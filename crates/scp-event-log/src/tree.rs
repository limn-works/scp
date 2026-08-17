//! Merkle tree operations for the event log.
//!
//! Implements the append-only Merkle tree following the Certificate
//! Transparency (RFC 6962) structure with domain separation prefixes per
//! Section 2.1. Leaf nodes are `SHA-256(0x00 || serialized_event)`. Interior
//! nodes are `SHA-256(0x01 || left_child || right_child)`. The domain
//! separation prevents second preimage attacks where a crafted payload could
//! make a leaf hash collide with an interior node hash.
//!
//! # Operations
//!
//! - [`append`] -- Append a verified event to the log.
//! - [`root`] -- Return the current Merkle root hash (O(1)).
//! - [`event_count`] -- Return the number of events in the log.
//!
//! See ADR-011 in `.docs/adrs/phase-2.md`.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::{Event, EventLog, EventLogError, EventType};
use scp_crypto::verify_ed25519_signature;
use scp_did::{
    DID, DidDocument, SigningKeyId, VerificationRelationship, extract_public_key_from_did,
};

/// The genesis sentinel hash used as `prev_hash` for the first event.
///
/// This is `[0u8; 32]` -- all zeros.
pub const GENESIS_PREV_HASH: [u8; 32] = [0u8; 32];

// ---------------------------------------------------------------------------
// Public operations
// ---------------------------------------------------------------------------

/// Appends an event to the event log.
///
/// 1. Verifies `event.sequence` matches the expected next sequence.
/// 2. Verifies `event.prev_hash` matches the hash of the last leaf
///    (or the genesis sentinel for the first event).
/// 3. Verifies an event signature against a verification method that
///    `actor_document` names — see [`verify_event_signature`].
/// 4. Serializes the event and computes `leaf_hash = SHA-256(0x00 || serialize(event))`
///    (RFC 6962 Section 2.1 leaf domain separation).
/// 5. Appends the leaf hash and incrementally updates affected interior
///    nodes — O(log n) per append.
/// 6. Inserts into the sorted leaf index.
/// 7. Returns the leaf index (position in the log).
///
/// # Arguments
///
/// * `log` — a per-context Merkle log this event extends.
/// * `event` — a signed event to append.
/// * `actor_document` — a DID document a caller resolved for
///   `event.actor_did`. A caller that cannot resolve that document does not
///   call this function, so an unresolvable actor fails closed by
///   construction (§23.13 paragraph 1).
///
/// # Errors
///
/// Returns [`EventLogError::SequenceMismatch`] if the sequence is wrong.
/// Returns [`EventLogError::PrevHashMismatch`] if the hash chain is broken.
/// Returns [`EventLogError::InvalidSignature`] if the signature is invalid.
/// Returns [`EventLogError::SerializationFailed`] if serialization fails.
///
/// See ADR-011 acceptance criterion 2.
pub fn append(
    log: &mut EventLog,
    event: &Event,
    actor_document: &DidDocument,
) -> Result<u64, EventLogError> {
    let expected_sequence = event_count(log);

    // 1. Verify sequence.
    if event.sequence != expected_sequence {
        return Err(EventLogError::SequenceMismatch {
            expected: expected_sequence,
            actual: event.sequence,
        });
    }

    // 2. Verify prev_hash.
    let expected_prev_hash = if log.leaves.is_empty() {
        GENESIS_PREV_HASH
    } else {
        // The prev_hash should match the last leaf hash.
        log.leaves[log.leaves.len() - 1]
    };

    if !bool::from(event.prev_hash.ct_eq(&expected_prev_hash)) {
        return Err(EventLogError::PrevHashMismatch {
            sequence: event.sequence,
        });
    }

    // 3. Verify signature.
    verify_event_signature(event, actor_document)?;

    // 4. Serialize and hash with 0x00 leaf domain prefix (RFC 6962 §2.1).
    let leaf_hash = leaf_hash(event)?;

    // 5. Append leaf and incrementally update tree — O(log n).
    let leaf_index = log.leaves.len() as u64;
    log.leaves.push(leaf_hash);
    incremental_update(log);

    // 6. Insert into sorted index.
    log.sorted_leaves.insert((leaf_hash, leaf_index));

    // 7. Store the full event payload for retrieval (#303, #330).
    log.push_event(event.clone());

    Ok(leaf_index)
}

/// Appends an event to the event log **without** Ed25519 signature verification.
///
/// # Why this exists
///
/// The MCP FFI bridge (`crates/scp-ffi/src/mcp.rs`) calls
/// `ContextProvider::invoke_outlet` synchronously from within the tokio runtime.
/// The `KeyCustody` signing trait is async, and calling `block_on` from inside
/// the tokio runtime panics ("Cannot block the current thread from within a
/// runtime"). Because signing key material cannot be accessed synchronously,
/// events emitted from this path carry an empty signature (`Vec::new()`).
///
/// # What it still guarantees
///
/// - **Sequence ordering**: the event's `sequence` must match the expected next
///   index, preventing out-of-order insertion.
/// - **Hash chain integrity**: `prev_hash` must match the last leaf hash (or
///   the genesis sentinel for the first event), preserving append-only ordering.
/// - **Merkle commitment**: the event is serialized and hashed with the same
///   RFC 6962 `0x00` leaf domain prefix mechanism used by [`append`], but the
///   empty signature means leaf hashes will differ from equivalent signed
///   events. The event is committed to the Merkle tree.
///
/// # Security limitation
///
/// **Events appended through this function are NOT cryptographically signed.**
/// The `signature` field is empty. This means:
///
/// - A compromised in-process attacker with write access to the `EventLog`
///   could inject fabricated events (e.g., fake `OutletInvokedEvent` entries)
///   that pass sequence and hash-chain validation but carry no proof of origin.
/// - External verifiers cannot distinguish between legitimate unsigned events
///   and injected ones — both have empty signatures.
/// - The threat is limited to in-process attackers because the `EventLog` is
///   not network-accessible and the calling code controls the event content.
///
/// # Threat model
///
/// Only **trusted in-process callers** should use this function. The caller
/// must control event content and an `EventLog` reference. Callers today:
///
/// - `MerkleEventLogProvider` in
///   `crates/scp-runtime/src/context/providers/event_log.rs` — every typed
///   context event a running node records
/// - `import_context_export` and context construction in
///   `crates/scp-runtime/src/context/{export_import,builder}.rs` — snapshot
///   replay, where each leaf arrives already committed
/// - UCAN-state and outlet event-log surfaces across all three FFI bridges
/// - `PerContextState::replay_event` in `crates/scp-client/src/context.rs`,
///   which `ScpClient::join_context_encrypted` drives over an event stream an
///   adder transported — an event another party produced, appended without a
///   signature check
/// - Test code
///
/// Nothing in this repository calls [`append`] outside test code, so no shipped
/// path verifies an event signature today. [`verify_event_signature`] states
/// what blocks a shipped caller: every shipped writer emits an empty
/// `signature`, so a verifier wired in ahead of leaf signing would reject every
/// honest event.
///
/// # Migration plan
///
/// When async FFI is available (SCP-214 wires `KeyCustodyProvider` into all
/// bridges), this function should be replaced by calls to [`append`] with
/// properly signed events. The migration path:
///
/// 1. Make `ContextProvider::invoke_outlet` async (or use a signing channel).
/// 2. Obtain the actor's `KeyCustody` handle in the FFI bridge.
/// 3. Sign the event via `KeyCustody::sign()` before appending.
/// 4. Replace all `append_unsigned_event` call sites with [`append`].
/// 5. Remove this function and its tests.
///
/// See `.docs/lessons/unsigned-event-mcp-bridge.md` for the full writeup.
///
/// # Errors
///
/// Returns [`EventLogError::SequenceMismatch`] if the sequence is wrong.
/// Returns [`EventLogError::PrevHashMismatch`] if the hash chain is broken.
/// Returns [`EventLogError::SerializationFailed`] if serialization fails.
pub fn append_unsigned_event(log: &mut EventLog, event: &Event) -> Result<u64, EventLogError> {
    let expected_sequence = event_count(log);

    // 1. Verify sequence.
    if event.sequence != expected_sequence {
        return Err(EventLogError::SequenceMismatch {
            expected: expected_sequence,
            actual: event.sequence,
        });
    }

    // 2. Verify prev_hash.
    let expected_prev_hash = if log.leaves.is_empty() {
        GENESIS_PREV_HASH
    } else {
        log.leaves[log.leaves.len() - 1]
    };

    if !bool::from(event.prev_hash.ct_eq(&expected_prev_hash)) {
        return Err(EventLogError::PrevHashMismatch {
            sequence: event.sequence,
        });
    }

    // 3. Serialize and hash with 0x00 leaf domain prefix (RFC 6962 §2.1).
    let leaf_hash = leaf_hash(event)?;

    // 4. Append leaf and incrementally update tree — O(log n).
    let leaf_index = log.leaves.len() as u64;
    log.leaves.push(leaf_hash);
    incremental_update(log);

    // 5. Insert into sorted index.
    log.sorted_leaves.insert((leaf_hash, leaf_index));

    // 6. Store the full event payload for retrieval (#303, #330).
    log.push_event(event.clone());

    Ok(leaf_index)
}

/// Returns the current Merkle root hash.
///
/// - If the log is empty, returns `SHA-256("")` per spec §25.8 Vector 15.
/// - If the log has one leaf, the root is that leaf hash.
/// - Otherwise, the root is the single element at the top interior layer.
///
/// This is O(1) -- the root is always maintained during appends.
///
/// See ADR-011 acceptance criterion 6.
#[must_use]
pub fn root(log: &EventLog) -> [u8; 32] {
    if log.leaves.is_empty() {
        return empty_tree_root();
    }

    if log.tree.is_empty() {
        // Single leaf -- the leaf hash is the root.
        return log.leaves[0];
    }

    // The root is the single element at the top layer.
    let top_layer = &log.tree[log.tree.len() - 1];
    if top_layer.len() == 1 {
        return top_layer[0];
    }

    // If the top layer has more than one element, we need to go higher.
    // This shouldn't happen with a correctly maintained tree, but handle
    // gracefully by returning the hash of the top layer.
    // In practice, `recompute_tree` always produces a single root.
    top_layer[0]
}

/// Returns the number of events in the log.
///
/// See ADR-011 acceptance criterion 7.
#[must_use]
pub const fn event_count(log: &EventLog) -> u64 {
    log.leaves.len() as u64
}

/// Recomputes the interior tree for an `EventLog` from its current leaves.
///
/// This is a `pub(crate)` entry point for use by `EventLog::rebuild_tree()`
/// after a `push_leaf_raw()` call. It performs the same full-tree recompute
/// as the internal `recompute_tree()` helper.
pub(crate) fn recompute_raw(log: &mut EventLog) {
    recompute_tree(log);
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Returns `SHA-256("")` -- the Merkle root for an empty event log.
///
/// Per spec §25.8 Vector 15, the empty tree root is the hash of the empty
/// string, NOT `[0u8; 32]`. This distinguishes "empty log" from the genesis
/// `prev_hash` sentinel (`GENESIS_PREV_HASH = [0u8; 32]`).
#[must_use]
pub(crate) fn empty_tree_root() -> [u8; 32] {
    let hash = Sha256::digest(b"");
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    out
}

/// Serializes the full event (including signature) for Merkle leaf hashing.
///
/// The leaf hash is a commitment to the complete, signed event. This is
/// distinct from [`compute_event_canonical_hash`], which excludes the
/// signature field to produce the message that gets signed.
fn serialize_event_for_hashing(event: &Event) -> Result<Vec<u8>, EventLogError> {
    // We serialize the full event including signature for the leaf hash.
    // The leaf hash is a commitment to the complete event (including its
    // signature), which is the standard approach in event logs.
    rmp_serde::to_vec(event).map_err(|e| EventLogError::SerializationFailed(e.to_string()))
}

/// Computes the RFC 6962 leaf hash for an event: `SHA-256(0x00 ‖ rmp_serde(event))`.
///
/// This is the canonical Merkle leaf preimage used by both [`append`] and
/// [`append_unsigned_event`]. It is exposed so consumers that hold an
/// [`Event`] (e.g. FFI bridge event-log surfaces) can reproduce the exact leaf
/// hash a verifier would compute, without re-deriving the domain-separation
/// scheme. The `0x00` prefix provides RFC 6962 §2.1 domain separation from
/// interior nodes (which use `0x01`).
///
/// # Errors
///
/// Returns [`EventLogError::SerializationFailed`] if event serialization fails.
pub fn leaf_hash(event: &Event) -> Result<[u8; 32], EventLogError> {
    let serialized = serialize_event_for_hashing(event)?;
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(&serialized);
    Ok(hasher.finalize().into())
}

/// Verification methods this crate accepts on an event signature, in trial
/// order.
///
/// **Criterion:** an event signature verifies against an operational signing key
/// that an actor's own DID document names — `#active` (a human's Active Signing
/// Key) or `#agent` (an agent's Signing Key). Spec §7.3.1 says an acting agent
/// signs an event, and ADR-039 grants an acting agent exactly those two
/// operational verification methods.
///
/// Two fragment families stay out of this list:
///
/// - `#0`, an Identity Key. ADR-039's key-property table marks it "Signs
///   operational actions: No", and §9.7.4 confines it to DID document updates
///   plus pre-rotation commitments. Recovering a key from a DID string yields
///   precisely that key, which is what this list replaces.
/// - `#retired-{n}` and `#retired-agent-{n}`, fragments that
///   [`DidDocument::retire_active_key`] and [`DidDocument::rotate_agent_key`]
///   assign on rotation. A document keeps them so a reader can audit rotation
///   history; accepting one would let a rotated key sign forever.
///
/// **Trial order is not role pinning.** An `Event` names no verification
/// method: ADR-011 acceptance criterion 1 defines it with seven fields and no
/// `signing_key_id`, and §23.13 paragraph 1 tells a verifier to try each method
/// `assertionMethod` authorizes and to return the one that verified. A caller
/// attributing an event to a human holder or to agent software reads that
/// returned [`SigningKeyId`], which is what ADR-039 gives the two methods
/// distinct holders for. No `EventType` names an act ADR-039's Category A
/// reserves to a human — that category covers DID document updates,
/// pre-rotation commitments, identity migration, and root UCAN issuance — so
/// Category A is not what a caller reads this value for.
pub const ACCEPTED_EVENT_SIGNING_KEY_IDS: [SigningKeyId; 2] =
    [SigningKeyId::Active, SigningKeyId::Agent];

/// Verifies an Ed25519 signature on an event against an actor's DID document,
/// and reports which verification method produced it.
///
/// Reads operational signing keys out of `actor_document`, recomputes a
/// canonical event hash, and tries each key in
/// [`ACCEPTED_EVENT_SIGNING_KEY_IDS`] until one verifies. [`append`] calls this
/// for a new event; a caller reconciling events from a remote peer calls it
/// through [`verify_event_batch`] (§23.13 paragraph 1).
///
/// # No shipped path verifies an event signature, and two questions block one
///
/// [`append`] has zero callers outside test code, so no shipped path reaches
/// this function. Every shipped writer emits an event whose `signature` field
/// is empty, so a caller who wired a verifier in today would reject every
/// honest event.
///
/// Two shipped paths append an event another party produced, and both go
/// through [`append_unsigned_event`], which runs no signature check:
///
/// - `scp_client::PerContextState::replay_event`, which
///   `ScpClient::join_context_encrypted` drives over a `prior_event_log` stream
///   an adder transported. That crate's own append path writes an empty
///   `signature`, because ADR-057, the in-browser client, records that a
///   browser holds no identity signing key — only an ephemeral MLS
///   `SignatureKeyPair` in wasm.
/// - `scp_runtime::context::export_import`, which replays a snapshot an exporter
///   produced. It authenticates that snapshot as a whole — a full-snapshot
///   Ed25519 signature (§23.16.8) plus a constant-time compare of the
///   recomputed Merkle root against the signed root — rather than per event, so
///   it trusts one exporter rather than each named actor.
///
/// §23.13 paragraph 1 requires per-event verification during reconciliation, so
/// a production caller belongs on the first path. Two questions stand in front
/// of that caller, and neither is answered in any artifact:
///
/// 1. **Which party's signature does a mirrored leaf carry?** §23.13 paragraph
///    1 says the claimed actor's, and ADR-057 says a per-leaf committer
///    signature. A `MemberJoined` leaf that every member records has one actor
///    and one committer, and they are different parties for every member except
///    the committer.
/// 2. **Can a per-member signature sit in the leaf preimage at all?**
///    [`leaf_hash`] hashes the whole event including `signature`, while
///    [`compute_event_canonical_hash`] excludes it. §7.3.1 requires honest
///    members to hold byte-identical leaf preimages for one event, because the
///    §9.9.3 equivocation test compares roots at equal event counts. Two members
///    that each signed their own copy of one logical event would hold different
///    leaves and read as equivocating.
///
/// A human settles both before a signing scheme lands; this crate does not
/// choose an answer.
///
/// # Why a document rather than a DID string
///
/// A DID string encodes an Identity Key (`#0`) that never rotates, so a verifier
/// recovering its key from that string would accept a rotated or retired signing
/// key forever. §23.13 paragraph 1 requires resolution from an actor's DID
/// document, and ADR-011's dependency on ADR-003 states that same rule for an
/// event signature. A caller resolves a document and passes it here; this crate
/// performs no I/O, which keeps it synchronous and wasm-safe (ADR-057 crate
/// topology) and matches
/// [`verify_checkpoint_signature`](crate::checkpoint::verify_checkpoint_signature),
/// which also takes a caller-resolved key.
///
/// # What a caller guarantees
///
/// `actor_document` is trusted input. This function checks that a document
/// describes `event.actor_did` and that a key it names verifies a signature; it
/// cannot check where that document came from, how recently a caller fetched it,
/// or whether a resolver validated its BEP44 signature and sequence number
/// (§3.10.4). A caller passing a document cached before a key rotation therefore
/// gets acceptance of a key an actor has since retired. Rotation revokes a key
/// exactly as fast as a caller re-resolves.
///
/// # Fail-closed conditions
///
/// - `actor_document.id` differs from `event.actor_did`.
/// - `event.actor_did` is not a canonical, supported DID string.
/// - A document's `#0` Identity Key derives some DID other than
///   `event.actor_did`, so that document self-certifies a different identity
///   (§3.8, §9.6.1).
/// - A document carries more than one `#agent` verification method, which
///   ADR-039's structural constraint tells a verifier to reject.
/// - A named method declares a type other than
///   [`ED25519_VERIFICATION_KEY_TYPE`](scp_did::ED25519_VERIFICATION_KEY_TYPE),
///   names a controller other than an actor,
///   or is absent from `assertionMethod`, so a document never authorized it to
///   sign an assertion.
/// - A document names neither `#active` nor `#agent`.
/// - No named key verifies a signature.
///
/// Each condition returns [`EventLogError::InvalidSignature`], which §23.13
/// paragraph 2 names as a rejection reason an SDK logs. None reaches for a key
/// recovered from a DID string.
///
/// # Errors
///
/// Returns [`EventLogError::InvalidSignature`] under each condition above.
pub fn verify_event_signature(
    event: &Event,
    actor_document: &DidDocument,
) -> Result<SigningKeyId, EventLogError> {
    let reject = |reason: String| EventLogError::InvalidSignature {
        sequence: event.sequence,
        reason,
    };

    if actor_document.id != *event.actor_did {
        return Err(reject(format!(
            "resolved DID document describes {}, not event actor {}",
            actor_document.id, event.actor_did
        )));
    }

    // Format and canonicality gate on an actor DID string. It admits a
    // canonical `did:dht` string, and a `did:key:<hex>` string under a
    // `testing` feature, so two spellings of one `did:dht` identity cannot
    // address one actor (§3.8.1, §9.6.1). `did:dht` is what `scp-did`
    // implements; a `did:web` fallback actor (§3.8) reaches no shipped resolver
    // in this repository and is rejected here for that reason, not for a
    // canonicality failure.
    let did_identity_key = extract_public_key_from_did(&event.actor_did).map_err(|reason| {
        reject(format!(
            "event actor DID is not a canonical, supported DID: {reason}"
        ))
    })?;

    // Self-certification (§3.8, §9.6.1): a `did:dht` string is z-base-32 of an
    // Identity Key, so a document whose `#0` method carries some other key
    // describes some other identity, whatever its `id` field claims. A caller
    // that skipped BEP44 verification hands over a document this check still
    // rejects, which is one property of a document's origin this crate can
    // establish on its own.
    let document_identity_key = actor_document.identity_key().map_err(|error| {
        reject(format!(
            "#0 key of {} is unusable: {error}",
            actor_document.id
        ))
    })?;
    if document_identity_key != did_identity_key {
        return Err(reject(format!(
            "#0 key of {} derives some other DID, so that document does not describe actor {}",
            actor_document.id, event.actor_did
        )));
    }

    actor_document
        .validate_agent_keys()
        .map_err(|reason| reject(format!("actor DID document is malformed: {reason}")))?;

    let canonical_hash = compute_event_canonical_hash(event);
    let mut failures = Vec::with_capacity(ACCEPTED_EVENT_SIGNING_KEY_IDS.len());
    let mut usable_keys = Vec::with_capacity(ACCEPTED_EVENT_SIGNING_KEY_IDS.len());

    for signing_key_id in ACCEPTED_EVENT_SIGNING_KEY_IDS {
        match actor_document.signing_key_for(signing_key_id, VerificationRelationship::Assertion) {
            Ok(public_key) => usable_keys.push((signing_key_id, public_key)),
            Err(error) => failures.push(error.to_string()),
        }
    }

    // ADR-039 gives `#active` and `#agent` distinct holders — a human and agent
    // software — so an owner publishing one key under both fragments erases a
    // distinction a returned `SigningKeyId` reports. Answering `Active` for a
    // signature agent software produced would attribute an agent's action to a
    // human, which ADR-039's accountability argument rests on keeping apart.
    if let [(_, first_key), (_, second_key)] = usable_keys.as_slice()
        && first_key == second_key
    {
        return Err(reject(format!(
            "DID document for {} publishes one key under both #active and #agent, \
             so no signature says which holder produced it",
            actor_document.id
        )));
    }

    for (signing_key_id, public_key) in usable_keys {
        match verify_ed25519_signature(&public_key, &canonical_hash, &event.signature) {
            Ok(()) => return Ok(signing_key_id),
            Err(error) => failures.push(format!(
                "{} key of {} rejected a signature: {error}",
                signing_key_id.as_fragment(),
                actor_document.id
            )),
        }
    }

    // Report every method a verifier tried, so an operator reading a log sees
    // why each one failed rather than why a last one did.
    Err(reject(failures.join("; ")))
}

/// Verifies signatures across a batch of events a peer supplied during sync
/// reconciliation (§23.13 paragraph 1).
///
/// Verifies each event against a DID document `actor_documents` holds for that
/// event's actor, and returns one verification method per event, in event order.
/// A first failure ends verification and returns that failure.
///
/// A caller resolves one DID document per distinct actor in a batch and passes
/// results here. An actor `actor_documents` does not cover fails closed: this
/// function rejects that event instead of reaching for a key recovered from a
/// DID string. Freshness of each document stays a caller's guarantee, exactly as
/// [`verify_event_signature`] describes.
///
/// # Errors
///
/// Returns [`EventLogError::InvalidSignature`] for a first event whose actor
/// `actor_documents` does not cover, or whose signature no key named by an
/// actor's document verifies.
pub fn verify_event_batch(
    events: &[Event],
    actor_documents: &BTreeMap<DID, DidDocument>,
) -> Result<Vec<SigningKeyId>, EventLogError> {
    let mut signing_key_ids = Vec::with_capacity(events.len());
    for event in events {
        let Some(actor_document) = actor_documents.get(&event.actor_did) else {
            return Err(EventLogError::InvalidSignature {
                sequence: event.sequence,
                reason: format!(
                    "no resolved DID document for event actor {}",
                    event.actor_did
                ),
            });
        };
        signing_key_ids.push(verify_event_signature(event, actor_document)?);
    }
    Ok(signing_key_ids)
}

/// Computes the canonical hash of an event for signature purposes.
///
/// This is the content that must be signed by the actor's Ed25519 key.
/// The hash covers all event fields except the signature itself.
///
/// ```text
/// SHA-256("SCP-EVENT-V1:" || event_type_tag || len(actor_did) || actor_did
///         || timestamp_BE || sequence_BE || len(payload) || payload
///         || prev_hash)
/// ```
///
/// Variable-length fields (`actor_did`, `payload.data`) are prefixed with
/// their length as a 4-byte big-endian u32 to prevent field-boundary
/// ambiguity. The `SCP-EVENT-V1:` domain separator prevents cross-protocol
/// hash confusion.
///
/// Used by [`append`] for signature verification and by FFI bridge layers
/// that need to sign events before appending.
#[must_use]
pub fn compute_event_canonical_hash(event: &Event) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"SCP-EVENT-V1:");

    // Length-prefix closure for variable-length fields.
    #[allow(clippy::cast_possible_truncation)]
    let length_prefix = |hasher: &mut Sha256, bytes: &[u8]| {
        hasher.update((bytes.len() as u32).to_be_bytes());
        hasher.update(bytes);
    };

    // Event type as a tag byte (fixed-width u16).
    hasher.update(event_type_tag(&event.event_type).to_be_bytes());
    length_prefix(&mut hasher, event.actor_did.as_bytes());
    hasher.update(event.timestamp.to_be_bytes());
    hasher.update(event.sequence.to_be_bytes());
    length_prefix(&mut hasher, &event.payload.data);
    hasher.update(event.prev_hash); // 32B fixed

    hasher.finalize().to_vec()
}

/// Returns a stable numeric tag for each event type variant.
///
/// Used in canonical hash computation. The tag values are protocol constants
/// and must never change.
#[must_use]
pub const fn event_type_tag(event_type: &EventType) -> u16 {
    match event_type {
        EventType::ContextCreated => 0,
        EventType::ContextClosing => 1,
        EventType::ContextClosed => 2,
        EventType::ContextExpired => 3,
        EventType::MemberJoined => 4,
        EventType::MemberLeft => 5,
        EventType::RoleAssigned => 6,
        EventType::TokenRevoked => 7,
        EventType::MessageSent => 8,
        EventType::OutletRegistered => 9,
        EventType::OutletUpdated => 10,
        EventType::OutletInvoked => 11,
        EventType::OutletVerified => 12,
        EventType::OutletInterfaceEstablished => 13,
        EventType::GovernanceAction => 14,
        EventType::ConsistencyCheckpoint => 15,
        EventType::AbsenceProofRequested => 16,
        EventType::MemberBlocked => 17,
        EventType::KeyEpochAdvance => 18,
        EventType::MediaSessionStarted => 19,
        EventType::MediaSessionEnded => 20,
        EventType::PaymentReceived => 21,
        EventType::EconomicPolicyChanged => 22,
        EventType::EconomicPolicyApplied => 33,
        EventType::SpendingUcanGranted => 23,
        EventType::SpendingUcanRevoked => 24,
        // Governance event types (ADR-031 §8)
        EventType::GovernanceProposalCreated => 25,
        EventType::GovernanceVoteCast => 26,
        EventType::GovernanceVoteWithdrawn => 27,
        EventType::GovernanceProposalResolved => 28,
        EventType::GovernanceConflictDetected => 29,
        EventType::GovernanceConflictResolved => 30,
        EventType::GovernanceDeadlockRecovery => 31,
        EventType::GovernanceActionExecuted => 32,
        // Provenance event types (issue #586)
        EventType::ProvenanceAttached => 34,
        EventType::ProvenanceReceived => 35,
        // Typed-event unification variants (ADR-011 Amendment). Tags 36..=75
        // are assigned in ADR declaration order, with tag 59 retired (see the
        // PseudonymAnnounced removal note below). Tags 76..=77 (below) are the
        // ADR-011 Amendment §6 cross-context-saga carve-out. Tags 0-35 above are
        // protocol constants and MUST NOT change.
        EventType::AdminTransferred => 36,
        EventType::CeilingModified => 37,
        EventType::CeilingModificationPending => 38,
        EventType::ThresholdModified => 39,
        EventType::SignerAdded => 40,
        EventType::SignerRemoved => 41,
        EventType::ChildContextCreated => 42,
        EventType::ContextPromoted => 43,
        EventType::ContentKeysRotated => 44,
        EventType::MemberReset => 45,
        EventType::MemberSuspended => 46,
        EventType::MemberSuspendedAll => 47,
        EventType::MemberUnblocked => 48,
        EventType::AccessRestored => 49,
        EventType::GovernanceReconfigured => 50,
        EventType::GovernanceFreezeExpired => 51,
        EventType::HardRateLimitModified => 52,
        EventType::EconomicPolicyLocked => 53,
        EventType::ContextMigrationStarted => 54,
        EventType::OutletRemoved => 55,
        EventType::PruningPolicyModified => 56,
        EventType::CommitBroadcasted => 57,
        EventType::CommitBroadcastPending => 58,
        // 59 retired: PseudonymAnnounced removed — a §9.10.4 routing-bootstrap
        // ContextEvent signal, not a durable Merkle event (ADR-011 Amendment).
        // The tag value is intentionally left as a gap so every other variant's
        // canonical tag (and the §25 KAT preimages) stays byte-stable.
        EventType::ContextTombstoned => 60,
        EventType::ContextMigrationCancelled => 61,
        EventType::TtlExtended => 62,
        EventType::TtlExtensionRejected => 63,
        EventType::AccessRevoked => 64,
        EventType::SpendApproved => 65,
        EventType::PaymentCaptureFailed => 66,
        EventType::ConsequenceTriggered => 67,
        EventType::ConsequenceEnforced => 68,
        EventType::ConsequenceEnforcementFailed => 69,
        EventType::ConsequenceEscalatedToSuspendAll => 70,
        EventType::CommitBroadcastSucceeded => 71,
        EventType::CommitBroadcastFailed => 72,
        EventType::RecoveryEpochAdvanced => 73,
        EventType::AppBound => 74,
        EventType::AppUnbound => 75,
        // Cross-context outlet-call saga (ADR-011 Amendment §6 carve-out). Tags
        // 76..=77 are the next free values after the current max (75); tag 59
        // stays retired. These are convergent commit-ordered durable leaves.
        EventType::CrossContextOutletInvoked => 76,
        EventType::CrossContextDivergenceMarker => 77,
    }
}

/// Incrementally updates the interior tree after a single leaf append.
///
/// Only recomputes the nodes along the path from the new leaf to the root
/// — O(log n) per append instead of rebuilding the entire tree O(n).
///
/// RFC 6962 structure: odd nodes are promoted (not duplicated).
///
/// Incremental path-only recompute (M1 performance fix) rather than a full
/// O(n) tree rebuild on every append.
fn incremental_update(log: &mut EventLog) {
    let n = log.leaves.len();

    if n <= 1 {
        log.tree.clear();
        return;
    }

    // For the very first pair (n == 2), bootstrap the tree.
    if n == 2 {
        log.tree.clear();
        log.tree
            .push(vec![hash_pair(&log.leaves[0], &log.leaves[1])]);
        return;
    }

    // Index of the new leaf in the leaf layer.
    let mut idx = n - 1;

    // Layer 0: pairs from the leaf layer.
    let layer_0_parent_count = n.div_ceil(2);

    // Ensure tree layer 0 exists and has enough capacity.
    if log.tree.is_empty() {
        log.tree.push(Vec::new());
    }
    let layer_0 = &mut log.tree[0];
    layer_0.resize(layer_0_parent_count, [0u8; 32]);

    // Recompute the affected parent at idx/2.
    let parent_idx = idx / 2;
    let left_child = parent_idx * 2;
    if left_child + 1 < n {
        layer_0[parent_idx] = hash_pair(&log.leaves[left_child], &log.leaves[left_child + 1]);
    } else {
        // Odd node: promoted per RFC 6962.
        layer_0[parent_idx] = log.leaves[left_child];
    }

    idx = parent_idx;

    // Walk up the remaining layers, recomputing only the affected node.
    let mut level = 0;
    loop {
        let current_layer_len = log.tree[level].len();
        if current_layer_len <= 1 {
            // This layer is the root; trim any layers above it.
            log.tree.truncate(level + 1);
            break;
        }

        let next_layer_len = current_layer_len.div_ceil(2);
        let next_level = level + 1;

        // Ensure the next layer exists and has the right size.
        if next_level >= log.tree.len() {
            log.tree.push(vec![[0u8; 32]; next_layer_len]);
        } else {
            log.tree[next_level].resize(next_layer_len, [0u8; 32]);
        }

        let parent_idx = idx / 2;
        let left_child = parent_idx * 2;

        // Compute the parent from its two children in tree[level].
        if left_child + 1 < current_layer_len {
            let hash = hash_pair(
                &log.tree[level][left_child],
                &log.tree[level][left_child + 1],
            );
            log.tree[next_level][parent_idx] = hash;
        } else {
            // Odd node: promoted.
            log.tree[next_level][parent_idx] = log.tree[level][left_child];
        }

        idx = parent_idx;
        level = next_level;
    }
}

/// Recomputes the entire interior tree from the leaf layer.
///
/// Used by `recompute_raw` for bulk reconstruction (e.g.,
/// `TruncatedEventLog::push_leaf_raw`). Single-leaf appends use
/// [`incremental_update`] instead for O(log n) performance.
///
/// RFC 6962 structure: if a layer has an odd number of nodes, the last node
/// is promoted directly to the next level (not hashed with itself).
fn recompute_tree(log: &mut EventLog) {
    log.tree.clear();

    if log.leaves.len() <= 1 {
        // 0 or 1 leaves: no interior nodes needed.
        return;
    }

    let mut current_layer: &[[u8; 32]] = &log.leaves;
    let mut owned_layer: Vec<[u8; 32]>;

    loop {
        let parent_count = current_layer.len().div_ceil(2);
        let mut parents = Vec::with_capacity(parent_count);

        let mut i = 0;
        while i < current_layer.len() {
            if i + 1 < current_layer.len() {
                // Hash pair: SHA-256(0x01 || left || right)
                parents.push(hash_pair(&current_layer[i], &current_layer[i + 1]));
            } else {
                // Odd node: promote directly to the next level per RFC 6962.
                parents.push(current_layer[i]);
            }
            i += 2;
        }

        log.tree.push(parents.clone());

        if parents.len() == 1 {
            // We've reached the root.
            break;
        }

        owned_layer = parents;
        current_layer = &owned_layer;
    }
}

/// Computes `SHA-256(0x01 || left || right)` for an interior node.
///
/// This is the RFC 6962 Section 2.1 interior node hash function. The `0x01`
/// prefix provides domain separation from leaf hashes (which use `0x00`),
/// preventing second preimage attacks.
pub(crate) fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::EventPayload;
    use crate::test_helpers::{
        did_from_pubkey, leaf_hash_from_event, sign_event, test_did_document,
        test_did_document_with_agent, test_keypair,
    };

    // -----------------------------------------------------------------------
    // append updates tree and root correctly
    // -----------------------------------------------------------------------

    #[test]
    fn append_updates_tree_and_root_correctly() {
        let (verifying_key, signing_key) = test_keypair();
        let did = did_from_pubkey(&verifying_key);
        let actor_document = test_did_document(&did, &verifying_key);
        let mut log = EventLog::new("ctx-test".to_owned());

        // Append first event.
        let event0 = sign_event(
            EventType::ContextCreated,
            &did,
            1_000_000,
            0,
            b"genesis".to_vec(),
            GENESIS_PREV_HASH,
            &signing_key,
        );

        let idx0 = append(&mut log, &event0, &actor_document).unwrap();
        assert_eq!(idx0, 0);
        assert_eq!(event_count(&log), 1);

        // Root of a single-leaf tree is the leaf hash itself.
        let leaf0_hash = leaf_hash_from_event(&event0);
        assert_eq!(root(&log), leaf0_hash);

        // Append second event.
        let event1 = sign_event(
            EventType::MemberJoined,
            &did,
            1_000_001,
            1,
            b"alice joined".to_vec(),
            leaf0_hash,
            &signing_key,
        );

        let idx1 = append(&mut log, &event1, &actor_document).unwrap();
        assert_eq!(idx1, 1);
        assert_eq!(event_count(&log), 2);

        // Root should be SHA-256(0x01 || leaf0 || leaf1).
        let leaf1_hash = leaf_hash_from_event(&event1);
        let expected_root = hash_pair(&leaf0_hash, &leaf1_hash);
        assert_eq!(root(&log), expected_root);

        // Verify sorted index has both leaves.
        assert_eq!(log.sorted_leaves().len(), 2);
    }

    // -----------------------------------------------------------------------
    // append rejects event with wrong prev_hash
    // -----------------------------------------------------------------------

    #[test]
    fn append_rejects_wrong_prev_hash() {
        let (verifying_key, signing_key) = test_keypair();
        let did = did_from_pubkey(&verifying_key);
        let actor_document = test_did_document(&did, &verifying_key);
        let mut log = EventLog::new("ctx-test".to_owned());

        // First event with correct genesis prev_hash.
        let event0 = sign_event(
            EventType::ContextCreated,
            &did,
            1_000_000,
            0,
            b"genesis".to_vec(),
            GENESIS_PREV_HASH,
            &signing_key,
        );
        append(&mut log, &event0, &actor_document).unwrap();

        // Second event with wrong prev_hash.
        let wrong_prev_hash = [0xFF; 32];
        let event1 = sign_event(
            EventType::MemberJoined,
            &did,
            1_000_001,
            1,
            b"bad".to_vec(),
            wrong_prev_hash,
            &signing_key,
        );

        let result = append(&mut log, &event1, &actor_document);
        assert!(result.is_err());
        match result {
            Err(EventLogError::PrevHashMismatch { sequence }) => {
                assert_eq!(sequence, 1);
            }
            other => panic!("expected PrevHashMismatch, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // append rejects event with invalid signature
    // -----------------------------------------------------------------------

    #[test]
    fn append_rejects_invalid_signature() {
        let (verifying_key, signing_key) = test_keypair();
        let did = did_from_pubkey(&verifying_key);
        let actor_document = test_did_document(&did, &verifying_key);
        let mut log = EventLog::new("ctx-test".to_owned());

        // Create event with a tampered signature.
        let mut event0 = sign_event(
            EventType::ContextCreated,
            &did,
            1_000_000,
            0,
            b"genesis".to_vec(),
            GENESIS_PREV_HASH,
            &signing_key,
        );

        // Tamper with the signature.
        event0.signature = vec![0xFF; 64];

        let result = append(&mut log, &event0, &actor_document);
        assert!(result.is_err());
        match result {
            Err(EventLogError::InvalidSignature { sequence, .. }) => {
                assert_eq!(sequence, 0);
            }
            other => panic!("expected InvalidSignature, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // append rejects event signed by wrong key
    // -----------------------------------------------------------------------

    #[test]
    fn append_rejects_wrong_signer() {
        let (verifying_key, _signing_key) = test_keypair();
        let did = did_from_pubkey(&verifying_key);

        // Sign with a different key.
        let (_other_verifying, other_signing) = test_keypair();

        let actor_document = test_did_document(&did, &verifying_key);
        let mut log = EventLog::new("ctx-test".to_owned());
        let event0 = sign_event(
            EventType::ContextCreated,
            &did, // DID points to first keypair
            1_000_000,
            0,
            b"genesis".to_vec(),
            GENESIS_PREV_HASH,
            &other_signing, // But signed with different key
        );

        let result = append(&mut log, &event0, &actor_document);
        assert!(result.is_err());
        match result {
            Err(EventLogError::InvalidSignature { sequence, .. }) => {
                assert_eq!(sequence, 0);
            }
            other => panic!("expected InvalidSignature, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // root is O(1) and consistent after multiple appends
    // -----------------------------------------------------------------------

    #[test]
    fn root_consistent_after_multiple_appends() {
        let (verifying_key, signing_key) = test_keypair();
        let did = did_from_pubkey(&verifying_key);
        let actor_document = test_did_document(&did, &verifying_key);
        let mut log = EventLog::new("ctx-test".to_owned());

        // Empty log root is SHA-256(""), not [0u8; 32] (spec §25.8 Vector 15).
        assert_eq!(root(&log), empty_tree_root());

        let mut prev_hash = GENESIS_PREV_HASH;
        let mut leaf_hashes: Vec<[u8; 32]> = Vec::new();

        // Append 10 events and verify root is consistent.
        for i in 0..10u64 {
            let event = sign_event(
                EventType::MessageSent,
                &did,
                1_000_000 + i,
                i,
                format!("message {i}").into_bytes(),
                prev_hash,
                &signing_key,
            );

            append(&mut log, &event, &actor_document).unwrap();

            let leaf_hash = leaf_hash_from_event(&event);
            leaf_hashes.push(leaf_hash);
            prev_hash = leaf_hash;

            // Root should always be accessible.
            let current_root = root(&log);
            assert_ne!(current_root, [0u8; 32]);

            // Root should match manual computation.
            let expected = compute_root_manually(&leaf_hashes);
            assert_eq!(current_root, expected, "root mismatch at event {i}");
        }
    }

    // -----------------------------------------------------------------------
    // event_count returns correct count
    // -----------------------------------------------------------------------

    #[test]
    fn event_count_returns_correct_count() {
        let (verifying_key, signing_key) = test_keypair();
        let did = did_from_pubkey(&verifying_key);
        let actor_document = test_did_document(&did, &verifying_key);
        let mut log = EventLog::new("ctx-test".to_owned());

        assert_eq!(event_count(&log), 0);

        let mut prev_hash = GENESIS_PREV_HASH;
        for i in 0..5u64 {
            let event = sign_event(
                EventType::MessageSent,
                &did,
                1_000_000 + i,
                i,
                format!("msg {i}").into_bytes(),
                prev_hash,
                &signing_key,
            );

            append(&mut log, &event, &actor_document).unwrap();
            assert_eq!(event_count(&log), i + 1);

            let leaf_hash = leaf_hash_from_event(&event);
            prev_hash = leaf_hash;
        }
    }

    // -----------------------------------------------------------------------
    // append rejects wrong sequence
    // -----------------------------------------------------------------------

    #[test]
    fn append_rejects_wrong_sequence() {
        let (verifying_key, signing_key) = test_keypair();
        let did = did_from_pubkey(&verifying_key);
        let actor_document = test_did_document(&did, &verifying_key);
        let mut log = EventLog::new("ctx-test".to_owned());

        // Event with sequence 5 when we expect 0.
        let event = sign_event(
            EventType::ContextCreated,
            &did,
            1_000_000,
            5, // Wrong sequence
            b"genesis".to_vec(),
            GENESIS_PREV_HASH,
            &signing_key,
        );

        let result = append(&mut log, &event, &actor_document);
        assert!(result.is_err());
        match result {
            Err(EventLogError::SequenceMismatch { expected, actual }) => {
                assert_eq!(expected, 0);
                assert_eq!(actual, 5);
            }
            other => panic!("expected SequenceMismatch, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // sorted leaf index is maintained
    // -----------------------------------------------------------------------

    #[test]
    fn sorted_leaf_index_maintained() {
        let (verifying_key, signing_key) = test_keypair();
        let did = did_from_pubkey(&verifying_key);
        let actor_document = test_did_document(&did, &verifying_key);
        let mut log = EventLog::new("ctx-test".to_owned());

        let mut prev_hash = GENESIS_PREV_HASH;
        for i in 0..5u64 {
            let event = sign_event(
                EventType::MessageSent,
                &did,
                1_000_000 + i,
                i,
                format!("msg {i}").into_bytes(),
                prev_hash,
                &signing_key,
            );

            append(&mut log, &event, &actor_document).unwrap();

            let leaf_hash = leaf_hash_from_event(&event);
            prev_hash = leaf_hash;
        }

        // Sorted index should have 5 entries.
        assert_eq!(log.sorted_leaves().len(), 5);

        // Verify entries are sorted by hash.
        let entries: Vec<_> = log.sorted_leaves().iter().copied().collect();
        for i in 1..entries.len() {
            assert!(
                entries[i - 1].0 <= entries[i].0,
                "sorted index is not sorted"
            );
        }
    }

    // -----------------------------------------------------------------------
    // all 21 event types are valid
    // -----------------------------------------------------------------------

    #[test]
    fn all_event_types_append_successfully() {
        let (verifying_key, signing_key) = test_keypair();
        let did = did_from_pubkey(&verifying_key);
        let actor_document = test_did_document(&did, &verifying_key);
        let mut log = EventLog::new("ctx-test".to_owned());

        let event_types = [
            EventType::ContextCreated,
            EventType::ContextClosing,
            EventType::ContextClosed,
            EventType::ContextExpired,
            EventType::MemberJoined,
            EventType::MemberLeft,
            EventType::RoleAssigned,
            EventType::TokenRevoked,
            EventType::MessageSent,
            EventType::OutletRegistered,
            EventType::OutletUpdated,
            EventType::OutletInvoked,
            EventType::OutletVerified,
            EventType::OutletInterfaceEstablished,
            EventType::GovernanceAction,
            EventType::ConsistencyCheckpoint,
            EventType::AbsenceProofRequested,
            EventType::MemberBlocked,
            EventType::KeyEpochAdvance,
            EventType::MediaSessionStarted,
            EventType::MediaSessionEnded,
            EventType::PaymentReceived,
            EventType::EconomicPolicyChanged,
            EventType::EconomicPolicyApplied,
            EventType::SpendingUcanGranted,
            EventType::SpendingUcanRevoked,
        ];

        let mut prev_hash = GENESIS_PREV_HASH;
        for (i, event_type) in event_types.iter().enumerate() {
            let event = sign_event(
                *event_type,
                &did,
                1_000_000 + i as u64,
                i as u64,
                format!("event {i}").into_bytes(),
                prev_hash,
                &signing_key,
            );

            let idx = append(&mut log, &event, &actor_document).unwrap();
            assert_eq!(idx, i as u64);

            let leaf_hash = leaf_hash_from_event(&event);
            prev_hash = leaf_hash;
        }

        assert_eq!(event_count(&log), 26);
    }

    // -----------------------------------------------------------------------
    // did:dht format support
    // -----------------------------------------------------------------------

    #[test]
    fn append_supports_did_dht_format() {
        let (verifying_key, signing_key) = test_keypair();

        // Encode as did:dht:z<z-base-32(pubkey)>.
        let z32 = zbase32::encode(verifying_key.as_bytes());
        let did = format!("did:dht:z{z32}");
        let actor_document = test_did_document(&did, &verifying_key);

        let mut log = EventLog::new("ctx-test".to_owned());
        let event = sign_event(
            EventType::ContextCreated,
            &did,
            1_000_000,
            0,
            b"genesis".to_vec(),
            GENESIS_PREV_HASH,
            &signing_key,
        );

        let idx = append(&mut log, &event, &actor_document).unwrap();
        assert_eq!(idx, 0);
    }

    // -----------------------------------------------------------------------
    // Signature verification resolves an actor's DID document (§23.13 ¶1)
    // -----------------------------------------------------------------------

    /// Builds a genesis-position event signed by `signing_key` for `actor_did`.
    fn genesis_event(actor_did: &str, signing_key: &ed25519_dalek::SigningKey) -> Event {
        sign_event(
            EventType::ContextCreated,
            actor_did,
            1_000_000,
            0,
            b"genesis".to_vec(),
            GENESIS_PREV_HASH,
            signing_key,
        )
    }

    #[test]
    fn append_accepts_event_signed_by_current_active_key() {
        let (verifying_key, signing_key) = test_keypair();
        let did = did_from_pubkey(&verifying_key);
        let actor_document = test_did_document(&did, &verifying_key);
        let mut log = EventLog::new("ctx-active-key".to_owned());

        let event = genesis_event(&did, &signing_key);

        assert_eq!(append(&mut log, &event, &actor_document).unwrap(), 0);
    }

    #[test]
    fn append_rejects_event_signed_by_rotated_active_key() {
        let (old_verifying_key, old_signing_key) = test_keypair();
        let (new_verifying_key, _new_signing_key) = test_keypair();
        let did = did_from_pubkey(&old_verifying_key);

        // An actor rotates `#active` (§9.7.4 key rotation): a DID string
        // stays put, an old key moves to `#retired-1`, and a new key
        // takes over `#active`.
        let mut actor_document = test_did_document(&did, &old_verifying_key);
        actor_document.retire_active_key(new_verifying_key.as_bytes(), 1);
        assert!(
            actor_document
                .verification_method_by_fragment("retired-1")
                .is_some(),
            "a rotated document retains its old key as #retired-1"
        );

        let mut log = EventLog::new("ctx-rotated-active".to_owned());
        let event = genesis_event(&did, &old_signing_key);

        let result = append(&mut log, &event, &actor_document);
        match result {
            Err(EventLogError::InvalidSignature { sequence, reason }) => {
                assert_eq!(sequence, 0);
                assert!(
                    reason.contains("#active"),
                    "rejection names a method it tried: {reason}"
                );
            }
            other => panic!("expected InvalidSignature, got {other:?}"),
        }
        assert_eq!(event_count(&log), 0, "a rejected event leaves no leaf");
    }

    #[test]
    fn verify_event_signature_accepts_agent_key() {
        let (active_verifying_key, _active_signing_key) = test_keypair();
        let (agent_verifying_key, agent_signing_key) = test_keypair();
        let did = did_from_pubkey(&active_verifying_key);
        let actor_document =
            test_did_document_with_agent(&did, &active_verifying_key, &agent_verifying_key);

        let event = genesis_event(&did, &agent_signing_key);

        verify_event_signature(&event, &actor_document)
            .expect("an event an #agent key signed verifies (ADR-039)");
    }

    #[test]
    fn verify_event_signature_rejects_rotated_agent_key() {
        let (active_verifying_key, _active_signing_key) = test_keypair();
        let (old_agent_verifying_key, old_agent_signing_key) = test_keypair();
        let (new_agent_verifying_key, new_agent_signing_key) = test_keypair();
        let did = did_from_pubkey(&active_verifying_key);

        let mut actor_document =
            test_did_document_with_agent(&did, &active_verifying_key, &old_agent_verifying_key);
        actor_document
            .rotate_agent_key(new_agent_verifying_key.as_bytes(), 1)
            .expect("rotating an existing #agent key succeeds");

        let old_key_event = genesis_event(&did, &old_agent_signing_key);
        let error = verify_event_signature(&old_key_event, &actor_document)
            .expect_err("a retired #agent key verifies no event");
        assert!(
            matches!(error, EventLogError::InvalidSignature { .. }),
            "expected InvalidSignature, got {error:?}"
        );

        let new_key_event = genesis_event(&did, &new_agent_signing_key);
        verify_event_signature(&new_key_event, &actor_document)
            .expect("a current #agent key verifies an event");
    }

    #[test]
    fn verify_event_signature_rejects_key_recovered_from_the_did_string() {
        // Every DID string encodes an Identity Key (`#0`), which never
        // rotates. Here a signer holds exactly that key, while a document names
        // a different `#active` key. A verifier recovering its key from a DID
        // string would accept this event; one reading a document rejects it.
        let (identity_verifying_key, identity_signing_key) = test_keypair();
        let (active_verifying_key, _active_signing_key) = test_keypair();
        let did = format!(
            "did:dht:z{}",
            zbase32::encode(identity_verifying_key.as_bytes())
        );
        let actor_document = test_did_document(&did, &active_verifying_key);

        let event = genesis_event(&did, &identity_signing_key);

        let error = verify_event_signature(&event, &actor_document)
            .expect_err("a key recovered from a DID string verifies no event");
        assert!(
            matches!(error, EventLogError::InvalidSignature { .. }),
            "expected InvalidSignature, got {error:?}"
        );
    }

    #[test]
    fn verify_event_signature_rejects_document_whose_identity_key_derives_another_did() {
        // §3.8 and §9.6.1: a `did:dht` string is z-base-32 of an Identity Key.
        // A document naming a different `#0` describes a different identity,
        // and a caller who skipped BEP44 verification supplies exactly that.
        let (verifying_key, signing_key) = test_keypair();
        let did = did_from_pubkey(&verifying_key);
        let (foreign_verifying_key, _foreign_signing_key) = test_keypair();

        let mut actor_document = test_did_document(&did, &verifying_key);
        let identity_id = actor_document.verification_method_id("0");
        for method in &mut actor_document.verification_method {
            if method.id == identity_id {
                method.public_key_multibase = test_did_document(
                    &did_from_pubkey(&foreign_verifying_key),
                    &foreign_verifying_key,
                )
                .verification_method
                .iter()
                .find(|vm| vm.id.ends_with("#0"))
                .expect("a test document names #0")
                .public_key_multibase
                .clone();
            }
        }

        let error = verify_event_signature(&genesis_event(&did, &signing_key), &actor_document)
            .expect_err("a document naming a foreign #0 key describes another identity");
        match error {
            EventLogError::InvalidSignature { reason, .. } => assert!(
                reason.contains("derives some other DID"),
                "rejection names a self-certification failure: {reason}"
            ),
            other => panic!("expected InvalidSignature, got {other:?}"),
        }
    }

    #[test]
    fn verify_event_signature_rejects_document_describing_another_did() {
        let (verifying_key, signing_key) = test_keypair();
        let did = did_from_pubkey(&verifying_key);
        let (other_verifying_key, _other_signing_key) = test_keypair();
        let other_did = did_from_pubkey(&other_verifying_key);
        // A document below carries an event signer's own `#active` key, so
        // that signature alone would verify. Its `id` names a different DID,
        // which is what this rejection turns on.
        let foreign_document = test_did_document(&other_did, &verifying_key);

        let event = genesis_event(&did, &signing_key);

        let error = verify_event_signature(&event, &foreign_document)
            .expect_err("a document for another DID authorizes no event");
        match error {
            EventLogError::InvalidSignature { reason, .. } => assert!(
                reason.contains("not event actor"),
                "rejection names a mismatch: {reason}"
            ),
            other => panic!("expected InvalidSignature, got {other:?}"),
        }
    }

    #[test]
    fn verify_event_signature_rejects_document_carrying_no_operational_key() {
        let (verifying_key, signing_key) = test_keypair();
        let did = did_from_pubkey(&verifying_key);
        // Identity migration (§9.12) strips `#active` and `#agent` from an old
        // document, leaving `#0` plus retired keys.
        let mut migrated_document = test_did_document(&did, &verifying_key);
        migrated_document.retire_operational_keys_for_migration();

        let event = genesis_event(&did, &signing_key);

        let error = verify_event_signature(&event, &migrated_document)
            .expect_err("a document naming no operational key authorizes no event");
        match error {
            EventLogError::InvalidSignature { reason, .. } => assert!(
                reason.contains("#active verification method")
                    && reason.contains("#agent verification method")
                    && reason.contains("no method carries that identifier"),
                "rejection names both absent methods: {reason}"
            ),
            other => panic!("expected InvalidSignature, got {other:?}"),
        }
    }

    #[test]
    fn verify_event_signature_rejects_document_with_two_agent_keys() {
        let (active_verifying_key, _active_signing_key) = test_keypair();
        let (agent_verifying_key, agent_signing_key) = test_keypair();
        let did = did_from_pubkey(&active_verifying_key);
        let mut actor_document =
            test_did_document_with_agent(&did, &active_verifying_key, &agent_verifying_key);
        // ADR-039 permits exactly one `#agent` verification method, and tells a
        // verifier to reject a document carrying more.
        let duplicate_agent_method = actor_document
            .agent_verification_method()
            .expect("a test document names #agent")
            .clone();
        actor_document
            .verification_method
            .push(duplicate_agent_method);

        let event = genesis_event(&did, &agent_signing_key);

        let error = verify_event_signature(&event, &actor_document)
            .expect_err("a document with two #agent methods authorizes no event");
        match error {
            EventLogError::InvalidSignature { reason, .. } => assert!(
                reason.contains("malformed"),
                "rejection names a document defect: {reason}"
            ),
            other => panic!("expected InvalidSignature, got {other:?}"),
        }
    }

    #[test]
    fn verify_event_signature_rejects_one_key_published_under_both_fragments() {
        // ADR-039 gives `#active` to a human and `#agent` to agent software. An
        // owner publishing one key under both fragments makes a returned
        // `SigningKeyId` report `Active` for work agent software did, which is
        // exactly what ADR-039's accountability argument rests on separating.
        let (verifying_key, signing_key) = test_keypair();
        let did = did_from_pubkey(&verifying_key);
        let actor_document = test_did_document_with_agent(&did, &verifying_key, &verifying_key);

        let error = verify_event_signature(&genesis_event(&did, &signing_key), &actor_document)
            .expect_err("one key under both fragments identifies no holder");
        match error {
            EventLogError::InvalidSignature { reason, .. } => assert!(
                reason.contains("publishes one key under both"),
                "rejection names a duplicated key: {reason}"
            ),
            other => panic!("expected InvalidSignature, got {other:?}"),
        }
    }

    #[test]
    fn verify_event_batch_verifies_every_actor_against_its_own_document() {
        let (verifying_key_a, signing_key_a) = test_keypair();
        let did_a = did_from_pubkey(&verifying_key_a);
        let (verifying_key_b, signing_key_b) = test_keypair();
        let did_b = did_from_pubkey(&verifying_key_b);

        let mut actor_documents = BTreeMap::new();
        actor_documents.insert(did_a.clone(), test_did_document(&did_a, &verifying_key_a));
        actor_documents.insert(did_b.clone(), test_did_document(&did_b, &verifying_key_b));

        let events = vec![
            genesis_event(&did_a, &signing_key_a),
            genesis_event(&did_b, &signing_key_b),
        ];

        verify_event_batch(&events, &actor_documents)
            .expect("each event verifies against its own actor's document");
    }

    #[test]
    fn verify_event_signature_reports_which_method_verified() {
        let (active_verifying_key, active_signing_key) = test_keypair();
        let (agent_verifying_key, agent_signing_key) = test_keypair();
        let did = did_from_pubkey(&active_verifying_key);
        let actor_document =
            test_did_document_with_agent(&did, &active_verifying_key, &agent_verifying_key);

        assert_eq!(
            verify_event_signature(&genesis_event(&did, &active_signing_key), &actor_document)
                .unwrap(),
            SigningKeyId::Active
        );
        assert_eq!(
            verify_event_signature(&genesis_event(&did, &agent_signing_key), &actor_document)
                .unwrap(),
            SigningKeyId::Agent
        );
    }

    #[test]
    fn verify_event_signature_rejects_non_canonical_did_string() {
        // z-base-32 pads a 32-byte payload, so 16 encodings decode to one key.
        // `scp_did::extract_public_key_from_did` admits one canonical spelling;
        // a verifier that skipped that gate would let two DID strings address
        // one actor (§3.8.1).
        let (verifying_key, signing_key) = test_keypair();
        let canonical = did_from_pubkey(&verifying_key);
        let canonical_suffix = canonical
            .strip_prefix("did:dht:z")
            .expect("a test DID carries a did:dht:z prefix");
        let canonical_payload = crate::test_helpers::identity_key_from_did(&canonical);
        // A 32-byte payload occupies 255 bits of 52 z-base-32 characters, so a
        // final character carries 1 payload bit plus 4 padding bits. Sixteen
        // spellings decode to one key; every spelling except one that
        // re-encodes to itself is non-canonical.
        let non_canonical_suffix = "ybndrfg8ejkmcpqxot1uwisza345h769"
            .chars()
            .map(|candidate| {
                let mut characters: Vec<char> = canonical_suffix.chars().collect();
                let last = characters.len() - 1;
                characters[last] = candidate;
                characters.into_iter().collect::<String>()
            })
            .find(|candidate_suffix| {
                candidate_suffix != canonical_suffix
                    && zbase32::decode(candidate_suffix).as_deref()
                        == Ok(canonical_payload.as_slice())
            })
            .expect("z-base-32 padding admits a second spelling of one key");
        let non_canonical = format!("did:dht:z{non_canonical_suffix}");

        let actor_document = test_did_document(&non_canonical, &verifying_key);
        let event = genesis_event(&non_canonical, &signing_key);

        let error = verify_event_signature(&event, &actor_document)
            .expect_err("a non-canonical DID string authorizes no event");
        match error {
            EventLogError::InvalidSignature { reason, .. } => assert!(
                reason.contains("canonical"),
                "rejection names a canonicality failure: {reason}"
            ),
            other => panic!("expected InvalidSignature, got {other:?}"),
        }
    }

    #[test]
    fn verify_event_signature_rejects_method_another_did_controls() {
        let (verifying_key, signing_key) = test_keypair();
        let did = did_from_pubkey(&verifying_key);
        let (other_verifying_key, _other_signing_key) = test_keypair();
        let other_did = did_from_pubkey(&other_verifying_key);

        let mut actor_document = test_did_document(&did, &verifying_key);
        for method in &mut actor_document.verification_method {
            if method.id == actor_document.id.clone() + "#active" {
                method.controller = other_did.to_string();
            }
        }

        let error = verify_event_signature(&genesis_event(&did, &signing_key), &actor_document)
            .expect_err("a method another DID controls authorizes no event");
        match error {
            EventLogError::InvalidSignature { reason, .. } => assert!(
                reason.contains("controller"),
                "rejection names a controller mismatch: {reason}"
            ),
            other => panic!("expected InvalidSignature, got {other:?}"),
        }
    }

    #[test]
    fn verify_event_signature_rejects_method_absent_from_assertion_method() {
        let (verifying_key, signing_key) = test_keypair();
        let did = did_from_pubkey(&verifying_key);
        let mut actor_document = test_did_document(&did, &verifying_key);
        // An owner withdraws signing authority by dropping a reference from
        // `assertionMethod` while keeping a key readable for audit.
        actor_document.assertion_method.clear();

        let error = verify_event_signature(&genesis_event(&did, &signing_key), &actor_document)
            .expect_err("a key no assertionMethod reference covers signs no event");
        match error {
            EventLogError::InvalidSignature { reason, .. } => assert!(
                reason.contains("assertionMethod"),
                "rejection names an assertionMethod omission: {reason}"
            ),
            other => panic!("expected InvalidSignature, got {other:?}"),
        }
    }

    #[test]
    fn verify_event_signature_rejects_method_declaring_another_suite() {
        let (verifying_key, signing_key) = test_keypair();
        let did = did_from_pubkey(&verifying_key);
        let mut actor_document = test_did_document(&did, &verifying_key);
        let active_id = actor_document.verification_method_id("active");
        for method in &mut actor_document.verification_method {
            if method.id == active_id {
                method.method_type = "JsonWebKey2020".to_owned();
            }
        }

        let error = verify_event_signature(&genesis_event(&did, &signing_key), &actor_document)
            .expect_err("a method declaring another suite supplies no Ed25519 key");
        match error {
            EventLogError::InvalidSignature { reason, .. } => assert!(
                reason.contains("declares type"),
                "rejection names a type mismatch: {reason}"
            ),
            other => panic!("expected InvalidSignature, got {other:?}"),
        }
    }

    #[test]
    fn verify_event_signature_rejects_a_decoy_active_method_placed_first() {
        // A document listing a method identified by some other DID ahead of an
        // actor's own `#active` method must not shadow that real key, and must
        // not supply a foreign key either.
        let (verifying_key, signing_key) = test_keypair();
        let did = did_from_pubkey(&verifying_key);
        let (decoy_verifying_key, decoy_signing_key) = test_keypair();
        let decoy_did = did_from_pubkey(&decoy_verifying_key);

        let mut actor_document = test_did_document(&did, &verifying_key);
        let decoy = scp_did::VerificationMethod {
            id: format!("{decoy_did}#active"),
            method_type: scp_did::ED25519_VERIFICATION_KEY_TYPE.to_owned(),
            controller: decoy_did.to_string(),
            public_key_multibase: actor_document
                .verification_method
                .iter()
                .find(|vm| vm.id == actor_document.verification_method_id("active"))
                .expect("a test document names #active")
                .public_key_multibase
                .clone(),
        };
        actor_document.verification_method.insert(0, decoy);

        verify_event_signature(&genesis_event(&did, &signing_key), &actor_document)
            .expect("an actor's own #active key still verifies past a decoy entry");

        let error =
            verify_event_signature(&genesis_event(&did, &decoy_signing_key), &actor_document)
                .expect_err("a decoy key another DID identifies verifies no event");
        assert!(
            matches!(error, EventLogError::InvalidSignature { .. }),
            "expected InvalidSignature, got {error:?}"
        );
    }

    #[test]
    fn verify_event_signature_rejects_duplicate_active_methods() {
        // W3C DID Core §5.3.1 requires a unique verification-method identifier.
        // Two entries under one identifier leave array position deciding which
        // key verifies, so a document carrying both authorizes nothing.
        let (verifying_key, signing_key) = test_keypair();
        let did = did_from_pubkey(&verifying_key);
        let mut actor_document = test_did_document(&did, &verifying_key);
        let duplicate = actor_document
            .verification_method
            .iter()
            .find(|vm| vm.id == actor_document.verification_method_id("active"))
            .expect("a test document names #active")
            .clone();
        actor_document.verification_method.push(duplicate);

        let error = verify_event_signature(&genesis_event(&did, &signing_key), &actor_document)
            .expect_err("two #active entries authorize no event");
        match error {
            EventLogError::InvalidSignature { reason, .. } => assert!(
                reason.contains("no method carries that identifier"),
                "rejection reports an unusable method set: {reason}"
            ),
            other => panic!("expected InvalidSignature, got {other:?}"),
        }
    }

    #[test]
    fn verify_event_batch_rejects_an_actor_without_a_resolved_document() {
        let (verifying_key, signing_key) = test_keypair();
        let did = did_from_pubkey(&verifying_key);

        let events = vec![genesis_event(&did, &signing_key)];

        let error = verify_event_batch(&events, &BTreeMap::new())
            .expect_err("an unresolvable actor fails closed");
        match error {
            EventLogError::InvalidSignature { sequence, reason } => {
                assert_eq!(sequence, 0);
                assert!(
                    reason.contains("no resolved DID document"),
                    "rejection names a missing document: {reason}"
                );
            }
            other => panic!("expected InvalidSignature, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Helper: manually compute Merkle root from leaf hashes
    // -----------------------------------------------------------------------

    fn compute_root_manually(leaves: &[[u8; 32]]) -> [u8; 32] {
        if leaves.is_empty() {
            return empty_tree_root();
        }
        if leaves.len() == 1 {
            return leaves[0];
        }

        let mut current: Vec<[u8; 32]> = leaves.to_vec();
        while current.len() > 1 {
            let mut next = Vec::new();
            let mut i = 0;
            while i < current.len() {
                if i + 1 < current.len() {
                    next.push(hash_pair(&current[i], &current[i + 1]));
                } else {
                    // Odd node: promote directly per RFC 6962.
                    next.push(current[i]);
                }
                i += 2;
            }
            current = next;
        }
        current[0]
    }

    // -----------------------------------------------------------------------
    // length prefix prevents field boundary ambiguity
    // -----------------------------------------------------------------------

    #[test]
    fn length_prefix_prevents_field_boundary_ambiguity() {
        // Two events that differ only by shifting bytes between actor_did
        // and payload. Without length prefixes these would hash identically.
        let event_a = Event {
            event_type: EventType::MessageSent,
            actor_did: "did:key:AB".into(),
            timestamp: 1000,
            sequence: 0,
            payload: EventPayload {
                data: b"CD".to_vec(),
            },
            prev_hash: [0u8; 32],
            signature: Vec::new(),
        };

        let event_b = Event {
            event_type: EventType::MessageSent,
            actor_did: "did:key:ABC".into(),
            timestamp: 1000,
            sequence: 0,
            payload: EventPayload {
                data: b"D".to_vec(),
            },
            prev_hash: [0u8; 32],
            signature: Vec::new(),
        };

        let hash_a = compute_event_canonical_hash(&event_a);
        let hash_b = compute_event_canonical_hash(&event_b);

        assert_ne!(
            hash_a, hash_b,
            "shifting bytes between actor_did and payload must produce different hashes"
        );
    }

    // -----------------------------------------------------------------------
    // append_unsigned_event: happy path
    // -----------------------------------------------------------------------

    #[test]
    fn append_unsigned_event_records_leaf_and_updates_root() {
        let mut log = EventLog::new("ctx-unsigned-test".to_owned());

        let event = Event {
            event_type: EventType::OutletInvoked,
            actor_did: "did:dht:z6MkTest".into(),
            timestamp: 1_000_000,
            sequence: 0,
            payload: EventPayload {
                data: b"outlet invoked payload".to_vec(),
            },
            prev_hash: GENESIS_PREV_HASH,
            signature: Vec::new(), // No signature required.
        };

        let idx = append_unsigned_event(&mut log, &event).unwrap();
        assert_eq!(idx, 0);
        assert_eq!(event_count(&log), 1);
        assert_ne!(
            root(&log),
            [0u8; 32],
            "root should be non-zero after append"
        );

        // Verify leaf hash uses the RFC 6962 domain prefix.
        let serialized = rmp_serde::to_vec(&event).unwrap();
        let mut hasher = Sha256::new();
        hasher.update([0x00]);
        hasher.update(&serialized);
        let expected_leaf: [u8; 32] = hasher.finalize().into();
        assert_eq!(log.leaves()[0], expected_leaf);
    }

    // -----------------------------------------------------------------------
    // append_unsigned_event: sequential appends
    // -----------------------------------------------------------------------

    #[test]
    fn append_unsigned_event_sequential_appends() {
        let mut log = EventLog::new("ctx-unsigned-seq".to_owned());

        let event0 = Event {
            event_type: EventType::OutletInvoked,
            actor_did: "did:dht:z6MkTest".into(),
            timestamp: 1_000_000,
            sequence: 0,
            payload: EventPayload {
                data: b"first".to_vec(),
            },
            prev_hash: GENESIS_PREV_HASH,
            signature: Vec::new(),
        };

        let idx0 = append_unsigned_event(&mut log, &event0).unwrap();
        assert_eq!(idx0, 0);

        // Second event with correct prev_hash.
        let event1 = Event {
            event_type: EventType::OutletInvoked,
            actor_did: "did:dht:z6MkTest".into(),
            timestamp: 1_000_001,
            sequence: 1,
            payload: EventPayload {
                data: b"second".to_vec(),
            },
            prev_hash: log.leaves()[0],
            signature: Vec::new(),
        };

        let idx1 = append_unsigned_event(&mut log, &event1).unwrap();
        assert_eq!(idx1, 1);
        assert_eq!(event_count(&log), 2);
    }

    // -----------------------------------------------------------------------
    // append_unsigned_event: rejects wrong sequence
    // -----------------------------------------------------------------------

    #[test]
    fn append_unsigned_event_rejects_wrong_sequence() {
        let mut log = EventLog::new("ctx-unsigned-seq-err".to_owned());

        let event = Event {
            event_type: EventType::OutletInvoked,
            actor_did: "did:dht:z6MkTest".into(),
            timestamp: 1_000_000,
            sequence: 5, // Wrong: should be 0.
            payload: EventPayload {
                data: b"bad".to_vec(),
            },
            prev_hash: GENESIS_PREV_HASH,
            signature: Vec::new(),
        };

        let result = append_unsigned_event(&mut log, &event);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EventLogError::SequenceMismatch {
                expected: 0,
                actual: 5
            }
        ));
    }

    // -----------------------------------------------------------------------
    // append_unsigned_event: rejects wrong prev_hash
    // -----------------------------------------------------------------------

    #[test]
    fn append_unsigned_event_rejects_wrong_prev_hash() {
        let mut log = EventLog::new("ctx-unsigned-prev-err".to_owned());

        let event = Event {
            event_type: EventType::OutletInvoked,
            actor_did: "did:dht:z6MkTest".into(),
            timestamp: 1_000_000,
            sequence: 0,
            payload: EventPayload {
                data: b"bad".to_vec(),
            },
            prev_hash: [0xFF; 32], // Wrong: should be GENESIS_PREV_HASH.
            signature: Vec::new(),
        };

        let result = append_unsigned_event(&mut log, &event);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EventLogError::PrevHashMismatch { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // empty tree root matches spec §25.8 Vector 15: SHA-256("")
    // -----------------------------------------------------------------------

    #[test]
    fn empty_tree_root_is_sha256_of_empty_string() {
        let log = EventLog::new("ctx-empty-root".to_owned());
        let r = root(&log);

        // Spec §25.8 Vector 15: SHA-256("") =
        // e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let expected =
            hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .unwrap();

        assert_eq!(
            r.as_slice(),
            expected.as_slice(),
            "empty Merkle root must be SHA-256(\"\"), not [0u8; 32]"
        );

        // Must differ from GENESIS_PREV_HASH (which stays [0u8; 32]).
        assert_ne!(
            r, GENESIS_PREV_HASH,
            "empty root and genesis prev_hash must be distinct values"
        );
    }

    // -----------------------------------------------------------------------
    // Provenance event type tags (issue #586)
    // -----------------------------------------------------------------------

    #[test]
    fn provenance_event_type_tags_are_correct() {
        assert_eq!(event_type_tag(&EventType::ProvenanceAttached), 34);
        assert_eq!(event_type_tag(&EventType::ProvenanceReceived), 35);
    }

    // -----------------------------------------------------------------------
    // Closed-taxonomy tag invariants (ADR-011 typed-event unification):
    //   - tags 0-35 are protocol constants and MUST NOT change;
    //   - the 39 unification variants occupy tags 36..=75 with tag 59 retired
    //     (PseudonymAnnounced removed — a routing-bootstrap ContextEvent signal);
    //   - the 2 ADR-011 Amendment §6 cross-context-saga variants occupy 76..=77;
    //   - all 77 tags are distinct.
    // -----------------------------------------------------------------------

    /// The complete `EventType` taxonomy in ADR declaration order, used to
    /// cross-check against `event_type_tag`.
    const ALL_EVENT_TYPES: [EventType; 77] = [
        EventType::ContextCreated,
        EventType::ContextClosing,
        EventType::ContextClosed,
        EventType::ContextExpired,
        EventType::MemberJoined,
        EventType::MemberLeft,
        EventType::RoleAssigned,
        EventType::TokenRevoked,
        EventType::MessageSent,
        EventType::OutletRegistered,
        EventType::OutletUpdated,
        EventType::OutletInvoked,
        EventType::OutletVerified,
        EventType::OutletInterfaceEstablished,
        EventType::GovernanceAction,
        EventType::ConsistencyCheckpoint,
        EventType::AbsenceProofRequested,
        EventType::MemberBlocked,
        EventType::KeyEpochAdvance,
        EventType::MediaSessionStarted,
        EventType::MediaSessionEnded,
        EventType::PaymentReceived,
        EventType::EconomicPolicyChanged,
        EventType::EconomicPolicyApplied,
        EventType::SpendingUcanGranted,
        EventType::SpendingUcanRevoked,
        EventType::GovernanceProposalCreated,
        EventType::GovernanceVoteCast,
        EventType::GovernanceVoteWithdrawn,
        EventType::GovernanceProposalResolved,
        EventType::GovernanceConflictDetected,
        EventType::GovernanceConflictResolved,
        EventType::GovernanceDeadlockRecovery,
        EventType::GovernanceActionExecuted,
        EventType::ProvenanceAttached,
        EventType::ProvenanceReceived,
        EventType::AdminTransferred,
        EventType::CeilingModified,
        EventType::CeilingModificationPending,
        EventType::ThresholdModified,
        EventType::SignerAdded,
        EventType::SignerRemoved,
        EventType::ChildContextCreated,
        EventType::ContextPromoted,
        EventType::ContentKeysRotated,
        EventType::MemberReset,
        EventType::MemberSuspended,
        EventType::MemberSuspendedAll,
        EventType::MemberUnblocked,
        EventType::AccessRestored,
        EventType::GovernanceReconfigured,
        EventType::GovernanceFreezeExpired,
        EventType::HardRateLimitModified,
        EventType::EconomicPolicyLocked,
        EventType::ContextMigrationStarted,
        EventType::OutletRemoved,
        EventType::PruningPolicyModified,
        EventType::CommitBroadcasted,
        EventType::CommitBroadcastPending,
        EventType::ContextTombstoned,
        EventType::ContextMigrationCancelled,
        EventType::TtlExtended,
        EventType::TtlExtensionRejected,
        EventType::AccessRevoked,
        EventType::SpendApproved,
        EventType::PaymentCaptureFailed,
        EventType::ConsequenceTriggered,
        EventType::ConsequenceEnforced,
        EventType::ConsequenceEnforcementFailed,
        EventType::ConsequenceEscalatedToSuspendAll,
        EventType::CommitBroadcastSucceeded,
        EventType::CommitBroadcastFailed,
        EventType::RecoveryEpochAdvanced,
        EventType::AppBound,
        EventType::AppUnbound,
        EventType::CrossContextOutletInvoked,
        EventType::CrossContextDivergenceMarker,
    ];

    #[test]
    fn all_event_type_tags_are_distinct() {
        let mut tags: Vec<u16> = ALL_EVENT_TYPES.iter().map(event_type_tag).collect();
        assert_eq!(tags.len(), 77, "taxonomy must enumerate all 77 variants");
        tags.sort_unstable();
        tags.dedup();
        assert_eq!(
            tags.len(),
            77,
            "all 77 EventType tags must be distinct (no two variants share a tag)"
        );
        // Tag 59 is intentionally retired (PseudonymAnnounced removed); the tag
        // space is therefore 0..=75 minus {59}. This is the only gap.
        assert!(
            !tags.contains(&59),
            "tag 59 is retired and must not be reused (PseudonymAnnounced removal)"
        );
    }

    #[test]
    fn protocol_constant_tags_0_through_35_are_unchanged() {
        // These tags are wire-protocol constants. Changing any of them breaks
        // canonical hash compatibility with already-signed leaves. The
        // out-of-order assignments (EconomicPolicyApplied=33) are deliberate
        // historical gap fills and are pinned here.
        assert_eq!(event_type_tag(&EventType::ContextCreated), 0);
        assert_eq!(event_type_tag(&EventType::ContextClosing), 1);
        assert_eq!(event_type_tag(&EventType::ContextClosed), 2);
        assert_eq!(event_type_tag(&EventType::ContextExpired), 3);
        assert_eq!(event_type_tag(&EventType::MemberJoined), 4);
        assert_eq!(event_type_tag(&EventType::MemberLeft), 5);
        assert_eq!(event_type_tag(&EventType::RoleAssigned), 6);
        assert_eq!(event_type_tag(&EventType::TokenRevoked), 7);
        assert_eq!(event_type_tag(&EventType::MessageSent), 8);
        assert_eq!(event_type_tag(&EventType::OutletRegistered), 9);
        assert_eq!(event_type_tag(&EventType::OutletUpdated), 10);
        assert_eq!(event_type_tag(&EventType::OutletInvoked), 11);
        assert_eq!(event_type_tag(&EventType::OutletVerified), 12);
        assert_eq!(event_type_tag(&EventType::OutletInterfaceEstablished), 13);
        assert_eq!(event_type_tag(&EventType::GovernanceAction), 14);
        assert_eq!(event_type_tag(&EventType::ConsistencyCheckpoint), 15);
        assert_eq!(event_type_tag(&EventType::AbsenceProofRequested), 16);
        assert_eq!(event_type_tag(&EventType::MemberBlocked), 17);
        assert_eq!(event_type_tag(&EventType::KeyEpochAdvance), 18);
        assert_eq!(event_type_tag(&EventType::MediaSessionStarted), 19);
        assert_eq!(event_type_tag(&EventType::MediaSessionEnded), 20);
        assert_eq!(event_type_tag(&EventType::PaymentReceived), 21);
        assert_eq!(event_type_tag(&EventType::EconomicPolicyChanged), 22);
        assert_eq!(event_type_tag(&EventType::SpendingUcanGranted), 23);
        assert_eq!(event_type_tag(&EventType::SpendingUcanRevoked), 24);
        assert_eq!(event_type_tag(&EventType::GovernanceProposalCreated), 25);
        assert_eq!(event_type_tag(&EventType::GovernanceVoteCast), 26);
        assert_eq!(event_type_tag(&EventType::GovernanceVoteWithdrawn), 27);
        assert_eq!(event_type_tag(&EventType::GovernanceProposalResolved), 28);
        assert_eq!(event_type_tag(&EventType::GovernanceConflictDetected), 29);
        assert_eq!(event_type_tag(&EventType::GovernanceConflictResolved), 30);
        assert_eq!(event_type_tag(&EventType::GovernanceDeadlockRecovery), 31);
        assert_eq!(event_type_tag(&EventType::GovernanceActionExecuted), 32);
        assert_eq!(event_type_tag(&EventType::EconomicPolicyApplied), 33);
        assert_eq!(event_type_tag(&EventType::ProvenanceAttached), 34);
        assert_eq!(event_type_tag(&EventType::ProvenanceReceived), 35);
    }

    #[test]
    fn unification_variant_tags_occupy_36_through_77() {
        // The 39 typed-event unification variants occupy tags 36..=75 in ADR
        // declaration order, with tag 59 retired (PseudonymAnnounced removed).
        // The 2 ADR-011 Amendment §6 cross-context-saga variants occupy tags
        // 76..=77.
        assert_eq!(event_type_tag(&EventType::AdminTransferred), 36);
        assert_eq!(event_type_tag(&EventType::CeilingModified), 37);
        assert_eq!(event_type_tag(&EventType::CeilingModificationPending), 38);
        assert_eq!(event_type_tag(&EventType::ThresholdModified), 39);
        assert_eq!(event_type_tag(&EventType::SignerAdded), 40);
        assert_eq!(event_type_tag(&EventType::SignerRemoved), 41);
        assert_eq!(event_type_tag(&EventType::ChildContextCreated), 42);
        assert_eq!(event_type_tag(&EventType::ContextPromoted), 43);
        assert_eq!(event_type_tag(&EventType::ContentKeysRotated), 44);
        assert_eq!(event_type_tag(&EventType::MemberReset), 45);
        assert_eq!(event_type_tag(&EventType::MemberSuspended), 46);
        assert_eq!(event_type_tag(&EventType::MemberSuspendedAll), 47);
        assert_eq!(event_type_tag(&EventType::MemberUnblocked), 48);
        assert_eq!(event_type_tag(&EventType::AccessRestored), 49);
        assert_eq!(event_type_tag(&EventType::GovernanceReconfigured), 50);
        assert_eq!(event_type_tag(&EventType::GovernanceFreezeExpired), 51);
        assert_eq!(event_type_tag(&EventType::HardRateLimitModified), 52);
        assert_eq!(event_type_tag(&EventType::EconomicPolicyLocked), 53);
        assert_eq!(event_type_tag(&EventType::ContextMigrationStarted), 54);
        assert_eq!(event_type_tag(&EventType::OutletRemoved), 55);
        assert_eq!(event_type_tag(&EventType::PruningPolicyModified), 56);
        assert_eq!(event_type_tag(&EventType::CommitBroadcasted), 57);
        assert_eq!(event_type_tag(&EventType::CommitBroadcastPending), 58);
        // Tag 59 retired: PseudonymAnnounced removed (routing-bootstrap signal).
        assert_eq!(event_type_tag(&EventType::ContextTombstoned), 60);
        assert_eq!(event_type_tag(&EventType::ContextMigrationCancelled), 61);
        assert_eq!(event_type_tag(&EventType::TtlExtended), 62);
        assert_eq!(event_type_tag(&EventType::TtlExtensionRejected), 63);
        assert_eq!(event_type_tag(&EventType::AccessRevoked), 64);
        assert_eq!(event_type_tag(&EventType::SpendApproved), 65);
        assert_eq!(event_type_tag(&EventType::PaymentCaptureFailed), 66);
        assert_eq!(event_type_tag(&EventType::ConsequenceTriggered), 67);
        assert_eq!(event_type_tag(&EventType::ConsequenceEnforced), 68);
        assert_eq!(event_type_tag(&EventType::ConsequenceEnforcementFailed), 69);
        assert_eq!(
            event_type_tag(&EventType::ConsequenceEscalatedToSuspendAll),
            70
        );
        assert_eq!(event_type_tag(&EventType::CommitBroadcastSucceeded), 71);
        assert_eq!(event_type_tag(&EventType::CommitBroadcastFailed), 72);
        assert_eq!(event_type_tag(&EventType::RecoveryEpochAdvanced), 73);
        assert_eq!(event_type_tag(&EventType::AppBound), 74);
        assert_eq!(event_type_tag(&EventType::AppUnbound), 75);
        // Cross-context-saga carve-out (ADR-011 Amendment §6): the next free
        // tags after 75 (tag 59 stays retired).
        assert_eq!(event_type_tag(&EventType::CrossContextOutletInvoked), 76);
        assert_eq!(event_type_tag(&EventType::CrossContextDivergenceMarker), 77);
    }

    #[test]
    fn provenance_events_append_unsigned() {
        use crate::DID;

        let mut log = EventLog::new("ctx-prov-test".to_owned());

        // Append a ProvenanceAttached event.
        let event_attached = Event {
            event_type: EventType::ProvenanceAttached,
            actor_did: DID::from(
                "did:key:aabbccdd00112233445566778899aabbccdd00112233445566778899aabbccdd"
                    .to_owned(),
            ),
            timestamp: 1_000_000,
            sequence: 0,
            payload: EventPayload {
                data: vec![0xAA; 32], // Simulated SHA-256 hash of provenance record
            },
            prev_hash: GENESIS_PREV_HASH,
            signature: Vec::new(),
        };
        let idx = append_unsigned_event(&mut log, &event_attached).unwrap();
        assert_eq!(idx, 0);
        assert_eq!(event_count(&log), 1);

        // Append a ProvenanceReceived event.
        let prev = log.leaves()[0];
        let event_received = Event {
            event_type: EventType::ProvenanceReceived,
            actor_did: DID::from(
                "did:key:aabbccdd00112233445566778899aabbccdd00112233445566778899aabbccdd"
                    .to_owned(),
            ),
            timestamp: 1_000_001,
            sequence: 1,
            payload: EventPayload {
                data: vec![0xBB; 32],
            },
            prev_hash: prev,
            signature: Vec::new(),
        };
        let idx = append_unsigned_event(&mut log, &event_received).unwrap();
        assert_eq!(idx, 1);
        assert_eq!(event_count(&log), 2);

        // Verify events are retrievable.
        let retrieved_0 = log.get_event(0).unwrap();
        assert!(matches!(
            retrieved_0.event_type,
            EventType::ProvenanceAttached
        ));

        let retrieved_1 = log.get_event(1).unwrap();
        assert!(matches!(
            retrieved_1.event_type,
            EventType::ProvenanceReceived
        ));
    }
}
