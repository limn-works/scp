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

use sha2::{Digest, Sha256};

use super::{Event, EventLog, EventLogError, EventType};
use crate::crypto::ed25519::verify_ed25519_signature;

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
/// 3. Verifies the event signature against `event.actor_did`.
/// 4. Serializes the event and computes `leaf_hash = SHA-256(0x00 || serialize(event))`
///    (RFC 6962 Section 2.1 leaf domain separation).
/// 5. Appends the leaf hash and recomputes affected interior nodes.
/// 6. Inserts into the sorted leaf index.
/// 7. Returns the leaf index (position in the log).
///
/// # Errors
///
/// Returns [`EventLogError::SequenceMismatch`] if the sequence is wrong.
/// Returns [`EventLogError::PrevHashMismatch`] if the hash chain is broken.
/// Returns [`EventLogError::InvalidSignature`] if the signature is invalid.
/// Returns [`EventLogError::SerializationFailed`] if serialization fails.
///
/// See ADR-011 acceptance criterion 2.
pub fn append(log: &mut EventLog, event: &Event) -> Result<u64, EventLogError> {
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

    if event.prev_hash != expected_prev_hash {
        return Err(EventLogError::PrevHashMismatch {
            sequence: event.sequence,
        });
    }

    // 3. Verify signature.
    verify_event_signature(event)?;

    // 4. Serialize and hash with 0x00 leaf domain prefix (RFC 6962 §2.1).
    let serialized = serialize_event_for_hashing(event)?;
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(&serialized);
    let leaf_hash: [u8; 32] = hasher.finalize().into();

    // 5. Append leaf and recompute tree.
    let leaf_index = log.leaves.len() as u64;
    log.leaves.push(leaf_hash);
    recompute_tree(log);

    // 6. Insert into sorted index.
    log.sorted_leaves.insert((leaf_hash, leaf_index));

    Ok(leaf_index)
}

/// Appends an event to the event log **without** signature verification.
///
/// Performs the same sequence and `prev_hash` checks as [`append`], but skips
/// the Ed25519 signature verification step. Intended for trusted in-process
/// callers (FFI bridge layers, testing) where the event source is the process
/// itself and signing key material may not be available in the sync context.
///
/// The event is still serialized and hashed with the RFC 6962 leaf domain
/// prefix, so it produces the same leaf hash as a signed event with identical
/// content would.
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

    if event.prev_hash != expected_prev_hash {
        return Err(EventLogError::PrevHashMismatch {
            sequence: event.sequence,
        });
    }

    // 3. Serialize and hash with 0x00 leaf domain prefix (RFC 6962 §2.1).
    let serialized = serialize_event_for_hashing(event)?;
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(&serialized);
    let leaf_hash: [u8; 32] = hasher.finalize().into();

    // 4. Append leaf and recompute tree.
    let leaf_index = log.leaves.len() as u64;
    log.leaves.push(leaf_hash);
    recompute_tree(log);

    // 5. Insert into sorted index.
    log.sorted_leaves.insert((leaf_hash, leaf_index));

    Ok(leaf_index)
}

/// Returns the current Merkle root hash.
///
/// - If the log is empty, returns `[0u8; 32]`.
/// - If the log has one leaf, the root is that leaf hash.
/// - Otherwise, the root is the single element at the top interior layer.
///
/// This is O(1) -- the root is always maintained during appends.
///
/// See ADR-011 acceptance criterion 6.
#[must_use]
pub fn root(log: &EventLog) -> [u8; 32] {
    if log.leaves.is_empty() {
        return [0u8; 32];
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

/// Serializes an event for hashing. The signature field is excluded from
/// the hash computation to avoid circular dependency (the signature covers
/// the serialized content, and the hash covers the serialized event).
///
/// We serialize all fields except `signature` to produce a deterministic
/// byte sequence for hashing.
fn serialize_event_for_hashing(event: &Event) -> Result<Vec<u8>, EventLogError> {
    // We serialize the full event including signature for the leaf hash.
    // The leaf hash is a commitment to the complete event (including its
    // signature), which is the standard approach in event logs.
    rmp_serde::to_vec(event).map_err(|e| EventLogError::SerializationFailed(e.to_string()))
}

/// Verifies the Ed25519 signature of an event against the actor's DID.
///
/// The signature covers a canonical hash of all event fields except the
/// signature itself.
fn verify_event_signature(event: &Event) -> Result<(), EventLogError> {
    let public_key_bytes = extract_public_key_from_did(&event.actor_did).map_err(|reason| {
        EventLogError::InvalidSignature {
            sequence: event.sequence,
            reason,
        }
    })?;
    let canonical_hash = compute_event_canonical_hash(event);
    verify_ed25519_signature(&public_key_bytes, &canonical_hash, &event.signature).map_err(
        |reason| EventLogError::InvalidSignature {
            sequence: event.sequence,
            reason,
        },
    )
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
pub(crate) const fn event_type_tag(event_type: &EventType) -> u16 {
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
        EventType::ToolRegistered => 9,
        EventType::ToolUpdated => 10,
        EventType::ToolInvoked => 11,
        EventType::ToolVerified => 12,
        EventType::ToolInterfaceEstablished => 13,
        EventType::GovernanceAction => 14,
        EventType::ConsistencyCheckpoint => 15,
        EventType::AbsenceProofRequested => 16,
        EventType::MemberBlocked => 17,
        EventType::KeyEpochAdvance => 18,
        EventType::MediaSessionStarted => 19,
        EventType::MediaSessionEnded => 20,
        EventType::PaymentReceived => 21,
        EventType::EconomicPolicyChanged => 22,
        EventType::SpendingUcanGranted => 23,
        EventType::SpendingUcanRevoked => 24,
    }
}

/// Extracts the Ed25519 public key bytes from a DID string.
///
/// Supports `did:dht:z<z-base-32>` format (production). The `did:key:<hex>`
/// test convenience format is only accepted when compiled with `#[cfg(test)]`
/// or the `testing` feature to prevent non-standard DID acceptance in release
/// builds. See: <https://github.com/limn-works/scp/issues/128>
fn extract_public_key_from_did(did: &str) -> Result<[u8; 32], String> {
    // Support did:dht:z<z-base-32> format.
    if let Some(suffix) = did.strip_prefix("did:dht:z") {
        let decoded = zbase32::decode(suffix)
            .map_err(|_| format!("z-base-32 decode failed for DID: {did}"))?;
        let bytes: [u8; 32] = decoded
            .try_into()
            .map_err(|v: Vec<u8>| format!("DID public key must be 32 bytes, got {}", v.len()))?;
        return Ok(bytes);
    }

    // did:key:{hex} is a non-standard test convenience. Gated behind the
    // `testing` feature (or #[cfg(test)]) to prevent acceptance in release
    // builds. See: https://github.com/limn-works/scp/issues/128
    #[cfg(any(test, feature = "testing"))]
    if let Some(hex_str) = did.strip_prefix("did:key:") {
        let decoded = hex::decode(hex_str).map_err(|e| format!("hex decode error: {e}"))?;
        let bytes: [u8; 32] = decoded
            .try_into()
            .map_err(|v: Vec<u8>| format!("DID public key must be 32 bytes, got {}", v.len()))?;
        return Ok(bytes);
    }

    Err(format!("unsupported DID format: {did}"))
}

/// Recomputes the entire interior tree from the leaf layer.
///
/// This is called after every append. For a production implementation,
/// incremental recomputation would be preferred, but for Phase 2's in-memory
/// storage this full recomputation is acceptable and simpler to reason about.
///
/// RFC 6962 structure: if a layer has an odd number of nodes, the last node
/// is promoted (hashed with itself) to produce the parent.
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
                // Odd node: promote by hashing with itself per RFC 6962.
                parents.push(hash_pair(&current_layer[i], &current_layer[i]));
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
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
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
    use ed25519_dalek::Signer;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::event_log::{EventPayload, EventType};

    /// Helper: create a signing keypair and return (`verifying_key`, `signing_key`).
    fn test_keypair() -> (ed25519_dalek::VerifyingKey, ed25519_dalek::SigningKey) {
        let mut rng = rand::thread_rng();
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        (verifying_key, signing_key)
    }

    /// Helper: encode a public key as a test DID (`did:key:<hex>`).
    fn did_from_pubkey(verifying_key: &ed25519_dalek::VerifyingKey) -> String {
        let hex: String = verifying_key
            .as_bytes()
            .iter()
            .fold(String::new(), |mut acc, b| {
                use std::fmt::Write;
                let _ = write!(acc, "{b:02x}");
                acc
            });
        format!("did:key:{hex}")
    }

    /// Helper: sign an event and return the completed event.
    fn sign_event(
        event_type: EventType,
        actor_did: &str,
        timestamp: u64,
        sequence: u64,
        payload: Vec<u8>,
        prev_hash: [u8; 32],
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Event {
        let mut event = Event {
            event_type,
            actor_did: actor_did.into(),
            timestamp,
            sequence,
            payload: EventPayload { data: payload },
            prev_hash,
            signature: Vec::new(),
        };

        // Compute canonical hash and sign.
        let canonical_hash = compute_event_canonical_hash(&event);
        let signature = signing_key.sign(&canonical_hash);
        event.signature = signature.to_bytes().to_vec();

        event
    }

    /// Compute a leaf hash with the 0x00 domain separation prefix (RFC 6962).
    fn leaf_hash_from_event(event: &Event) -> [u8; 32] {
        let serialized = rmp_serde::to_vec(event).unwrap();
        let mut hasher = Sha256::new();
        hasher.update([0x00]);
        hasher.update(&serialized);
        hasher.finalize().into()
    }

    // -----------------------------------------------------------------------
    // append updates tree and root correctly
    // -----------------------------------------------------------------------

    #[test]
    fn append_updates_tree_and_root_correctly() {
        let (verifying_key, signing_key) = test_keypair();
        let did = did_from_pubkey(&verifying_key);
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

        let idx0 = append(&mut log, &event0).unwrap();
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

        let idx1 = append(&mut log, &event1).unwrap();
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
        append(&mut log, &event0).unwrap();

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

        let result = append(&mut log, &event1);
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

        let result = append(&mut log, &event0);
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

        let result = append(&mut log, &event0);
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
        let mut log = EventLog::new("ctx-test".to_owned());

        // Empty log root.
        assert_eq!(root(&log), [0u8; 32]);

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

            append(&mut log, &event).unwrap();

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

            append(&mut log, &event).unwrap();
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

        let result = append(&mut log, &event);
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

            append(&mut log, &event).unwrap();

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
            EventType::ToolRegistered,
            EventType::ToolUpdated,
            EventType::ToolInvoked,
            EventType::ToolVerified,
            EventType::ToolInterfaceEstablished,
            EventType::GovernanceAction,
            EventType::ConsistencyCheckpoint,
            EventType::AbsenceProofRequested,
            EventType::MemberBlocked,
            EventType::KeyEpochAdvance,
            EventType::MediaSessionStarted,
            EventType::MediaSessionEnded,
            EventType::PaymentReceived,
            EventType::EconomicPolicyChanged,
            EventType::SpendingUcanGranted,
            EventType::SpendingUcanRevoked,
        ];

        let mut prev_hash = GENESIS_PREV_HASH;
        for (i, event_type) in event_types.iter().enumerate() {
            let event = sign_event(
                event_type.clone(),
                &did,
                1_000_000 + i as u64,
                i as u64,
                format!("event {i}").into_bytes(),
                prev_hash,
                &signing_key,
            );

            let idx = append(&mut log, &event).unwrap();
            assert_eq!(idx, i as u64);

            let leaf_hash = leaf_hash_from_event(&event);
            prev_hash = leaf_hash;
        }

        assert_eq!(event_count(&log), 25);
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

        let idx = append(&mut log, &event).unwrap();
        assert_eq!(idx, 0);
    }

    // -----------------------------------------------------------------------
    // Helper: manually compute Merkle root from leaf hashes
    // -----------------------------------------------------------------------

    fn compute_root_manually(leaves: &[[u8; 32]]) -> [u8; 32] {
        if leaves.is_empty() {
            return [0u8; 32];
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
                    next.push(hash_pair(&current[i], &current[i]));
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
            event_type: EventType::ToolInvoked,
            actor_did: "did:dht:z6MkTest".into(),
            timestamp: 1_000_000,
            sequence: 0,
            payload: EventPayload {
                data: b"tool invoked payload".to_vec(),
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
            event_type: EventType::ToolInvoked,
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
            event_type: EventType::ToolInvoked,
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
            event_type: EventType::ToolInvoked,
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
            event_type: EventType::ToolInvoked,
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
}
