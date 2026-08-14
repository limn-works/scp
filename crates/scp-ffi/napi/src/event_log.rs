//! napi-rs bridge for event log operations.
//!
//! Exposes event log queries and Merkle proof verification:
//!
//! - `event_log_query` — Query the context event log with optional filters.
//! - `event_log_verify` — Verify a claim against the event log (Merkle proof).
//!
//! See ADR-011 (Event Log) and ADR-022 in `.docs/adrs/`.

use napi_derive::napi;
use scp_clock::Clock;
use scp_ffi_common::error_codes as codes;

use crate::context::NapiContextHandle;
use crate::error::ScpNapiError;
use crate::runtime::NapiBridgeInstance;

// ---------------------------------------------------------------------------
// NapiEvent — protocol event record
// ---------------------------------------------------------------------------

/// A protocol event from the context event log.
///
/// See ADR-011 (Event Log) and spec section 13 (Event Log).
#[napi(object)]
pub struct NapiEvent {
    /// The event type (e.g., `"ContextCreated"`, `"MessageSent"`, `"OutletInvoked"`).
    pub event_type: String,
    /// DID of the actor who produced this event.
    pub actor_did: String,
    /// Unix timestamp (seconds since epoch) when the event was created.
    pub timestamp: f64,
    /// Event-specific data serialized as a JSON string.
    pub payload_json: String,
    /// Monotonic sequence number within the log.
    pub sequence: f64,
}

// ---------------------------------------------------------------------------
// NapiProof — Merkle proof record
// ---------------------------------------------------------------------------

/// A Merkle proof from the event log.
///
/// # There is no `verified` field
///
/// This type used to carry `verified: bool`. It was a constant `true` on every
/// success path: the bridge generated the proof and then "verified" that same
/// proof against the same snapshot, so the check was tautological and only
/// `Ok`-vs-`Err` ever carried information. A boolean named `verified` that no
/// independent verifier computed is a false guarantee, so it is gone —
/// `event_log_verify` returning `Err` IS the negative answer.
///
/// Real verification is done by the recipient from `details_json`, which carries
/// the full Merkle material for both proof types: the leaf hash, the sibling
/// path with per-step direction, and the root the path reaches. An absence
/// answer carries the same complete material for BOTH bracketing neighbours.
///
/// # What an `"absence"` answer does and does not establish
///
/// The neighbour material lets a recipient check that both bracketing leaves
/// really are in the tree the reported `root` commits to, and that the queried
/// hash sorts strictly between them. It does NOT establish that the two
/// neighbours are ADJACENT in sorted order: the log's Merkle root commits to
/// append order, and the sorted index the neighbours are drawn from is local
/// state the root does not cover. Treat an `"absence"` answer as the log's own
/// assertion plus checkable neighbour-inclusion, not as a self-contained
/// non-membership proof (a sorted/sparse tree is the real fix — see #2314).
///
/// See ADR-011 (Event Log).
#[napi(object)]
pub struct NapiProof {
    /// The proof type: `"inclusion"` or `"absence"`.
    pub proof_type: String,
    /// Proof material serialized as a JSON string: the Merkle path (for
    /// inclusion proofs) or the two sorted neighbours with their own inclusion
    /// proofs (for absence proofs).
    pub details_json: String,
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Per-bridge-instance implementation of [`event_log_query`].
///
/// # The answer comes from the AUTHORITATIVE log only
///
/// Every event returned is a leaf of the supervisor's canonical event log — the
/// same source [`event_log_verify_on`] proves against and the checkpoint path
/// commits to. There is no UCAN-state fallback.
///
/// This function used to end
/// `supervisor(bi).ok().and_then(|s| s.event_log_entries(..).ok().flatten())`
/// and, on ANY failure or on an empty result, fall through to the per-context
/// UCAN-state `EventLog` — publishing THAT tree's root as `merkle_root` in a
/// synthesized `LogSummary` event, under the same field name the authoritative
/// answers use. Two consequences (GitHub #1933): a consumer pinning a verify
/// proof against a queried root could accept a root a caller had shaped through
/// `provenance_attach` / outlet calls; and `entries.is_empty() -> fall through`
/// collapsed the empty-but-live vs unknown distinction, so query and verify
/// returned contradictory answers about the same context.
///
/// Now: an empty-but-live log returns an EMPTY list, and an unreachable or
/// unknown log FAILS CLOSED with [`codes::CTX_2138`].
#[allow(clippy::unused_async)] // napi-rs requires async for Promise return
pub(crate) async fn event_log_query_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
    filter_json: Option<String>,
) -> napi::Result<Vec<NapiEvent>> {
    crate::napi_check_handle!(&bi.core, handle);

    let filter: Option<serde_json::Value> = match filter_json {
        Some(ref json_str) => {
            let parsed: serde_json::Value =
                serde_json::from_str(json_str).map_err(|e| ScpNapiError::Validation {
                    message: format!("filter_json is not valid JSON: {e}"),
                    code: codes::VALID_7000.to_owned(),
                })?;
            Some(parsed)
        }
        None => None,
    };

    #[allow(clippy::cast_possible_truncation)] // Event limit is always small; truncation is safe.
    let limit = filter
        .as_ref()
        .and_then(|f| f.get("limit"))
        .and_then(serde_json::Value::as_u64)
        .map(|l| l as usize);

    let event_type_filter = filter
        .as_ref()
        .and_then(|f| f.get("event_type").or_else(|| f.get("eventType")))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let actor_did_filter = filter
        .as_ref()
        .and_then(|f| f.get("actor_did").or_else(|| f.get("actorDid")))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let after_sequence_filter = filter
        .as_ref()
        .and_then(|f| f.get("after_sequence").or_else(|| f.get("afterSequence")))
        .and_then(serde_json::Value::as_u64);
    let before_sequence_filter = filter
        .as_ref()
        .and_then(|f| f.get("before_sequence").or_else(|| f.get("beforeSequence")))
        .and_then(serde_json::Value::as_u64);

    let context_id = handle.context_id();

    // Same fail-closed gate as `event_log_verify_on` / the checkpoint path.
    bi.core
        .check_ready()
        .map_err(|e| authoritative_log_unreachable("query", &context_id, &e))?;
    let supervisor = crate::runtime::supervisor(bi)
        .map_err(|e| authoritative_log_unreachable("query", &context_id, &e))?;

    // ADR-056: resolve the context-id string to its 32-byte digest via the
    // canonical chokepoint (NOT the raw SHA-256 routing primitive, which
    // double-hashes a real 64-hex id and queries the wrong event-log key).
    let ctx_id_bytes = scp_core::context::state::context_id_to_bytes(&context_id);
    let entries = supervisor
        .event_log_entries(&ctx_id_bytes)
        .map_err(|e| authoritative_log_unreachable("query", &context_id, &e))?
        // `None` means UNKNOWN — never initialised, or destroyed on actor
        // shutdown / create-rollback. An empty-but-live log is
        // `Ok(Some(vec![]))` and returns an empty list below.
        .ok_or_else(|| {
            authoritative_log_unreachable("query", &context_id, &"no event log for this context")
        })?;

    // Canonical filter — pinned across PyO3/NAPI/UniFFI by
    // `scp_ffi_common::event_log::filter_manager_entries` so the three
    // bridges cannot drift on `after_sequence` / `before_sequence` /
    // `event_type` / `actor_did` / `limit`. Each bridge still owns its
    // `Event`/`NapiEvent`/`PyEvent` mapping; the helper only encodes the
    // filter contract. Filter semantics: `after_sequence` /
    // `before_sequence` exclusive on both ends (matches UniFFI reference).
    let filter = scp_ffi_common::event_log::EventLogFilter {
        after_sequence: after_sequence_filter,
        before_sequence: before_sequence_filter,
        event_type: event_type_filter.as_deref(),
        actor_did: actor_did_filter.as_deref(),
        limit,
    };
    let filtered = scp_ffi_common::event_log::filter_manager_entries(&entries, &filter);

    let mut events: Vec<NapiEvent> = Vec::with_capacity(filtered.len());
    for (seq, entry) in filtered {
        let leaf_hash = scp_event_log::tree::leaf_hash(entry).map_err(|e| {
            napi::Error::from(ScpNapiError::Context {
                message: format!("event leaf hash failed: {e}"),
                code: codes::CTX_2000.to_owned(),
            })
        })?;
        // Project the typed payload's bridge-facing fields (e.g.
        // `target_did` for governance/access-revocation events,
        // `subject_did` for role/membership events) through the single
        // shared `scp_event_log::payload::project_payload` decoder (via the
        // `inject_projection` helper) so all three native bridges surface
        // byte-identical values. Each key is omitted when the projection
        // yields `None`.
        let mut payload_value = serde_json::json!({
            "hash": hex::encode(leaf_hash),
        });
        scp_ffi_common::event_log::inject_projection(
            &mut payload_value,
            &entry.event_type,
            &entry.payload,
        );
        #[allow(clippy::cast_precision_loss)]
        events.push(NapiEvent {
            event_type: scp_ffi_common::event_log::event_type_label(&entry.event_type),
            actor_did: entry.actor_did.0.clone(),
            timestamp: entry.timestamp as f64,
            payload_json: payload_value.to_string(),
            sequence: seq as f64,
        });
    }

    Ok(events)
}

/// Maps a runtime authoritative-log failure into the fail-closed bridge error.
///
/// GitHub #1933. Raised when the bridge cannot reach the context's
/// AUTHORITATIVE event log at all — the instance is not ready (suspended or
/// shut down), no supervisor / event-log provider is attached, or the provider
/// reports NO LOG for the context (`Ok(None)`, which means UNKNOWN — a log
/// destroyed on actor shutdown or create-rollback reads exactly the same as one
/// that never existed; an empty-but-live log is `Ok(Some(vec![]))`).
///
/// Neither verification nor checkpointing may fall back to the UCAN-state tree
/// here: an absence proof over a non-authoritative or unknown log is a forgeable
/// FALSE NEGATIVE, and a checkpoint over one is a validly-SIGNED false
/// commitment.
///
/// `operation` names the refused operation ("verification" / "checkpointing") so
/// the message identifies which surface failed closed.
fn authoritative_log_unreachable(
    operation: &str,
    context_id: &str,
    detail: &impl std::fmt::Display,
) -> napi::Error {
    napi::Error::from(ScpNapiError::Context {
        message: format!(
            "event log {operation} cannot reach the authoritative log for context \
             '{context_id}': {detail}"
        ),
        code: codes::CTX_2138.to_owned(),
    })
}

/// Per-bridge-instance implementation of [`event_log_verify`].
///
/// # The proof is generated against the AUTHORITATIVE log
///
/// Both proof types are generated from ONE `Supervisor::authoritative_event_log`
/// snapshot — the runtime's single proof seam, replayed from the supervisor's
/// own canonical event log, the same source [`event_log_query`] reads. This
/// function NEVER reads or mutates the per-context UCAN-state `EventLog`
/// (`NapiContextRuntime::core.event_log`), a separate tree holding only
/// bridge-local records whose leaves a caller can influence; proving over it
/// produced forgeable absence AND inclusion results (GitHub #1933).
///
/// Because the proof and the reported `(leaf_count, root)` commitment come from
/// that ONE snapshot, they describe the same tree state by construction — a
/// relying party can pin the proof against the commitment beside it. Taking
/// them from two snapshots would let a concurrent append separate them, and a
/// root paired with another snapshot's leaf count commits to nothing.
///
/// # Errors
///
/// Returns [`codes::CTX_2138`] when the authoritative log is unreachable (the
/// instance is suspended or shut down, no supervisor is attached, or the
/// provider reports NO LOG for the context). FAILS CLOSED: it never falls back
/// to the UCAN-state tree. Proof-generation failures over a readable log (empty
/// log, out-of-range index, absence claimed for a present event) keep
/// [`codes::CTX_2139`].
#[allow(clippy::unused_async)] // napi-rs requires async for Promise return
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned String
#[allow(clippy::too_many_lines)] // Proof generation with match arms is inherently verbose.
pub(crate) async fn event_log_verify_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
    claim_json: String,
) -> napi::Result<NapiProof> {
    crate::napi_check_handle!(&bi.core, handle);
    // NO `ensure_registered` here. It ran BEFORE the `check_ready` gate below
    // and INSERTS a `UcanContextState` when absent, so a not-ready instance
    // mutated the registry before failing closed — and verification was not
    // read-only, contradicting the contract 001c38544 established. It also
    // served no purpose once proofs stopped reading the UCAN-state tree.
    // Matches PyO3, which touches no bridge-local state on this path.

    let claim: serde_json::Value =
        serde_json::from_str(&claim_json).map_err(|e| ScpNapiError::Validation {
            message: format!("claim_json is not valid JSON: {e}"),
            code: codes::VALID_7000.to_owned(),
        })?;

    // DELIBERATE ordering (black-hat NIT, #1933): the invalid-JSON and
    // missing/invalid-`type` checks run BEFORE the `check_ready`/authoritative-log
    // gate below, on purpose — rejecting obviously-malformed claim shape is cheap,
    // and a claim we cannot even parse or type cannot be answered against any log.
    // The resulting self-oracle (a malformed-`type` claim on a not-ready instance
    // returns VALID-7000 while a well-formed one returns CTX-2138) is benign: the
    // caller crafted the malformed type and can already probe readiness with a
    // well-formed claim, so the malformed path leaks strictly less. The remaining
    // VALID-7000 sites (missing `leaf_index`, malformed `event_hash`, unsupported
    // type) sit AFTER the gate, so an unreachable log surfaces CTX-2138 first for
    // those — the documented precedence.
    let claim_type = claim
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ScpNapiError::Validation {
            message: "claim must include 'type' field ('inclusion' or 'absence')".to_owned(),
            code: codes::VALID_7000.to_owned(),
        })
        .map_err(napi::Error::from)?;

    let context_id = handle.context_id();

    // #1933 fail-closed gate. `check_ready` rejects BOTH suspended and
    // shut-down instances (`supervisor()` only rejects suspended, and merely
    // warns after shutdown — while a shut-down context's authoritative log has
    // typically been destroyed).
    bi.core
        .check_ready()
        .map_err(|e| authoritative_log_unreachable("verification", &context_id, &e))?;
    let supervisor = crate::runtime::supervisor(bi)
        .map_err(|e| authoritative_log_unreachable("verification", &context_id, &e))?;

    // The ONE authoritative snapshot every answer below is derived from. Its
    // failure is the only "cannot answer" case (CTX-2138), which keeps it
    // distinct from "the claim is false" (a proof error over a readable log).
    let log = supervisor
        .authoritative_event_log(&context_id)
        .map_err(|e| authoritative_log_unreachable("verification", &context_id, &e))?;
    let leaf_count = scp_event_log::tree::event_count(&log);

    match claim_type {
        "inclusion" => {
            let leaf_index = claim
                .get("leaf_index")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| ScpNapiError::Validation {
                    message: "inclusion claim must include 'leaf_index' (integer)".to_owned(),
                    code: codes::VALID_7000.to_owned(),
                })
                .map_err(napi::Error::from)?;

            let proof = scp_event_log::proof::prove_inclusion(&log, leaf_index).map_err(|e| {
                napi::Error::from(ScpNapiError::Context {
                    message: format!("inclusion proof failed: {e}"),
                    code: codes::CTX_2139.to_owned(),
                })
            })?;
            let mut details = scp_ffi_common::event_log::inclusion_proof_json(&proof);
            if let Some(obj) = details.as_object_mut() {
                obj.insert("leaf_count".to_owned(), leaf_count.into());
            }

            Ok(NapiProof {
                proof_type: "inclusion".to_owned(),
                details_json: details.to_string(),
            })
        }
        "absence" => {
            let event_hash_hex = claim
                .get("event_hash")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ScpNapiError::Validation {
                    message: "absence claim must include 'event_hash' (hex string)".to_owned(),
                    code: codes::VALID_7000.to_owned(),
                })
                .map_err(napi::Error::from)?;

            let event_hash = decode_hex_hash(event_hash_hex).map_err(|e| {
                napi::Error::from(ScpNapiError::Validation {
                    message: format!("invalid event_hash: {e}"),
                    code: codes::VALID_7000.to_owned(),
                })
            })?;

            let proof = scp_event_log::proof::prove_absence(&log, &event_hash).map_err(|e| {
                napi::Error::from(ScpNapiError::Context {
                    message: format!("absence proof failed: {e}"),
                    code: codes::CTX_2139.to_owned(),
                })
            })?;

            // Both bracketing neighbours ship their FULL inclusion proofs
            // (sibling path + root), so the neighbour-inclusion half of the
            // claim is checkable off-box against the reported `root`. Shipping
            // only `leaf_hash` + `leaf_index` — as this arm used to — left the
            // recipient nothing to check while the response still carried a
            // producer-set `verified` flag.
            let details = serde_json::json!({
                "query_hash": hex::encode(proof.query_hash),
                "root": hex::encode(proof.root),
                "leaf_count": proof.leaf_count,
                "lower": scp_ffi_common::event_log::absence_neighbor_json(proof.lower.as_ref()),
                "upper": scp_ffi_common::event_log::absence_neighbor_json(proof.upper.as_ref()),
            });

            Ok(NapiProof {
                proof_type: "absence".to_owned(),
                details_json: details.to_string(),
            })
        }
        other => Err(ScpNapiError::Validation {
            message: format!("unsupported claim type '{other}': expected 'inclusion' or 'absence'"),
            code: codes::VALID_7000.to_owned(),
        }
        .into()),
    }
}

// ---------------------------------------------------------------------------
// NapiCheckpoint — consistency checkpoint record
// ---------------------------------------------------------------------------

/// A signed consistency checkpoint from the context event log.
///
/// See ADR-011 acceptance criterion 8 and ADR-030.
#[napi(object)]
pub struct NapiCheckpoint {
    /// The context this checkpoint belongs to.
    pub context_id: String,
    /// The DID of the member who generated this checkpoint.
    pub sender_did: String,
    /// The number of events in the log at checkpoint time.
    pub event_count: f64,
    /// The Merkle root hash at checkpoint time, hex-encoded.
    pub merkle_root: String,
    /// Current MLS epoch. `null` for Broadcast contexts.
    pub epoch: Option<f64>,
    /// Unix timestamp (seconds) when the checkpoint was generated.
    pub timestamp: f64,
    /// Ed25519 signature over the canonical checkpoint fields, hex-encoded.
    pub signature: String,
}

/// Builds the unsigned §9.9.3 checkpoint over the AUTHORITATIVE event log.
///
/// Shared by both checkpoint entry points so they cannot drift on WHICH log the
/// signed commitment is taken over — the bridge entry points differ only in how
/// they resolve key material.
///
/// # The commitment is taken over the AUTHORITATIVE log
///
/// The `(event_count, merkle_root)` pair comes from ONE
/// `Supervisor::unsigned_authoritative_checkpoint` snapshot — the same single
/// proof seam [`event_log_verify_on`] uses. This NEVER reads the per-context
/// UCAN-state `EventLog` (`NapiContextRuntime::core.event_log`).
///
/// A checkpoint is signed, non-repudiable evidence: a peer that sees the same
/// `event_count` with a different `merkle_root` raises `EquivocationDetected`
/// against its signer (§9.9.3). Signing over the UCAN-state tree — whose leaves
/// a caller shapes at will through ordinary `provenance_attach` /
/// `media_session_start` / outlet calls — let ANY member mint validly-signed
/// equivocation evidence against honest peers, and left honest members'
/// checkpoints simply wrong about their own history (GitHub #1933).
///
/// # Errors
///
/// Returns [`codes::CTX_2138`] when the authoritative log is unreachable (the
/// instance is suspended or shut down, no supervisor is attached, or the
/// provider reports NO LOG for the context). FAILS CLOSED: no checkpoint is
/// signed at all, because an absent checkpoint is an honest, detectable state
/// while a signed fabricated commitment is not.
fn unsigned_authoritative_checkpoint(
    bi: &NapiBridgeInstance,
    context_id: &str,
    sender_did: &scp_did::DID,
    epoch: u64,
) -> napi::Result<scp_event_log::checkpoint::UnsignedCheckpoint> {
    // #1933 fail-closed gate, identical to `event_log_verify_on`. `check_ready`
    // rejects BOTH suspended and shut-down instances (`supervisor()` only
    // rejects suspended, and merely warns after shutdown — while a shut-down
    // context's authoritative log has typically been destroyed).
    bi.core
        .check_ready()
        .map_err(|e| authoritative_log_unreachable("checkpointing", context_id, &e))?;
    let supervisor = crate::runtime::supervisor(bi)
        .map_err(|e| authoritative_log_unreachable("checkpointing", context_id, &e))?;

    // ONE authoritative snapshot: `event_count` and `merkle_root` are taken
    // together so the SIGNED pair describes one tree state by construction.
    supervisor
        .unsigned_authoritative_checkpoint(
            context_id,
            sender_did,
            Some(epoch),
            scp_clock::SystemClock.now_secs(),
        )
        .map_err(|e| authoritative_log_unreachable("checkpointing", context_id, &e))
}

/// Signs an unsigned checkpoint with retained key custody and maps it to the
/// bridge record.
///
/// `generate_checkpoint`'s signing step is async — these sync NAPI functions run
/// on a libuv worker thread (not inside tokio), so the stored runtime drives it.
fn sign_checkpoint(
    unsigned: scp_event_log::checkpoint::UnsignedCheckpoint,
    custody: &crate::custody::NapiKeyCustody,
    key: scp_platform::traits::KeyHandle,
) -> napi::Result<NapiCheckpoint> {
    let checkpoint = crate::runtime()
        .block_on(async {
            let signer = scp_core::event_log::KeyCustodySigner { custody, key: &key };
            unsigned.sign_with(&signer).await
        })
        .map_err(|e| {
            napi::Error::from(ScpNapiError::Context {
                message: format!("checkpoint generation failed: {e}"),
                code: codes::CTX_2023.to_owned(),
            })
        })?;

    #[allow(clippy::cast_precision_loss)]
    Ok(NapiCheckpoint {
        context_id: checkpoint.context_id,
        sender_did: checkpoint.sender_did.0,
        event_count: checkpoint.event_count as f64,
        merkle_root: hex::encode(checkpoint.merkle_root),
        epoch: checkpoint.epoch.map(|e| e as f64),
        timestamp: checkpoint.timestamp as f64,
        signature: hex::encode(checkpoint.signature),
    })
}

/// Per-bridge-instance implementation of [`event_log_checkpoint`].
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned types
pub(crate) fn event_log_checkpoint_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
    identity: &crate::identity::NapiIdentity,
    epoch: f64,
) -> napi::Result<NapiCheckpoint> {
    crate::napi_check_handle!(&bi.core, handle, identity);

    let custody = identity.inner.in_memory_custody.as_ref().ok_or_else(|| {
        napi::Error::from(ScpNapiError::Identity {
            message: "event log checkpoint requires retained signing custody — this identity \
                      has no retained custody (it was externally loaded)"
                .to_owned(),
            code: codes::IDENT_1017.to_owned(),
        })
    })?;
    let scp_id = identity.inner.scp_identity.as_ref().ok_or_else(|| {
        napi::Error::from(ScpNapiError::Identity {
            message: "event log checkpoint requires retained identity state — the identity \
                      was externally loaded"
                .to_owned(),
            code: codes::IDENT_1007.to_owned(),
        })
    })?;

    let context_id = handle.context_id();
    let sender_did = scp_did::DID(identity.inner.did.clone());
    let epoch_u64 = validate_non_negative_epoch(epoch)?;

    let unsigned = unsigned_authoritative_checkpoint(bi, &context_id, &sender_did, epoch_u64)?;
    sign_checkpoint(unsigned, custody.as_ref(), scp_id.active_signing_key)
}

/// Per-bridge-instance implementation of [`event_log_checkpoint_by_did`].
#[allow(clippy::needless_pass_by_value)] // napi-rs requires owned types
pub(crate) fn event_log_checkpoint_by_did_on(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
    did: String,
    epoch: f64,
) -> napi::Result<NapiCheckpoint> {
    crate::napi_check_handle!(&bi.core, handle);

    let (scp_id, custody) = crate::runtime::with_identity(bi, &did, |entry| {
        Ok((
            entry.identity.clone(),
            std::sync::Arc::clone(&entry.custody),
        ))
    })
    .map_err(napi::Error::from)?;

    let context_id = handle.context_id();
    let sender_did = scp_did::DID(did);
    let epoch_u64 = validate_non_negative_epoch(epoch)?;

    let unsigned = unsigned_authoritative_checkpoint(bi, &context_id, &sender_did, epoch_u64)?;
    sign_checkpoint(unsigned, custody.as_ref(), scp_id.active_signing_key)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Validates that an f64 epoch value is non-negative and returns it as u64.
///
/// Returns `napi::Error` with `SCP-VALID-7040` if the value is negative.
fn validate_non_negative_epoch(epoch: f64) -> napi::Result<u64> {
    if epoch < 0.0 || !epoch.is_finite() {
        return Err(napi::Error::from(ScpNapiError::Validation {
            message: format!("epoch must be non-negative, got {epoch}"),
            code: codes::VALID_7040.to_owned(),
        }));
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Ok(epoch as u64)
}

/// Decodes a hex string into a 32-byte hash.
///
/// Used by absence proof verification to decode the `event_hash` field from
/// the claim JSON. Rejects strings that are not exactly 64 hex characters
/// (32 bytes).
#[allow(dead_code)] // Will be used when event_log_verify is wired to scp-core.
pub(crate) fn decode_hex_hash(hex: &str) -> Result<[u8; 32], String> {
    if hex.len() != 64 {
        return Err(format!(
            "expected 64 hex characters (32 bytes), got {}",
            hex.len()
        ));
    }

    let mut bytes = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).map_err(|_| "invalid UTF-8 in hex string".to_owned())?;
        bytes[i] =
            u8::from_str_radix(s, 16).map_err(|e| format!("hex decode error at byte {i}: {e}"))?;
    }
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use scp_ffi_common::error_codes as codes;

    // -----------------------------------------------------------------------
    // decode_hex_hash
    // -----------------------------------------------------------------------

    #[test]
    fn decode_hex_hash_valid_32_bytes() {
        // 64 hex characters representing 32 zero bytes.
        let hex = "0".repeat(64);
        let result = decode_hex_hash(&hex).unwrap();
        assert_eq!(result, [0u8; 32]);
    }

    #[test]
    fn decode_hex_hash_valid_nonzero() {
        // Known 32-byte value encoded as hex.
        let mut expected = [0u8; 32];
        expected[0] = 0xab;
        expected[1] = 0xcd;
        expected[31] = 0xef;
        let hex = format!("abcd{}ef", "00".repeat(29));
        let result = decode_hex_hash(&hex).unwrap();
        assert_eq!(result, expected);
    }

    // -----------------------------------------------------------------------
    // Missing-signing-custody → SCP-IDENT-1017
    //
    // An identity that retains no custody (externally loaded: `in_memory_custody`
    // is `None`) must reject an event-log checkpoint with the canonical
    // missing-signing-custody code.
    // -----------------------------------------------------------------------

    #[test]
    fn event_log_checkpoint_without_retained_custody_returns_ident_1017() {
        let bi = std::sync::Arc::new(crate::runtime::NapiBridgeInstance::new_napi());
        let instance_id = bi.instance_id();
        let handle = crate::context::NapiContextHandle::test_active_on(
            &bi,
            "ctx-no-custody-checkpoint".to_owned(),
            "did:dht:z6MkCreatorNoCustody".to_owned(),
        );

        // Externally-loaded identity: no retained custody, no signing key state.
        let identity = crate::identity::NapiIdentity {
            inner: std::sync::Arc::new(crate::identity::NapiIdentityInner {
                did: "did:dht:z6MkCreatorNoCustody".to_owned(),
                custody_type: "external".to_owned(),
                scp_identity: None,
                in_memory_custody: None,
                document: None,
                bi: std::sync::Arc::clone(&bi),
                verifying_key_hex: None,
                instance_id,
                rotation_event_json: None,
            }),
        };

        let Err(err) = event_log_checkpoint_on(&bi, &handle, &identity, 1.0) else {
            panic!("checkpoint without retained custody must fail")
        };
        let reason = err.reason.clone();
        assert!(
            reason.contains("SCP-IDENT-1017"),
            "expected SCP-IDENT-1017, got: {reason}"
        );
    }

    #[test]
    fn decode_hex_hash_rejects_short_input() {
        // 62 hex chars (31 bytes) — too short.
        let hex = "ab".repeat(31);
        let result = decode_hex_hash(&hex);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("expected 64 hex characters"),
            "error should mention expected length, got: {err}"
        );
    }

    #[test]
    fn decode_hex_hash_rejects_long_input() {
        // 66 hex chars (33 bytes) — too long.
        let hex = "ab".repeat(33);
        let result = decode_hex_hash(&hex);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("expected 64 hex characters"),
            "error should mention expected length, got: {err}"
        );
    }

    #[test]
    fn decode_hex_hash_rejects_non_hex_characters() {
        // 64 characters but containing 'gg' which is not valid hex.
        let hex = format!("gg{}", "00".repeat(31));
        let result = decode_hex_hash(&hex);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("hex decode error"),
            "error should mention hex decode failure, got: {err}"
        );
    }

    #[test]
    fn decode_hex_hash_rejects_empty_input() {
        let result = decode_hex_hash("");
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // validate_non_negative_epoch
    // -----------------------------------------------------------------------

    #[test]
    fn validate_epoch_accepts_zero() {
        assert_eq!(validate_non_negative_epoch(0.0).unwrap(), 0);
    }

    #[test]
    fn validate_epoch_accepts_positive() {
        assert_eq!(validate_non_negative_epoch(42.0).unwrap(), 42);
    }

    #[test]
    fn validate_epoch_rejects_negative() {
        let result = validate_non_negative_epoch(-1.0);
        assert!(result.is_err(), "negative epoch should error");
    }

    #[test]
    fn validate_epoch_rejects_negative_infinity() {
        let result = validate_non_negative_epoch(f64::NEG_INFINITY);
        assert!(result.is_err(), "NEG_INFINITY epoch should error");
    }

    #[test]
    fn validate_epoch_rejects_f64_min() {
        let result = validate_non_negative_epoch(f64::MIN);
        assert!(result.is_err(), "f64::MIN epoch should error");
    }

    #[test]
    fn validate_epoch_negative_error_contains_code() {
        let result = validate_non_negative_epoch(-42.0);
        let err = result.unwrap_err();
        // The napi::Error's Display impl includes the reason string, which
        // contains the SCP-VALID-7040 code from ScpNapiError::Validation.
        let msg = format!("{err}");
        assert!(
            msg.contains(codes::VALID_7040),
            "error should contain SCP-VALID-7040, got: {msg}"
        );
    }

    #[test]
    fn validate_epoch_rejects_nan() {
        let result = validate_non_negative_epoch(f64::NAN);
        assert!(result.is_err(), "NaN epoch should error");
    }

    #[test]
    fn validate_epoch_rejects_positive_infinity() {
        let result = validate_non_negative_epoch(f64::INFINITY);
        assert!(result.is_err(), "INFINITY epoch should error");
    }

    // -----------------------------------------------------------------------
    // event_log_verify — AUTHORITATIVE-log-only proofs (F3 / GitHub #1933)
    // -----------------------------------------------------------------------

    /// The AUTHORITATIVE supervisor event log.
    #[cfg(feature = "testing")]
    fn authoritative_log(bi: &NapiBridgeInstance, context_id: &str) -> scp_event_log::EventLog {
        crate::runtime::supervisor(bi)
            .expect("supervisor attached")
            .authoritative_event_log(context_id)
            .expect("authoritative event log readable")
    }

    /// The canonical leaf hashes of the AUTHORITATIVE supervisor log.
    #[cfg(feature = "testing")]
    fn authoritative_leaves(bi: &NapiBridgeInstance, context_id: &str) -> Vec<[u8; 32]> {
        authoritative_log(bi, context_id).leaves().to_vec()
    }

    /// Minimal params for a supervisor-created context.
    #[cfg(feature = "testing")]
    fn verify_test_params_json() -> String {
        serde_json::json!({
            "ceiling": ["messages:read", "messages:write"],
            "ceilingPolicy": "immutable",
            "memoryScope": "ephemeral",
            "governance": "single_admin",
        })
        .to_string()
    }

    /// Injects a caller-influenced leaf into the UCAN-state tree through a real
    /// public bridge call.
    #[cfg(feature = "testing")]
    fn inject_local_leaf(bi: &NapiBridgeInstance, context_id: &str, actor_did: &str) {
        crate::provenance::provenance_attach_on(
            bi,
            "ctx-source-injected".to_owned(),
            "persistent".to_owned(),
            "full".to_owned(),
            vec![actor_did.to_owned()],
            context_id.to_owned(),
            actor_did.to_owned(),
            None,
            None,
            None,
            None,
        )
        .expect("provenance_attach appends a bridge-local leaf");
    }

    /// F3 / GitHub #1933 — proofs come from the AUTHORITATIVE log only.
    ///
    /// Covers: an absence claim for a present authoritative event is rejected;
    /// every authoritative leaf proves included; a caller-injected UCAN-state
    /// leaf is NEVER provable; the details carry the authoritative root + leaf
    /// count; and the UCAN-state log is left completely untouched.
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn event_log_verify_proves_against_the_authoritative_log_only() {
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let bi = std::sync::Arc::clone(&scp.inner);
        let identity = scp
            .identity_create("in_memory".to_owned(), None)
            .await
            .expect("identity_create should succeed");
        let did = identity.did();
        let handle = crate::context::context_create_on(&bi, &identity, verify_test_params_json())
            .await
            .expect("context_create should succeed");
        let context_id = handle.context_id();

        let authoritative = authoritative_leaves(&bi, &context_id);
        assert!(
            !authoritative.is_empty(),
            "creating a context appends ContextCreated to the authoritative log"
        );
        let auth_log = authoritative_log(&bi, &context_id);
        let auth_count = scp_event_log::tree::event_count(&auth_log);
        let auth_root = scp_event_log::tree::root(&auth_log);

        // Seed the UCAN-state tree with the authoritative prefix (so the old
        // append-only branch would have kept a local suffix) plus a real
        // caller-injected leaf.
        crate::runtime::ensure_registered(&bi, &handle).expect("ucan state registered");
        crate::runtime::with_context(&bi, &context_id, |rt| {
            for leaf in &authoritative {
                rt.core.event_log.push_leaf_raw(*leaf);
            }
            Ok(())
        })
        .expect("seed succeeds");
        inject_local_leaf(&bi, &context_id, &did);

        let local_before = crate::runtime::with_context(&bi, &context_id, |rt| {
            Ok(rt.core.event_log.leaves().to_vec())
        })
        .unwrap();
        let local_events_before = crate::runtime::with_context(&bi, &context_id, |rt| {
            Ok(rt.core.event_log.events().len())
        })
        .unwrap();
        assert!(
            local_before.len() > authoritative.len(),
            "precondition: the injected leaf extends the UCAN-state tree"
        );
        let injected: Vec<[u8; 32]> = local_before[authoritative.len()..].to_vec();

        // --- absence of a PRESENT authoritative event is rejected -----------
        let absence_claim = serde_json::json!({
            "type": "absence", "event_hash": hex::encode(authoritative[0]),
        })
        .to_string();
        let msg = match event_log_verify_on(&bi, &handle, absence_claim).await {
            Ok(proof) => panic!(
                "absence of a present authoritative event must be rejected, got {}",
                proof.details_json
            ),
            Err(err) => format!("{err}"),
        };
        assert!(
            msg.contains("present in the log"),
            "expected an absence-proof-for-present-event rejection, got: {msg}"
        );

        // --- absence of a genuinely-unknown event carries the auth root -----
        let absence_claim = serde_json::json!({
            "type": "absence", "event_hash": hex::encode([0xEEu8; 32]),
        })
        .to_string();
        let proof = event_log_verify_on(&bi, &handle, absence_claim)
            .await
            .expect("absence of an unknown event proves");
        let details: serde_json::Value = serde_json::from_str(&proof.details_json).unwrap();
        assert_eq!(
            details["root"].as_str(),
            Some(hex::encode(auth_root).as_str())
        );
        assert_eq!(details["leaf_count"].as_u64(), Some(auth_count));

        // --- no index ever proves a caller-injected leaf --------------------
        for leaf_index in 0..local_before.len() {
            let claim = serde_json::json!({
                "type": "inclusion", "leaf_index": leaf_index,
            })
            .to_string();
            match event_log_verify_on(&bi, &handle, claim).await {
                Err(_) => assert!(
                    leaf_index >= authoritative.len(),
                    "authoritative leaf {leaf_index} must still be provable"
                ),
                Ok(proof) => {
                    let details: serde_json::Value =
                        serde_json::from_str(&proof.details_json).unwrap();
                    let leaf_hash = details["leaf_hash"].as_str().unwrap().to_owned();
                    for forged in &injected {
                        assert_ne!(
                            leaf_hash,
                            hex::encode(forged),
                            "leaf_index {leaf_index} proved a caller-injected UCAN-state leaf"
                        );
                    }
                    assert_eq!(leaf_hash, hex::encode(authoritative[leaf_index]));
                    assert_eq!(
                        details["root"].as_str(),
                        Some(hex::encode(auth_root).as_str()),
                        "inclusion root must be authoritative"
                    );
                    assert_eq!(details["leaf_count"].as_u64(), Some(auth_count));
                }
            }
        }

        // --- verification is READ-ONLY -------------------------------------
        assert_eq!(
            crate::runtime::with_context(&bi, &context_id, |rt| Ok(rt
                .core
                .event_log
                .leaves()
                .to_vec()))
            .unwrap(),
            local_before,
            "verification must not touch the UCAN-state log's leaves"
        );
        assert_eq!(
            crate::runtime::with_context(&bi, &context_id, |rt| Ok(rt
                .core
                .event_log
                .events()
                .len()))
            .unwrap(),
            local_events_before,
            "verification must not discard the UCAN-state log's stored events"
        );
    }

    /// #1933 — the provider reporting NO LOG (`Ok(None)`) means UNKNOWN, never
    /// "empty". Must fail closed rather than fall through to the UCAN-state
    /// tree.
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn event_log_verify_fails_closed_when_the_authoritative_log_is_unknown() {
        let bi = std::sync::Arc::new(crate::runtime::NapiBridgeInstance::new_napi());
        crate::runtime::init_supervisor_for_test_on(&bi);
        // A synthetic handle: UCAN state exists, but the context was never
        // created through the supervisor, so the authoritative log is UNKNOWN.
        let handle = crate::context::NapiContextHandle::test_active_on(
            &bi,
            "ctx-unknown-authoritative-log".to_owned(),
            "did:dht:z6MkCreatorUnknownLog".to_owned(),
        );
        crate::runtime::ensure_registered(&bi, &handle).expect("ucan state registered");
        crate::runtime::with_context(&bi, &handle.context_id(), |rt| {
            rt.core.event_log.push_leaf_raw([0xABu8; 32]);
            Ok(())
        })
        .expect("seed succeeds");

        let absence_claim = serde_json::json!({
            "type": "absence", "event_hash": hex::encode([0xCDu8; 32]),
        })
        .to_string();
        let msg = match event_log_verify_on(&bi, &handle, absence_claim).await {
            Ok(proof) => panic!(
                "an unknown authoritative log must fail closed, got {}",
                proof.details_json
            ),
            Err(err) => format!("{err}"),
        };
        assert!(
            msg.contains(codes::CTX_2138),
            "expected the fail-closed authoritative-log code SCP-CTX-2138, got: {msg}"
        );
    }

    /// #1933 — a SHUT-DOWN instance must be rejected, not just a suspended one.
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn event_log_verify_fails_closed_after_shutdown_and_suspend() {
        for shutdown in [false, true] {
            let scp = crate::scp::Scp::new_in_memory_for_test();
            let bi = std::sync::Arc::clone(&scp.inner);
            let identity = scp
                .identity_create("in_memory".to_owned(), None)
                .await
                .expect("identity_create should succeed");
            let handle =
                crate::context::context_create_on(&bi, &identity, verify_test_params_json())
                    .await
                    .expect("context_create should succeed");
            let context_id = handle.context_id();
            let present = authoritative_leaves(&bi, &context_id)[0];

            crate::runtime::ensure_registered(&bi, &handle).expect("ucan state registered");
            crate::runtime::with_context(&bi, &context_id, |rt| {
                rt.core.event_log.push_leaf_raw([0xABu8; 32]);
                Ok(())
            })
            .expect("seed succeeds");

            if shutdown {
                bi.core.shutdown();
            } else {
                bi.core.suspend().expect("suspend");
            }

            let absence_claim = serde_json::json!({
                "type": "absence", "event_hash": hex::encode(present),
            })
            .to_string();
            let msg = match event_log_verify_on(&bi, &handle, absence_claim).await {
                Ok(proof) => panic!(
                    "a not-ready instance (shutdown={shutdown}) must fail closed, got {}",
                    proof.details_json
                ),
                Err(err) => format!("{err}"),
            };
            assert!(
                msg.contains(codes::CTX_2138),
                "shutdown={shutdown}: expected SCP-CTX-2138, got: {msg}"
            );
        }
    }

    /// #1933 — an UNKNOWN authoritative log must FAIL CLOSED, not fall through
    /// to the UCAN-state tree and publish its root as `merkle_root` in a
    /// synthesized `LogSummary` event.
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn event_log_query_fails_closed_when_the_authoritative_log_is_unknown() {
        let bi = std::sync::Arc::new(crate::runtime::NapiBridgeInstance::new_napi());
        crate::runtime::init_supervisor_for_test_on(&bi);
        // A synthetic handle: the context was never created through the
        // supervisor, so the authoritative log is UNKNOWN.
        let handle = crate::context::NapiContextHandle::test_active_on(
            &bi,
            "ctx-unknown-log-query".to_owned(),
            "did:dht:z6MkCreatorUnknownLogQuery".to_owned(),
        );
        crate::runtime::ensure_registered(&bi, &handle).expect("ucan state registered");
        crate::runtime::with_context(&bi, &handle.context_id(), |rt| {
            rt.core.event_log.push_leaf_raw([0xABu8; 32]);
            Ok(())
        })
        .expect("seed succeeds");

        let reason = match event_log_query_on(&bi, &handle, None).await {
            Ok(events) => panic!(
                "an unknown authoritative log must fail closed, got {} event(s)",
                events.len()
            ),
            Err(err) => err.reason.clone(),
        };
        assert!(
            reason.contains(codes::CTX_2138),
            "expected SCP-CTX-2138, got: {reason}"
        );
    }

    // -----------------------------------------------------------------------
    // event_log_checkpoint — the SIGNED commitment covers the AUTHORITATIVE
    // log only (GitHub #1933 follow-up)
    //
    // A `ConsistencyCheckpoint` is signed, non-repudiable evidence: a peer that
    // sees the same `event_count` with a different `merkle_root` raises
    // `EquivocationDetected` against its signer (§9.9.3). Signing over the
    // caller-shapeable UCAN-state tree let ANY member mint validly-signed
    // equivocation evidence against honest peers.
    // -----------------------------------------------------------------------

    /// A caller who shapes the UCAN-state tree must not be able to move the
    /// signed commitment one bit. Fails pre-fix: `event_count`/`merkle_root`
    /// were read straight off `rt.core.event_log`.
    ///
    /// A plain `#[test]`, not a `#[tokio::test]`: `event_log_checkpoint_on` is a
    /// SYNC napi entry point that drives its async signing step through
    /// `crate::runtime().block_on(...)`, which panics if the calling thread is
    /// already driving a tokio runtime. The async setup runs through the same
    /// stored runtime and completes before the checkpoint call.
    #[cfg(feature = "testing")]
    #[test]
    fn event_log_checkpoint_commits_to_the_authoritative_log_only() {
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let bi = std::sync::Arc::clone(&scp.inner);
        let (identity, handle) = crate::runtime().block_on(async {
            let identity = scp
                .identity_create("in_memory".to_owned(), None)
                .await
                .expect("identity_create should succeed");
            let handle =
                crate::context::context_create_on(&bi, &identity, verify_test_params_json())
                    .await
                    .expect("context_create should succeed");
            (identity, handle)
        });
        let did = identity.did();
        let context_id = handle.context_id();

        let auth_log = authoritative_log(&bi, &context_id);
        let auth_count = scp_event_log::tree::event_count(&auth_log);
        let auth_root = scp_event_log::tree::root(&auth_log);

        // Shape the UCAN-state tree away from the authoritative one: the
        // authoritative prefix plus real caller-injected leaves.
        crate::runtime::ensure_registered(&bi, &handle).expect("ucan state registered");
        crate::runtime::with_context(&bi, &context_id, |rt| {
            for leaf in auth_log.leaves() {
                rt.core.event_log.push_leaf_raw(*leaf);
            }
            Ok(())
        })
        .expect("seed succeeds");
        inject_local_leaf(&bi, &context_id, &did);
        inject_local_leaf(&bi, &context_id, &did);

        let local_root = crate::runtime::with_context(&bi, &context_id, |rt| {
            Ok(scp_event_log::tree::root(&rt.core.event_log))
        })
        .unwrap();
        assert_ne!(
            local_root, auth_root,
            "precondition: the caller has shaped the UCAN-state tree away from \
             the authoritative one"
        );

        let checkpoint = event_log_checkpoint_on(&bi, &handle, &identity, 3.0)
            .expect("checkpoint over a readable authoritative log");
        #[allow(clippy::cast_precision_loss)]
        {
            assert!((checkpoint.event_count - auth_count as f64).abs() < f64::EPSILON);
        }
        assert_eq!(checkpoint.merkle_root, hex::encode(auth_root));
        assert_ne!(
            checkpoint.merkle_root,
            hex::encode(local_root),
            "a caller-shaped UCAN-state root must never reach a signed field"
        );

        // `event_log_checkpoint_by_did` commits identically — both public
        // surfaces share one implementation.
        let by_did = event_log_checkpoint_by_did_on(&bi, &handle, did, 3.0)
            .expect("checkpoint_by_did over a readable authoritative log");
        assert_eq!(by_did.merkle_root, hex::encode(auth_root));
    }

    /// An UNKNOWN authoritative log must yield NO checkpoint at all — pre-fix
    /// the bridge signed a commitment over whatever the UCAN-state tree held.
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn event_log_checkpoint_fails_closed_when_the_authoritative_log_is_unknown() {
        let scp = crate::scp::Scp::new_in_memory_for_test();
        let bi = std::sync::Arc::clone(&scp.inner);
        let identity = scp
            .identity_create("in_memory".to_owned(), None)
            .await
            .expect("identity_create should succeed");
        // A synthetic handle: the context was never created through the
        // supervisor, so the authoritative log is UNKNOWN.
        let handle = crate::context::NapiContextHandle::test_active_on(
            &bi,
            "ctx-unknown-log-checkpoint".to_owned(),
            identity.did(),
        );
        crate::runtime::ensure_registered(&bi, &handle).expect("ucan state registered");
        crate::runtime::with_context(&bi, &handle.context_id(), |rt| {
            rt.core.event_log.push_leaf_raw([0xABu8; 32]);
            Ok(())
        })
        .expect("seed succeeds");

        let reason = match event_log_checkpoint_on(&bi, &handle, &identity, 0.0) {
            Ok(cp) => panic!(
                "an unknown authoritative log must not be signed over, got \
                 event_count={} merkle_root={}",
                cp.event_count, cp.merkle_root
            ),
            Err(err) => err.reason.clone(),
        };
        assert!(
            reason.contains(codes::CTX_2138),
            "expected SCP-CTX-2138, got: {reason}"
        );
    }

    /// A shut-down or suspended instance is rejected the same way verification
    /// is.
    #[cfg(feature = "testing")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn event_log_checkpoint_fails_closed_after_shutdown_and_suspend() {
        for shutdown in [false, true] {
            let scp = crate::scp::Scp::new_in_memory_for_test();
            let bi = std::sync::Arc::clone(&scp.inner);
            let identity = scp
                .identity_create("in_memory".to_owned(), None)
                .await
                .expect("identity_create should succeed");
            let handle =
                crate::context::context_create_on(&bi, &identity, verify_test_params_json())
                    .await
                    .expect("context_create should succeed");

            crate::runtime::ensure_registered(&bi, &handle).expect("ucan state registered");
            crate::runtime::with_context(&bi, &handle.context_id(), |rt| {
                rt.core.event_log.push_leaf_raw([0xABu8; 32]);
                Ok(())
            })
            .expect("seed succeeds");

            if shutdown {
                bi.core.shutdown();
            } else {
                bi.core.suspend().expect("suspend");
            }

            let reason = match event_log_checkpoint_on(&bi, &handle, &identity, 0.0) {
                Ok(cp) => panic!(
                    "a not-ready instance (shutdown={shutdown}) must not sign a \
                     checkpoint, got event_count={} merkle_root={}",
                    cp.event_count, cp.merkle_root
                ),
                Err(err) => err.reason.clone(),
            };
            assert!(
                reason.contains(codes::CTX_2138),
                "shutdown={shutdown}: expected SCP-CTX-2138, got: {reason}"
            );
        }
    }
}
