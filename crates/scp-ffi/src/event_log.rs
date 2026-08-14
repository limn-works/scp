//! `PyO3` bridge functions for event log queries, verification, and checkpoints.
//!
//! Exposes SCP event log operations to Python as methods on the `SCP` class:
//!
//! - `PyScp::event_log_query` -- Query the context event log with optional
//!   filters.
//! - `PyScp::event_log_verify` -- Verify a claim against the event log
//!   (inclusion/absence proofs).
//! - `PyScp::event_log_checkpoint` -- Generate a signed consistency checkpoint
//!   from the current event log state.
//!
//! All free `#[pyfunction]` exports were migrated to `#[pymethods] impl PyScp`
//! methods in Phase 4 PR 4 sub-slice E (#1549).
//!
//! # Types
//!
//! - [`PyEvent`] -- A protocol event (type, actor, timestamp, payload,
//!   sequence).
//! - [`PyProof`] -- A Merkle verification proof (proof type, details). There is
//!   no `verified` field; `event_log_verify` raising IS the negative answer.
//! - [`PyCheckpoint`] -- A signed consistency checkpoint (context ID, sender
//!   DID, event count, Merkle root, epoch, timestamp, signature).
//!
//! See ADR-013 in `.docs/adrs/phase-3.md` §7 and ADR-011 for the event
//! log specification. See ADR-030 in `.docs/adrs/phase-6.md` for checkpoint
//! and pruning design.

use pyo3::prelude::*;
use pyo3::types::PyDict;
use scp_clock::Clock;
use scp_ffi_common::error_codes as codes;

use crate::error::ScpPyError;
use crate::runtime::PyBridgeInstance;
use crate::types::{encode_hex, json_to_py_dict};
use crate::validate;

// ---------------------------------------------------------------------------
// PyEvent
// ---------------------------------------------------------------------------

/// A protocol event from the context event log, exposed to Python.
///
/// Each event records a single protocol action: what happened
/// (`event_type`), who did it (`actor_did`), when (`timestamp`), the
/// event data (`payload` as a JSON-compatible Python object), and its
/// position in the log (`sequence`).
///
/// See ADR-011 (event log) and ADR-013 §7 (bridge layer).
#[pyclass(name = "Event")]
#[derive(Debug)]
pub struct PyEvent {
    /// The event type (e.g., `"ContextCreated"`, `"MemberJoined"`,
    /// `"GovernanceActionExecuted"`).
    #[pyo3(get)]
    pub event_type: String,

    /// The DID of the actor who produced this event.
    #[pyo3(get)]
    pub actor_did: String,

    /// Unix timestamp (seconds since epoch) when the event was created.
    #[pyo3(get)]
    pub timestamp: f64,

    /// Event-specific data as a JSON-compatible Python object (dict, list,
    /// string, number, bool, or None).
    #[pyo3(get)]
    pub payload: PyObject,

    /// Monotonic event sequence number within the log (0-indexed).
    #[pyo3(get)]
    pub sequence: u64,
}

#[pymethods]
impl PyEvent {
    fn __repr__(&self) -> String {
        format!(
            "Event(event_type={:?}, actor_did={:?}, sequence={}, timestamp={})",
            self.event_type, self.actor_did, self.sequence, self.timestamp
        )
    }
}

// ---------------------------------------------------------------------------
// PyProof
// ---------------------------------------------------------------------------

/// A Merkle proof from the event log, exposed to Python.
///
/// Returned by `PyScp::event_log_verify`. Carries the proof type and the proof
/// material as a JSON-compatible Python object.
///
/// # There is no `verified` field
///
/// This type used to carry `verified: bool`. It was a constant `True` on every
/// success path: the bridge generated the proof and then "verified" that same
/// proof against the same snapshot, so the check was tautological and only
/// `Ok`-vs-raise ever carried information. A boolean named `verified` that no
/// independent verifier computed is a false guarantee, so it is gone —
/// `event_log_verify` raising IS the negative answer.
///
/// Real verification is done by the recipient from [`details`](Self::details),
/// which carries the full Merkle material for both proof types: the leaf hash,
/// the sibling path with per-step direction, and the root the path reaches. An
/// absence answer carries the same complete material for BOTH bracketing
/// neighbours.
///
/// # What an `"absence"` answer does and does not establish
///
/// The neighbour material above lets a recipient check that both bracketing
/// leaves really are in the tree the reported `root` commits to, and that the
/// queried hash sorts strictly between them. It does NOT establish that the two
/// neighbours are ADJACENT in sorted order: the log's Merkle root commits to
/// append order, and the sorted index the neighbours are drawn from is local
/// state the root does not cover. Treat an `"absence"` answer as the log's own
/// assertion plus checkable neighbour-inclusion, not as a self-contained
/// non-membership proof (a sorted/sparse tree is the real fix — see #2314).
///
/// See ADR-011 (Merkle proofs) and ADR-013 §7 (bridge layer).
#[pyclass(name = "Proof")]
#[derive(Debug)]
pub struct PyProof {
    /// The proof type: `"inclusion"` or `"absence"`.
    #[pyo3(get)]
    pub proof_type: String,

    /// Proof material as a JSON-compatible Python object: the Merkle path
    /// (for inclusion proofs) or the two sorted neighbours with their own
    /// inclusion proofs (for absence proofs).
    #[pyo3(get)]
    pub details: PyObject,
}

#[pymethods]
impl PyProof {
    fn __repr__(&self) -> String {
        format!("Proof(proof_type={:?})", self.proof_type)
    }
}

// ---------------------------------------------------------------------------
// PyCheckpoint
// ---------------------------------------------------------------------------

/// A signed consistency checkpoint from the context event log, exposed to
/// Python.
///
/// Checkpoints are signed snapshots of the event log state at a point in time.
/// Members exchange checkpoints to detect relay equivocation: if two members
/// have different Merkle roots for the same event count, the relay is showing
/// different histories to different members.
///
/// See ADR-011 acceptance criterion 8 and ADR-030 (pruning/checkpointing).
#[pyclass(name = "Checkpoint")]
#[derive(Debug)]
pub struct PyCheckpoint {
    /// The context this checkpoint belongs to.
    #[pyo3(get)]
    pub context_id: String,

    /// The DID of the member who generated this checkpoint.
    #[pyo3(get)]
    pub sender_did: String,

    /// The number of events in the log at checkpoint time.
    #[pyo3(get)]
    pub event_count: u64,

    /// The Merkle root hash at checkpoint time, hex-encoded.
    #[pyo3(get)]
    pub merkle_root: String,

    /// Current MLS epoch. `None` for Broadcast contexts.
    #[pyo3(get)]
    pub epoch: Option<u64>,

    /// Unix timestamp (seconds) when the checkpoint was generated.
    #[pyo3(get)]
    pub timestamp: u64,

    /// Ed25519 signature over the canonical checkpoint fields, hex-encoded.
    #[pyo3(get)]
    pub signature: String,
}

#[pymethods]
impl PyCheckpoint {
    fn __repr__(&self) -> String {
        format!(
            "Checkpoint(context_id={:?}, sender_did={:?}, event_count={}, timestamp={})",
            self.context_id, self.sender_did, self.event_count, self.timestamp
        )
    }
}

// ---------------------------------------------------------------------------
// Bridge helpers (per-bridge implementations used by PyScp methods)
// ---------------------------------------------------------------------------

/// Queries the context event log on a specific bridge instance.
///
/// # The answer comes from the AUTHORITATIVE log only
///
/// Every event returned is a leaf of the supervisor's canonical event log — the
/// same source [`event_log_verify`](PyScp::event_log_verify) proves against and
/// [`event_log_checkpoint`](PyScp::event_log_checkpoint) commits to. There is no
/// bridge-local fallback.
///
/// This function used to end
/// `supervisor(bi).ok().and_then(|m| m.event_log_entries(..).ok().flatten())`
/// and, on ANY failure or on an empty result, fall through to the bridge-local
/// `FfiBridgeState::event_log` — publishing THAT tree's root as `merkle_root`
/// in a synthesized `LogSummary` event, under the same field name the
/// authoritative answers use. Two consequences (GitHub #1933): a consumer
/// pinning a verify proof against a queried root could accept a root a caller
/// had shaped through `provenance_attach` / outlet calls; and
/// `entries.is_empty() -> fall through` collapsed the empty-but-live vs unknown
/// distinction, so query and verify returned contradictory answers about the
/// same context.
///
/// Now: an empty-but-live log returns an EMPTY list, and an unreachable or
/// unknown log FAILS CLOSED with `SCP-CTX-2138`.
///
/// # Arguments
///
/// * `context_id` -- The ID of the context whose event log to query.
/// * `filter` -- An optional Python dict with filter parameters:
///   - `"event_type"` (str): Filter by event type name.
///   - `"actor_did"` (str): Filter by actor DID.
///   - `"after_sequence"` (int): Only events after this sequence number.
///   - `"before_sequence"` (int): Only events before this sequence number.
///   - `"after_timestamp"` (float): Only events after this timestamp.
///   - `"before_timestamp"` (float): Only events before this timestamp.
///   - `"limit"` (int): Maximum number of events to return.
///
/// # Returns
///
/// A list of [`PyEvent`] objects, empty when the log is live but holds no
/// matching events.
///
/// # Errors
///
/// Raises `ContextError` with `SCP-CTX-2138` when the authoritative log is
/// unreachable (instance not ready, no supervisor, or no log for the context).
///
/// See ADR-013 §7: `py_event_log_query(handle, filter) -> list[PyEvent]`.
fn event_log_query_impl(
    bi: &PyBridgeInstance,
    py: Python<'_>,
    context_id: &str,
    filter: Option<&Bound<'_, PyDict>>,
) -> PyResult<Vec<PyEvent>> {
    validate::validate_context_id(context_id)?;
    let query_filter = parse_event_query_filter(filter)?;

    // Same fail-closed gate as `event_log_verify` / `event_log_checkpoint`.
    bi.core
        .check_ready()
        .map_err(|e| authoritative_log_unreachable("query", context_id, &e))?;
    let supervisor = crate::runtime::supervisor(bi)
        .map_err(|e| authoritative_log_unreachable("query", context_id, &e))?;

    // ADR-056: resolve the context-id string to its 32-byte digest via the
    // canonical chokepoint (NOT the raw SHA-256 routing primitive, which
    // double-hashes a real 64-hex id and queries the wrong event-log key).
    let ctx_id_bytes = scp_core::context::state::context_id_to_bytes(context_id);
    let entries = supervisor
        .event_log_entries(&ctx_id_bytes)
        .map_err(|e| authoritative_log_unreachable("query", context_id, &e))?
        // `None` means UNKNOWN — never initialised, or destroyed on actor
        // shutdown / create-rollback. An empty-but-live log is
        // `Ok(Some(vec![]))` and returns an empty list below.
        .ok_or_else(|| {
            authoritative_log_unreachable("query", context_id, &"no event log for this context")
        })?;

    // Canonical filter — pinned across PyO3/NAPI/UniFFI by
    // `scp_ffi_common::event_log::filter_manager_entries` so the three
    // bridges cannot drift. Each bridge still owns its payload/timestamp
    // mapping below; the helper only encodes the filter contract.
    let filter = scp_ffi_common::event_log::EventLogFilter {
        after_sequence: query_filter.sequence_start,
        before_sequence: query_filter.sequence_end,
        event_type: query_filter.event_type.as_deref(),
        actor_did: query_filter.actor_did.as_deref(),
        limit: query_filter.limit,
    };
    let filtered = scp_ffi_common::event_log::filter_manager_entries(&entries, &filter);

    let mut py_events = Vec::with_capacity(filtered.len());
    for (seq, entry) in filtered {
        #[allow(clippy::cast_precision_loss)]
        let timestamp = entry.timestamp as f64;
        let leaf_hash = scp_event_log::tree::leaf_hash(entry)
            .map_err(|e| ScpPyError::context(format!("event leaf hash failed: {e}")))?;
        // Project the typed payload's bridge-facing fields (e.g. `target_did`
        // for governance/access-revocation events, `subject_did` for
        // role/membership events) through the single shared
        // `scp_event_log::payload::project_payload` decoder (via the
        // `inject_projection` helper) so all three native bridges surface
        // byte-identical values. Each key is omitted when the projection
        // yields `None`.
        let mut payload_json = serde_json::json!({
            "hash": encode_hex(&leaf_hash),
        });
        scp_ffi_common::event_log::inject_projection(
            &mut payload_json,
            &entry.event_type,
            &entry.payload,
        );
        let payload = json_to_py_dict(py, &payload_json)?;
        py_events.push(PyEvent {
            event_type: scp_ffi_common::event_log::event_type_label(&entry.event_type),
            actor_did: entry.actor_did.0.clone(),
            timestamp,
            payload,
            sequence: seq,
        });
    }
    Ok(py_events)
}

/// Parses an `EventQueryFilter` from an optional Python dict.
///
/// Extracts filter fields from the dict if provided, mapping Python key
/// names to the `EventQueryFilter` struct fields.
fn parse_event_query_filter(
    filter: Option<&Bound<'_, PyDict>>,
) -> PyResult<scp_core::store::event_log::EventQueryFilter> {
    let mut query_filter = scp_core::store::event_log::EventQueryFilter::default();

    if let Some(f) = filter {
        if let Some(v) = f.get_item("event_type")? {
            query_filter.event_type = Some(v.extract::<String>()?);
        }
        if let Some(v) = f.get_item("actor_did")? {
            query_filter.actor_did = Some(v.extract::<String>()?);
        }
        if let Some(v) = f.get_item("after_sequence")? {
            query_filter.sequence_start = Some(v.extract::<u64>()?);
        }
        if let Some(v) = f.get_item("before_sequence")? {
            query_filter.sequence_end = Some(v.extract::<u64>()?);
        }
        if let Some(v) = f.get_item("after_timestamp")? {
            let ts = v.extract::<f64>()?;
            if ts < 0.0 || !ts.is_finite() {
                return Err(ScpPyError::ValidationError {
                    message: format!(
                        "after_timestamp must be a finite non-negative value, got {ts}"
                    ),
                    code: codes::VALID_7040.to_owned(),
                }
                .into());
            }
            #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
            {
                query_filter.timestamp_start = Some(ts as u64);
            }
        }
        if let Some(v) = f.get_item("before_timestamp")? {
            let ts = v.extract::<f64>()?;
            if ts < 0.0 || !ts.is_finite() {
                return Err(ScpPyError::ValidationError {
                    message: format!(
                        "before_timestamp must be a finite non-negative value, got {ts}"
                    ),
                    code: codes::VALID_7040.to_owned(),
                }
                .into());
            }
            #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
            {
                query_filter.timestamp_end = Some(ts as u64);
            }
        }
        if let Some(v) = f.get_item("limit")? {
            query_filter.limit = Some(v.extract::<usize>()?);
        }
    }

    Ok(query_filter)
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
/// Neither verification nor checkpointing may fall back to any bridge-local tree
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
) -> ScpPyError {
    ScpPyError::ContextError {
        message: format!(
            "event log {operation} cannot reach the authoritative log for context \
             '{context_id}': {detail}"
        ),
        code: codes::CTX_2138.to_owned(),
    }
}

/// Builds the malformed-claim-input validation error `event_log_verify` raises.
///
/// Malformed CLAIM input (missing `type`, missing `leaf_index`, an `event_hash`
/// that is not 32 hex-decoded bytes, an unsupported claim type) is caller input
/// validation, and the cross-bridge contract pins it to `VALID_7000` on EVERY
/// bridge — see [`codes::CTX_2139`]'s doc, and the napi (`napi/src/event_log.rs`)
/// and `UniFFI` (`uniffi/src/bridge.rs`) `event_log_verify` arms, which already
/// raise `VALID_7000` at the byte-identical conditions.
///
/// This path must NOT use the generic [`ScpPyError::validation`] helper, whose
/// `VALID_7001` would silently diverge the reference bridge from the contract
/// it establishes (GitHub #1933).
fn malformed_claim(message: impl Into<String>) -> ScpPyError {
    ScpPyError::ValidationError {
        message: message.into(),
        code: codes::VALID_7000.to_owned(),
    }
}

/// Verifies a claim against the context event log.
///
/// Generates and verifies a Merkle proof for the given claim. Supports
/// both inclusion proofs (proving an event IS in the log) and absence
/// proofs (proving an event is NOT in the log).
///
/// # The proof is generated against the AUTHORITATIVE log
///
/// Both proof types are generated from ONE `Supervisor::authoritative_event_log`
/// snapshot — the runtime's single proof seam, replayed from the supervisor's
/// own canonical event log, the same source
/// [`event_log_query`](PyScp::event_log_query) reads. This function NEVER reads
/// or mutates the bridge-local `FfiBridgeState::event_log`, which is a separate
/// tree holding only bridge-local records (UCAN revocations, outlet
/// invocations, provenance, media sessions) and whose leaves a caller can
/// influence. Proving over that tree produced forgeable absence AND inclusion
/// results (GitHub #1933).
///
/// Because the proof and the reported `(leaf_count, root)` commitment come from
/// that ONE snapshot, they describe the same tree state by construction — a
/// relying party can pin the proof against the commitment beside it. Taking
/// them from two snapshots would let a concurrent append separate them, and a
/// root paired with another snapshot's leaf count commits to nothing.
///
/// # Arguments
///
/// * `context_id` -- The ID of the context whose event log to verify
///   against.
/// * `claim` -- A Python dict describing the claim to verify:
///   - `"type"` (str): `"inclusion"` or `"absence"`.
///   - `"leaf_index"` (int): For inclusion proofs, the event's position.
///   - `"event_hash"` (str): For absence proofs, the hex-encoded hash
///     of the event to prove absent.
///
/// # Returns
///
/// A [`PyProof`] carrying the proof type and Merkle details. There is no
/// `verified` field — `event_log_verify` raising IS the negative answer.
///
/// # Errors
///
/// Raises `ContextError` with `SCP-CTX-2138` when the authoritative log is
/// unreachable (instance not ready, no supervisor, or no log for the context —
/// FAIL CLOSED, never a "verified" proof over a fallback tree), and
/// `ContextError` when proof generation legitimately fails over a readable log
/// (empty log, out-of-range leaf index, or an absence claim for an event that
/// IS present).
///
/// See ADR-013 §7 and ADR-011.
#[allow(clippy::too_many_lines)] // Proof generation with match arms is inherently verbose.
fn event_log_verify_impl(
    bi: &PyBridgeInstance,
    py: Python<'_>,
    context_id: &str,
    claim: &Bound<'_, PyDict>,
) -> PyResult<PyProof> {
    use crate::types::py_dict_to_json;
    validate::validate_context_id(context_id)?;

    // Parse the claim dict.
    let claim_json = py_dict_to_json(claim)?;

    // DELIBERATE ordering (black-hat NIT, #1933): the missing/invalid-`type`
    // check runs BEFORE the `check_ready`/authoritative-log gate below, on
    // purpose. Rejecting obviously-malformed claim shape is cheap; the log gate
    // rebuilds the authoritative log, so validating input first avoids that work
    // for a claim we would reject anyway. This yields a benign self-oracle — a
    // malformed-`type` claim on a not-ready instance returns VALID-7000 while a
    // well-formed one returns CTX-2138 — but the caller CRAFTED the malformed
    // type, so learns nothing new, and can already probe readiness with a
    // well-formed claim (which returns CTX-2138). The malformed path therefore
    // leaks strictly less, never more. The remaining VALID-7000 sites (missing
    // `leaf_index`, malformed `event_hash`, unsupported type) sit in the match
    // arms below, AFTER the gate — so an unreachable log surfaces CTX-2138 first
    // for those; this split is the documented precedence.
    let claim_type = claim_json
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            malformed_claim("claim must include 'type' field ('inclusion' or 'absence')")
        })?;

    // #1933 fail-closed gate. `check_ready` rejects BOTH suspended and
    // shut-down instances (`supervisor()` only rejects suspended, and merely
    // warns after shutdown — while a shut-down context's authoritative log has
    // typically been destroyed).
    bi.core
        .check_ready()
        .map_err(|e| authoritative_log_unreachable("verification", context_id, &e))?;
    let supervisor = crate::runtime::supervisor(bi)
        .map_err(|e| authoritative_log_unreachable("verification", context_id, &e))?;

    // The ONE authoritative snapshot every answer below is derived from. Its
    // failure is the only "cannot answer" case (CTX-2138), which keeps it
    // distinct from "the claim is false" (a proof error over a readable log).
    let log = supervisor
        .authoritative_event_log(context_id)
        .map_err(|e| authoritative_log_unreachable("verification", context_id, &e))?;
    let leaf_count = scp_event_log::tree::event_count(&log);

    match claim_type {
        "inclusion" => {
            let leaf_index = claim_json
                .get("leaf_index")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| {
                    malformed_claim("inclusion claim must include 'leaf_index' (integer)")
                })?;

            let proof = scp_event_log::proof::prove_inclusion(&log, leaf_index).map_err(|e| {
                ScpPyError::ContextError {
                    message: format!("inclusion proof failed: {e}"),
                    code: codes::CTX_2139.to_owned(),
                }
            })?;

            let mut details_json = scp_ffi_common::event_log::inclusion_proof_json(&proof);
            if let Some(obj) = details_json.as_object_mut() {
                obj.insert("leaf_count".to_owned(), leaf_count.into());
            }
            let details = json_to_py_dict(py, &details_json)?;

            Ok(PyProof {
                proof_type: "inclusion".to_owned(),
                details,
            })
        }
        "absence" => {
            let event_hash_hex = claim_json
                .get("event_hash")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    malformed_claim("absence claim must include 'event_hash' (hex string)")
                })?;

            // Decode the hex event hash.
            let event_hash = decode_hex_hash(event_hash_hex)
                .map_err(|e| malformed_claim(format!("invalid event_hash: {e}")))?;

            let proof = scp_event_log::proof::prove_absence(&log, &event_hash).map_err(|e| {
                ScpPyError::ContextError {
                    message: format!("absence proof failed: {e}"),
                    code: codes::CTX_2139.to_owned(),
                }
            })?;

            // Both bracketing neighbours ship their FULL inclusion proofs
            // (sibling path + root), so the neighbour-inclusion half of the
            // claim is checkable off-box against the reported `root`. Shipping
            // only `leaf_hash` + `leaf_index` — as this arm used to — left the
            // recipient nothing to check while the response still carried a
            // producer-set `verified` flag.
            let details_json = serde_json::json!({
                "query_hash": encode_hex(&proof.query_hash),
                "root": encode_hex(&proof.root),
                "leaf_count": proof.leaf_count,
                "lower": scp_ffi_common::event_log::absence_neighbor_json(proof.lower.as_ref()),
                "upper": scp_ffi_common::event_log::absence_neighbor_json(proof.upper.as_ref()),
            });
            let details = json_to_py_dict(py, &details_json)?;

            Ok(PyProof {
                proof_type: "absence".to_owned(),
                details,
            })
        }
        other => Err(malformed_claim(format!(
            "unsupported claim type '{other}': expected 'inclusion' or 'absence'"
        ))
        .into()),
    }
}

/// Generates a signed consistency checkpoint from the current event log state.
///
/// Creates a snapshot of the event log's Merkle root and event count, signs it
/// with the caller's identity key, and returns the checkpoint. Checkpoints
/// enable equivocation detection: members exchange signed Merkle roots and
/// compare them to detect relay misbehavior.
///
/// # The commitment is taken over the AUTHORITATIVE log
///
/// The `(event_count, merkle_root)` pair comes from ONE
/// `Supervisor::unsigned_authoritative_checkpoint` snapshot — the same single
/// proof seam [`event_log_verify`](PyScp::event_log_verify) uses. This function
/// NEVER reads the bridge-local `FfiBridgeState::event_log`.
///
/// A checkpoint is signed, non-repudiable evidence: a peer that sees the same
/// `event_count` with a different `merkle_root` raises `EquivocationDetected`
/// against its signer (§9.9.3). Signing over the bridge-local tree — whose
/// leaves a caller shapes at will through ordinary `provenance_attach` /
/// `media_session_start` / outlet calls — let ANY member mint validly-signed
/// equivocation evidence against honest peers, and left honest members'
/// checkpoints simply wrong about their own history (GitHub #1933).
///
/// # Arguments
///
/// * `context_id` -- The ID of the context whose event log to checkpoint.
/// * `identity_did` -- The DID of the identity generating the checkpoint
///   (used for signing).
/// * `epoch` -- The current MLS epoch (pass 0 for Broadcast contexts).
///
/// # Returns
///
/// A [`PyCheckpoint`] containing the signed checkpoint data.
///
/// # Errors
///
/// Raises `ContextError` with `SCP-CTX-2138` when the authoritative log is
/// unreachable (instance not ready, no supervisor, or no log for the context) —
/// FAIL CLOSED: no checkpoint is signed at all, because an absent checkpoint is
/// an honest, detectable state while a signed fabricated commitment is not.
/// Raises `ContextError` if signing fails, and `IdentityError` if the identity
/// is not found in the registry.
///
/// See ADR-011 acceptance criterion 8 and ADR-030.
///
/// The `did` parameter is the signing member's DID: it drives both the
/// identity-registry lookup (for key material) and the recorded `sender_did`.
/// Both public entry points (`event_log_checkpoint`, which takes the identity's
/// own DID, and `event_log_checkpoint_by_did`, which takes a member DID) share
/// this implementation — they are distinct public surface but identical in
/// behavior.
fn event_log_checkpoint_impl(
    bi: &PyBridgeInstance,
    context_id: &str,
    did: &str,
    epoch: u64,
) -> PyResult<PyCheckpoint> {
    validate::validate_context_id(context_id)?;
    validate::validate_did(did)?;
    let rt = crate::runtime()?;

    let did_owned = did.to_owned();
    let sender_did = scp_did::DID(did_owned.clone());

    // #1933 fail-closed gate, identical to `event_log_verify`. `check_ready`
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
    let unsigned = supervisor
        .unsigned_authoritative_checkpoint(
            context_id,
            &sender_did,
            Some(epoch),
            scp_clock::SystemClock.now_secs(),
        )
        .map_err(|e| authoritative_log_unreachable("checkpointing", context_id, &e))?;

    let checkpoint = crate::runtime::with_identity(bi, &did_owned, |entry| {
        rt.block_on(async {
            let signer = scp_core::event_log::KeyCustodySigner {
                custody: entry.custody.as_ref(),
                key: &entry.identity.active_signing_key,
            };
            unsigned.sign_with(&signer).await
        })
        .map_err(|e| ScpPyError::context(format!("checkpoint generation failed: {e}")))
    })?;

    Ok(PyCheckpoint {
        context_id: checkpoint.context_id,
        sender_did: checkpoint.sender_did.0,
        event_count: checkpoint.event_count,
        merkle_root: encode_hex(&checkpoint.merkle_root),
        epoch: checkpoint.epoch,
        timestamp: checkpoint.timestamp,
        signature: encode_hex(&checkpoint.signature),
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Decodes a hex string into a 32-byte hash.
fn decode_hex_hash(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("hex decode error: {e}"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| format!("expected 32 bytes, got {}", v.len()))?;
    Ok(arr)
}

// ---------------------------------------------------------------------------
// PyScp methods — migrated from #[pyfunction] exports (Phase 4 PR 4, #1549).
// ---------------------------------------------------------------------------

#[pymethods]
impl crate::scp::PyScp {
    /// Queries the context event log.
    ///
    /// Returns actual event data from the `ProtocolRepository` when available,
    /// falling back to a `LogSummary` metadata event when storage is not
    /// initialized or no event payloads have been persisted.
    ///
    /// # Arguments
    ///
    /// * `context_id` -- The ID of the context whose event log to query.
    /// * `filter` -- An optional Python dict with filter parameters:
    ///   - `"event_type"` (str): Filter by event type name.
    ///   - `"actor_did"` (str): Filter by actor DID.
    ///   - `"after_sequence"` (int): Only events after this sequence number.
    ///   - `"before_sequence"` (int): Only events before this sequence number.
    ///   - `"after_timestamp"` (float): Only events after this timestamp.
    ///   - `"before_timestamp"` (float): Only events before this timestamp.
    ///   - `"limit"` (int): Maximum number of events to return.
    ///
    /// # Returns
    ///
    /// A list of [`PyEvent`] objects.
    ///
    /// # Errors
    ///
    /// Raises `ContextError` if the context is not connected to the runtime
    /// or if the query fails.
    ///
    /// See ADR-013 §7 and GitHub issue #303.
    #[pyo3(name = "event_log_query", signature = (context_id, filter=None))]
    pub fn event_log_query(
        &self,
        py: Python<'_>,
        context_id: &str,
        filter: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Vec<PyEvent>> {
        let bi = &*self.inner;
        event_log_query_impl(bi, py, context_id, filter)
    }

    /// Verifies a claim against the context event log.
    ///
    /// Generates and verifies a Merkle proof for the given claim. Supports
    /// both inclusion proofs (proving an event IS in the log) and absence
    /// proofs (proving an event is NOT in the log).
    ///
    /// # Arguments
    ///
    /// * `context_id` -- The ID of the context whose event log to verify
    ///   against.
    /// * `claim` -- A Python dict describing the claim to verify:
    ///   - `"type"` (str): `"inclusion"` or `"absence"`.
    ///   - `"leaf_index"` (int): For inclusion proofs, the event's position.
    ///   - `"event_hash"` (str): For absence proofs, the hex-encoded hash
    ///     of the event to prove absent.
    ///
    /// # Returns
    ///
    /// A [`PyProof`] carrying the proof type and Merkle details. There is no
    /// `verified` field — `event_log_verify` raising IS the negative answer.
    ///
    /// # Errors
    ///
    /// Raises `ContextError` if the context is not connected to the runtime
    /// or if the verification fails (empty log, invalid index, etc.).
    ///
    /// See ADR-013 §7.
    #[pyo3(name = "event_log_verify")]
    pub fn event_log_verify(
        &self,
        py: Python<'_>,
        context_id: &str,
        claim: &Bound<'_, PyDict>,
    ) -> PyResult<PyProof> {
        let bi = &*self.inner;
        event_log_verify_impl(bi, py, context_id, claim)
    }

    /// Generates a signed consistency checkpoint from the current event log state.
    ///
    /// Creates a snapshot of the event log's Merkle root and event count, signs it
    /// with the caller's identity key, and returns the checkpoint. Checkpoints
    /// enable equivocation detection: members exchange signed Merkle roots and
    /// compare them to detect relay misbehavior.
    ///
    /// # Arguments
    ///
    /// * `context_id` -- The ID of the context whose event log to checkpoint.
    /// * `identity_did` -- The DID of the identity generating the checkpoint
    ///   (used for signing).
    /// * `epoch` -- The current MLS epoch (pass 0 for Broadcast contexts).
    ///
    /// # Returns
    ///
    /// A [`PyCheckpoint`] containing the signed checkpoint data.
    ///
    /// # Errors
    ///
    /// Raises `ContextError` if the context is not connected to the runtime
    /// or if signing fails. Raises `IdentityError` if the identity is not
    /// found in the registry.
    ///
    /// See ADR-011 acceptance criterion 8 and ADR-030.
    #[pyo3(name = "event_log_checkpoint")]
    pub fn event_log_checkpoint(
        &self,
        context_id: &str,
        identity_did: &str,
        epoch: u64,
    ) -> PyResult<PyCheckpoint> {
        let bi = &*self.inner;
        event_log_checkpoint_impl(bi, context_id, identity_did, epoch)
    }

    /// Generates a signed consistency checkpoint scoped to a member DID.
    ///
    /// Looks the signing identity up from this instance's identity registry by
    /// DID string, then signs a snapshot of the context event log's Merkle root
    /// and event count. The DID drives both the key-material lookup and the
    /// recorded `sender_did`. This is the canonical "checkpoint by DID" entry
    /// point, mirroring the NAPI bridge's `event_log_checkpoint_by_did`.
    ///
    /// # Arguments
    ///
    /// * `context_id` -- The ID of the context whose event log to checkpoint.
    /// * `did` -- The DID of the member generating the checkpoint. Must be
    ///   present in this instance's identity registry.
    /// * `epoch` -- The current MLS epoch (pass 0 for Broadcast contexts).
    ///
    /// # Returns
    ///
    /// A [`PyCheckpoint`] containing the signed checkpoint data.
    ///
    /// # Errors
    ///
    /// Raises `IdentityError` if `did` is not in the identity registry, or
    /// `ContextError` if the context is not registered or signing fails.
    ///
    /// See ADR-011 acceptance criterion 8 and ADR-030.
    #[pyo3(name = "event_log_checkpoint_by_did")]
    pub fn event_log_checkpoint_by_did(
        &self,
        context_id: &str,
        did: &str,
        epoch: u64,
    ) -> PyResult<PyCheckpoint> {
        let bi = &*self.inner;
        event_log_checkpoint_impl(bi, context_id, did, epoch)
    }
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

/// Registers event log bridge classes on the `_scp_core` module.
///
/// Post-migration (Phase 4 PR 4 sub-slice E), event log operations are
/// exposed as methods on `SCP`. Only the opaque result classes require
/// registration here.
///
/// Called from [`crate::_scp_core`] during module initialization.
///
/// # Errors
///
/// Returns `PyErr` if registration of classes fails.
pub fn register_event_log(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyEvent>()?;
    m.add_class::<PyProof>()?;
    m.add_class::<PyCheckpoint>()?;
    Ok(())
}
