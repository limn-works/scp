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
//! - [`PyProof`] -- A verification proof (verified, proof type, details).
//! - [`PyCheckpoint`] -- A signed consistency checkpoint (context ID, sender
//!   DID, event count, Merkle root, epoch, timestamp, signature).
//!
//! See ADR-013 in `.docs/adrs/phase-3.md` §7 and ADR-011 for the event
//! log specification. See ADR-030 in `.docs/adrs/phase-6.md` for checkpoint
//! and pruning design.

use pyo3::prelude::*;
use pyo3::types::PyDict;
use scp_ffi_common::error_codes as codes;
use scp_platform::traits::Storage;
use scp_primitives::Clock;

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
    /// The event type (e.g., `"ContextCreated"`, `"MessageSent"`,
    /// `"ToolInvoked"`).
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

/// A verification proof from the event log, exposed to Python.
///
/// Returned by `PyScp::event_log_verify`. Contains the verification result,
/// the type of proof (inclusion or absence), and proof details as a
/// JSON-compatible Python object.
///
/// See ADR-011 (Merkle proofs) and ADR-013 §7 (bridge layer).
#[pyclass(name = "Proof")]
#[derive(Debug)]
pub struct PyProof {
    /// `True` if the claim was verified successfully.
    #[pyo3(get)]
    pub verified: bool,

    /// The proof type: `"inclusion"` or `"absence"`.
    #[pyo3(get)]
    pub proof_type: String,

    /// Proof details as a JSON-compatible Python object. Contains the
    /// Merkle path (for inclusion proofs) or sorted neighbors (for
    /// absence proofs).
    #[pyo3(get)]
    pub details: PyObject,
}

#[pymethods]
impl PyProof {
    fn __repr__(&self) -> String {
        format!(
            "Proof(verified={}, proof_type={:?})",
            self.verified, self.proof_type
        )
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
/// A list of [`PyEvent`] objects. Returns deserialized real events when
/// event payloads have been persisted via `ProtocolRepository`, or a single
/// `LogSummary` event with Merkle root and event count as fallback.
///
/// # Errors
///
/// Raises `ContextError` if the context is not connected to the runtime
/// or if the query fails.
///
/// See ADR-013 §7: `py_event_log_query(handle, filter) -> list[PyEvent]`.
/// Queries the shared `ContextManager`'s event log provider and maps the
/// resulting entries into [`PyEvent`]s using the same shape NAPI emits from
/// its `MerkleEventLogProvider` path.
///
/// Returns `Ok(Some(events))` when the manager is initialized AND has
/// entries for the context, `Ok(None)` when the caller should fall back to
/// the bridge-local per-context `EventLog` (e.g. UCAN revocation writes,
/// tests that bypass the manager).
fn query_manager_entries(
    bi: &PyBridgeInstance,
    py: Python<'_>,
    context_id: &str,
    query_filter: &scp_core::store::event_log::EventQueryFilter,
) -> PyResult<Option<Vec<PyEvent>>> {
    let ctx_id_bytes = scp_core::context::context_id_bytes(context_id);
    let Some(entries) = crate::runtime::context_manager(bi)
        .ok()
        .and_then(|mgr| mgr.event_log_entries(&ctx_id_bytes).ok().flatten())
    else {
        return Ok(None);
    };
    if entries.is_empty() {
        return Ok(None);
    }

    let mut py_events = Vec::new();
    for (idx, entry) in entries.iter().enumerate() {
        if let Some(ref et) = query_filter.event_type
            && entry.event != *et
        {
            continue;
        }
        #[allow(clippy::cast_precision_loss)]
        let timestamp = entry.timestamp as f64;
        let payload_json = serde_json::json!({
            "hash": encode_hex(&entry.hash),
        });
        let payload = json_to_py_dict(py, &payload_json)?;
        py_events.push(PyEvent {
            event_type: entry.event.clone(),
            // `EventLogEntry` does not carry actor DID.
            actor_did: String::new(),
            timestamp,
            payload,
            sequence: idx as u64,
        });
        if let Some(limit) = query_filter.limit
            && py_events.len() >= limit
        {
            break;
        }
    }
    Ok(Some(py_events))
}

/// See GitHub issue #303.
fn event_log_query_impl(
    bi: &PyBridgeInstance,
    py: Python<'_>,
    context_id: &str,
    filter: Option<&Bound<'_, PyDict>>,
) -> PyResult<Vec<PyEvent>> {
    validate::validate_context_id(context_id)?;

    // Parse filter parameters from the Python dict (needed for both the
    // ContextManager-entries path and the storage fallback).
    let query_filter = parse_event_query_filter(filter)?;

    // First, try the ContextManager's event log provider — this is the
    // authoritative source populated by `builder_create_context`
    // (`ContextCreated` at step 7) and subsequent manager operations.
    // Mirrors the NAPI bridge. Aligned across PyO3/NAPI/WASM/UniFFI —
    // pinned by the cross-bridge parity harness's `OP_EVENT_LOG_APPEND`
    // and `OP_EVENT_LOG_FILTERED` (ADR-046).
    if let Some(events) = query_manager_entries(bi, py, context_id, &query_filter)? {
        return Ok(events);
    }

    // Fallback: look up this bridge's per-context event log from the runtime
    // registry. This path is used by legacy tests and callers that write
    // directly to the per-context `EventLog` (e.g. UCAN revocation).
    let (event_count, merkle_root_hex) = crate::runtime::with_context(bi, context_id, |rt| {
        let count = scp_event_log::tree::event_count(&rt.event_log);
        let root = scp_event_log::tree::root(&rt.event_log);
        Ok((count, encode_hex(&root)))
    })?;

    // If the log is empty, return an empty list.
    if event_count == 0 {
        return Ok(Vec::new());
    }

    // Attempt to load real events from storage if available.
    // Uses the Storage trait directly because the global storage is
    // Arc<EncryptingAdapter<InMemoryStorage>> and ProtocolRepository requires
    // an owned Storage impl. The key convention matches ProtocolRepository's
    // event_data key format (GitHub issue #303).
    if let Ok(storage) = crate::runtime::get_storage(bi) {
        let rt = crate::runtime()?;
        let prefix = format!("context/{context_id}/event_data/");
        let keys_result = rt.block_on(storage.list_keys(&prefix));

        if let Ok(keys) = keys_result {
            let seq_start = query_filter.sequence_start.unwrap_or(0);
            let seq_end = query_filter.sequence_end.unwrap_or(event_count);
            let start_suffix = format!("{seq_start:020}");
            let end_suffix = format!("{seq_end:020}");

            let mut py_events = Vec::new();
            for key in &keys {
                if let Some(seq_str) = key.strip_prefix(&prefix) {
                    if seq_str >= end_suffix.as_str() {
                        break;
                    }
                    if seq_str < start_suffix.as_str() {
                        continue;
                    }
                    if let Ok(Some(data)) = rt.block_on(storage.retrieve(key))
                        && let Ok(event) = rmp_serde::from_slice::<scp_event_log::Event>(&data)
                    {
                        // Apply additional filters.
                        if let Some(ref et) = query_filter.event_type
                            && format!("{:?}", event.event_type) != *et
                        {
                            continue;
                        }
                        if let Some(ref actor) = query_filter.actor_did
                            && event.actor_did.0 != *actor
                        {
                            continue;
                        }
                        if let Some(ts_start) = query_filter.timestamp_start
                            && event.timestamp < ts_start
                        {
                            continue;
                        }
                        if let Some(ts_end) = query_filter.timestamp_end
                            && event.timestamp >= ts_end
                        {
                            continue;
                        }

                        let payload_json = serde_json::json!({
                            "data": serde_json::to_value(&event.payload.data).unwrap_or_default(),
                        });
                        let payload = json_to_py_dict(py, &payload_json)?;

                        #[allow(clippy::cast_precision_loss)]
                        py_events.push(PyEvent {
                            event_type: format!("{:?}", event.event_type),
                            actor_did: event.actor_did.0.clone(),
                            timestamp: event.timestamp as f64,
                            payload,
                            sequence: event.sequence,
                        });

                        if let Some(limit) = query_filter.limit
                            && py_events.len() >= limit
                        {
                            break;
                        }
                    }
                }
            }
            if !py_events.is_empty() {
                return Ok(py_events);
            }
        }
    }

    // Fallback: Build a summary event with log metadata when ProtocolRepository
    // is unavailable or contains no event payloads for this context.
    let payload_json = serde_json::json!({
        "event_count": event_count,
        "merkle_root": merkle_root_hex,
    });
    let payload = json_to_py_dict(py, &payload_json)?;

    let summary_event = PyEvent {
        event_type: "LogSummary".to_owned(),
        actor_did: String::new(),
        #[allow(clippy::cast_precision_loss)] // Unix timestamp seconds fit in f64 mantissa for centuries.
        timestamp: scp_primitives::SystemClock.now_secs() as f64,
        payload,
        sequence: event_count.saturating_sub(1),
    };

    let events = vec![summary_event];

    // Apply limit if specified.
    if let Some(lim) = query_filter.limit {
        Ok(events.into_iter().take(lim).collect())
    } else {
        Ok(events)
    }
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
/// A [`PyProof`] with the verification result, proof type, and details.
///
/// # Errors
///
/// Raises `ContextError` if the context is not connected to the runtime
/// or if the verification fails (empty log, invalid index, etc.).
///
/// See ADR-013 §7.
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

    let claim_type = claim_json
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            ScpPyError::validation("claim must include 'type' field ('inclusion' or 'absence')")
        })?;

    match claim_type {
        "inclusion" => {
            let leaf_index = claim_json
                .get("leaf_index")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| {
                    ScpPyError::validation("inclusion claim must include 'leaf_index' (integer)")
                })?;

            // Generate and verify the inclusion proof via scp-core.
            let proof_result = crate::runtime::with_context(bi, context_id, |rt| {
                let proof = scp_event_log::proof::prove_inclusion(&rt.event_log, leaf_index)
                    .map_err(|e| ScpPyError::context(format!("inclusion proof failed: {e}")))?;
                let verified = scp_event_log::proof::verify_inclusion(&proof);

                let path_steps: Vec<serde_json::Value> = proof
                    .path
                    .iter()
                    .map(|step| {
                        let direction = match step.direction {
                            scp_event_log::proof::Direction::Left => "left",
                            scp_event_log::proof::Direction::Right => "right",
                        };
                        serde_json::json!({
                            "sibling_hash": encode_hex(&step.sibling_hash),
                            "direction": direction,
                        })
                    })
                    .collect();

                let details = serde_json::json!({
                    "leaf_index": proof.leaf_index,
                    "leaf_hash": encode_hex(&proof.leaf_hash),
                    "root": encode_hex(&proof.root),
                    "path": path_steps,
                    "path_length": proof.path.len(),
                });

                Ok((verified, details))
            })?;

            let (verified, details_json) = proof_result;
            let details = json_to_py_dict(py, &details_json)?;

            Ok(PyProof {
                verified,
                proof_type: "inclusion".to_owned(),
                details,
            })
        }
        "absence" => {
            let event_hash_hex = claim_json
                .get("event_hash")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    ScpPyError::validation("absence claim must include 'event_hash' (hex string)")
                })?;

            // Decode the hex event hash.
            let event_hash = decode_hex_hash(event_hash_hex)
                .map_err(|e| ScpPyError::validation(format!("invalid event_hash: {e}")))?;

            // Generate the absence proof via scp-core.
            let proof_result =
                crate::runtime::with_context(bi, context_id, |rt| {
                    let proof = scp_event_log::proof::prove_absence(&rt.event_log, &event_hash)
                        .map_err(|e| ScpPyError::context(format!("absence proof failed: {e}")))?;

                    let lower = proof.lower.as_ref().map(|lwp| {
                        serde_json::json!({
                            "leaf_hash": encode_hex(&lwp.leaf_hash),
                            "leaf_index": lwp.leaf_index,
                        })
                    });

                    let upper = proof.upper.as_ref().map(|uwp| {
                        serde_json::json!({
                            "leaf_hash": encode_hex(&uwp.leaf_hash),
                            "leaf_index": uwp.leaf_index,
                        })
                    });

                    // Verify the neighbor inclusion proofs.
                    let lower_verified = proof.lower.as_ref().is_none_or(|lwp| {
                        scp_event_log::proof::verify_inclusion(&lwp.inclusion_proof)
                    });
                    let upper_verified = proof.upper.as_ref().is_none_or(|uwp| {
                        scp_event_log::proof::verify_inclusion(&uwp.inclusion_proof)
                    });
                    let verified = lower_verified && upper_verified;

                    let details = serde_json::json!({
                        "query_hash": encode_hex(&proof.query_hash),
                        "root": encode_hex(&proof.root),
                        "leaf_count": proof.leaf_count,
                        "lower": lower,
                        "upper": upper,
                    });

                    Ok((verified, details))
                })?;

            let (verified, details_json) = proof_result;
            let details = json_to_py_dict(py, &details_json)?;

            Ok(PyProof {
                verified,
                proof_type: "absence".to_owned(),
                details,
            })
        }
        other => Err(ScpPyError::validation(format!(
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
fn event_log_checkpoint_impl(
    bi: &PyBridgeInstance,
    context_id: &str,
    identity_did: &str,
    epoch: u64,
) -> PyResult<PyCheckpoint> {
    validate::validate_context_id(context_id)?;
    validate::validate_did(identity_did)?;
    let rt = crate::runtime()?;

    let context_id_owned = context_id.to_owned();
    let identity_did_owned = identity_did.to_owned();

    let sender_did = scp_identity::DID(identity_did_owned.clone());

    let checkpoint = crate::runtime::with_identity(bi, &identity_did_owned, |entry| {
        crate::runtime::with_context(bi, &context_id_owned, |ctx_rt| {
            let result = rt.block_on(async {
                let signer = scp_core::event_log::KeyCustodySigner {
                    custody: entry.custody.as_ref(),
                    key: &entry.identity.active_signing_key,
                };
                scp_event_log::checkpoint::generate_checkpoint(
                    &ctx_rt.event_log,
                    &sender_did,
                    epoch,
                    &signer,
                )
                .await
            });

            result.map_err(|e| ScpPyError::context(format!("checkpoint generation failed: {e}")))
        })
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
    /// A [`PyProof`] with the verification result, proof type, and details.
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
