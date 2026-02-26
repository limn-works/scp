//! `PyO3` bridge functions for event log queries and verification.
//!
//! Exposes SCP event log operations to Python:
//!
//! - [`py_event_log_query`] — Query the context event log with optional
//!   filters.
//! - [`py_event_log_verify`] — Verify a claim against the event log
//!   (inclusion/absence proofs).
//!
//! # Types
//!
//! - [`PyEvent`] — A protocol event (type, actor, timestamp, payload,
//!   sequence).
//! - [`PyProof`] — A verification proof (verified, proof type, details).
//!
//! See ADR-013 in `.docs/adrs/phase-3.md` §7 and ADR-011 for the event
//! log specification.

use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::error::ScpPyError;
use crate::types::json_to_py_dict;

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
/// Returned by [`py_event_log_verify`]. Contains the verification result,
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
// Bridge functions
// ---------------------------------------------------------------------------

/// Queries the context event log.
///
/// Returns a list of events matching the optional filter criteria. If no
/// filter is provided, returns all events in the log.
///
/// # Arguments
///
/// * `context_id` — The ID of the context whose event log to query.
/// * `filter` — An optional Python dict with filter parameters:
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
/// A list of [`PyEvent`] objects matching the filter.
///
/// # Errors
///
/// Raises `ContextError` if the context is not connected to the runtime
/// or if the query fails.
///
/// See ADR-013 §7: `py_event_log_query(handle, filter) -> list[PyEvent]`.
#[pyfunction]
#[pyo3(name = "event_log_query", signature = (_context_id, _filter=None))]
pub fn py_event_log_query(
    _context_id: &str,
    _filter: Option<&Bound<'_, PyDict>>,
) -> PyResult<Vec<PyEvent>> {
    Err(ScpPyError::ContextError(
        "not yet connected to runtime — event log query requires a live context handle"
            .to_owned(),
    )
    .into())
}

/// Verifies a claim against the context event log.
///
/// Generates and verifies a Merkle proof for the given claim. Supports
/// both inclusion proofs (proving an event IS in the log) and absence
/// proofs (proving an event is NOT in the log).
///
/// # Arguments
///
/// * `context_id` — The ID of the context whose event log to verify
///   against.
/// * `claim` — A Python dict describing the claim to verify:
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
/// See ADR-013 §7: `py_event_log_verify(handle, claim) -> PyProof`.
#[pyfunction]
#[pyo3(name = "event_log_verify")]
pub fn py_event_log_verify(
    py: Python<'_>,
    _context_id: &str,
    _claim: &Bound<'_, PyDict>,
) -> PyResult<PyProof> {
    // Ensure json_to_py_dict is available for future implementations
    // that will convert proof details to Python objects.
    let _ = json_to_py_dict(py, &serde_json::Value::Null)?;
    Err(ScpPyError::ContextError(
        "not yet connected to runtime — event log verification requires a live context handle"
            .to_owned(),
    )
    .into())
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

/// Registers event log bridge functions and classes on the `_scp_core` module.
///
/// Called from [`crate::_scp_core`] during module initialization.
///
/// # Errors
///
/// Returns `PyErr` if registration of functions or classes fails.
pub fn register_event_log(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyEvent>()?;
    m.add_class::<PyProof>()?;
    m.add_function(wrap_pyfunction!(py_event_log_query, m)?)?;
    m.add_function(wrap_pyfunction!(py_event_log_verify, m)?)?;
    Ok(())
}
