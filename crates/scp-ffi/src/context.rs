//! `PyO3` bridge functions for SCP context lifecycle and messaging.
//!
//! This module exposes context operations to Python as flat `#[pyfunction]`
//! definitions and opaque `#[pyclass]` types. The Pythonic wrapper layer
//! (`scp_sdk.Context`) in pure Python builds async context managers and
//! method-chaining ergonomics on top of these primitives.
//!
//! # Types
//!
//! - [`PyContextHandle`] -- Opaque handle to a context, storing metadata
//!   (context ID, lifecycle state, creator DID).
//! - [`PyContextParams`] -- Context creation parameters, constructed from a
//!   Python dict.
//! - [`PyMessage`] -- A received message with sender DID, payload, timestamp,
//!   and context ID.
//! - [`PyMessageReceiver`] -- Async iterator over incoming messages, wrapping
//!   a `tokio::sync::mpsc::Receiver<PyMessage>`.
//!
//! # Bridge functions
//!
//! All bridge functions accept `identity_did: &str` rather than a `PyIdentity`
//! reference. The Python SDK wrapper extracts `.did` before calling these
//! functions, avoiding cross-module coupling at the bridge level (identity.rs
//! is implemented separately).
//!
//! See ADR-013 in `.docs/adrs/phase-3.md` for the full specification.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use pyo3::exceptions::{PyRuntimeError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyDict;
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// PyContextHandle
// ---------------------------------------------------------------------------

/// Opaque handle to an SCP context.
///
/// Stores context metadata: unique ID, lifecycle state, and the DID of the
/// context creator. The actual context runtime (MLS group, transport
/// connections) lives in scp-core and will be connected in future stories.
///
/// Exposed to Python as `_scp_core.PyContextHandle` with read-only properties
/// for `context_id` and `state`.
#[pyclass]
#[derive(Debug, Clone)]
pub struct PyContextHandle {
    /// Unique identifier for this context.
    context_id: String,
    /// Current lifecycle state: "creating", "active", "closing", "closed", "expired".
    state: Arc<Mutex<String>>,
    /// DID of the context creator.
    creator_did: String,
}

#[pymethods]
impl PyContextHandle {
    /// Returns the context's unique identifier.
    #[getter]
    fn context_id(&self) -> &str {
        &self.context_id
    }

    /// Returns the context's current lifecycle state as a string.
    ///
    /// One of: "creating", "active", "closing", "closed", "expired".
    #[getter]
    fn state(&self) -> PyResult<String> {
        let guard = self.state.lock().map_err(|_| {
            PyRuntimeError::new_err("context state lock is poisoned")
        })?;
        Ok(guard.clone())
    }

    /// Returns the DID of the context creator.
    #[getter]
    fn creator_did(&self) -> &str {
        &self.creator_did
    }

    fn __repr__(&self) -> PyResult<String> {
        let state = self.state.lock().map_err(|_| {
            PyRuntimeError::new_err("context state lock is poisoned")
        })?;
        let repr = format!(
            "PyContextHandle(context_id='{}', state='{}', creator_did='{}')",
            self.context_id, *state, self.creator_did
        );
        drop(state);
        Ok(repr)
    }
}

impl PyContextHandle {
    /// Creates a new handle in the "creating" state.
    fn new(context_id: String, creator_did: String) -> Self {
        Self {
            context_id,
            state: Arc::new(Mutex::new("creating".to_owned())),
            creator_did,
        }
    }
}

// ---------------------------------------------------------------------------
// PyContextParams
// ---------------------------------------------------------------------------

/// Context creation parameters, constructed from a Python dict.
///
/// The dict may contain any of these keys (all optional):
/// - `ceiling` -- list of capability strings
/// - `roles` -- dict mapping role names to lists of capability strings
/// - `tools` -- list of tool name strings
/// - `ttl` -- float (seconds) or `None`
/// - `memory_scope` -- string: "ephemeral", "summary", "full"
/// - `governance` -- string: `"single_admin"`
///
/// Unrecognized keys are silently ignored. Missing keys use protocol defaults.
#[pyclass]
#[derive(Debug, Clone)]
pub struct PyContextParams {
    /// Capability ceiling -- maximum capabilities any participant can hold.
    ceiling: Vec<String>,
    /// Role definitions mapping role names to capability lists.
    roles: HashMap<String, Vec<String>>,
    /// Initial tool registrations by name.
    tools: Vec<String>,
    /// Optional time-to-live in seconds.
    ttl: Option<f64>,
    /// Memory scope: "ephemeral", "summary", or "full".
    memory_scope: String,
    /// Governance model: `"single_admin"`.
    governance: String,
}

#[pymethods]
impl PyContextParams {
    /// Creates a new `PyContextParams` from a Python dict.
    ///
    /// # Arguments
    ///
    /// * `params` -- A Python dict with optional keys: `ceiling`, `roles`,
    ///   `tools`, `ttl`, `memory_scope`, `governance`.
    ///
    /// # Errors
    ///
    /// Returns `TypeError` if a value has an unexpected type, or `ValueError`
    /// if a value is out of the valid set.
    #[new]
    fn new(params: &Bound<'_, PyDict>) -> PyResult<Self> {
        Self::from_py_dict(params)
    }

    #[getter]
    fn ceiling(&self) -> Vec<String> {
        self.ceiling.clone()
    }

    #[getter]
    fn roles(&self) -> HashMap<String, Vec<String>> {
        self.roles.clone()
    }

    #[getter]
    fn tools(&self) -> Vec<String> {
        self.tools.clone()
    }

    #[getter]
    #[allow(clippy::missing_const_for_fn)] // PyO3 getter cannot be const.
    fn ttl(&self) -> Option<f64> {
        self.ttl
    }

    #[getter]
    fn memory_scope(&self) -> &str {
        &self.memory_scope
    }

    #[getter]
    fn governance(&self) -> &str {
        &self.governance
    }

    fn __repr__(&self) -> String {
        format!(
            "PyContextParams(ceiling={:?}, roles={:?}, tools={:?}, ttl={:?}, \
             memory_scope='{}', governance='{}')",
            self.ceiling, self.roles, self.tools, self.ttl,
            self.memory_scope, self.governance
        )
    }
}

impl PyContextParams {
    /// Extracts context parameters from a Python dict using `PyO3`'s native
    /// extraction API.
    ///
    /// This avoids depending on `crate::types::py_dict_to_json` (which may be
    /// implemented by a parallel subagent) and uses `PyO3` extraction directly.
    fn from_py_dict(dict: &Bound<'_, PyDict>) -> PyResult<Self> {
        // ceiling: list[str] (default: empty)
        let ceiling: Vec<String> = match dict.get_item("ceiling")? {
            Some(val) => val.extract()?,
            None => Vec::new(),
        };

        // roles: dict[str, list[str]] (default: empty)
        let roles: HashMap<String, Vec<String>> = match dict.get_item("roles")? {
            Some(val) => val.extract()?,
            None => HashMap::new(),
        };

        // tools: list[str] (default: empty)
        let tools: Vec<String> = match dict.get_item("tools")? {
            Some(val) => val.extract()?,
            None => Vec::new(),
        };

        // ttl: Optional[float] (default: None)
        let ttl: Option<f64> = match dict.get_item("ttl")? {
            Some(val) if val.is_none() => None,
            Some(val) => Some(val.extract()?),
            None => None,
        };

        // memory_scope: str (default: "ephemeral")
        let memory_scope: String = match dict.get_item("memory_scope")? {
            Some(val) => {
                let scope: String = val.extract()?;
                match scope.as_str() {
                    "ephemeral" | "summary" | "full" => scope,
                    _ => {
                        return Err(PyValueError::new_err(format!(
                            "invalid memory_scope '{scope}': \
                             expected 'ephemeral', 'summary', or 'full'"
                        )));
                    }
                }
            }
            None => "ephemeral".to_owned(),
        };

        // governance: str (default: "single_admin")
        let governance: String = match dict.get_item("governance")? {
            Some(val) => {
                let gov: String = val.extract()?;
                match gov.as_str() {
                    "single_admin" => gov,
                    _ => {
                        return Err(PyValueError::new_err(format!(
                            "invalid governance '{gov}': expected 'single_admin'"
                        )));
                    }
                }
            }
            None => "single_admin".to_owned(),
        };

        Ok(Self {
            ceiling,
            roles,
            tools,
            ttl,
            memory_scope,
            governance,
        })
    }
}

// ---------------------------------------------------------------------------
// PyMessage
// ---------------------------------------------------------------------------

/// A received message from an SCP context.
///
/// Exposed to Python with read-only properties for all fields. The payload
/// is stored as raw bytes (`Vec<u8>`) and exposed to Python as `bytes`.
/// Messages originate from the Rust transport layer as encrypted byte
/// sequences, so bytes is the natural representation.
#[pyclass]
#[derive(Debug, Clone)]
pub struct PyMessage {
    /// DID of the message sender.
    sender_did: String,
    /// Message payload as raw bytes.
    payload: Vec<u8>,
    /// Message timestamp as seconds since Unix epoch.
    timestamp: f64,
    /// Context ID this message belongs to.
    context_id: String,
}

#[pymethods]
impl PyMessage {
    #[getter]
    fn sender_did(&self) -> &str {
        &self.sender_did
    }

    #[getter]
    fn payload<'py>(&self, py: Python<'py>) -> Bound<'py, pyo3::types::PyBytes> {
        pyo3::types::PyBytes::new(py, &self.payload)
    }

    #[getter]
    #[allow(clippy::missing_const_for_fn)] // PyO3 getter cannot be const.
    fn timestamp(&self) -> f64 {
        self.timestamp
    }

    #[getter]
    fn context_id(&self) -> &str {
        &self.context_id
    }

    fn __repr__(&self) -> String {
        format!(
            "PyMessage(sender_did='{}', context_id='{}', timestamp={})",
            self.sender_did, self.context_id, self.timestamp
        )
    }
}

impl PyMessage {
    /// Creates a new `PyMessage`. Used internally by the receive pipeline.
    #[must_use]
    #[allow(dead_code)] // Will be used when transport wiring is connected.
    pub const fn new(
        sender_did: String,
        payload: Vec<u8>,
        timestamp: f64,
        context_id: String,
    ) -> Self {
        Self {
            sender_did,
            payload,
            timestamp,
            context_id,
        }
    }
}

// ---------------------------------------------------------------------------
// PyMessageReceiver -- async iterator
// ---------------------------------------------------------------------------

/// Async iterator over incoming messages from an SCP context.
///
/// Implements Python's async iterator protocol (`__aiter__` + `__anext__`).
/// Wraps a `tokio::sync::mpsc::Receiver<PyMessage>` and bridges to Python's
/// asyncio. Returns `None` (which `PyO3` translates to `StopAsyncIteration`)
/// when the channel is closed (no more messages).
///
/// Created by [`py_context_receive`] -- not directly constructible from Python.
///
/// # Current behavior
///
/// In the current bridge layer (before transport wiring), the sender half of
/// the channel is dropped immediately after creation, so `__anext__` returns
/// `None` on the first call. When the full runtime is connected, the transport
/// layer will hold the sender and feed messages into the channel.
#[pyclass]
pub struct PyMessageReceiver {
    /// The receiving half of the message channel, wrapped in a std `Mutex` for
    /// synchronous access from `__anext__`. The receiver is `!Sync` so we
    /// protect it with a `Mutex` to allow shared `&self` access from `PyO3`.
    rx: Arc<Mutex<mpsc::Receiver<PyMessage>>>,
}

#[pymethods]
impl PyMessageReceiver {
    #[allow(clippy::missing_const_for_fn)] // PyO3 protocol method cannot be const.
    fn __aiter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    /// Returns the next message from the channel, or `None` to signal
    /// `StopAsyncIteration` when the channel is closed.
    ///
    /// `PyO3` translates `Ok(None)` into `StopAsyncIteration` for the Python
    /// async iterator protocol.
    fn __anext__(&self) -> PyResult<Option<PyMessage>> {
        let mut guard = self.rx.lock().map_err(|_| {
            PyRuntimeError::new_err("message receiver lock is poisoned")
        })?;

        // Use try_recv for non-blocking receive. When the transport layer is
        // wired in, this will be replaced with proper async receive driven by
        // the tokio runtime.
        let result = match guard.try_recv() {
            Ok(msg) => Ok(Some(msg)),
            // Channel empty (sender alive) or disconnected (sender dropped)
            // -- both return None. Empty means "no message yet" and
            // Disconnected means "iteration complete".
            Err(
                mpsc::error::TryRecvError::Empty
                | mpsc::error::TryRecvError::Disconnected,
            ) => Ok(None),
        };
        drop(guard);
        result
    }
}

impl PyMessageReceiver {
    /// Creates a new receiver from a tokio mpsc channel.
    #[must_use]
    pub fn new(rx: mpsc::Receiver<PyMessage>) -> Self {
        Self {
            rx: Arc::new(Mutex::new(rx)),
        }
    }
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Creates a new SCP context.
///
/// # Arguments
///
/// * `identity_did` -- The DID string of the identity creating the context.
/// * `params` -- A Python dict with context parameters. See [`PyContextParams`]
///   for accepted keys.
///
/// # Returns
///
/// A [`PyContextHandle`] in the "active" state.
///
/// # Errors
///
/// Returns `TypeError` if params contains invalid types, `ValueError` if
/// parameter values are out of range, or `RuntimeError` if context creation
/// fails.
#[pyfunction]
#[pyo3(signature = (identity_did, params))]
fn py_context_create(
    identity_did: &str,
    params: &Bound<'_, PyDict>,
) -> PyResult<PyContextHandle> {
    // Validate params eagerly (before any async work).
    let _parsed = PyContextParams::from_py_dict(params)?;

    // Generate a context ID. In the full runtime this would come from
    // scp-core's builder flow (MLS group formation, event log init).
    // For the bridge layer, we generate a timestamp-based ID.
    let context_id = format!("ctx-{:016x}", {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before Unix epoch")
            .as_nanos()
    });

    let handle = PyContextHandle::new(context_id.clone(), identity_did.to_owned());

    // Register runtime objects (ToolRegistry, EventLog, RoleState, RevocationList)
    // in the global runtime registry so that tools/UCAN/event_log bridge functions
    // can look them up by context ID.
    crate::runtime::register_context(&context_id, identity_did)
        .map_err(|e| PyRuntimeError::new_err(format!("failed to register context runtime: {e}")))?;

    // Transition to "active" -- in the full runtime this happens after MLS
    // group formation and parameter validation complete.
    {
        let mut guard = handle.state.lock().map_err(|_| {
            PyRuntimeError::new_err("context state lock is poisoned")
        })?;
        "active".clone_into(&mut guard);
    }

    Ok(handle)
}

/// Joins an existing SCP context.
///
/// # Arguments
///
/// * `handle` -- The context to join.
/// * `identity_did` -- The DID string of the identity joining.
///
/// # Errors
///
/// Returns `RuntimeError` if the context is not in "active" state.
#[pyfunction]
#[pyo3(signature = (handle, identity_did))]
fn py_context_join(handle: &PyContextHandle, identity_did: &str) -> PyResult<()> {
    let state = handle.state.lock().map_err(|_| {
        PyRuntimeError::new_err("context state lock is poisoned")
    })?;

    if *state != "active" {
        return Err(PyRuntimeError::new_err(format!(
            "cannot join context in '{state}' state -- context must be 'active'"
        )));
    }
    drop(state);

    // In the full runtime, this would:
    // 1. Generate a key package for the joining member.
    // 2. Add the member to the MLS group.
    // 3. Log the join event.
    let _ = identity_did; // Will be used when connected to scp-core runtime.

    Ok(())
}

/// Leaves an SCP context.
///
/// # Arguments
///
/// * `handle` -- The context to leave.
/// * `identity_did` -- The DID string of the identity leaving.
///
/// # Errors
///
/// Returns `RuntimeError` if the context is not in "active" state.
#[pyfunction]
#[pyo3(signature = (handle, identity_did))]
fn py_context_leave(handle: &PyContextHandle, identity_did: &str) -> PyResult<()> {
    let state = handle.state.lock().map_err(|_| {
        PyRuntimeError::new_err("context state lock is poisoned")
    })?;

    if *state != "active" {
        return Err(PyRuntimeError::new_err(format!(
            "cannot leave context in '{state}' state -- context must be 'active'"
        )));
    }
    drop(state);

    // In the full runtime, this would:
    // 1. Remove the member from the MLS group.
    // 2. Update sender keys.
    // 3. Log the leave event.
    let _ = identity_did; // Will be used when connected to scp-core runtime.

    Ok(())
}

/// Closes an SCP context.
///
/// Transitions the context from "active" to "closed". In the full runtime,
/// this initiates the cooperative closing window (member notification,
/// summary generation, key destruction).
///
/// # Arguments
///
/// * `handle` -- The context to close.
/// * `identity_did` -- The DID of the identity initiating the close (must be
///   admin or have close capability).
///
/// # Errors
///
/// Returns `RuntimeError` if the context is not in "active" state.
#[pyfunction]
#[pyo3(signature = (handle, identity_did))]
fn py_context_close(handle: &PyContextHandle, identity_did: &str) -> PyResult<()> {
    let mut state = handle.state.lock().map_err(|_| {
        PyRuntimeError::new_err("context state lock is poisoned")
    })?;

    if *state != "active" {
        return Err(PyRuntimeError::new_err(format!(
            "cannot close context in '{state}' state -- context must be 'active'"
        )));
    }

    // In the full runtime, this would:
    // 1. Initiate the closing window.
    // 2. Notify members.
    // 3. Wait for summary generation (if memory_scope == "summary").
    // 4. Destroy keys.
    let _ = identity_did; // Will be used when connected to scp-core runtime.

    // Transition directly to "closed" (skipping "closing" for the bridge
    // layer -- the full runtime will implement the cooperative closing window).
    "closed".clone_into(&mut state);
    drop(state);

    // Remove context from the runtime registry to free resources.
    crate::runtime::remove_context(&handle.context_id);

    Ok(())
}

/// Sends a message to an SCP context.
///
/// # Arguments
///
/// * `handle` -- The context to send to.
/// * `identity_did` -- The DID of the sender.
/// * `payload` -- The message payload (bytes or str).
///
/// # Errors
///
/// Returns `RuntimeError` if the context is not in "active" state, or
/// `TypeError` if the payload is not bytes or str.
#[pyfunction]
#[pyo3(signature = (handle, identity_did, payload))]
fn py_context_send(
    handle: &PyContextHandle,
    identity_did: &str,
    payload: &Bound<'_, PyAny>,
) -> PyResult<()> {
    let state = handle.state.lock().map_err(|_| {
        PyRuntimeError::new_err("context state lock is poisoned")
    })?;

    if *state != "active" {
        return Err(PyRuntimeError::new_err(format!(
            "cannot send to context in '{state}' state -- context must be 'active'"
        )));
    }
    drop(state);

    // Validate payload type: must be bytes or str.
    let is_bytes = payload.is_instance_of::<pyo3::types::PyBytes>();
    let is_str = payload.is_instance_of::<pyo3::types::PyString>();
    if !is_bytes && !is_str {
        return Err(PyTypeError::new_err("payload must be bytes or str"));
    }

    // In the full runtime, this would:
    // 1. Encrypt the payload via MLS/sender keys.
    // 2. Create an OuterEnvelope with provenance metadata.
    // 3. Send via the transport layer.
    // 4. Log the send event.
    let _ = identity_did; // Will be used when connected to scp-core runtime.

    Ok(())
}

/// Returns an async iterator of incoming messages for a context.
///
/// # Arguments
///
/// * `handle` -- The context to receive messages from.
///
/// # Returns
///
/// A [`PyMessageReceiver`] implementing Python's async iterator protocol.
/// Iterate with `async for msg in receiver:`.
///
/// # Errors
///
/// Returns `RuntimeError` if the context is not in "active" state.
#[pyfunction]
#[pyo3(signature = (handle,))]
fn py_context_receive(handle: &PyContextHandle) -> PyResult<PyMessageReceiver> {
    let state = handle.state.lock().map_err(|_| {
        PyRuntimeError::new_err("context state lock is poisoned")
    })?;

    if *state != "active" {
        return Err(PyRuntimeError::new_err(format!(
            "cannot receive from context in '{state}' state -- context must be 'active'"
        )));
    }
    drop(state);

    // Create a bounded channel for incoming messages. The capacity is sized
    // for typical agent message rates. In the full runtime, the transport
    // layer feeds messages into the sender half.
    let (_tx, rx) = mpsc::channel::<PyMessage>(256);

    // In the full runtime, `_tx` would be registered with the transport layer
    // so that incoming messages are forwarded to this receiver. For now, the
    // channel is created but the sender is dropped -- the iterator will
    // immediately yield StopAsyncIteration until the transport wiring is
    // connected.

    Ok(PyMessageReceiver::new(rx))
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

/// Registers all context bridge types and functions with the Python module.
///
/// Called from `lib.rs` during module initialization.
///
/// # Errors
///
/// Returns `PyErr` if any class or function registration fails.
pub fn register_context(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyContextHandle>()?;
    m.add_class::<PyContextParams>()?;
    m.add_class::<PyMessage>()?;
    m.add_class::<PyMessageReceiver>()?;
    m.add_function(wrap_pyfunction!(py_context_create, m)?)?;
    m.add_function(wrap_pyfunction!(py_context_join, m)?)?;
    m.add_function(wrap_pyfunction!(py_context_leave, m)?)?;
    m.add_function(wrap_pyfunction!(py_context_close, m)?)?;
    m.add_function(wrap_pyfunction!(py_context_send, m)?)?;
    m.add_function(wrap_pyfunction!(py_context_receive, m)?)?;
    Ok(())
}
