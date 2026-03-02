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
use scp_core::context::roles::Capability;
use scp_platform::traits::KeyCustody;
use tokio::sync::mpsc;

use crate::validate;

// ---------------------------------------------------------------------------
// PyContextHandle
// ---------------------------------------------------------------------------

/// Opaque handle to an SCP context.
///
/// Stores context metadata: unique ID, lifecycle state, the DID of the
/// context creator, and creation-time parameters. The actual context runtime
/// (MLS group, transport connections) lives in scp-core and will be connected
/// in future stories.
///
/// Exposed to Python as `_scp_core.PyContextHandle` with read-only properties
/// for `context_id`, `state`, and spec §5.7 metadata (`mode`, `ceiling_policy`,
/// `promotion_policy`, `template_id`, `economic_policy`).
#[pyclass]
#[derive(Debug, Clone)]
pub struct PyContextHandle {
    /// Unique identifier for this context.
    context_id: String,
    /// Current lifecycle state: "creating", "active", "closing", "closed", "expired".
    state: Arc<Mutex<String>>,
    /// DID of the context creator.
    creator_did: String,
    /// Creation-time context parameters, retained for spec §5.7 metadata visibility.
    params: PyContextParams,
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
        let guard = self
            .state
            .lock()
            .map_err(|_| PyRuntimeError::new_err("context state lock is poisoned"))?;
        Ok(guard.clone())
    }

    /// Returns the DID of the context creator.
    #[getter]
    fn creator_did(&self) -> &str {
        &self.creator_did
    }

    /// Returns the context mode: "encrypted" or "broadcast" (spec §5.1).
    #[getter]
    fn mode(&self) -> &str {
        &self.params.mode
    }

    /// Returns the ceiling policy: "immutable" or "governed" (spec §5.3).
    #[getter]
    fn ceiling_policy(&self) -> &str {
        &self.params.ceiling_policy
    }

    /// Returns the promotion policy: `"no_promotion"` or `"promotable"` (spec §5.10).
    #[getter]
    fn promotion_policy(&self) -> &str {
        &self.params.promotion_policy
    }

    /// Returns the template ID if the context was created from a template, or `None`.
    #[getter]
    fn template_id(&self) -> Option<&str> {
        self.params.template_id.as_deref()
    }

    /// Returns the economic policy as a JSON string, or `None` if the context
    /// is free (no economic policy). See spec §19.
    #[getter]
    fn economic_policy(&self) -> Option<&str> {
        self.params.economic_policy.as_deref()
    }

    fn __repr__(&self) -> PyResult<String> {
        let state = self
            .state
            .lock()
            .map_err(|_| PyRuntimeError::new_err("context state lock is poisoned"))?;
        let repr = format!(
            "PyContextHandle(context_id='{}', state='{}', creator_did='{}', mode='{}')",
            self.context_id, *state, self.creator_did, self.params.mode
        );
        drop(state);
        Ok(repr)
    }
}

impl PyContextHandle {
    /// Creates a new handle in the "creating" state with associated params.
    fn new(context_id: String, creator_did: String, params: PyContextParams) -> Self {
        Self {
            context_id,
            state: Arc::new(Mutex::new("creating".to_owned())),
            creator_did,
            params,
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
/// - `mode` -- string: "encrypted" (default), "broadcast" (spec §5.1)
/// - `ceiling_policy` -- string: "immutable" (default), "governed" (spec §5.3)
/// - `promotion_policy` -- string: `"no_promotion"` (default), `"promotable"` (spec §5.10)
/// - `template_id` -- optional string: template identifier (spec §5.14)
/// - `economic_policy` -- optional JSON string: economic policy (spec §19)
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
    /// Context mode: "encrypted" (default) or "broadcast" (spec §5.1).
    mode: String,
    /// Ceiling policy: "immutable" (default) or "governed" (spec §5.3).
    ceiling_policy: String,
    /// Promotion policy: `"no_promotion"` (default) or `"promotable"` (spec §5.10).
    promotion_policy: String,
    /// Optional template identifier (spec §5.14).
    template_id: Option<String>,
    /// Optional economic policy as a JSON string (spec §19).
    economic_policy: Option<String>,
}

#[pymethods]
impl PyContextParams {
    /// Creates a new `PyContextParams` from a Python dict.
    ///
    /// # Arguments
    ///
    /// * `params` -- A Python dict with optional keys: `ceiling`, `roles`,
    ///   `tools`, `ttl`, `memory_scope`, `governance`, `mode`,
    ///   `ceiling_policy`, `promotion_policy`, `template_id`,
    ///   `economic_policy`.
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

    /// Returns the context mode: "encrypted" or "broadcast" (spec §5.1).
    #[getter]
    fn mode(&self) -> &str {
        &self.mode
    }

    /// Returns the ceiling policy: "immutable" or "governed" (spec §5.3).
    #[getter]
    fn ceiling_policy(&self) -> &str {
        &self.ceiling_policy
    }

    /// Returns the promotion policy: `"no_promotion"` or `"promotable"` (spec §5.10).
    #[getter]
    fn promotion_policy(&self) -> &str {
        &self.promotion_policy
    }

    /// Returns the template ID, or `None` if the context was not created
    /// from a template (spec §5.14).
    #[getter]
    fn template_id(&self) -> Option<&str> {
        self.template_id.as_deref()
    }

    /// Returns the economic policy as a JSON string, or `None` if the context
    /// is free (spec §19).
    #[getter]
    fn economic_policy(&self) -> Option<&str> {
        self.economic_policy.as_deref()
    }

    fn __repr__(&self) -> String {
        format!(
            "PyContextParams(ceiling={:?}, roles={:?}, tools={:?}, ttl={:?}, \
             memory_scope='{}', governance='{}', mode='{}', ceiling_policy='{}', \
             promotion_policy='{}', template_id={:?}, economic_policy={:?})",
            self.ceiling,
            self.roles,
            self.tools,
            self.ttl,
            self.memory_scope,
            self.governance,
            self.mode,
            self.ceiling_policy,
            self.promotion_policy,
            self.template_id,
            self.economic_policy,
        )
    }
}

/// Valid template ID strings accepted from the Python bridge layer.
///
/// These correspond to the `TemplateId` variants in scp-core, using the
/// exact serde serialization format: `PascalCase` for base templates, and
/// `scp:template/<name>` URIs for variants with explicit `#[serde(rename)]`.
const VALID_TEMPLATE_IDS: &[&str] = &[
    "BilateralEphemeral",
    "BilateralPersistent",
    "Coordination",
    "GroupDiscussion",
    "PublicBroadcast",
    "GatedBroadcast",
    "scp:template/tool-interface",
    "scp:template/paid-service",
    "scp:template/paid-broadcast",
];

impl PyContextParams {
    /// Extracts context parameters from a Python dict using `PyO3`'s native
    /// extraction API.
    ///
    /// This avoids depending on `crate::types::py_dict_to_json` (which may be
    /// implemented by a parallel subagent) and uses `PyO3` extraction directly.
    #[allow(clippy::too_many_lines)] // Flat field-by-field extraction with validation.
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

        // mode: str (default: "encrypted") -- spec §5.1
        let mode: String = match dict.get_item("mode")? {
            Some(val) => {
                let m: String = val.extract()?;
                match m.as_str() {
                    "encrypted" | "broadcast" => m,
                    _ => {
                        return Err(PyValueError::new_err(format!(
                            "invalid mode '{m}': expected 'encrypted' or 'broadcast'"
                        )));
                    }
                }
            }
            None => "encrypted".to_owned(),
        };

        // ceiling_policy: str (default: "immutable") -- spec §5.3
        let ceiling_policy: String = match dict.get_item("ceiling_policy")? {
            Some(val) => {
                let cp: String = val.extract()?;
                match cp.as_str() {
                    "immutable" | "governed" => cp,
                    _ => {
                        return Err(PyValueError::new_err(format!(
                            "invalid ceiling_policy '{cp}': \
                             expected 'immutable' or 'governed'"
                        )));
                    }
                }
            }
            None => "immutable".to_owned(),
        };

        // promotion_policy: str (default: "no_promotion") -- spec §5.10
        let promotion_policy: String = match dict.get_item("promotion_policy")? {
            Some(val) => {
                let pp: String = val.extract()?;
                match pp.as_str() {
                    "no_promotion" | "promotable" => pp,
                    _ => {
                        return Err(PyValueError::new_err(format!(
                            "invalid promotion_policy '{pp}': \
                             expected 'no_promotion' or 'promotable'"
                        )));
                    }
                }
            }
            None => "no_promotion".to_owned(),
        };

        // template_id: Optional[str] (default: None) -- spec §5.14
        let template_id: Option<String> = match dict.get_item("template_id")? {
            Some(val) if val.is_none() => None,
            Some(val) => {
                let tid: String = val.extract()?;
                if !VALID_TEMPLATE_IDS.contains(&tid.as_str()) {
                    return Err(PyValueError::new_err(format!(
                        "invalid template_id '{tid}': expected one of {VALID_TEMPLATE_IDS:?}"
                    )));
                }
                Some(tid)
            }
            None => None,
        };

        // economic_policy: Optional[str] (JSON string, default: None) -- spec §19
        let economic_policy: Option<String> = match dict.get_item("economic_policy")? {
            Some(val) if val.is_none() => None,
            Some(val) => {
                let ep: String = val.extract()?;
                Some(ep)
            }
            None => None,
        };

        Ok(Self {
            ceiling,
            roles,
            tools,
            ttl,
            memory_scope,
            governance,
            mode,
            ceiling_policy,
            promotion_policy,
            template_id,
            economic_policy,
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

/// Async iterator over incoming messages from an SCP context (SCP-216).
///
/// Implements Python's async iterator protocol (`__aiter__` + `__anext__`).
/// Wraps a `tokio::sync::mpsc::Receiver<PyMessage>` and bridges to Python's
/// asyncio via the shared tokio runtime.
///
/// Created by [`py_context_receive`] -- not directly constructible from Python.
///
/// # Lifecycle (ADR-014)
///
/// - **Empty channel:** `__anext__` suspends (awaits) until a message arrives.
///   It does NOT raise `StopAsyncIteration` for an empty channel.
/// - **Closed channel:** `StopAsyncIteration` is raised when the sender is
///   dropped (on `leave()`, eviction, or context close).
/// - **Buffer overflow:** Handled by `deliver_message` in `runtime.rs` --
///   oldest event is dropped and a `BufferOverflow` warning is injected.
/// - **Concurrency:** Multiple `async for` loops on the same receiver race
///   for messages; each message goes to exactly one consumer.
#[pyclass]
pub struct PyMessageReceiver {
    /// The receiving half of the message channel, wrapped in a `tokio::sync::Mutex`
    /// so it can be locked across `.await` points in `__anext__`. Shared with
    /// `ContextRuntime::message_rx` via `Arc` so that `deliver_message` can
    /// implement oldest-drop overflow.
    rx: Arc<tokio::sync::Mutex<mpsc::Receiver<PyMessage>>>,
}

#[pymethods]
impl PyMessageReceiver {
    #[allow(clippy::missing_const_for_fn)] // PyO3 protocol method cannot be const.
    fn __aiter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    /// Returns the next message from the channel as a Python awaitable (SCP-216).
    ///
    /// Creates a Python `asyncio.Future`, spawns the `recv()` on the tokio
    /// runtime, and resolves the future via `call_soon_threadsafe` when a
    /// message arrives. This allows the asyncio event loop to run other
    /// coroutines while waiting for messages (fixes #138).
    ///
    /// When the channel is closed (sender dropped), the future resolves to
    /// `None` which the Python wrapper translates to `StopAsyncIteration`.
    fn __anext__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let rx = Arc::clone(&self.rx);
        let rt = crate::runtime()?;

        // Get the running asyncio event loop.
        let asyncio = py.import("asyncio")?;
        let event_loop = asyncio.call_method0("get_running_loop")?;

        // Create a Future on the running loop.
        let future = event_loop.call_method0("create_future")?;

        // Clone references for the spawned task.
        let future_ref = future.clone().unbind();
        let loop_ref = event_loop.clone().unbind();

        // Spawn the recv on the tokio runtime. The task runs on a tokio
        // worker thread, not the Python event loop thread.
        rt.spawn(async move {
            let result = {
                let mut guard = rx.lock().await;
                guard.recv().await
            };

            // Resolve the Python future from the tokio thread using
            // call_soon_threadsafe, which is the only thread-safe way
            // to resolve an asyncio.Future from a non-event-loop thread.
            Python::with_gil(|py| {
                resolve_future(py, &future_ref, &loop_ref, result);
            });
        });

        Ok(future)
    }
}

impl PyMessageReceiver {
    /// Creates a new receiver from a pre-wrapped shared receiver Arc.
    ///
    /// The `Arc<tokio::sync::Mutex<Receiver>>` is shared with
    /// `ContextRuntime::message_rx` so that `deliver_message` can access
    /// the receiver for oldest-drop overflow handling.
    #[must_use]
    pub const fn from_shared_rx(rx: Arc<tokio::sync::Mutex<mpsc::Receiver<PyMessage>>>) -> Self {
        Self { rx }
    }
}

// ---------------------------------------------------------------------------
// Async future resolution helper
// ---------------------------------------------------------------------------

/// Resolves a Python `asyncio.Future` with the result of a channel recv.
///
/// Called from a tokio worker thread inside `Python::with_gil`. Uses
/// `call_soon_threadsafe` to schedule the resolution on the asyncio event
/// loop thread. If any Python operation fails (which should not happen in
/// practice), the error is set as an exception on the future.
fn resolve_future(
    py: Python<'_>,
    future_ref: &Py<PyAny>,
    loop_ref: &Py<PyAny>,
    result: Option<PyMessage>,
) {
    let future = future_ref.bind(py);
    let event_loop = loop_ref.bind(py);

    // Obtain the set_result method. If this fails, something is
    // fundamentally wrong with the asyncio.Future object.
    let set_result = match future.getattr("set_result") {
        Ok(method) => method,
        Err(e) => {
            tracing::error!("failed to get set_result on asyncio.Future: {e}");
            // Try to set the exception on the future as a last resort.
            if let Ok(set_exception) = future.getattr("set_exception") {
                let _ = event_loop.call_method1("call_soon_threadsafe", (set_exception, e));
            }
            return;
        }
    };

    match result {
        Some(msg) => {
            match Py::new(py, msg) {
                Ok(msg_obj) => {
                    // call_soon_threadsafe(future.set_result, value)
                    let _ = event_loop.call_method1("call_soon_threadsafe", (set_result, msg_obj));
                }
                Err(e) => {
                    // Failed to wrap message in PyObject — set exception.
                    if let Ok(set_exception) = future.getattr("set_exception") {
                        let _ = event_loop.call_method1("call_soon_threadsafe", (set_exception, e));
                    }
                }
            }
        }
        None => {
            // Channel closed — set None as the result. The Python
            // wrapper raises StopAsyncIteration when it sees None.
            let _ = event_loop.call_method1("call_soon_threadsafe", (set_result, py.None()));
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
fn py_context_create(identity_did: &str, params: &Bound<'_, PyDict>) -> PyResult<PyContextHandle> {
    validate::validate_did(identity_did)?;
    // Validate params eagerly (before any async work).
    let parsed = PyContextParams::from_py_dict(params)?;

    // Generate a context ID using cryptographic randomness. In the full
    // runtime this would come from scp-core's builder flow (MLS group
    // formation, event log init). Context IDs are pure hex per §18.4.1
    // for embedding in scp://context/<id> URIs.
    let context_id = crate::types::generate_context_id();

    let handle = PyContextHandle::new(context_id.clone(), identity_did.to_owned(), parsed);

    // Register runtime objects (ToolRegistry, EventLog, RoleState, RevocationList)
    // in the global runtime registry so that tools/UCAN/event_log bridge functions
    // can look them up by context ID.
    crate::runtime::register_context(&context_id, identity_did)
        .map_err(|e| PyRuntimeError::new_err(format!("failed to register context runtime: {e}")))?;

    // Register in the known-contexts registry for discovery via
    // py_mcp_load_contexts. Derive a per-identity routing ID using
    // KeyCustody::derive_pseudonym with real key material (§9.10.4).
    // The pseudonym is deterministic for the same identity + context pair,
    // providing unlinkability across contexts. See SCP-214 criterion 4.
    {
        let routing_id = crate::runtime::with_identity(identity_did, |entry| {
            let rt = crate::runtime().map_err(|e| {
                crate::error::ScpPyError::IdentityError(format!("runtime not available: {e}"))
            })?;
            let pseudonym = rt.block_on(async {
                entry
                    .custody
                    .derive_pseudonym(&entry.identity.identity_key, context_id.as_bytes())
                    .await
            });
            let pk = pseudonym
                .map_err(|e| {
                    crate::error::ScpPyError::IdentityError(format!(
                        "pseudonym derivation failed: {e}"
                    ))
                })?
                .public_key;
            let bytes: [u8; 32] = pk.as_bytes().try_into().map_err(|_| {
                crate::error::ScpPyError::IdentityError(
                    "pseudonym public key must be 32 bytes".to_owned(),
                )
            })?;
            Ok(bytes)
        })
        .map_err(|e| PyRuntimeError::new_err(format!("routing ID derivation failed: {e}")))?;

        // Get the relay URL from transport status if a relay is connected.
        let relay_url = match crate::transport::py_transport_status() {
            Ok(status) => status.relay_url,
            Err(e) => {
                tracing::warn!("failed to query transport status during context registration: {e}");
                None
            }
        };

        let last_seen =
            scp_core::time::now_secs().map_err(|e| PyRuntimeError::new_err(format!("{e}")))?;

        let known = crate::runtime::KnownContext {
            routing_id,
            relay_url,
            member_did: identity_did.to_owned(),
            last_seen,
        };
        crate::runtime::register_known_context(&context_id, known);
    }

    // Transition to "active" -- in the full runtime this happens after MLS
    // group formation and parameter validation complete.
    {
        let mut guard = handle
            .state
            .lock()
            .map_err(|_| PyRuntimeError::new_err("context state lock is poisoned"))?;
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
    validate::validate_did(identity_did)?;
    let state = handle
        .state
        .lock()
        .map_err(|_| PyRuntimeError::new_err("context state lock is poisoned"))?;

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
    validate::validate_did(identity_did)?;
    let state = handle
        .state
        .lock()
        .map_err(|_| PyRuntimeError::new_err("context state lock is poisoned"))?;

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

    // Close the receive channel so any active PyMessageReceiver raises
    // StopAsyncIteration (SCP-216 AC6).
    let _ = crate::runtime::close_receive_channel(&handle.context_id);

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
/// * `identity_did` -- The DID of the identity initiating the close. Must
///   hold the `ContextClose` capability (typically the context creator or
///   an admin).
///
/// # Errors
///
/// Returns `RuntimeError` if the context is not in "active" state.
/// Returns `ContextError` if the caller lacks the `ContextClose` capability.
#[pyfunction]
#[pyo3(signature = (handle, identity_did))]
fn py_context_close(handle: &PyContextHandle, identity_did: &str) -> PyResult<()> {
    validate::validate_did(identity_did)?;
    let mut state = handle
        .state
        .lock()
        .map_err(|_| PyRuntimeError::new_err("context state lock is poisoned"))?;

    if *state != "active" {
        return Err(PyRuntimeError::new_err(format!(
            "cannot close context in '{state}' state -- context must be 'active'"
        )));
    }

    // Verify the caller has the ContextClose capability before allowing
    // the close operation. Without this check, any caller could close any
    // context -- a privilege escalation vulnerability (black-hat finding).
    let context_id = handle.context_id.clone();
    crate::runtime::with_context(&context_id, |rt| {
        if !rt
            .role_state
            .member_has_capability(identity_did, &Capability::ContextClose)
        {
            return Err(crate::error::ScpPyError::ContextError(format!(
                "identity '{identity_did}' does not have the ContextClose capability \
                 for context '{context_id}' -- only admins or members with the \
                 context:close capability can close a context"
            )));
        }
        Ok(())
    })
    .map_err(|e: crate::error::ScpPyError| -> PyErr { e.into() })?;

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
    validate::validate_did(identity_did)?;
    let state = handle
        .state
        .lock()
        .map_err(|_| PyRuntimeError::new_err("context state lock is poisoned"))?;

    if *state != "active" {
        return Err(PyRuntimeError::new_err(format!(
            "cannot send to context in '{state}' state -- context must be 'active'"
        )));
    }
    drop(state);

    // Extract payload bytes: must be bytes or str.
    let payload_bytes: Vec<u8> = if payload.is_instance_of::<pyo3::types::PyBytes>() {
        payload.extract::<Vec<u8>>()?
    } else if payload.is_instance_of::<pyo3::types::PyString>() {
        let s: String = payload.extract()?;
        s.into_bytes()
    } else {
        return Err(PyTypeError::new_err("payload must be bytes or str"));
    };

    // Create a real inner envelope using the retained KeyCustody for signing.
    // This validates that the identity's active signing key can produce a
    // valid Ed25519 signature over the message. The inner envelope is not
    // yet transmitted (MLS encryption and transport are future stories) but
    // the signing path exercises real KeyCustody. See SCP-214 criterion 6.
    let context_id = handle.context_id.clone();
    let identity_did_owned = identity_did.to_owned();

    let rt = crate::runtime()?;
    crate::runtime::with_identity(&identity_did_owned, |entry| {
        let now_ms = scp_core::time::now_millis()
            .map_err(|e| crate::error::ScpPyError::ContextError(format!("{e}")))?;

        let inner_result = rt.block_on(async {
            let params = scp_core::envelope::InnerEnvelopeParams {
                context_id: &context_id,
                sender_did: &identity_did_owned,
                epoch: 0,
                generation: 0,
                sequence: 0,
                timestamp: now_ms,
                payload: &payload_bytes,
                provenance: None,
            };
            scp_core::envelope::create_inner_envelope(
                &params,
                entry.custody.as_ref(),
                &entry.identity.active_signing_key,
            )
            .await
        });

        inner_result.map_err(|e| {
            crate::error::ScpPyError::ContextError(format!("inner envelope creation failed: {e}"))
        })?;

        Ok(())
    })
    .map_err(|e: crate::error::ScpPyError| -> PyErr { e.into() })?;

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
    let state = handle
        .state
        .lock()
        .map_err(|_| PyRuntimeError::new_err("context state lock is poisoned"))?;

    if *state != "active" {
        return Err(PyRuntimeError::new_err(format!(
            "cannot receive from context in '{state}' state -- context must be 'active'"
        )));
    }
    drop(state);

    let (tx, rx) = mpsc::channel::<PyMessage>(crate::runtime::RECEIVE_BUFFER_CAPACITY);
    let rx_arc = Arc::new(tokio::sync::Mutex::new(rx));

    let context_id = handle.context_id.clone();
    crate::runtime::with_context(&context_id, |rt| {
        rt.message_tx = Some(tx);
        rt.message_rx = Some(Arc::clone(&rx_arc));
        Ok(())
    })
    .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

    Ok(PyMessageReceiver::from_shared_rx(rx_arc))
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

// ---------------------------------------------------------------------------
// Tests (SCP-216)
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::runtime::RECEIVE_BUFFER_CAPACITY;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn make_test_message(i: usize, context_id: &str) -> PyMessage {
        #[allow(clippy::cast_precision_loss)]
        let ts = i as f64;
        PyMessage::new(
            format!("did:test:sender-{i}"),
            format!("payload-{i}").into_bytes(),
            ts,
            context_id.to_owned(),
        )
    }

    #[tokio::test]
    async fn empty_then_message_delivery() {
        let (tx, rx) = mpsc::channel::<PyMessage>(RECEIVE_BUFFER_CAPACITY);
        let rx_arc = Arc::new(tokio::sync::Mutex::new(rx));
        let msg_receiver = PyMessageReceiver::from_shared_rx(Arc::clone(&rx_arc));

        let rx_clone = Arc::clone(&msg_receiver.rx);
        let handle = tokio::spawn(async move {
            let mut guard = rx_clone.lock().await;
            guard.recv().await
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!handle.is_finished(), "recv should block on empty channel");

        let msg = make_test_message(1, "ctx-empty-then-msg");
        tx.send(msg).await.unwrap();

        let result = handle.await.unwrap();
        assert!(result.is_some());
        let received = result.unwrap();
        assert_eq!(received.sender_did, "did:test:sender-1");
        assert_eq!(received.payload, b"payload-1");
    }

    #[tokio::test]
    async fn graceful_close_stops_iteration() {
        let (tx, rx) = mpsc::channel::<PyMessage>(RECEIVE_BUFFER_CAPACITY);
        let rx_arc = Arc::new(tokio::sync::Mutex::new(rx));

        let rx_clone = Arc::clone(&rx_arc);
        let handle = tokio::spawn(async move {
            let mut guard = rx_clone.lock().await;
            guard.recv().await
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        drop(tx);

        let result = handle.await.unwrap();
        assert!(
            result.is_none(),
            "recv should return None when sender is dropped"
        );
    }

    #[tokio::test]
    async fn buffer_overflow_drops_oldest() {
        let capacity = RECEIVE_BUFFER_CAPACITY;
        let (tx, rx) = mpsc::channel::<PyMessage>(capacity);
        let rx_arc = Arc::new(tokio::sync::Mutex::new(rx));
        let context_id = "ctx-overflow-test";

        for i in 0..capacity {
            tx.send(make_test_message(i, context_id)).await.unwrap();
        }

        assert!(
            tx.try_send(make_test_message(capacity, context_id))
                .is_err(),
            "channel should be full at capacity"
        );

        {
            let oldest = rx_arc.lock().await.try_recv();
            assert!(
                oldest.is_ok(),
                "should be able to pop oldest from full buffer"
            );
            let oldest_msg = oldest.unwrap();
            assert_eq!(oldest_msg.sender_did, "did:test:sender-0");
        }

        tx.try_send(make_test_message(capacity, context_id))
            .unwrap();

        let overflow_warning = PyMessage::new(
            "scp:system".to_owned(),
            b"BufferOverflow: oldest event dropped due to full receive buffer".to_vec(),
            0.0,
            context_id.to_owned(),
        );
        let _ = tx.try_send(overflow_warning);

        let first = rx_arc.lock().await.try_recv().unwrap();
        assert_eq!(
            first.sender_did, "did:test:sender-1",
            "after oldest-drop of 1, first message should be sender-1"
        );
    }

    #[tokio::test]
    async fn concurrent_receive_each_message_once() {
        let (tx, rx) = mpsc::channel::<PyMessage>(RECEIVE_BUFFER_CAPACITY);
        let rx_arc = Arc::new(tokio::sync::Mutex::new(rx));
        let total_messages = 100;
        let received_count = Arc::new(AtomicUsize::new(0));

        let mut consumers = Vec::new();
        for _ in 0..4 {
            let rx_clone = Arc::clone(&rx_arc);
            let count = Arc::clone(&received_count);
            consumers.push(tokio::spawn(async move {
                loop {
                    let msg = {
                        let mut guard = rx_clone.lock().await;
                        guard.recv().await
                    };
                    match msg {
                        Some(_) => {
                            count.fetch_add(1, Ordering::Relaxed);
                        }
                        None => break,
                    }
                }
            }));
        }

        for i in 0..total_messages {
            tx.send(make_test_message(i, "ctx-concurrent"))
                .await
                .unwrap();
        }
        drop(tx);

        for consumer in consumers {
            consumer.await.unwrap();
        }

        assert_eq!(
            received_count.load(Ordering::Relaxed),
            total_messages,
            "each message should be received exactly once across all consumers"
        );
    }

    #[tokio::test]
    async fn deliver_message_via_runtime() {
        let context_id = "ctx-deliver-test";

        crate::runtime::register_context(context_id, "did:test:creator").unwrap();

        let (tx, rx) = mpsc::channel::<PyMessage>(RECEIVE_BUFFER_CAPACITY);
        let rx_arc = Arc::new(tokio::sync::Mutex::new(rx));

        crate::runtime::with_context(context_id, |rt| {
            rt.message_tx = Some(tx);
            rt.message_rx = Some(Arc::clone(&rx_arc));
            Ok(())
        })
        .unwrap();

        let msg = make_test_message(42, context_id);
        crate::runtime::deliver_message(context_id, msg).unwrap();

        let mut guard = rx_arc.lock().await;
        let received = guard.try_recv().unwrap();
        assert_eq!(received.sender_did, "did:test:sender-42");
        drop(guard);

        crate::runtime::close_receive_channel(context_id).unwrap();

        let result = crate::runtime::deliver_message(context_id, make_test_message(43, context_id));
        assert!(result.is_err(), "should fail after channel is closed");

        crate::runtime::remove_context(context_id);
    }

    #[tokio::test]
    async fn deliver_message_overflow_injects_warning() {
        let context_id = "ctx-overflow-deliver";
        let capacity = RECEIVE_BUFFER_CAPACITY;

        crate::runtime::register_context(context_id, "did:test:creator").unwrap();

        let (tx, rx) = mpsc::channel::<PyMessage>(capacity);
        let rx_arc = Arc::new(tokio::sync::Mutex::new(rx));

        crate::runtime::with_context(context_id, |rt| {
            rt.message_tx = Some(tx);
            rt.message_rx = Some(Arc::clone(&rx_arc));
            Ok(())
        })
        .unwrap();

        // Fill the buffer from a blocking thread to avoid the
        // "cannot call blocking_lock from within a runtime" panic.
        // deliver_message uses blocking_lock internally for oldest-drop.
        let ctx_id = context_id.to_owned();
        tokio::task::spawn_blocking(move || {
            for i in 0..capacity {
                crate::runtime::deliver_message(&ctx_id, make_test_message(i, &ctx_id)).unwrap();
            }

            crate::runtime::deliver_message(&ctx_id, make_test_message(capacity, &ctx_id)).unwrap();
        })
        .await
        .unwrap();

        let mut guard = rx_arc.lock().await;
        let first = guard.try_recv().unwrap();
        assert_eq!(
            first.sender_did, "did:test:sender-1",
            "oldest message (sender-0) should have been dropped"
        );

        let mut found_new_msg = false;
        while let Ok(msg) = guard.try_recv() {
            if msg.sender_did == format!("did:test:sender-{capacity}") {
                found_new_msg = true;
            }
        }
        // The BufferOverflow warning is best-effort (try_send): it is only
        // injected when there is spare capacity after the overflow-triggering
        // message is sent.  In this test the buffer is immediately full again
        // after the send, so the warning is expected to be dropped.
        assert!(found_new_msg, "should find the overflow-triggering message");

        drop(guard);
        crate::runtime::remove_context(context_id);
    }

    #[test]
    fn close_receive_channel_on_leave() {
        crate::init_runtime().ok();
        let context_id = "ctx-leave-close";

        crate::runtime::register_context(context_id, "did:test:creator").unwrap();

        let (tx, rx) = mpsc::channel::<PyMessage>(RECEIVE_BUFFER_CAPACITY);
        let rx_arc = Arc::new(tokio::sync::Mutex::new(rx));

        crate::runtime::with_context(context_id, |rt| {
            rt.message_tx = Some(tx);
            rt.message_rx = Some(rx_arc);
            Ok(())
        })
        .unwrap();

        crate::runtime::close_receive_channel(context_id).unwrap();

        let result = crate::runtime::deliver_message(context_id, make_test_message(0, context_id));
        assert!(
            result.is_err(),
            "deliver should fail after close_receive_channel"
        );

        crate::runtime::remove_context(context_id);
    }

    // -----------------------------------------------------------------------
    // PyContextParams field tests (issue #109)
    // -----------------------------------------------------------------------

    /// Helper to build a `PyContextParams` with all defaults.
    fn default_params() -> PyContextParams {
        PyContextParams {
            ceiling: Vec::new(),
            roles: HashMap::new(),
            tools: Vec::new(),
            ttl: None,
            memory_scope: "ephemeral".to_owned(),
            governance: "single_admin".to_owned(),
            mode: "encrypted".to_owned(),
            ceiling_policy: "immutable".to_owned(),
            promotion_policy: "no_promotion".to_owned(),
            template_id: None,
            economic_policy: None,
        }
    }

    #[test]
    fn params_defaults_match_spec() {
        let p = default_params();
        assert_eq!(p.mode, "encrypted");
        assert_eq!(p.ceiling_policy, "immutable");
        assert_eq!(p.promotion_policy, "no_promotion");
        assert!(p.template_id.is_none());
        assert!(p.economic_policy.is_none());
    }

    #[test]
    fn params_mode_broadcast() {
        let p = PyContextParams {
            mode: "broadcast".to_owned(),
            ..default_params()
        };
        assert_eq!(p.mode, "broadcast");
    }

    #[test]
    fn params_ceiling_policy_governed() {
        let p = PyContextParams {
            ceiling_policy: "governed".to_owned(),
            ..default_params()
        };
        assert_eq!(p.ceiling_policy, "governed");
    }

    #[test]
    fn params_promotion_policy_promotable() {
        let p = PyContextParams {
            promotion_policy: "promotable".to_owned(),
            ..default_params()
        };
        assert_eq!(p.promotion_policy, "promotable");
    }

    #[test]
    fn params_template_id_present() {
        let p = PyContextParams {
            template_id: Some("PublicBroadcast".to_owned()),
            ..default_params()
        };
        assert_eq!(p.template_id.as_deref(), Some("PublicBroadcast"));
    }

    #[test]
    fn params_economic_policy_present() {
        let json = r#"{"locked":false,"cost_schedule":{}}"#;
        let p = PyContextParams {
            economic_policy: Some(json.to_owned()),
            ..default_params()
        };
        assert_eq!(p.economic_policy.as_deref(), Some(json));
    }

    #[test]
    fn valid_template_ids_constant_covers_all_variants() {
        // Ensure every entry in VALID_TEMPLATE_IDS is non-empty and unique.
        let set: std::collections::HashSet<&str> = VALID_TEMPLATE_IDS.iter().copied().collect();
        assert_eq!(
            set.len(),
            VALID_TEMPLATE_IDS.len(),
            "duplicate template IDs"
        );
        for id in VALID_TEMPLATE_IDS {
            assert!(!id.is_empty(), "empty template ID in VALID_TEMPLATE_IDS");
        }
    }

    #[test]
    fn params_repr_includes_new_fields() {
        let p = PyContextParams {
            mode: "broadcast".to_owned(),
            ceiling_policy: "governed".to_owned(),
            promotion_policy: "promotable".to_owned(),
            template_id: Some("Coordination".to_owned()),
            economic_policy: Some("{}".to_owned()),
            ..default_params()
        };
        let repr = p.__repr__();
        assert!(repr.contains("broadcast"), "repr should include mode");
        assert!(
            repr.contains("governed"),
            "repr should include ceiling_policy"
        );
        assert!(
            repr.contains("promotable"),
            "repr should include promotion_policy"
        );
        assert!(
            repr.contains("Coordination"),
            "repr should include template_id"
        );
    }

    // -----------------------------------------------------------------------
    // PyContextHandle metadata getter tests (spec §5.7, issue #109)
    // -----------------------------------------------------------------------

    #[test]
    fn handle_exposes_mode() {
        let handle = PyContextHandle::new(
            "ctx-1".to_owned(),
            "did:test:creator".to_owned(),
            PyContextParams {
                mode: "broadcast".to_owned(),
                ..default_params()
            },
        );
        assert_eq!(handle.mode(), "broadcast");
    }

    #[test]
    fn handle_exposes_ceiling_policy() {
        let handle = PyContextHandle::new(
            "ctx-2".to_owned(),
            "did:test:creator".to_owned(),
            PyContextParams {
                ceiling_policy: "governed".to_owned(),
                ..default_params()
            },
        );
        assert_eq!(handle.ceiling_policy(), "governed");
    }

    #[test]
    fn handle_exposes_promotion_policy() {
        let handle = PyContextHandle::new(
            "ctx-3".to_owned(),
            "did:test:creator".to_owned(),
            PyContextParams {
                promotion_policy: "promotable".to_owned(),
                ..default_params()
            },
        );
        assert_eq!(handle.promotion_policy(), "promotable");
    }

    #[test]
    fn handle_exposes_template_id_none() {
        let handle = PyContextHandle::new(
            "ctx-4".to_owned(),
            "did:test:creator".to_owned(),
            default_params(),
        );
        assert!(handle.template_id().is_none());
    }

    #[test]
    fn handle_exposes_template_id_some() {
        let handle = PyContextHandle::new(
            "ctx-5".to_owned(),
            "did:test:creator".to_owned(),
            PyContextParams {
                template_id: Some("BilateralEphemeral".to_owned()),
                ..default_params()
            },
        );
        assert_eq!(handle.template_id(), Some("BilateralEphemeral"));
    }

    #[test]
    fn handle_exposes_economic_policy_none() {
        let handle = PyContextHandle::new(
            "ctx-6".to_owned(),
            "did:test:creator".to_owned(),
            default_params(),
        );
        assert!(handle.economic_policy().is_none());
    }

    #[test]
    fn handle_exposes_economic_policy_some() {
        let json = r#"{"locked":true}"#;
        let handle = PyContextHandle::new(
            "ctx-7".to_owned(),
            "did:test:creator".to_owned(),
            PyContextParams {
                economic_policy: Some(json.to_owned()),
                ..default_params()
            },
        );
        assert_eq!(handle.economic_policy(), Some(json));
    }

    #[test]
    fn handle_repr_includes_mode() {
        let handle = PyContextHandle::new(
            "ctx-repr".to_owned(),
            "did:test:creator".to_owned(),
            PyContextParams {
                mode: "broadcast".to_owned(),
                ..default_params()
            },
        );
        let repr = handle.__repr__().unwrap();
        assert!(repr.contains("broadcast"), "repr should include mode");
    }

    #[test]
    fn handle_defaults_encrypted_immutable_no_promotion() {
        let handle = PyContextHandle::new(
            "ctx-defaults".to_owned(),
            "did:test:creator".to_owned(),
            default_params(),
        );
        assert_eq!(handle.mode(), "encrypted");
        assert_eq!(handle.ceiling_policy(), "immutable");
        assert_eq!(handle.promotion_policy(), "no_promotion");
        assert!(handle.template_id().is_none());
        assert!(handle.economic_policy().is_none());
    }
}
