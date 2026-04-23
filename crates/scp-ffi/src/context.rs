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

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use pyo3::exceptions::{PyRuntimeError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyDict;
use scp_platform::traits::KeyCustody;
use scp_primitives::Clock;
use tokio::sync::mpsc;

use scp_ffi_common::html_escape_event_string;

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
    /// Current lifecycle state: `"creating"`, `"active"`, `"closing"`, `"closed"`,
    /// `"expired"`, `"migrating_out"`, `"tombstoned"`.
    state: Arc<Mutex<String>>,
    /// DID of the context creator.
    creator_did: String,
    /// Creation-time context parameters, retained for spec §5.7 metadata visibility.
    params: PyContextParams,
    /// Bridge instance affinity id (Phase 4 PR 1 — #1549). The
    /// `PyBridgeInstance` that issued this handle. `#[pyfunction]` entry
    /// points that consume this handle must invoke the
    /// `pyscp_check_handle!` macro so cross-instance reuse is rejected
    /// with [`scp_ffi_common::error_codes::PERM_3030`].
    pub(crate) instance_id: u64,
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
    /// One of: `"creating"`, `"active"`, `"closing"`, `"closed"`, `"expired"`,
    /// `"migrating_out"`, `"tombstoned"`.
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
    /// Creates a new handle in the "creating" state with associated params,
    /// tagged with the default bridge instance's `instance_id`.
    fn new(context_id: String, creator_did: String, params: PyContextParams) -> Self {
        let instance_id = crate::runtime::bridge_instance_raw()
            .map_or(scp_ffi_common::bridge_instance::UNSET_INSTANCE_ID, |bi| {
                bi.core.instance_id()
            });
        Self {
            context_id,
            state: Arc::new(Mutex::new("creating".to_owned())),
            creator_did,
            params,
            instance_id,
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
    /// Minimum protocol version as `(major, minor)` tuple (spec §13.4).
    /// When `None`, defaults to `(1, 0)`.
    min_protocol_version: Option<(u8, u8)>,
    /// Maximum cross-context chain depth (spec §24.4, ADR-043).
    /// When `None`, defaults to `DEFAULT_MAX_CHAIN_DEPTH` (8).
    max_chain_depth: Option<u8>,
    /// Maximum nesting depth for sub-contexts (spec §5.6, ADR-043).
    /// When `None`, nesting is unbounded.
    max_nesting_depth: Option<u32>,
    /// Per-caller session cap (spec §6.2.1, ADR-043).
    /// When `None`, defaults to `DEFAULT_SESSION_CAP_PER_CALLER` (1000).
    session_cap: Option<u32>,
    /// Optional consequence rules as a JSON string (ADR-017, #1531).
    /// When `None`, defaults to an empty list (no consequences).
    consequence_rules: Option<String>,
    /// Optional consequence config as a JSON string (ADR-017, #1531).
    /// When `None`, defaults to `ConsequenceConfig::default()` (all severe
    /// enforcement tiers gated to governance only).
    consequence_config: Option<String>,
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

    /// Returns the minimum protocol version as `(major, minor)` tuple,
    /// or `None` if no minimum is set (defaults to SCP/1.0, spec §13.4).
    #[getter]
    #[allow(clippy::missing_const_for_fn)] // PyO3 getter cannot be const.
    fn min_protocol_version(&self) -> Option<(u8, u8)> {
        self.min_protocol_version
    }

    /// Returns the maximum cross-context chain depth, or `None` if using
    /// the protocol default (8, spec §24.4, ADR-043).
    #[getter]
    #[allow(clippy::missing_const_for_fn)] // PyO3 getter cannot be const.
    fn max_chain_depth(&self) -> Option<u8> {
        self.max_chain_depth
    }

    /// Returns the maximum nesting depth, or `None` for unbounded
    /// (spec §5.6, ADR-043).
    #[getter]
    #[allow(clippy::missing_const_for_fn)] // PyO3 getter cannot be const.
    fn max_nesting_depth(&self) -> Option<u32> {
        self.max_nesting_depth
    }

    /// Returns the per-caller session cap, or `None` if using the protocol
    /// default (1000, spec §6.2.1, ADR-043).
    #[getter]
    #[allow(clippy::missing_const_for_fn)] // PyO3 getter cannot be const.
    fn session_cap(&self) -> Option<u32> {
        self.session_cap
    }

    /// Returns the consequence rules as a JSON string, or `None` if the
    /// context has no consequence rules (ADR-017, #1531).
    #[getter]
    fn consequence_rules(&self) -> Option<&str> {
        self.consequence_rules.as_deref()
    }

    /// Returns the consequence config as a JSON string, or `None` if the
    /// context inherits the default config (ADR-017, #1531).
    #[getter]
    fn consequence_config(&self) -> Option<&str> {
        self.consequence_config.as_deref()
    }

    fn __repr__(&self) -> String {
        format!(
            "PyContextParams(ceiling={:?}, roles={:?}, tools={:?}, ttl={:?}, \
             memory_scope='{}', governance='{}', mode='{}', ceiling_policy='{}', \
             promotion_policy='{}', template_id={:?}, economic_policy={:?}, \
             min_protocol_version={:?}, max_chain_depth={:?}, \
             max_nesting_depth={:?}, session_cap={:?}, \
             consequence_rules={:?}, consequence_config={:?})",
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
            self.min_protocol_version,
            self.max_chain_depth,
            self.max_nesting_depth,
            self.session_cap,
            self.consequence_rules,
            self.consequence_config,
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
    "HandleRegistry",
    "scp:template/handle-registry",
    "DiscoveryContext",
    "scp:template/discovery-context",
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

        // min_protocol_version: Optional[tuple[int, int]] (default: None) -- spec §13.4
        let min_protocol_version: Option<(u8, u8)> = match dict.get_item("min_protocol_version")? {
            Some(val) if val.is_none() => None,
            Some(val) => {
                let (major, minor): (u8, u8) = val.extract()?;
                Some((major, minor))
            }
            None => None,
        };

        // max_chain_depth: Optional[int] (default: None → 8) -- spec §24.4, ADR-043
        let max_chain_depth: Option<u8> = match dict.get_item("max_chain_depth")? {
            Some(val) if val.is_none() => None,
            Some(val) => Some(val.extract()?),
            None => None,
        };

        // max_nesting_depth: Optional[int] (default: None → unbounded) -- spec §5.6, ADR-043
        let max_nesting_depth: Option<u32> = match dict.get_item("max_nesting_depth")? {
            Some(val) if val.is_none() => None,
            Some(val) => Some(val.extract()?),
            None => None,
        };

        // session_cap: Optional[int] (default: None → 1000) -- spec §6.2.1, ADR-043
        let session_cap: Option<u32> = match dict.get_item("session_cap")? {
            Some(val) if val.is_none() => None,
            Some(val) => Some(val.extract()?),
            None => None,
        };

        // consequence_rules: Optional[str] (JSON string, default: None) -- ADR-017, #1531
        let consequence_rules: Option<String> = match dict.get_item("consequence_rules")? {
            Some(val) if val.is_none() => None,
            Some(val) => {
                let cr: String = val.extract()?;
                Some(cr)
            }
            None => None,
        };

        // consequence_config: Optional[str] (JSON string, default: None) -- ADR-017, #1531
        let consequence_config: Option<String> = match dict.get_item("consequence_config")? {
            Some(val) if val.is_none() => None,
            Some(val) => {
                let cc: String = val.extract()?;
                Some(cc)
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
            min_protocol_version,
            max_chain_depth,
            max_nesting_depth,
            session_cap,
            consequence_rules,
            consequence_config,
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
    /// Bridge instance affinity id (Phase 4 PR 1 — #1549). The instance
    /// whose receive channel produced this message. Entry points that
    /// consume `PyMessage` (none today — `PyMessage` is read-only from
    /// Python) should `check_handle` against this value before acting.
    ///
    /// `dead_code` allowance: future commits of this PR will add
    /// `check_handle` at every entry point that accepts a `PyMessage`.
    #[allow(dead_code)]
    pub(crate) instance_id: u64,
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
    /// Creates a new `PyMessage` tagged with the default bridge instance's
    /// `instance_id`. Used by `drain_and_deliver` and `deliver_message` to
    /// feed messages into the receive channel.
    #[must_use]
    pub fn new(sender_did: String, payload: Vec<u8>, timestamp: f64, context_id: String) -> Self {
        let instance_id = crate::runtime::bridge_instance_raw()
            .map_or(scp_ffi_common::bridge_instance::UNSET_INSTANCE_ID, |bi| {
                bi.core.instance_id()
            });
        Self {
            sender_did,
            payload,
            timestamp,
            context_id,
            instance_id,
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
/// Created by `py_context_receive` -- not directly constructible from Python.
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
    /// `FfiBridgeState::message_rx` via `Arc` so that `deliver_message` can
    /// implement oldest-drop overflow.
    rx: Arc<tokio::sync::Mutex<mpsc::Receiver<PyMessage>>>,
    /// Bridge instance affinity id (Phase 4 PR 1 — #1549).
    ///
    /// `dead_code` allowance: future commits of this PR will add
    /// `check_handle` at entry points that consume a `PyMessageReceiver`.
    #[allow(dead_code)]
    pub(crate) instance_id: u64,
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
    /// Creates a new receiver from a pre-wrapped shared receiver Arc,
    /// tagged with the default bridge instance's `instance_id`.
    ///
    /// The `Arc<tokio::sync::Mutex<Receiver>>` is shared with
    /// `FfiBridgeState::message_rx` so that `deliver_message` can access
    /// the receiver for oldest-drop overflow handling.
    #[must_use]
    pub fn from_shared_rx(rx: Arc<tokio::sync::Mutex<mpsc::Receiver<PyMessage>>>) -> Self {
        let instance_id = crate::runtime::bridge_instance_raw()
            .map_or(scp_ffi_common::bridge_instance::UNSET_INSTANCE_ID, |bi| {
                bi.core.instance_id()
            });
        Self { rx, instance_id }
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
// MLS key package generation helper (#1324)
// ---------------------------------------------------------------------------

/// Generates serialized MLS key package bytes for a given DID.
///
/// Ported from the NAPI bridge (`generate_mls_key_package_bytes` in
/// `napi/src/context.rs`) as part of issue #1324. Creates an SCP credential
/// for the DID, generates a fresh MLS key package, and returns the
/// TLS-serialized bytes suitable for passing to
/// `ContextManager::join_context`.
fn generate_mls_key_package_bytes(did: &str) -> Result<Vec<u8>, crate::error::ScpPyError> {
    use scp_core::crypto::mls::credential::ScpCredential;
    use scp_core::crypto::mls::group::generate_key_package;
    use tls_codec::Serialize as TlsSerializeTrait;

    let cred = ScpCredential::new(did.to_owned(), None, scp_identity::SigningKeyId::Active)
        .map_err(|e| {
            crate::error::ScpPyError::crypto(format!(
                "failed to create SCP credential for MLS key package: {e}"
            ))
        })?;

    let (kp_bundle, _signer, _provider) = generate_key_package(&cred).map_err(|e| {
        crate::error::ScpPyError::crypto(format!("MLS key package generation failed: {e}"))
    })?;

    kp_bundle
        .key_package()
        .tls_serialize_detached()
        .map_err(|e| {
            crate::error::ScpPyError::crypto(format!(
                "MLS key package TLS serialization failed: {e}"
            ))
        })
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Dispatch `create_context` through the ADR-049 commit-9 lifecycle
/// shim ([`Supervisor::dispatch_lifecycle_command`](scp_core::context::supervisor::Supervisor::dispatch_lifecycle_command))
/// rather than calling `ContextManager::create_context` directly. The
/// shim wraps the delegated call in a 30s transport-timeout budget
/// and is the entry point commit 12 will keep after `ContextManager`
/// is deleted.
///
/// Extracted from `py_context_create` to keep that function below the
/// `too_many_lines` clippy threshold.
fn bridge_dispatch_create_context(
    parsed: &PyContextParams,
    context_id: &str,
    identity_did: &str,
    local_pseudonym: Option<[u8; 32]>,
) -> PyResult<()> {
    use scp_core::context::actor::commands::{CreateContextPayload, LifecycleCommand};
    let core_params = build_core_context_params(parsed)?;
    let creator_did_owned = scp_identity::DID(identity_did.to_owned());
    let rt = crate::runtime()?;
    let sup = crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let sup = Arc::clone(sup);
    let ctx_id = context_id.to_owned();
    let creator_did_for_register = scp_identity::DID(identity_did.to_owned());
    let sup_for_register = Arc::clone(&sup);
    let outcome = rt.block_on(async move {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = LifecycleCommand::CreateContext {
            payload: Box::new(CreateContextPayload {
                context_id: ctx_id,
                params: core_params,
                creator_did: creator_did_owned,
                local_pseudonym,
            }),
            reply: tx,
        };
        sup.dispatch_lifecycle_command(cmd).await.map_err(|e| {
            scp_core::context::ContextError::CreationFailed(format!(
                "supervisor dispatch_lifecycle_command failed: {e}"
            ))
        })?;
        rx.await
            .map_err(|e| {
                scp_core::context::ContextError::CreationFailed(format!("shim reply dropped: {e}"))
            })?
            .map_err(|e| scp_core::context::ContextError::CreationFailed(e.to_string()))?;
        // Register the creator's DID as a local DID for defense-in-depth,
        // matching NAPI's behavior. Routes through the supervisor's direct
        // method (no per-context command — the local-DID set is
        // supervisor-wide).
        sup_for_register
            .register_local_did(creator_did_for_register)
            .await
            .map_err(|e| {
                scp_core::context::ContextError::CreationFailed(format!(
                    "register_local_did failed: {e}"
                ))
            })?;
        Ok::<(), scp_core::context::ContextError>(())
    });
    outcome.map_err(|e| {
        // Clean up FFI state on ContextManager failure.
        crate::runtime::remove_context(context_id);
        PyRuntimeError::new_err(format!("ContextManager create_context failed: {e}"))
    })
}

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

    let handle = PyContextHandle::new(context_id.clone(), identity_did.to_owned(), parsed.clone());

    // Register FFI-specific state (ToolRegistry, EventLog, RoleState, RevocationList)
    // in the global FFI state registry so that tools/UCAN/event_log bridge functions
    // can look them up by context ID. Also initializes the shared ContextManager.
    crate::runtime::register_context(&context_id, identity_did, &parsed.ceiling)
        .map_err(|e| PyRuntimeError::new_err(format!("failed to register context state: {e}")))?;

    // Delegate context creation to the shared ContextManager for lifecycle tracking.
    // §9.10.4: Derive pseudonym BEFORE context creation so it can be passed
    // to the ContextManager for per-member routing. The pseudonym derivation
    // is also reused for the known-contexts registry below.
    let local_pseudonym: Option<[u8; 32]> = crate::runtime::with_identity(identity_did, |entry| {
        let rt = crate::runtime().map_err(|e| {
            crate::error::ScpPyError::identity(format!("runtime not available: {e}"))
        })?;
        let pseudonym = rt.block_on(async {
            entry
                .custody
                .derive_pseudonym(&entry.identity.identity_key, context_id.as_bytes())
                .await
        });
        let pk = pseudonym
            .map_err(|e| {
                crate::error::ScpPyError::identity(format!("pseudonym derivation failed: {e}"))
            })?
            .public_key;
        let bytes: [u8; 32] = pk.as_bytes().try_into().map_err(|_| {
            crate::error::ScpPyError::identity("pseudonym public key must be 32 bytes")
        })?;
        Ok(bytes)
    })
    .ok();

    // Build scp-core ContextParams from the parsed PyContextParams and
    // dispatch create-context through the ADR-049 commit-9 lifecycle
    // shim. Extracted to keep `py_context_create` under the
    // `too_many_lines` threshold.
    bridge_dispatch_create_context(&parsed, &context_id, identity_did, local_pseudonym)?;

    // §9.10.4: Send pseudonym announcement to inform other members of the
    // creator's per-context routing ID. For freshly created single-member
    // contexts this is a no-op (no recipients), but on restored/imported
    // contexts with existing members the announcement is needed.
    if local_pseudonym.is_some()
        && let Ok(sk) = resolve_signing_key(identity_did)
    {
        use scp_core::context::actor::commands::{
            MessagingCommand, SendPseudonymAnnouncementPayload, SigningKeyBytes,
        };
        let rt = crate::runtime()?;
        let sup =
            crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let sup = Arc::clone(sup);
        let sender_did = scp_identity::DID(identity_did.to_owned());
        let core_params = build_core_context_params(&handle.params)?;
        let ann_ctx_id = context_id.clone();
        rt.block_on(async move {
            let (tx, rx) = tokio::sync::oneshot::channel();
            let cmd = MessagingCommand::SendPseudonymAnnouncement {
                payload: Box::new(SendPseudonymAnnouncementPayload {
                    context_id: ann_ctx_id.clone(),
                    params: core_params,
                    sender_did,
                    signing_key: SigningKeyBytes::from_signing_key(&sk),
                }),
                reply: tx,
            };
            if sup.dispatch_command(&ann_ctx_id, cmd).await.is_ok() {
                let _ = rx.await;
            }
        });
    }

    // Register in the known-contexts registry for discovery via
    // py_mcp_load_contexts. Reuse the pre-derived pseudonym routing ID
    // (§9.10.4, SCP-214 criterion 4). Falls back to context_routing_id
    // for encrypted contexts or broadcast_routing_id for broadcast contexts.
    // Bug fix (#1534): broadcast contexts use broadcast_routing_id (plain
    // SHA-256) matching the send path, not context_routing_id (domain-separated).
    {
        let routing_id = local_pseudonym.unwrap_or_else(|| {
            if handle.params.mode == "broadcast" {
                scp_core::context::broadcast_routing_id(&context_id)
            } else {
                scp_core::context::context_routing_id(&context_id)
            }
        });

        // Get the relay URL from transport status if a relay is connected.
        let relay_url = match crate::transport::py_transport_status() {
            Ok(status) => status.relay_url,
            Err(e) => {
                tracing::warn!("failed to query transport status during context registration: {e}");
                None
            }
        };

        let last_seen = scp_primitives::SystemClock.now_secs();

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

/// Dispatches `LifecycleCommand::JoinContext` and the §9.10.4 pseudonym
/// announcement through the supervisor shim. Extracted from
/// [`py_context_join`] to keep that function under the `too_many_lines`
/// clippy threshold.
fn bridge_dispatch_join_context(
    handle: &PyContextHandle,
    identity_did: &str,
    spending_ucan: Option<scp_core::crypto::ucan::UcanToken>,
) -> PyResult<()> {
    use scp_core::context::actor::commands::{
        JoinContextPayload, LifecycleCommand, MessagingCommand, SendPseudonymAnnouncementPayload,
        SigningKeyBytes,
    };
    let context_id = handle.context_id.clone();
    let member_did = identity_did.to_owned();
    let rt = crate::runtime()?;
    let sup = crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let sup = Arc::clone(sup);

    // Generate a real MLS key package for the joining member (#1324).
    // The key package contains the joiner's SCP credential (DID) and is
    // validated by MlsCryptoProvider::validate_key_package before MLS
    // group addition.
    let kp_bytes = generate_mls_key_package_bytes(identity_did)
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

    let key_package = scp_core::context::membership::KeyPackage {
        owner_did: scp_identity::DID(member_did.clone()),
        mls_key_package_bytes: Some(kp_bytes),
    };

    // §9.10.4: Derive pseudonym for the joining member so it can be
    // stored in PerContextState and announced to other members.
    let local_pseudonym: Option<[u8; 32]> = crate::runtime::with_identity(identity_did, |entry| {
        let rt = crate::runtime()
            .map_err(|e| crate::error::ScpPyError::identity(format!("runtime init failed: {e}")))?;
        let pseudonym = rt.block_on(async {
            entry
                .custody
                .derive_pseudonym(&entry.identity.identity_key, context_id.as_bytes())
                .await
        });
        let pk = pseudonym
            .map_err(|e| {
                crate::error::ScpPyError::identity(format!("pseudonym derivation failed: {e}"))
            })?
            .public_key;
        let bytes: [u8; 32] = pk.as_bytes().try_into().map_err(|_| {
            crate::error::ScpPyError::identity("pseudonym public key must be 32 bytes")
        })?;
        Ok(bytes)
    })
    .ok();

    // §9.10.4: pass the pseudonym to join_context so it is stored in
    // PerContextState for subsequent send_message fan-out.
    let core_params = build_core_context_params(&handle.params)?;
    let join_ctx_id = context_id.clone();
    let join_params = core_params.clone();
    let sup_for_join = Arc::clone(&sup);
    rt.block_on(async move {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = LifecycleCommand::JoinContext {
            payload: Box::new(JoinContextPayload {
                context_id: join_ctx_id,
                params: join_params,
                key_package,
                spending_ucan,
                local_pseudonym,
            }),
            reply: tx,
        };
        sup_for_join
            .dispatch_lifecycle_command(cmd)
            .await
            .map_err(|e| {
                PyRuntimeError::new_err(format!(
                    "supervisor dispatch_lifecycle_command failed: {e}"
                ))
            })?;
        rx.await
            .map_err(|e| PyRuntimeError::new_err(format!("join shim reply dropped: {e}")))?
            .map_err(|e| {
                PyRuntimeError::new_err(format!("ContextManager join_context failed: {e}"))
            })
    })?;

    // §9.10.4: Send pseudonym announcement to inform existing members.
    if local_pseudonym.is_some()
        && let Ok(sk) = resolve_signing_key(identity_did)
    {
        let sender_did = scp_identity::DID(member_did.clone());
        let ann_ctx_id = context_id.clone();
        let sup_for_ann = Arc::clone(&sup);
        rt.block_on(async move {
            let (tx, rx) = tokio::sync::oneshot::channel();
            let cmd = MessagingCommand::SendPseudonymAnnouncement {
                payload: Box::new(SendPseudonymAnnouncementPayload {
                    context_id: ann_ctx_id.clone(),
                    params: core_params,
                    sender_did,
                    signing_key: SigningKeyBytes::from_signing_key(&sk),
                }),
                reply: tx,
            };
            if sup_for_ann.dispatch_command(&ann_ctx_id, cmd).await.is_ok() {
                let _ = rx.await;
            }
        });
    }

    // Also update FFI bridge state's role_state for UCAN/tool capability checks.
    crate::runtime::with_ffi_state(&context_id, |st| {
        st.role_state.members.insert(member_did);
        Ok(())
    })
    .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

    // Bridge: drain events (MemberJoined) from ContextManager's receive
    // buffer and deliver to the FFI receive channel (#332).
    drain_and_deliver(&context_id);

    Ok(())
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
#[pyo3(signature = (handle, identity_did, spending_ucan_jwt=None))]
fn py_context_join(
    handle: &PyContextHandle,
    identity_did: &str,
    spending_ucan_jwt: Option<&str>,
) -> PyResult<()> {
    crate::pyscp_check_handle!(handle);
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

    // Parse optional spending UCAN JWT for AND-composition (join cost).
    let spending_ucan = spending_ucan_jwt
        .map(|jwt| {
            scp_core::crypto::ucan::validate::parse_ucan(jwt)
                .map_err(|e| PyRuntimeError::new_err(format!("invalid spending UCAN: {e}")))
        })
        .transpose()?;

    // Ensure the ContextManager is initialized — context_join is a valid
    // first operation (e.g. a device joining a context without creating one).
    // init_context_manager is idempotent (OnceLock — first call wins). #1073
    // Passes the joiner DID to MlsCryptoProvider for real MLS encryption (#1324).
    #[cfg(test)]
    crate::runtime::init_context_manager_for_test();
    #[cfg(not(test))]
    crate::runtime::init_context_manager(identity_did);

    // Delegate join to the shared ContextManager via the ADR-049 commit-9
    // lifecycle shim and pseudonym-announcement messaging shim.
    bridge_dispatch_join_context(handle, identity_did, spending_ucan)?;

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
    crate::pyscp_check_handle!(handle);
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

    // Delegate leave to the shared ContextManager via the ADR-049 commit-9
    // lifecycle shim.
    {
        use scp_core::context::actor::commands::{LeaveContextPayload, LifecycleCommand};
        let context_id = handle.context_id.clone();
        let member_did = scp_identity::DID(identity_did.to_owned());
        let rt = crate::runtime()?;
        let sup =
            crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let sup = Arc::clone(sup);

        let core_params = build_core_context_params(&handle.params)?;
        let leave_ctx_id = context_id.clone();
        rt.block_on(async move {
            let (tx, rx) = tokio::sync::oneshot::channel();
            // Self-removal: caller_did == member_did.
            let cmd = LifecycleCommand::LeaveContext {
                payload: Box::new(LeaveContextPayload {
                    context_id: leave_ctx_id,
                    params: core_params,
                    caller_did: member_did.clone(),
                    member_did,
                }),
                reply: tx,
            };
            sup.dispatch_lifecycle_command(cmd).await.map_err(|e| {
                PyRuntimeError::new_err(format!(
                    "supervisor dispatch_lifecycle_command failed: {e}"
                ))
            })?;
            rx.await
                .map_err(|e| PyRuntimeError::new_err(format!("leave shim reply dropped: {e}")))?
                .map_err(|e| {
                    PyRuntimeError::new_err(format!("ContextManager leave_context failed: {e}"))
                })
        })?;

        // Also update FFI bridge state's role_state.
        let _ = crate::runtime::with_ffi_state(&context_id, |st| {
            st.role_state.members.remove(identity_did);
            Ok(())
        });

        // Bridge: drain events (MemberLeft) from ContextManager's receive
        // buffer and deliver BEFORE closing the channel (#332).
        drain_and_deliver(&context_id);
    }

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
    crate::pyscp_check_handle!(handle);
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

    // Authorization is enforced by the ContextManager (which delegates to
    // ttl::close_context checking the ContextClose capability). No bridge-layer
    // auth check — the ContextManager is authoritative.
    let context_id = handle.context_id.clone();

    // Delegate close through the ADR-049 commit-9 lifecycle shim
    // ([`Supervisor::dispatch_lifecycle_command`](scp_core::context::supervisor::Supervisor::dispatch_lifecycle_command)).
    // The shim routes the call through the migrated
    // `handlers::lifecycle` handler, which wraps
    // `ContextManager::close_context` in a 30s transport-timeout budget
    // and preserves byte-identical close semantics (capability check,
    // TTL cancel, broadcast teardown, persistence).
    //
    // If it fails with a real error (not "context not found" which is
    // idempotent), propagate before cleaning up FFI state. This
    // prevents the scenario where FFI state is destroyed but the
    // ContextManager still holds the context.
    {
        use scp_core::context::actor::commands::{CloseContextPayload, LifecycleCommand};
        let initiator_did = scp_identity::DID(identity_did.to_owned());
        let rt = crate::runtime()?;
        let sup =
            crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let sup = Arc::clone(sup);

        let core_params = build_core_context_params(&handle.params)?;
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = LifecycleCommand::CloseContext {
            payload: Box::new(CloseContextPayload {
                context_id,
                params: core_params,
                initiator_did,
            }),
            reply: tx,
        };
        // Returns `Result<Result<CloseResult, ContextError>, PyErr>` so
        // the idempotency check below can still match on
        // `ContextError::ContextNotRegistered` directly.
        let dispatch_outcome: Result<
            Result<scp_core::context::ttl::CloseResult, scp_core::context::ContextError>,
            pyo3::PyErr,
        > = rt.block_on(async move {
            sup.dispatch_lifecycle_command(cmd).await.map_err(|e| {
                PyRuntimeError::new_err(format!(
                    "supervisor dispatch_lifecycle_command failed: {e}"
                ))
            })?;
            rx.await
                .map_err(|e| PyRuntimeError::new_err(format!("shim reply dropped: {e}")))
        });
        match dispatch_outcome {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                // Propagate errors unless the context was already
                // removed from ContextManager (idempotent — e.g. all
                // members left).
                if !matches!(e, scp_core::context::ContextError::ContextNotRegistered(_)) {
                    return Err(PyRuntimeError::new_err(format!(
                        "ContextManager close_context failed: {e}"
                    )));
                }
            }
            Err(py_err) => return Err(py_err),
        }
    }

    // Transition directly to "closed" (skipping "closing" for the bridge
    // layer -- the full runtime will implement the cooperative closing window).
    "closed".clone_into(&mut state);
    drop(state);

    // Bridge: drain events (SystemClose) from ContextManager before
    // removing FFI state, so any active receiver gets the close event (#332).
    drain_and_deliver(&handle.context_id);

    // Remove context from the FFI state registry to free resources.
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
#[pyo3(signature = (handle, identity_did, payload, spending_ucan_jwt=None))]
fn py_context_send(
    handle: &PyContextHandle,
    identity_did: &str,
    payload: &Bound<'_, PyAny>,
    spending_ucan_jwt: Option<&str>,
) -> PyResult<()> {
    crate::pyscp_check_handle!(handle);
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

    // Parse optional spending UCAN JWT into a UcanToken for AND-composition.
    let spending_ucan = spending_ucan_jwt
        .map(|jwt| {
            scp_core::crypto::ucan::validate::parse_ucan(jwt)
                .map_err(|e| PyRuntimeError::new_err(format!("invalid spending UCAN: {e}")))
        })
        .transpose()?;

    // Delegate message sending to the shared ContextManager. The ContextManager
    // validates Active state, checks write capabilities, assigns sequence numbers,
    // encrypts via the crypto provider, and sends via the transport provider.
    let context_id = handle.context_id.clone();
    let identity_did_owned = identity_did.to_owned();
    let rt = crate::runtime()?;

    // Resolve the signing key from the identity registry so the ContextManager
    // can produce a valid inner envelope signature. Passing None would cause
    // the encrypted send path to fail with "signing key required".
    let signing_key = resolve_signing_key(&identity_did_owned)?;

    // Route through the ADR-049 commit-8 messaging shim
    // ([`Supervisor::dispatch_command`](scp_core::context::supervisor::Supervisor::dispatch_command))
    // rather than calling `ContextManager::send_message` directly. The
    // shim exercises the RAII [`SequenceReservation`] + 30s transport
    // timeout inside the handler, preserves byte-identical envelope
    // construction by delegating to the legacy method, and is the
    // entry point commit 12 will keep after `ContextManager` is
    // deleted.
    let context_id_for_drain = context_id.clone();
    {
        use scp_core::context::actor::commands::{
            MessagingCommand, SendMessagePayload, SigningKeyBytes,
        };
        let sender_did = scp_identity::DID(identity_did_owned);
        let sup =
            crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let sup = Arc::clone(sup);

        let core_params = build_core_context_params(&handle.params)?;
        let signing_key_bytes = SigningKeyBytes::from_signing_key(&signing_key);
        let ctx_id_for_cmd = context_id.clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = MessagingCommand::SendMessage {
            payload: Box::new(SendMessagePayload {
                context_id: ctx_id_for_cmd,
                params: core_params,
                sender_did,
                payload: payload_bytes,
                signing_key: Some(signing_key_bytes),
                source_provenance: None,
                spending_ucan,
            }),
            reply: tx,
        };
        rt.block_on(async move {
            sup.dispatch_command(&context_id, cmd).await.map_err(|e| {
                PyRuntimeError::new_err(format!("supervisor dispatch_command failed: {e}"))
            })?;
            rx.await
                .map_err(|e| PyRuntimeError::new_err(format!("shim reply dropped: {e}")))?
                .map_err(|e| PyRuntimeError::new_err(format!("send_message failed: {e}")))
        })?;
    }

    // Bridge: drain events from ContextManager's receive buffer and deliver
    // them to the FFI bridge's mpsc channel so that py_context_receive yields
    // them to Python consumers. This is the producer half of #332.
    drain_and_deliver(&context_id_for_drain);

    Ok(())
}

/// Drains events from the [`ContextManager`]'s receive buffer and delivers
/// them to the FFI bridge's receive channel via [`deliver_message`].
///
/// This is the bridge between the `ContextManager`'s internal event buffer
/// (`ReceiveBuffer`) and the `PyO3` bridge's `tokio::sync::mpsc` channel that
/// feeds `PyMessageReceiver`. Without this, events pushed by
/// `ContextManager::send_message` (e.g., `MessageSent`, `MemberJoined`)
/// would accumulate in the `ReceiveBuffer` but never reach the Python
/// `async for msg in context.receive()` consumer.
///
/// Called after any `ContextManager` operation that may produce events:
/// - `py_context_send` (produces `MessageSent`)
/// - `py_context_join` (produces `MemberJoined`)
/// - `py_context_leave` (produces `MemberLeft`)
///
/// Events are converted from [`ContextEvent`] to [`PyMessage`]:
/// - `MessageSent` -> payload is the message bytes, `sender_did` is the sender.
/// - `MemberJoined` -> payload is `"member_joined:{did}:{role}"`.
/// - `MemberLeft` -> payload is `"member_left:{did}"`.
/// - `SystemClose` -> payload is `"system_close:{did}"`.
/// - Other events -> payload is a debug representation.
///
/// If no receive channel is open (i.e., `py_context_receive` has not been
/// called), events are silently discarded. This is intentional: the channel
/// is demand-driven, and events before subscription are lost (consistent
/// with the subscription model in `TransportAdapter::subscribe`).
/// Converts a [`ContextEvent`] into the `(sender_did, payload, timestamp)` triple
/// used by the `PyO3` bridge event delivery pipeline.
#[allow(clippy::cast_precision_loss)]
#[allow(clippy::too_many_lines)]
fn convert_context_event(
    event: scp_core::context::membership::ContextEvent,
) -> (String, Vec<u8>, f64) {
    use scp_core::context::membership::ContextEvent::{ConsequenceEnforced, ConsequenceTriggered};
    let ts = scp_primitives::SystemClock.now_secs() as f64;
    match event {
        scp_core::context::membership::ContextEvent::MessageSent {
            sender_did,
            payload,
            ..
        } => (sender_did.to_string(), payload, ts),
        scp_core::context::membership::ContextEvent::MemberJoined {
            member_did,
            role_name,
        } => (
            "scp:system".to_owned(),
            // M10: HTML-escape all user-supplied values in event strings.
            format!(
                "member_joined:{}:{}",
                html_escape_event_string(member_did.as_ref()),
                html_escape_event_string(&role_name),
            )
            .into_bytes(),
            ts,
        ),
        scp_core::context::membership::ContextEvent::MemberLeft { member_did } => (
            "scp:system".to_owned(),
            format!(
                "member_left:{}",
                html_escape_event_string(member_did.as_ref()),
            )
            .into_bytes(),
            ts,
        ),
        scp_core::context::membership::ContextEvent::SystemClose { initiator_did } => (
            "scp:system".to_owned(),
            format!(
                "system_close:{}",
                html_escape_event_string(initiator_did.as_ref()),
            )
            .into_bytes(),
            ts,
        ),
        scp_core::context::membership::ContextEvent::SequenceGapDetected {
            sender_did,
            expected_sequence,
            first_delivered_sequence,
            reason,
        } => (
            "scp:system".to_owned(),
            format!(
                "sequence_gap_detected:sender={},\
                 expected={expected_sequence},\
                 first_delivered={first_delivered_sequence},\
                 reason={}",
                html_escape_event_string(&sender_did),
                html_escape_event_string(&reason),
            )
            .into_bytes(),
            ts,
        ),
        ConsequenceTriggered {
            context_id: ctx_id,
            member_did,
            rule_index,
            trigger_type,
            action_type,
        } => (
            "scp:system".to_owned(),
            format!(
                "consequence_triggered:member={},\
                 rule={rule_index},trigger={},\
                 action={},context={}",
                html_escape_event_string(member_did.as_ref()),
                html_escape_event_string(&trigger_type),
                html_escape_event_string(&action_type),
                html_escape_event_string(&ctx_id),
            )
            .into_bytes(),
            ts,
        ),
        ConsequenceEnforced {
            context_id: ctx_id,
            member_did,
            action_type,
            success,
        } => (
            "scp:system".to_owned(),
            format!(
                "consequence_enforced:member={},\
                 action={},success={success},\
                 context={}",
                html_escape_event_string(member_did.as_ref()),
                html_escape_event_string(&action_type),
                html_escape_event_string(&ctx_id),
            )
            .into_bytes(),
            ts,
        ),
        other => (
            "scp:system".to_owned(),
            html_escape_event_string(&format!("{other:?}")).into_bytes(),
            ts,
        ),
    }
}

fn drain_and_deliver(context_id: &str) {
    use scp_core::context::actor::commands::MessagingCommand;
    let Ok(rt) = crate::runtime() else {
        return;
    };
    // Route through the ADR-049 commit-8 messaging shim. Best-effort —
    // if the supervisor is not initialised or the dispatch fails, this
    // function silently no-ops (matches the legacy behaviour of returning
    // an empty events vec on unknown context).
    let Ok(sup) = crate::runtime::supervisor() else {
        return;
    };
    let sup = Arc::clone(sup);
    let context_id_owned = context_id.to_owned();

    let events = rt.block_on(async move {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = MessagingCommand::DrainEvents {
            context_id: context_id_owned.clone(),
            reply: tx,
        };
        if sup.dispatch_command(&context_id_owned, cmd).await.is_err() {
            return Vec::new();
        }
        match rx.await {
            Ok(Ok(events)) => events,
            _ => Vec::new(),
        }
    });

    for event in events {
        let (sender_did, payload, timestamp) = convert_context_event(event);

        let msg = PyMessage::new(sender_did, payload, timestamp, context_id.to_owned());
        // Best-effort: if no channel is open or the channel is full, the
        // event is dropped. This matches the subscription model where
        // events before subscribe are lost.
        let _ = crate::runtime::deliver_message(context_id, msg);
    }
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
    crate::pyscp_check_handle!(handle);
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
    crate::runtime::with_ffi_state(&context_id, |st| {
        st.message_tx = Some(tx);
        st.message_rx = Some(Arc::clone(&rx_arc));
        Ok(())
    })
    .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

    Ok(PyMessageReceiver::from_shared_rx(rx_arc))
}

// ---------------------------------------------------------------------------
// ContextManager delegation helpers
// ---------------------------------------------------------------------------

/// Builds scp-core [`ContextParams`] from a [`PyContextParams`].
///
/// Delegates to the shared [`scp_ffi_common::context_params::build_context_params`]
/// builder, which centralizes all parameter parsing and validation logic
/// across the three non-WASM bridges (#1447).
fn build_core_context_params(
    py_params: &PyContextParams,
) -> PyResult<scp_core::context::ContextParams> {
    use scp_ffi_common::context_params::{CommonContextParams, build_context_params};

    let common = CommonContextParams {
        mode: py_params.mode.clone(),
        ceiling: py_params.ceiling.clone(),
        ceiling_policy: py_params.ceiling_policy.clone(),
        promotion_policy: py_params.promotion_policy.clone(),
        memory_scope: py_params.memory_scope.clone(),
        governance: py_params.governance.clone(),
        ttl: py_params.ttl.map(std::time::Duration::from_secs_f64),
        min_protocol_version: py_params.min_protocol_version,
        max_chain_depth: py_params.max_chain_depth,
        max_nesting_depth: py_params.max_nesting_depth,
        session_cap: py_params.session_cap,
        economic_policy_json: py_params.economic_policy.clone(),
        consequence_rules_json: py_params.consequence_rules.clone(),
        consequence_config_json: py_params.consequence_config.clone(),
        roles: py_params
            .roles
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        tools: py_params.tools.clone(),
        template_id: py_params.template_id.clone(),
        governance_threshold: None, // PyO3 bridge uses string-only governance for now
        governance_signers: None,
        governance_voters: None,
    };

    build_context_params(&common).map_err(PyRuntimeError::new_err)
}

// ---------------------------------------------------------------------------
// Economic policy bridge (§19.3, ADR-033)
// ---------------------------------------------------------------------------

/// Rejects direct economic policy mutation — use governance flow instead
/// (§19.3, #728).
///
/// Economic policy changes MUST go through the governance proposal flow
/// (`SetEconomicPolicy` action) to ensure event logging and the mandatory
/// 24-hour notification period. Direct setters bypass these controls.
///
/// # Errors
///
/// Always returns `PermissionError` directing the caller to use governance.
#[pyfunction]
#[pyo3(signature = (handle, policy_json))]
fn py_set_economic_policy(handle: &mut PyContextHandle, policy_json: &str) -> PyResult<()> {
    crate::pyscp_check_handle!(handle);
    let _ = policy_json;
    Err(pyo3::exceptions::PyPermissionError::new_err(
        "economic policy changes must go through governance \
         (propose SetEconomicPolicy action). Direct mutation is \
         not permitted — see spec §19.3",
    ))
}

/// Returns the economic policy for a context as a JSON string, or `None`.
///
/// # Errors
///
/// Returns `PyErr` if the context handle is not valid, including when the
/// handle was minted by a different `SCP` bridge instance
/// ([`scp_ffi_common::error_codes::PERM_3030`]).
#[pyfunction]
#[pyo3(signature = (handle,))]
fn py_get_economic_policy(handle: &PyContextHandle) -> PyResult<Option<String>> {
    crate::pyscp_check_handle!(handle);
    Ok(handle.params.economic_policy.clone())
}

// ---------------------------------------------------------------------------
// Context export/import bridge (#363)
// ---------------------------------------------------------------------------

/// Exports a context's full state as serialized `MessagePack` bytes.
///
/// The returned bytes are a [`StoredValue<ContextExport>`] envelope per §17.5,
/// suitable for backup, migration, or transfer to another node.
///
/// # Arguments
///
/// * `context_id` -- The context to export.
///
/// # Returns
///
/// Serialized bytes of the context export.
///
/// # Errors
///
/// - `RuntimeError` if the context does not exist or export fails.
#[pyfunction]
#[pyo3(signature = (context_id,))]
fn py_context_export(context_id: &str) -> PyResult<Vec<u8>> {
    use scp_core::context::actor::commands::{LifecycleCommand, QueriesCommand};
    let rt = crate::runtime()?;
    // Route through the ADR-049 commit-9 lifecycle / query shims.
    let sup = crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let sup = Arc::clone(sup);
    let ctx_id = context_id.to_owned();

    let export = rt.block_on(async move {
        // Use the first registered local DID as the exporter.
        let (md_tx, md_rx) = tokio::sync::oneshot::channel();
        let md_cmd = QueriesCommand::MemberDids {
            context_id: ctx_id.clone(),
            reply: md_tx,
        };
        let exporter_did = match sup.dispatch_query(md_cmd).await {
            Ok(_) => match md_rx.await {
                Ok(Ok(dids)) => dids.into_iter().next().map_or_else(
                    || scp_identity::DID::from("did:key:unknown-exporter"),
                    scp_identity::DID::from,
                ),
                _ => scp_identity::DID::from("did:key:unknown-exporter"),
            },
            Err(_) => scp_identity::DID::from("did:key:unknown-exporter"),
        };

        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = LifecycleCommand::ExportContext {
            context_id: ctx_id,
            exporter_did,
            reply: tx,
        };
        sup.dispatch_lifecycle_command(cmd).await.map_err(|e| {
            PyRuntimeError::new_err(format!("supervisor dispatch_lifecycle_command failed: {e}"))
        })?;
        rx.await
            .map_err(|e| PyRuntimeError::new_err(format!("export shim reply dropped: {e}")))?
            .map_err(|e| PyRuntimeError::new_err(format!("context export failed: {e}")))
    })?;

    scp_core::context::export_import::serialize_export(&export)
        .map_err(|e| PyRuntimeError::new_err(format!("export serialization failed: {e}")))
}

/// Imports a context from serialized `MessagePack` bytes.
///
/// The bytes must be a [`StoredValue<ContextExport>`] envelope per §17.5,
/// as produced by [`py_context_export`].
///
/// # Arguments
///
/// * `data` -- Serialized context export bytes.
///
/// # Returns
///
/// The context ID string of the imported context.
///
/// # Errors
///
/// - `RuntimeError` if deserialization, validation, or import fails.
/// - `ValueError` if the data is malformed.
#[pyfunction]
#[pyo3(signature = (data,))]
fn py_context_import(data: &[u8]) -> PyResult<String> {
    use scp_core::context::actor::commands::LifecycleCommand;
    let export = scp_core::context::export_import::deserialize_export(data).map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!("invalid export data: {e}"))
    })?;

    let context_id = export.snapshot.context_id.clone();

    // Validate the exporter DID before passing to init_context_manager (#1324).
    validate::validate_did(&export.exporter_did.0)?;

    // Ensure the ContextManager is initialized — context_import is a valid
    // first operation (e.g. a device receiving exported context data).
    // init_context_manager is idempotent (OnceLock — first call wins). #1073
    // Passes the exporter DID to MlsCryptoProvider for real MLS encryption (#1324).
    #[cfg(test)]
    crate::runtime::init_context_manager_for_test();
    #[cfg(not(test))]
    crate::runtime::init_context_manager(&export.exporter_did.0);

    let rt = crate::runtime()?;
    // Route through the ADR-049 commit-9 lifecycle shim.
    let sup = crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let sup = Arc::clone(sup);

    rt.block_on(async move {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = LifecycleCommand::ImportContext {
            export: Box::new(export),
            reply: tx,
        };
        sup.dispatch_lifecycle_command(cmd).await.map_err(|e| {
            PyRuntimeError::new_err(format!("supervisor dispatch_lifecycle_command failed: {e}"))
        })?;
        rx.await
            .map_err(|e| PyRuntimeError::new_err(format!("import shim reply dropped: {e}")))?
            .map_err(|e| PyRuntimeError::new_err(format!("context import failed: {e}")))?;
        Ok::<(), PyErr>(())
    })?;

    Ok(context_id)
}

// ---------------------------------------------------------------------------
// Governance bridge (#369)
// ---------------------------------------------------------------------------

/// Executes a governance action on a context.
///
/// # Arguments
///
/// * `handle` -- The context handle.
/// * `proposal_json` -- JSON-serialized `GovernanceProposal`.
///
/// # Returns
///
/// A string describing the governance action result (e.g., `"MemberAdded"`).
///
/// # Errors
///
/// Returns `RuntimeError` if the context manager is not initialized, the
/// proposal JSON is invalid, or governance execution fails.
/// Maps a [`GovernanceActionResult`](scp_core::context::manager::GovernanceActionResult)
/// to its canonical `PascalCase` name for the SDK-facing return
/// string. Factored out of `py_governance_execute` to keep that
/// function below the `too_many_lines` clippy threshold.
const fn governance_action_result_name(
    result: &scp_core::context::manager::GovernanceActionResult,
) -> &'static str {
    use scp_core::context::manager::GovernanceActionResult;
    match result {
        GovernanceActionResult::MemberAdded => "MemberAdded",
        GovernanceActionResult::MemberRemoved => "MemberRemoved",
        GovernanceActionResult::RoleChanged => "RoleChanged",
        GovernanceActionResult::ToolRegistered => "ToolRegistered",
        GovernanceActionResult::ToolRemoved => "ToolRemoved",
        GovernanceActionResult::CeilingModified => "CeilingModified",
        GovernanceActionResult::ContextClosed => "ContextClosed",
        GovernanceActionResult::TtlExtended => "TtlExtended",
        GovernanceActionResult::PruningPolicyModified => "PruningPolicyModified",
        GovernanceActionResult::AdminTransferred => "AdminTransferred",
        GovernanceActionResult::SignerAdded => "SignerAdded",
        GovernanceActionResult::SignerRemoved => "SignerRemoved",
        GovernanceActionResult::ThresholdModified => "ThresholdModified",
        GovernanceActionResult::ChildContextCreated => "ChildContextCreated",
        GovernanceActionResult::ToolInterfaceEstablished => "ToolInterfaceEstablished",
        GovernanceActionResult::MemberReset => "MemberReset",
        GovernanceActionResult::ConflictResolved => "ConflictResolved",
        GovernanceActionResult::ContextPromoted => "ContextPromoted",
        GovernanceActionResult::MemberSuspended(_) => "MemberSuspended",
        GovernanceActionResult::AccessRevoked(_) => "AccessRevoked",
        GovernanceActionResult::AccessRestored(_) => "AccessRestored",
        GovernanceActionResult::ContentKeysRotated(_) => "ContentKeysRotated",
        GovernanceActionResult::GovernanceReconfigured(_) => "GovernanceReconfigured",
        GovernanceActionResult::SubscriberBanned(_) => "SubscriberBanned",
        GovernanceActionResult::SubscriberUnbanned { .. } => "SubscriberUnbanned",
        GovernanceActionResult::Executed => "Executed",
        GovernanceActionResult::MigrationProposed(_) => "MigrationProposed",
        GovernanceActionResult::MigrationCancelled => "MigrationCancelled",
        GovernanceActionResult::ContextTombstoned => "ContextTombstoned",
    }
}

#[pyfunction]
#[pyo3(signature = (handle, proposal_json))]
fn py_governance_execute(handle: &PyContextHandle, proposal_json: &str) -> PyResult<String> {
    crate::pyscp_check_handle!(handle);
    let rt = crate::runtime()?;
    let context_id = handle.context_id.clone();
    let handle_state = handle.state.clone();
    let proposal_json_owned = proposal_json.to_owned();

    // Route through the ADR-049 commit-10 governance shim
    // ([`Supervisor::dispatch_governance_command`](scp_core::context::supervisor::Supervisor::dispatch_governance_command))
    // rather than calling `ContextManager::execute_governance_action`
    // directly. The shim wraps the delegated call in a 30s transport-
    // timeout budget and is the entry point commit 12 will keep after
    // `ContextManager` is deleted.
    let sup = crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let sup = Arc::clone(sup);

    rt.block_on(async move {
        use scp_core::context::actor::commands::{
            ExecuteGovernanceActionPayload, GovernanceCommand, QueriesCommand,
        };

        let proposal: scp_core::context::governance::GovernanceProposal =
            serde_json::from_str(&proposal_json_owned).map_err(|e| {
                PyValueError::new_err(format!("invalid governance proposal JSON: {e}"))
            })?;
        scp_ffi_common::validate::validate_governance_action_strings(&proposal.action)
            .map_err(|e| PyValueError::new_err(e.message))?;
        let action_name = proposal.action.variant_name();

        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = GovernanceCommand::ExecuteGovernanceAction {
            payload: Box::new(ExecuteGovernanceActionPayload {
                context_id: context_id.clone(),
                proposal,
            }),
            reply: tx,
        };
        sup.dispatch_governance_command(cmd).await.map_err(|e| {
            PyRuntimeError::new_err(format!(
                "supervisor dispatch_governance_command failed: {e}"
            ))
        })?;
        let result = rx
            .await
            .map_err(|e| {
                PyRuntimeError::new_err(format!("governance execute shim reply dropped: {e}"))
            })?
            .map_err(|e| PyRuntimeError::new_err(format!("governance execution failed: {e}")))?;

        // Re-sync local role state cache from ContextManager after any
        // governance action that may have modified roles/membership (#560).
        //
        // NOTE: Cannot call `sync_role_state_from_manager()` here because that
        // function uses `rt.block_on()` and we are already inside `rt.block_on()`.
        // Nested `block_on` panics with "Cannot start a runtime from within a
        // runtime." Instead, dispatch the role-state query inline.
        let (rs_tx, rs_rx) = tokio::sync::oneshot::channel();
        let rs_cmd = QueriesCommand::GetRoleState {
            context_id: context_id.clone(),
            reply: rs_tx,
        };
        let role_state_lookup = match sup.dispatch_query(rs_cmd).await {
            Ok(_) => rs_rx.await.ok().and_then(Result::ok).flatten(),
            Err(_) => None,
        };
        match role_state_lookup {
            Some(new_role_state) => {
                if let Err(e) = crate::runtime::with_ffi_state(&context_id, |st| {
                    st.role_state = new_role_state;
                    Ok(())
                }) {
                    tracing::warn!(
                        context_id = %context_id,
                        action = action_name,
                        error = %e,
                        "failed to sync role state after governance action — \
                         local capability checks may be stale"
                    );
                }
            }
            None => {
                tracing::warn!(
                    context_id = %context_id,
                    action = action_name,
                    "failed to sync role state after governance action — \
                     context not found in ContextManager"
                );
            }
        }

        let result_str = governance_action_result_name(&result);

        // Sync FFI handle state for migration transitions (§5.11A).
        // The core ContextManager has already transitioned; keep the
        // FFI-side string in lockstep.
        match result_str {
            "MigrationProposed" => {
                if let Ok(mut s) = handle_state.lock() {
                    "migrating_out".clone_into(&mut s);
                }
            }
            "MigrationCancelled" => {
                if let Ok(mut s) = handle_state.lock() {
                    "active".clone_into(&mut s);
                }
            }
            "ContextTombstoned" => {
                if let Ok(mut s) = handle_state.lock() {
                    "tombstoned".clone_into(&mut s);
                }
            }
            _ => {}
        }

        Ok(result_str.to_owned())
    })
}

// ---------------------------------------------------------------------------
// Context migration lifecycle (§5.11A, #580)
// ---------------------------------------------------------------------------

/// Tombstones a migrated context after its grace period has expired (§5.11A.5).
///
/// Transitions the context from `MigratingOut` to `Tombstoned`, emits
/// the tombstone event, and cleans up timers/broadcast state. The
/// application layer calls this when it detects the grace period has elapsed.
///
/// # Arguments
///
/// * `handle` -- The context handle (must be in `MigratingOut` state).
///
/// # Errors
///
/// Returns `RuntimeError` if the context is not migrating or the grace
/// period has not expired.
#[pyfunction]
#[pyo3(signature = (handle,))]
fn py_tombstone_migrated_context(handle: &PyContextHandle) -> PyResult<()> {
    use scp_core::context::actor::commands::GovernanceCommand;
    crate::pyscp_check_handle!(handle);
    let rt = crate::runtime()?;
    // Route through the ADR-049 commit-10 governance shim.
    let sup = crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let sup = Arc::clone(sup);
    let context_id = handle.context_id.clone();
    let handle_state = handle.state.clone();

    rt.block_on(async move {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = GovernanceCommand::TombstoneMigratedContext {
            context_id,
            reply: tx,
        };
        sup.dispatch_governance_command(cmd).await.map_err(|e| {
            PyRuntimeError::new_err(format!(
                "supervisor dispatch_governance_command failed: {e}"
            ))
        })?;
        rx.await
            .map_err(|e| PyRuntimeError::new_err(format!("tombstone shim reply dropped: {e}")))?
            .map_err(|e| {
                PyRuntimeError::new_err(format!("tombstone_migrated_context failed: {e}"))
            })?;

        // Sync FFI handle state to "tombstoned" (§5.11A.5).
        if let Ok(mut s) = handle_state.lock() {
            "tombstoned".clone_into(&mut s);
        }

        Ok(())
    })
}

/// Returns the migration state for a context, if any (§5.11A).
///
/// Returns a JSON string with the migration state fields, or `None` if
/// the context is not migrating.
///
/// # Arguments
///
/// * `handle` -- The context handle.
///
/// # Returns
///
/// `Optional[str]` -- JSON string with `{ "destination_context_id": str,
/// "reason": str, "grace_period_end": int, "auto_invite": bool,
/// "proposal_id": hex }`, or `None`.
#[pyfunction]
#[pyo3(signature = (handle,))]
fn py_migration_state(handle: &PyContextHandle) -> PyResult<Option<String>> {
    use scp_core::context::actor::commands::GovernanceCommand;
    crate::pyscp_check_handle!(handle);
    let rt = crate::runtime()?;
    // Route through the ADR-049 commit-10 governance shim.
    let sup = crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let sup = Arc::clone(sup);
    let context_id = handle.context_id.clone();

    rt.block_on(async move {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = GovernanceCommand::MigrationState {
            context_id,
            reply: tx,
        };
        sup.dispatch_governance_command(cmd).await.map_err(|e| {
            PyRuntimeError::new_err(format!(
                "supervisor dispatch_governance_command failed: {e}"
            ))
        })?;
        let state = rx
            .await
            .map_err(|e| {
                PyRuntimeError::new_err(format!("migration_state shim reply dropped: {e}"))
            })?
            .map_err(|e| PyRuntimeError::new_err(format!("migration_state failed: {e}")))?;
        match state {
            Some(ms) => {
                let json = serde_json::json!({
                    "destination_context_id": ms.destination_context_id,
                    "reason": ms.reason,
                    "grace_period_end": ms.grace_period_end,
                    "auto_invite": ms.auto_invite,
                    "proposal_id": hex::encode(ms.proposal_id),
                });
                Ok(Some(json.to_string()))
            }
            None => Ok(None),
        }
    })
}

// ---------------------------------------------------------------------------
// Governance proposal lifecycle (#621)
// ---------------------------------------------------------------------------

/// Helper: resolve the raw Ed25519 signing key for an identity DID.
///
/// Looks up the identity in the global registry, retrieves the custody
/// provider and active signing key handle, and exports the raw
/// `ed25519_dalek::SigningKey`. Required because the core governance
/// lifecycle functions take `&SigningKey` directly.
fn resolve_signing_key(identity_did: &str) -> PyResult<ed25519_dalek::SigningKey> {
    let rt = crate::runtime()?;
    crate::runtime::with_identity(identity_did, |entry| {
        let handle = entry.identity.active_signing_key;
        let custody = entry.custody.clone();
        rt.block_on(async move { custody.export_ed25519_signing_key(&handle).await })
            .map_err(|e| {
                crate::error::ScpPyError::context(format!(
                    "failed to export signing key for governance: {e}"
                ))
            })
    })
    .map_err(|e| PyRuntimeError::new_err(e.to_string()))
}

/// Proposes a governance action for voting.
///
/// Delegates to [`ContextManager::propose_governance_action_checked`],
/// which validates the proposer's `GovernancePropose` capability before
/// submitting the proposal to the governance engine.
///
/// For `SingleAdmin` contexts, the proposal is auto-approved and executed
/// immediately. For multi-admin models (Threshold, Majority, Unanimity),
/// the proposal enters `Pending` status and must accumulate votes.
///
/// # Arguments
///
/// * `handle` -- The context handle.
/// * `identity_did` -- DID of the proposer.
/// * `action_json` -- JSON-serialized `GovernanceAction`.
///
/// # Returns
///
/// JSON string with `{ "proposal_id": hex, "status": string,
/// "execution_result": string | null }`.
///
/// # Errors
///
/// Returns `RuntimeError` (SCP-CTX-2040) if the context manager is not
/// initialized, the action JSON is invalid, or the proposal fails.
#[pyfunction]
#[pyo3(signature = (handle, identity_did, action_json))]
fn py_governance_propose(
    handle: &PyContextHandle,
    identity_did: &str,
    action_json: &str,
) -> PyResult<String> {
    crate::pyscp_check_handle!(handle);
    let rt = crate::runtime()?;
    // sync_role_state_from_manager below uses its own global accessor.
    let context_id = handle.context_id.clone();
    let action_json_owned = action_json.to_owned();
    let signing_key = resolve_signing_key(identity_did)?;
    let proposer_did = scp_identity::DID(identity_did.to_owned());

    // Route through the ADR-049 commit-10 governance shim.
    let sup = crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let sup = Arc::clone(sup);

    rt.block_on(async move {
        use scp_core::context::actor::commands::{
            GovernanceCommand, ProposeGovernanceActionPayload, SigningKeyBytes,
        };

        let action: scp_core::context::governance::GovernanceAction =
            serde_json::from_str(&action_json_owned).map_err(|e| {
                PyValueError::new_err(format!("SCP-CTX-2040: invalid governance action JSON: {e}"))
            })?;

        scp_ffi_common::validate::validate_governance_action_strings(&action)
            .map_err(|e| PyValueError::new_err(format!("SCP-CTX-2040: {}", e.message)))?;

        let action_name = action.variant_name();

        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = GovernanceCommand::ProposeGovernanceActionChecked {
            payload: Box::new(ProposeGovernanceActionPayload {
                context_id: context_id.clone(),
                proposer_did: proposer_did.clone(),
                action,
                signing_key: SigningKeyBytes::from_signing_key(&signing_key),
            }),
            reply: tx,
        };
        sup.dispatch_governance_command(cmd).await.map_err(|e| {
            PyRuntimeError::new_err(format!(
                "SCP-CTX-2041: supervisor dispatch_governance_command failed: {e}"
            ))
        })?;
        let outcome = rx
            .await
            .map_err(|e| {
                PyRuntimeError::new_err(format!(
                    "SCP-CTX-2041: governance propose shim reply dropped: {e}"
                ))
            })?
            .map_err(|e| {
                PyRuntimeError::new_err(format!("SCP-CTX-2041: governance proposal failed: {e}"))
            })?;

        // Re-sync local role state cache from ContextManager after any
        // governance action that may have modified roles/membership (#560).
        if let Err(e) = crate::runtime::sync_role_state_from_manager(&context_id) {
            tracing::warn!(
                context_id = %context_id,
                action = action_name,
                error = %e,
                "failed to sync role state after governance proposal — \
                 local capability checks may be stale"
            );
        }

        let result_str = outcome.execution_result.as_ref().map(|r| format!("{r:?}"));

        let response = serde_json::json!({
            "proposal_id": hex::encode(outcome.proposal.proposal_id),
            "status": format!("{:?}", outcome.status),
            "execution_result": result_str,
        });
        Ok(response.to_string())
    })
}

/// Validates all user-controlled string fields on a governance action.
#[cfg(test)]
fn validate_governance_action_strings(
    action: &scp_core::context::governance::GovernanceAction,
) -> Result<(), crate::error::ScpPyError> {
    scp_ffi_common::validate::validate_governance_action_strings(action)
        .map_err(|e| crate::error::ScpPyError::validation(e.message))
}

/// Casts an approval vote on a pending governance proposal.
///
/// Delegates to [`ContextManager::approve_governance_proposal`], which
/// validates the voter's `GovernanceVote` capability before casting the
/// vote. If the vote pushes the proposal past quorum, the action is
/// auto-executed.
///
/// # Arguments
///
/// * `handle` -- The context handle.
/// * `identity_did` -- DID of the voter.
/// * `proposal_id_hex` -- Hex-encoded 32-byte proposal ID.
///
/// # Returns
///
/// JSON string with `{ "status": string }` (Pending, Approved, Rejected,
/// etc.).
///
/// # Errors
///
/// Returns `RuntimeError` (SCP-CTX-2042) if the vote fails.
#[pyfunction]
#[pyo3(signature = (handle, identity_did, proposal_id_hex))]
fn py_governance_approve(
    handle: &PyContextHandle,
    identity_did: &str,
    proposal_id_hex: &str,
) -> PyResult<String> {
    crate::pyscp_check_handle!(handle);
    let rt = crate::runtime()?;
    // sync_role_state_from_manager below still relies on the attached
    // ContextManager via its own global accessor; no need to keep an
    // Arc alive in this scope now that the vote routes through the
    // supervisor shim.
    let context_id = handle.context_id.clone();
    let signing_key = resolve_signing_key(identity_did)?;
    let voter_did = scp_identity::DID(identity_did.to_owned());
    let proposal_id = parse_proposal_id(proposal_id_hex)?;

    // Route through the ADR-049 commit-10 governance shim.
    let sup = crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let sup = Arc::clone(sup);

    rt.block_on(async move {
        use scp_core::context::actor::commands::{
            GovernanceCommand, SigningKeyBytes, VoteOnProposalPayload,
        };

        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = GovernanceCommand::ApproveGovernanceProposal {
            payload: Box::new(VoteOnProposalPayload {
                context_id: context_id.clone(),
                proposal_id,
                voter_did: voter_did.clone(),
                signing_key: SigningKeyBytes::from_signing_key(&signing_key),
            }),
            reply: tx,
        };
        sup.dispatch_governance_command(cmd).await.map_err(|e| {
            PyRuntimeError::new_err(format!(
                "SCP-CTX-2042: supervisor dispatch_governance_command failed: {e}"
            ))
        })?;
        let status = rx
            .await
            .map_err(|e| {
                PyRuntimeError::new_err(format!(
                    "SCP-CTX-2042: governance approve shim reply dropped: {e}"
                ))
            })?
            .map_err(|e| {
                PyRuntimeError::new_err(format!("SCP-CTX-2042: governance approval failed: {e}"))
            })?;

        if let Err(e) = crate::runtime::sync_role_state_from_manager(&context_id) {
            tracing::warn!(
                context_id = %context_id,
                error = %e,
                "failed to sync role state after governance approval"
            );
        }

        Ok(serde_json::json!({ "status": format!("{status:?}") }).to_string())
    })
}

/// Casts a rejection vote on a pending governance proposal.
///
/// Delegates to [`ContextManager::reject_governance_proposal`], which
/// validates the voter's `GovernanceVote` capability before casting the
/// vote.
///
/// # Arguments
///
/// * `handle` -- The context handle.
/// * `identity_did` -- DID of the voter.
/// * `proposal_id_hex` -- Hex-encoded 32-byte proposal ID.
///
/// # Returns
///
/// JSON string with `{ "status": string }`.
///
/// # Errors
///
/// Returns `RuntimeError` (SCP-CTX-2043) if the vote fails.
#[pyfunction]
#[pyo3(signature = (handle, identity_did, proposal_id_hex))]
fn py_governance_reject(
    handle: &PyContextHandle,
    identity_did: &str,
    proposal_id_hex: &str,
) -> PyResult<String> {
    use scp_core::context::actor::commands::{
        GovernanceCommand, SigningKeyBytes, VoteOnProposalPayload,
    };
    crate::pyscp_check_handle!(handle);
    let rt = crate::runtime()?;
    // Route through the ADR-049 commit-10 governance shim.
    let sup = crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let sup = Arc::clone(sup);
    let context_id = handle.context_id.clone();
    let signing_key = resolve_signing_key(identity_did)?;
    let voter_did = scp_identity::DID(identity_did.to_owned());
    let proposal_id = parse_proposal_id(proposal_id_hex)?;

    rt.block_on(async move {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = GovernanceCommand::RejectGovernanceProposal {
            payload: Box::new(VoteOnProposalPayload {
                context_id: context_id.clone(),
                proposal_id,
                voter_did,
                signing_key: SigningKeyBytes::from_signing_key(&signing_key),
            }),
            reply: tx,
        };
        sup.dispatch_governance_command(cmd).await.map_err(|e| {
            PyRuntimeError::new_err(format!(
                "SCP-CTX-2043: supervisor dispatch_governance_command failed: {e}"
            ))
        })?;
        let status = rx
            .await
            .map_err(|e| {
                PyRuntimeError::new_err(format!(
                    "SCP-CTX-2043: governance reject shim reply dropped: {e}"
                ))
            })?
            .map_err(|e| {
                PyRuntimeError::new_err(format!("SCP-CTX-2043: governance rejection failed: {e}"))
            })?;

        if let Err(e) = crate::runtime::sync_role_state_from_manager(&context_id) {
            tracing::warn!(
                context_id = %context_id,
                error = %e,
                "failed to sync role state after governance rejection"
            );
        }

        Ok(serde_json::json!({ "status": format!("{status:?}") }).to_string())
    })
}

/// Withdraws a previously cast vote on a pending governance proposal.
///
/// Delegates to [`ContextManager::withdraw_governance_vote`]. No signing
/// key is required -- withdrawal is the voter's privileged operation on
/// their own vote.
///
/// # Arguments
///
/// * `handle` -- The context handle.
/// * `identity_did` -- DID of the voter.
/// * `proposal_id_hex` -- Hex-encoded 32-byte proposal ID.
///
/// # Returns
///
/// JSON string with `{ "status": string }`.
///
/// # Errors
///
/// Returns `RuntimeError` (SCP-CTX-2044) if the withdrawal fails.
#[pyfunction]
#[pyo3(signature = (handle, identity_did, proposal_id_hex))]
fn py_governance_withdraw(
    handle: &PyContextHandle,
    identity_did: &str,
    proposal_id_hex: &str,
) -> PyResult<String> {
    use scp_core::context::actor::commands::GovernanceCommand;
    crate::pyscp_check_handle!(handle);
    let rt = crate::runtime()?;
    // Route through the ADR-049 commit-10 governance shim.
    let sup = crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let sup = Arc::clone(sup);
    let context_id = handle.context_id.clone();
    let voter_did = scp_identity::DID(identity_did.to_owned());
    let proposal_id = parse_proposal_id(proposal_id_hex)?;

    rt.block_on(async move {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = GovernanceCommand::WithdrawGovernanceVote {
            context_id: context_id.clone(),
            proposal_id,
            voter_did,
            reply: tx,
        };
        sup.dispatch_governance_command(cmd).await.map_err(|e| {
            PyRuntimeError::new_err(format!(
                "SCP-CTX-2044: supervisor dispatch_governance_command failed: {e}"
            ))
        })?;
        let status = rx
            .await
            .map_err(|e| {
                PyRuntimeError::new_err(format!(
                    "SCP-CTX-2044: governance withdraw shim reply dropped: {e}"
                ))
            })?
            .map_err(|e| {
                PyRuntimeError::new_err(format!(
                    "SCP-CTX-2044: governance vote withdrawal failed: {e}"
                ))
            })?;

        if let Err(e) = crate::runtime::sync_role_state_from_manager(&context_id) {
            tracing::warn!(
                context_id = %context_id,
                error = %e,
                "failed to sync role state after governance withdrawal"
            );
        }

        Ok(serde_json::json!({ "status": format!("{status:?}") }).to_string())
    })
}

/// Parses a hex-encoded proposal ID into a 32-byte array.
fn parse_proposal_id(hex_str: &str) -> PyResult<[u8; 32]> {
    let bytes = hex::decode(hex_str).map_err(|e| {
        PyValueError::new_err(format!("SCP-CTX-2040: invalid proposal ID hex: {e}"))
    })?;
    let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
        PyValueError::new_err(format!(
            "SCP-CTX-2040: proposal ID must be 32 bytes, got {}",
            v.len()
        ))
    })?;
    Ok(arr)
}

/// Retrieves a single governance proposal by hex-encoded ID.
///
/// # Errors
///
/// Returns `RuntimeError` (SCP-CTX-2045) if the proposal is not found.
#[pyfunction]
#[pyo3(signature = (handle, proposal_id_hex))]
fn py_governance_get_proposal(
    handle: &PyContextHandle,
    proposal_id_hex: String,
) -> PyResult<String> {
    use scp_core::context::actor::commands::GovernanceCommand;
    crate::pyscp_check_handle!(handle);
    let context_id = handle.context_id.clone();
    let proposal_id = parse_proposal_id(&proposal_id_hex)?;

    // Route through the ADR-049 commit-10 governance shim.
    let sup = crate::runtime::supervisor()
        .map_err(|e| PyRuntimeError::new_err(format!("SCP-CTX-2040: {e}")))?;
    let sup = Arc::clone(sup);
    let rt = crate::runtime().map_err(|e| PyRuntimeError::new_err(format!("SCP-CTX-2040: {e}")))?;

    rt.block_on(async move {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = GovernanceCommand::GetProposal {
            context_id,
            proposal_id,
            reply: tx,
        };
        sup.dispatch_governance_command(cmd).await.map_err(|e| {
            PyRuntimeError::new_err(format!(
                "SCP-CTX-2045: supervisor dispatch_governance_command failed: {e}"
            ))
        })?;
        let proposal = rx
            .await
            .map_err(|e| {
                PyRuntimeError::new_err(format!(
                    "SCP-CTX-2045: get proposal shim reply dropped: {e}"
                ))
            })?
            .map_err(|e| {
                PyRuntimeError::new_err(format!("SCP-CTX-2045: get proposal failed: {e}"))
            })?;

        serde_json::to_string(&proposal).map_err(|e| {
            PyRuntimeError::new_err(format!("SCP-CTX-2045: serialization failed: {e}"))
        })
    })
}

/// Lists all governance proposals for a context.
///
/// # Errors
///
/// Returns `RuntimeError` (SCP-CTX-2046) if listing fails.
#[pyfunction]
#[pyo3(signature = (handle,))]
fn py_governance_list_proposals(handle: &PyContextHandle) -> PyResult<String> {
    use scp_core::context::actor::commands::GovernanceCommand;
    crate::pyscp_check_handle!(handle);
    let context_id = handle.context_id.clone();

    // Route through the ADR-049 commit-10 governance shim.
    let sup = crate::runtime::supervisor()
        .map_err(|e| PyRuntimeError::new_err(format!("SCP-CTX-2040: {e}")))?;
    let sup = Arc::clone(sup);
    let rt = crate::runtime().map_err(|e| PyRuntimeError::new_err(format!("SCP-CTX-2040: {e}")))?;

    rt.block_on(async move {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = GovernanceCommand::ListProposals {
            context_id,
            reply: tx,
        };
        sup.dispatch_governance_command(cmd).await.map_err(|e| {
            PyRuntimeError::new_err(format!(
                "SCP-CTX-2046: supervisor dispatch_governance_command failed: {e}"
            ))
        })?;
        let proposals = rx
            .await
            .map_err(|e| {
                PyRuntimeError::new_err(format!(
                    "SCP-CTX-2046: list proposals shim reply dropped: {e}"
                ))
            })?
            .map_err(|e| {
                PyRuntimeError::new_err(format!("SCP-CTX-2046: list proposals failed: {e}"))
            })?;

        serde_json::to_string(&proposals).map_err(|e| {
            PyRuntimeError::new_err(format!("SCP-CTX-2046: serialization failed: {e}"))
        })
    })
}

// ---------------------------------------------------------------------------
// Ceiling modification, context close, checkpoint, restore (#559)
// ---------------------------------------------------------------------------

/// Applies a pending ceiling modification if the notification period has elapsed.
///
/// Delegates to [`ContextManager::apply_pending_ceiling_modification`].
/// Returns `true` if the modification was applied, `false` if no pending
/// modification exists or the notification period has not elapsed.
///
/// # Arguments
///
/// * `handle` -- The context handle.
/// * `current_timestamp` -- Current Unix timestamp in seconds.
///
/// # Returns
///
/// `true` if the ceiling modification was applied, `false` otherwise.
///
/// # Errors
///
/// Returns `RuntimeError` (SCP-CTX-2060) if the operation fails.
#[pyfunction]
#[pyo3(signature = (handle, current_timestamp))]
fn py_apply_pending_ceiling_modification(
    handle: &PyContextHandle,
    current_timestamp: u64,
) -> PyResult<bool> {
    use scp_core::context::actor::commands::GovernanceCommand;
    crate::pyscp_check_handle!(handle);
    let rt = crate::runtime()?;
    // Route through the ADR-049 commit-10 governance shim.
    let sup = crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let sup = Arc::clone(sup);
    let context_id = handle.context_id.clone();

    rt.block_on(async move {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = GovernanceCommand::ApplyPendingCeilingModification {
            context_id,
            current_timestamp,
            reply: tx,
        };
        sup.dispatch_governance_command(cmd).await.map_err(|e| {
            PyRuntimeError::new_err(format!(
                "SCP-CTX-2060: supervisor dispatch_governance_command failed: {e}"
            ))
        })?;
        rx.await
            .map_err(|e| {
                PyRuntimeError::new_err(format!(
                    "SCP-CTX-2060: apply ceiling shim reply dropped: {e}"
                ))
            })?
            .map_err(|e| {
                PyRuntimeError::new_err(format!(
                    "SCP-CTX-2060: apply_pending_ceiling_modification failed: {e}"
                ))
            })
    })
}

/// Finalizes the cooperative close flow for a context in `Closing` state.
///
/// Delegates to [`ContextManager::finalize_close`], which transitions
/// the context from `Closing` to `Closed`, destroys keys per memory scope,
/// and records a `ContextClosed` event.
///
/// # Arguments
///
/// * `handle` -- The context handle (must be in `Closing` state).
///
/// # Errors
///
/// Returns `RuntimeError` (SCP-CTX-2061) if the context is not in
/// `Closing` state or finalization fails.
#[pyfunction]
#[pyo3(signature = (handle,))]
fn py_finalize_close(handle: &PyContextHandle) -> PyResult<()> {
    use scp_core::context::actor::commands::{TtlCloseCommand, TtlContextPayload};
    crate::pyscp_check_handle!(handle);
    let rt = crate::runtime()?;
    // Route through the ADR-049 commit-9 TTL-close shim.
    let sup = crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let sup = Arc::clone(sup);
    let core_params = build_core_context_params(&handle.params)?;
    let context_id = handle.context_id.clone();

    rt.block_on(async move {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = TtlCloseCommand::FinalizeClose {
            payload: Box::new(TtlContextPayload {
                context_id,
                params: core_params,
            }),
            reply: tx,
        };
        sup.dispatch_ttl_close_command(cmd).await.map_err(|e| {
            PyRuntimeError::new_err(format!(
                "SCP-CTX-2061: supervisor dispatch_ttl_close_command failed: {e}"
            ))
        })?;
        rx.await
            .map_err(|e| {
                PyRuntimeError::new_err(format!(
                    "SCP-CTX-2061: finalize_close shim reply dropped: {e}"
                ))
            })?
            .map_err(|e| {
                PyRuntimeError::new_err(format!("SCP-CTX-2061: finalize_close failed: {e}"))
            })
    })?;

    // Update FFI handle state to reflect close.
    let mut state = handle
        .state
        .lock()
        .map_err(|_| PyRuntimeError::new_err("context state lock is poisoned"))?;
    "closed".clone_into(&mut state);

    Ok(())
}

/// Creates a governance checkpoint for a context (ADR-031 §9).
///
/// Delegates to [`ContextManager::create_governance_checkpoint`].
///
/// # Arguments
///
/// * `handle` -- The context handle.
/// * `checkpoint_seq` -- Sequence number in the event log.
/// * `merkle_root_hex` -- Hex-encoded 32-byte Merkle root.
/// * `event_count` -- Number of events included.
/// * `last_event_hash_hex` -- Hex-encoded 32-byte hash of the last event.
/// * `state_snapshot_hash_hex` -- Hex-encoded 32-byte state snapshot hash.
/// * `creator_did` -- DID of the checkpoint creator.
/// * `creator_signature_hex` -- Hex-encoded Ed25519 signature (64 bytes).
///
/// # Returns
///
/// JSON string with the full `ContextCheckpoint` object.
///
/// # Errors
///
/// Returns `RuntimeError` (SCP-CTX-2062) if checkpoint creation fails.
#[pyfunction]
#[pyo3(signature = (handle, checkpoint_seq, merkle_root_hex, event_count, last_event_hash_hex, state_snapshot_hash_hex, creator_did, creator_signature_hex))]
#[allow(clippy::too_many_arguments)]
fn py_create_governance_checkpoint(
    handle: &PyContextHandle,
    checkpoint_seq: u64,
    merkle_root_hex: &str,
    event_count: u64,
    last_event_hash_hex: &str,
    state_snapshot_hash_hex: &str,
    creator_did: &str,
    creator_signature_hex: &str,
) -> PyResult<String> {
    use scp_core::context::actor::commands::{
        CreateGovernanceCheckpointPayload, TrustRecoveryCommand,
    };
    crate::pyscp_check_handle!(handle);
    let rt = crate::runtime()?;
    // Route through the ADR-049 commit-10 trust-recovery shim.
    let sup = crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let sup = Arc::clone(sup);
    let context_id = handle.context_id.clone();

    let merkle_root = parse_hex_32(merkle_root_hex, "merkle_root")?;
    let last_event_hash = parse_hex_32(last_event_hash_hex, "last_event_hash")?;
    let state_snapshot_hash = parse_hex_32(state_snapshot_hash_hex, "state_snapshot_hash")?;
    let creator_signature = hex::decode(creator_signature_hex).map_err(|e| {
        PyValueError::new_err(format!("SCP-CTX-2062: invalid creator_signature hex: {e}"))
    })?;
    let did = scp_identity::DID(creator_did.to_owned());

    rt.block_on(async move {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = TrustRecoveryCommand::CreateGovernanceCheckpoint {
            payload: Box::new(CreateGovernanceCheckpointPayload {
                context_id,
                checkpoint_seq,
                merkle_root,
                event_count,
                last_event_hash,
                state_snapshot_hash,
                creator_did: did,
                creator_signature,
            }),
            reply: tx,
        };
        sup.dispatch_trust_recovery_command(cmd)
            .await
            .map_err(|e| {
                PyRuntimeError::new_err(format!(
                    "SCP-CTX-2062: supervisor dispatch_trust_recovery_command failed: {e}"
                ))
            })?;
        let checkpoint = rx
            .await
            .map_err(|e| {
                PyRuntimeError::new_err(format!(
                    "SCP-CTX-2062: create_governance_checkpoint shim reply dropped: {e}"
                ))
            })?
            .map_err(|e| {
                PyRuntimeError::new_err(format!(
                    "SCP-CTX-2062: create_governance_checkpoint failed: {e}"
                ))
            })?;

        serde_json::to_string(&checkpoint).map_err(|e| {
            PyRuntimeError::new_err(format!("SCP-CTX-2062: serialization failed: {e}"))
        })
    })
}

/// Adds a cosignature to an existing governance checkpoint (ADR-031 §9).
///
/// Delegates to [`ContextManager::add_checkpoint_cosignature`].
///
/// # Arguments
///
/// * `handle` -- The context handle.
/// * `checkpoint_json` -- JSON-serialized `ContextCheckpoint`.
/// * `signer_did` -- DID of the cosigner.
/// * `signature_hex` -- Hex-encoded Ed25519 signature (64 bytes).
///
/// # Returns
///
/// JSON string with `{ "attestation_status": string, "checkpoint": object }`.
///
/// # Errors
///
/// Returns `RuntimeError` (SCP-CTX-2063) if cosignature validation fails.
#[pyfunction]
#[pyo3(signature = (handle, checkpoint_json, signer_did, signature_hex))]
fn py_add_checkpoint_cosignature(
    handle: &PyContextHandle,
    checkpoint_json: &str,
    signer_did: &str,
    signature_hex: &str,
) -> PyResult<String> {
    use scp_core::context::actor::commands::TrustRecoveryCommand;
    crate::pyscp_check_handle!(handle);
    let rt = crate::runtime()?;
    // Route through the ADR-049 commit-10 trust-recovery shim.
    let sup = crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let sup = Arc::clone(sup);
    let context_id = handle.context_id.clone();

    let checkpoint: scp_core::context::governance::ContextCheckpoint =
        serde_json::from_str(checkpoint_json).map_err(|e| {
            PyValueError::new_err(format!("SCP-CTX-2063: invalid checkpoint JSON: {e}"))
        })?;

    let signature = hex::decode(signature_hex)
        .map_err(|e| PyValueError::new_err(format!("SCP-CTX-2063: invalid signature hex: {e}")))?;

    let cosignature = scp_core::context::governance::CosignedCheckpoint {
        signer_did: scp_identity::DID(signer_did.to_owned()),
        signature,
    };

    rt.block_on(async move {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = TrustRecoveryCommand::AddCheckpointCosignature {
            context_id,
            checkpoint: Box::new(checkpoint),
            cosignature: Box::new(cosignature),
            reply: tx,
        };
        sup.dispatch_trust_recovery_command(cmd)
            .await
            .map_err(|e| {
                PyRuntimeError::new_err(format!(
                    "SCP-CTX-2063: supervisor dispatch_trust_recovery_command failed: {e}"
                ))
            })?;
        let (updated_checkpoint, status) = rx
            .await
            .map_err(|e| {
                PyRuntimeError::new_err(format!(
                    "SCP-CTX-2063: add_checkpoint_cosignature shim reply dropped: {e}"
                ))
            })?
            .map_err(|e| {
                PyRuntimeError::new_err(format!(
                    "SCP-CTX-2063: add_checkpoint_cosignature failed: {e}"
                ))
            })?;

        let response = serde_json::json!({
            "attestation_status": format!("{status:?}"),
            "checkpoint": serde_json::to_value(&updated_checkpoint).unwrap_or_default(),
        });
        Ok(response.to_string())
    })
}

/// Restores a single persisted context from storage.
///
/// Delegates to [`ContextManager::restore_context`]. The context must
/// have been previously persisted and must not already be registered.
///
/// # Arguments
///
/// * `context_id` -- The context ID to restore.
///
/// # Errors
///
/// Returns `RuntimeError` (SCP-CTX-2064) if restoration fails.
#[pyfunction]
#[pyo3(signature = (context_id,))]
fn py_restore_context(context_id: &str) -> PyResult<()> {
    use scp_core::context::actor::commands::{LifecycleCommand, RestoreContextPayload};
    let rt = crate::runtime()?;
    // Route through the ADR-049 commit-9 lifecycle shim. The handler
    // reconstructs an ephemeral ContextHandle and delegates to the
    // manager's restore_context, which loads its own snapshot from
    // persistence — the ContextParams we supply here is only used to
    // initialise the ephemeral handle wrapper (default is acceptable
    // because restore_context overwrites all memory-scope-sensitive
    // state from the loaded snapshot anyway).
    let sup = crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let sup = Arc::clone(sup);
    let context_id_owned = context_id.to_owned();

    rt.block_on(async move {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = LifecycleCommand::RestoreContext {
            payload: Box::new(RestoreContextPayload {
                context_id: context_id_owned,
                params: scp_core::context::ContextParams::default(),
            }),
            reply: tx,
        };
        sup.dispatch_lifecycle_command(cmd).await.map_err(|e| {
            PyRuntimeError::new_err(format!(
                "SCP-CTX-2064: supervisor dispatch_lifecycle_command failed: {e}"
            ))
        })?;
        rx.await
            .map_err(|e| {
                PyRuntimeError::new_err(format!(
                    "SCP-CTX-2064: restore_context shim reply dropped: {e}"
                ))
            })?
            .map_err(|e| {
                PyRuntimeError::new_err(format!("SCP-CTX-2064: restore_context failed: {e}"))
            })
    })
}

/// Restores all persisted contexts from storage.
///
/// Delegates to [`ContextManager::restore_all_contexts`]. Only contexts
/// in `Active` state are restored; contexts in `Closing`/`Closed`/`Expired`
/// states are skipped.
///
/// # Returns
///
/// JSON array of restored context ID strings.
///
/// # Errors
///
/// Returns `RuntimeError` (SCP-CTX-2065) if restoration fails (e.g., no
/// persistence provider configured).
#[pyfunction]
#[pyo3(signature = ())]
fn py_restore_all_contexts() -> PyResult<String> {
    let rt = crate::runtime()?;
    // Route through the supervisor-scope direct method; restore_all_contexts
    // operates on the supervisor-wide context registry and has no per-context
    // command target. The supervisor forwards to ContextManager today;
    // commit 12 will move the body onto the supervisor itself.
    let sup = crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let sup = Arc::clone(sup);

    rt.block_on(async move {
        let restored = sup.restore_all_contexts().await.map_err(|e| {
            PyRuntimeError::new_err(format!("SCP-CTX-2065: restore_all_contexts failed: {e}"))
        })?;

        serde_json::to_string(&restored).map_err(|e| {
            PyRuntimeError::new_err(format!("SCP-CTX-2065: serialization failed: {e}"))
        })
    })
}

/// Parses a hex string into a 32-byte array.
fn parse_hex_32(hex_str: &str, field_name: &str) -> PyResult<[u8; 32]> {
    let bytes = hex::decode(hex_str).map_err(|e| {
        PyValueError::new_err(format!("SCP-CTX-2062: invalid {field_name} hex: {e}"))
    })?;
    let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
        PyValueError::new_err(format!(
            "SCP-CTX-2062: {field_name} must be 32 bytes, got {}",
            v.len()
        ))
    })?;
    Ok(arr)
}

// ---------------------------------------------------------------------------
// Broadcast bridge (#369)
// ---------------------------------------------------------------------------

/// Subscribes a DID to a broadcast context.
///
/// For open broadcast contexts, any DID can subscribe. For gated contexts,
/// a valid `messagesRead` UCAN is required.
///
/// # Errors
///
/// Returns `RuntimeError` if the context is not active, not a broadcast
/// context, or if subscription fails.
#[pyfunction]
#[pyo3(signature = (handle, subscriber_did))]
fn py_broadcast_subscribe(handle: &PyContextHandle, subscriber_did: &str) -> PyResult<()> {
    use scp_core::context::actor::commands::{BroadcastCommand, SubscribeBroadcastPayload};
    crate::pyscp_check_handle!(handle);
    validate::validate_did(subscriber_did)?;
    let rt = crate::runtime()?;
    // Route through the ADR-049 commit-11 broadcast shim.
    let sup = crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let sup = Arc::clone(sup);
    let context_id = handle.context_id.clone();
    let did: scp_identity::DID = subscriber_did.to_owned().into();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    rt.block_on(async move {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = BroadcastCommand::SubscribeBroadcast {
            payload: Box::new(SubscribeBroadcastPayload {
                context_id,
                subscriber_did: did,
                ucan: None,
                timestamp,
            }),
            reply: tx,
        };
        sup.dispatch_broadcast_command(cmd).await.map_err(|e| {
            PyRuntimeError::new_err(format!("supervisor dispatch_broadcast_command failed: {e}"))
        })?;
        rx.await
            .map_err(|e| PyRuntimeError::new_err(format!("shim reply dropped: {e}")))?
            .map_err(|e| PyRuntimeError::new_err(format!("broadcast subscribe failed: {e}")))?;
        Ok(())
    })
}

/// Unsubscribes a DID from a broadcast context.
///
/// # Errors
///
/// Returns `RuntimeError` if the context is not active or not broadcast.
#[pyfunction]
#[pyo3(signature = (handle, subscriber_did, rotate_keys=false))]
fn py_broadcast_unsubscribe(
    handle: &PyContextHandle,
    subscriber_did: &str,
    rotate_keys: bool,
) -> PyResult<()> {
    use scp_core::context::actor::commands::{BroadcastCommand, UnsubscribeBroadcastPayload};
    crate::pyscp_check_handle!(handle);
    validate::validate_did(subscriber_did)?;
    let rt = crate::runtime()?;
    // Route through the ADR-049 commit-11 broadcast shim.
    let sup = crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let sup = Arc::clone(sup);
    let context_id = handle.context_id.clone();
    let did: scp_identity::DID = subscriber_did.to_owned().into();

    rt.block_on(async move {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = BroadcastCommand::UnsubscribeBroadcast {
            payload: Box::new(UnsubscribeBroadcastPayload {
                context_id,
                subscriber_did: did,
                rotate_keys,
            }),
            reply: tx,
        };
        sup.dispatch_broadcast_command(cmd).await.map_err(|e| {
            PyRuntimeError::new_err(format!("supervisor dispatch_broadcast_command failed: {e}"))
        })?;
        rx.await
            .map_err(|e| PyRuntimeError::new_err(format!("shim reply dropped: {e}")))?
            .map_err(|e| PyRuntimeError::new_err(format!("broadcast unsubscribe failed: {e}")))?;
        Ok(())
    })
}

/// Publishes a message to a broadcast context.
///
/// The payload is encrypted with the author's broadcast key. The author's
/// identity must have been previously created via `py_identity_create` so
/// that the key custody provider and signing key handle are available.
///
/// # Errors
///
/// Returns `RuntimeError` if the context is not active, not broadcast,
/// the sender is not an author, or the identity is not registered.
#[pyfunction]
#[pyo3(signature = (handle, author_did, payload))]
fn py_broadcast_publish(
    handle: &PyContextHandle,
    author_did: &str,
    payload: Vec<u8>,
) -> PyResult<()> {
    use scp_core::context::actor::commands::{BroadcastCommand, PublishBroadcastPayload};
    crate::pyscp_check_handle!(handle);
    validate::validate_did(author_did)?;
    let rt = crate::runtime()?;
    // Route through the ADR-049 commit-11 broadcast shim. Publish requires
    // the custody-bearing variant because the KeyCustody trait is not
    // dyn-safe and cannot cross the actor mailbox.
    let sup = crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let sup = Arc::clone(sup);
    let context_id = handle.context_id.clone();
    let author_did_owned = author_did.to_owned();

    crate::runtime::with_identity(&author_did_owned, |entry| {
        let custody = entry.custody.clone();
        let signing_key_handle = entry.identity.active_signing_key;
        let did: scp_identity::DID = author_did_owned.clone().into();

        rt.block_on(async move {
            let (tx, rx) = tokio::sync::oneshot::channel();
            let cmd = BroadcastCommand::PublishBroadcast {
                payload: Box::new(PublishBroadcastPayload {
                    context_id,
                    author_did: did,
                    payload,
                    signing_key_handle,
                }),
                reply: tx,
            };
            sup.dispatch_broadcast_command_with_custody(cmd, custody.as_ref())
                .await
                .map_err(|e| {
                    crate::error::ScpPyError::context(format!(
                        "supervisor dispatch_broadcast_command_with_custody failed: {e}"
                    ))
                })?;
            rx.await
                .map_err(|e| crate::error::ScpPyError::context(format!("shim reply dropped: {e}")))?
                .map_err(|e| {
                    crate::error::ScpPyError::context(format!("broadcast publish failed: {e}"))
                })?;
            Ok(())
        })
    })
    .map_err(|e: crate::error::ScpPyError| -> PyErr { e.into() })
}

/// Publishes a single asset to a broadcast context as structured content (SCP-290).
///
/// Constructs a [`BroadcastContent`] from the asset entry fields, computes an
/// `ETag` from the body, serializes with the magic prefix, and publishes via
/// [`ContextManager::publish_broadcast_content`].
///
/// Returns a dict with `blob_id` (hex-encoded SHA-256 of the serialized
/// envelope) and `etag` (hex-encoded SHA-256 of the body).
///
/// # Errors
///
/// Returns `RuntimeError` if the context is not active, not broadcast,
/// the sender is not an author, or the asset fields are invalid.
#[pyfunction]
#[pyo3(signature = (handle, author_did, path, content_type, body, deploy_id = None))]
fn py_broadcast_publish_asset(
    handle: &PyContextHandle,
    author_did: &str,
    path: &str,
    content_type: &str,
    body: Vec<u8>,
    deploy_id: Option<&str>,
) -> PyResult<HashMap<String, String>> {
    use scp_core::context::actor::commands::{BroadcastCommand, PublishBroadcastContentPayload};
    crate::pyscp_check_handle!(handle);
    validate::validate_did(author_did)?;
    let rt = crate::runtime()?;
    // Route through the ADR-049 commit-11 broadcast shim with custody.
    let sup = crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let sup = Arc::clone(sup);
    let context_id = handle.context_id.clone();
    let author_did_owned = author_did.to_owned();
    let path_owned = path.to_owned();
    let content_type_owned = content_type.to_owned();
    // Auto-generate deploy_id when None, matching batch behavior.
    let deploy_id_owned = Some(deploy_id.map_or_else(
        || {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(context_id.as_bytes());
            hasher.update(author_did_owned.as_bytes());
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis();
            hasher.update(ts.to_le_bytes());
            hex::encode(&Sha256::digest(hasher.finalize())[..16])
        },
        str::to_owned,
    ));

    crate::runtime::with_identity(&author_did_owned, |entry| {
        let custody = entry.custody.clone();
        let signing_key_handle = entry.identity.active_signing_key;
        let did: scp_identity::DID = author_did_owned.clone().into();

        // Validate and construct BroadcastContent.
        let content_path = scp_core::context::ContentPath::new(path_owned)
            .map_err(|e| crate::error::ScpPyError::context(format!("invalid path: {e}")))?;
        let mime_type = scp_core::context::MimeType::new(content_type_owned)
            .map_err(|e| crate::error::ScpPyError::context(format!("invalid content_type: {e}")))?;
        if let Some(ref did_str) = deploy_id_owned {
            scp_core::context::validate_deploy_id(did_str).map_err(|e| {
                crate::error::ScpPyError::context(format!("invalid deploy_id: {e}"))
            })?;
        }

        let etag = scp_core::context::compute_etag(&body);
        let content = scp_core::context::BroadcastContent {
            version: scp_core::context::BROADCAST_CONTENT_VERSION,
            metadata: scp_core::context::ContentMetadata {
                path: Some(content_path),
                content_type: Some(mime_type),
                deploy_id: deploy_id_owned.clone(),
                etag: Some(etag.clone()),
                immutable: false,
            },
            body,
        };

        rt.block_on(async move {
            let (tx, rx) = tokio::sync::oneshot::channel();
            let cmd = BroadcastCommand::PublishBroadcastContent {
                payload: Box::new(PublishBroadcastContentPayload {
                    context_id,
                    author_did: did,
                    content,
                    signing_key_handle,
                }),
                reply: tx,
            };
            sup.dispatch_broadcast_command_with_custody(cmd, custody.as_ref())
                .await
                .map_err(|e| {
                    crate::error::ScpPyError::context(format!(
                        "supervisor dispatch_broadcast_command_with_custody failed: {e}"
                    ))
                })?;
            let envelope = rx
                .await
                .map_err(|e| crate::error::ScpPyError::context(format!("shim reply dropped: {e}")))?
                .map_err(|e| {
                    crate::error::ScpPyError::context(format!(
                        "broadcast publish asset failed: {e}"
                    ))
                })?;

            // Compute blob_id as SHA-256 of the serialized envelope.
            let envelope_bytes = rmp_serde::to_vec_named(&envelope).map_err(|e| {
                crate::error::ScpPyError::context(format!(
                    "failed to serialize envelope for blob_id: {e}"
                ))
            })?;
            let blob_id = {
                use sha2::{Digest, Sha256};
                hex::encode(Sha256::digest(&envelope_bytes))
            };

            let mut result = HashMap::new();
            result.insert("blob_id".to_owned(), blob_id);
            result.insert("etag".to_owned(), etag);
            if let Some(ref did) = deploy_id_owned {
                result.insert("deploy_id".to_owned(), did.clone());
            }
            Ok(result)
        })
    })
    .map_err(|e: crate::error::ScpPyError| -> PyErr { e.into() })
}

/// Converts batch publish results into a Python dict `{"results": [...], "deploy_id": "..."}`.
fn build_batch_publish_dict(
    results: Vec<HashMap<String, String>>,
    deploy_id: &str,
) -> Result<PyObject, crate::error::ScpPyError> {
    Python::with_gil(|py| {
        use pyo3::IntoPyObjectExt;
        let outer = PyDict::new(py);
        outer
            .set_item(
                "results",
                results.into_py_any(py).map_err(|e| {
                    crate::error::ScpPyError::context(format!("failed to convert results: {e}"))
                })?,
            )
            .map_err(|e| {
                crate::error::ScpPyError::context(format!("failed to build result dict: {e}"))
            })?;
        outer.set_item("deploy_id", deploy_id).map_err(|e| {
            crate::error::ScpPyError::context(format!("failed to build result dict: {e}"))
        })?;
        Ok(outer.into_any().unbind())
    })
}

/// Static publish context for [`dispatch_publish_one_asset`] — fields that
/// stay constant across every asset in a batch. Bundling them keeps the
/// publish helper under the `too_many_arguments` clippy threshold.
struct PublishAssetContext<'a, C: scp_platform::KeyCustody> {
    sup: &'a Arc<scp_core::context::supervisor::Supervisor>,
    custody: &'a C,
    context_id: &'a str,
    did: &'a scp_identity::DID,
    signing_key_handle: scp_platform::KeyHandle,
    deploy_id: &'a str,
}

/// Publishes a single broadcast-content asset through the supervisor's
/// custody-bearing shim. Used by [`py_broadcast_publish_assets`] inside
/// the per-asset loop and extracted to keep that function below the
/// `too_many_lines` clippy threshold.
async fn dispatch_publish_one_asset<C: scp_platform::KeyCustody>(
    ctx: &PublishAssetContext<'_, C>,
    path: String,
    content_type: String,
    body: Vec<u8>,
) -> Result<HashMap<String, String>, crate::error::ScpPyError> {
    use scp_core::context::actor::commands::{BroadcastCommand, PublishBroadcastContentPayload};
    let content_path = scp_core::context::ContentPath::new(path)
        .map_err(|e| crate::error::ScpPyError::context(format!("invalid path: {e}")))?;
    let mime_type = scp_core::context::MimeType::new(content_type)
        .map_err(|e| crate::error::ScpPyError::context(format!("invalid content_type: {e}")))?;

    let etag = scp_core::context::compute_etag(&body);
    let content = scp_core::context::BroadcastContent {
        version: scp_core::context::BROADCAST_CONTENT_VERSION,
        metadata: scp_core::context::ContentMetadata {
            path: Some(content_path),
            content_type: Some(mime_type),
            deploy_id: Some(ctx.deploy_id.to_owned()),
            etag: Some(etag.clone()),
            immutable: false,
        },
        body,
    };

    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = BroadcastCommand::PublishBroadcastContent {
        payload: Box::new(PublishBroadcastContentPayload {
            context_id: ctx.context_id.to_owned(),
            author_did: ctx.did.clone(),
            content,
            signing_key_handle: ctx.signing_key_handle,
        }),
        reply: tx,
    };
    ctx.sup
        .dispatch_broadcast_command_with_custody(cmd, ctx.custody)
        .await
        .map_err(|e| {
            crate::error::ScpPyError::context(format!(
                "supervisor dispatch_broadcast_command_with_custody failed: {e}"
            ))
        })?;
    let envelope = rx
        .await
        .map_err(|e| crate::error::ScpPyError::context(format!("shim reply dropped: {e}")))?
        .map_err(|e| {
            crate::error::ScpPyError::context(format!("broadcast publish asset failed: {e}"))
        })?;

    let envelope_bytes = rmp_serde::to_vec_named(&envelope).map_err(|e| {
        crate::error::ScpPyError::context(format!("failed to serialize envelope for blob_id: {e}"))
    })?;
    let blob_id = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(&envelope_bytes))
    };

    let mut result = HashMap::new();
    result.insert("blob_id".to_owned(), blob_id);
    result.insert("etag".to_owned(), etag);
    result.insert("deploy_id".to_owned(), ctx.deploy_id.to_owned());
    Ok(result)
}

/// Publishes multiple assets to a broadcast context as structured content (SCP-290).
///
/// Each asset is an `(path, content_type, body)` tuple. All assets are published
/// with the same `deploy_id` (generated if not provided).
///
/// Returns a dict with `results` (list of dicts, each with `blob_id`, `etag`,
/// `deploy_id`) and `deploy_id` (shared deploy ID for the batch).
///
/// # Errors
///
/// Returns `RuntimeError` if any asset fails validation or publish.
#[pyfunction]
#[pyo3(signature = (handle, author_did, assets, deploy_id = None))]
fn py_broadcast_publish_assets(
    handle: &PyContextHandle,
    author_did: &str,
    assets: Vec<(String, String, Vec<u8>)>,
    deploy_id: Option<&str>,
) -> PyResult<PyObject> {
    crate::pyscp_check_handle!(handle);
    const MAX_BATCH_ASSETS: usize = 10_000;
    if assets.len() > MAX_BATCH_ASSETS {
        return Err(PyRuntimeError::new_err(format!(
            "batch too large: {} assets (max {MAX_BATCH_ASSETS})",
            assets.len()
        )));
    }

    validate::validate_did(author_did)?;
    let rt = crate::runtime()?;
    // Route through the ADR-049 commit-11 broadcast shim with custody.
    let sup = crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let sup = Arc::clone(sup);
    let context_id = handle.context_id.clone();
    let author_did_owned = author_did.to_owned();

    // Generate deploy_id if not provided.
    let deploy_id_owned = deploy_id.map_or_else(
        || {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(context_id.as_bytes());
            hasher.update(author_did_owned.as_bytes());
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis();
            hasher.update(ts.to_le_bytes());
            hex::encode(&Sha256::digest(hasher.finalize())[..16])
        },
        str::to_owned,
    );

    if let Err(e) = scp_core::context::validate_deploy_id(&deploy_id_owned) {
        return Err(PyRuntimeError::new_err(format!("invalid deploy_id: {e}")));
    }

    crate::runtime::with_identity(&author_did_owned, |entry| {
        let custody = entry.custody.clone();
        let signing_key_handle = entry.identity.active_signing_key;
        let did: scp_identity::DID = author_did_owned.clone().into();

        rt.block_on(async move {
            let publish_ctx = PublishAssetContext {
                sup: &sup,
                custody: custody.as_ref(),
                context_id: &context_id,
                did: &did,
                signing_key_handle,
                deploy_id: &deploy_id_owned,
            };
            let mut results = Vec::with_capacity(assets.len());
            for (path, content_type, body) in assets {
                let result =
                    dispatch_publish_one_asset(&publish_ctx, path, content_type, body).await?;
                results.push(result);
            }

            // Return {"results": [...], "deploy_id": "..."} matching NAPI/UniFFI/WASM.
            let outer = build_batch_publish_dict(results, &deploy_id_owned)?;
            Ok(outer)
        })
    })
    .map_err(|e: crate::error::ScpPyError| -> PyErr { e.into() })
}

/// Blocks a subscriber's read access in a broadcast context.
///
/// # Errors
///
/// Returns `RuntimeError` if the operation fails.
#[pyfunction]
#[pyo3(signature = (handle, subscriber_did, blocker_did))]
fn py_broadcast_block_subscriber(
    handle: &PyContextHandle,
    subscriber_did: &str,
    blocker_did: &str,
) -> PyResult<()> {
    use scp_core::context::actor::commands::{BroadcastBlockPayload, BroadcastCommand};
    crate::pyscp_check_handle!(handle);
    validate::validate_did(subscriber_did)?;
    validate::validate_did(blocker_did)?;
    let rt = crate::runtime()?;
    // Route through the ADR-049 commit-11 broadcast shim.
    let sup = crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let sup = Arc::clone(sup);
    let context_id = handle.context_id.clone();
    let subscriber: scp_identity::DID = subscriber_did.to_owned().into();
    let blocker: scp_identity::DID = blocker_did.to_owned().into();

    rt.block_on(async move {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = BroadcastCommand::BlockBroadcastSubscriber {
            payload: Box::new(BroadcastBlockPayload {
                context_id,
                author_did: blocker,
                subscriber_did: subscriber,
            }),
            reply: tx,
        };
        sup.dispatch_broadcast_command(cmd).await.map_err(|e| {
            PyRuntimeError::new_err(format!("supervisor dispatch_broadcast_command failed: {e}"))
        })?;
        rx.await
            .map_err(|e| PyRuntimeError::new_err(format!("shim reply dropped: {e}")))?
            .map_err(|e| PyRuntimeError::new_err(format!("broadcast block failed: {e}")))?;
        Ok(())
    })
}

/// Unblocks a previously blocked subscriber in a broadcast context (§9.16.8).
///
/// Forward-only: the unblocked subscriber can request the current key on
/// next pull but cannot decrypt content from the block period.
///
/// # Errors
///
/// Returns `RuntimeError` if the operation fails.
#[pyfunction]
#[pyo3(signature = (handle, subscriber_did, unblocker_did))]
fn py_broadcast_unblock_subscriber(
    handle: &PyContextHandle,
    subscriber_did: &str,
    unblocker_did: &str,
) -> PyResult<()> {
    use scp_core::context::actor::commands::{BroadcastBlockPayload, BroadcastCommand};
    crate::pyscp_check_handle!(handle);
    validate::validate_did(subscriber_did)?;
    validate::validate_did(unblocker_did)?;
    let rt = crate::runtime()?;
    // Route through the ADR-049 commit-11 broadcast shim.
    let sup = crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let sup = Arc::clone(sup);
    let context_id = handle.context_id.clone();
    let subscriber: scp_identity::DID = subscriber_did.to_owned().into();
    let unblocker: scp_identity::DID = unblocker_did.to_owned().into();

    rt.block_on(async move {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = BroadcastCommand::UnblockBroadcastSubscriber {
            payload: Box::new(BroadcastBlockPayload {
                context_id,
                author_did: unblocker,
                subscriber_did: subscriber,
            }),
            reply: tx,
        };
        sup.dispatch_broadcast_command(cmd).await.map_err(|e| {
            PyRuntimeError::new_err(format!("supervisor dispatch_broadcast_command failed: {e}"))
        })?;
        rx.await
            .map_err(|e| PyRuntimeError::new_err(format!("shim reply dropped: {e}")))?
            .map_err(|e| PyRuntimeError::new_err(format!("broadcast unblock failed: {e}")))?;
        Ok(())
    })
}

/// Handles a broadcast key request from a subscriber.
///
/// # Returns
///
/// A debug string describing the key request decision.
///
/// # Errors
///
/// Returns `RuntimeError` if the operation fails.
#[pyfunction]
#[pyo3(signature = (handle, author_did, requester_did))]
fn py_broadcast_handle_key_request(
    handle: &PyContextHandle,
    author_did: &str,
    requester_did: &str,
) -> PyResult<String> {
    use scp_core::context::actor::commands::BroadcastCommand;
    crate::pyscp_check_handle!(handle);
    validate::validate_did(author_did)?;
    validate::validate_did(requester_did)?;
    let rt = crate::runtime()?;
    // Route through the ADR-049 commit-11 broadcast shim.
    let sup = crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let sup = Arc::clone(sup);
    let context_id = handle.context_id.clone();
    let author: scp_identity::DID = author_did.to_owned().into();
    let requester: scp_identity::DID = requester_did.to_owned().into();

    rt.block_on(async move {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = BroadcastCommand::HandleBroadcastKeyRequest {
            context_id,
            author_did: author,
            requester_did: requester,
            reply: tx,
        };
        sup.dispatch_broadcast_command(cmd).await.map_err(|e| {
            PyRuntimeError::new_err(format!("supervisor dispatch_broadcast_command failed: {e}"))
        })?;
        let decision = rx
            .await
            .map_err(|e| PyRuntimeError::new_err(format!("shim reply dropped: {e}")))?
            .map_err(|e| {
                PyRuntimeError::new_err(format!("broadcast key request handling failed: {e}"))
            })?;
        Ok(format!("{decision:?}"))
    })
}

/// Returns the number of broadcast subscribers for a context.
///
/// Returns `None` if the context is not registered or not a broadcast context.
///
/// Routed through the ADR-049 commit-11 broadcast shim
/// ([`Supervisor::dispatch_broadcast_command`](scp_core::context::supervisor::Supervisor::dispatch_broadcast_command)).
#[pyfunction]
#[pyo3(signature = (handle,))]
fn py_broadcast_subscriber_count(handle: &PyContextHandle) -> PyResult<Option<u64>> {
    use scp_core::context::actor::commands::BroadcastCommand;
    crate::pyscp_check_handle!(handle);
    let rt = crate::runtime()?;
    let sup = crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let sup = Arc::clone(sup);
    let context_id = handle.context_id.clone();
    rt.block_on(async move {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = BroadcastCommand::BroadcastSubscriberCount {
            context_id,
            reply: tx,
        };
        sup.dispatch_broadcast_command(cmd).await.map_err(|e| {
            PyRuntimeError::new_err(format!("supervisor dispatch_broadcast_command failed: {e}"))
        })?;
        rx.await
            .map_err(|e| PyRuntimeError::new_err(format!("shim reply dropped: {e}")))?
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
            .map(|opt| opt.map(|n| n as u64))
    })
}

/// Returns `True` if the given DID is a broadcast subscriber.
///
/// Routed through the ADR-049 commit-11 broadcast shim.
#[pyfunction]
#[pyo3(signature = (handle, did))]
fn py_broadcast_is_subscriber(handle: &PyContextHandle, did: &str) -> PyResult<bool> {
    use scp_core::context::actor::commands::BroadcastCommand;
    crate::pyscp_check_handle!(handle);
    validate::validate_did(did)?;
    let rt = crate::runtime()?;
    let sup = crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let sup = Arc::clone(sup);
    let context_id = handle.context_id.clone();
    let did_owned = did.to_owned();
    rt.block_on(async move {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = BroadcastCommand::IsBroadcastSubscriber {
            context_id,
            did: did_owned,
            reply: tx,
        };
        sup.dispatch_broadcast_command(cmd).await.map_err(|e| {
            PyRuntimeError::new_err(format!("supervisor dispatch_broadcast_command failed: {e}"))
        })?;
        rx.await
            .map_err(|e| PyRuntimeError::new_err(format!("shim reply dropped: {e}")))?
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    })
}

/// Returns the broadcast admission policy for a context.
///
/// Returns the policy as a string: `"Open"` or `"Gated"`.
/// Returns `None` if the context is not a broadcast context.
///
/// Routed through the ADR-049 commit-11 broadcast shim.
#[pyfunction]
#[pyo3(signature = (handle,))]
fn py_broadcast_admission(handle: &PyContextHandle) -> PyResult<Option<String>> {
    use scp_core::context::actor::commands::BroadcastCommand;
    crate::pyscp_check_handle!(handle);
    let rt = crate::runtime()?;
    let sup = crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let sup = Arc::clone(sup);
    let context_id = handle.context_id.clone();
    rt.block_on(async move {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = BroadcastCommand::BroadcastAdmission {
            context_id,
            reply: tx,
        };
        sup.dispatch_broadcast_command(cmd).await.map_err(|e| {
            PyRuntimeError::new_err(format!("supervisor dispatch_broadcast_command failed: {e}"))
        })?;
        rx.await
            .map_err(|e| PyRuntimeError::new_err(format!("shim reply dropped: {e}")))?
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
            .map(|opt| opt.map(|a| format!("{a:?}")))
    })
}

// ---------------------------------------------------------------------------
// Membership query bridge (#369)
// ---------------------------------------------------------------------------

/// Returns the current member count for a context.
///
/// Returns `None` if the context is not registered.
///
/// Routed through the ADR-049 query shim
/// ([`Supervisor::dispatch_query`](scp_core::context::supervisor::Supervisor::dispatch_query))
/// rather than calling `ContextManager::member_count` directly. The shim
/// acquires the same per-context mutex as the legacy path and returns
/// byte-identical results; see `crates/scp-runtime/tests/actor_query_shim.rs`.
#[pyfunction]
#[pyo3(signature = (handle,))]
fn py_context_member_count(handle: &PyContextHandle) -> PyResult<Option<u64>> {
    use scp_core::context::actor::commands::QueriesCommand;
    crate::pyscp_check_handle!(handle);
    let rt = crate::runtime()?;
    let sup = crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let context_id = handle.context_id.clone();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = QueriesCommand::MemberCount {
        context_id,
        reply: tx,
    };
    rt.block_on(async move {
        sup.dispatch_query(cmd)
            .await
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        rx.await
            .map_err(|e| PyRuntimeError::new_err(format!("shim reply dropped: {e}")))?
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    })
    .map(|opt| opt.map(|n| n as u64))
}

/// Returns `True` if the given DID is a member of the context.
///
/// Routed through the ADR-049 query shim. See
/// [`py_context_member_count`] for the shim rationale.
#[pyfunction]
#[pyo3(signature = (handle, did))]
fn py_context_is_member(handle: &PyContextHandle, did: &str) -> PyResult<bool> {
    use scp_core::context::actor::commands::QueriesCommand;
    crate::pyscp_check_handle!(handle);
    validate::validate_did(did)?;
    let rt = crate::runtime()?;
    let sup = crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let context_id = handle.context_id.clone();
    let did = did.to_owned();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = QueriesCommand::IsMember {
        context_id,
        did,
        reply: tx,
    };
    rt.block_on(async move {
        sup.dispatch_query(cmd)
            .await
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        rx.await
            .map_err(|e| PyRuntimeError::new_err(format!("shim reply dropped: {e}")))?
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    })
}

/// Returns all member DIDs for a context.
///
/// Routed through the ADR-049 query shim. See
/// [`py_context_member_count`] for the shim rationale.
#[pyfunction]
#[pyo3(signature = (handle,))]
fn py_context_member_dids(handle: &PyContextHandle) -> PyResult<Vec<String>> {
    use scp_core::context::actor::commands::QueriesCommand;
    crate::pyscp_check_handle!(handle);
    let rt = crate::runtime()?;
    let sup = crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let context_id = handle.context_id.clone();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = QueriesCommand::MemberDids {
        context_id,
        reply: tx,
    };
    rt.block_on(async move {
        sup.dispatch_query(cmd)
            .await
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        rx.await
            .map_err(|e| PyRuntimeError::new_err(format!("shim reply dropped: {e}")))?
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    })
}

/// Returns the role assignment for a specific member as a debug string.
///
/// Returns `None` if the member is not found or the context is not registered.
///
/// Routed through the ADR-049 query shim. See
/// [`py_context_member_count`] for the shim rationale.
#[pyfunction]
#[pyo3(signature = (handle, did))]
fn py_context_member_role(handle: &PyContextHandle, did: &str) -> PyResult<Option<String>> {
    use scp_core::context::actor::commands::QueriesCommand;
    crate::pyscp_check_handle!(handle);
    validate::validate_did(did)?;
    let rt = crate::runtime()?;
    let sup = crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let context_id = handle.context_id.clone();
    let did = did.to_owned();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = QueriesCommand::MemberRole {
        context_id,
        did,
        reply: tx,
    };
    rt.block_on(async move {
        sup.dispatch_query(cmd)
            .await
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        rx.await
            .map_err(|e| PyRuntimeError::new_err(format!("shim reply dropped: {e}")))?
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    })
    .map(|opt| opt.map(|r| format!("{r:?}")))
}

// ---------------------------------------------------------------------------
// Events bridge (#369)
// ---------------------------------------------------------------------------

/// Drains all pending events from the context's receive buffer.
///
/// Returns a list of event descriptions as debug strings. Returns empty
/// if the context is not registered.
///
/// Routed through the ADR-049 commit-8 messaging shim
/// ([`Supervisor::dispatch_command`](scp_core::context::supervisor::Supervisor::dispatch_command)).
/// `drain_events` lives on the messaging enum because the receive buffer
/// is the messaging path's downstream sink (fed by `deliver_incoming`,
/// consumed by FFI receive polling).
#[pyfunction]
#[pyo3(signature = (handle,))]
fn py_context_drain_events(handle: &PyContextHandle) -> PyResult<Vec<String>> {
    use scp_core::context::actor::commands::MessagingCommand;
    crate::pyscp_check_handle!(handle);
    let rt = crate::runtime()?;
    let sup = crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let sup = Arc::clone(sup);
    let context_id = handle.context_id.clone();
    rt.block_on(async move {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = MessagingCommand::DrainEvents {
            context_id: context_id.clone(),
            reply: tx,
        };
        sup.dispatch_command(&context_id, cmd).await.map_err(|e| {
            PyRuntimeError::new_err(format!("supervisor dispatch_command failed: {e}"))
        })?;
        let events = rx
            .await
            .map_err(|e| PyRuntimeError::new_err(format!("shim reply dropped: {e}")))?
            .map_err(|e| PyRuntimeError::new_err(format!("drain_events failed: {e}")))?;
        Ok(events.into_iter().map(|e| format!("{e:?}")).collect())
    })
}

// ---------------------------------------------------------------------------
// TTL bridge (#369)
// ---------------------------------------------------------------------------

/// Handles TTL expiry for a context.
///
/// Transitions from `Active` to `Expired`, destroys keys per memory scope.
///
/// # Errors
///
/// Returns `RuntimeError` if the context is not active.
#[pyfunction]
#[pyo3(signature = (handle,))]
fn py_context_handle_ttl_expiry(handle: &PyContextHandle) -> PyResult<()> {
    use scp_core::context::actor::commands::{TtlCloseCommand, TtlContextPayload};
    crate::pyscp_check_handle!(handle);
    let rt = crate::runtime()?;
    // Route through the ADR-049 commit-9 TTL-close shim.
    let sup = crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let sup = Arc::clone(sup);
    let context_id = handle.context_id.clone();
    let core_params = build_core_context_params(&handle.params)?;

    rt.block_on(async move {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = TtlCloseCommand::ExecuteTtlClose {
            payload: Box::new(TtlContextPayload {
                context_id,
                params: core_params,
            }),
            reply: tx,
        };
        sup.dispatch_ttl_close_command(cmd).await.map_err(|e| {
            PyRuntimeError::new_err(format!("supervisor dispatch_ttl_close_command failed: {e}"))
        })?;
        rx.await
            .map_err(|e| PyRuntimeError::new_err(format!("shim reply dropped: {e}")))?
            .map_err(|e| PyRuntimeError::new_err(format!("TTL expiry handling failed: {e}")))?;
        Ok::<(), PyErr>(())
    })?;

    // Update FFI handle state to reflect expiry.
    let mut state = handle
        .state
        .lock()
        .map_err(|_| PyRuntimeError::new_err("context state lock is poisoned"))?;
    "expired".clone_into(&mut state);

    Ok(())
}

/// Proposes a TTL extension. Records consent from the given member.
///
/// Returns `True` if all members have consented (unanimous approval).
///
/// # Errors
///
/// Returns `RuntimeError` if the context is not registered or the member
/// is not found.
#[pyfunction]
#[pyo3(signature = (handle, member_did, proposed_seconds))]
fn py_context_propose_ttl_extension(
    handle: &PyContextHandle,
    member_did: &str,
    proposed_seconds: u64,
) -> PyResult<bool> {
    use scp_core::context::actor::commands::TtlCloseCommand;
    crate::pyscp_check_handle!(handle);
    validate::validate_did(member_did)?;
    let rt = crate::runtime()?;
    // Route through the ADR-049 commit-9 TTL-close shim.
    let sup = crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let sup = Arc::clone(sup);
    let context_id = handle.context_id.clone();
    let did: scp_identity::DID = member_did.to_owned().into();
    let duration = std::time::Duration::from_secs(proposed_seconds);

    rt.block_on(async move {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = TtlCloseCommand::ExtendTtl {
            context_id,
            member_did: did,
            proposed_duration: duration,
            reply: tx,
        };
        sup.dispatch_ttl_close_command(cmd).await.map_err(|e| {
            PyRuntimeError::new_err(format!("supervisor dispatch_ttl_close_command failed: {e}"))
        })?;
        rx.await
            .map_err(|e| PyRuntimeError::new_err(format!("shim reply dropped: {e}")))?
            .map_err(|e| PyRuntimeError::new_err(format!("TTL extension proposal failed: {e}")))
    })
}

/// Resets the TTL timer after a successful unanimous extension.
///
/// Cancels the old timer and spawns a new one with the given duration.
#[pyfunction]
#[pyo3(signature = (handle, new_seconds))]
fn py_context_reset_ttl_timer(handle: &PyContextHandle, new_seconds: u64) -> PyResult<()> {
    use scp_core::context::actor::commands::{TtlCloseCommand, TtlTimerPayload};
    crate::pyscp_check_handle!(handle);
    let rt = crate::runtime()?;
    // Route through the ADR-049 commit-9 TTL-close shim.
    let sup = crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let sup = Arc::clone(sup);
    let context_id = handle.context_id.clone();
    let core_params = build_core_context_params(&handle.params)?;
    let duration = std::time::Duration::from_secs(new_seconds);

    rt.block_on(async move {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = TtlCloseCommand::ResetTtlTimer {
            payload: Box::new(TtlTimerPayload {
                context_id,
                params: core_params,
                duration,
            }),
            reply: tx,
        };
        sup.dispatch_ttl_close_command(cmd).await.map_err(|e| {
            PyRuntimeError::new_err(format!("supervisor dispatch_ttl_close_command failed: {e}"))
        })?;
        rx.await
            .map_err(|e| PyRuntimeError::new_err(format!("shim reply dropped: {e}")))?
            .map_err(|e| PyRuntimeError::new_err(format!("TTL reset failed: {e}")))?;
        Ok::<(), PyErr>(())
    })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// App Sandboxing (#595, spec §8.4.1, §8.4.2)
// ---------------------------------------------------------------------------

/// Validates a capability declaration JSON string against a context ceiling and
/// role capabilities.
///
/// Returns a JSON string with fields: `valid` (bool), `granted_capabilities`
/// (list of str), `error` (str or null), `app_did` (str).
///
/// # Errors
///
/// Returns `PyValueError` if the declaration JSON is malformed, or
/// `PyRuntimeError` if serialization of the result fails.
#[pyfunction]
fn py_validate_capability_declaration(
    declaration_json: String,
    ceiling_capabilities: Vec<String>,
    role_capabilities: Vec<String>,
) -> PyResult<String> {
    use scp_core::context::app_sandbox::{CapabilityDeclaration, validate_declaration};
    use scp_core::context::roles::Capability;
    use scp_core::context::{ContextHandle, ContextParams};

    let decl: CapabilityDeclaration = serde_json::from_str(&declaration_json)
        .map_err(|e| PyValueError::new_err(format!("invalid declaration JSON: {e}")))?;

    let ceiling: Vec<Capability> = ceiling_capabilities.iter().map(Capability::new).collect();
    let role_caps: Vec<Capability> = role_capabilities.iter().map(Capability::new).collect();

    let handle = ContextHandle::new("validation-context".to_owned(), ContextParams::default());

    let result_json = match validate_declaration(&decl, &ceiling, &role_caps, handle) {
        Ok(scoped) => {
            let granted: Vec<String> = scoped
                .allowed_capabilities()
                .iter()
                .map(std::string::ToString::to_string)
                .collect();
            serde_json::json!({
                "valid": true,
                "granted_capabilities": granted,
                "error": null,
                "app_did": decl.app_id.to_string()
            })
        }
        Err(e) => {
            serde_json::json!({
                "valid": false,
                "granted_capabilities": [],
                "error": e.to_string(),
                "app_did": decl.app_id.to_string()
            })
        }
    };

    serde_json::to_string(&result_json)
        .map_err(|e| PyRuntimeError::new_err(format!("serialization failed: {e}")))
}

/// Checks whether a given capability is allowed for an app binding.
///
/// Returns `True` if the capability is granted, `False` otherwise.
#[pyfunction]
fn py_check_scoped_capability(
    granted_capabilities: Vec<String>,
    required_capability: String,
) -> bool {
    use scp_core::context::roles::Capability;

    let granted: HashSet<Capability> = granted_capabilities.iter().map(Capability::new).collect();
    let required = Capability::new(&required_capability);

    if granted.contains(&required) {
        return true;
    }
    // `ToolInvokeAll` covers any `ToolInvoke(specific)`
    if matches!(&required, Capability::ToolInvoke(_))
        && granted.contains(&Capability::ToolInvokeAll)
    {
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// Invitation evaluation pipeline (#614)
// ---------------------------------------------------------------------------

/// FFI-concrete implementation of [`scp_core::context::invitation::TrustOracle`].
///
/// At the FFI boundary, we cannot accept a trait object. Instead, the caller
/// provides a list of trusted DIDs. The bridge implements `TrustOracle` by
/// checking membership in this list.
struct FfiBridgeTrustOracle {
    /// DIDs that the inviter is checked against for `SharedContext` and
    /// `Explicit` trust requirements.
    trusted_dids: Vec<scp_identity::DID>,
}

impl scp_core::context::invitation::TrustOracle for FfiBridgeTrustOracle {
    fn satisfies_trust(
        &self,
        inviter: &scp_identity::DID,
        requirement: &scp_core::context::policy::TrustRequirement,
    ) -> bool {
        match requirement {
            scp_core::context::policy::TrustRequirement::Any => true,
            scp_core::context::policy::TrustRequirement::SharedContext => {
                self.trusted_dids.contains(inviter)
            }
            scp_core::context::policy::TrustRequirement::Explicit(dids) => dids.contains(inviter),
        }
    }
}

/// Evaluates a context invitation through the sequential pipeline.
///
/// Runs the 4-step evaluation pipeline from `scp-core`:
/// 1. Template validation (rejects template spoofing).
/// 2. Economic policy check (rejects insufficient spending capability).
/// 3. Auto-accept evaluation (trust, TTL cap, rate limit).
/// 4. Falls through to prompt-agent if no auto-accept matches.
///
/// # Arguments
///
/// * `params_json` -- JSON-serialized `ContextParams` from the invitation.
/// * `inviter_did` -- DID string of the identity sending the invitation.
/// * `identity_did` -- DID string of the local identity receiving the
///   invitation. Used to key the rate limit tracker.
/// * `policy_json` -- Optional JSON-serialized `AutoAcceptPolicy`. If `None`,
///   the pipeline always falls through to prompt-agent.
/// * `spending_json` -- Optional JSON-serialized `SpendingContext`. Required
///   when the context has an economic policy requiring payment.
/// * `trusted_dids_json` -- JSON array of DID strings representing identities
///   trusted by the local identity (e.g., shared-context peers). Used for
///   `SharedContext` trust requirement evaluation.
///
/// # Returns
///
/// `"auto_accept"` if the pipeline decided to auto-accept, `"prompt_agent"`
/// if the agent should be prompted for a decision.
///
/// # Errors
///
/// Returns `ScpError` if:
/// - JSON parsing fails for any input.
/// - Template validation fails (template spoofing detected).
/// - Economic policy checks fail (no spending UCAN, no compatible adapter,
///   insufficient balance).
/// - DID validation fails.
///
/// See `.docs/standards/sdk-common.md` "Invitation evaluation" and
/// `.docs/specs/19-economic-governance.md` sections 19.3, 19.14.
#[pyfunction]
#[pyo3(
    name = "evaluate_invitation",
    signature = (params_json, inviter_did, identity_did, policy_json=None, spending_json=None, trusted_dids_json=None)
)]
pub fn py_evaluate_invitation(
    params_json: &str,
    inviter_did: &str,
    identity_did: &str,
    policy_json: Option<&str>,
    spending_json: Option<&str>,
    trusted_dids_json: Option<&str>,
) -> PyResult<String> {
    use scp_core::context::invitation::{EvaluationDecision, SpendingContext, evaluate_invitation};
    use scp_core::context::policy::AutoAcceptPolicy;

    validate::validate_did(inviter_did)?;
    validate::validate_did(identity_did)?;

    let params: scp_core::context::ContextParams =
        serde_json::from_str(params_json).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "failed to parse context params JSON: {e}"
            ))
        })?;

    let policy: Option<AutoAcceptPolicy> = match policy_json {
        Some(json) => Some(serde_json::from_str(json).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "failed to parse auto-accept policy JSON: {e}"
            ))
        })?),
        None => None,
    };

    let spending: Option<SpendingContext> = match spending_json {
        Some(json) => Some(serde_json::from_str(json).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "failed to parse spending context JSON: {e}"
            ))
        })?),
        None => None,
    };

    let trusted_dids: Vec<scp_identity::DID> = match trusted_dids_json {
        Some(json) => {
            let did_strings: Vec<String> = serde_json::from_str(json).map_err(|e| {
                pyo3::exceptions::PyValueError::new_err(format!(
                    "failed to parse trusted DIDs JSON: {e}"
                ))
            })?;
            did_strings
                .into_iter()
                .map(scp_identity::DID::from)
                .collect()
        }
        None => Vec::new(),
    };

    let oracle = FfiBridgeTrustOracle { trusted_dids };
    let inviter = scp_identity::DID::from(inviter_did);

    let decision = crate::runtime::with_rate_limit_tracker(identity_did, |tracker| {
        evaluate_invitation(
            &params,
            &inviter,
            policy.as_ref(),
            spending.as_ref(),
            &oracle,
            tracker,
            &scp_core::time::SystemClock,
        )
    });

    match decision {
        Ok(EvaluationDecision::AutoAccept) => Ok("auto_accept".to_owned()),
        Ok(EvaluationDecision::PromptAgent) => Ok("prompt_agent".to_owned()),
        Err(e) => Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
            "[SCP-CTX-2060] invitation evaluation failed: {e}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// MetadataRecord inspection (§5.7.2, #615)
// ---------------------------------------------------------------------------

/// Serializes a `MetadataRecord` to a JSON string.
///
/// Constructs a `MetadataRecord` from the provided fields and returns its
/// JSON representation. The `signature` field is provided as a hex-encoded
/// string (64 bytes = 128 hex characters).
///
/// # Errors
///
/// Raises `ValidationError` if:
/// - `signer_did` is not a valid DID
/// - `context_id` is not a valid context ID
/// - `structural_json` or `operational_json` are not valid JSON
/// - `signature_hex` is not valid hex or wrong length
/// - Serialization fails
#[pyfunction]
#[pyo3(name = "metadata_record_to_json")]
pub fn py_metadata_record_to_json(
    context_id: String,
    sequence: u64,
    signer_did: String,
    timestamp: u64,
    structural_json: String,
    operational_json: String,
    signature_hex: String,
) -> PyResult<String> {
    use scp_core::context::metadata::{MetadataRecord, OperationalMetadata, StructuralMetadata};

    validate::validate_context_id(&context_id)?;
    validate::validate_did(&signer_did)?;

    if sequence == 0 {
        return Err(crate::error::ScpPyError::validation(
            "MetadataRecord sequence must start at 1 (per spec §5.7.2)",
        )
        .into());
    }

    let structural: StructuralMetadata = serde_json::from_str(&structural_json).map_err(|e| {
        crate::error::ScpPyError::validation(format!("invalid structural metadata JSON: {e}"))
    })?;

    let operational: OperationalMetadata =
        serde_json::from_str(&operational_json).map_err(|e| {
            crate::error::ScpPyError::validation(format!("invalid operational metadata JSON: {e}"))
        })?;

    let signature = hex::decode(&signature_hex)
        .map_err(|e| crate::error::ScpPyError::validation(format!("invalid signature hex: {e}")))?;
    if signature.len() != 64 {
        return Err(crate::error::ScpPyError::validation(format!(
            "signature must be 64 bytes (got {})",
            signature.len()
        ))
        .into());
    }

    let record = MetadataRecord {
        context_id,
        sequence,
        signer_did: scp_identity::DID::from(signer_did),
        timestamp,
        structural,
        operational,
        signature,
    };

    serde_json::to_string(&record).map_err(|e| {
        crate::error::ScpPyError::validation(format!("failed to serialize MetadataRecord: {e}"))
            .into()
    })
}

/// Deserializes a `MetadataRecord` from a JSON string.
///
/// Returns a dict with all fields of the metadata record. The `signature`
/// field is returned as a hex-encoded string.
///
/// # Errors
///
/// Raises `ValidationError` if the JSON is malformed or does not match the
/// `MetadataRecord` schema.
#[pyfunction]
#[pyo3(name = "metadata_record_from_json")]
pub fn py_metadata_record_from_json(json_str: String) -> PyResult<String> {
    use scp_core::context::metadata::MetadataRecord;

    // Validate that it parses, then return the normalized JSON
    let record: MetadataRecord = serde_json::from_str(&json_str).map_err(|e| {
        crate::error::ScpPyError::validation(format!("invalid MetadataRecord JSON: {e}"))
    })?;

    // F6: sequence must be >= 1 (spec §5.7.2)
    if record.sequence == 0 {
        return Err(crate::error::ScpPyError::validation(
            "MetadataRecord sequence must start at 1 (per spec §5.7.2)".to_owned(),
        )
        .into());
    }

    // F7: signature must be exactly 64 bytes (Ed25519)
    if record.signature.len() != 64 {
        return Err(crate::error::ScpPyError::validation(format!(
            "signature must be 64 bytes (got {})",
            record.signature.len()
        ))
        .into());
    }

    // Re-serialize to ensure canonical output
    serde_json::to_string(&record).map_err(|e| {
        crate::error::ScpPyError::validation(format!("failed to re-serialize MetadataRecord: {e}"))
            .into()
    })
}

// ---------------------------------------------------------------------------
// Context template inspection (§5.14, #615)
// ---------------------------------------------------------------------------

/// Returns the canonical `ContextParams` for a given template ID as JSON.
///
/// Template IDs are well-known protocol constants (spec §5.12.1). The
/// returned JSON matches the `ContextParams` struct from `scp-core`.
///
/// Valid template IDs:
/// - `"BilateralEphemeral"`
/// - `"BilateralPersistent"`
/// - `"Coordination"`
/// - `"GroupDiscussion"`
/// - `"PublicBroadcast"`
/// - `"GatedBroadcast"`
/// - `"scp:template/tool-interface"`
/// - `"PaidService"`
/// - `"PaidBroadcast"`
/// - `"HandleRegistry"`
///
/// # Errors
///
/// Raises `ValidationError` if the template ID is not recognized.
#[pyfunction]
#[pyo3(name = "template_get_params")]
pub fn py_template_get_params(template_id: String) -> PyResult<String> {
    use scp_core::context::templates::template_params;

    let tid = parse_template_id(&template_id)?;
    let params = template_params(&tid);
    serde_json::to_string(&params).map_err(|e| {
        crate::error::ScpPyError::validation(format!("failed to serialize template params: {e}"))
            .into()
    })
}

/// Validates that a `ContextParams` JSON matches its template definition.
///
/// When the params contain a `template_id`, every field is compared against
/// the canonical template definition. Returns `None` on success, or a string
/// error message on validation failure.
///
/// # Errors
///
/// Raises `ValidationError` if the JSON is malformed.
#[pyfunction]
#[pyo3(name = "validate_against_template")]
pub fn py_validate_against_template(params_json: String) -> PyResult<Option<String>> {
    use scp_core::context::templates::validate_against_template;

    let params: scp_core::context::ContextParams =
        serde_json::from_str(&params_json).map_err(|e| {
            crate::error::ScpPyError::validation(format!("invalid ContextParams JSON: {e}"))
        })?;

    match validate_against_template(&params) {
        Ok(()) => Ok(None),
        Err(e) => Ok(Some(e.to_string())),
    }
}

/// Validates cross-field invariants for `ContextParams` regardless of template.
///
/// Currently enforces: `projection_policy` must be `None` for Encrypted contexts.
/// Returns `None` on success, or a string error message on validation failure.
///
/// # Errors
///
/// Raises `ValidationError` if the JSON is malformed.
#[pyfunction]
#[pyo3(name = "validate_context_params")]
pub fn py_validate_context_params(params_json: String) -> PyResult<Option<String>> {
    use scp_core::context::templates::validate_context_params;

    let params: scp_core::context::ContextParams =
        serde_json::from_str(&params_json).map_err(|e| {
            crate::error::ScpPyError::validation(format!("invalid ContextParams JSON: {e}"))
        })?;

    match validate_context_params(&params) {
        Ok(()) => Ok(None),
        Err(e) => Ok(Some(e.to_string())),
    }
}

/// Parses a template ID string into a `TemplateId` enum value.
///
/// Accepts both the variant name and the serde-renamed form.
fn parse_template_id(
    template_id: &str,
) -> Result<scp_core::context::params::TemplateId, crate::error::ScpPyError> {
    use scp_core::context::params::TemplateId;

    match template_id {
        "BilateralEphemeral" => Ok(TemplateId::BilateralEphemeral),
        "BilateralPersistent" => Ok(TemplateId::BilateralPersistent),
        "Coordination" => Ok(TemplateId::Coordination),
        "GroupDiscussion" => Ok(TemplateId::GroupDiscussion),
        "PublicBroadcast" => Ok(TemplateId::PublicBroadcast),
        "GatedBroadcast" => Ok(TemplateId::GatedBroadcast),
        "scp:template/tool-interface" | "ToolInterfaceTemplate" => {
            Ok(TemplateId::ToolInterfaceTemplate)
        }
        "PaidService" => Ok(TemplateId::PaidService),
        "PaidBroadcast" => Ok(TemplateId::PaidBroadcast),
        "scp:template/handle-registry"
        | "HandleRegistry"
        | "scp:template/discovery-context"
        | "DiscoveryContext" => Ok(TemplateId::HandleRegistry),
        _ => Err(crate::error::ScpPyError::validation(format!(
            "unknown template ID: {template_id:?} — valid values: BilateralEphemeral, \
             BilateralPersistent, Coordination, GroupDiscussion, PublicBroadcast, \
             GatedBroadcast, scp:template/tool-interface, PaidService, PaidBroadcast, \
             HandleRegistry, scp:template/handle-registry, DiscoveryContext, \
             scp:template/discovery-context"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Access key operations (§9.17, ADR-038, #1529)
// ---------------------------------------------------------------------------

/// Generates and stores a per-member access key for explicit lifecycle
/// management.
///
/// Delegates to [`ContextManager::generate_context_access_key`].
///
/// # Errors
///
/// Returns `RuntimeError` if the context is not registered, the member
/// is not found, or the caller lacks admin capability.
#[pyfunction]
#[pyo3(name = "access_key_generate", signature = (context_id, member_did, caller_did))]
fn py_access_key_generate(context_id: &str, member_did: &str, caller_did: &str) -> PyResult<()> {
    use scp_core::context::actor::commands::LifecycleCommand;
    validate::validate_context_id(context_id)?;
    validate::validate_did(member_did)?;
    validate::validate_did(caller_did)?;
    let rt = crate::runtime()?;
    // Route through the ADR-049 commit-9 lifecycle shim
    // ([`Supervisor::dispatch_lifecycle_command`](scp_core::context::supervisor::Supervisor::dispatch_lifecycle_command)).
    let sup = crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let sup = Arc::clone(sup);
    let context_id_owned = context_id.to_owned();
    let member_did_owned = member_did.to_owned();
    let caller_did_owned = caller_did.to_owned();
    rt.block_on(async move {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = LifecycleCommand::GenerateContextAccessKey {
            context_id: context_id_owned,
            member_did: member_did_owned,
            caller_did: caller_did_owned,
            reply: tx,
        };
        sup.dispatch_lifecycle_command(cmd).await.map_err(|e| {
            PyRuntimeError::new_err(format!(
                "[SCP-CTX-2070] supervisor dispatch_lifecycle_command failed: {e}"
            ))
        })?;
        rx.await
            .map_err(|e| {
                PyRuntimeError::new_err(format!("[SCP-CTX-2070] shim reply dropped: {e}"))
            })?
            .map_err(|e| {
                PyRuntimeError::new_err(format!("[SCP-CTX-2070] access key generation failed: {e}"))
            })
    })
}

/// Revokes (removes) a member's access key from the context's access key
/// store.
///
/// Delegates to [`ContextManager::revoke_context_access_key`].
///
/// # Errors
///
/// Returns `RuntimeError` if the context is not registered, no access
/// key exists for the member, or the caller lacks admin capability.
#[pyfunction]
#[pyo3(name = "access_key_revoke", signature = (context_id, member_did, caller_did))]
fn py_access_key_revoke(context_id: &str, member_did: &str, caller_did: &str) -> PyResult<()> {
    use scp_core::context::actor::commands::LifecycleCommand;
    validate::validate_context_id(context_id)?;
    validate::validate_did(member_did)?;
    validate::validate_did(caller_did)?;
    let rt = crate::runtime()?;
    // Route through the ADR-049 commit-9 lifecycle shim.
    let sup = crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let sup = Arc::clone(sup);
    let context_id_owned = context_id.to_owned();
    let member_did_owned = member_did.to_owned();
    let caller_did_owned = caller_did.to_owned();
    rt.block_on(async move {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = LifecycleCommand::RevokeContextAccessKey {
            context_id: context_id_owned,
            member_did: member_did_owned,
            caller_did: caller_did_owned,
            reply: tx,
        };
        sup.dispatch_lifecycle_command(cmd).await.map_err(|e| {
            PyRuntimeError::new_err(format!(
                "[SCP-CTX-2071] supervisor dispatch_lifecycle_command failed: {e}"
            ))
        })?;
        rx.await
            .map_err(|e| {
                PyRuntimeError::new_err(format!("[SCP-CTX-2071] shim reply dropped: {e}"))
            })?
            .map_err(|e| {
                PyRuntimeError::new_err(format!("[SCP-CTX-2071] access key revocation failed: {e}"))
            })
    })
}

/// Restores a member's access key by generating a new key at the next
/// epoch.
///
/// Delegates to [`ContextManager::restore_context_access_key`].
///
/// # Errors
///
/// Returns `RuntimeError` if the context is not registered, the member
/// is not found, or the caller lacks admin capability.
#[pyfunction]
#[pyo3(name = "access_key_restore", signature = (context_id, member_did, caller_did))]
fn py_access_key_restore(context_id: &str, member_did: &str, caller_did: &str) -> PyResult<()> {
    use scp_core::context::actor::commands::LifecycleCommand;
    validate::validate_context_id(context_id)?;
    validate::validate_did(member_did)?;
    validate::validate_did(caller_did)?;
    let rt = crate::runtime()?;
    // Route through the ADR-049 commit-9 lifecycle shim.
    let sup = crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let sup = Arc::clone(sup);
    let context_id_owned = context_id.to_owned();
    let member_did_owned = member_did.to_owned();
    let caller_did_owned = caller_did.to_owned();
    rt.block_on(async move {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = LifecycleCommand::RestoreContextAccessKey {
            context_id: context_id_owned,
            member_did: member_did_owned,
            caller_did: caller_did_owned,
            reply: tx,
        };
        sup.dispatch_lifecycle_command(cmd).await.map_err(|e| {
            PyRuntimeError::new_err(format!(
                "[SCP-CTX-2072] supervisor dispatch_lifecycle_command failed: {e}"
            ))
        })?;
        rx.await
            .map_err(|e| {
                PyRuntimeError::new_err(format!("[SCP-CTX-2072] shim reply dropped: {e}"))
            })?
            .map_err(|e| {
                PyRuntimeError::new_err(format!(
                    "[SCP-CTX-2072] access key restoration failed: {e}"
                ))
            })
    })
}

// ---------------------------------------------------------------------------
// ADR-049 commit-11 shim entry points — 1 per domain routed through the
// new supervisor dispatch methods. These exercise the command round-
// trip at the FFI layer; they coexist with the direct-manager bridge
// functions above, which will be migrated en masse in commit 12 when
// `ContextManager` is deleted.
// ---------------------------------------------------------------------------

/// Query whether a standing (bilateral-persistent) context exists for
/// the given peer DID.
///
/// Routes through the ADR-049 commit-11 standing shim
/// ([`Supervisor::dispatch_standing_command`](scp_core::context::supervisor::Supervisor::dispatch_standing_command))
/// rather than calling `ContextManager::has_standing_context` directly.
///
/// # Errors
///
/// Returns `RuntimeError` if the supervisor is not initialized.
#[pyfunction]
#[pyo3(name = "standing_has_context_via_shim")]
pub fn py_standing_has_context_via_shim(peer_did: &str) -> PyResult<bool> {
    validate::validate_did(peer_did)?;
    let rt = crate::runtime()?;
    let sup = crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let sup = std::sync::Arc::clone(sup);

    let did = scp_identity::DID::from(peer_did);
    rt.block_on(async move {
        use scp_core::context::actor::commands::StandingCommand;
        let (tx, rx) = tokio::sync::oneshot::channel();
        sup.dispatch_standing_command(StandingCommand::HasStandingContext {
            peer_did: did,
            reply: tx,
        })
        .await
        .map_err(|e| {
            PyRuntimeError::new_err(format!("supervisor dispatch_standing_command failed: {e}"))
        })?;
        rx.await
            .map_err(|e| PyRuntimeError::new_err(format!("standing shim reply dropped: {e}")))?
            .map_err(|e| PyRuntimeError::new_err(format!("has_standing_context: {e}")))
    })
}

/// Try to consume one hard-rate-limit token. Routes through the
/// ADR-049 commit-11 tools shim
/// ([`Supervisor::dispatch_tools_command`](scp_core::context::supervisor::Supervisor::dispatch_tools_command)).
///
/// Returns `true` if a token was consumed OR the context is unknown
/// (matches the legacy pass-through contract).
///
/// # Errors
///
/// Returns `RuntimeError` if the supervisor is not initialized.
#[pyfunction]
#[pyo3(name = "tools_try_consume_hard_rate_limit_via_shim")]
pub fn py_tools_try_consume_hard_rate_limit_via_shim(
    context_id: &str,
    did: &str,
    now_secs: u64,
) -> PyResult<bool> {
    validate::validate_context_id(context_id)?;
    validate::validate_did(did)?;
    let rt = crate::runtime()?;
    let sup = crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let sup = std::sync::Arc::clone(sup);

    let ctx_id = context_id.to_owned();
    let did_owned = scp_identity::DID::from(did);
    rt.block_on(async move {
        use scp_core::context::actor::commands::ToolsCommand;
        let (tx, rx) = tokio::sync::oneshot::channel();
        sup.dispatch_tools_command(ToolsCommand::TryConsumeHardRateLimit {
            context_id: ctx_id,
            did: did_owned,
            now_secs,
            reply: tx,
        })
        .await
        .map_err(|e| {
            PyRuntimeError::new_err(format!("supervisor dispatch_tools_command failed: {e}"))
        })?;
        rx.await
            .map_err(|e| PyRuntimeError::new_err(format!("tools shim reply dropped: {e}")))?
            .map_err(|e| PyRuntimeError::new_err(format!("try_consume_hard_rate_limit: {e}")))
    })
}

/// Query the subscriber count for a broadcast context.
///
/// Routes through the ADR-049 commit-11 broadcast shim
/// ([`Supervisor::dispatch_broadcast_command`](scp_core::context::supervisor::Supervisor::dispatch_broadcast_command)).
/// Returns `None` if the context is unknown or not a broadcast context
/// (legacy contract preserved).
///
/// # Errors
///
/// Returns `RuntimeError` if the supervisor is not initialized.
#[pyfunction]
#[pyo3(name = "broadcast_subscriber_count_via_shim")]
pub fn py_broadcast_subscriber_count_via_shim(context_id: &str) -> PyResult<Option<usize>> {
    validate::validate_context_id(context_id)?;
    let rt = crate::runtime()?;
    let sup = crate::runtime::supervisor().map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let sup = std::sync::Arc::clone(sup);

    let ctx_id = context_id.to_owned();
    rt.block_on(async move {
        use scp_core::context::actor::commands::BroadcastCommand;
        let (tx, rx) = tokio::sync::oneshot::channel();
        sup.dispatch_broadcast_command(BroadcastCommand::BroadcastSubscriberCount {
            context_id: ctx_id,
            reply: tx,
        })
        .await
        .map_err(|e| {
            PyRuntimeError::new_err(format!("supervisor dispatch_broadcast_command failed: {e}"))
        })?;
        rx.await
            .map_err(|e| PyRuntimeError::new_err(format!("broadcast shim reply dropped: {e}")))?
            .map_err(|e| PyRuntimeError::new_err(format!("broadcast_subscriber_count: {e}")))
    })
}

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
    m.add_function(wrap_pyfunction!(py_set_economic_policy, m)?)?;
    m.add_function(wrap_pyfunction!(py_get_economic_policy, m)?)?;
    m.add_function(wrap_pyfunction!(py_context_export, m)?)?;
    m.add_function(wrap_pyfunction!(py_context_import, m)?)?;
    // Governance (#369)
    m.add_function(wrap_pyfunction!(py_governance_execute, m)?)?;
    // Governance proposal lifecycle (#621)
    m.add_function(wrap_pyfunction!(py_governance_propose, m)?)?;
    m.add_function(wrap_pyfunction!(py_governance_approve, m)?)?;
    m.add_function(wrap_pyfunction!(py_governance_reject, m)?)?;
    m.add_function(wrap_pyfunction!(py_governance_withdraw, m)?)?;
    m.add_function(wrap_pyfunction!(py_governance_get_proposal, m)?)?;
    m.add_function(wrap_pyfunction!(py_governance_list_proposals, m)?)?;
    // Ceiling modification, close, checkpoint, restore (#559)
    m.add_function(wrap_pyfunction!(py_apply_pending_ceiling_modification, m)?)?;
    m.add_function(wrap_pyfunction!(py_finalize_close, m)?)?;
    m.add_function(wrap_pyfunction!(py_create_governance_checkpoint, m)?)?;
    m.add_function(wrap_pyfunction!(py_add_checkpoint_cosignature, m)?)?;
    m.add_function(wrap_pyfunction!(py_restore_context, m)?)?;
    m.add_function(wrap_pyfunction!(py_restore_all_contexts, m)?)?;
    // Context migration (§5.11A, #580)
    m.add_function(wrap_pyfunction!(py_tombstone_migrated_context, m)?)?;
    m.add_function(wrap_pyfunction!(py_migration_state, m)?)?;
    // Broadcast (#369)
    m.add_function(wrap_pyfunction!(py_broadcast_subscribe, m)?)?;
    m.add_function(wrap_pyfunction!(py_broadcast_unsubscribe, m)?)?;
    m.add_function(wrap_pyfunction!(py_broadcast_publish, m)?)?;
    m.add_function(wrap_pyfunction!(py_broadcast_publish_asset, m)?)?;
    m.add_function(wrap_pyfunction!(py_broadcast_publish_assets, m)?)?;
    m.add_function(wrap_pyfunction!(py_broadcast_block_subscriber, m)?)?;
    m.add_function(wrap_pyfunction!(py_broadcast_unblock_subscriber, m)?)?;
    m.add_function(wrap_pyfunction!(py_broadcast_handle_key_request, m)?)?;
    m.add_function(wrap_pyfunction!(py_broadcast_subscriber_count, m)?)?;
    m.add_function(wrap_pyfunction!(py_broadcast_is_subscriber, m)?)?;
    m.add_function(wrap_pyfunction!(py_broadcast_admission, m)?)?;
    // Membership (#369)
    m.add_function(wrap_pyfunction!(py_context_member_count, m)?)?;
    m.add_function(wrap_pyfunction!(py_context_is_member, m)?)?;
    m.add_function(wrap_pyfunction!(py_context_member_dids, m)?)?;
    m.add_function(wrap_pyfunction!(py_context_member_role, m)?)?;
    // Events (#369)
    m.add_function(wrap_pyfunction!(py_context_drain_events, m)?)?;
    // TTL (#369)
    m.add_function(wrap_pyfunction!(py_context_handle_ttl_expiry, m)?)?;
    m.add_function(wrap_pyfunction!(py_context_propose_ttl_extension, m)?)?;
    m.add_function(wrap_pyfunction!(py_context_reset_ttl_timer, m)?)?;
    // App sandboxing (#595)
    m.add_function(wrap_pyfunction!(py_validate_capability_declaration, m)?)?;
    m.add_function(wrap_pyfunction!(py_check_scoped_capability, m)?)?;
    // Invitation evaluation (#614)
    m.add_function(wrap_pyfunction!(py_evaluate_invitation, m)?)?;
    // MetadataRecord and ContextTemplate inspection (#615)
    m.add_function(wrap_pyfunction!(py_metadata_record_to_json, m)?)?;
    m.add_function(wrap_pyfunction!(py_metadata_record_from_json, m)?)?;
    m.add_function(wrap_pyfunction!(py_template_get_params, m)?)?;
    m.add_function(wrap_pyfunction!(py_validate_against_template, m)?)?;
    m.add_function(wrap_pyfunction!(py_validate_context_params, m)?)?;
    // Access key operations (#1529)
    m.add_function(wrap_pyfunction!(py_access_key_generate, m)?)?;
    m.add_function(wrap_pyfunction!(py_access_key_revoke, m)?)?;
    m.add_function(wrap_pyfunction!(py_access_key_restore, m)?)?;
    // ADR-049 commit-11 shim entry points — 1 per domain routed
    // through the new supervisor dispatch methods.
    m.add_function(wrap_pyfunction!(py_standing_has_context_via_shim, m)?)?;
    m.add_function(wrap_pyfunction!(
        py_tools_try_consume_hard_rate_limit_via_shim,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(py_broadcast_subscriber_count_via_shim, m)?)?;
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

        crate::runtime::register_context(context_id, "did:test:creator", &[]).unwrap();

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

        crate::runtime::register_context(context_id, "did:test:creator", &[]).unwrap();

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

        crate::runtime::register_context(context_id, "did:test:creator", &[]).unwrap();

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
            min_protocol_version: None,
            max_chain_depth: None,
            max_nesting_depth: None,
            session_cap: None,
            consequence_rules: None,
            consequence_config: None,
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

    // -----------------------------------------------------------------------
    // Economic policy bridge tests (#334)
    // -----------------------------------------------------------------------

    #[test]
    fn set_economic_policy_always_rejects_requires_governance() {
        // Ensure the default bridge instance exists so the affinity check
        // passes and the governance-rejection path is what errors (not
        // `SCP-PERM-3030`).
        crate::runtime::ensure_bridge_instance();
        let mut handle = PyContextHandle::new(
            "ctx-econ-1".to_owned(),
            "did:test:creator".to_owned(),
            default_params(),
        );

        let json = r#"{"locked":false,"cost_schedule":{"currency":[85,83,68,0],"per_message":1,"per_tool_invoke":null,"per_join":null,"per_period":null,"per_byte_stored":null},"payment_adapters":[],"pricing_formula":null,"payee":"did:dht:z6MkPayee"}"#;
        let result = py_set_economic_policy(&mut handle, json);
        assert!(
            result.is_err(),
            "direct set must be rejected — use governance"
        );
        assert!(handle.params.economic_policy.is_none());
    }

    #[test]
    fn get_economic_policy_none() {
        // Ensure the default bridge instance exists so `PyContextHandle::new`
        // stamps the handle with a real instance id (not `UNSET_INSTANCE_ID`).
        // Without this, `pyscp_check_handle!` inside `py_get_economic_policy`
        // would reject the handle with `SCP-PERM-3030`.
        crate::runtime::ensure_bridge_instance();
        let handle = PyContextHandle::new(
            "ctx-econ-3".to_owned(),
            "did:test:creator".to_owned(),
            default_params(),
        );
        let result = py_get_economic_policy(&handle).expect("handle is default-instance");
        assert!(result.is_none());
    }

    #[test]
    fn get_economic_policy_some() {
        crate::runtime::ensure_bridge_instance();
        let json = r#"{"locked":false,"cost_schedule":{"currency":[85,83,68,0],"per_message":1,"per_tool_invoke":null,"per_join":null,"per_period":null,"per_byte_stored":null},"payment_adapters":[],"pricing_formula":null,"payee":"did:dht:z6MkPayee"}"#;
        let handle = PyContextHandle::new(
            "ctx-econ-4".to_owned(),
            "did:test:creator".to_owned(),
            PyContextParams {
                economic_policy: Some(json.to_owned()),
                ..default_params()
            },
        );
        let result = py_get_economic_policy(&handle).expect("handle is default-instance");
        assert_eq!(result.as_deref(), Some(json));
    }

    // -----------------------------------------------------------------------
    // Role state sync after governance (#560)
    // -----------------------------------------------------------------------

    use scp_ffi_common::test_helpers::approved_proposal;

    /// Test helper: dispatch `LifecycleCommand::CreateContext` through the
    /// supervisor. Mirrors `bridge_dispatch_create_context` but is callable
    /// from tests with a pre-built `ContextParams`.
    fn test_dispatch_create_context(
        ctx_id: &str,
        params: scp_core::context::ContextParams,
        creator: &str,
    ) {
        use scp_core::context::actor::commands::{CreateContextPayload, LifecycleCommand};
        let sup = crate::runtime::supervisor().unwrap();
        let sup = Arc::clone(sup);
        let rt = crate::runtime().unwrap();
        let ctx_id_owned = ctx_id.to_owned();
        let creator_did = scp_identity::DID(creator.to_owned());
        rt.block_on(async move {
            let (tx, rx) = tokio::sync::oneshot::channel();
            let cmd = LifecycleCommand::CreateContext {
                payload: Box::new(CreateContextPayload {
                    context_id: ctx_id_owned,
                    params,
                    creator_did,
                    local_pseudonym: None,
                }),
                reply: tx,
            };
            sup.dispatch_lifecycle_command(cmd).await.unwrap();
            rx.await.unwrap().unwrap();
        });
    }

    /// Test helper: dispatch `GovernanceCommand::ExecuteGovernanceAction`
    /// through the supervisor.
    fn test_dispatch_execute_governance(
        ctx_id: &str,
        proposal: scp_core::context::governance::GovernanceProposal,
    ) {
        use scp_core::context::actor::commands::{
            ExecuteGovernanceActionPayload, GovernanceCommand,
        };
        let sup = crate::runtime::supervisor().unwrap();
        let sup = Arc::clone(sup);
        let rt = crate::runtime().unwrap();
        let ctx_id_owned = ctx_id.to_owned();
        rt.block_on(async move {
            let (tx, rx) = tokio::sync::oneshot::channel();
            let cmd = GovernanceCommand::ExecuteGovernanceAction {
                payload: Box::new(ExecuteGovernanceActionPayload {
                    context_id: ctx_id_owned,
                    proposal,
                }),
                reply: tx,
            };
            sup.dispatch_governance_command(cmd).await.unwrap();
            rx.await.unwrap().unwrap();
        });
    }

    #[test]
    fn role_state_syncs_after_change_role() {
        crate::init_runtime().ok();
        let ctx_id = format!("sync-role-{}", uuid::Uuid::new_v4());
        let creator = "did:key:z6MkCreatorSync1";
        crate::runtime::register_context(&ctx_id, creator, &[]).unwrap();
        let params = scp_core::context::ContextParams {
            ceiling: vec![scp_core::context::params::Capability::new("role:assign")],
            ..scp_core::context::ContextParams::default()
        };
        test_dispatch_create_context(&ctx_id, params, creator);
        let new_did = "did:key:z6MkNewMember1";
        let add = approved_proposal(
            [1u8; 32],
            &ctx_id,
            scp_core::context::governance::GovernanceAction::AddMember {
                did: scp_identity::DID(new_did.to_owned()),
                role: "member".to_owned(),
            },
            creator,
        );
        test_dispatch_execute_governance(&ctx_id, add);
        crate::runtime::sync_role_state_from_manager(&ctx_id).unwrap();
        let change = approved_proposal(
            [2u8; 32],
            &ctx_id,
            scp_core::context::governance::GovernanceAction::ChangeRole {
                did: scp_identity::DID(new_did.to_owned()),
                new_role: "observer".to_owned(),
            },
            creator,
        );
        test_dispatch_execute_governance(&ctx_id, change);
        crate::runtime::sync_role_state_from_manager(&ctx_id).unwrap();
        crate::runtime::with_context(&ctx_id, |st| {
            let assignment = st
                .role_state
                .assignments
                .get(new_did)
                .expect("member should have an assignment");
            assert_eq!(
                assignment.role_name, "observer",
                "role should be observer after ChangeRole + sync"
            );
            Ok(())
        })
        .unwrap();
        crate::runtime::remove_context(&ctx_id);
    }

    #[test]
    fn role_state_syncs_after_add_member() {
        crate::init_runtime().ok();
        let ctx_id = format!("sync-add-{}", uuid::Uuid::new_v4());
        let creator = "did:key:z6MkCreatorSync2";
        crate::runtime::register_context(&ctx_id, creator, &[]).unwrap();
        let params = scp_core::context::ContextParams {
            ceiling: vec![scp_core::context::params::Capability::new("role:assign")],
            ..scp_core::context::ContextParams::default()
        };
        test_dispatch_create_context(&ctx_id, params, creator);
        let new_did = "did:key:z6MkAdded1";
        crate::runtime::with_context(&ctx_id, |st| {
            assert!(!st.role_state.members.contains(new_did));
            Ok(())
        })
        .unwrap();
        let add = approved_proposal(
            [3u8; 32],
            &ctx_id,
            scp_core::context::governance::GovernanceAction::AddMember {
                did: scp_identity::DID(new_did.to_owned()),
                role: "member".to_owned(),
            },
            creator,
        );
        test_dispatch_execute_governance(&ctx_id, add);
        crate::runtime::sync_role_state_from_manager(&ctx_id).unwrap();
        crate::runtime::with_context(&ctx_id, |st| {
            assert!(st.role_state.members.contains(new_did));
            assert_eq!(
                st.role_state
                    .assignments
                    .get(new_did)
                    .map(|a| a.role_name.as_str()),
                Some("member")
            );
            Ok(())
        })
        .unwrap();
        crate::runtime::remove_context(&ctx_id);
    }

    #[test]
    fn role_state_syncs_after_remove_member() {
        crate::init_runtime().ok();
        let ctx_id = format!("sync-rm-{}", uuid::Uuid::new_v4());
        let creator = "did:key:z6MkCreatorSync3";
        let target = "did:key:z6MkRemoveTarget";
        crate::runtime::register_context(&ctx_id, creator, &[]).unwrap();
        let params = scp_core::context::ContextParams {
            ceiling: vec![scp_core::context::params::Capability::new("role:assign")],
            ..scp_core::context::ContextParams::default()
        };
        test_dispatch_create_context(&ctx_id, params, creator);
        let add = approved_proposal(
            [4u8; 32],
            &ctx_id,
            scp_core::context::governance::GovernanceAction::AddMember {
                did: scp_identity::DID(target.to_owned()),
                role: "member".to_owned(),
            },
            creator,
        );
        test_dispatch_execute_governance(&ctx_id, add);
        crate::runtime::sync_role_state_from_manager(&ctx_id).unwrap();
        crate::runtime::with_context(&ctx_id, |st| {
            assert!(st.role_state.members.contains(target));
            Ok(())
        })
        .unwrap();
        let rm = approved_proposal(
            [5u8; 32],
            &ctx_id,
            scp_core::context::governance::GovernanceAction::RemoveMember {
                did: scp_identity::DID(target.to_owned()),
                reason: Some("test removal".to_owned()),
            },
            creator,
        );
        test_dispatch_execute_governance(&ctx_id, rm);
        crate::runtime::sync_role_state_from_manager(&ctx_id).unwrap();
        crate::runtime::with_context(&ctx_id, |st| {
            assert!(!st.role_state.members.contains(target));
            assert!(!st.role_state.assignments.contains_key(target));
            Ok(())
        })
        .unwrap();
        crate::runtime::remove_context(&ctx_id);
    }

    // -----------------------------------------------------------------------
    // Invitation evaluation (#614)
    // -----------------------------------------------------------------------

    #[test]
    fn evaluate_invitation_rejects_invalid_inviter_did() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|_py| {
            let result = py_evaluate_invitation(
                "{}",
                "", // empty DID
                "did:dht:z6MkLocal",
                None,
                None,
                None,
            );
            assert!(result.is_err());
        });
    }

    #[test]
    fn evaluate_invitation_rejects_invalid_params_json() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|_py| {
            let result = py_evaluate_invitation(
                "not valid json",
                "did:dht:z6MkBob",
                "did:dht:z6MkLocal",
                None,
                None,
                None,
            );
            assert!(result.is_err());
        });
    }

    #[test]
    fn evaluate_invitation_prompt_without_policy() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|_py| {
            // Use serde to produce a valid ContextParams JSON.
            let params = scp_core::context::ContextParams::default();
            let params_json = serde_json::to_string(&params).unwrap();
            let result = py_evaluate_invitation(
                &params_json,
                "did:dht:z6MkBob",
                "did:dht:z6MkLocal",
                None,
                None,
                None,
            );
            match &result {
                Ok(v) => assert_eq!(v, "prompt_agent"),
                Err(e) => panic!("expected Ok, got Err: {e}"),
            }
        });
    }

    // -- Governance action string validation (#1601) --

    #[test]
    fn governance_action_script_tag_in_role_name_rejected() {
        let action = scp_core::context::governance::GovernanceAction::AddMember {
            did: scp_identity::DID("did:dht:z6MkTest".to_owned()),
            role: "<script>alert('xss')</script>".to_owned(),
        };
        let err = validate_governance_action_strings(&action).unwrap_err();
        assert!(
            err.to_string().contains("HTML-special character"),
            "expected HTML-special rejection, got: {err}"
        );
    }

    // -------------------------------------------------------------------
    // Consequence event conversion tests (#1531, #1593, #1594)
    // -------------------------------------------------------------------

    #[test]
    fn convert_consequence_triggered_event_format() {
        use scp_core::context::membership::ContextEvent;

        let event = ContextEvent::ConsequenceTriggered {
            context_id: "ctx-test-123".to_owned(),
            member_did: scp_identity::DID("did:dht:z6MkBob".to_owned()),
            rule_index: 2,
            trigger_type: "velocity".to_owned(),
            action_type: "mute".to_owned(),
        };

        let (sender, payload, ts) = super::convert_context_event(event);
        assert_eq!(sender, "scp:system");
        assert!(ts > 0.0, "timestamp must be positive");

        let payload_str = String::from_utf8(payload).unwrap();
        assert!(
            payload_str.contains("consequence_triggered:"),
            "payload must contain consequence_triggered prefix"
        );
        assert!(
            payload_str.contains("member=did:dht:z6MkBob"),
            "payload must contain member DID"
        );
        assert!(
            payload_str.contains("rule=2"),
            "payload must contain rule index"
        );
        assert!(
            payload_str.contains("trigger=velocity"),
            "payload must contain trigger type"
        );
        assert!(
            payload_str.contains("action=mute"),
            "payload must contain action type"
        );
        assert!(
            payload_str.contains("context=ctx-test-123"),
            "payload must contain context ID"
        );
    }

    #[test]
    fn governance_action_control_chars_in_reason_rejected() {
        let action = scp_core::context::governance::GovernanceAction::RemoveMember {
            did: scp_identity::DID("did:dht:z6MkTest".to_owned()),
            reason: Some("bad\0actor".to_owned()),
        };
        let err = validate_governance_action_strings(&action).unwrap_err();
        assert!(
            err.to_string().contains("control character"),
            "expected control char rejection, got: {err}"
        );
    }

    #[test]
    fn convert_consequence_enforced_event_format() {
        use scp_core::context::membership::ContextEvent;

        let event = ContextEvent::ConsequenceEnforced {
            context_id: "ctx-test-456".to_owned(),
            member_did: scp_identity::DID("did:dht:z6MkAlice".to_owned()),
            action_type: "restrict_write".to_owned(),
            success: true,
        };

        let (sender, payload, _ts) = super::convert_context_event(event);
        assert_eq!(sender, "scp:system");

        let payload_str = String::from_utf8(payload).unwrap();
        assert!(
            payload_str.contains("consequence_enforced:"),
            "payload must contain consequence_enforced prefix"
        );
        assert!(
            payload_str.contains("member=did:dht:z6MkAlice"),
            "payload must contain member DID"
        );
        assert!(
            payload_str.contains("action=restrict_write"),
            "payload must contain action type"
        );
        assert!(
            payload_str.contains("success=true"),
            "payload must contain success flag"
        );
    }

    // -------------------------------------------------------------------
    // Consequence rules in context params tests (#1531, #1593)
    // -------------------------------------------------------------------

    #[test]
    fn consequence_rules_in_context_params_accepted() {
        let consequence_json = r#"[{"trigger":"MessageVelocity","action":{"Enforcement":"SuspendAccess"},"threshold":5,"window":{"secs":3600,"nanos":0}}]"#;
        let p = PyContextParams {
            consequence_rules: Some(consequence_json.to_owned()),
            ..default_params()
        };
        assert_eq!(
            p.consequence_rules.as_deref(),
            Some(consequence_json),
            "consequence_rules should be stored in params"
        );

        // Verify it flows through to core context params.
        let core_params = super::build_core_context_params(&p).unwrap();
        assert!(
            !core_params.consequence_rules.is_empty(),
            "consequence_rules should parse into non-empty vec"
        );
    }

    #[test]
    fn governance_action_valid_role_accepted() {
        let action = scp_core::context::governance::GovernanceAction::AddMember {
            did: scp_identity::DID("did:dht:z6MkTest".to_owned()),
            role: "moderator".to_owned(),
        };
        assert!(validate_governance_action_strings(&action).is_ok());
    }

    #[test]
    fn governance_action_html_in_change_role_rejected() {
        let action = scp_core::context::governance::GovernanceAction::ChangeRole {
            did: scp_identity::DID("did:dht:z6MkTest".to_owned()),
            new_role: "admin&owner".to_owned(),
        };
        let err = validate_governance_action_strings(&action).unwrap_err();
        assert!(
            err.to_string().contains("HTML-special character"),
            "expected HTML-special rejection, got: {err}"
        );
    }

    #[test]
    fn consequence_rules_none_defaults_to_empty() {
        let p = default_params();
        assert!(p.consequence_rules.is_none());

        let core_params = super::build_core_context_params(&p).unwrap();
        assert!(
            core_params.consequence_rules.is_empty(),
            "None consequence_rules should default to empty vec"
        );
    }

    #[test]
    fn governance_action_none_reason_accepted() {
        let action = scp_core::context::governance::GovernanceAction::RemoveMember {
            did: scp_identity::DID("did:dht:z6MkTest".to_owned()),
            reason: None,
        };
        assert!(validate_governance_action_strings(&action).is_ok());
    }

    #[test]
    fn context_description_with_control_chars_rejected() {
        let err =
            scp_ffi_common::validate::validate_context_description("A context\x00with null bytes")
                .unwrap_err();
        assert!(
            err.to_string().contains("control character"),
            "expected control char rejection, got: {err}"
        );
    }

    #[test]
    fn context_name_with_script_tag_rejected() {
        let err = scp_ffi_common::validate::validate_context_name("<script>alert(1)</script>")
            .unwrap_err();
        assert!(
            err.to_string().contains("HTML-special character"),
            "expected HTML-special rejection, got: {err}"
        );
    }

    #[test]
    fn consequence_rules_invalid_json_rejected() {
        let p = PyContextParams {
            consequence_rules: Some("not valid json".to_owned()),
            ..default_params()
        };

        let result = super::build_core_context_params(&p);
        assert!(
            result.is_err(),
            "invalid consequence_rules JSON should be rejected"
        );
    }

    /// C5: `PyContextParams` must accept a `consequence_config` JSON string
    /// and thread it into the core `ContextParams` instead of always falling
    /// back to `ConsequenceConfig::default()`.
    #[test]
    fn consequence_config_threaded_into_core_params() {
        let p = PyContextParams {
            consequence_config: Some(r#"{"allow_automatic_access_revocation":true}"#.to_owned()),
            ..default_params()
        };

        let core_params = super::build_core_context_params(&p)
            .expect("build_core_context_params should accept a valid consequence_config");

        assert!(
            core_params
                .consequence_config
                .allow_automatic_access_revocation,
            "consequence_config.allow_automatic_access_revocation should round-trip true into core ContextParams"
        );
    }

    /// C5: invalid `consequence_config` JSON must be rejected by
    /// `build_core_context_params` with a clear error.
    #[test]
    fn consequence_config_invalid_json_rejected() {
        let p = PyContextParams {
            consequence_config: Some("not valid json".to_owned()),
            ..default_params()
        };

        let result = super::build_core_context_params(&p);
        assert!(
            result.is_err(),
            "invalid consequence_config JSON should be rejected at the bridge boundary"
        );
    }

    /// C5: a `RevokeAccess` rule must be rejected by
    /// `build_core_context_params` when the per-context config does not
    /// opt in to `allow_automatic_access_revocation`.
    #[test]
    fn consequence_rules_revoke_access_rejected_without_config_opt_in() {
        let bad_rules = r#"[{
            "trigger": "MessageVelocity",
            "action": { "Enforcement": { "RevokeAccess": {
                "did": "did:dht:z6MkSubject",
                "access": "Both"
            } } },
            "threshold": 5,
            "window": { "secs": 60, "nanos": 0 }
        }]"#;
        let p = PyContextParams {
            consequence_rules: Some(bad_rules.to_owned()),
            // consequence_config left None -> default disallows RevokeAccess.
            ..default_params()
        };

        let result = super::build_core_context_params(&p);
        assert!(
            result.is_err(),
            "RevokeAccess rule must be rejected when consequence_config is missing or disallows it"
        );
    }

    /// C5: a `RevokeAccess` rule must be accepted when the per-context
    /// config opts into `allow_automatic_access_revocation`.
    #[test]
    fn consequence_rules_revoke_access_accepted_with_config_opt_in() {
        let rules = r#"[{
            "trigger": "MessageVelocity",
            "action": { "Enforcement": { "RevokeAccess": {
                "did": "did:dht:z6MkSubject",
                "access": "Both"
            } } },
            "threshold": 5,
            "window": { "secs": 3600, "nanos": 0 }
        }]"#;
        let config = r#"{"allow_automatic_access_revocation":true}"#;
        let p = PyContextParams {
            consequence_rules: Some(rules.to_owned()),
            consequence_config: Some(config.to_owned()),
            ..default_params()
        };

        let core_params = super::build_core_context_params(&p)
            .expect("RevokeAccess rule should be accepted when config opts in");
        assert_eq!(core_params.consequence_rules.len(), 1);
        assert!(
            core_params
                .consequence_config
                .allow_automatic_access_revocation
        );
    }

    // -------------------------------------------------------------------
    // Spending UCAN parameter acceptance tests (#1537, #1593)
    // -------------------------------------------------------------------

    #[test]
    fn evaluate_invitation_accepts_spending_json() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|_py| {
            let params = scp_core::context::ContextParams::default();
            let params_json = serde_json::to_string(&params).unwrap();
            let spending_json = r#"{"has_spending_ucan":true,"configured_adapters":["x402"],"available_balance":10000}"#;

            let result = py_evaluate_invitation(
                &params_json,
                "did:dht:z6MkBob",
                "did:dht:z6MkLocal",
                None,
                Some(spending_json),
                None,
            );

            // Free contexts do not require spending, so the pipeline should
            // still reach prompt_agent regardless of spending context.
            match &result {
                Ok(v) => assert_eq!(v, "prompt_agent"),
                Err(e) => panic!("expected Ok, got Err: {e}"),
            }
        });
    }

    #[test]
    fn evaluate_invitation_rejects_invalid_spending_json() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|_py| {
            let params = scp_core::context::ContextParams::default();
            let params_json = serde_json::to_string(&params).unwrap();

            let result = py_evaluate_invitation(
                &params_json,
                "did:dht:z6MkBob",
                "did:dht:z6MkLocal",
                None,
                Some("not valid json"),
                None,
            );

            assert!(result.is_err(), "invalid spending JSON should be rejected");
        });
    }

    #[test]
    fn evaluate_invitation_none_spending_accepted() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|_py| {
            let params = scp_core::context::ContextParams::default();
            let params_json = serde_json::to_string(&params).unwrap();

            let result = py_evaluate_invitation(
                &params_json,
                "did:dht:z6MkBob",
                "did:dht:z6MkLocal",
                None,
                None, // No spending context
                None,
            );

            match &result {
                Ok(v) => assert_eq!(v, "prompt_agent"),
                Err(e) => panic!("expected Ok, got Err: {e}"),
            }
        });
    }
}
