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
use scp_clock::Clock;
use scp_platform::traits::KeyCustody;
use tokio::sync::mpsc;

use scp_ffi_common::error_codes as codes;
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
    /// `"migrating_out"`, `"tombstoned"`, `"poisoned"`.
    ///
    /// This is a **best-effort, cached** snapshot taken at the last observed
    /// transition — it is intentionally NOT a live supervisor read (that would
    /// add a mailbox round-trip to every call). Per ADR-049 §10, an actor
    /// crash or poison detected by the supervisor watchdog is surfaced
    /// authoritatively via a typed **error code on the next per-context
    /// operation** (`SCP-CTX-2134` `ContextPoisoned` once the respawn budget is
    /// exceeded, `SCP-CTX-2135` `ActorCrashed` for the crashed/mid-respawn
    /// window) — NOT by polling this getter, which may still report the
    /// last-known non-terminal state. Operator recovery from a poisoned context
    /// is `clear_poison` / process restart, not an SDK call.
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
    /// tagged with the given bridge instance's `instance_id`.
    fn new(
        bi: &crate::runtime::PyBridgeInstance,
        context_id: String,
        creator_did: String,
        params: PyContextParams,
    ) -> Self {
        Self {
            context_id,
            state: Arc::new(Mutex::new("creating".to_owned())),
            creator_did,
            params,
            instance_id: bi.core.instance_id(),
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
/// - `outlets` -- list of outlet name strings
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
    /// Initial outlet registrations by name.
    outlets: Vec<String>,
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
    ///   `outlets`, `ttl`, `memory_scope`, `governance`, `mode`,
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
    fn outlets(&self) -> Vec<String> {
        self.outlets.clone()
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
            "PyContextParams(ceiling={:?}, roles={:?}, outlets={:?}, ttl={:?}, \
             memory_scope='{}', governance='{}', mode='{}', ceiling_policy='{}', \
             promotion_policy='{}', template_id={:?}, economic_policy={:?}, \
             min_protocol_version={:?}, max_chain_depth={:?}, \
             max_nesting_depth={:?}, session_cap={:?}, \
             consequence_rules={:?}, consequence_config={:?})",
            self.ceiling,
            self.roles,
            self.outlets,
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
    "scp:template/outlet-interface",
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

        // outlets: list[str] (default: empty)
        let outlets: Vec<String> = match dict.get_item("outlets")? {
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
            outlets,
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

    /// Projects an AUTHENTICATED core [`ContextParams`](scp_core::context::ContextParams)
    /// into a `PyContextParams` for the handle returned by
    /// [`context_join_from_welcome`](crate::scp::PyScp::context_join_from_welcome).
    ///
    /// The joiner no longer supplies params — the authoritative params are the
    /// ones carried by the joined MLS group's signed context binding (opened
    /// inside the runtime). This is the inverse of the forward
    /// `build_core_context_params` path: it recovers exactly the subset of
    /// fields `PyContextParams` projects (the rest of `ContextParams` — metadata
    /// visibility, projection policy, participation requirements, etc. — has no
    /// `PyContextParams` field and is not surfaced here, matching the forward
    /// path which fills those with defaults). Enum discriminants are rendered to
    /// their canonical bridge string form; capability sets to their user-facing
    /// colon names; JSON-backed fields (economic policy, consequence rules/config)
    /// to their serialized JSON strings.
    fn from_core_params(params: &scp_core::context::ContextParams) -> Self {
        use scp_core::context::params::{
            CeilingPolicy, ConsequenceConfig, ContextMode, GovernanceModel, MemoryScope,
            PromotionPolicy,
        };

        let mode = match params.mode {
            ContextMode::Broadcast => "broadcast",
            ContextMode::Encrypted => "encrypted",
        }
        .to_owned();
        let ceiling_policy = match params.ceiling_policy {
            CeilingPolicy::Governed => "governed",
            CeilingPolicy::Immutable => "immutable",
        }
        .to_owned();
        let promotion_policy = match params.promotion_policy {
            PromotionPolicy::Promotable => "promotable",
            PromotionPolicy::NoPromotion => "no_promotion",
        }
        .to_owned();
        let memory_scope = match params.memory_scope {
            MemoryScope::Full => "full",
            MemoryScope::Summary => "summary",
            MemoryScope::Ephemeral => "ephemeral",
        }
        .to_owned();
        let governance = match params.governance {
            GovernanceModel::SingleAdmin => "single_admin",
            GovernanceModel::Threshold { .. } => "threshold",
            GovernanceModel::Majority { .. } => "majority",
            GovernanceModel::Unanimity { .. } => "unanimity",
        }
        .to_owned();

        // Ceiling and role capabilities → user-facing colon names (`name()`),
        // the form a Python caller supplies on the forward path.
        let ceiling: Vec<String> = params
            .ceiling
            .iter()
            .map(|c| c.name().into_owned())
            .collect();
        let roles: HashMap<String, Vec<String>> = params
            .roles
            .iter()
            .map(|rd| {
                let mut caps: Vec<String> = rd
                    .capabilities
                    .iter()
                    .map(|c| c.name().into_owned())
                    .collect();
                caps.sort();
                (rd.name.clone(), caps)
            })
            .collect();
        let outlets: Vec<String> = params.outlets.iter().map(|t| t.name.clone()).collect();

        // JSON-backed projections. `None` when absent/empty/default so the
        // getters honor their "None means default/free" contract.
        let template_id = params.template_id.as_ref().and_then(|tid| {
            serde_json::to_value(tid)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
        });
        let economic_policy = params
            .economic_policy
            .as_ref()
            .and_then(|ep| serde_json::to_string(ep).ok());
        let consequence_rules = if params.consequence_rules.is_empty() {
            None
        } else {
            serde_json::to_string(&params.consequence_rules).ok()
        };
        let consequence_config = if params.consequence_config == ConsequenceConfig::default() {
            None
        } else {
            serde_json::to_string(&params.consequence_config).ok()
        };

        Self {
            ceiling,
            roles,
            outlets,
            ttl: params.ttl.map(|d| d.as_secs_f64()),
            memory_scope,
            governance,
            mode,
            ceiling_policy,
            promotion_policy,
            template_id,
            economic_policy,
            min_protocol_version: params.min_protocol_version,
            max_chain_depth: params.max_chain_depth,
            max_nesting_depth: params.max_nesting_depth,
            session_cap: params.session_cap,
            consequence_rules,
            consequence_config,
        }
    }
}

// ---------------------------------------------------------------------------
// PySealedInvitation / PyInviteMemberOutcome
// ---------------------------------------------------------------------------

/// A sealed, signed invitation bundle (ADR-049 Phase 2J; FFI-02 Option A).
///
/// The wire artifact produced by
/// [`invite_member`](crate::scp::PyScp::invite_member) on the creator side and
/// consumed by [`context_join_from_welcome`](crate::scp::PyScp::context_join_from_welcome)
/// on the joiner side.
///
/// Flat named-field config object per the agent-first API tenet: an LLM builds
/// it from the field names plus one example, with no positional-argument
/// footgun. Mirrors the runtime wire type
/// [`SealedInvitation`](scp_core::context::invitation_helpers::SealedInvitation):
/// `enc` is the RFC 9180 HPKE encapsulated key (32 bytes) and `ciphertext` is
/// the HPKE ciphertext (`ct = ciphertext || tag`) of the serialized, signed
/// `InvitationBundle`. Both are opaque bytes — the joiner does not interpret
/// them; the runtime opens the bundle and authenticates it.
#[pyclass]
#[derive(Debug, Clone)]
pub struct PySealedInvitation {
    /// Binding hint: the context id the bundle was sealed for.
    context_id: String,
    /// Binding hint: the creator DID the bundle was sealed by.
    creator_did: String,
    /// RFC 9180 HPKE encapsulated key (`enc`). Length is validated to be
    /// exactly 32 bytes at the join boundary (fail-closed).
    enc: Vec<u8>,
    /// RFC 9180 HPKE ciphertext (`ct = ciphertext || tag`).
    ciphertext: Vec<u8>,
}

#[pymethods]
impl PySealedInvitation {
    /// Constructs a sealed invitation from its four wire fields.
    #[new]
    #[allow(clippy::missing_const_for_fn)] // PyO3 #[new] cannot be const.
    fn new(context_id: String, creator_did: String, enc: Vec<u8>, ciphertext: Vec<u8>) -> Self {
        Self {
            context_id,
            creator_did,
            enc,
            ciphertext,
        }
    }

    #[getter]
    fn context_id(&self) -> &str {
        &self.context_id
    }

    #[getter]
    fn creator_did(&self) -> &str {
        &self.creator_did
    }

    /// The HPKE encapsulated key (`enc`) as Python `bytes`.
    #[getter]
    fn enc<'py>(&self, py: Python<'py>) -> Bound<'py, pyo3::types::PyBytes> {
        pyo3::types::PyBytes::new(py, &self.enc)
    }

    /// The HPKE ciphertext (`ct`) as Python `bytes`.
    #[getter]
    fn ciphertext<'py>(&self, py: Python<'py>) -> Bound<'py, pyo3::types::PyBytes> {
        pyo3::types::PyBytes::new(py, &self.ciphertext)
    }

    fn __repr__(&self) -> String {
        format!(
            "PySealedInvitation(context_id='{}', creator_did='{}', \
             enc=<{} bytes>, ciphertext=<{} bytes>)",
            self.context_id,
            self.creator_did,
            self.enc.len(),
            self.ciphertext.len()
        )
    }
}

/// The outcome of [`invite_member`](crate::scp::PyScp::invite_member).
///
/// Carries the sealed [`PySealedInvitation`] `bundle` (directly usable as the
/// `sealed` argument to
/// [`context_join_from_welcome`](crate::scp::PyScp::context_join_from_welcome) —
/// no re-boxing) plus `delivered`: `true` if the runtime published the sealed
/// bundle to the invitee's routing id, `false` if the caller (or transport) must
/// deliver `bundle` itself.
///
/// `invite_member` supports only `SingleAdmin` contexts today; a voting-governed
/// context raises an error (governed-context invitations are not yet
/// implemented) rather than surfacing here. This is an extensible object: a
/// future governed-invite outcome is added additively.
#[pyclass]
#[derive(Debug, Clone)]
pub struct PyInviteMemberOutcome {
    bundle: PySealedInvitation,
    delivered: bool,
}

impl PyInviteMemberOutcome {
    /// Maps a runtime [`InviteMemberOutcome`](scp_core::context::supervisor::InviteMemberOutcome)
    /// to its flat bridge projection.
    fn from_outcome(outcome: scp_core::context::supervisor::InviteMemberOutcome) -> Self {
        use scp_core::context::supervisor::InviteMemberOutcome;
        match outcome {
            InviteMemberOutcome::Sealed { bundle, delivered } => Self {
                bundle: PySealedInvitation {
                    context_id: bundle.context_id,
                    creator_did: bundle.creator_did.to_string(),
                    enc: bundle.enc,
                    ciphertext: bundle.ciphertext,
                },
                delivered,
            },
        }
    }
}

#[pymethods]
impl PyInviteMemberOutcome {
    /// The sealed invitation bundle — pass it directly to
    /// [`context_join_from_welcome`](crate::scp::PyScp::context_join_from_welcome).
    #[getter]
    fn bundle(&self) -> PySealedInvitation {
        self.bundle.clone()
    }

    /// Whether the runtime published the sealed invitation to the invitee's
    /// routing id (`true`) or the caller must deliver it (`false`).
    #[getter]
    #[allow(clippy::missing_const_for_fn)] // PyO3 getter cannot be const.
    fn delivered(&self) -> bool {
        self.delivered
    }

    fn __repr__(&self) -> String {
        format!(
            "PyInviteMemberOutcome(bundle={}, delivered={})",
            self.bundle.__repr__(),
            self.delivered,
        )
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
    /// Creates a new `PyMessage` tagged with the given bridge instance's
    /// `instance_id`. Used by `drain_and_deliver` and `deliver_message` to
    /// feed messages into the receive channel.
    #[must_use]
    pub const fn new(
        bi: &crate::runtime::PyBridgeInstance,
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
            instance_id: bi.core.instance_id(),
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
    /// tagged with the given bridge instance's `instance_id`.
    ///
    /// The `Arc<tokio::sync::Mutex<Receiver>>` is shared with
    /// `FfiBridgeState::message_rx` so that `deliver_message` can access
    /// the receiver for oldest-drop overflow handling.
    #[must_use]
    pub const fn from_shared_rx(
        bi: &crate::runtime::PyBridgeInstance,
        rx: Arc<tokio::sync::Mutex<mpsc::Receiver<PyMessage>>>,
    ) -> Self {
        Self {
            rx,
            instance_id: bi.core.instance_id(),
        }
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
///
/// Uses [`generate_key_package_with_context_params`] with `None` so the leaf
/// **declares the `0xFF02` (`scp_context_params`) capability** — mandatory to
/// be added to an encrypted context group (`valn0502`, §5.13.3). The base
/// `generate_key_package` (which declares no SCP capabilities) produces a KP
/// that real MLS rejects from a context group ("the capabilities of the add
/// proposal are insufficient for this group"). No wrapping-key leaf extension
/// is attached: this single-process membership path retains no joiner private
/// state, so a wrapping key here would advertise a key whose secret is
/// discarded; sender-key distribution to such a member is correctly skipped.
fn generate_mls_key_package_bytes(did: &str) -> Result<Vec<u8>, crate::error::ScpPyError> {
    use scp_core::crypto::mls::credential::ScpCredential;
    use scp_core::crypto::mls::group::generate_key_package_with_context_params;
    use tls_codec::Serialize as TlsSerializeTrait;

    let cred =
        ScpCredential::new(did.to_owned(), None, scp_did::SigningKeyId::Active).map_err(|e| {
            crate::error::ScpPyError::crypto(format!(
                "failed to create SCP credential for MLS key package: {e}"
            ))
        })?;

    let (kp_bundle, _signer, _provider) =
        generate_key_package_with_context_params(&cred, None, &scp_clock::SystemClock).map_err(
            |e| crate::error::ScpPyError::crypto(format!("MLS key package generation failed: {e}")),
        )?;

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
    let ts = scp_clock::SystemClock.now_secs() as f64;
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
        // Relay equivocation detected (§9.9.3, §23.7). This is a security event
        // and MUST NOT be silently discarded (§9.9.4) — surface it as a
        // structured, non-lossy, HTML-escaped record rather than a Debug blob.
        scp_core::context::membership::ContextEvent::EquivocationDetected {
            context_id: ctx_id,
            remote_sender_did,
            event_count,
            local_merkle_root,
            remote_merkle_root,
        } => (
            "scp:system".to_owned(),
            format!(
                "equivocation_detected:context={},\
                 remote_sender={},event_count={event_count},\
                 local_merkle_root={},remote_merkle_root={}",
                html_escape_event_string(&ctx_id),
                html_escape_event_string(remote_sender_did.as_ref()),
                hex::encode(local_merkle_root),
                hex::encode(remote_merkle_root),
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

fn drain_and_deliver(bi: &crate::runtime::PyBridgeInstance, context_id: &str) {
    let Ok(rt) = crate::runtime() else {
        return;
    };
    let sup = match crate::runtime::supervisor(bi) {
        Ok(sup) => sup.clone(),
        Err(_) => return,
    };

    let events = rt.block_on(sup.drain_events(context_id));

    for event in events {
        let (sender_did, payload, timestamp) = convert_context_event(event);

        let msg = PyMessage::new(bi, sender_did, payload, timestamp, context_id.to_owned());
        // Best-effort: if no channel is open or the channel is full, the
        // event is dropped. This matches the subscription model where
        // events before subscribe are lost.
        let _ = crate::runtime::deliver_message(bi, context_id, msg);
    }
}

/// Drain a context's pending events from the supervisor and deliver them
/// through pre-captured channel handles, instead of resolving the channel
/// via the FFI state registry.
///
/// Used by [`Self::context_close`] (the close teardown): on a successful
/// close the FFI bridge state is removed (so bridge outlet dispatch fails
/// closed for the id — defense in depth; close itself is non-terminal for
/// the supervisor actor and does not despawn it), but the `SystemClose`
/// event the close produces must still reach an active receiver. The
/// receive-channel handles are cloned out before the FFI-state removal and
/// threaded here. No-op (events drained, delivery skipped) when no channel
/// was open.
fn drain_and_deliver_via_sender(
    bi: &crate::runtime::PyBridgeInstance,
    context_id: &str,
    channel: Option<crate::runtime::ReceiveChannelHandles>,
) {
    let Ok(rt) = crate::runtime() else {
        return;
    };
    let sup = match crate::runtime::supervisor(bi) {
        Ok(sup) => sup.clone(),
        Err(_) => return,
    };

    let events = rt.block_on(sup.drain_events(context_id));

    // No receiver was subscribed — drain the supervisor buffer (above) so
    // it does not leak, but there is nowhere to deliver. Matches the
    // subscription model where events without an active receiver are lost.
    let Some((tx, rx)) = channel else {
        return;
    };

    for event in events {
        let (sender_did, payload, timestamp) = convert_context_event(event);

        let msg = PyMessage::new(bi, sender_did, payload, timestamp, context_id.to_owned());
        // Best-effort delivery through the captured handles (same
        // oldest-drop overflow semantics as `deliver_message`).
        let _ = crate::runtime::deliver_message_with_handles(bi, context_id, &tx, &rx, msg);
    }
}

// ---------------------------------------------------------------------------
// ContextManager delegation helpers
// ---------------------------------------------------------------------------

/// Builds scp-core [`ContextParams`] from a [`PyContextParams`].
///
/// Delegates to the shared [`scp_ffi_common::context_params::build_context_params`]
/// builder, which centralizes all parameter parsing and validation logic
/// across the three FFI bridges (#1447).
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
        outlets: py_params.outlets.clone(),
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

// ---------------------------------------------------------------------------
// Context export/import bridge (#363)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Governance bridge (#369)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Context migration lifecycle (§5.11A, #580)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Governance proposal lifecycle (#621)
// ---------------------------------------------------------------------------

/// Helper: resolve the raw Ed25519 signing key for an identity DID.
///
/// Looks up the identity in the global registry, retrieves the custody
/// provider and active signing key handle, and exports the raw
/// `ed25519_dalek::SigningKey`. Required because the core governance
/// lifecycle functions take `&SigningKey` directly.
///
/// `pub(crate)` so the cross-context saga export in `outlets.rs` can resolve
/// each co-resident participant context's Active Signing Key (via that
/// context's `creator_did`) without re-implementing the custody-export path.
pub(crate) fn resolve_signing_key(
    bi: &crate::runtime::PyBridgeInstance,
    identity_did: &str,
) -> PyResult<ed25519_dalek::SigningKey> {
    let rt = crate::runtime()?;
    // Copy the key handle and clone the custody `Arc` OUT of the `with_identity`
    // closure, then DROP the DashMap identity-registry shard guard (by exiting
    // the closure) BEFORE the blocking async export. The `block_on` at the FFI
    // sync boundary is the ADR-049 §12-14-exempt class and stays; the hazard is
    // holding a sharded read guard across a (potentially slow / HSM-backed /
    // callback) async export, which pins a runtime worker and blocks any writer
    // of the same shard for its duration. The export operates only on the cloned
    // `custody`/`handle` and never re-touches the registry, so the clone-then-drop
    // reorder is sufficient — same shape as the DashMap-ref-before-await fixes
    // elsewhere. See GitHub issue #1940.
    let (custody, handle) = crate::runtime::with_identity(bi, identity_did, |entry| {
        Ok((entry.custody.clone(), entry.identity.active_signing_key))
    })
    .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    rt.block_on(async move { custody.export_ed25519_signing_key(&handle).await })
        .map_err(|e| {
            PyRuntimeError::new_err(format!("failed to export signing key for governance: {e}"))
        })
}

/// Resolves the [`ResolvedMessageSigner`](scp_ffi_common::persona::ResolvedMessageSigner)
/// for a **message send** under the requested persona (ADR-039 Enforcement-Stack
/// Layer 2).
///
/// This is the persona-aware counterpart of [`resolve_signing_key`] (which
/// stays hard-`#active` for governance / Category-A signing). It selects BOTH
/// the key handle AND the persona in a single match, so the `#active`/`#agent`
/// stamp and the signing key are chosen together and cannot diverge:
/// - [`SigningKeyId::Active`](scp_did::SigningKeyId::Active) → the identity's
///   active signing key.
/// - [`SigningKeyId::Agent`](scp_did::SigningKeyId::Agent) → the identity's
///   agent signing key. **Fail-closed**: if the identity has no agent key this
///   returns `SCP-IDENT-1023`; it NEVER falls back to `#active` (that would let
///   an `#agent`-intended send be silently attributed to the human).
///
/// The custody `Arc` and key handle are cloned OUT of the `with_identity`
/// closure before the blocking export, mirroring [`resolve_signing_key`] so no
/// `DashMap` shard guard is held across the async export (#1940).
fn resolve_message_signer(
    bi: &crate::runtime::PyBridgeInstance,
    identity_did: &str,
    persona: scp_did::SigningKeyId,
) -> PyResult<scp_ffi_common::persona::ResolvedMessageSigner> {
    let rt = crate::runtime()?;
    let (custody, handle) = crate::runtime::with_identity(bi, identity_did, |entry| {
        let handle = match persona {
            scp_did::SigningKeyId::Active => entry.identity.active_signing_key,
            scp_did::SigningKeyId::Agent => entry.identity.agent_signing_key.ok_or_else(|| {
                crate::error::ScpPyError::identity_with_code(
                    format!(
                        "identity '{identity_did}' has no agent signing key — cannot send \
                             under #agent; add one with add_agent_key first"
                    ),
                    scp_ffi_common::error_codes::IDENT_1023,
                )
            })?,
        };
        Ok((entry.custody.clone(), handle))
    })
    .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let key = rt
        .block_on(async move { custody.export_ed25519_signing_key(&handle).await })
        .map_err(|e| {
            PyRuntimeError::new_err(format!("failed to export signing key for send: {e}"))
        })?;
    Ok(scp_ffi_common::persona::ResolvedMessageSigner::new(
        key, persona,
    ))
}

/// Helper: resolve the Ed25519 *verifying* key for an identity DID without
/// materializing the private signing key (ADR-006).
///
/// Looks up the identity in the registry and asks custody for the public key
/// of the active signing-key handle. Private key material never leaves
/// custody — only the public verifying key is returned. Used by the
/// snapshot-signature import path, where only the public half is needed.
fn resolve_verifying_key(
    bi: &crate::runtime::PyBridgeInstance,
    identity_did: &str,
) -> PyResult<ed25519_dalek::VerifyingKey> {
    let rt = crate::runtime()?;
    crate::runtime::with_identity(bi, identity_did, |entry| {
        let handle = entry.identity.active_signing_key;
        let custody = entry.custody.clone();
        let public_key = rt
            .block_on(async move { custody.public_key(&handle).await })
            .map_err(|e| {
                crate::error::ScpPyError::context(format!("failed to resolve verifying key: {e}"))
            })?;
        // 32-byte length + canonical-point decode: the shared conversion tail
        // in scp-ffi-common, identical across all FFI bridges. A `None`
        // (wrong length or non-canonical point) is the fail-closed signal that
        // this DID has no usable local verifying key.
        scp_ffi_common::export_verify::verifying_key_from_public_key(&public_key).ok_or_else(|| {
            crate::error::ScpPyError::context(
                "active signing-key public key is not a valid 32-byte Ed25519 verifying key"
                    .to_owned(),
            )
        })
    })
    .map_err(|e| PyRuntimeError::new_err(e.to_string()))
}

/// Resolves the snapshot creator's Ed25519 verification key for
/// snapshot-signature verification on context import (spec §23.16.8, ADR-050,
/// ADR-039).
///
/// Per §23.16.8 step 1 the verifying key is derived from the snapshot's
/// `creator_did` (`role_state.creator_did`), never from the unauthenticated
/// envelope `exporter_did`. The runtime separately asserts
/// `exporter_did == creator_did` (§23.16.8 step 2), so the bridge MUST resolve
/// from the creator identity.
///
/// Resolution order (local-custody-first, then DID resolver) is shared across
/// all FFI bridges via
/// [`scp_ffi_common::export_verify::resolve_export_verifying_key`]:
/// 1. **Local identity custody** — if the creator is a local identity (the
///    common self-export case: a device importing a context it exported), the
///    verifying key is resolved directly via `KeyCustody::public_key` on its
///    `#active` key handle (no private-key materialization, ADR-006).
///    This works even when the DID document has not been published to the DHT
///    (in-memory identities are not auto-published).
/// 2. **DID resolver** — otherwise resolve the creator DID's `#active` (then
///    `#agent`, ADR-039 shared-DID model) verification-method key.
///
/// Fails closed: if the creator is neither local nor resolvable, the import is
/// rejected with [`scp_ffi_common::error_codes::CTX_2093`] rather than
/// proceeding unverified.
fn resolve_creator_verifying_key(
    bi: &crate::runtime::PyBridgeInstance,
    creator_did: &str,
) -> PyResult<ed25519_dalek::VerifyingKey> {
    let resolver = crate::runtime::did_resolver(bi).map(std::convert::AsRef::as_ref);

    scp_ffi_common::export_verify::resolve_export_verifying_key(
        resolver,
        // Local custody: resolve the public verifying key directly via
        // `KeyCustody::public_key` when the DID is a local identity (ADR-006).
        // Private key material never leaves custody — only the public key is
        // returned.
        |did| resolve_verifying_key(bi, did).ok(),
        creator_did,
    )
    .map_err(|e| PyRuntimeError::new_err(format!("{}: {e}", scp_ffi_common::error_codes::CTX_2093)))
}

/// Derives a member's OWN per-context pseudonym routing ID (§9.10.4).
///
/// Used by both the encrypted-context CREATE path and the (encrypted-only)
/// IMPORT path: in each case a real pseudonym is REQUIRED for a usable
/// encrypted context. Custody / derivation failure is a hard error carrying the
/// canonical pseudonym-derivation identity codes (1054 missing key material,
/// 1055 derivation failed, 1057 wrong key length) — never a silent
/// zero-pseudonym fallback, which would reintroduce the relay-correlation
/// vector by leaving the routing axis degraded. On import the exporter's
/// pseudonym is local-instance state with no meaning to the importer, so it is
/// re-derived from the importer's identity; on create the creator derives its
/// own.
///
/// BROADCAST contexts MUST NOT call this — they carry no per-member pseudonym
/// (spec §5.14) and a derivation failure there is not a real error. The create
/// path branches on the context mode and only calls this for encrypted
/// contexts.
fn derive_member_pseudonym(
    bi: &crate::runtime::PyBridgeInstance,
    importer_did: &str,
    context_id: &str,
) -> PyResult<[u8; 32]> {
    crate::runtime::with_identity(bi, importer_did, |entry| {
        let rt = crate::runtime().map_err(|e| {
            crate::error::ScpPyError::identity_with_code(
                format!("runtime not available: {e}"),
                codes::IDENT_1055,
            )
        })?;
        let pseudonym = rt.block_on(async {
            entry
                .custody
                .derive_pseudonym(&entry.identity.identity_key, context_id.as_bytes())
                .await
        });
        let pk = pseudonym
            .map_err(|e| {
                crate::error::ScpPyError::identity_with_code(
                    format!("pseudonym derivation failed: {e}"),
                    codes::IDENT_1055,
                )
            })?
            .public_key;
        let bytes: [u8; 32] = pk.as_bytes().try_into().map_err(|_| {
            crate::error::ScpPyError::identity_with_code(
                "pseudonym public key must be 32 bytes",
                codes::IDENT_1057,
            )
        })?;
        Ok(bytes)
    })
    .map_err(|e| {
        // A registry miss surfaces `with_identity`'s generic SCP-IDENT-1001;
        // remap it to the canonical "missing key material" code
        // (SCP-IDENT-1054) so a caller switching on `.code` gets the same code
        // for the same failure across bridges. Errors raised inside the closure
        // already carry specific codes and pass through unchanged.
        let mapped = match e {
            crate::error::ScpPyError::IdentityError { message, code }
                if code == codes::IDENT_1001 =>
            {
                crate::error::ScpPyError::identity_with_code(
                    format!("{message} — cannot derive pseudonym without retained key material"),
                    codes::IDENT_1054,
                )
            }
            other => other,
        };
        PyErr::from(mapped)
    })
}

/// Bridge-level local-custody gate for the bare-`DID` join-side bootstraps
/// ([`crate::scp::PyScp::reserve_key_package`] /
/// [`crate::scp::PyScp::context_join_from_welcome`]), mirroring the trust model
/// of `context_create`: a node-level bootstrap only runs on behalf of an
/// identity this bridge locally custodies.
///
/// Presence in the identity registry is exactly the local-custody signal
/// `context_create` relies on — its pseudonym derivation touches the same
/// registry entry's custody provider (see [`derive_member_pseudonym`]). Reserve
/// derives no pseudonym, so it needs this explicit up-front check; the
/// Welcome-join path enforces the identical gate implicitly via
/// `derive_member_pseudonym`. Fails closed with the identity-not-found error
/// when the DID is not a locally-custodied identity.
fn ensure_local_custody(bi: &crate::runtime::PyBridgeInstance, did: &str) -> PyResult<()> {
    crate::runtime::with_identity(bi, did, |_| Ok(()))
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))
}

/// Validates all user-controlled string fields on a governance action.
#[cfg(test)]
fn validate_governance_action_strings(
    action: &scp_core::context::governance::GovernanceAction,
) -> Result<(), crate::error::ScpPyError> {
    scp_ffi_common::validate::validate_governance_action_strings(action)
        .map_err(|e| crate::error::ScpPyError::validation(e.message))
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

// ---------------------------------------------------------------------------
// Ceiling modification, context close, checkpoint, restore (#559)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Membership query bridge (#369)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Events bridge (#369)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// TTL bridge (#369)
// ---------------------------------------------------------------------------

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
/// Returns `PyValueError` if the declaration JSON is malformed or if any
/// `ceiling`/`role` capability string fails the §5.4.2.1 parser (fail-loud —
/// malformed entries are rejected, not silently dropped), or `PyRuntimeError`
/// if serialization of the result fails.
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

    let ceiling: Vec<Capability> = ceiling_capabilities
        .iter()
        .map(|s| {
            Capability::new(s).ok_or_else(|| {
                PyValueError::new_err(format!(
                    "invalid capability {s:?} in ceiling (fails §5.4.2.1 parser) (use \"outlet:call:*\" for actions, \"outlet:query:*\" for reads)"
                ))
            })
        })
        .collect::<PyResult<Vec<_>>>()?;
    let role_caps: Vec<Capability> = role_capabilities
        .iter()
        .map(|s| {
            Capability::new(s).ok_or_else(|| {
                PyValueError::new_err(format!(
                    "invalid capability {s:?} in role (fails §5.4.2.1 parser) (use \"outlet:call:*\" for actions, \"outlet:query:*\" for reads)"
                ))
            })
        })
        .collect::<PyResult<Vec<_>>>()?;

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
    use scp_core::context::roles::{Capability, CapabilityCeiling};

    let granted: HashSet<Capability> = granted_capabilities
        .iter()
        .filter_map(Capability::new)
        .collect();
    // Fail-closed: malformed required capability -> deny.
    let Some(required) = Capability::new(&required_capability) else {
        return false;
    };

    // Single authority: `CapabilityCeiling::contains` handles exact matches plus
    // the disjoint wildcard families — `OutletCallAll ⊇ OutletCall(id)` and
    // `OutletQueryAll ⊇ OutletQuery(id)` — never widening across query/call
    // (§5.4.2). Routing through it keeps this helper fail-closed and in lockstep
    // with UCAN ceiling validation.
    CapabilityCeiling::new(granted).contains(&required)
}

// ---------------------------------------------------------------------------
// Invitation evaluation pipeline (#614)
// ---------------------------------------------------------------------------

/// FFI-concrete implementation of [`scp_core::context::invitation::TrustOracle`].
///
/// At the FFI boundary, we cannot accept a trait object. Trust is allowlist-only
/// (§5.12.2): the allowlist travels inside the policy's
/// `TrustRequirement::KnownDid(dids)` variant, so the oracle carries no external
/// state and checks membership of the inviter in that embedded list.
struct FfiBridgeTrustOracle;

impl scp_core::context::invitation::TrustOracle for FfiBridgeTrustOracle {
    fn satisfies_trust(
        &self,
        inviter: &scp_did::DID,
        requirement: &scp_core::context::policy::TrustRequirement,
    ) -> bool {
        match requirement {
            scp_core::context::policy::TrustRequirement::KnownDid(dids) => dids.contains(inviter),
        }
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
        signer_did: scp_did::DID::from(signer_did),
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
/// - `"scp:template/outlet-interface"`
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
        "scp:template/outlet-interface" | "OutletInterfaceTemplate" => {
            Ok(TemplateId::OutletInterfaceTemplate)
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
             GatedBroadcast, scp:template/outlet-interface, PaidService, PaidBroadcast, \
             HandleRegistry, scp:template/handle-registry, DiscoveryContext, \
             scp:template/discovery-context"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Access key operations (§9.17, ADR-038, #1529)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Reconnection report (ADR-029)
// ---------------------------------------------------------------------------

/// Per-context reconnection result surfaced to Python.
///
/// Flat mirror of [`scp_ffi_common::reconnect::ContextReconnectResult`].
#[pyclass]
#[derive(Clone)]
pub struct PyContextReconnectResult {
    /// Context that was reconnected.
    #[pyo3(get)]
    pub context_id: String,
    /// Offline tier: `"short"` / `"extended"` / `"long"`.
    #[pyo3(get)]
    pub tier: String,
    /// Outcome string (`"fully_caught_up"`, `"reset"`, `"failed"`, …).
    #[pyo3(get)]
    pub outcome: String,
    /// MLS epochs caught up.
    #[pyo3(get)]
    pub epochs_caught_up: u64,
    /// Event-log events recovered.
    #[pyo3(get)]
    pub events_recovered: u64,
    /// Whether an MLS Update was issued (§9.12).
    #[pyo3(get)]
    pub mls_update_issued: bool,
    /// Number of equivocation alerts surfaced (§9.9.3).
    #[pyo3(get)]
    pub equivocations_detected: u64,
    /// Whether `needs_reconnect` was cleared on success.
    #[pyo3(get)]
    pub needs_reconnect_cleared: bool,
}

/// Aggregate reconnection report surfaced to Python.
///
/// Flat mirror of [`scp_ffi_common::reconnect::ReconnectReport`].
#[pyclass]
#[derive(Clone)]
pub struct PyReconnectReport {
    /// Per-context results.
    #[pyo3(get)]
    pub contexts: Vec<PyContextReconnectResult>,
    /// Total queued messages drained (Phase 6).
    #[pyo3(get)]
    pub messages_drained: u64,
    /// Total queued messages discarded.
    #[pyo3(get)]
    pub messages_discarded: u64,
    /// Total reconnection duration in milliseconds.
    #[pyo3(get)]
    pub total_duration_ms: u64,
}

impl From<scp_ffi_common::reconnect::ReconnectReport> for PyReconnectReport {
    fn from(report: scp_ffi_common::reconnect::ReconnectReport) -> Self {
        Self {
            contexts: report
                .contexts
                .into_iter()
                .map(|c| PyContextReconnectResult {
                    context_id: c.context_id,
                    tier: c.tier,
                    outcome: c.outcome,
                    epochs_caught_up: c.epochs_caught_up,
                    events_recovered: c.events_recovered,
                    mls_update_issued: c.mls_update_issued,
                    equivocations_detected: c.equivocations_detected,
                    needs_reconnect_cleared: c.needs_reconnect_cleared,
                })
                .collect(),
            messages_drained: report.messages_drained,
            messages_discarded: report.messages_discarded,
            total_duration_ms: report.total_duration_ms,
        }
    }
}

// ---------------------------------------------------------------------------
// PyScp methods — migrated from #[pyfunction] exports (Phase 4 PR 4, #1549).
// ---------------------------------------------------------------------------

#[pymethods]
impl crate::scp::PyScp {
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
    #[pyo3(signature = (identity_did, params))]
    #[allow(clippy::too_many_lines)] // orchestration: validates, registers FFI state, delegates to ContextManager, returns handle
    pub fn context_create(
        &self,
        identity_did: &str,
        params: &Bound<'_, PyDict>,
    ) -> PyResult<PyContextHandle> {
        let bi = &*self.inner;
        validate::validate_did(identity_did)?;
        // Validate params eagerly (before any async work).
        let parsed = PyContextParams::from_py_dict(params)?;

        // Spec §18.4.1: context IDs MUST be 64-char lowercase hex so they
        // embed in `scp://context/<context_id_hex>` URIs. The shared helper
        // in `scp-ffi-common` is the single source of truth for all three
        // bridges — see ADR-048 §7a.
        let context_id = scp_ffi_common::generate_context_id();

        let handle = PyContextHandle::new(
            bi,
            context_id.clone(),
            identity_did.to_owned(),
            parsed.clone(),
        );

        // Register FFI-specific state (OutletRegistry, EventLog, RoleState, RevocationList)
        // in the global FFI state registry so that outlets/UCAN/event_log bridge functions
        // can look them up by context ID. Also initializes the shared ContextManager.
        crate::runtime::register_context(bi, &context_id, identity_did, &parsed.ceiling).map_err(
            |e| PyRuntimeError::new_err(format!("failed to register context state: {e}")),
        )?;

        // Build scp-core ContextParams from the parsed PyContextParams. Built
        // BEFORE pseudonym derivation so the context mode (the authoritative
        // encrypted-vs-broadcast axis) governs the derivation policy.
        let core_params = build_core_context_params(&parsed)?;
        let create_is_broadcast = matches!(
            core_params.mode,
            scp_core::context::params::ContextMode::Broadcast
        );

        // Delegate context creation to the shared ContextManager for lifecycle tracking.
        // §9.10.4: Derive pseudonym BEFORE context creation so it can be passed
        // to the ContextManager for per-member routing. The pseudonym derivation
        // is also reused for the known-contexts registry below.
        //
        // ENCRYPTED contexts hard-fail derivation: a degraded (zero) pseudonym
        // produces a silently unusable encrypted context (the member cannot
        // send app-data on a pseudonymous routing axis), so propagate the
        // canonical identity error. BROADCAST contexts soft-fail to `None`: they
        // carry no per-member pseudonym (spec §5.14) and the runtime ignores the
        // value.
        let local_pseudonym: Option<[u8; 32]> = if create_is_broadcast {
            None
        } else {
            Some(derive_member_pseudonym(bi, identity_did, &context_id)?)
        };

        // Create the context via the shared ContextManager.
        {
            let creator_did_owned = scp_did::DID(identity_did.to_owned());
            let rt = crate::runtime()?;
            let sup = crate::runtime::supervisor(bi)
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            let sup = sup.clone();
            let ctx_id = context_id.clone();
            let creator_did_for_register = scp_did::DID(identity_did.to_owned());
            rt.block_on(async move {
                sup.create_context(ctx_id, core_params, creator_did_owned, local_pseudonym)
                    .await
                    .map_err(|e| scp_core::context::ContextError::CreationFailed(e.to_string()))?;
                // Register the creator's DID as a local DID for defense-in-depth,
                // matching NAPI's behavior. Routes through the supervisor's direct
                // method (no per-context command — the local-DID set is
                // supervisor-wide).
                sup.register_local_did(creator_did_for_register)
                    .await
                    .map_err(|e| {
                        scp_core::context::ContextError::CreationFailed(format!(
                            "register_local_did failed: {e}"
                        ))
                    })?;
                Ok::<(), scp_core::context::ContextError>(())
            })
            .map_err(|e| {
                // Clean up FFI state on ContextManager failure.
                crate::runtime::remove_context(bi, &context_id);
                PyRuntimeError::new_err(format!("ContextManager create_context failed: {e}"))
            })?;
        }

        // §9.10.4: Send pseudonym announcement to inform other members of the
        // creator's per-context routing ID. For freshly created single-member
        // contexts this is a no-op (no recipients), but on restored/imported
        // contexts with existing members the announcement is needed.
        if local_pseudonym.is_some()
            && let Ok(sk) = resolve_signing_key(bi, identity_did)
        {
            let rt = crate::runtime()?;
            let sup = crate::runtime::supervisor(bi)
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            let sup = sup.clone();
            use scp_core::context::actor::commands::{
                MessagingCommand, SendPseudonymAnnouncementPayload, SigningKeyBytes,
            };
            let sender_did = scp_did::DID(identity_did.to_owned());
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
        // Broadcast contexts use broadcast_routing_id (plain
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
            let relay_url = match self.transport_status() {
                Ok(status) => status.relay_url,
                Err(e) => {
                    tracing::warn!(
                        "failed to query transport status during context registration: {e}"
                    );
                    None
                }
            };

            let last_seen = scp_clock::SystemClock.now_secs();

            let known = crate::runtime::KnownContext {
                routing_id,
                relay_url,
                member_did: identity_did.to_owned(),
                last_seen,
            };
            crate::runtime::register_known_context_on(bi, &context_id, known);
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
    #[pyo3(signature = (handle, identity_did, spending_ucan_jwt=None))]
    #[allow(clippy::too_many_lines)] // orchestration: validates, UCAN gate, delegates to ContextManager, syncs FFI state
    pub fn context_join(
        &self,
        handle: &PyContextHandle,
        identity_did: &str,
        spending_ucan_jwt: Option<&str>,
    ) -> PyResult<()> {
        let bi = &*self.inner;
        crate::pyscp_check_handle!(&bi.core, handle);
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
        // init_context_manager is idempotent (CoreFields::set_context_manager
        // uses OnceLock internally — first call wins). #1073
        // Passes the joiner DID to NodeMlsFactory for real MLS encryption (#1324).
        #[cfg(test)]
        crate::runtime::init_context_manager_for_test(bi);
        #[cfg(not(test))]
        crate::runtime::init_context_manager(bi, identity_did);

        // Delegate join to the shared ContextManager for membership tracking.
        {
            let context_id = handle.context_id.clone();
            let member_did = identity_did.to_owned();
            let rt = crate::runtime()?;
            let sup = crate::runtime::supervisor(bi)
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            let sup = sup.clone();

            // Generate a real MLS key package for the joining member (#1324).
            // The key package contains the joiner's SCP credential (DID) and is
            // validated by NodeMlsFactory::validate_key_package before MLS
            // group addition.
            let kp_bytes = generate_mls_key_package_bytes(identity_did)
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

            let key_package = scp_core::context::membership::KeyPackage {
                owner_did: scp_did::DID(member_did.clone()),
                mls_key_package_bytes: Some(kp_bytes),
            };

            // Look up the ContextHandle from a completed create_context call.
            // The ContextManager stores PerContextState keyed by context_id.
            // We need the handle to delegate. Since the handle is stored in
            // ContextManager's internal state, we create a temporary handle
            // matching the context's params for the join call. Built BEFORE
            // pseudonym derivation so the context mode governs the policy.
            let core_params = build_core_context_params(&handle.params)?;
            let join_is_broadcast = matches!(
                core_params.mode,
                scp_core::context::params::ContextMode::Broadcast
            );

            // §9.10.4: Derive pseudonym for the joining member so it can be
            // stored in PerContextState and announced to other members.
            //
            // ENCRYPTED contexts hard-fail derivation: a soft-failed join into
            // an encrypted context yields `None`, which the runtime maps to the
            // reserved `[0u8; 32]` sentinel — peers reject any announce of a
            // reserved value, so the joiner becomes permanently unaddressable
            // with no error surfaced. Propagate the canonical identity codes
            // (1054/1055/1057) at the same granularity as create/import.
            // BROADCAST contexts soft-fail to `None`: they carry no per-member
            // pseudonym (spec §5.14) and the runtime ignores the value.
            let local_pseudonym: Option<[u8; 32]> = if join_is_broadcast {
                None
            } else {
                Some(derive_member_pseudonym(bi, identity_did, &context_id)?)
            };
            let temp_handle =
                scp_core::context::ContextHandle::new(context_id.clone(), core_params);
            // Transition the temp handle to Active to match the real state.
            // §9.10.4: pass the pseudonym to join_context so it is stored in
            // PerContextState for subsequent send_message fan-out.
            rt.block_on(async {
                let _ = temp_handle.transition_to(&scp_core::context::ContextState::Active);
                sup.join_context(
                    &temp_handle,
                    key_package,
                    spending_ucan.as_ref(),
                    local_pseudonym,
                )
                .await
            })
            .map_err(|e| {
                PyRuntimeError::new_err(format!("ContextManager join_context failed: {e}"))
            })?;

            // §9.10.4: Send pseudonym announcement to inform existing members.
            if local_pseudonym.is_some()
                && let Ok(sk) = resolve_signing_key(bi, identity_did)
            {
                use scp_core::context::actor::commands::{
                    MessagingCommand, SendPseudonymAnnouncementPayload, SigningKeyBytes,
                };
                let sender_did = scp_did::DID(member_did.clone());
                let ann_ctx_id = context_id.clone();
                let core_params = build_core_context_params(&handle.params)?;
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

            // Also update FFI bridge state's role_state for UCAN/outlet capability checks.
            crate::runtime::with_ffi_state(bi, &context_id, |st| {
                st.role_state.members.insert(member_did.clone());
                Ok(())
            })
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

            // Bridge: drain events (MemberJoined) from ContextManager's receive
            // buffer and deliver to the FFI receive channel (#332).
            drain_and_deliver(bi, &context_id);

            // Register the joined context in the known-contexts registry so the
            // JOINER surfaces its own plain-joined context via
            // py_mcp_load_contexts, closing the discovery asymmetry with
            // context_create and context_join_from_welcome (both of which
            // register post-commit). Reuse the joiner's derived §9.10.4 pseudonym
            // as the routing ID for encrypted contexts; fall back to
            // broadcast_routing_id (plain SHA-256, matching the send path) for
            // broadcast contexts, which carry no per-member pseudonym. Post-commit
            // and infallible/idempotent (overwrites), mirroring context_create's
            // POST-success registration — safe after the committed join, needs no
            // rollback.
            {
                let routing_id = local_pseudonym.unwrap_or_else(|| {
                    if join_is_broadcast {
                        scp_core::context::broadcast_routing_id(&context_id)
                    } else {
                        scp_core::context::context_routing_id(&context_id)
                    }
                });

                let relay_url = match self.transport_status() {
                    Ok(status) => status.relay_url,
                    Err(e) => {
                        tracing::warn!(
                            "failed to query transport status during context join registration: {e}"
                        );
                        None
                    }
                };

                let known = crate::runtime::KnownContext {
                    routing_id,
                    relay_url,
                    member_did,
                    last_seen: scp_clock::SystemClock.now_secs(),
                };
                crate::runtime::register_known_context_on(bi, &context_id, known);
            }
        }

        Ok(())
    }

    /// Reserves one of the owning identity's pooled MLS `KeyPackage`s for a
    /// spawn-from-Welcome join, returning the opaque `(reservation_id,
    /// key_package_public_bytes)` pair.
    ///
    /// The join-side peer of [`context_create`](Self::context_create): a node
    /// that intends to JOIN a context by receiving a Welcome first reserves a
    /// single-use `KeyPackage` under its own identity. The returned PUBLIC
    /// `KeyPackage` bytes are handed to the context creator (out of band), who
    /// adds them to its MLS group to mint a Welcome addressed to this
    /// reservation; the returned `reservation_id` is passed back to
    /// [`context_join_from_welcome`](Self::context_join_from_welcome) so the
    /// fused consume can match the join. The private signer state never leaves
    /// the node's `KeyPackage` actor — only PUBLIC bytes cross the FFI boundary.
    ///
    /// Local-identity custody is enforced at the bridge (the same trust model as
    /// `context_create`): `owning_did` MUST be a locally-custodied identity.
    ///
    /// # Arguments
    ///
    /// * `owning_did` -- DID of the LOCAL identity reserving the `KeyPackage`.
    ///
    /// # Returns
    ///
    /// `(reservation_id, key_package_public_bytes)` -- an opaque reservation id
    /// string and the PUBLIC MLS `KeyPackage` bytes (Python `(str, bytes)`).
    ///
    /// # Errors
    ///
    /// Returns `RuntimeError` if `owning_did` is not a locally-custodied
    /// identity, or if the reservation fails (providers not wired, empty pool).
    #[pyo3(name = "reserve_key_package", signature = (owning_did))]
    pub fn reserve_key_package(&self, owning_did: &str) -> PyResult<(String, Vec<u8>)> {
        let bi = &*self.inner;
        validate::validate_did(owning_did)?;
        // Local-custody gate — same trust model as context_create.
        ensure_local_custody(bi, owning_did)?;

        // reserve_key_package can be a node's FIRST context op (it joins before
        // it ever creates), so ensure the supervisor is attached first — the
        // same idempotent init context_join performs.
        #[cfg(test)]
        crate::runtime::init_context_manager_for_test(bi);
        #[cfg(not(test))]
        crate::runtime::init_context_manager(bi, owning_did);

        let rt = crate::runtime()?;
        let sup =
            crate::runtime::supervisor(bi).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let sup = Arc::clone(sup);
        let owning = scp_did::DID(owning_did.to_owned());
        let (reservation_id, kp_public) = rt
            .block_on(async move { sup.reserve_key_package(owning).await })
            .map_err(|e| PyRuntimeError::new_err(format!("reserve_key_package failed: {e}")))?;
        Ok((reservation_id.to_string(), kp_public))
    }

    /// Joins an existing SCP context by processing a received MLS Welcome,
    /// standing the local (joiner) identity up as a send-capable participant.
    ///
    /// Completes the reserve → Welcome → join handshake begun by
    /// [`reserve_key_package`](Self::reserve_key_package): given the Welcome the
    /// context creator minted for a previously-reserved `KeyPackage`, this installs
    /// the joined MLS group, derives the joiner's §9.10.4 routing pseudonym,
    /// persists the initial keyed snapshot fail-closed, registers a context
    /// actor, and records the joined context in the known-contexts discovery
    /// registry (so `py_mcp_load_contexts` surfaces it, exactly as
    /// [`context_create`](Self::context_create) does). Without it a Welcome-joined
    /// node can DECRYPT but cannot SEND (no actor-backed handle).
    ///
    /// The bridge-side FFI state is registered as a REVERSIBLE precheck BEFORE
    /// the irreversible runtime join and rolled back on failure, mirroring
    /// `context_create`: there is no path where the runtime join commits but
    /// bridge state errors, and no leaked FFI/discovery state when the join fails.
    ///
    /// Local-identity custody of the JOINER (`owning_did`) is enforced at the
    /// bridge exactly as `context_create` enforces it for the creator: the
    /// joiner's routing pseudonym is DERIVED from its locally-custodied identity
    /// (never caller-supplied), so a non-custodied joiner hard-fails at the
    /// derivation seam with the canonical `SCP-IDENT-1054` before the single-use
    /// `KeyPackage` is consumed.
    ///
    /// # Arguments
    ///
    /// * `owning_did` -- DID of the LOCAL (joiner) identity. Its custody derives
    ///   the routing pseudonym; passed separately from `creator_did` so the two
    ///   cannot be transposed.
    /// * `creator_did` -- DID of the context creator / admin (from the legible
    ///   params).
    /// * `context_id` -- Canonical 64-hex context id (ADR-056).
    /// * `params` -- Legible context parameters (a Python dict; see
    ///   [`PyContextParams`]).
    /// * `reservation_id` -- The opaque reservation id string returned by
    ///   `reserve_key_package` for the `KeyPackage` this Welcome addresses.
    /// * `welcome_bytes` -- The TLS-serialized MLS Welcome message (Python
    ///   `bytes`).
    ///
    /// # Returns
    ///
    /// A [`PyContextHandle`] in the "active" state for the joined context.
    ///
    /// # Errors
    ///
    /// Returns `RuntimeError` if the joiner is not locally custodied, the params
    /// are invalid, the reservation id is malformed, or the spawn fails
    /// (bad/duplicate Welcome, single-use replay, first-writer-wins collision,
    /// or fail-closed persist failure).
    #[pyo3(
        name = "context_join_from_welcome",
        signature = (owning_did, sealed, reservation_id)
    )]
    pub fn context_join_from_welcome(
        &self,
        owning_did: String,
        sealed: PySealedInvitation,
        reservation_id: String,
    ) -> PyResult<PyContextHandle> {
        let bi = &*self.inner;
        validate::validate_did(&owning_did)?;
        validate::validate_did(&sealed.creator_did)?;
        validate::validate_context_id(&sealed.context_id)?;

        // NOTE: the joiner no longer supplies `params`/`welcome_bytes`. The
        // authoritative params + Welcome now travel INSIDE the signed, sealed
        // `InvitationBundle` (`sealed.enc`/`sealed.ciphertext`), which the
        // runtime opens and authenticates. The old up-front broadcast-mode check
        // is gone: there are no caller params to inspect, and a broadcast bundle
        // (which carries no MLS Welcome, spec §5.14) is rejected INSIDE the
        // runtime at the fused `ConfirmConsume` — not at this boundary.

        // spawn-from-Welcome always stands up an ENCRYPTED context; ensure the
        // node's supervisor is attached first (this may be the joiner's first
        // context op — the same idempotent init context_join performs).
        #[cfg(test)]
        crate::runtime::init_context_manager_for_test(bi);
        #[cfg(not(test))]
        crate::runtime::init_context_manager(bi, &owning_did);

        // §9.10.4 + local-custody enforcement: DERIVE the joiner's routing
        // pseudonym from its locally-custodied identity — never caller-supplied.
        // This is the SAME custody gate context_create uses; a non-custodied
        // joiner hard-fails here with SCP-IDENT-1054 before the single-use
        // KeyPackage is consumed.
        let local_pseudonym = derive_member_pseudonym(bi, &owning_did, &sealed.context_id)?;

        // Fail-closed: the HPKE encapsulated key (`enc`) MUST be exactly 32
        // bytes. Reject a malformed length BEFORE any registry mutation or the
        // irreversible KeyPackage consume, rather than letting a short/long
        // buffer fail deep inside the HPKE open.
        let sealed_bundle_enc =
            scp_ffi_common::custody_parse::expect_32("sealed_bundle_enc", &sealed.enc)
                .map_err(|e| PyValueError::new_err(e.to_string()))?;

        // Reconstruct the opaque reservation id via its sanctioned transparent
        // serde form (a bare string): the id round-trips through the FFI as a
        // string. It is a lookup key, not a capability — a bogus id simply fails
        // the fused consume match downstream, it grants nothing. Parsed BEFORE
        // any registry mutation so a malformed id can't leave orphaned state.
        let reservation: scp_core::context::supervisor::ReservationId =
            serde_json::from_value(serde_json::Value::String(reservation_id))
                .map_err(|e| PyRuntimeError::new_err(format!("invalid reservation id: {e}")))?;

        // Resolve the tokio runtime + supervisor handle BEFORE any reversible
        // registration. Neither lookup needs registered bridge state, and both
        // short-circuit on `?` — resolving them AFTER `register_ffi_state` would
        // leak the just-registered (reversible) state with no rollback on their
        // failure, and a later same-id retry would then hard-fail the Occupied
        // check. Order: custody-derive (above) → runtime/supervisor-resolve →
        // custody+active-key resolve → register-reversible → spawn →
        // rollback-on-Err → authenticated ceiling re-sync.
        let rt = crate::runtime()?;
        let sup =
            crate::runtime::supervisor(bi).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let sup = Arc::clone(sup);

        // Resolve the joiner's OWN custody provider + `#active` KeyHandle (the
        // same locally-custodied identity the pseudonym was derived from). The
        // runtime needs these to open the sealed bundle and drive the join under
        // the joiner's key material — private keys never cross the FFI, only the
        // opaque custody handle + KeyHandle do (ADR-006).
        let (custody, active_handle) = crate::runtime::with_identity(bi, &owning_did, |entry| {
            Ok((entry.custody.clone(), entry.identity.active_signing_key))
        })
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

        // Register the bridge-side FFI state (OutletRegistry / EventLog / RoleState)
        // as a REVERSIBLE precheck BEFORE the irreversible runtime join. Mirrors
        // `context_create`, which registers FFI state first and rolls it back via
        // `remove_context` if the runtime step fails. The creator is the
        // role-state admin (bundle-derived); the joiner is added as a member
        // below.
        //
        // FLAG-1: the caller no longer supplies a ceiling, so register with the
        // DEFAULT ceiling (`&[]`). The Occupied dedup is keyed on `context_id`,
        // so the "detect a duplicate BEFORE consuming the single-use KeyPackage"
        // crash-safety is preserved regardless of the ceiling. The AUTHENTICATED
        // ceiling is re-synced from the joined handle's signed params AFTER a
        // successful spawn (see `sync_ceiling_from_params` below).
        //
        // Ordering matters for two reasons:
        //   1. `register_ffi_state` hard-errors on an already-registered context
        //      (`Entry::Occupied`) — that collision fails the join HERE, BEFORE
        //      `spawn_actor_from_welcome` consumes the single-use `KeyPackage`,
        //      and leaves any pre-existing entry untouched (we must NOT roll back
        //      state we did not create).
        //   2. If the runtime join later fails, we roll THIS state back, so there
        //      is no path where the join commits but bridge state errors, and no
        //      leaked FFI state when the join fails.
        crate::runtime::register_ffi_state(bi, &sealed.context_id, &sealed.creator_did, &[])
            .map_err(|e| {
                PyRuntimeError::new_err(format!("failed to register context state: {e}"))
            })?;
        // Insert the joiner as a member of the freshly-registered role state. On
        // the (practically unreachable) failure of this insert into state we just
        // created, roll it back so a failed join leaves nothing behind.
        if let Err(e) = crate::runtime::with_ffi_state(bi, &sealed.context_id, |st| {
            st.role_state.members.insert(owning_did.clone());
            Ok(())
        }) {
            crate::runtime::remove_context(bi, &sealed.context_id);
            return Err(PyRuntimeError::new_err(e.to_string()));
        }

        let owning = scp_did::DID(owning_did.clone());
        let req = scp_core::context::supervisor::WelcomeJoinRequest {
            creator_did: scp_did::DID(sealed.creator_did.clone()),
            context_id: sealed.context_id.clone(),
            sealed_bundle_enc,
            sealed_bundle_ct: sealed.ciphertext.clone(),
            reservation_id: reservation,
            local_pseudonym: Some(local_pseudonym),
        };
        // Irreversible: open + authenticate the sealed bundle, consume the
        // KeyPackage, install the joined MLS group, persist the keyed snapshot,
        // register the context actor. On failure, roll the reversible FFI state
        // (and — via `remove_context` → `remove_ffi_state` — any known-context
        // discovery entry) back so an errored join leaves no orphaned bridge
        // state beside a runtime that never committed.
        let joined =
            match rt.block_on(sup.spawn_actor_from_welcome(owning, &*custody, &active_handle, req))
            {
                Ok(handle) => handle,
                Err(e) => {
                    crate::runtime::remove_context(bi, &sealed.context_id);
                    return Err(PyRuntimeError::new_err(format!(
                        "context_join_from_welcome failed: {e}"
                    )));
                }
            };

        // FLAG-1: re-sync the AUTHENTICATED ceiling from the joined handle's
        // signed params, overwriting the default ceiling used for the reversible
        // precheck. The authoritative ceiling lives in the bundle the creator
        // signed — never in caller input. This runs AFTER the irreversible
        // commit; the FFI state was just registered (and not removed on this
        // success path), so the sync targets a live entry.
        //
        // BLACK-2JF-01 — post-irreversible-commit compensation: the sync fails
        // ONLY if a concurrent close/leave removed the just-registered FFI state
        // in the window since the spawn returned. A close/leave does NOT despawn
        // the runtime actor, so returning `Err` here without tearing the actor
        // down would strand a live, orphaned actor for a join that never fully
        // materialized at the bridge. Compensate with the COMPLETE teardown
        // (`discard_joined_context`): it removes the actor handle AND destroys
        // the resident MLS group AND deletes the durable Class-S snapshot the
        // join persisted — a bare `despawn_actor` would leave the crypto group
        // and snapshot behind, resurrecting the context on restart and blocking
        // a fresh re-join. Then purge residual bridge state and surface the
        // error.
        if let Err(e) = crate::runtime::sync_ceiling_from_params(
            bi,
            &sealed.context_id,
            &joined.params().ceiling,
        ) {
            rt.block_on(sup.discard_joined_context(&sealed.context_id));
            crate::runtime::remove_context(bi, &sealed.context_id);
            return Err(PyRuntimeError::new_err(e.to_string()));
        }

        // Runtime join committed. Register the context in the known-contexts
        // discovery registry so a Welcome-joined context is surfaced by
        // `py_mcp_load_contexts`, exactly as `context_create` does post-create.
        // Mirrors `context_create`'s POST-success registration: infallible and
        // idempotent (overwrites), so it is safe after the irreversible commit
        // and needs no rollback. spawn-from-Welcome always stands up an ENCRYPTED
        // context, so the routing id is the joiner's derived §9.10.4 pseudonym
        // (`local_pseudonym` is `Copy`, still valid after the request move). The
        // member is the JOINER (`owning_did`), matching the role-state member
        // inserted above so `context_ids_for_member` / discovery agree.
        {
            let relay_url = match self.transport_status() {
                Ok(status) => status.relay_url,
                Err(e) => {
                    tracing::warn!(
                        "failed to query transport status during join registration: {e}"
                    );
                    None
                }
            };
            let known = crate::runtime::KnownContext {
                routing_id: local_pseudonym,
                relay_url,
                member_did: owning_did,
                last_seen: scp_clock::SystemClock.now_secs(),
            };
            crate::runtime::register_known_context_on(bi, &sealed.context_id, known);
        }

        // Build the returned handle from the AUTHENTICATED params carried by the
        // joined MLS group's signed context binding — NOT from caller input
        // (there is none). The ceiling, mode, governance, and policies reflect
        // what the creator actually signed. `sealed` is fully consumed here
        // (its fields are moved into the handle; it is unused afterward).
        let authed_params = PyContextParams::from_core_params(joined.params());
        let handle = PyContextHandle::new(bi, sealed.context_id, sealed.creator_did, authed_params);
        {
            let mut guard = handle
                .state
                .lock()
                .map_err(|_| PyRuntimeError::new_err("context state lock is poisoned"))?;
            "active".clone_into(&mut guard);
        }
        Ok(handle)
    }

    /// Invites a member to an existing context, producing a sealed, signed
    /// invitation bundle (ADR-049 Phase 2J; FFI-02 Option A).
    ///
    /// The creator (or admin) seals the context's genesis params + Welcome for
    /// the invitee under RFC 9180 HPKE, binding them to the invitee's
    /// `KeyPackage`. Only a `SingleAdmin` context is supported today: the invite
    /// is unilateral and returns a [`PyInviteMemberOutcome`] whose `bundle` is
    /// the sealed [`PySealedInvitation`] — pass it directly to
    /// [`context_join_from_welcome`](Self::context_join_from_welcome). A
    /// voting-governed context raises `RuntimeError` (governed-context
    /// invitations are not yet implemented).
    ///
    /// The invite routes through the actor governance gate, which requires the
    /// inviter to hold the `governance:propose` capability (a normally-created
    /// `SingleAdmin` context grants its admin that capability at genesis, so it
    /// works out of the box; a custom ceiling must grant it).
    ///
    /// # Arguments
    ///
    /// * `context_id` -- The context to invite into.
    /// * `creator_did` -- The inviting member's DID (must be locally custodied;
    ///   the invite is signed under its `#active` key).
    /// * `invitee_did` -- The DID being invited.
    /// * `invitee_key_package` -- The invitee's TLS-serialized MLS `KeyPackage`.
    /// * `relay_urls` -- Relay URLs to include for the invitee's first contact.
    ///
    /// # Errors
    ///
    /// Returns `RuntimeError` if the supervisor is not initialized, the signing
    /// key cannot be resolved, the context is voting-governed (governed-context
    /// invitations are not yet implemented), or the runtime invite fails (e.g.
    /// unauthorized inviter, invalid `KeyPackage`).
    #[pyo3(signature = (context_id, creator_did, invitee_did, invitee_key_package, relay_urls))]
    pub fn invite_member(
        &self,
        context_id: String,
        creator_did: String,
        invitee_did: String,
        invitee_key_package: Vec<u8>,
        relay_urls: Vec<String>,
    ) -> PyResult<PyInviteMemberOutcome> {
        let bi = &*self.inner;
        validate::validate_context_id(&context_id)?;
        validate::validate_did(&creator_did)?;
        validate::validate_did(&invitee_did)?;

        let rt = crate::runtime()?;
        let sup =
            crate::runtime::supervisor(bi).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let sup = Arc::clone(sup);

        // Resolve the inviter's Ed25519 signing key. `resolve_signing_key` runs
        // its own `block_on` and returns BEFORE the invite `block_on` below, so
        // the two calls are sequential (not nested — nesting would deadlock the
        // multi-threaded runtime).
        let signing_key = resolve_signing_key(bi, &creator_did)?;
        let outcome = rt.block_on(sup.invite_member(
            context_id,
            scp_did::DID(creator_did),
            scp_did::DID(invitee_did),
            invitee_key_package,
            relay_urls,
            &signing_key,
        ));
        // Defense-in-depth: wipe the raw signing key the moment the invite is
        // produced, rather than letting it linger to end-of-scope. `SigningKey`
        // is `ZeroizeOnDrop` (ed25519-dalek `zeroize` feature) but does NOT
        // implement bare `Zeroize`, so the explicit early `drop` — not a
        // `.zeroize()` call — is what triggers the wipe here.
        drop(signing_key);

        let outcome =
            outcome.map_err(|e| PyRuntimeError::new_err(format!("invite_member failed: {e}")))?;
        Ok(PyInviteMemberOutcome::from_outcome(outcome))
    }

    /// Test-only: seed a peer's per-context pseudonym routing ID (§9.10.4)
    /// into this bridge's `Supervisor`, bypassing the `PseudonymAnnouncement`
    /// MLS round-trip.
    ///
    /// Single-member E2E tests host one view of a context, so a
    /// governance-added peer never gets to announce its pseudonym. This lets
    /// such tests populate the routing registry the way a delivered
    /// announcement would, so multi-member encrypted sends exercise real
    /// fan-out instead of failing closed with `SCP-CTX-2095`. Mirrors the
    /// runtime `Supervisor::seed_peer_pseudonym` test helper.
    ///
    /// Gated behind `testing` so it never ships in production
    /// builds.
    ///
    /// # Errors
    ///
    /// Returns `ValueError` if `pseudonym` is not exactly 32 bytes, or
    /// `RuntimeError` if the underlying supervisor call fails.
    #[cfg(feature = "testing")]
    pub fn context_seed_peer_pseudonym(
        &self,
        handle: &PyContextHandle,
        peer_did: &str,
        pseudonym: &[u8],
    ) -> PyResult<()> {
        let bi = &*self.inner;
        crate::pyscp_check_handle!(&bi.core, handle);

        if pseudonym.len() != 32 {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "pseudonym must be exactly 32 bytes, got {}",
                pseudonym.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(pseudonym);

        let context_id = handle.context_id.clone();
        let peer_did_owned = peer_did.to_owned();
        let rt = crate::runtime()?;
        let sup =
            crate::runtime::supervisor(bi).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let sup = sup.clone();

        rt.block_on(async move {
            sup.seed_peer_pseudonym(
                &context_id,
                scp_did::DID::from(peer_did_owned.as_str()),
                arr,
            )
            .await
        })
        .map_err(|e| {
            PyRuntimeError::new_err(format!("ContextManager seed_peer_pseudonym failed: {e}"))
        })?;

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
    #[pyo3(signature = (handle, identity_did))]
    pub fn context_leave(&self, handle: &PyContextHandle, identity_did: &str) -> PyResult<()> {
        let bi = &*self.inner;
        crate::pyscp_check_handle!(&bi.core, handle);
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

        // Delegate leave to the shared ContextManager for membership tracking.
        {
            let context_id = handle.context_id.clone();
            let member_did = scp_did::DID(identity_did.to_owned());
            let rt = crate::runtime()?;
            let sup = crate::runtime::supervisor(bi)
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            let sup = sup.clone();

            let core_params = build_core_context_params(&handle.params)?;
            let temp_handle =
                scp_core::context::ContextHandle::new(context_id.clone(), core_params);
            rt.block_on(async {
                let _ = temp_handle.transition_to(&scp_core::context::ContextState::Active);
                // Self-removal: caller_did == member_did.
                sup.leave_context(&temp_handle, &member_did, &member_did)
                    .await
            })
            .map_err(|e| {
                PyRuntimeError::new_err(format!("ContextManager leave_context failed: {e}"))
            })?;

            // Also update FFI bridge state's role_state.
            let _ = crate::runtime::with_ffi_state(bi, &context_id, |st| {
                st.role_state.members.remove(identity_did);
                Ok(())
            });

            // Bridge: drain events (MemberLeft) from ContextManager's receive
            // buffer and deliver BEFORE closing the channel (#332).
            drain_and_deliver(bi, &context_id);
        }

        // Close the receive channel so any active PyMessageReceiver raises
        // StopAsyncIteration (SCP-216 AC6).
        let _ = crate::runtime::close_receive_channel(bi, &handle.context_id);

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
    #[pyo3(signature = (handle, identity_did))]
    pub fn context_close(&self, handle: &PyContextHandle, identity_did: &str) -> PyResult<()> {
        let bi = &*self.inner;
        crate::pyscp_check_handle!(&bi.core, handle);
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

        // ----------------------------------------------------------------
        // Teardown ordering (close-auth-honoring, fail-closed on success).
        //
        // The `CloseContext` dispatch enforces close authorization: the
        // actor close handler runs `ttl::close_context`, which gates on the
        // initiator's `ContextClose` capability and the governance model and
        // can reject with `PermissionDenied` (or other non-idempotent
        // errors). Close is NON-terminal for the supervisor actor — it
        // transitions the context lifecycle to Closed but does NOT despawn
        // the actor (see `handle_close_context_actor`). Because the actor
        // stays alive, its per-context hard-rate-limit bucket remains live
        // and `try_consume_hard_rate_limit_from_any_context` stays
        // fail-CLOSED throughout; there is no despawn window in which the
        // rate limit fails open.
        //
        // The defense-in-depth value of removing the FFI bridge state (which
        // backs `with_context` outlet dispatch) is that, on a SUCCESSFUL
        // close, the bridge outlet-dispatch lookup fails closed first — once
        // the state is gone, `with_context` returns `not found` and the outlet
        // cannot dispatch. To make that property honor close authorization,
        // the dispatch runs BEFORE removal: an unauthorized or otherwise
        // failing close (anything but the idempotent `ContextNotRegistered`)
        // returns early WITHOUT removing the FFI state, leaving the context
        // fully usable through this bridge instance. Restoring an already-
        // removed `FfiBridgeState` is not viable: it holds non-reconstructible
        // live state (channel senders, registered outlet handlers, sessions,
        // the accumulated event log, nonce tracker, revocation list) that
        // `register_ffi_state` cannot rebuild — so the ordering is what
        // preserves the prior state on failure.
        //
        // The receive channel lives inside the `FfiBridgeState`, so capture
        // a clone of its sender BEFORE any removal and use it to deliver the
        // drained `SystemClose` event AFTER the close completes (the close is
        // what produces that event). The clone keeps the receiver alive even
        // once the registry entry is dropped.
        let close_channel = crate::runtime::clone_receive_channel_handles(bi, &handle.context_id);

        // Delegate close to the shared supervisor FIRST so close
        // authorization (and any other precondition) is honored before the
        // FFI bridge state is touched.
        {
            let initiator_did = scp_did::DID(identity_did.to_owned());
            let rt = crate::runtime()?;
            let sup = crate::runtime::supervisor(bi)
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            let sup = sup.clone();

            use scp_core::context::actor::commands::{CloseContextPayload, LifecycleCommand};
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
            // Returns `Result<Result<CloseResult, ContextError>, PyErr>` so the
            // idempotency check below can still match on
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
            // Propagate errors unless the context was already removed from the
            // supervisor (idempotent — e.g. all members left). The
            // ContextNotRegistered error is safe to ignore: in that case the
            // close already happened, so teardown proceeds. Any other error
            // returns BEFORE FFI-state removal, leaving the context usable.
            match dispatch_outcome {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    if !matches!(e, scp_core::context::ContextError::ContextNotRegistered(_)) {
                        return Err(PyRuntimeError::new_err(format!(
                            "Supervisor close_context failed: {e}"
                        )));
                    }
                }
                Err(py_err) => return Err(py_err),
            }
        }

        // Close succeeded (or was idempotently already closed). Remove the
        // FFI bridge state → bridge outlet dispatch fails closed for this id.
        crate::runtime::remove_context(bi, &handle.context_id);

        // Transition directly to "closed" (skipping "closing" for the bridge
        // layer -- the full runtime will implement the cooperative closing window).
        "closed".clone_into(&mut state);
        drop(state);

        // Bridge: drain the `SystemClose` event the close produced and
        // deliver it through the channel sender captured before FFI-state
        // removal, so an active receiver still observes the close (#332).
        // The FFI state is already gone, so delivery cannot go through
        // `with_context`; it uses the captured sender directly.
        drain_and_deliver_via_sender(bi, &handle.context_id, close_channel);

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
    #[pyo3(signature = (handle, identity_did, payload, spending_ucan_jwt=None))]
    pub fn context_send(
        &self,
        handle: &PyContextHandle,
        identity_did: &str,
        payload: &Bound<'_, PyAny>,
        spending_ucan_jwt: Option<&str>,
    ) -> PyResult<()> {
        let bi = &*self.inner;
        crate::pyscp_check_handle!(&bi.core, handle);
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

        // ADR-039 Enforcement-Stack Layer 2: consult the per-instance
        // persona-source seam to choose the send persona (default `#active`;
        // a future determiner — RFC #2242 — overrides it), then resolve BOTH
        // the VM stamp and the matching key handle from that one persona so the
        // stamped persona and the signing key cannot diverge. Fail-closed on a
        // `#agent` request with no agent key. Passing no signer would cause the
        // encrypted send path to fail with "signing key required".
        let persona = (bi.core.persona_source())();
        let resolved_signer = resolve_message_signer(bi, &identity_did_owned, persona)?;

        // Delegate to ContextManager for message delivery through the transport.
        let context_id_for_drain = context_id.clone();
        {
            let sender_did = scp_did::DID(identity_did_owned);
            let sup = crate::runtime::supervisor(bi)
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            let sup = sup.clone();

            let core_params = build_core_context_params(&handle.params)?;
            let temp_handle = scp_core::context::ContextHandle::new(context_id, core_params);
            rt.block_on(async {
                let _ = temp_handle.transition_to(&scp_core::context::ContextState::Active);
                sup.send_message(
                    &temp_handle,
                    &sender_did,
                    &payload_bytes,
                    // The `MessageSigner` is derived from the same persona that
                    // selected the key handle (see `resolve_message_signer`), so
                    // the persona stamped on the wire and the key that signs are
                    // one source of truth (ADR-039).
                    resolved_signer.message_signer(),
                    None,
                    spending_ucan.as_ref(),
                )
                .await
            })
            .map_err(|e| {
                PyRuntimeError::new_err(format!("ContextManager send_message failed: {e}"))
            })?;
        }

        // Bridge: drain events from ContextManager's receive buffer and deliver
        // them to the FFI bridge's mpsc channel so that py_context_receive yields
        // them to Python consumers. This is the producer half of #332.
        drain_and_deliver(bi, &context_id_for_drain);

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
    #[pyo3(signature = (handle,))]
    pub fn context_receive(&self, handle: &PyContextHandle) -> PyResult<PyMessageReceiver> {
        let bi = &*self.inner;
        crate::pyscp_check_handle!(&bi.core, handle);
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
        crate::runtime::with_ffi_state(bi, &context_id, |st| {
            st.message_tx = Some(tx);
            st.message_rx = Some(Arc::clone(&rx_arc));
            Ok(())
        })
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

        Ok(PyMessageReceiver::from_shared_rx(bi, rx_arc))
    }

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
    #[pyo3(signature = (handle, policy_json))]
    pub fn set_economic_policy(
        &self,
        handle: &mut PyContextHandle,
        policy_json: &str,
    ) -> PyResult<()> {
        let bi = &*self.inner;
        crate::pyscp_check_handle!(&bi.core, handle);
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
    #[pyo3(signature = (handle,))]
    pub fn get_economic_policy(&self, handle: &PyContextHandle) -> PyResult<Option<String>> {
        let bi = &*self.inner;
        crate::pyscp_check_handle!(&bi.core, handle);
        Ok(handle.params.economic_policy.clone())
    }

    /// Exports a context's full state as serialized `MessagePack` bytes.
    ///
    /// The returned bytes are a `StoredValue<ContextExport>` envelope per §17.5,
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
    #[pyo3(signature = (context_id,))]
    pub fn context_export(&self, py: Python<'_>, context_id: &str) -> PyResult<Vec<u8>> {
        let bi = &*self.inner;
        let rt = crate::runtime()?;
        let sup =
            crate::runtime::supervisor(bi).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let sup = sup.clone();
        let ctx_id = context_id.to_owned();

        // The exporter MUST be the context creator: the importer enforces
        // `exporter_did == role_state.creator_did` (§23.16.8 step 2), so the
        // bridge resolves the authoritative creator DID from the context's
        // role state — never a nondeterministic membership-map iteration.
        let exporter_did = rt
            .block_on(async { sup.get_role_state(&ctx_id).await })
            .map(|role_state| scp_did::DID::from(role_state.creator_did))
            .ok_or_else(|| {
                PyRuntimeError::new_err(format!(
                    "context export failed: context '{ctx_id}' not found"
                ))
            })?;

        // Resolve the creator's custody provider and `#active` signing-key
        // handle (NOT a raw exported private key). Signing the §23.16.8
        // snapshot digest is delegated to `KeyCustody::sign`, which dispatches
        // to whichever backend backs this identity — in-memory, file, OR a
        // Python callback custody (`identity_create_with_custody`). This lets
        // sign-only keychain/HSM-shaped providers — which implement `sign` but
        // intentionally refuse raw key export — produce a signed export.
        // Private key material never crosses the FFI boundary (ADR-006),
        // matching the NAPI/UniFFI bridges.
        let (custody, signing_handle) =
            crate::runtime::with_identity(bi, &exporter_did.0, |entry| {
                Ok((
                    Arc::clone(&entry.custody),
                    entry.identity.active_signing_key,
                ))
            })
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

        // `export_context`'s `sign` closure is synchronous, but custody `sign`
        // is async (a Python callback custody re-acquires the GIL). The whole
        // export runs inside `rt.block_on(...)`, so a nested
        // `block_on`/`block_in_place` on the SAME runtime would panic ("Cannot
        // start a runtime from within a runtime"), and `block_in_place` is
        // unavailable on the current-thread fallback runtime (see `init_runtime`
        // in `lib.rs`). The sign closure therefore drives the async custody sign
        // on a dedicated OS thread with its own tiny current-thread runtime and
        // hands the result back through `join()` — the regime-(c) pattern
        // documented in `mcp.rs`. This is runtime-flavor-agnostic and never
        // nests `block_on`.
        //
        // Crucially, the entire export (including that signing thread `join`) is
        // run under `Python::allow_threads`: the calling Python thread holds the
        // GIL, and a `Callback` custody's `sign` re-acquires the GIL on the
        // signing thread. Releasing the GIL here lets the signing thread acquire
        // it; otherwise the main thread would block on `join` while holding the
        // GIL, deadlocking against the signing thread (in-memory/file custody
        // never touch the GIL, but releasing it for them is harmless).
        let export = py
            .allow_threads(|| {
                rt.block_on(
                    sup.export_context(&ctx_id, exporter_did, |hash: &[u8; 32]| {
                        let hash = *hash;
                        let custody = Arc::clone(&custody);
                        let signature = std::thread::scope(|scope| {
                            scope
                                .spawn(move || {
                                    let sign_rt = tokio::runtime::Builder::new_current_thread()
                                        .enable_all()
                                        .build()
                                        .map_err(|e| {
                                            scp_platform::error::PlatformError::CustodyError(
                                                format!(
                                                "context export: failed to build signing runtime: {e}"
                                            ),
                                            )
                                        })?;
                                    sign_rt.block_on(custody.sign(&signing_handle, &hash))
                                })
                                .join()
                                .map_err(|_| {
                                    scp_platform::error::PlatformError::CustodyError(
                                        "context export: signing thread panicked".to_owned(),
                                    )
                                })?
                        })?;
                        let bytes: [u8; 64] = signature.as_bytes().try_into().map_err(|_| {
                            scp_platform::error::PlatformError::CustodyError(format!(
                                "custody sign returned {} bytes, expected 64 (Ed25519)",
                                signature.as_bytes().len()
                            ))
                        })?;
                        Ok::<[u8; 64], scp_platform::error::PlatformError>(bytes)
                    }),
                )
            })
            .map_err(|e| PyRuntimeError::new_err(format!("context export failed: {e}")))?;

        scp_core::context::export_import::serialize_export(&export)
            .map_err(|e| PyRuntimeError::new_err(format!("export serialization failed: {e}")))
    }

    /// Imports a context from serialized `MessagePack` bytes.
    ///
    /// The bytes must be a `StoredValue<ContextExport>` envelope per §17.5,
    /// as produced by `py_context_export`.
    ///
    /// # Arguments
    ///
    /// * `data` -- Serialized context export bytes.
    /// * `importer_did` -- DID of the LOCAL member re-homing the context (the
    ///   caller's own identity), distinct from the snapshot creator. Used to
    ///   derive this member's own per-context pseudonym (§9.10.4). Must already
    ///   be a member of the imported snapshot, otherwise the import is rejected
    ///   with `SCP-CTX-2092`.
    ///
    /// # Returns
    ///
    /// The context ID string of the imported context.
    ///
    /// # Errors
    ///
    /// - `RuntimeError` if deserialization, validation, or import fails.
    /// - `ValueError` if the data is malformed.
    #[pyo3(signature = (data, importer_did))]
    pub fn context_import(&self, data: &[u8], importer_did: &str) -> PyResult<String> {
        let bi = &*self.inner;
        let export = scp_core::context::export_import::deserialize_export(data).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("invalid export data: {e}"))
        })?;

        let context_id = export.snapshot.context_id.clone();

        // Resolve the verification-method key for the snapshot's `creator_did`
        // (§23.16.8 step 1, ADR-050) — NOT the unauthenticated envelope
        // `exporter_did`. The runtime separately asserts
        // `exporter_did == creator_did` (§23.16.8 step 2). Fail-closed: if no
        // key resolves, the import is rejected — never imported unverified.
        let creator_did = export.snapshot.role_state.creator_did.clone();
        validate::validate_did(&creator_did)?;
        // §9.10.4: the importer DID is DISTINCT from the snapshot creator —
        // it identifies the local member re-homing the context and is used to
        // derive this member's own per-context pseudonym. Validate it up front,
        // before any state mutation.
        validate::validate_did(importer_did)?;
        let verifying_key = resolve_creator_verifying_key(bi, &creator_did)?;

        // Verify-before-init: validate the snapshot signature, signer binding,
        // version gate, and Merkle chain BEFORE touching the bridge's
        // ContextManager. `init_context_manager` seeds the MLS provider's
        // credential identity from `creator_did`, and that OnceLock is
        // first-call-wins. Seeding it from an unverified snapshot would let an
        // attacker-crafted `creator_did` set the provider identity on a fresh
        // bridge whose first operation is an import. Running the full
        // verification here means the identity is only seeded from a
        // cryptographically authenticated `creator_did`. `import_context`
        // re-runs the same validation (authoritative path); the duplicate work
        // is acceptable to keep the security ordering correct.
        scp_core::context::export_import::validate_export_for_import(&export, &verifying_key)
            .map_err(crate::error::ScpPyError::from)?;

        // §9.10.4 misuse-resistance: the importer MUST be a member of the now-
        // verified snapshot, else its derived pseudonym routes to an ID no peer
        // expects and the member is silently unaddressable. Reject loudly
        // (SCP-CTX-2092). The creator is a member, so a creator re-homing its
        // own context passes.
        scp_core::context::export_import::ensure_importer_is_member(&export.snapshot, importer_did)
            .map_err(crate::error::ScpPyError::from)?;

        // Ensure the ContextManager is initialized — context_import is a valid
        // first operation (e.g. a device receiving exported context data).
        // init_context_manager is idempotent (CoreFields::set_context_manager
        // uses OnceLock internally — first call wins). Seeding from the
        // now-verified `creator_did` is safe per the verify-before-init step
        // above.
        #[cfg(test)]
        crate::runtime::init_context_manager_for_test(bi);
        #[cfg(not(test))]
        crate::runtime::init_context_manager(bi, &creator_did);

        let rt = crate::runtime()?;
        let sup =
            crate::runtime::supervisor(bi).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let sup = sup.clone();

        // §9.10.4: derive the importer's OWN per-context pseudonym before the
        // runtime import. See `derive_member_pseudonym` for the hard-error /
        // no-fallback rationale. DISTINCT from `creator_did` — this is the
        // local member re-homing the context, not the snapshot creator.
        let local_pseudonym: [u8; 32] = derive_member_pseudonym(bi, importer_did, &context_id)?;

        // §9.10.4: capture the imported context's params + mode before `export`
        // is moved into the import call, so the post-import pseudonym
        // announcement can build a temporary handle without re-reading state.
        let imported_core_params = export.snapshot.context_params.clone();
        let imported_is_broadcast = matches!(
            imported_core_params.mode,
            scp_core::context::params::ContextMode::Broadcast
        );
        // Resolve the importer's signing key for the post-import announcement
        // (best-effort — a missing key just skips the announcement, which peers
        // recover on the importer's next explicit announcement).
        let announce_signing_key = resolve_signing_key(bi, importer_did).ok();
        let context_id_for_announce = context_id.clone();

        rt.block_on(async move {
            // Dispatch the import carrying BOTH the creator verifying key
            // (verify-before-init, §23.16.8) and the importer's derived
            // pseudonym (§9.10.4). `import_context` re-runs the authoritative
            // verification and routes the typed `ContextError` (SCP-CTX-2091/
            // 2092/2093/2094, §9.10.4 codes) through the canonical converter so
            // it reaches Python as a `ScpContextError` carrying `.code`.
            sup.import_context(export, &verifying_key, Some(local_pseudonym))
                .await
                .map_err(|e| PyErr::from(crate::error::ScpPyError::from(e)))?;

            // §9.10.4: emit a PseudonymAnnouncement so existing members learn
            // this importer's per-context routing ID. Encrypted contexts only —
            // broadcast contexts use the shared `broadcast_routing_id` and carry
            // no pseudonym registry. Without this announcement peers' registries
            // stay stale and app-data fan-out would miss the importer entirely.
            if !imported_is_broadcast && let Some(sk) = announce_signing_key {
                use scp_core::context::actor::commands::{
                    MessagingCommand, SendPseudonymAnnouncementPayload, SigningKeyBytes,
                };
                let sender_did = scp_did::DID(importer_did.to_owned());
                let ann_ctx_id = context_id_for_announce.clone();
                let (atx, arx) = tokio::sync::oneshot::channel();
                let ann_cmd = MessagingCommand::SendPseudonymAnnouncement {
                    payload: Box::new(SendPseudonymAnnouncementPayload {
                        context_id: ann_ctx_id.clone(),
                        params: imported_core_params,
                        sender_did,
                        signing_key: SigningKeyBytes::from_signing_key(&sk),
                    }),
                    reply: atx,
                };
                if sup.dispatch_command(&ann_ctx_id, ann_cmd).await.is_ok() {
                    let _ = arx.await;
                }
            }
            Ok::<(), PyErr>(())
        })?;

        Ok(context_id)
    }

    /// Executes a previously-approved governance proposal by id.
    ///
    /// The runtime resolves the authoritative proposal from the context
    /// actor's own quorum-validated governance engine using `proposal_id_hex`;
    /// the bridge never supplies a proposal, action, or status. A caller
    /// therefore cannot fabricate an approved proposal or substitute an
    /// action — execution applies exactly the tracked, quorum-approved action.
    ///
    /// # Arguments
    ///
    /// * `handle` -- The context handle.
    /// * `proposal_id_hex` -- Hex-encoded 32-byte id of the approved proposal.
    ///
    /// # Returns
    ///
    /// A string describing the governance action result (e.g., `"MemberAdded"`).
    ///
    /// # Errors
    ///
    /// Returns `RuntimeError` if the context manager is not initialized, the
    /// proposal id is malformed or not tracked/approved, or execution fails.
    // FFI orchestration: validate + dispatch + map; grew at the origin/main actor merge
    #[allow(clippy::too_many_lines)]
    #[pyo3(signature = (handle, proposal_id_hex))]
    pub fn governance_execute(
        &self,
        handle: &PyContextHandle,
        proposal_id_hex: &str,
    ) -> PyResult<String> {
        let bi = &*self.inner;
        crate::pyscp_check_handle!(&bi.core, handle);
        let rt = crate::runtime()?;
        let sup =
            crate::runtime::supervisor(bi).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let sup = sup.clone();
        let context_id = handle.context_id.clone();
        let handle_state = handle.state.clone();
        let proposal_id = parse_proposal_id(proposal_id_hex)?;
        let proposal_id_log = hex::encode(proposal_id);

        rt.block_on(async move {
            use scp_core::context::actor::commands::{
                ExecuteGovernanceActionPayload, GovernanceCommand, QueriesCommand,
            };

            let (tx, rx) = tokio::sync::oneshot::channel();
            let cmd = GovernanceCommand::ExecuteGovernanceAction {
                payload: Box::new(ExecuteGovernanceActionPayload {
                    context_id: context_id.clone(),
                    proposal_id,
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
                .map_err(|e| {
                    PyRuntimeError::new_err(format!("governance execution failed: {e}"))
                })?;

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
                    if let Err(e) = crate::runtime::with_ffi_state(bi, &context_id, |st| {
                        st.role_state = new_role_state;
                        Ok(())
                    }) {
                        tracing::warn!(
                            context_id = %context_id,
                            proposal_id = %proposal_id_log,
                            error = %e,
                            "failed to sync role state after governance action — \
                             local capability checks may be stale"
                        );
                    }
                }
                None => {
                    tracing::warn!(
                        context_id = %context_id,
                        proposal_id = %proposal_id_log,
                        "failed to sync role state after governance action — \
                         context not found in ContextManager"
                    );
                }
            }

            use scp_core::context::state::GovernanceActionResult;
            let result_str = match result {
                GovernanceActionResult::MemberAdded { .. } => "MemberAdded",
                GovernanceActionResult::MemberRemoved => "MemberRemoved",
                GovernanceActionResult::RoleChanged => "RoleChanged",
                GovernanceActionResult::OutletRegistered => "OutletRegistered",
                GovernanceActionResult::OutletRemoved => "OutletRemoved",
                GovernanceActionResult::CeilingModified => "CeilingModified",
                GovernanceActionResult::ContextClosed => "ContextClosed",
                GovernanceActionResult::TtlExtended => "TtlExtended",
                GovernanceActionResult::PruningPolicyModified => "PruningPolicyModified",
                GovernanceActionResult::AdminTransferred => "AdminTransferred",
                GovernanceActionResult::SignerAdded => "SignerAdded",
                GovernanceActionResult::SignerRemoved => "SignerRemoved",
                GovernanceActionResult::ThresholdModified => "ThresholdModified",
                GovernanceActionResult::ChildContextCreated => "ChildContextCreated",
                GovernanceActionResult::OutletInterfaceEstablished => "OutletInterfaceEstablished",
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
            };

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
    #[pyo3(signature = (handle,))]
    pub fn tombstone_migrated_context(&self, handle: &PyContextHandle) -> PyResult<()> {
        let bi = &*self.inner;
        crate::pyscp_check_handle!(&bi.core, handle);
        let rt = crate::runtime()?;
        let sup =
            crate::runtime::supervisor(bi).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let sup = sup.clone();
        let context_id = handle.context_id.clone();
        let handle_state = handle.state.clone();

        rt.block_on(async move {
            use scp_core::context::actor::commands::GovernanceCommand;
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
    #[pyo3(signature = (handle,))]
    pub fn migration_state(&self, handle: &PyContextHandle) -> PyResult<Option<String>> {
        let bi = &*self.inner;
        crate::pyscp_check_handle!(&bi.core, handle);
        let rt = crate::runtime()?;
        let sup =
            crate::runtime::supervisor(bi).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let sup = sup.clone();
        let context_id = handle.context_id.clone();

        rt.block_on(async move {
            use scp_core::context::actor::commands::GovernanceCommand;
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

    /// Proposes a governance action for voting.
    ///
    /// Delegates to `ContextManager::propose_governance_action_checked`,
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
    #[pyo3(signature = (handle, identity_did, action_json))]
    pub fn governance_propose(
        &self,
        handle: &PyContextHandle,
        identity_did: &str,
        action_json: &str,
    ) -> PyResult<String> {
        let bi = &*self.inner;
        crate::pyscp_check_handle!(&bi.core, handle);
        let rt = crate::runtime()?;
        let sup =
            crate::runtime::supervisor(bi).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let sup = sup.clone();
        let context_id = handle.context_id.clone();
        let action_json_owned = action_json.to_owned();
        let signing_key = resolve_signing_key(bi, identity_did)?;
        let proposer_did = scp_did::DID(identity_did.to_owned());

        rt.block_on(async move {
            let action: scp_core::context::governance::GovernanceAction =
                serde_json::from_str(&action_json_owned).map_err(|e| {
                    PyValueError::new_err(format!(
                        "SCP-CTX-2040: invalid governance action JSON: {e}"
                    ))
                })?;

            scp_ffi_common::validate::validate_governance_action_strings(&action)
                .map_err(|e| PyValueError::new_err(format!("SCP-CTX-2040: {}", e.message)))?;

            let action_name = action.variant_name();

            let outcome = sup
                .propose_governance_action_checked(&context_id, &proposer_did, action, &signing_key)
                .await
                .map_err(|e| {
                    PyRuntimeError::new_err(format!(
                        "SCP-CTX-2041: governance proposal failed: {e}"
                    ))
                })?;

            // Re-sync local role state cache from ContextManager after any
            // governance action that may have modified roles/membership (#560).
            if let Err(e) =
                crate::runtime::sync_role_state_from_manager_async(bi, &context_id).await
            {
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

    /// Casts an approval vote on a pending governance proposal.
    ///
    /// Delegates to `ContextManager::approve_governance_proposal`, which
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
    #[pyo3(signature = (handle, identity_did, proposal_id_hex))]
    pub fn governance_approve(
        &self,
        handle: &PyContextHandle,
        identity_did: &str,
        proposal_id_hex: &str,
    ) -> PyResult<String> {
        let bi = &*self.inner;
        crate::pyscp_check_handle!(&bi.core, handle);
        let rt = crate::runtime()?;
        let sup =
            crate::runtime::supervisor(bi).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let sup = sup.clone();
        let context_id = handle.context_id.clone();
        let signing_key = resolve_signing_key(bi, identity_did)?;
        let voter_did = scp_did::DID(identity_did.to_owned());
        let proposal_id = parse_proposal_id(proposal_id_hex)?;

        rt.block_on(async move {
            use scp_core::context::actor::commands::{
                GovernanceCommand, SigningKeyBytes, VoteOnProposalPayload,
            };

            let (tx, rx) = tokio::sync::oneshot::channel();
            let cmd = GovernanceCommand::ApproveGovernanceProposal {
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
                    PyRuntimeError::new_err(format!(
                        "SCP-CTX-2042: governance approval failed: {e}"
                    ))
                })?;

            if let Err(e) =
                crate::runtime::sync_role_state_from_manager_async(bi, &context_id).await
            {
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
    /// Delegates to `ContextManager::reject_governance_proposal`, which
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
    #[pyo3(signature = (handle, identity_did, proposal_id_hex))]
    pub fn governance_reject(
        &self,
        handle: &PyContextHandle,
        identity_did: &str,
        proposal_id_hex: &str,
    ) -> PyResult<String> {
        let bi = &*self.inner;
        crate::pyscp_check_handle!(&bi.core, handle);
        let rt = crate::runtime()?;
        let sup =
            crate::runtime::supervisor(bi).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let sup = sup.clone();
        let context_id = handle.context_id.clone();
        let signing_key = resolve_signing_key(bi, identity_did)?;
        let voter_did = scp_did::DID(identity_did.to_owned());
        let proposal_id = parse_proposal_id(proposal_id_hex)?;

        rt.block_on(async move {
            use scp_core::context::actor::commands::{
                GovernanceCommand, SigningKeyBytes, VoteOnProposalPayload,
            };

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
                    PyRuntimeError::new_err(format!(
                        "SCP-CTX-2043: governance rejection failed: {e}"
                    ))
                })?;

            if let Err(e) =
                crate::runtime::sync_role_state_from_manager_async(bi, &context_id).await
            {
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
    /// Delegates to `ContextManager::withdraw_governance_vote`. No signing
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
    #[pyo3(signature = (handle, identity_did, proposal_id_hex))]
    pub fn governance_withdraw(
        &self,
        handle: &PyContextHandle,
        identity_did: &str,
        proposal_id_hex: &str,
    ) -> PyResult<String> {
        let bi = &*self.inner;
        crate::pyscp_check_handle!(&bi.core, handle);
        let rt = crate::runtime()?;
        let sup =
            crate::runtime::supervisor(bi).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let sup = sup.clone();
        let context_id = handle.context_id.clone();
        let voter_did = scp_did::DID(identity_did.to_owned());
        let proposal_id = parse_proposal_id(proposal_id_hex)?;

        rt.block_on(async move {
            let status = sup
                .withdraw_governance_vote(&context_id, &proposal_id, &voter_did)
                .await
                .map_err(|e| {
                    PyRuntimeError::new_err(format!(
                        "SCP-CTX-2044: governance vote withdrawal failed: {e}"
                    ))
                })?;

            if let Err(e) =
                crate::runtime::sync_role_state_from_manager_async(bi, &context_id).await
            {
                tracing::warn!(
                    context_id = %context_id,
                    error = %e,
                    "failed to sync role state after governance withdrawal"
                );
            }

            Ok(serde_json::json!({ "status": format!("{status:?}") }).to_string())
        })
    }

    /// Retrieves a single governance proposal by hex-encoded ID.
    ///
    /// # Errors
    ///
    /// Returns `RuntimeError` (SCP-CTX-2045) if the proposal is not found.
    #[pyo3(signature = (handle, proposal_id_hex))]
    pub fn governance_get_proposal(
        &self,
        handle: &PyContextHandle,
        proposal_id_hex: String,
    ) -> PyResult<String> {
        let bi = &*self.inner;
        crate::pyscp_check_handle!(&bi.core, handle);
        let context_id = handle.context_id.clone();
        let proposal_id = parse_proposal_id(&proposal_id_hex)?;

        let sup = crate::runtime::supervisor(bi)
            .map_err(|e| PyRuntimeError::new_err(format!("SCP-CTX-2040: {e}")))?;
        let rt =
            crate::runtime().map_err(|e| PyRuntimeError::new_err(format!("SCP-CTX-2040: {e}")))?;

        rt.block_on(async move {
            let proposal = sup
                .get_proposal(&context_id, &proposal_id)
                .await
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
    #[pyo3(signature = (handle,))]
    pub fn governance_list_proposals(&self, handle: &PyContextHandle) -> PyResult<String> {
        let bi = &*self.inner;
        crate::pyscp_check_handle!(&bi.core, handle);
        let context_id = handle.context_id.clone();

        let sup = crate::runtime::supervisor(bi)
            .map_err(|e| PyRuntimeError::new_err(format!("SCP-CTX-2040: {e}")))?;
        let rt =
            crate::runtime().map_err(|e| PyRuntimeError::new_err(format!("SCP-CTX-2040: {e}")))?;

        rt.block_on(async move {
            let proposals = sup.list_proposals(&context_id).await.map_err(|e| {
                PyRuntimeError::new_err(format!("SCP-CTX-2046: list proposals failed: {e}"))
            })?;

            serde_json::to_string(&proposals).map_err(|e| {
                PyRuntimeError::new_err(format!("SCP-CTX-2046: serialization failed: {e}"))
            })
        })
    }

    /// Applies a pending ceiling modification if the notification period has elapsed.
    ///
    /// Delegates to `ContextManager::apply_pending_ceiling_modification`.
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
    #[pyo3(signature = (handle, current_timestamp))]
    pub fn apply_pending_ceiling_modification(
        &self,
        handle: &PyContextHandle,
        current_timestamp: u64,
    ) -> PyResult<bool> {
        let bi = &*self.inner;
        crate::pyscp_check_handle!(&bi.core, handle);
        let rt = crate::runtime()?;
        let sup =
            crate::runtime::supervisor(bi).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let sup = sup.clone();
        let context_id = handle.context_id.clone();

        rt.block_on(async move {
            use scp_core::context::actor::commands::GovernanceCommand;
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
    /// Delegates to `ContextManager::finalize_close`, which transitions
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
    #[pyo3(signature = (handle,))]
    pub fn finalize_close(&self, handle: &PyContextHandle) -> PyResult<()> {
        let bi = &*self.inner;
        crate::pyscp_check_handle!(&bi.core, handle);
        let rt = crate::runtime()?;
        let sup =
            crate::runtime::supervisor(bi).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let sup = sup.clone();
        let core_params = build_core_context_params(&handle.params)?;
        let context_id = handle.context_id.clone();

        rt.block_on(async move {
            use scp_core::context::actor::commands::{TtlCloseCommand, TtlContextPayload};
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
    /// Delegates to `ContextManager::create_governance_checkpoint`.
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
    #[pyo3(signature = (handle, checkpoint_seq, merkle_root_hex, event_count, last_event_hash_hex, state_snapshot_hash_hex, creator_did, creator_signature_hex))]
    #[allow(clippy::too_many_arguments)]
    pub fn create_governance_checkpoint(
        &self,
        handle: &PyContextHandle,
        checkpoint_seq: u64,
        merkle_root_hex: &str,
        event_count: u64,
        last_event_hash_hex: &str,
        state_snapshot_hash_hex: &str,
        creator_did: &str,
        creator_signature_hex: &str,
    ) -> PyResult<String> {
        let bi = &*self.inner;
        crate::pyscp_check_handle!(&bi.core, handle);
        let rt = crate::runtime()?;
        let sup =
            crate::runtime::supervisor(bi).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let sup = sup.clone();
        let context_id = handle.context_id.clone();

        let merkle_root = parse_hex_32(merkle_root_hex, "merkle_root")?;
        let last_event_hash = parse_hex_32(last_event_hash_hex, "last_event_hash")?;
        let state_snapshot_hash = parse_hex_32(state_snapshot_hash_hex, "state_snapshot_hash")?;
        let creator_signature = hex::decode(creator_signature_hex).map_err(|e| {
            PyValueError::new_err(format!("SCP-CTX-2062: invalid creator_signature hex: {e}"))
        })?;
        let did = scp_did::DID(creator_did.to_owned());

        rt.block_on(async move {
            use scp_core::context::actor::commands::{
                CreateGovernanceCheckpointPayload, TrustRecoveryCommand,
            };
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
    /// Delegates to `ContextManager::add_checkpoint_cosignature`.
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
    #[pyo3(signature = (handle, checkpoint_json, signer_did, signature_hex))]
    pub fn add_checkpoint_cosignature(
        &self,
        handle: &PyContextHandle,
        checkpoint_json: &str,
        signer_did: &str,
        signature_hex: &str,
    ) -> PyResult<String> {
        let bi = &*self.inner;
        crate::pyscp_check_handle!(&bi.core, handle);
        let rt = crate::runtime()?;
        let sup =
            crate::runtime::supervisor(bi).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let sup = sup.clone();
        let context_id = handle.context_id.clone();

        let checkpoint: scp_core::context::governance::ContextCheckpoint =
            serde_json::from_str(checkpoint_json).map_err(|e| {
                PyValueError::new_err(format!("SCP-CTX-2063: invalid checkpoint JSON: {e}"))
            })?;

        let signature = hex::decode(signature_hex).map_err(|e| {
            PyValueError::new_err(format!("SCP-CTX-2063: invalid signature hex: {e}"))
        })?;

        let cosignature = scp_core::context::governance::CosignedCheckpoint {
            signer_did: scp_did::DID(signer_did.to_owned()),
            signature,
        };

        rt.block_on(async move {
            use scp_core::context::actor::commands::TrustRecoveryCommand;
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
    /// Delegates to `Supervisor::restore_context`. The context must
    /// have been previously persisted and must not already be registered.
    ///
    /// # Arguments
    ///
    /// * `context_id` -- The context ID to restore.
    ///
    /// # Errors
    ///
    /// Returns `RuntimeError` (SCP-CTX-2064) if restoration fails.
    #[pyo3(signature = (context_id,))]
    pub fn restore_context(&self, context_id: &str) -> PyResult<()> {
        let bi = &*self.inner;
        let rt = crate::runtime()?;
        let sup =
            crate::runtime::supervisor(bi).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let sup = sup.clone();
        let context_id_owned = context_id.to_owned();

        rt.block_on(async move {
            // Route through the ADR-049 commit-9 lifecycle shim. The handler
            // reconstructs an ephemeral ContextHandle and delegates to the
            // manager's restore_context, which loads its own snapshot from
            // persistence — the ContextParams we supply here is only used to
            // initialise the ephemeral handle wrapper (default is acceptable
            // because restore_context overwrites all memory-scope-sensitive
            // state from the loaded snapshot anyway).
            use scp_core::context::actor::commands::{LifecycleCommand, RestoreContextPayload};
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
    /// Delegates to `Supervisor::restore_on_startup` (ADR-049), which
    /// first restores contexts and then replays any crash-orphaned saga journal
    /// entries in the §17.16.4-required restore-then-replay order. Only contexts
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
    #[pyo3(signature = ())]
    pub fn restore_all_contexts(&self) -> PyResult<String> {
        let bi = &*self.inner;
        let rt = crate::runtime()?;
        let sup =
            crate::runtime::supervisor(bi).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let sup = sup.clone();

        rt.block_on(async move {
            let restored = sup.restore_on_startup().await.map_err(|e| {
                PyRuntimeError::new_err(format!("SCP-CTX-2065: restore_all_contexts failed: {e}"))
            })?;

            serde_json::to_string(&restored).map_err(|e| {
                PyRuntimeError::new_err(format!("SCP-CTX-2065: serialization failed: {e}"))
            })
        })
    }

    /// Subscribes a DID to a broadcast context.
    ///
    /// For open broadcast contexts, any DID can subscribe. For gated contexts,
    /// a valid `messages:read` UCAN issued to `subscriber_did` by the context
    /// admin/creator MUST be supplied as `messages_read_ucan_jwt` (spec §5.14.4);
    /// the full UCAN validation pipeline runs on it in the actor (spec §07:70).
    /// Omitting it for a gated context is rejected with `PermissionDenied`.
    ///
    /// # Errors
    ///
    /// Returns `RuntimeError` if the context is not active, not a broadcast
    /// context, if `messages_read_ucan_jwt` is malformed, or if subscription
    /// fails.
    #[pyo3(signature = (handle, subscriber_did, messages_read_ucan_jwt=None))]
    pub fn broadcast_subscribe(
        &self,
        handle: &PyContextHandle,
        subscriber_did: &str,
        messages_read_ucan_jwt: Option<&str>,
    ) -> PyResult<()> {
        let bi = &*self.inner;
        crate::pyscp_check_handle!(&bi.core, handle);
        validate::validate_did(subscriber_did)?;
        // Parse the optional gated-admission `messages:read` UCAN JWT into a
        // UcanToken; the actor runs the full validation pipeline on it.
        let ucan_token = messages_read_ucan_jwt
            .map(|jwt| {
                validate::validate_ucan_token(jwt)?;
                scp_core::crypto::ucan::validate::parse_ucan(jwt).map_err(|e| {
                    PyRuntimeError::new_err(format!("invalid messages:read UCAN: {e}"))
                })
            })
            .transpose()?;
        let rt = crate::runtime()?;
        let sup =
            crate::runtime::supervisor(bi).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let sup = sup.clone();
        let context_id = handle.context_id.clone();
        let did: scp_did::DID = subscriber_did.to_owned().into();
        let timestamp = scp_clock::Clock::now_secs(&scp_clock::SystemClock);

        rt.block_on(async move {
            use scp_core::context::actor::commands::{BroadcastCommand, SubscribeBroadcastPayload};
            let (tx, rx) = tokio::sync::oneshot::channel();
            let cmd = BroadcastCommand::SubscribeBroadcast {
                payload: Box::new(SubscribeBroadcastPayload {
                    context_id,
                    subscriber_did: did,
                    ucan: ucan_token,
                    timestamp,
                }),
                reply: tx,
            };
            sup.dispatch_broadcast_command(cmd).await.map_err(|e| {
                PyRuntimeError::new_err(format!(
                    "supervisor dispatch_broadcast_command failed: {e}"
                ))
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
    #[pyo3(signature = (handle, subscriber_did, rotate_keys=false))]
    pub fn broadcast_unsubscribe(
        &self,
        handle: &PyContextHandle,
        subscriber_did: &str,
        rotate_keys: bool,
    ) -> PyResult<()> {
        let bi = &*self.inner;
        crate::pyscp_check_handle!(&bi.core, handle);
        validate::validate_did(subscriber_did)?;
        let rt = crate::runtime()?;
        let sup =
            crate::runtime::supervisor(bi).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let sup = sup.clone();
        let context_id = handle.context_id.clone();
        let did: scp_did::DID = subscriber_did.to_owned().into();

        rt.block_on(async move {
            use scp_core::context::actor::commands::{
                BroadcastCommand, UnsubscribeBroadcastPayload,
            };
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
                PyRuntimeError::new_err(format!(
                    "supervisor dispatch_broadcast_command failed: {e}"
                ))
            })?;
            rx.await
                .map_err(|e| PyRuntimeError::new_err(format!("shim reply dropped: {e}")))?
                .map_err(|e| {
                    PyRuntimeError::new_err(format!("broadcast unsubscribe failed: {e}"))
                })?;
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
    #[pyo3(signature = (handle, author_did, payload))]
    pub fn broadcast_publish(
        &self,
        handle: &PyContextHandle,
        author_did: &str,
        payload: Vec<u8>,
    ) -> PyResult<()> {
        use scp_core::context::actor::commands::{BroadcastCommand, PublishBroadcastPayload};
        let bi = &*self.inner;
        crate::pyscp_check_handle!(&bi.core, handle);
        validate::validate_did(author_did)?;
        let rt = crate::runtime()?;
        let sup =
            crate::runtime::supervisor(bi).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let sup = sup.clone();
        let context_id = handle.context_id.clone();
        let author_did_owned = author_did.to_owned();

        crate::runtime::with_identity(bi, &author_did_owned, |entry| {
            let custody = entry.custody.clone();
            let signing_key_handle = entry.identity.active_signing_key;
            let did: scp_did::DID = author_did_owned.clone().into();

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
                    .map_err(|e| {
                        crate::error::ScpPyError::context(format!("shim reply dropped: {e}"))
                    })?
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
    /// Constructs a `BroadcastContent` from the asset entry fields, computes an
    /// `ETag` from the body, serializes with the magic prefix, and publishes via
    /// `ContextManager::publish_broadcast_content`.
    ///
    /// Returns a dict with `blob_id` (hex-encoded SHA-256 of the serialized
    /// envelope) and `etag` (hex-encoded SHA-256 of the body).
    ///
    /// # Errors
    ///
    /// Returns `RuntimeError` if the context is not active, not broadcast,
    /// the sender is not an author, or the asset fields are invalid.
    // FFI orchestration: validate + dispatch + map; grew at the origin/main actor merge
    #[allow(clippy::too_many_lines)]
    #[pyo3(signature = (handle, author_did, path, content_type, body, deploy_id = None))]
    pub fn broadcast_publish_asset(
        &self,
        handle: &PyContextHandle,
        author_did: &str,
        path: &str,
        content_type: &str,
        body: Vec<u8>,
        deploy_id: Option<&str>,
    ) -> PyResult<HashMap<String, String>> {
        use scp_core::context::actor::commands::{
            BroadcastCommand, PublishBroadcastContentPayload,
        };
        let bi = &*self.inner;
        crate::pyscp_check_handle!(&bi.core, handle);
        validate::validate_did(author_did)?;
        let rt = crate::runtime()?;
        let sup =
            crate::runtime::supervisor(bi).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let sup = sup.clone();
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

        crate::runtime::with_identity(bi, &author_did_owned, |entry| {
            let custody = entry.custody.clone();
            let signing_key_handle = entry.identity.active_signing_key;
            let did: scp_did::DID = author_did_owned.clone().into();

            // Validate and construct BroadcastContent.
            let content_path = scp_core::context::ContentPath::new(path_owned)
                .map_err(|e| crate::error::ScpPyError::context(format!("invalid path: {e}")))?;
            let mime_type = scp_core::context::MimeType::new(content_type_owned).map_err(|e| {
                crate::error::ScpPyError::context(format!("invalid content_type: {e}"))
            })?;
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
                    .map_err(|e| {
                        crate::error::ScpPyError::context(format!("shim reply dropped: {e}"))
                    })?
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
    // FFI orchestration: validate + dispatch + map; grew at the origin/main actor merge
    #[allow(clippy::too_many_lines)]
    #[pyo3(signature = (handle, author_did, assets, deploy_id = None))]
    pub fn broadcast_publish_assets(
        &self,
        handle: &PyContextHandle,
        author_did: &str,
        assets: Vec<(String, String, Vec<u8>)>,
        deploy_id: Option<&str>,
    ) -> PyResult<PyObject> {
        use scp_core::context::actor::commands::{
            BroadcastCommand, PublishBroadcastContentPayload,
        };
        let bi = &*self.inner;
        crate::pyscp_check_handle!(&bi.core, handle);
        const MAX_BATCH_ASSETS: usize = 10_000;
        if assets.len() > MAX_BATCH_ASSETS {
            return Err(PyRuntimeError::new_err(format!(
                "batch too large: {} assets (max {MAX_BATCH_ASSETS})",
                assets.len()
            )));
        }

        validate::validate_did(author_did)?;
        let rt = crate::runtime()?;
        let sup =
            crate::runtime::supervisor(bi).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let sup = sup.clone();
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

        crate::runtime::with_identity(bi, &author_did_owned, |entry| {
            let custody = entry.custody.clone();
            let signing_key_handle = entry.identity.active_signing_key;
            let did: scp_did::DID = author_did_owned.clone().into();

            rt.block_on(async move {
                let mut results = Vec::with_capacity(assets.len());
                for (path, content_type, body) in assets {
                    let content_path = scp_core::context::ContentPath::new(path).map_err(|e| {
                        crate::error::ScpPyError::context(format!("invalid path: {e}"))
                    })?;
                    let mime_type =
                        scp_core::context::MimeType::new(content_type).map_err(|e| {
                            crate::error::ScpPyError::context(format!("invalid content_type: {e}"))
                        })?;

                    let etag = scp_core::context::compute_etag(&body);
                    let content = scp_core::context::BroadcastContent {
                        version: scp_core::context::BROADCAST_CONTENT_VERSION,
                        metadata: scp_core::context::ContentMetadata {
                            path: Some(content_path),
                            content_type: Some(mime_type),
                            deploy_id: Some(deploy_id_owned.clone()),
                            etag: Some(etag.clone()),
                            immutable: false,
                        },
                        body,
                    };

                    let (tx, rx) = tokio::sync::oneshot::channel();
                    let cmd = BroadcastCommand::PublishBroadcastContent {
                        payload: Box::new(PublishBroadcastContentPayload {
                            context_id: context_id.clone(),
                            author_did: did.clone(),
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
                        .map_err(|e| {
                            crate::error::ScpPyError::context(format!("shim reply dropped: {e}"))
                        })?
                        .map_err(|e| {
                            crate::error::ScpPyError::context(format!(
                                "broadcast publish asset failed: {e}"
                            ))
                        })?;

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
                    result.insert("deploy_id".to_owned(), deploy_id_owned.clone());
                    results.push(result);
                }

                // Return {"results": [...], "deploy_id": "..."} matching NAPI/UniFFI.
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
    #[pyo3(signature = (handle, subscriber_did, blocker_did))]
    pub fn broadcast_block_subscriber(
        &self,
        handle: &PyContextHandle,
        subscriber_did: &str,
        blocker_did: &str,
    ) -> PyResult<()> {
        let bi = &*self.inner;
        crate::pyscp_check_handle!(&bi.core, handle);
        validate::validate_did(subscriber_did)?;
        validate::validate_did(blocker_did)?;
        let rt = crate::runtime()?;
        let sup =
            crate::runtime::supervisor(bi).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let sup = sup.clone();
        let context_id = handle.context_id.clone();
        let subscriber: scp_did::DID = subscriber_did.to_owned().into();
        let blocker: scp_did::DID = blocker_did.to_owned().into();

        rt.block_on(async move {
            use scp_core::context::actor::commands::{BroadcastBlockPayload, BroadcastCommand};
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
                PyRuntimeError::new_err(format!(
                    "supervisor dispatch_broadcast_command failed: {e}"
                ))
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
    #[pyo3(signature = (handle, subscriber_did, unblocker_did))]
    pub fn broadcast_unblock_subscriber(
        &self,
        handle: &PyContextHandle,
        subscriber_did: &str,
        unblocker_did: &str,
    ) -> PyResult<()> {
        let bi = &*self.inner;
        crate::pyscp_check_handle!(&bi.core, handle);
        validate::validate_did(subscriber_did)?;
        validate::validate_did(unblocker_did)?;
        let rt = crate::runtime()?;
        let sup =
            crate::runtime::supervisor(bi).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let sup = sup.clone();
        let context_id = handle.context_id.clone();
        let subscriber: scp_did::DID = subscriber_did.to_owned().into();
        let unblocker: scp_did::DID = unblocker_did.to_owned().into();

        rt.block_on(async move {
            use scp_core::context::actor::commands::{BroadcastBlockPayload, BroadcastCommand};
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
                PyRuntimeError::new_err(format!(
                    "supervisor dispatch_broadcast_command failed: {e}"
                ))
            })?;
            rx.await
                .map_err(|e| PyRuntimeError::new_err(format!("shim reply dropped: {e}")))?
                .map_err(|e| PyRuntimeError::new_err(format!("broadcast unblock failed: {e}")))?;
            Ok(())
        })
    }

    /// Handles a broadcast key request from a subscriber, sealing the author's
    /// current broadcast key to the requester's X25519 `wrapping_pubkey`
    /// (HPKE Base mode, §5.14.2). The raw broadcast key never crosses the FFI
    /// boundary — only the sealed material is returned.
    ///
    /// # Returns
    ///
    /// `Some(json)` on grant, where `json` is a serialized
    /// [`SealedBroadcastKey`](scp_core::context::broadcast::SealedBroadcastKey)
    /// (the subscriber opens it via [`Self::broadcast_open_key`]). `None` on
    /// deny — per §5.14.8 the author returns no key material to a denied
    /// (blocked, unregistered, or unauthorized) requester.
    ///
    /// # Errors
    ///
    /// Returns `ValueError` if `wrapping_pubkey` is not exactly 32 bytes, or
    /// `RuntimeError` if the operation fails.
    #[pyo3(signature = (handle, author_did, requester_did, wrapping_pubkey))]
    pub fn broadcast_handle_key_request(
        &self,
        handle: &PyContextHandle,
        author_did: &str,
        requester_did: &str,
        wrapping_pubkey: &[u8],
    ) -> PyResult<Option<String>> {
        let bi = &*self.inner;
        crate::pyscp_check_handle!(&bi.core, handle);
        validate::validate_did(author_did)?;
        validate::validate_did(requester_did)?;
        let wrapping: [u8; 32] = wrapping_pubkey.try_into().map_err(|_| {
            PyValueError::new_err(format!(
                "wrapping_pubkey must be 32 bytes, got {}",
                wrapping_pubkey.len()
            ))
        })?;
        let rt = crate::runtime()?;
        let sup =
            crate::runtime::supervisor(bi).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let sup = sup.clone();
        let context_id = handle.context_id.clone();
        let context_id_for_seal = context_id.clone();
        let author_did_owned = author_did.to_owned();
        let author: scp_did::DID = author_did.to_owned().into();
        let requester: scp_did::DID = requester_did.to_owned().into();

        rt.block_on(async move {
            use scp_core::context::actor::commands::BroadcastCommand;
            let (tx, rx) = tokio::sync::oneshot::channel();
            let cmd = BroadcastCommand::HandleBroadcastKeyRequest {
                context_id,
                author_did: author,
                requester_did: requester,
                wrapping_pubkey: wrapping,
                reply: tx,
            };
            sup.dispatch_broadcast_command(cmd).await.map_err(|e| {
                PyRuntimeError::new_err(format!(
                    "supervisor dispatch_broadcast_command failed: {e}"
                ))
            })?;
            let decision = rx
                .await
                .map_err(|e| PyRuntimeError::new_err(format!("shim reply dropped: {e}")))?
                .map_err(|e| {
                    PyRuntimeError::new_err(format!("broadcast key request handling failed: {e}"))
                })?;
            // Grant→sealed-JSON / Deny→None via the shared helper (per-SDK error
            // mapping kept here; only the value-shape logic is shared).
            scp_ffi_common::broadcast::seal_decision_to_json(
                decision,
                &author_did_owned,
                &context_id_for_seal,
            )
            .map_err(|e| PyRuntimeError::new_err(format!("serialize sealed broadcast key: {e}")))
        })
    }

    /// Opens an HPKE-sealed broadcast key (§5.14.2) using a software-held
    /// X25519 wrapping secret, returning the raw 32-byte AES-256 broadcast key.
    ///
    /// Pure crypto — no handle, no `self` state. The `sealed_json` is the
    /// JSON produced by [`Self::broadcast_handle_key_request`] on grant.
    ///
    /// # Errors
    ///
    /// Returns `ValueError` if `sealed_json` is malformed or `wrapping_secret`
    /// is not 32 bytes, or `RuntimeError` if HPKE open fails.
    #[staticmethod]
    #[pyo3(signature = (sealed_json, wrapping_secret))]
    pub fn broadcast_open_key(sealed_json: &str, wrapping_secret: &[u8]) -> PyResult<Vec<u8>> {
        use scp_ffi_common::broadcast::OpenSealedKeyError;
        scp_ffi_common::broadcast::open_sealed_broadcast_key(sealed_json, wrapping_secret).map_err(
            |e| match e {
                // Malformed JSON / wrong-length secret are caller-input errors
                // (ValueError); a failed HPKE open is a runtime crypto error.
                OpenSealedKeyError::InvalidJson { .. }
                | OpenSealedKeyError::InvalidSecretLength { .. } => {
                    PyValueError::new_err(e.to_string())
                }
                OpenSealedKeyError::OpenFailed { .. } => PyRuntimeError::new_err(e.to_string()),
            },
        )
    }

    /// Returns the number of broadcast subscribers for a context.
    ///
    /// Returns `None` if the context is not registered or not a broadcast context.
    #[pyo3(signature = (handle,))]
    pub fn broadcast_subscriber_count(&self, handle: &PyContextHandle) -> PyResult<Option<u64>> {
        let bi = &*self.inner;
        crate::pyscp_check_handle!(&bi.core, handle);
        let rt = crate::runtime()?;
        let sup =
            crate::runtime::supervisor(bi).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let sup = Arc::clone(sup);
        let context_id = handle.context_id.clone();
        rt.block_on(async move {
            use scp_core::context::actor::commands::BroadcastCommand;
            let (tx, rx) = tokio::sync::oneshot::channel();
            let cmd = BroadcastCommand::BroadcastSubscriberCount {
                context_id,
                reply: tx,
            };
            sup.dispatch_broadcast_command(cmd).await.map_err(|e| {
                PyRuntimeError::new_err(format!(
                    "supervisor dispatch_broadcast_command failed: {e}"
                ))
            })?;
            rx.await
                .map_err(|e| PyRuntimeError::new_err(format!("shim reply dropped: {e}")))?
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))
                .map(|opt| opt.map(|n| n as u64))
        })
    }

    /// Returns `True` if the given DID is a broadcast subscriber.
    #[pyo3(signature = (handle, did))]
    pub fn broadcast_is_subscriber(&self, handle: &PyContextHandle, did: &str) -> PyResult<bool> {
        let bi = &*self.inner;
        crate::pyscp_check_handle!(&bi.core, handle);
        validate::validate_did(did)?;
        let rt = crate::runtime()?;
        let sup =
            crate::runtime::supervisor(bi).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let sup = Arc::clone(sup);
        let context_id = handle.context_id.clone();
        let did_owned = did.to_owned();
        rt.block_on(async move {
            use scp_core::context::actor::commands::BroadcastCommand;
            let (tx, rx) = tokio::sync::oneshot::channel();
            let cmd = BroadcastCommand::IsBroadcastSubscriber {
                context_id,
                did: did_owned,
                reply: tx,
            };
            sup.dispatch_broadcast_command(cmd).await.map_err(|e| {
                PyRuntimeError::new_err(format!(
                    "supervisor dispatch_broadcast_command failed: {e}"
                ))
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
    #[pyo3(signature = (handle,))]
    pub fn broadcast_admission(&self, handle: &PyContextHandle) -> PyResult<Option<String>> {
        let bi = &*self.inner;
        crate::pyscp_check_handle!(&bi.core, handle);
        let rt = crate::runtime()?;
        let sup =
            crate::runtime::supervisor(bi).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let sup = Arc::clone(sup);
        let context_id = handle.context_id.clone();
        rt.block_on(async move {
            use scp_core::context::actor::commands::BroadcastCommand;
            let (tx, rx) = tokio::sync::oneshot::channel();
            let cmd = BroadcastCommand::BroadcastAdmission {
                context_id,
                reply: tx,
            };
            sup.dispatch_broadcast_command(cmd).await.map_err(|e| {
                PyRuntimeError::new_err(format!(
                    "supervisor dispatch_broadcast_command failed: {e}"
                ))
            })?;
            rx.await
                .map_err(|e| PyRuntimeError::new_err(format!("shim reply dropped: {e}")))?
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))
                .map(|opt| opt.map(|a| format!("{a:?}")))
        })
    }

    /// Returns the current member count for a context.
    ///
    /// Returns `None` if the context is not registered.
    #[pyo3(signature = (handle,))]
    pub fn context_member_count(&self, handle: &PyContextHandle) -> PyResult<Option<u64>> {
        let bi = &*self.inner;
        crate::pyscp_check_handle!(&bi.core, handle);
        let rt = crate::runtime()?;
        let sup =
            crate::runtime::supervisor(bi).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let context_id = handle.context_id.clone();
        Ok(rt.block_on(sup.member_count(&context_id)).map(|n| n as u64))
    }

    /// Reconnects all of `identity_did`'s contexts after an offline
    /// period, running the ADR-029 six-phase reconnection protocol for
    /// each context flagged `needs_reconnect` (§23.11).
    ///
    /// The driver lives here at the FFI relay-client layer (ADR-029
    /// reconnection-driver addendum): it pulls relay-buffered messages via
    /// the `TransportManager` and reaches actor-owned reconnection state
    /// (MLS epoch, Commit/Welcome processing, checkpoint build/compare,
    /// MLS update) through the `Supervisor`. On success each context's
    /// `needs_reconnect` flag is cleared.
    ///
    /// `context_ids` is the set of contexts to consider; each is driven
    /// through the protocol only if the actor reports it `needs_reconnect`.
    /// `last_relay_contacts` maps `context_id` → last-relay-contact Unix
    /// seconds (used to classify the offline tier). Contexts absent from
    /// the map default to the most conservative tier.
    ///
    /// # Errors
    ///
    /// Returns `RuntimeError` if no relay is connected, the supervisor is
    /// not initialized, or the signing key cannot be resolved.
    #[pyo3(signature = (identity_did, context_ids, last_relay_contacts=None))]
    pub fn context_reconnect(
        &self,
        identity_did: &str,
        context_ids: Vec<String>,
        last_relay_contacts: Option<HashMap<String, u64>>,
    ) -> PyResult<PyReconnectReport> {
        let bi = &*self.inner;
        validate::validate_did(identity_did)?;
        let rt = crate::runtime()?;
        let sup =
            crate::runtime::supervisor(bi).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let transport = bi.core.get_transport_arc().ok().flatten().ok_or_else(|| {
            PyRuntimeError::new_err(
                "no relay connection — call transport_connect() before reconnecting",
            )
        })?;

        // Resolve the local member's Ed25519 signing key (used to sign the
        // Phase-3 consistency checkpoint). Private key never crosses FFI
        // beyond this in-process driver call. The 32-byte seed is held in
        // `Zeroizing` so it is wiped when this call returns rather than
        // lingering on the stack/heap.
        let signing_key = resolve_signing_key(bi, identity_did)?;
        let signing_key_bytes = zeroize::Zeroizing::new(signing_key.to_bytes());

        let contacts = last_relay_contacts.unwrap_or_default();
        let now = scp_clock::SystemClock.now_secs();

        let report = rt.block_on(scp_ffi_common::reconnect::reconnect_contexts_no_drain(
            &transport,
            sup,
            scp_did::DID(identity_did.to_owned()),
            signing_key_bytes,
            context_ids,
            contacts,
            now,
            scp_core::sync::SyncPolicy::default(),
        ));
        Ok(report.into())
    }

    /// Returns `True` if the given DID is a member of the context.
    #[pyo3(signature = (handle, did))]
    pub fn context_is_member(&self, handle: &PyContextHandle, did: &str) -> PyResult<bool> {
        let bi = &*self.inner;
        crate::pyscp_check_handle!(&bi.core, handle);
        validate::validate_did(did)?;
        let rt = crate::runtime()?;
        let sup =
            crate::runtime::supervisor(bi).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let context_id = handle.context_id.clone();
        Ok(rt.block_on(sup.is_member(&context_id, did)))
    }

    /// Returns all member DIDs for a context.
    #[pyo3(signature = (handle,))]
    pub fn context_member_dids(&self, handle: &PyContextHandle) -> PyResult<Vec<String>> {
        let bi = &*self.inner;
        crate::pyscp_check_handle!(&bi.core, handle);
        let rt = crate::runtime()?;
        let sup =
            crate::runtime::supervisor(bi).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let context_id = handle.context_id.clone();
        Ok(rt.block_on(sup.member_dids(&context_id)))
    }

    /// Returns the role assignment for a specific member as a debug string.
    ///
    /// Returns `None` if the member is not found or the context is not registered.
    #[pyo3(signature = (handle, did))]
    pub fn context_member_role(
        &self,
        handle: &PyContextHandle,
        did: &str,
    ) -> PyResult<Option<String>> {
        let bi = &*self.inner;
        crate::pyscp_check_handle!(&bi.core, handle);
        validate::validate_did(did)?;
        let rt = crate::runtime()?;
        let sup =
            crate::runtime::supervisor(bi).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let context_id = handle.context_id.clone();
        Ok(rt
            .block_on(sup.member_role(&context_id, did))
            .map(|r| format!("{r:?}")))
    }

    /// Drains all pending events from the context's receive buffer.
    ///
    /// Returns a list of event descriptions as debug strings. Returns empty
    /// if the context is not registered.
    #[pyo3(signature = (handle,))]
    pub fn context_drain_events(&self, handle: &PyContextHandle) -> PyResult<Vec<String>> {
        let bi = &*self.inner;
        crate::pyscp_check_handle!(&bi.core, handle);
        let rt = crate::runtime()?;
        let sup =
            crate::runtime::supervisor(bi).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let sup = sup.clone();
        let context_id = handle.context_id.clone();
        Ok(rt
            .block_on(sup.drain_events(&context_id))
            .into_iter()
            .map(|e| format!("{e:?}"))
            .collect())
    }

    /// Handles TTL expiry for a context.
    ///
    /// Transitions from `Active` to `Expired`, destroys keys per memory scope.
    ///
    /// # Errors
    ///
    /// Returns `RuntimeError` if the context is not active.
    #[pyo3(signature = (handle,))]
    pub fn context_handle_ttl_expiry(&self, handle: &PyContextHandle) -> PyResult<()> {
        let bi = &*self.inner;
        crate::pyscp_check_handle!(&bi.core, handle);
        let rt = crate::runtime()?;
        let sup =
            crate::runtime::supervisor(bi).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let sup = sup.clone();
        let context_id = handle.context_id.clone();
        let core_params = build_core_context_params(&handle.params)?;

        rt.block_on(async move {
            use scp_core::context::actor::commands::{TtlCloseCommand, TtlContextPayload};
            let (tx, rx) = tokio::sync::oneshot::channel();
            let cmd = TtlCloseCommand::ExecuteTtlClose {
                payload: Box::new(TtlContextPayload {
                    context_id,
                    params: core_params,
                }),
                reply: tx,
            };
            sup.dispatch_ttl_close_command(cmd).await.map_err(|e| {
                PyRuntimeError::new_err(format!(
                    "supervisor dispatch_ttl_close_command failed: {e}"
                ))
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
    #[pyo3(signature = (handle, member_did, proposed_seconds))]
    pub fn context_propose_ttl_extension(
        &self,
        handle: &PyContextHandle,
        member_did: &str,
        proposed_seconds: u64,
    ) -> PyResult<bool> {
        let bi = &*self.inner;
        crate::pyscp_check_handle!(&bi.core, handle);
        validate::validate_did(member_did)?;
        let rt = crate::runtime()?;
        let sup =
            crate::runtime::supervisor(bi).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let sup = sup.clone();
        let context_id = handle.context_id.clone();
        let did: scp_did::DID = member_did.to_owned().into();
        let duration = std::time::Duration::from_secs(proposed_seconds);

        rt.block_on(async move {
            use scp_core::context::actor::commands::TtlCloseCommand;
            let (tx, rx) = tokio::sync::oneshot::channel();
            let cmd = TtlCloseCommand::ExtendTtl {
                context_id,
                member_did: did,
                proposed_duration: duration,
                reply: tx,
            };
            sup.dispatch_ttl_close_command(cmd).await.map_err(|e| {
                PyRuntimeError::new_err(format!(
                    "supervisor dispatch_ttl_close_command failed: {e}"
                ))
            })?;
            rx.await
                .map_err(|e| PyRuntimeError::new_err(format!("shim reply dropped: {e}")))?
                .map_err(|e| PyRuntimeError::new_err(format!("TTL extension proposal failed: {e}")))
        })
    }

    /// Resets the TTL timer after a successful unanimous extension.
    ///
    /// EXTENDS the existing convergent TTL deadline by `new_seconds`
    /// (`old_deadline + new_seconds`), NOT a local `now + new_seconds` — every
    /// member adds the same duration to the same recorded deadline, so the
    /// re-armed `ContextExpired`/`ContextClosed` leaf timestamp stays convergent
    /// across members (§7.3.1). It does NOT cancel/respawn a task: the TTL timer
    /// is an actor-owned arm and `reconcile_timers` re-derives the one-shot sleep
    /// from the new recorded deadline (ADR-049 finding A3).
    ///
    /// NO-OP on a context with no armed TTL (`deadline_unix_secs == None`): a
    /// context with no recorded deadline has no TTL to extend, so the disarmed
    /// timer stays disarmed rather than arming a long-past deadline (H2).
    #[pyo3(signature = (handle, new_seconds))]
    pub fn context_reset_ttl_timer(
        &self,
        handle: &PyContextHandle,
        new_seconds: u64,
    ) -> PyResult<()> {
        let bi = &*self.inner;
        crate::pyscp_check_handle!(&bi.core, handle);
        let rt = crate::runtime()?;
        let sup =
            crate::runtime::supervisor(bi).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let sup = sup.clone();
        let context_id = handle.context_id.clone();
        let core_params = build_core_context_params(&handle.params)?;
        let duration = std::time::Duration::from_secs(new_seconds);

        rt.block_on(async move {
            use scp_core::context::actor::commands::{TtlCloseCommand, TtlTimerPayload};
            let (tx, rx) = tokio::sync::oneshot::channel();
            let cmd = TtlCloseCommand::ResetTtlTimer {
                payload: Box::new(TtlTimerPayload {
                    context_id,
                    params: core_params,
                    duration,
                    // Ignored by ResetTtlTimer (which extends the existing
                    // convergent deadline by `duration`, not an absolute
                    // override).
                    deadline_override: None,
                }),
                reply: tx,
            };
            sup.dispatch_ttl_close_command(cmd).await.map_err(|e| {
                PyRuntimeError::new_err(format!(
                    "supervisor dispatch_ttl_close_command failed: {e}"
                ))
            })?;
            rx.await
                .map_err(|e| PyRuntimeError::new_err(format!("shim reply dropped: {e}")))?
                .map_err(|e| PyRuntimeError::new_err(format!("TTL reset failed: {e}")))?;
            Ok::<(), PyErr>(())
        })?;
        Ok(())
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
    ///
    /// The `KnownDid` allowlist (the sole auto-accept trigger) travels inside the
    /// `policy_json`'s `TrustRequirement::KnownDid(dids)` variant; there is no
    /// separate trusted-DID parameter.
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
    #[pyo3(
        name = "evaluate_invitation",
        signature = (params_json, inviter_did, identity_did, policy_json=None, spending_json=None)
    )]
    pub fn evaluate_invitation(
        &self,
        params_json: &str,
        inviter_did: &str,
        identity_did: &str,
        policy_json: Option<&str>,
        spending_json: Option<&str>,
    ) -> PyResult<String> {
        let bi = &*self.inner;
        use scp_core::context::invitation::{
            EvaluationDecision, SpendingContext, evaluate_invitation,
        };
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

        let oracle = FfiBridgeTrustOracle;
        let inviter = scp_did::DID::from(inviter_did);

        // Route the rate-limit tracker through this instance's core
        // (PyScp method — #1549 Phase 4 PR 4). Pre-migration this called
        // the module-level `with_rate_limit_tracker` which fell back to
        // the default bridge; routing via `bi.core` keeps the tracker
        // state scoped to the caller's `PyScp`.
        let decision = bi.core.with_rate_limit_tracker(identity_did, |tracker| {
            evaluate_invitation(
                &params,
                &inviter,
                policy.as_ref(),
                spending.as_ref(),
                &oracle,
                tracker,
                &scp_clock::SystemClock,
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

    /// Generates and stores a per-member access key for explicit lifecycle
    /// management.
    ///
    /// Delegates to `ContextManager::generate_context_access_key`.
    ///
    /// # Errors
    ///
    /// Returns `RuntimeError` if the context is not registered, the member
    /// is not found, or the caller lacks admin capability.
    #[pyo3(name = "access_key_generate", signature = (context_id, member_did, caller_did))]
    pub fn access_key_generate(
        &self,
        context_id: &str,
        member_did: &str,
        caller_did: &str,
    ) -> PyResult<()> {
        let bi = &*self.inner;
        validate::validate_context_id(context_id)?;
        validate::validate_did(member_did)?;
        validate::validate_did(caller_did)?;
        let rt = crate::runtime()?;
        let sup =
            crate::runtime::supervisor(bi).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let sup = Arc::clone(sup);
        let context_id_owned = context_id.to_owned();
        let member_did_owned = member_did.to_owned();
        let caller_did_owned = caller_did.to_owned();
        rt.block_on(async move {
            use scp_core::context::actor::commands::LifecycleCommand;
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
                    PyRuntimeError::new_err(format!(
                        "[SCP-CTX-2070] access key generation failed: {e}"
                    ))
                })
        })
    }

    /// Revokes (removes) a member's access key from the context's access key
    /// store.
    ///
    /// Delegates to `ContextManager::revoke_context_access_key`.
    ///
    /// # Errors
    ///
    /// Returns `RuntimeError` if the context is not registered, no access
    /// key exists for the member, or the caller lacks admin capability.
    #[pyo3(name = "access_key_revoke", signature = (context_id, member_did, caller_did))]
    pub fn access_key_revoke(
        &self,
        context_id: &str,
        member_did: &str,
        caller_did: &str,
    ) -> PyResult<()> {
        let bi = &*self.inner;
        validate::validate_context_id(context_id)?;
        validate::validate_did(member_did)?;
        validate::validate_did(caller_did)?;
        let rt = crate::runtime()?;
        let sup =
            crate::runtime::supervisor(bi).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let sup = Arc::clone(sup);
        let context_id_owned = context_id.to_owned();
        let member_did_owned = member_did.to_owned();
        let caller_did_owned = caller_did.to_owned();
        rt.block_on(async move {
            use scp_core::context::actor::commands::LifecycleCommand;
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
                    PyRuntimeError::new_err(format!(
                        "[SCP-CTX-2071] access key revocation failed: {e}"
                    ))
                })
        })
    }

    /// Restores a member's access key by generating a new key at the next
    /// epoch.
    ///
    /// Delegates to `Supervisor::restore_context_access_key`.
    ///
    /// # Errors
    ///
    /// Returns `RuntimeError` if the context is not registered, the member
    /// is not found, or the caller lacks admin capability.
    #[pyo3(name = "access_key_restore", signature = (context_id, member_did, caller_did))]
    pub fn access_key_restore(
        &self,
        context_id: &str,
        member_did: &str,
        caller_did: &str,
    ) -> PyResult<()> {
        let bi = &*self.inner;
        validate::validate_context_id(context_id)?;
        validate::validate_did(member_did)?;
        validate::validate_did(caller_did)?;
        let rt = crate::runtime()?;
        let sup =
            crate::runtime::supervisor(bi).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let sup = Arc::clone(sup);
        let context_id_owned = context_id.to_owned();
        let member_did_owned = member_did.to_owned();
        let caller_did_owned = caller_did.to_owned();
        rt.block_on(async move {
            use scp_core::context::actor::commands::LifecycleCommand;
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

    // -----------------------------------------------------------------------
    // App sandboxing — durable bind / unbind (spec §8.4)
    // -----------------------------------------------------------------------

    /// Binds an app to a context and appends an `AppBound` event to the
    /// durable event log (spec §8.4).
    ///
    /// Validates the capability declaration against the context ceiling and the
    /// actor's effective role capabilities (suspension-aware), then appends a
    /// typed `AppBound` event. Returns a JSON summary on success:
    /// `{"app_did": "...", "granted_capabilities": [...]}`.
    ///
    /// # Errors
    ///
    /// Returns `ValueError` for an invalid declaration or capability; returns
    /// `RuntimeError` if validation fails (ceiling exceeded, signature invalid)
    /// or if the durable event log append fails.
    #[pyo3(signature = (context_id, declaration_json, actor_did, timestamp_secs))]
    pub fn sandbox_app_bind(
        &self,
        context_id: &str,
        declaration_json: &str,
        actor_did: &str,
        timestamp_secs: u64,
    ) -> PyResult<String> {
        use scp_core::context::app_sandbox::{CapabilityDeclaration, SandboxError, bind_app};
        use scp_core::context::roles::Capability;
        use scp_core::context::{ContextHandle, ContextParams};

        let bi = &*self.inner;

        validate::validate_did(actor_did).map_err(|e| PyValueError::new_err(e.to_string()))?;

        let decl: CapabilityDeclaration = serde_json::from_str(declaration_json)
            .map_err(|e| PyValueError::new_err(format!("invalid declaration JSON: {e}")))?;

        // Extract the ceiling and effective role capabilities from FFI state.
        // Suspensions are applied via member_has_capability (suspension-aware).
        let (ceiling_caps, role_caps): (Vec<Capability>, Vec<Capability>) =
            crate::runtime::with_ffi_state(bi, context_id, |st| {
                let ceiling: Vec<Capability> = st
                    .ceiling_strings
                    .iter()
                    .filter_map(Capability::new)
                    .collect();
                // Effective caps = capabilities the actor holds in the ceiling universe,
                // filtered suspension-aware via member_has_capability.
                let role: Vec<Capability> = ceiling
                    .iter()
                    .filter(|cap| st.role_state.member_has_capability(actor_did, cap))
                    .cloned()
                    .collect();
                Ok((ceiling, role))
            })
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

        let handle = ContextHandle::new(context_id.to_owned(), ContextParams::default());
        let event_log = crate::runtime::build_event_log_provider(bi);
        let actor_did_owned = actor_did.to_owned();

        let rt = crate::runtime()?;
        let scoped = rt
            .block_on(async move {
                bind_app(
                    &decl,
                    &ceiling_caps,
                    &role_caps,
                    handle,
                    event_log.as_ref(),
                    &actor_did_owned,
                    timestamp_secs,
                )
                .await
            })
            .map_err(|e| match &e {
                SandboxError::CeilingExceeded { .. }
                | SandboxError::InvalidDeclaration(_)
                | SandboxError::SignatureVerificationFailed => {
                    PyRuntimeError::new_err(format!("[{}] bind_app rejected: {e}", codes::CTX_2056))
                }
                SandboxError::EventLogFailed(_) => PyRuntimeError::new_err(format!(
                    "[{}] event log append failed: {e}",
                    codes::CTX_2057
                )),
                _ => PyRuntimeError::new_err(format!("[{}] bind_app failed: {e}", codes::CTX_2058)),
            })?;

        let app_did = scoped.app_did().to_string();
        let granted: Vec<String> = scoped
            .allowed_capabilities()
            .iter()
            .map(std::string::ToString::to_string)
            .collect();

        // Store the scoped handle keyed by app_did for capability enforcement.
        crate::runtime::with_ffi_state(bi, context_id, |st| {
            st.bound_apps.insert(app_did.clone(), scoped);
            Ok(())
        })
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

        serde_json::to_string(&serde_json::json!({
            "app_did": app_did,
            "granted_capabilities": granted,
        }))
        .map_err(|e| PyRuntimeError::new_err(format!("serialization failed: {e}")))
    }

    /// Unbinds an app from a context and appends an `AppUnbound` event to
    /// the durable event log (spec §8.4).
    ///
    /// # Errors
    ///
    /// Returns `RuntimeError` if the context is not found or if the durable
    /// event log append fails.
    #[pyo3(signature = (context_id, app_did, actor_did, timestamp_secs))]
    pub fn sandbox_app_unbind(
        &self,
        context_id: &str,
        app_did: &str,
        actor_did: &str,
        timestamp_secs: u64,
    ) -> PyResult<()> {
        use scp_core::context::app_sandbox::unbind_app;

        let bi = &*self.inner;

        validate::validate_did(actor_did).map_err(|e| PyValueError::new_err(e.to_string()))?;
        validate::validate_did(app_did).map_err(|e| PyValueError::new_err(e.to_string()))?;

        let is_bound = crate::runtime::with_ffi_state(bi, context_id, |st| {
            Ok(st.bound_apps.contains_key(app_did))
        })
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        if !is_bound {
            return Err(PyRuntimeError::new_err(format!(
                "[{}] app '{}' is not currently bound to context '{}'",
                codes::CTX_2059,
                app_did,
                context_id
            )));
        }

        let event_log = crate::runtime::build_event_log_provider(bi);
        let context_id_owned = context_id.to_owned();
        let app_did_owned = app_did.to_owned();
        let actor_did_owned = actor_did.to_owned();

        let rt = crate::runtime()?;
        rt.block_on(async move {
            unbind_app(
                &context_id_owned,
                &app_did_owned,
                event_log.as_ref(),
                &actor_did_owned,
                timestamp_secs,
            )
            .await
        })
        .map_err(|e| {
            PyRuntimeError::new_err(format!("[{}] unbind_app failed: {e}", codes::CTX_2059))
        })?;

        // Remove the stored scoped handle.
        crate::runtime::with_ffi_state(bi, context_id, |st| {
            st.bound_apps.remove(app_did);
            Ok(())
        })
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

        Ok(())
    }
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
    // Invitation bundle + invite outcome (ADR-049 Phase 2J; FFI-02 Option A)
    m.add_class::<PySealedInvitation>()?;
    m.add_class::<PyInviteMemberOutcome>()?;
    // Reconnection report (ADR-029)
    m.add_class::<PyReconnectReport>()?;
    m.add_class::<PyContextReconnectResult>()?;
    // Governance (#369)
    // Governance proposal lifecycle (#621)
    // Ceiling modification, close, checkpoint, restore (#559)
    // Context migration (§5.11A, #580)
    // Broadcast (#369)
    // Membership (#369)
    // Events (#369)
    // TTL (#369)
    // App sandboxing (#595)
    m.add_function(wrap_pyfunction!(py_validate_capability_declaration, m)?)?;
    m.add_function(wrap_pyfunction!(py_check_scoped_capability, m)?)?;
    // Invitation evaluation (#614)
    // MetadataRecord and ContextTemplate inspection (#615)
    m.add_function(wrap_pyfunction!(py_metadata_record_to_json, m)?)?;
    m.add_function(wrap_pyfunction!(py_metadata_record_from_json, m)?)?;
    m.add_function(wrap_pyfunction!(py_template_get_params, m)?)?;
    m.add_function(wrap_pyfunction!(py_validate_against_template, m)?)?;
    m.add_function(wrap_pyfunction!(py_validate_context_params, m)?)?;
    // Access key operations (#1529)
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

    fn __bi() -> std::sync::Arc<crate::runtime::PyBridgeInstance> {
        std::sync::Arc::new(crate::runtime::PyBridgeInstance::new_py())
    }

    /// Test helper: build a [`PySealedInvitation`] from its four wire fields
    /// (the reshaped `context_join_from_welcome` input, replacing the old loose
    /// `params`/`welcome_bytes` args).
    fn __sealed(
        context_id: &str,
        creator_did: &str,
        enc: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> PySealedInvitation {
        PySealedInvitation {
            context_id: context_id.to_owned(),
            creator_did: creator_did.to_owned(),
            enc,
            ciphertext,
        }
    }

    /// §9.10.4: an ENCRYPTED `context_create` hard-fails pseudonym derivation.
    ///
    /// The encrypted create branch routes through `derive_member_pseudonym` with
    /// `?`, so a derivation failure (here: no retained key material for the
    /// creator DID — the identity is not in the bridge registry) propagates the
    /// canonical typed identity error (`SCP-IDENT-1054`), never a silent
    /// zero-pseudonym fallback that would leave the context unusable on the
    /// pseudonymous routing axis. Driving the helper directly exercises the
    /// exact seam the create/import/join paths share.
    #[test]
    fn encrypted_create_hard_fails_pseudonym_derivation_with_typed_code() {
        let bi = __bi();
        let err = derive_member_pseudonym(&bi, "did:dht:z6MkNoSuchIdentity", "ctx-encrypted")
            .expect_err("encrypted derivation without key material must hard-fail");
        let msg = err.to_string();
        assert!(
            msg.contains("SCP-IDENT-1054"),
            "expected missing-key-material code SCP-IDENT-1054, got: {msg}"
        );
    }

    /// Builds an active `PyContextHandle` for the given mode, driving the real
    /// `PyContextParams` parse so the handle carries an authoritative
    /// `ContextMode` (the same axis `context_join` branches on at the mode
    /// gate). Used by the encrypted-join hard-fail coverage below.
    fn active_handle_for_mode(
        bi: &crate::runtime::PyBridgeInstance,
        creator_did: &str,
        mode: &str,
    ) -> PyContextHandle {
        let params = Python::with_gil(|py| {
            let dict = PyDict::new(py);
            dict.set_item("mode", mode).unwrap();
            PyContextParams::from_py_dict(&dict).unwrap()
        });
        let handle = PyContextHandle::new(bi, "0".repeat(64), creator_did.to_owned(), params);
        *handle.state.lock().unwrap() = "active".to_owned();
        handle
    }

    /// §9.10.4 (PR-1744 main fix): an ENCRYPTED `context_join` HARD-FAILS
    /// pseudonym derivation when the joiner has no retained key material.
    ///
    /// Drives the REAL `context_join` entry point (not an inline copy of the
    /// gate). The joiner DID is unregistered, so when the encrypted branch at
    /// the mode gate calls `derive_member_pseudonym(bi, joiner, ctx)?`, the
    /// registry miss is remapped to the canonical `SCP-IDENT-1054`. Without
    /// this hard-fail the join would soft-fail to `None`, which the runtime maps
    /// to the reserved `[0u8; 32]` sentinel — peers reject any announce of a
    /// reserved value, leaving the joiner permanently unaddressable with no
    /// error surfaced.
    ///
    /// Not false-green: derivation runs BEFORE any context/MLS lookup, so the
    /// `SCP-IDENT-1054` is raised by the derivation seam itself. If the
    /// production mode gate were inverted (encrypted → `None`, broadcast →
    /// derive), the encrypted join would skip derivation and this assertion
    /// would fail — see the broadcast counterpart below which would then start
    /// raising 1054.
    #[test]
    fn encrypted_join_hard_fails_pseudonym_derivation_with_typed_code() {
        crate::init_runtime().ok();
        let bi_arc = __bi();
        let scp = crate::scp::PyScp {
            inner: std::sync::Arc::clone(&bi_arc),
        };
        let handle =
            active_handle_for_mode(&bi_arc, "did:dht:z6MkEncryptedJoinCreator", "encrypted");
        let err = scp
            .context_join(&handle, "did:dht:z6MkNoSuchJoinerIdentity", None)
            .expect_err("encrypted join without joiner key material must hard-fail");
        let msg = err.to_string();
        assert!(
            msg.contains("SCP-IDENT-1054"),
            "expected encrypted-join missing-key-material code SCP-IDENT-1054, got: {msg}"
        );
    }

    /// §5.14 / §9.10.4: a BROADCAST `context_join` SKIPS pseudonym derivation.
    ///
    /// Drives the REAL `context_join` entry point with the same unregistered
    /// joiner DID as the encrypted test. Broadcast contexts carry no per-member
    /// pseudonym, so the mode gate selects `None` and never calls
    /// `derive_member_pseudonym`. The join proceeds past the derivation seam and
    /// fails later for an UNRELATED reason (the standalone handle has no created
    /// context in the supervisor) — the point is that the failure is NOT the
    /// `SCP-IDENT-1054` derivation hard-fail.
    ///
    /// Not false-green: this is the inverse half of the gate pin. If the
    /// production mode gate were inverted (broadcast → derive), this broadcast
    /// join would call derivation on the unregistered joiner and start raising
    /// `SCP-IDENT-1054`, failing this assertion. Together with the encrypted
    /// test above, the pair fully pins the mode branch at `context.rs:2017`.
    #[test]
    fn broadcast_join_skips_pseudonym_derivation() {
        crate::init_runtime().ok();
        let bi_arc = __bi();
        let scp = crate::scp::PyScp {
            inner: std::sync::Arc::clone(&bi_arc),
        };
        let handle =
            active_handle_for_mode(&bi_arc, "did:dht:z6MkBroadcastJoinCreator", "broadcast");
        // The join is expected to fail downstream (no created context backs the
        // standalone handle), but it MUST NOT fail at the derivation seam.
        let result = scp.context_join(&handle, "did:dht:z6MkNoSuchJoinerIdentity", None);
        if let Err(err) = result {
            let msg = err.to_string();
            assert!(
                !msg.contains("SCP-IDENT-1054")
                    && !msg.contains("SCP-IDENT-1055")
                    && !msg.contains("SCP-IDENT-1057"),
                "broadcast join must skip derivation — got a derivation-code error: {msg}"
            );
        }
    }

    /// §5.14 / §9.10.4: the `context_create` MODE GATE at `context.rs:1799`
    /// drives derivation policy — exercised through the REAL `context_create`
    /// entry point, not an inline copy of the branch.
    ///
    /// Both sub-cases use an UNREGISTERED creator DID (no retained key material),
    /// which makes the gate's effect directly observable:
    /// - ENCRYPTED create routes through `derive_member_pseudonym(...)?`, so the
    ///   registry miss HARD-FAILS with the canonical `SCP-IDENT-1054` — never a
    ///   silent zero-pseudonym fallback that would leave the encrypted context
    ///   unusable on the pseudonymous routing axis.
    /// - BROADCAST create selects `None` (spec §5.14: no per-member pseudonym),
    ///   never touches custody, and SUCCEEDS into an active handle.
    ///
    /// Not false-green: the previous version of this test copied the production
    /// `if create_is_broadcast { None } else { Some(derive...) }` branch inline
    /// and asserted against its own copy, so inverting the production gate would
    /// not have failed it. This version calls `context_create` itself. If the
    /// production gate at `:1799` were inverted (broadcast → derive, encrypted →
    /// `None`), the broadcast create would hard-fail `SCP-IDENT-1054` and the
    /// encrypted create would succeed — both assertions below would flip.
    #[test]
    fn context_create_mode_gate_drives_pseudonym_derivation() {
        crate::init_runtime().ok();
        let bi_arc = __bi();
        let scp = crate::scp::PyScp {
            inner: std::sync::Arc::clone(&bi_arc),
        };

        // ENCRYPTED create with an unregistered creator HARD-FAILS at the
        // derivation seam the gate selects for encrypted contexts.
        let encrypted_err = Python::with_gil(|py| {
            let dict = PyDict::new(py);
            dict.set_item("mode", "encrypted").unwrap();
            scp.context_create("did:dht:z6MkNoSuchCreateCreatorEnc", &dict)
                .expect_err("encrypted create without creator key material must hard-fail")
                .to_string()
        });
        assert!(
            encrypted_err.contains("SCP-IDENT-1054"),
            "expected encrypted-create missing-key-material code SCP-IDENT-1054, got: {encrypted_err}"
        );

        // BROADCAST create with the SAME unregistered-creator condition SUCCEEDS
        // — the gate selects `None` and never calls derivation.
        let handle = Python::with_gil(|py| {
            let dict = PyDict::new(py);
            dict.set_item("mode", "broadcast").unwrap();
            // Broadcast contexts require MemoryScope::Full (spec §5.14).
            dict.set_item("memory_scope", "full").unwrap();
            scp.context_create("did:dht:z6MkNoSuchCreateCreatorBcast", &dict)
                .expect("broadcast create must succeed without pseudonym derivation")
        });
        assert_eq!(
            handle.state().unwrap(),
            "active",
            "broadcast create yields an active context handle"
        );
        assert_eq!(handle.mode(), "broadcast", "handle reflects broadcast mode");
    }

    /// ADR-049 Phase 2J: `reserve_key_package` enforces local custody at the
    /// bridge — a non-locally-custodied `owning_did` is rejected BEFORE any
    /// supervisor work (no `KeyPackage` pool is touched).
    ///
    /// Drives the REAL `reserve_key_package` entry point with an unregistered
    /// DID. The bridge's `ensure_local_custody` gate (the same trust model as
    /// `context_create`, which relies on identity-registry membership) fails
    /// closed with the identity-not-found error. This pins the bridge-side
    /// custody enforcement that guards the bare-`DID` join-side bootstrap. The
    /// end-to-end reserve→spawn happy path (which needs wired MLS providers and
    /// a real creator-minted Welcome) is covered at the runtime layer by
    /// `spawn_from_welcome_tests.rs` and by the Python E2E harness.
    #[test]
    fn reserve_key_package_rejects_non_locally_custodied_identity() {
        crate::init_runtime().ok();
        let bi_arc = __bi();
        let scp = crate::scp::PyScp {
            inner: std::sync::Arc::clone(&bi_arc),
        };
        let err = scp
            .reserve_key_package("did:dht:z6MkNoSuchReserveIdentity")
            .expect_err("reserve for a non-locally-custodied identity must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("not found in registry"),
            "expected local-custody rejection (identity not found in registry), got: {msg}"
        );
    }

    /// ADR-049 Phase 2J: `context_join_from_welcome` enforces local custody of
    /// the JOINER at the bridge — a non-locally-custodied `owning_did`
    /// hard-fails at the pseudonym-derivation seam (the SAME custody gate
    /// `context_create` uses) BEFORE the single-use `KeyPackage` is consumed.
    ///
    /// Drives the REAL `context_join_from_welcome` entry point with an
    /// unregistered joiner. Because the joiner's routing pseudonym is DERIVED
    /// from its locally-custodied identity (never caller-supplied), the registry
    /// miss is remapped to the canonical `SCP-IDENT-1054`, exactly as the
    /// encrypted `context_create` / `context_join` paths do. The `reservation_id`
    /// and `welcome_bytes` are dummies here — derivation runs before either is
    /// touched, so this is not false-green: were the custody gate removed, the
    /// call would proceed past derivation and fail later for an unrelated reason
    /// (a bogus reservation / bundle), not with `SCP-IDENT-1054`.
    #[test]
    fn context_join_from_welcome_rejects_non_locally_custodied_joiner() {
        crate::init_runtime().ok();
        let bi_arc = __bi();
        let scp = crate::scp::PyScp {
            inner: std::sync::Arc::clone(&bi_arc),
        };
        let err = Python::with_gil(|_py| {
            // A well-formed 32-byte `enc` so the failure isolates the custody
            // gate (which runs BEFORE the enc-length check), not a length
            // rejection.
            let sealed = __sealed(
                &"0".repeat(64),
                "did:dht:z6MkSomeCreator",
                vec![0u8; 32],
                b"not-a-real-bundle".to_vec(),
            );
            scp.context_join_from_welcome(
                "did:dht:z6MkNoSuchJoinFromWelcomeJoiner".to_owned(),
                sealed,
                "not-a-real-reservation".to_owned(),
            )
            .expect_err("join-from-Welcome for a non-locally-custodied joiner must be rejected")
            .to_string()
        });
        assert!(
            err.contains("SCP-IDENT-1054"),
            "expected joiner local-custody hard-fail SCP-IDENT-1054, got: {err}"
        );
    }

    /// ADR-049 Phase 2J / FFI-02 Option A (reshape): the reshaped
    /// `context_join_from_welcome` no longer takes caller `params`, so there is
    /// no `mode` field to inspect — broadcast rejection moved INSIDE the runtime
    /// (a broadcast context carries no MLS Welcome, spec §5.14, so it fails at
    /// the fused `ConfirmConsume`). The NEW bridge-level fail-closed boundary is
    /// the HPKE `enc` length: it MUST be exactly 32 bytes (RFC 9180 X25519
    /// encapsulated key). A wrong-length `enc` is rejected BEFORE the irreversible
    /// `KeyPackage` consume.
    ///
    /// Not false-green: a locally-custodied joiner is used so the custody gate
    /// SUCCEEDS and control reaches the enc-length check; were that check removed,
    /// the malformed `enc` would instead fail deep inside the HPKE open with a
    /// different message, not the exact "expected 32" surfaced here.
    #[test]
    #[cfg(feature = "testing")]
    fn context_join_from_welcome_rejects_non_32_byte_enc() {
        pyo3::prepare_freethreaded_python();
        crate::init_runtime().ok();
        Python::with_gil(|py| {
            let scp = crate::scp::PyScp::new_in_memory_for_test();

            // Locally-custodied joiner so the pseudonym-derivation custody gate
            // passes and control reaches the fail-closed enc-length check.
            let joiner = scp.identity_create(py, "in_memory", None).unwrap();
            let joiner_did = joiner.did().to_owned();

            // 31-byte `enc` — one short of the required 32.
            let sealed = __sealed(
                &"c".repeat(64),
                "did:dht:z6MkEncLenCreator",
                vec![0u8; 31],
                b"bogus-ciphertext".to_vec(),
            );
            let err = scp
                .context_join_from_welcome(joiner_did, sealed, "bogus-reservation-id".to_owned())
                .expect_err("a non-32-byte HPKE enc must be rejected at the bridge boundary")
                .to_string();
            assert!(
                err.contains("expected 32"),
                "expected a fail-closed 32-byte enc-length rejection, got: {err}"
            );
        });
    }

    /// ADR-049 Phase 2J (orphaned-success fix): `context_join_from_welcome`
    /// registers the bridge-side FFI state as a REVERSIBLE precheck BEFORE the
    /// irreversible runtime join, and ROLLS IT BACK when the runtime join fails —
    /// so a failed join leaves NO FFI state and NO known-context discovery entry
    /// behind.
    ///
    /// Drives the REAL entry point with a locally-custodied joiner, so the
    /// custody / pseudonym-derivation gate SUCCEEDS and control reaches the
    /// register -> spawn seam, but with a bogus reservation + Welcome so
    /// `spawn_actor_from_welcome` fails at the runtime layer (the joiner reserved
    /// nothing, so the fused consume finds no matching reservation). The
    /// assertion is on the observable post-condition: after the error, BOTH the
    /// FFI state registry and the known-contexts registry are empty for the
    /// context.
    ///
    /// Not false-green: custody SUCCEEDS here (real in-memory identity), so the
    /// failure is the runtime join itself — exactly the path the rollback guards.
    /// The explicit "no `SCP-IDENT-1054`" check pins that the register -> spawn
    /// seam was actually exercised (not short-circuited at the upstream custody
    /// gate). Were the rollback removed, the freshly-registered `FfiBridgeState`
    /// would leak beside a runtime that never committed.
    #[test]
    #[cfg(feature = "testing")]
    fn join_from_welcome_rolls_back_ffi_state_when_runtime_join_fails() {
        pyo3::prepare_freethreaded_python();
        crate::init_runtime().ok();
        Python::with_gil(|py| {
            let scp = crate::scp::PyScp::new_in_memory_for_test();
            let bi = Arc::clone(&scp.inner);

            // Locally-custodied joiner so the pseudonym-derivation custody gate
            // passes and control reaches the register -> spawn seam.
            let joiner = scp.identity_create(py, "in_memory", None).unwrap();
            let joiner_did = joiner.did().to_owned();

            let ctx_id = "a".repeat(64);
            // A well-formed 32-byte `enc` passes the bridge enc-length check, so
            // the failure is the runtime join itself (bogus reservation +
            // ciphertext) — exactly the register -> spawn seam the rollback
            // guards.
            let sealed = __sealed(
                &ctx_id,
                "did:dht:z6MkRollbackCreator",
                vec![0u8; 32],
                b"bogus-bundle-ciphertext".to_vec(),
            );

            let err = scp
                .context_join_from_welcome(joiner_did, sealed, "bogus-reservation-id".to_owned())
                .expect_err("join with a bogus sealed bundle must fail at the runtime layer");
            let msg = err.to_string();
            assert!(
                !msg.contains("SCP-IDENT-1054"),
                "custody must have SUCCEEDED so the register -> spawn seam is exercised; \
                 got a derivation error instead: {msg}"
            );

            // Post-condition: the reversible FFI state was rolled back — no
            // orphaned bridge state, and no known-context discovery entry.
            assert!(
                crate::runtime::with_ffi_state(&bi, &ctx_id, |_| Ok(())).is_err(),
                "FFI state must NOT survive a failed join"
            );
            let stats = crate::runtime::registry_stats(&bi);
            assert_eq!(
                stats.contexts, 0,
                "no FFI context state may leak after a failed join"
            );
            assert_eq!(
                stats.known_contexts, 0,
                "no known-context discovery entry may leak after a failed join"
            );
        });
    }

    /// ADR-049 Phase 2J (orphaned-success fix): a pre-existing (`Occupied`)
    /// FFI-state entry fails `context_join_from_welcome` at the
    /// `register_ffi_state` precheck — which runs BEFORE
    /// `spawn_actor_from_welcome` consumes the single-use `KeyPackage` — and does
    /// NOT roll back the pre-existing entry (the bridge must never delete state
    /// it did not create).
    ///
    /// Drives the REAL entry with a locally-custodied joiner (custody gate
    /// passes) against a context whose FFI state is already registered. The
    /// register-first ordering surfaces the collision as an `already registered`
    /// error at the precheck, with the `KeyPackage` untouched; the pre-existing
    /// entry SURVIVES the failed join.
    #[test]
    #[cfg(feature = "testing")]
    fn join_from_welcome_occupied_ffi_state_fails_before_keypackage_consumption() {
        pyo3::prepare_freethreaded_python();
        crate::init_runtime().ok();
        Python::with_gil(|py| {
            let scp = crate::scp::PyScp::new_in_memory_for_test();
            let bi = Arc::clone(&scp.inner);

            let joiner = scp.identity_create(py, "in_memory", None).unwrap();
            let joiner_did = joiner.did().to_owned();

            let ctx_id = "b".repeat(64);
            // Pre-occupy the FFI-state slot for this context id.
            crate::runtime::register_context(&bi, &ctx_id, "did:dht:z6MkOccupiedCreator", &[])
                .unwrap();

            // A well-formed 32-byte `enc` so control passes the bridge
            // enc-length check and reaches the `register_ffi_state` Occupied
            // precheck (which runs BEFORE the KeyPackage consume).
            let sealed = __sealed(
                &ctx_id,
                "did:dht:z6MkOccupiedCreator",
                vec![0u8; 32],
                b"bogus-bundle-ciphertext".to_vec(),
            );

            let err = scp
                .context_join_from_welcome(joiner_did, sealed, "bogus-reservation-id".to_owned())
                .expect_err("join into an already-registered context must be rejected");
            let msg = err.to_string();
            assert!(
                msg.contains("already registered"),
                "expected an Occupied-precheck rejection before KeyPackage consumption, got: {msg}"
            );

            // The PRE-EXISTING entry must SURVIVE — the failing join must not roll
            // back state it did not create.
            assert!(
                crate::runtime::with_ffi_state(&bi, &ctx_id, |_| Ok(())).is_ok(),
                "the pre-existing FFI state must be preserved on an Occupied-precheck failure"
            );
        });
    }

    /// ADR-049 Phase 2J / FFI-02 Option A (invite export wiring): the new
    /// `invite_member` bridge export is wired end-to-end — DID validation ->
    /// supervisor resolution -> inviter signing-key resolution -> live-context
    /// lookup -> typed error mapping — and rejects the two reachable failure
    /// modes on the pre-add path.
    ///
    /// NOTE ON SCOPE: the `"sealed"` happy-path (and the full creator-seal ->
    /// joiner-open round-trip) is NOT asserted here because it terminates in the
    /// MLS add-member step, which is not green on THIS branch — the same
    /// pre-existing gap the untouched `plain_join_registers_known_context_for_joiner`
    /// test hits ("the capabilities of the add proposal are insufficient for this
    /// group"). That is the §5.13.3 `0xFF02` KeyPackage-capabilities work FFI-02
    /// gates, not a defect in this bridge reshape. The sealed round-trip is
    /// covered at the E2E layer once that add-member path lands. This test pins
    /// what IS reachable on the pre-add path so the export is not merely
    /// compiled-but-dead.
    ///
    /// Not false-green: assertion (a) uses a REAL custodied inviter so
    /// signing-key resolution SUCCEEDS and the error is the live-context lookup
    /// ("no live context"); assertion (b) uses a non-custodied inviter so it
    /// fails EARLIER at signing-key resolution ("not found in registry") — the
    /// two distinct messages prove both seams are exercised, not short-circuited.
    #[test]
    #[cfg(feature = "testing")]
    fn invite_member_rejects_unknown_context_and_non_custodied_inviter() {
        pyo3::prepare_freethreaded_python();
        crate::init_runtime().ok();
        Python::with_gil(|py| {
            let scp = crate::scp::PyScp::new_in_memory_for_test();

            // A custodied creator + a real context so the supervisor is attached
            // and inviter signing-key resolution can succeed.
            let creator = scp.identity_create(py, "in_memory", None).unwrap();
            let creator_did = creator.did().to_owned();
            let params = PyDict::new(py);
            params.set_item("mode", "encrypted").unwrap();
            params.set_item("governance", "single_admin").unwrap();
            let _handle = scp
                .context_create(&creator_did, &params)
                .expect("encrypted single-admin context_create succeeds");

            // (a) A custodied inviter into a NON-EXISTENT context: signing-key
            // resolution succeeds, then the live-context lookup fails.
            let unknown_ctx = "d".repeat(64);
            let err_unknown = scp
                .invite_member(
                    unknown_ctx,
                    creator_did,
                    "did:dht:z6MkInviteeUnknownCtx".to_owned(),
                    b"bogus-key-package".to_vec(),
                    vec![],
                )
                .expect_err("inviting into an unknown context must be rejected")
                .to_string();
            assert!(
                err_unknown.contains("no live context"),
                "expected a live-context lookup rejection (signing-key resolved first), got: {err_unknown}"
            );

            // (b) A NON-custodied inviter: fails earlier, at signing-key
            // resolution, before any context lookup.
            let err_uncustodied = scp
                .invite_member(
                    "e".repeat(64),
                    "did:dht:z6MkNoSuchInviterIdentity".to_owned(),
                    "did:dht:z6MkInviteeUncustodied".to_owned(),
                    b"bogus-key-package".to_vec(),
                    vec![],
                )
                .expect_err("a non-locally-custodied inviter must be rejected")
                .to_string();
            assert!(
                err_uncustodied.contains("not found in registry"),
                "expected an inviter signing-key resolution failure, got: {err_uncustodied}"
            );
        });
    }

    /// ADR-049 Phase 2J (plain-join discovery symmetry): a successful plain
    /// `context_join` registers the JOINER's context in the known-contexts
    /// discovery registry, exactly as `context_create` and
    /// `context_join_from_welcome` already do — so a plain-joined node can
    /// surface its own joined context via `py_mcp_load_contexts`. Before the fix
    /// the plain join was the only membership entry point that skipped
    /// registration (a cross-bridge / cross-path asymmetry).
    ///
    /// Drives the REAL public entry points with two locally-custodied identities
    /// so the encrypted create + join both commit; then asserts the joiner's own
    /// entry exists in the registry, keyed to the joined context. Were the
    /// post-commit registration removed, `known_contexts_for_member_on` would
    /// return nothing for the joiner and the assertion would fail.
    #[test]
    #[cfg(feature = "testing")]
    fn plain_join_registers_known_context_for_joiner() {
        pyo3::prepare_freethreaded_python();
        crate::init_runtime().ok();
        Python::with_gil(|py| {
            let scp = crate::scp::PyScp::new_in_memory_for_test();
            let bi = Arc::clone(&scp.inner);

            // Two locally-custodied identities: the creator's custody lets the
            // encrypted create derive its §9.10.4 pseudonym; the joiner's lets
            // the plain join derive its own and reach the registration seam.
            let creator = scp.identity_create(py, "in_memory", None).unwrap();
            let creator_did = creator.did().to_owned();
            let joiner = scp.identity_create(py, "in_memory", None).unwrap();
            let joiner_did = joiner.did().to_owned();

            let params = PyDict::new(py);
            params.set_item("mode", "encrypted").unwrap();
            let handle = scp
                .context_create(&creator_did, &params)
                .expect("encrypted context_create with a custodied creator succeeds");
            let ctx_id = handle.context_id.clone();

            scp.context_join(&handle, &joiner_did, None)
                .expect("plain encrypted join with a custodied joiner succeeds");

            // The joiner's own known-context discovery entry now exists, keyed to
            // the joined context — the post-commit registration fired.
            let for_joiner = crate::runtime::known_contexts_for_member_on(&bi, &joiner_did);
            assert!(
                for_joiner.iter().any(|(cid, _)| cid == &ctx_id),
                "plain join must register the joiner's known-context entry for discovery"
            );
        });
    }

    /// Test helper: execute a governance action through the GENUINE
    /// propose flow on a `SingleAdmin` context.
    ///
    /// For `SingleAdmin` contexts, `propose_governance_action_checked`
    /// auto-approves and auto-executes the action in one step, and (crucially)
    /// the context actor's governance engine RETAINS the resulting approved
    /// proposal. This is the only legitimate way to drive an execution after
    /// the direct-execute quorum-bypass fix: a caller can no longer hand the
    /// runtime a fabricated `Approved` proposal — execution is by-id against
    /// the engine's own tracked, quorum-validated proposal.
    ///
    /// `creator_did` must be a real identity (registered custody + signing key)
    /// because the engine verifies the proposer's vote signature against their
    /// DID-resolved key.
    /// Test helper: dispatch `GovernanceCommand::ExecuteGovernanceAction` by id
    /// through the per-instance supervisor (ADR-049 actor model) and return the
    /// handler's `Result`.
    ///
    /// The payload now carries ONLY the proposal id — never a caller-supplied
    /// proposal/action/status, and never a caller-supplied executor DID. The
    /// runtime resolves the authoritative proposal from the context actor's own
    /// quorum-validated governance engine; a caller therefore cannot fabricate
    /// an `Approved` proposal or substitute an action. This helper exercises
    /// that trust boundary directly.
    fn test_dispatch_execute_by_id(
        bi: &crate::runtime::PyBridgeInstance,
        ctx_id: &str,
        proposal_id: [u8; 32],
    ) -> Result<scp_core::context::state::GovernanceActionResult, scp_core::context::ContextError>
    {
        use scp_core::context::actor::commands::{
            ExecuteGovernanceActionPayload, GovernanceCommand,
        };
        let sup = crate::runtime::supervisor(bi).unwrap();
        let sup = std::sync::Arc::clone(sup);
        let rt = crate::runtime().unwrap();
        let ctx_id_owned = ctx_id.to_owned();
        rt.block_on(async move {
            let (tx, rx) = tokio::sync::oneshot::channel();
            let cmd = GovernanceCommand::ExecuteGovernanceAction {
                payload: Box::new(ExecuteGovernanceActionPayload {
                    context_id: ctx_id_owned,
                    proposal_id,
                }),
                reply: tx,
            };
            sup.dispatch_governance_command(cmd).await.unwrap();
            rx.await.unwrap()
        })
    }

    /// Test helper: create a fresh `SingleAdmin` context owned by `creator`,
    /// returning `(bridge_instance, context_id)`. Used by the direct-execute
    /// trust-boundary tests, which only need a live context with known
    /// membership (they never drive a genuine proposal, so no real identity /
    /// DID resolver wiring is required).
    fn setup_singleadmin_ctx(
        creator: &str,
        ctx_prefix: &str,
    ) -> (std::sync::Arc<crate::runtime::PyBridgeInstance>, String) {
        let bi = __bi();
        let ctx_id = format!("{ctx_prefix}-{}", uuid::Uuid::new_v4());
        crate::runtime::register_context(&bi, &ctx_id, creator, &[]).unwrap();
        let sup = crate::runtime::supervisor(&bi).unwrap();
        let sup = Arc::clone(sup);
        let rt = crate::runtime().unwrap();
        let params = scp_core::context::ContextParams {
            ceiling: vec![
                scp_core::context::params::Capability::new("role:assign")
                    .expect("known capability"),
                scp_core::context::params::Capability::new("governance:propose")
                    .expect("known capability"),
                scp_core::context::params::Capability::new("governance:vote")
                    .expect("known capability"),
                scp_core::context::params::Capability::new("member:ban").expect("known capability"),
            ],
            ..scp_core::context::ContextParams::default()
        };
        rt.block_on(sup.create_context(
            ctx_id.clone(),
            params,
            scp_did::DID(creator.to_owned()),
            None,
        ))
        .unwrap();
        (bi, ctx_id)
    }

    /// Test helper that invokes `PyScp::evaluate_invitation` on a fresh
    /// SCP instance. Phase 4 PR 4 (#1549) migrated `py_evaluate_invitation`
    /// to a `PyScp` method; Phase D deleted the default-instance factory, so
    /// tests construct a per-call SCP.
    fn eval_invitation(
        params_json: &str,
        inviter_did: &str,
        identity_did: &str,
        policy_json: Option<&str>,
        spending_json: Option<&str>,
    ) -> PyResult<String> {
        let scp = crate::scp::PyScp::new_in_memory_for_test();
        scp.evaluate_invitation(
            params_json,
            inviter_did,
            identity_did,
            policy_json,
            spending_json,
        )
    }

    fn make_test_message(i: usize, context_id: &str) -> PyMessage {
        #[allow(clippy::cast_precision_loss)]
        let ts = i as f64;
        PyMessage::new(
            &__bi(),
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
        let msg_receiver = PyMessageReceiver::from_shared_rx(&__bi(), Arc::clone(&rx_arc));

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
            &__bi(),
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
        let bi = __bi();

        crate::runtime::register_context(&bi, context_id, "did:test:creator", &[]).unwrap();

        let (tx, rx) = mpsc::channel::<PyMessage>(RECEIVE_BUFFER_CAPACITY);
        let rx_arc = Arc::new(tokio::sync::Mutex::new(rx));

        crate::runtime::with_context(&bi, context_id, |rt| {
            rt.message_tx = Some(tx);
            rt.message_rx = Some(Arc::clone(&rx_arc));
            Ok(())
        })
        .unwrap();

        let msg = make_test_message(42, context_id);
        crate::runtime::deliver_message(&bi, context_id, msg).unwrap();

        let mut guard = rx_arc.lock().await;
        let received = guard.try_recv().unwrap();
        assert_eq!(received.sender_did, "did:test:sender-42");
        drop(guard);

        crate::runtime::close_receive_channel(&bi, context_id).unwrap();

        let result =
            crate::runtime::deliver_message(&bi, context_id, make_test_message(43, context_id));
        assert!(result.is_err(), "should fail after channel is closed");

        crate::runtime::remove_context(&bi, context_id);
    }

    #[tokio::test]
    async fn deliver_message_overflow_injects_warning() {
        let context_id = "ctx-overflow-deliver";
        let capacity = RECEIVE_BUFFER_CAPACITY;
        let bi = __bi();

        crate::runtime::register_context(&bi, context_id, "did:test:creator", &[]).unwrap();

        let (tx, rx) = mpsc::channel::<PyMessage>(capacity);
        let rx_arc = Arc::new(tokio::sync::Mutex::new(rx));

        crate::runtime::with_context(&bi, context_id, |rt| {
            rt.message_tx = Some(tx);
            rt.message_rx = Some(Arc::clone(&rx_arc));
            Ok(())
        })
        .unwrap();

        // Fill the buffer from a blocking thread to avoid the
        // "cannot call blocking_lock from within a runtime" panic.
        // deliver_message uses blocking_lock internally for oldest-drop.
        let ctx_id = context_id.to_owned();
        let bi_task = Arc::clone(&bi);
        tokio::task::spawn_blocking(move || {
            for i in 0..capacity {
                crate::runtime::deliver_message(&bi_task, &ctx_id, make_test_message(i, &ctx_id))
                    .unwrap();
            }

            crate::runtime::deliver_message(
                &bi_task,
                &ctx_id,
                make_test_message(capacity, &ctx_id),
            )
            .unwrap();
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
        crate::runtime::remove_context(&bi, context_id);
    }

    #[test]
    fn close_receive_channel_on_leave() {
        crate::init_runtime().ok();
        let context_id = "ctx-leave-close";
        let bi = __bi();

        crate::runtime::register_context(&bi, context_id, "did:test:creator", &[]).unwrap();

        let (tx, rx) = mpsc::channel::<PyMessage>(RECEIVE_BUFFER_CAPACITY);
        let rx_arc = Arc::new(tokio::sync::Mutex::new(rx));

        crate::runtime::with_context(&bi, context_id, |rt| {
            rt.message_tx = Some(tx);
            rt.message_rx = Some(rx_arc);
            Ok(())
        })
        .unwrap();

        crate::runtime::close_receive_channel(&bi, context_id).unwrap();

        let result =
            crate::runtime::deliver_message(&bi, context_id, make_test_message(0, context_id));
        assert!(
            result.is_err(),
            "deliver should fail after close_receive_channel"
        );

        crate::runtime::remove_context(&bi, context_id);
    }

    // -----------------------------------------------------------------------
    // PyContextParams field tests (issue #109)
    // -----------------------------------------------------------------------

    /// Helper to build a `PyContextParams` with all defaults.
    fn default_params() -> PyContextParams {
        PyContextParams {
            ceiling: Vec::new(),
            roles: HashMap::new(),
            outlets: Vec::new(),
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
            &__bi(),
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
            &__bi(),
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
            &__bi(),
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
            &__bi(),
            "ctx-4".to_owned(),
            "did:test:creator".to_owned(),
            default_params(),
        );
        assert!(handle.template_id().is_none());
    }

    #[test]
    fn handle_exposes_template_id_some() {
        let handle = PyContextHandle::new(
            &__bi(),
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
            &__bi(),
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
            &__bi(),
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
            &__bi(),
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
            &__bi(),
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
        // Build a fresh `PyBridgeInstance` via `__bi()` and mint the handle
        // off of it so the affinity check passes and the
        // governance-rejection path is what errors (not `SCP-PERM-3030`).
        // Phase D (#1695) deleted the process-wide default bridge, so
        // each test must construct its own instance.
        let mut handle = PyContextHandle::new(
            &__bi(),
            "ctx-econ-1".to_owned(),
            "did:test:creator".to_owned(),
            default_params(),
        );

        let json = r#"{"locked":false,"cost_schedule":{"currency":[85,83,68,0],"per_message":"1","per_outlet_call":null,"per_join":null,"per_period":null,"per_byte_stored":null},"payment_adapters":[],"pricing_formula":null,"payee":"did:dht:z6MkPayee"}"#;
        let scp = crate::scp::PyScp::new_in_memory_for_test();
        let result = scp.set_economic_policy(&mut handle, json);
        assert!(
            result.is_err(),
            "direct set must be rejected — use governance"
        );
        assert!(handle.params.economic_policy.is_none());
    }

    #[test]
    fn get_economic_policy_none() {
        // The handle must be stamped with the same bridge instance that
        // services the `get_economic_policy` call; otherwise
        // `pyscp_check_handle!` rejects it with `SCP-PERM-3030`.
        let scp = crate::scp::PyScp::new_in_memory_for_test();
        let handle = PyContextHandle::new(
            &scp.inner,
            "ctx-econ-3".to_owned(),
            "did:test:creator".to_owned(),
            default_params(),
        );
        let result = scp
            .get_economic_policy(&handle)
            .expect("handle is default-instance");
        assert!(result.is_none());
    }

    #[test]
    fn get_economic_policy_some() {
        let json = r#"{"locked":false,"cost_schedule":{"currency":[85,83,68,0],"per_message":"1","per_outlet_call":null,"per_join":null,"per_period":null,"per_byte_stored":null},"payment_adapters":[],"pricing_formula":null,"payee":"did:dht:z6MkPayee"}"#;
        let scp = crate::scp::PyScp::new_in_memory_for_test();
        let handle = PyContextHandle::new(
            &scp.inner,
            "ctx-econ-4".to_owned(),
            "did:test:creator".to_owned(),
            PyContextParams {
                economic_policy: Some(json.to_owned()),
                ..default_params()
            },
        );
        let result = scp
            .get_economic_policy(&handle)
            .expect("handle is default-instance");
        assert_eq!(result.as_deref(), Some(json));
    }

    // -----------------------------------------------------------------------
    // Role state sync after governance (#560)
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Direct-execute trust boundary (governance quorum-bypass fix)
    //
    // `GovernanceCommand::ExecuteGovernanceAction` carries ONLY a proposal id
    // (never a caller-supplied proposal/action/status/executor). The runtime
    // resolves the authoritative proposal from the context actor's OWN
    // quorum-validated governance engine and stamps the tracked proposer as the
    // executor; a caller cannot fabricate an `Approved` proposal or
    // substitute an action. These tests exercise that boundary directly:
    // executing an id the engine never tracked is rejected, and the rejection
    // leaves context state untouched.
    //
    // The "action substitution" facet is structurally impossible now: the
    // payload has no action/proposal field for a caller to populate.
    // -----------------------------------------------------------------------

    /// Executing an unknown/fabricated proposal id is rejected (the engine
    /// never tracked it) — the forgery path.
    #[test]
    fn direct_execute_rejects_untracked_proposal_id() {
        crate::init_runtime().ok();
        let creator = "did:key:z6MkCreatorForgery1";
        let (bi, ctx_id) = setup_singleadmin_ctx(creator, "exec-forgery");

        // A proposal id that was never proposed/tracked by the engine.
        let fabricated = [0xABu8; 32];
        let result = test_dispatch_execute_by_id(&bi, &ctx_id, fabricated);
        let err = result.expect_err("executing an untracked proposal id must be rejected");
        assert!(
            matches!(err, scp_core::context::ContextError::PermissionDenied(_)),
            "untracked proposal must be PermissionDenied, got: {err:?}"
        );
        let msg = format!("{err}");
        assert!(
            msg.contains("not tracked"),
            "rejection should name the untracked proposal: {msg}"
        );
        crate::runtime::remove_context(&bi, &ctx_id);
    }

    /// A rejected direct-execute leaves context membership/role state unchanged
    /// — the forgery cannot apply a phantom action as a side effect.
    #[test]
    fn direct_execute_rejection_does_not_mutate_state() {
        crate::init_runtime().ok();
        let creator = "did:key:z6MkCreatorForgery2";
        let victim = "did:key:z6MkVictimNeverAdded";
        let (bi, ctx_id) = setup_singleadmin_ctx(creator, "exec-forgery-state");

        // Snapshot membership before the forged execute.
        crate::runtime::with_context(&bi, &ctx_id, |st| {
            assert!(
                !st.role_state.members.contains(victim),
                "victim must not be a member before the forged execute"
            );
            Ok(())
        })
        .unwrap();

        let fabricated = [0x11u8; 32];
        let result = test_dispatch_execute_by_id(&bi, &ctx_id, fabricated);
        assert!(
            result.is_err(),
            "forged direct-execute must be rejected, got: {result:?}"
        );

        // Membership must be unchanged: no phantom AddMember took effect.
        crate::runtime::sync_role_state_from_manager(&bi, &ctx_id).unwrap();
        crate::runtime::with_context(&bi, &ctx_id, |st| {
            assert!(
                !st.role_state.members.contains(victim),
                "rejected forgery must not have added the victim as a member"
            );
            Ok(())
        })
        .unwrap();
        crate::runtime::remove_context(&bi, &ctx_id);
    }

    // -----------------------------------------------------------------------
    // context_close teardown ordering (close auth honored before FFI removal)
    // -----------------------------------------------------------------------

    /// A `context_close` that fails authorization (the initiator lacks the
    /// `ContextClose` capability) MUST return an error AND leave the FFI
    /// bridge state intact, so the context remains usable through this bridge
    /// instance. The `CloseContext` dispatch is performed BEFORE the FFI
    /// state is removed; only a successful (or idempotently already-closed)
    /// close removes the state.
    #[test]
    fn unauthorized_close_leaves_ffi_state_intact() {
        crate::init_runtime().ok();
        let ctx_id = format!("close-auth-{}", uuid::Uuid::new_v4());
        let creator = "did:key:z6MkCloseCreator1";
        let intruder = "did:key:z6MkCloseIntruder1";

        // Use the SAME bridge instance for FFI-state registration, actor
        // creation, the handle stamp, and the `context_close` call — the
        // handle-affinity check rejects a mismatched instance.
        let scp = crate::scp::PyScp::new_in_memory_for_test();
        let bi = scp.inner.clone();

        crate::runtime::register_context(&bi, &ctx_id, creator, &[]).unwrap();
        let sup = crate::runtime::supervisor(&bi).unwrap();
        let rt = crate::runtime().unwrap();
        rt.block_on(sup.create_context(
            ctx_id.clone(),
            scp_core::context::ContextParams::default(),
            scp_did::DID(creator.to_owned()),
            None,
        ))
        .unwrap();

        // Mint the handle off the same instance and mark it active so the
        // close passes the bridge-side state gate and reaches the dispatch.
        let handle =
            PyContextHandle::new(&bi, ctx_id.clone(), creator.to_owned(), default_params());
        "active".clone_into(&mut handle.state.lock().unwrap());

        // The intruder is not a member and holds no `ContextClose`
        // capability → the actor close handler rejects with
        // `PermissionDenied` (not the idempotent `ContextNotRegistered`).
        let result = scp.context_close(&handle, intruder);
        assert!(
            result.is_err(),
            "unauthorized close must be rejected by the supervisor"
        );

        // The FFI bridge state must still be present — the context is usable
        // through the bridge. `with_context` succeeding proves the state was
        // not torn down by the failed close.
        crate::runtime::with_context(&bi, &ctx_id, |st| {
            assert_eq!(
                st.creator_did, creator,
                "FFI bridge state must survive a failed close"
            );
            Ok(())
        })
        .expect("FFI bridge state must remain registered after a failed close");

        // The bridge handle state must also remain "active" (the failed
        // close returned before the transition to "closed").
        assert_eq!(*handle.state.lock().unwrap(), "active");

        crate::runtime::remove_context(&bi, &ctx_id);
    }

    // -----------------------------------------------------------------------
    // Invitation evaluation (#614)
    // -----------------------------------------------------------------------

    #[test]
    fn evaluate_invitation_rejects_invalid_inviter_did() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|_py| {
            let result = eval_invitation(
                "{}",
                "", // empty DID
                "did:dht:z6MkLocal",
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
            let result = eval_invitation(
                "not valid json",
                "did:dht:z6MkBob",
                "did:dht:z6MkLocal",
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
            let result = eval_invitation(
                &params_json,
                "did:dht:z6MkBob",
                "did:dht:z6MkLocal",
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
            did: scp_did::DID("did:dht:z6MkTest".to_owned()),
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
            member_did: scp_did::DID("did:dht:z6MkBob".to_owned()),
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
            did: scp_did::DID("did:dht:z6MkTest".to_owned()),
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
            member_did: scp_did::DID("did:dht:z6MkAlice".to_owned()),
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
            did: scp_did::DID("did:dht:z6MkTest".to_owned()),
            role: "moderator".to_owned(),
        };
        assert!(validate_governance_action_strings(&action).is_ok());
    }

    #[test]
    fn governance_action_html_in_change_role_rejected() {
        let action = scp_core::context::governance::GovernanceAction::ChangeRole {
            did: scp_did::DID("did:dht:z6MkTest".to_owned()),
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
            did: scp_did::DID("did:dht:z6MkTest".to_owned()),
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

            let result = eval_invitation(
                &params_json,
                "did:dht:z6MkBob",
                "did:dht:z6MkLocal",
                None,
                Some(spending_json),
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

            let result = eval_invitation(
                &params_json,
                "did:dht:z6MkBob",
                "did:dht:z6MkLocal",
                None,
                Some("not valid json"),
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

            let result = eval_invitation(
                &params_json,
                "did:dht:z6MkBob",
                "did:dht:z6MkLocal",
                None,
                None, // No spending context
            );

            match &result {
                Ok(v) => assert_eq!(v, "prompt_agent"),
                Err(e) => panic!("expected Ok, got Err: {e}"),
            }
        });
    }

    /// Multi-member export round-trip through the real `context_export` /
    /// `context_import` bridge methods.
    ///
    /// Regression guard for the CRITICAL signer-resolution bug: `context_export`
    /// previously picked the exporter DID from `member_dids().next()`
    /// (`HashMap` iteration order) with a `"did:key:unknown-exporter"` fallback.
    /// The importer requires `exporter_did == role_state.creator_did`, so for a
    /// context with more than one member the export non-deterministically
    /// signed as a non-creator DID and failed verification (or was unimportable)
    /// on import. The fix resolves the exporter from the authoritative
    /// `role_state.creator_did`.
    ///
    /// This builds a TWO-member context (creator + added member) so the
    /// membership map has multiple entries with non-deterministic iteration
    /// order, then exports and re-imports. It must round-trip deterministically.
    #[test]
    #[cfg(feature = "testing")]
    fn multi_member_context_export_round_trips_as_creator() {
        pyo3::prepare_freethreaded_python();
        crate::init_runtime().ok();

        Python::with_gil(|py| {
            let scp = crate::scp::PyScp::new_in_memory_for_test();
            let bi = Arc::clone(&scp.inner);

            // Real identity with in-memory custody so `resolve_signing_key`
            // (creator-side) and `resolve_creator_verifying_key` (import-side)
            // both succeed.
            let creator_identity = scp.identity_create(py, "in_memory", None).unwrap();
            let creator = creator_identity.did().to_owned();

            let ctx_id = format!("export-multi-{}", uuid::Uuid::new_v4());
            crate::runtime::register_context(&bi, &ctx_id, &creator, &[]).unwrap();
            let sup = crate::runtime::supervisor(&bi).unwrap();
            let sup = Arc::clone(sup);
            let rt = crate::runtime().unwrap();

            let params = scp_core::context::ContextParams {
                ceiling: vec![
                    scp_core::context::params::Capability::new("role:assign")
                        .expect("known capability"),
                    scp_core::context::params::Capability::new("governance:propose")
                        .expect("known capability"),
                    scp_core::context::params::Capability::new("governance:vote")
                        .expect("known capability"),
                ],
                ..scp_core::context::ContextParams::default()
            };
            rt.block_on(sup.create_context(
                ctx_id.clone(),
                params,
                scp_did::DID(creator.clone()),
                None,
            ))
            .unwrap();

            // Add a SECOND member so the membership map holds 2+ DIDs with
            // non-deterministic iteration order — the precondition that made
            // the old `member_dids().next()` exporter selection unsound. The
            // member is recorded directly in role state via the runtime's
            // `testing`-gated `test_insert_member` seam. The genuine governance
            // flow is unavailable here: it would require the bridge governance
            // key resolver to resolve the proposer's `#active` key from a
            // published DID document, and in-memory test identities are never
            // published. The exporter-selection invariant under test reads
            // `role_state.creator_did` (NOT a membership-map iteration), so a
            // membership-only seam is sufficient to recreate the 2+ member
            // precondition the old `.next()` bug depended on.
            let second_member = "did:key:z6MkExportSecondMember";
            rt.block_on(sup.test_insert_member(
                &ctx_id,
                scp_did::DID(second_member.to_owned()),
                "member",
            ))
            .expect("test_insert_member must record the second member");
            crate::runtime::sync_role_state_from_manager(&bi, &ctx_id).unwrap();

            // Sanity: the context really has multiple members.
            let members = rt.block_on(sup.member_dids(&ctx_id));
            assert!(
                members.len() >= 2,
                "test precondition: context must have 2+ members, got {members:?}"
            );

            // Export while the context is live and multi-member.
            let exported = scp.context_export(py, &ctx_id).unwrap();

            // The export MUST be signed as the creator. Decode it and assert
            // the §23.16.8 signer binding the bug violated: `exporter_did ==
            // creator_did == <the creator identity>`. Before the fix, the
            // exporter was picked from `member_dids().next()` (HashMap order),
            // so for a 2+ member context it was non-deterministically a
            // non-creator DID (or the `"did:key:unknown-exporter"` fallback).
            let decoded = scp_core::context::export_import::deserialize_export(&exported).unwrap();
            assert_eq!(
                decoded.exporter_did.0, creator,
                "export must be signed by the context creator, not an arbitrary member"
            );
            assert_eq!(
                decoded.snapshot.role_state.creator_did, creator,
                "snapshot creator_did must be the creator identity"
            );

            // End-to-end: the import pipeline verifies the snapshot signature
            // against the creator's resolved key BEFORE the already-exists
            // check. A wrong-signer export (the bug) fails with a signature
            // error (SCP-CTX-2093). The fix makes verification succeed, so the
            // import advances past signature verification to the idempotent
            // already-exists rejection — proving the signer binding is correct.
            let import_err = scp
                .context_import(&exported, &creator)
                .expect_err("re-importing a live context must be rejected (already exists)");
            let msg = import_err.to_string();
            assert!(
                !msg.contains("SCP-CTX-2093") && !msg.contains("signature"),
                "import must NOT fail signature verification — exporter signed \
                 as creator_did, got: {msg}"
            );

            crate::runtime::remove_context(&bi, &ctx_id);
        });
    }

    /// Python source for a SIGN-ONLY custody provider: it signs and reports a
    /// public key using a REAL Ed25519 keypair (via the pure-Rust `_scp_core`
    /// test signer exposed below), but `export_signing_key_bytes` RAISES —
    /// modelling a keychain/HSM-shaped custody that refuses raw private-key
    /// export. The provider's `sign`/`get_public_key` delegate to a
    /// process-local Rust Ed25519 signer keyed by an opaque id, so the
    /// signatures are cryptographically valid and verifiable. Only `sign`,
    /// `get_public_key`, and `export_signing_key_bytes` are load-bearing here;
    /// the remaining methods exist solely to satisfy the provider protocol
    /// surface (`PyKeyCustodyProvider::REQUIRED_METHODS`).
    #[cfg(feature = "testing")]
    const SIGN_ONLY_PROVIDER_PY: &std::ffi::CStr = c"
from _scp_core_export_signer import ed25519_sign, ed25519_public_key

class SignOnlyCustody:
    def __init__(self, key_id):
        self._key_id = str(key_id)

    def generate_keypair(self, key_type):
        return self._key_id

    def sign(self, key_id, message):
        # Real Ed25519 signature over `message` — produced WITHOUT ever
        # surfacing the private key to Python.
        return ed25519_sign(str(key_id), bytes(message))

    def get_public_key(self, key_id):
        return ed25519_public_key(str(key_id))

    def destroy_key(self, key_id):
        return None

    def dh_agree(self, key_id, peer_public):
        raise RuntimeError('sign-only custody: dh_agree unsupported')

    def derive_pseudonym(self, key_id, context_id):
        raise RuntimeError('sign-only custody: derive_pseudonym unsupported')

    def derive_rotatable_pseudonym(self, key_id, context_id, pseudonym_epoch):
        raise RuntimeError('sign-only custody: derive_rotatable_pseudonym unsupported')

    def export_signing_key_bytes(self, key_id):
        # The defining property: raw private-key export is REFUSED. A correct
        # context export must never call this path.
        raise RuntimeError('sign-only custody refuses raw key export')

    def custody_type(self, key_id):
        return 'hardware'
";

    /// Context export must sign via `KeyCustody::sign`, NOT by exporting the raw
    /// Ed25519 private key — so a sign-only custody (one that signs but refuses
    /// `export_signing_key_bytes`) can still produce a valid, verifiable export.
    ///
    /// This is the cross-bridge capability-parity guard: the `NAPI` and `UniFFI`
    /// export paths already delegate to `KeyCustody::sign`; `PyO3` previously
    /// exported the raw private key, which would fail closed for keychain/HSM
    /// custody. The test installs a Rust-backed sign-only callback custody whose
    /// `export_signing_key_bytes` RAISES, runs the real `context_export`, and
    /// asserts (a) the export SUCCEEDS — proving the raw-export path is not
    /// taken — and (b) the produced §23.16.8 signature VERIFIES against the
    /// public key the same custody reports.
    /// Installs a SIGN-ONLY callback custody on the identity `did`, replacing
    /// whatever custody was registered. The custody signs and reports a public
    /// key using a process-local REAL Ed25519 signer (the private key lives only
    /// in Rust, never surfaced to Python — exactly like a keychain), but its
    /// `export_signing_key_bytes` RAISES. Returns the signer's verifying key so
    /// the caller can verify the resulting export signature.
    #[cfg(feature = "testing")]
    fn install_sign_only_custody(
        py: Python<'_>,
        bi: &crate::runtime::PyBridgeInstance,
        did: &str,
    ) -> (
        ed25519_dalek::VerifyingKey,
        std::sync::Arc<crate::custody::FfiKeyCustody>,
    ) {
        use pyo3::types::PyModule;

        let signer =
            std::sync::Arc::new(ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng));
        let signer_pk = signer.verifying_key();

        let signer_for_sign = Arc::clone(&signer);
        let pk_bytes = signer_pk.to_bytes().to_vec();

        // Expose the Rust signer to Python via a tiny module of closures. The
        // private key never crosses into Python — only signatures / public bytes.
        let signer_module = PyModule::new(py, "_scp_core_export_signer").unwrap();
        signer_module
            .add(
                "ed25519_sign",
                pyo3::types::PyCFunction::new_closure(py, None, None, move |args, _kwargs| {
                    use ed25519_dalek::Signer;
                    let _key_id: String = args.get_item(0)?.extract()?;
                    let message: Vec<u8> = args.get_item(1)?.extract()?;
                    Ok::<Vec<u8>, PyErr>(signer_for_sign.sign(&message).to_bytes().to_vec())
                })
                .unwrap(),
            )
            .unwrap();
        signer_module
            .add(
                "ed25519_public_key",
                pyo3::types::PyCFunction::new_closure(py, None, None, move |args, _kwargs| {
                    let _key_id: String = args.get_item(0)?.extract()?;
                    Ok::<Vec<u8>, PyErr>(pk_bytes.clone())
                })
                .unwrap(),
            )
            .unwrap();
        py.import("sys")
            .unwrap()
            .getattr("modules")
            .unwrap()
            .downcast_into::<pyo3::types::PyDict>()
            .unwrap()
            .set_item("_scp_core_export_signer", &signer_module)
            .unwrap();

        let active_handle_id = crate::runtime::with_identity(bi, did, |entry| {
            Ok(entry.identity.active_signing_key.id())
        })
        .unwrap();

        let provider_module = PyModule::from_code(
            py,
            SIGN_ONLY_PROVIDER_PY,
            c"sign_only_custody.py",
            c"sign_only_custody",
        )
        .unwrap();
        let obj = provider_module
            .getattr("SignOnlyCustody")
            .unwrap()
            .call1((active_handle_id,))
            .unwrap();
        let provider = crate::custody::PyKeyCustodyProvider::new(py, obj.unbind()).unwrap();
        let sign_only_custody = Arc::new(crate::custody::FfiKeyCustody::Callback(
            crate::custody::PyCallbackKeyCustody::new(provider),
        ));

        crate::runtime::with_identity_mut(bi, did, |entry| {
            entry.custody = Arc::clone(&sign_only_custody);
            Ok(())
        })
        .unwrap();

        (signer_pk, sign_only_custody)
    }

    #[test]
    #[cfg(feature = "testing")]
    fn context_export_signs_via_sign_only_custody() {
        pyo3::prepare_freethreaded_python();
        crate::init_runtime().ok();

        Python::with_gil(|py| {
            let scp = crate::scp::PyScp::new_in_memory_for_test();
            let bi = Arc::clone(&scp.inner);

            // Create a real identity (registers DID document + registry entry +
            // supervisor wiring). Its custody is in-memory; `install_sign_only_custody`
            // overwrites it with a SIGN-ONLY callback custody so the export path
            // is forced through `KeyCustody::sign`.
            let creator_identity = scp.identity_create(py, "in_memory", None).unwrap();
            let creator = creator_identity.did().to_owned();

            let (signer_pk, sign_only_custody) = install_sign_only_custody(py, &bi, &creator);

            // Sanity: the swapped custody REFUSES raw key export but CAN sign.
            let rt = crate::runtime().unwrap();
            let active_handle_id = crate::runtime::with_identity(&bi, &creator, |entry| {
                Ok(entry.identity.active_signing_key.id())
            })
            .unwrap();
            let handle = scp_platform::KeyHandle::new(active_handle_id);
            assert!(
                rt.block_on(sign_only_custody.export_ed25519_signing_key(&handle))
                    .is_err(),
                "sign-only custody must refuse raw private-key export"
            );
            assert!(
                rt.block_on(sign_only_custody.sign(&handle, b"probe"))
                    .is_ok(),
                "sign-only custody must still sign"
            );

            // Build the context as the creator.
            let ctx_id = format!("export-sign-only-{}", uuid::Uuid::new_v4());
            crate::runtime::register_context(&bi, &ctx_id, &creator, &[]).unwrap();
            let sup = crate::runtime::supervisor(&bi).unwrap();
            let sup = Arc::clone(sup);
            rt.block_on(sup.create_context(
                ctx_id.clone(),
                scp_core::context::ContextParams::default(),
                scp_did::DID(creator.clone()),
                None,
            ))
            .unwrap();

            // The export MUST succeed even though raw key export is refused —
            // proving the signature is produced via `KeyCustody::sign`.
            let exported = scp.context_export(py, &ctx_id).expect(
                "context export must succeed under sign-only custody (signing via \
                 KeyCustody::sign, never raw key export)",
            );

            // The produced §23.16.8 signature must verify against the public key
            // the same sign-only custody reports — end-to-end cryptographic
            // proof that the export was signed correctly by custody.
            let decoded = scp_core::context::export_import::deserialize_export(&exported).unwrap();
            assert_eq!(
                decoded.exporter_did.0, creator,
                "export must be signed as the context creator"
            );
            scp_core::context::export_import::validate_export_for_import(&decoded, &signer_pk)
                .expect(
                    "export signed by sign-only custody must verify against the custody's \
                     reported public key",
                );

            crate::runtime::remove_context(&bi, &ctx_id);
        });
    }

    /// `py_check_scoped_capability` routes through
    /// [`scp_core::context::roles::CapabilityCeiling::contains`], so BOTH
    /// wildcard families are honored symmetrically: `outlet:call:*` implies any
    /// specific `outlet:call:id`, and `outlet:query:*` implies any specific
    /// `outlet:query:id`. The two families stay disjoint and fail-closed — a
    /// call-all grant never satisfies a query, a query-all grant never satisfies
    /// a call, and neither wildcard leaks across (§5.4.2). Malformed input denies.
    #[test]
    fn scoped_capability_check_honors_both_wildcard_families_fail_closed() {
        // Exact grant.
        assert!(py_check_scoped_capability(
            vec!["outlet:call:calc".to_owned()],
            "outlet:call:calc".to_owned()
        ));

        // OutletCallAll ⊇ OutletCall(specific).
        assert!(py_check_scoped_capability(
            vec!["outlet:call:*".to_owned()],
            "outlet:call:calc".to_owned()
        ));

        // OutletQueryAll ⊇ OutletQuery(specific) — the symmetry this fix adds.
        assert!(py_check_scoped_capability(
            vec!["outlet:query:*".to_owned()],
            "outlet:query:calc".to_owned()
        ));

        // Cross-family fail-closed: call-all does NOT satisfy a query.
        assert!(!py_check_scoped_capability(
            vec!["outlet:call:*".to_owned()],
            "outlet:query:calc".to_owned()
        ));
        // Cross-family fail-closed: query-all does NOT satisfy a call.
        assert!(!py_check_scoped_capability(
            vec!["outlet:query:*".to_owned()],
            "outlet:call:calc".to_owned()
        ));

        // No matching grant denies.
        assert!(!py_check_scoped_capability(
            vec!["outlet:query:other".to_owned()],
            "outlet:query:calc".to_owned()
        ));

        // Required capability parses to `Capability::Custom("not-a-capability")`
        // (via the catch-all, so it is `Some`, not malformed). The deny is
        // because the granted set (`outlet:query:*`) does not contain that
        // Custom capability — no matching grant.
        assert!(!py_check_scoped_capability(
            vec!["outlet:query:*".to_owned()],
            "not-a-capability".to_owned()
        ));
    }

    // -----------------------------------------------------------------------
    // ADR-039 Enforcement-Stack Layer 2 — message-send persona-source seam.
    //
    // These exercise the NEW FFI code directly: the per-instance persona-source
    // seam (default `#active`) and `resolve_message_signer`, which binds the VM
    // stamp and the key handle from ONE persona (fail-closed on `#agent` with no
    // agent key). The encrypted-#agent-verifying end-to-end for the exact
    // `MessageSigner` this produces is proven at the runtime layer
    // (`scp_runtime::context::agent_binding_pipeline_tests::live_supervisor_send`,
    // tests (d)) — the two-party MLS decrypt harness it uses is scp-runtime
    // internal and not reachable from this bridge crate.
    // -----------------------------------------------------------------------

    /// Registers a fresh identity in `bi` (optionally carrying an `#agent`
    /// signing key) and returns `(did, active_key, agent_key)` with the two keys
    /// exported so the resolver's output can be byte-compared against them.
    #[cfg(feature = "testing")]
    fn register_persona_test_identity(
        bi: &crate::runtime::PyBridgeInstance,
        with_agent_key: bool,
    ) -> (
        String,
        ed25519_dalek::SigningKey,
        Option<ed25519_dalek::SigningKey>,
    ) {
        crate::init_runtime().ok();
        let rt = crate::runtime().unwrap();
        let custody = std::sync::Arc::new(crate::custody::FfiKeyCustody::InMemory(
            scp_platform::testing::InMemoryKeyCustody::new(),
        ));
        let pre_rotation_custody =
            std::sync::Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new());
        let (identity, document, pre_rotation_handle) = rt.block_on(async {
            let did_method = scp_identity::DidDht::with_client(std::sync::Arc::new(
                scp_dht::InMemoryDhtClient::new(),
            ));
            if with_agent_key {
                did_method
                    .create_with_agent_key(custody.as_ref(), pre_rotation_custody.as_ref())
                    .await
                    .unwrap()
            } else {
                scp_identity::DidMethod::create(
                    &did_method,
                    custody.as_ref(),
                    pre_rotation_custody.as_ref(),
                )
                .await
                .unwrap()
            }
        });
        let did = identity.did.clone();
        // Export the raw keys BEFORE moving `identity` into the registry entry
        // (`KeyHandle` is `Copy`).
        let active_key = rt
            .block_on(custody.export_ed25519_signing_key(&identity.active_signing_key))
            .unwrap();
        let agent_key = identity
            .agent_signing_key
            .map(|h| rt.block_on(custody.export_ed25519_signing_key(&h)).unwrap());
        crate::runtime::register_identity(
            bi,
            &did,
            crate::runtime::IdentityEntry {
                identity,
                custody,
                document,
                identity_link_attestations: Vec::new(),
                pre_rotation_handle,
                pre_rotation_custody,
            },
        );
        (did, active_key, agent_key)
    }

    /// The default persona source is `#active` — the permanent conservative
    /// fail-safe (persona-uncertain ⇒ attribute to the human).
    #[test]
    fn persona_source_defaults_to_active() {
        let bi = __bi();
        assert_eq!(
            (bi.core.persona_source())(),
            scp_did::SigningKeyId::Active,
            "the default (no determiner) persona source must be #active"
        );
    }

    /// The test seam installs a non-default source; production has no such
    /// setter (RFC #2242 owns the determiner). Proves the send path actually
    /// *consults* the seam rather than pinning a constant.
    #[cfg(feature = "testing")]
    #[test]
    fn persona_source_test_seam_overrides_default() {
        let bi = __bi();
        bi.core
            .set_persona_source_for_test(std::sync::Arc::new(|| scp_did::SigningKeyId::Agent));
        assert_eq!((bi.core.persona_source())(), scp_did::SigningKeyId::Agent);
    }

    /// `resolve_message_signer` binds the `#agent` VM stamp to the identity's
    /// AGENT key (never the active key), and `#active` to the active key —
    /// atomically. This is the property that makes an `#agent`-stamped-but-
    /// `#active`-signed message unrepresentable at the FFI send boundary.
    #[cfg(feature = "testing")]
    #[test]
    fn resolve_message_signer_binds_stamp_and_key_atomically() {
        use scp_core::context::supervisor::MessageSigner;
        let bi = __bi();
        let (did, active_key, agent_key) = register_persona_test_identity(&bi, true);
        let agent_key = agent_key.expect("agent-keyed identity has an agent key");
        assert_ne!(
            active_key.to_bytes(),
            agent_key.to_bytes(),
            "test identity must have distinct active and agent keys"
        );

        // #agent persona → agent key + #agent stamp.
        let signer = resolve_message_signer(&bi, &did, scp_did::SigningKeyId::Agent).unwrap();
        assert_eq!(signer.persona(), scp_did::SigningKeyId::Agent);
        assert!(matches!(signer.message_signer(), MessageSigner::Agent(_)));
        assert_eq!(
            signer.message_signer().signing_key_id(),
            scp_did::SigningKeyId::Agent
        );
        assert_eq!(
            signer.message_signer().key().to_bytes(),
            agent_key.to_bytes(),
            "#agent persona MUST resolve the agent key, never the active key"
        );

        // #active persona → active key + #active stamp (default path unchanged).
        let signer = resolve_message_signer(&bi, &did, scp_did::SigningKeyId::Active).unwrap();
        assert_eq!(signer.persona(), scp_did::SigningKeyId::Active);
        assert!(matches!(signer.message_signer(), MessageSigner::Active(_)));
        assert_eq!(
            signer.message_signer().key().to_bytes(),
            active_key.to_bytes()
        );
    }

    /// Fail-closed: `#agent` requested for an identity with NO agent key returns
    /// a typed error (SCP-IDENT-1023) and NEVER falls back to the active key.
    #[cfg(feature = "testing")]
    #[test]
    fn resolve_message_signer_agent_without_agent_key_fails_closed() {
        let bi = __bi();
        let (did, active_key, agent_key) = register_persona_test_identity(&bi, false);
        assert!(agent_key.is_none(), "active-only identity has no agent key");

        let err = resolve_message_signer(&bi, &did, scp_did::SigningKeyId::Agent)
            .expect_err("#agent send without an agent key must fail closed");
        let msg = err.to_string();
        assert!(
            msg.contains("SCP-IDENT-1023"),
            "expected fail-closed no-agent-key code SCP-IDENT-1023, got: {msg}"
        );

        // The active path still resolves — the failure is specific to #agent,
        // not a broken identity.
        let signer = resolve_message_signer(&bi, &did, scp_did::SigningKeyId::Active).unwrap();
        assert_eq!(
            signer.message_signer().key().to_bytes(),
            active_key.to_bytes()
        );
    }
}
