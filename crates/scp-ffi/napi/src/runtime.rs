//! Global runtime registry mapping context IDs to live `scp-core` objects.
//!
//! The NAPI bridge functions accept `&NapiContextHandle` references but need
//! access to real `scp-core` runtime objects (event logs, UCAN revocation
//! lists, nonce trackers). This module provides a global registry that maps
//! context IDs to their associated runtime state.
//!
//! # Lazy registration
//!
//! Unlike the `PyO3` bridge (where `py_context_create` eagerly registers state),
//! the NAPI bridge uses lazy registration: the first UCAN or event log call
//! on a context triggers registration from `NapiContextHandle` metadata. This
//! avoids modifying `context.rs` (which is out of scope for SCP-219).
//!
//! See SCP-219 and ADR-022 in `.docs/adrs/phase-4.md`.

use std::collections::HashSet;
use std::sync::OnceLock;

use dashmap::DashMap;
use scp_core::context::roles::{ContextRoleState, default_ceiling};
use scp_core::context::tools::ToolRegistry;
use scp_core::crypto::ucan::nonce::NonceTracker;
use scp_core::crypto::ucan::revoke::RevocationList;
use scp_event_log::EventLog;
use scp_identity::cache::SystemClock;

use crate::context::NapiContextHandle;
use crate::error::ScpNapiError;

/// Global registry of per-context runtime state.
static CONTEXT_REGISTRY: OnceLock<DashMap<String, ContextRuntime>> = OnceLock::new();

/// Returns a reference to the global context registry.
fn registry() -> &'static DashMap<String, ContextRuntime> {
    CONTEXT_REGISTRY.get_or_init(DashMap::new)
}

/// Per-context runtime state: the live objects needed by bridge functions.
///
/// Each context gets its own tool registry, role state, event log, UCAN
/// revocation list, nonce tracker, and capability ceiling string set. These
/// are created lazily on first access from tool, UCAN, or event log bridge
/// functions.
pub struct ContextRuntime {
    /// Tool registry for this context.
    pub tool_registry: ToolRegistry,
    /// Role state for capability checking.
    pub role_state: ContextRoleState,
    /// Event log (Merkle tree) for this context.
    pub event_log: EventLog,
    /// UCAN revocation list for this context.
    pub revocation_list: RevocationList,
    /// UCAN nonce tracker for replay prevention (ADR-016 step 9).
    pub nonce_tracker: NonceTracker<SystemClock>,
    /// Capability ceiling as a set of `{resource}:{action}` strings for
    /// UCAN validation (ADR-016 step 8).
    pub ceiling_strings: HashSet<String>,
    /// The DID of the context creator.
    pub creator_did: String,
}

// default_ceiling() imported from scp_core::context::roles.

/// Ensures a context is registered in the runtime registry.
///
/// If the context is already registered, this is a no-op. Otherwise, creates
/// runtime state from the `NapiContextHandle` metadata (context ID, creator
/// DID, ceiling).
///
/// # Errors
///
/// Returns `ScpNapiError::Context` if the context state cannot be determined.
pub fn ensure_registered(handle: &NapiContextHandle) -> Result<(), ScpNapiError> {
    let context_id = handle.context_id();
    let map = registry();

    if map.contains_key(&context_id) {
        return Ok(());
    }

    let creator_did = handle.creator_did();
    let handle_ceiling = handle.ceiling();

    let (ceiling_strings, role_state) = if handle_ceiling.is_empty() {
        let ceiling = default_ceiling();
        let strings = ceiling
            .capabilities
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<HashSet<String>>();
        let rs =
            ContextRoleState::new(&context_id, &creator_did, ceiling, vec![]).map_err(|e| {
                ScpNapiError::Context {
                    message: format!("failed to create role state: {e}"),
                    code: "SCP-CTX-2023".to_owned(),
                }
            })?;
        (strings, rs)
    } else {
        let strings = handle_ceiling.iter().cloned().collect::<HashSet<String>>();
        let ceiling = scp_core::context::roles::CapabilityCeiling::new(
            handle_ceiling
                .iter()
                .map(scp_core::context::roles::Capability::new),
        );
        let rs =
            ContextRoleState::new(&context_id, &creator_did, ceiling, vec![]).map_err(|e| {
                ScpNapiError::Context {
                    message: format!("failed to create role state: {e}"),
                    code: "SCP-CTX-2023".to_owned(),
                }
            })?;
        (strings, rs)
    };

    let event_log = EventLog::new(context_id.clone());
    let revocation_list = RevocationList::new(context_id.clone());
    let nonce_tracker = NonceTracker::new(context_id.clone(), SystemClock);

    let runtime = ContextRuntime {
        tool_registry: ToolRegistry::new(),
        role_state,
        event_log,
        revocation_list,
        nonce_tracker,
        ceiling_strings,
        creator_did,
    };

    map.entry(context_id).or_insert(runtime);
    Ok(())
}

/// Executes a closure with mutable access to a context's runtime state.
///
/// Looks up the context by ID in the global registry and calls `f` with a
/// mutable reference to the [`ContextRuntime`]. Uses `DashMap::get_mut` for
/// fine-grained per-key locking.
///
/// # Errors
///
/// Returns `ScpNapiError::Context` if the context is not found.
pub fn with_context<T, F>(context_id: &str, f: F) -> Result<T, ScpNapiError>
where
    F: FnOnce(&mut ContextRuntime) -> Result<T, ScpNapiError>,
{
    let map = registry();

    let mut entry = map
        .get_mut(context_id)
        .ok_or_else(|| ScpNapiError::Context {
            message: format!(
                "context '{context_id}' not found in runtime registry \
             -- call a UCAN or event log function with the context handle first"
            ),
            code: "SCP-CTX-2023".to_owned(),
        })?;

    f(entry.value_mut())
}

/// Removes a context from the global runtime registry.
///
/// Called when a context is closed. All associated runtime objects are dropped.
/// Does not error if the context was not found (idempotent).
#[allow(dead_code)]
pub fn remove_context(context_id: &str) {
    registry().remove(context_id);
}

/// Registers a test context directly in the runtime registry.
///
/// Creates a `ContextRuntime` with the default ceiling, the given creator DID,
/// and empty event log, revocation list, and nonce tracker. This is for unit
/// tests that need to exercise runtime state without constructing a full
/// `NapiContextHandle`.
#[cfg(test)]
#[allow(clippy::expect_used, clippy::missing_panics_doc)] // Test helper — panicking on failure is the correct behavior.
pub fn register_test_context(context_id: &str, creator_did: &str) {
    let map = registry();

    let ceiling = default_ceiling();
    let ceiling_strings = ceiling
        .capabilities
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<HashSet<String>>();
    let role_state = ContextRoleState::new(context_id, creator_did, ceiling, vec![])
        .expect("default ceiling should always produce valid role state in tests");

    let runtime = ContextRuntime {
        tool_registry: ToolRegistry::new(),
        role_state,
        event_log: EventLog::new(context_id.to_owned()),
        revocation_list: RevocationList::new(context_id.to_owned()),
        nonce_tracker: NonceTracker::new(context_id.to_owned(), SystemClock),
        ceiling_strings,
        creator_did: creator_did.to_owned(),
    };

    map.entry(context_id.to_owned()).or_insert(runtime);
}
