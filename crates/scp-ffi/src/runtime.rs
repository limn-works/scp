//! Global runtime registry mapping context IDs to live `scp-core` objects.
//!
//! The FFI bridge functions accept `context_id: &str` parameters but need
//! access to real `scp-core` runtime objects (tool registries, event logs,
//! UCAN state). This module provides a global registry that maps context IDs
//! to their associated runtime state.
//!
//! # Pattern
//!
//! Uses `OnceLock<Mutex<HashMap<String, ContextRuntime>>>`, following the
//! same pattern as the `RUNTIME: OnceLock<Runtime>` in `lib.rs` for the
//! tokio runtime.
//!
//! # Lifecycle
//!
//! 1. `py_context_create` calls [`register_context`] to create runtime objects.
//! 2. Bridge functions call [`with_context`] to access runtime objects.
//! 3. `py_context_close` calls [`remove_context`] to clean up.
//!
//! See SCP-163 for the wiring story.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use scp_core::context::roles::{Capability, CapabilityCeiling, ContextRoleState};
use scp_core::context::tools::ToolRegistry;
use scp_core::crypto::ucan::revoke::RevocationList;
use scp_core::event_log::EventLog;

/// Global registry of per-context runtime state.
static CONTEXT_REGISTRY: OnceLock<Mutex<HashMap<String, ContextRuntime>>> = OnceLock::new();

/// Returns a reference to the global context registry mutex.
fn registry() -> &'static Mutex<HashMap<String, ContextRuntime>> {
    CONTEXT_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Per-context runtime state: the live objects needed by bridge functions.
///
/// Each context gets its own tool registry, event log, role state, and UCAN
/// revocation list. These are created when `py_context_create` is called and
/// destroyed when `py_context_close` is called.
pub struct ContextRuntime {
    /// Tool registry for this context.
    pub tool_registry: ToolRegistry,
    /// Event log (Merkle tree) for this context.
    pub event_log: EventLog,
    /// Role state tracking member capabilities.
    pub role_state: ContextRoleState,
    /// UCAN revocation list for this context.
    pub revocation_list: RevocationList,
    /// The DID of the context creator.
    pub creator_did: String,
}

/// Default capability ceiling for new contexts.
///
/// Includes all standard SCP capabilities. This matches the ceiling used in
/// scp-core test helpers.
fn default_ceiling() -> CapabilityCeiling {
    CapabilityCeiling::new([
        Capability::MessagesRead,
        Capability::MessagesWrite,
        Capability::ToolRegister,
        Capability::ToolInvokeAll,
        Capability::RoleAssign,
        Capability::MemberInvite,
        Capability::MemberRemove,
        Capability::GovernancePropose,
        Capability::GovernanceVote,
        Capability::ContextClose,
    ])
}

/// Registers a new context in the global runtime registry.
///
/// Creates a [`ToolRegistry`], [`EventLog`], [`ContextRoleState`], and
/// [`RevocationList`] for the context. The creator DID is assigned admin
/// capabilities (all capabilities in the ceiling).
///
/// # Errors
///
/// Returns an error message if the context ID is already registered or if
/// role state creation fails.
pub fn register_context(context_id: &str, creator_did: &str) -> Result<(), String> {
    let mut map = registry()
        .lock()
        .map_err(|_| "context registry lock is poisoned".to_owned())?;

    if map.contains_key(context_id) {
        return Err(format!("context '{context_id}' is already registered"));
    }

    let tool_registry = ToolRegistry::new();
    let event_log = EventLog::new(context_id.to_owned());
    let role_state =
        ContextRoleState::new(context_id, creator_did, default_ceiling(), vec![])
            .map_err(|e| format!("failed to create role state: {e}"))?;
    let revocation_list = RevocationList::new(context_id.to_owned());

    let runtime = ContextRuntime {
        tool_registry,
        event_log,
        role_state,
        revocation_list,
        creator_did: creator_did.to_owned(),
    };

    map.insert(context_id.to_owned(), runtime);
    Ok(())
}

/// Executes a closure with mutable access to a context's runtime state.
///
/// Looks up the context by ID in the global registry and calls `f` with a
/// mutable reference to the [`ContextRuntime`].
///
/// # Errors
///
/// Returns an error message if the context is not found or the registry lock
/// is poisoned.
pub fn with_context<T, F>(context_id: &str, f: F) -> Result<T, String>
where
    F: FnOnce(&mut ContextRuntime) -> Result<T, String>,
{
    let mut map = registry()
        .lock()
        .map_err(|_| "context registry lock is poisoned".to_owned())?;

    let runtime = map
        .get_mut(context_id)
        .ok_or_else(|| {
            format!(
                "context '{context_id}' not found in runtime registry \
                 -- was it created with py_context_create?"
            )
        })?;

    f(runtime)
}

/// Removes a context from the global runtime registry.
///
/// Called when a context is closed. All associated runtime objects are dropped.
///
/// # Errors
///
/// Returns an error message if the registry lock is poisoned. Does not error
/// if the context was not found (idempotent).
pub fn remove_context(context_id: &str) -> Result<(), String> {
    let mut map = registry()
        .lock()
        .map_err(|_| "context registry lock is poisoned".to_owned())?;

    map.remove(context_id);
    Ok(())
}
