//! Global runtime registry mapping context IDs to live `scp-core` objects.
//!
//! The FFI bridge functions accept `context_id: &str` parameters but need
//! access to real `scp-core` runtime objects (tool registries, event logs,
//! UCAN state). This module provides a global registry that maps context IDs
//! to their associated runtime state.
//!
//! # Pattern
//!
//! Uses [`DashMap`] for lock-free concurrent reads. Most bridge operations
//! read context state (`with_context`); writes (`register_context`,
//! `remove_context`) are infrequent. `DashMap` uses internal sharding to
//! eliminate reader contention — critical for free-threaded Python (PEP 703)
//! and high-throughput async workloads.
//!
//! # Lifecycle
//!
//! 1. `py_context_create` calls [`register_context`] to create runtime objects.
//! 2. Bridge functions call [`with_context`] to access runtime objects.
//! 3. `py_context_close` calls [`remove_context`] to clean up.
//!
//! # Error Propagation
//!
//! All public functions return `Result<T, ScpPyError>`, propagating typed
//! errors directly to the Python exception hierarchy without string
//! roundtripping.
//!
//! See SCP-163 for the wiring story.

use std::collections::HashSet;
use std::sync::OnceLock;

use dashmap::DashMap;
use scp_core::context::roles::{Capability, CapabilityCeiling, ContextRoleState};
use scp_core::context::tools::ToolRegistry;
use scp_core::crypto::ucan::nonce::NonceTracker;
use scp_core::crypto::ucan::revoke::RevocationList;
use scp_core::event_log::EventLog;
use scp_core::identity::cache::SystemClock;

use crate::error::ScpPyError;

/// Global registry of per-context runtime state.
static CONTEXT_REGISTRY: OnceLock<DashMap<String, ContextRuntime>> = OnceLock::new();

/// Returns a reference to the global context registry.
fn registry() -> &'static DashMap<String, ContextRuntime> {
    CONTEXT_REGISTRY.get_or_init(DashMap::new)
}

/// Per-context runtime state: the live objects needed by bridge functions.
///
/// Each context gets its own tool registry, event log, role state, UCAN
/// revocation list, nonce tracker, and capability ceiling string set. These
/// are created when `py_context_create` is called and destroyed when
/// `py_context_close` is called.
pub struct ContextRuntime {
    /// Tool registry for this context.
    pub tool_registry: ToolRegistry,
    /// Event log (Merkle tree) for this context.
    pub event_log: EventLog,
    /// Role state tracking member capabilities.
    pub role_state: ContextRoleState,
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
/// Returns `ScpPyError::ContextError` if the context ID is already registered
/// or if role state creation fails.
pub fn register_context(context_id: &str, creator_did: &str) -> Result<(), ScpPyError> {
    use dashmap::mapref::entry::Entry;

    let map = registry();

    match map.entry(context_id.to_owned()) {
        Entry::Occupied(_) => {
            return Err(ScpPyError::ContextError(format!(
                "context '{context_id}' is already registered"
            )));
        }
        Entry::Vacant(vacant) => {
            let tool_registry = ToolRegistry::new();
            let event_log = EventLog::new(context_id.to_owned());
            let ceiling = default_ceiling();
            let ceiling_strings = ceiling
                .capabilities
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<HashSet<String>>();
            let role_state = ContextRoleState::new(context_id, creator_did, ceiling, vec![])
                .map_err(|e| {
                    ScpPyError::ContextError(format!("failed to create role state: {e}"))
                })?;
            let revocation_list = RevocationList::new(context_id.to_owned());
            let nonce_tracker = NonceTracker::new(context_id.to_owned(), SystemClock);

            let runtime = ContextRuntime {
                tool_registry,
                event_log,
                role_state,
                revocation_list,
                nonce_tracker,
                ceiling_strings,
                creator_did: creator_did.to_owned(),
            };

            vacant.insert(runtime);
        }
    }

    Ok(())
}

/// Executes a closure with mutable access to a context's runtime state.
///
/// Looks up the context by ID in the global registry and calls `f` with a
/// mutable reference to the [`ContextRuntime`]. Uses `DashMap::get_mut` for
/// fine-grained per-key locking — only the accessed shard is locked, not the
/// entire registry.
///
/// # Errors
///
/// Returns `ScpPyError::ContextError` if the context is not found.
pub fn with_context<T, F>(context_id: &str, f: F) -> Result<T, ScpPyError>
where
    F: FnOnce(&mut ContextRuntime) -> Result<T, ScpPyError>,
{
    let map = registry();

    let mut entry = map.get_mut(context_id).ok_or_else(|| {
        ScpPyError::ContextError(format!(
            "context '{context_id}' not found in runtime registry \
                 -- was it created with py_context_create?"
        ))
    })?;

    f(entry.value_mut())
}

/// Returns the IDs of all registered contexts where the given DID is a member.
///
/// Used by `py_mcp_load_contexts` to return locally known contexts when
/// relay transport is not yet wired. Returns an empty Vec if no contexts
/// match.
pub fn context_ids_for_member(member_did: &str) -> Vec<String> {
    registry()
        .iter()
        .filter(|entry| entry.value().role_state.members.contains(member_did))
        .map(|entry| entry.key().clone())
        .collect()
}

/// Removes a context from the global runtime registry.
///
/// Called when a context is closed. All associated runtime objects are dropped.
/// Does not error if the context was not found (idempotent).
pub fn remove_context(context_id: &str) {
    registry().remove(context_id);
}
