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
//! # Context Discovery (SCP-213)
//!
//! The SCP relay is a dumb blob store routing by `RoutingId` -- it has no
//! concept of which DID belongs to which context or what contexts exist.
//! Context discovery is therefore **client-side**: the [`KnownContext`]
//! registry tracks context-to-routing-id-to-relay mappings locally.
//!
//! When `py_mcp_load_contexts` runs, it:
//! 1. Reads locally registered contexts from the [`ContextRuntime`] registry
//! 2. Reads the [`KnownContext`] registry for relay routing metadata
//! 3. If a relay connection is active, probes known routing IDs via QUERY
//! 4. Falls back to local-only when the relay is unreachable
//!
//! # Error Propagation
//!
//! All public functions return `Result<T, ScpPyError>`, propagating typed
//! errors directly to the Python exception hierarchy without string
//! roundtripping.
//!
//! See SCP-163 for the wiring story.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock, RwLock};

use dashmap::DashMap;
use scp_core::context::roles::{Capability, CapabilityCeiling, ContextRoleState};
use scp_core::context::tools::ToolRegistry;
use scp_core::crypto::ucan::nonce::NonceTracker;
use scp_core::crypto::ucan::revoke::RevocationList;
use scp_core::event_log::EventLog;
use scp_core::identity::cache::SystemClock;
use scp_transport::native::adapter::NativeRelayAdapter;

use crate::error::ScpPyError;

/// A sync tool handler function that takes JSON input and returns JSON output.
///
/// Stored in the runtime registry when Python callers register tool handlers
/// via [`register_tool_handler`]. The FFI bridge dispatches tool invocations
/// through these handlers instead of echoing validated input.
///
/// See SCP-212 and ADR-010 for the handler registration design.
pub type ToolHandler =
    Arc<dyn Fn(serde_json::Value) -> Result<serde_json::Value, String> + Send + Sync>;

/// Global registry of per-context runtime state.
static CONTEXT_REGISTRY: OnceLock<DashMap<String, ContextRuntime>> = OnceLock::new();

/// Global registry of known context-to-relay mappings for discovery (SCP-213).
///
/// Tracks contexts that have been created/joined locally, along with their
/// routing IDs and relay URLs. This allows `py_mcp_load_contexts` to probe
/// relays for context activity even across process restarts (when combined
/// with persistence, a future story).
static KNOWN_CONTEXTS: OnceLock<DashMap<String, KnownContext>> = OnceLock::new();

/// Global relay connection for context discovery probing.
///
/// Set by [`set_relay_connection`] when `py_transport_connect` succeeds.
/// Read by `py_mcp_load_contexts` to probe routing IDs on the relay.
/// Uses `RwLock` for infrequent writes (connect) and concurrent reads (probe).
static RELAY_CONNECTION: OnceLock<RwLock<Option<Arc<NativeRelayAdapter>>>> = OnceLock::new();

/// Returns a reference to the global context registry.
fn registry() -> &'static DashMap<String, ContextRuntime> {
    CONTEXT_REGISTRY.get_or_init(DashMap::new)
}

/// Returns a reference to the global known-contexts registry.
fn known_contexts_registry() -> &'static DashMap<String, KnownContext> {
    KNOWN_CONTEXTS.get_or_init(DashMap::new)
}

/// Returns a reference to the global relay connection state.
fn relay_state() -> &'static RwLock<Option<Arc<NativeRelayAdapter>>> {
    RELAY_CONNECTION.get_or_init(|| RwLock::new(None))
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
    /// Registered tool handlers keyed by tool ID.
    ///
    /// Python callers register callable handlers via
    /// [`register_tool_handler`]. When a tool is invoked through
    /// `FfiBridgeProvider::invoke_tool`, the handler is looked up here and
    /// called with the validated JSON input. If no handler is registered,
    /// the invocation falls back to echoing the validated input.
    ///
    /// See SCP-212 for the handler registration design.
    pub tool_handlers: HashMap<String, ToolHandler>,
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
                tool_handlers: HashMap::new(),
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
#[must_use]
pub fn context_ids_for_member(member_did: &str) -> Vec<String> {
    registry()
        .iter()
        .filter(|entry| entry.value().role_state.members.contains(member_did))
        .map(|entry| entry.key().clone())
        .collect()
}

/// Registers a tool handler for a specific tool in a context.
///
/// The handler is a sync closure that takes JSON input and returns JSON
/// output. It is called by `FfiBridgeProvider::invoke_tool` when the
/// tool is invoked via MCP. The handler must already have a corresponding
/// tool registration in the context's `ToolRegistry` (registered via
/// `py_tool_register`).
///
/// # Errors
///
/// Returns `ScpPyError::ContextError` if the context is not found or the
/// tool is not registered in the context's `ToolRegistry`.
pub fn register_tool_handler(
    context_id: &str,
    tool_id: &str,
    handler: ToolHandler,
) -> Result<(), ScpPyError> {
    with_context(context_id, |rt| {
        // Verify the tool exists in the registry before accepting a handler.
        if rt.tool_registry.get(tool_id).is_none() {
            return Err(ScpPyError::ContextError(format!(
                "tool '{tool_id}' not found in context '{context_id}' \
                 -- register the tool before adding a handler"
            )));
        }
        rt.tool_handlers.insert(tool_id.to_owned(), handler);
        Ok(())
    })
}

/// Removes a context from the global runtime registry.
///
/// Called when a context is closed. All associated runtime objects are dropped.
/// Does not error if the context was not found (idempotent).
pub fn remove_context(context_id: &str) {
    registry().remove(context_id);
    // Also remove from known-contexts registry.
    known_contexts_registry().remove(context_id);
}

// ---------------------------------------------------------------------------
// Known context registry (SCP-213: context discovery)
// ---------------------------------------------------------------------------

/// Metadata about a known context's relay presence.
///
/// Stored in the [`KNOWN_CONTEXTS`] registry so that `py_mcp_load_contexts`
/// can probe relays for context activity. The relay is a dumb blob store
/// with no identity-to-context mapping, so the client must track which
/// routing IDs correspond to which contexts.
///
/// See SCP-213 and ADR-015 in `.docs/adrs/phase-3.md`.
#[derive(Debug, Clone)]
pub struct KnownContext {
    /// The context's routing ID (32-byte pseudonym for relay routing).
    pub routing_id: [u8; 32],
    /// The relay URL where this context's blobs are stored.
    pub relay_url: String,
    /// The DID of the member who registered this known context.
    pub member_did: String,
    /// Unix timestamp (seconds) when this context was last seen active.
    pub last_seen: u64,
}

/// Registers a known context in the discovery registry.
///
/// Called after `py_context_create` to record the context's routing ID and
/// relay URL for later discovery via `py_mcp_load_contexts`.
///
/// Overwrites any existing entry for the same context ID (idempotent).
pub fn register_known_context(context_id: &str, known: KnownContext) {
    known_contexts_registry().insert(context_id.to_owned(), known);
}

/// Returns all known contexts from the discovery registry.
///
/// Used by `py_mcp_load_contexts` to find routing IDs to probe on the relay.
#[must_use]
pub fn all_known_contexts() -> Vec<(String, KnownContext)> {
    known_contexts_registry()
        .iter()
        .map(|entry| (entry.key().clone(), entry.value().clone()))
        .collect()
}

/// Returns known contexts where the given DID is the registered member.
#[must_use]
pub fn known_contexts_for_member(member_did: &str) -> Vec<(String, KnownContext)> {
    known_contexts_registry()
        .iter()
        .filter(|entry| entry.value().member_did == member_did)
        .map(|entry| (entry.key().clone(), entry.value().clone()))
        .collect()
}

// ---------------------------------------------------------------------------
// Relay connection state (SCP-213: transport wiring)
// ---------------------------------------------------------------------------

/// Stores a relay adapter connection for use by context discovery.
///
/// Called by `py_transport_connect` after a successful connection. The
/// adapter is wrapped in `Arc` for shared ownership between the transport
/// module and the discovery path in `py_mcp_load_contexts`.
///
/// # Errors
///
/// Returns `ScpPyError::TransportError` if the relay state lock is poisoned.
pub fn set_relay_connection(adapter: Arc<NativeRelayAdapter>) -> Result<(), ScpPyError> {
    *relay_state().write().map_err(|_| {
        ScpPyError::TransportError("relay connection state lock is poisoned".to_owned())
    })? = Some(adapter);
    Ok(())
}

/// Returns the current relay adapter connection, if one is active.
///
/// Used by `py_mcp_load_contexts` to probe routing IDs. Returns `None`
/// if `py_transport_connect` has not been called or the connection was
/// cleared.
///
/// # Errors
///
/// Returns `ScpPyError::TransportError` if the relay state lock is poisoned.
pub fn get_relay_connection() -> Result<Option<Arc<NativeRelayAdapter>>, ScpPyError> {
    let guard = relay_state().read().map_err(|_| {
        ScpPyError::TransportError("relay connection state lock is poisoned".to_owned())
    })?;
    Ok(guard.clone())
}

/// Clears the active relay connection.
///
/// Called when the transport is disconnected. After this, relay-based
/// context discovery in `py_mcp_load_contexts` will fall back to
/// local-only mode.
///
/// # Errors
///
/// Returns `ScpPyError::TransportError` if the relay state lock is poisoned.
pub fn clear_relay_connection() -> Result<(), ScpPyError> {
    *relay_state().write().map_err(|_| {
        ScpPyError::TransportError("relay connection state lock is poisoned".to_owned())
    })? = None;
    Ok(())
}
