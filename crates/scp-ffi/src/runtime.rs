//! Global runtime registry mapping context IDs to live `scp-core` objects.
//!
//! The FFI bridge functions accept `context_id: &str` parameters but need
//! access to real `scp-core` runtime objects (tool registries, event logs,
//! UCAN state). This module provides a global registry that maps context IDs
//! to their associated runtime state.
//!
//! # Safety: Single-Tenant Only (RED-017)
//!
//! **All registries in this module are process-global.** In multi-tenant
//! deployments (e.g., Django/FastAPI serving multiple SCP users), all tenants
//! share these registries. Context IDs and identity DIDs from one tenant are
//! accessible to another. This is a known architectural limitation.
//!
//! The NAPI (`Node.js`), `UniFFI` (Swift/Kotlin), and WASM bridges avoid this
//! issue by using per-instance handle objects instead of global registries.
//! The `PyO3` bridge must be refactored to match. See SCP-228.
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
use scp_core::context::roles::{ContextRoleState, default_ceiling};
use scp_core::context::tools::ToolRegistry;
use scp_core::crypto::ucan::nonce::NonceTracker;
use scp_core::crypto::ucan::revoke::RevocationList;
use scp_core::event_log::EventLog;
use scp_core::identity::cache::SystemClock;
use scp_core::identity::{DidDocument, ScpIdentity};
use scp_platform::testing::{InMemoryKeyCustody, InMemoryStorage};
use scp_transport::native::adapter::NativeRelayAdapter;
use tokio::sync::mpsc;

use crate::context::PyMessage;
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
///
/// # Safety: Single-Tenant Only
///
/// This registry is process-global. In multi-tenant deployments (e.g., a web
/// server serving multiple SCP users), ALL tenants share this registry. Context
/// IDs and identity DIDs from one tenant are accessible to another. This is a
/// known architectural limitation tracked for resolution before production
/// multi-tenant deployment.
///
/// See RED-017 in the security review. Follow-on story: SCP-228.
static CONTEXT_REGISTRY: OnceLock<DashMap<String, ContextRuntime>> = OnceLock::new();

/// Global registry of known context-to-relay mappings for discovery (SCP-213).
///
/// Tracks contexts that have been created/joined locally, along with their
/// routing IDs and relay URLs. This allows `py_mcp_load_contexts` to probe
/// relays for context activity even across process restarts (when combined
/// with persistence, a future story).
///
/// # Safety: Single-Tenant Only
///
/// This registry is process-global. In multi-tenant deployments (e.g., a web
/// server serving multiple SCP users), ALL tenants share this registry. Context
/// IDs and identity DIDs from one tenant are accessible to another. This is a
/// known architectural limitation tracked for resolution before production
/// multi-tenant deployment.
///
/// See RED-017 in the security review. Follow-on story: SCP-228.
static KNOWN_CONTEXTS: OnceLock<DashMap<String, KnownContext>> = OnceLock::new();

/// Global relay connection for context discovery probing.
///
/// Set by [`set_relay_connection`] when `py_transport_connect` succeeds.
/// Read by `py_mcp_load_contexts` to probe routing IDs on the relay.
/// Uses `RwLock` for infrequent writes (connect) and concurrent reads (probe).
///
/// # Safety: Single-Tenant Only
///
/// This registry is process-global. In multi-tenant deployments (e.g., a web
/// server serving multiple SCP users), ALL tenants share this registry. Context
/// IDs and identity DIDs from one tenant are accessible to another. This is a
/// known architectural limitation tracked for resolution before production
/// multi-tenant deployment.
///
/// See RED-017 in the security review. Follow-on story: SCP-228.
static RELAY_CONNECTION: OnceLock<RwLock<Option<Arc<NativeRelayAdapter>>>> = OnceLock::new();

/// Global identity registry mapping DID strings to retained identity state.
///
/// Stores the [`ScpIdentity`] (with opaque [`KeyHandle`]s), the
/// [`Arc<InMemoryKeyCustody>`] that owns the key material, and the
/// [`DidDocument`]. This allows bridge functions to perform crypto
/// operations (signing, pseudonym derivation, key rotation) without private
/// key material crossing the FFI boundary (ADR-006).
///
/// Uses [`DashMap`] for lock-free concurrent access matching the context
/// registry pattern.
static IDENTITY_REGISTRY: OnceLock<DashMap<String, IdentityEntry>> = OnceLock::new();

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

/// Buffer capacity for the receive channel (SCP-216, sketch.md §receive).
///
/// When the buffer is full, the oldest unconsumed event is dropped and a
/// `BufferOverflow` warning is injected into the stream.
pub const RECEIVE_BUFFER_CAPACITY: usize = 1000;

/// Returns a reference to the global identity registry.
fn identity_registry() -> &'static DashMap<String, IdentityEntry> {
    IDENTITY_REGISTRY.get_or_init(DashMap::new)
}

// ---------------------------------------------------------------------------
// Identity registry (SCP-214: KeyCustody wiring)
// ---------------------------------------------------------------------------

/// Retained identity state for a single DID.
///
/// Stores the [`ScpIdentity`] (opaque key handles), the [`InMemoryKeyCustody`]
/// that owns the key material, and the [`DidDocument`]. The custody provider
/// is behind an `Arc` so it can be shared with context-scoped operations
/// (pseudonym derivation, signing, UCAN minting) without moving or cloning
/// the key material.
///
/// See ADR-006 and SCP-214 criterion 3.
pub struct IdentityEntry {
    /// The scp-core identity handle (DID string, key handles, pre-rotation).
    pub identity: ScpIdentity,
    /// The key custody provider that manages the actual key material.
    pub custody: Arc<InMemoryKeyCustody>,
    /// The DID document for this identity.
    pub document: DidDocument,
}

/// Registers an identity in the global identity registry.
///
/// Called by `py_identity_create` after successfully creating an identity.
/// Subsequent bridge functions (UCAN minting, pseudonym derivation, key
/// rotation) look up the identity by DID to access the retained custody
/// provider and key handles.
///
/// Overwrites any existing entry for the same DID (idempotent).
pub fn register_identity(did: &str, entry: IdentityEntry) {
    identity_registry().insert(did.to_owned(), entry);
}

/// Executes a closure with a reference to an identity's retained state.
///
/// Looks up the identity by DID in the global registry and calls `f` with
/// a reference to the [`IdentityEntry`]. Uses `DashMap::get` for fine-grained
/// per-key locking.
///
/// # Errors
///
/// Returns `ScpPyError::IdentityError` if the DID is not found.
pub fn with_identity<T, F>(did: &str, f: F) -> Result<T, ScpPyError>
where
    F: FnOnce(&IdentityEntry) -> Result<T, ScpPyError>,
{
    let entry = identity_registry().get(did).ok_or_else(|| {
        ScpPyError::IdentityError(format!(
            "identity '{did}' not found in registry \
             -- was it created with py_identity_create?"
        ))
    })?;

    f(entry.value())
}

/// Executes a closure with mutable access to an identity's retained state.
///
/// # Errors
///
/// Returns `ScpPyError::IdentityError` if the DID is not found.
pub fn with_identity_mut<T, F>(did: &str, f: F) -> Result<T, ScpPyError>
where
    F: FnOnce(&mut IdentityEntry) -> Result<T, ScpPyError>,
{
    let mut entry = identity_registry().get_mut(did).ok_or_else(|| {
        ScpPyError::IdentityError(format!(
            "identity '{did}' not found in registry \
             -- was it created with py_identity_create?"
        ))
    })?;

    f(entry.value_mut())
}

/// Returns `true` if the identity registry contains an entry for the given DID.
///
/// Used by `py_identity_load` to check whether a loaded identity has live
/// crypto state before returning it. Without registry presence, a loaded
/// identity would be a dangling handle (SCP-IDENT-1010).
#[must_use]
pub fn identity_registry_contains(did: &str) -> bool {
    identity_registry().contains_key(did)
}

/// Removes an identity from the global registry.
///
/// Called when an identity is migrated to a new DID. The old entry is
/// removed and the new entry is registered under the new DID.
pub fn remove_identity(did: &str) {
    identity_registry().remove(did);
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
    /// Sender half of the receive channel (SCP-216).
    ///
    /// Stored here so that the transport layer (and `deliver_message`) can
    /// feed messages into the channel. The receiver half is held by the
    /// `PyMessageReceiver` returned from `py_context_receive`. Dropping
    /// the sender closes the channel, causing `__anext__` to raise
    /// `StopAsyncIteration`.
    pub message_tx: Option<mpsc::Sender<PyMessage>>,
    /// Shared reference to the receiver half of the receive channel (SCP-216).
    ///
    /// Shared with `PyMessageReceiver` via `Arc`. Used by `deliver_message`
    /// to implement oldest-drop overflow: when the buffer is full, the
    /// oldest item is popped from the receiver before sending the new one.
    /// Uses `tokio::sync::Mutex` so the lock can be held across `.await`
    /// points in `__anext__`.
    pub message_rx: Option<Arc<tokio::sync::Mutex<mpsc::Receiver<PyMessage>>>>,
}

// default_ceiling() imported from scp_core::context::roles.

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
                message_tx: None,
                message_rx: None,
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
/// Dropping the `ContextRuntime` also drops `message_tx`, which closes the
/// receive channel and causes `__anext__` to raise `StopAsyncIteration`.
/// Does not error if the context was not found (idempotent).
pub fn remove_context(context_id: &str) {
    registry().remove(context_id);
    known_contexts_registry().remove(context_id);
}

/// Closes the receive channel for a context by dropping the sender (SCP-216).
///
/// Called by `py_context_leave` when a member leaves. Dropping the sender
/// causes any `PyMessageReceiver` holding the receiver half to observe
/// channel closure: `recv()` returns `None` and `__anext__` raises
/// `StopAsyncIteration`.
///
/// Does nothing if no channel was open (idempotent).
///
/// # Errors
///
/// Returns `ScpPyError::ContextError` if the context is not found.
pub fn close_receive_channel(context_id: &str) -> Result<(), ScpPyError> {
    with_context(context_id, |rt| {
        rt.message_tx.take();
        rt.message_rx.take();
        Ok(())
    })
}

/// Delivers a message to a context's receive channel (SCP-216).
///
/// Implements oldest-drop overflow per sketch.md: when the buffer is full
/// (1000 events), exactly 1 oldest unconsumed event is popped from the
/// receiver, and the new message is sent in the freed slot. If there is
/// additional capacity after the send (i.e. the consumer drained an item
/// between the pop and the send), a `BufferOverflow` warning is also
/// injected so consumers can track drop events.
///
/// The function extracts channel references from the runtime registry (brief
/// `DashMap` shard lock), then operates on the channel outside the lock to
/// avoid holding the shard lock during overflow handling.
///
/// # Errors
///
/// Returns `ScpPyError::ContextError` if the context is not found, has no
/// active receive channel, or if the channel is closed.
pub fn deliver_message(context_id: &str, message: PyMessage) -> Result<(), ScpPyError> {
    let (tx, rx_arc) = with_context(context_id, |rt| {
        let tx = rt.message_tx.clone().ok_or_else(|| {
            ScpPyError::ContextError(format!(
                "context '{context_id}' has no active receive channel \
                 -- call py_context_receive first"
            ))
        })?;
        let rx = rt.message_rx.clone().ok_or_else(|| {
            ScpPyError::ContextError("receive channel has no shared receiver reference".to_owned())
        })?;
        Ok((tx, rx))
    })?;

    match tx.try_send(message.clone()) {
        Ok(()) => Ok(()),
        Err(mpsc::error::TrySendError::Full(_)) => {
            // Use blocking_lock() instead of try_lock() to guarantee
            // oldest-drop semantics. try_lock() would drop the NEW message
            // on lock contention -- the opposite of documented behavior
            // (RED-021). The lock is only held for a single try_recv()
            // (VecDeque pop_front), so blocking is brief and safe.
            let mut rx_guard = rx_arc.blocking_lock();

            let _ = rx_guard.try_recv();
            drop(rx_guard);

            tx.try_send(message).map_err(|e| {
                ScpPyError::ContextError(format!(
                    "failed to deliver message to context '{context_id}' \
                     after overflow drop: {e}"
                ))
            })?;

            #[allow(clippy::cast_precision_loss)]
            // Unix timestamp seconds fit in f64 mantissa for centuries.
            let overflow_warning = PyMessage::new(
                "scp:system".to_owned(),
                b"BufferOverflow: oldest event dropped due to full receive buffer".to_vec(),
                scp_core::time::now_secs().map_or(0.0, |s| s as f64),
                context_id.to_owned(),
            );
            let _ = tx.try_send(overflow_warning);
            Ok(())
        }
        Err(mpsc::error::TrySendError::Closed(_)) => Err(ScpPyError::ContextError(format!(
            "receive channel for context '{context_id}' is closed"
        ))),
    }
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
    /// The relay URL where this context's blobs are stored. `None` if no relay
    /// was connected at registration time.
    pub relay_url: Option<String>,
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
// Storage provider registry (SCP-217: identity persistence)
// ---------------------------------------------------------------------------

/// Global storage provider for identity persistence.
///
/// Injected via [`init_storage`] at Python initialization time. Bridge
/// functions use [`get_storage`] to access the provider for storing and
/// loading identity state. The storage backend is `InMemoryStorage` for
/// now -- persistent backends (`SQLite` via [`SqliteStorage`]) will replace it
/// when platform storage adapters land.
///
/// Uses the same `OnceLock` pattern as `CONTEXT_REGISTRY` and
/// `RELAY_CONNECTION`. The `Arc` enables shared ownership across bridge
/// functions without lifetime issues.
///
/// See spec section 17.3 for key conventions and section 17.4 for
/// `ProtocolStore` design.
///
/// # Safety: Single-Tenant Only
///
/// This registry is process-global. In multi-tenant deployments,
/// ALL tenants share the storage provider. See RED-017 / SCP-228.
static STORAGE_PROVIDER: OnceLock<Arc<InMemoryStorage>> = OnceLock::new();

/// Initializes the global storage provider.
///
/// Must be called before any storage-dependent bridge function
/// (`py_identity_create`, `py_identity_load`). Calling multiple times is
/// a no-op — the first call wins.
///
/// # Arguments
///
/// * `storage_type` — Currently only `"in_memory"` is supported.
///
/// # Errors
///
/// Returns `ScpPyError::ValidationError` if the storage type is not
/// recognized.
pub fn init_storage(storage_type: &str) -> Result<(), ScpPyError> {
    match storage_type {
        "in_memory" => {
            let _ = STORAGE_PROVIDER.set(Arc::new(InMemoryStorage::new()));
            Ok(())
        }
        other => Err(ScpPyError::ValidationError(format!(
            "unknown storage type: {other:?} — expected \"in_memory\""
        ))),
    }
}

/// Returns a reference to the global storage provider.
///
/// # Errors
///
/// Returns `ScpPyError::IdentityError` if storage has not been initialized
/// via [`init_storage`].
pub fn get_storage() -> Result<&'static Arc<InMemoryStorage>, ScpPyError> {
    STORAGE_PROVIDER.get().ok_or_else(|| {
        ScpPyError::IdentityError(
            "storage not initialized — call py_init_storage(\"in_memory\") first".to_owned(),
        )
    })
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

// ---------------------------------------------------------------------------
// Registry statistics and cleanup (issue #108)
// ---------------------------------------------------------------------------

/// Entry counts for all global FFI registries.
///
/// Returned by [`registry_stats`] for monitoring and debugging. Allows
/// Python callers to observe registry growth in long-running processes
/// without accessing the registries directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryStats {
    /// Number of entries in the context runtime registry.
    pub contexts: usize,
    /// Number of entries in the known-contexts discovery registry.
    pub known_contexts: usize,
    /// Number of entries in the identity registry.
    pub identities: usize,
    /// Whether a relay connection is currently active.
    pub relay_connected: bool,
}

/// Returns current entry counts for all global registries.
///
/// Intended for monitoring and debugging in long-running processes.
/// All reads are lock-free (`DashMap`) or brief (`RwLock` on relay state).
///
/// # Errors
///
/// Returns `ScpPyError::TransportError` if the relay state lock is poisoned.
pub fn registry_stats() -> Result<RegistryStats, ScpPyError> {
    let relay_connected = relay_state()
        .read()
        .map_err(|_| {
            ScpPyError::TransportError("relay connection state lock is poisoned".to_owned())
        })?
        .is_some();

    Ok(RegistryStats {
        contexts: registry().len(),
        known_contexts: known_contexts_registry().len(),
        identities: identity_registry().len(),
        relay_connected,
    })
}

/// Removes an identity from the global registry.
///
/// Returns `true` if the identity was present and removed, `false` if not found.
/// Provided as a cleanup mechanism for long-running processes alongside
/// [`remove_identity`] which is unconditional.
#[must_use]
pub fn remove_identity_if_present(did: &str) -> bool {
    identity_registry().remove(did).is_some()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Helper to generate unique context IDs for parallel test isolation.
    fn unique_ctx_id(prefix: &str) -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        format!(
            "{prefix}-cleanup-test-{}",
            COUNTER.fetch_add(1, Ordering::Relaxed)
        )
    }

    /// Helper to create a minimal `DidDocument` for testing.
    fn test_did_document(did: &str) -> DidDocument {
        DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
            id: did.to_owned(),
            verification_method: vec![],
            authentication: vec![],
            assertion_method: vec![],
            also_known_as: vec![],
            service: vec![],
        }
    }

    #[test]
    fn registry_stats_reflects_context_registration() {
        let ctx_id = unique_ctx_id("stats-ctx");
        let creator = "did:dht:z6MkStatsTest";

        register_context(&ctx_id, creator).unwrap();
        let stats = registry_stats().unwrap();

        // Verify that stats reports at least 1 context (our registered one).
        // Cannot assert exact counts due to parallel test interference.
        assert!(
            stats.contexts >= 1,
            "should have at least 1 context after registration (got {})",
            stats.contexts,
        );

        // Verify the specific entry exists via direct registry access.
        assert!(
            registry().contains_key(&ctx_id),
            "registered context should be in registry"
        );

        remove_context(&ctx_id);
        assert!(
            !registry().contains_key(&ctx_id),
            "removed context should not be in registry"
        );
    }

    #[test]
    fn registry_stats_reflects_identity_registration() {
        let did = "did:dht:z6MkStatsIdentityUnique9988";

        let entry = IdentityEntry {
            identity: ScpIdentity {
                did: did.to_owned(),
                identity_key: scp_platform::KeyHandle::new(0),
                active_signing_key: scp_platform::KeyHandle::new(0),
                pre_rotation_commitment: [0u8; 32],
            },
            custody: Arc::new(InMemoryKeyCustody::new()),
            document: test_did_document(did),
        };
        register_identity(did, entry);
        let stats = registry_stats().unwrap();

        assert!(
            stats.identities >= 1,
            "should have at least 1 identity after registration (got {})",
            stats.identities,
        );
        assert!(
            identity_registry().contains_key(did),
            "registered identity should be in registry"
        );

        remove_identity(did);
        assert!(
            !identity_registry().contains_key(did),
            "removed identity should not be in registry"
        );
    }

    #[test]
    fn registry_stats_reflects_known_context_registration() {
        let ctx_id = unique_ctx_id("stats-known");
        let known = KnownContext {
            routing_id: [0xCC; 32],
            relay_url: None,
            member_did: "did:dht:z6MkStatsKnown".to_owned(),
            last_seen: 0,
        };

        register_known_context(&ctx_id, known);
        let stats = registry_stats().unwrap();

        assert!(
            stats.known_contexts >= 1,
            "should have at least 1 known context after registration (got {})",
            stats.known_contexts,
        );
        assert!(
            known_contexts_registry().contains_key(&ctx_id),
            "registered known context should be in registry"
        );

        // remove_context clears both registries.
        remove_context(&ctx_id);
        assert!(
            !known_contexts_registry().contains_key(&ctx_id),
            "removed known context should not be in registry"
        );
    }

    #[test]
    fn remove_identity_if_present_returns_true_when_found() {
        let did = "did:dht:z6MkRemoveIfPresent";
        let entry = IdentityEntry {
            identity: ScpIdentity {
                did: did.to_owned(),
                identity_key: scp_platform::KeyHandle::new(0),
                active_signing_key: scp_platform::KeyHandle::new(0),
                pre_rotation_commitment: [0u8; 32],
            },
            custody: Arc::new(InMemoryKeyCustody::new()),
            document: test_did_document(did),
        };
        register_identity(did, entry);
        assert!(remove_identity_if_present(did));
    }

    #[test]
    fn remove_identity_if_present_returns_false_when_not_found() {
        assert!(!remove_identity_if_present("did:dht:z6MkNotPresent9999"));
    }

    #[test]
    fn registry_stats_returns_all_fields() {
        // Verifies the struct shape and that registry_stats() doesn't panic.
        let stats = registry_stats().unwrap();
        // Destructure to catch struct changes at compile time. If a field is
        // added or removed, this will fail to compile.
        let RegistryStats {
            contexts,
            known_contexts,
            identities,
            relay_connected,
        } = stats;
        // Ensure all fields are typed correctly.
        let _: usize = contexts;
        let _: usize = known_contexts;
        let _: usize = identities;
        let _: bool = relay_connected;
    }
}
