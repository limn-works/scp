//! Global runtime registry mapping context IDs to live `scp-core` objects.
//!
//! The FFI bridge functions accept `context_id: &str` parameters but need
//! access to both the shared [`ContextManager`] (for lifecycle, membership,
//! governance, and messaging operations) and per-context FFI-specific state
//! (tool registries, event logs, UCAN state, message channels).
//!
//! # Architecture (post-#386 rewrite)
//!
//! Context lifecycle is delegated to a shared [`ContextManager`] which holds
//! the canonical membership, role, governance, broadcast, and TTL state.
//! Per-context FFI-specific state (tool registries, event logs, UCAN
//! revocation/nonce tracking, tool handlers, message channels) lives in
//! [`FfiBridgeState`] — a thin struct that does NOT duplicate any
//! `ContextManager` state.
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
//! read per-context state (`with_ffi_state`); writes are infrequent. `DashMap`
//! uses internal sharding to eliminate reader contention — critical for
//! free-threaded Python (PEP 703) and high-throughput async workloads.
//!
//! # Lifecycle
//!
//! 1. `py_context_create` delegates to `ContextManager::create_context`, then
//!    registers FFI-specific state via [`register_ffi_state`].
//! 2. Bridge functions call [`with_ffi_state`] for FFI-specific state and
//!    [`context_manager`] for the shared `ContextManager`.
//! 3. `py_context_close` delegates to `ContextManager::close_context`, then
//!    removes FFI state via [`remove_ffi_state`].
//!
//! # Context Discovery (SCP-213)
//!
//! The SCP relay is a dumb blob store routing by `RoutingId` -- it has no
//! concept of which DID belongs to which context or what contexts exist.
//! Context discovery is therefore **client-side**: the [`KnownContext`]
//! registry tracks context-to-routing-id-to-relay mappings locally.
//!
//! # Error Propagation
//!
//! All public functions return `Result<T, ScpPyError>`, propagating typed
//! errors directly to the Python exception hierarchy without string
//! roundtripping.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock, RwLock};

use dashmap::DashMap;
use scp_core::context::ContextError;
use scp_core::context::builder::{
    ContextCreationError, ContextCryptoProvider, ContextEventLogProvider, ContextTransportProvider,
};
use scp_core::context::manager::{ContextManager, ContextPersistence};
use scp_core::context::providers::ProtocolRepositoryContextBridge;
use scp_core::context::roles::{ContextRoleState, default_ceiling};
use scp_core::context::tools::ToolRegistry;
use scp_core::crypto::ucan::nonce::NonceTracker;
use scp_core::crypto::ucan::revoke::RevocationList;
use scp_core::store::ProtocolRepository;
use scp_event_log::EventLog;
use scp_identity::cache::SystemClock;
use scp_identity::{DidDocument, ScpIdentity};
use scp_platform::encrypting_adapter::EncryptingAdapter;
use scp_platform::testing::InMemoryStorage;
use scp_transport::native::adapter::NativeRelayAdapter;
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use crate::context::PyMessage;
use crate::error::ScpPyError;

/// A sync tool handler function that takes JSON input and returns JSON output.
///
/// Stored in the FFI bridge state when Python callers register tool handlers
/// via [`register_tool_handler`]. The FFI bridge dispatches tool invocations
/// through these handlers instead of echoing validated input.
///
/// See SCP-212 and ADR-010 for the handler registration design.
pub type ToolHandler =
    Arc<dyn Fn(serde_json::Value) -> Result<serde_json::Value, String> + Send + Sync>;

// ---------------------------------------------------------------------------
// ContextManager (shared, process-global)
// ---------------------------------------------------------------------------

/// Global shared [`ContextManager`] that owns all context lifecycle state.
///
/// Initialized once via [`init_context_manager`]. All context lifecycle
/// operations (create, join, leave, close, send, governance, broadcast, TTL)
/// delegate to this instance.
///
/// # Safety: Single-Tenant Only
///
/// See module-level documentation.
static CONTEXT_MANAGER: OnceLock<Arc<ContextManager>> = OnceLock::new();

/// Returns a reference to the shared [`ContextManager`].
///
/// # Errors
///
/// Returns `ScpPyError::ContextError` if the context manager has not been
/// initialized via [`init_context_manager`].
pub fn context_manager() -> Result<&'static Arc<ContextManager>, ScpPyError> {
    CONTEXT_MANAGER.get().ok_or_else(|| {
        ScpPyError::context(
            "ContextManager not initialized — call py_context_create, \
             py_context_join, py_context_import, or init_context_manager first"
                .to_owned(),
        )
    })
}

/// Initializes the global [`ContextManager`] with production providers.
///
/// Uses `MlsCryptoProvider` (real OpenMLS-backed encryption, sender keys, and
/// group management — ported from NAPI bridge #1305, closes #1324),
/// `NotConfiguredTransportProvider` (returns descriptive errors until transport
/// is configured via `transport_connect`), and `NoOpEventLogProvider`
/// (bridge-level `EventLog` instances handle Merkle ops).
///
/// The `local_did` is passed to `MlsCryptoProvider::new` which uses it as
/// the MLS credential identity for group operations and sender key generation.
///
/// The key resolver rejects all lookups with an error rather than silently
/// returning `None`, ensuring governance vote signature verification failures
/// are visible rather than silently skipped.
///
/// When the global storage provider (`STORAGE_PROVIDER`) has been
/// initialized via [`init_storage`], a [`ProtocolRepositoryContextBridge`] is
/// constructed from it and injected into the `ContextManager`. This enables
/// context state persistence across process restarts without requiring
/// callers to manually wire persistence. See issue #329.
///
/// Subsequent calls are no-ops (`OnceLock` guarantees single initialization).
/// If the manager is already initialized with a different DID, a warning is logged.
pub fn init_context_manager(local_did: &str) {
    if CONTEXT_MANAGER.get().is_some() {
        tracing::warn!(
            requested_did = %local_did,
            "init_context_manager already initialized — MLS crypto uses the original DID"
        );
        return;
    }
    let did = local_did.to_owned();
    let _ = CONTEXT_MANAGER.get_or_init(|| {
        let crypto = Box::new(scp_core::crypto::mls::provider::MlsCryptoProvider::new(did));
        let persistence = build_persistence_provider();
        build_context_manager(
            crypto,
            Box::new(NotConfiguredTransportProvider),
            Box::new(NoOpEventLogProvider),
            persistence,
        )
    });
}

/// Initializes the global [`ContextManager`] with custom providers.
///
/// Allows injecting real or custom provider implementations. If the manager
/// is already initialized, this is a no-op (first call wins).
///
/// When `persistence` is `None` but the global storage provider has been
/// initialized, a [`ProtocolRepositoryContextBridge`] is automatically constructed
/// from it. Pass `Some(...)` to override with a custom implementation.
pub fn init_context_manager_with(
    crypto: Box<dyn ContextCryptoProvider>,
    transport: Box<dyn ContextTransportProvider>,
    event_log: Box<dyn ContextEventLogProvider>,
    persistence: Option<Box<dyn ContextPersistence>>,
) {
    let _ = CONTEXT_MANAGER.get_or_init(|| {
        let persistence = persistence.or_else(build_persistence_provider);
        build_context_manager(crypto, transport, event_log, persistence)
    });
}

/// Test variant of [`init_context_manager`] that uses `LocalTransportProvider`
/// instead of `NotConfiguredTransportProvider`.
///
/// Production code uses `NotConfiguredTransportProvider` to surface descriptive
/// errors when transport operations (publish, send) are attempted without a
/// configured relay. Tests use `LocalTransportProvider` so that
/// `publish_context` succeeds without real relay infrastructure.
///
/// Not behind `#[cfg(test)]` because integration tests (`tests/e2e_bridge.rs`)
/// compile as separate crates and need access to this function.
pub fn init_context_manager_for_test() {
    let _ = CONTEXT_MANAGER.get_or_init(|| {
        let persistence = build_persistence_provider();
        build_context_manager(
            Box::new(NoOpCryptoProvider),
            Box::new(scp_core::context::LocalTransportProvider),
            Box::new(NoOpEventLogProvider),
            persistence,
        )
    });
}

/// Constructs a [`ProtocolRepositoryContextBridge`] from the global storage provider,
/// if it has been initialized.
///
/// Returns `None` if [`init_storage`] has not been called yet. This is
/// expected during early initialization -- the `ContextManager` will operate
/// without persistence until the storage provider is available.
///
/// Uses `Arc<EncryptingAdapter<InMemoryStorage>>` as the storage backend
/// for `ProtocolRepository`, sharing the same underlying storage instance as
/// the identity layer. This ensures that identity and context data
/// coexist in the same store, matching the `ApplicationNode` pattern in
/// `scp-node`.
///
/// The `EncryptingAdapter` wraps `InMemoryStorage` with per-value
/// AES-256-GCM encryption, satisfying the sealed `EncryptedStorage`
/// bound required by `ProtocolRepository::new()`.
fn build_persistence_provider() -> Option<Box<dyn ContextPersistence>> {
    STORAGE_PROVIDER.get().map(|storage| {
        let protocol_repository = Arc::new(ProtocolRepository::new(Arc::clone(storage)));
        Box::new(ProtocolRepositoryContextBridge::new(protocol_repository))
            as Box<dyn ContextPersistence>
    })
}

/// Constructs a `ContextManager` with or without persistence.
fn build_context_manager(
    crypto: Box<dyn ContextCryptoProvider>,
    transport: Box<dyn ContextTransportProvider>,
    event_log: Box<dyn ContextEventLogProvider>,
    persistence: Option<Box<dyn ContextPersistence>>,
) -> Arc<ContextManager> {
    match persistence {
        Some(p) => Arc::new(ContextManager::with_persistence(
            crypto,
            transport,
            event_log,
            p,
            not_configured_key_resolver(),
        )),
        None => Arc::new(ContextManager::new(
            crypto,
            transport,
            event_log,
            not_configured_key_resolver(),
        )),
    }
}

// ---------------------------------------------------------------------------
// DID resolver (global, production)
// ---------------------------------------------------------------------------

/// Global production DID resolver that delegates to `scp_identity::resolver::DidResolver`
/// for full DID document validation (BEP44 signature verification, self-certification,
/// sequence number comparison, caching, healing).
///
/// Initialized by [`init_did_resolver`] when the identity layer is first set up.
/// Used by UCAN validation and attestation verification when available; falls back
/// to [`scp_ffi_common::BridgeDidResolver`] (string-only) when `None`.
///
/// See #311 for the unification design.
static DID_RESOLVER: OnceLock<Arc<scp_ffi_common::IdentityBackedDidResolver>> = OnceLock::new();

/// Returns the global production DID resolver, if initialized.
#[must_use]
pub fn did_resolver() -> Option<&'static Arc<scp_ffi_common::IdentityBackedDidResolver>> {
    DID_RESOLVER.get()
}

/// Initializes the global production DID resolver.
///
/// Wraps any `scp_identity::resolver::DidResolver` implementation (typically
/// `DualLayerResolver`) in an `IdentityBackedDidResolver` and stores it
/// as the process-global resolver for UCAN validation and attestation
/// verification.
///
/// Called once during identity system setup. Subsequent calls are no-ops
/// (the resolver is initialized via `OnceLock`).
pub fn init_did_resolver<R>(resolver: Arc<R>, handle: tokio::runtime::Handle)
where
    R: scp_identity::resolver::DidResolver + 'static,
{
    let _ = DID_RESOLVER.set(Arc::new(scp_ffi_common::IdentityBackedDidResolver::new(
        resolver, handle,
    )));
}

// ---------------------------------------------------------------------------
// Key resolver helper
// ---------------------------------------------------------------------------

/// Returns a key resolver that rejects all lookups with a logged error.
///
/// Logs an error once (via `std::sync::Once`) to signal that key resolution
/// is not configured. Subsequent lookups silently return `None` to avoid
/// log spam in governance-heavy contexts. The `KeyResolver` type signature
/// does not support `Result`, so `None` is the only way to signal failure.
fn not_configured_key_resolver() -> scp_core::context::governance::KeyResolver {
    Arc::new(
        |_did: &scp_identity::DID| -> Option<ed25519_dalek::VerifyingKey> {
            static LOG_ONCE: std::sync::Once = std::sync::Once::new();
            LOG_ONCE.call_once(|| {
                tracing::error!(
                    "key resolver not configured — governance vote signature verification is disabled. \
                     Wire a production KeyResolver to enable signature verification."
                );
            });
            None
        },
    )
}

// ---------------------------------------------------------------------------
// No-op provider implementations for ContextManager initialization
// ---------------------------------------------------------------------------

/// No-op crypto provider used only by [`init_context_manager_for_test`].
///
/// Production code now uses `MlsCryptoProvider` (issue #1324). Tests
/// continue using this no-op because they pass `did:key:` test DIDs and
/// `None` key packages which `MlsCryptoProvider` rejects.
struct NoOpCryptoProvider;

impl ContextCryptoProvider for NoOpCryptoProvider {
    fn validate_creator_identity(&self) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn create_mls_group(&self, _context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn generate_sender_key(&self, _context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn init_broadcast_key(&self, _context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn destroy_mls_group(&self, _context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn destroy_sender_key(&self, _context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn validate_key_package(
        &self,
        _owner_did: &str,
        _key_package_bytes: Option<&[u8]>,
    ) -> Result<(), ContextError> {
        Ok(())
    }
    fn add_member(
        &self,
        _context_id: &[u8; 32],
        _member_did: &str,
        _key_package_bytes: Option<&[u8]>,
    ) -> Result<scp_core::context::AddMemberOutput, ContextError> {
        Ok(scp_core::context::AddMemberOutput::default())
    }
    fn remove_member(&self, _context_id: &[u8; 32], _member_did: &str) -> Result<(), ContextError> {
        Ok(())
    }
    fn distribute_sender_key(
        &self,
        _context_id: &[u8; 32],
        _member_did: &str,
    ) -> Result<(), ContextError> {
        Ok(())
    }
    fn remove_member_sender_key(
        &self,
        _context_id: &[u8; 32],
        _member_did: &str,
    ) -> Result<(), ContextError> {
        Ok(())
    }
    fn encrypt_message(
        &self,
        _context_id: &[u8; 32],
        _sender_did: &str,
        _payload: &[u8],
        _epoch: u64,
        _sequence: u64,
    ) -> Result<Vec<u8>, ContextError> {
        Err(ContextError::CryptoFailed(
            "NoOpCryptoProvider::encrypt_message is not a real implementation — \
             wire a production crypto provider for MLS/sender-key encryption"
                .to_owned(),
        ))
    }
}

// Use the not-configured transport provider from scp-core (#501).
// Unlike `LocalTransportProvider` (which silently succeeds), this returns
// descriptive errors when transport operations are attempted without a relay.
use scp_core::context::NotConfiguredTransportProvider;

/// No-op event log provider for bridge-layer `ContextManager` initialization.
pub(crate) struct NoOpEventLogProvider;

impl ContextEventLogProvider for NoOpEventLogProvider {
    fn init_event_log(&self, _context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn append_event(
        &self,
        _context_id: &[u8; 32],
        _event: &str,
    ) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn destroy_event_log(&self, _context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// FfiBridgeState -- per-context FFI-specific state
// ---------------------------------------------------------------------------

/// Global registry of per-context FFI-specific state.
///
/// Stores state that is NOT managed by [`ContextManager`]: tool registries,
/// event logs, UCAN revocation/nonce tracking, tool handlers, and message
/// channels. Context lifecycle state (membership, roles, governance, broadcast,
/// TTL) lives in the `ContextManager`.
///
/// # Safety: Single-Tenant Only
///
/// This registry is process-global. See module-level documentation.
static FFI_BRIDGE_STATE: OnceLock<DashMap<String, FfiBridgeState>> = OnceLock::new();

/// Returns a reference to the global FFI bridge state registry.
fn ffi_state_registry() -> &'static DashMap<String, FfiBridgeState> {
    FFI_BRIDGE_STATE.get_or_init(DashMap::new)
}

/// Per-context FFI-specific state that does NOT duplicate [`ContextManager`].
///
/// Contains subsystem state used by `tools.rs`, `ucan.rs`, `event_log.rs`,
/// and `mcp.rs`, plus FFI-specific message channel and tool handler state.
pub struct FfiBridgeState {
    /// Tool registry for this context.
    pub tool_registry: ToolRegistry,
    /// Event log (Merkle tree) for this context.
    pub event_log: EventLog,
    /// Role state tracking member capabilities.
    ///
    /// Also maintained by `ContextManager` for lifecycle operations.
    /// This copy is used by UCAN validation (`ucan.rs`) and tool capability
    /// checking (`tools.rs`, `mcp.rs`) which access state via `with_ffi_state`.
    /// Both copies are kept in sync: `register_ffi_state` initializes from
    /// the same parameters, and `py_context_join` updates both.
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
    /// Session store for stateful tool sessions (spec section 6.2.1).
    ///
    /// Stores active tool sessions keyed by session ID. Sessions are created
    /// via `py_tool_session_create` and cleaned up on context close.
    pub session_store: scp_core::context::tools::SessionStore,
}

/// Buffer capacity for the receive channel (SCP-216, sketch.md §receive).
///
/// When the buffer is full, the oldest unconsumed event is dropped and a
/// `BufferOverflow` warning is injected into the stream.
pub const RECEIVE_BUFFER_CAPACITY: usize = 1000;

/// Registers FFI-specific state for a new context.
///
/// Creates a [`ToolRegistry`], [`EventLog`], [`ContextRoleState`], and
/// [`RevocationList`] for the context. The creator DID is assigned admin
/// capabilities (all capabilities in the ceiling).
///
/// `user_ceiling` contains user-provided ceiling strings in colon format
/// (e.g. `"tool:invoke:*"`). These are converted to UCAN underscore format
/// (e.g. `"tool_invoke:*"`) via `Capability::new` + `ucan_capability_name`.
/// Pass an empty slice to use the default ceiling.
///
/// # Errors
///
/// Returns `ScpPyError::ContextError` if the context ID is already registered
/// or if role state creation fails.
pub fn register_ffi_state(
    context_id: &str,
    creator_did: &str,
    user_ceiling: &[String],
) -> Result<(), ScpPyError> {
    use dashmap::mapref::entry::Entry;

    let map = ffi_state_registry();

    match map.entry(context_id.to_owned()) {
        Entry::Occupied(_) => {
            return Err(ScpPyError::context(format!(
                "context '{context_id}' FFI state is already registered"
            )));
        }
        Entry::Vacant(vacant) => {
            let tool_registry = ToolRegistry::new();
            let event_log = EventLog::new(context_id.to_owned());
            let ceiling = default_ceiling();
            let ceiling_strings = if user_ceiling.is_empty() {
                ceiling
                    .capabilities
                    .iter()
                    .map(scp_core::context::roles::Capability::ucan_capability_name)
                    .collect::<HashSet<String>>()
            } else {
                user_ceiling
                    .iter()
                    .map(|s| scp_core::context::roles::Capability::new(s).ucan_capability_name())
                    .collect::<HashSet<String>>()
            };
            let role_state =
                ContextRoleState::new(context_id, creator_did, ceiling, vec![], &SystemClock)
                    .map_err(|e| {
                        ScpPyError::context(format!("failed to create role state: {e}"))
                    })?;
            let revocation_list = RevocationList::new(context_id.to_owned());
            let nonce_tracker = NonceTracker::new(context_id.to_owned(), SystemClock);

            let state = FfiBridgeState {
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
                session_store: scp_core::context::tools::SessionStore::new(),
            };

            vacant.insert(state);
        }
    }

    Ok(())
}

/// Executes a closure with mutable access to a context's FFI bridge state.
///
/// Looks up the context by ID in the global FFI state registry and calls `f`
/// with a mutable reference to the [`FfiBridgeState`]. Uses `DashMap::get_mut`
/// for fine-grained per-key locking — only the accessed shard is locked, not
/// the entire registry.
///
/// # Errors
///
/// Returns `ScpPyError::ContextError` if the context is not found.
pub fn with_ffi_state<T, F>(context_id: &str, f: F) -> Result<T, ScpPyError>
where
    F: FnOnce(&mut FfiBridgeState) -> Result<T, ScpPyError>,
{
    let map = ffi_state_registry();

    let mut entry = map.get_mut(context_id).ok_or_else(|| {
        ScpPyError::context(format!(
            "context '{context_id}' not found in FFI state registry \
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
    ffi_state_registry()
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
    with_ffi_state(context_id, |st| {
        // Verify the tool exists in the registry before accepting a handler.
        if st.tool_registry.get(tool_id).is_none() {
            return Err(ScpPyError::context(format!(
                "tool '{tool_id}' not found in context '{context_id}' \
                 -- register the tool before adding a handler"
            )));
        }
        st.tool_handlers.insert(tool_id.to_owned(), handler);
        Ok(())
    })
}

/// Removes a context's FFI state from the registry.
///
/// Called when a context is closed. All associated FFI state objects are
/// dropped. Dropping the `FfiBridgeState` also drops `message_tx`, which
/// closes the receive channel and causes `__anext__` to raise
/// `StopAsyncIteration`. Does not error if the context was not found
/// (idempotent).
pub fn remove_ffi_state(context_id: &str) {
    ffi_state_registry().remove(context_id);
    known_contexts_registry().remove(context_id);
    // Clean up per-context bridge connector state (ShadowRegistry + SenderKeyStore)
    // to prevent unbounded memory growth in long-running processes.
    crate::bridge_connector::remove_bridge_state(context_id);
    // Clean up per-context economy state (budget + antispam trackers) to prevent
    // unbounded memory growth in long-running processes (#1433).
    remove_economy_state(context_id);
}

/// Re-syncs the `FfiBridgeState.role_state` for a context from the shared
/// `ContextManager`.
///
/// Must be called after any governance action that modifies role state
/// (`ChangeRole`, `ModifyCeiling`, `AddMember`, `RemoveMember`, etc.) so that the
/// FFI-side copy used by UCAN/tool capability checks stays current.
///
/// # Errors
///
/// Returns `ScpPyError` if the context manager is not initialized, the
/// context is not registered in either the manager or the FFI state registry,
/// or the tokio runtime is unavailable.
pub fn sync_role_state_from_manager(context_id: &str) -> Result<(), ScpPyError> {
    let mgr = context_manager()?;
    let rt = super::runtime().map_err(|e| ScpPyError::context(e.to_string()))?;
    let new_role_state = rt.block_on(mgr.get_role_state(context_id)).ok_or_else(|| {
        ScpPyError::context(format!(
            "context '{context_id}' not found in ContextManager"
        ))
    })?;

    with_ffi_state(context_id, |st| {
        st.role_state = new_role_state;
        Ok(())
    })
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
    with_ffi_state(context_id, |st| {
        st.message_tx.take();
        st.message_rx.take();
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
/// The function extracts channel references from the FFI state registry
/// (brief `DashMap` shard lock), then operates on the channel outside the
/// lock to avoid holding the shard lock during overflow handling.
///
/// # Errors
///
/// Returns `ScpPyError::ContextError` if the context is not found, has no
/// active receive channel, or if the channel is closed.
pub fn deliver_message(context_id: &str, message: PyMessage) -> Result<(), ScpPyError> {
    let (tx, rx_arc) = with_ffi_state(context_id, |st| {
        let tx = st.message_tx.clone().ok_or_else(|| {
            ScpPyError::context(format!(
                "context '{context_id}' has no active receive channel \
                 -- call py_context_receive first"
            ))
        })?;
        let rx = st.message_rx.clone().ok_or_else(|| {
            ScpPyError::context("receive channel has no shared receiver reference".to_owned())
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
                ScpPyError::context(format!(
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
        Err(mpsc::error::TrySendError::Closed(_)) => Err(ScpPyError::context(format!(
            "receive channel for context '{context_id}' is closed"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Known context registry (SCP-213: context discovery)
// ---------------------------------------------------------------------------

/// Global registry of known context-to-relay mappings for discovery (SCP-213).
///
/// Tracks contexts that have been created/joined locally, along with their
/// routing IDs and relay URLs. This allows `py_mcp_load_contexts` to probe
/// relays for context activity even across process restarts (when combined
/// with persistence, a future story).
///
/// # Safety: Single-Tenant Only
///
/// This registry is process-global. See module-level documentation.
static KNOWN_CONTEXTS: OnceLock<DashMap<String, KnownContext>> = OnceLock::new();

/// Returns a reference to the global known-contexts registry.
fn known_contexts_registry() -> &'static DashMap<String, KnownContext> {
    KNOWN_CONTEXTS.get_or_init(DashMap::new)
}

/// Metadata about a known context's relay presence.
///
/// Stored in the `KNOWN_CONTEXTS` registry so that `py_mcp_load_contexts`
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
// Invitation rate limit tracker registry (#614)
// ---------------------------------------------------------------------------

/// Global rate limit tracker registry for invitation auto-accept, keyed by
/// identity DID.
///
/// Each identity has its own [`RateLimitTracker`] that persists across
/// invitation evaluations. The tracker enforces the rate limit specified in
/// the auto-accept policy.
///
/// # Safety: Single-Tenant Only
///
/// This registry is process-global. See module-level documentation.
static RATE_LIMIT_TRACKERS: OnceLock<
    DashMap<String, scp_core::context::invitation::RateLimitTracker>,
> = OnceLock::new();

/// Returns a reference to the global rate limit tracker registry.
fn rate_limit_registry() -> &'static DashMap<String, scp_core::context::invitation::RateLimitTracker>
{
    RATE_LIMIT_TRACKERS.get_or_init(DashMap::new)
}

/// Returns a mutable reference to the rate limit tracker for the given
/// identity DID, creating one if it does not exist.
///
/// The caller passes a closure that receives `&mut RateLimitTracker`.
pub fn with_rate_limit_tracker<F, T>(identity_did: &str, f: F) -> T
where
    F: FnOnce(&mut scp_core::context::invitation::RateLimitTracker) -> T,
{
    let registry = rate_limit_registry();
    let mut entry = registry.entry(identity_did.to_owned()).or_default();
    f(entry.value_mut())
}

// ---------------------------------------------------------------------------
// Identity registry (SCP-214: KeyCustody wiring)
// ---------------------------------------------------------------------------

/// Global identity registry mapping DID strings to retained identity state.
///
/// Stores the [`ScpIdentity`] (with opaque [`KeyHandle`]s), the
/// [`Arc<FfiKeyCustody>`](crate::custody::FfiKeyCustody) that owns the key
/// material, and the [`DidDocument`]. This allows bridge functions to perform
/// crypto operations (signing, pseudonym derivation, key rotation) without
/// private key material crossing the FFI boundary (ADR-006).
///
/// Uses [`DashMap`] for lock-free concurrent access matching the context
/// registry pattern.
static IDENTITY_REGISTRY: OnceLock<DashMap<String, IdentityEntry>> = OnceLock::new();

/// Returns a reference to the global identity registry.
fn identity_registry() -> &'static DashMap<String, IdentityEntry> {
    IDENTITY_REGISTRY.get_or_init(DashMap::new)
}

/// Retained identity state for a single DID.
///
/// Stores the [`ScpIdentity`] (opaque key handles), the [`FfiKeyCustody`](crate::custody::FfiKeyCustody)
/// that owns the key material, and the [`DidDocument`]. The custody provider
/// is behind an `Arc` so it can be shared with context-scoped operations
/// (pseudonym derivation, signing, UCAN minting) without moving or cloning
/// the key material.
///
/// The `custody` field uses [`FfiKeyCustody`](crate::custody::FfiKeyCustody) — an enum dispatch wrapper —
/// because `KeyCustody` uses RPITIT and is not object-safe. This allows
/// the FFI bridge to support both in-memory (testing) and file-backed
/// (production) custody without dynamic dispatch via `dyn`.
///
/// See ADR-006, SCP-214 criterion 3, and issue #323.
pub struct IdentityEntry {
    /// The scp-core identity handle (DID string, key handles, pre-rotation).
    pub identity: ScpIdentity,
    /// The key custody provider that manages the actual key material.
    pub custody: Arc<crate::custody::FfiKeyCustody>,
    /// The DID document for this identity.
    pub document: DidDocument,
    /// Identity link attestations (§3.5.1). Stored locally per identity.
    pub identity_link_attestations: Vec<scp_core::identity::attestation::IdentityLinkAttestation>,
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
        ScpPyError::identity(format!(
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
        ScpPyError::identity(format!(
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

// ---------------------------------------------------------------------------
// Storage provider registry (SCP-217: identity persistence)
// ---------------------------------------------------------------------------

/// Global storage provider for identity persistence.
///
/// Injected via [`init_storage`] at Python initialization time. Bridge
/// functions use [`get_storage`] to access the provider for storing and
/// loading identity state.
///
/// **Default is `InMemoryStorage`:** Data does NOT survive process restarts.
/// SDK consumers requiring durable persistence should provide a file-backed
/// `Storage` implementation (e.g., `SqliteStorage`) at the application layer.
/// The in-memory default is suitable for testing and ephemeral workloads; the
/// architecture supports real persistence — it is an SDK integration concern
/// to wire a durable backend.
///
/// The storage backend is `InMemoryStorage` wrapped in
/// [`EncryptingAdapter`] with a random AES-256-GCM key. This satisfies
/// the sealed `EncryptedStorage` bound required by
/// `ProtocolRepository::new()`, matching the `scp-node` ephemeral mode
/// pattern. Persistent backends (`SQLite` via [`SqliteStorage`]) will
/// replace it when platform storage adapters land.
///
/// Uses the same `OnceLock` pattern as `FFI_BRIDGE_STATE` and
/// `RELAY_CONNECTION`. The `Arc` enables shared ownership across bridge
/// functions without lifetime issues.
///
/// See spec section 17.3 for key conventions and section 17.4 for
/// `ProtocolRepository` design.
///
/// # Safety: Single-Tenant Only
///
/// This registry is process-global. In multi-tenant deployments,
/// ALL tenants share the storage provider. See RED-017 / SCP-228.
static STORAGE_PROVIDER: OnceLock<Arc<EncryptingAdapter<InMemoryStorage>>> = OnceLock::new();

/// Initializes the global storage provider.
///
/// Must be called before any storage-dependent bridge function
/// (`py_identity_create`, `py_identity_load`). Calling multiple times is
/// a no-op — the first call wins.
///
/// Wraps `InMemoryStorage` in [`EncryptingAdapter`] with a random
/// AES-256-GCM key generated via `OsRng`. This ensures all stored
/// values are encrypted at rest, satisfying the `EncryptedStorage` bound.
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
            let mut key = Zeroizing::new([0u8; 32]);
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut *key);
            let encrypted = EncryptingAdapter::new(InMemoryStorage::new(), key);
            let _ = STORAGE_PROVIDER.set(Arc::new(encrypted));
            Ok(())
        }
        other => Err(ScpPyError::validation(format!(
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
pub fn get_storage() -> Result<&'static Arc<EncryptingAdapter<InMemoryStorage>>, ScpPyError> {
    STORAGE_PROVIDER.get().ok_or_else(|| {
        ScpPyError::identity(
            "storage not initialized — call py_init_storage(\"in_memory\") first".to_owned(),
        )
    })
}

// ---------------------------------------------------------------------------
// Relay connection state (SCP-213: transport wiring)
// ---------------------------------------------------------------------------

/// Global relay connection for context discovery probing.
///
/// Set by [`set_relay_connection`] when `py_transport_connect` succeeds.
/// Read by `py_mcp_load_contexts` to probe routing IDs on the relay.
/// Uses `RwLock` for infrequent writes (connect) and concurrent reads (probe).
///
/// # Safety: Single-Tenant Only
///
/// This registry is process-global. See module-level documentation.
static RELAY_CONNECTION: OnceLock<RwLock<Option<Arc<NativeRelayAdapter>>>> = OnceLock::new();

/// Returns a reference to the global relay connection state.
fn relay_state() -> &'static RwLock<Option<Arc<NativeRelayAdapter>>> {
    RELAY_CONNECTION.get_or_init(|| RwLock::new(None))
}

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
        ScpPyError::transport("relay connection state lock is poisoned".to_owned())
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
    let guard = relay_state()
        .read()
        .map_err(|_| ScpPyError::transport("relay connection state lock is poisoned".to_owned()))?;
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
        ScpPyError::transport("relay connection state lock is poisoned".to_owned())
    })? = None;
    Ok(())
}

// ---------------------------------------------------------------------------
// Backward-compatibility aliases
// ---------------------------------------------------------------------------

/// Backward-compatible alias: registers context in both `ContextManager` and
/// FFI state registry.
///
/// This function ensures that both the shared `ContextManager` (for lifecycle
/// operations) and the FFI bridge state (for tool/UCAN/event-log operations)
/// are initialized for the given context. Used during the transition period
/// where the full `ContextManager` flow is being connected.
///
/// # Errors
///
/// Returns `ScpPyError::ContextError` if registration fails.
pub fn register_context(
    context_id: &str,
    creator_did: &str,
    user_ceiling: &[String],
) -> Result<(), ScpPyError> {
    // Ensure the ContextManager is initialized.
    // Tests use LocalTransportProvider so publish_context succeeds silently.
    // Production uses NotConfiguredTransportProvider — publish_context
    // returns an error that create_context logs as a warning (best-effort;
    // context is valid locally even without relay publication, #501).
    // Passes the creator DID to MlsCryptoProvider for real MLS encryption (#1324).
    #[cfg(test)]
    init_context_manager_for_test();
    #[cfg(not(test))]
    init_context_manager(creator_did);

    // Register FFI-specific state.
    register_ffi_state(context_id, creator_did, user_ceiling)
}

/// Backward-compatible alias for [`with_ffi_state`].
///
/// Modules that previously used `with_context` to access `ContextRuntime`
/// now access [`FfiBridgeState`] through this alias. The function signature
/// is identical.
///
/// # Errors
///
/// Returns `ScpPyError::ContextError` if the context is not found, or
/// propagates any error returned by the closure `f`.
pub fn with_context<T, F>(context_id: &str, f: F) -> Result<T, ScpPyError>
where
    F: FnOnce(&mut FfiBridgeState) -> Result<T, ScpPyError>,
{
    with_ffi_state(context_id, f)
}

/// Backward-compatible alias for [`remove_ffi_state`].
pub fn remove_context(context_id: &str) {
    remove_ffi_state(context_id);
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
    /// Number of entries in the FFI bridge state registry.
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
        .map_err(|_| ScpPyError::transport("relay connection state lock is poisoned".to_owned()))?
        .is_some();

    Ok(RegistryStats {
        contexts: ffi_state_registry().len(),
        known_contexts: known_contexts_registry().len(),
        identities: identity_registry().len(),
        relay_connected,
    })
}

// ---------------------------------------------------------------------------
// Trust engine helpers
// ---------------------------------------------------------------------------

/// Queries event counts for trust scoring within a context.
///
/// Returns `(message_count, governance_count)` derived from the context's
/// event log. The event log stores leaf hashes (Merkle tree), not full event
/// payloads, so per-DID filtering is not possible at this level. The returned
/// counts represent total context-level event counts.
///
/// For per-DID behavioral data, use the full participation record computation
/// in `scp-core::trust::participation::compute_participation_record` with
/// the actual event objects.
///
/// Returns `(0, 0)` if the context is not registered.
#[must_use]
pub fn query_trust_event_counts(context_id: &str, _did: &str) -> (u64, u64) {
    let map = ffi_state_registry();
    match map.get(context_id) {
        Some(entry) => {
            let total = entry.event_log.leaves().len() as u64;
            // The event log records all event types as leaf hashes without
            // type discrimination. We report total events as message_count
            // and 0 governance_count as a best-effort approximation. For
            // precise per-type counts, callers should use the full
            // participation record computation with event objects.
            (total, 0)
        }
        None => (0, 0),
    }
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

// ---------------------------------------------------------------------------
// Economy state registries
// ---------------------------------------------------------------------------

/// Per-context member budget trackers for economic governance.
///
/// Keyed by context ID. Created lazily on first access via
/// [`with_economy_budget`] / [`with_economy_budget_mut`]. Budget trackers are
/// NOT removed automatically when contexts are closed -- call
/// [`remove_economy_state`] for cleanup in long-running processes.
static ECONOMY_BUDGETS: OnceLock<DashMap<String, scp_core::economy::MemberBudgetTracker>> =
    OnceLock::new();

fn economy_budget_registry() -> &'static DashMap<String, scp_core::economy::MemberBudgetTracker> {
    ECONOMY_BUDGETS.get_or_init(DashMap::new)
}

/// Per-context antispam velocity trackers for economic governance.
///
/// Keyed by context ID. Created lazily on first access with a default 60-second
/// sliding window. The window duration matches the spec section 19.7 example.
static ECONOMY_ANTISPAM: OnceLock<DashMap<String, scp_core::economy::SenderVelocityTracker>> =
    OnceLock::new();

/// Default sliding window duration for antispam velocity tracking (seconds).
/// Matches the spec section 19.7 example.
const ANTISPAM_DEFAULT_WINDOW_SECS: u64 = 60;

fn economy_antispam_registry() -> &'static DashMap<String, scp_core::economy::SenderVelocityTracker>
{
    ECONOMY_ANTISPAM.get_or_init(DashMap::new)
}

/// Reads the budget tracker for a context, creating one if it doesn't exist.
///
/// The closure receives an immutable reference to the tracker.
pub fn with_economy_budget<T, F>(context_id: &str, f: F) -> T
where
    F: FnOnce(&scp_core::economy::MemberBudgetTracker) -> T,
{
    let registry = economy_budget_registry();
    let entry = registry.entry(context_id.to_owned()).or_default();
    f(entry.value())
}

/// Mutably accesses the budget tracker for a context, creating one if needed.
///
/// The closure receives a mutable reference to the tracker.
pub fn with_economy_budget_mut<T, F>(context_id: &str, f: F) -> T
where
    F: FnOnce(&mut scp_core::economy::MemberBudgetTracker) -> T,
{
    let registry = economy_budget_registry();
    let mut entry = registry.entry(context_id.to_owned()).or_default();
    f(entry.value_mut())
}

/// Accesses the antispam velocity tracker for a context, creating one if needed.
///
/// The closure receives a reference to the tracker (which is internally
/// `Mutex`-protected, so `&self` methods like `record_message` and
/// `get_velocity` work without `&mut`).
pub fn with_economy_antispam<T, F>(context_id: &str, f: F) -> T
where
    F: FnOnce(&scp_core::economy::SenderVelocityTracker) -> T,
{
    let registry = economy_antispam_registry();
    let entry = registry.entry(context_id.to_owned()).or_insert_with(|| {
        scp_core::economy::SenderVelocityTracker::new(ANTISPAM_DEFAULT_WINDOW_SECS)
    });
    f(entry.value())
}

/// Removes economy state (budget tracker and antispam tracker) for a context.
///
/// Should be called during context cleanup for long-running processes.
pub fn remove_economy_state(context_id: &str) {
    economy_budget_registry().remove(context_id);
    economy_antispam_registry().remove(context_id);
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use scp_platform::testing::InMemoryKeyCustody;

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

        register_context(&ctx_id, creator, &[]).unwrap();
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
            ffi_state_registry().contains_key(&ctx_id),
            "registered context should be in registry"
        );

        remove_context(&ctx_id);
        assert!(
            !ffi_state_registry().contains_key(&ctx_id),
            "removed context should not be in registry"
        );
    }

    #[test]
    #[cfg(feature = "allow_in_memory_custody")]
    fn registry_stats_reflects_identity_registration() {
        let did = "did:dht:z6MkStatsIdentityUnique9988";

        let entry = IdentityEntry {
            identity: ScpIdentity {
                did: did.to_owned(),
                identity_key: scp_platform::KeyHandle::new(0),
                active_signing_key: scp_platform::KeyHandle::new(0),
                agent_signing_key: None,
                pre_rotation_commitment: [0u8; 32],
            },
            custody: Arc::new(crate::custody::FfiKeyCustody::InMemory(
                InMemoryKeyCustody::new(),
            )),
            document: test_did_document(did),
            identity_link_attestations: Vec::new(),
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
    #[cfg(feature = "allow_in_memory_custody")]
    fn remove_identity_if_present_returns_true_when_found() {
        let did = "did:dht:z6MkRemoveIfPresent";
        let entry = IdentityEntry {
            identity: ScpIdentity {
                did: did.to_owned(),
                identity_key: scp_platform::KeyHandle::new(0),
                active_signing_key: scp_platform::KeyHandle::new(0),
                agent_signing_key: None,
                pre_rotation_commitment: [0u8; 32],
            },
            custody: Arc::new(crate::custody::FfiKeyCustody::InMemory(
                InMemoryKeyCustody::new(),
            )),
            document: test_did_document(did),
            identity_link_attestations: Vec::new(),
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

    #[test]
    fn context_manager_initializes_once() {
        init_context_manager_for_test();
        let mgr1 = context_manager().unwrap();
        init_context_manager_for_test();
        let mgr2 = context_manager().unwrap();
        // Same Arc (same pointer).
        assert!(Arc::ptr_eq(mgr1, mgr2));
    }

    #[test]
    fn with_ffi_state_finds_registered_context() {
        let ctx_id = unique_ctx_id("ffi-find");
        let creator = "did:dht:z6MkFfiFind";
        register_context(&ctx_id, creator, &[]).unwrap();

        let creator_did = with_ffi_state(&ctx_id, |st| Ok(st.creator_did.clone())).unwrap();
        assert_eq!(creator_did, creator);

        remove_context(&ctx_id);
    }

    #[test]
    fn with_ffi_state_errors_on_missing_context() {
        let result = with_ffi_state("nonexistent-ctx-id", |_| Ok(()));
        assert!(result.is_err());
    }

    /// User-provided ceiling strings in colon format (e.g. `"tool:invoke:*"`)
    /// must be converted to UCAN underscore format (e.g. `"tool_invoke:*"`)
    /// when stored in `FfiBridgeState.ceiling_strings`. Without this conversion,
    /// `mint_ucan` ceiling checks fail because the minted capability name
    /// (underscore format) doesn't match the stored raw string.
    ///
    /// Regression test for PR #1293 review finding.
    #[test]
    fn user_ceiling_strings_converted_to_ucan_format() {
        let ctx_id = unique_ctx_id("ceiling-conv");
        let creator = "did:dht:z6MkCeilingConv";

        let user_ceiling = vec![
            "tool:invoke:*".to_owned(),
            "messages:write".to_owned(),
            "context:child:create".to_owned(),
            "tool:invoke:calculator".to_owned(),
        ];

        register_context(&ctx_id, creator, &user_ceiling).unwrap();

        let ceiling = with_ffi_state(&ctx_id, |st| Ok(st.ceiling_strings.clone())).unwrap();

        // Compound resources must have underscores joining their segments.
        assert!(
            ceiling.contains("tool_invoke:*"),
            "expected 'tool_invoke:*' but got: {ceiling:?}"
        );
        assert!(
            ceiling.contains("context_child:create"),
            "expected 'context_child:create' but got: {ceiling:?}"
        );
        assert!(
            ceiling.contains("tool_invoke:calculator"),
            "expected 'tool_invoke:calculator' but got: {ceiling:?}"
        );
        // Simple two-segment capabilities should pass through unchanged.
        assert!(
            ceiling.contains("messages:write"),
            "expected 'messages:write' but got: {ceiling:?}"
        );
        // Raw colon-format strings must NOT be present.
        assert!(
            !ceiling.contains("tool:invoke:*"),
            "raw 'tool:invoke:*' should not be in ceiling: {ceiling:?}"
        );
        assert!(
            !ceiling.contains("context:child:create"),
            "raw 'context:child:create' should not be in ceiling: {ceiling:?}"
        );

        remove_context(&ctx_id);
    }

    /// When no user ceiling is provided (empty slice), the default ceiling
    /// should be used with proper UCAN underscore format.
    #[test]
    fn empty_user_ceiling_uses_default_in_ucan_format() {
        let ctx_id = unique_ctx_id("ceiling-default");
        let creator = "did:dht:z6MkCeilingDefault";

        register_context(&ctx_id, creator, &[]).unwrap();

        let ceiling = with_ffi_state(&ctx_id, |st| Ok(st.ceiling_strings.clone())).unwrap();

        // Default ceiling must include tool_invoke:* (not tool:invoke:*).
        assert!(
            ceiling.contains("tool_invoke:*"),
            "default ceiling should contain 'tool_invoke:*' but got: {ceiling:?}"
        );
        assert!(
            !ceiling.contains("tool:invoke:*"),
            "default ceiling should not contain raw 'tool:invoke:*': {ceiling:?}"
        );

        remove_context(&ctx_id);
    }
}
