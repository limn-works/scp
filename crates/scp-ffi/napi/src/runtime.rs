//! Shared `ContextManager` instance for the NAPI bridge.
//!
//! Replaces the previous `ContextRuntime` / `DashMap` registry with a single
//! `Arc<ContextManager>` that owns all context state. Bridge functions delegate
//! lifecycle, messaging, governance, broadcast, membership, and TTL operations
//! to the manager.
//!
//! The manager is initialized once (via `OnceLock`) with lightweight provider
//! implementations suitable for the Node.js/Bun FFI environment:
//!
//! - [`NapiBridgeCryptoProvider`] — No-op MLS/sender-key operations. Real
//!   encryption is handled at the SDK layer above the FFI bridge.
//! - [`NapiBridgeTransportProvider`] — Reports connected, no-op send/publish.
//!   Real transport is handled via `NapiTransportManager`.
//! - [`NapiBridgeEventLogProvider`] — Delegates to `scp_event_log::EventLog`
//!   for Merkle tree operations.
//! - [`NapiBridgePersistence`] — In-memory persistence via `DashMap`.
//!
//! See issue #388 and `.docs/adrs/phase-4.md` (ADR-022).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};

use dashmap::DashMap;
use scp_core::context::ContextError;
use scp_core::context::builder::{
    ContextCreationError, ContextCryptoProvider, ContextEventLogProvider, ContextTransportProvider,
};
use scp_core::context::manager::{ContextManager, ContextPersistence, ContextSnapshot};
use scp_core::context::roles::{ContextRoleState, default_ceiling};
use scp_core::context::tools::{SessionStore, ToolRegistry};
use scp_core::crypto::ucan::nonce::NonceTracker;
use scp_core::crypto::ucan::revoke::RevocationList;
use scp_event_log::EventLog;
use scp_identity::cache::SystemClock;

use crate::context::NapiContextHandle;
use crate::error::ScpNapiError;

/// A tool handler is a closure that takes validated JSON input and returns
/// JSON output or an error string. Registered via [`register_tool_handler`].
pub type ToolHandler =
    Arc<dyn Fn(serde_json::Value) -> Result<serde_json::Value, String> + Send + Sync>;

// ---------------------------------------------------------------------------
// Global ContextManager instance
// ---------------------------------------------------------------------------

/// Global shared `ContextManager`, initialized once at first access.
static CONTEXT_MANAGER: OnceLock<Arc<ContextManager>> = OnceLock::new();

/// Global production DID resolver (#311).
static DID_RESOLVER: OnceLock<Arc<scp_ffi_common::IdentityBackedDidResolver>> = OnceLock::new();

/// Returns the global production DID resolver, if initialized.
#[must_use]
pub fn did_resolver() -> Option<&'static Arc<scp_ffi_common::IdentityBackedDidResolver>> {
    DID_RESOLVER.get()
}

/// Initializes the global production DID resolver.
pub fn init_did_resolver<R>(resolver: Arc<R>, handle: tokio::runtime::Handle)
where
    R: scp_identity::resolver::DidResolver + 'static,
{
    let _ = DID_RESOLVER.set(Arc::new(scp_ffi_common::IdentityBackedDidResolver::new(
        resolver, handle,
    )));
}

/// Returns a no-op key resolver for bridge-layer `ContextManager` initialization.
fn noop_key_resolver() -> scp_core::context::governance::KeyResolver {
    Arc::new(|_| None)
}

/// Returns a reference to the shared `ContextManager`.
///
/// Initializes the manager on first call with bridge-local provider
/// implementations. All NAPI bridge functions that need context operations
/// call this function.
pub fn context_manager() -> &'static Arc<ContextManager> {
    CONTEXT_MANAGER.get_or_init(|| {
        let crypto = Box::new(NapiBridgeCryptoProvider);
        let transport = Box::new(NapiBridgeTransportProvider);
        let event_log = Box::new(NapiBridgeEventLogProvider::new());
        let persistence = Box::new(NapiBridgePersistence::new());
        Arc::new(ContextManager::with_persistence(
            crypto,
            transport,
            event_log,
            persistence,
            noop_key_resolver(),
        ))
    })
}

// ---------------------------------------------------------------------------
// Per-context UCAN state — retained for the UCAN validation pipeline
//
// The ContextManager does not own UCAN revocation lists or nonce trackers.
// Those are validation-layer concerns that live in the bridge. We keep a
// lightweight registry for them, keyed by context ID.
// ---------------------------------------------------------------------------

/// Per-context UCAN validation state.
///
/// Retains the `RevocationList` and `NonceTracker` needed by the UCAN
/// validation pipeline (ADR-016). These are NOT duplicates of `ContextManager`
/// state — the manager does not track UCAN revocation or nonces.
pub struct UcanContextState {
    /// UCAN revocation list for this context.
    pub revocation_list: RevocationList,
    /// UCAN nonce tracker for replay prevention (ADR-016 step 9).
    pub nonce_tracker: NonceTracker<SystemClock>,
    /// Capability ceiling as a set of `{resource}:{action}` strings for
    /// UCAN validation (ADR-016 step 8).
    pub ceiling_strings: HashSet<String>,
    /// The DID of the context creator.
    pub creator_did: String,
    /// Event log (Merkle tree) for this context.
    pub event_log: EventLog,
    /// Role state for capability checking (tool registration, invocation).
    pub role_state: ContextRoleState,
    /// Tool registry for this context (cross-context + session support).
    pub tool_registry: ToolRegistry,
    /// Registered tool handlers keyed by tool ID.
    ///
    /// When a tool is invoked, the handler is looked up here and called with
    /// the validated JSON input. If no handler is registered, the invocation
    /// falls back to echoing the validated input (echo mode).
    pub tool_handlers: HashMap<String, ToolHandler>,
    /// Session store for stateful tool sessions (spec section 6.2.1).
    pub session_store: SessionStore,
}

/// Global registry of per-context UCAN validation state.
static UCAN_REGISTRY: OnceLock<DashMap<String, UcanContextState>> = OnceLock::new();

/// Returns a reference to the UCAN state registry.
fn ucan_registry() -> &'static DashMap<String, UcanContextState> {
    UCAN_REGISTRY.get_or_init(DashMap::new)
}

/// Ensures UCAN validation state is registered for a context.
///
/// If the context is already registered, this is a no-op. Otherwise, creates
/// UCAN state from the `NapiContextHandle` metadata.
///
/// # Errors
///
/// Returns `ScpNapiError::Context` if the context state cannot be determined.
pub fn ensure_registered(handle: &NapiContextHandle) -> Result<(), ScpNapiError> {
    let context_id = handle.context_id();
    let map = ucan_registry();

    if map.contains_key(&context_id) {
        return Ok(());
    }

    let creator_did = handle.creator_did();
    let handle_ceiling = handle.ceiling();

    let ceiling_strings = if handle_ceiling.is_empty() {
        scp_core::context::roles::default_ceiling()
            .capabilities
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<HashSet<String>>()
    } else {
        handle_ceiling.into_iter().collect::<HashSet<String>>()
    };

    let event_log = EventLog::new(context_id.clone());
    let revocation_list = RevocationList::new(context_id.clone());
    let nonce_tracker = NonceTracker::new(context_id.clone(), SystemClock);

    // No custom roles and default ceiling cannot fail validation.
    let role_state = match ContextRoleState::new(
        context_id.clone(),
        creator_did.clone(),
        default_ceiling(),
        Vec::new(),
    ) {
        Ok(rs) => rs,
        Err(e) => {
            return Err(ScpNapiError::Context {
                message: format!("failed to create role state: {e}"),
                code: "SCP-CTX-2023".to_owned(),
            });
        }
    };

    let state = UcanContextState {
        revocation_list,
        nonce_tracker,
        ceiling_strings,
        creator_did,
        event_log,
        role_state,
        tool_registry: ToolRegistry::new(),
        tool_handlers: HashMap::new(),
        session_store: SessionStore::new(),
    };

    map.entry(context_id).or_insert(state);
    Ok(())
}

/// Executes a closure with mutable access to a context's UCAN state.
///
/// # Errors
///
/// Returns `ScpNapiError::Context` if the context is not found in the registry.
pub fn with_context<T, F>(context_id: &str, f: F) -> Result<T, ScpNapiError>
where
    F: FnOnce(&mut UcanContextState) -> Result<T, ScpNapiError>,
{
    let map = ucan_registry();

    let mut entry = map
        .get_mut(context_id)
        .ok_or_else(|| ScpNapiError::Context {
            message: format!(
                "context '{context_id}' not found in UCAN state registry \
             -- call a UCAN or event log function with the context handle first"
            ),
            code: "SCP-CTX-2023".to_owned(),
        })?;

    f(entry.value_mut())
}

/// Removes UCAN state for a context.
///
/// Called when a context is closed. Idempotent.
pub fn remove_context(context_id: &str) {
    ucan_registry().remove(context_id);
}

/// Registers a tool handler for a tool in a context.
///
/// The handler will be called when the tool is invoked. The tool must already
/// be registered in the context's tool registry.
///
/// # Errors
///
/// Returns `ScpNapiError::Context` if the context is not found or the tool
/// is not registered.
pub fn register_tool_handler(
    context_id: &str,
    tool_id: &str,
    handler: ToolHandler,
) -> Result<(), ScpNapiError> {
    with_context(context_id, |st| {
        if st.tool_registry.get(tool_id).is_none() {
            return Err(ScpNapiError::Context {
                message: format!(
                    "tool '{tool_id}' not found in context '{context_id}' \
                     -- register the tool before adding a handler"
                ),
                code: "SCP-CTX-2023".to_owned(),
            });
        }
        st.tool_handlers.insert(tool_id.to_owned(), handler);
        Ok(())
    })
}

/// Queries event counts for trust scoring within a context.
///
/// Returns `(message_count, governance_count)` derived from the context's
/// event log. Returns `(0, 0)` if the context is not registered.
#[must_use]
pub fn query_trust_event_counts(context_id: &str, _did: &str) -> (u64, u64) {
    let map = ucan_registry();
    match map.get(context_id) {
        Some(entry) => {
            let total = entry.event_log.leaves().len() as u64;
            (total, 0)
        }
        None => (0, 0),
    }
}

/// Registers a test context in the UCAN state registry.
///
/// # Panics
///
/// Panics if `ContextRoleState::new` fails with default ceiling and no
/// custom roles, which should be infallible.
#[cfg(test)]
#[allow(clippy::expect_used)]
pub fn register_test_context(context_id: &str, creator_did: &str) {
    let map = ucan_registry();

    let ceiling_strings = scp_core::context::roles::default_ceiling()
        .capabilities
        .iter()
        .map(std::string::ToString::to_string)
        .collect::<HashSet<String>>();

    // Default ceiling + no custom roles: infallible in practice.
    let role_state = ContextRoleState::new(context_id, creator_did, default_ceiling(), Vec::new())
        .expect("ContextRoleState::new with default ceiling and no custom roles cannot fail");

    let state = UcanContextState {
        event_log: EventLog::new(context_id.to_owned()),
        revocation_list: RevocationList::new(context_id.to_owned()),
        nonce_tracker: NonceTracker::new(context_id.to_owned(), SystemClock),
        ceiling_strings,
        creator_did: creator_did.to_owned(),
        role_state,
        tool_registry: ToolRegistry::new(),
        tool_handlers: HashMap::new(),
        session_store: SessionStore::new(),
    };

    map.entry(context_id.to_owned()).or_insert(state);
}

// ---------------------------------------------------------------------------
// NapiBridgeCryptoProvider — no-op MLS/sender key operations
// ---------------------------------------------------------------------------

/// Bridge crypto provider for the NAPI layer.
///
/// All operations succeed immediately. Real MLS and sender key operations
/// will be delegated to production providers when integrated. The bridge
/// layer validates parameters and delegates lifecycle to `ContextManager`;
/// the crypto provider is called by the manager during creation, join,
/// leave, and send flows.
struct NapiBridgeCryptoProvider;

impl ContextCryptoProvider for NapiBridgeCryptoProvider {
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
    ) -> Result<(), ContextError> {
        Ok(())
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
        payload: &[u8],
    ) -> Result<Vec<u8>, ContextError> {
        // Return payload as-is; real encryption is layered above the bridge.
        Ok(payload.to_vec())
    }
}

// ---------------------------------------------------------------------------
// NapiBridgeTransportProvider — no-op transport
// ---------------------------------------------------------------------------

/// Bridge transport provider for the NAPI layer.
///
/// Reports connected and succeeds all operations. Real transport is
/// managed by `NapiTransportManager` at the SDK layer.
struct NapiBridgeTransportProvider;

impl ContextTransportProvider for NapiBridgeTransportProvider {
    fn is_connected(&self) -> bool {
        true
    }

    fn publish_context(
        &self,
        _context_id: &[u8; 32],
        _params: &scp_core::context::ContextParams,
    ) -> Result<(), ContextCreationError> {
        Ok(())
    }

    fn delete_published(&self, _context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }

    fn send_message(&self, _context_id: &[u8; 32], _encrypted: &[u8]) -> Result<(), ContextError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// NapiBridgeEventLogProvider — delegates to scp_event_log
// ---------------------------------------------------------------------------

/// Bridge event log provider for the NAPI layer.
///
/// No-op implementation. The `ContextManager` calls these methods during
/// context creation and messaging. Real event log operations (Merkle proofs,
/// queries) are handled by the UCAN registry's `EventLog` instances in
/// `ensure_registered`/`with_context`.
struct NapiBridgeEventLogProvider;

impl NapiBridgeEventLogProvider {
    const fn new() -> Self {
        Self
    }
}

impl ContextEventLogProvider for NapiBridgeEventLogProvider {
    fn init_event_log(&self, _context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }

    fn append_event(
        &self,
        _context_id: &[u8; 32],
        _event_type: &str,
    ) -> Result<(), ContextCreationError> {
        Ok(())
    }

    fn destroy_event_log(&self, _context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// NapiBridgePersistence — in-memory persistence
// ---------------------------------------------------------------------------

/// In-memory persistence provider for the NAPI bridge.
///
/// Stores context and broadcast snapshots in `DashMap`s. Suitable for
/// the Node.js/Bun environment where process lifetime matches context
/// lifetime. Production persistence (`SQLite`) is configured at the
/// application layer.
struct NapiBridgePersistence {
    contexts: DashMap<String, ContextSnapshot>,
    broadcasts: DashMap<String, scp_core::context::broadcast::BroadcastContextSnapshot>,
}

impl NapiBridgePersistence {
    fn new() -> Self {
        Self {
            contexts: DashMap::new(),
            broadcasts: DashMap::new(),
        }
    }
}

impl ContextPersistence for NapiBridgePersistence {
    fn persist_context(
        &self,
        context_id: &str,
        snapshot: &ContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.contexts
            .insert(context_id.to_owned(), snapshot.clone());
        Ok(())
    }

    fn load_context(
        &self,
        context_id: &str,
    ) -> Result<Option<ContextSnapshot>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.contexts.get(context_id).map(|v| v.value().clone()))
    }

    fn persist_broadcast(
        &self,
        context_id: &str,
        snapshot: &scp_core::context::broadcast::BroadcastContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.broadcasts
            .insert(context_id.to_owned(), snapshot.clone());
        Ok(())
    }

    fn load_broadcast(
        &self,
        context_id: &str,
    ) -> Result<
        Option<scp_core::context::broadcast::BroadcastContextSnapshot>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        Ok(self.broadcasts.get(context_id).map(|v| v.value().clone()))
    }

    fn delete_context(
        &self,
        context_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.contexts.remove(context_id);
        self.broadcasts.remove(context_id);
        Ok(())
    }

    fn list_persisted_contexts(
        &self,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self
            .contexts
            .iter()
            .map(|entry| entry.key().clone())
            .collect())
    }
}
