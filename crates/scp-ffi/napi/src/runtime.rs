//! Shared `ContextManager` instance for the NAPI bridge.
//!
//! Replaces the previous `ContextRuntime` / `DashMap` registry with a single
//! `Arc<ContextManager>` that owns all context state. Bridge functions delegate
//! lifecycle, messaging, governance, broadcast, membership, and TTL operations
//! to the manager.
//!
//! The manager is initialized once (via `OnceLock`) with production provider
//! implementations:
//!
//! - `MlsCryptoProvider` — Real OpenMLS-backed encryption, sender key
//!   generation, and group management. Wired in issue #1294.
//! - `NotConfiguredTransportProvider` (from `scp-core`) — Returns descriptive
//!   errors until transport is configured. See issue #501.
//! - `MerkleEventLogProvider` — Persistent Merkle-chained event log backed by
//!   `ProtocolRepositoryEventLogBridge` over encrypted in-memory storage (#484).
//! - `NapiBridgePersistence` — In-memory persistence via `DashMap`.
//!
//! See issue #388 and `.docs/adrs/phase-4.md` (ADR-022).

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::{Arc, OnceLock};

use dashmap::DashMap;
use scp_core::context::builder::ContextEventLogProvider;
use scp_core::context::manager::{ContextManager, ContextPersistence, ContextSnapshot};
use scp_core::context::providers::MerkleEventLogProvider;
use scp_core::context::roles::{ContextRoleState, default_ceiling};
use scp_core::context::tools::{SessionStore, ToolRegistry};
use scp_core::crypto::ucan::nonce::NonceTracker;
use scp_core::crypto::ucan::revoke::RevocationList;
use scp_core::store::ProtocolRepository;
use scp_core::store::context::ProtocolRepositoryEventLogBridge;
use scp_event_log::EventLog;
use scp_identity::cache::SystemClock;
use scp_platform::Storage;
use scp_platform::encrypting_adapter::EncryptingAdapter;
use scp_platform::error::PlatformError;
use zeroize::Zeroizing;

use crate::context::NapiContextHandle;
use crate::error::ScpNapiError;
#[cfg(feature = "allow_in_memory_custody")]
use crate::identity::OpaqueInMemoryKeyCustody;

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

/// Global shared `InMemoryDhtClient` used by the DID resolver.
///
/// Stored here so that `identity_create` can publish newly created DID
/// documents to the same DHT client that the resolver reads from. Without
/// this, UCAN validation fails because `IdentityBackedDidResolver` cannot
/// find the issuer's DID document.
///
/// See issue #1144 (UCAN validation tests require shared DHT state).
static SHARED_DHT_CLIENT: OnceLock<Arc<scp_identity::InMemoryDhtClient>> = OnceLock::new();

/// Returns the global production DID resolver, if initialized.
#[must_use]
pub fn did_resolver() -> Option<&'static Arc<scp_ffi_common::IdentityBackedDidResolver>> {
    DID_RESOLVER.get()
}

/// Returns the shared `InMemoryDhtClient`, if initialized.
///
/// Used by `identity_create` to publish DID documents so that the resolver
/// can later find them during UCAN validation (#1144).
#[must_use]
pub fn shared_dht_client() -> Option<&'static Arc<scp_identity::InMemoryDhtClient>> {
    SHARED_DHT_CLIENT.get()
}

/// Stores the shared `InMemoryDhtClient` for the DID resolver.
///
/// Called by `ensure_did_resolver_initialized` in `identity.rs`. Subsequent
/// calls are no-ops (`OnceLock` guarantees single initialization).
pub fn init_shared_dht_client(client: Arc<scp_identity::InMemoryDhtClient>) {
    let _ = SHARED_DHT_CLIENT.set(client);
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

/// Returns a key resolver that rejects all lookups with a logged error.
///
/// Logs an error once (via `std::sync::Once`) to signal that key resolution
/// is not configured. Subsequent lookups silently return `None` to avoid
/// log spam in governance-heavy contexts. The `KeyResolver` type signature
/// does not support `Result`, so `None` is the only way to signal failure.
fn not_configured_key_resolver() -> scp_core::context::governance::KeyResolver {
    Arc::new(|_did| {
        static LOG_ONCE: std::sync::Once = std::sync::Once::new();
        LOG_ONCE.call_once(|| {
            tracing::error!(
                "key resolver not configured — governance vote signature verification is disabled. \
                 Wire a production KeyResolver to enable signature verification."
            );
        });
        None
    })
}

/// Returns a reference to the shared `ContextManager`.
///
/// # Errors
///
/// Returns `napi::Error` if the manager has not been initialized via
/// [`init_context_manager`]. Matches the `PyO3` bridge pattern: callers
/// must explicitly initialize the manager (typically during
/// `context_create`) rather than silently auto-initializing with
/// potentially invalid state.
pub fn context_manager() -> napi::Result<&'static Arc<ContextManager>> {
    CONTEXT_MANAGER.get().ok_or_else(|| {
        napi::Error::from(ScpNapiError::Context {
            message: "ContextManager not initialized — call context_create, \
                      context_join, context_import, or init_context_manager first"
                .to_owned(),
            code: "SCP-CTX-2000".to_owned(),
        })
    })
}

/// Initializes the global [`ContextManager`] with production providers.
///
/// Uses `MlsCryptoProvider` (real MLS encryption, #1294),
/// `NotConfiguredTransportProvider`, `MerkleEventLogProvider` (persistent,
/// #484), and `NapiBridgePersistence`.
///
/// The `local_did` is passed to `MlsCryptoProvider::new` which uses it as
/// the MLS credential identity for group operations and sender key generation.
///
/// Event log persistence is wired via `MerkleEventLogProvider::with_persistence`
/// backed by a `ProtocolRepositoryEventLogBridge` over an encrypted in-memory
/// storage provider. This ensures event log entries are persisted on each
/// append (issue #484 AC).
///
/// Subsequent calls are no-ops (`OnceLock` guarantees single initialization).
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
        let transport = Box::new(scp_core::context::NotConfiguredTransportProvider);
        let event_log = build_event_log_provider();
        let persistence = Box::new(NapiBridgePersistence::new());
        Arc::new(ContextManager::with_persistence(
            crypto,
            transport,
            event_log,
            persistence,
            not_configured_key_resolver(),
        ))
    });
}

/// Initializes the global [`ContextManager`] with [`LocalTransportProvider`].
///
/// Identical to [`init_context_manager`] except the transport provider is
/// `LocalTransportProvider` (silently succeeds on all send/publish calls)
/// instead of `NotConfiguredTransportProvider` (rejects everything).
///
/// **Must be called before any `context_create` / `context_join` /
/// `context_import`** — those functions call `init_context_manager` which
/// will win the `OnceLock` race if called first.
///
/// Exposed to JS/TS via [`crate::transport::configure_local_transport`] so
/// that E2E tests can exercise `contextSend` and `broadcastPublish` without
/// a real relay server.
///
/// Subsequent calls are no-ops (`OnceLock`).
pub fn init_context_manager_with_local_transport(local_did: &str) {
    if CONTEXT_MANAGER.get().is_some() {
        tracing::warn!(
            requested_did = %local_did,
            "init_context_manager already initialized — ignoring local-transport init"
        );
        return;
    }
    let did = local_did.to_owned();
    let _ = CONTEXT_MANAGER.get_or_init(|| {
        let crypto = Box::new(scp_core::crypto::mls::provider::MlsCryptoProvider::new(did));
        let transport = Box::new(scp_core::context::LocalTransportProvider);
        let event_log = build_event_log_provider();
        let persistence = Box::new(NapiBridgePersistence::new());
        Arc::new(ContextManager::with_persistence(
            crypto,
            transport,
            event_log,
            persistence,
            not_configured_key_resolver(),
        ))
    });
}

/// Initializes the global [`ContextManager`] with [`RelayTransportProvider`].
///
/// Identical to [`init_context_manager`] except the transport provider is a
/// `RelayTransportProvider` wrapping a real `NativeRelayAdapter` connected to
/// the given relay URL. This allows `ContextManager::send_message` (and thus
/// `contextSend`) to publish encrypted payloads through the relay.
///
/// **Must be called before any `context_create` / `context_join` /
/// `context_import`** — those functions call `init_context_manager` which
/// will win the `OnceLock` race if called first.
///
/// Exposed to JS/TS via [`crate::transport::configure_relay_transport`] so
/// that E2E tests can exercise the full send → relay → subscribe → receive
/// pipeline.
///
/// # Arguments
///
/// * `local_did` — The DID of the first identity (MLS credential identity).
/// * `adapter` — A connected `NativeRelayAdapter` to wrap in
///   `RelayTransportProvider`.
///
/// Subsequent calls are no-ops (`OnceLock`).
pub fn init_context_manager_with_relay_transport(
    local_did: &str,
    adapter: scp_transport::native::adapter::NativeRelayAdapter,
) {
    if CONTEXT_MANAGER.get().is_some() {
        tracing::warn!(
            requested_did = %local_did,
            "init_context_manager already initialized — ignoring relay-transport init"
        );
        return;
    }
    let did = local_did.to_owned();
    let _ = CONTEXT_MANAGER.get_or_init(|| {
        let crypto = Box::new(scp_core::crypto::mls::provider::MlsCryptoProvider::new(did));
        let transport = Box::new(scp_transport::RelayTransportProvider::new(adapter));
        let event_log = build_event_log_provider();
        let persistence = Box::new(NapiBridgePersistence::new());
        Arc::new(ContextManager::with_persistence(
            crypto,
            transport,
            event_log,
            persistence,
            not_configured_key_resolver(),
        ))
    });
}

/// Constructs a persistent event log provider backed by encrypted in-memory
/// storage.
///
/// Creates an `EncryptingAdapter<BridgeInMemoryStorage>` with a random
/// AES-256-GCM key, wraps it in a `ProtocolRepository`, then builds a
/// `ProtocolRepositoryEventLogBridge` that implements `EventLogPersistence`.
/// The resulting `MerkleEventLogProvider` persists entries on each append.
///
/// Uses [`BridgeInMemoryStorage`] (a bridge-local `Storage` implementation)
/// instead of `scp_platform::testing::InMemoryStorage` so that the `testing`
/// feature (which also exposes `InMemoryKeyCustody`) is not required in
/// production builds. See issue #484.
///
/// SDK consumers requiring durable persistence across process restarts
/// should provide a file-backed `Storage` implementation at the application
/// layer (e.g., `SqliteStorage`). The in-memory default is suitable for the
/// Node.js/Bun environment where process lifetime matches context lifetime.
/// Global `ProtocolRepository` instance, shared between the event log
/// provider and the trust store bridge. Exposed via [`protocol_repository()`]
/// for trust aggregation (issue #502).
static PROTOCOL_REPOSITORY: OnceLock<
    Arc<ProtocolRepository<EncryptingAdapter<BridgeInMemoryStorage>>>,
> = OnceLock::new();

/// Returns the global `ProtocolRepository` if initialized.
///
/// Used by the trust aggregation bridge to construct a
/// `ProtocolRepositoryTrustBridge` backed by persistent (in-process) storage.
/// Returns `None` if `build_event_log_provider` has not been called yet.
#[must_use]
pub fn protocol_repository()
-> Option<&'static Arc<ProtocolRepository<EncryptingAdapter<BridgeInMemoryStorage>>>> {
    PROTOCOL_REPOSITORY.get()
}

fn build_event_log_provider() -> Box<dyn ContextEventLogProvider> {
    let mut key = Zeroizing::new([0u8; 32]);
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut *key);
    let encrypted = EncryptingAdapter::new(BridgeInMemoryStorage::new(), key);
    let store = Arc::new(ProtocolRepository::new(encrypted));

    // Expose the ProtocolRepository globally for trust store usage (#502).
    let _ = PROTOCOL_REPOSITORY.set(Arc::clone(&store));

    let bridge = ProtocolRepositoryEventLogBridge::new(store);
    Box::new(MerkleEventLogProvider::with_persistence(Arc::new(bridge)))
}

/// Test variant of [`context_manager`] initialization that uses
/// [`LocalTransportProvider`](scp_core::context::LocalTransportProvider) instead of
/// [`NotConfiguredTransportProvider`](scp_core::context::NotConfiguredTransportProvider)
/// and a no-op crypto provider for Rust unit tests that pass `None` key
/// package bytes with `did:key:` test DIDs.
///
/// Must be called before the first `context_manager()` call in tests.
/// `OnceLock::get_or_init` ensures only the first initialization wins.
#[cfg(test)]
pub(crate) fn init_context_manager_for_test() {
    let _ = CONTEXT_MANAGER.set(Arc::new(ContextManager::with_persistence(
        Box::new(TestNoOpCryptoProvider),
        Box::new(scp_core::context::LocalTransportProvider),
        build_event_log_provider(),
        Box::new(NapiBridgePersistence::new()),
        not_configured_key_resolver(),
    )));
}

/// No-op crypto provider for Rust unit tests only.
///
/// Accepts `None` key packages and `did:key:` DIDs, unlike the production
/// `MlsCryptoProvider` which requires real MLS key package bytes and
/// `did:dht:z` DIDs.
#[cfg(test)]
struct TestNoOpCryptoProvider;

#[cfg(test)]
impl scp_core::context::builder::ContextCryptoProvider for TestNoOpCryptoProvider {
    fn validate_creator_identity(
        &self,
    ) -> Result<(), scp_core::context::builder::ContextCreationError> {
        Ok(())
    }
    fn create_mls_group(
        &self,
        _context_id: &[u8; 32],
    ) -> Result<(), scp_core::context::builder::ContextCreationError> {
        Ok(())
    }
    fn generate_sender_key(
        &self,
        _context_id: &[u8; 32],
    ) -> Result<(), scp_core::context::builder::ContextCreationError> {
        Ok(())
    }
    fn init_broadcast_key(
        &self,
        _context_id: &[u8; 32],
    ) -> Result<(), scp_core::context::builder::ContextCreationError> {
        Ok(())
    }
    fn destroy_mls_group(
        &self,
        _context_id: &[u8; 32],
    ) -> Result<(), scp_core::context::builder::ContextCreationError> {
        Ok(())
    }
    fn destroy_sender_key(
        &self,
        _context_id: &[u8; 32],
    ) -> Result<(), scp_core::context::builder::ContextCreationError> {
        Ok(())
    }
    fn validate_key_package(
        &self,
        _owner_did: &str,
        _key_package_bytes: Option<&[u8]>,
    ) -> Result<(), scp_core::context::ContextError> {
        Ok(())
    }
    fn add_member(
        &self,
        _context_id: &[u8; 32],
        _member_did: &str,
        _key_package_bytes: Option<&[u8]>,
    ) -> Result<(), scp_core::context::ContextError> {
        Ok(())
    }
    fn remove_member(
        &self,
        _context_id: &[u8; 32],
        _member_did: &str,
    ) -> Result<(), scp_core::context::ContextError> {
        Ok(())
    }
    fn distribute_sender_key(
        &self,
        _context_id: &[u8; 32],
        _member_did: &str,
    ) -> Result<(), scp_core::context::ContextError> {
        Ok(())
    }
    fn remove_member_sender_key(
        &self,
        _context_id: &[u8; 32],
        _member_did: &str,
    ) -> Result<(), scp_core::context::ContextError> {
        Ok(())
    }
    fn encrypt_message(
        &self,
        _context_id: &[u8; 32],
        _sender_did: &str,
        _payload: &[u8],
        _epoch: u64,
        _sequence: u64,
    ) -> Result<Vec<u8>, scp_core::context::ContextError> {
        Ok(Vec::new())
    }
}

// ---------------------------------------------------------------------------
// BridgeInMemoryStorage — bridge-local Storage implementation
//
// This avoids pulling in `scp-platform/testing` (which also exposes
// `InMemoryKeyCustody`) just for event log persistence. Production builds
// must not compile `InMemoryKeyCustody` unconditionally.
// ---------------------------------------------------------------------------

/// In-memory `Storage` implementation for the NAPI bridge event log.
///
/// Identical in behavior to `scp_platform::testing::InMemoryStorage` but
/// defined locally so the `testing` feature is not required in production
/// dependencies. Only used as the backing store for the
/// `EncryptingAdapter`-wrapped `ProtocolRepository` that feeds the
/// `MerkleEventLogProvider`.
pub struct BridgeInMemoryStorage {
    data: tokio::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>,
}

impl BridgeInMemoryStorage {
    fn new() -> Self {
        Self {
            data: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

#[allow(clippy::manual_async_fn)]
impl Storage for BridgeInMemoryStorage {
    fn store(
        &self,
        key: &str,
        data: &[u8],
    ) -> impl Future<Output = Result<(), PlatformError>> + Send {
        let key = key.to_owned();
        let data = data.to_vec();
        async move {
            self.data.lock().await.insert(key, data);
            Ok(())
        }
    }

    fn retrieve(
        &self,
        key: &str,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, PlatformError>> + Send {
        let key = key.to_owned();
        async move { Ok(self.data.lock().await.get(&key).cloned()) }
    }

    fn delete(&self, key: &str) -> impl Future<Output = Result<(), PlatformError>> + Send {
        let key = key.to_owned();
        async move {
            self.data.lock().await.remove(&key);
            Ok(())
        }
    }

    fn list_keys(
        &self,
        prefix: &str,
    ) -> impl Future<Output = Result<Vec<String>, PlatformError>> + Send {
        let prefix = prefix.to_owned();
        async move {
            let store = self.data.lock().await;
            let mut keys: Vec<String> = store
                .keys()
                .filter(|k| k.starts_with(&prefix))
                .cloned()
                .collect();
            drop(store);
            keys.sort();
            Ok(keys)
        }
    }

    fn delete_prefix(
        &self,
        prefix: &str,
    ) -> impl Future<Output = Result<u64, PlatformError>> + Send {
        let prefix = prefix.to_owned();
        async move {
            let mut store = self.data.lock().await;
            let keys_to_delete: Vec<String> = store
                .keys()
                .filter(|k| k.starts_with(&prefix))
                .cloned()
                .collect();
            let count = keys_to_delete.len() as u64;
            for key in keys_to_delete {
                store.remove(&key);
            }
            drop(store);
            Ok(count)
        }
    }

    fn exists(&self, key: &str) -> impl Future<Output = Result<bool, PlatformError>> + Send {
        let key = key.to_owned();
        async move { Ok(self.data.lock().await.contains_key(&key)) }
    }
}

// ---------------------------------------------------------------------------
// Global identity registry — retained identity state for UCAN delegation
//
// The NAPI bridge stores key custody on the NapiIdentity JS object, but
// bridge functions like `ucan_delegate` need to look up the *delegator's*
// key, not the context creator's key. This registry provides that lookup.
// ---------------------------------------------------------------------------

/// Retained identity state for a single DID in the NAPI bridge.
///
/// Stores the `ScpIdentity` (key handles), `InMemoryKeyCustody` (key
/// material), and `DidDocument` so that bridge functions can look up any
/// registered identity by DID — including `identity_load` and
/// `identity_resolve` which need the document without DHT access (#1144 C6).
#[cfg(feature = "allow_in_memory_custody")]
pub(crate) struct NapiIdentityEntry {
    /// The scp-core identity handle (DID string, key handles).
    pub(crate) identity: scp_identity::ScpIdentity,
    /// The key custody provider holding the actual key material.
    pub(crate) custody: Arc<OpaqueInMemoryKeyCustody>,
    /// The DID document at the time of creation (or last key rotation).
    pub(crate) document: scp_identity::DidDocument,
    /// Identity link attestations (§3.5.1). Stored locally per identity.
    pub(crate) identity_link_attestations:
        Vec<scp_core::identity::attestation::IdentityLinkAttestation>,
}

/// Global registry of identity state, keyed by DID string.
#[cfg(feature = "allow_in_memory_custody")]
static IDENTITY_REGISTRY: OnceLock<DashMap<String, NapiIdentityEntry>> = OnceLock::new();

/// Returns a reference to the global identity registry.
#[cfg(feature = "allow_in_memory_custody")]
fn identity_registry() -> &'static DashMap<String, NapiIdentityEntry> {
    IDENTITY_REGISTRY.get_or_init(DashMap::new)
}

/// Registers an identity in the global identity registry.
///
/// Called by `identity_create` and `identity_create_with_agent_key` after
/// successfully creating an identity. Bridge functions (`ucan_delegate`)
/// look up the retained `InMemoryKeyCustody` and `KeyHandle`s via
/// [`with_identity`].
///
/// Overwrites any existing entry for the same DID (idempotent — supports
/// key rotation where the same DID gets new key material).
#[cfg(feature = "allow_in_memory_custody")]
pub(crate) fn register_identity(did: &str, entry: NapiIdentityEntry) {
    identity_registry().insert(did.to_owned(), entry);
}

/// Removes an identity from the global identity registry.
///
/// Called when an identity is migrated to a new DID or during cleanup.
/// The old entry is removed and its key material is dropped.
///
/// Idempotent: no-op if the DID is not present.
#[cfg(feature = "allow_in_memory_custody")]
pub(crate) fn remove_identity(did: &str) {
    identity_registry().remove(did);
}

/// Removes an identity from the global identity registry if present.
///
/// Returns `true` if the identity was found and removed, `false` if the
/// DID was not in the registry.
///
/// Provided as a cleanup mechanism for long-running processes alongside
/// [`remove_identity`] which is unconditional.
#[cfg(feature = "allow_in_memory_custody")]
#[must_use]
pub(crate) fn remove_identity_if_present(did: &str) -> bool {
    identity_registry().remove(did).is_some()
}

/// Executes a closure with a reference to an identity's retained state.
///
/// Looks up the identity by DID in the global registry and calls `f` with
/// a reference to the [`NapiIdentityEntry`].
///
/// # Errors
///
/// Returns `ScpNapiError::Permission` if the DID is not found (the identity
/// was not created via `identity_create` in this process).
#[cfg(feature = "allow_in_memory_custody")]
pub(crate) fn with_identity<T, F>(did: &str, f: F) -> Result<T, ScpNapiError>
where
    F: FnOnce(&NapiIdentityEntry) -> Result<T, ScpNapiError>,
{
    let entry = identity_registry()
        .get(did)
        .ok_or_else(|| ScpNapiError::Permission {
            message: format!(
                "identity '{did}' not found in registry — was it created with \
                 identityCreate(\"in_memory\") in this process?"
            ),
            code: "SCP-PERM-3023".to_owned(),
        })?;

    f(entry.value())
}

/// Executes a closure with mutable access to an identity's retained state.
///
/// Uses `DashMap::get_mut` for fine-grained per-key write locking.
///
/// # Errors
///
/// Returns `ScpNapiError::Permission` if the DID is not found.
#[cfg(feature = "allow_in_memory_custody")]
pub(crate) fn with_identity_mut<T, F>(did: &str, f: F) -> Result<T, ScpNapiError>
where
    F: FnOnce(&mut NapiIdentityEntry) -> Result<T, ScpNapiError>,
{
    let mut entry = identity_registry()
        .get_mut(did)
        .ok_or_else(|| ScpNapiError::Permission {
            message: format!(
                "identity '{did}' not found in registry — was it created with \
                 identityCreate(\"in_memory\") in this process?"
            ),
            code: "SCP-PERM-3023".to_owned(),
        })?;

    f(entry.value_mut())
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
            .map(scp_core::context::roles::Capability::ucan_capability_name)
            .collect::<HashSet<String>>()
    } else {
        handle_ceiling
            .into_iter()
            .map(|s| scp_core::context::roles::Capability::new(&s).ucan_capability_name())
            .collect::<HashSet<String>>()
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

/// Re-syncs the `UcanContextState.role_state` for a context from the shared
/// `ContextManager`.
///
/// Must be called after any governance action that modifies role state
/// (`ChangeRole`, `ModifyCeiling`, `AddMember`, `RemoveMember`, etc.) so that
/// the NAPI-side copy used by UCAN/tool capability checks stays current.
///
/// # Errors
///
/// Returns `ScpNapiError` if the context is not registered in either the
/// manager or the UCAN state registry.
pub async fn sync_role_state_from_manager(context_id: &str) -> Result<(), ScpNapiError> {
    let mgr = CONTEXT_MANAGER.get().ok_or_else(|| ScpNapiError::Context {
        message: "ContextManager not initialized — call context_create first".to_owned(),
        code: "SCP-CTX-2000".to_owned(),
    })?;
    let new_role_state =
        mgr.get_role_state(context_id)
            .await
            .ok_or_else(|| ScpNapiError::Context {
                message: format!("context '{context_id}' not found in ContextManager"),
                code: "SCP-CTX-2023".to_owned(),
            })?;

    with_context(context_id, |st| {
        st.role_state = new_role_state;
        Ok(())
    })
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
            let total = u64::try_from(entry.event_log.leaves().len()).unwrap_or(u64::MAX);
            (total, 0)
        }
        None => (0, 0),
    }
}

// ---------------------------------------------------------------------------
// Invitation rate limit tracker registry (#614)
// ---------------------------------------------------------------------------

/// Global rate limit tracker registry for invitation auto-accept, keyed by
/// identity DID.
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
pub fn with_rate_limit_tracker<F, T>(identity_did: &str, f: F) -> T
where
    F: FnOnce(&mut scp_core::context::invitation::RateLimitTracker) -> T,
{
    let registry = rate_limit_registry();
    let mut entry = registry.entry(identity_did.to_owned()).or_default();
    f(entry.value_mut())
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
        .map(scp_core::context::roles::Capability::ucan_capability_name)
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
// Transport provider — uses NotConfiguredTransportProvider from scp-core
// ---------------------------------------------------------------------------
//
// The NAPI bridge uses `scp_core::context::NotConfiguredTransportProvider`
// instead of a bridge-local no-op. This returns descriptive errors when
// transport operations are attempted without configuring a relay, rather
// than silently succeeding. See issue #501.

// NapiBridgeEventLogProvider removed — replaced by MerkleEventLogProvider
// with ProtocolRepositoryEventLogBridge persistence (issue #484).

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

// ---------------------------------------------------------------------------
// Economy state registries
// ---------------------------------------------------------------------------

/// Per-context member budget trackers for economic governance.
static ECONOMY_BUDGETS: OnceLock<DashMap<String, scp_core::economy::MemberBudgetTracker>> =
    OnceLock::new();

fn economy_budget_registry() -> &'static DashMap<String, scp_core::economy::MemberBudgetTracker> {
    ECONOMY_BUDGETS.get_or_init(DashMap::new)
}

/// Per-context antispam velocity trackers.
static ECONOMY_ANTISPAM: OnceLock<DashMap<String, scp_core::economy::SenderVelocityTracker>> =
    OnceLock::new();

const ANTISPAM_DEFAULT_WINDOW_SECS: u64 = 60;

fn economy_antispam_registry() -> &'static DashMap<String, scp_core::economy::SenderVelocityTracker>
{
    ECONOMY_ANTISPAM.get_or_init(DashMap::new)
}

/// Reads the budget tracker for a context (creates if absent).
pub fn with_economy_budget<T, F>(context_id: &str, f: F) -> T
where
    F: FnOnce(&scp_core::economy::MemberBudgetTracker) -> T,
{
    let registry = economy_budget_registry();
    let entry = registry.entry(context_id.to_owned()).or_default();
    f(entry.value())
}

/// Mutably accesses the budget tracker for a context (creates if absent).
pub fn with_economy_budget_mut<T, F>(context_id: &str, f: F) -> T
where
    F: FnOnce(&mut scp_core::economy::MemberBudgetTracker) -> T,
{
    let registry = economy_budget_registry();
    let mut entry = registry.entry(context_id.to_owned()).or_default();
    f(entry.value_mut())
}

/// Accesses the antispam velocity tracker for a context (creates if absent).
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
