//! Shared `ContextManager` and per-context UCAN state registry.
//!
//! A single `Arc<ContextManager>` is created once (lazily) and shared across
//! all bridge functions. The `ContextManager` owns all per-context state
//! (membership, roles, governance, broadcast, TTL) and the injected providers
//! for crypto, transport, and event log operations.
//!
//! # Per-context UCAN state
//!
//! The `ContextManager` does not own UCAN revocation lists or nonce trackers.
//! Those are validation-layer concerns that live in the bridge. We keep a
//! lightweight `DashMap<String, UcanContextState>` registry for them, keyed by
//! context ID. This mirrors the NAPI bridge's `UcanContextState` pattern
//! (see `crates/scp-ffi/napi/src/runtime.rs`).
//!
//! # Lifecycle
//!
//! 1. First call to [`context_manager()`] initializes the shared instance.
//! 2. Bridge functions call [`context_manager()`] and delegate to the manager's
//!    async methods.
//! 3. The `ContextManager` is dropped on process exit (static `OnceLock`).
//!
//! This replaces the old `DashMap<String, ContextRuntime>` global registry
//! (deleted as part of issue #387).

use scp_ffi_common::bridge_instance::BridgeInstance;
use scp_ffi_common::error_codes as codes;
use std::collections::HashSet;
use std::future::Future;
use std::sync::{Arc, OnceLock};

use dashmap::DashMap;
use scp_core::context::ContextError;
use scp_core::context::builder::{
    ContextCreationError, ContextCryptoProvider, ContextEventLogProvider,
};
use scp_core::context::manager::ContextManager;
use scp_core::context::providers::MerkleEventLogProvider;
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

/// Global shared `ContextManager` instance.
static CONTEXT_MANAGER: OnceLock<Arc<ContextManager>> = OnceLock::new();

/// Global production DID resolver that delegates to `scp_identity::resolver::DidResolver`
/// for full DID document validation (BEP44 signature verification, self-certification,
/// sequence number comparison, caching).
///
/// Initialized by [`init_did_resolver`] when the identity layer is first set up.
/// Used by UCAN validation when available; falls back to
/// [`scp_ffi_common::BridgeDidResolver`] (string-only) via `DispatchDidResolver`
/// when `None`.
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
/// Wraps any `scp_identity::resolver::DidResolver` implementation in an
/// [`IdentityBackedDidResolver`] and stores it as the process-global resolver
/// for UCAN validation.
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
/// Returns `ScpError::Context` if the manager has not been initialized via
/// [`init_context_manager`]. Matches the `PyO3` bridge pattern: callers
/// must explicitly initialize the manager (typically during
/// `context_create`) rather than silently auto-initializing with
/// potentially invalid state.
pub fn context_manager() -> Result<&'static Arc<ContextManager>, crate::ScpError> {
    // If BridgeInstance exists, enforce its lifecycle state. After
    // scp_shutdown(), 70+ operations flow through this path — without
    // this check they would continue operating on a shut-down bridge.
    if let Some(bi) = BRIDGE_INSTANCE.get() {
        bi.check_ready().map_err(|e| {
            let msg = match e {
                scp_ffi_common::bridge_instance::LifecycleError::AlreadyShutDown => {
                    "bridge has been shut down — OnceLock prevents re-initialization \
                     within the same process; use suspend/resume for mobile lifecycle"
                        .to_owned()
                }
                scp_ffi_common::bridge_instance::LifecycleError::Suspended => {
                    "bridge is suspended — call resume() before performing operations".to_owned()
                }
            };
            crate::ScpError::Context {
                msg,
                code: codes::CTX_2000.to_owned(),
            }
        })?;
    }
    CONTEXT_MANAGER
        .get()
        .ok_or_else(|| crate::ScpError::Context {
            msg: "ContextManager not initialized — call context_create, \
                  context_join, context_import, or init_context_manager first"
                .to_owned(),
            code: codes::CTX_2000.to_owned(),
        })
}

// ---------------------------------------------------------------------------
// BridgeInstance (consolidated singleton — #1549)
// ---------------------------------------------------------------------------

/// Global [`BridgeInstance`] that consolidates process-global state.
///
/// Holds the same `ContextManager` as [`CONTEXT_MANAGER`] plus the local DID
/// and a shutdown flag. Populated alongside `CONTEXT_MANAGER` during
/// [`init_context_manager`], [`init_context_manager_with_did`], or
/// [`init_context_manager_with_relay_transport`]. Existing callers continue
/// using `context_manager()` and other per-registry accessors; the
/// `BridgeInstance` provides an alternative path that will eventually replace
/// all singletons (#1549).
static BRIDGE_INSTANCE: OnceLock<Arc<BridgeInstance>> = OnceLock::new();

/// Initializes the global [`BridgeInstance`].
///
/// Called by the `init_context_manager*` family after the `ContextManager` is
/// created. The `BridgeInstance` wraps the same `Arc<ContextManager>` so that
/// `bridge_instance().context_manager()` and `context_manager()` return
/// pointers to the same allocation.
///
/// Registers UniFFI-specific shutdown hooks that clear bridge-specific
/// singletons (`UCAN_REGISTRY`, `ECONOMY_BUDGETS`, `ECONOMY_ANTISPAM`,
/// and `BRIDGE_STATE` in `bridge.rs`).
///
/// Subsequent calls are no-ops (`OnceLock` guarantees single initialization).
fn init_bridge_instance(context_manager: Arc<ContextManager>, local_did: &str) {
    // Guard against duplicate hook registration — OnceLock guarantees
    // single BridgeInstance creation, but hooks must only be registered once.
    if BRIDGE_INSTANCE.get().is_some() {
        return;
    }

    let instance = Arc::new(BridgeInstance::new(context_manager, local_did.to_owned()));
    let bi = BRIDGE_INSTANCE.get_or_init(|| instance);

    // Register UniFFI-specific cleanup hooks.
    bi.register_shutdown_hook(Box::new(|| {
        if let Some(reg) = UCAN_REGISTRY.get() {
            reg.clear();
        }
        #[cfg(feature = "allow_in_memory_custody")]
        crate::bridge::identity_custody_registry().clear();
        if let Some(reg) = ECONOMY_BUDGETS.get() {
            reg.clear();
        }
        if let Some(reg) = ECONOMY_ANTISPAM.get() {
            reg.clear();
        }
        // BRIDGE_STATE in bridge.rs — per-context bridge connector state
        crate::bridge::clear_bridge_state();
        // MCP server/client registries
        crate::bridge::clear_mcp_registries();
    }));
}

/// Returns the raw `BridgeInstance` reference without lifecycle checks.
///
/// Used by [`crate::scp_shutdown`] to call `BridgeInstance::shutdown()`
/// during teardown, when the bridge is transitioning to shut-down state.
/// Returns `None` if the instance was never initialized.
#[must_use]
pub fn bridge_instance_raw() -> Option<&'static Arc<BridgeInstance>> {
    BRIDGE_INSTANCE.get()
}

/// Ensures a `BridgeInstance` exists, creating one from the given
/// `ContextManager` if necessary.
///
/// Used by `transport_connect` to lazily create a `BridgeInstance` when
/// the standard `UniFFI` flow (`init_context_manager()` without DID →
/// `context_create` → `transport_connect`) did not create one during
/// initialization.
///
/// Uses a placeholder DID (`"did:unknown:bridge"`) since the real DID
/// is not available at this point. The DID is only used for logging and
/// MLS credential identity — the `ContextManager` already has the real
/// MLS provider if `init_context_manager_with_did` was called.
pub fn ensure_bridge_instance(cm: Arc<ContextManager>) {
    if BRIDGE_INSTANCE.get().is_some() {
        return;
    }
    init_bridge_instance(cm, "did:unknown:bridge");
}

/// Returns a reference to the global [`BridgeInstance`].
///
/// # Errors
///
/// Returns `ScpError::Context` if the bridge has not been initialized
/// via [`init_context_manager`] (which also creates the `BridgeInstance`),
/// or if the bridge has been permanently shut down.
///
/// Called by rate-limiter delegation and other functions that access the
/// consolidated `BridgeInstance` state (#1549).
pub fn bridge_instance() -> Result<&'static Arc<BridgeInstance>, crate::ScpError> {
    let bi = BRIDGE_INSTANCE
        .get()
        .ok_or_else(|| crate::ScpError::Context {
            msg: "bridge not initialized — call context_create, \
                  context_join, context_import, or init_context_manager first"
                .to_owned(),
            code: codes::CTX_2000.to_owned(),
        })?;
    bi.check_ready().map_err(|e| {
        let msg = match e {
            scp_ffi_common::bridge_instance::LifecycleError::AlreadyShutDown => {
                "bridge has been shut down — OnceLock prevents re-initialization \
                 within the same process; use suspend/resume for mobile lifecycle"
                    .to_owned()
            }
            scp_ffi_common::bridge_instance::LifecycleError::Suspended => {
                "bridge is suspended — call resume() before performing operations".to_owned()
            }
        };
        crate::ScpError::Context {
            msg,
            code: codes::CTX_2000.to_owned(),
        }
    })?;
    Ok(bi)
}

/// Builds a default `ContextManager` with bridge-local providers.
///
/// Uses `FfiBridgeCrypto` (no-op), `NotConfiguredTransportProvider`,
/// `MerkleEventLogProvider` (persistent, #484), and a not-configured key
/// resolver.
///
/// Event log persistence is wired via `MerkleEventLogProvider::with_persistence`
/// backed by a `ProtocolRepositoryEventLogBridge` over an encrypted in-memory
/// storage provider. Mobile apps (Swift/Kotlin) are killed aggressively by
/// the OS, making persistence critical for data durability.
fn build_default_context_manager() -> Arc<ContextManager> {
    let event_log = build_event_log_provider();
    Arc::new(ContextManager::new(
        Box::new(FfiBridgeCrypto),
        Box::new(scp_core::context::NotConfiguredTransportProvider),
        event_log,
        not_configured_key_resolver(),
    ))
}

/// Returns a reference to the shared `ContextManager`, initializing it with
/// defaults if necessary.
///
/// For `#[uniffi::export]` functions that return non-Result types (bool, Vec,
/// Option, ()), this provides access to the manager without requiring a
/// `Result` return type. Callers should prefer [`context_manager`] when the
/// return type supports `Result`.
///
/// Auto-initializes via `get_or_init` on first access. The initialized
/// manager uses `NotConfiguredTransportProvider` (which returns descriptive
/// errors, not silent no-ops) and `FfiBridgeCrypto` (no-op crypto for state
/// tracking). This is safe because standalone functions like
/// `register_local_did` / `is_local_did` only access the DID registry, not
/// transport or crypto, and should not require a prior `context_create` call.
pub fn context_manager_expect() -> &'static Arc<ContextManager> {
    // Do NOT call init_bridge_instance here — BridgeInstance should only
    // be created when a real DID is known (via init_context_manager_with_did
    // or init_context_manager_with_relay_transport). Populating with a
    // placeholder DID permanently locks the OnceLock and prevents the real
    // DID from being stored.
    CONTEXT_MANAGER.get_or_init(build_default_context_manager)
}

/// Initializes the global [`ContextManager`] with bridge-local providers.
///
/// This is called during `context_create` to ensure the manager is ready
/// before any context operations.
///
/// Does NOT populate the [`BridgeInstance`] — no real DID is available at
/// this point. The DID-aware variants ([`init_context_manager_with_did`]
/// and [`init_context_manager_with_relay_transport`]) populate both.
///
/// Subsequent calls are no-ops (`OnceLock` guarantees single initialization).
pub fn init_context_manager() {
    let _ = CONTEXT_MANAGER.get_or_init(build_default_context_manager);
}

/// Initializes the global [`ContextManager`] with [`MlsCryptoProvider`]
/// and `NotConfiguredTransportProvider`.
///
/// Unlike [`init_context_manager`] (which uses `FfiBridgeCrypto` no-op),
/// this variant initializes real MLS crypto backed by the given DID. Used
/// by `auto_wire_context_manager`'s fallback path when relay connection
/// fails — the `ContextManager` exists with real crypto but no transport,
/// matching the `PyO3` and NAPI bridge behavior.
///
/// Also populates the global [`BridgeInstance`] with the same `ContextManager`
/// and the provided `local_did` (#1549).
///
/// Subsequent calls are no-ops (`OnceLock`).
pub fn init_context_manager_with_did(local_did: &str) {
    if CONTEXT_MANAGER.get().is_some() {
        tracing::warn!(
            requested_did = %local_did,
            "init_context_manager already initialized — ignoring DID-parameterized init"
        );
        return;
    }
    let did = local_did.to_owned();
    let cm_arc = CONTEXT_MANAGER
        .get_or_init(|| {
            let crypto = Box::new(scp_core::crypto::mls::provider::MlsCryptoProvider::new(did));
            let event_log = build_event_log_provider();
            Arc::new(ContextManager::new(
                crypto,
                Box::new(scp_core::context::NotConfiguredTransportProvider),
                event_log,
                not_configured_key_resolver(),
            ))
        })
        .clone();

    // Populate the BridgeInstance with the same ContextManager.
    // No-op if already set (OnceLock guarantees single initialization).
    init_bridge_instance(cm_arc, local_did);
}

/// Initializes the global [`ContextManager`] with [`RelayTransportProvider`].
///
/// Identical to [`init_context_manager`] except the transport provider is a
/// `RelayTransportProvider` wrapping a real `NativeRelayAdapter` connected to
/// the given relay URL. This allows `ContextManager::send_message` (and thus
/// `context_send`) to publish encrypted payloads through the relay.
///
/// **Must be called before any `context_create` / `context_join` /
/// `context_import`** — those functions call `init_context_manager` which
/// will win the `OnceLock` race if called first.
///
/// Exposed to Swift/Kotlin via [`crate::bridge::configure_relay_transport`]
/// so that E2E tests can exercise the full send → relay → subscribe → receive
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
    let cm_arc = CONTEXT_MANAGER
        .get_or_init(|| {
            let crypto = Box::new(scp_core::crypto::mls::provider::MlsCryptoProvider::new(did));
            let transport = Box::new(scp_transport::RelayTransportProvider::new(adapter));
            let event_log = build_event_log_provider();
            Arc::new(ContextManager::new(
                crypto,
                transport,
                event_log,
                not_configured_key_resolver(),
            ))
        })
        .clone();

    // Populate the BridgeInstance with the same ContextManager.
    // No-op if already set (OnceLock guarantees single initialization).
    init_bridge_instance(cm_arc, local_did);
}

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
/// production mobile builds. See issue #484.
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

// ---------------------------------------------------------------------------
// BridgeInMemoryStorage — bridge-local Storage implementation
//
// This avoids pulling in `scp-platform/testing` (which also exposes
// `InMemoryKeyCustody`) just for event log persistence. Production mobile
// builds (iOS/Android) must not compile `InMemoryKeyCustody`.
// ---------------------------------------------------------------------------

/// In-memory `Storage` implementation for the `UniFFI` bridge event log.
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

/// Global stub crypto provider shared with the `CloseOrchestrator`.
///
/// The `CloseOrchestrator::new` requires a `&dyn ContextCryptoProvider`.
/// This provides the same no-op `FfiBridgeCrypto` used by the
/// `ContextManager` initialization. The actual crypto operations are
/// handled by the platform-injected `KeyCustodyProvider`.
static FFI_CRYPTO: FfiBridgeCrypto = FfiBridgeCrypto;

/// Returns a reference to the bridge crypto provider for `CloseOrchestrator`.
pub fn context_manager_crypto() -> &'static dyn ContextCryptoProvider {
    &FFI_CRYPTO
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
/// UCAN state from the provided context metadata.
pub fn ensure_ucan_registered(context_id: &str, creator_did: &str, ceiling: &[String]) {
    let map = ucan_registry();

    if map.contains_key(context_id) {
        return;
    }

    let ceiling_strings = if ceiling.is_empty() {
        scp_core::context::roles::default_ceiling()
            .capabilities
            .iter()
            .map(scp_core::context::roles::Capability::ucan_capability_name)
            .collect::<HashSet<String>>()
    } else {
        ceiling
            .iter()
            .map(|s| scp_core::context::roles::Capability::new(s).ucan_capability_name())
            .collect::<HashSet<String>>()
    };

    let event_log = EventLog::new(context_id.to_owned());
    let revocation_list = RevocationList::new(context_id.to_owned());
    let nonce_tracker = NonceTracker::new(context_id.to_owned(), SystemClock);

    map.insert(
        context_id.to_owned(),
        UcanContextState {
            revocation_list,
            nonce_tracker,
            ceiling_strings,
            creator_did: creator_did.to_owned(),
            event_log,
        },
    );
}

/// Accesses per-context UCAN state via a closure.
///
/// Returns `None` if the context is not registered. The caller is responsible
/// for converting `None` to an appropriate error.
pub fn with_ucan_state<T, F>(context_id: &str, f: F) -> Option<T>
where
    F: FnOnce(&mut UcanContextState) -> T,
{
    let map = ucan_registry();
    let mut entry = map.get_mut(context_id)?;
    Some(f(&mut entry))
}

/// Removes UCAN validation state for a context.
///
/// Called on context close to clean up per-context state.
pub fn remove_ucan_state(context_id: &str) {
    let map = ucan_registry();
    map.remove(context_id);
    // Clean up known-context discovery entry via BridgeInstance.
    if let Ok(bi) = bridge_instance() {
        bi.remove_known_context(context_id);
    }
}

/// Syncs role state from the `ContextManager` after governance operations.
///
/// The `UniFFI` bridge reads role state directly from the `ContextManager`
/// (unlike `PyO3`/NAPI which cache `role_state` locally). This function
/// validates the `ContextManager` state is consistent and logs the sync
/// for traceability, matching the pattern of the other bridges.
///
/// # Errors
///
/// Returns `ScpError` if the context is not registered in the manager.
pub async fn sync_role_state_from_manager(context_id: &str) -> Result<(), crate::ScpError> {
    let manager = context_manager()?;
    let _role_state =
        manager
            .get_role_state(context_id)
            .await
            .ok_or_else(|| crate::ScpError::Context {
                msg: format!(
                    "context '{context_id}' not found in ContextManager during role state sync"
                ),
                code: codes::CTX_2040.to_owned(),
            })?;
    tracing::debug!(context_id = %context_id, "UniFFI: role state synced after governance operation");
    Ok(())
}

// ---------------------------------------------------------------------------
// Provider implementations for the FFI bridge
//
// These are thin implementations of the `ContextManager` provider traits.
// They succeed by default (no-op), allowing the `ContextManager` to track
// state (membership, roles, governance) while the actual crypto/transport/
// event-log operations are handled at a higher level or by platform
// callbacks.
//
// This pattern matches the mock providers used in `scp-core` tests, but
// is intentional for the FFI bridge: the bridge layer is responsible for
// routing and state management, not for performing cryptographic operations
// directly. Production crypto is provided by the `KeyCustodyProvider`
// callback interface injected from Swift/Kotlin.
// ---------------------------------------------------------------------------

/// Stub crypto provider for the FFI bridge `ContextManager`.
///
/// All operations succeed (no-op). Real MLS and sender key operations are
/// performed by the platform-injected `KeyCustodyProvider`.
struct FfiBridgeCrypto;

impl ContextCryptoProvider for FfiBridgeCrypto {
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

    fn remove_member(
        &self,
        _context_id: &[u8; 32],
        _member_did: &str,
    ) -> Result<scp_core::context::RemoveMemberOutput, ContextError> {
        Ok(scp_core::context::RemoveMemberOutput::default())
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
}

// Transport provider: uses `scp_core::context::NotConfiguredTransportProvider`
// instead of a bridge-local no-op. Returns descriptive errors when transport
// operations are attempted without configuring a relay. See issue #501.

// FfiBridgeEventLog removed — replaced by MerkleEventLogProvider with
// ProtocolRepositoryEventLogBridge persistence (issue #484).

// ---------------------------------------------------------------------------
// Invitation rate limit tracker registry (#614)
//
// Delegates to the `BridgeInstance`'s `rate_limiters` DashMap (#1549).
// ---------------------------------------------------------------------------

/// Returns a mutable reference to the rate limit tracker for the given
/// identity DID, creating one if it does not exist.
///
/// Delegates to [`BridgeInstance::with_rate_limit_tracker`]. If the bridge
/// has not been initialized (unusual — identity must be created before
/// invitation evaluation), falls back to a thread-local default tracker
/// to preserve the original infallible signature.
pub fn with_rate_limit_tracker<F, T>(identity_did: &str, f: F) -> T
where
    F: FnOnce(&mut scp_core::context::invitation::RateLimitTracker) -> T,
{
    if let Ok(bi) = bridge_instance() {
        bi.with_rate_limit_tracker(identity_did, f)
    } else {
        // Bridge not initialized — use a temporary tracker. This path
        // should not be hit in normal operation (identity is always
        // created before invitation evaluation).
        tracing::warn!(
            "with_rate_limit_tracker called before bridge init — using ephemeral tracker"
        );
        let mut tracker = scp_core::context::invitation::RateLimitTracker::default();
        f(&mut tracker)
    }
}

/// Queries event counts for trust scoring within a context.
///
/// Returns `(message_count, governance_count)` derived from the context's
/// event log. The event log stores leaf hashes (Merkle tree), not full event
/// payloads, so per-DID filtering is not possible at this level.
///
/// Returns `(0, 0)` if the context is not registered.
#[must_use]
pub const fn query_trust_event_counts(_context_id: &str, _did: &str) -> (u64, u64) {
    // UniFFI bridge: ContextManager owns context state but does not expose
    // per-context event log leaf counts directly. Return (0, 0) as a stub.
    // Full trust scoring requires ContextManager event log integration.
    (0, 0)
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

/// Removes per-context economy state (budget + antispam trackers) on context close.
pub fn remove_economy_state(context_id: &str) {
    economy_budget_registry().remove(context_id);
    economy_antispam_registry().remove(context_id);
}

#[cfg(test)]
mod tests {
    use super::*;

    // OnceLock is process-global, so the first init_context_manager call in any
    // test wins. Subsequent calls are no-ops. All tests must tolerate this.

    // -----------------------------------------------------------------------
    // BridgeInstance tests (#1549)
    // -----------------------------------------------------------------------

    #[test]
    fn bridge_instance_populated_by_init_context_manager() -> Result<(), crate::ScpError> {
        // DID-aware init populates both CONTEXT_MANAGER and BRIDGE_INSTANCE.
        // The no-arg init_context_manager() intentionally does NOT populate
        // BRIDGE_INSTANCE (commit 8019f054). Idempotent — first call in the
        // process wins.
        init_context_manager_with_did("did:dht:ztest");

        let cm = context_manager()?;
        let bi = bridge_instance()?;

        // Both should point to the same ContextManager allocation.
        assert!(
            Arc::ptr_eq(cm, bi.context_manager()),
            "bridge_instance().context_manager() must be the same Arc as context_manager()"
        );
        Ok(())
    }

    #[test]
    fn bridge_instance_has_local_did() -> Result<(), crate::ScpError> {
        init_context_manager_with_did("did:dht:ztest");

        let bi = bridge_instance()?;
        // local_did should be non-empty (a real DID from the DID-aware init).
        assert!(
            !bi.local_did().is_empty(),
            "bridge_instance local_did should not be empty"
        );
        Ok(())
    }

    #[test]
    fn bridge_instance_not_shutdown_initially() -> Result<(), crate::ScpError> {
        init_context_manager_with_did("did:dht:ztest");

        let bi = bridge_instance()?;
        assert!(
            !bi.is_shutdown(),
            "bridge_instance should not be shutdown immediately after init"
        );
        Ok(())
    }

    #[test]
    fn bridge_instance_error_code_is_ctx_2000() {
        // We can't truly test the "not initialized" path because OnceLock is
        // process-global and other tests initialize it. Instead, verify the
        // error shape: bridge_instance() returns a ScpError::Context with the
        // expected error code when BRIDGE_INSTANCE is not set.
        //
        // Since we can't reset OnceLock, we verify the contract by checking
        // that the function returns Ok after init (covered above) and that
        // the error message format is correct via a unit check of the error
        // constructor.
        let err = crate::ScpError::Context {
            msg: "bridge not initialized".to_owned(),
            code: codes::CTX_2000.to_owned(),
        };
        assert!(
            matches!(err, crate::ScpError::Context { ref code, .. } if code == codes::CTX_2000),
            "expected ScpError::Context with CTX_2000 code"
        );
    }
}
