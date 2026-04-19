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

use async_trait::async_trait;
use scp_ffi_common::bridge_instance::{BridgeInstanceCore, ShutdownError, ShutdownOutcome};
// Re-export `CoreFields` at `crate::runtime::CoreFields` so the
// `napi_check_handle!` macro can refer to it as `$crate::runtime::CoreFields`
// without each caller importing the full `scp_ffi_common` path.
pub use scp_ffi_common::bridge_instance::CoreFields;
use scp_ffi_common::bridge_runtime::BridgeInMemoryStorage;
use scp_ffi_common::error_codes as codes;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

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
use scp_platform::encrypting_adapter::EncryptingAdapter;

use crate::context::NapiContextHandle;
use crate::error::ScpNapiError;
#[cfg(feature = "allow_in_memory_custody")]
use crate::identity::OpaqueInMemoryKeyCustody;

// ---------------------------------------------------------------------------
// NapiBridgeInstance — per-bridge concrete bridge instance (#1549 Phase 4 PR 1)
// ---------------------------------------------------------------------------

/// Storage configuration for [`NapiBridgeInstance`].
///
/// During Phase 4 PR 1 only the in-memory variant is exposed; the
/// `SQLite` variant lands in PR 3 alongside
/// [`scp_platform::sqlite::SqliteStorage`]. Kept here (not in
/// `scp-ffi-common`) because each bridge owns its own storage shape until
/// the shared type lands.
#[derive(Debug, Clone, Default)]
pub enum StorageConfig {
    /// Encrypted in-memory storage — the only variant supported in PR 1.
    #[default]
    InMemory,
}

/// NAPI-specific concrete bridge instance.
///
/// Embeds the bridge-agnostic [`CoreFields`] and adds typed fields for the
/// NAPI-specific registries (UCAN state, identity state, protocol
/// repository). The MCP registries continue to live in [`crate::mcp`] as
/// their own `OnceLock`s during PR 1 — they move onto this struct in PR 2.
///
/// Constructed via [`NapiBridgeInstance::new_napi`] /
/// [`NapiBridgeInstance::with_persistence_napi`] /
/// [`NapiBridgeInstance::with_storage_napi`]. The default global instance is
/// lazily allocated into [`DEFAULT_BRIDGE_INSTANCE`]; user-owned instances
/// (via `#[napi] Scp`) build their own instead.
///
/// Implements [`BridgeInstanceCore`] so shared helpers can operate on
/// `&dyn BridgeInstanceCore`. `shutdown(timeout)` delegates to
/// [`CoreFields::shutdown_core_async`] and then drops the NAPI-specific
/// registries in [`BridgeInstanceCore::bridge_specific_shutdown`].
pub struct NapiBridgeInstance {
    /// Bridge-agnostic core state.
    pub(crate) core: CoreFields,

    /// Per-context UCAN validation state (revocation lists, nonce trackers,
    /// role state, tool registries, tool handlers, session stores).
    ///
    /// Previously stored type-erased in `CoreFields::ucan_registry`. Post
    /// PR 1, the registry lives here as a typed field and is cleared by
    /// [`BridgeInstanceCore::bridge_specific_shutdown`].
    pub(crate) ucan_registry: Arc<DashMap<String, UcanContextState>>,

    /// Retained identity state for in-memory custody DIDs.
    ///
    /// Previously stored type-erased in `CoreFields::identity_registry`.
    /// Feature-gated because only the `allow_in_memory_custody` build flag
    /// pulls in [`OpaqueInMemoryKeyCustody`]. Cleared on shutdown — drops
    /// the `Arc<OpaqueInMemoryKeyCustody>` values which zeroize their
    /// underlying key material via `Drop`.
    #[cfg(feature = "allow_in_memory_custody")]
    pub(crate) identity_registry: Arc<DashMap<String, NapiIdentityEntry>>,

    /// Protocol repository used for trust aggregation + event log persistence.
    ///
    /// Previously stored type-erased in `CoreFields::protocol_repository`.
    /// Wrapped in `Arc` for cheap clones into the `MerkleEventLogProvider`.
    pub(crate) protocol_repository:
        Arc<ProtocolRepository<EncryptingAdapter<BridgeInMemoryStorage>>>,
}

impl NapiBridgeInstance {
    /// Constructs a new `NapiBridgeInstance` with default in-memory state.
    ///
    /// Allocates a fresh `CoreFields` (new `instance_id`, new
    /// `CancellationToken`, empty `JoinSet`) and populates the protocol
    /// repository + typed registries. No `ContextManager` is attached —
    /// callers attach one later via [`CoreFields::set_context_manager`].
    #[must_use]
    pub fn new_napi() -> Self {
        let (_event_log, protocol_repository) =
            scp_ffi_common::bridge_runtime::build_event_log_provider();
        Self {
            core: CoreFields::new(),
            ucan_registry: Arc::new(DashMap::new()),
            #[cfg(feature = "allow_in_memory_custody")]
            identity_registry: Arc::new(DashMap::new()),
            protocol_repository,
        }
    }

    /// Constructs a new `NapiBridgeInstance` with an explicit
    /// [`ContextPersistence`] provider.
    ///
    /// Used by callers that already have a persistence strategy (typically
    /// unit tests; production persistence is wired through PR 3's
    /// [`StorageConfig::InMemory`] path on [`NapiBridgeInstance::with_storage_napi`]).
    #[must_use]
    pub fn with_persistence_napi(persistence: Box<dyn ContextPersistence + Send + Sync>) -> Self {
        let (_event_log, protocol_repository) =
            scp_ffi_common::bridge_runtime::build_event_log_provider();
        Self {
            core: CoreFields::with_persistence(persistence),
            ucan_registry: Arc::new(DashMap::new()),
            #[cfg(feature = "allow_in_memory_custody")]
            identity_registry: Arc::new(DashMap::new()),
            protocol_repository,
        }
    }

    /// Constructs a new `NapiBridgeInstance` honoring a [`StorageConfig`].
    ///
    /// Only [`StorageConfig::InMemory`] is supported in PR 1; PR 3 adds the
    /// `SQLite` variant once [`scp_platform::sqlite::SqliteStorage`] is wired
    /// through the FFI boundary. The current implementation is equivalent
    /// to [`NapiBridgeInstance::new_napi`].
    #[must_use]
    pub fn with_storage_napi(config: StorageConfig) -> Self {
        match config {
            StorageConfig::InMemory => Self::new_napi(),
        }
    }

    /// Returns the monotonic instance id for this bridge.
    #[must_use]
    pub const fn instance_id(&self) -> u64 {
        self.core.instance_id()
    }
}

#[async_trait]
impl BridgeInstanceCore for NapiBridgeInstance {
    fn core(&self) -> &CoreFields {
        &self.core
    }

    async fn shutdown(&self, timeout: Duration) -> Result<ShutdownOutcome, ShutdownError> {
        // `bridge_specific_shutdown` MUST run even when
        // `shutdown_core_async` returns `AlreadyShutDown` — that variant
        // signals the sync shutdown path raced ahead; without the cleanup
        // call, typed NAPI registries (UCAN, identity) leak key material
        // past shutdown.
        let result = self.core.shutdown_core_async(timeout).await;
        self.bridge_specific_shutdown();
        result
    }

    fn bridge_specific_shutdown(&self) {
        // Clear typed registries. Dropping `Arc<OpaqueInMemoryKeyCustody>`
        // values zeroizes any key material they hold via the custody
        // provider's `Drop` impl (matching the behavior of the previous
        // `clear_fn` closures).
        self.ucan_registry.clear();
        #[cfg(feature = "allow_in_memory_custody")]
        self.identity_registry.clear();
        // MCP registries continue to live in `crate::mcp` as their own
        // `OnceLock`s during PR 1 (migrated onto this struct in PR 2).
        // Their clear path runs via the core `shutdown_hooks` vector
        // populated by `init_bridge_instance_empty`.
    }
}

/// A tool handler is a closure that takes validated JSON input and returns
/// JSON output or an error string. Registered via [`register_tool_handler`].
pub type ToolHandler =
    Arc<dyn Fn(serde_json::Value) -> Result<serde_json::Value, String> + Send + Sync>;

// ---------------------------------------------------------------------------
// Global ContextManager instance
// ---------------------------------------------------------------------------

/// Global shared `InMemoryDhtClient` used by the DID resolver.
///
/// Stored here so that `identity_create` can publish newly created DID
/// documents to the same DHT client that the resolver reads from. Without
/// this, UCAN validation fails because `IdentityBackedDidResolver` cannot
/// find the issuer's DID document.
///
/// See issue #1144 (UCAN validation tests require shared DHT state).
static SHARED_DHT_CLIENT: OnceLock<Arc<scp_identity::InMemoryDhtClient>> = OnceLock::new();

/// Returns the production DID resolver, if initialized.
///
/// Reads the default instance's embedded [`CoreFields`] and returns its
/// configured DID resolver. The resolver is a shared, thread-safe handle
/// to an [`scp_ffi_common::IdentityBackedDidResolver`].
#[must_use]
pub fn did_resolver() -> Option<&'static Arc<scp_ffi_common::IdentityBackedDidResolver>> {
    DEFAULT_BRIDGE_INSTANCE.get()?.core.did_resolver()
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

/// Initializes the production DID resolver on the default instance.
///
/// Wraps the resolver in an [`scp_ffi_common::IdentityBackedDidResolver`]
/// and stores it on [`DEFAULT_BRIDGE_INSTANCE`]'s core. Logs an error if
/// the default bridge has not been initialized yet (`identity_create`
/// always runs after `init_context_manager`).
pub fn init_did_resolver<R>(resolver: Arc<R>, handle: tokio::runtime::Handle)
where
    R: scp_identity::resolver::DidResolver + 'static,
{
    if let Some(bi) = DEFAULT_BRIDGE_INSTANCE.get() {
        bi.core
            .set_did_resolver(Arc::new(scp_ffi_common::IdentityBackedDidResolver::new(
                resolver, handle,
            )));
    } else {
        tracing::error!(
            "init_did_resolver called before DEFAULT_BRIDGE_INSTANCE initialized — resolver not stored"
        );
    }
}

/// Returns a key resolver that rejects all lookups with a logged error.
///
/// Delegates to [`scp_ffi_common::bridge_runtime::not_configured_key_resolver`].
fn not_configured_key_resolver() -> scp_core::context::governance::KeyResolver {
    scp_ffi_common::bridge_runtime::not_configured_key_resolver()
}

/// Returns a reference to the shared `ContextManager` on the default
/// bridge instance.
///
/// # Errors
///
/// Returns `napi::Error` if the default bridge has not been initialized
/// via [`init_context_manager`], or if it is currently suspended.
pub fn context_manager() -> napi::Result<&'static Arc<ContextManager>> {
    let bi = DEFAULT_BRIDGE_INSTANCE.get().ok_or_else(|| {
        napi::Error::from(ScpNapiError::Context {
            message: "ContextManager not initialized — call context_create, \
                      context_join, context_import, or init_context_manager first"
                .to_owned(),
            code: codes::CTX_2000.to_owned(),
        })
    })?;
    // Suspended: return error (recoverable — caller should resume()).
    // AlreadyShutDown: warn only — shutdown already destroyed state,
    // operations will fail naturally at MLS/transport layer.
    if bi.core.is_suspended() {
        return Err(napi::Error::from(ScpNapiError::Context {
            message: "bridge is suspended — call resume() before performing operations".to_owned(),
            code: codes::CTX_2000.to_owned(),
        }));
    }
    if bi.core.is_shutdown() {
        tracing::warn!("context_manager() called after shutdown — operations may fail");
    }
    bi.core.try_context_manager().ok_or_else(|| {
        napi::Error::from(ScpNapiError::Context {
            message: "ContextManager not yet attached — call context_create, \
                      context_join, context_import, or init_context_manager first"
                .to_owned(),
            code: codes::CTX_2000.to_owned(),
        })
    })
}

// ---------------------------------------------------------------------------
// Default bridge instance (#1549 Phase 4 PR 1)
//
// The free-function façade (`contextCreate`, `identityCreate`, …) continues
// to work by looking up a single process-global `NapiBridgeInstance` here.
// New callers should instead hold a `#[napi] Scp` instance and call methods
// on it directly. This static will be sunset two release cycles after Phase
// 4 merges (see ADR + plan).
// ---------------------------------------------------------------------------

/// Default [`NapiBridgeInstance`] for the legacy free-function façade.
///
/// Lazily initialized on the first free-function call that touches bridge
/// state (via [`ensure_bridge_instance`]). User-owned instances
/// (from `#[napi] Scp`) do **not** share state with this default — the two
/// paths have independent `ContextManager`s, registries, and transports.
static DEFAULT_BRIDGE_INSTANCE: OnceLock<Arc<NapiBridgeInstance>> = OnceLock::new();

/// Initializes the default [`NapiBridgeInstance`] without a `ContextManager`.
///
/// Called by [`ensure_bridge_instance`] and (transitively) by the
/// `init_context_manager*` family. The `ContextManager` is attached later
/// via [`CoreFields::set_context_manager`] once `identity_create` has
/// produced the local DID and the `MlsCryptoProvider` has been constructed
/// with it. Per spec §12.2.3 the bridge instance carries no DID of its own.
///
/// Subsequent calls are no-ops (`OnceLock` guarantees single initialization).
fn init_default_bridge_instance() {
    // Register the MCP shutdown hook INSIDE the `get_or_init` closure so it
    // runs exactly once per process regardless of how many threads race
    // through `init_default_bridge_instance` before the OnceLock is filled.
    // A prior pattern registered the hook outside the closure, which caused
    // duplicate-registration races under concurrent first-call scenarios.
    let _ = DEFAULT_BRIDGE_INSTANCE.get_or_init(|| {
        let instance = Arc::new(NapiBridgeInstance::new_napi());
        // Shutdown hook for state still living outside the
        // `NapiBridgeInstance` during PR 1 (MCP registries — migrated onto
        // the struct in PR 2). Identity + UCAN registries are now typed
        // fields and are cleared by `bridge_specific_shutdown` without
        // needing a hook.
        instance.core.register_shutdown_hook(Box::new(|| {
            crate::mcp::clear_registries();
        }));
        instance
    });
}

/// Returns the raw default `NapiBridgeInstance`, if initialized.
///
/// Used by [`crate::scp_shutdown`] to reach the default instance during
/// teardown. Returns `None` if the default was never initialized.
#[must_use]
#[cfg_attr(test, allow(dead_code))]
pub fn default_bridge_instance_raw() -> Option<&'static Arc<NapiBridgeInstance>> {
    DEFAULT_BRIDGE_INSTANCE.get()
}

/// Returns a handle to the default `NapiBridgeInstance`, initializing it if needed.
///
/// Used by the `#[napi] Scp::default_instance` factory to surface the same
/// long-lived `Arc` shared by the free-function façade.
///
/// # Errors
///
/// Returns an error if the default bridge has been permanently shut down.
pub fn default_bridge_instance() -> napi::Result<Arc<NapiBridgeInstance>> {
    ensure_bridge_instance();
    let bi = DEFAULT_BRIDGE_INSTANCE.get().ok_or_else(|| {
        napi::Error::from(ScpNapiError::Context {
            message: "default bridge instance not initialized".to_owned(),
            code: codes::CTX_2000.to_owned(),
        })
    })?;
    if bi.core.is_shutdown() {
        return Err(napi::Error::from(ScpNapiError::Context {
            message: "default bridge instance has been permanently shut down".to_owned(),
            code: codes::CTX_2000.to_owned(),
        }));
    }
    Ok(Arc::clone(bi))
}

/// Ensures a `BridgeInstance` exists (without a `ContextManager`).
///
/// Called by [`crate::identity::ensure_did_resolver_initialized`] before
/// `DidDht::create()` runs, so that the DID resolver slot owned by
/// `BridgeInstance` is available. The `ContextManager` is attached later
/// via [`init_context_manager`] (or [`attach_context_manager_to_bridge`])
/// once the identity is known. Per spec §12.2.3 the `BridgeInstance`
/// container has no DID requirement.
///
/// Subsequent calls are no-ops (`OnceLock` guarantees single initialization).
pub fn ensure_bridge_instance() {
    if DEFAULT_BRIDGE_INSTANCE.get().is_some() {
        return;
    }
    init_default_bridge_instance();
}

/// Attaches an externally-constructed `ContextManager` to the default
/// `NapiBridgeInstance`.
///
/// Used by `set_transport_manager` and similar code paths that need to install
/// a `ContextManager` that was not created by `init_context_manager*`. Creates
/// the default bridge if one does not yet exist.
///
/// No-op if the default bridge already has a `ContextManager` attached.
pub fn attach_context_manager_to_bridge(cm: Arc<ContextManager>) {
    ensure_bridge_instance();
    if let Some(bi) = DEFAULT_BRIDGE_INSTANCE.get()
        && !bi.core.has_context_manager()
    {
        bi.core.set_context_manager(cm);
    }
}

/// Returns a reference to the default [`NapiBridgeInstance`]'s core for
/// handle-affinity checks only.
///
/// Unlike [`bridge_instance`], this helper does NOT return an error when
/// the bridge is suspended — a handle-affinity check is a pure
/// compare-two-u64 operation that does not touch transport or context
/// manager state, so suspending the bridge must not block it. Used
/// exclusively by the [`crate::napi_check_handle!`] macro at FFI entry
/// points.
///
/// # Errors
///
/// Returns `napi::Error` if the default bridge has not been initialized
/// via [`init_context_manager`] (initializes it if needed — same
/// semantics as the old `check_handle_affinity` path).
#[must_use = "the returned CoreFields reference must be used for the affinity check"]
pub fn bridge_instance_for_affinity() -> napi::Result<&'static CoreFields> {
    ensure_bridge_instance();
    DEFAULT_BRIDGE_INSTANCE
        .get()
        .map(|bi| &bi.core)
        .ok_or_else(|| {
            napi::Error::from(ScpNapiError::Context {
                message: "bridge not initialized — call identityCreate first".to_owned(),
                code: codes::CTX_2000.to_owned(),
            })
        })
}

/// Returns a reference to the default [`NapiBridgeInstance`]'s core.
///
/// Existing callers interacting with core state (known contexts, transport,
/// economy trackers) continue to use this helper. Handle-affinity checks
/// on the default path collapse to trivial equality because every handle
/// minted by the free-function façade carries the default `instance_id`.
///
/// # Errors
///
/// Returns `napi::Error` if the default bridge has not been initialized
/// via [`init_context_manager`], or if it is currently suspended.
pub fn bridge_instance() -> napi::Result<&'static CoreFields> {
    let bi = DEFAULT_BRIDGE_INSTANCE.get().ok_or_else(|| {
        napi::Error::from(ScpNapiError::Context {
            message: "bridge not initialized — call identityCreate first".to_owned(),
            code: codes::CTX_2000.to_owned(),
        })
    })?;
    // Suspended: return error (recoverable — caller should resume()).
    // AlreadyShutDown: warn only — shutdown already destroyed state,
    // operations will fail naturally at MLS/transport layer.
    if bi.core.is_suspended() {
        return Err(napi::Error::from(ScpNapiError::Context {
            message: "bridge is suspended — call resume() before performing operations".to_owned(),
            code: codes::CTX_2000.to_owned(),
        }));
    }
    if bi.core.is_shutdown() {
        tracing::warn!("bridge_instance() called after shutdown — operations may fail");
    }
    Ok(&bi.core)
}

/// Returns the default instance id for handle-affinity checks in free-function
/// entry points.
///
/// Every handle minted by the free-function façade carries this id, so
/// the `check_handle` call at each entry is essentially a sanity check in
/// PR 1. Distinct `instance_id`s appear in PR 2 once `#[napi] Scp::new`
/// is the primary construction path.
pub fn default_instance_id() -> napi::Result<u64> {
    ensure_bridge_instance();
    DEFAULT_BRIDGE_INSTANCE
        .get()
        .map(|bi| bi.core.instance_id())
        .ok_or_else(|| {
            napi::Error::from(ScpNapiError::Context {
                message: "default bridge instance not initialized".to_owned(),
                code: codes::CTX_2000.to_owned(),
            })
        })
}

/// Runtime handle-affinity check against the default `NapiBridgeInstance`.
///
/// Compares `handle_instance_id` against the default bridge's
/// [`CoreFields::instance_id`] and maps any mismatch to
/// [`ScpNapiError::Permission`] with error code `SCP-PERM-3030`.
///
/// Every free-function bridge entry that takes a `#[napi]` handle calls
/// this helper (or the [`crate::napi_check_handle!`] macro) on the handle's
/// stored `instance_id`. Once multi-instance is primary (PR 2+),
/// `SCP::method` entries will instead compare against
/// `self.inner.core.instance_id`.
pub fn check_handle_affinity(handle_instance_id: u64) -> napi::Result<()> {
    let expected = default_instance_id()?;
    if handle_instance_id == expected {
        Ok(())
    } else {
        Err(napi::Error::from(ScpNapiError::from(
            scp_ffi_common::bridge_instance::HandleAffinityError::new(handle_instance_id, expected),
        )))
    }
}

/// Uniform accessor for the instance id carried by every `#[napi]` handle type.
///
/// Implemented for `NapiContextHandle`, `NapiIdentity`, `NapiUcanToken`,
/// `NapiTransportManager`, `NapiMcpServerHandle`, `NapiMcpClientHandle`, etc.
/// Consumed by the [`crate::napi_check_handle!`] macro so every bridge
/// entry can run the affinity check uniformly regardless of the handle's
/// internal field layout.
pub trait HandleInstance {
    /// Returns the id of the bridge instance that minted this handle.
    fn instance_id(&self) -> u64;
}

impl HandleInstance for crate::context::NapiContextHandle {
    fn instance_id(&self) -> u64 {
        self.instance_id
    }
}

impl HandleInstance for crate::identity::NapiIdentity {
    fn instance_id(&self) -> u64 {
        // Delegate to the `NapiIdentity` inherent method which accesses
        // the private `inner.instance_id` field.
        Self::instance_id(self)
    }
}

impl HandleInstance for crate::ucan::NapiUcanToken {
    fn instance_id(&self) -> u64 {
        self.instance_id
    }
}

impl HandleInstance for crate::transport::NapiTransportManager {
    fn instance_id(&self) -> u64 {
        self.instance_id
    }
}

impl HandleInstance for crate::mcp::NapiMcpServerHandle {
    fn instance_id(&self) -> u64 {
        self.instance_id
    }
}

impl HandleInstance for crate::mcp::NapiMcpClientHandle {
    fn instance_id(&self) -> u64 {
        self.instance_id
    }
}

#[cfg(feature = "server")]
impl HandleInstance for crate::server::NapiRelayHandle {
    fn instance_id(&self) -> u64 {
        self.instance_id
    }
}

#[cfg(feature = "server")]
impl HandleInstance for crate::server::NapiNodeHandle {
    fn instance_id(&self) -> u64 {
        self.instance_id
    }
}

#[cfg(feature = "allow_in_memory_custody")]
impl HandleInstance for crate::testing::NapiFullStackNode {
    fn instance_id(&self) -> u64 {
        self.instance_id
    }
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
/// The `local_did` is consumed only by `MlsCryptoProvider::new` — the
/// `BridgeInstance` container carries no DID of its own (spec §12.2.3).
///
/// Subsequent calls are no-ops (`OnceLock` guarantees single initialization).
pub fn init_context_manager(local_did: &str) {
    ensure_bridge_instance();
    let Some(bi) = DEFAULT_BRIDGE_INSTANCE.get() else {
        tracing::error!("init_context_manager: BridgeInstance unexpectedly None");
        return;
    };
    if bi.core.has_context_manager() {
        tracing::debug!(
            requested_did = %local_did,
            "init_context_manager: ContextManager already attached — using existing instance"
        );
        return;
    }
    let did = local_did.to_owned();
    let crypto = Box::new(scp_core::crypto::mls::provider::MlsCryptoProvider::new(did));
    let transport = Box::new(scp_core::context::NotConfiguredTransportProvider);
    let event_log = event_log_provider_from_existing_repo().unwrap_or_else(|| {
        tracing::error!(
            "init_context_manager: missing ProtocolRepository after ensure_bridge_instance — \
             falling back to a fresh event log provider (persistence will be lost)"
        );
        build_event_log_provider().0
    });
    let persistence = Box::new(NapiBridgePersistence::new());
    let cm_arc = Arc::new(ContextManager::with_persistence(
        crypto,
        transport,
        event_log,
        persistence,
        not_configured_key_resolver(),
    ));

    bi.core.set_context_manager(cm_arc);
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
    ensure_bridge_instance();
    let Some(bi) = DEFAULT_BRIDGE_INSTANCE.get() else {
        tracing::error!(
            "init_context_manager_with_local_transport: BridgeInstance unexpectedly None"
        );
        return;
    };
    if bi.core.has_context_manager() {
        tracing::warn!(
            requested_did = %local_did,
            "init_context_manager_with_local_transport: ContextManager already attached — ignoring"
        );
        return;
    }
    let did = local_did.to_owned();
    let crypto = Box::new(scp_core::crypto::mls::provider::MlsCryptoProvider::new(did));
    let transport = Box::new(scp_core::context::LocalTransportProvider);
    let event_log = event_log_provider_from_existing_repo().unwrap_or_else(|| {
        tracing::error!(
            "init_context_manager_with_local_transport: missing ProtocolRepository after \
             ensure_bridge_instance — falling back to a fresh event log provider"
        );
        build_event_log_provider().0
    });
    let persistence = Box::new(NapiBridgePersistence::new());
    let cm_arc = Arc::new(ContextManager::with_persistence(
        crypto,
        transport,
        event_log,
        persistence,
        not_configured_key_resolver(),
    ));

    bi.core.set_context_manager(cm_arc);
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
    ensure_bridge_instance();
    let Some(bi) = DEFAULT_BRIDGE_INSTANCE.get() else {
        tracing::error!(
            "init_context_manager_with_relay_transport: BridgeInstance unexpectedly None"
        );
        return;
    };
    if bi.core.has_context_manager() {
        tracing::warn!(
            requested_did = %local_did,
            "init_context_manager_with_relay_transport: ContextManager already attached — ignoring"
        );
        return;
    }
    let did = local_did.to_owned();
    let crypto = Box::new(scp_core::crypto::mls::provider::MlsCryptoProvider::new(did));
    let transport = Box::new(scp_transport::RelayTransportProvider::new(adapter));
    let event_log = event_log_provider_from_existing_repo().unwrap_or_else(|| {
        tracing::error!(
            "init_context_manager_with_relay_transport: missing ProtocolRepository after \
             ensure_bridge_instance — falling back to a fresh event log provider"
        );
        build_event_log_provider().0
    });
    let persistence = Box::new(NapiBridgePersistence::new());
    let cm_arc = Arc::new(ContextManager::with_persistence(
        crypto,
        transport,
        event_log,
        persistence,
        not_configured_key_resolver(),
    ));

    bi.core.set_context_manager(cm_arc);
}

/// Returns the default-instance `ProtocolRepository` if initialized.
///
/// Used by the trust aggregation bridge to construct a
/// `ProtocolRepositoryTrustBridge` backed by persistent (in-process) storage.
/// Returns `None` if the default bridge has not been initialized.
#[must_use]
pub fn protocol_repository()
-> Option<&'static Arc<ProtocolRepository<EncryptingAdapter<BridgeInMemoryStorage>>>> {
    DEFAULT_BRIDGE_INSTANCE
        .get()
        .map(|bi| &bi.protocol_repository)
}

/// Constructs a persistent event log provider backed by encrypted in-memory
/// storage.
///
/// Delegates to [`scp_ffi_common::bridge_runtime::build_event_log_provider`].
/// Returns both the event log provider and the underlying `ProtocolRepository`
/// (for registration in `NapiBridgeInstance`).
pub(crate) fn build_event_log_provider() -> (
    Box<dyn ContextEventLogProvider>,
    Arc<ProtocolRepository<EncryptingAdapter<BridgeInMemoryStorage>>>,
) {
    scp_ffi_common::bridge_runtime::build_event_log_provider()
}

/// Builds an event log provider that reuses the already-registered
/// `ProtocolRepository` in the default `NapiBridgeInstance`.
///
/// Called by `init_context_manager*` after the default bridge was created
/// by `ensure_bridge_instance`. Reusing the repository is critical — a fresh
/// repository would have a different encryption key, rendering any already
/// persisted event log entries unreadable.
fn event_log_provider_from_existing_repo() -> Option<Box<dyn ContextEventLogProvider>> {
    let bi = DEFAULT_BRIDGE_INSTANCE.get()?;
    let bridge = ProtocolRepositoryEventLogBridge::new(Arc::clone(&bi.protocol_repository));
    Some(Box::new(MerkleEventLogProvider::with_persistence(
        Arc::new(bridge),
    )))
}

/// Process-wide async mutex that serializes the
/// `scp_suspend_resume_roundtrip` test with EVERY other test in this
/// binary that calls `context_manager()` or `bridge_instance()` (both of
/// which error when the `BridgeInstance::suspended` flag is set). Cargo
/// runs lib-tests in parallel by default, and because NAPI is a cdylib
/// (`napi_wrap` is only defined when loaded by Node), suspend/resume
/// cannot be moved into a separate integration-test binary as in the
/// `PyO3` and `UniFFI` bridges.
///
/// Every test that touches shared bridge state — including context
/// creation, governance, economy trackers, and bridge-connector
/// registration — must acquire this mutex for the duration of its
/// assertions so the roundtrip test cannot observe `is_suspended=true`
/// mid-test. A `tokio::sync::Mutex` is used (not `std::sync::Mutex`)
/// because several callers are `async` tests that hold the guard across
/// `.await` points — `std::sync::Mutex` guards are not `Send` and would
/// trigger the `await_holding_lock` lint, which specifically warns
/// against deadlock via blocked worker threads.
#[cfg(test)]
pub(crate) fn bridge_lifecycle_serial() -> &'static tokio::sync::Mutex<()> {
    static BRIDGE_LIFECYCLE_SERIAL: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    BRIDGE_LIFECYCLE_SERIAL.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// Test variant of [`context_manager`] initialization that uses
/// [`LocalTransportProvider`](scp_core::context::LocalTransportProvider)
/// instead of
/// [`NotConfiguredTransportProvider`](scp_core::context::NotConfiguredTransportProvider)
/// and a no-op crypto provider for Rust unit tests that pass `None` key
/// package bytes with `did:key:` test DIDs.
///
/// Must be called before the first `context_manager()` call in tests.
/// `OnceLock::get_or_init` ensures only the first initialization wins.
#[cfg(test)]
pub(crate) fn init_context_manager_for_test() {
    ensure_bridge_instance();
    let Some(bi) = DEFAULT_BRIDGE_INSTANCE.get() else {
        tracing::error!("init_context_manager_for_test: BridgeInstance unexpectedly None");
        return;
    };
    if bi.core.has_context_manager() {
        return;
    }
    let event_log = event_log_provider_from_existing_repo().unwrap_or_else(|| {
        tracing::error!(
            "init_context_manager_for_test: missing ProtocolRepository after \
             ensure_bridge_instance — falling back to a fresh event log provider"
        );
        build_event_log_provider().0
    });
    let cm_arc = Arc::new(ContextManager::with_persistence(
        Box::new(TestNoOpCryptoProvider),
        Box::new(scp_core::context::LocalTransportProvider),
        event_log,
        Box::new(NapiBridgePersistence::new()),
        not_configured_key_resolver(),
    ));

    bi.core.set_context_manager(cm_arc);
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
    ) -> Result<scp_core::context::AddMemberOutput, scp_core::context::ContextError> {
        Ok(scp_core::context::AddMemberOutput::default())
    }
    fn remove_member(
        &self,
        _context_id: &[u8; 32],
        _member_did: &str,
    ) -> Result<scp_core::context::RemoveMemberOutput, scp_core::context::ContextError> {
        Ok(scp_core::context::RemoveMemberOutput::default())
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
}

// ---------------------------------------------------------------------------
// BridgeInMemoryStorage — previously defined locally with identical code.
// Consolidated in `scp-ffi-common::bridge_runtime` (#1447). Imported via
// `use scp_ffi_common::bridge_runtime::BridgeInMemoryStorage` at the top.
// ---------------------------------------------------------------------------

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

/// Fallback empty identity registry for when `BridgeInstance` is not initialized
/// or the identity registry feature gate is disabled.
#[cfg(feature = "allow_in_memory_custody")]
static EMPTY_IDENTITY_REGISTRY: std::sync::OnceLock<DashMap<String, NapiIdentityEntry>> =
    std::sync::OnceLock::new();

/// Returns a reference to the default-instance identity registry.
///
/// The registry is a typed field on [`NapiBridgeInstance`]. We eagerly call
/// [`ensure_bridge_instance`] so writers never silently land in the dead
/// `EMPTY_IDENTITY_REGISTRY` fallback — that was the H1 bug where
/// `register_identity` wrote to the empty map before the bridge was
/// initialized, and a later `with_identity` read from the real instance
/// registry and missed the write. The fallback branch remains only for
/// code paths that cannot trigger initialization (vanishingly rare); PR 2
/// deletes it once single-ownership sequencing makes it unreachable.
#[cfg(feature = "allow_in_memory_custody")]
fn identity_registry() -> &'static DashMap<String, NapiIdentityEntry> {
    ensure_bridge_instance();
    DEFAULT_BRIDGE_INSTANCE.get().map_or_else(
        || EMPTY_IDENTITY_REGISTRY.get_or_init(DashMap::new),
        |bi| bi.identity_registry.as_ref(),
    )
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
            code: codes::PERM_3023.to_owned(),
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
            code: codes::PERM_3023.to_owned(),
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

/// Per-context UCAN validation state (NAPI bridge).
///
/// Wraps [`scp_ffi_common::bridge_runtime::UcanContextStateCore`] with
/// NAPI-specific fields for tool management and role state. The core
/// fields (revocation list, nonce tracker, ceiling, creator DID, event log)
/// are shared with the `UniFFI` bridge (#1447).
pub struct UcanContextState {
    /// Core UCAN validation state shared with `UniFFI` bridge.
    pub core: scp_ffi_common::bridge_runtime::UcanContextStateCore,
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

/// Returns a reference to the UCAN state registry.
///
/// The registry is stored as a type-erased `Arc<DashMap<String, UcanContextState>>`
/// in the `BridgeInstance`. Falls back to an empty registry when the bridge
/// has not been initialized (e.g. in unit tests that don't call
/// `init_context_manager`).
///
/// Fallback empty UCAN registry for when `BridgeInstance` is not initialized.
static EMPTY_UCAN_REGISTRY: std::sync::OnceLock<DashMap<String, UcanContextState>> =
    std::sync::OnceLock::new();

fn ucan_registry() -> &'static DashMap<String, UcanContextState> {
    ensure_bridge_instance();
    DEFAULT_BRIDGE_INSTANCE.get().map_or_else(
        || EMPTY_UCAN_REGISTRY.get_or_init(DashMap::new),
        |bi| bi.ucan_registry.as_ref(),
    )
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
        &SystemClock,
    ) {
        Ok(rs) => rs,
        Err(e) => {
            return Err(ScpNapiError::Context {
                message: format!("failed to create role state: {e}"),
                code: codes::CTX_2023.to_owned(),
            });
        }
    };

    let state = UcanContextState {
        core: scp_ffi_common::bridge_runtime::UcanContextStateCore {
            revocation_list,
            nonce_tracker,
            ceiling_strings,
            creator_did,
            event_log,
        },
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
            code: codes::CTX_2023.to_owned(),
        })?;

    f(entry.value_mut())
}

/// Removes UCAN state for a context.
///
/// Called when a context is closed. Idempotent.
pub fn remove_context(context_id: &str) {
    ucan_registry().remove(context_id);
    // Clean up known-context discovery entry via BridgeInstance.
    if let Ok(bi) = bridge_instance() {
        bi.remove_known_context(context_id);
    }
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
    let mgr = context_manager().map_err(|e| ScpNapiError::Context {
        message: e.to_string(),
        code: codes::CTX_2000.to_owned(),
    })?;
    let new_role_state =
        mgr.get_role_state(context_id)
            .await
            .ok_or_else(|| ScpNapiError::Context {
                message: format!("context '{context_id}' not found in ContextManager"),
                code: codes::CTX_2023.to_owned(),
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
                code: codes::CTX_2023.to_owned(),
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
            let total = u64::try_from(entry.core.event_log.leaves().len()).unwrap_or(u64::MAX);
            (total, 0)
        }
        None => (0, 0),
    }
}

// ---------------------------------------------------------------------------
// Invitation rate limit tracker registry (#614)
//
// Delegates to the `BridgeInstance`'s `rate_limiters` DashMap (#1549).
// ---------------------------------------------------------------------------

/// Returns a mutable reference to the rate limit tracker for the given
/// identity DID, creating one if it does not exist.
///
/// Delegates to [`CoreFields::with_rate_limit_tracker`]. If the bridge
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
    let role_state = ContextRoleState::new(
        context_id,
        creator_did,
        default_ceiling(),
        Vec::new(),
        &SystemClock,
    )
    .expect("ContextRoleState::new with default ceiling and no custom roles cannot fail");

    let state = UcanContextState {
        core: scp_ffi_common::bridge_runtime::UcanContextStateCore {
            event_log: EventLog::new(context_id.to_owned()),
            revocation_list: RevocationList::new(context_id.to_owned()),
            nonce_tracker: NonceTracker::new(context_id.to_owned(), SystemClock),
            ceiling_strings,
            creator_did: creator_did.to_owned(),
        },
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

// Economy state is now owned by BridgeInstance. Callers access it via
// `bridge_instance()?.with_economy_budget(...)` etc. directly.

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // BridgeInstance tests (#1549)
    // -----------------------------------------------------------------------

    #[test]
    fn bridge_instance_populated_by_init_context_manager() {
        let _lifecycle_guard = bridge_lifecycle_serial().blocking_lock();
        // init_context_manager_for_test populates DEFAULT_BRIDGE_INSTANCE which
        // owns the ContextManager. Since OnceLock is process-global, the first
        // call in any test wins — subsequent calls are no-ops. We rely on this
        // being called (possibly by other tests) before asserting.
        init_context_manager_for_test();

        let cm = context_manager().expect("context_manager should be initialized");
        let core = bridge_instance().expect("bridge_instance should be initialized");

        // Both should point to the same ContextManager allocation.
        assert!(
            Arc::ptr_eq(cm, core.try_context_manager().unwrap()),
            "bridge_instance().try_context_manager() must be the same Arc as context_manager()"
        );
    }

    #[test]
    fn bridge_instance_not_shutdown_initially() {
        let _lifecycle_guard = bridge_lifecycle_serial().blocking_lock();
        init_context_manager_for_test();

        let core = bridge_instance().expect("bridge_instance should be initialized");
        assert!(
            !core.is_shutdown(),
            "bridge_instance should not be shutdown immediately after init"
        );
    }

    #[test]
    fn shutdown_hook_runs_with_external_state() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        // Build an isolated NapiBridgeInstance (not the global one) to avoid
        // interfering with the OnceLock-based singleton used by other tests.
        let bi = Arc::new(NapiBridgeInstance::new_napi());

        let ran = Arc::new(AtomicBool::new(false));
        let ran2 = Arc::clone(&ran);

        bi.core.register_shutdown_hook(Box::new(move || {
            ran2.store(true, Ordering::SeqCst);
        }));

        assert!(
            !ran.load(Ordering::SeqCst),
            "hook must not fire before shutdown"
        );
        bi.core.shutdown();
        assert!(
            ran.load(Ordering::SeqCst),
            "shutdown hook must execute during CoreFields::shutdown()"
        );
    }

    // -----------------------------------------------------------------------
    // NapiBridgeInstance tests (#1549 Phase 4 PR 1)
    // -----------------------------------------------------------------------

    #[test]
    fn test_napi_bridge_instance_typed_registries() {
        let bi = NapiBridgeInstance::new_napi();

        // Typed registries are accessible and start empty.
        assert!(
            bi.ucan_registry.is_empty(),
            "ucan_registry must start empty"
        );
        #[cfg(feature = "allow_in_memory_custody")]
        assert!(
            bi.identity_registry.is_empty(),
            "identity_registry must start empty"
        );
        // protocol_repository is a live `Arc` — no panic on access.
        let _repo: &Arc<ProtocolRepository<EncryptingAdapter<BridgeInMemoryStorage>>> =
            &bi.protocol_repository;
    }

    #[test]
    fn test_napi_bridge_instance_unique_ids() {
        let a = NapiBridgeInstance::new_napi();
        let b = NapiBridgeInstance::new_napi();
        assert_ne!(
            a.instance_id(),
            b.instance_id(),
            "fresh NapiBridgeInstance instances must have distinct ids"
        );
    }

    #[test]
    fn test_default_instance_is_same_arc() {
        // First call may or may not initialize depending on test order; second
        // call must return an `Arc` pointing at the same allocation.
        let a = default_bridge_instance().expect("default instance must be available");
        let b = default_bridge_instance().expect("default instance must be available");
        assert!(
            Arc::ptr_eq(&a, &b),
            "repeated default_bridge_instance() calls must return the same Arc"
        );
        assert_eq!(a.instance_id(), b.instance_id());
    }
}
