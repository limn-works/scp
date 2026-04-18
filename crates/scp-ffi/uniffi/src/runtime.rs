//! Shared `ContextManager` and per-context UCAN state registry.
//!
//! A single `Arc<UniffiBridgeInstance>` is allocated into
//! [`DEFAULT_BRIDGE_INSTANCE`] the first time a free-function bridge entry
//! touches bridge state. Bridge functions access its `ContextManager` and
//! typed registries (UCAN, identity custody, protocol repository) via
//! [`default_bridge_instance`] / [`bridge_instance`].
//!
//! # Per-context UCAN state
//!
//! The `ContextManager` does not own UCAN revocation lists or nonce trackers.
//! Those are validation-layer concerns that live in the bridge. A typed
//! `DashMap<String, UcanContextState>` on [`UniffiBridgeInstance`] owns them,
//! keyed by context ID. This mirrors the NAPI bridge's `UcanContextState`
//! pattern (see `crates/scp-ffi/napi/src/runtime.rs`).
//!
//! # Lifecycle
//!
//! 1. First call to a bridge free function initializes the default
//!    [`UniffiBridgeInstance`] via [`ensure_bridge_instance`].
//! 2. Bridge functions call [`context_manager()`] or [`bridge_instance()`]
//!    and delegate to the manager's async methods or the instance's typed
//!    registries.
//! 3. The `UniffiBridgeInstance` is dropped on process exit (static
//!    `OnceLock`) or permanently deactivated via
//!    [`UniffiBridgeInstance::shutdown`].
//!
//! This replaces the old `DashMap<String, ContextRuntime>` global registry
//! (deleted as part of issue #387) and the type-erased `Box<dyn Any>` slots
//! on `BridgeInstance` (deleted as part of #1549 Phase 4 PR 1).

use async_trait::async_trait;
use scp_ffi_common::bridge_instance::{BridgeInstanceCore, ShutdownError, ShutdownOutcome};
// Re-export `CoreFields` at `crate::runtime::CoreFields` so the
// `uniffi_check_handle!` macro can refer to it as
// `$crate::runtime::CoreFields`.
pub use scp_ffi_common::bridge_instance::CoreFields;
use scp_ffi_common::bridge_runtime::BridgeInMemoryStorage;
use scp_ffi_common::error_codes as codes;
use std::collections::HashSet;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

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
use scp_platform::encrypting_adapter::EncryptingAdapter;

// ---------------------------------------------------------------------------
// UniffiBridgeInstance — per-bridge concrete bridge instance (#1549 Phase 4 PR 1)
// ---------------------------------------------------------------------------

/// Storage configuration for [`UniffiBridgeInstance`].
///
/// Two variants are supported:
/// - [`StorageConfig::InMemory`] — encrypted in-memory storage (ephemeral).
/// - [`StorageConfig::Sqlite`] — SQLCipher-encrypted storage on disk at
///   `{path}/scp.db`, wired through [`scp_platform::sqlite::SqliteStorage`].
///
/// Kept here (not in `scp-ffi-common`) because each bridge owns its own
/// storage shape until a shared type lands.
///
/// # `UniFFI` representation
///
/// `#[derive(uniffi::Enum)]` exposes this to Swift and Kotlin as an
/// associated-value enum. Swift will see `case sqlite(path: String, key:
/// Data)`; Kotlin `sealed class StorageConfig.Sqlite(path: String, key:
/// ByteArray)`. The raw key is accepted as a byte array; callers should
/// zero their copy after the call returns.
#[derive(Debug, Clone, Default, uniffi::Enum)]
pub enum StorageConfig {
    /// Encrypted in-memory storage.
    #[default]
    InMemory,
    /// SQLCipher-encrypted on-disk storage at `{path}/scp.db`.
    Sqlite {
        /// Directory the database file is created in. Path is passed
        /// through `std::path::PathBuf` on the Rust side.
        path: String,
        /// Raw encryption key material (typically 32 bytes).
        key: Vec<u8>,
    },
}

/// `UniFFI`-specific concrete bridge instance.
///
/// Embeds the bridge-agnostic [`CoreFields`] and adds typed fields for the
/// `UniFFI`-specific registries (UCAN state, identity custody, protocol
/// repository). The MCP, identity-link-attestation, and context-handle
/// registries continue to live in [`crate::bridge`] as their own `OnceLock`s
/// during PR 1 — they move onto this struct in PR 2.
///
/// Constructed via [`UniffiBridgeInstance::new_uniffi`] /
/// [`UniffiBridgeInstance::with_persistence_uniffi`] /
/// [`UniffiBridgeInstance::with_storage_uniffi`]. The default global instance
/// is lazily allocated into [`DEFAULT_BRIDGE_INSTANCE`]; user-owned instances
/// (via `#[derive(uniffi::Object)] Scp`) build their own instead.
///
/// Implements [`BridgeInstanceCore`] so shared helpers can operate on
/// `&dyn BridgeInstanceCore`. `shutdown(timeout)` delegates to
/// [`CoreFields::shutdown_core_async`] and then drops the `UniFFI`-specific
/// registries in [`BridgeInstanceCore::bridge_specific_shutdown`].
pub struct UniffiBridgeInstance {
    /// Bridge-agnostic core state.
    pub(crate) core: CoreFields,

    /// Per-context UCAN validation state.
    ///
    /// Previously stored type-erased in `CoreFields::ucan_registry`.
    /// Post PR 1, the registry lives here as a typed field and is cleared by
    /// [`BridgeInstanceCore::bridge_specific_shutdown`].
    pub(crate) ucan_registry: Arc<DashMap<String, UcanContextState>>,

    /// Retained identity state for in-memory custody DIDs.
    ///
    /// Previously stored type-erased in `CoreFields::identity_registry` AND
    /// as a bridge-local `OnceLock` in `bridge.rs::identity_custody_registry`.
    /// Both paths are unified here: `bridge.rs::identity_custody_registry`
    /// now returns a reference to this field on the default instance.
    /// Feature-gated because only the `allow_in_memory_custody` build flag
    /// pulls in [`OpaqueInMemoryKeyCustody`](crate::bridge::OpaqueInMemoryKeyCustody).
    /// Cleared on shutdown — drops the `Arc<OpaqueInMemoryKeyCustody>` values
    /// which zeroize their underlying key material via `Drop`.
    #[cfg(feature = "allow_in_memory_custody")]
    pub(crate) identity_custody_registry: Arc<
        DashMap<
            String,
            (
                Arc<crate::bridge::OpaqueInMemoryKeyCustody>,
                scp_platform::KeyHandle,
            ),
        >,
    >,

    /// Protocol repository used for trust aggregation + event log persistence.
    ///
    /// Previously stored type-erased in `CoreFields::protocol_repository`.
    /// Wrapped in `Arc` for cheap clones into the `MerkleEventLogProvider`.
    pub(crate) protocol_repository:
        Arc<ProtocolRepository<EncryptingAdapter<BridgeInMemoryStorage>>>,
}

impl UniffiBridgeInstance {
    /// Constructs a new `UniffiBridgeInstance` with default in-memory state.
    ///
    /// Allocates a fresh `CoreFields` (new `instance_id`, new
    /// `CancellationToken`, empty `JoinSet`) and populates the protocol
    /// repository + typed registries. No `ContextManager` is attached —
    /// callers attach one later via [`CoreFields::set_context_manager`].
    #[must_use]
    pub fn new_uniffi() -> Self {
        let (_event_log, protocol_repository) =
            scp_ffi_common::bridge_runtime::build_event_log_provider();
        Self {
            core: CoreFields::new(),
            ucan_registry: Arc::new(DashMap::new()),
            #[cfg(feature = "allow_in_memory_custody")]
            identity_custody_registry: Arc::new(DashMap::new()),
            protocol_repository,
        }
    }

    /// Constructs a new `UniffiBridgeInstance` with an explicit
    /// [`scp_core::context::manager::ContextPersistence`] provider.
    ///
    /// Used by callers that already have a persistence strategy (typically
    /// unit tests; production persistence is wired through PR 3's
    /// [`StorageConfig::InMemory`] path on
    /// [`UniffiBridgeInstance::with_storage_uniffi`]).
    #[must_use]
    pub fn with_persistence_uniffi(
        persistence: Box<dyn scp_core::context::manager::ContextPersistence + Send + Sync>,
    ) -> Self {
        let (_event_log, protocol_repository) =
            scp_ffi_common::bridge_runtime::build_event_log_provider();
        Self {
            core: CoreFields::with_persistence(persistence),
            ucan_registry: Arc::new(DashMap::new()),
            #[cfg(feature = "allow_in_memory_custody")]
            identity_custody_registry: Arc::new(DashMap::new()),
            protocol_repository,
        }
    }

    /// Constructs a new `UniffiBridgeInstance` honoring a [`StorageConfig`].
    ///
    /// - [`StorageConfig::InMemory`] — equivalent to
    ///   [`UniffiBridgeInstance::new_uniffi`]; no persistence provider is
    ///   attached to the embedded `CoreFields`.
    /// - [`StorageConfig::Sqlite`] — wired in a later commit inside this PR.
    ///   For now the variant is accepted and ignored (no persistence). This
    ///   keeps the public API change atomic without partially-wired state.
    #[must_use]
    pub fn with_storage_uniffi(config: StorageConfig) -> Self {
        match config {
            StorageConfig::InMemory => Self::new_uniffi(),
            StorageConfig::Sqlite { path: _, key: _ } => {
                // Wired in commit 3. The variant is accepted so the shape
                // of the public API is stable from commit 1 on.
                Self::new_uniffi()
            }
        }
    }

    /// Returns the monotonic instance id for this bridge.
    #[must_use]
    pub const fn instance_id(&self) -> u64 {
        self.core.instance_id()
    }

    /// Returns a reference to the typed UCAN registry.
    #[must_use]
    pub const fn ucan_registry(&self) -> &Arc<DashMap<String, UcanContextState>> {
        &self.ucan_registry
    }

    /// Returns a reference to the typed identity custody registry.
    ///
    /// `pub(crate)` because `OpaqueInMemoryKeyCustody` is itself `pub(crate)`
    /// and would leak through the public signature otherwise.
    ///
    /// Marked `#[allow(dead_code)]` because bridge callers currently reach
    /// the registry via the free helper `bridge::identity_custody_registry()`
    /// which dereferences this field directly. The typed accessor is kept for
    /// per-instance callers introduced in later PRs.
    #[cfg(feature = "allow_in_memory_custody")]
    #[must_use]
    #[allow(dead_code)]
    pub(crate) const fn identity_custody_registry(
        &self,
    ) -> &Arc<
        DashMap<
            String,
            (
                Arc<crate::bridge::OpaqueInMemoryKeyCustody>,
                scp_platform::KeyHandle,
            ),
        >,
    > {
        &self.identity_custody_registry
    }

    /// Returns a reference to the protocol repository.
    #[must_use]
    pub const fn protocol_repository(
        &self,
    ) -> &Arc<ProtocolRepository<EncryptingAdapter<BridgeInMemoryStorage>>> {
        &self.protocol_repository
    }
}

#[async_trait]
impl BridgeInstanceCore for UniffiBridgeInstance {
    fn core(&self) -> &CoreFields {
        &self.core
    }

    async fn shutdown(&self, timeout: Duration) -> Result<ShutdownOutcome, ShutdownError> {
        // `bridge_specific_shutdown` MUST run even when
        // `shutdown_core_async` returns `AlreadyShutDown` — that variant
        // signals the sync shutdown path raced ahead; without the cleanup
        // call, typed UniFFI registries (UCAN, identity custody) leak
        // key material past shutdown.
        let result = self.core.shutdown_core_async(timeout).await;
        self.bridge_specific_shutdown();
        result
    }

    fn bridge_specific_shutdown(&self) {
        // Clear typed registries. Dropping `Arc<OpaqueInMemoryKeyCustody>`
        // values zeroizes any key material they hold via the custody
        // provider's `Drop` impl.
        self.ucan_registry.clear();
        #[cfg(feature = "allow_in_memory_custody")]
        self.identity_custody_registry.clear();
        // MCP, identity-link-attestation, and context-handle registries live
        // in `crate::bridge` as their own `OnceLock`s during PR 1 (migrated
        // onto this struct in PR 2). Their clear path runs via the core
        // `shutdown_hooks` vector populated by `init_default_bridge_instance`.
    }
}

// ---------------------------------------------------------------------------
// Default bridge instance — consolidated singleton for the free-function façade
// ---------------------------------------------------------------------------

/// Default [`UniffiBridgeInstance`] used by the flat `#[uniffi::export]`
/// free-function façade.
///
/// Lazily initialized on the first free-function call that touches bridge
/// state (via [`ensure_bridge_instance`]). User-owned instances (from the
/// `#[derive(uniffi::Object)] Scp` class) do **not** share state with this
/// default — the two paths have independent `ContextManager`s, registries,
/// and transports.
pub(crate) static DEFAULT_BRIDGE_INSTANCE: OnceLock<Arc<UniffiBridgeInstance>> = OnceLock::new();

/// Initializes the default [`UniffiBridgeInstance`] without a `ContextManager`.
///
/// Registers the MCP shutdown hook (MCP registries still live in
/// `crate::bridge` during PR 1). Subsequent calls are no-ops (`OnceLock`
/// guarantees single initialization).
fn init_default_bridge_instance() {
    // Register the MCP shutdown hook INSIDE the `get_or_init` closure so it
    // runs exactly once per process regardless of how many threads race
    // through `init_default_bridge_instance` before the OnceLock is filled.
    // A prior pattern registered the hook outside the closure, which caused
    // duplicate-registration races under concurrent first-call scenarios.
    let _ = DEFAULT_BRIDGE_INSTANCE.get_or_init(|| {
        let instance = Arc::new(UniffiBridgeInstance::new_uniffi());
        // Shutdown hook for state still living outside
        // `UniffiBridgeInstance` during PR 1 (MCP registries — migrated
        // onto the struct in PR 2). Identity and UCAN registries are now
        // typed fields and are cleared by `bridge_specific_shutdown`
        // without needing a hook.
        instance.core.register_shutdown_hook(Box::new(|| {
            crate::bridge::clear_mcp_registries();
        }));
        instance
    });
}

/// Returns the raw default `UniffiBridgeInstance` without lifecycle checks.
///
/// Used by [`crate::scp_shutdown`] and the `#[derive(uniffi::Object)] Scp`
/// `default_instance` factory to reach the default bridge during teardown or
/// wrapping. Returns `None` if the default was never initialized.
#[must_use]
#[cfg_attr(test, allow(dead_code))]
pub fn default_bridge_instance_raw() -> Option<&'static Arc<UniffiBridgeInstance>> {
    DEFAULT_BRIDGE_INSTANCE.get()
}

/// Back-compat alias for [`default_bridge_instance_raw`].
///
/// Kept so that `lib.rs::scp_shutdown` and other callers using the previous
/// name continue to compile. Removed when all call sites are migrated.
#[must_use]
#[cfg_attr(test, allow(dead_code))]
pub fn bridge_instance_raw() -> Option<&'static Arc<UniffiBridgeInstance>> {
    DEFAULT_BRIDGE_INSTANCE.get()
}

/// Returns the default `UniffiBridgeInstance`, initializing it if needed.
///
/// Used by the `#[derive(uniffi::Object)] Scp::default_instance` factory to
/// surface the same long-lived `Arc` shared by the free-function façade.
///
/// # Errors
///
/// Returns `ScpError::Context` if the default bridge is currently suspended
/// or has been permanently shut down.
pub fn default_bridge_instance() -> Result<Arc<UniffiBridgeInstance>, crate::ScpError> {
    ensure_bridge_instance();
    let bi = DEFAULT_BRIDGE_INSTANCE
        .get()
        .ok_or_else(|| crate::ScpError::Context {
            msg: "default bridge instance not initialized".to_owned(),
            code: codes::CTX_2000.to_owned(),
        })?;
    if bi.core.is_suspended() {
        return Err(crate::ScpError::Context {
            msg: "bridge is suspended — call resume() before performing operations".to_owned(),
            code: codes::CTX_2000.to_owned(),
        });
    }
    if bi.core.is_shutdown() {
        return Err(crate::ScpError::Context {
            msg: "default bridge instance has been permanently shut down".to_owned(),
            code: codes::CTX_2000.to_owned(),
        });
    }
    Ok(Arc::clone(bi))
}

/// Ensures a `UniffiBridgeInstance` exists (without a `ContextManager`).
///
/// Called by `identity_create` before `DidDht::create()` runs, so that the
/// DID resolver slot owned by `CoreFields` is available. The `ContextManager`
/// is attached later via [`init_context_manager_with_did`] (or
/// [`attach_context_manager_to_bridge`]) once the identity is known. Per
/// spec §12.2.3 the bridge instance container has no DID requirement — the
/// authoritative local DID lives inside the `ContextManager`'s
/// `MlsCryptoProvider`.
///
/// Subsequent calls are no-ops (`OnceLock` guarantees single initialization).
pub fn ensure_bridge_instance() {
    if DEFAULT_BRIDGE_INSTANCE.get().is_some() {
        return;
    }
    init_default_bridge_instance();
}

/// Attaches an externally-constructed `ContextManager` to the default
/// `UniffiBridgeInstance`.
///
/// Used by `transport_connect` and similar code paths that need to install
/// a `ContextManager` not created by `init_context_manager*`. Creates the
/// default bridge if one does not yet exist.
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

/// Returns a reference to the default [`UniffiBridgeInstance`]'s core for
/// handle-affinity checks only.
///
/// Unlike [`bridge_instance`], this helper does NOT return an error when
/// the bridge is suspended — a handle-affinity check is a pure
/// compare-two-u64 operation that does not touch transport or context
/// manager state, so suspending the bridge must not block it. Used
/// exclusively by the [`crate::uniffi_check_handle!`] macro at FFI entry
/// points.
///
/// # Errors
///
/// Returns `ScpError::Context` if the default bridge has not been
/// initialized. Initializes the bridge if needed — same semantics as
/// the old `check_handle_affinity` path.
#[must_use = "the returned CoreFields reference must be used for the affinity check"]
pub fn bridge_instance_for_affinity() -> Result<&'static CoreFields, crate::ScpError> {
    ensure_bridge_instance();
    DEFAULT_BRIDGE_INSTANCE
        .get()
        .map(|bi| &bi.core)
        .ok_or_else(|| crate::ScpError::Context {
            msg: "bridge not initialized — call context_create, \
                  context_join, context_import, or init_context_manager first"
                .to_owned(),
            code: codes::CTX_2000.to_owned(),
        })
}

/// Returns a reference to the default [`UniffiBridgeInstance`].
///
/// Called by rate-limiter delegation and other functions that access the
/// consolidated instance state (#1549).
///
/// # Errors
///
/// Returns `ScpError::Context` if the bridge has not been initialized or is
/// currently suspended. Shutdown is a warning (not an error) because shutdown
/// is terminal and operations fail naturally at the MLS/transport layer.
pub fn bridge_instance() -> Result<&'static Arc<UniffiBridgeInstance>, crate::ScpError> {
    let bi = DEFAULT_BRIDGE_INSTANCE
        .get()
        .ok_or_else(|| crate::ScpError::Context {
            msg: "bridge not initialized — call context_create, \
                  context_join, context_import, or init_context_manager first"
                .to_owned(),
            code: codes::CTX_2000.to_owned(),
        })?;
    if bi.core.is_suspended() {
        return Err(crate::ScpError::Context {
            msg: "bridge is suspended — call resume() before performing operations".to_owned(),
            code: codes::CTX_2000.to_owned(),
        });
    }
    if bi.core.is_shutdown() {
        tracing::warn!("bridge_instance() called after shutdown — operations may fail");
    }
    Ok(bi)
}

/// Returns the default instance id for handle-affinity checks on the
/// free-function façade.
///
/// Every handle minted by the free-function façade carries this id, so the
/// `check_handle` call at each entry is essentially a sanity check in PR 1.
/// Distinct `instance_id`s appear once `Scp::new` is the primary construction
/// path (PR 2+).
///
/// # Errors
///
/// Returns `ScpError::Context` if the default bridge is not initialized.
pub fn default_instance_id() -> Result<u64, crate::ScpError> {
    ensure_bridge_instance();
    DEFAULT_BRIDGE_INSTANCE
        .get()
        .map(|bi| bi.core.instance_id())
        .ok_or_else(|| crate::ScpError::Context {
            msg: "default bridge instance not initialized".to_owned(),
            code: codes::CTX_2000.to_owned(),
        })
}

/// Runtime handle-affinity check against the default `UniffiBridgeInstance`.
///
/// Compares `handle_instance_id` against the default bridge's
/// [`CoreFields::instance_id`] and maps any mismatch to
/// [`crate::ScpError::Permission`] with error code `SCP-PERM-3030`.
///
/// Every free-function bridge entry that takes a handle with a stored
/// `instance_id` calls this helper (via the
/// [`crate::uniffi_check_handle!`] macro). Once multi-instance is primary
/// (PR 2+), `Scp::method` entries will instead compare against
/// `self.inner.core.instance_id`.
///
/// # Errors
///
/// Returns `ScpError::Permission` with code `SCP-PERM-3030` on mismatch, or
/// `ScpError::Context` if the default bridge is not initialized.
pub fn check_handle_affinity(handle_instance_id: u64) -> Result<(), crate::ScpError> {
    let expected = default_instance_id()?;
    if handle_instance_id == expected {
        Ok(())
    } else {
        Err(crate::ScpError::from(
            scp_ffi_common::bridge_instance::HandleAffinityError::new(handle_instance_id, expected),
        ))
    }
}

// All UniFFI handle types (`Identity`, `ContextHandle`, `UcanToken`,
// `TransportManager`, `RelayHandle`, `NodeHandle`) carry an inherent
// `instance_id(&self) -> u64` method. The `uniffi_check_handle!` macro uses
// method syntax (`handle.instance_id()`) which auto-derefs through `&T`,
// `&Arc<T>`, and `Arc<T>` without needing the `HandleInstance` /
// `AsHandleInstance` traits from earlier drafts. Those traits were deleted
// in PR 1 post-review; the inherent methods alone are sufficient.

// ---------------------------------------------------------------------------
// DID resolver shims (preserved for existing callers)
// ---------------------------------------------------------------------------

/// Returns the production DID resolver on the default bridge instance, if
/// initialized.
///
/// `bridge_runtime::did_resolver_from` takes `&Arc<CoreFields>`. Because
/// [`UniffiBridgeInstance`] embeds `CoreFields` (not `Arc<CoreFields>`),
/// the helper is incompatible with the new pattern. Access the resolver
/// directly on the embedded core.
#[must_use]
pub fn did_resolver() -> Option<&'static Arc<scp_ffi_common::IdentityBackedDidResolver>> {
    DEFAULT_BRIDGE_INSTANCE.get()?.core.did_resolver()
}

/// Initializes the production DID resolver on the default bridge instance.
///
/// See [`did_resolver`] for why the `scp_ffi_common::bridge_runtime` helpers
/// cannot be used here.
pub fn init_did_resolver<R>(resolver: Arc<R>, handle: tokio::runtime::Handle)
where
    R: scp_identity::resolver::DidResolver + 'static,
{
    ensure_bridge_instance();
    if let Some(bi) = DEFAULT_BRIDGE_INSTANCE.get() {
        bi.core
            .set_did_resolver(Arc::new(scp_ffi_common::IdentityBackedDidResolver::new(
                resolver, handle,
            )));
    } else {
        tracing::error!(
            "init_did_resolver called before DEFAULT_BRIDGE_INSTANCE initialized — \
             resolver not stored"
        );
    }
}

/// Returns a key resolver that rejects all lookups with a logged error.
///
/// Delegates to [`scp_ffi_common::bridge_runtime::not_configured_key_resolver`].
fn not_configured_key_resolver() -> scp_core::context::governance::KeyResolver {
    scp_ffi_common::bridge_runtime::not_configured_key_resolver()
}

// ---------------------------------------------------------------------------
// ContextManager accessors
// ---------------------------------------------------------------------------

/// Returns a reference to the shared `ContextManager` on the default bridge
/// instance.
///
/// # Errors
///
/// Returns `ScpError::Context` if the manager has not been initialized or if
/// the bridge is currently suspended.
pub fn context_manager() -> Result<&'static Arc<ContextManager>, crate::ScpError> {
    let bi = DEFAULT_BRIDGE_INSTANCE
        .get()
        .ok_or_else(|| crate::ScpError::Context {
            msg: "ContextManager not initialized — call context_create, \
                  context_join, context_import, or init_context_manager first"
                .to_owned(),
            code: codes::CTX_2000.to_owned(),
        })?;
    if bi.core.is_suspended() {
        return Err(crate::ScpError::Context {
            msg: "bridge is suspended — call resume() before performing operations".to_owned(),
            code: codes::CTX_2000.to_owned(),
        });
    }
    if bi.core.is_shutdown() {
        tracing::warn!("context_manager() called after shutdown — operations may fail");
    }
    bi.core
        .try_context_manager()
        .ok_or_else(|| crate::ScpError::Context {
            msg: "ContextManager not yet attached — call context_create, \
                  context_join, context_import, or init_context_manager first"
                .to_owned(),
            code: codes::CTX_2000.to_owned(),
        })
}

/// Builds a default `ContextManager` with bridge-local providers, and returns
/// both the manager and the underlying `ProtocolRepository`.
///
/// Used only in tests that construct isolated bridge instances. The production
/// path reuses the repository registered on the default instance so keys are
/// consistent across restarts.
fn build_default_context_manager() -> (
    Arc<ContextManager>,
    Arc<ProtocolRepository<EncryptingAdapter<BridgeInMemoryStorage>>>,
) {
    let (event_log, protocol_repo) = build_event_log_provider();
    let cm = build_context_manager(
        Box::new(FfiBridgeCrypto),
        Box::new(scp_core::context::NotConfiguredTransportProvider),
        event_log,
        None,
    );
    (cm, protocol_repo)
}

/// Adapter that lets a shared `Arc<dyn ContextPersistence + Send + Sync>` be
/// consumed by [`ContextManager::with_persistence`] which requires a `Box`.
///
/// `ContextManager::with_persistence` converts the `Box` back into an `Arc`
/// internally, but the call-site signature is `Box`-only. Rather than
/// cloning the underlying backend (which would open a second `SQLite`
/// connection), we box a thin wrapper that delegates every trait method to
/// the shared `Arc`. The `Arc` mirror retained on `CoreFields::persistence`
/// and the `Arc` reconstructed inside `ContextManager` end up pointing at
/// the same provider, so suspend/resume flush + `flush_all_contexts_sync`
/// operate on the same underlying storage.
struct ArcContextPersistence {
    inner: Arc<dyn scp_core::context::manager::ContextPersistence + Send + Sync>,
}

impl ArcContextPersistence {
    fn new(inner: Arc<dyn scp_core::context::manager::ContextPersistence + Send + Sync>) -> Self {
        Self { inner }
    }
}

impl scp_core::context::manager::ContextPersistence for ArcContextPersistence {
    fn persist_context(
        &self,
        context_id: &str,
        snapshot: &scp_core::context::manager::ContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.inner.persist_context(context_id, snapshot)
    }

    fn load_context(
        &self,
        context_id: &str,
    ) -> Result<
        Option<scp_core::context::manager::ContextSnapshot>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        self.inner.load_context(context_id)
    }

    fn persist_broadcast(
        &self,
        context_id: &str,
        snapshot: &scp_core::context::broadcast::BroadcastContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.inner.persist_broadcast(context_id, snapshot)
    }

    fn load_broadcast(
        &self,
        context_id: &str,
    ) -> Result<
        Option<scp_core::context::broadcast::BroadcastContextSnapshot>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        self.inner.load_broadcast(context_id)
    }

    fn delete_context(
        &self,
        context_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.inner.delete_context(context_id)
    }

    fn list_persisted_contexts(
        &self,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        self.inner.list_persisted_contexts()
    }
}

/// Constructs a [`ContextManager`] with or without persistence.
///
/// Mirrors the `PyO3` bridge's `build_context_manager` (`crates/scp-ffi/src/runtime.rs`).
/// When `persistence` is `Some`, wraps the shared `Arc` in
/// [`ArcContextPersistence`] and hands it to
/// [`ContextManager::with_persistence`]; otherwise calls
/// [`ContextManager::new`]. Callers pull the shared persistence from the
/// embedded `CoreFields` via
/// [`scp_ffi_common::bridge_instance::CoreFields::persistence_arc_clone`]
/// so the manager and the bridge mirror share the same backend — a
/// single `SQLite` connection, not two.
fn build_context_manager(
    crypto: Box<dyn ContextCryptoProvider>,
    transport: Box<dyn scp_core::context::builder::ContextTransportProvider>,
    event_log: Box<dyn ContextEventLogProvider>,
    persistence: Option<Arc<dyn scp_core::context::manager::ContextPersistence + Send + Sync>>,
) -> Arc<ContextManager> {
    match persistence {
        Some(shared) => Arc::new(ContextManager::with_persistence(
            crypto,
            transport,
            event_log,
            Box::new(ArcContextPersistence::new(shared)),
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

/// Reads the shared persistence provider from the default bridge instance,
/// if one has been attached (typically via
/// [`UniffiBridgeInstance::with_storage_uniffi`] with a `SQLite` config).
///
/// Returns `None` when no persistence is configured — callers then fall
/// back to the ephemeral `ContextManager::new` path.
fn persistence_from_default_instance()
-> Option<Arc<dyn scp_core::context::manager::ContextPersistence + Send + Sync>> {
    DEFAULT_BRIDGE_INSTANCE.get()?.core.persistence_arc_clone()
}

/// Builds an event log provider that reuses the already-registered
/// `ProtocolRepository` on the default [`UniffiBridgeInstance`].
///
/// Reusing the repository is critical — a fresh repository would have a
/// different encryption key, rendering any already persisted event log
/// entries unreadable.
fn event_log_provider_from_existing_repo() -> Option<Box<dyn ContextEventLogProvider>> {
    let bi = DEFAULT_BRIDGE_INSTANCE.get()?;
    let bridge = ProtocolRepositoryEventLogBridge::new(Arc::clone(&bi.protocol_repository));
    Some(Box::new(MerkleEventLogProvider::with_persistence(
        Arc::new(bridge),
    )))
}

/// Builds a default `ContextManager` reusing the protocol repository already
/// registered on the default instance.
fn build_default_context_manager_reusing_repo() -> Arc<ContextManager> {
    let event_log = event_log_provider_from_existing_repo().unwrap_or_else(|| {
        tracing::error!(
            "build_default_context_manager_reusing_repo: missing ProtocolRepository — \
             falling back to a fresh event log provider (persistence will be lost)"
        );
        build_event_log_provider().0
    });
    let persistence = persistence_from_default_instance();
    build_context_manager(
        Box::new(FfiBridgeCrypto),
        Box::new(scp_core::context::NotConfiguredTransportProvider),
        event_log,
        persistence,
    )
}

/// Returns a reference to the shared `ContextManager`, initializing it with
/// defaults if necessary.
///
/// For `#[uniffi::export]` functions that return non-Result types (bool, Vec,
/// Option, ()), this provides access to the manager without requiring a
/// `Result` return type. Callers should prefer [`context_manager`] when the
/// return type supports `Result`.
pub fn context_manager_expect() -> &'static Arc<ContextManager> {
    if let Some(bi) = DEFAULT_BRIDGE_INSTANCE.get()
        && let Some(cm) = bi.core.try_context_manager()
    {
        return cm;
    }
    ensure_bridge_instance();
    if let Some(bi) = DEFAULT_BRIDGE_INSTANCE.get() {
        if !bi.core.has_context_manager() {
            bi.core
                .set_context_manager(build_default_context_manager_reusing_repo());
        }
        if let Some(cm) = bi.core.try_context_manager() {
            return cm;
        }
        tracing::error!(
            "context_manager_expect: default instance had no CM after set_context_manager — \
             falling back to a leaked default CM"
        );
    }
    // Defensive fallback — should not happen (ensure_bridge_instance just set it).
    let (cm, _protocol_repo) = build_default_context_manager();
    Box::leak(Box::new(cm))
}

/// Initializes the global [`ContextManager`] with bridge-local providers.
///
/// Called during `context_create` to ensure the manager is ready before any
/// context operations. Creates the default instance (without a DID) and
/// attaches a default `ContextManager` so shared registries are available.
///
/// Subsequent calls are no-ops (`OnceLock` guarantees single initialization).
pub fn init_context_manager() {
    ensure_bridge_instance();
    if let Some(bi) = DEFAULT_BRIDGE_INSTANCE.get()
        && !bi.core.has_context_manager()
    {
        bi.core
            .set_context_manager(build_default_context_manager_reusing_repo());
    }
}

/// Initializes the global [`ContextManager`] with [`MlsCryptoProvider`]
/// and `NotConfiguredTransportProvider`.
///
/// Unlike [`init_context_manager`] (which uses `FfiBridgeCrypto` no-op),
/// this variant initializes real MLS crypto backed by the given DID. Used
/// by `auto_wire_context_manager`'s fallback path when relay connection
/// fails.
///
/// Subsequent calls are no-ops (`OnceLock`).
pub fn init_context_manager_with_did(local_did: &str) {
    ensure_bridge_instance();
    let Some(bi) = DEFAULT_BRIDGE_INSTANCE.get() else {
        tracing::error!("init_context_manager_with_did: default instance unexpectedly None");
        return;
    };
    if bi.core.has_context_manager() {
        tracing::debug!(
            requested_did = %local_did,
            "init_context_manager_with_did: ContextManager already attached — using existing instance"
        );
        return;
    }
    let did = local_did.to_owned();
    let crypto = Box::new(scp_core::crypto::mls::provider::MlsCryptoProvider::new(did));
    let event_log = event_log_provider_from_existing_repo().unwrap_or_else(|| {
        tracing::error!(
            "init_context_manager_with_did: missing ProtocolRepository after \
             ensure_bridge_instance — falling back to a fresh event log provider"
        );
        build_event_log_provider().0
    });
    let persistence = bi.core.persistence_arc_clone();
    let cm_arc = build_context_manager(
        crypto,
        Box::new(scp_core::context::NotConfiguredTransportProvider),
        event_log,
        persistence,
    );

    bi.core.set_context_manager(cm_arc);
}

/// Initializes the global [`ContextManager`] with [`RelayTransportProvider`].
///
/// Identical to [`init_context_manager`] except the transport provider is a
/// `RelayTransportProvider` wrapping a real `NativeRelayAdapter` connected to
/// the given relay URL.
///
/// Subsequent calls are no-ops (`OnceLock`).
pub fn init_context_manager_with_relay_transport(
    local_did: &str,
    adapter: scp_transport::native::adapter::NativeRelayAdapter,
) {
    ensure_bridge_instance();
    let Some(bi) = DEFAULT_BRIDGE_INSTANCE.get() else {
        tracing::error!(
            "init_context_manager_with_relay_transport: default instance unexpectedly None"
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
    let persistence = bi.core.persistence_arc_clone();
    let cm_arc = build_context_manager(crypto, transport, event_log, persistence);

    bi.core.set_context_manager(cm_arc);
}

/// Returns the default instance's `ProtocolRepository`, if initialized.
///
/// Used by the trust aggregation bridge to construct a
/// `ProtocolRepositoryTrustBridge` backed by persistent (in-process) storage.
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
#[must_use]
pub fn build_event_log_provider() -> (
    Box<dyn ContextEventLogProvider>,
    Arc<ProtocolRepository<EncryptingAdapter<BridgeInMemoryStorage>>>,
) {
    scp_ffi_common::bridge_runtime::build_event_log_provider()
}

/// Global stub crypto provider shared with the `CloseOrchestrator`.
static FFI_CRYPTO: FfiBridgeCrypto = FfiBridgeCrypto;

/// Returns a reference to the bridge crypto provider for `CloseOrchestrator`.
#[must_use]
pub fn context_manager_crypto() -> &'static dyn ContextCryptoProvider {
    &FFI_CRYPTO
}

// ---------------------------------------------------------------------------
// Per-context UCAN state
// ---------------------------------------------------------------------------

/// Per-context UCAN validation state.
///
/// Type alias for [`scp_ffi_common::bridge_runtime::UcanContextStateCore`].
pub type UcanContextState = scp_ffi_common::bridge_runtime::UcanContextStateCore;

/// Returns a reference to the default instance's UCAN registry.
///
/// Falls back to an empty (process-static) registry when the default instance
/// has not been initialized. Consistent with the previous behaviour of
/// `EMPTY_UCAN_REGISTRY` in PR 0.
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
pub fn with_ucan_state<T, F>(context_id: &str, f: F) -> Option<T>
where
    F: FnOnce(&mut UcanContextState) -> T,
{
    let map = ucan_registry();
    let mut entry = map.get_mut(context_id)?;
    Some(f(&mut entry))
}

/// Removes UCAN validation state for a context.
pub fn remove_ucan_state(context_id: &str) {
    let map = ucan_registry();
    map.remove(context_id);
    if let Ok(bi) = bridge_instance() {
        bi.core.remove_known_context(context_id);
    }
}

/// Syncs role state from the `ContextManager` after governance operations.
///
/// Validates the `ContextManager` state is consistent and logs the sync for
/// traceability.
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

// ---------------------------------------------------------------------------
// Invitation rate limit tracker registry (#614)
// ---------------------------------------------------------------------------

/// Returns a mutable reference to the rate limit tracker for the given
/// identity DID, creating one if it does not exist.
///
/// Delegates to [`CoreFields::with_rate_limit_tracker`].
pub fn with_rate_limit_tracker<F, T>(identity_did: &str, f: F) -> T
where
    F: FnOnce(&mut scp_core::context::invitation::RateLimitTracker) -> T,
{
    if let Ok(bi) = bridge_instance() {
        bi.core.with_rate_limit_tracker(identity_did, f)
    } else {
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
/// event log. Returns `(0, 0)` as a stub; full trust scoring requires
/// `ContextManager` event log integration.
#[must_use]
pub const fn query_trust_event_counts(_context_id: &str, _did: &str) -> (u64, u64) {
    (0, 0)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // UniffiBridgeInstance tests (#1549)
    // -----------------------------------------------------------------------

    #[test]
    fn default_instance_is_same_arc() -> Result<(), crate::ScpError> {
        // Two calls to default_bridge_instance() must return the same
        // underlying Arc<UniffiBridgeInstance>.
        ensure_bridge_instance();
        let a = default_bridge_instance()?;
        let b = default_bridge_instance()?;
        assert!(
            Arc::ptr_eq(&a, &b),
            "default_bridge_instance() must return the same Arc on every call"
        );
        assert_eq!(a.instance_id(), b.instance_id());
        Ok(())
    }

    #[test]
    fn test_uniffi_bridge_instance_unique_ids() {
        let a = UniffiBridgeInstance::new_uniffi();
        let b = UniffiBridgeInstance::new_uniffi();
        assert_ne!(
            a.instance_id(),
            b.instance_id(),
            "every UniffiBridgeInstance must have a unique monotonic instance_id"
        );
        // u64 must not collide with the reserved UNSET_INSTANCE_ID (0).
        assert_ne!(
            a.instance_id(),
            scp_ffi_common::bridge_instance::UNSET_INSTANCE_ID
        );
        assert_ne!(
            b.instance_id(),
            scp_ffi_common::bridge_instance::UNSET_INSTANCE_ID
        );
    }

    #[test]
    fn test_uniffi_bridge_instance_typed_registries() {
        // Typed registries start empty and support insertion via their
        // typed interface (DashMap, Arc).
        let bi = UniffiBridgeInstance::new_uniffi();
        assert!(bi.ucan_registry().is_empty());
        #[cfg(feature = "allow_in_memory_custody")]
        assert!(bi.identity_custody_registry().is_empty());

        // ucan_registry is `Arc<DashMap<...>>` — typed, not Box<dyn Any>.
        bi.ucan_registry.insert(
            "test-ctx".to_owned(),
            UcanContextState {
                revocation_list: RevocationList::new("test-ctx".to_owned()),
                nonce_tracker: NonceTracker::new("test-ctx".to_owned(), SystemClock),
                ceiling_strings: HashSet::new(),
                creator_did: "did:dht:test".to_owned(),
                event_log: EventLog::new("test-ctx".to_owned()),
            },
        );
        assert_eq!(bi.ucan_registry().len(), 1);
    }

    #[test]
    fn test_handle_affinity_rejects_cross_instance() {
        // Two instances with distinct ids: a handle carrying A's id must be
        // rejected by a `check_handle` against B, and vice versa.
        let a = UniffiBridgeInstance::new_uniffi();
        let b = UniffiBridgeInstance::new_uniffi();

        // A's check_handle accepts A's id.
        assert!(a.core.check_handle(a.instance_id()).is_ok());
        // A's check_handle rejects B's id.
        let err = a
            .core
            .check_handle(b.instance_id())
            .expect_err("check_handle must reject cross-instance id");
        assert_eq!(err.handle_instance_id(), b.instance_id());
        assert_eq!(err.expected_instance_id(), a.instance_id());

        // Mapping to ScpError produces SCP-PERM-3030.
        let mapped = crate::ScpError::from(err);
        match mapped {
            crate::ScpError::Permission { code, .. } => {
                assert_eq!(code, codes::PERM_3030);
            }
            other => panic!("expected ScpError::Permission, got: {other:?}"),
        }
    }

    #[test]
    fn bridge_instance_populated_by_init_context_manager() -> Result<(), crate::ScpError> {
        init_context_manager_with_did("did:dht:ztest");
        let cm = context_manager()?;
        let bi = bridge_instance()?;
        assert!(
            Arc::ptr_eq(cm, bi.core.try_context_manager().unwrap()),
            "bridge_instance().context_manager() must be the same Arc as context_manager()"
        );
        Ok(())
    }

    #[test]
    fn bridge_instance_not_shutdown_initially() -> Result<(), crate::ScpError> {
        init_context_manager_with_did("did:dht:ztest");
        let bi = bridge_instance()?;
        assert!(
            !bi.core.is_shutdown(),
            "bridge_instance should not be shutdown immediately after init"
        );
        Ok(())
    }

    #[test]
    fn bridge_instance_error_code_is_ctx_2000() {
        let err = crate::ScpError::Context {
            msg: "bridge not initialized".to_owned(),
            code: codes::CTX_2000.to_owned(),
        };
        assert!(
            matches!(err, crate::ScpError::Context { ref code, .. } if code == codes::CTX_2000),
            "expected ScpError::Context with CTX_2000 code"
        );
    }

    #[test]
    fn shutdown_hook_runs_with_external_state() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        // Build an isolated UniffiBridgeInstance (not the global one) to avoid
        // interfering with the OnceLock-based singleton used by other tests.
        let bi = UniffiBridgeInstance::new_uniffi();

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
}
