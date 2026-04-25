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
//! # Safety: Single-Tenant Only
//!
//! **All registries in this module are process-global.** In multi-tenant
//! deployments (e.g., Django/FastAPI serving multiple SCP users), all tenants
//! share these registries. Context IDs and identity DIDs from one tenant are
//! accessible to another. This is a known architectural limitation.
//!
//! The NAPI (`Node.js`), `UniFFI` (Swift/Kotlin), and WASM bridges avoid this
//! issue by using per-instance handle objects instead of global registries.
//! The `PyO3` bridge must be refactored to match.
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
use scp_core::context::builder::{
    ContextCreationError, ContextEventLogProvider, ContextTransportProvider,
};
use scp_core::context::manager::{ContextManager, ContextPersistence};
use scp_core::context::providers::ProtocolRepositoryContextBridge;
use scp_core::context::roles::{ContextRoleState, default_ceiling};
use scp_core::context::tools::ToolRegistry;
use scp_core::crypto::mls::provider::MlsCryptoProvider;
use scp_core::crypto::ucan::nonce::NonceTracker;
use scp_core::crypto::ucan::revoke::RevocationList;
use scp_core::store::ProtocolRepository;
use scp_event_log::EventLog;
use scp_ffi_common::bridge_instance::BridgeInstanceCore;
// Re-export `CoreFields` at `crate::runtime::CoreFields` so the
// `pyscp_check_handle!` macro can refer to it as
// `$crate::runtime::CoreFields`.
pub use scp_ffi_common::bridge_instance::CoreFields;
use scp_identity::cache::SystemClock;
use scp_identity::{DidDocument, ScpIdentity};
use scp_platform::PlatformError;
use scp_platform::encrypting_adapter::EncryptingAdapter;
use scp_platform::sqlite::SqliteStorage;
use scp_platform::testing::InMemoryStorage;
use scp_platform::traits::Storage;
use scp_primitives::Clock;
use std::path::PathBuf;
use tokio::sync::mpsc;
use zeroize::Zeroizing;

// Re-export `KnownContext` from scp-ffi-common so that existing callers
// (`context.rs`, `mcp.rs`) can continue using `crate::runtime::KnownContext`.
pub use scp_ffi_common::bridge_instance::KnownContext;

use crate::context::PyMessage;
use crate::error::ScpPyError;

/// Runtime handle-affinity enforcement at every `#[pyfunction]` entry point
/// that accepts a handle.
///
/// Resolves [`bridge_instance_for_affinity`](crate::runtime::bridge_instance_for_affinity)
/// internally to obtain a [`CoreFields`] reference, then checks that each
/// supplied `$handle.instance_id` matches the core's `instance_id`. On
/// mismatch, returns a [`ScpPyError::UcanError`] with code
/// [`scp_ffi_common::error_codes::PERM_3030`] (mapped via the
/// [`From<HandleAffinityError>`](scp_ffi_common::bridge_instance::HandleAffinityError)
/// conversion).
///
/// Round 5 simplifier review removed the explicit `$core` parameter: all
/// 175 call sites passed `crate::runtime::bridge_instance_for_affinity()?`
/// identically, so YAGNI applied. If a future per-instance `SCP` method
/// needs to target a different core (e.g. `&self.inner.core`), add a
/// second macro arm rather than re-expanding the default one.
///
/// The affinity check is never blocked by transient lifecycle state
/// (e.g., a suspended bridge) because `bridge_instance_for_affinity`
/// intentionally bypasses the suspended guard.
///
/// # Example
///
/// ```ignore
/// #[pyfunction]
/// pub fn example(handle: &SomeHandle) -> PyResult<()> {
///     pyscp_check_handle!(handle);
///     // ... real work ...
///     Ok(())
/// }
/// ```
#[macro_export]
macro_rules! pyscp_check_handle {
    ($($handle:expr),+ $(,)?) => {{
        let __core = $crate::runtime::bridge_instance_for_affinity()?;
        $(
            __core
                .check_handle($handle.instance_id)
                .map_err($crate::error::ScpPyError::from)?;
        )+
    }};
}

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
// Supervisor (per-bridge, process-global default)
// ---------------------------------------------------------------------------

/// Returns a reference to the shared
/// [`Supervisor`](scp_core::context::supervisor::Supervisor) from the
/// default bridge instance.
///
/// Per ADR-049 commit 12c.9g.3 the FFI bridge no longer hands out an
/// `Arc<ContextManager>`. Every bridge function that previously routed
/// through `context_manager()` now goes through this accessor and uses
/// the supervisor's
/// [`dispatch_*`](scp_core::context::supervisor::Supervisor) family or
/// the per-method passthrough surface added on the supervisor.
///
/// # Errors
///
/// Returns `ScpPyError::ContextError` if the bridge instance has not
/// been initialized yet, if no supervisor has been wired (i.e.
/// `ensure_bridge_instance` ran but `init_supervisor` has not), or if
/// the bridge is currently suspended.
pub fn supervisor() -> Result<&'static Arc<scp_core::context::supervisor::Supervisor>, ScpPyError> {
    let bi = DEFAULT_BRIDGE_INSTANCE.get().ok_or_else(|| {
        ScpPyError::context(
            "Supervisor not initialized — call py_context_create, \
             py_context_join, py_context_import, or init_supervisor first"
                .to_owned(),
        )
    })?;
    if bi.core.is_suspended() {
        return Err(ScpPyError::context(
            "bridge is suspended — call resume() before performing operations".to_owned(),
        ));
    }
    if bi.core.is_shutdown() {
        tracing::warn!("supervisor() called after shutdown — operations may fail");
    }
    bi.core.try_supervisor().ok_or_else(|| {
        ScpPyError::context(
            "Supervisor not yet attached — call py_context_create, \
             py_context_join, py_context_import, or init_supervisor first"
                .to_owned(),
        )
    })
}

// ---------------------------------------------------------------------------
// PyBridgeInstance (per-bridge concrete struct wrapping CoreFields — #1549 Phase 4)
// ---------------------------------------------------------------------------

/// Storage configuration selector for [`PyBridgeInstance::with_storage_py`].
///
/// Two variants are supported:
/// - [`StorageConfig::InMemory`] — encrypted in-memory storage (ephemeral).
/// - [`StorageConfig::Sqlite`] — persistent SQLCipher-encrypted storage on
///   disk. The `key` is the raw encryption key material held in
///   [`Zeroizing`] so it is wiped from memory as soon as the config is
///   consumed.
///
/// Keeping this as an enum (instead of a string parameter) means adding future
/// variants is an additional arm, not a breaking API change.
#[derive(Debug, Clone)]
pub enum StorageConfig {
    /// In-memory encrypted storage (default; lost on process exit).
    InMemory,
    /// SQLCipher-encrypted storage at `{path}/scp.db`.
    ///
    /// Wraps [`scp_platform::sqlite::SqliteStorage`]. Persists across
    /// process restarts. The `key` is raw encryption key material wrapped in
    /// [`Zeroizing`] so the caller's copy is wiped after construction.
    Sqlite {
        /// Directory the database file is created in.
        path: PathBuf,
        /// Raw encryption key material (32 bytes recommended).
        key: Zeroizing<Vec<u8>>,
    },
}

/// Concrete storage provider backing a [`PyBridgeInstance`].
///
/// Wraps one of two encrypted storage backends. Implements
/// [`scp_platform::traits::Storage`] by dispatching method calls to the
/// inner backend inside a single `async move { match }` block, which keeps
/// the RPITIT return type consistent across variants.
///
/// Both inner types also satisfy `EncryptedStorage`, but the enum itself is
/// not `EncryptedStorage` because the sealed trait lives in `scp-platform`
/// and cannot be implemented here. Call sites that need
/// [`scp_core::store::ProtocolRepository`] dispatch on the variant and
/// construct the concrete `ProtocolRepository<S>` directly (see
/// [`build_persistence_provider`]).
#[derive(Clone)]
pub enum StorageProvider {
    /// Encrypted in-memory storage.
    InMemoryEncrypted(Arc<EncryptingAdapter<InMemoryStorage>>),
    /// SQLCipher-encrypted on-disk storage.
    Sqlite(Arc<SqliteStorage>),
}

impl StorageProvider {
    /// Constructs an in-memory encrypted provider with a fresh random key.
    #[must_use]
    pub fn new_in_memory_encrypted() -> Self {
        let mut key = Zeroizing::new([0u8; 32]);
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut *key);
        Self::InMemoryEncrypted(Arc::new(EncryptingAdapter::new(
            InMemoryStorage::new(),
            key,
        )))
    }

    /// Constructs a `SQLCipher`-encrypted provider at the given directory.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::StorageError`] if the database cannot be
    /// opened or the encryption key is rejected. The key material is
    /// consumed (moved) so that the original `Zeroizing<Vec<u8>>` is
    /// dropped — `SQLCipher` retains its own derived key internally.
    pub fn new_sqlite(path: &std::path::Path, key: &[u8]) -> Result<Self, PlatformError> {
        let storage = SqliteStorage::new(path, key)?;
        Ok(Self::Sqlite(Arc::new(storage)))
    }
}

impl Storage for StorageProvider {
    async fn store(&self, key: &str, data: &[u8]) -> Result<(), PlatformError> {
        match self {
            Self::InMemoryEncrypted(s) => s.store(key, data).await,
            Self::Sqlite(s) => s.store(key, data).await,
        }
    }

    async fn retrieve(&self, key: &str) -> Result<Option<Vec<u8>>, PlatformError> {
        match self {
            Self::InMemoryEncrypted(s) => s.retrieve(key).await,
            Self::Sqlite(s) => s.retrieve(key).await,
        }
    }

    async fn delete(&self, key: &str) -> Result<(), PlatformError> {
        match self {
            Self::InMemoryEncrypted(s) => s.delete(key).await,
            Self::Sqlite(s) => s.delete(key).await,
        }
    }

    async fn list_keys(&self, prefix: &str) -> Result<Vec<String>, PlatformError> {
        match self {
            Self::InMemoryEncrypted(s) => s.list_keys(prefix).await,
            Self::Sqlite(s) => s.list_keys(prefix).await,
        }
    }

    async fn delete_prefix(&self, prefix: &str) -> Result<u64, PlatformError> {
        match self {
            Self::InMemoryEncrypted(s) => s.delete_prefix(prefix).await,
            Self::Sqlite(s) => s.delete_prefix(prefix).await,
        }
    }

    async fn exists(&self, key: &str) -> Result<bool, PlatformError> {
        match self {
            Self::InMemoryEncrypted(s) => s.exists(key).await,
            Self::Sqlite(s) => s.exists(key).await,
        }
    }
}

/// `PyO3`-specific concrete bridge instance owning the bridge-agnostic
/// [`CoreFields`] plus `PyO3`-specific typed fields.
///
/// Replaces the type-erased `Box<dyn Any>` slots that previously lived on
/// `BridgeInstance`. Each typed field is owned by the per-bridge struct so
/// shutdown and handle-affinity enforcement flow through a single concrete
/// type.
///
/// Handle types carry [`CoreFields::instance_id`] and pass it to
/// [`CoreFields::check_handle`] at every FFI entry point, rejecting
/// cross-instance handle reuse with [`scp_ffi_common::bridge_instance::HandleAffinityError`].
pub struct PyBridgeInstance {
    /// Bridge-agnostic core state (transport, known contexts, rate limiters,
    /// DID resolver, lifecycle flags, `CancellationToken`, `JoinSet`,
    /// `instance_id`, etc.).
    pub(crate) core: CoreFields,

    /// Identity registry: `DID → IdentityEntry`. `PyO3`-specific because the
    /// `IdentityEntry` stores `Arc<FfiKeyCustody>` which is a `PyO3`-bridge
    /// crate concrete type that `scp-ffi-common` cannot know about.
    pub(crate) identity_registry: Arc<DashMap<String, IdentityEntry>>,

    /// Encrypted storage provider — [`StorageProvider`] enum dispatching
    /// between `EncryptingAdapter<InMemoryStorage>` and `SqliteStorage`.
    /// `OnceLock` because it is set once at `py_init_storage` (or
    /// construction) time. Typed (not `dyn`) because the `Storage` trait is
    /// not dyn-compatible (RPITIT).
    pub(crate) storage_provider: OnceLock<StorageProvider>,

    // -----------------------------------------------------------------
    // #1549 Phase 4 PR 2 commit 1 — additive typed fields replacing
    // process-global singletons in later commits.
    // -----------------------------------------------------------------
    /// Per-context FFI bridge state registry (replaces `FFI_BRIDGE_STATE`).
    ///
    /// Migrated from a process-global `OnceLock<DashMap<String, FfiBridgeState>>`
    /// singleton in commit 3. Wrapped in `Arc` so the existing free-function
    /// helpers (`with_ffi_state` / `register_ffi_state` / `remove_ffi_state`)
    /// can borrow it as `&'static` via the default-instance fallback pattern
    /// established for `identity_registry`.
    pub(crate) ffi_bridge_state: Arc<DashMap<String, FfiBridgeState>>,

    /// MCP server registry (replaces `SERVER_REGISTRY` in `mcp.rs`).
    ///
    /// Migrated from a process-global `OnceLock<DashMap<String, McpServerState>>`
    /// singleton in commit 4. Cleared by
    /// [`BridgeInstanceCore::bridge_specific_shutdown`] so server shutdown
    /// senders drop during instance shutdown.
    pub(crate) mcp_server_registry: Arc<DashMap<String, crate::mcp::McpServerState>>,

    /// MCP client registry (replaces `CLIENT_REGISTRY` in `mcp.rs`).
    ///
    /// Migrated from a process-global `OnceLock<DashMap<String, McpClientState>>`
    /// singleton in commit 4. Cleared by
    /// [`BridgeInstanceCore::bridge_specific_shutdown`] so client connections
    /// drop during instance shutdown.
    pub(crate) mcp_client_registry: Arc<DashMap<String, crate::mcp::McpClientState>>,

    /// Bridge credential store (replaces `CREDENTIAL_STORE` in
    /// `bridge_connector.rs`).
    ///
    /// Migrated from a process-global `OnceLock<InMemoryCredentialStore>`
    /// singleton in commit 5. Production deployments should replace this with
    /// a `Storage`-backed implementation when it lands (spec §12.11.2).
    pub(crate) credential_store: Arc<scp_core::bridge::credentials::InMemoryCredentialStore>,

    /// Most recently connected relay URL (replaces `CONNECTED_RELAY_URL` in
    /// `transport.rs`).
    ///
    /// Migrated from a process-global `OnceLock<RwLock<Option<String>>>`
    /// singleton in commit 8. Distinct from `CoreFields::pending_relay_url`:
    /// that tracks the pending URL saved for resume; this tracks the URL
    /// currently bound to an active `TransportManager`.
    pub(crate) connected_relay_url: RwLock<Option<String>>,

    /// Shared full-stack test network (replaces `NETWORK` in `testing.rs`).
    ///
    /// Migrated from a process-global
    /// `std::sync::Mutex<Option<FullStackNetwork>>` singleton in commit 9.
    /// Feature-gated behind `allow_in_memory_custody` to mirror `testing.rs`
    /// which is only compiled with that feature.
    #[cfg(feature = "allow_in_memory_custody")]
    pub(crate) network: std::sync::Mutex<Option<scp_testing::fullstack::FullStackNetwork>>,
}

impl PyBridgeInstance {
    /// Constructs a new `PyBridgeInstance` without a `ContextManager` or
    /// storage provider. The `CoreFields` allocates a fresh monotonic
    /// `instance_id`, a fresh `CancellationToken`, and an empty `JoinSet`.
    #[must_use]
    pub fn new_py() -> Self {
        Self {
            core: CoreFields::new(),
            identity_registry: Arc::new(DashMap::new()),
            storage_provider: OnceLock::new(),
            ffi_bridge_state: Arc::new(DashMap::new()),
            mcp_server_registry: Arc::new(DashMap::new()),
            mcp_client_registry: Arc::new(DashMap::new()),
            credential_store: Arc::new(
                scp_core::bridge::credentials::InMemoryCredentialStore::new(),
            ),
            connected_relay_url: RwLock::new(None),
            #[cfg(feature = "allow_in_memory_custody")]
            network: std::sync::Mutex::new(None),
        }
    }

    /// Constructs a new `PyBridgeInstance` with a persistence provider.
    ///
    /// Mirrors [`CoreFields::with_persistence`] — callers pass the same
    /// provider they used to build the eventual `ContextManager`.
    #[must_use]
    pub fn with_persistence_py(persistence: Box<dyn ContextPersistence + Send + Sync>) -> Self {
        Self {
            core: CoreFields::with_persistence(persistence),
            identity_registry: Arc::new(DashMap::new()),
            storage_provider: OnceLock::new(),
            ffi_bridge_state: Arc::new(DashMap::new()),
            mcp_server_registry: Arc::new(DashMap::new()),
            mcp_client_registry: Arc::new(DashMap::new()),
            credential_store: Arc::new(
                scp_core::bridge::credentials::InMemoryCredentialStore::new(),
            ),
            connected_relay_url: RwLock::new(None),
            #[cfg(feature = "allow_in_memory_custody")]
            network: std::sync::Mutex::new(None),
        }
    }

    /// Constructs a new `PyBridgeInstance` configured per the given
    /// [`StorageConfig`].
    ///
    /// - [`StorageConfig::InMemory`] — creates an
    ///   `EncryptingAdapter<InMemoryStorage>` with a random AES-256-GCM
    ///   key. `CoreFields::persistence` is left unset; the existing
    ///   `build_persistence_provider` path constructs a
    ///   `ProtocolRepositoryContextBridge` from `storage_provider()` on
    ///   demand when `init_context_manager*` runs.
    /// - [`StorageConfig::Sqlite`] — opens a `SQLCipher`-encrypted database at
    ///   `{path}/scp.db` and attaches a
    ///   [`ProtocolRepositoryContextBridge<Arc<SqliteStorage>>`] to
    ///   `CoreFields::persistence`, so suspend / shutdown flush runs
    ///   against the persistent store. The same `Arc<SqliteStorage>` is
    ///   also registered as `storage_provider` so identity, event log,
    ///   trust, and MCP reads hit the same connection pool (one DB
    ///   connection per process — `SQLite` cannot share one across two
    ///   `SqliteStorage::new` calls). If opening fails, the bridge is
    ///   returned with neither `storage_provider` nor `persistence` set
    ///   and the caller sees the existing "storage not initialized" error
    ///   paths. Errors are logged via `tracing::error!` so they are not
    ///   silently swallowed.
    ///
    /// For fallible construction that surfaces the `SQLite` error, use
    /// [`PyBridgeInstance::new_py`] + [`PyBridgeInstance::init_sqlite_storage`].
    #[must_use]
    pub fn with_storage_py(cfg: StorageConfig) -> Self {
        match cfg {
            StorageConfig::InMemory => {
                let instance = Self::new_py();
                // OnceLock: first set wins. `new_py()` leaves this unset, so
                // this set always succeeds.
                let _ = instance
                    .storage_provider
                    .set(StorageProvider::new_in_memory_encrypted());
                instance
            }
            StorageConfig::Sqlite { path, key } => {
                // Open the database once — `SqliteStorage` owns a single
                // `rusqlite::Connection` that every downstream consumer
                // (storage_provider + persistence) must share. An earlier
                // draft called `SqliteStorage::new` twice (once for the
                // provider, once for the persistence bridge) and hit
                // `SQLITE_BUSY` the moment both tried to write.
                match SqliteStorage::new(&path, &key) {
                    Ok(storage) => {
                        let arc_storage = Arc::new(storage);
                        // Build persistence bridge first so we can share
                        // the same Arc across CoreFields + storage_provider.
                        let repo = Arc::new(ProtocolRepository::new(Arc::clone(&arc_storage)));
                        let persistence: Arc<dyn ContextPersistence + Send + Sync> =
                            Arc::new(ProtocolRepositoryContextBridge::new(repo));
                        let instance = Self {
                            core: CoreFields::with_persistence_arc(persistence),
                            identity_registry: Arc::new(DashMap::new()),
                            storage_provider: OnceLock::new(),
                            ffi_bridge_state: Arc::new(DashMap::new()),
                            mcp_server_registry: Arc::new(DashMap::new()),
                            mcp_client_registry: Arc::new(DashMap::new()),
                            credential_store: Arc::new(
                                scp_core::bridge::credentials::InMemoryCredentialStore::new(),
                            ),
                            connected_relay_url: RwLock::new(None),
                            #[cfg(feature = "allow_in_memory_custody")]
                            network: std::sync::Mutex::new(None),
                        };
                        let _ = instance
                            .storage_provider
                            .set(StorageProvider::Sqlite(arc_storage));
                        // `key` is `Zeroizing<Vec<u8>>`, zeroed on drop here.
                        // SQLCipher has already retained its derived key
                        // internally, so the caller's key material is safe
                        // to wipe at this point.
                        drop(key);
                        instance
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            path = %path.display(),
                            "with_storage_py: SqliteStorage::new failed — instance created without storage or persistence"
                        );
                        drop(key);
                        Self::new_py()
                    }
                }
            }
        }
    }

    /// Returns a reference to the identity registry.
    #[must_use]
    pub const fn identity_registry(&self) -> &Arc<DashMap<String, IdentityEntry>> {
        &self.identity_registry
    }

    /// Returns a reference to the storage provider if initialized.
    #[must_use]
    pub fn storage_provider(&self) -> Option<&StorageProvider> {
        self.storage_provider.get()
    }

    /// Returns a reference to the per-context FFI bridge state registry.
    ///
    /// Wired into the existing `with_ffi_state` / `register_ffi_state` /
    /// `remove_ffi_state` free helpers in commit 3 via the default-instance
    /// fallback pattern established for `identity_registry`.
    #[must_use]
    pub const fn ffi_bridge_state(&self) -> &Arc<DashMap<String, FfiBridgeState>> {
        &self.ffi_bridge_state
    }

    /// Returns a reference to the MCP server registry.
    ///
    /// `pub(crate)` because `McpServerState` is itself `pub(crate)` — this
    /// accessor is used from `crate::mcp` to migrate the registry off the
    /// process-global `OnceLock` in commit 4.
    #[must_use]
    pub(crate) const fn mcp_server_registry(
        &self,
    ) -> &Arc<DashMap<String, crate::mcp::McpServerState>> {
        &self.mcp_server_registry
    }

    /// Returns a reference to the MCP client registry.
    ///
    /// `pub(crate)` — see `mcp_server_registry`.
    #[must_use]
    pub(crate) const fn mcp_client_registry(
        &self,
    ) -> &Arc<DashMap<String, crate::mcp::McpClientState>> {
        &self.mcp_client_registry
    }

    /// Returns a reference to the bridge credential store.
    #[must_use]
    pub const fn credential_store(
        &self,
    ) -> &Arc<scp_core::bridge::credentials::InMemoryCredentialStore> {
        &self.credential_store
    }

    /// Returns a reference to the connected-relay URL slot.
    ///
    /// Distinct from `CoreFields::pending_relay_url`: this field tracks the
    /// URL bound to the active `TransportManager`; the core's field tracks
    /// the pending URL saved for resume.
    #[must_use]
    pub const fn connected_relay_url(&self) -> &RwLock<Option<String>> {
        &self.connected_relay_url
    }

    /// Returns a reference to the shared full-stack test network slot.
    #[cfg(feature = "allow_in_memory_custody")]
    #[must_use]
    pub const fn network(
        &self,
    ) -> &std::sync::Mutex<Option<scp_testing::fullstack::FullStackNetwork>> {
        &self.network
    }

    /// Initializes the in-memory storage provider on this instance.
    ///
    /// Returns an error if storage was already initialized on this instance
    /// (`OnceLock` semantics) — matches the previous
    /// `set_storage_provider` warning behaviour but surfaces the failure
    /// to the caller instead of silently dropping it.
    ///
    /// # Errors
    ///
    /// Returns `ScpPyError::ContextError` if storage was already set.
    pub fn init_in_memory_storage(&self) -> Result<(), ScpPyError> {
        self.storage_provider
            .set(StorageProvider::new_in_memory_encrypted())
            .map_err(|_| {
                ScpPyError::context(
                    "storage already initialized — py_init_storage may only be called once per SCP instance"
                        .to_owned(),
                )
            })
    }

    /// Initializes a SQLCipher-encrypted storage provider on this instance.
    ///
    /// Opens a database at `{path}/scp.db` with the given raw encryption
    /// key. Subsequent calls return an error (`OnceLock` semantics).
    ///
    /// # Errors
    ///
    /// Returns `ScpPyError::ContextError` if storage was already set or if
    /// `SqliteStorage::new` fails (database open, schema creation, or
    /// encryption key rejection).
    pub fn init_sqlite_storage(
        &self,
        path: &std::path::Path,
        key: &[u8],
    ) -> Result<(), ScpPyError> {
        let provider = StorageProvider::new_sqlite(path, key)
            .map_err(|e| ScpPyError::context(format!("failed to open SQLite storage: {e}")))?;
        self.storage_provider.set(provider).map_err(|_| {
            ScpPyError::context(
                "storage already initialized — init_sqlite_storage may only be called once per SCP instance"
                    .to_owned(),
            )
        })
    }
}

#[async_trait::async_trait]
impl BridgeInstanceCore for PyBridgeInstance {
    fn core(&self) -> &CoreFields {
        &self.core
    }

    // `resume` inherits the `BridgeInstanceCore` default (ADR-049 §11,
    // landed in commit 6): flag flip + transport reconnect +
    // persisted-context restore. Overriding here would diverge from
    // the shared contract and be caught by the cross-bridge consistency
    // gate `scripts/check-bridge-instance-lifecycle.py`.

    // `shutdown` inherits the `BridgeInstanceCore` default (ADR-049 §11,
    // landed in commit 6): `core.shutdown_core_async(timeout).await +
    // bridge_specific_shutdown()`. Overriding here would diverge from
    // the shared contract and be caught by the cross-bridge consistency
    // gate `scripts/check-bridge-instance-lifecycle.py`.

    fn bridge_specific_shutdown(&self) {
        // Clear the identity registry so held `Arc<FfiKeyCustody>` entries
        // drop, triggering `Zeroizing` on key material.
        self.identity_registry.clear();
        // `storage_provider` is `OnceLock` — we cannot clear it. The
        // `Arc<EncryptingAdapter>` is released when the `PyBridgeInstance`
        // is dropped.
        // Clear the typed per-context FFI state registry so per-context
        // `ToolRegistry`, `EventLog`, receive channel senders, and
        // registered tool handlers drop.
        self.ffi_bridge_state.clear();
        // Clear MCP registries so server shutdown senders and client
        // connections drop, allowing background tasks to terminate cleanly.
        self.mcp_server_registry.clear();
        self.mcp_client_registry.clear();
    }
}

/// Default (process-global) `PyBridgeInstance`.
///
/// Retained as a `OnceLock` for backward compatibility with the PR 0
/// flat `#[pyfunction]` API (`py_identity_create`, `py_context_create`, …).
/// New callers should prefer explicit [`crate::scp::PyScp`] instances.
///
/// # Safety: Single-Tenant Fallback
///
/// Callers that construct their own `PyScp` instance escape the process-
/// global pattern entirely. The default instance is retained only so the
/// flat bridge functions continue to work during the migration.
pub(crate) static DEFAULT_BRIDGE_INSTANCE: OnceLock<Arc<PyBridgeInstance>> = OnceLock::new();

/// Initializes the default [`PyBridgeInstance`] without a `ContextManager`.
///
/// Called by [`ensure_bridge_instance`] and (transitively) by
/// [`init_context_manager`]. The `ContextManager` is attached later via
/// [`CoreFields::set_context_manager`] once `identity_create` has produced
/// the local DID and the `MlsCryptoProvider` has been constructed with it.
///
/// `PyBridgeInstance` itself carries no DID (spec §12.2.3) — the
/// authoritative local DID lives inside the `ContextManager`'s
/// `MlsCryptoProvider`. The instance is created before any identity exists
/// so that the DID resolver slot (owned by `CoreFields`) is available while
/// `DidDht::create()` runs.
///
/// Subsequent calls are no-ops (`OnceLock` guarantees single initialization).
fn init_bridge_instance_empty() {
    if DEFAULT_BRIDGE_INSTANCE.get().is_some() {
        return;
    }
    let _ = DEFAULT_BRIDGE_INSTANCE.get_or_init(|| Arc::new(PyBridgeInstance::new_py()));
}

/// Returns the raw default `PyBridgeInstance` reference without lifecycle
/// checks.
///
/// Used by lifecycle / shutdown code that must touch the container even
/// when the `ContextManager` has not been attached yet.
#[must_use]
pub fn bridge_instance_raw() -> Option<&'static Arc<PyBridgeInstance>> {
    DEFAULT_BRIDGE_INSTANCE.get()
}

/// Returns a reference to the default `PyBridgeInstance`.
///
/// # Errors
///
/// Returns `ScpPyError::ContextError` if the bridge has not been initialized
/// via [`init_context_manager`] (which also creates the default instance),
/// or if the bridge is currently suspended. Shutdown is a warning (not an
/// error) because shutdown is terminal and operations fail naturally at the
/// MLS/transport layer.
pub fn bridge_instance() -> Result<&'static Arc<PyBridgeInstance>, ScpPyError> {
    let bi = DEFAULT_BRIDGE_INSTANCE.get().ok_or_else(|| {
        ScpPyError::context("bridge not initialized — call identity_create first".to_owned())
    })?;
    if bi.core.is_suspended() {
        return Err(ScpPyError::context(
            "bridge is suspended — call resume() before performing operations".to_owned(),
        ));
    }
    if bi.core.is_shutdown() {
        tracing::warn!("bridge_instance() called after shutdown — operations may fail");
    }
    Ok(bi)
}

/// Lazily initializes and returns the default `PyBridgeInstance`.
///
/// Unlike [`bridge_instance`], this never fails due to "not yet initialized"
/// — it creates the default instance on first call. Used by shared helpers
/// that must resolve the default instance regardless of caller order.
///
/// # Errors
///
/// Returns `ScpPyError::ContextError` if the bridge is currently suspended.
pub fn default_bridge_instance() -> Result<Arc<PyBridgeInstance>, ScpPyError> {
    ensure_bridge_instance();
    let bi = DEFAULT_BRIDGE_INSTANCE.get().ok_or_else(|| {
        ScpPyError::context("failed to initialize default bridge instance".to_owned())
    })?;
    if bi.core.is_suspended() {
        return Err(ScpPyError::context(
            "bridge is suspended — call resume() before performing operations".to_owned(),
        ));
    }
    if bi.core.is_shutdown() {
        tracing::warn!("default_bridge_instance() called after shutdown — operations may fail");
    }
    Ok(Arc::clone(bi))
}

/// Returns a reference to the default `PyBridgeInstance`'s `CoreFields` for
/// handle-affinity checks only.
///
/// Unlike [`bridge_instance`] / [`default_bridge_instance`], this helper does
/// NOT return an error when the bridge is suspended — a handle-affinity check
/// is a pure compare-two-u64 operation that does not touch transport or
/// `ContextManager` state, so suspending the bridge must not block it. Used
/// exclusively by the [`crate::pyscp_check_handle!`] macro at FFI entry
/// points to mirror the NAPI/UniFFI [`bridge_instance_for_affinity`] helpers
/// (cross-bridge symmetry).
///
/// # Errors
///
/// Returns `ScpPyError::ContextError` if the default bridge failed to
/// initialize (very unlikely — [`ensure_bridge_instance`] runs first and is
/// infallible in practice).
#[must_use = "the returned CoreFields reference must be used for the affinity check"]
pub fn bridge_instance_for_affinity() -> Result<&'static CoreFields, ScpPyError> {
    ensure_bridge_instance();
    DEFAULT_BRIDGE_INSTANCE
        .get()
        .map(|bi| &bi.core)
        .ok_or_else(|| {
            ScpPyError::context(
                "bridge not initialized — call identity_create or \
                 init_context_manager first"
                    .to_owned(),
            )
        })
}

// ---------------------------------------------------------------------------
// ContextManager initialization
// ---------------------------------------------------------------------------

/// Initializes the per-bridge [`Supervisor`] with production providers.
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
/// When the `BridgeInstance` storage provider has been initialized via
/// [`init_storage`], a [`ProtocolRepositoryContextBridge`] is constructed
/// from it and injected into the `ContextManager` that the supervisor wraps.
/// This enables context state persistence across process restarts without
/// requiring callers to manually wire persistence. See issue #329.
///
/// The `local_did` is consumed only by `MlsCryptoProvider::new` — the
/// `BridgeInstance` itself carries no DID (spec §12.2.3).
///
/// Subsequent calls are no-ops (`OnceLock` guarantees single initialization).
/// If the supervisor is already initialized with a different DID, a warning is
/// logged.
pub fn init_supervisor(local_did: &str) {
    // Always ensure the BridgeInstance exists first so that identity-time
    // state (DID resolver, identity registry) is wired up before we attempt
    // to attach a Supervisor.
    ensure_bridge_instance();

    let Some(bi) = DEFAULT_BRIDGE_INSTANCE.get() else {
        tracing::error!(
            "init_supervisor: PyBridgeInstance unexpectedly None after ensure_bridge_instance"
        );
        return;
    };

    if bi.core.has_supervisor() {
        tracing::debug!(
            requested_did = %local_did,
            "init_supervisor: Supervisor already attached — using existing instance"
        );
        return;
    }

    let did = local_did.to_owned();
    let crypto = Arc::new(scp_core::crypto::mls::provider::MlsCryptoProvider::new(did));
    let persistence = build_persistence_provider();
    let supervisor_arc = build_supervisor(
        crypto,
        Box::new(NotConfiguredTransportProvider),
        Box::new(NoOpEventLogProvider),
        persistence,
    );

    bi.core.set_supervisor(supervisor_arc);
}

/// Ensures the default [`PyBridgeInstance`] exists (without a `Supervisor`).
///
/// Called by [`crate::identity::ensure_did_resolver_initialized`] before
/// `DidDht::create()` runs, so that the DID resolver slot owned by
/// `BridgeInstance` is available. The `Supervisor` is attached later
/// via [`init_supervisor`] once the identity is known and the
/// `MlsCryptoProvider` has been constructed with it. Per spec §12.2.3
/// the `BridgeInstance` container has no DID requirement.
///
/// Subsequent calls are no-ops (`OnceLock` guarantees single initialization).
pub fn ensure_bridge_instance() {
    init_bridge_instance_empty();
}

/// Initializes the per-bridge [`Supervisor`] with custom providers.
///
/// Allows injecting real or custom provider implementations. If the
/// supervisor is already initialized, this is a no-op (first call wins).
///
/// When `persistence` is `None` but the global storage provider has been
/// initialized, a [`ProtocolRepositoryContextBridge`] is automatically
/// constructed from it. Pass `Some(...)` to override with a custom
/// implementation.
pub fn init_supervisor_with(
    _local_did: &str,
    crypto: Arc<MlsCryptoProvider>,
    transport: Box<dyn ContextTransportProvider>,
    event_log: Box<dyn ContextEventLogProvider>,
    persistence: Option<Box<dyn ContextPersistence>>,
) {
    // `_local_did` is retained in the signature for API stability: callers
    // construct `crypto` with the DID before calling into this function
    // (it is the `MlsCryptoProvider` that carries the DID; see spec §12.2.3).
    ensure_bridge_instance();
    let Some(bi) = DEFAULT_BRIDGE_INSTANCE.get() else {
        tracing::error!("init_supervisor_with: PyBridgeInstance unexpectedly None");
        return;
    };
    if bi.core.has_supervisor() {
        return;
    }
    let persistence = persistence.or_else(build_persistence_provider);
    let supervisor_arc = build_supervisor(crypto, transport, event_log, persistence);
    bi.core.set_supervisor(supervisor_arc);
}

/// Test variant of [`init_supervisor`] that uses `LocalTransportProvider`
/// instead of `NotConfiguredTransportProvider`.
///
/// Production code uses `NotConfiguredTransportProvider` to surface descriptive
/// errors when transport operations (publish, send) are attempted without a
/// configured relay. Tests use `LocalTransportProvider` so that
/// `publish_context` succeeds without real relay infrastructure.
///
/// Not behind `#[cfg(test)]` because integration tests (`tests/e2e_bridge.rs`)
/// compile as separate crates and need access to this function.
pub fn init_supervisor_for_test() {
    ensure_bridge_instance();
    let Some(bi) = DEFAULT_BRIDGE_INSTANCE.get() else {
        tracing::error!("init_supervisor_for_test: PyBridgeInstance unexpectedly None");
        return;
    };
    if bi.core.has_supervisor() {
        return;
    }
    let persistence = build_persistence_provider();
    let supervisor_arc = build_supervisor(
        Arc::new(MlsCryptoProvider::new(
            "did:test:pyo3-bridge-test".to_owned(),
        )),
        Box::new(scp_core::context::LocalTransportProvider),
        Box::new(NoOpEventLogProvider),
        persistence,
    );

    bi.core.set_supervisor(supervisor_arc);
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
    let bi = DEFAULT_BRIDGE_INSTANCE.get()?;
    // Prefer the shared provider attached to `CoreFields` at construction
    // time — this is the path the `Sqlite` variant of `with_storage_py`
    // uses, and it guarantees the ContextManager and the CoreFields
    // mirror hand out the same underlying provider (one SQLite
    // connection, not two).
    if let Some(shared) = bi.core.persistence_arc_clone() {
        return Some(Box::new(ArcContextPersistence::new(shared)) as Box<dyn ContextPersistence>);
    }
    bi.storage_provider().map(|provider| match provider {
        StorageProvider::InMemoryEncrypted(storage) => {
            let repo = Arc::new(ProtocolRepository::new(Arc::clone(storage)));
            Box::new(ProtocolRepositoryContextBridge::new(repo)) as Box<dyn ContextPersistence>
        }
        StorageProvider::Sqlite(storage) => {
            let repo = Arc::new(ProtocolRepository::new(Arc::clone(storage)));
            Box::new(ProtocolRepositoryContextBridge::new(repo)) as Box<dyn ContextPersistence>
        }
    })
}

/// Adapter that lets a shared `Arc<dyn ContextPersistence + Send + Sync>`
/// be consumed by APIs requiring a `Box<dyn ContextPersistence>`.
///
/// Mirrors the `UniFFI` bridge's `ArcContextPersistence`
/// (`crates/scp-ffi/uniffi/src/runtime.rs`). See that file for rationale
/// — the short version is that `ContextManager::with_persistence` takes
/// `Box`, but we want the same underlying provider to back both the
/// `CoreFields` mirror and the manager's reference so `SQLite` sees a
/// single connection instead of two.
struct ArcContextPersistence {
    inner: Arc<dyn ContextPersistence + Send + Sync>,
}

impl ArcContextPersistence {
    const fn new(inner: Arc<dyn ContextPersistence + Send + Sync>) -> Self {
        Self { inner }
    }
}

impl ContextPersistence for ArcContextPersistence {
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

/// Constructs a fresh per-instance [`Supervisor`] wrapping a
/// `ContextManager` (with or without persistence).
///
/// ADR-049 commit 12c.9g.3 — the FFI bridge no longer hands out a raw
/// `Arc<ContextManager>`. The manager is built here, attached to the
/// supervisor (so the supervisor's lifted-provider slots populate),
/// and the supervisor is the only handle returned to the bridge layer.
/// Commit 12c.9g.4 deletes the manager-construction step and lets the
/// supervisor own its providers directly.
fn build_supervisor(
    crypto: Arc<MlsCryptoProvider>,
    transport: Box<dyn ContextTransportProvider>,
    event_log: Box<dyn ContextEventLogProvider>,
    persistence: Option<Box<dyn ContextPersistence>>,
) -> Arc<scp_core::context::supervisor::Supervisor> {
    use scp_core::context::supervisor::Supervisor;

    let cm = match persistence {
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
    };
    let supervisor = Arc::new(Supervisor::for_query_shim());
    if let Err(err) = supervisor.attach_context_manager(&cm) {
        tracing::warn!(
            error = %err,
            "build_supervisor: attach_context_manager failed — supervisor still constructed but \
             without lifted providers"
        );
    }
    supervisor
}

// ---------------------------------------------------------------------------
// DID resolver (global, production)
// ---------------------------------------------------------------------------

/// Returns the production DID resolver on the default bridge instance, if
/// initialized.
///
/// Reads the DID resolver slot on [`DEFAULT_BRIDGE_INSTANCE`]'s `CoreFields`.
/// Returns `None` when the bridge has not been initialized or no resolver
/// has been set.
#[must_use]
pub fn did_resolver() -> Option<&'static Arc<scp_ffi_common::IdentityBackedDidResolver>> {
    // SAFETY: DEFAULT_BRIDGE_INSTANCE is in a OnceLock<Arc<...>> which is
    // 'static. The DID resolver inside CoreFields is in a OnceLock<Arc<...>>
    // which is also 'static. The returned reference has 'static lifetime
    // because both OnceLocks are static.
    DEFAULT_BRIDGE_INSTANCE
        .get()
        .and_then(|bi| bi.core.did_resolver())
}

/// Initializes the production DID resolver on the default bridge instance.
///
/// Wraps any `scp_identity::resolver::DidResolver` implementation (typically
/// `DualLayerResolver`) in an `IdentityBackedDidResolver` and stores it in
/// the default `PyBridgeInstance`'s `CoreFields`.
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
            "init_did_resolver called before PyBridgeInstance initialized — resolver not stored"
        );
    }
}

// ---------------------------------------------------------------------------
// Key resolver helper — delegates to scp-ffi-common
// ---------------------------------------------------------------------------

/// Returns a key resolver that rejects all lookups with a logged error.
///
/// Delegates to [`scp_ffi_common::bridge_runtime::not_configured_key_resolver`].
fn not_configured_key_resolver() -> scp_core::context::governance::KeyResolver {
    scp_ffi_common::bridge_runtime::not_configured_key_resolver()
}

// ---------------------------------------------------------------------------
// No-op provider implementations for ContextManager initialization
// ---------------------------------------------------------------------------

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
        _actor_did: &str,
        _payload: Option<&serde_json::Value>,
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

/// Fallback empty FFI bridge state registry for when the default
/// `PyBridgeInstance` has not been initialized yet.
///
/// Mirrors the `EMPTY_IDENTITY_REGISTRY` pattern introduced for the
/// identity-registry migration. Used by [`ffi_state_registry`] to keep the
/// existing free-function signatures infallible even when callers touch
/// bridge state before `ensure_bridge_instance` runs.
static EMPTY_FFI_BRIDGE_STATE: OnceLock<DashMap<String, FfiBridgeState>> = OnceLock::new();

/// Returns a reference to the default bridge instance's FFI bridge state
/// registry.
///
/// Resolves the registry via the typed `ffi_bridge_state` field on the
/// default [`PyBridgeInstance`]. Falls back to an empty registry when the
/// default instance has not been initialized yet — matching the behaviour of
/// the removed standalone `OnceLock<DashMap<...>>` (callers previously saw
/// an empty registry on first touch; they still do).
///
/// Stores state that is NOT managed by [`ContextManager`]: tool registries,
/// event logs, UCAN revocation/nonce tracking, tool handlers, and message
/// channels. Context lifecycle state (membership, roles, governance,
/// broadcast, TTL) lives in the `ContextManager`.
///
/// # Safety: Single-Tenant Only
///
/// The default instance's registry is process-global. See module-level
/// documentation.
fn ffi_state_registry() -> &'static DashMap<String, FfiBridgeState> {
    DEFAULT_BRIDGE_INSTANCE.get().map_or_else(
        || EMPTY_FFI_BRIDGE_STATE.get_or_init(DashMap::new),
        |bi| bi.ffi_bridge_state.as_ref(),
    )
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
    // Clean up known-context discovery entry via CoreFields.
    if let Ok(bi) = bridge_instance() {
        bi.core.remove_known_context(context_id);
    }
    // Clean up per-context bridge connector state and economy state via CoreFields.
    if let Ok(bi) = bridge_instance() {
        bi.core.remove_bridge_state(context_id);
        bi.core.remove_economy_state(context_id);
    }
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
    use scp_core::context::actor::commands::QueriesCommand;
    let sup = supervisor()?;
    let rt = super::runtime().map_err(|e| ScpPyError::context(e.to_string()))?;
    let context_id_owned = context_id.to_owned();
    // Route through the ADR-049 query shim. The handler returns
    // `Ok(None)` when the context is unknown, matching the legacy
    // `ContextManager::get_role_state` `Option` contract.
    let new_role_state = rt
        .block_on(async move {
            let (tx, rx) = tokio::sync::oneshot::channel();
            let cmd = QueriesCommand::GetRoleState {
                context_id: context_id_owned,
                reply: tx,
            };
            sup.dispatch_query(cmd).await.map_err(|e| {
                ScpPyError::context(format!("supervisor dispatch_query failed: {e}"))
            })?;
            rx.await
                .map_err(|e| ScpPyError::context(format!("query shim reply dropped: {e}")))?
                .map_err(|e| ScpPyError::context(e.to_string()))
        })?
        .ok_or_else(|| {
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
            // oldest-drop semantics. try_lock() would drop the NEW
            // message on lock contention — the opposite of documented
            // behavior. The lock is only held for a single try_recv()
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
                scp_primitives::SystemClock.now_secs() as f64,
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
//
// Delegates to the `BridgeInstance`'s `known_contexts` DashMap.
// The `KnownContext` type is defined in `scp-ffi-common::bridge_instance`
// and re-exported at the top of this module for backward compatibility.
//
// These functions require the bridge to be initialized. Before
// `init_context_manager` is called, `register_known_context` panics
// (callers must initialize identity first, which initializes the bridge).
// ---------------------------------------------------------------------------

/// Registers a known context in the discovery registry.
///
/// Called after `py_context_create` to record the context's routing ID and
/// relay URL for later discovery via `py_mcp_load_contexts`.
///
/// Overwrites any existing entry for the same context ID (idempotent).
///
/// # Panics
///
/// Panics if the bridge has not been initialized via [`init_context_manager`].
pub fn register_known_context(context_id: &str, known: KnownContext) {
    if let Ok(bi) = bridge_instance() {
        bi.core.register_known_context(context_id, known);
    } else {
        tracing::warn!(
            "register_known_context called before bridge init — context '{}' not tracked",
            context_id
        );
    }
}

/// Returns all known contexts from the discovery registry.
///
/// Used by `py_mcp_load_contexts` to find routing IDs to probe on the relay.
/// Returns an empty `Vec` if the bridge has not been initialized.
#[must_use]
pub fn all_known_contexts() -> Vec<(String, KnownContext)> {
    bridge_instance()
        .map(|bi| bi.core.all_known_contexts())
        .unwrap_or_default()
}

/// Returns known contexts where the given DID is the registered member.
///
/// Returns an empty `Vec` if the bridge has not been initialized.
#[must_use]
pub fn known_contexts_for_member(member_did: &str) -> Vec<(String, KnownContext)> {
    bridge_instance()
        .map(|bi| bi.core.known_contexts_for_member(member_did))
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Invitation rate limit tracker registry (#614)
// ---------------------------------------------------------------------------
//
// Delegates to the `BridgeInstance`'s `rate_limiters` DashMap.
// ---------------------------------------------------------------------------

/// Returns a mutable reference to the rate limit tracker for the given
/// identity DID, creating one if it does not exist.
///
/// Delegates to the `BridgeInstance`'s rate-limiter registry. If the bridge
/// has not been initialized (unusual — identity must be created before
/// invitation evaluation), falls back to a thread-local default tracker
/// to preserve the original infallible signature.
///
/// The caller passes a closure that receives `&mut RateLimitTracker`.
pub fn with_rate_limit_tracker<F, T>(identity_did: &str, f: F) -> T
where
    F: FnOnce(&mut scp_core::context::invitation::RateLimitTracker) -> T,
{
    if let Ok(bi) = bridge_instance() {
        bi.core.with_rate_limit_tracker(identity_did, f)
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

// ---------------------------------------------------------------------------
// Identity registry (SCP-214: KeyCustody wiring)
// ---------------------------------------------------------------------------

/// Returns the default bridge instance's identity registry.
///
/// The registry is a typed `Arc<DashMap<String, IdentityEntry>>` field on
/// [`PyBridgeInstance`]. `ensure_bridge_instance()` initializes
/// `DEFAULT_BRIDGE_INSTANCE` if it is not yet set, so the registry is
/// always real — there is no fallback empty map that writers could land in
/// before a reader sees the instance registry (the H1 bug fixed in commit
/// 10 of #1549 Phase 4 PR 2).
///
/// The `DashMap` provides lock-free concurrent access matching the context
/// registry pattern (ADR-006).
fn identity_registry() -> &'static DashMap<String, IdentityEntry> {
    ensure_bridge_instance();
    // `ensure_bridge_instance()` returns early if the instance is already
    // set, otherwise it runs `OnceLock::get_or_init` to allocate one. The
    // only `None` path left is a compiler-level `OnceLock` bug — treat that
    // as unreachable. A panicking fallback matches the previous behavior
    // on instance-poisoned paths (e.g. `context_manager()` after shutdown).
    DEFAULT_BRIDGE_INSTANCE.get().map_or_else(
        || unreachable!("DEFAULT_BRIDGE_INSTANCE set by ensure_bridge_instance()"),
        |bi| bi.identity_registry.as_ref(),
    )
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

/// Initializes the storage provider and stores it in the `BridgeInstance`.
///
/// Must be called before any storage-dependent bridge function
/// (`py_identity_create`, `py_identity_load`). Calling multiple times is
/// a no-op — the first call wins (`OnceLock` in `BridgeInstance`).
///
/// Wraps `InMemoryStorage` in [`EncryptingAdapter`] with a random
/// AES-256-GCM key generated via `OsRng`. This ensures all stored
/// values are encrypted at rest, satisfying the `EncryptedStorage` bound.
///
/// See spec section 17.3 for key conventions and section 17.4 for
/// `ProtocolRepository` design.
///
/// # Arguments
///
/// * `storage_type` — Currently only `"in_memory"` is supported.
///
/// # Errors
///
/// Returns `ScpPyError::ValidationError` if the storage type is not
/// recognized, or `ScpPyError::ContextError` if the bridge has not been
/// initialized.
pub fn init_storage(storage_type: &str) -> Result<(), ScpPyError> {
    match storage_type {
        "in_memory" => {
            let bi = bridge_instance()?;
            // `init_in_memory_storage` returns an error if already set; match
            // the previous silent-no-op behaviour by converting already-set
            // to Ok (OnceLock semantics: first wins, subsequent silent).
            if bi.init_in_memory_storage().is_err() {
                tracing::debug!(
                    "init_storage: storage already initialized on default instance — reusing existing provider"
                );
            }
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
/// via [`init_storage`], or `ScpPyError::ContextError` if the bridge has
/// not been initialized.
pub fn get_storage() -> Result<&'static StorageProvider, ScpPyError> {
    let bi = DEFAULT_BRIDGE_INSTANCE.get().ok_or_else(|| {
        ScpPyError::identity(
            "bridge not initialized — call identity_create before storage operations".to_owned(),
        )
    })?;
    bi.storage_provider().ok_or_else(|| {
        ScpPyError::identity(
            "storage not initialized — call py_init_storage(\"in_memory\") first".to_owned(),
        )
    })
}

// ---------------------------------------------------------------------------
// Relay connection state (SCP-213: transport wiring)
// ---------------------------------------------------------------------------
//
// Delegates to the `BridgeInstance`'s `transport` RwLock.
// ---------------------------------------------------------------------------

/// Stores a new `TransportManager` (called by `py_transport_connect`).
///
/// Delegates to [`CoreFields::set_transport`].
///
/// # Errors
///
/// Returns `ScpPyError::TransportError` if the transport manager lock is
/// poisoned or the bridge is not initialized.
pub fn set_transport_manager(manager: scp_transport::TransportManager) -> Result<(), ScpPyError> {
    let bi = bridge_instance().map_err(|_| {
        ScpPyError::transport(
            "bridge not initialized — call identity_create before transport_connect".to_owned(),
        )
    })?;
    bi.core
        .set_transport(Arc::new(manager))
        .map_err(|e| ScpPyError::transport(e.to_string()))
}

/// Executes a closure with a read reference to the `TransportManager`.
///
/// Delegates to [`CoreFields::with_transport`].
///
/// # Errors
///
/// Returns `ScpPyError::TransportError` if the lock is poisoned, no
/// transport manager has been initialized, or the bridge is not initialized.
pub fn with_transport_manager<T>(
    f: impl FnOnce(&scp_transport::TransportManager) -> Result<T, ScpPyError>,
) -> Result<T, ScpPyError> {
    let bi = bridge_instance().map_err(|_| {
        ScpPyError::transport("no transport manager — call transport_connect first".to_owned())
    })?;
    bi.core
        .with_transport(f)
        .map_err(|e| ScpPyError::transport(e.to_string()))?
}

/// Executes a closure with a mutable reference to the `TransportManager`.
///
/// Delegates to [`CoreFields::with_transport_mut`].
///
/// # Errors
///
/// Returns `ScpPyError::TransportError` if the lock is poisoned, no
/// transport manager has been initialized, or the bridge is not initialized.
pub fn with_transport_manager_mut<T>(
    f: impl FnOnce(&mut scp_transport::TransportManager) -> Result<T, ScpPyError>,
) -> Result<T, ScpPyError> {
    let bi = bridge_instance().map_err(|_| {
        ScpPyError::transport("no transport manager — call transport_connect first".to_owned())
    })?;
    bi.core
        .with_transport_mut(f)
        .map_err(|e| ScpPyError::transport(e.to_string()))?
}

/// Returns `true` if a transport manager has been initialized.
#[must_use]
pub fn has_transport_manager() -> bool {
    bridge_instance().is_ok_and(|bi| bi.core.has_transport())
}

/// Records a heartbeat suppression event for a relay, downgrading its
/// reliability score.
///
/// Called from the background task spawned by `transport_add_relay` /
/// `transport_connect` that drains the per-adapter suppression receiver
/// (#1533 AC5). Silently no-ops if the bridge or transport manager has
/// been cleared (e.g., after disconnect).
pub fn record_suppression(relay_url: &str) {
    let Ok(bi) = bridge_instance() else {
        return;
    };
    let _ = bi.core.with_transport(|manager| {
        manager.update_score(relay_url, scp_transport::scoring::DeliveryOutcome::Failure);
        Ok::<(), ScpPyError>(())
    });
}

/// Clears the transport manager (called by `py_transport_disconnect`).
///
/// After this, relay-based context discovery in `py_mcp_load_contexts`
/// will fall back to local-only mode.
///
/// # Errors
///
/// Returns `ScpPyError::TransportError` if the transport manager lock is
/// poisoned or the bridge is not initialized.
pub fn clear_transport_manager() -> Result<(), ScpPyError> {
    let bi = bridge_instance().map_err(|_| {
        ScpPyError::transport(
            "bridge not initialized — call identity_create before transport_disconnect".to_owned(),
        )
    })?;
    bi.core
        .clear_transport()
        .map_err(|e| ScpPyError::transport(e.to_string()))
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
    init_supervisor_for_test();
    #[cfg(not(test))]
    init_supervisor(creator_did);

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
/// All reads are lock-free (`DashMap`) or brief (`RwLock` on transport
/// state). Known contexts and transport status are read from the
/// `BridgeInstance` (returns 0/false if the bridge is not initialized).
#[must_use]
pub fn registry_stats() -> RegistryStats {
    let (known_count, relay_connected) = bridge_instance().map_or((0, false), |bi| {
        (bi.core.known_context_count(), bi.core.has_transport())
    });
    RegistryStats {
        contexts: ffi_state_registry().len(),
        known_contexts: known_count,
        identities: identity_registry().len(),
        relay_connected,
    }
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

// Economy state is now owned by BridgeInstance. Callers access it via
// `bridge_instance()?.with_economy_budget(...)` etc. directly.

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
        init_supervisor_for_test();
        let ctx_id = unique_ctx_id("stats-ctx");
        let creator = "did:dht:z6MkStatsTest";

        register_context(&ctx_id, creator, &[]).unwrap();
        let stats = registry_stats();

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
        init_supervisor_for_test();
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
        let stats = registry_stats();

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
        // Ensure bridge is initialized so known_contexts DashMap exists.
        init_supervisor_for_test();
        let bi = bridge_instance().unwrap();

        let ctx_id = unique_ctx_id("stats-known");
        let known = KnownContext {
            routing_id: [0xCC; 32],
            relay_url: None,
            member_did: "did:dht:z6MkStatsKnown".to_owned(),
            last_seen: 0,
        };

        register_known_context(&ctx_id, known);
        let stats = registry_stats();

        assert!(
            stats.known_contexts >= 1,
            "should have at least 1 known context after registration (got {})",
            stats.known_contexts,
        );
        assert!(
            bi.core.has_known_context(&ctx_id),
            "registered known context should be in BridgeInstance"
        );

        // remove_ffi_state clears both registries (FFI state + known contexts).
        // Register FFI state first so remove_ffi_state has something to remove.
        let _ = register_ffi_state(&ctx_id, "did:dht:z6MkStatsKnown", &[]);
        remove_ffi_state(&ctx_id);
        assert!(
            !bi.core.has_known_context(&ctx_id),
            "removed known context should not be in BridgeInstance"
        );
    }

    #[test]
    #[cfg(feature = "allow_in_memory_custody")]
    fn remove_identity_if_present_returns_true_when_found() {
        init_supervisor_for_test();
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
        init_supervisor_for_test();
        assert!(!remove_identity_if_present("did:dht:z6MkNotPresent9999"));
    }

    #[test]
    fn registry_stats_returns_all_fields() {
        init_supervisor_for_test();
        // Verifies the struct shape and that registry_stats() doesn't panic.
        let stats = registry_stats();
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
    fn supervisor_initializes_once() {
        init_supervisor_for_test();
        let sup1 = supervisor().unwrap();
        init_supervisor_for_test();
        let sup2 = supervisor().unwrap();
        // Same Arc (same pointer).
        assert!(Arc::ptr_eq(sup1, sup2));
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
    /// when stored in `FfiBridgeState.ceiling_strings`. Without this
    /// conversion, `mint_ucan` ceiling checks fail because the minted
    /// capability name (underscore format) doesn't match the stored
    /// raw string.
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

    // -----------------------------------------------------------------------
    // BridgeInstance tests (#1549)
    // -----------------------------------------------------------------------

    #[test]
    fn bridge_instance_populated_by_init_supervisor() {
        // init_supervisor_for_test populates DEFAULT_BRIDGE_INSTANCE which
        // owns the per-instance Supervisor. Since OnceLock is process-global,
        // the first call in any test wins — subsequent calls are no-ops. We
        // rely on this being called (possibly by other tests) before
        // asserting.
        init_supervisor_for_test();

        let sup = supervisor().expect("supervisor should be initialized");
        let bi = bridge_instance().expect("bridge_instance should be initialized");

        // Both should point to the same Supervisor allocation.
        assert!(
            Arc::ptr_eq(sup, bi.core.try_supervisor().unwrap()),
            "bridge_instance().try_supervisor() must be the same Arc as supervisor()"
        );
    }

    #[test]
    fn bridge_instance_not_shutdown_initially() {
        init_supervisor_for_test();

        let bi = bridge_instance().expect("bridge_instance should be initialized");
        assert!(
            !bi.core.is_shutdown(),
            "bridge_instance should not be shutdown immediately after init"
        );
    }

    #[test]
    fn shutdown_hook_runs_with_external_state() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        // Build an isolated CoreFields (not the global default PyBridgeInstance)
        // to avoid interfering with the OnceLock-based singleton used by other
        // tests. `CoreFields` is imported at module top via `use
        // scp_ffi_common::bridge_instance::CoreFields`.
        let persistence = build_persistence_provider();
        let supervisor_arc = build_supervisor(
            Arc::new(MlsCryptoProvider::new(
                "did:test:pyo3-bridge-test".to_owned(),
            )),
            Box::new(scp_core::context::LocalTransportProvider),
            Box::new(NoOpEventLogProvider),
            persistence,
        );
        let bi = CoreFields::with_supervisor(supervisor_arc);

        let ran = Arc::new(AtomicBool::new(false));
        let ran2 = Arc::clone(&ran);

        bi.register_shutdown_hook(Box::new(move || {
            ran2.store(true, Ordering::SeqCst);
        }));

        assert!(
            !ran.load(Ordering::SeqCst),
            "hook must not fire before shutdown"
        );
        bi.shutdown();
        assert!(
            ran.load(Ordering::SeqCst),
            "shutdown hook must execute during CoreFields::shutdown()"
        );
    }

    // -----------------------------------------------------------------------
    // PyBridgeInstance tests (#1549 Phase 4 PR 1)
    // -----------------------------------------------------------------------

    #[test]
    fn test_py_bridge_instance_typed_identity_registry_roundtrip() {
        // Verify that the typed identity_registry field is wired correctly:
        // inserting an entry through the field is observable via the same
        // Arc<DashMap> from both sides.
        let bi = PyBridgeInstance::new_py();
        assert!(bi.identity_registry().is_empty());
        bi.identity_registry().insert(
            "did:dht:z6MkTest".to_owned(),
            IdentityEntry {
                identity: ScpIdentity {
                    did: "did:dht:z6MkTest".to_owned(),
                    identity_key: scp_platform::KeyHandle::new(0),
                    active_signing_key: scp_platform::KeyHandle::new(0),
                    agent_signing_key: None,
                    pre_rotation_commitment: [0u8; 32],
                },
                custody: Arc::new(crate::custody::FfiKeyCustody::InMemory(
                    scp_platform::testing::InMemoryKeyCustody::new(),
                )),
                document: DidDocument {
                    context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
                    id: "did:dht:z6MkTest".to_owned(),
                    verification_method: vec![],
                    authentication: vec![],
                    assertion_method: vec![],
                    also_known_as: vec![],
                    service: vec![],
                },
                identity_link_attestations: Vec::new(),
            },
        );
        assert_eq!(bi.identity_registry().len(), 1);
        assert!(bi.identity_registry().contains_key("did:dht:z6MkTest"));
    }

    #[test]
    fn test_py_bridge_instance_unique_ids() {
        // Every new instance must get a fresh monotonic instance_id.
        let a = PyBridgeInstance::new_py();
        let b = PyBridgeInstance::new_py();
        assert_ne!(
            a.core.instance_id(),
            b.core.instance_id(),
            "consecutive PyBridgeInstance instances must receive distinct instance ids"
        );
        // Handle from b rejected by a.
        assert!(
            a.core.check_handle(b.core.instance_id()).is_err(),
            "handle from instance b must be rejected by instance a"
        );
        assert!(a.core.check_handle(a.core.instance_id()).is_ok());
    }

    #[test]
    fn test_default_instance_is_same_arc() {
        // Two calls to default_bridge_instance() must return the same Arc.
        let a = default_bridge_instance().expect("default instance");
        let b = default_bridge_instance().expect("default instance");
        assert!(
            Arc::ptr_eq(&a, &b),
            "default_bridge_instance must return the same Arc on repeated calls"
        );
    }

    #[test]
    fn test_py_bridge_instance_with_storage_py_initializes_storage() {
        let bi = PyBridgeInstance::with_storage_py(StorageConfig::InMemory);
        assert!(
            bi.storage_provider().is_some(),
            "with_storage_py(InMemory) must initialize the storage provider"
        );
    }
}
