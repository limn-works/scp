//! Global runtime registry mapping context IDs to live `scp-core` objects.
//!
//! The FFI bridge functions accept `context_id: &str` parameters but need
//! access to both the shared [`ContextManager`] (for lifecycle, membership,
//! governance, and messaging operations) and per-context FFI-specific state
//! (outlet registries, event logs, UCAN state, message channels).
//!
//! # Architecture (post-#386 rewrite)
//!
//! Context lifecycle is delegated to a shared [`ContextManager`] which holds
//! the canonical membership, role, governance, broadcast, and TTL state.
//! Per-context FFI-specific state (outlet registries, event logs, UCAN
//! revocation/nonce tracking, outlet handlers, message channels) lives in
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
//! The NAPI (`Node.js`) and `UniFFI` (Swift/Kotlin) bridges avoid this
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
use scp_core::context::builder::{ContextEventLogProvider, ContextTransportProvider};
use scp_core::context::outlets::OutletRegistry;
use scp_core::context::persistence::ContextPersistence;
use scp_core::context::providers::{
    MerkleEventLogProvider, ProtocolRepositoryContextBridge, ProtocolRepositoryEventLogBridge,
};
use scp_core::context::roles::ContextRoleState;
use scp_core::crypto::mls::provider::NodeMlsFactory;
use scp_core::crypto::ucan::nonce::NonceTracker;
use scp_core::crypto::ucan::revoke::RevocationList;
use scp_core::store::ProtocolRepository;
use scp_event_log::EventLog;
use scp_ffi_common::bridge_instance::BridgeInstanceCore;
use scp_ffi_common::credentials::FfiCredentialStore;
// Re-export `CoreFields` at `crate::runtime::CoreFields` so the
// `pyscp_check_handle!` macro can refer to it as
// `$crate::runtime::CoreFields`.
use scp_clock::{Clock, SystemClock};
use scp_did::DidDocument;
pub use scp_ffi_common::bridge_instance::CoreFields;
use scp_identity::ScpIdentity;
use scp_platform::PlatformError;
use scp_platform::encrypting_adapter::EncryptingAdapter;
use scp_platform::in_memory::InMemoryStorage;
use scp_platform::sqlite::SqliteStorage;
use scp_platform::traits::Storage;
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
/// The caller passes a [`CoreFields`] reference as the first argument (typically
/// `&self.inner.core` on a `PyScp` method, or `&bi.core` where `bi` is a
/// `&PyBridgeInstance` already in scope). The macro then checks that each
/// supplied `$handle.instance_id` matches the core's `instance_id`. On
/// mismatch, returns a [`ScpPyError::UcanError`] with code
/// [`scp_ffi_common::error_codes::PERM_3030`] (mapped via the
/// [`From<HandleAffinityError>`](scp_ffi_common::bridge_instance::HandleAffinityError)
/// conversion).
///
/// Sub-slice A of #1549 Phase 4 PR 4 reintroduced the explicit `$core`
/// parameter so per-`PyBridgeInstance` call paths can flow their own core
/// through without routing via the process-global default. Sub-slices B-E
/// update every call site.
///
/// The affinity check is never blocked by transient lifecycle state
/// (e.g., a suspended bridge) because it is a pure `u64` comparison that
/// does not touch transport or `ContextManager` state.
///
/// # Example
///
/// ```ignore
/// #[pyfunction]
/// pub fn example(scp: &PyScp, handle: &SomeHandle) -> PyResult<()> {
///     pyscp_check_handle!(&scp.inner.core, handle);
///     // ... real work ...
///     Ok(())
/// }
/// ```
#[macro_export]
macro_rules! pyscp_check_handle {
    ($core:expr, $($handle:expr),+ $(,)?) => {{
        let __core: &$crate::runtime::CoreFields = $core;
        $(
            __core
                .check_handle($handle.instance_id)
                .map_err($crate::error::ScpPyError::from)?;
        )+
    }};
}

/// A sync outlet handler function that takes JSON input and returns JSON output.
///
/// Stored in the FFI bridge state when Python callers register outlet handlers
/// via [`register_outlet_handler`]. The FFI bridge dispatches outlet invocations
/// through these handlers instead of echoing validated input.
///
/// See SCP-212 and ADR-010 for the handler registration design.
pub type OutletHandler =
    Arc<dyn Fn(serde_json::Value) -> Result<serde_json::Value, String> + Send + Sync>;

// ---------------------------------------------------------------------------
// ContextManager (shared, process-global)
// ---------------------------------------------------------------------------

/// Returns a reference to the shared [`ContextManager`] from the given
/// bridge instance.
///
/// Delegates to [`PyBridgeInstance::core`] → [`CoreFields::try_context_manager`].
///
/// # Errors
///
/// Returns `ScpPyError::ContextError` if the `ContextManager` has not been
/// attached to the instance yet (i.e., `init_context_manager` has not been
/// called), or if the bridge is currently suspended.
pub fn supervisor(
    bi: &PyBridgeInstance,
) -> Result<&Arc<scp_core::context::supervisor::Supervisor>, ScpPyError> {
    // Suspended: return error (recoverable — caller should call resume()).
    // AlreadyShutDown: warn only. Shutdown already destroyed MLS groups,
    // cleared registries, and disconnected transport — operations will fail
    // naturally. Returning an error breaks test suites that call shutdown
    // before exit, since OnceLock cannot be re-initialized.
    if bi.core.is_suspended() {
        return Err(ScpPyError::context(
            "bridge is suspended — call resume() before performing operations".to_owned(),
        ));
    }
    if bi.core.is_shutdown() {
        tracing::warn!("context_manager() called after shutdown — operations may fail");
    }
    bi.core.try_supervisor().ok_or_else(|| {
        ScpPyError::context(
            "ContextManager not yet attached — call py_context_create, \
             py_context_join, py_context_import, or init_context_manager first"
                .to_owned(),
        )
    })
}

// ---------------------------------------------------------------------------
// PyBridgeInstance (per-bridge concrete struct wrapping CoreFields — #1549 Phase 4)
// ---------------------------------------------------------------------------

/// `SQLCipher` key-material selector for [`StorageConfig::Sqlite`] (spec §17.6).
///
/// The caller supplies EITHER raw key material OR a passphrase — never both,
/// never neither. The sum type makes that mutual exclusion unrepresentable as
/// an invalid state: there is exactly one happy path per variant. Both forms
/// are wrapped in [`Zeroizing`] so they are wiped from memory on drop. This
/// mirrors the `NAPI` and `UniFFI` bridges' `SqliteKeyMaterial`.
///
/// - [`SqliteKeyMaterial::Raw`] feeds [`SqliteStorage::new`] directly (raw-key
///   mode; the existing, unchanged path).
/// - [`SqliteKeyMaterial::Passphrase`] feeds
///   [`SqliteStorage::with_passphrase`], which derives the `SQLCipher` PRAGMA
///   key from the passphrase via the shared Argon2id parameterization with a
///   persisted per-database salt sidecar.
///
/// Does NOT derive `Debug`: a custom redacting [`std::fmt::Debug`] impl keeps
/// the key/passphrase bytes out of logs and panic messages (defense in depth).
#[derive(Clone)]
pub enum SqliteKeyMaterial {
    /// Raw encryption key material (32 bytes recommended).
    Raw(Zeroizing<Vec<u8>>),
    /// Human-chosen passphrase; the `SQLCipher` key is derived via Argon2id.
    Passphrase(Zeroizing<String>),
}

impl std::fmt::Debug for SqliteKeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the key or passphrase bytes — only the variant and a
        // length hint for the raw case. Mirrors the NAPI/UniFFI redacting impl.
        match self {
            Self::Raw(bytes) => {
                write!(
                    f,
                    "SqliteKeyMaterial::Raw(<redacted {} bytes>)",
                    bytes.len()
                )
            }
            Self::Passphrase(_) => write!(f, "SqliteKeyMaterial::Passphrase(<redacted>)"),
        }
    }
}

/// Storage configuration selector for [`PyBridgeInstance::with_storage_py`].
///
/// Two variants are supported:
/// - [`StorageConfig::InMemory`] — encrypted in-memory storage (ephemeral).
/// - [`StorageConfig::Sqlite`] — persistent SQLCipher-encrypted storage on
///   disk. The key material is a [`SqliteKeyMaterial`]: EITHER raw key bytes
///   (`key`) OR a passphrase (`passphrase`), each held in [`Zeroizing`] so it
///   is wiped from memory as soon as the config is consumed.
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
    /// process restarts. The `key` selects raw-key vs. passphrase derivation
    /// via [`SqliteKeyMaterial`]; both forms are wrapped in [`Zeroizing`] so
    /// the caller's copy is wiped after construction.
    Sqlite {
        /// Directory the database file is created in.
        path: PathBuf,
        /// Raw key material or passphrase (exactly one — see
        /// [`SqliteKeyMaterial`]).
        key: SqliteKeyMaterial,
    },
}

/// Bridge-internal error returned by [`PyBridgeInstance::with_storage_py`]
/// when a persistence backend cannot be initialized.
///
/// Converted to [`ScpPyError`] at the `PyScp::with_storage` factory surface.
/// Kept as a dedicated enum so the `runtime` layer does not depend on the
/// bridge error vocabulary and so new backends (e.g. encrypted filesystem)
/// can extend the enum without touching every caller.
#[derive(Debug)]
pub enum StorageInitError {
    /// `SqliteStorage::new` failed — directory permission denied, key
    /// mismatch on an existing DB, `SQLCipher` init error, and so on.
    SqliteOpen {
        /// The directory path the caller asked for (for the error message).
        path: String,
        /// The underlying `scp-platform` error rendered via `Display`.
        message: String,
    },
}

impl std::fmt::Display for StorageInitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SqliteOpen { path, message } => {
                write!(f, "failed to open SQLCipher storage at {path}: {message}")
            }
        }
    }
}

impl std::error::Error for StorageInitError {}

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
/// construct the concrete `ProtocolRepository<S>` directly (see the
/// `build_persistence_provider` helper in this module).
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

    /// Releases any persistent resources held by the variant.
    ///
    /// For [`StorageProvider::Sqlite`] this delegates to
    /// [`SqliteStorage::close`] to release the advisory lock on
    /// `scp.db.lock` even when outer `Arc<SqliteStorage>` references
    /// remain alive. [`StorageProvider::InMemoryEncrypted`] has no
    /// persistent resources and the call is a no-op.
    ///
    /// Called from `bridge_specific_shutdown` on the `PyO3` bridge so
    /// that `SCP.shutdown()` on a `StorageConfig::Sqlite` instance
    /// releases the lock at the SDK surface.
    pub fn close(&self) {
        match self {
            Self::InMemoryEncrypted(_) => {}
            Self::Sqlite(storage) => storage.close(),
        }
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
    /// `OnceLock` because it is set once at construction via
    /// [`PyBridgeInstance::with_storage_py`] (driven from Python by
    /// `SCP.with_storage({...})`). Typed (not `dyn`) because the `Storage`
    /// trait is not dyn-compatible (RPITIT).
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

    /// Most recently connected relay URL (replaces `CONNECTED_RELAY_URL` in
    /// `transport.rs`).
    ///
    /// Migrated from a process-global `OnceLock<RwLock<Option<String>>>`
    /// singleton in commit 8. Distinct from `CoreFields::pending_relay_url`:
    /// that tracks the pending URL saved for resume; this tracks the URL
    /// currently bound to an active `TransportManager`.
    pub(crate) connected_relay_url: RwLock<Option<String>>,

    /// Per-instance active outlet-stream registry (§5.4.5, SCP-OUT-037).
    ///
    /// Maps a `StreamHandleId` (the stream's `request_id` as lowercase hex)
    /// to the live [`StreamEntry`](crate::outlet_stream::StreamEntry) that
    /// owns the returned `StreamSessionHandle` (control plane) and its
    /// detached chunk receiver (data plane), plus the `invoker_did` pinned
    /// at open. Per-INSTANCE (not a process-global) so handle-affinity and
    /// no-bridge-globals hold: a stream opened on one bridge instance is
    /// invisible to another, and instance shutdown drops every live stream
    /// with the `Arc`. Entries are evicted when `poll_next` observes the
    /// terminal (channel-closed) sentinel.
    pub(crate) outlet_stream_registry: Arc<DashMap<String, crate::outlet_stream::StreamEntry>>,

    /// Per-instance active cross-context streaming-saga registry (§5.4.5,
    /// SCP-OUT-047).
    ///
    /// Maps a saga id (the durable `SagaId` string minted at the
    /// Commit-transition) to the live
    /// [`StreamingSagaEntry`](scp_ffi_common::streaming_saga::StreamingSagaEntry)
    /// that owns A's plaintext operator-signed chunk receiver (handed out
    /// PROMPTLY at Commit, AC1) plus the pinned target-context id / invoker DID /
    /// `request_id` a truncated-close recovery keys on. Per-INSTANCE (not a
    /// process-global) so handle-affinity and no-bridge-globals hold — a saga
    /// opened on one bridge instance is invisible to another, and instance
    /// shutdown drops every live saga stream with the `Arc`. Entries are evicted
    /// when `poll_next` observes the terminal (channel-closed) sentinel. DISTINCT
    /// from `outlet_stream_registry` (same-context streams) so the two surfaces
    /// never collide on a handle id.
    pub(crate) outlet_streaming_saga_registry:
        Arc<DashMap<String, scp_ffi_common::streaming_saga::StreamingSagaEntry>>,

    /// Shared full-stack test network (replaces `NETWORK` in `testing.rs`).
    ///
    /// Migrated from a process-global
    /// `std::sync::Mutex<Option<FullStackNetwork>>` singleton in commit 9.
    /// Feature-gated behind `testing` to mirror `testing.rs`
    /// which is only compiled with that feature.
    #[cfg(feature = "testing")]
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
            connected_relay_url: RwLock::new(None),
            outlet_stream_registry: Arc::new(DashMap::new()),
            outlet_streaming_saga_registry: Arc::new(DashMap::new()),
            #[cfg(feature = "testing")]
            network: std::sync::Mutex::new(None),
        }
    }

    /// Constructs a `PyBridgeInstance` with explicit in-memory storage, for
    /// Rust-side tests only.
    ///
    /// Equivalent to `with_storage_py(StorageConfig::InMemory)` but
    /// infallible: in-memory construction performs no I/O and cannot fail,
    /// so this returns `Self` directly without a `Result`. This is the
    /// dev/test in-memory selection (spec §17.6), NOT a silent default —
    /// the public `SCP(config)` constructor still requires an explicit
    /// storage dict.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn new_in_memory_for_test() -> Self {
        let instance = Self::new_py();
        // OnceLock: first set wins. `new_py()` leaves this unset, so this set
        // always succeeds.
        let _ = instance
            .storage_provider
            .set(StorageProvider::new_in_memory_encrypted());
        instance
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
            connected_relay_url: RwLock::new(None),
            outlet_stream_registry: Arc::new(DashMap::new()),
            outlet_streaming_saga_registry: Arc::new(DashMap::new()),
            #[cfg(feature = "testing")]
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
    ///   `SqliteStorage::new` calls). If opening fails, the
    ///   [`StorageInitError::SqliteOpen`] error is returned to the caller
    ///   (and logged via `tracing::error!`) — no half-constructed bridge
    ///   is exposed.
    ///
    /// # Errors
    ///
    /// Returns [`StorageInitError::SqliteOpen`] if `SqliteStorage::new`
    /// fails (bad key, permission denied, corrupt file, schema mismatch).
    pub fn with_storage_py(cfg: StorageConfig) -> Result<Self, StorageInitError> {
        match cfg {
            StorageConfig::InMemory => {
                let instance = Self::new_py();
                // OnceLock: first set wins. `new_py()` leaves this unset, so
                // this set always succeeds.
                let _ = instance
                    .storage_provider
                    .set(StorageProvider::new_in_memory_encrypted());
                Ok(instance)
            }
            StorageConfig::Sqlite { path, key } => {
                // Open the database once — `SqliteStorage` owns a single
                // `rusqlite::Connection` that every downstream consumer
                // (storage_provider + persistence) must share. An earlier
                // draft called `SqliteStorage::new` twice (once for the
                // provider, once for the persistence bridge) and hit
                // `SQLITE_BUSY` the moment both tried to write.
                //
                // Raw-key mode feeds `SqliteStorage::new`; passphrase mode feeds
                // `SqliteStorage::with_passphrase` (Argon2id key derivation with
                // a persisted per-database salt sidecar). Both share the same
                // single-open / shared-`Arc` / fail-closed contract below.
                let open_result = match &key {
                    SqliteKeyMaterial::Raw(bytes) => SqliteStorage::new(&path, bytes),
                    SqliteKeyMaterial::Passphrase(pass) => {
                        SqliteStorage::with_passphrase(&path, pass.as_bytes())
                    }
                };
                let storage = open_result.map_err(|e| {
                    // FAIL CLOSED (spec §17.6): surface the error rather than
                    // degrading to in-memory. No silent fallback. The error
                    // message never carries key or passphrase bytes.
                    tracing::error!(
                        error = %e,
                        path = %path.display(),
                        "with_storage_py: SQLCipher open failed — returning error to caller, no in-memory fallback"
                    );
                    StorageInitError::SqliteOpen {
                        path: path.display().to_string(),
                        message: e.to_string(),
                    }
                })?;
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
                    connected_relay_url: RwLock::new(None),
                    outlet_stream_registry: Arc::new(DashMap::new()),
                    outlet_streaming_saga_registry: Arc::new(DashMap::new()),
                    #[cfg(feature = "testing")]
                    network: std::sync::Mutex::new(None),
                };
                let _ = instance
                    .storage_provider
                    .set(StorageProvider::Sqlite(arc_storage));
                // `key` is a `SqliteKeyMaterial` wrapping `Zeroizing` raw
                // bytes or passphrase, zeroed on drop here. SQLCipher has
                // already retained its derived key internally, so the caller's
                // key material is safe to wipe at this point.
                drop(key);
                Ok(instance)
            }
        }
    }

    /// Returns a reference to the identity registry.
    #[must_use]
    pub const fn identity_registry(&self) -> &Arc<DashMap<String, IdentityEntry>> {
        &self.identity_registry
    }

    /// Returns a reference to the attached [`ContextManager`], if any.
    ///
    /// Convenience accessor that delegates to
    /// [`CoreFields::try_context_manager`]. Returns `None` until
    /// `init_context_manager` (or one of its variants) has been called.
    #[must_use]
    pub fn try_supervisor(&self) -> Option<&Arc<scp_core::context::supervisor::Supervisor>> {
        self.core.try_supervisor()
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

    /// Selects this instance's **durable** bridge credential store from the
    /// chosen storage backend, or `None` if storage has not yet been selected.
    ///
    /// The credential store is derived on demand from the SAME per-instance
    /// [`StorageProvider`] the supervisor's `mls_storage` / saga journal derive
    /// from (spec §17.6) — so a `Sqlite` selection persists bridge tokens across
    /// restart and an encrypted-in-memory selection keeps them encrypted at
    /// rest. Because `StorageProvider` is not itself `EncryptedStorage` (the
    /// sealed marker lives in `scp-platform`), the concrete inner
    /// `EncryptedStorage` handle is dispatched per variant, exactly as
    /// `build_persistence_provider` does for `ProtocolRepository`.
    ///
    /// Returns `None` only in the storage-before-selection window; production
    /// `PyScp` construction always goes through
    /// [`PyBridgeInstance::with_storage_py`], which selects storage first. The
    /// caller ([`crate::bridge_connector`]) maps `None` to a fail-closed error
    /// emitted as `SCP-CTX-2105` (`codes::CTX_2105`) — never a silent in-memory
    /// fallback. This satisfies requirement SCP-CAPSEL-8001 (spec §17.17.1,
    /// "selection fails closed"); note SCP-CAPSEL-8001 is a classification
    /// requirement, not the emitted error code. There is no in-memory arm on
    /// this shipped path (ADR-062 §Decision 5, SCP-CAPINJECT-009).
    #[must_use]
    pub fn credential_store(&self) -> Option<FfiCredentialStore> {
        match self.storage_provider()? {
            StorageProvider::InMemoryEncrypted(handle) => {
                Some(FfiCredentialStore::durable_from_handle(Arc::clone(handle)))
            }
            StorageProvider::Sqlite(handle) => {
                Some(FfiCredentialStore::durable_from_handle(Arc::clone(handle)))
            }
        }
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
    #[cfg(feature = "testing")]
    #[must_use]
    pub const fn network(
        &self,
    ) -> &std::sync::Mutex<Option<scp_testing::fullstack::FullStackNetwork>> {
        &self.network
    }
}

#[async_trait::async_trait]
impl BridgeInstanceCore for PyBridgeInstance {
    fn core(&self) -> &CoreFields {
        &self.core
    }

    fn bridge_specific_shutdown(&self) {
        // Clear the identity registry so held `Arc<FfiKeyCustody>` entries
        // drop, triggering `Zeroizing` on key material.
        self.identity_registry.clear();
        // `storage_provider` is `OnceLock` — we cannot clear the slot, but
        // the `Sqlite` variant holds an advisory lock on
        // `{dir}/scp.db.lock` that must be released at shutdown so
        // `SCP(storage=...)` against the same path succeeds after a prior
        // `SCP.shutdown()`. `StorageProvider::close()` delegates to
        // `SqliteStorage::close()` which drops the `File` inside the
        // lock-file mutex without dropping the `Arc<SqliteStorage>`
        // (other Arc holders — `CoreFields::persistence`,
        // `ContextManager::persistence` — keep the storage struct alive
        // until the `PyBridgeInstance` itself drops). The
        // `InMemoryEncrypted` variant's `close()` is a no-op.
        if let Some(provider) = self.storage_provider.get() {
            provider.close();
        }
        // Clear the typed per-context FFI state registry so per-context
        // `OutletRegistry`, `EventLog`, receive channel senders, and
        // registered outlet handlers drop.
        self.ffi_bridge_state.clear();
        // Clear MCP registries so server shutdown senders and client
        // connections drop, allowing background tasks to terminate cleanly.
        self.mcp_server_registry.clear();
        self.mcp_client_registry.clear();
        // Clear the outlet-stream registry so every live stream's
        // `StreamSessionHandle` (and its detached chunk receiver) drops —
        // dropping the receiver closes the channel and lets the off-mailbox
        // pump observe the close and settle out during instance shutdown.
        self.outlet_stream_registry.clear();
        // Clear the cross-context streaming-saga registry so every live saga
        // stream's chunk receiver drops — dropping the receiver closes the
        // channel and lets the off-mailbox seal task observe the close and
        // settle out during instance shutdown (SCP-OUT-047).
        self.outlet_streaming_saga_registry.clear();
        // Reset lifecycle-owned typed slots so their held URLs / networks
        // do not survive past shutdown. Best-effort: on lock poisoning
        // we swallow the error and leave the slot alone — a poisoned
        // lock means another thread panicked while holding it, and the
        // caller already has bigger problems than a stale `None`
        // inconsistency.
        if let Ok(mut slot) = self.connected_relay_url.write() {
            *slot = None;
        }
        #[cfg(feature = "testing")]
        if let Ok(mut net) = self.network.lock() {
            *net = None;
        }
    }
}

/// Emergency cancellation for `PyBridgeInstance` dropped without a prior
/// `shutdown(timeout)`.
///
/// The graceful path is `BridgeInstanceCore::shutdown(timeout)` — callers
/// that want deterministic cleanup of subscriptions, timers, and relay
/// connections must still invoke that. This `Drop` is the safety net for
/// the case where a caller constructs a `PyBridgeInstance` (typically via
/// `PyScp`), spawns background work under its `CancellationToken` +
/// `JoinSet`, and then drops the whole thing without awaiting shutdown.
/// Without this impl, those tasks hold `Arc<PyBridgeInstance>` captures
/// and live forever — leaking a `ContextManager`, relay connection, and
/// any attached Python callbacks.
///
/// See ADR-048 for the multi-instance lifecycle contract.
impl Drop for PyBridgeInstance {
    fn drop(&mut self) {
        self.core.emergency_cancel_tasks();
    }
}

// Phase D (#1695): DEFAULT_BRIDGE_INSTANCE static and default-lookup helpers
// (`default_bridge_instance`, `bridge_instance`, `bridge_instance_raw`,
// `bridge_instance_for_affinity`, `ensure_bridge_instance`) have been
// deleted. All FFI entry points must route through an explicit
// `&PyBridgeInstance` — typically `&*self.inner` inside a `#[pymethods]
// impl PyScp` block. Tests construct fresh `PyBridgeInstance::new_py()`
// instances directly.

// ---------------------------------------------------------------------------
// ContextManager initialization
// ---------------------------------------------------------------------------

/// Initializes the global [`ContextManager`] with production providers.
///
/// Uses `NodeMlsFactory` (real OpenMLS-backed encryption, sender keys, and
/// group management — ported from NAPI bridge #1305, closes #1324),
/// `NotConfiguredTransportProvider` (returns descriptive errors until transport
/// is configured via `transport_connect`), and the persistent
/// `MerkleEventLogProvider` from [`build_event_log_provider`] (sharing the
/// bridge instance's single storage backend), so the supervisor's own
/// convergent event log is readable by `Supervisor::participation_record`
/// (§7.3.2) and the other supervisor log queries — not a no-op.
///
/// The `local_did` is passed to `NodeMlsFactory::new` which uses it as
/// the MLS credential identity for group operations and sender key generation.
///
/// The key resolver rejects all lookups with an error rather than silently
/// returning `None`, ensuring governance vote signature verification failures
/// are visible rather than silently skipped.
///
/// When the `BridgeInstance` was constructed via
/// [`PyBridgeInstance::with_storage_py`] (driven from Python by
/// `SCP.with_storage({...})`), a [`ProtocolRepositoryContextBridge`] is
/// constructed from the attached storage provider and injected into the
/// `ContextManager`. This enables context state persistence across process
/// restarts without requiring callers to manually wire persistence.
/// See issue #329.
///
/// The `local_did` is consumed only by `NodeMlsFactory::new` — the
/// `BridgeInstance` itself carries no DID (spec §12.2.3).
///
/// Subsequent calls are no-ops (`OnceLock` guarantees single initialization).
/// If the manager is already initialized with a different DID, a warning is logged.
pub fn init_context_manager(bi: &PyBridgeInstance, local_did: &str) {
    if bi.core.has_supervisor() {
        tracing::debug!(
            requested_did = %local_did,
            "init_context_manager: ContextManager already attached — using existing instance"
        );
        return;
    }

    let did = local_did.to_owned();
    let crypto = Arc::new(scp_core::crypto::mls::provider::NodeMlsFactory::new(
        did,
        std::sync::Arc::new(scp_clock::SystemClock),
    ));
    let persistence = build_persistence_provider(bi);
    let supervisor_arc = match build_supervisor(
        bi,
        crypto,
        Box::new(NotConfiguredTransportProvider),
        build_event_log_provider(bi),
        persistence,
    ) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "init_context_manager: build_supervisor failed");
            return;
        }
    };

    bi.core.set_supervisor(supervisor_arc);
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
    bi: &PyBridgeInstance,
    _local_did: &str,
    crypto: Arc<NodeMlsFactory>,
    transport: Box<dyn ContextTransportProvider>,
    event_log: Box<dyn ContextEventLogProvider>,
    persistence: Option<Box<dyn ContextPersistence>>,
) {
    // `_local_did` is retained in the signature for API stability: callers
    // construct `crypto` with the DID before calling into this function
    // (it is the `NodeMlsFactory` that carries the DID; see spec §12.2.3).
    if bi.core.has_supervisor() {
        return;
    }
    let persistence = persistence.or_else(|| build_persistence_provider(bi));
    let supervisor_arc = match build_supervisor(bi, crypto, transport, event_log, persistence) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "init_context_manager_with: build_supervisor failed");
            return;
        }
    };
    bi.core.set_supervisor(supervisor_arc);
}

/// Initializes the given bridge instance's [`ContextManager`] with a
/// `LocalTransportProvider`.
///
/// Identical to [`init_context_manager`] except the transport provider is
/// `LocalTransportProvider` (silently succeeds on all send/publish calls)
/// instead of `NotConfiguredTransportProvider` (rejects everything). Like
/// production initialization, it installs a real `NodeMlsFactory` bound to
/// `local_did` so encryption is exercised end to end against an in-process
/// loopback transport.
///
/// **Must be called before any `context_create` / `context_join` /
/// `context_import`** — those functions call `init_context_manager` which wins
/// the `OnceLock` race if called first.
///
/// Exposed to Python via `PyScp::configure_local_transport` so that E2E tests
/// can exercise `context_send` and `broadcast_publish` without a real relay
/// server.
///
/// No-op if the bridge already has a `ContextManager` attached.
pub fn init_context_manager_with_local_transport(bi: &PyBridgeInstance, local_did: &str) {
    if bi.core.has_supervisor() {
        tracing::warn!(
            requested_did = %local_did,
            "init_context_manager_with_local_transport: ContextManager already attached — ignoring"
        );
        return;
    }
    // The supervisor's `mls_storage` consumer requires a single Storage
    // handle (storage-before-supervisor precondition, spec §17.6). Test
    // instances built via `new_py()` carry no storage, so the bridge layer
    // makes the explicit in-memory dev-affordance selection here when none
    // was set. The runtime core itself never defaults storage — this is a
    // bridge-layer choice. A no-op if a provider is already set (`OnceLock`).
    if bi.storage_provider().is_none() {
        let _ = bi
            .storage_provider
            .set(StorageProvider::new_in_memory_encrypted());
    }
    let did = local_did.to_owned();
    let crypto = Arc::new(scp_core::crypto::mls::provider::NodeMlsFactory::new(
        did,
        std::sync::Arc::new(scp_clock::SystemClock),
    ));
    let persistence = build_persistence_provider(bi);
    let supervisor_arc = match build_supervisor(
        bi,
        crypto,
        Box::new(scp_core::context::LocalTransportProvider),
        build_event_log_provider(bi),
        persistence,
    ) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "init_context_manager_with_local_transport: build_supervisor failed");
            return;
        }
    };

    bi.core.set_supervisor(supervisor_arc);
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
pub fn init_context_manager_for_test(bi: &PyBridgeInstance) {
    if bi.core.has_supervisor() {
        return;
    }
    // The supervisor's `mls_storage` consumer requires a single Storage
    // handle (storage-before-supervisor precondition, spec §17.6). Test
    // instances built via `new_py()` carry no storage, so the bridge layer
    // makes the explicit in-memory dev-affordance selection here when none
    // was set. The runtime core itself never defaults storage — this is a
    // bridge-layer choice. A no-op if a provider is already set (`OnceLock`).
    if bi.storage_provider().is_none() {
        let _ = bi
            .storage_provider
            .set(StorageProvider::new_in_memory_encrypted());
    }
    let crypto = Arc::new(scp_core::crypto::mls::provider::NodeMlsFactory::new(
        "did:test:pyo3-bridge-test".to_owned(),
        std::sync::Arc::new(scp_clock::SystemClock),
    ));
    let persistence = build_persistence_provider(bi);
    let supervisor_arc = match build_supervisor(
        bi,
        crypto,
        Box::new(scp_core::context::LocalTransportProvider),
        build_event_log_provider(bi),
        persistence,
    ) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "init_context_manager_for_test: build_supervisor failed");
            return;
        }
    };

    bi.core.set_supervisor(supervisor_arc);
}

/// Constructs a [`ProtocolRepositoryContextBridge`] from the bridge's storage
/// provider, if one was attached at construction time.
///
/// Returns `None` for `PyBridgeInstance` instances built via
/// [`PyBridgeInstance::new_py`] (no storage attached) — only instances
/// constructed via [`PyBridgeInstance::with_storage_py`] (driven from Python
/// by `SCP.with_storage({...})`) carry a provider. The `ContextManager` will
/// operate without persistence in the no-storage case.
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
fn build_persistence_provider(bi: &PyBridgeInstance) -> Option<Box<dyn ContextPersistence>> {
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

#[async_trait::async_trait]
impl ContextPersistence for ArcContextPersistence {
    async fn persist_context(
        &self,
        context_id: &str,
        snapshot: &scp_core::context::state::ContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.inner.persist_context(context_id, snapshot).await
    }

    async fn load_context(
        &self,
        context_id: &str,
    ) -> Result<
        Option<scp_core::context::state::ContextSnapshot>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        self.inner.load_context(context_id).await
    }

    async fn delete_context(
        &self,
        context_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.inner.delete_context(context_id).await
    }

    async fn list_persisted_contexts(
        &self,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        self.inner.list_persisted_contexts().await
    }
}

/// Constructs a persistent [`MerkleEventLogProvider`] backed by the global
/// storage provider if initialized, or a non-persistent one otherwise.
///
/// This is NOT a direct reuse of
/// `scp-ffi-common::bridge_runtime::build_event_log_provider` — that common
/// fn owns its own storage (creates a fresh
/// `scp_platform::in_memory::InMemoryStorage` + `ProtocolRepository` and
/// returns both) so the NAPI / `UniFFI` bridges can
/// keep the repository handle around for later queries. The `PyO3` bridge
/// instead reads from `DEFAULT_BRIDGE_INSTANCE.storage_provider()` so the
/// event log shares storage with every other per-context data sink
/// (identity state, protocol repository, blobs) — one backend per bridge
/// instance, switchable between `InMemoryEncrypted` and `Sqlite` at init
/// time. Collapsing the two would force the `PyO3` bridge to duplicate its
/// storage or force the common fn to grow a storage-provider parameter,
/// both of which cost more than the current 30-line duplication. See
/// `.claude/memory/feedback_dedup_bridge_validators.md` for the dedup
/// heuristic and when to break it.
///
/// The persistent provider writes event entries to encrypted in-memory
/// storage via `ProtocolRepositoryEventLogBridge`, so `ContextCreated`
/// (appended by `builder_create_context`) survives across manager calls
/// and is visible to `py_event_log_query`.
///
/// This replaced `NoOpEventLogProvider` so that the `PyO3` bridge emits the
/// same initial `ContextCreated` event as the NAPI and `UniFFI`
/// bridges (cross-bridge parity, ADR-046 `OP_EVENT_LOG_APPEND`).
pub(crate) fn build_event_log_provider(bi: &PyBridgeInstance) -> Box<dyn ContextEventLogProvider> {
    match bi.storage_provider() {
        Some(StorageProvider::InMemoryEncrypted(storage)) => {
            let protocol_repository = Arc::new(ProtocolRepository::new(Arc::clone(storage)));
            let bridge = ProtocolRepositoryEventLogBridge::new(protocol_repository);
            Box::new(MerkleEventLogProvider::with_persistence(Arc::new(bridge)))
        }
        Some(StorageProvider::Sqlite(storage)) => {
            let protocol_repository = Arc::new(ProtocolRepository::new(Arc::clone(storage)));
            let bridge = ProtocolRepositoryEventLogBridge::new(protocol_repository);
            Box::new(MerkleEventLogProvider::with_persistence(Arc::new(bridge)))
        }
        None => Box::new(MerkleEventLogProvider::new()),
    }
}

/// Constructs a fresh per-instance `Supervisor` with the given providers.
///
/// ADR-049 — the FFI bridge no longer touches `ContextManager` at all.
/// Bounded capacity of the supervisor's `ContextEvent` broadcast channel.
///
/// Every production supervisor built here enables this channel so that local
/// context events can be consumed by external sinks — notably the node's
/// outbound webhook dispatcher (spec §12.10.5), wired in
/// [`crate::server::node_start_in_memory`]/`node_start_local`. Lagging consumers
/// drop the oldest events (logged, never panics); `1024` is the documented
/// default shared across all three FFI bridges.
const EVENT_CHANNEL_CAPACITY: usize = 1024;

/// `Supervisor::with_providers` is the single entry point that constructs the
/// supervisor + populates the lifted-provider slots. The supervisor is the
/// only handle returned to the bridge layer.
///
/// The event broadcast channel is always enabled (capacity
/// [`EVENT_CHANNEL_CAPACITY`]) so downstream consumers — e.g. the node webhook
/// dispatcher — can subscribe via
/// [`Supervisor::subscribe_events`](scp_core::context::supervisor::Supervisor::subscribe_events).
/// When no consumer subscribes, emitting into the channel is a cheap no-op: the
/// retained sender has no receivers, so `send` returns `Err` and the event is
/// simply dropped without blocking context operations.
///
/// The supervisor's `mls_storage` consumer (the `OpenMLS` storage view) is
/// derived from the bridge instance's single chosen Storage:
/// `storage_provider()` is wrapped ONCE via `SpawnBlockingStorageAdapter` into
/// an `Arc<dyn OpenMlsStorageAdapter>`. This is the same `StorageProvider` that
/// backs persistence and the event log, so all three consumers share one
/// backend (spec §17.6).
///
/// # Errors
///
/// Returns a [`ScpPyError::ContextError`] if the bridge instance has no
/// storage provider set (storage-before-supervisor precondition). The runtime
/// never defaults storage; the caller (bridge layer) must supply it first.
fn build_supervisor(
    bi: &PyBridgeInstance,
    crypto: Arc<NodeMlsFactory>,
    transport: Box<dyn ContextTransportProvider>,
    event_log: Box<dyn ContextEventLogProvider>,
    persistence: Option<Box<dyn ContextPersistence>>,
) -> Result<Arc<scp_core::context::supervisor::Supervisor>, ScpPyError> {
    // Derive the durable saga journal AND the `OpenMLS` `mls_storage` view from
    // the bridge instance's SINGLE chosen `StorageProvider` (§17.6 / §17.16 /
    // ADR-049), bound into one [`DurableProviders`]. Its only non-test
    // constructor (`from_handle`) derives both halves from one handle, so a
    // caller cannot wire the journal to a different backend than `mls_storage`,
    // and the fail-closed `STORAGE_8000` storage-before-supervisor check fires
    // once for both.
    let durable = durable_providers_from_bi(bi)?;
    // Enable the event broadcast channel so `subscribe_events()` yields a
    // receiver for the node webhook dispatcher (§12.10.5). The unused receiver
    // is dropped immediately; the retained sender keeps the channel open so
    // later subscribers (wired at node startup) observe subsequent events.
    let (event_tx, _rx) = tokio::sync::broadcast::channel(EVENT_CHANNEL_CAPACITY);
    // Wire the production VM-aware governance key resolver when a DID resolver
    // is configured; otherwise fail closed with the always-`None` resolver so
    // governance vote-signature verification is never silently permissive.
    let key_resolver = bi
        .core
        .did_resolver()
        .map_or_else(not_configured_key_resolver, |r| {
            document_vm_key_resolver(std::sync::Arc::clone(r))
        });
    // Share the provider's exact hardened `Clock` Arc with the supervisor so the
    // "one hardened clock per node" invariant (see the `NodeMlsFactory::clock`
    // field doc, ADR-057 §Prereq-1) holds by construction — the supervisor does
    // not fabricate a second `SystemClock`. Read before `crypto` is moved below.
    let clock = crypto.clock();
    Ok(
        scp_core::context::supervisor::Supervisor::with_providers_and_journal(
            crypto,
            transport,
            event_log,
            key_resolver,
            persistence,
            None,
            Some(event_tx),
            Some(clock),
            durable,
        ),
    )
}

/// Builds the bridge's [`DurableProviders`] — the durable saga journal + the
/// `OpenMLS` `mls_storage` view bound into one same-backend-by-construction
/// value — from this bridge instance's single chosen [`StorageProvider`]
/// (spec §17.6 / §17.16 / ADR-049).
///
/// [`DurableProviders::from_handle`] derives BOTH halves from the one
/// `Arc<StorageProvider>` taken from `bi.storage_provider()`, so the journal,
/// the `OpenMLS` view, persistence, and the event log all read/write one
/// backend — a caller cannot wire the journal to a divergent store.
/// `StorageProvider` implements `Storage` (enum dispatch) and `Clone` (over a
/// shared inner `Arc`), so the cloned handle shares the same inner backend
/// (`Arc<EncryptingAdapter<InMemoryStorage>>` or `Arc<SqliteStorage>`).
///
/// # Errors
///
/// Returns [`ScpPyError::ContextError`] with [`error_codes::STORAGE_8000`] when
/// no storage provider is set — the storage-before-supervisor precondition. The
/// runtime never defaults storage; no fabrication, no default.
fn durable_providers_from_bi(
    bi: &PyBridgeInstance,
) -> Result<scp_core::context::supervisor::DurableProviders, ScpPyError> {
    let provider = bi
        .storage_provider()
        .ok_or_else(|| ScpPyError::ContextError {
            message: "storage-before-supervisor precondition failed: no storage provider \
             set on the bridge instance — the runtime never defaults storage \
             (spec §17.6). Select storage via SCP({...}) / SCP.with_storage({...}) first."
                .to_owned(),
            code: scp_ffi_common::error_codes::STORAGE_8000.to_owned(),
        })?;
    Ok(scp_core::context::supervisor::DurableProviders::from_handle(Arc::new(provider.clone())))
}

// ---------------------------------------------------------------------------
// DID resolver (global, production)
// ---------------------------------------------------------------------------

/// Returns the production DID resolver on the given bridge instance, if
/// initialized.
///
/// Reads the DID resolver slot on the [`PyBridgeInstance`]'s `CoreFields`.
/// Returns `None` when no resolver has been set.
#[must_use]
pub fn did_resolver(
    bi: &PyBridgeInstance,
) -> Option<&Arc<scp_ffi_common::IdentityBackedDidResolver>> {
    bi.core.did_resolver()
}

/// Initializes the production DID resolver on the given bridge instance.
///
/// Wraps any `scp_identity::resolver::DidResolver` implementation (typically
/// `DualLayerResolver`) in an `IdentityBackedDidResolver` and stores it in
/// the bridge instance's `CoreFields`.
pub fn init_did_resolver<R>(bi: &PyBridgeInstance, resolver: Arc<R>, handle: tokio::runtime::Handle)
where
    R: scp_identity::resolver::DidResolver + 'static,
{
    bi.core
        .set_did_resolver(Arc::new(scp_ffi_common::IdentityBackedDidResolver::new(
            resolver, handle,
        )));
}

/// Returns the shared DHT client backing this instance's DID resolver, if
/// initialized.
///
/// The client is the shared [`FfiDhtClient`](scp_ffi_common::dht::FfiDhtClient)
/// — the real Mainline Pkarr client in a shipped build, or the in-memory test
/// seam under `testing`. Used by `identity_create`/rotation/migration to
/// publish freshly minted DID documents into the same client the resolver
/// reads from, so the DID resolves for signature verification (UCAN
/// validation, governance vote verification).
#[must_use]
pub fn resolver_dht_client(
    bi: &PyBridgeInstance,
) -> Option<Arc<scp_ffi_common::dht::FfiDhtClient>> {
    bi.core.dht_client().map(Arc::clone)
}

/// Stores the shared DHT client backing this instance's DID resolver.
///
/// Called once during resolver initialization with the SAME
/// [`FfiDhtClient`](scp_ffi_common::dht::FfiDhtClient) `Arc` the resolver was
/// built over. Subsequent calls are no-ops.
pub fn set_resolver_dht_client(
    bi: &PyBridgeInstance,
    client: Arc<scp_ffi_common::dht::FfiDhtClient>,
) {
    bi.core.set_dht_client(client);
}

/// Stores the DID-resolution cache backing this instance's DID resolver.
///
/// Called once during resolver initialization with the SAME `Arc<DidCache>`
/// the resolver was built over. Subsequent calls are no-ops.
pub fn set_resolver_cache(bi: &PyBridgeInstance, cache: Arc<scp_identity::cache::DidCache>) {
    bi.core.set_resolver_cache(cache);
}

/// Returns the resolver's DID-resolution cache, if initialized.
///
/// Async callers (already inside the shared runtime) can `await
/// cache.remove(did)` directly; sync callers should use
/// [`invalidate_resolver_cache`].
#[must_use]
pub fn resolver_cache(bi: &PyBridgeInstance) -> Option<Arc<scp_identity::cache::DidCache>> {
    bi.core.resolver_cache().map(Arc::clone)
}

/// Invalidates the resolver's cached document for `did` after a higher-sequence
/// re-publish (key rotation, agent-key add/rotate/remove, migration).
///
/// The resolver caches resolved documents with a multi-day TTL. Without this,
/// a freshly rotated identity would keep resolving to its pre-rotation document
/// (and pre-rotation `#active` key) until the cache TTL expired — defeating
/// rotation's revocation purpose. Best-effort: a no-op when no cache is wired.
pub fn invalidate_resolver_cache(bi: &PyBridgeInstance, did: &str, rt: &tokio::runtime::Runtime) {
    // Delegates to the shared `BridgeInstanceCore::invalidate_resolver_cache`
    // (the single implementation of the invalidation body); the sync PyO3 bridge
    // drives the async method on the shared runtime.
    rt.block_on(bi.core.invalidate_resolver_cache(did));
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

/// Builds the production VM-aware governance key resolver from a DID resolver.
///
/// Delegates to [`scp_ffi_common::bridge_runtime::document_vm_key_resolver`].
fn document_vm_key_resolver(
    did_resolver: std::sync::Arc<scp_ffi_common::IdentityBackedDidResolver>,
) -> scp_core::context::governance::KeyResolver {
    scp_ffi_common::bridge_runtime::document_vm_key_resolver(did_resolver)
}

// ---------------------------------------------------------------------------
// No-op provider implementations for ContextManager initialization
// ---------------------------------------------------------------------------

// Use the not-configured transport provider from scp-core (#501).
// Unlike `LocalTransportProvider` (which silently succeeds), this returns
// descriptive errors when transport operations are attempted without a relay.
use scp_core::context::NotConfiguredTransportProvider;

// ---------------------------------------------------------------------------
// FfiBridgeState -- per-context FFI-specific state
// ---------------------------------------------------------------------------

/// Returns a reference to the given bridge instance's FFI bridge state
/// registry.
///
/// Resolves the registry via the typed `ffi_bridge_state` field on the
/// passed [`PyBridgeInstance`].
///
/// Stores state that is NOT managed by [`ContextManager`]: outlet registries,
/// event logs, UCAN revocation/nonce tracking, outlet handlers, and message
/// channels. Context lifecycle state (membership, roles, governance,
/// broadcast, TTL) lives in the `ContextManager`.
pub(crate) fn ffi_state_registry(bi: &PyBridgeInstance) -> &DashMap<String, FfiBridgeState> {
    bi.ffi_bridge_state.as_ref()
}

/// Per-context FFI-specific state that does NOT duplicate [`ContextManager`].
///
/// Contains subsystem state used by `outlets.rs`, `ucan.rs`, `event_log.rs`,
/// and `mcp.rs`, plus FFI-specific message channel and outlet handler state.
///
/// # No authorization state lives here
///
/// This struct holds NO role state, NO membership set, NO capability ceiling,
/// and NO creator DID. Every authorization, membership, role, and ceiling
/// decision reads [`live_role_state`], which queries the context's supervisor
/// actor. A bridge-local copy of any of those refreshes only when THIS bridge
/// performs the mutation, so a change the supervisor applied by another route —
/// a governance execution, a broadcast-subscriber removal, a TTL expiry, a
/// trust-recovery transition — left the copy granting authority the supervisor
/// had already withdrawn. Deleting the fields is what stops a caller from
/// reading one; a scanner over source text would not.
pub struct FfiBridgeState {
    /// Outlet registry for this context.
    pub outlet_registry: OutletRegistry,
    /// Event log (Merkle tree) for this context.
    pub event_log: EventLog,
    /// UCAN revocation list for this context.
    ///
    /// The bridge OWNS this list: `PyScp::ucan_revoke` writes it and the
    /// supervisor keeps no counterpart, so reading it here reads the record of
    /// state, not a copy of someone else's.
    pub revocation_list: RevocationList,
    /// UCAN nonce tracker for replay prevention (ADR-016 step 9).
    ///
    /// Bridge-owned for the same reason as `revocation_list`.
    pub nonce_tracker: NonceTracker<SystemClock>,
    /// Registered outlet handlers keyed by outlet ID.
    ///
    /// Python callers register callable handlers via
    /// [`register_outlet_handler`]. When an outlet is invoked through
    /// `FfiBridgeProvider::invoke_outlet`, the handler is looked up here and
    /// called with the validated JSON input. If no handler is registered,
    /// the invocation falls back to echoing the validated input.
    ///
    /// See SCP-212 for the handler registration design.
    pub outlet_handlers: HashMap<String, OutletHandler>,
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
    /// Session store for stateful outlet sessions (spec section 6.2.1).
    ///
    /// Stores active outlet sessions keyed by session ID. Sessions are created
    /// via `py_outlet_session_create` and cleaned up on context close.
    pub session_store: scp_core::context::outlets::SessionStore,
}

/// Buffer capacity for the receive channel (SCP-216, sketch.md §receive).
///
/// When the buffer is full, the oldest unconsumed event is dropped and a
/// `BufferOverflow` warning is injected into the stream.
pub const RECEIVE_BUFFER_CAPACITY: usize = 1000;

/// Registers FFI-specific state for a new context.
///
/// Creates an [`OutletRegistry`], an [`EventLog`], a [`RevocationList`], a
/// [`NonceTracker`], and a session store for the context. Role state,
/// membership, the capability ceiling, and the creator DID are NOT stored here:
/// the supervisor actor owns them and [`live_role_state`] reads them.
///
/// `user_ceiling` contains user-provided ceiling strings in colon format
/// (e.g. `"outlet:call:*"`). This function VALIDATES each entry against the
/// ceiling-entry grammar (spec §5.3.1.1) and then discards the parsed values —
/// `Supervisor::create_context` stores the ceiling that authorization reads.
/// Validating at the FFI boundary rejects a malformed entry with a bridge-native
/// message before the supervisor sees it. Pass an empty slice when the context
/// takes the default ceiling.
///
/// # Errors
///
/// Returns `ScpPyError::ContextError` if the context ID is already registered
/// or if a `user_ceiling` entry fails the ceiling-entry grammar.
pub fn register_ffi_state(
    bi: &PyBridgeInstance,
    context_id: &str,
    user_ceiling: &[String],
) -> Result<(), ScpPyError> {
    use dashmap::mapref::entry::Entry;

    // Ceiling-entry grammar enforcement (spec §5.3.1.1) on each user entry.
    // Validate the PARSED enum (`Capability::new(entry).validate_as_ceiling_entry()`)
    // — NOT the raw string — so the validation checks EXACTLY the capability the
    // supervisor will enforce. `Capability::new` strips a `custom:` prefix: the raw
    // string `"custom:payments"` has one colon (would pass a raw-string check) but
    // parses to `Custom("payments")`, whose enforced form (`ucan_capability_name` →
    // `payments:payments`) corresponds to a no-colon custom that
    // `validate_as_ceiling_entry` REJECTS. Routing through the parsed enum keeps the
    // raw-string validation and the enforced parse in agreement on one canonical form
    // (BLACK-003), and still rejects a no-colon `payments` that would otherwise be
    // widened to `payments:*`.
    for entry in user_ceiling {
        // Fail-closed: a malformed capability string (deleted legacy
        // outlet-invoke / pre-rename outlet-invoke stems, invalid §5.4.2.1
        // outlet suffix) parses to `None` and is rejected at the FFI boundary
        // rather than silently dropped.
        let cap = scp_core::context::roles::Capability::new(entry).ok_or_else(|| {
            ScpPyError::context(format!(
                "invalid capability {entry:?} in ceiling (fails §5.4.2.1 parser) (use \"outlet:call:*\" for actions, \"outlet:query:*\" for reads)"
            ))
        })?;
        cap.validate_as_ceiling_entry()
            .map_err(|e| ScpPyError::context(e.to_string()))?;
    }

    let map = ffi_state_registry(bi);

    match map.entry(context_id.to_owned()) {
        Entry::Occupied(_) => {
            return Err(ScpPyError::context(format!(
                "context '{context_id}' FFI state is already registered"
            )));
        }
        Entry::Vacant(vacant) => {
            let state = FfiBridgeState {
                outlet_registry: OutletRegistry::new(),
                event_log: EventLog::new(context_id.to_owned()),
                revocation_list: RevocationList::new(context_id.to_owned()),
                nonce_tracker: NonceTracker::new(context_id.to_owned(), SystemClock),
                outlet_handlers: HashMap::new(),
                message_tx: None,
                message_rx: None,
                session_store: scp_core::context::outlets::SessionStore::new(),
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
pub fn with_ffi_state<T, F>(bi: &PyBridgeInstance, context_id: &str, f: F) -> Result<T, ScpPyError>
where
    F: FnOnce(&mut FfiBridgeState) -> Result<T, ScpPyError>,
{
    let map = ffi_state_registry(bi);

    let mut entry = map.get_mut(context_id).ok_or_else(|| {
        ScpPyError::context(format!(
            "context '{context_id}' not found in FFI state registry \
                 -- was it created with py_context_create?"
        ))
    })?;

    f(entry.value_mut())
}

// ---------------------------------------------------------------------------
// Live supervisor role state — the single authorization source
// ---------------------------------------------------------------------------

/// Runs `fut` to completion under whichever tokio regime the calling thread
/// sits in, and returns whatever `fut` produced.
///
/// A `PyO3` entry point reaches a supervisor query from three regimes:
///
/// 1. a Python call that carries no ambient tokio runtime (`PyO3` methods are
///    synchronous, and the Python SDK dispatches them through
///    `asyncio.to_thread`);
/// 2. an MCP server task running on the shared multi-thread runtime, where
///    `Runtime::block_on` panics but `block_in_place` is legal; and
/// 3. an MCP server task running on a current-thread runtime, where
///    `Runtime::block_on` and `block_in_place` both panic.
///
/// This function reads the ambient handle, then picks the bridge that regime
/// permits: the shared runtime's `block_on`, `block_in_place` around the
/// ambient handle, or a private current-thread runtime on a fresh thread. The
/// supervisor query itself only awaits a mailbox channel, so a private runtime
/// drives it to completion while the per-context actor keeps running on the
/// shared runtime. `scripts/check-block-in-place.py` excludes
/// `crates/scp-ffi/**` because every FFI bridge needs a synchronous-to-async
/// seam of exactly this shape.
///
/// # Errors
///
/// Returns `ScpPyError::ContextError` when the shared tokio runtime is absent,
/// when a private current-thread runtime fails to build, or when the fresh
/// thread ends before it sends an answer.
fn block_on_supervisor_query<T, F>(fut: F) -> Result<T, ScpPyError>
where
    T: Send + 'static,
    F: std::future::Future<Output = T> + Send + 'static,
{
    match tokio::runtime::Handle::try_current() {
        Err(_) => {
            let rt = super::runtime().map_err(|e| ScpPyError::context(e.to_string()))?;
            Ok(rt.block_on(fut))
        }
        Ok(handle)
            if matches!(
                handle.runtime_flavor(),
                tokio::runtime::RuntimeFlavor::MultiThread
            ) =>
        {
            Ok(tokio::task::block_in_place(|| handle.block_on(fut)))
        }
        Ok(_) => {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => drop(tx.send(rt.block_on(fut))),
                    Err(e) => tracing::error!(
                        error = %e,
                        "live supervisor query could not build a private runtime; \
                         the caller fails closed"
                    ),
                }
            });
            rx.recv().map_err(|_| {
                ScpPyError::context(
                    "live supervisor query ended before the supervisor answered".to_owned(),
                )
            })
        }
    }
}

/// Reads a context's role state from that context's supervisor actor.
///
/// Every `PyO3` entry point that decides authorization, membership, a role, a
/// capability, or a capability ceiling reads through this function.
/// [`FfiBridgeState`] deliberately holds no role-state copy: a bridge-local
/// copy only refreshes when THIS bridge performs the mutation, so a membership
/// change another participant authored — an MLS commit that the per-context
/// actor applies — leaves a copy that still grants authority the supervisor
/// already withdrew. `outlet_stream_open` and the cross-context streaming saga
/// already read the actor, so a bridge-local copy also made one bridge answer
/// one authorization question two ways.
///
/// Fails closed. A context whose actor returns no role state yields
/// [`ScpPyError::ContextError`]; no caller receives a permissive default.
///
/// # Errors
///
/// Returns `ScpPyError::ContextError` when the supervisor is unavailable, when
/// the tokio bridge fails (see [`block_on_supervisor_query`]), or when the
/// supervisor holds no role state for `context_id`.
pub fn live_role_state(
    bi: &PyBridgeInstance,
    context_id: &str,
) -> Result<ContextRoleState, ScpPyError> {
    let sup = Arc::clone(supervisor(bi)?);
    let ctx = context_id.to_owned();
    block_on_supervisor_query(async move { sup.get_role_state(&ctx).await })?.ok_or_else(|| {
        ScpPyError::context(format!(
            "context '{context_id}' has no live supervisor role state — refusing to \
             authorize against an absent membership record"
        ))
    })
}

/// Reads a context's lifecycle state from that context's supervisor actor.
///
/// Every `PyO3` entry point that gates on a lifecycle state reads through this
/// function. [`PyContextHandle`](crate::context::PyContextHandle) carries a
/// `state` string, and that string records the last transition THIS bridge
/// observed: a TTL expiry the supervisor applied on its own timer, a close
/// another member initiated, a migration that tombstoned the context, and an
/// actor the watchdog poisoned all leave that string reading `"active"`. A gate
/// reading that string therefore admits an operation into a context the
/// supervisor had already stopped serving. The handle's `state` getter stays a
/// cached snapshot, because its documented contract says so; a gate does not.
///
/// Fails closed. A context whose supervisor reports no state — an unknown
/// context, or one whose mailbox does not answer — yields
/// [`ScpPyError::ContextError`], so no caller passes a gate on an absent
/// answer.
///
/// # Errors
///
/// Returns `ScpPyError::ContextError` when the supervisor is unavailable, when
/// the tokio bridge fails (see [`block_on_supervisor_query`]), or when the
/// supervisor reports no state for `context_id`.
pub fn live_context_state(
    bi: &PyBridgeInstance,
    context_id: &str,
) -> Result<scp_core::context::ContextState, ScpPyError> {
    read_live_context_state(bi, context_id)?.ok_or_else(|| {
        ScpPyError::context(format!(
            "context '{context_id}' has no live supervisor state — refusing to run a \
             lifecycle-gated operation against a context no actor serves"
        ))
    })
}

/// Reads a context's lifecycle state from that context's supervisor actor, and
/// reports an absent actor as `None` instead of as an error.
///
/// [`live_context_state`] is the gate form: it turns `None` into an error so a
/// gate never admits an operation on an absent answer. `context_close` calls
/// this form instead, because a close of a context whose actor the supervisor
/// already despawned — a completed TTL expiry, an all-members-left teardown —
/// is idempotent: the close already happened, and the bridge still has to
/// release the [`FfiBridgeState`] it holds for that id. Refusing that close
/// would leave the registry entry alive for the life of the process.
///
/// # Errors
///
/// Returns `ScpPyError::ContextError` when the supervisor is unavailable or
/// when the tokio bridge fails (see [`block_on_supervisor_query`]).
pub fn read_live_context_state(
    bi: &PyBridgeInstance,
    context_id: &str,
) -> Result<Option<scp_core::context::ContextState>, ScpPyError> {
    let sup = Arc::clone(supervisor(bi)?);
    let ctx = context_id.to_owned();
    block_on_supervisor_query(async move { sup.read_context_state(&ctx).await })
}

/// Reads a context's capability ceiling from that context's supervisor actor,
/// normalized to the `{resource}:{action}` UCAN capability names that ADR-016
/// step 8 compares a token's grants against.
///
/// Callers that also need membership or roles call [`live_role_state`] once and
/// derive the ceiling from it, so one authorization decision costs one mailbox
/// round trip.
///
/// # Errors
///
/// Propagates every error [`live_role_state`] returns.
pub fn live_ceiling_strings(
    bi: &PyBridgeInstance,
    context_id: &str,
) -> Result<HashSet<String>, ScpPyError> {
    Ok(live_role_state(bi, context_id)?
        .ceiling()
        .to_ucan_string_set())
}

/// Returns the IDs of all registered contexts where the given DID is a member,
/// reading each context's membership from its supervisor actor.
///
/// Used by `py_mcp_load_contexts` to return locally known contexts when
/// relay transport is not yet wired. Returns an empty Vec if no contexts
/// match.
///
/// A context whose actor holds no role state is omitted rather than reported as
/// a match: the bridge cannot confirm membership it cannot read, and claiming
/// membership from a bridge-local copy is the staleness this function exists to
/// avoid.
#[must_use]
pub fn context_ids_for_member(bi: &PyBridgeInstance, member_did: &str) -> Vec<String> {
    let context_ids: Vec<String> = ffi_state_registry(bi)
        .iter()
        .map(|entry| entry.key().clone())
        .collect();
    context_ids
        .into_iter()
        .filter(|context_id| {
            live_role_state(bi, context_id)
                .is_ok_and(|role_state| role_state.members.contains(member_did))
        })
        .collect()
}

/// Registers an outlet handler for a specific outlet in a context.
///
/// The handler is a sync closure that takes JSON input and returns JSON
/// output. It is called by `FfiBridgeProvider::invoke_outlet` when the
/// outlet is invoked via MCP. The handler must already have a corresponding
/// outlet registration in the context's `OutletRegistry` (registered via
/// `py_outlet_register`).
///
/// # Errors
///
/// Returns `ScpPyError::ContextError` if the context is not found or the
/// outlet is not registered in the context's `OutletRegistry`.
pub fn register_outlet_handler(
    bi: &PyBridgeInstance,
    context_id: &str,
    outlet_id: &str,
    handler: OutletHandler,
) -> Result<(), ScpPyError> {
    with_ffi_state(bi, context_id, |st| {
        // Verify the outlet exists in the registry before accepting a handler.
        if st.outlet_registry.get(outlet_id).is_none() {
            return Err(ScpPyError::context(format!(
                "outlet '{outlet_id}' not found in context '{context_id}' \
                 -- register the outlet before adding a handler"
            )));
        }
        st.outlet_handlers.insert(outlet_id.to_owned(), handler);
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
pub fn remove_ffi_state(bi: &PyBridgeInstance, context_id: &str) {
    ffi_state_registry(bi).remove(context_id);
    // Clean up known-context discovery entry via CoreFields.
    bi.core.remove_known_context(context_id);
    // Clean up per-context bridge connector state and economy state via CoreFields.
    bi.core.remove_bridge_state(context_id);
    bi.core.remove_economy_state(context_id);
}

// `sync_role_state_from_manager`, `sync_role_state_from_manager_async`, and
// `sync_ceiling_from_params` are DELETED. Each one copied supervisor role state
// or an authenticated ceiling into `FfiBridgeState` so a later authorization
// check could read the copy. A copy refreshed on a local mutation still went
// stale on every change the supervisor applied by another route, so
// authorization now reads `live_role_state` at the moment it decides, and no
// copy exists for a caller to read.

/// Test-only: spawns the per-context supervisor actor that [`live_role_state`]
/// reads, carrying `ceiling` as the context's capability ceiling.
///
/// [`register_context`] alone registers FFI state and attaches a supervisor to
/// the bridge instance; it does NOT create the context inside that supervisor,
/// so a unit test that only calls it leaves every authorization read failing
/// closed. Tests call this to give the context the role state a real
/// `context_create` would have created.
///
/// `ceiling` entries take the colon form the Python surface accepts
/// (`"outlet:register"`, `"messages:write"`). An empty slice creates the context
/// with `default_ceiling()`, matching what `build_core_context_params` sends
/// when a caller supplies no ceiling.
///
/// # Panics
///
/// Panics when a `ceiling` entry fails the §5.4.2.1 capability parser, when the
/// tokio runtime is unavailable, or when `create_context` rejects the request —
/// each one is a broken test fixture rather than a condition under test.
#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)] // A broken test fixture panics; production paths keep the deny.
pub(crate) fn create_supervisor_context_for_test(
    bi: &PyBridgeInstance,
    context_id: &str,
    creator_did: &str,
    ceiling: &[&str],
) {
    let capabilities: Vec<scp_core::context::roles::Capability> = if ceiling.is_empty() {
        scp_core::context::roles::default_ceiling()
            .iter()
            .cloned()
            .collect()
    } else {
        ceiling
            .iter()
            .map(|entry| {
                scp_core::context::roles::Capability::new(entry)
                    .unwrap_or_else(|| panic!("test ceiling entry {entry:?} must parse"))
            })
            .collect()
    };
    let params = scp_core::context::ContextParams {
        ceiling: capabilities,
        ..scp_core::context::ContextParams::default()
    };
    let sup = Arc::clone(supervisor(bi).expect("test supervisor must be attached"));
    let rt = super::runtime().expect("tokio runtime must be initialized");
    rt.block_on(sup.create_context(
        context_id.to_owned(),
        params,
        scp_did::DID(creator_did.to_owned()),
        None,
    ))
    .expect("test supervisor context creation must succeed");
}

/// Test-only: builds a bridge instance whose supervisor role state DIFFERS from
/// anything a bridge-local copy could have held, and returns it with the
/// context id.
///
/// `register_context` is called with an EMPTY ceiling. A bridge copy built from
/// that argument carried `default_ceiling()` and named `creator_did` as the
/// context creator, so passing a NARROWER `supervisor_ceiling` (or a different
/// creator) makes the supervisor and any such copy disagree. A test that asserts
/// the supervisor's answer therefore fails the moment a call site goes back to
/// reading a copy.
///
/// # Panics
///
/// Panics when `register_context` or the supervisor context creation fails —
/// each is a broken fixture rather than a condition under test.
#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)] // A broken test fixture panics; production paths keep the deny.
pub(crate) fn live_state_fixture(
    prefix: &str,
    creator_did: &str,
    supervisor_ceiling: &[&str],
) -> (Arc<PyBridgeInstance>, String) {
    crate::init_runtime().ok();
    let bi = Arc::new(PyBridgeInstance::new_py());
    let context_id = format!("{prefix}-{}", uuid::Uuid::new_v4());
    register_context(&bi, &context_id, creator_did, &[]).expect("fixture registration");
    create_supervisor_context_for_test(&bi, &context_id, creator_did, supervisor_ceiling);
    (bi, context_id)
}

/// Test-only: records `member` in the context's SUPERVISOR role state through
/// the `testing`-gated actor seam, writing nothing bridge-side.
///
/// A membership change this bridge did not author is the shape the stale-copy
/// defect turned on, so the fixture reproduces it.
///
/// # Panics
///
/// Panics when the supervisor rejects the insert.
#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)] // A broken test fixture panics; production paths keep the deny.
pub(crate) fn insert_supervisor_member_for_test(
    bi: &PyBridgeInstance,
    context_id: &str,
    member: &str,
) {
    let sup = Arc::clone(supervisor(bi).expect("fixture supervisor"));
    let rt = super::runtime().expect("tokio runtime");
    rt.block_on(sup.test_insert_member(context_id, scp_did::DID(member.to_owned()), "member"))
        .expect("supervisor must record the member");
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
pub fn close_receive_channel(bi: &PyBridgeInstance, context_id: &str) -> Result<(), ScpPyError> {
    with_ffi_state(bi, context_id, |st| {
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
/// The sender + shared-receiver pair backing a context's receive channel.
/// Cloned out of [`FfiBridgeState`] so an event can be delivered after the
/// owning bridge state has been removed from the registry (the close
/// teardown removes the FFI state BEFORE the actor despawn to fail closed,
/// then still delivers the `SystemClose` event through these handles).
pub type ReceiveChannelHandles = (
    mpsc::Sender<PyMessage>,
    Arc<tokio::sync::Mutex<mpsc::Receiver<PyMessage>>>,
);

/// Clone a context's receive-channel handles out of the FFI state
/// registry, if a receive channel is active. Returns `None` when the
/// context is unregistered or has no open channel.
#[must_use]
pub fn clone_receive_channel_handles(
    bi: &PyBridgeInstance,
    context_id: &str,
) -> Option<ReceiveChannelHandles> {
    with_ffi_state(bi, context_id, |st| {
        Ok(st.message_tx.clone().zip(st.message_rx.clone()))
    })
    .ok()
    .flatten()
}

pub fn deliver_message(
    bi: &PyBridgeInstance,
    context_id: &str,
    message: PyMessage,
) -> Result<(), ScpPyError> {
    let (tx, rx_arc) = with_ffi_state(bi, context_id, |st| {
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
    deliver_message_with_handles(bi, context_id, &tx, &rx_arc, message)
}

/// Deliver a message through pre-captured channel handles.
///
/// Bypasses the FFI state registry (oldest-drop on overflow). Used by the
/// close teardown to deliver the `SystemClose` event AFTER the bridge
/// state has been removed (fail-closed ordering). Same overflow semantics
/// as [`deliver_message`].
///
/// # Errors
///
/// Returns `ScpPyError::ContextError` if the channel is closed or a send
/// fails after an overflow drop.
pub fn deliver_message_with_handles(
    bi: &PyBridgeInstance,
    context_id: &str,
    tx: &mpsc::Sender<PyMessage>,
    rx_arc: &Arc<tokio::sync::Mutex<mpsc::Receiver<PyMessage>>>,
    message: PyMessage,
) -> Result<(), ScpPyError> {
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
                bi,
                "scp:system".to_owned(),
                b"BufferOverflow: oldest event dropped due to full receive buffer".to_vec(),
                SystemClock.now_secs() as f64,
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

/// Registers a known context in the discovery registry for the supplied
/// [`PyBridgeInstance`].
///
/// Called after `py_context_create` to record the context's routing ID and
/// relay URL for later discovery via `py_mcp_load_contexts`.
///
/// Overwrites any existing entry for the same context ID (idempotent).
pub fn register_known_context_on(bi: &PyBridgeInstance, context_id: &str, known: KnownContext) {
    bi.core.register_known_context(context_id, known);
}

// Phase D (#1695): legacy default-bridge free-fn shims deleted. Callers
// must use the `*_on(bi, ...)` variants with an explicit PyBridgeInstance.

/// Returns all known contexts registered against the supplied
/// [`PyBridgeInstance`].
///
/// Used by `py_mcp_load_contexts` to find routing IDs to probe on the relay.
#[must_use]
pub fn all_known_contexts_on(bi: &PyBridgeInstance) -> Vec<(String, KnownContext)> {
    bi.core.all_known_contexts()
}

/// Returns known contexts (registered against the supplied
/// [`PyBridgeInstance`]) where the given DID is the registered member.
#[must_use]
pub fn known_contexts_for_member_on(
    bi: &PyBridgeInstance,
    member_did: &str,
) -> Vec<(String, KnownContext)> {
    bi.core.known_contexts_for_member(member_did)
}

// ---------------------------------------------------------------------------
// Invitation rate limit tracker registry (#614)
// ---------------------------------------------------------------------------
//
// Delegates to the `BridgeInstance`'s `rate_limiters` DashMap.
// ---------------------------------------------------------------------------

// Phase D (#1695): `with_rate_limit_tracker` default-bridge shim deleted.
// Callers use `bi.core.with_rate_limit_tracker(...)` directly.

// ---------------------------------------------------------------------------
// Identity registry (SCP-214: KeyCustody wiring)
// ---------------------------------------------------------------------------

/// Returns the given bridge instance's identity registry.
///
/// The registry is a typed `Arc<DashMap<String, IdentityEntry>>` field on
/// [`PyBridgeInstance`] — always real, no fallback.
///
/// The `DashMap` provides lock-free concurrent access matching the context
/// registry pattern (ADR-006).
pub(crate) fn identity_registry(bi: &PyBridgeInstance) -> &DashMap<String, IdentityEntry> {
    bi.identity_registry.as_ref()
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
    /// Handle to the per-identity pre-rotation key in cold-storage custody.
    /// Returned by `DidDht::create` / `migrate_identity` and consumed by
    /// the next `migrate_identity` call. See ADR-003 §4b.
    pub pre_rotation_handle: scp_platform::PreRotationKeyHandle,
    /// Cold-storage custody for the pre-rotation key. A separate substrate
    /// from operational `key_custody` (spec §9.7.4.1 §3). The same `Arc` is
    /// preserved across migrations (we don't mint a new custody per
    /// migration — only a new handle).
    ///
    /// TEST-HARNESS ONLY (`#[cfg(feature = "testing")]`, ADR-062 §Decision 6):
    /// the only `PreRotationCustody` backend is the in-memory nullifier. On a
    /// shipped build, identity creation FAILS CLOSED (`IDENT_1059`) before any
    /// `IdentityEntry` is constructed, so no production entry ever carries this
    /// field — the retained-custody + migration machinery is gated with it.
    #[cfg(feature = "testing")]
    pub pre_rotation_custody: Arc<scp_platform::testing::InMemoryPreRotationCustody>,
}

/// Registers an identity in the global identity registry.
///
/// Called by `py_identity_create` after successfully creating an identity.
/// Subsequent bridge functions (UCAN minting, pseudonym derivation, key
/// rotation) look up the identity by DID to access the retained custody
/// provider and key handles.
///
/// Overwrites any existing entry for the same DID (idempotent).
pub fn register_identity(bi: &PyBridgeInstance, did: &str, entry: IdentityEntry) {
    identity_registry(bi).insert(did.to_owned(), entry);
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
pub fn with_identity<T, F>(bi: &PyBridgeInstance, did: &str, f: F) -> Result<T, ScpPyError>
where
    F: FnOnce(&IdentityEntry) -> Result<T, ScpPyError>,
{
    let entry = identity_registry(bi).get(did).ok_or_else(|| {
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
pub fn with_identity_mut<T, F>(bi: &PyBridgeInstance, did: &str, f: F) -> Result<T, ScpPyError>
where
    F: FnOnce(&mut IdentityEntry) -> Result<T, ScpPyError>,
{
    let mut entry = identity_registry(bi).get_mut(did).ok_or_else(|| {
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
pub fn identity_registry_contains(bi: &PyBridgeInstance, did: &str) -> bool {
    identity_registry(bi).contains_key(did)
}

/// Removes an identity from the global registry.
///
/// Called when an identity is migrated to a new DID. The old entry is
/// removed and the new entry is registered under the new DID.
pub fn remove_identity(bi: &PyBridgeInstance, did: &str) {
    identity_registry(bi).remove(did);
}

// ---------------------------------------------------------------------------
// Storage provider registry (SCP-217: identity persistence)
// ---------------------------------------------------------------------------

/// Returns a reference to the storage provider attached to this bridge instance.
///
/// Storage is fixed at construction via [`PyBridgeInstance::with_storage_py`]
/// (driven from Python by `SCP.with_storage({...})`). A `PyBridgeInstance`
/// constructed via [`PyBridgeInstance::new_py`] has no storage attached —
/// callers needing persistence must use the factory.
///
/// # Errors
///
/// Returns `ScpPyError::IdentityError` if no storage provider was attached
/// at construction time. The legacy `init_storage` imperative-attach path
/// (and the matching Python `SCP.init_storage(...)` shim) was removed in
/// favour of the `with_storage` factory — see #1543 PR-C.
pub fn get_storage(bi: &PyBridgeInstance) -> Result<&StorageProvider, ScpPyError> {
    bi.storage_provider().ok_or_else(|| {
        ScpPyError::identity(
            "storage not initialized — construct the SCP instance via \
             SCP.with_storage({...}) instead of bare SCP()"
                .to_owned(),
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
pub fn set_transport_manager(
    bi: &PyBridgeInstance,
    manager: scp_transport::TransportManager,
) -> Result<(), ScpPyError> {
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
    bi: &PyBridgeInstance,
    f: impl FnOnce(&scp_transport::TransportManager) -> Result<T, ScpPyError>,
) -> Result<T, ScpPyError> {
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
    bi: &PyBridgeInstance,
    f: impl FnOnce(&mut scp_transport::TransportManager) -> Result<T, ScpPyError>,
) -> Result<T, ScpPyError> {
    bi.core
        .with_transport_mut(f)
        .map_err(|e| ScpPyError::transport(e.to_string()))?
}

/// Returns `true` if a transport manager has been initialized.
#[must_use]
pub fn has_transport_manager(bi: &PyBridgeInstance) -> bool {
    bi.core.has_transport()
}

/// Records a heartbeat suppression event for a relay, downgrading its
/// reliability score.
///
/// Called from the background task spawned by `transport_add_relay` /
/// `transport_connect` that drains the per-adapter suppression receiver
/// (#1533 AC5). Silently no-ops if the bridge or transport manager has
/// been cleared (e.g., after disconnect).
pub fn record_suppression(bi: &PyBridgeInstance, relay_url: &str) {
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
pub fn clear_transport_manager(bi: &PyBridgeInstance) -> Result<(), ScpPyError> {
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
/// operations) and the FFI bridge state (for outlet/UCAN/event-log operations)
/// are initialized for the given context. Used during the transition period
/// where the full `ContextManager` flow is being connected.
///
/// # Errors
///
/// Returns `ScpPyError::ContextError` if registration fails.
pub fn register_context(
    bi: &PyBridgeInstance,
    context_id: &str,
    creator_did: &str,
    user_ceiling: &[String],
) -> Result<(), ScpPyError> {
    // Ensure the ContextManager is initialized.
    // Tests use LocalTransportProvider so publish_context succeeds silently.
    // Production uses NotConfiguredTransportProvider — publish_context
    // returns an error that create_context logs as a warning (best-effort;
    // context is valid locally even without relay publication, #501).
    // Passes the creator DID to NodeMlsFactory for real MLS encryption (#1324).
    #[cfg(test)]
    {
        // The test supervisor is built with a fixed MLS credential identity, so
        // `creator_did` has no consumer on this branch.
        let _ = creator_did;
        init_context_manager_for_test(bi);
    }
    #[cfg(not(test))]
    init_context_manager(bi, creator_did);

    // Register FFI-specific state. `creator_did` reaches the MLS factory above;
    // FFI state stores no creator DID, because authorization reads the
    // supervisor's `creator_did` through `live_role_state`.
    register_ffi_state(bi, context_id, user_ceiling)
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
pub fn with_context<T, F>(bi: &PyBridgeInstance, context_id: &str, f: F) -> Result<T, ScpPyError>
where
    F: FnOnce(&mut FfiBridgeState) -> Result<T, ScpPyError>,
{
    with_ffi_state(bi, context_id, f)
}

/// Backward-compatible alias for [`remove_ffi_state`].
pub fn remove_context(bi: &PyBridgeInstance, context_id: &str) {
    remove_ffi_state(bi, context_id);
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
pub fn registry_stats(bi: &PyBridgeInstance) -> RegistryStats {
    RegistryStats {
        contexts: ffi_state_registry(bi).len(),
        known_contexts: bi.core.known_context_count(),
        identities: identity_registry(bi).len(),
        relay_connected: bi.core.has_transport(),
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
pub fn query_trust_event_counts(bi: &PyBridgeInstance, context_id: &str, _did: &str) -> (u64, u64) {
    let map = ffi_state_registry(bi);
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
pub fn remove_identity_if_present(bi: &PyBridgeInstance, did: &str) -> bool {
    identity_registry(bi).remove(did).is_some()
}

// Economy state is owned by `PyBridgeInstance`. Callers thread a
// `&PyBridgeInstance` through from the enclosing `PyScp` method and
// access it via `bi.with_economy_budget(...)` / `bi.economy_*(...)`
// directly. The `bridge_instance()` default-lookup helper was deleted
// in Phase D (#1549 PR 4) along with the rest of the process-wide
// default-instance scaffolding.

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    // Test-harness key-custody nullifier: used only by the `#[cfg(feature =
    // "testing")]` identity-registry tests below. Gated so the shipped
    // (no-`testing`) test lane — which exists now that this module carries
    // `#[cfg(not(feature = "testing"))]` fail-closed proofs elsewhere in the
    // crate — does not see an unused import (ADR-062 §Decision 6 parity).
    #[cfg(feature = "testing")]
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

    #[cfg(feature = "testing")]
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
        let bi_arc = std::sync::Arc::new(PyBridgeInstance::new_py());
        let bi = &*bi_arc;
        init_context_manager_for_test(bi);
        let ctx_id = unique_ctx_id("stats-ctx");
        let creator = "did:dht:z6MkStatsTest";

        register_context(bi, &ctx_id, creator, &[]).unwrap();
        let stats = registry_stats(bi);

        // Verify that stats reports at least 1 context (our registered one).
        // Cannot assert exact counts due to parallel test interference.
        assert!(
            stats.contexts >= 1,
            "should have at least 1 context after registration (got {})",
            stats.contexts,
        );

        // Verify the specific entry exists via direct registry access.
        assert!(
            ffi_state_registry(bi).contains_key(&ctx_id),
            "registered context should be in registry"
        );

        remove_context(bi, &ctx_id);
        assert!(
            !ffi_state_registry(bi).contains_key(&ctx_id),
            "removed context should not be in registry"
        );
    }

    #[test]
    #[cfg(feature = "testing")]
    fn registry_stats_reflects_identity_registration() {
        let bi_arc = std::sync::Arc::new(PyBridgeInstance::new_py());
        let bi = &*bi_arc;
        init_context_manager_for_test(bi);
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
            pre_rotation_handle: scp_platform::PreRotationKeyHandle::new(0),
            pre_rotation_custody: Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new()),
        };
        register_identity(bi, did, entry);
        let stats = registry_stats(bi);

        assert!(
            stats.identities >= 1,
            "should have at least 1 identity after registration (got {})",
            stats.identities,
        );
        assert!(
            identity_registry(bi).contains_key(did),
            "registered identity should be in registry"
        );

        remove_identity(bi, did);
        assert!(
            !identity_registry(bi).contains_key(did),
            "removed identity should not be in registry"
        );
    }

    #[test]
    fn registry_stats_reflects_known_context_registration() {
        // Ensure bridge is initialized so known_contexts DashMap exists.
        let bi_arc = std::sync::Arc::new(PyBridgeInstance::new_py());
        let bi = &*bi_arc;
        init_context_manager_for_test(bi);

        let ctx_id = unique_ctx_id("stats-known");
        let known = KnownContext {
            routing_id: [0xCC; 32],
            relay_url: None,
            member_did: "did:dht:z6MkStatsKnown".to_owned(),
            last_seen: 0,
        };

        register_known_context_on(bi, &ctx_id, known);
        let stats = registry_stats(bi);

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
        let _ = register_ffi_state(bi, &ctx_id, &[]);
        remove_ffi_state(bi, &ctx_id);
        assert!(
            !bi.core.has_known_context(&ctx_id),
            "removed known context should not be in BridgeInstance"
        );
    }

    #[test]
    #[cfg(feature = "testing")]
    fn remove_identity_if_present_returns_true_when_found() {
        let bi_arc = std::sync::Arc::new(PyBridgeInstance::new_py());
        let bi = &*bi_arc;
        init_context_manager_for_test(bi);
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
            pre_rotation_handle: scp_platform::PreRotationKeyHandle::new(0),
            pre_rotation_custody: Arc::new(scp_platform::testing::InMemoryPreRotationCustody::new()),
        };
        register_identity(bi, did, entry);
        assert!(remove_identity_if_present(bi, did));
    }

    #[test]
    fn remove_identity_if_present_returns_false_when_not_found() {
        let bi_arc = std::sync::Arc::new(PyBridgeInstance::new_py());
        let bi = &*bi_arc;
        init_context_manager_for_test(bi);
        assert!(!remove_identity_if_present(
            bi,
            "did:dht:z6MkNotPresent9999"
        ));
    }

    #[test]
    fn registry_stats_returns_all_fields() {
        let bi_arc = std::sync::Arc::new(PyBridgeInstance::new_py());
        let bi = &*bi_arc;
        init_context_manager_for_test(bi);
        // Verifies the struct shape and that registry_stats() doesn't panic.
        let stats = registry_stats(bi);
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
        let bi_arc = std::sync::Arc::new(PyBridgeInstance::new_py());
        let bi = &*bi_arc;
        init_context_manager_for_test(bi);
        let sup1 = supervisor(bi).unwrap();
        init_context_manager_for_test(bi);
        let sup2 = supervisor(bi).unwrap();
        // Same Arc (same pointer).
        assert!(Arc::ptr_eq(sup1, sup2));
    }

    #[test]
    fn with_ffi_state_finds_registered_context() {
        let bi_arc = std::sync::Arc::new(PyBridgeInstance::new_py());
        let bi = &*bi_arc;
        init_context_manager_for_test(bi);
        let ctx_id = unique_ctx_id("ffi-find");
        let creator = "did:dht:z6MkFfiFind";
        register_context(bi, &ctx_id, creator, &[]).unwrap();

        // `FfiBridgeState` carries no creator DID any more, so the lookup asserts
        // that the registered entry exists by reading a bridge-owned field.
        let context_id = with_ffi_state(bi, &ctx_id, |st| Ok(st.event_log.context_id().to_owned()))
            .expect("registered context must be found in the FFI state registry");
        assert_eq!(context_id, ctx_id);

        remove_context(bi, &ctx_id);
    }

    #[test]
    fn with_ffi_state_errors_on_missing_context() {
        let bi_arc = std::sync::Arc::new(PyBridgeInstance::new_py());
        let bi = &*bi_arc;
        init_context_manager_for_test(bi);
        let result = with_ffi_state(bi, "nonexistent-ctx-id", |_| Ok(()));
        assert!(result.is_err());
    }

    /// The close-teardown fail-closed ordering: once the FFI bridge state
    /// is removed (which `context_close` now does BEFORE the actor
    /// despawn, so a fail-open rate-limit can't gate unthrottled outlet
    /// dispatch), `with_context`/`with_ffi_state` outlet lookups fail
    /// closed — yet the receive-channel handles captured BEFORE removal
    /// still deliver the `SystemClose` event to an active receiver.
    #[tokio::test(flavor = "multi_thread")]
    async fn close_channel_handles_survive_ffi_state_removal() {
        let bi_arc = std::sync::Arc::new(PyBridgeInstance::new_py());
        let bi = &*bi_arc;
        init_context_manager_for_test(bi);
        let ctx_id = unique_ctx_id("close-fail-closed");
        register_context(bi, &ctx_id, "did:dht:z6MkCloseFailClosed", &[]).unwrap();

        // Open a receive channel on the FFI state (as `context_receive`
        // would).
        let (tx, rx) = mpsc::channel::<PyMessage>(RECEIVE_BUFFER_CAPACITY);
        let rx_arc = Arc::new(tokio::sync::Mutex::new(rx));
        with_ffi_state(bi, &ctx_id, |st| {
            st.message_tx = Some(tx);
            st.message_rx = Some(Arc::clone(&rx_arc));
            Ok(())
        })
        .unwrap();

        // Capture the channel handles BEFORE removing the FFI state — this
        // is what the close teardown does so it can still deliver the
        // close event after failing the outlet path closed.
        let handles =
            clone_receive_channel_handles(bi, &ctx_id).expect("an open channel yields handles");

        // Fail closed: remove the FFI bridge state.
        remove_context(bi, &ctx_id);
        assert!(
            with_ffi_state(bi, &ctx_id, |_| Ok(())).is_err(),
            "outlet dispatch lookup must fail closed once FFI state is removed"
        );

        // Delivery through the captured handles still works after removal.
        let (tx2, rx2) = handles;
        let msg = PyMessage::new(
            bi,
            "scp:system".to_owned(),
            b"SystemClose".to_vec(),
            0.0,
            ctx_id.clone(),
        );
        deliver_message_with_handles(bi, &ctx_id, &tx2, &rx2, msg)
            .expect("captured handles still deliver after FFI-state removal");

        // The receiver observes the delivered close event.
        let received = rx_arc.lock().await.try_recv();
        assert!(
            received.is_ok(),
            "the SystemClose event must reach the receiver via the captured handles"
        );
    }

    /// User-provided ceiling strings in colon format (e.g. `"outlet:call:*"`)
    /// must be converted to UCAN underscore format (e.g. `"outlet_call:*"`)
    /// when stored in `FfiBridgeState.ceiling_strings`. Without this
    /// conversion, `mint_ucan` ceiling checks fail because the minted
    /// capability name (underscore format) doesn't match the stored
    /// raw string. The set now comes from the supervisor actor, so this also
    /// proves the normalization survives the round trip through the supervisor.
    #[test]
    fn user_ceiling_strings_converted_to_ucan_format() {
        crate::init_runtime().ok();
        let bi_arc = std::sync::Arc::new(PyBridgeInstance::new_py());
        let bi = &*bi_arc;
        init_context_manager_for_test(bi);
        let ctx_id = unique_ctx_id("ceiling-conv");
        let creator = "did:dht:z6MkCeilingConv";

        let user_ceiling = vec![
            "outlet:call:*".to_owned(),
            "messages:write".to_owned(),
            "context:child:create".to_owned(),
            "outlet:call:calculator".to_owned(),
        ];

        register_context(bi, &ctx_id, creator, &user_ceiling).unwrap();
        create_supervisor_context_for_test(
            bi,
            &ctx_id,
            creator,
            &[
                "outlet:call:*",
                "messages:write",
                "context:child:create",
                "outlet:call:calculator",
            ],
        );

        let ceiling = live_ceiling_strings(bi, &ctx_id).unwrap();

        // Compound resources must have underscores joining their segments.
        assert!(
            ceiling.contains("outlet_call:*"),
            "expected 'outlet_call:*' but got: {ceiling:?}"
        );
        assert!(
            ceiling.contains("context_child:create"),
            "expected 'context_child:create' but got: {ceiling:?}"
        );
        assert!(
            ceiling.contains("outlet_call:calculator"),
            "expected 'outlet_call:calculator' but got: {ceiling:?}"
        );
        // Simple two-segment capabilities should pass through unchanged.
        assert!(
            ceiling.contains("messages:write"),
            "expected 'messages:write' but got: {ceiling:?}"
        );
        // Raw colon-format strings must NOT be present.
        assert!(
            !ceiling.contains("outlet:call:*"),
            "raw 'outlet:call:*' should not be in ceiling: {ceiling:?}"
        );
        assert!(
            !ceiling.contains("context:child:create"),
            "raw 'context:child:create' should not be in ceiling: {ceiling:?}"
        );

        remove_context(bi, &ctx_id);
    }

    /// When no user ceiling is provided (empty slice), the default ceiling
    /// should be used with proper UCAN underscore format.
    #[test]
    fn empty_user_ceiling_uses_default_in_ucan_format() {
        crate::init_runtime().ok();
        let bi_arc = std::sync::Arc::new(PyBridgeInstance::new_py());
        let bi = &*bi_arc;
        init_context_manager_for_test(bi);
        let ctx_id = unique_ctx_id("ceiling-default");
        let creator = "did:dht:z6MkCeilingDefault";

        register_context(bi, &ctx_id, creator, &[]).unwrap();
        create_supervisor_context_for_test(bi, &ctx_id, creator, &[]);

        let ceiling = live_ceiling_strings(bi, &ctx_id).unwrap();

        // Default ceiling must include outlet_call:* (not outlet:call:*).
        assert!(
            ceiling.contains("outlet_call:*"),
            "default ceiling should contain 'outlet_call:*' but got: {ceiling:?}"
        );
        assert!(
            !ceiling.contains("outlet:call:*"),
            "default ceiling should not contain raw 'outlet:call:*': {ceiling:?}"
        );

        remove_context(bi, &ctx_id);
    }

    // -----------------------------------------------------------------------
    // BridgeInstance tests (#1549)
    // -----------------------------------------------------------------------

    #[test]
    fn bridge_instance_populated_by_init_context_manager() {
        // init_context_manager_for_test populates the per-instance
        // ContextManager. Phase D (#1695) removed the global default.
        let bi_arc = std::sync::Arc::new(PyBridgeInstance::new_py());
        let bi = &*bi_arc;
        init_context_manager_for_test(bi);

        let sup = supervisor(bi).expect("supervisor should be initialized");

        // Both should point to the same ContextManager allocation.
        assert!(
            Arc::ptr_eq(sup, bi.core.try_supervisor().unwrap()),
            "context_manager() must return the per-instance ContextManager Arc"
        );
    }

    #[test]
    fn bridge_instance_not_shutdown_initially() {
        let bi_arc = std::sync::Arc::new(PyBridgeInstance::new_py());
        let bi = &*bi_arc;
        init_context_manager_for_test(bi);

        assert!(
            !bi.core.is_shutdown(),
            "bridge_instance should not be shutdown immediately after init"
        );
    }

    #[test]
    fn shutdown_hook_runs_with_external_state() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        // Build an isolated PyBridgeInstance (not the global default) to avoid
        // interfering with the OnceLock-based singleton used by other tests.
        // It carries an explicit in-memory storage provider so the
        // storage-before-supervisor precondition in `build_supervisor` is
        // satisfied.
        let isolated = PyBridgeInstance::with_storage_py(StorageConfig::InMemory)
            .expect("in-memory storage construction is infallible");
        let supervisor_arc = build_supervisor(
            &isolated,
            Arc::new(NodeMlsFactory::new(
                "did:test:pyo3-bridge-test".to_owned(),
                std::sync::Arc::new(scp_clock::SystemClock),
            )),
            Box::new(scp_core::context::LocalTransportProvider),
            build_event_log_provider(&isolated),
            None,
        )
        .expect("build_supervisor must succeed with in-memory storage set");
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

    // Gated `#[cfg(feature = "testing")]`: it constructs an `IdentityEntry` whose
    // `custody` (`FfiKeyCustody::InMemory`) and `pre_rotation_custody`
    // (`InMemoryPreRotationCustody`) fields are severed to the test harness only
    // (ADR-062 §Decision 6). Without this gate the shipped (no-`testing`) test
    // lane fails to compile — the very lane that now runs the crate's
    // `#[cfg(not(feature = "testing"))]` fail-closed proofs.
    #[test]
    #[cfg(feature = "testing")]
    fn test_py_bridge_instance_typed_identity_registry_roundtrip() {
        // Verify that the typed identity_registry field is wired correctly:
        // inserting an entry through the field is observable via the same
        // Arc<DashMap> from both sides.
        let bi_arc = std::sync::Arc::new(PyBridgeInstance::new_py());
        let bi = &*bi_arc;
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
                pre_rotation_handle: scp_platform::PreRotationKeyHandle::new(0),
                pre_rotation_custody: Arc::new(
                    scp_platform::testing::InMemoryPreRotationCustody::new(),
                ),
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

    // Phase D (#1695): `test_default_instance_is_same_arc` deleted — there
    // is no process-global default instance to assert identity against.

    #[test]
    fn test_py_bridge_instance_with_storage_py_initializes_storage() {
        let bi = PyBridgeInstance::with_storage_py(StorageConfig::InMemory)
            .expect("in-memory storage must always succeed");
        assert!(
            bi.storage_provider().is_some(),
            "with_storage_py(InMemory) must initialize the storage provider"
        );
    }

    /// Build a dedicated current-thread tokio runtime so the async `Storage`
    /// trait methods can be driven from a sync `#[test]` without depending on
    /// the bridge's shared global runtime (which may not be initialized in a
    /// unit-test process).
    fn test_rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build current-thread tokio runtime")
    }

    /// Parity with the NAPI bridge `test_sqlite_passphrase_round_trip`: data
    /// written under a passphrase-derived `SQLCipher` key must survive a reopen
    /// with the SAME passphrase (the persisted salt sidecar re-derives the
    /// same key). Exercises the `with_storage_py` `Passphrase` arm.
    #[test]
    fn test_with_storage_py_sqlite_passphrase_round_trip() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path().to_path_buf();

        let bi = PyBridgeInstance::with_storage_py(StorageConfig::Sqlite {
            path: dir.clone(),
            key: SqliteKeyMaterial::Passphrase(Zeroizing::new(
                "correct horse battery staple".to_owned(),
            )),
        })
        .expect("passphrase sqlite open must succeed");
        let provider = bi
            .storage_provider()
            .cloned()
            .expect("passphrase path must populate the storage provider");
        let rt = test_rt();
        rt.block_on(async {
            provider
                .store("scp-test/persist", b"durable-value")
                .await
                .expect("store via storage provider");
        });
        drop(provider);
        drop(bi);

        // Reopen with the SAME passphrase.
        let bi2 = PyBridgeInstance::with_storage_py(StorageConfig::Sqlite {
            path: dir,
            key: SqliteKeyMaterial::Passphrase(Zeroizing::new(
                "correct horse battery staple".to_owned(),
            )),
        })
        .expect("reopen with same passphrase must succeed");
        let provider2 = bi2
            .storage_provider()
            .cloned()
            .expect("reopened passphrase path must populate the storage provider");
        let read_back = rt.block_on(async {
            provider2
                .retrieve("scp-test/persist")
                .await
                .expect("retrieve via reopened provider")
        });
        assert_eq!(
            read_back.as_deref(),
            Some(b"durable-value".as_slice()),
            "data written under the passphrase must survive a reopen with the same passphrase"
        );
    }

    /// Parity with the NAPI bridge `test_sqlite_wrong_passphrase_fails_closed`:
    /// reopening an existing DB with the WRONG passphrase must FAIL CLOSED
    /// (spec §17.6) — never silently open a fresh, empty database.
    #[test]
    fn test_with_storage_py_sqlite_wrong_passphrase_fails_closed() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path().to_path_buf();

        let bi = PyBridgeInstance::with_storage_py(StorageConfig::Sqlite {
            path: dir.clone(),
            key: SqliteKeyMaterial::Passphrase(Zeroizing::new("the-right-passphrase".to_owned())),
        })
        .expect("initial passphrase open must succeed");
        let provider = bi
            .storage_provider()
            .cloned()
            .expect("storage provider present");
        test_rt().block_on(async {
            provider
                .store("scp-test/secret", b"top-secret")
                .await
                .expect("store secret");
        });
        drop(provider);
        drop(bi);

        // Reopen with the WRONG passphrase: must fail closed, no in-memory
        // fallback, no fresh empty DB.
        let result = PyBridgeInstance::with_storage_py(StorageConfig::Sqlite {
            path: dir,
            key: SqliteKeyMaterial::Passphrase(Zeroizing::new("the-wrong-passphrase".to_owned())),
        });
        assert!(
            matches!(result, Err(StorageInitError::SqliteOpen { .. })),
            "reopening with the wrong passphrase must fail closed with SqliteOpen"
        );
    }

    /// `SqliteKeyMaterial`'s custom `Debug` impl must NOT leak the key or
    /// passphrase bytes (defense in depth). Mirrors the NAPI/UniFFI redacting
    /// impls.
    #[test]
    fn test_sqlite_key_material_debug_redacts_secrets() {
        let raw = SqliteKeyMaterial::Raw(Zeroizing::new(vec![0xAB_u8; 32]));
        let raw_dbg = format!("{raw:?}");
        assert_eq!(raw_dbg, "SqliteKeyMaterial::Raw(<redacted 32 bytes>)");
        assert!(
            !raw_dbg.contains("ab") && !raw_dbg.contains("171"),
            "raw Debug must not contain key bytes: {raw_dbg}"
        );

        let secret = "super-secret-passphrase";
        let pass = SqliteKeyMaterial::Passphrase(Zeroizing::new(secret.to_owned()));
        let pass_dbg = format!("{pass:?}");
        assert_eq!(pass_dbg, "SqliteKeyMaterial::Passphrase(<redacted>)");
        assert!(
            !pass_dbg.contains(secret),
            "passphrase Debug must not contain the passphrase: {pass_dbg}"
        );
    }

    // -----------------------------------------------------------------------
    // Per-instance ContextManager attachment (bug-catcher follow-up, #1549)
    // -----------------------------------------------------------------------
    //
    // Regression: `init_context_manager*` previously always attached to the
    // default `DEFAULT_BRIDGE_INSTANCE`, ignoring the `bi` passed by newer
    // `PyScp::method` call paths. That meant a non-default `PyScp` instance
    // would appear to "work" while secretly wiring its `ContextManager` onto
    // the default bridge — breaking multi-instance isolation entirely.

    /// `init_context_manager_for_test(bi)` must attach the `ContextManager`
    /// to `bi.core` (not the default bridge instance).
    #[test]
    fn init_context_manager_for_test_respects_explicit_bi() {
        let bi_arc = std::sync::Arc::new(PyBridgeInstance::new_py());
        let bi = &*bi_arc;
        assert!(
            !bi.core.has_supervisor(),
            "fresh PyBridgeInstance must not have a ContextManager attached"
        );
        init_context_manager_for_test(bi);
        assert!(
            bi.core.has_supervisor(),
            "init_context_manager_for_test(bi) must attach a ContextManager to bi.core"
        );
    }

    /// Each freshly constructed `PyBridgeInstance` must be able to attach
    /// its own `ContextManager` in isolation, with no dependency on any
    /// other bridge instance.
    ///
    /// Before the fix, `init_context_manager_for_test()` silently targeted
    /// the since-deleted process-wide `DEFAULT_BRIDGE_INSTANCE`, so the
    /// explicit `bi` passed into it appeared unaffected. Phase D (#1695)
    /// deleted that default bridge and this test now verifies that two
    /// independent instances get independent managers.
    #[test]
    fn non_default_bi_gets_its_own_context_manager() {
        let bi_a = PyBridgeInstance::new_py();
        let bi_b = PyBridgeInstance::new_py();
        init_context_manager_for_test(&bi_a);
        init_context_manager_for_test(&bi_b);
        assert!(bi_a.core.has_supervisor());
        assert!(bi_b.core.has_supervisor());
        // Each instance holds a distinct Arc<ContextManager>.
        let cm_a = bi_a.core.try_supervisor().unwrap();
        let cm_b = bi_b.core.try_supervisor().unwrap();
        assert!(
            !Arc::ptr_eq(cm_a, cm_b),
            "distinct PyBridgeInstances must hold distinct ContextManager Arcs"
        );
    }

    /// `register_context(bi_b, ...)` must attach `bi_b`'s own `ContextManager`.
    ///
    /// Post-Phase D (#1695) there is no default bridge instance; this test
    /// still verifies that two independent instances get independent managers.
    #[test]
    fn register_context_on_non_default_bi_attaches_cm_to_bi() {
        let first = PyBridgeInstance::new_py();
        init_context_manager_for_test(&first);
        let first_manager = Arc::clone(first.core.try_supervisor().unwrap());

        let second = PyBridgeInstance::new_py();
        assert!(
            !second.core.has_supervisor(),
            "fresh bi must not inherit a ContextManager from another instance"
        );

        let ctx_id = unique_ctx_id("per-instance-cm");
        let creator = "did:dht:z6MkPerInstanceCm";
        register_context(&second, &ctx_id, creator, &[]).unwrap();

        assert!(
            second.core.has_supervisor(),
            "register_context(second, ...) must attach a ContextManager to it"
        );
        let second_manager = second.core.try_supervisor().unwrap();
        assert!(
            !Arc::ptr_eq(&first_manager, second_manager),
            "second bi must hold a distinct ContextManager — not the first's"
        );
    }

    /// `register_context` rejects a malformed ceiling entry (spec §5.3.1.1) at
    /// the bridge boundary: a single-token custom (`payments`) and stray-wildcard
    /// entries (`*:*`, `*:read`) and a multi-colon entry are all rejected, and NO
    /// FFI state is stored. Proves the `PyO3` reference bridge does not silently
    /// widen a no-colon custom into `payments:*`.
    #[test]
    fn register_context_rejects_malformed_ceiling_entry() {
        for bad in [
            "payments",
            "*:*",
            "*:read",
            "payments:read:write",
            "payments:wr*",
        ] {
            let bi = PyBridgeInstance::new_py();
            let ctx_id = unique_ctx_id("bad-ceiling");
            let creator = "did:dht:z6MkBadCeiling";
            let user_ceiling = vec!["messages:read".to_owned(), (*bad).to_owned()];
            let err = register_context(&bi, &ctx_id, creator, &user_ceiling)
                .expect_err("malformed ceiling entry must be rejected");
            assert!(
                err.to_string().contains("InvalidCeilingCategory"),
                "expected InvalidCeilingCategory for {bad:?}, got: {err}"
            );
            // Defense-in-depth: no FFI state was stored for the rejected context.
            assert!(
                with_ffi_state(&bi, &ctx_id, |_| Ok::<(), ScpPyError>(())).is_err(),
                "rejected context must not have stored FFI state for {bad:?}"
            );
        }
    }

    /// `register_context` accepts a well-formed custom ceiling entry, an explicit
    /// `{resource}:*` wildcard, the parameterized `outlet:call:{outlet_id}`
    /// built-in, and a built-in supplied in its canonical UCAN wire spelling
    /// (`outlet_call:*`, `context_child:create`, `bridging:*`,
    /// `outlet_call:{id}`). Pins the regression where a UCAN-form built-in entry
    /// — the canonical stored ceiling spelling — was misparsed to a `Custom`
    /// lookalike and rejected with `InvalidCeilingCategory`.
    #[test]
    fn register_context_accepts_wellformed_custom_ceiling() {
        for good in [
            "payments:approve",
            "payments:*",
            "outlet:call:calc",
            "outlet:call:*",
            "context:child:create",
            "outlet_call:*",
            "outlet_call:calc",
            "context_child:create",
            "bridging:*",
        ] {
            let bi = PyBridgeInstance::new_py();
            let ctx_id = unique_ctx_id("good-ceiling");
            let creator = "did:dht:z6MkGoodCeiling";
            let user_ceiling = vec!["messages:read".to_owned(), (*good).to_owned()];
            let result = register_context(&bi, &ctx_id, creator, &user_ceiling);
            assert!(
                result.is_ok(),
                "well-formed ceiling {good:?} must be accepted: {result:?}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Per-instance known-context registry (bug-catcher follow-up, #1549)
    // -----------------------------------------------------------------------
    //
    // Regression: `known_contexts_for_member`/`register_known_context` used
    // `bridge_instance()` internally, so discovery routed through the default
    // bridge even when called from a non-default `PyScp::load_contexts`.

    /// `register_known_context_on(bi_b, ...)` must persist into `bi_b`'s
    /// registry and be visible via `known_contexts_for_member_on(bi_b, ...)`.
    #[test]
    fn known_contexts_are_per_instance() {
        let bi_a = PyBridgeInstance::new_py();
        let bi_b = PyBridgeInstance::new_py();
        let member = "did:dht:z6MkPerInstanceKnown";
        let ctx_id = unique_ctx_id("known-per-instance");

        let known = KnownContext {
            routing_id: [0x11; 32],
            relay_url: Some("ws://127.0.0.1:9000/scp/v1".to_owned()),
            member_did: member.to_owned(),
            last_seen: 1_700_000_000,
        };

        // Register against bi_b only.
        register_known_context_on(&bi_b, &ctx_id, known);

        let found_b = known_contexts_for_member_on(&bi_b, member);
        assert!(
            found_b.iter().any(|(id, _)| id == &ctx_id),
            "bi_b must see its own registered known context"
        );

        // bi_a must NOT see bi_b's registration. Before the fix,
        // known_contexts_for_member routed through the default bridge, which
        // would have surfaced bi_b's entry on the default path.
        let found_a = known_contexts_for_member_on(&bi_a, member);
        assert!(
            !found_a.iter().any(|(id, _)| id == &ctx_id),
            "bi_a must NOT see known contexts registered against bi_b"
        );
    }

    /// `all_known_contexts_on(bi)` is per-instance.
    #[test]
    fn all_known_contexts_is_per_instance() {
        let bi_a = PyBridgeInstance::new_py();
        let bi_b = PyBridgeInstance::new_py();
        let ctx_id = unique_ctx_id("all-known-per-instance");
        let known = KnownContext {
            routing_id: [0x22; 32],
            relay_url: None,
            member_did: "did:dht:z6MkAllKnownPerInstance".to_owned(),
            last_seen: 0,
        };

        register_known_context_on(&bi_a, &ctx_id, known);

        let list_a = all_known_contexts_on(&bi_a);
        let list_b = all_known_contexts_on(&bi_b);
        assert!(list_a.iter().any(|(id, _)| id == &ctx_id));
        assert!(
            !list_b.iter().any(|(id, _)| id == &ctx_id),
            "bi_b must not see bi_a's known contexts"
        );
    }

    // -----------------------------------------------------------------------
    // Saga-journal swap: fail-closed proof (PyO3 reference bridge). The
    // structural `pipeline_wiring.rs` gate is presence-only. The SAME-backend
    // property is now enforced BY CONSTRUCTION: `durable_providers_from_bi`
    // returns a `DurableProviders` whose only non-test constructor
    // (`DurableProviders::from_handle`) derives the journal AND the `mls_storage`
    // view from ONE handle, so a divergent wiring is a compile error rather than
    // a runtime defect. The single same-backend behavioral proof on
    // `from_handle` lives next to it in `scp-runtime`
    // (`durable_providers_from_handle_shares_one_backend`), where the bundled
    // journal is reachable for an append/read-back. This test pins the remaining
    // bridge-specific behavior the type cannot encode: the fail-closed
    // STORAGE_8000 refusal when no storage provider has been selected.
    // -----------------------------------------------------------------------

    /// Fail-closed behavioral proof. `durable_providers_from_bi` on a bridge
    /// instance with NO storage provider must return the `STORAGE_8000`
    /// storage-before-supervisor error rather than attaching a Noop/absent
    /// journal. This is the per-bridge fail-closed guard that source-text gates
    /// alone cannot prove behaviorally.
    #[test]
    fn durable_providers_from_bi_fails_closed_without_storage_provider() {
        // A bare bridge instance with no storage provider selected.
        let bi = PyBridgeInstance::new_py();
        assert!(
            bi.storage_provider().is_none(),
            "precondition: the bare bridge instance has no storage provider"
        );

        // Reduce the result to the error code without panicking on success:
        // `Ok` -> None (no error code), the wrong error variant -> a sentinel
        // that fails the STORAGE_8000 assertion below.
        let observed_code = match durable_providers_from_bi(&bi) {
            Ok(_) => None,
            Err(ScpPyError::ContextError { code, .. }) => Some(code),
            Err(other) => Some(format!("unexpected-error-variant: {other:?}")),
        };
        assert_eq!(
            observed_code.as_deref(),
            Some(scp_ffi_common::error_codes::STORAGE_8000),
            "durable_providers_from_bi MUST fail closed with STORAGE_8000 when no storage \
             provider is set (not attach a Noop/absent journal); observed {observed_code:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Live supervisor state is the only authorization source
    // -----------------------------------------------------------------------

    /// `live_role_state` fails closed when the context has no supervisor actor,
    /// so no caller receives a permissive default in place of a membership
    /// record it could not read.
    #[test]
    fn live_role_state_fails_closed_without_a_supervisor_actor() {
        crate::init_runtime().ok();
        let bi = Arc::new(PyBridgeInstance::new_py());
        let ctx_id = unique_ctx_id("live-no-actor");
        // FFI state exists; the supervisor never created the context.
        register_context(&bi, &ctx_id, "did:dht:z6MkLiveNoActor", &[]).unwrap();

        let err = live_role_state(&bi, &ctx_id)
            .expect_err("a context with no supervisor role state must refuse to authorize");
        assert!(
            format!("{err:?}").contains("no live supervisor role state"),
            "the refusal must name the absent supervisor role state: {err:?}"
        );
    }

    /// `context_ids_for_member` reports a member the SUPERVISOR recorded and the
    /// bridge never wrote down. Reading a bridge-local roster omitted that
    /// member, so this test fails if the function goes back to one.
    #[test]
    fn context_ids_for_member_reads_supervisor_membership() {
        let creator = "did:dht:z6MkIdsForMemberCreator";
        let member = "did:dht:z6MkIdsForMemberJoiner";
        let (bi, ctx_id) = live_state_fixture("ids-for-member", creator, &[]);

        assert!(
            !context_ids_for_member(&bi, member).contains(&ctx_id),
            "precondition: the member is not in the context yet"
        );

        insert_supervisor_member_for_test(&bi, &ctx_id, member);

        assert!(
            context_ids_for_member(&bi, member).contains(&ctx_id),
            "a member the supervisor recorded must be reported, with no bridge-side write"
        );
        remove_context(&bi, &ctx_id);
    }

    /// `live_ceiling_strings` returns the ceiling the SUPERVISOR holds, not the
    /// `default_ceiling()` a bridge-local copy carried. The fixture registers FFI
    /// state with an empty ceiling argument and gives the supervisor a narrower
    /// one, so a copy-reading implementation reports the wider default and fails
    /// the exclusion below.
    #[test]
    fn live_ceiling_strings_reads_the_supervisor_ceiling() {
        let creator = "did:dht:z6MkLiveCeilingCreator";
        let (bi, ctx_id) = live_state_fixture(
            "live-ceiling",
            creator,
            &["messages:read", "messages:write"],
        );

        let ceiling = live_ceiling_strings(&bi, &ctx_id).unwrap();
        assert!(
            ceiling.contains("messages:write"),
            "the supervisor ceiling entry must be present: {ceiling:?}"
        );
        assert!(
            !ceiling.contains("outlet_register:*") && !ceiling.contains("outlet_call:*"),
            "entries the supervisor ceiling omits must be absent — a default-ceiling copy \
             would carry them: {ceiling:?}"
        );
        remove_context(&bi, &ctx_id);
    }

    /// `live_role_state` answers from inside `Runtime::block_on`, the regime a
    /// bridge method enters when it drives an async supervisor call and then
    /// needs an authorization read. A plain `Runtime::block_on` here would panic
    /// with "Cannot start a runtime from within a runtime".
    #[test]
    fn live_role_state_answers_from_inside_block_on() {
        let creator = "did:dht:z6MkRegimeBlockOnCreator";
        let (bi, ctx_id) = live_state_fixture("regime-block-on", creator, &[]);

        let rt = crate::runtime().unwrap();
        let answer = rt.block_on(async { live_role_state(&bi, &ctx_id) });
        assert_eq!(
            answer
                .expect("the read must answer from inside block_on")
                .creator_did,
            creator
        );
        remove_context(&bi, &ctx_id);
    }

    /// `live_role_state` answers from inside a spawned task, the regime the MCP
    /// server's `ContextProvider` methods run in: a synchronous trait method on a
    /// runtime worker thread, where `Runtime::block_on` panics and
    /// `block_in_place` is the legal bridge.
    #[test]
    fn live_role_state_answers_from_inside_a_spawned_task() {
        let creator = "did:dht:z6MkRegimeSpawnedCreator";
        let (bi, ctx_id) = live_state_fixture("regime-spawned", creator, &[]);

        let rt = crate::runtime().unwrap();
        let bi_for_task = Arc::clone(&bi);
        let ctx_for_task = ctx_id.clone();
        let answer = rt.block_on(async move {
            rt.spawn(async move { live_role_state(&bi_for_task, &ctx_for_task) })
                .await
                .expect("the spawned task must not panic")
        });
        assert_eq!(
            answer
                .expect("the read must answer from inside a spawned task")
                .creator_did,
            creator
        );
        remove_context(&bi, &ctx_id);
    }
}
