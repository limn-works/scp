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
use scp_ffi_common::bridge_instance::BridgeInstanceCore;
// Re-export `CoreFields` at `crate::runtime::CoreFields` so the
// `napi_check_handle!` macro can refer to it as `$crate::runtime::CoreFields`
// without each caller importing the full `scp_ffi_common` path.
pub use scp_ffi_common::bridge_instance::CoreFields;
use scp_ffi_common::bridge_runtime::BridgeInMemoryStorageHandle;
use scp_ffi_common::error_codes as codes;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};

use dashmap::DashMap;
use scp_core::context::builder::{ContextEventLogProvider, ContextTransportProvider};
use scp_core::context::persistence::ContextPersistence;
use scp_core::context::roles::{ContextRoleState, default_ceiling};
use scp_core::context::state::ContextSnapshot;
use scp_core::context::tools::{SessionStore, ToolRegistry};
use scp_core::crypto::ucan::nonce::NonceTracker;
use scp_core::crypto::ucan::revoke::RevocationList;
use scp_core::store::ProtocolRepository;
use scp_event_log::EventLog;
use scp_identity::cache::SystemClock;

use crate::context::NapiContextHandle;
use crate::error::ScpNapiError;

// ---------------------------------------------------------------------------
// NapiBridgeInstance — per-bridge concrete bridge instance (#1549 Phase 4 PR 1)
// ---------------------------------------------------------------------------

/// Storage configuration for `NapiBridgeInstance`.
///
/// Two variants are supported:
/// - [`StorageConfig::InMemory`] — encrypted in-memory storage (ephemeral).
/// - [`StorageConfig::Sqlite`] — SQLCipher-encrypted storage on disk at
///   `{path}/scp.db`, wired through [`scp_platform::sqlite::SqliteStorage`].
///
/// Kept here (not in `scp-ffi-common`) because each bridge owns its own
/// storage shape until a shared type lands.
#[derive(Debug, Clone, Default)]
pub enum StorageConfig {
    /// Encrypted in-memory storage.
    #[default]
    InMemory,
    /// SQLCipher-encrypted on-disk storage at `{path}/scp.db`.
    ///
    /// Persists context snapshots, identity state, and the event log
    /// across process restarts. The encryption key material is selected via
    /// [`SqliteKeyMaterial`] — either raw key bytes or a passphrase run
    /// through Argon2id (spec §17.6). Both forms are held in `Zeroizing` so
    /// the caller's copy is wiped after the variant is consumed.
    Sqlite {
        /// Directory the database file is created in.
        path: std::path::PathBuf,
        /// Encryption key material — raw bytes or passphrase (mutually
        /// exclusive; the [`SqliteKeyMaterial`] sum type enforces "exactly
        /// one").
        key: SqliteKeyMaterial,
    },
}

/// `SQLCipher` key-material selector for [`StorageConfig::Sqlite`] (spec §17.6).
///
/// The caller supplies EITHER raw key material OR a passphrase — never both,
/// never neither. The sum type makes that mutual exclusion unrepresentable as
/// an invalid state: there is exactly one happy path per variant. Both forms
/// are wrapped in `Zeroizing` so they are wiped from memory on drop. This
/// mirrors the `PyO3` and `UniFFI` bridges' `SqliteKeyMaterial`.
///
/// - [`SqliteKeyMaterial::Raw`] feeds [`SqliteStorage::new`] directly (raw-key
///   mode; the existing, unchanged path).
/// - [`SqliteKeyMaterial::Passphrase`] feeds
///   [`SqliteStorage::with_passphrase`], which derives the `SQLCipher` PRAGMA
///   key from the passphrase via the shared Argon2id parameterization with a
///   persisted per-database salt sidecar.
#[derive(Clone)]
pub enum SqliteKeyMaterial {
    /// Raw encryption key material (32 bytes recommended).
    Raw(zeroize::Zeroizing<Vec<u8>>),
    /// Human-chosen passphrase; the `SQLCipher` key is derived via Argon2id.
    Passphrase(zeroize::Zeroizing<String>),
}

impl std::fmt::Debug for SqliteKeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the key or passphrase bytes — only the variant and a
        // length hint for the raw case (defense in depth). Mirrors the PyO3 /
        // UniFFI redacting impl.
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

/// Bridge-internal error returned by
/// [`NapiBridgeInstance::with_storage_napi`] when a durable storage backend
/// cannot be opened.
///
/// Surfacing this (rather than silently degrading to in-memory or no storage)
/// is the fail-closed contract from spec §17.6: a failed durable-backend open
/// is a terminal error the caller observes, never a condition the system
/// recovers from by downgrading durability. Converted to a JS-thrown
/// `ValidationError` at the [`crate::scp::Scp::with_storage`] factory surface.
///
/// Mirrors the `PyO3` and `UniFFI` bridges' `StorageInitError`. The message
/// never contains key or passphrase bytes.
#[derive(Debug)]
pub enum StorageInitError {
    /// `SqliteStorage::new` / `SqliteStorage::with_passphrase` failed —
    /// directory permission denied, key/passphrase rejected by `SQLCipher` on
    /// an existing DB, salt-sidecar fail-closed condition, corrupt file, and
    /// so on. The message never carries key or passphrase bytes.
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

// `ProtocolRepoVariant` lives in `scp-ffi-common::bridge_runtime`. Re-exported
// here so existing `crate::runtime::ProtocolRepoVariant` references across
// the NAPI bridge keep compiling without mass rename. See ADR-048 §2 for
// the "shared-variant types for storage-backed repositories" exemption.
pub use scp_ffi_common::bridge_runtime::ProtocolRepoVariant;

/// NAPI-specific concrete bridge instance.
///
/// Embeds the bridge-agnostic [`CoreFields`] and adds typed fields for the
/// NAPI-specific registries (UCAN state, identity state, protocol
/// repository). The MCP registries continue to live in [`crate::mcp`] as
/// their own `OnceLock`s during PR 1 — they move onto this struct in PR 2.
///
/// Constructed via [`NapiBridgeInstance::new_napi`] /
/// [`NapiBridgeInstance::with_persistence_napi`] /
/// [`NapiBridgeInstance::with_storage_napi`]. Each `#[napi] Scp` owns an
/// `Arc<NapiBridgeInstance>` exclusively — there is no process-global
/// default bridge (the legacy default bridge was deleted in Phase D).
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
    /// Previously stored type-erased in `CoreFields::protocol_repository`,
    /// then as a concrete `Arc<ProtocolRepository<EncryptingAdapter<...>>>`
    /// regardless of configured storage. Now a variant so that
    /// [`StorageConfig::Sqlite`] also routes event log entries and trust
    /// attestations into the `SQLCipher` database.
    ///
    /// See [`ProtocolRepoVariant`] for the dispatch details.
    pub(crate) protocol_repository: ProtocolRepoVariant,

    /// The single chosen `Storage` backend, erased ONCE into the supervisor's
    /// required `mls_storage` (`OpenMLS`) view via
    /// [`SpawnBlockingStorageAdapter`](scp_core::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter):
    /// - in-memory path → the un-swallowed
    ///   `Arc<EncryptingAdapter<BridgeInMemoryStorage>>` handle (3rd element
    ///   returned by `build_event_log_provider`);
    /// - `SQLite` path → the same `Arc<SqliteStorage>` that backs persistence
    ///   and the event log.
    ///
    /// `build_supervisor_arc` reads this to satisfy the required `mls_storage`
    /// argument of `Supervisor::with_providers`. The runtime never defaults
    /// storage (spec §17.6 / ADR-049); `None` is the
    /// storage-before-supervisor fail-closed condition. Note that
    /// `NapiBridgePersistence` (a `DashMap`) is NOT a `Storage` and therefore
    /// can never back `mls_storage` — the in-memory `mls_storage` always
    /// comes from the `build_event_log_provider` handle.
    pub(crate) mls_storage_backend:
        Option<Arc<dyn scp_core::crypto::mls::storage_adapter::OpenMlsStorageAdapter>>,

    // -----------------------------------------------------------------
    // #1549 Phase 4 PR 2 commit 1 — additive typed fields replacing
    // process-global singletons in later commits.
    // -----------------------------------------------------------------
    /// MCP server registry (replaces `mcp_server_registry` `OnceLock` in
    /// `mcp.rs`).
    ///
    /// Migrated from a process-global
    /// `OnceLock<DashMap<String, McpServerEntry>>` singleton in commit 4.
    /// Cleared by [`BridgeInstanceCore::bridge_specific_shutdown`].
    pub(crate) mcp_server_registry: Arc<DashMap<String, crate::mcp::McpServerEntry>>,

    /// MCP client registry (replaces `mcp_client_registry` `OnceLock` in
    /// `mcp.rs`).
    ///
    /// Migrated from a process-global
    /// `OnceLock<DashMap<String, McpClientEntry>>` singleton in commit 4.
    /// Cleared by [`BridgeInstanceCore::bridge_specific_shutdown`].
    pub(crate) mcp_client_registry: Arc<DashMap<String, crate::mcp::McpClientEntry>>,

    /// Shared full-stack test network (replaces `NETWORK` in `testing.rs`).
    ///
    /// Migrated from a process-global
    /// `std::sync::Mutex<Option<FullStackNetwork>>` singleton in commit 9.
    /// Feature-gated behind `allow_in_memory_custody` to mirror `testing.rs`.
    #[cfg(feature = "allow_in_memory_custody")]
    pub(crate) network: std::sync::Mutex<Option<scp_testing::fullstack::FullStackNetwork>>,

    /// Bounds concurrent compromise-recovery and custody-migration calls.
    ///
    /// `Scp::identity_execute_recovery` and
    /// `Scp::identity_execute_custody_migration` drive an async orchestrator
    /// via `crate::runtime().block_on(...)` on the napi-rs worker thread.
    /// Each in-flight call pins one libuv worker for the duration of the
    /// `block_on` — the default libuv pool has 4 threads, so a realm-local
    /// attacker (or a buggy app) issuing concurrent recovery requests against
    /// valid DIDs could saturate the pool and starve every other NAPI async
    /// callback.
    ///
    /// The permit cap is enforced via `try_acquire_owned` (non-blocking): if
    /// no permit is available the call returns `SCP-VALID-7140` immediately
    /// rather than queueing on the semaphore, which would itself pin a libuv
    /// worker on the permit wait. The cap is deliberately small
    /// (see [`RECOVERY_CONCURRENCY_CAP`]) so that an attacker flooding
    /// recovery calls burns negligible work per rejected request.
    ///
    /// Shared between recovery and migration because both issue the same
    /// shape of work (async orchestrator on the module runtime) and a
    /// single cap is simpler to reason about than two separate ones.
    ///
    /// Closes RED-PR5-002 / BLACK-PR5-002 (#1549).
    pub(crate) recovery_semaphore: Arc<tokio::sync::Semaphore>,

    /// Per-instance bridge credential store (spec §12.11).
    ///
    /// Mirrors `PyBridgeInstance::credential_store` — each `Scp` instance
    /// owns its own `InMemoryCredentialStore` so that OAuth tokens, API
    /// keys, and bridge credential keys provisioned through one bridge
    /// instance are isolated from every other instance in the same process
    /// (ADR-048 §1 multi-instance neutrality). The store is thread-safe via
    /// its internal `tokio::sync::RwLock`. Production deployments should
    /// replace this with a `Storage`-backed implementation when it lands
    /// (spec §12.11.2). Dropping the `Arc` on shutdown zeroizes any retained
    /// bridge credential keys via the store's `Zeroizing` fields — there is no
    /// explicit clear step in `bridge_specific_shutdown`, so the store lives
    /// exactly as long as its last `Arc` reference.
    pub(crate) credential_store: Arc<scp_core::bridge::credentials::InMemoryCredentialStore>,
}

/// Permit cap for [`NapiBridgeInstance::recovery_semaphore`].
///
/// Bounds the number of concurrent `block_on`-driven
/// `identityExecuteRecovery` + `identityExecuteCustodyMigration` calls on a
/// single NAPI bridge instance. Chosen to allow at most one recovery plus
/// one migration (or two of one) to run simultaneously while leaving the
/// remaining libuv workers free for other NAPI async callbacks. The
/// happy-path caller sees no throttling; a misbehaving or hostile caller
/// gets `SCP-VALID-7140` on the N+1 concurrent invocation.
pub(crate) const RECOVERY_CONCURRENCY_CAP: usize = 2;

impl NapiBridgeInstance {
    /// Constructs a new `NapiBridgeInstance` with default in-memory state.
    ///
    /// Allocates a fresh `CoreFields` (new `instance_id`, new
    /// `CancellationToken`, empty `JoinSet`) and populates the protocol
    /// repository + typed registries. No `ContextManager` is attached —
    /// callers attach one later via `CoreFields::set_context_manager`.
    #[must_use]
    pub fn new_napi() -> Self {
        let (_event_log, protocol_repository, storage_handle) =
            scp_ffi_common::bridge_runtime::build_event_log_provider();
        // The un-swallowed in-memory storage handle backs the supervisor's
        // `mls_storage` view. The SAME store backs the event-log repository
        // above (spec §17.6 — one chosen backend, derived consumers). This is
        // the in-memory storage source for `mls_storage` — NOT
        // `NapiBridgePersistence`, which is a `DashMap` and not a `Storage`.
        let mls_storage_backend = mls_storage_from_handle(storage_handle);
        Self {
            core: CoreFields::new(),
            ucan_registry: Arc::new(DashMap::new()),
            #[cfg(feature = "allow_in_memory_custody")]
            identity_registry: Arc::new(DashMap::new()),
            protocol_repository: ProtocolRepoVariant::InMemory(protocol_repository),
            mls_storage_backend: Some(mls_storage_backend),
            mcp_server_registry: Arc::new(DashMap::new()),
            mcp_client_registry: Arc::new(DashMap::new()),
            #[cfg(feature = "allow_in_memory_custody")]
            network: std::sync::Mutex::new(None),
            recovery_semaphore: Arc::new(tokio::sync::Semaphore::new(RECOVERY_CONCURRENCY_CAP)),
            credential_store: Arc::new(
                scp_core::bridge::credentials::InMemoryCredentialStore::new(),
            ),
        }
    }

    /// Constructs a new `NapiBridgeInstance` with an explicit
    /// [`ContextPersistence`] provider.
    ///
    /// Used by callers that already have a persistence strategy (typically
    /// unit tests; production persistence is wired through PR 3's
    /// [`StorageConfig::InMemory`] path on `NapiBridgeInstance::with_storage_napi`).
    #[must_use]
    pub fn with_persistence_napi(persistence: Box<dyn ContextPersistence + Send + Sync>) -> Self {
        let (_event_log, protocol_repository, storage_handle) =
            scp_ffi_common::bridge_runtime::build_event_log_provider();
        let mls_storage_backend = mls_storage_from_handle(storage_handle);
        Self {
            core: CoreFields::with_persistence(persistence),
            ucan_registry: Arc::new(DashMap::new()),
            #[cfg(feature = "allow_in_memory_custody")]
            identity_registry: Arc::new(DashMap::new()),
            protocol_repository: ProtocolRepoVariant::InMemory(protocol_repository),
            mls_storage_backend: Some(mls_storage_backend),
            mcp_server_registry: Arc::new(DashMap::new()),
            mcp_client_registry: Arc::new(DashMap::new()),
            #[cfg(feature = "allow_in_memory_custody")]
            network: std::sync::Mutex::new(None),
            recovery_semaphore: Arc::new(tokio::sync::Semaphore::new(RECOVERY_CONCURRENCY_CAP)),
            credential_store: Arc::new(
                scp_core::bridge::credentials::InMemoryCredentialStore::new(),
            ),
        }
    }

    /// Constructs a new `NapiBridgeInstance` honoring a [`StorageConfig`].
    ///
    /// - [`StorageConfig::InMemory`] — equivalent to
    ///   `NapiBridgeInstance::new_napi`; the supervisor's `mls_storage` view is
    ///   backed by the same encrypted in-memory store as the event log
    ///   (dev/test affordance; spec §17.6).
    /// - [`StorageConfig::Sqlite`] — opens a `SQLCipher`-encrypted database at
    ///   `{path}/scp.db`. The raw-key path feeds [`SqliteStorage::new`]; the
    ///   passphrase path feeds [`SqliteStorage::with_passphrase`] (Argon2id;
    ///   spec §17.6). The ONE `Arc<SqliteStorage>` backs the context-snapshot
    ///   persistence bridge, the Merkle event log + trust aggregation
    ///   repository, AND the supervisor's `mls_storage` `OpenMLS` view, so all
    ///   three consumers share a single `SQLCipher` connection. Downstream
    ///   `init_supervisor*` picks the shared persistence `Arc` up via
    ///   `persistence_arc_clone()`.
    ///
    /// # Errors
    ///
    /// Returns [`StorageInitError::SqliteOpen`] if the `SQLCipher` database
    /// cannot be opened (bad key/passphrase, permission denied, corrupt file,
    /// or a salt-sidecar fail-closed condition). FAIL CLOSED (spec §17.6): the
    /// bridge does NOT silently degrade to in-memory or no-storage on a failed
    /// durable-backend open. The error is surfaced to the `SCP.withStorage`
    /// factory and thrown as a JS `ValidationError`.
    pub fn with_storage_napi(config: StorageConfig) -> Result<Self, StorageInitError> {
        match config {
            StorageConfig::InMemory => Ok(Self::new_napi()),
            StorageConfig::Sqlite { path, key } => {
                // Open the database ONCE — the same `Arc<SqliteStorage>` is
                // shared across persistence, event log, and `mls_storage` (a
                // second open would hit `SQLITE_BUSY` on first write).
                let open_result = match &key {
                    SqliteKeyMaterial::Raw(bytes) => {
                        scp_platform::sqlite::SqliteStorage::new(&path, bytes)
                    }
                    SqliteKeyMaterial::Passphrase(pass) => {
                        scp_platform::sqlite::SqliteStorage::with_passphrase(&path, pass.as_bytes())
                    }
                };
                // Zero our copy of the raw key / passphrase regardless of
                // outcome. The error message never carries key bytes.
                drop(key);

                let storage = open_result.map_err(|e| {
                    // FAIL CLOSED (spec §17.6): surface the error rather than
                    // degrading to in-memory. No silent fallback.
                    tracing::error!(
                        error = %e,
                        path = %path.display(),
                        "with_storage_napi: SQLCipher open failed — failing closed, no in-memory fallback"
                    );
                    StorageInitError::SqliteOpen {
                        path: path.display().to_string(),
                        message: e.to_string(),
                    }
                })?;

                let arc_storage = Arc::new(storage);
                // The same `Arc<SqliteStorage>` backs the context-snapshot
                // persistence bridge, the Merkle event log + trust aggregation
                // repository, AND the supervisor's `mls_storage` `OpenMLS`
                // view.
                let persistence_repo = Arc::new(ProtocolRepository::new(Arc::clone(&arc_storage)));
                let persistence: Arc<dyn ContextPersistence + Send + Sync> = Arc::new(
                    scp_core::store::context::ProtocolRepositoryContextBridge::new(
                        persistence_repo,
                    ),
                );
                let event_log_repo = Arc::new(ProtocolRepository::new(Arc::clone(&arc_storage)));
                // Derive the supervisor's `mls_storage` view from the same
                // `Arc<SqliteStorage>` — erased ONCE via
                // `SpawnBlockingStorageAdapter`.
                let mls_storage_backend = mls_storage_from_handle(Arc::clone(&arc_storage));
                drop(arc_storage);

                Ok(Self::with_persistence_napi_arc_and_repo(
                    persistence,
                    ProtocolRepoVariant::Sqlite(event_log_repo),
                    mls_storage_backend,
                ))
            }
        }
    }

    /// Internal helper: constructs a new `NapiBridgeInstance` pre-populated
    /// with a shared [`ContextPersistence`] provider.
    ///
    /// Accepts an `Arc<dyn ContextPersistence + Send + Sync>` so the same
    /// persistence provider is later picked up by
    /// `init_context_manager*` via
    /// [`scp_ffi_common::bridge_instance::CoreFields::persistence_arc_clone`],
    /// avoiding duplicate `SqliteStorage` connections to the same database.
    /// Constructs a `NapiBridgeInstance` with both the
    /// [`ContextPersistence`] provider and the [`ProtocolRepoVariant`]
    /// explicitly configured.
    ///
    /// `with_storage_napi(StorageConfig::Sqlite)` uses this so the event log
    /// repository and the snapshot persistence bridge share a single
    /// `Arc<SqliteStorage>`.
    #[must_use]
    fn with_persistence_napi_arc_and_repo(
        persistence: Arc<dyn ContextPersistence + Send + Sync>,
        protocol_repository: ProtocolRepoVariant,
        mls_storage_backend: Arc<dyn scp_core::crypto::mls::storage_adapter::OpenMlsStorageAdapter>,
    ) -> Self {
        Self {
            core: CoreFields::with_persistence_arc(persistence),
            ucan_registry: Arc::new(DashMap::new()),
            #[cfg(feature = "allow_in_memory_custody")]
            identity_registry: Arc::new(DashMap::new()),
            protocol_repository,
            mls_storage_backend: Some(mls_storage_backend),
            mcp_server_registry: Arc::new(DashMap::new()),
            mcp_client_registry: Arc::new(DashMap::new()),
            #[cfg(feature = "allow_in_memory_custody")]
            network: std::sync::Mutex::new(None),
            recovery_semaphore: Arc::new(tokio::sync::Semaphore::new(RECOVERY_CONCURRENCY_CAP)),
            credential_store: Arc::new(
                scp_core::bridge::credentials::InMemoryCredentialStore::new(),
            ),
        }
    }

    /// Returns the supervisor's `mls_storage` (`OpenMLS`) backend for this
    /// bridge instance, if populated.
    ///
    /// Populated at construction time from the single chosen `Storage`
    /// backend (erased once via
    /// [`SpawnBlockingStorageAdapter`](scp_core::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter)).
    /// `build_supervisor_arc` reads it to satisfy the required `mls_storage`
    /// argument of `Supervisor::with_providers`; a `None` here is the
    /// storage-before-supervisor fail-closed condition (spec §17.6).
    #[must_use]
    pub(crate) fn mls_storage_ref(
        &self,
    ) -> Option<&Arc<dyn scp_core::crypto::mls::storage_adapter::OpenMlsStorageAdapter>> {
        self.mls_storage_backend.as_ref()
    }

    /// Returns the monotonic instance id for this bridge.
    #[must_use]
    pub const fn instance_id(&self) -> u64 {
        self.core.instance_id()
    }

    /// Returns a reference to the MCP server registry.
    ///
    /// `pub(crate)` because `McpServerEntry` is itself `pub(crate)`.
    #[must_use]
    pub(crate) const fn mcp_server_registry(
        &self,
    ) -> &Arc<DashMap<String, crate::mcp::McpServerEntry>> {
        &self.mcp_server_registry
    }

    /// Returns a reference to the MCP client registry.
    ///
    /// `pub(crate)` — see `mcp_server_registry`.
    #[must_use]
    pub(crate) const fn mcp_client_registry(
        &self,
    ) -> &Arc<DashMap<String, crate::mcp::McpClientEntry>> {
        &self.mcp_client_registry
    }

    /// Returns a reference to this instance's bridge credential store.
    ///
    /// Mirrors `PyBridgeInstance::credential_store`. The returned
    /// `Arc<InMemoryCredentialStore>` is the same instance the
    /// `NapiBridgeInstance` holds — thread-safe via internal
    /// `tokio::sync::RwLock`.
    #[must_use]
    pub const fn credential_store(
        &self,
    ) -> &Arc<scp_core::bridge::credentials::InMemoryCredentialStore> {
        &self.credential_store
    }

    /// Returns a reference to the shared full-stack test network slot.
    #[cfg(feature = "allow_in_memory_custody")]
    #[must_use]
    pub const fn network(
        &self,
    ) -> &std::sync::Mutex<Option<scp_testing::fullstack::FullStackNetwork>> {
        &self.network
    }

    /// Returns a reference to the attached `Supervisor`, if any.
    ///
    /// Inherent method mirror of the free [`supervisor`] helper. Unlike the
    /// free helper this does NOT check suspension/shutdown state — it simply
    /// reflects whether a `Supervisor` has been attached to the embedded
    /// `CoreFields` via
    /// [`scp_ffi_common::bridge_instance::CoreFields::set_supervisor`].
    ///
    /// Callers that need suspension-aware error reporting should use the
    /// free [`supervisor`] helper instead; callers that want raw access
    /// (e.g. `Scp::method` paths that already guard lifecycle explicitly)
    /// use this method.
    #[must_use]
    pub fn try_supervisor(&self) -> Option<&Arc<scp_core::context::supervisor::Supervisor>> {
        self.core.try_supervisor()
    }
}

#[async_trait]
impl BridgeInstanceCore for NapiBridgeInstance {
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
        // Clear typed registries. Dropping `Arc<OpaqueInMemoryKeyCustody>`
        // values zeroizes any key material they hold via the custody
        // provider's `Drop` impl (matching the behavior of the previous
        // `clear_fn` closures).
        self.ucan_registry.clear();
        #[cfg(feature = "allow_in_memory_custody")]
        self.identity_registry.clear();
        // Release the SQLite advisory lock on `{dir}/scp.db.lock` for the
        // `Sqlite` variant. Other `Arc<SqliteStorage>` holders
        // (`CoreFields::persistence`, `ContextManager`) keep the storage
        // struct alive until the `NapiBridgeInstance` drops, but the
        // advisory lock must be released now so that a subsequent
        // `new SCP({ storage: { type: 'sqlite', path, key } })` against
        // the same directory does not fail with "already open by another
        // SCP instance". The `InMemory` variant's `close()` is a no-op.
        self.protocol_repository.close();
        // Clear MCP registries so server shutdown senders and client
        // connections drop, allowing background tasks to terminate cleanly.
        // Migrated off `crate::mcp::clear_registries` (called by a
        // shutdown-hook closure) in #1549 Phase 4 PR 2 commit 4.
        self.mcp_server_registry.clear();
        self.mcp_client_registry.clear();
        // Reset the full-stack test network slot. Best-effort: on lock
        // poisoning we leave the slot alone — a poisoned mutex means
        // another thread panicked while holding it, which is a larger
        // problem than a stale `FullStackNetwork` reference.
        #[cfg(feature = "allow_in_memory_custody")]
        if let Ok(mut net) = self.network.lock() {
            *net = None;
        }
    }
}

/// Emergency cancellation for `NapiBridgeInstance` dropped without a
/// prior `shutdown(timeout)`.
///
/// The graceful path is `BridgeInstanceCore::shutdown(timeout)` — callers
/// that want deterministic cleanup of subscriptions, timers, and relay
/// connections must still invoke that. This `Drop` is the safety net for
/// the case where a caller constructs a `NapiBridgeInstance` (typically
/// via `Scp::new` on the JS/TS side), spawns background work (the
/// `context_subscribe` task in particular captures an
/// `Arc<NapiBridgeInstance>` for the lifetime of the subscription), and
/// then drops the SCP without awaiting `shutdown(timeout)`. Without this
/// impl, those tasks hold their captures forever and leak a
/// `ContextManager`, relay connection, and attached JS threadsafe
/// functions.
///
/// See ADR-048 for the multi-instance lifecycle contract.
impl Drop for NapiBridgeInstance {
    fn drop(&mut self) {
        self.core.emergency_cancel_tasks();
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
/// # Why this remains a process-global after the #1549 Phase 4 singleton purge
///
/// Every other bridge-level `OnceLock` was migrated onto
/// `NapiBridgeInstance` so that an `SCP` instance can be constructed, used,
/// and dropped without leaking state into a second instance. `SHARED_DHT_CLIENT`
/// intentionally stays process-global because the cross-identity Alice+Bob
/// integration flows published and read from a single in-memory DHT:
///
///   1. `Alice.identity_create(...)` publishes a DID document into the DHT.
///   2. `Bob.ucan_validate(token_minted_by_alice)` must resolve Alice's DID
///      document to verify her signature — in the **same process** — using
///      the **same DHT instance** Alice published to.
///
/// If this were per-bridge, Alice's document would land in her instance's DHT
/// and Bob's resolver would see an empty DHT, and the test would spuriously
/// report a missing DID document. That was the behaviour before #1144, and it
/// broke every parity test that exercises multi-identity UCAN paths.
///
/// Production ecosystems do not share this constraint because they use real
/// `did:dht` (Mainline DHT, bittorrent BEP44) or `did:web` resolvers backed by
/// the public network, not an in-memory stub. The `InMemoryDhtClient` is a
/// test/demo affordance; its process-global scope matches the scope of the
/// network it is emulating, and it stores only signed, public DID documents.
///
/// # Ratchet justification
///
/// The #1549 Phase 4 PR 2 plan explicitly retains `SHARED_DHT_CLIENT` alongside
/// the legacy default bridge, `RUNTIME`, `HANDLE_COUNT`, and `INSTANCE_ID_COUNTER`
/// in the enforcement allowlist. See `scripts/check-no-bridge-globals.sh`.
///
/// See issue #1144 (UCAN validation tests require shared DHT state).
static SHARED_DHT_CLIENT: OnceLock<Arc<scp_identity::InMemoryDhtClient>> = OnceLock::new();

/// Returns the production DID resolver on the given bridge instance, if
/// initialized.
///
/// Reads the bridge instance's embedded [`CoreFields`] and returns its
/// configured DID resolver. The resolver is a shared, thread-safe handle
/// to an [`scp_ffi_common::IdentityBackedDidResolver`].
#[must_use]
pub fn did_resolver(
    bi: &NapiBridgeInstance,
) -> Option<&Arc<scp_ffi_common::IdentityBackedDidResolver>> {
    bi.core.did_resolver()
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

/// Initializes the production DID resolver on the given bridge instance.
///
/// Wraps the resolver in an [`scp_ffi_common::IdentityBackedDidResolver`]
/// and stores it on the bridge instance's `CoreFields`.
pub fn init_did_resolver<R>(
    bi: &NapiBridgeInstance,
    resolver: Arc<R>,
    handle: tokio::runtime::Handle,
) where
    R: scp_identity::resolver::DidResolver + 'static,
{
    bi.core
        .set_did_resolver(Arc::new(scp_ffi_common::IdentityBackedDidResolver::new(
            resolver, handle,
        )));
}

/// Returns a key resolver that rejects all lookups with a logged error.
///
/// Delegates to [`scp_ffi_common::bridge_runtime::not_configured_key_resolver`].
fn not_configured_key_resolver() -> scp_core::context::governance::KeyResolver {
    scp_ffi_common::bridge_runtime::not_configured_key_resolver()
}

/// Returns the per-instance
/// [`Supervisor`](scp_core::context::supervisor::Supervisor) on the given
/// bridge instance.
///
/// Per ADR-049 the FFI bridge no longer hands out an `Arc<ContextManager>`.
/// Every bridge function that previously routed through `context_manager()`
/// now goes through this accessor and uses the supervisor's
/// [`dispatch_*`](scp_core::context::supervisor::Supervisor) family or
/// the per-method passthrough surface added on the supervisor.
///
/// # Errors
///
/// Returns `napi::Error` if the supervisor has not been attached via
/// [`init_supervisor`], or if the instance is currently suspended.
pub fn supervisor(
    bi: &NapiBridgeInstance,
) -> napi::Result<&Arc<scp_core::context::supervisor::Supervisor>> {
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
        tracing::warn!("supervisor() called after shutdown — operations may fail");
    }
    bi.core.try_supervisor().ok_or_else(|| {
        napi::Error::from(ScpNapiError::Context {
            message: "Supervisor not yet attached — call context_create, \
                      context_join, context_import, or init_supervisor first"
                .to_owned(),
            code: codes::CTX_2000.to_owned(),
        })
    })
}

// ---------------------------------------------------------------------------
// Phase D (#1695): the legacy process-global default bridge static and its
// lookup helpers have been deleted. Every FFI entry point routes through
// an explicit `&NapiBridgeInstance` — typically `&*self.inner` inside a
// `#[napi] impl Scp` block. Tests construct fresh
// `NapiBridgeInstance::new_napi()` instances directly.
// ---------------------------------------------------------------------------

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

/// Initializes the given bridge instance's per-instance `Supervisor` with
/// production
/// providers.
///
/// Uses `MlsCryptoProvider` (real MLS encryption, #1294),
/// `NotConfiguredTransportProvider`, `MerkleEventLogProvider` (persistent,
/// #484), and the bridge's configured persistence.
///
/// The `local_did` is passed to `MlsCryptoProvider::new` which uses it as
/// the MLS credential identity for group operations and sender key generation.
///
/// Event log persistence is wired via `MerkleEventLogProvider::with_persistence`
/// backed by a `ProtocolRepositoryEventLogBridge` over the configured
/// storage provider. This ensures event log entries are persisted on each
/// append (issue #484 AC).
///
/// The `local_did` is consumed only by `MlsCryptoProvider::new` — the
/// `BridgeInstance` container carries no DID of its own (spec §12.2.3).
///
/// No-op if the bridge already has a `Supervisor` attached (first
/// attach wins — `CoreFields::set_supervisor` is `OnceLock`-backed).
pub fn init_supervisor(bi: &NapiBridgeInstance, local_did: &str) {
    if bi.core.has_supervisor() {
        tracing::debug!(
            requested_did = %local_did,
            "init_supervisor: Supervisor already attached — using existing instance"
        );
        return;
    }
    let did = local_did.to_owned();
    let crypto = Arc::new(scp_core::crypto::mls::provider::MlsCryptoProvider::new(did));
    let transport = Box::new(scp_core::context::NotConfiguredTransportProvider);
    let event_log = event_log_provider_from_existing_repo(bi);
    let persistence = persistence_box_for_init(bi);
    // Storage-before-supervisor precondition (spec §17.6): the chosen storage
    // must already be erased into the `mls_storage` view. The runtime never
    // defaults storage, so a missing backend fails closed — no supervisor is
    // attached and subsequent operations error, rather than fabricating an
    // in-memory default. Every constructor populates this, so this is a
    // defense-in-depth guard.
    let Some(mls_storage) = bi.mls_storage_ref().map(Arc::clone) else {
        tracing::error!(
            "init_supervisor: storage-before-supervisor precondition failed — no \
             mls_storage backend on the bridge instance; refusing to attach a \
             supervisor (fail closed, spec §17.6)"
        );
        return;
    };
    let supervisor_arc =
        build_supervisor_arc(crypto, transport, event_log, persistence, mls_storage);

    bi.core.set_supervisor(supervisor_arc);
}

/// Erases a chosen `Storage` backend into the supervisor's required
/// `mls_storage` (`OpenMLS`) view via [`SpawnBlockingStorageAdapter`].
///
/// The single chosen backend (`Arc<EncryptingAdapter<BridgeInMemoryStorage>>`
/// for the dev/in-memory path, or `Arc<SqliteStorage>` for the durable path)
/// is wrapped ONCE so the event log, persistence, and the `OpenMLS` view all
/// read/write one store (spec §17.6).
fn mls_storage_from_handle<S>(
    handle: Arc<S>,
) -> Arc<dyn scp_core::crypto::mls::storage_adapter::OpenMlsStorageAdapter>
where
    S: scp_platform::Storage + 'static,
{
    Arc::new(scp_core::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(handle))
        as Arc<dyn scp_core::crypto::mls::storage_adapter::OpenMlsStorageAdapter>
}

/// Constructs an `Arc<Supervisor>` with the given providers (ADR-049
/// commit 12c.9g.3.6 — bridge layer no longer touches
/// `ContextManager`). [`scp_core::context::supervisor::Supervisor::with_providers`]
/// is the single entry point that constructs the supervisor +
/// populates the lifted-provider slots.
///
/// `mls_storage` is REQUIRED (non-Option): the runtime never defaults storage;
/// the bridge supplies it (spec §17.6 / ADR-049). It is the single chosen
/// `Storage` erased once into the `OpenMLS` view, derived from the bridge
/// instance's `mls_storage_ref()`.
fn build_supervisor_arc(
    crypto: Arc<scp_core::crypto::mls::provider::MlsCryptoProvider>,
    transport: Box<dyn ContextTransportProvider>,
    event_log: Box<dyn ContextEventLogProvider>,
    persistence: Box<dyn ContextPersistence>,
    mls_storage: Arc<dyn scp_core::crypto::mls::storage_adapter::OpenMlsStorageAdapter>,
) -> Arc<scp_core::context::supervisor::Supervisor> {
    scp_core::context::supervisor::Supervisor::with_providers(
        crypto,
        transport,
        event_log,
        not_configured_key_resolver(),
        Some(persistence),
        None,
        None,
        None,
        mls_storage,
    )
}

/// Returns a `Box<dyn ContextPersistence>` for `ContextManager::with_persistence`.
///
/// Prefers the shared provider attached to `CoreFields::persistence` (the
/// path taken by `with_storage_napi(StorageConfig::Sqlite)`) so the
/// manager and the `CoreFields` mirror share a single backend. Falls
/// back to the legacy in-memory [`NapiBridgePersistence`] when no shared
/// provider is configured.
fn persistence_box_for_init(bi: &NapiBridgeInstance) -> Box<dyn ContextPersistence> {
    if let Some(shared) = bi.core.persistence_arc_clone() {
        Box::new(ArcContextPersistence::new(shared))
    } else {
        Box::new(NapiBridgePersistence::new())
    }
}

/// Initializes the given bridge instance's per-instance `Supervisor` with
/// `LocalTransportProvider`.
///
/// Identical to [`init_supervisor`] except the transport provider is
/// `LocalTransportProvider` (silently succeeds on all send/publish calls)
/// instead of `NotConfiguredTransportProvider` (rejects everything).
///
/// **Must be called before any `context_create` / `context_join` /
/// `context_import`** — those functions call `init_supervisor` which
/// will win the `OnceLock` race if called first.
///
/// Exposed to JS/TS via `crate::transport::configure_local_transport` so
/// that E2E tests can exercise `contextSend` and `broadcastPublish` without
/// a real relay server.
///
/// No-op if the bridge already has a `Supervisor` attached.
pub fn init_supervisor_with_local_transport(bi: &NapiBridgeInstance, local_did: &str) {
    if bi.core.has_supervisor() {
        tracing::warn!(
            requested_did = %local_did,
            "init_supervisor_with_local_transport: Supervisor already attached — ignoring"
        );
        return;
    }
    let did = local_did.to_owned();
    let crypto = Arc::new(scp_core::crypto::mls::provider::MlsCryptoProvider::new(did));
    let transport = Box::new(scp_core::context::LocalTransportProvider);
    let event_log = event_log_provider_from_existing_repo(bi);
    let persistence = persistence_box_for_init(bi);
    let Some(mls_storage) = bi.mls_storage_ref().map(Arc::clone) else {
        tracing::error!(
            "init_supervisor_with_local_transport: storage-before-supervisor \
             precondition failed — no mls_storage backend on the bridge instance; \
             refusing to attach a supervisor (fail closed, spec §17.6)"
        );
        return;
    };
    let supervisor_arc =
        build_supervisor_arc(crypto, transport, event_log, persistence, mls_storage);

    bi.core.set_supervisor(supervisor_arc);
}

/// Initializes the given bridge instance's per-instance `Supervisor` with a
/// `RelayTransportProvider`.
///
/// Identical to [`init_supervisor`] except the transport provider is a
/// `RelayTransportProvider` wrapping a real `NativeRelayAdapter` connected to
/// the given relay URL. This allows the supervisor's send pipeline (and
/// thus `contextSend`) to publish encrypted payloads through the relay.
///
/// **Must be called before any `context_create` / `context_join` /
/// `context_import`** — those functions call `init_supervisor` which
/// will win the `OnceLock` race if called first.
///
/// Exposed to JS/TS via `crate::transport::configure_relay_transport` so
/// that E2E tests can exercise the full send → relay → subscribe → receive
/// pipeline.
///
/// # Arguments
///
/// * `bi` — The bridge instance to attach the manager to.
/// * `local_did` — The DID of the first identity (MLS credential identity).
/// * `adapter` — A connected `NativeRelayAdapter` to wrap in
///   `RelayTransportProvider`.
///
/// No-op if the bridge already has a `Supervisor` attached.
pub fn init_supervisor_with_relay_transport(
    bi: &NapiBridgeInstance,
    local_did: &str,
    adapter: Box<dyn scp_transport::TransportAdapter>,
) {
    if bi.core.has_supervisor() {
        tracing::warn!(
            requested_did = %local_did,
            "init_supervisor_with_relay_transport: Supervisor already attached — ignoring"
        );
        return;
    }
    let did = local_did.to_owned();
    let crypto = Arc::new(scp_core::crypto::mls::provider::MlsCryptoProvider::new(did));
    let transport = Box::new(scp_transport::RelayTransportProvider::new(adapter));
    let event_log = event_log_provider_from_existing_repo(bi);
    let persistence = persistence_box_for_init(bi);
    let Some(mls_storage) = bi.mls_storage_ref().map(Arc::clone) else {
        tracing::error!(
            "init_supervisor_with_relay_transport: storage-before-supervisor \
             precondition failed — no mls_storage backend on the bridge instance; \
             refusing to attach a supervisor (fail closed, spec §17.6)"
        );
        return;
    };
    let supervisor_arc =
        build_supervisor_arc(crypto, transport, event_log, persistence, mls_storage);

    bi.core.set_supervisor(supervisor_arc);
}

/// Returns the given bridge instance's `ProtocolRepoVariant`.
///
/// Used by the trust aggregation bridge to construct a
/// `ProtocolRepositoryTrustBridge` backed by the configured storage (either
/// encrypted in-memory or SQLCipher-on-disk).
#[must_use]
pub const fn protocol_repository(bi: &NapiBridgeInstance) -> &ProtocolRepoVariant {
    &bi.protocol_repository
}

/// Constructs a persistent event log provider backed by encrypted in-memory
/// storage.
///
/// Delegates to [`scp_ffi_common::bridge_runtime::build_event_log_provider`].
/// Returns three handles to the SAME underlying store: the event log provider,
/// the underlying `ProtocolRepository` (for registration in
/// `NapiBridgeInstance`), and the raw
/// [`BridgeInMemoryStorageHandle`](scp_ffi_common::bridge_runtime::BridgeInMemoryStorageHandle)
/// — the un-swallowed in-memory storage handle the bridge wraps via
/// `SpawnBlockingStorageAdapter` into the supervisor's required `mls_storage`
/// consumer (spec §17.6 — one chosen backend, derived consumers).
//
// Retained as a thin re-export of the shared `scp-ffi-common` helper; the
// per-instance constructors call the common helper directly, so the bridge's
// local wrapper has no live caller.
#[allow(dead_code)]
pub(crate) fn build_event_log_provider() -> (
    Box<dyn ContextEventLogProvider>,
    Arc<scp_ffi_common::bridge_runtime::BridgeInMemoryRepo>,
    BridgeInMemoryStorageHandle,
) {
    scp_ffi_common::bridge_runtime::build_event_log_provider()
}

/// Builds an event log provider that reuses the bridge instance's
/// already-registered `ProtocolRepoVariant`.
///
/// Called by `init_context_manager*` after the bridge was constructed.
/// Reusing the repository is critical — a fresh repository would have a
/// different encryption key, rendering any already persisted event log
/// entries unreadable. When the bridge is SQLite-backed, this returns an
/// event log provider that writes into the same `SQLCipher` database as
/// context snapshots.
fn event_log_provider_from_existing_repo(
    bi: &NapiBridgeInstance,
) -> Box<dyn ContextEventLogProvider> {
    bi.protocol_repository.event_log_provider()
}

// `bridge_lifecycle_serial` (and its backing `BRIDGE_LIFECYCLE_SERIAL`
// `OnceLock`) were deleted in #1549 Phase 4 PR 2 commit 11. They existed
// solely to serialize the `scp_suspend_resume_roundtrip` test — which
// mutated the legacy process-wide default bridge's suspended flag —
// against every other test that touched shared bridge state. The
// roundtrip test has been rewritten to use a caller-owned `Scp::new()`
// instance (see `scp_class_suspend_resume_roundtrip` in `lib.rs`), and
// Phase 4 PR 4 (#1549) subsequently deleted the process-wide default
// bridge entirely, so no shared suspended flag exists for lifecycle
// tests to race on and the serial is no longer required. Other tests
// that previously acquired the guard now simply run without it.

/// Test variant of [`init_supervisor`] that uses
/// [`LocalTransportProvider`](scp_core::context::LocalTransportProvider)
/// instead of
/// [`NotConfiguredTransportProvider`](scp_core::context::NotConfiguredTransportProvider)
/// and a no-op crypto provider for Rust unit tests that pass `None` key
/// package bytes with `did:key:` test DIDs.
///
/// Initializes the given bridge instance's per-instance `Supervisor` with
/// test-only providers (local transport).
///
/// Must be called before the first `supervisor(bi)` call in tests.
/// First-call-wins semantics via `CoreFields::set_supervisor`.
#[cfg(test)]
pub(crate) fn init_supervisor_for_test_on(bi: &NapiBridgeInstance) {
    if bi.core.has_supervisor() {
        return;
    }
    let event_log = event_log_provider_from_existing_repo(bi);
    // The in-memory `mls_storage` backend is populated at construction
    // (the dev/test affordance, spec §17.6). Read it directly; a missing
    // backend fails closed.
    let Some(mls_storage) = bi.mls_storage_ref().map(Arc::clone) else {
        tracing::error!(
            "init_supervisor_for_test_on: storage-before-supervisor precondition failed — \
             no mls_storage backend on the bridge instance"
        );
        return;
    };
    let supervisor_arc = build_supervisor_arc(
        Arc::new(scp_core::crypto::mls::provider::MlsCryptoProvider::new(
            "did:test:napi-bridge-test".to_owned(),
        )),
        Box::new(scp_core::context::LocalTransportProvider),
        event_log,
        Box::new(NapiBridgePersistence::new()),
        mls_storage,
    );

    bi.core.set_supervisor(supervisor_arc);
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
    /// The key custody provider holding (or delegating to) the key material.
    ///
    /// Enum-dispatched ([`NapiKeyCustody`](crate::custody::NapiKeyCustody)) so
    /// the same registry entry can back either an in-memory test identity or a
    /// caller-provided callback custody (`identityCreateWithCustody`). The
    /// `KeyCustody` trait is not object-safe (RPITIT), so this is a concrete
    /// enum rather than `Arc<dyn KeyCustody>`.
    pub(crate) custody: Arc<crate::custody::NapiKeyCustody>,
    /// The DID document at the time of creation (or last key rotation).
    pub(crate) document: scp_identity::DidDocument,
    /// Identity link attestations (§3.5.1). Stored locally per identity.
    pub(crate) identity_link_attestations:
        Vec<scp_core::identity::attestation::IdentityLinkAttestation>,
    /// Cold-storage handle for the pre-rotation key associated with this
    /// identity. Returned by `dht.create()` / `dht.migrate_identity()` and
    /// must be presented to the next `migrate_identity` call to reveal the
    /// committed key (spec §9.7.4.1, ADR-003 §4b).
    pub(crate) pre_rotation_handle: scp_platform::PreRotationKeyHandle,
    /// Cold-storage custody provider for the pre-rotation key. Held alongside
    /// the operational `custody` so that migration can hand the old handle
    /// back to the same custody instance that issued it (spec §9.7.4.1 §3:
    /// storage isolation — distinct from operational `KeyCustody`).
    pub(crate) pre_rotation_custody: Arc<scp_platform::testing::InMemoryPreRotationCustody>,
}

/// Returns a reference to the given bridge instance's identity registry.
///
/// The registry is a typed `Arc<DashMap<String, NapiIdentityEntry>>` field
/// on [`NapiBridgeInstance`].
#[cfg(feature = "allow_in_memory_custody")]
pub(crate) fn identity_registry(bi: &NapiBridgeInstance) -> &DashMap<String, NapiIdentityEntry> {
    bi.identity_registry.as_ref()
}

/// Registers an identity in the bridge instance's identity registry.
///
/// Called by `identity_create` and `identity_create_with_agent_key` after
/// successfully creating an identity. Bridge functions (`ucan_delegate`)
/// look up the retained `InMemoryKeyCustody` and `KeyHandle`s via
/// [`with_identity`].
///
/// Overwrites any existing entry for the same DID (idempotent — supports
/// key rotation where the same DID gets new key material).
#[cfg(feature = "allow_in_memory_custody")]
pub(crate) fn register_identity(bi: &NapiBridgeInstance, did: &str, entry: NapiIdentityEntry) {
    identity_registry(bi).insert(did.to_owned(), entry);
}

/// Removes an identity from the bridge instance's identity registry.
///
/// Called when an identity is migrated to a new DID or during cleanup.
/// The old entry is removed and its key material is dropped.
///
/// Idempotent: no-op if the DID is not present.
#[cfg(feature = "allow_in_memory_custody")]
pub(crate) fn remove_identity(bi: &NapiBridgeInstance, did: &str) {
    identity_registry(bi).remove(did);
}

/// Removes an identity from the bridge instance's identity registry if present.
///
/// Returns `true` if the identity was found and removed, `false` if the
/// DID was not in the registry.
///
/// Provided as a cleanup mechanism for long-running processes alongside
/// [`remove_identity`] which is unconditional.
#[cfg(feature = "allow_in_memory_custody")]
#[must_use]
pub(crate) fn remove_identity_if_present(bi: &NapiBridgeInstance, did: &str) -> bool {
    identity_registry(bi).remove(did).is_some()
}

/// Executes a closure with a reference to an identity's retained state on
/// the given bridge instance.
///
/// Looks up the identity by DID in the bridge's registry and calls `f` with
/// a reference to the [`NapiIdentityEntry`].
///
/// # Errors
///
/// Returns `ScpNapiError::Identity` (SCP-IDENT-1001) if the DID is not found
/// (the identity was not created via `identity_create` on this bridge).
/// Aligned with the `PyO3` canonical bridge for cross-bridge parity.
#[cfg(feature = "allow_in_memory_custody")]
pub(crate) fn with_identity<T, F>(
    bi: &NapiBridgeInstance,
    did: &str,
    f: F,
) -> Result<T, ScpNapiError>
where
    F: FnOnce(&NapiIdentityEntry) -> Result<T, ScpNapiError>,
{
    let entry = identity_registry(bi)
        .get(did)
        .ok_or_else(|| ScpNapiError::Identity {
            message: format!(
                "identity '{did}' not found in registry — was it created with \
                 identityCreate(\"in_memory\") in this process?"
            ),
            code: codes::IDENT_1001.to_owned(),
        })?;

    f(entry.value())
}

/// Executes a closure with mutable access to an identity's retained state on
/// the given bridge instance.
///
/// Uses `DashMap::get_mut` for fine-grained per-key write locking.
///
/// # Errors
///
/// Returns `ScpNapiError::Identity` (SCP-IDENT-1001) if the DID is not found.
/// Aligned with the `PyO3` canonical bridge for cross-bridge parity.
#[cfg(feature = "allow_in_memory_custody")]
pub(crate) fn with_identity_mut<T, F>(
    bi: &NapiBridgeInstance,
    did: &str,
    f: F,
) -> Result<T, ScpNapiError>
where
    F: FnOnce(&mut NapiIdentityEntry) -> Result<T, ScpNapiError>,
{
    let mut entry = identity_registry(bi)
        .get_mut(did)
        .ok_or_else(|| ScpNapiError::Identity {
            message: format!(
                "identity '{did}' not found in registry — was it created with \
                 identityCreate(\"in_memory\") in this process?"
            ),
            code: codes::IDENT_1001.to_owned(),
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

/// Returns a reference to the given bridge instance's UCAN state registry.
///
/// The registry is a typed `Arc<DashMap<String, UcanContextState>>` field
/// on [`NapiBridgeInstance`].
pub(crate) fn ucan_registry(bi: &NapiBridgeInstance) -> &DashMap<String, UcanContextState> {
    bi.ucan_registry.as_ref()
}

/// Ensures UCAN validation state is registered for a context on the given
/// bridge instance.
///
/// If the context is already registered, this is a no-op. Otherwise, creates
/// UCAN state from the `NapiContextHandle` metadata.
///
/// # Errors
///
/// Returns `ScpNapiError::Context` if the context state cannot be determined.
pub fn ensure_registered(
    bi: &NapiBridgeInstance,
    handle: &NapiContextHandle,
) -> Result<(), ScpNapiError> {
    let context_id = handle.context_id();
    let map = ucan_registry(bi);

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

/// Executes a closure with mutable access to a context's UCAN state on the
/// given bridge instance.
///
/// # Errors
///
/// Returns `ScpNapiError::Context` if the context is not found in the registry.
pub fn with_context<T, F>(
    bi: &NapiBridgeInstance,
    context_id: &str,
    f: F,
) -> Result<T, ScpNapiError>
where
    F: FnOnce(&mut UcanContextState) -> Result<T, ScpNapiError>,
{
    let map = ucan_registry(bi);

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

/// Removes UCAN state for a context on the given bridge instance.
///
/// Called when a context is closed. Idempotent.
pub fn remove_context(bi: &NapiBridgeInstance, context_id: &str) {
    ucan_registry(bi).remove(context_id);
    // Clean up known-context discovery entry on the same instance.
    bi.core.remove_known_context(context_id);
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
pub async fn sync_role_state_from_manager(
    bi: &NapiBridgeInstance,
    context_id: &str,
) -> Result<(), ScpNapiError> {
    use scp_core::context::actor::commands::QueriesCommand;
    let sup = supervisor(bi).map_err(|e| ScpNapiError::Context {
        message: e.to_string(),
        code: codes::CTX_2000.to_owned(),
    })?;
    let sup = Arc::clone(sup);
    // Route through the ADR-049 query shim. The handler returns
    // `Ok(None)` when the context is unknown, matching the legacy
    // `ContextManager::get_role_state` `Option` contract.
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = QueriesCommand::GetRoleState {
        context_id: context_id.to_owned(),
        reply: tx,
    };
    sup.dispatch_query(cmd)
        .await
        .map_err(|e| ScpNapiError::Context {
            message: format!("supervisor dispatch_query failed: {e}"),
            code: codes::CTX_2000.to_owned(),
        })?;
    let new_role_state = rx
        .await
        .map_err(|e| ScpNapiError::Context {
            message: format!("query shim reply dropped: {e}"),
            code: codes::CTX_2000.to_owned(),
        })?
        .map_err(|e| ScpNapiError::Context {
            message: e.to_string(),
            code: codes::CTX_2000.to_owned(),
        })?
        .ok_or_else(|| ScpNapiError::Context {
            message: format!("context '{context_id}' not registered with Supervisor"),
            code: codes::CTX_2023.to_owned(),
        })?;

    with_context(bi, context_id, |st| {
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
    bi: &NapiBridgeInstance,
    context_id: &str,
    tool_id: &str,
    handler: ToolHandler,
) -> Result<(), ScpNapiError> {
    with_context(bi, context_id, |st| {
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

/// Queries event counts for trust scoring within a context on the given
/// bridge instance.
///
/// Returns `(message_count, governance_count)` derived from the context's
/// event log. Returns `(0, 0)` if the context is not registered.
#[must_use]
pub fn query_trust_event_counts(
    bi: &NapiBridgeInstance,
    context_id: &str,
    _did: &str,
) -> (u64, u64) {
    let map = ucan_registry(bi);
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

// Phase D (#1695): `with_rate_limit_tracker` default-bridge shim deleted.
// Callers pass a `&NapiBridgeInstance` and call
// `bi.core.with_rate_limit_tracker(identity_did, f)` directly.

/// Registers a test context in the UCAN state registry.
///
/// # Panics
///
/// Panics if `ContextRoleState::new` fails with default ceiling and no
/// custom roles, which should be infallible.
#[cfg(test)]
#[allow(clippy::expect_used)]
pub fn register_test_context(bi: &NapiBridgeInstance, context_id: &str, creator_did: &str) {
    let map = ucan_registry(bi);

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
// ArcContextPersistence — shared-Arc adapter
// ---------------------------------------------------------------------------

/// Adapter that lets a shared `Arc<dyn ContextPersistence + Send + Sync>` be
/// consumed by `ContextManager::with_persistence` which requires a `Box`.
///
/// Mirrors the `UniFFI` and `PyO3` bridges' `ArcContextPersistence`.
/// `ContextManager::with_persistence` converts the `Box` back into an
/// `Arc` internally, but the call-site signature is `Box`-only. Rather
/// than cloning the underlying backend (which would open a second
/// `SQLite` connection), we box a thin wrapper that delegates every
/// trait method to the shared `Arc`. The manager's internal `Arc` and
/// the `CoreFields::persistence` mirror end up pointing at the same
/// provider instance.
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
        snapshot: &ContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.inner.persist_context(context_id, snapshot)
    }

    fn load_context(
        &self,
        context_id: &str,
    ) -> Result<Option<ContextSnapshot>, Box<dyn std::error::Error + Send + Sync>> {
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

// ---------------------------------------------------------------------------
// Economy state registries
// ---------------------------------------------------------------------------

// Economy state is owned by NapiBridgeInstance. Callers access it via
// `bi.core.with_economy_budget(...)` etc. on an explicit bridge.

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
    fn bridge_instance_populated_by_init_supervisor() {
        // A fresh NapiBridgeInstance must accept a Supervisor via
        // init_supervisor_for_test_on and make it visible through
        // supervisor(&bi).
        let bi = NapiBridgeInstance::new_napi();
        init_supervisor_for_test_on(&bi);

        let sup = supervisor(&bi).expect("supervisor should be initialized");

        // Both should point to the same Supervisor allocation.
        assert!(
            Arc::ptr_eq(sup, bi.core.try_supervisor().unwrap()),
            "supervisor(&bi) must match bi.core.try_supervisor()"
        );
    }

    #[test]
    fn bridge_instance_not_shutdown_initially() {
        let bi = NapiBridgeInstance::new_napi();
        init_supervisor_for_test_on(&bi);

        assert!(
            !bi.core.is_shutdown(),
            "fresh bridge instance should not be shutdown after init"
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
        // protocol_repository is a live variant — default construction is
        // the in-memory variant.
        assert!(
            matches!(&bi.protocol_repository, ProtocolRepoVariant::InMemory(_)),
            "default NapiBridgeInstance must use in-memory protocol repository"
        );
    }

    #[test]
    fn test_with_storage_sqlite_uses_sqlite_variant() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let bi = NapiBridgeInstance::with_storage_napi(StorageConfig::Sqlite {
            path: tmp.path().to_path_buf(),
            key: SqliteKeyMaterial::Raw(zeroize::Zeroizing::new(vec![0x11u8; 32])),
        })
        .expect("raw-key sqlite open must succeed");
        assert!(
            matches!(&bi.protocol_repository, ProtocolRepoVariant::Sqlite(_)),
            "with_storage(Sqlite) must produce ProtocolRepoVariant::Sqlite so event log \
             entries persist to the same `SQLCipher` database as context snapshots"
        );
        assert!(
            bi.mls_storage_ref().is_some(),
            "Sqlite path must populate the mls_storage backend (spec §17.6)"
        );
    }

    #[test]
    fn test_in_memory_populates_mls_storage_backend() {
        // The dev/in-memory path must populate `mls_storage` from the
        // un-swallowed in-memory storage handle (spec §17.6 — one chosen
        // backend, derived consumers). NapiBridgePersistence (a DashMap) is
        // NOT the source; the build_event_log_provider handle is.
        let bi = NapiBridgeInstance::new_napi();
        assert!(
            bi.mls_storage_ref().is_some(),
            "in-memory dev path must populate the mls_storage backend"
        );
    }

    #[test]
    fn test_sqlite_open_failure_fails_closed() {
        // FAIL CLOSED (spec §17.6): a Sqlite open at an unwritable path must
        // return an error, NOT silently fall back to in-memory/no storage.
        // Point at a path whose parent is a regular file so the directory
        // cannot be created.
        let tmp = tempfile::tempdir().expect("tempdir");
        let blocker = tmp.path().join("not-a-dir");
        std::fs::write(&blocker, b"x").expect("write blocker file");
        let bad_dir = blocker.join("scp-data");
        let result = NapiBridgeInstance::with_storage_napi(StorageConfig::Sqlite {
            path: bad_dir,
            key: SqliteKeyMaterial::Raw(zeroize::Zeroizing::new(vec![0x22u8; 32])),
        });
        assert!(
            matches!(result, Err(StorageInitError::SqliteOpen { .. })),
            "Sqlite open failure must fail closed with SqliteOpen, but the open \
             unexpectedly succeeded (in-memory fallback is forbidden)"
        );
    }

    #[test]
    fn test_sqlite_passphrase_round_trip() {
        // Create with a passphrase, write data, reopen the same dir with the
        // same passphrase, and confirm the data survives — the passphrase
        // re-derives the same SQLCipher key via the persisted salt sidecar.
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path().to_path_buf();

        let bi = NapiBridgeInstance::with_storage_napi(StorageConfig::Sqlite {
            path: dir.clone(),
            key: SqliteKeyMaterial::Passphrase(zeroize::Zeroizing::new(
                "correct horse battery staple".to_owned(),
            )),
        })
        .expect("passphrase sqlite open must succeed");
        // Write through the mls_storage backend (the OpenMLS view shares the
        // one SQLCipher connection).
        let backend = bi
            .mls_storage_ref()
            .cloned()
            .expect("passphrase path must populate mls_storage");
        crate::runtime().block_on(async {
            backend
                .store("scp-test/persist", b"durable-value")
                .await
                .expect("store via mls_storage backend");
        });
        drop(backend);
        drop(bi);

        // Reopen with the SAME passphrase.
        let bi2 = NapiBridgeInstance::with_storage_napi(StorageConfig::Sqlite {
            path: dir,
            key: SqliteKeyMaterial::Passphrase(zeroize::Zeroizing::new(
                "correct horse battery staple".to_owned(),
            )),
        })
        .expect("reopen with same passphrase must succeed");
        let backend2 = bi2
            .mls_storage_ref()
            .cloned()
            .expect("reopened passphrase path must populate mls_storage");
        let read_back = crate::runtime().block_on(async {
            backend2
                .retrieve("scp-test/persist")
                .await
                .expect("retrieve via reopened backend")
        });
        assert_eq!(
            read_back.as_deref(),
            Some(b"durable-value".as_slice()),
            "data written under the passphrase must survive a reopen with the same passphrase"
        );
    }

    #[test]
    fn test_sqlite_wrong_passphrase_fails_closed() {
        // Security-critical (spec §17.6): reopening an existing DB with the
        // WRONG passphrase must fail closed — never silently open a fresh,
        // empty database.
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path().to_path_buf();

        let bi = NapiBridgeInstance::with_storage_napi(StorageConfig::Sqlite {
            path: dir.clone(),
            key: SqliteKeyMaterial::Passphrase(zeroize::Zeroizing::new(
                "the-right-passphrase".to_owned(),
            )),
        })
        .expect("initial passphrase open must succeed");
        let backend = bi
            .mls_storage_ref()
            .cloned()
            .expect("mls_storage backend present");
        crate::runtime().block_on(async {
            backend
                .store("scp-test/secret", b"top-secret")
                .await
                .expect("store secret");
        });
        drop(backend);
        drop(bi);

        // Reopen with the WRONG passphrase: must fail closed.
        let result = NapiBridgeInstance::with_storage_napi(StorageConfig::Sqlite {
            path: dir,
            key: SqliteKeyMaterial::Passphrase(zeroize::Zeroizing::new(
                "the-WRONG-passphrase".to_owned(),
            )),
        });
        assert!(
            matches!(result, Err(StorageInitError::SqliteOpen { .. })),
            "wrong passphrase must fail closed (no silent fresh DB), but the open \
             unexpectedly succeeded"
        );
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

    // Phase D (#1695): `test_default_instance_is_same_arc` deleted — the
    // legacy default bridge no longer exists. Each caller owns its own
    // `NapiBridgeInstance` and `Scp::new()` verifies uniqueness via
    // `test_napi_bridge_instance_unique_ids` above.
}
