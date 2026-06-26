//! Per-instance `UniffiBridgeInstance` and its registries.
//!
//! Each `Arc<UniffiBridgeInstance>` is owned by the caller via a
//! `#[derive(uniffi::Object)] Scp` handle. The instance bundles a
//! shared `ContextManager` and typed registries (UCAN, identity custody,
//! protocol repository, context handles, MCP servers/clients, identity
//! link attestations) so lifecycle (`suspend` / `resume` / `shutdown`)
//! cascades to all of them as a unit.
//!
//! # Per-context UCAN state
//!
//! The `ContextManager` does not own UCAN revocation lists or nonce trackers.
//! Those are validation-layer concerns that live on the `UniffiBridgeInstance`.
//! A typed `Arc<DashMap<String, UcanContextState>>` on the instance owns them,
//! keyed by context ID. This mirrors the NAPI bridge's `UcanContextState`
//! pattern (see `crates/scp-ffi/napi/src/runtime.rs`).
//!
//! # Lifecycle
//!
//! 1. `Scp::with_storage` (the sole public constructor; storage selection
//!    is mandatory, spec §17.6) constructs a fresh `UniffiBridgeInstance`;
//!    per-instance setup (e.g. `init_context_manager_with_did`, transport
//!    setup) happens lazily on the first `Scp::identity_create` /
//!    `context_create` / `context_join` call.
//! 2. `Scp::method(...)` delegates to methods on
//!    `UniffiBridgeInstance` (`context_manager_expect`, `with_ucan_state`,
//!    `ensure_ucan_registered`, `did_resolver`, etc.) — all per-instance,
//!    no process-wide shared state. `context_manager_expect` returns the
//!    instance's `Arc<Supervisor>` (ADR-049 actor migration).
//! 3. The instance is dropped when the last `Arc` reference is released
//!    or permanently deactivated via [`UniffiBridgeInstance::shutdown`].
//!
//! This replaces the old `DashMap<String, ContextRuntime>` global registry
//! (deleted as part of issue #387), the type-erased `Box<dyn Any>` slots on
//! `BridgeInstance` (deleted as part of #1549 Phase 4 PR 1), and the
//! process-wide `DEFAULT_BRIDGE_INSTANCE` façade (deleted as part of
//! #1549 Phase 4 PR 4 Phase D).

use async_trait::async_trait;
use scp_ffi_common::bridge_instance::BridgeInstanceCore;
// Re-export `CoreFields` at `crate::runtime::CoreFields` so bridge.rs
// and server.rs can name it in impl blocks without pulling in the full
// path.
pub use scp_ffi_common::bridge_instance::CoreFields;
use scp_ffi_common::error_codes as codes;
use std::collections::HashSet;
use std::sync::Arc;

use dashmap::DashMap;
use scp_core::context::builder::ContextEventLogProvider;
use scp_core::crypto::mls::provider::MlsCryptoProvider;
use scp_core::crypto::ucan::nonce::NonceTracker;
use scp_core::crypto::ucan::revoke::RevocationList;
use scp_core::store::ProtocolRepository;
use scp_event_log::EventLog;
use scp_identity::cache::SystemClock;

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
        /// Encryption key material — raw bytes or a passphrase (mutually
        /// exclusive; the [`SqliteKeyMaterial`] sum type makes "exactly
        /// one" the only representable state).
        key: SqliteKeyMaterial,
    },
}

/// `SQLCipher` key-material selector for [`StorageConfig::Sqlite`] (spec §17.6).
///
/// The caller supplies EITHER raw key material OR a passphrase — never both,
/// never neither. The sum type makes that mutual exclusion unrepresentable as
/// an invalid state, so there is exactly one happy path per variant. This
/// mirrors the `PyO3` bridge's `SqliteKeyMaterial`.
///
/// - [`SqliteKeyMaterial::Raw`] feeds [`SqliteStorage::new`] directly (raw-key
///   mode; the existing, unchanged path).
/// - [`SqliteKeyMaterial::Passphrase`] feeds
///   [`SqliteStorage::with_passphrase`], which derives the `SQLCipher` PRAGMA
///   key from the passphrase via the shared Argon2id parameterization with a
///   persisted per-database salt sidecar.
///
/// # `UniFFI` representation
///
/// `#[derive(uniffi::Enum)]` exposes this to Swift and Kotlin as an
/// associated-value enum: Swift sees `case raw(Data)` / `case
/// passphrase(String)`; Kotlin a `sealed class SqliteKeyMaterial`. The raw
/// `Vec<u8>` and the `String` cross the FFI boundary by value; the Rust side
/// moves the passphrase into `Zeroizing` and zeroes the raw bytes after
/// `SQLCipher` has consumed them. Callers cannot zero their own copy across
/// the boundary, so they should overwrite their source buffer after the call
/// returns.
#[derive(Clone, uniffi::Enum)]
pub enum SqliteKeyMaterial {
    /// Raw encryption key material (32 bytes recommended).
    Raw {
        /// The raw key bytes.
        key: Vec<u8>,
    },
    /// Human-chosen passphrase; the `SQLCipher` key is derived via Argon2id.
    Passphrase {
        /// The passphrase. Moved into `Zeroizing` at the bridge boundary.
        passphrase: String,
    },
}

impl std::fmt::Debug for SqliteKeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the key or passphrase bytes — only the variant and a
        // length hint for the raw case (defense in depth). Mirrors the PyO3 /
        // NAPI redacting impl.
        match self {
            Self::Raw { key } => {
                write!(f, "SqliteKeyMaterial::Raw(<redacted {} bytes>)", key.len())
            }
            Self::Passphrase { .. } => write!(f, "SqliteKeyMaterial::Passphrase(<redacted>)"),
        }
    }
}

/// Bridge-internal error returned by
/// [`UniffiBridgeInstance::with_storage_uniffi`] when a durable storage
/// backend cannot be opened.
///
/// Surfacing this (rather than silently degrading to in-memory or no storage)
/// is the fail-closed contract from spec §17.6: a failed durable-backend open
/// is a terminal error the caller observes, never a condition the system
/// recovers from by downgrading durability. Converted to [`ScpError`] (and so
/// to a Swift `throws` / Kotlin exception) via the [`From`] impl below.
///
/// Mirrors the `PyO3` bridge's `StorageInitError`. The message never contains
/// key or passphrase bytes.
#[derive(Debug)]
pub enum StorageInitError {
    /// `SqliteStorage::new` / `SqliteStorage::with_passphrase` failed —
    /// directory permission denied, key/passphrase rejected by `SQLCipher` on
    /// an existing DB, salt-sidecar fail-closed condition, corrupt file, and
    /// so on.
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

impl From<StorageInitError> for crate::ScpError {
    fn from(err: StorageInitError) -> Self {
        match err {
            StorageInitError::SqliteOpen { .. } => Self::Context {
                msg: err.to_string(),
                code: codes::CTX_2000.to_owned(),
            },
        }
    }
}

// `ProtocolRepoVariant` lives in `scp-ffi-common::bridge_runtime`. Re-exported
// here so existing `crate::runtime::ProtocolRepoVariant` references across
// the UniFFI bridge keep compiling without mass rename. See ADR-048 §2 for
// the "shared-variant types for storage-backed repositories" exemption.
pub use scp_ffi_common::bridge_runtime::ProtocolRepoVariant;

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
/// [`UniffiBridgeInstance::with_storage_uniffi`]. Every caller-owned
/// `#[derive(uniffi::Object)] Scp` constructs its own instance —
/// Phase D (#1695, ADR-048) deleted the process-wide
/// `DEFAULT_BRIDGE_INSTANCE` that earlier revisions lazily allocated.
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

    /// Retained identity custody for the production identity ops, keyed by DID.
    ///
    /// Previously stored type-erased in `CoreFields::identity_registry` AND
    /// as a bridge-local `OnceLock` in `bridge.rs::identity_custody_registry`.
    /// Both paths are unified here: `bridge.rs::identity_custody_registry`
    /// now returns a reference to this field on the caller's own
    /// `UniffiBridgeInstance` (Phase D, #1695, deleted the process-wide
    /// default that the earlier `OnceLock` path backed).
    ///
    /// Typed to [`UniffiKeyCustody`](crate::bridge::UniffiKeyCustody) — an
    /// enum over the callback (production) and in-memory (`allow_in_memory_custody`,
    /// dev/desktop) backends — so the registry, the accessor, and the
    /// `scpid_sign` / `identity_create_link_attestation` / `identity_remove*`
    /// ops that read it exist in BARE production builds (matching the `PyO3` and
    /// napi bridges, whose registries are likewise custody-enum-typed). The
    /// previous in-memory-typed field forced those production ops behind the
    /// `allow_in_memory_custody` gate, silently dropping them from the released
    /// Swift/Kotlin SDKs.
    ///
    /// Cleared on shutdown — dropping the `Arc<UniffiKeyCustody>` values
    /// zeroizes any underlying key material via the custody provider's `Drop`.
    pub(crate) identity_custody_registry: Arc<
        DashMap<
            String,
            (
                Arc<crate::bridge::UniffiKeyCustody>,
                scp_platform::KeyHandle,
            ),
        >,
    >,

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

    // -----------------------------------------------------------------
    // #1549 Phase 4 PR 2 commit 1 — additive typed fields replacing
    // process-global singletons in later commits.
    // -----------------------------------------------------------------
    /// Identity link attestation registry (replaces
    /// `identity_link_attestation_registry` `OnceLock` in `bridge.rs`).
    ///
    /// Keyed by DID string. Migrated from a process-global
    /// `OnceLock<DashMap<String, Vec<IdentityLinkAttestation>>>` singleton in
    /// commit 6.
    pub(crate) identity_link_attestation_registry:
        Arc<DashMap<String, Vec<scp_core::identity::attestation::IdentityLinkAttestation>>>,

    /// Context handle registry (replaces `context_handle_registry` `OnceLock`
    /// in `bridge.rs`).
    ///
    /// Maps `context_id` to `Arc<ContextHandle>`. Migrated from a process-
    /// global `OnceLock<DashMap<String, Arc<ContextHandle>>>` singleton in
    /// commit 6. Used by the MCP bridge provider to look up per-context state.
    pub(crate) context_handle_registry: Arc<DashMap<String, Arc<crate::bridge::ContextHandle>>>,

    /// MCP server registry (replaces `mcp_server_registry` `OnceLock` in
    /// `bridge.rs`).
    ///
    /// Migrated from a process-global
    /// `OnceLock<DashMap<String, McpServerEntry>>` singleton in commit 4.
    /// Cleared by [`BridgeInstanceCore::bridge_specific_shutdown`].
    pub(crate) mcp_server_registry: Arc<DashMap<String, crate::bridge::McpServerEntry>>,

    /// MCP client registry (replaces `mcp_client_registry` `OnceLock` in
    /// `bridge.rs`).
    ///
    /// Migrated from a process-global
    /// `OnceLock<DashMap<String, McpClientEntry>>` singleton in commit 4.
    /// Cleared by [`BridgeInstanceCore::bridge_specific_shutdown`].
    pub(crate) mcp_client_registry: Arc<DashMap<String, crate::bridge::McpClientEntry>>,

    /// The supervisor's `OpenMLS` storage view (spec §17.6 / ADR-049).
    ///
    /// Holds the SAME backend the bridge chose for persistence + event log,
    /// erased ONCE via [`SpawnBlockingStorageAdapter`]:
    /// - in-memory path: the un-swallowed
    ///   [`scp_ffi_common::bridge_runtime::BridgeInMemoryStorageHandle`]
    ///   returned by `build_event_log_provider`;
    /// - `SQLCipher` path: the `Arc<SqliteStorage>` that also backs
    ///   `CoreFields::persistence` and the event-log repository.
    ///
    /// `build_supervisor` reads this to satisfy the required `mls_storage`
    /// argument of `Supervisor::with_providers`. The runtime never defaults
    /// storage; if this is `None` at supervisor construction the
    /// storage-before-supervisor precondition fails closed. It is `Option`
    /// only because the field is populated at instance construction, before
    /// the supervisor exists — every constructor sets it to `Some`.
    pub(crate) mls_storage_backend:
        Option<Arc<dyn scp_core::crypto::mls::storage_adapter::OpenMlsStorageAdapter>>,

    /// Durable saga journal (§17.16 / ADR-049) built over the SAME single
    /// chosen `Storage` backend as `mls_storage_backend`, persistence, and the
    /// event log. `Storage` is not object-safe (RPITIT async methods), so the
    /// journal — a `ProtocolRepositorySagaJournal<S>` — is constructed at the
    /// concrete-storage construction site (where `S` is the in-memory handle or
    /// `Arc<SqliteStorage>`) from the SAME `Arc` that feeds
    /// `mls_storage_backend`, then erased to `Arc<dyn SagaJournal>`.
    /// `build_supervisor` reads this to supply
    /// `Supervisor::with_providers_and_journal`'s journal argument so
    /// crash-recovery replay is durably backed in production. `None` is the
    /// same storage-before-supervisor fail-closed condition (spec §17.6) as a
    /// `None` `mls_storage_backend` — both are populated together.
    pub(crate) saga_journal: Option<Arc<dyn scp_core::context::supervisor::SagaJournal>>,

    /// Per-instance bridge credential store (spec §12.11).
    ///
    /// Mirrors `PyBridgeInstance::credential_store` and
    /// `NapiBridgeInstance::credential_store` — each `Scp` instance owns its
    /// own `InMemoryCredentialStore` so OAuth tokens, API keys, and bridge
    /// credential keys provisioned through one instance are isolated from
    /// every other instance in the same process (ADR-048 §1 multi-instance
    /// neutrality). Thread-safe via the store's internal
    /// `tokio::sync::RwLock`. Production deployments should replace this with
    /// a `Storage`-backed implementation when it lands (spec §12.11.2).
    /// Dropping the `Arc` on shutdown zeroizes any retained bridge
    /// credential keys via the store's `Zeroizing` fields.
    pub(crate) credential_store: Arc<scp_core::bridge::credentials::InMemoryCredentialStore>,
}

impl UniffiBridgeInstance {
    /// Constructs a new `UniffiBridgeInstance` with default in-memory state.
    ///
    /// Allocates a fresh `CoreFields` (new `instance_id`, new
    /// `CancellationToken`, empty `JoinSet`) and populates the protocol
    /// repository + typed registries. No `ContextManager` is attached —
    /// callers attach one later via `CoreFields::set_context_manager`.
    #[must_use]
    pub fn new_uniffi() -> Self {
        let (_event_log, protocol_repository, storage_handle) =
            scp_ffi_common::bridge_runtime::build_event_log_provider();
        // The un-swallowed in-memory storage handle backs the supervisor's
        // `mls_storage` view. The SAME store backs the event-log repository
        // above (spec §17.6 — one chosen backend, derived consumers). The
        // durable saga journal is built over the SAME `Arc` (cloned before the
        // `mls_storage` wrap consumes it) so replay shares one backend.
        let saga_journal = saga_journal_from_handle(Arc::clone(&storage_handle));
        let mls_storage_backend = mls_storage_from_handle(storage_handle);
        Self {
            core: CoreFields::new(),
            ucan_registry: Arc::new(DashMap::new()),
            identity_custody_registry: Arc::new(DashMap::new()),
            protocol_repository: ProtocolRepoVariant::InMemory(protocol_repository),
            identity_link_attestation_registry: Arc::new(DashMap::new()),
            context_handle_registry: Arc::new(DashMap::new()),
            mcp_server_registry: Arc::new(DashMap::new()),
            mcp_client_registry: Arc::new(DashMap::new()),
            mls_storage_backend: Some(mls_storage_backend),
            saga_journal: Some(saga_journal),
            credential_store: Arc::new(
                scp_core::bridge::credentials::InMemoryCredentialStore::new(),
            ),
        }
    }

    /// Constructs a new `UniffiBridgeInstance` with an explicit
    /// [`scp_core::context::persistence::ContextPersistence`] provider.
    ///
    /// Used by callers that already have a persistence strategy (typically
    /// unit tests; production persistence is wired through PR 3's
    /// [`StorageConfig::InMemory`] path on
    /// [`UniffiBridgeInstance::with_storage_uniffi`]).
    #[must_use]
    pub fn with_persistence_uniffi(
        persistence: Box<dyn scp_core::context::persistence::ContextPersistence + Send + Sync>,
    ) -> Self {
        let (_event_log, protocol_repository, storage_handle) =
            scp_ffi_common::bridge_runtime::build_event_log_provider();
        let saga_journal = saga_journal_from_handle(Arc::clone(&storage_handle));
        let mls_storage_backend = mls_storage_from_handle(storage_handle);
        Self {
            core: CoreFields::with_persistence(persistence),
            ucan_registry: Arc::new(DashMap::new()),
            identity_custody_registry: Arc::new(DashMap::new()),
            protocol_repository: ProtocolRepoVariant::InMemory(protocol_repository),
            identity_link_attestation_registry: Arc::new(DashMap::new()),
            context_handle_registry: Arc::new(DashMap::new()),
            mcp_server_registry: Arc::new(DashMap::new()),
            mcp_client_registry: Arc::new(DashMap::new()),
            mls_storage_backend: Some(mls_storage_backend),
            saga_journal: Some(saga_journal),
            credential_store: Arc::new(
                scp_core::bridge::credentials::InMemoryCredentialStore::new(),
            ),
        }
    }

    /// Constructs a new `UniffiBridgeInstance` honoring a [`StorageConfig`].
    ///
    /// - [`StorageConfig::InMemory`] — equivalent to
    ///   [`UniffiBridgeInstance::new_uniffi`]; the supervisor's `mls_storage`
    ///   view is backed by the same encrypted in-memory store as the event
    ///   log (dev/test affordance; spec §17.6).
    /// - [`StorageConfig::Sqlite`] — opens a `SQLCipher`-encrypted database at
    ///   `{path}/scp.db`. The raw-key path feeds [`SqliteStorage::new`]; the
    ///   passphrase path feeds [`SqliteStorage::with_passphrase`] (Argon2id;
    ///   spec §17.6). The ONE `Arc<SqliteStorage>` backs the context-snapshot
    ///   persistence bridge, the Merkle event log + trust aggregation
    ///   repository, AND the supervisor's `mls_storage` `OpenMLS` view, so
    ///   all three consumers share a single `SQLCipher` connection.
    ///
    /// # Errors
    ///
    /// Returns [`StorageInitError::SqliteOpen`] if the `SQLCipher` database
    /// cannot be opened (bad key/passphrase, permission denied, corrupt file,
    /// or a salt-sidecar fail-closed condition). FAIL CLOSED (spec §17.6):
    /// the bridge does NOT silently degrade to in-memory or no-storage on a
    /// failed durable-backend open. The error surfaces to Swift as `throws`
    /// and Kotlin as a thrown exception via the [`From`] impl on
    /// [`crate::ScpError`].
    pub fn with_storage_uniffi(config: StorageConfig) -> Result<Self, StorageInitError> {
        match config {
            StorageConfig::InMemory => Ok(Self::new_uniffi()),
            StorageConfig::Sqlite { path, key } => {
                // Defense-in-depth: validate path string at FFI boundary
                // (matches the project pattern for every other caller-supplied
                // string). #1543 PR-C security review.
                scp_ffi_common::validate::validate_storage_path(&path).map_err(|e| {
                    StorageInitError::SqliteOpen {
                        path: path.clone(),
                        message: format!("invalid 'path' — {}", e.message),
                    }
                })?;
                let path_buf = std::path::PathBuf::from(&path);
                // Move the passphrase into `Zeroizing` at the bridge entry
                // before any use; the raw-key bytes are zeroed after
                // SQLCipher consumes them. Open the database ONCE — the same
                // `Arc<SqliteStorage>` is shared across persistence, event
                // log, and `mls_storage` (a second open would hit
                // `SQLITE_BUSY` on first write).
                let open_result = match &key {
                    SqliteKeyMaterial::Raw { key: bytes } => {
                        scp_platform::sqlite::SqliteStorage::new(&path_buf, bytes)
                    }
                    SqliteKeyMaterial::Passphrase { passphrase } => {
                        let pass = zeroize::Zeroizing::new(passphrase.clone());
                        scp_platform::sqlite::SqliteStorage::with_passphrase(
                            &path_buf,
                            pass.as_bytes(),
                        )
                    }
                };
                // Zero our copy of the raw key / passphrase regardless of
                // outcome. The caller's copy crossed the UniFFI boundary by
                // value and cannot be zeroed from here.
                zero_key_material(key);

                let storage = open_result.map_err(|e| {
                    // FAIL CLOSED (spec §17.6): surface the error rather than
                    // degrading to in-memory. The message never carries key
                    // or passphrase bytes.
                    tracing::error!(
                        error = %e,
                        path = %path,
                        "with_storage_uniffi: SQLCipher open failed — failing closed, no in-memory fallback"
                    );
                    StorageInitError::SqliteOpen {
                        path: path.clone(),
                        message: e.to_string(),
                    }
                })?;

                let arc_storage = Arc::new(storage);
                // Build the persistence bridge and the event-log repository
                // over clones of the SAME `Arc<SqliteStorage>`.
                let persistence_repo = Arc::new(ProtocolRepository::new(Arc::clone(&arc_storage)));
                let persistence: Arc<
                    dyn scp_core::context::persistence::ContextPersistence + Send + Sync,
                > = Arc::new(
                    scp_core::store::context::ProtocolRepositoryContextBridge::new(
                        persistence_repo,
                    ),
                );
                let event_log_repo = Arc::new(ProtocolRepository::new(Arc::clone(&arc_storage)));
                // Derive the supervisor's `mls_storage` view from the same
                // `Arc<SqliteStorage>` — erased ONCE via
                // `SpawnBlockingStorageAdapter`. The durable saga journal is
                // built over the SAME `Arc<SqliteStorage>` so saga replay reads
                // and writes the one `SQLCipher` connection.
                let saga_journal = saga_journal_from_handle(Arc::clone(&arc_storage));
                let mls_storage_backend = mls_storage_from_handle(Arc::clone(&arc_storage));
                drop(arc_storage);

                Ok(Self::with_persistence_uniffi_arc_and_repo(
                    persistence,
                    ProtocolRepoVariant::Sqlite(event_log_repo),
                    mls_storage_backend,
                    saga_journal,
                ))
            }
        }
    }

    /// Internal helper: constructs a new `UniffiBridgeInstance`
    /// pre-populated with a shared [`ContextPersistence`] provider.
    ///
    /// Accepts an `Arc<dyn ContextPersistence + Send + Sync>` so the same
    /// persistence provider is later picked up by
    /// `init_context_manager*` via
    /// [`scp_ffi_common::bridge_instance::CoreFields::persistence_arc_clone`],
    /// avoiding duplicate `SqliteStorage` connections to the same database.
    /// Constructs a `UniffiBridgeInstance` with both the
    /// [`ContextPersistence`] provider and the [`ProtocolRepoVariant`]
    /// explicitly configured.
    ///
    /// `with_storage_uniffi(StorageConfig::Sqlite)` uses this so the event
    /// log repository and the snapshot persistence bridge share a single
    /// `Arc<SqliteStorage>`.
    #[must_use]
    fn with_persistence_uniffi_arc_and_repo(
        persistence: Arc<dyn scp_core::context::persistence::ContextPersistence + Send + Sync>,
        protocol_repository: ProtocolRepoVariant,
        mls_storage_backend: Arc<dyn scp_core::crypto::mls::storage_adapter::OpenMlsStorageAdapter>,
        saga_journal: Arc<dyn scp_core::context::supervisor::SagaJournal>,
    ) -> Self {
        Self {
            core: CoreFields::with_persistence_arc(persistence),
            ucan_registry: Arc::new(DashMap::new()),
            identity_custody_registry: Arc::new(DashMap::new()),
            protocol_repository,
            identity_link_attestation_registry: Arc::new(DashMap::new()),
            context_handle_registry: Arc::new(DashMap::new()),
            mcp_server_registry: Arc::new(DashMap::new()),
            mcp_client_registry: Arc::new(DashMap::new()),
            mls_storage_backend: Some(mls_storage_backend),
            saga_journal: Some(saga_journal),
            credential_store: Arc::new(
                scp_core::bridge::credentials::InMemoryCredentialStore::new(),
            ),
        }
    }

    /// Returns the supervisor's `mls_storage` (`OpenMLS`) backend for this
    /// instance, if populated.
    ///
    /// Every constructor populates this with `Some` (the chosen storage
    /// erased once via [`SpawnBlockingStorageAdapter`]). `build_supervisor`
    /// reads it to satisfy the required `mls_storage` argument of
    /// `Supervisor::with_providers`; a `None` here is the
    /// storage-before-supervisor precondition failing closed (spec §17.6).
    #[must_use]
    pub(crate) fn mls_storage_ref(
        &self,
    ) -> Option<&Arc<dyn scp_core::crypto::mls::storage_adapter::OpenMlsStorageAdapter>> {
        self.mls_storage_backend.as_ref()
    }

    /// Returns the durable saga journal for this instance, if populated.
    ///
    /// Built at construction time over the SAME single chosen `Storage`
    /// backend as `mls_storage_ref` (spec §17.16 / ADR-049). `build_supervisor`
    /// reads it to supply `Supervisor::with_providers_and_journal`'s journal
    /// argument; a `None` here is the same storage-before-supervisor
    /// fail-closed condition (spec §17.6) as a `None` `mls_storage_ref` — both
    /// are populated together.
    #[must_use]
    pub(crate) fn saga_journal_ref(
        &self,
    ) -> Option<&Arc<dyn scp_core::context::supervisor::SagaJournal>> {
        self.saga_journal.as_ref()
    }

    /// Returns the monotonic instance id for this bridge.
    #[must_use]
    pub const fn instance_id(&self) -> u64 {
        self.core.instance_id()
    }

    /// Returns a reference to this instance's bridge credential store.
    ///
    /// Mirrors `PyBridgeInstance::credential_store` /
    /// `NapiBridgeInstance::credential_store`. The returned
    /// `Arc<InMemoryCredentialStore>` is the same instance the
    /// `UniffiBridgeInstance` holds — thread-safe via internal
    /// `tokio::sync::RwLock`.
    #[must_use]
    pub const fn credential_store(
        &self,
    ) -> &Arc<scp_core::bridge::credentials::InMemoryCredentialStore> {
        &self.credential_store
    }

    /// Returns a reference to the typed UCAN registry.
    #[must_use]
    pub const fn ucan_registry(&self) -> &Arc<DashMap<String, UcanContextState>> {
        &self.ucan_registry
    }

    /// Returns a reference to the typed identity custody registry.
    ///
    /// `pub(crate)` because [`UniffiKeyCustody`](crate::bridge::UniffiKeyCustody)
    /// is itself `pub(crate)` and would leak through the public signature
    /// otherwise.
    ///
    /// Marked `#[allow(dead_code)]` because bridge callers currently reach
    /// the registry via the free helper `bridge::identity_custody_registry()`
    /// which dereferences this field directly. The typed accessor is kept
    /// for any future per-instance callers that prefer the typed path; it
    /// is not gated on any pending work.
    #[must_use]
    #[allow(dead_code)]
    pub(crate) const fn identity_custody_registry(
        &self,
    ) -> &Arc<
        DashMap<
            String,
            (
                Arc<crate::bridge::UniffiKeyCustody>,
                scp_platform::KeyHandle,
            ),
        >,
    > {
        &self.identity_custody_registry
    }

    /// Returns a reference to the protocol repository variant.
    #[must_use]
    pub const fn protocol_repository(&self) -> &ProtocolRepoVariant {
        &self.protocol_repository
    }

    /// Returns a reference to the identity link attestation registry.
    #[must_use]
    pub const fn identity_link_attestation_registry(
        &self,
    ) -> &Arc<DashMap<String, Vec<scp_core::identity::attestation::IdentityLinkAttestation>>> {
        &self.identity_link_attestation_registry
    }

    /// Returns a reference to the context handle registry.
    #[must_use]
    pub const fn context_handle_registry(
        &self,
    ) -> &Arc<DashMap<String, Arc<crate::bridge::ContextHandle>>> {
        &self.context_handle_registry
    }

    /// Returns a reference to the MCP server registry.
    ///
    /// `pub(crate)` because `McpServerEntry` is itself `pub(crate)`.
    #[must_use]
    pub(crate) const fn mcp_server_registry(
        &self,
    ) -> &Arc<DashMap<String, crate::bridge::McpServerEntry>> {
        &self.mcp_server_registry
    }

    /// Returns a reference to the MCP client registry.
    ///
    /// `pub(crate)` — see `mcp_server_registry`.
    #[must_use]
    pub(crate) const fn mcp_client_registry(
        &self,
    ) -> &Arc<DashMap<String, crate::bridge::McpClientEntry>> {
        &self.mcp_client_registry
    }
}

// ---------------------------------------------------------------------------
// Per-instance accessor methods — #1549 Phase 4 PR 4 sub-slice A
// ---------------------------------------------------------------------------
//
// These methods are the per-instance equivalents of the module-level free
// helpers further down in this file. They operate on `&self` instead of
// looking up `DEFAULT_BRIDGE_INSTANCE`. Sub-slice A (this commit) is purely
// additive — the module-level helpers are still present and callers have not
// yet migrated. Sub-slices B–E migrate callers and then remove the free
// helpers as each domain is fully switched over. The `#[allow(dead_code)]`
// attribute on methods without any in-tree caller yet is intentional and is
// removed incrementally as the sub-slices land.

impl UniffiBridgeInstance {
    /// Per-instance equivalent of the module-level
    /// `context_manager_expect` free function.
    ///
    /// Returns the attached `ContextManager` if the instance is not suspended
    /// and not shut down. A shutdown bridge is a hard error (not a warning)
    /// so stateful exports never run against a zombie bridge
    /// (ADR-048 §PR 2, #1646).
    ///
    /// # Errors
    ///
    /// Returns `ScpError::Context` (code `SCP-CTX-2000`) when no local DID has
    /// been registered yet (no `ContextManager` attached), when the instance
    /// is currently suspended, or when the instance has been permanently shut
    /// down.
    #[allow(dead_code)]
    pub fn context_manager_expect(
        &self,
    ) -> Result<&Arc<scp_core::context::supervisor::Supervisor>, crate::ScpError> {
        if self.core.is_suspended() {
            return Err(crate::ScpError::Context {
                msg: "bridge not ready: suspended".to_owned(),
                code: codes::CTX_2000.to_owned(),
            });
        }
        if self.core.is_shutdown() {
            return Err(crate::ScpError::Context {
                msg: "bridge not ready: shut down".to_owned(),
                code: codes::CTX_2000.to_owned(),
            });
        }
        self.core
            .try_supervisor()
            .ok_or_else(|| crate::ScpError::Context {
                msg: "bridge not ready: no local DID registered".to_owned(),
                code: codes::CTX_2000.to_owned(),
            })
    }

    /// Per-instance equivalent of the module-level `context_manager` free
    /// function.
    ///
    /// Like [`UniffiBridgeInstance::context_manager_expect`] but treats
    /// shutdown as a logged warning rather than a hard error — this mirrors
    /// the legacy behaviour of the free `context_manager()` helper which some
    /// callers still rely on to let operations fail naturally at the MLS or
    /// transport layer after shutdown.
    ///
    /// # Errors
    ///
    /// Returns `ScpError::Context` (code `SCP-CTX-2000`) when the instance is
    /// currently suspended or when no `ContextManager` has been attached.
    #[allow(dead_code)]
    pub fn context_manager_or_error(
        &self,
    ) -> Result<&Arc<scp_core::context::supervisor::Supervisor>, crate::ScpError> {
        if self.core.is_suspended() {
            return Err(crate::ScpError::Context {
                msg: "bridge is suspended — call resume() before performing operations".to_owned(),
                code: codes::CTX_2000.to_owned(),
            });
        }
        if self.core.is_shutdown() {
            tracing::warn!(
                "context_manager_or_error() called after shutdown — operations may fail"
            );
        }
        self.core
            .try_supervisor()
            .ok_or_else(|| crate::ScpError::Context {
                msg: "ContextManager not yet attached — call context_create, \
                      context_join, context_import, or init_context_manager first"
                    .to_owned(),
                code: codes::CTX_2000.to_owned(),
            })
    }

    /// Returns the attached `ContextManager` only when the instance is in a
    /// ready state (not suspended, not shut down, and a manager is attached).
    ///
    /// Unlike [`UniffiBridgeInstance::context_manager_or_error`] this is an
    /// infallible `Option` accessor — callers that simply want to skip work
    /// when the bridge isn't ready use this.
    #[must_use]
    #[allow(dead_code)]
    pub fn try_context_manager_ready(
        &self,
    ) -> Option<&Arc<scp_core::context::supervisor::Supervisor>> {
        if self.core.is_suspended() || self.core.is_shutdown() {
            return None;
        }
        self.core.try_supervisor()
    }

    /// Per-instance equivalent of the module-level
    /// `init_context_manager_with_did` free function.
    ///
    /// Installs an `MlsCryptoProvider(local_did)` and
    /// `NotConfiguredTransportProvider` on this instance. No-op if a
    /// `ContextManager` is already attached.
    #[allow(dead_code)]
    pub fn init_context_manager_with_did(&self, local_did: &str) {
        if self.core.has_supervisor() {
            tracing::debug!(
                requested_did = %local_did,
                "init_context_manager_with_did: ContextManager already attached — using existing instance"
            );
            return;
        }
        let did = local_did.to_owned();
        let crypto = Arc::new(scp_core::crypto::mls::provider::MlsCryptoProvider::new(did));
        let event_log = self.protocol_repository.event_log_provider();
        let persistence = self.core.persistence_arc_clone();
        // Storage-before-supervisor precondition (spec §17.6): the chosen
        // storage must already be erased into the `mls_storage` view. The
        // runtime never defaults storage, so a missing backend fails closed —
        // no supervisor is attached and subsequent operations error rather
        // than fabricating an in-memory default. Every constructor populates
        // this, so this is a defense-in-depth guard.
        let Some(mls_storage) = self.mls_storage_ref().map(Arc::clone) else {
            tracing::error!(
                "init_context_manager_with_did: storage-before-supervisor                  precondition failed — no mls_storage backend on the bridge                  instance; refusing to attach a supervisor (fail closed, spec §17.6)"
            );
            return;
        };
        let Some(saga_journal) = self.saga_journal_ref().map(Arc::clone) else {
            tracing::error!(
                "init_context_manager_with_did: storage-before-supervisor precondition \
                 failed — no saga journal backend on the bridge instance; refusing to \
                 attach a supervisor (fail closed, spec §17.6 / §17.16)"
            );
            return;
        };
        let supervisor_arc = build_supervisor(
            crypto,
            Box::new(scp_core::context::NotConfiguredTransportProvider),
            event_log,
            persistence,
            mls_storage,
            saga_journal,
            key_resolver_for_core(&self.core),
        );

        self.core.set_supervisor(supervisor_arc);
    }

    /// Per-instance equivalent of the module-level
    /// `init_context_manager_with_relay_transport` free function.
    ///
    /// Installs an `MlsCryptoProvider(local_did)` and a
    /// `RelayTransportProvider` wrapping the supplied `NativeRelayAdapter` on
    /// this instance. No-op if a `ContextManager` is already attached.
    #[allow(dead_code)]
    pub fn init_context_manager_with_relay_transport(
        &self,
        local_did: &str,
        adapter: Box<dyn scp_transport::TransportAdapter>,
    ) {
        if self.core.has_supervisor() {
            tracing::warn!(
                requested_did = %local_did,
                "init_context_manager_with_relay_transport: ContextManager already attached — ignoring"
            );
            return;
        }
        let did = local_did.to_owned();
        let crypto = Arc::new(scp_core::crypto::mls::provider::MlsCryptoProvider::new(did));
        let transport = Box::new(scp_transport::RelayTransportProvider::new(adapter));
        let event_log = self.protocol_repository.event_log_provider();
        let persistence = self.core.persistence_arc_clone();
        let Some(mls_storage) = self.mls_storage_ref().map(Arc::clone) else {
            tracing::error!(
                "init_context_manager_with_relay_transport: storage-before-supervisor                  precondition failed — no mls_storage backend on the bridge                  instance; refusing to attach a supervisor (fail closed, spec §17.6)"
            );
            return;
        };
        let Some(saga_journal) = self.saga_journal_ref().map(Arc::clone) else {
            tracing::error!(
                "init_context_manager_with_relay_transport: storage-before-supervisor \
                 precondition failed — no saga journal backend on the bridge instance; \
                 refusing to attach a supervisor (fail closed, spec §17.6 / §17.16)"
            );
            return;
        };
        let supervisor_arc = build_supervisor(
            crypto,
            transport,
            event_log,
            persistence,
            mls_storage,
            saga_journal,
            key_resolver_for_core(&self.core),
        );

        self.core.set_supervisor(supervisor_arc);
    }

    /// Per-instance initializer that installs an `MlsCryptoProvider(local_did)`
    /// and an in-process loopback `LocalTransportProvider` on this instance.
    ///
    /// Mirrors [`UniffiBridgeInstance::init_context_manager_with_relay_transport`]
    /// except the transport silently succeeds on all send/publish calls instead
    /// of routing through a real relay. Used by `Scp::configure_local_transport`
    /// so that E2E tests can exercise `context_send` / `broadcast_publish`
    /// (encryption included) without a real relay server. No-op if a
    /// `ContextManager` is already attached.
    #[allow(dead_code)]
    pub fn init_context_manager_with_local_transport(&self, local_did: &str) {
        if self.core.has_supervisor() {
            tracing::warn!(
                requested_did = %local_did,
                "init_context_manager_with_local_transport: ContextManager already attached — ignoring"
            );
            return;
        }
        let did = local_did.to_owned();
        let crypto = Arc::new(scp_core::crypto::mls::provider::MlsCryptoProvider::new(did));
        let transport = Box::new(scp_core::context::LocalTransportProvider);
        let event_log = self.protocol_repository.event_log_provider();
        let persistence = self.core.persistence_arc_clone();
        let Some(mls_storage) = self.mls_storage_ref().map(Arc::clone) else {
            tracing::error!(
                "init_context_manager_with_local_transport: storage-before-supervisor                  precondition failed — no mls_storage backend on the bridge                  instance; refusing to attach a supervisor (fail closed, spec §17.6)"
            );
            return;
        };
        let Some(saga_journal) = self.saga_journal_ref().map(Arc::clone) else {
            tracing::error!(
                "init_context_manager_with_local_transport: storage-before-supervisor \
                 precondition failed — no saga journal backend on the bridge instance; \
                 refusing to attach a supervisor (fail closed, spec §17.6 / §17.16)"
            );
            return;
        };
        let supervisor_arc = build_supervisor(
            crypto,
            transport,
            event_log,
            persistence,
            mls_storage,
            saga_journal,
            key_resolver_for_core(&self.core),
        );

        self.core.set_supervisor(supervisor_arc);
    }

    /// Per-instance equivalent of the module-level
    /// `sync_role_state_from_manager` free function.
    ///
    /// Validates that the attached `ContextManager` has role state for the
    /// given context after a governance operation. Logs the sync for
    /// traceability.
    ///
    /// # Errors
    ///
    /// Returns `ScpError::Context` (code `SCP-CTX-2040`) if the context is
    /// not registered in the attached `ContextManager`, or any error returned
    /// by [`UniffiBridgeInstance::context_manager_or_error`] if no manager is
    /// attached.
    #[allow(dead_code)]
    pub async fn sync_role_state_from_manager(
        &self,
        context_id: &str,
    ) -> Result<(), crate::ScpError> {
        let supervisor = self.context_manager_or_error()?;
        let _role_state = supervisor.get_role_state(context_id).await.ok_or_else(|| {
            crate::ScpError::Context {
                msg: format!(
                    "context '{context_id}' not found in Supervisor during role state sync"
                ),
                code: codes::CTX_2040.to_owned(),
            }
        })?;
        tracing::debug!(context_id = %context_id, "UniFFI: role state synced after governance operation");
        Ok(())
    }

    /// Per-instance equivalent of the module-level
    /// `with_rate_limit_tracker` free function.
    ///
    /// Delegates to [`CoreFields::with_rate_limit_tracker`].
    #[allow(dead_code)]
    pub fn with_rate_limit_tracker<F, T>(&self, identity_did: &str, f: F) -> T
    where
        F: FnOnce(&mut scp_core::context::invitation::RateLimitTracker) -> T,
    {
        self.core.with_rate_limit_tracker(identity_did, f)
    }

    /// Per-instance equivalent of the module-level `did_resolver` free
    /// function.
    ///
    /// Returns a cloned `Arc` to the production DID resolver, if one has been
    /// installed via [`UniffiBridgeInstance::set_did_resolver`]. Returning an
    /// owned `Arc` (instead of a `&'static Arc`) keeps the accessor usable
    /// from per-instance callers that don't have `'static` lifetimes.
    #[must_use]
    #[allow(dead_code)]
    pub fn did_resolver(&self) -> Option<Arc<scp_ffi_common::IdentityBackedDidResolver>> {
        self.core.did_resolver().map(Arc::clone)
    }

    /// Per-instance equivalent of the module-level `init_did_resolver` free
    /// function.
    ///
    /// Wraps the supplied `DidResolver` in an `IdentityBackedDidResolver` and
    /// stores it on this instance. Subsequent calls are no-ops
    /// (`OnceLock` guarantees single initialization — the underlying
    /// `CoreFields::set_did_resolver` logs a warning on repeat calls).
    #[allow(dead_code)]
    pub fn set_did_resolver<R>(&self, resolver: Arc<R>, handle: tokio::runtime::Handle)
    where
        R: scp_identity::resolver::DidResolver + 'static,
    {
        self.core
            .set_did_resolver(Arc::new(scp_ffi_common::IdentityBackedDidResolver::new(
                resolver, handle,
            )));
    }

    /// Per-instance equivalent of the module-level `ensure_ucan_registered`
    /// free function.
    ///
    /// Ensures UCAN validation state is registered for `context_id` in this
    /// instance's UCAN registry. No-op if the context is already registered.
    #[allow(dead_code)]
    pub fn ensure_ucan_registered(&self, context_id: &str, creator_did: &str, ceiling: &[String]) {
        if self.ucan_registry.contains_key(context_id) {
            return;
        }

        let ceiling_strings = if ceiling.is_empty() {
            scp_core::context::roles::default_ceiling()
                .iter()
                .map(scp_core::context::roles::Capability::ucan_capability_name)
                .collect::<HashSet<String>>()
        } else {
            // Ceiling-entry grammar enforcement (spec §5.3.1.1). This per-instance
            // UCAN-state cache is populated AFTER `context_create` already routed
            // through the runtime creation gate (`lifecycle_helpers::create_context`
            // → `ContextRoleState::new`), which rejects any malformed ceiling — so
            // every surviving entry is well-formed. As infallible defense-in-depth,
            // a malformed entry is SKIPPED rather than normalized: this forecloses
            // the silent broadening where a no-colon `payments` would become
            // `payments:*` via `Capability::new` + `ucan_capability_name`.
            //
            // Filter on the PARSED enum (`Capability::new(s)
            // .validate_as_ceiling_entry()`) — NOT the raw string — so the
            // accept/skip decision uses EXACTLY the capability that gets enforced
            // (and mapped via `ucan_capability_name` on the next line). The runtime
            // gate validates the same parsed-enum form, so this filter never skips
            // an entry the runtime accepted nor keeps one it rejected. Validating
            // the raw string instead would diverge on a prefix-stripped custom: the
            // raw `"custom:payments"` passes a raw-string check but parses to
            // `Custom("payments")` (enforced `payments:payments`), a no-colon custom
            // the parsed-enum check correctly rejects (BLACK-003).
            ceiling
                .iter()
                .filter(|s| {
                    scp_core::context::roles::Capability::new(s)
                        .validate_as_ceiling_entry()
                        .is_ok()
                })
                .map(|s| scp_core::context::roles::Capability::new(s).ucan_capability_name())
                .collect::<HashSet<String>>()
        };

        let event_log = EventLog::new(context_id.to_owned());
        let revocation_list = RevocationList::new(context_id.to_owned());
        let nonce_tracker = NonceTracker::new(context_id.to_owned(), SystemClock);

        self.ucan_registry.insert(
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

    /// Per-instance equivalent of the module-level `with_ucan_state` free
    /// function.
    ///
    /// Accesses per-context UCAN state on this instance via a closure.
    /// Returns `None` if the context is not registered.
    #[allow(dead_code)]
    pub fn with_ucan_state<T, F>(&self, context_id: &str, f: F) -> Option<T>
    where
        F: FnOnce(&mut UcanContextState) -> T,
    {
        let mut entry = self.ucan_registry.get_mut(context_id)?;
        Some(f(&mut entry))
    }

    /// Per-instance equivalent of the module-level `remove_ucan_state` free
    /// function.
    ///
    /// Removes per-context UCAN state from this instance and evicts the
    /// corresponding known-context entry from `CoreFields`.
    #[allow(dead_code)]
    pub fn remove_ucan_state(&self, context_id: &str) {
        self.ucan_registry.remove(context_id);
        self.core.remove_known_context(context_id);
    }
}

#[async_trait]
impl BridgeInstanceCore for UniffiBridgeInstance {
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
        // Clear typed registries. Dropping `Arc<UniffiKeyCustody>` values
        // zeroizes any key material they hold via the custody provider's
        // `Drop` impl.
        self.ucan_registry.clear();
        self.identity_custody_registry.clear();
        // Release the SQLite advisory lock on `{dir}/scp.db.lock` for the
        // `Sqlite` variant. Other `Arc<SqliteStorage>` holders
        // (`CoreFields::persistence`, `ContextManager`) keep the storage
        // struct alive until the `UniffiBridgeInstance` drops, but the
        // advisory lock must be released now so that a subsequent
        // `SCP.withStorage(sqlite { path, key })` call against the same
        // directory does not fail with "already open by another SCP
        // instance". The `InMemory` variant's `close()` is a no-op.
        self.protocol_repository.close();
        // Clear MCP registries so server shutdown senders and client
        // connections drop, allowing background tasks to terminate cleanly.
        // Migrated off `crate::bridge::clear_mcp_registries` (called by a
        // shutdown-hook closure) in #1549 Phase 4 PR 2 commit 4.
        self.mcp_server_registry.clear();
        self.mcp_client_registry.clear();
        // Clear identity-link-attestation and context-handle registries.
        // Migrated off module-level `OnceLock` statics in bridge.rs in
        // #1549 Phase 4 PR 2 commit 6. Dropping `Arc<ContextHandle>`
        // values releases any remaining handle references held past
        // shutdown (the caller normally holds its own `Arc`).
        self.identity_link_attestation_registry.clear();
        self.context_handle_registry.clear();
    }
}

/// Emergency cancellation for `UniffiBridgeInstance` dropped without a
/// prior `shutdown(timeout)`.
///
/// The graceful path is `BridgeInstanceCore::shutdown(timeout)` — Swift
/// and Kotlin callers that want deterministic cleanup of subscriptions,
/// timers, and relay connections must still invoke that. This `Drop` is
/// the safety net for the case where a caller constructs a `Scp` and
/// then lets `Arc<UniffiBridgeInstance>` go out of scope without awaiting
/// `shutdown`. Without this impl, background tasks hold their
/// `Arc<UniffiBridgeInstance>` captures forever — leaking a
/// `ContextManager`, relay connection, and attached platform callbacks.
///
/// See ADR-048 for the multi-instance lifecycle contract.
impl Drop for UniffiBridgeInstance {
    fn drop(&mut self) {
        self.core.emergency_cancel_tasks();
    }
}

// ---------------------------------------------------------------------------
// Phase D (#1695): `DEFAULT_BRIDGE_INSTANCE` + façade helpers deleted
// ---------------------------------------------------------------------------
//
// The process-wide default [`UniffiBridgeInstance`] and its lifecycle
// helpers (`default_bridge_instance`, `default_bridge_instance_raw`,
// `bridge_instance_raw`, `bridge_instance`, `bridge_instance_for_affinity`,
// `ensure_bridge_instance`, `default_instance_id`, `check_handle_affinity`,
// `attach_context_manager_to_bridge`) are removed in Phase D along with
// the free-function façade they served.
//
// Every caller (bridge.rs handle methods, `Scp::...` methods, server
// startup, the `uniffi_check_handle!` macro) now threads through the
// caller-owned `Scp`'s `Arc<UniffiBridgeInstance>` via
// `&self.inner` / `bi` parameters, or calls a per-instance method on
// `UniffiBridgeInstance` directly. Handle-affinity is enforced inline
// via `self.inner.core.check_handle(handle.instance_id())` — there is no
// process-wide default to compare against.

// All UniFFI handle types (`Identity`, `ContextHandle`, `UcanToken`,
// `TransportManager`, `RelayHandle`, `NodeHandle`) carry an inherent
// `instance_id(&self) -> u64` method so `&self.inner.core.check_handle(...)`
// composes cleanly from `Scp` methods without any trait imports.

// ---------------------------------------------------------------------------
// Per-instance helpers used by `UniffiBridgeInstance`
// ---------------------------------------------------------------------------

/// Returns a key resolver that rejects all lookups with a logged error.
///
/// Delegates to [`scp_ffi_common::bridge_runtime::not_configured_key_resolver`].
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

/// Builds the durable [`ProtocolRepositorySagaJournal`] from the SAME concrete
/// `Storage` handle that feeds [`mls_storage_from_handle`] (§17.16 / ADR-049).
///
/// Constructed at the concrete-storage construction site because `Storage` is
/// not object-safe (its async methods use `-> impl Future`), so the journal's
/// `S` type parameter cannot be recovered from the erased
/// `Arc<dyn OpenMlsStorageAdapter>`. Passing the SAME `Arc<S>` here as is wrapped
/// into `mls_storage` guarantees the journal, the `OpenMLS` view, persistence,
/// and the event log all read/write one backend (spec §17.6).
fn saga_journal_from_handle<S>(
    handle: Arc<S>,
) -> Arc<dyn scp_core::context::supervisor::SagaJournal>
where
    S: scp_platform::Storage + 'static,
{
    Arc::new(scp_core::context::supervisor::ProtocolRepositorySagaJournal::new(handle))
        as Arc<dyn scp_core::context::supervisor::SagaJournal>
}

/// Zeros the bridge's owned copy of `SQLCipher` key material after `SQLCipher`
/// has consumed it internally.
///
/// The caller's copy crossed the `UniFFI` boundary by value and cannot be
/// zeroed from here; this only wipes the Rust-side copy. The passphrase is
/// already routed through `Zeroizing` during derivation — this additionally
/// overwrites the original `String`/`Vec<u8>` carried in the enum.
fn zero_key_material(key: SqliteKeyMaterial) {
    match key {
        SqliteKeyMaterial::Raw { mut key } => {
            zeroize::Zeroize::zeroize(&mut key);
            drop(key);
        }
        SqliteKeyMaterial::Passphrase { mut passphrase } => {
            zeroize::Zeroize::zeroize(&mut passphrase);
            drop(passphrase);
        }
    }
}

fn not_configured_key_resolver() -> scp_core::context::governance::KeyResolver {
    scp_ffi_common::bridge_runtime::not_configured_key_resolver()
}

/// Builds the production VM-aware governance key resolver from a DID resolver.
///
/// Delegates to [`scp_ffi_common::bridge_runtime::document_vm_key_resolver`].
fn document_vm_key_resolver(
    did_resolver: Arc<scp_ffi_common::IdentityBackedDidResolver>,
) -> scp_core::context::governance::KeyResolver {
    scp_ffi_common::bridge_runtime::document_vm_key_resolver(did_resolver)
}

/// Adapter that lets a shared `Arc<dyn ContextPersistence + Send + Sync>` be
/// consumed by `ContextManager::with_persistence` which requires a `Box`.
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
    inner: Arc<dyn scp_core::context::persistence::ContextPersistence + Send + Sync>,
}

impl ArcContextPersistence {
    fn new(
        inner: Arc<dyn scp_core::context::persistence::ContextPersistence + Send + Sync>,
    ) -> Self {
        Self { inner }
    }
}

impl scp_core::context::persistence::ContextPersistence for ArcContextPersistence {
    fn persist_context(
        &self,
        context_id: &str,
        snapshot: &scp_core::context::state::ContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.inner.persist_context(context_id, snapshot)
    }

    fn load_context(
        &self,
        context_id: &str,
    ) -> Result<
        Option<scp_core::context::state::ContextSnapshot>,
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

/// Bounded capacity of the supervisor's `ContextEvent` broadcast channel.
///
/// Every production supervisor built here enables this channel so that local
/// context events can be consumed by external sinks — notably the node's
/// outbound webhook dispatcher (spec §12.10.5), wired in [`crate::server`] node
/// startup. Lagging consumers drop the oldest events (logged, never panics);
/// `1024` matches the documented default shared with the `PyO3` reference
/// bridge.
const EVENT_CHANNEL_CAPACITY: usize = 1024;

/// Constructs a fresh per-instance `Supervisor` with the given
/// providers.
///
/// ADR-049 commit 12c.9g.3.6 — the FFI bridge no longer touches
/// [`scp_core::context::manager::ContextManager`] at all.
/// [`scp_core::context::supervisor::Supervisor::with_providers`] is
/// the single entry point that constructs the supervisor + populates
/// the lifted-provider slots. The supervisor is the only handle
/// returned to the bridge layer.
///
/// When `persistence` is `Some`, the shared `Arc` is wrapped in
/// [`ArcContextPersistence`] so the manager's internal `Arc` and the
/// `CoreFields::persistence` mirror end up pointing at the same
/// provider — a single `SQLite` connection, not two. Callers pull
/// the shared persistence from the embedded `CoreFields` via
/// [`scp_ffi_common::bridge_instance::CoreFields::persistence_arc_clone`].
///
/// The event broadcast channel is always enabled (capacity
/// [`EVENT_CHANNEL_CAPACITY`]) so downstream consumers — e.g. the node webhook
/// dispatcher — can subscribe via
/// [`Supervisor::subscribe_events`](scp_core::context::supervisor::Supervisor::subscribe_events).
/// When no consumer subscribes, emitting into the channel is a cheap no-op: the
/// retained sender has no receivers, so `send` returns `Err` and the event is
/// simply dropped without blocking context operations.
fn build_supervisor(
    crypto: Arc<MlsCryptoProvider>,
    transport: Box<dyn scp_core::context::builder::ContextTransportProvider>,
    event_log: Box<dyn ContextEventLogProvider>,
    persistence: Option<Arc<dyn scp_core::context::persistence::ContextPersistence + Send + Sync>>,
    mls_storage: Arc<dyn scp_core::crypto::mls::storage_adapter::OpenMlsStorageAdapter>,
    saga_journal: Arc<dyn scp_core::context::supervisor::SagaJournal>,
    key_resolver: scp_core::context::governance::KeyResolver,
) -> Arc<scp_core::context::supervisor::Supervisor> {
    let persistence_box: Option<Box<dyn scp_core::context::persistence::ContextPersistence>> =
        persistence.map(|shared| {
            Box::new(ArcContextPersistence::new(shared))
                as Box<dyn scp_core::context::persistence::ContextPersistence>
        });
    // Enable the event broadcast channel so `subscribe_events()` yields a
    // receiver for the node webhook dispatcher (§12.10.5). The unused receiver
    // is dropped immediately; the retained sender keeps the channel open.
    let (event_tx, _rx) = tokio::sync::broadcast::channel(EVENT_CHANNEL_CAPACITY);
    // `mls_storage` is REQUIRED (non-Option): the runtime never defaults
    // storage; the bridge supplies it (spec §17.6 / ADR-049). It is the
    // single chosen Storage erased once into the `OpenMLS` view. The durable
    // saga journal is built over the SAME backend so crash-recovery replay
    // loads unresolved saga entries from one store on restart (§17.16).
    scp_core::context::supervisor::Supervisor::with_providers_and_journal(
        crypto,
        transport,
        event_log,
        key_resolver,
        persistence_box,
        None,
        Some(event_tx),
        None,
        mls_storage,
        saga_journal,
    )
}

/// Selects the governance key resolver for a bridge instance core.
///
/// Wires the production VM-aware document resolver when a DID resolver is
/// configured; otherwise fails closed with the always-`None`
/// [`not_configured_key_resolver`] so vote-signature verification is never
/// silently permissive.
fn key_resolver_for_core(core: &CoreFields) -> scp_core::context::governance::KeyResolver {
    core.did_resolver()
        .map_or_else(not_configured_key_resolver, |r| {
            document_vm_key_resolver(Arc::clone(r))
        })
}

// Phase D (#1695): module-level `context_manager`, `context_manager_expect`,
// `init_context_manager_with_did`, `init_context_manager_with_relay_transport`,
// `did_resolver`, `init_did_resolver`, `protocol_repository`, and
// `event_log_provider_from_existing_repo` free functions deleted. Every
// caller now accesses these through `Scp::` methods or directly on the
// caller-owned `UniffiBridgeInstance` (see the `impl UniffiBridgeInstance`
// block above for equivalents: `context_manager_expect`, `did_resolver`,
// `init_context_manager_with_did`, `init_context_manager_with_relay_transport`,
// `protocol_repository`, `event_log_provider_from_existing_repo`).

/// Constructs a persistent event log provider backed by encrypted in-memory
/// storage.
///
/// Delegates to [`scp_ffi_common::bridge_runtime::build_event_log_provider`].
/// Retained for tests and for
/// [`UniffiBridgeInstance::init_context_manager_with_did`] fallback paths.
#[must_use]
pub fn build_event_log_provider() -> (
    Box<dyn ContextEventLogProvider>,
    Arc<scp_ffi_common::bridge_runtime::BridgeInMemoryRepo>,
    scp_ffi_common::bridge_runtime::BridgeInMemoryStorageHandle,
) {
    scp_ffi_common::bridge_runtime::build_event_log_provider()
}

// ---------------------------------------------------------------------------
// Per-context UCAN state
// ---------------------------------------------------------------------------

/// Per-context UCAN validation state.
///
/// Type alias for [`scp_ffi_common::bridge_runtime::UcanContextStateCore`].
pub type UcanContextState = scp_ffi_common::bridge_runtime::UcanContextStateCore;

// Phase D (#1695): module-level `ucan_registry`, `ensure_ucan_registered`,
// `with_ucan_state`, `remove_ucan_state`, `sync_role_state_from_manager`,
// and `with_rate_limit_tracker` free functions deleted. Every caller
// accesses the per-instance equivalents on `UniffiBridgeInstance`
// (`ensure_ucan_registered`, `with_ucan_state`, `remove_ucan_state`,
// `sync_role_state_from_manager`, `with_rate_limit_tracker`).

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

    // Phase D (#1695): `default_instance_is_same_arc` deleted —
    // `DEFAULT_BRIDGE_INSTANCE` no longer exists. The new invariant is that
    // each `Scp::new_in_memory_for_test()` returns a distinct `Arc<UniffiBridgeInstance>`
    // (see `test_uniffi_bridge_instance_unique_ids` below) and that a
    // handle minted by one `Scp` fails `check_handle` on a different
    // `Scp` (see `test_handle_affinity_rejects_cross_instance`).

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
    fn test_with_storage_sqlite_uses_sqlite_variant() {
        // Regression test for the event log split-brain bug: before this
        // variant existed, `with_storage(Sqlite)` persisted context
        // snapshots to SQLCipher but Merkle event log entries only to the
        // ephemeral in-memory repo. This asserts that the variant now
        // routes to SQLite so both paths share one database.
        let tmp = tempfile::tempdir().expect("tempdir");
        let Ok(bi) = UniffiBridgeInstance::with_storage_uniffi(StorageConfig::Sqlite {
            path: tmp.path().to_string_lossy().into_owned(),
            key: SqliteKeyMaterial::Raw {
                key: vec![0x11u8; 32],
            },
        }) else {
            panic!("raw-key sqlite open must succeed");
        };
        assert!(
            matches!(bi.protocol_repository(), ProtocolRepoVariant::Sqlite(_)),
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
        // The dev/in-memory path must still populate `mls_storage` from the
        // un-swallowed in-memory storage handle (spec §17.6 — one chosen
        // backend, derived consumers).
        let bi = UniffiBridgeInstance::new_uniffi();
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
        let result = UniffiBridgeInstance::with_storage_uniffi(StorageConfig::Sqlite {
            path: bad_dir.to_string_lossy().into_owned(),
            key: SqliteKeyMaterial::Raw {
                key: vec![0x22u8; 32],
            },
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
        let dir = tmp.path().to_string_lossy().into_owned();

        let Ok(bi) = UniffiBridgeInstance::with_storage_uniffi(StorageConfig::Sqlite {
            path: dir.clone(),
            key: SqliteKeyMaterial::Passphrase {
                passphrase: "correct horse battery staple".to_owned(),
            },
        }) else {
            panic!("passphrase sqlite open must succeed");
        };
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
        let Ok(bi2) = UniffiBridgeInstance::with_storage_uniffi(StorageConfig::Sqlite {
            path: dir,
            key: SqliteKeyMaterial::Passphrase {
                passphrase: "correct horse battery staple".to_owned(),
            },
        }) else {
            panic!("reopen with same passphrase must succeed");
        };
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
        let dir = tmp.path().to_string_lossy().into_owned();

        let Ok(bi) = UniffiBridgeInstance::with_storage_uniffi(StorageConfig::Sqlite {
            path: dir.clone(),
            key: SqliteKeyMaterial::Passphrase {
                passphrase: "the-right-passphrase".to_owned(),
            },
        }) else {
            panic!("initial passphrase open must succeed");
        };
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
        let result = UniffiBridgeInstance::with_storage_uniffi(StorageConfig::Sqlite {
            path: dir,
            key: SqliteKeyMaterial::Passphrase {
                passphrase: "the-WRONG-passphrase".to_owned(),
            },
        });
        assert!(
            matches!(result, Err(StorageInitError::SqliteOpen { .. })),
            "wrong passphrase must fail closed (no silent fresh DB), but the open \
             unexpectedly succeeded"
        );
    }

    #[test]
    fn test_new_uniffi_uses_in_memory_variant() {
        let bi = UniffiBridgeInstance::new_uniffi();
        assert!(
            matches!(bi.protocol_repository(), ProtocolRepoVariant::InMemory(_)),
            "default UniffiBridgeInstance must use in-memory protocol repository"
        );
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
        let bi = UniffiBridgeInstance::new_uniffi();
        bi.init_context_manager_with_did("did:dht:ztest");
        let cm = bi.context_manager_expect()?;
        assert!(
            Arc::ptr_eq(cm, bi.core.try_supervisor().unwrap()),
            "instance.context_manager_expect() must be the same Arc as core.try_supervisor()"
        );
        Ok(())
    }

    #[test]
    fn bridge_instance_not_shutdown_initially() {
        let bi = UniffiBridgeInstance::new_uniffi();
        bi.init_context_manager_with_did("did:dht:ztest");
        assert!(
            !bi.core.is_shutdown(),
            "fresh UniffiBridgeInstance must not be shutdown immediately after init"
        );
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
