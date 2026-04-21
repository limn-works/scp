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
//! 1. `Scp::new` (or `Scp::with_storage` / `Scp::with_persistence`)
//!    constructs a fresh `UniffiBridgeInstance`; per-instance setup
//!    (e.g. `init_context_manager_with_did`, transport setup) happens
//!    lazily on the first `Scp::identity_create` / `context_create` /
//!    `context_join` call.
//! 2. `Scp::method(...)` delegates to methods on
//!    `UniffiBridgeInstance` (`context_manager_expect`, `with_ucan_state`,
//!    `ensure_ucan_registered`, `did_resolver`, etc.) — all per-instance,
//!    no process-wide shared state.
//! 3. The instance is dropped when the last `Arc` reference is released
//!    or permanently deactivated via [`UniffiBridgeInstance::shutdown`].
//!
//! This replaces the old `DashMap<String, ContextRuntime>` global registry
//! (deleted as part of issue #387), the type-erased `Box<dyn Any>` slots on
//! `BridgeInstance` (deleted as part of #1549 Phase 4 PR 1), and the
//! process-wide `DEFAULT_BRIDGE_INSTANCE` façade (deleted as part of
//! #1549 Phase 4 PR 4 Phase D).

use async_trait::async_trait;
use scp_ffi_common::bridge_instance::{BridgeInstanceCore, ShutdownError, ShutdownOutcome};
// Re-export `CoreFields` at `crate::runtime::CoreFields` so bridge.rs
// and server.rs can name it in impl blocks without pulling in the full
// path.
pub use scp_ffi_common::bridge_instance::CoreFields;
use scp_ffi_common::bridge_runtime::BridgeInMemoryStorage;
use scp_ffi_common::error_codes as codes;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use scp_core::context::builder::{ContextCryptoProvider, ContextEventLogProvider};
use scp_core::context::manager::ContextManager;
use scp_core::context::providers::MerkleEventLogProvider;
use scp_core::crypto::ucan::nonce::NonceTracker;
use scp_core::crypto::ucan::revoke::RevocationList;
use scp_core::store::ProtocolRepository;
use scp_core::store::context::ProtocolRepositoryEventLogBridge;
use scp_event_log::EventLog;
use scp_identity::cache::SystemClock;
use scp_platform::encrypting_adapter::EncryptingAdapter;
use scp_platform::sqlite::SqliteStorage;

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

/// Protocol repository variant: an `Arc<ProtocolRepository<_>>` whose inner
/// `Storage` matches the bridge's configured persistence backend.
///
/// Before this variant existed, `UniffiBridgeInstance::protocol_repository`
/// was always `Arc<ProtocolRepository<EncryptingAdapter<BridgeInMemoryStorage>>>`,
/// even when the bridge was constructed with [`StorageConfig::Sqlite`]. That
/// meant the Merkle event log — which uses the protocol repository as its
/// backing `EventLogPersistence` — silently ran against an ephemeral
/// in-memory store, while context snapshots correctly landed in `SQLite`. On
/// restart the event log would be empty even though the rest of the state
/// survived, producing a split-brain the caller had no way to detect.
///
/// The enum dispatches the event log bridge and the trust bridge onto the
/// real backing store for each variant, so `SCP({storage: sqlite})` now
/// persists *both* snapshots and Merkle event log entries to the same
/// `SQLCipher` database.
pub enum ProtocolRepoVariant {
    /// Encrypted in-memory repository. Event log and trust aggregation are
    /// backed by an `EncryptingAdapter<BridgeInMemoryStorage>` with a random
    /// per-instance AES-256-GCM key. Data is lost when the instance drops.
    InMemory(Arc<ProtocolRepository<EncryptingAdapter<BridgeInMemoryStorage>>>),
    /// SQLCipher-backed repository. Event log and trust aggregation share the
    /// same `Arc<SqliteStorage>` that backs `CoreFields::persistence`, so
    /// context snapshots, trust attestations, and event log entries all
    /// survive restart and share a single `SQLCipher` connection.
    Sqlite(Arc<ProtocolRepository<Arc<SqliteStorage>>>),
}

impl ProtocolRepoVariant {
    /// Constructs a [`ContextEventLogProvider`] backed by this repository.
    ///
    /// The bridge is retained by `Arc` inside [`MerkleEventLogProvider`], so
    /// subsequent `append` calls persist entries through the backing store
    /// that was configured at instance-construction time.
    #[must_use]
    pub fn event_log_provider(&self) -> Box<dyn ContextEventLogProvider> {
        match self {
            Self::InMemory(repo) => {
                let bridge = ProtocolRepositoryEventLogBridge::new(Arc::clone(repo));
                Box::new(MerkleEventLogProvider::with_persistence(Arc::new(bridge)))
            }
            Self::Sqlite(repo) => {
                let bridge = ProtocolRepositoryEventLogBridge::new(Arc::clone(repo));
                Box::new(MerkleEventLogProvider::with_persistence(Arc::new(bridge)))
            }
        }
    }
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
            protocol_repository: ProtocolRepoVariant::InMemory(protocol_repository),
            identity_link_attestation_registry: Arc::new(DashMap::new()),
            context_handle_registry: Arc::new(DashMap::new()),
            mcp_server_registry: Arc::new(DashMap::new()),
            mcp_client_registry: Arc::new(DashMap::new()),
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
            protocol_repository: ProtocolRepoVariant::InMemory(protocol_repository),
            identity_link_attestation_registry: Arc::new(DashMap::new()),
            context_handle_registry: Arc::new(DashMap::new()),
            mcp_server_registry: Arc::new(DashMap::new()),
            mcp_client_registry: Arc::new(DashMap::new()),
        }
    }

    /// Constructs a new `UniffiBridgeInstance` honoring a [`StorageConfig`].
    ///
    /// - [`StorageConfig::InMemory`] — equivalent to
    ///   [`UniffiBridgeInstance::new_uniffi`]; no persistence provider is
    ///   attached to the embedded `CoreFields`.
    /// - [`StorageConfig::Sqlite`] — opens a `SQLCipher`-encrypted
    ///   database at `{path}/scp.db` and attaches a
    ///   `ProtocolRepositoryContextBridge<Arc<SqliteStorage>>` to
    ///   `CoreFields::persistence`. The subsequent
    ///   `init_context_manager*` call picks the shared `Arc` up via
    ///   [`scp_ffi_common::bridge_instance::CoreFields::persistence_arc_clone`]
    ///   so the `ContextManager` and the `CoreFields` mirror share a
    ///   single `SqliteStorage` instance. If opening fails, the error is
    ///   logged via `tracing::error!` and the instance is returned
    ///   without persistence (matching the `PyO3` / NAPI bridges).
    #[must_use]
    pub fn with_storage_uniffi(config: StorageConfig) -> Self {
        match config {
            StorageConfig::InMemory => Self::new_uniffi(),
            StorageConfig::Sqlite { path, key } => {
                let path_buf = std::path::PathBuf::from(&path);
                match scp_platform::sqlite::SqliteStorage::new(&path_buf, &key) {
                    Ok(storage) => {
                        let arc_storage = Arc::new(storage);
                        // The same `Arc<SqliteStorage>` backs BOTH the
                        // context-snapshot persistence bridge AND the
                        // Merkle event log + trust aggregation repository.
                        // This is the fix for the split-brain where
                        // `with_storage(Sqlite)` used to persist snapshots
                        // but silently fall back to in-memory storage for
                        // event log entries.
                        let persistence_repo =
                            Arc::new(ProtocolRepository::new(Arc::clone(&arc_storage)));
                        let persistence: Arc<
                            dyn scp_core::context::manager::ContextPersistence + Send + Sync,
                        > = Arc::new(
                            scp_core::store::context::ProtocolRepositoryContextBridge::new(
                                persistence_repo,
                            ),
                        );
                        let event_log_repo =
                            Arc::new(ProtocolRepository::new(Arc::clone(&arc_storage)));
                        drop(arc_storage);
                        // `key` is a `Vec<u8>` crossing the UniFFI
                        // boundary — we cannot zero the caller's copy,
                        // but we zero ours after SQLCipher has consumed
                        // it internally.
                        let mut key_owned = key;
                        zeroize::Zeroize::zeroize(&mut key_owned);
                        drop(key_owned);
                        Self::with_persistence_uniffi_arc_and_repo(
                            persistence,
                            ProtocolRepoVariant::Sqlite(event_log_repo),
                        )
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            path = %path,
                            "with_storage_uniffi: SqliteStorage::new failed — instance created without persistence"
                        );
                        let mut key_owned = key;
                        zeroize::Zeroize::zeroize(&mut key_owned);
                        drop(key_owned);
                        Self::new_uniffi()
                    }
                }
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
        persistence: Arc<dyn scp_core::context::manager::ContextPersistence + Send + Sync>,
        protocol_repository: ProtocolRepoVariant,
    ) -> Self {
        Self {
            core: CoreFields::with_persistence_arc(persistence),
            ucan_registry: Arc::new(DashMap::new()),
            #[cfg(feature = "allow_in_memory_custody")]
            identity_custody_registry: Arc::new(DashMap::new()),
            protocol_repository,
            identity_link_attestation_registry: Arc::new(DashMap::new()),
            context_handle_registry: Arc::new(DashMap::new()),
            mcp_server_registry: Arc::new(DashMap::new()),
            mcp_client_registry: Arc::new(DashMap::new()),
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
    /// [`context_manager_expect`] free function.
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
    pub fn context_manager_expect(&self) -> Result<&Arc<ContextManager>, crate::ScpError> {
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
            .try_context_manager()
            .ok_or_else(|| crate::ScpError::Context {
                msg: "bridge not ready: no local DID registered".to_owned(),
                code: codes::CTX_2000.to_owned(),
            })
    }

    /// Per-instance equivalent of the module-level [`context_manager`] free
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
    pub fn context_manager_or_error(&self) -> Result<&Arc<ContextManager>, crate::ScpError> {
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
            .try_context_manager()
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
    pub fn try_context_manager_ready(&self) -> Option<&Arc<ContextManager>> {
        if self.core.is_suspended() || self.core.is_shutdown() {
            return None;
        }
        self.core.try_context_manager()
    }

    /// Per-instance equivalent of the module-level
    /// [`init_context_manager_with_did`] free function.
    ///
    /// Installs an `MlsCryptoProvider(local_did)` and
    /// `NotConfiguredTransportProvider` on this instance. No-op if a
    /// `ContextManager` is already attached.
    #[allow(dead_code)]
    pub fn init_context_manager_with_did(&self, local_did: &str) {
        if self.core.has_context_manager() {
            tracing::debug!(
                requested_did = %local_did,
                "init_context_manager_with_did: ContextManager already attached — using existing instance"
            );
            return;
        }
        let did = local_did.to_owned();
        let crypto = Box::new(scp_core::crypto::mls::provider::MlsCryptoProvider::new(did));
        let event_log = self.protocol_repository.event_log_provider();
        let persistence = self.core.persistence_arc_clone();
        let cm_arc = build_context_manager(
            crypto,
            Box::new(scp_core::context::NotConfiguredTransportProvider),
            event_log,
            persistence,
        );

        self.core.set_context_manager(cm_arc);
    }

    /// Per-instance equivalent of the module-level
    /// [`init_context_manager_with_relay_transport`] free function.
    ///
    /// Installs an `MlsCryptoProvider(local_did)` and a
    /// `RelayTransportProvider` wrapping the supplied `NativeRelayAdapter` on
    /// this instance. No-op if a `ContextManager` is already attached.
    #[allow(dead_code)]
    pub fn init_context_manager_with_relay_transport(
        &self,
        local_did: &str,
        adapter: scp_transport::native::adapter::NativeRelayAdapter,
    ) {
        if self.core.has_context_manager() {
            tracing::warn!(
                requested_did = %local_did,
                "init_context_manager_with_relay_transport: ContextManager already attached — ignoring"
            );
            return;
        }
        let did = local_did.to_owned();
        let crypto = Box::new(scp_core::crypto::mls::provider::MlsCryptoProvider::new(did));
        let transport = Box::new(scp_transport::RelayTransportProvider::new(adapter));
        let event_log = self.protocol_repository.event_log_provider();
        let persistence = self.core.persistence_arc_clone();
        let cm_arc = build_context_manager(crypto, transport, event_log, persistence);

        self.core.set_context_manager(cm_arc);
    }

    /// Per-instance equivalent of the module-level
    /// [`sync_role_state_from_manager`] free function.
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
        let manager = self.context_manager_or_error()?;
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

    /// Per-instance equivalent of the module-level
    /// [`with_rate_limit_tracker`] free function.
    ///
    /// Delegates to [`CoreFields::with_rate_limit_tracker`].
    #[allow(dead_code)]
    pub fn with_rate_limit_tracker<F, T>(&self, identity_did: &str, f: F) -> T
    where
        F: FnOnce(&mut scp_core::context::invitation::RateLimitTracker) -> T,
    {
        self.core.with_rate_limit_tracker(identity_did, f)
    }

    /// Per-instance equivalent of the module-level [`did_resolver`] free
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

    /// Per-instance equivalent of the module-level [`init_did_resolver`] free
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

    /// Per-instance equivalent of the module-level [`ensure_ucan_registered`]
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

    /// Per-instance equivalent of the module-level [`with_ucan_state`] free
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

    /// Per-instance equivalent of the module-level [`remove_ucan_state`] free
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

    /// `UniFFI`-specific resume: flag flip, then transport reconnect, then
    /// persisted-context restore.
    ///
    /// Mirrors the `PyO3` / NAPI overrides so Swift and Kotlin callers get
    /// the same resume semantics as Python and TypeScript.
    async fn resume(&self) -> Result<(), scp_ffi_common::bridge_instance::LifecycleError> {
        self.core.resume().await?;
        // Reconnect transport BEFORE rehydrating persisted contexts so
        // restored subscriptions can attach to a live relay connection.
        self.core.reconnect_transport_if_pending().await?;
        self.core.restore_all_persisted_contexts().await;
        Ok(())
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
fn not_configured_key_resolver() -> scp_core::context::governance::KeyResolver {
    scp_ffi_common::bridge_runtime::not_configured_key_resolver()
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
    Arc<ProtocolRepository<EncryptingAdapter<BridgeInMemoryStorage>>>,
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
    // each `Scp::new()` returns a distinct `Arc<UniffiBridgeInstance>`
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
    fn test_with_storage_sqlite_uses_sqlite_variant() {
        // Regression test for the event log split-brain bug: before this
        // variant existed, `with_storage(Sqlite)` persisted context
        // snapshots to SQLCipher but Merkle event log entries only to the
        // ephemeral in-memory repo. This asserts that the variant now
        // routes to SQLite so both paths share one database.
        let tmp = tempfile::tempdir().expect("tempdir");
        let bi = UniffiBridgeInstance::with_storage_uniffi(StorageConfig::Sqlite {
            path: tmp.path().to_string_lossy().into_owned(),
            key: vec![0x11u8; 32],
        });
        assert!(
            matches!(bi.protocol_repository(), ProtocolRepoVariant::Sqlite(_)),
            "with_storage(Sqlite) must produce ProtocolRepoVariant::Sqlite so event log \
             entries persist to the same `SQLCipher` database as context snapshots"
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
            Arc::ptr_eq(cm, bi.core.try_context_manager().unwrap()),
            "instance.context_manager_expect() must be the same Arc as core.try_context_manager()"
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
