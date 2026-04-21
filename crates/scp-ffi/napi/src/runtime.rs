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
use scp_platform::sqlite::SqliteStorage;

use crate::context::NapiContextHandle;
use crate::error::ScpNapiError;
#[cfg(feature = "allow_in_memory_custody")]
use crate::identity::OpaqueInMemoryKeyCustody;

// ---------------------------------------------------------------------------
// NapiBridgeInstance — per-bridge concrete bridge instance (#1549 Phase 4 PR 1)
// ---------------------------------------------------------------------------

/// Storage configuration for [`NapiBridgeInstance`].
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
    /// SQLCipher-encrypted on-disk storage.
    ///
    /// Persists context snapshots, identity state, and the event log
    /// across process restarts. The `key` is raw encryption key material
    /// wrapped in `Zeroizing` so the caller's copy is zeroed after the
    /// variant is consumed.
    Sqlite {
        /// Directory the database file is created in.
        path: std::path::PathBuf,
        /// Raw encryption key material (32 bytes recommended).
        key: zeroize::Zeroizing<Vec<u8>>,
    },
}

/// Protocol repository variant: an `Arc<ProtocolRepository<_>>` whose inner
/// `Storage` matches the bridge's configured persistence backend.
///
/// Before this variant existed, `NapiBridgeInstance::protocol_repository` was
/// always `Arc<ProtocolRepository<EncryptingAdapter<BridgeInMemoryStorage>>>`,
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
/// default bridge (the legacy the legacy default bridge was deleted in
/// Phase D, #1695).
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
            protocol_repository: ProtocolRepoVariant::InMemory(protocol_repository),
            mcp_server_registry: Arc::new(DashMap::new()),
            mcp_client_registry: Arc::new(DashMap::new()),
            #[cfg(feature = "allow_in_memory_custody")]
            network: std::sync::Mutex::new(None),
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
            protocol_repository: ProtocolRepoVariant::InMemory(protocol_repository),
            mcp_server_registry: Arc::new(DashMap::new()),
            mcp_client_registry: Arc::new(DashMap::new()),
            #[cfg(feature = "allow_in_memory_custody")]
            network: std::sync::Mutex::new(None),
        }
    }

    /// Constructs a new `NapiBridgeInstance` honoring a [`StorageConfig`].
    ///
    /// - [`StorageConfig::InMemory`] — equivalent to
    ///   [`NapiBridgeInstance::new_napi`]; no persistence provider is
    ///   attached to the embedded `CoreFields` (the legacy
    ///   `NapiBridgePersistence` `DashMap` is still wired into the
    ///   `ContextManager` by `init_context_manager*`).
    /// - [`StorageConfig::Sqlite`] — opens a `SQLCipher`-encrypted
    ///   database at `{path}/scp.db` and attaches a
    ///   `ProtocolRepositoryContextBridge<Arc<SqliteStorage>>` to
    ///   `CoreFields::persistence`. Downstream
    ///   `init_context_manager*` picks the shared `Arc` up via
    ///   `persistence_arc_clone()` so the `ContextManager` and the
    ///   `CoreFields` mirror share a single `SqliteStorage` instance. If
    ///   opening fails, the error is logged via `tracing::error!` and the
    ///   instance is returned without persistence (matching the `PyO3`
    ///   bridge's behaviour).
    #[must_use]
    pub fn with_storage_napi(config: StorageConfig) -> Self {
        match config {
            StorageConfig::InMemory => Self::new_napi(),
            StorageConfig::Sqlite { path, key } => {
                match scp_platform::sqlite::SqliteStorage::new(&path, &key) {
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
                        let persistence: Arc<dyn ContextPersistence + Send + Sync> = Arc::new(
                            scp_core::store::context::ProtocolRepositoryContextBridge::new(
                                persistence_repo,
                            ),
                        );
                        let event_log_repo =
                            Arc::new(ProtocolRepository::new(Arc::clone(&arc_storage)));
                        drop(arc_storage);
                        drop(key);
                        Self::with_persistence_napi_arc_and_repo(
                            persistence,
                            ProtocolRepoVariant::Sqlite(event_log_repo),
                        )
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            path = %path.display(),
                            "with_storage_napi: SqliteStorage::new failed — instance created without persistence"
                        );
                        drop(key);
                        Self::new_napi()
                    }
                }
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
    ) -> Self {
        Self {
            core: CoreFields::with_persistence_arc(persistence),
            ucan_registry: Arc::new(DashMap::new()),
            #[cfg(feature = "allow_in_memory_custody")]
            identity_registry: Arc::new(DashMap::new()),
            protocol_repository,
            mcp_server_registry: Arc::new(DashMap::new()),
            mcp_client_registry: Arc::new(DashMap::new()),
            #[cfg(feature = "allow_in_memory_custody")]
            network: std::sync::Mutex::new(None),
        }
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

    /// Returns a reference to the shared full-stack test network slot.
    #[cfg(feature = "allow_in_memory_custody")]
    #[must_use]
    pub const fn network(
        &self,
    ) -> &std::sync::Mutex<Option<scp_testing::fullstack::FullStackNetwork>> {
        &self.network
    }

    /// Returns a cloned handle to the attached `ContextManager`, if any.
    ///
    /// Inherent method mirror of the free [`context_manager`] helper. Unlike
    /// the free helper this does NOT check suspension/shutdown state — it
    /// simply reflects whether a `ContextManager` has been attached to the
    /// embedded `CoreFields` via
    /// [`scp_ffi_common::bridge_instance::CoreFields::set_context_manager`].
    ///
    /// Callers that need suspension-aware error reporting should use the
    /// free [`context_manager`] helper instead; callers that want raw access
    /// (e.g. `Scp::method` paths that already guard lifecycle explicitly)
    /// use this method.
    #[must_use]
    pub fn context_manager(&self) -> Option<Arc<ContextManager>> {
        self.core.try_context_manager().cloned()
    }
}

#[async_trait]
impl BridgeInstanceCore for NapiBridgeInstance {
    fn core(&self) -> &CoreFields {
        &self.core
    }

    /// NAPI-specific resume: flag flip, then transport reconnect, then
    /// persisted-context restore.
    ///
    /// Mirrors the `PyO3` / `UniFFI` overrides so TypeScript callers see
    /// the same semantics as Python, Swift, and Kotlin.
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
/// [`NapiBridgeInstance`] so that an `SCP` instance can be constructed, used,
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

/// Returns a reference to the shared `ContextManager` on the given
/// bridge instance.
///
/// # Errors
///
/// Returns `napi::Error` if the `ContextManager` has not been attached
/// via [`init_context_manager`], or if the instance is currently suspended.
pub fn context_manager(bi: &NapiBridgeInstance) -> napi::Result<&Arc<ContextManager>> {
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

/// Initializes the given bridge instance's [`ContextManager`] with production
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
/// No-op if the bridge already has a `ContextManager` attached (first
/// attach wins — `CoreFields::set_context_manager` is `OnceLock`-backed).
pub fn init_context_manager(bi: &NapiBridgeInstance, local_did: &str) {
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
    let event_log = event_log_provider_from_existing_repo(bi);
    let persistence = persistence_box_for_init(bi);
    let cm_arc = Arc::new(ContextManager::with_persistence(
        crypto,
        transport,
        event_log,
        persistence,
        not_configured_key_resolver(),
    ));

    bi.core.set_context_manager(cm_arc);
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

/// Initializes the given bridge instance's [`ContextManager`] with
/// `LocalTransportProvider`.
///
/// Identical to [`init_context_manager`] except the transport provider is
/// `LocalTransportProvider` (silently succeeds on all send/publish calls)
/// instead of `NotConfiguredTransportProvider` (rejects everything).
///
/// **Must be called before any `context_create` / `context_join` /
/// `context_import`** — those functions call `init_context_manager` which
/// wins the `OnceLock` race if called first.
///
/// Exposed to JS/TS via `crate::transport::configure_local_transport` so
/// that E2E tests can exercise `contextSend` and `broadcastPublish` without
/// a real relay server.
///
/// No-op if the bridge already has a `ContextManager` attached.
pub fn init_context_manager_with_local_transport(bi: &NapiBridgeInstance, local_did: &str) {
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
    let event_log = event_log_provider_from_existing_repo(bi);
    let persistence = persistence_box_for_init(bi);
    let cm_arc = Arc::new(ContextManager::with_persistence(
        crypto,
        transport,
        event_log,
        persistence,
        not_configured_key_resolver(),
    ));

    bi.core.set_context_manager(cm_arc);
}

/// Initializes the given bridge instance's [`ContextManager`] with a
/// `RelayTransportProvider`.
///
/// Identical to [`init_context_manager`] except the transport provider is a
/// `RelayTransportProvider` wrapping a real `NativeRelayAdapter` connected to
/// the given relay URL. This allows `ContextManager::send_message` (and thus
/// `contextSend`) to publish encrypted payloads through the relay.
///
/// **Must be called before any `context_create` / `context_join` /
/// `context_import`** — those functions call `init_context_manager` which
/// wins the `OnceLock` race if called first.
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
/// No-op if the bridge already has a `ContextManager` attached.
pub fn init_context_manager_with_relay_transport(
    bi: &NapiBridgeInstance,
    local_did: &str,
    adapter: scp_transport::native::adapter::NativeRelayAdapter,
) {
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
    let event_log = event_log_provider_from_existing_repo(bi);
    let persistence = persistence_box_for_init(bi);
    let cm_arc = Arc::new(ContextManager::with_persistence(
        crypto,
        transport,
        event_log,
        persistence,
        not_configured_key_resolver(),
    ));

    bi.core.set_context_manager(cm_arc);
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
/// Returns both the event log provider and the underlying `ProtocolRepository`
/// (for registration in `NapiBridgeInstance`).
//
// Retained alongside the `_on` variants used by per-bridge initialization
// paths. Deleted in the Phase 4 demolition slice.
#[allow(dead_code)]
pub(crate) fn build_event_log_provider() -> (
    Box<dyn ContextEventLogProvider>,
    Arc<ProtocolRepository<EncryptingAdapter<BridgeInMemoryStorage>>>,
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

/// Test variant of [`context_manager`] initialization that uses
/// [`LocalTransportProvider`](scp_core::context::LocalTransportProvider)
/// instead of
/// [`NotConfiguredTransportProvider`](scp_core::context::NotConfiguredTransportProvider)
/// and a no-op crypto provider for Rust unit tests that pass `None` key
/// package bytes with `did:key:` test DIDs.
///
/// Must be called before the first `context_manager()` call in tests.
/// Initializes the given bridge instance's `ContextManager` with
/// test-only providers (no-op crypto + local transport).
///
/// Must be called before the first `context_manager(bi)` call in tests.
/// First-call-wins semantics via `CoreFields::set_context_manager`.
#[cfg(test)]
pub(crate) fn init_context_manager_for_test_on(bi: &NapiBridgeInstance) {
    if bi.core.has_context_manager() {
        return;
    }
    let event_log = event_log_provider_from_existing_repo(bi);
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
/// Returns `ScpNapiError::Permission` if the DID is not found (the identity
/// was not created via `identity_create` on this bridge).
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
        .ok_or_else(|| ScpNapiError::Permission {
            message: format!(
                "identity '{did}' not found in registry — was it created with \
                 identityCreate(\"in_memory\") in this process?"
            ),
            code: codes::PERM_3023.to_owned(),
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
/// Returns `ScpNapiError::Permission` if the DID is not found.
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
    let mgr = context_manager(bi).map_err(|e| ScpNapiError::Context {
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
/// consumed by [`ContextManager::with_persistence`] which requires a `Box`.
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
    fn bridge_instance_populated_by_init_context_manager() {
        // A fresh NapiBridgeInstance must accept a ContextManager via
        // init_context_manager_for_test_on and make it visible through
        // context_manager(&bi).
        let bi = NapiBridgeInstance::new_napi();
        init_context_manager_for_test_on(&bi);

        let cm = context_manager(&bi).expect("context_manager should be initialized");

        // Both should point to the same ContextManager allocation.
        assert!(
            Arc::ptr_eq(cm, bi.core.try_context_manager().unwrap()),
            "context_manager(&bi) must match bi.core.try_context_manager()"
        );
    }

    #[test]
    fn bridge_instance_not_shutdown_initially() {
        let bi = NapiBridgeInstance::new_napi();
        init_context_manager_for_test_on(&bi);

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
            key: zeroize::Zeroizing::new(vec![0x11u8; 32]),
        });
        assert!(
            matches!(&bi.protocol_repository, ProtocolRepoVariant::Sqlite(_)),
            "with_storage(Sqlite) must produce ProtocolRepoVariant::Sqlite so event log \
             entries persist to the same `SQLCipher` database as context snapshots"
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
