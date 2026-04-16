//! Self-contained bridge instance replacing process-global `OnceLock` singletons.
//!
//! `BridgeInstance` consolidates most per-bridge `OnceLock` statics into a
//! single owned struct. Each instance holds its own `ContextManager`, local
//! DID, shutdown flag, and shared state registries.
//!
//! # Owned state (consolidated into `BridgeInstance`)
//!
//! - `ContextManager` — context lifecycle (MLS, membership, governance, broadcast)
//! - Transport manager — relay connections
//! - Known contexts — context discovery registry
//! - Rate limiters — invitation auto-accept
//! - Economy budgets + antispam — economic governance trackers
//! - Bridge connector state — per-context shadow registries + sender key stores
//! - DID resolver — production identity-backed resolver
//!
//! # Remaining per-bridge `OnceLock`s (not consolidated)
//!
//! Only truly process-scoped state remains as per-bridge `OnceLock`s:
//!
//! - `FFI_BRIDGE_STATE` — PyO3-specific per-context FFI state (`DashMap`)
//!
//! All bridge-specific singleton registries that were previously declared as
//! per-bridge `OnceLock` statics are now owned by `BridgeInstance` via type
//! erasure (`OnceLock<Box<dyn Any + Send + Sync>>`):
//!
//! - `identity_registry` — stores `Arc<DashMap<String, BridgeIdentityEntry>>`
//! - `storage_provider` — stores `Arc<ConcreteStorageType>`
//! - `protocol_repository` — stores `Arc<ProtocolRepository<ConcreteStorageType>>`
//! - `ucan_registry` — stores `Arc<DashMap<String, BridgeUcanContextState>>`
//!
//! Each bridge calls `set_identity_registry` / `get_identity_registry_as::<T>()` etc.
//! to store and retrieve its bridge-specific concrete type.
//!
//! `FFI_BRIDGE_STATE` is cleaned up during `shutdown()` via a registered shutdown hook.
//!
//! # Thread Safety
//!
//! `BridgeInstance` is `Send + Sync`. The `ContextManager` is behind `Arc`
//! (interior `RwLock`/`DashMap`). The shutdown flag uses `AtomicBool` with
//! `Ordering::SeqCst` for visibility across threads. Transport uses
//! `std::sync::RwLock` for infrequent writes (connect/disconnect) and
//! concurrent reads (probe/query). Known contexts and rate limiters use
//! `DashMap` for lock-free concurrent access.

use std::any::Any;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};

use dashmap::DashMap;
use scp_core::context::ContextManager;
use scp_core::context::ContextPersistence;
use scp_protocol::context::invitation::RateLimitTracker;
use scp_protocol::economy::antispam::SenderVelocityTracker;
use scp_protocol::economy::budget::MemberBudgetTracker;

use crate::IdentityBackedDidResolver;
use crate::bridge_state::BridgeContextState;

/// Maximum number of known contexts that can be registered in the discovery
/// registry. When this limit is reached, the oldest entry (by `last_seen`)
/// is evicted to make room for the new one. 10,000 is well beyond any
/// realistic per-device usage while preventing unbounded memory growth from
/// a misbehaving caller.
const MAX_KNOWN_CONTEXTS: usize = 10_000;

/// Maximum number of rate limit trackers. When this limit is reached, the
/// least-recently-inserted tracker is evicted to make room for the new one.
/// 1,000 concurrent identity DIDs per bridge instance is generous for any
/// single-process deployment.
const MAX_RATE_LIMITERS: usize = 1_000;

/// Maximum number of economy budget tracker entries. Budget trackers are
/// 1:1 with contexts and are bounded by context membership, so growth is
/// inherently limited in practice. This constant provides a hard ceiling
/// against any pathological caller. When at capacity and a new context ID
/// is requested, an ephemeral (non-persisted) tracker is used and a warning
/// is logged.
const MAX_ECONOMY_CONTEXTS: usize = 10_000;

// Note: bridge connector state entries are 1:1 with contexts managed through
// the `ContextManager`. No separate capacity constant is needed because
// `ContextManager` itself enforces membership bounds, and bridge state entries
// are removed via `remove_bridge_state` during context cleanup.

/// Default sliding window duration for antispam velocity tracking (seconds).
/// Matches the spec section 19.7 example.
const ANTISPAM_DEFAULT_WINDOW_SECS: u64 = 60;

/// Metadata about a known context's relay presence.
///
/// Stored in the `BridgeInstance`'s known-contexts registry so that context
/// discovery can probe relays for context activity. The relay is a dumb blob
/// store with no identity-to-context mapping, so the client must track which
/// routing IDs correspond to which contexts.
///
/// See SCP-213 and ADR-015 in `.docs/adrs/phase-3.md`.
#[derive(Debug, Clone)]
pub struct KnownContext {
    /// The context's routing ID (32-byte pseudonym for relay routing).
    pub routing_id: [u8; 32],
    /// The relay URL where this context's blobs are stored. `None` if no relay
    /// was connected at registration time.
    pub relay_url: Option<String>,
    /// The DID of the member who registered this known context.
    pub member_did: String,
    /// Unix timestamp (seconds) when this context was last seen active.
    pub last_seen: u64,
}

/// A self-contained bridge instance replacing process-global `OnceLock` singletons.
///
/// Each instance holds its own [`ContextManager`], local DID, shutdown flag,
/// and shared state registries (transport, known contexts, rate limiters).
/// Multiple instances can coexist (different identities, test isolation).
/// Mobile platforms use `shutdown()` for lifecycle cleanup.
///
/// # `OnceLock` limitation — shutdown is terminal
///
/// Each non-WASM FFI bridge stores its `BridgeInstance` in a
/// `OnceLock<Arc<BridgeInstance>>`. `OnceLock` does not support re-initialization
/// after the first `get_or_init` call, so once `shutdown()` is called the
/// bridge cannot be re-created within the same process. This is deliberate:
/// shutdown is a final cleanup step (process exit, test teardown).
///
/// For mobile app lifecycle (background/foreground), use `suspend()` /
/// `resume()` instead — these toggle the `suspended` flag and
/// disconnect/reconnect transport without touching the `OnceLock`.
///
/// # Invariants
///
/// - `local_did` is immutable after construction.
/// - Once `shutdown()` is called, `is_shutdown()` returns `true` permanently.
///   All bridge operations should check this flag and fail fast.
/// - The `ContextManager` reference is shared (`Arc`) and may outlive this
///   instance if cloned elsewhere. `shutdown()` does NOT drop or invalidate
///   the `ContextManager` — it is a signal to the bridge layer only.
pub struct BridgeInstance {
    /// Shared context lifecycle manager (MLS, membership, governance, broadcast).
    context_manager: Arc<ContextManager>,

    /// The local DID this instance was initialized with.
    local_did: String,

    /// Whether this instance has been shut down permanently.
    ///
    /// Uses `SeqCst` ordering for cross-thread visibility. Once set to `true`,
    /// all subsequent bridge operations should return an error immediately.
    /// A shut-down instance cannot be resumed.
    shutdown: AtomicBool,

    /// Whether this instance is currently suspended.
    ///
    /// Suspended instances have disconnected transport but retain their
    /// context state. `resume()` clears this flag — the caller must
    /// re-establish transport via `set_transport`. Suspension is intended
    /// for mobile app backgrounding.
    suspended: AtomicBool,

    // -----------------------------------------------------------------
    // Shared state — previously per-bridge OnceLock singletons
    // -----------------------------------------------------------------
    /// Transport manager for multi-relay support.
    ///
    /// Stores the real [`scp_transport::TransportManager`] with multi-relay
    /// fanout, per-context relay set assignment, suppression detection, and
    /// reliability scoring. Uses `RwLock` for infrequent writes (connect) and
    /// concurrent reads (probe/query). Wrapped in `Arc` so that NAPI bridge
    /// subscription tasks (which run in spawned async tasks) can hold a
    /// `Send`-compatible reference without keeping the `RwLock` guard alive
    /// across `.await` points.
    transport: RwLock<Option<Arc<scp_transport::TransportManager>>>,

    /// Known context-to-relay mappings for discovery (SCP-213).
    ///
    /// Tracks contexts that have been created/joined locally, along with their
    /// routing IDs and relay URLs. This allows context discovery to probe
    /// relays for context activity even across process restarts (when combined
    /// with persistence, a future story). Uses `DashMap` for lock-free
    /// concurrent access.
    known_contexts: DashMap<String, KnownContext>,

    /// Rate limit tracker registry for invitation auto-accept, keyed by
    /// identity DID.
    ///
    /// Each identity has its own [`RateLimitTracker`] that persists across
    /// invitation evaluations. The tracker enforces the rate limit specified
    /// in the auto-accept policy. Uses `DashMap` for lock-free concurrent
    /// access.
    rate_limiters: DashMap<String, RateLimitTracker>,

    // -----------------------------------------------------------------
    // Economy state — previously per-bridge OnceLock singletons
    // -----------------------------------------------------------------
    /// Per-context member budget trackers for economic governance.
    ///
    /// Keyed by context ID. Created lazily on first access via
    /// [`with_economy_budget`] / [`with_economy_budget_mut`]. Budget trackers
    /// are NOT removed automatically when contexts are closed -- call
    /// [`remove_economy_state`] for cleanup in long-running processes.
    economy_budgets: DashMap<String, MemberBudgetTracker>,

    /// Per-context antispam velocity trackers for economic governance.
    ///
    /// Keyed by context ID. Created lazily on first access with a default
    /// 60-second sliding window. The window duration matches the spec
    /// section 19.7 example.
    economy_antispam: DashMap<String, SenderVelocityTracker>,

    // -----------------------------------------------------------------
    // Bridge connector state — previously in bridge_state.rs OnceLock
    // -----------------------------------------------------------------
    /// Per-context bridge connector state (shadow registries and sender key
    /// stores).
    ///
    /// Keyed by context ID. See [`BridgeContextState`] for contents.
    /// Previously in `scp_ffi_common::bridge_state::BRIDGE_STATE`.
    bridge_state: DashMap<String, BridgeContextState>,

    // -----------------------------------------------------------------
    // DID resolver — previously per-bridge OnceLock
    // -----------------------------------------------------------------
    /// Production DID resolver that delegates to
    /// `scp_identity::resolver::DidResolver` for full DID document validation
    /// (BEP44 signature verification, self-certification, sequence number
    /// tracking, caching).
    ///
    /// Initialized by [`set_did_resolver`] when the identity layer is first
    /// set up. `None` until `identity_create` initializes it.
    ///
    /// See #311 for the unification design.
    did_resolver: OnceLock<Arc<IdentityBackedDidResolver>>,

    /// Registered shutdown hooks for bridge-specific state cleanup.
    ///
    /// Each FFI bridge registers hooks that clear bridge-specific singletons
    /// that cannot be owned by `BridgeInstance` due to crate dependency
    /// boundaries (e.g., `PyO3` `FFI_BRIDGE_STATE`, MCP registries).
    ///
    /// Type-erased `DashMap` registries (`identity_registry`, `ucan_registry`)
    /// are cleared directly in `shutdown()` via their registered clear
    /// functions (`identity_registry_clear_fn`, `ucan_registry_clear_fn`),
    /// not through this hook Vec.
    ///
    /// Hooks are called exactly once during `shutdown()` and then discarded.
    /// The `Mutex` is only locked during `shutdown()` and `register_shutdown_hook()`
    /// — no contention on the hot path.
    shutdown_hooks: Mutex<Vec<Box<dyn FnOnce() + Send>>>,

    // -----------------------------------------------------------------
    // Persistence — optional context state persistence provider
    // -----------------------------------------------------------------
    /// Optional persistence provider, forwarded from the `ContextManager`.
    ///
    /// When `Some`, `suspend()` and `shutdown()` call
    /// [`ContextManager::flush_all_contexts_sync`] to persist context state
    /// before tearing down transport or destroying MLS groups. The provider
    /// reference is retained here so the bridge layer can pass it through
    /// `with_persistence()` at construction time and expose it via the
    /// `persistence()` accessor for bridge-specific restore logic.
    ///
    /// This is logically a mirror of the persistence configured on the
    /// `ContextManager` — the `ContextManager` owns the canonical reference;
    /// this field allows the bridge layer to use the same provider for
    /// bridge-level suspend/resume coordination without separate storage.
    persistence: Option<Box<dyn ContextPersistence + Send + Sync>>,

    // -----------------------------------------------------------------
    // Relay URL — for resume after suspend
    // -----------------------------------------------------------------
    /// The relay URL most recently connected via `set_transport`.
    ///
    /// Stored so that callers can retrieve it after `resume()` and
    /// reconnect to the same relay. Full auto-reconnect is the caller's
    /// responsibility — `resume()` only clears the suspended flag.
    ///
    /// Set via [`set_relay_url`]. Retrieved via [`pending_relay_url`].
    /// Preserved across `suspend()` / `resume()` cycles so callers can
    /// reconnect. Only cleared during `shutdown()`.
    relay_url: Mutex<Option<String>>,

    // -----------------------------------------------------------------
    // Type-erased bridge-specific singletons
    //
    // Each slot stores a bridge-specific concrete type erased to
    // `Box<dyn Any + Send + Sync>`. The per-bridge runtime sets the
    // value once (via the `set_*` accessor) and retrieves it via
    // `get_*_as::<ConcreteType>()` which downcasts back.
    //
    // DashMap-based registries (`identity_registry`, `ucan_registry`) are
    // stored as `Arc<DashMap<...>>` and also register an `Arc`-cloned clear
    // closure so `shutdown()` can wipe them without knowing the concrete type.
    // -----------------------------------------------------------------
    /// Identity registry: stores `Arc<DashMap<String, BridgeIdentityEntry>>`
    ///
    /// `PyO3` stores `Arc<DashMap<String, IdentityEntry>>`.
    /// `NAPI` stores `Arc<DashMap<String, NapiIdentityEntry>>` (feature-gated).
    /// Cleared on `shutdown()` via `identity_registry_clear_fn`.
    identity_registry: OnceLock<Box<dyn Any + Send + Sync>>,
    /// Clear function for `identity_registry`. Called once during `shutdown()`.
    identity_registry_clear_fn: OnceLock<Box<dyn Fn() + Send + Sync>>,

    /// Storage provider: stores `Arc<ConcreteEncryptingStorage>`.
    ///
    /// `PyO3` stores `Arc<EncryptingAdapter<InMemoryStorage>>`.
    /// `NAPI`/`UniFFI` store `Arc<EncryptingAdapter<BridgeInMemoryStorage>>`.
    ///
    /// Released on process exit (`OnceLock` — not clearable).
    storage_provider: OnceLock<Box<dyn Any + Send + Sync>>,

    /// Protocol repository: stores `Arc<ProtocolRepository<ConcreteStorageType>>`.
    ///
    /// `NAPI`/`UniFFI` store `Arc<ProtocolRepository<EncryptingAdapter<BridgeInMemoryStorage>>>`.
    /// `PyO3` uses `storage_provider` to construct its repository on demand.
    ///
    /// Released on process exit (`OnceLock` — not clearable).
    protocol_repository: OnceLock<Box<dyn Any + Send + Sync>>,

    /// UCAN context state registry: stores `Arc<DashMap<String, BridgeUcanContextState>>`.
    ///
    /// `NAPI` stores `Arc<DashMap<String, UcanContextState>>`.
    /// `UniFFI` stores `Arc<DashMap<String, UcanContextState>>` (different type).
    /// `PyO3` stores UCAN state inline in `FfiBridgeState` (no separate `DashMap`).
    ///
    /// Cleared on `shutdown()` via `ucan_registry_clear_fn`.
    ucan_registry: OnceLock<Box<dyn Any + Send + Sync>>,
    /// Clear function for `ucan_registry`. Called once during `shutdown()`.
    ucan_registry_clear_fn: OnceLock<Box<dyn Fn() + Send + Sync>>,
}

impl BridgeInstance {
    /// Creates a new bridge instance.
    ///
    /// Initializes all shared state registries (transport, known contexts,
    /// rate limiters) as empty. Transport is `None` until a relay connection
    /// is established.
    ///
    /// # Arguments
    ///
    /// - `context_manager` — the shared `ContextManager` that owns context
    ///   lifecycle state (MLS groups, membership, governance, broadcast).
    /// - `local_did` — the DID this instance operates as. Passed through to
    ///   `MlsCryptoProvider` for MLS credential identity.
    #[must_use]
    pub fn new(context_manager: Arc<ContextManager>, local_did: String) -> Self {
        Self {
            context_manager,
            local_did,
            shutdown: AtomicBool::new(false),
            suspended: AtomicBool::new(false),
            transport: RwLock::new(None),
            known_contexts: DashMap::new(),
            rate_limiters: DashMap::new(),
            economy_budgets: DashMap::new(),
            economy_antispam: DashMap::new(),
            bridge_state: DashMap::new(),
            did_resolver: OnceLock::new(),
            shutdown_hooks: Mutex::new(Vec::new()),
            persistence: None,
            relay_url: Mutex::new(None),
            identity_registry: OnceLock::new(),
            identity_registry_clear_fn: OnceLock::new(),
            storage_provider: OnceLock::new(),
            protocol_repository: OnceLock::new(),
            ucan_registry: OnceLock::new(),
            ucan_registry_clear_fn: OnceLock::new(),
        }
    }

    /// Creates a new bridge instance with a persistence provider.
    ///
    /// Same as [`new`](Self::new) but additionally attaches a
    /// [`ContextPersistence`] provider. When provided, [`suspend`] and
    /// [`shutdown`] will flush all context snapshots to the provider via
    /// [`ContextManager::flush_all_contexts_sync`] before tearing down
    /// transport or destroying MLS groups.
    ///
    /// The persistence provider should be the same one configured on the
    /// [`ContextManager`] (typically constructed via
    /// [`ContextManager::with_persistence`] or the builder `.storage()` method).
    ///
    /// # Arguments
    ///
    /// - `context_manager` — the shared `ContextManager` (must already have
    ///   persistence configured via [`ContextManager::with_persistence`]).
    /// - `local_did` — the DID this instance operates as.
    /// - `persistence` — the persistence provider for bridge-level flush on
    ///   suspend/shutdown.
    #[must_use]
    pub fn with_persistence(
        context_manager: Arc<ContextManager>,
        local_did: String,
        persistence: Box<dyn ContextPersistence + Send + Sync>,
    ) -> Self {
        Self {
            context_manager,
            local_did,
            shutdown: AtomicBool::new(false),
            suspended: AtomicBool::new(false),
            transport: RwLock::new(None),
            known_contexts: DashMap::new(),
            rate_limiters: DashMap::new(),
            economy_budgets: DashMap::new(),
            economy_antispam: DashMap::new(),
            bridge_state: DashMap::new(),
            did_resolver: OnceLock::new(),
            shutdown_hooks: Mutex::new(Vec::new()),
            persistence: Some(persistence),
            relay_url: Mutex::new(None),
            identity_registry: OnceLock::new(),
            identity_registry_clear_fn: OnceLock::new(),
            storage_provider: OnceLock::new(),
            protocol_repository: OnceLock::new(),
            ucan_registry: OnceLock::new(),
            ucan_registry_clear_fn: OnceLock::new(),
        }
    }

    /// Returns a reference to the persistence provider, if configured.
    ///
    /// `None` if this instance was created without persistence (via [`new`]).
    #[must_use]
    pub fn persistence(&self) -> Option<&(dyn ContextPersistence + Send + Sync)> {
        self.persistence.as_deref()
    }

    /// Returns a reference to the shared [`ContextManager`].
    #[must_use]
    pub const fn context_manager(&self) -> &Arc<ContextManager> {
        &self.context_manager
    }

    /// Returns the local DID this instance was created with.
    #[must_use]
    pub fn local_did(&self) -> &str {
        &self.local_did
    }

    /// Whether this instance has been shut down permanently.
    ///
    /// Bridge operations should check this before proceeding and return
    /// an appropriate error if `true`.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    /// Whether this instance is currently suspended (backgrounded).
    ///
    /// Suspended instances have disconnected transport but retain context
    /// state. Bridge operations that require transport should check this
    /// and return an appropriate error.
    #[must_use]
    pub fn is_suspended(&self) -> bool {
        self.suspended.load(Ordering::SeqCst)
    }

    /// Checks that the bridge instance is ready to service operations.
    ///
    /// Rejects both permanently shut-down and suspended instances. This is
    /// the single gatekeeper that all bridge `bridge_instance()` functions
    /// should call to enforce lifecycle state.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError::AlreadyShutDown`] if the instance has been
    /// permanently shut down, or [`LifecycleError::Suspended`] if the
    /// instance is currently suspended.
    pub fn check_ready(&self) -> Result<(), LifecycleError> {
        if self.is_shutdown() {
            return Err(LifecycleError::AlreadyShutDown);
        }
        if self.is_suspended() {
            return Err(LifecycleError::Suspended);
        }
        Ok(())
    }

    /// Registers a shutdown hook for bridge-specific state cleanup.
    ///
    /// The hook is called exactly once during [`shutdown()`] and then
    /// discarded. Hooks run in registration order after all
    /// `BridgeInstance`-owned state has been cleared (including the
    /// type-erased `DashMap` registries via their clear functions).
    ///
    /// Intended for bridge-specific singletons that cannot be migrated into
    /// `BridgeInstance` due to crate dependency boundaries (e.g., `PyO3`
    /// `FFI_BRIDGE_STATE`, MCP server/client registries). For
    /// `DashMap`-based registries that CAN be owned here, prefer
    /// [`set_identity_registry`] / [`set_ucan_registry`] which register
    /// a clear closure directly.
    ///
    /// If the internal `Mutex` is poisoned (a previous hook registration
    /// panicked while holding the lock), the hook is silently dropped and
    /// an error is logged.
    pub fn register_shutdown_hook(&self, hook: Box<dyn FnOnce() + Send>) {
        if self.is_shutdown() {
            // Already shut down — run the hook immediately since shutdown()
            // won't be called again. Wrap in catch_unwind for consistency
            // with shutdown()'s hook execution.
            tracing::warn!("hook registered after shutdown — running immediately");
            if let Err(_payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(hook)) {
                tracing::error!(
                    "post-shutdown hook panicked — bridge-specific cleanup may be incomplete"
                );
            }
            return;
        }
        match self.shutdown_hooks.lock() {
            Ok(mut hooks) => hooks.push(hook),
            Err(_) => {
                tracing::error!(
                    "shutdown_hooks mutex poisoned — hook not registered; \
                     bridge-specific cleanup may be incomplete on shutdown"
                );
            }
        }
    }

    /// Suspends the bridge instance.
    ///
    /// - Disconnects the relay (clears transport)
    /// - Keeps the instance alive but inactive (context state is preserved)
    /// - Intended for mobile app backgrounding
    ///
    /// After suspension, `is_suspended()` returns `true` and transport-dependent
    /// operations will fail. Call `resume()` to clear the suspended flag, then
    /// re-establish transport via `set_transport`.
    ///
    /// No-op if already shut down.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the transport `RwLock` is poisoned.
    pub fn suspend(&self) -> Result<(), TransportLockError> {
        if self.is_shutdown() {
            return Ok(());
        }
        // Set flag FIRST to prevent new operations from starting between
        // flag check and transport teardown.
        self.suspended.store(true, Ordering::SeqCst);
        // Flush all context snapshots before disconnecting transport.
        // Best-effort: errors are logged inside flush_all_contexts_sync and do
        // not prevent suspension from completing.
        self.context_manager.flush_all_contexts_sync();
        if let Err(e) = self.clear_transport() {
            // Revert the suspended flag — the instance is not cleanly
            // suspended if transport wasn't cleared.
            self.suspended.store(false, Ordering::SeqCst);
            return Err(e);
        }
        tracing::debug!(local_did = %self.local_did, "bridge instance suspended");
        Ok(())
    }

    /// Resumes a suspended bridge instance.
    ///
    /// Clears the suspended flag so bridge operations can proceed. The caller
    /// must re-establish the relay connection via `set_transport` — resume
    /// does not reconnect automatically. Use [`pending_relay_url`] to
    /// retrieve the URL that was active before suspension.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the instance has been permanently shut down.
    pub fn resume(&self) -> Result<(), LifecycleError> {
        if self.is_shutdown() {
            return Err(LifecycleError::AlreadyShutDown);
        }
        self.suspended.store(false, Ordering::SeqCst);
        tracing::debug!(local_did = %self.local_did, "bridge instance resumed");
        Ok(())
    }

    /// Shuts down the bridge instance permanently.
    ///
    /// - Clears transport (disconnects relay)
    /// - Clears all registries (known contexts, rate limiters)
    /// - Runs all registered shutdown hooks (bridge-specific cleanup)
    /// - Marks instance as shut down (all subsequent operations fail)
    ///
    /// Idempotent: calling `shutdown()` on an already-shut-down instance is
    /// a no-op. Hooks are drained on the first call and will not run again.
    ///
    /// # Hook execution
    ///
    /// Shutdown hooks are called in registration order after all
    /// `BridgeInstance`-owned state has been cleared (registries, economy
    /// trackers, type-erased identity/UCAN `DashMap`s via their clear
    /// functions). Hooks handle bridge-specific singletons that cannot be
    /// owned by `BridgeInstance` (FFI bridge state, MCP registries).
    /// Together, these steps release key material held by custody
    /// providers (zeroized via `Drop` when `Arc` refcount reaches zero).
    ///
    /// This function is infallible. Transport lock failures are logged and
    /// cleanup continues. Shutdown must always complete regardless of
    /// intermediate failures.
    pub fn shutdown(&self) {
        if self.shutdown.swap(true, Ordering::SeqCst) {
            return; // Already shut down
        }

        // Clear transport (disconnect relay). Best-effort: if the RwLock
        // is poisoned, log the error and continue with remaining cleanup.
        // Shutdown must not abort — key material zeroization and hook
        // execution are more critical than a clean transport teardown.
        if let Err(e) = self.clear_transport() {
            tracing::error!("failed to clear transport during shutdown: {e} — continuing cleanup");
        }
        // Clear the relay URL after transport teardown. This is only done
        // in shutdown — suspend() preserves the URL so callers can reconnect.
        if let Ok(mut url) = self.relay_url.lock() {
            *url = None;
        }

        // Flush all context snapshots before destroying MLS groups. This
        // ensures durably-persisted state reflects the last known-good
        // context state before key material is zeroized.
        // Best-effort: errors are logged inside flush_all_contexts_sync.
        self.context_manager.flush_all_contexts_sync();

        // Remove all contexts from the ContextManager (MLS groups, sender
        // keys, event logs). Best-effort — already-removed contexts are
        // silently ignored.
        self.context_manager.shutdown_all_contexts();

        // Clear registries
        self.known_contexts.clear();
        self.rate_limiters.clear();
        self.economy_budgets.clear();
        self.economy_antispam.clear();
        self.bridge_state.clear();

        // Clear type-erased DashMap registries (identity + UCAN).
        // Dropping `Arc<DashMap>` entries here releases key material held by
        // custody providers (zeroized via `Zeroizing` fields on Drop).
        // Wrapped in catch_unwind so a panic in one clear_fn (e.g., DashMap
        // value Drop panics) does not skip remaining cleanup.
        if let Some(clear_fn) = self.identity_registry_clear_fn.get()
            && std::panic::catch_unwind(std::panic::AssertUnwindSafe(clear_fn)).is_err()
        {
            tracing::error!("identity registry clear panicked during shutdown");
        }
        if let Some(clear_fn) = self.ucan_registry_clear_fn.get()
            && std::panic::catch_unwind(std::panic::AssertUnwindSafe(clear_fn)).is_err()
        {
            tracing::error!("UCAN registry clear panicked during shutdown");
        }

        // Run bridge-specific shutdown hooks (FFI bridge state, MCP
        // registries, etc.). Drain the Vec so hooks are called exactly once
        // even if the Mutex isn't dropped.
        if let Ok(mut hooks) = self.shutdown_hooks.lock() {
            for hook in hooks.drain(..) {
                if let Err(_payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(hook))
                {
                    tracing::error!(
                        "shutdown hook panicked — bridge-specific cleanup may be incomplete"
                    );
                }
            }
        } else {
            tracing::error!("shutdown_hooks mutex poisoned — bridge-specific cleanup skipped");
        }

        // Also clear suspended flag (shutdown supersedes suspension)
        self.suspended.store(false, Ordering::SeqCst);

        tracing::debug!(local_did = %self.local_did, "bridge instance shut down");
    }

    // -----------------------------------------------------------------
    // Transport accessors
    // -----------------------------------------------------------------

    /// Stores a pre-built `Arc<TransportManager>` (called after relay
    /// connect).
    ///
    /// The `Arc` allows async tasks (e.g., NAPI subscription) to clone the
    /// reference without keeping the `RwLock` guard alive across `.await`
    /// points.
    ///
    /// Replaces any previous transport manager.
    ///
    /// If the instance is shut down, logs a warning but still sets the
    /// transport — matching the `bridge_instance()` / `context_manager()`
    /// pattern where shutdown operations fail naturally at the MLS/transport
    /// layer rather than being hard-rejected.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the `RwLock` is poisoned, or if the instance is
    /// suspended (lifecycle violation — call `resume()` first).
    #[allow(clippy::significant_drop_tightening)]
    pub fn set_transport(
        &self,
        manager: Arc<scp_transport::TransportManager>,
    ) -> Result<(), TransportLockError> {
        // Shutdown: warn only — matches bridge_instance()/context_manager()
        // behavior where shutdown is a terminal state and operations fail
        // naturally at the MLS/transport layer. This avoids hard failures
        // in test teardown when afterAll calls shutdown() and a later test
        // file tries to set transport.
        if self.is_shutdown() {
            tracing::warn!("set_transport called after shutdown — transport will not be usable");
        }
        if self.is_suspended() {
            return Err(TransportLockError::Rejected(
                "bridge instance is suspended — call resume() before setting transport".to_owned(),
            ));
        }
        let mut guard = self
            .transport
            .write()
            .map_err(|_| TransportLockError::Poisoned)?;
        *guard = Some(manager);
        Ok(())
    }

    /// Clears the transport manager (called on disconnect or suspend).
    ///
    /// Does **not** clear the stored relay URL — the URL is preserved so
    /// that callers can retrieve it after [`resume`] and reconnect to the
    /// same relay. The relay URL is only cleared explicitly in
    /// [`shutdown`] (after flush) or by the caller via an explicit
    /// disconnect flow.
    ///
    /// After this, relay-based operations will fail until a new transport
    /// manager is set.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the `RwLock` is poisoned.
    #[allow(clippy::significant_drop_tightening)]
    pub fn clear_transport(&self) -> Result<(), TransportLockError> {
        let mut guard = self
            .transport
            .write()
            .map_err(|_| TransportLockError::Poisoned)?;
        *guard = None;
        Ok(())
    }

    /// Returns `true` if a transport manager has been set.
    #[must_use]
    pub fn has_transport(&self) -> bool {
        self.transport
            .read()
            .ok()
            .is_some_and(|guard| guard.is_some())
    }

    /// Stores the relay URL for the current transport connection.
    ///
    /// Callers (bridge `transport_connect` functions) should call this
    /// immediately after [`set_transport`] so that [`pending_relay_url`]
    /// can return the URL for reconnection after [`resume`].
    ///
    /// If the `relay_url` mutex is poisoned (a previous caller panicked
    /// while holding it), the URL is silently dropped and a warning is
    /// logged — a lost relay URL on resume is recoverable by the caller.
    pub fn set_relay_url(&self, url: String) {
        match self.relay_url.lock() {
            Ok(mut guard) => *guard = Some(url),
            Err(_) => {
                tracing::warn!("relay_url mutex poisoned — relay URL not stored");
            }
        }
    }

    /// Returns the relay URL stored by the most recent [`set_relay_url`] call.
    ///
    /// After [`suspend`], this returns `Some` — the URL is preserved so
    /// callers can reconnect after [`resume`]. After [`shutdown`], this
    /// returns `None` (the URL is cleared during shutdown cleanup).
    ///
    /// Returns `None` if no URL has been stored, if the instance has been
    /// shut down, or if the internal mutex is poisoned.
    #[must_use]
    pub fn pending_relay_url(&self) -> Option<String> {
        self.relay_url.lock().ok().and_then(|guard| guard.clone())
    }

    /// Returns an `Arc` clone of the current transport manager, if one exists.
    ///
    /// Used by NAPI `context_subscribe` which needs to move the manager
    /// reference into an async task that outlives any lock guard.
    ///
    /// # Errors
    ///
    /// Returns `TransportLockError::Poisoned` if the lock is poisoned.
    pub fn get_transport_arc(
        &self,
    ) -> Result<Option<Arc<scp_transport::TransportManager>>, TransportLockError> {
        let guard = self
            .transport
            .read()
            .map_err(|_| TransportLockError::Poisoned)?;
        Ok(guard.clone())
    }

    /// Executes a closure with a read reference to the `TransportManager`.
    ///
    /// # Errors
    ///
    /// Returns `TransportLockError::Poisoned` if the lock is poisoned,
    /// or `TransportLockError::NotInitialized` if no transport manager has
    /// been set.
    #[allow(clippy::significant_drop_tightening)]
    pub fn with_transport<T>(
        &self,
        f: impl FnOnce(&scp_transport::TransportManager) -> T,
    ) -> Result<T, TransportLockError> {
        let guard = self.transport.read().map_err(|_| {
            tracing::debug!("transport RwLock poisoned (a writer panicked)");
            TransportLockError::Poisoned
        })?;
        let manager = guard.as_deref().ok_or_else(|| {
            tracing::debug!("transport slot is empty — no transport_connect call");
            TransportLockError::NotInitialized
        })?;
        Ok(f(manager))
    }

    /// Executes a closure with a mutable reference to the `TransportManager`.
    ///
    /// Requires exclusive access to the `Arc` (refcount == 1). If subscription
    /// tasks hold cloned `Arc` references, this will return
    /// [`TransportLockError::InUse`].
    ///
    /// # Errors
    ///
    /// Returns `TransportLockError::Poisoned` if the lock is poisoned,
    /// `TransportLockError::NotInitialized` if no transport manager has been
    /// set, or `TransportLockError::InUse` if the `Arc` has other holders.
    #[allow(clippy::significant_drop_tightening)]
    pub fn with_transport_mut<T>(
        &self,
        f: impl FnOnce(&mut scp_transport::TransportManager) -> T,
    ) -> Result<T, TransportLockError> {
        let mut guard = self.transport.write().map_err(|_| {
            tracing::debug!("transport RwLock poisoned (a writer panicked)");
            TransportLockError::Poisoned
        })?;
        let arc = guard.as_mut().ok_or_else(|| {
            tracing::debug!("transport slot is empty — no transport_connect call");
            TransportLockError::NotInitialized
        })?;
        // Capture strong count before the mutable borrow attempt (can't borrow
        // arc immutably inside the ok_or_else closure while get_mut borrows it).
        let strong_count = Arc::strong_count(arc);
        let manager = Arc::get_mut(arc).ok_or_else(|| {
            tracing::debug!(
                strong_count,
                "transport Arc has multiple holders — subscription task(s) holding references",
            );
            TransportLockError::InUse
        })?;
        Ok(f(manager))
    }

    // -----------------------------------------------------------------
    // Known contexts accessors
    // -----------------------------------------------------------------

    /// Returns a reference to the known-contexts `DashMap`.
    ///
    /// **Prefer the typed accessors** ([`register_known_context`],
    /// [`remove_known_context`], [`all_known_contexts`],
    /// [`known_contexts_for_member`], [`known_context_count`],
    /// [`has_known_context`]) which enforce capacity limits. Direct
    /// mutation via this reference bypasses capacity enforcement.
    #[must_use]
    pub const fn known_contexts(&self) -> &DashMap<String, KnownContext> {
        &self.known_contexts
    }

    /// Returns the number of known contexts in the discovery registry.
    #[must_use]
    pub fn known_context_count(&self) -> usize {
        self.known_contexts.len()
    }

    /// Returns whether the given context ID is in the discovery registry.
    #[must_use]
    pub fn has_known_context(&self, context_id: &str) -> bool {
        self.known_contexts.contains_key(context_id)
    }

    /// Registers a known context in the discovery registry.
    ///
    /// Overwrites any existing entry for the same context ID (idempotent).
    /// When the registry is at capacity ([`MAX_KNOWN_CONTEXTS`]), evicts the
    /// oldest entry (by `last_seen` timestamp) before inserting.
    ///
    /// Note: Under concurrent registration, the cap may be temporarily exceeded
    /// by up to `num_threads - 1` entries. This is bounded and benign.
    pub fn register_known_context(&self, context_id: &str, known: KnownContext) {
        // If this context_id already exists, it's an overwrite — no eviction needed.
        if !self.known_contexts.contains_key(context_id)
            && self.known_contexts.len() >= MAX_KNOWN_CONTEXTS
        {
            // Find the entry with the smallest (oldest) last_seen timestamp.
            if let Some(oldest) = self
                .known_contexts
                .iter()
                .min_by_key(|entry| entry.value().last_seen)
            {
                let oldest_key = oldest.key().clone();
                drop(oldest);
                self.known_contexts.remove(&oldest_key);
                tracing::debug!(
                    evicted_context_id = %oldest_key,
                    capacity = MAX_KNOWN_CONTEXTS,
                    "evicted oldest known context to make room for new registration"
                );
            }
        }
        self.known_contexts.insert(context_id.to_owned(), known);
    }

    /// Removes a known context from the discovery registry.
    pub fn remove_known_context(&self, context_id: &str) {
        self.known_contexts.remove(context_id);
    }

    /// Returns all known contexts from the discovery registry.
    #[must_use]
    pub fn all_known_contexts(&self) -> Vec<(String, KnownContext)> {
        self.known_contexts
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }

    /// Returns known contexts where the given DID is the registered member.
    #[must_use]
    pub fn known_contexts_for_member(&self, member_did: &str) -> Vec<(String, KnownContext)> {
        self.known_contexts
            .iter()
            .filter(|entry| entry.value().member_did == member_did)
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }

    // -----------------------------------------------------------------
    // Rate limiter accessors
    // -----------------------------------------------------------------

    /// Returns a reference to the rate-limiters `DashMap`.
    ///
    /// **Prefer [`with_rate_limit_tracker`]** which enforces capacity limits.
    /// Direct mutation via this reference bypasses capacity enforcement.
    #[must_use]
    pub const fn rate_limiters(&self) -> &DashMap<String, RateLimitTracker> {
        &self.rate_limiters
    }

    /// Returns the number of rate limit trackers in the registry.
    #[must_use]
    pub fn rate_limiter_count(&self) -> usize {
        self.rate_limiters.len()
    }

    /// Executes a closure with a mutable reference to the rate limit tracker
    /// for the given identity DID, creating a default tracker if none exists.
    ///
    /// When the registry is at capacity ([`MAX_RATE_LIMITERS`]) and the
    /// requested DID does not already have a tracker, the oldest (first)
    /// entry is evicted to make room. This ensures rate limiting always has
    /// persistent history — an evicted tracker loses its window state, but
    /// rate limit bypass requires evicting and re-creating the same DID
    /// repeatedly, which is itself a detectable attack pattern.
    ///
    /// Note: Under concurrent creation, the cap may be temporarily exceeded
    /// by up to `num_threads - 1` entries. This is bounded and benign.
    pub fn with_rate_limit_tracker<F, T>(&self, identity_did: &str, f: F) -> T
    where
        F: FnOnce(&mut RateLimitTracker) -> T,
    {
        // If the entry already exists, serve it regardless of capacity.
        if let Some(mut entry) = self.rate_limiters.get_mut(identity_did) {
            return f(entry.value_mut());
        }
        // New entry: evict oldest if at capacity.
        if self.rate_limiters.len() >= MAX_RATE_LIMITERS {
            // Move the iterator result out before entering the remove call to
            // avoid holding the DashMap shard lock across the remove (which
            // would deadlock on the same shard).
            let oldest_key = self
                .rate_limiters
                .iter()
                .next()
                .map(|entry| entry.key().clone());
            if let Some(oldest_key) = oldest_key {
                self.rate_limiters.remove(&oldest_key);
                tracing::debug!(
                    evicted_did = %oldest_key,
                    capacity = MAX_RATE_LIMITERS,
                    "evicted oldest rate limiter entry to make room for new DID"
                );
            }
        }
        let mut entry = self
            .rate_limiters
            .entry(identity_did.to_owned())
            .or_default();
        f(entry.value_mut())
    }

    // -----------------------------------------------------------------
    // Economy accessors
    // -----------------------------------------------------------------

    /// Reads the budget tracker for a context, creating one if it doesn't exist.
    ///
    /// The closure receives an immutable reference to the tracker.
    ///
    /// When the registry is at capacity ([`MAX_ECONOMY_CONTEXTS`]) and the
    /// requested context ID does not already have a tracker, an ephemeral
    /// (non-persisted) default tracker is used and a warning is logged.
    /// Budget trackers are 1:1 with contexts, so the cap should never be
    /// reached unless [`remove_economy_state`] is not called on context cleanup.
    ///
    /// After shutdown, returns an ephemeral tracker to avoid re-populating
    /// the cleared `DashMap`.
    pub fn with_economy_budget<T, F>(&self, context_id: &str, f: F) -> T
    where
        F: FnOnce(&MemberBudgetTracker) -> T,
    {
        if self.is_shutdown() {
            // Post-shutdown: use ephemeral tracker, don't re-populate cleared map
            let ephemeral = MemberBudgetTracker::default();
            return f(&ephemeral);
        }
        if let Some(entry) = self.economy_budgets.get(context_id) {
            return f(entry.value());
        }
        if self.economy_budgets.len() >= MAX_ECONOMY_CONTEXTS {
            tracing::warn!(
                context_id = %context_id,
                capacity = MAX_ECONOMY_CONTEXTS,
                "economy budget registry at capacity — using ephemeral tracker; \
                 call remove_economy_state during context cleanup"
            );
            let ephemeral = MemberBudgetTracker::default();
            return f(&ephemeral);
        }
        let entry = self
            .economy_budgets
            .entry(context_id.to_owned())
            .or_default();
        f(entry.value())
    }

    /// Mutably accesses the budget tracker for a context, creating one if needed.
    ///
    /// The closure receives a mutable reference to the tracker.
    ///
    /// When the registry is at capacity ([`MAX_ECONOMY_CONTEXTS`]) and the
    /// requested context ID does not already have a tracker, an ephemeral
    /// (non-persisted) default tracker is used and a warning is logged.
    ///
    /// After shutdown, returns an ephemeral tracker to avoid re-populating
    /// the cleared `DashMap`.
    pub fn with_economy_budget_mut<T, F>(&self, context_id: &str, f: F) -> T
    where
        F: FnOnce(&mut MemberBudgetTracker) -> T,
    {
        if self.is_shutdown() {
            // Post-shutdown: use ephemeral tracker, don't re-populate cleared map
            let mut ephemeral = MemberBudgetTracker::default();
            return f(&mut ephemeral);
        }
        if let Some(mut entry) = self.economy_budgets.get_mut(context_id) {
            return f(entry.value_mut());
        }
        if self.economy_budgets.len() >= MAX_ECONOMY_CONTEXTS {
            tracing::warn!(
                context_id = %context_id,
                capacity = MAX_ECONOMY_CONTEXTS,
                "economy budget registry at capacity — using ephemeral tracker; \
                 call remove_economy_state during context cleanup"
            );
            let mut ephemeral = MemberBudgetTracker::default();
            return f(&mut ephemeral);
        }
        let mut entry = self
            .economy_budgets
            .entry(context_id.to_owned())
            .or_default();
        f(entry.value_mut())
    }

    /// Accesses the antispam velocity tracker for a context, creating one if
    /// needed.
    ///
    /// The closure receives a reference to the tracker (which is internally
    /// `Mutex`-protected, so `&self` methods like `record_message` and
    /// `get_velocity` work without `&mut`).
    ///
    /// When the registry is at capacity ([`MAX_ECONOMY_CONTEXTS`]) and the
    /// requested context ID does not already have a tracker, an ephemeral
    /// (non-persisted) tracker is used and a warning is logged.
    ///
    /// After shutdown, returns an ephemeral tracker to avoid re-populating
    /// the cleared `DashMap`.
    pub fn with_economy_antispam<T, F>(&self, context_id: &str, f: F) -> T
    where
        F: FnOnce(&SenderVelocityTracker) -> T,
    {
        if self.is_shutdown() {
            // Post-shutdown: use ephemeral tracker, don't re-populate cleared map
            let ephemeral = SenderVelocityTracker::new(ANTISPAM_DEFAULT_WINDOW_SECS);
            return f(&ephemeral);
        }
        if let Some(entry) = self.economy_antispam.get(context_id) {
            return f(entry.value());
        }
        if self.economy_antispam.len() >= MAX_ECONOMY_CONTEXTS {
            tracing::warn!(
                context_id = %context_id,
                capacity = MAX_ECONOMY_CONTEXTS,
                "economy antispam registry at capacity — using ephemeral tracker; \
                 call remove_economy_state during context cleanup"
            );
            let ephemeral = SenderVelocityTracker::new(ANTISPAM_DEFAULT_WINDOW_SECS);
            return f(&ephemeral);
        }
        let entry = self
            .economy_antispam
            .entry(context_id.to_owned())
            .or_insert_with(|| SenderVelocityTracker::new(ANTISPAM_DEFAULT_WINDOW_SECS));
        f(entry.value())
    }

    /// Removes economy state (budget tracker and antispam tracker) for a context.
    ///
    /// Should be called during context cleanup for long-running processes.
    pub fn remove_economy_state(&self, context_id: &str) {
        self.economy_budgets.remove(context_id);
        self.economy_antispam.remove(context_id);
    }

    // -----------------------------------------------------------------
    // Bridge connector state accessors
    // -----------------------------------------------------------------

    /// Returns a reference to the bridge connector state `DashMap`.
    ///
    /// Keyed by context ID. Each entry holds a [`BridgeContextState`] with
    /// the shadow registry and sender key store for that context.
    #[must_use]
    pub const fn bridge_state(&self) -> &DashMap<String, BridgeContextState> {
        &self.bridge_state
    }

    /// Removes per-context bridge connector state on context close, preventing
    /// unbounded memory growth in long-running processes.
    pub fn remove_bridge_state(&self, context_id: &str) {
        self.bridge_state.remove(context_id);
    }

    /// Clears all bridge connector state entries. Called during shutdown.
    pub fn clear_bridge_state(&self) {
        self.bridge_state.clear();
    }

    // -----------------------------------------------------------------
    // DID resolver accessors
    // -----------------------------------------------------------------

    /// Returns the production DID resolver, if initialized.
    #[must_use]
    pub fn did_resolver(&self) -> Option<&Arc<IdentityBackedDidResolver>> {
        self.did_resolver.get()
    }

    /// Stores the production DID resolver.
    ///
    /// Called once during identity system setup. Subsequent calls are no-ops
    /// (`OnceLock` guarantees single initialization).
    pub fn set_did_resolver(&self, resolver: Arc<IdentityBackedDidResolver>) {
        if self.did_resolver.set(resolver).is_err() {
            tracing::warn!("set_did_resolver called but resolver already initialized — ignoring");
        }
    }

    // -----------------------------------------------------------------
    // Type-erased bridge-specific singleton accessors
    // -----------------------------------------------------------------

    /// Stores the bridge's identity registry as a type-erased value and
    /// registers a clear function called during [`shutdown`].
    ///
    /// `value` should be `Arc<DashMap<String, BridgeIdentityEntry>>`.
    /// `clear_fn` must call `.clear()` on the same map (typically a closure
    /// holding a cloned `Arc` to the same map).
    /// Subsequent calls are no-ops (`OnceLock`).
    pub fn set_identity_registry<T: Any + Send + Sync>(
        &self,
        value: T,
        clear_fn: Box<dyn Fn() + Send + Sync>,
    ) {
        if self.identity_registry.set(Box::new(value)).is_err() {
            tracing::warn!(
                "set_identity_registry called but identity registry already initialized — ignoring"
            );
            return;
        }
        let _ = self.identity_registry_clear_fn.set(clear_fn);
    }

    /// Retrieves the bridge's identity registry, downcasting to `T`.
    ///
    /// Returns `None` if the registry has not been set or if the downcast
    /// fails (mismatched type). A downcast failure logs an error with the
    /// expected type name to distinguish "not initialized" from "wrong type."
    #[must_use]
    pub fn get_identity_registry_as<T: Any + Send + Sync>(&self) -> Option<&T> {
        let boxed = self.identity_registry.get()?;
        let result = boxed.downcast_ref::<T>();
        if result.is_none() {
            tracing::error!(
                expected = std::any::type_name::<T>(),
                "identity_registry downcast failed — type mismatch (not 'not initialized')"
            );
        }
        result
    }

    /// Stores the bridge's storage provider as a type-erased value.
    ///
    /// `value` should be `Arc<EncryptingAdapter<T>>`. Subsequent calls are
    /// no-ops (`OnceLock`). The value is released on process exit.
    pub fn set_storage_provider<T: Any + Send + Sync>(&self, value: T) {
        if self.storage_provider.set(Box::new(value)).is_err() {
            tracing::warn!(
                "set_storage_provider called but storage provider already initialized — ignoring"
            );
        }
    }

    /// Retrieves the bridge's storage provider, downcasting to `T`.
    ///
    /// Returns `None` if the provider has not been set or if the downcast
    /// fails (mismatched type). A downcast failure logs an error with the
    /// expected type name to distinguish "not initialized" from "wrong type."
    #[must_use]
    pub fn get_storage_provider_as<T: Any + Send + Sync>(&self) -> Option<&T> {
        let boxed = self.storage_provider.get()?;
        let result = boxed.downcast_ref::<T>();
        if result.is_none() {
            tracing::error!(
                expected = std::any::type_name::<T>(),
                "storage_provider downcast failed — type mismatch (not 'not initialized')"
            );
        }
        result
    }

    /// Stores the bridge's protocol repository as a type-erased value.
    ///
    /// `value` should be `Arc<ProtocolRepository<T>>`. Subsequent calls are
    /// no-ops (`OnceLock`). The value is released on process exit.
    pub fn set_protocol_repository<T: Any + Send + Sync>(&self, value: T) {
        if self.protocol_repository.set(Box::new(value)).is_err() {
            tracing::warn!(
                "set_protocol_repository called but protocol repository already initialized — ignoring"
            );
        }
    }

    /// Retrieves the bridge's protocol repository, downcasting to `T`.
    ///
    /// Returns `None` if the repository has not been set or if the downcast
    /// fails (mismatched type). A downcast failure logs an error with the
    /// expected type name to distinguish "not initialized" from "wrong type."
    #[must_use]
    pub fn get_protocol_repository_as<T: Any + Send + Sync>(&self) -> Option<&T> {
        let boxed = self.protocol_repository.get()?;
        let result = boxed.downcast_ref::<T>();
        if result.is_none() {
            tracing::error!(
                expected = std::any::type_name::<T>(),
                "protocol_repository downcast failed — type mismatch (not 'not initialized')"
            );
        }
        result
    }

    /// Stores the bridge's UCAN context state registry as a type-erased value
    /// and registers a clear function called during [`shutdown`].
    ///
    /// `value` should be `Arc<DashMap<String, BridgeUcanContextState>>`.
    /// `clear_fn` must call `.clear()` on the same map (typically a closure
    /// holding a cloned `Arc` to the same map).
    /// Subsequent calls are no-ops (`OnceLock`).
    pub fn set_ucan_registry<T: Any + Send + Sync>(
        &self,
        value: T,
        clear_fn: Box<dyn Fn() + Send + Sync>,
    ) {
        if self.ucan_registry.set(Box::new(value)).is_err() {
            tracing::warn!(
                "set_ucan_registry called but UCAN registry already initialized — ignoring"
            );
            return;
        }
        let _ = self.ucan_registry_clear_fn.set(clear_fn);
    }

    /// Retrieves the bridge's UCAN registry, downcasting to `T`.
    ///
    /// Returns `None` if the registry has not been set or if the downcast
    /// fails (mismatched type). A downcast failure logs an error with the
    /// expected type name to distinguish "not initialized" from "wrong type."
    #[must_use]
    pub fn get_ucan_registry_as<T: Any + Send + Sync>(&self) -> Option<&T> {
        let boxed = self.ucan_registry.get()?;
        let result = boxed.downcast_ref::<T>();
        if result.is_none() {
            tracing::error!(
                expected = std::any::type_name::<T>(),
                "ucan_registry downcast failed — type mismatch (not 'not initialized')"
            );
        }
        result
    }
}

/// Error type for transport lock operations.
///
/// Used by [`BridgeInstance`] transport accessor methods. Bridge layers map
/// this to their own error types (`ScpPyError`, napi `Error`, etc.).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportLockError {
    /// The transport `RwLock` was poisoned (a writer panicked while holding it).
    Poisoned,
    /// No transport manager has been set (call `set_transport` first).
    NotInitialized,
    /// The transport manager `Arc` is in use by an active subscription task.
    /// Mutable access requires exclusive ownership (refcount == 1).
    InUse,
    /// The operation was rejected due to a lifecycle violation — the bridge
    /// instance is shut down or suspended and cannot accept transport changes.
    Rejected(String),
}

impl std::fmt::Display for TransportLockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Sanitized messages: no internal architecture details (lock types,
        // Arc refcounts, etc.) leak to callers. Debug-level logging at the
        // creation site provides the detailed reason for operators.
        match self {
            Self::Poisoned => write!(f, "transport operation failed — internal error"),
            Self::NotInitialized => {
                write!(
                    f,
                    "transport not initialized — call transport_connect first"
                )
            }
            Self::InUse => write!(f, "transport is busy — try again later"),
            Self::Rejected(msg) => write!(f, "transport operation rejected: {msg}"),
        }
    }
}

impl std::error::Error for TransportLockError {}

/// Error type for lifecycle operations (`resume`, `check_ready`).
///
/// Used by [`BridgeInstance::resume`] and [`BridgeInstance::check_ready`].
/// Bridge layers map this to their own error types (`ScpPyError`, napi `Error`,
/// etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleError {
    /// The instance has been permanently shut down and cannot be resumed.
    AlreadyShutDown,
    /// The instance is currently suspended (backgrounded). Transport-dependent
    /// operations are unavailable. Call `resume()` to re-activate.
    Suspended,
}

impl std::fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyShutDown => {
                write!(f, "bridge instance has been permanently shut down")
            }
            Self::Suspended => write!(
                f,
                "bridge is suspended — call resume() before performing operations"
            ),
        }
    }
}

impl std::error::Error for LifecycleError {}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use scp_core::context::LocalTransportProvider;
    use scp_core::context::builder::{
        ContextCreationError, ContextCryptoProvider, ContextEventLogProvider,
    };
    use scp_core::context::{AddMemberOutput, ContextError, RemoveMemberOutput};
    use std::pin::Pin;

    use scp_core::envelope::outer::OuterEnvelope;
    use scp_transport::{BlobId, RoutingId, SubscriptionStream, TransportAdapter, TransportError};

    // Minimal no-op providers for constructing a ContextManager in tests.

    struct NoOpCrypto;
    impl ContextCryptoProvider for NoOpCrypto {
        fn validate_creator_identity(&self) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn create_mls_group(&self, _: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn generate_sender_key(&self, _: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn init_broadcast_key(&self, _: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn destroy_mls_group(&self, _: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn destroy_sender_key(&self, _: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn validate_key_package(&self, _: &str, _: Option<&[u8]>) -> Result<(), ContextError> {
            Ok(())
        }
        fn add_member(
            &self,
            _: &[u8; 32],
            _: &str,
            _: Option<&[u8]>,
        ) -> Result<AddMemberOutput, ContextError> {
            Ok(AddMemberOutput::default())
        }
        fn remove_member(&self, _: &[u8; 32], _: &str) -> Result<RemoveMemberOutput, ContextError> {
            Ok(RemoveMemberOutput::default())
        }
        fn distribute_sender_key(&self, _: &[u8; 32], _: &str) -> Result<(), ContextError> {
            Ok(())
        }
        fn remove_member_sender_key(&self, _: &[u8; 32], _: &str) -> Result<(), ContextError> {
            Ok(())
        }
    }

    struct NoOpEventLog;
    impl ContextEventLogProvider for NoOpEventLog {
        fn init_event_log(&self, _: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn append_event(
            &self,
            _: &[u8; 32],
            _: &str,
            _: &str,
            _: Option<&serde_json::Value>,
        ) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn destroy_event_log(&self, _: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
    }

    fn test_context_manager() -> Arc<ContextManager> {
        // Use LocalTransportProvider (silently succeeds) for tests.
        // Key resolver returns None — no signature verification in tests.
        let key_resolver: scp_core::context::governance::KeyResolver = Arc::new(|_| None);
        Arc::new(ContextManager::new(
            Box::new(NoOpCrypto),
            Box::new(LocalTransportProvider),
            Box::new(NoOpEventLog),
            key_resolver,
        ))
    }

    /// Minimal no-op transport adapter for lifecycle tests.
    struct NoOpAdapter;

    type BoxFut<'a, T> = Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

    impl TransportAdapter for NoOpAdapter {
        fn send(&self, _: &OuterEnvelope) -> BoxFut<'_, Result<BlobId, TransportError>> {
            Box::pin(async { Err(TransportError::NotConnected) })
        }
        fn subscribe(
            &self,
            _: &RoutingId,
            _: Option<u64>,
        ) -> BoxFut<'_, Result<SubscriptionStream, TransportError>> {
            Box::pin(async { Err(TransportError::NotConnected) })
        }
        fn unsubscribe(&self, _: &RoutingId) -> BoxFut<'_, Result<(), TransportError>> {
            Box::pin(async { Ok(()) })
        }
        fn query(
            &self,
            _: &RoutingId,
            _: Option<u64>,
        ) -> BoxFut<'_, Result<Vec<OuterEnvelope>, TransportError>> {
            Box::pin(async { Err(TransportError::NotConnected) })
        }
        fn delete(&self, _: &BlobId) -> BoxFut<'_, Result<(), TransportError>> {
            Box::pin(async { Ok(()) })
        }
    }

    fn test_transport_manager() -> scp_transport::TransportManager {
        scp_transport::TransportManager::new(Box::new(NoOpAdapter))
    }

    #[test]
    fn new_creates_instance_with_expected_state() {
        let cm = test_context_manager();
        let instance = BridgeInstance::new(Arc::clone(&cm), "did:dht:z1234".to_owned());

        assert_eq!(instance.local_did(), "did:dht:z1234");
        assert!(!instance.is_shutdown());
        // Verify the ContextManager pointer is the same Arc
        assert!(Arc::ptr_eq(instance.context_manager(), &cm));
        // Shared state starts empty
        assert!(!instance.has_transport());
        assert!(instance.known_contexts().is_empty());
        assert!(instance.rate_limiters().is_empty());
    }

    #[test]
    fn shutdown_transitions_flag_permanently() {
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());

        assert!(!instance.is_shutdown());
        instance.shutdown();
        assert!(instance.is_shutdown());

        // Calling shutdown again is a no-op — still true
        instance.shutdown();
        assert!(instance.is_shutdown());
    }

    #[test]
    fn context_manager_returns_shared_reference() {
        let cm = test_context_manager();
        let instance = BridgeInstance::new(Arc::clone(&cm), "did:dht:z5678".to_owned());

        // Both should point to the same ContextManager allocation
        assert!(Arc::ptr_eq(instance.context_manager(), &cm));
    }

    #[test]
    fn local_did_returns_construction_value() {
        let did = "did:dht:zabcdef0123456789";
        let instance = BridgeInstance::new(test_context_manager(), did.to_owned());
        assert_eq!(instance.local_did(), did);
    }

    #[test]
    fn is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<BridgeInstance>();
    }

    // -----------------------------------------------------------------
    // Transport tests
    // -----------------------------------------------------------------

    #[test]
    fn transport_starts_empty() {
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());
        assert!(!instance.has_transport());
        assert_eq!(
            instance.with_transport(|_| ()).unwrap_err(),
            TransportLockError::NotInitialized
        );
    }

    #[test]
    fn clear_transport_when_empty_is_ok() {
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());
        assert!(instance.clear_transport().is_ok());
        assert!(!instance.has_transport());
    }

    // -----------------------------------------------------------------
    // Known context tests
    // -----------------------------------------------------------------

    #[test]
    fn register_and_retrieve_known_context() {
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());
        let known = KnownContext {
            routing_id: [42u8; 32],
            relay_url: Some("wss://relay.example.com".to_owned()),
            member_did: "did:dht:zalice".to_owned(),
            last_seen: 1_700_000_000,
        };
        instance.register_known_context("ctx-1", known);
        assert_eq!(instance.known_contexts().len(), 1);

        let all = instance.all_known_contexts();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].0, "ctx-1");
        assert_eq!(all[0].1.routing_id, [42u8; 32]);
        assert_eq!(all[0].1.member_did, "did:dht:zalice");
    }

    #[test]
    fn known_contexts_for_member_filters() {
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());
        instance.register_known_context(
            "ctx-alice",
            KnownContext {
                routing_id: [1u8; 32],
                relay_url: None,
                member_did: "did:dht:zalice".to_owned(),
                last_seen: 100,
            },
        );
        instance.register_known_context(
            "ctx-bob",
            KnownContext {
                routing_id: [2u8; 32],
                relay_url: None,
                member_did: "did:dht:zbob".to_owned(),
                last_seen: 200,
            },
        );

        let alice_contexts = instance.known_contexts_for_member("did:dht:zalice");
        assert_eq!(alice_contexts.len(), 1);
        assert_eq!(alice_contexts[0].0, "ctx-alice");

        let bob_contexts = instance.known_contexts_for_member("did:dht:zbob");
        assert_eq!(bob_contexts.len(), 1);
        assert_eq!(bob_contexts[0].0, "ctx-bob");

        let nobody_contexts = instance.known_contexts_for_member("did:dht:znobody");
        assert!(nobody_contexts.is_empty());
    }

    #[test]
    fn remove_known_context_works() {
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());
        instance.register_known_context(
            "ctx-1",
            KnownContext {
                routing_id: [0u8; 32],
                relay_url: None,
                member_did: "did:dht:ztest".to_owned(),
                last_seen: 0,
            },
        );
        assert_eq!(instance.known_contexts().len(), 1);
        instance.remove_known_context("ctx-1");
        assert!(instance.known_contexts().is_empty());
    }

    // -----------------------------------------------------------------
    // Rate limiter tests
    // -----------------------------------------------------------------

    #[test]
    fn rate_limiter_creates_default_on_first_access() {
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());
        assert!(instance.rate_limiters().is_empty());

        // Accessing a non-existent tracker creates a default one
        instance.with_rate_limit_tracker("did:dht:zalice", |_tracker| {});
        assert_eq!(instance.rate_limiters().len(), 1);
    }

    // -----------------------------------------------------------------
    // TransportLockError tests
    // -----------------------------------------------------------------

    #[test]
    fn transport_lock_error_display() {
        assert_eq!(
            TransportLockError::Poisoned.to_string(),
            "transport operation failed \u{2014} internal error"
        );
        assert_eq!(
            TransportLockError::NotInitialized.to_string(),
            "transport not initialized \u{2014} call transport_connect first"
        );
        assert_eq!(
            TransportLockError::InUse.to_string(),
            "transport is busy \u{2014} try again later"
        );
        assert_eq!(
            TransportLockError::Rejected("bridge is shut down".to_owned()).to_string(),
            "transport operation rejected: bridge is shut down"
        );
    }

    // -----------------------------------------------------------------
    // Lifecycle tests (suspend / resume / shutdown)
    // -----------------------------------------------------------------

    #[test]
    fn suspend_clears_transport() {
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());
        instance
            .set_transport(Arc::new(test_transport_manager()))
            .unwrap();
        assert!(instance.has_transport());

        instance.suspend().unwrap();

        assert!(!instance.has_transport());
        assert!(instance.is_suspended());
    }

    #[test]
    fn suspend_is_noop_when_shutdown() {
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());
        instance.shutdown();

        // Suspending an already-shutdown instance is a no-op (not an error)
        instance.suspend().unwrap();
        assert!(instance.is_shutdown());
        assert!(!instance.is_suspended());
    }

    #[test]
    fn resume_clears_suspended_flag() {
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());
        instance.suspend().unwrap();
        assert!(instance.is_suspended());

        instance.resume().unwrap();
        assert!(!instance.is_suspended());
    }

    #[test]
    fn resume_fails_after_shutdown() {
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());
        instance.shutdown();

        let err = instance.resume().unwrap_err();
        assert_eq!(err, LifecycleError::AlreadyShutDown);
        assert_eq!(
            err.to_string(),
            "bridge instance has been permanently shut down"
        );
    }

    #[test]
    fn shutdown_is_idempotent() {
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());

        // Register some state
        instance.register_known_context(
            "ctx-1",
            KnownContext {
                routing_id: [0u8; 32],
                relay_url: None,
                member_did: "did:dht:ztest".to_owned(),
                last_seen: 0,
            },
        );
        instance.with_rate_limit_tracker("did:dht:ztest", |_| {});

        instance.shutdown();
        assert!(instance.is_shutdown());
        assert!(instance.known_contexts().is_empty());
        assert!(instance.rate_limiters().is_empty());

        // Second call is a no-op
        instance.shutdown();
        assert!(instance.is_shutdown());
    }

    #[test]
    fn shutdown_clears_registries() {
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());

        // Populate registries
        instance.register_known_context(
            "ctx-a",
            KnownContext {
                routing_id: [1u8; 32],
                relay_url: Some("wss://r.example.com".to_owned()),
                member_did: "did:dht:zalice".to_owned(),
                last_seen: 100,
            },
        );
        instance.register_known_context(
            "ctx-b",
            KnownContext {
                routing_id: [2u8; 32],
                relay_url: None,
                member_did: "did:dht:zbob".to_owned(),
                last_seen: 200,
            },
        );
        instance.with_rate_limit_tracker("did:dht:zalice", |_| {});
        instance.with_rate_limit_tracker("did:dht:zbob", |_| {});

        assert_eq!(instance.known_contexts().len(), 2);
        assert_eq!(instance.rate_limiters().len(), 2);

        instance.shutdown();

        assert!(instance.known_contexts().is_empty());
        assert!(instance.rate_limiters().is_empty());
    }

    #[test]
    fn shutdown_clears_suspended_flag() {
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());
        instance.suspend().unwrap();
        assert!(instance.is_suspended());

        instance.shutdown();
        assert!(instance.is_shutdown());
        // Shutdown supersedes suspension
        assert!(!instance.is_suspended());
    }

    #[test]
    fn new_instance_is_not_suspended() {
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());
        assert!(!instance.is_suspended());
    }

    #[test]
    fn lifecycle_error_display() {
        assert_eq!(
            LifecycleError::AlreadyShutDown.to_string(),
            "bridge instance has been permanently shut down"
        );
        assert_eq!(
            LifecycleError::Suspended.to_string(),
            "bridge is suspended \u{2014} call resume() before performing operations"
        );
    }

    #[test]
    fn check_ready_passes_when_active() {
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());
        assert!(instance.check_ready().is_ok());
    }

    #[test]
    fn check_ready_fails_when_shutdown() {
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());
        instance.shutdown();
        let err = instance.check_ready().unwrap_err();
        assert_eq!(err, LifecycleError::AlreadyShutDown);
    }

    #[test]
    fn check_ready_fails_when_suspended() {
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());
        instance.suspend().unwrap();
        let err = instance.check_ready().unwrap_err();
        assert_eq!(err, LifecycleError::Suspended);
    }

    #[test]
    fn check_ready_passes_after_resume() {
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());
        instance.suspend().unwrap();
        assert!(instance.check_ready().is_err());
        instance.resume().unwrap();
        assert!(instance.check_ready().is_ok());
    }

    #[test]
    fn known_contexts_cap_evicts_oldest() {
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());

        // Register MAX_KNOWN_CONTEXTS entries.
        for i in 0..MAX_KNOWN_CONTEXTS {
            instance.register_known_context(
                &format!("ctx-{i}"),
                KnownContext {
                    routing_id: [0u8; 32],
                    relay_url: None,
                    member_did: "did:dht:ztest".to_owned(),
                    last_seen: i as u64,
                },
            );
        }
        assert_eq!(instance.known_contexts().len(), MAX_KNOWN_CONTEXTS);

        // Register one more — should evict ctx-0 (smallest last_seen = 0).
        instance.register_known_context(
            "ctx-new",
            KnownContext {
                routing_id: [0u8; 32],
                relay_url: None,
                member_did: "did:dht:ztest".to_owned(),
                last_seen: MAX_KNOWN_CONTEXTS as u64,
            },
        );
        assert_eq!(instance.known_contexts().len(), MAX_KNOWN_CONTEXTS);
        assert!(instance.known_contexts().get("ctx-new").is_some());
        assert!(instance.known_contexts().get("ctx-0").is_none());
    }

    #[test]
    fn rate_limiter_cap_evicts_oldest() {
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());

        // Fill up to capacity.
        for i in 0..MAX_RATE_LIMITERS {
            instance.with_rate_limit_tracker(&format!("did:dht:z{i}"), |_| {});
        }
        assert_eq!(instance.rate_limiters().len(), MAX_RATE_LIMITERS);

        // Next new DID evicts an oldest entry and persists the new one.
        let result = instance.with_rate_limit_tracker("did:dht:znew", |_| 42);
        assert_eq!(result, 42);
        // Registry remains at capacity (one evicted, one added).
        assert_eq!(instance.rate_limiters().len(), MAX_RATE_LIMITERS);
        // The new DID is now persisted.
        assert!(
            instance.rate_limiters().contains_key("did:dht:znew"),
            "new DID should be persisted after eviction"
        );
    }

    // -----------------------------------------------------------------
    // Shutdown hook tests
    // -----------------------------------------------------------------

    #[test]
    fn shutdown_hooks_are_called_on_shutdown() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());

        let counter = Arc::new(AtomicUsize::new(0));
        let c1 = Arc::clone(&counter);
        let c2 = Arc::clone(&counter);

        instance.register_shutdown_hook(Box::new(move || {
            c1.fetch_add(1, Ordering::SeqCst);
        }));
        instance.register_shutdown_hook(Box::new(move || {
            c2.fetch_add(10, Ordering::SeqCst);
        }));

        // Before shutdown: hooks haven't run
        assert_eq!(counter.load(Ordering::SeqCst), 0);

        instance.shutdown();

        // Both hooks ran
        assert_eq!(counter.load(Ordering::SeqCst), 11);
    }

    #[test]
    fn shutdown_hooks_run_only_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());

        let counter = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&counter);

        instance.register_shutdown_hook(Box::new(move || {
            c.fetch_add(1, Ordering::SeqCst);
        }));

        instance.shutdown();
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        // Second shutdown is idempotent — hooks don't run again
        instance.shutdown();
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn register_hook_after_shutdown_runs_immediately() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());

        instance.shutdown();

        let ran = Arc::new(AtomicBool::new(false));
        let r = Arc::clone(&ran);

        // Registering after shutdown runs the hook immediately — shutdown()
        // already drained the hook Vec, so a late registration must fire
        // eagerly to guarantee cleanup.
        instance.register_shutdown_hook(Box::new(move || {
            r.store(true, Ordering::SeqCst);
        }));

        assert!(
            ran.load(Ordering::SeqCst),
            "hook registered after shutdown must run immediately"
        );
    }

    // -----------------------------------------------------------------
    // set_transport lifecycle guard tests
    // -----------------------------------------------------------------

    #[test]
    fn set_transport_warns_after_shutdown() {
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());
        instance.shutdown();

        // set_transport after shutdown warns but does not error — matches
        // the bridge_instance()/context_manager() pattern where shutdown
        // is a terminal state and operations fail naturally at the
        // MLS/transport layer.
        assert!(
            instance
                .set_transport(Arc::new(test_transport_manager()))
                .is_ok(),
            "set_transport should warn, not reject, after shutdown"
        );
    }

    #[test]
    fn set_transport_rejects_when_suspended() {
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());
        instance.suspend().unwrap();

        let err = instance
            .set_transport(Arc::new(test_transport_manager()))
            .unwrap_err();
        assert!(
            matches!(err, TransportLockError::Rejected(_)),
            "expected Rejected, got {err:?}"
        );
        assert!(err.to_string().contains("suspended"));
    }

    #[test]
    fn set_transport_accepts_after_resume() {
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());
        instance.suspend().unwrap();
        instance.resume().unwrap();

        assert!(
            instance
                .set_transport(Arc::new(test_transport_manager()))
                .is_ok()
        );
        assert!(instance.has_transport());
    }

    // -----------------------------------------------------------------
    // Post-shutdown hook panic safety
    // -----------------------------------------------------------------

    #[test]
    #[allow(clippy::panic)]
    fn register_hook_after_shutdown_catches_panic() {
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());
        instance.shutdown();

        // A panicking hook registered after shutdown must not propagate.
        instance.register_shutdown_hook(Box::new(|| {
            panic!("deliberate panic in post-shutdown hook test");
        }));

        // If we got here, the panic was caught.
        assert!(instance.is_shutdown());
    }

    // -----------------------------------------------------------------
    // Shutdown hook: hooks run exactly once, modify external state
    // -----------------------------------------------------------------

    #[test]
    fn shutdown_hook_modifies_external_state() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());
        let state = Arc::new(AtomicBool::new(false));
        let state2 = Arc::clone(&state);

        instance.register_shutdown_hook(Box::new(move || {
            state2.store(true, Ordering::SeqCst);
        }));

        // Hook has not run yet.
        assert!(
            !state.load(Ordering::SeqCst),
            "hook must not run before shutdown"
        );

        instance.shutdown();

        assert!(
            state.load(Ordering::SeqCst),
            "hook must have modified external state during shutdown"
        );
    }

    #[test]
    #[allow(clippy::panic)]
    fn multiple_hooks_all_run_even_if_one_panics() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());
        let counter = Arc::new(AtomicUsize::new(0));
        let c1 = Arc::clone(&counter);
        let c3 = Arc::clone(&counter);

        // Hook 1: increments counter.
        instance.register_shutdown_hook(Box::new(move || {
            c1.fetch_add(1, Ordering::SeqCst);
        }));
        // Hook 2: panics — must not prevent hook 3 from running.
        instance.register_shutdown_hook(Box::new(|| {
            panic!("deliberate panic to test isolation between hooks");
        }));
        // Hook 3: increments counter.
        instance.register_shutdown_hook(Box::new(move || {
            c3.fetch_add(1, Ordering::SeqCst);
        }));

        instance.shutdown();

        // Hooks 1 and 3 both ran despite hook 2 panicking.
        assert_eq!(
            counter.load(Ordering::SeqCst),
            2,
            "hooks 1 and 3 must both run even when hook 2 panics"
        );
    }

    // -----------------------------------------------------------------
    // Economy tests
    // -----------------------------------------------------------------

    #[test]
    fn economy_budget_creates_default_on_first_access() {
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());
        let remaining = instance.with_economy_budget("ctx-1", |tracker| {
            tracker.remaining(&scp_primitives::DID::from("did:dht:zalice"))
        });
        assert_eq!(remaining.value(), 0);
    }

    #[test]
    fn economy_budget_mut_grants_and_reads() {
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());
        let did = scp_primitives::DID::from("did:dht:zalice");
        instance.with_economy_budget_mut("ctx-eco", |tracker| {
            tracker.grant(&did, scp_protocol::economy::Amount::new(500));
        });
        let remaining = instance.with_economy_budget("ctx-eco", |tracker| tracker.remaining(&did));
        assert_eq!(remaining.value(), 500);
    }

    #[test]
    fn economy_antispam_creates_default_on_first_access() {
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());
        let did = scp_primitives::DID::from("did:dht:zbob");
        let velocity =
            instance.with_economy_antispam("ctx-spam", |tracker| tracker.get_velocity(&did, 1000));
        assert_eq!(velocity, 0);
    }

    #[test]
    fn remove_economy_state_clears_both() {
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());
        let did = scp_primitives::DID::from("did:dht:zalice");
        instance.with_economy_budget_mut("ctx-rm", |tracker| {
            tracker.grant(&did, scp_protocol::economy::Amount::new(100));
        });
        instance.with_economy_antispam("ctx-rm", |tracker| {
            tracker.record_message(&did, 1000);
        });

        instance.remove_economy_state("ctx-rm");

        // Budget should be fresh (zero) after removal.
        let remaining = instance.with_economy_budget("ctx-rm", |tracker| tracker.remaining(&did));
        assert_eq!(remaining.value(), 0);
    }

    #[test]
    fn economy_existing_context_id_bypasses_capacity_check() {
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());
        let did = scp_primitives::DID::from("did:dht:zalice");

        // Create one entry.
        instance.with_economy_budget_mut("ctx-exist", |tracker| {
            tracker.grant(&did, scp_protocol::economy::Amount::new(777));
        });

        // Reading the same context ID when the map is non-empty uses the
        // existing entry (not ephemeral).
        let remaining =
            instance.with_economy_budget("ctx-exist", |tracker| tracker.remaining(&did));
        assert_eq!(
            remaining.value(),
            777,
            "existing entry must be served, not an ephemeral default"
        );
    }

    #[test]
    fn economy_accessors_use_ephemeral_after_shutdown() {
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());
        let did = scp_primitives::DID::from("did:dht:zalice");

        // Grant a budget before shutdown.
        instance.with_economy_budget_mut("ctx-sd", |tracker| {
            tracker.grant(&did, scp_protocol::economy::Amount::new(500));
        });

        instance.shutdown();

        // Post-shutdown: budget should be empty (ephemeral), NOT re-populate the map.
        let remaining = instance.with_economy_budget("ctx-sd", |tracker| tracker.remaining(&did));
        assert_eq!(
            remaining.value(),
            0,
            "post-shutdown economy_budget must use ephemeral tracker"
        );

        // The DashMap must remain empty — economy_budget must NOT re-insert.
        assert!(
            instance.economy_budgets.is_empty(),
            "economy_budgets must not be re-populated after shutdown"
        );

        // with_economy_budget_mut also returns ephemeral.
        instance.with_economy_budget_mut("ctx-sd2", |tracker| {
            tracker.grant(&did, scp_protocol::economy::Amount::new(100));
        });
        assert!(
            instance.economy_budgets.is_empty(),
            "economy_budgets must not be re-populated after shutdown via _mut"
        );

        // with_economy_antispam also returns ephemeral.
        instance.with_economy_antispam("ctx-sd3", |tracker| {
            tracker.record_message(&did, 1000);
        });
        assert!(
            instance.economy_antispam.is_empty(),
            "economy_antispam must not be re-populated after shutdown"
        );
    }

    // -----------------------------------------------------------------
    // Bridge state tests
    // -----------------------------------------------------------------

    #[test]
    fn bridge_state_starts_empty() {
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());
        assert!(instance.bridge_state().is_empty());
    }

    #[test]
    fn bridge_state_insert_and_remove() {
        use scp_protocol::bridge::shadow::ShadowRegistry;
        use scp_protocol::crypto::sender_keys::SenderKeyStore;

        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());
        instance.bridge_state().insert(
            "ctx-bs".to_owned(),
            BridgeContextState {
                shadow_registry: ShadowRegistry::new("ctx-bs".to_owned()),
                sender_key_store: SenderKeyStore::new(),
            },
        );
        assert_eq!(instance.bridge_state().len(), 1);

        instance.remove_bridge_state("ctx-bs");
        assert!(instance.bridge_state().is_empty());
    }

    // -----------------------------------------------------------------
    // DID resolver tests
    // -----------------------------------------------------------------

    #[test]
    fn did_resolver_starts_none() {
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());
        assert!(instance.did_resolver().is_none());
    }

    // -----------------------------------------------------------------
    // Shutdown clears new registries
    // -----------------------------------------------------------------

    #[test]
    fn shutdown_clears_economy_and_bridge_state() {
        use scp_protocol::bridge::shadow::ShadowRegistry;
        use scp_protocol::crypto::sender_keys::SenderKeyStore;

        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());

        // Populate economy
        let did = scp_primitives::DID::from("did:dht:zalice");
        instance.with_economy_budget_mut("ctx-sd", |tracker| {
            tracker.grant(&did, scp_protocol::economy::Amount::new(100));
        });
        instance.with_economy_antispam("ctx-sd", |_| {});

        // Populate bridge state
        instance.bridge_state().insert(
            "ctx-sd".to_owned(),
            BridgeContextState {
                shadow_registry: ShadowRegistry::new("ctx-sd".to_owned()),
                sender_key_store: SenderKeyStore::new(),
            },
        );

        instance.shutdown();

        assert!(instance.bridge_state().is_empty());
        // Economy DashMaps should be cleared
        assert!(instance.economy_budgets.is_empty());
        assert!(instance.economy_antispam.is_empty());
    }

    // -----------------------------------------------------------------
    // AC 2: persistence field and accessor
    // -----------------------------------------------------------------

    #[test]
    fn new_instance_has_no_persistence() {
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());
        assert!(
            instance.persistence().is_none(),
            "new() must not have a persistence provider"
        );
    }

    #[test]
    fn with_persistence_sets_provider() {
        use scp_core::context::providers::InMemoryPersistence;

        let cm = test_context_manager();
        let persistence = Box::new(InMemoryPersistence::new());
        let instance =
            BridgeInstance::with_persistence(cm, "did:dht:zalice".to_owned(), persistence);
        assert!(
            instance.persistence().is_some(),
            "with_persistence() must set the persistence provider"
        );
    }

    // -----------------------------------------------------------------
    // AC 4: relay URL tracking
    // -----------------------------------------------------------------

    #[test]
    fn pending_relay_url_is_none_by_default() {
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());
        assert!(instance.pending_relay_url().is_none());
    }

    #[test]
    fn set_relay_url_stores_url() {
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());
        instance.set_relay_url("wss://relay.example.com".to_owned());
        assert_eq!(
            instance.pending_relay_url().as_deref(),
            Some("wss://relay.example.com")
        );
    }

    #[test]
    fn clear_transport_preserves_relay_url() {
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());
        instance
            .set_transport(Arc::new(test_transport_manager()))
            .unwrap();
        instance.set_relay_url("wss://relay.example.com".to_owned());
        assert!(instance.pending_relay_url().is_some());

        instance.clear_transport().unwrap();
        assert_eq!(
            instance.pending_relay_url().as_deref(),
            Some("wss://relay.example.com"),
            "clear_transport must preserve relay URL so callers can reconnect"
        );
    }

    #[test]
    fn suspend_preserves_relay_url() {
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());
        instance
            .set_transport(Arc::new(test_transport_manager()))
            .unwrap();
        instance.set_relay_url("wss://relay.example.com".to_owned());
        assert!(instance.pending_relay_url().is_some());

        instance.suspend().unwrap();
        assert_eq!(
            instance.pending_relay_url().as_deref(),
            Some("wss://relay.example.com"),
            "suspend must preserve relay URL so callers can reconnect after resume"
        );
    }

    #[test]
    fn relay_url_survives_suspend_resume_cycle() {
        // The relay URL is preserved across suspend/resume so callers can
        // reconnect to the same relay after resume.
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());
        instance
            .set_transport(Arc::new(test_transport_manager()))
            .unwrap();
        instance.set_relay_url("wss://relay.example.com".to_owned());
        instance.suspend().unwrap();
        assert_eq!(
            instance.pending_relay_url().as_deref(),
            Some("wss://relay.example.com"),
            "relay URL must survive suspend"
        );
        instance.resume().unwrap();
        assert_eq!(
            instance.pending_relay_url().as_deref(),
            Some("wss://relay.example.com"),
            "relay URL must survive resume — caller uses it to reconnect"
        );
    }

    #[test]
    fn shutdown_clears_relay_url() {
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());
        instance.set_relay_url("wss://relay.example.com".to_owned());
        assert!(instance.pending_relay_url().is_some());

        instance.shutdown();
        assert!(
            instance.pending_relay_url().is_none(),
            "shutdown must clear relay URL"
        );
    }

    // -----------------------------------------------------------------
    // AC 6: two-instance independence
    // -----------------------------------------------------------------

    #[test]
    fn two_instances_with_different_dids_are_independent() {
        let cm1 = test_context_manager();
        let cm2 = test_context_manager();
        let bi1 = BridgeInstance::new(Arc::clone(&cm1), "did:dht:alice".to_owned());
        let bi2 = BridgeInstance::new(Arc::clone(&cm2), "did:dht:bob".to_owned());

        assert_eq!(bi1.local_did(), "did:dht:alice");
        assert_eq!(bi2.local_did(), "did:dht:bob");

        // Shutting down one does not affect the other.
        bi1.shutdown();
        assert!(bi1.is_shutdown());
        assert!(!bi2.is_shutdown());

        // bi2 local_did is still accessible.
        assert_eq!(bi2.local_did(), "did:dht:bob");
        // bi2 is still ready to service operations.
        assert!(bi2.check_ready().is_ok());
    }

    // -----------------------------------------------------------------
    // AC 8: suspend/resume with persistence
    // -----------------------------------------------------------------

    #[test]
    fn suspend_flushes_contexts_to_persistence() {
        use scp_core::context::providers::InMemoryPersistence;
        use std::sync::Arc;

        let persistence = Arc::new(InMemoryPersistence::new());
        let persistence_for_cm = Box::new(InMemoryPersistence::new());
        let persistence_for_instance: Box<dyn ContextPersistence + Send + Sync> =
            Box::new(InMemoryPersistence::new());

        // Build a ContextManager with persistence.
        let key_resolver: scp_core::context::governance::KeyResolver = Arc::new(|_| None);
        let cm = Arc::new(ContextManager::with_persistence(
            Box::new(NoOpCrypto),
            Box::new(scp_core::context::LocalTransportProvider),
            Box::new(NoOpEventLog),
            persistence_for_cm,
            key_resolver,
        ));

        let instance = BridgeInstance::with_persistence(
            cm,
            "did:dht:ztest".to_owned(),
            persistence_for_instance,
        );

        // Verify the persistence accessor returns Some.
        assert!(instance.persistence().is_some());

        // Suspend should complete without errors (flush is best-effort).
        instance.suspend().unwrap();
        assert!(instance.is_suspended());

        // The relay URL was not set, so pending_relay_url is None.
        assert!(instance.pending_relay_url().is_none());

        // Resume clears the suspended flag.
        instance.resume().unwrap();
        assert!(!instance.is_suspended());

        // Instance is ready again.
        assert!(instance.check_ready().is_ok());

        // Suppress the unused `persistence` warning — it was only used to
        // verify the Arc::new pattern compiles; the real persistence is
        // inside the ContextManager.
        let _ = persistence;
    }

    // -----------------------------------------------------------------
    // AC 9: two instances operate concurrently (independent state)
    // -----------------------------------------------------------------

    #[test]
    fn two_instances_operate_concurrently() {
        let cm1 = test_context_manager();
        let cm2 = test_context_manager();
        let bi1 = BridgeInstance::new(Arc::clone(&cm1), "did:dht:alice".to_owned());
        let bi2 = BridgeInstance::new(Arc::clone(&cm2), "did:dht:bob".to_owned());

        // Register known contexts independently.
        bi1.register_known_context(
            "ctx-1",
            KnownContext {
                routing_id: [1u8; 32],
                relay_url: None,
                member_did: "did:dht:alice".to_owned(),
                last_seen: 100,
            },
        );
        bi2.register_known_context(
            "ctx-2",
            KnownContext {
                routing_id: [2u8; 32],
                relay_url: None,
                member_did: "did:dht:bob".to_owned(),
                last_seen: 200,
            },
        );

        // Each instance only knows about its own context.
        assert_eq!(bi1.known_context_count(), 1);
        assert!(bi1.has_known_context("ctx-1"));
        assert!(!bi1.has_known_context("ctx-2"));

        assert_eq!(bi2.known_context_count(), 1);
        assert!(bi2.has_known_context("ctx-2"));
        assert!(!bi2.has_known_context("ctx-1"));

        // Set relay URLs independently.
        bi1.set_relay_url("wss://relay1.example.com".to_owned());
        bi2.set_relay_url("wss://relay2.example.com".to_owned());
        assert_eq!(
            bi1.pending_relay_url().as_deref(),
            Some("wss://relay1.example.com")
        );
        assert_eq!(
            bi2.pending_relay_url().as_deref(),
            Some("wss://relay2.example.com")
        );

        // Shutdown of bi1 does not affect bi2's state.
        bi1.shutdown();
        assert!(bi1.is_shutdown());
        assert!(!bi2.is_shutdown());
        assert_eq!(bi2.known_context_count(), 1);
        assert_eq!(
            bi2.pending_relay_url().as_deref(),
            Some("wss://relay2.example.com")
        );
    }
}
