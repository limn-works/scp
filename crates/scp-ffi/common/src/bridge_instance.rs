//! Self-contained bridge instance replacing process-global `OnceLock` singletons.
//!
//! Each non-WASM FFI bridge currently uses 10+ `OnceLock` statics
//! (`CONTEXT_MANAGER`, `DID_RESOLVER`, `FFI_BRIDGE_STATE`, `KNOWN_CONTEXTS`,
//! `IDENTITY_REGISTRY`, `STORAGE_PROVIDER`, `TRANSPORT_MANAGER`,
//! `RATE_LIMIT_TRACKERS`, `ECONOMY_BUDGETS`, `ECONOMY_ANTISPAM`) for runtime
//! state. This forces single-tenant, process-global semantics and blocks
//! multi-instance use cases (test isolation, multiple identities, mobile
//! app lifecycle).
//!
//! `BridgeInstance` consolidates these into a single owned struct. Each
//! instance holds its own `ContextManager`, local DID, shutdown flag, and
//! shared state registries (transport, known contexts, rate limiters).
//! Multiple instances can coexist for different identities or test scenarios.
//!
//! # Migration
//!
//! Phase 4 Step 1 (#1549): Shared singletons (transport, known contexts,
//! rate limiters) are now owned by `BridgeInstance`. Bridge-specific singletons
//! (`FFI_BRIDGE_STATE`, `IDENTITY_REGISTRY`, `DID_RESOLVER`, `STORAGE_PROVIDER`,
//! `ECONOMY_BUDGETS`, `ECONOMY_ANTISPAM`) remain as per-bridge `OnceLock`s but
//! are now cleaned up during `shutdown()` via registered shutdown hooks. Each
//! bridge registers hooks that clear its bridge-specific `DashMap` singletons,
//! releasing `Arc` references to custody providers (key material zeroized on
//! `Drop`). `DID_RESOLVER` and `STORAGE_PROVIDER` are `OnceLock<Arc<...>>`
//! that cannot be cleared (no `OnceLock::take`) — they are dropped with the
//! process.
//!
//! # Thread Safety
//!
//! `BridgeInstance` is `Send + Sync`. The `ContextManager` is behind `Arc`
//! (interior `RwLock`/`DashMap`). The shutdown flag uses `AtomicBool` with
//! `Ordering::SeqCst` for visibility across threads. Transport uses
//! `std::sync::RwLock` for infrequent writes (connect/disconnect) and
//! concurrent reads (probe/query). Known contexts and rate limiters use
//! `DashMap` for lock-free concurrent access.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};

use dashmap::DashMap;
use scp_core::context::ContextManager;
use scp_protocol::context::invitation::RateLimitTracker;

/// Maximum number of known contexts that can be registered in the discovery
/// registry. When this limit is reached, the oldest entry (by `last_seen`)
/// is evicted to make room for the new one. 10,000 is well beyond any
/// realistic per-device usage while preventing unbounded memory growth from
/// a misbehaving caller.
const MAX_KNOWN_CONTEXTS: usize = 10_000;

/// Maximum number of rate limit trackers. When this limit is reached,
/// new tracker creation requests are rejected (the caller must retry
/// later). 1,000 concurrent identity DIDs per bridge instance is generous
/// for any single-process deployment.
const MAX_RATE_LIMITERS: usize = 1_000;

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

    /// Registered shutdown hooks for bridge-specific state cleanup.
    ///
    /// Each FFI bridge registers hooks that clear bridge-specific singletons
    /// (`IDENTITY_REGISTRY`, `FFI_BRIDGE_STATE`, `ECONOMY_BUDGETS`, etc.)
    /// during [`shutdown()`]. These singletons use bridge-specific types
    /// (e.g., `PyO3` `IdentityEntry` with `Arc<InMemoryKeyCustody>`) that
    /// cannot be owned by `BridgeInstance` because `scp-ffi-common` does not
    /// depend on PyO3/NAPI/UniFFI.
    ///
    /// Hooks are called exactly once during `shutdown()` and then discarded.
    /// The `Mutex` is only locked during `shutdown()` and `register_shutdown_hook()`
    /// — no contention on the hot path.
    shutdown_hooks: Mutex<Vec<Box<dyn FnOnce() + Send>>>,
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
            shutdown_hooks: Mutex::new(Vec::new()),
        }
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
    /// `BridgeInstance`-owned state has been cleared.
    ///
    /// Intended for bridge-specific singletons that use `OnceLock` and
    /// cannot be owned by `BridgeInstance` due to crate dependency
    /// boundaries (e.g., `PyO3` `IDENTITY_REGISTRY`, NAPI
    /// `BRIDGE_STATE`).
    ///
    /// If the internal `Mutex` is poisoned (a previous hook registration
    /// panicked while holding the lock), the hook is silently dropped and
    /// an error is logged.
    pub fn register_shutdown_hook(&self, hook: Box<dyn FnOnce() + Send>) {
        if self.is_shutdown() {
            // Already shut down — run the hook immediately since shutdown()
            // won't be called again.
            tracing::warn!("hook registered after shutdown — running immediately");
            hook();
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
        self.clear_transport()?;
        tracing::debug!(local_did = %self.local_did, "bridge instance suspended");
        Ok(())
    }

    /// Resumes a suspended bridge instance.
    ///
    /// Clears the suspended flag so bridge operations can proceed. The caller
    /// must re-establish the relay connection via `set_transport` — resume
    /// does not reconnect automatically because the relay URL is not stored
    /// in `BridgeInstance`.
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
    /// `BridgeInstance`-owned state has been cleared. This ensures that
    /// bridge-specific singletons (identity registries, FFI bridge state,
    /// economy trackers) are cleaned up during shutdown, releasing key
    /// material held by custody providers (zeroized via `Drop` when
    /// `Arc` refcount reaches zero).
    ///
    /// # Errors
    ///
    /// Returns `Err` if the transport `RwLock` is poisoned.
    pub fn shutdown(&self) -> Result<(), TransportLockError> {
        if self.shutdown.swap(true, Ordering::SeqCst) {
            return Ok(()); // Already shut down
        }

        // Clear transport (disconnect relay)
        self.clear_transport()?;

        // Remove all contexts from the ContextManager (MLS groups, sender
        // keys, event logs). Best-effort — already-removed contexts are
        // silently ignored.
        self.context_manager.shutdown_all_contexts();

        // Clear registries
        self.known_contexts.clear();
        self.rate_limiters.clear();

        // Run bridge-specific shutdown hooks (identity registries, FFI
        // bridge state, economy trackers). Drain the Vec so hooks are
        // called exactly once even if the Mutex isn't dropped.
        if let Ok(mut hooks) = self.shutdown_hooks.lock() {
            for hook in hooks.drain(..) {
                if let Err(e) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(hook)) {
                    tracing::error!("shutdown hook panicked: {e:?}");
                }
            }
        } else {
            tracing::error!("shutdown_hooks mutex poisoned — bridge-specific cleanup skipped");
        }

        // Also clear suspended flag (shutdown supersedes suspension)
        self.suspended.store(false, Ordering::SeqCst);

        tracing::debug!(local_did = %self.local_did, "bridge instance shut down");
        Ok(())
    }

    // -----------------------------------------------------------------
    // Transport accessors
    // -----------------------------------------------------------------

    /// Stores a new `TransportManager` (called after relay connect).
    ///
    /// Wraps the manager in `Arc` before storing so that async tasks (e.g.,
    /// NAPI subscription) can clone the `Arc` without keeping the `RwLock`
    /// guard alive across `.await` points.
    ///
    /// Replaces any previous transport manager.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the `RwLock` is poisoned.
    #[allow(clippy::significant_drop_tightening)]
    pub fn set_transport(
        &self,
        manager: scp_transport::TransportManager,
    ) -> Result<(), TransportLockError> {
        let mut guard = self
            .transport
            .write()
            .map_err(|_| TransportLockError::Poisoned)?;
        *guard = Some(Arc::new(manager));
        Ok(())
    }

    /// Stores a pre-built `Arc<TransportManager>`.
    ///
    /// Used by callers (e.g., NAPI server auto-wire) that construct the
    /// manager externally and wrap it in `Arc` before storing.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the `RwLock` is poisoned.
    #[allow(clippy::significant_drop_tightening)]
    pub fn set_transport_arc(
        &self,
        manager: Arc<scp_transport::TransportManager>,
    ) -> Result<(), TransportLockError> {
        let mut guard = self
            .transport
            .write()
            .map_err(|_| TransportLockError::Poisoned)?;
        *guard = Some(manager);
        Ok(())
    }

    /// Clears the transport manager (called on disconnect).
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
    #[must_use]
    pub const fn known_contexts(&self) -> &DashMap<String, KnownContext> {
        &self.known_contexts
    }

    /// Registers a known context in the discovery registry.
    ///
    /// Overwrites any existing entry for the same context ID (idempotent).
    /// When the registry is at capacity ([`MAX_KNOWN_CONTEXTS`]), evicts the
    /// oldest entry (by `last_seen` timestamp) before inserting.
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
    #[must_use]
    pub const fn rate_limiters(&self) -> &DashMap<String, RateLimitTracker> {
        &self.rate_limiters
    }

    /// Executes a closure with a mutable reference to the rate limit tracker
    /// for the given identity DID, creating a default tracker if none exists.
    ///
    /// When the registry is at capacity ([`MAX_RATE_LIMITERS`]) and the
    /// requested DID does not already have a tracker, uses a temporary
    /// ephemeral tracker that is not persisted. This preserves the infallible
    /// signature while preventing unbounded memory growth.
    pub fn with_rate_limit_tracker<F, T>(&self, identity_did: &str, f: F) -> T
    where
        F: FnOnce(&mut RateLimitTracker) -> T,
    {
        // If the entry already exists, serve it regardless of capacity.
        if let Some(mut entry) = self.rate_limiters.get_mut(identity_did) {
            return f(entry.value_mut());
        }
        // New entry: check capacity.
        if self.rate_limiters.len() >= MAX_RATE_LIMITERS {
            tracing::warn!(
                identity_did = %identity_did,
                capacity = MAX_RATE_LIMITERS,
                "rate limiter registry at capacity — using ephemeral tracker"
            );
            let mut ephemeral = RateLimitTracker::default();
            return f(&mut ephemeral);
        }
        let mut entry = self
            .rate_limiters
            .entry(identity_did.to_owned())
            .or_default();
        f(entry.value_mut())
    }
}

/// Error type for transport lock operations.
///
/// Used by [`BridgeInstance`] transport accessor methods. Bridge layers map
/// this to their own error types (`ScpPyError`, napi `Error`, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportLockError {
    /// The transport `RwLock` was poisoned (a writer panicked while holding it).
    Poisoned,
    /// No transport manager has been set (call `set_transport` first).
    NotInitialized,
    /// The transport manager `Arc` is in use by an active subscription task.
    /// Mutable access requires exclusive ownership (refcount == 1).
    InUse,
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
            Self::AlreadyShutDown => write!(f, "cannot resume a shut down instance"),
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
        instance.shutdown().unwrap();
        assert!(instance.is_shutdown());

        // Calling shutdown again is a no-op — still true
        instance.shutdown().unwrap();
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
    }

    // -----------------------------------------------------------------
    // Lifecycle tests (suspend / resume / shutdown)
    // -----------------------------------------------------------------

    #[test]
    fn suspend_clears_transport() {
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());
        instance.set_transport(test_transport_manager()).unwrap();
        assert!(instance.has_transport());

        instance.suspend().unwrap();

        assert!(!instance.has_transport());
        assert!(instance.is_suspended());
    }

    #[test]
    fn suspend_is_noop_when_shutdown() {
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());
        instance.shutdown().unwrap();

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
        instance.shutdown().unwrap();

        let err = instance.resume().unwrap_err();
        assert_eq!(err, LifecycleError::AlreadyShutDown);
        assert_eq!(err.to_string(), "cannot resume a shut down instance");
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

        instance.shutdown().unwrap();
        assert!(instance.is_shutdown());
        assert!(instance.known_contexts().is_empty());
        assert!(instance.rate_limiters().is_empty());

        // Second call is a no-op
        instance.shutdown().unwrap();
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

        instance.shutdown().unwrap();

        assert!(instance.known_contexts().is_empty());
        assert!(instance.rate_limiters().is_empty());
    }

    #[test]
    fn shutdown_clears_suspended_flag() {
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());
        instance.suspend().unwrap();
        assert!(instance.is_suspended());

        instance.shutdown().unwrap();
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
            "cannot resume a shut down instance"
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
        instance.shutdown().unwrap();
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
    fn rate_limiter_cap_uses_ephemeral() {
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());

        // Fill up to capacity.
        for i in 0..MAX_RATE_LIMITERS {
            instance.with_rate_limit_tracker(&format!("did:dht:z{i}"), |_| {});
        }
        assert_eq!(instance.rate_limiters().len(), MAX_RATE_LIMITERS);

        // Next new DID uses ephemeral — registry stays at capacity.
        let result = instance.with_rate_limit_tracker("did:dht:znew", |_| 42);
        assert_eq!(result, 42);
        assert_eq!(instance.rate_limiters().len(), MAX_RATE_LIMITERS);
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

        instance.shutdown().unwrap();

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

        instance.shutdown().unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        // Second shutdown is idempotent — hooks don't run again
        instance.shutdown().unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn register_hook_after_shutdown_does_not_run() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let instance = BridgeInstance::new(test_context_manager(), "did:dht:ztest".to_owned());

        instance.shutdown().unwrap();

        let ran = Arc::new(AtomicBool::new(false));
        let r = Arc::clone(&ran);

        // Registering after shutdown succeeds (no panic) but the hook
        // will never run because shutdown already completed.
        instance.register_shutdown_hook(Box::new(move || {
            r.store(true, Ordering::SeqCst);
        }));

        // Second shutdown is a no-op (already shut down)
        instance.shutdown().unwrap();
        assert!(!ran.load(Ordering::SeqCst));
    }
}
