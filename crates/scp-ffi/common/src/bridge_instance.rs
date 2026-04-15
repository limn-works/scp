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
//! `ECONOMY_BUDGETS`, `ECONOMY_ANTISPAM`) remain as per-bridge `OnceLock`s until
//! subsequent migration steps.
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
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};

use dashmap::DashMap;
use scp_core::context::ContextManager;
use scp_protocol::context::invitation::RateLimitTracker;

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

    /// Whether this instance has been shut down.
    ///
    /// Uses `SeqCst` ordering for cross-thread visibility. Once set to `true`,
    /// all subsequent bridge operations should return an error immediately.
    shutdown: AtomicBool,

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
            transport: RwLock::new(None),
            known_contexts: DashMap::new(),
            rate_limiters: DashMap::new(),
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

    /// Whether this instance has been shut down.
    ///
    /// Bridge operations should check this before proceeding and return
    /// an appropriate error if `true`.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    /// Marks this instance as shut down.
    ///
    /// All subsequent calls to `is_shutdown()` will return `true`. This is
    /// a one-way transition — there is no `resume()`. A shut-down instance
    /// should be dropped and a new one created if the bridge needs to restart.
    ///
    /// This does NOT drop the `ContextManager` or close any MLS groups.
    /// Callers should perform cleanup (close contexts, drop transport, etc.)
    /// before or after calling `shutdown()`.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    // -----------------------------------------------------------------
    // Transport accessors
    // -----------------------------------------------------------------

    /// Returns a reference to the transport `RwLock`.
    ///
    /// Callers acquire a read or write lock as needed. Prefer the convenience
    /// methods ([`set_transport`], [`clear_transport`], [`with_transport`],
    /// [`with_transport_mut`]) for common patterns.
    #[must_use]
    pub const fn transport_lock(&self) -> &RwLock<Option<Arc<scp_transport::TransportManager>>> {
        &self.transport
    }

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
        let guard = self
            .transport
            .read()
            .map_err(|_| TransportLockError::Poisoned)?;
        let manager = guard.as_deref().ok_or(TransportLockError::NotInitialized)?;
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
        let mut guard = self
            .transport
            .write()
            .map_err(|_| TransportLockError::Poisoned)?;
        let arc = guard.as_mut().ok_or(TransportLockError::NotInitialized)?;
        let manager = Arc::get_mut(arc).ok_or(TransportLockError::InUse)?;
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
    pub fn register_known_context(&self, context_id: &str, known: KnownContext) {
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
    pub fn with_rate_limit_tracker<F, T>(&self, identity_did: &str, f: F) -> T
    where
        F: FnOnce(&mut RateLimitTracker) -> T,
    {
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
        match self {
            Self::Poisoned => write!(f, "transport manager lock poisoned"),
            Self::NotInitialized => {
                write!(f, "no transport manager — call transport_connect first")
            }
            Self::InUse => write!(
                f,
                "transport manager is in use by an active subscription — \
                 cannot modify while subscriptions are active"
            ),
        }
    }
}

impl std::error::Error for TransportLockError {}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use scp_core::context::LocalTransportProvider;
    use scp_core::context::builder::{
        ContextCreationError, ContextCryptoProvider, ContextEventLogProvider,
    };
    use scp_core::context::{AddMemberOutput, ContextError, RemoveMemberOutput};

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
            "transport manager lock poisoned"
        );
        assert_eq!(
            TransportLockError::NotInitialized.to_string(),
            "no transport manager \u{2014} call transport_connect first"
        );
        assert_eq!(
            TransportLockError::InUse.to_string(),
            "transport manager is in use by an active subscription \u{2014} \
             cannot modify while subscriptions are active"
        );
    }
}
