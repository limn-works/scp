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
//! instance holds its own `ContextManager`, local DID, and shutdown flag.
//! Multiple instances can coexist for different identities or test scenarios.
//!
//! # Migration
//!
//! This is the minimal foundation (Chunk 1 of the bridge dedup plan, #1549).
//! Additional fields (identity registry, transport manager, per-context FFI
//! state, rate limiters, economy state) will be added as bridges are migrated
//! in Chunks 2-4. The existing `OnceLock` singletons remain operational and
//! are not touched by this change.
//!
//! # Thread Safety
//!
//! `BridgeInstance` is `Send + Sync`. The `ContextManager` is behind `Arc`
//! (interior `RwLock`/`DashMap`). The shutdown flag uses `AtomicBool` with
//! `Ordering::SeqCst` for visibility across threads.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use scp_core::context::ContextManager;

/// A self-contained bridge instance replacing process-global `OnceLock` singletons.
///
/// Each instance holds its own [`ContextManager`], local DID, and shutdown
/// flag. Multiple instances can coexist (different identities, test
/// isolation). Mobile platforms use `shutdown()` for lifecycle cleanup.
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
}

impl BridgeInstance {
    /// Creates a new bridge instance.
    ///
    /// # Arguments
    ///
    /// - `context_manager` — the shared `ContextManager` that owns context
    ///   lifecycle state (MLS groups, membership, governance, broadcast).
    /// - `local_did` — the DID this instance operates as. Passed through to
    ///   `MlsCryptoProvider` for MLS credential identity.
    #[must_use]
    pub const fn new(context_manager: Arc<ContextManager>, local_did: String) -> Self {
        Self {
            context_manager,
            local_did,
            shutdown: AtomicBool::new(false),
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
}

#[cfg(test)]
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
}
