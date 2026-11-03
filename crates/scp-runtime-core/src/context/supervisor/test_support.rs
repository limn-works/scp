//! Test Supervisors and fixtures shared by the runtime crates' tests (`testing`
//! only). Core names no domain crate, so each caller passes the
//! [`DomainHandlers`](crate::context::domains::DomainHandlers) it builds: the assembly crate passes `domain_handlers()`,
//! and a domain crate's tests pass their `test_support::test_domain_handlers()`.

use std::sync::Arc;

use crate::context::domains::DomainHandlers;

/// Builds a test [`Supervisor`](crate::context::supervisor::Supervisor) with
/// `domains` installed: the body behind `scp_runtime::test_supervisor` and each
/// domain crate's `test_support::test_supervisor`.
///
/// # Non-production
///
/// `persistence`, `payment_adapter`, `event_tx`, and `clock` are `None` (no-op
/// persistence and a `SystemClock`). The required `mls_storage` provider is an
/// in-memory backend, a test-only opt-in; production bridges supply a real
/// `Storage`. Tests that exercise any of those surfaces build their own
/// Supervisor with `Supervisor::with_providers`.
#[must_use]
pub fn test_supervisor_with_domains(
    crypto: Arc<crate::crypto::mls::provider::NodeMlsFactory>,
    transport: Box<dyn crate::context::builder::ContextTransportProvider>,
    event_log: Box<dyn crate::context::builder::ContextEventLogProvider>,
    key_resolver: scp_protocol::context::governance::KeyResolver,
    domains: DomainHandlers,
) -> Arc<crate::context::supervisor::Supervisor> {
    let mls_storage: Arc<
        dyn scp_runtime_types::crypto::mls::storage_adapter::OpenMlsStorageAdapter,
    > = Arc::new(
        scp_runtime_types::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(
            Arc::new(scp_platform::in_memory::InMemoryStorage::new()),
        ),
    );
    crate::context::supervisor::Supervisor::with_providers(
        crypto,
        transport,
        event_log,
        key_resolver,
        None,
        None,
        None,
        None,
        mls_storage,
        domains,
    )
}

/// A Supervisor the test can drop while keeping the `ActorDeps` built from it.
///
/// It serves the paths that must fail closed after the Supervisor drops (ADR-049
/// Decision 16): no floor export exists, so nothing is persisted and the caller
/// gets [`ContextError::SupervisorShutDown`](scp_protocol::context::ContextError::SupervisorShutDown).
pub mod dropped_supervisor {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use scp_did::DID;
    use scp_protocol::context::ContextError;
    use scp_protocol::context::builder::ContextCreationError;

    use crate::context::actor::deps::ActorDeps;
    use crate::context::actor::state::PerContextState;
    use crate::context::domains::DomainHandlers;
    use crate::context::supervisor::supervisor::Supervisor;

    /// The DID that owns the fixture context and builds its `ActorDeps`.
    pub const OWNER: &str = "did:example:dropped-supervisor-owner";
    /// The byte the fixture context id repeats.
    pub const CTX_BYTE: u8 = 0x5d;

    /// Persistence counting every `persist_context` call.
    struct CountingPersistence(Arc<AtomicUsize>);
    #[async_trait::async_trait]
    impl crate::context::persistence::ContextPersistence for CountingPersistence {
        async fn persist_context(
            &self,
            _: &str,
            _: &crate::context::state::ContextSnapshot,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        async fn load_context(
            &self,
            _: &str,
        ) -> Result<
            Option<crate::context::state::ContextSnapshot>,
            Box<dyn std::error::Error + Send + Sync>,
        > {
            Ok(None)
        }
        async fn delete_context(
            &self,
            _: &str,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
        async fn list_persisted_contexts(
            &self,
        ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(Vec::new())
        }
    }

    /// Event log counting every `append_event` call.
    struct CountingEventLog(Arc<AtomicUsize>);
    #[async_trait::async_trait]
    impl crate::context::builder::ContextEventLogProvider for CountingEventLog {
        fn event_log_entries(
            &self,
            _context_id: &[u8; 32],
        ) -> Result<Option<Vec<scp_event_log::Event>>, scp_protocol::context::ContextError>
        {
            Ok(None)
        }

        async fn init_event_log(&self, _: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        async fn append_event(
            &self,
            _: &[u8; 32],
            _event_type: scp_event_log::EventType,
            _actor_did: &str,
            _payload: scp_event_log::EventPayload,
            _timestamp_secs: u64,
        ) -> Result<(), ContextCreationError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        async fn destroy_event_log(&self, _: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
    }

    /// The owning `Arc<Supervisor>` (not leaked, so a test can drop it), the
    /// `ActorDeps` built from it, and the persist and event-append counters.
    pub struct Fixture {
        supervisor: Option<Arc<Supervisor>>,
        /// The `ActorDeps` for [`OWNER`], built while the Supervisor was live.
        pub deps: ActorDeps,
        /// The number of `persist_context` calls.
        pub persists: Arc<AtomicUsize>,
        /// The number of `append_event` calls.
        pub appends: Arc<AtomicUsize>,
    }

    impl Fixture {
        /// Builds a Supervisor with counting persistence and event log, a
        /// `TestClock`, an in-memory MLS store and `domains`, and the
        /// `ActorDeps` for [`OWNER`].
        ///
        /// # Errors
        ///
        /// The error of `Supervisor::build_actor_deps_loaded`.
        pub async fn new(domains: DomainHandlers) -> Result<Self, ContextError> {
            use scp_platform::in_memory::InMemoryStorage;

            let persists = Arc::new(AtomicUsize::new(0));
            let appends = Arc::new(AtomicUsize::new(0));
            let crypto = Arc::new(crate::crypto::mls::provider::NodeMlsFactory::new(
                OWNER.to_owned(),
                Arc::new(scp_clock::SystemClock),
            ));
            let mls_storage: Arc<
                dyn scp_runtime_types::crypto::mls::storage_adapter::OpenMlsStorageAdapter,
            > = Arc::new(
                scp_runtime_types::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(
                    Arc::new(InMemoryStorage::new()),
                ),
            );
            let clock: Arc<dyn scp_clock::Clock> =
                Arc::new(scp_clock::TestClock::new(1_700_000_000));
            let key_resolver: scp_protocol::context::governance::KeyResolver =
                Arc::new(|_, _| None);
            let supervisor = Supervisor::with_providers(
                crypto,
                Box::new(crate::context::builder::NotConfiguredTransportProvider),
                Box::new(CountingEventLog(Arc::clone(&appends))),
                key_resolver,
                Some(Box::new(CountingPersistence(Arc::clone(&persists)))),
                None,
                None,
                Some(clock),
                mls_storage,
                domains,
            );
            let deps = supervisor
                .build_actor_deps_loaded(&DID(OWNER.to_owned()))
                .await?;
            Ok(Self {
                supervisor: Some(supervisor),
                deps,
                persists,
                appends,
            })
        }

        /// Drops the owning `Arc` and asserts the Supervisor is gone, so a test
        /// cannot pass against a Supervisor that another reference keeps alive.
        ///
        /// # Panics
        ///
        /// When the Supervisor was already dropped, or another reference keeps
        /// it alive.
        #[must_use]
        pub fn drop_supervisor(mut self) -> Self {
            let supervisor = self.supervisor.take();
            assert!(supervisor.is_some(), "supervisor not yet dropped");
            let weak = supervisor.as_ref().map(Arc::downgrade);
            drop(supervisor);
            assert!(
                weak.is_some_and(|w| w.upgrade().is_none()),
                "the Supervisor must have dropped"
            );
            self
        }
    }

    /// An encrypted per-context state for context `[CTX_BYTE; 32]`, owned by [`OWNER`].
    #[must_use]
    pub fn state() -> PerContextState {
        PerContextState::new_for_test_encrypted(
            [CTX_BYTE; 32],
            1_700_000_000,
            DID(OWNER.to_owned()),
        )
    }

    /// The hex context id of [`state`].
    #[must_use]
    pub fn ctx_hex() -> String {
        hex::encode([CTX_BYTE; 32])
    }

    /// Asserts `r` is [`ContextError::SupervisorShutDown`].
    ///
    /// # Panics
    ///
    /// When `r` is anything else.
    pub fn assert_shut_down<T: std::fmt::Debug>(r: &Result<T, ContextError>) {
        assert!(
            matches!(r, Err(ContextError::SupervisorShutDown(_))),
            "expected SupervisorShutDown, got {r:?}"
        );
    }
}
