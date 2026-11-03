//! Tests moved out of `scp-runtime-core` `context::supervisor::handle` (ADR-070 §6.2): they build a
//! `Supervisor`, which needs the domain handlers only `scp-runtime` assembles.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use scp_did::DID;
use scp_platform::in_memory::InMemoryStorage;
use scp_platform::testing::InMemoryKeyCustody;
use scp_protocol::context::ContextError;
use scp_runtime_core::context::supervisor::handle::*;
use scp_runtime_core::context::supervisor::key_package_actor::KeyPackageStoreActor;
use scp_runtime_core::context::supervisor::supervisor::Supervisor;
use scp_runtime_core::context::supervisor::supervisor::SupervisorConfig;
use scp_runtime_core::crypto::wrapping::test_wrapping_key;
use scp_runtime_types::context::supervisor::saga_journal::{
    ProtocolRepositorySagaJournal, SagaJournal,
};
use std::sync::Arc;

struct TestPersistence;
#[async_trait::async_trait]
impl scp_runtime_core::context::persistence::ContextPersistence for TestPersistence {
    async fn persist_context(
        &self,
        _: &str,
        _: &scp_runtime_core::context::state::ContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
    async fn load_context(
        &self,
        _: &str,
    ) -> Result<
        Option<scp_runtime_core::context::state::ContextSnapshot>,
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

fn test_handle() -> (Arc<Supervisor>, SupervisorHandle) {
    let persistence: Arc<dyn scp_runtime_core::context::persistence::ContextPersistence> =
        Arc::new(TestPersistence);
    let journal: Arc<dyn SagaJournal> = Arc::new(ProtocolRepositorySagaJournal::new(Arc::new(
        InMemoryStorage::new(),
    )));
    let sup = Arc::new(Supervisor::new(
        persistence,
        journal,
        SupervisorConfig::default(),
        scp_runtime::domain_handlers(),
    ));
    let handle = SupervisorHandle::wrap(&sup);
    (sup, handle)
}

/// ADR-049 Decision 16: the handle holds a `Weak<Supervisor>`, so it never
/// keeps the Supervisor alive.
#[tokio::test]
async fn handle_returns_supervisor_shut_down_after_owner_drops() {
    let (sup, handle) = test_handle();
    assert!(handle.local_dids().is_ok());
    drop(sup);

    let shut_down = |r: Result<(), ContextError>| {
        assert!(
            matches!(r, Err(ContextError::SupervisorShutDown(_))),
            "expected SupervisorShutDown, got {r:?}"
        );
    };
    shut_down(handle.local_dids().map(drop));
    shut_down(handle.lookup("ctx").map(drop));
    shut_down(handle.export_sender_key_epochs(&[7u8; 32]).map(drop));
    shut_down(handle.export_recv_sequence_floors(&[7u8; 32]).map(drop));
    shut_down(handle.seed_context_floors(&[7u8; 32]));
    shut_down(handle.is_context_poisoned("ctx").map(drop));
    shut_down(handle.find_shared_context("a", "b").await.map(drop));
    shut_down(handle.update_context_gauges());
    shut_down(handle.relay_contact_store().map(drop));
    shut_down(handle.spawn_tracked("probe", async {}).map(drop));
}

#[tokio::test]
async fn local_dids_returns_empty_snapshot_on_fresh_supervisor() {
    let (_sup, handle) = test_handle();
    assert!(handle.local_dids().unwrap().is_empty());
}

#[tokio::test]
async fn standing_peer_returns_none_when_unknown() {
    let (_sup, handle) = test_handle();
    let unknown = DID("did:example:never-registered".to_owned());
    assert!(handle.standing_peer(&unknown).unwrap().is_none());
}

/// Minimal event log provider: accepts every call (these tests never
/// touch the event log).
struct NoopEventLog;
#[async_trait::async_trait]
impl scp_runtime_core::context::builder::ContextEventLogProvider for NoopEventLog {
    fn event_log_entries(
        &self,
        _context_id: &[u8; 32],
    ) -> Result<Option<Vec<scp_event_log::Event>>, ContextError> {
        Ok(None)
    }
    async fn init_event_log(
        &self,
        _id: &[u8; 32],
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        Ok(())
    }
    async fn append_event(
        &self,
        _id: &[u8; 32],
        _event_type: scp_event_log::EventType,
        _actor: &str,
        _payload: scp_event_log::EventPayload,
        _timestamp_secs: u64,
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        Ok(())
    }
    async fn destroy_event_log(
        &self,
        _id: &[u8; 32],
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        Ok(())
    }
}

/// A provider-backed supervisor and the `ActorDeps` of one actor of
/// `owner`, built through the supervisor's own deps path: the only place
/// that mints the actor's `OwnedIdentityDid` (ADR-049 Decision 5). The
/// deps reach `SupervisorHandle::my_wrapping_key` through
/// `ActorDeps::my_wrapping_key`.
async fn owner_deps(
    owner: &DID,
) -> (
    Arc<Supervisor>,
    scp_runtime_core::context::actor::deps::ActorDeps,
) {
    let crypto = Arc::new(
        scp_runtime_core::crypto::mls::provider::NodeMlsFactory::new(
            owner.0.clone(),
            Arc::new(scp_clock::SystemClock),
        ),
    );
    let mls_storage: Arc<
        dyn scp_runtime_types::crypto::mls::storage_adapter::OpenMlsStorageAdapter,
    > = Arc::new(
        scp_runtime_types::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(
            Arc::new(InMemoryStorage::new()),
        ),
    );
    let sup = Supervisor::with_providers(
        crypto,
        Box::new(scp_runtime_core::context::builder::NotConfiguredTransportProvider),
        Box::new(NoopEventLog),
        Arc::new(|_, _| None),
        Some(Box::new(TestPersistence)),
        None,
        None,
        None,
        mls_storage,
        scp_runtime::domain_handlers(),
    );
    let deps = sup
        .build_actor_deps_loaded(owner)
        .await
        .expect("build_actor_deps");
    (sup, deps)
}

/// An identity with no loaded key gets a typed error, never a default key.
#[tokio::test]
async fn my_wrapping_key_fails_closed_when_unset() {
    let did = DID("did:example:alice".to_owned());
    let (sup, deps) = owner_deps(&did).await;
    sup.wrapping_keys_for_test().remove(&did);
    assert!(matches!(
        deps.my_wrapping_key(),
        Err(ContextError::InvalidState(_))
    ));
}

/// Once shutdown has begun, a missing key reports `SupervisorShutDown`,
/// because shutdown clears every key; a loaded key is still returned.
#[tokio::test]
async fn my_wrapping_key_reports_shutdown_after_the_gate_closes() {
    let alice = DID("did:example:alice".to_owned());
    let bob = DID("did:example:bob".to_owned());
    let (sup, alice_deps) = owner_deps(&alice).await;
    let bob_deps = sup.build_actor_deps_loaded(&bob).await.expect("bob deps");
    sup.wrapping_keys_for_test().remove(&bob);
    sup.close_spawn_gate();
    assert!(matches!(
        bob_deps.my_wrapping_key(),
        Err(ContextError::SupervisorShutDown(_))
    ));
    assert!(alice_deps.my_wrapping_key().is_ok());
}

/// The reader returns the identity's own key, never another identity's:
/// the same public point and the same custody handle as the installed key.
#[tokio::test]
async fn my_wrapping_key_reads_the_owner_slot() {
    let custody = Arc::new(InMemoryKeyCustody::new());
    let did = DID("did:example:alice".to_owned());
    let (sup, deps) = owner_deps(&did).await;
    let installed = test_wrapping_key(&custody).await.unwrap();
    let other = test_wrapping_key(&custody).await.unwrap();
    sup.wrapping_keys_for_test()
        .insert(did.clone(), Arc::clone(&installed));
    sup.wrapping_keys_for_test()
        .insert(DID("did:example:bob".to_owned()), Arc::clone(&other));
    let got = deps.my_wrapping_key().unwrap();
    assert_eq!(got.public(), installed.public());
    assert_eq!(got.handle(), installed.handle());
    assert_ne!(got.handle(), other.handle());
}

/// With the owner's slot empty the reader returns `None`, even while
/// another identity has a store registered.
#[tokio::test]
async fn my_key_package_store_returns_none_when_unset() {
    let alice = DID("did:example:alice".to_owned());
    let bob = DID("did:example:bob".to_owned());
    let (sup, alice_deps) = owner_deps(&alice).await;
    let _bob_deps = sup.build_actor_deps_loaded(&bob).await.expect("bob deps");
    sup.key_package_stores_for_test().remove(&alice);
    assert!(sup.key_package_stores_for_test().contains_key(&bob));
    assert!(alice_deps.my_key_package_store().unwrap().is_none());
}

#[tokio::test]
async fn my_key_package_store_returns_registered_handle() {
    use scp_runtime_core::context::supervisor::key_package_actor::KeyPackageStoreDeps;
    use scp_runtime_core::crypto::mls::provider::NodeMlsFactory;
    use scp_runtime_types::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter;

    let did = DID("did:dht:z6MkAliceKpStore".to_owned());
    let (sup, owner) = owner_deps(&did).await;
    let crypto = Arc::new(NodeMlsFactory::new(
        did.0.clone(),
        std::sync::Arc::new(scp_clock::SystemClock),
    ));
    let mls_storage: Arc<
        dyn scp_runtime_types::crypto::mls::storage_adapter::OpenMlsStorageAdapter,
    > = Arc::new(SpawnBlockingStorageAdapter::new(Arc::new(
        InMemoryStorage::new(),
    )));
    let transport: Arc<dyn scp_runtime_core::context::builder::ContextTransportProvider> =
        Arc::new(scp_runtime_core::context::builder::NotConfiguredTransportProvider);
    let clock: Arc<dyn scp_clock::Clock> = Arc::new(scp_clock::SystemClock);
    let deps = KeyPackageStoreDeps {
        mls: Arc::clone(crypto.mls_backend()),
        mls_storage,
        transport,
        clock,
        wrapping_key: test_wrapping_key(&Arc::new(InMemoryKeyCustody::new()))
            .await
            .unwrap(),
    };
    sup.key_package_stores_for_test().remove(&did);
    assert!(owner.my_key_package_store().unwrap().is_none());
    let (kp_handle, _join) = KeyPackageStoreActor::spawn(did.clone(), deps);
    sup.key_package_stores_for_test()
        .insert(did.clone(), kp_handle);
    let got = owner.my_key_package_store().unwrap();
    assert!(got.is_some());
    if let Some(h) = got {
        h.send_shutdown().await.unwrap();
    }
}
