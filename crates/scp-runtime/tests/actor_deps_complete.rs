//! Integration test for the ADR-049 commit-12a.5 `ActorDeps` expansion.
//!
//! Asserts that
//! [`Supervisor::build_actor_deps`](scp_runtime::context::supervisor::Supervisor::build_actor_deps)
//! populates **every** field of
//! [`ActorDeps`](scp_runtime::context::actor::ActorDeps) from the
//! supervisor's directly-owned providers (post commit-12 — there is no
//! `ContextManager` to attach).
//!
//! No handler body migration happens in commit 12a.5 — the deps bundle
//! is wired but not yet consumed by `MutationStateView`-based handlers (the adapter was deleted in commit 12c.7).
//! This test is the mechanical check that the wiring is correct so
//! commit 12b can move call sites onto `deps.X` one submodule at a
//! time without discovering missing fields mid-migration.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::doc_markdown,
    clippy::disallowed_types,
    clippy::missing_const_for_fn
)]

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use scp_identity::DID;
use scp_platform::testing::InMemoryStorage;
use scp_protocol::context::ContextError;
use scp_protocol::context::builder::ContextCreationError;
use scp_protocol::context::governance::KeyResolver;
use scp_protocol::context::membership::ContextEvent;
use scp_protocol::context::params::ContextParams;
use scp_runtime::context::persistence::ContextPersistence;
use scp_runtime::context::supervisor::Supervisor;
use scp_runtime::crypto::mls::provider::MlsCryptoProvider;

// ---------------------------------------------------------------------------
// Mocks (same shape as actor_tools_shim.rs fixtures)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct TransportCaptures(Mutex<Vec<([u8; 32], Vec<u8>)>>);
struct MockTransport {
    captures: Arc<TransportCaptures>,
    connected: AtomicBool,
}
impl MockTransport {
    fn new(c: Arc<TransportCaptures>) -> Self {
        Self {
            captures: c,
            connected: AtomicBool::new(true),
        }
    }
}
impl scp_runtime::context::builder::ContextTransportProvider for MockTransport {
    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }
    fn publish_context(&self, _: &[u8; 32], _: &ContextParams) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn delete_published(&self, _: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn send_message(&self, id: &[u8; 32], p: &[u8]) -> Result<(), ContextError> {
        self.captures.0.lock().unwrap().push((*id, p.to_vec()));
        Ok(())
    }
}

#[derive(Default)]
struct MockEventLog;
impl scp_runtime::context::builder::ContextEventLogProvider for MockEventLog {
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

struct NoopPersistence;
impl ContextPersistence for NoopPersistence {
    fn persist_context(
        &self,
        _: &str,
        _: &scp_runtime::context::state::ContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
    fn load_context(
        &self,
        _: &str,
    ) -> Result<
        Option<scp_runtime::context::state::ContextSnapshot>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        Ok(None)
    }
    fn persist_broadcast(
        &self,
        _: &str,
        _: &scp_protocol::context::broadcast::BroadcastContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
    fn load_broadcast(
        &self,
        _: &str,
    ) -> Result<
        Option<scp_protocol::context::broadcast::BroadcastContextSnapshot>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        Ok(None)
    }
    fn delete_context(&self, _: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
    fn list_persisted_contexts(
        &self,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Vec::new())
    }
}

fn mock_key_resolver() -> KeyResolver {
    Arc::new(|did| {
        let mut s = [0u8; 32];
        for (i, b) in did.as_ref().as_bytes().iter().enumerate() {
            s[i % 32] ^= *b;
        }
        Some(ed25519_dalek::SigningKey::from_bytes(&s).verifying_key())
    })
}

/// Fixture — a fully-wired `Supervisor` with providers populated and an
/// event channel attached. Returns the supervisor along with a
/// pre-subscribed receiver so the caller can witness `event_tx`
/// propagation through `ActorDeps`.
fn new_fixture() -> (
    Arc<Supervisor>,
    tokio::sync::broadcast::Receiver<(String, ContextEvent)>,
) {
    let captures = Arc::new(TransportCaptures::default());
    let crypto = Arc::new(MlsCryptoProvider::new(
        "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_owned(),
    ));
    let transport: Box<dyn scp_runtime::context::builder::ContextTransportProvider> =
        Box::new(MockTransport::new(Arc::clone(&captures)));
    let event_log: Box<dyn scp_runtime::context::builder::ContextEventLogProvider> =
        Box::new(MockEventLog);
    let (event_tx, event_rx) = tokio::sync::broadcast::channel(16);
    let supervisor = Supervisor::with_providers(
        crypto,
        transport,
        event_log,
        mock_key_resolver(),
        None,
        None,
        Some(event_tx),
        None,
    );
    (supervisor, event_rx)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Every `ActorDeps` field populates from the supervisor + the
/// caller-supplied backends. Baseline "no panic, no missing field"
/// assertion.
#[tokio::test]
async fn build_actor_deps_populates_every_field() {
    let (supervisor, mut event_rx) = new_fixture();

    let persistence: Arc<dyn ContextPersistence> = Arc::new(NoopPersistence);
    let mls: Arc<dyn scp_runtime::crypto::mls::backend::MlsBackend> =
        Arc::new(scp_runtime::crypto::mls::production_backend::ProductionMlsBackend::new());
    let hpke: Arc<dyn scp_runtime::crypto::hpke_backend::HpkeBackend> =
        Arc::new(scp_runtime::crypto::hpke_backend::ProductionHpkeBackend::new());
    let mls_storage: Arc<dyn scp_runtime::crypto::mls::storage_adapter::OpenMlsStorageAdapter> =
        Arc::new(
            scp_runtime::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
                InMemoryStorage::new(),
            )),
        );
    let kp_store = scp_runtime::context::supervisor::KeyPackageStoreActor::spawn(DID::from(
        "did:example:alice",
    ));

    let deps = supervisor
        .build_actor_deps(
            Arc::clone(&persistence),
            Arc::clone(&mls),
            Arc::clone(&hpke),
            Arc::clone(&mls_storage),
            kp_store.clone(),
        )
        .await
        .expect("build_actor_deps should succeed when providers are populated");

    // 8 existing fields — witness by downcast-free usage patterns.
    assert!(
        deps.transport.is_connected(),
        "transport field must populate and reflect the mock's connected state"
    );
    // persistence, event_log, mls, hpke, mls_storage — witness by Arc
    // pointer equality with the inputs we passed in (for the ones we
    // supplied) and non-empty trait-object for the ones sourced from
    // the supervisor.
    assert!(
        Arc::ptr_eq(&deps.persistence, &persistence),
        "persistence field must be the exact Arc the caller supplied"
    );
    assert!(
        Arc::ptr_eq(&deps.mls, &mls),
        "mls field must be the exact Arc the caller supplied"
    );
    assert!(
        Arc::ptr_eq(&deps.hpke, &hpke),
        "hpke field must be the exact Arc the caller supplied"
    );
    assert!(
        Arc::ptr_eq(&deps.mls_storage, &mls_storage),
        "mls_storage field must be the exact Arc the caller supplied"
    );

    // supervisor handle — accessors are the capability-reduced surface
    // (no ContextActorHandle leak). `local_dids()` returns the current
    // supervisor's snapshot; fresh supervisor has an empty set.
    assert!(
        deps.supervisor.local_dids().is_empty(),
        "fresh supervisor exposes empty local_dids snapshot through the handle"
    );
    assert!(
        deps.supervisor.standing_peer("never-registered").is_none(),
        "fresh supervisor exposes empty standing_contexts through the handle"
    );

    // key_package_store — witness by successful shutdown send (handle
    // is live and connected to the actor task).
    kp_store.send_shutdown().await.unwrap();

    // New 12a.5 fields.

    // `clock` — `Arc<dyn scp_primitives::Clock>`. The supervisor's
    // default is `SystemClock`; assert a sensible wall-clock value.
    let seconds_since_epoch = deps.clock.now_secs();
    assert!(
        seconds_since_epoch > 1_700_000_000,
        "clock field must populate and return a sensible wall-clock value \
         (got {seconds_since_epoch})"
    );
    let millis_since_epoch = deps.clock.now_millis();
    assert!(
        millis_since_epoch >= seconds_since_epoch * 1000,
        "clock.now_millis should be >= now_secs * 1000 (got secs={seconds_since_epoch}, \
         ms={millis_since_epoch})"
    );

    // `event_tx` — the Sender half the supervisor is holding. Cloneable
    // (Arc inside). Verify it's the SAME broadcast channel as the
    // supervisor's by sending on the ActorDeps copy and observing the
    // pre-subscribed receiver.
    let tx = deps
        .event_tx
        .as_ref()
        .expect("event_tx must populate — fixture passed Some(event_tx) to with_providers");
    let probe = (
        "probe-ctx".to_owned(),
        ContextEvent::MemberLeft {
            member_did: DID::from("did:example:probe"),
        },
    );
    tx.send(probe.clone())
        .expect("send through ActorDeps.event_tx should reach receivers subscribed on supervisor");
    let received = event_rx
        .try_recv()
        .expect("receiver subscribed on the supervisor must observe the ActorDeps.event_tx send");
    assert_eq!(
        received, probe,
        "event_tx must be the same broadcast channel as the supervisor's — round-trip check"
    );

    // `key_resolver` — `Arc<dyn Fn(&DID) -> Option<VerifyingKey> + ..>`.
    // The mock resolver returns a signing-key-derived verifying key for
    // every DID.
    let resolved = (deps.key_resolver)(&DID::from("did:example:alice"));
    assert!(
        resolved.is_some(),
        "key_resolver field must populate — mock returns Some for any DID"
    );

    // `payment_adapter` — not configured in the fixture → `None` from
    // the supervisor. Witness by `Option::is_none`.
    assert!(
        deps.payment_adapter.is_none(),
        "payment_adapter must populate as `None` when the supervisor has no adapter configured"
    );

    // `local_dids` — wired from the supervisor's authoritative snapshot.
    // Fresh supervisor has an empty set; witness by loading the
    // snapshot.
    assert!(
        deps.local_dids.load().is_empty(),
        "local_dids must populate — fresh supervisor starts with empty set"
    );
}

/// `build_actor_deps` fails clean if the supervisor was constructed via
/// `for_query_shim()` (no providers populated).
#[tokio::test]
async fn build_actor_deps_fails_when_no_providers() {
    let supervisor = Arc::new(Supervisor::for_query_shim());

    let persistence: Arc<dyn ContextPersistence> = Arc::new(NoopPersistence);
    let mls: Arc<dyn scp_runtime::crypto::mls::backend::MlsBackend> =
        Arc::new(scp_runtime::crypto::mls::production_backend::ProductionMlsBackend::new());
    let hpke: Arc<dyn scp_runtime::crypto::hpke_backend::HpkeBackend> =
        Arc::new(scp_runtime::crypto::hpke_backend::ProductionHpkeBackend::new());
    let mls_storage: Arc<dyn scp_runtime::crypto::mls::storage_adapter::OpenMlsStorageAdapter> =
        Arc::new(
            scp_runtime::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
                InMemoryStorage::new(),
            )),
        );
    let kp_store =
        scp_runtime::context::supervisor::KeyPackageStoreActor::spawn(DID::from("did:example:a"));

    let result = supervisor
        .build_actor_deps(persistence, mls, hpke, mls_storage, kp_store.clone())
        .await;
    // `ActorDeps` does not impl `Debug`, so we cannot use `expect_err`
    // — match on the Result shape explicitly.
    match result {
        Ok(_) => panic!("build_actor_deps must fail when supervisor has no providers"),
        Err(ContextError::NotInitialized(_)) => {}
        Err(other) => panic!("expected NotInitialized, got {other:?}"),
    }

    kp_store.send_shutdown().await.unwrap();
}

/// `ActorDeps.supervisor` is backed by the same `Arc<Supervisor>` as
/// the caller's — not a fresh `for_query_shim()` throwaway. Witness by
/// `Arc::strong_count`: cloning the outer supervisor Arc via the
/// build path must bump the refcount.
///
/// Regression guard for the `self: &Arc<Self>` receiver choice on
/// `build_actor_deps`. If the body switched to
/// `Arc::new(Supervisor::for_query_shim())`, `strong_count(&supervisor)`
/// would NOT increase when the handle is constructed.
#[tokio::test]
async fn supervisor_handle_holds_outer_arc_not_throwaway() {
    let (supervisor, _event_rx) = new_fixture();

    let count_before = Arc::strong_count(&supervisor);

    let persistence: Arc<dyn ContextPersistence> = Arc::new(NoopPersistence);
    let mls: Arc<dyn scp_runtime::crypto::mls::backend::MlsBackend> =
        Arc::new(scp_runtime::crypto::mls::production_backend::ProductionMlsBackend::new());
    let hpke: Arc<dyn scp_runtime::crypto::hpke_backend::HpkeBackend> =
        Arc::new(scp_runtime::crypto::hpke_backend::ProductionHpkeBackend::new());
    let mls_storage: Arc<dyn scp_runtime::crypto::mls::storage_adapter::OpenMlsStorageAdapter> =
        Arc::new(
            scp_runtime::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
                InMemoryStorage::new(),
            )),
        );
    let kp_store = scp_runtime::context::supervisor::KeyPackageStoreActor::spawn(DID::from(
        "did:example:alice",
    ));

    let deps = supervisor
        .build_actor_deps(persistence, mls, hpke, mls_storage, kp_store.clone())
        .await
        .unwrap();

    let count_after = Arc::strong_count(&supervisor);
    assert!(
        count_after > count_before,
        "SupervisorHandle must hold a clone of the OUTER supervisor Arc \
         (strong_count {count_before} → {count_after} after build). If the \
         body constructed a throwaway `for_query_shim()` supervisor, the \
         count would not change."
    );

    // Handle observes the outer supervisor's state (empty by default).
    assert!(deps.supervisor.local_dids().is_empty());

    kp_store.send_shutdown().await.unwrap();
}
