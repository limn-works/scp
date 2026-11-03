//! Tests of the broadcast domain moved from `scp-runtime-core`
//! `context::supervisor::supervisor` (ADR-070 §6.1): they call a function private to this domain.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use scp_did::DID;
use scp_protocol::context::governance::KeyResolver;
use scp_runtime_core::context::actor::commands::BroadcastCommand;
use std::sync::Arc;

use scp_platform::in_memory::InMemoryStorage;
use scp_runtime_core::context::actor::signer::CommandSigner;
use scp_runtime_core::context::supervisor::supervisor::*;

// -----------------------------------------------------------------
// ADR-049 §15 — `spawn_actor_with_state` tests
// -----------------------------------------------------------------

/// Construct a minimal [`scp_runtime_core::context::actor::deps::ActorDeps`] for
/// the `spawn_actor_with_state` tests. Builds through the
/// supervisor's `build_actor_deps` path so we exercise real
/// construction rather than invent synthetic mocks.
async fn test_actor_deps(
    supervisor: &Arc<Supervisor>,
) -> scp_runtime_core::context::actor::deps::ActorDeps {
    supervisor
        .build_actor_deps_loaded(&DID("did:example:spawn-state-test".to_owned()))
        .await
        .expect("build_actor_deps requires providers populated")
}

/// A tiny `ContextEventLogProvider` that accepts every call and
/// returns empty data for every read. Exists only so
/// [`supervisor_with_providers`] can construct a supervisor with
/// minimal providers without dragging in the full mock stack from
/// the `tests/actor_*_shim.rs` integration harnesses.
struct TestEventLog;
#[async_trait::async_trait]
impl scp_runtime_core::context::builder::ContextEventLogProvider for TestEventLog {
    fn event_log_entries(
        &self,
        _context_id: &[u8; 32],
    ) -> Result<Option<Vec<scp_event_log::Event>>, scp_protocol::context::ContextError> {
        Ok(None)
    }

    async fn init_event_log(
        &self,
        _context_id: &[u8; 32],
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        Ok(())
    }
    async fn append_event(
        &self,
        _context_id: &[u8; 32],
        _event: scp_event_log::EventType,
        _actor_did: &str,
        _payload: scp_event_log::EventPayload,
        _timestamp_secs: u64,
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        Ok(())
    }
    async fn destroy_event_log(
        &self,
        _context_id: &[u8; 32],
    ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
        Ok(())
    }
}

/// Build a supervisor with minimal providers so
/// [`test_actor_deps`] can construct `ActorDeps` via the real
/// `build_actor_deps` path. The plain `test_supervisor` helper
/// above does NOT populate providers because its saga / lookup
/// tests do not need them.
fn supervisor_with_providers() -> Arc<Supervisor> {
    supervisor_with_providers_and_event_log(Box::new(TestEventLog))
}

/// [`supervisor_with_providers`] with a caller-supplied event-log provider,
/// for tests that assert what did (or did NOT) reach the durable event log
/// (e.g. via a [`RecordingEventLog`]).
fn supervisor_with_providers_and_event_log(
    event_log: Box<dyn scp_runtime_core::context::builder::ContextEventLogProvider>,
) -> Arc<Supervisor> {
    supervisor_with_event_log_and_resolver(
        event_log,
        Arc::new(|_: &DID, _: scp_did::SigningKeyId| None),
    )
}

fn supervisor_with_event_log_and_resolver(
    event_log: Box<dyn scp_runtime_core::context::builder::ContextEventLogProvider>,
    key_resolver: KeyResolver,
) -> Arc<Supervisor> {
    // Minimal providers — the spawn-registry tests only care about
    // the supervisor's actor map, not the providers' behaviour.
    // `NodeMlsFactory::new` takes a String DID; the stub DID is
    // never used by the spawn tests because no
    // `create_context` call runs.
    let crypto = Arc::new(
        scp_runtime_core::crypto::mls::provider::NodeMlsFactory::new(
            "did:dht:z6MktestDoNotRely".to_owned(),
            std::sync::Arc::new(scp_clock::SystemClock),
        ),
    );
    let transport: Box<dyn scp_runtime_core::context::builder::ContextTransportProvider> =
        Box::new(scp_runtime_core::context::builder::NotConfiguredTransportProvider);
    let mls_storage: Arc<
        dyn scp_runtime_types::crypto::mls::storage_adapter::OpenMlsStorageAdapter,
    > = Arc::new(
        scp_runtime_types::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(
            Arc::new(InMemoryStorage::new()),
        ),
    );
    Supervisor::with_providers(
        crypto,
        transport,
        event_log,
        key_resolver,
        None,
        None,
        None,
        None,
        mls_storage,
        crate::test_support::test_domain_handlers(),
    )
}

/// Two publishes through `dispatch_broadcast_command` each sign inside
/// the actor turn with the payload's `CommandSigner`, take consecutive
/// sequences, and produce envelopes whose signatures verify against the
/// signer's key.
#[tokio::test]
async fn publish_broadcast_dispatches_through_mailbox() {
    use scp_runtime_core::context::actor::commands::PublishBroadcastPayload;

    let supervisor_arc = supervisor_with_providers();
    let mut deps = test_actor_deps(&supervisor_arc).await;
    // The test supervisor's transport refuses sends; publish delivers
    // the sealed envelope, so this actor gets one that accepts them.
    deps.transport = Arc::new(scp_runtime_core::context::builder::LocalTransportProvider);

    let ctx_id_bytes = [0xC0u8; 32];
    let ctx_key = hex::encode(ctx_id_bytes);
    let author = DID("did:example:author".to_owned());

    // A broadcast-mode state with the author registered (so the
    // reservation passes) and present in membership (so the seal's
    // per-sender sequence resolves), in the Active state.
    let mut state =
        scp_runtime_core::context::actor::state::PerContextState::new_for_test_broadcast(
            ctx_id_bytes,
            1_700_000_000,
            DID("did:example:admin".to_owned()),
        );
    let mut bc = scp_protocol::context::broadcast::BroadcastContext::new(
        ctx_key.clone(),
        &scp_protocol::context::ContextMode::Broadcast,
        scp_protocol::context::broadcast::BroadcastAdmission::Open,
    )
    .expect("broadcast context constructs");
    bc.add_author(author.as_ref()).expect("author registers");
    state.broadcast_context = Some(bc);
    state
        .membership
        .add_member(author.clone(), "author".to_owned(), vec![]);
    state
        .handle
        .transition_to(&scp_protocol::context::ContextState::Active)
        .expect("transition to Active");

    let handle = supervisor_arc
        .spawn_actor_with_state_for_test(state, deps, None)
        .await
        .expect("spawn_actor_with_state: fresh context id registers");

    let signer = CommandSigner::local_ed25519(ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]));
    let verifying_key = signer.verifying_key().expect("Ed25519 signer");

    let mut envelopes = Vec::new();
    for body in [b"first".as_slice(), b"second".as_slice()] {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = BroadcastCommand::PublishBroadcast {
            payload: Box::new(PublishBroadcastPayload {
                context_id: ctx_key.clone(),
                author_did: author.clone(),
                payload: body.to_vec(),
                signer: signer.clone(),
            }),
            reply: tx,
        };
        supervisor_arc
            .dispatch_broadcast_command(cmd)
            .await
            .expect("mailbox dispatch succeeds");
        envelopes.push(rx.await.expect("publish reply").expect("publish succeeds"));
    }

    assert_eq!(
        envelopes[1].sequence,
        envelopes[0].sequence + 1,
        "the mailbox serializes publishes onto consecutive sequences",
    );
    for envelope in &envelopes {
        crate::helpers::check_envelope_signed_by(envelope, &verifying_key)
            .expect("each envelope verifies under the custody key");
    }

    handle.send_shutdown().await.expect("handle is live");
}

// =================================================================
// Watchdog / respawn / poison integration tests (ADR-049 §10).
//
// These spawn real state-bearing actors, induce panics via the
// testing-only `TestInducePanic` seam, and assert the watchdog's
// crash-budget, poison, respawn, and payload-redaction behaviour.
// They run on a multi-thread runtime so the watchdog task (spawned
// separately from the actor) makes progress, and inject a
// `TestClock` so the 60s crash window is driven deterministically.
// =================================================================
