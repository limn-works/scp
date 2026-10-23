//! Push-wake pull mode (ADR-029 §2, `.docs/adrs/phase-6.md`), the wake
//! ADR-025 criterion 4 and ADR-027 criterion 10 run on a silent push, against
//! a real native relay and two full-stack members (real MLS, real sender keys,
//! real Supervisor).
//!
//! Alice seals an application message through her actor; the test publishes
//! the sealed bytes to the relay exactly as `RelayTransportProvider` does
//! (one outer envelope per fan-out routing ID, the sealed bytes as its
//! `encrypted_blob`). Bob's bridge core then handles a wake through
//! `scp_ffi_common::push::handle_wake`, which dials a transient transport,
//! pulls, and feeds his actor.
//!
//! Coverage:
//! - one envelope at Bob's pseudonym routing ID gives `NewData`, a
//!   `MessageReceived` event, and a `last_relay_contact` write;
//! - nothing buffered gives `NoData`;
//! - an unreachable relay, and a relay that accepts the WebSocket upgrade and
//!   never answers QUERY, each give `Failed` within the wake deadline;
//! - an invalid payload for each platform gives `SCP-TRANS-5080` with no
//!   connection opened;
//! - a cold start (no resident context, no `connect`) restores and gives
//!   `NewData`; the woken device publishes nothing and `needs_reconnect`
//!   stays set;
//! - a cold start whose restore fails gives `Failed`, not `NoData`;
//! - the second wake's QUERY `since` is the stored contact minus 5 seconds;
//! - a refused re-feed is not counted;
//! - a full reconnection that clears `needs_reconnect` writes the contact.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use scp_core::context::ContextState;
use scp_core::context::membership::ContextEvent;
use scp_core::context::params::{ContextMode, ContextParams};
use scp_core::context::roles::Capability;
use scp_core::context::supervisor::Supervisor;
use scp_core::envelope::OuterEnvelope;
use scp_core::store::ProtocolRepository;
use scp_core::store::sync::RelayContactStore;
use scp_core::sync::SyncPolicy;
use scp_did::DID;
use scp_ffi_common::bridge_instance::CoreFields;
use scp_ffi_common::push::{WAKE_DEADLINE, WakeFailure, WakeOutcome, handle_wake};
use scp_platform::in_memory::InMemoryStorage;
use scp_protocol::discovery::push::PushPlatform;
use scp_testing::fullstack::{FullStackNetwork, FullStackNode};
use scp_transport::TransportError;
use scp_transport::TransportManager;
use scp_transport::native::adapter::NativeRelayAdapter;
use scp_transport::native::server::{RelayConfig, RelayServer, ShutdownHandle};
use scp_transport::native::storage::BlobStorageBackend;
use scp_transport::relay::connection::{RelayUrlSource, SourcedRelayUrl};
use scp_transport::traits::{BlobId, RoutingId, SubscriptionStream, TransportAdapter};

const ALICE_DID: &str = "did:dht:z6MkAlicePushWake";
const BOB_DID: &str = "did:dht:z6MkBobPushWake";
const PLAINTEXT: &[u8] = b"wake me up";
const APNS_WAKE: &[u8] = br#"{"aps":{"content-available":1}}"#;

type Contacts = Arc<ProtocolRepository<InMemoryStorage>>;

fn encrypted_params() -> ContextParams {
    ContextParams {
        mode: ContextMode::Encrypted,
        ceiling: vec![
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::RoleAssign,
            Capability::MemberInvite,
            Capability::MemberRemove,
            Capability::GovernancePropose,
            Capability::GovernanceVote,
            Capability::ContextClose,
        ],
        ..ContextParams::default()
    }
}

fn now_secs() -> u64 {
    scp_clock::Clock::now_secs(&scp_clock::SystemClock)
}

/// Starts an ephemeral native relay; returns its handle and `ws://` URL.
async fn start_relay() -> (ShutdownHandle, String) {
    let config = RelayConfig {
        bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        delivery_jitter_ms: 0,
        ..RelayConfig::defaults(scp_transport::relay::push_gate::LiveRelayUrl::new(
            scp_transport::relay::push_gate::RelayUrl::new("ws://127.0.0.1:9000/scp/v1").unwrap(),
        ))
    };
    let server = RelayServer::new(config, Arc::new(BlobStorageBackend::in_memory()));
    let (handle, addr) = server.start().await.unwrap();
    (handle, format!("ws://{addr}/scp/v1"))
}

async fn connect(url: &str) -> NativeRelayAdapter {
    NativeRelayAdapter::connect_sourced(
        &SourcedRelayUrl {
            url: url.to_owned(),
            source: RelayUrlSource::DhtResolved,
        },
        None,
    )
    .await
    .expect("relay adapter connect")
}

/// Alice and Bob in one encrypted context that `relay_urls` host. Bob is an
/// observed node, so his supervisor persists snapshots a restart can read.
struct Members {
    _network: FullStackNetwork,
    alice: FullStackNode,
    bob: FullStackNode,
    handle: scp_core::context::ContextHandle,
    ctx_id: String,
    bob_pseudonym: [u8; 32],
}

async fn members(ctx_id: &str, relay_urls: Vec<String>) -> Members {
    let network = FullStackNetwork::new();
    let alice = network.create_node(ALICE_DID);
    let bob = network.create_observed_node(BOB_DID);
    let ctx_bytes = scp_core::context::context_id_bytes(ctx_id);
    let handle = alice
        .create_context_hosted(ctx_id, encrypted_params(), relay_urls)
        .await
        .unwrap();
    assert_eq!(handle.state(), ContextState::Active);
    alice.add_member(&handle, BOB_DID).await.unwrap();
    bob.join_from_welcome(ctx_id, &ctx_bytes).await.unwrap();
    // Alice addresses application data to Bob's real §9.10.4 pseudonym.
    let bob_pseudonym = bob.manager.local_pseudonym(ctx_id).await.unwrap();
    alice
        .manager
        .seed_peer_pseudonym(ctx_id, DID::from(BOB_DID), bob_pseudonym)
        .await
        .unwrap();
    drop(alice.take_sent_ciphertexts());
    drop(bob.take_sent_ciphertexts());
    Members {
        _network: network,
        alice,
        bob,
        handle,
        ctx_id: ctx_id.to_owned(),
        bob_pseudonym,
    }
}

impl Members {
    /// Alice seals `PLAINTEXT` and the test publishes every fan-out blob to
    /// the relay at `url` as `RelayTransportProvider` would. Returns the
    /// routing IDs the blobs went to.
    async fn publish_from_alice(&self, url: &str) -> Vec<[u8; 32]> {
        self.alice
            .send_message(&self.handle, PLAINTEXT)
            .await
            .unwrap();
        let sent = self.alice.take_sent_ciphertexts();
        assert!(!sent.is_empty(), "Alice's actor sealed nothing");
        let adapter = connect(url).await;
        let mut routing_ids = Vec::new();
        for (routing_id, sealed) in sent {
            let envelope =
                scp_core::envelope::create_outer_envelope(&routing_id, None, 3600, sealed).unwrap();
            adapter.send(&envelope).await.unwrap();
            routing_ids.push(routing_id);
        }
        routing_ids
    }

    fn message_received(events: &[ContextEvent]) -> bool {
        events.iter().any(|e| {
            matches!(e, ContextEvent::MessageReceived { sender_did, payload }
                if sender_did.as_ref() == ALICE_DID && payload.as_slice() == PLAINTEXT)
        })
    }
}

/// Bob's bridge core over `supervisor`, with an in-memory contact store the
/// test reads back.
fn bob_core(supervisor: &Arc<Supervisor>) -> (CoreFields, Contacts) {
    let core = CoreFields::with_supervisor(Arc::clone(supervisor));
    let contacts: Contacts = Arc::new(ProtocolRepository::new_for_testing(InMemoryStorage::new()));
    let store: Arc<dyn RelayContactStore> = Arc::clone(&contacts) as _;
    assert!(core.set_relay_contact_store(store).is_ok());
    (core, contacts)
}

async fn wake(core: &CoreFields) -> WakeOutcome {
    handle_wake(core, PushPlatform::Apns, APNS_WAKE)
        .await
        .expect("a valid APNs payload")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_envelope_at_the_pseudonym_routing_id_gives_new_data_and_a_message_event() {
    let (relay, url) = start_relay().await;
    let m = members("push-wake-new-data", vec![url.clone()]).await;
    let routing_ids = m.publish_from_alice(&url).await;
    // §9.10.4: app data reaches Bob only at his pseudonym, never at the shared
    // routing ID, so a wake that queried the shared ID alone would miss it.
    assert_eq!(routing_ids, vec![m.bob_pseudonym]);
    assert_ne!(
        m.bob_pseudonym,
        scp_core::context::context_routing_id(&m.ctx_id)
    );

    let (core, contacts) = bob_core(&m.bob.manager);
    let before = now_secs();
    let outcome = wake(&core).await;
    let after = now_secs();
    assert!(matches!(outcome, WakeOutcome::NewData), "{outcome:?}");
    assert!(
        Members::message_received(&m.bob.drain_events(&m.ctx_id).await),
        "the actor must emit MessageReceived for Alice's message"
    );
    let contact = contacts.load_last_relay_contact(&m.ctx_id).await.unwrap();
    assert!(
        contact.is_some_and(|t| (before..=after).contains(&t)),
        "a successful Phase 1 writes the local time: {contact:?} not in {before}..={after}"
    );
    assert!(
        m.bob.take_sent_ciphertexts().is_empty(),
        "the woken device publishes nothing"
    );
    relay.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nothing_buffered_gives_no_data() {
    let (relay, url) = start_relay().await;
    let m = members("push-wake-no-data", vec![url]).await;
    let (core, contacts) = bob_core(&m.bob.manager);
    let outcome = wake(&core).await;
    assert!(matches!(outcome, WakeOutcome::NoData), "{outcome:?}");
    assert!(
        contacts
            .load_last_relay_contact(&m.ctx_id)
            .await
            .unwrap()
            .is_some(),
        "every relay answered, so the contact is written"
    );
    relay.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreachable_relay_fails_the_wake() {
    // A port nothing listens on.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let m = members("push-wake-unreachable", vec![format!("ws://{addr}/scp/v1")]).await;
    let (core, contacts) = bob_core(&m.bob.manager);
    let started = Instant::now();
    let outcome = wake(&core).await;
    assert!(
        matches!(outcome, WakeOutcome::Failed(WakeFailure::Dial(_))),
        "{outcome:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(26));
    assert_eq!(
        contacts.load_last_relay_contact(&m.ctx_id).await.unwrap(),
        None,
        "a failed wake writes no contact"
    );
}

/// A WebSocket server that completes the upgrade, then reads and discards
/// every frame and never answers.
async fn start_silent_relay() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                use futures::StreamExt;
                if let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await {
                    while ws.next().await.is_some() {}
                }
            });
        }
    });
    format!("ws://{addr}/scp/v1")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_relay_that_never_answers_query_fails_the_wake_within_the_deadline() {
    let url = start_silent_relay().await;
    let m = members("push-wake-silent", vec![url]).await;
    let (core, contacts) = bob_core(&m.bob.manager);
    let started = Instant::now();
    let outcome = wake(&core).await;
    let elapsed = started.elapsed();
    assert!(matches!(outcome, WakeOutcome::Failed(_)), "{outcome:?}");
    assert!(
        elapsed < WAKE_DEADLINE + Duration::from_secs(1),
        "the wake must end by its deadline, took {elapsed:?}"
    );
    assert_eq!(
        contacts.load_last_relay_contact(&m.ctx_id).await.unwrap(),
        None
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_invalid_payload_gets_5080_and_opens_no_connection() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepted);
    tokio::spawn(async move {
        while listener.accept().await.is_ok() {
            counter.fetch_add(1, Ordering::SeqCst);
        }
    });
    let m = members("push-wake-invalid", vec![format!("ws://{addr}/scp/v1")]).await;
    let (core, _contacts) = bob_core(&m.bob.manager);
    for (platform, payload) in [
        (
            PushPlatform::Apns,
            br#"{"aps":{"content-available":true}}"#.as_slice(),
        ),
        (PushPlatform::Fcm, br#"{"scp":"2"}"#.as_slice()),
        (PushPlatform::WebPush, br#"{"scp":"1","x":"y"}"#.as_slice()),
    ] {
        let err = handle_wake(&core, platform, payload).await.unwrap_err();
        assert_eq!(err.code(), "SCP-TRANS-5080", "{platform:?}");
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        0,
        "an invalid payload opens no connection"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cold_start_restores_and_pulls_without_connect_and_publishes_nothing() {
    let (relay, url) = start_relay().await;
    let m = members("push-wake-cold", vec![url.clone()]).await;
    m.bob.manager.flush_all_contexts().await.unwrap();
    // The host's stored state says the context needs a full reconnection.
    assert!(
        m.bob
            .edit_persisted_snapshot(&m.ctx_id, |s| s.needs_reconnect = true)
    );
    m.publish_from_alice(&url).await;

    // A new process: a supervisor with no resident context and no transport.
    let restarted = m.bob.restarted_supervisor().unwrap();
    restarted.register_local_did(DID::from(BOB_DID)).await;
    assert!(!restarted.has_known_contexts());
    let (core, _contacts) = bob_core(&restarted);
    assert!(!core.has_transport());
    drop(m.bob.take_sent_ciphertexts());

    let outcome = wake(&core).await;
    assert!(matches!(outcome, WakeOutcome::NewData), "{outcome:?}");
    assert!(
        Members::message_received(&restarted.drain_events(&m.ctx_id).await),
        "the restored actor must emit MessageReceived"
    );
    assert!(
        m.bob.take_sent_ciphertexts().is_empty(),
        "the woken device publishes nothing"
    );
    assert!(
        restarted.needs_reconnect(&m.ctx_id).await,
        "a wake leaves needs_reconnect set for the next full reconnection"
    );
    assert!(!core.has_transport(), "the wake installs no transport");
    relay.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cold_start_whose_restore_fails_fails_the_wake() {
    let (relay, url) = start_relay().await;
    let m = members("push-wake-lost-keys", vec![url.clone()]).await;
    m.bob.manager.flush_all_contexts().await.unwrap();
    m.publish_from_alice(&url).await;

    // The keystore was wiped, so the persisted context cannot be restored.
    let restarted = m.bob.restarted_supervisor_with_lost_keys().unwrap();
    restarted.register_local_did(DID::from(BOB_DID)).await;
    let (core, contacts) = bob_core(&restarted);

    let outcome = wake(&core).await;
    match outcome {
        WakeOutcome::Failed(WakeFailure::Unrestored { context_ids }) => {
            assert_eq!(context_ids, vec![m.ctx_id.clone()]);
        }
        other => panic!("a wake that cannot reach a context must fail, got {other:?}"),
    }
    assert_eq!(
        contacts.load_last_relay_contact(&m.ctx_id).await.unwrap(),
        None
    );
    relay.shutdown();
}

/// Each QUERY a [`RecordingAdapter`] saw: the routing ID and its `since`.
type QueryLog = Arc<Mutex<Vec<(RoutingId, Option<u64>)>>>;

/// Delegates to a native relay adapter and records each QUERY's `since`.
struct RecordingAdapter {
    inner: NativeRelayAdapter,
    queries: QueryLog,
}

type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

impl TransportAdapter for RecordingAdapter {
    fn send(&self, envelope: &OuterEnvelope) -> BoxFuture<'_, Result<BlobId, TransportError>> {
        self.inner.send(envelope)
    }
    fn subscribe(
        &self,
        routing_id: &RoutingId,
        since: Option<u64>,
    ) -> BoxFuture<'_, Result<SubscriptionStream, TransportError>> {
        self.inner.subscribe(routing_id, since)
    }
    fn unsubscribe(&self, routing_id: &RoutingId) -> BoxFuture<'_, Result<(), TransportError>> {
        self.inner.unsubscribe(routing_id)
    }
    fn query(
        &self,
        routing_id: &RoutingId,
        since: Option<u64>,
    ) -> BoxFuture<'_, Result<Vec<OuterEnvelope>, TransportError>> {
        self.queries.lock().unwrap().push((*routing_id, since));
        self.inner.query(routing_id, since)
    }
    fn delete(&self, blob_id: &BlobId) -> BoxFuture<'_, Result<(), TransportError>> {
        self.inner.delete(blob_id)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_second_wake_queries_since_the_stored_contact_minus_five_seconds() {
    let (relay, url) = start_relay().await;
    let m = members("push-wake-since", vec![url.clone()]).await;
    m.publish_from_alice(&url).await;
    let queries = Arc::new(Mutex::new(Vec::new()));
    let transport = TransportManager::new(
        url.clone(),
        Box::new(RecordingAdapter {
            inner: connect(&url).await,
            queries: Arc::clone(&queries),
        }),
    );
    let contacts: Contacts = Arc::new(ProtocolRepository::new_for_testing(InMemoryStorage::new()));
    let targets = m.bob.manager.wake_targets().await.unwrap();
    let expected_ids: Vec<RoutingId> = targets[0]
        .routing_ids
        .iter()
        .copied()
        .map(RoutingId::new)
        .collect();
    assert!(expected_ids.contains(&RoutingId::new(m.bob_pseudonym)));

    // First wake: no stored contact, so `since` is 0; it stores `first`.
    let first = now_secs();
    let delivered = scp_ffi_common::reconnect::wake_pull_contexts(
        &transport,
        &m.bob.manager,
        &targets,
        contacts.as_ref(),
        &SyncPolicy::default(),
        first,
    )
    .await
    .unwrap();
    assert_eq!(delivered, 1);
    assert_eq!(
        contacts.load_last_relay_contact(&m.ctx_id).await.unwrap(),
        Some(first)
    );
    let recorded: Vec<_> = std::mem::take(&mut *queries.lock().unwrap());
    assert_eq!(
        recorded,
        expected_ids
            .iter()
            .map(|id| (*id, Some(0)))
            .collect::<Vec<_>>()
    );

    // Second wake: `since` is the stored contact minus 5 on every routing ID.
    let second = first + 1;
    scp_ffi_common::reconnect::wake_pull_contexts(
        &transport,
        &m.bob.manager,
        &targets,
        contacts.as_ref(),
        &SyncPolicy::default(),
        second,
    )
    .await
    .unwrap();
    let recorded: Vec<_> = std::mem::take(&mut *queries.lock().unwrap());
    assert_eq!(
        recorded,
        expected_ids
            .iter()
            .map(|id| (*id, Some(first - 5)))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        contacts.load_last_relay_contact(&m.ctx_id).await.unwrap(),
        Some(second)
    );
    relay.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_refeed_is_not_counted() {
    let (relay, url) = start_relay().await;
    let m = members("push-wake-refeed", vec![url.clone()]).await;
    m.publish_from_alice(&url).await;
    let (core, _contacts) = bob_core(&m.bob.manager);
    let outcome = wake(&core).await;
    assert!(matches!(outcome, WakeOutcome::NewData), "{outcome:?}");

    // The relay still holds the blob and the 5-second overlap returns it
    // again; the actor refuses it as a replay, so the wake counts nothing.
    let outcome = wake(&core).await;
    assert!(matches!(outcome, WakeOutcome::NoData), "{outcome:?}");

    // The Phase 4 re-feed alone over the same buffer counts nothing either.
    let transport = TransportManager::new(url.clone(), Box::new(connect(&url).await));
    let messages = scp_ffi_common::reconnect::pull_buffered(
        &transport,
        &m.ctx_id,
        &[RoutingId::new(m.bob_pseudonym)],
        0,
        now_secs(),
    )
    .await
    .unwrap();
    assert_eq!(messages.len(), 1, "the relay still holds the blob");
    assert_eq!(
        scp_ffi_common::reconnect::refeed_buffer(&m.bob.manager, &m.ctx_id, &messages).await,
        0
    );
    relay.shutdown();
}

/// A full reconnection writes `last_relay_contact` once it clears
/// `needs_reconnect`. The context is classified Long (Tier 3), whose Welcome
/// pull over the live relay succeeds with nothing buffered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_reconnect_that_clears_needs_reconnect_writes_the_contact() {
    let (relay, url) = start_relay().await;
    let m = members("push-wake-full-reconnect", vec![url.clone()]).await;
    let transport = Arc::new(TransportManager::new(
        url.clone(),
        Box::new(connect(&url).await),
    ));
    let contacts: Contacts = Arc::new(ProtocolRepository::new_for_testing(InMemoryStorage::new()));
    let policy = SyncPolicy::default();
    let now = now_secs();
    let mut last = HashMap::new();
    last.insert(
        m.ctx_id.clone(),
        now - (policy.tier_2_threshold_secs + 3600),
    );
    let report = scp_ffi_common::reconnect::reconnect_contexts_no_drain(
        &transport,
        &m.bob.manager,
        DID::from(BOB_DID),
        scp_core::context::actor::CommandSigner::local_ed25519(
            ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]),
        ),
        contacts.as_ref(),
        vec![m.ctx_id.clone()],
        last,
        now,
        policy,
    )
    .await;
    let result = &report.contexts[0];
    assert_eq!(result.tier, "long");
    assert!(result.needs_reconnect_cleared, "{result:?}");
    assert_eq!(result.relay_contact_error, None);
    assert_eq!(
        contacts.load_last_relay_contact(&m.ctx_id).await.unwrap(),
        Some(now)
    );
    relay.shutdown();
}
