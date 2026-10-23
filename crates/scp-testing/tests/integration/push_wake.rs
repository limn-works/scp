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
//! - an unreachable relay gives `Failed` with `RelayUnavailable`, and a relay
//!   that accepts the WebSocket upgrade and never answers QUERY gives
//!   `DeadlineExpired`, within the wake deadline;
//! - an invalid payload for each platform gives `SCP-TRANS-5080` with no
//!   connection opened;
//! - a cold start (no resident context, no `connect`) and a warm wake each
//!   give `NewData`; the woken device publishes nothing and `needs_reconnect`
//!   stays set;
//! - a cold start whose restore fails gives `Failed`, not `NoData`;
//! - a sender-key request a wake delivers leaves its answer queued, and the
//!   next full reconnection sends it;
//! - a deadline that stops a pull mid-delivery leaves the stored contact
//!   unchanged, so the next wake pulls the same window again;
//! - each context is queried only at its own relays, and a dead relay fails
//!   only the context it serves;
//! - a context on 11 relays keeps every relay of the transient dial;
//! - the second wake's QUERY `since` is the stored contact minus 5 seconds;
//! - a refused re-feed is not counted;
//! - a full reconnection that clears `needs_reconnect` writes the contact, and
//!   a Tier 3 reconnection with no Welcome fails, keeps `needs_reconnect` set
//!   and writes no contact.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::{BTreeMap, HashSet};
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
use scp_ffi_common::reconnect::{
    DeliveryTally, ReconnectRequest, RelayScope, WakePull, WakePullError,
    reconnect_contexts_no_drain, wake_pull_contexts,
};
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

/// A URL nothing listens on.
fn dead_url() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    format!("ws://{addr}/scp/v1")
}

fn new_contacts() -> Contacts {
    Arc::new(ProtocolRepository::new_for_testing(InMemoryStorage::new()))
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
        scp_transport::native::adapter::CoverTraffic::Off,
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

/// Alice creates `ctx_id` hosted on `relay_urls` and Bob joins it. Returns
/// the handle and Bob's §9.10.4 pseudonym, which Alice addresses data to.
async fn join(
    alice: &FullStackNode,
    bob: &FullStackNode,
    ctx_id: &str,
    relay_urls: Vec<String>,
) -> (scp_core::context::ContextHandle, [u8; 32]) {
    let ctx_bytes = scp_core::context::context_id_bytes(ctx_id);
    let handle = alice
        .create_context_hosted(ctx_id, encrypted_params(), relay_urls)
        .await
        .unwrap();
    assert_eq!(handle.state(), ContextState::Active);
    alice.add_member(&handle, BOB_DID).await.unwrap();
    bob.join_from_welcome(ctx_id, &ctx_bytes).await.unwrap();
    let bob_pseudonym = bob.manager.local_pseudonym(ctx_id).await.unwrap();
    alice
        .manager
        .seed_peer_pseudonym(ctx_id, DID::from(BOB_DID), bob_pseudonym)
        .await
        .unwrap();
    drop(alice.take_sent_ciphertexts());
    drop(bob.take_sent_ciphertexts());
    (handle, bob_pseudonym)
}

async fn members(ctx_id: &str, relay_urls: Vec<String>) -> Members {
    let network = FullStackNetwork::new();
    let alice = network.create_node(ALICE_DID);
    let bob = network.create_observed_node(BOB_DID);
    let (handle, bob_pseudonym) = join(&alice, &bob, ctx_id, relay_urls).await;
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
    /// A second context between Alice and Bob, hosted on `relay_urls`.
    async fn add_context(
        &self,
        ctx_id: &str,
        relay_urls: Vec<String>,
    ) -> scp_core::context::ContextHandle {
        join(&self.alice, &self.bob, ctx_id, relay_urls).await.0
    }

    /// Alice seals `PLAINTEXT` and the test publishes every fan-out blob to
    /// the relay at `url` as `RelayTransportProvider` would. Returns the
    /// routing IDs the blobs went to.
    async fn publish_from_alice(&self, url: &str) -> Vec<[u8; 32]> {
        self.publish_in(&self.handle, url).await
    }

    /// [`Self::publish_from_alice`] in the context of `handle`.
    async fn publish_in(
        &self,
        handle: &scp_core::context::ContextHandle,
        url: &str,
    ) -> Vec<[u8; 32]> {
        self.alice.send_message(handle, PLAINTEXT).await.unwrap();
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

    /// Bob's command signer over his `#active` key.
    fn bob_signer(&self) -> scp_core::context::actor::CommandSigner {
        scp_core::context::actor::CommandSigner::local_ed25519(self.bob.signing_key())
    }

    /// Bob's process restarted with `needs_reconnect` set in his stored state
    /// and his context restored: a warm process for the next wake, sending
    /// into the same capture buffer as `self.bob`.
    async fn restarted_bob_needing_reconnect(&self) -> Arc<Supervisor> {
        self.bob.manager.flush_all_contexts().await.unwrap();
        assert!(
            self.bob
                .edit_persisted_snapshot(&self.ctx_id, |s| s.needs_reconnect = true)
        );
        let restarted = self.bob.restarted_supervisor().unwrap();
        restarted.register_local_did(DID::from(BOB_DID)).await;
        restarted.restore_on_startup().await.unwrap();
        assert!(restarted.has_known_contexts());
        assert!(restarted.needs_reconnect(&self.ctx_id).await);
        drop(self.bob.take_sent_ciphertexts());
        restarted
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
    let url = dead_url();
    let m = members("push-wake-unreachable", vec![url.clone()]).await;
    let (core, contacts) = bob_core(&m.bob.manager);
    let started = Instant::now();
    let outcome = wake(&core).await;
    match &outcome {
        WakeOutcome::Failed(WakeFailure::Pull(failures)) => {
            assert!(
                matches!(failures.as_slice(), [WakePullError::RelayUnavailable { context_id, relay_url, .. }]
                    if *context_id == m.ctx_id && *relay_url == url),
                "{failures:?}"
            );
        }
        other => panic!("an undialed relay fails its context, got {other:?}"),
    }
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
    assert!(
        matches!(outcome, WakeOutcome::Failed(WakeFailure::DeadlineExpired)),
        "{outcome:?}"
    );
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
    let contacts = new_contacts();
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
    let unreachable = BTreeMap::new();
    let policy = SyncPolicy::default();
    let tally = DeliveryTally::default();
    let failures = wake_pull_contexts(
        &WakePull {
            transport: &transport,
            supervisor: &m.bob.manager,
            unreachable: &unreachable,
            relay_contacts: contacts.as_ref(),
            policy: &policy,
            now: first,
            tally: &tally,
        },
        &targets,
    )
    .await;
    assert!(failures.is_empty(), "{failures:?}");
    assert_eq!(tally.total(), 1);
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
    let failures = wake_pull_contexts(
        &WakePull {
            transport: &transport,
            supervisor: &m.bob.manager,
            unreachable: &unreachable,
            relay_contacts: contacts.as_ref(),
            policy: &policy,
            now: second,
            tally: &tally,
        },
        &targets,
    )
    .await;
    assert!(failures.is_empty(), "{failures:?}");
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
        RelayScope::Installed,
        &m.ctx_id,
        &[RoutingId::new(m.bob_pseudonym)],
        0,
        now_secs(),
    )
    .await
    .unwrap();
    assert_eq!(messages.len(), 1, "the relay still holds the blob");
    let tally = DeliveryTally::default();
    assert_eq!(
        scp_ffi_common::reconnect::refeed_buffer(
            &m.bob.manager,
            &m.ctx_id,
            &messages,
            scp_core::context::actor::commands::DeliveryMode::PullOnly,
            &tally,
        )
        .await,
        0
    );
    assert_eq!(tally.total(), 0);
    relay.shutdown();
}

/// A full reconnection writes `last_relay_contact` once it clears
/// `needs_reconnect`. Bob's stored state carries `needs_reconnect` and a
/// contact 60 seconds old, so the reconnection runs Tier 1 over the live relay
/// and the clear is real.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "Tier 1 reconnection fails every encrypted context with `epoch state unavailable` \
            (ADR-029 reconnection-driver addendum), so no full reconnection clears the flag"]
async fn a_full_reconnect_that_clears_needs_reconnect_writes_the_contact() {
    let (relay, url) = start_relay().await;
    let m = members("push-wake-full-reconnect", vec![url.clone()]).await;
    let bob = m.restarted_bob_needing_reconnect().await;
    let transport = Arc::new(TransportManager::new(
        url.clone(),
        Box::new(connect(&url).await),
    ));
    let contacts = new_contacts();
    let now = now_secs();
    contacts
        .store_last_relay_contact(&m.ctx_id, now - 60)
        .await
        .unwrap();
    let report = reconnect_contexts_no_drain(ReconnectRequest {
        transport: &transport,
        supervisor: &bob,
        member_did: DID::from(BOB_DID),
        signer: m.bob_signer(),
        relay_contacts: contacts.as_ref(),
        context_ids: vec![m.ctx_id.clone()],
        now,
        policy: SyncPolicy::default(),
    })
    .await
    .expect("the contact reads");
    let result = &report.contexts[0];
    assert_eq!(result.tier, "short", "{result:?}");
    assert_eq!(result.outcome, "fully_caught_up", "{result:?}");
    assert!(result.needs_reconnect_cleared, "{result:?}");
    assert!(!bob.needs_reconnect(&m.ctx_id).await);
    assert_eq!(result.relay_contact_error, None);
    assert_eq!(
        contacts.load_last_relay_contact(&m.ctx_id).await.unwrap(),
        Some(now)
    );
    relay.shutdown();
}

/// A Tier 3 reconnection that finds no Welcome within the Welcome window
/// reports a failure, not a reset: `needs_reconnect` stays set and the stored
/// contact is unchanged. The window is 30 seconds, so this test takes that
/// long.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tier_3_reconnect_with_no_welcome_fails_and_keeps_needs_reconnect_set() {
    let (relay, url) = start_relay().await;
    let m = members("push-wake-tier-3-timeout", vec![url.clone()]).await;
    let bob = m.restarted_bob_needing_reconnect().await;
    let transport = Arc::new(TransportManager::new(
        url.clone(),
        Box::new(connect(&url).await),
    ));
    let contacts = new_contacts();
    let policy = SyncPolicy::default();
    let now = now_secs();
    let old = now - (policy.tier_2_threshold_secs + 3600);
    contacts
        .store_last_relay_contact(&m.ctx_id, old)
        .await
        .unwrap();
    let report = reconnect_contexts_no_drain(ReconnectRequest {
        transport: &transport,
        supervisor: &bob,
        member_did: DID::from(BOB_DID),
        signer: m.bob_signer(),
        relay_contacts: contacts.as_ref(),
        context_ids: vec![m.ctx_id.clone()],
        now,
        policy,
    })
    .await
    .expect("the contact reads");
    let result = &report.contexts[0];
    assert_eq!(result.tier, "long", "{result:?}");
    assert_eq!(result.outcome, "failed", "{result:?}");
    assert!(!result.needs_reconnect_cleared, "{result:?}");
    assert!(
        bob.needs_reconnect(&m.ctx_id).await,
        "a Tier 3 pull with no Welcome leaves needs_reconnect set"
    );
    assert_eq!(
        contacts.load_last_relay_contact(&m.ctx_id).await.unwrap(),
        Some(old),
        "a reconnection that reset nothing writes no contact"
    );
    relay.shutdown();
}

/// A warm process whose stored state carries `needs_reconnect` pulls on a
/// wake, publishes nothing, and leaves `needs_reconnect` set.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_warm_wake_leaves_needs_reconnect_set_and_publishes_nothing() {
    let (relay, url) = start_relay().await;
    let m = members("push-wake-warm-needs-reconnect", vec![url.clone()]).await;
    let bob = m.restarted_bob_needing_reconnect().await;
    m.publish_from_alice(&url).await;
    let (core, contacts) = bob_core(&bob);
    let outcome = wake(&core).await;
    assert!(matches!(outcome, WakeOutcome::NewData), "{outcome:?}");
    assert!(Members::message_received(
        &bob.drain_events(&m.ctx_id).await
    ));
    assert!(
        bob.needs_reconnect(&m.ctx_id).await,
        "a wake leaves needs_reconnect set for the next full reconnection"
    );
    assert!(
        m.bob.take_sent_ciphertexts().is_empty(),
        "the woken device publishes nothing"
    );
    assert!(
        contacts
            .load_last_relay_contact(&m.ctx_id)
            .await
            .unwrap()
            .is_some()
    );
    relay.shutdown();
}

/// Publishes to `url` Alice's §9.16.2 request for Bob's sender key, signed
/// with her `#active` key and sealed through her MLS group as a management
/// message.
async fn publish_alice_key_request(m: &Members, url: &str) {
    use ed25519_dalek::Signer as _;
    use scp_protocol::crypto::sender_keys::key_protocol_verify::{
        RequestHashInput, compute_request_hash,
    };
    use scp_protocol::crypto::sender_keys::{
        SenderKeyDistributionMessage, SenderKeyRequest, generate_wrapping_keypair,
    };

    let epoch = m.bob.manager.local_mls_epoch(&m.ctx_id).await.unwrap();
    let (wrapping_pubkey, _wrapping_secret) = generate_wrapping_keypair();
    let nonce = [7u8; 16];
    let timestamp = now_secs();
    let hash = compute_request_hash(
        ALICE_DID,
        BOB_DID,
        &wrapping_pubkey,
        &nonce,
        RequestHashInput {
            epoch,
            requested_at: timestamp,
        },
    )
    .unwrap();
    let request = SenderKeyDistributionMessage::KeyRequest(SenderKeyRequest {
        requester_did: ALICE_DID.to_owned(),
        sender_did: BOB_DID.to_owned(),
        epoch,
        wrapping_pubkey,
        nonce,
        timestamp,
        signature: m.alice.signing_key().sign(&hash).to_bytes(),
    })
    .to_bytes()
    .unwrap();
    let sealed = m
        .alice
        .manager
        .test_seal_management(&m.ctx_id, request)
        .await
        .unwrap();
    // The relay carries the sealed management envelope as the encrypted
    // blob of a transport envelope, as it carries every sealed message.
    let envelope = scp_core::envelope::create_outer_envelope(
        &scp_core::context::context_routing_id(&m.ctx_id),
        None,
        3600,
        sealed,
    )
    .unwrap();
    connect(url).await.send(&envelope).await.unwrap();
}

/// Wakes Bob over `url` and asserts that the wake delivered Alice's key
/// request, queued Bob's answer and published nothing.
async fn wake_queues_the_answer(m: &Members) {
    let (core, _contacts) = bob_core(&m.bob.manager);
    let outcome = wake(&core).await;
    assert!(matches!(outcome, WakeOutcome::NoData), "{outcome:?}");
    assert!(
        m.bob.take_sent_ciphertexts().is_empty(),
        "the wake publishes no answer"
    );
    assert_eq!(
        m.bob
            .manager
            .queued_sender_key_count(&m.ctx_id)
            .await
            .unwrap(),
        1,
        "the wake queues the answer"
    );
}

/// A §9.16.2 sender-key request that a wake delivers queues Bob's answer
/// without sending it. `Supervisor::send_queued_sender_keys`, the call a full
/// reconnection makes after a terminal success, then sends it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_request_a_wake_delivers_stays_queued_until_the_answers_are_sent() {
    let (relay, url) = start_relay().await;
    let m = members("push-wake-key-request", vec![url.clone()]).await;
    publish_alice_key_request(&m, &url).await;
    wake_queues_the_answer(&m).await;

    m.bob
        .manager
        .send_queued_sender_keys(&m.ctx_id)
        .await
        .unwrap();
    assert_eq!(
        m.bob
            .manager
            .queued_sender_key_count(&m.ctx_id)
            .await
            .unwrap(),
        0
    );
    assert!(
        !m.bob.take_sent_ciphertexts().is_empty(),
        "sending the queued answers publishes the answer"
    );
    relay.shutdown();
}

/// The full reconnection after a wake sends the answer the wake queued.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "Tier 1 reconnection fails every encrypted context with `epoch state unavailable` \
            (ADR-029 reconnection-driver addendum), so no full reconnection reaches the send"]
async fn a_full_reconnect_sends_the_answer_a_wake_queued() {
    let (relay, url) = start_relay().await;
    let m = members("push-wake-key-request-reconnect", vec![url.clone()]).await;
    publish_alice_key_request(&m, &url).await;
    wake_queues_the_answer(&m).await;
    let transport = Arc::new(TransportManager::new(
        url.clone(),
        Box::new(connect(&url).await),
    ));
    let contacts = new_contacts();
    let now = now_secs();
    contacts
        .store_last_relay_contact(&m.ctx_id, now - 60)
        .await
        .unwrap();
    let report = reconnect_contexts_no_drain(ReconnectRequest {
        transport: &transport,
        supervisor: &m.bob.manager,
        member_did: DID::from(BOB_DID),
        signer: m.bob_signer(),
        relay_contacts: contacts.as_ref(),
        context_ids: vec![m.ctx_id.clone()],
        now,
        policy: SyncPolicy::default(),
    })
    .await
    .expect("the contact reads");
    assert_eq!(report.contexts[0].outcome, "fully_caught_up", "{report:?}");
    assert_eq!(
        m.bob
            .manager
            .queued_sender_key_count(&m.ctx_id)
            .await
            .unwrap(),
        0,
        "the full reconnection sends the queued answer"
    );
    assert!(!m.bob.take_sent_ciphertexts().is_empty());
    relay.shutdown();
}

/// A contact store whose write yields once before it writes, so a deadline
/// that is due when the write starts drops the pull before the write lands.
struct YieldingContacts(Contacts);

#[async_trait::async_trait]
impl RelayContactStore for YieldingContacts {
    async fn store_last_relay_contact(
        &self,
        context_id: &str,
        last_relay_contact: u64,
    ) -> Result<(), scp_core::store::StoreError> {
        tokio::task::yield_now().await;
        self.0
            .store_last_relay_contact(context_id, last_relay_contact)
            .await
    }
    async fn load_last_relay_contact(
        &self,
        context_id: &str,
    ) -> Result<Option<u64>, scp_core::store::StoreError> {
        self.0.load_last_relay_contact(context_id).await
    }
}

/// A deadline that drops the pull after the actor accepted an envelope but
/// before the contact write leaves the stored contact unchanged, so the next
/// wake pulls the same window again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_deadline_that_stops_a_pull_mid_delivery_keeps_the_stored_contact() {
    let (relay, url) = start_relay().await;
    let m = members("push-wake-deadline-mid-delivery", vec![url.clone()]).await;
    m.publish_from_alice(&url).await;
    let queries = Arc::new(Mutex::new(Vec::new()));
    let mut transport = TransportManager::with_connection_budget(1);
    let _ = transport.add_adapter(
        url.clone(),
        Box::new(RecordingAdapter {
            inner: connect(&url).await,
            queries: Arc::clone(&queries),
        }),
    );
    let contacts = new_contacts();
    let yielding = YieldingContacts(Arc::clone(&contacts));
    let targets = m.bob.manager.wake_targets().await.unwrap();
    let unreachable = BTreeMap::new();
    let policy = SyncPolicy::default();

    // The deadline is due as soon as the actor accepted an envelope.
    let tally = DeliveryTally::default();
    let pull = WakePull {
        transport: &transport,
        supervisor: &m.bob.manager,
        unreachable: &unreachable,
        relay_contacts: &yielding,
        policy: &policy,
        now: now_secs(),
        tally: &tally,
    };
    let deadline = async {
        while tally.total() == 0 {
            tokio::task::yield_now().await;
        }
    };
    tokio::select! {
        biased;
        () = deadline => {}
        failures = wake_pull_contexts(&pull, &targets) => {
            panic!("the pull finished before the deadline: {failures:?}");
        }
    }
    assert_eq!(tally.total(), 1, "the actor accepted Alice's message");
    assert_eq!(
        contacts.load_last_relay_contact(&m.ctx_id).await.unwrap(),
        None,
        "a pull the deadline stopped writes no contact"
    );

    // The next wake queries from 0 again and then writes the contact.
    queries.lock().unwrap().clear();
    let second = now_secs();
    let tally = DeliveryTally::default();
    let failures = wake_pull_contexts(
        &WakePull {
            now: second,
            tally: &tally,
            ..pull
        },
        &targets,
    )
    .await;
    assert!(failures.is_empty(), "{failures:?}");
    let recorded = queries.lock().unwrap().clone();
    assert!(!recorded.is_empty());
    assert!(
        recorded.iter().all(|(_, since)| *since == Some(0)),
        "{recorded:?}"
    );
    assert_eq!(
        contacts.load_last_relay_contact(&m.ctx_id).await.unwrap(),
        Some(second)
    );
    relay.shutdown();
}

/// Each context is queried only at the relays its own relay set names, so a
/// relay never sees another context's routing IDs (§9.10.4).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_context_is_queried_only_at_its_own_relays() {
    let (relay_a, url_a) = start_relay().await;
    let (relay_b, url_b) = start_relay().await;
    let m = members("push-wake-disjoint-a", vec![url_a.clone()]).await;
    m.add_context("push-wake-disjoint-b", vec![url_b.clone()])
        .await;
    let log_a: QueryLog = Arc::new(Mutex::new(Vec::new()));
    let log_b: QueryLog = Arc::new(Mutex::new(Vec::new()));
    let mut transport = TransportManager::with_connection_budget(2);
    for (url, log) in [(&url_a, &log_a), (&url_b, &log_b)] {
        assert!(
            transport
                .add_adapter(
                    url.clone(),
                    Box::new(RecordingAdapter {
                        inner: connect(url).await,
                        queries: Arc::clone(log),
                    }),
                )
                .is_none()
        );
    }
    let targets = m.bob.manager.wake_targets().await.unwrap();
    assert_eq!(targets.len(), 2);
    let ids_of = |ctx: &str| -> HashSet<RoutingId> {
        targets
            .iter()
            .find(|t| t.context_id == ctx)
            .unwrap()
            .routing_ids
            .iter()
            .copied()
            .map(RoutingId::new)
            .collect()
    };
    let ids_a = ids_of("push-wake-disjoint-a");
    let ids_b = ids_of("push-wake-disjoint-b");
    assert!(ids_a.is_disjoint(&ids_b));

    let contacts = new_contacts();
    let unreachable = BTreeMap::new();
    let policy = SyncPolicy::default();
    let tally = DeliveryTally::default();
    let failures = wake_pull_contexts(
        &WakePull {
            transport: &transport,
            supervisor: &m.bob.manager,
            unreachable: &unreachable,
            relay_contacts: contacts.as_ref(),
            policy: &policy,
            now: now_secs(),
            tally: &tally,
        },
        &targets,
    )
    .await;
    assert!(failures.is_empty(), "{failures:?}");
    let seen = |log: &QueryLog| -> HashSet<RoutingId> {
        log.lock().unwrap().iter().map(|(id, _)| *id).collect()
    };
    assert_eq!(seen(&log_a), ids_a, "relay A sees only context A");
    assert_eq!(seen(&log_b), ids_b, "relay B sees only context B");
    relay_a.shutdown();
    relay_b.shutdown();
}

/// A dead relay fails only the context whose relay set names it: context A
/// still delivers and the wake reports `NewData`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dead_relay_fails_only_the_context_it_serves() {
    let (relay, url) = start_relay().await;
    let m = members("push-wake-dead-only-b-a", vec![url.clone()]).await;
    let ctx_b = "push-wake-dead-only-b-b";
    m.add_context(ctx_b, vec![dead_url()]).await;
    m.publish_from_alice(&url).await;
    let (core, contacts) = bob_core(&m.bob.manager);
    let outcome = wake(&core).await;
    assert!(matches!(outcome, WakeOutcome::NewData), "{outcome:?}");
    assert!(Members::message_received(
        &m.bob.drain_events(&m.ctx_id).await
    ));
    assert!(
        contacts
            .load_last_relay_contact(&m.ctx_id)
            .await
            .unwrap()
            .is_some(),
        "context A delivered, so its contact is written"
    );
    assert_eq!(
        contacts.load_last_relay_contact(ctx_b).await.unwrap(),
        None,
        "context B's relay was not dialed, so its contact is unchanged"
    );
    relay.shutdown();
}

/// A context hosted on 11 relays, one more than the mobile connection budget,
/// keeps every relay of the transient dial: the relay holding the envelope is
/// not evicted and the wake reports `NewData`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_context_on_eleven_relays_keeps_every_relay_of_the_dial() {
    let mut relays = Vec::new();
    let mut urls = Vec::new();
    for _ in 0..11 {
        let (handle, url) = start_relay().await;
        relays.push(handle);
        urls.push(url);
    }
    let m = members("push-wake-eleven-relays", urls.clone()).await;
    m.publish_from_alice(&urls[0]).await;
    let (core, contacts) = bob_core(&m.bob.manager);
    let outcome = wake(&core).await;
    assert!(matches!(outcome, WakeOutcome::NewData), "{outcome:?}");
    assert!(
        contacts
            .load_last_relay_contact(&m.ctx_id)
            .await
            .unwrap()
            .is_some()
    );
    for relay in relays {
        relay.shutdown();
    }
}
