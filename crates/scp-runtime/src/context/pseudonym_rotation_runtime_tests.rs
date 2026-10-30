//! Runtime tests for the local member's pseudonym rotation (spec 09
//! §9.10.4.1): the epoch schedule and membership trigger the actor's rotation
//! arm signals, the fail-closed `rotate_pseudonym` commit, the announcement,
//! the leave/close/expiry discard of the query-only list, and crash recovery through
//! the production `restore_all_contexts`.
//!
//! Every test drives the production Supervisor entry points
//! (`create_context`, `propose_governance_action_checked`, `rotate_pseudonym`,
//! `local_routing_ids`, `leave_context`, `dispatch_ttl_close_command`,
//! `restore_all_contexts`). Wall-clock time comes from an injected
//! [`TestClock`]; the schedule tests also pause tokio time, so the actor's
//! one-shot sleeps fire on `advance` rather than on real time.

#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use dashmap::DashMap;
use ed25519_dalek::SigningKey;
use scp_clock::TestClock;
use scp_did::DID;
use scp_platform::in_memory::InMemoryStorage;
use scp_protocol::context::builder::ContextCreationError;
use scp_protocol::context::governance::{GovernanceAction, ProposalStatus};
use scp_protocol::context::membership::ContextEvent;
use scp_protocol::context::params::{ContextMode, ContextParams, PseudonymRotationPolicy};
use scp_protocol::context::roles::Capability;
use scp_protocol::context::{ContextError, context_routing_id};
use tokio::sync::broadcast;

use crate::context::ContextHandle;
use crate::context::actor::pseudonym_rotation::LocalRoutingIds;
use crate::context::actor::signer::CommandSigner;
use crate::context::builder::{ContextEventLogProvider, ContextTransportProvider};
use crate::context::persistence::ContextPersistence;
use crate::context::state::ContextSnapshot;
use crate::context::supervisor::supervisor::Supervisor;

type PersistErr = Box<dyn std::error::Error + Send + Sync>;

const LOCAL: &str = "did:dht:z6MkRotationLocal";
const BOB: &str = "did:dht:z6MkRotationBob";
const T0: u64 = 1_700_000_000;
const INTERVAL: u64 = 3_600;
const V1_RID: [u8; 32] = [0x07; 32];
const RID_1: [u8; 32] = [0x61; 32];
const RID_2: [u8; 32] = [0x62; 32];

fn local_key() -> SigningKey {
    SigningKey::from_bytes(&[0x51; 32])
}

fn bob_key() -> SigningKey {
    SigningKey::from_bytes(&[0x52; 32])
}

fn local() -> DID {
    DID(LOCAL.to_owned())
}

fn bob() -> DID {
    DID(BOB.to_owned())
}

/// A canonical context ID: production IDs are 64 lowercase hex characters,
/// which the actor keys its own writes by, so the fixture uses the same form.
fn cid(name: &str) -> String {
    hex::encode(crate::context::state::context_id_to_bytes(name))
}

fn interval_policy() -> PseudonymRotationPolicy {
    PseudonymRotationPolicy {
        interval_secs: Some(INTERVAL),
        on_membership_change: false,
    }
}

fn membership_policy() -> PseudonymRotationPolicy {
    PseudonymRotationPolicy {
        interval_secs: None,
        on_membership_change: true,
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Snapshot store shared across supervisors, so a test can restart a node on
/// the snapshots the first one persisted. `fail_writes` makes every write fail.
#[derive(Default)]
struct Store {
    contexts: DashMap<String, ContextSnapshot>,
    fail_writes: AtomicBool,
    writes: AtomicUsize,
}

impl Store {
    /// The write count once the actor's coalesced persist, which lands about
    /// 50 ms after a Class-C mutation, has drained: the count unchanged
    /// across 300 ms. A "nothing persisted" check that snapshots the count
    /// earlier counts that late write against the operation under test.
    async fn settled_writes(&self) -> usize {
        let mut last = self.writes.load(Ordering::SeqCst);
        loop {
            tokio::time::sleep(Duration::from_millis(300)).await;
            let now = self.writes.load(Ordering::SeqCst);
            if now == last {
                return now;
            }
            last = now;
        }
    }

    fn snapshot(&self, ctx_id: &str) -> ContextSnapshot {
        self.contexts
            .get(ctx_id)
            .map(|s| s.value().clone())
            .expect("the context is persisted")
    }

    fn copy(&self) -> Arc<Self> {
        let copy = Self::default();
        for entry in &self.contexts {
            copy.contexts
                .insert(entry.key().clone(), entry.value().clone());
        }
        Arc::new(copy)
    }
}

struct SharedStore(Arc<Store>);

#[async_trait::async_trait]
impl ContextPersistence for SharedStore {
    async fn persist_context(&self, id: &str, s: &ContextSnapshot) -> Result<(), PersistErr> {
        if self.0.fail_writes.load(Ordering::SeqCst) {
            return Err("fixture: persistence write fails".into());
        }
        self.0.writes.fetch_add(1, Ordering::SeqCst);
        self.0.contexts.insert(id.to_owned(), s.clone());
        Ok(())
    }
    async fn load_context(&self, id: &str) -> Result<Option<ContextSnapshot>, PersistErr> {
        Ok(self.0.contexts.get(id).map(|s| s.value().clone()))
    }
    async fn delete_context(&self, id: &str) -> Result<(), PersistErr> {
        self.0.contexts.remove(id);
        Ok(())
    }
    async fn list_persisted_contexts(&self) -> Result<Vec<String>, PersistErr> {
        Ok(self.0.contexts.iter().map(|e| e.key().clone()).collect())
    }
}

/// Records every `send_message`'s transport address, in send order.
/// `fail_sends` makes every send fail.
#[derive(Default)]
struct Sent {
    addresses: DashMap<usize, [u8; 32]>,
    next: AtomicUsize,
    fail_sends: AtomicBool,
}

impl Sent {
    fn count(&self) -> usize {
        self.next.load(Ordering::SeqCst)
    }

    fn last_address(&self) -> Option<[u8; 32]> {
        let last = self.count().checked_sub(1)?;
        self.addresses.get(&last).map(|a| *a)
    }
}

struct RecordingTransport(Arc<Sent>);

#[async_trait::async_trait]
impl ContextTransportProvider for RecordingTransport {
    fn is_connected(&self) -> bool {
        true
    }
    async fn publish_context(
        &self,
        _id: &[u8; 32],
        _params: &ContextParams,
    ) -> Result<(), ContextCreationError> {
        Ok(())
    }
    async fn delete_published(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    async fn send_message(
        &self,
        id: &[u8; 32],
        _payload: &[u8],
        _ttl: scp_protocol::envelope::outer::BlobTtl,
    ) -> Result<(), ContextError> {
        if self.0.fail_sends.load(Ordering::SeqCst) {
            return Err(ContextError::TransportFailed(
                "fixture: transport send fails".to_owned(),
            ));
        }
        let index = self.0.next.fetch_add(1, Ordering::SeqCst);
        self.0.addresses.insert(index, *id);
        Ok(())
    }
}

struct OkEventLog;

#[async_trait::async_trait]
impl ContextEventLogProvider for OkEventLog {
    fn event_log_entries(
        &self,
        _context_id: &[u8; 32],
    ) -> Result<Option<Vec<scp_event_log::Event>>, scp_protocol::context::ContextError> {
        Ok(None)
    }

    /// The fixture holds no entry, so its root is the empty log's root.
    fn event_log_merkle_root(
        &self,
        _context_id: &[u8; 32],
    ) -> Result<[u8; 32], scp_protocol::context::ContextError> {
        Ok(scp_event_log::tree::root(&scp_event_log::EventLog::new(
            String::new(),
        )))
    }

    async fn init_event_log(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    async fn append_event(
        &self,
        _id: &[u8; 32],
        _event: scp_event_log::EventType,
        _actor: &str,
        _payload: scp_event_log::EventPayload,
        _timestamp_secs: u64,
    ) -> Result<(), ContextCreationError> {
        Ok(())
    }
    async fn destroy_event_log(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
}

/// One node: a Supervisor whose local DID is [`LOCAL`], with its event
/// receiver, clock, snapshot store and transport record.
struct Node {
    supervisor: Arc<Supervisor>,
    events: broadcast::Receiver<(String, ContextEvent)>,
    clock: Arc<TestClock>,
    store: Arc<Store>,
    sent: Arc<Sent>,
}

fn mls_storage() -> Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> {
    Arc::new(
        crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
            InMemoryStorage::new(),
        )),
    )
}

fn node_on(store: Arc<Store>, clock: Arc<TestClock>) -> Node {
    let crypto = Arc::new(crate::crypto::mls::provider::NodeMlsFactory::new(
        LOCAL.to_owned(),
        Arc::new(scp_clock::SystemClock),
    ));
    let keys: HashMap<String, ed25519_dalek::VerifyingKey> = [
        (LOCAL.to_owned(), local_key().verifying_key()),
        (BOB.to_owned(), bob_key().verifying_key()),
    ]
    .into_iter()
    .collect();
    let resolver: scp_protocol::context::governance::KeyResolver =
        Arc::new(move |did: &DID, _: scp_did::SigningKeyId| keys.get(did.as_ref()).copied());
    let (tx, events) = broadcast::channel(4_096);
    let sent = Arc::new(Sent::default());
    let supervisor = Supervisor::with_providers(
        crypto,
        Box::new(RecordingTransport(Arc::clone(&sent))),
        Box::new(OkEventLog),
        resolver,
        Some(Box::new(SharedStore(Arc::clone(&store)))),
        None,
        Some(tx),
        Some(Arc::clone(&clock) as Arc<dyn scp_clock::Clock>),
        mls_storage(),
    );
    Node {
        supervisor,
        events,
        clock,
        store,
        sent,
    }
}

fn node() -> Node {
    node_on(Arc::new(Store::default()), Arc::new(TestClock::new(T0)))
}

fn params(policy: Option<PseudonymRotationPolicy>) -> ContextParams {
    ContextParams {
        mode: ContextMode::Encrypted,
        ceiling: vec![
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::GovernancePropose,
            Capability::MemberRemove,
        ],
        pseudonym_rotation: policy,
        ..ContextParams::default()
    }
}

impl Node {
    async fn create(&self, ctx_id: &str, params: ContextParams) -> ContextHandle {
        self.supervisor
            .create_context(ctx_id.to_owned(), params, local(), Some(V1_RID), Vec::new())
            .await
            .expect("create_context")
    }

    async fn ids(&self, ctx_id: &str) -> LocalRoutingIds {
        self.supervisor
            .local_routing_ids(ctx_id)
            .await
            .expect("local_routing_ids")
    }

    async fn rotate(
        &self,
        ctx_id: &str,
        epoch: u64,
        routing_id: [u8; 32],
    ) -> Result<(), ContextError> {
        self.supervisor
            .rotate_pseudonym(
                ctx_id,
                &local(),
                &CommandSigner::local_ed25519(local_key()),
                epoch,
                routing_id,
            )
            .await
    }

    async fn govern(&self, ctx_id: &str, action: GovernanceAction) {
        let outcome = self
            .supervisor
            .propose_governance_action_checked(
                ctx_id,
                &local(),
                action,
                &CommandSigner::local_ed25519(local_key()),
            )
            .await
            .expect("the sole admin's proposal executes");
        assert_eq!(outcome.status, ProposalStatus::Approved);
    }

    /// Every event received so far, without waiting.
    fn drain(&mut self) -> Vec<ContextEvent> {
        let mut out = Vec::new();
        while let Ok((_, event)) = self.events.try_recv() {
            out.push(event);
        }
        out
    }

    /// Waits up to `within` for an event `pick` maps to `Some`, discarding
    /// others; `None` on timeout.
    async fn wait_for<T>(
        &mut self,
        within: Duration,
        mut pick: impl FnMut(&ContextEvent) -> Option<T>,
    ) -> Option<T> {
        tokio::time::timeout(within, async {
            loop {
                match self.events.recv().await {
                    Ok((_, event)) => {
                        if let Some(found) = pick(&event) {
                            return found;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => {
                        std::future::pending::<()>().await;
                    }
                }
            }
        })
        .await
        .ok()
    }

    /// Every event received within `within`.
    async fn collect_for(&mut self, within: Duration) -> Vec<ContextEvent> {
        let mut out = Vec::new();
        let _ = self
            .wait_for(within, |event| {
                out.push(event.clone());
                None::<()>
            })
            .await;
        out
    }
}

fn due(event: &ContextEvent) -> Option<u64> {
    match event {
        ContextEvent::PseudonymRotationDue { pseudonym_epoch } => Some(*pseudonym_epoch),
        _ => None,
    }
}

fn pending(event: &ContextEvent) -> Option<u64> {
    match event {
        ContextEvent::PseudonymAnnouncementPending { pseudonym_epoch } => Some(*pseudonym_epoch),
        _ => None,
    }
}

fn rotated(events: &[ContextEvent]) -> Vec<u64> {
    events
        .iter()
        .filter_map(|e| match e {
            ContextEvent::LocalPseudonymRotated { pseudonym_epoch } => Some(*pseudonym_epoch),
            _ => None,
        })
        .collect()
}

fn is_rotation_signal(event: &ContextEvent) -> bool {
    due(event).is_some() || pending(event).is_some()
}

/// Real-time bound for an arm that fires at once (`sleep(0)`).
const PROMPT: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Commit, announcement, and query
// ---------------------------------------------------------------------------

/// §9.10.4.1 steps 2, 4, 5: a rotation persists the epoch, the new routing
/// ID and the previous one as a query-only entry, emits
/// `LocalPseudonymRotated` once, sends exactly one announcement on the shared
/// `context_routing_id`, and clears `announce_pending`; `LocalRoutingIds`
/// reports all of it, with the previous routing ID only on `query_only`.
#[tokio::test]
async fn a_rotation_persists_emits_once_announces_on_the_shared_channel_and_clears_pending() {
    let mut n = node();
    let ctx = &cid("rotation-commit");
    n.create(ctx, params(Some(interval_policy()))).await;
    n.clock.set(T0 + INTERVAL);
    n.drain();
    let sent_before = n.sent.count();

    let before = n.ids(ctx).await;
    assert_eq!(before.current, V1_RID);
    assert_eq!(
        before.pseudonym_epoch, None,
        "the creator holds a v1 routing ID"
    );
    assert_eq!(
        before.next_pseudonym_epoch,
        Some(1),
        "a v1 member's first rotation derives v2 at the schedule index k = 1"
    );

    n.rotate(ctx, 1, RID_1).await.expect("the rotation commits");

    let after = n.ids(ctx).await;
    assert_eq!(after.current, RID_1);
    assert_eq!(after.pseudonym_epoch, Some(1));
    assert_eq!(after.next_pseudonym_epoch, Some(2));
    assert!(!after.announce_pending, "the announcement cleared the flag");
    assert_eq!(
        after
            .query_only
            .iter()
            .map(|e| (e.routing_id, e.expires_at_secs))
            .collect::<Vec<_>>(),
        vec![(
            V1_RID,
            T0 + INTERVAL + u64::from(scp_relay_client::MAX_BLOB_TTL)
        )],
        "the old routing ID is query-only from the moment of the rotation"
    );

    let persisted = n.store.snapshot(ctx);
    assert_eq!(persisted.routing.local_pseudonym(), Some(RID_1));
    assert_eq!(persisted.pseudonym_rotation.epoch(), Some(1));
    assert_eq!(persisted.pseudonym_rotation.query_only, after.query_only);
    assert!(!persisted.pseudonym_rotation.announce_pending());

    assert_eq!(
        n.sent.count() - sent_before,
        1,
        "a rotation sends exactly one message"
    );
    assert_eq!(
        n.sent.last_address(),
        Some(context_routing_id(ctx)),
        "the announcement travels only on the shared context_routing_id"
    );

    let events = n.collect_for(Duration::from_millis(200)).await;
    assert_eq!(
        rotated(&events),
        vec![1],
        "LocalPseudonymRotated is emitted once"
    );
}

/// The push routing IDs (`10-infrastructure-and-self-hosting.md` §10.7.1)
/// read the same local pseudonym a rotation writes: after the rotation,
/// `Supervisor::push_routing_ids` lists the new routing ID in place of the
/// old one, beside the shared `context_routing_id`, under the context's relay.
#[tokio::test]
async fn push_routing_ids_follow_a_rotation() {
    const RELAY: &str = "wss://relay.example/scp/v1";
    let n = node();
    let ctx = &cid("rotation-push-routes");
    n.supervisor
        .create_context(
            ctx.clone(),
            params(Some(interval_policy())),
            local(),
            Some(V1_RID),
            vec![RELAY.to_owned()],
        )
        .await
        .expect("create_context");
    let relay = scp_did::canonical_relay_url(RELAY).expect("canonical");
    let routes = |ids: [u8; 32]| {
        std::collections::BTreeMap::from([(
            relay.clone(),
            std::collections::BTreeSet::from([context_routing_id(ctx), ids]),
        )])
    };

    let before = n.supervisor.push_routing_ids().await.expect("push routes");
    assert_eq!(
        before,
        routes(V1_RID),
        "the v1 routing ID before a rotation"
    );

    n.clock.set(T0 + INTERVAL);
    n.rotate(ctx, 1, RID_1).await.expect("the rotation commits");

    let after = n.supervisor.push_routing_ids().await.expect("push routes");
    assert_eq!(after, routes(RID_1), "the rotated routing ID after it");
}

/// Records every push message the registrar publishes and accepts it.
struct PushRecorder(tokio::sync::mpsc::UnboundedSender<(String, Vec<u8>)>);

impl crate::push::PushRelayPublisher for PushRecorder {
    fn publish<'a>(
        &'a self,
        relay_url: &'a str,
        _routing_id: [u8; 32],
        blob: Vec<u8>,
    ) -> futures::future::BoxFuture<'a, Result<(), crate::push::PushPublishError>> {
        let sent = self.0.send((relay_url.to_owned(), blob));
        Box::pin(async move {
            sent.map_err(|_| crate::push::PushPublishError::Unreachable {
                reason: "test receiver closed".to_owned(),
            })
        })
    }
}

/// A rotation after the push registrar's task started reaches the registrar
/// through the supervisor's route watch (`10-infrastructure-and-self-hosting.md`
/// §10.7.1 **Re-registration**): the relay gets exactly one registration,
/// holding the new routing ID and not the old one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rotation_after_start_reregisters_once_with_the_new_routing_id() {
    use scp_protocol::discovery::push::{PushPlatform, PushRegistration};

    const RELAY: &str = "wss://relay.example/scp/v1";
    let n = node();
    let ctx = &cid("rotation-push-registrar");
    n.supervisor
        .create_context(
            ctx.clone(),
            params(Some(interval_policy())),
            local(),
            Some(V1_RID),
            vec![RELAY.to_owned()],
        )
        .await
        .expect("create_context");

    let custody = Arc::new(scp_platform::testing::InMemoryKeyCustody::new());
    let handle = scp_platform::KeyCustody::generate_keypair(
        custody.as_ref(),
        scp_platform::KeyType::P256Signing,
    )
    .await
    .expect("P-256 key");
    let signing_key = crate::push::PushSigningKey::for_testing(local(), custody, handle)
        .await
        .expect("signing key");
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let registrar = crate::push::PushRegistrar::new(crate::push::PushRegistrarConfig {
        signing_key,
        publisher: Arc::new(PushRecorder(tx)),
        clock: Arc::clone(&n.clock) as Arc<dyn scp_clock::Clock>,
        monotonic_clock: Arc::new(scp_clock::SystemMonotonicClock::new()),
        platform: PushPlatform::Apns,
        token: scp_platform::PushToken::new(b"rotation-device-token".to_vec()),
        storage: Arc::new(crate::store::ProtocolRepository::new_for_testing(
            InMemoryStorage::new(),
        )),
    })
    .await
    .expect("registrar");
    let shutdown = tokio_util::sync::CancellationToken::new();
    let task = registrar.spawn_trigger(Arc::clone(&n.supervisor), shutdown.clone());

    let (_, blob) = tokio::time::timeout(Duration::from_secs(20), rx.recv())
        .await
        .expect("the start registration")
        .expect("publisher alive");
    let start = PushRegistration::from_msgpack(&blob).expect("a registration");
    assert!(start.routing_ids.contains(&V1_RID));

    n.clock.set(T0 + INTERVAL);
    n.rotate(ctx, 1, RID_1).await.expect("the rotation commits");

    let (url, blob) = tokio::time::timeout(Duration::from_secs(20), rx.recv())
        .await
        .expect("a registration after the rotation")
        .expect("publisher alive");
    assert_eq!(url, scp_did::canonical_relay_url(RELAY).expect("canonical"));
    let after = PushRegistration::from_msgpack(&blob).expect("a registration");
    assert!(after.routing_ids.contains(&RID_1), "the new routing ID");
    assert!(!after.routing_ids.contains(&V1_RID), "not the old one");
    assert!(
        tokio::time::timeout(Duration::from_millis(700), rx.recv())
            .await
            .is_err(),
        "exactly one registration follows the rotation"
    );

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(20), task.into_join_handle())
        .await
        .expect("the task stops")
        .expect("the task ends cleanly");
}

/// §25.19 Vector 58: the announcement plaintext a v2 member sends is
/// byte-equal to both golden encodings; a v1 member sends the v1 form.
#[test]
fn the_announcement_plaintext_matches_vector_58() {
    const MEMBER: &str = "scp:z5glr2inbuzd33xrfkdgpjejz4x7z4r2jxcsfvdxbwtgoi73xx2q";
    const EPOCH_1: &str = "84a3746167ba007363703a70736575646f6e796d2d616e6e6f756e63653a7632aa6d656d6265725f646964d9387363703a7a35676c7232696e62757a6433337872666b6467706a656a7a3478377a3472326a78637366766478627774676f69373378783271af70736575646f6e796d5f65706f636801aa726f7574696e675f6964c4204343434343434343434343434343434343434343434343434343434343434343";
    const EPOCH_2_32: &str = "84a3746167ba007363703a70736575646f6e796d2d616e6e6f756e63653a7632aa6d656d6265725f646964d9387363703a7a35676c7232696e62757a6433337872666b6467706a656a7a3478377a3472326a78637366766478627774676f69373378783271af70736575646f6e796d5f65706f6368cf0000000100000000aa726f7574696e675f6964c4204343434343434343434343434343434343434343434343434343434343434343";
    let encode = |epoch| {
        hex::encode(
            crate::context::messaging_helpers::encode_local_announcement(MEMBER, [0x43; 32], epoch)
                .expect("encodes"),
        )
    };
    assert_eq!(encode(Some(1)), EPOCH_1);
    assert_eq!(encode(Some(1 << 32)), EPOCH_2_32);
    let v1 = crate::context::messaging_helpers::encode_local_announcement(MEMBER, [0x42; 32], None)
        .expect("encodes");
    let decoded: scp_protocol::context::pseudonym::PseudonymAnnouncement =
        rmp_serde::from_slice(&v1).expect("a v1 member sends the v1 form");
    assert_eq!(decoded.pseudonym, [0x42; 32]);
}

/// Every rejected rotation leaves the routing IDs, the persisted snapshot,
/// the transport and the event stream untouched.
#[tokio::test]
async fn rejected_rotations_change_nothing_and_send_nothing() {
    let mut n = node();
    let ctx = &cid("rotation-rejects");
    n.create(ctx, params(Some(interval_policy()))).await;
    n.supervisor
        .seed_peer_pseudonym(ctx, bob(), [0x42; 32])
        .await
        .expect("record a peer routing ID");
    n.clock.set(T0 + INTERVAL);
    n.drain();
    let before = n.ids(ctx).await;
    let writes = n.store.settled_writes().await;
    let sent = n.sent.count();

    let invalid = |r: Result<(), ContextError>, what: &str| {
        assert!(
            matches!(r, Err(ContextError::InvalidState(_))),
            "{what} must be InvalidState: {r:?}"
        );
    };
    invalid(
        n.rotate(ctx, 2, RID_1).await,
        "an epoch past the admissible one",
    );
    invalid(
        n.rotate(ctx, 0, RID_1).await,
        "an epoch before the admissible one",
    );
    invalid(n.rotate(ctx, 1, [0; 32]).await, "the zero routing ID");
    invalid(
        n.rotate(ctx, 1, context_routing_id(ctx)).await,
        "the shared context routing ID",
    );
    invalid(
        n.rotate(ctx, 1, scp_protocol::context::broadcast_routing_id(ctx))
            .await,
        "the broadcast routing ID",
    );
    invalid(n.rotate(ctx, 1, V1_RID).await, "the current routing ID");
    invalid(n.rotate(ctx, 1, [0x42; 32]).await, "a peer's routing ID");

    let foreign = n
        .supervisor
        .rotate_pseudonym(
            ctx,
            &bob(),
            &CommandSigner::local_ed25519(bob_key()),
            1,
            RID_1,
        )
        .await;
    assert!(
        matches!(foreign, Err(ContextError::PermissionDenied(_))),
        "a member rotates only its own pseudonym: {foreign:?}"
    );

    assert_eq!(
        n.ids(ctx).await,
        before,
        "no rejected rotation changed state"
    );
    assert_eq!(
        n.store.writes.load(Ordering::SeqCst),
        writes,
        "nothing persisted"
    );
    assert_eq!(n.sent.count(), sent, "nothing sent");
    let events = n.collect_for(Duration::from_millis(200)).await;
    assert!(rotated(&events).is_empty(), "no rotation event: {events:?}");

    // A routing ID on the query-only list is also rejected, at the next
    // boundary, where epoch 2 is due.
    n.rotate(ctx, 1, RID_1)
        .await
        .expect("an admissible rotation");
    n.clock.set(T0 + 2 * INTERVAL);
    invalid(n.rotate(ctx, 2, V1_RID).await, "a query-only routing ID");
}

/// §9.10.4.1 "no caller action starts a rotation": `rotate_pseudonym` commits
/// only the rotation the schedule makes due. Before the first boundary and
/// between boundaries it refuses the epoch `next_pseudonym_epoch` reports,
/// and changes, persists and sends nothing; at the boundary the same call
/// commits.
#[tokio::test]
async fn a_rotation_off_the_schedule_is_refused() {
    let n = node();
    let ctx = &cid("rotation-off-schedule");
    n.create(ctx, params(Some(interval_policy()))).await;

    let refused = |r: Result<(), ContextError>, what: &str| {
        assert!(
            matches!(r, Err(ContextError::InvalidState(_))),
            "{what} must be InvalidState: {r:?}"
        );
    };
    let writes = n.store.settled_writes().await;
    let sent = n.sent.count();
    let before = n.ids(ctx).await;
    assert_eq!(before.next_pseudonym_epoch, Some(0));
    refused(
        n.rotate(ctx, 0, RID_1).await,
        "a rotation before the first boundary",
    );
    assert_eq!(n.ids(ctx).await, before, "nothing changed");
    assert_eq!(
        n.store.writes.load(Ordering::SeqCst),
        writes,
        "nothing persisted"
    );
    assert_eq!(n.sent.count(), sent, "nothing sent");

    n.clock.set(T0 + INTERVAL);
    n.rotate(ctx, 1, RID_1)
        .await
        .expect("the rotation due at the first boundary commits");

    n.clock.set(T0 + INTERVAL + 60);
    let mid = n.ids(ctx).await;
    assert_eq!(mid.next_pseudonym_epoch, Some(2));
    let writes = n.store.settled_writes().await;
    let sent = n.sent.count();
    refused(
        n.rotate(ctx, 2, RID_2).await,
        "a rotation between boundaries",
    );
    assert_eq!(n.ids(ctx).await, mid, "nothing changed");
    assert_eq!(
        n.store.writes.load(Ordering::SeqCst),
        writes,
        "nothing persisted"
    );
    assert_eq!(n.sent.count(), sent, "nothing sent");

    n.clock.set(T0 + 2 * INTERVAL);
    n.rotate(ctx, 2, RID_2)
        .await
        .expect("the rotation due at the second boundary commits");
    assert_eq!(n.ids(ctx).await.current, RID_2);
}

/// Rotation is opt-in: a v1 member of a context without a policy has no
/// admissible rotation, and a broadcast context has no local routing ID.
#[tokio::test]
async fn no_policy_admits_no_rotation_and_a_broadcast_context_has_no_routing_ids() {
    let n = node();
    let ctx = &cid("rotation-opt-in");
    n.create(ctx, params(None)).await;
    n.clock.set(T0 + 1_000 * INTERVAL);
    assert_eq!(n.ids(ctx).await.next_pseudonym_epoch, None);
    let r = n.rotate(ctx, 0, RID_1).await;
    assert!(matches!(r, Err(ContextError::InvalidState(_))), "{r:?}");

    let bctx = &cid("rotation-broadcast");
    n.supervisor
        .create_context(
            bctx.to_owned(),
            ContextParams {
                mode: ContextMode::Broadcast,
                memory_scope: scp_protocol::context::params::MemoryScope::Full,
                ceiling: vec![Capability::MessagesRead],
                ..ContextParams::default()
            },
            local(),
            None,
            Vec::new(),
        )
        .await
        .expect("create a broadcast context");
    let ids = n.supervisor.local_routing_ids(bctx).await;
    assert!(
        matches!(ids, Err(ContextError::NotPseudonymousContext { .. })),
        "{ids:?}"
    );
    let r = n.rotate(bctx, 0, RID_1).await;
    assert!(
        matches!(r, Err(ContextError::NotPseudonymousContext { .. })),
        "{r:?}"
    );
    let unknown = n
        .supervisor
        .local_routing_ids(&cid("rotation-unknown"))
        .await;
    assert!(
        unknown.is_err(),
        "an unknown context is an error: {unknown:?}"
    );
}

/// §9.10.4.1 step 2 is fail-closed: a failed persist leaves the epoch and
/// routing IDs unchanged, emits nothing and sends nothing; the same rotation
/// succeeds once persistence recovers.
#[tokio::test]
async fn a_failed_rotation_persist_changes_nothing_and_sends_nothing() {
    let mut n = node();
    let ctx = &cid("rotation-persist-fails");
    n.create(ctx, params(Some(interval_policy()))).await;
    n.clock.set(T0 + INTERVAL);
    n.drain();
    let before = n.ids(ctx).await;
    let persisted_before = n.store.snapshot(ctx).pseudonym_rotation;
    let sent = n.sent.count();

    n.store.fail_writes.store(true, Ordering::SeqCst);
    let r = n.rotate(ctx, 1, RID_1).await;
    assert!(
        matches!(r, Err(ContextError::PersistenceFailed(_))),
        "{r:?}"
    );
    n.store.fail_writes.store(false, Ordering::SeqCst);

    assert_eq!(n.ids(ctx).await, before, "the live state is restored");
    assert_eq!(n.store.snapshot(ctx).pseudonym_rotation, persisted_before);
    assert_eq!(n.sent.count(), sent, "nothing is sent");
    let events = n.collect_for(Duration::from_millis(200)).await;
    assert!(rotated(&events).is_empty(), "{events:?}");

    n.rotate(ctx, 1, RID_1).await.expect("the retry commits");
    assert_eq!(n.ids(ctx).await.current, RID_1);
}

/// A failed announcement leaves the committed rotation with
/// `announce_pending` set; the rotation arm signals
/// `PseudonymAnnouncementPending`, never a second rotation, and the
/// re-published announcement clears the flag.
#[tokio::test]
async fn a_failed_announcement_stays_pending_and_the_republish_clears_it() {
    let mut n = node();
    let ctx = &cid("rotation-announce-fails");
    let handle = n.create(ctx, params(Some(interval_policy()))).await;
    n.clock.set(T0 + INTERVAL);
    n.drain();

    n.sent.fail_sends.store(true, Ordering::SeqCst);
    let r = n.rotate(ctx, 1, RID_1).await;
    assert!(r.is_err(), "the announcement failure is reported: {r:?}");
    let ids = n.ids(ctx).await;
    assert_eq!(ids.current, RID_1, "the rotation stays committed");
    assert_eq!(ids.pseudonym_epoch, Some(1));
    assert!(ids.announce_pending);
    assert!(n.store.snapshot(ctx).pseudonym_rotation.announce_pending());

    let signal = n
        .wait_for(PROMPT, |e| pending(e).or_else(|| due(e).map(|_| u64::MAX)))
        .await;
    assert_eq!(signal, Some(1), "the arm signals the pending announcement");

    n.sent.fail_sends.store(false, Ordering::SeqCst);
    republish(&n.supervisor, &handle)
        .await
        .expect("the re-publish succeeds");
    let ids = n.ids(ctx).await;
    assert!(!ids.announce_pending);
    assert_eq!(ids.pseudonym_epoch, Some(1), "no second rotation");
    assert!(!n.store.snapshot(ctx).pseudonym_rotation.announce_pending());
}

/// Dispatches `SendPseudonymAnnouncement`, the bridge's re-publish path.
async fn republish(supervisor: &Supervisor, handle: &ContextHandle) -> Result<(), ContextError> {
    use crate::context::actor::commands::{MessagingCommand, SendPseudonymAnnouncementPayload};
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = MessagingCommand::SendPseudonymAnnouncement {
        payload: Box::new(SendPseudonymAnnouncementPayload {
            context_id: handle.context_id().to_owned(),
            params: handle.params().clone(),
            sender_did: local(),
            signer: crate::context::actor::signer::CommandSigner::local_ed25519(local_key()),
        }),
        reply: tx,
    };
    supervisor
        .dispatch_command(handle.context_id(), cmd)
        .await?;
    rx.await
        .map_err(|_| ContextError::TransportFailed("reply dropped".to_owned()))?
}

// ---------------------------------------------------------------------------
// Rotation arm: schedule, membership trigger, governance re-anchor
// ---------------------------------------------------------------------------

/// §9.10.4.1 "Epoch schedule": with no policy, nothing is signalled across a
/// thousand interval lengths.
#[tokio::test(start_paused = true)]
async fn nothing_is_signalled_without_a_policy_over_a_thousand_periods() {
    let mut n = node();
    let ctx = &cid("rotation-none");
    n.create(ctx, params(None)).await;
    n.clock.set(T0 + 1_000 * INTERVAL);
    let events = n.collect_for(Duration::from_secs(1_000 * INTERVAL)).await;
    assert!(
        !events.iter().any(is_rotation_signal),
        "rotation is opt-in: {events:?}"
    );
}

/// The arm signals `PseudonymRotationDue` at each boundary `T0 + j × I`
/// (j = 1, 2, 3) with the epoch the rotation must carry, repeats an
/// unanswered signal after the backoff, and is silent between a committed
/// rotation and the next boundary.
#[tokio::test(start_paused = true)]
async fn the_arm_signals_each_boundary_and_repeats_until_the_epoch_advances() {
    let mut n = node();
    let ctx = &cid("rotation-schedule");
    n.create(ctx, params(Some(interval_policy()))).await;

    let early = n.collect_for(Duration::from_secs(INTERVAL - 60)).await;
    assert!(
        !early.iter().any(is_rotation_signal),
        "nothing is due before the first boundary: {early:?}"
    );

    for (j, rid) in [(1u64, RID_1), (2, RID_2), (3, [0x63; 32])] {
        n.clock.set(T0 + j * INTERVAL);
        let epoch = n
            .wait_for(Duration::from_secs(2 * INTERVAL), due)
            .await
            .expect("the boundary signals a rotation");
        assert_eq!(epoch, j, "boundary j = {j} carries epoch {j}");

        if j == 1 {
            // Unanswered: the signal repeats after the backoff.
            n.clock.advance(30);
            let again = n.wait_for(Duration::from_secs(120), due).await;
            assert_eq!(again, Some(1), "an unanswered signal repeats");
        }

        n.rotate(ctx, j, rid).await.expect("the rotation commits");
        let quiet = n.collect_for(Duration::from_secs(INTERVAL / 2)).await;
        assert!(
            !quiet.iter().any(is_rotation_signal),
            "a committed rotation silences the arm until the next boundary: {quiet:?}"
        );
    }
}

/// §9.10.4.1 "Membership trigger": under `on_membership_change`, a committed
/// `AddMember` and a committed `RemoveMember` of another member each make one
/// rotation due.
#[tokio::test]
async fn adding_and_removing_another_member_each_trigger_one_rotation() {
    let mut n = node();
    let ctx = &cid("rotation-membership");
    n.create(ctx, params(Some(membership_policy()))).await;
    let quiet = n.collect_for(Duration::from_millis(200)).await;
    assert!(!quiet.iter().any(is_rotation_signal), "{quiet:?}");

    n.govern(
        ctx,
        GovernanceAction::AddMember {
            did: bob(),
            role: "member".to_owned(),
        },
    )
    .await;
    assert_eq!(
        n.wait_for(PROMPT, due).await,
        Some(0),
        "an add makes a v1 member's first rotation due at k = 0"
    );
    n.rotate(ctx, 0, RID_1).await.expect("the rotation commits");
    let quiet = n.collect_for(Duration::from_millis(200)).await;
    assert!(!quiet.iter().any(is_rotation_signal), "{quiet:?}");

    n.govern(
        ctx,
        GovernanceAction::RemoveMember {
            did: bob(),
            reason: None,
        },
    )
    .await;
    assert_eq!(
        n.wait_for(PROMPT, due).await,
        Some(1),
        "a removal triggers one rotation"
    );
}

/// §9.10.4.1 "First v2 derivation": enabling rotation on a live context
/// anchors the schedule at the governance commit, so boundaries already
/// passed trigger nothing and the v1 member's next rotation derives at the
/// schedule index.
#[tokio::test]
async fn enabling_rotation_anchors_the_schedule_at_the_commit() {
    let mut n = node();
    let ctx = &cid("rotation-reanchor");
    n.create(ctx, params(None)).await;
    n.clock.set(T0 + 2 * INTERVAL + INTERVAL / 2);
    n.govern(
        ctx,
        GovernanceAction::ModifyPseudonymRotationPolicy {
            new_policy: Some(interval_policy()),
        },
    )
    .await;
    let quiet = n.collect_for(Duration::from_millis(300)).await;
    assert!(
        !quiet.iter().any(is_rotation_signal),
        "passed boundaries trigger nothing: {quiet:?}"
    );
    assert_eq!(n.store.snapshot(ctx).pseudonym_rotation.boundary_index, 2);
    assert_eq!(n.ids(ctx).await.next_pseudonym_epoch, Some(2));
}

// ---------------------------------------------------------------------------
// Leave, close and expiry
// ---------------------------------------------------------------------------

/// §9.10.4.1 "Leave, close and expiry": each discards the query-only list
/// and the pending work.
#[tokio::test]
async fn leave_close_and_expiry_discard_the_rotation_state() {
    for (name, how) in [
        ("rotation-discard-leave", "leave"),
        ("rotation-discard-close", "close"),
        ("rotation-discard-expiry", "expiry"),
    ] {
        let ctx = &cid(name);
        let n = node();
        let mut p = params(Some(interval_policy()));
        p.ttl = Some(Duration::from_secs(100 * INTERVAL));
        let handle = n.create(ctx, p).await;
        n.govern(
            ctx,
            GovernanceAction::AddMember {
                did: bob(),
                role: "admin".to_owned(),
            },
        )
        .await;
        n.clock.set(T0 + INTERVAL);
        n.sent.fail_sends.store(true, Ordering::SeqCst);
        let _ = n.rotate(ctx, 1, RID_1).await;
        n.sent.fail_sends.store(false, Ordering::SeqCst);
        let held = n.store.snapshot(ctx).pseudonym_rotation;
        assert!(
            !held.query_only.is_empty() && held.announce_pending(),
            "{ctx}"
        );

        match how {
            "leave" => n
                .supervisor
                .leave_context(&handle, &local(), &local())
                .await
                .expect("the local member leaves"),
            "close" => {
                n.govern(ctx, GovernanceAction::CloseContext { reason: None })
                    .await;
            }
            _ => {
                use crate::context::actor::commands::{TtlCloseCommand, TtlContextPayload};
                let (tx, rx) = tokio::sync::oneshot::channel();
                n.supervisor
                    .dispatch_ttl_close_command(TtlCloseCommand::ExecuteTtlClose {
                        payload: Box::new(TtlContextPayload {
                            context_id: ctx.to_owned(),
                            params: handle.params().clone(),
                        }),
                        reply: tx,
                    })
                    .await
                    .expect("dispatch the expiry");
                rx.await.expect("reply").expect("the context expires");
            }
        }
        let after = n.store.snapshot(ctx).pseudonym_rotation;
        assert!(
            after.query_only.is_empty(),
            "{how} discards the query-only list"
        );
        assert!(
            !after.announce_pending(),
            "{how} discards the pending announcement"
        );
    }
}

// ---------------------------------------------------------------------------
// Crash recovery through `restore_all_contexts`
// ---------------------------------------------------------------------------

/// Restarts a node on a copy of `from`'s snapshots at the same wall clock
/// and restores every context through the production startup sweep.
async fn restart(from: &Node) -> Node {
    let restarted = node_on(from.store.copy(), Arc::clone(&from.clock));
    let ids = restarted
        .supervisor
        .restore_all_contexts()
        .await
        .expect("restore_all_contexts")
        .into_ids();
    assert!(!ids.is_empty(), "the contexts restore");
    restarted
}

/// A crash after the fail-closed persist (step 2) and before the
/// announcement (step 4) restores the completed rotation with
/// `announce_pending` set: the arm signals the pending announcement for the
/// persisted epoch, never a second rotation, and the previous routing ID is
/// on the query-only list.
#[tokio::test]
async fn a_crash_between_persist_and_announce_restores_the_rotation_and_republishes() {
    let n = node();
    let ctx = &cid("rotation-crash-after-persist");
    let handle = n.create(ctx, params(Some(interval_policy()))).await;
    n.clock.set(T0 + INTERVAL);
    n.sent.fail_sends.store(true, Ordering::SeqCst);
    let _ = n.rotate(ctx, 1, RID_1).await;
    assert!(n.store.snapshot(ctx).pseudonym_rotation.announce_pending());

    let mut r = restart(&n).await;
    let ids = r.ids(ctx).await;
    assert_eq!(ids.current, RID_1);
    assert_eq!(ids.pseudonym_epoch, Some(1));
    assert!(ids.announce_pending);
    assert_eq!(
        ids.query_only
            .iter()
            .map(|e| e.routing_id)
            .collect::<Vec<_>>(),
        vec![V1_RID]
    );

    let signal = r
        .wait_for(PROMPT, |e| pending(e).or_else(|| due(e).map(|_| u64::MAX)))
        .await;
    assert_eq!(
        signal,
        Some(1),
        "the restored node re-publishes, not re-rotates"
    );
    republish(&r.supervisor, &handle)
        .await
        .expect("the re-publish succeeds");
    let ids = r.ids(ctx).await;
    assert!(!ids.announce_pending);
    assert_eq!(ids.pseudonym_epoch, Some(1), "no rotation was duplicated");
    assert_eq!(r.sent.count(), 1, "the re-publish is the one announcement");
}

/// A crash before the persist (step 2) restores the old state; the arm then
/// signals one rotation for the boundaries missed while down, at the current
/// schedule index, and a committed rotation answers all of them.
#[tokio::test]
async fn a_crash_before_persist_restores_the_old_state_and_signals_one_rotation() {
    let n = node();
    let ctx = &cid("rotation-crash-before-persist");
    n.create(ctx, params(Some(interval_policy()))).await;
    n.clock.set(T0 + INTERVAL);
    n.store.fail_writes.store(true, Ordering::SeqCst);
    let _ = n.rotate(ctx, 1, RID_1).await;
    n.store.fail_writes.store(false, Ordering::SeqCst);

    // Down across four more boundaries.
    n.clock.set(T0 + 5 * INTERVAL + 10);
    let mut r = restart(&n).await;
    let ids = r.ids(ctx).await;
    assert_eq!(
        ids.current, V1_RID,
        "nothing of the failed rotation survives"
    );
    assert_eq!(ids.pseudonym_epoch, None);
    assert_eq!(ids.next_pseudonym_epoch, Some(5));

    let signals = r.collect_for(Duration::from_millis(500)).await;
    let dues: Vec<u64> = signals.iter().filter_map(due).collect();
    assert_eq!(dues, vec![5], "missed boundaries make one rotation due");

    r.rotate(ctx, 5, RID_1).await.expect("the rotation commits");
    let quiet = r.collect_for(Duration::from_millis(300)).await;
    assert!(!quiet.iter().any(is_rotation_signal), "{quiet:?}");
}

/// A crash after the announcement (step 4) and before the flag is cleared
/// (step 5) restores with `announce_pending` set; the re-published
/// announcement repeats the same epoch and routing ID, which is the
/// idempotent same-epoch case for peers.
#[tokio::test]
async fn a_crash_before_the_flag_clears_republishes_the_same_epoch_and_routing_id() {
    let n = node();
    let ctx = &cid("rotation-crash-after-announce");
    let handle = n.create(ctx, params(Some(interval_policy()))).await;
    n.clock.set(T0 + INTERVAL);
    n.rotate(ctx, 1, RID_1).await.expect("the rotation commits");
    // Model step 5 never persisting: the snapshot keeps the step-2 flag.
    n.store
        .contexts
        .get_mut(ctx.as_str())
        .unwrap()
        .pseudonym_rotation
        .announce_pending = true;

    let mut r = restart(&n).await;
    let signal = r
        .wait_for(PROMPT, |e| pending(e).or_else(|| due(e).map(|_| u64::MAX)))
        .await;
    assert_eq!(signal, Some(1));
    republish(&r.supervisor, &handle)
        .await
        .expect("the re-publish succeeds");
    let ids = r.ids(ctx).await;
    assert_eq!((ids.pseudonym_epoch, ids.current), (Some(1), RID_1));
    assert!(!ids.announce_pending);
}
