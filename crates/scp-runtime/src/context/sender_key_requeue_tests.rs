//! A sender-key distribution whose publish fails (spec 09 §9.16.9 "A
//! distribution whose publish fails"; spec 05 §5.15.3).
//!
//! The queue tests stand Alice up as the creator of a real two-party MLS pair
//! (`stand_up_two_party`), in a `ClassSCell` with production `ActorDeps` over
//! a snapshot store, a `TestClock`, an event channel, and a transport whose
//! `send_message` fails while a switch is set. Her queued distribution to Bob
//! is built by the production `distribute_sender_key`, and every pass runs
//! through a production entry point: the `SendQueuedSenderKeys` handler, the
//! governance timer (`evaluate_governance_timeouts`), or the drain itself.
//!
//! - A failed publish keeps the distribution in the persisted snapshot, and a
//!   restored actor's timer publishes it.
//! - A failed publish reports `SenderKeyDistributionPending` on the receive
//!   buffer and the event channel; the re-send request returns the report.
//! - A pass after an operation publishes only entries never attempted; the
//!   timer retries the failed one with the TTL that remains of its first
//!   attempt.
//! - A distribution whose TTL is spent, or that MLS cannot seal, is dropped
//!   and reported with its attempt count.
//! - A distribution supersedes the one queued to the same target and key.
//! - `seal` refuses the current epoch while a distribution of it is pending.
//! - Removing a member purges its queued distributions in the same persist.
//! - The receive path answers no `SenderKeyRequest` from a read-revoked
//!   member (spec 09 §9.16.10).
//!
//! The operation tests drive each of the six operations that rotate or
//! distribute (join, Add, leave, Remove, reset, write revoke) through the
//! Supervisor with the relay down: the operation returns `Ok`, the persisted
//! snapshot holds the distribution, and `SenderKeyDistributionPending` reaches
//! the event channel. A read revoke drops the member's queued distributions
//! in its persist and no later rotation queues one to it. A leave or write
//! revoke whose rotation step fails returns that typed error, and the
//! operation stands.

#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use dashmap::DashMap;
use scp_clock::{Clock, TestClock};
use scp_did::DID;
use scp_protocol::context::builder::ContextCreationError;
use scp_protocol::context::membership::ContextEvent;
use scp_protocol::context::params::ContextParams;
use scp_protocol::context::roles::Capability;
use scp_protocol::context::{ContextError, ContextState};
use scp_protocol::envelope::outer::BlobTtl;

use crate::context::ContextHandle;
use crate::context::actor::class_s::ClassSCell;
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::state::{DistributionFault, PerContextState};
use crate::context::builder::{ContextEventLogProvider, ContextTransportProvider};
use crate::context::lifecycle_helpers::{DistributionScope, drain_and_deliver_sender_keys};
use crate::context::persistence::ContextPersistence;
use crate::context::state::ContextSnapshot;
use crate::context::supervisor::supervisor::Supervisor;
use crate::crypto::mls::provider::{NodeMlsFactory, PendingDistribution};

const ALICE: &str = "did:dht:z6MkAliceSenderKeyRequeueAliceSenderKeyRe1";
const BOB: &str = "did:dht:z6MkBobSenderKeyRequeueBobSenderKeyRequeu1";
const T0: u64 = 1_800_000_000;

type PersistErr = Box<dyn std::error::Error + Send + Sync>;
type EventRx = tokio::sync::broadcast::Receiver<(String, ContextEvent)>;

#[derive(Default)]
struct Store(DashMap<String, ContextSnapshot>, AtomicBool);

/// The local sender-key epoch a snapshot carries, if it carries crypto.
fn snapshot_sender_epoch(ctx: &str, s: &ContextSnapshot) -> Option<u64> {
    NodeMlsFactory::build_restored_owned(
        &scp_protocol::context::context_id_bytes(ctx),
        &s.mls_crypto_state.0,
    )
    .ok()
    .map(|(owned, _floors)| owned.sender_key_epoch)
}

impl Store {
    /// Arms a one-shot refusal of the next persist that raises the local
    /// sender-key epoch: only a rotation's Class-S step raises it.
    fn refuse_next_rotation(&self) {
        self.1.store(true, Ordering::SeqCst);
    }

    /// Whether the armed refusal takes this persist (and disarms).
    fn refuses(&self, id: &str, s: &ContextSnapshot) -> bool {
        if !self.1.load(Ordering::SeqCst) {
            return false;
        }
        let old = self
            .0
            .get(id)
            .and_then(|prev| snapshot_sender_epoch(id, prev.value()));
        let new = snapshot_sender_epoch(id, s);
        let bumps = matches!((old, new), (Some(o), Some(n)) if n > o);
        if bumps {
            self.1.store(false, Ordering::SeqCst);
        }
        bumps
    }

    /// The distribution queue of the one persisted snapshot of `ctx`.
    fn queue(&self, ctx: &str) -> Vec<PendingDistribution> {
        let snapshot = self
            .0
            .get(ctx)
            .map(|s| s.value().clone())
            .expect("a persisted snapshot of the context");
        let (owned, _floors) = NodeMlsFactory::build_restored_owned(
            &scp_protocol::context::context_id_bytes(ctx),
            &snapshot.mls_crypto_state.0,
        )
        .expect("restore the crypto blob");
        owned.pending_distributions
    }
}

struct SharedStore(Arc<Store>);

#[async_trait::async_trait]
impl ContextPersistence for SharedStore {
    async fn persist_context(&self, id: &str, s: &ContextSnapshot) -> Result<(), PersistErr> {
        if self.0.refuses(id, s) {
            return Err("the store refuses the rotation's persist".into());
        }
        self.0.0.insert(id.to_owned(), s.clone());
        Ok(())
    }
    async fn load_context(&self, id: &str) -> Result<Option<ContextSnapshot>, PersistErr> {
        Ok(self.0.0.get(id).map(|s| s.value().clone()))
    }
    async fn delete_context(&self, id: &str) -> Result<(), PersistErr> {
        self.0.0.remove(id);
        Ok(())
    }
    async fn list_persisted_contexts(&self) -> Result<Vec<String>, PersistErr> {
        Ok(self.0.0.iter().map(|e| e.key().clone()).collect())
    }
}

/// The relay: every accepted publish with its TTL, and a switch that fails
/// each `send_message` while set.
#[derive(Default)]
struct Relay {
    down: AtomicBool,
    next: AtomicU64,
    accepted: DashMap<u64, (Vec<u8>, u32)>,
}

impl Relay {
    /// Accepted publishes in publish order.
    fn accepted(&self) -> Vec<(Vec<u8>, u32)> {
        let mut keys: Vec<u64> = self.accepted.iter().map(|e| *e.key()).collect();
        keys.sort_unstable();
        keys.into_iter()
            .filter_map(|k| self.accepted.get(&k).map(|e| e.value().clone()))
            .collect()
    }
}

struct RelayTransport(Arc<Relay>);

#[async_trait::async_trait]
impl ContextTransportProvider for RelayTransport {
    fn is_connected(&self) -> bool {
        !self.0.down.load(Ordering::SeqCst)
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
        _id: &[u8; 32],
        payload: &[u8],
        ttl: BlobTtl,
    ) -> Result<(), ContextError> {
        if self.0.down.load(Ordering::SeqCst) {
            return Err(ContextError::TransportFailed("relay down".to_owned()));
        }
        let n = self.0.next.fetch_add(1, Ordering::SeqCst);
        self.0.accepted.insert(n, (payload.to_vec(), ttl.secs()));
        Ok(())
    }
}

struct OkEventLog;

#[async_trait::async_trait]
impl ContextEventLogProvider for OkEventLog {
    fn event_log_entries(
        &self,
        _context_id: &[u8; 32],
    ) -> Result<Option<Vec<scp_event_log::Event>>, ContextError> {
        Ok(None)
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

/// Alice's cell and deps, the relay her transport reaches, the store her
/// snapshots land in, her event channel, and the clock.
struct Alice {
    cell: ClassSCell,
    deps: ActorDeps,
    /// Held so the deps' weak handle to the supervisor stays live.
    _sup: Arc<Supervisor>,
    relay: Arc<Relay>,
    store: Arc<Store>,
    events: EventRx,
    clock: Arc<TestClock>,
}

async fn alice_deps(
    crypto: Arc<NodeMlsFactory>,
    relay: &Arc<Relay>,
    store: &Arc<Store>,
    clock: &Arc<TestClock>,
) -> (ActorDeps, Arc<Supervisor>, EventRx) {
    let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> = Arc::new(
        crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
            scp_platform::in_memory::InMemoryStorage::new(),
        )),
    );
    let clock: Arc<dyn Clock> = Arc::clone(clock) as Arc<dyn Clock>;
    let (event_tx, events) = tokio::sync::broadcast::channel(64);
    let supervisor = Supervisor::with_providers(
        crypto,
        Box::new(RelayTransport(Arc::clone(relay))),
        Box::new(OkEventLog),
        crate::crypto::mls::two_party_test_support::pair_resolver(ALICE, BOB),
        Some(Box::new(SharedStore(Arc::clone(store)))),
        None,
        Some(event_tx),
        Some(clock),
        mls_storage,
    );
    supervisor.register_local_did(DID::from(ALICE)).await;
    let deps = supervisor
        .build_actor_deps_loaded(&DID::from(ALICE))
        .await
        .expect("build actor deps");
    assert!(deps.event_tx.is_some(), "the deps carry the event channel");
    (deps, supervisor, events)
}

/// Makes `state` an active context with Alice and Bob as writing members.
fn activate(state: &mut PerContextState) {
    let params = state.handle.params().clone();
    state.handle = ContextHandle::new(state.handle.context_id().to_owned(), params);
    state
        .handle
        .transition_to(&ContextState::Active)
        .expect("activate the context");
    for did in [ALICE, BOB] {
        state
            .membership
            .add_member(DID::from(did), "member".to_owned(), Vec::new());
        state.members.insert(DID::from(did));
        state.role_state.members.insert(did.to_owned());
        state.role_state.member_capabilities.insert(
            did.to_owned(),
            std::collections::HashSet::from([Capability::MessagesWrite]),
        );
    }
}

/// Alice, active, with one distribution of her sender key to Bob queued by the
/// production `distribute_sender_key`, and the relay down.
async fn alice_with_queued_distribution(ctx: &str) -> Alice {
    let crate::crypto::mls::two_party_test_support::TwoPartyPair {
        alice_provider,
        mut alice_state,
        ..
    } = crate::crypto::mls::two_party_test_support::stand_up_two_party(ctx, ALICE, BOB);
    let relay = Arc::new(Relay::default());
    relay.down.store(true, Ordering::SeqCst);
    let store = Arc::new(Store::default());
    let clock = Arc::new(TestClock::new(T0));
    let (deps, sup, events) = alice_deps(alice_provider, &relay, &store, &clock).await;
    activate(&mut alice_state);
    alice_state
        .distribute_sender_key(ALICE, BOB, None)
        .expect("Alice builds a distribution for Bob");
    assert_eq!(queue(&alice_state).len(), 1, "one distribution queued");
    Alice {
        cell: ClassSCell::new(alice_state),
        deps,
        _sup: sup,
        relay,
        store,
        events,
        clock,
    }
}

fn queue(state: &PerContextState) -> Vec<PendingDistribution> {
    state
        .mode
        .crypto()
        .expect("encrypted mode")
        .pending_distributions
        .clone()
}

/// Queues `message` of `epoch` for `target`, sealed to `recipient_key`,
/// through the production enqueue.
fn enqueue(
    cell: &mut ClassSCell,
    target: &str,
    recipient_key: &[u8],
    epoch: u64,
    message: Vec<u8>,
) {
    let mut view = cell.class_c_view();
    let crypto = view.mode_mut().crypto_mut().expect("encrypted");
    crate::context::actor::state::ContextCryptoState::enqueue_distribution(
        &mut crypto.pending_distributions,
        target.to_owned(),
        recipient_key.to_vec(),
        epoch,
        message,
    );
}

/// Every `SenderKeyDistribution*` event the context recorded on its receive
/// buffer since the last call.
fn distribution_events(cell: &mut ClassSCell) -> Vec<ContextEvent> {
    cell.class_c_view()
        .receive_buffer_mut()
        .drain()
        .into_iter()
        .filter(is_distribution_event)
        .collect()
}

/// Every `SenderKeyDistribution*` event on `rx` since the last call.
fn channel_events(rx: &mut EventRx) -> Vec<ContextEvent> {
    let mut out = Vec::new();
    loop {
        match rx.try_recv() {
            Ok((_, e)) if is_distribution_event(&e) => out.push(e),
            Ok(_) | Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => {}
            Err(_) => return out,
        }
    }
}

const fn is_distribution_event(e: &ContextEvent) -> bool {
    matches!(
        e,
        ContextEvent::SenderKeyDistributionPending { .. }
            | ContextEvent::SenderKeyDistributionFailed { .. }
    )
}

async fn send_queued(
    alice: &mut Alice,
    ctx: &str,
) -> Result<crate::context::actor::state::DistributionReport, ContextError> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let _outcome = crate::context::actor::handlers::messaging::dispatch(
        &mut alice.cell,
        &alice.deps,
        crate::context::actor::commands::MessagingCommand::SendQueuedSenderKeys {
            context_id: ctx.to_owned(),
            reply: tx,
        },
    )
    .await;
    rx.await.expect("send-queued reply")
}

async fn timer_tick(alice: &mut Alice) {
    let _ = crate::context::actor::handlers::governance::evaluate_governance_timeouts(
        &mut alice.cell,
        &alice.deps,
    )
    .await;
}

/// The full TTL of a sealed management publish (`MAX_BLOB_TTL`).
fn full_ttl() -> u32 {
    BlobTtl::republish_sealed_management(T0, T0).unwrap().secs()
}

/// Fails if the export drops the queue (`pending_distributions` not carried
/// into `MlsCryptoSnapshot`) or the restore drops it: the restored actor then
/// has nothing to publish. Also fails if the re-send turns a requeued
/// distribution into an `Err` instead of reporting it.
#[tokio::test]
async fn failed_publish_survives_persist_and_a_restored_timer_publishes_it() {
    let ctx = "sender-key-requeue-survives-restart";
    let mut alice = alice_with_queued_distribution(ctx).await;
    let queued = queue(&alice.cell)[0].clone();

    let report = send_queued(&mut alice, ctx)
        .await
        .expect("a delivery fault is reported, not an error");
    assert_eq!(
        (report.sent, report.requeued(), report.dropped()),
        (0, 1, 0)
    );

    // Persist exactly as the run loop does, then restore into a fresh actor.
    let snapshot = crate::context::messaging_helpers::build_snapshot_for_persist(
        &alice.cell,
        &alice.deps,
        ctx,
    )
    .expect("snapshot");
    let ctx_bytes = scp_protocol::context::context_id_bytes(ctx);
    let (owned, _floors) =
        NodeMlsFactory::build_restored_owned(&ctx_bytes, &snapshot.mls_crypto_state.0)
            .expect("restore the crypto blob");
    let restored_queue = owned.pending_distributions.clone();
    assert_eq!(
        restored_queue.len(),
        1,
        "the persisted queue holds the entry"
    );
    let restored = &restored_queue[0];
    assert_eq!(restored.target_did, BOB);
    assert_eq!(restored.recipient_key, queued.recipient_key);
    assert_eq!(restored.epoch, queued.epoch);
    assert_eq!(restored.message.as_slice(), queued.message.as_slice());
    assert_eq!(restored.first_attempt_at, Some(T0));
    assert_eq!(restored.failed_attempts, 1);

    let mut state = PerContextState::new_for_test_encrypted(ctx_bytes, 0, DID::from(ALICE));
    state.seed_encrypted_crypto_from_owned(owned);
    activate(&mut state);
    alice.cell = ClassSCell::new(state);

    alice.relay.down.store(false, Ordering::SeqCst);
    alice.clock.advance(1);
    timer_tick(&mut alice).await;
    let accepted = alice.relay.accepted();
    assert_eq!(accepted.len(), 1, "the restored timer publishes the entry");
    assert_eq!(
        accepted[0].1,
        full_ttl() - 1,
        "TTL counts from the first attempt"
    );
    assert!(
        queue(&alice.cell).is_empty(),
        "a delivered entry leaves the queue"
    );
}

/// Fails if the drain stops reporting its faults at the mutation: no event
/// on the receive buffer or the event channel reports the requeued
/// distribution.
#[tokio::test]
async fn failed_publish_emits_pending_event_on_buffer_and_channel() {
    let ctx = "sender-key-requeue-pending-event";
    let mut alice = alice_with_queued_distribution(ctx).await;
    let report = drain_and_deliver_sender_keys(
        &alice.deps,
        &mut alice.cell.class_c_view(),
        ctx,
        DistributionScope::All,
    )
    .await;
    assert_eq!(report.sent, 0);
    assert!(matches!(
        report.faults.as_slice(),
        [DistributionFault::Requeued { attempt: 1, .. }]
    ));
    for (source, events) in [
        ("buffer", distribution_events(&mut alice.cell)),
        ("channel", channel_events(&mut alice.events)),
    ] {
        assert!(
            matches!(
                events.as_slice(),
                [ContextEvent::SenderKeyDistributionPending { target_did, attempt: 1, .. }]
                    if target_did.0 == BOB
            ),
            "{source}: got {events:?}"
        );
    }
    let entry = &queue(&alice.cell)[0];
    assert_eq!(entry.first_attempt_at, Some(T0));
    assert_eq!(entry.failed_attempts, 1);
}

/// Fails if the pass after an operation selects a failed entry (it would
/// retry on every operation instead of the timer's cadence) or skips a
/// never-attempted one, or if the timer does not retry the failed entry.
#[tokio::test]
async fn post_operation_pass_skips_a_failed_entry_and_the_timer_retries_it() {
    let ctx = "sender-key-requeue-never-attempted";
    let mut alice = alice_with_queued_distribution(ctx).await;
    let _ = send_queued(&mut alice, ctx).await;
    // A second distribution, never attempted, to another key of Bob's (an
    // answer sealed to a request's ephemeral key).
    enqueue(
        &mut alice.cell,
        BOB,
        &[0x03; 33],
        1,
        b"never attempted".to_vec(),
    );
    alice.relay.down.store(false, Ordering::SeqCst);

    let report = drain_and_deliver_sender_keys(
        &alice.deps,
        &mut alice.cell.class_c_view(),
        ctx,
        DistributionScope::NeverAttempted,
    )
    .await;
    assert_eq!(report.sent, 1);
    assert!(report.faults.is_empty());
    let left = queue(&alice.cell);
    assert_eq!(left.len(), 1, "the failed entry waits");
    assert_eq!(left[0].failed_attempts, 1);
    let accepted = alice.relay.accepted();
    assert_eq!(accepted.len(), 1);

    timer_tick(&mut alice).await;
    assert_eq!(alice.relay.accepted().len(), 2, "the timer retries it");
    assert!(queue(&alice.cell).is_empty());
}

/// Fails if the age cap counts from the current attempt instead of the first
/// (the entry would then be published after `MAX_BLOB_TTL`), or if the drop
/// reports another attempt count than the failed attempts the entry carried.
#[tokio::test]
async fn spent_ttl_drops_the_entry_and_reports_failed() {
    let ctx = "sender-key-requeue-age-cap";
    let mut alice = alice_with_queued_distribution(ctx).await;
    let _ = send_queued(&mut alice, ctx).await;
    let _ = distribution_events(&mut alice.cell);
    alice.relay.down.store(false, Ordering::SeqCst);

    alice.clock.advance(u64::from(full_ttl()));
    timer_tick(&mut alice).await;
    assert!(
        alice.relay.accepted().is_empty(),
        "an expired entry is never published"
    );
    assert!(
        queue(&alice.cell).is_empty(),
        "an expired entry leaves the queue"
    );
    let events = distribution_events(&mut alice.cell);
    assert!(
        matches!(
            events.as_slice(),
            [ContextEvent::SenderKeyDistributionFailed { target_did, reason, attempts: 1 }]
                if target_did.0 == BOB && reason.starts_with("expired:")
        ),
        "got {events:?}"
    );
}

/// Fails if an encrypt failure is skipped instead of reported, keeps the
/// entry, or turns the re-send into an `Err`: an oversized payload can never
/// be sealed.
#[tokio::test]
async fn unsealable_entry_is_dropped_and_reported() {
    let ctx = "sender-key-requeue-unsealable";
    let mut alice = alice_with_queued_distribution(ctx).await;
    alice.relay.down.store(false, Ordering::SeqCst);
    enqueue(
        &mut alice.cell,
        BOB,
        &[0x03; 33],
        1,
        vec![0; scp_protocol::context::builder::MAX_MANAGEMENT_PAYLOAD_SIZE + 1],
    );

    let report = send_queued(&mut alice, ctx)
        .await
        .expect("a dropped distribution is reported, not an error");
    assert_eq!(
        (report.sent, report.requeued(), report.dropped()),
        (1, 0, 1)
    );
    assert_eq!(
        alice.relay.accepted().len(),
        1,
        "the sealable one is published"
    );
    assert!(queue(&alice.cell).is_empty());
    let events = distribution_events(&mut alice.cell);
    assert!(
        matches!(
            events.as_slice(),
            [ContextEvent::SenderKeyDistributionFailed { reason, attempts: 0, .. }]
                if reason.starts_with("unsealable:")
        ),
        "got {events:?}"
    );
}

/// Fails if a distribution to a target and key already queued is appended
/// instead of replacing the queued one, or if the replacement reaches past
/// that target and key.
#[tokio::test]
async fn a_distribution_supersedes_the_one_queued_to_the_same_target_and_key() {
    let ctx = "sender-key-requeue-supersede";
    let mut alice = alice_with_queued_distribution(ctx).await;
    let pushed = queue(&alice.cell)[0].clone();
    for n in 0..3_u8 {
        enqueue(&mut alice.cell, BOB, &[0x03; 33], 1, vec![n]);
    }
    enqueue(&mut alice.cell, BOB, &pushed.recipient_key, 2, vec![0xEE]);
    let left = queue(&alice.cell);
    assert_eq!(left.len(), 2, "one entry per target and key: {left:?}");
    let answer = left
        .iter()
        .find(|p| p.recipient_key == [0x03; 33])
        .expect("the answer entry");
    assert_eq!(answer.message.as_slice(), [2], "the latest answer stays");
    let push = left
        .iter()
        .find(|p| p.recipient_key == pushed.recipient_key)
        .expect("the push entry");
    assert_eq!((push.epoch, push.message.as_slice()), (2, &[0xEE][..]));
}

/// Builds and signs an inner envelope from Alice in `ctx` at `epoch`.
fn alice_inner(ctx: &str, epoch: u64) -> crate::envelope::inner::InnerEnvelope {
    let params = crate::envelope::inner::InnerEnvelopeParams {
        version: scp_protocol::envelope::SCP_PROTOCOL_VERSION,
        context_id: ctx,
        sender_did: ALICE,
        epoch,
        generation: 0,
        sequence: 0,
        timestamp: T0,
        message_type: crate::envelope::inner::MessageType::Content,
        payload: b"hello",
        provenance: None,
        signing_key_id: scp_did::SigningKeyId::Active,
    };
    crate::envelope::inner::sign::create_inner_envelope_raw(
        &params,
        &crate::crypto::mls::two_party_test_support::alice_signing_key(),
    )
    .expect("alice signs the inner envelope")
}

/// Spec 09 §9.16.9: H MUST NOT encrypt under epoch N while a distribution of
/// N has no accepted publish. Fails if `seal` encrypts while the
/// distribution is pending, or still refuses after a relay accepts it.
#[tokio::test]
async fn seal_refuses_the_epoch_of_a_pending_distribution() {
    let ctx = "sender-key-requeue-seal-gate";
    let mut alice = alice_with_queued_distribution(ctx).await;
    let ctx_bytes = scp_protocol::context::context_id_bytes(ctx);
    let epoch = queue(&alice.cell)[0].epoch;
    let inner = alice_inner(ctx, epoch);
    let seal = |cell: &mut ClassSCell| {
        cell.class_c_view()
            .mode_mut()
            .crypto_mut()
            .expect("encrypted")
            .seal(&ctx_bytes, ALICE, &inner, 0)
    };

    let refused = seal(&mut alice.cell);
    assert!(
        matches!(
            &refused,
            Err(ContextError::SenderKeyDistributionPending { target_did, epoch: e })
                if target_did == BOB && *e == epoch
        ),
        "got {refused:?}"
    );

    alice.relay.down.store(false, Ordering::SeqCst);
    let report = send_queued(&mut alice, ctx).await.expect("re-send");
    assert_eq!(report.sent, 1);
    assert!(seal(&mut alice.cell).is_ok(), "the published epoch seals");
}

/// Fails if the removal primitive leaves a departed member's distributions
/// queued, drops another member's, or persists the queue before the purge.
#[tokio::test]
async fn removing_a_member_purges_its_queue_in_the_same_persist() {
    let ctx = "sender-key-requeue-departure";
    let mut alice = alice_with_queued_distribution(ctx).await;
    let other = "did:dht:z6MkOtherSenderKeyRequeueOtherSenderKeyRe1";
    enqueue(&mut alice.cell, BOB, &[0x03; 33], 1, vec![1]);
    enqueue(&mut alice.cell, other, &[0x04; 33], 1, vec![2]);
    alice
        .cell
        .commit_class_s_keep(&alice.deps, ctx, |mut v| {
            v.rest_mut().remove_member_sender_key(BOB)
        })
        .await
        .expect("the removal persists");
    let left = queue(&alice.cell);
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].target_did, other);
    let persisted = alice.store.queue(ctx);
    assert_eq!(persisted.len(), 1, "the persist carries the purge");
    assert_eq!(persisted[0].target_did, other);
}

/// Fails if a member with no wrapping key is skipped in silence, or if the
/// missing key fails the distribution and with it the operation.
#[tokio::test]
async fn a_member_with_no_wrapping_key_is_reported_not_built() {
    let ctx = "sender-key-requeue-not-built";
    let mut alice = alice_with_queued_distribution(ctx).await;
    let carol = "did:dht:z6MkCarolSenderKeyRequeueCarolSenderKeyRe1";
    let tx = alice.deps.event_tx.clone();
    let mut state = alice.cell.into_inner();
    state
        .distribute_sender_key(ALICE, carol, tx.as_ref())
        .expect("no wrapping key is not an error");
    assert_eq!(queue(&state).len(), 1, "nothing queued for Carol");
    let events = channel_events(&mut alice.events);
    assert!(
        matches!(
            events.as_slice(),
            [ContextEvent::SenderKeyDistributionFailed { target_did, reason, attempts: 0 }]
                if target_did.0 == carol && reason.starts_with("not built:")
        ),
        "got {events:?}"
    );
}

/// Bob's signed `SenderKeyRequest` for Alice's key, in its distribution
/// envelope.
fn bob_key_request(nonce: [u8; 16]) -> Vec<u8> {
    use ed25519_dalek::Signer as _;
    use scp_protocol::crypto::sender_keys::key_protocol_verify::{
        RequestHashInput, compute_request_hash,
    };
    use scp_protocol::crypto::sender_keys::{SenderKeyDistributionMessage, SenderKeyRequest};
    let (wrapping_pubkey, _secret) = scp_protocol::crypto::sender_keys::generate_wrapping_keypair();
    let hash = compute_request_hash(
        BOB,
        ALICE,
        &wrapping_pubkey,
        &nonce,
        RequestHashInput {
            epoch: 1,
            requested_at: T0,
        },
    )
    .expect("hash the request");
    let signature = crate::crypto::mls::two_party_test_support::bob_signing_key()
        .sign(&hash)
        .to_bytes();
    SenderKeyDistributionMessage::KeyRequest(SenderKeyRequest {
        requester_did: BOB.to_owned(),
        sender_did: ALICE.to_owned(),
        epoch: 1,
        wrapping_pubkey,
        nonce,
        timestamp: T0,
        signature,
    })
    .to_bytes()
    .expect("encode the request")
}

/// Fails if the production receive path answers a `SenderKeyRequest` from a
/// read-revoked member, or does not answer one from a member that reads
/// (spec 09 §9.16.10).
#[tokio::test]
async fn a_read_revoked_requester_gets_no_answer() {
    let ctx = "sender-key-requeue-read-revoked-request";
    let crate::crypto::mls::two_party_test_support::TwoPartyPair {
        alice_provider,
        mut alice_state,
        mut bob_state,
        ..
    } = crate::crypto::mls::two_party_test_support::stand_up_two_party(ctx, ALICE, BOB);
    let relay = Arc::new(Relay::default());
    let store = Arc::new(Store::default());
    let clock = Arc::new(TestClock::new(T0));
    let (deps, _sup, _events) = alice_deps(alice_provider, &relay, &store, &clock).await;
    activate(&mut alice_state);
    alice_state
        .access
        .read_exclusion_list
        .insert(DID::from(BOB));
    let mut cell = ClassSCell::new(alice_state);
    let bob_cs = bob_state.mode.crypto_mut().expect("encrypted");
    let denied = bob_cs
        .mls_encrypt_management(&bob_key_request([1; 16]))
        .expect("Bob seals the first request");
    let answered = bob_cs
        .mls_encrypt_management(&bob_key_request([2; 16]))
        .expect("Bob seals the second request");
    let answers_to_bob =
        |cell: &ClassSCell| queue(cell).iter().filter(|p| p.target_did == BOB).count();

    let outcome = crate::context::messaging_helpers::deliver_incoming(
        &mut cell.class_c_view(),
        &deps,
        ctx,
        &denied,
        &mut None,
        &mut None,
    )
    .await
    .expect("the request is consumed");
    assert!(matches!(
        outcome,
        crate::context::messaging_helpers::DeliverOutcome::Handled
    ));
    assert_eq!(
        answers_to_bob(&cell),
        0,
        "a read-revoked requester gets none"
    );

    cell.class_c_view()
        .access_mut()
        .read_exclusion_list
        .remove(&DID::from(BOB));
    crate::context::messaging_helpers::deliver_incoming(
        &mut cell.class_c_view(),
        &deps,
        ctx,
        &answered,
        &mut None,
        &mut None,
    )
    .await
    .expect("the request is consumed");
    assert_eq!(answers_to_bob(&cell), 1, "a member that reads is answered");
}

// ---------------------------------------------------------------------------
// The six operations, through the Supervisor, with the relay down.
// ---------------------------------------------------------------------------

mod operations {
    use super::{EventRx, Relay, RelayTransport, SharedStore, Store, channel_events};
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    use ed25519_dalek::SigningKey;
    use scp_did::DID;
    use scp_protocol::context::governance::{AccessScope, GovernanceAction};
    use scp_protocol::context::membership::{ContextEvent, KeyPackage};
    use scp_protocol::context::roles::Capability;
    use scp_protocol::context::{ContextMode, ContextParams};

    use crate::context::ContextHandle;
    use crate::context::actor::CommandSigner;
    use crate::context::builder::NotConfiguredTransportProvider;
    use crate::context::providers::event_log::MerkleEventLogProvider;
    use crate::context::supervisor::supervisor::Supervisor;
    use crate::crypto::mls::provider::NodeMlsFactory;

    const ALICE: &str = "did:dht:z6MkAliceSenderKeyOpsAliceSenderKeyOpsAli1";
    const BOB: &str = "did:dht:z6MkBobSenderKeyOpsBobSenderKeyOpsBobSend1";
    const CAROL: &str = "did:dht:z6MkCarolSenderKeyOpsCarolSenderKeyOpsCa1";

    fn key(did: &str) -> SigningKey {
        let seed = match did {
            ALICE => 0xA7,
            BOB => 0xB7,
            _ => 0xC7,
        };
        SigningKey::from_bytes(&[seed; 32])
    }

    fn signer(did: &str) -> CommandSigner {
        CommandSigner::local_ed25519(key(did))
    }

    fn resolver() -> scp_protocol::context::governance::KeyResolver {
        crate::crypto::mls::test_support::role_resolver(
            &[ALICE, BOB, CAROL].map(|d| (DID::from(d), key(d))),
        )
    }

    fn mls_storage() -> Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> {
        Arc::new(
            crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
                scp_platform::in_memory::InMemoryStorage::new(),
            )),
        )
    }

    fn params() -> ContextParams {
        ContextParams {
            mode: ContextMode::Encrypted,
            ceiling: vec![
                Capability::MessagesRead,
                Capability::MessagesWrite,
                Capability::RoleAssign,
                Capability::MemberInvite,
                Capability::MemberRemove,
                Capability::MemberBan,
                Capability::GovernancePropose,
                Capability::GovernanceVote,
                Capability::ContextClose,
            ],
            ..ContextParams::default()
        }
    }

    /// Alice's node with a relay, a snapshot store and an event channel, and
    /// the context she created.
    struct Node {
        sup: Arc<Supervisor>,
        relay: Arc<Relay>,
        store: Arc<Store>,
        events: EventRx,
        handle: ContextHandle,
        ctx: String,
    }

    async fn alice_node(seed: u8) -> Node {
        let relay = Arc::new(Relay::default());
        let store = Arc::new(Store::default());
        let (event_tx, events) = tokio::sync::broadcast::channel(256);
        let crypto = Arc::new(NodeMlsFactory::new(
            ALICE.to_owned(),
            Arc::new(scp_clock::SystemClock),
        ));
        let sup = Supervisor::with_providers(
            crypto,
            Box::new(RelayTransport(Arc::clone(&relay))),
            Box::new(MerkleEventLogProvider::new()),
            resolver(),
            Some(Box::new(SharedStore(Arc::clone(&store)))),
            None,
            Some(event_tx),
            None,
            mls_storage(),
        );
        let ctx = format!("{seed:02x}").repeat(32);
        let handle = sup
            .create_context(
                ctx.clone(),
                params(),
                DID::from(ALICE),
                Some([0x5a; 32]),
                Vec::new(),
            )
            .await
            .expect("alice creates the context");
        Node {
            sup,
            relay,
            store,
            events,
            handle,
            ctx,
        }
    }

    /// A fresh `KeyPackage` of `did`, reserved from `did`'s own node.
    async fn key_package(did: &str) -> Vec<u8> {
        let sup = Supervisor::with_providers(
            Arc::new(NodeMlsFactory::new(
                did.to_owned(),
                Arc::new(scp_clock::SystemClock),
            )),
            Box::new(NotConfiguredTransportProvider),
            Box::new(MerkleEventLogProvider::new()),
            resolver(),
            None,
            None,
            None,
            None,
            mls_storage(),
        );
        let (_reservation, kp) = sup
            .reserve_key_package(DID::from(did), &signer(did))
            .await
            .expect("reserve a key package");
        kp
    }

    async fn invite(node: &Node, did: &str) {
        node.sup
            .invite_member(
                node.ctx.clone(),
                DID::from(ALICE),
                DID::from(did),
                key_package(did).await,
                &signer(ALICE),
            )
            .await
            .expect("alice adds the member");
    }

    /// Alice's node with Bob and Carol added while the relay was up, every
    /// distribution delivered, the relay then down and the channel drained.
    async fn trio(seed: u8) -> Node {
        let mut node = alice_node(seed).await;
        invite(&node, BOB).await;
        invite(&node, CAROL).await;
        assert!(
            node.store.queue(&node.ctx).is_empty(),
            "every distribution was delivered while the relay was up"
        );
        node.relay.down.store(true, Ordering::SeqCst);
        let _ = channel_events(&mut node.events);
        node
    }

    /// The operation queued a distribution to `target`, the persisted
    /// snapshot holds it, and the event channel reports it pending.
    fn assert_pending_to(node: &mut Node, target: &str) {
        let persisted = node.store.queue(&node.ctx);
        assert!(
            persisted.iter().any(|p| p.target_did == target),
            "the persisted queue holds the distribution to {target}: {persisted:?}"
        );
        let events = channel_events(&mut node.events);
        assert!(
            events.iter().any(|e| matches!(
                e,
                ContextEvent::SenderKeyDistributionPending { target_did, .. } if target_did.0 == target
            )),
            "the channel reports the distribution to {target} pending: {events:?}"
        );
    }

    async fn govern(node: &Node, action: GovernanceAction) {
        let outcome = node
            .sup
            .propose_governance_action_checked(&node.ctx, &DID::from(ALICE), action, &signer(ALICE))
            .await
            .expect("the proposal executes");
        assert!(outcome.execution_result.is_some(), "auto-executed");
    }

    /// Fails if a failed publish after a governance Add fails the Add, or
    /// the distribution is not persisted or not reported.
    #[tokio::test]
    async fn add_with_the_relay_down() {
        let mut node = alice_node(0x31).await;
        node.relay.down.store(true, Ordering::SeqCst);
        invite(&node, BOB).await;
        assert_pending_to(&mut node, BOB);
    }

    /// Fails if a failed publish after a join fails the join, or the
    /// distribution is not persisted or not reported.
    #[tokio::test]
    async fn join_with_the_relay_down() {
        let mut node = alice_node(0x32).await;
        node.relay.down.store(true, Ordering::SeqCst);
        let kp = KeyPackage::new(DID::from(CAROL), key_package(CAROL).await);
        node.sup
            .join_context(&node.handle, kp, None, None)
            .await
            .expect("the join returns Ok");
        assert_pending_to(&mut node, CAROL);
    }

    /// Fails if a failed publish after the leave's rotation fails the leave,
    /// or the rotation's distribution is not persisted or not reported.
    #[tokio::test]
    async fn leave_with_the_relay_down() {
        let mut node = trio(0x33).await;
        node.sup
            .leave_context(&node.handle, &DID::from(ALICE), &DID::from(BOB))
            .await
            .expect("the leave returns Ok");
        assert_pending_to(&mut node, CAROL);
    }

    /// Fails if a failed publish after the Remove's rotation fails the
    /// Remove, or the distribution is not persisted or not reported.
    #[tokio::test]
    async fn remove_with_the_relay_down() {
        let mut node = trio(0x34).await;
        govern(
            &node,
            GovernanceAction::RemoveMember {
                did: DID::from(BOB),
                reason: None,
            },
        )
        .await;
        assert_pending_to(&mut node, CAROL);
    }

    /// Fails if a failed publish after the write revoke's rotation fails the
    /// revoke, or the distribution is not persisted or not reported.
    #[tokio::test]
    async fn write_revoke_with_the_relay_down() {
        let mut node = trio(0x35).await;
        govern(
            &node,
            GovernanceAction::RevokeAccess {
                did: DID::from(BOB),
                access: AccessScope::Write,
            },
        )
        .await;
        assert_pending_to(&mut node, CAROL);
    }

    /// Fails if a failed publish after the reset's rotation fails the reset,
    /// or the distribution is not persisted or not reported.
    #[tokio::test]
    async fn reset_with_the_relay_down() {
        let mut node = trio(0x36).await;
        let kp = key_package(BOB).await;
        let (tx, rx) = tokio::sync::oneshot::channel();
        node.sup
            .dispatch_governance_command(
                crate::context::actor::commands::GovernanceCommand::ProposeGovernanceActionChecked {
                    payload: Box::new(
                        crate::context::actor::commands::ProposeGovernanceActionPayload {
                            context_id: node.ctx.clone(),
                            proposer_did: DID::from(ALICE),
                            action: GovernanceAction::ResetMember {
                                did: DID::from(BOB),
                                reason: "test".to_owned(),
                            },
                            signer: signer(ALICE),
                            key_package: Some(kp),
                        },
                    ),
                    reply: tx,
                },
            )
            .await
            .expect("dispatch the reset");
        let outcome = rx.await.expect("reply").expect("the reset executes");
        assert!(outcome.execution_result.is_some(), "auto-executed");
        assert_pending_to(&mut node, CAROL);
    }

    fn revoke(did: &str, access: AccessScope) -> GovernanceAction {
        GovernanceAction::RevokeAccess {
            did: DID::from(did),
            access,
        }
    }

    /// The highest epoch of a distribution to `target` in the persisted queue.
    fn persisted_epoch_to(node: &Node, target: &str) -> Option<u64> {
        node.store
            .queue(&node.ctx)
            .iter()
            .filter(|p| p.target_did == target)
            .map(|p| p.epoch)
            .max()
    }

    /// Fails if a read revoke leaves the revoked member's queued distribution
    /// in the persist that records the revoke, drops another member's, or a
    /// later rotation queues the new key to the revoked member (spec 09
    /// §9.16.10).
    #[tokio::test]
    async fn read_revoke_purges_and_excludes_the_member() {
        let mut node = trio(0x37).await;
        // A write revoke of Bob rotates with the relay down: a distribution
        // to Carol and one to Bob stay queued.
        govern(&node, revoke(BOB, AccessScope::Write)).await;
        assert_pending_to(&mut node, CAROL);
        let first = persisted_epoch_to(&node, BOB).expect("Bob's distribution queued");

        govern(&node, revoke(CAROL, AccessScope::Read)).await;
        assert_eq!(
            persisted_epoch_to(&node, CAROL),
            None,
            "the persist that records the read revoke drops Carol's distribution"
        );
        assert_eq!(persisted_epoch_to(&node, BOB), Some(first), "Bob's stays");

        // Carol can still write; revoking that rotates the key again.
        govern(&node, revoke(CAROL, AccessScope::Write)).await;
        assert!(
            persisted_epoch_to(&node, BOB).expect("Bob's distribution") > first,
            "the second rotation queued its key to Bob"
        );
        assert_eq!(
            persisted_epoch_to(&node, CAROL),
            None,
            "no rotation after the read revoke queues a key to Carol"
        );
    }

    /// Fails if a write revoke whose rotation step fails returns `Ok`, or if
    /// the revoke does not stand.
    #[tokio::test]
    async fn write_revoke_reports_a_failed_rotation() {
        let node = trio(0x38).await;
        node.store.refuse_next_rotation();
        let err = node
            .sup
            .propose_governance_action_checked(
                &node.ctx,
                &DID::from(ALICE),
                revoke(BOB, AccessScope::Write),
                &signer(ALICE),
            )
            .await
            .expect_err("the failed rotation reaches the caller");
        assert!(
            matches!(
                err,
                scp_protocol::context::ContextError::PersistenceFailed(_)
            ),
            "the rotation's persist error, typed: {err:?}"
        );
        // The revoke stood: the persisted state suspends Bob's write.
        let snapshot = node
            .store
            .0
            .get(&node.ctx)
            .map(|s| s.value().clone())
            .expect("a persisted snapshot");
        assert!(
            snapshot
                .role_state
                .suspended_for(BOB)
                .is_some_and(|s| s.contains(&Capability::MessagesWrite)),
            "Bob's write is suspended durably"
        );
    }

    /// Fails if a leave whose rotation step fails returns `Ok`, or if the
    /// leave does not stand.
    #[tokio::test]
    async fn leave_reports_a_failed_rotation() {
        let node = trio(0x39).await;
        node.store.refuse_next_rotation();
        let err = node
            .sup
            .leave_context(&node.handle, &DID::from(ALICE), &DID::from(BOB))
            .await
            .expect_err("the failed rotation reaches the caller");
        assert!(
            matches!(
                err,
                scp_protocol::context::ContextError::PersistenceFailed(_)
            ),
            "the rotation's persist error, typed: {err:?}"
        );
        let again = node
            .sup
            .leave_context(&node.handle, &DID::from(ALICE), &DID::from(BOB))
            .await;
        assert!(
            matches!(
                again,
                Err(scp_protocol::context::ContextError::MemberNotFound(_))
            ),
            "the leave stood: {again:?}"
        );
    }
}
