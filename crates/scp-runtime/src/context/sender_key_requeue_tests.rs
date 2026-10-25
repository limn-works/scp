//! A sender-key distribution whose publish fails (spec 09 §9.16.9 "A
//! distribution whose publish fails"; spec 05 §5.15.3).
//!
//! Alice is the creator of a real two-party MLS pair (`stand_up_two_party`),
//! in a `ClassSCell` with production `ActorDeps` over a snapshot store, a
//! `TestClock`, and a transport whose `send_message` fails while a switch is
//! set. Her queued distribution to Bob is built by the production
//! `distribute_sender_key`, and every pass runs through a production entry
//! point: the `SendQueuedSenderKeys` handler, the governance timer
//! (`evaluate_governance_timeouts`), or the drain itself.
//!
//! - A failed publish keeps the distribution in the persisted snapshot, and a
//!   restored actor's timer publishes it.
//! - A failed publish reports `SenderKeyDistributionPending`, and the explicit
//!   re-send request returns an error.
//! - The timer publishes only a distribution whose earlier publish failed and
//!   whose backoff has elapsed, with the TTL that remains of its first attempt.
//! - A distribution whose TTL is spent is dropped and reported as
//!   `SenderKeyDistributionFailed`, never published.
//! - A distribution MLS cannot seal is dropped and reported.
//! - The queue holds at most `MAX_PUSH_CHAINS_PER_MEMBER` distributions per
//!   target; the displaced ones are reported.

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
use scp_protocol::crypto::sender_keys::MAX_PUSH_CHAINS_PER_MEMBER;
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

#[derive(Default)]
struct Store(DashMap<String, ContextSnapshot>);

struct SharedStore(Arc<Store>);

#[async_trait::async_trait]
impl ContextPersistence for SharedStore {
    async fn persist_context(&self, id: &str, s: &ContextSnapshot) -> Result<(), PersistErr> {
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

/// Alice's cell and deps, the relay her transport reaches, and the clock.
struct Alice {
    cell: ClassSCell,
    deps: ActorDeps,
    /// Held so the deps' weak handle to the supervisor stays live.
    _sup: Arc<Supervisor>,
    relay: Arc<Relay>,
    clock: Arc<TestClock>,
}

async fn alice_deps(
    crypto: Arc<NodeMlsFactory>,
    relay: &Arc<Relay>,
    clock: &Arc<TestClock>,
) -> (ActorDeps, Arc<Supervisor>) {
    let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> = Arc::new(
        crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
            scp_platform::in_memory::InMemoryStorage::new(),
        )),
    );
    let clock: Arc<dyn Clock> = Arc::clone(clock) as Arc<dyn Clock>;
    let supervisor = Supervisor::with_providers(
        crypto,
        Box::new(RelayTransport(Arc::clone(relay))),
        Box::new(OkEventLog),
        crate::crypto::mls::two_party_test_support::pair_resolver(ALICE, BOB),
        Some(Box::new(SharedStore(Arc::new(Store::default())))),
        None,
        None,
        Some(clock),
        mls_storage,
    );
    supervisor.register_local_did(DID::from(ALICE)).await;
    let deps = supervisor
        .build_actor_deps_loaded(&DID::from(ALICE))
        .await
        .expect("build actor deps");
    (deps, supervisor)
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
    let clock = Arc::new(TestClock::new(T0));
    let (deps, sup) = alice_deps(alice_provider, &relay, &clock).await;
    activate(&mut alice_state);
    alice_state
        .distribute_sender_key(ALICE, BOB)
        .expect("Alice builds a distribution for Bob");
    assert_eq!(queue(&alice_state).len(), 1, "one distribution queued");
    Alice {
        cell: ClassSCell::new(alice_state),
        deps,
        _sup: sup,
        relay,
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

/// Queues `message` for Bob through the production bound.
fn enqueue(cell: &mut ClassSCell, message: Vec<u8>) {
    let mut view = cell.class_c_view();
    let crypto = view.mode_mut().crypto_mut().expect("encrypted");
    crate::context::actor::state::ContextCryptoState::enqueue_distribution(
        &mut crypto.pending_distributions,
        &mut crypto.undelivered,
        BOB.to_owned(),
        message,
    );
}

/// Every `SenderKeyDistribution*` event the context recorded since the last
/// call.
fn distribution_events(cell: &mut ClassSCell) -> Vec<ContextEvent> {
    cell.class_c_view()
        .receive_buffer_mut()
        .drain()
        .into_iter()
        .filter(|e| {
            matches!(
                e,
                ContextEvent::SenderKeyDistributionPending { .. }
                    | ContextEvent::SenderKeyDistributionFailed { .. }
            )
        })
        .collect()
}

async fn send_queued(alice: &mut Alice, ctx: &str) -> Result<(), ContextError> {
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
/// has nothing to publish.
#[tokio::test]
async fn failed_publish_survives_persist_and_a_restored_timer_publishes_it() {
    let ctx = "sender-key-requeue-survives-restart";
    let mut alice = alice_with_queued_distribution(ctx).await;
    let queued = queue(&alice.cell)[0].clone();

    let result = send_queued(&mut alice, ctx).await;
    assert!(
        matches!(result, Err(ContextError::TransportFailed(_))),
        "a requeued distribution fails the explicit re-send: {result:?}"
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

/// Fails if the drain stops emitting its faults: no event reports the
/// requeued distribution.
#[tokio::test]
async fn failed_publish_emits_pending_event() {
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
    let events = distribution_events(&mut alice.cell);
    assert!(
        matches!(
            events.as_slice(),
            [ContextEvent::SenderKeyDistributionPending { target_did, attempt: 1, .. }]
                if target_did.0 == BOB
        ),
        "got {events:?}"
    );
    let entry = &queue(&alice.cell)[0];
    assert_eq!(entry.next_attempt_at, T0 + 1, "first backoff step is 1 s");
}

/// Fails if the timer's scope selects every entry (it would publish the
/// never-attempted answer, or publish before the backoff elapses) or if the
/// timer does not run the drain at all.
#[tokio::test]
async fn timer_publishes_only_failed_entries_whose_backoff_elapsed() {
    let ctx = "sender-key-requeue-timer-due-only";
    let mut alice = alice_with_queued_distribution(ctx).await;
    let _ = send_queued(&mut alice, ctx).await;
    // A second distribution, never attempted (a push-wake answer).
    enqueue(&mut alice.cell, b"never attempted".to_vec());
    alice.relay.down.store(false, Ordering::SeqCst);

    timer_tick(&mut alice).await;
    assert!(alice.relay.accepted().is_empty(), "backoff not yet elapsed");
    assert_eq!(queue(&alice.cell).len(), 2);

    alice.clock.advance(1);
    timer_tick(&mut alice).await;
    assert_eq!(
        alice.relay.accepted().len(),
        1,
        "only the due retry is published"
    );
    let left = queue(&alice.cell);
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].message.as_slice(), b"never attempted");
    assert_eq!(left[0].first_attempt_at, None);
}

/// Fails if the age cap counts from the current attempt instead of the first:
/// the entry would then be published after `MAX_BLOB_TTL`.
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

/// Fails if an encrypt failure is skipped instead of reported, or keeps the
/// entry: an oversized payload can never be sealed.
#[tokio::test]
async fn unsealable_entry_is_dropped_and_reported() {
    let ctx = "sender-key-requeue-unsealable";
    let mut alice = alice_with_queued_distribution(ctx).await;
    alice.relay.down.store(false, Ordering::SeqCst);
    enqueue(
        &mut alice.cell,
        vec![0; scp_protocol::context::builder::MAX_MANAGEMENT_PAYLOAD_SIZE + 1],
    );

    let result = send_queued(&mut alice, ctx).await;
    assert!(
        matches!(result, Err(ContextError::CryptoFailed(_))),
        "a dropped distribution fails the explicit re-send: {result:?}"
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
            [ContextEvent::SenderKeyDistributionFailed { reason, .. }]
                if reason.starts_with("unsealable:")
        ),
        "got {events:?}"
    );
}

/// Fails if the per-target bound is lifted (the queue grows to 18) or the
/// displaced entries go unreported.
#[tokio::test]
async fn per_target_bound_evicts_oldest_and_reports_count() {
    let ctx = "sender-key-requeue-bound";
    let mut alice = alice_with_queued_distribution(ctx).await;
    for n in 0..=MAX_PUSH_CHAINS_PER_MEMBER {
        enqueue(&mut alice.cell, vec![u8::try_from(n).unwrap()]);
    }
    let left = queue(&alice.cell);
    assert_eq!(left.len(), MAX_PUSH_CHAINS_PER_MEMBER);
    assert_eq!(
        left[0].message.as_slice(),
        [1],
        "the two oldest were displaced"
    );

    let report = drain_and_deliver_sender_keys(
        &alice.deps,
        &mut alice.cell.class_c_view(),
        ctx,
        DistributionScope::DueRetries,
    )
    .await;
    assert!(
        report
            .faults
            .iter()
            .any(|f| matches!(f, DistributionFault::Evicted { displaced: 2, .. })),
        "got {:?}",
        report.faults
    );
    assert!(
        distribution_events(&mut alice.cell).iter().any(|e| matches!(
            e,
            ContextEvent::SenderKeyDistributionFailed { reason, .. } if reason.starts_with("evicted:")
        )),
        "the eviction is reported by event"
    );
}
