//! Receive-side and reset tests for a membership Commit (spec 07 §7.3.1.1;
//! spec 09 §9.10.4.1; ADR-066 decisions 7 and 11; story PUSH-030).
//!
//! Alice and Bob are a real two-party MLS pair (`stand_up_two_party`), each in
//! a `ClassSCell` with production `ActorDeps` over a snapshot store. Carol
//! holds only `KeyPackage`s: Alice adds her leaf and Bob merges that Commit, so
//! Bob's tree holds Carol's leaf. Each received Commit goes through the
//! production `MessagingCommand::DeliverIncoming` handler, and each reset
//! through the production `execute_reset_member`.
//!
//! - A processed Remove Commit changes only the rotation trigger and the
//!   removed DID's registry record (07 §7.3.1.1 step 3: membership and role
//!   change only from verified leaves, story SCP-330).
//! - A reset is one Commit and one epoch, refused before any MLS mutation
//!   when its `KeyPackage` is missing or names another DID (07 §7.3.1.1 step
//!   1.6; ADR-066 decision 11).
//! - A non-committer that processes a reset records no rotation trigger (09
//!   §9.10.4.1 "Membership-change criterion": one leaf of the DID before and
//!   after is no change).
//! - A member that processes its own removal discards its query-only list and
//!   records no trigger.

#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;
use openmls::prelude::tls_codec::Serialize as _;
use scp_clock::SystemClock;
use scp_did::DID;
use scp_protocol::context::builder::{ContextCreationError, ReceiveFloor};
use scp_protocol::context::params::{ContextParams, PseudonymRotationPolicy};
use scp_protocol::context::roles::Capability;
use scp_protocol::context::{ContextError, ContextState};
use scp_protocol::crypto::sender_keys::{MAX_EPOCH_ADVANCE, SenderKey};

use crate::context::ContextHandle;
use crate::context::actor::class_s::ClassSCell;
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::pseudonym_rotation::PseudonymRotationState;
use crate::context::actor::state::PerContextState;
use crate::context::builder::{ContextEventLogProvider, ContextTransportProvider};
use crate::context::governance_helpers::{CommitMeta, execute_reset_member};
use crate::context::persistence::ContextPersistence;
use crate::context::state::{ContextSnapshot, context_id_to_bytes};
use crate::context::supervisor::supervisor::Supervisor;

const ALICE: &str = "did:dht:z6MkAliceProcessedCommitAliceProcessedCo1";
const BOB: &str = "did:dht:z6MkBobProcessedCommitBobProcessedCommitB1";
const CAROL: &str = "did:dht:z6MkCarolProcessedCommitCarolProcessedC1";
const DAVE: &str = "did:dht:z6MkDaveProcessedCommitDaveProcessedCom1";

type PersistErr = Box<dyn std::error::Error + Send + Sync>;

/// The last snapshot persisted per context.
#[derive(Default)]
struct Store(DashMap<String, ContextSnapshot>);

impl Store {
    fn snapshot(&self, ctx: &str) -> Option<ContextSnapshot> {
        self.0.get(ctx).map(|s| s.value().clone())
    }
}

struct SharedStore(Arc<Store>);

#[async_trait::async_trait]
impl ContextPersistence for SharedStore {
    async fn persist_context(&self, id: &str, s: &ContextSnapshot) -> Result<(), PersistErr> {
        self.0.0.insert(id.to_owned(), s.clone());
        Ok(())
    }
    async fn load_context(&self, id: &str) -> Result<Option<ContextSnapshot>, PersistErr> {
        Ok(self.0.snapshot(id))
    }
    async fn delete_context(&self, id: &str) -> Result<(), PersistErr> {
        self.0.0.remove(id);
        Ok(())
    }
    async fn list_persisted_contexts(&self) -> Result<Vec<String>, PersistErr> {
        Ok(self.0.0.iter().map(|e| e.key().clone()).collect())
    }
}

/// Every `send_message` payload, keyed by send order.
#[derive(Default)]
struct Sent {
    next: AtomicU64,
    payloads: DashMap<u64, Vec<u8>>,
}

impl Sent {
    fn push(&self, payload: Vec<u8>) {
        let n = self.next.fetch_add(1, Ordering::SeqCst);
        self.payloads.insert(n, payload);
    }

    fn take(&self) -> Vec<Vec<u8>> {
        let mut keys: Vec<u64> = self.payloads.iter().map(|e| *e.key()).collect();
        keys.sort_unstable();
        keys.into_iter()
            .filter_map(|k| self.payloads.remove(&k).map(|(_, v)| v))
            .collect()
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
        _id: &[u8; 32],
        payload: &[u8],
        _ttl: scp_protocol::envelope::outer::BlobTtl,
    ) -> Result<(), ContextError> {
        self.0.push(payload.to_vec());
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

/// One member: its cell, production deps, snapshot store and sent payloads.
struct Member {
    cell: ClassSCell,
    deps: ActorDeps,
    /// The supervisor; held so the deps' weak handle to it stays live.
    sup: Arc<Supervisor>,
    store: Arc<Store>,
    sent: Arc<Sent>,
}

async fn member_deps(
    did: &str,
    crypto: Arc<crate::crypto::mls::provider::NodeMlsFactory>,
) -> (ActorDeps, Arc<Supervisor>, Arc<Store>, Arc<Sent>) {
    let store = Arc::new(Store::default());
    let sent = Arc::new(Sent::default());
    let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> = Arc::new(
        crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
            scp_platform::in_memory::InMemoryStorage::new(),
        )),
    );
    let supervisor = Supervisor::with_providers(
        crypto,
        Box::new(RecordingTransport(Arc::clone(&sent))),
        Box::new(OkEventLog),
        crate::crypto::mls::two_party_test_support::pair_resolver(ALICE, BOB),
        Some(Box::new(SharedStore(Arc::clone(&store)))),
        None,
        None,
        None,
        mls_storage,
    );
    supervisor.register_local_did(DID::from(did)).await;
    let deps = supervisor
        .build_actor_deps_loaded(&DID::from(did))
        .await
        .expect("build actor deps");
    (deps, supervisor, store, sent)
}

/// The membership-only rotation policy.
const fn membership_policy() -> PseudonymRotationPolicy {
    PseudonymRotationPolicy {
        interval_secs: None,
        on_membership_change: true,
    }
}

/// Makes `state` active under the membership-only policy, with `members` as
/// members holding `messages:write`.
fn activate(state: &mut PerContextState, members: &[&str]) {
    let mut params = state.handle.params().clone();
    params.pseudonym_rotation = Some(membership_policy());
    state.handle = ContextHandle::new(state.handle.context_id().to_owned(), params);
    state
        .handle
        .transition_to(&ContextState::Active)
        .expect("activate the context");
    for did in members {
        seed_member(state, did);
    }
}

fn seed_member(state: &mut PerContextState, did: &str) {
    state
        .membership
        .add_member(DID::from(did), "member".to_owned(), Vec::new());
    state.members.insert(DID::from(did));
    state.role_state.members.insert((*did).to_owned());
    state.role_state.member_capabilities.insert(
        (*did).to_owned(),
        std::collections::HashSet::from([Capability::MessagesWrite]),
    );
}

/// A fresh TLS-serialized `KeyPackage` for `did`.
fn key_package(did: &str) -> Vec<u8> {
    let credential =
        scp_mls::ScpCredential::new(did.to_owned(), None, scp_did::SigningKeyId::Active)
            .expect("credential");
    let (bundle, _signer, _provider) = scp_mls::group::generate_key_package_with_context_params(
        &credential,
        &scp_crypto::p256::testing::uncompressed_point_for(did),
        &SystemClock,
    )
    .expect("key package");
    bundle
        .key_package()
        .tls_serialize_detached()
        .expect("serialize key package")
}

fn epoch(state: &PerContextState) -> u64 {
    state
        .mode
        .crypto()
        .and_then(|c| c.mls_group.as_ref())
        .expect("an encrypted group")
        .epoch()
        .expect("epoch")
}

/// Whether `state`'s tree holds a leaf whose credential names `did`.
fn holds_leaf(state: &PerContextState, did: &str) -> bool {
    state
        .mode
        .crypto()
        .and_then(|c| c.mls_group.as_ref())
        .expect("an encrypted group")
        .members()
        .expect("members")
        .iter()
        .any(|m| {
            openmls::prelude::BasicCredential::try_from(m.credential.clone())
                .ok()
                .and_then(|b| scp_mls::credential::ScpCredential::from_bytes(b.identity()).ok())
                .is_some_and(|c| c.did == did)
        })
}

/// Delivers `blob` through the production `DeliverIncoming` handler.
async fn deliver(
    member: &mut Member,
    ctx: &str,
    blob: Vec<u8>,
) -> Result<crate::context::messaging_helpers::DeliverOutcome, ContextError> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let _outcome = crate::context::actor::handlers::messaging::dispatch(
        &mut member.cell,
        &member.deps,
        crate::context::actor::commands::MessagingCommand::DeliverIncoming {
            context_id: ctx.to_owned(),
            envelope_bytes: blob,
            mode: crate::context::actor::commands::DeliveryMode::Live,
            reply: tx,
        },
    )
    .await;
    rx.await.expect("deliver reply")
}

/// Whether `bytes` decode as an MLS message carrying a Commit.
fn is_commit(bytes: &[u8]) -> bool {
    use openmls::prelude::{ContentType, MlsMessageBodyIn};
    let Ok(message) = scp_mls::wire::parse_mls_message_in(bytes) else {
        return false;
    };
    match message.extract() {
        MlsMessageBodyIn::PublicMessage(m) => m.content_type() == ContentType::Commit,
        MlsMessageBodyIn::PrivateMessage(m) => m.content_type() == ContentType::Commit,
        _ => false,
    }
}

/// Alice and Bob, each active with Alice, Bob and Carol as members, and
/// Carol's leaf in both trees: Alice added it, and Bob merged that Commit on
/// the raw receive path before his cell was built, so nothing persisted it and
/// Bob's rotation state starts with nothing pending.
async fn trio(ctx: &str) -> (Member, Member) {
    let crate::crypto::mls::two_party_test_support::TwoPartyPair {
        alice_provider,
        mut alice_state,
        bob_provider,
        mut bob_state,
        ctx_bytes,
        ..
    } = crate::crypto::mls::two_party_test_support::stand_up_two_party(ctx, ALICE, BOB);
    let (alice_deps, alice_sup, alice_store, alice_sent) = member_deps(ALICE, alice_provider).await;
    let (bob_deps, bob_sup, bob_store, bob_sent) = member_deps(BOB, bob_provider).await;

    let add = alice_state
        .add_member(CAROL, Some(&key_package(CAROL)), &SystemClock)
        .expect("Alice adds Carol")
        .commit_bytes;
    let dispatched = crate::context::messaging_helpers::decrypt_and_dispatch(
        &bob_deps,
        bob_state.mode.crypto_mut(),
        ctx,
        &ctx_bytes,
        &add,
        &std::collections::HashSet::new(),
    )
    .await
    .expect("Bob merges the add");
    assert!(matches!(
        dispatched,
        crate::context::messaging_helpers::Dispatched::Commit { .. }
    ));

    activate(&mut alice_state, &[ALICE, BOB, CAROL]);
    activate(&mut bob_state, &[ALICE, BOB, CAROL]);
    assert!(holds_leaf(&alice_state, CAROL) && holds_leaf(&bob_state, CAROL));
    (
        Member {
            cell: ClassSCell::new(alice_state),
            deps: alice_deps,
            sup: alice_sup,
            store: alice_store,
            sent: alice_sent,
        },
        Member {
            cell: ClassSCell::new(bob_state),
            deps: bob_deps,
            sup: bob_sup,
            store: bob_store,
            sent: bob_sent,
        },
    )
}

async fn reset_carol(
    alice: &mut Member,
    ctx: &str,
    key_package: Option<&[u8]>,
) -> Result<scp_protocol::context::builder::AddMemberOutput, ContextError> {
    execute_reset_member(
        &mut alice.cell,
        &alice.deps,
        ctx,
        &DID::from(CAROL),
        "test reset",
        key_package,
        CommitMeta {
            pid: [0x30; 32],
            actor_did: ALICE,
            timestamp_secs: 1_700_000_000,
        },
    )
    .await
}

/// Seeds everything Bob can hold for Carol: a role assignment, an access key,
/// a read-exclusion entry, a registry record, a sequence-tracker entry at 4,
/// a sender key, a sender-epoch floor at 1 and a receive floor at (1, 4).
async fn seed_bob_for_carol(bob: &mut Member, ctx: &str, sender_key_ctx: &str) {
    let ctx_bytes = context_id_to_bytes(ctx);
    let carol_key = scp_protocol::crypto::access_keys::generate_access_key(ctx, CAROL);
    bob.cell
        .commit_class_s_keep(&bob.deps, ctx, |mut v| {
            let s = v.rest_mut();
            s.role_state.assignments.insert(
                CAROL.to_owned(),
                scp_protocol::context::roles::RoleAssignment {
                    member_did: CAROL.to_owned(),
                    role_name: "member".to_owned(),
                    tokens: Vec::new(),
                },
            );
            s.access.access_key_store.set(ctx, CAROL, carol_key.clone());
            s.access.read_exclusion_list.insert(DID::from(CAROL));
            s.routing
                .peer_registry_mut()
                .expect("encrypted ⇒ registry")
                .insert(
                    DID::from(CAROL),
                    scp_protocol::context::pseudonym::PseudonymRecord {
                        routing_id: [0xC0; 32],
                        epoch: Some(0),
                    },
                );
            s.sequence_tracker.advance(ctx, CAROL, 4, 1_700_000_000);
            s.mode
                .crypto_mut()
                .expect("encrypted")
                .sender_key_store
                .set_unchecked(sender_key_ctx, CAROL, SenderKey::from_bytes([0xC5; 32]));
            Ok(())
        })
        .await
        .expect("seed Bob's state for Carol");
    bob.sup
        .check_and_advance_sender_epoch(&ctx_bytes, CAROL, 1, MAX_EPOCH_ADVANCE)
        .expect("seed Carol's sender-epoch floor");
    bob.sup
        .check_and_advance_recv_sequence(
            &ctx_bytes,
            CAROL,
            ReceiveFloor {
                epoch: 1,
                sequence: 4,
            },
            MAX_EPOCH_ADVANCE,
        )
        .expect("seed Carol's receive floor");
}

/// Spec 07 §7.3.1.1 step 3 and "Fail closed": Bob processes a Remove Commit
/// Alice committed for Carol. His persisted snapshot keeps Carol's membership,
/// role, capability, access key and read exclusion, and his sender key,
/// sequence tracker and anti-replay floors for Carol are unchanged; the same
/// snapshot holds the rotation trigger and no registry record for Carol.
#[tokio::test]
async fn a_received_remove_commit_changes_only_the_trigger_and_the_registry_record() {
    let ctx = "processed-remove-commit-tears-down-nothing";
    let ctx_bytes = context_id_to_bytes(ctx);
    let sender_key_ctx = hex::encode(scp_protocol::context::context_id_bytes(ctx));
    let (mut alice, mut bob) = trio(ctx).await;

    seed_bob_for_carol(&mut bob, ctx, &sender_key_ctx).await;
    let seeded = bob.store.snapshot(ctx).expect("the seed persisted");
    assert!(!seeded.pseudonym_rotation.membership_change_pending);

    let remove = alice
        .cell
        .commit_class_s_keep(&alice.deps, ctx, |mut v| {
            v.rest_mut().remove_member(ALICE, CAROL, &SystemClock)
        })
        .await
        .expect("Alice removes Carol's leaf")
        .commit_bytes;
    let epoch_before = epoch(&bob.cell);
    deliver(&mut bob, ctx, remove)
        .await
        .expect("Bob processes the Remove Commit");
    assert_eq!(epoch(&bob.cell), epoch_before + 1, "Bob merged the Commit");
    assert!(!holds_leaf(&bob.cell, CAROL), "Carol's leaf is gone");

    let after = bob.store.snapshot(ctx).expect("the Commit persisted");
    assert!(
        after.pseudonym_rotation.membership_change_pending,
        "the processed Commit records the rotation trigger"
    );
    assert!(
        !after
            .routing
            .peer_registry()
            .expect("encrypted ⇒ registry")
            .contains_key(&DID::from(CAROL)),
        "the processed Commit deletes Carol's registry record"
    );
    assert!(after.membership.contains(CAROL), "membership kept");
    assert!(after.role_state.members.contains(CAROL), "role member kept");
    assert_eq!(
        after
            .role_state
            .assignments
            .get(CAROL)
            .map(|a| a.role_name.as_str()),
        Some("member"),
        "role assignment kept"
    );
    assert!(
        after
            .role_state
            .member_has_capability(CAROL, &Capability::MessagesWrite),
        "capability kept"
    );
    assert!(
        after.access_key_store.get(ctx, CAROL).is_some(),
        "access key kept"
    );
    assert!(
        after.read_exclusion_list.contains(&DID::from(CAROL)),
        "read exclusion kept"
    );

    // The sender key, sequence tracker and floors are not in the snapshot's
    // plain fields; they are read where they live.
    let crypto = bob.cell.mode.crypto().expect("encrypted");
    assert_eq!(
        crypto
            .sender_key_store
            .get(&sender_key_ctx, CAROL)
            .map(|k| *k.as_bytes()),
        Some([0xC5; 32]),
        "sender key kept"
    );
    assert_eq!(
        bob.cell.sequence_tracker.last_seen_sequence(ctx, CAROL),
        Some(4),
        "sequence tracker kept"
    );
    assert!(
        bob.sup
            .export_sender_key_epochs(&ctx_bytes)
            .contains(&(CAROL.to_owned(), 1)),
        "sender-epoch floor kept"
    );
    assert!(
        bob.sup.export_recv_sequence_floors(&ctx_bytes).contains(&(
            CAROL.to_owned(),
            ReceiveFloor {
                epoch: 1,
                sequence: 4
            }
        )),
        "receive floor kept"
    );
}

/// Spec 07 §7.3.1.1 step 1.6 and ADR-066 decision 11: a reset is one Commit
/// that removes Carol's leaf and adds her fresh one. Alice's group advances by
/// exactly one epoch, the reset persists, and exactly one of her sends is an
/// MLS Commit: the one the reset returned.
#[tokio::test]
async fn a_reset_is_one_commit_and_one_epoch() {
    let ctx = "reset-is-one-commit";
    let (mut alice, _bob) = trio(ctx).await;
    let epoch_before = epoch(&alice.cell);
    let _ = alice.sent.take();

    let output = reset_carol(&mut alice, ctx, Some(&key_package(CAROL)))
        .await
        .expect("the reset commits");

    assert_eq!(epoch(&alice.cell), epoch_before + 1, "one epoch");
    assert!(holds_leaf(&alice.cell, CAROL), "Carol holds her fresh leaf");
    assert!(
        !output.welcome_bytes.is_empty(),
        "a Welcome for the fresh leaf"
    );
    let sent = alice.sent.take();
    let commits: Vec<&Vec<u8>> = sent.iter().filter(|s| is_commit(s)).collect();
    assert_eq!(commits.len(), 1, "exactly one Commit is broadcast");
    assert_eq!(commits[0], &output.commit_bytes);
    assert!(
        alice.store.snapshot(ctx).is_some(),
        "the reset persisted once its Commit merged"
    );
}

/// ADR-066 decision 7: a reset without a `KeyPackage`, or with one that names
/// another DID, is refused with `InvalidKeyPackage` before any MLS mutation.
/// The epoch and the cell's mutation epoch are unchanged, nothing is
/// persisted, and nothing is sent.
#[tokio::test]
async fn a_reset_without_the_targets_key_package_changes_nothing() {
    let ctx = "reset-refused-without-key-package";
    let (mut alice, _bob) = trio(ctx).await;
    let epoch_before = epoch(&alice.cell);
    let mutation_before = alice.cell.mutation_epoch();
    assert!(alice.store.snapshot(ctx).is_none(), "nothing persisted yet");
    let _ = alice.sent.take();

    let dave = key_package(DAVE);
    for key_package in [None, Some(dave.as_slice())] {
        let refused = reset_carol(&mut alice, ctx, key_package).await;
        assert!(
            matches!(refused, Err(ContextError::InvalidKeyPackage(_))),
            "{refused:?}"
        );
        assert_eq!(epoch(&alice.cell), epoch_before, "the epoch is unchanged");
        assert_eq!(alice.cell.mutation_epoch(), mutation_before);
        assert!(alice.store.snapshot(ctx).is_none(), "nothing persisted");
        assert!(alice.sent.take().is_empty(), "nothing broadcast");
    }
}

/// Spec 09 §9.10.4.1 "Membership-change criterion": Bob processes Alice's
/// real reset Commit for Carol. Carol holds one leaf before and after, so Bob
/// records no rotation trigger: his persisted rotation state is the one he
/// held before the Commit, with nothing due.
#[tokio::test]
async fn a_non_committer_records_no_rotation_for_a_reset() {
    let ctx = "reset-records-no-rotation";
    let (mut alice, mut bob) = trio(ctx).await;
    let rotation_before: PseudonymRotationState = bob.cell.class_s.pseudonym_rotation.clone();
    assert!(!rotation_before.membership_change_pending);

    let output = reset_carol(&mut alice, ctx, Some(&key_package(CAROL)))
        .await
        .expect("the reset commits");
    let epoch_before = epoch(&bob.cell);
    deliver(&mut bob, ctx, output.commit_bytes)
        .await
        .expect("Bob processes the reset Commit");

    assert_eq!(epoch(&bob.cell), epoch_before + 1, "Bob merged the Commit");
    assert!(holds_leaf(&bob.cell, CAROL));
    // Nothing persisted Bob's state before this Commit, so this snapshot is
    // the one the processed Commit wrote.
    let persisted = bob.store.snapshot(ctx).expect("the Commit persisted");
    assert_eq!(
        persisted.pseudonym_rotation, rotation_before,
        "the persisted trigger is unchanged"
    );
    assert!(
        !persisted
            .pseudonym_rotation
            .rotation_due(Some(&membership_policy()), 0),
        "no rotation is due, so the rotation arm signals none"
    );
}

/// Spec 09 §9.10.4.1 "Record lifetime": Bob processes the real Commit Alice
/// committed to remove him. He discards his query-only list and his pending
/// announcement, and records no rotation trigger, persisted with the Commit.
#[tokio::test]
async fn the_removed_member_discards_its_rotation_state_and_records_no_rotation() {
    let ctx = "processed-own-removal";
    let (mut alice, mut bob) = trio(ctx).await;
    bob.cell
        .commit_class_s_keep(&bob.deps, ctx, |mut v| {
            v.rest_mut()
                .class_s
                .pseudonym_rotation
                .record_rotation(0, [0xB9; 32], Some(&membership_policy()), 1_700_000_000)
                .expect("record Bob's rotation");
            Ok(())
        })
        .await
        .expect("seed Bob's rotation");
    let seeded = bob.store.snapshot(ctx).expect("the seed persisted");
    assert!(!seeded.pseudonym_rotation.query_only.is_empty());
    assert!(seeded.pseudonym_rotation.announce_pending());

    let remove = alice
        .cell
        .commit_class_s_keep(&alice.deps, ctx, |mut v| {
            v.rest_mut().remove_member(ALICE, BOB, &SystemClock)
        })
        .await
        .expect("Alice removes Bob's leaf")
        .commit_bytes;
    deliver(&mut bob, ctx, remove)
        .await
        .expect("Bob processes his own removal");

    let persisted = bob.store.snapshot(ctx).expect("the Commit persisted");
    assert!(
        persisted.pseudonym_rotation.query_only.is_empty(),
        "the query-only list is discarded"
    );
    assert!(
        !persisted.pseudonym_rotation.announce_pending(),
        "the pending announcement is discarded"
    );
    assert!(
        !persisted.pseudonym_rotation.membership_change_pending,
        "a member's own removal records no rotation"
    );
}
