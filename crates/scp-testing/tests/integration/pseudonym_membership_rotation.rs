//! Non-committing members rotate on a processed membership Commit (spec 09
//! §9.10.4.1 "Membership trigger", "Membership-change criterion", "Record
//! lifetime"; story PUSH-030).
//!
//! Every node is a real `Supervisor` with real MLS, sender keys, and access
//! keys (the full-stack harness). The creator (Alice) commits each membership
//! change; the observed members receive the Commit on the `DeliverIncoming`
//! path, the path a relay delivery takes. Bob's supervisor event channel shows
//! the rotation-due signals the actor's rotation arm sends, and his persisted
//! snapshots show the registry deletion the Commit causes.
//!
//! A second device leaf for an existing member is not reachable here: the
//! Supervisor's `AddMember` rejects a DID that is already a member. The
//! classifier tests in `scp-protocol` (`pseudonym.rs`) and the received-Commit
//! test in `scp-mls` (`admission.rs`) cover that rule, and the runtime test in
//! `scp-runtime` (`pseudonym_rotation.rs`) shows an empty change records no
//! rotation.
//!
//! A rejoiner's announcement reaching Bob is not reachable here either. A
//! non-committer records no member a processed Commit adds until it verifies
//! the `MemberJoined` governance leaf that Commit carries (spec 07 §7.3.1.1
//! "Fail closed", ADR-066 decision 7), and that receive step is story SCP-330.
//! Until it lands Bob rejects every message from Carol as from a non-member, so
//! the rejoin clause of PUSH-030's record-deletion criterion waits on SCP-330.

use std::time::Duration;

use scp_core::context::membership::ContextEvent;
use scp_core::context::state::context_id_to_bytes;
use scp_core::context::{
    Capability, ContextError, ContextMode, ContextParams, PseudonymRotationPolicy,
};
use scp_did::DID;
use scp_testing::fullstack::{FullStackNetwork, FullStackNode};
use tokio::sync::broadcast::Receiver;
use tokio::sync::broadcast::error::RecvError;

const ALICE: &str = "did:dht:z6MkPush030Alice";
const BOB: &str = "did:dht:z6MkPush030Bob";
const CAROL: &str = "did:dht:z6MkPush030Carol";
const DAVE: &str = "did:dht:z6MkPush030Dave";

/// A bound on one awaited signal, only so a missing signal fails the test
/// instead of hanging it. No assertion depends on it elapsing.
const SIGNAL_DEADLINE: Duration = Duration::from_secs(60);

type Events = Receiver<(String, ContextEvent)>;

/// A test or helper outcome; a harness or channel failure is an error.
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// A membership-only policy, so every rotation these tests observe comes from
/// the membership trigger (spec 09 §9.10.4.1 "Membership trigger"), never from
/// an interval boundary. A Welcome joiner installs the creator's `T0` from the
/// committed `0xFF02` extension (spec 05 §5.13.3 rule 9).
const fn membership_policy() -> PseudonymRotationPolicy {
    PseudonymRotationPolicy {
        interval_secs: None,
        on_membership_change: true,
    }
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
            Capability::GovernancePropose,
            Capability::GovernanceVote,
            Capability::ContextClose,
        ],
        pseudonym_rotation: Some(membership_policy()),
        ..ContextParams::default()
    }
}

/// A canonical 64-hex context ID, the form the actor keys its persistence by.
fn context_id() -> String {
    hex::encode(context_id_to_bytes("push030-membership-rotation"))
}

/// The epoch of the next `PseudonymRotationDue` signal `rx` receives for
/// `ctx`, skipping every other event.
async fn next_signal(rx: &mut Events, ctx: &str) -> TestResult<u64> {
    loop {
        let event = tokio::time::timeout(SIGNAL_DEADLINE, rx.recv())
            .await
            .map_err(|_| "no rotation signal arrived")?;
        match event {
            Ok((id, ContextEvent::PseudonymRotationDue { pseudonym_epoch })) if id == ctx => {
                return Ok(pseudonym_epoch);
            }
            Ok(_) => {}
            Err(RecvError::Lagged(n)) => {
                return Err(format!("the event receiver lagged by {n} events").into());
            }
            Err(RecvError::Closed) => return Err("the event channel closed".into()),
        }
    }
}

/// Whether `node`'s persisted rotation state has a rotation due. The rotation
/// arm signals only while one is due, so `false` means no further signal.
fn persisted_due(node: &FullStackNode, ctx: &str) -> TestResult<bool> {
    Ok(node
        .persisted_snapshot(ctx)
        .ok_or("the node persisted the context")?
        .pseudonym_rotation
        .rotation_due(Some(&membership_policy()), 0))
}

/// Rotates `node` at `epoch` and checks, from its persisted state, that no
/// rotation is left due. The announcement stays in the node's send buffer.
///
/// A second signal for the change this rotation answered would arrive ahead
/// of the next change's signal, so the caller's next [`next_signal`] would
/// read this epoch instead of the next one.
async fn rotate(node: &FullStackNode, ctx: &str, epoch: u64, rid: [u8; 32]) -> TestResult {
    node.rotate_pseudonym(ctx, epoch, rid)
        .await
        .map_err(|e| format!("{} rotates at epoch {epoch}: {e}", node.did.as_ref()))?;
    assert!(
        !persisted_due(node, ctx)?,
        "a rotation whose announcement went out leaves nothing due"
    );
    Ok(())
}

/// Returns once the wall clock has left the second it read on entry.
///
/// The shipped proposal ID still hashes the proposer, the action and the
/// proposal time in whole seconds (`SCP-PROPOSAL-V1`, which spec 09 §9.5.2
/// retires for the `anchor_seq` preimage of story SCP-331). Re-adding a DID
/// within the second of its first add proposes the same ID, and the
/// governance engine refuses it as a duplicate, so a re-add calls this first.
async fn leave_this_second() {
    use scp_clock::Clock as _;
    let entered = scp_clock::SystemClock.now_secs();
    while scp_clock::SystemClock.now_secs() == entered {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// `node`'s persisted registry record for `member`.
fn persisted_record(
    node: &FullStackNode,
    ctx: &str,
    member: &str,
) -> Option<scp_core::context::pseudonym::PseudonymRecord> {
    node.persisted_snapshot(ctx).and_then(|snapshot| {
        snapshot
            .routing
            .peer_registry()
            .and_then(|registry| registry.get(&DID::from(member)).copied())
    })
}

/// PUSH-030 acceptance: one signal per membership-changing Commit on a
/// non-committing member, and the removed DID's record deleted when that
/// member processes the removal.
#[tokio::test]
async fn a_non_committer_rotates_once_per_membership_commit_and_deletes_the_removed_record()
-> TestResult {
    let ctx = context_id();
    let ctx_bytes = context_id_to_bytes(&ctx);
    let network = FullStackNetwork::new();
    let alice = network.create_node(ALICE);
    let bob = network.create_observed_node(BOB);
    let _carol = network.create_node(CAROL);
    let _dave = network.create_node(DAVE);
    let mut bob_rx = bob.subscribe_events().ok_or("Bob is observed")?;

    // Alice creates the context under `on_membership_change`; Bob joins by
    // Welcome. His join-time v2 derivation is due at epoch 0, so he takes it
    // first and later counts start from nothing due.
    let handle = alice.create_context(&ctx, params()).await?;
    alice.add_member(&handle, BOB).await?;
    bob.join_from_welcome(&ctx, &ctx_bytes).await?;
    assert_eq!(next_signal(&mut bob_rx, &ctx).await?, 0, "join derivation");
    rotate(&bob, &ctx, 0, [0xB0; 32]).await?;

    // Alice adds Carol: Bob processes the Commit and gets exactly one signal.
    alice.add_member(&handle, CAROL).await?;
    bob.feed_pending_incoming(&ctx, &ctx_bytes).await?;
    assert_eq!(
        next_signal(&mut bob_rx, &ctx).await?,
        1,
        "an AddMember Commit Bob did not commit signals one rotation"
    );
    let snapshot = bob
        .persisted_snapshot(&ctx)
        .ok_or("Bob persisted the Commit")?;
    assert!(
        snapshot
            .pseudonym_rotation
            .rotation_due(Some(&membership_policy()), 0),
        "the trigger is persisted with the processed Commit"
    );
    // Fail closed (spec 07 §7.3.1.1, ADR-066 decision 7): the processed add
    // records no membership, role or capability for Carol at Bob. Only the
    // verified `MemberJoined` leaf of SCP-330 may supply one. The snapshot is
    // the one the processed Commit wrote, since it holds the trigger above.
    assert!(
        !snapshot.membership.contains(CAROL),
        "Bob's persisted membership holds no entry for Carol"
    );
    assert!(
        !snapshot.role_state.members.contains(CAROL),
        "Bob's persisted role-state members hold no entry for Carol"
    );
    assert!(
        !snapshot.role_state.assignments.contains_key(CAROL),
        "Bob's persisted role state assigns Carol no role"
    );
    assert!(
        !snapshot.role_state.member_capabilities.contains_key(CAROL),
        "Bob's persisted role state grants Carol no capability"
    );
    rotate(&bob, &ctx, 1, [0xB1; 32]).await?;

    // Bob holds a record for Carol. Carol's own announcement cannot reach
    // Bob here: he records no role for a member a processed Commit adds until
    // SCP-330 verifies its `MemberJoined` leaf, so he rejects Carol's messages
    // as from a non-member. The record is seeded instead; the Commit that
    // deletes it is real.
    bob.manager
        .seed_peer_pseudonym(&ctx, DID::from(CAROL), [0xC0; 32])
        .await?;

    // Alice adds Dave: one more signal, and the persist of the processed
    // Commit, done before the delivery returns, carries Bob's record for Carol.
    alice.add_member(&handle, DAVE).await?;
    bob.feed_pending_incoming(&ctx, &ctx_bytes).await?;
    assert_eq!(
        persisted_record(&bob, &ctx, CAROL).map(|r| r.routing_id),
        Some([0xC0; 32]),
        "Bob's record for Carol is persisted before her removal"
    );
    assert_eq!(next_signal(&mut bob_rx, &ctx).await?, 2);
    rotate(&bob, &ctx, 2, [0xB2; 32]).await?;

    // Alice removes Carol: Bob processes the Commit, gets exactly one signal,
    // and holds no registry record for Carol.
    alice.remove_member(&handle, CAROL).await?;
    bob.feed_pending_incoming(&ctx, &ctx_bytes).await?;
    assert_eq!(
        next_signal(&mut bob_rx, &ctx).await?,
        3,
        "a RemoveMember Commit Bob did not commit signals one rotation"
    );
    let snapshot = bob
        .persisted_snapshot(&ctx)
        .ok_or("Bob persisted the Commit")?;
    let registry = snapshot
        .routing
        .peer_registry()
        .ok_or("an encrypted context has a peer registry")?;
    assert!(
        !registry.contains_key(&DID::from(CAROL)),
        "processing Carol's removal deletes her record (§9.10.4.1 Record lifetime)"
    );
    rotate(&bob, &ctx, 3, [0xB3; 32]).await?;

    // Carol rejoins on a fresh device: the re-add is one more AddMember.
    let _carol = network.create_node(CAROL);
    leave_this_second().await;
    alice.add_member(&handle, CAROL).await?;
    bob.feed_pending_incoming(&ctx, &ctx_bytes).await?;
    assert_eq!(next_signal(&mut bob_rx, &ctx).await?, 4);
    rotate(&bob, &ctx, 4, [0xB4; 32]).await?;
    Ok(())
}

/// PUSH-030 fail-closed persist: when the Class-S persist after a processed
/// membership Commit fails, the delivery reports `PersistenceFailed` and the
/// trigger stays in memory (keep-direction), so the rotation is still
/// signalled and still admissible once persistence recovers.
#[tokio::test]
async fn a_failed_persist_after_a_membership_commit_keeps_the_trigger() -> TestResult {
    let ctx = context_id();
    let ctx_bytes = context_id_to_bytes(&ctx);
    let network = FullStackNetwork::new();
    let alice = network.create_node(ALICE);
    let bob = network.create_observed_node(BOB);
    let _carol = network.create_node(CAROL);
    let mut bob_rx = bob.subscribe_events().ok_or("Bob is observed")?;

    let handle = alice.create_context(&ctx, params()).await?;
    alice.add_member(&handle, BOB).await?;
    bob.join_from_welcome(&ctx, &ctx_bytes).await?;
    assert_eq!(next_signal(&mut bob_rx, &ctx).await?, 0);
    rotate(&bob, &ctx, 0, [0xB0; 32]).await?;

    alice.add_member(&handle, CAROL).await?;
    assert!(bob.set_persistence_failing(true));
    let delivered = bob.feed_pending_incoming(&ctx, &ctx_bytes).await;
    assert!(
        matches!(delivered, Err(ContextError::PersistenceFailed(_))),
        "a failed persist after a merged Commit is reported, got {delivered:?}"
    );
    assert_eq!(
        next_signal(&mut bob_rx, &ctx).await?,
        1,
        "the membership change is kept in memory, not dropped"
    );

    // `rotate` checks that the persisted state holds nothing due afterwards.
    assert!(bob.set_persistence_failing(false));
    rotate(&bob, &ctx, 1, [0xB1; 32]).await?;
    Ok(())
}

/// How the committer removes Carol in [`readd_after_removal`].
#[derive(Clone, Copy, Debug)]
enum Removal {
    /// A governance `RemoveMember` proposal Alice executes.
    Governance,
    /// The leave path, `Supervisor::leave_context`, which Alice commits.
    Leave,
}

/// Carol sends `payload` and Alice opens it; returns the plaintext Alice
/// recovered.
async fn carol_to_alice(
    alice: &FullStackNode,
    carol: &FullStackNode,
    carol_handle: &scp_core::context::ContextHandle,
    ctx: &str,
    payload: &[u8],
) -> TestResult<Vec<u8>> {
    let ctx_bytes = context_id_to_bytes(ctx);
    let _ = carol.take_sent_ciphertexts();
    carol.send_message(carol_handle, payload).await?;
    let sent = carol.take_sent_ciphertexts();
    let (_, ciphertext) = sent.first().ok_or("Carol's send produced a ciphertext")?;
    Ok(alice
        .decrypt_message(ctx, &ctx_bytes, ciphertext, CAROL)
        .await?)
}

/// Alice commits Carol's removal (`removal`), re-adds Carol on a fresh
/// device, and opens that device's first message, at sequence 1.
///
/// Alice opened two messages from Carol's first device, so her receive floor
/// for Carol stood at sequence 2. The committer's removal runs
/// `remove_member_state`, which drops Carol's sender key, sequence tracker
/// and floors; without that teardown the fresh device's sequence 1 would be a
/// replay below the floor.
async fn readd_after_removal(removal: Removal) -> TestResult {
    let ctx = hex::encode(context_id_to_bytes(&format!("push030-readd-{removal:?}")));
    let ctx_bytes = context_id_to_bytes(&ctx);
    let network = FullStackNetwork::new();
    let alice = network.create_node(ALICE);
    let carol = network.create_node(CAROL);

    let handle = alice.create_context(&ctx, params()).await?;
    alice.add_member(&handle, CAROL).await?;
    let carol_handle = carol.join_from_welcome(&ctx, &ctx_bytes).await?;
    carol
        .manager
        .seed_peer_pseudonym(&ctx, DID::from(ALICE), [0xA0; 32])
        .await?;
    for payload in [b"first".as_slice(), b"second".as_slice()] {
        assert_eq!(
            carol_to_alice(&alice, &carol, &carol_handle, &ctx, payload).await?,
            payload
        );
    }

    match removal {
        Removal::Governance => {
            alice
                .propose_governance(
                    &ctx,
                    scp_core::context::governance::GovernanceAction::RemoveMember {
                        did: DID::from(CAROL),
                        reason: None,
                    },
                )
                .await?;
            let _ = alice.take_sent_ciphertexts();
        }
        Removal::Leave => alice.remove_member(&handle, CAROL).await?,
    }
    assert!(
        !alice.manager.is_member(&ctx, CAROL).await,
        "Alice removed Carol"
    );

    let fresh = network.create_node(CAROL);
    leave_this_second().await;
    alice.add_member(&handle, CAROL).await?;
    let fresh_handle = fresh.join_from_welcome(&ctx, &ctx_bytes).await?;
    fresh
        .manager
        .seed_peer_pseudonym(&ctx, DID::from(ALICE), [0xA1; 32])
        .await?;
    let payload = b"from the fresh device";
    assert_eq!(
        carol_to_alice(&alice, &fresh, &fresh_handle, &ctx, payload).await?,
        payload,
        "Alice accepts the re-added Carol's message at sequence 1"
    );
    Ok(())
}

/// The committer's governance removal tears down Carol's receive state, so
/// Alice accepts the re-added Carol's first message.
#[tokio::test]
async fn the_committer_accepts_a_readded_member_after_a_governance_removal() -> TestResult {
    readd_after_removal(Removal::Governance).await
}

/// The committer's leave-path removal tears down Carol's receive state, so
/// Alice accepts the re-added Carol's first message.
#[tokio::test]
async fn the_committer_accepts_a_readded_member_after_a_committed_leave() -> TestResult {
    readd_after_removal(Removal::Leave).await
}
