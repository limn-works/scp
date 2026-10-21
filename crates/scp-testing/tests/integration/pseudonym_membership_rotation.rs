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

/// How long a drain waits for one more event before it decides the channel
/// is quiet. The rotation arm signals on a zero-length sleep right after the
/// handler returns and repeats only after a 30 s backoff, so a quiet window
/// this long separates "one signal" from "two".
const QUIET: Duration = Duration::from_millis(750);

type Events = Receiver<(String, ContextEvent)>;

/// A test or helper outcome; a harness or channel failure is an error.
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// A Welcome joiner holds no copy of the creator's `T0`, so the policy is
/// membership-only (spec 09 §9.10.4.1 "First v2 derivation").
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

/// Every event `rx` receives until it stays quiet for [`QUIET`].
async fn drain(rx: &mut Events) -> TestResult<Vec<(String, ContextEvent)>> {
    let mut events = Vec::new();
    loop {
        match tokio::time::timeout(QUIET, rx.recv()).await {
            Ok(Ok(event)) => events.push(event),
            Ok(Err(RecvError::Lagged(n))) => {
                return Err(format!("the event receiver lagged by {n} events").into());
            }
            Ok(Err(RecvError::Closed)) | Err(_) => return Ok(events),
        }
    }
}

/// The epochs of the `PseudonymRotationDue` signals among `events` for `ctx`.
fn rotation_due(events: &[(String, ContextEvent)], ctx: &str) -> Vec<u64> {
    events
        .iter()
        .filter(|(id, _)| id == ctx)
        .filter_map(|(_, event)| match event {
            ContextEvent::PseudonymRotationDue { pseudonym_epoch } => Some(*pseudonym_epoch),
            _ => None,
        })
        .collect()
}

/// The rotation signals `rx` receives until it goes quiet.
async fn signals(rx: &mut Events, ctx: &str) -> TestResult<Vec<u64>> {
    Ok(rotation_due(&drain(rx).await?, ctx))
}

/// Rotates `node` at `epoch`, then drains the rotation's own events so the
/// next count starts clean. The announcement stays in the node's send buffer.
async fn rotate(
    node: &FullStackNode,
    rx: &mut Events,
    ctx: &str,
    epoch: u64,
    rid: [u8; 32],
) -> TestResult {
    node.rotate_pseudonym(ctx, epoch, rid)
        .await
        .map_err(|e| format!("{} rotates at epoch {epoch}: {e}", node.did.as_ref()))?;
    assert_eq!(
        signals(rx, ctx).await?,
        Vec::<u64>::new(),
        "a rotation whose announcement went out leaves nothing due"
    );
    Ok(())
}

/// Bob's persisted registry record for `member`, once the coalesced persist
/// that follows an announcement has landed (`None` if it never does).
async fn persisted_record(
    node: &FullStackNode,
    ctx: &str,
    member: &str,
) -> Option<scp_core::context::pseudonym::PseudonymRecord> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        let record = node.persisted_snapshot(ctx).and_then(|snapshot| {
            snapshot
                .routing
                .peer_registry()
                .and_then(|registry| registry.get(&DID::from(member)).copied())
        });
        if record.is_some() || tokio::time::Instant::now() >= deadline {
            return record;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
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
    assert_eq!(
        signals(&mut bob_rx, &ctx).await?,
        vec![0],
        "join derivation"
    );
    rotate(&bob, &mut bob_rx, &ctx, 0, [0xB0; 32]).await?;

    // Alice adds Carol: Bob processes the Commit and gets exactly one signal.
    alice.add_member(&handle, CAROL).await?;
    bob.feed_pending_incoming(&ctx, &ctx_bytes).await?;
    assert_eq!(
        signals(&mut bob_rx, &ctx).await?,
        vec![1],
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
    rotate(&bob, &mut bob_rx, &ctx, 1, [0xB1; 32]).await?;

    // Bob holds a record for Carol. Carol's own announcement cannot reach
    // Bob here: he records no role for a member a processed Commit adds until
    // SCP-330 verifies its `MemberJoined` leaf, so he rejects Carol's messages
    // as from a non-member. The record is seeded instead; the Commit that
    // deletes it is real.
    bob.manager
        .seed_peer_pseudonym(&ctx, DID::from(CAROL), [0xC0; 32])
        .await?;

    // Alice adds Dave: one more signal, and the persist that follows carries
    // Bob's record for Carol.
    alice.add_member(&handle, DAVE).await?;
    bob.feed_pending_incoming(&ctx, &ctx_bytes).await?;
    assert_eq!(signals(&mut bob_rx, &ctx).await?, vec![2]);
    assert_eq!(
        persisted_record(&bob, &ctx, CAROL)
            .await
            .map(|r| r.routing_id),
        Some([0xC0; 32]),
        "Bob's record for Carol is persisted before her removal"
    );
    rotate(&bob, &mut bob_rx, &ctx, 2, [0xB2; 32]).await?;

    // Alice removes Carol: Bob processes the Commit, gets exactly one signal,
    // and holds no registry record for Carol.
    alice.remove_member(&handle, CAROL).await?;
    bob.feed_pending_incoming(&ctx, &ctx_bytes).await?;
    assert_eq!(
        signals(&mut bob_rx, &ctx).await?,
        vec![3],
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
    rotate(&bob, &mut bob_rx, &ctx, 3, [0xB3; 32]).await?;

    // Carol rejoins on a fresh device: the re-add is one more AddMember.
    let _carol = network.create_node(CAROL);
    alice.add_member(&handle, CAROL).await?;
    bob.feed_pending_incoming(&ctx, &ctx_bytes).await?;
    assert_eq!(signals(&mut bob_rx, &ctx).await?, vec![4]);
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
    assert_eq!(signals(&mut bob_rx, &ctx).await?, vec![0]);
    rotate(&bob, &mut bob_rx, &ctx, 0, [0xB0; 32]).await?;

    alice.add_member(&handle, CAROL).await?;
    assert!(bob.set_persistence_failing(true));
    let delivered = bob.feed_pending_incoming(&ctx, &ctx_bytes).await;
    assert!(
        matches!(delivered, Err(ContextError::PersistenceFailed(_))),
        "a failed persist after a merged Commit is reported, got {delivered:?}"
    );
    assert_eq!(
        signals(&mut bob_rx, &ctx).await?,
        vec![1],
        "the membership change is kept in memory, not dropped"
    );

    assert!(bob.set_persistence_failing(false));
    rotate(&bob, &mut bob_rx, &ctx, 1, [0xB1; 32]).await?;
    let snapshot = bob
        .persisted_snapshot(&ctx)
        .ok_or("Bob persisted the rotation")?;
    assert!(
        !snapshot
            .pseudonym_rotation
            .rotation_due(Some(&membership_policy()), 0),
        "the rotation the kept trigger admitted is persisted"
    );
    Ok(())
}
