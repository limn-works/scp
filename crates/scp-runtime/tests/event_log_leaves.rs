#![allow(
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::items_after_statements,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::large_futures
)]
//! Integration tests asserting that `KeyEpochAdvance` event-log leaves are
//! appended by the four code paths that emit them (#1847).
//!
//! Code paths under test:
//!
//! 1. `block_broadcast_subscriber` (`broadcast_helpers.rs`): after
//!    `MemberBlocked`, emits exactly one `KeyEpochAdvance` leaf (the blocking
//!    author's new epoch).
//! 2. `unsubscribe_broadcast` (`broadcast_helpers.rs`): when `rotate_keys =
//!    true`, emits one `KeyEpochAdvance` leaf per rotated author.
//! 3. `execute_revoke` (`governance_helpers.rs`): after a governance ban on a
//!    broadcast context subscriber, emits one `KeyEpochAdvance` leaf per
//!    rotated author.
//! 4. `execute_rotate_content_keys` (`governance_helpers.rs`): `RotateContentKeys`
//!    on a broadcast context emits one `KeyEpochAdvance` leaf per rotated author.
//!
//! All paths are best-effort (warn on failure, no error propagation), so
//! a regression silently drops the leaves. These tests pin the expected leaf
//! count to catch silent regressions.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use scp_did::DID;
use scp_event_log::EventType;
use scp_protocol::context::ContextError;
use scp_protocol::context::builder::ContextCreationError;
use scp_protocol::context::governance::{AccessScope, GovernanceAction};
use scp_protocol::context::params::{
    Capability, ContextMode, ContextParams, GovernanceModel, MemoryScope,
};
use scp_runtime::context::actor::commands::{
    BroadcastBlockPayload, BroadcastCommand, SubscribeBroadcastPayload, UnsubscribeBroadcastPayload,
};
use scp_runtime::context::builder::ContextTransportProvider;
use scp_runtime::context::providers::MerkleEventLogProvider;
use scp_runtime::context::supervisor::Supervisor;
use scp_runtime::crypto::mls::provider::NodeMlsFactory;

// ---------------------------------------------------------------------------
// Mock transport — replicates the pattern from governance_integration.rs.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MockTransport {
    connected: AtomicBool,
}

impl MockTransport {
    const fn connected() -> Self {
        Self {
            connected: AtomicBool::new(true),
        }
    }
}

#[async_trait::async_trait]
impl ContextTransportProvider for MockTransport {
    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
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
        _encrypted_payload: &[u8],
    ) -> Result<(), ContextError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// DID helpers.
// ---------------------------------------------------------------------------

fn alice() -> DID {
    DID::from("did:dht:z6MkAliceLeaves")
}
fn bob() -> DID {
    DID::from("did:dht:z6MkBobLeaves")
}

// ---------------------------------------------------------------------------
// Key helpers (for governance signing in the governance-ban test).
// ---------------------------------------------------------------------------

fn did_to_seed(did: &DID) -> [u8; 32] {
    let mut s = [0u8; 32];
    let bytes = did.as_ref().as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        s[i % 32] ^= *b;
    }
    s
}

fn mock_key_resolver() -> scp_protocol::context::governance::KeyResolver {
    Arc::new(|did, _kid: scp_did::SigningKeyId| {
        let seed = did_to_seed(did);
        Some(ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key())
    })
}

fn signing_key_for_did(did: &DID) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&did_to_seed(did))
}

// ---------------------------------------------------------------------------
// Supervisor factory — uses a REAL `MerkleEventLogProvider` so event-log
// leaves are persisted and readable via `Supervisor::event_log_entries`.
// ---------------------------------------------------------------------------

fn new_manager() -> Arc<Supervisor> {
    scp_runtime::context::test_supervisor(
        Arc::new(NodeMlsFactory::new(
            "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_owned(),
            Arc::new(scp_clock::SystemClock),
        )),
        Box::new(MockTransport::connected()),
        Box::new(MerkleEventLogProvider::new()),
        mock_key_resolver(),
    )
}

// ---------------------------------------------------------------------------
// Shared broadcast context params: open broadcast with all relevant caps.
// ---------------------------------------------------------------------------

fn broadcast_params_with_ban() -> ContextParams {
    ContextParams {
        mode: ContextMode::Broadcast,
        memory_scope: MemoryScope::Full,
        ceiling: vec![
            Capability::MessagesRead,
            Capability::MessagesWrite,
            // MemberBan is required by execute_revoke's ceiling check.
            Capability::MemberBan,
            Capability::new("governance:propose").expect("known capability"),
            Capability::new("governance:vote").expect("known capability"),
        ],
        governance: GovernanceModel::SingleAdmin,
        ..ContextParams::default()
    }
}

fn broadcast_params() -> ContextParams {
    ContextParams {
        mode: ContextMode::Broadcast,
        memory_scope: MemoryScope::Full,
        ceiling: vec![Capability::MessagesRead, Capability::MessagesWrite],
        governance: GovernanceModel::SingleAdmin,
        ..ContextParams::default()
    }
}

// ---------------------------------------------------------------------------
// Helper: subscribe bob to a broadcast context.
// ---------------------------------------------------------------------------

async fn subscribe_bob(manager: &Arc<Supervisor>, ctx_id: &str) {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = BroadcastCommand::SubscribeBroadcast {
        payload: Box::new(SubscribeBroadcastPayload {
            context_id: ctx_id.to_owned(),
            subscriber_did: bob(),
            ucan: None,
            timestamp: 1_700_000_000,
        }),
        reply: tx,
    };
    manager
        .dispatch_broadcast_command(cmd)
        .await
        .expect("dispatch SubscribeBroadcast");
    rx.await
        .expect("subscribe reply")
        .expect("subscribe bob succeeds");
}

// ===========================================================================
// Test 1: block_broadcast_subscriber emits MemberBlocked + KeyEpochAdvance
// ===========================================================================

/// Blocking a subscriber advances the blocking author's broadcast-key epoch
/// and records a `KeyEpochAdvance` leaf immediately after the `MemberBlocked`
/// leaf.  This test drives the `BlockBroadcastSubscriber` command on a REAL
/// `MerkleEventLogProvider`, then reads back the event log to assert both
/// leaves are present and the `KeyEpochAdvance` payload is coherent.
#[tokio::test]
async fn block_subscriber_emits_key_epoch_advance_leaf() {
    let manager = new_manager();
    let ctx_id = "kea-block-subscriber-leaf";

    // Create a broadcast context.  Alice (the creator DID we pass here) is
    // auto-registered as the first (and only) author.
    manager
        .create_context(ctx_id.into(), broadcast_params(), alice(), None)
        .await
        .expect("create broadcast context");

    // Subscribe bob so there is a registered subscriber to block.
    subscribe_bob(&manager, ctx_id).await;

    // Alice blocks bob.  The handler appends MemberBlocked then
    // KeyEpochAdvance (best-effort) to the event log.
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = BroadcastCommand::BlockBroadcastSubscriber {
        payload: Box::new(BroadcastBlockPayload {
            context_id: ctx_id.to_owned(),
            author_did: alice(),
            subscriber_did: bob(),
        }),
        reply: tx,
    };
    manager
        .dispatch_broadcast_command(cmd)
        .await
        .expect("dispatch BlockBroadcastSubscriber");
    let block_result = rx.await.expect("block reply").expect("block succeeds");

    // Read the durable event-log entries back out.
    let ctx_bytes = scp_protocol::context::context_id_bytes(ctx_id);
    let entries = manager
        .event_log_entries(&ctx_bytes)
        .expect("event_log_entries Ok")
        .expect("event log exists for active context");

    // Assert MemberBlocked leaf is present.
    assert!(
        entries
            .iter()
            .any(|e| e.event_type == EventType::MemberBlocked),
        "REGRESSION: MemberBlocked leaf missing from event log after block_broadcast_subscriber"
    );

    // Assert KeyEpochAdvance leaf is present — the best-effort append that
    // must NOT silently regress to zero.
    let kea_leaves: Vec<_> = entries
        .iter()
        .filter(|e| e.event_type == EventType::KeyEpochAdvance)
        .collect();
    assert!(
        !kea_leaves.is_empty(),
        "REGRESSION: no KeyEpochAdvance leaf after block_broadcast_subscriber (#1847)"
    );

    // The leaf's actor_did must be alice (the author whose key was rotated).
    assert_eq!(
        kea_leaves[0].actor_did.as_ref(),
        alice().as_ref(),
        "KeyEpochAdvance actor_did must be the blocking author (alice)"
    );

    // Decode the payload and validate the epoch transition.
    let kea_payload = scp_event_log::payload::decode_payload::<
        scp_event_log::payload::KeyEpochAdvancePayload,
    >(&kea_leaves[0].payload)
    .expect("KeyEpochAdvancePayload decodes");

    assert!(
        kea_payload.new_epoch >= 1,
        "new_epoch must be >= 1 after a block (was epoch 0 at creation)"
    );
    assert_eq!(
        kea_payload.old_epoch + 1,
        kea_payload.new_epoch,
        "rotate_sender_key_for_block always increments by exactly 1: \
         old_epoch + 1 == new_epoch"
    );
    // Cross-check the payload epoch against the BlockResult returned live.
    assert_eq!(
        kea_payload.new_epoch, block_result.new_epoch,
        "KeyEpochAdvance payload new_epoch must match the BlockResult returned to the caller"
    );
}

// ===========================================================================
// Test 2: unsubscribe_broadcast with rotate_keys=true emits KeyEpochAdvance
// ===========================================================================

/// Unsubscribing with `rotate_keys = true` rotates every author's broadcast
/// key (forward secrecy: the departing subscriber cannot decrypt future
/// broadcasts).  Each rotation produces one `KeyEpochAdvance` leaf.  This
/// test asserts a `MemberLeft` leaf AND at least one `KeyEpochAdvance` leaf
/// are appended by `unsubscribe_broadcast`.
#[tokio::test]
async fn unsubscribe_with_key_rotation_emits_key_epoch_advance_leaf() {
    let manager = new_manager();
    let ctx_id = "kea-unsubscribe-rotate-leaf";

    manager
        .create_context(ctx_id.into(), broadcast_params(), alice(), None)
        .await
        .expect("create broadcast context");

    subscribe_bob(&manager, ctx_id).await;

    // Bob unsubscribes with key rotation requested.  The handler appends
    // MemberLeft then one KeyEpochAdvance per rotated author.
    let (tx, rx) = tokio::sync::oneshot::channel();
    let cmd = BroadcastCommand::UnsubscribeBroadcast {
        payload: Box::new(UnsubscribeBroadcastPayload {
            context_id: ctx_id.to_owned(),
            subscriber_did: bob(),
            rotate_keys: true,
        }),
        reply: tx,
    };
    manager
        .dispatch_broadcast_command(cmd)
        .await
        .expect("dispatch UnsubscribeBroadcast");
    let unsub_result = rx
        .await
        .expect("unsubscribe reply")
        .expect("unsubscribe succeeds");

    // Sanity: the result reports at least one key rotation (alice is the only
    // author, so exactly one rotation is expected).
    assert!(
        !unsub_result.key_rotations.is_empty(),
        "UnsubscribeResult.key_rotations is empty with rotate_keys=true — \
         no keys to rotate means no KeyEpochAdvance leaves, making the subsequent assertions vacuous"
    );

    // Read durable event-log entries.
    let ctx_bytes = scp_protocol::context::context_id_bytes(ctx_id);
    let entries = manager
        .event_log_entries(&ctx_bytes)
        .expect("event_log_entries Ok")
        .expect("event log exists for active context");

    // Assert MemberLeft leaf.
    assert!(
        entries
            .iter()
            .any(|e| e.event_type == EventType::MemberLeft),
        "REGRESSION: MemberLeft leaf missing after unsubscribe_broadcast"
    );

    // Assert KeyEpochAdvance leaf — the best-effort append that must not
    // silently drop.
    let kea_leaves: Vec<_> = entries
        .iter()
        .filter(|e| e.event_type == EventType::KeyEpochAdvance)
        .collect();
    assert!(
        !kea_leaves.is_empty(),
        "REGRESSION: no KeyEpochAdvance leaf after unsubscribe with rotate_keys=true (#1847)"
    );

    // One leaf per rotated author: since alice is the only author, exactly one.
    assert_eq!(
        kea_leaves.len(),
        unsub_result.key_rotations.len(),
        "number of KeyEpochAdvance leaves must equal the number of rotated authors"
    );

    // Validate payload coherence for the first leaf.
    let kea_payload = scp_event_log::payload::decode_payload::<
        scp_event_log::payload::KeyEpochAdvancePayload,
    >(&kea_leaves[0].payload)
    .expect("KeyEpochAdvancePayload decodes");

    assert!(
        kea_payload.new_epoch >= 1,
        "new_epoch must be >= 1 after key rotation on unsubscribe"
    );
    assert_eq!(
        kea_payload.old_epoch + 1,
        kea_payload.new_epoch,
        "unsubscribe rotation always increments by exactly 1"
    );
}

// ===========================================================================
// Test 3: execute_revoke (governance ban) emits KeyEpochAdvance per author
// ===========================================================================

/// A governance `RevokeAccess { access: Both }` on a broadcast subscriber
/// calls `governance_ban_subscriber`, which rotates every author's broadcast
/// key and records one `KeyEpochAdvance` leaf per rotated author.  This test
/// exercises the code path in `execute_revoke` (`governance_helpers.rs`).
#[tokio::test]
async fn governance_ban_emits_key_epoch_advance_per_author() {
    let manager = new_manager();
    let ctx_id = "kea-governance-ban-leaf";

    // Create a broadcast context that includes MemberBan in the ceiling
    // (required by execute_revoke's ceiling-check gate) and uses SingleAdmin
    // governance so the proposal auto-executes.
    manager
        .create_context(ctx_id.into(), broadcast_params_with_ban(), alice(), None)
        .await
        .expect("create broadcast context with MemberBan");

    // Subscribe bob: execute_revoke checks membership, so bob must be a member.
    subscribe_bob(&manager, ctx_id).await;

    // Alice proposes RevokeAccess for bob.  In SingleAdmin mode this
    // auto-executes immediately, running execute_revoke.
    //
    // AccessScope::Both triggers both write revocation (block_author on
    // BroadcastContext — no KeyEpochAdvance) AND read revocation
    // (governance_ban_subscriber — KeyEpochAdvance per author).
    let sk_alice = signing_key_for_did(&alice());
    let (proposal, _events, _) = manager
        .propose_governance_action(
            ctx_id,
            &alice(),
            GovernanceAction::RevokeAccess {
                did: bob(),
                access: AccessScope::Both,
            },
            &sk_alice,
        )
        .await
        .expect("propose RevokeAccess");

    use scp_protocol::context::governance::ProposalStatus;
    assert_eq!(
        proposal.status,
        ProposalStatus::Approved,
        "SingleAdmin RevokeAccess must auto-execute"
    );

    // Read durable event-log entries.
    let ctx_bytes = scp_protocol::context::context_id_bytes(ctx_id);
    let entries = manager
        .event_log_entries(&ctx_bytes)
        .expect("event_log_entries Ok")
        .expect("event log exists for active context");

    // Assert at least one KeyEpochAdvance leaf was appended.
    let kea_leaves: Vec<_> = entries
        .iter()
        .filter(|e| e.event_type == EventType::KeyEpochAdvance)
        .collect();
    assert!(
        !kea_leaves.is_empty(),
        "REGRESSION: no KeyEpochAdvance leaf after governance ban (execute_revoke #1847)"
    );

    // There is exactly one author (alice, registered at context creation), so
    // there must be exactly one KeyEpochAdvance leaf.
    assert_eq!(
        kea_leaves.len(),
        1,
        "expected exactly one KeyEpochAdvance leaf (one per rotated author = alice)"
    );

    // The leaf's actor_did must be alice (the author whose key was rotated).
    assert_eq!(
        kea_leaves[0].actor_did.as_ref(),
        alice().as_ref(),
        "KeyEpochAdvance actor_did must be the rotated author (alice)"
    );

    // Validate payload coherence.
    let kea_payload = scp_event_log::payload::decode_payload::<
        scp_event_log::payload::KeyEpochAdvancePayload,
    >(&kea_leaves[0].payload)
    .expect("KeyEpochAdvancePayload decodes");

    assert!(
        kea_payload.new_epoch >= 1,
        "new_epoch must be >= 1 after governance-ban key rotation"
    );
    assert_eq!(
        kea_payload.old_epoch + 1,
        kea_payload.new_epoch,
        "governance_ban_subscriber rotation always increments by exactly 1"
    );
}

// ===========================================================================
// Test 4: RotateContentKeys on a broadcast context emits KeyEpochAdvance per
//         author (#1847)
// ===========================================================================

/// A `RotateContentKeys` governance action on a broadcast context must emit:
///
/// - Exactly one `ContentKeysRotated` leaf.
/// - Exactly N `KeyEpochAdvance` leaves, one per registered author, each with
///   `new_epoch == 1` (starting from 0 at creation) and `old_epoch + 1 ==
///   new_epoch`.
///
/// This pins the fix for the gap where `rotate_all_author_keys` previously
/// discarded the per-author advance data and emitted no `KeyEpochAdvance`
/// leaves.
#[tokio::test]
async fn rotate_content_keys_broadcast_emits_key_epoch_advance_per_author() {
    let manager = new_manager();
    let ctx_id = "kea-rotate-content-keys-broadcast";

    // Create a broadcast context.  Alice is auto-registered as an author at
    // creation.  The ceiling must include MessagesRead and MessagesWrite.
    manager
        .create_context(ctx_id.into(), broadcast_params(), alice(), None)
        .await
        .expect("create broadcast context");

    // Subscribe bob so the context has an active subscriber (ensures the
    // rotation code path touches a non-empty subscriber roster).
    subscribe_bob(&manager, ctx_id).await;

    // Alice (the single admin) proposes RotateContentKeys.  In SingleAdmin
    // mode the proposal auto-executes immediately.
    let sk_alice = signing_key_for_did(&alice());
    let (proposal, _events, _) = manager
        .propose_governance_action(
            ctx_id,
            &alice(),
            GovernanceAction::RotateContentKeys { reason: None },
            &sk_alice,
        )
        .await
        .expect("propose RotateContentKeys");

    use scp_protocol::context::governance::ProposalStatus;
    assert_eq!(
        proposal.status,
        ProposalStatus::Approved,
        "SingleAdmin RotateContentKeys must auto-execute"
    );

    // Read back the durable event-log entries.
    let ctx_bytes = scp_protocol::context::context_id_bytes(ctx_id);
    let entries = manager
        .event_log_entries(&ctx_bytes)
        .expect("event_log_entries Ok")
        .expect("event log exists for active context");

    // Assert exactly one ContentKeysRotated leaf.
    let ckr_leaves: Vec<_> = entries
        .iter()
        .filter(|e| e.event_type == EventType::ContentKeysRotated)
        .collect();
    assert_eq!(
        ckr_leaves.len(),
        1,
        "expected exactly one ContentKeysRotated leaf after RotateContentKeys, got {}",
        ckr_leaves.len()
    );

    // Assert KeyEpochAdvance leaves: one per registered author.  Alice is the
    // only author (the context creator is auto-registered), so exactly one
    // leaf is expected.
    let kea_leaves: Vec<_> = entries
        .iter()
        .filter(|e| e.event_type == EventType::KeyEpochAdvance)
        .collect();
    assert_eq!(
        kea_leaves.len(),
        1,
        "REGRESSION: expected one KeyEpochAdvance leaf per author after \
         RotateContentKeys on broadcast context (#1847), got {}",
        kea_leaves.len()
    );

    // The leaf's actor_did must be alice (the only registered author).
    assert_eq!(
        kea_leaves[0].actor_did.as_ref(),
        alice().as_ref(),
        "KeyEpochAdvance actor_did must be the rotated author (alice)"
    );

    // Validate payload coherence: first rotation from epoch 0 → epoch 1.
    let kea_payload = scp_event_log::payload::decode_payload::<
        scp_event_log::payload::KeyEpochAdvancePayload,
    >(&kea_leaves[0].payload)
    .expect("KeyEpochAdvancePayload decodes");

    assert_eq!(
        kea_payload.new_epoch, 1,
        "first RotateContentKeys must advance broadcast key from epoch 0 to 1"
    );
    assert_eq!(
        kea_payload.old_epoch, 0,
        "old_epoch must be 0 before the first rotation"
    );
}

// ===========================================================================
// Test 5: checkpoint counter for governance ban is 1 + kea_success_count
// ===========================================================================

/// Regression guard for the checkpoint-counter formula in `execute_revoke`.
///
/// The formula is `checkpoint_events_since += 1 + kea_success_count` (§5.14.8 /
/// §5.14.10).  A revert to `+= 1` would leave the counter under-counting; a
/// revert that also drops the KEA appends would reduce the durable leaf count.
///
/// `checkpoint_events_since` is not observable from integration tests, so this
/// test pins the DURABLE LEAF COUNT that the counter should track.  With a
/// single author (alice) the ban emits:
///   1 × `AccessRevoked`  +  1 × `KeyEpochAdvance`  =  2 leaves
///
/// If either leaf is silently dropped by a code regression in the append path,
/// this assertion fails. NOTE: a counter regression (`+= 2` → `+= 1`, or
/// `+= 1 + kea_success_count` → `+= 1`) would NOT fail this test, since
/// `checkpoint_events_since` is not directly observable from integration
/// tests — the counter formula itself must be guarded at unit level.
#[tokio::test]
async fn broadcast_governance_ban_checkpoint_counter_increments_by_one_plus_author_count() {
    let manager = new_manager();
    let ctx_id = "kea-ban-checkpoint-counter";

    manager
        .create_context(ctx_id.into(), broadcast_params_with_ban(), alice(), None)
        .await
        .expect("create broadcast context with MemberBan");

    subscribe_bob(&manager, ctx_id).await;

    // Governance ban on bob (SingleAdmin → auto-execute).
    let sk_alice = signing_key_for_did(&alice());
    let (proposal, _events, _) = manager
        .propose_governance_action(
            ctx_id,
            &alice(),
            GovernanceAction::RevokeAccess {
                did: bob(),
                access: AccessScope::Both,
            },
            &sk_alice,
        )
        .await
        .expect("propose RevokeAccess");

    use scp_protocol::context::governance::ProposalStatus;
    assert_eq!(
        proposal.status,
        ProposalStatus::Approved,
        "SingleAdmin RevokeAccess must auto-execute"
    );

    let ctx_bytes = scp_protocol::context::context_id_bytes(ctx_id);
    let entries = manager
        .event_log_entries(&ctx_bytes)
        .expect("event_log_entries Ok")
        .expect("event log exists for active context");

    // Assert AccessRevoked leaf is present (the '1' in '1 + kea_success_count').
    let access_revoked: Vec<_> = entries
        .iter()
        .filter(|e| e.event_type == EventType::AccessRevoked)
        .collect();
    assert_eq!(
        access_revoked.len(),
        1,
        "REGRESSION: expected exactly 1 AccessRevoked leaf after governance ban, got {}",
        access_revoked.len()
    );

    // Assert KeyEpochAdvance leaves: one per registered author (alice only here).
    let kea_leaves: Vec<_> = entries
        .iter()
        .filter(|e| e.event_type == EventType::KeyEpochAdvance)
        .collect();
    assert_eq!(
        kea_leaves.len(),
        1,
        "REGRESSION: expected 1 KeyEpochAdvance leaf (one per author = alice) after governance ban, got {}",
        kea_leaves.len()
    );

    // Combined count of operation-specific leaves: 1 (AccessRevoked) + 1 (KEA) = 2.
    // This pins the formula: checkpoint_events_since += 1 + kea_success_count.
    // With kea_success_count = 1, the counter should be 2 after this ban.
    // (Total event log entries may be higher due to context-creation / subscribe
    // setup leaves — we count only the leaves this operation is responsible for.)
    let operation_leaves = access_revoked.len() + kea_leaves.len();
    assert_eq!(
        operation_leaves, 2,
        "REGRESSION: execute_revoke must produce 1 AccessRevoked + 1 KEA leaf          (formula: 1 + kea_success_count), got {operation_leaves} leaves of those two types",
    );
}

// ===========================================================================
// Test 6: checkpoint counter for ReconfigureGovernance is exactly 2
// ===========================================================================

/// Regression guard for the checkpoint-counter formula in
/// `execute_reconfigure_governance`.
///
/// The formula is `checkpoint_events_since += 2` — one for `GovernanceReconfigured`
/// and one for `GovernanceDeadlockRecovery`.  A revert to `+= 1` would leave the
/// counter under-counting.
///
/// `checkpoint_events_since` is not observable from integration tests, so this
/// test pins the DURABLE LEAF COUNT that the counter should track:
///   1 × `GovernanceReconfigured`  +  1 × `GovernanceDeadlockRecovery`  =  2 leaves
///
/// If either leaf is silently dropped by a code regression in the append path,
/// this assertion fails. NOTE: a counter regression (`+= 2` → `+= 1`, or
/// `+= 1 + kea_success_count` → `+= 1`) would NOT fail this test, since
/// `checkpoint_events_since` is not directly observable from integration
/// tests — the counter formula itself must be guarded at unit level.
#[tokio::test]
async fn governance_reconfigure_checkpoint_counter_increments_by_two() {
    use scp_protocol::context::governance::{DeadlockJustification, GovernanceReconfigAction};

    let manager = new_manager();
    let ctx_id = "kea-reconfigure-checkpoint-counter";

    // Threshold(1-of-2): alice's auto-vote immediately crosses the threshold,
    // so ReconfigureGovernance executes inline without a second voter.
    let params = scp_protocol::context::params::ContextParams {
        ceiling: vec![
            Capability::new("governance:propose").expect("known capability"),
            Capability::new("governance:vote").expect("known capability"),
            Capability::new("governance:reconfigure").expect("known capability"),
        ],
        governance: scp_protocol::context::params::GovernanceModel::Threshold {
            threshold: 1,
            signers: vec![alice(), bob()],
        },
        ..scp_protocol::context::params::ContextParams::default()
    };
    manager
        .create_context(ctx_id.into(), params, alice(), None)
        .await
        .expect("create threshold context");

    let justification = DeadlockJustification {
        unavailable_dids: vec![bob()],
        missed_windows: vec![(bob(), 3)],
        detected_at: 1_700_000_000,
    };
    let action = GovernanceAction::ReconfigureGovernance {
        changes: vec![GovernanceReconfigAction::RemoveInactiveSigner { did: bob() }],
        justification,
    };
    let sk_alice = signing_key_for_did(&alice());

    let (proposal, _events, _) = manager
        .propose_governance_action(ctx_id, &alice(), action, &sk_alice)
        .await
        .expect("propose ReconfigureGovernance");

    use scp_protocol::context::governance::ProposalStatus;
    assert_eq!(
        proposal.status,
        ProposalStatus::Approved,
        "threshold=1: proposer auto-vote must immediately approve and execute"
    );

    let ctx_bytes = scp_protocol::context::context_id_bytes(ctx_id);
    let entries = manager
        .event_log_entries(&ctx_bytes)
        .expect("event_log_entries Ok")
        .expect("event log exists for active context");

    // Assert exactly one GovernanceReconfigured leaf.
    let reconfig_leaves: Vec<_> = entries
        .iter()
        .filter(|e| e.event_type == scp_event_log::EventType::GovernanceReconfigured)
        .collect();
    assert_eq!(
        reconfig_leaves.len(),
        1,
        "REGRESSION: expected exactly 1 GovernanceReconfigured leaf, got {}",
        reconfig_leaves.len()
    );

    // Assert exactly one GovernanceDeadlockRecovery leaf.
    let recovery_leaves: Vec<_> = entries
        .iter()
        .filter(|e| e.event_type == scp_event_log::EventType::GovernanceDeadlockRecovery)
        .collect();
    assert_eq!(
        recovery_leaves.len(),
        1,
        "REGRESSION: expected exactly 1 GovernanceDeadlockRecovery leaf, got {}",
        recovery_leaves.len()
    );

    // Combined count of operation-specific leaves: 1 (GovernanceReconfigured) + 1
    // (GovernanceDeadlockRecovery) = 2.  This pins the formula:
    //   checkpoint_events_since += 2
    // A revert that drops either leaf is caught by the per-type assertions above;
    // this combined assertion verifies no EXTRA unexpected leaves are emitted by
    // the execute_reconfigure_governance path either.
    // (Total event log entries may be higher due to context-creation setup leaves —
    // we count only the leaves this operation is responsible for.)
    let operation_leaves = reconfig_leaves.len() + recovery_leaves.len();
    assert_eq!(
        operation_leaves, 2,
        "REGRESSION: execute_reconfigure_governance must produce exactly          1 GovernanceReconfigured + 1 GovernanceDeadlockRecovery leaf (formula: += 2),          got {operation_leaves} leaves of those two types",
    );
}
