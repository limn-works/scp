#![allow(
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::items_after_statements,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    // ADR-049 commit 12c.2: lifecycle hoist inflates some test-path
    // futures past clippy's 16 KB stack budget.
    clippy::large_futures
)]
//! SCP-CAC-009: Content access integration tests.
//!
//! Exercises the full block/unblock lifecycle across encrypted and broadcast
//! context types. Tests all three tiers (in-context, global, governance-gated),
//! all three enforcement layers (key distribution denial, SDK-mandated
//! destruction, access key wrapping), and forward-only restoration semantics.
//!
//! See spec §3.6, §9.16, §9.17, ADR-031, ADR-038.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use scp_did::{DID, SigningKeyId};
use scp_platform::testing::InMemoryKeyCustody;
use scp_platform::traits::{KeyCustody, KeyType};
use scp_protocol::context::ContextError;
use scp_protocol::context::builder::ContextCreationError;
use scp_protocol::context::governance::{
    AccessScope, GovernanceAction, KeyResolver, ProposalStatus,
};
use scp_protocol::context::params::{Capability, ContextParams, GovernanceModel};
use scp_protocol::crypto::access_keys::wrapping::{Recipient, unwrap_content, wrap_content};
use scp_protocol::crypto::access_keys::{AccessKeyStore, ContentAccessState, generate_access_key};
use scp_protocol::crypto::sender_keys::{BlockNotification, SenderKeyStore, generate_sender_key};
use scp_protocol::identity::block_list::{BlockListEvent, BlockListState};
use scp_runtime::context::ContextHandle;
use scp_runtime::context::builder::{ContextEventLogProvider, ContextTransportProvider};
use scp_runtime::context::state::ProposalOutcome;
use scp_runtime::context::supervisor::{MessageSigner, Supervisor};
use scp_runtime::crypto::access_keys::lifecycle::{
    handle_block_as_blocked_party, handle_block_as_blocker, restore_access_key, revoke_access_key,
    revoke_read_access, revoke_write_access,
};
use scp_runtime::crypto::mls::provider::NodeMlsFactory;
use scp_runtime::crypto::sender_keys::key_protocol::send_block_notification;
use scp_runtime::identity::blocking::{
    BlockInContextParams, GlobalBlockParams, block_did_global, block_did_in_context,
    is_block_effective,
};

// ---------------------------------------------------------------------------
// DID string constants
// ---------------------------------------------------------------------------

const ALICE: &str = "did:dht:z6MkAlice";
const BOB: &str = "did:dht:z6MkBob";
const DAVE: &str = "did:dht:z6MkDave";
const EVE: &str = "did:dht:z6MkEve";
const AUTHOR: &str = "did:dht:z6MkAuthor";

fn alice() -> DID {
    DID::from(ALICE)
}
fn bob() -> DID {
    DID::from(BOB)
}
fn dave() -> DID {
    DID::from(DAVE)
}
fn eve() -> DID {
    DID::from(EVE)
}
fn author_did() -> DID {
    DID::from(AUTHOR)
}

// ---------------------------------------------------------------------------
// Custody helpers
// ---------------------------------------------------------------------------

async fn make_custody_and_key() -> (InMemoryKeyCustody, scp_platform::traits::KeyHandle) {
    let custody = InMemoryKeyCustody::new();
    let handle = custody
        .generate_keypair(KeyType::Ed25519)
        .await
        .expect("key generation should succeed");
    (custody, handle)
}

// ---------------------------------------------------------------------------
// Mock providers (same pattern as content_access_governance_integration.rs)
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

#[derive(Default)]
struct MockEventLog;

#[async_trait::async_trait]
impl ContextEventLogProvider for MockEventLog {
    async fn init_event_log(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    async fn append_event(
        &self,
        _id: &[u8; 32],
        _event: scp_event_log::EventType,
        _actor_did: &str,
        _payload: scp_event_log::EventPayload,
        _timestamp_secs: u64,
    ) -> Result<(), ContextCreationError> {
        Ok(())
    }
    async fn destroy_event_log(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Key resolver helpers (same as governance integration tests)
// ---------------------------------------------------------------------------

fn did_to_seed(did: &DID) -> [u8; 32] {
    let mut s = [0u8; 32];
    let bytes = did.as_ref().as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        s[i % 32] ^= *b;
    }
    s
}

fn mock_key_resolver() -> KeyResolver {
    Arc::new(|did, _kid: scp_did::SigningKeyId| {
        let seed = did_to_seed(did);
        Some(ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key())
    })
}

fn signing_key_for_did(did: &DID) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&did_to_seed(did))
}

// ---------------------------------------------------------------------------
// Manager factory
// ---------------------------------------------------------------------------

fn new_manager() -> std::sync::Arc<scp_runtime::context::supervisor::Supervisor> {
    // ADR-049 commit 12 — `ContextManager` is gone; tests construct a
    // `Supervisor` directly via `test_supervisor`.
    scp_runtime::context::test_supervisor(
        Arc::new(NodeMlsFactory::new(
            "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_owned(),
            std::sync::Arc::new(scp_clock::SystemClock),
        )),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog),
        mock_key_resolver(),
    )
}

fn governance_ceiling() -> Vec<Capability> {
    vec![
        Capability::new("messages:read").expect("known capability"),
        Capability::new("messages:write").expect("known capability"),
        Capability::new("role:assign").expect("known capability"),
        Capability::new("governance:propose").expect("known capability"),
        Capability::new("governance:vote").expect("known capability"),
        Capability::new("context:close").expect("known capability"),
        Capability::MemberBan,
    ]
}

/// Helper: propose a governance action with Threshold(2-of-N) approval.
/// Alice proposes, Bob approves.
///
/// Returns a boxed future because the composed state machine inside
/// `ContextManager::propose_governance_action_checked` +
/// `vote_on_proposal` exceeds clippy's `large_futures` threshold
/// (~16 KB) when inlined at many call sites.
fn propose_and_approve_threshold<'a>(
    manager: &'a Supervisor,
    ctx_id: &'a str,
    action: GovernanceAction,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = ProposalOutcome> + Send + 'a>> {
    Box::pin(async move {
        let sk_alice = signing_key_for_did(&alice());

        let outcome = manager
            .propose_governance_action_checked(ctx_id, &alice(), action, &sk_alice)
            .await
            .unwrap();

        if outcome.status == ProposalStatus::Pending {
            let sk_bob = signing_key_for_did(&bob());
            let (status, _events) = manager
                .vote_on_proposal(ctx_id, &outcome.proposal.proposal_id, &bob(), true, &sk_bob)
                .await
                .unwrap();
            assert_eq!(
                status,
                ProposalStatus::Approved,
                "threshold proposal should be approved after 2/2 votes"
            );

            let fetched = manager
                .get_proposal(ctx_id, &outcome.proposal.proposal_id)
                .await
                .unwrap();
            ProposalOutcome {
                proposal: fetched,
                status,
                execution_result: None,
            }
        } else {
            outcome
        }
    })
}

// =========================================================================
// Test 1: Tier 1 in-context block/unblock lifecycle
// =========================================================================

/// Tier 1 (in-context) block/unblock lifecycle with content access control.
///
/// Creates an encrypted context with Alice, Bob, Dave (3 members).
/// - Alice blocks Dave in-context -> Dave's `ContentAccessState` transitions
///   to `PresenceOnly`.
/// - Verify Dave cannot decrypt Alice's future messages.
/// - Verify Dave CAN still decrypt Bob's messages (block is per-DID).
/// - Alice unblocks Dave -> Dave gets NEW access key (forward-only).
/// - Verify Dave can decrypt future messages from Alice.
/// - Verify Dave CANNOT decrypt messages from the blocked period.
#[tokio::test]
async fn tier1_in_context_block_unblock_lifecycle() {
    let context_id = "ctx-tier1-lifecycle";
    let (custody, signing_key) = make_custody_and_key().await;

    // --- Setup: generate access keys for Alice, Bob, Dave ---

    let alice_access_key = generate_access_key(context_id, ALICE);
    let bob_access_key = generate_access_key(context_id, BOB);
    let dave_access_key = generate_access_key(context_id, DAVE);

    // --- Pre-block: Alice sends message to all 3 members ---

    let pre_block_msg = b"Pre-block message from Alice";
    let recipients_all = vec![
        Recipient {
            did: ALICE,
            access_key: &alice_access_key,
        },
        Recipient {
            did: BOB,
            access_key: &bob_access_key,
        },
        Recipient {
            did: DAVE,
            access_key: &dave_access_key,
        },
    ];
    let wrapped_pre =
        wrap_content(pre_block_msg, &recipients_all, context_id, ALICE, 0, 1).unwrap();

    // Verify Dave can decrypt pre-block message.
    let decrypted = unwrap_content(
        &wrapped_pre,
        DAVE,
        &dave_access_key,
        context_id,
        ALICE,
        0,
        1,
    )
    .unwrap();
    assert_eq!(decrypted, pre_block_msg);

    // --- Alice blocks Dave (Tier 1) ---

    let mut block_list: HashSet<String> = HashSet::new();
    let block_params = BlockInContextParams {
        blocker_did: ALICE,
        target_did: DAVE,
        context_id,
        current_epoch: 0,
        signer_key_ref: SigningKeyId::Active,
    };
    let clock = scp_clock::SystemClock;
    let block_result = block_did_in_context(
        &custody,
        &signing_key,
        &block_params,
        &mut block_list,
        &clock,
    )
    .await
    .expect("block should succeed");

    // Verify Layer 1: Dave is in the block list.
    assert!(block_list.contains(DAVE));
    // Verify Layer 2: destruction event targets Dave.
    assert_eq!(block_result.destruction_event.target_did, dave());
    // Verify Layer 3: access key deletion signaled.
    assert!(block_result.access_key_deletion_required);

    // Simulate Layer 3: remove Dave's access key from Alice's store.
    let mut alice_access_store = AccessKeyStore::new();
    alice_access_store.set(context_id, DAVE, generate_access_key(context_id, DAVE));
    let deleted = handle_block_as_blocker(&mut alice_access_store, context_id, DAVE);
    assert!(deleted);
    assert!(alice_access_store.get(context_id, DAVE).is_none());

    // Verify ContentAccessState transition: Full -> PresenceOnly.
    let dave_state = ContentAccessState::Full;
    let revoke_result =
        revoke_read_access(&mut AccessKeyStore::new(), context_id, DAVE, dave_state);
    assert!(revoke_result.is_ok());
    assert_eq!(
        revoke_result.unwrap().new_state,
        ContentAccessState::PresenceOnly,
    );

    // --- Post-block: Alice sends message EXCLUDING Dave from recipients ---

    let post_block_msg = b"Post-block message from Alice (Dave excluded)";
    let recipients_no_dave = vec![
        Recipient {
            did: ALICE,
            access_key: &alice_access_key,
        },
        Recipient {
            did: BOB,
            access_key: &bob_access_key,
        },
    ];
    let wrapped_blocked = wrap_content(
        post_block_msg,
        &recipients_no_dave,
        context_id,
        ALICE,
        1, // new epoch after block
        2,
    )
    .unwrap();

    // Dave cannot decrypt Alice's post-block message (not a recipient).
    let dave_decrypt = unwrap_content(
        &wrapped_blocked,
        DAVE,
        &dave_access_key,
        context_id,
        ALICE,
        1,
        2,
    );
    assert!(
        dave_decrypt.is_err(),
        "Dave should not be able to decrypt Alice's post-block message"
    );

    // --- Verify Dave CAN still decrypt Bob's messages (per-DID block) ---

    let bob_msg = b"Message from Bob to all";
    let bob_recipients = vec![
        Recipient {
            did: ALICE,
            access_key: &alice_access_key,
        },
        Recipient {
            did: BOB,
            access_key: &bob_access_key,
        },
        Recipient {
            did: DAVE,
            access_key: &dave_access_key,
        },
    ];
    let wrapped_bob = wrap_content(bob_msg, &bob_recipients, context_id, BOB, 0, 3).unwrap();

    let dave_from_bob =
        unwrap_content(&wrapped_bob, DAVE, &dave_access_key, context_id, BOB, 0, 3).unwrap();
    assert_eq!(
        dave_from_bob, bob_msg,
        "Dave should still decrypt Bob's messages (block is per-DID)"
    );

    // --- Alice unblocks Dave: forward-only restoration ---

    let revocation = revoke_access_key(&dave_access_key).unwrap();
    let dave_new_access_key = restore_access_key(context_id, DAVE, revocation.new_epoch);

    // Verify new key is different from old key (forward-only).
    assert_ne!(
        dave_access_key.as_bytes(),
        dave_new_access_key.as_bytes(),
        "Restored access key must be new key material (forward-only)"
    );
    assert_eq!(dave_new_access_key.epoch(), 1);

    // --- Post-unblock: Alice sends message including Dave with new key ---

    let post_unblock_msg = b"Post-unblock message from Alice";
    let recipients_restored = vec![
        Recipient {
            did: ALICE,
            access_key: &alice_access_key,
        },
        Recipient {
            did: BOB,
            access_key: &bob_access_key,
        },
        Recipient {
            did: DAVE,
            access_key: &dave_new_access_key,
        },
    ];
    let wrapped_post_unblock = wrap_content(
        post_unblock_msg,
        &recipients_restored,
        context_id,
        ALICE,
        2, // new epoch after unblock
        4,
    )
    .unwrap();

    // Dave CAN decrypt future messages with new key.
    let dave_post = unwrap_content(
        &wrapped_post_unblock,
        DAVE,
        &dave_new_access_key,
        context_id,
        ALICE,
        2,
        4,
    )
    .unwrap();
    assert_eq!(dave_post, post_unblock_msg);

    // Dave CANNOT decrypt messages from the blocked period with new key.
    let dave_blocked_period = unwrap_content(
        &wrapped_blocked,
        DAVE,
        &dave_new_access_key,
        context_id,
        ALICE,
        1,
        2,
    );
    assert!(
        dave_blocked_period.is_err(),
        "Dave should NOT decrypt messages from the blocked period (forward-only)"
    );
}

// =========================================================================
// Test 2: Tier 2 global block propagation
// =========================================================================

/// Tier 2 (global) block propagation across multiple shared contexts.
///
/// Creates 2 contexts sharing Alice and Eve.
/// - Alice globally blocks Eve -> Eve blocked in BOTH contexts.
/// - Verify Eve cannot decrypt in either context.
/// - Alice unblocks Eve -> forward-only restoration in both.
#[tokio::test]
async fn tier2_global_block_propagation() {
    let (custody, signing_key) = make_custody_and_key().await;
    let ctx1 = "ctx-tier2-ctx1";
    let ctx2 = "ctx-tier2-ctx2";

    // --- Setup: access keys for both contexts ---

    let alice_key_ctx1 = generate_access_key(ctx1, ALICE);
    let eve_key_ctx1 = generate_access_key(ctx1, EVE);
    let alice_key_ctx2 = generate_access_key(ctx2, ALICE);
    let eve_key_ctx2 = generate_access_key(ctx2, EVE);

    // Pre-block messages in both contexts.
    let msg1 = b"Message in context 1";
    let msg2 = b"Message in context 2";

    let wrapped1_pre = wrap_content(
        msg1,
        &[
            Recipient {
                did: ALICE,
                access_key: &alice_key_ctx1,
            },
            Recipient {
                did: EVE,
                access_key: &eve_key_ctx1,
            },
        ],
        ctx1,
        ALICE,
        0,
        1,
    )
    .unwrap();

    let wrapped2_pre = wrap_content(
        msg2,
        &[
            Recipient {
                did: ALICE,
                access_key: &alice_key_ctx2,
            },
            Recipient {
                did: EVE,
                access_key: &eve_key_ctx2,
            },
        ],
        ctx2,
        ALICE,
        0,
        1,
    )
    .unwrap();

    // Eve can decrypt in both contexts before block.
    let dec1 = unwrap_content(&wrapped1_pre, EVE, &eve_key_ctx1, ctx1, ALICE, 0, 1).unwrap();
    assert_eq!(dec1, msg1);
    let dec2 = unwrap_content(&wrapped2_pre, EVE, &eve_key_ctx2, ctx2, ALICE, 0, 1).unwrap();
    assert_eq!(dec2, msg2);

    // --- Alice globally blocks Eve ---

    let block_list_state = BlockListState::new();
    let mut per_context_block_lists = HashMap::new();
    let mut per_context_epochs = HashMap::new();
    per_context_epochs.insert(ctx1.to_owned(), 0u64);
    per_context_epochs.insert(ctx2.to_owned(), 0u64);

    let shared_contexts = vec![ctx1.to_owned(), ctx2.to_owned()];
    let global_params = GlobalBlockParams {
        blocker_did: ALICE,
        target_did: EVE,
        shared_context_ids: &shared_contexts,
        signer_key_ref: SigningKeyId::Active,
    };
    let clock = scp_clock::SystemClock;
    let global_result = block_did_global(
        &custody,
        &signing_key,
        &global_params,
        &block_list_state,
        &mut per_context_block_lists,
        &per_context_epochs,
        &clock,
    )
    .await
    .expect("global block should succeed");

    // Both contexts had block executed.
    assert_eq!(global_result.context_results.len(), 2);
    assert!(global_result.pending_contexts.is_empty());

    // Verify Eve is in block lists for both contexts.
    assert!(per_context_block_lists[ctx1].contains(EVE));
    assert!(per_context_block_lists[ctx2].contains(EVE));

    // Verify global block event.
    assert!(matches!(
        &global_result.block_list_event,
        BlockListEvent::BlockDID { target_did, .. }
        if *target_did == eve()
    ));

    // --- Post-block: Eve excluded from both contexts ---

    let post_block_ctx1 = b"Post-block ctx1";
    let wrapped1_post = wrap_content(
        post_block_ctx1,
        &[Recipient {
            did: ALICE,
            access_key: &alice_key_ctx1,
        }],
        ctx1,
        ALICE,
        1,
        2,
    )
    .unwrap();

    let eve_dec1_post = unwrap_content(&wrapped1_post, EVE, &eve_key_ctx1, ctx1, ALICE, 1, 2);
    assert!(
        eve_dec1_post.is_err(),
        "Eve should not decrypt in ctx1 after global block"
    );

    let post_block_ctx2 = b"Post-block ctx2";
    let wrapped2_post = wrap_content(
        post_block_ctx2,
        &[Recipient {
            did: ALICE,
            access_key: &alice_key_ctx2,
        }],
        ctx2,
        ALICE,
        1,
        2,
    )
    .unwrap();

    let eve_dec2_post = unwrap_content(&wrapped2_post, EVE, &eve_key_ctx2, ctx2, ALICE, 1, 2);
    assert!(
        eve_dec2_post.is_err(),
        "Eve should not decrypt in ctx2 after global block"
    );

    // --- Unblock: forward-only restoration in both contexts ---

    let eve_revoke_ctx1 = revoke_access_key(&eve_key_ctx1).unwrap();
    let eve_new_key_ctx1 = restore_access_key(ctx1, EVE, eve_revoke_ctx1.new_epoch);

    let eve_revoke_ctx2 = revoke_access_key(&eve_key_ctx2).unwrap();
    let eve_new_key_ctx2 = restore_access_key(ctx2, EVE, eve_revoke_ctx2.new_epoch);

    // Eve can decrypt future messages with new keys in ctx1.
    let future_ctx1 = b"Future message ctx1";
    let wrapped1_future = wrap_content(
        future_ctx1,
        &[
            Recipient {
                did: ALICE,
                access_key: &alice_key_ctx1,
            },
            Recipient {
                did: EVE,
                access_key: &eve_new_key_ctx1,
            },
        ],
        ctx1,
        ALICE,
        2,
        3,
    )
    .unwrap();

    let eve_future1 =
        unwrap_content(&wrapped1_future, EVE, &eve_new_key_ctx1, ctx1, ALICE, 2, 3).unwrap();
    assert_eq!(eve_future1, future_ctx1);

    // Eve can decrypt future messages with new keys in ctx2.
    let future_ctx2 = b"Future message ctx2";
    let wrapped2_future = wrap_content(
        future_ctx2,
        &[
            Recipient {
                did: ALICE,
                access_key: &alice_key_ctx2,
            },
            Recipient {
                did: EVE,
                access_key: &eve_new_key_ctx2,
            },
        ],
        ctx2,
        ALICE,
        2,
        3,
    )
    .unwrap();

    let eve_future2 =
        unwrap_content(&wrapped2_future, EVE, &eve_new_key_ctx2, ctx2, ALICE, 2, 3).unwrap();
    assert_eq!(eve_future2, future_ctx2);

    // Eve still cannot decrypt blocked-period messages with new key.
    let eve_old1 = unwrap_content(&wrapped1_post, EVE, &eve_new_key_ctx1, ctx1, ALICE, 1, 2);
    assert!(
        eve_old1.is_err(),
        "Eve should NOT decrypt blocked-period messages in ctx1 (forward-only)"
    );

    let eve_old2 = unwrap_content(&wrapped2_post, EVE, &eve_new_key_ctx2, ctx2, ALICE, 1, 2);
    assert!(
        eve_old2.is_err(),
        "Eve should NOT decrypt blocked-period messages in ctx2 (forward-only)"
    );
}

// =========================================================================
// Test 3: Tier 3 governance write revocation in broadcast
// =========================================================================

/// Tier 3 governance-gated content access control in broadcast context.
///
/// Creates a context with Author as a member.
/// - Governance `Revoke { access: AccessScope::Both }` on Author.
/// - Verify Author cannot publish new messages.
/// - `RestoreAccess { access: AccessScope::Write }` -> Author can publish again (forward-only).
#[tokio::test]
async fn tier3_governance_revoke_write_access_broadcast() {
    let manager = new_manager();
    let ctx_id = "ctx-tier3-broadcast";

    let params = ContextParams {
        ceiling: governance_ceiling(),
        governance: GovernanceModel::Threshold {
            threshold: 2,
            signers: vec![alice(), bob(), author_did()],
        },
        ..ContextParams::default()
    };
    let _handle = manager
        .create_context(ctx_id.into(), params.clone(), alice(), None)
        .await
        .unwrap();

    // Add Author as a member.
    let sk_alice = signing_key_for_did(&alice());
    let sk_bob = signing_key_for_did(&bob());

    let (add_author, _, _) = manager
        .propose_governance_action(
            ctx_id,
            &alice(),
            GovernanceAction::AddMember {
                did: author_did(),
                role: "author".into(),
            },
            &sk_alice,
        )
        .await
        .unwrap();
    let (status, _) = manager
        .vote_on_proposal(ctx_id, &add_author.proposal_id, &bob(), true, &sk_bob)
        .await
        .unwrap();
    assert_eq!(status, ProposalStatus::Approved);
    assert!(manager.is_member(ctx_id, AUTHOR).await);

    // §9.10.4: seed the author's pseudonym so the encrypted multi-member send
    // below has a non-empty routing registry (in production the author
    // announces this; the single-node test seeds it directly).
    manager
        .seed_peer_pseudonym(ctx_id, author_did(), [7u8; 32])
        .await
        .expect("seed peer pseudonym");

    // --- Governance Revoke { access: AccessScope::Both } on Author ---

    let revoke = GovernanceAction::RevokeAccess {
        did: author_did(),
        access: AccessScope::Both,
    };
    let outcome = propose_and_approve_threshold(&manager, ctx_id, revoke).await;
    assert_eq!(outcome.status, ProposalStatus::Approved);

    // Verify Author cannot publish (write access revoked).
    let handle = ContextHandle::new(ctx_id.to_owned(), params.clone());
    let send_result = manager
        .send_message(
            &handle,
            &author_did(),
            b"blocked message",
            MessageSigner::Active(&signing_key_for_did(&author_did())),
            None,
            None,
        )
        .await;
    assert!(
        send_result.is_err(),
        "Author should not be able to publish after write revocation"
    );
    match send_result.unwrap_err() {
        ContextError::PermissionDenied(msg) => {
            assert!(
                msg.contains("write access"),
                "error should mention write access: {msg}"
            );
        }
        other => panic!("expected PermissionDenied, got {other:?}"),
    }

    // Author is still a member (membership/access decoupling).
    assert!(
        manager.is_member(ctx_id, AUTHOR).await,
        "Author should remain a member after write revocation"
    );

    // --- RestoreAccess { access: AccessScope::Write } -> Author can publish again ---

    let _ = manager.drain_events(ctx_id).await;
    let restore = GovernanceAction::RestoreAccess {
        did: author_did(),
        capabilities: vec![Capability::MessagesWrite],
    };
    let outcome = propose_and_approve_threshold(&manager, ctx_id, restore).await;
    assert_eq!(outcome.status, ProposalStatus::Approved);

    // Verify WriteAccessRestored event.
    let events = manager.drain_events(ctx_id).await;
    let has_restored = events.iter().any(|e| {
        matches!(
            e,
            scp_protocol::context::membership::ContextEvent::WriteAccessRestored { did }
            if *did == author_did()
        )
    });
    assert!(
        has_restored,
        "WriteAccessRestored event should be emitted for Author"
    );

    // Author can send again.
    let send_result = manager
        .send_message(
            &handle,
            &author_did(),
            b"restored message",
            MessageSigner::Active(&signing_key_for_did(&author_did())),
            None,
            None,
        )
        .await;
    assert!(
        send_result.is_ok(),
        "Author should be able to publish after write restore: {:?}",
        send_result.err()
    );
}

// =========================================================================
// Test 4: Three-layer enforcement
// =========================================================================

/// Three-layer enforcement verification after Full revocation.
///
/// After Full revocation of Dave:
/// - Layer 1: `SenderKeyRequest` from Dave returns denial
///   (Dave is in the block list, `is_block_effective` returns true)
/// - Layer 2: Dave's cached sender keys are deleted
///   (`ContentAccessState` = `PresenceOnly`)
/// - Layer 3: Dave's access key is removed (wrapping no longer includes Dave)
#[tokio::test]
async fn three_layer_enforcement_after_full_revocation() {
    let context_id = "ctx-three-layers";
    let (custody, signing_key) = make_custody_and_key().await;

    // --- Layer 1: key distribution denial ---

    let mut block_list: HashSet<String> = HashSet::new();
    let block_params = BlockInContextParams {
        blocker_did: ALICE,
        target_did: DAVE,
        context_id,
        current_epoch: 0,
        signer_key_ref: SigningKeyId::Active,
    };
    let clock = scp_clock::SystemClock;
    let _block_result = block_did_in_context(
        &custody,
        &signing_key,
        &block_params,
        &mut block_list,
        &clock,
    )
    .await
    .unwrap();

    // Build block list state and check is_block_effective.
    let mut block_list_state = BlockListState::new();
    block_list_state.apply(&BlockListEvent::BlockDIDInContext {
        target_did: dave(),
        context_id: context_id.to_owned(),
        timestamp: 1000,
    });

    // Layer 1 check: SenderKeyRequest from Dave would be denied.
    assert!(
        is_block_effective(&block_list_state, &dave(), context_id),
        "Layer 1: Dave should be effectively blocked (key distribution denied)"
    );

    // Not blocked for other members.
    assert!(
        !is_block_effective(&block_list_state, &bob(), context_id),
        "Bob should NOT be blocked"
    );

    // --- Layer 2: SDK-mandated state destruction ---

    let notification_bytes = send_block_notification(
        &custody,
        &signing_key,
        context_id,
        ALICE,
        DAVE,
        SigningKeyId::Active,
        &clock,
    )
    .await
    .unwrap();

    let notification: BlockNotification =
        rmp_serde::from_slice(&notification_bytes).expect("deserialize notification");
    let pubkey = custody.public_key(&signing_key).await.unwrap();

    // Set up Dave's stores with Alice's cached material.
    let mut dave_sender_store = SenderKeyStore::new();
    dave_sender_store.set_unchecked(context_id, ALICE, generate_sender_key());
    let mut dave_access_store = AccessKeyStore::new();
    dave_access_store.set(context_id, ALICE, generate_access_key(context_id, ALICE));

    // Dave processes the verified block notification.
    let destruction = handle_block_as_blocked_party(
        &notification,
        context_id,
        &pubkey.into_bytes(),
        &mut dave_sender_store,
        &mut dave_access_store,
    );
    assert!(
        destruction.is_some(),
        "valid notification should trigger destruction"
    );
    let destruction = destruction.unwrap();

    // Layer 2: sender keys deleted.
    assert_eq!(destruction.sender_keys_deleted, 1);
    assert!(
        dave_sender_store.get(context_id, ALICE).is_none(),
        "Layer 2: Dave's cached sender keys from Alice should be deleted"
    );

    // Layer 3 (on blocked side): access key deleted.
    assert!(destruction.access_key_deleted);
    assert!(
        dave_access_store.get(context_id, ALICE).is_none(),
        "Layer 3 (blocked side): Alice's access key deleted from Dave's store"
    );

    // --- Layer 3 (on blocker side): wrapping no longer includes Dave ---

    let mut alice_access_store = AccessKeyStore::new();
    alice_access_store.set(context_id, DAVE, generate_access_key(context_id, DAVE));

    let blocker_deleted = handle_block_as_blocker(&mut alice_access_store, context_id, DAVE);
    assert!(
        blocker_deleted,
        "Layer 3 (blocker): Dave's access key should be deleted"
    );
    assert!(
        alice_access_store.get(context_id, DAVE).is_none(),
        "Layer 3: Dave's access key removed from Alice's store"
    );

    // ContentAccessState = PresenceOnly after full revocation.
    let state = ContentAccessState::Full;
    let revoke_result =
        revoke_read_access(&mut AccessKeyStore::new(), context_id, DAVE, state).unwrap();
    assert_eq!(
        revoke_result.new_state,
        ContentAccessState::PresenceOnly,
        "Layer 2: ContentAccessState should be PresenceOnly after revocation"
    );

    // Verify wrapping no longer includes Dave.
    let alice_key = generate_access_key(context_id, ALICE);
    let bob_key = generate_access_key(context_id, BOB);
    let msg = b"Post-revocation message";
    let wrapped = wrap_content(
        msg,
        &[
            Recipient {
                did: ALICE,
                access_key: &alice_key,
            },
            Recipient {
                did: BOB,
                access_key: &bob_key,
            },
            // Dave intentionally excluded — his access key was deleted.
        ],
        context_id,
        ALICE,
        1,
        1,
    )
    .unwrap();

    // Dave cannot decrypt (not a recipient).
    let dave_key = generate_access_key(context_id, DAVE);
    let dave_dec = unwrap_content(&wrapped, DAVE, &dave_key, context_id, ALICE, 1, 1);
    assert!(
        dave_dec.is_err(),
        "Dave should not be able to decrypt (excluded from wrapping)"
    );
}

// =========================================================================
// Test 5: Tier stacking
// =========================================================================

/// Tier stacking: both identity-level (Tier 1) and governance (Tier 3)
/// revoke Dave's access. Reversing only one does not restore access.
/// Both must be reversed.
#[tokio::test]
async fn tier_stacking_requires_both_reversals() {
    let context_id = "ctx-tier-stacking";

    // --- Identity-level block (Tier 1) ---

    let mut block_list_state = BlockListState::new();
    block_list_state.apply(&BlockListEvent::BlockDIDInContext {
        target_did: dave(),
        context_id: context_id.to_owned(),
        timestamp: 1000,
    });

    // Dave is blocked at Tier 1.
    assert!(is_block_effective(&block_list_state, &dave(), context_id));

    // --- Governance revocation (Tier 3) ---

    let state_after_write_revoke = revoke_write_access(context_id, DAVE, ContentAccessState::Full);
    assert!(state_after_write_revoke.is_ok());
    assert_eq!(
        state_after_write_revoke.unwrap().new_state,
        ContentAccessState::ReadOnly
    );

    // Also revoke read (full governance revocation -> PresenceOnly).
    let state_after_read_revoke = revoke_read_access(
        &mut AccessKeyStore::new(),
        context_id,
        DAVE,
        ContentAccessState::ReadOnly,
    );
    assert!(state_after_read_revoke.is_ok());
    assert_eq!(
        state_after_read_revoke.unwrap().new_state,
        ContentAccessState::PresenceOnly
    );

    // --- Reverse ONLY Alice's Tier 1 block ---

    block_list_state.unblock_did_in_context(dave(), context_id.to_owned(), 2000);

    // Tier 1 block is lifted.
    assert!(
        !block_list_state.is_blocked_in_context(&dave(), context_id),
        "Tier 1 block should be lifted after unblock"
    );

    // But governance still has Dave at PresenceOnly -> cannot read or write.
    let governance_state = ContentAccessState::PresenceOnly;
    assert!(
        !governance_state.can_read(),
        "Dave should NOT have read access (governance still restricts)"
    );
    assert!(
        !governance_state.can_write(),
        "Dave should NOT have write access (governance still restricts)"
    );

    // --- Reverse governance block too -> Dave fully restored ---

    let restored_state = governance_state.restore_to(ContentAccessState::Full);
    assert_eq!(restored_state, ContentAccessState::Full);
    assert!(restored_state.can_read());
    assert!(restored_state.can_write());

    // Both tiers reversed -> Dave has full access (forward-only: new key).
    let dave_new_key = generate_access_key(context_id, DAVE);
    let alice_key = generate_access_key(context_id, ALICE);
    let msg = b"Fully restored message";
    let wrapped = wrap_content(
        msg,
        &[
            Recipient {
                did: ALICE,
                access_key: &alice_key,
            },
            Recipient {
                did: DAVE,
                access_key: &dave_new_key,
            },
        ],
        context_id,
        ALICE,
        0,
        1,
    )
    .unwrap();

    let dave_dec = unwrap_content(&wrapped, DAVE, &dave_new_key, context_id, ALICE, 0, 1).unwrap();
    assert_eq!(
        dave_dec, msg,
        "Dave should decrypt after both tiers are reversed"
    );
}

// =========================================================================
// Test 6: Forward-only restoration
// =========================================================================

/// Forward-only restoration verification.
///
/// Block, send 3 messages during block, unblock.
/// - Messages 1-3 from block period are NOT decryptable.
/// - Message 4 (post-unblock) IS decryptable.
#[tokio::test]
async fn forward_only_restoration_messages() {
    let context_id = "ctx-forward-only";

    // --- Setup ---

    let alice_key = generate_access_key(context_id, ALICE);
    let dave_key_original = generate_access_key(context_id, DAVE);

    // --- Block Dave ---
    // Dave is blocked. Alice sends 3 messages during the block period.
    // Dave is NOT in the recipients list for these messages.

    let mut blocked_messages = Vec::new();
    for seq in 1..=3u64 {
        let msg = format!("Blocked-period message {seq}");
        let wrapped = wrap_content(
            msg.as_bytes(),
            &[Recipient {
                did: ALICE,
                access_key: &alice_key,
            }],
            context_id,
            ALICE,
            1, // epoch after block
            seq,
        )
        .unwrap();
        blocked_messages.push((wrapped, msg));
    }

    // --- Unblock Dave: new key at new epoch ---

    let revocation = revoke_access_key(&dave_key_original).unwrap();
    let dave_key_restored = restore_access_key(context_id, DAVE, revocation.new_epoch);

    // --- Verify blocked-period messages NOT decryptable ---

    for (idx, (wrapped, _msg)) in blocked_messages.iter().enumerate() {
        let seq = (idx as u64) + 1;

        // Try with OLD key: not a recipient (was excluded during block).
        let result_old =
            unwrap_content(wrapped, DAVE, &dave_key_original, context_id, ALICE, 1, seq);
        assert!(
            result_old.is_err(),
            "Message {seq} from block period should NOT be decryptable with old key"
        );

        // Try with NEW key: also not a recipient (was excluded during block).
        let result_new =
            unwrap_content(wrapped, DAVE, &dave_key_restored, context_id, ALICE, 1, seq);
        assert!(
            result_new.is_err(),
            "Message {seq} from block period should NOT be decryptable with new key either"
        );
    }

    // --- Post-unblock: Message 4 IS decryptable ---

    let msg4 = b"Post-unblock message 4";
    let wrapped4 = wrap_content(
        msg4,
        &[
            Recipient {
                did: ALICE,
                access_key: &alice_key,
            },
            Recipient {
                did: DAVE,
                access_key: &dave_key_restored,
            },
        ],
        context_id,
        ALICE,
        2, // new epoch after unblock
        4,
    )
    .unwrap();

    let dave_msg4 =
        unwrap_content(&wrapped4, DAVE, &dave_key_restored, context_id, ALICE, 2, 4).unwrap();
    assert_eq!(
        dave_msg4, msg4,
        "Message 4 (post-unblock) should be decryptable"
    );
}

// =========================================================================
// Test 7: Invalid block notification discarded (Layer 2 defense)
// =========================================================================

/// Verifies that an invalid block notification (wrong key, wrong context)
/// is discarded without triggering state destruction.
#[tokio::test]
async fn invalid_block_notification_no_destruction() {
    let context_id = "ctx-invalid-notification";
    let (custody, signing_key) = make_custody_and_key().await;

    // Create a valid notification.
    let clock = scp_clock::SystemClock;
    let notification_bytes = send_block_notification(
        &custody,
        &signing_key,
        context_id,
        ALICE,
        DAVE,
        SigningKeyId::Active,
        &clock,
    )
    .await
    .unwrap();

    let notification: BlockNotification =
        rmp_serde::from_slice(&notification_bytes).expect("deserialize notification");

    // Dave's stores with Alice's cached material.
    let mut sender_store = SenderKeyStore::new();
    sender_store.set_unchecked(context_id, ALICE, generate_sender_key());
    let mut access_store = AccessKeyStore::new();
    access_store.set(context_id, ALICE, generate_access_key(context_id, ALICE));

    // Use WRONG public key -> signature verification fails.
    let wrong_pubkey = [0u8; 32];
    let result = handle_block_as_blocked_party(
        &notification,
        context_id,
        &wrong_pubkey,
        &mut sender_store,
        &mut access_store,
    );

    // Should return None (discard).
    assert!(result.is_none(), "invalid signature should cause discard");

    // State should NOT be destroyed.
    assert!(
        sender_store.get(context_id, ALICE).is_some(),
        "sender keys should NOT be deleted on invalid notification"
    );
    assert!(
        access_store.get(context_id, ALICE).is_some(),
        "access keys should NOT be deleted on invalid notification"
    );

    // Also test with wrong context_id.
    let result_wrong_ctx = handle_block_as_blocked_party(
        &notification,
        "ctx-WRONG",
        &custody.public_key(&signing_key).await.unwrap().into_bytes(),
        &mut sender_store,
        &mut access_store,
    );
    assert!(
        result_wrong_ctx.is_none(),
        "wrong context should cause discard"
    );
    assert!(
        sender_store.get(context_id, ALICE).is_some(),
        "sender keys should be intact after wrong-context discard"
    );
}

// =========================================================================
// Test 8: ContentAccessState transitions are one-way
// =========================================================================

/// Verifies that `ContentAccessState` transitions are one-way
/// (decreasing access only) unless `restore_to` is used.
#[test]
fn content_access_state_one_way_transitions() {
    // Full -> ReadOnly (valid).
    assert_eq!(
        ContentAccessState::Full.transition_to(ContentAccessState::ReadOnly),
        Ok(ContentAccessState::ReadOnly)
    );

    // Full -> PresenceOnly (valid).
    assert_eq!(
        ContentAccessState::Full.transition_to(ContentAccessState::PresenceOnly),
        Ok(ContentAccessState::PresenceOnly)
    );

    // ReadOnly -> PresenceOnly (valid).
    assert_eq!(
        ContentAccessState::ReadOnly.transition_to(ContentAccessState::PresenceOnly),
        Ok(ContentAccessState::PresenceOnly)
    );

    // ReadOnly -> Full (INVALID — would increase access).
    assert_eq!(
        ContentAccessState::ReadOnly.transition_to(ContentAccessState::Full),
        Err(ContentAccessState::ReadOnly)
    );

    // PresenceOnly -> ReadOnly (INVALID — would increase access).
    assert_eq!(
        ContentAccessState::PresenceOnly.transition_to(ContentAccessState::ReadOnly),
        Err(ContentAccessState::PresenceOnly)
    );

    // NonMember -> Full (INVALID).
    assert_eq!(
        ContentAccessState::NonMember.transition_to(ContentAccessState::Full),
        Err(ContentAccessState::NonMember)
    );

    // restore_to bypasses the one-way constraint.
    assert_eq!(
        ContentAccessState::NonMember.restore_to(ContentAccessState::Full),
        ContentAccessState::Full
    );
    assert_eq!(
        ContentAccessState::PresenceOnly.restore_to(ContentAccessState::ReadOnly),
        ContentAccessState::ReadOnly
    );
}

// =========================================================================
// Test 9: CEK wrapping excludes blocked members
// =========================================================================

/// Verifies that after blocking, the wrapping pipeline correctly excludes
/// the blocked member from CEK recipients, and that an attacker who still
/// has a cached (old) access key cannot decrypt new messages.
#[test]
fn wrapping_excludes_blocked_member_even_with_cached_key() {
    let context_id = "ctx-wrapping-exclude";

    let alice_key = generate_access_key(context_id, ALICE);
    let bob_key = generate_access_key(context_id, BOB);
    let dave_key_old = generate_access_key(context_id, DAVE);

    // Pre-block: Dave is a recipient and can decrypt.
    let msg_pre = b"Before block";
    let wrapped_pre = wrap_content(
        msg_pre,
        &[
            Recipient {
                did: ALICE,
                access_key: &alice_key,
            },
            Recipient {
                did: BOB,
                access_key: &bob_key,
            },
            Recipient {
                did: DAVE,
                access_key: &dave_key_old,
            },
        ],
        context_id,
        ALICE,
        0,
        1,
    )
    .unwrap();

    let dec = unwrap_content(&wrapped_pre, DAVE, &dave_key_old, context_id, ALICE, 0, 1).unwrap();
    assert_eq!(dec, msg_pre);

    // Post-block: Dave excluded from recipients.
    let msg_post = b"After block";
    let wrapped_post = wrap_content(
        msg_post,
        &[
            Recipient {
                did: ALICE,
                access_key: &alice_key,
            },
            Recipient {
                did: BOB,
                access_key: &bob_key,
            },
            // Dave intentionally excluded.
        ],
        context_id,
        ALICE,
        1,
        2,
    )
    .unwrap();

    // Dave tries with cached old key -> NotRecipient.
    let dave_attempt = unwrap_content(&wrapped_post, DAVE, &dave_key_old, context_id, ALICE, 1, 2);
    assert!(
        matches!(
            dave_attempt,
            Err(scp_protocol::crypto::access_keys::AccessKeyError::NotRecipient)
        ),
        "Dave should get NotRecipient even with cached key: {dave_attempt:?}"
    );
}

// =========================================================================
// Test 10: Governance tier stacking with ContextManager
// =========================================================================

/// End-to-end tier stacking test through the `ContextManager` governance path.
///
/// Alice (Tier 1, via block list) AND governance (Tier 3, via
/// write revocation) both revoke Dave.
/// - Reverse only Alice's block -> Dave still revoked (governance block active).
/// - Reverse governance block too -> Dave restored.
#[tokio::test]
async fn governance_tier_stacking_via_context_manager() {
    let manager = new_manager();
    let ctx_id = "ctx-gov-tier-stack";

    let params = ContextParams {
        ceiling: governance_ceiling(),
        governance: GovernanceModel::Threshold {
            threshold: 2,
            signers: vec![alice(), bob()],
        },
        ..ContextParams::default()
    };
    let _handle = manager
        .create_context(ctx_id.into(), params.clone(), alice(), None)
        .await
        .unwrap();

    // Add Dave.
    let sk_alice = signing_key_for_did(&alice());
    let sk_bob = signing_key_for_did(&bob());

    let (add_dave, _, _) = manager
        .propose_governance_action(
            ctx_id,
            &alice(),
            GovernanceAction::AddMember {
                did: dave(),
                role: "member".into(),
            },
            &sk_alice,
        )
        .await
        .unwrap();
    let (status, _) = manager
        .vote_on_proposal(ctx_id, &add_dave.proposal_id, &bob(), true, &sk_bob)
        .await
        .unwrap();
    assert_eq!(status, ProposalStatus::Approved);
    assert!(manager.is_member(ctx_id, DAVE).await);

    // §9.10.4: seed peer pseudonyms so multi-member encrypted sends have a
    // non-empty routing registry. In production each peer announces its
    // routing ID via a `PseudonymAnnouncement`; this single-node test hosts
    // only one member's view, so the registry is seeded directly (the same
    // mutation a delivered announcement performs).
    for (member, tag) in [(bob(), 2u8), (dave(), 3u8)] {
        manager
            .seed_peer_pseudonym(ctx_id, member, [tag; 32])
            .await
            .expect("seed peer pseudonym");
    }

    // --- Governance (Tier 3): write revocation on Dave ---

    let revoke = GovernanceAction::RevokeAccess {
        did: dave(),
        access: AccessScope::Both,
    };
    let outcome = propose_and_approve_threshold(&manager, ctx_id, revoke).await;
    assert_eq!(outcome.status, ProposalStatus::Approved);

    // Dave cannot write.
    let handle = ContextHandle::new(ctx_id.to_owned(), params.clone());
    let send = manager
        .send_message(
            &handle,
            &dave(),
            b"should fail",
            MessageSigner::Active(&signing_key_for_did(&dave())),
            None,
            None,
        )
        .await;
    assert!(send.is_err(), "Dave should not be able to write (Tier 3)");

    // --- Identity block (Tier 1): block list ---

    let mut block_list_state = BlockListState::new();
    block_list_state.apply(&BlockListEvent::BlockDIDInContext {
        target_did: dave(),
        context_id: ctx_id.to_owned(),
        timestamp: 1000,
    });
    assert!(is_block_effective(&block_list_state, &dave(), ctx_id));

    // --- Reverse Tier 1 only ---

    block_list_state.unblock_did_in_context(dave(), ctx_id.to_owned(), 2000);
    assert!(!block_list_state.is_blocked_in_context(&dave(), ctx_id));

    // Dave STILL cannot write (governance Tier 3 still active).
    let send2 = manager
        .send_message(
            &handle,
            &dave(),
            b"still blocked",
            MessageSigner::Active(&signing_key_for_did(&dave())),
            None,
            None,
        )
        .await;
    assert!(
        send2.is_err(),
        "Dave should still not write (governance Tier 3 active)"
    );

    // --- Reverse Tier 3 too: RestoreAccess (write) ---

    let _ = manager.drain_events(ctx_id).await;
    let restore = GovernanceAction::RestoreAccess {
        did: dave(),
        capabilities: vec![Capability::MessagesWrite],
    };
    let outcome = propose_and_approve_threshold(&manager, ctx_id, restore).await;
    assert_eq!(outcome.status, ProposalStatus::Approved);

    // Dave CAN write now (both tiers reversed).
    let send3 = manager
        .send_message(
            &handle,
            &dave(),
            b"success",
            MessageSigner::Active(&signing_key_for_did(&dave())),
            None,
            None,
        )
        .await;
    assert!(
        send3.is_ok(),
        "Dave should be able to write after both tiers reversed: {:?}",
        send3.err()
    );
}
