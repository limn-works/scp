#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    // ADR-049 commit 12c.2: lifecycle hoist inflates some test-path
    // futures past clippy's 16 KB stack budget.
    clippy::large_futures
)]
//! Producer-side integration coverage for the `Supervisor` event channel
//! (ADR-049 §12a, spec §12.10.5).
//!
//! The structural `pipeline_wiring` assertions prove the consumer wire exists,
//! and `scp-node/tests/webhook_event_wiring.rs` proves the node-side consumer
//! delivers a `ContextEvent` fed onto the broadcast channel. This file closes
//! the remaining half: that a **live** `Supervisor` — built with its event
//! channel enabled and driving a real context operation — actually emits a
//! `ContextEvent` onto the channel a `subscribe_events()` receiver observes,
//! and that the emitted event is payload-stripped (no decrypted plaintext, no
//! MLS key material crosses the channel).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use scp_did::DID;
use scp_protocol::context::ContextError;
use scp_protocol::context::builder::ContextCreationError;
use scp_protocol::context::governance::KeyResolver;
use scp_protocol::context::membership::ContextEvent;
use scp_protocol::context::params::{Capability, ContextParams, GovernanceModel};
use scp_runtime::context::ContextHandle;
use scp_runtime::context::builder::{ContextEventLogProvider, ContextTransportProvider};
use scp_runtime::context::supervisor::{MessageSigner, Supervisor};
use scp_runtime::crypto::mls::provider::MlsCryptoProvider;

// ---------------------------------------------------------------------------
// Mock providers (same pattern as content_access_integration.rs)
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
// Key resolver helpers (same as the other runtime integration tests)
// ---------------------------------------------------------------------------

fn did_to_seed(did: &DID) -> [u8; 32] {
    let mut s = [0u8; 32];
    for (i, b) in did.as_ref().as_bytes().iter().enumerate() {
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

fn alice() -> DID {
    DID::from("did:dht:z6MkAlice")
}

fn bob() -> DID {
    DID::from("did:dht:z6MkBob")
}

/// Builds a `Supervisor` with the event broadcast channel **enabled** —
/// `test_supervisor` passes `event_tx = None`, so this test must wire the
/// channel explicitly via `with_providers` to exercise the producer path.
fn supervisor_with_event_channel() -> (
    Arc<Supervisor>,
    tokio::sync::broadcast::Sender<(String, ContextEvent)>,
) {
    let (event_tx, _seed_rx) = tokio::sync::broadcast::channel::<(String, ContextEvent)>(1024);
    let mls_storage: Arc<dyn scp_runtime::crypto::mls::storage_adapter::OpenMlsStorageAdapter> =
        Arc::new(
            scp_runtime::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
                scp_platform::testing::InMemoryStorage::new(),
            )),
        );
    let supervisor = Supervisor::with_providers(
        Arc::new(MlsCryptoProvider::new(
            "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_owned(),
            std::sync::Arc::new(scp_clock::SystemClock),
        )),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog),
        mock_key_resolver(),
        None,
        None,
        Some(event_tx.clone()),
        None,
        mls_storage,
    );
    (supervisor, event_tx)
}

fn messaging_ceiling() -> Vec<Capability> {
    vec![
        Capability::new("messages:read"),
        Capability::new("messages:write"),
        Capability::new("governance:propose"),
        Capability::new("governance:vote"),
        Capability::new("role:assign"),
    ]
}

/// A live `Supervisor` emitting on a real context operation reaches a
/// `subscribe_events()` receiver, and the observed event is payload-stripped.
#[tokio::test]
async fn supervisor_send_emits_stripped_message_sent_to_subscriber() {
    let (supervisor, _event_tx) = supervisor_with_event_channel();

    // `subscribe_events()` must yield a receiver when the channel is enabled.
    let mut rx = supervisor
        .subscribe_events()
        .expect("event channel was enabled via with_providers");

    let ctx_id = "ctx-producer-wire";
    // Threshold governance with Alice + Bob so the context can become
    // multi-member: a lone-member encrypted send fans out to zero recipients
    // and is a no-op (no MessageSent), so the producer wire must be exercised by
    // a send that has a REAL recipient (§9.10.4).
    let params = ContextParams {
        ceiling: messaging_ceiling(),
        governance: GovernanceModel::Threshold {
            threshold: 2,
            signers: vec![alice(), bob()],
        },
        ..ContextParams::default()
    };
    let handle = supervisor
        .create_context(ctx_id.into(), params, alice(), None)
        .await
        .expect("context creation should succeed");
    assert_eq!(handle.context_id(), ctx_id);

    // Add Bob via threshold governance so the encrypted send has a real fan-out
    // target, then seed his pseudonym (production: Bob announces it).
    let sk_alice = signing_key_for_did(&alice());
    let sk_bob = signing_key_for_did(&bob());
    let (prop, _, _) = supervisor
        .propose_governance_action(
            ctx_id,
            &alice(),
            scp_protocol::context::governance::GovernanceAction::AddMember {
                did: bob(),
                role: "member".into(),
            },
            &sk_alice,
        )
        .await
        .expect("proposing AddMember should succeed");
    supervisor
        .vote_on_proposal(ctx_id, &prop.proposal_id, &bob(), true, &sk_bob)
        .await
        .expect("Bob voting to approve his own add should succeed");
    supervisor
        .seed_peer_pseudonym(ctx_id, bob(), [0x42u8; 32])
        .await
        .expect("seeding Bob's pseudonym should succeed");

    // Drive a real send. This is the producer: the actor emits a MessageSent
    // ContextEvent (payload stripped) onto the broadcast channel.
    let plaintext = b"super secret plaintext that must never cross the channel";
    let send_handle = ContextHandle::new(ctx_id.to_owned(), handle.params().clone());
    supervisor
        .send_message(
            &send_handle,
            &alice(),
            plaintext,
            MessageSigner::Active(&signing_key_for_did(&alice())),
            None,
            None,
        )
        .await
        .expect("alice (creator) can send in her own context");

    // Drain the channel until the MessageSent event arrives (bounded — fail
    // fast if the producer wire is broken). Other variants (e.g. MemberJoined
    // emitted on create) may precede it.
    let observed = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match rx.recv().await {
                Ok((cid, event)) => {
                    assert_eq!(cid, ctx_id, "events carry their originating context id");
                    // WelcomeGenerated must NEVER cross the broadcast channel —
                    // it is pushed to the receive buffer only (it carries MLS
                    // key material). Its appearance here is a hard failure.
                    assert!(
                        !matches!(event, ContextEvent::WelcomeGenerated { .. }),
                        "WelcomeGenerated must never reach the broadcast channel"
                    );
                    if let ContextEvent::MessageSent {
                        sender_did,
                        payload,
                        ..
                    } = &event
                    {
                        assert_eq!(sender_did.as_ref(), alice().as_ref());
                        // The payload-stripping invariant: no plaintext crosses
                        // the channel (subscribers see metadata only).
                        assert!(
                            payload.is_empty(),
                            "MessageSent payload must be stripped on the broadcast channel"
                        );
                        break;
                    }
                }
                Err(e) => panic!("channel error before observing MessageSent: {e:?}"),
            }
        }
    })
    .await;

    observed.expect("a MessageSent event must reach the subscriber before timeout");
}

/// A live `Supervisor` emitting a SECURITY/AUDIT event — `MemberLeft`, one of
/// the variants the lag-warning flags as critical (spec §12.10.5) — reaches a
/// `subscribe_events()` subscriber with the correct shape. The `MessageSent`
/// test above proves the channel carries application traffic; this proves an
/// actual audit event reaches the channel, which is the security-relevant
/// guarantee the webhook dispatcher and Merkle event log both depend on.
///
/// Driving a leave is the simplest deterministic audit-event producer: the
/// context creator (alice) leaves her own context, which emits a payload-free
/// `MemberLeft { member_did: alice }` onto the broadcast channel.
#[tokio::test]
async fn supervisor_leave_emits_member_left_audit_event_to_subscriber() {
    let (supervisor, _event_tx) = supervisor_with_event_channel();

    let mut rx = supervisor
        .subscribe_events()
        .expect("event channel was enabled via with_providers");

    let ctx_id = "ctx-audit-wire";
    let params = ContextParams {
        ceiling: messaging_ceiling(),
        governance: GovernanceModel::SingleAdmin,
        ..ContextParams::default()
    };
    let handle = supervisor
        .create_context(ctx_id.into(), params, alice(), None)
        .await
        .expect("context creation should succeed");
    assert_eq!(handle.context_id(), ctx_id);

    // Drive a real leave: alice (the creator, and sole member) leaves her own
    // context. This is the producer — the actor emits a MemberLeft audit event
    // onto the broadcast channel.
    let leave_handle = ContextHandle::new(ctx_id.to_owned(), handle.params().clone());
    supervisor
        .leave_context(&leave_handle, &alice(), &alice())
        .await
        .expect("alice (creator) can leave her own context");

    // Drain the channel until the MemberLeft audit event arrives (bounded — fail
    // fast if the producer wire is broken). Other variants (e.g. MemberJoined
    // emitted on create) may precede it.
    let observed = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match rx.recv().await {
                Ok((cid, event)) => {
                    assert_eq!(cid, ctx_id, "events carry their originating context id");
                    if let ContextEvent::MemberLeft { member_did } = &event {
                        assert_eq!(
                            member_did.as_ref(),
                            alice().as_ref(),
                            "the MemberLeft audit event must name the departing member"
                        );
                        break;
                    }
                }
                Err(e) => panic!("channel error before observing MemberLeft: {e:?}"),
            }
        }
    })
    .await;

    observed.expect("a MemberLeft audit event must reach the subscriber before timeout");
}

/// A `Supervisor` built without the event channel (the `test_supervisor` /
/// `for_query_shim` shape) returns `None` from `subscribe_events()` rather than
/// panicking — the defensive branch the FFI wiring relies on (ADR-049 §12a).
#[tokio::test]
async fn supervisor_without_channel_yields_no_subscriber() {
    let supervisor = scp_runtime::context::test_supervisor(
        Arc::new(MlsCryptoProvider::new(
            "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_owned(),
            std::sync::Arc::new(scp_clock::SystemClock),
        )),
        Box::new(MockTransport::connected()),
        Box::new(MockEventLog),
        mock_key_resolver(),
    );
    assert!(
        supervisor.subscribe_events().is_none(),
        "a supervisor with no event channel must yield None, not panic"
    );
}
