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

use scp_identity::DID;
use scp_protocol::context::ContextError;
use scp_protocol::context::builder::ContextCreationError;
use scp_protocol::context::governance::KeyResolver;
use scp_protocol::context::membership::ContextEvent;
use scp_protocol::context::params::{Capability, ContextParams, GovernanceModel};
use scp_runtime::context::ContextHandle;
use scp_runtime::context::builder::{ContextEventLogProvider, ContextTransportProvider};
use scp_runtime::context::supervisor::Supervisor;
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

impl ContextTransportProvider for MockTransport {
    fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }
    fn publish_context(
        &self,
        _id: &[u8; 32],
        _params: &ContextParams,
    ) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn delete_published(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn send_message(&self, _id: &[u8; 32], _encrypted_payload: &[u8]) -> Result<(), ContextError> {
        Ok(())
    }
}

#[derive(Default)]
struct MockEventLog;

impl ContextEventLogProvider for MockEventLog {
    fn init_event_log(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn append_event(
        &self,
        _id: &[u8; 32],
        _event: &str,
        _actor_did: &str,
        _payload: Option<&serde_json::Value>,
    ) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn destroy_event_log(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
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
    Arc::new(|did| {
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

    // Drive a real send. This is the producer: the actor emits a MessageSent
    // ContextEvent (payload stripped) onto the broadcast channel.
    let plaintext = b"super secret plaintext that must never cross the channel";
    let send_handle = ContextHandle::new(ctx_id.to_owned(), handle.params().clone());
    supervisor
        .send_message(
            &send_handle,
            &alice(),
            plaintext,
            Some(&signing_key_for_did(&alice())),
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

/// A `Supervisor` built without the event channel (the `test_supervisor` /
/// `for_query_shim` shape) returns `None` from `subscribe_events()` rather than
/// panicking — the defensive branch the FFI wiring relies on (ADR-049 §12a).
#[tokio::test]
async fn supervisor_without_channel_yields_no_subscriber() {
    let supervisor = scp_runtime::context::test_supervisor(
        Arc::new(MlsCryptoProvider::new(
            "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_owned(),
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
