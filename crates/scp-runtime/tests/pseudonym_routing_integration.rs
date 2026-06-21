#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::large_futures,
    // Test-only recording transport: `send_message` is a synchronous trait
    // method, so a plain `std::sync::Mutex` (never held across `.await`) is the
    // right tool. The runtime's actor path bans it (ADR-049); test fixtures are
    // explicitly exempt. See crates/scp-runtime/clippy.toml.
    clippy::disallowed_types
)]
//! §9.10.4 pseudonym-routing integration tests.
//!
//! Verifies the privacy-critical routing re-home: encrypted application data
//! fans out to per-member pseudonym routing IDs only — NEVER to the shared,
//! relay-derivable `context_routing_id` (the deleted `shared_rid` fallback).
//!
//! Behaviors covered:
//! - Encrypted app-data send fans out to exactly the peer registry; the shared
//!   `context_routing_id` is never emitted as a fan-out target.
//! - A multi-member encrypted send with an empty registry fails closed with
//!   `PseudonymRegistryEmpty` (not a silent drop), rolling back the sequence
//!   reservation so a later retry is not skipped.
//! - The `local_pseudonym` query returns `NotPseudonymousContext` on a
//!   broadcast context.
//!
//! See spec §9.10.4, §5.14.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use scp_identity::DID;
use scp_protocol::context::ContextError;
use scp_protocol::context::builder::ContextCreationError;
use scp_protocol::context::governance::KeyResolver;
use scp_protocol::context::params::{
    Capability, ContextMode, ContextParams, GovernanceModel, MemoryScope,
};
use scp_runtime::context::ContextHandle;
use scp_runtime::context::builder::{ContextEventLogProvider, ContextTransportProvider};
use scp_runtime::context::supervisor::{MessageSigner, Supervisor};
use scp_runtime::crypto::mls::provider::MlsCryptoProvider;

const ALICE: &str = "did:dht:z6MkAlice";
const BOB: &str = "did:dht:z6MkBob";

fn alice() -> DID {
    DID::from(ALICE)
}
fn bob() -> DID {
    DID::from(BOB)
}

// ---------------------------------------------------------------------------
// Recording transport — captures every routing ID a send fans out to.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct RecordingTransport {
    connected: AtomicBool,
    routing_ids: Mutex<Vec<[u8; 32]>>,
}

impl RecordingTransport {
    const fn connected() -> Self {
        Self {
            connected: AtomicBool::new(true),
            routing_ids: Mutex::new(Vec::new()),
        }
    }
}

impl ContextTransportProvider for RecordingTransport {
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
    fn send_message(&self, id: &[u8; 32], _encrypted_payload: &[u8]) -> Result<(), ContextError> {
        self.routing_ids.lock().expect("lock").push(*id);
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
        _event: scp_event_log::EventType,
        _actor_did: &str,
        _payload: scp_event_log::EventPayload,
        _timestamp_secs: u64,
    ) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn destroy_event_log(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
}

fn did_to_seed(did: &DID) -> [u8; 32] {
    let mut s = [0u8; 32];
    for (i, b) in did.as_ref().as_bytes().iter().enumerate() {
        s[i % 32] ^= *b;
    }
    s
}

fn mock_key_resolver() -> KeyResolver {
    Arc::new(|did, _kid: scp_identity::SigningKeyId| {
        let seed = did_to_seed(did);
        Some(ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key())
    })
}

fn signing_key_for_did(did: &DID) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&did_to_seed(did))
}

fn ceiling() -> Vec<Capability> {
    vec![
        Capability::new("messages:read"),
        Capability::new("messages:write"),
        Capability::new("governance:propose"),
        Capability::new("governance:vote"),
        Capability::new("role:assign"),
    ]
}

fn manager_with_transport(transport: Arc<RecordingTransport>) -> std::sync::Arc<Supervisor> {
    scp_runtime::context::test_supervisor(
        Arc::new(MlsCryptoProvider::new(ALICE.to_owned())),
        Box::new(TransportShim(transport)),
        Box::new(MockEventLog),
        mock_key_resolver(),
    )
}

/// Forwards the trait to the shared `Arc<RecordingTransport>` so the test can
/// inspect captured routing IDs after the supervisor sends.
struct TransportShim(Arc<RecordingTransport>);

impl ContextTransportProvider for TransportShim {
    fn is_connected(&self) -> bool {
        self.0.is_connected()
    }
    fn publish_context(
        &self,
        id: &[u8; 32],
        params: &ContextParams,
    ) -> Result<(), ContextCreationError> {
        self.0.publish_context(id, params)
    }
    fn delete_published(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.0.delete_published(id)
    }
    fn send_message(&self, id: &[u8; 32], payload: &[u8]) -> Result<(), ContextError> {
        self.0.send_message(id, payload)
    }
}

fn encrypted_params() -> ContextParams {
    ContextParams {
        ceiling: ceiling(),
        governance: GovernanceModel::Threshold {
            threshold: 2,
            signers: vec![alice(), bob()],
        },
        ..ContextParams::default()
    }
}

/// §9.10.4 PRIVACY: an encrypted multi-member app-data send fans out to the
/// peer registry ONLY. The shared `context_routing_id` (which a relay can
/// derive from the public context id) must NEVER appear as a fan-out target —
/// this is the deleted `shared_rid` fallback, and its absence is what stops a
/// relay from correlating every sender in the context.
#[tokio::test]
async fn encrypted_send_fans_out_to_peer_registry_not_shared_rid() {
    let transport = Arc::new(RecordingTransport::connected());
    let manager = manager_with_transport(Arc::clone(&transport));
    let ctx_id = "ctx-routing-fanout";

    manager
        .create_context(ctx_id.into(), encrypted_params(), alice(), None)
        .await
        .unwrap();

    // Add Bob via threshold governance so the context is multi-member.
    let sk_alice = signing_key_for_did(&alice());
    let sk_bob = signing_key_for_did(&bob());
    let (prop, _, _) = manager
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
        .unwrap();
    manager
        .vote_on_proposal(ctx_id, &prop.proposal_id, &bob(), true, &sk_bob)
        .await
        .unwrap();

    // Seed Bob's pseudonym (production: Bob announces it). Use a non-reserved
    // routing ID so the send has a real fan-out target.
    let bob_pseudonym = [0x42u8; 32];
    manager
        .seed_peer_pseudonym(ctx_id, bob(), bob_pseudonym)
        .await
        .unwrap();

    // Clear any routing IDs captured during setup (none expected, but be safe).
    transport.routing_ids.lock().unwrap().clear();

    let handle = ContextHandle::new(ctx_id.to_owned(), encrypted_params());
    manager
        .send_message(
            &handle,
            &alice(),
            b"hello",
            MessageSigner::Active(&sk_alice),
            None,
            None,
        )
        .await
        .expect("encrypted send should succeed with a seeded peer pseudonym");

    let captured = transport.routing_ids.lock().unwrap().clone();
    let shared_rid = scp_protocol::context::context_routing_id(ctx_id);

    assert!(
        captured.contains(&bob_pseudonym),
        "app-data must fan out to the peer's pseudonym routing ID"
    );
    assert!(
        !captured.contains(&shared_rid),
        "app-data must NEVER be addressed to the shared context routing id \
         (the deleted shared_rid relay-correlation fallback); captured={captured:?}"
    );
}

/// §9.10.4: a multi-member encrypted send with an EMPTY pseudonym registry
/// fails closed with `PseudonymRegistryEmpty` rather than silently dropping
/// the payload, and rolls back the sequence reservation so a later send (after
/// peers announce) is not skipped.
#[tokio::test]
async fn multi_member_empty_registry_send_errors_and_rolls_back() {
    let transport = Arc::new(RecordingTransport::connected());
    let manager = manager_with_transport(Arc::clone(&transport));
    let ctx_id = "ctx-routing-empty";

    manager
        .create_context(ctx_id.into(), encrypted_params(), alice(), None)
        .await
        .unwrap();

    let sk_alice = signing_key_for_did(&alice());
    let sk_bob = signing_key_for_did(&bob());
    let (prop, _, _) = manager
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
        .unwrap();
    manager
        .vote_on_proposal(ctx_id, &prop.proposal_id, &bob(), true, &sk_bob)
        .await
        .unwrap();

    let handle = ContextHandle::new(ctx_id.to_owned(), encrypted_params());
    // No pseudonyms seeded → the registry is empty.
    let result = manager
        .send_message(
            &handle,
            &alice(),
            b"hello",
            MessageSigner::Active(&sk_alice),
            None,
            None,
        )
        .await;
    assert!(
        matches!(result, Err(ContextError::PseudonymRegistryEmpty { member_count, .. }) if member_count == 2),
        "multi-member send with empty registry must fail closed; got {result:?}"
    );

    // No ciphertext should have hit the wire.
    assert!(
        transport.routing_ids.lock().unwrap().is_empty(),
        "no fan-out should occur when the registry is empty"
    );

    // Sequence reservation was rolled back: seeding a peer and retrying now
    // succeeds (the earlier failure did not burn the slot or wedge the sender).
    manager
        .seed_peer_pseudonym(ctx_id, bob(), [0x55u8; 32])
        .await
        .unwrap();
    manager
        .send_message(
            &handle,
            &alice(),
            b"hello-again",
            MessageSigner::Active(&sk_alice),
            None,
            None,
        )
        .await
        .expect("retry after seeding must succeed");
}

/// §9.10.4: a single-member encrypted context send is a true no-op — it
/// reaches NO recipients (the lone member has no peers to address, so the
/// app-data routing-ID set is empty and the `member_count > 1`
/// `PseudonymRegistryEmpty` guard does NOT fire). With nothing on the wire, the
/// send must NOT charge the economy and must NOT emit a `MessageSent` event:
/// charging for a message delivered to nobody is the bug this guards against.
/// The economy ticket and the sequence reservation are both rolled back, so a
/// later real send (once a peer joins and announces) is not skipped.
#[tokio::test]
async fn lone_member_encrypted_send_is_noop_no_charge_no_event() {
    let transport = Arc::new(RecordingTransport::connected());
    let manager = manager_with_transport(Arc::clone(&transport));
    let ctx_id = "ctx-routing-lone";

    // Single-member encrypted context: Alice creates it and never adds Bob, so
    // `member_count == 1` and the peer registry is empty.
    manager
        .create_context(ctx_id.into(), encrypted_params(), alice(), None)
        .await
        .unwrap();

    let sk_alice = signing_key_for_did(&alice());
    let handle = ContextHandle::new(ctx_id.to_owned(), encrypted_params());

    // Drain any setup events (e.g. context creation) so the post-send drain
    // observes ONLY what this send did — which must be nothing.
    let _setup = manager.drain_events(ctx_id).await;
    transport.routing_ids.lock().unwrap().clear();

    // The lone-member send is a no-op: it returns Ok with nothing on the wire.
    manager
        .send_message(
            &handle,
            &alice(),
            b"hello-nobody",
            MessageSigner::Active(&sk_alice),
            None,
            None,
        )
        .await
        .expect("lone-member encrypted send must be a silent no-op, not an error");

    // No ciphertext hit the transport.
    assert!(
        transport.routing_ids.lock().unwrap().is_empty(),
        "a 0-recipient lone-member send must make no transport call"
    );

    // No MessageSent event was emitted (the sender was not charged for a
    // delivered message because nothing was delivered).
    let events = manager.drain_events(ctx_id).await;
    assert!(
        !events.iter().any(|e| matches!(
            e,
            scp_protocol::context::membership::ContextEvent::MessageSent { .. }
        )),
        "a 0-recipient no-op send must NOT emit MessageSent; got {events:?}"
    );

    // The sequence reservation was rolled back: after Bob joins and announces a
    // pseudonym, the next send succeeds and DOES fan out + emit MessageSent —
    // proving the earlier no-op neither burned the sequence slot nor wedged the
    // sender.
    let sk_bob = signing_key_for_did(&bob());
    let (prop, _, _) = manager
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
        .unwrap();
    manager
        .vote_on_proposal(ctx_id, &prop.proposal_id, &bob(), true, &sk_bob)
        .await
        .unwrap();
    manager
        .seed_peer_pseudonym(ctx_id, bob(), [0x66u8; 32])
        .await
        .unwrap();

    let _ = manager.drain_events(ctx_id).await;
    transport.routing_ids.lock().unwrap().clear();

    manager
        .send_message(
            &handle,
            &alice(),
            b"hello-bob",
            MessageSigner::Active(&sk_alice),
            None,
            None,
        )
        .await
        .expect("send after a peer joins + announces must succeed");
    assert!(
        transport
            .routing_ids
            .lock()
            .unwrap()
            .contains(&[0x66u8; 32]),
        "the real multi-member send must fan out to the seeded peer pseudonym"
    );
    let events = manager.drain_events(ctx_id).await;
    assert!(
        events.iter().any(|e| matches!(
            e,
            scp_protocol::context::membership::ContextEvent::MessageSent { .. }
        )),
        "the real send (1 recipient) MUST emit MessageSent; got {events:?}"
    );
}

/// §9.10.4 / §5.14: the `local_pseudonym` query is typed — a broadcast context
/// carries no per-member pseudonym and returns `NotPseudonymousContext`, not a
/// silent `None`.
#[tokio::test]
async fn local_pseudonym_query_on_broadcast_is_not_pseudonymous() {
    let transport = Arc::new(RecordingTransport::connected());
    let manager = manager_with_transport(Arc::clone(&transport));
    let ctx_id = "ctx-routing-broadcast";

    let params = ContextParams {
        ceiling: ceiling(),
        mode: ContextMode::Broadcast,
        // Broadcast contexts only support full memory scope (no MLS group to
        // deliver key-destruction semantics for ephemeral/summary).
        memory_scope: MemoryScope::Full,
        ..ContextParams::default()
    };
    manager
        .create_context(ctx_id.into(), params, alice(), None)
        .await
        .unwrap();

    let result = manager.local_pseudonym(ctx_id).await;
    assert!(
        matches!(result, Err(ContextError::NotPseudonymousContext { .. })),
        "broadcast contexts have no per-member pseudonym; got {result:?}"
    );
}

// §9.10.4 (FIX 1 runtime defense): the broadcast-import-rejection test moved
// in-crate to `supervisor::tests::import_rejects_broadcast_export`, because the
// signed export/import flow signs at the FFI boundary — building a
// validation-passing signed `ContextExport` requires the crate-private
// `export_import::create_export`, which is not reachable from this external
// integration crate.
