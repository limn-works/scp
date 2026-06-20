//! Live-pipeline agent-binding tests (ADR-039, SCP-AB-021).
//!
//! These tests prove that the shared-DID `#agent` persona is wired through the
//! *live* scp-runtime message pipeline end to end — both halves of the wiring
//! this story makes real:
//!
//! - **Send side (Part 2).** [`messaging_helpers::build_encrypted_envelope`] —
//!   the exact function the live `Supervisor::send_message` →
//!   `messaging_helpers::send_message` → `encrypt_and_send` chain bottoms out in
//!   — now stamps the caller's chosen [`SigningKeyId`] into
//!   `InnerEnvelope.signing_key_id` instead of hardcoding `#active`. The send
//!   half here drives that helper directly with `SigningKeyId::Agent` /
//!   `SigningKeyId::Active`.
//! - **Receive side (Part 1).** [`messaging_helpers::verify_and_unwrap`] reads
//!   `inner.signing_key_id` and resolves the matching verification method
//!   (`#active` vs `#agent`) from the sender's DID document via the VM-aware
//!   [`KeyResolver`]. The receive half is exercised by MLS-opening the produced
//!   blob on the recipient's crypto provider and driving the *live*
//!   [`messaging_helpers::verify_and_unwrap`] receive helper — the exact code
//!   path the actor's `deliver_incoming` invokes.
//!
//! # Why this is a true pipeline test (and not a component test)
//!
//! [`crate::crypto::agent_binding_tests`] is a *component-level* test: it
//! hand-calls `create_inner_envelope` / `verify_inner_signature` /
//! governance-engine internals in isolation. This module instead drives the two
//! live messaging helpers this story wires (`build_encrypted_envelope` and
//! `verify_and_unwrap`) over a real two-party MLS group, with a
//! **document-derived** resolver built from a real
//! [`DidDocument::new_with_agent_key`] — so an `#agent`-signed message is
//! produced through the real seal path AND verified through the real receive
//! helper, and a resolver that returns the wrong key for `#agent` makes
//! verification fail. It never hand-calls `create_inner_envelope` /
//! `verify_inner_signature`.
//!
//! # Harness notes (forced deviations from the literal plan)
//!
//! The plan's first-choice seams — `Supervisor::send_message` for send and
//! `Supervisor::deliver_commit_blob` for receive — are not jointly reachable
//! today, for two independent code-level reasons:
//!
//! 1. **Receive: no joiner actor.** A Welcome-joined node has no per-context
//!    actor on its own `Supervisor` (the spawn-from-Welcome follow-up is
//!    explicitly unfinished; see the note in
//!    `crates/scp-testing/tests/integration/reconnect_sync.rs`). The actor's
//!    `deliver_incoming` therefore cannot run on the joiner side, so
//!    `deliver_commit_blob` cannot decrypt a peer's application blob. This
//!    module drives the very same receive helper (`verify_and_unwrap`) the
//!    actor's `deliver_incoming` calls, after a real MLS `open()` on the
//!    recipient provider — exercising the identical VM-aware resolution logic.
//! 2. **Send: peer fan-out needs the full add-member flow.**
//!    `Supervisor::send_message` only fans out to members the actor added (and
//!    whose access keys it distributed) through the governance add-member path;
//!    there is no public `Supervisor` API to seed a peer's membership + access
//!    key. That bootstrap exists only in the `scp-testing` `FullStackNode`
//!    harness, which cannot reach the `pub(crate)` `verify_and_unwrap`. This
//!    module therefore drives `build_encrypted_envelope` directly — the exact
//!    function the Supervisor send path delegates the `signing_key_id` stamp to
//!    (verified by reading the `send_message → encrypt_and_send →
//!    build_encrypted_envelope` chain).
//!
//! Both helpers are `pub(crate)`, so this test must live in-crate rather than in
//! `crates/scp-runtime/tests/`.

#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use std::sync::Arc;

use ed25519_dalek::{SigningKey, VerifyingKey};
use scp_identity::{DID, DidDocument, SigningKeyId};
use scp_primitives::{Clock, SystemClock};
use scp_protocol::context::ContextError;
use scp_protocol::context::governance::KeyResolver;
use scp_protocol::crypto::access_keys::{AccessKey, generate_access_key};
use scp_protocol::envelope::inner::{InnerEnvelope, MessageType};

use crate::context::messaging_helpers::{build_encrypted_envelope, verify_and_unwrap};
use crate::context::supervisor::MessageSigner;
use crate::crypto::mls::provider::MlsCryptoProvider;

const ALICE_DID: &str = "did:dht:z6MkAgentBindingPipelineAliceAliceAliceA";
const BOB_DID: &str = "did:dht:z6MkAgentBindingPipelineBobBobBobBobBobBo";

// ---------------------------------------------------------------------------
// Document-derived VM-aware resolver.
// ---------------------------------------------------------------------------

/// Decodes a `z`-prefixed base58btc multibase public key (as stored in a
/// [`DidDocument`] verification method) into an Ed25519 [`VerifyingKey`], using
/// the canonical `scp_identity::decode_multibase_key` decoder (which performs
/// the same curve-point validation production DID resolution does).
fn verifying_key_from_vm_multibase(multibase: &str) -> VerifyingKey {
    let bytes = scp_identity::decode_multibase_key(multibase)
        .expect("verification-method multibase must decode to a valid Ed25519 key");
    VerifyingKey::from_bytes(&bytes).expect("decoded bytes must be a valid Ed25519 key")
}

/// Builds a VM-aware [`KeyResolver`] backed by a real [`DidDocument`].
///
/// The returned resolver answers `(did, signing_key_id)` lookups by reading the
/// matching verification method (`#active` / `#agent`) off `alice_doc` — so the
/// verifying key is genuinely document-derived (ADR-039), not handed in raw.
/// `agent_override` lets a test substitute a *wrong* key for the `#agent`
/// verification method to drive the negative case.
fn document_backed_resolver(
    alice_doc: &DidDocument,
    agent_override: Option<VerifyingKey>,
) -> KeyResolver {
    let mut map: HashMap<(String, SigningKeyId), VerifyingKey> = HashMap::new();

    let active_vm = alice_doc
        .verification_method_by_fragment("active")
        .expect("alice doc must carry an #active verification method");
    map.insert(
        (ALICE_DID.to_owned(), SigningKeyId::Active),
        verifying_key_from_vm_multibase(&active_vm.public_key_multibase),
    );

    let agent_key = agent_override.unwrap_or_else(|| {
        let agent_vm = alice_doc
            .verification_method_by_fragment("agent")
            .expect("alice doc must carry an #agent verification method");
        verifying_key_from_vm_multibase(&agent_vm.public_key_multibase)
    });
    map.insert((ALICE_DID.to_owned(), SigningKeyId::Agent), agent_key);

    Arc::new(move |did: &DID, kid: SigningKeyId| map.get(&(did.as_ref().to_owned(), kid)).copied())
}

// ---------------------------------------------------------------------------
// Two-party MLS bootstrap (Alice creator provider + Bob joiner provider).
// ---------------------------------------------------------------------------

/// Sets up a real two-party MLS group keyed by `context_id_bytes(ctx_str)` —
/// the same key `build_encrypted_envelope` derives from the context-id string —
/// returning Alice's provider (the sender) and Bob's provider (used to MLS-open
/// the produced blob on the receive side).
fn setup_two_party(ctx_str: &str) -> (Arc<MlsCryptoProvider>, Arc<MlsCryptoProvider>, [u8; 32]) {
    let context_id = scp_protocol::context::context_id_bytes(ctx_str);

    let alice = MlsCryptoProvider::new(ALICE_DID.to_owned());
    alice.create_mls_group(&context_id).unwrap();
    alice.generate_sender_key(&context_id).unwrap();

    let bob = MlsCryptoProvider::new(BOB_DID.to_owned());
    let bob_kp_bytes = bob.prepare_key_package_for_join().unwrap();
    let add_output = alice
        .add_member(&context_id, BOB_DID, Some(&bob_kp_bytes))
        .unwrap();
    bob.join_from_welcome(&context_id, &add_output.welcome_bytes)
        .unwrap();
    bob.generate_sender_key(&context_id).unwrap();

    // Distribute Alice's sender key to Bob so Bob can sender-key-decrypt
    // Alice's application sends.
    alice.distribute_sender_key(&context_id, BOB_DID).unwrap();
    for (_target, msg) in alice
        .drain_pending_sender_key_messages(&context_id)
        .unwrap()
    {
        bob.process_incoming_sender_key(&context_id, ALICE_DID, &msg)
            .unwrap();
    }

    (Arc::new(alice), Arc::new(bob), context_id)
}

/// Generates Alice's identity-key, active-key, and agent-key keypairs and the
/// matching `DidDocument` (so the resolver is document-derived). Returns the
/// agent signing key (used to sign sends) and the document.
fn alice_identity() -> (SigningKey, SigningKey, DidDocument) {
    let identity_sk = SigningKey::from_bytes(&[0x11; 32]);
    let active_sk = SigningKey::from_bytes(&[0x22; 32]);
    let agent_sk = SigningKey::from_bytes(&[0x33; 32]);
    let pre_rotation_commitment = [0x44; 32];

    let doc = DidDocument::new_with_agent_key(
        ALICE_DID,
        identity_sk.verifying_key().as_bytes(),
        active_sk.verifying_key().as_bytes(),
        &pre_rotation_commitment,
        Some(agent_sk.verifying_key().as_bytes()),
    );

    (active_sk, agent_sk, doc)
}

// ---------------------------------------------------------------------------
// Send half: drive the live `build_encrypted_envelope` helper under a chosen
// SigningKeyId (the exact function the Supervisor send path delegates to).
// ---------------------------------------------------------------------------

/// Seals `payload` over Alice's MLS group via the live
/// [`build_encrypted_envelope`] helper, signed by `signing_key` and stamped
/// with `signing_key_id`. The recipient wrap addresses both Alice and Bob (so
/// Bob can unwrap with `bob_access_key`). Returns the sealed wire blob.
fn build_send_blob(
    alice_provider: &Arc<MlsCryptoProvider>,
    ctx_str: &str,
    signing_key: &SigningKey,
    signing_key_id: SigningKeyId,
    bob_access_key: &AccessKey,
    payload: &[u8],
) -> Vec<u8> {
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let sender = DID::from(ALICE_DID);

    let mut recipients: HashMap<String, AccessKey> = HashMap::new();
    recipients.insert(
        ALICE_DID.to_owned(),
        generate_access_key(ctx_str, ALICE_DID),
    );
    recipients.insert(BOB_DID.to_owned(), bob_access_key.clone());

    // Pair the chosen persona with the signing key so the stamped
    // `signing_key_id` and the key that signs come from one source — this is
    // exactly the invariant the #agent-persona slice asserts.
    let signer = match signing_key_id {
        SigningKeyId::Active => MessageSigner::Active(signing_key),
        SigningKeyId::Agent => MessageSigner::Agent(signing_key),
    };

    build_encrypted_envelope(
        &clock,
        alice_provider,
        ctx_str,
        &sender,
        payload,
        signer,
        &recipients,
        0,
        None,
        MessageType::Content,
    )
    .expect("build_encrypted_envelope")
}

/// Receive half: MLS-open the captured blob on Bob's provider, then drive the
/// *live* `verify_and_unwrap` receive helper with `resolver`.
fn receive_via_verify_and_unwrap(
    bob_provider: &MlsCryptoProvider,
    ctx_str: &str,
    ctx_bytes: &[u8; 32],
    blob: &[u8],
    resolver: &KeyResolver,
    bob_access_key: &AccessKey,
) -> Result<Vec<u8>, ContextError> {
    let opened = match bob_provider.open(ctx_bytes, blob)? {
        scp_protocol::context::builder::OpenResult::Application(env) => *env,
        other => {
            return Err(ContextError::CryptoFailed(format!(
                "expected an Application open result, got {other:?}"
            )));
        }
    };
    let inner: InnerEnvelope = opened.inner;
    verify_and_unwrap(
        resolver,
        &inner,
        &opened.sender_did,
        ctx_str,
        BOB_DID,
        bob_access_key,
        false,
    )
}

// ---------------------------------------------------------------------------
// (a) Happy path: Alice sends signed by #agent; Bob verifies through the live
//     pipeline against the document-derived agent key.
// ---------------------------------------------------------------------------

#[test]
fn agent_signed_message_verifies_through_live_pipeline() {
    let ctx_str = "ctx-agent-binding-pipeline-agent";
    let (alice_provider, bob_provider, ctx_bytes) = setup_two_party(ctx_str);
    let (_active_sk, agent_sk, alice_doc) = alice_identity();
    let bob_access_key = generate_access_key(ctx_str, BOB_DID);

    let resolver = document_backed_resolver(&alice_doc, None);
    let blob = build_send_blob(
        &alice_provider,
        ctx_str,
        &agent_sk,
        SigningKeyId::Agent,
        &bob_access_key,
        b"hello from the agent persona",
    );

    let plaintext = receive_via_verify_and_unwrap(
        &bob_provider,
        ctx_str,
        &ctx_bytes,
        &blob,
        &resolver,
        &bob_access_key,
    )
    .expect("agent-signed message must verify through the live pipeline");

    assert_eq!(
        plaintext.as_slice(),
        b"hello from the agent persona",
        "decrypted plaintext must match what Alice's #agent persona sent"
    );
}

// ---------------------------------------------------------------------------
// (b) Negative: resolver returns the WRONG key for #agent ⇒ verification fails.
// ---------------------------------------------------------------------------

#[test]
fn agent_signed_message_rejected_when_resolver_returns_wrong_agent_key() {
    let ctx_str = "ctx-agent-binding-pipeline-wrongkey";
    let (alice_provider, bob_provider, ctx_bytes) = setup_two_party(ctx_str);
    let (_active_sk, agent_sk, alice_doc) = alice_identity();
    let bob_access_key = generate_access_key(ctx_str, BOB_DID);

    // Alice signs with the real agent key. The RECEIVE-side resolver returns a
    // WRONG key for #agent, so the live `verify_and_unwrap` signature check must
    // fail.
    let blob = build_send_blob(
        &alice_provider,
        ctx_str,
        &agent_sk,
        SigningKeyId::Agent,
        &bob_access_key,
        b"agent message that must be rejected",
    );

    let wrong_agent_key = SigningKey::from_bytes(&[0x99; 32]).verifying_key();
    let bad_resolver = document_backed_resolver(&alice_doc, Some(wrong_agent_key));

    let result = receive_via_verify_and_unwrap(
        &bob_provider,
        ctx_str,
        &ctx_bytes,
        &blob,
        &bad_resolver,
        &bob_access_key,
    );
    // The happy-path test uses the IDENTICAL setup with the correct #agent key
    // and succeeds (MLS open + access-key unwrap all work), so the only changed
    // variable here is the resolved #agent key — the failure must be the inner
    // Ed25519 signature check inside `verify_and_unwrap`.
    assert!(
        matches!(&result, Err(ContextError::CryptoFailed(msg)) if msg.contains("signature")),
        "a wrong #agent key must make live verification fail with the inner-signature \
         check, got {result:?}"
    );
}

// ---------------------------------------------------------------------------
// (c) Regression: Alice sends signed by #active ⇒ still verifies (the wiring
//     did not break the human-key default path).
// ---------------------------------------------------------------------------

#[test]
fn active_signed_message_still_verifies_through_live_pipeline() {
    let ctx_str = "ctx-agent-binding-pipeline-active";
    let (alice_provider, bob_provider, ctx_bytes) = setup_two_party(ctx_str);
    let (active_sk, _agent_sk, alice_doc) = alice_identity();
    let bob_access_key = generate_access_key(ctx_str, BOB_DID);

    let resolver = document_backed_resolver(&alice_doc, None);
    let blob = build_send_blob(
        &alice_provider,
        ctx_str,
        &active_sk,
        SigningKeyId::Active,
        &bob_access_key,
        b"hello from the human persona",
    );

    let plaintext = receive_via_verify_and_unwrap(
        &bob_provider,
        ctx_str,
        &ctx_bytes,
        &blob,
        &resolver,
        &bob_access_key,
    )
    .expect("active-signed message must still verify through the live pipeline");

    assert_eq!(
        plaintext.as_slice(),
        b"hello from the human persona",
        "decrypted plaintext must match what Alice's #active persona sent"
    );
}

// ===========================================================================
// (d) PUBLIC SEND API: drive the real `Supervisor::send_message` end to end.
//
// Tests (a)-(c) above drive `build_encrypted_envelope` directly — the helper
// the Supervisor send path bottoms out in. They prove the *helper* stamps the
// caller's `SigningKeyId`, but they do NOT exercise the parameter threading
// through the public seam:
//
//     Supervisor::send_message(signing_key_id)
//       → SendMessagePayload.signing_key_id
//       → MessagingCommand::SendMessage
//       → handle_send_message
//       → messaging_helpers::send_message
//       → encrypt_and_send
//       → build_encrypted_envelope (the stamp)
//
// That threading was previously verified only by compilation — the exact
// "bypass the Supervisor" gap that let the agent-persona wiring be falsely
// marked complete once before. This module closes it for the SEND side (the
// side the sender's own context actor genuinely owns): it constructs a real
// `Supervisor`, creates an encrypted context, runs the real governance
// add-member path so Bob is a true MLS member with an access key, seeds Bob's
// per-context pseudonym (§9.10.4) so the encrypted send fans out, then calls
// the *public* `Supervisor::send_message` with the chosen persona. The
// outgoing wire blob is captured off a recording transport, MLS-opened on
// Bob's provider, and its recovered inner-envelope `signing_key_id` is
// asserted — proving the persona threaded from the public API all the way to
// the wire.
//
// The RECEIVE side cannot likewise go through a second `Supervisor` (a
// Welcome-joined node spawns no per-context actor — see the Harness notes at
// the top of this file), so this module asserts the receive contract by
// MLS-opening the captured blob directly on Bob's provider, exactly as
// tests (a)-(c) do.
//
// Gated behind `feature = "testing"` because the per-context pseudonym seed
// (`Supervisor::seed_peer_pseudonym`) — the §9.10.4 stand-in for a delivered
// `PseudonymAnnouncement` — is only compiled under that feature.
// ===========================================================================

#[cfg(feature = "testing")]
mod live_supervisor_send {
    // Test-only recording transport: the `Mutex<Vec<...>>` capture buffer is
    // written/read exclusively from the synchronous `ContextTransportProvider`
    // trait methods (and the test body), never held across an `.await`, so a
    // plain `std::sync::Mutex` is the correct tool. The runtime's actor path
    // bans it (ADR-049); test fixtures are explicitly exempt — same exemption
    // the `CapturingPersistence` fixture takes. See crates/scp-runtime/clippy.toml.
    #![allow(clippy::disallowed_types)]

    use std::sync::{Arc, Mutex};

    use ed25519_dalek::SigningKey;
    use scp_identity::{DID, SigningKeyId};
    use scp_protocol::context::builder::{ContextCreationError, OpenResult};
    use scp_protocol::context::membership::{ContextEvent, KeyPackage};
    use scp_protocol::context::params::{ContextMode, ContextParams};
    use scp_protocol::context::roles::Capability;
    use scp_protocol::context::{ContextError, context_id_bytes};

    use super::{ALICE_DID, BOB_DID, alice_identity, document_backed_resolver};
    use crate::context::ContextHandle;
    use crate::context::builder::ContextTransportProvider;
    use crate::context::supervisor::{MessageSigner, Supervisor};
    use crate::crypto::mls::provider::MlsCryptoProvider;

    /// Shared buffer of `(routing_id, payload)` pairs the recording transport
    /// captures. Mirrors the `scp-testing` `CapturingTransport` (which lives in
    /// a different crate and cannot be reached from this in-crate module).
    type SentBuffer = Arc<Mutex<Vec<([u8; 32], Vec<u8>)>>>;

    /// Minimal `ContextTransportProvider` that records every outgoing
    /// `(routing_id, payload)` instead of putting it on a wire — so the test can
    /// recover the exact bytes the Supervisor's send path produced and open them
    /// on Bob's provider.
    #[derive(Clone)]
    struct CapturingTransport {
        sent: SentBuffer,
    }

    impl CapturingTransport {
        const fn new(sent: SentBuffer) -> Self {
            Self { sent }
        }
    }

    impl ContextTransportProvider for CapturingTransport {
        fn is_connected(&self) -> bool {
            true
        }

        fn publish_context(
            &self,
            _context_id: &[u8; 32],
            _params: &ContextParams,
        ) -> Result<(), ContextCreationError> {
            Ok(())
        }

        fn delete_published(&self, _context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }

        fn send_message(
            &self,
            context_id: &[u8; 32],
            encrypted_payload: &[u8],
        ) -> Result<(), ContextError> {
            self.sent
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((*context_id, encrypted_payload.to_vec()));
            Ok(())
        }
    }

    /// Drains the capture buffer, recovering from poisoning.
    fn drain_sent(sent: &SentBuffer) -> Vec<([u8; 32], Vec<u8>)> {
        std::mem::take(
            &mut *sent
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// Encrypted `ContextParams` whose ceiling permits create + add-member +
    /// send (the creator auto-holds admin; `MemberInvite` lets the add-member
    /// path auto-accept Bob without a separate governance vote — mirrors the
    /// `scp-testing` `encrypted_params()` recipe `FullStackNode::add_member`
    /// relies on).
    fn encrypted_params() -> ContextParams {
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
            ..ContextParams::default()
        }
    }

    /// Builds Alice's real `Supervisor` (real MLS crypto + recording transport +
    /// in-memory event log / MLS storage via `test_supervisor`) and returns it
    /// alongside the shared capture buffer.
    fn alice_supervisor(sent: SentBuffer) -> Arc<Supervisor> {
        let crypto = Arc::new(MlsCryptoProvider::new(ALICE_DID.to_owned()));
        let (_active_sk, _agent_sk, alice_doc) = alice_identity();
        let resolver = document_backed_resolver(&alice_doc, None);
        let transport: Box<dyn ContextTransportProvider> = Box::new(CapturingTransport::new(sent));
        let event_log: Box<dyn crate::context::builder::ContextEventLogProvider> =
            Box::new(crate::context::providers::event_log::MerkleEventLogProvider::new());
        crate::context::test_supervisor(crypto, transport, event_log, resolver)
    }

    /// Reads Bob's actor-minted `AccessKey` from Alice's context actor via the
    /// `GetAllAccessKeys` mailbox query (the same query
    /// `FullStackNode::get_all_access_keys` uses). The actor mints each member's
    /// key with `generate_access_key`, which draws fresh `OsRng` bytes — so the
    /// recipient key MUST be read back from the actor, never re-derived.
    async fn bob_access_key_from_actor(
        sup: &Arc<Supervisor>,
        ctx_id: &str,
    ) -> scp_protocol::crypto::access_keys::AccessKey {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = crate::context::actor::QueriesCommand::GetAllAccessKeys {
            context_id: ctx_id.to_owned(),
            reply: tx,
        };
        sup.dispatch_query(cmd)
            .await
            .expect("dispatch GetAllAccessKeys");
        let keys = rx
            .await
            .expect("GetAllAccessKeys reply channel open")
            .expect("GetAllAccessKeys succeeds");
        keys.get(BOB_DID)
            .cloned()
            .expect("actor minted an access key for Bob during add-member")
    }

    /// Runs the real governance add-member path so Bob becomes a true MLS member
    /// of Alice's actor-owned group, then bootstraps Bob's standalone provider
    /// (Welcome join + sender-key processing) so it can open Alice's later
    /// application send.
    ///
    /// Returns Bob's provider, Bob's per-context pseudonym (already seeded into
    /// Alice's actor), and Bob's actor-minted access key.
    async fn add_and_bootstrap_bob(
        sup: &Arc<Supervisor>,
        handle: &ContextHandle,
        ctx_id: &str,
        sent: &SentBuffer,
    ) -> (
        Arc<MlsCryptoProvider>,
        [u8; 32],
        scp_protocol::crypto::access_keys::AccessKey,
    ) {
        let ctx_bytes = context_id_bytes(ctx_id);

        // Bob mints a real MLS key package (his provider keeps the matching
        // signer state for the later Welcome join).
        let bob = Arc::new(MlsCryptoProvider::new(BOB_DID.to_owned()));
        let bob_kp_bytes = bob
            .prepare_key_package_for_join()
            .expect("bob prepares key package");

        // Real add-member through the actor: real MLS add → real Welcome → real
        // HPKE sender-key distribution → minted access keys.
        sup.join_context(
            handle,
            KeyPackage {
                owner_did: DID::from(BOB_DID),
                mls_key_package_bytes: Some(bob_kp_bytes),
            },
            None,
            None,
        )
        .await
        .expect("actor add-member (join_context) succeeds");

        // The actor MLS-wrapped the sender-key distribution and "sent" it over
        // the recording transport. Drain those management blobs and feed them to
        // Bob so his provider learns Alice's sender key (mirrors
        // `FullStackNode::add_member` draining the buffer post-join). Keeps the
        // buffer clean for the application ciphertext the test sends later.
        let bootstrap_blobs = drain_sent(sent);

        // Bob forms his group from the Welcome the actor emitted.
        let welcome_bytes = {
            let mut welcome = None;
            for event in sup.drain_events(ctx_id).await {
                if let ContextEvent::WelcomeGenerated { welcome_bytes, .. } = event {
                    welcome = Some(welcome_bytes.0);
                }
            }
            welcome.expect("actor emitted a WelcomeGenerated event for Bob")
        };
        bob.join_from_welcome(&ctx_bytes, &welcome_bytes)
            .expect("bob joins from Welcome");
        bob.generate_sender_key(&ctx_bytes)
            .expect("bob generates his sender key");

        // Process the captured sender-key distribution: each blob is a sealed
        // management OuterEnvelope — open it, then feed the inner MLS payload to
        // `process_incoming_sender_key` (exactly the `Management` arm of
        // `FullStackNode::decrypt_message`).
        for (_routing_id, blob) in bootstrap_blobs {
            match bob
                .open(&ctx_bytes, &blob)
                .expect("bob opens bootstrap blob")
            {
                OpenResult::Management {
                    sender_did,
                    payload,
                } => {
                    bob.process_incoming_sender_key(&ctx_bytes, &sender_did, &payload)
                        .expect("bob processes Alice's sender key");
                }
                OpenResult::Control => {}
                OpenResult::Application(_) => {
                    panic!("bootstrap blob must be management/control, not application")
                }
            }
        }

        // Seed Bob's per-member pseudonym (§9.10.4): the encrypted send fans out
        // to known peer pseudonyms only, so without this seed the send fails
        // closed with `PseudonymRegistryEmpty`.
        let bob_pseudonym = [0x42u8; 32];
        sup.seed_peer_pseudonym(ctx_id, DID::from(BOB_DID), bob_pseudonym)
            .await
            .expect("seed Bob's per-context pseudonym");

        let bob_access_key = bob_access_key_from_actor(sup, ctx_id).await;

        (bob, bob_pseudonym, bob_access_key)
    }

    /// Drives the public `Supervisor::send_message` for `ctx_id` under
    /// `signing_key_id`, captures the single application ciphertext, opens it on
    /// Bob's provider, and returns the recovered inner envelope's
    /// `signing_key_id`, the recovered inner-envelope payload (still
    /// access-key-wrapped), and Bob's actor-minted access key (so the caller can
    /// optionally unwrap the content layer and assert on the plaintext).
    ///
    /// This is the assertion that closes the gap: the persona stamped on the
    /// wire is read back straight off the bytes the public send API produced.
    async fn send_via_public_api_and_recover(
        signing_key: &SigningKey,
        signing_key_id: SigningKeyId,
        payload: &[u8],
    ) -> (
        SigningKeyId,
        Vec<u8>,
        scp_protocol::crypto::access_keys::AccessKey,
    ) {
        let ctx_id = match signing_key_id {
            SigningKeyId::Agent => "ctx-live-supervisor-send-agent",
            SigningKeyId::Active => "ctx-live-supervisor-send-active",
        };
        let ctx_bytes = context_id_bytes(ctx_id);
        let sent: SentBuffer = Arc::new(Mutex::new(Vec::new()));
        let sup = alice_supervisor(Arc::clone(&sent));

        let handle = sup
            .create_context(
                ctx_id.to_owned(),
                encrypted_params(),
                DID::from(ALICE_DID),
                None,
            )
            .await
            .expect("create encrypted context");

        let (bob, bob_pseudonym, bob_access_key) =
            add_and_bootstrap_bob(&sup, &handle, ctx_id, &sent).await;

        // THE PUBLIC SEND. Persona chosen by `signing_key_id`; the signing key
        // is Alice's matching (#agent or #active) key. `MessageSigner` pairs the
        // two so the stamped persona cannot disagree with the key that signs.
        let signer = match signing_key_id {
            SigningKeyId::Active => MessageSigner::Active(signing_key),
            SigningKeyId::Agent => MessageSigner::Agent(signing_key),
        };
        sup.send_message(&handle, &DID::from(ALICE_DID), payload, signer, None, None)
            .await
            .expect("Supervisor::send_message (public API) succeeds");

        // Exactly one application ciphertext, addressed to Bob's pseudonym
        // (§9.10.4 — never the shared context routing id).
        let captured = drain_sent(&sent);
        assert_eq!(
            captured.len(),
            1,
            "the public send must produce exactly one application ciphertext"
        );
        let (routing_id, ciphertext) = &captured[0];
        assert_eq!(
            routing_id, &bob_pseudonym,
            "app-data must be addressed to Bob's per-member pseudonym (§9.10.4)"
        );
        assert_ne!(
            ciphertext.as_slice(),
            payload,
            "ciphertext must differ from plaintext"
        );

        // Open the captured wire blob on Bob's provider and read the persona
        // straight off the recovered inner envelope.
        match bob
            .open(&ctx_bytes, ciphertext)
            .expect("bob opens the app blob")
        {
            OpenResult::Application(env) => {
                let inner = env.inner;
                (inner.signing_key_id, inner.payload, bob_access_key)
            }
            other => panic!("expected an Application open result, got {other:?}"),
        }
    }

    /// Unwraps the access-key content layer of a recovered inner-envelope
    /// payload so the test can assert on the original plaintext Alice sent.
    fn unwrap_app_payload(
        inner_payload: &[u8],
        ctx_id: &str,
        bob_access_key: &scp_protocol::crypto::access_keys::AccessKey,
    ) -> Vec<u8> {
        let stripped = scp_protocol::envelope::strip_padding(inner_payload)
            .expect("strip inner-envelope padding");
        let wrapped: scp_protocol::crypto::access_keys::WrappedContent =
            rmp_serde::from_slice(&stripped).expect("deserialize WrappedContent");
        scp_protocol::crypto::access_keys::wrapping::unwrap_content(
            &wrapped,
            BOB_DID,
            bob_access_key,
            ctx_id,
            ALICE_DID,
            0,
            0,
        )
        .expect("unwrap access-key content layer")
    }

    // -----------------------------------------------------------------------
    // (d) #agent persona threads from `Supervisor::send_message` to the wire.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn supervisor_send_stamps_agent_persona_on_the_wire() {
        let (_active_sk, agent_sk, _doc) = alice_identity();
        let ctx_id = "ctx-live-supervisor-send-agent";
        let payload = b"agent persona through the public Supervisor send API";

        let (wire_persona, inner_payload, bob_access_key) =
            send_via_public_api_and_recover(&agent_sk, SigningKeyId::Agent, payload).await;

        assert_eq!(
            wire_persona,
            SigningKeyId::Agent,
            "the wire envelope produced by Supervisor::send_message(SigningKeyId::Agent) \
             must carry signing_key_id == Agent — proving the #agent persona threads \
             from the public send API through to the wire (not just the helper)"
        );

        // Symmetric end-to-end content check (mirrors the #active test): the
        // recovered payload decrypts to exactly what Alice's #agent persona
        // sent, confirming this is a real send and not just a header inspection.
        let recovered = unwrap_app_payload(&inner_payload, ctx_id, &bob_access_key);
        assert_eq!(
            recovered.as_slice(),
            payload,
            "decrypted plaintext must match what Alice's #agent persona sent"
        );
    }

    // -----------------------------------------------------------------------
    // (e) #active regression guard: the same public seam stamps #active when
    //     asked, so the agent wiring did not hijack the human-key default.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn supervisor_send_stamps_active_persona_on_the_wire() {
        let (active_sk, _agent_sk, _doc) = alice_identity();
        let ctx_id = "ctx-live-supervisor-send-active";
        let payload = b"active persona through the public Supervisor send API";

        let (wire_persona, inner_payload, bob_access_key) =
            send_via_public_api_and_recover(&active_sk, SigningKeyId::Active, payload).await;

        assert_eq!(
            wire_persona,
            SigningKeyId::Active,
            "the wire envelope produced by Supervisor::send_message(SigningKeyId::Active) \
             must carry signing_key_id == Active"
        );

        // Bonus: the recovered payload decrypts to exactly what Alice sent —
        // confirming this is a real end-to-end send, not just a header check.
        // Bob's access key is the actual key the actor minted (read back via
        // `GetAllAccessKeys`); the actor draws it from `OsRng`, so it cannot be
        // re-derived and MUST be threaded through from the bootstrap.
        let recovered = unwrap_app_payload(&inner_payload, ctx_id, &bob_access_key);
        assert_eq!(
            recovered.as_slice(),
            payload,
            "decrypted plaintext must match what Alice's #active persona sent"
        );
    }
}
