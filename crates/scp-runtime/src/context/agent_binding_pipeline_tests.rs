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

    build_encrypted_envelope(
        &clock,
        alice_provider,
        ctx_str,
        &sender,
        payload,
        signing_key,
        signing_key_id,
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
        other => panic!("expected an Application open result, got {other:?}"),
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
    match result {
        Err(ContextError::CryptoFailed(msg)) => {
            assert!(
                msg.contains("signature"),
                "live rejection must be the inner-signature check, got CryptoFailed({msg:?})"
            );
        }
        other => panic!("a wrong #agent key must make live verification fail, got {other:?}"),
    }
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
