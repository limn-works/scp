//! Tests moved out of `scp-runtime-core` `context::actor::state` (ADR-070 §6.2): they build a
//! `Supervisor`, which needs the domain handlers only `scp-runtime` assembles.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

use scp_clock::SystemClock;
use scp_did::DID;
use scp_did::SigningKeyId;
use scp_protocol::context::ContextError;
use scp_protocol::context::builder::OpenResult;
use scp_protocol::crypto::sender_keys::SenderKey;
use scp_protocol::envelope::inner::InnerEnvelope;
use scp_runtime_core::context::actor::state::*;
use scp_runtime_core::crypto::mls::provider::MlsCryptoSnapshot;
use scp_runtime_core::crypto::mls::provider::NodeMlsFactory;
use scp_runtime_core::crypto::mls::two_party_test_support::{TwoPartyPair, stand_up_two_party};
use scp_runtime_core::crypto::wrapping::IdentityWrappingKey;
use scp_runtime_types::context::actor::sequence::SendSequenceTracker;
use std::sync::Arc;

const CTX_STR: &str = "cryptomove-golden-ctx";
const ALICE: &str = "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
const BOB: &str = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";

/// Stand up the real joined Alice/Bob pair, born DIRECTLY onto actor-owned
/// [`PerContextState`] via the #2148 owned-return constructors + the
/// production `seed_encrypted_crypto_from_owned` primitive (no provider
/// `take_crypto_state` round-trip). Returns
/// `(alice_wrapping, alice_state, bob_wrapping, bob_state, ctx)`: each
/// [`PerContextState`] already OWNS its per-context crypto, beside each
/// party's identity wrapping key.
fn setup() -> (
    Arc<IdentityWrappingKey>,
    PerContextState,
    Arc<IdentityWrappingKey>,
    PerContextState,
    [u8; 32],
) {
    let TwoPartyPair {
        alice_wrapping,
        alice_state,
        bob_wrapping,
        bob_state,
        ctx_bytes,
        ..
    } = stand_up_two_party(CTX_STR, ALICE, BOB, scp_runtime::domain_handlers());
    (
        alice_wrapping,
        alice_state,
        bob_wrapping,
        bob_state,
        ctx_bytes,
    )
}

/// Build a minimal signed `InnerEnvelope` (signature is not verified by
/// `open`, per the provider contract).
fn build_inner(sender_did: &str, sequence: u64) -> InnerEnvelope {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let params = scp_runtime_core::envelope::inner::InnerEnvelopeParams {
        version: scp_runtime_core::envelope::inner::SCP_INNER_ENVELOPE_VERSION,
        context_id: CTX_STR,
        sender_did,
        epoch: 0,
        generation: 0,
        sequence,
        timestamp: 1_700_000_000,
        message_type: scp_runtime_core::envelope::inner::MessageType::Content,
        payload: b"cryptomove golden payload",
        provenance: None,
        signing_key_id: SigningKeyId::Active,
    };
    scp_runtime_core::envelope::inner::sign::create_inner_envelope_raw(&params, &sk).unwrap()
}

/// §9.5, §9.16.1: a `KeyPackage` whose `scp_wrapping_key` (`0xFF01`)
/// extension is present but is not a valid uncompressed P-256 point is
/// refused with `CryptoFailed` before the MLS add: the member is not
/// admitted and no wrapping key is recorded. Positive control: the same
/// invitee with a valid point is added and its key is recorded.
#[test]
fn add_member_rejects_key_package_with_off_curve_wrapping_key() {
    use openmls::prelude::tls_codec::Serialize as _;
    const CAROL: &str = "did:dht:z6MkCarolCarolCarolCarolCarolCarolCarolCa";
    let (_alice_p, mut alice_a, _bob_p, _bob_a, _ctx) = setup();
    let carol_cred =
        scp_mls::ScpCredential::new(CAROL.to_owned(), None, SigningKeyId::Active).unwrap();
    let kp_bytes = |wrapping: &[u8; 65]| {
        let (bundle, _signer, _provider) =
            scp_mls::group::generate_key_package_with_context_params(
                &carol_cred,
                wrapping,
                &SystemClock,
            )
            .unwrap();
        bundle.key_package().tls_serialize_detached().unwrap()
    };
    let epoch_of = |state: &PerContextState| match &state.mode {
        ContextModeState::Encrypted(c) => c.mls_group.as_ref().unwrap().epoch().unwrap(),
        ContextModeState::Broadcast(_) => panic!("expected encrypted mode"),
    };
    let recorded = |state: &PerContextState| match &state.mode {
        ContextModeState::Encrypted(c) => c.member_wrapping_keys.get(CAROL).copied(),
        ContextModeState::Broadcast(_) => panic!("expected encrypted mode"),
    };
    let epoch_before = epoch_of(&alice_a);

    let mut off_curve = [0u8; 65];
    off_curve[0] = 0x04;
    let err = alice_a
        .add_member(CAROL, Some(&kp_bytes(&off_curve)), &SystemClock)
        .expect_err("an off-curve 0xFF01 point is refused");
    match err {
        ContextError::CryptoFailed(msg) => {
            assert!(
                msg.starts_with("extension error: scp_wrapping_key extension: "),
                "got: {msg}"
            );
        }
        other => panic!("expected CryptoFailed, got {other:?}"),
    }
    assert_eq!(epoch_of(&alice_a), epoch_before, "no MLS add ran");
    assert_eq!(recorded(&alice_a), None, "no wrapping key is recorded");

    let (valid, _secret) = scp_protocol::crypto::sender_keys::generate_wrapping_keypair();
    alice_a
        .add_member(CAROL, Some(&kp_bytes(valid.as_bytes())), &SystemClock)
        .expect("a valid 0xFF01 point is admitted");
    assert_eq!(epoch_of(&alice_a), epoch_before + 1, "the MLS add ran");
    assert_eq!(recorded(&alice_a), Some(valid));
}

/// Serialized `KeyPackage` for `did` publishing `wrapping` in `0xFF01`.
fn key_package_bytes(did: &str, wrapping: &[u8; 65]) -> Vec<u8> {
    use openmls::prelude::tls_codec::Serialize as _;
    let cred = scp_mls::ScpCredential::new(did.to_owned(), None, SigningKeyId::Active).unwrap();
    let (bundle, _signer, _provider) =
        scp_mls::group::generate_key_package_with_context_params(&cred, wrapping, &SystemClock)
            .unwrap();
    bundle.key_package().tls_serialize_detached().unwrap()
}

fn cached_key(
    state: &PerContextState,
    did: &str,
) -> Option<scp_protocol::crypto::hpke::p256::P256Point> {
    match &state.mode {
        ContextModeState::Encrypted(c) => c.member_wrapping_keys.get(did).copied(),
        ContextModeState::Broadcast(_) => panic!("expected encrypted mode"),
    }
}

/// Spec 10 §10.8.1(7): a second `KeyPackage` for an existing member that
/// publishes a different wrapping key is refused before the MLS add, and the
/// cached key stays. Positive control: a second device of the same DID with
/// the same key is admitted.
#[test]
fn add_of_existing_member_with_a_different_wrapping_key_is_refused() {
    let (_alice_p, mut alice_a, bob_p, _bob_a, _ctx) = setup();
    let bob_key = scp_protocol::crypto::hpke::p256::P256Point::try_from(*bob_p.public()).unwrap();
    assert_eq!(cached_key(&alice_a, BOB), Some(bob_key));
    let epoch_before = actor_mls_epoch(&alice_a);

    let (other_key, _secret) = scp_protocol::crypto::sender_keys::generate_wrapping_keypair();
    let err = alice_a
        .add_member(
            BOB,
            Some(&key_package_bytes(BOB, other_key.as_bytes())),
            &SystemClock,
        )
        .expect_err("a different key for a recorded DID is refused");
    let expected = scp_mls::MlsError::LeafAdmissionRejected {
        did: BOB.to_owned(),
        reason: scp_mls::LeafAdmissionRejection::WrappingKeyMismatch,
    }
    .to_string();
    match err {
        ContextError::CryptoFailed(msg) => assert_eq!(msg, expected),
        other => panic!("expected CryptoFailed, got {other:?}"),
    }
    assert_eq!(actor_mls_epoch(&alice_a), epoch_before, "no MLS add ran");
    assert_eq!(
        cached_key(&alice_a, BOB),
        Some(bob_key),
        "the recorded key stays"
    );

    alice_a
        .add_member(
            BOB,
            Some(&key_package_bytes(BOB, bob_key.as_bytes())),
            &SystemClock,
        )
        .expect("a second device with the same key is admitted");
    assert_eq!(actor_mls_epoch(&alice_a), epoch_before + 1);
    assert_eq!(cached_key(&alice_a, BOB), Some(bob_key));
}

/// The governance command's invitee and the `KeyPackage` credential must
/// name the same DID; otherwise the add is refused before any MLS state
/// changes and nothing is cached under either DID.
#[test]
fn add_whose_key_package_names_another_did_is_refused() {
    const CAROL: &str = "did:dht:z6MkCarolCarolCarolCarolCarolCarolCarolCa";
    const DAVE: &str = "did:dht:z6MkDaveDaveDaveDaveDaveDaveDaveDaveDaveD";
    let (_alice_p, mut alice_a, _bob_p, _bob_a, _ctx) = setup();
    let epoch_before = actor_mls_epoch(&alice_a);
    let (carol_key, _secret) = scp_protocol::crypto::sender_keys::generate_wrapping_keypair();

    let err = alice_a
        .add_member(
            DAVE,
            Some(&key_package_bytes(CAROL, carol_key.as_bytes())),
            &SystemClock,
        )
        .expect_err("a KeyPackage for Carol cannot admit Dave");
    match err {
        ContextError::CryptoFailed(msg) => assert_eq!(
            msg,
            format!("key package credential names '{CAROL}', not the invitee '{DAVE}'")
        ),
        other => panic!("expected CryptoFailed, got {other:?}"),
    }
    assert_eq!(actor_mls_epoch(&alice_a), epoch_before, "no MLS add ran");
    assert_eq!(cached_key(&alice_a, DAVE), None);
    assert_eq!(cached_key(&alice_a, CAROL), None);
}

/// A member's own Update that publishes a new wrapping key replaces the
/// receiver's cached key through `open`, so later seals target the new key.
#[test]
fn open_of_an_update_commit_applies_the_new_wrapping_key() {
    let (alice_p, mut alice_a, _bob_p, mut bob_a, _) = setup();
    // A Welcome joiner's cache starts empty; Bob learned Alice's key.
    bob_a
        .encrypted_crypto_mut()
        .unwrap()
        .member_wrapping_keys
        .insert(
            ALICE.to_owned(),
            scp_protocol::crypto::hpke::p256::P256Point::try_from(*alice_p.public()).unwrap(),
        );
    let (new_key, _secret) = scp_protocol::crypto::sender_keys::generate_wrapping_keypair();

    let commit = alice_a
        .advance_epoch(*new_key.as_bytes(), &SystemClock)
        .unwrap()
        .commit_bytes;
    match bob_a.open(CTX_STR, &commit).unwrap() {
        OpenResult::Commit { committer_did, .. } => assert_eq!(committer_did, ALICE),
        other => panic!("expected a Commit, got {other:?}"),
    }
    assert_eq!(cached_key(&bob_a, ALICE), Some(new_key));
}

/// `open` of `commit` by `state`, which must yield a Commit.
fn open_commit(state: &mut PerContextState, commit: &[u8]) {
    match state.open(CTX_STR, commit).unwrap() {
        OpenResult::Commit { .. } => {}
        other => panic!("expected a Commit, got {other:?}"),
    }
}

/// A member another member removed leaves this node's wrapping-key cache
/// when this node processes the Remove, so re-adding it under a new key
/// succeeds and the adder's epoch matches its peer's afterwards.
#[test]
fn peer_removed_member_re_added_with_a_new_key_succeeds() {
    const CAROL: &str = "did:dht:z6MkCarolCarolCarolCarolCarolCarolCarolCa";
    let (_alice_p, mut alice_a, _bob_p, mut bob_a, _) = setup();
    let (k1, _s1) = scp_protocol::crypto::sender_keys::generate_wrapping_keypair();
    let (k2, _s2) = scp_protocol::crypto::sender_keys::generate_wrapping_keypair();

    let add = alice_a
        .add_member(
            CAROL,
            Some(&key_package_bytes(CAROL, k1.as_bytes())),
            &SystemClock,
        )
        .unwrap();
    open_commit(&mut bob_a, &add.commit_bytes);
    assert_eq!(cached_key(&alice_a, CAROL), Some(k1));

    let remove = bob_a.remove_member(BOB, CAROL, &SystemClock).unwrap();
    open_commit(&mut alice_a, &remove.commit_bytes);
    assert_eq!(cached_key(&alice_a, CAROL), None, "the Remove pruned Carol");
    assert_eq!(actor_mls_epoch(&alice_a), actor_mls_epoch(&bob_a));

    let re_add = alice_a
        .add_member(
            CAROL,
            Some(&key_package_bytes(CAROL, k2.as_bytes())),
            &SystemClock,
        )
        .expect("Carol holds no leaf, so her new key contradicts nothing");
    assert_eq!(cached_key(&alice_a, CAROL), Some(k2));
    open_commit(&mut bob_a, &re_add.commit_bytes);
    assert_eq!(actor_mls_epoch(&alice_a), actor_mls_epoch(&bob_a));
}

/// #2199: `dispose_secrets` on a REAL seeded encrypted state (a live MLS
/// group + a present sender key, born over the end-to-end join path) reports
/// BOTH destroyed-flags `true` — an OBSERVED disposal of present material.
/// This is the only path on which a `KeyDestructionAttestation`'s
/// destroyed-flags may honestly be `true`.
#[test]
fn dispose_secrets_seeded_encrypted_reports_observed_true() {
    let (_alice_p, mut alice_a, _bob_p, _bob_a, _ctx) = setup();
    // Precondition: the fixture really did seed a live group + sender key.
    match &alice_a.mode {
        ContextModeState::Encrypted(c) => {
            assert!(c.mls_group.is_some(), "fixture seeds a live MLS group");
            assert!(c.sender_key.is_some(), "fixture seeds a local sender key");
        }
        ContextModeState::Broadcast(_) => panic!("expected encrypted mode"),
    }
    let outcome = alice_a.dispose_secrets();
    assert_eq!(
        (
            outcome.mls_group_destroyed(),
            outcome.sender_keys_destroyed()
        ),
        (true, true),
        "present group + present sender key ⇒ both destroyed-flags observed true"
    );
    // The material is now gone: a repeat disposal reports honest false.
    let repeat = alice_a.dispose_secrets();
    assert_eq!(
        (repeat.mls_group_destroyed(), repeat.sender_keys_destroyed()),
        (false, false),
        "after disposal the state is emptied ⇒ a repeat reports honest false"
    );
}

/// Read the (cloned) local sender key out of an encrypted actor state.
fn actor_sender_key(state: &PerContextState) -> SenderKey {
    match &state.mode {
        ContextModeState::Encrypted(c) => c.sender_key.clone().expect("sender key present"),
        ContextModeState::Broadcast(_) => panic!("expected encrypted mode"),
    }
}

/// The live MLS epoch of an encrypted actor's group.
fn actor_mls_epoch(state: &PerContextState) -> u64 {
    match &state.mode {
        ContextModeState::Encrypted(c) => c
            .mls_group
            .as_ref()
            .expect("group present")
            .epoch()
            .unwrap(),
        ContextModeState::Broadcast(_) => panic!("expected encrypted mode"),
    }
}

/// Apply a public MLS Commit (as produced by `advance_epoch` / `remove_member`)
/// to an encrypted actor's group through
/// `scp_mls::encrypt::decrypt_with_sender_did`, the path the backend's
/// `decrypt` runs, and assert the message was a Commit.
fn merge_commit_on_actor(
    state: &mut PerContextState,
    commit_bytes: &[u8],
) -> Result<(), scp_mls::error::MlsError> {
    match &mut state.mode {
        ContextModeState::Encrypted(c) => {
            let group = c.mls_group.as_mut().expect("group present");
            match scp_mls::encrypt::decrypt_with_sender_did(group, commit_bytes)? {
                scp_mls::DecryptedContent::Commit { .. } => Ok(()),
                other => panic!("expected a Commit, got {other:?}"),
            }
        }
        ContextModeState::Broadcast(_) => panic!("expected encrypted mode"),
    }
}

#[test]
fn golden_seal_open_cross_roundtrip() {
    let (_alice_p, mut alice_a, _bob_p, mut bob_a, _) = setup();
    let inner = build_inner(ALICE, 0);

    // Actor seals; the actor receiver opens. The provider twin is deleted
    // (its crypto was destructively taken into the actor), so the golden pin
    // is the actor seal→open round-trip decrypting to the ORIGINAL
    // InnerEnvelope byte-for-byte at the base sender-key epoch (1).
    let blob_actor = alice_a.seal(ALICE, &inner).unwrap();
    let env = match bob_a.open(CTX_STR, &blob_actor).unwrap() {
        OpenResult::Application(e) => e,
        other => panic!("expected Application result, got {other:?}"),
    };

    assert_eq!(env.sender_did, ALICE);
    assert_eq!(
        env.receive_floor.epoch, 1,
        "an unrotated context binds the base sender-key epoch 1 in the AAD"
    );
    assert_eq!(env.receive_floor.sequence, 0, "first seal is sequence 0");
    assert_eq!(
        rmp_serde::to_vec_named(&env.inner).unwrap(),
        rmp_serde::to_vec_named(&inner).unwrap(),
        "decrypted InnerEnvelope must be byte-identical to the original"
    );
}

/// Multi-seal cross-round-trip: the `send_sequence → send_tracker` increment
/// adaptation is the exact thing this suite exists to guard. Seal several
/// messages in a row on BOTH impls and assert the AAD-bound
/// `receive_floor.sequence` progresses 0,1,2,… identically — proving the
/// actor's `send_tracker` advance matches the provider's `send_sequence`
/// post-increment at every step, not just at 0.
#[test]
fn golden_seal_open_multi_sequence_progression() {
    let (_alice_p, mut alice_a, _bob_p, mut bob_a, _) = setup();

    let mut actor_seqs = Vec::new();
    for i in 0..4u64 {
        let inner = build_inner(ALICE, i);

        // Actor seals -> actor receiver opens (in-order consecutive gens).
        let blob_actor = alice_a.seal(ALICE, &inner).unwrap();
        match bob_a.open(CTX_STR, &blob_actor).unwrap() {
            OpenResult::Application(e) => actor_seqs.push(e.receive_floor.sequence),
            other => panic!("expected Application, got {other:?}"),
        }
    }

    assert_eq!(
        actor_seqs,
        vec![0, 1, 2, 3],
        "actor send_tracker AAD sequence must progress 0,1,2,3 (post-increment high-water)"
    );
}

/// Post-rotate (NON-ZERO epoch) cross-round-trip: rotate the sender key so
/// the sealed message binds a non-zero epoch in its AAD, then seal→open on
/// EACH impl and assert byte-identical decrypt at the non-zero epoch —
/// proving the epoch is bound in the AAD identically across impls (the
/// zero-epoch tests cannot see an epoch-binding divergence).
#[tokio::test]
async fn golden_seal_open_after_rotate_nonzero_epoch() {
    let (_alice_p, mut alice_a, bob_p, mut bob_recv_a, _) = setup();
    let inner = build_inner(ALICE, 0);

    // --- Actor path: actor rotate + actor seal + actor open. ---
    alice_a.rotate_sender_key(ALICE, None).unwrap();
    let epoch_a = alice_a.local_sender_key_epoch();
    assert!(
        epoch_a >= 1,
        "rotate must advance the sender-key epoch past 0"
    );
    // Deliver the rotated key to Bob (the rotate queued a distribution).
    let msgs_a = alice_a.drain_pending_sender_key_messages().unwrap();
    assert_eq!(msgs_a.len(), 1);
    let (key_a, recv_epoch_a) =
        scp_runtime_core::crypto::mls::provider::NodeMlsFactory::open_incoming_sender_key_bytes(
            &bob_p,
            &bob_recv_a.context_id,
            ALICE,
            &msgs_a[0].1,
        )
        .await
        .unwrap();
    assert_eq!(recv_epoch_a, epoch_a);
    bob_recv_a.set_sender_key_unchecked(ALICE, key_a);
    let blob_actor = alice_a.seal(ALICE, &inner).unwrap();
    let opened_a = match bob_recv_a.open(CTX_STR, &blob_actor).unwrap() {
        OpenResult::Application(e) => e,
        other => panic!("expected Application, got {other:?}"),
    };

    // The rotated (non-zero) sender-key epoch is bound in the sender-layer
    // AAD, and the decrypted inner round-trips the original byte-for-byte.
    assert!(
        opened_a.receive_floor.epoch >= 1,
        "non-zero epoch bound in AAD"
    );
    assert_eq!(
        opened_a.receive_floor.epoch, epoch_a,
        "the AAD-bound epoch is the rotated sender-key epoch"
    );
    assert_eq!(
        rmp_serde::to_vec_named(&opened_a.inner).unwrap(),
        rmp_serde::to_vec_named(&inner).unwrap(),
        "decrypt at a non-zero epoch must round-trip the original inner"
    );
}

/// Round-trip at a NON-ZERO sender-key epoch: Alice rotates once on the
/// actor (so she holds a single rotated key at a non-zero epoch), delivers
/// that key to Bob, then seals — and Bob opens under the matching rotated
/// key, proving the non-zero epoch is encoded into the sender-layer AAD and
/// the receiver reconstructs the AAD + looks up the matching key.
///
/// The zero-epoch [`golden_seal_open_cross_roundtrip`] opens only at epoch 0
/// (endian-invariant); this closes the non-zero-epoch key-lookup gap by
/// delivering the rotated key to a DIFFERENT actor (Bob) before the open,
/// where [`golden_seal_open_after_rotate_nonzero_epoch`] opens on the
/// receiver that was seeded with the delivered key inline.
#[tokio::test]
async fn golden_seal_open_cross_roundtrip_nonzero_epoch() {
    let (_alice_p, mut alice_a, bob_p, mut bob_a, _) = setup();

    // Rotate ONCE on the actor so Alice holds a single rotated key at a
    // non-zero epoch.
    alice_a.rotate_sender_key(ALICE, None).unwrap();
    let epoch = alice_a.local_sender_key_epoch();
    assert!(epoch >= 1, "rotate advances the sender-key epoch past 0");

    // Deliver the rotated key to Bob (the rotate queued a distribution).
    let msgs = alice_a.drain_pending_sender_key_messages().unwrap();
    assert_eq!(msgs.len(), 1);
    let (rotated_key, recv_epoch) =
        scp_runtime_core::crypto::mls::provider::NodeMlsFactory::open_incoming_sender_key_bytes(
            &bob_p,
            &bob_a.context_id,
            ALICE,
            &msgs[0].1,
        )
        .await
        .unwrap();
    assert_eq!(recv_epoch, epoch);
    bob_a.set_sender_key_unchecked(ALICE, rotated_key);

    let inner = build_inner(ALICE, 0);

    // ACTOR seals at the non-zero epoch -> ACTOR receiver opens under the
    // delivered rotated key.
    let blob_actor = alice_a.seal(ALICE, &inner).unwrap();
    let env = match bob_a.open(CTX_STR, &blob_actor).unwrap() {
        OpenResult::Application(e) => e,
        other => panic!("expected Application result, got {other:?}"),
    };

    assert_eq!(env.sender_did, ALICE);
    assert!(
        env.receive_floor.epoch >= 1,
        "non-zero epoch bound in the AAD"
    );
    assert_eq!(
        env.receive_floor.epoch, epoch,
        "the AAD epoch is the rotated sender-key epoch"
    );
    assert_eq!(
        rmp_serde::to_vec_named(&env.inner).unwrap(),
        rmp_serde::to_vec_named(&inner).unwrap(),
        "decrypt at a non-zero epoch must round-trip the original inner"
    );
}

/// ADR-049 §15(c) fail-closed rotation coverage, RESTORED on the actor
/// (#2148 F1). The one-shot fault seam re-homed onto the actor's
/// `PerContextState` makes the NEXT `rotate_sender_key` fail closed with NO
/// partial mutation — the local sender-key epoch is unchanged (old
/// epoch/key/store retained) — proving the actor's rotation is fail-closed;
/// the seam then clears itself so the subsequent rotation advances normally.
/// This replaces the deleted provider
/// `arm_rotation_failure_once_forces_fail_closed_then_normal`.
#[test]
fn arm_rotation_failure_once_forces_fail_closed_then_normal() {
    let (_alice_p, mut alice_a, _bob_p, _bob_a, _ctx) = setup();
    let epoch_before = alice_a.local_sender_key_epoch();

    // Arm the one-shot seam: the next rotation must fail closed.
    alice_a.arm_rotation_failure_once();
    assert!(
        matches!(
            alice_a.rotate_sender_key(ALICE, None),
            Err(ContextError::CryptoFailed(_))
        ),
        "armed rotation must return CryptoFailed"
    );
    // Fail-closed: the injected failure fired BEFORE any mutation, so the
    // epoch is unchanged — the rotation was NOT committed.
    assert_eq!(
        alice_a.local_sender_key_epoch(),
        epoch_before,
        "failed rotation must NOT advance the epoch (no partial mutation)"
    );

    // One-shot cleared: the next rotation persists normally and advances the
    // epoch by exactly one.
    alice_a.rotate_sender_key(ALICE, None).unwrap();
    assert_eq!(
        alice_a.local_sender_key_epoch(),
        epoch_before + 1,
        "post-clear rotation must advance the epoch by one"
    );
}

/// `seal` must FAIL-CLOSED at the `u64::MAX` send-sequence boundary — byte
/// parity with the provider's `send_sequence.checked_add(1)?` (emit nothing,
/// return `CryptoFailed("send sequence counter overflow")`). Guards against
/// the `SendSequenceTracker::reserve_next` saturating-add fail-OPEN.
#[test]
fn seal_fails_closed_on_send_sequence_overflow() {
    let (_alice_p, mut alice_a, _bob_p, _bob_a, _) = setup();
    // Saturate the send tracker to the u64 ceiling.
    alice_a.send_tracker = SendSequenceTracker::from_persisted(u64::MAX);
    let inner = build_inner(ALICE, 0);
    let err = alice_a
        .seal(ALICE, &inner)
        .expect_err("seal must fail-closed at the u64::MAX send-sequence boundary");
    match err {
        ContextError::CryptoFailed(msg) => {
            assert_eq!(msg, "send sequence counter overflow");
        }
        other => panic!("expected CryptoFailed overflow, got {other:?}"),
    }
    // The tracker was NOT advanced (no reservation taken) — matches the
    // provider leaving `send_sequence` unchanged on `checked_add` overflow.
    assert_eq!(alice_a.send_tracker.last_issued(), u64::MAX);
}

#[test]
fn golden_mls_encrypt_management_cross_roundtrip() {
    let (_alice_p, mut alice_a, _bob_p, mut bob_a, _) = setup();
    let payload = b"management golden payload";

    // Actor management-encrypts; the actor receiver opens and recovers the
    // exact payload (the provider twin is deleted).
    let blob_actor = alice_a.mls_encrypt_management(payload).unwrap();
    match bob_a.open(CTX_STR, &blob_actor).unwrap() {
        OpenResult::Management { payload: p, .. } => assert_eq!(p, payload),
        other => panic!("expected Management result, got {other:?}"),
    }
}

#[test]
fn golden_group_context_extension_byte_identical() {
    let (_alice_p, alice_a, _bob_p, _bob_a, _ctx) = setup();
    let from_actor = alice_a.group_context_extension().unwrap();
    let ext = from_actor.expect("an SCP context group carries the 0xFF02 extension");
    assert_eq!(
        ext.context_id, CTX_STR,
        "the group-context extension binds the golden context id"
    );
    assert_eq!(
        ext.creator_did,
        DID::from(ALICE.to_owned()),
        "the group-context extension binds the creator DID"
    );
}

#[test]
fn golden_local_sender_key_epoch_matches() {
    let (_alice_p, alice_a, _bob_p, _bob_a, _ctx) = setup();
    assert_eq!(
        alice_a.local_sender_key_epoch(),
        1,
        "a freshly joined, unrotated context reads the base local sender-key epoch 1"
    );
}

#[tokio::test]
async fn golden_distribute_and_process_recover_identical_key() {
    let (_alice_p, mut alice_a, bob_p, mut bob_a, _) = setup();

    // Actor distributes Alice's CURRENT (unrotated) sender key.
    alice_a.distribute_sender_key(ALICE, BOB, None).unwrap();
    let actor_msgs = alice_a.drain_pending_sender_key_messages().unwrap();
    assert_eq!(actor_msgs.len(), 1, "one queued distribution");
    // Drain again — the queue is now empty (verbatim `std::mem::take`).
    assert!(
        alice_a
            .drain_pending_sender_key_messages()
            .unwrap()
            .is_empty()
    );

    // Recover the key via the actor receive half. The recovered key material
    // is deterministic (Alice's existing key), so it equals Alice's actual
    // local sender key byte-for-byte.
    let (recovered_key, epoch) =
        scp_runtime_core::crypto::mls::provider::NodeMlsFactory::open_incoming_sender_key_bytes(
            &bob_p,
            &bob_a.context_id,
            ALICE,
            &actor_msgs[0].1,
        )
        .await
        .unwrap();
    assert_eq!(
        epoch, 1,
        "the unrotated key distributes at the base epoch 1"
    );
    assert_eq!(
        recovered_key.as_bytes(),
        actor_sender_key(&alice_a).as_bytes(),
        "recovered sender key must equal Alice's actual sender key"
    );

    // `set_sender_key_unchecked` install half: after installing the recovered
    // key on the Bob actor, Alice's application seal opens under it.
    bob_a.set_sender_key_unchecked(ALICE, recovered_key);
    let inner = build_inner(ALICE, 0);
    let sealed = alice_a.seal(ALICE, &inner).unwrap();
    match bob_a.open(CTX_STR, &sealed).unwrap() {
        OpenResult::Application(env) => assert_eq!(env.sender_did, ALICE),
        other => panic!("expected Application, got {other:?}"),
    }
}

#[tokio::test]
async fn golden_rotate_sender_key_parity() {
    let (_alice_p, mut alice_a, bob_p, bob_a, _ctx) = setup();

    let epoch_before = alice_a.local_sender_key_epoch();
    assert_eq!(
        epoch_before, 1,
        "unrotated context starts at the base epoch 1"
    );

    // Rotate on the actor. The fresh key + HPKE ephemeral are random; the
    // EPOCH advance and the distribution's processability are the
    // deterministic golden invariants.
    alice_a.rotate_sender_key(ALICE, None).unwrap();

    assert_eq!(
        alice_a.local_sender_key_epoch(),
        epoch_before + 1,
        "actor rotate advances the local epoch by one"
    );

    // The queued distribution from the actor rotate is processable by Bob and
    // carries the new epoch.
    let msgs = alice_a.drain_pending_sender_key_messages().unwrap();
    assert_eq!(msgs.len(), 1, "one member (Bob) receives the rotated key");
    let (_key, epoch) =
        scp_runtime_core::crypto::mls::provider::NodeMlsFactory::open_incoming_sender_key_bytes(
            &bob_p,
            &bob_a.context_id,
            ALICE,
            &msgs[0].1,
        )
        .await
        .unwrap();
    assert_eq!(epoch, epoch_before + 1);
}

#[test]
fn golden_advance_epoch_parity() {
    let (alice_p, mut alice_a, _bob_p, mut bob_from_actor, _ctx) = setup();
    let wpub = *alice_p.public();

    // `advance_epoch` self-merges the committer's Update+Commit, advancing
    // the local MLS epoch by one.
    let epoch_before = actor_mls_epoch(&alice_a);
    let out_a = alice_a.advance_epoch(wpub, &SystemClock).unwrap();
    assert!(
        !out_a.commit_bytes.is_empty(),
        "actor advance_epoch produces a non-empty commit"
    );
    let epoch_after = actor_mls_epoch(&alice_a);
    assert_eq!(
        epoch_after,
        epoch_before + 1,
        "advance_epoch self-merges, advancing the committer's MLS epoch by one"
    );

    // The counterparty PROCESSES the commit and reaches the committer's new
    // epoch (the actor is the sole crypto authority; the provider twin is
    // deleted).
    merge_commit_on_actor(&mut bob_from_actor, &out_a.commit_bytes)
        .expect("Bob processes the actor-produced advance Commit");
    assert_eq!(
        actor_mls_epoch(&bob_from_actor),
        epoch_after,
        "Bob reaches the committer's new epoch after processing the advance Commit"
    );
}

#[test]
fn golden_remove_member_parity() {
    let (_alice_p, mut alice_a, _bob_p, mut bob_from_actor, _ctx) = setup();

    // Self-removal is a no-op (empty output).
    assert!(
        alice_a
            .remove_member(ALICE, ALICE, &SystemClock)
            .unwrap()
            .commit_bytes
            .is_empty()
    );

    // Removing Bob self-merges the remove-Commit, advancing Alice's epoch by
    // one; the output is a non-empty Commit + group-info.
    let epoch_before = actor_mls_epoch(&alice_a);
    let out_a = alice_a.remove_member(ALICE, BOB, &SystemClock).unwrap();
    assert!(
        !out_a.commit_bytes.is_empty(),
        "actor remove_member produces a Commit"
    );
    assert!(!out_a.group_info_bytes.is_empty());
    assert_eq!(
        actor_mls_epoch(&alice_a),
        epoch_before + 1,
        "remove_member self-merges, advancing the committer's MLS epoch by one"
    );

    // The counterparty (Bob — the removed member) PROCESSES the remove-Commit
    // and learns of his removal, reaching the committer's new epoch.
    merge_commit_on_actor(&mut bob_from_actor, &out_a.commit_bytes)
        .expect("Bob processes the actor-produced remove Commit");
    assert_eq!(actor_mls_epoch(&bob_from_actor), epoch_before + 1);
}

#[test]
fn golden_export_restore_equivalent() {
    let (_alice_p, alice_a, _bob_p, _bob_a, ctx) = setup();

    // Capture the ORIGINAL group-context extension + local epoch off the live
    // actor (export is non-destructive) as the golden restore target.
    let orig_ext = alice_a.group_context_extension().unwrap();
    let orig_epoch = alice_a.local_sender_key_epoch();

    let blob_a = alice_a.export_crypto_state(Vec::new(), Vec::new()).unwrap();
    assert!(!blob_a.is_empty());

    // Functional restore equivalence: rebuild the owned material on a fresh
    // provider via the retained `build_restored_owned` reader (the deleted
    // insert-path `restore_crypto_state` twin is gone), reseed an actor, and
    // confirm it agrees with the ORIGINAL on the group-context extension and
    // local sender-key epoch.
    let (owned, _floors) = NodeMlsFactory::build_restored_owned(&ctx, &blob_a).unwrap();
    let mut restored = PerContextState::new_for_test_encrypted(ctx, 0, DID::from(ALICE.to_owned()));
    restored.seed_encrypted_crypto_from_owned(owned);
    assert_eq!(
        restored.group_context_extension().unwrap(),
        orig_ext,
        "restored group-context extension must match the original"
    );
    assert_eq!(
        restored.local_sender_key_epoch(),
        orig_epoch,
        "restored local sender-key epoch must match the original"
    );
}

/// `MlsCryptoSnapshot`'s `Zeroizing` fields encode exactly as the plain
/// fields they replaced: the exported blob decodes into the plain-field
/// layout and re-encodes to the same bytes, and those bytes decode back
/// into the wiping type.
#[test]
fn crypto_snapshot_encodes_like_plain_fields() {
    #[derive(serde::Serialize, serde::Deserialize)]
    struct Plain {
        mls_storage_entries: Vec<(Vec<u8>, Vec<u8>)>,
        local_sender_key: SenderKey,
        sender_key_entries: Vec<(String, SenderKey)>,
        sender_key_epochs: Vec<(String, u64)>,
        sender_key_epoch: u64,
        send_sequence: u64,
        member_wrapping_keys: Vec<(String, scp_protocol::crypto::hpke::p256::P256Point)>,
        signer_bytes: Vec<u8>,
        group_id: Vec<u8>,
        recv_sequence_tracker: Vec<(String, u64, u64)>,
        pending_distributions: Vec<PlainDistribution>,
        sender_key_rotation_pending: bool,
    }
    #[derive(serde::Serialize, serde::Deserialize)]
    struct PlainDistribution {
        kind: scp_runtime_core::crypto::mls::provider::DistributionKind,
        target_did: String,
        recipient_key: Vec<u8>,
        epoch: u64,
        message: Vec<u8>,
        first_attempt_at: Option<u64>,
        failed_attempts: u32,
    }
    let (_alice_p, mut alice_a, _bob_p, _bob_a, _ctx) = setup();
    // A queued distribution, so `pending_distributions` is not empty.
    if let ContextModeState::Encrypted(cs) = &mut alice_a.mode {
        ContextCryptoState::enqueue_distribution(
            &mut cs.pending_distributions,
            BOB.to_owned(),
            vec![0x02; 33],
            1,
            vec![0xAB; 4],
        );
    }
    // A peer's sender key, so `sender_key_entries` is not empty.
    alice_a.set_sender_key_unchecked(
        BOB,
        scp_protocol::crypto::sender_keys::generate_sender_key(),
    );
    let blob = alice_a.export_crypto_state(Vec::new(), Vec::new()).unwrap();

    let plain: Plain = rmp_serde::from_slice(&blob).unwrap();
    assert!(!plain.mls_storage_entries.is_empty());
    assert!(!plain.sender_key_entries.is_empty());
    assert_eq!(plain.pending_distributions.len(), 1);
    assert_eq!(plain.pending_distributions[0].message, [0xAB; 4]);
    assert_eq!(plain.pending_distributions[0].recipient_key, [0x02; 33]);
    assert_eq!(plain.pending_distributions[0].epoch, 1);
    let plain_bytes = rmp_serde::to_vec_named(&plain).unwrap();
    assert_eq!(*blob, plain_bytes);

    let wiping: MlsCryptoSnapshot = rmp_serde::from_slice(&plain_bytes).unwrap();
    assert_eq!(*wiping.signer_bytes, plain.signer_bytes);
    assert_eq!(*wiping.mls_storage_entries, plain.mls_storage_entries);
    assert_eq!(
        wiping.local_sender_key.as_bytes(),
        plain.local_sender_key.as_bytes()
    );
    assert_eq!(
        wiping.sender_key_entries.len(),
        plain.sender_key_entries.len()
    );
    assert_eq!(
        wiping.pending_distributions[0].message.as_slice(),
        plain.pending_distributions[0].message.as_slice()
    );
}

#[test]
fn golden_destroy_mls_group_empties_export() {
    let (_alice_p, mut alice_a, _bob_p, _bob_a, _ctx) = setup();

    assert!(
        !alice_a
            .export_crypto_state(Vec::new(), Vec::new())
            .unwrap()
            .is_empty()
    );
    alice_a.destroy_mls_group().unwrap();
    assert!(
        alice_a
            .export_crypto_state(Vec::new(), Vec::new())
            .unwrap()
            .is_empty(),
        "destroy_mls_group makes export return empty (the group map entry is \
             removed)"
    );
}

#[test]
fn golden_destroy_sender_key_rotates_and_clears() {
    let (_alice_p, mut alice_a, _bob_p, _bob_a, ctx) = setup();

    let key_before = actor_sender_key(&alice_a);
    alice_a.destroy_sender_key().unwrap();
    let key_after = actor_sender_key(&alice_a);
    assert_ne!(
        key_before.as_bytes(),
        key_after.as_bytes(),
        "destroy_sender_key rotates the local key to fresh material"
    );
    // Store is cleared for this context.
    match &alice_a.mode {
        ContextModeState::Encrypted(c) => assert!(
            c.sender_key_store.get_all(&hex::encode(ctx)).is_empty(),
            "destroy_sender_key clears the per-context sender-key store"
        ),
        ContextModeState::Broadcast(_) => panic!("expected encrypted mode"),
    }
}

/// §9.16.2 sender-key ANSWER round-trip (ADR-049 PR-7): the actor
/// [`ContextCryptoState::handle_sender_key_request`] seals its local sender
/// key to a member requester's fresh ephemeral wrapping key, and the
/// requester recovers Alice's ACTUAL local sender key — the ground truth —
/// plus the response metadata (`sender_did` / `epoch` / echoed nonce).
///
/// The answer is the `SenderKeyDistributionMessage::KeyResponse` envelope the
/// production receive path parses (BLACK-P7-2), so the test decodes the enum,
/// not a bare `SenderKeyResponse`. This is a self-contained actor round-trip:
/// the earlier oracle-vs-actor byte comparison was DROPPED — the retained
/// provider `handle_sender_key_request` is a test FIXTURE builder, not a wire
/// authority, so agreement with a second copy of the same code proved nothing
/// the ground-truth assert below does not. The sealed ciphertext is
/// HPKE-randomised (fresh ephemeral per answer), so the deterministic golden
/// is the RECOVERED key, not the ciphertext bytes.
#[tokio::test]
async fn golden_handle_sender_key_request_actor_round_trip() {
    use ed25519_dalek::Signer as _;
    use scp_clock::Clock as _;

    let (_alice_p, mut alice_a, _bob_p, _bob_a, ctx) = setup();
    let ctx_hex = hex::encode(ctx);
    let blocked: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Bob's request-signing key (arbitrary; its public half is passed as the
    // `requester_public_key`). BOB is a real group member, so the §9.16.6
    // Mitigation-1 membership gate passes on the group tree regardless.
    let bob_request_signing_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let bob_verifying_key = bob_request_signing_key.verifying_key();

    // Build a signed SenderKeyRequest for Alice's key, sealing to a fresh
    // ephemeral DHKEM(P-256) wrapping key held in custody.
    let nonce = [2u8; 16];
    let ephemeral = scp_runtime_core::crypto::wrapping::test_wrapping_key(&Arc::new(
        scp_platform::testing::InMemoryKeyCustody::new(),
    ))
    .await
    .unwrap();
    let wrapping_pub =
        scp_protocol::crypto::hpke::p256::P256Point::try_from(*ephemeral.public()).unwrap();
    let timestamp = SystemClock.now_secs();
    let hash = scp_protocol::crypto::sender_keys::key_protocol_verify::compute_request_hash(
        BOB,
        ALICE,
        &wrapping_pub,
        &nonce,
        scp_protocol::crypto::sender_keys::key_protocol_verify::RequestHashInput {
            epoch: 1,
            requested_at: timestamp,
        },
    )
    .unwrap();
    let signature: [u8; 64] = bob_request_signing_key.sign(&hash).to_bytes();
    let request = scp_protocol::crypto::sender_keys::SenderKeyRequest {
        requester_did: BOB.to_owned(),
        sender_did: ALICE.to_owned(),
        epoch: 1,
        wrapping_pubkey: wrapping_pub,
        nonce,
        timestamp,
        signature,
    };
    let req_bytes = rmp_serde::to_vec_named(&request).unwrap();

    // Answer Bob's request on Alice's owned actor state.
    let resp_bytes = {
        let crypto = match &mut alice_a.mode {
            ContextModeState::Encrypted(c) => c.as_mut(),
            ContextModeState::Broadcast(_) => panic!("expected encrypted mode"),
        };
        crypto
            .handle_sender_key_request(
                &ctx,
                ALICE,
                SystemClock.now_secs(),
                &req_bytes,
                bob_verifying_key.as_bytes(),
                &blocked,
            )
            .expect("actor answers a member request")
            .expect("member requester receives a response")
    };

    // The answer is the KeyResponse envelope the production receiver parses.
    let resp = match scp_protocol::crypto::sender_keys::SenderKeyDistributionMessage::from_bytes(
        &resp_bytes,
    )
    .expect("answer decodes as a SenderKeyDistributionMessage")
    {
        scp_protocol::crypto::sender_keys::SenderKeyDistributionMessage::KeyResponse(r) => r,
        other => panic!("expected a KeyResponse envelope, got {other:?}"),
    };
    let dh = ephemeral
        .agree(&scp_protocol::crypto::hpke::p256::ValidatedEnc::from(
            resp.ephemeral_pubkey,
        ))
        .await
        .unwrap();
    let key_actor =
        scp_runtime_types::crypto::sender_keys::key_protocol::open_sender_key_response_with_dh(
            &dh,
            ephemeral.public(),
            &ctx_hex,
            &resp,
        )
        .unwrap();

    // Ground truth: the recovered key is Alice's ACTUAL local sender key, and
    // the metadata echoes the request.
    assert_eq!(
        key_actor.as_bytes(),
        actor_sender_key(&alice_a).as_bytes(),
        "the recovered key is Alice's actual local sender key"
    );
    assert_eq!(resp.sender_did, ALICE);
    assert_eq!(resp.epoch, 1);
    assert_eq!(
        resp.request_nonce, nonce,
        "response echoes the request nonce"
    );
}
