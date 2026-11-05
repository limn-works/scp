//! Tests moved out of `scp-runtime-core` `crypto::mls::provider` (ADR-070 §6.2): they build a
//! `Supervisor`, which needs the domain handlers only `scp-runtime` assembles.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::significant_drop_tightening
)]

use scp_did::SigningKeyId;
use scp_protocol::context::ContextError;

const TEST_DID: &str = "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

// ADR-049 PR-7 (SCP-CRYPTOMOVE-001): the 11 provider steady-state crypto
// methods (seal/open/advance_epoch/rotate_sender_key/remove_member/
// remove_member_sender_key/mls_encrypt_management/local_sender_key_epoch/
// export_crypto_state/restore_crypto_state/drain_pending_sender_key_messages)
// were RELOCATED onto the actor's `PerContextState`. The provider retains
// only the birth/restore machinery (`create_mls_group[_with_context]`,
// `add_member`, `take_crypto_state`, `build_restored_owned`, `with_context`,
// `destroy_*`, `validate_key_package`) plus the
// receive-side primitives (`distribute_sender_key`,
// `open_incoming_sender_key`, `set_sender_key_unchecked`,
// `store_member_sender_key`). The helpers below drive the relocated actor
// seam so this module's coverage of the snapshot format, the one-way take,
// and the retained per-context restore reader survives the move. Byte-parity
// between the provider receiver and the actor seal/open path is pinned by the
// `golden_*` cross-roundtrip tests in `context::actor::state`'s test module.
use scp_runtime_core::context::actor::PerContextState;

/// Mutable sibling of [`actor_crypto`] — hands out the `&mut ContextCryptoState`
/// that the field-granular Class-C send/receive seams (e.g.
/// `ContextCryptoState::seal` / `build_encrypted_envelope_actor`) operate on.
fn actor_crypto_mut(
    state: &mut PerContextState,
) -> &mut scp_runtime_core::context::actor::ContextCryptoState {
    match &mut state.mode {
        scp_runtime_core::context::actor::ContextModeState::Encrypted(crypto) => crypto,
        scp_runtime_core::context::actor::ContextModeState::Broadcast(_) => {
            panic!("expected encrypted mode")
        }
    }
}

// -------------------------------------------------------------------
// H9: receive-side sender-key epoch ceiling
// -------------------------------------------------------------------

/// Two-party fixture: Alice (creator) and Bob (joiner) share a real
/// MLS group via the provider-level Welcome flow, exchange Alice's
/// sender key, and return both providers ready for `seal()` /
/// `open()`. Used by the H9 ceiling tests.
/// String whose SHA-256 is the `context_id` returned by
/// [`setup_alice_bob_two_party`]. The sender-layer AEAD AAD binds the raw
/// context-id string (§9.16.1), and both `seal` and `open` assert the
/// supplied 32-byte id is `context_id_bytes(ctx_str)`, so the fixture must
/// derive its id from a real string rather than an arbitrary 32-byte value.
const TEST_CTX_STR: &str = "h9-ceiling-ctx";

fn setup_alice_bob_two_party() -> (PerContextState, PerContextState, [u8; 32], String) {
    let alice_did = TEST_DID;
    let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
    // Stand up the joined pair over the REAL reserve → creator-add → sign →
    // HPKE-seal → join path, born DIRECTLY onto actor-owned state via the
    // #2148 owned-return constructors (no provider `take_crypto_state`
    // round-trip). The helper also pulls Alice's sender key to Bob, so Bob's
    // installed sender-key epoch for Alice is 1 — the H9 high-water mark these
    // tests anchor on. The returned providers are unused here, so they are
    // discarded.
    let scp_runtime_core::crypto::mls::two_party_test_support::TwoPartyPair {
        alice_state,
        bob_state,
        ctx_bytes: context_id,
        ..
    } = scp_runtime_core::crypto::mls::two_party_test_support::stand_up_two_party(
        TEST_CTX_STR,
        alice_did,
        bob_did,
        scp_runtime::domain_handlers(),
    );

    (alice_state, bob_state, context_id, alice_did.to_string())
}

/// Build a minimal `InnerEnvelope` with a deterministic signing key.
/// The actor seal/open seam (`PerContextState::open`) does not verify inner
/// signatures — signature verification is deferred to the receive/dispatch
/// path — so an arbitrary key suffices for the H9 receive-ceiling tests.
fn build_test_inner(
    context_id_str: &str,
    sender_did: &str,
    epoch_field: u64,
    sequence_field: u64,
) -> scp_protocol::envelope::inner::InnerEnvelope {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let params = scp_runtime_core::envelope::inner::InnerEnvelopeParams {
        version: scp_runtime_core::envelope::inner::SCP_INNER_ENVELOPE_VERSION,
        context_id: context_id_str,
        sender_did,
        epoch: epoch_field,
        generation: 0,
        sequence: sequence_field,
        timestamp: 1_700_000_000,
        message_type: scp_runtime_core::envelope::inner::MessageType::Content,
        payload: b"h9 ceiling probe",
        provenance: None,
        signing_key_id: SigningKeyId::Active,
    };
    scp_runtime_core::envelope::inner::sign::create_inner_envelope_raw(&params, &sk).unwrap()
}

#[test]
fn seal_open_binds_raw_context_id_string_not_hex() {
    // §9.16.1: the sender-layer AEAD AAD MUST bind the RAW context_id
    // string (UTF-8, BE32 length-prefixed), NOT the hex encoding of its
    // 32-byte hash. This is the #1909 fix and the cross-implementation interop
    // contract. Proof: a `seal`ed message opens with the raw string but
    // FAILS to open when the hex-of-bytes string is supplied as the AAD
    // source — the exact value native used to (incorrectly) bind.
    let (mut alice_actor, mut bob_actor, ctx_id, alice_did) = setup_alice_bob_two_party();

    // Two independently-sealed messages. MLS forward secrecy deletes the
    // per-message decryption secret on the FIRST `open` of a given
    // ciphertext, so the negative and positive cases must each consume
    // their own freshly-sealed blob — re-opening one blob twice would fail
    // at the MLS layer for an unrelated (forward-secrecy) reason.
    let inner1 = build_test_inner(TEST_CTX_STR, &alice_did, 0, 0);
    let inner2 = build_test_inner(TEST_CTX_STR, &alice_did, 0, 1);
    let sealed_neg = alice_actor.seal(&alice_did, &inner1).unwrap();
    let sealed_pos = alice_actor.seal(&alice_did, &inner2).unwrap();

    // Negative: opening with the hex-of-bytes string supplies a
    // `context_id_str` of `hex(ctx_id)` instead of the raw `TEST_CTX_STR`
    // the message was sealed under. The OLD (spec-violating) native code
    // bound `hex(ctx_id)` as the AAD; the §9.16.1 fix binds the RAW string,
    // so reconstructing the AAD from `hex(ctx_id)` yields a DIFFERENT AAD
    // and the sender-layer AEAD authentication fails — proving the bound
    // value is the raw string, not the hex.
    //
    // ADR-056 note: `hex(ctx_id)` is a canonical 64-hex string, so the
    // top-of-`open` resolve-consistency guard (`context_id_to_bytes`)
    // now resolves it back to `ctx_id` and PASSES — `hex(digest)` IS the
    // canonical id-string form of `digest`. The rejection therefore comes
    // from the AEAD layer (the AAD mismatch), one layer deeper than the
    // pre-ADR-056 hash-consistency guard, but it still proves the same
    // §9.16.1 contract: the AAD binds the raw string, not its hex. The
    // dedicated guard-rejection path is covered by
    // `open_rejects_context_id_str_that_does_not_resolve_to_context_id`.
    let hex_ctx = hex::encode(ctx_id);
    bob_actor.open(&hex_ctx, &sealed_neg).expect_err(
        "opening with hex(ctx_id) as the AAD source must fail — the message was sealed \
             under the RAW context_id string, so the rebuilt AAD does not authenticate",
    );

    // Positive: opening the second blob with the RAW context_id string
    // (the spec value) succeeds, proving the AAD binds the raw string.
    let opened = bob_actor
        .open(TEST_CTX_STR, &sealed_pos)
        .expect("opening with the raw context_id string (spec AAD) must succeed");
    match opened {
        scp_protocol::context::builder::OpenResult::Application(env) => {
            assert_eq!(env.sender_did, alice_did);
        }
        other => panic!("expected Application, got {other:?}"),
    }
}

#[test]
fn open_rejects_context_id_str_that_does_not_resolve_to_context_id() {
    // Defense-in-depth symmetry with `seal`: `open` asserts the supplied
    // 32-byte `context_id` is `context_id_to_bytes(context_id_str)`
    // (ADR-056) and fails CLOSED if they diverge. This guard fires at the
    // very top of `open`, BEFORE any outer-envelope deserialization, MLS
    // decrypt, or sender-layer AEAD work — so the rejection is the fast-path
    // resolve-consistency error, distinct from an AEAD authentication
    // failure.
    let (_alice_actor, mut bob_actor, ctx_id, _alice_did) = setup_alice_bob_two_party();

    // A `context_id_str` whose canonical resolution is NOT `ctx_id`. It is a
    // non-64-hex string, so it resolves via the SHA-256 fallback; `ctx_id`
    // is the resolution of TEST_CTX_STR, so any other string resolves
    // elsewhere.
    let mismatched_ctx_str = "definitely-not-the-real-context-string";
    assert_ne!(
        scp_runtime_core::context::state::context_id_to_bytes(mismatched_ctx_str),
        ctx_id,
        "test precondition: the mismatched string must not resolve to ctx_id"
    );

    // The outer bytes are deliberately garbage: the guard must reject the
    // mismatched id/string pair BEFORE it ever attempts to deserialize or
    // decrypt them. If the guard did not fire first, this call would
    // instead surface an "outer envelope deserialization" error — proving
    // by its absence that the fail-fast assert ran ahead of the AEAD layer.
    let bogus_outer = [0xABu8; 64];
    let err = bob_actor
        .open(mismatched_ctx_str, &bogus_outer)
        .expect_err("open must reject a context_id_str that does not resolve to context_id");

    match err {
        ContextError::CryptoFailed(msg) => {
            assert_eq!(
                msg, "context_id_str does not resolve to the supplied context_id",
                "expected the fail-fast resolve-consistency rejection, not an AEAD or \
                     deserialization failure, got: {msg}"
            );
        }
        other => panic!("expected CryptoFailed, got {other:?}"),
    }
}

#[test]
fn seal_rejects_context_id_str_that_does_not_resolve_to_context_id() {
    // Defense-in-depth symmetry with `open` (mirror of
    // `open_rejects_context_id_str_that_does_not_resolve_to_context_id`):
    // `seal` asserts the AAD-bound inner-envelope `context_id` STRING
    // resolves via `context_id_to_bytes` (ADR-056) to the supplied 32-byte
    // `context_id` keying argument, and fails CLOSED if they diverge. This
    // guard fires at the very top of `seal`'s `with_context` closure,
    // BEFORE any inner-envelope serialization, sender-layer AEAD, or MLS
    // encrypt work — so the rejection is the fast-path resolve-consistency
    // error, not a downstream crypto failure.
    let (mut alice_actor, _bob_actor, ctx_id, alice_did) = setup_alice_bob_two_party();

    // The keying context is the REAL `ctx_id`, but the inner envelope binds
    // a DIFFERENT context-id string. The string is non-64-hex, so it
    // resolves via the SHA-256 fallback; `ctx_id` is the resolution of
    // TEST_CTX_STR, so any other string resolves elsewhere. The mismatch is
    // load-bearing: without it the guard would not fire.
    let mismatched_ctx_str = "definitely-not-the-real-context-string";
    assert_ne!(
        scp_runtime_core::context::state::context_id_to_bytes(mismatched_ctx_str),
        ctx_id,
        "test precondition: the mismatched string must not resolve to ctx_id"
    );

    let inner = build_test_inner(mismatched_ctx_str, &alice_did, 0, 0);
    let err = alice_actor
        .seal(&alice_did, &inner)
        .expect_err("seal must reject an inner context_id that does not resolve to context_id");

    match err {
        ContextError::CryptoFailed(msg) => {
            assert_eq!(
                msg, "inner envelope context_id does not resolve to the supplied context_id",
                "expected the fail-fast resolve-consistency rejection, not a serialization, \
                     AEAD, or MLS-encrypt failure, got: {msg}"
            );
        }
        other => panic!("expected CryptoFailed, got {other:?}"),
    }
}
// #2148 (ADR-049 birth-into-actor): the provider take/with_context bookkeeping
// tests (`take_crypto_state_removes_entry_from_provider`,
// `take_crypto_state_missing_context_returns_not_registered`,
// `take_crypto_state_double_take_returns_owned_by_actor`,
// `with_context_distinguishes_never_created_from_taken`,
// `taken_context_write_paths_fail_closed`) were DELETED. They tested the
// provider's `contexts` / `taken_context_ids` / `take_crypto_state` /
// `with_context` mechanics, all of which are deleted — the provider holds no
// per-context state, so there is no residency, take, or overwrite guard to
// assert. The sole double-birth authority is now the supervisor registry's
// atomic first-writer-wins insert.

// -----------------------------------------------------------------------
// §9.10.4 privacy: app-data outer-envelope routing_id is zeroed.
//
// App-data sends seal ONE blob and fan it out to N per-member pseudonym
// transport addresses. If the cleartext outer-envelope `routing_id` field
// embedded the relay-derivable `context_routing_id`, a curious relay could
// read it off every pseudonym-addressed app-data blob and re-correlate all
// senders — defeating the pseudonym scheme. The production helper
// `build_encrypted_envelope` therefore zeroes that field for app-data.
// Control messages (recovery / sender-key dist) legitimately keep
// `context_routing_id` because their inner field == their transport address
// (the shared bootstrap channel every member subscribes to), so there is no
// leak — those sites are guarded below.
// -----------------------------------------------------------------------

fn app_data_recipients(
    ctx_str: &str,
    sender_did: &str,
) -> std::collections::HashMap<String, scp_protocol::crypto::access_keys::AccessKey> {
    let mut map = std::collections::HashMap::new();
    map.insert(
        sender_did.to_owned(),
        scp_protocol::crypto::access_keys::generate_access_key(ctx_str, sender_did),
    );
    map
}

/// Two-party MLS setup whose group is keyed by `context_id_bytes(ctx_str)`,
/// matching how `build_encrypted_envelope` derives the group key from the
/// context-id STRING it is passed. (`setup_alice_bob_two_party` keys the
/// group by an arbitrary `[u8; 32]` that is not the SHA-256 of any string,
/// which the string-driven helper cannot address.)
fn setup_two_party_for_ctx_string(
    ctx_str: &str,
) -> (PerContextState, PerContextState, [u8; 32], String) {
    let alice_did = TEST_DID;
    let bob_did = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";
    // Stand up the joined pair over the REAL join path, born DIRECTLY onto
    // actor-owned state via the #2148 owned-return constructors, keyed by
    // `context_id_bytes(ctx_str)`. The helper pulls Alice's sender key to Bob
    // so Bob can decrypt Alice's app-data sends. The returned providers are
    // unused here, so they are discarded.
    let scp_runtime_core::crypto::mls::two_party_test_support::TwoPartyPair {
        alice_state,
        bob_state,
        ctx_bytes: context_id,
        ..
    } = scp_runtime_core::crypto::mls::two_party_test_support::stand_up_two_party(
        ctx_str,
        alice_did,
        bob_did,
        scp_runtime::domain_handlers(),
    );

    (alice_state, bob_state, context_id, alice_did.to_string())
}

/// Whether `haystack` contains `needle` as a contiguous byte run.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// The app-data seal returns the serialized MLS message itself, with no
/// second envelope inside it (ADR-002, spec 23 §23.4.1): the bytes parse
/// as an MLS message, carry no relay-derivable `context_routing_id` a
/// relay could read as a shared correlator, and Bob opens them as they
/// are, recovering the sender from the MLS credential.
#[tokio::test]
async fn app_data_seal_returns_the_mls_message_and_it_opens() {
    let ctx_str = "ctx-app-data-roundtrip";
    let (mut alice_actor, mut bob_actor, _ctx_id, alice_did) =
        setup_two_party_for_ctx_string(ctx_str);
    let clock: std::sync::Arc<dyn scp_clock::Clock> = std::sync::Arc::new(scp_clock::SystemClock);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let sender = scp_did::DID(alice_did.clone());
    let recipients = app_data_recipients(ctx_str, &alice_did);

    let wire =
        scp_runtime_core::context::shared::messaging::build_encrypted_envelope_actor_for_test(
            &clock,
            actor_crypto_mut(&mut alice_actor),
            &alice_did,
            scp_runtime_core::context::shared::messaging::EncryptedEnvelopeRequest {
                context_id: ctx_str,
                sender_did: &sender,
                payload: b"roundtrip payload",
                signer: scp_runtime_core::context::supervisor::MessageSigner::Active(
                    &scp_runtime_core::context::actor::signer::CommandSigner::local_ed25519(
                        signing_key,
                    ),
                ),
                recipients_data: &recipients,
                aad_sequence: 0,
                source_provenance: None,
                message_type: scp_protocol::envelope::inner::MessageType::Content,
            },
        )
        .await
        .unwrap();

    assert!(
        scp_mls::wire::parse_mls_message_in(&wire).is_ok(),
        "the app-data seal output is a serialized MLS message"
    );
    let context_rid = scp_protocol::context::context_routing_id(ctx_str);
    assert!(
        !contains_bytes(&wire, &context_rid),
        "the app-data seal output carries no context_routing_id"
    );

    let opened = bob_actor.open(ctx_str, &wire).unwrap();
    match opened {
        scp_protocol::context::builder::OpenResult::Application(env) => {
            assert_eq!(
                env.sender_did, alice_did,
                "sender DID recovered from the MLS credential"
            );
        }
        other => panic!("expected an Application message, got {other:?}"),
    }
}

/// A control message (Recovery type) seals to the serialized MLS message
/// as well: `seal` adds no envelope for any message type, and the
/// transport frames every payload once for the address it publishes to.
#[test]
fn control_message_seal_returns_the_mls_message() {
    // The context id must be derived from a real string: `seal` binds the
    // raw `inner.context_id` into the AEAD AAD (§9.16.1) and asserts the
    // supplied 32-byte id is its SHA-256, so a hex-of-bytes inner id (which
    // is not the preimage of `ctx_id`) would be rejected.
    let ctx_str = "ctx-control-routing-id";
    let (mut alice_actor, _bob_actor, _ctx_id, alice_did) = setup_two_party_for_ctx_string(ctx_str);
    let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);

    let params = scp_runtime_core::envelope::inner::InnerEnvelopeParams {
        version: scp_protocol::envelope::SCP_PROTOCOL_VERSION,
        context_id: ctx_str,
        sender_did: &alice_did,
        epoch: 0,
        generation: 0,
        sequence: 0,
        timestamp: 1_700_000_000,
        message_type: scp_runtime_core::envelope::inner::MessageType::Recovery,
        payload: b"recovery notification",
        provenance: None,
        signing_key_id: SigningKeyId::Active,
    };
    let inner =
        scp_runtime_core::envelope::inner::sign::create_inner_envelope_raw(&params, &sk).unwrap();

    let wire = alice_actor.seal(&alice_did, &inner).unwrap();

    assert!(
        scp_mls::wire::parse_mls_message_in(&wire).is_ok(),
        "the control seal output is a serialized MLS message"
    );
    assert!(
        scp_protocol::envelope::outer::OuterEnvelope::from_bytes(&wire).is_err(),
        "the control seal output is not an outer envelope"
    );
}
