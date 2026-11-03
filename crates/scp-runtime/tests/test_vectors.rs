//! §25 Cryptographic Test Vectors — the Rust assertions for the vectors whose
//! production builders live in `scp-protocol` and `scp-runtime`.
//!
//! Every value below, except the push vectors whose section says so, is
//! printed in `.docs/specs/25-test-vectors.md` and produced by
//! `scripts/gen-test-vectors-p256.py`. Each test feeds the spec
//! inputs to the production builder and asserts the spec output. A test also
//! hashes the spec's printed preimage and compares that digest with the
//! production result, which proves the production preimage is byte-identical
//! to the printed one.
//!
//! Vectors asserted elsewhere: V7 (`vote_signing_digest`, also here) and V27
//! (`pseudonymize_did`) in-module in `scp-protocol`, V25 (access-key
//! `build_hpke_info`) in-module in `scp-runtime`, V32 and V33 in
//! `scp-event-log/tests/test_vectors.rs`, V35 in `scp-protocol`'s
//! `sender_keys/broadcast.rs`, V36 in `scp-client-wasm`, and V41 and V42 in
//! `scp-crypto`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use std::num::NonZeroU64;
use std::time::SystemTime;

use sha2::{Digest, Sha256};

use scp_crypto::p256::{
    P256Error, P256PublicKey, P256SecretKey, SeedLabel, sign_prehash_rfc6979, verify_prehash_strict,
};
use scp_did::{
    ABSENT_BRIDGE_TARGET, BridgeEndpoint, BridgeTarget, DID, Identifier, NodeUrl, RelayService,
    SigningKeyId,
};
use scp_kel::{
    OperatorProof, ResolutionInput, ResolutionVerdict, ResolvedState, SourceExhaustion, SourceRead,
    classify,
};
use scp_protocol::context::governance::{
    GovernanceAction, VoteType, compute_proposal_id, vote_signing_digest,
};
use scp_protocol::context::outlets::interface::InterfaceOffer;
use scp_protocol::context::{
    CONTEXT_CHAIN_SEPARATOR, CONTEXT_NODE_ADDRESS_SEPARATOR, CONTEXT_OPERATOR_SEPARATOR,
    CONTEXT_RECEIPT_SEPARATOR, ContextChainEntry, ContextNodeAddress, ContextOperatorBinding,
    ContextOperatorError, ContextReceipt, FIRST_PREVIOUS_HASH, HeldBindingHash, NodeAddress,
    NodeAddressError, NodeBridge, VerifiedContextChainEntry, VerifiedContextNodeAddress,
    VerifiedContextOperatorBinding, VerifiedContextReceipt, submission_hash,
};
use scp_protocol::crypto::anchored_key::AnchoredKeyError;
use scp_protocol::crypto::canonical::{CanonicalField, canonical_hash_bytes};
use scp_protocol::crypto::sender_keys::key_protocol_verify::build_hpke_info;
use scp_protocol::discovery::push::{
    PushDeregistration, PushPlatform, PushRegistration, PushRelay,
    push_deregistration_signing_bytes, push_registration_routing_id,
    push_registration_signing_bytes, relay_service_push_routing_id, tier3_push_routing_id,
};
use scp_protocol::envelope::inner::compute_canonical_hash;
use scp_protocol::envelope::padding::{BUCKET_SIZES, pad_to_bucket, strip_padding};
use scp_protocol::envelope::{InnerEnvelopeParams, MessageType};
use scp_protocol::identity::attestation::IdentityLinkAttestation;
use scp_protocol::node::{
    NODE_BINDING_SEPARATOR, NODE_LIST_SEPARATOR, NODE_PROOF_SEPARATOR, NodeBinding,
    NodeBindingError, NodeListEntry, NodeListEntryError, NodeListError, NodeListFrameError,
    NodeListKeyClass, NodeListRecord, NodeProof, NodeProofError, VerifiedNodeBinding,
    VerifiedNodeListEntry, VerifiedNodeListRecord, check_node_list_publish, decode_node_list_frame,
    encode_node_list_frame, entries_canonical_json, node_url_hash, response_value_digest,
};
use scp_protocol::trust::capability_definition::CapabilityDefinition;
use scp_protocol::trust::capability_registry::MinCases;
use scp_protocol::trust::challenge::{
    ChallengeCase, ChallengeRequest, ChallengeResponse, ChallengeVerification, ExpectedOutput,
    TestOutput, canonical_challenge_request_bytes, canonical_challenge_response_bytes,
    canonical_challenge_verification_bytes, challenge_request_signing_digest,
    challenge_response_signing_digest, challenge_suite_digest, challenge_verification_id,
    challenge_verification_signing_digest,
};
use scp_runtime_types::sync::weeks_offline::{ResetReason, ResetRequest};

// ---------------------------------------------------------------------------
// §25.2 Reference key material
// ---------------------------------------------------------------------------

/// The §25.2 seed-to-scalar label.
const TEST_VECTOR_KEY_LABEL: &[u8] = b"SCP-TEST-VECTOR-KEY-V1";

/// §25.2 reference seeds, scalars, and public keys, in that order per key.
const REFERENCE_KEYS: [(&str, &str, &str, &str); 3] = [
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "6f0712104c3f61ba04526a822836d3f4a13be12e09a8c3c7586b2da0c795998b",
        "033b1cac23f45cf1cdfdf0b32f8f777b99166c1b69649c2295b1517883d47f3027",
        "043b1cac23f45cf1cdfdf0b32f8f777b99166c1b69649c2295b1517883d47f3027471695574e78728df503a0c21dd1da9f7b77252d8398527a1b2177c78224f051",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "0fed5549df222a5cf0b537e423fbd60875c6fb2b334b381a0c0a6c89eae9ac6a",
        "0223702a648232f2d00713de9289753c2fbd4c4efa7e1e33905e3723a412b20aea",
        "0423702a648232f2d00713de9289753c2fbd4c4efa7e1e33905e3723a412b20aead0992a08064d996d9268dc511c7430f3a4e614871d4a888b52a8dbecb56d6da6",
    ),
    (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "55118deda48fbb900efe9692e644dc5971211c8d3dfcc50f117d842c6056be4f",
        "026fc6523b7b1e22ff3fbce8740cfbb7cbc816501864bf40f683db69c860d1a670",
        "046fc6523b7b1e22ff3fbce8740cfbb7cbc816501864bf40f683db69c860d1a6700192d543b6d5d6b3d7990f4463d2f0692bcb7bdbaf3b1ee8f4465dd888323df0",
    ),
];

/// SHA-256(0x00) — the absent optional field sentinel (§9.5.1).
const ABSENT_SENTINEL_HEX: &str =
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d";

/// §25.1 fixture identifiers, each `SHA-256("SCP test vector identifier <role>")`
/// in the `scp:` text form.
const ID_SENDER: &str = "scp:hv6a3pfs4qcibthh3kaekzhfo2xxqlfnie7ups6hvcsqsmkipyla";
const ID_SYNC_MEMBER: &str = "scp:ufveadjgygwpujfense3z6e6jwthxmug26owvhrjnvzdfjkjrq5q";
const ID_PROPOSER: &str = "scp:flrkfgy6ehrwj35ay57p36ldffarlcmh2mj7smr7rauyvpreyqfa";
const ID_NEW_MEMBER: &str = "scp:ykcz3x3dycntc6lkxzbe3nixvd7w5c37riaowlh26lczdnc5vmja";
const ID_HPKE_SENDER: &str = "scp:jx35aojrkpxu2pjy7k6v6blpsotz5iakm7yui2t3rc6lmthfcbpa";
const ID_ISSUER: &str = "scp:mhe6nmpij74wrgb46ngrakeetnlycmnfmcgppkfqqufyl7kkl3ia";
const ID_SUBJECT: &str = "scp:ktarg6aqtsju6mh2ws3hk7t5kmsvmckq7d5eqwsmaw5di3e3p4ta";
const ID_VERIFIER: &str = "scp:vsrmsobf2uzejsbdaag3txwauasjrpnt5wlkulhahbbfwtdfaapa";
const ID_DEFINER: &str = "scp:tfgiiao36zlseo2tzfoi32knfx6topped3qloxcsube5gdvfrqgq";
const ID_LEAF_ATTESTER: &str = "scp:gomjxlxjt4kesb5fghb6tpykrvhsxdduwwlo3uwgmvh2jhoqvjyq";

/// The P-256 group order `n`.
const P256_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

fn unhex32(s: &str) -> [u8; 32] {
    unhex(s).try_into().unwrap()
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn reference_key() -> P256SecretKey {
    P256SecretKey::from_seed(SeedLabel::TestVectorKey, &unhex32(REFERENCE_KEYS[0].0))
}

/// Asserts that the spec's printed preimage is `expected_len` bytes and hashes
/// to `digest`, the value the production builder returned.
fn assert_spec_preimage(label: &str, preimage_hex: &str, expected_len: usize, digest: &[u8]) {
    let preimage = unhex(preimage_hex);
    assert_eq!(preimage.len(), expected_len, "{label}: preimage length");
    assert_eq!(
        sha256(&preimage).as_slice(),
        digest,
        "{label}: production hash differs from SHA-256 of the spec preimage"
    );
}

/// Replaces `s` with `n − s`, which turns a low-`s` signature into the
/// high-`s` form of the same signature.
fn high_s_form(signature: &[u8; 64]) -> [u8; 64] {
    let mut out = *signature;
    let mut borrow = 0u16;
    for i in (0..32).rev() {
        let minuend = u16::from(P256_ORDER[i]);
        let subtrahend = u16::from(signature[32 + i]) + borrow;
        let (diff, next_borrow) = if minuend >= subtrahend {
            (minuend - subtrahend, 0)
        } else {
            (minuend + 0x100 - subtrahend, 1)
        };
        out[32 + i] = diff.to_le_bytes()[0];
        borrow = next_borrow;
    }
    assert_eq!(borrow, 0, "s must be below n");
    out
}

/// §25.17 step 5 for one signature: RFC 6979 over the canonical hash with the
/// §25.2 reference key reproduces the printed 64 bytes, strict verification
/// accepts them, rejects their high-`s` form, and rejects them over a changed
/// digest.
///
/// This asserts the signature through the scp-crypto P-256 primitives. The
/// production envelope, vote, reset-request, and attestation signers still
/// sign with Ed25519; slice S12 of the identity plan wires the P-256 signer
/// into those paths, and its tests assert these bytes through them.
fn assert_reference_signature(label: &str, digest: &[u8; 32], expected_hex: &str) {
    let key = reference_key();
    let signature = sign_prehash_rfc6979(&key, digest).unwrap();
    assert_eq!(
        hex::encode(signature),
        expected_hex,
        "{label}: signature bytes"
    );

    let public = P256PublicKey::from_sec1(&unhex(REFERENCE_KEYS[0].2)).unwrap();
    verify_prehash_strict(&public, digest, &signature)
        .unwrap_or_else(|e| panic!("{label}: strict verification rejected: {e}"));
    assert_eq!(
        verify_prehash_strict(&public, digest, &high_s_form(&signature)),
        Err(P256Error::HighS),
        "{label}: high-s form must be rejected"
    );
    let mut other_digest = *digest;
    other_digest[0] ^= 0x01;
    assert_eq!(
        verify_prehash_strict(&public, &other_digest, &signature),
        Err(P256Error::VerificationFailed),
        "{label}: signature must not verify over another digest"
    );
}

// ---------------------------------------------------------------------------
// §25.2 Reference key derivation
// ---------------------------------------------------------------------------

#[test]
fn vector_0_reference_keys_derive_from_seeds() {
    assert_eq!(SeedLabel::TestVectorKey.as_bytes(), TEST_VECTOR_KEY_LABEL);
    for (seed, scalar, compressed, uncompressed) in REFERENCE_KEYS {
        let key = P256SecretKey::from_seed(SeedLabel::TestVectorKey, &unhex32(seed));
        assert_eq!(
            hex::encode(*key.to_scalar_bytes()),
            scalar,
            "scalar of seed {seed}"
        );
        let public = key.public_key();
        assert_eq!(hex::encode(public.to_compressed()), compressed);
        assert_eq!(hex::encode(public.to_uncompressed()), uncompressed);
    }
}

#[test]
fn high_s_form_is_rejected_and_its_normalization_accepted() {
    // Control for `high_s_form`: the RFC 6979 signer emits low `s`, and the
    // helper's output must differ from it and carry the same `r`.
    let digest = sha256(b"high-s control");
    let signature = sign_prehash_rfc6979(&reference_key(), &digest).unwrap();
    let high = high_s_form(&signature);
    assert_ne!(high, signature);
    assert_eq!(high[..32], signature[..32]);
    assert_eq!(high_s_form(&high), signature, "n - (n - s) = s");
}

// ---------------------------------------------------------------------------
// §25.3 Canonical hash construction
// ---------------------------------------------------------------------------

#[test]
fn vector_1_domain_separator_encoding() {
    assert_eq!(
        hex::encode(b"SCP-INNER-ENVELOPE-V1:"),
        "5343502d494e4e45522d454e56454c4f50452d56313a"
    );
}

#[test]
fn vector_2_variable_length_field_encoding() {
    let encoded = canonical_hash_bytes(
        b"",
        &[CanonicalField::VarBytes(SigningKeyId::Active.as_bytes())],
    )
    .unwrap();
    assert_eq!(hex::encode(encoded), "0000000723616374697665");
}

#[test]
fn vector_3_fixed_length_u64_encoding() {
    let encoded = canonical_hash_bytes(b"", &[CanonicalField::U64(1_700_000_000)]).unwrap();
    assert_eq!(hex::encode(encoded), "000000006553f100");
}

#[test]
fn vector_4_absent_sentinel() {
    assert_eq!(hex::encode(sha256(&[0x00])), ABSENT_SENTINEL_HEX);
    let encoded = canonical_hash_bytes(b"", &[CanonicalField::Absent]).unwrap();
    assert_eq!(hex::encode(encoded), ABSENT_SENTINEL_HEX);
}

// ---------------------------------------------------------------------------
// §25.4 InnerEnvelope signing
// ---------------------------------------------------------------------------

const fn vector_5_params() -> InnerEnvelopeParams<'static> {
    InnerEnvelopeParams {
        version: 256,
        context_id: "test-context-01",
        sender_did: ID_SENDER,
        epoch: 1,
        generation: 0,
        sequence: 0,
        timestamp: 1_700_000_000,
        message_type: MessageType::Content,
        payload: b"hello world",
        provenance: None,
        signing_key_id: SigningKeyId::Active,
    }
}

#[test]
fn vector_5_minimal_inner_envelope() {
    let payload_hash = sha256(b"hello world");
    assert_eq!(
        hex::encode(payload_hash),
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    );
    let hash = compute_canonical_hash(
        &vector_5_params(),
        &payload_hash,
        &unhex32(ABSENT_SENTINEL_HEX),
    )
    .unwrap();
    assert_eq!(
        hex::encode(hash),
        "cdc77fc58cb85548ba41ba1f5f074182a6af339847af091bf33020eb9fefab59"
    );
    assert_spec_preimage(
        "vector 5",
        "5343502d494e4e45522d454e56454c4f50452d56313a0100000000000f746573742d636f6e746578742d3031000000387363703a68763661337066733471636962746868336b61656b7a68666f327878716c666e696537757073366876637371736d6b6970796c61000000000000000100000000000000000000000000000000000000006553f10000000020b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9000000206e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d0000000723616374697665",
        219,
        &hash,
    );
    assert_reference_signature(
        "vector 5",
        &hash,
        "e497dc3efd4154502252aefe673479166c0550d7b85255caa9dacab08178eb2109bb6c4226340c1bed189e7c5c187ae54f484dd174954a6debd301823116bf46",
    );
}

#[test]
fn vector_6_inner_envelope_with_provenance() {
    let hash = compute_canonical_hash(
        &vector_5_params(),
        &sha256(b"hello world"),
        &unhex32("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"),
    )
    .unwrap();
    assert_eq!(
        hex::encode(hash),
        "dfb243d4574dec6c798782906e381ed875f18b9b2b14a8bd87d0b2e8df1e1c1b"
    );
    assert_spec_preimage(
        "vector 6",
        "5343502d494e4e45522d454e56454c4f50452d56313a0100000000000f746573742d636f6e746578742d3031000000387363703a68763661337066733471636962746868336b61656b7a68666f327878716c666e696537757073366876637371736d6b6970796c61000000000000000100000000000000000000000000000000000000006553f10000000020b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde900000020abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567890000000723616374697665",
        219,
        &hash,
    );
    assert_reference_signature(
        "vector 6",
        &hash,
        "5a52a4b0e87965a109a82439cd905eae241543be579e42d963713feae3f312406c2b0fdc15deaf5d3d40b41990f147c4c63cd702e16d2e656386bcf922a97203",
    );
}

// ---------------------------------------------------------------------------
// §25.5 Vote signing
// ---------------------------------------------------------------------------

/// Asserts the printed preimage, that the production `vote_signing_digest`
/// (the digest a voter's signer signs) equals its hash, and the signature over
/// that hash.
#[test]
fn vector_7_vote_signature() {
    let hash = unhex32("3a0c35742f6ddd8c3a935f924ede5ca85ad905c1312ca99e18eb618223769c67");
    let proposal_id = unhex32("0102030405060708091011121314151617181920212223242526272829303132");
    assert_eq!(
        vote_signing_digest(
            &proposal_id,
            "scp:bbxkpyevxkco6odwvddqgluf3ug2a3qj3lacn4olgxtpshuk4a6a",
            &VoteType::Approve,
            1_700_000_000,
        )
        .expect("vote digest"),
        hash,
        "vector 7: production vote digest drift"
    );
    assert_spec_preimage(
        "vector 7",
        "5343502d564f54452d56313a0102030405060708091011121314151617181920212223242526272829303132000000387363703a6262786b70796576786b636f366f647776646471676c7566337567326133716a336c61636e346f6c677874707368756b346136610000000922417070726f766522000000006553f100",
        125,
        &hash,
    );
    assert_reference_signature(
        "vector 7",
        &hash,
        "a67326a389ccc007e8980df47d08fd7c650967dbcda44518d161515a04f4df986a6255182635d282d4c77a9ae8948a8986ab48235ef93d377038454a341ed891",
    );
}

// ---------------------------------------------------------------------------
// §25.6 Reset request signing
// ---------------------------------------------------------------------------

#[test]
fn vector_8_reset_request() {
    let request = ResetRequest {
        context_id: "sync-test-context".to_owned(),
        member_did: DID::from(ID_SYNC_MEMBER),
        last_known_epoch: 42,
        reason: ResetReason::ExtendedOffline {
            offline_duration_secs: 691_200,
        },
        nonce: unhex("01020304050607080910111213141516")
            .try_into()
            .unwrap(),
        timestamp: 1_700_000_000,
        signature: Vec::new(),
    };
    let hash = request.canonical_hash().unwrap();
    assert_eq!(
        hex::encode(hash),
        "1c0dc57c74a1b6f1072d65aa87c8d2de3ed3ed921c22d6754e5d6f8137ae8b6e"
    );
    assert_spec_preimage(
        "vector 8",
        "5343502d52455345542d524551554553542d56313a0000001173796e632d746573742d636f6e74657874000000387363703a7566766561646a6779677770756a66656e7365337a3665366a777468786d756732366f777668726a6e767a64666a6b6a72713571000000000000002a00000019657874656e646564206f66666c696e6520283820646179732901020304050607080910111213141516000000006553f100",
        163,
        &hash,
    );
    assert_reference_signature(
        "vector 8",
        &hash,
        "adfb7ae6be806d4e7bef5f97a7e996d5b071e31d488ca331b144928119cd137a21071a52305eea42a704daef9cc498e09eec8dec0720ab76bcdb7d88f85dfed2",
    );
}

// ---------------------------------------------------------------------------
// §25.7 Envelope padding
// ---------------------------------------------------------------------------

#[test]
fn vector_9_empty_payload_padding() {
    let padded = pad_to_bucket(b"").unwrap();
    assert_eq!(padded.len(), 256);
    assert_eq!(&padded[252..256], &0u32.to_be_bytes());
    assert!(padded[..252].iter().all(|&b| b == 0));
}

#[test]
fn vector_10_small_payload_padding() {
    let payload = b"hello";
    let padded = pad_to_bucket(payload).unwrap();
    assert_eq!(padded.len(), 256);
    assert_eq!(&padded[..5], b"hello");
    assert!(padded[5..252].iter().all(|&b| b == 0));
    assert_eq!(&padded[252..256], &5u32.to_be_bytes());
    assert_eq!(strip_padding(&padded).unwrap(), payload);
}

#[test]
fn vector_11_exact_bucket_boundary() {
    let payload = vec![0xAB; 252];
    let padded = pad_to_bucket(&payload).unwrap();
    assert_eq!(padded.len(), 256);
    assert_eq!(&padded[..252], payload.as_slice());
    assert_eq!(&padded[252..256], &252u32.to_be_bytes());
    assert_eq!(strip_padding(&padded).unwrap(), payload);
}

#[test]
fn vector_12_one_byte_over_boundary() {
    let payload = vec![0xAB; 253];
    let padded = pad_to_bucket(&payload).unwrap();
    assert_eq!(padded.len(), 1024);
    assert_eq!(&padded[..253], payload.as_slice());
    assert!(padded[253..1020].iter().all(|&b| b == 0));
    assert_eq!(&padded[1020..1024], &253u32.to_be_bytes());
    assert_eq!(strip_padding(&padded).unwrap(), payload);
}

#[test]
fn vector_13_maximum_payload() {
    let payload = vec![0x42; 262_140];
    let padded = pad_to_bucket(&payload).unwrap();
    assert_eq!(padded.len(), 262_144);
    assert_eq!(&padded[..262_140], payload.as_slice());
    assert_eq!(&padded[262_140..262_144], &262_140u32.to_be_bytes());
    assert_eq!(strip_padding(&padded).unwrap().len(), payload.len());
}

#[test]
fn vector_14_payload_too_large() {
    assert!(
        pad_to_bucket(&vec![0x00; 262_141]).is_err(),
        "payload exceeding max bucket must return error"
    );
}

/// Bucket sizes are protocol invariants (ADR-043): an implementation with
/// other sizes is distinguishable by ciphertext size.
#[test]
fn padding_bucket_sizes_are_correct() {
    assert_eq!(BUCKET_SIZES, [256, 1024, 4096, 16384, 65536, 262_144]);
}

// ---------------------------------------------------------------------------
// §25.8 Merkle tree (RFC 6962)
// ---------------------------------------------------------------------------

fn leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(data);
    hasher.finalize().into()
}

fn interior_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

#[test]
fn vector_15_empty_merkle_tree() {
    assert_eq!(
        hex::encode(sha256(b"")),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn vector_16_single_leaf() {
    assert_eq!(
        hex::encode(leaf_hash(b"Hello")),
        "90b626dbb1e994c962942db2b3b16d97c63f679912a176bb96f4e308c213005b"
    );
}

#[test]
fn vector_17_two_leaves() {
    let leaf_1 = leaf_hash(b"Event1");
    let leaf_2 = leaf_hash(b"Event2");
    assert_eq!(
        hex::encode(leaf_1),
        "00d9ea40d70522a7d0aa41e2708afd5dc148a4dcc26011d598cbc28cdbde306f"
    );
    assert_eq!(
        hex::encode(leaf_2),
        "7a7b6da2a00d46f75c01d0c5a33cb62e99caa7f0ebbd084a169a00874751e7a3"
    );
    assert_eq!(
        hex::encode(interior_hash(&leaf_1, &leaf_2)),
        "9f7a0b4b3965ce3eb4dda7c7c56bc9f7fb2c627d5120692d4ff8e531920ebbf9"
    );
}

#[test]
fn vector_18_three_leaves_unbalanced() {
    let [a, b, c] = [b"A", b"B", b"C"].map(|d| leaf_hash(d));
    let interior_1 = interior_hash(&a, &b);
    assert_eq!(
        hex::encode(a),
        "c00b4d3c929cb5cc316691ed4636f634576f2c9b2954767234c5274e9dde185d"
    );
    assert_eq!(
        hex::encode(b),
        "87afe6086fe4571e37657e76281301f189c75ebae1d2eaafb56d578067a1d95e"
    );
    assert_eq!(
        hex::encode(c),
        "b563a5e69628743929eddec0ccfeb0745c39577e12a72e84915edd6633cb97f2"
    );
    assert_eq!(
        hex::encode(interior_1),
        "ed692f01f7f6c46930d7ad8f9adad3f9f38b7379cf6a8d2f399a0ba1e914fe25"
    );
    assert_eq!(
        hex::encode(interior_hash(&interior_1, &c)),
        "961d2e2be20f538ffdf56962a86d1bd165498f222684ee4c5e02c1e9f852adc5"
    );
}

#[test]
fn vector_19_four_leaves_balanced() {
    let [a, b, c, d] = [b"A", b"B", b"C", b"D"].map(|x| leaf_hash(x));
    let left = interior_hash(&a, &b);
    let right = interior_hash(&c, &d);
    assert_eq!(
        hex::encode(d),
        "08a2afecc9feaef6737f055c177a56a363d28a78d7b259b8c5f66b32174f2e7d"
    );
    assert_eq!(
        hex::encode(left),
        "ed692f01f7f6c46930d7ad8f9adad3f9f38b7379cf6a8d2f399a0ba1e914fe25"
    );
    assert_eq!(
        hex::encode(right),
        "d62c77efa9be96355bb8b07aefc985914377de5aec1287998c9a10f11cd8d075"
    );
    assert_eq!(
        hex::encode(interior_hash(&left, &right)),
        "5c8dc617d287a4297eb2bcb81b37644b5138e57ad461c657db152109e3fc9fca"
    );
}

// ---------------------------------------------------------------------------
// §25.11 Proposal ID
// ---------------------------------------------------------------------------

#[test]
fn vector_23_governance_proposal_id() {
    let action = GovernanceAction::AddMember {
        did: DID::from(ID_NEW_MEMBER),
        role: "member".to_owned(),
    };
    let action_bytes = scp_protocol::jcs::to_vec(&action).unwrap();
    assert_eq!(
        hex::encode(&action_bytes),
        "7b224164644d656d626572223a7b22646964223a227363703a796b637a3378336479636e7463366c6b787a6265336e697876643777356333377269616f776c6832366c637a646e6335766d6a61222c22726f6c65223a226d656d626572227d7d"
    );
    assert_eq!(action_bytes.len(), 96);

    let proposal_id = compute_proposal_id(
        "gov-proposal-context",
        &DID::from(ID_PROPOSER),
        &action_bytes,
        1_700_000_000,
    );
    assert_eq!(
        hex::encode(proposal_id),
        "15ff55609885bc70e5c7828697ce978af7c09b8d12d058fee276822d1d34e7f6"
    );
    assert_spec_preimage(
        "vector 23",
        "5343502d50524f504f53414c2d56313a00000014676f762d70726f706f73616c2d636f6e74657874000000387363703a666c726b66677936656872776a3335617935377033366c64666661726c636d68326d6a37736d7237726175797670726579716661000000607b224164644d656d626572223a7b22646964223a227363703a796b637a3378336479636e7463366c6b787a6265336e697876643777356333377269616f776c6832366c637a646e6335766d6a61222c22726f6c65223a226d656d626572227d7d000000006553f100",
        208,
        &proposal_id,
    );
}

// ---------------------------------------------------------------------------
// §25.12 HPKE info strings
// ---------------------------------------------------------------------------

/// Vector 24 through the production sender-key builder. Vector 25's
/// access-key builder is private to `scp-runtime` and asserted in-module
/// (`spec_25_vector_25_access_key_hpke_info`).
#[test]
fn vector_24_sender_key_hpke_info() {
    let info = build_hpke_info("hpke-test-context", ID_HPKE_SENDER, 42);
    assert_eq!(info.len(), 106);
    assert_eq!(
        hex::encode(info),
        "7363702d73656e6465722d6b65792d76310000001168706b652d746573742d636f6e74657874000000387363703a6a783335616f6a726b70787532706a79376b367636626c70736f747a3569616b6d377975693274337263366c6d74686663627061000000000000002a"
    );
}

// ---------------------------------------------------------------------------
// §25.13 Identity link attestation signing
// ---------------------------------------------------------------------------

#[test]
fn vector_26_identity_link_attestation() {
    use scp_protocol::identity::attestation::{
        ATTESTATION_TYPE_IDENTITY_LINK, AttestationClaim, AttestationEvidence, VerificationMethod,
    };
    use scp_protocol::trust::attestation::RevocationStatus;
    use std::borrow::Cow;

    let issuer = DID::from(ID_ISSUER);
    let attestation = IdentityLinkAttestation {
        id: "att-001".to_owned(),
        attestation_type: Cow::Borrowed(ATTESTATION_TYPE_IDENTITY_LINK),
        issuer: issuer.clone(),
        subject: issuer,
        issued_at: 1_700_000_000,
        expires_at: None,
        claim: AttestationClaim::new("google.com".to_owned(), "alice@gmail.com".to_owned(), None),
        evidence: AttestationEvidence {
            method: VerificationMethod::Oauth,
            proof: r#"{"provider":"google.com","subject_id":"12345","verified_at":1700000000}"#
                .to_owned(),
            verified_at: 1_700_000_000,
            verifier_did: None,
        },
        revocation_status: RevocationStatus::Active,
        signature: Vec::new(),
    };

    let hash = attestation.canonical_signing_bytes().unwrap();
    assert_eq!(
        hex::encode(&hash),
        "7c30340a9e30605a1569b44e5f5bf9902b7b79246f9984c858c1d5b13a8bd66f"
    );
    assert_spec_preimage(
        "vector 26",
        "5343502d4944454e544954592d4c494e4b2d4154544553544154494f4e2d56313a000000076174742d3030310000000d6964656e746974795f6c696e6b000000387363703a6d6865366e6d70696a37347772676234366e6772616b6565746e6c79636d6e666d636770706b6671717566796c376b6b6c336961000000387363703a6d6865366e6d70696a37347772676234366e6772616b6565746e6c79636d6e666d636770706b6671717566796c376b6b6c336961000000006553f1006e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d0000005083a8706c6174666f726daa676f6f676c652e636f6daf706c6174666f726d5f68616e646c65af616c69636540676d61696c2e636f6da96c696e6b5f74797065b073656c665f6174746573746174696f6e0000006e83a66d6574686f64a56f61757468a570726f6f66d9477b2270726f7669646572223a22676f6f676c652e636f6d222c227375626a6563745f6964223a223132333435222c2276657269666965645f6174223a313730303030303030307dab76657269666965645f6174ce6553f10000000007a6416374697665",
        430,
        &hash,
    );
    assert_reference_signature(
        "vector 26",
        &hash.try_into().unwrap(),
        "060e1ff0cd840e9fe7257d86f1702d15a19ae2fe26c78341903ec1e705ceeb2945b5917b8a8b400a4f3178267313f3573ab2556d4248bf6dc7bbe88ecd297318",
    );
}

// ---------------------------------------------------------------------------
// §25.15 Outlet interface offer ID
// ---------------------------------------------------------------------------

#[test]
fn vector_28_outlet_interface_offer_id() {
    let offer_id = InterfaceOffer::compute_offer_id(
        "source-ctx-01",
        "outlet-abc123",
        "target-ctx-02",
        1_700_000_000,
    );
    assert_eq!(
        hex::encode(offer_id),
        "ea9ce09b497405e8c160c8d0d57067c726092866f6d1ec541e8e6081a5328733"
    );
}

// ---------------------------------------------------------------------------
// §25.16 Attestation ID
// ---------------------------------------------------------------------------

#[test]
fn vector_29_attestation_id() {
    let attestation_id = IdentityLinkAttestation::compute_id(
        &DID::from(ID_ISSUER),
        "google.com",
        "alice@gmail.com",
        1_700_000_000,
    );
    assert_eq!(
        attestation_id,
        "e742f0c58ad19c527626b51608d3d8ef2a4093188fa98f1a70041f7b59044ce2"
    );
}

// ---------------------------------------------------------------------------
// §25.20 Trust attestation signing
// ---------------------------------------------------------------------------

fn vector_34_attestation() -> scp_protocol::trust::attestation::Attestation {
    use scp_protocol::trust::AttestationType;
    use scp_protocol::trust::attestation::{Attestation, RevocationStatus};

    // The claim's keys are inserted out of order on purpose: RFC 8785 sorts
    // them, so insertion order must not reach the preimage.
    Attestation {
        id: "att-trust-001".to_owned(),
        attestation_type: AttestationType::Endorsement,
        issuer: ID_ISSUER.into(),
        subject: ID_SUBJECT.into(),
        claim: serde_json::json!({"score": 42, "level": "gold"}),
        evidence: None,
        issued_at: 1_700_000_000,
        expires_at: None,
        renewal_interval: None,
        renewed_at: None,
        revocation_status: RevocationStatus::Active,
        signature: Vec::new(),
    }
}

#[test]
fn vector_34_trust_attestation_signature() {
    use scp_protocol::trust::attestation::canonical_attestation_bytes;

    let hash = canonical_attestation_bytes(&vector_34_attestation()).unwrap();
    assert_eq!(
        hex::encode(&hash),
        "e1ccf47b4b1a50bd91342c14df9630a5abc8cf51c2dbe1ad7099348d9fe6d018"
    );
    assert_spec_preimage(
        "vector 34",
        "5343502d4154544553544154494f4e2d56313a0000000d6174742d74727573742d3030310004000000387363703a6d6865366e6d70696a37347772676234366e6772616b6565746e6c79636d6e666d636770706b6671717566796c376b6b6c336961000000387363703a6b7461726736617174736a75366d6832777333686b3774356b6d73766d636b71376435657177736d6177356469336533703474610000001b7b226c6576656c223a22676f6c64222c2273636f7265223a34327d6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d000000006553f1006e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d00000007a6416374697665",
        272,
        &hash,
    );
    assert_reference_signature(
        "vector 34",
        &hash.try_into().unwrap(),
        "c09daa8f076cfc13d93b9a1a6ae51d3d03c335ca9e62a120d1d3f55050e9884a7dd4eb8e302a9c542acee0310e3626032fcd2c825ddd22797f3d5be4e189bf1a",
    );
}

/// Wiring test, not a §25 vector: the production `verify_attestation`
/// accepts a signature over the Vector 34 canonical hash. Production
/// attestation verification is still Ed25519 (rule B of the identity plan)
/// until slice S12 moves it to P-256, so this signs with the RFC 8032 §7.1
/// test-vector-1 Ed25519 key.
#[test]
fn trust_attestation_verify_round_trip_rule_b_ed25519() {
    use ed25519_dalek::Signer;
    use scp_clock::TestClock;
    use scp_protocol::trust::TrustError;
    use scp_protocol::trust::attestation::{
        ActiveKeyResolver, AttestationRevocationChecker, canonical_attestation_bytes,
        verify_attestation,
    };

    /// This vector carries no revocation list, so the list names nothing.
    struct EmptyRevocationList;
    impl AttestationRevocationChecker for EmptyRevocationList {
        fn check_revocation(&self, _id: &str, _issuer: &scp_did::DID) -> Option<u64> {
            None
        }
    }

    struct Resolver(Vec<u8>);
    impl ActiveKeyResolver for Resolver {
        fn resolve_active_key(&self, _did: &str) -> Result<Vec<u8>, TrustError> {
            Ok(self.0.clone())
        }
    }

    // Rule B: the RFC 8032 §7.1 test-vector-1 Ed25519 seed, which is also
    // the §25.2 P-256 reference seed 1.
    let rule_b_ed25519_key = ed25519_dalek::SigningKey::from_bytes(&unhex32(REFERENCE_KEYS[0].0));
    let resolver = Resolver(rule_b_ed25519_key.verifying_key().to_bytes().to_vec());

    let mut signed = vector_34_attestation();
    let hash = canonical_attestation_bytes(&signed).unwrap();
    signed.signature = rule_b_ed25519_key.sign(&hash).to_bytes().to_vec();
    let clock = TestClock::new(1_700_000_001);
    verify_attestation(&signed, &resolver, &clock, &EmptyRevocationList)
        .expect("signature must verify");

    let mut tampered = signed;
    tampered.subject = ID_ISSUER.into();
    assert!(
        verify_attestation(&tampered, &resolver, &clock, &EmptyRevocationList).is_err(),
        "a changed subject must invalidate the signature"
    );
}

// ---------------------------------------------------------------------------
// §25.23 KeyPackage attestation
// ---------------------------------------------------------------------------

/// §25.23 Vector 37, asserted over the spec bytes with primitives: the four
/// bound keys derive from their stated seeds, the preimage assembles from the
/// stated fields, and the signature and `0xFF03` extension body match.
///
/// `scp-mls` asserts the same preimage, hash and body through the production
/// `KeyPackageAttestation` (`keypackage_attestation.rs`,
/// `spec_vector37_matches`); this test pins the key derivations from their
/// seeds.
#[test]
fn vector37_keypackage_attestation() {
    let derived = |seed: u8| {
        P256SecretKey::from_seed(SeedLabel::TestVectorKey, &[seed; 32])
            .public_key()
            .to_uncompressed()
    };
    let leaf_signature_key = unhex(REFERENCE_KEYS[1].3);
    assert_eq!(
        hex::encode(&leaf_signature_key),
        "0423702a648232f2d00713de9289753c2fbd4c4efa7e1e33905e3723a412b20aead0992a08064d996d9268dc511c7430f3a4e614871d4a888b52a8dbecb56d6da6"
    );
    let leaf_encryption_key = derived(0x33);
    let init_key = derived(0x11);
    let wrapping_key = derived(0x22);
    assert_eq!(
        hex::encode(leaf_encryption_key),
        "04bb9fe4749210aad657fb3937fa97a0d79c976c442c54176ccce88477e1b32f304661cb77defd365843a4d43584afc760fed0d9a889d9cb3dd155986b446f4550"
    );
    assert_eq!(
        hex::encode(init_key),
        "041f75a6a31cc4516a2eb0b28511c45160b976b44e8c31ec377b0c2cb67b05f0ad3195794c4fc38b105bd5f5e1239a3c73feb58bd815cbfd2fe049c084f7f88a8a"
    );
    assert_eq!(
        hex::encode(wrapping_key),
        "04ff08966117691da4f3f0a3bbc4a63cab7193008d316127821b1e09b9e2aef925eaa5de2932cc294a2cc58f36e31a9a245f67404ad14d142d0e423901aa44cac3"
    );

    let mut fields = Vec::new();
    fields.extend_from_slice(&(ID_LEAF_ATTESTER.len() as u32).to_be_bytes());
    fields.extend_from_slice(ID_LEAF_ATTESTER.as_bytes());
    fields.extend_from_slice(&leaf_signature_key);
    fields.extend_from_slice(&leaf_encryption_key);
    fields.extend_from_slice(&init_key);
    fields.extend_from_slice(&wrapping_key);
    fields.extend_from_slice(&7u32.to_be_bytes());
    fields.extend_from_slice(b"#active");
    fields.extend_from_slice(&1_700_000_000u64.to_be_bytes());
    fields.extend_from_slice(&1_700_086_400u64.to_be_bytes());
    let mut preimage = b"SCP-KEYPACKAGE-ATTESTATION-V1:".to_vec();
    preimage.extend_from_slice(&fields);

    assert_eq!(preimage.len(), 377);
    assert_eq!(
        hex::encode(&preimage),
        "5343502d4b45595041434b4147452d4154544553544154494f4e2d56313a000000387363703a676f6d6a786c786a74346b6573623566676862367470796b727668737864647577776c6f337577676d7668326a686f71766a79710423702a648232f2d00713de9289753c2fbd4c4efa7e1e33905e3723a412b20aead0992a08064d996d9268dc511c7430f3a4e614871d4a888b52a8dbecb56d6da604bb9fe4749210aad657fb3937fa97a0d79c976c442c54176ccce88477e1b32f304661cb77defd365843a4d43584afc760fed0d9a889d9cb3dd155986b446f4550041f75a6a31cc4516a2eb0b28511c45160b976b44e8c31ec377b0c2cb67b05f0ad3195794c4fc38b105bd5f5e1239a3c73feb58bd815cbfd2fe049c084f7f88a8a04ff08966117691da4f3f0a3bbc4a63cab7193008d316127821b1e09b9e2aef925eaa5de2932cc294a2cc58f36e31a9a245f67404ad14d142d0e423901aa44cac30000000723616374697665000000006553f1000000000065554280"
    );
    let hash = sha256(&preimage);
    assert_eq!(
        hex::encode(hash),
        "f3e2825b6d0534827fec7a6b196b729578ef47be0c0847f6e8879cf5242aa4ad"
    );
    assert_reference_signature(
        "vector 37",
        &hash,
        "e84f59744b0fba5ebc162f26a59d027694c1fae7c73dcdeb8d776e357bbf12632abea2a97205d75ca50e3914eec8af68f7315e27dd6f9296136e75ecb044ff24",
    );

    let signature = sign_prehash_rfc6979(&reference_key(), &hash).unwrap();
    let mut body = fields;
    body.extend_from_slice(&signature);
    assert_eq!(body.len(), 411);
    assert_eq!(
        hex::encode(body),
        "000000387363703a676f6d6a786c786a74346b6573623566676862367470796b727668737864647577776c6f337577676d7668326a686f71766a79710423702a648232f2d00713de9289753c2fbd4c4efa7e1e33905e3723a412b20aead0992a08064d996d9268dc511c7430f3a4e614871d4a888b52a8dbecb56d6da604bb9fe4749210aad657fb3937fa97a0d79c976c442c54176ccce88477e1b32f304661cb77defd365843a4d43584afc760fed0d9a889d9cb3dd155986b446f4550041f75a6a31cc4516a2eb0b28511c45160b976b44e8c31ec377b0c2cb67b05f0ad3195794c4fc38b105bd5f5e1239a3c73feb58bd815cbfd2fe049c084f7f88a8a04ff08966117691da4f3f0a3bbc4a63cab7193008d316127821b1e09b9e2aef925eaa5de2932cc294a2cc58f36e31a9a245f67404ad14d142d0e423901aa44cac30000000723616374697665000000006553f1000000000065554280e84f59744b0fba5ebc162f26a59d027694c1fae7c73dcdeb8d776e357bbf12632abea2a97205d75ca50e3914eec8af68f7315e27dd6f9296136e75ecb044ff24"
    );
}

// ---------------------------------------------------------------------------
// Push preimages and push routing IDs (§9.5.2, §9.18.2; §25.28 Vector 70)
// ---------------------------------------------------------------------------
//
// `scripts/gen-test-vectors-p256.py` computes these values from the §9.5.2
// tables outside the production builder, and §25.28 Vector 70 prints them.
// Each test checks the production bytes against both the golden hex and a
// layout the test assembles byte by byte. The registrant is the §25.1 sender
// fixture in its 56-byte `scp:` text form, the encoding §9.5.2 fixes, so the
// vectors stay valid when SCP-315 retypes the field. The bridge entry is
// Vector 48's entry 3.

const PUSH_TOKEN_HEX: &str = "0123456789abcdef";
const PUSH_TIMESTAMP: u64 = 1_700_000_000;
const PUSH_DEREGISTER_TIMESTAMP: u64 = 1_700_000_300;
const PUSH_RELAY_A: &str = "wss://relay.example";
const PUSH_RELAY_B: &str = "wss://relay.example/scp/v1";

const PUSH_REGISTER_A_HEX: &str = "5343502d505553482d52454749535445522d56313a000000387363703a68763661337066733471636962746868336b61656b7a68666f327878716c666e696537757073366876637371736d6b6970796c6101000000080123456789abcdef00000002f8f7da66a5b0f0d9466a2e1d8145fc72717465bb5e95638084d956dabd1ef6607c6b6cbf3a3930e627c126cfe0d79a6014853588f8aa56cfef59b6ef2725356e000000006553f100000000137773733a2f2f72656c61792e6578616d706c656e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d";
const PUSH_REGISTER_B_HEX: &str = "5343502d505553482d52454749535445522d56313a000000387363703a68763661337066733471636962746868336b61656b7a68666f327878716c666e696537757073366876637371736d6b6970796c6101000000080123456789abcdef00000002f8f7da66a5b0f0d9466a2e1d8145fc72717465bb5e95638084d956dabd1ef6607c6b6cbf3a3930e627c126cfe0d79a6014853588f8aa56cfef59b6ef2725356e000000006553f1000000001a7773733a2f2f72656c61792e6578616d706c652f7363702f76316e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d";
const PUSH_DEREGISTER_A_HEX: &str = "5343502d505553482d444552454749535445522d56313a000000387363703a68763661337066733471636962746868336b61656b7a68666f327878716c666e696537757073366876637371736d6b6970796c6102000000080123456789abcdef000000006553f22c000000137773733a2f2f72656c61792e6578616d706c656e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d";
const PUSH_DEREGISTER_B_HEX: &str = "5343502d505553482d444552454749535445522d56313a000000387363703a68763661337066733471636962746868336b61656b7a68666f327878716c666e696537757073366876637371736d6b6970796c6102000000080123456789abcdef000000006553f22c0000001a7773733a2f2f72656c61792e6578616d706c652f7363702f76316e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d";
const PUSH_ROUTING_ID_A_HEX: &str =
    "b980a702c8f9cc2504a164bde90549a079621c8306fdf64d2c3adefd2739367a";
const PUSH_ROUTING_ID_B_HEX: &str =
    "b2f96d91d7b43038f18f9d1b686a5e033f8e07635e9baa819754d6a829942fcd";
const PUSH_BRIDGE_URL: &str = "wss://bridge.example.com/scp/v1";
const PUSH_BRIDGE_TARGET_HEX: &str =
    "4102ed70d1c4b106466149a7d129630c11a20554683ae012fdffa56341d1c323";
const PUSH_REGISTER_BRIDGE_HEX: &str = "5343502d505553482d52454749535445522d56313a000000387363703a68763661337066733471636962746868336b61656b7a68666f327878716c666e696537757073366876637371736d6b6970796c6101000000080123456789abcdef00000002f8f7da66a5b0f0d9466a2e1d8145fc72717465bb5e95638084d956dabd1ef6607c6b6cbf3a3930e627c126cfe0d79a6014853588f8aa56cfef59b6ef2725356e000000006553f1000000001f7773733a2f2f6272696467652e6578616d706c652e636f6d2f7363702f76314102ed70d1c4b106466149a7d129630c11a20554683ae012fdffa56341d1c323";
const PUSH_DEREGISTER_BRIDGE_HEX: &str = "5343502d505553482d444552454749535445522d56313a000000387363703a68763661337066733471636962746868336b61656b7a68666f327878716c666e696537757073366876637371736d6b6970796c6102000000080123456789abcdef000000006553f22c0000001f7773733a2f2f6272696467652e6578616d706c652e636f6d2f7363702f76314102ed70d1c4b106466149a7d129630c11a20554683ae012fdffa56341d1c323";
const PUSH_TIER3_PREIMAGE_HEX: &str = "7363702d707573682d6272696467653a7773733a2f2f6272696467652e6578616d706c652e636f6d2f7363702f76314102ed70d1c4b106466149a7d129630c11a20554683ae012fdffa56341d1c323";
const PUSH_TIER3_ROUTING_ID_HEX: &str =
    "b01dcde6d4e3d24f807acbc4ddadf3dd2bb8103f24f8f099ec08e4c476e7d9ec";
const PUSH_BRIDGE_RELAY_ROUTING_ID_HEX: &str =
    "e47cce36c946ac50a2ee3dbc40f0416d7012bf82344c8f24a756c0f62242eea1";

fn push_bridge_target() -> BridgeTarget {
    BridgeTarget::new(unhex(PUSH_BRIDGE_TARGET_HEX).try_into().unwrap()).unwrap()
}

fn push_routing_ids() -> [[u8; 32]; 2] {
    [
        sha256(b"SCP test vector push routing id 1"),
        sha256(b"SCP test vector push routing id 2"),
    ]
}

fn push_registration_fixture() -> PushRegistration {
    PushRegistration {
        registrant: DID::from(ID_SENDER),
        platform: PushPlatform::Apns,
        token: unhex(PUSH_TOKEN_HEX),
        routing_ids: push_routing_ids().to_vec(),
        timestamp: PUSH_TIMESTAMP,
        signature: [0; 64],
    }
}

fn push_deregistration_fixture() -> PushDeregistration {
    PushDeregistration {
        registrant: DID::from(ID_SENDER),
        platform: PushPlatform::Fcm,
        token: unhex(PUSH_TOKEN_HEX),
        timestamp: PUSH_DEREGISTER_TIMESTAMP,
        signature: [0; 64],
    }
}

/// Appends a 4-byte big-endian length and the bytes.
fn push_var(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// The §9.5.2 `bridge_target` field: the target's 32 bytes, or
/// `SHA-256(0x00)` when absent.
fn push_target_bytes(target: Option<BridgeTarget>) -> [u8; 32] {
    target.map_or_else(|| sha256(&[0x00]), BridgeTarget::to_bytes)
}

/// The §9.5.2 `PushRegistration` table, assembled field by field.
fn push_register_layout(relay_url: &str, target: Option<BridgeTarget>) -> Vec<u8> {
    let mut out = b"SCP-PUSH-REGISTER-V1:".to_vec();
    assert_eq!(ID_SENDER.len(), 56);
    push_var(&mut out, ID_SENDER.as_bytes());
    out.push(0x01);
    push_var(&mut out, &unhex(PUSH_TOKEN_HEX));
    out.extend_from_slice(&2u32.to_be_bytes());
    for id in push_routing_ids() {
        out.extend_from_slice(&id);
    }
    out.extend_from_slice(&PUSH_TIMESTAMP.to_be_bytes());
    push_var(&mut out, relay_url.as_bytes());
    out.extend_from_slice(&push_target_bytes(target));
    out
}

/// The §9.5.2 `PushDeregistration` table, assembled field by field.
fn push_deregister_layout(relay_url: &str, target: Option<BridgeTarget>) -> Vec<u8> {
    let mut out = b"SCP-PUSH-DEREGISTER-V1:".to_vec();
    push_var(&mut out, ID_SENDER.as_bytes());
    out.push(0x02);
    push_var(&mut out, &unhex(PUSH_TOKEN_HEX));
    out.extend_from_slice(&PUSH_DEREGISTER_TIMESTAMP.to_be_bytes());
    push_var(&mut out, relay_url.as_bytes());
    out.extend_from_slice(&push_target_bytes(target));
    out
}

/// The [`PushRelay`] a golden is signed for: the tier 3 entry at `url` with
/// `target`, or the relay at `url` with no target.
fn push_relay(url: &str, target: Option<BridgeTarget>) -> PushRelay {
    target.map_or_else(
        || PushRelay::direct(url).unwrap(),
        |t| PushRelay::from(&RelayService::bridge(BridgeEndpoint::new(url).unwrap(), t)),
    )
}

#[test]
fn push_registration_signing_bytes_match_golden_vectors() {
    let reg = push_registration_fixture();
    for (url, target, golden) in [
        (PUSH_RELAY_A, None, PUSH_REGISTER_A_HEX),
        (PUSH_RELAY_B, None, PUSH_REGISTER_B_HEX),
        (
            PUSH_BRIDGE_URL,
            Some(push_bridge_target()),
            PUSH_REGISTER_BRIDGE_HEX,
        ),
    ] {
        let produced = push_registration_signing_bytes(&reg, &push_relay(url, target)).unwrap();
        assert_eq!(hex::encode(&produced), golden, "{url}: golden vector");
        assert_eq!(
            produced,
            push_register_layout(url, target),
            "{url}: §9.5.2 layout"
        );
    }
    assert_eq!(unhex(PUSH_REGISTER_A_HEX).len(), 225);
    assert_eq!(unhex(PUSH_REGISTER_B_HEX).len(), 232);
    assert_eq!(
        unhex(PUSH_REGISTER_A_HEX)[193..],
        ABSENT_BRIDGE_TARGET,
        "relay A ends with the absent sentinel"
    );
}

#[test]
fn push_deregistration_signing_bytes_match_golden_vectors() {
    let dereg = push_deregistration_fixture();
    for (url, target, golden) in [
        (PUSH_RELAY_A, None, PUSH_DEREGISTER_A_HEX),
        (PUSH_RELAY_B, None, PUSH_DEREGISTER_B_HEX),
        (
            PUSH_BRIDGE_URL,
            Some(push_bridge_target()),
            PUSH_DEREGISTER_BRIDGE_HEX,
        ),
    ] {
        let produced = push_deregistration_signing_bytes(&dereg, &push_relay(url, target)).unwrap();
        assert_eq!(hex::encode(&produced), golden, "{url}: golden vector");
        assert_eq!(
            produced,
            push_deregister_layout(url, target),
            "{url}: §9.5.2 layout"
        );
    }
    assert_eq!(unhex(PUSH_DEREGISTER_A_HEX).len(), 159);
    assert_eq!(unhex(PUSH_DEREGISTER_B_HEX).len(), 166);
}

#[test]
fn push_preimages_differ_across_relay_urls() {
    let reg = push_registration_fixture();
    assert_ne!(
        push_registration_signing_bytes(&reg, &push_relay(PUSH_RELAY_A, None)).unwrap(),
        push_registration_signing_bytes(&reg, &push_relay(PUSH_RELAY_B, None)).unwrap()
    );
    let dereg = push_deregistration_fixture();
    assert_ne!(
        push_deregistration_signing_bytes(&dereg, &push_relay(PUSH_RELAY_A, None)).unwrap(),
        push_deregistration_signing_bytes(&dereg, &push_relay(PUSH_RELAY_B, None)).unwrap()
    );
}

#[test]
fn push_preimages_are_equal_across_spellings_of_one_relay_url() {
    let reg = push_registration_fixture();
    assert_eq!(
        hex::encode(
            push_registration_signing_bytes(&reg, &push_relay("WSS://Relay.Example:443/", None))
                .unwrap()
        ),
        PUSH_REGISTER_A_HEX
    );
    let dereg = push_deregistration_fixture();
    assert_eq!(
        hex::encode(
            push_deregistration_signing_bytes(
                &dereg,
                &push_relay("WSS://Relay.Example:443/", None)
            )
            .unwrap()
        ),
        PUSH_DEREGISTER_A_HEX
    );
}

#[test]
fn push_registration_routing_id_matches_golden_vectors() {
    let a = push_registration_routing_id("WSS://Relay.Example:443/").unwrap();
    assert_eq!(a, push_registration_routing_id(PUSH_RELAY_A).unwrap());
    assert_eq!(hex::encode(a), PUSH_ROUTING_ID_A_HEX);
    assert_eq!(
        a,
        sha256(&[b"scp-push-registration".as_slice(), PUSH_RELAY_A.as_bytes()].concat())
    );
    assert_eq!(
        hex::encode(push_registration_routing_id(PUSH_RELAY_B).unwrap()),
        PUSH_ROUTING_ID_B_HEX
    );
}

/// §9.18.2 **Tier 3 push routing ID** over Vector 48's bridge entry, and the
/// bridge relay's own `"scp-push-registration"` ID, which differs from it.
#[test]
fn tier3_push_routing_id_matches_golden_vector() {
    let preimage = unhex(PUSH_TIER3_PREIMAGE_HEX);
    assert_eq!(preimage.len(), 79);
    assert_eq!(
        preimage,
        [
            b"scp-push-bridge:".as_slice(),
            PUSH_BRIDGE_URL.as_bytes(),
            &push_bridge_target().to_bytes(),
        ]
        .concat()
    );
    assert_eq!(hex::encode(sha256(&preimage)), PUSH_TIER3_ROUTING_ID_HEX);

    let bridge = RelayService::bridge(
        BridgeEndpoint::new(PUSH_BRIDGE_URL).unwrap(),
        push_bridge_target(),
    );
    assert_eq!(
        hex::encode(relay_service_push_routing_id(&bridge)),
        PUSH_TIER3_ROUTING_ID_HEX
    );
    assert_eq!(
        hex::encode(tier3_push_routing_id(
            &NodeUrl::new(PUSH_BRIDGE_URL).unwrap(),
            push_bridge_target()
        )),
        PUSH_TIER3_ROUTING_ID_HEX
    );
    let direct = RelayService::direct(NodeUrl::new(PUSH_BRIDGE_URL).unwrap());
    assert_eq!(
        hex::encode(relay_service_push_routing_id(&direct)),
        PUSH_BRIDGE_RELAY_ROUTING_ID_HEX
    );
    assert_eq!(
        hex::encode(push_registration_routing_id(PUSH_BRIDGE_URL).unwrap()),
        PUSH_BRIDGE_RELAY_ROUTING_ID_HEX
    );
}

// ---------------------------------------------------------------------------
// §25.31 Trust challenge vectors (§7.3.4, §7.3.4.6)
// ---------------------------------------------------------------------------

/// An identifier-scoped URI: `ID_DEFINER` followed by
/// `:capability:schema-validation/v1`.
const CHALLENGE_CAPABILITY_URI: &str =
    "scp:tfgiiao36zlseo2tzfoi32knfx6topped3qloxcsube5gdvfrqgq:capability:schema-validation/v1";
/// Vector 65 `definition_digest`.
const CHALLENGE_DEFINITION_DIGEST_HEX: &str =
    "1947de3173cb08e14fa71bd41bb256274ba2b62e0d0d9e73b83af1a971ee8f67";
/// Vector 61 `suite_digest`: SHA-256 of `T`, no prefix.
const CHALLENGE_SUITE_DIGEST_HEX: &str =
    "9cec9fc1c4c6a8a835e448fd94c33310692514aa51c4b52d2ba2d4a819f13cd8";
/// Vector 61 `D`.
const CHALLENGE_REQUEST_DIGEST_HEX: &str =
    "bf8a8adb49daf2eb0078296f1a4bd29a637b992aa1c795cf930a863978c0e7e2";
/// Vector 65 `Def`.
const VDEF_HEX: &str = "5343502d4341504142494c4954592d444546494e4954494f4e2d56313a000000587363703a7466676969616f33367a6c73656f32747a666f6933326b6e667836746f7070656433716c6f7863737562653567647666727167713a6361706162696c6974793a736368656d612d76616c69646174696f6e2f7631000000000100001f400000000200000e100000002d4669787475726520646566696e6974696f6e20666f72207370656320323520766563746f72732035392d36322e";
/// Vector 61 `T`.
const VT_HEX: &str = "0000000100000015736368656d612d76616c69646174696f6e2d3030310000001b7b22636f756e74223a332c226e616d65223a22776964676574227d00000006736368656d6100002710";
/// Vector 61 `R`.
const VR_HEX: &str = "5343502d4348414c4c454e47452d5245512d56313a0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000587363703a7466676969616f33367a6c73656f32747a666f6933326b6e667836746f7070656433716c6f7863737562653567647666727167713a6361706162696c6974793a736368656d612d76616c69646174696f6e2f76311947de3173cb08e14fa71bd41bb256274ba2b62e0d0d9e73b83af1a971ee8f670000000100000015736368656d612d76616c69646174696f6e2d3030310000001b7b22636f756e74223a332c226e616d65223a22776964676574227d00000006736368656d6100002710000000006553f10000000000655542800000000200000e1000001f400000000f746573742d636f6e746578742d3031000000387363703a7673726d736f626632757a656a73626461616733747877617561736a72706e7435776c6b756c6861686262667774646661617061000000387363703a6b7461726736617174736a75366d6832777333686b3774356b6d73766d636b71376435657177736d617735646933653370347461";
/// Vector 64 `P`, attempt 2.
const VP2_HEX: &str = "5343502d4348414c4c454e47452d524553502d56313a0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20bf8a8adb49daf2eb0078296f1a4bd29a637b992aa1c795cf930a863978c0e7e2000000387363703a6b7461726736617174736a75366d6832777333686b3774356b6d73766d636b71376435657177736d617735646933653370347461000000020000000100000015736368656d612d76616c69646174696f6e2d3030310000001b7b22636f756e74223a332c226e616d65223a22776964676574227d";
/// Vector 62 attempt-1 response `P`.
const VP1_HEX: &str = "5343502d4348414c4c454e47452d524553502d56313a0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20bf8a8adb49daf2eb0078296f1a4bd29a637b992aa1c795cf930a863978c0e7e2000000387363703a6b7461726736617174736a75366d6832777333686b3774356b6d73766d636b71376435657177736d617735646933653370347461000000010000000100000015736368656d612d76616c69646174696f6e2d303031000000117b226e616d65223a22776964676574227d";
/// Vector 62 `verification_id` preimage.
const VID60_HEX: &str = "000000387363703a7673726d736f626632757a656a73626461616733747877617561736a72706e7435776c6b756c6861686262667774646661617061000000387363703a6b7461726736617174736a75366d6832777333686b3774356b6d73766d636b71376435657177736d617735646933653370347461000000587363703a7466676969616f33367a6c73656f32747a666f6933326b6e667836746f7070656433716c6f7863737562653567647666727167713a6361706162696c6974793a736368656d612d76616c69646174696f6e2f76310102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2000000001000000006553f358";
/// Vector 62 `R_v`.
const VRV60_HEX: &str = "5343502d4348414c4c454e47452d5645524946592d56313a9554fd256e3c6bb5ee6c73e1ca28e72ade44785bde24d84c17869cb1da667b77000000387363703a7673726d736f626632757a656a73626461616733747877617561736a72706e7435776c6b756c6861686262667774646661617061000000387363703a6b7461726736617174736a75366d6832777333686b3774356b6d73766d636b71376435657177736d617735646933653370347461000000587363703a7466676969616f33367a6c73656f32747a666f6933326b6e667836746f7070656433716c6f7863737562653567647666727167713a6361706162696c6974793a736368656d612d76616c69646174696f6e2f76311947de3173cb08e14fa71bd41bb256274ba2b62e0d0d9e73b83af1a971ee8f679cec9fc1c4c6a8a835e448fd94c33310692514aa51c4b52d2ba2d4a819f13cd80102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2000000001e2d6a7768d281382acb3573e23ba9c76f58c07509c2f7727a151b589a687a1850000000200000e1000001f400000000100000000000000000100000000000000006553f1000000000065554280000000006553f3580000000065ca9a580000000f746573742d636f6e746578742d3031";
/// Vector 63 `verification_id` preimage.
const VID61_HEX: &str = "000000387363703a7673726d736f626632757a656a73626461616733747877617561736a72706e7435776c6b756c6861686262667774646661617061000000387363703a6b7461726736617174736a75366d6832777333686b3774356b6d73766d636b71376435657177736d617735646933653370347461000000587363703a7466676969616f33367a6c73656f32747a666f6933326b6e667836746f7070656433716c6f7863737562653567647666727167713a6361706162696c6974793a736368656d612d76616c69646174696f6e2f76310102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000000020000000065540168";
/// Vector 63 `R_v`.
const VRV61_HEX: &str = "5343502d4348414c4c454e47452d5645524946592d56313a5cec3cdef9ef548b71a346c713eead24381a8cac1e0d422e1a788cf524d99d63000000387363703a7673726d736f626632757a656a73626461616733747877617561736a72706e7435776c6b756c6861686262667774646661617061000000387363703a6b7461726736617174736a75366d6832777333686b3774356b6d73766d636b71376435657177736d617735646933653370347461000000587363703a7466676969616f33367a6c73656f32747a666f6933326b6e667836746f7070656433716c6f7863737562653567647666727167713a6361706162696c6974793a736368656d612d76616c69646174696f6e2f76311947de3173cb08e14fa71bd41bb256274ba2b62e0d0d9e73b83af1a971ee8f679cec9fc1c4c6a8a835e448fd94c33310692514aa51c4b52d2ba2d4a819f13cd80102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2000000002f6e06ef6438935719b8b784119b6f75e8095ea27ffdfb8c60efc1c88bddb49490000000200000e1000001f400000000101000027100000000100000001000000006553f100000000006555428000000000655401680000000065caa8680000000f746573742d636f6e746578742d3031";

fn challenge_vector_id() -> [u8; 32] {
    core::array::from_fn(|i| u8::try_from(i + 1).unwrap())
}

fn challenge_vector_request() -> ChallengeRequest {
    ChallengeRequest {
        challenge_id: challenge_vector_id(),
        capability_uri: CHALLENGE_CAPABILITY_URI.to_owned(),
        definition_digest: unhex32(CHALLENGE_DEFINITION_DIGEST_HEX),
        test_cases: vec![ChallengeCase {
            test_id: "schema-validation-001".to_owned(),
            input: serde_json::json!({"name": "widget", "count": 3}),
            category: "schema".to_owned(),
            weight: 10_000,
        }],
        created_at: 1_700_000_000,
        expires_at: 1_700_086_400,
        max_retries: 2,
        cooldown_secs: 3600,
        pass_threshold_bps: 8000,
        context_id: "test-context-01".to_owned(),
        verifier: DID(ID_VERIFIER.to_owned()),
        subject: DID(ID_SUBJECT.to_owned()),
        verifier_signature: Vec::new(),
    }
}

fn challenge_vector_response(attempt: u32, output: serde_json::Value) -> ChallengeResponse {
    ChallengeResponse {
        challenge_id: challenge_vector_id(),
        request_digest: unhex32(CHALLENGE_REQUEST_DIGEST_HEX),
        subject: DID(ID_SUBJECT.to_owned()),
        attempt,
        outputs: vec![TestOutput {
            test_id: "schema-validation-001".to_owned(),
            output,
        }],
        subject_signature: Vec::new(),
    }
}

/// The inputs and expected bytes of one verification-record vector.
struct VerificationVector<'a> {
    label: &'a str,
    attempt: u32,
    response_preimage_hex: &'a str,
    passed: bool,
    timestamp: u64,
    id_preimage_hex: &'a str,
    rv_hex: &'a str,
    dv_hex: &'a str,
}

/// Asserts one verification-record vector through the production encoders:
/// the `verification_id` preimage and value, `R_v` and `D_v`. Returns `R_v`.
fn assert_challenge_verification_vector(v: &VerificationVector<'_>) -> Vec<u8> {
    let VerificationVector {
        label,
        attempt,
        response_preimage_hex,
        passed,
        timestamp,
        id_preimage_hex,
        rv_hex,
        dv_hex,
    } = *v;
    let challenge_id = challenge_vector_id();
    let id_preimage = hex::decode(id_preimage_hex).unwrap();
    let verification_id = challenge_verification_id(
        ID_VERIFIER,
        ID_SUBJECT,
        CHALLENGE_CAPABILITY_URI,
        &challenge_id,
        attempt,
        timestamp,
    )
    .unwrap();
    assert_eq!(
        verification_id,
        sha256(&id_preimage),
        "{label}: verification_id"
    );
    let record = ChallengeVerification {
        verification_id,
        verifier: DID(ID_VERIFIER.to_owned()),
        subject: DID(ID_SUBJECT.to_owned()),
        capability_uri: CHALLENGE_CAPABILITY_URI.to_owned(),
        definition_digest: unhex32(CHALLENGE_DEFINITION_DIGEST_HEX),
        suite_digest: unhex32(CHALLENGE_SUITE_DIGEST_HEX),
        challenge_id,
        attempt,
        response_digest: sha256(&hex::decode(response_preimage_hex).unwrap()),
        max_retries: 2,
        cooldown_secs: 3600,
        pass_threshold_bps: 8000,
        min_category_cases: 1,
        passed,
        score: if passed { 10_000 } else { 0 },
        test_count: 1,
        pass_count: u32::from(passed),
        challenge_created_at: 1_700_000_000,
        challenge_expires_at: 1_700_086_400,
        timestamp,
        expires_at: timestamp + 7_776_000,
        context_id: "test-context-01".to_owned(),
        verifier_signature: Vec::new(),
    };
    let rv = canonical_challenge_verification_bytes(&record).unwrap();
    assert_eq!(rv.len(), 480, "{label}: R_v length");
    assert_eq!(hex::encode(&rv), rv_hex, "{label}: R_v");
    assert_eq!(
        hex::encode(challenge_verification_signing_digest(&record).unwrap()),
        dv_hex,
        "{label}: D_v"
    );
    assert_eq!(
        hex::encode(sha256(&rv)),
        dv_hex,
        "{label}: D_v = SHA-256(R_v)"
    );
    rv
}

#[test]
fn vector_65_capability_definition() {
    let definition = CapabilityDefinition {
        capability_uri: CHALLENGE_CAPABILITY_URI.to_owned(),
        min_cases: MinCases::Total(1),
        pass_threshold_bps: 8000,
        max_retries: 2,
        cooldown_secs: 3600,
        description: "Fixture definition for spec 25 vectors 59-62.".to_owned(),
    };
    let def = definition.canonical_bytes().unwrap();
    assert_eq!(def.len(), 187);
    assert_eq!(hex::encode(&def), VDEF_HEX);
    assert_eq!(
        hex::encode(definition.digest().unwrap()),
        CHALLENGE_DEFINITION_DIGEST_HEX
    );
    assert_eq!(hex::encode(sha256(&def)), CHALLENGE_DEFINITION_DIGEST_HEX);
}

#[test]
fn vector_61_challenge_request() {
    assert_eq!(
        CHALLENGE_CAPABILITY_URI,
        format!("{ID_DEFINER}:capability:schema-validation/v1")
    );
    let request = challenge_vector_request();
    let t = hex::decode(VT_HEX).unwrap();
    assert_eq!(t.len(), 74);
    assert_eq!(hex::encode(sha256(&t)), CHALLENGE_SUITE_DIGEST_HEX);
    assert_eq!(
        hex::encode(challenge_suite_digest(&request.test_cases).unwrap()),
        CHALLENGE_SUITE_DIGEST_HEX,
        "challenge_suite_digest"
    );
    let r = canonical_challenge_request_bytes(&request).unwrap();
    assert_eq!(r.len(), 418);
    assert_eq!(hex::encode(&r), VR_HEX, "R");
    // `R` embeds `T` verbatim and no byte of the expected output: `T` ends
    // at the last case's weight, and the next field is `created_at`.
    assert!(VR_HEX.contains(&format!("{VT_HEX}{:016x}", request.created_at)));
    let expected = ExpectedOutput::SchemaMatch {
        schema: serde_json::json!({"type": "object", "required": ["name", "count"]}),
    };
    let expected_jcs = hex::encode(scp_protocol::jcs::to_vec(&expected).unwrap());
    assert!(!VR_HEX.contains(&expected_jcs));
    assert_eq!(
        hex::encode(challenge_request_signing_digest(&request).unwrap()),
        CHALLENGE_REQUEST_DIGEST_HEX,
        "challenge_request_signing_digest"
    );
    assert_eq!(hex::encode(sha256(&r)), CHALLENGE_REQUEST_DIGEST_HEX);
}

#[test]
fn vector_64_challenge_response() {
    let request = challenge_vector_request();
    assert_eq!(
        challenge_request_signing_digest(&request).unwrap(),
        unhex32(CHALLENGE_REQUEST_DIGEST_HEX)
    );
    for (attempt, output, p_hex, d_r) in [
        (
            2,
            serde_json::json!({"count": 3, "name": "widget"}),
            VP2_HEX,
            "f6e06ef6438935719b8b784119b6f75e8095ea27ffdfb8c60efc1c88bddb4949",
        ),
        (
            1,
            serde_json::json!({"name": "widget"}),
            VP1_HEX,
            "e2d6a7768d281382acb3573e23ba9c76f58c07509c2f7727a151b589a687a185",
        ),
    ] {
        let response = challenge_vector_response(attempt, output);
        let p = canonical_challenge_response_bytes(&response).unwrap();
        assert_eq!(hex::encode(&p), p_hex, "attempt {attempt}: P");
        assert_eq!(
            hex::encode(challenge_response_signing_digest(&response).unwrap()),
            d_r,
            "attempt {attempt}: D_r"
        );
        assert_eq!(hex::encode(sha256(&p)), d_r);
    }
    assert_eq!(hex::decode(VP2_HEX).unwrap().len(), 210);
    assert_eq!(hex::decode(VP1_HEX).unwrap().len(), 200);
}

#[test]
fn vector_62_challenge_verification() {
    let rv = assert_challenge_verification_vector(&VerificationVector {
        label: "vector 62",
        attempt: 1,
        response_preimage_hex: VP1_HEX,
        passed: false,
        timestamp: 1_700_000_600,
        id_preimage_hex: VID60_HEX,
        rv_hex: VRV60_HEX,
        dv_hex: "b4c5366bb9a106b8819cb974e602a6490a9b1b3f862497a6def7764d5bfa162d",
    });
    assert_eq!(
        hex::encode(sha256(&hex::decode(VID60_HEX).unwrap())),
        "9554fd256e3c6bb5ee6c73e1ca28e72ade44785bde24d84c17869cb1da667b77"
    );
    assert_eq!(hex::decode(VID60_HEX).unwrap().len(), 256);
    assert!(!hex::encode(rv).contains(ABSENT_SENTINEL_HEX));
}

#[test]
fn vector_63_challenge_verification_passing_attempt() {
    let rv = assert_challenge_verification_vector(&VerificationVector {
        label: "vector 63",
        attempt: 2,
        response_preimage_hex: VP2_HEX,
        passed: true,
        timestamp: 1_700_004_200,
        id_preimage_hex: VID61_HEX,
        rv_hex: VRV61_HEX,
        dv_hex: "765bf9ca092df576175ae942aae2a0cc501fba5f899a96dbd065157f5e6c0fa3",
    });
    assert_eq!(
        hex::encode(sha256(&hex::decode(VID61_HEX).unwrap())),
        "5cec3cdef9ef548b71a346c713eead24381a8cac1e0d422e1a788cf524d99d63"
    );
    // The record has no optional field, so no absent-field sentinel appears.
    assert!(!hex::encode(rv).contains(ABSENT_SENTINEL_HEX));
}

// ---------------------------------------------------------------------------
// §25.27 Node vectors: Vector 90 (NodeId), 91 (NodeBinding), 44 (node proof),
// 49 (node-list record and frame), and Vector 80's list record and node proof
// ---------------------------------------------------------------------------

/// §25.2's secret key at index `i` of [`REFERENCE_KEYS`].
fn fixture_secret(i: usize) -> P256SecretKey {
    P256SecretKey::from_seed(SeedLabel::TestVectorKey, &unhex32(REFERENCE_KEYS[i].0))
}

/// §25.2's public key at index `i` of [`REFERENCE_KEYS`].
fn fixture_public(i: usize) -> P256PublicKey {
    P256PublicKey::from_sec1(&unhex(REFERENCE_KEYS[i].2)).unwrap()
}

fn fixture_node_key(i: usize) -> [u8; 33] {
    unhex(REFERENCE_KEYS[i].2).try_into().unwrap()
}

/// Vector 49's entry `index`: the operator is Vector 41's identity at its
/// inception digest, whose `#active` is §25.2's secondary key, and the node
/// key is §25.2's reference key (entry 0) or tertiary key (entry 1).
fn vector_49_entry(index: usize) -> NodeListEntry {
    let (operator, head, url, url_hash, operator_sig, possession_sig, free) = if index == 0 {
        (
            "d5adb473c01283dc9a7e7e998c1d312b3a353acf4863c13fe77efe304ad38bb3",
            "fcd42118a68664c30ff6b44a74aa21fcee2e248e863b973dcad7c75dead5a763",
            "wss://node-a.example.com/scp/v1",
            "0e9d09b337c5fc0be71b0688d6397b804369509fb9cd9b656276e5953fb7ad98",
            "77c19022c3b69482fb133ddd1d01f11988bdc733a910390e8b5c494e63d66ef10b7b039f1cab5c00efabbb7b7cd1020cc9505cdbea2d866b7a5b8ba649366397",
            "52d92cfbef55246e511e354cadb35f71ec8105cfc909ce9b2b1e23e061535d8e794028c9eb1a344f2521f2dfa6caea45e77ebacbf0ece4e561d2f524dafba02d",
            true,
        )
    } else {
        (
            "d5adb473c01283dc9a7e7e998c1d312b3a353acf4863c13fe77efe304ad38bb3",
            "fcd42118a68664c30ff6b44a74aa21fcee2e248e863b973dcad7c75dead5a763",
            "wss://node-b.example.com/scp/v1",
            "fa2f2df6d37f5691e35046764de6d6a65257da441fe53d427c18c6f4e166174d",
            "25a05afd2c1f2ad360e22c8ec169a09acf989d3522384bfcd8e882ade990c33e60afdc10b0ee280f0efb15346a2caa07c5f174608367b1d631609848de80324b",
            "441aced9a76dd0c653388ac554bb8a17448d085d3c0d166952c4bee0ed647a367d01bc2af588042d25e812f7f216d76ef40c4cc5f331429328d91d2b7931a610",
            false,
        )
    };
    NodeListEntry {
        binding: NodeBinding {
            operator: Identifier::from_bytes(unhex32(operator)),
            node_key: fixture_node_key(if index == 0 { 0 } else { 2 }),
            url_hash: unhex32(url_hash),
            key_state_head: unhex32(head),
            operator_sig: unhex(operator_sig).try_into().unwrap(),
            possession_sig: unhex(possession_sig).try_into().unwrap(),
        },
        url: NodeUrl::new(url).unwrap(),
        free,
    }
}

/// Vector 41's signed preimage and its root key's raw signature.
const VECTOR_41_PREIMAGE: &str = "5343502d4b454c2d4556454e542d56313a0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000001010000000000000001033b1cac23f45cf1cdfdf0b32f8f777b99166c1b69649c2295b1517883d47f3027000000010000000100000002033b1cac23f45cf1cdfdf0b32f8f777b99166c1b69649c2295b1517883d47f30270101000000000000000001010223702a648232f2d00713de9289753c2fbd4c4efa7e1e33905e3723a412b20aea02010000000000000000010100000001575d27a9d81af87b505b07f00c00031382c4ca1f3b9bf03e874f25179e21bcae00000e10020000000000000000000000000000000000000000000000000000000000000000000000000100000001421be508c6ed135a9737895007e5ba16f9542e1b3440f6d00a515de80a3e43eb010100000001";
const VECTOR_41_SIGNATURE: &str = "0f53fa982d5dedc4e0f7b0c0216098ee17e8fa0e0c42609a976c4b1d444a9ba15f6fe6f9cbc80d4f37cf39e620b9ae7ff4e022e3810beab421655170ec4ddd07";

/// The key state the verdict classifier accepts over Vector 41's log, its
/// one inception as the unit `BE32(len) ‖ signed preimage ‖ signature`,
/// served to the end by two sources under two distinct proven operator keys
/// (`09-security-model.md` §9.7.4.2 R11's floor; `03-identity.md` §3.10.10).
/// A reader reads Vector 49's operators' and governor's and Vector 92's
/// operator's `#active` from it.
fn vector_41_resolved() -> ResolvedState {
    let preimage = unhex(VECTOR_41_PREIMAGE);
    let mut unit = u32::try_from(preimage.len())
        .unwrap()
        .to_be_bytes()
        .to_vec();
    unit.extend_from_slice(&preimage);
    unit.extend_from_slice(&unhex(VECTOR_41_SIGNATURE));
    let source = |name: &str, operator: u8| SourceRead {
        name: name.to_owned(),
        units: vec![unit.clone()],
        exhaustion: SourceExhaustion::Exhausted,
        proof: OperatorProof::Verified {
            operator_key: [operator; 33],
        },
    };
    let classification = classify(ResolutionInput {
        identifier: Identifier::from_bytes(unhex32(NODE_LIST_GOVERNOR)),
        held: None,
        reads: &[source("relay-a", 0x02), source("relay-b", 0x03)],
        now: SystemTime::now(),
    })
    .unwrap();
    assert!(
        matches!(classification.verdict, ResolutionVerdict::Adopted { .. }),
        "Vector 41's log: {:?}",
        classification.verdict
    );
    classification.key_state.unwrap()
}

/// Vector 49's entry `index` binding, verified against Vector 41's log.
fn vector_49_bound(index: usize) -> VerifiedNodeBinding {
    VerifiedNodeBinding::verify(vector_49_entry(index).binding, &vector_41_resolved()).unwrap()
}

/// The verdict on a copy of `binding` against Vector 41's log.
fn check_binding(binding: &NodeBinding) -> Result<(), NodeBindingError> {
    VerifiedNodeBinding::verify(binding.clone(), &vector_41_resolved()).map(|_| ())
}

/// The verdict on a copy of `record` against Vector 41's log, as attribution.
fn check_record(record: &NodeListRecord) -> Result<(), NodeListError> {
    VerifiedNodeListRecord::verify(
        record.clone(),
        NodeListKeyClass::Attribution,
        &vector_41_resolved(),
    )
    .map(|_| ())
}

const NODE_LIST_CONTEXT_ID: &str =
    "97f678456b525ee215759c254e3ce5248249cf62dff666963caa5f25411354ce";
const NODE_LIST_GOVERNOR: &str = "d5adb473c01283dc9a7e7e998c1d312b3a353acf4863c13fe77efe304ad38bb3";
const NODE_LIST_SIGNING_HEAD: &str =
    "fcd42118a68664c30ff6b44a74aa21fcee2e248e863b973dcad7c75dead5a763";

fn vector_49_record(sequence: u64, signature: &str) -> NodeListRecord {
    NodeListRecord {
        context_id: NODE_LIST_CONTEXT_ID.to_owned(),
        sequence,
        governor: Identifier::from_bytes(unhex32(NODE_LIST_GOVERNOR)),
        signing_key_state_head: unhex32(NODE_LIST_SIGNING_HEAD),
        entries: vec![vector_49_entry(0), vector_49_entry(1)],
        signature: unhex(signature).try_into().unwrap(),
    }
}

#[test]
fn vector_90_node_id() {
    let binding = vector_49_entry(0).binding;
    let node_id = binding.node_id().unwrap();
    assert_eq!(
        hex::encode(node_id.as_bytes()),
        "e77d53354271e4c1c3c319cf7b5cfcc23be431c2ec795d5b6ecf549355f15610"
    );
    assert_spec_preimage(
        "vector 90",
        "5343502d4e4f44452d49442d56313a033b1cac23f45cf1cdfdf0b32f8f777b99166c1b69649c2295b1517883d47f3027",
        48,
        node_id.as_bytes(),
    );
    let mut secondary = vector_49_entry(1).binding;
    secondary.node_key = fixture_node_key(1);
    let secondary = secondary.node_id().unwrap();
    assert_eq!(
        hex::encode(secondary.as_bytes()),
        "575d27a9d81af87b505b07f00c00031382c4ca1f3b9bf03e874f25179e21bcae"
    );
    assert_ne!(node_id, secondary);

    // Negative: a binding whose node key carries the uncompressed prefix
    // names no node, so no proof can be checked against it.
    let mut off_prefix = vector_49_entry(0).binding;
    off_prefix.node_key[0] = 0x04;
    assert!(off_prefix.node_id().is_err());
    assert!(matches!(
        check_binding(&off_prefix),
        Err(NodeBindingError::NodeKey(_))
    ));
}

#[test]
fn vector_91_node_binding() {
    let binding = vector_49_entry(0).binding;
    assert_eq!(
        binding.operator.as_bytes(),
        &unhex32("d5adb473c01283dc9a7e7e998c1d312b3a353acf4863c13fe77efe304ad38bb3")
    );
    assert_eq!(
        binding.url_hash,
        node_url_hash(&NodeUrl::new("wss://node-a.example.com/scp/v1").unwrap())
    );
    assert_eq!(
        binding.url_hash,
        unhex32("0e9d09b337c5fc0be71b0688d6397b804369509fb9cd9b656276e5953fb7ad98")
    );
    let digest = binding.digest();
    assert_eq!(
        hex::encode(digest),
        "21d77bb1c8bb2799c0ba94064e338b698de499c39b7d9f8e052376e541f0d202"
    );
    assert_spec_preimage(
        "vector 91",
        "5343502d4e4f44452d42494e442d56313ad5adb473c01283dc9a7e7e998c1d312b3a353acf4863c13fe77efe304ad38bb3033b1cac23f45cf1cdfdf0b32f8f777b99166c1b69649c2295b1517883d47f30270e9d09b337c5fc0be71b0688d6397b804369509fb9cd9b656276e5953fb7ad98fcd42118a68664c30ff6b44a74aa21fcee2e248e863b973dcad7c75dead5a763",
        146,
        &digest,
    );
    assert_eq!(
        hex::encode(sign_prehash_rfc6979(&fixture_secret(1), &digest).unwrap()),
        "77c19022c3b69482fb133ddd1d01f11988bdc733a910390e8b5c494e63d66ef10b7b039f1cab5c00efabbb7b7cd1020cc9505cdbea2d866b7a5b8ba649366397"
    );
    assert_eq!(
        hex::encode(sign_prehash_rfc6979(&fixture_secret(0), &digest).unwrap()),
        "52d92cfbef55246e511e354cadb35f71ec8105cfc909ce9b2b1e23e061535d8e794028c9eb1a344f2521f2dfa6caea45e77ebacbf0ece4e561d2f524dafba02d"
    );
    let verified = VerifiedNodeBinding::verify(binding.clone(), &vector_41_resolved()).unwrap();
    assert_eq!(verified.binding(), &binding);
    assert_eq!(*verified.node_key(), fixture_public(0));
    assert_eq!(*verified.node_id(), binding.node_id().unwrap());

    // Negative: another identity as the operator, a key_state_head Vector
    // 41's log does not hold, and an operator_sig by any key but the
    // `#active` at key_state_head.
    let mut changed = binding.clone();
    changed.operator = Identifier::from_bytes([0x11; 32]);
    assert_eq!(
        check_binding(&changed),
        Err(NodeBindingError::OperatorKey(
            AnchoredKeyError::IdentityMismatch
        ))
    );
    let mut changed = binding.clone();
    changed.key_state_head[31] ^= 1;
    assert_eq!(
        check_binding(&changed),
        Err(NodeBindingError::OperatorKey(
            AnchoredKeyError::HeadNotOnChain
        ))
    );
    for other in [0, 2] {
        let mut changed = binding.clone();
        changed.operator_sig = sign_prehash_rfc6979(&fixture_secret(other), &digest).unwrap();
        assert_eq!(
            check_binding(&changed),
            Err(NodeBindingError::OperatorSignature(
                P256Error::VerificationFailed
            ))
        );
    }
    // Negative: each remaining field changed.
    let mut changed = binding.clone();
    changed.url_hash[0] ^= 1;
    assert!(matches!(
        check_binding(&changed),
        Err(NodeBindingError::OperatorSignature(_))
    ));
    let mut changed = binding.clone();
    changed.node_key = fixture_node_key(1);
    assert!(check_binding(&changed).is_err());
    let mut changed = binding.clone();
    changed.possession_sig[0] ^= 1;
    assert!(matches!(
        check_binding(&changed),
        Err(NodeBindingError::PossessionSignature(_))
    ));

    // Negative: the high-`s` form of each valid signature is refused.
    let mut changed = binding.clone();
    changed.operator_sig = high_s_form(&binding.operator_sig);
    assert_eq!(
        check_binding(&changed),
        Err(NodeBindingError::OperatorSignature(P256Error::HighS))
    );
    let mut changed = binding.clone();
    changed.possession_sig = high_s_form(&binding.possession_sig);
    assert_eq!(
        check_binding(&changed),
        Err(NodeBindingError::PossessionSignature(P256Error::HighS))
    );
}

fn vector_44_proof() -> NodeProof {
    NodeProof {
        node_id: vector_49_entry(0).binding.node_id().unwrap(),
        nonce: unhex32("8c10b9bc0b5acdcfb85432747587fbbd8894bbad69f35de6dff46093513daac8"),
        routing_id: unhex32("4102ed70d1c4b106466149a7d129630c11a20554683ae012fdffa56341d1c323"),
        value_digest: response_value_digest(&[
            b"scp-25-served-blob-a".as_slice(),
            b"scp-25-served-blob-bb".as_slice(),
        ])
        .unwrap(),
        observed_at: 1_700_000_000,
        signature: unhex("e3181283bee0dfc05c16d114441e110743ebe830078d42380c68e520e86558557e2ddfbebb87ab89de8c16432122da3f5e8e230eecb8424359d35c816a8c03ab").try_into().unwrap(),
    }
}

#[test]
fn vector_44_node_proof() {
    let proof = vector_44_proof();
    assert_eq!(
        hex::encode(proof.node_id.as_bytes()),
        "e77d53354271e4c1c3c319cf7b5cfcc23be431c2ec795d5b6ecf549355f15610"
    );
    assert_eq!(
        hex::encode(proof.value_digest),
        "ebbf1905dedb60f162f2cc5190ae0a8cd0adc66bb34e0ea45469bc4957405115"
    );
    let digest = proof.digest();
    assert_eq!(
        hex::encode(digest),
        "576f5707e3f53d47e9dbf92e376cf28032dfba602087803c93451326318d0952"
    );
    assert_spec_preimage(
        "vector 44",
        "5343502d4e4f44452d50524f4f462d56313ae77d53354271e4c1c3c319cf7b5cfcc23be431c2ec795d5b6ecf549355f156108c10b9bc0b5acdcfb85432747587fbbd8894bbad69f35de6dff46093513daac84102ed70d1c4b106466149a7d129630c11a20554683ae012fdffa56341d1c323ebbf1905dedb60f162f2cc5190ae0a8cd0adc66bb34e0ea45469bc4957405115000000006553f100",
        154,
        &digest,
    );
    assert_reference_signature(
        "vector 44",
        &digest,
        "e3181283bee0dfc05c16d114441e110743ebe830078d42380c68e520e86558557e2ddfbebb87ab89de8c16432122da3f5e8e230eecb8424359d35c816a8c03ab",
    );
    let bytes = proof.to_bytes();
    assert_eq!(bytes.len(), 200);
    assert_eq!(NodeProof::from_bytes(&bytes).unwrap(), proof);
    let node = vector_49_bound(0);
    proof.verify_signature(&node).unwrap();

    // Negative: the secondary key's binding names another node, the high-`s`
    // form of the signature is refused, and any changed byte fails.
    assert_eq!(
        proof.verify_signature(&vector_49_bound(1)),
        Err(NodeProofError::NodeIdMismatch)
    );
    let mut high = proof.clone();
    high.signature = high_s_form(&proof.signature);
    assert_eq!(
        high.verify_signature(&node),
        Err(NodeProofError::Signature(P256Error::HighS))
    );
    for i in 0..bytes.len() {
        let mut changed = bytes;
        changed[i] ^= 1;
        let decoded = NodeProof::from_bytes(&changed).unwrap();
        assert!(
            decoded.verify_signature(&node).is_err(),
            "byte {i} changed and the proof still verified"
        );
    }
}

#[test]
fn vector_49_node_list_entries() {
    let entries = [vector_49_entry(0), vector_49_entry(1)];
    let entries_json = entries_canonical_json(&entries).unwrap();
    assert_eq!(entries_json.len(), 1362);
    assert_eq!(
        hex::encode(sha256(&entries_json)),
        "4f09885c65c8abab8b548f6ed1849c889a0b06f353d39531fe68f27c5c54d1cc"
    );
    for entry in &entries {
        let verified = VerifiedNodeListEntry::verify(entry.clone(), &vector_41_resolved()).unwrap();
        assert_eq!(verified.url(), &entry.url);
        assert_eq!(verified.free(), entry.free);
    }
    // Negative: an entry listed under another URL is void.
    let mut moved = vector_49_entry(0);
    moved.url = NodeUrl::new("wss://node-b.example.com/scp/v1").unwrap();
    assert_eq!(
        VerifiedNodeListEntry::verify(moved, &vector_41_resolved()),
        Err(NodeListEntryError::UrlHashMismatch)
    );
}

#[test]
fn vector_49_node_list_record() {
    let record = vector_49_record(
        1,
        "05b95e41b015d94253187d1f38e776bd044b5c6e08fc2e92d5ec8b201a916eee28fb61bd0a14ea126f3ce2c6e2d8ba02db4771d49ebe8403b5b696537accd49f",
    );
    let digest = record.digest().unwrap();
    assert_eq!(
        hex::encode(digest),
        "3c3deb5f3a7651c0801acfcb8dcce2759a547af6f44a41e09af8938a0dbadf46"
    );
    assert_spec_preimage(
        "vector 49",
        "5343502d4e4f44452d4c4953542d56313a00000040393766363738343536623532356565323135373539633235346533636535323438323439636636326466663636363936336361613566323534313133353463650000000000000001d5adb473c01283dc9a7e7e998c1d312b3a353acf4863c13fe77efe304ad38bb3fcd42118a68664c30ff6b44a74aa21fcee2e248e863b973dcad7c75dead5a7634f09885c65c8abab8b548f6ed1849c889a0b06f353d39531fe68f27c5c54d1cc",
        189,
        &digest,
    );
    assert_eq!(
        hex::encode(sign_prehash_rfc6979(&fixture_secret(1), &digest).unwrap()),
        "05b95e41b015d94253187d1f38e776bd044b5c6e08fc2e92d5ec8b201a916eee28fb61bd0a14ea126f3ce2c6e2d8ba02db4771d49ebe8403b5b696537accd49f"
    );
    for class in [NodeListKeyClass::Standing, NodeListKeyClass::Attribution] {
        let verified =
            VerifiedNodeListRecord::verify(record.clone(), class, &vector_41_resolved()).unwrap();
        assert_eq!(verified.class(), class);
        assert_eq!(verified.record(), &record);
    }

    let json = record.to_canonical_json().unwrap();
    assert_eq!(json.len(), 1782);
    assert_eq!(
        hex::encode(sha256(&json)),
        "c7fc9810c282d0b44d0c55348cde9597eb20b59c539c4f9d67771a59e0832d06"
    );
    assert_eq!(NodeListRecord::from_canonical_json(&json).unwrap(), record);

    let routing_id = unhex32("e949d5a827c14f541cf388ce78193aeac04b893af96b472055ad595c14823fc6");
    let frame = encode_node_list_frame(&record).unwrap();
    assert_eq!(frame.len(), 1815);
    assert_eq!(
        hex::encode(sha256(&frame)),
        "456401835740d44056b9c511eb37dc9d4792601134b0876f9ad4dd8e4a9460e3"
    );
    assert_eq!(
        check_node_list_publish(&routing_id, &frame).unwrap(),
        record
    );

    // Negative: another signer, the high-`s` form of the signature, and each
    // signed field changed.
    let mut changed = record.clone();
    changed.signature = sign_prehash_rfc6979(&fixture_secret(0), &digest).unwrap();
    assert!(matches!(
        check_record(&changed),
        Err(NodeListError::Signature(_))
    ));
    let mut changed = record.clone();
    changed.signature = high_s_form(&record.signature);
    assert_eq!(
        check_record(&changed),
        Err(NodeListError::Signature(P256Error::HighS))
    );
    let mut changed = record.clone();
    changed.sequence = 2;
    assert!(check_record(&changed).is_err());
    let mut changed = record.clone();
    changed.context_id.push('0');
    assert!(check_record(&changed).is_err());
    let mut changed = record.clone();
    changed.signing_key_state_head[0] ^= 1;
    assert!(check_record(&changed).is_err());
    let mut changed = record.clone();
    changed.governor = Identifier::from_bytes([0x11; 32]);
    assert!(check_record(&changed).is_err());
    let mut changed = record;
    changed.entries.swap(0, 1);
    assert!(check_record(&changed).is_err());

    // Negative: the frame's version byte, its governor, and a space.
    let mut bad = frame.clone();
    bad[0] = 5;
    assert_eq!(
        decode_node_list_frame(&bad),
        Err(NodeListFrameError::WrongVersion(5))
    );
    let mut bad = frame.clone();
    bad[1] ^= 1;
    assert_eq!(
        decode_node_list_frame(&bad),
        Err(NodeListFrameError::GovernorMismatch)
    );
    let mut bad = frame[..33].to_vec();
    bad.extend_from_slice(b" ");
    bad.extend_from_slice(&json);
    assert!(decode_node_list_frame(&bad).is_err());
    assert_eq!(
        check_node_list_publish(&unhex32(NODE_LIST_GOVERNOR), &frame),
        Err(NodeListFrameError::RoutingIdMismatch)
    );
}

#[test]
fn vector_80_list_record_and_node_proof() {
    let record = vector_49_record(
        3,
        "5de7f4875963b4829604e49c68af4e57d9ef8f6ab961fb52da12c44f24e7550e76f0e7494ae66440e61a86122eab0f1c0b66f5f21c1beae4c08740999765e3b8",
    );
    let digest = record.digest().unwrap();
    assert_eq!(
        hex::encode(digest),
        "5a4e9c64f3c5e5a38e035e1e694dedac63fe51aaa3eb5ac13e61cdef42b46dcb"
    );
    check_record(&record).unwrap();
    let json = record.to_canonical_json().unwrap();
    assert_eq!(json.len(), 1782);
    assert_eq!(
        hex::encode(sha256(&json)),
        "e8bfe67b0fe13614345c34460da175817d534c120de83247c947309276ac16fa"
    );

    let proof_bytes = unhex(
        "e77d53354271e4c1c3c319cf7b5cfcc23be431c2ec795d5b6ecf549355f156105a5054e04186dcdb137484414cc26f7a0b4100126689b5fee53f290d72b6eb9b4102ed70d1c4b106466149a7d129630c11a20554683ae012fdffa56341d1c3239762ccc1e7d800f5ede39f61fab3c5d53584c8ea17514964b36202ab5825330a000000006553f10019ccb6fb372c14165c1774324b3c9e96a0fff3ee18a60047b980404deaa949cf7f8615dfa625481895765838b261f38d8c39b8c7bc80f37fed3931a6ff2f80f8",
    );
    let proof = NodeProof::from_bytes(&proof_bytes).unwrap();
    assert_eq!(proof.node_id, vector_49_entry(0).binding.node_id().unwrap());
    assert_eq!(
        hex::encode(proof.nonce),
        "5a5054e04186dcdb137484414cc26f7a0b4100126689b5fee53f290d72b6eb9b"
    );
    assert_eq!(
        hex::encode(proof.value_digest),
        "9762ccc1e7d800f5ede39f61fab3c5d53584c8ea17514964b36202ab5825330a"
    );
    proof.verify_signature(&vector_49_bound(0)).unwrap();
    assert_eq!(
        proof.verify_signature(&vector_49_bound(1)),
        Err(NodeProofError::NodeIdMismatch)
    );
}

// ---------------------------------------------------------------------------
// Cross-vector consistency
// ---------------------------------------------------------------------------

#[test]
fn domain_separators_are_all_unique() {
    // SHA-256 hash domain separators, used as the leading prefix of a hash
    // input. A prefix collision here would allow domain confusion.
    let hash_domains = [
        "SCP-INNER-ENVELOPE-V1:",
        "SCP-VOTE-V1:",
        "SCP-RESET-REQUEST-V1:",
        "SCP-KEY-CONTINUITY-V1:",
        "SCP-PROPOSAL-V1:",
        "SCP-ATTESTATION-V1:",
        "SCP-PSEUDONYM-V1:",
        "SCP-OFFER-ID-V1:",
        "SCP-ATTESTATION-ID-V1:",
        "SCP-EVENT-V1:",
        "SCP-CHECKPOINT-V1:",
        "SCP-MIGRATION-V1:",
        "SCP-KEY-DESTRUCTION-V1:",
        "SCP-CHUNK-MSG-ID-V1:",
        "SCP-PRIVATE-LOG-V1:",
        "SCP-BROADCAST-ENVELOPE-V1:",
        "SCP-PARTICIPATION-V1:",
        "SCP-IDENTITY-LINK-ATTESTATION-V1:",
        "SCP-ACCESS-KEY-REQUEST-V1:",
        "SCP-OUTLET-REGISTRATION-V2:",
        "SCP-FORK-ID-V1:",
        "SCP-COMMIT-RANGE-REQ-V1:",
        "SCP-COMMIT-RANGE-RESP-V1:",
        "SCP-CONTEXT-SNAPSHOT-V1:",
        "SCP-CONTEXT-EXPORT-V1:",
        "SCP-CHALLENGE-REQ-V1:",
        "SCP-CHALLENGE-RESP-V1:",
        "SCP-CHALLENGE-VERIFY-V1:",
        "SCP-CAPABILITY-DEFINITION-V1:",
        "SCP-BRIDGE-REGISTER-V1:",
        "SCP-BLOCK-NOTIFICATION-V1:",
        "SCP-EPOCH-ADVANCE-V1:",
        "SCP-KEY-REQUEST-V1:",
        "SCP-DID-AUTH-V1:",
        "SCP-KEYPACKAGE-ATTESTATION-V1:",
        "SCP-PUSH-REGISTER-V1:",
        "SCP-PUSH-DEREGISTER-V1:",
        "SCP-NODE-ID-V1:",
        NODE_BINDING_SEPARATOR,
        NODE_LIST_SEPARATOR,
        NODE_PROOF_SEPARATOR,
        CONTEXT_OPERATOR_SEPARATOR,
        CONTEXT_NODE_ADDRESS_SEPARATOR,
        CONTEXT_CHAIN_SEPARATOR,
        CONTEXT_RECEIPT_SEPARATOR,
    ];

    // HKDF/HMAC labels, used as info strings, salts, or trailing labels. A
    // prefix relation between two of them is structurally safe, but each
    // label must still be unique.
    let derivation_labels = [
        "scp-sender-key-v1",
        "scp-access-key-v1",
        "scp-private-state-v1",
        "scp-private-state-salt-v1",
        "scp-media-key-v1",
        "scp-pseudonym-secret-v1",
        "scp-participation-statement-v1",
        "scp-context-export-integrity-v1",
        "scp-psk-wrap-v1",
        "scp-test-attestation-v1:",
        "scp-pseudonym",
        "scp-pseudonym-v2",
        "scp-push-registration",
    ];

    let all: Vec<&str> = hash_domains
        .iter()
        .chain(&derivation_labels)
        .copied()
        .collect();
    for (i, a) in all.iter().enumerate() {
        for b in &all[i + 1..] {
            assert_ne!(a, b, "domain separators must be unique");
        }
    }
    for (i, a) in hash_domains.iter().enumerate() {
        for b in &hash_domains[i + 1..] {
            assert!(
                !a.starts_with(b) && !b.starts_with(a),
                "no hash domain separator may prefix another: '{a}' vs '{b}'"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// §25.36 Context operator vectors: Vector 92 (ContextOperatorBinding), 93
// (ContextNodeAddress), 94 (context chain entry) and 95 (context receipt)
// ---------------------------------------------------------------------------

const VECTOR_92_BINDING_HASH: &str =
    "3e557b07e2fbeb0f814eeb206e1b68cd27d647c41887afc61a99208f6fc44bc9";

fn vector_92_binding() -> ContextOperatorBinding {
    ContextOperatorBinding::from_bytes(&unhex(
        "0000004036323532636634363739656562343365356434663234353637323565643533383565643935323530643434653734653663356164616561643439396431333433d5adb473c01283dc9a7e7e998c1d312b3a353acf4863c13fe77efe304ad38bb3026fc6523b7b1e22ff3fbce8740cfbb7cbc816501864bf40f683db69c860d1a670fcd42118a68664c30ff6b44a74aa21fcee2e248e863b973dcad7c75dead5a763109548c3518205997cb3bc6468ee9a0206d1e88eb12ea698f5b5bfb75074e57f77d210f3517d2f5d37b1b92006cf88e16a5f939ad06728fdb06db63db606a1c9",
    ))
    .unwrap()
}

/// The `binding_hash` a reader holds from the invitation or the `0xFF02`
/// extension: Vector 92's printed hash.
fn vector_92_held() -> HeldBindingHash {
    HeldBindingHash::testing_only_from_bytes(unhex32(VECTOR_92_BINDING_HASH))
}

fn vector_92_verified() -> VerifiedContextOperatorBinding {
    VerifiedContextOperatorBinding::verify(
        vector_92_binding(),
        &vector_92_held(),
        &vector_41_resolved(),
    )
    .unwrap()
}

/// The verdict on a copy of `binding` against Vector 92's held hash and
/// Vector 41's log.
fn check_context_binding(binding: &ContextOperatorBinding) -> Result<(), ContextOperatorError> {
    VerifiedContextOperatorBinding::verify(
        binding.clone(),
        &vector_92_held(),
        &vector_41_resolved(),
    )
    .map(|_| ())
}

#[test]
fn vector_92_context_operator_binding() {
    let binding = vector_92_binding();
    assert_eq!(
        binding.context_id,
        hex::encode(sha256(b"scp-25-context-operator-context"))
    );
    // The operator is Vector 41's identity at its inception digest, whose
    // `#active` is §25.2's secondary key; the context key is the tertiary.
    assert_eq!(binding.operator, *vector_41_resolved().identifier());
    assert_eq!(binding.operator.as_bytes(), &unhex32(NODE_LIST_GOVERNOR));
    assert_eq!(binding.key_state_head, unhex32(NODE_LIST_SIGNING_HEAD));
    assert_eq!(binding.context_key.as_slice(), unhex(REFERENCE_KEYS[2].2));
    let hash = binding.binding_hash().unwrap();
    assert_eq!(hex::encode(hash), VECTOR_92_BINDING_HASH);
    assert_spec_preimage(
        "vector 92",
        "5343502d434f4e544558542d4f50455241544f522d56313a0000004036323532636634363739656562343365356434663234353637323565643533383565643935323530643434653734653663356164616561643439396431333433d5adb473c01283dc9a7e7e998c1d312b3a353acf4863c13fe77efe304ad38bb3026fc6523b7b1e22ff3fbce8740cfbb7cbc816501864bf40f683db69c860d1a670fcd42118a68664c30ff6b44a74aa21fcee2e248e863b973dcad7c75dead5a763",
        189,
        &hash,
    );
    assert_eq!(
        sign_prehash_rfc6979(&fixture_secret(1), &hash).unwrap(),
        binding.signature
    );
    assert_eq!(binding.to_bytes().unwrap().len(), 229);
    let verified = vector_92_verified();
    assert_eq!(verified.binding(), &binding);
    assert_eq!(*verified.context_key(), fixture_public(2));

    // Negative: signed by any key but the `#active` at key_state_head, the
    // context key included.
    for other in [0, 2] {
        let mut changed = binding.clone();
        changed.signature = sign_prehash_rfc6979(&fixture_secret(other), &hash).unwrap();
        assert_eq!(
            check_context_binding(&changed),
            Err(ContextOperatorError::Signature(
                P256Error::VerificationFailed
            ))
        );
    }
    // Negative: another held hash.
    let mut other_hash = unhex32(VECTOR_92_BINDING_HASH);
    other_hash[0] ^= 1;
    assert_eq!(
        VerifiedContextOperatorBinding::verify(
            binding.clone(),
            &HeldBindingHash::testing_only_from_bytes(other_hash),
            &vector_41_resolved()
        ),
        Err(ContextOperatorError::BindingMismatch)
    );
    // Negative: a binding held as is, naming another identity or a head
    // Vector 41's log does not hold.
    let mut changed = binding.clone();
    changed.operator = Identifier::from_bytes([0x11; 32]);
    let held = HeldBindingHash::testing_only_from_bytes(changed.binding_hash().unwrap());
    assert_eq!(
        VerifiedContextOperatorBinding::verify(changed, &held, &vector_41_resolved()),
        Err(ContextOperatorError::OperatorKey(
            AnchoredKeyError::IdentityMismatch
        ))
    );
    let mut changed = binding.clone();
    changed.key_state_head[31] ^= 1;
    let held = HeldBindingHash::testing_only_from_bytes(changed.binding_hash().unwrap());
    assert_eq!(
        VerifiedContextOperatorBinding::verify(changed, &held, &vector_41_resolved()),
        Err(ContextOperatorError::OperatorKey(
            AnchoredKeyError::HeadNotOnChain
        ))
    );
    // Negative: each field changed against the held hash.
    let mut changed = binding.clone();
    changed.context_id.push('0');
    assert_eq!(
        check_context_binding(&changed),
        Err(ContextOperatorError::BindingMismatch)
    );
    let mut changed = binding.clone();
    changed.key_state_head[31] ^= 1;
    assert_eq!(
        check_context_binding(&changed),
        Err(ContextOperatorError::BindingMismatch)
    );
    let mut changed = binding.clone();
    changed.context_key = fixture_node_key(0);
    assert_eq!(
        check_context_binding(&changed),
        Err(ContextOperatorError::BindingMismatch)
    );
    let mut changed = binding.clone();
    changed.signature[0] ^= 1;
    assert!(matches!(
        check_context_binding(&changed),
        Err(ContextOperatorError::Signature(_))
    ));

    // Negative: the high-`s` form of the valid signature is refused.
    let mut changed = binding;
    changed.signature = high_s_form(&changed.signature);
    assert_eq!(
        check_context_binding(&changed),
        Err(ContextOperatorError::Signature(P256Error::HighS))
    );
}

const VECTOR_93A_BYTES: &str = "3e557b07e2fbeb0f814eeb206e1b68cd27d647c41887afc61a99208f6fc44bc90000000000000001000000257773733a2f2f636f6e746578742d6e6f64652e6578616d706c652e636f6d2f7363702f7631000000206e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d890a93f4fca4f113c6a4ced4b04a16eb19072be1b408f5403f3118e248ced92e6683d6c7051f0663cf8916a169ab9008c5d42704588e1671b1a466b2b410ee8d";
const VECTOR_93B_BYTES: &str = "3e557b07e2fbeb0f814eeb206e1b68cd27d647c41887afc61a99208f6fc44bc900000000000000020000001f7773733a2f2f6272696467652e6578616d706c652e636f6d2f7363702f763100000061e77d53354271e4c1c3c319cf7b5cfcc23be431c2ec795d5b6ecf549355f156104102ed70d1c4b106466149a7d129630c11a20554683ae012fdffa56341d1c3230205de7df5512de2c640fb2dce84659ae7bbae26e7add7fb557d02b00a809ce0ae8f67d5b094954062fecb3df36973a9445e56409bbe46f207cc75e84bd958f3024b3021c5eaada057724a68185c79d9c6c46ddd834a271609793f62d868c2de3d";

/// Vector 93b's node: Vector 90's `NodeId`, Vector 48's bridge target and
/// wrapping key.
fn vector_93b_node() -> NodeAddress {
    NodeAddress::bridged(
        BridgeEndpoint::new("wss://bridge.example.com/scp/v1").unwrap(),
        NodeBridge {
            via: vector_49_entry(0).binding.node_id().unwrap(),
            bridge_target: BridgeTarget::new(unhex32(
                "4102ed70d1c4b106466149a7d129630c11a20554683ae012fdffa56341d1c323",
            ))
            .unwrap(),
            wrapping_key: P256PublicKey::from_sec1(&unhex(
                "0205de7df5512de2c640fb2dce84659ae7bbae26e7add7fb557d02b00a809ce0ae",
            ))
            .unwrap(),
        },
    )
}

const fn sequence(value: u64) -> NonZeroU64 {
    NonZeroU64::new(value).unwrap()
}

#[test]
fn vector_93_context_node_address() {
    let binding = vector_92_verified();

    // 93a: the production encoder builds the printed bytes from the inputs.
    let direct =
        NodeAddress::direct(NodeUrl::new("wss://context-node.example.com/scp/v1").unwrap());
    let digest_a =
        ContextNodeAddress::signing_digest(binding.binding_hash(), sequence(1), &direct).unwrap();
    assert_eq!(
        hex::encode(digest_a),
        "8eb373fec13ec613108bb88be54b523e3ea602c040129dd1a57503bf37bf09b6"
    );
    assert_spec_preimage(
        "vector 93a",
        "5343502d434f4e544558542d4e4f44452d414444524553532d56313a3e557b07e2fbeb0f814eeb206e1b68cd27d647c41887afc61a99208f6fc44bc90000000000000001000000257773733a2f2f636f6e746578742d6e6f64652e6578616d706c652e636f6d2f7363702f7631000000206e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        145,
        &digest_a,
    );
    let address_a = ContextNodeAddress {
        binding_hash: *binding.binding_hash(),
        sequence: sequence(1),
        node: direct,
        signature: sign_prehash_rfc6979(&fixture_secret(2), &digest_a).unwrap(),
    };
    assert_eq!(hex::encode(address_a.to_bytes().unwrap()), VECTOR_93A_BYTES);
    assert_eq!(
        ContextNodeAddress::from_bytes(&unhex(VECTOR_93A_BYTES)).unwrap(),
        address_a
    );

    let bridged = vector_93b_node();
    assert_eq!(
        hex::encode(bridged.bridge().unwrap().via.as_bytes()),
        "e77d53354271e4c1c3c319cf7b5cfcc23be431c2ec795d5b6ecf549355f15610"
    );
    let digest_b =
        ContextNodeAddress::signing_digest(binding.binding_hash(), sequence(2), &bridged).unwrap();
    assert_eq!(
        hex::encode(digest_b),
        "454a44bd6bcfa2dcb51b7dff549e94ff8d8e9b1b930644e9619bde7b680a5981"
    );
    assert_spec_preimage(
        "vector 93b",
        "5343502d434f4e544558542d4e4f44452d414444524553532d56313a3e557b07e2fbeb0f814eeb206e1b68cd27d647c41887afc61a99208f6fc44bc900000000000000020000001f7773733a2f2f6272696467652e6578616d706c652e636f6d2f7363702f763100000061e77d53354271e4c1c3c319cf7b5cfcc23be431c2ec795d5b6ecf549355f156104102ed70d1c4b106466149a7d129630c11a20554683ae012fdffa56341d1c3230205de7df5512de2c640fb2dce84659ae7bbae26e7add7fb557d02b00a809ce0ae",
        204,
        &digest_b,
    );
    let address_b = ContextNodeAddress {
        binding_hash: *binding.binding_hash(),
        sequence: sequence(2),
        node: bridged,
        signature: sign_prehash_rfc6979(&fixture_secret(2), &digest_b).unwrap(),
    };
    assert_eq!(hex::encode(address_b.to_bytes().unwrap()), VECTOR_93B_BYTES);

    // A reader holding nothing adopts 93a; holding 93a it adopts 93b; holding
    // 93b it refuses 93a, and holding 93a it refuses 93a again.
    let offered_a = ContextNodeAddress::from_bytes(&unhex(VECTOR_93A_BYTES)).unwrap();
    let offered_b = ContextNodeAddress::from_bytes(&unhex(VECTOR_93B_BYTES)).unwrap();
    let held_a = VerifiedContextNodeAddress::adopt(offered_a.clone(), &binding, None).unwrap();
    let held_b = VerifiedContextNodeAddress::adopt(offered_b, &binding, Some(&held_a)).unwrap();
    assert_eq!(held_b.sequence(), sequence(2));
    assert_eq!(
        VerifiedContextNodeAddress::adopt(offered_a.clone(), &binding, Some(&held_b)),
        Err(NodeAddressError::NotNewer {
            held: 2,
            offered: 1
        })
    );
    assert_eq!(
        VerifiedContextNodeAddress::adopt(offered_a, &binding, Some(&held_a)),
        Err(NodeAddressError::NotNewer {
            held: 1,
            offered: 1
        })
    );

    // Negative: under the operator's #active instead of context_key.
    let mut wrong_key = address_a.clone();
    wrong_key.signature = sign_prehash_rfc6979(&fixture_secret(1), &digest_a).unwrap();
    assert_eq!(
        VerifiedContextNodeAddress::adopt(wrong_key, &binding, None),
        Err(NodeAddressError::Signature(P256Error::VerificationFailed))
    );
    // Negative: the high-`s` form of each valid signature is refused.
    for address in [address_a, address_b] {
        let mut high = address;
        high.signature = high_s_form(&high.signature);
        assert_eq!(
            VerifiedContextNodeAddress::adopt(high, &binding, None),
            Err(NodeAddressError::Signature(P256Error::HighS))
        );
    }
}

/// Vector 93: a change to any one byte of either printed address is refused,
/// at decode or at verification.
#[test]
fn vector_93_refuses_any_changed_byte() {
    let binding = vector_92_verified();
    for printed in [VECTOR_93A_BYTES, VECTOR_93B_BYTES] {
        let bytes = unhex(printed);
        for i in 0..bytes.len() {
            let mut flipped = bytes.clone();
            flipped[i] ^= 1;
            let refused = ContextNodeAddress::from_bytes(&flipped)
                .and_then(|a| VerifiedContextNodeAddress::adopt(a, &binding, None))
                .is_err();
            assert!(refused, "byte {i} of {printed}");
        }
    }
}

fn vector_94_entry() -> ContextChainEntry {
    ContextChainEntry {
        binding_hash: unhex32(VECTOR_92_BINDING_HASH),
        position: 7,
        item_hash: submission_hash(b"scp-25-context-submission"),
        previous_hash: sha256(b"scp-25-context-chain-entry-6"),
        signature: unhex(
            "1e0bca03fafee8fa0271cb214fbb09fdceffb5bc46b8670abd6bd48d9be8d24125915ca94bdcf8fca33950bcd1fdf8b6cb25d417a3be855d05b0281089974886",
        )
        .try_into()
        .unwrap(),
    }
}

fn vector_95_receipt() -> ContextReceipt {
    ContextReceipt {
        binding_hash: unhex32(VECTOR_92_BINDING_HASH),
        position: 7,
        submission_hash: submission_hash(b"scp-25-context-submission"),
        signature: unhex(
            "a524e283d0cad9ee2f6c2a25b9a2e36d81b3c48066e1baf5e68854301c2f8d1013ab0fe20c08a327a9ddf2a911b730afc5f568221a137f1255ba32afa3b4bdf1",
        )
        .try_into()
        .unwrap(),
    }
}

#[test]
fn vector_94_context_chain_entry() {
    let binding = vector_92_verified();
    let entry = vector_94_entry();
    assert_eq!(
        entry.item_hash,
        unhex32("15ced3699799818d385b605e1ef4d0db4b3d316b212b707bba4fddc642b1daf3")
    );
    assert_eq!(
        entry.previous_hash,
        unhex32("256e09d2a7df03b2dc686d806fe1c7933b4fd1b1c9aae033e764c35917e9b4fa")
    );
    let digest = entry.digest();
    assert_eq!(
        hex::encode(digest),
        "180ee7f6339f466dbc2d645c0334ddc493e6c834cc9dce868c210a71fce80589"
    );
    assert_spec_preimage(
        "vector 94",
        "5343502d434f4e544558542d434841494e2d56313a3e557b07e2fbeb0f814eeb206e1b68cd27d647c41887afc61a99208f6fc44bc9000000000000000715ced3699799818d385b605e1ef4d0db4b3d316b212b707bba4fddc642b1daf3256e09d2a7df03b2dc686d806fe1c7933b4fd1b1c9aae033e764c35917e9b4fa",
        125,
        &digest,
    );
    assert_eq!(
        sign_prehash_rfc6979(&fixture_secret(2), &digest).unwrap(),
        entry.signature
    );
    assert_eq!(
        VerifiedContextChainEntry::verify(entry.clone(), &binding)
            .unwrap()
            .entry(),
        &entry
    );

    // Negative: the first position's `SHA-256(0x00)` previous_hash at
    // position 7, even under a valid signature.
    assert_eq!(FIRST_PREVIOUS_HASH, sha256(&[0x00]));
    let mut changed = entry.clone();
    changed.previous_hash = FIRST_PREVIOUS_HASH;
    changed.signature = sign_prehash_rfc6979(&fixture_secret(2), &changed.digest()).unwrap();
    assert_eq!(
        VerifiedContextChainEntry::verify(changed, &binding),
        Err(ContextOperatorError::PreviousHash)
    );

    // Negative: under the operator's #active, each field changed, high s.
    let mut changed = entry.clone();
    changed.signature = sign_prehash_rfc6979(&fixture_secret(1), &digest).unwrap();
    assert_eq!(
        VerifiedContextChainEntry::verify(changed, &binding),
        Err(ContextOperatorError::Signature(
            P256Error::VerificationFailed
        ))
    );
    let mut changed = entry.clone();
    changed.position = 6;
    assert!(VerifiedContextChainEntry::verify(changed, &binding).is_err());
    let mut changed = entry.clone();
    changed.item_hash[0] ^= 1;
    assert!(VerifiedContextChainEntry::verify(changed, &binding).is_err());
    let mut changed = entry.clone();
    changed.previous_hash[0] ^= 1;
    assert!(VerifiedContextChainEntry::verify(changed, &binding).is_err());
    let mut changed = entry.clone();
    changed.binding_hash[0] ^= 1;
    assert_eq!(
        VerifiedContextChainEntry::verify(changed, &binding),
        Err(ContextOperatorError::BindingMismatch)
    );
    let mut changed = entry;
    changed.signature = high_s_form(&changed.signature);
    assert_eq!(
        VerifiedContextChainEntry::verify(changed, &binding),
        Err(ContextOperatorError::Signature(P256Error::HighS))
    );
}

#[test]
fn vector_95_context_receipt() {
    let binding = vector_92_verified();
    let receipt = vector_95_receipt();
    // One submission's receipt carries the hash Vector 94's entry prints.
    assert_eq!(
        receipt.submission_hash,
        unhex32("15ced3699799818d385b605e1ef4d0db4b3d316b212b707bba4fddc642b1daf3")
    );
    let digest = receipt.digest();
    assert_eq!(
        hex::encode(digest),
        "7a6e026d8dadbc8e662cf37857053e226d9a433770e514e5aa0c24b3a7f1fbea"
    );
    assert_spec_preimage(
        "vector 95",
        "5343502d434f4e544558542d524543454950542d56313a3e557b07e2fbeb0f814eeb206e1b68cd27d647c41887afc61a99208f6fc44bc9000000000000000715ced3699799818d385b605e1ef4d0db4b3d316b212b707bba4fddc642b1daf3",
        95,
        &digest,
    );
    assert_eq!(
        sign_prehash_rfc6979(&fixture_secret(2), &digest).unwrap(),
        receipt.signature
    );
    assert_eq!(
        VerifiedContextReceipt::verify(receipt.clone(), &binding)
            .unwrap()
            .receipt(),
        &receipt
    );

    // Negative: under the operator's #active, each field changed, high s.
    let mut changed = receipt.clone();
    changed.signature = sign_prehash_rfc6979(&fixture_secret(1), &digest).unwrap();
    assert_eq!(
        VerifiedContextReceipt::verify(changed, &binding),
        Err(ContextOperatorError::Signature(
            P256Error::VerificationFailed
        ))
    );
    let mut changed = receipt.clone();
    changed.position = 8;
    assert!(VerifiedContextReceipt::verify(changed, &binding).is_err());
    let mut changed = receipt.clone();
    changed.submission_hash[0] ^= 1;
    assert!(VerifiedContextReceipt::verify(changed, &binding).is_err());
    let mut changed = receipt.clone();
    changed.binding_hash[0] ^= 1;
    assert_eq!(
        VerifiedContextReceipt::verify(changed, &binding),
        Err(ContextOperatorError::BindingMismatch)
    );
    let mut changed = receipt;
    changed.signature = high_s_form(&changed.signature);
    assert_eq!(
        VerifiedContextReceipt::verify(changed, &binding),
        Err(ContextOperatorError::Signature(P256Error::HighS))
    );
}
