//! §25 Cryptographic Test Vectors — the Rust assertions for the vectors whose
//! production builders live in `scp-protocol` and `scp-runtime`.
//!
//! Every value below is printed in `.docs/specs/25-test-vectors.md` and
//! produced by `scripts/gen-test-vectors-p256.py`. Each test feeds the spec
//! inputs to the production builder and asserts the spec output. A test also
//! hashes the spec's printed preimage and compares that digest with the
//! production result, which proves the production preimage is byte-identical
//! to the printed one.
//!
//! Vectors asserted elsewhere: V7 (`compute_vote_hash`) and V27
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

use sha2::{Digest, Sha256};

use scp_crypto::p256::{
    P256Error, P256PublicKey, P256SecretKey, SeedLabel, sign_prehash_rfc6979, verify_prehash_strict,
};
use scp_did::{DID, SigningKeyId};
use scp_protocol::context::governance::{GovernanceAction, compute_proposal_id};
use scp_protocol::context::outlets::interface::InterfaceOffer;
use scp_protocol::crypto::canonical::{CanonicalField, canonical_hash_bytes};
use scp_protocol::crypto::sender_keys::key_protocol_verify::build_hpke_info;
use scp_protocol::envelope::inner::compute_canonical_hash;
use scp_protocol::envelope::padding::{BUCKET_SIZES, pad_to_bucket, strip_padding};
use scp_protocol::envelope::{InnerEnvelopeParams, MessageType};
use scp_protocol::identity::attestation::IdentityLinkAttestation;
use scp_runtime::sync::weeks_offline::{ResetReason, ResetRequest};

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

fn fixture_identifier_bytes(role: &str) -> [u8; 32] {
    sha256(format!("SCP test vector identifier {role}").as_bytes())
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
        hex::encode(&hash),
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
        &hash.try_into().unwrap(),
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
        hex::encode(&hash),
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
        &hash.try_into().unwrap(),
        "5a52a4b0e87965a109a82439cd905eae241543be579e42d963713feae3f312406c2b0fdc15deaf5d3d40b41990f147c4c63cd702e16d2e656386bcf922a97203",
    );
}

// ---------------------------------------------------------------------------
// §25.5 Vote signing
// ---------------------------------------------------------------------------

/// The production `compute_vote_hash` is private; the in-module test
/// `spec_25_vector_7_vote_canonical_hash` in `scp-protocol` asserts the
/// canonical hash through it. This test asserts the printed preimage and the
/// signature over that hash.
#[test]
fn vector_7_vote_signature() {
    let hash = unhex32("3a0c35742f6ddd8c3a935f924ede5ca85ad905c1312ca99e18eb618223769c67");
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
// §25.9 Key continuity fingerprint
// ---------------------------------------------------------------------------

/// One party's §9.11 block: identifier, `BE32(count)`, root-set members, and
/// the `#active` key, every key a 33-byte compressed point.
fn continuity_block(identifier: &[u8; 32], root_set: &[[u8; 33]], active: &[u8; 33]) -> Vec<u8> {
    let mut block = identifier.to_vec();
    block.extend_from_slice(&(root_set.len() as u32).to_be_bytes());
    for member in root_set {
        block.extend_from_slice(member);
    }
    block.extend_from_slice(active);
    block
}

/// The §9.11 two-party fingerprint preimage, ordering the blocks by
/// identifier regardless of which party is supplied first.
fn continuity_preimage(
    first: (&[u8; 32], &[[u8; 33]], &[u8; 33]),
    second: (&[u8; 32], &[[u8; 33]], &[u8; 33]),
) -> Vec<u8> {
    let (lo, hi) = if first.0 <= second.0 {
        (first, second)
    } else {
        (second, first)
    };
    let mut preimage = b"SCP-KEY-CONTINUITY-V1:".to_vec();
    preimage.extend(continuity_block(lo.0, lo.1, lo.2));
    preimage.extend(continuity_block(hi.0, hi.1, hi.2));
    preimage
}

/// §25.9 Vectors 20 and 38, asserted over the spec bytes with primitives.
///
/// Production `compute_key_continuity_fingerprint` is the pre-§9.11
/// construction over DID strings and 32-byte keys; the §9.11 construction
/// takes root sets, which production gains with the key-event-log data model
/// (slice S1, SCP-308). The slice that introduces root sets replaces
/// `compute_key_continuity_fingerprint` with the §9.11 construction and
/// asserts these two vectors through it; slices S9 and S10 wire its callers.
#[test]
fn vectors_20_38_key_continuity_fingerprint() {
    let key = |seed: u8| {
        P256SecretKey::from_seed(SeedLabel::TestVectorKey, &[seed; 32])
            .public_key()
            .to_compressed()
    };
    let id_a = fixture_identifier_bytes("A");
    let id_b = fixture_identifier_bytes("B");
    let a_root = [key(0x41), key(0x42)];
    let a_active = key(0x43);
    let b_root = [key(0x44)];
    let b_active = key(0x45);

    let preimage = continuity_preimage((&id_a, &a_root, &a_active), (&id_b, &b_root, &b_active));
    assert_eq!(preimage.len(), 259);
    assert_eq!(
        hex::encode(&preimage),
        "5343502d4b45592d434f4e54494e554954592d56313abcdcea594dbb12037950ee2d0f356300ea8e37d9dfb01b87c6249033e871095e0000000202542c432f5a8f756764e2f18c8125e5338e61ba1540057f8c6ee666b07c7aa8d102b945d8e097faded7a70e6c18134caf2a9521bc2b05af0becdf99adc9212789d002e264c93973b59b7699221aff574dcde04a79347335c4f9c4a643c7525cd9b975f30cbaf928e7bd22a3d2f4aecf6573120a0cdddd8600aa685f61e7f72c78e8560000000102c4ed969c4a9e294576355bbeb14270e54b51bf6f00b6d1b587676fd0865ee8a8027a3f3aad1b66ab82d3d67a2e3af15f89f304c4b6369accc5715dda72d2800512"
    );
    assert_eq!(
        hex::encode(sha256(&preimage)),
        "c6cdaa8eeb6d04798e308ee0f7c1ecdc29874f8f4411c7c9df921539ad975466"
    );

    // Vector 38: party B supplied first yields the same preimage.
    let reversed = continuity_preimage((&id_b, &b_root, &b_active), (&id_a, &a_root, &a_active));
    assert_eq!(reversed, preimage);
    assert_eq!(
        hex::encode(sha256(&reversed)),
        "c6cdaa8eeb6d04798e308ee0f7c1ecdc29874f8f4411c7c9df921539ad975466"
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
        DidPublicKeyResolver, canonical_attestation_bytes, verify_attestation,
    };

    struct Resolver(Vec<u8>);
    impl DidPublicKeyResolver for Resolver {
        fn resolve_public_key(&self, _did: &str) -> Result<Vec<u8>, TrustError> {
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
    verify_attestation(&signed, &resolver, &clock).expect("signature must verify");

    let mut tampered = signed;
    tampered.subject = ID_ISSUER.into();
    assert!(
        verify_attestation(&tampered, &resolver, &clock).is_err(),
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
/// Production `KeyPackageAttestation` still carries 32-byte keys, so it cannot
/// build this 65-byte-key preimage. PR4 of the identity plan's S0 slice
/// moves it to 65-byte P-256 keys and replaces the 32-byte `vector_37_*`
/// tests in `scp-mls` with an assertion of this value through the struct.
#[test]
fn vector_37_keypackage_attestation() {
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
        "SCP-CLAIM-V1:",
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
        "SCP-BRIDGE-REGISTER-V1:",
        "SCP-BLOCK-NOTIFICATION-V1:",
        "SCP-EPOCH-ADVANCE-V1:",
        "SCP-KEY-REQUEST-V1:",
        "SCP-DID-AUTH-V1:",
        "SCP-KEYPACKAGE-ATTESTATION-V1:",
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
