//! §25 Cryptographic Test Vectors — reference implementation.
//!
//! These tests produce known-answer outputs for all cryptographic constructions
//! in the SCP protocol. Independent implementations MUST reproduce these outputs
//! to pass interoperability testing.
//!
//! Run with `--nocapture` to see hex-encoded intermediate and final values:
//! ```bash
//! cargo test -p scp-core --test test_vectors -- --nocapture
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use ed25519_dalek::{Signer, Verifier};
use sha2::{Digest, Sha256};

use scp_core::crypto::canonical::{CanonicalField, canonical_hash, canonical_hash_bytes};
use scp_core::crypto::key_continuity::{
    KeyContinuityParty, compute_key_continuity_fingerprint, fingerprint_to_decimal,
};
use scp_core::envelope::padding::{BUCKET_SIZES, pad_to_bucket, strip_padding};

// ---------------------------------------------------------------------------
// §25.2 Reference Key Material (RFC 8032 §7.1)
// ---------------------------------------------------------------------------

/// RFC 8032 §7.1 Test Vector 1 — Ed25519 seed.
const REF_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

/// RFC 8032 §7.1 Test Vector 1 — Ed25519 public key.
const REF_PUBKEY: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

/// RFC 8032 §7.1 Test Vector 2 — secondary Ed25519 public key.
const REF_PUBKEY_2: [u8; 32] = [
    0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
    0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c,
];

/// RFC 8032 §7.1 Test Vector 3 — third Ed25519 public key (used for agent key).
const REF_PUBKEY_3: [u8; 32] = [
    0xfc, 0x51, 0xcd, 0x8e, 0x62, 0x18, 0xa1, 0xa3, 0x8d, 0xa4, 0x7e, 0xd0, 0x02, 0x30, 0xf0, 0x58,
    0x08, 0x16, 0xed, 0x13, 0xba, 0x33, 0x03, 0xac, 0x5d, 0xeb, 0x91, 0x15, 0x48, 0x90, 0x80, 0x25,
];

/// SHA-256(0x00) — absent optional field sentinel.
const ABSENT_SENTINEL: [u8; 32] = [
    0x6e, 0x34, 0x0b, 0x9c, 0xff, 0xb3, 0x7a, 0x98, 0x9c, 0xa5, 0x44, 0xe6, 0xbb, 0x78, 0x0a, 0x2c,
    0x78, 0x90, 0x1d, 0x3f, 0xb3, 0x37, 0x38, 0x76, 0x85, 0x11, 0xa3, 0x06, 0x17, 0xaf, 0xa0, 0x1d,
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn print_vec(label: &str, bytes: &[u8]) {
    println!("  {label}: 0x{} ({} bytes)", hex(bytes), bytes.len());
}

// ---------------------------------------------------------------------------
// §25.2 Ed25519 Sanity Check
// ---------------------------------------------------------------------------

#[test]
fn vector_0_ed25519_sanity_check() {
    println!("=== Vector 0: Ed25519 Sanity Check ===");
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&REF_SEED);
    let derived_pubkey = signing_key.verifying_key().to_bytes();
    print_vec("Seed", &REF_SEED);
    print_vec("Derived pubkey", &derived_pubkey);
    print_vec("Expected pubkey", &REF_PUBKEY);
    assert_eq!(
        derived_pubkey, REF_PUBKEY,
        "Ed25519 implementation must derive correct public key from RFC 8032 §7.1 seed"
    );
}

// ---------------------------------------------------------------------------
// §25.3 Canonical Hash Construction Vectors
// ---------------------------------------------------------------------------

#[test]
fn vector_1_domain_separator_encoding() {
    println!("=== Vector 1: Domain Separator Encoding ===");
    let domain = "SCP-INNER-ENVELOPE-V1:";
    let domain_bytes = domain.as_bytes();
    print_vec("Domain separator bytes", domain_bytes);

    let expected = b"SCP-INNER-ENVELOPE-V1:";
    assert_eq!(domain_bytes, expected);
    assert_eq!(
        hex(domain_bytes),
        "5343502d494e4e45522d454e56454c4f50452d56313a"
    );
}

#[test]
fn vector_2_variable_length_field_encoding() {
    println!("=== Vector 2: Variable-Length Field Encoding ===");
    let field = "did:dht:z6MkTest";
    let field_bytes = field.as_bytes();

    // Build manually: BE32(16) || field_bytes
    let mut expected = Vec::new();
    expected.extend_from_slice(&16u32.to_be_bytes());
    expected.extend_from_slice(field_bytes);
    print_vec("Length prefix", &16u32.to_be_bytes());
    print_vec("Field bytes", field_bytes);
    print_vec("Combined", &expected);

    assert_eq!(hex(&expected), "000000106469643a6468743a7a364d6b54657374");

    // Verify via canonical_hash_bytes
    let canonical = canonical_hash_bytes(b"", &[CanonicalField::VarBytes(field_bytes)]);
    assert_eq!(canonical, expected);
}

#[test]
fn vector_3_fixed_length_u64_encoding() {
    println!("=== Vector 3: Fixed-Length u64 Encoding ===");
    let value: u64 = 1_700_000_000;
    let encoded = value.to_be_bytes();
    print_vec("u64 BE bytes", &encoded);
    assert_eq!(hex(&encoded), "000000006553f100");

    // Verify via canonical_hash_bytes
    let canonical = canonical_hash_bytes(b"", &[CanonicalField::U64(value)]);
    assert_eq!(canonical, encoded);
}

#[test]
fn vector_4_absent_sentinel() {
    println!("=== Vector 4: Absent Optional Field Sentinel ===");
    let sentinel: [u8; 32] = Sha256::digest([0x00]).into();
    print_vec("SHA-256(0x00)", &sentinel);
    assert_eq!(
        hex(&sentinel),
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
    );
    assert_eq!(sentinel, ABSENT_SENTINEL);

    // Verify via canonical_hash_bytes
    let canonical = canonical_hash_bytes(b"", &[CanonicalField::Absent]);
    assert_eq!(canonical, sentinel);
}

// ---------------------------------------------------------------------------
// §25.4 InnerEnvelope Signing Vectors
// ---------------------------------------------------------------------------

#[test]
fn vector_5_minimal_inner_envelope_canonical_hash() {
    println!("=== Vector 5: Minimal InnerEnvelope Canonical Hash ===");

    let context_id = b"test-context-01";
    let sender_did = b"did:dht:z6MkTest";
    let epoch: u64 = 1;
    let generation: u64 = 0;
    let sequence: u64 = 0;
    let timestamp: u64 = 1_700_000_000;
    let payload_hash: [u8; 32] = Sha256::digest(b"hello world").into();
    let signing_key_id = b"#active";

    print_vec("payload_hash (SHA-256(\"hello world\"))", &payload_hash);
    assert_eq!(
        hex(&payload_hash),
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    );

    // Build canonical hash input using the public API.
    // Note: The actual InnerEnvelope canonical hash in the code includes
    // version (U16) and message_type (U8) fields. This test vector verifies
    // the canonical hash construction per §25.4's specified field order.
    let hash = canonical_hash(
        "SCP-INNER-ENVELOPE-V1:",
        &[
            CanonicalField::VarBytes(context_id),
            CanonicalField::VarBytes(sender_did),
            CanonicalField::U64(epoch),
            CanonicalField::U64(generation),
            CanonicalField::U64(sequence),
            CanonicalField::U64(timestamp),
            CanonicalField::VarBytes(&payload_hash),
            CanonicalField::Absent, // provenance_hash absent
            CanonicalField::VarBytes(signing_key_id),
        ],
    );

    // Manually construct the same bytes for independent verification.
    let bytes = canonical_hash_bytes(
        b"SCP-INNER-ENVELOPE-V1:",
        &[
            CanonicalField::VarBytes(context_id),
            CanonicalField::VarBytes(sender_did),
            CanonicalField::U64(epoch),
            CanonicalField::U64(generation),
            CanonicalField::U64(sequence),
            CanonicalField::U64(timestamp),
            CanonicalField::VarBytes(&payload_hash),
            CanonicalField::Absent,
            CanonicalField::VarBytes(signing_key_id),
        ],
    );

    println!("  Canonical hash input length: {} bytes", bytes.len());
    // 22 (domain) + (4+15) + (4+16) + 8 + 8 + 8 + 8 + (4+32) + 32 (Absent: raw, no prefix) + (4+7) = 172
    assert_eq!(bytes.len(), 172, "canonical input must be 172 bytes");
    print_vec("Canonical hash", &hash);

    // Verify: SHA-256 of the bytes matches the hash
    let manual_hash: [u8; 32] = Sha256::digest(&bytes).into();
    assert_eq!(hash, manual_hash);

    // Sign with reference key and verify
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&REF_SEED);
    let signature = signing_key.sign(&hash);
    print_vec("Signature", signature.to_bytes().as_slice());

    signing_key
        .verifying_key()
        .verify(&hash, &signature)
        .expect("Ed25519 signature must verify");
}

#[test]
fn vector_6_inner_envelope_with_provenance() {
    println!("=== Vector 6: InnerEnvelope with Provenance ===");

    let provenance_hash: [u8; 32] = [
        0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
        0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45,
        0x67, 0x89,
    ];

    let payload_hash: [u8; 32] = Sha256::digest(b"hello world").into();

    // Same as Vector 5 but with real provenance hash.
    let hash_with_provenance = canonical_hash(
        "SCP-INNER-ENVELOPE-V1:",
        &[
            CanonicalField::VarBytes(b"test-context-01"),
            CanonicalField::VarBytes(b"did:dht:z6MkTest"),
            CanonicalField::U64(1),
            CanonicalField::U64(0),
            CanonicalField::U64(0),
            CanonicalField::U64(1_700_000_000),
            CanonicalField::VarBytes(&payload_hash),
            CanonicalField::VarBytes(&provenance_hash), // present provenance
            CanonicalField::VarBytes(b"#active"),
        ],
    );

    let hash_without = canonical_hash(
        "SCP-INNER-ENVELOPE-V1:",
        &[
            CanonicalField::VarBytes(b"test-context-01"),
            CanonicalField::VarBytes(b"did:dht:z6MkTest"),
            CanonicalField::U64(1),
            CanonicalField::U64(0),
            CanonicalField::U64(0),
            CanonicalField::U64(1_700_000_000),
            CanonicalField::VarBytes(&payload_hash),
            CanonicalField::Absent,
            CanonicalField::VarBytes(b"#active"),
        ],
    );

    print_vec("Hash with provenance", &hash_with_provenance);
    print_vec("Hash without provenance", &hash_without);

    assert_ne!(
        hash_with_provenance, hash_without,
        "provenance presence must change the canonical hash"
    );
}

// ---------------------------------------------------------------------------
// §25.5 Vote Signing Vectors
// ---------------------------------------------------------------------------

#[test]
fn vector_7_approval_vote() {
    println!("=== Vector 7: Approval Vote ===");

    let proposal_id: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30,
        0x31, 0x32,
    ];
    let voter_did = b"did:dht:z6MkVoter";
    let timestamp: u64 = 1_700_000_000;

    // The code's compute_vote_hash (pub(crate)) uses canonical_hash with:
    //   domain: "SCP-VOTE-V1:"
    //   fields: proposal_id (Fixed32) || voter_did (VarBytes) || vote_json (VarBytes) || timestamp (U64)
    //
    // We reproduce this construction using the public canonical_hash API.
    // The vote value is serialized as JSON by serde — "\"Approve\"" for VoteType::Approve.
    let vote_json = b"\"Approve\"";

    let hash = canonical_hash(
        "SCP-VOTE-V1:",
        &[
            CanonicalField::Fixed32(&proposal_id),
            CanonicalField::VarBytes(voter_did),
            CanonicalField::VarBytes(vote_json),
            CanonicalField::U64(timestamp),
        ],
    );

    let bytes = canonical_hash_bytes(
        b"SCP-VOTE-V1:",
        &[
            CanonicalField::Fixed32(&proposal_id),
            CanonicalField::VarBytes(voter_did),
            CanonicalField::VarBytes(vote_json),
            CanonicalField::U64(timestamp),
        ],
    );

    println!("  Canonical hash input length: {} bytes", bytes.len());
    // 12 (domain) + 32 (Fixed32) + (4+17) + (4+9) + 8 = 12 + 32 + 21 + 13 + 8 = 86
    assert_eq!(bytes.len(), 86);
    print_vec("Vote canonical hash", &hash);

    // Verify: SHA-256 of raw bytes equals canonical_hash output
    let manual_hash: [u8; 32] = Sha256::digest(&bytes).into();
    assert_eq!(hash, manual_hash);

    // Sign and verify with reference key.
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&REF_SEED);
    let signature = signing_key.sign(&hash);
    print_vec("Vote signature", signature.to_bytes().as_slice());

    signing_key
        .verifying_key()
        .verify(&hash, &signature)
        .expect("vote signature must verify");
}

// ---------------------------------------------------------------------------
// §25.6 Reset Request Signing Vectors
// ---------------------------------------------------------------------------

#[test]
fn vector_8_reset_request() {
    println!("=== Vector 8: Reset Request ===");

    let context_id = b"sync-test-context";
    let requester_did = b"did:dht:z6MkSync";
    let nonce: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30,
        0x31, 0x32,
    ];
    let timestamp: u64 = 1_700_000_000;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"SCP-RESET-REQUEST-V1:");
    bytes.extend_from_slice(&(context_id.len() as u32).to_be_bytes());
    bytes.extend_from_slice(context_id);
    bytes.extend_from_slice(&(requester_did.len() as u32).to_be_bytes());
    bytes.extend_from_slice(requester_did);
    bytes.extend_from_slice(&nonce); // Fixed-length, no prefix per spec
    bytes.extend_from_slice(&timestamp.to_be_bytes());

    println!("  Canonical hash input length: {} bytes", bytes.len());
    assert_eq!(
        bytes.len(),
        102,
        "reset request must be 102 bytes per §25.6"
    );

    let hash: [u8; 32] = Sha256::digest(&bytes).into();
    print_vec("Reset request canonical hash", &hash);

    // Sign with reference key
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&REF_SEED);
    let signature = signing_key.sign(&hash);
    print_vec("Reset request signature", signature.to_bytes().as_slice());

    signing_key
        .verifying_key()
        .verify(&hash, &signature)
        .expect("reset request signature must verify");
}

// ---------------------------------------------------------------------------
// §25.7 Envelope Padding Vectors
// ---------------------------------------------------------------------------

#[test]
fn vector_9_empty_payload_padding() {
    println!("=== Vector 9: Empty Payload Padding ===");
    let padded = pad_to_bucket(b"").unwrap();
    println!("  Total size: {} bytes", padded.len());
    println!(
        "  Last 4 bytes (length suffix): 0x{}",
        hex(&padded[252..256])
    );

    assert_eq!(padded.len(), 256);
    // Last 4 bytes: BE32(0) = 0x00000000
    assert_eq!(&padded[252..256], &0u32.to_be_bytes());
    // First 252 bytes: all zeros (no payload + zero padding)
    assert!(padded[..252].iter().all(|&b| b == 0));
}

#[test]
fn vector_10_small_payload_padding() {
    println!("=== Vector 10: Small Payload Padding ===");
    let payload = b"hello";
    let padded = pad_to_bucket(payload).unwrap();
    println!("  Total size: {} bytes", padded.len());

    assert_eq!(padded.len(), 256);
    assert_eq!(&padded[..5], b"hello");
    // Zero padding between payload end and length suffix
    assert!(padded[5..252].iter().all(|&b| b == 0));
    // Last 4 bytes: BE32(5) = 0x00000005
    assert_eq!(&padded[252..256], &5u32.to_be_bytes());

    // Roundtrip
    let recovered = strip_padding(&padded).unwrap();
    assert_eq!(recovered, payload);
}

#[test]
fn vector_11_exact_bucket_boundary() {
    println!("=== Vector 11: Exact Bucket Boundary ===");
    let payload = vec![0xAB; 252];
    let padded = pad_to_bucket(&payload).unwrap();
    println!("  Total size: {} bytes", padded.len());

    assert_eq!(padded.len(), 256);
    assert_eq!(&padded[..252], payload.as_slice());
    // No zero padding (exact fit)
    assert_eq!(&padded[252..256], &252u32.to_be_bytes());

    let recovered = strip_padding(&padded).unwrap();
    assert_eq!(recovered, payload);
}

#[test]
fn vector_12_one_byte_over_boundary() {
    println!("=== Vector 12: One Byte Over Bucket Boundary ===");
    let payload = vec![0xAB; 253];
    let padded = pad_to_bucket(&payload).unwrap();
    println!("  Total size: {} bytes", padded.len());

    assert_eq!(padded.len(), 1024);
    assert_eq!(&padded[..253], payload.as_slice());
    // 1024 - 253 - 4 = 767 zero bytes
    assert!(padded[253..1020].iter().all(|&b| b == 0));
    assert_eq!(&padded[1020..1024], &253u32.to_be_bytes());

    let recovered = strip_padding(&padded).unwrap();
    assert_eq!(recovered, payload);
}

#[test]
fn vector_13_maximum_payload() {
    println!("=== Vector 13: Maximum Payload ===");
    let payload = vec![0x42; 262_140];
    let padded = pad_to_bucket(&payload).unwrap();
    println!("  Total size: {} bytes", padded.len());

    assert_eq!(padded.len(), 262_144);
    assert_eq!(&padded[..262_140], payload.as_slice());
    assert_eq!(&padded[262_140..262_144], &262_140u32.to_be_bytes());

    let recovered = strip_padding(&padded).unwrap();
    assert_eq!(recovered.len(), payload.len());
}

#[test]
fn vector_14_payload_too_large() {
    println!("=== Vector 14: Payload Too Large ===");
    let payload = vec![0x00; 262_141];
    let result = pad_to_bucket(&payload);
    assert!(
        result.is_err(),
        "payload exceeding max bucket must return error"
    );
    println!("  Error: {:?}", result.unwrap_err());
}

#[test]
fn padding_bucket_sizes_are_correct() {
    println!("=== Padding Bucket Sizes ===");
    assert_eq!(BUCKET_SIZES, [256, 1024, 4096, 16384, 65536, 262_144]);
}

// ---------------------------------------------------------------------------
// §25.8 Merkle Tree Vectors (RFC 6962)
// ---------------------------------------------------------------------------

/// Leaf hash: SHA-256(0x00 || data)
fn leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(data);
    hasher.finalize().into()
}

/// Interior hash: SHA-256(0x01 || left || right)
fn interior_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

#[test]
fn vector_15_empty_merkle_tree() {
    println!("=== Vector 15: Empty Merkle Tree ===");
    let empty_root: [u8; 32] = Sha256::digest(b"").into();
    print_vec("SHA-256(\"\")", &empty_root);
    assert_eq!(
        hex(&empty_root),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn vector_16_single_leaf() {
    println!("=== Vector 16: Single Leaf ===");
    let data = b"Hello"; // 0x48656c6c6f
    let leaf = leaf_hash(data);
    print_vec("Input", data);
    print_vec("Leaf hash (SHA-256(0x00 || data))", &leaf);

    // Root = leaf hash for single leaf
    let root = leaf;
    print_vec("Root", &root);

    // Verify construction
    let mut expected_hasher = Sha256::new();
    expected_hasher.update([0x00]);
    expected_hasher.update(data);
    let expected: [u8; 32] = expected_hasher.finalize().into();
    assert_eq!(root, expected);
}

#[test]
fn vector_17_two_leaves() {
    println!("=== Vector 17: Two Leaves ===");
    let event_1 = b"Event1"; // 0x4576656e7431
    let event_2 = b"Event2"; // 0x4576656e7432

    let leaf_1 = leaf_hash(event_1);
    let leaf_2 = leaf_hash(event_2);
    print_vec("Leaf 1", &leaf_1);
    print_vec("Leaf 2", &leaf_2);

    let root = interior_hash(&leaf_1, &leaf_2);
    print_vec("Root (SHA-256(0x01 || leaf1 || leaf2))", &root);
}

#[test]
fn vector_18_three_leaves_unbalanced() {
    println!("=== Vector 18: Three Leaves (Unbalanced) ===");
    let leaf_1 = leaf_hash(b"A");
    let leaf_2 = leaf_hash(b"B");
    let leaf_3 = leaf_hash(b"C");
    print_vec("Leaf A", &leaf_1);
    print_vec("Leaf B", &leaf_2);
    print_vec("Leaf C", &leaf_3);

    // RFC 6962: pair (leaf_1, leaf_2), then pair (interior_1, leaf_3)
    let interior_1 = interior_hash(&leaf_1, &leaf_2);
    print_vec("Interior 1 (A|B)", &interior_1);

    let root = interior_hash(&interior_1, &leaf_3);
    print_vec("Root (interior1 | C)", &root);
}

#[test]
fn vector_19_four_leaves_balanced() {
    println!("=== Vector 19: Four Leaves (Balanced) ===");
    let leaf_1 = leaf_hash(b"A");
    let leaf_2 = leaf_hash(b"B");
    let leaf_3 = leaf_hash(b"C");
    let leaf_4 = leaf_hash(b"D");
    print_vec("Leaf A", &leaf_1);
    print_vec("Leaf B", &leaf_2);
    print_vec("Leaf C", &leaf_3);
    print_vec("Leaf D", &leaf_4);

    let interior_l = interior_hash(&leaf_1, &leaf_2);
    let interior_r = interior_hash(&leaf_3, &leaf_4);
    print_vec("Interior L (A|B)", &interior_l);
    print_vec("Interior R (C|D)", &interior_r);

    let root = interior_hash(&interior_l, &interior_r);
    print_vec("Root (L|R)", &root);
}

// ---------------------------------------------------------------------------
// §25.9 Key Continuity Fingerprint Vectors
// ---------------------------------------------------------------------------

#[test]
fn vector_20_full_fingerprint_all_keys() {
    println!("=== Vector 20: Full Fingerprint (All Three Keys) ===");

    let alice = KeyContinuityParty {
        did: "did:dht:z6MkAlice",
        identity_key: &REF_PUBKEY,
        active_key: &REF_PUBKEY_2,
        agent_key: Some(&REF_PUBKEY_3),
    };
    let bob = KeyContinuityParty {
        did: "did:dht:z6MkBob",
        identity_key: &REF_PUBKEY_2,
        active_key: &REF_PUBKEY_3,
        agent_key: Some(&REF_PUBKEY),
    };

    let fingerprint = compute_key_continuity_fingerprint(&alice, &bob);
    print_vec("Fingerprint", &fingerprint);

    let decimal = fingerprint_to_decimal(&fingerprint);
    println!("  Decimal: {decimal}");
    assert_eq!(decimal.len(), 60);

    // Verify symmetry
    let reversed = compute_key_continuity_fingerprint(&bob, &alice);
    assert_eq!(fingerprint, reversed, "fingerprint must be symmetric");
}

#[test]
fn vector_21_fingerprint_without_agent_key() {
    println!("=== Vector 21: Fingerprint Without Agent Key ===");

    // Verify the absent agent key sentinel
    let sentinel: [u8; 32] = Sha256::digest(b"SCP-ABSENT-AGENT-KEY").into();
    print_vec("Absent agent key sentinel", &sentinel);
    assert_eq!(
        hex(&sentinel),
        "57b4f5f2d16153bc6ca4ef9719868e5953a4c5eb527a66e701b844fa892cea58"
    );

    let alice = KeyContinuityParty {
        did: "did:dht:z6MkAlice",
        identity_key: &REF_PUBKEY,
        active_key: &REF_PUBKEY_2,
        agent_key: None, // absent
    };
    let bob = KeyContinuityParty {
        did: "did:dht:z6MkBob",
        identity_key: &REF_PUBKEY_2,
        active_key: &REF_PUBKEY_3,
        agent_key: None, // absent
    };

    let fp_without = compute_key_continuity_fingerprint(&alice, &bob);
    print_vec("Fingerprint (no agent keys)", &fp_without);

    // Verify it differs when agent key is present
    let alice_with = KeyContinuityParty {
        did: "did:dht:z6MkAlice",
        identity_key: &REF_PUBKEY,
        active_key: &REF_PUBKEY_2,
        agent_key: Some(&REF_PUBKEY_3),
    };
    let fp_with = compute_key_continuity_fingerprint(&alice_with, &bob);
    print_vec("Fingerprint (alice has agent key)", &fp_with);
    assert_ne!(fp_without, fp_with);

    // Verify passing the sentinel explicitly gives the same result as None
    let alice_sentinel = KeyContinuityParty {
        did: "did:dht:z6MkAlice",
        identity_key: &REF_PUBKEY,
        active_key: &REF_PUBKEY_2,
        agent_key: Some(&sentinel),
    };
    let bob_sentinel = KeyContinuityParty {
        did: "did:dht:z6MkBob",
        identity_key: &REF_PUBKEY_2,
        active_key: &REF_PUBKEY_3,
        agent_key: Some(&sentinel),
    };
    let fp_sentinel = compute_key_continuity_fingerprint(&alice_sentinel, &bob_sentinel);
    assert_eq!(fp_without, fp_sentinel, "None must equal explicit sentinel");
}

// ---------------------------------------------------------------------------
// §25.10 Claim Validation Vectors
// ---------------------------------------------------------------------------

#[test]
fn vector_22_shadow_claim_hash() {
    println!("=== Vector 22: Shadow Claim Hash ===");

    let shadow_id = b"shadow-alice-x-12345";
    let claimant_did = b"did:dht:z6MkClaim";
    let context_id = b"bridge-test-context";
    let timestamp: u64 = 1_700_000_000;

    let bytes = canonical_hash_bytes(
        b"SCP-CLAIM-V1:",
        &[
            CanonicalField::VarBytes(shadow_id),
            CanonicalField::VarBytes(claimant_did),
            CanonicalField::VarBytes(context_id),
            CanonicalField::U64(timestamp),
        ],
    );

    println!("  Canonical hash input length: {} bytes", bytes.len());
    // 13 (domain) + (4+20) + (4+17) + (4+19) + 8 = 13 + 24 + 21 + 23 + 8 = 89
    assert_eq!(bytes.len(), 89);

    let hash: [u8; 32] = Sha256::digest(&bytes).into();
    print_vec("Claim canonical hash", &hash);
}

// ---------------------------------------------------------------------------
// §25.11 Proposal ID Vectors
// ---------------------------------------------------------------------------

#[test]
fn vector_23_governance_proposal_id() {
    println!("=== Vector 23: Governance Proposal ID ===");

    let context_id = b"gov-proposal-context";
    let proposer_did = b"did:dht:z6MkProposer";
    let timestamp: u64 = 1_700_000_000;

    // action_hash: SHA-256 of serialized governance action (arbitrary 32 bytes for test)
    let action_hash: [u8; 32] = Sha256::digest(b"test-governance-action").into();
    print_vec("Action hash", &action_hash);

    let bytes = canonical_hash_bytes(
        b"SCP-PROPOSAL-V1:",
        &[
            CanonicalField::VarBytes(context_id),
            CanonicalField::Fixed32(&action_hash), // fixed-length per spec
            CanonicalField::VarBytes(proposer_did),
            CanonicalField::U64(timestamp),
        ],
    );

    println!("  Canonical hash input length: {} bytes", bytes.len());
    // 16 (domain) + (4+20) + 32 + (4+20) + 8 = 16 + 24 + 32 + 24 + 8 = 104
    assert_eq!(bytes.len(), 104);

    let proposal_id: [u8; 32] = Sha256::digest(&bytes).into();
    print_vec("Proposal ID", &proposal_id);
}

// ---------------------------------------------------------------------------
// §25.12 HPKE Key Distribution Vectors
// ---------------------------------------------------------------------------

#[test]
fn vector_24_sender_key_hpke_info_string() {
    println!("=== Vector 24: Sender Key HPKE Info String ===");

    let context_id = "hpke-test-context";
    let sender_did = "did:dht:z6MkSender";
    let epoch: u64 = 42;

    // Sender key HPKE info uses length-prefixed fields.
    // The code at key_protocol.rs:1130 uses:
    //   prefix || BE32(ctx_len) || ctx || BE32(did_len) || did || BE64(epoch)
    let mut info = Vec::new();
    info.extend_from_slice(b"scp-sender-key-v1");
    info.extend_from_slice(&(context_id.len() as u32).to_be_bytes());
    info.extend_from_slice(context_id.as_bytes());
    info.extend_from_slice(&(sender_did.len() as u32).to_be_bytes());
    info.extend_from_slice(sender_did.as_bytes());
    info.extend_from_slice(&epoch.to_be_bytes());

    println!("  Info string length: {} bytes", info.len());
    // 17 (prefix) + (4+17) + (4+18) + 8 = 17 + 21 + 22 + 8 = 68
    assert_eq!(info.len(), 68);
    print_vec("Sender key HPKE info", &info);

    // Verify it starts with the correct prefix
    assert!(info.starts_with(b"scp-sender-key-v1"));
}

#[test]
fn vector_25_access_key_hpke_info_string() {
    println!("=== Vector 25: Access Key HPKE Info String ===");

    let context_id = "hpke-test-context";
    let member_did = "did:dht:z6MkMember";
    let epoch: u64 = 42;

    // Access key HPKE info uses length-prefixed fields per §25.12.
    let mut info = Vec::new();
    info.extend_from_slice(b"scp-access-key-v1");
    info.extend_from_slice(&(context_id.len() as u32).to_be_bytes());
    info.extend_from_slice(context_id.as_bytes());
    info.extend_from_slice(&(member_did.len() as u32).to_be_bytes());
    info.extend_from_slice(member_did.as_bytes());
    info.extend_from_slice(&epoch.to_be_bytes());

    println!("  Info string length: {} bytes", info.len());
    // 17 (prefix) + (4+17) + (4+18) + 8 = 17 + 21 + 22 + 8 = 68
    assert_eq!(info.len(), 68);
    print_vec("Access key HPKE info", &info);

    // Verify structural difference from sender key
    assert!(info.starts_with(b"scp-access-key-v1"));
    assert!(!info.starts_with(b"scp-sender-key-v1"));
}

#[test]
fn vector_24_25_sender_and_access_info_differ() {
    println!("=== Vectors 24-25: Sender vs Access Info Differ ===");

    // Same parameters, different domain → different info strings
    let context_id = "same-context";
    let did = "did:dht:z6MkSame";
    let epoch: u64 = 0;

    let mut sender_info = Vec::new();
    sender_info.extend_from_slice(b"scp-sender-key-v1");
    sender_info.extend_from_slice(&(context_id.len() as u32).to_be_bytes());
    sender_info.extend_from_slice(context_id.as_bytes());
    sender_info.extend_from_slice(&(did.len() as u32).to_be_bytes());
    sender_info.extend_from_slice(did.as_bytes());
    sender_info.extend_from_slice(&epoch.to_be_bytes());

    let mut access_info = Vec::new();
    access_info.extend_from_slice(b"scp-access-key-v1");
    access_info.extend_from_slice(&(context_id.len() as u32).to_be_bytes());
    access_info.extend_from_slice(context_id.as_bytes());
    access_info.extend_from_slice(&(did.len() as u32).to_be_bytes());
    access_info.extend_from_slice(did.as_bytes());
    access_info.extend_from_slice(&epoch.to_be_bytes());

    assert_ne!(
        sender_info, access_info,
        "sender key and access key HPKE info must differ due to domain prefix"
    );
}

// ---------------------------------------------------------------------------
// §25.13 Attestation Signing Vectors
// ---------------------------------------------------------------------------

#[test]
fn vector_26_identity_link_attestation() {
    println!("=== Vector 26: Identity Link Attestation ===");

    let id = b"att-001";
    let attestation_type: u16 = 0x0001; // IdentityLink
    let issuer = b"did:dht:z6MkIssuer";
    let subject = b"did:dht:z6MkSubject";
    let claim = br#"{"handle":"@alice","platform":"x"}"#;
    let issued_at: u64 = 1_700_000_000;
    let expires_at: u64 = 0; // no expiry

    let bytes = canonical_hash_bytes(
        b"SCP-ATTESTATION-V1:",
        &[
            CanonicalField::VarBytes(id),
            CanonicalField::U16(attestation_type),
            CanonicalField::VarBytes(issuer),
            CanonicalField::VarBytes(subject),
            CanonicalField::VarBytes(claim),
            CanonicalField::Absent, // evidence absent
            CanonicalField::U64(issued_at),
            CanonicalField::U64(expires_at),
        ],
    );

    println!("  Canonical hash input length: {} bytes", bytes.len());
    // 19 (domain) + (4+7) + 2 + (4+18) + (4+19) + (4+34) + 32 (Absent) + 8 + 8
    // = 19 + 11 + 2 + 22 + 23 + 38 + 32 + 8 + 8 = 163
    assert_eq!(bytes.len(), 163);

    let hash: [u8; 32] = Sha256::digest(&bytes).into();
    print_vec("Attestation canonical hash", &hash);

    // Sign with reference key
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&REF_SEED);
    let signature = signing_key.sign(&hash);
    print_vec("Attestation signature", signature.to_bytes().as_slice());

    signing_key
        .verifying_key()
        .verify(&hash, &signature)
        .expect("attestation signature must verify");
}

// ---------------------------------------------------------------------------
// §25.14 Verification Procedure — SHA-256 Sanity Check
// ---------------------------------------------------------------------------

#[test]
fn sha256_sanity_check() {
    println!("=== SHA-256 Sanity Check ===");
    let empty_hash: [u8; 32] = Sha256::digest(b"").into();
    print_vec("SHA-256(\"\")", &empty_hash);
    assert_eq!(
        hex(&empty_hash),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

// ---------------------------------------------------------------------------
// Cross-vector consistency checks
// ---------------------------------------------------------------------------

#[test]
fn domain_separators_are_all_unique() {
    let domains = [
        "SCP-INNER-ENVELOPE-V1:",
        "SCP-VOTE-V1:",
        "SCP-RESET-REQUEST-V1:",
        "SCP-KEY-CONTINUITY-V1:",
        "SCP-CLAIM-V1:",
        "SCP-PROPOSAL-V1:",
        "SCP-ATTESTATION-V1:",
        "scp-sender-key-v1",
        "scp-access-key-v1",
    ];

    for i in 0..domains.len() {
        for j in (i + 1)..domains.len() {
            assert_ne!(
                domains[i], domains[j],
                "domain separators must be unique: '{}' vs '{}'",
                domains[i], domains[j]
            );
            // Also verify no domain is a prefix of another
            assert!(
                !domains[i].starts_with(domains[j]) && !domains[j].starts_with(domains[i]),
                "no domain separator must be a prefix of another: '{}' vs '{}'",
                domains[i],
                domains[j]
            );
        }
    }
}
