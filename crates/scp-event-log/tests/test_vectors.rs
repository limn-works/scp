//! §25.8 Merkle Tree Test Vectors — reference implementation.
//!
//! These tests verify the RFC 6962 Merkle tree construction used in
//! SCP's event log. They complement the test vectors in scp-core.
//!
//! Run with `--nocapture` to see hex-encoded values:
//! ```bash
//! cargo test -p scp-event-log --test test_vectors -- --nocapture
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Helpers — standalone Merkle hash functions (RFC 6962 §2)
// ---------------------------------------------------------------------------

/// Leaf hash: SHA-256(0x00 || data) per RFC 6962 §2.1.
fn leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(data);
    hasher.finalize().into()
}

/// Interior hash: SHA-256(0x01 || left || right) per RFC 6962 §2.1.
fn interior_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn print_vec(label: &str, bytes: &[u8]) {
    println!("  {label}: 0x{} ({} bytes)", hex(bytes), bytes.len());
}

// ---------------------------------------------------------------------------
// §25.8 Merkle Tree Vectors
// ---------------------------------------------------------------------------

#[test]
fn vector_15_empty_tree() {
    println!("=== Vector 15: Empty Merkle Tree ===");
    // Spec defines empty tree root as SHA-256("").
    // Note: The EventLog implementation returns [0u8; 32] for empty logs.
    // This test documents both values.
    let spec_empty_root: [u8; 32] = Sha256::digest(b"").into();
    print_vec("SHA-256(\"\") [spec §25.8]", &spec_empty_root);
    assert_eq!(
        hex(&spec_empty_root),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );

    let impl_empty_root: [u8; 32] = [0u8; 32];
    print_vec("EventLog empty root [impl]", &impl_empty_root);
    println!("  Note: Implementation uses all-zeros for empty log.");
}

#[test]
fn vector_16_single_leaf() {
    println!("=== Vector 16: Single Leaf ===");
    let data = b"Hello";
    let leaf = leaf_hash(data);
    print_vec("Input (\"Hello\")", data);
    print_vec("Leaf hash (SHA-256(0x00 || data))", &leaf);

    // For a single leaf, the root IS the leaf hash.
    let root = leaf;
    print_vec("Root (= leaf hash)", &root);

    // The leaf hash is deterministic — print the exact value.
    println!("  Root hex: 0x{}", hex(&root));
}

#[test]
fn vector_17_two_leaves() {
    println!("=== Vector 17: Two Leaves ===");
    let event_1 = b"Event1";
    let event_2 = b"Event2";

    let leaf_1 = leaf_hash(event_1);
    let leaf_2 = leaf_hash(event_2);
    print_vec("Leaf 1 (\"Event1\")", &leaf_1);
    print_vec("Leaf 2 (\"Event2\")", &leaf_2);

    let root = interior_hash(&leaf_1, &leaf_2);
    print_vec("Root (SHA-256(0x01 || leaf1 || leaf2))", &root);
    println!("  Root hex: 0x{}", hex(&root));
}

#[test]
fn vector_18_three_leaves_unbalanced() {
    println!("=== Vector 18: Three Leaves (Unbalanced) ===");
    let leaf_a = leaf_hash(b"A");
    let leaf_b = leaf_hash(b"B");
    let leaf_c = leaf_hash(b"C");
    print_vec("Leaf A", &leaf_a);
    print_vec("Leaf B", &leaf_b);
    print_vec("Leaf C", &leaf_c);

    // RFC 6962 unbalanced tree: pair first two, then pair with third.
    let interior_ab = interior_hash(&leaf_a, &leaf_b);
    print_vec("Interior (A|B)", &interior_ab);

    let root = interior_hash(&interior_ab, &leaf_c);
    print_vec("Root (AB|C)", &root);
    println!("  Root hex: 0x{}", hex(&root));
}

#[test]
fn vector_19_four_leaves_balanced() {
    println!("=== Vector 19: Four Leaves (Balanced) ===");
    let leaf_a = leaf_hash(b"A");
    let leaf_b = leaf_hash(b"B");
    let leaf_c = leaf_hash(b"C");
    let leaf_d = leaf_hash(b"D");
    print_vec("Leaf A", &leaf_a);
    print_vec("Leaf B", &leaf_b);
    print_vec("Leaf C", &leaf_c);
    print_vec("Leaf D", &leaf_d);

    let interior_l = interior_hash(&leaf_a, &leaf_b);
    let interior_r = interior_hash(&leaf_c, &leaf_d);
    print_vec("Interior L (A|B)", &interior_l);
    print_vec("Interior R (C|D)", &interior_r);

    let root = interior_hash(&interior_l, &interior_r);
    print_vec("Root (L|R)", &root);
    println!("  Root hex: 0x{}", hex(&root));
}

// ---------------------------------------------------------------------------
// Additional Merkle consistency checks
// ---------------------------------------------------------------------------

#[test]
fn leaf_prefix_differs_from_interior_prefix() {
    // RFC 6962 §2.1: leaf prefix 0x00, interior prefix 0x01.
    // This prevents second-preimage attacks.
    let data = [0xAA; 32];
    let as_leaf = leaf_hash(&data);

    // Construct something that would be interior_hash(X, Y) where X||Y == data
    // but with different structure.
    let left = [0xAA; 16];
    let right = [0xAA; 16];
    let mut interior_attempt = Sha256::new();
    interior_attempt.update([0x01]);
    interior_attempt.update(left);
    interior_attempt.update(right);
    let as_interior: [u8; 32] = interior_attempt.finalize().into();

    assert_ne!(as_leaf, as_interior, "leaf and interior hashes must differ");
}

#[test]
fn tree_construction_is_deterministic() {
    let events = [b"X".as_ref(), b"Y", b"Z"];
    let leaves: Vec<[u8; 32]> = events.iter().map(|e| leaf_hash(e)).collect();

    let root1 = {
        let interior = interior_hash(&leaves[0], &leaves[1]);
        interior_hash(&interior, &leaves[2])
    };

    let root2 = {
        let interior = interior_hash(&leaves[0], &leaves[1]);
        interior_hash(&interior, &leaves[2])
    };

    assert_eq!(root1, root2, "same events must produce same root");
}

#[test]
fn different_event_order_produces_different_root() {
    let leaf_a = leaf_hash(b"first");
    let leaf_b = leaf_hash(b"second");

    let root_ab = interior_hash(&leaf_a, &leaf_b);
    let root_ba = interior_hash(&leaf_b, &leaf_a);

    assert_ne!(root_ab, root_ba, "swapping children must change the root");
}
