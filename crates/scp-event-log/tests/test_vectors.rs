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
    // Spec §25.8 defines the empty-tree root as SHA-256("") (RFC 6962 MTH({})),
    // and the production EventLog matches it: `tree::root` returns
    // `empty_tree_root()` = SHA-256("") for an empty log. The all-zero value
    // below is NOT the empty root — it is the distinct genesis `prev_hash`
    // sentinel (`GENESIS_PREV_HASH = [0u8; 32]`), shown here only to contrast
    // the two so they are not conflated.
    let spec_empty_root: [u8; 32] = Sha256::digest(b"").into();
    print_vec(
        "SHA-256(\"\") [spec §25.8 = EventLog empty root]",
        &spec_empty_root,
    );
    assert_eq!(
        hex(&spec_empty_root),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );

    let genesis_prev_hash: [u8; 32] = [0u8; 32];
    print_vec("genesis prev_hash sentinel [distinct]", &genesis_prev_hash);
    println!("  Note: all-zeros is the genesis prev_hash, not the empty root.");
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

    // §25.8 Vector 16: assert exact spec hex values.
    assert_eq!(
        hex(&leaf),
        "90b626dbb1e994c962942db2b3b16d97c63f679912a176bb96f4e308c213005b"
    );
    assert_eq!(
        hex(&root),
        "90b626dbb1e994c962942db2b3b16d97c63f679912a176bb96f4e308c213005b"
    );
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

    // §25.8 Vector 17: assert exact spec hex values.
    assert_eq!(
        hex(&leaf_1),
        "00d9ea40d70522a7d0aa41e2708afd5dc148a4dcc26011d598cbc28cdbde306f"
    );
    assert_eq!(
        hex(&leaf_2),
        "7a7b6da2a00d46f75c01d0c5a33cb62e99caa7f0ebbd084a169a00874751e7a3"
    );
    assert_eq!(
        hex(&root),
        "9f7a0b4b3965ce3eb4dda7c7c56bc9f7fb2c627d5120692d4ff8e531920ebbf9"
    );
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

    // §25.8 Vector 18: assert exact spec hex values.
    assert_eq!(
        hex(&leaf_a),
        "c00b4d3c929cb5cc316691ed4636f634576f2c9b2954767234c5274e9dde185d"
    );
    assert_eq!(
        hex(&leaf_b),
        "87afe6086fe4571e37657e76281301f189c75ebae1d2eaafb56d578067a1d95e"
    );
    assert_eq!(
        hex(&leaf_c),
        "b563a5e69628743929eddec0ccfeb0745c39577e12a72e84915edd6633cb97f2"
    );
    assert_eq!(
        hex(&interior_ab),
        "ed692f01f7f6c46930d7ad8f9adad3f9f38b7379cf6a8d2f399a0ba1e914fe25"
    );
    assert_eq!(
        hex(&root),
        "961d2e2be20f538ffdf56962a86d1bd165498f222684ee4c5e02c1e9f852adc5"
    );
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

    // §25.8 Vector 19: assert exact spec hex values.
    assert_eq!(
        hex(&leaf_a),
        "c00b4d3c929cb5cc316691ed4636f634576f2c9b2954767234c5274e9dde185d"
    );
    assert_eq!(
        hex(&leaf_b),
        "87afe6086fe4571e37657e76281301f189c75ebae1d2eaafb56d578067a1d95e"
    );
    assert_eq!(
        hex(&leaf_c),
        "b563a5e69628743929eddec0ccfeb0745c39577e12a72e84915edd6633cb97f2"
    );
    assert_eq!(
        hex(&leaf_d),
        "08a2afecc9feaef6737f055c177a56a363d28a78d7b259b8c5f66b32174f2e7d"
    );
    assert_eq!(
        hex(&interior_l),
        "ed692f01f7f6c46930d7ad8f9adad3f9f38b7379cf6a8d2f399a0ba1e914fe25"
    );
    assert_eq!(
        hex(&interior_r),
        "d62c77efa9be96355bb8b07aefc985914377de5aec1287998c9a10f11cd8d075"
    );
    assert_eq!(
        hex(&root),
        "5c8dc617d287a4297eb2bcb81b37644b5138e57ad461c657db152109e3fc9fca"
    );
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

// ---------------------------------------------------------------------------
// §25.8 Typed-leaf + checkpoint KAT (ADR-011 typed-event unification)
//
// The vectors above pin the abstract RFC 6962 tree construction. These pin the
// *typed* leaf preimage: each leaf is SHA-256(0x00 || rmp_serde(Event)) over a
// canonical `scp_event_log::Event` whose `event_type` is one of the closed
// EventType taxonomy, and the checkpoint `merkle_root` equals `tree::root`.
//
// Determinism: a fixed 32-byte Ed25519 seed yields a fixed signing key; Ed25519
// signatures are deterministic (RFC 8032), so the full-Event rmp_serde bytes —
// and hence the leaf hash — are reproducible across runs and implementations.
// The DID is `did:dht:z<z-base-32(pubkey)>`, which `extract_public_key_from_did`
// accepts without the `testing` feature.
// ---------------------------------------------------------------------------

use ed25519_dalek::{Signer, SigningKey, Verifier};
use scp_event_log::tree::{self, compute_event_canonical_hash};
use scp_event_log::{
    Event, EventLog, EventLogSigner, EventPayload, EventType, checkpoint, payload,
};

/// Fixed 32-byte Ed25519 seed for KAT reproducibility. Not a real key.
const KAT_SEED: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

/// Genesis sentinel `prev_hash` for the first event (mirrors `tree::GENESIS_PREV_HASH`).
const KAT_GENESIS_PREV_HASH: [u8; 32] = [0u8; 32];

fn kat_signing_key() -> SigningKey {
    SigningKey::from_bytes(&KAT_SEED)
}

/// Builds the `did:dht:z<z-base-32(pubkey)>` DID for the fixed KAT key.
fn kat_did() -> String {
    let vk = kat_signing_key().verifying_key();
    format!("did:dht:z{}", zbase32::encode(vk.as_bytes()))
}

/// A deterministic, fixed-key [`EventLogSigner`] for checkpoint KAT signing.
struct KatSigner(SigningKey);

#[async_trait::async_trait]
impl EventLogSigner for KatSigner {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        Ok(self.0.sign(message).to_bytes().to_vec())
    }
}

/// Signs an event with the fixed KAT key (canonical hash over all fields except
/// the signature).
fn kat_sign_event(
    event_type: EventType,
    actor_did: &str,
    timestamp: u64,
    sequence: u64,
    payload_bytes: Vec<u8>,
    prev_hash: [u8; 32],
) -> Event {
    let mut event = Event {
        event_type,
        actor_did: actor_did.to_owned().into(),
        timestamp,
        sequence,
        payload: EventPayload {
            data: payload_bytes,
        },
        prev_hash,
        signature: Vec::new(),
    };
    let canonical_hash = compute_event_canonical_hash(&event);
    event.signature = kat_signing_key().sign(&canonical_hash).to_bytes().to_vec();
    event
}

/// Computes the RFC 6962 leaf hash over the full signed event:
/// `SHA-256(0x00 || rmp_serde(Event))`.
fn typed_leaf_hash(event: &Event) -> [u8; 32] {
    let serialized = rmp_serde::to_vec(event).expect("event serialization");
    leaf_hash(&serialized)
}

/// Builds the representative spread of typed events for the KAT.
///
/// Spread (ADR-011 Amendment coverage): `AppBound`, `SpendApproved`,
/// `TtlExtended`, `RecoveryEpochAdvanced`, `ContextTombstoned`,
/// `ConsequenceTriggered`, `CommitBroadcastSucceeded`, `RoleAssigned`,
/// `MemberJoined`. Payloads use the shared `payload` encoder where a structured
/// struct is defined; the remaining variants carry their documented opaque
/// payloads. The trailing `RoleAssigned`/`MemberJoined` leaves pin the
/// subject-bearing payloads added by the ADR-011 amendment.
/// Encodes a structured payload via the shared `payload` encoder.
fn enc<T: serde::Serialize>(value: &T) -> Vec<u8> {
    payload::encode_payload(value)
        .expect("shared payload encode")
        .data
}

fn kat_events() -> Vec<Event> {
    let did = kat_did();
    let mut events: Vec<Event> = Vec::new();
    let mut prev = KAT_GENESIS_PREV_HASH;

    // (event_type, timestamp, payload-bytes) in append order. Structured
    // payloads use the shared `payload` encoder; opaque ones carry their
    // documented bytes. Spread covers AppBound, SpendApproved, TtlExtended,
    // RecoveryEpochAdvanced, ContextTombstoned, ConsequenceTriggered,
    // CommitBroadcastSucceeded, RoleAssigned, MemberJoined.
    let spec: Vec<(EventType, u64, Vec<u8>)> = vec![
        (
            EventType::AppBound,
            1_700_000_000,
            enc(&payload::AppBoundPayload {
                app_did: "did:key:app".to_owned(),
                app_name: "Scheduler".to_owned(),
                app_version: "1.0.0".to_owned(),
                capabilities: vec!["outlet:call:*".to_owned()],
            }),
        ),
        (
            EventType::SpendApproved,
            1_700_000_001,
            enc(&payload::SpendApprovedPayload {
                spender: "did:key:agent".to_owned(),
                amount: 5_000,
                purpose: "inference".to_owned(),
            }),
        ),
        (
            EventType::TtlExtended,
            1_700_000_002,
            enc(&payload::TtlExtendedPayload {
                old_deadline_unix: 1_700_000_000,
                new_deadline_unix: 1_800_000_000,
                proposal_id: [0xABu8; 32],
                consenting_members: vec!["did:key:a".to_owned(), "did:key:b".to_owned()],
            }),
        ),
        (
            EventType::RecoveryEpochAdvanced,
            1_700_000_003,
            enc(&payload::RecoveryEpochAdvancedPayload {
                old_epoch: 7,
                new_epoch: 8,
            }),
        ),
        (
            EventType::ContextTombstoned,
            1_700_000_004,
            enc(&payload::ContextTombstonedPayload {
                destination_id: "ctx-dest".to_owned(),
                migration_proposal_id: [0xCDu8; 32],
            }),
        ),
        (
            EventType::ConsequenceTriggered,
            1_700_000_005,
            b"member_did=did:key:m;rule_index=2;trigger_kind=absence;action_type=suspend".to_vec(),
        ),
        (
            EventType::CommitBroadcastSucceeded,
            1_700_000_006,
            b"operation=join;attempts=3".to_vec(),
        ),
        (
            EventType::RoleAssigned,
            1_700_000_007,
            enc(&payload::RoleAssignedPayload {
                subject_did: "did:key:carol".to_owned(),
                role: "admin".to_owned(),
            }),
        ),
        (
            EventType::MemberJoined,
            1_700_000_008,
            enc(&payload::MembershipChangePayload {
                subject_did: "did:key:dave".to_owned(),
                role_name: "member".to_owned(),
            }),
        ),
    ];

    for (seq, (et, ts, data)) in spec.into_iter().enumerate() {
        let ev = kat_sign_event(et, &did, ts, seq as u64, data, prev);
        prev = typed_leaf_hash(&ev);
        events.push(ev);
    }

    events
}

#[test]
fn vector_32_typed_leaf_and_checkpoint_kat() {
    println!("=== Vector 32: Typed-leaf + checkpoint KAT ===");
    println!("  KAT DID: {}", kat_did());

    let events = kat_events();
    assert_eq!(events.len(), 9, "KAT spread must be 9 events");

    // Build the log via the production append path (verifies signatures, builds
    // the RFC 6962 tree incrementally).
    let mut log = EventLog::new("ctx-kat".to_owned());
    let mut leaves = Vec::new();
    for ev in &events {
        tree::append(&mut log, ev).expect("append KAT event");
        leaves.push(typed_leaf_hash(ev));
    }

    // Print + pin each typed leaf.
    for (i, leaf) in leaves.iter().enumerate() {
        print_vec(&format!("Leaf {i} ({:?})", events[i].event_type), leaf);
    }
    let root = tree::root(&log);
    print_vec("tree::root", &root);

    // --- Pinned typed-leaf vectors (generated by this test, then pinned) ---
    let expected_leaves = [
        // 0: AppBound
        "e0c0691d264ca38d086375a0274afb630e9bbb906f2e12e0112adf4d1b4fcd38",
        // 1: SpendApproved
        "f2f973a4df60ef87abcb99dd1f3afcd537037cbd1aae6297582c52be3bd8e695",
        // 2: TtlExtended
        "ccdbb8dfa15a7abff3fbd0c08efe45e99d9fc4cb5f042f8f7db5f9e36e3fb0b0",
        // 3: RecoveryEpochAdvanced
        "7a1a91c33ddaa1a92c02f70a3f567f065bed48b578124a803c07dca2f9a47863",
        // 4: ContextTombstoned
        "3848718f23aefaba0e47743e72f5ce3bcc3254bc09b4cb38c3f5c263c9c4dd8d",
        // 5: ConsequenceTriggered
        "7ea6b6a020d94e0850cb84410af43e69ecd1c945223cbf478356d93503724507",
        // 6: CommitBroadcastSucceeded
        "87e3cde25168f4af4328f010369313e28fde305dbc6f706be3392fdf7b8e7f3c",
        // 7: RoleAssigned (RoleAssignedPayload)
        "9455cca66b6528ff7061d27b70ddab795ffff1e790fc1f797f22e21687e5f449",
        // 8: MemberJoined (MembershipChangePayload)
        "28860f95688e8b0604db7349fd79deed13d3b9a10198a9623ea288a6eeea58f2",
    ];
    for (i, leaf) in leaves.iter().enumerate() {
        assert_eq!(hex(leaf), expected_leaves[i], "typed leaf {i} mismatch");
    }
    assert_eq!(
        hex(&root),
        "0c6f6a09ecdda29319880ca609060ec15aa8055ee9fbc85099e5f6e8b1ba4117",
        "tree::root mismatch"
    );
}

#[tokio::test]
async fn vector_33_checkpoint_root_equals_tree_root_kat() {
    println!("=== Vector 33: Checkpoint merkle_root == tree::root KAT ===");

    let events = kat_events();
    let mut log = EventLog::new("ctx-kat".to_owned());
    for ev in &events {
        tree::append(&mut log, ev).expect("append KAT event");
    }

    let tree_root = tree::root(&log);
    let did: scp_did::DID = kat_did().into();
    let signer = KatSigner(kat_signing_key());

    // generate_checkpoint computes merkle_root = tree::root(log) and signs the
    // §23.16.1 canonical-hash layout (SCP-CHECKPOINT-V1: || len(ctx) || ctx ||
    // len(did) || did || event_count_BE || merkle_root || epoch || ts_BE).
    let cp = checkpoint::generate_checkpoint(&log, &did, 5, &signer)
        .await
        .expect("generate checkpoint");

    print_vec("checkpoint.merkle_root", &cp.merkle_root);
    print_vec("tree::root", &tree_root);

    assert_eq!(
        cp.merkle_root, tree_root,
        "checkpoint merkle_root must equal RFC 6962 tree::root"
    );
    assert_eq!(cp.event_count, 9, "checkpoint must cover all 9 events");

    // Recompute the §23.16.1 canonical checkpoint hash and assert the signature
    // verifies against the KAT key — pins the canonical-hash layout.
    let canonical = checkpoint::compute_checkpoint_canonical_hash(
        "ctx-kat",
        &did,
        cp.event_count,
        &cp.merkle_root,
        Some(5),
        cp.timestamp,
    );
    print_vec("checkpoint canonical hash (§23.16.1)", &canonical);

    let vk = kat_signing_key().verifying_key();
    let sig = ed25519_dalek::Signature::from_slice(&cp.signature).expect("sig bytes");
    vk.verify(&canonical, &sig)
        .expect("checkpoint signature must verify over §23.16.1 canonical hash");

    // --- Pinned checkpoint root (generated by this test, then pinned) ---
    assert_eq!(
        hex(&tree_root),
        "0c6f6a09ecdda29319880ca609060ec15aa8055ee9fbc85099e5f6e8b1ba4117",
        "checkpoint tree::root mismatch"
    );
}
