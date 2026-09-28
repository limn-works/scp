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
// §25.8 Vectors 32 and 33: typed event-log leaves and the checkpoint root
//
// The vectors above pin the abstract RFC 6962 tree construction. These pin the
// typed leaf preimage: each leaf is SHA-256(0x00 || rmp_serde(Event)) over a
// signed `scp_event_log::Event`, and the checkpoint `merkle_root` equals
// `tree::root`. Every value is printed in `.docs/specs/25-test-vectors.md` and
// produced by `scripts/gen-test-vectors-p256.py`.
//
// Each event is signed with the §25.2 reference key 1 (P-256, RFC 6979) over
// the production `compute_event_canonical_hash`, through the scp-crypto
// primitives. Production event signing and `tree::append`'s signature check
// are still Ed25519 (rule B of the identity plan); slice S12 moves them to
// P-256 and asserts these leaves through the signed append path. Until then
// the log is built with `tree::append_unsigned_event`, which runs the
// production sequence, hash-chain, leaf-hash, and incremental-root code
// without the Ed25519 signature check.
// ---------------------------------------------------------------------------

use scp_crypto::p256::{P256SigningKey, sign_prehash_rfc6979, verify_prehash_strict};
use scp_crypto::{CustodyFailure, CustodyFailureKind};
use scp_event_log::tree::{self, compute_event_canonical_hash};
use scp_event_log::{
    Event, EventLog, EventLogSigner, EventPayload, EventType, checkpoint, payload,
};

/// The §25.2 seed-to-scalar label.
const TEST_VECTOR_KEY_LABEL: &[u8] = b"SCP-TEST-VECTOR-KEY-V1";

/// §25.2 reference seed 1.
const REFERENCE_SEED_1: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

/// Genesis sentinel `prev_hash` for the first event.
const KAT_GENESIS_PREV_HASH: [u8; 32] = [0u8; 32];

/// §25.1 fixture identifiers, each `SHA-256("SCP test vector identifier <role>")`
/// in the `scp:` text form.
const ID_EVENT_LOG_ACTOR: &str = "scp:gweyicxangesw4cafjfvafnt2cusxvt7nxked4z6356q4fzkmqoa";
const ID_APP: &str = "scp:n5hzj47neu6axurs4j5c2raqo3bvyxmuhir75dypf5enuktwmzga";
const ID_AGENT: &str = "scp:gugakbvop4hkbtpmivkcnpm6z75kvk5nrk35wnfiwkxn2tv5cegq";
const ID_A: &str = "scp:i3cbnrsij6l54zihsollo6mzasshwszcz5uoi6j5a3hv7x4s24ca";
const ID_B: &str = "scp:ihyapxk7wahtonmyfkolh4c2sq5vd52u3f477ik3xc5fontsqima";
const ID_M: &str = "scp:ni4vblzmv5aysoj57nmwlnrzkznatwiks2txqtva66hma3sgqneq";
const ID_CAROL: &str = "scp:mu3leerpopwlqi4da5g65wgpv5cp4lmvxfpebotmnyugveds37qa";
const ID_DAVE: &str = "scp:xwseckbpifculwol66dbthmywocvxzfskyzedf2wg6qqr3pywu2q";

/// §25.8 Vector 32 leaves, in append order.
const EXPECTED_LEAVES: [&str; 9] = [
    "5f0b7494633bf4e50df0734a73431985184a88ac0d31700f25cf32923b232ba9",
    "69ac3c845a002b16f0ef612b73419f8cc56ecb061c062328a5c4efbca97c5e79",
    "4312aeeb911f88a1ba67ed94aa796f4a5660e1c701fa41945dc0f94cf3245465",
    "65857aebf0d00dc53adf6cb23911b12aeee9b1e57a416c947fe82f2b2c7716b1",
    "f03d157ae6a4b86f88fdd93140b9e7a57d362d285e80d3f8e9d1a99a0124270b",
    "e0a65df7a50bb297bf0b06d197dbe21479615b229b81a7c90fb9ff5cbc3e8f42",
    "74348229437898c2ab6a19e86ced221d41146301c51aaee2c67ef1ff061a6a69",
    "08a3d79d1f54dec672c3194a60ef6c391c3465a92af01304c603395098ea3649",
    "2cd931312eea90d2e786f34b1c1891717a803acdbe3a2237416b9139ac4b8b29",
];

/// §25.8 Vector 32 root, which Vector 33 reuses as the checkpoint root.
const EXPECTED_ROOT: &str = "d161de08f68888a0b13e7fb03e8bbc25758701ab247beb7b6bc2232c87971500";

fn reference_key() -> P256SigningKey {
    let seed: [u8; 32] = hex::decode(REFERENCE_SEED_1).unwrap().try_into().unwrap();
    P256SigningKey::from_seed(TEST_VECTOR_KEY_LABEL, &seed).unwrap()
}

fn prehash(digest: &[u8]) -> [u8; 32] {
    digest.try_into().expect("32-byte canonical hash")
}

/// Signs checkpoints with the §25.2 reference key over the 32-byte canonical
/// hash `generate_checkpoint` passes it. Slice S12 replaces this with the
/// production P-256 signer.
struct ReferenceKeySigner(P256SigningKey);

#[async_trait::async_trait]
impl EventLogSigner for ReferenceKeySigner {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CustodyFailure> {
        let digest: [u8; 32] = message.try_into().map_err(|_| CustodyFailure {
            kind: CustodyFailureKind::Failed,
            detail: format!("expected a 32-byte digest, got {} bytes", message.len()),
        })?;
        sign_prehash_rfc6979(&self.0, &digest)
            .map(|signature| signature.to_vec())
            .map_err(|e| CustodyFailure {
                kind: CustodyFailureKind::Failed,
                detail: e.to_string(),
            })
    }
}

/// Encodes a structured payload through the shared `payload` encoder.
fn enc<T: serde::Serialize>(value: &T) -> Vec<u8> {
    payload::encode_payload(value)
        .expect("shared payload encode")
        .data
}

/// Builds the nine signed Vector 32 events, chaining each `prev_hash` to the
/// previous production leaf hash.
fn kat_events() -> Vec<Event> {
    let key = reference_key();
    let spec: Vec<(EventType, u64, Vec<u8>)> = vec![
        (
            EventType::AppBound,
            1_700_000_000,
            enc(&payload::AppBoundPayload {
                app_did: ID_APP.to_owned(),
                app_name: "Scheduler".to_owned(),
                app_version: "1.0.0".to_owned(),
                capabilities: vec!["outlet:call:*".to_owned()],
            }),
        ),
        (
            EventType::SpendApproved,
            1_700_000_001,
            enc(&payload::SpendApprovedPayload {
                spender: ID_AGENT.to_owned(),
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
                consenting_members: vec![ID_A.to_owned(), ID_B.to_owned()],
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
            format!("member_did={ID_M};rule_index=2;trigger_kind=absence;action_type=suspend")
                .into_bytes(),
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
                subject_did: ID_CAROL.to_owned(),
                role: "admin".to_owned(),
            }),
        ),
        (
            EventType::MemberJoined,
            1_700_000_008,
            enc(&payload::MembershipChangePayload {
                subject_did: ID_DAVE.to_owned(),
                role_name: "member".to_owned(),
            }),
        ),
    ];

    let mut events = Vec::with_capacity(spec.len());
    let mut prev_hash = KAT_GENESIS_PREV_HASH;
    for (sequence, (event_type, timestamp, data)) in (0u64..).zip(spec) {
        let mut event = Event {
            event_type,
            actor_did: ID_EVENT_LOG_ACTOR.to_owned().into(),
            timestamp,
            sequence,
            payload: EventPayload { data },
            prev_hash,
            signature: Vec::new(),
        };
        let digest = prehash(&compute_event_canonical_hash(&event));
        let signature = sign_prehash_rfc6979(&key, &digest).unwrap();
        verify_prehash_strict(&key.public_key(), &digest, &signature)
            .expect("reference-key event signature must verify");
        event.signature = signature.to_vec();
        prev_hash = tree::leaf_hash(&event).expect("leaf hash");
        events.push(event);
    }
    events
}

/// Appends the Vector 32 events through the production hash-chain and tree
/// code (see the section comment for why the append is unsigned until S12).
fn kat_log() -> EventLog {
    let mut log = EventLog::new("ctx-kat".to_owned());
    for event in kat_events() {
        tree::append_unsigned_event(&mut log, &event).expect("append KAT event");
    }
    log
}

#[test]
fn vector_32_typed_leaves_and_root() {
    let events = kat_events();
    assert_eq!(events.len(), EXPECTED_LEAVES.len());
    for (i, event) in events.iter().enumerate() {
        let leaf = tree::leaf_hash(event).unwrap();
        assert_eq!(
            hex(&leaf),
            EXPECTED_LEAVES[i],
            "leaf {i} ({:?})",
            event.event_type
        );
        // The production leaf is RFC 6962 SHA-256(0x00 || rmp_serde(Event)).
        assert_eq!(leaf, leaf_hash(&rmp_serde::to_vec(event).unwrap()));
    }

    let log = kat_log();
    assert_eq!(hex(&tree::root(&log)), EXPECTED_ROOT, "tree::root");

    // The root is the RFC 6962 tree over the nine leaves: an unbalanced split
    // of eight and one.
    let leaves: Vec<[u8; 32]> = EXPECTED_LEAVES
        .iter()
        .map(|l| hex::decode(l).unwrap().try_into().unwrap())
        .collect();
    let level = |nodes: &[[u8; 32]]| -> Vec<[u8; 32]> {
        nodes
            .chunks(2)
            .map(|p| interior_hash(&p[0], &p[1]))
            .collect()
    };
    let eight = level(&level(&level(&leaves[..8])));
    assert_eq!(hex(&interior_hash(&eight[0], &leaves[8])), EXPECTED_ROOT);
}

#[tokio::test]
async fn vector_33_checkpoint_root_equals_tree_root() {
    let log = kat_log();
    let did: scp_did::DID = ID_EVENT_LOG_ACTOR.into();
    let key = reference_key();
    let public = key.public_key();
    let cp = checkpoint::generate_checkpoint(&log, &did, 5, &ReferenceKeySigner(key))
        .await
        .expect("generate checkpoint");

    assert_eq!(
        hex(&cp.merkle_root),
        EXPECTED_ROOT,
        "checkpoint merkle_root"
    );
    assert_eq!(cp.merkle_root, tree::root(&log));
    assert_eq!(cp.event_count, 9, "checkpoint must cover all 9 events");

    // The checkpoint signature covers the §23.16.1 canonical hash. Slice S12
    // asserts it through the production P-256 checkpoint verifier.
    let canonical = checkpoint::compute_checkpoint_canonical_hash(
        "ctx-kat",
        &did,
        cp.event_count,
        &cp.merkle_root,
        Some(5),
        cp.timestamp,
    );
    verify_prehash_strict(&public, &prehash(&canonical), &cp.signature)
        .expect("checkpoint signature must verify over the §23.16.1 canonical hash");
}
