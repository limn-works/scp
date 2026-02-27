//! Merkle inclusion and absence proofs for the event log.
//!
//! Provides three core operations:
//!
//! - [`prove_inclusion`] -- Generate a Merkle path from a leaf to the root.
//! - [`prove_absence`] -- Prove that a hash is NOT in the log using sorted
//!   leaf neighbors.
//! - [`verify_inclusion`] -- Verify an inclusion proof without access to the
//!   log (pure function).
//!
//! Proof sizes are O(log n) where n is the number of leaves. Absence proofs
//! reveal exactly two leaf hashes (the sorted neighbors of the query hash).
//!
//! See ADR-011 in `.docs/adrs/phase-2.md` for the full design.

use sha2::{Digest, Sha256};

use super::{EventLog, EventLogError};
use crate::event_log::tree;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Direction indicator for a proof step.
///
/// Indicates whether the sibling hash is to the left or right of the node
/// on the path being verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// The sibling is to the left (our node is the right child).
    Left,
    /// The sibling is to the right (our node is the left child).
    Right,
}

/// A single step in a Merkle inclusion proof path.
///
/// Each step contains the sibling hash at a given tree level and indicates
/// whether that sibling is to the left or right of the path node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofStep {
    /// The hash of the sibling node at this tree level.
    pub sibling_hash: [u8; 32],
    /// Whether the sibling is to the left or right of the path node.
    pub direction: Direction,
}

/// A Merkle inclusion proof: the path from a leaf to the root.
///
/// The proof consists of sibling hashes at each tree level with direction
/// indicators. Proof size is O(log n) where n is the number of leaves.
///
/// See ADR-011 acceptance criterion 3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    /// The index of the leaf in the append-order log.
    pub leaf_index: u64,
    /// The SHA-256 hash of the leaf.
    pub leaf_hash: [u8; 32],
    /// The Merkle path from the leaf to the root: sibling hashes with
    /// direction indicators at each level.
    pub path: Vec<ProofStep>,
    /// The Merkle root at the time the proof was generated.
    pub root: [u8; 32],
}

/// A leaf hash paired with its inclusion proof, used in absence proofs.
///
/// See ADR-011 acceptance criterion 4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafWithProof {
    /// The SHA-256 hash of the leaf.
    pub leaf_hash: [u8; 32],
    /// The index of the leaf in the append-order log.
    pub leaf_index: u64,
    /// The inclusion proof for this leaf.
    pub inclusion_proof: InclusionProof,
}

/// An absence proof: proves that a given hash is NOT in the log.
///
/// Uses the sorted leaf hash approach: finds the two adjacent leaf hashes
/// that bracket the query hash in sorted order, and provides inclusion
/// proofs for both. A verifier confirms that both neighbors are in the tree,
/// that they are truly adjacent in sorted order, and that the query hash
/// falls between them.
///
/// **Privacy:** Reveals exactly two leaf hashes (the sorted neighbors).
///
/// See ADR-011 acceptance criterion 4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbsenceProof {
    /// The event hash being proven absent.
    pub query_hash: [u8; 32],
    /// The greatest leaf hash less than `query_hash` in sorted order,
    /// with its inclusion proof. `None` if `query_hash` is less than all
    /// leaf hashes.
    pub lower: Option<LeafWithProof>,
    /// The least leaf hash greater than `query_hash` in sorted order,
    /// with its inclusion proof. `None` if `query_hash` is greater than
    /// all leaf hashes.
    pub upper: Option<LeafWithProof>,
    /// The Merkle root at the time of the proof.
    pub root: [u8; 32],
    /// Total number of leaves in the log.
    pub leaf_count: u64,
}

// ---------------------------------------------------------------------------
// Public operations
// ---------------------------------------------------------------------------

/// Generates a Merkle inclusion proof for the leaf at `leaf_index`.
///
/// The proof consists of sibling hashes at each tree level from the leaf
/// up to the root, along with direction indicators. The proof size is
/// O(log n) where n is the number of leaves.
///
/// # Errors
///
/// Returns [`EventLogError::LeafIndexOutOfBounds`] if `leaf_index` is
/// greater than or equal to the number of leaves.
/// Returns [`EventLogError::EmptyLog`] if the log has no events.
///
/// See ADR-011 acceptance criterion 3.
pub fn prove_inclusion(log: &EventLog, leaf_index: u64) -> Result<InclusionProof, EventLogError> {
    let leaf_count = tree::event_count(log);

    if leaf_count == 0 {
        return Err(EventLogError::EmptyLog);
    }

    if leaf_index >= leaf_count {
        return Err(EventLogError::LeafIndexOutOfBounds {
            index: leaf_index,
            count: leaf_count,
        });
    }

    let leaves = log.leaves();
    #[allow(clippy::cast_possible_truncation)] // leaf_index < leaf_count which fits in leaves.len()
    let leaf_idx_usize = leaf_index as usize;
    let leaf_hash = leaves[leaf_idx_usize];
    let current_root = tree::root(log);

    // Single-leaf tree: no path steps needed.
    if leaf_count == 1 {
        return Ok(InclusionProof {
            leaf_index,
            leaf_hash,
            path: Vec::new(),
            root: current_root,
        });
    }

    let tree_layers = log.tree_layers();
    let mut path = Vec::new();
    let mut idx = leaf_idx_usize;

    // Walk from the leaf layer upward through each interior layer.
    // At each level, determine the sibling and direction.

    // First level: siblings are in the leaf layer.
    let sibling_idx = idx ^ 1; // Toggle the last bit to get sibling.
    if sibling_idx < leaves.len() {
        let direction = if idx.is_multiple_of(2) {
            Direction::Right
        } else {
            Direction::Left
        };
        path.push(ProofStep {
            sibling_hash: leaves[sibling_idx],
            direction,
        });
    } else {
        // Odd node at the end: sibling is itself (promoted).
        path.push(ProofStep {
            sibling_hash: leaves[idx],
            direction: Direction::Right,
        });
    }

    // Move to the parent index for the next level.
    idx /= 2;

    // Remaining levels: siblings are in tree_layers.
    for layer in tree_layers.iter().take(tree_layers.len().saturating_sub(1)) {
        let sibling_idx = idx ^ 1;
        if sibling_idx < layer.len() {
            let direction = if idx.is_multiple_of(2) {
                Direction::Right
            } else {
                Direction::Left
            };
            path.push(ProofStep {
                sibling_hash: layer[sibling_idx],
                direction,
            });
        } else {
            // Odd node: sibling is itself (promoted).
            path.push(ProofStep {
                sibling_hash: layer[idx],
                direction: Direction::Right,
            });
        }
        idx /= 2;
    }

    Ok(InclusionProof {
        leaf_index,
        leaf_hash,
        path,
        root: current_root,
    })
}

/// Generates an absence proof for `event_hash`, proving it is NOT in the log.
///
/// Uses the sorted leaf hash approach: finds the two adjacent leaf hashes
/// that bracket `event_hash` in sorted order and generates inclusion proofs
/// for both.
///
/// # Errors
///
/// Returns [`EventLogError::AbsenceProofForPresentEvent`] if `event_hash`
/// IS in the log.
/// Returns [`EventLogError::EmptyLog`] if the log has no events.
///
/// See ADR-011 acceptance criterion 4.
pub fn prove_absence(log: &EventLog, event_hash: &[u8; 32]) -> Result<AbsenceProof, EventLogError> {
    let leaf_count = tree::event_count(log);

    if leaf_count == 0 {
        return Err(EventLogError::EmptyLog);
    }

    let sorted = log.sorted_leaves();
    let current_root = tree::root(log);

    // Check if the hash is actually present. Use a range query starting
    // from (event_hash, 0) to find any entry with this hash.
    let exact_match = sorted
        .range((*event_hash, 0)..=(*event_hash, u64::MAX))
        .next();

    if exact_match.is_some() {
        return Err(EventLogError::AbsenceProofForPresentEvent);
    }

    // Find the lower neighbor (greatest hash less than event_hash).
    // We query for everything less than (event_hash, 0).
    let lower = sorted
        .range(..(*event_hash, 0))
        .next_back()
        .map(|(hash, index)| (*hash, *index));

    // Find the upper neighbor (least hash greater than event_hash).
    // We query for everything greater than (event_hash, u64::MAX).
    let upper = sorted
        .range((*event_hash, u64::MAX)..)
        .next()
        .map(|(hash, index)| (*hash, *index));

    // Generate inclusion proofs for the neighbors.
    let lower_proof = lower
        .map(|(hash, index)| {
            let inclusion_proof = prove_inclusion(log, index)?;
            Ok(LeafWithProof {
                leaf_hash: hash,
                leaf_index: index,
                inclusion_proof,
            })
        })
        .transpose()?;

    let upper_proof = upper
        .map(|(hash, index)| {
            let inclusion_proof = prove_inclusion(log, index)?;
            Ok(LeafWithProof {
                leaf_hash: hash,
                leaf_index: index,
                inclusion_proof,
            })
        })
        .transpose()?;

    Ok(AbsenceProof {
        query_hash: *event_hash,
        lower: lower_proof,
        upper: upper_proof,
        root: current_root,
        leaf_count,
    })
}

/// Verifies a Merkle inclusion proof.
///
/// Recomputes the root hash by walking from the leaf hash up through the
/// proof path, combining with sibling hashes at each level. Returns `true`
/// if the computed root matches the proof's stated root.
///
/// This is a **pure function** -- no access to the event log is needed.
/// Any third party can verify an inclusion proof.
///
/// See ADR-011 acceptance criterion 5.
#[must_use]
pub fn verify_inclusion(proof: &InclusionProof) -> bool {
    let mut current_hash = proof.leaf_hash;

    for step in &proof.path {
        current_hash = match step.direction {
            // Sibling is on the left: hash(sibling || current).
            Direction::Left => hash_pair(&step.sibling_hash, &current_hash),
            // Sibling is on the right: hash(current || sibling).
            Direction::Right => hash_pair(&current_hash, &step.sibling_hash),
        };
    }

    current_hash == proof.root
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Computes `SHA-256(0x01 || left || right)` for an interior node (RFC 6962 §2.1).
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(&[0x01]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use ed25519_dalek::Signer;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::event_log::tree::{self, GENESIS_PREV_HASH};
    use crate::event_log::{Event, EventLog, EventLogError, EventPayload, EventType};

    // -------------------------------------------------------------------
    // Test helpers
    // -------------------------------------------------------------------

    /// Helper: create a signing keypair.
    fn test_keypair() -> (ed25519_dalek::VerifyingKey, ed25519_dalek::SigningKey) {
        let mut rng = rand::thread_rng();
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        (verifying_key, signing_key)
    }

    /// Helper: encode a public key as a test DID (`did:key:<hex>`).
    fn did_from_pubkey(verifying_key: &ed25519_dalek::VerifyingKey) -> String {
        let hex: String = verifying_key
            .as_bytes()
            .iter()
            .fold(String::new(), |mut acc, b| {
                use std::fmt::Write;
                let _ = write!(acc, "{b:02x}");
                acc
            });
        format!("did:key:{hex}")
    }

    /// Helper: compute the canonical hash for signing an event.
    fn compute_event_canonical_hash(event: &Event) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(event_type_tag(&event.event_type).to_be_bytes());
        hasher.update(event.actor_did.as_bytes());
        hasher.update(event.timestamp.to_be_bytes());
        hasher.update(event.sequence.to_be_bytes());
        hasher.update(&event.payload.data);
        hasher.update(event.prev_hash);
        hasher.finalize().to_vec()
    }

    /// Returns a stable numeric tag for each event type variant.
    const fn event_type_tag(event_type: &EventType) -> u16 {
        match event_type {
            EventType::ContextCreated => 0,
            EventType::ContextClosing => 1,
            EventType::ContextClosed => 2,
            EventType::ContextExpired => 3,
            EventType::MemberJoined => 4,
            EventType::MemberLeft => 5,
            EventType::RoleAssigned => 6,
            EventType::TokenRevoked => 7,
            EventType::MessageSent => 8,
            EventType::ToolRegistered => 9,
            EventType::ToolUpdated => 10,
            EventType::ToolInvoked => 11,
            EventType::ToolVerified => 12,
            EventType::ToolInterfaceEstablished => 13,
            EventType::GovernanceAction => 14,
            EventType::ConsistencyCheckpoint => 15,
            EventType::AbsenceProofRequested => 16,
            EventType::MemberBlocked => 17,
            EventType::KeyEpochAdvance => 18,
            EventType::MediaSessionStarted => 19,
            EventType::MediaSessionEnded => 20,
            EventType::PaymentReceived => 21,
            EventType::EconomicPolicyChanged => 22,
            EventType::SpendingUcanGranted => 23,
            EventType::SpendingUcanRevoked => 24,
        }
    }

    /// Helper: sign an event.
    fn sign_event(
        event_type: EventType,
        actor_did: &str,
        timestamp: u64,
        sequence: u64,
        payload: Vec<u8>,
        prev_hash: [u8; 32],
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Event {
        let mut event = Event {
            event_type,
            actor_did: actor_did.into(),
            timestamp,
            sequence,
            payload: EventPayload { data: payload },
            prev_hash,
            signature: Vec::new(),
        };

        let canonical_hash = compute_event_canonical_hash(&event);
        let signature = signing_key.sign(&canonical_hash);
        event.signature = signature.to_bytes().to_vec();

        event
    }

    /// Helper: build a log with `n` events and return the log and leaf hashes.
    fn build_log(n: u64) -> (EventLog, Vec<[u8; 32]>) {
        let (verifying_key, signing_key) = test_keypair();
        let did = did_from_pubkey(&verifying_key);
        let mut log = EventLog::new("ctx-proof-test".to_owned());
        let mut prev_hash = GENESIS_PREV_HASH;
        let mut leaf_hashes = Vec::new();

        for i in 0..n {
            let event = sign_event(
                EventType::MessageSent,
                &did,
                1_000_000 + i,
                i,
                format!("message {i}").into_bytes(),
                prev_hash,
                &signing_key,
            );
            tree::append(&mut log, &event).unwrap();
            // Compute leaf hash with RFC 6962 domain separation (0x00 prefix).
            let serialized = rmp_serde::to_vec(&event).unwrap();
            let mut hasher = Sha256::new();
            hasher.update(&[0x00]);
            hasher.update(&serialized);
            let leaf_hash: [u8; 32] = hasher.finalize().into();
            leaf_hashes.push(leaf_hash);
            prev_hash = leaf_hash;
        }

        (log, leaf_hashes)
    }

    // -------------------------------------------------------------------
    // prove_inclusion: first leaf
    // -------------------------------------------------------------------

    #[test]
    fn prove_inclusion_first_leaf() {
        let (log, leaf_hashes) = build_log(5);
        let proof = prove_inclusion(&log, 0).unwrap();

        assert_eq!(proof.leaf_index, 0);
        assert_eq!(proof.leaf_hash, leaf_hashes[0]);
        assert_eq!(proof.root, tree::root(&log));
        assert!(verify_inclusion(&proof));
    }

    // -------------------------------------------------------------------
    // prove_inclusion: middle leaf
    // -------------------------------------------------------------------

    #[test]
    fn prove_inclusion_middle_leaf() {
        let (log, leaf_hashes) = build_log(7);
        let proof = prove_inclusion(&log, 3).unwrap();

        assert_eq!(proof.leaf_index, 3);
        assert_eq!(proof.leaf_hash, leaf_hashes[3]);
        assert_eq!(proof.root, tree::root(&log));
        assert!(verify_inclusion(&proof));
    }

    // -------------------------------------------------------------------
    // prove_inclusion: last leaf
    // -------------------------------------------------------------------

    #[test]
    fn prove_inclusion_last_leaf() {
        let (log, leaf_hashes) = build_log(8);
        let last_index = leaf_hashes.len() - 1;
        let proof = prove_inclusion(&log, last_index as u64).unwrap();

        assert_eq!(proof.leaf_index, last_index as u64);
        assert_eq!(proof.leaf_hash, leaf_hashes[last_index]);
        assert_eq!(proof.root, tree::root(&log));
        assert!(verify_inclusion(&proof));
    }

    // -------------------------------------------------------------------
    // prove_inclusion: single-leaf tree
    // -------------------------------------------------------------------

    #[test]
    fn prove_inclusion_single_leaf() {
        let (log, leaf_hashes) = build_log(1);
        let proof = prove_inclusion(&log, 0).unwrap();

        assert_eq!(proof.leaf_index, 0);
        assert_eq!(proof.leaf_hash, leaf_hashes[0]);
        assert!(proof.path.is_empty());
        assert_eq!(proof.root, leaf_hashes[0]);
        assert!(verify_inclusion(&proof));
    }

    // -------------------------------------------------------------------
    // prove_inclusion: all leaves in a larger tree
    // -------------------------------------------------------------------

    #[test]
    fn prove_inclusion_all_leaves_in_larger_tree() {
        let (log, leaf_hashes) = build_log(10);
        for i in 0..leaf_hashes.len() as u64 {
            let proof = prove_inclusion(&log, i).unwrap();
            assert_eq!(proof.leaf_index, i);
            assert_eq!(proof.leaf_hash, leaf_hashes[usize::try_from(i).unwrap()]);
            assert_eq!(proof.root, tree::root(&log));
            assert!(
                verify_inclusion(&proof),
                "inclusion proof failed for leaf {i}"
            );
        }
    }

    // -------------------------------------------------------------------
    // prove_inclusion: proof size is O(log n)
    // -------------------------------------------------------------------

    #[test]
    fn prove_inclusion_proof_size_is_logarithmic() {
        let (log, _) = build_log(16);
        let proof = prove_inclusion(&log, 0).unwrap();
        // 16 leaves => 4 levels => 4 proof steps (log2(16) = 4).
        assert_eq!(proof.path.len(), 4);

        let (log, _) = build_log(8);
        let proof = prove_inclusion(&log, 0).unwrap();
        // 8 leaves => 3 levels => 3 proof steps.
        assert_eq!(proof.path.len(), 3);
    }

    // -------------------------------------------------------------------
    // verify_inclusion: tampered sibling hash fails
    // -------------------------------------------------------------------

    #[test]
    fn verify_inclusion_fails_with_tampered_sibling() {
        let (log, _) = build_log(5);
        let mut proof = prove_inclusion(&log, 2).unwrap();

        // Tamper with the first sibling hash.
        proof.path[0].sibling_hash = [0xFF; 32];

        assert!(!verify_inclusion(&proof));
    }

    // -------------------------------------------------------------------
    // verify_inclusion: tampered leaf hash fails
    // -------------------------------------------------------------------

    #[test]
    fn verify_inclusion_fails_with_tampered_leaf_hash() {
        let (log, _) = build_log(5);
        let mut proof = prove_inclusion(&log, 2).unwrap();

        // Tamper with the leaf hash.
        proof.leaf_hash = [0xAA; 32];

        assert!(!verify_inclusion(&proof));
    }

    // -------------------------------------------------------------------
    // verify_inclusion: tampered root fails
    // -------------------------------------------------------------------

    #[test]
    fn verify_inclusion_fails_with_tampered_root() {
        let (log, _) = build_log(5);
        let mut proof = prove_inclusion(&log, 2).unwrap();

        // Tamper with the root.
        proof.root = [0xBB; 32];

        assert!(!verify_inclusion(&proof));
    }

    // -------------------------------------------------------------------
    // prove_inclusion: out-of-bounds index returns error
    // -------------------------------------------------------------------

    #[test]
    fn prove_inclusion_rejects_out_of_bounds_index() {
        let (log, _) = build_log(5);
        let result = prove_inclusion(&log, 5);
        assert!(result.is_err());
        match result {
            Err(EventLogError::LeafIndexOutOfBounds { index, count }) => {
                assert_eq!(index, 5);
                assert_eq!(count, 5);
            }
            other => panic!("expected LeafIndexOutOfBounds, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // prove_inclusion: empty log returns error
    // -------------------------------------------------------------------

    #[test]
    fn prove_inclusion_rejects_empty_log() {
        let log = EventLog::new("ctx-empty".to_owned());
        let result = prove_inclusion(&log, 0);
        assert!(result.is_err());
        match result {
            Err(EventLogError::EmptyLog) => {}
            other => panic!("expected EmptyLog, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // prove_absence: hash not in log returns valid proof
    // -------------------------------------------------------------------

    #[test]
    fn prove_absence_for_missing_hash() {
        let (log, _) = build_log(5);
        let missing_hash = [0x42; 32];
        let proof = prove_absence(&log, &missing_hash).unwrap();

        assert_eq!(proof.query_hash, missing_hash);
        assert_eq!(proof.root, tree::root(&log));
        assert_eq!(proof.leaf_count, 5);

        // At least one of lower/upper should exist (the log is not empty).
        assert!(proof.lower.is_some() || proof.upper.is_some());

        // Verify the inclusion proofs for the neighbors.
        if let Some(ref lower) = proof.lower {
            assert!(verify_inclusion(&lower.inclusion_proof));
            assert!(lower.leaf_hash < missing_hash);
        }
        if let Some(ref upper) = proof.upper {
            assert!(verify_inclusion(&upper.inclusion_proof));
            assert!(upper.leaf_hash > missing_hash);
        }
    }

    // -------------------------------------------------------------------
    // prove_absence: hash at extremes (below all / above all)
    // -------------------------------------------------------------------

    #[test]
    fn prove_absence_below_all_leaves() {
        let (log, _) = build_log(5);
        // [0x00; 32] is very likely below all leaf hashes (SHA-256 outputs).
        let low_hash = [0x00; 32];
        let proof = prove_absence(&log, &low_hash).unwrap();

        assert_eq!(proof.query_hash, low_hash);
        // lower should be None (nothing below), upper should exist.
        assert!(proof.lower.is_none());
        assert!(proof.upper.is_some());
        if let Some(ref upper) = proof.upper {
            assert!(verify_inclusion(&upper.inclusion_proof));
        }
    }

    #[test]
    fn prove_absence_above_all_leaves() {
        let (log, _) = build_log(5);
        // [0xFF; 32] is very likely above all leaf hashes.
        let high_hash = [0xFF; 32];
        let proof = prove_absence(&log, &high_hash).unwrap();

        assert_eq!(proof.query_hash, high_hash);
        // upper should be None (nothing above), lower should exist.
        assert!(proof.lower.is_some());
        assert!(proof.upper.is_none());
        if let Some(ref lower) = proof.lower {
            assert!(verify_inclusion(&lower.inclusion_proof));
        }
    }

    // -------------------------------------------------------------------
    // prove_absence: hash that IS in log returns error
    // -------------------------------------------------------------------

    #[test]
    fn prove_absence_rejects_present_hash() {
        let (log, leaf_hashes) = build_log(5);
        // Try to prove absence of a hash that IS in the log.
        let result = prove_absence(&log, &leaf_hashes[2]);
        assert!(result.is_err());
        match result {
            Err(EventLogError::AbsenceProofForPresentEvent) => {}
            other => panic!("expected AbsenceProofForPresentEvent, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // prove_absence: empty log returns error
    // -------------------------------------------------------------------

    #[test]
    fn prove_absence_rejects_empty_log() {
        let log = EventLog::new("ctx-empty".to_owned());
        let hash = [0x42; 32];
        let result = prove_absence(&log, &hash);
        assert!(result.is_err());
        match result {
            Err(EventLogError::EmptyLog) => {}
            other => panic!("expected EmptyLog, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // verify_inclusion: true for valid proof, false for tampered
    // -------------------------------------------------------------------

    #[test]
    fn verify_inclusion_true_for_valid_false_for_tampered() {
        let (log, _) = build_log(8);

        // Valid proof.
        let proof = prove_inclusion(&log, 4).unwrap();
        assert!(verify_inclusion(&proof));

        // Tamper with a sibling hash in the middle of the path.
        let mut tampered = proof;
        if tampered.path.len() > 1 {
            tampered.path[1].sibling_hash = [0xDE; 32];
        }
        assert!(!verify_inclusion(&tampered));
    }

    // -------------------------------------------------------------------
    // prove_inclusion: power-of-two tree sizes (2, 4, 8, 16)
    // -------------------------------------------------------------------

    #[test]
    fn prove_inclusion_power_of_two_sizes() {
        for size in [2, 4, 8, 16] {
            let (log, _) = build_log(size);
            for i in 0..size {
                let proof = prove_inclusion(&log, i).unwrap();
                assert!(verify_inclusion(&proof), "failed for size={size}, leaf={i}");
            }
        }
    }

    // -------------------------------------------------------------------
    // prove_inclusion: non-power-of-two tree sizes (3, 5, 6, 7, 9, 13)
    // -------------------------------------------------------------------

    #[test]
    fn prove_inclusion_non_power_of_two_sizes() {
        for size in [3, 5, 6, 7, 9, 13] {
            let (log, _) = build_log(size);
            for i in 0..size {
                let proof = prove_inclusion(&log, i).unwrap();
                assert!(verify_inclusion(&proof), "failed for size={size}, leaf={i}");
            }
        }
    }

    // -------------------------------------------------------------------
    // prove_absence: neighbors are truly adjacent in sorted order
    // -------------------------------------------------------------------

    #[test]
    fn prove_absence_neighbors_are_adjacent() {
        let (log, _) = build_log(10);
        let missing_hash = [0x80; 32]; // Likely in the middle of the hash space.
        let proof = prove_absence(&log, &missing_hash).unwrap();

        // Collect all sorted leaf hashes.
        let sorted: Vec<[u8; 32]> = log.sorted_leaves().iter().map(|(h, _)| *h).collect();

        if let Some(ref lower) = proof.lower
            && let Some(ref upper) = proof.upper
        {
            // Verify that lower and upper are indeed adjacent: no leaf
            // hash exists between them.
            let lower_pos = sorted.iter().position(|h| *h == lower.leaf_hash).unwrap();
            let upper_pos = sorted.iter().position(|h| *h == upper.leaf_hash).unwrap();
            assert_eq!(upper_pos, lower_pos + 1, "neighbors are not adjacent");
        }
    }
}
