//! Merkle inclusion and absence proofs for the event log.
//!
//! Provides three core operations:
//!
//! - [`prove_inclusion`] -- Generate a Merkle path from a leaf to the root.
//! - [`prove_absence`] -- Build an absence answer by scanning the full local
//!   log: ship the sorted-neighbour inclusion proofs that bracket the query
//!   hash. The neighbour inclusion is checkable off-box, but the append-order
//!   root does not commit to their sorted adjacency (see [`AbsenceProof`]).
//! - [`verify_inclusion`] -- Verify an inclusion proof without access to the
//!   log (pure function).
//!
//! Proof sizes are O(log n) where n is the number of leaves. Absence proofs
//! reveal exactly two leaf hashes (the sorted neighbors of the query hash).
//!
//! See ADR-011 in `.docs/adrs/phase-2.md` for the full design.

use subtle::ConstantTimeEq;

use super::{EventLog, EventLogError};
use crate::tree;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Direction indicator for a proof step.
///
/// Indicates whether the sibling hash is to the left or right of the node
/// on the path being verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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

/// A Merkle consistency proof: proves that the log at `old_size` is a prefix
/// of the log at `new_size` (CT-style per RFC 6962).
///
/// The proof stores the leaf hashes for the full new tree. A verifier
/// reconstructs both roots independently: the old root from the first
/// `old_size` leaf hashes, and the new root from all `new_size` leaf hashes.
/// The prefix relationship is guaranteed because both roots are computed
/// from the same ordered sequence of leaf hashes.
///
/// See ADR-011 and RFC 6962 Section 2.1.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsistencyProof {
    /// The size (number of leaves) of the old tree.
    pub old_size: u64,
    /// The size (number of leaves) of the new tree.
    pub new_size: u64,
    /// The Merkle root of the old tree.
    pub old_root: [u8; 32],
    /// The Merkle root of the new tree.
    pub new_root: [u8; 32],
    /// Leaf hashes for the new tree (first `new_size` leaves). The first
    /// `old_size` entries reconstruct the old root; all entries reconstruct
    /// the new root.
    pub leaf_hashes: Vec<[u8; 32]>,
}

/// An event paired with its Merkle inclusion proof.
///
/// Returned by [`query_events`] to provide both the event data and a
/// cryptographic proof of its inclusion in the log.
#[derive(Debug, Clone)]
pub struct EventWithProof {
    /// The full event data.
    pub event: super::Event,
    /// The Merkle inclusion proof for this event.
    pub inclusion_proof: InclusionProof,
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

/// An absence answer for a query hash, built by inspecting the full local log.
///
/// Uses the sorted leaf hash approach: [`prove_absence`] scans the log's leaf
/// hashes in sorted order, finds the two that bracket the query hash, and ships
/// each neighbour's full [`InclusionProof`]. The two inclusion proofs are
/// checkable off-box against the reported [`root`](Self::root) — a recipient can
/// confirm both neighbours are in the tree and that the query hash sorts strictly
/// between them.
///
/// What the inclusion proofs do NOT establish is that the two neighbours are
/// *adjacent* in sorted order. Adjacency is asserted only by [`prove_absence`]
/// having walked the full local sorted index; the append-order Merkle root does
/// not commit to sorted order, so no off-box verifier can confirm it, and there
/// is deliberately no `verify_absence` in this crate (only [`verify_inclusion`]
/// and [`verify_consistency`]). A recipient checking only the two inclusion
/// proofs cannot rule out a hidden leaf sorting between the neighbours. This is
/// therefore NOT a self-contained, off-box non-membership proof — it is the
/// log's own adjacency assertion plus checkable neighbour-inclusion. The real
/// fix is a sorted/sparse Merkle tree whose root commits to sorted order; see
/// #2314.
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
    }
    // Odd node at the end: no proof step needed -- node is promoted
    // directly to the next level per RFC 6962.

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
        }
        // Odd node: no proof step needed -- node is promoted directly
        // per RFC 6962.
        idx /= 2;
    }

    Ok(InclusionProof {
        leaf_index,
        leaf_hash,
        path,
        root: current_root,
    })
}

/// Builds an [`AbsenceProof`] for `event_hash` by scanning the full local log.
///
/// Uses the sorted leaf hash approach: finds the two leaf hashes that bracket
/// `event_hash` in the local sorted index — adjacent there by construction — and
/// generates inclusion proofs for both. The neighbour inclusion is checkable
/// off-box against the root, but the append-order root does not commit to their
/// sorted adjacency, so the result is not a self-contained off-box
/// non-membership proof; see [`AbsenceProof`] for the full caveat.
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
        .map(|(hash, index)| -> Result<LeafWithProof, EventLogError> {
            let inclusion_proof = prove_inclusion(log, index)?;
            Ok(LeafWithProof {
                leaf_hash: hash,
                leaf_index: index,
                inclusion_proof,
            })
        })
        .transpose()?;

    let upper_proof = upper
        .map(|(hash, index)| -> Result<LeafWithProof, EventLogError> {
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

    // Constant-time comparison to prevent timing side-channels.
    current_hash.ct_eq(&proof.root).into()
}

/// Generates a consistency proof between two tree sizes (CT-style per RFC 6962).
///
/// Proves that the log at `old_size` is a prefix of the log at `new_size`.
/// Stores the leaf hashes for the new tree, enabling independent
/// reconstruction of both roots.
///
/// # Errors
///
/// Returns [`EventLogError::EmptyLog`] if the log is empty.
/// Returns [`EventLogError::LeafIndexOutOfBounds`] if `old_size` is 0,
/// `old_size > new_size`, or `new_size` exceeds the log size.
pub fn prove_consistency(
    log: &EventLog,
    old_size: u64,
    new_size: u64,
) -> Result<ConsistencyProof, EventLogError> {
    let total = tree::event_count(log);

    if total == 0 {
        return Err(EventLogError::EmptyLog);
    }

    if old_size == 0 || old_size > new_size || new_size > total {
        return Err(EventLogError::LeafIndexOutOfBounds {
            index: if old_size == 0 || old_size > new_size {
                old_size
            } else {
                new_size
            },
            count: total,
        });
    }

    let leaves = log.leaves();
    // Safety: old_size <= new_size <= total, and total == leaves.len() which fits in usize.
    #[allow(clippy::cast_possible_truncation)]
    let old_end = old_size as usize;
    #[allow(clippy::cast_possible_truncation)]
    let new_end = new_size as usize;
    let old_root = compute_root_from_leaves(&leaves[..old_end]);
    let new_root = compute_root_from_leaves(&leaves[..new_end]);

    Ok(ConsistencyProof {
        old_size,
        new_size,
        old_root,
        new_root,
        leaf_hashes: leaves[..new_end].to_vec(),
    })
}

/// Verifies a consistency proof: confirms the old tree is a prefix of the new tree.
///
/// Reconstructs both Merkle roots from the stored leaf hashes: the old root
/// from the first `old_size` hashes, and the new root from all `new_size`
/// hashes. Both must match their stated values.
///
/// This is a **pure function** -- no access to the log needed.
///
/// See RFC 6962 Section 2.1.2.
#[must_use]
pub fn verify_consistency(proof: &ConsistencyProof) -> bool {
    if proof.old_size == 0 || proof.old_size > proof.new_size {
        return false;
    }

    // The leaf_hashes must have exactly new_size entries.
    if proof.leaf_hashes.len() as u64 != proof.new_size {
        return false;
    }

    // old_size must not exceed the available leaf hashes.
    if proof.old_size > proof.leaf_hashes.len() as u64 {
        return false;
    }

    // Reconstruct the old root from the first old_size leaf hashes.
    // Safety: old_size <= leaf_hashes.len() validated above.
    #[allow(clippy::cast_possible_truncation)]
    let old_end = proof.old_size as usize;
    let reconstructed_old = compute_root_from_leaves(&proof.leaf_hashes[..old_end]);
    // Constant-time comparison to prevent timing side-channels.
    if !bool::from(reconstructed_old.ct_eq(&proof.old_root)) {
        return false;
    }

    // Reconstruct the new root from all new_size leaf hashes.
    let reconstructed_new = compute_root_from_leaves(&proof.leaf_hashes);
    // Constant-time comparison to prevent timing side-channels.
    if !bool::from(reconstructed_new.ct_eq(&proof.new_root)) {
        return false;
    }

    true
}

/// Queries events in the given range and returns them with inclusion proofs.
///
/// Returns events at sequence numbers in `[start, end)` (half-open range),
/// each paired with its Merkle inclusion proof.
///
/// # Errors
///
/// Returns [`EventLogError::EmptyLog`] if the log is empty.
/// Returns [`EventLogError::LeafIndexOutOfBounds`] if the range exceeds
/// the number of events.
pub fn query_events(
    log: &EventLog,
    start: u64,
    end: u64,
) -> Result<Vec<EventWithProof>, EventLogError> {
    let total = tree::event_count(log);

    if total == 0 {
        return Err(EventLogError::EmptyLog);
    }

    if end > total {
        return Err(EventLogError::LeafIndexOutOfBounds {
            index: end,
            count: total,
        });
    }

    if start >= end {
        return Ok(Vec::new());
    }

    // Safety: end <= total which fits in leaves.len() (usize).
    #[allow(clippy::cast_possible_truncation)]
    let capacity = (end - start) as usize;
    let mut results = Vec::with_capacity(capacity);
    for seq in start..end {
        let event = log.get_event(seq)?.clone();
        let inclusion_proof = prove_inclusion(log, seq)?;
        results.push(EventWithProof {
            event,
            inclusion_proof,
        });
    }

    Ok(results)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

use super::tree::hash_pair;

/// Computes the Merkle root from a slice of leaf hashes.
///
/// Uses the same RFC 6962 structure as the main tree: odd nodes are
/// promoted directly to the next level (not hashed with themselves).
fn compute_root_from_leaves(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return super::tree::empty_tree_root();
    }
    if leaves.len() == 1 {
        return leaves[0];
    }

    let mut current: Vec<[u8; 32]> = leaves.to_vec();
    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        let mut i = 0;
        while i < current.len() {
            if i + 1 < current.len() {
                next.push(hash_pair(&current[i], &current[i + 1]));
            } else {
                // Odd node: promote directly per RFC 6962.
                next.push(current[i]);
            }
            i += 2;
        }
        current = next;
    }
    current[0]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::test_helpers::build_test_log;
    use crate::tree;
    use crate::{EventLog, EventLogError};

    /// Helper: build a log with `n` events and return the log and leaf hashes.
    fn build_log(n: u64) -> (EventLog, Vec<[u8; 32]>) {
        build_test_log(n)
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

    // -------------------------------------------------------------------
    // prove_consistency: basic consistency proof
    // -------------------------------------------------------------------

    #[test]
    fn prove_consistency_basic() {
        let (log, _) = build_log(10);
        let proof = prove_consistency(&log, 5, 10).unwrap();

        assert_eq!(proof.old_size, 5);
        assert_eq!(proof.new_size, 10);
        assert_eq!(proof.leaf_hashes.len(), 10);
        assert!(verify_consistency(&proof));
    }

    // -------------------------------------------------------------------
    // prove_consistency: tampered intermediate hash fails
    // -------------------------------------------------------------------

    #[test]
    fn prove_consistency_tampered_leaf_hash_fails() {
        let (log, _) = build_log(10);
        let mut proof = prove_consistency(&log, 5, 10).unwrap();

        // Tamper with a leaf hash in the middle.
        proof.leaf_hashes[3] = [0xFF; 32];

        assert!(!verify_consistency(&proof));
    }

    #[test]
    fn prove_consistency_tampered_new_leaf_fails() {
        let (log, _) = build_log(10);
        let mut proof = prove_consistency(&log, 5, 10).unwrap();

        // Tamper with a new leaf hash (beyond old_size).
        proof.leaf_hashes[7] = [0xFF; 32];

        assert!(!verify_consistency(&proof));
    }

    // -------------------------------------------------------------------
    // prove_consistency: same size returns valid proof with empty path
    // -------------------------------------------------------------------

    #[test]
    fn prove_consistency_same_size() {
        let (log, _) = build_log(5);
        let proof = prove_consistency(&log, 5, 5).unwrap();

        assert_eq!(proof.old_size, 5);
        assert_eq!(proof.new_size, 5);
        assert_eq!(proof.old_root, proof.new_root);
        assert_eq!(proof.leaf_hashes.len(), 5);
        assert!(verify_consistency(&proof));
    }

    // -------------------------------------------------------------------
    // prove_consistency: power-of-two sizes
    // -------------------------------------------------------------------

    #[test]
    fn prove_consistency_power_of_two() {
        let (log, _) = build_log(16);
        for old in [1, 2, 4, 8] {
            let proof = prove_consistency(&log, old, 16).unwrap();
            assert!(
                verify_consistency(&proof),
                "failed for old_size={old}, new_size=16"
            );
        }
    }

    // -------------------------------------------------------------------
    // prove_consistency: non-power-of-two sizes
    // -------------------------------------------------------------------

    #[test]
    fn prove_consistency_non_power_of_two() {
        let (log, _) = build_log(13);
        for old in [1, 3, 5, 7, 9, 11] {
            let proof = prove_consistency(&log, old, 13).unwrap();
            assert!(
                verify_consistency(&proof),
                "failed for old_size={old}, new_size=13"
            );
        }
    }

    // -------------------------------------------------------------------
    // prove_consistency: errors
    // -------------------------------------------------------------------

    #[test]
    fn prove_consistency_rejects_empty_log() {
        let log = EventLog::new("ctx-empty".to_owned());
        let result = prove_consistency(&log, 1, 2);
        assert!(matches!(result.unwrap_err(), EventLogError::EmptyLog));
    }

    #[test]
    fn prove_consistency_rejects_zero_old_size() {
        let (log, _) = build_log(5);
        let result = prove_consistency(&log, 0, 5);
        assert!(matches!(
            result.unwrap_err(),
            EventLogError::LeafIndexOutOfBounds { .. }
        ));
    }

    #[test]
    fn prove_consistency_rejects_old_greater_than_new() {
        let (log, _) = build_log(5);
        let result = prove_consistency(&log, 5, 3);
        assert!(matches!(
            result.unwrap_err(),
            EventLogError::LeafIndexOutOfBounds { .. }
        ));
    }

    #[test]
    fn prove_consistency_rejects_new_exceeding_log() {
        let (log, _) = build_log(5);
        let result = prove_consistency(&log, 3, 10);
        assert!(matches!(
            result.unwrap_err(),
            EventLogError::LeafIndexOutOfBounds { .. }
        ));
    }

    // -------------------------------------------------------------------
    // get_event: retrieval tests
    // -------------------------------------------------------------------

    #[test]
    fn get_event_returns_correct_event() {
        let (log, _) = build_log(10);
        let event = log.get_event(5).unwrap();

        assert_eq!(event.sequence, 5);
        assert_eq!(event.payload.data, b"message 5");
    }

    #[test]
    fn get_event_all_events_match() {
        let (log, _) = build_log(10);
        for i in 0..10u64 {
            let event = log.get_event(i).unwrap();
            assert_eq!(event.sequence, i);
            assert_eq!(event.payload.data, format!("message {i}").into_bytes());
        }
    }

    #[test]
    fn get_event_out_of_bounds() {
        let (log, _) = build_log(5);
        let result = log.get_event(5);
        assert!(matches!(
            result.unwrap_err(),
            EventLogError::LeafIndexOutOfBounds { index: 5, count: 5 }
        ));
    }

    #[test]
    fn get_event_empty_log() {
        let log = EventLog::new("ctx-empty".to_owned());
        let result = log.get_event(0);
        assert!(matches!(result.unwrap_err(), EventLogError::EmptyLog));
    }

    // -------------------------------------------------------------------
    // query_events: range query with proofs
    // -------------------------------------------------------------------

    #[test]
    fn query_events_returns_events_with_valid_proofs() {
        let (log, _) = build_log(10);
        let results = query_events(&log, 3, 7).unwrap();

        assert_eq!(results.len(), 4);
        for (i, result) in results.iter().enumerate() {
            let expected_seq = 3 + i as u64;
            assert_eq!(result.event.sequence, expected_seq);
            assert!(verify_inclusion(&result.inclusion_proof));
        }
    }

    #[test]
    fn query_events_empty_range_returns_empty() {
        let (log, _) = build_log(10);
        let results = query_events(&log, 5, 5).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn query_events_full_range() {
        let (log, _) = build_log(5);
        let results = query_events(&log, 0, 5).unwrap();
        assert_eq!(results.len(), 5);
        for (i, result) in results.iter().enumerate() {
            assert_eq!(result.event.sequence, i as u64);
            assert!(verify_inclusion(&result.inclusion_proof));
        }
    }

    #[test]
    fn query_events_rejects_out_of_bounds() {
        let (log, _) = build_log(5);
        let result = query_events(&log, 3, 10);
        assert!(matches!(
            result.unwrap_err(),
            EventLogError::LeafIndexOutOfBounds {
                index: 10,
                count: 5
            }
        ));
    }

    #[test]
    fn query_events_rejects_empty_log() {
        let log = EventLog::new("ctx-empty".to_owned());
        let result = query_events(&log, 0, 1);
        assert!(matches!(result.unwrap_err(), EventLogError::EmptyLog));
    }
}
