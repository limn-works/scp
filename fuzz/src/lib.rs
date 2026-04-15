//! Shared structured types for Tier 3–4 fuzz targets.
//!
//! Tier 1–2 targets use raw bytes + dictionary files and never import from here.
//! Tier 3–4 targets that require semantically valid structures use the
//! [`Arbitrary`](arbitrary::Arbitrary) types defined in this module so that
//! libFuzzer's mutation engine can generate meaningful inputs.
//!
//! # Guidelines
//!
//! - Keep all fields bounded — unbounded `Vec`s cause OOM in corpus runs.
//! - Use `#[arbitrary(with = ...)]` sparingly; prefer explicit bound wrappers.
//! - Never place invariant assertions here; keep them in individual targets.

use arbitrary::Arbitrary;
use scp_event_log::proof::{Direction, InclusionProof, ProofStep};

// ---------------------------------------------------------------------------
// Merkle proof types (Tier 3 — T15)
// ---------------------------------------------------------------------------

/// Bounded direction for use in `Arbitrary` proof steps.
#[derive(Debug, Clone, Arbitrary)]
pub enum ArbDirection {
    Left,
    Right,
}

impl From<ArbDirection> for Direction {
    fn from(d: ArbDirection) -> Self {
        match d {
            ArbDirection::Left => Direction::Left,
            ArbDirection::Right => Direction::Right,
        }
    }
}

/// A single step in a fuzz-generated Merkle proof path.
#[derive(Debug, Clone, Arbitrary)]
pub struct ArbProofStep {
    pub sibling_hash: [u8; 32],
    pub direction: ArbDirection,
}

impl From<ArbProofStep> for ProofStep {
    fn from(s: ArbProofStep) -> Self {
        ProofStep {
            sibling_hash: s.sibling_hash,
            direction: s.direction.into(),
        }
    }
}

/// A fuzz-generated Merkle inclusion proof.
///
/// Path length is bounded to 64 steps (supports trees up to 2^64 leaves).
#[derive(Debug, Clone, Arbitrary)]
pub struct ArbInclusionProof {
    pub leaf_index: u64,
    pub leaf_hash: [u8; 32],
    /// Bounded path: at most 64 steps (covers trees up to 2^64 leaves).
    pub path: Vec<ArbProofStep>,
    pub root: [u8; 32],
}

impl ArbInclusionProof {
    /// Converts to the production [`InclusionProof`] type, truncating path to
    /// [`MAX_PROOF_PATH_STEPS`] steps to avoid OOM in corpus runs.
    pub fn into_proof(self) -> InclusionProof {
        const MAX_PROOF_PATH_STEPS: usize = 64;
        InclusionProof {
            leaf_index: self.leaf_index,
            leaf_hash: self.leaf_hash,
            path: self
                .path
                .into_iter()
                .take(MAX_PROOF_PATH_STEPS)
                .map(ProofStep::from)
                .collect(),
            root: self.root,
        }
    }
}

/// A fuzz-generated AAD differential pair.
///
/// Contains two `(context_id, sender_did)` pairs used by
/// `fuzz_aad_differential` to assert that different inputs produce different
/// AAD bytes (security invariant I9).
#[derive(Debug, Clone, Arbitrary)]
pub struct ArbAadInput {
    /// First input: (`context_id` bytes, `sender_did` bytes, epoch, seq).
    ///
    /// Kept as byte vectors so the fuzzer can mutate them freely. The target
    /// converts to `&str` (skipping non-UTF-8).
    pub a_context_id: Vec<u8>,
    pub a_sender_did: Vec<u8>,
    pub a_epoch: u64,
    pub a_seq: u64,
    /// Second input: same structure.
    pub b_context_id: Vec<u8>,
    pub b_sender_did: Vec<u8>,
    pub b_epoch: u64,
    pub b_seq: u64,
}
