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
use scp_primitives::Clock;
use scp_protocol::envelope::MessageType;

// ---------------------------------------------------------------------------
// Shared test clock (reused by Tier 4 targets)
// ---------------------------------------------------------------------------

/// A minimal test clock that returns a fixed `now` (seconds since Unix epoch).
///
/// Used by Tier 4 targets that need a deterministic clock for `ValidationContext`
/// without coupling to `SystemClock`.
pub struct FixedClock(pub u64);

impl Clock for FixedClock {
    fn now_secs(&self) -> u64 {
        self.0
    }

    fn now_millis(&self) -> u64 {
        self.0.saturating_mul(1000)
    }
}

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
/// Path is a fixed-size array of 8 steps. Real Merkle trees in SCP rarely
/// exceed depth 40, and 8 steps is more than sufficient to exercise all
/// proof-verification invariants. Using a fixed array bounds memory at
/// `Arbitrary` generation time, avoiding the previous pattern of generating
/// an unbounded `Vec<ArbProofStep>` before truncating in `into_proof`.
#[derive(Debug, Clone, Arbitrary)]
pub struct ArbInclusionProof {
    pub leaf_index: u64,
    pub leaf_hash: [u8; 32],
    /// Fixed-size path: 8 steps, sufficient for all invariant tests.
    pub path: [ArbProofStep; 8],
    pub root: [u8; 32],
}

impl ArbInclusionProof {
    /// Converts to the production [`InclusionProof`] type.
    pub fn into_proof(self) -> InclusionProof {
        InclusionProof {
            leaf_index: self.leaf_index,
            leaf_hash: self.leaf_hash,
            path: self.path.into_iter().map(ProofStep::from).collect(),
            root: self.root,
        }
    }
}

/// A fuzz-generated AAD differential pair.
///
/// Contains two `(context_id, sender_did)` pairs used by
/// `fuzz_aad_differential` to assert that different inputs produce different
/// AAD bytes (security invariant I9).
///
/// Fields are fixed-size arrays (64 bytes each) rather than `Vec<u8>` to
/// prevent OOM in corpus runs. The AAD format uses length-prefixed encoding,
/// so 64 bytes per field is sufficient to test injectivity.
#[derive(Debug, Clone, Arbitrary)]
pub struct ArbAadInput {
    /// First input: (`context_id` bytes, `sender_did` bytes, epoch, seq).
    ///
    /// Bounded arrays so the fuzzer can mutate them without heap growth.
    /// The target converts to `&str` (skipping non-UTF-8).
    pub a_context_id: [u8; 64],
    pub a_sender_did: [u8; 64],
    pub a_epoch: u64,
    pub a_seq: u64,
    /// Second input: same structure.
    pub b_context_id: [u8; 64],
    pub b_sender_did: [u8; 64],
    pub b_epoch: u64,
    pub b_seq: u64,
}

// ---------------------------------------------------------------------------
// Canonical hash differential types (Tier 3 — T14)
// ---------------------------------------------------------------------------

/// Fuzz-controlled `MessageType` discriminant.
///
/// `MessageType` is not `Arbitrary` in production code so we provide a bounded
/// wrapper.
#[derive(Debug, Clone, Arbitrary)]
pub enum ArbMessageType {
    Content,
    Signaling,
    KeyDistribution,
    Recovery,
}

impl From<ArbMessageType> for MessageType {
    fn from(m: ArbMessageType) -> Self {
        match m {
            ArbMessageType::Content => MessageType::Content,
            ArbMessageType::Signaling => MessageType::Signaling,
            ArbMessageType::KeyDistribution => MessageType::KeyDistribution,
            ArbMessageType::Recovery => MessageType::Recovery,
        }
    }
}

impl ArbMessageType {
    /// Returns a numeric discriminant for equality comparison in differential
    /// targets. Matches the byte values produced by `MessageType::as_discriminator_byte`.
    #[must_use]
    pub fn discriminant(m: &Self) -> u8 {
        match m {
            Self::Content => 0,
            Self::Signaling => 1,
            Self::KeyDistribution => 2,
            Self::Recovery => 3,
        }
    }
}

/// One set of `InnerEnvelope`-compatible fields for the canonical hash
/// differential target.
///
/// All fields are bounded: strings are fixed-size byte arrays (the target
/// converts to `&str`, skipping non-UTF-8), numeric fields are standard
/// integer types. The 128-byte bounds for `context_id` and `sender_did` cover
/// realistic DID lengths while keeping corpus entries compact.
#[derive(Debug, Clone, Arbitrary)]
pub struct ArbInnerEnvelopeFields {
    pub version: u16,
    pub context_id: [u8; 128],
    pub sender_did: [u8; 128],
    pub epoch: u64,
    pub generation: u64,
    pub sequence: u64,
    pub timestamp: u64,
    pub message_type: ArbMessageType,
    pub payload: [u8; 128],
    pub payload_hash: [u8; 32],
    pub provenance_hash: [u8; 32],
}

/// A pair of `InnerEnvelope` field sets for differential canonical hash
/// testing (security invariant I10).
///
/// Using `Arbitrary` rather than splitting raw bytes at a midpoint ensures the
/// fuzzer generates two fully-structured inputs independently, making it far
/// more likely that both inputs are valid enough to reach `compute_canonical_hash`
/// and that the differential assertion actually fires.
#[derive(Debug, Clone, Arbitrary)]
pub struct ArbCanonicalHashInput {
    pub a: ArbInnerEnvelopeFields,
    pub b: ArbInnerEnvelopeFields,
}
