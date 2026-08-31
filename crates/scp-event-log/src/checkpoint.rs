//! Consistency checkpoints for equivocation detection and event log pruning.
//!
//! Members periodically exchange signed Merkle roots. If two members have
//! different roots for the same event count, the relay is equivocating
//! (showing different histories to different members). Detection requires
//! only two honest members.
//!
//! Phase 6 extends checkpoints with:
//! - [`CheckpointPolicy`] -- Configurable checkpoint creation intervals.
//! - [`CheckpointManager`] -- Manages periodic checkpoint creation with
//!   configurable policy and non-blocking semantics.
//! - [`PrunedInclusionProof`] -- Inclusion proof verified against a checkpoint
//!   root instead of the current root (for pruned events).
//! - [`CheckpointedProof`] -- Combines a pruned proof with the checkpoint that
//!   anchors it.
//! - [`TruncatedEventLog`] -- An event log pruned to a checkpoint plus tail
//!   events, supporting proofs for both pruned and live regions.
//!
//! # Types
//!
//! - [`ConsistencyCheckpoint`] -- A signed snapshot of the event log state.
//! - [`CheckpointComparison`] -- The result of comparing a remote checkpoint
//!   against local state.
//! - [`CheckpointScheduler`] -- Tracks when the next checkpoint should be
//!   generated (every 50 events or 10 minutes, whichever comes first).
//! - [`CheckpointPolicy`] -- Configurable intervals for checkpoint creation.
//! - [`CheckpointManager`] -- Manages checkpoint lifecycle.
//! - [`PrunedInclusionProof`] -- Proof against a checkpoint Merkle root.
//! - [`CheckpointedProof`] -- Proof bundled with its anchoring checkpoint.
//! - [`TruncatedEventLog`] -- Log with pre-checkpoint events pruned.
//!
//! See ADR-011 acceptance criterion 8 in `.docs/adrs/phase-2.md`.
//! See ADR-030 in `.docs/adrs/phase-6.md` for pruning and checkpointing.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use scp_clock::Clock;

use super::{ContextId, DID, Ed25519Signature, EventLog, EventLogError, EventLogSigner};
use crate::proof::{self, Direction, InclusionProof, ProofStep};
use crate::tree;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Number of events between automatic checkpoint generation.
const CHECKPOINT_EVENT_INTERVAL: u64 = 50;

/// Time interval (in seconds) between automatic checkpoint generation.
const CHECKPOINT_TIME_INTERVAL_SECS: u64 = 600; // 10 minutes

// ---------------------------------------------------------------------------
// ConsistencyCheckpoint
// ---------------------------------------------------------------------------

/// A signed snapshot of the event log state at a point in time.
///
/// Exchanged between context members as regular MLS application messages.
/// If two members produce checkpoints with different Merkle roots for the
/// same event count, relay equivocation is detected.
///
/// This is the single canonical checkpoint type for the workspace. It is
/// transmitted on the wire (the §9.9.3 checkpoint-exchange message carries a
/// `MessagePack`-serialized value through the inner-envelope pipeline) and
/// embedded in [`crate::sync`]-layer equivocation evidence, so it derives the
/// full serde + equality surface those uses require. `deny_unknown_fields`
/// rejects adversarial extra fields at the deserialization boundary;
/// `serde_bytes` encodes the signature as a compact `MessagePack` binary blob.
///
/// See ADR-011 acceptance criterion 8 and spec §9.9.3.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsistencyCheckpoint {
    /// The context this checkpoint belongs to.
    pub context_id: ContextId,
    /// The DID of the member who generated this checkpoint.
    pub sender_did: DID,
    /// The number of events in the log at checkpoint time.
    pub event_count: u64,
    /// The Merkle root hash at checkpoint time.
    pub merkle_root: [u8; 32],
    /// Current MLS epoch. `None` for Broadcast contexts that do not use MLS.
    pub epoch: Option<u64>,
    /// Unix timestamp (seconds) when the checkpoint was generated.
    pub timestamp: u64,
    /// Ed25519 signature over the canonical hash of all checkpoint fields
    /// (excluding the signature itself).
    #[serde(with = "serde_bytes")]
    pub signature: Ed25519Signature,
}

// ---------------------------------------------------------------------------
// CheckpointComparison
// ---------------------------------------------------------------------------

/// The result of comparing a remote checkpoint against local event log state.
///
/// See ADR-011 acceptance criterion 8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointComparison {
    /// Local and remote logs have the same event count and Merkle root.
    Consistent,
    /// Local and remote logs have the same event count but different Merkle
    /// roots. This indicates relay equivocation.
    Divergent {
        /// The first event index where divergence was detected, if known.
        /// Currently always `None` (pinpointing requires exchanging full
        /// proof paths). Reserved for future bisection-based detection.
        first_divergent_event: Option<u64>,
    },
    /// The local log has fewer events than the remote checkpoint.
    Behind {
        /// The number of events the local log is missing.
        missing_events: u64,
    },
    /// The local log has more events than the remote checkpoint.
    Ahead {
        /// The number of extra events in the local log.
        extra_events: u64,
    },
}

// ---------------------------------------------------------------------------
// CheckpointScheduler
// ---------------------------------------------------------------------------

/// Tracks when the next consistency checkpoint should be generated.
///
/// A checkpoint is due when either:
/// - 50 events have been appended since the last checkpoint, or
/// - 10 minutes have elapsed since the last checkpoint,
///
/// whichever comes first. See ADR-011 acceptance criterion 8.
#[deprecated(note = "Use CheckpointManager instead")]
#[derive(Debug, Clone)]
pub struct CheckpointScheduler {
    /// Number of events appended since the last checkpoint.
    events_since_last: u64,
    /// Unix timestamp (seconds) of the last checkpoint.
    last_checkpoint_timestamp: u64,
}

#[allow(deprecated)]
impl CheckpointScheduler {
    /// Creates a new scheduler with the given initial timestamp.
    ///
    /// The scheduler starts with zero events since the last checkpoint and
    /// the provided timestamp as the baseline.
    #[must_use]
    pub const fn new(initial_timestamp: u64) -> Self {
        Self {
            events_since_last: 0,
            last_checkpoint_timestamp: initial_timestamp,
        }
    }

    /// Records that an event was appended to the log.
    pub const fn record_event(&mut self) {
        self.events_since_last += 1;
    }

    /// Returns `true` if a checkpoint should be generated now.
    ///
    /// A checkpoint is due when either:
    /// - `CHECKPOINT_EVENT_INTERVAL` events have been appended, or
    /// - `CHECKPOINT_TIME_INTERVAL_SECS` seconds have elapsed.
    #[must_use]
    pub const fn is_checkpoint_due(&self, current_timestamp: u64) -> bool {
        if self.events_since_last >= CHECKPOINT_EVENT_INTERVAL {
            return true;
        }
        let elapsed = current_timestamp.saturating_sub(self.last_checkpoint_timestamp);
        elapsed >= CHECKPOINT_TIME_INTERVAL_SECS
    }

    /// Resets the scheduler after a checkpoint has been generated.
    pub const fn reset(&mut self, checkpoint_timestamp: u64) {
        self.events_since_last = 0;
        self.last_checkpoint_timestamp = checkpoint_timestamp;
    }
}

// ---------------------------------------------------------------------------
// CheckpointPolicy (ADR-030 §3)
// ---------------------------------------------------------------------------

/// Configurable checkpoint creation policy.
///
/// Controls how frequently checkpoints are created. Checkpoints are triggered
/// when either the event interval or time interval is reached, provided at
/// least `min_events_since_last` events have been appended since the previous
/// checkpoint.
///
/// See ADR-030 §3 in `.docs/adrs/phase-6.md`.
#[derive(Debug, Clone)]
pub struct CheckpointPolicy {
    /// Create a checkpoint every N events. Default: 10,000.
    pub event_interval: u64,
    /// Create a checkpoint every N seconds. Default: 86,400 (24 hours).
    pub time_interval_secs: u64,
    /// Minimum events since last checkpoint before a new one is created.
    /// Prevents checkpoint spam in low-activity contexts. Default: 100.
    pub min_events_since_last: u64,
}

impl Default for CheckpointPolicy {
    fn default() -> Self {
        Self {
            event_interval: 10_000,
            time_interval_secs: 86_400,
            min_events_since_last: 100,
        }
    }
}

// ---------------------------------------------------------------------------
// CheckpointManager (ADR-030 §3)
// ---------------------------------------------------------------------------

/// Manages periodic checkpoint creation for an event log.
///
/// The manager tracks event count and elapsed time since the last checkpoint,
/// and determines when a new checkpoint should be created according to the
/// configured [`CheckpointPolicy`]. Checkpoint creation captures a snapshot
/// of the current Merkle root and event count, which can then serve as a
/// pruning boundary.
///
/// Checkpoint creation does not block ongoing event log appends -- the
/// manager takes an immutable reference to the log and produces a
/// [`ConsistencyCheckpoint`] without mutating the log.
///
/// # Concurrency
///
/// `CheckpointManager` is intended as a **single-owner-per-context** type:
/// each context task owns exactly one manager instance. The `&mut self`
/// requirement on mutating methods ([`record_event`](Self::record_event),
/// [`maybe_create_checkpoint`](Self::maybe_create_checkpoint),
/// [`force_create_checkpoint`](Self::force_create_checkpoint)) enforces
/// exclusive access through the borrow checker, making accidental data
/// races a compile-time error.
///
/// ## `&mut self` / `&EventLog` asymmetry
///
/// Checkpoint-creating methods take `&mut self` (exclusive access to the
/// manager's internal state: counters, stored checkpoints) but only
/// `&EventLog` (shared access to the log). This asymmetry is intentional:
///
/// - **`&mut self`** -- The manager must update its `events_since_last`
///   counter, `last_checkpoint_timestamp`, and stored checkpoint list.
///   These are manager-private bookkeeping; exclusive access prevents
///   inconsistent counter resets.
/// - **`&EventLog`** -- Checkpoint creation only *reads* the log's Merkle
///   root and event count. Taking `&EventLog` (not `&mut EventLog`)
///   ensures that ongoing appends to the log are not blocked while a
///   checkpoint is being generated.
///
/// ## Sharing across threads
///
/// Although `CheckpointManager` is `Send + Sync` (all fields are plain
/// data), the single-owner-per-context model means sharing is unnecessary
/// in normal operation. If a use case does require sharing (e.g., a
/// monitoring task that reads checkpoint state), wrap the manager in an
/// `Arc<Mutex<CheckpointManager>>` and the log in a separate
/// `Arc<RwLock<EventLog>>`. The two locks remain independent -- holding
/// the manager mutex during checkpoint creation does not contend with log
/// appends, because checkpoint creation requires only `&EventLog` (a read
/// lock on the log).
///
/// See ADR-030 §3 in `.docs/adrs/phase-6.md`.
#[derive(Debug, Clone)]
pub struct CheckpointManager {
    /// The checkpoint creation policy.
    policy: CheckpointPolicy,
    /// Number of events appended since the last checkpoint.
    events_since_last: u64,
    /// Unix timestamp (seconds) of the last checkpoint.
    last_checkpoint_timestamp: u64,
    /// Stored checkpoints in creation order.
    checkpoints: Vec<ConsistencyCheckpoint>,
}

impl CheckpointManager {
    /// Creates a new checkpoint manager with the given policy and initial
    /// timestamp.
    #[must_use]
    pub const fn new(policy: CheckpointPolicy, initial_timestamp: u64) -> Self {
        Self {
            policy,
            events_since_last: 0,
            last_checkpoint_timestamp: initial_timestamp,
            checkpoints: Vec::new(),
        }
    }

    /// Returns a reference to the configured policy.
    #[must_use]
    pub const fn policy(&self) -> &CheckpointPolicy {
        &self.policy
    }

    /// Returns the number of events since the last checkpoint.
    #[must_use]
    pub const fn events_since_last(&self) -> u64 {
        self.events_since_last
    }

    /// Returns a reference to all stored checkpoints.
    #[must_use]
    pub fn checkpoints(&self) -> &[ConsistencyCheckpoint] {
        &self.checkpoints
    }

    /// Returns the most recent checkpoint, if any.
    #[must_use]
    pub fn latest_checkpoint(&self) -> Option<&ConsistencyCheckpoint> {
        self.checkpoints.last()
    }

    /// Records that an event was appended to the log.
    pub const fn record_event(&mut self) {
        self.events_since_last += 1;
    }

    /// Returns `true` if a checkpoint should be created now.
    ///
    /// A checkpoint is due when either:
    /// - `policy.event_interval` events have been appended, or
    /// - `policy.time_interval_secs` seconds have elapsed,
    ///
    /// AND at least `policy.min_events_since_last` events have been appended
    /// (to prevent checkpoint spam in low-activity contexts). The time
    /// interval overrides the minimum event threshold to ensure checkpoints
    /// are created even in very low-activity contexts.
    #[must_use]
    pub const fn is_checkpoint_due(&self, current_timestamp: u64) -> bool {
        let elapsed = current_timestamp.saturating_sub(self.last_checkpoint_timestamp);
        let time_due = elapsed >= self.policy.time_interval_secs;
        let event_due = self.events_since_last >= self.policy.event_interval;
        let min_events_met = self.events_since_last >= self.policy.min_events_since_last;

        // Event threshold met AND minimum events met: create checkpoint.
        if event_due && min_events_met {
            return true;
        }

        // Time threshold met AND minimum events met: create checkpoint.
        // The time interval is the upper bound on checkpoint staleness per
        // ADR-030 §3, but we still require the minimum event threshold to
        // prevent checkpoint spam in low-activity contexts.
        if time_due && min_events_met {
            return true;
        }

        false
    }

    /// Creates a checkpoint from the current event log state if one is due.
    ///
    /// Returns `Some(checkpoint)` if a checkpoint was created, `None` if not
    /// yet due. The checkpoint is stored internally and the scheduler is
    /// reset.
    ///
    /// # Borrow semantics
    ///
    /// This method takes `&mut self` (exclusive manager access) but only
    /// `&EventLog` (shared log access). The `&mut self` is needed to reset
    /// the internal event counter and store the new checkpoint. The `&EventLog`
    /// is intentionally immutable -- checkpoint creation reads the current
    /// Merkle root and event count without blocking concurrent appends to the
    /// log. See the [type-level concurrency docs](Self#concurrency) for the
    /// full rationale.
    ///
    /// # Errors
    ///
    /// Returns [`EventLogError::SigningFailed`] if signing fails.
    pub async fn maybe_create_checkpoint(
        &mut self,
        log: &EventLog,
        sender_did: &DID,
        epoch: u64,
        current_timestamp: u64,
        signer: &(impl EventLogSigner + ?Sized),
    ) -> Result<Option<ConsistencyCheckpoint>, EventLogError> {
        if !self.is_checkpoint_due(current_timestamp) {
            return Ok(None);
        }

        let checkpoint = self
            .create_and_store_checkpoint(log, sender_did, epoch, current_timestamp, signer)
            .await?;

        Ok(Some(checkpoint))
    }

    /// Unconditionally creates a checkpoint from the current event log state.
    ///
    /// Unlike [`Self::maybe_create_checkpoint`], this always creates a
    /// checkpoint regardless of whether one is due. Useful for forced
    /// checkpoints (e.g., before context closure).
    ///
    /// # Borrow semantics
    ///
    /// Same as [`Self::maybe_create_checkpoint`]: `&mut self` for exclusive
    /// manager access, `&EventLog` for non-blocking log reads. See the
    /// [type-level concurrency docs](Self#concurrency) for details.
    ///
    /// # Errors
    ///
    /// Returns [`EventLogError::SigningFailed`] if signing fails.
    pub async fn force_create_checkpoint(
        &mut self,
        log: &EventLog,
        sender_did: &DID,
        epoch: u64,
        current_timestamp: u64,
        signer: &(impl EventLogSigner + ?Sized),
    ) -> Result<ConsistencyCheckpoint, EventLogError> {
        self.create_and_store_checkpoint(log, sender_did, epoch, current_timestamp, signer)
            .await
    }

    /// Creates a checkpoint, stores it, and resets the scheduler.
    ///
    /// Shared implementation for [`Self::maybe_create_checkpoint`] and
    /// [`Self::force_create_checkpoint`].
    async fn create_and_store_checkpoint(
        &mut self,
        log: &EventLog,
        sender_did: &DID,
        epoch: u64,
        current_timestamp: u64,
        signer: &(impl EventLogSigner + ?Sized),
    ) -> Result<ConsistencyCheckpoint, EventLogError> {
        let checkpoint =
            generate_checkpoint_at(log, sender_did, epoch, current_timestamp, signer).await?;

        self.checkpoints.push(checkpoint.clone());
        self.events_since_last = 0;
        self.last_checkpoint_timestamp = current_timestamp;

        Ok(checkpoint)
    }
}

// ---------------------------------------------------------------------------
// PrunedInclusionProof (ADR-030 §4b)
// ---------------------------------------------------------------------------

/// A Merkle inclusion proof verified against a checkpoint's Merkle root
/// rather than the current root.
///
/// Used for events behind a checkpoint boundary. The proof path is identical
/// in structure to a standard [`InclusionProof`], but it is verified against
/// the checkpoint's `merkle_root` instead of the live log's root.
///
/// See ADR-030 §4b in `.docs/adrs/phase-6.md`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrunedInclusionProof {
    /// The leaf hash of the event.
    pub leaf_hash: [u8; 32],
    /// The leaf index in the log.
    pub leaf_index: u64,
    /// Merkle proof path (sibling hashes + directions).
    pub path: Vec<ProofStep>,
    /// The checkpoint Merkle root this proof verifies against.
    pub checkpoint_root: [u8; 32],
    /// The checkpoint event count (number of events at checkpoint time).
    pub checkpoint_event_count: u64,
}

// ---------------------------------------------------------------------------
// CheckpointedProof (ADR-030 §4c)
// ---------------------------------------------------------------------------

/// A proof bundled with the checkpoint that anchors it.
///
/// Provides a self-contained proof that an event was included in the log at
/// the time of the checkpoint. Verification steps:
///
/// 1. Verify the checkpoint signature against the creator's public key.
/// 2. Verify the pruned proof path recomputes to `checkpoint.merkle_root`.
///
/// See ADR-030 §4c in `.docs/adrs/phase-6.md`.
#[derive(Debug, Clone)]
pub struct CheckpointedProof {
    /// The pruned inclusion proof against the checkpoint's Merkle root.
    pub pruned_proof: PrunedInclusionProof,
    /// The checkpoint that anchors this proof.
    pub checkpoint: ConsistencyCheckpoint,
}

// ---------------------------------------------------------------------------
// TruncatedEventLog (ADR-030 §4-5)
// ---------------------------------------------------------------------------

/// An event log where pre-checkpoint events have been pruned.
///
/// After checkpoint creation and verification, events behind the checkpoint
/// can be pruned to save storage. The `TruncatedEventLog` retains:
///
/// - The checkpoint (signed Merkle root snapshot).
/// - Leaf hashes for pruned events (32 bytes each, retained for proof paths).
/// - A full event log for post-checkpoint events.
///
/// This supports both pruned proofs (against the checkpoint root) and live
/// proofs (against the current root).
///
/// See ADR-030 §4-5 in `.docs/adrs/phase-6.md`.
pub struct TruncatedEventLog {
    /// The checkpoint that serves as the pruning boundary.
    checkpoint: ConsistencyCheckpoint,
    /// Leaf hashes for events `0..checkpoint.event_count` (pruned region).
    /// These are retained so proof paths can still be computed.
    pruned_leaf_hashes: Vec<[u8; 32]>,
    /// Interior tree layers for the pruned region. Retained for proof
    /// generation against the checkpoint root.
    pruned_tree_layers: Vec<Vec<[u8; 32]>>,
    /// The live event log containing only post-checkpoint events.
    /// This is a full `EventLog` with its own Merkle tree.
    tail_log: EventLog,
    /// The number of events in the pruned region (== `checkpoint.event_count`).
    pruned_event_count: u64,
}

impl TruncatedEventLog {
    /// Creates a truncated event log from a full log and a checkpoint.
    ///
    /// Captures the Merkle tree state at the checkpoint boundary, then
    /// creates a tail log for post-checkpoint events.
    ///
    /// # Errors
    ///
    /// Returns [`EventLogError::EmptyLog`] if the log has fewer events than
    /// the checkpoint claims.
    pub fn from_log_and_checkpoint(
        log: &EventLog,
        checkpoint: ConsistencyCheckpoint,
    ) -> Result<Self, EventLogError> {
        let total_events = tree::event_count(log);
        let checkpoint_count = checkpoint.event_count;

        if total_events < checkpoint_count {
            return Err(EventLogError::EmptyLog);
        }

        // Extract leaf hashes for the pruned region.
        let all_leaves = log.leaves();
        // checkpoint_count derived from log size; fits in usize.
        #[allow(clippy::cast_possible_truncation)]
        let pruned_leaves: Vec<[u8; 32]> = all_leaves[..checkpoint_count as usize].to_vec();

        // Recompute the pruned region's interior tree.
        let pruned_tree = recompute_tree_from_leaves(&pruned_leaves);

        // Build a tail log containing post-checkpoint events.
        // For the tail log, we use the same context_id but only track
        // post-checkpoint leaves.
        let context_id = log.context_id().to_owned();
        let mut tail_log = EventLog::new(context_id);

        // Copy post-checkpoint leaves into the tail log.
        #[allow(clippy::cast_possible_truncation)]
        let tail_leaves = &all_leaves[checkpoint_count as usize..];
        for &leaf_hash in tail_leaves {
            tail_log.push_leaf_raw(leaf_hash);
        }

        Ok(Self {
            checkpoint,
            pruned_leaf_hashes: pruned_leaves,
            pruned_tree_layers: pruned_tree,
            tail_log,
            pruned_event_count: checkpoint_count,
        })
    }

    /// Returns the checkpoint anchoring this truncated log.
    #[must_use]
    pub const fn checkpoint(&self) -> &ConsistencyCheckpoint {
        &self.checkpoint
    }

    /// Returns the total event count (pruned + tail).
    #[must_use]
    pub const fn total_event_count(&self) -> u64 {
        self.pruned_event_count + tree::event_count(&self.tail_log)
    }

    /// Returns the number of pruned events.
    #[must_use]
    pub const fn pruned_event_count(&self) -> u64 {
        self.pruned_event_count
    }

    /// Returns the number of live (post-checkpoint) events.
    #[must_use]
    pub const fn tail_event_count(&self) -> u64 {
        tree::event_count(&self.tail_log)
    }

    /// Returns a reference to the tail (post-checkpoint) event log.
    #[must_use]
    pub const fn tail_log(&self) -> &EventLog {
        &self.tail_log
    }

    /// Returns the leaf hashes retained for the pruned region.
    #[must_use]
    pub fn pruned_leaf_hashes(&self) -> &[[u8; 32]] {
        &self.pruned_leaf_hashes
    }

    /// Generates a pruned inclusion proof for an event in the pruned region.
    ///
    /// The proof is verified against the checkpoint's Merkle root.
    ///
    /// # Errors
    ///
    /// Returns [`EventLogError::LeafIndexOutOfBounds`] if the index is
    /// outside the pruned region.
    pub fn prove_pruned_inclusion(
        &self,
        leaf_index: u64,
    ) -> Result<PrunedInclusionProof, EventLogError> {
        if leaf_index >= self.pruned_event_count {
            return Err(EventLogError::LeafIndexOutOfBounds {
                index: leaf_index,
                count: self.pruned_event_count,
            });
        }
        // leaf_index validated against pruned_leaf_hashes.len().
        #[allow(clippy::cast_possible_truncation)]
        let idx = leaf_index as usize;
        let leaf_hash = self.pruned_leaf_hashes[idx];

        // Build proof path from the pruned tree.
        let path = build_proof_path(idx, &self.pruned_leaf_hashes, &self.pruned_tree_layers);

        Ok(PrunedInclusionProof {
            leaf_hash,
            leaf_index,
            path,
            checkpoint_root: self.checkpoint.merkle_root,
            checkpoint_event_count: self.pruned_event_count,
        })
    }

    /// Generates a standard inclusion proof for a post-checkpoint event.
    ///
    /// The `tail_index` is relative to the tail log (0-indexed from the
    /// first post-checkpoint event).
    ///
    /// # Errors
    ///
    /// Returns [`EventLogError::LeafIndexOutOfBounds`] if the index is out
    /// of range for the tail log.
    pub fn prove_tail_inclusion(&self, tail_index: u64) -> Result<InclusionProof, EventLogError> {
        proof::prove_inclusion(&self.tail_log, tail_index)
    }

    /// Generates a [`CheckpointedProof`] for an event in the pruned region.
    ///
    /// Bundles the pruned proof with the anchoring checkpoint for
    /// self-contained verification.
    ///
    /// # Errors
    ///
    /// Returns [`EventLogError::LeafIndexOutOfBounds`] if the index is
    /// outside the pruned region.
    pub fn prove_checkpointed(&self, leaf_index: u64) -> Result<CheckpointedProof, EventLogError> {
        let pruned_proof = self.prove_pruned_inclusion(leaf_index)?;
        Ok(CheckpointedProof {
            pruned_proof,
            checkpoint: self.checkpoint.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// Verification functions
// ---------------------------------------------------------------------------

/// Verifies a pruned inclusion proof against a checkpoint Merkle root.
///
/// Recomputes the root from the leaf hash and proof path, then checks that
/// the computed root matches the proof's `checkpoint_root`.
///
/// This is a **pure function** -- no access to the event log is needed.
///
/// See ADR-030 §4b in `.docs/adrs/phase-6.md`.
#[must_use]
pub fn verify_pruned_inclusion(proof: &PrunedInclusionProof) -> bool {
    let mut current_hash = proof.leaf_hash;

    for step in &proof.path {
        current_hash = match step.direction {
            Direction::Left => hash_pair(&step.sibling_hash, &current_hash),
            Direction::Right => hash_pair(&current_hash, &step.sibling_hash),
        };
    }

    // Constant-time comparison to prevent timing side-channels.
    current_hash.ct_eq(&proof.checkpoint_root).into()
}

/// Verifies a checkpointed proof (pruned proof + checkpoint).
///
/// Steps:
/// 1. Verify the pruned inclusion proof recomputes to the checkpoint root.
/// 2. Verify the checkpoint root matches the one in the proof.
///
/// Note: Checkpoint *signature* verification requires the signer's public
/// key, which is a separate concern. This function verifies structural
/// consistency only.
///
/// See ADR-030 §4c in `.docs/adrs/phase-6.md`.
#[must_use]
pub fn verify_checkpointed_proof(proof: &CheckpointedProof) -> bool {
    // Verify the pruned proof's checkpoint_root matches the checkpoint.
    // Constant-time comparison to prevent timing side-channels.
    if !bool::from(
        proof
            .pruned_proof
            .checkpoint_root
            .ct_eq(&proof.checkpoint.merkle_root),
    ) {
        return false;
    }

    // Verify the pruned proof path recomputes to the root.
    verify_pruned_inclusion(&proof.pruned_proof)
}

/// Verifies the Ed25519 signature on a consistency checkpoint (M17).
///
/// Recomputes the canonical hash from the checkpoint fields (same computation
/// used during creation in `generate_checkpoint_at`) and verifies the
/// signature against the provided public key. The public key should be the
/// signing key of the checkpoint's `sender_did`.
///
/// # Errors
///
/// Returns `Err` with a human-readable reason if:
/// - The signature is not 64 bytes.
/// - The Ed25519 signature does not verify against the public key.
pub fn verify_checkpoint_signature(
    checkpoint: &ConsistencyCheckpoint,
    signer_public_key: &ed25519_dalek::VerifyingKey,
) -> Result<(), String> {
    let sig_bytes: [u8; 64] = checkpoint.signature.as_slice().try_into().map_err(|_| {
        format!(
            "checkpoint signature must be 64 bytes, got {}",
            checkpoint.signature.len()
        )
    })?;

    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    let canonical = compute_checkpoint_canonical_hash(
        &checkpoint.context_id,
        &checkpoint.sender_did,
        checkpoint.event_count,
        &checkpoint.merkle_root,
        checkpoint.epoch,
        checkpoint.timestamp,
    );

    signer_public_key
        .verify_strict(&canonical, &signature)
        .map_err(|e| format!("Ed25519 verification failed: {e}"))
}

/// Verifies consistency between two checkpoints.
///
/// Two checkpoints are consistent if they cover the same context and the
/// older checkpoint's Merkle root can be recomputed from the newer
/// checkpoint's event log (given the leaf hashes for the older range).
///
/// For efficiency, this function checks structural consistency:
/// - Same context ID.
/// - The older checkpoint's event count is <= the newer one's.
/// - If event counts are equal, Merkle roots must match.
///
/// Full cryptographic verification (that the newer checkpoint's tree
/// contains the older checkpoint's tree as a prefix) requires access to
/// the leaf hashes, which is done by [`verify_cross_checkpoint_with_leaves`].
#[must_use]
pub fn cross_checkpoint_verify(
    older: &ConsistencyCheckpoint,
    newer: &ConsistencyCheckpoint,
) -> CrossCheckpointResult {
    if older.context_id != newer.context_id {
        return CrossCheckpointResult::ContextMismatch;
    }

    if older.event_count > newer.event_count {
        return CrossCheckpointResult::OrderViolation;
    }

    if older.event_count == newer.event_count {
        // Constant-time comparison to prevent timing side-channels.
        return if older.merkle_root.ct_eq(&newer.merkle_root).into() {
            CrossCheckpointResult::Consistent
        } else {
            CrossCheckpointResult::Divergent
        };
    }

    // older.event_count < newer.event_count -- structurally plausible but
    // we cannot verify Merkle root prefix without leaf data.
    CrossCheckpointResult::PlausiblyConsistent {
        events_between: newer.event_count - older.event_count,
    }
}

/// Verifies cross-checkpoint consistency using leaf hashes.
///
/// Given two checkpoints and the full leaf hashes for the newer checkpoint's
/// range, verifies that the older checkpoint's Merkle root is the correct
/// root for the first `older.event_count` leaves.
///
/// This is the full cryptographic verification of cross-checkpoint
/// consistency.
#[must_use]
pub fn verify_cross_checkpoint_with_leaves(
    older: &ConsistencyCheckpoint,
    newer: &ConsistencyCheckpoint,
    newer_leaves: &[[u8; 32]],
) -> CrossCheckpointResult {
    if older.context_id != newer.context_id {
        return CrossCheckpointResult::ContextMismatch;
    }

    if older.event_count > newer.event_count {
        return CrossCheckpointResult::OrderViolation;
    }

    // newer_leaves.len() bounded by event log size; fits in u64.
    #[allow(clippy::cast_possible_truncation)]
    let newer_count = newer_leaves.len() as u64;
    if newer_count != newer.event_count {
        return CrossCheckpointResult::Divergent;
    }

    if older.event_count == newer.event_count {
        // Constant-time comparison to prevent timing side-channels.
        return if older.merkle_root.ct_eq(&newer.merkle_root).into() {
            CrossCheckpointResult::Consistent
        } else {
            CrossCheckpointResult::Divergent
        };
    }

    // Verify that the first `older.event_count` leaves produce the older
    // checkpoint's Merkle root.
    #[allow(clippy::cast_possible_truncation)]
    let older_leaves = &newer_leaves[..older.event_count as usize];
    let computed_root = compute_root_from_leaves(older_leaves);

    // Constant-time comparison to prevent timing side-channels.
    if computed_root.ct_eq(&older.merkle_root).into() {
        CrossCheckpointResult::Consistent
    } else {
        CrossCheckpointResult::Divergent
    }
}

/// Result of cross-checkpoint consistency verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrossCheckpointResult {
    /// Both checkpoints are consistent (the older is a valid prefix of the
    /// newer).
    Consistent,
    /// The checkpoints cover the same event range but have different Merkle
    /// roots. This indicates equivocation or corruption.
    Divergent,
    /// The checkpoints belong to different contexts.
    ContextMismatch,
    /// The "older" checkpoint has more events than the "newer" one.
    OrderViolation,
    /// Structural consistency is plausible but not cryptographically verified.
    /// Full verification requires leaf hashes (use
    /// [`verify_cross_checkpoint_with_leaves`]).
    PlausiblyConsistent {
        /// Number of events between the two checkpoints.
        events_between: u64,
    },
}

// ---------------------------------------------------------------------------
// Public operations (Phase 2 -- unchanged)
// ---------------------------------------------------------------------------

/// Creates and signs a consistency checkpoint from the current event log state.
///
/// The checkpoint captures the current Merkle root, event count, and MLS epoch,
/// then signs the canonical hash of all checkpoint fields using the provided
/// key custody and signing key handle.
///
/// # Errors
///
/// Returns [`EventLogError::SigningFailed`] if the signing operation fails.
///
/// See ADR-011 acceptance criterion 8.
pub async fn generate_checkpoint(
    log: &EventLog,
    sender_did: &DID,
    epoch: u64,
    signer: &(impl EventLogSigner + ?Sized),
) -> Result<ConsistencyCheckpoint, EventLogError> {
    let timestamp = current_timestamp();
    generate_checkpoint_at(log, sender_did, epoch, timestamp, signer).await
}

/// Compares a received remote checkpoint against the local event log state.
///
/// The comparison logic:
/// 1. If event counts differ, the result is [`CheckpointComparison::Behind`]
///    or [`CheckpointComparison::Ahead`].
/// 2. If event counts match but Merkle roots differ, the result is
///    [`CheckpointComparison::Divergent`] -- this indicates equivocation.
/// 3. If both match, the result is [`CheckpointComparison::Consistent`].
///
/// See ADR-011 acceptance criterion 8.
#[must_use]
pub fn compare_checkpoint(
    local_log: &EventLog,
    remote_checkpoint: &ConsistencyCheckpoint,
) -> CheckpointComparison {
    let local_count = tree::event_count(local_log);
    let remote_count = remote_checkpoint.event_count;

    if local_count < remote_count {
        return CheckpointComparison::Behind {
            missing_events: remote_count - local_count,
        };
    }

    if local_count > remote_count {
        return CheckpointComparison::Ahead {
            extra_events: local_count - remote_count,
        };
    }

    // Counts match -- compare Merkle roots.
    let local_root = tree::root(local_log);
    // Constant-time comparison to prevent timing side-channels.
    if local_root.ct_eq(&remote_checkpoint.merkle_root).into() {
        CheckpointComparison::Consistent
    } else {
        CheckpointComparison::Divergent {
            first_divergent_event: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Creates and signs a checkpoint with an explicit timestamp.
///
/// Used by [`CheckpointManager`] to create checkpoints with a controlled
/// timestamp (important for deterministic testing).
async fn generate_checkpoint_at(
    log: &EventLog,
    sender_did: &DID,
    epoch: u64,
    timestamp: u64,
    signer: &(impl EventLogSigner + ?Sized),
) -> Result<ConsistencyCheckpoint, EventLogError> {
    let context_id = log.context_id().to_owned();
    let event_count = tree::event_count(log);
    let merkle_root = tree::root(log);

    let canonical_hash = compute_checkpoint_canonical_hash(
        &context_id,
        sender_did,
        event_count,
        &merkle_root,
        Some(epoch),
        timestamp,
    );

    let signature = signer
        .sign(&canonical_hash)
        .await
        .map_err(EventLogError::SigningFailed)?;

    Ok(ConsistencyCheckpoint {
        context_id,
        sender_did: sender_did.clone(),
        event_count,
        merkle_root,
        epoch: Some(epoch),
        timestamp,
        signature,
    })
}

/// Builds a Merkle proof path from a leaf to the root using pre-computed
/// leaf hashes and tree layers.
fn build_proof_path(
    leaf_idx: usize,
    leaves: &[[u8; 32]],
    tree_layers: &[Vec<[u8; 32]>],
) -> Vec<ProofStep> {
    if leaves.len() <= 1 {
        return Vec::new();
    }

    let mut path = Vec::new();
    let mut idx = leaf_idx;

    // First level: siblings are in the leaf layer.
    let sibling_idx = idx ^ 1;
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
        // Odd node: no proof step needed -- promoted directly per RFC 6962.
        idx /= 2;
    }

    path
}

/// Recomputes the interior tree layers from a set of leaf hashes.
///
/// Returns the layers from bottom (first interior) to top (root).
fn recompute_tree_from_leaves(leaves: &[[u8; 32]]) -> Vec<Vec<[u8; 32]>> {
    let mut layers = Vec::new();

    if leaves.len() <= 1 {
        return layers;
    }

    let mut current: &[[u8; 32]] = leaves;
    let mut owned: Vec<[u8; 32]>;

    loop {
        let parent_count = current.len().div_ceil(2);
        let mut parents = Vec::with_capacity(parent_count);

        let mut i = 0;
        while i < current.len() {
            if i + 1 < current.len() {
                parents.push(hash_pair(&current[i], &current[i + 1]));
            } else {
                // Odd node: promote directly per RFC 6962.
                parents.push(current[i]);
            }
            i += 2;
        }

        layers.push(parents.clone());

        if parents.len() == 1 {
            break;
        }

        owned = parents;
        current = &owned;
    }

    layers
}

/// Computes the Merkle root from a set of leaf hashes.
///
/// Returns `SHA-256("")` for an empty set (spec §25.8 Vector 15).
fn compute_root_from_leaves(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return crate::tree::empty_tree_root();
    }
    if leaves.len() == 1 {
        return leaves[0];
    }

    let layers = recompute_tree_from_leaves(leaves);
    if let Some(top) = layers.last()
        && top.len() == 1
    {
        return top[0];
    }

    unreachable!("recompute_tree_from_leaves always produces a single root for non-empty input")
}

/// Computes `SHA-256(0x01 || left || right)` for an interior node.
///
/// RFC 6962 Section 2.1 interior node hash function with domain separation.
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Computes the canonical hash of a checkpoint for signing/verification.
///
/// ```text
/// SHA-256("SCP-CHECKPOINT-V1:" || len(context_id) || context_id
///         || len(sender_did) || sender_did || event_count_BE || merkle_root
///         || epoch_flag || epoch_BE || timestamp_BE)
/// ```
///
/// Variable-length fields (`context_id`, `sender_did`) are prefixed with their
/// length as a 4-byte big-endian u32 to prevent field-boundary ambiguity. The
/// `SCP-CHECKPOINT-V1:` domain separator prevents cross-protocol hash confusion.
///
/// The `epoch_flag` byte is `0x01` if epoch is `Some`, `0x00` if `None`.
/// When `Some`, the epoch value follows as 8 big-endian bytes.
#[must_use]
pub fn compute_checkpoint_canonical_hash(
    context_id: &str,
    sender_did: &str,
    event_count: u64,
    merkle_root: &[u8; 32],
    epoch: Option<u64>,
    timestamp: u64,
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"SCP-CHECKPOINT-V1:");
    // Length-prefix closure for variable-length fields. Field values (DIDs,
    // context IDs) are short strings; truncation is not a concern.
    #[allow(clippy::cast_possible_truncation)]
    let length_prefix = |hasher: &mut Sha256, bytes: &[u8]| {
        hasher.update((bytes.len() as u32).to_be_bytes());
        hasher.update(bytes);
    };
    length_prefix(&mut hasher, context_id.as_bytes());
    length_prefix(&mut hasher, sender_did.as_bytes());
    hasher.update(event_count.to_be_bytes());
    hasher.update(merkle_root);
    match epoch {
        Some(e) => {
            hasher.update([0x01]);
            hasher.update(e.to_be_bytes());
        }
        None => {
            hasher.update([0x00]);
        }
    }
    hasher.update(timestamp.to_be_bytes());
    hasher.finalize().to_vec()
}

/// Returns the current Unix timestamp in seconds using [`scp_clock::SystemClock`].
fn current_timestamp() -> u64 {
    scp_clock::SystemClock.now_secs()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::needless_range_loop
)]
mod tests {
    use ed25519_dalek::Verifier;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::DID;
    use crate::test_helpers::{
        TestSigner, did_from_pubkey, leaf_hash_from_event, sign_event, test_did_document,
        test_keypair,
    };
    use crate::tree::{self, GENESIS_PREV_HASH};
    use crate::{EventLog, EventType};

    // -------------------------------------------------------------------
    // Test helpers (checkpoint-specific)
    // -------------------------------------------------------------------

    /// Helper: build a log with `n` events and return the log, leaf hashes,
    /// and the DID used for signing.
    fn build_log(n: u64) -> (EventLog, Vec<[u8; 32]>, DID) {
        let (verifying_key, signing_key) = test_keypair();
        let did = did_from_pubkey(&verifying_key);
        let actor_document = test_did_document(&did, &verifying_key);
        let mut log = EventLog::new("ctx-checkpoint-test".to_owned());
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
            tree::append(&mut log, &event, &actor_document).unwrap();
            let leaf_hash = leaf_hash_from_event(&event);
            leaf_hashes.push(leaf_hash);
            prev_hash = leaf_hash;
        }

        (log, leaf_hashes, did)
    }

    /// Helper: build two identical logs with `n` events each.
    fn build_matching_logs(n: u64) -> (EventLog, EventLog, DID) {
        let (verifying_key, signing_key) = test_keypair();
        let did = did_from_pubkey(&verifying_key);
        let actor_document = test_did_document(&did, &verifying_key);
        let mut log_a = EventLog::new("ctx-checkpoint-test".to_owned());
        let mut log_b = EventLog::new("ctx-checkpoint-test".to_owned());
        let mut prev_hash = GENESIS_PREV_HASH;

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
            tree::append(&mut log_a, &event, &actor_document).unwrap();
            tree::append(&mut log_b, &event, &actor_document).unwrap();
            let leaf_hash = leaf_hash_from_event(&event);
            prev_hash = leaf_hash;
        }

        (log_a, log_b, did)
    }

    // ===================================================================
    // Phase 2 tests (unchanged)
    // ===================================================================

    // -------------------------------------------------------------------
    // generate_checkpoint creates valid signed checkpoint
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn generate_creates_valid_signed_checkpoint() {
        let (log, _, did) = build_log(10);
        let signer = TestSigner::new();

        let checkpoint = generate_checkpoint(&log, &did, 5, &signer).await.unwrap();

        assert_eq!(checkpoint.context_id, "ctx-checkpoint-test");
        assert_eq!(checkpoint.sender_did, did);
        assert_eq!(checkpoint.event_count, 10);
        assert_eq!(checkpoint.merkle_root, tree::root(&log));
        assert_eq!(checkpoint.epoch, Some(5));
        assert!(!checkpoint.signature.is_empty());
        assert_eq!(checkpoint.signature.len(), 64);

        // Verify the signature manually.
        let verifying_key = signer.verifying_key();

        let canonical_hash = compute_checkpoint_canonical_hash(
            &checkpoint.context_id,
            &checkpoint.sender_did,
            checkpoint.event_count,
            &checkpoint.merkle_root,
            checkpoint.epoch,
            checkpoint.timestamp,
        );

        let sig_bytes: [u8; 64] = checkpoint.signature.as_slice().try_into().unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

        verifying_key.verify(&canonical_hash, &signature).unwrap();
    }

    // -------------------------------------------------------------------
    // generate_checkpoint on empty log
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn generate_checkpoint_on_empty_log() {
        let log = EventLog::new("ctx-empty".to_owned());
        let signer = TestSigner::new();
        let did: DID = "did:key:test".into();

        let checkpoint = generate_checkpoint(&log, &did, 0, &signer).await.unwrap();

        assert_eq!(checkpoint.event_count, 0);
        // Empty root is SHA-256(""), not [0u8; 32] (spec §25.8 Vector 15).
        let expected_empty_root: [u8; 32] = Sha256::digest(b"").into();
        assert_eq!(checkpoint.merkle_root, expected_empty_root);
    }

    // -------------------------------------------------------------------
    // compare_checkpoint returns Consistent for matching roots
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn compare_returns_consistent_for_matching_roots() {
        let (log_a, log_b, did) = build_matching_logs(10);
        let signer = TestSigner::new();

        let checkpoint = generate_checkpoint(&log_a, &did, 5, &signer).await.unwrap();

        let result = compare_checkpoint(&log_b, &checkpoint);
        assert_eq!(result, CheckpointComparison::Consistent);
    }

    // -------------------------------------------------------------------
    // compare_checkpoint returns Divergent for mismatched roots at same count
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn compare_returns_divergent_for_mismatched_roots_same_count() {
        let (verifying_key_a, signing_key_a) = test_keypair();
        let did_a = did_from_pubkey(&verifying_key_a);
        let actor_document_a = test_did_document(&did_a, &verifying_key_a);

        let (verifying_key_b, signing_key_b) = test_keypair();
        let did_b = did_from_pubkey(&verifying_key_b);
        let actor_document_b = test_did_document(&did_b, &verifying_key_b);

        let mut log_a = EventLog::new("ctx-checkpoint-test".to_owned());
        let mut log_b = EventLog::new("ctx-checkpoint-test".to_owned());

        let mut prev_hash_a = GENESIS_PREV_HASH;
        let mut prev_hash_b = GENESIS_PREV_HASH;

        for i in 0..5u64 {
            let event_a = sign_event(
                EventType::MessageSent,
                &did_a,
                1_000_000 + i,
                i,
                format!("msg-a-{i}").into_bytes(),
                prev_hash_a,
                &signing_key_a,
            );
            tree::append(&mut log_a, &event_a, &actor_document_a).unwrap();
            let leaf_hash_a: [u8; 32] = {
                let mut h = Sha256::new();
                h.update([0x00]);
                h.update(rmp_serde::to_vec(&event_a).unwrap());
                h.finalize().into()
            };
            prev_hash_a = leaf_hash_a;

            let event_b = sign_event(
                EventType::MessageSent,
                &did_b,
                1_000_000 + i,
                i,
                format!("msg-b-{i}").into_bytes(),
                prev_hash_b,
                &signing_key_b,
            );
            tree::append(&mut log_b, &event_b, &actor_document_b).unwrap();
            let leaf_hash_b: [u8; 32] = {
                let mut h = Sha256::new();
                h.update([0x00]);
                h.update(rmp_serde::to_vec(&event_b).unwrap());
                h.finalize().into()
            };
            prev_hash_b = leaf_hash_b;
        }

        assert_eq!(tree::event_count(&log_a), tree::event_count(&log_b));
        assert_ne!(tree::root(&log_a), tree::root(&log_b));

        let signer = TestSigner::new();
        let checkpoint = generate_checkpoint(&log_a, &did_a, 1, &signer)
            .await
            .unwrap();

        let result = compare_checkpoint(&log_b, &checkpoint);
        assert_eq!(
            result,
            CheckpointComparison::Divergent {
                first_divergent_event: None
            }
        );
    }

    // -------------------------------------------------------------------
    // compare_checkpoint returns Behind when local has fewer events
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn compare_returns_behind_when_local_has_fewer() {
        let (verifying_key, signing_key) = test_keypair();
        let did = did_from_pubkey(&verifying_key);
        let actor_document = test_did_document(&did, &verifying_key);

        let mut log_full = EventLog::new("ctx-checkpoint-test".to_owned());
        let mut log_partial = EventLog::new("ctx-checkpoint-test".to_owned());
        let mut prev_hash = GENESIS_PREV_HASH;

        for i in 0..10u64 {
            let event = sign_event(
                EventType::MessageSent,
                &did,
                1_000_000 + i,
                i,
                format!("message {i}").into_bytes(),
                prev_hash,
                &signing_key,
            );
            tree::append(&mut log_full, &event, &actor_document).unwrap();
            if i < 7 {
                tree::append(&mut log_partial, &event, &actor_document).unwrap();
            }
            let leaf_hash: [u8; 32] = {
                let mut h = Sha256::new();
                h.update([0x00]);
                h.update(rmp_serde::to_vec(&event).unwrap());
                h.finalize().into()
            };
            prev_hash = leaf_hash;
        }

        let signer = TestSigner::new();

        let checkpoint = generate_checkpoint(&log_full, &did, 1, &signer)
            .await
            .unwrap();

        let result = compare_checkpoint(&log_partial, &checkpoint);
        assert_eq!(result, CheckpointComparison::Behind { missing_events: 3 });
    }

    // -------------------------------------------------------------------
    // compare_checkpoint returns Ahead when local has more events
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn compare_returns_ahead_when_local_has_more() {
        let (verifying_key, signing_key) = test_keypair();
        let did = did_from_pubkey(&verifying_key);
        let actor_document = test_did_document(&did, &verifying_key);

        let mut log_full = EventLog::new("ctx-checkpoint-test".to_owned());
        let mut log_partial = EventLog::new("ctx-checkpoint-test".to_owned());
        let mut prev_hash = GENESIS_PREV_HASH;

        for i in 0..10u64 {
            let event = sign_event(
                EventType::MessageSent,
                &did,
                1_000_000 + i,
                i,
                format!("message {i}").into_bytes(),
                prev_hash,
                &signing_key,
            );
            tree::append(&mut log_full, &event, &actor_document).unwrap();
            if i < 4 {
                tree::append(&mut log_partial, &event, &actor_document).unwrap();
            }
            let leaf_hash: [u8; 32] = {
                let mut h = Sha256::new();
                h.update([0x00]);
                h.update(rmp_serde::to_vec(&event).unwrap());
                h.finalize().into()
            };
            prev_hash = leaf_hash;
        }

        let signer = TestSigner::new();

        let checkpoint = generate_checkpoint(&log_partial, &did, 1, &signer)
            .await
            .unwrap();

        let result = compare_checkpoint(&log_full, &checkpoint);
        assert_eq!(result, CheckpointComparison::Ahead { extra_events: 6 });
    }

    // -------------------------------------------------------------------
    // compare_checkpoint returns Consistent for empty logs
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn compare_returns_consistent_for_empty_logs() {
        let log_a = EventLog::new("ctx-empty".to_owned());
        let log_b = EventLog::new("ctx-empty".to_owned());
        let signer = TestSigner::new();
        let did: DID = "did:key:test".into();

        let checkpoint = generate_checkpoint(&log_a, &did, 0, &signer).await.unwrap();

        let result = compare_checkpoint(&log_b, &checkpoint);
        assert_eq!(result, CheckpointComparison::Consistent);
    }

    // -------------------------------------------------------------------
    // CheckpointScheduler: checkpoint due after event threshold
    // -------------------------------------------------------------------

    #[test]
    #[allow(deprecated)]
    fn scheduler_triggers_after_event_threshold() {
        let mut scheduler = CheckpointScheduler::new(1_000_000);

        for _ in 0..49 {
            scheduler.record_event();
            assert!(!scheduler.is_checkpoint_due(1_000_000));
        }

        scheduler.record_event();
        assert!(scheduler.is_checkpoint_due(1_000_000));

        scheduler.reset(1_000_000);
        assert!(!scheduler.is_checkpoint_due(1_000_000));
    }

    // -------------------------------------------------------------------
    // CheckpointScheduler: checkpoint due after time threshold
    // -------------------------------------------------------------------

    #[test]
    #[allow(deprecated)]
    fn scheduler_triggers_after_time_threshold() {
        let scheduler = CheckpointScheduler::new(1_000_000);

        assert!(!scheduler.is_checkpoint_due(1_000_000 + 539));
        assert!(scheduler.is_checkpoint_due(1_000_000 + 600));
        assert!(scheduler.is_checkpoint_due(1_000_000 + 700));
    }

    // -------------------------------------------------------------------
    // CheckpointScheduler: reset clears state
    // -------------------------------------------------------------------

    #[test]
    #[allow(deprecated)]
    fn scheduler_reset_clears_state() {
        let mut scheduler = CheckpointScheduler::new(1_000_000);

        for _ in 0..49 {
            scheduler.record_event();
        }
        assert!(!scheduler.is_checkpoint_due(1_000_539));

        scheduler.reset(1_000_600);

        assert!(!scheduler.is_checkpoint_due(1_000_600));
        assert!(scheduler.is_checkpoint_due(1_001_200));
    }

    #[test]
    fn checkpoint_canonical_hash_is_deterministic() {
        let hash1 = compute_checkpoint_canonical_hash(
            "ctx-1",
            "did:key:abc",
            10,
            &[0xAA; 32],
            Some(5),
            1_000_000,
        );
        let hash2 = compute_checkpoint_canonical_hash(
            "ctx-1",
            "did:key:abc",
            10,
            &[0xAA; 32],
            Some(5),
            1_000_000,
        );
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn checkpoint_canonical_hash_changes_with_different_inputs() {
        let base = compute_checkpoint_canonical_hash(
            "ctx-1",
            "did:key:abc",
            10,
            &[0xAA; 32],
            Some(5),
            1_000_000,
        );

        let different_ctx = compute_checkpoint_canonical_hash(
            "ctx-2",
            "did:key:abc",
            10,
            &[0xAA; 32],
            Some(5),
            1_000_000,
        );
        assert_ne!(base, different_ctx);

        let different_did = compute_checkpoint_canonical_hash(
            "ctx-1",
            "did:key:xyz",
            10,
            &[0xAA; 32],
            Some(5),
            1_000_000,
        );
        assert_ne!(base, different_did);

        let different_count = compute_checkpoint_canonical_hash(
            "ctx-1",
            "did:key:abc",
            11,
            &[0xAA; 32],
            Some(5),
            1_000_000,
        );
        assert_ne!(base, different_count);

        let different_root = compute_checkpoint_canonical_hash(
            "ctx-1",
            "did:key:abc",
            10,
            &[0xBB; 32],
            Some(5),
            1_000_000,
        );
        assert_ne!(base, different_root);

        let different_epoch = compute_checkpoint_canonical_hash(
            "ctx-1",
            "did:key:abc",
            10,
            &[0xAA; 32],
            Some(6),
            1_000_000,
        );
        assert_ne!(base, different_epoch);

        let no_epoch = compute_checkpoint_canonical_hash(
            "ctx-1",
            "did:key:abc",
            10,
            &[0xAA; 32],
            None,
            1_000_000,
        );
        assert_ne!(base, no_epoch);

        let different_ts = compute_checkpoint_canonical_hash(
            "ctx-1",
            "did:key:abc",
            10,
            &[0xAA; 32],
            Some(5),
            2_000_000,
        );
        assert_ne!(base, different_ts);
    }

    #[tokio::test]
    async fn divergent_roots_indicate_equivocation() {
        let (vk_a, sk_a) = test_keypair();
        let did_a = did_from_pubkey(&vk_a);
        let actor_document_a = test_did_document(&did_a, &vk_a);
        let (vk_b, sk_b) = test_keypair();
        let did_b = did_from_pubkey(&vk_b);
        let actor_document_b = test_did_document(&did_b, &vk_b);

        let mut log_a = EventLog::new("ctx-equivocation".to_owned());
        let mut log_b = EventLog::new("ctx-equivocation".to_owned());

        let mut prev_a = GENESIS_PREV_HASH;
        let mut prev_b = GENESIS_PREV_HASH;

        for i in 0..5u64 {
            let event_a = sign_event(
                EventType::MessageSent,
                &did_a,
                1_000_000 + i,
                i,
                format!("alice-{i}").into_bytes(),
                prev_a,
                &sk_a,
            );
            tree::append(&mut log_a, &event_a, &actor_document_a).unwrap();
            let h_a: [u8; 32] = {
                let mut h = Sha256::new();
                h.update([0x00]);
                h.update(rmp_serde::to_vec(&event_a).unwrap());
                h.finalize().into()
            };
            prev_a = h_a;

            let event_b = sign_event(
                EventType::MessageSent,
                &did_b,
                1_000_000 + i,
                i,
                format!("bob-{i}").into_bytes(),
                prev_b,
                &sk_b,
            );
            tree::append(&mut log_b, &event_b, &actor_document_b).unwrap();
            let h_b: [u8; 32] = {
                let mut h = Sha256::new();
                h.update([0x00]);
                h.update(rmp_serde::to_vec(&event_b).unwrap());
                h.finalize().into()
            };
            prev_b = h_b;
        }

        assert_eq!(tree::event_count(&log_a), tree::event_count(&log_b));
        assert_ne!(tree::root(&log_a), tree::root(&log_b));

        let signer = TestSigner::new();

        let checkpoint_a = generate_checkpoint(&log_a, &did_a, 1, &signer)
            .await
            .unwrap();

        let result = compare_checkpoint(&log_b, &checkpoint_a);
        match result {
            CheckpointComparison::Divergent { .. } => {}
            other => panic!("expected Divergent (equivocation), got {other:?}"),
        }
    }

    // ===================================================================
    // Phase 6 tests — CheckpointPolicy
    // ===================================================================

    // -------------------------------------------------------------------
    // 1. CheckpointPolicy default values
    // -------------------------------------------------------------------

    #[test]
    fn checkpoint_policy_default_values() {
        let policy = CheckpointPolicy::default();
        assert_eq!(policy.event_interval, 10_000);
        assert_eq!(policy.time_interval_secs, 86_400);
        assert_eq!(policy.min_events_since_last, 100);
    }

    // ===================================================================
    // Phase 6 tests — CheckpointManager
    // ===================================================================

    // -------------------------------------------------------------------
    // 2. Manager not due before thresholds
    // -------------------------------------------------------------------

    #[test]
    fn manager_not_due_before_thresholds() {
        let policy = CheckpointPolicy {
            event_interval: 100,
            time_interval_secs: 3600,
            min_events_since_last: 10,
        };
        let mut mgr = CheckpointManager::new(policy, 1_000_000);

        // Record 50 events -- not yet at the 100-event threshold.
        for _ in 0..50 {
            mgr.record_event();
        }

        // 30 minutes elapsed -- not yet at 1-hour threshold.
        assert!(!mgr.is_checkpoint_due(1_001_800));
    }

    // -------------------------------------------------------------------
    // 3. Manager due after event interval
    // -------------------------------------------------------------------

    #[test]
    fn manager_due_after_event_interval() {
        let policy = CheckpointPolicy {
            event_interval: 100,
            time_interval_secs: 3600,
            min_events_since_last: 10,
        };
        let mut mgr = CheckpointManager::new(policy, 1_000_000);

        for _ in 0..100 {
            mgr.record_event();
        }

        assert!(mgr.is_checkpoint_due(1_000_000));
    }

    // -------------------------------------------------------------------
    // 4. Manager due after time interval
    // -------------------------------------------------------------------

    #[test]
    fn manager_due_after_time_interval() {
        let policy = CheckpointPolicy {
            event_interval: 10_000,
            time_interval_secs: 3600,
            min_events_since_last: 10,
        };
        let mut mgr = CheckpointManager::new(policy, 1_000_000);

        // Time threshold reached but min_events_since_last not met.
        assert!(!mgr.is_checkpoint_due(1_003_600));

        // Record enough events to meet min_events_since_last.
        for _ in 0..10 {
            mgr.record_event();
        }

        // Now both time threshold and min events are met.
        assert!(mgr.is_checkpoint_due(1_003_600));
    }

    // -------------------------------------------------------------------
    // 5. Manager maybe_create_checkpoint returns None when not due
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn manager_maybe_create_returns_none_when_not_due() {
        let policy = CheckpointPolicy {
            event_interval: 100,
            time_interval_secs: 3600,
            min_events_since_last: 10,
        };
        let mut mgr = CheckpointManager::new(policy, 1_000_000);
        let (log, _, did) = build_log(5);
        let signer = TestSigner::new();

        for _ in 0..5 {
            mgr.record_event();
        }

        let result = mgr
            .maybe_create_checkpoint(&log, &did, 1, 1_000_100, &signer)
            .await
            .unwrap();

        assert!(result.is_none());
        assert!(mgr.checkpoints().is_empty());
    }

    // -------------------------------------------------------------------
    // 6. Manager maybe_create_checkpoint creates when due
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn manager_maybe_create_creates_when_due() {
        let policy = CheckpointPolicy {
            event_interval: 5,
            time_interval_secs: 3600,
            min_events_since_last: 1,
        };
        let mut mgr = CheckpointManager::new(policy, 1_000_000);
        let (log, _, did) = build_log(10);
        let signer = TestSigner::new();

        for _ in 0..5 {
            mgr.record_event();
        }

        let result = mgr
            .maybe_create_checkpoint(&log, &did, 1, 1_000_100, &signer)
            .await
            .unwrap();

        assert!(result.is_some());
        let cp = result.unwrap();
        assert_eq!(cp.event_count, 10);
        assert_eq!(cp.merkle_root, tree::root(&log));

        // Manager should reset after creation.
        assert_eq!(mgr.events_since_last(), 0);
        assert_eq!(mgr.checkpoints().len(), 1);
    }

    // -------------------------------------------------------------------
    // 7. Manager force_create always creates
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn manager_force_create_always_creates() {
        let policy = CheckpointPolicy {
            event_interval: 10_000,
            time_interval_secs: 86_400,
            min_events_since_last: 100,
        };
        let mut mgr = CheckpointManager::new(policy, 1_000_000);
        let (log, _, did) = build_log(3);
        let signer = TestSigner::new();

        // Not due by any metric, but force_create overrides.
        let cp = mgr
            .force_create_checkpoint(&log, &did, 1, 1_000_001, &signer)
            .await
            .unwrap();

        assert_eq!(cp.event_count, 3);
        assert_eq!(mgr.checkpoints().len(), 1);
    }

    // -------------------------------------------------------------------
    // 8. Manager resets scheduler after checkpoint
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn manager_resets_after_checkpoint_creation() {
        let policy = CheckpointPolicy {
            event_interval: 5,
            time_interval_secs: 3600,
            min_events_since_last: 1,
        };
        let mut mgr = CheckpointManager::new(policy, 1_000_000);
        let (log, _, did) = build_log(10);
        let signer = TestSigner::new();

        for _ in 0..5 {
            mgr.record_event();
        }
        assert!(mgr.is_checkpoint_due(1_000_100));

        mgr.maybe_create_checkpoint(&log, &did, 1, 1_000_100, &signer)
            .await
            .unwrap();

        // After creation, should not be due again.
        assert!(!mgr.is_checkpoint_due(1_000_100));
        assert_eq!(mgr.events_since_last(), 0);
    }

    // -------------------------------------------------------------------
    // 9. Manager stores multiple checkpoints
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn manager_stores_multiple_checkpoints() {
        let policy = CheckpointPolicy {
            event_interval: 3,
            time_interval_secs: 86_400,
            min_events_since_last: 1,
        };
        let mut mgr = CheckpointManager::new(policy, 1_000_000);
        let (log, _, did) = build_log(10);
        let signer = TestSigner::new();

        // First checkpoint.
        for _ in 0..3 {
            mgr.record_event();
        }
        mgr.maybe_create_checkpoint(&log, &did, 1, 1_000_100, &signer)
            .await
            .unwrap();

        // Second checkpoint.
        for _ in 0..3 {
            mgr.record_event();
        }
        mgr.maybe_create_checkpoint(&log, &did, 2, 1_000_200, &signer)
            .await
            .unwrap();

        assert_eq!(mgr.checkpoints().len(), 2);
        assert_eq!(mgr.latest_checkpoint().unwrap().epoch, Some(2));
    }

    // -------------------------------------------------------------------
    // 10. Manager latest_checkpoint returns None initially
    // -------------------------------------------------------------------

    #[test]
    fn manager_latest_checkpoint_returns_none_initially() {
        let policy = CheckpointPolicy::default();
        let mgr = CheckpointManager::new(policy, 1_000_000);
        assert!(mgr.latest_checkpoint().is_none());
    }

    // ===================================================================
    // Phase 6 tests — PrunedInclusionProof
    // ===================================================================

    // -------------------------------------------------------------------
    // 11. Pruned proof verifies against checkpoint root
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn pruned_proof_verifies_against_checkpoint_root() {
        let (log, _, did) = build_log(10);
        let signer = TestSigner::new();

        let checkpoint = generate_checkpoint(&log, &did, 1, &signer).await.unwrap();

        let truncated = TruncatedEventLog::from_log_and_checkpoint(&log, checkpoint).unwrap();

        // All pruned events should have valid proofs.
        for i in 0..10 {
            let proof = truncated.prove_pruned_inclusion(i).unwrap();
            assert!(
                verify_pruned_inclusion(&proof),
                "pruned proof failed for leaf {i}",
            );
        }
    }

    // -------------------------------------------------------------------
    // 12. Pruned proof fails with tampered leaf hash
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn pruned_proof_fails_with_tampered_leaf_hash() {
        let (log, _, did) = build_log(8);
        let signer = TestSigner::new();

        let checkpoint = generate_checkpoint(&log, &did, 1, &signer).await.unwrap();

        let truncated = TruncatedEventLog::from_log_and_checkpoint(&log, checkpoint).unwrap();

        let mut proof = truncated.prove_pruned_inclusion(3).unwrap();
        proof.leaf_hash = [0xFF; 32]; // Tamper.
        assert!(!verify_pruned_inclusion(&proof));
    }

    // -------------------------------------------------------------------
    // 13. Pruned proof rejects out-of-bounds index
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn pruned_proof_rejects_out_of_bounds() {
        let (log, _, did) = build_log(5);
        let signer = TestSigner::new();

        let checkpoint = generate_checkpoint(&log, &did, 1, &signer).await.unwrap();

        let truncated = TruncatedEventLog::from_log_and_checkpoint(&log, checkpoint).unwrap();

        let result = truncated.prove_pruned_inclusion(5);
        assert!(result.is_err());
    }

    // ===================================================================
    // Phase 6 tests — CheckpointedProof
    // ===================================================================

    // -------------------------------------------------------------------
    // 14. Checkpointed proof verifies correctly
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn checkpointed_proof_verifies_correctly() {
        let (log, _, did) = build_log(8);
        let signer = TestSigner::new();

        let checkpoint = generate_checkpoint(&log, &did, 1, &signer).await.unwrap();

        let truncated = TruncatedEventLog::from_log_and_checkpoint(&log, checkpoint).unwrap();

        let proof = truncated.prove_checkpointed(4).unwrap();
        assert!(verify_checkpointed_proof(&proof));
    }

    // -------------------------------------------------------------------
    // 15. Checkpointed proof fails with mismatched checkpoint root
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn checkpointed_proof_fails_with_mismatched_root() {
        let (log, _, did) = build_log(8);
        let signer = TestSigner::new();

        let checkpoint = generate_checkpoint(&log, &did, 1, &signer).await.unwrap();

        let truncated = TruncatedEventLog::from_log_and_checkpoint(&log, checkpoint).unwrap();

        let mut proof = truncated.prove_checkpointed(4).unwrap();
        // Tamper with the checkpoint's Merkle root.
        proof.checkpoint.merkle_root = [0xBB; 32];
        assert!(!verify_checkpointed_proof(&proof));
    }

    // ===================================================================
    // Phase 6 tests — TruncatedEventLog
    // ===================================================================

    // -------------------------------------------------------------------
    // 16. Truncated log counts are correct
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn truncated_log_counts_are_correct() {
        let (log, _, did) = build_log(20);
        let signer = TestSigner::new();

        // Create checkpoint at event 10 by making a checkpoint from a
        // partial log with 10 events.
        let mut partial_log = EventLog::new("ctx-checkpoint-test".to_owned());
        let leaves = log.leaves();
        for i in 0..10 {
            partial_log.push_leaf_raw(leaves[i]);
        }

        let checkpoint = generate_checkpoint_at(&partial_log, &did, 1, 1_000_010, &signer)
            .await
            .unwrap();

        let truncated = TruncatedEventLog::from_log_and_checkpoint(&log, checkpoint).unwrap();

        assert_eq!(truncated.pruned_event_count(), 10);
        assert_eq!(truncated.tail_event_count(), 10);
        assert_eq!(truncated.total_event_count(), 20);
    }

    // -------------------------------------------------------------------
    // 17. Truncated log tail proofs work
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn truncated_log_tail_proofs_work() {
        let (log, _, did) = build_log(15);
        let signer = TestSigner::new();

        // Checkpoint at 8 events.
        let mut partial_log = EventLog::new("ctx-checkpoint-test".to_owned());
        let leaves = log.leaves();
        for i in 0..8 {
            partial_log.push_leaf_raw(leaves[i]);
        }

        let checkpoint = generate_checkpoint_at(&partial_log, &did, 1, 1_000_008, &signer)
            .await
            .unwrap();

        let truncated = TruncatedEventLog::from_log_and_checkpoint(&log, checkpoint).unwrap();

        // Verify tail proofs (post-checkpoint events, 0-indexed in tail).
        for i in 0..7 {
            let proof = truncated.prove_tail_inclusion(i).unwrap();
            assert!(
                proof::verify_inclusion(&proof),
                "tail proof failed for index {i}",
            );
        }
    }

    // -------------------------------------------------------------------
    // 18. Truncated log preserves pruned leaf hashes
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn truncated_log_preserves_pruned_leaf_hashes() {
        let (log, leaf_hashes, did) = build_log(10);
        let signer = TestSigner::new();

        let checkpoint = generate_checkpoint(&log, &did, 1, &signer).await.unwrap();

        let truncated = TruncatedEventLog::from_log_and_checkpoint(&log, checkpoint).unwrap();

        let pruned = truncated.pruned_leaf_hashes();
        assert_eq!(pruned.len(), 10);

        for i in 0..10 {
            assert_eq!(pruned[i], leaf_hashes[i]);
        }
    }

    // -------------------------------------------------------------------
    // 19. Truncated log with all events pruned (checkpoint at end)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn truncated_log_all_pruned() {
        let (log, _, did) = build_log(5);
        let signer = TestSigner::new();

        let checkpoint = generate_checkpoint(&log, &did, 1, &signer).await.unwrap();

        let truncated = TruncatedEventLog::from_log_and_checkpoint(&log, checkpoint).unwrap();

        assert_eq!(truncated.pruned_event_count(), 5);
        assert_eq!(truncated.tail_event_count(), 0);
        assert_eq!(truncated.total_event_count(), 5);
    }

    // ===================================================================
    // Phase 6 tests — Cross-checkpoint verification
    // ===================================================================

    // -------------------------------------------------------------------
    // 20. Cross-checkpoint verify detects consistent checkpoints
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn cross_checkpoint_consistent() {
        let (log, _, did) = build_log(20);
        let signer = TestSigner::new();

        // Checkpoint at 10 events.
        let mut log_10 = EventLog::new("ctx-checkpoint-test".to_owned());
        let leaves = log.leaves();
        for i in 0..10 {
            log_10.push_leaf_raw(leaves[i]);
        }
        let cp_10 = generate_checkpoint_at(&log_10, &did, 1, 1_000_010, &signer)
            .await
            .unwrap();

        // Checkpoint at 20 events.
        let cp_20 = generate_checkpoint_at(&log, &did, 2, 1_000_020, &signer)
            .await
            .unwrap();

        // Structural check: plausibly consistent.
        let result = cross_checkpoint_verify(&cp_10, &cp_20);
        assert_eq!(
            result,
            CrossCheckpointResult::PlausiblyConsistent { events_between: 10 },
        );

        // Full verification with leaves.
        let all_leaves: Vec<[u8; 32]> = leaves.to_vec();
        let result = verify_cross_checkpoint_with_leaves(&cp_10, &cp_20, &all_leaves);
        assert_eq!(result, CrossCheckpointResult::Consistent);
    }

    // -------------------------------------------------------------------
    // 21. Cross-checkpoint verify detects divergence
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn cross_checkpoint_divergent() {
        let (log_a, _, did_a) = build_log(10);
        let (log_b, _, _) = build_log(10);
        let signer = TestSigner::new();

        let cp_a = generate_checkpoint_at(&log_a, &did_a, 1, 1_000_010, &signer)
            .await
            .unwrap();

        let cp_b = generate_checkpoint_at(&log_b, &did_a, 1, 1_000_010, &signer)
            .await
            .unwrap();

        // Same event count, different roots.
        let result = cross_checkpoint_verify(&cp_a, &cp_b);
        assert_eq!(result, CrossCheckpointResult::Divergent);
    }

    // -------------------------------------------------------------------
    // 22. Cross-checkpoint verify detects context mismatch
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn cross_checkpoint_context_mismatch() {
        let signer = TestSigner::new();
        let did: DID = "did:key:test".into();

        let log_a = EventLog::new("ctx-a".to_owned());
        let log_b = EventLog::new("ctx-b".to_owned());

        let cp_a = generate_checkpoint_at(&log_a, &did, 0, 1_000_000, &signer)
            .await
            .unwrap();

        let cp_b = generate_checkpoint_at(&log_b, &did, 0, 1_000_000, &signer)
            .await
            .unwrap();

        let result = cross_checkpoint_verify(&cp_a, &cp_b);
        assert_eq!(result, CrossCheckpointResult::ContextMismatch);
    }

    // -------------------------------------------------------------------
    // 23. Cross-checkpoint verify detects order violation
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn cross_checkpoint_order_violation() {
        let (log, _, did) = build_log(20);
        let signer = TestSigner::new();

        let mut log_10 = EventLog::new("ctx-checkpoint-test".to_owned());
        let leaves = log.leaves();
        for i in 0..10 {
            log_10.push_leaf_raw(leaves[i]);
        }

        let cp_10 = generate_checkpoint_at(&log_10, &did, 1, 1_000_010, &signer)
            .await
            .unwrap();

        let cp_20 = generate_checkpoint_at(&log, &did, 2, 1_000_020, &signer)
            .await
            .unwrap();

        // Pass in wrong order.
        let result = cross_checkpoint_verify(&cp_20, &cp_10);
        assert_eq!(result, CrossCheckpointResult::OrderViolation);
    }

    // -------------------------------------------------------------------
    // 24. Cross-checkpoint with leaves detects divergent histories
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn cross_checkpoint_with_leaves_detects_divergent() {
        let (log_a, _, did) = build_log(10);
        let (log_b, _, _) = build_log(20);
        let signer = TestSigner::new();

        // Checkpoint from log_a at 10.
        let cp_a = generate_checkpoint_at(&log_a, &did, 1, 1_000_010, &signer)
            .await
            .unwrap();

        // Checkpoint from log_b at 20 (different history).
        let cp_b = generate_checkpoint_at(&log_b, &did, 2, 1_000_020, &signer)
            .await
            .unwrap();

        // log_b leaves won't match log_a's checkpoint root.
        let b_leaves: Vec<[u8; 32]> = log_b.leaves().to_vec();
        let result = verify_cross_checkpoint_with_leaves(&cp_a, &cp_b, &b_leaves);
        assert_eq!(result, CrossCheckpointResult::Divergent);
    }

    // -------------------------------------------------------------------
    // 25. Cross-checkpoint same checkpoint is consistent
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn cross_checkpoint_same_is_consistent() {
        let (log, _, did) = build_log(10);
        let signer = TestSigner::new();

        let cp = generate_checkpoint_at(&log, &did, 1, 1_000_010, &signer)
            .await
            .unwrap();

        let result = cross_checkpoint_verify(&cp, &cp.clone());
        assert_eq!(result, CrossCheckpointResult::Consistent);
    }

    // NOTE: Test "26. Participation validation works with checkpointed logs (SCP-125 AC6)"
    // has been moved to scp-core integration tests because it depends on
    // crate::trust::compute_participation_record which crosses crate boundaries.
    // 27. Pruned proofs work for all leaf positions in various tree sizes
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn pruned_proofs_all_positions_various_sizes() {
        let signer = TestSigner::new();

        for size in [1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17] {
            let (log, _, did) = build_log(size);
            let checkpoint = generate_checkpoint_at(&log, &did, 1, 1_000_000, &signer)
                .await
                .unwrap();

            let truncated = TruncatedEventLog::from_log_and_checkpoint(&log, checkpoint).unwrap();

            for i in 0..size {
                let proof = truncated.prove_pruned_inclusion(i).unwrap();
                assert!(
                    verify_pruned_inclusion(&proof),
                    "pruned proof failed for size={size}, leaf={i}",
                );
            }
        }
    }

    // -------------------------------------------------------------------
    // 28. Checkpoint creation does not mutate the log (non-blocking)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn checkpoint_does_not_mutate_log() {
        let (log, _, did) = build_log(10);
        let signer = TestSigner::new();

        let root_before = tree::root(&log);
        let count_before = tree::event_count(&log);

        let _cp = generate_checkpoint(&log, &did, 1, &signer).await.unwrap();

        assert_eq!(tree::root(&log), root_before);
        assert_eq!(tree::event_count(&log), count_before);
    }

    // -------------------------------------------------------------------
    // 29. Manager checkpoint creation with explicit timestamp
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn manager_checkpoint_uses_explicit_timestamp() {
        let policy = CheckpointPolicy {
            event_interval: 1,
            time_interval_secs: 1,
            min_events_since_last: 1,
        };
        let mut mgr = CheckpointManager::new(policy, 1_000_000);
        let (log, _, did) = build_log(5);
        let signer = TestSigner::new();

        mgr.record_event();

        let result = mgr
            .maybe_create_checkpoint(&log, &did, 1, 2_000_000, &signer)
            .await
            .unwrap();

        let cp = result.unwrap();
        assert_eq!(cp.timestamp, 2_000_000);
    }

    // -------------------------------------------------------------------
    // 30. Pruned proof path length is O(log n)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn pruned_proof_path_length_is_logarithmic() {
        let signer = TestSigner::new();

        let (log_16, _, did) = build_log(16);
        let cp_16 = generate_checkpoint_at(&log_16, &did, 1, 1_000_000, &signer)
            .await
            .unwrap();
        let truncated_16 = TruncatedEventLog::from_log_and_checkpoint(&log_16, cp_16).unwrap();
        let proof_16 = truncated_16.prove_pruned_inclusion(0).unwrap();
        // 16 leaves => log2(16) = 4 steps.
        assert_eq!(proof_16.path.len(), 4);

        let (log_8, _, did2) = build_log(8);
        let cp_8 = generate_checkpoint_at(&log_8, &did2, 1, 1_000_000, &signer)
            .await
            .unwrap();
        let truncated_8 = TruncatedEventLog::from_log_and_checkpoint(&log_8, cp_8).unwrap();
        let proof_8 = truncated_8.prove_pruned_inclusion(0).unwrap();
        // 8 leaves => log2(8) = 3 steps.
        assert_eq!(proof_8.path.len(), 3);
    }

    // -------------------------------------------------------------------
    // 31. compute_root_from_leaves matches tree::root
    // -------------------------------------------------------------------

    #[test]
    fn compute_root_from_leaves_matches_tree_root() {
        let (log, leaf_hashes, _) = build_log(10);
        let root = compute_root_from_leaves(&leaf_hashes);
        assert_eq!(root, tree::root(&log));
    }

    // -------------------------------------------------------------------
    // 32. compute_root_from_leaves empty returns SHA-256("") per spec §25.8
    // -------------------------------------------------------------------

    #[test]
    fn compute_root_from_leaves_empty_returns_sha256_empty() {
        let root = compute_root_from_leaves(&[]);
        let expected: [u8; 32] = Sha256::digest(b"").into();
        assert_eq!(root, expected);
        // Must NOT be [0u8; 32].
        assert_ne!(root, [0u8; 32]);
    }

    // -------------------------------------------------------------------
    // 33. compute_root_from_leaves single leaf returns leaf
    // -------------------------------------------------------------------

    #[test]
    fn compute_root_from_leaves_single_returns_leaf() {
        let leaf = [0xAB; 32];
        let root = compute_root_from_leaves(&[leaf]);
        assert_eq!(root, leaf);
    }

    // -------------------------------------------------------------------
    // 34. Truncated log rejects checkpoint with more events than log
    // -------------------------------------------------------------------

    #[test]
    fn truncated_log_rejects_checkpoint_exceeding_log() {
        let (log, _, _) = build_log(5);

        // Fake a checkpoint claiming 10 events from a 5-event log.
        let fake_checkpoint = ConsistencyCheckpoint {
            context_id: "ctx-checkpoint-test".to_owned(),
            sender_did: "did:key:test".into(),
            event_count: 10,
            merkle_root: [0u8; 32],
            epoch: Some(1),
            timestamp: 1_000_000,
            signature: vec![0u8; 64],
        };

        let result = TruncatedEventLog::from_log_and_checkpoint(&log, fake_checkpoint);
        assert!(result.is_err());
    }
}
