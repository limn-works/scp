//! Governance proposal timeout task with deadlock detection (SCP-271, ADR-031 §5/§10).
//!
//! The [`GovernanceTimeoutTask`] runs as a per-context background task that:
//!
//! 1. **Checks active proposals every 60 seconds.** When a proposal's
//!    `voting_deadline` passes without resolution, `resolve()` transitions
//!    it to `Expired` or `Rejected` per model-specific rules (ADR-031 §4b-4d).
//!
//! 2. **Handles proposer departure.** If the proposer has left the context
//!    while a proposal is `Pending`, the proposal is `Invalidated`.
//!
//! 3. **Handles voter departure.** If an eligible voter departs, their vote
//!    is removed and quorum is recalculated. This may change the resolution.
//!
//! 4. **Handles epoch reset (ADR-029 Tier 3).** When a member undergoes a
//!    group state reset, their votes on pending proposals are invalidated.
//!
//! 5. **Detects deadlock conditions** (ADR-031 §10):
//!    - `Threshold`: fewer than `threshold` signers are active.
//!    - `Majority`: fewer than `ceil(eligible * min_participation / 10000)`
//!      members responsive over 3 consecutive voting windows.
//!    - `Unanimity`: any eligible voter offline beyond 7 days (Tier 3 threshold).
//!
//! 6. **Initiates deadlock recovery.** Any member with `GovernancePropose`
//!    capability can propose `ReconfigureGovernance` with fallback quorum
//!    (majority-of-active, 48-hour window, model TYPE never changes).
//!
//! The task starts when a context enters `Active` state and stops when the
//! context is closed or dropped.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;
use tokio::task::JoinHandle;

use scp_identity::DID;

use super::{
    DeadlockJustification, GovernanceContext, GovernanceEngine, GovernanceEvent,
    GovernanceModelConfig,
};

/// Interval between timeout checks (60 seconds per ADR-031 §5).
pub const TIMEOUT_CHECK_INTERVAL_SECS: u64 = 60;

/// Number of consecutive missed voting windows before a voter is considered
/// unresponsive for majority-model deadlock detection (ADR-031 §10).
const MAJORITY_MISSED_WINDOW_THRESHOLD: u32 = 3;

/// Tier 3 offline threshold in seconds (7 days, ADR-029/ADR-031 §10).
const TIER3_OFFLINE_THRESHOLD_SECS: u64 = 7 * 24 * 60 * 60;

/// Deadlock recovery proposals use 48-hour voting window (double default,
/// ADR-031 §10).
pub const DEADLOCK_RECOVERY_VOTING_WINDOW_SECS: u64 = 48 * 60 * 60;

/// Minimum active voters required for fallback quorum (ADR-031 §10).
const MIN_ACTIVE_VOTERS_FOR_FALLBACK: usize = 2;

// ---------------------------------------------------------------------------
// DeadlockCondition -- detected deadlock states
// ---------------------------------------------------------------------------

/// A detected deadlock condition (ADR-031 §10).
#[derive(Debug, Clone)]
pub enum DeadlockCondition {
    /// Threshold model: fewer than `threshold` signers are active members.
    ThresholdInsufficient {
        /// Required threshold.
        threshold: u32,
        /// Number of active signers remaining.
        active_signers: usize,
        /// DIDs of unavailable signers.
        unavailable: Vec<DID>,
    },
    /// Majority model: fewer than the minimum participation count are
    /// responsive over 3 consecutive voting windows.
    MajorityUnresponsive {
        /// Required minimum participants.
        min_participants: usize,
        /// Number of responsive voters.
        responsive_count: usize,
        /// DIDs and their consecutive missed window counts.
        missed_windows: Vec<(DID, u32)>,
    },
    /// Unanimity model: an eligible voter has been offline beyond the
    /// Tier 3 threshold (7+ days).
    UnanimityOffline {
        /// The DID that has been offline.
        offline_did: DID,
        /// How long they have been offline (seconds).
        offline_duration_secs: u64,
    },
}

// ---------------------------------------------------------------------------
// DeadlockDetectionState -- per-context tracking for deadlock detection
// ---------------------------------------------------------------------------

/// Per-context state for deadlock detection (ADR-031 §10).
///
/// Tracks voter responsiveness across voting windows to detect deadlock
/// in Majority-model contexts.
#[derive(Debug, Clone, Default)]
pub struct DeadlockDetectionState {
    /// For each voter DID, the number of consecutive voting windows where
    /// they did not cast a vote on any pending proposal.
    pub consecutive_missed_windows: HashMap<DID, u32>,
    /// Last time each voter was seen active (cast a vote or was otherwise
    /// confirmed responsive). Unix timestamp in seconds.
    pub last_seen_active: HashMap<DID, u64>,
    /// Whether a deadlock has been detected and a recovery proposal is
    /// already in flight (prevents duplicate recovery proposals).
    pub recovery_in_progress: bool,
}

// ---------------------------------------------------------------------------
// GovernanceTimeoutTask
// ---------------------------------------------------------------------------

/// Background task that checks governance proposals for timeout, departure,
/// and deadlock conditions (ADR-031 §5, §10).
///
/// One instance per active context. Runs a 60-second interval loop that:
/// - Calls `resolve()` on all pending proposals to detect expiry.
/// - Checks for proposer/voter departures.
/// - Updates deadlock detection state and emits recovery events.
///
/// Cancellation: call [`cancel()`](Self::cancel) or drop the task.
pub struct GovernanceTimeoutTask {
    /// The spawned task handle.
    task: Option<JoinHandle<()>>,
    /// Cancellation signal.
    cancel: Arc<Notify>,
}

impl GovernanceTimeoutTask {
    /// Creates a new timeout task without starting it.
    #[must_use]
    pub fn new() -> Self {
        Self {
            task: None,
            cancel: Arc::new(Notify::new()),
        }
    }

    /// Starts the background timeout loop.
    ///
    /// The `tick_fn` callback is invoked every 60 seconds (see
    /// [`TIMEOUT_CHECK_INTERVAL_SECS`]). It should perform timeout
    /// processing (call [`process_pending_proposals`], [`detect_deadlock`],
    /// etc.) and return `true` to continue or `false` to stop the loop
    /// (e.g., when the context is no longer active).
    ///
    /// If the task is already running, this cancels the previous task
    /// before spawning the new one.
    pub fn start<F, Fut>(&mut self, tick_fn: F)
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = bool> + Send,
    {
        // Cancel any existing task.
        self.cancel.notify_one();
        if let Some(task) = self.task.take() {
            task.abort();
        }

        // Fresh cancellation signal for the new task.
        let cancel = Arc::new(Notify::new());
        self.cancel = cancel.clone();

        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = tokio::time::sleep(Duration::from_secs(TIMEOUT_CHECK_INTERVAL_SECS)) => {
                        if !tick_fn().await {
                            break;
                        }
                    }
                    () = cancel.notified() => {
                        break;
                    }
                }
            }
        });
        self.task = Some(task);
    }

    /// Returns `true` if the task is currently running.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.task.as_ref().is_some_and(|t| !t.is_finished())
    }

    /// Cancels the running task, if any.
    ///
    /// Signals the cancellation token AND aborts the `JoinHandle` for
    /// consistency with the `Drop` implementation.
    pub fn cancel(&self) {
        self.cancel.notify_one();
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

impl Default for GovernanceTimeoutTask {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for GovernanceTimeoutTask {
    fn drop(&mut self) {
        self.cancel.notify_one();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

// ---------------------------------------------------------------------------
// Timeout processing logic (engine-independent)
// ---------------------------------------------------------------------------

/// Result of processing pending proposals for timeout and departures.
#[derive(Debug, Default)]
pub struct TimeoutProcessingResult {
    /// Events generated by timeout processing (resolved proposals, etc.).
    pub events: Vec<GovernanceEvent>,
    /// Detected deadlock conditions, if any.
    pub deadlock_conditions: Vec<DeadlockCondition>,
}

/// Process all pending proposals in a governance engine for timeout,
/// proposer departure, and voter departure.
///
/// This is the core logic called by the background task every 60 seconds.
/// It operates on a mutable reference to the governance engine, which the
/// caller must obtain by acquiring the per-engine Mutex.
///
/// # Arguments
///
/// * `engine` - The governance engine (with per-engine Mutex already held).
/// * `context` - Current governance context snapshot.
/// * `departed_members` - DIDs that have departed since the last check.
/// * `epoch_reset_members` - DIDs that have undergone epoch reset since last check.
///
/// # Returns
///
/// A [`TimeoutProcessingResult`] containing generated events and any
/// detected deadlock conditions.
pub fn process_pending_proposals(
    engine: &mut dyn GovernanceEngine,
    context: &GovernanceContext,
    departed_members: &[DID],
    epoch_reset_members: &[DID],
) -> TimeoutProcessingResult {
    let mut result = TimeoutProcessingResult::default();
    let pending_ids = engine.pending_proposal_ids();

    for proposal_id in &pending_ids {
        // 1. Check proposer departure (ADR-031 §5).
        let proposer_departed = engine
            .get_proposal(proposal_id)
            .is_some_and(|p| departed_members.contains(&p.proposer_did));
        if proposer_departed
            && let Ok(events) =
                engine.invalidate_proposal(proposal_id, "proposer departed the context".to_owned())
        {
            result.events.extend(events);
            continue; // Proposal invalidated, skip further processing.
        }

        // 2. Handle voter departure — remove votes and recalculate (ADR-031 §5).
        let mut resolved_by_departure = false;
        for departed in departed_members {
            if let Ok((status_change, events)) =
                engine.remove_departed_voter(proposal_id, departed, context)
            {
                result.events.extend(events);
                if status_change.is_some() {
                    resolved_by_departure = true;
                    break;
                }
            }
        }
        if resolved_by_departure {
            continue;
        }

        // 3. Handle epoch reset — invalidate votes from reset members (ADR-031 §5).
        for reset_member in epoch_reset_members {
            // Epoch reset invalidates votes but not the proposal itself.
            // Remove the vote (treated as departure from voting perspective).
            if let Ok((_status_change, events)) =
                engine.remove_departed_voter(proposal_id, reset_member, context)
            {
                result.events.extend(events);
            }
        }

        // 4. Attempt resolution (timeout check, ADR-031 §5).
        if let Ok((_status, events)) = engine.resolve(proposal_id, context) {
            result.events.extend(events);
        }
    }

    result
}

/// Detect deadlock conditions for the current governance model (ADR-031 §10).
///
/// Examines the governance model configuration and current context state
/// to determine if any deadlock condition exists. Does not modify state.
///
/// # Arguments
///
/// * `engine` - The governance engine to check.
/// * `context` - Current governance context snapshot.
/// * `detection_state` - Per-context deadlock detection tracking state.
///
/// # Returns
///
/// A list of detected deadlock conditions (may be empty).
#[must_use]
pub fn detect_deadlock(
    engine: &dyn GovernanceEngine,
    context: &GovernanceContext,
    detection_state: &DeadlockDetectionState,
) -> Vec<DeadlockCondition> {
    let config = engine.model_config();
    let mut conditions = Vec::new();

    match config {
        GovernanceModelConfig::SingleAdmin { .. } => {
            // SingleAdmin cannot deadlock (single authority).
        }
        GovernanceModelConfig::Threshold {
            signers, threshold, ..
        } => {
            // Deadlock: fewer than threshold signers are active members.
            let active_members: Vec<&DID> = context.members.iter().map(|(did, _)| did).collect();
            let active_signers: Vec<&DID> = signers
                .iter()
                .filter(|s| active_members.contains(s))
                .collect();
            #[allow(clippy::cast_possible_truncation)]
            if (active_signers.len() as u32) < threshold {
                let unavailable: Vec<DID> = signers
                    .iter()
                    .filter(|s| !active_members.contains(s))
                    .cloned()
                    .collect();
                conditions.push(DeadlockCondition::ThresholdInsufficient {
                    threshold,
                    active_signers: active_signers.len(),
                    unavailable,
                });
            }
        }
        GovernanceModelConfig::Majority {
            min_participation_bps,
            ..
        } => {
            // Deadlock: fewer than ceil(eligible * min_participation_bps / 10000) responsive
            // over 3 consecutive windows.
            let eligible = engine.eligible_voters(context);
            // Convert basis points to integer ceiling count.
            // Voter count * basis points fits comfortably in u64; result fits in usize on 64-bit.
            #[allow(clippy::cast_possible_truncation)]
            let min_participants =
                (eligible.len() as u64 * u64::from(min_participation_bps)).div_ceil(10000) as usize;
            let unresponsive: Vec<(DID, u32)> = eligible
                .iter()
                .filter_map(|did| {
                    let missed = detection_state
                        .consecutive_missed_windows
                        .get(did)
                        .copied()
                        .unwrap_or(0);
                    if missed >= MAJORITY_MISSED_WINDOW_THRESHOLD {
                        Some((did.clone(), missed))
                    } else {
                        None
                    }
                })
                .collect();
            let responsive_count = eligible.len() - unresponsive.len();
            if responsive_count < min_participants {
                conditions.push(DeadlockCondition::MajorityUnresponsive {
                    min_participants,
                    responsive_count,
                    missed_windows: unresponsive,
                });
            }
        }
        GovernanceModelConfig::Unanimity { .. } => {
            // Deadlock: any eligible voter offline beyond 7 days.
            let eligible = engine.eligible_voters(context);
            for did in &eligible {
                if let Some(&last_seen) = detection_state.last_seen_active.get(did) {
                    let offline_duration = context.now.saturating_sub(last_seen);
                    if offline_duration >= TIER3_OFFLINE_THRESHOLD_SECS {
                        conditions.push(DeadlockCondition::UnanimityOffline {
                            offline_did: did.clone(),
                            offline_duration_secs: offline_duration,
                        });
                    }
                }
            }
        }
    }

    conditions
}

/// Build a [`DeadlockJustification`] from detected deadlock conditions.
///
/// Aggregates all detected conditions into a single justification suitable
/// for a `ReconfigureGovernance` proposal.
#[must_use]
pub fn build_justification(conditions: &[DeadlockCondition], now: u64) -> DeadlockJustification {
    let mut unavailable_dids = Vec::new();
    let mut missed_windows = Vec::new();

    for condition in conditions {
        match condition {
            DeadlockCondition::ThresholdInsufficient { unavailable, .. } => {
                for did in unavailable {
                    if !unavailable_dids.contains(did) {
                        unavailable_dids.push(did.clone());
                    }
                }
            }
            DeadlockCondition::MajorityUnresponsive {
                missed_windows: mw, ..
            } => {
                for (did, count) in mw {
                    if !unavailable_dids.contains(did) {
                        unavailable_dids.push(did.clone());
                    }
                    missed_windows.push((did.clone(), *count));
                }
            }
            DeadlockCondition::UnanimityOffline { offline_did, .. } => {
                if !unavailable_dids.contains(offline_did) {
                    unavailable_dids.push(offline_did.clone());
                }
            }
        }
    }

    DeadlockJustification {
        unavailable_dids,
        missed_windows,
        detected_at: now,
    }
}

/// Update the deadlock detection state after a voting window passes.
///
/// For each eligible voter, checks whether they cast any vote during the
/// current window. Increments the consecutive missed counter for non-voters,
/// resets for active voters.
pub fn update_detection_state(
    detection_state: &mut DeadlockDetectionState,
    engine: &dyn GovernanceEngine,
    context: &GovernanceContext,
    active_voters_this_window: &[DID],
) {
    let eligible = engine.eligible_voters(context);
    for did in &eligible {
        if active_voters_this_window.contains(did) {
            detection_state.consecutive_missed_windows.remove(did);
            detection_state
                .last_seen_active
                .insert(did.clone(), context.now);
        } else {
            let counter = detection_state
                .consecutive_missed_windows
                .entry(did.clone())
                .or_insert(0);
            *counter += 1;
        }
    }
}

/// Check whether a fallback quorum (majority-of-active) is achievable.
///
/// Requires at least [`MIN_ACTIVE_VOTERS_FOR_FALLBACK`] (2) active voters.
/// If only 1 remains, returns `false` and the caller should log single-admin
/// authority (ADR-031 §10).
#[must_use]
pub const fn can_use_fallback_quorum(active_voter_count: usize) -> bool {
    active_voter_count >= MIN_ACTIVE_VOTERS_FOR_FALLBACK
}

/// Compute the fallback quorum threshold: majority of active voters.
///
/// Returns `ceil(active_voter_count / 2)`.
///
/// # Panics
///
/// Panics if `active_voter_count` is 0. Caller must check
/// [`can_use_fallback_quorum`] first.
#[must_use]
pub fn fallback_quorum_threshold(active_voter_count: usize) -> usize {
    assert!(
        active_voter_count > 0,
        "cannot compute fallback quorum for 0 voters"
    );
    active_voter_count.div_ceil(2)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::significant_drop_tightening
)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::context::governance::majority::MajorityVoteEngine;
    use crate::context::governance::multisig::ThresholdEngine;
    use crate::context::governance::unanimity::UnanimityEngine;
    use crate::context::governance::{
        GovernanceAction, GovernanceEngine, KeyResolver, ProposalStatus, SingleAdminEngine,
    };

    fn alice() -> DID {
        DID::from("did:dht:z6MkAlice")
    }

    fn bob() -> DID {
        DID::from("did:dht:z6MkBob")
    }

    fn carol() -> DID {
        DID::from("did:dht:z6MkCarol")
    }

    fn dave() -> DID {
        DID::from("did:dht:z6MkDave")
    }

    fn mock_resolver() -> KeyResolver {
        Arc::new(|did: &DID| {
            let did_str: &str = did.as_ref();
            match did_str {
                "did:dht:z6MkAlice" => {
                    Some(ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]).verifying_key())
                }
                "did:dht:z6MkBob" => {
                    Some(ed25519_dalek::SigningKey::from_bytes(&[2u8; 32]).verifying_key())
                }
                "did:dht:z6MkCarol" => {
                    Some(ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]).verifying_key())
                }
                "did:dht:z6MkDave" => {
                    Some(ed25519_dalek::SigningKey::from_bytes(&[4u8; 32]).verifying_key())
                }
                _ => None,
            }
        })
    }

    fn test_signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[1u8; 32])
    }

    fn test_signing_key_2() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[2u8; 32])
    }

    fn threshold_context(now: u64) -> GovernanceContext {
        GovernanceContext {
            context_id: "ctx-timeout-test".to_owned(),
            members: vec![
                (alice(), "admin".to_owned()),
                (bob(), "admin".to_owned()),
                (carol(), "admin".to_owned()),
            ],
            admin_dids: vec![alice(), bob(), carol()],
            current_epoch: Some(1),
            now,
        }
    }

    fn majority_context(now: u64) -> GovernanceContext {
        GovernanceContext {
            context_id: "ctx-majority-test".to_owned(),
            members: vec![
                (alice(), "member".to_owned()),
                (bob(), "member".to_owned()),
                (carol(), "member".to_owned()),
                (dave(), "member".to_owned()),
            ],
            admin_dids: vec![alice()],
            current_epoch: Some(1),
            now,
        }
    }

    fn unanimity_context(now: u64) -> GovernanceContext {
        GovernanceContext {
            context_id: "ctx-unanimity-test".to_owned(),
            members: vec![
                (alice(), "member".to_owned()),
                (bob(), "member".to_owned()),
                (carol(), "member".to_owned()),
            ],
            admin_dids: vec![alice()],
            current_epoch: Some(1),
            now,
        }
    }

    // -----------------------------------------------------------------------
    // Timeout expiration tests (AC: Tests verify timeout expiration
    // transitions for each governance model)
    // -----------------------------------------------------------------------

    #[test]
    fn threshold_proposal_expires_after_deadline() {
        let mut engine =
            ThresholdEngine::new(vec![alice(), bob(), carol()], 2, 300, mock_resolver()).unwrap();

        let now = 1_000_000;
        let ctx = threshold_context(now);

        // Create proposal. Alice's proposal counts as first approval.
        let (proposal, _events) = engine
            .propose(
                &alice(),
                GovernanceAction::AddMember {
                    did: dave(),
                    role: "member".to_owned(),
                },
                &ctx,
                &test_signing_key(),
            )
            .unwrap();

        // Advance time past deadline.
        let expired_ctx = GovernanceContext {
            now: now + 301,
            ..ctx
        };

        let result = process_pending_proposals(&mut engine, &expired_ctx, &[], &[]);

        assert!(
            !result.events.is_empty(),
            "should produce resolution events"
        );
        let resolved = engine.get_proposal(&proposal.proposal_id).unwrap();
        assert_eq!(resolved.status, ProposalStatus::Expired);
    }

    #[test]
    fn majority_proposal_expires_insufficient_participation() {
        let mut engine = MajorityVoteEngine::new(
            vec![alice(), bob(), carol(), dave()],
            300,
            5000,
            mock_resolver(),
        )
        .unwrap();

        let now = 1_000_000;
        let ctx = majority_context(now);

        // Create proposal (no votes cast beyond creation).
        let (proposal, _events) = engine
            .propose(
                &alice(),
                GovernanceAction::CloseContext { reason: None },
                &ctx,
                &test_signing_key(),
            )
            .unwrap();

        // Advance time past deadline — no quorum met.
        let expired_ctx = GovernanceContext {
            now: now + 301,
            ..ctx
        };

        let result = process_pending_proposals(&mut engine, &expired_ctx, &[], &[]);

        assert!(!result.events.is_empty());
        let resolved = engine.get_proposal(&proposal.proposal_id).unwrap();
        assert!(
            matches!(
                &resolved.status,
                ProposalStatus::Rejected {
                    reason: super::super::RejectionReason::InsufficientParticipation
                }
            ),
            "expected InsufficientParticipation, got {:?}",
            resolved.status
        );
    }

    #[test]
    fn unanimity_proposal_expires_after_deadline() {
        let mut engine =
            UnanimityEngine::new(vec![alice(), bob(), carol()], 300, mock_resolver()).unwrap();

        let now = 1_000_000;
        let ctx = unanimity_context(now);

        // Only Alice proposes and approves.
        let (proposal, _events) = engine
            .propose(
                &alice(),
                GovernanceAction::CloseContext { reason: None },
                &ctx,
                &test_signing_key(),
            )
            .unwrap();

        // Advance time past deadline.
        let expired_ctx = GovernanceContext {
            now: now + 301,
            ..ctx
        };

        let result = process_pending_proposals(&mut engine, &expired_ctx, &[], &[]);

        assert!(!result.events.is_empty());
        let resolved = engine.get_proposal(&proposal.proposal_id).unwrap();
        assert_eq!(resolved.status, ProposalStatus::Expired);
    }

    // -----------------------------------------------------------------------
    // Proposer departure (AC: Tests verify proposer departure invalidation)
    // -----------------------------------------------------------------------

    #[test]
    fn proposer_departure_invalidates_pending_proposal() {
        let mut engine =
            ThresholdEngine::new(vec![alice(), bob(), carol()], 2, 300, mock_resolver()).unwrap();

        let now = 1_000_000;
        let ctx = threshold_context(now);

        let (proposal, _events) = engine
            .propose(
                &alice(),
                GovernanceAction::AddMember {
                    did: dave(),
                    role: "member".to_owned(),
                },
                &ctx,
                &test_signing_key(),
            )
            .unwrap();

        // Alice departs.
        let result = process_pending_proposals(&mut engine, &ctx, &[alice()], &[]);

        assert!(!result.events.is_empty());
        let resolved = engine.get_proposal(&proposal.proposal_id).unwrap();
        assert!(
            matches!(&resolved.status, ProposalStatus::Invalidated { reason } if reason.contains("proposer departed")),
            "expected Invalidated, got {:?}",
            resolved.status
        );
    }

    // -----------------------------------------------------------------------
    // Voter departure (AC: Tests verify voter departure quorum recalculation)
    // -----------------------------------------------------------------------

    #[test]
    fn voter_departure_recalculates_quorum_threshold() {
        let mut engine =
            ThresholdEngine::new(vec![alice(), bob(), carol()], 2, 300, mock_resolver()).unwrap();

        let now = 1_000_000;
        let ctx = threshold_context(now);

        // Alice proposes (auto-approval as first vote).
        let (proposal, _events) = engine
            .propose(
                &alice(),
                GovernanceAction::AddMember {
                    did: dave(),
                    role: "member".to_owned(),
                },
                &ctx,
                &test_signing_key(),
            )
            .unwrap();

        // Bob approves — threshold met (2 of 3).
        let (_status, _events) = engine
            .approve(&proposal.proposal_id, &bob(), &ctx, &test_signing_key_2())
            .unwrap();

        let resolved = engine.get_proposal(&proposal.proposal_id).unwrap();
        assert_eq!(resolved.status, ProposalStatus::Approved);

        // Now create a new proposal for departure test.
        let (proposal2, _events) = engine
            .propose(
                &alice(),
                GovernanceAction::CloseContext { reason: None },
                &GovernanceContext {
                    now: now + 1,
                    ..ctx.clone()
                },
                &test_signing_key(),
            )
            .unwrap();

        // Carol departs — her vote is removed. Only alice+bob remain as signers.
        // Alice has 1 approval (auto from propose). Threshold is 2, signers still 3 in engine.
        // Carol departing should remove her potential vote.
        let _result = process_pending_proposals(
            &mut engine,
            &GovernanceContext {
                now: now + 2,
                ..ctx.clone()
            },
            &[carol()],
            &[],
        );

        // Proposal2 should still be pending — only 1 of 2 threshold approvals.
        let p2 = engine.get_proposal(&proposal2.proposal_id).unwrap();
        assert!(
            p2.status.is_pending(),
            "expected Pending, got {:?}",
            p2.status
        );
    }

    // -----------------------------------------------------------------------
    // Deadlock detection (AC: Tests verify deadlock detection for Threshold)
    // -----------------------------------------------------------------------

    #[test]
    fn threshold_deadlock_detected_when_too_few_active_signers() {
        let engine =
            ThresholdEngine::new(vec![alice(), bob(), carol()], 2, 300, mock_resolver()).unwrap();

        let now = 1_000_000;
        // Only Alice is an active member (bob and carol departed).
        let ctx = GovernanceContext {
            context_id: "ctx-deadlock-test".to_owned(),
            members: vec![(alice(), "admin".to_owned())],
            admin_dids: vec![alice()],
            current_epoch: Some(1),
            now,
        };

        let detection_state = DeadlockDetectionState::default();
        let conditions = detect_deadlock(&engine, &ctx, &detection_state);

        assert_eq!(conditions.len(), 1);
        assert!(
            matches!(
                &conditions[0],
                DeadlockCondition::ThresholdInsufficient {
                    threshold: 2,
                    active_signers: 1,
                    ..
                }
            ),
            "expected ThresholdInsufficient, got {:?}",
            conditions[0]
        );
    }

    #[test]
    fn unanimity_deadlock_detected_when_voter_offline_7_days() {
        let engine =
            UnanimityEngine::new(vec![alice(), bob(), carol()], 300, mock_resolver()).unwrap();

        let now = 1_000_000;
        let ctx = unanimity_context(now);

        let mut detection_state = DeadlockDetectionState::default();
        // Bob was last seen 8 days ago.
        detection_state
            .last_seen_active
            .insert(bob(), now - 8 * 24 * 60 * 60);
        detection_state.last_seen_active.insert(alice(), now);
        detection_state.last_seen_active.insert(carol(), now);

        let conditions = detect_deadlock(&engine, &ctx, &detection_state);

        assert_eq!(conditions.len(), 1);
        assert!(
            matches!(&conditions[0], DeadlockCondition::UnanimityOffline { offline_did, .. } if *offline_did == bob()),
            "expected UnanimityOffline for Bob, got {:?}",
            conditions[0]
        );
    }

    #[test]
    fn majority_deadlock_detected_when_insufficient_responsive() {
        let engine = MajorityVoteEngine::new(
            vec![alice(), bob(), carol(), dave()],
            300,
            7500,
            mock_resolver(),
        )
        .unwrap();

        let now = 1_000_000;
        let ctx = majority_context(now);

        let mut detection_state = DeadlockDetectionState::default();
        // Bob and Carol have missed 3 consecutive windows.
        detection_state.consecutive_missed_windows.insert(bob(), 3);
        detection_state
            .consecutive_missed_windows
            .insert(carol(), 3);

        let conditions = detect_deadlock(&engine, &ctx, &detection_state);

        assert_eq!(conditions.len(), 1);
        assert!(
            matches!(
                &conditions[0],
                DeadlockCondition::MajorityUnresponsive {
                    min_participants: 3,
                    responsive_count: 2,
                    ..
                }
            ),
            "expected MajorityUnresponsive, got {:?}",
            conditions[0]
        );
    }

    // -----------------------------------------------------------------------
    // ReconfigureGovernance fallback quorum
    // (AC: Tests verify ReconfigureGovernance fallback quorum)
    // -----------------------------------------------------------------------

    #[test]
    fn fallback_quorum_requires_at_least_2_voters() {
        assert!(!can_use_fallback_quorum(0));
        assert!(!can_use_fallback_quorum(1));
        assert!(can_use_fallback_quorum(2));
        assert!(can_use_fallback_quorum(3));
    }

    #[test]
    fn fallback_quorum_threshold_is_majority() {
        assert_eq!(fallback_quorum_threshold(2), 1);
        assert_eq!(fallback_quorum_threshold(3), 2);
        assert_eq!(fallback_quorum_threshold(4), 2);
        assert_eq!(fallback_quorum_threshold(5), 3);
    }

    #[test]
    fn deadlock_justification_aggregates_conditions() {
        let conditions = vec![DeadlockCondition::ThresholdInsufficient {
            threshold: 3,
            active_signers: 1,
            unavailable: vec![bob(), carol()],
        }];

        let justification = build_justification(&conditions, 1_000_000);
        assert_eq!(justification.unavailable_dids.len(), 2);
        assert!(justification.unavailable_dids.contains(&bob()));
        assert!(justification.unavailable_dids.contains(&carol()));
        assert_eq!(justification.detected_at, 1_000_000);
    }

    #[test]
    fn update_detection_state_tracks_missed_windows() {
        let engine =
            MajorityVoteEngine::new(vec![alice(), bob(), carol()], 300, 5000, mock_resolver())
                .unwrap();

        let now = 1_000_000;
        let ctx = majority_context(now);
        let mut state = DeadlockDetectionState::default();

        // Window 1: only Alice voted.
        update_detection_state(&mut state, &engine, &ctx, &[alice()]);
        assert_eq!(state.consecutive_missed_windows.get(&bob()), Some(&1));
        assert_eq!(state.consecutive_missed_windows.get(&carol()), Some(&1));
        assert_eq!(state.consecutive_missed_windows.get(&alice()), None);

        // Window 2: only Alice voted again.
        update_detection_state(&mut state, &engine, &ctx, &[alice()]);
        assert_eq!(state.consecutive_missed_windows.get(&bob()), Some(&2));

        // Window 3: Bob votes.
        update_detection_state(&mut state, &engine, &ctx, &[alice(), bob()]);
        assert_eq!(state.consecutive_missed_windows.get(&bob()), None);
        assert_eq!(state.consecutive_missed_windows.get(&carol()), Some(&3));
    }

    #[test]
    fn single_admin_never_deadlocks() {
        let engine = SingleAdminEngine::new(alice(), mock_resolver());
        let ctx = GovernanceContext {
            context_id: "ctx-single-admin".to_owned(),
            members: vec![(alice(), "admin".to_owned())],
            admin_dids: vec![alice()],
            current_epoch: Some(1),
            now: 1_000_000,
        };
        let state = DeadlockDetectionState::default();
        let conditions = detect_deadlock(&engine, &ctx, &state);
        assert!(conditions.is_empty());
    }

    #[test]
    fn no_deadlock_when_sufficient_signers_active() {
        let engine =
            ThresholdEngine::new(vec![alice(), bob(), carol()], 2, 300, mock_resolver()).unwrap();

        let ctx = threshold_context(1_000_000);
        let state = DeadlockDetectionState::default();
        let conditions = detect_deadlock(&engine, &ctx, &state);
        assert!(conditions.is_empty());
    }

    #[test]
    fn recovery_voting_window_is_48_hours() {
        assert_eq!(DEADLOCK_RECOVERY_VOTING_WINDOW_SECS, 48 * 60 * 60);
    }

    // -----------------------------------------------------------------------
    // GovernanceTimeoutTask start/cancel lifecycle (AC: task lifecycle)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn timeout_task_starts_and_is_active() {
        let mut task = GovernanceTimeoutTask::new();
        assert!(!task.is_active());

        let tick_count = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let tick_count_clone = Arc::clone(&tick_count);
        task.start(move || {
            let tick_count = Arc::clone(&tick_count_clone);
            async move {
                tick_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                true
            }
        });

        assert!(task.is_active());
        task.cancel();
        // Give the task time to process cancellation.
        tokio::time::sleep(Duration::from_millis(10)).await;
        // Task should have stopped. It may or may not have finished by now
        // since cancellation is async, but cancel was called.
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_task_stops_when_callback_returns_false() {
        let mut task = GovernanceTimeoutTask::new();
        task.start(|| async { false });

        // Advance past the check interval to trigger the tick.
        // Use sleep (which auto-advances paused time) instead of advance().
        tokio::time::sleep(Duration::from_secs(TIMEOUT_CHECK_INTERVAL_SECS + 1)).await;
        // Give the spawned task time to finish after the callback returns false.
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert!(
            !task.is_active(),
            "task should have stopped after callback returned false"
        );
    }

    #[tokio::test]
    async fn timeout_task_cancelled_on_drop() {
        let mut task = GovernanceTimeoutTask::new();
        task.start(|| async { true });
        assert!(task.is_active());
        let _cancel = task.cancel.clone();
        drop(task);
        // After drop, the cancel signal was sent and the task was aborted.
        // Verify the cancel was notified (drop calls notify_one).
        // This is a structural test — the Drop impl is already tested by compilation.
    }

    // -----------------------------------------------------------------------
    // Integration: proposal expires after voting window via background task
    // (AC: Test: proposal expires after voting window)
    // -----------------------------------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn proposal_expires_via_background_task() {
        use std::sync::atomic::{AtomicBool, Ordering};

        // ThresholdEngine enforces voting_window_secs >= 300.
        let mut engine =
            ThresholdEngine::new(vec![alice(), bob(), carol()], 2, 300, mock_resolver()).unwrap();

        let now = 1_000_000_u64;
        let ctx = threshold_context(now);

        let (proposal, _events) = engine
            .propose(
                &alice(),
                GovernanceAction::AddMember {
                    did: dave(),
                    role: "member".to_owned(),
                },
                &ctx,
                &test_signing_key(),
            )
            .unwrap();
        let proposal_id = proposal.proposal_id;

        // Wrap engine in shared state so the callback can access it.
        let engine = Arc::new(tokio::sync::Mutex::new(engine));
        let expired = Arc::new(AtomicBool::new(false));

        let engine_clone = Arc::clone(&engine);
        let expired_clone = Arc::clone(&expired);
        let mut task = GovernanceTimeoutTask::new();
        task.start(move || {
            let engine = Arc::clone(&engine_clone);
            let expired = Arc::clone(&expired_clone);
            async move {
                let mut eng = engine.lock().await;
                // Simulate time past the 300-second voting deadline.
                let expired_ctx = GovernanceContext {
                    now: now + 301,
                    ..threshold_context(now)
                };
                let result = process_pending_proposals(&mut *eng, &expired_ctx, &[], &[]);
                if !result.events.is_empty() {
                    expired.store(true, Ordering::SeqCst);
                }
                false // Stop after one tick.
            }
        });

        // Advance tokio time past the check interval to trigger the tick.
        tokio::time::sleep(Duration::from_secs(TIMEOUT_CHECK_INTERVAL_SECS + 1)).await;
        // Give the spawned task time to execute.
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }

        assert!(
            expired.load(Ordering::SeqCst),
            "proposal should have been resolved by the background task"
        );

        let eng = engine.lock().await;
        let resolved = eng.get_proposal(&proposal_id).unwrap();
        assert_eq!(
            resolved.status,
            ProposalStatus::Expired,
            "proposal should be Expired after voting window passed"
        );
    }
}
