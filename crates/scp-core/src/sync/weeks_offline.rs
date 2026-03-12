//! Tier 3 weeks-scale offline recovery: forced re-join with state reset.
//!
//! This module implements the long offline scenario (> 7 days) from ADR-029
//! section 4. When a member has been offline for weeks, MLS group state may be
//! irrecoverable: relays have expired buffered messages, no peer can provide
//! the full Commit chain, and Welcome-based fast-forward has failed or is
//! unavailable. The only recovery path is a forced re-join — the offline
//! member leaves and immediately re-joins with fresh MLS state.
//!
//! **Group state reset is NOT a group-wide operation.** It affects only the
//! offline member's participation. The rest of the group continues operating
//! normally. See ADR-029 section 4.
//!
//! # Architecture
//!
//! - [`OfflineAssessment`] — Evaluates whether catch-up recovery is possible or
//!   forced re-join is required, based on epoch drift and offline duration.
//! - [`ReJoinPlan`] — Describes the steps for forced re-join (remove old member,
//!   add new member with fresh `KeyPackage`).
//! - [`StatePreservation`] — Records how context state (membership roster,
//!   governance config, event log) is preserved across re-join.
//! - [`InFlightMessageHandling`] — Determines what happens to messages sent
//!   during the transition (queue, discard, or re-request).
//! - [`BilateralContextRecovery`] — Special handling for standing bilateral
//!   (2-person) contexts that must survive weeks-offline.
//! - [`ReJoinExecutor`] — Async trait for the actual MLS operations (remove old
//!   leaf, add fresh `KeyPackage`, distribute Welcome).
//!
//! See ADR-029 in `.docs/adrs/phase-6.md`.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use super::{ContextId, Ed25519Signature, SyncError, SyncOutcome};
use crate::crypto::canonical::{CanonicalField, canonical_hash};
use scp_identity::DID;

/// Safely compare a `u64` against a `usize` without truncation.
///
/// Returns `true` if `value` exceeds `limit`, handling 32-bit targets where
/// `usize` is smaller than `u64`.
fn u64_exceeds_usize(value: u64, limit: usize) -> bool {
    // On 64-bit targets this is a simple comparison. On 32-bit targets,
    // usize::MAX < u64::MAX, so we compare in u64 space.
    u64::try_from(limit).is_ok_and(|limit_u64| value > limit_u64)
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum MLS epoch drift before forced re-join is required.
///
/// When the gap between the member's last known epoch and the group's current
/// epoch exceeds this threshold, catch-up recovery is considered infeasible.
/// This accounts for contexts with extremely high churn (frequent joins/leaves/
/// updates). Value is 10x the sequential catch-up limit (100 Commits) to
/// provide a generous margin before triggering reset.
///
/// See ADR-029 section 4.
pub const MAX_EPOCH_DRIFT: u64 = 1_000;

/// Maximum offline duration in seconds before forced re-join is required.
///
/// Equals [`super::TIER_2_THRESHOLD_SECS`] (7 days). Any offline duration
/// exceeding this triggers Tier 3 recovery. Defined separately for clarity
/// and to allow governance-configurable overrides.
///
/// For policy-aware code, use `SyncPolicy::tier_2_threshold_secs` instead.
///
/// See ADR-029 section 4 trigger condition 1.
pub const MAX_OFFLINE_DURATION_SECS: u64 = super::TIER_2_THRESHOLD_SECS;

/// Timeout for waiting for a Welcome message after publishing a
/// [`ResetRequest`], in seconds.
///
/// See ADR-029 section 4, acceptance criterion 4.
pub const RESET_WELCOME_TIMEOUT_SECS: u64 = 60;

/// Maximum number of in-flight messages that can be queued during a re-join
/// transition. Messages beyond this limit are discarded.
///
/// Prevents unbounded memory growth if the transition stalls.
pub const MAX_INFLIGHT_QUEUE_SIZE: usize = 500;

/// Domain separator for `ResetRequest` canonical hash (§23, ADR-029).
///
/// Used in `SHA-256(domain_separator || field_1 || ... || field_N)` to produce
/// the bytes that are signed and verified.
pub const RESET_REQUEST_DOMAIN_SEPARATOR: &str = "SCP-RESET-REQUEST-V1:";

/// Maximum age of a `ResetRequest` before it is rejected as stale (seconds).
///
/// A 30-second freshness window prevents replaying captured reset requests
/// after the original processing window. Matches the multi-device
/// reconnection dedup window (§23.8).
///
/// See §23.5.2, ADR-029 section 4.
pub const RESET_REQUEST_FRESHNESS_SECS: u64 = 30;

/// TTL for tracking seen `ResetRequest` nonces (seconds).
///
/// Nonces older than this are evicted from the in-memory tracker.
/// Set to 60 seconds — 2x the freshness window — to ensure that replays
/// within the freshness window are always caught even with minor clock skew.
///
/// See §23.5.2, ADR-029 section 4.
pub const RESET_REQUEST_NONCE_TTL_SECS: u64 = 60;

/// Maximum number of entries in the `ResetRequestNonceTracker` cache.
///
/// When exceeded, the oldest entry (by timestamp) is evicted first.
///
/// See §23.5.2: "Cache capacity: bounded at 10,000 entries with oldest-first
/// eviction."
pub const MAX_NONCE_CACHE_ENTRIES: usize = 10_000;

// ---------------------------------------------------------------------------
// ResetReason
// ---------------------------------------------------------------------------

/// Why a group state reset was triggered.
///
/// Recorded in the event log's `MemberReset` event for auditability.
/// See ADR-029 section 4.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResetReason {
    /// Offline duration exceeded the 7-day threshold.
    ExtendedOffline {
        /// How long the member was offline, in seconds.
        offline_duration_secs: u64,
    },
    /// Epoch catch-up failed after exhausting all recovery sources.
    CatchUpFailed {
        /// Recovery sources that were attempted before giving up.
        attempted_sources: Vec<String>,
    },
    /// Governance-initiated reset (future: ADR-031 governance action).
    GovernanceAction {
        /// The governance proposal ID that triggered the reset.
        proposal_id: String,
    },
}

impl std::fmt::Display for ResetReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExtendedOffline {
                offline_duration_secs,
            } => {
                let days = offline_duration_secs / 86_400;
                write!(f, "extended offline ({days} days)")
            }
            Self::CatchUpFailed { attempted_sources } => {
                write!(
                    f,
                    "catch-up failed (tried: {})",
                    attempted_sources.join(", ")
                )
            }
            Self::GovernanceAction { proposal_id } => {
                write!(f, "governance action (proposal: {proposal_id})")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ResetRequest
// ---------------------------------------------------------------------------

/// A request to reset a member's group state.
///
/// Published to the relay as a plaintext (not MLS-encrypted) message, since
/// the member may not be able to encrypt at the current epoch. Signed by the
/// member's Active Signing Key for authentication.
///
/// The `nonce` field provides anti-replay protection: each request carries a
/// cryptographically random 16-byte nonce that is included in the canonical
/// hash (at position 5) and checked for uniqueness by the processing admin.
///
/// See §23.5.2, ADR-029 section 4, step 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResetRequest {
    /// The context in which the member needs to be reset.
    pub context_id: ContextId,
    /// The DID of the member requesting reset.
    pub member_did: DID,
    /// The member's last known MLS epoch before going offline.
    pub last_known_epoch: u64,
    /// Why the reset is being requested.
    pub reason: ResetReason,
    /// Cryptographically random 16-byte nonce for anti-replay protection.
    ///
    /// Included in the canonical hash at position 5. The processing admin
    /// tracks seen nonces with a 60-second TTL to reject replays.
    ///
    /// See §23.5.2, ADR-029 section 4.
    pub nonce: [u8; 16],
    /// Unix timestamp (seconds) when the request was created.
    pub timestamp: u64,
    /// Ed25519 signature over the canonical hash of all fields (except
    /// signature itself). Domain separator: `"SCP-RESET-REQUEST-V1:"`.
    #[serde(with = "serde_bytes")]
    pub signature: Ed25519Signature,
}

impl ResetRequest {
    /// Creates a new `ResetRequest` with a cryptographically random nonce.
    ///
    /// The nonce is generated from `OsRng` (CSPRNG). The `signature` field is
    /// left empty — the caller must sign `self.canonical_hash()` and set
    /// `self.signature` before transmitting.
    #[must_use]
    pub fn new(
        context_id: ContextId,
        member_did: DID,
        last_known_epoch: u64,
        reason: ResetReason,
        timestamp: u64,
    ) -> Self {
        use rand::RngCore;
        let mut nonce = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        Self {
            context_id,
            member_did,
            last_known_epoch,
            reason,
            nonce,
            timestamp,
            signature: Vec::new(),
        }
    }

    /// Computes the canonical hash for this `ResetRequest`.
    ///
    /// The hash covers all fields except `signature` using the domain separator
    /// `"SCP-RESET-REQUEST-V1:"`. Field order per §23.5.2:
    ///
    /// 1. `context_id` (`VarBytes`)
    /// 2. `member_did` (`VarBytes`)
    /// 3. `last_known_epoch` (`U64`)
    /// 4. `reason` (`VarBytes` — Display string)
    /// 5. `nonce` (`RawBytes` — 16 bytes, no length prefix)
    /// 6. `timestamp` (`U64`)
    ///
    /// The result is the message to be signed/verified.
    #[must_use]
    pub fn canonical_hash(&self) -> [u8; 32] {
        let reason_str = self.reason.to_string();
        canonical_hash(
            RESET_REQUEST_DOMAIN_SEPARATOR,
            &[
                CanonicalField::VarBytes(self.context_id.as_bytes()),
                CanonicalField::VarBytes(self.member_did.as_bytes()),
                CanonicalField::U64(self.last_known_epoch),
                CanonicalField::VarBytes(reason_str.as_bytes()),
                CanonicalField::RawBytes(&self.nonce),
                CanonicalField::U64(self.timestamp),
            ],
        )
    }
}

// ---------------------------------------------------------------------------
// ResetRequestNonceTracker
// ---------------------------------------------------------------------------

/// In-memory nonce deduplication tracker for `ResetRequest` anti-replay.
///
/// Tracks seen `(member_did, nonce)` pairs with a configurable TTL. When a
/// nonce is checked, expired entries are lazily evicted. Thread-safe via
/// internal `Mutex`.
///
/// The cache is bounded at [`MAX_NONCE_CACHE_ENTRIES`] entries with
/// oldest-first eviction to prevent unbounded memory growth.
///
/// This is the primary, synchronous anti-replay defense. The persistent
/// `ProtocolStore` nonce tracking is a defence-in-depth layer for crash
/// recovery (same pattern as UCAN `NonceTracker` in `crypto/ucan/nonce.rs`).
///
/// See §23.5.2, ADR-029 section 4.
#[derive(Debug)]
pub struct ResetRequestNonceTracker {
    /// Map of `(member_did, nonce)` to the timestamp when first seen.
    seen: Mutex<HashMap<(String, [u8; 16]), u64>>,
    /// TTL for nonce entries in seconds.
    ttl_secs: u64,
}

impl ResetRequestNonceTracker {
    /// Creates a new nonce tracker with the given TTL.
    #[must_use]
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            seen: Mutex::new(HashMap::new()),
            ttl_secs,
        }
    }

    /// Creates a new nonce tracker with the default TTL
    /// ([`RESET_REQUEST_NONCE_TTL_SECS`]).
    #[must_use]
    pub fn with_default_ttl() -> Self {
        Self::new(RESET_REQUEST_NONCE_TTL_SECS)
    }

    /// Atomically checks and tentatively records a `(member_did, nonce)` pair.
    ///
    /// Returns `Some(NonceGuard)` if the pair is new (not a replay) — the
    /// nonce is recorded in the same lock acquisition, eliminating the TOCTOU
    /// window that exists with separate check-then-record calls.
    ///
    /// Returns `None` if the pair has been seen within the TTL window (replay).
    ///
    /// The returned [`NonceGuard`] **must** be committed via
    /// [`NonceGuard::commit`] after signature verification succeeds. If the
    /// guard is dropped without being committed (e.g., signature verification
    /// fails, or a panic occurs), the nonce is automatically rolled back so
    /// the legitimate request can still succeed.
    ///
    /// Lazily evicts expired entries on each call. After insertion, if the
    /// cache exceeds [`MAX_NONCE_CACHE_ENTRIES`], the oldest entry (by
    /// timestamp) is evicted.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned (another thread panicked
    /// while holding the lock). This is unrecoverable.
    #[must_use = "ignoring nonce check result is a security bug"]
    pub fn check_and_tentatively_record(
        &self,
        member_did: &str,
        nonce: &[u8; 16],
        now: u64,
    ) -> Option<NonceGuard<'_>> {
        #[allow(clippy::expect_used)]
        let mut seen = self.seen.lock().expect("nonce tracker lock poisoned");

        // Lazy eviction of expired entries.
        seen.retain(|_, first_seen| now.saturating_sub(*first_seen) < self.ttl_secs);

        let key = (member_did.to_owned(), *nonce);

        // Check for replay.
        if seen.contains_key(&key) {
            return None;
        }

        // Record the entry.
        seen.insert(key, now);

        // Capacity bound: evict oldest entry if over limit.
        if seen.len() > MAX_NONCE_CACHE_ENTRIES
            && let Some(oldest_key) = seen
                .iter()
                .min_by_key(|(_, ts)| **ts)
                .map(|(k, _)| k.clone())
        {
            seen.remove(&oldest_key);
        }

        drop(seen);

        Some(NonceGuard {
            tracker: self,
            member_did: member_did.to_owned(),
            nonce: *nonce,
            committed: false,
        })
    }

    /// Rolls back a tentatively recorded `(member_did, nonce)` pair.
    ///
    /// Called automatically by [`NonceGuard::drop`] when the guard is not
    /// committed. Not part of the public API — use `NonceGuard::commit` and
    /// drop semantics instead.
    ///
    /// No-op if the entry does not exist (e.g., already expired or evicted).
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    fn rollback_nonce(&self, member_did: &str, nonce: &[u8; 16]) {
        #[allow(clippy::expect_used)]
        let mut seen = self.seen.lock().expect("nonce tracker lock poisoned");

        let key = (member_did.to_owned(), *nonce);
        seen.remove(&key);
    }
}

/// RAII guard for a tentatively recorded nonce.
///
/// Returned by [`ResetRequestNonceTracker::check_and_tentatively_record`].
/// The nonce is automatically rolled back when the guard is dropped unless
/// [`commit`](NonceGuard::commit) has been called. This makes the
/// tentative-record + rollback pattern fail-safe: panics, early returns,
/// and logic errors all trigger automatic rollback.
///
/// # Usage
///
/// ```ignore
/// let guard = tracker.check_and_tentatively_record(did, &nonce, now)
///     .ok_or(WeeksOfflineError::ReplayedResetRequest { .. })?;
/// // ... verify signature ...
/// guard.commit(); // nonce stays recorded on success
/// // if we never reach commit(), drop rolls back the nonce
/// ```
#[derive(Debug)]
pub struct NonceGuard<'a> {
    tracker: &'a ResetRequestNonceTracker,
    member_did: String,
    nonce: [u8; 16],
    committed: bool,
}

impl NonceGuard<'_> {
    /// Commits the tentatively recorded nonce, preventing rollback on drop.
    ///
    /// Call this after signature verification succeeds. Once committed, the
    /// nonce remains in the tracker for the duration of its TTL, blocking
    /// replay attempts.
    pub fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for NonceGuard<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.tracker.rollback_nonce(&self.member_did, &self.nonce);
        }
    }
}

impl Default for ResetRequestNonceTracker {
    fn default() -> Self {
        Self::with_default_ttl()
    }
}

// ---------------------------------------------------------------------------
// validate_reset_request
// ---------------------------------------------------------------------------

/// Validation result for a `ResetRequest`.
///
/// Returned by [`validate_reset_request`] when anti-replay checks pass.
/// Contains both the canonical hash for signature verification and a
/// [`NonceGuard`] that must be committed after signature verification
/// succeeds. If the guard is dropped without being committed, the nonce
/// is automatically rolled back.
#[derive(Debug)]
pub struct ValidatedResetRequest<'a> {
    /// The canonical hash that was validated. Verify the Ed25519 signature
    /// over this hash using the member's DID verification method
    /// (`#active` or `#agent`).
    pub canonical_hash: [u8; 32],
    /// RAII guard for the tentatively recorded nonce. Call
    /// [`NonceGuard::commit`] after signature verification succeeds.
    /// Automatically rolls back on drop if not committed.
    pub nonce_guard: NonceGuard<'a>,
}

/// Validates a `ResetRequest` for anti-replay (freshness + nonce dedup).
///
/// This function performs two checks:
///
/// 1. **Freshness:** Rejects requests where `|now - request.timestamp|` exceeds
///    [`RESET_REQUEST_FRESHNESS_SECS`] (30 seconds). Both past and future
///    timestamps are checked.
/// 2. **Nonce dedup:** Atomically checks and tentatively records the nonce via
///    [`ResetRequestNonceTracker::check_and_tentatively_record`]. This
///    eliminates the TOCTOU race condition that existed with the previous
///    separate check-then-record pattern.
///
/// On success, returns a [`ValidatedResetRequest`] containing both the
/// canonical hash and a [`NonceGuard`]. The caller must:
/// 1. Verify the Ed25519 signature over `canonical_hash` using the member's
///    DID verification method (`#active` or `#agent`).
/// 2. Call [`NonceGuard::commit`] on `nonce_guard` if signature verification
///    succeeds.
///
/// If signature verification fails (or any other error occurs), simply drop
/// the `ValidatedResetRequest` — the `NonceGuard` will automatically roll
/// back the nonce so the legitimate request can still succeed.
///
/// # Errors
///
/// Returns [`WeeksOfflineError::StaleResetRequest`] if the request is too old.
/// Returns [`WeeksOfflineError::ReplayedResetRequest`] if the nonce was seen.
pub fn validate_reset_request<'a>(
    request: &ResetRequest,
    now: u64,
    nonce_tracker: &'a ResetRequestNonceTracker,
) -> Result<ValidatedResetRequest<'a>, WeeksOfflineError> {
    // Check 1: freshness — absolute difference (§23.5.2 requires
    // |relay_clock - timestamp| <= 30s, rejecting both past and future).
    let diff = now.abs_diff(request.timestamp);
    if diff > RESET_REQUEST_FRESHNESS_SECS {
        return Err(WeeksOfflineError::StaleResetRequest {
            context_id: request.context_id.clone(),
            age_secs: diff,
            max_age_secs: RESET_REQUEST_FRESHNESS_SECS,
        });
    }

    // Check 2: nonce dedup — atomic check + tentative record.
    // The nonce is recorded in the same lock acquisition as the check,
    // eliminating the TOCTOU window. The returned NonceGuard auto-rolls-back
    // on drop if not committed.
    let nonce_guard = nonce_tracker
        .check_and_tentatively_record(request.member_did.as_ref(), &request.nonce, now)
        .ok_or_else(|| WeeksOfflineError::ReplayedResetRequest {
            context_id: request.context_id.clone(),
            nonce: request.nonce,
        })?;

    Ok(ValidatedResetRequest {
        canonical_hash: request.canonical_hash(),
        nonce_guard,
    })
}

// ---------------------------------------------------------------------------
// OfflineAssessment
// ---------------------------------------------------------------------------

/// Assessment of whether catch-up recovery is possible or forced re-join is
/// required.
///
/// Produced by [`assess_offline_state`]. The assessment considers both time
/// offline and MLS epoch drift.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OfflineAssessment {
    /// Catch-up recovery is feasible. The member should use Tier 1 or Tier 2
    /// mechanisms (relay backfill, delta sync, Welcome fast-forward).
    CatchUpFeasible {
        /// Offline duration in seconds.
        offline_duration_secs: u64,
        /// MLS epoch gap (0 if unknown or Broadcast context).
        epoch_gap: u64,
    },
    /// Forced re-join is required. Catch-up recovery is not feasible due to
    /// one or more trigger conditions being met.
    ForceReJoinRequired {
        /// Why re-join is required (the trigger conditions that fired).
        triggers: Vec<ResetTrigger>,
    },
}

/// A specific trigger condition that caused forced re-join to be required.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResetTrigger {
    /// Offline duration exceeded [`MAX_OFFLINE_DURATION_SECS`].
    OfflineDurationExceeded {
        /// Actual offline duration in seconds.
        duration_secs: u64,
        /// Configured threshold in seconds.
        threshold_secs: u64,
    },
    /// MLS epoch drift exceeded [`MAX_EPOCH_DRIFT`].
    EpochDriftExceeded {
        /// Local (stale) epoch.
        local_epoch: u64,
        /// Current group epoch.
        current_epoch: u64,
        /// Configured drift threshold.
        threshold: u64,
    },
    /// All catch-up recovery sources have been exhausted.
    CatchUpExhausted {
        /// Sources that were attempted.
        attempted_sources: Vec<String>,
    },
}

/// Assesses whether a member needs forced re-join based on offline duration
/// and MLS epoch drift.
///
/// Returns [`OfflineAssessment::ForceReJoinRequired`] if any trigger condition
/// is met. Returns [`OfflineAssessment::CatchUpFeasible`] otherwise.
///
/// # Arguments
///
/// * `last_relay_contact` - Unix timestamp of the member's last successful
///   relay interaction.
/// * `now` - Current Unix timestamp.
/// * `local_epoch` - The member's last known MLS epoch. `None` for Broadcast
///   contexts (no MLS).
/// * `current_epoch` - The group's current MLS epoch. `None` for Broadcast
///   contexts.
///
/// See ADR-029 section 4 trigger conditions.
#[must_use]
pub fn assess_offline_state(
    last_relay_contact: u64,
    now: u64,
    local_epoch: Option<u64>,
    current_epoch: Option<u64>,
) -> OfflineAssessment {
    let offline_duration_secs = now.saturating_sub(last_relay_contact);
    let epoch_gap = match (local_epoch, current_epoch) {
        (Some(local), Some(current)) => current.saturating_sub(local),
        _ => 0,
    };

    let mut triggers = Vec::new();

    // Trigger 1: offline duration exceeds threshold
    if offline_duration_secs > MAX_OFFLINE_DURATION_SECS {
        triggers.push(ResetTrigger::OfflineDurationExceeded {
            duration_secs: offline_duration_secs,
            threshold_secs: MAX_OFFLINE_DURATION_SECS,
        });
    }

    // Trigger 2: epoch drift exceeds threshold
    if epoch_gap > MAX_EPOCH_DRIFT
        && let (Some(local), Some(current)) = (local_epoch, current_epoch)
    {
        triggers.push(ResetTrigger::EpochDriftExceeded {
            local_epoch: local,
            current_epoch: current,
            threshold: MAX_EPOCH_DRIFT,
        });
    }

    if triggers.is_empty() {
        OfflineAssessment::CatchUpFeasible {
            offline_duration_secs,
            epoch_gap,
        }
    } else {
        OfflineAssessment::ForceReJoinRequired { triggers }
    }
}

// ---------------------------------------------------------------------------
// ReJoinPlan
// ---------------------------------------------------------------------------

/// A plan describing the steps for a forced re-join.
///
/// Generated after [`OfflineAssessment::ForceReJoinRequired`] is determined.
/// The plan captures the member's current state, the reason for re-join, and
/// what state should be preserved across the transition.
///
/// See ADR-029 section 4 reset protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReJoinPlan {
    /// The context in which the re-join occurs.
    pub context_id: ContextId,
    /// The DID of the member being re-joined.
    pub member_did: DID,
    /// The member's last known MLS epoch.
    pub last_known_epoch: u64,
    /// Why the re-join is needed.
    pub reason: ResetReason,
    /// State preservation details.
    pub state_preservation: StatePreservation,
    /// How in-flight messages should be handled.
    pub inflight_handling: InFlightMessageHandling,
}

// ---------------------------------------------------------------------------
// StatePreservation
// ---------------------------------------------------------------------------

/// Records what context state is preserved across a forced re-join.
///
/// Per ADR-029 section 4, the reset member retains:
/// - Their DID and identity
/// - Their role in the context (re-assigned by admin during re-add)
/// - Their event log history up to the last known epoch
/// - Context metadata (params, tools, ceiling)
///
/// The reset member loses:
/// - Access to messages encrypted in skipped epochs (forward secrecy)
/// - Pending governance proposals initiated while offline
/// - Queue entries that reference the old epoch
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatePreservation {
    /// The member's role to be re-assigned after re-join.
    pub role_to_restore: String,
    /// Number of events in the member's local event log at reset time.
    pub local_event_count: u64,
    /// Merkle root of the member's local event log at reset time.
    pub local_merkle_root: [u8; 32],
    /// Context metadata (params hash) to verify continuity.
    pub params_hash: [u8; 32],
    /// Tool names active at reset time.
    pub active_tools: Vec<String>,
    /// Membership roster at reset time (DID -> role name).
    pub membership_roster: BTreeMap<String, String>,
    /// Number of governance proposals invalidated by the reset.
    pub invalidated_proposals: u64,
}

// ---------------------------------------------------------------------------
// InFlightMessageHandling
// ---------------------------------------------------------------------------

/// Strategy for handling messages during the re-join transition.
///
/// Messages may be in-flight (queued locally, or sent by other members during
/// the transition window). This enum determines what happens to each category.
///
/// See ADR-029 section 4, step 4.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InFlightMessageHandling {
    /// Queue messages locally until the re-join completes, then re-encrypt
    /// and send with the new epoch's key schedule.
    QueueAndResend {
        /// Number of messages currently queued.
        queued_count: u64,
        /// Maximum queue size before overflow.
        max_queue_size: usize,
    },
    /// Discard all in-flight messages. Used when the queue has overflowed
    /// or the messages are stale beyond the context's `blob_ttl`.
    Discard {
        /// Number of messages discarded.
        discarded_count: u64,
        /// Why messages were discarded.
        reason: String,
    },
    /// Re-request messages from peers after re-join completes.
    ReRequest {
        /// Number of messages to re-request.
        message_count: u64,
    },
}

// ---------------------------------------------------------------------------
// BilateralContextRecovery
// ---------------------------------------------------------------------------

/// Special recovery handling for standing bilateral (2-person) contexts.
///
/// Bilateral contexts are unique because when one member goes offline for
/// weeks, the other member is the sole remaining participant. The context
/// cannot function until the offline member returns. Recovery must preserve
/// the bilateral relationship and its history.
///
/// See ADR-029 section 4 and the standing bilateral context design.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BilateralContextRecovery {
    /// The context being recovered.
    pub context_id: ContextId,
    /// The DID of the member who went offline.
    pub offline_member_did: DID,
    /// The DID of the member who stayed online.
    pub online_member_did: DID,
    /// Whether the online member can initiate the reset autonomously
    /// (they have both `MemberRemove` and `MemberInvite` capabilities).
    pub online_member_can_reset: bool,
    /// The offline member's last known epoch.
    pub last_known_epoch: u64,
    /// Current epoch in the bilateral context.
    pub current_epoch: u64,
    /// Messages queued by the online member during the offline period.
    pub online_member_queued_messages: u64,
    /// Assessment outcome for this bilateral context.
    pub assessment: OfflineAssessment,
}

/// Input parameters for bilateral context recovery assessment.
///
/// Bundles the arguments for [`assess_bilateral_recovery`] to stay within
/// the 7-argument clippy limit.
pub struct BilateralRecoveryParams<'a> {
    /// The bilateral context ID.
    pub context_id: &'a str,
    /// DID of the member who went offline.
    pub offline_did: &'a DID,
    /// DID of the member who stayed online.
    pub online_did: &'a DID,
    /// Whether the online member has reset capabilities.
    pub online_can_reset: bool,
    /// Offline member's last relay interaction timestamp.
    pub last_relay_contact: u64,
    /// Current timestamp.
    pub now: u64,
    /// Offline member's last known epoch.
    pub local_epoch: u64,
    /// Current group epoch.
    pub current_epoch: u64,
}

/// Assesses recovery for a bilateral (2-person) context.
///
/// Bilateral contexts have simplified recovery because:
/// 1. Only one member needs to act as admin for the reset.
/// 2. There is no risk of conflicting concurrent resets.
/// 3. The context's existence depends on both members, so recovery is
///    always preferred over context closure.
#[must_use]
pub fn assess_bilateral_recovery(params: &BilateralRecoveryParams<'_>) -> BilateralContextRecovery {
    let assessment = assess_offline_state(
        params.last_relay_contact,
        params.now,
        Some(params.local_epoch),
        Some(params.current_epoch),
    );

    BilateralContextRecovery {
        context_id: params.context_id.to_owned(),
        offline_member_did: params.offline_did.clone(),
        online_member_did: params.online_did.clone(),
        online_member_can_reset: params.online_can_reset,
        last_known_epoch: params.local_epoch,
        current_epoch: params.current_epoch,
        online_member_queued_messages: 0,
        assessment,
    }
}

// ---------------------------------------------------------------------------
// MemberResetEvent
// ---------------------------------------------------------------------------

/// Event log entry for a member group state reset.
///
/// Distinct from `MemberLeft` + `MemberJoined` — this records that the member
/// underwent a forced re-join, preserving the causal link between the old and
/// new MLS leaf nodes.
///
/// See ADR-029 section 4, step 5.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberResetEvent {
    /// The DID of the member who was reset.
    pub member_did: DID,
    /// The MLS epoch before reset (the member's stale epoch).
    pub old_epoch: u64,
    /// The MLS epoch after reset (the current group epoch post-Welcome).
    pub new_epoch: u64,
    /// Why the reset occurred.
    pub reason: ResetReason,
    /// The DID of the admin who processed the reset.
    pub processed_by: DID,
    /// Unix timestamp when the reset was processed.
    pub timestamp: u64,
}

// ---------------------------------------------------------------------------
// ReJoinExecutor (trait)
// ---------------------------------------------------------------------------

/// Async interface for executing the MLS operations during a forced re-join.
///
/// Implementations handle the actual MLS group manipulation: removing the
/// stale leaf node, adding a fresh `KeyPackage`, and distributing the Welcome
/// message. The trait abstracts these operations so the module can be tested
/// without a live MLS group.
///
/// Note: uses `async fn in trait` which is NOT object-safe (cannot use
/// `dyn ReJoinExecutor`). If dyn-dispatch is needed in the future, convert
/// to `BoxFuture` return types per the `TransportAdapter` pattern in the
/// `days_offline` module.
///
/// See ADR-029 section 4, steps 2-3.
#[allow(async_fn_in_trait)]
pub trait ReJoinExecutor: Send + Sync {
    /// Publishes a [`ResetRequest`] to the relay.
    ///
    /// The request is sent as plaintext (not MLS-encrypted) since the member
    /// may not be able to encrypt at the current epoch.
    async fn publish_reset_request(&self, request: &ResetRequest) -> Result<(), WeeksOfflineError>;

    /// Processes a reset request on the admin side: removes the stale member
    /// and re-adds them with a fresh `KeyPackage`.
    ///
    /// Returns the new epoch after the re-add Commit.
    async fn process_reset(
        &self,
        context_id: &str,
        member_did: &DID,
        role_to_restore: &str,
    ) -> Result<u64, WeeksOfflineError>;

    /// Waits for and processes the Welcome message after a reset.
    ///
    /// The reconnecting member calls this after publishing the reset request.
    /// Returns the new epoch after joining via Welcome.
    async fn await_welcome(
        &self,
        context_id: &str,
        timeout_secs: u64,
    ) -> Result<u64, WeeksOfflineError>;
}

// ---------------------------------------------------------------------------
// WeeksOfflineError
// ---------------------------------------------------------------------------

/// Errors specific to weeks-scale offline recovery.
#[derive(Debug, thiserror::Error)]
pub enum WeeksOfflineError {
    /// The reset request could not be published to the relay.
    #[error("failed to publish reset request for context {context_id}: {reason}")]
    ResetRequestFailed {
        /// The context where the reset request failed.
        context_id: ContextId,
        /// Human-readable reason.
        reason: String,
    },

    /// The reset was not processed within the timeout.
    #[error(
        "reset welcome timeout for context {context_id} \
         (waited {timeout_secs}s)"
    )]
    WelcomeTimeout {
        /// The context where the timeout occurred.
        context_id: ContextId,
        /// How long we waited.
        timeout_secs: u64,
    },

    /// No admin is online to process the reset request.
    #[error("no admin online to process reset for context {context_id}")]
    NoAdminAvailable {
        /// The context with no available admin.
        context_id: ContextId,
    },

    /// The admin lacks required capabilities (`MemberRemove` + `MemberInvite`).
    #[error("admin {admin_did} lacks reset capabilities for context {context_id}")]
    InsufficientCapabilities {
        /// The context where the capability check failed.
        context_id: ContextId,
        /// The admin DID that lacks capabilities.
        admin_did: DID,
    },

    /// State preservation failed — the member's role could not be restored.
    #[error("role restoration failed for {member_did} in context {context_id}: {reason}")]
    RoleRestorationFailed {
        /// The context where restoration failed.
        context_id: ContextId,
        /// The member whose role could not be restored.
        member_did: DID,
        /// Human-readable reason.
        reason: String,
    },

    /// The bilateral context recovery failed.
    #[error("bilateral recovery failed for context {context_id}: {reason}")]
    BilateralRecoveryFailed {
        /// The bilateral context.
        context_id: ContextId,
        /// Human-readable reason.
        reason: String,
    },

    /// The `ResetRequest` is too old (exceeds freshness window).
    ///
    /// See §23.5.2, ADR-029 section 4.
    #[error(
        "stale reset request for context {context_id}: \
         age {age_secs}s exceeds max {max_age_secs}s"
    )]
    StaleResetRequest {
        /// The context where the stale request was received.
        context_id: ContextId,
        /// Actual age of the request in seconds.
        age_secs: u64,
        /// Maximum allowed age in seconds.
        max_age_secs: u64,
    },

    /// The `ResetRequest` nonce was already seen (replay attempt).
    ///
    /// See §23.5.2, ADR-029 section 4.
    #[error("replayed reset request for context {context_id}: nonce already seen")]
    ReplayedResetRequest {
        /// The context where the replay was detected.
        context_id: ContextId,
        /// The replayed nonce.
        nonce: [u8; 16],
    },

    /// In-flight message queue overflow.
    #[error(
        "in-flight queue overflow in context {context_id}: \
         {queued} messages (max {max_size})"
    )]
    InFlightQueueOverflow {
        /// The context where the overflow occurred.
        context_id: ContextId,
        /// Number of messages queued.
        queued: usize,
        /// Maximum queue size.
        max_size: usize,
    },

    /// Underlying sync error.
    #[error("sync error: {0}")]
    Sync(#[from] SyncError),
}

// ---------------------------------------------------------------------------
// create_rejoin_plan
// ---------------------------------------------------------------------------

/// Input parameters for creating a re-join plan.
///
/// Bundles the arguments for [`create_rejoin_plan`] to stay within the
/// 7-argument clippy limit.
pub struct ReJoinPlanParams<'a> {
    /// The context requiring re-join.
    pub context_id: &'a str,
    /// The DID of the member being re-joined.
    pub member_did: &'a DID,
    /// The member's last known MLS epoch.
    pub last_known_epoch: u64,
    /// Why the re-join is needed.
    pub reason: ResetReason,
    /// The member's current role to be preserved.
    pub role_name: &'a str,
    /// State preservation details.
    pub preservation: StatePreservation,
    /// Number of messages queued locally.
    pub queued_message_count: u64,
}

/// Creates a [`ReJoinPlan`] for a member who needs forced re-join.
///
/// The plan captures the member's current state, the reason for re-join, and
/// what context state to preserve across the transition. The caller is
/// responsible for executing the plan via a [`ReJoinExecutor`].
#[must_use]
pub fn create_rejoin_plan(params: &ReJoinPlanParams<'_>) -> ReJoinPlan {
    let queued_message_count = params.queued_message_count;

    let inflight_handling = if queued_message_count == 0 {
        InFlightMessageHandling::Discard {
            discarded_count: 0,
            reason: "no messages queued".to_owned(),
        }
    } else if u64_exceeds_usize(queued_message_count, MAX_INFLIGHT_QUEUE_SIZE) {
        InFlightMessageHandling::Discard {
            discarded_count: queued_message_count,
            reason: format!("queue overflow: {queued_message_count} > {MAX_INFLIGHT_QUEUE_SIZE}"),
        }
    } else {
        InFlightMessageHandling::QueueAndResend {
            queued_count: queued_message_count,
            max_queue_size: MAX_INFLIGHT_QUEUE_SIZE,
        }
    };

    ReJoinPlan {
        context_id: params.context_id.to_owned(),
        member_did: params.member_did.clone(),
        last_known_epoch: params.last_known_epoch,
        reason: params.reason.clone(),
        state_preservation: params.preservation.clone(),
        inflight_handling,
    }
}

// ---------------------------------------------------------------------------
// ReJoinResult
// ---------------------------------------------------------------------------

/// Result of a weeks-scale offline re-join for a single context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReJoinResult {
    /// The context that was re-joined.
    pub context_id: ContextId,
    /// The member who was re-joined.
    pub member_did: DID,
    /// The old (stale) MLS epoch before reset.
    pub old_epoch: u64,
    /// The new MLS epoch after reset.
    pub new_epoch: u64,
    /// How in-flight messages were handled.
    pub inflight_handling: InFlightMessageHandling,
    /// Number of events recovered from the event log.
    pub events_recovered: u64,
    /// Overall sync outcome.
    pub outcome: SyncOutcome,
}

// ---------------------------------------------------------------------------
// determine_inflight_handling
// ---------------------------------------------------------------------------

/// Determines the appropriate in-flight message handling strategy.
///
/// # Arguments
///
/// * `queued_count` - Number of locally queued messages.
/// * `queue_max` - Maximum queue size.
/// * `blob_ttl_secs` - Context's blob TTL in seconds (`None` if no TTL).
/// * `oldest_message_age_secs` - Age of the oldest queued message in seconds.
#[must_use]
pub fn determine_inflight_handling(
    queued_count: u64,
    queue_max: usize,
    blob_ttl_secs: Option<u64>,
    oldest_message_age_secs: u64,
) -> InFlightMessageHandling {
    // If no messages, nothing to handle.
    if queued_count == 0 {
        return InFlightMessageHandling::Discard {
            discarded_count: 0,
            reason: "no messages queued".to_owned(),
        };
    }

    // If queue overflows, discard all.
    if u64_exceeds_usize(queued_count, queue_max) {
        return InFlightMessageHandling::Discard {
            discarded_count: queued_count,
            reason: format!("queue overflow: {queued_count} exceeds max {queue_max}"),
        };
    }

    // If messages are older than blob TTL, discard — they would expire on
    // relays before delivery anyway (ADR-029 section 1).
    if let Some(ttl) = blob_ttl_secs
        && oldest_message_age_secs > ttl
    {
        return InFlightMessageHandling::Discard {
            discarded_count: queued_count,
            reason: format!("messages older than blob TTL ({oldest_message_age_secs}s > {ttl}s)"),
        };
    }

    // Otherwise, queue and resend after re-join completes.
    InFlightMessageHandling::QueueAndResend {
        queued_count,
        max_queue_size: queue_max,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::match_wildcard_for_single_variants
)]
mod tests {
    use super::super::SyncPolicy;
    use super::*;

    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------

    const BASE_TIMESTAMP: u64 = 1_700_000_000;
    const EIGHT_DAYS_SECS: u64 = 8 * 86_400;
    const THREE_DAYS_SECS: u64 = 3 * 86_400;
    const FOURTEEN_DAYS_SECS: u64 = 14 * 86_400;
    const THIRTY_DAYS_SECS: u64 = 30 * 86_400;

    // -----------------------------------------------------------------------
    // assess_offline_state tests
    // -----------------------------------------------------------------------

    #[test]
    fn assess_catch_up_feasible_within_threshold() {
        // 3 days offline, small epoch gap — catch-up feasible.
        let result = assess_offline_state(
            BASE_TIMESTAMP,
            BASE_TIMESTAMP + THREE_DAYS_SECS,
            Some(100),
            Some(200),
        );
        match result {
            OfflineAssessment::CatchUpFeasible {
                offline_duration_secs,
                epoch_gap,
            } => {
                assert_eq!(offline_duration_secs, THREE_DAYS_SECS);
                assert_eq!(epoch_gap, 100);
            }
            _ => panic!("expected CatchUpFeasible, got {result:?}"),
        }
    }

    #[test]
    fn assess_force_rejoin_offline_duration_exceeded() {
        // 8 days offline — exceeds 7-day threshold.
        let result = assess_offline_state(
            BASE_TIMESTAMP,
            BASE_TIMESTAMP + EIGHT_DAYS_SECS,
            Some(100),
            Some(200),
        );
        match result {
            OfflineAssessment::ForceReJoinRequired { triggers } => {
                assert_eq!(triggers.len(), 1);
                match &triggers[0] {
                    ResetTrigger::OfflineDurationExceeded {
                        duration_secs,
                        threshold_secs,
                    } => {
                        assert_eq!(*duration_secs, EIGHT_DAYS_SECS);
                        assert_eq!(*threshold_secs, MAX_OFFLINE_DURATION_SECS);
                    }
                    _ => panic!("expected OfflineDurationExceeded, got {:?}", triggers[0]),
                }
            }
            _ => panic!("expected ForceReJoinRequired, got {result:?}"),
        }
    }

    #[test]
    fn assess_force_rejoin_epoch_drift_exceeded() {
        // Within 7-day window but epoch drift > 1000.
        let result = assess_offline_state(
            BASE_TIMESTAMP,
            BASE_TIMESTAMP + THREE_DAYS_SECS,
            Some(100),
            Some(1_200),
        );
        match result {
            OfflineAssessment::ForceReJoinRequired { triggers } => {
                assert_eq!(triggers.len(), 1);
                match &triggers[0] {
                    ResetTrigger::EpochDriftExceeded {
                        local_epoch,
                        current_epoch,
                        threshold,
                    } => {
                        assert_eq!(*local_epoch, 100);
                        assert_eq!(*current_epoch, 1_200);
                        assert_eq!(*threshold, MAX_EPOCH_DRIFT);
                    }
                    _ => panic!("expected EpochDriftExceeded, got {:?}", triggers[0]),
                }
            }
            _ => panic!("expected ForceReJoinRequired, got {result:?}"),
        }
    }

    #[test]
    fn assess_force_rejoin_both_triggers() {
        // Both offline duration AND epoch drift exceeded.
        let result = assess_offline_state(
            BASE_TIMESTAMP,
            BASE_TIMESTAMP + FOURTEEN_DAYS_SECS,
            Some(10),
            Some(2_000),
        );
        match result {
            OfflineAssessment::ForceReJoinRequired { triggers } => {
                assert_eq!(triggers.len(), 2);
                assert!(matches!(
                    triggers[0],
                    ResetTrigger::OfflineDurationExceeded { .. }
                ));
                assert!(matches!(
                    triggers[1],
                    ResetTrigger::EpochDriftExceeded { .. }
                ));
            }
            _ => panic!("expected ForceReJoinRequired, got {result:?}"),
        }
    }

    #[test]
    fn assess_broadcast_context_no_epoch_trigger() {
        // Broadcast context (no MLS) — only offline duration matters.
        let result =
            assess_offline_state(BASE_TIMESTAMP, BASE_TIMESTAMP + EIGHT_DAYS_SECS, None, None);
        match result {
            OfflineAssessment::ForceReJoinRequired { triggers } => {
                assert_eq!(triggers.len(), 1);
                assert!(matches!(
                    triggers[0],
                    ResetTrigger::OfflineDurationExceeded { .. }
                ));
            }
            _ => panic!("expected ForceReJoinRequired, got {result:?}"),
        }
    }

    #[test]
    fn assess_at_exact_threshold_is_feasible() {
        // Exactly 7 days = 604_800 seconds — NOT exceeded (must be strictly >).
        let result = assess_offline_state(
            BASE_TIMESTAMP,
            BASE_TIMESTAMP + MAX_OFFLINE_DURATION_SECS,
            Some(100),
            Some(200),
        );
        assert!(matches!(result, OfflineAssessment::CatchUpFeasible { .. }));
    }

    #[test]
    fn assess_epoch_drift_exactly_at_threshold_is_feasible() {
        // Exactly 1000 epoch drift — NOT exceeded (must be strictly >).
        let result = assess_offline_state(
            BASE_TIMESTAMP,
            BASE_TIMESTAMP + THREE_DAYS_SECS,
            Some(100),
            Some(1_100),
        );
        assert!(matches!(result, OfflineAssessment::CatchUpFeasible { .. }));
    }

    #[test]
    fn assess_clock_skew_saturates_to_zero() {
        // now < last_relay_contact — saturating_sub returns 0 (Short tier).
        let result = assess_offline_state(
            BASE_TIMESTAMP + 1_000_000,
            BASE_TIMESTAMP,
            Some(100),
            Some(200),
        );
        assert!(matches!(result, OfflineAssessment::CatchUpFeasible { .. }));
    }

    // -----------------------------------------------------------------------
    // create_rejoin_plan tests
    // -----------------------------------------------------------------------

    #[test]
    fn create_plan_with_no_queued_messages() {
        let plan = create_rejoin_plan(&ReJoinPlanParams {
            context_id: "ctx-bilateral",
            member_did: &DID::from("did:dht:z6MkBob"),
            last_known_epoch: 50,
            reason: ResetReason::ExtendedOffline {
                offline_duration_secs: EIGHT_DAYS_SECS,
            },
            role_name: "member",
            preservation: StatePreservation {
                role_to_restore: "member".to_owned(),
                local_event_count: 1000,
                local_merkle_root: [1u8; 32],
                params_hash: [2u8; 32],
                active_tools: vec!["tool-a".to_owned()],
                membership_roster: BTreeMap::from([
                    ("did:alice".to_owned(), "admin".to_owned()),
                    ("did:bob".to_owned(), "member".to_owned()),
                ]),
                invalidated_proposals: 0,
            },
            queued_message_count: 0,
        });

        assert_eq!(plan.context_id, "ctx-bilateral");
        assert_eq!(plan.member_did, "did:dht:z6MkBob");
        assert_eq!(plan.last_known_epoch, 50);
        assert_eq!(plan.state_preservation.role_to_restore, "member");
        assert_eq!(plan.state_preservation.local_event_count, 1000);
        assert_eq!(plan.state_preservation.active_tools, vec!["tool-a"]);
        assert_eq!(plan.state_preservation.membership_roster.len(), 2);
        assert!(matches!(
            plan.inflight_handling,
            InFlightMessageHandling::Discard {
                discarded_count: 0,
                ..
            }
        ));
    }

    #[test]
    fn create_plan_with_queued_messages_within_limit() {
        let plan = create_rejoin_plan(&ReJoinPlanParams {
            context_id: "ctx-1",
            member_did: &DID::from("did:dht:z6MkBob"),
            last_known_epoch: 50,
            reason: ResetReason::CatchUpFailed {
                attempted_sources: vec!["relay".to_owned(), "peer".to_owned()],
            },
            role_name: "member",
            preservation: StatePreservation {
                role_to_restore: "member".to_owned(),
                local_event_count: 500,
                local_merkle_root: [0u8; 32],
                params_hash: [0u8; 32],
                active_tools: vec![],
                membership_roster: BTreeMap::new(),
                invalidated_proposals: 0,
            },
            queued_message_count: 100,
        });

        match plan.inflight_handling {
            InFlightMessageHandling::QueueAndResend {
                queued_count,
                max_queue_size,
            } => {
                assert_eq!(queued_count, 100);
                assert_eq!(max_queue_size, MAX_INFLIGHT_QUEUE_SIZE);
            }
            _ => panic!("expected QueueAndResend, got {:?}", plan.inflight_handling),
        }
    }

    #[test]
    fn create_plan_with_queue_overflow() {
        let plan = create_rejoin_plan(&ReJoinPlanParams {
            context_id: "ctx-1",
            member_did: &DID::from("did:dht:z6MkBob"),
            last_known_epoch: 50,
            reason: ResetReason::ExtendedOffline {
                offline_duration_secs: THIRTY_DAYS_SECS,
            },
            role_name: "admin",
            preservation: StatePreservation {
                role_to_restore: "admin".to_owned(),
                local_event_count: 2000,
                local_merkle_root: [0u8; 32],
                params_hash: [0u8; 32],
                active_tools: vec![],
                membership_roster: BTreeMap::new(),
                invalidated_proposals: 0,
            },
            queued_message_count: 600, // > MAX_INFLIGHT_QUEUE_SIZE (500)
        });

        match plan.inflight_handling {
            InFlightMessageHandling::Discard {
                discarded_count,
                reason,
            } => {
                assert_eq!(discarded_count, 600);
                assert!(reason.contains("overflow"));
            }
            _ => panic!("expected Discard, got {:?}", plan.inflight_handling),
        }
    }

    // -----------------------------------------------------------------------
    // determine_inflight_handling tests
    // -----------------------------------------------------------------------

    #[test]
    fn inflight_no_messages() {
        let result = determine_inflight_handling(0, 500, Some(604_800), 0);
        assert!(matches!(
            result,
            InFlightMessageHandling::Discard {
                discarded_count: 0,
                ..
            }
        ));
    }

    #[test]
    fn inflight_queue_overflow() {
        let result = determine_inflight_handling(600, 500, Some(604_800), 100);
        match result {
            InFlightMessageHandling::Discard {
                discarded_count,
                reason,
            } => {
                assert_eq!(discarded_count, 600);
                assert!(reason.contains("overflow"));
            }
            _ => panic!("expected Discard, got {result:?}"),
        }
    }

    #[test]
    fn inflight_messages_older_than_ttl() {
        // Messages are 8 days old, TTL is 7 days.
        let result = determine_inflight_handling(10, 500, Some(604_800), EIGHT_DAYS_SECS);
        match result {
            InFlightMessageHandling::Discard {
                discarded_count,
                reason,
            } => {
                assert_eq!(discarded_count, 10);
                assert!(reason.contains("TTL"));
            }
            _ => panic!("expected Discard, got {result:?}"),
        }
    }

    #[test]
    fn inflight_messages_within_ttl() {
        // Messages are 3 days old, TTL is 7 days — queue and resend.
        let result = determine_inflight_handling(10, 500, Some(604_800), THREE_DAYS_SECS);
        match result {
            InFlightMessageHandling::QueueAndResend {
                queued_count,
                max_queue_size,
            } => {
                assert_eq!(queued_count, 10);
                assert_eq!(max_queue_size, 500);
            }
            _ => panic!("expected QueueAndResend, got {result:?}"),
        }
    }

    #[test]
    fn inflight_no_ttl_queues_messages() {
        // No blob TTL — queue and resend.
        let result = determine_inflight_handling(50, 500, None, EIGHT_DAYS_SECS);
        assert!(matches!(
            result,
            InFlightMessageHandling::QueueAndResend { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // assess_bilateral_recovery tests
    // -----------------------------------------------------------------------

    #[test]
    fn bilateral_recovery_offline_exceeds_threshold() {
        let recovery = assess_bilateral_recovery(&BilateralRecoveryParams {
            context_id: "ctx-bilateral",
            offline_did: &DID::from("did:dht:z6MkBob"),
            online_did: &DID::from("did:dht:z6MkAlice"),
            online_can_reset: true,
            last_relay_contact: BASE_TIMESTAMP,
            now: BASE_TIMESTAMP + FOURTEEN_DAYS_SECS,
            local_epoch: 50,
            current_epoch: 200,
        });

        assert_eq!(recovery.context_id, "ctx-bilateral");
        assert_eq!(recovery.offline_member_did, "did:dht:z6MkBob");
        assert_eq!(recovery.online_member_did, "did:dht:z6MkAlice");
        assert!(recovery.online_member_can_reset);
        assert_eq!(recovery.last_known_epoch, 50);
        assert_eq!(recovery.current_epoch, 200);
        assert!(matches!(
            recovery.assessment,
            OfflineAssessment::ForceReJoinRequired { .. }
        ));
    }

    #[test]
    fn bilateral_recovery_within_threshold() {
        let recovery = assess_bilateral_recovery(&BilateralRecoveryParams {
            context_id: "ctx-bilateral",
            offline_did: &DID::from("did:dht:z6MkBob"),
            online_did: &DID::from("did:dht:z6MkAlice"),
            online_can_reset: true,
            last_relay_contact: BASE_TIMESTAMP,
            now: BASE_TIMESTAMP + THREE_DAYS_SECS,
            local_epoch: 50,
            current_epoch: 60,
        });

        assert!(matches!(
            recovery.assessment,
            OfflineAssessment::CatchUpFeasible { .. }
        ));
    }

    #[test]
    fn bilateral_recovery_online_member_cannot_reset() {
        let recovery = assess_bilateral_recovery(&BilateralRecoveryParams {
            context_id: "ctx-bilateral",
            offline_did: &DID::from("did:dht:z6MkBob"),
            online_did: &DID::from("did:dht:z6MkAlice"),
            online_can_reset: false,
            last_relay_contact: BASE_TIMESTAMP,
            now: BASE_TIMESTAMP + FOURTEEN_DAYS_SECS,
            local_epoch: 50,
            current_epoch: 200,
        });

        assert!(!recovery.online_member_can_reset);
    }

    // -----------------------------------------------------------------------
    // ResetReason Display tests
    // -----------------------------------------------------------------------

    #[test]
    fn reset_reason_display_extended_offline() {
        let reason = ResetReason::ExtendedOffline {
            offline_duration_secs: FOURTEEN_DAYS_SECS,
        };
        let display = reason.to_string();
        assert!(display.contains("14 days"));
        assert!(display.contains("extended offline"));
    }

    #[test]
    fn reset_reason_display_catch_up_failed() {
        let reason = ResetReason::CatchUpFailed {
            attempted_sources: vec!["relay".to_owned(), "peer".to_owned(), "welcome".to_owned()],
        };
        let display = reason.to_string();
        assert!(display.contains("catch-up failed"));
        assert!(display.contains("relay, peer, welcome"));
    }

    #[test]
    fn reset_reason_display_governance_action() {
        let reason = ResetReason::GovernanceAction {
            proposal_id: "prop-42".to_owned(),
        };
        assert!(reason.to_string().contains("prop-42"));
    }

    // -----------------------------------------------------------------------
    // ResetRequest serialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn reset_request_serializable() {
        let request = ResetRequest {
            context_id: "ctx-1".to_owned(),
            member_did: DID::from("did:dht:z6MkBob"),
            last_known_epoch: 42,
            reason: ResetReason::ExtendedOffline {
                offline_duration_secs: EIGHT_DAYS_SECS,
            },
            nonce: [0xAB; 16],
            timestamp: BASE_TIMESTAMP,
            signature: vec![0u8; 64],
        };
        let json = serde_json::to_string(&request).unwrap();
        let deserialized: ResetRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(request, deserialized);
    }

    // -----------------------------------------------------------------------
    // MemberResetEvent tests
    // -----------------------------------------------------------------------

    #[test]
    fn member_reset_event_serializable() {
        let event = MemberResetEvent {
            member_did: DID::from("did:dht:z6MkBob"),
            old_epoch: 50,
            new_epoch: 200,
            reason: ResetReason::CatchUpFailed {
                attempted_sources: vec!["relay".to_owned()],
            },
            processed_by: DID::from("did:dht:z6MkAlice"),
            timestamp: BASE_TIMESTAMP,
        };
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: MemberResetEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, deserialized);
    }

    // -----------------------------------------------------------------------
    // StatePreservation tests
    // -----------------------------------------------------------------------

    #[test]
    fn state_preservation_captures_roster() {
        let roster = BTreeMap::from([
            ("did:alice".to_owned(), "admin".to_owned()),
            ("did:bob".to_owned(), "member".to_owned()),
            ("did:carol".to_owned(), "member".to_owned()),
        ]);
        let preservation = StatePreservation {
            role_to_restore: "member".to_owned(),
            local_event_count: 5000,
            local_merkle_root: [42u8; 32],
            params_hash: [7u8; 32],
            active_tools: vec!["search".to_owned(), "translate".to_owned()],
            membership_roster: roster,
            invalidated_proposals: 2,
        };
        assert_eq!(preservation.membership_roster.len(), 3);
        assert_eq!(preservation.invalidated_proposals, 2);
        assert_eq!(preservation.active_tools.len(), 2);
    }

    // -----------------------------------------------------------------------
    // ReJoinResult tests
    // -----------------------------------------------------------------------

    #[test]
    fn rejoin_result_serializable() {
        let result = ReJoinResult {
            context_id: "ctx-1".to_owned(),
            member_did: DID::from("did:dht:z6MkBob"),
            old_epoch: 50,
            new_epoch: 200,
            inflight_handling: InFlightMessageHandling::QueueAndResend {
                queued_count: 10,
                max_queue_size: 500,
            },
            events_recovered: 150,
            outcome: SyncOutcome::Reset,
        };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: ReJoinResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, deserialized);
    }

    #[test]
    fn rejoin_result_with_discard_serializable() {
        let result = ReJoinResult {
            context_id: "ctx-2".to_owned(),
            member_did: DID::from("did:dht:z6MkCarol"),
            old_epoch: 10,
            new_epoch: 500,
            inflight_handling: InFlightMessageHandling::Discard {
                discarded_count: 42,
                reason: "queue overflow".to_owned(),
            },
            events_recovered: 0,
            outcome: SyncOutcome::Reset,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("queue overflow"));
    }

    // -----------------------------------------------------------------------
    // WeeksOfflineError Display tests
    // -----------------------------------------------------------------------

    #[test]
    fn error_display_messages() {
        let err = WeeksOfflineError::ResetRequestFailed {
            context_id: "ctx-1".to_owned(),
            reason: "connection refused".to_owned(),
        };
        assert!(err.to_string().contains("ctx-1"));
        assert!(err.to_string().contains("connection refused"));

        let err = WeeksOfflineError::WelcomeTimeout {
            context_id: "ctx-2".to_owned(),
            timeout_secs: 60,
        };
        assert!(err.to_string().contains("ctx-2"));
        assert!(err.to_string().contains("60s"));

        let err = WeeksOfflineError::NoAdminAvailable {
            context_id: "ctx-3".to_owned(),
        };
        assert!(err.to_string().contains("no admin"));

        let err = WeeksOfflineError::InsufficientCapabilities {
            context_id: "ctx-4".to_owned(),
            admin_did: DID::from("did:admin"),
        };
        assert!(err.to_string().contains("did:admin"));

        let err = WeeksOfflineError::InFlightQueueOverflow {
            context_id: "ctx-5".to_owned(),
            queued: 600,
            max_size: 500,
        };
        assert!(err.to_string().contains("600"));
        assert!(err.to_string().contains("500"));
    }

    // -----------------------------------------------------------------------
    // Stress tests — simulated weeks-offline scenarios
    // -----------------------------------------------------------------------

    #[test]
    fn stress_thirty_days_offline_triggers_rejoin() {
        let result = assess_offline_state(
            BASE_TIMESTAMP,
            BASE_TIMESTAMP + THIRTY_DAYS_SECS,
            Some(10),
            Some(5_000),
        );
        match result {
            OfflineAssessment::ForceReJoinRequired { triggers } => {
                // Both triggers should fire: duration AND epoch drift.
                assert_eq!(triggers.len(), 2);
            }
            _ => panic!("expected ForceReJoinRequired for 30-day offline"),
        }
    }

    #[test]
    fn stress_many_epoch_advances_during_offline() {
        // Simulate a context with very high churn: 10_000 epoch advances
        // while the member was offline for just 6 days (within Tier 2 window).
        let result = assess_offline_state(
            BASE_TIMESTAMP,
            BASE_TIMESTAMP + (6 * 86_400),
            Some(100),
            Some(10_100),
        );
        match result {
            OfflineAssessment::ForceReJoinRequired { triggers } => {
                assert_eq!(triggers.len(), 1);
                assert!(matches!(
                    triggers[0],
                    ResetTrigger::EpochDriftExceeded { .. }
                ));
            }
            _ => panic!("expected ForceReJoinRequired for epoch drift"),
        }
    }

    #[test]
    fn stress_bilateral_recovery_long_offline() {
        let recovery = assess_bilateral_recovery(&BilateralRecoveryParams {
            context_id: "ctx-bilateral-long",
            offline_did: &DID::from("did:dht:z6MkBobLong"),
            online_did: &DID::from("did:dht:z6MkAliceLong"),
            online_can_reset: true,
            last_relay_contact: BASE_TIMESTAMP,
            now: BASE_TIMESTAMP + THIRTY_DAYS_SECS,
            local_epoch: 10,
            current_epoch: 3_000,
        });
        assert!(matches!(
            recovery.assessment,
            OfflineAssessment::ForceReJoinRequired { .. }
        ));
        assert!(recovery.online_member_can_reset);
    }

    #[test]
    fn stress_full_rejoin_plan_with_large_roster() {
        let mut roster = BTreeMap::new();
        for i in 0..100 {
            roster.insert(format!("did:member-{i}"), "member".to_owned());
        }
        roster.insert("did:admin".to_owned(), "admin".to_owned());

        let plan = create_rejoin_plan(&ReJoinPlanParams {
            context_id: "ctx-large-group",
            member_did: &DID::from("did:member-42"),
            last_known_epoch: 100,
            reason: ResetReason::ExtendedOffline {
                offline_duration_secs: FOURTEEN_DAYS_SECS,
            },
            role_name: "member",
            preservation: StatePreservation {
                role_to_restore: "member".to_owned(),
                local_event_count: 50_000,
                local_merkle_root: [99u8; 32],
                params_hash: [88u8; 32],
                active_tools: (0..20).map(|i| format!("tool-{i}")).collect(),
                membership_roster: roster,
                invalidated_proposals: 0,
            },
            queued_message_count: 250,
        });

        assert_eq!(plan.state_preservation.membership_roster.len(), 101);
        assert_eq!(plan.state_preservation.active_tools.len(), 20);
        assert_eq!(plan.state_preservation.local_event_count, 50_000);
        assert!(matches!(
            plan.inflight_handling,
            InFlightMessageHandling::QueueAndResend {
                queued_count: 250,
                ..
            }
        ));
    }

    // -----------------------------------------------------------------------
    // Constants sanity checks
    // -----------------------------------------------------------------------

    #[test]
    fn max_epoch_drift_is_one_thousand() {
        assert_eq!(MAX_EPOCH_DRIFT, 1_000);
    }

    #[test]
    fn max_offline_duration_matches_tier_2_threshold() {
        assert_eq!(
            MAX_OFFLINE_DURATION_SECS,
            SyncPolicy::default().tier_2_threshold_secs,
        );
    }

    #[test]
    fn reset_welcome_timeout_is_sixty_seconds() {
        assert_eq!(RESET_WELCOME_TIMEOUT_SECS, 60);
    }

    #[test]
    fn max_inflight_queue_size_is_five_hundred() {
        assert_eq!(MAX_INFLIGHT_QUEUE_SIZE, 500);
    }

    // -----------------------------------------------------------------------
    // ResetRequest canonical hash tests
    // -----------------------------------------------------------------------

    #[test]
    fn canonical_hash_is_deterministic() {
        let request = ResetRequest {
            context_id: "ctx-1".to_owned(),
            member_did: DID::from("did:dht:z6MkBob"),
            last_known_epoch: 42,
            reason: ResetReason::ExtendedOffline {
                offline_duration_secs: EIGHT_DAYS_SECS,
            },
            nonce: [0xAB; 16],
            timestamp: BASE_TIMESTAMP,
            signature: vec![0u8; 64],
        };
        let hash1 = request.canonical_hash();
        let hash2 = request.canonical_hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn canonical_hash_differs_with_different_nonce() {
        let mut request = ResetRequest {
            context_id: "ctx-1".to_owned(),
            member_did: DID::from("did:dht:z6MkBob"),
            last_known_epoch: 42,
            reason: ResetReason::ExtendedOffline {
                offline_duration_secs: EIGHT_DAYS_SECS,
            },
            nonce: [0xAA; 16],
            timestamp: BASE_TIMESTAMP,
            signature: vec![0u8; 64],
        };
        let hash1 = request.canonical_hash();
        request.nonce = [0xBB; 16];
        let hash2 = request.canonical_hash();
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn canonical_hash_uses_correct_domain_separator() {
        use crate::crypto::canonical::{CanonicalField as CF, canonical_hash as ch};

        let request = ResetRequest {
            context_id: "ctx-1".to_owned(),
            member_did: DID::from("did:dht:z6MkBob"),
            last_known_epoch: 42,
            reason: ResetReason::ExtendedOffline {
                offline_duration_secs: EIGHT_DAYS_SECS,
            },
            nonce: [0xAB; 16],
            timestamp: BASE_TIMESTAMP,
            signature: vec![],
        };
        let hash = request.canonical_hash();
        // Verify by manual construction using the same canonical_hash utility.
        let reason_str = request.reason.to_string();
        let expected = ch(
            "SCP-RESET-REQUEST-V1:",
            &[
                CF::VarBytes(b"ctx-1"),
                CF::VarBytes(b"did:dht:z6MkBob"),
                CF::U64(42),
                CF::VarBytes(reason_str.as_bytes()),
                CF::RawBytes(&[0xAB; 16]),
                CF::U64(BASE_TIMESTAMP),
            ],
        );
        assert_eq!(hash, expected);
    }

    // -----------------------------------------------------------------------
    // ResetRequestNonceTracker tests
    // -----------------------------------------------------------------------

    #[test]
    fn nonce_tracker_accepts_new_nonce() {
        let tracker = ResetRequestNonceTracker::with_default_ttl();
        let nonce = [0x01; 16];
        let guard =
            tracker.check_and_tentatively_record("did:dht:z6MkAlice", &nonce, BASE_TIMESTAMP);
        assert!(guard.is_some());
        guard.unwrap().commit();
    }

    #[test]
    fn nonce_tracker_rejects_duplicate_nonce() {
        let tracker = ResetRequestNonceTracker::with_default_ttl();
        let nonce = [0x01; 16];
        let did = "did:dht:z6MkAlice";
        let guard = tracker.check_and_tentatively_record(did, &nonce, BASE_TIMESTAMP);
        assert!(guard.is_some());
        guard.unwrap().commit();
        assert!(
            tracker
                .check_and_tentatively_record(did, &nonce, BASE_TIMESTAMP + 1)
                .is_none()
        );
    }

    #[test]
    fn nonce_tracker_same_nonce_different_did_accepted() {
        let tracker = ResetRequestNonceTracker::with_default_ttl();
        let nonce = [0x01; 16];
        // Same nonce from different DIDs should both be accepted.
        let g1 = tracker.check_and_tentatively_record("did:dht:z6MkAlice", &nonce, BASE_TIMESTAMP);
        assert!(g1.is_some());
        g1.unwrap().commit();
        let g2 = tracker.check_and_tentatively_record("did:dht:z6MkBob", &nonce, BASE_TIMESTAMP);
        assert!(g2.is_some());
        g2.unwrap().commit();
    }

    #[test]
    fn nonce_tracker_accepts_after_ttl_expires() {
        let tracker = ResetRequestNonceTracker::new(60);
        let nonce = [0x01; 16];
        let did = "did:dht:z6MkAlice";
        let guard = tracker.check_and_tentatively_record(did, &nonce, BASE_TIMESTAMP);
        assert!(guard.is_some());
        guard.unwrap().commit();
        // 61 seconds later — TTL expired, nonce evicted.
        let guard = tracker.check_and_tentatively_record(did, &nonce, BASE_TIMESTAMP + 61);
        assert!(guard.is_some());
        guard.unwrap().commit();
    }

    #[test]
    fn nonce_tracker_different_nonces_both_accepted() {
        let tracker = ResetRequestNonceTracker::with_default_ttl();
        let did = "did:dht:z6MkAlice";
        let nonce_a = [0xAA; 16];
        let nonce_b = [0xBB; 16];
        let g1 = tracker.check_and_tentatively_record(did, &nonce_a, BASE_TIMESTAMP);
        assert!(g1.is_some());
        g1.unwrap().commit();
        let g2 = tracker.check_and_tentatively_record(did, &nonce_b, BASE_TIMESTAMP);
        assert!(g2.is_some());
        g2.unwrap().commit();
    }

    #[test]
    fn nonce_tracker_capacity_bound_evicts_oldest() {
        let tracker = ResetRequestNonceTracker::new(3600); // long TTL
        let did = "did:dht:z6MkAlice";

        // Fill to MAX_NONCE_CACHE_ENTRIES.
        for i in 0..MAX_NONCE_CACHE_ENTRIES {
            let mut nonce = [0u8; 16];
            nonce[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let guard =
                tracker.check_and_tentatively_record(did, &nonce, BASE_TIMESTAMP + i as u64);
            assert!(guard.is_some());
            guard.unwrap().commit();
        }

        // Insert one more — should trigger eviction of the oldest (i=0).
        let overflow_nonce = [0xFF; 16];
        let guard = tracker.check_and_tentatively_record(
            did,
            &overflow_nonce,
            BASE_TIMESTAMP + MAX_NONCE_CACHE_ENTRIES as u64,
        );
        assert!(guard.is_some());
        guard.unwrap().commit();

        // The oldest entry (i=0, nonce=[0x00;16] with first 8 bytes = 0u64)
        // should have been evicted, so re-inserting it should succeed.
        let oldest_nonce = [0u8; 16]; // i=0 → all zeros
        let guard = tracker.check_and_tentatively_record(
            did,
            &oldest_nonce,
            BASE_TIMESTAMP + MAX_NONCE_CACHE_ENTRIES as u64 + 1,
        );
        assert!(guard.is_some());
        guard.unwrap().commit();
    }

    // -----------------------------------------------------------------------
    // validate_reset_request tests
    // -----------------------------------------------------------------------

    fn make_test_request(nonce: [u8; 16], timestamp: u64) -> ResetRequest {
        ResetRequest {
            context_id: "ctx-test".to_owned(),
            member_did: DID::from("did:dht:z6MkBob"),
            last_known_epoch: 100,
            reason: ResetReason::ExtendedOffline {
                offline_duration_secs: EIGHT_DAYS_SECS,
            },
            nonce,
            timestamp,
            signature: vec![0u8; 64],
        }
    }

    #[test]
    fn validate_accepts_fresh_unique_request() {
        let tracker = ResetRequestNonceTracker::with_default_ttl();
        let request = make_test_request([0x01; 16], BASE_TIMESTAMP);
        let result = validate_reset_request(&request, BASE_TIMESTAMP + 5, &tracker);
        assert!(result.is_ok());
        let validated = result.unwrap();
        assert_eq!(validated.canonical_hash, request.canonical_hash());
        validated.nonce_guard.commit();
    }

    #[test]
    fn validate_rejects_stale_request() {
        let tracker = ResetRequestNonceTracker::with_default_ttl();
        let request = make_test_request([0x01; 16], BASE_TIMESTAMP);
        // 31 seconds later — exceeds 30-second freshness window.
        let result = validate_reset_request(&request, BASE_TIMESTAMP + 31, &tracker);
        assert!(result.is_err());
        match result.unwrap_err() {
            WeeksOfflineError::StaleResetRequest {
                age_secs,
                max_age_secs,
                ..
            } => {
                assert_eq!(age_secs, 31);
                assert_eq!(max_age_secs, RESET_REQUEST_FRESHNESS_SECS);
            }
            other => panic!("expected StaleResetRequest, got {other:?}"),
        }
    }

    #[test]
    fn validate_accepts_request_at_exact_freshness_boundary() {
        let tracker = ResetRequestNonceTracker::with_default_ttl();
        let request = make_test_request([0x01; 16], BASE_TIMESTAMP);
        // Exactly 30 seconds — NOT exceeded (must be strictly >).
        let result = validate_reset_request(&request, BASE_TIMESTAMP + 30, &tracker);
        assert!(result.is_ok());
        result.unwrap().nonce_guard.commit();
    }

    #[test]
    fn validate_rejects_replayed_request() {
        let tracker = ResetRequestNonceTracker::with_default_ttl();
        let nonce = [0x42; 16];
        let request = make_test_request(nonce, BASE_TIMESTAMP);

        // First submission succeeds — nonce is tentatively recorded atomically.
        let result = validate_reset_request(&request, BASE_TIMESTAMP + 1, &tracker);
        assert!(result.is_ok());
        result.unwrap().nonce_guard.commit();

        // Second submission with same nonce is rejected — no TOCTOU window.
        let result = validate_reset_request(&request, BASE_TIMESTAMP + 2, &tracker);
        assert!(result.is_err());
        match result.unwrap_err() {
            WeeksOfflineError::ReplayedResetRequest {
                nonce: replayed_nonce,
                ..
            } => {
                assert_eq!(replayed_nonce, nonce);
            }
            other => panic!("expected ReplayedResetRequest, got {other:?}"),
        }
    }

    #[test]
    fn validate_stale_checked_before_nonce() {
        // A stale request should be rejected even if the nonce is new.
        // This verifies that freshness is checked first (fail fast).
        let tracker = ResetRequestNonceTracker::with_default_ttl();
        let request = make_test_request([0xFF; 16], BASE_TIMESTAMP);
        let result = validate_reset_request(&request, BASE_TIMESTAMP + 100, &tracker);
        assert!(matches!(
            result,
            Err(WeeksOfflineError::StaleResetRequest { .. })
        ));
    }

    #[test]
    fn validate_rejects_future_timestamp() {
        // A request with a timestamp 31 seconds in the future should be
        // rejected — §23.5.2 requires |relay_clock - timestamp| <= 30s.
        let tracker = ResetRequestNonceTracker::with_default_ttl();
        let future_ts = BASE_TIMESTAMP + 31;
        let request = make_test_request([0xFE; 16], future_ts);
        let result = validate_reset_request(&request, BASE_TIMESTAMP, &tracker);
        assert!(result.is_err());
        match result.unwrap_err() {
            WeeksOfflineError::StaleResetRequest {
                age_secs,
                max_age_secs,
                ..
            } => {
                assert_eq!(age_secs, 31);
                assert_eq!(max_age_secs, RESET_REQUEST_FRESHNESS_SECS);
            }
            other => panic!("expected StaleResetRequest, got {other:?}"),
        }
    }

    #[test]
    fn validate_accepts_slightly_future_timestamp() {
        // A request 30 seconds in the future is at the boundary — should pass.
        let tracker = ResetRequestNonceTracker::with_default_ttl();
        let future_ts = BASE_TIMESTAMP + 30;
        let request = make_test_request([0xFD; 16], future_ts);
        let result = validate_reset_request(&request, BASE_TIMESTAMP, &tracker);
        assert!(result.is_ok());
        result.unwrap().nonce_guard.commit();
    }

    #[test]
    fn validate_tentatively_records_nonce() {
        // validate_reset_request atomically records the nonce to prevent
        // TOCTOU replay. Second call with same nonce must be rejected.
        let tracker = ResetRequestNonceTracker::with_default_ttl();
        let nonce = [0xCC; 16];
        let request = make_test_request(nonce, BASE_TIMESTAMP);

        // First validation succeeds — nonce tentatively recorded.
        let result = validate_reset_request(&request, BASE_TIMESTAMP + 1, &tracker);
        assert!(result.is_ok());
        result.unwrap().nonce_guard.commit();

        // Second validation with same nonce is rejected (nonce already recorded).
        let result = validate_reset_request(&request, BASE_TIMESTAMP + 2, &tracker);
        assert!(matches!(
            result,
            Err(WeeksOfflineError::ReplayedResetRequest { .. })
        ));
    }

    #[test]
    fn validate_rollback_allows_retry() {
        // If signature verification fails, dropping the ValidatedResetRequest
        // (which drops the NonceGuard) auto-rolls-back the nonce so the
        // legitimate request can still succeed.
        let tracker = ResetRequestNonceTracker::with_default_ttl();
        let nonce = [0xCC; 16];
        let request = make_test_request(nonce, BASE_TIMESTAMP);

        // First validation succeeds — nonce tentatively recorded.
        let result = validate_reset_request(&request, BASE_TIMESTAMP + 1, &tracker);
        assert!(result.is_ok());

        // Simulate signature verification failure — drop without committing.
        // The NonceGuard's Drop impl rolls back the nonce automatically.
        drop(result);

        // Same nonce can now be accepted again (legitimate request).
        let result = validate_reset_request(&request, BASE_TIMESTAMP + 2, &tracker);
        assert!(result.is_ok());
        result.unwrap().nonce_guard.commit();
    }

    #[test]
    fn reset_request_new_generates_random_nonce() {
        let r1 = ResetRequest::new(
            "ctx-test".to_owned(),
            DID::from("did:dht:z6MkBob"),
            100,
            ResetReason::ExtendedOffline {
                offline_duration_secs: EIGHT_DAYS_SECS,
            },
            BASE_TIMESTAMP,
        );
        let r2 = ResetRequest::new(
            "ctx-test".to_owned(),
            DID::from("did:dht:z6MkBob"),
            100,
            ResetReason::ExtendedOffline {
                offline_duration_secs: EIGHT_DAYS_SECS,
            },
            BASE_TIMESTAMP,
        );
        // Nonces must differ (CSPRNG).
        assert_ne!(r1.nonce, r2.nonce);
        // Signature must be empty (caller signs after construction).
        assert!(r1.signature.is_empty());
        // Other fields match inputs.
        assert_eq!(r1.context_id, "ctx-test");
        assert_eq!(r1.member_did.as_ref(), "did:dht:z6MkBob");
        assert_eq!(r1.last_known_epoch, 100);
        assert_eq!(r1.timestamp, BASE_TIMESTAMP);
    }

    #[test]
    fn tentative_record_blocks_concurrent_replay() {
        let tracker = ResetRequestNonceTracker::with_default_ttl();
        let nonce = [0xDD; 16];
        let did = "did:dht:z6MkAlice";

        // First call succeeds and records the nonce atomically.
        let guard = tracker.check_and_tentatively_record(did, &nonce, BASE_TIMESTAMP);
        assert!(guard.is_some());

        // Second call with same nonce is rejected — no TOCTOU window.
        // (guard is still alive, nonce is tentatively recorded)
        assert!(
            tracker
                .check_and_tentatively_record(did, &nonce, BASE_TIMESTAMP + 1)
                .is_none()
        );

        guard.unwrap().commit();
    }

    #[test]
    fn guard_drop_rolls_back_nonce() {
        // NonceGuard's Drop impl rolls back the nonce when not committed.
        let tracker = ResetRequestNonceTracker::with_default_ttl();
        let nonce = [0xDD; 16];
        let did = "did:dht:z6MkAlice";

        // Tentatively record, then drop without committing.
        let guard = tracker.check_and_tentatively_record(did, &nonce, BASE_TIMESTAMP);
        assert!(guard.is_some());
        drop(guard); // triggers rollback

        // Nonce slot is available again.
        let guard = tracker.check_and_tentatively_record(did, &nonce, BASE_TIMESTAMP + 1);
        assert!(guard.is_some());
        guard.unwrap().commit();
    }

    #[test]
    fn guard_commit_prevents_rollback() {
        // Committing a NonceGuard prevents rollback on drop.
        let tracker = ResetRequestNonceTracker::with_default_ttl();
        let nonce = [0xDD; 16];
        let did = "did:dht:z6MkAlice";

        // Tentatively record and commit.
        let guard = tracker.check_and_tentatively_record(did, &nonce, BASE_TIMESTAMP);
        assert!(guard.is_some());
        guard.unwrap().commit(); // nonce stays recorded

        // Nonce is still recorded — second attempt is rejected.
        assert!(
            tracker
                .check_and_tentatively_record(did, &nonce, BASE_TIMESTAMP + 1)
                .is_none()
        );
    }

    // -----------------------------------------------------------------------
    // Anti-replay error Display tests
    // -----------------------------------------------------------------------

    #[test]
    fn error_display_stale_reset_request() {
        let err = WeeksOfflineError::StaleResetRequest {
            context_id: "ctx-1".to_owned(),
            age_secs: 45,
            max_age_secs: 30,
        };
        let msg = err.to_string();
        assert!(msg.contains("ctx-1"));
        assert!(msg.contains("45s"));
        assert!(msg.contains("30s"));
    }

    #[test]
    fn error_display_replayed_reset_request() {
        let err = WeeksOfflineError::ReplayedResetRequest {
            context_id: "ctx-2".to_owned(),
            nonce: [0xAB; 16],
        };
        let msg = err.to_string();
        assert!(msg.contains("ctx-2"));
        assert!(msg.contains("nonce already seen"));
    }
}
