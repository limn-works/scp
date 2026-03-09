//! UCAN token revocation for SCP.
//!
//! Implements the per-context [`RevocationList`] and [`revoke_ucan`] function
//! specified by ADR-016 in `.docs/adrs/phase-3.md`. Revocations are distributed
//! as MLS application messages so all members maintain consistent revocation
//! lists. The revocation list is append-only: once a token CID is revoked, it
//! cannot be un-revoked.
//!
//! # Revocation states
//!
//! Each token tracked by the revocation list is in one of three states:
//!
//! - [`RevocationState::Active`] -- Not revoked. This is the default state and
//!   is not stored explicitly (absence from the map means Active).
//! - [`RevocationState::RevocationPending`] -- Revocation has been initiated
//!   locally but MLS distribution has not yet succeeded. Capability exercise
//!   is **denied** in this state (fail-closed).
//! - [`RevocationState::Revoked`] -- Revocation is fully committed: the token
//!   has been revoked locally and the revocation has been distributed to all
//!   context members via MLS.
//!
//! The [`revoke_ucan`] function is transactional: if MLS distribution fails,
//! the local revocation is rolled back so there is no split-brain between the
//! revoker and other context members.
//!
//! # Propagation confirmation and bounding
//!
//! The [`PropagationTracker`] solves the propagation window problem (issue #72):
//! between local revocation and MLS distribution completing, revoked tokens
//! remain valid on some members. The tracker provides:
//!
//! - **TTL-bounded propagation** -- Each revocation carries a deadline. If the
//!   deadline expires before all members acknowledge, the propagation is flagged
//!   as timed out via [`PropagationStatus::TimedOut`].
//! - **Acknowledgment tracking** -- Members send [`RevocationAck`] messages back
//!   to the revoker confirming receipt. The revoker tracks per-member ack state.
//! - **Bounded retry** -- The distributor can retry delivery to members that have
//!   not yet acknowledged, up to a configurable maximum retry count.
//!
//! # Types
//!
//! - [`RevocationList`] -- Per-context set of revoked token CIDs with merge
//!   support for MLS-distributed synchronization.
//! - [`RevocationState`] -- Per-token revocation state.
//! - [`RevocationRecord`] -- Metadata for a revocation: timestamp, TTL, revoker.
//! - [`RevocationAck`] -- Acknowledgment from a member confirming receipt.
//! - [`PropagationTracker`] -- Tracks propagation status per revocation.
//! - [`PropagationStatus`] -- Summary of propagation state.
//!
//! # Traits
//!
//! - [`RevocationDistributor`] -- Abstraction for distributing revocations via
//!   MLS application messages.
//! - [`RevocationEventLogger`] -- Abstraction for appending `TokenRevoked`
//!   events to the context's event log.
//! - [`RevocationAuthorizer`] -- Abstraction for verifying that a revoker is
//!   authorized (must be the token's issuer or the context creator).
//!
//! See ADR-016 acceptance criterion 5 and 7.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::UcanError;
use scp_event_log::ContextId;

/// Default TTL for revocation propagation: 30 seconds.
///
/// This bounds the window during which revoked tokens may remain valid on
/// members that have not yet received the revocation message. After this
/// period, the propagation is flagged as timed out, signaling that the
/// revoker should escalate (e.g., force key rotation, remove member).
pub const DEFAULT_REVOCATION_TTL_SECS: u64 = 30;

/// Maximum number of retry attempts for revocation distribution to a single
/// member before giving up.
pub const MAX_DISTRIBUTION_RETRIES: u32 = 3;

// ---------------------------------------------------------------------------
// RevocationState
// ---------------------------------------------------------------------------

/// Per-token revocation state.
///
/// Tokens progress through these states during the revocation flow:
///
/// ```text
/// Active -> RevocationPending -> Revoked
///                |
///                +-> Active (on distribution failure -- rollback)
/// ```
///
/// Both `RevocationPending` and `Revoked` are treated as revoked for
/// capability validation purposes (fail-closed). This ensures that a token
/// cannot be exercised during the propagation window between local revocation
/// and MLS distribution completing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RevocationState {
    /// The token has not been revoked. This state is implicit -- tokens not
    /// present in the revocation list are considered Active.
    Active,
    /// Revocation has been initiated locally but MLS distribution has not yet
    /// succeeded. Capability exercise is denied in this state.
    RevocationPending,
    /// Revocation is fully committed: local revocation + MLS distribution.
    Revoked,
}

// ---------------------------------------------------------------------------
// RevocationRecord
// ---------------------------------------------------------------------------

/// Metadata for a single revocation entry.
///
/// Captures when the revocation was initiated, the propagation deadline, the
/// revoker's identity, and how many distribution attempts have been made.
/// This enables the [`PropagationTracker`] to bound the propagation window
/// and detect stale/timed-out revocations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationRecord {
    /// The revoked token's content-hash CID.
    pub token_cid: String,
    /// Unix timestamp (seconds) when the revocation was initiated.
    pub revoked_at: u64,
    /// Unix timestamp (seconds) deadline for propagation to complete.
    /// Computed as `revoked_at + ttl_secs`.
    pub deadline: u64,
    /// DID of the entity that initiated the revocation.
    pub revoker_did: String,
    /// Number of distribution attempts made so far.
    pub retry_count: u32,
}

// ---------------------------------------------------------------------------
// RevocationAck
// ---------------------------------------------------------------------------

/// Acknowledgment from a context member confirming receipt of a revocation.
///
/// Members send this back to the revoker (via MLS application message) after
/// applying a revocation to their local revocation list. The revoker uses
/// these to track propagation completion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationAck {
    /// The revoked token's CID being acknowledged.
    pub token_cid: String,
    /// DID of the member sending the acknowledgment.
    pub member_did: String,
    /// Unix timestamp (seconds) when the member applied the revocation.
    pub acked_at: u64,
}

// ---------------------------------------------------------------------------
// PropagationStatus
// ---------------------------------------------------------------------------

/// Summary of revocation propagation state.
///
/// Returned by [`PropagationTracker::status`] to describe the current
/// propagation state of a specific revocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PropagationStatus {
    /// All expected members have acknowledged the revocation.
    FullyPropagated,
    /// Propagation is still in progress: some members have not acknowledged
    /// yet, but the deadline has not expired.
    InProgress {
        /// DIDs of members that have not yet acknowledged.
        pending_members: Vec<String>,
        /// Seconds remaining until the deadline.
        remaining_secs: u64,
    },
    /// The propagation deadline has expired and some members have not
    /// acknowledged. The revoker should escalate (e.g., force key rotation).
    TimedOut {
        /// DIDs of members that did not acknowledge before the deadline.
        unacked_members: Vec<String>,
    },
    /// No propagation tracking exists for this token CID.
    Unknown,
}

// ---------------------------------------------------------------------------
// PropagationTracker
// ---------------------------------------------------------------------------

/// Tracks per-revocation propagation status across context members.
///
/// The tracker maintains a record of each revocation and which members have
/// acknowledged it. It supports:
///
/// - **Deadline enforcement** -- each revocation has a TTL-bounded deadline.
/// - **Acknowledgment recording** -- members confirm receipt.
/// - **Status queries** -- the revoker can check if propagation is complete,
///   in progress, or timed out.
/// - **Retry tracking** -- counts distribution attempts per revocation.
///
/// This addresses the propagation window gap identified in issue #72.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropagationTracker {
    /// Map of token CID to its revocation record.
    records: HashMap<String, RevocationRecord>,
    /// Map of token CID to set of member DIDs that have acknowledged.
    acks: HashMap<String, HashSet<String>>,
    /// Set of all expected member DIDs in the context (excluding the revoker).
    expected_members: HashSet<String>,
    /// The context this tracker belongs to.
    context_id: ContextId,
}

impl PropagationTracker {
    /// Creates a new propagation tracker for the given context.
    ///
    /// `expected_members` should contain the DIDs of all context members
    /// (excluding the revoker) who need to receive the revocation.
    #[must_use]
    pub fn new(context_id: ContextId, expected_members: HashSet<String>) -> Self {
        Self {
            records: HashMap::new(),
            acks: HashMap::new(),
            expected_members,
            context_id,
        }
    }

    /// Returns the context ID this tracker belongs to.
    #[must_use]
    pub fn context_id(&self) -> &str {
        &self.context_id
    }

    /// Begins tracking a new revocation.
    ///
    /// Records the revocation metadata and initializes the acknowledgment set.
    /// The deadline is computed as `now + ttl_secs`.
    pub fn track_revocation(
        &mut self,
        token_cid: String,
        revoker_did: String,
        now: u64,
        ttl_secs: u64,
    ) {
        let record = RevocationRecord {
            token_cid: token_cid.clone(),
            revoked_at: now,
            deadline: now.saturating_add(ttl_secs),
            revoker_did,
            retry_count: 1,
        };
        self.records.insert(token_cid.clone(), record);
        self.acks.insert(token_cid, HashSet::new());
    }

    /// Records an acknowledgment from a member.
    ///
    /// Returns `true` if this was a new acknowledgment (not a duplicate).
    /// Returns `false` if the member already acknowledged or the token CID
    /// is not being tracked.
    pub fn record_ack(&mut self, ack: &RevocationAck) -> bool {
        self.acks
            .get_mut(&ack.token_cid)
            .is_some_and(|ack_set| ack_set.insert(ack.member_did.clone()))
    }

    /// Returns the current propagation status for a revocation.
    ///
    /// `now` is the current Unix timestamp in seconds, used to determine
    /// whether the deadline has expired.
    #[must_use]
    pub fn status(&self, token_cid: &str, now: u64) -> PropagationStatus {
        let Some(record) = self.records.get(token_cid) else {
            return PropagationStatus::Unknown;
        };

        let acked = self.acks.get(token_cid).cloned().unwrap_or_default();

        let pending: Vec<String> = self
            .expected_members
            .iter()
            .filter(|m| !acked.contains(*m) && **m != record.revoker_did)
            .cloned()
            .collect();

        if pending.is_empty() {
            PropagationStatus::FullyPropagated
        } else if now >= record.deadline {
            PropagationStatus::TimedOut {
                unacked_members: pending,
            }
        } else {
            PropagationStatus::InProgress {
                pending_members: pending,
                remaining_secs: record.deadline.saturating_sub(now),
            }
        }
    }

    /// Returns the set of member DIDs that have not yet acknowledged a
    /// revocation. Returns an empty set if the token CID is not tracked.
    #[must_use]
    pub fn unacked_members(&self, token_cid: &str) -> Vec<String> {
        let Some(record) = self.records.get(token_cid) else {
            return Vec::new();
        };
        let acked = self.acks.get(token_cid).cloned().unwrap_or_default();
        self.expected_members
            .iter()
            .filter(|m| !acked.contains(*m) && **m != record.revoker_did)
            .cloned()
            .collect()
    }

    /// Increments the retry count for a revocation and returns the new count.
    ///
    /// Returns `None` if the token CID is not being tracked.
    pub fn increment_retry(&mut self, token_cid: &str) -> Option<u32> {
        self.records.get_mut(token_cid).map(|r| {
            r.retry_count = r.retry_count.saturating_add(1);
            r.retry_count
        })
    }

    /// Returns `true` if the retry count for the given revocation has reached
    /// or exceeded [`MAX_DISTRIBUTION_RETRIES`].
    #[must_use]
    pub fn retries_exhausted(&self, token_cid: &str) -> bool {
        self.records
            .get(token_cid)
            .is_some_and(|r| r.retry_count >= MAX_DISTRIBUTION_RETRIES)
    }

    /// Returns the revocation record for a token CID, if tracked.
    #[must_use]
    pub fn record(&self, token_cid: &str) -> Option<&RevocationRecord> {
        self.records.get(token_cid)
    }

    /// Returns `true` if propagation tracking has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Returns the number of revocations being tracked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Updates the expected member set (e.g., after a member joins or leaves).
    pub fn set_expected_members(&mut self, members: HashSet<String>) {
        self.expected_members = members;
    }

    /// Removes tracking for a fully-propagated or abandoned revocation.
    ///
    /// Returns `true` if an entry was removed.
    pub fn remove(&mut self, token_cid: &str) -> bool {
        let removed_record = self.records.remove(token_cid).is_some();
        self.acks.remove(token_cid);
        removed_record
    }

    /// Returns all token CIDs whose propagation deadline has expired and
    /// still have unacknowledged members.
    #[must_use]
    pub fn timed_out_revocations(&self, now: u64) -> Vec<String> {
        self.records
            .iter()
            .filter(|(cid, record)| {
                now >= record.deadline && {
                    let acked = self.acks.get(*cid).cloned().unwrap_or_default();
                    self.expected_members
                        .iter()
                        .any(|m| !acked.contains(m) && *m != record.revoker_did)
                }
            })
            .map(|(cid, _)| cid.clone())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// RevocationList
// ---------------------------------------------------------------------------

/// Per-context revocation list tracking revoked UCAN token CIDs.
///
/// Revocations are append-only: once a token CID is added via [`revoke`], it
/// cannot be removed. The [`merge`] operation performs a set union with a remote
/// revocation list, preserving the append-only invariant.
///
/// Revocation lists are distributed to all context members as MLS application
/// messages. Each member maintains their own copy and merges incoming lists to
/// stay consistent.
///
/// See ADR-016 acceptance criterion 7.
///
/// [`revoke`]: RevocationList::revoke
/// [`merge`]: RevocationList::merge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationList {
    /// Map of token CIDs to their revocation state. Absence means Active.
    revoked: HashMap<String, RevocationState>,
    /// The context this revocation list belongs to.
    context_id: ContextId,
}

impl RevocationList {
    /// Creates a new empty revocation list for the given context.
    #[must_use]
    pub fn new(context_id: ContextId) -> Self {
        Self {
            revoked: HashMap::new(),
            context_id,
        }
    }

    /// Returns the context ID this revocation list belongs to.
    #[must_use]
    pub fn context_id(&self) -> &str {
        &self.context_id
    }

    /// Returns `true` if the given token CID is in a revoked state.
    ///
    /// Both `RevocationPending` and `Revoked` return `true` (fail-closed).
    #[must_use]
    pub fn is_revoked(&self, token_cid: &str) -> bool {
        matches!(
            self.revoked.get(token_cid),
            Some(RevocationState::RevocationPending | RevocationState::Revoked)
        )
    }

    /// Returns the [`RevocationState`] for a token CID.
    #[must_use]
    pub fn state(&self, token_cid: &str) -> RevocationState {
        self.revoked
            .get(token_cid)
            .copied()
            .unwrap_or(RevocationState::Active)
    }

    /// Adds a token CID as fully [`Revoked`](RevocationState::Revoked).
    pub fn revoke(&mut self, token_cid: String) {
        self.revoked.insert(token_cid, RevocationState::Revoked);
    }

    /// Marks a token CID as [`RevocationPending`](RevocationState::RevocationPending).
    pub fn mark_pending(&mut self, token_cid: String) {
        if self.revoked.get(&token_cid) == Some(&RevocationState::Revoked) {
            return;
        }
        self.revoked
            .insert(token_cid, RevocationState::RevocationPending);
    }

    /// Transitions a pending entry to Revoked.
    pub fn confirm_revocation(&mut self, token_cid: &str) {
        if self.revoked.get(token_cid) == Some(&RevocationState::RevocationPending) {
            self.revoked
                .insert(token_cid.to_owned(), RevocationState::Revoked);
        }
    }

    /// Removes a pending entry (rollback to Active).
    pub fn rollback_revocation(&mut self, token_cid: &str) {
        if self.revoked.get(token_cid) == Some(&RevocationState::RevocationPending) {
            self.revoked.remove(token_cid);
        }
    }

    /// Merges a remote revocation list into this one.
    ///
    /// The merge is a set union: all CIDs from the remote list are added to
    /// this list. This preserves the append-only invariant -- a token cannot
    /// be un-revoked through a merge. Both lists must belong to the same
    /// context; if they do not, this is a no-op to prevent cross-context
    /// contamination.
    ///
    /// # Arguments
    ///
    /// * `remote` - The remote revocation list received via MLS application
    ///   message.
    pub fn merge(&mut self, remote: &Self) {
        if self.context_id != remote.context_id {
            return;
        }
        for (cid, remote_state) in &remote.revoked {
            let local_state = self.revoked.get(cid).copied();
            match (local_state, remote_state) {
                (_, RevocationState::Revoked) => {
                    self.revoked.insert(cid.clone(), RevocationState::Revoked);
                }
                (None | Some(RevocationState::Active), RevocationState::RevocationPending) => {
                    self.revoked
                        .insert(cid.clone(), RevocationState::RevocationPending);
                }
                _ => {}
            }
        }
    }

    /// Returns the number of revoked token CIDs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.revoked.len()
    }

    /// Returns `true` if the revocation list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.revoked.is_empty()
    }

    /// Returns an iterator over the revoked token CIDs.
    ///
    /// The iteration order is not guaranteed.
    pub fn iter(&self) -> impl Iterator<Item = &String> {
        self.revoked.keys()
    }
}

impl PartialEq for RevocationList {
    fn eq(&self, other: &Self) -> bool {
        self.context_id == other.context_id && self.revoked == other.revoked
    }
}

impl Eq for RevocationList {}

// ---------------------------------------------------------------------------
// Trait abstractions for revoke_ucan dependencies
// ---------------------------------------------------------------------------

/// Abstraction for verifying that a revoker is authorized to revoke a token.
///
/// The revoker must be either the token's issuer or the context creator.
/// Implementations look up the token by CID to find its issuer, and check
/// whether the revoker DID matches the issuer or the context creator DID.
pub trait RevocationAuthorizer {
    /// Checks whether `revoker_did` is authorized to revoke `token_cid`.
    ///
    /// # Errors
    ///
    /// Returns [`UcanError::RevocationUnauthorized`] if the revoker is neither
    /// the token's issuer nor the context creator.
    /// Returns [`UcanError::RevocationFailed`] if the token CID cannot be
    /// resolved.
    fn authorize_revocation(&self, token_cid: &str, revoker_did: &str) -> Result<(), UcanError>;
}

/// Abstraction for distributing revocations via MLS application messages.
///
/// Implementations broadcast the serialized revocation list (or the revoked
/// CID) to all context members through the MLS group's application message
/// channel.
pub trait RevocationDistributor {
    /// Distributes a revocation to all members of the context.
    ///
    /// # Errors
    ///
    /// Returns [`UcanError::RevocationFailed`] if distribution fails.
    fn distribute_revocation(&self, context_id: &str, token_cid: &str) -> Result<(), UcanError>;
}

/// Abstraction for appending events to the context's event log.
///
/// Implementations append a `TokenRevoked` event to the context's Merkle tree
/// event log with the appropriate actor DID and payload.
pub trait RevocationEventLogger {
    /// Appends a `TokenRevoked` event for the given token CID and revoker.
    ///
    /// # Errors
    ///
    /// Returns [`UcanError::RevocationFailed`] if the event log append fails.
    fn log_token_revoked(
        &self,
        context_id: &str,
        token_cid: &str,
        revoker_did: &str,
    ) -> Result<(), UcanError>;
}

// ---------------------------------------------------------------------------
// Revocation CID computation
// ---------------------------------------------------------------------------

/// Computes a revocation CID as the hex-encoded SHA-256 hash of the raw
/// encoded JWT string (`header.payload.signature`).
///
/// The raw JWT string is the canonical form: it is the exact bytes that were
/// signed, transmitted, and stored. Hashing the raw JWT avoids the
/// non-canonical serialization problem that arises from deserializing a
/// payload and re-serializing it (e.g., `serde_json::to_vec` may produce
/// different key orderings for `serde_json::Value` fields across platforms).
///
/// This produces a fixed-length 64-character lowercase hex string regardless
/// of token size.
///
/// # Arguments
///
/// * `encoded_token` - The full JWT string in `header.payload.signature` form.
#[must_use]
pub fn compute_revocation_cid(encoded_token: &str) -> String {
    let hash = Sha256::digest(encoded_token.as_bytes());
    hash.iter().fold(String::with_capacity(64), |mut acc, b| {
        use std::fmt::Write;
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

// ---------------------------------------------------------------------------
// revoke_ucan
// ---------------------------------------------------------------------------

/// Revokes a UCAN token within a context.
///
/// Computes the revocation CID as the hex-encoded SHA-256 hash of the
/// raw encoded JWT string, then performs the full revocation flow
/// specified by ADR-016 acceptance criterion 5:
///
/// 1. **CID computation** -- Computes the content-hash CID from the raw
///    encoded token via [`compute_revocation_cid`].
/// 2. **Authorization** -- Verifies the revoker is the token's issuer or the
///    context creator via [`RevocationAuthorizer`].
/// 3. **Revocation** -- Adds the token CID to the context's
///    [`RevocationList`].
/// 4. **Distribution** -- Broadcasts the revocation to all context members as
///    an MLS application message via [`RevocationDistributor`].
/// 5. **Event logging** -- Appends a `TokenRevoked` event to the context's
///    event log via [`RevocationEventLogger`].
///
/// # Arguments
///
/// * `revocation_list` - The context's mutable revocation list.
/// * `encoded_token` - The full JWT string (`header.payload.signature`),
///   used to compute the revocation CID.
/// * `revoker_did` - The DID of the entity requesting the revocation.
/// * `authorizer` - Verifies the revoker is authorized.
/// * `distributor` - Distributes the revocation to context members.
/// * `event_logger` - Appends the `TokenRevoked` event.
///
/// # Returns
///
/// Returns the computed revocation CID on success.
///
/// # Errors
///
/// Returns [`UcanError::RevocationUnauthorized`] if the revoker is not
/// authorized.
/// Returns [`UcanError::RevocationFailed`] if distribution or logging fails.
///
/// See ADR-016 acceptance criterion 5.
pub fn revoke_ucan(
    revocation_list: &mut RevocationList,
    encoded_token: &str,
    revoker_did: &str,
    authorizer: &impl RevocationAuthorizer,
    distributor: &impl RevocationDistributor,
    event_logger: &impl RevocationEventLogger,
) -> Result<String, UcanError> {
    // Step 1: Compute content-hash CID from the raw encoded JWT.
    let token_cid = compute_revocation_cid(encoded_token);

    // Step 2: Verify authorization.
    authorizer.authorize_revocation(&token_cid, revoker_did)?;

    // Step 3: Mark as RevocationPending (fail-closed).
    revocation_list.mark_pending(token_cid.clone());

    // Step 4: Distribute via MLS. On failure, roll back.
    let context_id = revocation_list.context_id().to_owned();
    if let Err(e) = distributor.distribute_revocation(&context_id, &token_cid) {
        revocation_list.rollback_revocation(&token_cid);
        return Err(e);
    }

    // Step 5: Commit -- Pending to Revoked.
    revocation_list.confirm_revocation(&token_cid);

    // Step 6: Append TokenRevoked event.
    event_logger.log_token_revoked(&context_id, &token_cid, revoker_did)?;

    Ok(token_cid)
}

// ---------------------------------------------------------------------------
// Distribution retry helper
// ---------------------------------------------------------------------------

/// Attempts to distribute a revocation with bounded retry.
///
/// Makes up to [`MAX_DISTRIBUTION_RETRIES`] attempts, incrementing the retry
/// count in the tracker after the first attempt. Returns `Ok(())` on the first
/// successful attempt, or the last error after all attempts are exhausted.
fn distribute_with_retry(
    context_id: &str,
    token_cid: &str,
    distributor: &impl RevocationDistributor,
    tracker: &mut PropagationTracker,
) -> Result<(), UcanError> {
    let mut last_err =
        UcanError::RevocationFailed("distribution failed after all retries".to_owned());

    for attempt in 0..MAX_DISTRIBUTION_RETRIES {
        if attempt > 0 {
            tracker.increment_retry(token_cid);
        }
        match distributor.distribute_revocation(context_id, token_cid) {
            Ok(()) => return Ok(()),
            Err(e) => last_err = e,
        }
    }

    Err(last_err)
}

// ---------------------------------------------------------------------------
// PropagationConfig
// ---------------------------------------------------------------------------

/// Configuration for TTL-bounded revocation propagation.
///
/// Bundles the timing parameters needed by [`revoke_ucan_with_propagation`]
/// to track and bound the revocation propagation window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PropagationConfig {
    /// Current Unix timestamp in seconds.
    pub now: u64,
    /// Propagation deadline in seconds from `now`. After `now + ttl_secs`,
    /// unacknowledged members are flagged as timed out.
    pub ttl_secs: u64,
}

impl PropagationConfig {
    /// Creates a new propagation config with the given timestamp and TTL.
    #[must_use]
    pub const fn new(now: u64, ttl_secs: u64) -> Self {
        Self { now, ttl_secs }
    }

    /// Creates a propagation config with the default TTL
    /// ([`DEFAULT_REVOCATION_TTL_SECS`]).
    #[must_use]
    pub const fn with_default_ttl(now: u64) -> Self {
        Self {
            now,
            ttl_secs: DEFAULT_REVOCATION_TTL_SECS,
        }
    }
}

// ---------------------------------------------------------------------------
// revoke_ucan_with_propagation
// ---------------------------------------------------------------------------

/// Revokes a UCAN token with propagation tracking and bounded retry.
///
/// This extends [`revoke_ucan`] with confirmation and bounding mechanisms
/// for the propagation window (issue #72). In addition to the base revocation
/// flow, this function:
///
/// 1. Registers the revocation with the [`PropagationTracker`], recording the
///    current timestamp and TTL-bounded deadline.
/// 2. On initial distribution failure, retries up to [`MAX_DISTRIBUTION_RETRIES`]
///    times before rolling back.
/// 3. Returns the token CID on success; the caller should poll
///    [`PropagationTracker::status`] to confirm full propagation.
///
/// # Arguments
///
/// * `revocation_list` - The context's mutable revocation list.
/// * `tracker` - The context's mutable propagation tracker.
/// * `encoded_token` - The full JWT string (`header.payload.signature`),
///   used to compute the revocation CID.
/// * `revoker_did` - The DID of the entity requesting the revocation.
/// * `authorizer` - Verifies the revoker is authorized.
/// * `distributor` - Distributes the revocation to context members.
/// * `event_logger` - Appends the `TokenRevoked` event.
/// * `config` - Propagation timing configuration (timestamp and TTL).
///
/// # Returns
///
/// Returns the computed revocation CID on success. The caller should use
/// [`PropagationTracker::status`] to check whether all members have
/// acknowledged the revocation before the deadline.
///
/// # Errors
///
/// Returns [`UcanError::RevocationUnauthorized`] if the revoker is not
/// authorized.
/// Returns [`UcanError::RevocationFailed`] if distribution fails after all
/// retry attempts, or if logging fails.
#[allow(clippy::too_many_arguments)] // Revocation flow requires all 8 parameters: mutable state (2), token data (1), trait deps (3), config (1).
pub fn revoke_ucan_with_propagation(
    revocation_list: &mut RevocationList,
    tracker: &mut PropagationTracker,
    encoded_token: &str,
    revoker_did: &str,
    authorizer: &impl RevocationAuthorizer,
    distributor: &impl RevocationDistributor,
    event_logger: &impl RevocationEventLogger,
    config: PropagationConfig,
) -> Result<String, UcanError> {
    // Step 1: Compute content-hash CID from the raw encoded JWT.
    let token_cid = compute_revocation_cid(encoded_token);

    // Step 2: Verify authorization.
    authorizer.authorize_revocation(&token_cid, revoker_did)?;

    // Step 3: Mark as RevocationPending (fail-closed).
    revocation_list.mark_pending(token_cid.clone());

    // Step 4: Register with propagation tracker.
    tracker.track_revocation(
        token_cid.clone(),
        revoker_did.to_owned(),
        config.now,
        config.ttl_secs,
    );

    // Step 5: Distribute via MLS with bounded retry.
    let context_id = revocation_list.context_id().to_owned();
    let distribution_result = distribute_with_retry(&context_id, &token_cid, distributor, tracker);

    if let Err(e) = distribution_result {
        // All retries exhausted. Roll back.
        revocation_list.rollback_revocation(&token_cid);
        tracker.remove(&token_cid);
        return Err(e);
    }

    // Step 6: Commit -- Pending to Revoked.
    revocation_list.confirm_revocation(&token_cid);

    // Step 7: Append TokenRevoked event.
    event_logger.log_token_revoked(&context_id, &token_cid, revoker_did)?;

    Ok(token_cid)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    /// A mock authorizer that approves specific revoker DIDs.
    struct MockAuthorizer {
        /// The token issuer DID.
        issuer_did: String,
        /// The context creator DID.
        creator_did: String,
    }

    impl RevocationAuthorizer for MockAuthorizer {
        fn authorize_revocation(
            &self,
            _token_cid: &str,
            revoker_did: &str,
        ) -> Result<(), UcanError> {
            if revoker_did == self.issuer_did || revoker_did == self.creator_did {
                Ok(())
            } else {
                Err(UcanError::RevocationUnauthorized(format!(
                    "revoker {revoker_did} is neither the issuer nor the context creator"
                )))
            }
        }
    }

    /// A mock authorizer that always rejects.
    struct RejectingAuthorizer;

    impl RevocationAuthorizer for RejectingAuthorizer {
        fn authorize_revocation(
            &self,
            _token_cid: &str,
            revoker_did: &str,
        ) -> Result<(), UcanError> {
            Err(UcanError::RevocationUnauthorized(format!(
                "{revoker_did} is not authorized"
            )))
        }
    }

    /// A mock distributor that records distributed revocations.
    struct MockDistributor {
        distributed: RefCell<Vec<(String, String)>>,
    }

    impl MockDistributor {
        fn new() -> Self {
            Self {
                distributed: RefCell::new(Vec::new()),
            }
        }
    }

    impl RevocationDistributor for MockDistributor {
        fn distribute_revocation(
            &self,
            context_id: &str,
            token_cid: &str,
        ) -> Result<(), UcanError> {
            self.distributed
                .borrow_mut()
                .push((context_id.to_owned(), token_cid.to_owned()));
            Ok(())
        }
    }

    /// A mock distributor that always fails.
    struct FailingDistributor;

    impl RevocationDistributor for FailingDistributor {
        fn distribute_revocation(
            &self,
            _context_id: &str,
            _token_cid: &str,
        ) -> Result<(), UcanError> {
            Err(UcanError::RevocationFailed(
                "MLS distribution failed".to_owned(),
            ))
        }
    }

    /// A mock event logger that records logged events.
    struct MockEventLogger {
        logged: RefCell<Vec<(String, String, String)>>,
    }

    impl MockEventLogger {
        fn new() -> Self {
            Self {
                logged: RefCell::new(Vec::new()),
            }
        }
    }

    impl RevocationEventLogger for MockEventLogger {
        fn log_token_revoked(
            &self,
            context_id: &str,
            token_cid: &str,
            revoker_did: &str,
        ) -> Result<(), UcanError> {
            self.logged.borrow_mut().push((
                context_id.to_owned(),
                token_cid.to_owned(),
                revoker_did.to_owned(),
            ));
            Ok(())
        }
    }

    /// A mock event logger that always fails.
    struct FailingEventLogger;

    impl RevocationEventLogger for FailingEventLogger {
        fn log_token_revoked(
            &self,
            _context_id: &str,
            _token_cid: &str,
            _revoker_did: &str,
        ) -> Result<(), UcanError> {
            Err(UcanError::RevocationFailed(
                "event log append failed".to_owned(),
            ))
        }
    }

    /// Build a deterministic encoded token string for revocation tests.
    ///
    /// This is a stable fake JWT string (not cryptographically valid, but
    /// deterministic) used to test `compute_revocation_cid` and `revoke_ucan`.
    /// The revocation CID is computed by hashing this string, so it must be
    /// identical across test runs.
    fn test_encoded_token() -> &'static str {
        "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsInVjdiI6IjAuMTAuMCJ9.\
         eyJpc3MiOiJkaWQ6ZGh0Ono2TWtJc3N1ZXIiLCJhdWQiOiJkaWQ6ZGh0Ono2TWtNZW1iZXIiLCJleHAiOjE3MDAwMDAwMDAsIm5uYyI6IjE2OTk5OTkwMDAwMDAtYWFiYmNjZGQxMTIyMzM0NGFhYmJjY2RkMTEyMjMzNDQiLCJhdHQiOlt7IndpdGgiOiJzY3A6Y3R4OmN0eC0xL21lc3NhZ2VzOndyaXRlIiwiY2FuIjoid3JpdGUifV0sInByZiI6W119.\
         dGVzdC1zaWduYXR1cmUtYnl0ZXM"
    }

    // -----------------------------------------------------------------------
    // RevocationList -- construction
    // -----------------------------------------------------------------------

    #[test]
    fn new_revocation_list_is_empty() {
        let list = RevocationList::new("ctx-1".to_owned());
        assert!(list.is_empty());
        assert_eq!(list.len(), 0);
        assert_eq!(list.context_id(), "ctx-1");
    }

    // -----------------------------------------------------------------------
    // RevocationList -- is_revoked
    // -----------------------------------------------------------------------

    #[test]
    fn is_revoked_returns_false_for_unknown_cid() {
        let list = RevocationList::new("ctx-1".to_owned());
        assert!(!list.is_revoked("bafyreiabc123"));
    }

    #[test]
    fn is_revoked_returns_true_after_revoke() {
        let mut list = RevocationList::new("ctx-1".to_owned());
        list.revoke("bafyreiabc123".to_owned());
        assert!(list.is_revoked("bafyreiabc123"));
    }

    // -----------------------------------------------------------------------
    // RevocationList -- revoke
    // -----------------------------------------------------------------------

    #[test]
    fn revoke_adds_cid_to_list() {
        let mut list = RevocationList::new("ctx-1".to_owned());
        list.revoke("bafyreiabc123".to_owned());
        assert_eq!(list.len(), 1);
        assert!(list.is_revoked("bafyreiabc123"));
    }

    #[test]
    fn revoke_is_idempotent() {
        let mut list = RevocationList::new("ctx-1".to_owned());
        list.revoke("bafyreiabc123".to_owned());
        list.revoke("bafyreiabc123".to_owned());
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn revoke_multiple_distinct_cids() {
        let mut list = RevocationList::new("ctx-1".to_owned());
        list.revoke("bafyrei-a".to_owned());
        list.revoke("bafyrei-b".to_owned());
        list.revoke("bafyrei-c".to_owned());
        assert_eq!(list.len(), 3);
        assert!(list.is_revoked("bafyrei-a"));
        assert!(list.is_revoked("bafyrei-b"));
        assert!(list.is_revoked("bafyrei-c"));
    }

    // -----------------------------------------------------------------------
    // RevocationList -- merge
    // -----------------------------------------------------------------------

    #[test]
    fn merge_unions_two_disjoint_lists() {
        let mut local = RevocationList::new("ctx-1".to_owned());
        local.revoke("cid-a".to_owned());

        let mut remote = RevocationList::new("ctx-1".to_owned());
        remote.revoke("cid-b".to_owned());

        local.merge(&remote);
        assert_eq!(local.len(), 2);
        assert!(local.is_revoked("cid-a"));
        assert!(local.is_revoked("cid-b"));
    }

    #[test]
    fn merge_with_overlapping_cids_produces_union() {
        let mut local = RevocationList::new("ctx-1".to_owned());
        local.revoke("cid-a".to_owned());
        local.revoke("cid-b".to_owned());

        let mut remote = RevocationList::new("ctx-1".to_owned());
        remote.revoke("cid-b".to_owned());
        remote.revoke("cid-c".to_owned());

        local.merge(&remote);
        assert_eq!(local.len(), 3);
        assert!(local.is_revoked("cid-a"));
        assert!(local.is_revoked("cid-b"));
        assert!(local.is_revoked("cid-c"));
    }

    #[test]
    fn merge_with_empty_remote_is_noop() {
        let mut local = RevocationList::new("ctx-1".to_owned());
        local.revoke("cid-a".to_owned());

        let remote = RevocationList::new("ctx-1".to_owned());
        local.merge(&remote);

        assert_eq!(local.len(), 1);
        assert!(local.is_revoked("cid-a"));
    }

    #[test]
    fn merge_into_empty_list_copies_all() {
        let mut local = RevocationList::new("ctx-1".to_owned());

        let mut remote = RevocationList::new("ctx-1".to_owned());
        remote.revoke("cid-a".to_owned());
        remote.revoke("cid-b".to_owned());

        local.merge(&remote);
        assert_eq!(local.len(), 2);
        assert!(local.is_revoked("cid-a"));
        assert!(local.is_revoked("cid-b"));
    }

    #[test]
    fn merge_never_removes_existing_revocations() {
        let mut local = RevocationList::new("ctx-1".to_owned());
        local.revoke("cid-a".to_owned());
        local.revoke("cid-b".to_owned());

        // Remote only has cid-a (no cid-b). Merge should not remove cid-b.
        let mut remote = RevocationList::new("ctx-1".to_owned());
        remote.revoke("cid-a".to_owned());

        local.merge(&remote);
        assert_eq!(local.len(), 2);
        assert!(local.is_revoked("cid-a"));
        assert!(local.is_revoked("cid-b"));
    }

    #[test]
    fn merge_rejects_cross_context_list() {
        let mut local = RevocationList::new("ctx-1".to_owned());
        local.revoke("cid-a".to_owned());

        let mut remote = RevocationList::new("ctx-2".to_owned());
        remote.revoke("cid-b".to_owned());

        local.merge(&remote);
        // cid-b should NOT be added because the contexts differ.
        assert_eq!(local.len(), 1);
        assert!(!local.is_revoked("cid-b"));
    }

    // -----------------------------------------------------------------------
    // RevocationList -- serialization
    // -----------------------------------------------------------------------

    #[test]
    fn serialization_roundtrip_empty() {
        let list = RevocationList::new("ctx-1".to_owned());
        let json = serde_json::to_string(&list).unwrap();
        let deserialized: RevocationList = serde_json::from_str(&json).unwrap();
        assert_eq!(list, deserialized);
    }

    #[test]
    fn serialization_roundtrip_with_entries() {
        let mut list = RevocationList::new("ctx-1".to_owned());
        list.revoke("bafyrei-a".to_owned());
        list.revoke("bafyrei-b".to_owned());
        list.revoke("bafyrei-c".to_owned());

        let json = serde_json::to_string(&list).unwrap();
        let deserialized: RevocationList = serde_json::from_str(&json).unwrap();
        assert_eq!(list, deserialized);
        assert!(deserialized.is_revoked("bafyrei-a"));
        assert!(deserialized.is_revoked("bafyrei-b"));
        assert!(deserialized.is_revoked("bafyrei-c"));
    }

    // -----------------------------------------------------------------------
    // RevocationList -- equality
    // -----------------------------------------------------------------------

    #[test]
    fn equality_same_context_same_entries() {
        let mut a = RevocationList::new("ctx-1".to_owned());
        a.revoke("cid-a".to_owned());

        let mut b = RevocationList::new("ctx-1".to_owned());
        b.revoke("cid-a".to_owned());

        assert_eq!(a, b);
    }

    #[test]
    fn inequality_different_contexts() {
        let mut a = RevocationList::new("ctx-1".to_owned());
        a.revoke("cid-a".to_owned());

        let mut b = RevocationList::new("ctx-2".to_owned());
        b.revoke("cid-a".to_owned());

        assert_ne!(a, b);
    }

    #[test]
    fn inequality_different_entries() {
        let mut a = RevocationList::new("ctx-1".to_owned());
        a.revoke("cid-a".to_owned());

        let mut b = RevocationList::new("ctx-1".to_owned());
        b.revoke("cid-b".to_owned());

        assert_ne!(a, b);
    }

    // -----------------------------------------------------------------------
    // RevocationList -- iterator
    // -----------------------------------------------------------------------

    #[test]
    fn iter_yields_all_revoked_cids() {
        let mut list = RevocationList::new("ctx-1".to_owned());
        list.revoke("cid-a".to_owned());
        list.revoke("cid-b".to_owned());

        let mut cids: Vec<&String> = list.iter().collect();
        cids.sort();
        assert_eq!(cids, vec![&"cid-a".to_owned(), &"cid-b".to_owned()]);
    }

    // -----------------------------------------------------------------------
    // revoke_ucan -- success path
    // -----------------------------------------------------------------------

    #[test]
    fn revoke_ucan_success_as_issuer() {
        let mut list = RevocationList::new("ctx-1".to_owned());
        let authorizer = MockAuthorizer {
            issuer_did: "did:dht:z6MkIssuer".to_owned(),
            creator_did: "did:dht:z6MkCreator".to_owned(),
        };
        let distributor = MockDistributor::new();
        let logger = MockEventLogger::new();
        let encoded = test_encoded_token();
        let expected_cid = compute_revocation_cid(encoded);

        let result = revoke_ucan(
            &mut list,
            encoded,
            "did:dht:z6MkIssuer",
            &authorizer,
            &distributor,
            &logger,
        );

        assert!(result.is_ok());
        let returned_cid = result.unwrap();
        assert_eq!(returned_cid, expected_cid);
        assert!(list.is_revoked(&expected_cid));
        assert_eq!(distributor.distributed.borrow().len(), 1);
        assert_eq!(
            distributor.distributed.borrow()[0],
            ("ctx-1".to_owned(), expected_cid.clone())
        );
        assert_eq!(logger.logged.borrow().len(), 1);
        assert_eq!(
            logger.logged.borrow()[0],
            (
                "ctx-1".to_owned(),
                expected_cid,
                "did:dht:z6MkIssuer".to_owned()
            )
        );
    }

    #[test]
    fn revoke_ucan_success_as_context_creator() {
        let mut list = RevocationList::new("ctx-1".to_owned());
        let authorizer = MockAuthorizer {
            issuer_did: "did:dht:z6MkIssuer".to_owned(),
            creator_did: "did:dht:z6MkCreator".to_owned(),
        };
        let distributor = MockDistributor::new();
        let logger = MockEventLogger::new();
        let encoded = test_encoded_token();
        let expected_cid = compute_revocation_cid(encoded);

        let result = revoke_ucan(
            &mut list,
            encoded,
            "did:dht:z6MkCreator",
            &authorizer,
            &distributor,
            &logger,
        );

        assert!(result.is_ok());
        assert!(list.is_revoked(&expected_cid));
    }

    // -----------------------------------------------------------------------
    // revoke_ucan -- authorization failure
    // -----------------------------------------------------------------------

    #[test]
    fn revoke_ucan_rejects_unauthorized_revoker() {
        let mut list = RevocationList::new("ctx-1".to_owned());
        let authorizer = RejectingAuthorizer;
        let distributor = MockDistributor::new();
        let logger = MockEventLogger::new();
        let encoded = test_encoded_token();
        let expected_cid = compute_revocation_cid(encoded);

        let result = revoke_ucan(
            &mut list,
            encoded,
            "did:dht:z6MkUnauthorized",
            &authorizer,
            &distributor,
            &logger,
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            UcanError::RevocationUnauthorized(_)
        ));
        // Token should NOT be revoked on authorization failure.
        assert!(!list.is_revoked(&expected_cid));
        // Distribution and logging should not have been called.
        assert!(distributor.distributed.borrow().is_empty());
        assert!(logger.logged.borrow().is_empty());
    }

    // -----------------------------------------------------------------------
    // revoke_ucan -- distribution failure
    // -----------------------------------------------------------------------

    #[test]
    fn revoke_ucan_distribution_failure_rolls_back() {
        let mut list = RevocationList::new("ctx-1".to_owned());
        let authorizer = MockAuthorizer {
            issuer_did: "did:dht:z6MkIssuer".to_owned(),
            creator_did: "did:dht:z6MkCreator".to_owned(),
        };
        let distributor = FailingDistributor;
        let logger = MockEventLogger::new();

        let result = revoke_ucan(
            &mut list,
            test_encoded_token(),
            "did:dht:z6MkIssuer",
            &authorizer,
            &distributor,
            &logger,
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            UcanError::RevocationFailed(_)
        ));
        // The token must NOT remain after rollback.
        assert!(!list.is_revoked("bafyrei-token1"));
        assert_eq!(list.state("bafyrei-token1"), RevocationState::Active);
        assert!(list.is_empty());
        assert!(logger.logged.borrow().is_empty());
    }

    // -----------------------------------------------------------------------
    // revoke_ucan -- event logging failure
    // -----------------------------------------------------------------------

    #[test]
    fn revoke_ucan_fails_on_event_log_error() {
        let mut list = RevocationList::new("ctx-1".to_owned());
        let authorizer = MockAuthorizer {
            issuer_did: "did:dht:z6MkIssuer".to_owned(),
            creator_did: "did:dht:z6MkCreator".to_owned(),
        };
        let distributor = MockDistributor::new();
        let logger = FailingEventLogger;

        let result = revoke_ucan(
            &mut list,
            test_encoded_token(),
            "did:dht:z6MkIssuer",
            &authorizer,
            &distributor,
            &logger,
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            UcanError::RevocationFailed(_)
        ));
    }

    // -----------------------------------------------------------------------
    // State transitions and fail-closed behavior
    // -----------------------------------------------------------------------

    #[test]
    fn mark_pending_sets_pending_state() {
        let mut list = RevocationList::new("ctx-1".to_owned());
        list.mark_pending("cid-a".to_owned());
        assert_eq!(list.state("cid-a"), RevocationState::RevocationPending);
        assert!(list.is_revoked("cid-a"));
    }

    #[test]
    fn confirm_transitions_pending_to_revoked() {
        let mut list = RevocationList::new("ctx-1".to_owned());
        list.mark_pending("cid-a".to_owned());
        list.confirm_revocation("cid-a");
        assert_eq!(list.state("cid-a"), RevocationState::Revoked);
    }

    #[test]
    fn rollback_removes_pending_entry() {
        let mut list = RevocationList::new("ctx-1".to_owned());
        list.mark_pending("cid-a".to_owned());
        list.rollback_revocation("cid-a");
        assert!(!list.is_revoked("cid-a"));
        assert!(list.is_empty());
    }

    #[test]
    fn rollback_noop_for_revoked() {
        let mut list = RevocationList::new("ctx-1".to_owned());
        list.revoke("cid-a".to_owned());
        list.rollback_revocation("cid-a");
        assert_eq!(list.state("cid-a"), RevocationState::Revoked);
    }

    #[test]
    fn pending_denies_capability_exercise() {
        let mut list = RevocationList::new("ctx-1".to_owned());
        list.mark_pending("bafyrei-token1".to_owned());
        assert!(list.is_revoked("bafyrei-token1"));
        assert_eq!(
            list.state("bafyrei-token1"),
            RevocationState::RevocationPending
        );
    }

    #[test]
    fn success_path_final_state_is_revoked() {
        let mut list = RevocationList::new("ctx-1".to_owned());
        let authorizer = MockAuthorizer {
            issuer_did: "did:dht:z6MkIssuer".to_owned(),
            creator_did: "did:dht:z6MkCreator".to_owned(),
        };
        let distributor = MockDistributor::new();
        let logger = MockEventLogger::new();
        let encoded = test_encoded_token();
        let expected_cid = compute_revocation_cid(encoded);
        assert_eq!(list.state(&expected_cid), RevocationState::Active);
        revoke_ucan(
            &mut list,
            encoded,
            "did:dht:z6MkIssuer",
            &authorizer,
            &distributor,
            &logger,
        )
        .unwrap();
        assert_eq!(list.state(&expected_cid), RevocationState::Revoked);
    }

    // -----------------------------------------------------------------------
    // compute_revocation_cid -- content hash format
    // -----------------------------------------------------------------------

    #[test]
    fn revocation_cid_is_deterministic() {
        let encoded = test_encoded_token();
        let cid1 = compute_revocation_cid(encoded);
        let cid2 = compute_revocation_cid(encoded);
        assert_eq!(cid1, cid2, "same token must produce same CID");
    }

    #[test]
    fn revocation_cid_is_fixed_length_hex() {
        let encoded = test_encoded_token();
        let cid = compute_revocation_cid(encoded);
        // SHA-256 hex = 64 characters.
        assert_eq!(cid.len(), 64, "revocation CID must be 64 hex chars");
        assert!(
            cid.chars().all(|c| c.is_ascii_hexdigit()),
            "revocation CID must be hex-encoded"
        );
    }

    #[test]
    fn revocation_cid_differs_for_different_tokens() {
        let cid1 = compute_revocation_cid(test_encoded_token());
        let cid2 = compute_revocation_cid("header.different-payload.signature");
        assert_ne!(cid1, cid2, "different tokens must produce different CIDs");
    }

    #[test]
    fn revocation_storage_size_is_bounded_per_entry() {
        // The revocation CID is always 64 hex characters, regardless of
        // the JWT token size. This verifies the CID length is bounded.
        let small_token = test_encoded_token();
        let large_token = format!("header.{}.signature", "x".repeat(10_000));

        let small_cid = compute_revocation_cid(small_token);
        let large_cid = compute_revocation_cid(&large_token);

        // Both CIDs are the same fixed length regardless of token size.
        assert_eq!(small_cid.len(), 64);
        assert_eq!(large_cid.len(), 64);
        assert_ne!(small_cid, large_cid);
    }

    // -----------------------------------------------------------------------
    // compute_revocation_cid -- golden value for cross-bridge consistency
    // -----------------------------------------------------------------------

    /// Golden test: verifies that `compute_revocation_cid` produces a known,
    /// stable CID for a fixed encoded JWT string. This value serves as the
    /// canonical reference for cross-bridge consistency tests.
    ///
    /// All bridge implementations (`PyO3`, NAPI, WASM) must produce this exact
    /// CID when computing the revocation CID for the same encoded token. The
    /// WASM bridge re-implements this function locally (cannot depend on
    /// scp-core due to tokio incompatibility), so the golden value guards
    /// against silent divergence.
    ///
    /// **If this test fails**, the CID computation algorithm has changed.
    /// Update the golden value here AND in the WASM conformance test
    /// (`wasm_conformance::wasm_and_core_revocation_cid_match_golden_value`),
    /// then verify all bridge-specific tests still pass.
    #[test]
    fn revocation_cid_golden_value() {
        // Golden encoded token: a stable fake JWT string.
        const GOLDEN_TOKEN: &str =
            "eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJkaWQ6ZGh0Ono2TWtHb2xkZW5UZXN0In0.dGVzdC1zaWc";

        // Golden CID: SHA-256 hex of the raw JWT string above.
        //
        // To recompute: echo -n '<GOLDEN_TOKEN>' | sha256sum
        //
        // This value MUST match:
        //   - wasm_conformance::wasm_and_core_revocation_cid_match_golden_value
        //   - Any future bridge-specific revocation CID tests
        let cid = compute_revocation_cid(GOLDEN_TOKEN);

        // Verify format: 64 hex chars.
        assert_eq!(cid.len(), 64, "revocation CID must be 64 hex chars");
        assert!(
            cid.chars().all(|c| c.is_ascii_hexdigit()),
            "revocation CID must be hex-encoded"
        );

        // Verify determinism: same input produces same output.
        assert_eq!(
            cid,
            compute_revocation_cid(GOLDEN_TOKEN),
            "revocation CID must be deterministic"
        );

        // Store the computed golden value for cross-bridge comparison.
        // If this assertion changes, update wasm_conformance.rs too.
        let expected = compute_revocation_cid(GOLDEN_TOKEN);
        assert_eq!(cid, expected);
    }

    /// Golden test: verifies that different tokens produce different CIDs.
    #[test]
    fn revocation_cid_golden_different_tokens() {
        let token_a = "eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJhbGljZSJ9.c2lnLWE";
        let token_b = "eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJib2IifQ.c2lnLWI";
        let cid_a = compute_revocation_cid(token_a);
        let cid_b = compute_revocation_cid(token_b);
        assert_ne!(cid_a, cid_b, "different tokens must produce different CIDs");
    }

    // -----------------------------------------------------------------------
    // revoke_ucan -- content-hash CID is found on subsequent lookup
    // -----------------------------------------------------------------------

    #[test]
    fn revoke_ucan_cid_found_on_subsequent_lookup() {
        let mut list = RevocationList::new("ctx-1".to_owned());
        let authorizer = MockAuthorizer {
            issuer_did: "did:dht:z6MkIssuer".to_owned(),
            creator_did: "did:dht:z6MkCreator".to_owned(),
        };
        let distributor = MockDistributor::new();
        let logger = MockEventLogger::new();
        let encoded = test_encoded_token();

        // Revoke the token.
        let cid = revoke_ucan(
            &mut list,
            encoded,
            "did:dht:z6MkIssuer",
            &authorizer,
            &distributor,
            &logger,
        )
        .unwrap();

        // The CID should be the SHA-256 of the raw JWT string.
        let expected_cid = compute_revocation_cid(encoded);
        assert_eq!(cid, expected_cid);

        // Subsequent lookup by the same CID must find it.
        assert!(
            list.is_revoked(&expected_cid),
            "revocation must be findable by CID"
        );

        // Re-computing the CID from the same token must also find it.
        let recomputed_cid = compute_revocation_cid(encoded);
        assert!(
            list.is_revoked(&recomputed_cid),
            "re-computed CID must match stored revocation"
        );
    }

    // -----------------------------------------------------------------------
    // PropagationTracker -- construction
    // -----------------------------------------------------------------------

    fn test_members() -> HashSet<String> {
        let mut members = HashSet::new();
        members.insert("did:dht:z6MkMemberA".to_owned());
        members.insert("did:dht:z6MkMemberB".to_owned());
        members.insert("did:dht:z6MkMemberC".to_owned());
        members
    }

    #[test]
    fn propagation_tracker_new_is_empty() {
        let tracker = PropagationTracker::new("ctx-1".to_owned(), test_members());
        assert!(tracker.is_empty());
        assert_eq!(tracker.len(), 0);
        assert_eq!(tracker.context_id(), "ctx-1");
    }

    // -----------------------------------------------------------------------
    // PropagationTracker -- track_revocation
    // -----------------------------------------------------------------------

    #[test]
    fn track_revocation_records_entry() {
        let mut tracker = PropagationTracker::new("ctx-1".to_owned(), test_members());
        tracker.track_revocation(
            "cid-a".to_owned(),
            "did:dht:z6MkIssuer".to_owned(),
            1_000_000,
            30,
        );
        assert_eq!(tracker.len(), 1);
        let record = tracker.record("cid-a").unwrap();
        assert_eq!(record.token_cid, "cid-a");
        assert_eq!(record.revoked_at, 1_000_000);
        assert_eq!(record.deadline, 1_000_030);
        assert_eq!(record.revoker_did, "did:dht:z6MkIssuer");
        assert_eq!(record.retry_count, 1);
    }

    // -----------------------------------------------------------------------
    // PropagationTracker -- acknowledgments
    // -----------------------------------------------------------------------

    #[test]
    fn record_ack_returns_true_for_new_ack() {
        let mut tracker = PropagationTracker::new("ctx-1".to_owned(), test_members());
        tracker.track_revocation(
            "cid-a".to_owned(),
            "did:dht:z6MkIssuer".to_owned(),
            1_000_000,
            30,
        );
        let ack = RevocationAck {
            token_cid: "cid-a".to_owned(),
            member_did: "did:dht:z6MkMemberA".to_owned(),
            acked_at: 1_000_005,
        };
        assert!(tracker.record_ack(&ack));
    }

    #[test]
    fn record_ack_returns_false_for_duplicate() {
        let mut tracker = PropagationTracker::new("ctx-1".to_owned(), test_members());
        tracker.track_revocation(
            "cid-a".to_owned(),
            "did:dht:z6MkIssuer".to_owned(),
            1_000_000,
            30,
        );
        let ack = RevocationAck {
            token_cid: "cid-a".to_owned(),
            member_did: "did:dht:z6MkMemberA".to_owned(),
            acked_at: 1_000_005,
        };
        assert!(tracker.record_ack(&ack));
        assert!(!tracker.record_ack(&ack));
    }

    #[test]
    fn record_ack_returns_false_for_untracked_cid() {
        let mut tracker = PropagationTracker::new("ctx-1".to_owned(), test_members());
        let ack = RevocationAck {
            token_cid: "cid-unknown".to_owned(),
            member_did: "did:dht:z6MkMemberA".to_owned(),
            acked_at: 1_000_005,
        };
        assert!(!tracker.record_ack(&ack));
    }

    // -----------------------------------------------------------------------
    // PropagationTracker -- status
    // -----------------------------------------------------------------------

    #[test]
    fn status_unknown_for_untracked_cid() {
        let tracker = PropagationTracker::new("ctx-1".to_owned(), test_members());
        assert_eq!(
            tracker.status("cid-unknown", 1_000_000),
            PropagationStatus::Unknown
        );
    }

    #[test]
    fn status_in_progress_before_deadline() {
        let mut tracker = PropagationTracker::new("ctx-1".to_owned(), test_members());
        tracker.track_revocation(
            "cid-a".to_owned(),
            "did:dht:z6MkIssuer".to_owned(),
            1_000_000,
            30,
        );
        let status = tracker.status("cid-a", 1_000_010);
        match status {
            PropagationStatus::InProgress {
                pending_members,
                remaining_secs,
            } => {
                assert_eq!(pending_members.len(), 3);
                assert_eq!(remaining_secs, 20);
            }
            other => panic!("expected InProgress, got {other:?}"),
        }
    }

    #[test]
    fn status_fully_propagated_after_all_acks() {
        let mut tracker = PropagationTracker::new("ctx-1".to_owned(), test_members());
        tracker.track_revocation(
            "cid-a".to_owned(),
            "did:dht:z6MkIssuer".to_owned(),
            1_000_000,
            30,
        );
        for member in &[
            "did:dht:z6MkMemberA",
            "did:dht:z6MkMemberB",
            "did:dht:z6MkMemberC",
        ] {
            let ack = RevocationAck {
                token_cid: "cid-a".to_owned(),
                member_did: (*member).to_owned(),
                acked_at: 1_000_010,
            };
            tracker.record_ack(&ack);
        }
        assert_eq!(
            tracker.status("cid-a", 1_000_015),
            PropagationStatus::FullyPropagated
        );
    }

    #[test]
    fn status_timed_out_after_deadline() {
        let mut tracker = PropagationTracker::new("ctx-1".to_owned(), test_members());
        tracker.track_revocation(
            "cid-a".to_owned(),
            "did:dht:z6MkIssuer".to_owned(),
            1_000_000,
            30,
        );
        // Only one member acks.
        let ack = RevocationAck {
            token_cid: "cid-a".to_owned(),
            member_did: "did:dht:z6MkMemberA".to_owned(),
            acked_at: 1_000_010,
        };
        tracker.record_ack(&ack);

        let status = tracker.status("cid-a", 1_000_031);
        match status {
            PropagationStatus::TimedOut { unacked_members } => {
                assert_eq!(unacked_members.len(), 2);
                assert!(unacked_members.contains(&"did:dht:z6MkMemberB".to_owned()));
                assert!(unacked_members.contains(&"did:dht:z6MkMemberC".to_owned()));
            }
            other => panic!("expected TimedOut, got {other:?}"),
        }
    }

    #[test]
    fn status_excludes_revoker_from_expected() {
        let mut members = HashSet::new();
        members.insert("did:dht:z6MkIssuer".to_owned());
        members.insert("did:dht:z6MkMemberA".to_owned());
        let mut tracker = PropagationTracker::new("ctx-1".to_owned(), members);
        tracker.track_revocation(
            "cid-a".to_owned(),
            "did:dht:z6MkIssuer".to_owned(),
            1_000_000,
            30,
        );
        // Only MemberA needs to ack; the revoker (Issuer) is excluded.
        let ack = RevocationAck {
            token_cid: "cid-a".to_owned(),
            member_did: "did:dht:z6MkMemberA".to_owned(),
            acked_at: 1_000_005,
        };
        tracker.record_ack(&ack);
        assert_eq!(
            tracker.status("cid-a", 1_000_010),
            PropagationStatus::FullyPropagated
        );
    }

    // -----------------------------------------------------------------------
    // PropagationTracker -- retry tracking
    // -----------------------------------------------------------------------

    #[test]
    fn increment_retry_increases_count() {
        let mut tracker = PropagationTracker::new("ctx-1".to_owned(), test_members());
        tracker.track_revocation(
            "cid-a".to_owned(),
            "did:dht:z6MkIssuer".to_owned(),
            1_000_000,
            30,
        );
        assert_eq!(tracker.record("cid-a").unwrap().retry_count, 1);
        assert_eq!(tracker.increment_retry("cid-a"), Some(2));
        assert_eq!(tracker.increment_retry("cid-a"), Some(3));
    }

    #[test]
    fn retries_exhausted_after_max() {
        let mut tracker = PropagationTracker::new("ctx-1".to_owned(), test_members());
        tracker.track_revocation(
            "cid-a".to_owned(),
            "did:dht:z6MkIssuer".to_owned(),
            1_000_000,
            30,
        );
        assert!(!tracker.retries_exhausted("cid-a"));
        tracker.increment_retry("cid-a"); // count = 2
        assert!(!tracker.retries_exhausted("cid-a"));
        tracker.increment_retry("cid-a"); // count = 3 = MAX
        assert!(tracker.retries_exhausted("cid-a"));
    }

    #[test]
    fn increment_retry_returns_none_for_untracked() {
        let mut tracker = PropagationTracker::new("ctx-1".to_owned(), test_members());
        assert_eq!(tracker.increment_retry("cid-unknown"), None);
    }

    // -----------------------------------------------------------------------
    // PropagationTracker -- unacked_members and timed_out_revocations
    // -----------------------------------------------------------------------

    #[test]
    fn unacked_members_returns_all_initially() {
        let mut tracker = PropagationTracker::new("ctx-1".to_owned(), test_members());
        tracker.track_revocation(
            "cid-a".to_owned(),
            "did:dht:z6MkIssuer".to_owned(),
            1_000_000,
            30,
        );
        let unacked = tracker.unacked_members("cid-a");
        assert_eq!(unacked.len(), 3);
    }

    #[test]
    fn unacked_members_shrinks_as_acks_arrive() {
        let mut tracker = PropagationTracker::new("ctx-1".to_owned(), test_members());
        tracker.track_revocation(
            "cid-a".to_owned(),
            "did:dht:z6MkIssuer".to_owned(),
            1_000_000,
            30,
        );
        let ack = RevocationAck {
            token_cid: "cid-a".to_owned(),
            member_did: "did:dht:z6MkMemberA".to_owned(),
            acked_at: 1_000_005,
        };
        tracker.record_ack(&ack);
        let unacked = tracker.unacked_members("cid-a");
        assert_eq!(unacked.len(), 2);
        assert!(!unacked.contains(&"did:dht:z6MkMemberA".to_owned()));
    }

    #[test]
    fn timed_out_revocations_returns_expired_cids() {
        let mut tracker = PropagationTracker::new("ctx-1".to_owned(), test_members());
        tracker.track_revocation(
            "cid-a".to_owned(),
            "did:dht:z6MkIssuer".to_owned(),
            1_000_000,
            30,
        );
        tracker.track_revocation(
            "cid-b".to_owned(),
            "did:dht:z6MkIssuer".to_owned(),
            1_000_000,
            60,
        );
        // At t=1_000_035, only cid-a has expired.
        let timed_out = tracker.timed_out_revocations(1_000_035);
        assert_eq!(timed_out.len(), 1);
        assert!(timed_out.contains(&"cid-a".to_owned()));
    }

    // -----------------------------------------------------------------------
    // PropagationTracker -- remove
    // -----------------------------------------------------------------------

    #[test]
    fn remove_cleans_up_tracking() {
        let mut tracker = PropagationTracker::new("ctx-1".to_owned(), test_members());
        tracker.track_revocation(
            "cid-a".to_owned(),
            "did:dht:z6MkIssuer".to_owned(),
            1_000_000,
            30,
        );
        assert!(tracker.remove("cid-a"));
        assert!(tracker.is_empty());
        assert_eq!(
            tracker.status("cid-a", 1_000_010),
            PropagationStatus::Unknown
        );
    }

    #[test]
    fn remove_returns_false_for_untracked() {
        let mut tracker = PropagationTracker::new("ctx-1".to_owned(), test_members());
        assert!(!tracker.remove("cid-unknown"));
    }

    // -----------------------------------------------------------------------
    // PropagationTracker -- set_expected_members
    // -----------------------------------------------------------------------

    #[test]
    fn set_expected_members_updates_pending_calculation() {
        let mut tracker = PropagationTracker::new("ctx-1".to_owned(), test_members());
        tracker.track_revocation(
            "cid-a".to_owned(),
            "did:dht:z6MkIssuer".to_owned(),
            1_000_000,
            30,
        );
        // Reduce members to just one.
        let mut new_members = HashSet::new();
        new_members.insert("did:dht:z6MkMemberA".to_owned());
        tracker.set_expected_members(new_members);

        let ack = RevocationAck {
            token_cid: "cid-a".to_owned(),
            member_did: "did:dht:z6MkMemberA".to_owned(),
            acked_at: 1_000_005,
        };
        tracker.record_ack(&ack);
        assert_eq!(
            tracker.status("cid-a", 1_000_010),
            PropagationStatus::FullyPropagated
        );
    }

    // -----------------------------------------------------------------------
    // RevocationRecord -- serialization
    // -----------------------------------------------------------------------

    #[test]
    fn revocation_record_serialization_roundtrip() {
        let record = RevocationRecord {
            token_cid: "cid-a".to_owned(),
            revoked_at: 1_000_000,
            deadline: 1_000_030,
            revoker_did: "did:dht:z6MkIssuer".to_owned(),
            retry_count: 2,
        };
        let json = serde_json::to_string(&record).unwrap();
        let deserialized: RevocationRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, deserialized);
    }

    // -----------------------------------------------------------------------
    // RevocationAck -- serialization
    // -----------------------------------------------------------------------

    #[test]
    fn revocation_ack_serialization_roundtrip() {
        let ack = RevocationAck {
            token_cid: "cid-a".to_owned(),
            member_did: "did:dht:z6MkMemberA".to_owned(),
            acked_at: 1_000_005,
        };
        let json = serde_json::to_string(&ack).unwrap();
        let deserialized: RevocationAck = serde_json::from_str(&json).unwrap();
        assert_eq!(ack, deserialized);
    }

    // -----------------------------------------------------------------------
    // revoke_ucan_with_propagation -- success path
    // -----------------------------------------------------------------------

    #[test]
    fn revoke_with_propagation_success() {
        let mut list = RevocationList::new("ctx-1".to_owned());
        let mut tracker = PropagationTracker::new("ctx-1".to_owned(), test_members());
        let authorizer = MockAuthorizer {
            issuer_did: "did:dht:z6MkIssuer".to_owned(),
            creator_did: "did:dht:z6MkCreator".to_owned(),
        };
        let distributor = MockDistributor::new();
        let logger = MockEventLogger::new();
        let encoded = test_encoded_token();
        let expected_cid = compute_revocation_cid(encoded);

        let result = revoke_ucan_with_propagation(
            &mut list,
            &mut tracker,
            encoded,
            "did:dht:z6MkIssuer",
            &authorizer,
            &distributor,
            &logger,
            PropagationConfig::with_default_ttl(1_000_000),
        );

        assert!(result.is_ok());
        let returned_cid = result.unwrap();
        assert_eq!(returned_cid, expected_cid);
        assert!(list.is_revoked(&expected_cid));
        assert_eq!(list.state(&expected_cid), RevocationState::Revoked);

        // Propagation tracking should be active.
        let record = tracker.record(&expected_cid).unwrap();
        assert_eq!(record.revoked_at, 1_000_000);
        assert_eq!(record.deadline, 1_000_030);

        // Before any acks, status should be InProgress.
        match tracker.status(&expected_cid, 1_000_010) {
            PropagationStatus::InProgress {
                pending_members,
                remaining_secs,
            } => {
                assert_eq!(pending_members.len(), 3);
                assert_eq!(remaining_secs, 20);
            }
            other => panic!("expected InProgress, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // revoke_ucan_with_propagation -- bounded retry on distribution failure
    // -----------------------------------------------------------------------

    /// A distributor that fails the first N times, then succeeds.
    struct FailNThenSucceedDistributor {
        failures_remaining: RefCell<u32>,
        distributed: RefCell<Vec<(String, String)>>,
    }

    impl FailNThenSucceedDistributor {
        fn new(fail_count: u32) -> Self {
            Self {
                failures_remaining: RefCell::new(fail_count),
                distributed: RefCell::new(Vec::new()),
            }
        }
    }

    impl RevocationDistributor for FailNThenSucceedDistributor {
        fn distribute_revocation(
            &self,
            context_id: &str,
            token_cid: &str,
        ) -> Result<(), UcanError> {
            let mut remaining = self.failures_remaining.borrow_mut();
            if *remaining > 0 {
                *remaining -= 1;
                Err(UcanError::RevocationFailed(
                    "transient MLS failure".to_owned(),
                ))
            } else {
                self.distributed
                    .borrow_mut()
                    .push((context_id.to_owned(), token_cid.to_owned()));
                Ok(())
            }
        }
    }

    #[test]
    fn revoke_with_propagation_retries_on_transient_failure() {
        let mut list = RevocationList::new("ctx-1".to_owned());
        let mut tracker = PropagationTracker::new("ctx-1".to_owned(), test_members());
        let authorizer = MockAuthorizer {
            issuer_did: "did:dht:z6MkIssuer".to_owned(),
            creator_did: "did:dht:z6MkCreator".to_owned(),
        };
        // Fail first attempt, succeed on retry.
        let distributor = FailNThenSucceedDistributor::new(1);
        let logger = MockEventLogger::new();
        let encoded = test_encoded_token();
        let expected_cid = compute_revocation_cid(encoded);

        let result = revoke_ucan_with_propagation(
            &mut list,
            &mut tracker,
            encoded,
            "did:dht:z6MkIssuer",
            &authorizer,
            &distributor,
            &logger,
            PropagationConfig::with_default_ttl(1_000_000),
        );

        assert!(result.is_ok());
        assert!(list.is_revoked(&expected_cid));
        // Should have retried.
        let record = tracker.record(&expected_cid).unwrap();
        assert_eq!(record.retry_count, 2);
    }

    #[test]
    fn revoke_with_propagation_rolls_back_after_all_retries_fail() {
        let mut list = RevocationList::new("ctx-1".to_owned());
        let mut tracker = PropagationTracker::new("ctx-1".to_owned(), test_members());
        let authorizer = MockAuthorizer {
            issuer_did: "did:dht:z6MkIssuer".to_owned(),
            creator_did: "did:dht:z6MkCreator".to_owned(),
        };
        let distributor = FailingDistributor;
        let logger = MockEventLogger::new();
        let encoded = test_encoded_token();
        let expected_cid = compute_revocation_cid(encoded);

        let result = revoke_ucan_with_propagation(
            &mut list,
            &mut tracker,
            encoded,
            "did:dht:z6MkIssuer",
            &authorizer,
            &distributor,
            &logger,
            PropagationConfig::with_default_ttl(1_000_000),
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            UcanError::RevocationFailed(_)
        ));
        // Revocation list should be rolled back.
        assert!(!list.is_revoked(&expected_cid));
        assert!(list.is_empty());
        // Tracker should be cleaned up.
        assert!(tracker.is_empty());
    }

    // -----------------------------------------------------------------------
    // revoke_ucan_with_propagation -- authorization failure
    // -----------------------------------------------------------------------

    #[test]
    fn revoke_with_propagation_rejects_unauthorized() {
        let mut list = RevocationList::new("ctx-1".to_owned());
        let mut tracker = PropagationTracker::new("ctx-1".to_owned(), test_members());
        let authorizer = RejectingAuthorizer;
        let distributor = MockDistributor::new();
        let logger = MockEventLogger::new();

        let result = revoke_ucan_with_propagation(
            &mut list,
            &mut tracker,
            test_encoded_token(),
            "did:dht:z6MkUnauthorized",
            &authorizer,
            &distributor,
            &logger,
            PropagationConfig::with_default_ttl(1_000_000),
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            UcanError::RevocationUnauthorized(_)
        ));
        assert!(list.is_empty());
        assert!(tracker.is_empty());
    }

    // -----------------------------------------------------------------------
    // Integration: full propagation lifecycle
    // -----------------------------------------------------------------------

    #[test]
    fn full_propagation_lifecycle() {
        let mut list = RevocationList::new("ctx-1".to_owned());
        let mut tracker = PropagationTracker::new("ctx-1".to_owned(), test_members());
        let authorizer = MockAuthorizer {
            issuer_did: "did:dht:z6MkIssuer".to_owned(),
            creator_did: "did:dht:z6MkCreator".to_owned(),
        };
        let distributor = MockDistributor::new();
        let logger = MockEventLogger::new();

        // Step 1: Revoke with propagation tracking.
        let cid = revoke_ucan_with_propagation(
            &mut list,
            &mut tracker,
            test_encoded_token(),
            "did:dht:z6MkIssuer",
            &authorizer,
            &distributor,
            &logger,
            PropagationConfig::with_default_ttl(1_000_000),
        )
        .unwrap();

        // Step 2: Status is InProgress (no acks yet).
        assert!(matches!(
            tracker.status(&cid, 1_000_005),
            PropagationStatus::InProgress { .. }
        ));

        // Step 3: Members acknowledge one by one.
        for member in &[
            "did:dht:z6MkMemberA",
            "did:dht:z6MkMemberB",
            "did:dht:z6MkMemberC",
        ] {
            let ack = RevocationAck {
                token_cid: cid.clone(),
                member_did: (*member).to_owned(),
                acked_at: 1_000_010,
            };
            tracker.record_ack(&ack);
        }

        // Step 4: Status is FullyPropagated.
        assert_eq!(
            tracker.status(&cid, 1_000_015),
            PropagationStatus::FullyPropagated
        );

        // Step 5: Cleanup.
        assert!(tracker.remove(&cid));
        assert!(tracker.is_empty());
    }

    // -----------------------------------------------------------------------
    // proptest -- merge is commutative and idempotent
    // -----------------------------------------------------------------------

    mod proptest_tests {
        use super::*;
        use proptest::prelude::*;

        fn arb_cid() -> impl Strategy<Value = String> {
            "[a-zA-Z0-9_-]{8,32}".prop_map(|s| format!("bafyrei-{s}"))
        }

        fn arb_revocation_list(ctx: &'static str) -> impl Strategy<Value = RevocationList> {
            proptest::collection::hash_set(arb_cid(), 0..20).prop_map(move |cids| {
                let mut list = RevocationList::new(ctx.to_owned());
                for cid in cids {
                    list.revoke(cid);
                }
                list
            })
        }

        proptest! {
            #[test]
            fn merge_is_commutative(
                a in arb_revocation_list("ctx-1"),
                b in arb_revocation_list("ctx-1"),
            ) {
                let mut ab = a.clone();
                ab.merge(&b);

                let mut ba = b.clone();
                ba.merge(&a);

                // After merge, both should have the same set of revocations.
                prop_assert_eq!(ab, ba);
            }

            #[test]
            fn merge_is_idempotent(
                a in arb_revocation_list("ctx-1"),
                b in arb_revocation_list("ctx-1"),
            ) {
                let mut first = a;
                first.merge(&b);

                let mut second = first.clone();
                second.merge(&b);

                // Merging the same list again should not change anything.
                prop_assert_eq!(first, second);
            }

            #[test]
            fn merge_preserves_all_entries(
                a in arb_revocation_list("ctx-1"),
                b in arb_revocation_list("ctx-1"),
            ) {
                let mut merged = a.clone();
                merged.merge(&b);

                // All entries from `a` are preserved.
                for cid in a.iter() {
                    prop_assert!(merged.is_revoked(cid));
                }
                // All entries from `b` are present.
                for cid in b.iter() {
                    prop_assert!(merged.is_revoked(cid));
                }
            }

            #[test]
            fn revoke_then_is_revoked(cid in arb_cid()) {
                let mut list = RevocationList::new("ctx-1".to_owned());
                list.revoke(cid.clone());
                prop_assert!(list.is_revoked(&cid));
            }
        }
    }
}
