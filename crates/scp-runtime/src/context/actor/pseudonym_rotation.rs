//! The local member's pseudonym rotation state and epoch schedule (spec 09
//! §9.10.4.1).
//!
//! [`PseudonymRotationState`] is Class-S state (ADR-049 §9): a rotation
//! persists it fail-closed before the announcement goes out, so a crash at any
//! point of the §9.10.4.1 rotation order restores either the old state or the
//! completed rotation with `announce_pending` set. The current routing ID stays
//! in [`ContextRouting`](super::state::ContextRouting); this state holds the
//! epoch, the previous routing ID during its grace, and the schedule
//! bookkeeping.
//!
//! The context actor holds no key custody, so it never derives a routing ID.
//! It decides when a rotation is due ([`PseudonymRotationState::rotation_due`])
//! and signals; the bridge driver derives at the epoch
//! [`PseudonymRotationState::next_epoch`] names and dispatches the rotation
//! back.

use scp_protocol::context::params::{PSEUDONYM_ROTATION_GRACE_SECS, PseudonymRotationPolicy};
use scp_protocol::context::pseudonym::CommitMembershipChange;
use serde::{Deserialize, Serialize};

use super::state::PerContextState;

/// The routing ID a member held before its latest rotation, kept for the
/// rotation grace (spec 09 §9.10.4.1 "Transition protocol and grace").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraceRoutingId {
    /// The previous routing ID.
    #[serde(with = "serde_bytes")]
    pub routing_id: [u8; 32],
    /// Wall-clock second at which the grace ends: the persist time of the
    /// rotation plus [`PSEUDONYM_ROTATION_GRACE_SECS`].
    pub grace_until_secs: u64,
}

impl GraceRoutingId {
    /// Returns `true` while the grace runs at wall-clock second `now_secs`.
    #[must_use]
    pub const fn in_grace(&self, now_secs: u64) -> bool {
        now_secs < self.grace_until_secs
    }
}

/// The local member's persisted pseudonym rotation state (spec 09 §9.10.4.1
/// "Rotation order and crash recovery").
///
/// Every field carries `#[serde(default)]`, so a snapshot written before
/// rotation existed decodes as the default: no v2 epoch, no previous routing
/// ID, nothing pending.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PseudonymRotationState {
    /// The member's v2 rotation epoch, or `None` while it holds a v1 routing
    /// ID. Never decreases.
    #[serde(default)]
    pub(crate) epoch: Option<u64>,
    /// The previous routing ID and its grace end. A second rotation during a
    /// grace replaces it, so a member holds at most two routing IDs.
    #[serde(default)]
    pub(crate) previous: Option<GraceRoutingId>,
    /// Set by the rotation's fail-closed persist and cleared after the
    /// announcement is published. A restore with it set re-publishes the
    /// announcement for `epoch` and the current routing ID.
    #[serde(default)]
    pub(crate) announce_pending: bool,
    /// The highest interval boundary index `j` (boundary `T0 + j × interval`)
    /// the member has handled. A rotation is due when the schedule index of
    /// the current time exceeds it. Anchored to the schedule index of the
    /// moment the member starts following a policy (creation, join, or a
    /// policy change), so boundaries before that moment trigger nothing.
    #[serde(default)]
    pub(crate) boundary_index: u64,
    /// Set when a committed AddMember or RemoveMember of another member
    /// obliges a rotation under `on_membership_change`; cleared by the next
    /// rotation. One rotation covers every change committed before it.
    #[serde(default)]
    pub(crate) membership_change_pending: bool,
    /// Set when the member joined a context whose policy is set while holding
    /// a v1 routing ID: spec 09 §9.10.4.1 "First v2 derivation" puts a joiner
    /// on v2 at the schedule index `k`, and the join entry point receives the
    /// bridge's v1 routing ID, so the first rotation is due at once. Cleared by
    /// that rotation, and by a policy change that disables rotation.
    #[serde(default)]
    pub(crate) join_derivation_pending: bool,
    /// `T0`, the creation timestamp the interval boundaries `T0 + j ×
    /// interval_secs` count from: the creator's own stamp at creation, the
    /// creator-signed snapshot's value at import. `None` for a member that
    /// holds no copy of the creator's `T0`: a Welcome joiner, because the
    /// invitation bundle carries none. Without `T0` the shared schedule
    /// cannot be computed, so under a policy that sets `interval_secs` no
    /// rotation is admissible ([`Self::next_epoch`] is `None`).
    #[serde(default)]
    pub(crate) schedule_t0_secs: Option<u64>,
}

/// The schedule index `k = floor((now − T0) / interval_secs)` of spec 09
/// §9.10.4.1 "First v2 derivation". A time before `T0` is index 0. An
/// `interval_secs` of 0 never passes policy validation; it maps to index 0 so
/// the division cannot fault.
#[must_use]
pub const fn schedule_index(t0_secs: u64, interval_secs: u64, now_secs: u64) -> u64 {
    if interval_secs == 0 {
        return 0;
    }
    now_secs.saturating_sub(t0_secs) / interval_secs
}

/// The schedule index under `policy` at `now_secs`: the interval index when
/// the policy sets `interval_secs`, else 0 (spec 09 §9.10.4.1). `None` when
/// the policy sets `interval_secs` and `t0_secs` is unknown.
fn policy_schedule_index(
    policy: Option<&PseudonymRotationPolicy>,
    t0_secs: Option<u64>,
    now_secs: u64,
) -> Option<u64> {
    policy
        .and_then(|p| p.interval_secs)
        .map_or(Some(0), |interval| {
            t0_secs.map(|t0| schedule_index(t0, interval, now_secs))
        })
}

impl PseudonymRotationState {
    /// The state of a member that starts following `policy` at `now_secs`
    /// with a v1 routing ID it keeps until its next trigger: at import. See
    /// [`Self::anchor_schedule`].
    #[must_use]
    pub fn anchored(
        policy: Option<&PseudonymRotationPolicy>,
        t0_secs: Option<u64>,
        now_secs: u64,
    ) -> Self {
        let mut state = Self {
            schedule_t0_secs: t0_secs,
            ..Self::default()
        };
        state.anchor_schedule(policy, now_secs);
        state
    }

    /// The state of a member that joined with a v1 routing ID at `now_secs`:
    /// [`Self::anchored`], plus an immediate first rotation to v2 at the
    /// schedule index when `policy` is set (spec 09 §9.10.4.1 "First v2
    /// derivation": a member that joins a context whose policy is set derives
    /// its first pseudonym with v2 at epoch `k`).
    #[must_use]
    pub fn joined(
        policy: Option<&PseudonymRotationPolicy>,
        t0_secs: Option<u64>,
        now_secs: u64,
    ) -> Self {
        let mut state = Self::anchored(policy, t0_secs, now_secs);
        state.join_derivation_pending = policy.is_some();
        state
    }

    /// The member's v2 rotation epoch, `None` while it holds a v1 routing ID.
    #[must_use]
    pub const fn epoch(&self) -> Option<u64> {
        self.epoch
    }

    /// The previous routing ID and its grace end, whether or not the grace
    /// has elapsed by the wall clock.
    #[must_use]
    pub const fn previous(&self) -> Option<GraceRoutingId> {
        self.previous
    }

    /// Whether a persisted rotation still waits for its announcement.
    #[must_use]
    pub const fn announce_pending(&self) -> bool {
        self.announce_pending
    }

    /// The epoch the next rotation must carry (spec 09 §9.10.4.1 "Epoch
    /// schedule" and "First v2 derivation"): the persisted epoch plus one, or,
    /// for a member with no v2 epoch, the schedule index under `policy`.
    ///
    /// Returns `None` when no rotation is admissible: a v1 member of a context
    /// without a policy (rotation is opt-in), a v1 member without `T0` under
    /// a policy that sets `interval_secs`, or a persisted epoch of
    /// `u64::MAX`, which has no successor.
    #[must_use]
    pub fn next_epoch(
        &self,
        policy: Option<&PseudonymRotationPolicy>,
        now_secs: u64,
    ) -> Option<u64> {
        self.epoch.map_or_else(
            || policy.and_then(|p| policy_schedule_index(Some(p), self.schedule_t0_secs, now_secs)),
            |epoch| epoch.checked_add(1),
        )
    }

    /// Whether a rotation is due at `now_secs` (spec 09 §9.10.4.1 "Epoch
    /// schedule"): the policy is set and an interval boundary the member has
    /// not handled has passed, `on_membership_change` holds and a membership
    /// change is pending, or the member's join-time v2 derivation is pending. A
    /// disabled policy (`None`) makes nothing due, which freezes the current
    /// routing ID. Nothing is due while the previous rotation's announcement
    /// is pending, because a rotation drops the previous routing ID.
    #[must_use]
    pub fn rotation_due(&self, policy: Option<&PseudonymRotationPolicy>, now_secs: u64) -> bool {
        let Some(p) = policy else {
            return false;
        };
        if self.announce_pending || self.next_epoch(policy, now_secs).is_none() {
            return false;
        }
        let boundary_passed = p.interval_secs.is_some()
            && policy_schedule_index(policy, self.schedule_t0_secs, now_secs)
                .is_some_and(|index| index > self.boundary_index);
        boundary_passed
            || (p.on_membership_change && self.membership_change_pending)
            || self.join_derivation_pending
    }

    /// The epoch of the rotation due at `now_secs`: [`Self::next_epoch`] while
    /// [`Self::rotation_due`] holds, else `None`. The rotation arm signals this
    /// epoch and `rotate_pseudonym` commits only this epoch, so a rotation off
    /// the schedule cannot commit (spec 09 §9.10.4.1: "no caller action starts
    /// a rotation").
    #[must_use]
    pub fn due_epoch(
        &self,
        policy: Option<&PseudonymRotationPolicy>,
        now_secs: u64,
    ) -> Option<u64> {
        if self.rotation_due(policy, now_secs) {
            self.next_epoch(policy, now_secs)
        } else {
            None
        }
    }

    /// The wall-clock second of the next interval boundary the member has not
    /// handled, `T0 + (boundary_index + 1) × interval_secs`, or `None` when the
    /// policy sets no interval, `T0` is unknown, or the value overflows `u64`.
    #[must_use]
    pub fn next_boundary_secs(&self, policy: Option<&PseudonymRotationPolicy>) -> Option<u64> {
        let interval = policy.and_then(|p| p.interval_secs)?;
        self.boundary_index
            .checked_add(1)?
            .checked_mul(interval)?
            .checked_add(self.schedule_t0_secs?)
    }

    /// Anchors the schedule at `now_secs` for a member that starts following
    /// `policy`: at join, and when governance sets or changes the policy.
    /// Boundaries at or before `now_secs` trigger nothing (spec 09 §9.10.4.1
    /// "First v2 derivation": a v1 member keeps its routing ID until its next
    /// trigger). A pending membership change survives only while the policy
    /// still sets `on_membership_change`.
    pub fn anchor_schedule(&mut self, policy: Option<&PseudonymRotationPolicy>, now_secs: u64) {
        self.boundary_index =
            policy_schedule_index(policy, self.schedule_t0_secs, now_secs).unwrap_or(0);
        if !policy.is_some_and(|p| p.on_membership_change) {
            self.membership_change_pending = false;
        }
        if policy.is_none() {
            self.join_derivation_pending = false;
        }
    }

    /// Records a committed AddMember or RemoveMember of another member (spec
    /// 09 §9.10.4.1 "Membership trigger"). No-op unless `policy` sets
    /// `on_membership_change`.
    pub fn note_membership_change(&mut self, policy: Option<&PseudonymRotationPolicy>) {
        if policy.is_some_and(|p| p.on_membership_change) {
            self.membership_change_pending = true;
        }
    }

    /// Applies a rotation to `new_epoch` (spec 09 §9.10.4.1 step 2): keeps
    /// `previous_routing_id` for the grace from `now_secs`, sets
    /// `announce_pending`, marks every boundary up to `now_secs` handled and
    /// clears a pending membership change and join derivation. Any older
    /// previous routing ID is dropped.
    ///
    /// Returns `None`, leaving `self` unchanged, when `now_secs` plus the grace
    /// overflows `u64`.
    #[must_use]
    pub fn record_rotation(
        &mut self,
        new_epoch: u64,
        previous_routing_id: [u8; 32],
        policy: Option<&PseudonymRotationPolicy>,
        now_secs: u64,
    ) -> Option<()> {
        let grace_until_secs = now_secs.checked_add(PSEUDONYM_ROTATION_GRACE_SECS)?;
        self.epoch = Some(new_epoch);
        self.previous = Some(GraceRoutingId {
            routing_id: previous_routing_id,
            grace_until_secs,
        });
        self.announce_pending = true;
        self.boundary_index = self
            .boundary_index
            .max(policy_schedule_index(policy, self.schedule_t0_secs, now_secs).unwrap_or(0));
        self.membership_change_pending = false;
        self.join_derivation_pending = false;
        Some(())
    }

    /// What the actor's rotation arm does at `now_secs` (spec 09 §9.10.4.1
    /// "Rotation order and crash recovery" and "Epoch schedule"). A pending
    /// announcement outranks a due rotation: the member re-publishes the
    /// rotation it persisted before it derives the next one.
    #[must_use]
    pub fn wake(&self, policy: Option<&PseudonymRotationPolicy>, now_secs: u64) -> RotationWake {
        if let (true, Some(pseudonym_epoch)) = (self.announce_pending, self.epoch) {
            return RotationWake::AnnouncementPending { pseudonym_epoch };
        }
        if let Some(pseudonym_epoch) = self.due_epoch(policy, now_secs) {
            return RotationWake::RotationDue { pseudonym_epoch };
        }
        self.next_boundary_secs(policy)
            .map_or(RotationWake::Idle, |boundary_secs| {
                RotationWake::SleepUntil { boundary_secs }
            })
    }

    /// Discards the grace state when the member leaves the context or the
    /// context closes or expires (spec 09 §9.10.4.1 "Leave, close and expiry
    /// during a grace"). A terminal context announces nothing further, so the
    /// pending announcement and membership trigger go too.
    pub const fn discard_grace(&mut self) {
        self.previous = None;
        self.announce_pending = false;
        self.membership_change_pending = false;
        self.join_derivation_pending = false;
    }
}

/// What the actor's rotation arm does at a given second; see
/// [`PseudonymRotationState::wake`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationWake {
    /// Signal [`ContextEvent::PseudonymAnnouncementPending`](scp_protocol::context::membership::ContextEvent::PseudonymAnnouncementPending)
    /// for the persisted epoch.
    AnnouncementPending {
        /// The persisted epoch whose announcement is pending.
        pseudonym_epoch: u64,
    },
    /// Signal [`ContextEvent::PseudonymRotationDue`](scp_protocol::context::membership::ContextEvent::PseudonymRotationDue)
    /// for the epoch the rotation must carry.
    RotationDue {
        /// The epoch the next rotation derives at.
        pseudonym_epoch: u64,
    },
    /// Nothing is due; wake at the next interval boundary.
    SleepUntil {
        /// Wall-clock second of the next unhandled boundary.
        boundary_secs: u64,
    },
    /// Nothing is due and no boundary is scheduled: no policy, a
    /// membership-only policy, or a boundary past `u64::MAX`.
    Idle,
}

/// Records a committed AddMember of `added_did` on the local member's rotation
/// state (spec 09 §9.10.4.1 "Membership trigger": every member except the added
/// one rotates). Call it inside the Class-S commit that applies the add, so the
/// trigger persists with the membership change.
pub(crate) fn note_member_added(state: &mut PerContextState, local_did: &str, added_did: &str) {
    if added_did != local_did {
        let policy = state.handle.params().pseudonym_rotation;
        state
            .class_s
            .pseudonym_rotation
            .note_membership_change(policy.as_ref());
    }
}

/// Records a committed RemoveMember or leave of `removed_did` on the local
/// member's rotation state, inside the Class-S commit that applies it. Another
/// member's departure triggers a rotation under `on_membership_change` (spec 09
/// §9.10.4.1 "Membership trigger"); the local member's own departure discards
/// its grace state ("Leave, close and expiry during a grace").
pub(crate) fn note_member_removed(state: &mut PerContextState, local_did: &str, removed_did: &str) {
    if removed_did == local_did {
        state.class_s.pseudonym_rotation.discard_grace();
    } else {
        let policy = state.handle.params().pseudonym_rotation;
        state
            .class_s
            .pseudonym_rotation
            .note_membership_change(policy.as_ref());
    }
}

/// A Commit another member committed, which the local member processed on
/// the `DeliverIncoming` path, with its membership changes counted by DID (spec
/// 09 §9.10.4.1 "Membership-change criterion").
///
/// `deliver_incoming` produces it from
/// [`classify_commit_membership`](scp_protocol::context::pseudonym::classify_commit_membership);
/// the messaging handler applies it with [`note_processed_commit`] inside a
/// fail-closed Class-S commit, because the receive view cannot reach Class-S
/// state.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "a processed Commit's membership change must reach note_processed_commit, or the rotation trigger and the registry deletion are lost"]
pub(crate) struct ProcessedCommit {
    /// The committer's DID from its MLS credential.
    pub(crate) committer_did: String,
    /// The `AddMember` and `RemoveMember` DIDs the Commit applies.
    pub(crate) change: CommitMembershipChange,
}

/// Applies a processed Commit's membership changes to the local member's
/// state (spec 09 §9.10.4.1). Call it inside the Class-S commit that persists
/// them.
///
/// - **Record lifetime and removal:** tears down every DID the Commit removes,
///   other than the local member, as the committer's removal does: its sender
///   key, its sender-epoch and receive-sequence floors through
///   `remove_floors`, and, through [`PerContextState::remove_member_state`],
///   its pseudonym-registry record, so a rejoining member's new epoch sequence
///   is accepted, and its membership, role state (spec §5.6.1), access key and
///   read exclusion. Without the floor prune a rejoiner's sender key, which
///   restarts its epochs, is refused as a rollback.
/// - **Membership trigger:** when the Commit applies at least one `AddMember` or
///   `RemoveMember`, records one pending rotation unless the local member is the
///   committer (it rotates after its own commit) or is removed. A removed local
///   member discards its grace instead ("Leave, close and expiry during a
///   grace"). [`PseudonymRotationState::note_membership_change`] records
///   nothing unless the policy sets `on_membership_change`.
///
/// A DID the Commit adds gets no membership entry, role or token here. A
/// receiver assigns no role it inferred: the added member's role comes only
/// from the verified `MemberJoined` governance leaf the Commit carries (spec
/// 07 §7.3.1.1 "Fail closed", ADR-066 decision 7), which story SCP-330
/// applies. Until then the added member's messages fail authorization with
/// `MemberNotFound`.
///
/// # Errors
///
/// [`PerContextState::remove_member_sender_key`]'s error on a context
/// without MLS state. Removals applied before the error stay in memory for
/// the next persist.
pub(crate) fn note_processed_commit(
    state: &mut PerContextState,
    context_id: &str,
    local_did: &str,
    commit: &ProcessedCommit,
    mut remove_floors: impl FnMut(&str),
) -> Result<(), scp_protocol::context::ContextError> {
    for did in &commit.change.removed_dids {
        if did != local_did {
            state.remove_member_sender_key(did)?;
            remove_floors(did);
            state.remove_member_state(context_id, &scp_did::DID::from(did.as_str()));
        }
    }
    if commit.change.removed_dids.iter().any(|d| d == local_did) {
        state.class_s.pseudonym_rotation.discard_grace();
        return Ok(());
    }
    if commit.committer_did != local_did && !commit.change.is_empty() {
        let policy = state.handle.params().pseudonym_rotation;
        state
            .class_s
            .pseudonym_rotation
            .note_membership_change(policy.as_ref());
    }
    Ok(())
}

/// The local member's routing IDs in one context (spec 09 §9.10.4.1), the
/// answer to [`Supervisor::local_routing_ids`](crate::context::supervisor::supervisor::Supervisor::local_routing_ids).
///
/// A subscriber holds `current` and, while it is set, `previous`; a rotation
/// driver derives at `next_pseudonym_epoch` and re-publishes the announcement
/// while `announce_pending` is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalRoutingIds {
    /// The routing ID peers address now.
    pub current: [u8; 32],
    /// The previous routing ID, only while its grace runs by the wall clock.
    pub previous: Option<GraceRoutingId>,
    /// The member's v2 rotation epoch, `None` while it holds a v1 routing ID.
    pub pseudonym_epoch: Option<u64>,
    /// The epoch the next rotation must carry, or `None` when no rotation is
    /// admissible (see [`PseudonymRotationState::next_epoch`]).
    pub next_pseudonym_epoch: Option<u64>,
    /// Whether a persisted rotation still waits for its announcement.
    pub announce_pending: bool,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const T0: u64 = 1_700_000_000;
    const I: u64 = 3_600;

    /// A member that holds the creator's `T0`, before any policy applies.
    fn at_t0() -> PseudonymRotationState {
        PseudonymRotationState::anchored(None, Some(T0), T0)
    }

    fn interval_policy() -> PseudonymRotationPolicy {
        PseudonymRotationPolicy {
            interval_secs: Some(I),
            on_membership_change: false,
        }
    }

    fn membership_policy() -> PseudonymRotationPolicy {
        PseudonymRotationPolicy {
            interval_secs: None,
            on_membership_change: true,
        }
    }

    #[test]
    fn schedule_index_floors_and_clamps_before_t0() {
        assert_eq!(schedule_index(T0, I, T0 - 1), 0);
        assert_eq!(schedule_index(T0, I, T0), 0);
        assert_eq!(schedule_index(T0, I, T0 + I - 1), 0);
        assert_eq!(schedule_index(T0, I, T0 + I), 1);
        assert_eq!(schedule_index(T0, I, T0 + 3 * I + 5), 3);
        assert_eq!(schedule_index(T0, 0, T0 + I), 0);
    }

    #[test]
    fn nothing_is_due_without_a_policy_over_a_thousand_periods() {
        let state = at_t0();
        for j in 0..=1_000 {
            assert!(!state.rotation_due(None, T0 + j * I));
        }
        assert_eq!(state.next_epoch(None, T0 + 1_000 * I), None);
    }

    #[test]
    fn due_at_each_boundary_and_once_for_missed_boundaries() {
        let policy = interval_policy();
        let mut state = at_t0();
        assert!(!state.rotation_due(Some(&policy), T0 + I - 1));
        assert_eq!(state.next_boundary_secs(Some(&policy)), Some(T0 + I));
        assert!(state.rotation_due(Some(&policy), T0 + I));
        // First v2 derivation at the schedule index of that moment.
        assert_eq!(state.next_epoch(Some(&policy), T0 + I), Some(1));
        state
            .record_rotation(1, [1; 32], Some(&policy), T0 + I)
            .unwrap();
        state.announce_pending = false;
        assert!(!state.rotation_due(Some(&policy), T0 + I));
        assert_eq!(state.next_boundary_secs(Some(&policy)), Some(T0 + 2 * I));

        // Three boundaries pass while stopped: one rotation covers them.
        let late = T0 + 5 * I;
        assert!(state.rotation_due(Some(&policy), late));
        assert_eq!(state.next_epoch(Some(&policy), late), Some(2));
        state
            .record_rotation(2, [2; 32], Some(&policy), late)
            .unwrap();
        assert!(!state.rotation_due(Some(&policy), late));
        assert_eq!(state.next_boundary_secs(Some(&policy)), Some(T0 + 6 * I));
    }

    #[test]
    fn anchoring_skips_boundaries_before_the_policy_applies() {
        let policy = interval_policy();
        let mut state = at_t0();
        let enabled_at = T0 + 4 * I + 10;
        state.anchor_schedule(Some(&policy), enabled_at);
        assert!(!state.rotation_due(Some(&policy), enabled_at));
        assert!(state.rotation_due(Some(&policy), T0 + 5 * I));
        assert_eq!(state.next_epoch(Some(&policy), T0 + 5 * I), Some(5));
    }

    #[test]
    fn membership_change_is_due_only_under_on_membership_change() {
        let mut state = at_t0();
        state.note_membership_change(Some(&interval_policy()));
        assert!(!state.membership_change_pending);

        let policy = membership_policy();
        state.note_membership_change(Some(&policy));
        assert!(state.rotation_due(Some(&policy), T0));
        assert_eq!(state.next_epoch(Some(&policy), T0), Some(0));
        state
            .record_rotation(0, [9; 32], Some(&policy), T0)
            .unwrap();
        assert!(!state.rotation_due(Some(&policy), T0 + 10 * I));

        // Disabling the policy freezes the routing ID: nothing is due.
        state.note_membership_change(Some(&policy));
        assert!(!state.rotation_due(None, T0));
        // A policy change that drops the membership trigger clears the flag.
        state.anchor_schedule(Some(&interval_policy()), T0);
        assert!(!state.membership_change_pending);
    }

    #[test]
    fn a_joiner_under_a_policy_rotates_to_v2_at_the_schedule_index_at_once() {
        let policy = interval_policy();
        let joined_at = T0 + 3 * I + 7;
        let mut state = PseudonymRotationState::joined(Some(&policy), Some(T0), joined_at);
        assert!(state.rotation_due(Some(&policy), joined_at));
        assert_eq!(state.next_epoch(Some(&policy), joined_at), Some(3));
        state
            .record_rotation(3, [3; 32], Some(&policy), joined_at)
            .unwrap();
        state.announce_pending = false;
        assert!(!state.rotation_due(Some(&policy), T0 + 4 * I - 1));
        assert!(state.rotation_due(Some(&policy), T0 + 4 * I));

        // Without a policy a joiner keeps v1: nothing is due.
        let v1 = PseudonymRotationState::joined(None, Some(T0), joined_at);
        assert!(!v1.rotation_due(None, joined_at + 1_000 * I));
        // Disabling the policy before the first rotation cancels it.
        let mut cancelled = PseudonymRotationState::joined(Some(&policy), Some(T0), joined_at);
        cancelled.anchor_schedule(None, joined_at);
        assert!(!cancelled.join_derivation_pending);
    }

    /// A Welcome joiner holds no copy of the creator's `T0`: under an interval
    /// policy it computes no boundary and no epoch, so nothing is due, while a
    /// membership-only policy, whose schedule index is 0, still rotates it.
    #[test]
    fn a_member_without_t0_follows_no_interval_schedule() {
        let joined_at = T0 + 3 * I + 7;
        let policy = interval_policy();
        let state = PseudonymRotationState::joined(Some(&policy), None, joined_at);
        assert!(state.join_derivation_pending);
        assert_eq!(state.next_epoch(Some(&policy), joined_at), None);
        assert_eq!(state.next_boundary_secs(Some(&policy)), None);
        for j in 0..=10 {
            assert!(!state.rotation_due(Some(&policy), joined_at + j * I));
        }
        assert_eq!(state.wake(Some(&policy), joined_at), RotationWake::Idle);

        let membership = membership_policy();
        let state = PseudonymRotationState::joined(Some(&membership), None, joined_at);
        assert_eq!(state.due_epoch(Some(&membership), joined_at), Some(0));
    }

    /// While a persisted rotation waits for its announcement, no further
    /// rotation is due, whatever trigger fired; once the announcement
    /// succeeds, the trigger makes the next epoch due.
    #[test]
    fn no_rotation_is_due_while_an_announcement_is_pending() {
        let policy = PseudonymRotationPolicy {
            interval_secs: Some(I),
            on_membership_change: true,
        };
        let mut state = at_t0();
        state
            .record_rotation(1, [1; 32], Some(&policy), T0 + I)
            .unwrap();
        state.note_membership_change(Some(&policy));
        assert_eq!(state.due_epoch(Some(&policy), T0 + 3 * I), None);
        assert_eq!(
            state.wake(Some(&policy), T0 + 3 * I),
            RotationWake::AnnouncementPending { pseudonym_epoch: 1 }
        );

        state.announce_pending = false;
        assert_eq!(state.due_epoch(Some(&policy), T0 + I + 1), Some(2));
    }

    #[test]
    fn rotation_keeps_at_most_one_previous_and_sets_the_grace() {
        let policy = interval_policy();
        let mut state = at_t0();
        state
            .record_rotation(1, [1; 32], Some(&policy), T0 + I)
            .unwrap();
        let previous = state.previous().unwrap();
        assert_eq!(previous.routing_id, [1; 32]);
        assert_eq!(
            previous.grace_until_secs,
            T0 + I + PSEUDONYM_ROTATION_GRACE_SECS
        );
        assert!(previous.in_grace(T0 + I + PSEUDONYM_ROTATION_GRACE_SECS - 1));
        assert!(!previous.in_grace(T0 + I + PSEUDONYM_ROTATION_GRACE_SECS));
        assert!(state.announce_pending());

        state
            .record_rotation(2, [2; 32], Some(&policy), T0 + I + 1)
            .unwrap();
        assert_eq!(state.previous().unwrap().routing_id, [2; 32]);
        assert_eq!(state.epoch(), Some(2));
    }

    #[test]
    fn exhausted_epoch_and_overflowing_grace_admit_no_rotation() {
        let policy = interval_policy();
        let state = PseudonymRotationState {
            epoch: Some(u64::MAX),
            ..at_t0()
        };
        assert_eq!(state.next_epoch(Some(&policy), T0 + 9 * I), None);
        assert!(!state.rotation_due(Some(&policy), T0 + 9 * I));

        let mut fresh = at_t0();
        assert!(
            fresh
                .record_rotation(1, [1; 32], Some(&policy), u64::MAX)
                .is_none()
        );
        assert_eq!(fresh, at_t0());
    }

    #[test]
    fn discard_grace_drops_previous_and_pending_work() {
        let policy = membership_policy();
        let mut state = at_t0();
        state
            .record_rotation(0, [1; 32], Some(&policy), T0)
            .unwrap();
        state.note_membership_change(Some(&policy));
        state.discard_grace();
        assert_eq!(state.previous(), None);
        assert!(!state.announce_pending());
        assert!(!state.membership_change_pending);
        assert_eq!(state.epoch(), Some(0));
    }

    #[test]
    fn a_snapshot_without_rotation_fields_decodes_as_no_rotation_state() {
        let decoded: PseudonymRotationState = serde_json::from_str("{}").unwrap();
        assert_eq!(decoded, PseudonymRotationState::default());
    }

    const LOCAL: &str = "did:dht:z6MkRotationUnitLocal";
    const PEER: &str = "did:dht:z6MkRotationUnitPeer";

    fn context_state(policy: Option<PseudonymRotationPolicy>) -> PerContextState {
        let mut state =
            PerContextState::new_for_test_encrypted([0x31; 32], T0, scp_did::DID(LOCAL.to_owned()));
        state.handle = crate::context::ContextHandle::new(
            state.handle.context_id().to_owned(),
            scp_protocol::context::ContextParams {
                pseudonym_rotation: policy,
                ..scp_protocol::context::ContextParams::default()
            },
        );
        state.creation_timestamp_secs = T0;
        state.routing.set_local_pseudonym([9; 32]);
        state
    }

    /// "Membership trigger": every member except the added one rotates, so
    /// the local member's own add records nothing and a peer's add records
    /// the trigger.
    #[test]
    fn the_added_member_does_not_trigger_its_own_rotation() {
        let mut state = context_state(Some(membership_policy()));
        note_member_added(&mut state, LOCAL, LOCAL);
        assert_eq!(state.class_s.pseudonym_rotation, at_t0());

        note_member_added(&mut state, LOCAL, PEER);
        assert!(state.class_s.pseudonym_rotation.membership_change_pending);
    }

    /// A peer's removal triggers a rotation; the local member's own removal
    /// discards its grace and pending work instead.
    #[test]
    fn the_local_members_removal_discards_its_grace() {
        let policy = membership_policy();
        let mut state = context_state(Some(policy));
        note_member_removed(&mut state, LOCAL, PEER);
        assert!(state.class_s.pseudonym_rotation.membership_change_pending);

        state
            .class_s
            .pseudonym_rotation
            .record_rotation(0, [1; 32], Some(&policy), T0)
            .unwrap();
        note_member_removed(&mut state, LOCAL, LOCAL);
        let rotation = &state.class_s.pseudonym_rotation;
        assert_eq!(rotation.previous(), None);
        assert!(!rotation.announce_pending());
        assert!(!rotation.membership_change_pending);
    }

    /// `local_routing_ids` reports the previous routing ID only while its
    /// grace runs by the wall clock, even before the grace arm has dropped it.
    #[test]
    fn local_routing_ids_reports_the_previous_routing_id_only_during_its_grace() {
        let policy = interval_policy();
        let mut state = context_state(Some(policy));
        state
            .class_s
            .pseudonym_rotation
            .record_rotation(1, [9; 32], Some(&policy), T0 + I)
            .unwrap();
        let grace_end = T0 + I + PSEUDONYM_ROTATION_GRACE_SECS;
        let during =
            crate::context::queries_helpers::local_routing_ids(&state, grace_end - 1).unwrap();
        assert_eq!(during.previous.map(|p| p.routing_id), Some([9; 32]));
        let after = crate::context::queries_helpers::local_routing_ids(&state, grace_end).unwrap();
        assert_eq!(after.previous, None);
        assert!(state.class_s.pseudonym_rotation.previous().is_some());
        assert_eq!(after.pseudonym_epoch, Some(1));
        assert!(after.announce_pending);
    }

    /// The arm's decision: a pending announcement outranks a due rotation,
    /// a due rotation outranks the next boundary, and a membership-only
    /// policy with nothing pending is idle.
    #[test]
    fn wake_orders_pending_announcement_then_due_rotation_then_the_boundary() {
        let policy = interval_policy();
        let mut state = at_t0();
        assert_eq!(
            state.wake(Some(&policy), T0 + 1),
            RotationWake::SleepUntil {
                boundary_secs: T0 + I
            }
        );
        assert_eq!(
            state.wake(Some(&policy), T0 + I),
            RotationWake::RotationDue { pseudonym_epoch: 1 }
        );
        state
            .record_rotation(1, [1; 32], Some(&policy), T0 + I)
            .unwrap();
        assert_eq!(
            state.wake(Some(&policy), T0 + 3 * I),
            RotationWake::AnnouncementPending { pseudonym_epoch: 1 }
        );
        assert_eq!(
            at_t0().wake(Some(&membership_policy()), T0 + 9 * I),
            RotationWake::Idle
        );
        assert_eq!(at_t0().wake(None, T0 + 9 * I), RotationWake::Idle);
    }

    fn processed(committer: &str, added: &[&str], removed: &[&str]) -> ProcessedCommit {
        ProcessedCommit {
            committer_did: committer.to_owned(),
            change: CommitMembershipChange {
                added_dids: added.iter().map(|d| (*d).to_owned()).collect(),
                removed_dids: removed.iter().map(|d| (*d).to_owned()).collect(),
            },
        }
    }

    fn record_peer(state: &mut PerContextState, did: &str, epoch: u64) {
        state.routing.peer_registry_mut().unwrap().insert(
            scp_did::DID::from(did),
            scp_protocol::context::pseudonym::PseudonymRecord {
                routing_id: [7; 32],
                epoch: Some(epoch),
            },
        );
    }

    fn has_record(state: &PerContextState, did: &str) -> bool {
        state
            .routing
            .peer_registry()
            .unwrap()
            .contains_key(&scp_did::DID::from(did))
    }

    const COMMITTER: &str = "did:dht:committer";
    const CTX: &str = "ctx-push-030";

    fn apply(state: &mut PerContextState, commit: &ProcessedCommit) {
        let mut pruned = Vec::new();
        note_processed_commit(state, CTX, LOCAL, commit, |did| {
            pruned.push(did.to_owned());
        })
        .unwrap();
        let removed_peers: Vec<String> = commit
            .change
            .removed_dids
            .iter()
            .filter(|d| d.as_str() != LOCAL)
            .cloned()
            .collect();
        assert_eq!(
            pruned, removed_peers,
            "every removed peer's floors are pruned"
        );
    }

    /// "Membership trigger": a peer's Commit that adds or removes a member
    /// records one pending rotation, and a Commit with several changes still
    /// records one.
    #[test]
    fn a_peers_membership_commit_records_one_pending_rotation() {
        let mut state = context_state(Some(membership_policy()));
        apply(&mut state, &processed(COMMITTER, &[PEER], &[]));
        assert!(state.class_s.pseudonym_rotation.membership_change_pending);

        let mut state = context_state(Some(membership_policy()));
        apply(
            &mut state,
            &processed(COMMITTER, &["did:dht:a", "did:dht:b"], &[PEER]),
        );
        assert!(state.class_s.pseudonym_rotation.membership_change_pending);
        assert_eq!(
            state
                .class_s
                .pseudonym_rotation
                .due_epoch(Some(&membership_policy()), T0),
            Some(0)
        );
    }

    /// A Commit with no `AddMember` or `RemoveMember` (a device leaf or a key
    /// update), the local member's own Commit, and a policy without
    /// `on_membership_change` record nothing.
    #[test]
    fn no_rotation_without_a_membership_change_a_peer_committer_or_the_policy() {
        let mut state = context_state(Some(membership_policy()));
        apply(&mut state, &processed(COMMITTER, &[], &[]));
        assert_eq!(state.class_s.pseudonym_rotation, at_t0());

        apply(&mut state, &processed(LOCAL, &[PEER], &[]));
        assert_eq!(state.class_s.pseudonym_rotation, at_t0());

        let mut state = context_state(Some(interval_policy()));
        apply(&mut state, &processed(COMMITTER, &[PEER], &[]));
        assert!(!state.class_s.pseudonym_rotation.membership_change_pending);

        let mut state = context_state(None);
        apply(&mut state, &processed(COMMITTER, &[PEER], &[]));
        assert!(!state.class_s.pseudonym_rotation.membership_change_pending);
    }

    /// Fail closed (spec 07 §7.3.1.1, ADR-066 decision 7): a processed add
    /// records the trigger and nothing for the added DID: no membership entry,
    /// active-member entry, role, capability, token, or access key. Only the
    /// verified `MemberJoined` leaf of story SCP-330 may supply them.
    #[test]
    fn a_processed_add_records_no_membership_or_role_for_the_added_did() {
        let mut state = context_state(Some(membership_policy()));
        apply(&mut state, &processed(COMMITTER, &[PEER], &[]));
        assert!(state.class_s.pseudonym_rotation.membership_change_pending);
        assert!(!state.membership.contains(PEER));
        assert!(!state.members.contains(&scp_did::DID::from(PEER)));
        assert!(!state.role_state.members.contains(PEER));
        assert!(!state.role_state.assignments.contains_key(PEER));
        assert!(!state.role_state.member_capabilities.contains_key(PEER));
        assert!(state.access.access_key_store.get(CTX, PEER).is_none());
    }

    /// PUSH-030 AC1 device-leaf rule (spec 09 §9.10.4.1 "Membership-change
    /// criterion"): a Commit after which C still holds a leaf, whether a second
    /// leaf joins C's or C's leaf is removed and re-added as a `ResetMember`
    /// Commit does, classifies as no membership change and records no rotation.
    #[test]
    fn a_device_leaf_or_a_reset_leaf_of_a_held_did_records_no_rotation() {
        use scp_protocol::context::pseudonym::{CommitLeafDids, classify_commit_membership};
        let leaves = |before: &[&str], after: &[&str]| CommitLeafDids {
            before: before.iter().map(|d| (*d).to_owned()).collect(),
            after: after.iter().map(|d| (*d).to_owned()).collect(),
        };
        let second_device = leaves(&[LOCAL, COMMITTER, PEER], &[LOCAL, COMMITTER, PEER, PEER]);
        // The re-added leaf takes the removed leaf's place, so each side
        // holds one leaf for PEER.
        let reset = leaves(&[LOCAL, PEER, COMMITTER], &[LOCAL, COMMITTER, PEER]);
        for leaf_dids in [second_device, reset] {
            let change = classify_commit_membership(&leaf_dids);
            assert!(change.is_empty(), "{leaf_dids:?} -> {change:?}");
            let mut state = context_state(Some(membership_policy()));
            apply(
                &mut state,
                &ProcessedCommit {
                    committer_did: COMMITTER.to_owned(),
                    change,
                },
            );
            assert_eq!(state.class_s.pseudonym_rotation, at_t0());
        }
    }

    /// "Record lifetime": a processed removal deletes the removed DID's record
    /// and keeps every other record, even when the local member is the
    /// committer or the policy sets no rotation.
    #[test]
    fn a_processed_removal_deletes_the_removed_dids_record() {
        let mut state = context_state(None);
        record_peer(&mut state, PEER, 3);
        record_peer(&mut state, COMMITTER, 1);
        apply(&mut state, &processed(LOCAL, &[], &[PEER]));
        assert!(!has_record(&state, PEER));
        assert!(has_record(&state, COMMITTER));
    }

    fn admit(state: &mut PerContextState, did: &str) {
        state
            .membership
            .add_member(scp_did::DID::from(did), "member".to_owned(), Vec::new());
        state.members.insert(scp_did::DID::from(did));
        state.role_state.members.insert(did.to_owned());
        state.role_state.member_capabilities.insert(
            did.to_owned(),
            std::iter::once(scp_protocol::context::roles::Capability::MessagesWrite).collect(),
        );
        let key = scp_protocol::crypto::access_keys::generate_access_key(CTX, did);
        state.access.access_key_store.set(CTX, did, key);
        state
            .access
            .read_exclusion_list
            .insert(scp_did::DID::from(did));
        record_peer(state, did, 1);
        state.sequence_tracker.advance(CTX, did, 2, 1);
    }

    fn admitted(state: &PerContextState, did: &str) -> [bool; 7] {
        [
            state.membership.contains(did),
            state.members.contains(&scp_did::DID::from(did)),
            state.role_state.member_has_capability(
                did,
                &scp_protocol::context::roles::Capability::MessagesWrite,
            ),
            state.access.access_key_store.get(CTX, did).is_some(),
            state
                .access
                .read_exclusion_list
                .contains(&scp_did::DID::from(did)),
            has_record(state, did),
            state.sequence_tracker.expected_sequence(CTX, did).is_some(),
        ]
    }

    /// A processed removal takes the removed DID out of the membership, the
    /// role state, the access-key store, the read-exclusion list, the
    /// pseudonym registry and the sequence tracker, keeps
    /// every other member, and keeps the local member when it is the one
    /// removed.
    #[test]
    fn a_processed_removal_removes_the_dids_membership_and_keeps_the_rest() {
        let mut state = context_state(None);
        for did in [PEER, COMMITTER, LOCAL] {
            admit(&mut state, did);
        }
        apply(&mut state, &processed(COMMITTER, &[], &[PEER]));
        assert_eq!(admitted(&state, PEER), [false; 7]);
        assert_eq!(admitted(&state, COMMITTER), [true; 7]);
        assert_eq!(admitted(&state, LOCAL), [true; 7]);

        apply(&mut state, &processed(COMMITTER, &[], &[LOCAL]));
        assert_eq!(admitted(&state, LOCAL), [true; 7]);
    }

    /// A removed member that processes the Commit removing it does not rotate;
    /// it discards its grace and pending work.
    #[test]
    fn the_removed_local_member_does_not_rotate_and_discards_its_grace() {
        let policy = membership_policy();
        let mut state = context_state(Some(policy));
        state
            .class_s
            .pseudonym_rotation
            .record_rotation(0, [1; 32], Some(&policy), T0)
            .unwrap();
        apply(&mut state, &processed(COMMITTER, &[PEER], &[LOCAL]));
        let rotation = &state.class_s.pseudonym_rotation;
        assert!(!rotation.membership_change_pending);
        assert_eq!(rotation.previous(), None);
        assert!(!rotation.announce_pending());
    }
}
