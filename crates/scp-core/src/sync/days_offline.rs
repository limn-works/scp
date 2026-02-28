//! Tier 2 days-scale offline recovery: state snapshot + delta sync.
//!
//! This module implements the extended offline scenario (4 hours to 7 days) from
//! ADR-029 section 1. When a member has been offline for an extended period, the
//! relay's buffered messages may be insufficient (blob TTL expiry) and the MLS
//! epoch gap may be large enough that sequential Commit processing is impractical.
//!
//! The strategy is:
//! 1. Capture a [`ContextSnapshot`] — a self-contained, point-in-time record of
//!    the authoritative context state (params, membership, roles, event log root,
//!    MLS epoch).
//! 2. On reconnection, fetch the current snapshot from the sync provider and
//!    compute a [`SnapshotDelta`] — the set of differences between the local
//!    (stale) snapshot and the current (remote) snapshot.
//! 3. Apply the delta to the local state, rebuilding MLS group state via
//!    Welcome-based fast-forward when the epoch gap exceeds the sequential
//!    catch-up limit.
//! 4. Detect and resolve multi-device divergence using Merkle root comparison.
//!
//! # Architecture
//!
//! - [`ContextSnapshot`] — Authoritative context state at a point in time.
//! - [`SnapshotDelta`] — Differences between two snapshots.
//! - [`DeltaSyncEngine`] — Async trait for fetching snapshots and deltas from a
//!   provider (relay, peer, or local storage).
//! - [`compute_delta`] — Computes the delta between two snapshots.
//! - [`apply_delta`] — Applies a delta to a local snapshot, producing the
//!   updated state.
//! - [`MlsRecoveryAction`] — Determines how MLS group state should be rebuilt.
//! - [`DeviceSyncState`] — Tracks per-device offline state for multi-device
//!   divergence detection.
//!
//! See ADR-029 in `.docs/adrs/phase-6.md`.

use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Serialize};

use super::{ContextId, Ed25519Signature, MAX_SEQUENTIAL_COMMITS, SyncError, SyncOutcome};
use crate::identity::DID;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum epoch gap for sequential Commit catch-up (Tier 2).
///
/// If the MLS epoch gap exceeds this limit, the SDK switches to Welcome-based
/// fast-forward instead of processing Commits sequentially. Value matches
/// [`MAX_SEQUENTIAL_COMMITS`] from the parent module (ADR-029 section 3).
pub const MAX_EPOCH_GAP_FOR_SEQUENTIAL: u64 = MAX_SEQUENTIAL_COMMITS;

/// Default snapshot interval in seconds (4 hours).
///
/// Snapshots are created at regular intervals so that reconnecting members
/// have a recent baseline for delta computation. The interval is aligned
/// with the Tier 1/Tier 2 boundary.
pub const DEFAULT_SNAPSHOT_INTERVAL_SECS: u64 = 14_400;

// ---------------------------------------------------------------------------
// MembershipEntry
// ---------------------------------------------------------------------------

/// A single member's state within a snapshot.
///
/// Captures the member's identity, role, and sequence number at the time the
/// snapshot was taken.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipEntry {
    /// The member's decentralized identifier.
    pub did: DID,
    /// The member's assigned role name (e.g., `"admin"`, `"member"`).
    pub role_name: String,
    /// Per-sender monotonic sequence number at snapshot time.
    pub sequence_number: u64,
}

// ---------------------------------------------------------------------------
// ContextSnapshot
// ---------------------------------------------------------------------------

/// Authoritative context state at a point in time.
///
/// A snapshot is self-contained — it includes everything a reconnecting member
/// needs to determine what has changed and resume participation. Snapshots are
/// generated periodically and on significant state changes (membership changes,
/// governance actions, epoch advances).
///
/// See ADR-029 section 1 (Tier 2: state snapshot comparison and delta sync).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextSnapshot {
    /// The context this snapshot belongs to.
    pub context_id: ContextId,

    /// Unix timestamp (seconds) when this snapshot was taken.
    pub timestamp: u64,

    /// The MLS epoch at snapshot time. `None` for Broadcast contexts.
    pub mls_epoch: Option<u64>,

    /// Event log Merkle root at snapshot time.
    pub event_log_merkle_root: [u8; 32],

    /// Number of events in the log at snapshot time.
    pub event_count: u64,

    /// Current membership roster: DID -> membership entry.
    pub members: BTreeMap<String, MembershipEntry>,

    /// Active role definitions: role name -> set of capability names.
    pub role_definitions: BTreeMap<String, Vec<String>>,

    /// Context parameters hash (SHA-256 of serialized `ContextParams`).
    ///
    /// We store the hash rather than the full params to keep snapshots compact.
    /// The reconnecting member can verify the hash against their local params
    /// copy and fetch the full params only if they differ.
    pub params_hash: [u8; 32],

    /// Tool registrations active at snapshot time.
    pub tool_names: Vec<String>,

    /// DID of the snapshot creator (for verification).
    pub creator_did: DID,

    /// Ed25519 signature over all fields (except signature itself).
    #[serde(with = "serde_bytes")]
    pub signature: Ed25519Signature,

    /// Snapshot sequence number. Monotonically increasing per context.
    pub sequence: u64,
}

// ---------------------------------------------------------------------------
// MembershipChange
// ---------------------------------------------------------------------------

/// A change to a single member's state between two snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MembershipChange {
    /// A new member joined.
    Joined(MembershipEntry),
    /// An existing member left or was removed.
    Left {
        /// The DID of the member who left.
        did: DID,
    },
    /// A member's role changed.
    RoleChanged {
        /// The member's DID.
        did: DID,
        /// Previous role name.
        old_role: String,
        /// New role name.
        new_role: String,
    },
}

// ---------------------------------------------------------------------------
// SnapshotDelta
// ---------------------------------------------------------------------------

/// Differences between two [`ContextSnapshot`]s.
///
/// A delta captures everything that changed between the member's last known
/// state and the current state. The reconnecting member applies this delta to
/// update their local state without replaying the full event history.
///
/// See ADR-029 section 1 (Tier 2 strategy).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotDelta {
    /// The context this delta applies to.
    pub context_id: ContextId,

    /// Snapshot sequence the delta is computed from (the old/stale snapshot).
    pub from_sequence: u64,

    /// Snapshot sequence the delta targets (the new/current snapshot).
    pub to_sequence: u64,

    /// MLS epoch at the old snapshot.
    pub from_epoch: Option<u64>,

    /// MLS epoch at the new snapshot.
    pub to_epoch: Option<u64>,

    /// Membership changes between the two snapshots.
    pub membership_changes: Vec<MembershipChange>,

    /// Role definitions that were added or modified.
    pub role_definition_changes: BTreeMap<String, Vec<String>>,

    /// Role definitions that were removed.
    pub removed_role_definitions: Vec<String>,

    /// Tools that were added.
    pub added_tools: Vec<String>,

    /// Tools that were removed.
    pub removed_tools: Vec<String>,

    /// Whether context parameters changed (params hash differs).
    pub params_changed: bool,

    /// Number of events added between the two snapshots.
    pub events_added: u64,

    /// Old Merkle root (from the stale snapshot).
    pub old_merkle_root: [u8; 32],

    /// New Merkle root (from the current snapshot).
    pub new_merkle_root: [u8; 32],
}

// ---------------------------------------------------------------------------
// MlsRecoveryAction
// ---------------------------------------------------------------------------

/// Determines how MLS group state should be rebuilt after extended offline.
///
/// The action depends on the epoch gap: small gaps use sequential Commit
/// processing (Tier 1 mechanism), large gaps use Welcome-based fast-forward
/// (Tier 2 fallback).
///
/// See ADR-029 section 3.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MlsRecoveryAction {
    /// No MLS recovery needed — context is Broadcast mode or epoch is current.
    NoAction,
    /// Sequential Commit processing: process each missed Commit in order.
    SequentialCatchUp {
        /// First epoch to process.
        from_epoch: u64,
        /// Target epoch (inclusive).
        to_epoch: u64,
    },
    /// Welcome-based fast-forward: request a fresh Welcome message.
    ///
    /// Used when the epoch gap exceeds [`MAX_EPOCH_GAP_FOR_SEQUENTIAL`].
    WelcomeFastForward {
        /// Local stale epoch.
        stale_epoch: u64,
        /// Current group epoch.
        current_epoch: u64,
    },
}

// ---------------------------------------------------------------------------
// DeviceSyncState
// ---------------------------------------------------------------------------

/// Per-device offline state for multi-device divergence detection.
///
/// Each device independently tracks when it last contacted a relay and its
/// last known MLS epoch. When multiple devices reconnect, each computes its
/// own delta. Divergence is detected by comparing Merkle roots from each
/// device's local snapshot against the authoritative current snapshot.
///
/// See ADR-029 section 7 (Multi-Device Coordination).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceSyncState {
    /// Opaque device identifier (unique per device, stable across sessions).
    pub device_id: String,

    /// The DID of the identity that owns this device.
    pub owner_did: DID,

    /// Unix timestamp (seconds) of last successful relay interaction.
    pub last_relay_contact: u64,

    /// Last known MLS epoch on this device. `None` for Broadcast contexts.
    pub last_known_epoch: Option<u64>,

    /// Merkle root of the event log on this device.
    pub local_merkle_root: [u8; 32],

    /// Event count on this device.
    pub local_event_count: u64,
}

/// Result of comparing two devices' sync states.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceDivergence {
    /// Both devices have the same state — no divergence.
    Consistent,

    /// One device is behind the other (same history, different lengths).
    Behind {
        /// Device ID of the device that is behind.
        behind_device: String,
        /// Number of events the behind device is missing.
        missing_events: u64,
    },

    /// Devices have divergent histories (different Merkle roots at the same
    /// event count). This indicates relay equivocation or a bug.
    Divergent {
        /// Device ID of the first device.
        device_a: String,
        /// Device ID of the second device.
        device_b: String,
        /// Event count where divergence was detected.
        event_count: u64,
    },
}

// ---------------------------------------------------------------------------
// DaysOfflineError
// ---------------------------------------------------------------------------

/// Errors specific to days-scale offline recovery.
#[derive(Debug, thiserror::Error)]
pub enum DaysOfflineError {
    /// The snapshot provider returned no snapshot for the context.
    #[error("no snapshot available for context {context_id}")]
    NoSnapshotAvailable {
        /// The context for which no snapshot was found.
        context_id: ContextId,
    },

    /// The snapshot's context ID does not match the expected context.
    #[error("snapshot context mismatch: expected {expected}, got {actual}")]
    ContextMismatch {
        /// Expected context ID.
        expected: ContextId,
        /// Actual context ID from the snapshot.
        actual: ContextId,
    },

    /// The delta cannot be applied because the `from_sequence` does not match
    /// the local snapshot's sequence.
    #[error("delta sequence mismatch: expected from_sequence {expected}, got {actual}")]
    DeltaSequenceMismatch {
        /// Expected `from_sequence` (local snapshot sequence).
        expected: u64,
        /// Actual `from_sequence` in the delta.
        actual: u64,
    },

    /// The snapshot signature verification failed.
    #[error("snapshot signature verification failed for context {context_id}")]
    SignatureVerificationFailed {
        /// The context with the bad signature.
        context_id: ContextId,
    },

    /// Multi-device divergence detected.
    #[error(
        "device divergence detected between {device_a} and {device_b} \
         at event count {event_count}"
    )]
    DeviceDivergenceDetected {
        /// First device ID.
        device_a: String,
        /// Second device ID.
        device_b: String,
        /// Event count where divergence was detected.
        event_count: u64,
    },

    /// MLS epoch gap too large — Welcome-based fast-forward required but not
    /// available.
    #[error(
        "MLS epoch gap too large ({gap} epochs) and fast-forward unavailable \
         for context {context_id}"
    )]
    EpochGapTooLarge {
        /// The context with the epoch gap.
        context_id: ContextId,
        /// Number of epochs the member is behind.
        gap: u64,
    },

    /// Underlying sync error.
    #[error("sync error: {0}")]
    Sync(#[from] SyncError),
}

// ---------------------------------------------------------------------------
// DeltaSyncEngine (trait)
// ---------------------------------------------------------------------------

/// Async interface for fetching snapshots and deltas from a sync provider.
///
/// The sync provider may be a relay, a peer, or local storage. Implementations
/// are responsible for transport, authentication, and retry logic. The trait
/// Note: uses `async fn in trait` which is NOT object-safe (cannot use
/// `dyn DeltaSyncEngine`). If dyn-dispatch is needed in the future, convert
/// to `BoxFuture` return types per the `TransportAdapter` pattern.
///
/// See ADR-029 section 1 (Tier 2 strategy).
#[allow(async_fn_in_trait)]
pub trait DeltaSyncEngine: Send + Sync {
    /// Fetches the most recent snapshot for a context.
    ///
    /// Returns `None` if no snapshot is available (e.g., context was just
    /// created and no snapshot has been taken yet).
    async fn fetch_snapshot(
        &self,
        context_id: &str,
    ) -> Result<Option<ContextSnapshot>, DaysOfflineError>;

    /// Fetches a delta between two snapshot sequences for a context.
    ///
    /// The provider computes the delta between `from_sequence` and the
    /// latest snapshot. Returns `None` if the provider cannot compute the
    /// delta (e.g., the `from_sequence` snapshot has been pruned).
    async fn fetch_delta(
        &self,
        context_id: &str,
        from_sequence: u64,
    ) -> Result<Option<SnapshotDelta>, DaysOfflineError>;

    /// Publishes a snapshot to the sync provider.
    ///
    /// Called after local snapshot creation so other members and devices can
    /// retrieve it for delta computation.
    async fn publish_snapshot(&self, snapshot: &ContextSnapshot) -> Result<(), DaysOfflineError>;
}

// ---------------------------------------------------------------------------
// compute_delta
// ---------------------------------------------------------------------------

/// Computes the differences between two [`ContextSnapshot`]s.
///
/// The `old` snapshot represents the reconnecting member's stale local state.
/// The `new` snapshot represents the current authoritative state. The returned
/// [`SnapshotDelta`] contains everything needed to update the local state.
///
/// # Errors
///
/// Returns [`DaysOfflineError::ContextMismatch`] if the two snapshots belong
/// to different contexts.
pub fn compute_delta(
    old: &ContextSnapshot,
    new: &ContextSnapshot,
) -> Result<SnapshotDelta, DaysOfflineError> {
    if old.context_id != new.context_id {
        return Err(DaysOfflineError::ContextMismatch {
            expected: old.context_id.clone(),
            actual: new.context_id.clone(),
        });
    }

    // Membership changes
    let old_dids: HashSet<&str> = old.members.keys().map(String::as_str).collect();
    let new_dids: HashSet<&str> = new.members.keys().map(String::as_str).collect();

    let mut membership_changes = Vec::new();

    // Members who joined (in new but not in old)
    for did in &new_dids {
        if !old_dids.contains(did)
            && let Some(entry) = new.members.get(*did) {
                membership_changes.push(MembershipChange::Joined(entry.clone()));
            }
    }

    // Members who left (in old but not in new)
    for did in &old_dids {
        if !new_dids.contains(did) {
            membership_changes.push(MembershipChange::Left {
                did: DID::from(*did),
            });
        }
    }

    // Members whose role changed (in both, but different role)
    for did in old_dids.intersection(&new_dids) {
        if let (Some(old_entry), Some(new_entry)) = (old.members.get(*did), new.members.get(*did))
            && old_entry.role_name != new_entry.role_name {
                membership_changes.push(MembershipChange::RoleChanged {
                    did: DID::from(*did),
                    old_role: old_entry.role_name.clone(),
                    new_role: new_entry.role_name.clone(),
                });
            }
    }

    // Role definition changes
    let mut role_definition_changes = BTreeMap::new();
    let mut removed_role_definitions = Vec::new();

    for (name, caps) in &new.role_definitions {
        match old.role_definitions.get(name) {
            Some(old_caps) if old_caps != caps => {
                role_definition_changes.insert(name.clone(), caps.clone());
            }
            None => {
                role_definition_changes.insert(name.clone(), caps.clone());
            }
            _ => {}
        }
    }
    for name in old.role_definitions.keys() {
        if !new.role_definitions.contains_key(name) {
            removed_role_definitions.push(name.clone());
        }
    }

    // Tool changes
    let old_tools: HashSet<&str> = old.tool_names.iter().map(String::as_str).collect();
    let new_tools: HashSet<&str> = new.tool_names.iter().map(String::as_str).collect();

    let added_tools: Vec<String> = new_tools
        .difference(&old_tools)
        .map(|s| (*s).to_owned())
        .collect();
    let removed_tools: Vec<String> = old_tools
        .difference(&new_tools)
        .map(|s| (*s).to_owned())
        .collect();

    // Params changed
    let params_changed = old.params_hash != new.params_hash;

    // Events added
    let events_added = new.event_count.saturating_sub(old.event_count);

    Ok(SnapshotDelta {
        context_id: old.context_id.clone(),
        from_sequence: old.sequence,
        to_sequence: new.sequence,
        from_epoch: old.mls_epoch,
        to_epoch: new.mls_epoch,
        membership_changes,
        role_definition_changes,
        removed_role_definitions,
        added_tools,
        removed_tools,
        params_changed,
        events_added,
        old_merkle_root: old.event_log_merkle_root,
        new_merkle_root: new.event_log_merkle_root,
    })
}

// ---------------------------------------------------------------------------
// apply_delta
// ---------------------------------------------------------------------------

/// Applies a [`SnapshotDelta`] to a local [`ContextSnapshot`], producing the
/// updated state.
///
/// This function mutates the local snapshot in-place, applying membership
/// changes, role definition updates, tool changes, and advancing the event
/// log state. MLS epoch is advanced but actual MLS group rebuild is the
/// caller's responsibility (see [`determine_mls_recovery`]).
///
/// # Errors
///
/// Returns [`DaysOfflineError::ContextMismatch`] if the delta's context ID
/// does not match the local snapshot.
///
/// Returns [`DaysOfflineError::DeltaSequenceMismatch`] if the delta's
/// `from_sequence` does not match the local snapshot's sequence.
pub fn apply_delta(
    local_state: &mut ContextSnapshot,
    delta: &SnapshotDelta,
) -> Result<(), DaysOfflineError> {
    if local_state.context_id != delta.context_id {
        return Err(DaysOfflineError::ContextMismatch {
            expected: local_state.context_id.clone(),
            actual: delta.context_id.clone(),
        });
    }

    if local_state.sequence != delta.from_sequence {
        return Err(DaysOfflineError::DeltaSequenceMismatch {
            expected: local_state.sequence,
            actual: delta.from_sequence,
        });
    }

    // Apply membership changes
    for change in &delta.membership_changes {
        match change {
            MembershipChange::Joined(entry) => {
                local_state
                    .members
                    .insert(entry.did.0.clone(), entry.clone());
            }
            MembershipChange::Left { did } => {
                local_state.members.remove(&did.0);
            }
            MembershipChange::RoleChanged { did, new_role, .. } => {
                if let Some(entry) = local_state.members.get_mut(&did.0) {
                    entry.role_name.clone_from(new_role);
                }
            }
        }
    }

    // Apply role definition changes
    for (name, caps) in &delta.role_definition_changes {
        local_state
            .role_definitions
            .insert(name.clone(), caps.clone());
    }
    for name in &delta.removed_role_definitions {
        local_state.role_definitions.remove(name);
    }

    // Apply tool changes
    let mut tools: HashSet<String> = local_state.tool_names.drain(..).collect();
    for name in &delta.added_tools {
        tools.insert(name.clone());
    }
    for name in &delta.removed_tools {
        tools.remove(name);
    }
    local_state.tool_names = tools.into_iter().collect();
    local_state.tool_names.sort();

    // Advance event log state
    local_state.event_count += delta.events_added;
    local_state.event_log_merkle_root = delta.new_merkle_root;

    // Advance epoch and snapshot sequence
    local_state.mls_epoch = delta.to_epoch;
    local_state.sequence = delta.to_sequence;

    Ok(())
}

// ---------------------------------------------------------------------------
// determine_mls_recovery
// ---------------------------------------------------------------------------

/// Determines the appropriate MLS recovery action based on the epoch gap.
///
/// The decision follows ADR-029 section 3:
/// - Epoch gap <= [`MAX_EPOCH_GAP_FOR_SEQUENTIAL`] (100): sequential Commit
///   processing.
/// - Epoch gap > 100: Welcome-based fast-forward.
/// - Broadcast contexts (no MLS epoch): no action.
///
/// See ADR-029 section 3 (MLS Epoch Catch-Up).
#[must_use]
pub const fn determine_mls_recovery(delta: &SnapshotDelta) -> MlsRecoveryAction {
    match (delta.from_epoch, delta.to_epoch) {
        (Some(from), Some(to)) if from == to => MlsRecoveryAction::NoAction,
        (Some(from), Some(to)) => {
            let gap = to.saturating_sub(from);
            if gap <= MAX_EPOCH_GAP_FOR_SEQUENTIAL {
                MlsRecoveryAction::SequentialCatchUp {
                    from_epoch: from,
                    to_epoch: to,
                }
            } else {
                MlsRecoveryAction::WelcomeFastForward {
                    stale_epoch: from,
                    current_epoch: to,
                }
            }
        }
        // (None, None) = broadcast context, or mismatched None/Some —
        // anomalous state; treat as no action (caller handles).
        _ => MlsRecoveryAction::NoAction,
    }
}

// ---------------------------------------------------------------------------
// detect_device_divergence
// ---------------------------------------------------------------------------

/// Detects divergence between two devices' sync states.
///
/// Compares the Merkle roots and event counts of two devices. If one device
/// has more events but the Merkle roots are consistent (one is a prefix of
/// the other), the lagging device is behind. If roots differ at the same
/// event count, the devices have diverged (relay equivocation).
///
/// See ADR-029 section 7 (Multi-Device Coordination).
#[must_use]
pub fn detect_device_divergence(
    device_a: &DeviceSyncState,
    device_b: &DeviceSyncState,
) -> DeviceDivergence {
    if device_a.local_merkle_root == device_b.local_merkle_root
        && device_a.local_event_count == device_b.local_event_count
    {
        return DeviceDivergence::Consistent;
    }

    if device_a.local_event_count != device_b.local_event_count {
        // One device has more events. This is the expected case: one device
        // was online longer. The device with fewer events is behind.
        // We cannot verify prefix consistency without the full Merkle tree,
        // so we report which device is behind.
        if device_a.local_event_count < device_b.local_event_count {
            return DeviceDivergence::Behind {
                behind_device: device_a.device_id.clone(),
                missing_events: device_b
                    .local_event_count
                    .saturating_sub(device_a.local_event_count),
            };
        }
        return DeviceDivergence::Behind {
            behind_device: device_b.device_id.clone(),
            missing_events: device_a
                .local_event_count
                .saturating_sub(device_b.local_event_count),
        };
    }

    // Same event count but different Merkle roots — divergence.
    DeviceDivergence::Divergent {
        device_a: device_a.device_id.clone(),
        device_b: device_b.device_id.clone(),
        event_count: device_a.local_event_count,
    }
}

// ---------------------------------------------------------------------------
// DaysOfflineSyncResult
// ---------------------------------------------------------------------------

/// Result of a days-scale offline sync attempt for a single context.
///
/// Returned by the high-level sync orchestration (not part of this module's
/// public API — the orchestrator lives in the reconnection coordinator).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaysOfflineSyncResult {
    /// The context that was synced.
    pub context_id: ContextId,

    /// The delta that was applied (if any).
    pub delta_applied: Option<SnapshotDelta>,

    /// The MLS recovery action taken.
    pub mls_recovery: MlsRecoveryAction,

    /// Number of events recovered.
    pub events_recovered: u64,

    /// Overall sync outcome.
    pub outcome: SyncOutcome,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn make_snapshot(
        context_id: &str,
        sequence: u64,
        epoch: Option<u64>,
        event_count: u64,
        merkle_root: [u8; 32],
        members: Vec<(&str, &str)>,
    ) -> ContextSnapshot {
        let members_map: BTreeMap<String, MembershipEntry> = members
            .into_iter()
            .map(|(did, role)| {
                (
                    did.to_owned(),
                    MembershipEntry {
                        did: DID::from(did),
                        role_name: role.to_owned(),
                        sequence_number: 0,
                    },
                )
            })
            .collect();

        ContextSnapshot {
            context_id: context_id.to_owned(),
            timestamp: 1_700_000_000 + sequence * 1000,
            mls_epoch: epoch,
            event_log_merkle_root: merkle_root,
            event_count,
            members: members_map,
            role_definitions: BTreeMap::new(),
            params_hash: [0u8; 32],
            tool_names: Vec::new(),
            creator_did: DID::from("did:dht:z6MkCreator"),
            signature: vec![0u8; 64],
            sequence,
        }
    }

    fn make_device_state(
        device_id: &str,
        event_count: u64,
        merkle_root: [u8; 32],
    ) -> DeviceSyncState {
        DeviceSyncState {
            device_id: device_id.to_owned(),
            owner_did: DID::from("did:dht:z6MkOwner"),
            last_relay_contact: 1_700_000_000,
            last_known_epoch: Some(10),
            local_merkle_root: merkle_root,
            local_event_count: event_count,
        }
    }

    // -----------------------------------------------------------------------
    // compute_delta tests
    // -----------------------------------------------------------------------

    #[test]
    fn compute_delta_identical_snapshots() {
        let root = [1u8; 32];
        let old = make_snapshot(
            "ctx-1",
            1,
            Some(10),
            100,
            root,
            vec![("did:alice", "admin")],
        );
        let new = old.clone();

        let delta = compute_delta(&old, &new).unwrap();

        assert!(delta.membership_changes.is_empty());
        assert!(delta.role_definition_changes.is_empty());
        assert!(delta.removed_role_definitions.is_empty());
        assert!(delta.added_tools.is_empty());
        assert!(delta.removed_tools.is_empty());
        assert!(!delta.params_changed);
        assert_eq!(delta.events_added, 0);
        assert_eq!(delta.from_sequence, 1);
        assert_eq!(delta.to_sequence, 1);
    }

    #[test]
    fn compute_delta_context_mismatch_errors() {
        let old = make_snapshot("ctx-1", 1, Some(10), 100, [1u8; 32], vec![]);
        let new = make_snapshot("ctx-2", 2, Some(20), 200, [2u8; 32], vec![]);

        let err = compute_delta(&old, &new).unwrap_err();
        match err {
            DaysOfflineError::ContextMismatch { expected, actual } => {
                assert_eq!(expected, "ctx-1");
                assert_eq!(actual, "ctx-2");
            }
            _ => panic!("unexpected error: {err:?}"),
        }
    }

    #[test]
    fn compute_delta_member_joined() {
        let old = make_snapshot(
            "ctx-1",
            1,
            Some(10),
            100,
            [1u8; 32],
            vec![("did:alice", "admin")],
        );
        let new = make_snapshot(
            "ctx-1",
            2,
            Some(15),
            150,
            [2u8; 32],
            vec![("did:alice", "admin"), ("did:bob", "member")],
        );

        let delta = compute_delta(&old, &new).unwrap();

        assert_eq!(delta.membership_changes.len(), 1);
        match &delta.membership_changes[0] {
            MembershipChange::Joined(entry) => {
                assert_eq!(entry.did, "did:bob");
                assert_eq!(entry.role_name, "member");
            }
            _ => panic!("expected Joined"),
        }
        assert_eq!(delta.events_added, 50);
    }

    #[test]
    fn compute_delta_member_left() {
        let old = make_snapshot(
            "ctx-1",
            1,
            Some(10),
            100,
            [1u8; 32],
            vec![("did:alice", "admin"), ("did:bob", "member")],
        );
        let new = make_snapshot(
            "ctx-1",
            2,
            Some(15),
            150,
            [2u8; 32],
            vec![("did:alice", "admin")],
        );

        let delta = compute_delta(&old, &new).unwrap();

        assert_eq!(delta.membership_changes.len(), 1);
        match &delta.membership_changes[0] {
            MembershipChange::Left { did } => {
                assert_eq!(did, "did:bob");
            }
            _ => panic!("expected Left"),
        }
    }

    #[test]
    fn compute_delta_member_role_changed() {
        let old = make_snapshot(
            "ctx-1",
            1,
            Some(10),
            100,
            [1u8; 32],
            vec![("did:bob", "member")],
        );
        let new = make_snapshot(
            "ctx-1",
            2,
            Some(15),
            150,
            [2u8; 32],
            vec![("did:bob", "admin")],
        );

        let delta = compute_delta(&old, &new).unwrap();

        assert_eq!(delta.membership_changes.len(), 1);
        match &delta.membership_changes[0] {
            MembershipChange::RoleChanged {
                did,
                old_role,
                new_role,
            } => {
                assert_eq!(did, "did:bob");
                assert_eq!(old_role, "member");
                assert_eq!(new_role, "admin");
            }
            _ => panic!("expected RoleChanged"),
        }
    }

    #[test]
    fn compute_delta_tool_changes() {
        let mut old = make_snapshot("ctx-1", 1, Some(10), 100, [1u8; 32], vec![]);
        old.tool_names = vec!["search".to_owned(), "translate".to_owned()];

        let mut new = make_snapshot("ctx-1", 2, Some(15), 150, [2u8; 32], vec![]);
        new.tool_names = vec!["search".to_owned(), "summarize".to_owned()];

        let delta = compute_delta(&old, &new).unwrap();

        assert_eq!(delta.added_tools, vec!["summarize"]);
        assert_eq!(delta.removed_tools, vec!["translate"]);
    }

    #[test]
    fn compute_delta_params_changed() {
        let old = make_snapshot("ctx-1", 1, Some(10), 100, [1u8; 32], vec![]);
        let mut new = make_snapshot("ctx-1", 2, Some(15), 150, [2u8; 32], vec![]);
        new.params_hash = [42u8; 32];

        let delta = compute_delta(&old, &new).unwrap();
        assert!(delta.params_changed);
    }

    #[test]
    fn compute_delta_role_definitions_added_and_removed() {
        let mut old = make_snapshot("ctx-1", 1, Some(10), 100, [1u8; 32], vec![]);
        old.role_definitions.insert(
            "editor".to_owned(),
            vec!["messages:read".to_owned(), "messages:write".to_owned()],
        );
        old.role_definitions
            .insert("viewer".to_owned(), vec!["messages:read".to_owned()]);

        let mut new = make_snapshot("ctx-1", 2, Some(15), 150, [2u8; 32], vec![]);
        // "editor" modified (added a capability)
        new.role_definitions.insert(
            "editor".to_owned(),
            vec![
                "messages:read".to_owned(),
                "messages:write".to_owned(),
                "tool:invoke".to_owned(),
            ],
        );
        // "viewer" removed, "moderator" added
        new.role_definitions
            .insert("moderator".to_owned(), vec!["messages:read".to_owned()]);

        let delta = compute_delta(&old, &new).unwrap();

        assert!(delta.role_definition_changes.contains_key("editor"));
        assert!(delta.role_definition_changes.contains_key("moderator"));
        assert!(
            delta
                .removed_role_definitions
                .contains(&"viewer".to_owned())
        );
    }

    // -----------------------------------------------------------------------
    // apply_delta tests
    // -----------------------------------------------------------------------

    #[test]
    fn apply_delta_updates_membership() {
        let mut local = make_snapshot(
            "ctx-1",
            1,
            Some(10),
            100,
            [1u8; 32],
            vec![("did:alice", "admin")],
        );
        let remote = make_snapshot(
            "ctx-1",
            2,
            Some(15),
            150,
            [2u8; 32],
            vec![("did:alice", "admin"), ("did:bob", "member")],
        );

        let delta = compute_delta(&local, &remote).unwrap();
        apply_delta(&mut local, &delta).unwrap();

        assert_eq!(local.members.len(), 2);
        assert!(local.members.contains_key("did:bob"));
        assert_eq!(local.mls_epoch, Some(15));
        assert_eq!(local.event_count, 150);
        assert_eq!(local.sequence, 2);
    }

    #[test]
    fn apply_delta_context_mismatch_errors() {
        let mut local = make_snapshot("ctx-1", 1, Some(10), 100, [1u8; 32], vec![]);

        let delta = SnapshotDelta {
            context_id: "ctx-2".to_owned(),
            from_sequence: 1,
            to_sequence: 2,
            from_epoch: Some(10),
            to_epoch: Some(15),
            membership_changes: vec![],
            role_definition_changes: BTreeMap::new(),
            removed_role_definitions: vec![],
            added_tools: vec![],
            removed_tools: vec![],
            params_changed: false,
            events_added: 50,
            old_merkle_root: [1u8; 32],
            new_merkle_root: [2u8; 32],
        };

        let err = apply_delta(&mut local, &delta).unwrap_err();
        assert!(matches!(err, DaysOfflineError::ContextMismatch { .. }));
    }

    #[test]
    fn apply_delta_sequence_mismatch_errors() {
        let mut local = make_snapshot("ctx-1", 1, Some(10), 100, [1u8; 32], vec![]);

        let delta = SnapshotDelta {
            context_id: "ctx-1".to_owned(),
            from_sequence: 5, // mismatch: local is at sequence 1
            to_sequence: 6,
            from_epoch: Some(10),
            to_epoch: Some(15),
            membership_changes: vec![],
            role_definition_changes: BTreeMap::new(),
            removed_role_definitions: vec![],
            added_tools: vec![],
            removed_tools: vec![],
            params_changed: false,
            events_added: 50,
            old_merkle_root: [1u8; 32],
            new_merkle_root: [2u8; 32],
        };

        let err = apply_delta(&mut local, &delta).unwrap_err();
        assert!(matches!(
            err,
            DaysOfflineError::DeltaSequenceMismatch { .. }
        ));
    }

    #[test]
    fn apply_delta_removes_member_and_tools() {
        let mut local = make_snapshot(
            "ctx-1",
            1,
            Some(10),
            100,
            [1u8; 32],
            vec![("did:alice", "admin"), ("did:bob", "member")],
        );
        local.tool_names = vec!["search".to_owned(), "translate".to_owned()];

        let delta = SnapshotDelta {
            context_id: "ctx-1".to_owned(),
            from_sequence: 1,
            to_sequence: 2,
            from_epoch: Some(10),
            to_epoch: Some(15),
            membership_changes: vec![MembershipChange::Left {
                did: DID::from("did:bob"),
            }],
            role_definition_changes: BTreeMap::new(),
            removed_role_definitions: vec![],
            added_tools: vec!["summarize".to_owned()],
            removed_tools: vec!["translate".to_owned()],
            params_changed: false,
            events_added: 50,
            old_merkle_root: [1u8; 32],
            new_merkle_root: [2u8; 32],
        };

        apply_delta(&mut local, &delta).unwrap();

        assert_eq!(local.members.len(), 1);
        assert!(!local.members.contains_key("did:bob"));
        assert!(local.tool_names.contains(&"search".to_owned()));
        assert!(local.tool_names.contains(&"summarize".to_owned()));
        assert!(!local.tool_names.contains(&"translate".to_owned()));
    }

    // -----------------------------------------------------------------------
    // determine_mls_recovery tests
    // -----------------------------------------------------------------------

    #[test]
    fn mls_recovery_no_action_for_broadcast() {
        let delta = SnapshotDelta {
            context_id: "ctx-1".to_owned(),
            from_sequence: 1,
            to_sequence: 2,
            from_epoch: None,
            to_epoch: None,
            membership_changes: vec![],
            role_definition_changes: BTreeMap::new(),
            removed_role_definitions: vec![],
            added_tools: vec![],
            removed_tools: vec![],
            params_changed: false,
            events_added: 0,
            old_merkle_root: [0u8; 32],
            new_merkle_root: [0u8; 32],
        };

        assert_eq!(determine_mls_recovery(&delta), MlsRecoveryAction::NoAction);
    }

    #[test]
    fn mls_recovery_no_action_for_same_epoch() {
        let delta = SnapshotDelta {
            context_id: "ctx-1".to_owned(),
            from_sequence: 1,
            to_sequence: 2,
            from_epoch: Some(10),
            to_epoch: Some(10),
            membership_changes: vec![],
            role_definition_changes: BTreeMap::new(),
            removed_role_definitions: vec![],
            added_tools: vec![],
            removed_tools: vec![],
            params_changed: false,
            events_added: 50,
            old_merkle_root: [0u8; 32],
            new_merkle_root: [0u8; 32],
        };

        assert_eq!(determine_mls_recovery(&delta), MlsRecoveryAction::NoAction);
    }

    #[test]
    fn mls_recovery_sequential_for_small_gap() {
        let delta = SnapshotDelta {
            context_id: "ctx-1".to_owned(),
            from_sequence: 1,
            to_sequence: 2,
            from_epoch: Some(10),
            to_epoch: Some(60),
            membership_changes: vec![],
            role_definition_changes: BTreeMap::new(),
            removed_role_definitions: vec![],
            added_tools: vec![],
            removed_tools: vec![],
            params_changed: false,
            events_added: 500,
            old_merkle_root: [0u8; 32],
            new_merkle_root: [0u8; 32],
        };

        assert_eq!(
            determine_mls_recovery(&delta),
            MlsRecoveryAction::SequentialCatchUp {
                from_epoch: 10,
                to_epoch: 60,
            }
        );
    }

    #[test]
    fn mls_recovery_sequential_at_boundary() {
        let delta = SnapshotDelta {
            context_id: "ctx-1".to_owned(),
            from_sequence: 1,
            to_sequence: 2,
            from_epoch: Some(10),
            to_epoch: Some(110), // gap = 100 = MAX_SEQUENTIAL_COMMITS
            membership_changes: vec![],
            role_definition_changes: BTreeMap::new(),
            removed_role_definitions: vec![],
            added_tools: vec![],
            removed_tools: vec![],
            params_changed: false,
            events_added: 1000,
            old_merkle_root: [0u8; 32],
            new_merkle_root: [0u8; 32],
        };

        assert_eq!(
            determine_mls_recovery(&delta),
            MlsRecoveryAction::SequentialCatchUp {
                from_epoch: 10,
                to_epoch: 110,
            }
        );
    }

    #[test]
    fn mls_recovery_fast_forward_for_large_gap() {
        let delta = SnapshotDelta {
            context_id: "ctx-1".to_owned(),
            from_sequence: 1,
            to_sequence: 2,
            from_epoch: Some(10),
            to_epoch: Some(200), // gap = 190 > 100
            membership_changes: vec![],
            role_definition_changes: BTreeMap::new(),
            removed_role_definitions: vec![],
            added_tools: vec![],
            removed_tools: vec![],
            params_changed: false,
            events_added: 2000,
            old_merkle_root: [0u8; 32],
            new_merkle_root: [0u8; 32],
        };

        assert_eq!(
            determine_mls_recovery(&delta),
            MlsRecoveryAction::WelcomeFastForward {
                stale_epoch: 10,
                current_epoch: 200,
            }
        );
    }

    // -----------------------------------------------------------------------
    // detect_device_divergence tests
    // -----------------------------------------------------------------------

    #[test]
    fn device_divergence_consistent() {
        let root = [1u8; 32];
        let a = make_device_state("phone", 100, root);
        let b = make_device_state("laptop", 100, root);

        assert_eq!(
            detect_device_divergence(&a, &b),
            DeviceDivergence::Consistent,
        );
    }

    #[test]
    fn device_divergence_one_behind() {
        let root_a = [1u8; 32];
        let root_b = [2u8; 32];
        let a = make_device_state("phone", 80, root_a);
        let b = make_device_state("laptop", 100, root_b);

        let result = detect_device_divergence(&a, &b);
        match result {
            DeviceDivergence::Behind {
                behind_device,
                missing_events,
            } => {
                assert_eq!(behind_device, "phone");
                assert_eq!(missing_events, 20);
            }
            _ => panic!("expected Behind"),
        }
    }

    #[test]
    fn device_divergence_detected() {
        let root_a = [1u8; 32];
        let root_b = [2u8; 32];
        let a = make_device_state("phone", 100, root_a);
        let b = make_device_state("laptop", 100, root_b);

        let result = detect_device_divergence(&a, &b);
        match result {
            DeviceDivergence::Divergent {
                device_a,
                device_b,
                event_count,
            } => {
                assert_eq!(device_a, "phone");
                assert_eq!(device_b, "laptop");
                assert_eq!(event_count, 100);
            }
            _ => panic!("expected Divergent"),
        }
    }

    // -----------------------------------------------------------------------
    // SnapshotDelta serialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn snapshot_delta_serialization_roundtrip() {
        let delta = SnapshotDelta {
            context_id: "ctx-1".to_owned(),
            from_sequence: 1,
            to_sequence: 5,
            from_epoch: Some(10),
            to_epoch: Some(50),
            membership_changes: vec![
                MembershipChange::Joined(MembershipEntry {
                    did: DID::from("did:bob"),
                    role_name: "member".to_owned(),
                    sequence_number: 0,
                }),
                MembershipChange::Left {
                    did: DID::from("did:charlie"),
                },
            ],
            role_definition_changes: BTreeMap::new(),
            removed_role_definitions: vec![],
            added_tools: vec!["new-tool".to_owned()],
            removed_tools: vec![],
            params_changed: true,
            events_added: 400,
            old_merkle_root: [1u8; 32],
            new_merkle_root: [2u8; 32],
        };

        let json = serde_json::to_string(&delta).unwrap();
        let deserialized: SnapshotDelta = serde_json::from_str(&json).unwrap();
        assert_eq!(delta, deserialized);
    }

    #[test]
    fn context_snapshot_serialization_roundtrip() {
        let snapshot = make_snapshot(
            "ctx-1",
            3,
            Some(25),
            500,
            [42u8; 32],
            vec![("did:alice", "admin"), ("did:bob", "member")],
        );

        let json = serde_json::to_string(&snapshot).unwrap();
        let deserialized: ContextSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snapshot, deserialized);
    }

    #[test]
    fn mls_recovery_action_serialization_roundtrip() {
        let actions = vec![
            MlsRecoveryAction::NoAction,
            MlsRecoveryAction::SequentialCatchUp {
                from_epoch: 5,
                to_epoch: 50,
            },
            MlsRecoveryAction::WelcomeFastForward {
                stale_epoch: 10,
                current_epoch: 200,
            },
        ];

        for action in &actions {
            let json = serde_json::to_string(action).unwrap();
            let deserialized: MlsRecoveryAction = serde_json::from_str(&json).unwrap();
            assert_eq!(*action, deserialized);
        }
    }

    // -----------------------------------------------------------------------
    // DaysOfflineError display tests
    // -----------------------------------------------------------------------

    #[test]
    fn days_offline_error_display_messages() {
        let err = DaysOfflineError::NoSnapshotAvailable {
            context_id: "ctx-1".to_owned(),
        };
        assert!(err.to_string().contains("ctx-1"));

        let err = DaysOfflineError::EpochGapTooLarge {
            context_id: "ctx-2".to_owned(),
            gap: 250,
        };
        assert!(err.to_string().contains("250"));
        assert!(err.to_string().contains("ctx-2"));
    }

    // -----------------------------------------------------------------------
    // Stress tests: simulated days-offline scenarios
    // -----------------------------------------------------------------------

    #[test]
    fn stress_large_membership_churn() {
        // Simulate a context where many members joined and left during a
        // multi-day offline period.
        let mut old_members: Vec<(&str, &str)> = Vec::new();
        let original_members = [
            "did:m001", "did:m002", "did:m003", "did:m004", "did:m005", "did:m006", "did:m007",
            "did:m008", "did:m009", "did:m010",
        ];
        for did in &original_members {
            old_members.push((did, "member"));
        }
        old_members.push(("did:admin", "admin"));

        let old = make_snapshot("ctx-stress", 1, Some(10), 1000, [1u8; 32], old_members);

        // New state: half the original members left, 15 new members joined,
        // and the admin's role didn't change. 200 epochs advanced.
        let mut new_members: Vec<(&str, &str)> = vec![("did:admin", "admin")];
        // Keep m001-m005
        for did in &original_members[..5] {
            new_members.push((did, "member"));
        }
        // 15 new members
        let new_member_dids = [
            "did:n001", "did:n002", "did:n003", "did:n004", "did:n005", "did:n006", "did:n007",
            "did:n008", "did:n009", "did:n010", "did:n011", "did:n012", "did:n013", "did:n014",
            "did:n015",
        ];
        for did in &new_member_dids {
            new_members.push((did, "member"));
        }

        let new = make_snapshot("ctx-stress", 10, Some(210), 5000, [2u8; 32], new_members);

        let delta = compute_delta(&old, &new).unwrap();

        // Verify: 5 members left (m006-m010), 15 joined (n001-n015)
        let joined_count = delta
            .membership_changes
            .iter()
            .filter(|c| matches!(c, MembershipChange::Joined(_)))
            .count();
        let left_count = delta
            .membership_changes
            .iter()
            .filter(|c| matches!(c, MembershipChange::Left { .. }))
            .count();

        assert_eq!(joined_count, 15);
        assert_eq!(left_count, 5);
        assert_eq!(delta.events_added, 4000);

        // MLS recovery should be fast-forward (210 - 10 = 200 > 100)
        let recovery = determine_mls_recovery(&delta);
        assert_eq!(
            recovery,
            MlsRecoveryAction::WelcomeFastForward {
                stale_epoch: 10,
                current_epoch: 210,
            }
        );

        // Apply delta and verify final state
        let mut local = make_snapshot(
            "ctx-stress",
            1,
            Some(10),
            1000,
            [1u8; 32],
            vec![
                ("did:admin", "admin"),
                ("did:m001", "member"),
                ("did:m002", "member"),
                ("did:m003", "member"),
                ("did:m004", "member"),
                ("did:m005", "member"),
                ("did:m006", "member"),
                ("did:m007", "member"),
                ("did:m008", "member"),
                ("did:m009", "member"),
                ("did:m010", "member"),
            ],
        );

        apply_delta(&mut local, &delta).unwrap();

        // 1 admin + 5 remaining original + 15 new = 21
        assert_eq!(local.members.len(), 21);
        assert!(local.members.contains_key("did:admin"));
        assert!(local.members.contains_key("did:m001"));
        assert!(!local.members.contains_key("did:m006"));
        assert!(local.members.contains_key("did:n001"));
        assert_eq!(local.mls_epoch, Some(210));
        assert_eq!(local.event_count, 5000);
    }

    #[test]
    fn stress_multi_day_epoch_gap_with_role_changes() {
        // Simulate a 5-day offline period: 300 epoch advances, role changes,
        // tools added/removed, params changed.
        let mut old = make_snapshot(
            "ctx-days",
            1,
            Some(100),
            2000,
            [10u8; 32],
            vec![
                ("did:alice", "admin"),
                ("did:bob", "member"),
                ("did:carol", "member"),
            ],
        );
        old.tool_names = vec!["search".to_owned(), "translate".to_owned()];
        old.role_definitions.insert(
            "moderator".to_owned(),
            vec!["messages:read".to_owned(), "member:block".to_owned()],
        );

        let mut new = make_snapshot(
            "ctx-days",
            20,
            Some(400),
            8000,
            [20u8; 32],
            vec![
                ("did:alice", "admin"),
                ("did:bob", "admin"),   // promoted
                ("did:dave", "member"), // new
            ],
        );
        new.tool_names = vec![
            "search".to_owned(),
            "summarize".to_owned(),
            "code-review".to_owned(),
        ];
        new.params_hash = [99u8; 32]; // params changed
        // "moderator" role removed, "reviewer" added
        new.role_definitions
            .insert("reviewer".to_owned(), vec!["messages:read".to_owned()]);

        let delta = compute_delta(&old, &new).unwrap();

        // Bob promoted, Carol left, Dave joined
        assert_eq!(delta.membership_changes.len(), 3);
        assert!(delta.params_changed);
        assert_eq!(delta.events_added, 6000);

        // Tools: +summarize, +code-review, -translate
        assert_eq!(delta.added_tools.len(), 2);
        assert_eq!(delta.removed_tools.len(), 1);

        // Roles: "moderator" removed, "reviewer" added
        assert!(
            delta
                .removed_role_definitions
                .contains(&"moderator".to_owned())
        );
        assert!(delta.role_definition_changes.contains_key("reviewer"));

        // MLS: gap = 300 > 100 -> fast-forward
        let recovery = determine_mls_recovery(&delta);
        assert_eq!(
            recovery,
            MlsRecoveryAction::WelcomeFastForward {
                stale_epoch: 100,
                current_epoch: 400,
            }
        );

        // Apply and verify
        let mut local = old.clone();
        apply_delta(&mut local, &delta).unwrap();

        assert_eq!(local.members.len(), 3);
        assert!(!local.members.contains_key("did:carol"));
        assert!(local.members.contains_key("did:dave"));
        assert_eq!(
            local.members.get("did:bob").map(|m| m.role_name.as_str()),
            Some("admin"),
        );
        assert_eq!(local.event_count, 8000);
        assert_eq!(local.mls_epoch, Some(400));
        assert!(local.tool_names.contains(&"summarize".to_owned()));
        assert!(!local.tool_names.contains(&"translate".to_owned()));
        assert!(!local.role_definitions.contains_key("moderator"));
        assert!(local.role_definitions.contains_key("reviewer"));
    }

    #[test]
    fn stress_multi_device_divergence_scenario() {
        // Simulate three devices with varying offline durations:
        // - Phone: 3 days offline (behind)
        // - Laptop: 1 day offline (less behind)
        // - Tablet: same as laptop but different Merkle root (divergent)
        let phone = make_device_state("phone", 500, [1u8; 32]);
        let laptop = make_device_state("laptop", 800, [2u8; 32]);
        let mut tablet = make_device_state("tablet", 800, [3u8; 32]);
        tablet.local_merkle_root = [3u8; 32]; // different from laptop

        // Phone vs laptop: phone is behind
        let result = detect_device_divergence(&phone, &laptop);
        match &result {
            DeviceDivergence::Behind {
                behind_device,
                missing_events,
            } => {
                assert_eq!(behind_device, "phone");
                assert_eq!(*missing_events, 300);
            }
            _ => panic!("expected phone Behind laptop"),
        }

        // Laptop vs tablet: same event count, different roots -> divergent
        let result = detect_device_divergence(&laptop, &tablet);
        match &result {
            DeviceDivergence::Divergent {
                device_a,
                device_b,
                event_count,
            } => {
                assert_eq!(device_a, "laptop");
                assert_eq!(device_b, "tablet");
                assert_eq!(*event_count, 800);
            }
            _ => panic!("expected laptop/tablet Divergent"),
        }

        // Phone vs phone (same device, consistent)
        let result = detect_device_divergence(&phone, &phone);
        assert_eq!(result, DeviceDivergence::Consistent);
    }

    #[test]
    fn stress_sequential_delta_application() {
        // Simulate applying multiple sequential deltas (as would happen if
        // the member reconnects and catches up incrementally).
        let mut local = make_snapshot(
            "ctx-seq",
            1,
            Some(10),
            100,
            [1u8; 32],
            vec![("did:alice", "admin")],
        );

        // Delta 1: Bob joins, 50 events
        let delta1 = SnapshotDelta {
            context_id: "ctx-seq".to_owned(),
            from_sequence: 1,
            to_sequence: 2,
            from_epoch: Some(10),
            to_epoch: Some(30),
            membership_changes: vec![MembershipChange::Joined(MembershipEntry {
                did: DID::from("did:bob"),
                role_name: "member".to_owned(),
                sequence_number: 0,
            })],
            role_definition_changes: BTreeMap::new(),
            removed_role_definitions: vec![],
            added_tools: vec![],
            removed_tools: vec![],
            params_changed: false,
            events_added: 50,
            old_merkle_root: [1u8; 32],
            new_merkle_root: [2u8; 32],
        };

        apply_delta(&mut local, &delta1).unwrap();
        assert_eq!(local.members.len(), 2);
        assert_eq!(local.sequence, 2);
        assert_eq!(local.event_count, 150);

        // Delta 2: Carol joins, Bob promoted, 100 events
        let delta2 = SnapshotDelta {
            context_id: "ctx-seq".to_owned(),
            from_sequence: 2,
            to_sequence: 3,
            from_epoch: Some(30),
            to_epoch: Some(80),
            membership_changes: vec![
                MembershipChange::Joined(MembershipEntry {
                    did: DID::from("did:carol"),
                    role_name: "member".to_owned(),
                    sequence_number: 0,
                }),
                MembershipChange::RoleChanged {
                    did: DID::from("did:bob"),
                    old_role: "member".to_owned(),
                    new_role: "admin".to_owned(),
                },
            ],
            role_definition_changes: BTreeMap::new(),
            removed_role_definitions: vec![],
            added_tools: vec!["search".to_owned()],
            removed_tools: vec![],
            params_changed: false,
            events_added: 100,
            old_merkle_root: [2u8; 32],
            new_merkle_root: [3u8; 32],
        };

        apply_delta(&mut local, &delta2).unwrap();
        assert_eq!(local.members.len(), 3);
        assert_eq!(local.sequence, 3);
        assert_eq!(local.event_count, 250);
        assert_eq!(local.mls_epoch, Some(80));
        assert_eq!(
            local.members.get("did:bob").map(|m| m.role_name.as_str()),
            Some("admin"),
        );
        assert!(local.tool_names.contains(&"search".to_owned()));
    }

    #[test]
    fn days_offline_sync_result_serialization() {
        let result = DaysOfflineSyncResult {
            context_id: "ctx-1".to_owned(),
            delta_applied: None,
            mls_recovery: MlsRecoveryAction::NoAction,
            events_recovered: 0,
            outcome: SyncOutcome::FullyCaughtUp,
        };

        let json = serde_json::to_string(&result).unwrap();
        let deserialized: DaysOfflineSyncResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, deserialized);
    }
}
