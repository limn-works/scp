//! Trust On First Use (TOFU) key tracking for SCP (spec section 9.11).
//!
//! When a DID is first encountered, the SDK records all three verification
//! method public keys (`#0` Identity Key, `#active` Active Signing Key,
//! `#agent` Agent Signing Key). On any subsequent DID resolution that returns
//! different keys, the SDK detects the change and reports it to the
//! application for user action.
//!
//! Per-VM tracking (ADR-039): each verification method is tracked
//! independently. A change in any single VM triggers the key change alert,
//! even if others remain stable. This enables precise identification of
//! which key changed (agent rotation vs. identity compromise).
//!
//! # Persistence
//!
//! TOFU records are persisted via `ProtocolStore` under the `tofu/{did}`
//! key namespace. The store module (`store::tofu`) provides the typed
//! read/write methods. This module provides the types and comparison logic.
//!
//! See spec section 9.11 (Key Continuity Verification) and §9.6.2.

use serde::{Deserialize, Serialize};

/// A snapshot of a DID's verification method public keys at a point in time.
///
/// Tracks all three verification methods independently per ADR-039:
/// `#0` (Identity Key), `#active` (Active Signing Key), and `#agent`
/// (Agent Signing Key, optional). Agent key absence is represented as
/// `None`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TofuRecord {
    /// The `#0` Identity Key (32-byte Ed25519 public key).
    pub identity_key: [u8; 32],
    /// The `#active` Active Signing Key (32-byte Ed25519 public key).
    pub active_key: [u8; 32],
    /// The `#agent` Agent Signing Key (32-byte Ed25519 public key), or
    /// `None` if no agent is bound to the DID.
    pub agent_key: Option<[u8; 32]>,
    /// Unix timestamp (seconds) when this DID was first encountered.
    pub first_seen_at: u64,
    /// Unix timestamp (seconds) of the most recent successful verification.
    pub last_verified_at: u64,
    /// Whether Key Continuity Verification (out-of-band fingerprint
    /// comparison per §9.11) has been completed for this DID.
    pub verified_out_of_band: bool,
}

/// Describes which verification method keys changed between the stored
/// TOFU record and a newly resolved DID document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyChanges {
    /// `true` if the `#0` Identity Key changed.
    pub identity_key_changed: bool,
    /// `true` if the `#active` Active Signing Key changed.
    pub active_key_changed: bool,
    /// `true` if the `#agent` Agent Signing Key changed (including
    /// transitions between `Some` and `None`).
    pub agent_key_changed: bool,
}

impl KeyChanges {
    /// Returns `true` if any verification method key changed.
    #[must_use]
    pub fn any_changed(&self) -> bool {
        self.identity_key_changed || self.active_key_changed || self.agent_key_changed
    }
}

/// Result of a TOFU key check against a stored record.
///
/// Returned by [`check_tofu`] after comparing a newly resolved DID's
/// keys against the stored TOFU record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TofuResult {
    /// This DID has never been seen before. The caller should record
    /// the keys as the initial TOFU binding.
    FirstSeen,

    /// The DID's keys match the stored TOFU record. No action needed.
    Consistent,

    /// One or more verification method keys have changed since the last
    /// observation. The caller MUST alert the user and refuse to send
    /// encrypted content until the user explicitly accepts the change
    /// or completes re-verification (spec §9.11).
    Changed {
        /// The previously stored keys.
        old_record: TofuRecord,
        /// The newly observed keys (not yet stored).
        new_keys: ObservedKeys,
        /// Which specific verification methods changed.
        changes: KeyChanges,
    },
}

/// A set of newly observed verification method keys from a DID resolution.
///
/// Used as input to [`check_tofu`] and included in [`TofuResult::Changed`]
/// for the caller to inspect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedKeys {
    /// The `#0` Identity Key (32-byte Ed25519 public key).
    pub identity_key: [u8; 32],
    /// The `#active` Active Signing Key (32-byte Ed25519 public key).
    pub active_key: [u8; 32],
    /// The `#agent` Agent Signing Key, or `None` if absent.
    pub agent_key: Option<[u8; 32]>,
}

/// Compares newly observed keys against a stored TOFU record.
///
/// Returns [`TofuResult::FirstSeen`] if `stored` is `None`,
/// [`TofuResult::Consistent`] if all keys match, or
/// [`TofuResult::Changed`] with per-VM change details if any key differs.
///
/// # Arguments
///
/// * `stored` — The previously stored TOFU record, or `None` if this DID
///   has not been seen before.
/// * `observed` — The keys from the current DID resolution.
#[must_use]
pub fn check_tofu(stored: Option<&TofuRecord>, observed: &ObservedKeys) -> TofuResult {
    let Some(record) = stored else {
        return TofuResult::FirstSeen;
    };

    let identity_key_changed = record.identity_key != observed.identity_key;
    let active_key_changed = record.active_key != observed.active_key;
    let agent_key_changed = record.agent_key != observed.agent_key;

    let changes = KeyChanges {
        identity_key_changed,
        active_key_changed,
        agent_key_changed,
    };

    if changes.any_changed() {
        TofuResult::Changed {
            old_record: record.clone(),
            new_keys: observed.clone(),
            changes,
        }
    } else {
        TofuResult::Consistent
    }
}

/// Creates a new [`TofuRecord`] from observed keys and a timestamp.
///
/// Used when [`TofuResult::FirstSeen`] is returned, or when the user
/// explicitly accepts a key change.
#[must_use]
pub fn create_tofu_record(observed: &ObservedKeys, now_secs: u64) -> TofuRecord {
    TofuRecord {
        identity_key: observed.identity_key,
        active_key: observed.active_key,
        agent_key: observed.agent_key,
        first_seen_at: now_secs,
        last_verified_at: now_secs,
        verified_out_of_band: false,
    }
}

/// Updates a TOFU record's `last_verified_at` timestamp.
///
/// Called after a successful interaction to track liveness. Does not
/// modify the stored keys.
#[must_use]
pub fn update_last_verified(record: &TofuRecord, now_secs: u64) -> TofuRecord {
    TofuRecord {
        last_verified_at: now_secs,
        ..record.clone()
    }
}

/// Marks a TOFU record as verified out-of-band.
///
/// Called after the user completes Key Continuity Verification (§9.11)
/// by comparing fingerprints via an out-of-band channel.
#[must_use]
pub fn mark_verified_out_of_band(record: &TofuRecord, now_secs: u64) -> TofuRecord {
    TofuRecord {
        verified_out_of_band: true,
        last_verified_at: now_secs,
        ..record.clone()
    }
}

/// Creates an updated TOFU record after the user explicitly accepts a
/// key change.
///
/// Resets `verified_out_of_band` to `false` (spec §9.11: key change
/// invalidates previous verification). Preserves `first_seen_at`.
#[must_use]
pub fn accept_key_change(
    old_record: &TofuRecord,
    new_keys: &ObservedKeys,
    now_secs: u64,
) -> TofuRecord {
    TofuRecord {
        identity_key: new_keys.identity_key,
        active_key: new_keys.active_key,
        agent_key: new_keys.agent_key,
        first_seen_at: old_record.first_seen_at,
        last_verified_at: now_secs,
        verified_out_of_band: false,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn keys_a() -> ObservedKeys {
        ObservedKeys {
            identity_key: [1u8; 32],
            active_key: [2u8; 32],
            agent_key: Some([3u8; 32]),
        }
    }

    fn keys_b_different_active() -> ObservedKeys {
        ObservedKeys {
            identity_key: [1u8; 32],
            active_key: [99u8; 32],
            agent_key: Some([3u8; 32]),
        }
    }

    fn keys_c_no_agent() -> ObservedKeys {
        ObservedKeys {
            identity_key: [1u8; 32],
            active_key: [2u8; 32],
            agent_key: None,
        }
    }

    fn record_from(keys: &ObservedKeys) -> TofuRecord {
        create_tofu_record(keys, 1000)
    }

    #[test]
    fn first_seen_when_no_stored_record() {
        let observed = keys_a();
        let result = check_tofu(None, &observed);
        assert_eq!(result, TofuResult::FirstSeen);
    }

    #[test]
    fn consistent_when_keys_match() {
        let observed = keys_a();
        let record = record_from(&observed);
        let result = check_tofu(Some(&record), &observed);
        assert_eq!(result, TofuResult::Consistent);
    }

    #[test]
    fn changed_when_active_key_differs() {
        let original = keys_a();
        let record = record_from(&original);
        let changed = keys_b_different_active();

        let result = check_tofu(Some(&record), &changed);
        match result {
            TofuResult::Changed { changes, .. } => {
                assert!(!changes.identity_key_changed);
                assert!(changes.active_key_changed);
                assert!(!changes.agent_key_changed);
                assert!(changes.any_changed());
            }
            other => panic!("expected Changed, got {other:?}"),
        }
    }

    #[test]
    fn changed_when_agent_key_removed() {
        let original = keys_a();
        let record = record_from(&original);
        let no_agent = keys_c_no_agent();

        let result = check_tofu(Some(&record), &no_agent);
        match result {
            TofuResult::Changed { changes, .. } => {
                assert!(!changes.identity_key_changed);
                assert!(!changes.active_key_changed);
                assert!(changes.agent_key_changed);
            }
            other => panic!("expected Changed, got {other:?}"),
        }
    }

    #[test]
    fn changed_when_agent_key_added() {
        let no_agent = keys_c_no_agent();
        let record = record_from(&no_agent);
        let with_agent = keys_a();

        let result = check_tofu(Some(&record), &with_agent);
        match result {
            TofuResult::Changed { changes, .. } => {
                assert!(changes.agent_key_changed);
            }
            other => panic!("expected Changed, got {other:?}"),
        }
    }

    #[test]
    fn changed_when_all_keys_differ() {
        let original = keys_a();
        let record = record_from(&original);
        let all_different = ObservedKeys {
            identity_key: [10u8; 32],
            active_key: [20u8; 32],
            agent_key: Some([30u8; 32]),
        };

        let result = check_tofu(Some(&record), &all_different);
        match result {
            TofuResult::Changed { changes, .. } => {
                assert!(changes.identity_key_changed);
                assert!(changes.active_key_changed);
                assert!(changes.agent_key_changed);
            }
            other => panic!("expected Changed, got {other:?}"),
        }
    }

    #[test]
    fn create_tofu_record_sets_timestamps() {
        let keys = keys_a();
        let record = create_tofu_record(&keys, 5000);

        assert_eq!(record.identity_key, keys.identity_key);
        assert_eq!(record.active_key, keys.active_key);
        assert_eq!(record.agent_key, keys.agent_key);
        assert_eq!(record.first_seen_at, 5000);
        assert_eq!(record.last_verified_at, 5000);
        assert!(!record.verified_out_of_band);
    }

    #[test]
    fn update_last_verified_preserves_keys() {
        let keys = keys_a();
        let record = create_tofu_record(&keys, 1000);
        let updated = update_last_verified(&record, 2000);

        assert_eq!(updated.identity_key, record.identity_key);
        assert_eq!(updated.active_key, record.active_key);
        assert_eq!(updated.agent_key, record.agent_key);
        assert_eq!(updated.first_seen_at, 1000);
        assert_eq!(updated.last_verified_at, 2000);
        assert!(!updated.verified_out_of_band);
    }

    #[test]
    fn mark_verified_out_of_band_sets_flag() {
        let keys = keys_a();
        let record = create_tofu_record(&keys, 1000);
        let verified = mark_verified_out_of_band(&record, 3000);

        assert!(verified.verified_out_of_band);
        assert_eq!(verified.last_verified_at, 3000);
        assert_eq!(verified.first_seen_at, 1000);
    }

    #[test]
    fn accept_key_change_resets_verification() {
        let original = keys_a();
        let record = create_tofu_record(&original, 1000);
        let record = mark_verified_out_of_band(&record, 2000);
        assert!(record.verified_out_of_band);

        let new_keys = keys_b_different_active();
        let accepted = accept_key_change(&record, &new_keys, 3000);

        assert_eq!(accepted.active_key, new_keys.active_key);
        assert!(!accepted.verified_out_of_band);
        assert_eq!(accepted.first_seen_at, 1000); // preserved
        assert_eq!(accepted.last_verified_at, 3000);
    }

    #[test]
    fn key_changes_any_changed_false_when_none_changed() {
        let changes = KeyChanges {
            identity_key_changed: false,
            active_key_changed: false,
            agent_key_changed: false,
        };
        assert!(!changes.any_changed());
    }

    #[test]
    fn key_changes_any_changed_true_for_each_field() {
        assert!(
            KeyChanges {
                identity_key_changed: true,
                active_key_changed: false,
                agent_key_changed: false,
            }
            .any_changed()
        );

        assert!(
            KeyChanges {
                identity_key_changed: false,
                active_key_changed: true,
                agent_key_changed: false,
            }
            .any_changed()
        );

        assert!(
            KeyChanges {
                identity_key_changed: false,
                active_key_changed: false,
                agent_key_changed: true,
            }
            .any_changed()
        );
    }
}
