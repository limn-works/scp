//! napi-rs bridge for sync/offline operations.
//!
//! Exposes SCP sync operations to Node.js/Bun:
//!
//! - [`sync_classify_offline`] -- Classify offline duration into a tier.
//! - [`sync_get_policy`] -- Get the current sync policy parameters.
//! - [`sync_classify_offline_custom`] -- Classify with custom thresholds.
//!
//! See ADR-029 in `.docs/adrs/phase-6.md`.

use napi_derive::napi;

use scp_core::sync::{OfflineTier, SyncPolicy, classify_offline_duration};

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// Sync policy parameters.
#[napi(object)]
pub struct NapiSyncPolicy {
    /// Short offline upper bound in seconds (default 14400 = 4 hours).
    pub tier_1_threshold_secs: i64,
    /// Extended offline upper bound in seconds (default 604800 = 7 days).
    pub tier_2_threshold_secs: i64,
    /// Gap timeout in seconds (default 30).
    pub gap_timeout_secs: i64,
    /// Max buffered messages (default 100).
    pub reorder_buffer_capacity: i32,
    /// Max commits for epoch catch-up (default 100).
    pub max_sequential_commits: i64,
    /// Per-commit timeout in seconds (default 5).
    pub commit_process_timeout_secs: i64,
    /// Sender key re-acquisition timeout in seconds (default 60).
    pub sender_key_timeout_secs: i64,
    /// Multi-device reconnection dedup window in seconds (default 30).
    pub reconnection_dedup_window_secs: i64,
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Classifies an offline duration into the appropriate recovery tier.
///
/// Returns `"short"`, `"extended"`, or `"long"`.
#[napi]
pub fn sync_classify_offline(last_relay_contact: i64, now: i64) -> String {
    #[allow(clippy::cast_sign_loss)]
    match classify_offline_duration(last_relay_contact as u64, now as u64) {
        OfflineTier::Short => "short".to_string(),
        OfflineTier::Extended => "extended".to_string(),
        OfflineTier::Long => "long".to_string(),
    }
}

/// Returns the default sync policy parameters.
#[napi]
pub fn sync_get_policy() -> NapiSyncPolicy {
    let policy = SyncPolicy::default();

    #[allow(clippy::cast_possible_wrap)]
    NapiSyncPolicy {
        tier_1_threshold_secs: policy.tier_1_threshold_secs as i64,
        tier_2_threshold_secs: policy.tier_2_threshold_secs as i64,
        gap_timeout_secs: policy.gap_timeout.as_secs() as i64,
        reorder_buffer_capacity: policy.reorder_buffer_capacity as i32,
        max_sequential_commits: policy.max_sequential_commits as i64,
        commit_process_timeout_secs: policy.commit_process_timeout.as_secs() as i64,
        sender_key_timeout_secs: policy.sender_key_timeout.as_secs() as i64,
        reconnection_dedup_window_secs: policy.reconnection_dedup_window.as_secs() as i64,
    }
}

/// Classifies an offline duration using custom policy thresholds.
///
/// Returns `"short"`, `"extended"`, or `"long"`.
#[napi]
pub fn sync_classify_offline_custom(
    last_relay_contact: i64,
    now: i64,
    tier_1_threshold_secs: i64,
    tier_2_threshold_secs: i64,
) -> String {
    #[allow(clippy::cast_sign_loss)]
    let policy = SyncPolicy::default()
        .with_tier_1_threshold_secs(tier_1_threshold_secs as u64)
        .with_tier_2_threshold_secs(tier_2_threshold_secs as u64);

    #[allow(clippy::cast_sign_loss)]
    match policy.classify_offline_duration(last_relay_contact as u64, now as u64) {
        OfflineTier::Short => "short".to_string(),
        OfflineTier::Extended => "extended".to_string(),
        OfflineTier::Long => "long".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn classify_short_offline() {
        assert_eq!(sync_classify_offline(1_000_000, 1_003_600), "short");
    }

    #[test]
    fn classify_extended_offline() {
        assert_eq!(sync_classify_offline(1_000_000, 1_100_000), "extended");
    }

    #[test]
    fn classify_long_offline() {
        assert_eq!(sync_classify_offline(1_000_000, 2_000_000), "long");
    }

    #[test]
    fn get_policy_returns_defaults() {
        let policy = sync_get_policy();
        assert_eq!(policy.tier_1_threshold_secs, 14_400);
        assert_eq!(policy.tier_2_threshold_secs, 604_800);
    }
}
