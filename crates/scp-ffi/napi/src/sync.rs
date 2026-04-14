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
use scp_ffi_common::error_codes as codes;

use scp_core::sync::{OfflineTier, SyncPolicy, classify_offline_duration};

use crate::error::ScpNapiError;

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
// Internal helpers
// ---------------------------------------------------------------------------

/// Validates that an i64 timestamp is non-negative and returns it as u64.
fn validate_non_negative_timestamp(value: i64, name: &str) -> napi::Result<u64> {
    if value < 0 {
        return Err(napi::Error::from(ScpNapiError::Validation {
            message: format!("{name} must be non-negative, got {value}"),
            code: codes::VALID_7040.to_owned(),
        }));
    }
    #[allow(clippy::cast_sign_loss)]
    Ok(value as u64)
}

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Classifies an offline duration into the appropriate recovery tier.
///
/// Returns `"short"`, `"extended"`, or `"long"`.
#[napi]
pub fn sync_classify_offline(last_relay_contact: i64, now: i64) -> napi::Result<String> {
    let last = validate_non_negative_timestamp(last_relay_contact, "last_relay_contact")?;
    let current = validate_non_negative_timestamp(now, "now")?;
    Ok(match classify_offline_duration(last, current) {
        OfflineTier::Short => "short".to_string(),
        OfflineTier::Extended => "extended".to_string(),
        OfflineTier::Long => "long".to_string(),
    })
}

/// Returns the default sync policy parameters.
#[must_use]
#[napi]
pub fn sync_get_policy() -> NapiSyncPolicy {
    let policy = SyncPolicy::default();

    #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
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
) -> napi::Result<String> {
    let last = validate_non_negative_timestamp(last_relay_contact, "last_relay_contact")?;
    let current = validate_non_negative_timestamp(now, "now")?;
    let t1 = validate_non_negative_timestamp(tier_1_threshold_secs, "tier_1_threshold_secs")?;
    let t2 = validate_non_negative_timestamp(tier_2_threshold_secs, "tier_2_threshold_secs")?;

    let policy = SyncPolicy::default()
        .with_tier_1_threshold_secs(t1)
        .with_tier_2_threshold_secs(t2);

    Ok(match policy.classify_offline_duration(last, current) {
        OfflineTier::Short => "short".to_string(),
        OfflineTier::Extended => "extended".to_string(),
        OfflineTier::Long => "long".to_string(),
    })
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
        assert_eq!(
            sync_classify_offline(1_000_000, 1_003_600).unwrap(),
            "short"
        );
    }

    #[test]
    fn classify_extended_offline() {
        assert_eq!(
            sync_classify_offline(1_000_000, 1_100_000).unwrap(),
            "extended"
        );
    }

    #[test]
    fn classify_long_offline() {
        assert_eq!(sync_classify_offline(1_000_000, 2_000_000).unwrap(), "long");
    }

    #[test]
    fn get_policy_returns_defaults() {
        let policy = sync_get_policy();
        assert_eq!(policy.tier_1_threshold_secs, 14_400);
        assert_eq!(policy.tier_2_threshold_secs, 604_800);
    }

    #[test]
    fn classify_negative_last_relay_contact_errors() {
        let result = sync_classify_offline(-1, 1_000_000);
        assert!(result.is_err(), "negative last_relay_contact should error");
    }

    #[test]
    fn classify_negative_now_errors() {
        let result = sync_classify_offline(0, -1);
        assert!(result.is_err(), "negative now should error");
    }

    #[test]
    fn classify_i64_min_boundary_errors() {
        let result = sync_classify_offline(i64::MIN, 1_000_000);
        assert!(result.is_err(), "i64::MIN should error");
        let result2 = sync_classify_offline(0, i64::MIN);
        assert!(result2.is_err(), "i64::MIN as now should error");
    }

    #[test]
    fn classify_custom_negative_threshold_errors() {
        let result = sync_classify_offline_custom(0, 100, -3600, 259_200);
        assert!(result.is_err(), "negative tier_1_threshold should error");
    }
}
