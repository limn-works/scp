//! `wasm-bindgen` bridge for sync/offline operations.
//!
//! Exposes offline classification and sync policy to JavaScript (browser target):
//!
//! - `sync_classify_offline` — Classify offline duration using default thresholds.
//! - `sync_get_policy` — Get the default sync policy as JSON.
//! - `sync_classify_offline_custom` — Classify offline duration with custom thresholds.
//!
//! # WASM constraints
//!
//! This bridge does NOT depend on `scp-core` (tokio multi-thread incompatible
//! with `wasm32-unknown-unknown`). Offline tier classification is a pure
//! arithmetic function re-implemented locally with algorithm-identical constants.
//!
//! See ADR-029 in `.docs/adrs/phase-6.md`.

use wasm_bindgen::prelude::*;

use crate::error::ScpWasmError;

// ---------------------------------------------------------------------------
// Constants (mirror scp-core::sync)
// ---------------------------------------------------------------------------

/// Tier 1 upper bound: 4 hours in seconds.
const TIER_1_THRESHOLD_SECS: u64 = 14_400;
/// Tier 2 upper bound: 7 days in seconds.
const TIER_2_THRESHOLD_SECS: u64 = 604_800;
/// Gap timeout for the reorder buffer: 30 seconds.
const GAP_TIMEOUT_SECS: u64 = 30;
/// Maximum number of messages held in the reorder buffer.
const REORDER_BUFFER_CAPACITY: u64 = 100;
/// Maximum number of sequential MLS Commits processed during epoch catch-up.
const MAX_SEQUENTIAL_COMMITS: u64 = 100;
/// Per-Commit processing timeout during epoch catch-up: 5 seconds.
const COMMIT_PROCESS_TIMEOUT_SECS: u64 = 5;
/// Timeout for sender key re-acquisition after missed rotations: 60 seconds.
const SENDER_KEY_TIMEOUT_SECS: u64 = 60;
/// Multi-device reconnection deduplication window: 30 seconds.
const RECONNECTION_DEDUP_WINDOW_SECS: u64 = 30;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Validates that an f64 timestamp is non-negative and finite.
///
/// Returns the value cast to `u64` on success, or a [`ScpWasmError`] validation
/// error on failure. Call sites convert to `JsValue` via `.map_err(|e| e.into_js().into())`.
/// This separation allows native-target tests to exercise the validation logic
/// without invoking wasm-bindgen.
fn validate_non_negative_timestamp(value: f64, name: &str) -> Result<u64, ScpWasmError> {
    if value < 0.0 || !value.is_finite() {
        return Err(ScpWasmError::Validation {
            message: format!("{name} must be non-negative, got {value}"),
            code: "SCP-VALID-7040".to_owned(),
        });
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Ok(value as u64)
}

/// Classifies offline duration using the given thresholds.
fn classify(duration_secs: u64, tier_1: u64, tier_2: u64) -> &'static str {
    if duration_secs <= tier_1 {
        "short"
    } else if duration_secs <= tier_2 {
        "extended"
    } else {
        "long"
    }
}

// ---------------------------------------------------------------------------
// sync_classify_offline
// ---------------------------------------------------------------------------

/// Classifies an offline duration into the appropriate recovery tier.
///
/// Uses the default ADR-029 thresholds: Tier 1 < 4 hours, Tier 2 < 7 days.
///
/// Both parameters are `f64` because JavaScript numbers are IEEE 754 doubles.
/// They represent Unix timestamps in seconds. The function computes
/// `now - last_relay_contact` (with saturating subtraction for clock skew).
///
/// Returns one of: `"short"`, `"extended"`, `"long"`.
///
/// # Errors
///
/// Returns `SCP-VALID-7040` if either parameter is negative.
///
/// # JS usage
///
/// ```js
/// const tier = sync_classify_offline(lastContact, Date.now() / 1000);
/// console.log(tier); // "short" | "extended" | "long"
/// ```
#[wasm_bindgen]
pub fn sync_classify_offline(last_relay_contact: f64, now: f64) -> Result<String, JsValue> {
    let last = validate_non_negative_timestamp(last_relay_contact, "last_relay_contact")
        .map_err(ScpWasmError::into_js)?;
    let current = validate_non_negative_timestamp(now, "now").map_err(ScpWasmError::into_js)?;
    let duration_secs = current.saturating_sub(last);
    Ok(classify(duration_secs, TIER_1_THRESHOLD_SECS, TIER_2_THRESHOLD_SECS).to_owned())
}

// ---------------------------------------------------------------------------
// sync_get_policy
// ---------------------------------------------------------------------------

/// Returns the default sync policy as a JSON string.
///
/// The policy contains all ADR-029 default constants. Consumers can inspect
/// these values to understand the current tier thresholds and buffer sizes.
///
/// # JS usage
///
/// ```js
/// const policy = JSON.parse(sync_get_policy());
/// console.log(policy.tier_1_threshold_secs); // 14400
/// ```
#[must_use]
#[wasm_bindgen]
pub fn sync_get_policy() -> String {
    serde_json::json!({
        "tier_1_threshold_secs": TIER_1_THRESHOLD_SECS,
        "tier_2_threshold_secs": TIER_2_THRESHOLD_SECS,
        "gap_timeout_secs": GAP_TIMEOUT_SECS,
        "reorder_buffer_capacity": REORDER_BUFFER_CAPACITY,
        "max_sequential_commits": MAX_SEQUENTIAL_COMMITS,
        "commit_process_timeout_secs": COMMIT_PROCESS_TIMEOUT_SECS,
        "sender_key_timeout_secs": SENDER_KEY_TIMEOUT_SECS,
        "reconnection_dedup_window_secs": RECONNECTION_DEDUP_WINDOW_SECS,
    })
    .to_string()
}

// ---------------------------------------------------------------------------
// sync_classify_offline_custom
// ---------------------------------------------------------------------------

/// Classifies an offline duration with custom tier thresholds.
///
/// All parameters are `f64` for JS number compatibility (cast to `u64`).
///
/// # Arguments
///
/// - `last_relay_contact` — Unix timestamp (seconds) of last relay contact.
/// - `now` — Current Unix timestamp (seconds).
/// - `tier_1_threshold_secs` — Custom Tier 1 upper bound (seconds).
/// - `tier_2_threshold_secs` — Custom Tier 2 upper bound (seconds).
///
/// Returns one of: `"short"`, `"extended"`, `"long"`.
///
/// # Errors
///
/// Returns `SCP-VALID-7040` if any parameter is negative.
///
/// # JS usage
///
/// ```js
/// // Custom: 1 hour short, 3 days extended
/// const tier = sync_classify_offline_custom(last, now, 3600, 259200);
/// ```
#[wasm_bindgen]
pub fn sync_classify_offline_custom(
    last_relay_contact: f64,
    now: f64,
    tier_1_threshold_secs: f64,
    tier_2_threshold_secs: f64,
) -> Result<String, JsValue> {
    let last = validate_non_negative_timestamp(last_relay_contact, "last_relay_contact")
        .map_err(ScpWasmError::into_js)?;
    let current = validate_non_negative_timestamp(now, "now").map_err(ScpWasmError::into_js)?;
    let t1 = validate_non_negative_timestamp(tier_1_threshold_secs, "tier_1_threshold_secs")
        .map_err(ScpWasmError::into_js)?;
    let t2 = validate_non_negative_timestamp(tier_2_threshold_secs, "tier_2_threshold_secs")
        .map_err(ScpWasmError::into_js)?;
    let duration_secs = current.saturating_sub(last);
    Ok(classify(duration_secs, t1, t2).to_owned())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // classify (pure logic — no wasm-bindgen dependency)
    // -----------------------------------------------------------------------

    #[test]
    fn classify_short_zero_seconds() {
        assert_eq!(
            classify(0, TIER_1_THRESHOLD_SECS, TIER_2_THRESHOLD_SECS),
            "short"
        );
    }

    #[test]
    fn classify_short_at_boundary() {
        assert_eq!(
            classify(14_400, TIER_1_THRESHOLD_SECS, TIER_2_THRESHOLD_SECS),
            "short"
        );
    }

    #[test]
    fn classify_extended_just_over() {
        assert_eq!(
            classify(14_401, TIER_1_THRESHOLD_SECS, TIER_2_THRESHOLD_SECS),
            "extended"
        );
    }

    #[test]
    fn classify_extended_at_boundary() {
        assert_eq!(
            classify(604_800, TIER_1_THRESHOLD_SECS, TIER_2_THRESHOLD_SECS),
            "extended"
        );
    }

    #[test]
    fn classify_long_just_over() {
        assert_eq!(
            classify(604_801, TIER_1_THRESHOLD_SECS, TIER_2_THRESHOLD_SECS),
            "long"
        );
    }

    #[test]
    fn classify_handles_clock_skew() {
        // now < last_relay_contact => saturating_sub => 0 => Short
        let duration = 1_000_000u64.saturating_sub(2_000_000);
        assert_eq!(
            classify(duration, TIER_1_THRESHOLD_SECS, TIER_2_THRESHOLD_SECS),
            "short"
        );
    }

    #[test]
    fn classify_custom_thresholds() {
        assert_eq!(classify(3601, 3600, 259_200), "extended");
    }

    #[test]
    fn policy_json_has_expected_fields() {
        let json: serde_json::Value = serde_json::from_str(&sync_get_policy()).unwrap();
        assert_eq!(json["tier_1_threshold_secs"], 14_400);
        assert_eq!(json["tier_2_threshold_secs"], 604_800);
        assert_eq!(json["gap_timeout_secs"], 30);
        assert_eq!(json["reorder_buffer_capacity"], 100);
    }

    // -----------------------------------------------------------------------
    // validate_non_negative_timestamp — returns ScpWasmError (no JsValue)
    // -----------------------------------------------------------------------

    #[test]
    fn validate_timestamp_accepts_zero() {
        assert_eq!(validate_non_negative_timestamp(0.0, "ts").unwrap(), 0);
    }

    #[test]
    fn validate_timestamp_accepts_positive() {
        assert_eq!(validate_non_negative_timestamp(42.0, "ts").unwrap(), 42);
    }

    #[test]
    fn validate_timestamp_rejects_negative() {
        let result = validate_non_negative_timestamp(-100.0, "last_relay_contact");
        assert!(result.is_err(), "negative last_relay_contact should error");
    }

    #[test]
    fn validate_timestamp_rejects_negative_now() {
        let result = validate_non_negative_timestamp(-1.0, "now");
        assert!(result.is_err(), "negative now should error");
    }

    #[test]
    fn validate_timestamp_rejects_f64_min() {
        let result = validate_non_negative_timestamp(f64::MIN, "ts");
        assert!(result.is_err(), "f64::MIN should error");
    }

    #[test]
    fn validate_timestamp_rejects_neg_infinity() {
        let result = validate_non_negative_timestamp(f64::NEG_INFINITY, "ts");
        assert!(result.is_err(), "NEG_INFINITY should error");
    }

    #[test]
    fn validate_timestamp_rejects_nan() {
        let result = validate_non_negative_timestamp(f64::NAN, "ts");
        assert!(result.is_err(), "NaN should error");
    }

    #[test]
    fn validate_timestamp_rejects_positive_infinity() {
        let result = validate_non_negative_timestamp(f64::INFINITY, "ts");
        assert!(result.is_err(), "INFINITY should error");
    }

    #[test]
    fn validate_timestamp_error_contains_code() {
        let result = validate_non_negative_timestamp(-42.0, "ts");
        let err = result.unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("SCP-VALID-7040"),
            "error should contain SCP-VALID-7040, got: {msg}"
        );
    }
}
