//! Clock utilities with proper error handling.
//!
//! Provides [`now_secs`] and [`now_millis`] as drop-in replacements for the
//! `SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_*()` pattern that
//! silently falls back to epoch 0 on clock errors. A UCAN minted with
//! timestamp 0 could appear to never expire — this is a security issue.
//!
//! All production code should use these functions instead of inlining
//! `SystemTime::now()` calls. The error type [`ClockError`] deliberately hides
//! raw system error details to avoid leaking internal state.

use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// ClockError
// ---------------------------------------------------------------------------

/// The system clock is unavailable or before the Unix epoch.
///
/// This is a hard failure — falling back to epoch 0 would bypass security
/// checks (UCAN expiry, nonce freshness, checkpoint timestamps, etc.).
///
/// The error message is intentionally generic to avoid exposing raw system
/// error details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClockError;

impl std::fmt::Display for ClockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("system clock is unavailable or before Unix epoch")
    }
}

impl std::error::Error for ClockError {}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Returns the current Unix timestamp in seconds.
///
/// # Errors
///
/// Returns [`ClockError`] if the system clock is before the Unix epoch.
pub fn now_secs() -> Result<u64, ClockError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| ClockError)
}

/// Returns the current Unix timestamp in milliseconds.
///
/// Uses `as_secs() * 1000 + subsec_millis` to avoid `u128` → `u64`
/// truncation (safe until year 584 million).
///
/// # Errors
///
/// Returns [`ClockError`] if the system clock is before the Unix epoch.
pub fn now_millis() -> Result<u64, ClockError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| {
            d.as_secs()
                .saturating_mul(1000)
                .saturating_add(u64::from(d.subsec_millis()))
        })
        .map_err(|_| ClockError)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn now_secs_returns_ok_on_normal_system() {
        let result = now_secs();
        assert!(
            result.is_ok(),
            "now_secs() should succeed on a normal system"
        );
        // Sanity check: timestamp should be after 2020-01-01.
        let secs = result.unwrap();
        assert!(secs > 1_577_836_800, "timestamp should be after 2020");
    }

    #[test]
    fn now_millis_returns_ok_on_normal_system() {
        let result = now_millis();
        assert!(
            result.is_ok(),
            "now_millis() should succeed on a normal system"
        );
        let ms = result.unwrap();
        // Should be roughly 1000x the seconds value.
        assert!(ms > 1_577_836_800_000, "millis should be after 2020");
    }

    #[test]
    fn clock_error_display_is_generic() {
        let err = ClockError;
        assert_eq!(
            err.to_string(),
            "system clock is unavailable or before Unix epoch"
        );
        // Verify no raw system error details are exposed.
        assert!(!err.to_string().contains("SystemTimeError"));
    }

    #[test]
    fn now_millis_is_roughly_1000x_now_secs() {
        let secs = now_secs().unwrap();
        let ms = now_millis().unwrap();
        // Should be within 2 seconds of each other.
        let diff = ms.saturating_sub(secs * 1000);
        assert!(diff < 2000, "millis and secs should agree within 2s");
    }
}
