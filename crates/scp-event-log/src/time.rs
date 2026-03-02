//! Clock utilities with proper error handling.
//!
//! Provides [`now_secs`] as a drop-in replacement for the
//! `SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_*()` pattern.
//!
//! Mirrors `scp-core::time` to avoid a dependency on scp-core.

use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// ClockError
// ---------------------------------------------------------------------------

/// The system clock is unavailable or before the Unix epoch.
///
/// This is a hard failure -- falling back to epoch 0 would bypass security
/// checks (checkpoint timestamps, nonce freshness, etc.).
#[derive(Debug, Clone)]
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
