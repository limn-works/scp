//! `PyO3` bridge functions for sync/offline operations.
//!
//! Exposes SCP sync operations to Python:
//!
//! - [`py_sync_classify_offline`] -- Classify offline duration into a tier.
//! - [`py_sync_get_policy`] -- Get the current sync policy parameters.
//!
//! See ADR-029 in `.docs/adrs/phase-6.md`.

use pyo3::prelude::*;
use pyo3::types::PyDict;

use scp_core::sync::{OfflineTier, SyncPolicy, classify_offline_duration};

// ---------------------------------------------------------------------------
// Bridge functions
// ---------------------------------------------------------------------------

/// Classifies an offline duration into the appropriate recovery tier.
///
/// Uses the default sync policy thresholds:
/// - Tier 1 (Short): < 4 hours
/// - Tier 2 (Extended): 4 hours to 7 days
/// - Tier 3 (Long): > 7 days
///
/// # Arguments
///
/// * `last_relay_contact` -- Unix timestamp (seconds) of last relay contact.
/// * `now` -- Current Unix timestamp (seconds).
///
/// # Returns
///
/// A string: `"short"`, `"extended"`, or `"long"`.
#[pyfunction]
#[pyo3(name = "sync_classify_offline")]
#[must_use]
pub fn py_sync_classify_offline(last_relay_contact: u64, now: u64) -> String {
    match classify_offline_duration(last_relay_contact, now) {
        OfflineTier::Short => "short".to_string(),
        OfflineTier::Extended => "extended".to_string(),
        OfflineTier::Long => "long".to_string(),
    }
}

/// Returns the default sync policy parameters as a dict.
///
/// # Returns
///
/// A dict with:
/// - `tier_1_threshold_secs` (int): Short offline upper bound (default 14400).
/// - `tier_2_threshold_secs` (int): Extended offline upper bound (default 604800).
/// - `gap_timeout_secs` (int): Gap timeout in seconds (default 30).
/// - `reorder_buffer_capacity` (int): Max buffered messages (default 100).
/// - `max_sequential_commits` (int): Max commits for epoch catch-up (default 100).
/// - `commit_process_timeout_secs` (int): Per-commit timeout (default 5).
/// - `sender_key_timeout_secs` (int): Sender key re-acquisition timeout (default 60).
/// - `reconnection_dedup_window_secs` (int): Dedup window (default 30).
#[pyfunction]
#[pyo3(name = "sync_get_policy")]
pub fn py_sync_get_policy(py: Python<'_>) -> PyResult<Py<PyDict>> {
    let policy = SyncPolicy::default();

    let dict = PyDict::new(py);
    dict.set_item("tier_1_threshold_secs", policy.tier_1_threshold_secs)?;
    dict.set_item("tier_2_threshold_secs", policy.tier_2_threshold_secs)?;
    dict.set_item("gap_timeout_secs", policy.gap_timeout.as_secs())?;
    dict.set_item("reorder_buffer_capacity", policy.reorder_buffer_capacity)?;
    dict.set_item("max_sequential_commits", policy.max_sequential_commits)?;
    dict.set_item(
        "commit_process_timeout_secs",
        policy.commit_process_timeout.as_secs(),
    )?;
    dict.set_item(
        "sender_key_timeout_secs",
        policy.sender_key_timeout.as_secs(),
    )?;
    dict.set_item(
        "reconnection_dedup_window_secs",
        policy.reconnection_dedup_window.as_secs(),
    )?;
    Ok(dict.into())
}

/// Classifies an offline duration using custom policy thresholds.
///
/// # Arguments
///
/// * `last_relay_contact` -- Unix timestamp (seconds) of last relay contact.
/// * `now` -- Current Unix timestamp (seconds).
/// * `tier_1_threshold_secs` -- Custom Tier 1 upper bound in seconds.
/// * `tier_2_threshold_secs` -- Custom Tier 2 upper bound in seconds.
///
/// # Returns
///
/// A string: `"short"`, `"extended"`, or `"long"`.
#[pyfunction]
#[pyo3(name = "sync_classify_offline_custom")]
#[must_use]
pub fn py_sync_classify_offline_custom(
    last_relay_contact: u64,
    now: u64,
    tier_1_threshold_secs: u64,
    tier_2_threshold_secs: u64,
) -> String {
    let policy = SyncPolicy::default()
        .with_tier_1_threshold_secs(tier_1_threshold_secs)
        .with_tier_2_threshold_secs(tier_2_threshold_secs);

    match policy.classify_offline_duration(last_relay_contact, now) {
        OfflineTier::Short => "short".to_string(),
        OfflineTier::Extended => "extended".to_string(),
        OfflineTier::Long => "long".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

/// Registers sync bridge functions on the `_scp_core` module.
///
/// # Errors
///
/// Returns `PyErr` if registration fails.
pub fn register_sync(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_sync_classify_offline, m)?)?;
    m.add_function(wrap_pyfunction!(py_sync_get_policy, m)?)?;
    m.add_function(wrap_pyfunction!(py_sync_classify_offline_custom, m)?)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn classify_short_offline() {
        assert_eq!(py_sync_classify_offline(1_000_000, 1_003_600), "short");
    }

    #[test]
    fn classify_extended_offline() {
        assert_eq!(py_sync_classify_offline(1_000_000, 1_100_000), "extended");
    }

    #[test]
    fn classify_long_offline() {
        assert_eq!(py_sync_classify_offline(1_000_000, 2_000_000), "long");
    }

    #[test]
    fn classify_custom_thresholds() {
        // 2 hours tier 1, 3 days tier 2
        assert_eq!(
            py_sync_classify_offline_custom(1_000_000, 1_003_600, 7_200, 259_200),
            "short"
        );
        assert_eq!(
            py_sync_classify_offline_custom(1_000_000, 1_010_800, 7_200, 259_200),
            "extended"
        );
        assert_eq!(
            py_sync_classify_offline_custom(1_000_000, 1_432_000, 7_200, 259_200),
            "long"
        );
    }
}
