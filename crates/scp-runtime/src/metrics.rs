//! Operational metrics for SCP core protocol.
//!
//! Uses the [`metrics`] crate facade. Counters, histograms, and gauges are
//! emitted via the global recorder — callers must install a backend (e.g.,
//! `metrics-exporter-prometheus`) at program startup. If no recorder is
//! installed, metrics calls are no-ops.
//!
//! # Metric names
//!
//! | Name                              | Type      | Description                                    |
//! |-----------------------------------|-----------|------------------------------------------------|
//! | `scp_messages_sent_total`         | Counter   | Messages sent (encrypted + broadcast)          |
//! | `scp_messages_received_total`     | Counter   | Messages delivered to receive buffer           |
//! | `scp_mls_encrypt_duration_seconds`| Histogram | MLS + sender key encryption latency            |
//! | `scp_mls_decrypt_duration_seconds`| Histogram | MLS + sender key decryption latency            |
//! | `scp_persistence_failures_total`  | Counter   | Persistence write failures (best-effort saves) |
//! | `scp_saga_repair_needed_total`    | Counter   | Cross-context sagas landed in `NeedsRepair` requiring operator repair (§17.16.4) |
//! | `scp_pseudonym_announcements_rejected_total` | Counter | Rejected pseudonym announcements (forged DID, reserved value, or cross-DID RID collision, §9.10.4) |
//! | `scp_active_contexts`             | Gauge     | Number of registered (active) contexts         |
//! | `scp_buffer_occupancy`            | Gauge     | Total events buffered across all contexts      |
//!
//! See issue #1467.

/// Records a message sent.
pub fn record_message_sent() {
    metrics::counter!("scp_messages_sent_total").increment(1);
}

/// Records a message received and delivered to the receive buffer.
pub fn record_message_received() {
    metrics::counter!("scp_messages_received_total").increment(1);
}

/// Records MLS encryption duration in seconds.
pub fn record_encrypt_duration(duration: std::time::Duration) {
    metrics::histogram!("scp_mls_encrypt_duration_seconds").record(duration.as_secs_f64());
}

/// Records MLS decryption duration in seconds.
pub fn record_decrypt_duration(duration: std::time::Duration) {
    metrics::histogram!("scp_mls_decrypt_duration_seconds").record(duration.as_secs_f64());
}

/// Records a persistence failure (counter).
pub fn record_persistence_failure() {
    metrics::counter!("scp_persistence_failures_total").increment(1);
}

/// Records a cross-context saga landing in `NeedsRepair` (§17.16.4).
///
/// Incremented at every site that records or re-surfaces a `NeedsRepair`
/// terminal: the live FSM commit-retry-exhaustion tail, and the crash-recovery
/// arms (commit-in-progress that could not confirm both sides, an Aborting
/// entry whose rollback never completed, and a `NeedsRepair` carryover observed
/// at process start). `NeedsRepair` is FSM-terminal but NOT resolved, so the
/// recovery scan re-surfaces it each process start until an operator repairs it
/// — a nonzero rate is the operator-alerting signal §17.16.4 names.
pub(crate) fn record_saga_repair_needed() {
    metrics::counter!("scp_saga_repair_needed_total").increment(1);
}

/// Records a rejected pseudonym announcement (§9.10.4).
///
/// Incremented when an ingested `PseudonymAnnouncement` is dropped because the
/// claimed `member_did` does not match the MLS-authenticated sender (a forged
/// RID-hijack attempt), uses a reserved routing ID value, or collides with a
/// routing ID already claimed by a different member. A nonzero rate here
/// signals either a misbehaving/forging peer or a routing-ID derivation bug.
pub(crate) fn record_pseudonym_announcement_rejected() {
    metrics::counter!("scp_pseudonym_announcements_rejected_total").increment(1);
}

/// Sets the active context gauge to the given count.
pub fn set_active_contexts(count: usize) {
    #[allow(clippy::cast_precision_loss)]
    metrics::gauge!("scp_active_contexts").set(count as f64);
}

/// Sets the buffer occupancy gauge (total events across all contexts).
pub fn set_buffer_occupancy(count: usize) {
    #[allow(clippy::cast_precision_loss)]
    metrics::gauge!("scp_buffer_occupancy").set(count as f64);
}
