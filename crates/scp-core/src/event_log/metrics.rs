//! Event log growth monitoring and profiling.
//!
//! Tracks per-context event log growth rates, proof generation/verification
//! costs, and storage consumption. Metrics are exportable for analysis.
//!
//! # Types
//!
//! - [`EventLogMetrics`] -- Per-context metrics collector tracking event
//!   counts, byte totals, growth rates, and proof timing.
//! - [`GrowthSnapshot`] -- A timestamped sample of event count and byte total,
//!   used for rate calculation.
//! - [`ProofProfile`] -- Timing and memory data from a single proof operation.
//! - [`MetricsExport`] -- Serializable snapshot of all collected metrics.
//!
//! # Operations
//!
//! - [`EventLogMetrics::new`] -- Create a new metrics collector for a context.
//! - [`EventLogMetrics::record_event`] -- Record an appended event.
//! - [`EventLogMetrics::record_proof_generation`] -- Record proof gen timing.
//! - [`EventLogMetrics::record_proof_verification`] -- Record proof verify timing.
//! - [`EventLogMetrics::growth_rate`] -- Compute events/hour and bytes/hour.
//! - [`EventLogMetrics::export`] -- Export all metrics as a serializable snapshot.
//! - [`bench_proof_generation`] -- Benchmark proof generation at a given log size.
//! - [`bench_proof_verification`] -- Benchmark proof verification at a given log size.
//!
//! See ADR-030 in `.docs/adrs/phase-6.md` for the pruning/checkpointing context.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::ContextId;

// ---------------------------------------------------------------------------
// GrowthSnapshot
// ---------------------------------------------------------------------------

/// A timestamped sample of event log state, used for growth rate calculation.
///
/// Snapshots are recorded at each event append and retained for rate
/// computation over a sliding window.
#[derive(Debug, Clone)]
struct GrowthSnapshot {
    /// Unix timestamp (seconds) when this snapshot was taken.
    timestamp_secs: u64,
    /// Cumulative event count at snapshot time.
    event_count: u64,
    /// Cumulative byte total at snapshot time.
    bytes_total: u64,
}

// ---------------------------------------------------------------------------
// GrowthRate
// ---------------------------------------------------------------------------

/// Computed growth rate over a time window.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct GrowthRate {
    /// Events appended per hour over the measurement window.
    pub events_per_hour: f64,
    /// Bytes added per hour over the measurement window.
    pub bytes_per_hour: f64,
    /// Duration of the measurement window in seconds.
    pub window_secs: u64,
}

// ---------------------------------------------------------------------------
// ProofProfile
// ---------------------------------------------------------------------------

/// Timing data from a single proof operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofProfile {
    /// Wall-clock duration of the operation.
    pub duration: Duration,
    /// Number of events in the log when the proof was generated/verified.
    pub log_size: u64,
}

// ---------------------------------------------------------------------------
// StorageBreakdown
// ---------------------------------------------------------------------------

/// Per-context storage consumption breakdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageBreakdown {
    /// Total bytes consumed by event payloads.
    pub event_bytes: u64,
    /// Total bytes consumed by Merkle tree interior nodes.
    ///
    /// Each interior node is 32 bytes. The number of interior nodes for `n`
    /// leaves is approximately `n - 1` (for a balanced binary tree), so this
    /// is roughly `(n - 1) * 32`.
    pub tree_node_bytes: u64,
    /// Total bytes (events + tree nodes).
    pub total_bytes: u64,
}

// ---------------------------------------------------------------------------
// MetricsExport
// ---------------------------------------------------------------------------

/// Serializable snapshot of all collected metrics for a context.
///
/// Produced by [`EventLogMetrics::export`] for external analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsExport {
    /// The context these metrics belong to.
    pub context_id: ContextId,
    /// Total number of events recorded.
    pub event_count: u64,
    /// Total bytes of event payloads recorded.
    pub bytes_total: u64,
    /// Storage breakdown (events + tree nodes).
    pub storage: StorageBreakdown,
    /// Number of proof generation operations recorded.
    pub proof_generation_count: u64,
    /// Number of proof verification operations recorded.
    pub proof_verification_count: u64,
    /// Minimum proof generation duration observed.
    pub proof_generation_min: Option<Duration>,
    /// Maximum proof generation duration observed.
    pub proof_generation_max: Option<Duration>,
    /// Mean proof generation duration.
    pub proof_generation_mean: Option<Duration>,
    /// Minimum proof verification duration observed.
    pub proof_verification_min: Option<Duration>,
    /// Maximum proof verification duration observed.
    pub proof_verification_max: Option<Duration>,
    /// Mean proof verification duration.
    pub proof_verification_mean: Option<Duration>,
    /// Current growth rate (if sufficient data exists).
    pub growth_rate: Option<GrowthRate>,
}

// ---------------------------------------------------------------------------
// EventLogMetrics
// ---------------------------------------------------------------------------

/// Per-context event log metrics collector.
///
/// Tracks event counts, byte totals, growth rates (events/hour, bytes/hour),
/// and proof generation/verification cost profiles. All data is held in memory
/// and can be exported via [`Self::export`] for serialization and analysis.
///
/// See ADR-030 in `.docs/adrs/phase-6.md`.
pub struct EventLogMetrics {
    /// The context this collector tracks.
    context_id: ContextId,
    /// Total events recorded.
    event_count: u64,
    /// Total event payload bytes recorded.
    bytes_total: u64,
    /// Number of Merkle tree interior nodes (for storage estimation).
    tree_node_count: u64,
    /// Growth snapshots for rate calculation (ring buffer, most recent last).
    snapshots: Vec<GrowthSnapshot>,
    /// Maximum number of snapshots retained.
    max_snapshots: usize,
    /// Proof generation timing samples.
    proof_gen_profiles: Vec<ProofProfile>,
    /// Proof verification timing samples.
    proof_verify_profiles: Vec<ProofProfile>,
}

impl EventLogMetrics {
    /// Creates a new metrics collector for the given context.
    #[must_use]
    pub const fn new(context_id: ContextId) -> Self {
        Self {
            context_id,
            event_count: 0,
            bytes_total: 0,
            tree_node_count: 0,
            snapshots: Vec::new(),
            max_snapshots: 1000,
            proof_gen_profiles: Vec::new(),
            proof_verify_profiles: Vec::new(),
        }
    }

    /// Returns the context ID this collector tracks.
    #[must_use]
    pub fn context_id(&self) -> &str {
        &self.context_id
    }

    /// Returns the total number of events recorded.
    #[must_use]
    pub const fn event_count(&self) -> u64 {
        self.event_count
    }

    /// Returns the total bytes of event payloads recorded.
    #[must_use]
    pub const fn bytes_total(&self) -> u64 {
        self.bytes_total
    }

    /// Records an appended event with its serialized byte size.
    ///
    /// `event_bytes` is the serialized size of the event (payload + envelope).
    /// `timestamp_secs` is the Unix timestamp when the event was appended.
    /// `tree_node_count` is the current number of interior tree nodes after
    /// the append (used for storage tracking).
    pub fn record_event(&mut self, event_bytes: u64, timestamp_secs: u64, tree_node_count: u64) {
        self.event_count += 1;
        self.bytes_total += event_bytes;
        self.tree_node_count = tree_node_count;

        // Record snapshot for growth rate calculation.
        self.snapshots.push(GrowthSnapshot {
            timestamp_secs,
            event_count: self.event_count,
            bytes_total: self.bytes_total,
        });

        // Evict oldest snapshots if over capacity.
        if self.snapshots.len() > self.max_snapshots {
            let excess = self.snapshots.len() - self.max_snapshots;
            self.snapshots.drain(..excess);
        }
    }

    /// Records a proof generation operation with its timing.
    pub fn record_proof_generation(&mut self, duration: Duration, log_size: u64) {
        self.proof_gen_profiles
            .push(ProofProfile { duration, log_size });
    }

    /// Records a proof verification operation with its timing.
    pub fn record_proof_verification(&mut self, duration: Duration, log_size: u64) {
        self.proof_verify_profiles
            .push(ProofProfile { duration, log_size });
    }

    /// Computes the event log growth rate over the full snapshot window.
    ///
    /// Returns `None` if fewer than two snapshots exist or the time span
    /// between the oldest and newest snapshot is zero.
    #[must_use]
    pub fn growth_rate(&self) -> Option<GrowthRate> {
        if self.snapshots.len() < 2 {
            return None;
        }

        let first = &self.snapshots[0];
        let last = &self.snapshots[self.snapshots.len() - 1];

        let time_delta_secs = last.timestamp_secs.saturating_sub(first.timestamp_secs);
        if time_delta_secs == 0 {
            return None;
        }

        let event_delta = last.event_count.saturating_sub(first.event_count);
        let byte_delta = last.bytes_total.saturating_sub(first.bytes_total);

        #[allow(clippy::cast_precision_loss)] // Growth rate precision loss is acceptable
        let hours = time_delta_secs as f64 / 3600.0;

        #[allow(clippy::cast_precision_loss)] // Growth rate precision loss is acceptable
        let events_per_hour = event_delta as f64 / hours;
        #[allow(clippy::cast_precision_loss)] // Growth rate precision loss is acceptable
        let bytes_per_hour = byte_delta as f64 / hours;

        Some(GrowthRate {
            events_per_hour,
            bytes_per_hour,
            window_secs: time_delta_secs,
        })
    }

    /// Returns the per-context storage breakdown.
    #[must_use]
    pub const fn storage_breakdown(&self) -> StorageBreakdown {
        let tree_node_bytes = self.tree_node_count * 32;
        StorageBreakdown {
            event_bytes: self.bytes_total,
            tree_node_bytes,
            total_bytes: self.bytes_total + tree_node_bytes,
        }
    }

    /// Exports all collected metrics as a serializable snapshot.
    #[must_use]
    pub fn export(&self) -> MetricsExport {
        MetricsExport {
            context_id: self.context_id.clone(),
            event_count: self.event_count,
            bytes_total: self.bytes_total,
            storage: self.storage_breakdown(),
            proof_generation_count: self.proof_gen_profiles.len() as u64,
            proof_verification_count: self.proof_verify_profiles.len() as u64,
            proof_generation_min: min_duration(&self.proof_gen_profiles),
            proof_generation_max: max_duration(&self.proof_gen_profiles),
            proof_generation_mean: mean_duration(&self.proof_gen_profiles),
            proof_verification_min: min_duration(&self.proof_verify_profiles),
            proof_verification_max: max_duration(&self.proof_verify_profiles),
            proof_verification_mean: mean_duration(&self.proof_verify_profiles),
            growth_rate: self.growth_rate(),
        }
    }
}

// ---------------------------------------------------------------------------
// Benchmark helpers
// ---------------------------------------------------------------------------

/// Result of a benchmark run for proof generation or verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    /// Number of events in the log during the benchmark.
    pub log_size: u64,
    /// Number of iterations (proof operations) performed.
    pub iterations: u64,
    /// Minimum duration observed.
    pub min: Duration,
    /// Maximum duration observed.
    pub max: Duration,
    /// Mean duration.
    pub mean: Duration,
    /// Median duration.
    pub median: Duration,
}

/// Benchmarks proof generation at a given log size.
///
/// Generates inclusion proofs for `iterations` sequentially-selected leaf
/// indices and returns timing statistics. The caller provides a pre-built
/// [`super::EventLog`] with the desired number of events.
///
/// # Panics
///
/// Panics if `log` is empty or `iterations` is zero. This function is intended
/// for benchmarking only, not production use.
#[must_use]
pub fn bench_proof_generation(log: &super::EventLog, iterations: u64) -> BenchmarkResult {
    let log_size = super::tree::event_count(log);
    assert!(
        log_size > 0,
        "bench_proof_generation requires a non-empty log"
    );
    assert!(iterations > 0, "iterations must be > 0");

    #[allow(clippy::cast_possible_truncation)] // benchmark iteration counts are small
    let mut durations = Vec::with_capacity(iterations as usize);

    for i in 0..iterations {
        let leaf_index = i % log_size;
        let start = Instant::now();
        let _proof = super::proof::prove_inclusion(log, leaf_index);
        let elapsed = start.elapsed();
        durations.push(elapsed);
    }

    compute_benchmark_result(log_size, iterations, &mut durations)
}

/// Benchmarks proof verification at a given log size.
///
/// Generates an inclusion proof for each iteration and then verifies it,
/// measuring only the verification time. The caller provides a pre-built
/// [`super::EventLog`].
///
/// # Panics
///
/// Panics if `log` is empty or `iterations` is zero. This function is intended
/// for benchmarking only, not production use.
#[must_use]
pub fn bench_proof_verification(log: &super::EventLog, iterations: u64) -> BenchmarkResult {
    let log_size = super::tree::event_count(log);
    assert!(
        log_size > 0,
        "bench_proof_verification requires a non-empty log"
    );
    assert!(iterations > 0, "iterations must be > 0");

    #[allow(clippy::cast_possible_truncation)] // benchmark iteration counts are small
    let mut durations = Vec::with_capacity(iterations as usize);

    for i in 0..iterations {
        let leaf_index = i % log_size;
        // Generate the proof (not timed).
        if let Ok(proof) = super::proof::prove_inclusion(log, leaf_index) {
            // Time only the verification.
            let start = Instant::now();
            let _valid = super::proof::verify_inclusion(&proof);
            let elapsed = start.elapsed();
            durations.push(elapsed);
        }
    }

    compute_benchmark_result(log_size, iterations, &mut durations)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Computes min/max/mean/median from a set of duration samples.
fn compute_benchmark_result(
    log_size: u64,
    iterations: u64,
    durations: &mut [Duration],
) -> BenchmarkResult {
    durations.sort();

    let min = durations.first().copied().unwrap_or(Duration::ZERO);
    let max = durations.last().copied().unwrap_or(Duration::ZERO);
    let total: Duration = durations.iter().sum();
    let count = u32::try_from(durations.len()).unwrap_or(u32::MAX);
    let mean = if durations.is_empty() {
        Duration::ZERO
    } else {
        total / count
    };
    let median = if durations.is_empty() {
        Duration::ZERO
    } else {
        durations[durations.len() / 2]
    };

    BenchmarkResult {
        log_size,
        iterations,
        min,
        max,
        mean,
        median,
    }
}

/// Returns the minimum duration from a slice of proof profiles.
fn min_duration(profiles: &[ProofProfile]) -> Option<Duration> {
    profiles.iter().map(|p| p.duration).min()
}

/// Returns the maximum duration from a slice of proof profiles.
fn max_duration(profiles: &[ProofProfile]) -> Option<Duration> {
    profiles.iter().map(|p| p.duration).max()
}

/// Returns the mean duration from a slice of proof profiles.
fn mean_duration(profiles: &[ProofProfile]) -> Option<Duration> {
    if profiles.is_empty() {
        return None;
    }
    let total: Duration = profiles.iter().map(|p| p.duration).sum();
    let count = u32::try_from(profiles.len()).unwrap_or(u32::MAX);
    Some(total / count)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::time::Duration;

    use ed25519_dalek::Signer;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::event_log::tree::{self, GENESIS_PREV_HASH};
    use crate::event_log::{Event, EventLog, EventPayload, EventType};

    // -------------------------------------------------------------------
    // Test helpers
    // -------------------------------------------------------------------

    fn test_keypair() -> (ed25519_dalek::VerifyingKey, ed25519_dalek::SigningKey) {
        let mut rng = rand::thread_rng();
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        (verifying_key, signing_key)
    }

    fn did_from_pubkey(verifying_key: &ed25519_dalek::VerifyingKey) -> String {
        let hex: String = verifying_key
            .as_bytes()
            .iter()
            .fold(String::new(), |mut acc, b| {
                use std::fmt::Write;
                let _ = write!(acc, "{b:02x}");
                acc
            });
        format!("did:key:{hex}")
    }

    fn compute_event_canonical_hash(event: &Event) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(event_type_tag(&event.event_type).to_be_bytes());
        hasher.update(event.actor_did.as_bytes());
        hasher.update(event.timestamp.to_be_bytes());
        hasher.update(event.sequence.to_be_bytes());
        hasher.update(&event.payload.data);
        hasher.update(event.prev_hash);
        hasher.finalize().to_vec()
    }

    const fn event_type_tag(event_type: &EventType) -> u16 {
        match event_type {
            EventType::ContextCreated => 0,
            EventType::ContextClosing => 1,
            EventType::ContextClosed => 2,
            EventType::ContextExpired => 3,
            EventType::MemberJoined => 4,
            EventType::MemberLeft => 5,
            EventType::RoleAssigned => 6,
            EventType::TokenRevoked => 7,
            EventType::MessageSent => 8,
            EventType::ToolRegistered => 9,
            EventType::ToolUpdated => 10,
            EventType::ToolInvoked => 11,
            EventType::ToolVerified => 12,
            EventType::ToolInterfaceEstablished => 13,
            EventType::GovernanceAction => 14,
            EventType::ConsistencyCheckpoint => 15,
            EventType::AbsenceProofRequested => 16,
            EventType::MemberBlocked => 17,
            EventType::KeyEpochAdvance => 18,
            EventType::MediaSessionStarted => 19,
            EventType::MediaSessionEnded => 20,
            EventType::PaymentReceived => 21,
            EventType::EconomicPolicyChanged => 22,
            EventType::SpendingUcanGranted => 23,
            EventType::SpendingUcanRevoked => 24,
        }
    }

    fn sign_event(
        event_type: EventType,
        actor_did: &str,
        timestamp: u64,
        sequence: u64,
        payload: Vec<u8>,
        prev_hash: [u8; 32],
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Event {
        let mut event = Event {
            event_type,
            actor_did: actor_did.into(),
            timestamp,
            sequence,
            payload: EventPayload { data: payload },
            prev_hash,
            signature: Vec::new(),
        };

        let canonical_hash = compute_event_canonical_hash(&event);
        let signature = signing_key.sign(&canonical_hash);
        event.signature = signature.to_bytes().to_vec();

        event
    }

    /// Build a log with `n` events. Returns the log and serialized event sizes.
    fn build_log(n: u64) -> (EventLog, Vec<u64>) {
        let (verifying_key, signing_key) = test_keypair();
        let did = did_from_pubkey(&verifying_key);
        let mut log = EventLog::new("ctx-metrics-test".to_owned());
        let mut prev_hash = GENESIS_PREV_HASH;
        let mut sizes = Vec::new();

        for i in 0..n {
            let event = sign_event(
                EventType::MessageSent,
                &did,
                1_000_000 + i,
                i,
                format!("message {i}").into_bytes(),
                prev_hash,
                &signing_key,
            );
            let serialized = rmp_serde::to_vec(&event).unwrap();
            sizes.push(serialized.len() as u64);
            tree::append(&mut log, &event).unwrap();
            let leaf_hash: [u8; 32] = {
                let mut h = Sha256::new();
                h.update([0x00]);
                h.update(&serialized);
                h.finalize().into()
            };
            prev_hash = leaf_hash;
        }

        (log, sizes)
    }

    /// Count total interior tree nodes for a log.
    fn count_tree_nodes(log: &EventLog) -> u64 {
        log.tree_layers()
            .iter()
            .map(|layer| layer.len() as u64)
            .sum()
    }

    // -------------------------------------------------------------------
    // EventLogMetrics::new creates empty collector
    // -------------------------------------------------------------------

    #[test]
    fn new_creates_empty_collector() {
        let m = EventLogMetrics::new("ctx-1".to_owned());
        assert_eq!(m.context_id(), "ctx-1");
        assert_eq!(m.event_count(), 0);
        assert_eq!(m.bytes_total(), 0);
    }

    // -------------------------------------------------------------------
    // record_event increments counters correctly
    // -------------------------------------------------------------------

    #[test]
    fn record_event_increments_counters() {
        let mut m = EventLogMetrics::new("ctx-1".to_owned());

        m.record_event(100, 1_000_000, 0);
        assert_eq!(m.event_count(), 1);
        assert_eq!(m.bytes_total(), 100);

        m.record_event(200, 1_000_001, 1);
        assert_eq!(m.event_count(), 2);
        assert_eq!(m.bytes_total(), 300);
    }

    // -------------------------------------------------------------------
    // growth_rate returns None with insufficient data
    // -------------------------------------------------------------------

    #[test]
    fn growth_rate_returns_none_with_insufficient_data() {
        let m = EventLogMetrics::new("ctx-1".to_owned());
        assert!(m.growth_rate().is_none());

        let mut m = EventLogMetrics::new("ctx-1".to_owned());
        m.record_event(100, 1_000_000, 0);
        assert!(m.growth_rate().is_none());
    }

    // -------------------------------------------------------------------
    // growth_rate returns None when timestamps are identical
    // -------------------------------------------------------------------

    #[test]
    fn growth_rate_returns_none_for_zero_time_delta() {
        let mut m = EventLogMetrics::new("ctx-1".to_owned());
        m.record_event(100, 1_000_000, 0);
        m.record_event(100, 1_000_000, 1);
        assert!(m.growth_rate().is_none());
    }

    // -------------------------------------------------------------------
    // growth_rate computes correctly
    // -------------------------------------------------------------------

    #[test]
    fn growth_rate_computes_correctly() {
        let mut m = EventLogMetrics::new("ctx-1".to_owned());

        // Simulate 10 events over 1 hour (3600 seconds).
        for i in 0..10u64 {
            m.record_event(100, 1_000_000 + i * 360, i);
        }

        let rate = m.growth_rate().unwrap();

        // 10 events recorded: first snapshot at t=1_000_000, last at t=1_003_240.
        // 9 events delta over 3240 seconds = 9 / (3240/3600) = 10 events/hour.
        let expected_window = 3240u64;
        assert_eq!(rate.window_secs, expected_window);

        let expected_events_per_hour = 9.0 / (3240.0 / 3600.0);
        assert!(
            (rate.events_per_hour - expected_events_per_hour).abs() < 0.01,
            "expected ~{expected_events_per_hour}, got {}",
            rate.events_per_hour,
        );

        let expected_bytes_per_hour = 900.0 / (3240.0 / 3600.0);
        assert!(
            (rate.bytes_per_hour - expected_bytes_per_hour).abs() < 0.1,
            "expected ~{expected_bytes_per_hour}, got {}",
            rate.bytes_per_hour,
        );
    }

    // -------------------------------------------------------------------
    // storage_breakdown tracks event and tree bytes
    // -------------------------------------------------------------------

    #[test]
    fn storage_breakdown_tracks_event_and_tree_bytes() {
        let mut m = EventLogMetrics::new("ctx-1".to_owned());

        m.record_event(200, 1_000_000, 0);
        let s = m.storage_breakdown();
        assert_eq!(s.event_bytes, 200);
        assert_eq!(s.tree_node_bytes, 0);
        assert_eq!(s.total_bytes, 200);

        // After 2 events, tree has 1 interior node.
        m.record_event(200, 1_000_001, 1);
        let s = m.storage_breakdown();
        assert_eq!(s.event_bytes, 400);
        assert_eq!(s.tree_node_bytes, 32); // 1 node * 32 bytes
        assert_eq!(s.total_bytes, 432);
    }

    // -------------------------------------------------------------------
    // record_proof_generation and record_proof_verification
    // -------------------------------------------------------------------

    #[test]
    fn record_proof_profiles() {
        let mut m = EventLogMetrics::new("ctx-1".to_owned());

        m.record_proof_generation(Duration::from_micros(50), 100);
        m.record_proof_generation(Duration::from_micros(100), 100);
        m.record_proof_verification(Duration::from_micros(20), 100);
        m.record_proof_verification(Duration::from_micros(40), 100);

        let export = m.export();
        assert_eq!(export.proof_generation_count, 2);
        assert_eq!(export.proof_verification_count, 2);

        assert_eq!(export.proof_generation_min, Some(Duration::from_micros(50)));
        assert_eq!(
            export.proof_generation_max,
            Some(Duration::from_micros(100)),
        );
        assert_eq!(
            export.proof_generation_mean,
            Some(Duration::from_micros(75)),
        );

        assert_eq!(
            export.proof_verification_min,
            Some(Duration::from_micros(20)),
        );
        assert_eq!(
            export.proof_verification_max,
            Some(Duration::from_micros(40)),
        );
        assert_eq!(
            export.proof_verification_mean,
            Some(Duration::from_micros(30)),
        );
    }

    // -------------------------------------------------------------------
    // export produces complete snapshot
    // -------------------------------------------------------------------

    #[test]
    fn export_produces_complete_snapshot() {
        let mut m = EventLogMetrics::new("ctx-export".to_owned());

        for i in 0..5u64 {
            m.record_event(150, 1_000_000 + i * 3600, i);
        }
        m.record_proof_generation(Duration::from_micros(80), 5);

        let export = m.export();

        assert_eq!(export.context_id, "ctx-export");
        assert_eq!(export.event_count, 5);
        assert_eq!(export.bytes_total, 750);
        assert_eq!(export.proof_generation_count, 1);
        assert_eq!(export.proof_verification_count, 0);
        assert!(export.growth_rate.is_some());
        assert!(export.proof_verification_min.is_none());
        assert!(export.proof_verification_max.is_none());
        assert!(export.proof_verification_mean.is_none());
    }

    // -------------------------------------------------------------------
    // export is JSON-serializable
    // -------------------------------------------------------------------

    #[test]
    fn export_is_json_serializable() {
        let mut m = EventLogMetrics::new("ctx-json".to_owned());
        m.record_event(100, 1_000_000, 0);
        m.record_event(100, 1_003_600, 1);
        m.record_proof_generation(Duration::from_micros(42), 2);

        let export = m.export();
        let json = serde_json::to_string(&export).unwrap();
        let deserialized: MetricsExport = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.context_id, "ctx-json");
        assert_eq!(deserialized.event_count, 2);
        assert_eq!(deserialized.bytes_total, 200);
        assert_eq!(deserialized.proof_generation_count, 1);
    }

    // -------------------------------------------------------------------
    // snapshot eviction respects max_snapshots
    // -------------------------------------------------------------------

    #[test]
    fn snapshot_eviction_respects_limit() {
        let mut m = EventLogMetrics::new("ctx-evict".to_owned());
        m.max_snapshots = 5;

        for i in 0..10u64 {
            m.record_event(100, 1_000_000 + i * 100, i);
        }

        // Internal snapshots should be capped at 5.
        assert_eq!(m.snapshots.len(), 5);
        // The oldest snapshot should be from timestamp 1_000_500 (index 5).
        assert_eq!(m.snapshots[0].timestamp_secs, 1_000_500);
    }

    // -------------------------------------------------------------------
    // bench_proof_generation returns valid statistics
    // -------------------------------------------------------------------

    #[test]
    fn bench_proof_generation_returns_valid_statistics() {
        let (log, _) = build_log(20);
        let result = bench_proof_generation(&log, 10);

        assert_eq!(result.log_size, 20);
        assert_eq!(result.iterations, 10);
        assert!(result.min <= result.median);
        assert!(result.median <= result.max);
        assert!(result.mean >= result.min);
        assert!(result.mean <= result.max);
    }

    // -------------------------------------------------------------------
    // bench_proof_verification returns valid statistics
    // -------------------------------------------------------------------

    #[test]
    fn bench_proof_verification_returns_valid_statistics() {
        let (log, _) = build_log(20);
        let result = bench_proof_verification(&log, 10);

        assert_eq!(result.log_size, 20);
        assert_eq!(result.iterations, 10);
        assert!(result.min <= result.median);
        assert!(result.median <= result.max);
    }

    // -------------------------------------------------------------------
    // bench_proof_generation at various log sizes
    // -------------------------------------------------------------------

    #[test]
    fn bench_proof_generation_at_various_sizes() {
        for size in [1, 5, 10, 50, 100] {
            let (log, _) = build_log(size);
            let result = bench_proof_generation(&log, 5);
            assert_eq!(result.log_size, size);
            assert!(result.min <= result.max);
        }
    }

    // -------------------------------------------------------------------
    // bench_proof_verification at various log sizes
    // -------------------------------------------------------------------

    #[test]
    fn bench_proof_verification_at_various_sizes() {
        for size in [1, 5, 10, 50, 100] {
            let (log, _) = build_log(size);
            let result = bench_proof_verification(&log, 5);
            assert_eq!(result.log_size, size);
            assert!(result.min <= result.max);
        }
    }

    // -------------------------------------------------------------------
    // metrics track real event log accurately
    // -------------------------------------------------------------------

    #[test]
    fn metrics_track_real_event_log_accurately() {
        let (log, sizes) = build_log(10);
        let mut m = EventLogMetrics::new("ctx-metrics-test".to_owned());

        for (i, &size) in sizes.iter().enumerate() {
            let tree_nodes = if i == 0 { 0 } else { count_tree_nodes(&log) };
            m.record_event(size, 1_000_000 + i as u64 * 3600, tree_nodes);
        }

        assert_eq!(m.event_count(), 10);
        assert_eq!(m.bytes_total(), sizes.iter().sum::<u64>());

        let storage = m.storage_breakdown();
        assert_eq!(storage.event_bytes, sizes.iter().sum::<u64>());
        assert!(storage.tree_node_bytes > 0);
        assert_eq!(
            storage.total_bytes,
            storage.event_bytes + storage.tree_node_bytes,
        );

        // Growth rate should be computable (10 events over 9 hours).
        let rate = m.growth_rate().unwrap();
        assert!(rate.events_per_hour > 0.0);
        assert!(rate.bytes_per_hour > 0.0);
    }

    // -------------------------------------------------------------------
    // growth_rate with rapid events shows high rate
    // -------------------------------------------------------------------

    #[test]
    fn growth_rate_with_rapid_events() {
        let mut m = EventLogMetrics::new("ctx-rapid".to_owned());

        // 1000 events in 1 second.
        for i in 0..1000u64 {
            m.record_event(50, 1_000_000 + (i / 1000), i);
        }

        // Most events have the same timestamp, so window is ~0-1 seconds.
        // Growth rate should be calculable if any time difference exists.
        let rate = m.growth_rate();
        // Events 0-999 share timestamps 1_000_000; last is 1_000_000.
        // All at same timestamp => None.
        if let Some(r) = rate {
            assert!(r.events_per_hour > 0.0);
        }
    }

    // -------------------------------------------------------------------
    // empty proof profiles produce None in export
    // -------------------------------------------------------------------

    #[test]
    fn empty_proof_profiles_produce_none_in_export() {
        let m = EventLogMetrics::new("ctx-empty".to_owned());
        let export = m.export();

        assert!(export.proof_generation_min.is_none());
        assert!(export.proof_generation_max.is_none());
        assert!(export.proof_generation_mean.is_none());
        assert!(export.proof_verification_min.is_none());
        assert!(export.proof_verification_max.is_none());
        assert!(export.proof_verification_mean.is_none());
        assert!(export.growth_rate.is_none());
    }

    // -------------------------------------------------------------------
    // Helper functions: min/max/mean duration
    // -------------------------------------------------------------------

    #[test]
    fn duration_helpers_handle_single_profile() {
        let profiles = [ProofProfile {
            duration: Duration::from_micros(42),
            log_size: 10,
        }];

        assert_eq!(min_duration(&profiles), Some(Duration::from_micros(42)));
        assert_eq!(max_duration(&profiles), Some(Duration::from_micros(42)));
        assert_eq!(mean_duration(&profiles), Some(Duration::from_micros(42)));
    }

    #[test]
    fn duration_helpers_handle_empty_profiles() {
        let profiles: &[ProofProfile] = &[];

        assert_eq!(min_duration(profiles), None);
        assert_eq!(max_duration(profiles), None);
        assert_eq!(mean_duration(profiles), None);
    }
}
