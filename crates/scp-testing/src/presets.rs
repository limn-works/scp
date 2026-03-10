//! Preset test scenarios for common protocol testing patterns.
//!
//! Each function creates a pre-configured [`PresetScenario`] with the
//! appropriate relay behavior and simulated clock, ready for immediate use
//! in tests. These are convenience wrappers over [`InMemoryRelay`] and
//! [`SimulatedClock`] — they do not involve the `NetworkSimulator` (which
//! is built on top of these primitives in a separate module).
//!
//! # Scenarios
//!
//! | Function | Relays | Behavior | Purpose |
//! |----------|--------|----------|---------|
//! | [`two_party_basic`] | 1 | Normal | Simple two-party messaging |
//! | [`five_party_group`] | 1 | Normal | Multi-party group scenarios |
//! | [`suppression_scenario`] | 1 | Suppressing (drop every 2nd) | Message suppression detection |
//! | [`equivocation_scenario`] | 1 | Equivocating (after 5 msgs) | Equivocation detection |
//! | [`relay_partitioned`] | 2 | Normal + Normal | Network partition simulation |
//! | [`ephemeral_ttl`] | 1 | Normal | TTL expiration testing |
//! | [`blocking_scenario`] | 1 | Normal | Content access control |
//! | [`reorder_scenario`] | 1 | Delayed (100-500ms) | Out-of-order delivery |

#![forbid(unsafe_code)]

use std::sync::{Arc, Mutex};

use crate::clock::SimulatedClock;
use crate::relay::behavior::{DelayConfig, EquivocationConfig, SuppressionConfig};
use crate::relay::{BehaviorMode, InMemoryRelay};

/// The default epoch-seconds start time for all preset clocks.
///
/// Set to 1,000,000 (1970-01-12T13:46:40Z) to avoid edge cases at epoch 0
/// while remaining deterministic.
const DEFAULT_START_SECS: u64 = 1_000_000;

/// Result of a preset scenario setup.
///
/// Contains the simulated clock and one or more relays, each with a
/// human-readable label. Tests destructure this to access the components
/// they need.
pub struct PresetScenario {
    /// Simulated clock for time control.
    pub clock: Arc<SimulatedClock>,
    /// The relay(s) in this scenario.
    pub relays: Vec<Arc<Mutex<InMemoryRelay>>>,
    /// Human-readable labels for the relays (same length as `relays`).
    pub relay_labels: Vec<String>,
}

impl PresetScenario {
    /// Returns a reference to the first (and often only) relay.
    ///
    /// # Panics
    ///
    /// Panics if the scenario has no relays (should never happen with the
    /// provided preset functions).
    #[must_use]
    #[allow(clippy::expect_used)] // Preset scenarios always have at least one relay.
    pub fn relay(&self) -> &Arc<Mutex<InMemoryRelay>> {
        self.relays.first().expect("preset scenario has no relays")
    }
}

// ---------------------------------------------------------------------------
// Preset factories
// ---------------------------------------------------------------------------

/// Two-party basic messaging scenario.
///
/// - 1 relay with [`BehaviorMode::Normal`].
/// - Clock starts at epoch 1,000,000.
///
/// Use for simple send/receive tests between two participants.
#[must_use]
pub fn two_party_basic() -> PresetScenario {
    PresetScenario {
        clock: Arc::new(SimulatedClock::new(DEFAULT_START_SECS)),
        relays: vec![Arc::new(Mutex::new(InMemoryRelay::new()))],
        relay_labels: vec!["primary".to_owned()],
    }
}

/// Five-party group messaging scenario.
///
/// - 1 relay with [`BehaviorMode::Normal`].
/// - Clock starts at epoch 1,000,000.
///
/// Use for multi-party group protocol tests (MLS group operations, fan-out
/// delivery, governance actions, etc.).
#[must_use]
pub fn five_party_group() -> PresetScenario {
    PresetScenario {
        clock: Arc::new(SimulatedClock::new(DEFAULT_START_SECS)),
        relays: vec![Arc::new(Mutex::new(InMemoryRelay::new()))],
        relay_labels: vec!["group-relay".to_owned()],
    }
}

/// Message suppression scenario.
///
/// - 1 relay with [`BehaviorMode::Suppressing`] configured to drop every
///   2nd message.
/// - Clock starts at epoch 1,000,000.
///
/// Use for testing suppression detection, cross-relay consistency checks,
/// and reliability scoring.
#[must_use]
pub fn suppression_scenario() -> PresetScenario {
    PresetScenario {
        clock: Arc::new(SimulatedClock::new(DEFAULT_START_SECS)),
        relays: vec![Arc::new(Mutex::new(InMemoryRelay::with_behavior(
            BehaviorMode::Suppressing(SuppressionConfig { drop_nth: 2 }),
        )))],
        relay_labels: vec!["suppressing-relay".to_owned()],
    }
}

/// Equivocation scenario.
///
/// - 1 relay with [`BehaviorMode::Equivocating`] configured to diverge
///   after 5 messages.
/// - Clock starts at epoch 1,000,000.
///
/// Use for testing equivocation detection, consistency alerts, and
/// subscriber-specific content verification.
#[must_use]
pub fn equivocation_scenario() -> PresetScenario {
    PresetScenario {
        clock: Arc::new(SimulatedClock::new(DEFAULT_START_SECS)),
        relays: vec![Arc::new(Mutex::new(InMemoryRelay::with_behavior(
            BehaviorMode::Equivocating(EquivocationConfig { diverge_after: 5 }),
        )))],
        relay_labels: vec!["equivocating-relay".to_owned()],
    }
}

/// Network partition scenario.
///
/// - 2 relays, both [`BehaviorMode::Normal`].
/// - Clock starts at epoch 1,000,000.
///
/// Simulates a network partition by having separate relays: participants
/// subscribed to different relays will not see each other's messages until
/// the partition is healed (by bridging or re-subscribing).
#[must_use]
pub fn relay_partitioned() -> PresetScenario {
    PresetScenario {
        clock: Arc::new(SimulatedClock::new(DEFAULT_START_SECS)),
        relays: vec![
            Arc::new(Mutex::new(InMemoryRelay::new())),
            Arc::new(Mutex::new(InMemoryRelay::new())),
        ],
        relay_labels: vec!["partition-a".to_owned(), "partition-b".to_owned()],
    }
}

/// Ephemeral TTL testing scenario.
///
/// - 1 relay with [`BehaviorMode::Normal`].
/// - Clock starts at epoch 1,000,000.
///
/// Use for testing blob TTL expiration. Advance the simulated clock past
/// the TTL and call [`InMemoryRelay::expire_blobs`] to verify cleanup.
#[must_use]
pub fn ephemeral_ttl() -> PresetScenario {
    PresetScenario {
        clock: Arc::new(SimulatedClock::new(DEFAULT_START_SECS)),
        relays: vec![Arc::new(Mutex::new(InMemoryRelay::new()))],
        relay_labels: vec!["ttl-relay".to_owned()],
    }
}

/// Content blocking scenario.
///
/// - 1 relay with [`BehaviorMode::Normal`].
/// - Clock starts at epoch 1,000,000.
///
/// Use for testing sender-side content access control (AES-256 access key
/// layer per ADR-038). The relay itself is faithful; blocking is enforced
/// at the encryption layer.
#[must_use]
pub fn blocking_scenario() -> PresetScenario {
    PresetScenario {
        clock: Arc::new(SimulatedClock::new(DEFAULT_START_SECS)),
        relays: vec![Arc::new(Mutex::new(InMemoryRelay::new()))],
        relay_labels: vec!["blocking-relay".to_owned()],
    }
}

/// Message reorder / delay scenario.
///
/// - 1 relay with [`BehaviorMode::Delayed`] configured for 100-500ms
///   jitter.
/// - Clock starts at epoch 1,000,000.
///
/// Use for testing out-of-order delivery handling. Note that at the
/// [`InMemoryRelay`] level, delayed mode still delivers immediately (the
/// delay is simulated at a higher async layer); this preset sets up the
/// configuration so that higher-level simulators can read it.
#[must_use]
pub fn reorder_scenario() -> PresetScenario {
    PresetScenario {
        clock: Arc::new(SimulatedClock::new(DEFAULT_START_SECS)),
        relays: vec![Arc::new(Mutex::new(InMemoryRelay::with_behavior(
            BehaviorMode::Delayed(DelayConfig {
                min_ms: 100,
                max_ms: 500,
            }),
        )))],
        relay_labels: vec!["delayed-relay".to_owned()],
    }
}
