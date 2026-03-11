//! Fault injection modes for simulated relays.
//!
//! These types model the misbehavior scenarios described in spec section 16,
//! allowing tests to verify protocol resilience against faulty or malicious
//! relay implementations.

#![forbid(unsafe_code)]

/// Configuration for periodic message suppression.
#[derive(Clone, Debug)]
pub struct SuppressionConfig {
    /// Drop every Nth message (1-indexed). A value of 3 means messages 3, 6, 9, ... are dropped.
    pub drop_nth: u32,
}

/// Configuration for equivocation (serving divergent content to different subscribers).
#[derive(Clone, Debug)]
pub struct EquivocationConfig {
    /// Begin serving divergent content after this many messages have been delivered.
    pub diverge_after: u32,
}

/// Configuration for delivery delay injection.
#[derive(Clone, Debug)]
pub struct DelayConfig {
    /// Minimum delay in milliseconds.
    pub min_ms: u64,
    /// Maximum delay in milliseconds.
    pub max_ms: u64,
}

/// Configuration for message replay attacks.
#[derive(Clone, Debug)]
pub struct ReplayConfig {
    /// Number of additional times each message is replayed (1 = delivered twice total).
    pub replay_count: u32,
}

/// Configuration for selective MLS commit suppression.
#[derive(Clone, Debug)]
pub struct CommitSuppressionConfig {
    /// Probability of suppressing an MLS commit message, in the range `[0.0, 1.0]`.
    pub suppress_probability: f64,
}

/// Fault injection modes for simulated relays (spec section 16).
///
/// Each variant models a specific relay misbehavior scenario. The
/// [`Composite`](BehaviorMode::Composite) variant allows combining multiple
/// fault modes for complex adversarial testing.
#[derive(Clone, Debug, Default)]
pub enum BehaviorMode {
    /// No faults — faithful relay behavior.
    #[default]
    Normal,
    /// Drop messages periodically.
    Suppressing(SuppressionConfig),
    /// Send different content to different subscribers.
    Equivocating(EquivocationConfig),
    /// Add latency to deliveries.
    Delayed(DelayConfig),
    /// Replay old messages.
    Replaying(ReplayConfig),
    /// Suppress MLS commit messages specifically.
    CommitSuppressing(CommitSuppressionConfig),
    /// Ignore DELETE requests (blob persists).
    DeletionNonCompliant,
    /// Compose multiple behaviors.
    Composite(Vec<Self>),
}

impl BehaviorMode {
    /// Returns `true` if this is the [`Normal`](BehaviorMode::Normal) variant
    /// (no fault injection).
    #[must_use]
    pub const fn is_normal(&self) -> bool {
        matches!(self, Self::Normal)
    }
}
