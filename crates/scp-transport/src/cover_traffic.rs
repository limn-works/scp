//! Cover traffic generation for metadata privacy.
//!
//! Spec section 9.10.6 mandates tiered cover traffic on persistent
//! connections to mask activity patterns. This module provides:
//!
//! - [`CoverTrafficConfig`] -- per-connection configuration driven by
//!   [`CoverTrafficTier`].
//! - [`CoverTrafficGenerator`] -- produces dummy messages on a strict timer,
//!   always emitting exactly one dummy per interval regardless of real traffic.
//! - [`CoverAction`] -- the decision output: send a dummy or skip (off tier).
//!
//! Cover traffic is per relay connection, not per context (spec 9.10.6 item 4).
//! A single timer per connection prevents relay correlation of traffic rate
//! changes with context activity.
//!
//! **Constant-rate invariant:** The generator always emits a dummy at each tick.
//! Real messages sent by the application are additional traffic; they never
//! suppress a dummy. Suppressing dummies when real messages are sent creates a
//! timing oracle -- observable gaps reveal that a real message was sent.
//!
//! See spec section 9.10.6 and ADR-036 for the full design.

use std::time::Duration;

use rand::RngCore;
use scp_core::envelope::BUCKET_SIZES;
use tokio::time::Instant;

use crate::profile::CoverTrafficTier;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The single-byte flag that marks a dummy message payload. Recipients
/// decrypt, check this flag, and discard dummies (spec 9.10.6 item 3).
pub const DUMMY_FLAG: u8 = 0x00;

/// The single-byte flag that marks a real message payload. Used to
/// distinguish real content from cover traffic after decryption.
pub const REAL_FLAG: u8 = 0x01;

/// Pads a payload to the nearest canonical bucket boundary.
///
/// Uses the same bucket sizes as the core encryption layer
/// (`scp_core::envelope::BUCKET_SIZES`: 256, 1024, 4096, 16384, 65536,
/// 262144) so that dummy traffic frame sizes are indistinguishable from
/// real traffic frame sizes at the wire level (CRYPTO-009b fix, spec
/// §9.10.6). Padding bytes are filled with random data to prevent
/// distinguishing padded regions from content via entropy analysis.
#[must_use]
pub fn pad_to_bucket(payload: &[u8]) -> Vec<u8> {
    let target = bucket_size_for(payload.len());
    let mut padded = Vec::with_capacity(target);
    padded.extend_from_slice(payload);
    if padded.len() < target {
        let start = padded.len();
        padded.resize(target, 0);
        rand::thread_rng().fill_bytes(&mut padded[start..]);
    }
    padded
}

/// Returns the canonical bucket size for a given payload length. Uses
/// `scp_core::envelope::BUCKET_SIZES` to ensure cover traffic frame sizes
/// match real traffic frame sizes (CRYPTO-009b fix).
#[must_use]
fn bucket_size_for(len: usize) -> usize {
    for &bucket in &BUCKET_SIZES {
        if len <= bucket {
            return bucket;
        }
    }
    // For payloads larger than the largest bucket, round up to next power of 2.
    // This matches the core layer's behavior for oversized payloads.
    len.next_power_of_two()
}

// ---------------------------------------------------------------------------
// CoverTrafficConfig
// ---------------------------------------------------------------------------

/// Configuration for cover traffic generation on a single relay connection.
///
/// Uses [`CoverTrafficTier`] to determine the interval and padding size.
/// Defaults to `CoverTrafficTier::Full` (30-second interval, 1024-byte
/// padding) per spec §9.10.6. Use [`CoverTrafficTier::from_profile`] to
/// derive the tier from a [`TransportProfile`](crate::profile::TransportProfile).
///
/// See spec §9.10.6 and ADR-036 for the tiered cover traffic design.
#[derive(Debug, Clone)]
pub struct CoverTrafficConfig {
    /// The cover traffic tier controlling interval and padding size.
    ///
    /// - `Full`: 30s interval, 1024-byte padding (maximum metadata privacy).
    /// - `Reduced`: 120s interval, 256-byte padding (battery-conscious).
    /// - `Off`: No cover traffic (constrained devices, push-wake).
    /// - `Custom`: User-specified interval and padding size.
    pub tier: CoverTrafficTier,

    /// Optional bytes-per-minute cap across all connections (spec §9.10.6).
    ///
    /// When the budget is reached, the tier degrades gracefully:
    /// `Full` -> `Reduced` -> `Off`. The budget is a soft limit for
    /// resource-constrained environments, not a security feature.
    ///
    /// `None` means no bandwidth limit (the default).
    pub bandwidth_budget_bytes_per_min: Option<u64>,
}

impl Default for CoverTrafficConfig {
    fn default() -> Self {
        Self {
            tier: CoverTrafficTier::Full,
            bandwidth_budget_bytes_per_min: None,
        }
    }
}

impl CoverTrafficConfig {
    /// Creates a `CoverTrafficConfig` from a [`TransportProfile`](crate::profile::TransportProfile).
    ///
    /// Maps the profile to its default tier via [`CoverTrafficTier::from_profile`].
    /// No bandwidth budget is applied by default.
    #[must_use]
    pub const fn from_profile(profile: crate::profile::TransportProfile) -> Self {
        Self {
            tier: CoverTrafficTier::from_profile(profile),
            bandwidth_budget_bytes_per_min: None,
        }
    }
}

// ---------------------------------------------------------------------------
// CoverAction
// ---------------------------------------------------------------------------

/// The action a cover traffic generator recommends for the current cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoverAction {
    /// Send a dummy message. The payload is a padded dummy (single `DUMMY_FLAG`
    /// byte followed by random padding to the tier's message size).
    SendDummy(Vec<u8>),
    /// Skip this cycle because cover traffic is off (tier is `Off`) or the
    /// interval has not yet elapsed. This variant is never returned due to
    /// real message activity -- dummies are always sent at each tick to
    /// maintain constant rate and prevent timing oracles.
    Skip,
}

// ---------------------------------------------------------------------------
// CoverTrafficSender
// ---------------------------------------------------------------------------

/// Trait for sending cover traffic payloads over a relay connection.
///
/// Implementors map the padded dummy payload onto the transport's wire format.
/// This keeps the cover traffic module self-contained and decoupled from
/// specific relay implementation details.
pub trait CoverTrafficSender: Send + Sync {
    /// Send a cover traffic payload over the connection.
    ///
    /// The payload is a padded dummy message (single `DUMMY_FLAG` byte followed
    /// by zero-padding). The implementor is responsible for encrypting and
    /// framing the payload before transmission.
    fn send_cover_traffic(
        &self,
        payload: Vec<u8>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), crate::error::TransportError>> + Send + '_>,
    >;
}

// ---------------------------------------------------------------------------
// CoverTrafficGenerator
// ---------------------------------------------------------------------------

/// Generates cover traffic for a single relay connection.
///
/// Produces dummy messages at a strict constant rate regardless of real
/// message activity (spec 9.10.6 item 1). Real messages are sent by the
/// application as additional traffic; they never suppress a dummy. This
/// ensures the relay always observes exactly one dummy per interval,
/// preventing timing oracles where gaps reveal real message sends.
///
/// This struct is per-connection, not per-context (spec 9.10.6 item 4).
///
/// # Bandwidth budget enforcement
///
/// When `CoverTrafficConfig::bandwidth_budget_bytes_per_min` is set, the
/// generator tracks bytes sent per minute and degrades the effective tier
/// gracefully when the budget is exhausted: `Full` -> `Reduced` -> `Off`
/// (spec §9.10.6 "Bandwidth budget"). The budget resets each minute.
///
/// # Usage
///
/// The caller runs a timer at the configured interval and calls
/// [`next_action`](Self::next_action) each tick, passing the current
/// [`Instant`].
#[derive(Debug)]
pub struct CoverTrafficGenerator {
    config: CoverTrafficConfig,
    last_tick: Option<Instant>,
    /// Bytes of cover traffic sent in the current budget period.
    bytes_sent_this_period: u64,
    /// Start of the current budget tracking period (1-minute windows).
    period_start: Option<Instant>,
}

impl CoverTrafficGenerator {
    /// Creates a new cover traffic generator with the given configuration.
    #[must_use]
    pub const fn new(config: CoverTrafficConfig) -> Self {
        Self {
            config,
            last_tick: None,
            bytes_sent_this_period: 0,
            period_start: None,
        }
    }

    /// Returns the configured interval between cover traffic messages.
    ///
    /// Returns `None` when the tier is `Off`.
    #[must_use]
    pub const fn interval(&self) -> Option<Duration> {
        self.config.tier.interval()
    }

    /// Returns whether cover traffic is enabled (tier is not `Off`).
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.config.tier.is_enabled()
    }

    /// Returns a reference to the active cover traffic tier.
    #[must_use]
    pub const fn tier(&self) -> &CoverTrafficTier {
        &self.config.tier
    }

    /// Determines whether to send a dummy message or skip this cycle.
    ///
    /// Called at each interval tick. Returns [`CoverAction::SendDummy`] with
    /// a padded payload unconditionally when the interval has elapsed,
    /// maintaining constant-rate traffic regardless of real message activity.
    /// Returns [`CoverAction::Skip`] only if cover traffic is off (tier is
    /// `Off`) or the interval has not yet elapsed.
    ///
    /// Real messages sent by the application are additional traffic and never
    /// suppress a dummy. This prevents timing oracles where a relay operator
    /// could observe gaps in the constant-rate stream and infer that a real
    /// message was sent during that window.
    ///
    /// The `now` parameter enables deterministic testing without real timers.
    #[must_use]
    pub fn next_action(&mut self, now: Instant) -> CoverAction {
        // Determine the effective tier after applying bandwidth budget
        // degradation (§9.10.6 "Bandwidth budget"). If no budget is set,
        // the configured tier is used as-is.
        let effective_tier = self.effective_tier(now);

        // Off tier returns None; all other tiers return (interval, padding_bytes)
        // as a structurally paired tuple — impossible to get one without the other.
        let Some((interval, message_size)) = effective_tier.traffic_params() else {
            return CoverAction::Skip;
        };

        if let Some(last) = self.last_tick
            && now < last + interval
        {
            return CoverAction::Skip;
        }

        // Advance last_tick by the interval (not `now`) to prevent cumulative
        // drift when the caller is late. If multiple intervals have been
        // missed, snap forward to the most recent overdue boundary rather
        // than anchoring to `now`. This preserves the constant-rate invariant
        // required by §9.10.6 item 1.
        self.last_tick = Some(self.last_tick.map_or(now, |last| {
            let mut t = last + interval;
            // Catch up through any missed intervals.
            while t + interval <= now {
                t += interval;
            }
            t
        }));

        let payload = Self::build_dummy_payload(message_size);

        // Track bytes sent for budget enforcement.
        if self.config.bandwidth_budget_bytes_per_min.is_some() {
            self.bytes_sent_this_period += payload.len() as u64;
        }

        CoverAction::SendDummy(payload)
    }

    /// Returns the effective cover traffic tier after applying bandwidth
    /// budget degradation.
    ///
    /// When `bandwidth_budget_bytes_per_min` is `Some(budget)` and the
    /// bytes sent in the current period have reached or exceeded the budget,
    /// the tier degrades: `Full` -> `Reduced` -> `Off`. If the degraded
    /// tier also exceeds the budget, it degrades further.
    ///
    /// Resets the budget counter when a new 1-minute period begins.
    fn effective_tier(&mut self, now: Instant) -> CoverTrafficTier {
        let Some(budget) = self.config.bandwidth_budget_bytes_per_min else {
            return self.config.tier;
        };

        // Reset counter when a new minute begins.
        let one_minute = Duration::from_secs(60);
        match self.period_start {
            Some(start) if now >= start + one_minute => {
                self.bytes_sent_this_period = 0;
                self.period_start = Some(now);
                // Reset last_tick so the next call produces a dummy immediately
                // rather than waiting for the remaining interval from the
                // previous (now-degraded) tier. The snap-forward logic in
                // next_action() prevents burst-sending of accumulated missed
                // intervals.
                self.last_tick = None;
            }
            None => {
                self.period_start = Some(now);
            }
            _ => {}
        }

        if self.bytes_sent_this_period < budget {
            return self.config.tier;
        }

        // Budget exceeded — degrade.
        match self.config.tier {
            CoverTrafficTier::Full => CoverTrafficTier::Reduced,
            CoverTrafficTier::Reduced | CoverTrafficTier::Custom { .. } | CoverTrafficTier::Off => {
                CoverTrafficTier::Off
            }
        }
    }

    /// Builds a dummy payload: a single `DUMMY_FLAG` byte padded to the
    /// nearest power-of-2 bucket size with random bytes. The `size` hint
    /// determines the minimum payload size before bucket padding.
    #[must_use]
    fn build_dummy_payload(size: usize) -> Vec<u8> {
        let mut base = vec![DUMMY_FLAG];
        // Extend with random bytes to the requested size
        if size > 1 {
            let start = base.len();
            base.resize(size, 0);
            rand::thread_rng().fill_bytes(&mut base[start..]);
        }
        pad_to_bucket(&base)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::profile::TransportProfile;

    #[test]
    fn default_config_matches_spec_full_tier() {
        let config = CoverTrafficConfig::default();
        assert_eq!(config.tier, CoverTrafficTier::Full);
        assert_eq!(config.tier.interval(), Some(Duration::from_secs(30)));
        assert_eq!(config.tier.padding_bytes(), Some(1024));
    }

    #[test]
    fn from_profile_server_produces_full_tier() {
        let config = CoverTrafficConfig::from_profile(TransportProfile::Server);
        assert_eq!(config.tier, CoverTrafficTier::Full);
    }

    #[test]
    fn from_profile_desktop_produces_full_tier() {
        let config = CoverTrafficConfig::from_profile(TransportProfile::Desktop);
        assert_eq!(config.tier, CoverTrafficTier::Full);
    }

    #[test]
    fn from_profile_mobile_produces_reduced_tier() {
        let config = CoverTrafficConfig::from_profile(TransportProfile::Mobile);
        assert_eq!(config.tier, CoverTrafficTier::Reduced);
    }

    #[test]
    fn from_profile_constrained_produces_off_tier() {
        let config = CoverTrafficConfig::from_profile(TransportProfile::Constrained);
        assert_eq!(config.tier, CoverTrafficTier::Off);
    }

    #[test]
    fn full_tier_produces_dummy_at_1024_bytes() {
        let config = CoverTrafficConfig {
            tier: CoverTrafficTier::Full,
            ..Default::default()
        };
        let mut ctg = CoverTrafficGenerator::new(config);
        let now = Instant::now();
        match ctg.next_action(now) {
            CoverAction::SendDummy(payload) => {
                assert_eq!(payload.len(), 1024);
                assert_eq!(payload[0], DUMMY_FLAG);
            }
            CoverAction::Skip => panic!("expected SendDummy for Full tier"),
        }
    }

    #[test]
    fn reduced_tier_produces_dummy_at_256_bytes() {
        let config = CoverTrafficConfig {
            tier: CoverTrafficTier::Reduced,
            ..Default::default()
        };
        let mut ctg = CoverTrafficGenerator::new(config);
        let now = Instant::now();
        match ctg.next_action(now) {
            CoverAction::SendDummy(payload) => {
                assert_eq!(payload.len(), 256);
                assert_eq!(payload[0], DUMMY_FLAG);
            }
            CoverAction::Skip => panic!("expected SendDummy for Reduced tier"),
        }
    }

    #[test]
    fn full_tier_interval_is_30s() {
        let config = CoverTrafficConfig {
            tier: CoverTrafficTier::Full,
            ..Default::default()
        };
        let mut ctg = CoverTrafficGenerator::new(config);
        let now = Instant::now();

        // First action sends dummy
        assert!(matches!(ctg.next_action(now), CoverAction::SendDummy(_)));
        // Within 30s interval -> skip
        assert_eq!(
            ctg.next_action(now + Duration::from_secs(15)),
            CoverAction::Skip,
        );
        // After 30s -> sends dummy
        assert!(matches!(
            ctg.next_action(now + Duration::from_secs(31)),
            CoverAction::SendDummy(_),
        ));
    }

    #[test]
    fn reduced_tier_interval_is_120s() {
        let config = CoverTrafficConfig {
            tier: CoverTrafficTier::Reduced,
            ..Default::default()
        };
        let mut ctg = CoverTrafficGenerator::new(config);
        let now = Instant::now();

        // First action sends dummy
        assert!(matches!(ctg.next_action(now), CoverAction::SendDummy(_)));
        // Within 120s interval -> skip
        assert_eq!(
            ctg.next_action(now + Duration::from_secs(60)),
            CoverAction::Skip,
        );
        // After 120s -> sends dummy
        assert!(matches!(
            ctg.next_action(now + Duration::from_secs(121)),
            CoverAction::SendDummy(_),
        ));
    }

    #[test]
    fn off_tier_always_skips() {
        let config = CoverTrafficConfig {
            tier: CoverTrafficTier::Off,
            ..Default::default()
        };
        let mut ctg = CoverTrafficGenerator::new(config);
        let now = Instant::now();
        assert_eq!(ctg.next_action(now), CoverAction::Skip);
        assert_eq!(
            ctg.next_action(now + Duration::from_secs(60)),
            CoverAction::Skip,
        );
        assert_eq!(
            ctg.next_action(now + Duration::from_secs(600)),
            CoverAction::Skip,
        );
    }

    #[test]
    fn custom_tier_uses_specified_interval_and_padding() {
        let config = CoverTrafficConfig {
            tier: CoverTrafficTier::Custom {
                interval: Duration::from_secs(45),
                padding_bytes: 1024,
            },
            ..Default::default()
        };
        let mut ctg = CoverTrafficGenerator::new(config);
        let now = Instant::now();

        match ctg.next_action(now) {
            CoverAction::SendDummy(payload) => {
                assert_eq!(payload.len(), 1024); // 1024 is a canonical bucket boundary
                assert_eq!(payload[0], DUMMY_FLAG);
            }
            CoverAction::Skip => panic!("expected SendDummy for Custom tier"),
        }

        // Within 45s -> skip
        assert_eq!(
            ctg.next_action(now + Duration::from_secs(30)),
            CoverAction::Skip,
        );
        // After 45s -> sends dummy
        assert!(matches!(
            ctg.next_action(now + Duration::from_secs(46)),
            CoverAction::SendDummy(_),
        ));
    }

    #[test]
    fn dummy_payload_starts_with_dummy_flag() {
        let payload = CoverTrafficGenerator::build_dummy_payload(1024);
        assert_eq!(payload[0], DUMMY_FLAG);
        // 1024 is already a bucket size, so padded to 1024
        assert_eq!(payload.len(), 1024);
    }

    #[test]
    fn dummy_payload_is_bucket_padded() {
        // 256 bytes -> bucket 256, so length should be 256
        let payload = CoverTrafficGenerator::build_dummy_payload(256);
        assert_eq!(payload[0], DUMMY_FLAG);
        assert_eq!(payload.len(), 256);
    }

    #[test]
    fn dummy_payload_minimum_size_is_bucket() {
        // size=0 produces a 1-byte base (DUMMY_FLAG), padded to bucket 256
        let payload = CoverTrafficGenerator::build_dummy_payload(0);
        assert_eq!(payload.len(), 256);
        assert_eq!(payload[0], DUMMY_FLAG);
    }

    #[test]
    fn first_action_sends_dummy() {
        let config = CoverTrafficConfig::default();
        let mut ctg = CoverTrafficGenerator::new(config);
        let now = Instant::now();
        match ctg.next_action(now) {
            CoverAction::SendDummy(payload) => {
                // Full tier: message_size=1024, which is a bucket boundary
                assert_eq!(payload.len(), 1024);
                assert_eq!(payload[0], DUMMY_FLAG);
            }
            CoverAction::Skip => panic!("expected SendDummy on first action"),
        }
    }

    #[test]
    fn second_action_within_interval_skips() {
        let config = CoverTrafficConfig::default(); // Full tier, 30s interval
        let mut ctg = CoverTrafficGenerator::new(config);
        let now = Instant::now();

        assert!(matches!(ctg.next_action(now), CoverAction::SendDummy(_)));
        assert_eq!(
            ctg.next_action(now + Duration::from_secs(15)),
            CoverAction::Skip,
        );
    }

    #[test]
    fn action_after_full_interval_sends_dummy() {
        let config = CoverTrafficConfig::default(); // Full tier, 30s interval
        let mut ctg = CoverTrafficGenerator::new(config);
        let now = Instant::now();

        assert!(matches!(ctg.next_action(now), CoverAction::SendDummy(_)));
        assert!(matches!(
            ctg.next_action(now + Duration::from_secs(31)),
            CoverAction::SendDummy(_),
        ));
    }

    #[test]
    fn dummy_always_sent_regardless_of_real_traffic() {
        let config = CoverTrafficConfig::default(); // Full tier
        let mut ctg = CoverTrafficGenerator::new(config);
        let now = Instant::now();

        assert!(matches!(ctg.next_action(now), CoverAction::SendDummy(_)));

        assert!(
            matches!(
                ctg.next_action(now + Duration::from_secs(31)),
                CoverAction::SendDummy(_),
            ),
            "dummy must always be sent at tick regardless of real message activity",
        );
    }

    #[test]
    fn constant_rate_maintained_across_intervals() {
        let config = CoverTrafficConfig::default(); // Full tier, 30s
        let mut ctg = CoverTrafficGenerator::new(config);
        let now = Instant::now();

        assert!(matches!(ctg.next_action(now), CoverAction::SendDummy(_)));

        assert!(matches!(
            ctg.next_action(now + Duration::from_secs(31)),
            CoverAction::SendDummy(_),
        ));

        assert!(matches!(
            ctg.next_action(now + Duration::from_secs(62)),
            CoverAction::SendDummy(_),
        ));
    }

    #[test]
    fn interval_accessor_returns_tier_value() {
        let full = CoverTrafficGenerator::new(CoverTrafficConfig {
            tier: CoverTrafficTier::Full,
            ..Default::default()
        });
        assert_eq!(full.interval(), Some(Duration::from_secs(30)));

        let reduced = CoverTrafficGenerator::new(CoverTrafficConfig {
            tier: CoverTrafficTier::Reduced,
            ..Default::default()
        });
        assert_eq!(reduced.interval(), Some(Duration::from_secs(120)));

        let off = CoverTrafficGenerator::new(CoverTrafficConfig {
            tier: CoverTrafficTier::Off,
            ..Default::default()
        });
        assert_eq!(off.interval(), None);

        let custom = CoverTrafficGenerator::new(CoverTrafficConfig {
            tier: CoverTrafficTier::Custom {
                interval: Duration::from_secs(45),
                padding_bytes: 512,
            },
            ..Default::default()
        });
        assert_eq!(custom.interval(), Some(Duration::from_secs(45)));
    }

    #[test]
    fn is_enabled_reflects_tier() {
        let full = CoverTrafficGenerator::new(CoverTrafficConfig::default());
        assert!(full.is_enabled());

        let off = CoverTrafficGenerator::new(CoverTrafficConfig {
            tier: CoverTrafficTier::Off,
            ..Default::default()
        });
        assert!(!off.is_enabled());
    }

    #[test]
    fn real_and_dummy_flags_are_distinct() {
        assert_ne!(DUMMY_FLAG, REAL_FLAG);
    }

    #[test]
    fn multiple_consecutive_intervals_each_send_dummy() {
        let config = CoverTrafficConfig {
            tier: CoverTrafficTier::Custom {
                interval: Duration::from_secs(10),
                padding_bytes: 1024,
            },
            ..Default::default()
        };
        let mut ctg = CoverTrafficGenerator::new(config);
        let now = Instant::now();

        assert!(matches!(ctg.next_action(now), CoverAction::SendDummy(_)));
        assert!(matches!(
            ctg.next_action(now + Duration::from_secs(11)),
            CoverAction::SendDummy(_),
        ));
        assert!(matches!(
            ctg.next_action(now + Duration::from_secs(22)),
            CoverAction::SendDummy(_),
        ));
    }

    #[test]
    fn no_timing_oracle_from_real_messages() {
        let config = CoverTrafficConfig::default(); // Full tier, 30s
        let mut ctg = CoverTrafficGenerator::new(config);
        let now = Instant::now();

        assert!(matches!(ctg.next_action(now), CoverAction::SendDummy(_)));

        assert!(
            matches!(
                ctg.next_action(now + Duration::from_secs(31)),
                CoverAction::SendDummy(_),
            ),
            "real message activity must never suppress dummies (timing oracle)",
        );

        assert!(matches!(
            ctg.next_action(now + Duration::from_secs(62)),
            CoverAction::SendDummy(_),
        ));
    }

    // -- from_profile tests (SCP-251 AC6) --

    #[test]
    fn from_profile_returns_correct_tier_for_each_variant() {
        // Server -> Full
        assert_eq!(
            CoverTrafficConfig::from_profile(TransportProfile::Server).tier,
            CoverTrafficTier::Full
        );
        // Desktop -> Full
        assert_eq!(
            CoverTrafficConfig::from_profile(TransportProfile::Desktop).tier,
            CoverTrafficTier::Full
        );
        // Mobile -> Reduced
        assert_eq!(
            CoverTrafficConfig::from_profile(TransportProfile::Mobile).tier,
            CoverTrafficTier::Reduced
        );
        // Constrained -> Off
        assert_eq!(
            CoverTrafficConfig::from_profile(TransportProfile::Constrained).tier,
            CoverTrafficTier::Off
        );
    }

    // -- Timer drift regression tests (review MAJOR-1) -------------------------

    #[test]
    fn timer_does_not_drift_across_late_calls() {
        // Full tier: 30s interval. Each call arrives 100ms late.
        let config = CoverTrafficConfig {
            tier: CoverTrafficTier::Full,
            ..Default::default()
        };
        let mut ctg = CoverTrafficGenerator::new(config);
        let start = Instant::now();

        // First tick at t=0
        assert!(matches!(ctg.next_action(start), CoverAction::SendDummy(_)));

        // Second tick arrives 100ms late at t=30.1s
        assert!(matches!(
            ctg.next_action(start + Duration::from_millis(30_100)),
            CoverAction::SendDummy(_)
        ));

        // With correct anchoring, the next tick should be at t=60s (not 60.1s).
        // A call at t=59.9s should still be a Skip.
        assert!(matches!(
            ctg.next_action(start + Duration::from_millis(59_900)),
            CoverAction::Skip
        ));

        // A call at t=60.0s should fire.
        assert!(matches!(
            ctg.next_action(start + Duration::from_secs(60)),
            CoverAction::SendDummy(_)
        ));
    }

    #[test]
    fn timer_catches_up_after_missed_intervals() {
        // Full tier: 30s interval. Call is 95s late (missed 3 intervals).
        let config = CoverTrafficConfig {
            tier: CoverTrafficTier::Full,
            ..Default::default()
        };
        let mut ctg = CoverTrafficGenerator::new(config);
        let start = Instant::now();

        // First tick at t=0
        let _ = ctg.next_action(start);

        // Next call at t=95s (missed t=30, t=60, now past t=90).
        // Should fire and anchor to t=90 (the most recent overdue boundary).
        assert!(matches!(
            ctg.next_action(start + Duration::from_secs(95)),
            CoverAction::SendDummy(_)
        ));

        // Next tick should be at t=120 (90 + 30), not t=125 (95 + 30).
        assert!(matches!(
            ctg.next_action(start + Duration::from_secs(119)),
            CoverAction::Skip
        ));
        assert!(matches!(
            ctg.next_action(start + Duration::from_secs(120)),
            CoverAction::SendDummy(_)
        ));
    }

    // -- Bucket padding tests -------------------------------------------------

    #[test]
    fn pad_to_bucket_pads_small_payload_to_256() {
        let payload = vec![REAL_FLAG, 0x01, 0x02];
        let padded = pad_to_bucket(&payload);
        assert_eq!(padded.len(), 256);
        assert_eq!(&padded[..3], &[REAL_FLAG, 0x01, 0x02]);
    }

    #[test]
    fn pad_to_bucket_exact_boundary_no_growth() {
        let payload = vec![0u8; 256];
        let padded = pad_to_bucket(&payload);
        assert_eq!(padded.len(), 256);
    }

    #[test]
    fn pad_to_bucket_just_over_256_goes_to_1024() {
        let payload = vec![0u8; 257];
        let padded = pad_to_bucket(&payload);
        assert_eq!(padded.len(), 1024);
    }

    #[test]
    fn pad_to_bucket_1024_stays_1024() {
        let payload = vec![0u8; 1024];
        let padded = pad_to_bucket(&payload);
        assert_eq!(padded.len(), 1024);
    }

    #[test]
    fn pad_to_bucket_over_4096_goes_to_16384() {
        let payload = vec![0u8; 5000];
        let padded = pad_to_bucket(&payload);
        assert_eq!(padded.len(), 16384); // next canonical bucket above 4096
    }

    #[test]
    fn pad_to_bucket_preserves_original_content() {
        let payload = vec![REAL_FLAG, 0xAA, 0xBB, 0xCC];
        let padded = pad_to_bucket(&payload);
        assert_eq!(&padded[..4], &[REAL_FLAG, 0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn pad_to_bucket_empty_payload_pads_to_256() {
        let padded = pad_to_bucket(&[]);
        assert_eq!(padded.len(), 256);
    }

    #[test]
    fn bucket_size_for_returns_correct_canonical_buckets() {
        // Canonical buckets from scp_core::envelope::BUCKET_SIZES:
        // [256, 1024, 4096, 16384, 65536, 262144]
        assert_eq!(bucket_size_for(1), 256);
        assert_eq!(bucket_size_for(256), 256);
        assert_eq!(bucket_size_for(257), 1024);
        assert_eq!(bucket_size_for(512), 1024);
        assert_eq!(bucket_size_for(1024), 1024);
        assert_eq!(bucket_size_for(1025), 4096);
        assert_eq!(bucket_size_for(4096), 4096);
        assert_eq!(bucket_size_for(4097), 16384);
        assert_eq!(bucket_size_for(16384), 16384);
        assert_eq!(bucket_size_for(16385), 65536);
        assert_eq!(bucket_size_for(65536), 65536);
        assert_eq!(bucket_size_for(65537), 262_144);
        assert_eq!(bucket_size_for(262_144), 262_144);
        assert_eq!(bucket_size_for(262_145), 524_288); // next power of 2
    }

    // -- Bandwidth budget enforcement tests (§9.10.6 "Bandwidth budget") ------

    #[test]
    fn budget_degrades_full_to_reduced_when_exceeded() {
        // Full tier sends 1024-byte payloads at 30s intervals. Set budget to
        // 1024 bytes so the first dummy exhausts it. Within the same minute,
        // the effective tier degrades to Reduced (120s interval, 256B).
        //
        // Since the Reduced tier has a 120s interval, any call within 120s
        // of the last_tick will skip. This verifies the tier actually
        // degraded (Full would have sent at 31s; Reduced does not).
        let config = CoverTrafficConfig {
            tier: CoverTrafficTier::Full,
            bandwidth_budget_bytes_per_min: Some(1024),
        };
        let mut ctg = CoverTrafficGenerator::new(config);
        let now = Instant::now();

        // First action: Full tier, 1024-byte dummy. Exhausts budget.
        match ctg.next_action(now) {
            CoverAction::SendDummy(payload) => {
                assert_eq!(payload.len(), 1024, "first dummy should be Full tier size");
            }
            CoverAction::Skip => panic!("expected SendDummy on first action"),
        }

        // Budget now exhausted (1024 >= 1024). Effective tier degrades to
        // Reduced (120s interval). At t=31s, the Full tier would have sent
        // a dummy, but the degraded Reduced tier's 120s interval has not
        // elapsed, so this must skip — proving degradation occurred.
        assert_eq!(
            ctg.next_action(now + Duration::from_secs(31)),
            CoverAction::Skip,
            "degraded to Reduced tier which has 120s interval; 31s is too soon"
        );

        // Still within the same minute (t=55s). Confirm continued skip.
        assert_eq!(
            ctg.next_action(now + Duration::from_secs(55)),
            CoverAction::Skip,
            "still within Reduced interval; should continue to skip"
        );
    }

    #[test]
    fn budget_degrades_reduced_to_off_when_exceeded() {
        // Reduced tier sends 256-byte payloads. Set budget to 256 bytes so
        // the first dummy exhausts it. Within the same minute, subsequent
        // ticks should skip because Reduced degrades to Off.
        let config = CoverTrafficConfig {
            tier: CoverTrafficTier::Reduced,
            bandwidth_budget_bytes_per_min: Some(256),
        };
        let mut ctg = CoverTrafficGenerator::new(config);
        let now = Instant::now();

        // First action: Reduced tier, 256-byte dummy. Exhausts budget.
        match ctg.next_action(now) {
            CoverAction::SendDummy(payload) => {
                assert_eq!(payload.len(), 256);
            }
            CoverAction::Skip => panic!("expected SendDummy on first action"),
        }

        // Budget exhausted. Reduced degrades to Off -> all subsequent actions
        // within this minute skip.
        assert_eq!(
            ctg.next_action(now + Duration::from_secs(30)),
            CoverAction::Skip,
            "after Reduced budget exceeded, tier should degrade to Off (skip)"
        );
        assert_eq!(
            ctg.next_action(now + Duration::from_secs(55)),
            CoverAction::Skip,
            "Off tier should keep skipping within same period"
        );
    }

    #[test]
    fn budget_resets_each_minute() {
        // Full tier with a budget that allows exactly one 1024-byte dummy per
        // minute. After the minute rolls over, the counter resets and a new
        // dummy can be sent.
        let config = CoverTrafficConfig {
            tier: CoverTrafficTier::Full,
            bandwidth_budget_bytes_per_min: Some(1024),
        };
        let mut ctg = CoverTrafficGenerator::new(config);
        let now = Instant::now();

        // First minute: one Full dummy, then degraded.
        assert!(matches!(ctg.next_action(now), CoverAction::SendDummy(_)));

        // Within same minute, budget exceeded, degraded to Reduced.
        // At 31s, Reduced interval (120s) not yet elapsed from the
        // degradation point, so this should skip.
        let within_minute = now + Duration::from_secs(31);
        // The effective tier is Reduced (120s interval). Since the last_tick
        // was reset and we're only 31s in, this skips.
        assert_eq!(ctg.next_action(within_minute), CoverAction::Skip);

        // New minute: budget resets. Full tier restored.
        let new_minute = now + Duration::from_secs(61);
        match ctg.next_action(new_minute) {
            CoverAction::SendDummy(payload) => {
                assert_eq!(
                    payload.len(),
                    1024,
                    "after minute reset, Full tier should be restored"
                );
            }
            CoverAction::Skip => panic!("expected SendDummy after budget reset"),
        }
    }

    #[test]
    fn no_budget_has_no_effect() {
        // Default config: no bandwidth budget. Behavior unchanged.
        let config = CoverTrafficConfig {
            tier: CoverTrafficTier::Full,
            bandwidth_budget_bytes_per_min: None,
        };
        let mut ctg = CoverTrafficGenerator::new(config);
        let now = Instant::now();

        // Multiple dummies sent without any degradation.
        assert!(matches!(ctg.next_action(now), CoverAction::SendDummy(_)));
        match ctg.next_action(now + Duration::from_secs(31)) {
            CoverAction::SendDummy(payload) => {
                assert_eq!(payload.len(), 1024, "no budget means Full tier always used");
            }
            CoverAction::Skip => panic!("expected SendDummy without budget"),
        }
        match ctg.next_action(now + Duration::from_secs(62)) {
            CoverAction::SendDummy(payload) => {
                assert_eq!(payload.len(), 1024, "no budget means Full tier always used");
            }
            CoverAction::Skip => panic!("expected SendDummy without budget"),
        }
    }
}
