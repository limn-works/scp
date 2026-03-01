//! Cover traffic generation for metadata privacy.
//!
//! Spec section 9.10.6 mandates constant-rate cover traffic on persistent
//! connections to mask activity patterns. This module provides:
//!
//! - [`CoverTrafficConfig`] -- per-connection configuration (interval, padding
//!   size, enabled flag).
//! - [`CoverTrafficGenerator`] -- produces dummy messages on a strict timer,
//!   always emitting exactly one dummy per interval regardless of real traffic.
//! - [`CoverAction`] -- the decision output: send a dummy or skip (disabled).
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
//! See spec section 9.10.6 for the full design.

use std::time::Duration;

use rand::RngCore;
use tokio::time::Instant;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default cover traffic interval per spec 9.10.6: one padded message every
/// 30 seconds per relay connection.
const DEFAULT_INTERVAL: Duration = Duration::from_secs(30);

/// Default padding target size in bytes. Spec 9.10.6 suggests ~1KB padding
/// (~15MB/day for 5 relay connections).
const DEFAULT_MESSAGE_SIZE: usize = 1024;

/// The single-byte flag that marks a dummy message payload. Recipients
/// decrypt, check this flag, and discard dummies (spec 9.10.6 item 3).
pub const DUMMY_FLAG: u8 = 0x00;

/// The single-byte flag that marks a real message payload. Used to
/// distinguish real content from cover traffic after decryption.
pub const REAL_FLAG: u8 = 0x01;

/// Power-of-2 size buckets for payload padding. All payloads (real and dummy)
/// are padded to the nearest bucket boundary so that message sizes do not
/// distinguish real traffic from cover traffic.
const BUCKET_SIZES: [usize; 5] = [256, 512, 1024, 2048, 4096];

/// Pads a payload to the nearest power-of-2 size bucket (256, 512, 1024,
/// 2048, or 4096 bytes). Payloads larger than 4096 bytes are padded to the
/// next power of 2.
///
/// Padding bytes are filled with random data to prevent distinguishing
/// padded regions from content via entropy analysis.
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

/// Returns the bucket size for a given payload length.
#[must_use]
fn bucket_size_for(len: usize) -> usize {
    for &bucket in &BUCKET_SIZES {
        if len <= bucket {
            return bucket;
        }
    }
    // For payloads larger than the largest bucket, round up to next power of 2
    len.next_power_of_two()
}

// ---------------------------------------------------------------------------
// CoverTrafficConfig
// ---------------------------------------------------------------------------

/// Configuration for cover traffic generation on a single relay connection.
///
/// Defaults match spec 9.10.6: enabled, 30-second interval, 1KB padding.
/// Cover traffic is enabled by default and configurable per-client. Disabling
/// degrades traffic analysis resistance but has no functional impact.
#[derive(Debug, Clone)]
pub struct CoverTrafficConfig {
    /// Interval between cover traffic messages. Default: 30 seconds.
    pub interval: Duration,
    /// Whether cover traffic is enabled. Default: `true`.
    pub enabled: bool,
    /// Target size for dummy message payloads in bytes. Default: 1024.
    pub message_size: usize,
}

impl Default for CoverTrafficConfig {
    fn default() -> Self {
        Self {
            interval: DEFAULT_INTERVAL,
            enabled: true,
            message_size: DEFAULT_MESSAGE_SIZE,
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
    /// byte followed by zero-padding to `message_size`).
    SendDummy(Vec<u8>),
    /// Skip this cycle because cover traffic is disabled or the interval has
    /// not yet elapsed. This variant is never returned due to real message
    /// activity -- dummies are always sent at each tick to maintain constant
    /// rate and prevent timing oracles.
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
/// # Usage
///
/// The caller runs a timer at the configured interval and calls
/// [`next_action`](Self::next_action) each tick, passing the current
/// [`Instant`].
#[derive(Debug)]
pub struct CoverTrafficGenerator {
    config: CoverTrafficConfig,
    last_tick: Option<Instant>,
}

impl CoverTrafficGenerator {
    /// Creates a new cover traffic generator with the given configuration.
    #[must_use]
    pub const fn new(config: CoverTrafficConfig) -> Self {
        Self {
            config,
            last_tick: None,
        }
    }

    /// Returns the configured interval between cover traffic messages.
    #[must_use]
    pub const fn interval(&self) -> Duration {
        self.config.interval
    }

    /// Returns whether cover traffic is enabled.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Determines whether to send a dummy message or skip this cycle.
    ///
    /// Called at each interval tick. Returns [`CoverAction::SendDummy`] with
    /// a padded payload unconditionally when the interval has elapsed,
    /// maintaining constant-rate traffic regardless of real message activity.
    /// Returns [`CoverAction::Skip`] only if cover traffic is disabled or the
    /// interval has not yet elapsed.
    ///
    /// Real messages sent by the application are additional traffic and never
    /// suppress a dummy. This prevents timing oracles where a relay operator
    /// could observe gaps in the constant-rate stream and infer that a real
    /// message was sent during that window.
    ///
    /// The `now` parameter enables deterministic testing without real timers.
    #[must_use]
    pub fn next_action(&mut self, now: Instant) -> CoverAction {
        if !self.config.enabled {
            return CoverAction::Skip;
        }

        if let Some(last) = self.last_tick
            && now < last + self.config.interval
        {
            return CoverAction::Skip;
        }

        self.last_tick = Some(now);

        CoverAction::SendDummy(Self::build_dummy_payload(self.config.message_size))
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

    #[test]
    fn default_config_matches_spec() {
        let config = CoverTrafficConfig::default();
        assert!(config.enabled);
        assert_eq!(config.interval, Duration::from_secs(30));
        assert_eq!(config.message_size, 1024);
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
    fn disabled_generator_always_skips() {
        let config = CoverTrafficConfig {
            enabled: false,
            ..CoverTrafficConfig::default()
        };
        let mut ctg = CoverTrafficGenerator::new(config);
        let now = Instant::now();
        assert_eq!(ctg.next_action(now), CoverAction::Skip);
        assert_eq!(
            ctg.next_action(now + Duration::from_secs(60)),
            CoverAction::Skip,
        );
    }

    #[test]
    fn first_action_sends_dummy() {
        let config = CoverTrafficConfig::default();
        let mut ctg = CoverTrafficGenerator::new(config);
        let now = Instant::now();
        match ctg.next_action(now) {
            CoverAction::SendDummy(payload) => {
                // Default message_size=1024, which is a bucket boundary
                assert_eq!(payload.len(), 1024);
                assert_eq!(payload[0], DUMMY_FLAG);
            }
            CoverAction::Skip => panic!("expected SendDummy on first action"),
        }
    }

    #[test]
    fn second_action_within_interval_skips() {
        let config = CoverTrafficConfig {
            interval: Duration::from_secs(30),
            ..CoverTrafficConfig::default()
        };
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
        let config = CoverTrafficConfig {
            interval: Duration::from_secs(30),
            ..CoverTrafficConfig::default()
        };
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
        let config = CoverTrafficConfig {
            interval: Duration::from_secs(30),
            ..CoverTrafficConfig::default()
        };
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
        let config = CoverTrafficConfig {
            interval: Duration::from_secs(30),
            ..CoverTrafficConfig::default()
        };
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
    fn custom_message_size_in_dummy_payload() {
        let config = CoverTrafficConfig {
            message_size: 256,
            ..CoverTrafficConfig::default()
        };
        let mut ctg = CoverTrafficGenerator::new(config);
        let now = Instant::now();
        match ctg.next_action(now) {
            // 256 is a bucket boundary so padded size stays 256
            CoverAction::SendDummy(payload) => assert_eq!(payload.len(), 256),
            CoverAction::Skip => panic!("expected SendDummy"),
        }
    }

    #[test]
    fn interval_accessor_returns_configured_value() {
        let config = CoverTrafficConfig {
            interval: Duration::from_secs(45),
            ..CoverTrafficConfig::default()
        };
        let ctg = CoverTrafficGenerator::new(config);
        assert_eq!(ctg.interval(), Duration::from_secs(45));
    }

    #[test]
    fn is_enabled_reflects_config() {
        let enabled = CoverTrafficGenerator::new(CoverTrafficConfig::default());
        assert!(enabled.is_enabled());

        let disabled = CoverTrafficGenerator::new(CoverTrafficConfig {
            enabled: false,
            ..CoverTrafficConfig::default()
        });
        assert!(!disabled.is_enabled());
    }

    #[test]
    fn real_and_dummy_flags_are_distinct() {
        assert_ne!(DUMMY_FLAG, REAL_FLAG);
    }

    #[test]
    fn multiple_consecutive_intervals_each_send_dummy() {
        let config = CoverTrafficConfig {
            interval: Duration::from_secs(10),
            ..CoverTrafficConfig::default()
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
        let config = CoverTrafficConfig {
            interval: Duration::from_secs(30),
            ..CoverTrafficConfig::default()
        };
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
    fn pad_to_bucket_just_over_256_goes_to_512() {
        let payload = vec![0u8; 257];
        let padded = pad_to_bucket(&payload);
        assert_eq!(padded.len(), 512);
    }

    #[test]
    fn pad_to_bucket_1024_stays_1024() {
        let payload = vec![0u8; 1024];
        let padded = pad_to_bucket(&payload);
        assert_eq!(padded.len(), 1024);
    }

    #[test]
    fn pad_to_bucket_over_4096_rounds_to_power_of_2() {
        let payload = vec![0u8; 5000];
        let padded = pad_to_bucket(&payload);
        assert_eq!(padded.len(), 8192); // next power of 2 above 5000
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
    fn bucket_size_for_returns_correct_buckets() {
        assert_eq!(bucket_size_for(1), 256);
        assert_eq!(bucket_size_for(256), 256);
        assert_eq!(bucket_size_for(257), 512);
        assert_eq!(bucket_size_for(512), 512);
        assert_eq!(bucket_size_for(513), 1024);
        assert_eq!(bucket_size_for(1024), 1024);
        assert_eq!(bucket_size_for(1025), 2048);
        assert_eq!(bucket_size_for(2048), 2048);
        assert_eq!(bucket_size_for(2049), 4096);
        assert_eq!(bucket_size_for(4096), 4096);
        assert_eq!(bucket_size_for(4097), 8192);
    }
}
