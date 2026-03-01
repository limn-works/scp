//! Heartbeat monitoring and relay suppression detection.
//!
//! Spec section 9.9.2 specifies periodic heartbeat messages for detecting relay
//! suppression. This module provides:
//!
//! - [`HeartbeatConfig`] -- interval, enabled flag, and suppression threshold
//!   multiplier.
//! - [`HeartbeatMonitor`] -- tracks sent/received heartbeats and detects gaps
//!   that indicate relay suppression.
//! - [`SuppressionSuspected`] -- event raised when expected heartbeats are
//!   missing for longer than the configured threshold.
//!
//! Heartbeats are minimal MLS application messages with a sequence number but
//! no user content (spec 9.9.2). If heartbeats stop arriving from a participant
//! who was recently active, suppression is suspected.
//!
//! See spec section 9.9.2 for the full design.

use std::time::Duration;

use tokio::time::Instant;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default heartbeat interval per spec 9.9.2: 60 seconds when the context has
/// active participants.
const DEFAULT_INTERVAL: Duration = Duration::from_secs(60);

/// Default suppression threshold multiplier. Suppression is suspected when
/// expected heartbeats are missing for longer than `interval * multiplier`.
/// Per spec 9.9.2, the default is 2x the heartbeat interval.
const DEFAULT_THRESHOLD_MULTIPLIER: f64 = 2.0;

// ---------------------------------------------------------------------------
// HeartbeatConfig
// ---------------------------------------------------------------------------

/// Configuration for heartbeat monitoring.
///
/// Defaults match spec 9.9.2: enabled, 60-second interval, 2x suppression
/// threshold multiplier. Heartbeats and cover traffic are independently
/// configurable.
#[derive(Debug, Clone)]
pub struct HeartbeatConfig {
    /// Interval between heartbeat messages. Default: 60 seconds.
    pub interval: Duration,
    /// Whether heartbeat monitoring is enabled. Default: `true`.
    pub enabled: bool,
    /// Multiplier applied to the interval to determine the suppression
    /// detection threshold. Default: 2.0 (suppression suspected after
    /// 2x the interval with no heartbeat received).
    pub suppression_threshold_multiplier: f64,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self {
            interval: DEFAULT_INTERVAL,
            enabled: true,
            suppression_threshold_multiplier: DEFAULT_THRESHOLD_MULTIPLIER,
        }
    }
}

impl HeartbeatConfig {
    /// Returns the suppression threshold duration: `interval * multiplier`.
    #[must_use]
    pub fn suppression_threshold(&self) -> Duration {
        self.interval.mul_f64(self.suppression_threshold_multiplier)
    }
}

// ---------------------------------------------------------------------------
// SuppressionSuspected
// ---------------------------------------------------------------------------

/// Event raised when expected heartbeats are missing for longer than the
/// suppression threshold (spec 9.9.2).
///
/// The SDK SHOULD alert the user and attempt delivery via alternative relays.
/// The SDK MUST NOT silently discard the suspicion (spec 9.9.4).
#[derive(Debug, Clone)]
pub struct SuppressionSuspected {
    /// The relay URL where suppression was detected.
    pub relay_url: String,
    /// The last time a heartbeat was received from this relay.
    pub last_received: Instant,
    /// The time by which a heartbeat was expected.
    pub expected_by: Instant,
    /// How long the gap has lasted beyond the expected time.
    pub gap_duration: Duration,
}

// ---------------------------------------------------------------------------
// HeartbeatMonitor
// ---------------------------------------------------------------------------

/// Monitors heartbeat messages for a single relay connection to detect
/// suppression.
///
/// Tracks when heartbeats are sent and received. When the gap between the
/// last received heartbeat and the current time exceeds the configured
/// threshold (`interval * suppression_threshold_multiplier`), a
/// [`SuppressionSuspected`] event is raised.
///
/// # Usage
///
/// ```ignore
/// let config = HeartbeatConfig::default();
/// let mut monitor = HeartbeatMonitor::new(config, "wss://relay.example.com".into());
/// let now = Instant::now();
///
/// monitor.record_heartbeat_sent(now);
/// monitor.record_heartbeat_received(now);
///
/// // Later, check for suppression
/// if let Some(event) = monitor.check_suppression(now + Duration::from_secs(200)) {
///     // Handle suppression suspicion
/// }
/// ```
#[derive(Debug)]
pub struct HeartbeatMonitor {
    config: HeartbeatConfig,
    relay_url: String,
    last_sent: Option<Instant>,
    last_received: Option<Instant>,
}

impl HeartbeatMonitor {
    /// Creates a new heartbeat monitor for the given relay.
    #[must_use]
    pub const fn new(config: HeartbeatConfig, relay_url: String) -> Self {
        Self {
            config,
            relay_url,
            last_sent: None,
            last_received: None,
        }
    }

    /// Returns the configured heartbeat interval.
    #[must_use]
    pub const fn interval(&self) -> Duration {
        self.config.interval
    }

    /// Returns whether heartbeat monitoring is enabled.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Returns the relay URL this monitor tracks.
    #[must_use]
    pub fn relay_url(&self) -> &str {
        &self.relay_url
    }

    /// Records that a heartbeat was sent at the given instant.
    pub const fn record_heartbeat_sent(&mut self, now: Instant) {
        self.last_sent = Some(now);
    }

    /// Records that a heartbeat was received at the given instant.
    pub const fn record_heartbeat_received(&mut self, now: Instant) {
        self.last_received = Some(now);
    }

    /// Checks whether suppression is suspected based on the heartbeat gap.
    ///
    /// Returns [`Some(SuppressionSuspected)`] if the time since the last
    /// received heartbeat exceeds `interval * suppression_threshold_multiplier`.
    /// Returns [`None`] if monitoring is disabled, no heartbeats have been
    /// sent yet, or the gap is within the acceptable threshold.
    ///
    /// The `now` parameter enables deterministic testing without real timers.
    #[must_use]
    pub fn check_suppression(&self, now: Instant) -> Option<SuppressionSuspected> {
        if !self.config.enabled {
            return None;
        }

        self.last_sent?;

        let threshold = self.config.suppression_threshold();

        let Some(last_recv) = self.last_received else {
            let sent = self.last_sent?;
            if now.duration_since(sent) > threshold {
                return Some(SuppressionSuspected {
                    relay_url: self.relay_url.clone(),
                    last_received: sent,
                    expected_by: sent + threshold,
                    gap_duration: now.duration_since(sent + threshold),
                });
            }
            return None;
        };

        let expected_by = last_recv + threshold;

        if now > expected_by {
            Some(SuppressionSuspected {
                relay_url: self.relay_url.clone(),
                last_received: last_recv,
                expected_by,
                gap_duration: now.duration_since(expected_by),
            })
        } else {
            None
        }
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
        let config = HeartbeatConfig::default();
        assert!(config.enabled);
        assert_eq!(config.interval, Duration::from_secs(60));
        assert!((config.suppression_threshold_multiplier - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn suppression_threshold_is_interval_times_multiplier() {
        let config = HeartbeatConfig {
            interval: Duration::from_secs(60),
            suppression_threshold_multiplier: 2.0,
            ..HeartbeatConfig::default()
        };
        assert_eq!(config.suppression_threshold(), Duration::from_secs(120));
    }

    #[test]
    fn suppression_threshold_custom_multiplier() {
        let config = HeartbeatConfig {
            interval: Duration::from_secs(30),
            suppression_threshold_multiplier: 3.0,
            ..HeartbeatConfig::default()
        };
        assert_eq!(config.suppression_threshold(), Duration::from_secs(90));
    }

    #[test]
    fn disabled_monitor_never_reports_suppression() {
        let config = HeartbeatConfig {
            enabled: false,
            ..HeartbeatConfig::default()
        };
        let mut monitor = HeartbeatMonitor::new(config, "wss://relay.example.com".into());
        let now = Instant::now();

        monitor.record_heartbeat_sent(now);

        assert!(
            monitor
                .check_suppression(now + Duration::from_secs(300))
                .is_none()
        );
    }

    #[test]
    fn no_suppression_before_any_heartbeat_sent() {
        let config = HeartbeatConfig::default();
        let monitor = HeartbeatMonitor::new(config, "wss://relay.example.com".into());
        let now = Instant::now();

        assert!(
            monitor
                .check_suppression(now + Duration::from_secs(300))
                .is_none()
        );
    }

    #[test]
    fn no_suppression_when_heartbeats_received_on_time() {
        let config = HeartbeatConfig::default();
        let mut monitor = HeartbeatMonitor::new(config, "wss://relay.example.com".into());
        let now = Instant::now();

        monitor.record_heartbeat_sent(now);
        monitor.record_heartbeat_received(now);

        assert!(
            monitor
                .check_suppression(now + Duration::from_secs(60))
                .is_none()
        );
        assert!(
            monitor
                .check_suppression(now + Duration::from_secs(119))
                .is_none()
        );
    }

    #[test]
    fn suppression_detected_after_two_times_interval() {
        let config = HeartbeatConfig::default();
        let mut monitor = HeartbeatMonitor::new(config, "wss://relay.example.com".into());
        let now = Instant::now();

        monitor.record_heartbeat_sent(now);
        monitor.record_heartbeat_received(now);

        let event = monitor
            .check_suppression(now + Duration::from_secs(121))
            .expect("expected suppression event");

        assert_eq!(event.relay_url, "wss://relay.example.com");
        assert_eq!(event.last_received, now);
        assert_eq!(event.expected_by, now + Duration::from_secs(120));
        assert_eq!(event.gap_duration, Duration::from_secs(1));
    }

    #[test]
    fn suppression_clears_when_heartbeat_received() {
        let config = HeartbeatConfig::default();
        let mut monitor = HeartbeatMonitor::new(config, "wss://relay.example.com".into());
        let now = Instant::now();

        monitor.record_heartbeat_sent(now);
        monitor.record_heartbeat_received(now);

        assert!(
            monitor
                .check_suppression(now + Duration::from_secs(121))
                .is_some()
        );

        monitor.record_heartbeat_received(now + Duration::from_secs(121));

        assert!(
            monitor
                .check_suppression(now + Duration::from_secs(130))
                .is_none()
        );
    }

    #[test]
    fn suppression_detected_when_never_received() {
        let config = HeartbeatConfig::default();
        let mut monitor = HeartbeatMonitor::new(config, "wss://relay.example.com".into());
        let now = Instant::now();

        monitor.record_heartbeat_sent(now);

        let event = monitor
            .check_suppression(now + Duration::from_secs(121))
            .expect("expected suppression event");

        assert_eq!(event.relay_url, "wss://relay.example.com");
        assert_eq!(event.expected_by, now + Duration::from_secs(120));
    }

    #[test]
    fn no_suppression_within_threshold_when_never_received() {
        let config = HeartbeatConfig::default();
        let mut monitor = HeartbeatMonitor::new(config, "wss://relay.example.com".into());
        let now = Instant::now();

        monitor.record_heartbeat_sent(now);

        assert!(
            monitor
                .check_suppression(now + Duration::from_secs(119))
                .is_none()
        );
    }

    #[test]
    fn relay_url_accessor_returns_configured_value() {
        let monitor =
            HeartbeatMonitor::new(HeartbeatConfig::default(), "wss://test.relay".into());
        assert_eq!(monitor.relay_url(), "wss://test.relay");
    }

    #[test]
    fn interval_accessor_returns_configured_value() {
        let config = HeartbeatConfig {
            interval: Duration::from_secs(45),
            ..HeartbeatConfig::default()
        };
        let monitor = HeartbeatMonitor::new(config, "wss://relay".into());
        assert_eq!(monitor.interval(), Duration::from_secs(45));
    }

    #[test]
    fn is_enabled_reflects_config() {
        let enabled = HeartbeatMonitor::new(HeartbeatConfig::default(), "wss://r".into());
        assert!(enabled.is_enabled());

        let disabled = HeartbeatMonitor::new(
            HeartbeatConfig {
                enabled: false,
                ..HeartbeatConfig::default()
            },
            "wss://r".into(),
        );
        assert!(!disabled.is_enabled());
    }

    #[test]
    fn gap_duration_grows_with_time() {
        let config = HeartbeatConfig::default();
        let mut monitor = HeartbeatMonitor::new(config, "wss://relay".into());
        let now = Instant::now();

        monitor.record_heartbeat_sent(now);
        monitor.record_heartbeat_received(now);

        let event1 = monitor
            .check_suppression(now + Duration::from_secs(150))
            .expect("expected suppression");
        assert_eq!(event1.gap_duration, Duration::from_secs(30));

        let event2 = monitor
            .check_suppression(now + Duration::from_secs(180))
            .expect("expected suppression");
        assert_eq!(event2.gap_duration, Duration::from_secs(60));
    }

    #[test]
    fn custom_threshold_multiplier_changes_detection_time() {
        let config = HeartbeatConfig {
            interval: Duration::from_secs(60),
            suppression_threshold_multiplier: 3.0,
            ..HeartbeatConfig::default()
        };
        let mut monitor = HeartbeatMonitor::new(config, "wss://relay".into());
        let now = Instant::now();

        monitor.record_heartbeat_sent(now);
        monitor.record_heartbeat_received(now);

        assert!(
            monitor
                .check_suppression(now + Duration::from_secs(179))
                .is_none()
        );

        assert!(
            monitor
                .check_suppression(now + Duration::from_secs(181))
                .is_some()
        );
    }
}
