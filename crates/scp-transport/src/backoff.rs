//! Shared reconnection backoff with jitter for all transport adapters.
//!
//! [`ReconnectBackoff`] implements exponential backoff with random jitter
//! (up to 25% of the delay) to prevent thundering herd when multiple
//! clients reconnect simultaneously after a relay failure.
//!
//! This module is transport-agnostic: any adapter (WebSocket, QUIC,
//! WebTransport, CoAP) can use it for profile-aware reconnection.
//!
//! # Jitter (BLACK-001 / thundering herd prevention)
//!
//! Without jitter, all clients using the same profile and attempt count
//! compute identical delays and reconnect simultaneously, overwhelming
//! the relay. Random jitter (up to 25%) decorrelates reconnection times
//! across clients. See AWS Builder's Library "Timeouts, retries, and
//! backoff with jitter."
//!
//! # Usage
//!
//! ```rust
//! use std::time::Duration;
//! use scp_transport::backoff::ReconnectBackoff;
//! use scp_transport::TransportProfile;
//!
//! let mut backoff = ReconnectBackoff::from_profile(&TransportProfile::Desktop).unwrap();
//! let delay = backoff.next_delay(); // ~1s + jitter
//! // tokio::time::sleep(delay).await;
//! // ... reconnect attempt ...
//! backoff.reset(); // on success
//! ```
//!
//! See spec section 10.13.1 and ADR-037 for profile-aware backoff ranges.

use std::time::Duration;

use rand::Rng;

use crate::profile::TransportProfile;

/// Exponential backoff for reconnection, parameterized by transport
/// profile (section 10.14.2 point 4, section 10.13.1).
///
/// On connection loss, the client uses profile-aware exponential backoff.
/// After reconnection, the client re-opens subscription streams with
/// `since = last_received_stored_at - 5s` overlap (same gap-fill strategy
/// as WebSocket, per ADR-004).
///
/// # Profiles
///
/// | Profile | Min backoff | Max backoff |
/// |---------|------------|------------|
/// | Server | 1s | 30s |
/// | Desktop | 1s | 30s |
/// | Mobile | 5s | 60s |
/// | Constrained | N/A (poll-based) | N/A |
///
/// The backoff doubles on each attempt (with jitter) until reaching the
/// maximum. A successful reconnection resets the backoff to the minimum.
#[derive(Debug, Clone)]
pub struct ReconnectBackoff {
    /// Minimum backoff duration (initial delay).
    min_backoff: Duration,

    /// Maximum backoff duration (cap).
    max_backoff: Duration,

    /// Current backoff duration.
    current: Duration,

    /// Number of consecutive failed reconnection attempts.
    attempts: u32,
}

impl ReconnectBackoff {
    /// Creates a new reconnect backoff from a transport profile.
    ///
    /// Returns `None` for `Constrained` profile (poll-based, no reconnect).
    #[must_use]
    pub fn from_profile(profile: &TransportProfile) -> Option<Self> {
        let (min_backoff, max_backoff) = profile.reconnect_backoff_range()?;
        Some(Self {
            min_backoff,
            max_backoff,
            current: min_backoff,
            attempts: 0,
        })
    }

    /// Creates a new reconnect backoff with explicit min/max bounds.
    ///
    /// # Panics
    ///
    /// Panics if `min_backoff` is zero or if `min_backoff > max_backoff`.
    #[must_use]
    pub const fn new(min_backoff: Duration, max_backoff: Duration) -> Self {
        assert!(
            min_backoff.as_nanos() > 0,
            "min_backoff must be greater than zero"
        );
        assert!(
            min_backoff.as_nanos() <= max_backoff.as_nanos(),
            "min_backoff must not exceed max_backoff"
        );
        Self {
            min_backoff,
            max_backoff,
            current: min_backoff,
            attempts: 0,
        }
    }

    /// Returns the current backoff duration (the delay before the next
    /// reconnection attempt).
    #[must_use]
    pub const fn current_delay(&self) -> Duration {
        self.current
    }

    /// Returns the minimum backoff duration.
    #[must_use]
    pub const fn min_backoff(&self) -> Duration {
        self.min_backoff
    }

    /// Returns the maximum backoff duration.
    #[must_use]
    pub const fn max_backoff(&self) -> Duration {
        self.max_backoff
    }

    /// Returns the number of consecutive failed attempts.
    #[must_use]
    pub const fn attempts(&self) -> u32 {
        self.attempts
    }

    /// Advances the backoff after a failed reconnection attempt.
    ///
    /// Doubles the current delay (exponential backoff) up to `max_backoff`.
    /// Adds random jitter (up to 25% of the delay) to prevent thundering
    /// herd when multiple clients reconnect simultaneously after a relay
    /// failure.
    ///
    /// Returns the delay to wait before the next attempt.
    pub fn next_delay(&mut self) -> Duration {
        let delay = self.current;

        // Advance: double the current backoff, capped at max.
        self.current = self.max_backoff.min(self.current.saturating_mul(2));
        self.attempts = self.attempts.saturating_add(1);

        // Add random jitter: up to 25% of the delay to prevent thundering herd.
        // Random jitter is essential -- deterministic jitter produces identical
        // delays across all clients with the same profile and attempt count,
        // defeating the purpose entirely. See AWS Builder's Library "Timeouts,
        // retries, and backoff with jitter."
        let jitter_range_ms = delay.as_millis() / 4;
        if jitter_range_ms > 0 {
            let jitter_ms = u64::try_from(rand::thread_rng().gen_range(0..=jitter_range_ms))
                .unwrap_or(u64::MAX);
            delay + Duration::from_millis(jitter_ms)
        } else {
            delay
        }
    }

    /// Resets the backoff after a successful reconnection.
    ///
    /// Restores the delay to `min_backoff` and resets the attempt counter.
    pub const fn reset(&mut self) {
        self.current = self.min_backoff;
        self.attempts = 0;
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
    fn from_profile_server_returns_some() {
        let backoff = ReconnectBackoff::from_profile(&TransportProfile::Server);
        assert!(backoff.is_some());
    }

    #[test]
    fn from_profile_desktop_has_correct_bounds() {
        let backoff = ReconnectBackoff::from_profile(&TransportProfile::Desktop).unwrap();
        assert_eq!(backoff.min_backoff(), Duration::from_secs(1));
        assert_eq!(backoff.max_backoff(), Duration::from_secs(30));
    }

    #[test]
    fn from_profile_mobile_has_correct_bounds() {
        let backoff = ReconnectBackoff::from_profile(&TransportProfile::Mobile).unwrap();
        assert_eq!(backoff.min_backoff(), Duration::from_secs(5));
        assert_eq!(backoff.max_backoff(), Duration::from_mins(1));
    }

    #[test]
    fn from_profile_constrained_returns_none() {
        assert!(ReconnectBackoff::from_profile(&TransportProfile::Constrained).is_none());
    }

    #[test]
    fn exponential_increase_with_jitter() {
        let mut backoff = ReconnectBackoff::new(Duration::from_secs(1), Duration::from_secs(30));

        // First delay should be ~1s (min_backoff) + jitter.
        let d1 = backoff.next_delay();
        assert!(d1 >= Duration::from_secs(1));
        assert!(d1 <= Duration::from_millis(1250)); // 1s + 25% jitter

        // Second delay should be ~2s + jitter (doubled from 1s).
        let d2 = backoff.next_delay();
        assert!(d2 >= Duration::from_secs(2));
        assert!(d2 <= Duration::from_millis(2500));

        // Third delay should be ~4s + jitter (doubled from 2s).
        let d3 = backoff.next_delay();
        assert!(d3 >= Duration::from_secs(4));
        assert!(d3 <= Duration::from_secs(5));
    }

    #[test]
    fn backoff_caps_at_max() {
        let mut backoff = ReconnectBackoff::new(Duration::from_secs(1), Duration::from_secs(4));

        let _d1 = backoff.next_delay(); // 1s
        let _d2 = backoff.next_delay(); // 2s
        let _d3 = backoff.next_delay(); // 4s (cap)
        let d4 = backoff.next_delay(); // Should still be <= 4s + jitter

        // The base delay is capped at 4s, jitter adds up to 25%.
        assert!(d4 <= Duration::from_secs(5));
    }

    #[test]
    fn reset_restores_initial_state() {
        let mut backoff = ReconnectBackoff::new(Duration::from_secs(1), Duration::from_secs(30));
        let _ = backoff.next_delay();
        let _ = backoff.next_delay();
        assert!(backoff.attempts() >= 2);

        backoff.reset();
        assert_eq!(backoff.attempts(), 0);
        assert_eq!(backoff.current_delay(), Duration::from_secs(1));
    }

    #[test]
    fn attempts_counter_increments() {
        let mut backoff = ReconnectBackoff::new(Duration::from_secs(1), Duration::from_secs(30));
        assert_eq!(backoff.attempts(), 0);
        let _ = backoff.next_delay();
        assert_eq!(backoff.attempts(), 1);
        let _ = backoff.next_delay();
        assert_eq!(backoff.attempts(), 2);
    }

    #[test]
    fn mobile_profile_backoff_range() {
        let mut backoff = ReconnectBackoff::from_profile(&TransportProfile::Mobile).unwrap();

        // First delay: 5s (min for mobile) + jitter.
        let d1 = backoff.next_delay();
        assert!(d1 >= Duration::from_secs(5));
        assert!(d1 <= Duration::from_millis(6250)); // 5s + 25%

        // Second delay: 10s + jitter.
        let d2 = backoff.next_delay();
        assert!(d2 >= Duration::from_secs(10));
        assert!(d2 <= Duration::from_millis(12500));
    }

    #[test]
    #[should_panic(expected = "min_backoff must be greater than zero")]
    fn zero_min_backoff_panics() {
        let _ = ReconnectBackoff::new(Duration::ZERO, Duration::from_secs(10));
    }

    #[test]
    #[should_panic(expected = "min_backoff must not exceed max_backoff")]
    fn min_exceeds_max_panics() {
        let _ = ReconnectBackoff::new(Duration::from_secs(10), Duration::from_secs(1));
    }
}
