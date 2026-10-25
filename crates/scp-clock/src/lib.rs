#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Clock utilities with proper error handling.
//!
//! The public API is the [`Clock`] trait with two implementations:
//! - [`SystemClock`] — production clock backed by [`SystemTime`].
//! - [`TestClock`] — deterministic clock with manual time control.
//!
//! The [`MonotonicClock`] trait measures elapsed time that a step of the
//! wall clock does not move: [`SystemMonotonicClock`] in production, and
//! [`TestClock`] in tests.
//!
//! The free functions `now_secs()` / `now_millis()` and `ClockError` are
//! private implementation details of `SystemClock`. All production code
//! should use `&dyn Clock` or `SystemClock` directly.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// ClockError
// ---------------------------------------------------------------------------

/// The system clock is unavailable or before the Unix epoch.
///
/// This is a hard failure — falling back to epoch 0 would bypass security
/// checks (UCAN expiry, nonce freshness, checkpoint timestamps, etc.).
///
/// The error message is intentionally generic to avoid exposing raw system
/// error details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClockError;

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
fn now_secs() -> Result<u64, ClockError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| ClockError)
}

/// Returns the current Unix timestamp in milliseconds.
///
/// Uses `as_secs() * 1000 + subsec_millis` to avoid `u128` → `u64`
/// truncation (safe until year 584 million).
///
/// # Errors
///
/// Returns [`ClockError`] if the system clock is before the Unix epoch.
fn now_millis() -> Result<u64, ClockError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| {
            d.as_secs()
                .saturating_mul(1000)
                .saturating_add(u64::from(d.subsec_millis()))
        })
        .map_err(|_| ClockError)
}

// ---------------------------------------------------------------------------
// Clock trait
// ---------------------------------------------------------------------------

/// Trait for obtaining the current time. Implementations must be thread-safe.
///
/// A system clock before the Unix epoch is an
/// unrecoverable environment failure; implementations should panic rather
/// than silently return 0 (which would bypass UCAN expiry and nonce
/// freshness checks).
pub trait Clock: Send + Sync {
    /// Current time in seconds since the Unix epoch.
    fn now_secs(&self) -> u64;

    /// Current time in milliseconds since the Unix epoch.
    fn now_millis(&self) -> u64;
}

/// Production clock backed by [`SystemTime`].
pub struct SystemClock;

impl Clock for SystemClock {
    #[allow(clippy::expect_used)]
    fn now_secs(&self) -> u64 {
        now_secs().expect("system clock is unavailable or before Unix epoch")
    }

    #[allow(clippy::expect_used)]
    fn now_millis(&self) -> u64 {
        now_millis().expect("system clock is unavailable or before Unix epoch")
    }
}

/// Elapsed time that never goes back and that a step of the wall clock
/// (an NTP correction, a user setting the date) does not move.
/// Implementations must be thread-safe.
pub trait MonotonicClock: Send + Sync {
    /// Milliseconds since a fixed origin of this clock. Only the difference
    /// of two readings of one clock means anything.
    fn monotonic_millis(&self) -> u64;
}

/// Production monotonic clock backed by [`Instant`].
///
/// Its origin is the moment of construction. [`Instant`] is unavailable on
/// `wasm32-unknown-unknown`, as [`SystemTime`] is, so the browser client
/// brings its own implementation.
pub struct SystemMonotonicClock {
    origin: Instant,
}

impl SystemMonotonicClock {
    /// A clock whose origin is now.
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemMonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

impl MonotonicClock for SystemMonotonicClock {
    fn monotonic_millis(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

/// Test clock with manual time control.
///
/// Time is stored internally in milliseconds. The [`advance`](TestClock::advance)
/// and [`set`](TestClock::set) methods operate in seconds for convenience;
/// use [`advance_millis`](TestClock::advance_millis) when sub-second precision
/// is needed.
///
/// A `TestClock` is also a [`MonotonicClock`]: [`advance`](TestClock::advance)
/// and [`advance_millis`](TestClock::advance_millis) are elapsed time and move
/// both readings, while [`set`](TestClock::set) is a step of the wall clock
/// and leaves the monotonic reading where it is.
pub struct TestClock {
    current_millis: AtomicU64,
    monotonic_millis: AtomicU64,
}

impl TestClock {
    /// Create a new test clock starting at the given seconds.
    #[must_use]
    pub const fn new(start_secs: u64) -> Self {
        Self {
            current_millis: AtomicU64::new(start_secs.saturating_mul(1000)),
            monotonic_millis: AtomicU64::new(0),
        }
    }

    /// Advance time by the given number of seconds: the wall clock and the
    /// monotonic clock both move.
    pub fn advance(&self, secs: u64) {
        self.advance_millis(secs.saturating_mul(1000));
    }

    /// Advance time by the given number of milliseconds: the wall clock and
    /// the monotonic clock both move.
    pub fn advance_millis(&self, ms: u64) {
        self.current_millis.fetch_add(ms, Ordering::Release);
        self.monotonic_millis.fetch_add(ms, Ordering::Release);
    }

    /// Step the wall clock to a specific timestamp in seconds. The monotonic
    /// reading does not move.
    pub fn set(&self, timestamp_secs: u64) {
        self.current_millis
            .store(timestamp_secs.saturating_mul(1000), Ordering::Release);
    }
}

impl Clock for TestClock {
    fn now_secs(&self) -> u64 {
        self.current_millis.load(Ordering::Acquire) / 1000
    }

    fn now_millis(&self) -> u64 {
        self.current_millis.load(Ordering::Acquire)
    }
}

impl MonotonicClock for TestClock {
    fn monotonic_millis(&self) -> u64 {
        self.monotonic_millis.load(Ordering::Acquire)
    }
}

/// Blanket implementation so `Arc<T: Clock>` is itself a `Clock`.
///
/// This allows clocks to be shared between production code and test code
/// that needs to advance time.
impl<T: Clock + ?Sized> Clock for Arc<T> {
    fn now_secs(&self) -> u64 {
        (**self).now_secs()
    }

    fn now_millis(&self) -> u64 {
        (**self).now_millis()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn now_secs_returns_ok_on_normal_system() {
        let result = now_secs();
        assert!(
            result.is_ok(),
            "now_secs() should succeed on a normal system"
        );
        // Sanity check: timestamp should be after 2020-01-01.
        let secs = result.unwrap();
        assert!(secs > 1_577_836_800, "timestamp should be after 2020");
    }

    #[test]
    fn now_millis_returns_ok_on_normal_system() {
        let result = now_millis();
        assert!(
            result.is_ok(),
            "now_millis() should succeed on a normal system"
        );
        let ms = result.unwrap();
        // Should be roughly 1000x the seconds value.
        assert!(ms > 1_577_836_800_000, "millis should be after 2020");
    }

    #[test]
    fn clock_error_display_is_generic() {
        let err = ClockError;
        assert_eq!(
            err.to_string(),
            "system clock is unavailable or before Unix epoch"
        );
        // Verify no raw system error details are exposed.
        assert!(!err.to_string().contains("SystemTimeError"));
    }

    #[test]
    fn now_millis_is_roughly_1000x_now_secs() {
        let secs = now_secs().unwrap();
        let ms = now_millis().unwrap();
        // Should be within 2 seconds of each other.
        let diff = ms.saturating_sub(secs * 1000);
        assert!(diff < 2000, "millis and secs should agree within 2s");
    }

    // -----------------------------------------------------------------------
    // Clock trait tests
    // -----------------------------------------------------------------------

    #[test]
    fn system_clock_returns_reasonable_values() {
        let clock = SystemClock;
        let secs = clock.now_secs();
        assert!(secs > 1_577_836_800, "timestamp should be after 2020");
        let ms = clock.now_millis();
        assert!(ms > 1_577_836_800_000, "millis should be after 2020");
    }

    #[test]
    fn test_clock_starts_at_given_time() {
        let clock = TestClock::new(100);
        assert_eq!(clock.now_secs(), 100);
        assert_eq!(clock.now_millis(), 100_000);
    }

    #[test]
    fn test_clock_advance_by_seconds() {
        let clock = TestClock::new(0);
        clock.advance(5);
        assert_eq!(clock.now_secs(), 5);
        assert_eq!(clock.now_millis(), 5000);
    }

    #[test]
    fn test_clock_advance_by_millis() {
        let clock = TestClock::new(0);
        clock.advance_millis(1500);
        assert_eq!(clock.now_millis(), 1500);
        assert_eq!(clock.now_secs(), 1);
    }

    #[test]
    fn test_clock_set() {
        let clock = TestClock::new(10);
        clock.set(20);
        assert_eq!(clock.now_secs(), 20);
        assert_eq!(clock.now_millis(), 20_000);
    }

    #[test]
    fn test_clock_monotonic_moves_on_advance_not_on_set() {
        let clock = TestClock::new(10);
        assert_eq!(clock.monotonic_millis(), 0);
        clock.advance(2);
        clock.advance_millis(500);
        assert_eq!(clock.monotonic_millis(), 2_500);
        clock.set(1_000);
        assert_eq!(clock.now_secs(), 1_000);
        assert_eq!(
            clock.monotonic_millis(),
            2_500,
            "a wall step is not elapsed time"
        );
    }

    #[test]
    fn system_monotonic_clock_never_goes_back() {
        let clock = SystemMonotonicClock::new();
        let first = clock.monotonic_millis();
        let second = clock.monotonic_millis();
        assert!(second >= first);
    }

    #[test]
    fn arc_clock_delegates_to_inner() {
        let clock = Arc::new(TestClock::new(42));
        assert_eq!(clock.now_secs(), 42);
        clock.advance(1);
        assert_eq!(clock.now_secs(), 43);
    }
}
