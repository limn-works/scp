//! Clock abstraction for deterministic time control in tests.
//!
//! Provides a [`Clock`] trait with two implementations:
//!
//! - [`SystemClock`] delegates to [`scp_primitives::time`] for production use.
//! - [`SimulatedClock`] offers explicit time control: advance by delta, set
//!   absolute time, and fire registered timers in chronological order.
//!
//! Timer callbacks registered via [`Clock::register_timer`] fire when the
//! simulated clock advances past their scheduled instant. Callbacks registered
//! *during* an advance fire in the same pass if their time is at or before the
//! target.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// TimerHandle
// ---------------------------------------------------------------------------

/// Opaque handle returned by [`Clock::register_timer`].
///
/// Handles are unique across all clocks within a process (global atomic
/// counter).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TimerHandle(u64);

/// Global counter for generating unique [`TimerHandle`] values.
static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);

impl TimerHandle {
    /// Allocate the next unique handle.
    fn next() -> Self {
        Self(NEXT_HANDLE.fetch_add(1, Ordering::Relaxed))
    }
}

// ---------------------------------------------------------------------------
// TimerEntry type alias
// ---------------------------------------------------------------------------

/// A pending timer: handle + callback.
type TimerEntry = (TimerHandle, Box<dyn FnOnce() + Send>);

/// The timer storage map: fire-time (millis) -> list of entries.
type TimerMap = BTreeMap<u64, Vec<TimerEntry>>;

// ---------------------------------------------------------------------------
// Clock trait
// ---------------------------------------------------------------------------

/// Trait for obtaining the current time and scheduling timer callbacks.
///
/// Implementations must be thread-safe. Production code uses [`SystemClock`];
/// tests use [`SimulatedClock`] for deterministic control.
pub trait Clock: Send + Sync + 'static {
    /// Current time in seconds since the Unix epoch.
    fn now_secs(&self) -> u64;

    /// Current time in milliseconds since the Unix epoch.
    fn now_millis(&self) -> u64;

    /// Register a one-shot timer that fires `callback` at `at_millis`.
    ///
    /// Returns a handle that can be passed to [`Clock::cancel_timer`].
    fn register_timer(&self, at_millis: u64, callback: Box<dyn FnOnce() + Send>) -> TimerHandle;

    /// Cancel a previously registered timer.
    ///
    /// Returns `true` if the timer was found and cancelled, `false` if it had
    /// already fired or was not found.
    fn cancel_timer(&self, handle: TimerHandle) -> bool;
}

// ---------------------------------------------------------------------------
// SystemClock
// ---------------------------------------------------------------------------

/// Production clock backed by [`scp_primitives::time`].
///
/// Timer registration returns a valid handle but callbacks never fire --
/// production code uses its own real timer infrastructure.
pub struct SystemClock;

impl Clock for SystemClock {
    #[allow(clippy::expect_used)]
    fn now_secs(&self) -> u64 {
        // The Clock trait returns u64 (not Result), so we cannot propagate the
        // error. A system clock before the Unix epoch is an unrecoverable
        // environment failure — panicking is the correct behaviour here, as
        // silently returning 0 would bypass UCAN expiry and nonce freshness
        // checks.
        scp_primitives::time::now_secs().expect("system clock is unavailable or before Unix epoch")
    }

    #[allow(clippy::expect_used)]
    fn now_millis(&self) -> u64 {
        // Same rationale as now_secs — returning 0 would bypass security checks.
        scp_primitives::time::now_millis()
            .expect("system clock is unavailable or before Unix epoch")
    }

    fn register_timer(&self, _at_millis: u64, _callback: Box<dyn FnOnce() + Send>) -> TimerHandle {
        // No-op: production code uses real timer infrastructure.
        TimerHandle::next()
    }

    fn cancel_timer(&self, _handle: TimerHandle) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// SimulatedClock
// ---------------------------------------------------------------------------

/// A fully-deterministic clock for testing.
///
/// Time only advances when explicitly instructed via [`advance`],
/// [`advance_millis`], or [`advance_to`]. Registered timers fire in
/// chronological order during advances.
///
/// [`advance`]: SimulatedClock::advance
/// [`advance_millis`]: SimulatedClock::advance_millis
/// [`advance_to`]: SimulatedClock::advance_to
pub struct SimulatedClock {
    /// Current time in milliseconds.
    current_millis: AtomicU64,
    /// Pending timers keyed by fire-time (millis).
    ///
    /// The `Mutex` is only held briefly during registration, cancellation, or
    /// timer drain -- never across user callbacks.
    timers: Mutex<TimerMap>,
}

impl SimulatedClock {
    /// Create a new simulated clock starting at `start_secs` (converted to
    /// milliseconds internally).
    #[must_use]
    pub fn new(start_secs: u64) -> Self {
        Self {
            current_millis: AtomicU64::new(start_secs.saturating_mul(1000)),
            timers: Mutex::new(BTreeMap::new()),
        }
    }

    /// Advance time by `delta_secs` seconds, firing due timers in
    /// chronological order.
    pub fn advance(&self, delta_secs: u64) {
        self.advance_millis(delta_secs.saturating_mul(1000));
    }

    /// Advance time by `delta` milliseconds, firing due timers in
    /// chronological order.
    pub fn advance_millis(&self, delta: u64) {
        let target = self
            .current_millis
            .load(Ordering::Acquire)
            .saturating_add(delta);
        self.advance_to(target);
    }

    /// Advance to an absolute `target_millis` (must be >= current time).
    ///
    /// Fires all pending timers whose scheduled time is <= `target_millis` in
    /// chronological order. `current_millis` is updated progressively before
    /// each batch so that `now_millis()` returns the correct time during
    /// callback execution. Callbacks registered by other callbacks during this
    /// advance also fire if their time <= `target_millis`.
    pub fn advance_to(&self, target_millis: u64) {
        let current = self.current_millis.load(Ordering::Acquire);
        if target_millis < current {
            return;
        }

        // Drain and fire in a loop so that timers registered by callbacks also
        // get a chance to fire within this advance window.
        loop {
            let batch = self.drain_due_timers_with_times(target_millis);
            if batch.is_empty() {
                break;
            }
            for (fire_time, callback) in batch {
                // Update current_millis before firing so now_millis() returns
                // the correct time during callback execution.
                self.current_millis.fetch_max(fire_time, Ordering::AcqRel);
                callback();
            }
        }

        self.current_millis.store(target_millis, Ordering::Release);
    }

    /// Return the number of pending (unfired) timers.
    pub fn pending_timers(&self) -> usize {
        let guard = self.lock_timers();
        guard.values().map(Vec::len).sum()
    }

    /// Set the clock to `millis` without firing any timers.
    ///
    /// Useful for initial setup before the test scenario begins.
    pub fn set(&self, millis: u64) {
        self.current_millis.store(millis, Ordering::Release);
    }

    // -- internal helpers ---------------------------------------------------

    /// Lock the timer map, converting a poisoned mutex into an empty map
    /// (tests may panic inside callbacks).
    fn lock_timers(&self) -> std::sync::MutexGuard<'_, TimerMap> {
        match self.timers.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Remove and return all callbacks (with their fire times) whose fire-time
    /// is <= `up_to_millis`, sorted chronologically.
    fn drain_due_timers_with_times(
        &self,
        up_to_millis: u64,
    ) -> Vec<(u64, Box<dyn FnOnce() + Send>)> {
        let mut guard = self.lock_timers();

        // Collect keys that are due. We split the map at up_to_millis + 1 so
        // that everything <= up_to_millis is in the left half.
        let split_point = up_to_millis.saturating_add(1);
        let mut due = guard.split_off(&split_point);
        // `due` now contains everything > up_to_millis; swap so `guard` has
        // the future timers and we iterate the due ones.
        std::mem::swap(&mut *guard, &mut due);
        drop(guard);

        let mut callbacks: Vec<(u64, Box<dyn FnOnce() + Send>)> = Vec::new();
        for (time, entries) in due {
            for (_handle, cb) in entries {
                callbacks.push((time, cb));
            }
        }
        callbacks
    }
}

impl Clock for SimulatedClock {
    fn now_secs(&self) -> u64 {
        self.current_millis.load(Ordering::Acquire) / 1000
    }

    fn now_millis(&self) -> u64 {
        self.current_millis.load(Ordering::Acquire)
    }

    fn register_timer(&self, at_millis: u64, callback: Box<dyn FnOnce() + Send>) -> TimerHandle {
        let handle = TimerHandle::next();
        let mut guard = self.lock_timers();
        guard.entry(at_millis).or_default().push((handle, callback));
        handle
    }

    #[allow(clippy::significant_drop_tightening)]
    fn cancel_timer(&self, handle: TimerHandle) -> bool {
        let mut guard = self.lock_timers();
        for entries in guard.values_mut() {
            if let Some(pos) = entries.iter().position(|(h, _)| *h == handle) {
                let (_handle, _callback) = entries.swap_remove(pos);
                return true;
            }
        }
        false
    }
}

// ---------------------------------------------------------------------------
// scp_primitives::Clock compatibility
// ---------------------------------------------------------------------------

/// `SimulatedClock` implements `scp_primitives::Clock` so it can be used
/// wherever protocol code expects `&dyn scp_primitives::Clock`.
impl scp_primitives::Clock for SimulatedClock {
    fn now_secs(&self) -> u64 {
        Clock::now_secs(self)
    }

    fn now_millis(&self) -> u64 {
        Clock::now_millis(self)
    }
}

/// `SystemClock` implements `scp_primitives::Clock` for completeness.
impl scp_primitives::Clock for SystemClock {
    fn now_secs(&self) -> u64 {
        Clock::now_secs(self)
    }

    fn now_millis(&self) -> u64 {
        Clock::now_millis(self)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn system_clock_returns_reasonable_values() {
        let clock = SystemClock;
        let secs = clock.now_secs();
        // After 2020-01-01
        assert!(secs > 1_577_836_800);
        let millis = clock.now_millis();
        assert!(millis > 1_577_836_800_000);
    }

    #[test]
    fn simulated_clock_starts_at_given_time() {
        let clock = SimulatedClock::new(100);
        assert_eq!(clock.now_secs(), 100);
        assert_eq!(clock.now_millis(), 100_000);
    }

    #[test]
    fn advance_by_seconds() {
        let clock = SimulatedClock::new(0);
        clock.advance(5);
        assert_eq!(clock.now_secs(), 5);
        assert_eq!(clock.now_millis(), 5000);
    }

    #[test]
    fn advance_by_millis() {
        let clock = SimulatedClock::new(0);
        clock.advance_millis(1500);
        assert_eq!(clock.now_millis(), 1500);
        assert_eq!(clock.now_secs(), 1);
    }

    #[test]
    fn advance_to_absolute() {
        let clock = SimulatedClock::new(10);
        clock.advance_to(20_000);
        assert_eq!(clock.now_millis(), 20_000);
    }

    #[test]
    fn advance_to_past_is_noop() {
        let clock = SimulatedClock::new(10);
        clock.advance_to(5000);
        // Should remain at 10_000 (10 * 1000).
        assert_eq!(clock.now_millis(), 10_000);
    }

    #[test]
    fn set_does_not_fire_timers() {
        let fired = Arc::new(AtomicU64::new(0));
        let clock = SimulatedClock::new(0);

        let f = Arc::clone(&fired);
        clock.register_timer(
            500,
            Box::new(move || {
                f.fetch_add(1, Ordering::Relaxed);
            }),
        );

        clock.set(1000);
        assert_eq!(fired.load(Ordering::Relaxed), 0);
        assert_eq!(clock.now_millis(), 1000);
    }

    #[test]
    fn timers_fire_on_advance() {
        let fired = Arc::new(AtomicU64::new(0));
        let clock = SimulatedClock::new(0);

        let f = Arc::clone(&fired);
        clock.register_timer(
            500,
            Box::new(move || {
                f.fetch_add(1, Ordering::Relaxed);
            }),
        );

        assert_eq!(clock.pending_timers(), 1);
        clock.advance_millis(600);
        assert_eq!(fired.load(Ordering::Relaxed), 1);
        assert_eq!(clock.pending_timers(), 0);
    }

    #[test]
    fn timers_fire_in_chronological_order() {
        let order = Arc::new(Mutex::new(Vec::<u64>::new()));
        let clock = SimulatedClock::new(0);

        for t in [300, 100, 200] {
            let o = Arc::clone(&order);
            clock.register_timer(
                t,
                Box::new(move || match o.lock() {
                    Ok(mut v) => v.push(t),
                    Err(p) => p.into_inner().push(t),
                }),
            );
        }

        clock.advance_millis(400);
        let result = match order.lock() {
            Ok(v) => v.clone(),
            Err(p) => p.into_inner().clone(),
        };
        assert_eq!(result, vec![100, 200, 300]);
    }

    #[test]
    fn cancel_timer_removes_pending() {
        let fired = Arc::new(AtomicU64::new(0));
        let clock = SimulatedClock::new(0);

        let f = Arc::clone(&fired);
        let handle = clock.register_timer(
            500,
            Box::new(move || {
                f.fetch_add(1, Ordering::Relaxed);
            }),
        );

        assert!(clock.cancel_timer(handle));
        clock.advance_millis(1000);
        assert_eq!(fired.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn cancel_nonexistent_returns_false() {
        let clock = SimulatedClock::new(0);
        assert!(!clock.cancel_timer(TimerHandle(999_999_999)));
    }

    #[test]
    fn timers_registered_during_advance_fire_if_due() {
        let clock = Arc::new(SimulatedClock::new(0));
        let nested_fired = Arc::new(AtomicU64::new(0));

        let c = Arc::clone(&clock);
        let nf = Arc::clone(&nested_fired);
        clock.register_timer(
            100,
            Box::new(move || {
                // Register a new timer at 200 while advancing to 500.
                c.register_timer(
                    200,
                    Box::new(move || {
                        nf.fetch_add(1, Ordering::Relaxed);
                    }),
                );
            }),
        );

        clock.advance_millis(500);
        assert_eq!(nested_fired.load(Ordering::Relaxed), 1);
    }
}
