//! The one way FFI code turns a caller's budget into a runtime deadline.
//!
//! `tokio::time::Instant::now() + budget` panics when `budget` is too large
//! to add, and every bridge budget comes from a host caller (a
//! `Duration::MAX`, a JavaScript `BigInt`, a Kotlin `Long`). Every
//! `Instant::now() + …` under `crates/scp-ffi/` goes through
//! [`deadline_after`] instead.

use std::time::Duration;

/// How far ahead [`deadline_after`] places a deadline whose budget does not
/// fit the runtime clock: about thirty years, the horizon tokio itself uses
/// for a timer that never fires.
const FAR_FUTURE: Duration = Duration::from_hours(24 * 365 * 30);

/// Returns the runtime-clock instant `budget` from now.
///
/// A `budget` that overflows the clock yields a deadline [`FAR_FUTURE`]
/// ahead, which a caller reads as "no deadline", never a panic and never a
/// deadline already passed. If even that overflows, the horizon halves until
/// it fits.
#[must_use]
pub fn deadline_after(budget: Duration) -> tokio::time::Instant {
    let now = tokio::time::Instant::now();
    if let Some(deadline) = now.checked_add(budget) {
        return deadline;
    }
    let mut horizon = FAR_FUTURE;
    loop {
        if let Some(deadline) = now.checked_add(horizon) {
            return deadline;
        }
        // `now + Duration::ZERO` always fits, so the loop ends.
        horizon /= 2;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn a_budget_that_fits_lands_exactly_that_far_ahead() {
        let before = tokio::time::Instant::now();
        let deadline = deadline_after(Duration::from_secs(5));
        assert_eq!(deadline.duration_since(before), Duration::from_secs(5));
    }

    #[tokio::test(start_paused = true)]
    async fn a_maximal_budget_lands_far_ahead_without_panicking() {
        let before = tokio::time::Instant::now();
        let deadline = deadline_after(Duration::MAX);
        assert!(
            deadline.duration_since(before) >= Duration::from_hours(24 * 365),
            "Duration::MAX must read as no deadline, not one already passed"
        );
    }
}
