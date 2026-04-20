//! Send-sequence reservation guard.
//!
//! Per spec §5.15.7 (send-sequence reservation): a sequence number is
//! consumed (becomes durable) IFF the corresponding payload has been
//! handed to the transport. Any terminal outcome prior to transmit MUST
//! release the sequence back into the pool. The RAII guard
//! [`SequenceReservation`] makes that release automatic on drop, closing
//! the discipline-enforced rollback path that previously lived as scattered
//! `rollback_sequence_number` calls in `manager/messaging.rs` (see
//! plan §"`SequenceReservation`").
//!
//! # Crash-recovery interaction
//!
//! The RAII guard handles within-lifetime panics, cancellations, and
//! early-`?` returns. Across an actor crash, the per-context snapshot is
//! the floor: the respawned actor loads a snapshot that predates the
//! in-flight reservation, so `send_tracker` starts from the persisted
//! value. RAII is belt-and-braces; the snapshot is the actual mechanism
//! protecting sequence monotonicity across crashes (plan §"Actor panic
//! recovery").
//!
//! # Match with existing behavior
//!
//! [`SendSequenceTracker::reserve_next`] increments and returns the next
//! number; [`SendSequenceTracker::rollback`] decrements iff the rolled-back
//! number is the most-recently-reserved one (i.e. only the youngest
//! reservation can be rolled back without re-using a number that is
//! already being used by an in-flight younger reservation). This mirrors
//! the existing `MembershipState::rollback_sequence_number` semantics in
//! `crates/scp-protocol/src/context/membership.rs` (saturating subtract
//! by 1) — no semantic change is introduced here.

// ---------------------------------------------------------------------------
// SendSequenceTracker
// ---------------------------------------------------------------------------

/// Minimal monotonic-counter shape the reservation guards.
///
/// This is the per-actor send-sequence counter that pairs with the RAII
/// reservation. The wiring of this counter into `PerContextState` lands in
/// a later commit; this type is created here so [`SequenceReservation`]
/// can be unit-tested against its real counterpart.
///
/// Semantics: numbers are issued in ascending order starting at 1. The
/// "next" number is one past the last successfully reserved number. A
/// rollback decrements iff the rolled-back number is the head — i.e.
/// only the youngest outstanding reservation may be rolled back. This
/// mirrors the existing per-sender semantics in
/// `MembershipState::rollback_sequence_number`.
#[derive(Debug, Default)]
pub struct SendSequenceTracker {
    /// Last number successfully issued. `0` means no number has been
    /// issued yet, so the next number issued is `1`.
    last_issued: u64,
}

impl SendSequenceTracker {
    /// Construct a fresh tracker. The first number issued will be `1`.
    #[must_use]
    pub const fn new() -> Self {
        Self { last_issued: 0 }
    }

    /// Construct a tracker with a pre-existing high-water mark. Used by
    /// snapshot restore: the next number issued will be `from + 1`. The
    /// caller is responsible for ensuring `from` matches the persisted
    /// counter — supplying a smaller value can cause sequence reuse.
    #[must_use]
    pub const fn from_persisted(from: u64) -> Self {
        Self { last_issued: from }
    }

    /// Reserve the next sequence number. Increments the high-water mark
    /// and returns the newly-issued number.
    ///
    /// Wraps `u64`; per `SCP` protocol the protocol-level u64 ceiling is
    /// far beyond any realistic per-context send rate (2^64 messages),
    /// so wrap is impossible in practice. We `saturating_add` defensively
    /// — a reservation request after saturation returns `u64::MAX`
    /// repeatedly until the actor restarts; the impossible case fails
    /// loudly rather than wrapping silently.
    pub const fn reserve_next(&mut self) -> u64 {
        self.last_issued = self.last_issued.saturating_add(1);
        self.last_issued
    }

    /// Roll back the most-recently-issued number. The argument is the
    /// number being rolled back — used as a defensive check that the
    /// caller is not trying to roll back a stale reservation.
    ///
    /// Mirrors the existing
    /// `MembershipState::rollback_sequence_number` semantics: no-op when
    /// `number != last_issued` (rollback of a non-head number would
    /// corrupt the counter). When `last_issued` is `0`, no-op (there is
    /// nothing to roll back).
    pub const fn rollback(&mut self, number: u64) {
        if self.last_issued == 0 {
            return;
        }
        if number == self.last_issued {
            self.last_issued = self.last_issued.saturating_sub(1);
        }
        // Else: a stale rollback request. Silently ignore rather than
        // corrupt the counter — caller-side this never happens because
        // `SequenceReservation::rollback` is called only via Drop on the
        // youngest outstanding reservation, by construction.
    }

    /// Return the last-issued number without mutating. Convenience for
    /// snapshot persist and tests.
    #[must_use]
    pub const fn last_issued(&self) -> u64 {
        self.last_issued
    }
}

// ---------------------------------------------------------------------------
// SequenceReservation
// ---------------------------------------------------------------------------

/// RAII guard around a reserved send-sequence number.
///
/// The guard borrows the tracker mutably for its lifetime, ensuring no
/// other reservation may be issued while this one is outstanding. On
/// drop without [`commit`](Self::commit), the guard rolls the tracker
/// back to its pre-reservation state.
///
/// Usage:
///
/// ```ignore
/// let reservation = SequenceReservation::reserve(&mut state.send_tracker);
/// let sequence = reservation.number();
/// let ciphertext = self.mls_encrypt(&msg, sequence)?;  // ?-early-return rolls back
/// self.transport.send(&ciphertext).await?;            // same
/// reservation.commit();  // only here does the sequence become permanent
/// ```
///
/// The `Drop` impl is the actual mechanism — both `?`-early-return and
/// panic unwind call destructors of in-scope locals.
pub struct SequenceReservation<'a> {
    tracker: &'a mut SendSequenceTracker,
    reserved: u64,
    committed: bool,
}

impl<'a> SequenceReservation<'a> {
    /// Reserve the next number from the tracker. Returns the reservation
    /// guard; drop without `commit` rolls the tracker back.
    pub const fn reserve(tracker: &'a mut SendSequenceTracker) -> Self {
        let reserved = tracker.reserve_next();
        Self {
            tracker,
            reserved,
            committed: false,
        }
    }

    /// The reserved sequence number. Stable for the lifetime of the
    /// guard.
    #[must_use]
    pub const fn number(&self) -> u64 {
        self.reserved
    }

    /// Commit the reservation. Drop runs but does not roll back.
    ///
    /// Takes `mut self` (move) so the guard cannot be used after
    /// commit. The compiler enforces single-shot commit by consuming the
    /// guard.
    pub fn commit(mut self) {
        self.committed = true;
        // Drop runs here but the !committed branch is skipped.
    }
}

impl Drop for SequenceReservation<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.tracker.rollback(self.reserved);
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
    fn fresh_tracker_starts_at_zero() {
        let t = SendSequenceTracker::new();
        assert_eq!(t.last_issued(), 0);
    }

    #[test]
    fn from_persisted_preserves_high_water_mark() {
        let t = SendSequenceTracker::from_persisted(42);
        assert_eq!(t.last_issued(), 42);
    }

    #[test]
    fn reserve_next_increments_monotonically() {
        let mut t = SendSequenceTracker::new();
        assert_eq!(t.reserve_next(), 1);
        assert_eq!(t.reserve_next(), 2);
        assert_eq!(t.reserve_next(), 3);
        assert_eq!(t.last_issued(), 3);
    }

    /// Reserve + commit: tracker advances, no rollback.
    #[test]
    fn reserve_then_commit_advances_tracker() {
        let mut t = SendSequenceTracker::new();
        let reservation = SequenceReservation::reserve(&mut t);
        assert_eq!(reservation.number(), 1);
        reservation.commit();
        assert_eq!(t.last_issued(), 1);
    }

    /// Reserve + drop without commit: rollback fires, tracker returns to
    /// pre-reservation state.
    #[test]
    fn reserve_then_drop_rolls_back() {
        let mut t = SendSequenceTracker::new();
        {
            let reservation = SequenceReservation::reserve(&mut t);
            assert_eq!(reservation.number(), 1);
            // Implicit drop here, no commit.
        }
        assert_eq!(
            t.last_issued(),
            0,
            "Drop without commit must roll back the reservation",
        );
    }

    /// Reserve + ?-early-return (panic-unwind safety): drop fires, rollback
    /// executed.
    ///
    /// We use `catch_unwind` to assert that even when the surrounding scope
    /// panics, the guard's Drop runs and rolls the tracker back. This is the
    /// same code path that handles `?`-early-return.
    #[test]
    fn reserve_then_panic_rolls_back() {
        // The tracker must be UnwindSafe via Box<...>; SendSequenceTracker
        // is plain owned data, but the &mut borrow inside the guard makes
        // the closure non-unwind-safe. We sidestep by using
        // `AssertUnwindSafe`.
        use std::panic::AssertUnwindSafe;
        let mut t = SendSequenceTracker::new();
        let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
            let reservation = SequenceReservation::reserve(&mut t);
            assert_eq!(reservation.number(), 1);
            panic!("simulated handler failure prior to commit");
        }));
        assert!(result.is_err(), "expected panic to propagate");
        assert_eq!(
            t.last_issued(),
            0,
            "Drop on unwind must roll back the reservation",
        );
    }

    /// Multiple sequential reservations all commit: monotonic.
    #[test]
    fn multiple_sequential_commits_are_monotonic() {
        let mut t = SendSequenceTracker::new();
        for expected in 1u64..=5 {
            let reservation = SequenceReservation::reserve(&mut t);
            assert_eq!(reservation.number(), expected);
            reservation.commit();
        }
        assert_eq!(t.last_issued(), 5);
    }

    /// Reserve + drop + reserve again: the second reservation reuses the
    /// freed number — matching `MembershipState::rollback_sequence_number`
    /// semantics (saturating subtract → next reserve hands back the same
    /// number).
    #[test]
    fn reserve_drop_reserve_reuses_freed_number() {
        let mut t = SendSequenceTracker::new();
        {
            let r = SequenceReservation::reserve(&mut t);
            assert_eq!(r.number(), 1);
            // Drop without commit — tracker rolls back to 0.
        }
        let r2 = SequenceReservation::reserve(&mut t);
        assert_eq!(
            r2.number(),
            1,
            "After rollback, the next reservation re-uses the freed number — \
             matches MembershipState::rollback_sequence_number semantics",
        );
        r2.commit();
        assert_eq!(t.last_issued(), 1);
    }

    /// From persisted state, the next reservation issues `from + 1`.
    #[test]
    fn from_persisted_then_reserve_continues_above_water_mark() {
        let mut t = SendSequenceTracker::from_persisted(7);
        let r = SequenceReservation::reserve(&mut t);
        assert_eq!(r.number(), 8);
        r.commit();
        assert_eq!(t.last_issued(), 8);
    }

    /// Stale rollback (calling `rollback` with a number that is not the
    /// head) is a silent no-op — defensive guard against caller bugs.
    /// `SequenceReservation::Drop` never triggers this path because the
    /// guard's `reserved` is always the head when it was issued, and the
    /// borrow checker prevents another reservation from issuing while
    /// this one is alive.
    #[test]
    fn stale_rollback_is_noop() {
        let mut t = SendSequenceTracker::new();
        for _ in 0..3 {
            t.reserve_next();
        }
        assert_eq!(t.last_issued(), 3);

        // Roll back a stale (non-head) number; tracker should not move.
        t.rollback(1);
        assert_eq!(t.last_issued(), 3);

        // Roll back the head; tracker decrements.
        t.rollback(3);
        assert_eq!(t.last_issued(), 2);
    }

    /// Rollback at zero is a no-op (avoid underflow).
    #[test]
    fn rollback_at_zero_is_noop() {
        let mut t = SendSequenceTracker::new();
        t.rollback(1);
        assert_eq!(t.last_issued(), 0);
        t.rollback(0);
        assert_eq!(t.last_issued(), 0);
    }

    /// `commit()` consumes the guard so post-commit use is a compile-
    /// error. We can't write a positive test for a compile-fail; this
    /// test instead asserts that committing a guard does not roll back
    /// the tracker and does not move the reserved number, by reading
    /// `t.last_issued()` after commit.
    #[test]
    fn commit_consumes_guard_and_does_not_rollback() {
        let mut t = SendSequenceTracker::new();
        let r = SequenceReservation::reserve(&mut t);
        let n = r.number();
        r.commit();
        // Post-commit: the reservation is permanent.
        assert_eq!(t.last_issued(), n);
    }
}
