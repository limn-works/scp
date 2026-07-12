//! Owned Class-S caveat counters for §7.3.8 value-caveat runtime enforcement.
//!
//! A [`CaveatCounters`] record holds the durable per-`(context, ucan_cid)`
//! accounting for the three counter-bearing invocation caveats:
//!
//! - `max_calls` — absolute invocation cap.
//! - `amount_max_cumulative` — cumulative economic ceiling.
//! - `rate_window` — sliding-window rate cap (`max` calls per `window_secs`).
//!
//! # Owned Class-S, not a store
//!
//! Unlike the durable sibling caches keyed by `context/{id}/…`, this record is
//! a **plain, `Clone`-able, serde value co-located with the owning actor's
//! Class-S state** ([`ClassSState::caveat_counters`](crate::context::actor::state::ClassSState)).
//! The per-context actor mailbox already serializes every invocation against
//! the same context, so no `Mutex`/`DashMap` CAS layer is needed to make the
//! load-modify-store atomic — the actor holds `&mut` to the map for the whole
//! reserve step. This deliberately diverges from a repository-backed store: an
//! owned field cannot introduce a lock on the actor hot path (clippy
//! `disallowed_types` bans `tokio::sync::Mutex` / `dashmap::DashMap` here), and
//! it rides the existing fail-closed Class-S snapshot/restore machinery
//! (ADR-049 §9) rather than a separate persistence namespace.
//!
//! # Crash-safety (ADR-049 §9)
//!
//! A consumed counter is Class-S: it MUST be mutated ONLY inside a
//! `commit_class_s_keep`-family closure so a ≤50 ms coalesce-window crash after
//! the caller observed success cannot *un-consume* a cap (which would re-open
//! the spend/rate window the counter exists to close). The methods here are
//! pure `&mut self` transformations with no I/O — the fail-closed persist and
//! the KEEP-on-failure discipline live in the combinator at the call site
//! ([`reserve_outlet_economy`](crate::context::outlets_helpers::reserve_outlet_economy)).
//!
//! See `.docs/specs/07-trust-validation-and-capabilities.md` §7.3.8 and
//! `.docs/adrs/ADR-049-outlet-redesign.md` §9.

use scp_protocol::trust::CaveatKind;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// CounterExhausted
// ---------------------------------------------------------------------------

/// Rejection reasons produced by [`CaveatCounters::try_consume`].
///
/// Each variant carries the numeric context of the breach (the value the
/// consume *would* have produced and the cap it would have crossed) so the
/// call site can surface a precise diagnostic. The owning `ucan_cid` is NOT
/// carried here — the pure record does not know its own map key; the call
/// site (which holds the key) folds it into the surfaced error message.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CounterExhausted {
    /// `max_calls` cap reached — the next invocation would push
    /// `max_calls_used` past `cap`.
    #[error("max_calls caveat exhausted: would_be={would_be}, cap={cap}")]
    MaxCalls {
        /// What `max_calls_used` would have become had the increment been
        /// admitted.
        would_be: u64,
        /// The `max_calls` ceiling from the delegation's caveats.
        cap: u64,
    },
    /// `amount_max_cumulative` cap reached — the next charge would push the
    /// cumulative amount past the ceiling.
    #[error("amount_max_cumulative caveat exhausted: would_be={would_be}, cap={cap}")]
    AmountCumulative {
        /// What `amount_cumulative_used` would have become had the charge been
        /// admitted.
        would_be: u64,
        /// The `amount_max_cumulative` ceiling from the delegation's caveats.
        cap: u64,
    },
    /// `rate_window` cap reached — the active window already holds `cap`
    /// timestamps.
    #[error(
        "rate_window caveat exhausted: in_window={in_window}, cap={cap}, window_secs={window_secs}"
    )]
    RateWindow {
        /// Number of timestamps currently within the active window.
        in_window: u64,
        /// The `RateWindow::max` ceiling from the delegation's caveats.
        cap: u64,
        /// `RateWindow::window_secs` — the active sliding-window length.
        window_secs: u32,
    },
}

impl CounterExhausted {
    /// Returns the [`CaveatKind`] this exhaustion corresponds to.
    #[must_use]
    pub const fn kind(&self) -> CaveatKind {
        match self {
            Self::MaxCalls { .. } => CaveatKind::MaxCalls,
            Self::AmountCumulative { .. } => CaveatKind::AmountCumulative,
            Self::RateWindow { .. } => CaveatKind::RateWindow,
        }
    }
}

// ---------------------------------------------------------------------------
// CaveatCounters
// ---------------------------------------------------------------------------

/// Per-`ucan_cid` counter record for the three counter-bearing §7.3.8 caveats.
///
/// One record per `(context, ucan_cid)` pair (the map key lives in
/// [`ClassSState::caveat_counters`](crate::context::actor::state::ClassSState)),
/// regardless of which caveat kinds the delegation declares — storing all
/// kinds together means a single Class-S persist atomically commits every
/// counter change made under one reserve step.
///
/// **Field-ordering invariant.** `rate_window_timestamps` MUST be sorted in
/// ascending order. [`prune_expired_window_entries`] relies on this to
/// short-circuit the scan; new timestamps are always appended (`now` is
/// monotonic enough for our purposes — see the saturating-clamp behaviour in
/// [`prune_expired_window_entries`] for the non-monotonic-clock guard).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaveatCounters {
    /// Cumulative count of invocations charged against `max_calls`.
    pub max_calls_used: u64,
    /// Cumulative amount charged against `amount_max_cumulative`.
    pub amount_cumulative_used: u64,
    /// Ring buffer of invocation timestamps (Unix seconds) for `rate_window`,
    /// sorted ascending. Pruned to entries within the active window on every
    /// [`Self::try_consume`] for the [`CaveatKind::RateWindow`] kind.
    pub rate_window_timestamps: Vec<u64>,
}

impl CaveatCounters {
    /// Checks the relevant counter against its cap and, if the invocation is
    /// admissible, mutates the counter in place.
    ///
    /// `amount` is interpreted per-kind:
    ///
    /// - [`CaveatKind::MaxCalls`]: ignored — every admitted invocation
    ///   increments by 1 (§7.3.8 "absolute invocation cap").
    /// - [`CaveatKind::AmountCumulative`]: added to `amount_cumulative_used`.
    /// - [`CaveatKind::RateWindow`]: ignored — admission depends on the count
    ///   of timestamps already inside the window, not on any amount. `now` is
    ///   appended on admission; `window_secs` sets the sliding-window length.
    ///
    /// Returns `Ok(())` iff the consume was admitted (and the record mutated).
    /// On [`CounterExhausted`] the record is left **unchanged** — the caller
    /// can safely reject without persisting.
    ///
    /// # Errors
    ///
    /// Returns [`CounterExhausted`] when the cap is reached.
    pub fn try_consume(
        &mut self,
        kind: CaveatKind,
        amount: u64,
        cap: u64,
        window_secs: u32,
        now: u64,
    ) -> Result<(), CounterExhausted> {
        match kind {
            CaveatKind::MaxCalls => {
                let would_be = self.max_calls_used.saturating_add(1);
                if would_be > cap {
                    return Err(CounterExhausted::MaxCalls { would_be, cap });
                }
                self.max_calls_used = would_be;
            }
            CaveatKind::AmountCumulative => {
                let would_be = self.amount_cumulative_used.saturating_add(amount);
                if would_be > cap {
                    return Err(CounterExhausted::AmountCumulative { would_be, cap });
                }
                self.amount_cumulative_used = would_be;
            }
            CaveatKind::RateWindow => {
                prune_expired_window_entries(&mut self.rate_window_timestamps, now, window_secs);
                let in_window =
                    u64::try_from(self.rate_window_timestamps.len()).unwrap_or(u64::MAX);
                if in_window >= cap {
                    return Err(CounterExhausted::RateWindow {
                        in_window,
                        cap,
                        window_secs,
                    });
                }
                self.rate_window_timestamps.push(now);
            }
        }
        Ok(())
    }

    /// Releases (decrements) a previously-consumed counter amount.
    ///
    /// The streaming settlement slice (SCP R4 HIGH-1) returns the unspent
    /// portion of an open-time reservation to the counter at close-time. This
    /// single-shot slice never calls `release`; it is provided (and unit-
    /// tested) so the streaming slice builds on a settled surface.
    ///
    /// `amount` is interpreted per-kind:
    ///
    /// - [`CaveatKind::AmountCumulative`]: subtracted from
    ///   `amount_cumulative_used` (saturating at `0`).
    /// - [`CaveatKind::MaxCalls`]: subtracts whole invocations from
    ///   `max_calls_used` (saturating at `0`).
    /// - [`CaveatKind::RateWindow`]: a no-op — sliding-window timestamps age
    ///   out by time, not by release.
    ///
    /// Idempotent against underflow: a release larger than the recorded usage
    /// clamps to `0` rather than wrapping.
    pub fn release(&mut self, kind: CaveatKind, amount: u64) {
        match kind {
            CaveatKind::AmountCumulative => {
                self.amount_cumulative_used = self.amount_cumulative_used.saturating_sub(amount);
            }
            CaveatKind::MaxCalls => {
                self.max_calls_used = self.max_calls_used.saturating_sub(amount);
            }
            CaveatKind::RateWindow => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Sliding-window pruning helper
// ---------------------------------------------------------------------------

/// Removes timestamps older than `now - window_secs` from a sorted ring buffer.
///
/// `timestamps` MUST be sorted ascending (the [`CaveatCounters`] invariant).
/// After pruning, the buffer holds only entries `t` with
/// `t > now - window_secs` — timestamps strictly inside the current window. An
/// event at exactly `now - window_secs` is treated as expired (§7.3.8
/// sliding-window boundary semantics).
///
/// `now < window_secs` (a clock pathologically close to the Unix epoch) would
/// underflow `now - window_secs`; [`u64::saturating_sub`] clamps the cutoff to
/// `0`, so any timestamp at exactly `0` is expired but any positive timestamp
/// survives. Production clocks report seconds well above any plausible
/// `window_secs`, so this regime is purely a defensive guard against a caller
/// passing a near-epoch test clock — and it also means a restart cannot
/// *widen* a rate window: pruning against the restored wall clock only ever
/// drops more entries.
pub fn prune_expired_window_entries(timestamps: &mut Vec<u64>, now: u64, window_secs: u32) {
    let cutoff = now.saturating_sub(u64::from(window_secs));
    // `timestamps` is sorted ascending, so `partition_point` finds the first
    // index strictly greater than `cutoff` in O(log n).
    let drop_through = timestamps.partition_point(|&ts| ts <= cutoff);
    if drop_through > 0 {
        timestamps.drain(..drop_through);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    // ----- prune (ported verbatim from the reference store tests) ----------

    #[test]
    fn prune_drops_entries_at_or_below_cutoff() {
        let mut buf = vec![10, 20, 30, 40, 50];
        // window = 10s, now = 35 -> cutoff = 25 -> drop 10, 20.
        prune_expired_window_entries(&mut buf, 35, 10);
        assert_eq!(buf, vec![30, 40, 50]);
    }

    #[test]
    fn prune_keeps_all_entries_strictly_inside_window() {
        let mut buf = vec![100, 105, 109];
        prune_expired_window_entries(&mut buf, 110, 10);
        assert_eq!(buf, vec![105, 109]); // 100 == 110 - 10 (boundary expired).
    }

    #[test]
    fn prune_handles_empty_buffer() {
        let mut buf: Vec<u64> = Vec::new();
        prune_expired_window_entries(&mut buf, 1000, 60);
        assert!(buf.is_empty());
    }

    #[test]
    fn prune_handles_clock_below_window_via_saturating_sub() {
        // cutoff = 5.saturating_sub(60) = 0, so entries with ts <= 0 drop.
        let mut buf = vec![0_u64, 1_u64, 2_u64];
        prune_expired_window_entries(&mut buf, 5, 60);
        assert_eq!(buf, vec![1, 2]);
    }

    // ----- max_calls -------------------------------------------------------

    #[test]
    fn max_calls_admits_until_cap_then_rejects() {
        let mut c = CaveatCounters::default();
        for i in 0..5_u64 {
            c.try_consume(CaveatKind::MaxCalls, 1, 5, 0, 0)
                .unwrap_or_else(|e| panic!("increment {i} failed: {e:?}"));
        }
        let err = c
            .try_consume(CaveatKind::MaxCalls, 1, 5, 0, 0)
            .expect_err("6th increment must reject");
        assert_eq!(
            err,
            CounterExhausted::MaxCalls {
                would_be: 6,
                cap: 5
            }
        );
        // Rejection did not mutate the counter.
        assert_eq!(c.max_calls_used, 5);
    }

    #[test]
    fn max_calls_rejection_does_not_mutate() {
        let mut c = CaveatCounters::default();
        c.try_consume(CaveatKind::MaxCalls, 1, 1, 0, 0).unwrap();
        let _ = c.try_consume(CaveatKind::MaxCalls, 1, 1, 0, 0).unwrap_err();
        assert_eq!(c.max_calls_used, 1);
    }

    // ----- amount_max_cumulative -------------------------------------------

    #[test]
    fn amount_cumulative_admits_until_cap_then_rejects() {
        let mut c = CaveatCounters::default();
        c.try_consume(CaveatKind::AmountCumulative, 30, 100, 0, 0)
            .unwrap();
        c.try_consume(CaveatKind::AmountCumulative, 70, 100, 0, 0)
            .unwrap();
        let err = c
            .try_consume(CaveatKind::AmountCumulative, 1, 100, 0, 0)
            .expect_err("third charge would exceed cap");
        assert_eq!(
            err,
            CounterExhausted::AmountCumulative {
                would_be: 101,
                cap: 100
            }
        );
        assert_eq!(c.amount_cumulative_used, 100);
    }

    #[test]
    fn amount_cumulative_admits_exact_cap_then_rejects_one_more() {
        let mut c = CaveatCounters::default();
        c.try_consume(CaveatKind::AmountCumulative, 100, 100, 0, 0)
            .unwrap();
        let err = c
            .try_consume(CaveatKind::AmountCumulative, 1, 100, 0, 0)
            .expect_err("one more unit must reject");
        assert_eq!(err.kind(), CaveatKind::AmountCumulative);
    }

    // ----- rate_window -----------------------------------------------------

    #[test]
    fn rate_window_admits_until_cap_then_rejects() {
        let mut c = CaveatCounters::default();
        for _ in 0..3 {
            c.try_consume(CaveatKind::RateWindow, 0, 3, 60, 1000)
                .unwrap();
        }
        let err = c
            .try_consume(CaveatKind::RateWindow, 0, 3, 60, 1000)
            .expect_err("4th invocation in window must reject");
        assert_eq!(
            err,
            CounterExhausted::RateWindow {
                in_window: 3,
                cap: 3,
                window_secs: 60,
            }
        );
    }

    #[test]
    fn rate_window_old_entries_age_out_with_clock_advance() {
        let mut c = CaveatCounters::default();
        for _ in 0..3 {
            c.try_consume(CaveatKind::RateWindow, 0, 3, 60, 1000)
                .unwrap();
        }
        // Window full at t=1000.
        c.try_consume(CaveatKind::RateWindow, 0, 3, 60, 1000)
            .unwrap_err();
        // Advance past the window: cutoff = 1100 - 60 = 1040; all three at 1000
        // are stale. Two more admissions succeed.
        c.try_consume(CaveatKind::RateWindow, 0, 3, 60, 1100)
            .unwrap();
        c.try_consume(CaveatKind::RateWindow, 0, 3, 60, 1100)
            .unwrap();
    }

    // ----- release ---------------------------------------------------------

    #[test]
    fn release_saturates_and_is_kind_specific() {
        let mut c = CaveatCounters {
            max_calls_used: 2,
            amount_cumulative_used: 50,
            rate_window_timestamps: vec![1000],
        };
        c.release(CaveatKind::AmountCumulative, 30);
        assert_eq!(c.amount_cumulative_used, 20);
        c.release(CaveatKind::AmountCumulative, 999); // saturates at 0.
        assert_eq!(c.amount_cumulative_used, 0);
        c.release(CaveatKind::MaxCalls, 1);
        assert_eq!(c.max_calls_used, 1);
        c.release(CaveatKind::RateWindow, 5); // no-op.
        assert_eq!(c.rate_window_timestamps, vec![1000]);
    }
}
