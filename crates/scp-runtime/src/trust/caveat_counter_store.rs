//! `CaveatCounterStore` — durable per-`(ucan_cid, caveat_kind)` accounting
//! for §7.3.8 invocation caveats.
//!
//! This is the runtime sibling of `NonceTracker` (§9.5). UCAN delegations for
//! outlet invocation may carry [`InvocationCaveats`](scp_protocol::trust::caveats::InvocationCaveats)
//! with three counter-bearing fields:
//!
//! - `max_calls` — absolute invocation cap.
//! - `amount_max_cumulative` — economic cumulative ceiling.
//! - `rate_window` — sliding-window rate cap (`max` calls per `window_secs`).
//!
//! Naïvely re-checking each cap against persisted state at every invocation
//! permits a TOCTOU race: two concurrent invocations both load `used == cap - 1`,
//! both decide the cap is not yet reached, both write `used = cap`, and the
//! delegation has been spent twice. The store closes that race with
//! per-`(context_id, ucan_cid)` `tokio::sync::Mutex` guards: every
//! `check_and_increment` call serializes against concurrent calls for the same
//! delegation, so the load-modify-store sequence is atomic with respect to other
//! racers on the same UCAN. Different UCANs are independent and remain
//! concurrent. The lock map itself uses `dashmap::DashMap` to avoid blocking
//! the hot path on a global `Mutex`.
//!
//! Counters persist via [`ProtocolRepository`](crate::store::ProtocolRepository)
//! under `context/{id}/caveat_counters/{ucan_cid}` per §17.3, so a process
//! restart does not reset cumulative state. The `caveat_counters/` namespace
//! holds one record per UCAN — all three counter kinds for the same delegation
//! live in a single record so a single `store_value` write atomically commits
//! every counter change made under one mutex acquisition.
//!
//! See `.docs/specs/07-trust-validation-and-capabilities.md` §7.3.8,
//! `.docs/specs/17-persistence-and-storage.md` §17.3, ADR-049, and SCP-OUT-020.

use std::sync::Arc;

use dashmap::DashMap;
use scp_platform::traits::Storage;
use scp_primitives::Clock;
use tokio::sync::Mutex;

use crate::store::caveat_counters::CaveatCounters;
use crate::store::{ProtocolRepository, StoreError};
use scp_protocol::trust::CaveatKind;

// ---------------------------------------------------------------------------
// CounterExhausted error
// ---------------------------------------------------------------------------

/// Reasons [`CaveatCounterStore::check_and_increment`] may reject an invocation.
///
/// Each variant maps to a specific Authorization-class slug (§7.3.8 runtime
/// enforcement pipeline). Variants carry the cap, the value the increment
/// would have produced, and (for the rate-window case) the window length —
/// enough information for the caller to surface a precise error to the
/// invoking SDK.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CounterExhausted {
    /// `max_calls` cap reached. The next invocation would push
    /// `max_calls_used` past `cap`.
    #[error("max_calls caveat exhausted for ucan_cid={ucan_cid}: would_be={would_be}, cap={cap}")]
    MaxCalls {
        /// CID of the UCAN whose delegation carries the cap.
        ucan_cid: String,
        /// What `max_calls_used` would have become if the increment had been
        /// allowed.
        would_be: u64,
        /// The `max_calls` ceiling from the delegation's caveats.
        cap: u64,
    },
    /// `amount_max_cumulative` cap reached. The next charge would push the
    /// cumulative amount past the ceiling.
    #[error(
        "amount_max_cumulative caveat exhausted for ucan_cid={ucan_cid}: would_be={would_be}, cap={cap}"
    )]
    AmountCumulative {
        /// CID of the UCAN whose delegation carries the cap.
        ucan_cid: String,
        /// What `amount_cumulative_used` would have become if the charge had
        /// been allowed.
        would_be: u64,
        /// The `amount_max_cumulative` ceiling from the delegation's caveats.
        cap: u64,
    },
    /// `rate_window` cap reached. The active window already holds `cap`
    /// timestamps, so admitting another would exceed `RateWindow::max`.
    #[error(
        "rate_window caveat exhausted for ucan_cid={ucan_cid}: in_window={in_window}, cap={cap}, window_secs={window_secs}"
    )]
    RateWindow {
        /// CID of the UCAN whose delegation carries the cap.
        ucan_cid: String,
        /// Number of timestamps currently within the active window.
        in_window: u64,
        /// The `RateWindow::max` ceiling from the delegation's caveats.
        cap: u64,
        /// `RateWindow::window_secs` — the active sliding-window length.
        window_secs: u32,
    },
}

impl CounterExhausted {
    /// Returns the [`CaveatKind`] this exhaustion error corresponds to.
    ///
    /// Convenience for callers that surface the kind alongside the error.
    #[must_use]
    pub const fn kind(&self) -> CaveatKind {
        match self {
            Self::MaxCalls { .. } => CaveatKind::MaxCalls,
            Self::AmountCumulative { .. } => CaveatKind::AmountCumulative,
            Self::RateWindow { .. } => CaveatKind::RateWindow,
        }
    }

    /// Returns the UCAN CID this exhaustion error corresponds to.
    #[must_use]
    pub const fn ucan_cid(&self) -> &str {
        match self {
            Self::MaxCalls { ucan_cid, .. }
            | Self::AmountCumulative { ucan_cid, .. }
            | Self::RateWindow { ucan_cid, .. } => ucan_cid.as_str(),
        }
    }
}

// ---------------------------------------------------------------------------
// CounterError — wrapping enum
// ---------------------------------------------------------------------------

/// Errors produced by [`CaveatCounterStore::check_and_increment`].
///
/// Two distinct failure surfaces share one return type: caveat exhaustion
/// (`Exhausted`) is an authorization decision that flows back to the invoking
/// SDK; storage failures (`Store`) are infrastructure errors that bubble up
/// to the runtime's general error handling. Splitting them lets callers
/// pattern-match on the difference without a stringly-typed dispatch.
#[derive(Debug, thiserror::Error)]
pub enum CounterError {
    /// The caveat counter would exceed its cap. Authorization rejection.
    #[error(transparent)]
    Exhausted(#[from] CounterExhausted),
    /// The underlying persistent storage failed. Infrastructure error.
    #[error("counter store error: {0}")]
    Store(#[from] StoreError),
}

// ---------------------------------------------------------------------------
// CaveatCounterStore
// ---------------------------------------------------------------------------

/// Per-(`ucan_cid`, `caveat_kind`) counter store with CAS-style atomicity.
///
/// Wraps a [`ProtocolRepository`] for durability and an in-process map of
/// `tokio::sync::Mutex` guards to serialize concurrent increments against the
/// same `(context_id, ucan_cid)` pair. See module docs for the full design.
///
/// The store is `Clone`-safe via `Arc` semantics: cloning produces a new
/// handle pointing at the same repository and lock map, so concurrent
/// invocations across cloned handles still serialize correctly.
///
/// The clock is injected (rather than read from a global) so tests can
/// substitute a deterministic [`scp_primitives::TestClock`] for the
/// rate-window scan.
pub struct CaveatCounterStore<S: Storage> {
    repository: Arc<ProtocolRepository<S>>,
    clock: Arc<dyn Clock>,
    locks: Arc<DashMap<LockKey, Arc<Mutex<()>>>>,
}

/// Composite key for the per-UCAN lock map.
///
/// `(context_id, ucan_cid)` together identify a single counter record.
/// Different contexts may legitimately reuse the same UCAN CID for unrelated
/// delegations, so the lock space is partitioned by both fields.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct LockKey {
    context_id: String,
    ucan_cid: String,
}

impl<S: Storage> CaveatCounterStore<S> {
    /// Constructs a [`CaveatCounterStore`] over the given repository and clock.
    ///
    /// The lock map starts empty; entries are inserted lazily on first
    /// access for each `(context_id, ucan_cid)` pair and persist for the
    /// lifetime of the store. This is bounded by the number of distinct
    /// in-flight UCAN delegations per process — a quantity the rest of the
    /// runtime already constrains via UCAN cache eviction.
    #[must_use]
    pub fn new(repository: Arc<ProtocolRepository<S>>, clock: Arc<dyn Clock>) -> Self {
        Self {
            repository,
            clock,
            locks: Arc::new(DashMap::new()),
        }
    }

    /// Returns a clone of the lock guard for the given `(context_id, ucan_cid)`.
    ///
    /// `dashmap::DashMap::entry` is used to insert-if-absent atomically — two
    /// callers asking for the same key concurrently both observe the same
    /// `Arc<Mutex<()>>` and serialize against it.
    fn lock_for(&self, context_id: &str, ucan_cid: &str) -> Arc<Mutex<()>> {
        let key = LockKey {
            context_id: context_id.to_owned(),
            ucan_cid: ucan_cid.to_owned(),
        };
        self.locks
            .entry(key)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// Atomically checks the relevant counter against its cap and, if the
    /// invocation is admissible, increments the counter and persists the
    /// updated record.
    ///
    /// `amount` is interpreted per-kind:
    ///
    /// - [`CaveatKind::MaxCalls`]: ignored — every successful invocation
    ///   increments by 1. (Callers MAY pass `1` for clarity but the field is
    ///   not consulted; this matches the spec wording, "absolute invocation cap.")
    /// - [`CaveatKind::AmountCumulative`]: added to `amount_cumulative_used`.
    /// - [`CaveatKind::RateWindow`]: ignored — the `amount` value plays no
    ///   role in rate accounting; admission depends on the count of
    ///   timestamps already in the window. Use
    ///   [`Self::record_rate_window_event`] when the caller wants to lock in a
    ///   timestamp without accepting/rejecting a charge in one call.
    ///
    /// Returns `Ok(())` iff the increment was committed. Returns
    /// `Err(CounterError::Exhausted(_))` if the cap is reached, in which case
    /// no state is mutated.
    ///
    /// # CAS semantics
    ///
    /// The check, mutate, and write all happen while holding the per-UCAN
    /// `Mutex`, so two concurrent calls cannot both observe `used == cap - 1`
    /// and both decide to admit. Whichever caller acquires the lock first
    /// either commits the increment (and the second caller observes the new
    /// value) or rejects (and the second caller may yet succeed). At most
    /// `cap` invocations are ever admitted across all callers for a given
    /// `(context_id, ucan_cid, MaxCalls)` triple, even under arbitrary
    /// concurrency.
    ///
    /// # Errors
    ///
    /// - [`CounterError::Exhausted`]: the cap is reached (no state change).
    /// - [`CounterError::Store`]: the underlying storage layer failed; the
    ///   in-memory counter state is unchanged.
    pub async fn check_and_increment(
        &self,
        context_id: &str,
        ucan_cid: &str,
        kind: CaveatKind,
        amount: u64,
        cap: u64,
        window_secs: u32,
    ) -> Result<(), CounterError> {
        // Sanitize key components up front so we surface invalid inputs as
        // storage errors before acquiring a lock. The repository's
        // `load_caveat_counters` performs the canonical sanitization; do it
        // once here so a malformed caller cannot poison the lock map.
        crate::store::caveat_counters::caveat_counters_key(context_id, ucan_cid)?;
        let lock = self.lock_for(context_id, ucan_cid);
        let _guard = lock.lock().await;

        let mut record: CaveatCounters = self
            .repository
            .load_caveat_counters(context_id, ucan_cid)
            .await?
            .unwrap_or_default();

        match kind {
            CaveatKind::MaxCalls => {
                let _ = amount; // §7.3.8: max_calls is per-invocation, not per-amount.
                let would_be = record.max_calls_used.saturating_add(1);
                if would_be > cap {
                    return Err(CounterError::Exhausted(CounterExhausted::MaxCalls {
                        ucan_cid: ucan_cid.to_owned(),
                        would_be,
                        cap,
                    }));
                }
                record.max_calls_used = would_be;
            }
            CaveatKind::AmountCumulative => {
                let would_be = record.amount_cumulative_used.saturating_add(amount);
                if would_be > cap {
                    return Err(CounterError::Exhausted(
                        CounterExhausted::AmountCumulative {
                            ucan_cid: ucan_cid.to_owned(),
                            would_be,
                            cap,
                        },
                    ));
                }
                record.amount_cumulative_used = would_be;
            }
            CaveatKind::RateWindow => {
                let _ = amount; // §7.3.8: rate-window admission is by count, not amount.
                let now = self.clock.now_secs();
                prune_expired_window_entries(&mut record.rate_window_timestamps, now, window_secs);
                let in_window =
                    u64::try_from(record.rate_window_timestamps.len()).unwrap_or(u64::MAX);
                if in_window >= cap {
                    return Err(CounterError::Exhausted(CounterExhausted::RateWindow {
                        ucan_cid: ucan_cid.to_owned(),
                        in_window,
                        cap,
                        window_secs,
                    }));
                }
                record.rate_window_timestamps.push(now);
            }
        }

        self.repository
            .store_caveat_counters(context_id, ucan_cid, &record)
            .await?;
        Ok(())
    }

    /// Reads the persisted [`CaveatCounters`] record for diagnostics or
    /// migration.
    ///
    /// Returns `None` if no invocation has yet been recorded for this UCAN.
    /// Does NOT prune the rate-window ring buffer; callers wanting a "live"
    /// view should pass the result through [`prune_expired_window_entries`]
    /// with the desired window length.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the underlying storage read or
    /// deserialization fails.
    pub async fn load_counters(
        &self,
        context_id: &str,
        ucan_cid: &str,
    ) -> Result<Option<CaveatCounters>, StoreError> {
        self.repository
            .load_caveat_counters(context_id, ucan_cid)
            .await
    }

    /// Deletes the persisted counter record for a UCAN.
    ///
    /// Used during whole-token revocation (§7.3.8 revocation granularity is
    /// whole-token, so a `UcanRevocation` event implicitly invalidates every
    /// caveat including counter state). Idempotent: succeeds even if no
    /// record exists.
    ///
    /// Does NOT clear the in-process lock map — a re-issued UCAN with the
    /// same CID would observe a fresh storage record but the lock entry
    /// would still be in the map. That is fine: the lock guards
    /// load-modify-store, so a fresh record under the same lock simply
    /// starts at `Default`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if key sanitization or the underlying storage
    /// delete fails.
    pub async fn delete_counters(
        &self,
        context_id: &str,
        ucan_cid: &str,
    ) -> Result<(), StoreError> {
        self.repository
            .delete_caveat_counters(context_id, ucan_cid)
            .await
    }
}

impl<S: Storage> Clone for CaveatCounterStore<S> {
    fn clone(&self) -> Self {
        Self {
            repository: Arc::clone(&self.repository),
            clock: Arc::clone(&self.clock),
            locks: Arc::clone(&self.locks),
        }
    }
}

// ---------------------------------------------------------------------------
// CaveatCounterApi — type-erased trait for FFI/manager wiring
// ---------------------------------------------------------------------------

/// SCP-OUT-021: type-erased API surface for [`CaveatCounterStore`].
///
/// `CaveatCounterStore<S>` is generic over the [`Storage`] implementor —
/// useful for compile-time storage choice, awkward when the manager
/// wrapper wants to hold "*some* counter store" without leaking the
/// storage type into every call site. Boxing the store as
/// `Arc<dyn CaveatCounterApi>` removes the generic parameter from the
/// manager API while preserving every operation `CaveatCounterStore`
/// exposes.
///
/// All methods mirror the inherent methods on [`CaveatCounterStore`].
/// The trait is `Send + Sync` because invocation enforcement runs from
/// async tasks shared across executors (napi, uniffi, etc.).
pub trait CaveatCounterApi: Send + Sync {
    /// See [`CaveatCounterStore::check_and_increment`].
    fn check_and_increment<'a>(
        &'a self,
        context_id: &'a str,
        ucan_cid: &'a str,
        kind: scp_protocol::trust::CaveatKind,
        amount: u64,
        cap: u64,
        window_secs: u32,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), CounterError>> + Send + 'a>>;
}

impl<S: Storage + 'static> CaveatCounterApi for CaveatCounterStore<S> {
    fn check_and_increment<'a>(
        &'a self,
        context_id: &'a str,
        ucan_cid: &'a str,
        kind: scp_protocol::trust::CaveatKind,
        amount: u64,
        cap: u64,
        window_secs: u32,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), CounterError>> + Send + 'a>>
    {
        Box::pin(async move {
            self.check_and_increment(context_id, ucan_cid, kind, amount, cap, window_secs)
                .await
        })
    }
}

// ---------------------------------------------------------------------------
// Sliding-window pruning helper
// ---------------------------------------------------------------------------

/// Removes timestamps older than `now - window_secs` from a sorted ring buffer.
///
/// `timestamps` MUST be sorted in ascending order (the [`CaveatCounters`]
/// invariant). After pruning, the buffer holds only entries `t` with
/// `t > now - window_secs` — i.e., timestamps strictly inside the current
/// window. The boundary semantics match §7.3.8 sliding-window behaviour:
/// an event at exactly `now - window_secs` is treated as expired.
///
/// This is a free function so it can be shared between
/// `check_and_increment` (for rate admission) and external callers that want
/// a live view of the window count.
///
/// `now < window_secs` (a clock pathologically close to the Unix epoch)
/// would underflow `now - window_secs`. The implementation uses
/// [`u64::saturating_sub`] so the cutoff clamps to `0`; the practical
/// consequence is that any timestamp at exactly `0` would still be expired
/// against that cutoff (`0 <= 0`), but any positive timestamp survives.
/// Production clocks pinned by NTP report seconds well above any plausible
/// `window_secs`, so this regime is purely a defensive guard against a
/// caller passing a `TestClock::new(0)`.
pub fn prune_expired_window_entries(timestamps: &mut Vec<u64>, now: u64, window_secs: u32) {
    let cutoff = now.saturating_sub(u64::from(window_secs));
    // Find the first index whose timestamp is strictly greater than `cutoff`.
    // Because `timestamps` is sorted ascending, `partition_point` finds the
    // boundary in O(log n).
    let drop_through = timestamps.partition_point(|&ts| ts <= cutoff);
    if drop_through > 0 {
        timestamps.drain(..drop_through);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::similar_names,
    clippy::doc_markdown,
    clippy::uninlined_format_args,
    clippy::match_wildcard_for_single_variants,
    clippy::type_complexity
)]
mod tests {
    use std::sync::Arc;

    use scp_platform::testing::InMemoryStorage;
    use scp_primitives::TestClock;

    use super::*;
    use crate::store::ProtocolRepository;

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    fn make_repo() -> Arc<ProtocolRepository<InMemoryStorage>> {
        Arc::new(ProtocolRepository::new_for_testing(InMemoryStorage::new()))
    }

    fn make_repo_shared(
        storage: Arc<InMemoryStorage>,
    ) -> Arc<ProtocolRepository<Arc<InMemoryStorage>>> {
        Arc::new(ProtocolRepository::new_for_testing(storage))
    }

    fn make_store_with_clock(clock: Arc<dyn Clock>) -> CaveatCounterStore<InMemoryStorage> {
        CaveatCounterStore::new(make_repo(), clock)
    }

    fn make_store() -> CaveatCounterStore<InMemoryStorage> {
        make_store_with_clock(Arc::new(TestClock::new(1_000_000)))
    }

    // -----------------------------------------------------------------------
    // Path-traversal rejection at check_and_increment boundary
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn check_and_increment_rejects_path_traversal_in_context_id() {
        let store = make_store();
        let err = store
            .check_and_increment("../etc/passwd", "ucan-1", CaveatKind::MaxCalls, 1, 1, 0)
            .await
            .expect_err("malformed context id must error before lock acquisition");
        match err {
            CounterError::Store(StoreError::SerializationFailed(_)) => {}
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[tokio::test]
    async fn check_and_increment_rejects_null_byte_in_ucan_cid() {
        let store = make_store();
        let err = store
            .check_and_increment("ctx", "tok\0evil", CaveatKind::MaxCalls, 1, 1, 0)
            .await
            .expect_err("null-byte ucan_cid must error");
        match err {
            CounterError::Store(StoreError::SerializationFailed(_)) => {}
            other => panic!("unexpected error: {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Sliding-window pruning
    // -----------------------------------------------------------------------

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
        // now < window_secs would underflow; saturating_sub clamps to 0,
        // and 0 <= 0 means the very first entry could be dropped if it is
        // exactly 0. Verify nothing-greater-than-0 stays.
        let mut buf = vec![0_u64, 1_u64, 2_u64];
        prune_expired_window_entries(&mut buf, 5, 60);
        // cutoff = 5.saturating_sub(60) = 0, so entries with ts <= 0 drop.
        assert_eq!(buf, vec![1, 2]);
    }

    // -----------------------------------------------------------------------
    // CaveatKind round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn caveat_kind_string_slugs_match_spec() {
        assert_eq!(CaveatKind::MaxCalls.as_str(), "maxCalls");
        assert_eq!(CaveatKind::AmountCumulative.as_str(), "amountMaxCumulative");
        assert_eq!(CaveatKind::RateWindow.as_str(), "rateWindow");
    }

    // -----------------------------------------------------------------------
    // max_calls happy path + cap
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn max_calls_admits_until_cap_then_rejects() {
        let store = make_store();

        for i in 0..5_u64 {
            store
                .check_and_increment("ctx", "ucan-1", CaveatKind::MaxCalls, 1, 5, 0)
                .await
                .unwrap_or_else(|e| panic!("increment {} failed: {:?}", i, e));
        }

        let err = store
            .check_and_increment("ctx", "ucan-1", CaveatKind::MaxCalls, 1, 5, 0)
            .await
            .expect_err("6th increment must reject");

        match err {
            CounterError::Exhausted(CounterExhausted::MaxCalls {
                ucan_cid,
                would_be,
                cap,
            }) => {
                assert_eq!(ucan_cid, "ucan-1");
                assert_eq!(would_be, 6);
                assert_eq!(cap, 5);
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[tokio::test]
    async fn max_calls_failure_does_not_persist_state() {
        let store = make_store();

        // Cap = 1, exhaust it.
        store
            .check_and_increment("ctx", "ucan-1", CaveatKind::MaxCalls, 1, 1, 0)
            .await
            .unwrap();
        let _ = store
            .check_and_increment("ctx", "ucan-1", CaveatKind::MaxCalls, 1, 1, 0)
            .await
            .unwrap_err();

        let counters = store.load_counters("ctx", "ucan-1").await.unwrap().unwrap();
        // First call succeeded -> max_calls_used = 1. Second rejected -> still 1.
        assert_eq!(counters.max_calls_used, 1);
    }

    #[tokio::test]
    async fn max_calls_kinds_are_per_ucan_isolated() {
        let store = make_store();

        store
            .check_and_increment("ctx", "ucan-A", CaveatKind::MaxCalls, 1, 1, 0)
            .await
            .unwrap();
        // ucan-B has its own counter even within the same context.
        store
            .check_and_increment("ctx", "ucan-B", CaveatKind::MaxCalls, 1, 1, 0)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn max_calls_kinds_are_per_context_isolated() {
        let store = make_store();

        store
            .check_and_increment("ctx-1", "ucan-shared", CaveatKind::MaxCalls, 1, 1, 0)
            .await
            .unwrap();
        store
            .check_and_increment("ctx-2", "ucan-shared", CaveatKind::MaxCalls, 1, 1, 0)
            .await
            .unwrap();
    }

    // -----------------------------------------------------------------------
    // amount_max_cumulative happy path + cap
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn amount_cumulative_admits_until_cap_then_rejects() {
        let store = make_store();

        store
            .check_and_increment("ctx", "ucan-1", CaveatKind::AmountCumulative, 30, 100, 0)
            .await
            .unwrap();
        store
            .check_and_increment("ctx", "ucan-1", CaveatKind::AmountCumulative, 70, 100, 0)
            .await
            .unwrap();
        let err = store
            .check_and_increment("ctx", "ucan-1", CaveatKind::AmountCumulative, 1, 100, 0)
            .await
            .expect_err("third charge would push past cap");

        match err {
            CounterError::Exhausted(CounterExhausted::AmountCumulative {
                ucan_cid,
                would_be,
                cap,
            }) => {
                assert_eq!(ucan_cid, "ucan-1");
                assert_eq!(would_be, 101);
                assert_eq!(cap, 100);
            }
            other => panic!("unexpected error: {:?}", other),
        }

        let counters = store.load_counters("ctx", "ucan-1").await.unwrap().unwrap();
        assert_eq!(counters.amount_cumulative_used, 100);
    }

    #[tokio::test]
    async fn amount_cumulative_admits_exact_cap() {
        let store = make_store();

        store
            .check_and_increment("ctx", "ucan-1", CaveatKind::AmountCumulative, 100, 100, 0)
            .await
            .unwrap();

        // Exactly at cap; one more unit must reject.
        let err = store
            .check_and_increment("ctx", "ucan-1", CaveatKind::AmountCumulative, 1, 100, 0)
            .await
            .expect_err("one more must reject");
        assert_eq!(err.kind_if_exhausted(), Some(CaveatKind::AmountCumulative));
    }

    // -----------------------------------------------------------------------
    // rate_window happy path + sliding behaviour
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn rate_window_admits_until_cap_then_rejects() {
        let clock = Arc::new(TestClock::new(1000));
        let store = make_store_with_clock(clock.clone());

        for _ in 0..3 {
            store
                .check_and_increment("ctx", "ucan-1", CaveatKind::RateWindow, 0, 3, 60)
                .await
                .unwrap();
        }

        let err = store
            .check_and_increment("ctx", "ucan-1", CaveatKind::RateWindow, 0, 3, 60)
            .await
            .expect_err("4th invocation in window must reject");

        match err {
            CounterError::Exhausted(CounterExhausted::RateWindow {
                ucan_cid,
                in_window,
                cap,
                window_secs,
            }) => {
                assert_eq!(ucan_cid, "ucan-1");
                assert_eq!(in_window, 3);
                assert_eq!(cap, 3);
                assert_eq!(window_secs, 60);
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[tokio::test]
    async fn rate_window_old_entries_age_out_via_clock_advance() {
        let clock = Arc::new(TestClock::new(1000));
        let store = make_store_with_clock(clock.clone());

        // Fill the window: 3 calls at t=1000 with 60s window, cap=3.
        for _ in 0..3 {
            store
                .check_and_increment("ctx", "ucan-1", CaveatKind::RateWindow, 0, 3, 60)
                .await
                .unwrap();
        }
        // Window full -> reject.
        store
            .check_and_increment("ctx", "ucan-1", CaveatKind::RateWindow, 0, 3, 60)
            .await
            .unwrap_err();

        // Advance past the window.
        clock.set(1100);
        // Now the original 3 timestamps (all at 1000) are stale (cutoff =
        // 1100 - 60 = 1040; 1000 <= 1040). Two more invocations must succeed.
        store
            .check_and_increment("ctx", "ucan-1", CaveatKind::RateWindow, 0, 3, 60)
            .await
            .unwrap();
        store
            .check_and_increment("ctx", "ucan-1", CaveatKind::RateWindow, 0, 3, 60)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn rate_window_uses_ring_buffer_keyed_by_window_secs() {
        // Two callers with different `window_secs` for the same UCAN should
        // both see the same timestamp ring buffer; the window length only
        // affects the cutoff used during pruning. (Per §7.3.8, narrowing
        // shrinks `window_secs`, so a tighter window's cutoff drops more
        // entries — which is exactly what we want to verify here.)
        let clock = Arc::new(TestClock::new(1000));
        let store = make_store_with_clock(clock.clone());

        // Record 3 events at t=1000 under a 60s window, cap=10.
        for _ in 0..3 {
            store
                .check_and_increment("ctx", "ucan-1", CaveatKind::RateWindow, 0, 10, 60)
                .await
                .unwrap();
        }

        // Advance to t=1010. Under window_secs=5 (cutoff=1005), all three
        // timestamps (at 1000) are stale and pruned -> we can record more.
        clock.set(1010);

        // Cap=2, window=5s, current count=0 (after prune) -> two slots.
        store
            .check_and_increment("ctx", "ucan-1", CaveatKind::RateWindow, 0, 2, 5)
            .await
            .unwrap();
        store
            .check_and_increment("ctx", "ucan-1", CaveatKind::RateWindow, 0, 2, 5)
            .await
            .unwrap();
        store
            .check_and_increment("ctx", "ucan-1", CaveatKind::RateWindow, 0, 2, 5)
            .await
            .unwrap_err();
    }

    // -----------------------------------------------------------------------
    // Atomicity — concurrent invocations under tokio threads
    // -----------------------------------------------------------------------

    /// Concurrent double-increment cannot both succeed when combined > cap.
    ///
    /// Two tasks each increment `amount = 50` against `cap = 50`. Combined
    /// would be 100, which exceeds the cap, so exactly one must succeed and
    /// one must reject.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_double_increment_cannot_both_succeed() {
        let store = Arc::new(make_store());

        let store_a = Arc::clone(&store);
        let store_b = Arc::clone(&store);

        let task_a = tokio::task::spawn_blocking(move || {
            tokio::runtime::Handle::current().block_on(async move {
                store_a
                    .check_and_increment(
                        "ctx",
                        "ucan-race",
                        CaveatKind::AmountCumulative,
                        50,
                        50,
                        0,
                    )
                    .await
            })
        });

        let task_b = tokio::task::spawn_blocking(move || {
            tokio::runtime::Handle::current().block_on(async move {
                store_b
                    .check_and_increment(
                        "ctx",
                        "ucan-race",
                        CaveatKind::AmountCumulative,
                        50,
                        50,
                        0,
                    )
                    .await
            })
        });

        let (a_res, b_res) = tokio::join!(task_a, task_b);
        let a = a_res.unwrap();
        let b = b_res.unwrap();

        let successes = u32::from(a.is_ok()) + u32::from(b.is_ok());
        assert_eq!(
            successes, 1,
            "exactly one concurrent increment must succeed"
        );
        // The persisted counter must reflect exactly one successful charge.
        let counters = store
            .load_counters("ctx", "ucan-race")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(counters.amount_cumulative_used, 50);
    }

    /// 1000-iteration race test required by SCP-OUT-020 AC-6.
    ///
    /// On each iteration, fresh store; two tasks each increment amount=50
    /// against cap=50; assert exactly one succeeds (and the loser sees
    /// CounterExhausted::AmountCumulative). After 1000 iterations, no
    /// double-success has been observed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn race_test_1000_iterations() {
        for i in 0..1000_u32 {
            let store = Arc::new(make_store());

            let store_a = Arc::clone(&store);
            let store_b = Arc::clone(&store);

            let task_a = tokio::task::spawn_blocking(move || {
                tokio::runtime::Handle::current().block_on(async move {
                    store_a
                        .check_and_increment(
                            "ctx",
                            "ucan-race",
                            CaveatKind::AmountCumulative,
                            50,
                            50,
                            0,
                        )
                        .await
                })
            });

            let task_b = tokio::task::spawn_blocking(move || {
                tokio::runtime::Handle::current().block_on(async move {
                    store_b
                        .check_and_increment(
                            "ctx",
                            "ucan-race",
                            CaveatKind::AmountCumulative,
                            50,
                            50,
                            0,
                        )
                        .await
                })
            });

            let (a_res, b_res) = tokio::join!(task_a, task_b);
            let a = a_res.unwrap();
            let b = b_res.unwrap();

            let oks = u32::from(a.is_ok()) + u32::from(b.is_ok());
            assert_eq!(oks, 1, "iteration {i}: expected exactly one success");

            // Verify the loser saw CounterExhausted::AmountCumulative.
            let loser = if a.is_err() { a } else { b };
            match loser.unwrap_err() {
                CounterError::Exhausted(CounterExhausted::AmountCumulative { .. }) => {}
                other => panic!("iteration {i}: loser had unexpected error {other:?}"),
            }
        }
    }

    // -----------------------------------------------------------------------
    // Restart semantics — drop store, reopen on shared backing storage
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn restart_preserves_counters_when_backing_storage_is_shared() {
        // Backing storage shared via Arc — the platform Storage trait has a
        // blanket impl for Arc<T: Storage>, so we can wrap the same
        // InMemoryStorage in two distinct ProtocolRepository instances.
        let storage = Arc::new(InMemoryStorage::new());

        // First lifecycle: create store, increment counters, drop store.
        {
            let repo = make_repo_shared(Arc::clone(&storage));
            let clock: Arc<dyn Clock> = Arc::new(TestClock::new(1000));
            let store = CaveatCounterStore::new(repo, clock);

            store
                .check_and_increment("ctx", "ucan-1", CaveatKind::MaxCalls, 1, 10, 0)
                .await
                .unwrap();
            store
                .check_and_increment("ctx", "ucan-1", CaveatKind::MaxCalls, 1, 10, 0)
                .await
                .unwrap();
            store
                .check_and_increment("ctx", "ucan-1", CaveatKind::AmountCumulative, 250, 1000, 0)
                .await
                .unwrap();
            store
                .check_and_increment("ctx", "ucan-1", CaveatKind::RateWindow, 0, 5, 60)
                .await
                .unwrap();

            let counters = store.load_counters("ctx", "ucan-1").await.unwrap().unwrap();
            assert_eq!(counters.max_calls_used, 2);
            assert_eq!(counters.amount_cumulative_used, 250);
            assert_eq!(counters.rate_window_timestamps, vec![1000]);
            // store and repo go out of scope here.
        }

        // Second lifecycle: a fresh store wraps the same backing storage.
        let repo2 = make_repo_shared(Arc::clone(&storage));
        let clock2: Arc<dyn Clock> = Arc::new(TestClock::new(1010));
        let store2 = CaveatCounterStore::new(repo2, clock2);

        let counters = store2
            .load_counters("ctx", "ucan-1")
            .await
            .unwrap()
            .expect("counter record must survive store reopen");
        assert_eq!(counters.max_calls_used, 2);
        assert_eq!(counters.amount_cumulative_used, 250);
        assert_eq!(counters.rate_window_timestamps, vec![1000]);

        // Subsequent increments compose with persisted state.
        store2
            .check_and_increment("ctx", "ucan-1", CaveatKind::MaxCalls, 1, 10, 0)
            .await
            .unwrap();
        let counters = store2
            .load_counters("ctx", "ucan-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(counters.max_calls_used, 3);
    }

    // -----------------------------------------------------------------------
    // delete_counters — token revocation hygiene
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn delete_counters_clears_persisted_record() {
        let store = make_store();

        store
            .check_and_increment("ctx", "ucan-1", CaveatKind::MaxCalls, 1, 5, 0)
            .await
            .unwrap();
        assert!(
            store
                .load_counters("ctx", "ucan-1")
                .await
                .unwrap()
                .is_some()
        );

        store.delete_counters("ctx", "ucan-1").await.unwrap();
        assert!(
            store
                .load_counters("ctx", "ucan-1")
                .await
                .unwrap()
                .is_none()
        );

        // Subsequent increment starts from default state.
        store
            .check_and_increment("ctx", "ucan-1", CaveatKind::MaxCalls, 1, 5, 0)
            .await
            .unwrap();
        let counters = store.load_counters("ctx", "ucan-1").await.unwrap().unwrap();
        assert_eq!(counters.max_calls_used, 1);
    }

    #[tokio::test]
    async fn delete_counters_is_idempotent() {
        let store = make_store();
        // No record exists; delete must not error.
        store.delete_counters("ctx", "never-seen").await.unwrap();
    }

    // -----------------------------------------------------------------------
    // Helper trait used by tests
    // -----------------------------------------------------------------------

    impl CounterError {
        fn kind_if_exhausted(&self) -> Option<CaveatKind> {
            match self {
                Self::Exhausted(e) => Some(e.kind()),
                Self::Store(_) => None,
            }
        }
    }
}
