//! Subscription map for transport adapters.
//!
//! Unifies the ad-hoc `HashMap<[u8; 32], V>` pattern used across transport
//! adapters (QUIC, `NativeRelayClient`, WebTransport). Distinct from
//! [`relay::SubscriptionRegistry`](crate::relay::subscription::SubscriptionRegistry),
//! which is a 1:N fan-out registry; this one is a 1:1 keyed map.
//!
//! # Closure constraints for [`with`], [`with_mut`], [`for_each`]
//!
//! These methods invoke a caller-supplied closure while holding the inner
//! `RwLock`. To stay safe, the closure must:
//!
//! * Run synchronously to completion. The closure is `FnOnce` / `FnMut`,
//!   never `async`. A closure that calls `block_on` will stall the runtime
//!   worker (and on WASM there is no runtime worker to stall it on).
//! * Avoid acquiring any other lock that participates in a lock ordering
//!   with this map -- otherwise the program may deadlock.
//! * Avoid re-entering the same map (any of [`insert`], [`remove`],
//!   [`with`], etc.) -- otherwise the program will deadlock or, on a
//!   re-entrant write attempt, panic on poison.
//!
//! Keep closures short: clone out anything you need, drop the closure, and
//! do further work on the cloned value.
//!
//! [`with`]: TransportSubscriptionMap::with
//! [`with_mut`]: TransportSubscriptionMap::with_mut
//! [`for_each`]: TransportSubscriptionMap::for_each
//! [`insert`]: TransportSubscriptionMap::insert
//! [`remove`]: TransportSubscriptionMap::remove

use std::collections::HashMap;
use std::sync::RwLock;

use thiserror::Error;

use crate::traits::RoutingId;

/// Maximum concurrent subscriptions tracked per transport adapter.
///
/// Bounds memory growth from pathological producers or programming bugs
/// (e.g., a runaway loop calling `subscribe`). 10,000 is well above the
/// highest realistic SCP transport-adapter participant footprint (a heavy
/// participant typically holds ~hundreds of context subscriptions; the cap
/// leaves >100x headroom). The cap exists to bound memory growth from
/// pathological producers or bugs. Revisit this constant if real participant
/// counts approach 1,000.
///
/// This cap is independent of the server-side relay caps in
/// [`crate::relay::subscription`], which protect relay memory under a
/// different shape (1:N fan-out, total + per-routing-id limits).
///
/// Adapters whose subscription lifecycle requires close-on-unsubscribe with
/// network IO outside the lock (e.g., the WebTransport HTTP/3 bidi-stream
/// path) must enforce this cap inline rather than going through the
/// [`TransportSubscriptionMap`] storage primitive.
pub const MAX_TRANSPORT_SUBSCRIPTIONS: usize = 10_000;

/// Errors returned by [`TransportSubscriptionMap`] mutation methods.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum SubscriptionError {
    /// A subscription is already registered for this routing ID.
    ///
    /// Callers wanting replace semantics should use
    /// [`insert_or_replace`](TransportSubscriptionMap::insert_or_replace)
    /// or call [`remove`](TransportSubscriptionMap::remove) then
    /// [`insert`](TransportSubscriptionMap::insert).
    #[error("subscription already exists for routing id")]
    Duplicate,

    /// The map has reached [`MAX_TRANSPORT_SUBSCRIPTIONS`] entries and cannot
    /// accept another subscription until an existing one is removed.
    #[error("subscription capacity exceeded: max {0}")]
    CapacityExceeded(usize),
}

/// A 1:1 map from SCP routing ID to adapter-specific subscription value.
///
/// Used by transport adapters (QUIC, `NativeRelayClient`, WebTransport) to
/// track active subscriptions. See the [module-level documentation](self) for
/// closure-safety constraints on [`with`](Self::with),
/// [`with_mut`](Self::with_mut), and [`for_each`](Self::for_each).
///
/// All methods recover from lock-poisoning automatically by extracting the
/// inner state via [`std::sync::PoisonError::into_inner`]. They do not panic
/// on poison.
///
/// # Type parameter
///
/// `V` is the adapter's per-subscription value. Typical choices:
///
/// | Adapter | `V` |
/// |---------|-----|
/// | QUIC | cancellation handle for the read-loop task |
/// | `NativeRelayClient` | subscription state + sender channel |
/// | WebTransport (WebSocket fallback) | `mpsc::UnboundedSender<TransportEvent>` |
///
/// # Concurrency
///
/// The map is `Send + Sync` when `V: Send + Sync`. Internal synchronization
/// uses [`std::sync::RwLock`] (rather than `tokio::sync::RwLock`) so the map
/// works on `wasm32` and avoids forcing callers to be `async`.
#[derive(Debug)]
pub struct TransportSubscriptionMap<V> {
    inner: RwLock<HashMap<RoutingId, V>>,
    max: usize,
}

impl<V> Default for TransportSubscriptionMap<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V> TransportSubscriptionMap<V> {
    /// Creates an empty map with the default capacity
    /// [`MAX_TRANSPORT_SUBSCRIPTIONS`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(MAX_TRANSPORT_SUBSCRIPTIONS)
    }

    /// Creates an empty map with the given maximum entry count. For tests
    /// and internal use; zero is legal (rejects every insert) but useless.
    #[must_use]
    pub(crate) fn with_capacity(max: usize) -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            max,
        }
    }

    /// Inserts `value` at `routing_id`.
    ///
    /// # Errors
    ///
    /// Returns [`SubscriptionError::Duplicate`] if an entry already exists
    /// for `routing_id`, or [`SubscriptionError::CapacityExceeded`] if the
    /// map has reached its configured maximum.
    pub fn insert(&self, routing_id: RoutingId, value: V) -> Result<(), SubscriptionError> {
        {
            // Hold the write lock across contains-then-insert to make the
            // check-and-insert atomic.
            let mut guard = self
                .inner
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if guard.contains_key(&routing_id) {
                return Err(SubscriptionError::Duplicate);
            }
            if guard.len() >= self.max {
                return Err(SubscriptionError::CapacityExceeded(self.max));
            }
            guard.insert(routing_id, value);
        }
        Ok(())
    }

    /// Inserts `value` at `routing_id`, replacing any existing entry.
    ///
    /// Returns the previous value if the slot was occupied. Use
    /// [`insert`](Self::insert) instead when duplicate detection is required.
    ///
    /// # Errors
    ///
    /// Returns [`SubscriptionError::CapacityExceeded`] if the map is at its
    /// maximum and the insert would grow it (i.e. the routing ID was not
    /// already present).
    pub fn insert_or_replace(
        &self,
        routing_id: RoutingId,
        value: V,
    ) -> Result<Option<V>, SubscriptionError> {
        let mut guard = self
            .inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let present = guard.contains_key(&routing_id);
        if !present && guard.len() >= self.max {
            return Err(SubscriptionError::CapacityExceeded(self.max));
        }
        Ok(guard.insert(routing_id, value))
    }

    /// Removes and returns the value at `routing_id`, if any.
    pub fn remove(&self, routing_id: &RoutingId) -> Option<V> {
        let mut guard = self
            .inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.remove(routing_id)
    }

    /// Returns `true` if the map contains an entry for `routing_id`.
    #[must_use]
    pub fn contains(&self, routing_id: &RoutingId) -> bool {
        let guard = self
            .inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.contains_key(routing_id)
    }

    /// Returns the count of currently registered subscriptions.
    ///
    /// Useful for callers that want to pre-check capacity before doing
    /// expensive work (e.g. opening a network stream) that would fail at
    /// insert time. The post-insert capacity gate in
    /// [`insert`](Self::insert) and [`insert_or_replace`](Self::insert_or_replace)
    /// remains the authoritative bound; this is a fast-path optimization.
    #[must_use]
    pub fn len(&self) -> usize {
        let guard = self
            .inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.len()
    }

    /// Returns `true` if the map contains no subscriptions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Applies `f` to the value at `routing_id`, if present.
    ///
    /// Acquires a read lock and calls `f` with a shared reference to the
    /// value. Returns `None` if the slot is empty; otherwise returns
    /// `Some(f(&V))`. Used by adapters that need to read a field of `V`
    /// without cloning it. The closure runs while the lock is held; see
    /// [module docs](self) for constraints.
    pub fn with<R>(&self, routing_id: &RoutingId, f: impl FnOnce(&V) -> R) -> Option<R> {
        let guard = self
            .inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.get(routing_id).map(f)
    }

    /// Applies `f` to a mutable reference to the value at `routing_id`,
    /// if present.
    ///
    /// Acquires a write lock and calls `f` with an exclusive reference to
    /// the value. Returns `None` if the slot is empty; otherwise returns
    /// `Some(f(&mut V))`. The closure runs while the lock is held; see
    /// [module docs](self) for constraints.
    pub fn with_mut<R>(&self, routing_id: &RoutingId, f: impl FnOnce(&mut V) -> R) -> Option<R> {
        let mut guard = self
            .inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.get_mut(routing_id).map(f)
    }

    /// Applies `f` to each value in the map.
    ///
    /// Holds a read lock for the duration of iteration. Intended for simple
    /// fan-out operations (e.g. notifying every subscription of a reconnect
    /// event). The closure runs while the lock is held; see
    /// [module docs](self) for constraints.
    pub fn for_each(&self, mut f: impl FnMut(&RoutingId, &V)) {
        let guard = self
            .inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (k, v) in guard.iter() {
            f(k, v);
        }
    }
}

impl<V: Clone> TransportSubscriptionMap<V> {
    /// Returns a snapshot of every `(routing_id, value)` pair.
    ///
    /// Used by adapters during reconnection when both the routing ID and
    /// per-subscription state are needed to re-issue SUBSCRIBE.
    #[must_use]
    pub fn snapshot(&self) -> Vec<(RoutingId, V)> {
        let guard = self
            .inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.iter().map(|(k, v)| (*k, v.clone())).collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn rid(byte: u8) -> RoutingId {
        RoutingId::new([byte; 32])
    }

    #[test]
    fn new_is_empty() {
        let map: TransportSubscriptionMap<u32> = TransportSubscriptionMap::new();
        assert!(map.snapshot().is_empty());
    }

    #[test]
    fn insert_and_contains() {
        let map = TransportSubscriptionMap::<u32>::new();
        assert!(!map.contains(&rid(1)));
        map.insert(rid(1), 42).unwrap();
        assert!(map.contains(&rid(1)));
        assert_eq!(map.snapshot().len(), 1);
    }

    #[test]
    fn insert_duplicate_is_rejected() {
        let map = TransportSubscriptionMap::<u32>::new();
        map.insert(rid(1), 42).unwrap();
        let err = map.insert(rid(1), 99).unwrap_err();
        assert_eq!(err, SubscriptionError::Duplicate);
        // Original value untouched.
        assert_eq!(map.with(&rid(1), |v| *v), Some(42));
    }

    #[test]
    fn insert_or_replace_returns_previous() {
        let map = TransportSubscriptionMap::<u32>::new();
        assert_eq!(map.insert_or_replace(rid(1), 42).unwrap(), None);
        assert_eq!(map.insert_or_replace(rid(1), 99).unwrap(), Some(42));
        assert_eq!(map.with(&rid(1), |v| *v), Some(99));
    }

    #[test]
    fn insert_or_replace_respects_capacity() {
        let map = TransportSubscriptionMap::<u32>::with_capacity(2);
        map.insert_or_replace(rid(1), 1).unwrap();
        map.insert_or_replace(rid(2), 2).unwrap();
        // Replacing an existing key never grows the map.
        assert!(map.insert_or_replace(rid(1), 11).is_ok());
        // New key at capacity fails.
        let err = map.insert_or_replace(rid(3), 3).unwrap_err();
        assert_eq!(err, SubscriptionError::CapacityExceeded(2));
    }

    #[test]
    fn remove_returns_value() {
        let map = TransportSubscriptionMap::<u32>::new();
        map.insert(rid(1), 42).unwrap();
        assert_eq!(map.remove(&rid(1)), Some(42));
        assert_eq!(map.remove(&rid(1)), None);
        assert!(map.snapshot().is_empty());
    }

    #[test]
    fn capacity_limit_blocks_inserts() {
        let map = TransportSubscriptionMap::<u32>::with_capacity(2);
        map.insert(rid(1), 1).unwrap();
        map.insert(rid(2), 2).unwrap();
        let err = map.insert(rid(3), 3).unwrap_err();
        assert_eq!(err, SubscriptionError::CapacityExceeded(2));
        assert_eq!(map.snapshot().len(), 2);
    }

    #[test]
    fn capacity_limit_recovers_after_remove() {
        let map = TransportSubscriptionMap::<u32>::with_capacity(1);
        map.insert(rid(1), 1).unwrap();
        assert!(map.insert(rid(2), 2).is_err());
        map.remove(&rid(1));
        map.insert(rid(2), 2).unwrap();
    }

    #[test]
    fn zero_capacity_rejects_every_insert() {
        let map = TransportSubscriptionMap::<u32>::with_capacity(0);
        let err = map.insert(rid(1), 1).unwrap_err();
        assert_eq!(err, SubscriptionError::CapacityExceeded(0));
    }

    #[test]
    fn snapshot_contains_inserted_keys() {
        let map = TransportSubscriptionMap::<u32>::new();
        map.insert(rid(1), 1).unwrap();
        map.insert(rid(2), 2).unwrap();
        let mut ids: Vec<RoutingId> = map.snapshot().into_iter().map(|(k, _)| k).collect();
        ids.sort_by_key(|id| id.as_bytes()[0]);
        assert_eq!(ids, vec![rid(1), rid(2)]);
    }

    #[test]
    fn with_returns_none_when_absent() {
        let map = TransportSubscriptionMap::<u32>::new();
        assert!(map.with(&rid(1), |_| ()).is_none());
    }

    #[test]
    fn with_mut_mutates_in_place() {
        let map = TransportSubscriptionMap::<u32>::new();
        map.insert(rid(1), 10).unwrap();
        map.with_mut(&rid(1), |v| *v += 5).unwrap();
        assert_eq!(map.with(&rid(1), |v| *v), Some(15));
    }

    #[test]
    fn for_each_visits_every_entry() {
        let map = TransportSubscriptionMap::<u32>::new();
        map.insert(rid(1), 1).unwrap();
        map.insert(rid(2), 2).unwrap();
        map.insert(rid(3), 3).unwrap();
        let seen = AtomicUsize::new(0);
        map.for_each(|_, v| {
            seen.fetch_add(*v as usize, Ordering::Relaxed);
        });
        assert_eq!(seen.load(Ordering::Relaxed), 6);
    }

    #[test]
    fn snapshot_returns_all_pairs() {
        let map = TransportSubscriptionMap::<u32>::new();
        map.insert(rid(1), 10).unwrap();
        map.insert(rid(2), 20).unwrap();
        let mut pairs = map.snapshot();
        pairs.sort_by_key(|(k, _)| k.as_bytes()[0]);
        assert_eq!(pairs, vec![(rid(1), 10), (rid(2), 20)]);
        // Original still present.
        assert_eq!(map.snapshot().len(), 2);
    }

    #[test]
    fn concurrent_inserts_and_removes_do_not_deadlock() {
        // Smoke test: disjoint thread keyspaces ensure no insert/remove ever
        // contends on the same routing ID. Verifies the lock plumbing alone.
        let map = Arc::new(TransportSubscriptionMap::<u64>::new());
        let mut handles = Vec::new();
        for thread_idx in 0..8u8 {
            let map = Arc::clone(&map);
            handles.push(std::thread::spawn(move || {
                for i in 0..100u8 {
                    let mut id = [0u8; 32];
                    id[0] = thread_idx;
                    id[1] = i;
                    let _ = map.insert(
                        RoutingId::new(id),
                        u64::from(thread_idx) * 1000 + u64::from(i),
                    );
                }
                for i in 0..100u8 {
                    let mut id = [0u8; 32];
                    id[0] = thread_idx;
                    id[1] = i;
                    let _ = map.remove(&RoutingId::new(id));
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert!(map.snapshot().is_empty());
    }

    #[test]
    fn concurrent_inserts_and_removes_preserve_invariants() {
        // Stress test: 4 threads each cycle through the SAME 16 routing IDs
        // with random insert / insert_or_replace / remove operations. After
        // joining we verify (a) no entry is torn (every present value is one
        // we wrote), (b) `snapshot().len()` is at most 16, and (c)
        // `insert_or_replace` against a present key never trips the capacity
        // bound (capacity is bounded but greater than the keyspace).
        const KEYSPACE: u8 = 16;
        const THREADS: usize = 4;
        const ITERATIONS: usize = 500;

        // Capacity > keyspace so resize-by-replace never hits the cap.
        let map = Arc::new(TransportSubscriptionMap::<u64>::with_capacity(
            usize::from(KEYSPACE) + 4,
        ));
        let cap_violations = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for thread_idx in 0..THREADS {
            let map = Arc::clone(&map);
            let cap_violations = Arc::clone(&cap_violations);
            handles.push(std::thread::spawn(move || {
                // Cheap thread-distinct xorshift64* sequence.
                let mut state: u64 = (thread_idx as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
                for iter in 0..ITERATIONS {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;

                    // Low bits drive the key, high bits the op; sharing
                    // bits would pin each key to a single operation.
                    let key_byte =
                        u8::try_from(state % u64::from(KEYSPACE)).expect("modulo fits in u8");
                    let mut id = [0u8; 32];
                    id[0] = key_byte;
                    let rid = RoutingId::new(id);
                    let value = (thread_idx as u64) << 32 | iter as u64;

                    match (state >> 32) & 0x3 {
                        0 => {
                            // insert: may legitimately error with Duplicate.
                            let _ = map.insert(rid, value);
                        }
                        1 => {
                            // insert_or_replace: against any key, must not
                            // trip CapacityExceeded with cap > keyspace.
                            if let Err(SubscriptionError::CapacityExceeded(_)) =
                                map.insert_or_replace(rid, value)
                            {
                                cap_violations.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        2 => {
                            let _ = map.remove(&rid);
                        }
                        _ => {
                            let _ = map.contains(&rid);
                        }
                    }
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(
            cap_violations.load(Ordering::Relaxed),
            0,
            "insert_or_replace must never report CapacityExceeded when capacity > keyspace"
        );

        // Final state is some valid subset of the keyspace -- no orphan or
        // torn entries. Verify (a) keys live in the configured keyspace, and
        // (b) every present value decodes back to a `(thread_idx, iter)` pair
        // we actually wrote, with no torn or interleaved high/low halves.
        let entries: Vec<(RoutingId, u64)> = map.snapshot();
        assert!(entries.len() <= usize::from(KEYSPACE));
        for (id, value) in &entries {
            assert!(id.as_bytes()[0] < KEYSPACE);
            let thread_idx = (value >> 32) as usize;
            let iter = (value & 0xFFFF_FFFF) as usize;
            assert!(
                thread_idx < THREADS,
                "torn entry: thread_idx {thread_idx} out of range"
            );
            assert!(iter < ITERATIONS, "torn entry: iter {iter} out of range");
        }
    }

    #[test]
    fn concurrent_readers_do_not_block_each_other() {
        // Smoke test: many readers run concurrently without deadlock.
        let map = Arc::new(TransportSubscriptionMap::<u32>::new());
        for i in 0..10u8 {
            let mut id = [0u8; 32];
            id[0] = i;
            map.insert(RoutingId::new(id), u32::from(i)).unwrap();
        }

        let mut handles = Vec::new();
        for _ in 0..8 {
            let map = Arc::clone(&map);
            handles.push(std::thread::spawn(move || {
                for _ in 0..100 {
                    let _ = map.snapshot();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(map.snapshot().len(), 10);
    }
}
