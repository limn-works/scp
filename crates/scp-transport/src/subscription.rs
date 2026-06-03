//! Client-side subscription map for transport adapters.
//!
//! Unifies the ad-hoc `HashMap<[u8; 32], V>` pattern used across transport
//! adapters (QUIC, `NativeRelayClient`, WebTransport). Each client adapter has at
//! most one subscription per routing ID (1:1), unlike the server-side
//! [`relay::subscription`](crate::relay::subscription) registry which is a
//! fan-out (1-to-N) delivery map from a routing ID to multiple subscribers.
//!
//! # When to use
//!
//! Use [`ClientSubscriptionMap`] in client-side transport adapters to track
//! subscription state keyed by [`crate::traits::RoutingId`]. The value type is
//! adapter-specific (e.g. a cancellation token, a channel sender, or a richer
//! state struct).
//!
//! # Why not reuse the server-side registry?
//!
//! The server-side [`SubscriptionRegistry`](crate::relay::subscription::SubscriptionRegistry)
//! is a fan-out map (`HashMap<[u8; 32], Vec<SubscriberEntry>>`) delivering
//! blobs to every subscriber on a routing ID. A client has exactly one
//! subscription per routing ID -- the two shapes are different. Unifying them
//! would introduce fan-out machinery the client never uses.
//!
//! # Lock choice
//!
//! Uses [`std::sync::RwLock`] rather than `tokio::sync::RwLock` because:
//!
//! * Operations are fast [`HashMap`] reads/writes -- no `await` points.
//! * `std::sync::RwLock` is available on `wasm32`, where
//!   [`WebTransportAdapter`](crate::webtransport::client::WebTransportAdapter)
//!   runs.
//! * It avoids forcing every caller to be `async` just to look up a
//!   subscription.

use std::collections::HashMap;
use std::sync::RwLock;

use thiserror::Error;

/// Maximum concurrent subscriptions tracked per client adapter.
///
/// Mirrors the server-side SEC-006 per-routing-ID cap but applied at the
/// client. Ten thousand entries is far beyond any realistic SCP client (a
/// heavy participant might be in hundreds of contexts at once) while still
/// bounding memory growth from pathological producers or bugs.
pub const MAX_CLIENT_SUBSCRIPTIONS: usize = 10_000;

/// Errors returned by [`ClientSubscriptionMap`] mutation methods.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum SubscriptionError {
    /// A subscription is already registered for this routing ID.
    ///
    /// Callers that want "replace" semantics should [`remove`] the existing
    /// entry first (and tear it down as appropriate for the adapter), then
    /// [`insert`] the new value.
    ///
    /// [`remove`]: ClientSubscriptionMap::remove
    /// [`insert`]: ClientSubscriptionMap::insert
    #[error("subscription already exists for routing id")]
    Duplicate,

    /// The map has reached [`MAX_CLIENT_SUBSCRIPTIONS`] entries and cannot
    /// accept another subscription until an existing one is removed.
    #[error("subscription capacity exceeded: {0}/{0}", )]
    CapacityExceeded(usize),
}

/// A 1:1 map from SCP routing ID to adapter-specific subscription value.
///
/// Used by client-side transport adapters (QUIC, `NativeRelayClient`,
/// WebTransport) to track active subscriptions. See the [module-level
/// documentation](self) for the design rationale.
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
/// uses [`std::sync::RwLock`] for the reasons described in the module docs.
#[derive(Debug)]
pub struct ClientSubscriptionMap<V> {
    inner: RwLock<HashMap<[u8; 32], V>>,
    max: usize,
}

impl<V> Default for ClientSubscriptionMap<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V> ClientSubscriptionMap<V> {
    /// Creates an empty map with the default capacity
    /// [`MAX_CLIENT_SUBSCRIPTIONS`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(MAX_CLIENT_SUBSCRIPTIONS)
    }

    /// Creates an empty map with the given maximum entry count.
    ///
    /// The cap is a defense against buggy or malicious producers; a value of
    /// zero is legal (rejects every insert) though not useful.
    #[must_use]
    pub fn with_capacity(max: usize) -> Self {
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
    ///
    /// # Panics
    ///
    /// Panics only if the inner lock is poisoned, which would require a
    /// previous panic while holding the lock -- a bug rather than a
    /// recoverable condition.
    pub fn insert(&self, routing_id: [u8; 32], value: V) -> Result<(), SubscriptionError> {
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
    ///
    /// # Panics
    ///
    /// Panics only if the inner lock is poisoned (see [`insert`](Self::insert)).
    pub fn insert_or_replace(
        &self,
        routing_id: [u8; 32],
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
    ///
    /// # Panics
    ///
    /// Panics only if the inner lock is poisoned.
    pub fn remove(&self, routing_id: &[u8; 32]) -> Option<V> {
        let mut guard = self
            .inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.remove(routing_id)
    }

    /// Returns `true` if the map contains an entry for `routing_id`.
    ///
    /// # Panics
    ///
    /// Panics only if the inner lock is poisoned.
    #[must_use]
    pub fn contains(&self, routing_id: &[u8; 32]) -> bool {
        let guard = self
            .inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.contains_key(routing_id)
    }

    /// Returns the number of active subscriptions.
    ///
    /// # Panics
    ///
    /// Panics only if the inner lock is poisoned.
    #[must_use]
    pub fn len(&self) -> usize {
        let guard = self
            .inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.len()
    }

    /// Returns `true` if the map is empty.
    ///
    /// # Panics
    ///
    /// Panics only if the inner lock is poisoned.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns a snapshot of all active routing IDs.
    ///
    /// Used by adapters during reconnection to re-issue SUBSCRIBE for each
    /// tracked routing ID.
    ///
    /// # Panics
    ///
    /// Panics only if the inner lock is poisoned.
    #[must_use]
    pub fn routing_ids(&self) -> Vec<[u8; 32]> {
        let guard = self
            .inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.keys().copied().collect()
    }

    /// Removes every entry and returns the removed `(routing_id, value)`
    /// pairs.
    ///
    /// Used by adapters at shutdown to tear down every subscription in one
    /// pass (e.g. cancelling every read loop).
    ///
    /// # Panics
    ///
    /// Panics only if the inner lock is poisoned.
    pub fn clear(&self) -> Vec<([u8; 32], V)> {
        let mut guard = self
            .inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.drain().collect()
    }

    /// Applies `f` to the value at `routing_id`, if present.
    ///
    /// Acquires a read lock and calls `f` with a shared reference to the
    /// value. Returns `None` if the slot is empty; otherwise returns
    /// `Some(f(&V))`. Used by adapters that need to read a field of `V`
    /// without cloning it.
    ///
    /// # Panics
    ///
    /// Panics only if the inner lock is poisoned.
    pub fn with<R>(&self, routing_id: &[u8; 32], f: impl FnOnce(&V) -> R) -> Option<R> {
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
    /// `Some(f(&mut V))`.
    ///
    /// # Panics
    ///
    /// Panics only if the inner lock is poisoned.
    pub fn with_mut<R>(&self, routing_id: &[u8; 32], f: impl FnOnce(&mut V) -> R) -> Option<R> {
        let mut guard = self
            .inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.get_mut(routing_id).map(f)
    }

    /// Applies `f` to each value in the map.
    ///
    /// Holds a read lock for the duration; `f` must not call back into this
    /// map. Intended for simple fan-out operations (e.g. notifying every
    /// subscription of a reconnect event).
    ///
    /// # Panics
    ///
    /// Panics only if the inner lock is poisoned.
    pub fn for_each(&self, mut f: impl FnMut(&[u8; 32], &V)) {
        let guard = self
            .inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (k, v) in guard.iter() {
            f(k, v);
        }
    }
}

impl<V: Clone> ClientSubscriptionMap<V> {
    /// Returns a clone of the value at `routing_id`, if present.
    ///
    /// Convenience for cases where `V: Clone` (e.g. a sender handle) and
    /// the caller wants to drop the lock before using the value.
    ///
    /// # Panics
    ///
    /// Panics only if the inner lock is poisoned.
    #[must_use]
    pub fn get_cloned(&self, routing_id: &[u8; 32]) -> Option<V> {
        let guard = self
            .inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.get(routing_id).cloned()
    }

    /// Returns a snapshot of every `(routing_id, value)` pair.
    ///
    /// Used by adapters during reconnection when both the routing ID and
    /// per-subscription state are needed to re-issue SUBSCRIBE.
    ///
    /// # Panics
    ///
    /// Panics only if the inner lock is poisoned.
    #[must_use]
    pub fn snapshot(&self) -> Vec<([u8; 32], V)> {
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

    fn rid(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn new_is_empty() {
        let map: ClientSubscriptionMap<u32> = ClientSubscriptionMap::new();
        assert!(map.is_empty());
        assert_eq!(map.len(), 0);
        assert!(map.routing_ids().is_empty());
    }

    #[test]
    fn default_matches_new() {
        let a: ClientSubscriptionMap<u32> = ClientSubscriptionMap::default();
        assert!(a.is_empty());
    }

    #[test]
    fn insert_and_contains() {
        let map = ClientSubscriptionMap::<u32>::new();
        assert!(!map.contains(&rid(1)));
        map.insert(rid(1), 42).unwrap();
        assert!(map.contains(&rid(1)));
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn insert_duplicate_is_rejected() {
        let map = ClientSubscriptionMap::<u32>::new();
        map.insert(rid(1), 42).unwrap();
        let err = map.insert(rid(1), 99).unwrap_err();
        assert_eq!(err, SubscriptionError::Duplicate);
        // Original value untouched.
        assert_eq!(map.with(&rid(1), |v| *v), Some(42));
    }

    #[test]
    fn insert_or_replace_returns_previous() {
        let map = ClientSubscriptionMap::<u32>::new();
        assert_eq!(map.insert_or_replace(rid(1), 42).unwrap(), None);
        assert_eq!(map.insert_or_replace(rid(1), 99).unwrap(), Some(42));
        assert_eq!(map.with(&rid(1), |v| *v), Some(99));
    }

    #[test]
    fn insert_or_replace_respects_capacity() {
        let map = ClientSubscriptionMap::<u32>::with_capacity(2);
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
        let map = ClientSubscriptionMap::<u32>::new();
        map.insert(rid(1), 42).unwrap();
        assert_eq!(map.remove(&rid(1)), Some(42));
        assert_eq!(map.remove(&rid(1)), None);
        assert!(map.is_empty());
    }

    #[test]
    fn capacity_limit_blocks_inserts() {
        let map = ClientSubscriptionMap::<u32>::with_capacity(2);
        map.insert(rid(1), 1).unwrap();
        map.insert(rid(2), 2).unwrap();
        let err = map.insert(rid(3), 3).unwrap_err();
        assert_eq!(err, SubscriptionError::CapacityExceeded(2));
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn capacity_limit_recovers_after_remove() {
        let map = ClientSubscriptionMap::<u32>::with_capacity(1);
        map.insert(rid(1), 1).unwrap();
        assert!(map.insert(rid(2), 2).is_err());
        map.remove(&rid(1));
        map.insert(rid(2), 2).unwrap();
    }

    #[test]
    fn zero_capacity_rejects_every_insert() {
        let map = ClientSubscriptionMap::<u32>::with_capacity(0);
        let err = map.insert(rid(1), 1).unwrap_err();
        assert_eq!(err, SubscriptionError::CapacityExceeded(0));
    }

    #[test]
    fn clear_returns_all_entries() {
        let map = ClientSubscriptionMap::<u32>::new();
        map.insert(rid(1), 10).unwrap();
        map.insert(rid(2), 20).unwrap();
        let mut drained = map.clear();
        drained.sort_by_key(|(k, _)| k[0]);
        assert_eq!(drained, vec![(rid(1), 10), (rid(2), 20)]);
        assert!(map.is_empty());
    }

    #[test]
    fn routing_ids_snapshot() {
        let map = ClientSubscriptionMap::<u32>::new();
        map.insert(rid(1), 1).unwrap();
        map.insert(rid(2), 2).unwrap();
        let mut ids = map.routing_ids();
        ids.sort_by_key(|id| id[0]);
        assert_eq!(ids, vec![rid(1), rid(2)]);
    }

    #[test]
    fn with_returns_none_when_absent() {
        let map = ClientSubscriptionMap::<u32>::new();
        assert!(map.with(&rid(1), |_| ()).is_none());
    }

    #[test]
    fn with_mut_mutates_in_place() {
        let map = ClientSubscriptionMap::<u32>::new();
        map.insert(rid(1), 10).unwrap();
        map.with_mut(&rid(1), |v| *v += 5).unwrap();
        assert_eq!(map.with(&rid(1), |v| *v), Some(15));
    }

    #[test]
    fn for_each_visits_every_entry() {
        let map = ClientSubscriptionMap::<u32>::new();
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
    fn get_cloned_returns_copy() {
        let map = ClientSubscriptionMap::<String>::new();
        map.insert(rid(1), "hello".to_string()).unwrap();
        let v = map.get_cloned(&rid(1)).unwrap();
        assert_eq!(v, "hello");
        // Original still present.
        assert!(map.contains(&rid(1)));
    }

    #[test]
    fn snapshot_returns_all_pairs() {
        let map = ClientSubscriptionMap::<u32>::new();
        map.insert(rid(1), 10).unwrap();
        map.insert(rid(2), 20).unwrap();
        let mut pairs = map.snapshot();
        pairs.sort_by_key(|(k, _)| k[0]);
        assert_eq!(pairs, vec![(rid(1), 10), (rid(2), 20)]);
        // Original still present.
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn concurrent_inserts_and_removes_preserve_invariants() {
        let map = Arc::new(ClientSubscriptionMap::<u64>::new());
        let mut handles = Vec::new();
        for thread_idx in 0..8u8 {
            let map = Arc::clone(&map);
            handles.push(std::thread::spawn(move || {
                for i in 0..100u8 {
                    let mut id = [0u8; 32];
                    id[0] = thread_idx;
                    id[1] = i;
                    // Ignore duplicate errors (they can't happen here since
                    // each (thread_idx, i) is unique) but don't unwrap in
                    // case of pathological scheduling.
                    let _ = map.insert(id, u64::from(thread_idx) * 1000 + u64::from(i));
                }
                for i in 0..100u8 {
                    let mut id = [0u8; 32];
                    id[0] = thread_idx;
                    id[1] = i;
                    let _ = map.remove(&id);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(map.len(), 0);
    }

    #[test]
    fn concurrent_readers_do_not_block_each_other() {
        // Smoke test: many readers run concurrently without deadlock.
        let map = Arc::new(ClientSubscriptionMap::<u32>::new());
        for i in 0..10u8 {
            let mut id = [0u8; 32];
            id[0] = i;
            map.insert(id, u32::from(i)).unwrap();
        }

        let mut handles = Vec::new();
        for _ in 0..8 {
            let map = Arc::clone(&map);
            handles.push(std::thread::spawn(move || {
                for _ in 0..100 {
                    let _ = map.len();
                    let _ = map.routing_ids();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(map.len(), 10);
    }
}
