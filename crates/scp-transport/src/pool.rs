//! Connection pool keyed by (relay URL, transport type).
//!
//! [`ConnectionPool`] ensures at most one [`TransportAdapter`] connection per
//! relay per transport type. [`TransportManager`] uses the pool for adapter
//! lookup and reuse instead of creating new connections directly.
//! Cross-[`TransportManager`] sharing is supported via `Arc<ConnectionPool>`.
//!
//! # Architecture
//!
//! The pool is keyed by a `(relay_url, transport_type)` tuple represented as
//! [`PoolKey`]. When a caller requests a connection, the pool either returns
//! the existing adapter for that key or invokes a caller-provided factory to
//! create a new one. The factory pattern keeps the pool transport-agnostic --
//! it does not know how to construct specific adapter types.
//!
//! # Thread Safety
//!
//! The pool uses interior mutability via `RwLock` so that lookups are
//! concurrent reads and insertions are exclusive writes. All operations
//! take `&self`, enabling the pool to be wrapped in `Arc` for sharing.
//!
//! # Spec References
//!
//! - §10.13.2 Connection Pooling (`.docs/specs/10-infrastructure-and-self-hosting.md`)
//! - ADR-036 (`.docs/adrs/phase-2.md`)
//!
//! See SCP-253 in `.docs/prds/transport-expansion.json`.
//!
//! [`TransportAdapter`]: crate::traits::TransportAdapter
//! [`TransportManager`]: crate::manager::TransportManager

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, RwLock};

use crate::error::TransportError;
use crate::traits::TransportAdapter;

// ---------------------------------------------------------------------------
// TransportType
// ---------------------------------------------------------------------------

/// Transport type discriminant for the connection pool key.
///
/// Each variant represents a distinct transport binding. The pool maintains
/// at most one connection per `(relay_url, TransportType)` pair, so a single
/// relay can have one WebSocket connection AND one QUIC connection
/// simultaneously (different transport types to the same endpoint).
///
/// # Variants
///
/// - `NativeWebSocket` -- SCP native relay over WebSocket (ADR-004).
/// - `Quic` -- SCP native relay over QUIC (§10.14).
/// - `WebTransport` -- SCP native relay over WebTransport (§10.15).
/// - `UdpDtls` -- Constrained-device transport over UDP/DTLS (§10.16).
/// - `CoAP` -- Constrained-device transport over CoAP/DTLS (§10.16.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportType {
    /// SCP native relay over WebSocket (ADR-004).
    NativeWebSocket,
    /// SCP native relay over QUIC (§10.14).
    Quic,
    /// SCP native relay over WebTransport (§10.15).
    WebTransport,
    /// Constrained-device transport over UDP/DTLS (§10.16).
    UdpDtls,
    /// Constrained-device transport over CoAP/DTLS (§10.16.2).
    CoAP,
}

impl fmt::Display for TransportType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NativeWebSocket => write!(f, "native-websocket"),
            Self::Quic => write!(f, "quic"),
            Self::WebTransport => write!(f, "webtransport"),
            Self::UdpDtls => write!(f, "udp-dtls"),
            Self::CoAP => write!(f, "coap"),
        }
    }
}

// ---------------------------------------------------------------------------
// PoolKey
// ---------------------------------------------------------------------------

/// Composite key for the connection pool: `(relay_url, transport_type)`.
///
/// Two keys are equal if and only if both the relay URL string and the
/// transport type match exactly. URL normalization (e.g., trailing slash
/// stripping) is the caller's responsibility -- the pool stores keys as-is.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PoolKey {
    /// The relay URL (e.g., `wss://relay.example.com/scp/v1`).
    pub relay_url: String,
    /// The transport type.
    pub transport_type: TransportType,
}

impl PoolKey {
    /// Creates a new pool key.
    #[must_use]
    pub const fn new(relay_url: String, transport_type: TransportType) -> Self {
        Self {
            relay_url,
            transport_type,
        }
    }
}

impl fmt::Display for PoolKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({}, {})", self.relay_url, self.transport_type)
    }
}

// ---------------------------------------------------------------------------
// ConnectionPool
// ---------------------------------------------------------------------------

/// Connection pool keyed by `(relay_url, transport_type)`.
///
/// Ensures at most one [`TransportAdapter`] connection per relay per transport
/// type. All methods take `&self` (interior mutability via `RwLock`), so the
/// pool can be shared across multiple [`TransportManager`] instances via
/// `Arc<ConnectionPool>`.
///
/// # Per-Relay Deduplication (§10.13.2 item 1)
///
/// The pool maintains at most one connection per relay URL per transport type.
/// When a caller requests a connection for a key that already exists, the
/// existing adapter is returned without creating a new connection.
///
/// # Reuse on Assignment (§10.13.2 item 2)
///
/// When a context is assigned a relay that already has an active connection,
/// it reuses the existing adapter from the pool -- no new connection is opened.
///
/// # Cross-Manager Sharing (§10.13.2 item 3)
///
/// Wrap the pool in `Arc<ConnectionPool>` and pass clones to multiple
/// `TransportManager` instances. All managers share the same connection
/// entries.
///
/// [`TransportAdapter`]: crate::traits::TransportAdapter
/// [`TransportManager`]: crate::manager::TransportManager
pub struct ConnectionPool {
    /// The connection entries keyed by `(relay_url, transport_type)`.
    ///
    /// Each entry holds an `Arc<Box<dyn TransportAdapter>>` so that multiple
    /// callers (managers, contexts) can hold references to the same adapter
    /// without ownership conflicts.
    entries: RwLock<HashMap<PoolKey, Arc<Box<dyn TransportAdapter>>>>,
}

impl fmt::Debug for ConnectionPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let count = self.entries.read().map(|e| e.len()).unwrap_or(0);
        f.debug_struct("ConnectionPool")
            .field("entries", &count)
            .finish()
    }
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionPool {
    /// Creates an empty connection pool.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
        }
    }

    /// Returns the adapter for the given key, if one exists.
    ///
    /// This is a read-only lookup that does not create a connection.
    #[must_use]
    pub fn get(&self, key: &PoolKey) -> Option<Arc<Box<dyn TransportAdapter>>> {
        self.entries
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(key)
            .cloned()
    }

    /// Returns the adapter for the given key if one exists, or inserts the
    /// provided adapter and returns it.
    ///
    /// This ensures at most one connection per key: the first caller's
    /// adapter is stored, and all subsequent callers for the same key
    /// receive the same adapter.
    ///
    /// # Arguments
    ///
    /// * `key` -- The `(relay_url, transport_type)` pair.
    /// * `adapter` -- The adapter to insert if the key is not present.
    ///
    /// # Returns
    ///
    /// A shared reference to the adapter (either existing or newly inserted).
    pub fn get_or_insert(
        &self,
        key: PoolKey,
        adapter: Box<dyn TransportAdapter>,
    ) -> Arc<Box<dyn TransportAdapter>> {
        // Fast path: check if the key already exists (read lock).
        if let Some(existing) = self.get(&key) {
            return existing;
        }

        // Slow path: acquire write lock and re-check (double-checked locking).
        let mut entries = self
            .entries
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // Re-check after acquiring write lock -- another thread may have
        // inserted between the read and write lock acquisitions.
        if let Some(existing) = entries.get(&key) {
            return Arc::clone(existing);
        }

        let arc_adapter = Arc::new(adapter);
        entries.insert(key, Arc::clone(&arc_adapter));
        arc_adapter
    }

    /// Returns the adapter for the given key if one exists, or calls the
    /// factory to create and insert a new one.
    ///
    /// Unlike [`get_or_insert`](Self::get_or_insert), this defers adapter
    /// construction until it's known that no existing connection exists —
    /// avoiding wasted work (and potentially wasted network connections)
    /// when the key is already present.
    ///
    /// # Errors
    ///
    /// Propagates any error returned by the factory closure.
    pub fn get_or_try_insert_with<F>(
        &self,
        key: PoolKey,
        factory: F,
    ) -> Result<Arc<Box<dyn TransportAdapter>>, TransportError>
    where
        F: FnOnce() -> Result<Box<dyn TransportAdapter>, TransportError>,
    {
        // Fast path: check if the key already exists (read lock).
        if let Some(existing) = self.get(&key) {
            return Ok(existing);
        }

        // Slow path: acquire write lock and re-check (double-checked locking).
        let mut entries = self
            .entries
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // Re-check after acquiring write lock -- another thread may have
        // inserted between the read and write lock acquisitions.
        if let Some(existing) = entries.get(&key) {
            return Ok(Arc::clone(existing));
        }

        let adapter = factory()?;
        let arc_adapter = Arc::new(adapter);
        entries.insert(key, Arc::clone(&arc_adapter));
        drop(entries);
        Ok(arc_adapter)
    }

    /// Inserts an adapter for the given key, replacing any existing entry.
    ///
    /// Returns the previously stored adapter if one existed.
    pub fn insert(
        &self,
        key: PoolKey,
        adapter: Box<dyn TransportAdapter>,
    ) -> Option<Arc<Box<dyn TransportAdapter>>> {
        let mut entries = self
            .entries
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        entries.insert(key, Arc::new(adapter))
    }

    /// Removes the adapter for the given key.
    ///
    /// Returns the removed adapter if one existed.
    pub fn remove(&self, key: &PoolKey) -> Option<Arc<Box<dyn TransportAdapter>>> {
        let mut entries = self
            .entries
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        entries.remove(key)
    }

    /// Returns the number of active connections in the pool.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// Returns `true` if the pool contains no connections.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns `true` if the pool contains an adapter for the given key.
    #[must_use]
    pub fn contains_key(&self, key: &PoolKey) -> bool {
        self.entries
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains_key(key)
    }

    /// Returns all keys currently in the pool.
    #[must_use]
    pub fn keys(&self) -> Vec<PoolKey> {
        self.entries
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .keys()
            .cloned()
            .collect()
    }

    /// Removes all entries from the pool.
    pub fn clear(&self) {
        let mut entries = self
            .entries
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        entries.clear();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::pin::Pin;
    use std::sync::Arc;

    use futures::stream;
    use scp_core::envelope::OuterEnvelope;

    use super::*;
    use crate::error::TransportError;
    use crate::traits::{BlobId, RoutingId, SubscriptionStream, TransportAdapter};

    /// A boxed, pinned, `Send`-safe future.
    type BoxFuture<'a, T> = Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

    /// A minimal mock adapter for pool tests.
    struct MockPoolAdapter;

    impl MockPoolAdapter {
        fn new(_tag: &str) -> Self {
            Self
        }
    }

    impl TransportAdapter for MockPoolAdapter {
        fn send(&self, _envelope: &OuterEnvelope) -> BoxFuture<'_, Result<BlobId, TransportError>> {
            Box::pin(async { Ok(BlobId::new([0xAA; 32])) })
        }

        fn subscribe(
            &self,
            _routing_id: &RoutingId,
            _since: Option<u64>,
        ) -> BoxFuture<'_, Result<SubscriptionStream, TransportError>> {
            Box::pin(async {
                let s: SubscriptionStream = Box::pin(stream::empty());
                Ok(s)
            })
        }

        fn unsubscribe(
            &self,
            _routing_id: &RoutingId,
        ) -> BoxFuture<'_, Result<(), TransportError>> {
            Box::pin(async { Ok(()) })
        }

        fn query(
            &self,
            _routing_id: &RoutingId,
            _since: Option<u64>,
        ) -> BoxFuture<'_, Result<Vec<OuterEnvelope>, TransportError>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn delete(&self, _blob_id: &BlobId) -> BoxFuture<'_, Result<(), TransportError>> {
            Box::pin(async { Ok(()) })
        }
    }

    // -- TransportType tests -----------------------------------------------

    #[test]
    fn transport_type_display() {
        assert_eq!(
            TransportType::NativeWebSocket.to_string(),
            "native-websocket"
        );
        assert_eq!(TransportType::Quic.to_string(), "quic");
        assert_eq!(TransportType::WebTransport.to_string(), "webtransport");
        assert_eq!(TransportType::UdpDtls.to_string(), "udp-dtls");
    }

    #[test]
    fn transport_type_equality_and_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(TransportType::NativeWebSocket);
        set.insert(TransportType::Quic);
        assert!(set.contains(&TransportType::NativeWebSocket));
        assert!(set.contains(&TransportType::Quic));
        assert!(!set.contains(&TransportType::WebTransport));
    }

    // -- PoolKey tests -----------------------------------------------------

    #[test]
    fn pool_key_equality() {
        let k1 = PoolKey::new(
            "wss://relay.example.com/scp/v1".to_owned(),
            TransportType::NativeWebSocket,
        );
        let k2 = PoolKey::new(
            "wss://relay.example.com/scp/v1".to_owned(),
            TransportType::NativeWebSocket,
        );
        assert_eq!(k1, k2);
    }

    #[test]
    fn pool_key_differs_by_url() {
        let k1 = PoolKey::new(
            "wss://relay1.example.com/scp/v1".to_owned(),
            TransportType::NativeWebSocket,
        );
        let k2 = PoolKey::new(
            "wss://relay2.example.com/scp/v1".to_owned(),
            TransportType::NativeWebSocket,
        );
        assert_ne!(k1, k2);
    }

    #[test]
    fn pool_key_differs_by_transport_type() {
        let k1 = PoolKey::new(
            "wss://relay.example.com/scp/v1".to_owned(),
            TransportType::NativeWebSocket,
        );
        let k2 = PoolKey::new(
            "wss://relay.example.com/scp/v1".to_owned(),
            TransportType::Quic,
        );
        assert_ne!(k1, k2);
    }

    #[test]
    fn pool_key_display() {
        let key = PoolKey::new(
            "wss://relay.example.com/scp/v1".to_owned(),
            TransportType::NativeWebSocket,
        );
        assert_eq!(
            key.to_string(),
            "(wss://relay.example.com/scp/v1, native-websocket)"
        );
    }

    // -- ConnectionPool tests ----------------------------------------------

    #[test]
    fn pool_new_is_empty() {
        let pool = ConnectionPool::new();
        assert!(pool.is_empty());
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn pool_default_is_empty() {
        let pool = ConnectionPool::default();
        assert!(pool.is_empty());
    }

    #[test]
    fn pool_insert_and_get() {
        let pool = ConnectionPool::new();
        let key = PoolKey::new(
            "wss://relay.example.com/scp/v1".to_owned(),
            TransportType::NativeWebSocket,
        );

        pool.insert(key.clone(), Box::new(MockPoolAdapter::new("adapter-1")));
        assert_eq!(pool.len(), 1);
        assert!(pool.contains_key(&key));

        let adapter = pool.get(&key);
        assert!(adapter.is_some());
    }

    #[test]
    fn pool_get_returns_none_for_missing_key() {
        let pool = ConnectionPool::new();
        let key = PoolKey::new(
            "wss://relay.example.com/scp/v1".to_owned(),
            TransportType::NativeWebSocket,
        );
        assert!(pool.get(&key).is_none());
    }

    #[test]
    fn pool_same_relay_returns_same_connection() {
        // AC: two requests for the same relay return the same connection.
        let pool = ConnectionPool::new();
        let make_key = || {
            PoolKey::new(
                "wss://relay.example.com/scp/v1".to_owned(),
                TransportType::NativeWebSocket,
            )
        };

        let adapter1 = pool.get_or_insert(make_key(), Box::new(MockPoolAdapter::new("first")));
        let adapter2 = pool.get_or_insert(make_key(), Box::new(MockPoolAdapter::new("second")));

        // Both should be the same Arc (same underlying pointer).
        assert!(Arc::ptr_eq(&adapter1, &adapter2));
        // Pool should only have one entry.
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn pool_different_relays_get_different_connections() {
        // AC: different relays get different connections.
        let pool = ConnectionPool::new();

        let adapter1 = pool.get_or_insert(
            PoolKey::new(
                "wss://relay1.example.com/scp/v1".to_owned(),
                TransportType::NativeWebSocket,
            ),
            Box::new(MockPoolAdapter::new("relay1")),
        );
        let adapter2 = pool.get_or_insert(
            PoolKey::new(
                "wss://relay2.example.com/scp/v1".to_owned(),
                TransportType::NativeWebSocket,
            ),
            Box::new(MockPoolAdapter::new("relay2")),
        );

        // Different keys should produce different Arc pointers.
        assert!(!Arc::ptr_eq(&adapter1, &adapter2));
        // Pool should have two entries.
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn pool_same_relay_different_transport_types_get_different_connections() {
        let pool = ConnectionPool::new();

        let ws_adapter = pool.get_or_insert(
            PoolKey::new(
                "wss://relay.example.com/scp/v1".to_owned(),
                TransportType::NativeWebSocket,
            ),
            Box::new(MockPoolAdapter::new("ws")),
        );
        let quic_adapter = pool.get_or_insert(
            PoolKey::new(
                "wss://relay.example.com/scp/v1".to_owned(),
                TransportType::Quic,
            ),
            Box::new(MockPoolAdapter::new("quic")),
        );

        assert!(!Arc::ptr_eq(&ws_adapter, &quic_adapter));
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn pool_remove() {
        let pool = ConnectionPool::new();
        let key = PoolKey::new(
            "wss://relay.example.com/scp/v1".to_owned(),
            TransportType::NativeWebSocket,
        );

        pool.insert(key.clone(), Box::new(MockPoolAdapter::new("adapter")));
        assert_eq!(pool.len(), 1);

        let removed = pool.remove(&key);
        assert!(removed.is_some());
        assert!(pool.is_empty());

        // Removing again should return None.
        let removed_again = pool.remove(&key);
        assert!(removed_again.is_none());
    }

    #[test]
    fn pool_clear() {
        let pool = ConnectionPool::new();
        let key1 = PoolKey::new(
            "wss://r1.example.com".to_owned(),
            TransportType::NativeWebSocket,
        );
        let key2 = PoolKey::new("wss://r2.example.com".to_owned(), TransportType::Quic);

        pool.insert(key1, Box::new(MockPoolAdapter::new("a1")));
        pool.insert(key2, Box::new(MockPoolAdapter::new("a2")));
        assert_eq!(pool.len(), 2);

        pool.clear();
        assert!(pool.is_empty());
    }

    #[test]
    fn pool_keys_returns_all_entries() {
        let pool = ConnectionPool::new();
        let first = PoolKey::new(
            "wss://r1.example.com".to_owned(),
            TransportType::NativeWebSocket,
        );
        let second = PoolKey::new("wss://r2.example.com".to_owned(), TransportType::Quic);

        pool.insert(first.clone(), Box::new(MockPoolAdapter::new("a1")));
        pool.insert(second.clone(), Box::new(MockPoolAdapter::new("a2")));

        let all_keys = pool.keys();
        assert_eq!(all_keys.len(), 2);
        assert!(all_keys.contains(&first));
        assert!(all_keys.contains(&second));
    }

    #[test]
    fn pool_insert_replaces_existing() {
        let pool = ConnectionPool::new();
        let make_key = || {
            PoolKey::new(
                "wss://relay.example.com/scp/v1".to_owned(),
                TransportType::NativeWebSocket,
            )
        };

        let old = pool.insert(make_key(), Box::new(MockPoolAdapter::new("first")));
        assert!(old.is_none()); // No previous entry.

        let old = pool.insert(make_key(), Box::new(MockPoolAdapter::new("second")));
        assert!(old.is_some()); // Replaced the first entry.

        // Pool still has exactly one entry.
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn pool_arc_sharing_across_managers() {
        // AC: Arc<ConnectionPool> enables cross-TransportManager sharing.
        let pool = Arc::new(ConnectionPool::new());
        let key = PoolKey::new(
            "wss://relay.example.com/scp/v1".to_owned(),
            TransportType::NativeWebSocket,
        );

        // Simulate manager 1 inserting a connection.
        let pool1 = Arc::clone(&pool);
        let adapter = pool1.get_or_insert(
            key.clone(),
            Box::new(MockPoolAdapter::new("manager1-adapter")),
        );

        // Simulate manager 2 looking up the same connection.
        let pool2 = Arc::clone(&pool);
        let adapter_from_pool2 = pool2.get(&key);
        assert!(adapter_from_pool2.is_some());

        // Both managers got the same adapter.
        assert!(Arc::ptr_eq(&adapter, &adapter_from_pool2.unwrap()));
    }

    #[test]
    fn pool_get_or_try_insert_with_defers_construction() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let pool = ConnectionPool::new();
        let key = PoolKey::new(
            "wss://relay.example.com/scp/v1".to_owned(),
            TransportType::NativeWebSocket,
        );

        // Pre-insert an adapter for the key.
        pool.insert(key.clone(), Box::new(MockPoolAdapter::new("existing")));

        // Factory should NOT be called when key exists.
        let factory_called = Arc::new(AtomicBool::new(false));
        let factory_called_clone = Arc::clone(&factory_called);
        let result = pool.get_or_try_insert_with(key, move || {
            factory_called_clone.store(true, Ordering::SeqCst);
            Ok(Box::new(MockPoolAdapter::new("should-not-be-used")) as Box<dyn TransportAdapter>)
        });
        assert!(result.is_ok());
        assert!(
            !factory_called.load(Ordering::SeqCst),
            "factory should NOT be called when key exists"
        );
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn pool_get_or_try_insert_with_calls_factory_when_missing() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let pool = ConnectionPool::new();
        let key = PoolKey::new(
            "wss://relay.example.com/scp/v1".to_owned(),
            TransportType::NativeWebSocket,
        );

        // Factory IS called when key is missing.
        let factory_called = Arc::new(AtomicBool::new(false));
        let factory_called_clone = Arc::clone(&factory_called);
        let result = pool.get_or_try_insert_with(key.clone(), move || {
            factory_called_clone.store(true, Ordering::SeqCst);
            Ok(Box::new(MockPoolAdapter::new("new-adapter")) as Box<dyn TransportAdapter>)
        });
        assert!(result.is_ok());
        assert!(
            factory_called.load(Ordering::SeqCst),
            "factory SHOULD be called when key is missing"
        );
        assert_eq!(pool.len(), 1);
        assert!(pool.contains_key(&key));
    }

    #[test]
    fn pool_get_or_try_insert_with_propagates_factory_error() {
        let pool = ConnectionPool::new();
        let key = PoolKey::new(
            "wss://relay.example.com/scp/v1".to_owned(),
            TransportType::NativeWebSocket,
        );

        let result = pool.get_or_try_insert_with(key, || {
            Err(TransportError::ConnectionFailed(
                "factory failed".to_owned(),
            ))
        });
        assert!(result.is_err());
        assert!(
            pool.is_empty(),
            "pool should remain empty when factory errors"
        );
    }

    #[test]
    fn pool_debug_shows_count() {
        let pool = ConnectionPool::new();
        let debug = format!("{pool:?}");
        assert!(debug.contains("entries: 0"));

        pool.insert(
            PoolKey::new(
                "wss://r1.example.com".to_owned(),
                TransportType::NativeWebSocket,
            ),
            Box::new(MockPoolAdapter::new("a1")),
        );
        let debug = format!("{pool:?}");
        assert!(debug.contains("entries: 1"));
    }
}
