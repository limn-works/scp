//! Relay operational state persistence (SCP-PERSIST-066).
//!
//! Defines [`RelayPersistence`], a dyn-compatible **async** trait for
//! persisting relay operational state (subscriptions, rate limits) across
//! relay restarts. Follows the async-provider-trait pattern used by
//! `ContextPersistence` / `EventLogPersistence` in `scp-core` (ADR-049
//! Decision 7): the methods `.await` the async [`Storage`](scp_platform::Storage)
//! backend directly — there is NO `block_in_place` sync→async bridge.
//!
//! The canonical implementation `StorageRelayPersistence` wraps any
//! `Storage` implementation.

use std::fmt;

#[cfg(feature = "relay-persistence")]
use std::sync::Arc;

/// Type alias for boxed errors in relay persistence operations.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Key prefix for relay subscription records.
#[cfg(feature = "relay-persistence")]
const SUBSCRIPTION_PREFIX: &str = "relay/subscription/";

/// Key prefix for relay rate limit state.
#[cfg(feature = "relay-persistence")]
const RATE_LIMIT_PREFIX: &str = "relay/rate_limit/";

// ---------------------------------------------------------------------------
// RelayPersistence trait
// ---------------------------------------------------------------------------

/// Provider for persisting relay operational state across restarts.
///
/// Implementors must be dyn-compatible (`Send + Sync`, async methods via
/// `#[async_trait]`). All methods are best-effort — the relay logs errors but
/// does not abort operations when persistence fails.
///
/// # Async discipline (ADR-049 Decision 7)
///
/// Plain `#[async_trait]` (Send), not `?Send`: the relay holds the provider as
/// `Arc<dyn RelayPersistence>` and calls it from spawned async tasks, so the
/// method futures must be `Send`.
///
/// See SCP-PERSIST-066.
#[async_trait::async_trait]
pub trait RelayPersistence: Send + Sync + fmt::Debug {
    /// Records that `routing_id` has an active subscription.
    ///
    /// Called on each SUBSCRIBE operation. Idempotent — storing the same
    /// `routing_id` multiple times is a no-op.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage backend fails.
    async fn persist_subscription(&self, routing_id: &[u8; 32]) -> Result<(), BoxError>;

    /// Removes the subscription record for `routing_id`.
    ///
    /// Called on each UNSUBSCRIBE operation. No-op if the `routing_id`
    /// is not persisted.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage backend fails.
    async fn remove_subscription(&self, routing_id: &[u8; 32]) -> Result<(), BoxError>;

    /// Loads all persisted routing IDs that had active subscriptions.
    ///
    /// Called on relay startup. Returns the set of routing IDs that
    /// should be pre-populated in the subscription registry so that
    /// blobs published to these routing IDs are retained for delivery
    /// when clients reconnect and re-subscribe.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage backend fails.
    async fn load_subscribed_routing_ids(&self) -> Result<Vec<[u8; 32]>, BoxError>;

    /// Persists rate limit state for an IP address.
    ///
    /// Called periodically to snapshot rate limit counters.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage backend fails.
    async fn persist_rate_limit(
        &self,
        ip: &str,
        tokens: f64,
        window_start_secs: u64,
    ) -> Result<(), BoxError>;

    /// Loads persisted rate limit state for an IP address.
    ///
    /// Returns `None` if no rate limit state exists for the IP.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage backend fails.
    async fn load_rate_limit(&self, ip: &str) -> Result<Option<(f64, u64)>, BoxError>;

    /// Deletes all persisted relay state.
    ///
    /// Used for relay cleanup / reset.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage backend fails.
    async fn clear_all(&self) -> Result<(), BoxError>;
}

// ---------------------------------------------------------------------------
// StorageRelayPersistence — bridges Storage trait to RelayPersistence
// ---------------------------------------------------------------------------

/// Bridges any [`Storage`](scp_platform::Storage) implementation to
/// [`RelayPersistence`] using the sync-to-async bridge pattern.
///
/// Key layout:
/// - `relay/subscription/{routing_id_hex}` — marker value `b"1"`
/// - `relay/rate_limit/{ip}` — MessagePack-encoded `(f64, u64)`
#[cfg(feature = "relay-persistence")]
pub struct StorageRelayPersistence<S> {
    storage: Arc<S>,
}

#[cfg(feature = "relay-persistence")]
impl<S> fmt::Debug for StorageRelayPersistence<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StorageRelayPersistence")
            .field("storage", &"<Storage>")
            .finish()
    }
}

#[cfg(feature = "relay-persistence")]
impl<S> StorageRelayPersistence<S> {
    /// Creates a new relay persistence provider wrapping the given storage.
    pub const fn new(storage: Arc<S>) -> Self {
        Self { storage }
    }
}

#[cfg(feature = "relay-persistence")]
#[async_trait::async_trait]
impl<S: scp_platform::Storage + 'static> RelayPersistence for StorageRelayPersistence<S> {
    async fn persist_subscription(&self, routing_id: &[u8; 32]) -> Result<(), BoxError> {
        let key = format!("{}{}", SUBSCRIPTION_PREFIX, hex::encode(routing_id));
        self.storage
            .store(&key, b"1")
            .await
            .map_err(|e| -> BoxError { Box::new(e) })
    }

    async fn remove_subscription(&self, routing_id: &[u8; 32]) -> Result<(), BoxError> {
        let key = format!("{}{}", SUBSCRIPTION_PREFIX, hex::encode(routing_id));
        self.storage
            .delete(&key)
            .await
            .map_err(|e| -> BoxError { Box::new(e) })
    }

    async fn load_subscribed_routing_ids(&self) -> Result<Vec<[u8; 32]>, BoxError> {
        let keys = self
            .storage
            .list_keys(SUBSCRIPTION_PREFIX)
            .await
            .map_err(|e| -> BoxError { Box::new(e) })?;

        let mut routing_ids = Vec::with_capacity(keys.len());
        for key in keys {
            let hex_part = key
                .strip_prefix(SUBSCRIPTION_PREFIX)
                .ok_or_else(|| -> BoxError {
                    format!("unexpected key without prefix: {key}").into()
                })?;
            let bytes = hex::decode(hex_part).map_err(|e| -> BoxError { Box::new(e) })?;
            if bytes.len() != 32 {
                continue; // skip malformed entries
            }
            let mut routing_id = [0u8; 32];
            routing_id.copy_from_slice(&bytes);
            routing_ids.push(routing_id);
        }
        Ok(routing_ids)
    }

    async fn persist_rate_limit(
        &self,
        ip: &str,
        tokens: f64,
        window_start_secs: u64,
    ) -> Result<(), BoxError> {
        // Validate IP to prevent key injection (e.g., "../../identity/victim").
        let _: std::net::IpAddr = ip.parse().map_err(|e| -> BoxError {
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid IP for rate limit key: {e}"),
            ))
        })?;
        let key = format!("{RATE_LIMIT_PREFIX}{ip}");
        let value = rmp_serde::to_vec(&(tokens, window_start_secs))
            .map_err(|e| -> BoxError { Box::new(e) })?;
        self.storage
            .store(&key, &value)
            .await
            .map_err(|e| -> BoxError { Box::new(e) })
    }

    async fn load_rate_limit(&self, ip: &str) -> Result<Option<(f64, u64)>, BoxError> {
        // Validate IP to prevent key injection.
        let _: std::net::IpAddr = ip.parse().map_err(|e| -> BoxError {
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid IP for rate limit key: {e}"),
            ))
        })?;
        let key = format!("{RATE_LIMIT_PREFIX}{ip}");
        let data = self
            .storage
            .retrieve(&key)
            .await
            .map_err(|e| -> BoxError { Box::new(e) })?;
        match data {
            Some(bytes) => {
                let (tokens, window): (f64, u64) =
                    rmp_serde::from_slice(&bytes).map_err(|e| -> BoxError { Box::new(e) })?;
                Ok(Some((tokens, window)))
            }
            None => Ok(None),
        }
    }

    async fn clear_all(&self) -> Result<(), BoxError> {
        self.storage
            .delete_prefix(SUBSCRIPTION_PREFIX)
            .await
            .map_err(|e| -> BoxError { Box::new(e) })?;
        self.storage
            .delete_prefix(RATE_LIMIT_PREFIX)
            .await
            .map_err(|e| -> BoxError { Box::new(e) })?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::significant_drop_tightening
)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// A simple in-memory implementation for testing the trait interface.
    #[derive(Debug)]
    struct MockRelayPersistence {
        subscriptions: std::sync::Mutex<Vec<[u8; 32]>>,
        rate_limits: std::sync::Mutex<std::collections::HashMap<String, (f64, u64)>>,
    }

    impl MockRelayPersistence {
        fn new() -> Self {
            Self {
                subscriptions: std::sync::Mutex::new(Vec::new()),
                rate_limits: std::sync::Mutex::new(std::collections::HashMap::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl RelayPersistence for MockRelayPersistence {
        async fn persist_subscription(&self, routing_id: &[u8; 32]) -> Result<(), BoxError> {
            let mut subs = self.subscriptions.lock().unwrap();
            if !subs.contains(routing_id) {
                subs.push(*routing_id);
            }
            Ok(())
        }

        async fn remove_subscription(&self, routing_id: &[u8; 32]) -> Result<(), BoxError> {
            let mut subs = self.subscriptions.lock().unwrap();
            subs.retain(|id| id != routing_id);
            Ok(())
        }

        async fn load_subscribed_routing_ids(&self) -> Result<Vec<[u8; 32]>, BoxError> {
            Ok(self.subscriptions.lock().unwrap().clone())
        }

        async fn persist_rate_limit(
            &self,
            ip: &str,
            tokens: f64,
            window_start_secs: u64,
        ) -> Result<(), BoxError> {
            self.rate_limits
                .lock()
                .unwrap()
                .insert(ip.to_string(), (tokens, window_start_secs));
            Ok(())
        }

        async fn load_rate_limit(&self, ip: &str) -> Result<Option<(f64, u64)>, BoxError> {
            Ok(self.rate_limits.lock().unwrap().get(ip).copied())
        }

        async fn clear_all(&self) -> Result<(), BoxError> {
            self.subscriptions.lock().unwrap().clear();
            self.rate_limits.lock().unwrap().clear();
            Ok(())
        }
    }

    #[tokio::test]
    async fn subscription_roundtrip() {
        let persistence = MockRelayPersistence::new();
        let routing_id = [0xAA; 32];

        persistence.persist_subscription(&routing_id).await.unwrap();
        let loaded = persistence.load_subscribed_routing_ids().await.unwrap();
        assert_eq!(loaded, vec![routing_id]);
    }

    #[tokio::test]
    async fn subscription_remove() {
        let persistence = MockRelayPersistence::new();
        let routing_id = [0xAA; 32];

        persistence.persist_subscription(&routing_id).await.unwrap();
        persistence.remove_subscription(&routing_id).await.unwrap();
        let loaded = persistence.load_subscribed_routing_ids().await.unwrap();
        assert!(loaded.is_empty());
    }

    #[tokio::test]
    async fn subscription_idempotent() {
        let persistence = MockRelayPersistence::new();
        let routing_id = [0xAA; 32];

        persistence.persist_subscription(&routing_id).await.unwrap();
        persistence.persist_subscription(&routing_id).await.unwrap();
        let loaded = persistence.load_subscribed_routing_ids().await.unwrap();
        assert_eq!(loaded.len(), 1);
    }

    #[tokio::test]
    async fn rate_limit_roundtrip() {
        let persistence = MockRelayPersistence::new();
        persistence
            .persist_rate_limit("192.168.1.1", 50.0, 1_000_000)
            .await
            .unwrap();
        let loaded = persistence.load_rate_limit("192.168.1.1").await.unwrap();
        assert_eq!(loaded, Some((50.0, 1_000_000)));
    }

    #[tokio::test]
    async fn rate_limit_missing_returns_none() {
        let persistence = MockRelayPersistence::new();
        let loaded = persistence.load_rate_limit("10.0.0.1").await.unwrap();
        assert_eq!(loaded, None);
    }

    #[tokio::test]
    async fn clear_all_removes_everything() {
        let persistence = MockRelayPersistence::new();
        persistence.persist_subscription(&[0xBB; 32]).await.unwrap();
        persistence
            .persist_rate_limit("1.2.3.4", 10.0, 500)
            .await
            .unwrap();

        persistence.clear_all().await.unwrap();

        assert!(
            persistence
                .load_subscribed_routing_ids()
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            persistence
                .load_rate_limit("1.2.3.4")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn trait_is_dyn_compatible() {
        // Verify RelayPersistence can be used as a trait object.
        let persistence: Arc<dyn RelayPersistence> = Arc::new(MockRelayPersistence::new());
        persistence.persist_subscription(&[0xCC; 32]).await.unwrap();
        let loaded = persistence.load_subscribed_routing_ids().await.unwrap();
        assert_eq!(loaded.len(), 1);
    }
}
