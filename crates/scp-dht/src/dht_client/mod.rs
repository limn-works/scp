//! DHT client abstraction for DID publishing and resolution.
//!
//! Defines the [`DhtClient`] trait that abstracts Mainline DHT operations
//! (BEP44 signed mutable items). This enables testing with [`InMemoryDhtClient`]
//! while production code uses a real DHT client.
//!
//! # Production Implementations
//!
//! - [`PkarrDhtClient`] — Uses the `mainline` crate for direct Mainline DHT
//!   BEP44 operations, with optional HTTP gateway fallback for resolution
//!   behind restrictive firewalls. Enabled via the `production-dht` feature.
//!
//! See ADR-003 in `.docs/adrs/phase-1.md` and §3.10 (DID Resolution Layers).

use std::collections::HashMap;

use tokio::sync::Mutex;

use crate::DhtError;

/// Abstraction over BEP44 signed mutable item operations on a DHT.
///
/// Production implementations use the `mainline` crate for Mainline DHT access.
/// The [`InMemoryDhtClient`] provides a `HashMap`-backed implementation for
/// unit tests that require no network access.
///
/// # BEP44 Model
///
/// Each item is keyed by a 32-byte Ed25519 public key. The value is an opaque
/// byte blob (the serialized DID document) with a monotonically increasing
/// sequence number and a 64-byte Ed25519 signature over the value + sequence.
pub trait DhtClient: Send + Sync {
    /// Publishes a BEP44 signed mutable item to the DHT.
    ///
    /// # Arguments
    ///
    /// * `public_key` — The 32-byte Ed25519 public key that identifies this item.
    /// * `signature` — The 64-byte Ed25519 signature over the encoded value + sequence.
    /// * `value` — The serialized DID document bytes.
    /// * `seq` — The monotonically increasing sequence number.
    ///
    /// # Errors
    ///
    /// Returns [`DhtError::DhtPublishFailed`] if the publish operation fails.
    fn publish(
        &self,
        public_key: &[u8; 32],
        signature: &[u8; 64],
        value: &[u8],
        seq: u64,
    ) -> impl Future<Output = Result<(), DhtError>> + Send;

    /// Resolves a BEP44 signed mutable item from the DHT.
    ///
    /// # Arguments
    ///
    /// * `public_key` — The 32-byte Ed25519 public key to look up.
    ///
    /// # Returns
    ///
    /// `Ok(Some((value, signature, seq)))` if found — the document bytes,
    /// Ed25519 signature, and sequence number. `Ok(None)` if not found.
    ///
    /// # Errors
    ///
    /// Returns [`DhtError::DhtResolveFailed`] if the lookup operation fails.
    fn resolve(
        &self,
        public_key: &[u8; 32],
    ) -> impl Future<Output = Result<Option<DhtRecord>, DhtError>> + Send;
}

/// A BEP44 record retrieved from the DHT.
#[derive(Debug, Clone)]
pub struct DhtRecord {
    /// The serialized DID document bytes.
    pub value: Vec<u8>,
    /// The Ed25519 signature over the BEP44 encoded payload.
    pub signature: [u8; 64],
    /// The monotonically increasing sequence number.
    pub seq: u64,
}

/// In-memory DHT client for testing.
///
/// Stores BEP44 mutable items in a `HashMap` keyed by the 32-byte public key.
/// Enforces the BEP44 monotonic sequence number invariant: a publish with a
/// sequence number less than or equal to the existing one is silently ignored
/// (idempotent no-op).
///
/// This implementation requires no network access and is suitable for unit tests.
#[derive(Debug, Default)]
pub struct InMemoryDhtClient {
    /// Map from public key bytes to (value, signature, sequence number).
    items: Mutex<HashMap<[u8; 32], StoredItem>>,
}

/// A stored BEP44 item in the in-memory DHT.
#[derive(Debug, Clone)]
struct StoredItem {
    value: Vec<u8>,
    signature: [u8; 64],
    seq: u64,
}

impl InMemoryDhtClient {
    /// Creates a new empty in-memory DHT client.
    #[must_use]
    pub fn new() -> Self {
        Self {
            items: Mutex::new(HashMap::new()),
        }
    }

    /// Removes all stored items. Test-only utility for verifying republish behavior.
    pub async fn clear(&self) {
        let mut items = self.items.lock().await;
        items.clear();
    }
}

// Trait uses RPITIT with explicit `+ Send` bound; async fn in trait
// does not guarantee Send futures, so manual impl Future is required.
#[allow(clippy::manual_async_fn)]
impl DhtClient for InMemoryDhtClient {
    fn publish(
        &self,
        public_key: &[u8; 32],
        signature: &[u8; 64],
        value: &[u8],
        seq: u64,
    ) -> impl Future<Output = Result<(), DhtError>> + Send {
        async move {
            let mut items = self.items.lock().await;
            let key = *public_key;

            // BEP44 semantics: only update if new sequence number is strictly greater.
            if let Some(existing) = items.get(&key)
                && seq <= existing.seq
            {
                // Idempotent no-op for same or lower sequence number.
                return Ok(());
            }

            items.insert(
                key,
                StoredItem {
                    value: value.to_vec(),
                    signature: *signature,
                    seq,
                },
            );
            drop(items);

            Ok(())
        }
    }

    fn resolve(
        &self,
        public_key: &[u8; 32],
    ) -> impl Future<Output = Result<Option<DhtRecord>, DhtError>> + Send {
        async move {
            let items = self.items.lock().await;
            let record = items.get(public_key).map(|item| DhtRecord {
                value: item.value.clone(),
                signature: item.signature,
                seq: item.seq,
            });
            drop(items);
            Ok(record)
        }
    }
}

// ---------------------------------------------------------------------------
// PkarrDhtClient — production Mainline DHT client (feature: production-dht)
// ---------------------------------------------------------------------------

#[cfg(feature = "production-dht")]
mod pkarr_client;

#[cfg(feature = "production-dht")]
pub use pkarr_client::{PkarrDhtClient, PkarrDhtClientBuilder};

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn publish_and_resolve_roundtrip() {
        let client = InMemoryDhtClient::new();
        let key = [1u8; 32];
        let sig = [2u8; 64];
        let value = b"test document";

        client.publish(&key, &sig, value, 1).await.unwrap();
        let record = client.resolve(&key).await.unwrap().unwrap();

        assert_eq!(record.value, value);
        assert_eq!(record.signature, sig);
        assert_eq!(record.seq, 1);
    }

    #[tokio::test]
    async fn resolve_returns_none_for_missing_key() {
        let client = InMemoryDhtClient::new();
        let key = [1u8; 32];

        let result = client.resolve(&key).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn publish_ignores_lower_sequence_number() {
        let client = InMemoryDhtClient::new();
        let key = [1u8; 32];
        let sig1 = [2u8; 64];
        let sig2 = [3u8; 64];

        client.publish(&key, &sig1, b"version 1", 5).await.unwrap();
        client.publish(&key, &sig2, b"version 2", 3).await.unwrap();

        let record = client.resolve(&key).await.unwrap().unwrap();
        assert_eq!(record.value, b"version 1");
        assert_eq!(record.seq, 5);
    }

    #[tokio::test]
    async fn publish_ignores_same_sequence_number() {
        let client = InMemoryDhtClient::new();
        let key = [1u8; 32];
        let sig1 = [2u8; 64];
        let sig2 = [3u8; 64];

        client.publish(&key, &sig1, b"version 1", 5).await.unwrap();
        client.publish(&key, &sig2, b"version 2", 5).await.unwrap();

        let record = client.resolve(&key).await.unwrap().unwrap();
        assert_eq!(record.value, b"version 1");
        assert_eq!(record.seq, 5);
    }

    #[tokio::test]
    async fn publish_updates_with_higher_sequence_number() {
        let client = InMemoryDhtClient::new();
        let key = [1u8; 32];
        let sig1 = [2u8; 64];
        let sig2 = [3u8; 64];

        client.publish(&key, &sig1, b"version 1", 1).await.unwrap();
        client.publish(&key, &sig2, b"version 2", 2).await.unwrap();

        let record = client.resolve(&key).await.unwrap().unwrap();
        assert_eq!(record.value, b"version 2");
        assert_eq!(record.seq, 2);
    }
}
