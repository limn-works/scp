//! Transport storage operations for `ProtocolStore`.
//!
//! Implements relay score and key package persistence following the key
//! convention from spec section 17.3:
//!
//! ```text
//! relay_score/{sha256_hex(url)}
//! key_package/{sha256_hex(url)}/{index:010d}
//! ```
//!
//! URLs contain `/` which fails `sanitize_key_component`, so relay URLs
//! are hashed with SHA-256 and encoded as lowercase hex for use as key
//! components. Key package indices use 10-digit zero-padding.
//!
//! See spec sections 17.3 and 17.4. See SCP-PERSIST-012.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use scp_platform::traits::Storage;

use super::{ProtocolStore, StoreError};

/// A relay score entry with the original URL preserved.
///
/// Stored alongside the relay score so that `list_relay_scores` can return
/// usable URLs instead of opaque hashes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayScoreEntry {
    /// The original relay URL.
    pub url: String,
    /// The opaque score bytes (format defined by the scoring algorithm).
    pub score: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Key helpers
// ---------------------------------------------------------------------------

/// Hashes a URL to a SHA-256 hex string for use as a key component.
///
/// URLs contain `/` which fails `sanitize_key_component`. This helper
/// produces a fixed-length, path-safe key component.
fn hash_url(url: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(url.as_bytes());
    hex::encode(hasher.finalize())
}

/// Builds the storage key for a relay score.
///
/// Format: `relay_score/{sha256_hex(url)}`
/// See spec section 17.3.
fn relay_score_key(relay_url: &str) -> String {
    let url_hash = hash_url(relay_url);
    format!("relay_score/{url_hash}")
}

/// Builds the prefix for listing all relay scores.
///
/// Format: `relay_score/`
const fn relay_score_prefix() -> &'static str {
    "relay_score/"
}

/// Builds the storage key for a key package.
///
/// Format: `key_package/{sha256_hex(url)}/{index:010d}`
/// Uses 10-digit zero-padding for lexicographic ordering.
/// See spec section 17.3.
fn key_package_key(relay_url: &str, index: u32) -> String {
    let url_hash = hash_url(relay_url);
    format!("key_package/{url_hash}/{index:010}")
}

/// Builds the prefix for listing all key packages for a relay.
///
/// Format: `key_package/{sha256_hex(url)}/`
fn key_package_prefix(relay_url: &str) -> String {
    let url_hash = hash_url(relay_url);
    format!("key_package/{url_hash}/")
}

/// Builds the storage key for a certificate pin.
///
/// Format: `cert_pin/{sha256_hex(url)}`
/// See spec section 9.13.
fn cert_pin_key(relay_url: &str) -> String {
    let url_hash = hash_url(relay_url);
    format!("cert_pin/{url_hash}")
}

// ---------------------------------------------------------------------------
// ProtocolStore — transport methods
// ---------------------------------------------------------------------------

impl<S: Storage> ProtocolStore<S> {
    /// Stores a relay score for a relay URL.
    ///
    /// Serializes a [`RelayScoreEntry`] (URL + score bytes) under
    /// `relay_score/{sha256_hex(url)}` wrapped in a `StoredValue` version
    /// envelope. The original URL is preserved in the value so that
    /// `list_relay_scores` can return usable URLs.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn store_relay_score(&self, relay_url: &str, score: &[u8]) -> Result<(), StoreError> {
        let key = relay_score_key(relay_url);
        let entry = RelayScoreEntry {
            url: relay_url.to_owned(),
            score: score.to_vec(),
        };
        self.store_value(&key, &entry).await
    }

    /// Loads a relay score for a relay URL.
    ///
    /// Returns `None` if no score exists for the given relay.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::DeserializationFailed`] if deserialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage read fails.
    pub async fn load_relay_score(&self, relay_url: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let key = relay_score_key(relay_url);
        let entry: Option<RelayScoreEntry> = self.load_value(&key).await?;
        Ok(entry.map(|e| e.score))
    }

    /// Lists all relay scores.
    ///
    /// Returns a vector of [`RelayScoreEntry`] containing the original
    /// relay URL and score bytes.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage operation fails.
    /// Returns [`StoreError::DeserializationFailed`] if any score record fails
    /// to deserialize.
    pub async fn list_relay_scores(&self) -> Result<Vec<RelayScoreEntry>, StoreError> {
        let prefix = relay_score_prefix();
        let keys = self.storage.list_keys(prefix).await?;
        let mut results = Vec::with_capacity(keys.len());
        for key in keys {
            if key.strip_prefix(prefix).is_some() {
                if let Some(entry) = self.load_value::<RelayScoreEntry>(&key).await? {
                    results.push(entry);
                } else {
                    tracing::warn!(
                        key = %key,
                        "relay score key exists but load_value returned None — data integrity issue"
                    );
                }
            }
        }
        Ok(results)
    }

    /// Stores a key package for a relay URL at the given index.
    ///
    /// Serializes the key package bytes under
    /// `key_package/{sha256_hex(url)}/{index:010d}` wrapped in a
    /// `StoredValue` version envelope.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn store_key_package(
        &self,
        relay_url: &str,
        index: u32,
        kp: &[u8],
    ) -> Result<(), StoreError> {
        let key = key_package_key(relay_url, index);
        self.store_value(&key, &kp.to_vec()).await
    }

    /// Loads all key packages for a relay URL.
    ///
    /// Returns key package bytes in index order (lexicographic via
    /// zero-padded keys).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage operation fails.
    /// Returns [`StoreError::DeserializationFailed`] if any key package fails
    /// to deserialize.
    pub async fn load_key_packages(&self, relay_url: &str) -> Result<Vec<Vec<u8>>, StoreError> {
        let prefix = key_package_prefix(relay_url);
        let keys = self.storage.list_keys(&prefix).await?;
        let mut results = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some(kp) = self.load_value::<Vec<u8>>(&key).await? {
                results.push(kp);
            }
        }
        Ok(results)
    }

    /// Deletes a key package for a relay URL at the given index.
    ///
    /// No-op if the key package does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage delete fails.
    pub async fn delete_key_package(&self, relay_url: &str, index: u32) -> Result<(), StoreError> {
        let key = key_package_key(relay_url, index);
        self.storage.delete(&key).await?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Certificate pin methods (spec §9.13)
    // -----------------------------------------------------------------------

    /// Stores a certificate pin for a relay URL.
    ///
    /// Serializes the pin data (fingerprint + timestamps) under
    /// `cert_pin/{sha256_hex(url)}` wrapped in a `StoredValue` version
    /// envelope.
    ///
    /// # Raw bytes API
    ///
    /// This method accepts raw bytes rather than a typed `CertificatePin`
    /// because `CertificatePin` lives in `scp-transport`, which `scp-core`
    /// cannot depend on (it would create a circular dependency). The caller
    /// is responsible for serializing/deserializing `CertificatePin` to/from
    /// bytes (e.g., via `rmp_serde`). See `scp_transport::native::cert_pin`
    /// for the type definition.
    ///
    /// See spec section 9.13 (Transport Security Requirements).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn store_cert_pin(&self, relay_url: &str, pin_data: &[u8]) -> Result<(), StoreError> {
        let key = cert_pin_key(relay_url);
        self.store_value(&key, &pin_data.to_vec()).await
    }

    /// Loads a certificate pin for a relay URL.
    ///
    /// Returns `None` if no pin exists for the given relay. The returned
    /// bytes should be deserialized to `scp_transport::native::cert_pin::CertificatePin`
    /// by the caller (see [`store_cert_pin`](Self::store_cert_pin) for why
    /// this uses raw bytes).
    ///
    /// See spec section 9.13.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::DeserializationFailed`] if deserialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage read fails.
    pub async fn load_cert_pin(&self, relay_url: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let key = cert_pin_key(relay_url);
        self.load_value(&key).await
    }

    /// Deletes a certificate pin for a relay URL.
    ///
    /// Used when a pin needs to be reset (e.g., after legitimate
    /// certificate rotation).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage delete fails.
    pub async fn delete_cert_pin(&self, relay_url: &str) -> Result<(), StoreError> {
        let key = cert_pin_key(relay_url);
        self.storage.delete(&key).await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use scp_platform::testing::InMemoryStorage;

    use super::*;

    fn make_store() -> ProtocolStore<InMemoryStorage> {
        ProtocolStore::new_for_testing(InMemoryStorage::new())
    }

    // -------------------------------------------------------------------
    // Relay scores
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn store_and_load_relay_score_roundtrip() {
        let protocol_store = make_store();
        let score_data = b"score-data-for-relay".to_vec();

        protocol_store
            .store_relay_score("https://relay.example.com/v1", &score_data)
            .await
            .unwrap();
        let loaded = protocol_store
            .load_relay_score("https://relay.example.com/v1")
            .await
            .unwrap();
        assert_eq!(loaded, Some(score_data));
    }

    #[tokio::test]
    async fn load_relay_score_returns_none_for_missing() {
        let store = make_store();
        let loaded = store
            .load_relay_score("https://unknown.relay.com")
            .await
            .unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn list_relay_scores_returns_all_entries_with_urls() {
        let store = make_store();

        store
            .store_relay_score("https://relay-a.example.com", b"score-a")
            .await
            .unwrap();
        store
            .store_relay_score("https://relay-b.example.com", b"score-b")
            .await
            .unwrap();
        store
            .store_relay_score("https://relay-c.example.com", b"score-c")
            .await
            .unwrap();

        let mut scores = store.list_relay_scores().await.unwrap();
        assert_eq!(scores.len(), 3);

        // Verify original URLs are preserved (sort for deterministic order).
        scores.sort_by(|a, b| a.url.cmp(&b.url));
        assert_eq!(scores[0].url, "https://relay-a.example.com");
        assert_eq!(scores[0].score, b"score-a");
        assert_eq!(scores[1].url, "https://relay-b.example.com");
        assert_eq!(scores[2].url, "https://relay-c.example.com");
    }

    // -------------------------------------------------------------------
    // Key packages
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn store_and_load_key_packages_roundtrip() {
        let store = make_store();
        let url = "https://relay.example.com/v1";

        store.store_key_package(url, 0, b"kp-0").await.unwrap();
        store.store_key_package(url, 1, b"kp-1").await.unwrap();
        store.store_key_package(url, 2, b"kp-2").await.unwrap();

        let packages = store.load_key_packages(url).await.unwrap();
        assert_eq!(packages.len(), 3);
        assert_eq!(packages[0], b"kp-0");
        assert_eq!(packages[1], b"kp-1");
        assert_eq!(packages[2], b"kp-2");
    }

    #[tokio::test]
    async fn load_key_packages_returns_index_ordered_results() {
        let store = make_store();
        let url = "https://relay.example.com";

        // Store out of order.
        store.store_key_package(url, 5, b"kp-5").await.unwrap();
        store.store_key_package(url, 1, b"kp-1").await.unwrap();
        store.store_key_package(url, 10, b"kp-10").await.unwrap();

        let packages = store.load_key_packages(url).await.unwrap();
        assert_eq!(packages.len(), 3);
        // Zero-padded keys ensure lexicographic = numeric order.
        assert_eq!(packages[0], b"kp-1");
        assert_eq!(packages[1], b"kp-5");
        assert_eq!(packages[2], b"kp-10");
    }

    #[tokio::test]
    async fn delete_key_package_removes_correct_entry_only() {
        let store = make_store();
        let url = "https://relay.example.com";

        store.store_key_package(url, 0, b"kp-0").await.unwrap();
        store.store_key_package(url, 1, b"kp-1").await.unwrap();

        store.delete_key_package(url, 0).await.unwrap();

        let packages = store.load_key_packages(url).await.unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0], b"kp-1");
    }

    #[tokio::test]
    async fn load_key_packages_empty_for_missing_relay() {
        let store = make_store();
        let packages = store
            .load_key_packages("https://unknown.relay.com")
            .await
            .unwrap();
        assert!(packages.is_empty());
    }

    // -------------------------------------------------------------------
    // URL hashing
    // -------------------------------------------------------------------

    #[test]
    fn hash_url_produces_consistent_hex() {
        let hash1 = hash_url("https://relay.example.com/v1");
        let hash2 = hash_url("https://relay.example.com/v1");
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // SHA-256 = 32 bytes = 64 hex chars
    }

    #[test]
    fn hash_url_differs_for_different_urls() {
        let hash1 = hash_url("https://relay-a.example.com");
        let hash2 = hash_url("https://relay-b.example.com");
        assert_ne!(hash1, hash2);
    }

    // -------------------------------------------------------------------
    // Key convention tests
    // -------------------------------------------------------------------

    #[test]
    fn relay_score_key_uses_url_hash() {
        let key = relay_score_key("https://relay.example.com");
        assert!(key.starts_with("relay_score/"));
        assert!(!key.contains("https"));
        // Key component is 64-char hex SHA-256.
        let suffix = key.strip_prefix("relay_score/").unwrap();
        assert_eq!(suffix.len(), 64);
    }

    #[test]
    fn key_package_key_uses_10_digit_zero_padding() {
        let key = key_package_key("https://relay.example.com", 42);
        assert!(key.contains("/0000000042"));
    }

    // -------------------------------------------------------------------
    // Certificate pins (spec §9.13)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn store_and_load_cert_pin_roundtrip() {
        let store = make_store();
        let pin_data = b"serialized-cert-pin-data".to_vec();

        store
            .store_cert_pin("wss://relay.example.com/scp/v1", &pin_data)
            .await
            .unwrap();
        let loaded = store
            .load_cert_pin("wss://relay.example.com/scp/v1")
            .await
            .unwrap();
        assert_eq!(loaded, Some(pin_data));
    }

    #[tokio::test]
    async fn load_cert_pin_returns_none_for_missing() {
        let store = make_store();
        let loaded = store
            .load_cert_pin("wss://unknown.relay.com/scp/v1")
            .await
            .unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn delete_cert_pin_removes_stored_data() {
        let store = make_store();
        let pin_data = b"pin-data".to_vec();

        store
            .store_cert_pin("wss://relay.example.com/scp/v1", &pin_data)
            .await
            .unwrap();
        assert!(
            store
                .load_cert_pin("wss://relay.example.com/scp/v1")
                .await
                .unwrap()
                .is_some()
        );

        store
            .delete_cert_pin("wss://relay.example.com/scp/v1")
            .await
            .unwrap();
        assert!(
            store
                .load_cert_pin("wss://relay.example.com/scp/v1")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn cert_pin_key_uses_url_hash() {
        let key = cert_pin_key("wss://relay.example.com/scp/v1");
        assert!(key.starts_with("cert_pin/"));
        let suffix = key.strip_prefix("cert_pin/").unwrap();
        assert_eq!(suffix.len(), 64); // SHA-256 hex
    }
}
