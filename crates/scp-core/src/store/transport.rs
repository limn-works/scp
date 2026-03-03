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

use sha2::{Digest, Sha256};

use scp_platform::traits::Storage;

use super::{ProtocolStore, StoreError};

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

// ---------------------------------------------------------------------------
// ProtocolStore — transport methods
// ---------------------------------------------------------------------------

impl<S: Storage> ProtocolStore<S> {
    /// Stores a relay score for a relay URL.
    ///
    /// Serializes the score bytes under `relay_score/{sha256_hex(url)}`
    /// wrapped in a `StoredValue` version envelope.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn store_relay_score(&self, relay_url: &str, score: &[u8]) -> Result<(), StoreError> {
        let key = relay_score_key(relay_url);
        self.store_value(&key, &score.to_vec()).await
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
        self.load_value(&key).await
    }

    /// Lists all relay scores.
    ///
    /// Returns a vector of `(url_hash, score_bytes)` pairs. The URL hash
    /// is the SHA-256 hex of the original URL. Callers that need to map
    /// back to URLs must maintain their own URL-to-hash index.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage operation fails.
    /// Returns [`StoreError::DeserializationFailed`] if any score record fails
    /// to deserialize.
    pub async fn list_relay_scores(&self) -> Result<Vec<(String, Vec<u8>)>, StoreError> {
        let prefix = relay_score_prefix();
        let keys = self.storage.list_keys(prefix).await?;
        let mut results = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some(url_hash) = key.strip_prefix(prefix)
                && let Some(score) = self.load_value::<Vec<u8>>(&key).await?
            {
                results.push((url_hash.to_owned(), score));
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
        ProtocolStore::new(InMemoryStorage::new())
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
    async fn list_relay_scores_returns_all_entries() {
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

        let scores = store.list_relay_scores().await.unwrap();
        assert_eq!(scores.len(), 3);
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
}
