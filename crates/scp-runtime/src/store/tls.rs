//! TLS certificate storage operations for `ProtocolRepository`.
//!
//! Implements certificate chain and private key persistence following the
//! key convention from spec section 17.3:
//!
//! ```text
//! tls/certificate_chain
//! tls/private_key
//! ```
//!
//! The private key is stored via `store_value_zeroize` to clear serialized
//! bytes from memory after the write completes (defense-in-depth).
//!
//! See spec sections 17.3 and 17.4.

use scp_platform::traits::Storage;
use zeroize::Zeroizing;

use super::{ProtocolRepository, StoreError};

// ---------------------------------------------------------------------------
// Key helpers
// ---------------------------------------------------------------------------

/// Storage key for the TLS certificate chain (PEM-encoded).
const CERT_CHAIN_KEY: &str = "tls/certificate_chain";

/// Storage key for the TLS private key (PEM-encoded).
const PRIVATE_KEY_KEY: &str = "tls/private_key";

// ---------------------------------------------------------------------------
// ProtocolRepository — TLS methods
// ---------------------------------------------------------------------------

impl<S: Storage> ProtocolRepository<S> {
    /// Stores a TLS certificate chain and private key.
    ///
    /// The certificate chain and private key are stored as PEM-encoded
    /// strings under `tls/certificate_chain` and `tls/private_key`
    /// respectively, each wrapped in a `StoredValue` version envelope.
    ///
    /// The private key buffer is zeroized after the storage write completes.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn store_tls_certificate(
        &self,
        certificate_chain_pem: &str,
        private_key_pem: &str,
    ) -> Result<(), StoreError> {
        self.store_value(CERT_CHAIN_KEY, &certificate_chain_pem.to_owned())
            .await?;
        self.store_value_zeroize(PRIVATE_KEY_KEY, &private_key_pem.to_owned())
            .await?;
        Ok(())
    }

    /// Loads a TLS certificate chain and private key.
    ///
    /// Returns `None` if no certificate is stored. The private key is
    /// returned as `Zeroizing<String>` so callers cannot accidentally
    /// hold an unprotected copy.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::DeserializationFailed`] if deserialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage read fails.
    pub async fn load_tls_certificate(
        &self,
    ) -> Result<Option<(String, Zeroizing<String>)>, StoreError> {
        let cert: Option<String> = self.load_value(CERT_CHAIN_KEY).await?;
        let key: Option<String> = self.load_value(PRIVATE_KEY_KEY).await?;
        match (cert, key) {
            (Some(c), Some(k)) => Ok(Some((c, Zeroizing::new(k)))),
            _ => Ok(None),
        }
    }

    /// Deletes the stored TLS certificate and private key.
    ///
    /// No-op if no certificate is stored.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage delete fails.
    pub async fn delete_tls_certificate(&self) -> Result<(), StoreError> {
        self.storage.delete(CERT_CHAIN_KEY).await?;
        self.storage.delete(PRIVATE_KEY_KEY).await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use scp_platform::in_memory::InMemoryStorage;

    use super::*;

    fn make_store() -> ProtocolRepository<InMemoryStorage> {
        ProtocolRepository::new_for_testing(InMemoryStorage::new())
    }

    #[tokio::test]
    async fn store_and_load_tls_certificate_roundtrip() {
        let store = make_store();
        let cert_pem = "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----";
        let key_pem = "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----";

        store
            .store_tls_certificate(cert_pem, key_pem)
            .await
            .unwrap();

        let (loaded_cert, loaded_key) = store.load_tls_certificate().await.unwrap().unwrap();
        assert_eq!(loaded_cert, cert_pem);
        assert_eq!(&*loaded_key, key_pem);
    }

    #[tokio::test]
    async fn load_tls_certificate_returns_none_when_empty() {
        let store = make_store();
        let result = store.load_tls_certificate().await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn delete_tls_certificate_removes_both_entries() {
        let store = make_store();
        store.store_tls_certificate("cert", "key").await.unwrap();

        store.delete_tls_certificate().await.unwrap();

        let result = store.load_tls_certificate().await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn partial_storage_returns_none() {
        let store = make_store();
        // Only store the cert, not the key — simulates corruption.
        store
            .store_value(CERT_CHAIN_KEY, &"cert-only".to_owned())
            .await
            .unwrap();

        let result = store.load_tls_certificate().await.unwrap();
        assert!(result.is_none(), "should return None when key is missing");
    }
}
