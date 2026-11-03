//! The node's own node key in `ProtocolRepository` (spec section 17.3
//! "Node key"; `09-security-model.md` §9.6.3 "How a node gets its key and
//! its binding").
//!
//! ```text
//! scp/node-key
//! ```
//!
//! The value is a `StoredValue` envelope around the 32-byte P-256 scalar.
//! The serialized buffer is zeroized after the write and after the read,
//! while SCP still owns it; security model spec §9.15 (freed heap memory)
//! lists the copies no wipe reaches. A stored value that does not decode, or
//! whose scalar is no P-256 key, is an error and never reads as no key,
//! because the caller would then draw a fresh key and orphan the binding the
//! operator installed for the stored one.

use scp_platform::traits::Storage;
use scp_protocol::node::NodeSigningKey;
use zeroize::Zeroizing;

use super::{ProtocolRepository, StoreError};

/// Storage key of the node key (spec section 17.3), a top-level singleton.
pub const NODE_KEY_KEY: &str = "scp/node-key";

impl<S: Storage> ProtocolRepository<S> {
    /// Stores the node's node key under `scp/node-key`.
    ///
    /// The node writes it once, on the first start that finds none (spec
    /// section 17.3); this method does not read first, so its caller makes
    /// that check.
    ///
    /// # Errors
    ///
    /// [`StoreError::SerializationFailed`] or [`StoreError::Storage`].
    pub async fn store_node_key(&self, key: &NodeSigningKey) -> Result<(), StoreError> {
        let scalar = key.to_scalar_bytes();
        self.store_value_zeroize(NODE_KEY_KEY, &*scalar).await
    }

    /// Loads the node's node key, or `None` where none is stored.
    ///
    /// # Errors
    ///
    /// [`StoreError::Storage`] when the read fails,
    /// [`StoreError::DeserializationFailed`] or
    /// [`StoreError::IncompatibleVersion`] when the value is no node-key
    /// envelope this build reads, and [`StoreError::InvalidKeyMaterial`]
    /// when its scalar is no P-256 private key.
    pub async fn load_node_key(&self) -> Result<Option<NodeSigningKey>, StoreError> {
        let Some(bytes) = self.storage.retrieve(NODE_KEY_KEY).await? else {
            return Ok(None);
        };
        let bytes = Zeroizing::new(bytes);
        let scalar: Zeroizing<[u8; 32]> = Zeroizing::new(Self::deserialize(&bytes)?);
        NodeSigningKey::from_scalar_bytes(&scalar)
            .map(Some)
            .map_err(|e| StoreError::InvalidKeyMaterial(format!("node key: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use scp_platform::in_memory::InMemoryStorage;
    use scp_platform::store_value::{CURRENT_STORE_VERSION, StoredValue};

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn make_store() -> ProtocolRepository<InMemoryStorage> {
        ProtocolRepository::new_for_testing(InMemoryStorage::new())
    }

    async fn store_envelope(
        store: &ProtocolRepository<InMemoryStorage>,
        version: u16,
        scalar: [u8; 32],
    ) -> TestResult {
        let envelope = StoredValue {
            version,
            data: scalar,
        };
        store
            .storage()
            .store(NODE_KEY_KEY, &rmp_serde::to_vec_named(&envelope)?)
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn a_stored_node_key_loads_as_the_same_key() -> TestResult {
        let store = make_store();
        assert!(store.load_node_key().await?.is_none());
        let key = NodeSigningKey::from_scalar_bytes(&[7; 32])?;
        store.store_node_key(&key).await?;
        let loaded = store.load_node_key().await?.ok_or("no key loaded")?;
        assert_eq!(loaded.node_key(), key.node_key());
        assert_eq!(loaded.node_id(), key.node_id());
        assert!(store.storage().retrieve(NODE_KEY_KEY).await?.is_some());
        Ok(())
    }

    #[tokio::test]
    async fn a_value_that_is_no_envelope_is_an_error_not_absence() -> TestResult {
        let store = make_store();
        store.storage().store(NODE_KEY_KEY, b"not a key").await?;
        assert!(matches!(
            store.load_node_key().await,
            Err(StoreError::DeserializationFailed(_))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn a_zero_scalar_is_invalid_key_material() -> TestResult {
        let store = make_store();
        store_envelope(&store, CURRENT_STORE_VERSION, [0; 32]).await?;
        assert!(matches!(
            store.load_node_key().await,
            Err(StoreError::InvalidKeyMaterial(_))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn a_newer_envelope_is_refused() -> TestResult {
        let store = make_store();
        store_envelope(&store, CURRENT_STORE_VERSION + 1, [7; 32]).await?;
        assert!(matches!(
            store.load_node_key().await,
            Err(StoreError::IncompatibleVersion { .. })
        ));
        Ok(())
    }
}
