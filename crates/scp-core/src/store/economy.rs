//! Economic governance storage operations for `ProtocolStore`.
//!
//! Implements adapter credential storage following the key convention from
//! spec section 17.3:
//!
//! ```text
//! identity/{did}/adapter_credentials/{adapter_id}
//! ```
//!
//! Adapter credentials are identity-private state (spec section 19.2.5).
//! They are stored alongside identity keys and never exposed to contexts
//! or relays.
//!
//! See spec sections 17.3, 17.4, and 19.2.5.

use scp_platform::traits::Storage;

use crate::economy::credentials::{AdapterCredential, AdapterCredentialStore, CredentialError};
use crate::identity::DID;

use super::{ProtocolStore, StoreError};

// ---------------------------------------------------------------------------
// Key helpers
// ---------------------------------------------------------------------------

/// Builds the storage key for an adapter credential.
///
/// Format: `identity/{did}/adapter_credentials/{adapter_id}`
/// See spec section 17.3.
fn adapter_credential_key(did: &DID, adapter_id: &str) -> String {
    format!("identity/{did}/adapter_credentials/{adapter_id}")
}

/// Builds the prefix for listing all adapter credentials for an identity.
///
/// Format: `identity/{did}/adapter_credentials/`
fn adapter_credentials_prefix(did: &DID) -> String {
    format!("identity/{did}/adapter_credentials/")
}

// ---------------------------------------------------------------------------
// ProtocolStore — adapter credential methods
// ---------------------------------------------------------------------------

impl<S: Storage> ProtocolStore<S> {
    /// Stores adapter credentials for an identity.
    ///
    /// Stores raw credential bytes under
    /// `identity/{did}/adapter_credentials/{adapter_id}`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn store_adapter_credentials(
        &self,
        did: &DID,
        adapter_id: &str,
        credentials: &[u8],
    ) -> Result<(), StoreError> {
        let key = adapter_credential_key(did, adapter_id);
        self.storage.store(&key, credentials).await?;
        Ok(())
    }

    /// Loads adapter credentials for an identity and adapter.
    ///
    /// Returns `None` if no credentials exist for the given pair.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage read fails.
    pub async fn load_adapter_credentials(
        &self,
        did: &DID,
        adapter_id: &str,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let key = adapter_credential_key(did, adapter_id);
        Ok(self.storage.retrieve(&key).await?)
    }

    /// Lists all configured adapter IDs for an identity.
    ///
    /// Returns adapter_id strings extracted from the stored keys.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage list fails.
    pub async fn list_adapter_credentials(
        &self,
        did: &DID,
    ) -> Result<Vec<String>, StoreError> {
        let prefix = adapter_credentials_prefix(did);
        let keys = self.storage.list_keys(&prefix).await?;
        let adapter_ids: Vec<String> = keys
            .into_iter()
            .filter_map(|key| key.strip_prefix(&prefix).map(String::from))
            .collect();
        Ok(adapter_ids)
    }

    /// Removes adapter credentials for an identity and adapter.
    ///
    /// No-op if the credential does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage delete fails.
    pub async fn remove_adapter_credentials(
        &self,
        did: &DID,
        adapter_id: &str,
    ) -> Result<(), StoreError> {
        let key = adapter_credential_key(did, adapter_id);
        self.storage.delete(&key).await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// AdapterCredentialStore impl for ProtocolStore
// ---------------------------------------------------------------------------

impl<S: Storage> AdapterCredentialStore for ProtocolStore<S> {
    fn store_adapter_credential(
        &self,
        credential: &AdapterCredential,
    ) -> impl std::future::Future<Output = Result<(), CredentialError>> + Send {
        let credential = credential.clone();
        async move {
            let data = rmp_serde::to_vec(&credential).map_err(|e| {
                CredentialError::SerializationFailed(e.to_string())
            })?;
            self.store_adapter_credentials(
                &credential.identity,
                &credential.adapter_id,
                &data,
            )
            .await
            .map_err(|e| CredentialError::StorageError(e.to_string()))
        }
    }

    fn load_adapter_credential(
        &self,
        identity: &DID,
        adapter_id: &str,
    ) -> impl std::future::Future<Output = Result<Option<AdapterCredential>, CredentialError>>
           + Send
    {
        let identity = identity.clone();
        let adapter_id = adapter_id.to_owned();
        async move {
            let data = self
                .load_adapter_credentials(&identity, &adapter_id)
                .await
                .map_err(|e| CredentialError::StorageError(e.to_string()))?;
            match data {
                Some(bytes) => {
                    let credential: AdapterCredential =
                        rmp_serde::from_slice(&bytes).map_err(|e| {
                            CredentialError::DeserializationFailed(e.to_string())
                        })?;
                    Ok(Some(credential))
                }
                None => Ok(None),
            }
        }
    }

    fn list_adapter_credentials(
        &self,
        identity: &DID,
    ) -> impl std::future::Future<Output = Result<Vec<String>, CredentialError>> + Send {
        let identity = identity.clone();
        async move {
            ProtocolStore::list_adapter_credentials(self, &identity)
                .await
                .map_err(|e| CredentialError::StorageError(e.to_string()))
        }
    }

    fn remove_adapter_credential(
        &self,
        identity: &DID,
        adapter_id: &str,
    ) -> impl std::future::Future<Output = Result<(), CredentialError>> + Send {
        let identity = identity.clone();
        let adapter_id = adapter_id.to_owned();
        async move {
            self.remove_adapter_credentials(&identity, &adapter_id)
                .await
                .map_err(|e| CredentialError::StorageError(e.to_string()))
        }
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

    fn test_did() -> DID {
        DID::from("did:dht:z6MkTestHuman")
    }

    fn other_did() -> DID {
        DID::from("did:dht:z6MkOtherHuman")
    }

    fn make_store() -> ProtocolStore<InMemoryStorage> {
        ProtocolStore::new(InMemoryStorage::new())
    }

    // -------------------------------------------------------------------
    // Raw byte storage tests (ProtocolStore methods)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn store_and_load_raw_credentials_roundtrip() {
        let store = make_store();
        let did = test_did();
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];

        store
            .store_adapter_credentials(&did, "x402", &data)
            .await
            .unwrap();

        let loaded = store
            .load_adapter_credentials(&did, "x402")
            .await
            .unwrap();
        assert_eq!(loaded, Some(data));
    }

    #[tokio::test]
    async fn load_nonexistent_raw_credentials_returns_none() {
        let store = make_store();
        let did = test_did();

        let loaded = store
            .load_adapter_credentials(&did, "missing")
            .await
            .unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn list_raw_credentials_returns_adapter_ids() {
        let store = make_store();
        let did = test_did();

        store
            .store_adapter_credentials(&did, "lightning", &[1])
            .await
            .unwrap();
        store
            .store_adapter_credentials(&did, "x402", &[2])
            .await
            .unwrap();

        let mut ids = store.list_adapter_credentials(&did).await.unwrap();
        ids.sort();
        assert_eq!(ids, vec!["lightning", "x402"]);
    }

    #[tokio::test]
    async fn remove_raw_credentials_deletes() {
        let store = make_store();
        let did = test_did();

        store
            .store_adapter_credentials(&did, "x402", &[1])
            .await
            .unwrap();
        store
            .remove_adapter_credentials(&did, "x402")
            .await
            .unwrap();

        let loaded = store
            .load_adapter_credentials(&did, "x402")
            .await
            .unwrap();
        assert!(loaded.is_none());
    }

    // -------------------------------------------------------------------
    // AdapterCredentialStore trait impl tests
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn trait_store_and_load_roundtrip() {
        let store = make_store();
        let did = test_did();

        let credential = AdapterCredential {
            adapter_id: "x402".to_owned(),
            identity: did.clone(),
            encrypted_data: vec![1, 2, 3, 4],
            created_at: 1_700_000_000,
            rotated_at: 1_700_000_000,
        };

        AdapterCredentialStore::store_adapter_credential(&store, &credential)
            .await
            .unwrap();

        let loaded =
            AdapterCredentialStore::load_adapter_credential(&store, &did, "x402")
                .await
                .unwrap();
        assert_eq!(loaded, Some(credential));
    }

    #[tokio::test]
    async fn trait_list_returns_adapter_ids() {
        let store = make_store();
        let did = test_did();

        for adapter_id in &["spl", "x402"] {
            let credential = AdapterCredential {
                adapter_id: (*adapter_id).to_owned(),
                identity: did.clone(),
                encrypted_data: vec![1],
                created_at: 1_700_000_000,
                rotated_at: 1_700_000_000,
            };
            AdapterCredentialStore::store_adapter_credential(&store, &credential)
                .await
                .unwrap();
        }

        let mut ids =
            AdapterCredentialStore::list_adapter_credentials(&store, &did)
                .await
                .unwrap();
        ids.sort();
        assert_eq!(ids, vec!["spl", "x402"]);
    }

    #[tokio::test]
    async fn trait_credentials_isolated_between_identities() {
        let store = make_store();
        let did_a = test_did();
        let did_b = other_did();

        let cred_a = AdapterCredential {
            adapter_id: "x402".to_owned(),
            identity: did_a.clone(),
            encrypted_data: vec![0xAA],
            created_at: 1_700_000_000,
            rotated_at: 1_700_000_000,
        };

        let cred_b = AdapterCredential {
            adapter_id: "x402".to_owned(),
            identity: did_b.clone(),
            encrypted_data: vec![0xBB],
            created_at: 1_700_000_000,
            rotated_at: 1_700_000_000,
        };

        AdapterCredentialStore::store_adapter_credential(&store, &cred_a)
            .await
            .unwrap();
        AdapterCredentialStore::store_adapter_credential(&store, &cred_b)
            .await
            .unwrap();

        let loaded_a =
            AdapterCredentialStore::load_adapter_credential(&store, &did_a, "x402")
                .await
                .unwrap()
                .unwrap();
        let loaded_b =
            AdapterCredentialStore::load_adapter_credential(&store, &did_b, "x402")
                .await
                .unwrap()
                .unwrap();

        assert_eq!(loaded_a.encrypted_data, vec![0xAA]);
        assert_eq!(loaded_b.encrypted_data, vec![0xBB]);
    }

    #[tokio::test]
    async fn trait_remove_deletes_credential() {
        let store = make_store();
        let did = test_did();

        let credential = AdapterCredential {
            adapter_id: "x402".to_owned(),
            identity: did.clone(),
            encrypted_data: vec![1],
            created_at: 1_700_000_000,
            rotated_at: 1_700_000_000,
        };

        AdapterCredentialStore::store_adapter_credential(&store, &credential)
            .await
            .unwrap();
        AdapterCredentialStore::remove_adapter_credential(&store, &did, "x402")
            .await
            .unwrap();

        let loaded =
            AdapterCredentialStore::load_adapter_credential(&store, &did, "x402")
                .await
                .unwrap();
        assert!(loaded.is_none());
    }

    // -------------------------------------------------------------------
    // Key convention tests
    // -------------------------------------------------------------------

    #[test]
    fn adapter_credential_key_follows_convention() {
        let did = DID::from("did:dht:z6MkTest");
        let key = adapter_credential_key(&did, "x402");
        assert_eq!(key, "identity/did:dht:z6MkTest/adapter_credentials/x402");
    }

    #[test]
    fn adapter_credentials_prefix_follows_convention() {
        let did = DID::from("did:dht:z6MkTest");
        let prefix = adapter_credentials_prefix(&did);
        assert_eq!(
            prefix,
            "identity/did:dht:z6MkTest/adapter_credentials/"
        );
    }
}
