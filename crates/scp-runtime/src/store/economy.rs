//! Economic governance storage operations for `ProtocolRepository`.
//!
//! Implements adapter credential storage, economic policy, payment receipts,
//! and spending UCAN persistence following the key convention from spec
//! section 17.3:
//!
//! ```text
//! identity/{did}/adapter_credentials/{adapter_id}
//! context/{context_id}/economic_policy
//! context/{context_id}/payment_receipt/{receipt_id_hex}
//! context/{context_id}/spending_ucan/{token_id}
//! ```
//!
//! Adapter credentials are identity-private state (spec section 19.2.5).
//! They are stored alongside identity keys and never exposed to contexts
//! or relays.
//!
//! See spec sections 17.3, 17.4, and 19.2.5.
//! See SCP-PERSIST-015 and SCP-PERSIST-016.

use scp_platform::traits::Storage;

use crate::economy::credentials::{AdapterCredential, AdapterCredentialStore, CredentialError};
use scp_did::DID;

use super::{ProtocolRepository, StoreError};

// ---------------------------------------------------------------------------
// Key helpers
// ---------------------------------------------------------------------------

/// Builds the storage key for an adapter credential.
///
/// Format: `identity/{did}/adapter_credentials/{adapter_id}`
/// See spec section 17.3.
fn adapter_credential_key(did: &DID, adapter_id: &str) -> Result<String, super::StoreError> {
    let did_str = super::sanitize_key_component(did.as_ref())?;
    let adapter = super::sanitize_key_component(adapter_id)?;
    Ok(format!("identity/{did_str}/adapter_credentials/{adapter}"))
}

/// Builds the prefix for listing all adapter credentials for an identity.
///
/// Format: `identity/{did}/adapter_credentials/`
fn adapter_credentials_prefix(did: &DID) -> Result<String, super::StoreError> {
    let did_str = super::sanitize_key_component(did.as_ref())?;
    Ok(format!("identity/{did_str}/adapter_credentials/"))
}

/// Builds the storage key for an economic policy within a context.
///
/// Format: `context/{context_id}/economic_policy`
/// See spec section 17.3.
fn economic_policy_key(context_id: &str) -> Result<String, super::StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    Ok(format!("context/{ctx}/economic_policy"))
}

/// Builds the storage key for a payment receipt within a context.
///
/// Format: `context/{context_id}/payment_receipt/{receipt_id_hex}`
/// See spec section 17.3.
fn payment_receipt_key(
    context_id: &str,
    receipt_id: &[u8; 32],
) -> Result<String, super::StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    let receipt_hex = hex::encode(receipt_id);
    Ok(format!("context/{ctx}/payment_receipt/{receipt_hex}"))
}

/// Builds the prefix for listing all payment receipts in a context.
///
/// Format: `context/{context_id}/payment_receipt/`
fn payment_receipts_prefix(context_id: &str) -> Result<String, super::StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    Ok(format!("context/{ctx}/payment_receipt/"))
}

/// Builds the storage key for a spending UCAN within a context.
///
/// Format: `context/{context_id}/spending_ucan/{token_id}`
/// See spec section 17.3.
fn spending_ucan_key(context_id: &str, token_id: &str) -> Result<String, super::StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    let tok = super::sanitize_key_component(token_id)?;
    Ok(format!("context/{ctx}/spending_ucan/{tok}"))
}

/// Builds the prefix for listing all spending UCANs in a context.
///
/// Format: `context/{context_id}/spending_ucan/`
fn spending_ucans_prefix(context_id: &str) -> Result<String, super::StoreError> {
    let ctx = super::sanitize_key_component(context_id)?;
    Ok(format!("context/{ctx}/spending_ucan/"))
}

// ---------------------------------------------------------------------------
// ProtocolRepository — adapter credential methods
// ---------------------------------------------------------------------------

impl<S: Storage> ProtocolRepository<S> {
    /// Stores adapter credentials for an identity.
    ///
    /// Serializes credential bytes under
    /// `identity/{did}/adapter_credentials/{adapter_id}` wrapped
    /// in a `StoredValue` version envelope.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn store_adapter_credentials(
        &self,
        did: &DID,
        adapter_id: &str,
        credentials: &[u8],
    ) -> Result<(), StoreError> {
        let key = adapter_credential_key(did, adapter_id)?;
        self.store_value_zeroize(&key, &credentials.to_vec()).await
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
        let key = adapter_credential_key(did, adapter_id)?;
        self.load_value(&key).await
    }

    /// Lists all configured adapter IDs for an identity.
    ///
    /// Returns `adapter_id` strings extracted from the stored keys.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage list fails.
    pub async fn list_adapter_credentials(&self, did: &DID) -> Result<Vec<String>, StoreError> {
        let prefix = adapter_credentials_prefix(did)?;
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
        let key = adapter_credential_key(did, adapter_id)?;
        self.storage.delete(&key).await?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Economic policy methods (SCP-PERSIST-015)
    // -----------------------------------------------------------------------

    /// Stores an economic policy for a context.
    ///
    /// Serializes the policy bytes under
    /// `context/{context_id}/economic_policy` wrapped in a
    /// `StoredValue` version envelope.
    ///
    /// See spec section 17.4. See SCP-PERSIST-015.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn store_economic_policy(
        &self,
        context_id: &str,
        policy: &[u8],
    ) -> Result<(), StoreError> {
        let key = economic_policy_key(context_id)?;
        self.store_value(&key, &policy.to_vec()).await
    }

    /// Loads an economic policy for a context.
    ///
    /// Returns `None` if no economic policy exists for the given context.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::DeserializationFailed`] if deserialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage read fails.
    pub async fn load_economic_policy(
        &self,
        context_id: &str,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let key = economic_policy_key(context_id)?;
        self.load_value(&key).await
    }

    // -----------------------------------------------------------------------
    // Payment receipt methods (SCP-PERSIST-015)
    // -----------------------------------------------------------------------

    /// Stores a payment receipt within a context.
    ///
    /// Serializes the receipt bytes under
    /// `context/{context_id}/payment_receipt/{receipt_id_hex}` wrapped
    /// in a `StoredValue` version envelope.
    ///
    /// See spec section 17.4. See SCP-PERSIST-015.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn store_payment_receipt(
        &self,
        context_id: &str,
        receipt_id: &[u8; 32],
        receipt: &[u8],
    ) -> Result<(), StoreError> {
        let key = payment_receipt_key(context_id, receipt_id)?;
        self.store_value(&key, &receipt.to_vec()).await
    }

    /// Loads a payment receipt from a context.
    ///
    /// Returns `None` if no receipt with the given ID exists.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::DeserializationFailed`] if deserialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage read fails.
    pub async fn load_payment_receipt(
        &self,
        context_id: &str,
        receipt_id: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let key = payment_receipt_key(context_id, receipt_id)?;
        self.load_value(&key).await
    }

    /// Lists all payment receipt IDs for a context.
    ///
    /// Returns the 32-byte receipt IDs extracted from stored keys.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage operation fails.
    pub async fn list_payment_receipts(
        &self,
        context_id: &str,
    ) -> Result<Vec<[u8; 32]>, StoreError> {
        let prefix = payment_receipts_prefix(context_id)?;
        let keys = self.storage.list_keys(&prefix).await?;
        let mut receipt_ids = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some(hex_str) = key.strip_prefix(&prefix)
                && let Ok(bytes) = hex::decode(hex_str)
                && let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice())
            {
                receipt_ids.push(arr);
            }
        }
        Ok(receipt_ids)
    }

    // -----------------------------------------------------------------------
    // Spending UCAN methods (SCP-PERSIST-016)
    // -----------------------------------------------------------------------

    /// Stores a spending UCAN within a context.
    ///
    /// Serializes the UCAN bytes under
    /// `context/{context_id}/spending_ucan/{token_id}` wrapped in a
    /// `StoredValue` version envelope.
    ///
    /// See spec section 17.4. See SCP-PERSIST-016.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::SerializationFailed`] if serialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage write fails.
    pub async fn store_spending_ucan(
        &self,
        context_id: &str,
        token_id: &str,
        ucan: &[u8],
    ) -> Result<(), StoreError> {
        let key = spending_ucan_key(context_id, token_id)?;
        self.store_value_zeroize(&key, &ucan.to_vec()).await
    }

    /// Loads a spending UCAN from a context.
    ///
    /// Returns `None` if no UCAN with the given token ID exists.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::DeserializationFailed`] if deserialization fails.
    /// Returns [`StoreError::Storage`] if the underlying storage read fails.
    pub async fn load_spending_ucan(
        &self,
        context_id: &str,
        token_id: &str,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let key = spending_ucan_key(context_id, token_id)?;
        self.load_value(&key).await
    }

    /// Lists all spending UCAN token IDs for a context.
    ///
    /// Returns token ID strings extracted from stored keys.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Storage`] if the underlying storage operation fails.
    pub async fn list_spending_ucans(&self, context_id: &str) -> Result<Vec<String>, StoreError> {
        let prefix = spending_ucans_prefix(context_id)?;
        let keys = self.storage.list_keys(&prefix).await?;
        let token_ids: Vec<String> = keys
            .into_iter()
            .filter_map(|key| key.strip_prefix(&prefix).map(String::from))
            .collect();
        Ok(token_ids)
    }
}

// ---------------------------------------------------------------------------
// AdapterCredentialStore impl for ProtocolRepository
// ---------------------------------------------------------------------------

impl<S: Storage> AdapterCredentialStore for ProtocolRepository<S> {
    fn store_adapter_credential(
        &self,
        credential: &AdapterCredential,
    ) -> impl std::future::Future<Output = Result<(), CredentialError>> + Send {
        let credential = credential.clone();
        async move {
            let data = rmp_serde::to_vec(&credential)
                .map_err(|e| CredentialError::SerializationFailed(e.to_string()))?;
            self.store_adapter_credentials(&credential.identity, &credential.adapter_id, &data)
                .await
                .map_err(|e| CredentialError::StorageError(e.to_string()))
        }
    }

    fn load_adapter_credential(
        &self,
        identity: &DID,
        adapter_id: &str,
    ) -> impl std::future::Future<Output = Result<Option<AdapterCredential>, CredentialError>> + Send
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
                    let credential: AdapterCredential = rmp_serde::from_slice(&bytes)
                        .map_err(|e| CredentialError::DeserializationFailed(e.to_string()))?;
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
            Self::list_adapter_credentials(self, &identity)
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
    use crate::economy::credentials::EncryptedBlob;

    fn test_did() -> DID {
        DID::from("did:dht:z6MkTestHuman")
    }

    fn other_did() -> DID {
        DID::from("did:dht:z6MkOtherHuman")
    }

    fn make_store() -> ProtocolRepository<InMemoryStorage> {
        ProtocolRepository::new_for_testing(InMemoryStorage::new())
    }

    // -------------------------------------------------------------------
    // Raw byte storage tests (ProtocolRepository methods)
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

        let loaded = store.load_adapter_credentials(&did, "x402").await.unwrap();
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

        let loaded = store.load_adapter_credentials(&did, "x402").await.unwrap();
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
            encrypted_data: EncryptedBlob::from_encrypted(vec![1, 2, 3, 4]),
            created_at: 1_700_000_000,
            rotated_at: 1_700_000_000,
        };

        AdapterCredentialStore::store_adapter_credential(&store, &credential)
            .await
            .unwrap();

        let loaded = AdapterCredentialStore::load_adapter_credential(&store, &did, "x402")
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
                encrypted_data: EncryptedBlob::from_encrypted(vec![1]),
                created_at: 1_700_000_000,
                rotated_at: 1_700_000_000,
            };
            AdapterCredentialStore::store_adapter_credential(&store, &credential)
                .await
                .unwrap();
        }

        let mut ids = AdapterCredentialStore::list_adapter_credentials(&store, &did)
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
            encrypted_data: EncryptedBlob::from_encrypted(vec![0xAA]),
            created_at: 1_700_000_000,
            rotated_at: 1_700_000_000,
        };

        let cred_b = AdapterCredential {
            adapter_id: "x402".to_owned(),
            identity: did_b.clone(),
            encrypted_data: EncryptedBlob::from_encrypted(vec![0xBB]),
            created_at: 1_700_000_000,
            rotated_at: 1_700_000_000,
        };

        AdapterCredentialStore::store_adapter_credential(&store, &cred_a)
            .await
            .unwrap();
        AdapterCredentialStore::store_adapter_credential(&store, &cred_b)
            .await
            .unwrap();

        let loaded_a = AdapterCredentialStore::load_adapter_credential(&store, &did_a, "x402")
            .await
            .unwrap()
            .unwrap();
        let loaded_b = AdapterCredentialStore::load_adapter_credential(&store, &did_b, "x402")
            .await
            .unwrap()
            .unwrap();

        assert_eq!(loaded_a.encrypted_data.as_bytes(), &[0xAA]);
        assert_eq!(loaded_b.encrypted_data.as_bytes(), &[0xBB]);
    }

    #[tokio::test]
    async fn trait_remove_deletes_credential() {
        let store = make_store();
        let did = test_did();

        let credential = AdapterCredential {
            adapter_id: "x402".to_owned(),
            identity: did.clone(),
            encrypted_data: EncryptedBlob::from_encrypted(vec![1]),
            created_at: 1_700_000_000,
            rotated_at: 1_700_000_000,
        };

        AdapterCredentialStore::store_adapter_credential(&store, &credential)
            .await
            .unwrap();
        AdapterCredentialStore::remove_adapter_credential(&store, &did, "x402")
            .await
            .unwrap();

        let loaded = AdapterCredentialStore::load_adapter_credential(&store, &did, "x402")
            .await
            .unwrap();
        assert!(loaded.is_none());
    }

    // -------------------------------------------------------------------
    // Economic policy (SCP-PERSIST-015)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn store_and_load_economic_policy_roundtrip() {
        let store = make_store();
        let policy = b"economic-policy-bytes".to_vec();

        store.store_economic_policy("ctx-1", &policy).await.unwrap();
        let loaded = store.load_economic_policy("ctx-1").await.unwrap();
        assert_eq!(loaded, Some(policy));
    }

    #[tokio::test]
    async fn load_economic_policy_returns_none_for_missing() {
        let store = make_store();
        let loaded = store.load_economic_policy("ctx-1").await.unwrap();
        assert!(loaded.is_none());
    }

    // -------------------------------------------------------------------
    // Payment receipts (SCP-PERSIST-015)
    // -------------------------------------------------------------------

    fn test_receipt_id(byte: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = byte;
        id
    }

    #[tokio::test]
    async fn store_and_load_payment_receipt_roundtrip() {
        let store = make_store();
        let receipt_id = test_receipt_id(0xAA);
        let receipt = b"receipt-data".to_vec();

        store
            .store_payment_receipt("ctx-1", &receipt_id, &receipt)
            .await
            .unwrap();
        let loaded = store
            .load_payment_receipt("ctx-1", &receipt_id)
            .await
            .unwrap();
        assert_eq!(loaded, Some(receipt));
    }

    #[tokio::test]
    async fn load_payment_receipt_returns_none_for_missing() {
        let store = make_store();
        let receipt_id = test_receipt_id(0xBB);
        let loaded = store
            .load_payment_receipt("ctx-1", &receipt_id)
            .await
            .unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn list_payment_receipts_returns_all_ids() {
        let store = make_store();
        let id_a = test_receipt_id(0xAA);
        let id_b = test_receipt_id(0xBB);

        store
            .store_payment_receipt("ctx-1", &id_a, b"receipt-a")
            .await
            .unwrap();
        store
            .store_payment_receipt("ctx-1", &id_b, b"receipt-b")
            .await
            .unwrap();

        let ids = store.list_payment_receipts("ctx-1").await.unwrap();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&id_a));
        assert!(ids.contains(&id_b));
    }

    // -------------------------------------------------------------------
    // Spending UCANs (SCP-PERSIST-016)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn store_and_load_spending_ucan_roundtrip() {
        let store = make_store();
        let ucan = b"spending-ucan-body".to_vec();

        store
            .store_spending_ucan("ctx-1", "spend-tok-1", &ucan)
            .await
            .unwrap();
        let loaded = store
            .load_spending_ucan("ctx-1", "spend-tok-1")
            .await
            .unwrap();
        assert_eq!(loaded, Some(ucan));
    }

    #[tokio::test]
    async fn load_spending_ucan_returns_none_for_missing() {
        let store = make_store();
        let loaded = store
            .load_spending_ucan("ctx-1", "nonexistent")
            .await
            .unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn list_spending_ucans_returns_all_token_ids() {
        let store = make_store();

        store
            .store_spending_ucan("ctx-1", "spend-aaa", b"ucan-a")
            .await
            .unwrap();
        store
            .store_spending_ucan("ctx-1", "spend-bbb", b"ucan-b")
            .await
            .unwrap();

        let ids = store.list_spending_ucans("ctx-1").await.unwrap();
        assert_eq!(ids, vec!["spend-aaa", "spend-bbb"]);
    }

    // -------------------------------------------------------------------
    // Key convention tests
    // -------------------------------------------------------------------

    #[test]
    fn economic_policy_key_follows_convention() {
        assert_eq!(
            economic_policy_key("ctx-123").unwrap(),
            "context/ctx-123/economic_policy"
        );
    }

    #[test]
    fn payment_receipt_key_follows_convention() {
        let id = test_receipt_id(0xFF);
        let key = payment_receipt_key("ctx-123", &id).unwrap();
        assert!(key.starts_with("context/ctx-123/payment_receipt/"));
        assert!(key.contains("ff"));
    }

    #[test]
    fn spending_ucan_key_follows_convention() {
        assert_eq!(
            spending_ucan_key("ctx-123", "tok-abc").unwrap(),
            "context/ctx-123/spending_ucan/tok-abc"
        );
    }

    #[test]
    fn adapter_credential_key_follows_convention() {
        let did = DID::from("did:dht:z6MkTest");
        let key = adapter_credential_key(&did, "x402").unwrap();
        assert_eq!(key, "identity/did:dht:z6MkTest/adapter_credentials/x402");
    }

    #[test]
    fn adapter_credentials_prefix_follows_convention() {
        let did = DID::from("did:dht:z6MkTest");
        let prefix = adapter_credentials_prefix(&did).unwrap();
        assert_eq!(prefix, "identity/did:dht:z6MkTest/adapter_credentials/");
    }
}
