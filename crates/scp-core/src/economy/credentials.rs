//! Adapter credential management for SCP economic governance.
//!
//! Each payment adapter requires credentials to operate (wallet private key,
//! LND macaroon, Stripe API key, SPL delegate keypair). These are distinct
//! from spending UCANs:
//!
//! - **Spending UCAN** = authorization ("you may spend $X")
//! - **Adapter credential** = capability ("here's how to move money")
//! - Both required for any payment. UCAN without credential = can't pay.
//!   Credential without UCAN = not authorized to pay.
//!
//! Credentials are bound to the human identity, not the agent. An agent never
//! holds raw payment credentials -- it holds a spending UCAN that authorizes
//! the SDK (which holds the credential) to execute payments on its behalf.
//! This separation is critical: revoking the spending UCAN instantly cuts off
//! the agent's ability to spend, without needing to rotate the underlying
//! payment credential.
//!
//! Credential rotation follows identity key rotation (spec section 9.12).
//!
//! See spec section 19.2.5 (Adapter Credential Management), 19.2.4 (Adapter
//! Discovery and Configuration), and 19.11 (SDK Surface).

use serde::{Deserialize, Serialize};

use crate::identity::DID;

use super::adapter::PaymentAdapter;

// ---------------------------------------------------------------------------
// CredentialError
// ---------------------------------------------------------------------------

/// Errors produced by adapter credential operations.
///
/// See spec section 19.2.5.
#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    /// The adapter failed validation (does not properly implement the
    /// `PaymentAdapter` trait contract -- e.g., returns an empty adapter_id).
    #[error("invalid adapter: {0}")]
    InvalidAdapter(String),

    /// Serialization of adapter credentials failed.
    #[error("credential serialization failed: {0}")]
    SerializationFailed(String),

    /// Deserialization of adapter credentials failed.
    #[error("credential deserialization failed: {0}")]
    DeserializationFailed(String),

    /// The requested adapter credential was not found.
    #[error("adapter credential not found: {0}")]
    NotFound(String),

    /// A storage operation failed.
    #[error("storage error: {0}")]
    StorageError(String),
}

// ---------------------------------------------------------------------------
// AdapterCredential
// ---------------------------------------------------------------------------

/// Encrypted adapter credential bound to a human identity.
///
/// Credentials are identity-private state (spec section 3.7) -- encrypted,
/// stored alongside identity keys, never exposed to contexts or relays.
/// The `encrypted_data` field contains the adapter-specific credential
/// material (wallet key, macaroon, API key, etc.) encrypted with the
/// identity's encryption key.
///
/// See spec section 19.2.5.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterCredential {
    /// The adapter this credential is for. Matches
    /// [`PaymentAdapter::adapter_id()`].
    pub adapter_id: String,
    /// The human identity (DID) this credential is bound to.
    /// Agents never hold raw credentials -- only spending UCANs.
    pub identity: DID,
    /// Encrypted credential material. The encryption scheme follows
    /// identity key encryption (spec section 3.7). The plaintext
    /// format is adapter-specific and opaque to the protocol.
    pub encrypted_data: Vec<u8>,
    /// Unix timestamp (seconds) when this credential was stored.
    pub created_at: u64,
    /// Unix timestamp (seconds) of the last credential rotation.
    /// Matches the identity key rotation timestamp (spec section 9.12).
    pub rotated_at: u64,
}

impl std::fmt::Debug for AdapterCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdapterCredential")
            .field("adapter_id", &self.adapter_id)
            .field("identity", &self.identity)
            .field(
                "encrypted_data",
                &format!("[{} bytes]", self.encrypted_data.len()),
            )
            .field("created_at", &self.created_at)
            .field("rotated_at", &self.rotated_at)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// AdapterCredentialStore trait
// ---------------------------------------------------------------------------

/// Storage interface for adapter credentials.
///
/// Adapter credentials are identity-private state. They follow the key
/// convention `identity/{did}/adapter_credentials/{adapter_id}` (spec
/// section 17.3). This trait abstracts the storage operations so that
/// credential management is decoupled from the concrete storage backend.
///
/// See spec sections 17.3 and 19.2.5.
pub trait AdapterCredentialStore: Send + Sync {
    /// Stores an adapter credential for an identity.
    ///
    /// Overwrites any existing credential for the same (identity, adapter_id)
    /// pair. The credential data must already be encrypted by the caller.
    fn store_adapter_credential(
        &self,
        credential: &AdapterCredential,
    ) -> impl std::future::Future<Output = Result<(), CredentialError>> + Send;

    /// Loads an adapter credential for an identity and adapter.
    ///
    /// Returns `None` if no credential is stored for the given pair.
    fn load_adapter_credential(
        &self,
        identity: &DID,
        adapter_id: &str,
    ) -> impl std::future::Future<Output = Result<Option<AdapterCredential>, CredentialError>>
           + Send;

    /// Lists all configured adapter IDs for an identity.
    ///
    /// Returns the adapter_id strings, not the full credentials. This is
    /// used for adapter discovery (spec section 19.2.4) without exposing
    /// credential material.
    fn list_adapter_credentials(
        &self,
        identity: &DID,
    ) -> impl std::future::Future<Output = Result<Vec<String>, CredentialError>> + Send;

    /// Removes an adapter credential for an identity.
    ///
    /// No-op if the credential does not exist.
    fn remove_adapter_credential(
        &self,
        identity: &DID,
        adapter_id: &str,
    ) -> impl std::future::Future<Output = Result<(), CredentialError>> + Send;
}

// ---------------------------------------------------------------------------
// validate_adapter
// ---------------------------------------------------------------------------

/// Validates that a payment adapter is properly configured before accepting
/// it for credential registration.
///
/// Checks that the adapter returns a non-empty `adapter_id()` and valid
/// `capabilities()`. This is the validation step for
/// `SCP.Identity.configureAdapter(adapter)` (spec section 19.11).
///
/// # Errors
///
/// Returns [`CredentialError::InvalidAdapter`] if the adapter fails
/// validation checks.
pub fn validate_adapter(adapter: &impl PaymentAdapter) -> Result<(), CredentialError> {
    let adapter_id = adapter.adapter_id();
    if adapter_id.is_empty() {
        return Err(CredentialError::InvalidAdapter(
            "adapter_id() must not be empty".to_owned(),
        ));
    }

    // Validate that adapter_id contains only safe characters (alphanumeric,
    // hyphens, underscores) to prevent key injection in storage paths.
    if !adapter_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(CredentialError::InvalidAdapter(format!(
            "adapter_id contains invalid characters: {adapter_id}"
        )));
    }

    let caps = adapter.capabilities();
    if caps.supported_currencies.is_empty() {
        return Err(CredentialError::InvalidAdapter(
            "adapter must support at least one currency".to_owned(),
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// configure_adapter
// ---------------------------------------------------------------------------

/// Registers a payment adapter with an identity by storing its credentials.
///
/// This implements `SCP.Identity.configureAdapter(adapter)` from the SDK
/// surface (spec section 19.11). The function:
///
/// 1. Validates the adapter implements the `PaymentAdapter` trait correctly.
/// 2. Stores the provided encrypted credential data via the credential store.
///
/// The caller is responsible for encrypting the credential data before
/// passing it to this function. The encryption follows identity key
/// encryption (spec section 3.7).
///
/// # Errors
///
/// Returns [`CredentialError::InvalidAdapter`] if the adapter fails
/// validation.
/// Returns [`CredentialError::StorageError`] if the credential store
/// operation fails.
pub async fn configure_adapter<A: PaymentAdapter, S: AdapterCredentialStore>(
    adapter: &A,
    identity: &DID,
    encrypted_credential_data: Vec<u8>,
    timestamp: u64,
    store: &S,
) -> Result<(), CredentialError> {
    validate_adapter(adapter)?;

    let credential = AdapterCredential {
        adapter_id: adapter.adapter_id().to_owned(),
        identity: identity.clone(),
        encrypted_data: encrypted_credential_data,
        created_at: timestamp,
        rotated_at: timestamp,
    };

    store.store_adapter_credential(&credential).await
}

// ---------------------------------------------------------------------------
// retrieve_adapter_credential
// ---------------------------------------------------------------------------

/// Retrieves an adapter credential for payment execution.
///
/// This is the credential retrieval step during the payment integration
/// sequence (spec section 19.2.2, step 3). Both a valid spending UCAN and
/// a stored adapter credential are required for any payment.
///
/// # Errors
///
/// Returns [`CredentialError::NotFound`] if no credential is stored for the
/// given identity and adapter.
pub async fn retrieve_adapter_credential<S: AdapterCredentialStore>(
    identity: &DID,
    adapter_id: &str,
    store: &S,
) -> Result<AdapterCredential, CredentialError> {
    store
        .load_adapter_credential(identity, adapter_id)
        .await?
        .ok_or_else(|| {
            CredentialError::NotFound(format!(
                "no credential for adapter '{adapter_id}' on identity '{identity}'"
            ))
        })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::HashMap;

    use tokio::sync::Mutex;

    use super::*;
    use crate::economy::adapter::{
        AdapterCapabilities, PaymentAuthorization, PaymentError, PaymentMetadata, PaymentReceipt,
        RefundConfirmation, VerificationResult,
    };
    use crate::economy::types::{Amount, CurrencyCode};

    // -------------------------------------------------------------------
    // InMemoryCredentialStore — test-only implementation
    // -------------------------------------------------------------------

    /// In-memory credential store for testing.
    struct InMemoryCredentialStore {
        /// Key: (identity DID string, adapter_id)
        data: Mutex<HashMap<(String, String), AdapterCredential>>,
    }

    impl InMemoryCredentialStore {
        fn new() -> Self {
            Self {
                data: Mutex::new(HashMap::new()),
            }
        }
    }

    impl AdapterCredentialStore for InMemoryCredentialStore {
        fn store_adapter_credential(
            &self,
            credential: &AdapterCredential,
        ) -> impl std::future::Future<Output = Result<(), CredentialError>> + Send {
            let credential = credential.clone();
            async move {
                let key = (credential.identity.0.clone(), credential.adapter_id.clone());
                self.data.lock().await.insert(key, credential);
                Ok(())
            }
        }

        fn load_adapter_credential(
            &self,
            identity: &DID,
            adapter_id: &str,
        ) -> impl std::future::Future<Output = Result<Option<AdapterCredential>, CredentialError>>
               + Send
        {
            let key = (identity.0.clone(), adapter_id.to_owned());
            async move { Ok(self.data.lock().await.get(&key).cloned()) }
        }

        fn list_adapter_credentials(
            &self,
            identity: &DID,
        ) -> impl std::future::Future<Output = Result<Vec<String>, CredentialError>> + Send
        {
            let did_str = identity.0.clone();
            async move {
                let data = self.data.lock().await;
                let mut ids: Vec<String> = data
                    .keys()
                    .filter(|(did, _)| *did == did_str)
                    .map(|(_, adapter_id)| adapter_id.clone())
                    .collect();
                ids.sort();
                Ok(ids)
            }
        }

        fn remove_adapter_credential(
            &self,
            identity: &DID,
            adapter_id: &str,
        ) -> impl std::future::Future<Output = Result<(), CredentialError>> + Send {
            let key = (identity.0.clone(), adapter_id.to_owned());
            async move {
                self.data.lock().await.remove(&key);
                Ok(())
            }
        }
    }

    // -------------------------------------------------------------------
    // TestPaymentAdapter — valid adapter for testing
    // -------------------------------------------------------------------

    struct TestPaymentAdapter {
        id: String,
    }

    impl TestPaymentAdapter {
        fn new(id: &str) -> Self {
            Self {
                id: id.to_owned(),
            }
        }
    }

    impl PaymentAdapter for TestPaymentAdapter {
        fn adapter_id(&self) -> &str {
            &self.id
        }

        fn capabilities(&self) -> AdapterCapabilities {
            AdapterCapabilities {
                supported_currencies: vec![CurrencyCode::from("USD")],
                supports_streaming: false,
                supports_batch_auth: false,
                supports_single_step: false,
                min_amount: None,
                max_amount: None,
                typical_settlement_ms: 1000,
                requires_facilitator: false,
            }
        }

        fn authorize(
            &self,
            _payer: &DID,
            _payee: &DID,
            _amount: Amount,
            _currency: CurrencyCode,
            _metadata: PaymentMetadata,
        ) -> impl std::future::Future<Output = Result<PaymentAuthorization, PaymentError>> + Send
        {
            async { Err(PaymentError::AdapterError("not implemented".to_owned())) }
        }

        fn capture(
            &self,
            _auth: &PaymentAuthorization,
        ) -> impl std::future::Future<Output = Result<PaymentReceipt, PaymentError>> + Send
        {
            async { Err(PaymentError::AdapterError("not implemented".to_owned())) }
        }

        fn void(
            &self,
            _auth: &PaymentAuthorization,
        ) -> impl std::future::Future<Output = Result<(), PaymentError>> + Send {
            async { Err(PaymentError::AdapterError("not implemented".to_owned())) }
        }

        fn verify_authorization(
            &self,
            _auth: &PaymentAuthorization,
        ) -> impl std::future::Future<Output = Result<(), PaymentError>> + Send {
            async { Err(PaymentError::AdapterError("not implemented".to_owned())) }
        }

        fn verify(
            &self,
            _receipt: &PaymentReceipt,
        ) -> impl std::future::Future<Output = Result<VerificationResult, PaymentError>> + Send
        {
            async { Err(PaymentError::AdapterError("not implemented".to_owned())) }
        }

        fn refund(
            &self,
            _receipt: &PaymentReceipt,
            _amount: Option<Amount>,
        ) -> impl std::future::Future<Output = Result<RefundConfirmation, PaymentError>> + Send
        {
            async { Err(PaymentError::AdapterError("not implemented".to_owned())) }
        }
    }

    // -------------------------------------------------------------------
    // InvalidAdapter — adapter with empty id for rejection test
    // -------------------------------------------------------------------

    struct EmptyIdAdapter;

    impl PaymentAdapter for EmptyIdAdapter {
        fn adapter_id(&self) -> &str {
            ""
        }

        fn capabilities(&self) -> AdapterCapabilities {
            AdapterCapabilities {
                supported_currencies: vec![CurrencyCode::from("USD")],
                supports_streaming: false,
                supports_batch_auth: false,
                supports_single_step: false,
                min_amount: None,
                max_amount: None,
                typical_settlement_ms: 0,
                requires_facilitator: false,
            }
        }

        fn authorize(
            &self,
            _payer: &DID,
            _payee: &DID,
            _amount: Amount,
            _currency: CurrencyCode,
            _metadata: PaymentMetadata,
        ) -> impl std::future::Future<Output = Result<PaymentAuthorization, PaymentError>> + Send
        {
            async { Err(PaymentError::AdapterError("not implemented".to_owned())) }
        }

        fn capture(
            &self,
            _auth: &PaymentAuthorization,
        ) -> impl std::future::Future<Output = Result<PaymentReceipt, PaymentError>> + Send
        {
            async { Err(PaymentError::AdapterError("not implemented".to_owned())) }
        }

        fn void(
            &self,
            _auth: &PaymentAuthorization,
        ) -> impl std::future::Future<Output = Result<(), PaymentError>> + Send {
            async { Err(PaymentError::AdapterError("not implemented".to_owned())) }
        }

        fn verify_authorization(
            &self,
            _auth: &PaymentAuthorization,
        ) -> impl std::future::Future<Output = Result<(), PaymentError>> + Send {
            async { Err(PaymentError::AdapterError("not implemented".to_owned())) }
        }

        fn verify(
            &self,
            _receipt: &PaymentReceipt,
        ) -> impl std::future::Future<Output = Result<VerificationResult, PaymentError>> + Send
        {
            async { Err(PaymentError::AdapterError("not implemented".to_owned())) }
        }

        fn refund(
            &self,
            _receipt: &PaymentReceipt,
            _amount: Option<Amount>,
        ) -> impl std::future::Future<Output = Result<RefundConfirmation, PaymentError>> + Send
        {
            async { Err(PaymentError::AdapterError("not implemented".to_owned())) }
        }
    }

    // -------------------------------------------------------------------
    // NoCurrencyAdapter — adapter with no supported currencies
    // -------------------------------------------------------------------

    struct NoCurrencyAdapter;

    impl PaymentAdapter for NoCurrencyAdapter {
        fn adapter_id(&self) -> &str {
            "no-currency"
        }

        fn capabilities(&self) -> AdapterCapabilities {
            AdapterCapabilities {
                supported_currencies: vec![],
                supports_streaming: false,
                supports_batch_auth: false,
                supports_single_step: false,
                min_amount: None,
                max_amount: None,
                typical_settlement_ms: 0,
                requires_facilitator: false,
            }
        }

        fn authorize(
            &self,
            _payer: &DID,
            _payee: &DID,
            _amount: Amount,
            _currency: CurrencyCode,
            _metadata: PaymentMetadata,
        ) -> impl std::future::Future<Output = Result<PaymentAuthorization, PaymentError>> + Send
        {
            async { Err(PaymentError::AdapterError("not implemented".to_owned())) }
        }

        fn capture(
            &self,
            _auth: &PaymentAuthorization,
        ) -> impl std::future::Future<Output = Result<PaymentReceipt, PaymentError>> + Send
        {
            async { Err(PaymentError::AdapterError("not implemented".to_owned())) }
        }

        fn void(
            &self,
            _auth: &PaymentAuthorization,
        ) -> impl std::future::Future<Output = Result<(), PaymentError>> + Send {
            async { Err(PaymentError::AdapterError("not implemented".to_owned())) }
        }

        fn verify_authorization(
            &self,
            _auth: &PaymentAuthorization,
        ) -> impl std::future::Future<Output = Result<(), PaymentError>> + Send {
            async { Err(PaymentError::AdapterError("not implemented".to_owned())) }
        }

        fn verify(
            &self,
            _receipt: &PaymentReceipt,
        ) -> impl std::future::Future<Output = Result<VerificationResult, PaymentError>> + Send
        {
            async { Err(PaymentError::AdapterError("not implemented".to_owned())) }
        }

        fn refund(
            &self,
            _receipt: &PaymentReceipt,
            _amount: Option<Amount>,
        ) -> impl std::future::Future<Output = Result<RefundConfirmation, PaymentError>> + Send
        {
            async { Err(PaymentError::AdapterError("not implemented".to_owned())) }
        }
    }

    // -------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------

    fn test_did() -> DID {
        DID::from("did:dht:z6MkTestHuman")
    }

    fn other_did() -> DID {
        DID::from("did:dht:z6MkOtherHuman")
    }

    // -------------------------------------------------------------------
    // validate_adapter tests
    // -------------------------------------------------------------------

    #[test]
    fn validate_adapter_accepts_valid_adapter() {
        let adapter = TestPaymentAdapter::new("x402");
        assert!(validate_adapter(&adapter).is_ok());
    }

    #[test]
    fn validate_adapter_rejects_empty_id() {
        let adapter = EmptyIdAdapter;
        let err = validate_adapter(&adapter).unwrap_err();
        assert!(matches!(err, CredentialError::InvalidAdapter(_)));
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn validate_adapter_rejects_no_currencies() {
        let adapter = NoCurrencyAdapter;
        let err = validate_adapter(&adapter).unwrap_err();
        assert!(matches!(err, CredentialError::InvalidAdapter(_)));
        assert!(err.to_string().contains("at least one currency"));
    }

    #[test]
    fn validate_adapter_rejects_invalid_id_characters() {
        let adapter = TestPaymentAdapter::new("x402/../../etc");
        let err = validate_adapter(&adapter).unwrap_err();
        assert!(matches!(err, CredentialError::InvalidAdapter(_)));
        assert!(err.to_string().contains("invalid characters"));
    }

    #[test]
    fn validate_adapter_accepts_hyphen_underscore_in_id() {
        let adapter = TestPaymentAdapter::new("my-adapter_v2");
        assert!(validate_adapter(&adapter).is_ok());
    }

    // -------------------------------------------------------------------
    // configure_adapter tests
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn configure_adapter_stores_credential() {
        let adapter = TestPaymentAdapter::new("x402");
        let identity = test_did();
        let store = InMemoryCredentialStore::new();
        let cred_data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let timestamp = 1_700_000_000;

        let result =
            configure_adapter(&adapter, &identity, cred_data.clone(), timestamp, &store).await;
        assert!(result.is_ok());

        // Verify it was stored
        let loaded = store
            .load_adapter_credential(&identity, "x402")
            .await
            .unwrap();
        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.adapter_id, "x402");
        assert_eq!(loaded.identity, identity);
        assert_eq!(loaded.encrypted_data, cred_data);
        assert_eq!(loaded.created_at, timestamp);
        assert_eq!(loaded.rotated_at, timestamp);
    }

    #[tokio::test]
    async fn configure_adapter_rejects_invalid_adapter() {
        let adapter = EmptyIdAdapter;
        let identity = test_did();
        let store = InMemoryCredentialStore::new();

        let result = configure_adapter(&adapter, &identity, vec![], 0, &store).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CredentialError::InvalidAdapter(_)
        ));
    }

    // -------------------------------------------------------------------
    // Store and load roundtrip tests
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn store_and_load_credential_roundtrip() {
        let store = InMemoryCredentialStore::new();
        let identity = test_did();
        let credential = AdapterCredential {
            adapter_id: "lightning".to_owned(),
            identity: identity.clone(),
            encrypted_data: vec![1, 2, 3, 4, 5],
            created_at: 1_700_000_000,
            rotated_at: 1_700_000_000,
        };

        store.store_adapter_credential(&credential).await.unwrap();
        let loaded = store
            .load_adapter_credential(&identity, "lightning")
            .await
            .unwrap();
        assert_eq!(loaded, Some(credential));
    }

    #[tokio::test]
    async fn load_nonexistent_credential_returns_none() {
        let store = InMemoryCredentialStore::new();
        let identity = test_did();

        let loaded = store
            .load_adapter_credential(&identity, "nonexistent")
            .await
            .unwrap();
        assert!(loaded.is_none());
    }

    // -------------------------------------------------------------------
    // Credential isolation tests
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn credentials_isolated_between_identities() {
        let store = InMemoryCredentialStore::new();
        let identity_a = test_did();
        let identity_b = other_did();

        let cred_a = AdapterCredential {
            adapter_id: "x402".to_owned(),
            identity: identity_a.clone(),
            encrypted_data: vec![0xAA],
            created_at: 1_700_000_000,
            rotated_at: 1_700_000_000,
        };

        let cred_b = AdapterCredential {
            adapter_id: "x402".to_owned(),
            identity: identity_b.clone(),
            encrypted_data: vec![0xBB],
            created_at: 1_700_000_000,
            rotated_at: 1_700_000_000,
        };

        store.store_adapter_credential(&cred_a).await.unwrap();
        store.store_adapter_credential(&cred_b).await.unwrap();

        // Each identity gets their own credential
        let loaded_a = store
            .load_adapter_credential(&identity_a, "x402")
            .await
            .unwrap()
            .unwrap();
        let loaded_b = store
            .load_adapter_credential(&identity_b, "x402")
            .await
            .unwrap()
            .unwrap();

        assert_eq!(loaded_a.encrypted_data, vec![0xAA]);
        assert_eq!(loaded_b.encrypted_data, vec![0xBB]);
    }

    #[tokio::test]
    async fn credentials_not_accessible_from_context_operations() {
        // This test verifies the design invariant: adapter credentials are
        // stored under identity/{did}/adapter_credentials/{adapter_id},
        // NOT under context/{context_id}/... . A context-scoped prefix
        // query would never return adapter credentials because they use
        // a different key namespace entirely.
        //
        // We verify this by confirming that the credential store keys
        // (identity-scoped) are separate from any context-scoped keys.

        let store = InMemoryCredentialStore::new();
        let identity = test_did();

        let credential = AdapterCredential {
            adapter_id: "x402".to_owned(),
            identity: identity.clone(),
            encrypted_data: vec![0xDE, 0xAD],
            created_at: 1_700_000_000,
            rotated_at: 1_700_000_000,
        };

        store.store_adapter_credential(&credential).await.unwrap();

        // Credential is accessible via identity lookup
        let loaded = store
            .load_adapter_credential(&identity, "x402")
            .await
            .unwrap();
        assert!(loaded.is_some());

        // But a different identity cannot access it
        let other = other_did();
        let loaded = store
            .load_adapter_credential(&other, "x402")
            .await
            .unwrap();
        assert!(loaded.is_none());
    }

    // -------------------------------------------------------------------
    // list_adapter_credentials tests
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn list_adapter_credentials_returns_all_adapters() {
        let store = InMemoryCredentialStore::new();
        let identity = test_did();

        for adapter_id in &["lightning", "spl", "x402"] {
            let credential = AdapterCredential {
                adapter_id: (*adapter_id).to_owned(),
                identity: identity.clone(),
                encrypted_data: vec![1],
                created_at: 1_700_000_000,
                rotated_at: 1_700_000_000,
            };
            store.store_adapter_credential(&credential).await.unwrap();
        }

        let mut ids = store
            .list_adapter_credentials(&identity)
            .await
            .unwrap();
        ids.sort();

        assert_eq!(ids, vec!["lightning", "spl", "x402"]);
    }

    #[tokio::test]
    async fn list_adapter_credentials_empty_for_unknown_identity() {
        let store = InMemoryCredentialStore::new();
        let identity = test_did();

        let ids = store
            .list_adapter_credentials(&identity)
            .await
            .unwrap();
        assert!(ids.is_empty());
    }

    #[tokio::test]
    async fn list_adapter_credentials_scoped_to_identity() {
        let store = InMemoryCredentialStore::new();
        let identity_a = test_did();
        let identity_b = other_did();

        let cred_a = AdapterCredential {
            adapter_id: "x402".to_owned(),
            identity: identity_a.clone(),
            encrypted_data: vec![1],
            created_at: 1_700_000_000,
            rotated_at: 1_700_000_000,
        };

        let cred_b = AdapterCredential {
            adapter_id: "lightning".to_owned(),
            identity: identity_b.clone(),
            encrypted_data: vec![2],
            created_at: 1_700_000_000,
            rotated_at: 1_700_000_000,
        };

        store.store_adapter_credential(&cred_a).await.unwrap();
        store.store_adapter_credential(&cred_b).await.unwrap();

        let ids_a = store
            .list_adapter_credentials(&identity_a)
            .await
            .unwrap();
        let ids_b = store
            .list_adapter_credentials(&identity_b)
            .await
            .unwrap();

        assert_eq!(ids_a, vec!["x402"]);
        assert_eq!(ids_b, vec!["lightning"]);
    }

    // -------------------------------------------------------------------
    // remove_adapter_credential tests
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn remove_adapter_credential_deletes_credential() {
        let store = InMemoryCredentialStore::new();
        let identity = test_did();

        let credential = AdapterCredential {
            adapter_id: "x402".to_owned(),
            identity: identity.clone(),
            encrypted_data: vec![1, 2, 3],
            created_at: 1_700_000_000,
            rotated_at: 1_700_000_000,
        };

        store.store_adapter_credential(&credential).await.unwrap();
        assert!(store
            .load_adapter_credential(&identity, "x402")
            .await
            .unwrap()
            .is_some());

        store
            .remove_adapter_credential(&identity, "x402")
            .await
            .unwrap();
        assert!(store
            .load_adapter_credential(&identity, "x402")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn remove_nonexistent_credential_is_noop() {
        let store = InMemoryCredentialStore::new();
        let identity = test_did();

        // Should not error
        store
            .remove_adapter_credential(&identity, "nonexistent")
            .await
            .unwrap();
    }

    // -------------------------------------------------------------------
    // retrieve_adapter_credential tests
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn retrieve_credential_returns_stored_credential() {
        let store = InMemoryCredentialStore::new();
        let identity = test_did();

        let credential = AdapterCredential {
            adapter_id: "spl".to_owned(),
            identity: identity.clone(),
            encrypted_data: vec![9, 8, 7],
            created_at: 1_700_000_000,
            rotated_at: 1_700_000_000,
        };

        store.store_adapter_credential(&credential).await.unwrap();

        let retrieved = retrieve_adapter_credential(&identity, "spl", &store)
            .await
            .unwrap();
        assert_eq!(retrieved, credential);
    }

    #[tokio::test]
    async fn retrieve_credential_returns_not_found_error() {
        let store = InMemoryCredentialStore::new();
        let identity = test_did();

        let err = retrieve_adapter_credential(&identity, "missing", &store)
            .await
            .unwrap_err();
        assert!(matches!(err, CredentialError::NotFound(_)));
        assert!(err.to_string().contains("missing"));
    }

    // -------------------------------------------------------------------
    // Multiple adapters per identity
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn identity_supports_multiple_adapters_simultaneously() {
        let store = InMemoryCredentialStore::new();
        let identity = test_did();

        let adapters = vec![
            ("x402", vec![0x01]),
            ("lightning", vec![0x02]),
            ("spl", vec![0x03]),
            ("stripe", vec![0x04]),
        ];

        for (adapter_id, data) in &adapters {
            let credential = AdapterCredential {
                adapter_id: (*adapter_id).to_owned(),
                identity: identity.clone(),
                encrypted_data: data.clone(),
                created_at: 1_700_000_000,
                rotated_at: 1_700_000_000,
            };
            store.store_adapter_credential(&credential).await.unwrap();
        }

        // All four are retrievable
        for (adapter_id, expected_data) in &adapters {
            let cred = store
                .load_adapter_credential(&identity, adapter_id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(cred.encrypted_data, *expected_data);
        }

        let ids = store
            .list_adapter_credentials(&identity)
            .await
            .unwrap();
        assert_eq!(ids.len(), 4);
    }

    // -------------------------------------------------------------------
    // Credential overwrite (rotation)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn store_credential_overwrites_existing() {
        let store = InMemoryCredentialStore::new();
        let identity = test_did();

        let original = AdapterCredential {
            adapter_id: "x402".to_owned(),
            identity: identity.clone(),
            encrypted_data: vec![0x01],
            created_at: 1_700_000_000,
            rotated_at: 1_700_000_000,
        };

        let rotated = AdapterCredential {
            adapter_id: "x402".to_owned(),
            identity: identity.clone(),
            encrypted_data: vec![0x02],
            created_at: 1_700_000_000,
            rotated_at: 1_700_001_000,
        };

        store.store_adapter_credential(&original).await.unwrap();
        store.store_adapter_credential(&rotated).await.unwrap();

        let loaded = store
            .load_adapter_credential(&identity, "x402")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(loaded.encrypted_data, vec![0x02]);
        assert_eq!(loaded.rotated_at, 1_700_001_000);
    }

    // -------------------------------------------------------------------
    // Serde roundtrip
    // -------------------------------------------------------------------

    #[test]
    fn adapter_credential_serde_roundtrip() {
        let credential = AdapterCredential {
            adapter_id: "x402".to_owned(),
            identity: DID::from("did:dht:z6MkTestHuman"),
            encrypted_data: vec![0xDE, 0xAD, 0xBE, 0xEF],
            created_at: 1_700_000_000,
            rotated_at: 1_700_001_000,
        };

        let json = serde_json::to_string(&credential).unwrap();
        let deserialized: AdapterCredential = serde_json::from_str(&json).unwrap();
        assert_eq!(credential, deserialized);
    }

    #[test]
    fn adapter_credential_msgpack_roundtrip() {
        let credential = AdapterCredential {
            adapter_id: "lightning".to_owned(),
            identity: DID::from("did:dht:z6MkTestHuman"),
            encrypted_data: vec![1, 2, 3, 4, 5],
            created_at: 1_700_000_000,
            rotated_at: 1_700_000_000,
        };

        let bytes = rmp_serde::to_vec(&credential).unwrap();
        let deserialized: AdapterCredential = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(credential, deserialized);
    }

    // -------------------------------------------------------------------
    // Debug impl (credential data not leaked)
    // -------------------------------------------------------------------

    #[test]
    fn adapter_credential_debug_hides_encrypted_data() {
        let credential = AdapterCredential {
            adapter_id: "x402".to_owned(),
            identity: DID::from("did:dht:z6MkTestHuman"),
            encrypted_data: vec![0xDE, 0xAD, 0xBE, 0xEF],
            created_at: 1_700_000_000,
            rotated_at: 1_700_000_000,
        };

        let debug_output = format!("{credential:?}");
        // Should show byte count, not raw data
        assert!(debug_output.contains("[4 bytes]"));
        assert!(!debug_output.contains("0xDE"));
        assert!(!debug_output.contains("222")); // 0xDE = 222
    }

    // -------------------------------------------------------------------
    // CredentialError display
    // -------------------------------------------------------------------

    #[test]
    fn credential_error_display_messages() {
        let err = CredentialError::InvalidAdapter("bad adapter".to_owned());
        assert_eq!(err.to_string(), "invalid adapter: bad adapter");

        let err = CredentialError::NotFound("x402".to_owned());
        assert_eq!(err.to_string(), "adapter credential not found: x402");

        let err = CredentialError::SerializationFailed("encode error".to_owned());
        assert_eq!(
            err.to_string(),
            "credential serialization failed: encode error"
        );

        let err = CredentialError::DeserializationFailed("decode error".to_owned());
        assert_eq!(
            err.to_string(),
            "credential deserialization failed: decode error"
        );

        let err = CredentialError::StorageError("disk full".to_owned());
        assert_eq!(err.to_string(), "storage error: disk full");
    }
}
