//! Bridge credential lifecycle management.
//!
//! Implements the `BridgeCredentialStore` trait specified in spec section 12.11.
//! Bridge credentials (OAuth tokens, API keys, webhook secrets) are encrypted
//! at rest using AES-256-GCM with keys derived via HKDF-SHA256 from the bridge
//! operator's identity key material and a bridge-specific salt.
//!
//! # Lifecycle Phases (spec section 12.11.1)
//!
//! 1. **Provision** -- Store new credentials, encrypted at rest.
//! 2. **Retrieve** -- Decrypt and return credentials for use. Blocked when
//!    bridge is suspended.
//! 3. **Rotate** -- Replace existing credential with a new value.
//! 4. **Revoke** -- Destroy all credentials for a bridge instance (overwrite
//!    with zeros, then delete).
//! 5. **List** -- Enumerate credential types stored for a bridge.
//!
//! # Security Properties (spec section 12.11.2)
//!
//! - Credentials are encrypted at rest using a key derived from the bridge
//!   operator's identity key material (not the identity key itself).
//! - Key derivation uses HKDF-SHA256 with `bridge_id || credential_type` as
//!   the salt, providing per-credential key isolation.
//! - Credential access is scoped to bridge instance -- cross-bridge credential
//!   sharing is prohibited even under the same operator DID.
//! - On `BridgeStatus::Revoked`, `revoke()` overwrites encrypted data with
//!   zeros before deletion (defense-in-depth).
//! - On `BridgeStatus::Suspended`, `retrieve()` returns an error; credentials
//!   are retained for potential reactivation.
//!
//! See ADR-023 in `.docs/adrs/phase-5.md`.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// AES-256-GCM nonce size in bytes.
const NONCE_SIZE: usize = 12;

/// HKDF info string for bridge credential encryption.
///
/// Domain-separated from sender key HPKE (`scp-sender-key-hpke-v1`) and
/// access key derivation (`scp-access-key-v1`) to prevent cross-protocol
/// key reuse.
const CREDENTIAL_HKDF_INFO: &[u8] = b"scp-bridge-credential-v1";

// ---------------------------------------------------------------------------
// CredentialType
// ---------------------------------------------------------------------------

/// Type of credential stored for a bridge instance.
///
/// Covers the common authentication mechanisms used by external platforms
/// (spec section 12.11.3). `Custom` accommodates platform-specific credential
/// types not covered by the standard variants.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CredentialType {
    /// OAuth 2.0 access token (short-lived, typically 1 hour).
    OAuthAccessToken,

    /// OAuth 2.0 refresh token (long-lived, days to months).
    OAuthRefreshToken,

    /// Static API key for platform authentication.
    ApiKey,

    /// Webhook signing secret for verifying platform-initiated callbacks.
    WebhookSecret,

    /// Platform-specific credential type not covered by standard variants.
    Custom(String),
}

impl std::fmt::Display for CredentialType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OAuthAccessToken => write!(f, "OAuthAccessToken"),
            Self::OAuthRefreshToken => write!(f, "OAuthRefreshToken"),
            Self::ApiKey => write!(f, "ApiKey"),
            Self::WebhookSecret => write!(f, "WebhookSecret"),
            Self::Custom(name) => write!(f, "Custom({name})"),
        }
    }
}

// ---------------------------------------------------------------------------
// BridgeCredential
// ---------------------------------------------------------------------------

/// An encrypted credential stored for a bridge instance.
///
/// The `encrypted_data` field contains AES-256-GCM ciphertext (nonce prepended)
/// encrypted with a key derived from the operator's identity key material.
/// The credential is scoped to a single bridge instance via `bridge_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeCredential {
    /// AES-256-GCM ciphertext with prepended nonce.
    ///
    /// Format: `[12-byte nonce][ciphertext+tag]`.
    pub encrypted_data: Vec<u8>,

    /// The type of credential stored.
    pub credential_type: CredentialType,

    /// Unix timestamp (seconds) when the credential was provisioned.
    pub created_at: u64,

    /// Optional Unix timestamp (seconds) when the credential expires.
    ///
    /// `None` for credentials without expiry (e.g., static API keys).
    pub expires_at: Option<u64>,

    /// The bridge instance this credential belongs to.
    ///
    /// Credential access is scoped to this bridge -- cross-bridge access
    /// is rejected with `CredentialError::NotFound`.
    pub bridge_id: String,
}

// ---------------------------------------------------------------------------
// CredentialError
// ---------------------------------------------------------------------------

/// Errors produced by bridge credential operations.
#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    /// The requested credential was not found for the given bridge and type.
    #[error("credential not found for bridge '{bridge_id}' with type '{credential_type}'")]
    NotFound {
        /// The bridge ID that was queried.
        bridge_id: String,
        /// The credential type that was queried.
        credential_type: CredentialType,
    },

    /// The bridge is suspended; credential retrieval is blocked.
    ///
    /// Credentials are retained for potential reactivation (spec section
    /// 12.11.1 phase 5), but `retrieve()` returns this error until the
    /// bridge is reactivated.
    #[error("bridge '{bridge_id}' is suspended; credential retrieval blocked")]
    BridgeSuspended {
        /// The suspended bridge ID.
        bridge_id: String,
    },

    /// Encryption or decryption failed.
    #[error("cryptographic operation failed: {reason}")]
    CryptoError {
        /// Description of the failure.
        reason: String,
    },

    /// HKDF key derivation failed.
    #[error("key derivation failed: {reason}")]
    KeyDerivationError {
        /// Description of the failure.
        reason: String,
    },

    /// A credential of the given type already exists for this bridge.
    #[error("credential already exists for bridge '{bridge_id}' with type '{credential_type}'")]
    AlreadyExists {
        /// The bridge ID.
        bridge_id: String,
        /// The credential type.
        credential_type: CredentialType,
    },

    /// Storage backend error.
    #[error("storage error: {reason}")]
    StorageError {
        /// Description of the failure.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// BridgeCredentialStore trait
// ---------------------------------------------------------------------------

/// Trait defining the credential lifecycle for bridge connectors.
///
/// Implementations manage encrypted credential storage scoped to individual
/// bridge instances. The trait is async to accommodate both in-memory and
/// persistent storage backends.
///
/// # Security Contract
///
/// - All credential data MUST be encrypted at rest using
///   [`derive_credential_key`] before storage.
/// - `retrieve()` MUST reject requests when the bridge is suspended.
/// - `revoke()` MUST overwrite credential data with zeros before deletion.
/// - Cross-bridge credential access MUST be rejected (return `NotFound`).
///
/// See spec section 12.11 and ADR-023.
pub trait BridgeCredentialStore: Send + Sync {
    /// Store a new credential for a bridge instance.
    ///
    /// The `plaintext` credential is encrypted using a key derived from
    /// `operator_key_material` via HKDF with `bridge_id || credential_type`
    /// as the salt, then stored.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError::AlreadyExists`] if a credential of the
    /// same type already exists for this bridge. Use [`rotate`](Self::rotate)
    /// to replace an existing credential.
    ///
    /// Returns [`CredentialError::CryptoError`] if encryption fails.
    fn provision(
        &self,
        bridge_id: &str,
        credential_type: CredentialType,
        plaintext: &[u8],
        operator_key_material: &[u8],
    ) -> impl std::future::Future<Output = Result<BridgeCredential, CredentialError>> + Send;

    /// Retrieve and decrypt a credential for a bridge instance.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError::BridgeSuspended`] if the bridge is
    /// currently suspended (spec section 12.11.1).
    ///
    /// Returns [`CredentialError::NotFound`] if no credential of the
    /// given type exists for this bridge (also returned for cross-bridge
    /// access attempts).
    fn retrieve(
        &self,
        bridge_id: &str,
        credential_type: &CredentialType,
        operator_key_material: &[u8],
    ) -> impl std::future::Future<Output = Result<Zeroizing<Vec<u8>>, CredentialError>> + Send;

    /// Replace an existing credential with a new value.
    ///
    /// Encrypts the new `plaintext` and replaces the stored credential.
    /// The old credential's encrypted data is overwritten with zeros
    /// before replacement (defense-in-depth).
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError::NotFound`] if no credential of the
    /// given type exists for this bridge.
    fn rotate(
        &self,
        bridge_id: &str,
        credential_type: &CredentialType,
        new_plaintext: &[u8],
        operator_key_material: &[u8],
    ) -> impl std::future::Future<Output = Result<BridgeCredential, CredentialError>> + Send;

    /// Destroy all credentials for a bridge instance.
    ///
    /// Called when `BridgeStatus` transitions to `Revoked`. For each
    /// credential: (a) overwrite `encrypted_data` with zeros, (b) delete
    /// the credential record.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError::StorageError`] if the storage backend
    /// fails during destruction.
    fn revoke(
        &self,
        bridge_id: &str,
    ) -> impl std::future::Future<Output = Result<(), CredentialError>> + Send;

    /// List all credential types stored for a bridge instance.
    ///
    /// Returns the credential types without decrypting or exposing
    /// credential data.
    fn list(
        &self,
        bridge_id: &str,
    ) -> impl std::future::Future<Output = Result<Vec<CredentialType>, CredentialError>> + Send;
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// Derives a 32-byte AES-256-GCM encryption key from operator key material
/// using HKDF-SHA256.
///
/// The salt is `bridge_id || credential_type` (Display-formatted), providing
/// per-bridge, per-credential-type key isolation. This ensures:
/// - Different bridges under the same operator get different keys.
/// - Different credential types within the same bridge get different keys.
///
/// The returned key is wrapped in [`Zeroizing`] so derived key material is
/// zeroed on drop.
///
/// # Errors
///
/// Returns [`CredentialError::KeyDerivationError`] if HKDF expansion fails
/// (should not occur with valid inputs and SHA-256).
pub fn derive_credential_key(
    operator_key_material: &[u8],
    bridge_id: &str,
    credential_type: &CredentialType,
) -> Result<Zeroizing<[u8; 32]>, CredentialError> {
    // Salt = bridge_id || credential_type (Display-formatted).
    let salt = format!("{bridge_id}{credential_type}");

    let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), operator_key_material);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(CREDENTIAL_HKDF_INFO, okm.as_mut()).map_err(|e| {
        CredentialError::KeyDerivationError {
            reason: e.to_string(),
        }
    })?;
    Ok(okm)
}

/// Encrypts plaintext credential data with AES-256-GCM.
///
/// Returns a byte vector containing `[12-byte nonce][ciphertext+tag]`.
/// The nonce is randomly generated via `OsRng`.
///
/// # Errors
///
/// Returns [`CredentialError::CryptoError`] if AES-256-GCM encryption fails.
fn encrypt_credential(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, CredentialError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| CredentialError::CryptoError {
        reason: format!("invalid key length: {e}"),
    })?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext =
        cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| CredentialError::CryptoError {
                reason: format!("encryption failed: {e}"),
            })?;

    // Prepend nonce to ciphertext.
    let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypts credential data encrypted by [`encrypt_credential`].
///
/// Expects input in the format `[12-byte nonce][ciphertext+tag]`.
/// The returned plaintext is wrapped in [`Zeroizing`] for defense-in-depth.
///
/// # Errors
///
/// Returns [`CredentialError::CryptoError`] if decryption fails (wrong key,
/// tampered ciphertext, or malformed input).
fn decrypt_credential(
    key: &[u8; 32],
    encrypted: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CredentialError> {
    if encrypted.len() < NONCE_SIZE {
        return Err(CredentialError::CryptoError {
            reason: "encrypted data too short to contain nonce".to_owned(),
        });
    }

    let (nonce_bytes, ciphertext) = encrypted.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| CredentialError::CryptoError {
        reason: format!("invalid key length: {e}"),
    })?;

    let plaintext =
        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| CredentialError::CryptoError {
                reason: format!("decryption failed: {e}"),
            })?;

    Ok(Zeroizing::new(plaintext))
}

// ---------------------------------------------------------------------------
// InMemoryCredentialStore
// ---------------------------------------------------------------------------

/// In-memory implementation of [`BridgeCredentialStore`] for testing and
/// development.
///
/// Stores credentials in a `HashMap` keyed by `(bridge_id, credential_type)`.
/// Thread-safe via `tokio::sync::RwLock`. Tracks bridge suspension status
/// via an internal set.
///
/// Not suitable for production -- credentials are not persisted across
/// restarts. Production implementations should use the `Storage` trait
/// (spec section 17) with `SQLite` or equivalent.
#[derive(Debug)]
pub struct InMemoryCredentialStore {
    /// Credentials keyed by `(bridge_id, credential_type)`.
    credentials:
        tokio::sync::RwLock<std::collections::HashMap<(String, CredentialType), BridgeCredential>>,

    /// Set of bridge IDs that are currently suspended.
    suspended_bridges: tokio::sync::RwLock<std::collections::HashSet<String>>,
}

impl InMemoryCredentialStore {
    /// Creates a new empty in-memory credential store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            credentials: tokio::sync::RwLock::new(std::collections::HashMap::new()),
            suspended_bridges: tokio::sync::RwLock::new(std::collections::HashSet::new()),
        }
    }

    /// Mark a bridge as suspended.
    ///
    /// After this call, `retrieve()` will return
    /// [`CredentialError::BridgeSuspended`] for this bridge. Credentials
    /// are retained for potential reactivation.
    pub async fn suspend_bridge(&self, bridge_id: &str) {
        self.suspended_bridges
            .write()
            .await
            .insert(bridge_id.to_owned());
    }

    /// Mark a bridge as active (no longer suspended).
    ///
    /// After this call, `retrieve()` will succeed for this bridge
    /// (assuming credentials exist).
    pub async fn reactivate_bridge(&self, bridge_id: &str) {
        self.suspended_bridges.write().await.remove(bridge_id);
    }
}

impl Default for InMemoryCredentialStore {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(clippy::significant_drop_tightening)] // Nursery false positive on async RwLock patterns.
impl BridgeCredentialStore for InMemoryCredentialStore {
    async fn provision(
        &self,
        bridge_id: &str,
        credential_type: CredentialType,
        plaintext: &[u8],
        operator_key_material: &[u8],
    ) -> Result<BridgeCredential, CredentialError> {
        let key = derive_credential_key(operator_key_material, bridge_id, &credential_type)?;
        let encrypted_data = encrypt_credential(&key, plaintext)?;

        let credential = BridgeCredential {
            encrypted_data,
            credential_type: credential_type.clone(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            expires_at: None,
            bridge_id: bridge_id.to_owned(),
        };

        let map_key = (bridge_id.to_owned(), credential_type.clone());
        let mut creds = self.credentials.write().await;

        if creds.contains_key(&map_key) {
            return Err(CredentialError::AlreadyExists {
                bridge_id: bridge_id.to_owned(),
                credential_type,
            });
        }

        creds.insert(map_key, credential.clone());
        Ok(credential)
    }

    async fn retrieve(
        &self,
        bridge_id: &str,
        credential_type: &CredentialType,
        operator_key_material: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CredentialError> {
        // Check suspension status before retrieval.
        if self.suspended_bridges.read().await.contains(bridge_id) {
            return Err(CredentialError::BridgeSuspended {
                bridge_id: bridge_id.to_owned(),
            });
        }

        let map_key = (bridge_id.to_owned(), credential_type.clone());
        let creds = self.credentials.read().await;

        let credential = creds
            .get(&map_key)
            .ok_or_else(|| CredentialError::NotFound {
                bridge_id: bridge_id.to_owned(),
                credential_type: credential_type.clone(),
            })?;

        let key = derive_credential_key(operator_key_material, bridge_id, credential_type)?;
        decrypt_credential(&key, &credential.encrypted_data)
    }

    async fn rotate(
        &self,
        bridge_id: &str,
        credential_type: &CredentialType,
        new_plaintext: &[u8],
        operator_key_material: &[u8],
    ) -> Result<BridgeCredential, CredentialError> {
        let key = derive_credential_key(operator_key_material, bridge_id, credential_type)?;
        let new_encrypted = encrypt_credential(&key, new_plaintext)?;

        let map_key = (bridge_id.to_owned(), credential_type.clone());
        let mut creds = self.credentials.write().await;

        let existing = creds
            .get_mut(&map_key)
            .ok_or_else(|| CredentialError::NotFound {
                bridge_id: bridge_id.to_owned(),
                credential_type: credential_type.clone(),
            })?;

        // Overwrite old encrypted data with zeros before replacement
        // (defense-in-depth).
        existing.encrypted_data.zeroize();

        // Replace with new credential.
        let rotated = BridgeCredential {
            encrypted_data: new_encrypted,
            credential_type: credential_type.clone(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            expires_at: None,
            bridge_id: bridge_id.to_owned(),
        };

        *existing = rotated.clone();
        Ok(rotated)
    }

    async fn revoke(&self, bridge_id: &str) -> Result<(), CredentialError> {
        {
            let mut creds = self.credentials.write().await;

            // Collect keys for this bridge.
            let keys_to_remove: Vec<(String, CredentialType)> = creds
                .keys()
                .filter(|(bid, _)| bid == bridge_id)
                .cloned()
                .collect();

            // Overwrite encrypted data with zeros, then remove.
            for key in &keys_to_remove {
                if let Some(cred) = creds.get_mut(key) {
                    cred.encrypted_data.zeroize();
                }
                creds.remove(key);
            }
        }

        // Also remove from suspended set if present (lock dropped above).
        self.suspended_bridges.write().await.remove(bridge_id);

        Ok(())
    }

    async fn list(&self, bridge_id: &str) -> Result<Vec<CredentialType>, CredentialError> {
        let creds = self.credentials.read().await;

        let types: Vec<CredentialType> = creds
            .keys()
            .filter(|(bid, _)| bid == bridge_id)
            .map(|(_, ct)| ct.clone())
            .collect();

        Ok(types)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Shared operator key material for tests (32 bytes, deterministic).
    const TEST_OPERATOR_KEY: &[u8; 32] = b"operator-key-material-32-bytes!!";

    /// A different operator key to verify key isolation.
    const OTHER_OPERATOR_KEY: &[u8; 32] = b"other-operator-key-material-32b!";

    // -----------------------------------------------------------------------
    // CredentialType tests
    // -----------------------------------------------------------------------

    #[test]
    fn credential_type_display() {
        assert_eq!(
            CredentialType::OAuthAccessToken.to_string(),
            "OAuthAccessToken"
        );
        assert_eq!(
            CredentialType::OAuthRefreshToken.to_string(),
            "OAuthRefreshToken"
        );
        assert_eq!(CredentialType::ApiKey.to_string(), "ApiKey");
        assert_eq!(CredentialType::WebhookSecret.to_string(), "WebhookSecret");
        assert_eq!(
            CredentialType::Custom("Discord".to_owned()).to_string(),
            "Custom(Discord)"
        );
    }

    #[test]
    fn credential_type_serialization_roundtrip() {
        let types = vec![
            CredentialType::OAuthAccessToken,
            CredentialType::OAuthRefreshToken,
            CredentialType::ApiKey,
            CredentialType::WebhookSecret,
            CredentialType::Custom("session-token".to_owned()),
        ];

        for ct in &types {
            let json = serde_json::to_string(ct).expect("serialize");
            let restored: CredentialType = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(&restored, ct);
        }
    }

    // -----------------------------------------------------------------------
    // BridgeCredential tests
    // -----------------------------------------------------------------------

    #[test]
    fn bridge_credential_serialization_roundtrip() {
        let cred = BridgeCredential {
            encrypted_data: vec![1, 2, 3, 4],
            credential_type: CredentialType::ApiKey,
            created_at: 1_700_000_000,
            expires_at: Some(1_700_003_600),
            bridge_id: "bridge-001".to_owned(),
        };

        let json = serde_json::to_string(&cred).expect("serialize");
        let restored: BridgeCredential = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(restored.encrypted_data, cred.encrypted_data);
        assert_eq!(restored.credential_type, cred.credential_type);
        assert_eq!(restored.created_at, cred.created_at);
        assert_eq!(restored.expires_at, cred.expires_at);
        assert_eq!(restored.bridge_id, cred.bridge_id);
    }

    // -----------------------------------------------------------------------
    // Key derivation tests
    // -----------------------------------------------------------------------

    #[test]
    fn derive_credential_key_produces_deterministic_output() {
        let key1 = derive_credential_key(TEST_OPERATOR_KEY, "bridge-001", &CredentialType::ApiKey)
            .expect("derive");
        let key2 = derive_credential_key(TEST_OPERATOR_KEY, "bridge-001", &CredentialType::ApiKey)
            .expect("derive");

        assert_eq!(*key1, *key2, "same inputs must produce same key");
    }

    #[test]
    fn derive_credential_key_differs_by_bridge_id() {
        let key1 = derive_credential_key(TEST_OPERATOR_KEY, "bridge-001", &CredentialType::ApiKey)
            .expect("derive");
        let key2 = derive_credential_key(TEST_OPERATOR_KEY, "bridge-002", &CredentialType::ApiKey)
            .expect("derive");

        assert_ne!(
            *key1, *key2,
            "different bridge IDs must produce different keys"
        );
    }

    #[test]
    fn derive_credential_key_differs_by_credential_type() {
        let key1 = derive_credential_key(TEST_OPERATOR_KEY, "bridge-001", &CredentialType::ApiKey)
            .expect("derive");
        let key2 = derive_credential_key(
            TEST_OPERATOR_KEY,
            "bridge-001",
            &CredentialType::OAuthAccessToken,
        )
        .expect("derive");

        assert_ne!(
            *key1, *key2,
            "different credential types must produce different keys"
        );
    }

    #[test]
    fn derive_credential_key_differs_by_operator_key() {
        let key1 = derive_credential_key(TEST_OPERATOR_KEY, "bridge-001", &CredentialType::ApiKey)
            .expect("derive");
        let key2 = derive_credential_key(OTHER_OPERATOR_KEY, "bridge-001", &CredentialType::ApiKey)
            .expect("derive");

        assert_ne!(
            *key1, *key2,
            "different operator keys must produce different keys"
        );
    }

    // -----------------------------------------------------------------------
    // Encrypt/decrypt roundtrip tests
    // -----------------------------------------------------------------------

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = derive_credential_key(TEST_OPERATOR_KEY, "bridge-001", &CredentialType::ApiKey)
            .expect("derive");

        let plaintext = b"my-secret-api-key-12345";
        let encrypted = encrypt_credential(&key, plaintext).expect("encrypt");

        // Encrypted output must be longer than plaintext (nonce + tag).
        assert!(encrypted.len() > plaintext.len());

        let decrypted = decrypt_credential(&key, &encrypted).expect("decrypt");
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let key1 = derive_credential_key(TEST_OPERATOR_KEY, "bridge-001", &CredentialType::ApiKey)
            .expect("derive");
        let key2 = derive_credential_key(OTHER_OPERATOR_KEY, "bridge-001", &CredentialType::ApiKey)
            .expect("derive");

        let encrypted = encrypt_credential(&key1, b"secret").expect("encrypt");
        let result = decrypt_credential(&key2, &encrypted);

        assert!(result.is_err(), "wrong key must fail decryption");
    }

    #[test]
    fn decrypt_truncated_data_fails() {
        let result = decrypt_credential(&[0u8; 32], &[0u8; 5]);
        assert!(result.is_err(), "data shorter than nonce must fail");
    }

    // -----------------------------------------------------------------------
    // InMemoryCredentialStore tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn provision_and_retrieve_roundtrip() {
        let store = InMemoryCredentialStore::new();
        let plaintext = b"oauth-access-token-abc123";

        let cred = store
            .provision(
                "bridge-001",
                CredentialType::OAuthAccessToken,
                plaintext,
                TEST_OPERATOR_KEY,
            )
            .await
            .expect("provision");

        assert_eq!(cred.bridge_id, "bridge-001");
        assert_eq!(cred.credential_type, CredentialType::OAuthAccessToken);
        assert!(cred.created_at > 0);

        let retrieved = store
            .retrieve(
                "bridge-001",
                &CredentialType::OAuthAccessToken,
                TEST_OPERATOR_KEY,
            )
            .await
            .expect("retrieve");

        assert_eq!(retrieved.as_slice(), plaintext);
    }

    #[tokio::test]
    async fn provision_duplicate_returns_already_exists() {
        let store = InMemoryCredentialStore::new();

        store
            .provision(
                "bridge-001",
                CredentialType::ApiKey,
                b"key-1",
                TEST_OPERATOR_KEY,
            )
            .await
            .expect("first provision");

        let result = store
            .provision(
                "bridge-001",
                CredentialType::ApiKey,
                b"key-2",
                TEST_OPERATOR_KEY,
            )
            .await;

        assert!(
            matches!(result, Err(CredentialError::AlreadyExists { .. })),
            "duplicate provision must return AlreadyExists"
        );
    }

    #[tokio::test]
    async fn retrieve_nonexistent_returns_not_found() {
        let store = InMemoryCredentialStore::new();

        let result = store
            .retrieve("bridge-001", &CredentialType::ApiKey, TEST_OPERATOR_KEY)
            .await;

        assert!(
            matches!(result, Err(CredentialError::NotFound { .. })),
            "missing credential must return NotFound"
        );
    }

    #[tokio::test]
    async fn cross_bridge_access_returns_not_found() {
        let store = InMemoryCredentialStore::new();

        store
            .provision(
                "bridge-001",
                CredentialType::ApiKey,
                b"secret-key",
                TEST_OPERATOR_KEY,
            )
            .await
            .expect("provision");

        // Attempt to retrieve from a different bridge -- must fail.
        let result = store
            .retrieve("bridge-002", &CredentialType::ApiKey, TEST_OPERATOR_KEY)
            .await;

        assert!(
            matches!(result, Err(CredentialError::NotFound { .. })),
            "cross-bridge access must return NotFound"
        );
    }

    #[tokio::test]
    async fn rotate_replaces_credential() {
        let store = InMemoryCredentialStore::new();

        store
            .provision(
                "bridge-001",
                CredentialType::OAuthAccessToken,
                b"old-token",
                TEST_OPERATOR_KEY,
            )
            .await
            .expect("provision");

        let rotated = store
            .rotate(
                "bridge-001",
                &CredentialType::OAuthAccessToken,
                b"new-token",
                TEST_OPERATOR_KEY,
            )
            .await
            .expect("rotate");

        assert_eq!(rotated.bridge_id, "bridge-001");

        // Retrieve should return the new value.
        let retrieved = store
            .retrieve(
                "bridge-001",
                &CredentialType::OAuthAccessToken,
                TEST_OPERATOR_KEY,
            )
            .await
            .expect("retrieve");

        assert_eq!(retrieved.as_slice(), b"new-token");
    }

    #[tokio::test]
    async fn rotate_nonexistent_returns_not_found() {
        let store = InMemoryCredentialStore::new();

        let result = store
            .rotate(
                "bridge-001",
                &CredentialType::ApiKey,
                b"new-value",
                TEST_OPERATOR_KEY,
            )
            .await;

        assert!(
            matches!(result, Err(CredentialError::NotFound { .. })),
            "rotating nonexistent credential must return NotFound"
        );
    }

    #[tokio::test]
    async fn revoke_destroys_all_credentials() {
        let store = InMemoryCredentialStore::new();

        // Provision multiple credential types for the same bridge.
        store
            .provision(
                "bridge-001",
                CredentialType::OAuthAccessToken,
                b"token",
                TEST_OPERATOR_KEY,
            )
            .await
            .expect("provision access token");

        store
            .provision(
                "bridge-001",
                CredentialType::OAuthRefreshToken,
                b"refresh",
                TEST_OPERATOR_KEY,
            )
            .await
            .expect("provision refresh token");

        store
            .provision(
                "bridge-001",
                CredentialType::WebhookSecret,
                b"webhook-secret",
                TEST_OPERATOR_KEY,
            )
            .await
            .expect("provision webhook secret");

        // Verify they exist.
        let types = store.list("bridge-001").await.expect("list");
        assert_eq!(types.len(), 3);

        // Revoke.
        store.revoke("bridge-001").await.expect("revoke");

        // All credentials should be gone.
        let types_after = store.list("bridge-001").await.expect("list");
        assert!(types_after.is_empty(), "all credentials must be destroyed");

        // Retrieval should fail.
        let result = store
            .retrieve(
                "bridge-001",
                &CredentialType::OAuthAccessToken,
                TEST_OPERATOR_KEY,
            )
            .await;
        assert!(
            matches!(result, Err(CredentialError::NotFound { .. })),
            "revoked credentials must not be retrievable"
        );
    }

    #[tokio::test]
    async fn revoke_does_not_affect_other_bridges() {
        let store = InMemoryCredentialStore::new();

        store
            .provision(
                "bridge-001",
                CredentialType::ApiKey,
                b"key-1",
                TEST_OPERATOR_KEY,
            )
            .await
            .expect("provision bridge-001");

        store
            .provision(
                "bridge-002",
                CredentialType::ApiKey,
                b"key-2",
                TEST_OPERATOR_KEY,
            )
            .await
            .expect("provision bridge-002");

        // Revoke bridge-001 only.
        store.revoke("bridge-001").await.expect("revoke");

        // bridge-002 should be unaffected.
        let retrieved = store
            .retrieve("bridge-002", &CredentialType::ApiKey, TEST_OPERATOR_KEY)
            .await
            .expect("retrieve bridge-002");

        assert_eq!(retrieved.as_slice(), b"key-2");
    }

    #[tokio::test]
    async fn suspended_bridge_blocks_retrieve() {
        let store = InMemoryCredentialStore::new();

        store
            .provision(
                "bridge-001",
                CredentialType::ApiKey,
                b"my-key",
                TEST_OPERATOR_KEY,
            )
            .await
            .expect("provision");

        // Suspend the bridge.
        store.suspend_bridge("bridge-001").await;

        // Retrieve should fail with BridgeSuspended.
        let result = store
            .retrieve("bridge-001", &CredentialType::ApiKey, TEST_OPERATOR_KEY)
            .await;

        assert!(
            matches!(result, Err(CredentialError::BridgeSuspended { .. })),
            "suspended bridge must block retrieval"
        );

        // Reactivate the bridge.
        store.reactivate_bridge("bridge-001").await;

        // Retrieve should succeed again.
        let retrieved = store
            .retrieve("bridge-001", &CredentialType::ApiKey, TEST_OPERATOR_KEY)
            .await
            .expect("retrieve after reactivation");

        assert_eq!(retrieved.as_slice(), b"my-key");
    }

    #[tokio::test]
    async fn list_returns_all_credential_types() {
        let store = InMemoryCredentialStore::new();

        store
            .provision(
                "bridge-001",
                CredentialType::OAuthAccessToken,
                b"token",
                TEST_OPERATOR_KEY,
            )
            .await
            .expect("provision");

        store
            .provision(
                "bridge-001",
                CredentialType::ApiKey,
                b"key",
                TEST_OPERATOR_KEY,
            )
            .await
            .expect("provision");

        store
            .provision(
                "bridge-001",
                CredentialType::Custom("discord-bot-token".to_owned()),
                b"bot-token",
                TEST_OPERATOR_KEY,
            )
            .await
            .expect("provision");

        let mut types = store.list("bridge-001").await.expect("list");
        types.sort_by_key(std::string::ToString::to_string);

        assert_eq!(types.len(), 3);
        assert!(types.contains(&CredentialType::OAuthAccessToken));
        assert!(types.contains(&CredentialType::ApiKey));
        assert!(types.contains(&CredentialType::Custom("discord-bot-token".to_owned())));
    }

    #[tokio::test]
    async fn list_empty_bridge_returns_empty_vec() {
        let store = InMemoryCredentialStore::new();
        let types = store.list("bridge-nonexistent").await.expect("list");
        assert!(types.is_empty());
    }

    #[tokio::test]
    async fn multiple_credential_types_per_bridge() {
        let store = InMemoryCredentialStore::new();

        let types_to_provision = vec![
            (CredentialType::OAuthAccessToken, b"access-token" as &[u8]),
            (CredentialType::OAuthRefreshToken, b"refresh-token"),
            (CredentialType::ApiKey, b"api-key-value"),
            (CredentialType::WebhookSecret, b"webhook-secret-value"),
            (
                CredentialType::Custom("session".to_owned()),
                b"session-token",
            ),
        ];

        for (ct, plaintext) in &types_to_provision {
            store
                .provision("bridge-001", ct.clone(), plaintext, TEST_OPERATOR_KEY)
                .await
                .expect("provision");
        }

        // Verify each can be independently retrieved.
        for (ct, expected) in &types_to_provision {
            let retrieved = store
                .retrieve("bridge-001", ct, TEST_OPERATOR_KEY)
                .await
                .expect("retrieve");
            assert_eq!(retrieved.as_slice(), *expected);
        }
    }
}
