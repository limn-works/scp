//! Bridge credential lifecycle management.
//!
//! Implements the `BridgeCredentialStore` trait specified in spec section 12.11.
//! Bridge credentials (OAuth tokens, API keys, webhook secrets) are encrypted
//! at rest using AES-256-GCM with keys derived via HKDF-SHA256 from a per-bridge
//! random secret (`bridge_credential_key`) — NOT from the operator's identity
//! key material.
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
//! # Key Derivation (spec section 12.11.1 Phase 2)
//!
//! ```text
//! ikm  = bridge_credential_key                       // 32 bytes, per-bridge CSPRNG
//! salt = SHA-256("SCP-BRIDGE-CREDENTIAL-V1")          // fixed 32-byte hash
//! info = "scp-bridge-credential:" || bridge_id        // bridge-specific context
//! okm  = HKDF-Expand(HKDF-Extract(salt, ikm), info, 32)
//! ```
//!
//! # Security Properties (spec section 12.11.2)
//!
//! - Credentials are encrypted at rest using a key derived from the bridge's
//!   `bridge_credential_key` — a per-bridge random secret stored in the
//!   custody boundary, independent of any identity key.
//! - Key derivation uses HKDF-SHA256 with a fixed salt and bridge-specific
//!   info string, providing per-bridge key isolation.
//! - Credential access is scoped to bridge instance -- cross-bridge credential
//!   sharing is prohibited even under the same operator DID.
//! - On `BridgeStatus::Revoked`, `revoke()` overwrites encrypted data with
//!   zeros before deletion (defense-in-depth).
//! - On `BridgeStatus::Suspended`, `retrieve()` returns an error; credentials
//!   are retained for potential reactivation.
//!
//! See ADR-023 in `.docs/adrs/phase-5.md`.

use std::sync::LazyLock;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use async_trait::async_trait;
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use scp_platform::EncryptedStorage;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
// `Zeroize` (the trait) is only used by the testing-gated
// `InMemoryCredentialStore`'s in-place `.zeroize()` calls; `Zeroizing` is used
// unconditionally by the durable path and key derivation.
#[cfg(any(test, feature = "testing"))]
use zeroize::Zeroize;
use zeroize::Zeroizing;

use crate::store::ProtocolRepository;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// AES-256-GCM nonce size in bytes.
const NONCE_SIZE: usize = 12;

/// Precomputed HKDF salt: SHA-256("SCP-BRIDGE-CREDENTIAL-V1").
///
/// Computed once on first access and reused for all subsequent
/// `derive_credential_key` calls.
static CREDENTIAL_HKDF_SALT: LazyLock<[u8; 32]> = LazyLock::new(|| {
    let digest = Sha256::digest(b"SCP-BRIDGE-CREDENTIAL-V1");
    let mut salt = [0u8; 32];
    salt.copy_from_slice(&digest);
    salt
});

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
/// encrypted with a key derived from the bridge's `bridge_credential_key`.
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

    /// The bridge credential key was not found for the given bridge.
    ///
    /// Returned when [`BridgeCredentialStore::get_bridge_credential_key`]
    /// is called for a bridge that was never provisioned or whose key was
    /// deleted.
    #[error("bridge credential key not found for bridge {bridge_id}")]
    KeyNotFound {
        /// The bridge ID that was queried.
        bridge_id: String,
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
    /// the per-bridge `bridge_credential_key` via HKDF-SHA256
    /// (spec §12.11.1 Phase 2), then stored.
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
        bridge_credential_key: &[u8; 32],
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
        bridge_credential_key: &[u8; 32],
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
        bridge_credential_key: &[u8; 32],
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

    /// Store a bridge credential key in the custody boundary.
    ///
    /// Called once at bridge provisioning time with the output of
    /// [`generate_bridge_credential_key`]. The key MUST be stored
    /// securely — it is the root secret for all credential encryption
    /// for this bridge instance.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError::StorageError`] if the storage backend
    /// fails.
    fn store_bridge_credential_key(
        &self,
        bridge_id: &str,
        key: Zeroizing<[u8; 32]>,
    ) -> impl std::future::Future<Output = Result<(), CredentialError>> + Send;

    /// Retrieve the bridge credential key from the custody boundary.
    ///
    /// Returns the key wrapped in [`Zeroizing`] so it is zeroed on drop.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError::KeyNotFound`] if no key is stored for
    /// the given bridge (bridge was never provisioned, or key was deleted
    /// via [`delete_bridge_credential_key`](Self::delete_bridge_credential_key)).
    fn get_bridge_credential_key(
        &self,
        bridge_id: &str,
    ) -> impl std::future::Future<Output = Result<Zeroizing<[u8; 32]>, CredentialError>> + Send;

    /// Delete and zeroize the bridge credential key.
    ///
    /// Called during [`revoke`](Self::revoke) to destroy the root secret.
    /// After this call, no credentials can be decrypted for this bridge.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError::StorageError`] if the storage backend
    /// fails during deletion.
    fn delete_bridge_credential_key(
        &self,
        bridge_id: &str,
    ) -> impl std::future::Future<Output = Result<(), CredentialError>> + Send;
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// Derives a 32-byte AES-256-GCM encryption key from a per-bridge random
/// secret using HKDF-SHA256 (spec §12.11.1 Phase 2).
///
/// ```text
/// ikm  = bridge_credential_key                       // 32 bytes, per-bridge CSPRNG
/// salt = SHA-256("SCP-BRIDGE-CREDENTIAL-V1")          // fixed 32-byte hash
/// info = "scp-bridge-credential:" || bridge_id        // bridge-specific context
/// okm  = HKDF-Expand(HKDF-Extract(salt, ikm), info, 32)
/// ```
///
/// The `bridge_credential_key` is a standalone random secret generated once
/// per bridge instance at provisioning time — it is NOT derived from any
/// identity key (avoiding coupling to key rotation or hardware custody).
///
/// Per-bridge isolation is provided by the `bridge_id` in the info string:
/// different bridges produce different derived keys even if they somehow
/// shared the same `bridge_credential_key`.
///
/// The returned key is wrapped in [`Zeroizing`] so derived key material is
/// zeroed on drop.
///
/// # Errors
///
/// Returns [`CredentialError::KeyDerivationError`] if HKDF expansion fails
/// (should not occur with valid inputs and SHA-256).
pub fn derive_credential_key(
    bridge_credential_key: &[u8; 32],
    bridge_id: &str,
) -> Result<Zeroizing<[u8; 32]>, CredentialError> {
    // Info = "scp-bridge-credential:" || bridge_id.
    let info = format!("scp-bridge-credential:{bridge_id}");

    let hk = Hkdf::<Sha256>::new(Some(&*CREDENTIAL_HKDF_SALT), bridge_credential_key);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(info.as_bytes(), okm.as_mut())
        .map_err(|e| CredentialError::KeyDerivationError {
            reason: e.to_string(),
        })?;
    Ok(okm)
}

/// Generate a new random bridge credential key (32 bytes from CSPRNG).
///
/// Called once at bridge provisioning time. The returned key MUST be
/// stored in the custody boundary via `ProtocolRepository`.
///
/// The key is wrapped in [`Zeroizing`] so it is zeroed on drop,
/// consistent with every other key-returning function in this module.
#[must_use]
pub fn generate_bridge_credential_key() -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(key.as_mut());
    key
}

/// Builds the AES-256-GCM Additional Authenticated Data (AAD) that binds a
/// credential ciphertext to its *slot identity* — its `credential_type` and
/// `created_at`.
///
/// AAD is authenticated-but-not-encrypted: GCM's tag covers it, so a ciphertext
/// sealed with one AAD cannot be decrypted (tag verification fails) under a
/// different AAD. Binding the slot's `credential_type` defeats a **slot-swap**
/// (copying an `OAuthAccessToken` ciphertext into the `ApiKey` slot, past a
/// defeated at-rest `SQLCipher` layer): retrieval derives the AAD from the slot
/// being *accessed*, so a mismatched slot fails the tag rather than returning a
/// misattributed secret. Binding `created_at` authenticates that otherwise
/// unauthenticated metadata field against tampering (defense-in-depth).
///
/// Encoding is domain-separated, length-delimited, and fixed-width so it is
/// unambiguous — two distinct `(credential_type, created_at)` pairs can never
/// produce the same bytes:
///
/// ```text
/// AAD = "SCP-BRIDGE-CREDENTIAL-AAD-V1"          // fixed 28-byte domain tag
///     || u64_le(len(Display(credential_type)))  // 8-byte length prefix
///     || Display(credential_type)               // exactly that many bytes
///     || u64_le(created_at)                      // fixed 8 bytes
/// ```
///
/// `Display(credential_type)` is injective across variants (standard variants
/// are bare identifiers; `Custom(name)` always renders `Custom(<name>)`, which
/// no standard variant can equal), and the length prefix removes any
/// concatenation ambiguity between the type field and the trailing timestamp.
pub(crate) fn credential_aad(credential_type: &CredentialType, created_at: u64) -> Vec<u8> {
    const DOMAIN: &[u8] = b"SCP-BRIDGE-CREDENTIAL-AAD-V1";
    let type_str = credential_type.to_string();
    let type_bytes = type_str.as_bytes();
    let mut aad = Vec::with_capacity(DOMAIN.len() + 8 + type_bytes.len() + 8);
    aad.extend_from_slice(DOMAIN);
    aad.extend_from_slice(&(type_bytes.len() as u64).to_le_bytes());
    aad.extend_from_slice(type_bytes);
    aad.extend_from_slice(&created_at.to_le_bytes());
    aad
}

/// Encrypts plaintext credential data with AES-256-GCM, binding `aad`.
///
/// Returns a byte vector containing `[12-byte nonce][ciphertext+tag]`.
/// The nonce is randomly generated via `OsRng`. `aad` (see [`credential_aad`])
/// is authenticated but not stored inline — the caller must reconstruct the
/// identical AAD at decrypt time.
///
/// # Errors
///
/// Returns [`CredentialError::CryptoError`] if AES-256-GCM encryption fails.
pub(crate) fn encrypt_credential(
    key: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CredentialError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| CredentialError::CryptoError {
        reason: format!("invalid key length: {e}"),
    })?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| CredentialError::CryptoError {
            reason: format!("encryption failed: {e}"),
        })?;

    // Prepend nonce to ciphertext.
    let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypts credential data encrypted by [`encrypt_credential`], verifying `aad`.
///
/// Expects input in the format `[12-byte nonce][ciphertext+tag]`. `aad` MUST be
/// byte-identical to the AAD used at encrypt time (see [`credential_aad`]); a
/// mismatch (e.g. a ciphertext moved to a different credential-type slot) fails
/// the GCM tag and returns [`CredentialError::CryptoError`], never a
/// misattributed plaintext. The returned plaintext is wrapped in [`Zeroizing`].
///
/// # Errors
///
/// Returns [`CredentialError::CryptoError`] if decryption fails (wrong key,
/// tampered ciphertext, AAD mismatch, or malformed input).
pub(crate) fn decrypt_credential(
    key: &[u8; 32],
    encrypted: &[u8],
    aad: &[u8],
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

    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
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
/// Thread-safe via `std::sync::RwLock`. Tracks bridge suspension status
/// via an internal set.
///
/// Every locked region is a synchronous map/set operation — no guard is ever
/// held across an `.await`, so a blocking `std::sync::RwLock` is correct here
/// (ADR-049 Decision 12: the async `tokio` read-path `RwLock` is banned).
///
/// Not suitable for production -- credentials are not persisted across
/// restarts. Production selects the durable
/// [`ProtocolRepositoryCredentialStore`] at the FFI bridge construction
/// boundary instead; this in-memory double is **test-harness-only**, gated
/// behind `#[cfg(any(test, feature = "testing"))]` so it is provably absent
/// from every shipped artifact (ADR-062 §Decision 5, SCP-CAPINJECT-009).
///
/// Classified **durability-only** (spec §17.17.2): RAM-only tokens are
/// re-obtainable by re-auth, so losing them fails closed — it nullifies no
/// security property. The `impl Default` that made it a *default* selection
/// was the live SCP-CAPSEL-8000/8011 violation and has been deleted; there is
/// no zero-argument / omit-the-field way to reach it.
#[cfg(any(test, feature = "testing"))]
#[derive(Debug)]
pub struct InMemoryCredentialStore {
    /// Credentials keyed by `(bridge_id, credential_type)`.
    credentials:
        std::sync::RwLock<std::collections::HashMap<(String, CredentialType), BridgeCredential>>,

    /// Set of bridge IDs that are currently suspended.
    suspended_bridges: std::sync::RwLock<std::collections::HashSet<String>>,

    /// Bridge credential keys keyed by bridge ID.
    ///
    /// Each key is wrapped in [`Zeroizing`] so it is zeroed on drop.
    bridge_credential_keys:
        std::sync::RwLock<std::collections::HashMap<String, Zeroizing<[u8; 32]>>>,
}

#[cfg(any(test, feature = "testing"))]
impl InMemoryCredentialStore {
    /// Creates a new empty in-memory credential store.
    // No `Default` impl: a `Default` is a *default selection* of the in-memory
    // arm, the live SCP-CAPSEL-8000/8011 violation this story deletes
    // (ADR-062 §Decision 5, SCP-CAPINJECT-009). Callers must select explicitly.
    #[allow(clippy::new_without_default)]
    #[must_use]
    pub fn new() -> Self {
        Self {
            credentials: std::sync::RwLock::new(std::collections::HashMap::new()),
            suspended_bridges: std::sync::RwLock::new(std::collections::HashSet::new()),
            bridge_credential_keys: std::sync::RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// Mark a bridge as suspended.
    ///
    /// After this call, `retrieve()` will return
    /// [`CredentialError::BridgeSuspended`] for this bridge. Credentials
    /// are retained for potential reactivation.
    pub fn suspend_bridge(&self, bridge_id: &str) {
        self.suspended_bridges
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(bridge_id.to_owned());
    }

    /// Mark a bridge as active (no longer suspended).
    ///
    /// After this call, `retrieve()` will succeed for this bridge
    /// (assuming credentials exist).
    pub fn reactivate_bridge(&self, bridge_id: &str) {
        self.suspended_bridges
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(bridge_id);
    }
}

// NOTE: the in-memory store's `Default` impl was DELETED (ADR-062 §Decision 5,
// SCP-CAPINJECT-009). A `Default` impl is a *default selection* of the
// in-memory arm — the live SCP-CAPSEL-8000/8011 violation this story fixes.
// Every reachable construction goes through an explicit `::new()` under
// `#[cfg(any(test, feature = "testing"))]`, never a zero-argument default.

#[cfg(any(test, feature = "testing"))]
#[allow(clippy::significant_drop_tightening)] // Nursery false positive: guards are held across the synchronous critical section, then dropped at scope end.
impl BridgeCredentialStore for InMemoryCredentialStore {
    async fn provision(
        &self,
        bridge_id: &str,
        credential_type: CredentialType,
        plaintext: &[u8],
        bridge_credential_key: &[u8; 32],
    ) -> Result<BridgeCredential, CredentialError> {
        // Bind the credential-type slot + created_at as AES-GCM AAD. Compute
        // `created_at` BEFORE encrypting so the stored value and the sealed AAD
        // carry the same timestamp.
        let created_at = now_secs();
        let key = derive_credential_key(bridge_credential_key, bridge_id)?;
        let aad = credential_aad(&credential_type, created_at);
        let encrypted_data = encrypt_credential(&key, plaintext, &aad)?;

        let credential = BridgeCredential {
            encrypted_data,
            credential_type: credential_type.clone(),
            created_at,
            expires_at: None,
            bridge_id: bridge_id.to_owned(),
        };

        let map_key = (bridge_id.to_owned(), credential_type.clone());
        let mut creds = self
            .credentials
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

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
        bridge_credential_key: &[u8; 32],
    ) -> Result<Zeroizing<Vec<u8>>, CredentialError> {
        // Check suspension status before retrieval.
        if self
            .suspended_bridges
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(bridge_id)
        {
            return Err(CredentialError::BridgeSuspended {
                bridge_id: bridge_id.to_owned(),
            });
        }

        let map_key = (bridge_id.to_owned(), credential_type.clone());
        let creds = self
            .credentials
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let credential = creds
            .get(&map_key)
            .ok_or_else(|| CredentialError::NotFound {
                bridge_id: bridge_id.to_owned(),
                credential_type: credential_type.clone(),
            })?;

        let key = derive_credential_key(bridge_credential_key, bridge_id)?;
        // AAD from the SLOT being accessed (`credential_type`) + the stored
        // `created_at`. A ciphertext moved into the wrong slot fails the tag.
        let aad = credential_aad(credential_type, credential.created_at);
        decrypt_credential(&key, &credential.encrypted_data, &aad)
    }

    async fn rotate(
        &self,
        bridge_id: &str,
        credential_type: &CredentialType,
        new_plaintext: &[u8],
        bridge_credential_key: &[u8; 32],
    ) -> Result<BridgeCredential, CredentialError> {
        let created_at = now_secs();
        let key = derive_credential_key(bridge_credential_key, bridge_id)?;
        let aad = credential_aad(credential_type, created_at);
        let new_encrypted = encrypt_credential(&key, new_plaintext, &aad)?;

        let map_key = (bridge_id.to_owned(), credential_type.clone());
        let mut creds = self
            .credentials
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let existing = creds
            .get_mut(&map_key)
            .ok_or_else(|| CredentialError::NotFound {
                bridge_id: bridge_id.to_owned(),
                credential_type: credential_type.clone(),
            })?;

        // Overwrite old encrypted data with zeros before replacement
        // (defense-in-depth).
        existing.encrypted_data.zeroize();

        // Replace with new credential (same `created_at` bound into the AAD
        // above).
        let rotated = BridgeCredential {
            encrypted_data: new_encrypted,
            credential_type: credential_type.clone(),
            created_at,
            expires_at: None,
            bridge_id: bridge_id.to_owned(),
        };

        *existing = rotated.clone();
        Ok(rotated)
    }

    async fn revoke(&self, bridge_id: &str) -> Result<(), CredentialError> {
        {
            let mut creds = self
                .credentials
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);

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

        // Destroy the bridge credential key (root secret).
        self.delete_bridge_credential_key(bridge_id).await?;

        // Also remove from suspended set if present.
        self.suspended_bridges
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(bridge_id);

        Ok(())
    }

    async fn list(&self, bridge_id: &str) -> Result<Vec<CredentialType>, CredentialError> {
        let creds = self
            .credentials
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let types: Vec<CredentialType> = creds
            .keys()
            .filter(|(bid, _)| bid == bridge_id)
            .map(|(_, ct)| ct.clone())
            .collect();

        Ok(types)
    }

    async fn store_bridge_credential_key(
        &self,
        bridge_id: &str,
        key: Zeroizing<[u8; 32]>,
    ) -> Result<(), CredentialError> {
        self.bridge_credential_keys
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(bridge_id.to_owned(), key);
        Ok(())
    }

    async fn get_bridge_credential_key(
        &self,
        bridge_id: &str,
    ) -> Result<Zeroizing<[u8; 32]>, CredentialError> {
        self.bridge_credential_keys
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(bridge_id)
            .cloned()
            .ok_or_else(|| CredentialError::KeyNotFound {
                bridge_id: bridge_id.to_owned(),
            })
    }

    async fn delete_bridge_credential_key(&self, bridge_id: &str) -> Result<(), CredentialError> {
        // Zeroizing<[u8; 32]> zeros on drop when removed from the HashMap.
        self.bridge_credential_keys
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(bridge_id);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// DurableCredentialBackend — object-safe erasure trait
// ---------------------------------------------------------------------------

/// Object-safe durable credential backend.
///
/// [`BridgeCredentialStore`] uses RPITIT (return-position `impl Trait`), so it
/// is **not** dyn-compatible — the FFI `FfiCredentialStore` seam cannot hold an
/// `Arc<dyn BridgeCredentialStore>`. This companion trait mirrors the same 8
/// operations under `#[async_trait]` (boxed, `Send` futures), which **is**
/// object-safe, so the real durable arm can be type-erased as
/// `Arc<dyn DurableCredentialBackend>` over whatever `EncryptedStorage` backend
/// the caller selected at the bridge construction boundary. This is the same
/// erasure pattern `OpenMlsStorageAdapter` uses to erase a concrete
/// `S: Storage` (ADR-062 §Dispatch mechanism).
///
/// Two [`BridgeCredentialStore`] contract lines are satisfied differently by
/// the durable production backend than by the in-memory test double, and the
/// difference is deliberate:
///
/// - **Suspension.** `InMemoryCredentialStore::suspend_bridge` is a
///   test-harness inherent method, not part of [`BridgeCredentialStore`], never
///   wired by any bridge — so this durable surface has no suspend hook. A
///   durable store it cannot suspend is never suspended; `retrieve` honors the
///   "reject when suspended" contract vacuously.
/// - **Revoke erasure.** The trait's "overwrite with zeros before deletion"
///   line describes the in-memory (RAM) double. The durable backend instead
///   crypto-shreds: it deletes the credential *records* (which is what makes
///   `retrieve` fail, since `retrieve` derives its key from the caller-supplied
///   `bridge_credential_key`) and the stored root-key custody copy, relying on
///   the `EncryptedStorage` backend for at-rest confidentiality. This is a
///   stronger property for durable-at-rest storage than an in-place
///   zero-overwrite (which `SQLCipher` pages do not reliably provide anyway).
#[async_trait]
pub trait DurableCredentialBackend: Send + Sync {
    /// See [`BridgeCredentialStore::provision`].
    async fn provision(
        &self,
        bridge_id: &str,
        credential_type: CredentialType,
        plaintext: &[u8],
        bridge_credential_key: &[u8; 32],
    ) -> Result<BridgeCredential, CredentialError>;

    /// See [`BridgeCredentialStore::retrieve`].
    async fn retrieve(
        &self,
        bridge_id: &str,
        credential_type: &CredentialType,
        bridge_credential_key: &[u8; 32],
    ) -> Result<Zeroizing<Vec<u8>>, CredentialError>;

    /// See [`BridgeCredentialStore::rotate`].
    async fn rotate(
        &self,
        bridge_id: &str,
        credential_type: &CredentialType,
        new_plaintext: &[u8],
        bridge_credential_key: &[u8; 32],
    ) -> Result<BridgeCredential, CredentialError>;

    /// See [`BridgeCredentialStore::revoke`].
    async fn revoke(&self, bridge_id: &str) -> Result<(), CredentialError>;

    /// See [`BridgeCredentialStore::list`].
    async fn list(&self, bridge_id: &str) -> Result<Vec<CredentialType>, CredentialError>;

    /// See [`BridgeCredentialStore::store_bridge_credential_key`].
    async fn store_bridge_credential_key(
        &self,
        bridge_id: &str,
        key: Zeroizing<[u8; 32]>,
    ) -> Result<(), CredentialError>;

    /// See [`BridgeCredentialStore::get_bridge_credential_key`].
    async fn get_bridge_credential_key(
        &self,
        bridge_id: &str,
    ) -> Result<Zeroizing<[u8; 32]>, CredentialError>;

    /// See [`BridgeCredentialStore::delete_bridge_credential_key`].
    async fn delete_bridge_credential_key(&self, bridge_id: &str) -> Result<(), CredentialError>;
}

/// Lifts a persistence-layer [`StoreError`](crate::store::StoreError) into a
/// [`CredentialError::StorageError`].
// Takes the error by value so it can be used directly as a `.map_err(store_err)`
// function pointer (which passes owned `E`).
#[allow(clippy::needless_pass_by_value)]
fn store_err(e: crate::store::StoreError) -> CredentialError {
    CredentialError::StorageError {
        reason: e.to_string(),
    }
}

/// Current Unix time in whole seconds (credential `created_at`).
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ---------------------------------------------------------------------------
// ProtocolRepositoryCredentialStore — the real durable backend
// ---------------------------------------------------------------------------

/// The **real** durable [`BridgeCredentialStore`] backend.
///
/// Bridge credentials and their per-bridge root keys are persisted through the
/// existing [`ProtocolRepository`] substrate (spec §17.4) over any
/// `EncryptedStorage` backend (`SQLCipher` on disk, or an `EncryptingAdapter`
/// in memory — encrypted at rest either way).
///
/// Selected at the FFI bridge construction boundary from the SAME storage
/// handle the bridge already uses for `mls_storage` and the saga journal, so a
/// Sqlite selection persists bridge tokens across process restart and an
/// encrypted-in-memory selection keeps them encrypted at rest — durability
/// tracks the storage selection, by construction (ADR-062 §Decision 5).
///
/// This is a `DurableCredentialBackend` (not a `BridgeCredentialStore`
/// directly) purely so it can be `Arc<dyn …>`-erased behind the
/// `FfiCredentialStore` seam; the enum re-implements `BridgeCredentialStore` by
/// delegating to this trait.
pub struct ProtocolRepositoryCredentialStore<S: EncryptedStorage> {
    repo: ProtocolRepository<S>,
}

impl<S: EncryptedStorage> ProtocolRepositoryCredentialStore<S> {
    /// Wraps an `EncryptedStorage` handle as a durable credential backend.
    #[must_use]
    pub const fn new(storage: S) -> Self {
        Self {
            repo: ProtocolRepository::new(storage),
        }
    }
}

#[async_trait]
impl<S: EncryptedStorage + 'static> DurableCredentialBackend
    for ProtocolRepositoryCredentialStore<S>
{
    async fn provision(
        &self,
        bridge_id: &str,
        credential_type: CredentialType,
        plaintext: &[u8],
        bridge_credential_key: &[u8; 32],
    ) -> Result<BridgeCredential, CredentialError> {
        // Reject duplicates — mirrors the in-memory store's `AlreadyExists`
        // contract. Callers use `rotate` to replace.
        //
        // Best-effort under concurrency: this is a load-check then store over a
        // non-transactional KV backend (no compare-and-swap), so unlike the
        // in-memory store's single `RwLock` critical section, two racing
        // `provision`s for the same `(bridge_id, credential_type)` can both see
        // `None` and last-write-wins instead of one getting `AlreadyExists`.
        // Acceptable for this durability-only, rare admin-path capability;
        // callers needing strict single-writer semantics must quiesce.
        if self
            .repo
            .load_bridge_credential(bridge_id, &credential_type)
            .await
            .map_err(store_err)?
            .is_some()
        {
            return Err(CredentialError::AlreadyExists {
                bridge_id: bridge_id.to_owned(),
                credential_type,
            });
        }

        // Bind the credential-type slot + created_at as AES-GCM AAD (compute
        // `created_at` before sealing so the stored value matches the AAD).
        let created_at = now_secs();
        let key = derive_credential_key(bridge_credential_key, bridge_id)?;
        let aad = credential_aad(&credential_type, created_at);
        let encrypted_data = encrypt_credential(&key, plaintext, &aad)?;
        let credential = BridgeCredential {
            encrypted_data,
            credential_type,
            created_at,
            expires_at: None,
            bridge_id: bridge_id.to_owned(),
        };
        self.repo
            .store_bridge_credential(&credential)
            .await
            .map_err(store_err)?;
        Ok(credential)
    }

    async fn retrieve(
        &self,
        bridge_id: &str,
        credential_type: &CredentialType,
        bridge_credential_key: &[u8; 32],
    ) -> Result<Zeroizing<Vec<u8>>, CredentialError> {
        let credential = self
            .repo
            .load_bridge_credential(bridge_id, credential_type)
            .await
            .map_err(store_err)?
            .ok_or_else(|| CredentialError::NotFound {
                bridge_id: bridge_id.to_owned(),
                credential_type: credential_type.clone(),
            })?;

        let key = derive_credential_key(bridge_credential_key, bridge_id)?;
        // AAD from the SLOT being accessed + the stored `created_at`: a
        // ciphertext moved into a different-type slot fails the GCM tag.
        let aad = credential_aad(credential_type, credential.created_at);
        decrypt_credential(&key, &credential.encrypted_data, &aad)
    }

    async fn rotate(
        &self,
        bridge_id: &str,
        credential_type: &CredentialType,
        new_plaintext: &[u8],
        bridge_credential_key: &[u8; 32],
    ) -> Result<BridgeCredential, CredentialError> {
        // Must already exist — mirrors the in-memory store's `NotFound`. Same
        // best-effort-under-concurrency caveat as `provision`: the existence
        // check and the store are separate round-trips (no CAS), so a race with
        // a concurrent `revoke`/`provision` is last-write-wins rather than
        // strictly serialized.
        if self
            .repo
            .load_bridge_credential(bridge_id, credential_type)
            .await
            .map_err(store_err)?
            .is_none()
        {
            return Err(CredentialError::NotFound {
                bridge_id: bridge_id.to_owned(),
                credential_type: credential_type.clone(),
            });
        }

        let created_at = now_secs();
        let key = derive_credential_key(bridge_credential_key, bridge_id)?;
        let aad = credential_aad(credential_type, created_at);
        let encrypted_data = encrypt_credential(&key, new_plaintext, &aad)?;
        let rotated = BridgeCredential {
            encrypted_data,
            credential_type: credential_type.clone(),
            created_at,
            expires_at: None,
            bridge_id: bridge_id.to_owned(),
        };
        // `store_bridge_credential` overwrites the existing record; the old
        // ciphertext is superseded at rest.
        self.repo
            .store_bridge_credential(&rotated)
            .await
            .map_err(store_err)?;
        Ok(rotated)
    }

    async fn revoke(&self, bridge_id: &str) -> Result<(), CredentialError> {
        // Erasure = deletion of the credential *records* (`retrieve` reads them
        // and derives its AES key from the CALLER-supplied
        // `bridge_credential_key`, not the stored root key, so record deletion —
        // not root-key deletion — is what makes `retrieve` return `NotFound`).
        // Deleting the root key additionally makes `get_bridge_credential_key`
        // return `KeyNotFound`, tearing down the stored custody copy. At-rest
        // confidentiality of any not-yet-overwritten pages rests on the
        // `EncryptedStorage` backend (SQLCipher / `EncryptingAdapter`); this is
        // crypto-shredding, not in-place zero-overwrite.
        //
        // NOTE: these are separate `delete`s with no per-bridge serialization
        // (the durable store is stateless — unlike the in-memory store's
        // `RwLock`). A `rotate`/`provision` racing a `revoke` on the same
        // `bridge_id` could re-materialize a record after `delete_prefix`.
        // Callers MUST quiesce a bridge's credential operations before revoking.
        // Acceptable for this durability-only capability (tokens are
        // re-obtainable by re-auth; same authorized caller, same bridge).
        self.repo
            .delete_bridge_credentials(bridge_id)
            .await
            .map_err(store_err)?;
        self.repo
            .delete_bridge_credential_root_key(bridge_id)
            .await
            .map_err(store_err)?;
        Ok(())
    }

    async fn list(&self, bridge_id: &str) -> Result<Vec<CredentialType>, CredentialError> {
        self.repo
            .list_bridge_credential_types(bridge_id)
            .await
            .map_err(store_err)
    }

    async fn store_bridge_credential_key(
        &self,
        bridge_id: &str,
        key: Zeroizing<[u8; 32]>,
    ) -> Result<(), CredentialError> {
        self.repo
            .store_bridge_credential_root_key(bridge_id, &key)
            .await
            .map_err(store_err)
    }

    async fn get_bridge_credential_key(
        &self,
        bridge_id: &str,
    ) -> Result<Zeroizing<[u8; 32]>, CredentialError> {
        self.repo
            .load_bridge_credential_root_key(bridge_id)
            .await
            .map_err(store_err)?
            .ok_or_else(|| CredentialError::KeyNotFound {
                bridge_id: bridge_id.to_owned(),
            })
    }

    async fn delete_bridge_credential_key(&self, bridge_id: &str) -> Result<(), CredentialError> {
        self.repo
            .delete_bridge_credential_root_key(bridge_id)
            .await
            .map_err(store_err)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Shared bridge credential key for tests (32 bytes, deterministic).
    const TEST_BRIDGE_KEY: &[u8; 32] = b"bridge-credential-key-32-bytes!!";

    /// A different bridge credential key to verify key isolation.
    const OTHER_BRIDGE_KEY: &[u8; 32] = b"other-bridge-credential-key-32b!";

    // -----------------------------------------------------------------------
    // ProtocolRepositoryCredentialStore (durable backend) — the SHIPPED path
    //
    // Exercises `FfiCredentialStore::Durable`'s backend directly over an
    // `EncryptedStorage` (`EncryptingAdapter<InMemoryStorage>`, the same
    // encrypted-at-rest shape the in-memory storage *selection* uses), asserting
    // the durable arm's provision/retrieve/rotate/revoke/list + root-key
    // semantics — not just the raw `ProtocolRepository` methods (covered by the
    // on-disk restart test in `store::credentials`) or the in-memory enum arm
    // (covered in `scp-ffi-common`). SCP-CAPINJECT-009.
    // -----------------------------------------------------------------------

    /// Builds a durable credential store over encrypted-at-rest in-memory
    /// storage (`EncryptedStorage`, so it drives the production
    /// `ProtocolRepository::new` path — never `new_for_testing`).
    fn durable_store() -> ProtocolRepositoryCredentialStore<
        std::sync::Arc<
            scp_platform::encrypting_adapter::EncryptingAdapter<
                scp_platform::in_memory::InMemoryStorage,
            >,
        >,
    > {
        let key = Zeroizing::new([7u8; 32]);
        let handle = std::sync::Arc::new(scp_platform::encrypting_adapter::EncryptingAdapter::new(
            scp_platform::in_memory::InMemoryStorage::new(),
            key,
        ));
        ProtocolRepositoryCredentialStore::new(handle)
    }

    #[tokio::test]
    async fn durable_provision_and_retrieve_roundtrip() {
        let store = durable_store();
        let plaintext = b"oauth-access-token-abc123";

        let cred = store
            .provision(
                "bridge-001",
                CredentialType::OAuthAccessToken,
                plaintext,
                TEST_BRIDGE_KEY,
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
                TEST_BRIDGE_KEY,
            )
            .await
            .expect("retrieve");
        assert_eq!(retrieved.as_slice(), plaintext);
    }

    #[tokio::test]
    async fn durable_provision_duplicate_returns_already_exists() {
        let store = durable_store();
        store
            .provision(
                "bridge-001",
                CredentialType::ApiKey,
                b"key-1",
                TEST_BRIDGE_KEY,
            )
            .await
            .expect("first provision");

        let result = store
            .provision(
                "bridge-001",
                CredentialType::ApiKey,
                b"key-2",
                TEST_BRIDGE_KEY,
            )
            .await;
        assert!(matches!(result, Err(CredentialError::AlreadyExists { .. })));
    }

    #[tokio::test]
    async fn durable_retrieve_nonexistent_returns_not_found() {
        let store = durable_store();
        let result = store
            .retrieve("bridge-001", &CredentialType::ApiKey, TEST_BRIDGE_KEY)
            .await;
        assert!(matches!(result, Err(CredentialError::NotFound { .. })));
    }

    #[tokio::test]
    async fn durable_cross_bridge_access_returns_not_found() {
        let store = durable_store();
        store
            .provision(
                "bridge-001",
                CredentialType::ApiKey,
                b"secret-key",
                TEST_BRIDGE_KEY,
            )
            .await
            .expect("provision");

        // A different bridge id must not see bridge-001's credential.
        let result = store
            .retrieve("bridge-002", &CredentialType::ApiKey, TEST_BRIDGE_KEY)
            .await;
        assert!(matches!(result, Err(CredentialError::NotFound { .. })));
    }

    #[tokio::test]
    async fn durable_rotate_replaces_credential() {
        let store = durable_store();
        store
            .provision(
                "bridge-001",
                CredentialType::OAuthAccessToken,
                b"old-token",
                TEST_BRIDGE_KEY,
            )
            .await
            .expect("provision");

        store
            .rotate(
                "bridge-001",
                &CredentialType::OAuthAccessToken,
                b"new-token",
                TEST_BRIDGE_KEY,
            )
            .await
            .expect("rotate");

        let retrieved = store
            .retrieve(
                "bridge-001",
                &CredentialType::OAuthAccessToken,
                TEST_BRIDGE_KEY,
            )
            .await
            .expect("retrieve");
        assert_eq!(retrieved.as_slice(), b"new-token");
    }

    #[tokio::test]
    async fn durable_rotate_nonexistent_returns_not_found() {
        let store = durable_store();
        let result = store
            .rotate(
                "bridge-001",
                &CredentialType::ApiKey,
                b"new-value",
                TEST_BRIDGE_KEY,
            )
            .await;
        assert!(matches!(result, Err(CredentialError::NotFound { .. })));
    }

    #[tokio::test]
    async fn durable_wrong_key_fails_to_decrypt() {
        let store = durable_store();
        store
            .provision(
                "bridge-001",
                CredentialType::ApiKey,
                b"secret",
                TEST_BRIDGE_KEY,
            )
            .await
            .expect("provision");

        // Retrieval with a different bridge_credential_key must fail the AEAD.
        let result = store
            .retrieve("bridge-001", &CredentialType::ApiKey, OTHER_BRIDGE_KEY)
            .await;
        assert!(matches!(result, Err(CredentialError::CryptoError { .. })));
    }

    #[tokio::test]
    async fn durable_list_returns_all_credential_types() {
        let store = durable_store();
        for ct in [
            CredentialType::OAuthAccessToken,
            CredentialType::ApiKey,
            CredentialType::Custom("discord-bot-token".to_owned()),
        ] {
            store
                .provision("bridge-001", ct, b"v", TEST_BRIDGE_KEY)
                .await
                .expect("provision");
        }

        let mut types = store.list("bridge-001").await.expect("list");
        types.sort_by_key(std::string::ToString::to_string);
        assert_eq!(types.len(), 3);
        assert!(types.contains(&CredentialType::OAuthAccessToken));
        assert!(types.contains(&CredentialType::ApiKey));
        assert!(types.contains(&CredentialType::Custom("discord-bot-token".to_owned())));
    }

    #[tokio::test]
    async fn durable_revoke_destroys_credentials_and_root_key() {
        let store = durable_store();
        let root = generate_bridge_credential_key();
        let raw = *root;

        store
            .store_bridge_credential_key("bridge-001", root)
            .await
            .expect("store key");
        store
            .provision("bridge-001", CredentialType::ApiKey, b"secret", &raw)
            .await
            .expect("provision");
        // A second bridge must survive the revoke of the first.
        store
            .provision(
                "bridge-002",
                CredentialType::ApiKey,
                b"keep",
                TEST_BRIDGE_KEY,
            )
            .await
            .expect("provision bridge-002");

        store.revoke("bridge-001").await.expect("revoke");

        // Records gone → retrieve NotFound; list empty.
        assert!(matches!(
            store
                .retrieve("bridge-001", &CredentialType::ApiKey, &raw)
                .await,
            Err(CredentialError::NotFound { .. })
        ));
        assert!(store.list("bridge-001").await.expect("list").is_empty());
        // Stored root-key custody copy destroyed → KeyNotFound.
        assert!(matches!(
            store.get_bridge_credential_key("bridge-001").await,
            Err(CredentialError::KeyNotFound { .. })
        ));
        // bridge-002 untouched.
        let kept = store
            .retrieve("bridge-002", &CredentialType::ApiKey, TEST_BRIDGE_KEY)
            .await
            .expect("retrieve bridge-002");
        assert_eq!(kept.as_slice(), b"keep");
    }

    #[tokio::test]
    async fn durable_store_get_delete_root_key_roundtrip() {
        let store = durable_store();
        let root = generate_bridge_credential_key();
        let expected = *root;

        store
            .store_bridge_credential_key("bridge-001", root)
            .await
            .expect("store key");
        let got = store
            .get_bridge_credential_key("bridge-001")
            .await
            .expect("get key");
        assert_eq!(*got, expected);

        store
            .delete_bridge_credential_key("bridge-001")
            .await
            .expect("delete key");
        assert!(matches!(
            store.get_bridge_credential_key("bridge-001").await,
            Err(CredentialError::KeyNotFound { .. })
        ));
    }

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
        let key1 = derive_credential_key(TEST_BRIDGE_KEY, "bridge-001").expect("derive");
        let key2 = derive_credential_key(TEST_BRIDGE_KEY, "bridge-001").expect("derive");

        assert_eq!(*key1, *key2, "same inputs must produce same key");
    }

    #[test]
    fn derive_credential_key_differs_by_bridge_id() {
        let key1 = derive_credential_key(TEST_BRIDGE_KEY, "bridge-001").expect("derive");
        let key2 = derive_credential_key(TEST_BRIDGE_KEY, "bridge-002").expect("derive");

        assert_ne!(
            *key1, *key2,
            "different bridge IDs must produce different keys"
        );
    }

    #[test]
    fn derive_credential_key_differs_by_ikm() {
        let key1 = derive_credential_key(TEST_BRIDGE_KEY, "bridge-001").expect("derive");
        let key2 = derive_credential_key(OTHER_BRIDGE_KEY, "bridge-001").expect("derive");

        assert_ne!(
            *key1, *key2,
            "different bridge credential keys must produce different keys"
        );
    }

    #[test]
    fn derive_credential_key_different_bridges_different_ikm_produces_different_keys() {
        let key1 = derive_credential_key(TEST_BRIDGE_KEY, "bridge-001").expect("derive");
        let key2 = derive_credential_key(OTHER_BRIDGE_KEY, "bridge-002").expect("derive");

        assert_ne!(
            *key1, *key2,
            "different bridge_credential_key + different bridge_id must produce different keys"
        );
    }

    #[test]
    fn derive_credential_key_same_bridge_id_different_ikm_key_isolation() {
        // Verifies that two bridges with the same bridge_id but different
        // bridge_credential_key values produce completely different derived keys,
        // confirming that the IKM (not just the info string) drives key isolation.
        let key1 = derive_credential_key(TEST_BRIDGE_KEY, "shared-bridge-id").expect("derive");
        let key2 = derive_credential_key(OTHER_BRIDGE_KEY, "shared-bridge-id").expect("derive");

        assert_ne!(
            *key1, *key2,
            "same bridge_id with different IKM must produce different keys (key isolation)"
        );
    }

    // -----------------------------------------------------------------------
    // Encrypt/decrypt roundtrip tests
    // -----------------------------------------------------------------------

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = derive_credential_key(TEST_BRIDGE_KEY, "bridge-001").expect("derive");
        let aad = credential_aad(&CredentialType::ApiKey, 1_700_000_000);

        let plaintext = b"my-secret-api-key-12345";
        let encrypted = encrypt_credential(&key, plaintext, &aad).expect("encrypt");

        // Encrypted output must be longer than plaintext (nonce + tag).
        assert!(encrypted.len() > plaintext.len());

        let decrypted = decrypt_credential(&key, &encrypted, &aad).expect("decrypt");
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let key1 = derive_credential_key(TEST_BRIDGE_KEY, "bridge-001").expect("derive");
        let key2 = derive_credential_key(OTHER_BRIDGE_KEY, "bridge-001").expect("derive");
        let aad = credential_aad(&CredentialType::ApiKey, 1_700_000_000);

        let encrypted = encrypt_credential(&key1, b"secret", &aad).expect("encrypt");
        let result = decrypt_credential(&key2, &encrypted, &aad);

        assert!(result.is_err(), "wrong key must fail decryption");
    }

    #[test]
    fn decrypt_truncated_data_fails() {
        let aad = credential_aad(&CredentialType::ApiKey, 1_700_000_000);
        let result = decrypt_credential(&[0u8; 32], &[0u8; 5], &aad);
        assert!(result.is_err(), "data shorter than nonce must fail");
    }

    #[test]
    fn credential_aad_is_unambiguous_across_type_and_time() {
        // Distinct (type, created_at) → distinct AAD bytes; the length prefix
        // prevents a Custom name from spoofing the trailing timestamp bytes.
        let a = credential_aad(&CredentialType::ApiKey, 1);
        let b = credential_aad(&CredentialType::ApiKey, 2);
        let c = credential_aad(&CredentialType::OAuthAccessToken, 1);
        let d = credential_aad(&CredentialType::Custom("ApiKey".to_owned()), 1);
        assert_ne!(a, b, "differing created_at must differ");
        assert_ne!(a, c, "differing type must differ");
        assert_ne!(a, d, "Custom(\"ApiKey\") must not collide with ApiKey");
        // Deterministic: same inputs → identical bytes (required for decrypt).
        assert_eq!(a, credential_aad(&CredentialType::ApiKey, 1));
    }

    #[test]
    fn decrypt_with_wrong_slot_aad_fails() {
        // Slot-swap: seal under credential-type A, attempt to open with the AAD
        // of a DIFFERENT slot (type B) at the same key/timestamp. GCM tag must
        // reject it rather than returning misattributed plaintext.
        let key = derive_credential_key(TEST_BRIDGE_KEY, "bridge-001").expect("derive");
        let created_at = 1_700_000_000;
        let aad_a = credential_aad(&CredentialType::OAuthAccessToken, created_at);
        let aad_b = credential_aad(&CredentialType::ApiKey, created_at);

        let sealed = encrypt_credential(&key, b"token", &aad_a).expect("encrypt");
        let result = decrypt_credential(&key, &sealed, &aad_b);
        assert!(
            matches!(result, Err(CredentialError::CryptoError { .. })),
            "wrong-slot AAD must fail the GCM tag, not decrypt"
        );
        // Sanity: the correct slot AAD still opens it.
        assert_eq!(
            decrypt_credential(&key, &sealed, &aad_a)
                .expect("correct AAD decrypts")
                .as_slice(),
            b"token"
        );
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
                TEST_BRIDGE_KEY,
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
                TEST_BRIDGE_KEY,
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
                TEST_BRIDGE_KEY,
            )
            .await
            .expect("first provision");

        let result = store
            .provision(
                "bridge-001",
                CredentialType::ApiKey,
                b"key-2",
                TEST_BRIDGE_KEY,
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
            .retrieve("bridge-001", &CredentialType::ApiKey, TEST_BRIDGE_KEY)
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
                TEST_BRIDGE_KEY,
            )
            .await
            .expect("provision");

        // Attempt to retrieve from a different bridge -- must fail.
        let result = store
            .retrieve("bridge-002", &CredentialType::ApiKey, TEST_BRIDGE_KEY)
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
                TEST_BRIDGE_KEY,
            )
            .await
            .expect("provision");

        let rotated = store
            .rotate(
                "bridge-001",
                &CredentialType::OAuthAccessToken,
                b"new-token",
                TEST_BRIDGE_KEY,
            )
            .await
            .expect("rotate");

        assert_eq!(rotated.bridge_id, "bridge-001");

        // Retrieve should return the new value.
        let retrieved = store
            .retrieve(
                "bridge-001",
                &CredentialType::OAuthAccessToken,
                TEST_BRIDGE_KEY,
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
                TEST_BRIDGE_KEY,
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
                TEST_BRIDGE_KEY,
            )
            .await
            .expect("provision access token");

        store
            .provision(
                "bridge-001",
                CredentialType::OAuthRefreshToken,
                b"refresh",
                TEST_BRIDGE_KEY,
            )
            .await
            .expect("provision refresh token");

        store
            .provision(
                "bridge-001",
                CredentialType::WebhookSecret,
                b"webhook-secret",
                TEST_BRIDGE_KEY,
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
                TEST_BRIDGE_KEY,
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
                TEST_BRIDGE_KEY,
            )
            .await
            .expect("provision bridge-001");

        store
            .provision(
                "bridge-002",
                CredentialType::ApiKey,
                b"key-2",
                TEST_BRIDGE_KEY,
            )
            .await
            .expect("provision bridge-002");

        // Revoke bridge-001 only.
        store.revoke("bridge-001").await.expect("revoke");

        // bridge-002 should be unaffected.
        let retrieved = store
            .retrieve("bridge-002", &CredentialType::ApiKey, TEST_BRIDGE_KEY)
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
                TEST_BRIDGE_KEY,
            )
            .await
            .expect("provision");

        // Suspend the bridge.
        store.suspend_bridge("bridge-001");

        // Retrieve should fail with BridgeSuspended.
        let result = store
            .retrieve("bridge-001", &CredentialType::ApiKey, TEST_BRIDGE_KEY)
            .await;

        assert!(
            matches!(result, Err(CredentialError::BridgeSuspended { .. })),
            "suspended bridge must block retrieval"
        );

        // Reactivate the bridge.
        store.reactivate_bridge("bridge-001");

        // Retrieve should succeed again.
        let retrieved = store
            .retrieve("bridge-001", &CredentialType::ApiKey, TEST_BRIDGE_KEY)
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
                TEST_BRIDGE_KEY,
            )
            .await
            .expect("provision");

        store
            .provision(
                "bridge-001",
                CredentialType::ApiKey,
                b"key",
                TEST_BRIDGE_KEY,
            )
            .await
            .expect("provision");

        store
            .provision(
                "bridge-001",
                CredentialType::Custom("discord-bot-token".to_owned()),
                b"bot-token",
                TEST_BRIDGE_KEY,
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
                .provision("bridge-001", ct.clone(), plaintext, TEST_BRIDGE_KEY)
                .await
                .expect("provision");
        }

        // Verify each can be independently retrieved.
        for (ct, expected) in &types_to_provision {
            let retrieved = store
                .retrieve("bridge-001", ct, TEST_BRIDGE_KEY)
                .await
                .expect("retrieve");
            assert_eq!(retrieved.as_slice(), *expected);
        }
    }

    // -----------------------------------------------------------------------
    // Finding 1: CSPRNG provisioning tests
    // -----------------------------------------------------------------------

    #[test]
    fn generate_bridge_credential_key_produces_unique_keys() {
        let key1 = generate_bridge_credential_key();
        let key2 = generate_bridge_credential_key();

        assert_ne!(
            key1, key2,
            "two CSPRNG-generated keys must differ (collision probability ~2^-256)"
        );
    }

    // -----------------------------------------------------------------------
    // Finding 2: Bridge credential key custody tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn store_and_retrieve_bridge_credential_key_roundtrip() {
        let store = InMemoryCredentialStore::new();
        let key = generate_bridge_credential_key();
        let expected = *key;

        store
            .store_bridge_credential_key("bridge-001", key)
            .await
            .expect("store key");

        let retrieved = store
            .get_bridge_credential_key("bridge-001")
            .await
            .expect("get key");

        assert_eq!(*retrieved, expected, "retrieved key must match stored key");
    }

    #[tokio::test]
    async fn get_missing_bridge_credential_key_returns_not_found() {
        let store = InMemoryCredentialStore::new();

        let result = store.get_bridge_credential_key("bridge-nonexistent").await;

        assert!(
            matches!(result, Err(CredentialError::KeyNotFound { .. })),
            "missing bridge credential key must return KeyNotFound"
        );
    }

    // -----------------------------------------------------------------------
    // Finding 3: Revoke destroys bridge credential key
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn revoke_destroys_bridge_credential_key() {
        let store = InMemoryCredentialStore::new();
        let key = generate_bridge_credential_key();
        let raw_key = *key;

        // Store a key and a credential.
        store
            .store_bridge_credential_key("bridge-001", key)
            .await
            .expect("store key");

        store
            .provision("bridge-001", CredentialType::ApiKey, b"secret", &raw_key)
            .await
            .expect("provision");

        // Revoke the bridge.
        store.revoke("bridge-001").await.expect("revoke");

        // Bridge credential key must be gone.
        let result = store.get_bridge_credential_key("bridge-001").await;
        assert!(
            matches!(result, Err(CredentialError::KeyNotFound { .. })),
            "bridge credential key must be destroyed after revoke"
        );
    }
}
