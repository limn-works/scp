//! Platform abstraction traits for key custody, storage, device attestation, and push.
//!
//! These traits define the contract between SCP protocol operations and
//! platform-specific capabilities. Production implementations back onto hardware
//! security (Secure Enclave, Android Keystore). Testing implementations use
//! in-memory stores. See ADR-006.

use async_trait::async_trait;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors returned by platform abstraction operations.
#[derive(Debug, Error)]
pub enum PlatformError {
    /// The requested key handle does not exist or has been destroyed.
    #[error("key not found: handle {0}")]
    KeyNotFound(u64),

    /// The operation is not valid for the key type (e.g., signing with an X25519 key).
    #[error("invalid key type for this operation")]
    InvalidKeyType,

    /// The key custody backend is unavailable (e.g., Secure Enclave locked).
    #[error("custody unavailable: {0}")]
    CustodyUnavailable(String),

    /// A storage operation failed.
    #[error("storage error: {0}")]
    StorageError(String),

    /// A signing operation failed.
    #[error("signing failed: {0}")]
    SigningFailed(String),

    /// An attestation operation failed.
    #[error("attestation error: {0}")]
    AttestationError(String),

    /// A push notification operation failed.
    #[error("push error: {0}")]
    PushError(String),

    /// A Diffie-Hellman key agreement operation failed.
    #[error("key agreement failed: {0}")]
    KeyAgreementFailed(String),

    /// A pseudonym derivation operation failed.
    #[error("pseudonym derivation failed: {0}")]
    PseudonymDerivationFailed(String),
}

// ---------------------------------------------------------------------------
// Key types and handles
// ---------------------------------------------------------------------------

/// The type of cryptographic key managed by this handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// Ed25519 signing key (identity key, pseudonym keys).
    Ed25519,
    /// X25519 key agreement key (HPKE wrapping keys).
    X25519,
}

/// Opaque handle to a key managed by a [`KeyCustody`] implementation.
///
/// The inner value is an opaque identifier; callers must not interpret it.
/// The `pub(crate)` visibility allows testing adapters within the crate to
/// construct handles directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyHandle(pub(crate) u64);

impl KeyHandle {
    /// Returns the raw numeric identifier for this handle.
    #[must_use]
    pub const fn id(&self) -> u64 {
        self.0
    }
}

/// An Ed25519 signature (64 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature(pub Vec<u8>);

/// A public key — either Ed25519 (32 bytes) or X25519 (32 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    /// The raw public key bytes.
    pub bytes: Vec<u8>,
    /// The key type this public key belongs to.
    pub key_type: KeyType,
}

/// A 32-byte shared secret produced by X25519 Diffie-Hellman key agreement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedSecret(pub [u8; 32]);

/// A deterministic pseudonym keypair derived from an identity key and context ID.
///
/// The pseudonym keypair is always software-managed (derived output),
/// even when the source identity key is hardware-backed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PseudonymKeypair {
    /// The Ed25519 public key of the pseudonym.
    pub public_key: Vec<u8>,
    /// The Ed25519 private key bytes of the pseudonym (32-byte seed).
    pub private_key: Vec<u8>,
}

/// The type of custody backing a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyType {
    /// Key is stored in software memory only.
    InMemory,
    /// Key is backed by a hardware security module (Secure Enclave, Android Keystore).
    Hardware,
}

// ---------------------------------------------------------------------------
// Attestation and push types
// ---------------------------------------------------------------------------

/// An opaque device attestation token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceAttestationToken(pub Vec<u8>);

/// An opaque push notification registration token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushToken(pub String);

/// A wake signal produced when a push notification is processed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WakeSignal(pub Vec<u8>);

// ---------------------------------------------------------------------------
// Traits
// ---------------------------------------------------------------------------

/// Key custody — manages cryptographic key lifecycle and operations.
///
/// Implementations guard private key material behind an opaque [`KeyHandle`].
/// Private keys never leave the custody boundary for hardware-backed
/// implementations. All async methods use `#[async_trait]` for object safety
/// (`Box<dyn KeyCustody>` must work). See ADR-006.
#[async_trait]
pub trait KeyCustody: Send + Sync {
    /// Generate a new keypair of the specified type.
    ///
    /// Ed25519 keys may be hardware-backed. X25519 wrapping keys are
    /// always software-managed but routed through `KeyCustody` for API
    /// consistency. Returns an opaque [`KeyHandle`].
    async fn generate_keypair(&self, key_type: KeyType) -> Result<KeyHandle, PlatformError>;

    /// Sign data with an Ed25519 key.
    ///
    /// Returns an error if the key handle refers to an X25519 key
    /// ([`PlatformError::InvalidKeyType`]).
    async fn sign(&self, key: &KeyHandle, data: &[u8]) -> Result<Signature, PlatformError>;

    /// Return the public key for a handle.
    async fn public_key(&self, key: &KeyHandle) -> Result<PublicKey, PlatformError>;

    /// Destroy key material. Subsequent operations with this handle fail
    /// with [`PlatformError::KeyNotFound`].
    async fn destroy_key(&self, key: &KeyHandle) -> Result<(), PlatformError>;

    /// Perform X25519 Diffie-Hellman key agreement.
    ///
    /// Returns the 32-byte shared secret. The private key never leaves the
    /// custody boundary (scalar multiplication happens inside the adapter).
    /// Returns an error if the key handle refers to an Ed25519 key
    /// ([`PlatformError::InvalidKeyType`]).
    async fn dh_agree(
        &self,
        key: &KeyHandle,
        peer_public: &[u8; 32],
    ) -> Result<SharedSecret, PlatformError>;

    /// Derive a deterministic, context-scoped pseudonym keypair.
    ///
    /// Algorithm (all implementations MUST produce identical output):
    ///   1. `seed = HMAC-SHA256(identity_key_material, context_id || "scp-pseudonym")`
    ///   2. `pseudonym_keypair = Ed25519_keygen(seed[0..32])`
    ///
    /// For hardware-backed keys: the HMAC is computed inside the HSM using
    /// an associated symmetric key derived during `generate_keypair`.
    /// For software keys: the HMAC uses the raw Ed25519 private key bytes.
    ///
    /// The returned [`PseudonymKeypair`] is always software-managed (derived output).
    /// Returns an error if the key handle refers to an X25519 key
    /// ([`PlatformError::InvalidKeyType`]).
    async fn derive_pseudonym(
        &self,
        key: &KeyHandle,
        context_id: &[u8],
    ) -> Result<PseudonymKeypair, PlatformError>;

    /// Returns the custody type for a given key handle.
    fn custody_type(&self, key: &KeyHandle) -> CustodyType;
}

/// Persistent key-value storage abstraction.
///
/// Implementations may back onto in-memory maps, `SQLite`, or platform-specific
/// secure storage. Keys are UTF-8 strings; values are opaque byte slices.
/// See ADR-006.
#[async_trait]
pub trait Storage: Send + Sync {
    /// Store bytes under the given key, overwriting any existing value.
    async fn store(&self, key: &str, data: &[u8]) -> Result<(), PlatformError>;

    /// Retrieve the bytes stored under the given key, or `None` if absent.
    async fn retrieve(&self, key: &str) -> Result<Option<Vec<u8>>, PlatformError>;

    /// Delete the value stored under the given key. No-op if absent.
    async fn delete(&self, key: &str) -> Result<(), PlatformError>;

    /// List all keys matching the given prefix, in lexicographic order.
    ///
    /// Useful for `KeyPackage` buffer management, event log range queries,
    /// and similar enumeration patterns.
    async fn list_keys(&self, prefix: &str) -> Result<Vec<String>, PlatformError>;

    /// Delete all keys matching a prefix. Returns the count of deleted entries.
    ///
    /// Used for context cleanup (see spec section 17.2).
    async fn delete_prefix(&self, prefix: &str) -> Result<u64, PlatformError>;

    /// Check whether a key exists without reading its value.
    ///
    /// Used for UCAN nonce replay prevention (see spec section 17.2).
    async fn exists(&self, key: &str) -> Result<bool, PlatformError>;
}

/// Device attestation — proves that code is running on genuine hardware.
///
/// Production implementations delegate to platform attestation APIs
/// (Apple App Attest, Android Key Attestation). Testing implementations
/// return synthetic tokens that always verify. See ADR-006.
#[async_trait]
pub trait DeviceAttestation: Send + Sync {
    /// Generate a device attestation token.
    async fn attest(&self) -> Result<DeviceAttestationToken, PlatformError>;

    /// Verify a device attestation token.
    async fn verify(&self, token: &DeviceAttestationToken) -> Result<bool, PlatformError>;
}

/// Push notification registration and handling.
///
/// Production implementations delegate to APNs (iOS) or FCM (Android).
/// Testing implementations return synthetic tokens. See ADR-006.
#[async_trait]
pub trait Push: Send + Sync {
    /// Register for push notifications. Returns an opaque push token.
    async fn register(&self) -> Result<PushToken, PlatformError>;

    /// Process an incoming push notification payload into a wake signal.
    async fn handle_notification(&self, payload: &[u8]) -> Result<WakeSignal, PlatformError>;
}
