//! Platform abstraction traits for SCP.
//!
//! These four traits abstract device-specific capabilities behind Rust trait
//! interfaces so that production implementations (Secure Enclave, Android
//! Keystore) and testing implementations (in-memory) share the same API
//! surface. See ADR-006 for the full platform adapter design.
//!
//! # Traits
//!
//! - [`KeyCustody`] — Cryptographic key management (generation, signing, ECDH, pseudonym derivation)
//! - [`DeviceAttestation`] — Device-level attestation tokens
//! - [`Push`] — Push notification registration and handling
//! - [`Storage`] — Persistent key-value byte storage

use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use crate::error::PlatformError;

// ---------------------------------------------------------------------------
// Supporting types
// ---------------------------------------------------------------------------

/// The type of cryptographic key managed by a [`KeyHandle`].
///
/// See ADR-006 for usage: Ed25519 keys are used for identity and signing,
/// X25519 keys are used for key agreement (HPKE wrapping keys).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyType {
    /// Ed25519 signing key (identity keys, active signing keys, pseudonym keys).
    Ed25519,
    /// X25519 key agreement key (HPKE wrapping keys).
    X25519,
}

/// Opaque handle to a cryptographic key managed by a [`KeyCustody`] implementation.
///
/// The handle is an integer identifier. Implementations map this to actual key
/// material stored internally (e.g., in a `HashMap`, Secure Enclave slot, or
/// Android Keystore alias). The raw private key never leaves the custody
/// boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyHandle(u64);

impl KeyHandle {
    /// Creates a new key handle from a raw identifier.
    ///
    /// This is intended for [`KeyCustody`] implementations that allocate
    /// integer IDs for their managed keys.
    #[must_use]
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// Returns the raw integer identifier for this handle.
    #[must_use]
    pub const fn id(&self) -> u64 {
        self.0
    }
}

/// A public key extracted from a [`KeyHandle`].
///
/// Contains the raw public key bytes — Ed25519 (32 bytes) or X25519 (32 bytes).
/// The interpretation depends on the [`KeyType`] of the originating handle.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PublicKey(Vec<u8>);

impl PublicKey {
    /// Creates a new public key from raw bytes.
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns a reference to the raw public key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes this value and returns the raw public key bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// An Ed25519 signature produced by [`KeyCustody::sign`].
///
/// Contains the raw 64-byte Ed25519 signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature(Vec<u8>);

impl Signature {
    /// Creates a new signature from raw bytes.
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns a reference to the raw signature bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes this value and returns the raw signature bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// A 32-byte X25519 shared secret produced by [`KeyCustody::dh_agree`].
///
/// This type intentionally does **not** implement [`Clone`] or [`Serialize`] to
/// prevent accidental duplication or serialization of secret material. Callers
/// should consume the secret and then let it be dropped.
///
/// **Zeroization:** The inner bytes are automatically zeroed on drop via
/// [`ZeroizeOnDrop`], ensuring key material is cleared from memory.
#[derive(Debug, PartialEq, Eq, ZeroizeOnDrop)]
pub struct SharedSecret([u8; 32]);

impl SharedSecret {
    /// Creates a new shared secret from a 32-byte array.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns a reference to the raw shared secret bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A deterministic pseudonym keypair derived from an identity key and a context
/// ID via [`KeyCustody::derive_pseudonym`].
///
/// The derivation algorithm is specified in ADR-006:
///   1. `seed = HMAC-SHA256(identity_key_material, context_id || "scp-pseudonym")`
///   2. `pseudonym_keypair = Ed25519_keygen(seed[0..32])`
///
/// The returned keypair is always software-managed regardless of whether the
/// source identity key is hardware-backed.
#[derive(Debug, Clone)]
pub struct PseudonymKeypair {
    /// The public key of the derived pseudonym.
    pub public_key: PublicKey,
    /// A handle to the derived pseudonym's signing key, managed by the
    /// [`KeyCustody`] implementation.
    pub key_handle: KeyHandle,
}

/// The custody type for a given key, indicating where the key material is
/// stored and how it is protected.
///
/// See ADR-006 for the custody model: production adapters use hardware-backed
/// custody, while the testing adapter uses [`CustodyType::InMemory`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CustodyType {
    /// Key material is stored in memory only (testing adapter).
    InMemory,
    /// Key material is protected by a hardware security module (Secure Enclave,
    /// Android Keystore, TPM).
    Hardware,
    /// Key material is stored in software (e.g., encrypted file on disk) but
    /// not in a hardware security module.
    Software,
}

/// A device attestation token produced by [`DeviceAttestation::attest`].
///
/// The token format is platform-specific (e.g., Apple App Attest, Android
/// `SafetyNet`). The testing adapter returns a synthetic token. See ADR-006.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceAttestationToken(Vec<u8>);

impl DeviceAttestationToken {
    /// Creates a new attestation token from raw bytes.
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns a reference to the raw token bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes this value and returns the raw token bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// A push notification token returned by [`Push::register`].
///
/// The token format is platform-specific (e.g., APNs device token, FCM
/// registration token). The testing adapter returns a synthetic UUID. See ADR-006.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushToken(Vec<u8>);

impl PushToken {
    /// Creates a new push token from raw bytes.
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns a reference to the raw token bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes this value and returns the raw token bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// A wake signal produced by [`Push::handle_notification`].
///
/// Indicates that the application should wake up and process pending messages.
/// The payload carries transport-specific context (e.g., which context has new
/// messages). See ADR-006.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WakeSignal {
    /// The raw notification payload that triggered this wake signal.
    pub payload: Vec<u8>,
}

impl WakeSignal {
    /// Creates a new wake signal from a notification payload.
    #[must_use]
    pub const fn new(payload: Vec<u8>) -> Self {
        Self { payload }
    }
}

// ---------------------------------------------------------------------------
// Trait definitions
// ---------------------------------------------------------------------------

/// Cryptographic key management trait.
///
/// Abstracts key generation, signing, key agreement, and pseudonym derivation
/// behind a uniform interface. Production implementations delegate to hardware
/// security modules (Secure Enclave on iOS, Android Keystore on Android). The
/// testing implementation ([`InMemoryKeyCustody`](ADR-006)) stores keys in a
/// `HashMap`.
///
/// All methods that perform I/O or hardware interaction are `async`. The
/// [`custody_type`](KeyCustody::custody_type) method is synchronous because it
/// only inspects local state.
///
/// See ADR-006 for the full design rationale.
pub trait KeyCustody: Send + Sync {
    /// Generate a new keypair of the specified type.
    ///
    /// Ed25519 keys may be hardware-backed (Secure Enclave, Keystore).
    /// X25519 wrapping keys are always software-managed but routed through
    /// `KeyCustody` for API consistency.
    ///
    /// Returns an opaque [`KeyHandle`] that references the generated key.
    fn generate_keypair(
        &self,
        key_type: KeyType,
    ) -> impl Future<Output = Result<KeyHandle, PlatformError>> + Send;

    /// Sign data with an Ed25519 key.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::KeyNotFound`] if the handle is invalid.
    /// Returns [`PlatformError::WrongKeyType`] if the handle refers to an
    /// X25519 key.
    fn sign(
        &self,
        key: &KeyHandle,
        data: &[u8],
    ) -> impl Future<Output = Result<Signature, PlatformError>> + Send;

    /// Return the public key for a handle.
    ///
    /// Works for both Ed25519 and X25519 key handles.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::KeyNotFound`] if the handle is invalid.
    fn public_key(
        &self,
        key: &KeyHandle,
    ) -> impl Future<Output = Result<PublicKey, PlatformError>> + Send;

    /// Destroy key material associated with a handle.
    ///
    /// After this call, all subsequent operations with the same handle will
    /// return [`PlatformError::KeyNotFound`].
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::KeyNotFound`] if the handle is already invalid.
    fn destroy_key(
        &self,
        key: &KeyHandle,
    ) -> impl Future<Output = Result<(), PlatformError>> + Send;

    /// Perform X25519 Diffie-Hellman key agreement.
    ///
    /// Returns the 32-byte shared secret. The private key never leaves the
    /// custody boundary — the scalar multiplication happens inside the adapter.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::KeyNotFound`] if the handle is invalid.
    /// Returns [`PlatformError::WrongKeyType`] if the handle refers to an
    /// Ed25519 key.
    fn dh_agree(
        &self,
        key: &KeyHandle,
        peer_public: &[u8; 32],
    ) -> impl Future<Output = Result<SharedSecret, PlatformError>> + Send;

    /// Derive a deterministic, context-scoped pseudonym keypair (v1, non-rotatable).
    ///
    /// Algorithm (all implementations MUST produce identical output):
    ///   1. `seed = HMAC-SHA256(identity_key_material, context_id || "scp-pseudonym")`
    ///   2. `pseudonym_keypair = Ed25519_keygen(seed[0..32])`
    ///
    /// For hardware-backed keys: the HMAC is computed inside the HSM using an
    /// associated symmetric key derived during [`generate_keypair`](KeyCustody::generate_keypair).
    /// For software keys: the HMAC uses the raw Ed25519 public key bytes (ADR-027 amendment).
    ///
    /// The returned [`PseudonymKeypair`] is always software-managed (derived
    /// output).
    ///
    /// For contexts that support pseudonym rotation (BLACK-001 mitigation),
    /// use [`derive_rotatable_pseudonym`](KeyCustody::derive_rotatable_pseudonym) instead.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::KeyNotFound`] if the handle is invalid.
    /// Returns [`PlatformError::WrongKeyType`] if the handle refers to an
    /// X25519 key.
    fn derive_pseudonym(
        &self,
        key: &KeyHandle,
        context_id: &[u8],
    ) -> impl Future<Output = Result<PseudonymKeypair, PlatformError>> + Send;

    /// Derive a rotatable, epoch-scoped pseudonym keypair (v2).
    ///
    /// Mitigates relay-side pseudonym correlation (BLACK-001) by including a
    /// rotation epoch in the HMAC derivation, producing a different pseudonym
    /// for each epoch within the same context.
    ///
    /// Algorithm (all implementations MUST produce identical output):
    ///   1. `seed = HMAC-SHA256(identity_key_material, context_id || epoch_BE || "scp-pseudonym-v2")`
    ///   2. `pseudonym_keypair = Ed25519_keygen(seed[0..32])`
    ///
    /// where `epoch_BE` is the `pseudonym_epoch` as an 8-byte big-endian u64.
    ///
    /// The domain separator `"scp-pseudonym-v2"` is intentionally different from
    /// the v1 separator `"scp-pseudonym"` so that epoch 0 in v2 produces a
    /// different pseudonym than the v1 derivation. This prevents accidental
    /// domain confusion.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::KeyNotFound`] if the handle is invalid.
    /// Returns [`PlatformError::WrongKeyType`] if the handle refers to an
    /// X25519 key.
    fn derive_rotatable_pseudonym(
        &self,
        key: &KeyHandle,
        context_id: &[u8],
        pseudonym_epoch: u64,
    ) -> impl Future<Output = Result<PseudonymKeypair, PlatformError>> + Send;

    /// Returns the custody type for a given key handle.
    ///
    /// This is a synchronous query against local state — no I/O is required.
    fn custody_type(&self, key: &KeyHandle) -> CustodyType;
}

/// Device attestation trait.
///
/// Abstracts platform-specific device attestation (Apple App Attest, Android
/// `SafetyNet` / Play Integrity). The testing implementation returns synthetic
/// attestation tokens that always verify. See ADR-006.
pub trait DeviceAttestation: Send + Sync {
    /// Generate a device attestation token.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::AttestationError`] if the platform attestation
    /// service is unavailable.
    fn attest(&self) -> impl Future<Output = Result<DeviceAttestationToken, PlatformError>> + Send;

    /// Verify a device attestation token.
    ///
    /// Returns `true` if the token is valid, `false` otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::AttestationError`] if verification cannot be
    /// completed (e.g., network error contacting the attestation service).
    fn verify(
        &self,
        token: &DeviceAttestationToken,
    ) -> impl Future<Output = Result<bool, PlatformError>> + Send;
}

/// Push notification trait.
///
/// Abstracts platform-specific push notification registration and handling
/// (APNs, FCM). The testing implementation returns synthetic tokens and passes
/// payloads through as wake signals. See ADR-006.
pub trait Push: Send + Sync {
    /// Register for push notifications and return a platform-specific token.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::PushError`] if registration fails.
    fn register(&self) -> impl Future<Output = Result<PushToken, PlatformError>> + Send;

    /// Handle an incoming push notification payload and produce a wake signal.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::PushError`] if the payload cannot be processed.
    fn handle_notification(
        &self,
        payload: &[u8],
    ) -> impl Future<Output = Result<WakeSignal, PlatformError>> + Send;
}

/// Persistent key-value byte storage trait.
///
/// Abstracts platform-specific secure storage (Keychain, encrypted `SQLite`,
/// browser `IndexedDB`). Keys are UTF-8 strings; values are opaque byte
/// slices. The testing implementation stores data in an in-memory `HashMap`.
/// See ADR-006.
pub trait Storage: Send + Sync {
    /// Store a byte slice under the given key.
    ///
    /// Overwrites any existing value for the same key.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::StorageError`] if the write fails.
    fn store(
        &self,
        key: &str,
        data: &[u8],
    ) -> impl Future<Output = Result<(), PlatformError>> + Send;

    /// Retrieve the byte slice stored under the given key.
    ///
    /// Returns `None` if the key does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::StorageError`] if the read fails.
    fn retrieve(
        &self,
        key: &str,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, PlatformError>> + Send;

    /// Delete the value stored under the given key.
    ///
    /// No-op if the key does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::StorageError`] if the delete fails.
    fn delete(&self, key: &str) -> impl Future<Output = Result<(), PlatformError>> + Send;

    /// List all keys matching the given prefix in lexicographic order.
    ///
    /// Useful for `KeyPackage` buffer management and event log range queries.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::StorageError`] if the operation fails.
    fn list_keys(
        &self,
        prefix: &str,
    ) -> impl Future<Output = Result<Vec<String>, PlatformError>> + Send;

    /// Delete all keys matching the given prefix.
    ///
    /// Returns the number of keys deleted. Used for context cleanup. See
    /// ADR-006 acceptance criterion 4 (`InMemoryStorage`).
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::StorageError`] if the operation fails.
    fn delete_prefix(
        &self,
        prefix: &str,
    ) -> impl Future<Output = Result<u64, PlatformError>> + Send;

    /// Check whether a key exists without reading its value.
    ///
    /// Used for UCAN nonce replay prevention. See ADR-006 acceptance
    /// criterion 4 (`InMemoryStorage`).
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::StorageError`] if the operation fails.
    fn exists(&self, key: &str) -> impl Future<Output = Result<bool, PlatformError>> + Send;
}
