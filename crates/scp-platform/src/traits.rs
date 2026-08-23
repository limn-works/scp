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
//! - [`PreRotationCustody`] — Cold-storage custody for pre-rotation keys (spec §9.7.4.1)
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

/// Opaque handle to a pre-rotation key managed by a [`PreRotationCustody`]
/// implementation.
///
/// **Structurally distinct from [`KeyHandle`].** There is no `From<KeyHandle>`,
/// `Into<KeyHandle>`, or shared accessor — the type system rejects passing an
/// operational handle to pre-rotation methods at compile time. Per spec
/// §9.7.4.1 step 3, pre-rotation keys "MUST NOT be accessible through the
/// same custody provider or authentication flow used for daily operations".
/// This newtype enforces the rule mechanically.
///
/// The inner identifier is reachable via [`PreRotationKeyHandle::id`] as a
/// diagnostic / log-only accessor. SDK code MUST treat the handle as opaque —
/// pass it back to [`PreRotationCustody`] methods by value rather than
/// reconstructing from the raw `u64`. [`PreRotationCustody`] implementations
/// allocate identifiers privately; cross-instance handles are not
/// interchangeable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PreRotationKeyHandle(u64);

impl PreRotationKeyHandle {
    /// Creates a new pre-rotation key handle from a raw identifier.
    ///
    /// Two narrow use sites are sanctioned; SDK code MUST NOT construct
    /// handles directly:
    ///
    /// 1. [`PreRotationCustody`] implementations allocating a fresh
    ///    handle inside their own backing store (e.g., the in-memory
    ///    test custody, the file-backed custody, future HSM-bound
    ///    backends).
    /// 2. FFI bridge code constructing a placeholder handle (`new(0)`)
    ///    for an `Identity` record that has no associated
    ///    [`PreRotationCustody`] — e.g., the externally-loaded DID
    ///    path in the `UniFFI` bridge, where `migrate_identity` is
    ///    rejected before the field is ever consulted.
    ///
    /// Outside those sites, route handles through
    /// [`PreRotationCustody::store_committed_pre_rotation_key`] and
    /// pass them by value. Cross-instance handles are not
    /// interchangeable — a `u64` minted by one custody impl is
    /// meaningless to another.
    #[must_use]
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// Returns the raw integer identifier for this handle.
    ///
    /// Diagnostic / log-only accessor. SDK code MUST treat the handle as
    /// opaque — never reconstruct a [`PreRotationKeyHandle`] from a raw
    /// `u64`. [`PreRotationCustody`] implementations allocate identifiers
    /// privately, and cross-instance handles are not interchangeable.
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
/// The derivation algorithm is specified in ADR-006 and §9.10.4:
///   1. `seed = HMAC-SHA256(pseudonym_secret, context_id || "scp-pseudonym")`
///   2. `pseudonym_keypair = Ed25519_keygen(seed[0..32])`
///
/// The HMAC key is the 32-byte `pseudonym_secret` (NEVER the public key, §9.10.4.A).
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
    /// Algorithm:
    ///   1. `seed = HMAC-SHA256(pseudonym_secret, context_id || "scp-pseudonym")`
    ///   2. `pseudonym_keypair = Ed25519_keygen(seed[0..32])` — `seed` is an RFC-8032 Ed25519 seed
    ///
    /// The HMAC key is the 32-byte `pseudonym_secret`, NEVER the public key (public
    /// key bytes would be a membership-enumeration oracle, §9.10.4.A). For SOFTWARE
    /// keys the `pseudonym_secret` is HKDF-derived from the private seed and is
    /// cross-platform deterministic (pinned by §25.19 vectors). For HARDWARE keys
    /// (Secure Enclave, Keystore TEE, HSM) the private key is non-exportable, so the
    /// `pseudonym_secret` is a device-local value computed inside the boundary;
    /// hardware pseudonyms are therefore device-local BY DESIGN, not cross-platform
    /// identical. The Rust software backends share this derivation via
    /// [`scp_crypto::pseudonym::derive_pseudonym_keypair`].
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
    /// Algorithm:
    ///   1. `seed = HMAC-SHA256(pseudonym_secret, context_id || epoch_BE || "scp-pseudonym-v2")`
    ///   2. `pseudonym_keypair = Ed25519_keygen(seed[0..32])` — `seed` is an RFC-8032 Ed25519 seed
    ///
    /// where `epoch_BE` is the `pseudonym_epoch` as an 8-byte big-endian u64. As in
    /// v1, the HMAC key is the `pseudonym_secret` (NEVER the public key, §9.10.4.A):
    /// software custody is cross-platform deterministic, hardware custody is
    /// device-local by design.
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

    /// Performs X25519 key agreement using an Ed25519 key via birational conversion.
    ///
    /// Converts the Ed25519 key to X25519 internally (`SHA-512(seed)[0..32]` → clamp → scalar),
    /// then performs X25519 DH with the peer's X25519 public key. The private key never
    /// leaves the custody boundary.
    ///
    /// Used for RFC 9180 HPKE decryption of invitation bundles (spec §5.12.3.1).
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::KeyNotFound`] if the handle is invalid.
    /// Returns [`PlatformError::WrongKeyType`] if the handle refers to an X25519 key
    /// (use [`dh_agree`](Self::dh_agree) for X25519 keys directly).
    fn ed25519_to_x25519_agree(
        &self,
        ed25519_handle: &KeyHandle,
        peer_x25519_public: &[u8; 32],
    ) -> impl Future<Output = Result<SharedSecret, PlatformError>> + Send;

    /// Returns the custody type for a given key handle.
    ///
    /// This is a synchronous query against local state — no I/O is required.
    fn custody_type(&self, key: &KeyHandle) -> CustodyType;

    /// Import an existing Ed25519 private key (raw 32-byte seed) into
    /// operational custody, returning a fresh [`KeyHandle`].
    ///
    /// This is used by `migrate_identity` (ADR-003 §4b) to install the
    /// pre-rotation key revealed from cold custody as the NEW identity
    /// key (`#0`) of the migrated identity. The pre-rotation seed bytes
    /// are consumed in a [`zeroize::Zeroizing`] wrapper, so partial
    /// failure does not leak.
    ///
    /// # Hardware-backed implementations
    ///
    /// HSM-bound custody (Apple Secure Enclave, Android `StrongBox`)
    /// generally cannot import raw Ed25519 seed bytes — the key material
    /// must be generated inside the secure element. Such backends MUST
    /// return [`PlatformError::Unsupported`]. The SDK is responsible for
    /// surfacing this as a degraded-mode warning at migration time;
    /// production HSM-backed migration requires a separate flow (HSM-attested
    /// generation chained to the previous commitment) — out of scope for
    /// the trait baseline.
    fn import_ed25519_signing_key(
        &self,
        seed: &zeroize::Zeroizing<[u8; 32]>,
    ) -> impl Future<Output = Result<KeyHandle, PlatformError>> + Send {
        // Default: not supported. The seed parameter is borrowed (not
        // consumed) so the default impl does not even need to drop it.
        let _ = seed;
        async {
            Err(PlatformError::Unsupported(
                "Ed25519 signing-key import not supported by this custody backend",
            ))
        }
    }

    /// Generate an Ed25519 keypair seed whose private bytes are returned to the
    /// caller and NEVER retained in operational custody.
    ///
    /// The protocol's pre-rotation flow (spec §9.7.4.1 §1, §5(a), §5(f) and
    /// ADR-003 §4) requires that the pre-rotation keypair be generated using
    /// the device CSPRNG — but the private bytes must then be handed off to a
    /// separate [`PreRotationCustody`] and destroyed from operational custody.
    /// This method models that one-shot extraction without requiring the
    /// caller to first persist a real handle (which would put the private
    /// bytes in operational custody briefly, even if destroyed afterward).
    ///
    /// # ADR-046 byte parity
    ///
    /// Implementations MUST consume RNG bytes from the same RNG stream as
    /// [`generate_keypair`](Self::generate_keypair) so that cross-bridge
    /// deterministic-seed tests remain valid. Specifically:
    /// `[seed[0..32]] [seed[32..64]] [seed[64..96]]` MUST map to
    /// identity/active/pre-rotation in that order.
    ///
    /// # Hardware-backed implementations
    ///
    /// For HSM-bound custody (Secure Enclave non-extractable Ed25519), the
    /// default implementation returns
    /// [`PlatformError::Unsupported`]. Such backends require a different
    /// flow — the SDK MUST call platform CSPRNG (`SecRandomCopyBytes`,
    /// `KeyStore` random API) directly and route the bytes into a
    /// `PreRotationCustody` provider. Filed as a follow-up workstream.
    fn generate_ephemeral_ed25519_seed(
        &self,
    ) -> impl Future<Output = Result<zeroize::Zeroizing<[u8; 32]>, PlatformError>> + Send {
        async {
            Err(PlatformError::Unsupported(
                "ephemeral Ed25519 seed export not supported by this custody backend",
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// PreRotationCustody — cold-storage custody for the pre-rotation key
// ---------------------------------------------------------------------------

/// Errors specific to [`PreRotationCustody`] operations.
///
/// Distinct from [`PlatformError`] so that a `Result<_, PreRotationCustodyError>`
/// signature in protocol code cannot be confused with operational-custody
/// errors (and vice versa) — the type system rejects accidental cross-boundary
/// `?`-propagation without an explicit conversion. None is provided.
#[derive(Debug, thiserror::Error)]
pub enum PreRotationCustodyError {
    /// The handle is not known to this custody (already destroyed, never
    /// stored, or stored against a different custody instance).
    #[error("pre-rotation key handle not found")]
    HandleNotFound,
    /// The custody backend (FIDO2 device, callback, paper backup, etc.) is
    /// unavailable. Carries a human-readable description for diagnostics.
    ///
    /// IMPLEMENTERS: do NOT embed key material, handle bytes, path
    /// information, or other sensitive data in the diagnostic string —
    /// it flows verbatim to SDK consumers via the typed error envelope.
    /// Use opaque error categories with non-sensitive context only.
    #[error("pre-rotation custody unavailable: {0}")]
    Unavailable(String),
    /// The user declined an interactive prompt (e.g., FIDO2 touch
    /// confirmation, passphrase entry).
    #[error("pre-rotation custody operation declined by user")]
    UserDeclined,
    /// Persistence backend I/O failure. Carries a human-readable description.
    ///
    /// IMPLEMENTERS: do NOT embed key material, handle bytes, file-system
    /// paths, database connection strings, or other sensitive data in the
    /// diagnostic string — it flows verbatim to SDK consumers via the
    /// typed error envelope. Use opaque error categories with
    /// non-sensitive context only (e.g., "disk full", "permission
    /// denied", "transient I/O failure").
    #[error("pre-rotation custody storage error: {0}")]
    Storage(String),
    /// A callback returned malformed bytes (wrong length, non-canonical
    /// encoding, etc.).
    ///
    /// IMPLEMENTERS: do NOT embed the raw callback bytes, derived key
    /// material, or other sensitive data in the diagnostic string — it
    /// flows verbatim to SDK consumers via the typed error envelope.
    /// Describe the structural defect (e.g., "wrong length", "non-UTF-8
    /// in expected text field") without echoing the offending input.
    #[error("pre-rotation custody callback returned invalid data: {0}")]
    InvalidCallbackResponse(String),
    /// The committed public key does not match what the custody returns —
    /// the backup is corrupted or has been substituted. Treat as a critical
    /// integrity failure; do not proceed with migration.
    #[error("pre-rotation custody public-key mismatch (commitment integrity failure)")]
    CommitmentMismatch,
}

/// Discriminator for the six approved §9.7.4.1 §4 custody methods, plus the
/// bridge-callback variant that routes to one of the six.
///
/// Used for diagnostics and SDK UX (e.g., "Your pre-rotation key is on a
/// hardware token — please tap your `YubiKey`"). MUST NOT be used for security
/// decisions — the [`PreRotationCustody`] instance itself is the security
/// boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PreRotationCustodyKind {
    /// In-process registry. Satisfies the §9.7.4.1 §3 type-level isolation
    /// requirement (separate custody object, distinct handle type) but does NOT
    /// satisfy the substrate isolation requirement — the pre-rotation key
    /// co-resides in the same process memory as operational keys.
    ///
    /// NOT a production default. ADR-062 §Decision 6 severed it: the only
    /// implementation is `InMemoryPreRotationCustody`, compiled under
    /// `feature = "testing"`, and every production FFI/SDK create path returns
    /// `SCP-IDENT-1059` rather than reach for it. passkey-PRF / hardware-token /
    /// Shamir backends are a separate workstream.
    InMemory,
    /// FIDO2/U2F hardware security key. Highest security per §9.7.4.1 §4.
    HardwareSecurityKey,
    /// Secondary device's secure enclave (not the daily-driver device).
    SecondaryDeviceEnclave,
    /// Platform-backed cloud key store (iCloud Keychain ADP, Google Cloud
    /// Key Vault).
    PlatformCloudKeyStore,
    /// Encrypted offline backup (AES-256-GCM + Argon2id).
    EncryptedOfflineBackup,
    /// Shamir 3-of-5 secret sharing.
    ShamirSecretSharing,
    /// BIP39 paper backup (24-word mnemonic). Lowest acceptable per spec.
    PaperBackupBip39,
    /// Bridge-callback-driven. The actual substrate is determined by the
    /// SDK caller's callback (Apple Keychain entry distinct from
    /// operational custody, Android Keystore alias with separate
    /// authentication flow, FIDO2/PRF, encrypted backup, etc.).
    Callback,
}

/// Cold-custody interface for pre-rotation keys (spec §9.7.4.1).
///
/// The pre-rotation key is the security backstop for the entire identity
/// system — the last resort for recovery after Identity Key compromise
/// (§9.12). Spec §9.7.4.1 §3 mandates that it be stored separately from the
/// Identity Key and Active Signing Key, and that it MUST NOT be accessible
/// through the same custody provider or authentication flow used for daily
/// operations.
///
/// This trait is the protocol's type-level enforcement of that isolation: it
/// accepts and yields only [`PreRotationKeyHandle`]s, which cannot be
/// exchanged with the operational [`KeyHandle`] type.
///
/// # Lifecycle (per §9.7.4.1)
///
/// 1. **Generation.** The pre-rotation keypair is generated using the device
///    CSPRNG by the operational [`KeyCustody`] (so that ADR-046 byte-parity
///    tests stay valid — same RNG stream as identity/active keys). The
///    private bytes are then handed off via
///    [`store_committed_pre_rotation_key`](Self::store_committed_pre_rotation_key)
///    to this trait, and the operational copy is destroyed (§9.7.4.1 §5(f)).
///
/// 2. **Commitment publication.** The caller computes
///    `SHA-256(public_key)` and publishes it as a `PreRotationCommitment`
///    service entry in the DID document. Only the hash is published; the
///    public key itself is private until migration.
///
/// 3. **Migration.** [`reveal_public_key`](Self::reveal_public_key) returns
///    the 32-byte public key for the `PreRotationProof::revealed_key`
///    field. The migration proof is signed by the OLD identity key (via
///    operational [`KeyCustody::sign`]) — pre-rotation keys never sign
///    anything, which is why this trait has no `sign` method. The
///    cryptographic invariant verifiers check is
///    `SHA-256(revealed_key) == commitment` from the old DID document.
///
/// 4. **Post-migration cycling (§9.7.4.1 §6).** After the new identity is
///    successfully built and registered, the old pre-rotation key is
///    destroyed via [`destroy_after_migration`](Self::destroy_after_migration),
///    which returns the private bytes for re-import as the new identity
///    key. The protocol immediately generates a new pre-rotation keypair
///    and stores it in this same custody.
///
/// # Why no `sign` method
///
/// Pre-rotation keys never sign anything in the SCP protocol. Omitting
/// `sign` keeps the trait viable across all six §9.7.4.1 §4 backends — a
/// printed BIP39 mnemonic, paper backup, or distributed Shamir shares
/// cannot sign on demand. Substrates that CAN sign (FIDO2 hardware keys,
/// platform enclaves) MAY expose signing through a separate method on
/// their concrete impl, but the trait itself is sign-free.
///
/// # Atomicity contract for `destroy_after_migration`
///
/// Implementations SHOULD make export-and-destroy atomic where possible
/// (single `SQLite` transaction, single keychain update). For backends where
/// atomicity is impossible (printed BIP39 mnemonic), callers MUST treat
/// any error as "key may or may not still exist" and surface a recovery
/// prompt.
///
/// # SDK presentation (spec §9.7.4.1 §5) lives ABOVE this trait
///
/// The trait covers steps §9.7.4.1 §5(a) (generation) and §5(f)
/// (operational copy destruction) directly. The protocol API
/// `DidDht::create` returns the identity + document + handle in
/// memory; `DidDht::publish_document` is a SEPARATE call. That seam
/// is where the SDK layers in §5(b) (present custody options),
/// §5(c) (guide the user through the selected method), and §5(d)
/// (verify the backup before commitment publish) — by:
///
/// 1. Picking the concrete [`PreRotationCustody`] implementation
///    based on the user's choice (§5(b)).
/// 2. Driving the per-backend onboarding flow during/after
///    `dht.create()` returns (§5(c) — e.g., "tap your `YubiKey`",
///    "scan this QR", "write down these 24 words").
/// 3. For paper / Shamir / encrypted-backup methods: prompting the
///    user to re-enter the backup and verifying it matches before
///    calling `dht.publish_document()` (§5(d) — the commitment
///    isn't on the DHT until publish).
///
/// The protocol-level hooks already exist — the trait deliberately
/// stays UX-agnostic so it works across all six §9.7.4.1 §4
/// substrates (FIDO2, secondary-device enclave, platform cloud key
/// store, encrypted offline backup, Shamir 3-of-5, BIP39 paper
/// backup). Modeling UX inside the trait would force concrete
/// flows that don't generalize.
///
/// The only implementation in this workspace, `InMemoryPreRotationCustody`, is
/// compiled under `feature = "testing"` and is process-memory only — it satisfies
/// the trait's type-level isolation but not §9.7.4.1 §3 substrate isolation. It is
/// not linked here because the path does not resolve on a default build. No
/// production backend ships yet, so every production create path fails closed.
/// Note that this trait is not sealed: a consumer can implement it (issue 2392).
///
/// # Concurrency
///
/// Implementations MUST be safe under concurrent calls (`Send + Sync` is
/// trait-required). Hardware-backed callbacks may serialize internally;
/// concurrent callers will simply queue.
pub trait PreRotationCustody: Send + Sync {
    /// Store a pre-generated pre-rotation keypair in cold custody.
    ///
    /// The `private_key` argument is consumed
    /// ([`zeroize::Zeroizing`](::zeroize::Zeroizing) — wipes on drop, so
    /// partial failure does not leak). The `public_key` is retained
    /// alongside for verification on retrieval (`reveal_public_key`'s
    /// internal commitment-mismatch check, if implemented).
    ///
    /// Implementations MAY return immediately (in-memory, callback that
    /// stashes synchronously) or MAY block on user interaction (FIDO2
    /// touch, passphrase entry). Callers running on the protocol thread
    /// should treat this as potentially long-running.
    fn store_committed_pre_rotation_key(
        &self,
        public_key: &[u8; 32],
        private_key: zeroize::Zeroizing<[u8; 32]>,
    ) -> impl Future<Output = Result<PreRotationKeyHandle, PreRotationCustodyError>> + Send;

    /// Return the 32-byte Ed25519 public key for the stored pre-rotation
    /// key. Used to populate `PreRotationProof::revealed_key` during
    /// `migrate_identity` (ADR-003 §4b).
    ///
    /// Implementations MAY verify the public key against an internally
    /// stored commitment as a defense-in-depth check; if the verification
    /// fails, return [`PreRotationCustodyError::CommitmentMismatch`].
    fn reveal_public_key(
        &self,
        handle: &PreRotationKeyHandle,
    ) -> impl Future<Output = Result<[u8; 32], PreRotationCustodyError>> + Send;

    /// Destroy the pre-rotation key after a successful migration, returning
    /// the raw private key bytes (zeroized wrapper) so the caller can
    /// re-import them into operational custody as the new identity key
    /// (the canonical use of the pre-rotation key per ADR-003 §4b).
    ///
    /// After this returns, subsequent calls with the same handle MUST
    /// return [`PreRotationCustodyError::HandleNotFound`].
    fn destroy_after_migration(
        &self,
        handle: PreRotationKeyHandle,
    ) -> impl Future<Output = Result<zeroize::Zeroizing<[u8; 32]>, PreRotationCustodyError>> + Send;

    /// Returns the custody kind for diagnostic/logging purposes only.
    ///
    /// MUST NOT be used for security decisions — the
    /// [`PreRotationCustody`] instance itself is the security boundary.
    fn custody_kind(&self) -> PreRotationCustodyKind;
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

// ---------------------------------------------------------------------------
// Arc<T> blanket impl for Storage
// ---------------------------------------------------------------------------

/// Blanket implementation of [`Storage`] for `Arc<T>` where `T: Storage`.
///
/// Enables sharing a single storage backend across multiple owners (e.g.,
/// `ProtocolRepository`, identity layer, and FFI bridge) via `Arc`. Delegates all
/// operations to the inner `T` via `Deref`.
///
/// This is essential for `ProtocolRepository<Arc<S>>` to work when the storage
/// backend is shared via `Arc` (e.g., the FFI bridge's global
/// `STORAGE_PROVIDER`). See issue #329.
#[allow(clippy::manual_async_fn)]
impl<T: Storage> Storage for std::sync::Arc<T> {
    fn store(
        &self,
        key: &str,
        data: &[u8],
    ) -> impl Future<Output = Result<(), PlatformError>> + Send {
        (**self).store(key, data)
    }

    fn retrieve(
        &self,
        key: &str,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, PlatformError>> + Send {
        (**self).retrieve(key)
    }

    fn delete(&self, key: &str) -> impl Future<Output = Result<(), PlatformError>> + Send {
        (**self).delete(key)
    }

    fn list_keys(
        &self,
        prefix: &str,
    ) -> impl Future<Output = Result<Vec<String>, PlatformError>> + Send {
        (**self).list_keys(prefix)
    }

    fn delete_prefix(
        &self,
        prefix: &str,
    ) -> impl Future<Output = Result<u64, PlatformError>> + Send {
        (**self).delete_prefix(prefix)
    }

    fn exists(&self, key: &str) -> impl Future<Output = Result<bool, PlatformError>> + Send {
        (**self).exists(key)
    }
}

// ---------------------------------------------------------------------------
// X25519 key agreement helper (software_platform only)
// ---------------------------------------------------------------------------

/// Performs X25519 key agreement using an Ed25519 signing key via birational conversion.
///
/// Converts the Ed25519 key to X25519 using `to_scalar_bytes()` (`SHA-512(seed)[0..32]`),
/// then performs X25519 DH with the peer's public key.
///
/// This helper eliminates duplication across the `InMemoryKeyCustody`, `FileKeyCustody`,
/// and `SqliteKeyCustody` implementations.
#[cfg(feature = "software_platform")]
#[must_use]
pub fn x25519_agree_from_ed25519(
    signing_key: &ed25519_dalek::SigningKey,
    peer_x25519_public: &[u8; 32],
) -> SharedSecret {
    let scalar_bytes = zeroize::Zeroizing::new(signing_key.to_scalar_bytes());
    let x25519_secret = x25519_dalek::StaticSecret::from(*scalar_bytes);
    let peer_key = x25519_dalek::PublicKey::from(*peer_x25519_public);
    let shared = x25519_secret.diffie_hellman(&peer_key);
    // x25519-dalek v2 SharedSecret implements Zeroize + zeroize(drop) when the
    // zeroize feature is enabled (which it is). Wrapping in Zeroizing is
    // defense-in-depth — ensures zeroing even if the feature is ever removed.
    let shared_bytes = zeroize::Zeroizing::new(shared.to_bytes());
    SharedSecret::new(*shared_bytes)
}
