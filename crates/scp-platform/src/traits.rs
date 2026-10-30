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
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::error::PlatformError;

// ---------------------------------------------------------------------------
// Supporting types
// ---------------------------------------------------------------------------

/// The type of cryptographic key managed by a [`KeyHandle`].
///
/// See ADR-006 for usage. The P-256 types are the SCP key suite (ADR-063);
/// Ed25519 remains until the identity key moves to P-256 (SCP-315). The set is
/// these three types: the X25519 custody type and its `dh_agree` path were
/// removed under SCP-307 criterion 37 (ADR-006, ADR-021 and ADR-025, each
/// amended 2026-10-20).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyType {
    /// Ed25519 signing key (identity keys, active signing keys). Pseudonym keys
    /// are P-256 (§9.10.4) and are never generated through this type.
    Ed25519,
    /// P-256 ECDSA signing key. Signs a 32-byte digest (prehash) and returns
    /// the 64-byte low-`s` `r ‖ s`; its public key is the 33-byte compressed
    /// SEC1 point.
    P256Signing,
    /// P-256 key-agreement key (HPKE `DHKEM(P-256, HKDF-SHA256)`). Its public
    /// key is the 65-byte uncompressed SEC1 point; it only performs ECDH.
    HpkeP256,
    /// P-256 key-event key: a member of an identity's signing set that signs
    /// only a key event's digest `D` or a custody probe's raw digest, through
    /// [`KeyEventSigner`](scp_kel::KeyEventSigner) (`09-security-model.md`
    /// §9.7.4.2 R10). [`KeyCustody::generate_key_event_keypair`] is its one
    /// mint, in the [`KeyRole::Operational`] role; [`KeyCustody::sign`],
    /// [`KeyCustody::dh_agree`] and both pseudonym derivations refuse it. Its
    /// public key is the 33-byte compressed SEC1 point (SCP-345).
    P256KeyEvent,
}

impl KeyType {
    /// The type's name in a host custody contract: `"ed25519"`, `"p256"`,
    /// `"hpke-p256"` or `"p256-key-event"` (ADR-021, amended 2026-10-10).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::P256Signing => "p256",
            Self::HpkeP256 => "hpke-p256",
            Self::P256KeyEvent => "p256-key-event",
        }
    }

    /// Parses a name that [`as_str`](Self::as_str) produces; any other string
    /// is `None`.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "ed25519" => Some(Self::Ed25519),
            "p256" => Some(Self::P256Signing),
            "hpke-p256" => Some(Self::HpkeP256),
            "p256-key-event" => Some(Self::P256KeyEvent),
            _ => None,
        }
    }

    /// The type's one-byte code in a `SqliteKeyCustody` key row and in a
    /// custody record (spec §17.3 `custody/record/{namespace}/{key_id}`):
    /// `0` Ed25519, `2` P-256 signing, `3` HPKE P-256, `4` P-256 key event.
    /// Code 1 named the
    /// retired X25519 type and is never reused. `FileKeyCustody` keeps its own
    /// §17.8 bytes.
    #[must_use]
    pub const fn storage_code(self) -> u8 {
        match self {
            Self::Ed25519 => 0,
            Self::P256Signing => 2,
            Self::HpkeP256 => 3,
            Self::P256KeyEvent => 4,
        }
    }

    /// The type whose [`storage_code`](Self::storage_code) is `code`; any
    /// other byte is `None`, never a default type.
    #[must_use]
    pub const fn from_storage_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Ed25519),
            2 => Some(Self::P256Signing),
            3 => Some(Self::HpkeP256),
            4 => Some(Self::P256KeyEvent),
            _ => None,
        }
    }
}

/// What a custody key is for, fixed when custody first holds the key
/// (ADR-006, amended 2026-10-10).
///
/// [`KeyCustody::generate_identity_keypair`] and
/// [`KeyCustody::import_ed25519_signing_key`] hold their key in the
/// [`Identity`](Self::Identity) role, and [`KeyCustody::generate_keypair`]
/// holds every other key in the [`Operational`](Self::Operational) role. Only
/// an identity key may be a pseudonym-derivation source
/// (`09-security-model.md` §9.10.4.A); see [`require_derive_source`].
///
/// This is a custody record, distinct from the key-state role of
/// `09-security-model.md` §9.7.4.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyRole {
    /// The identity key (`#0`) of an identity: the only pseudonym-derivation
    /// source.
    Identity,
    /// Every key that is not an identity key.
    Operational,
}

impl KeyRole {
    /// The role's name in a host custody contract: `"identity"` or
    /// `"operational"` (ADR-021, amended 2026-10-10).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Operational => "operational",
        }
    }

    /// Parses a name that [`as_str`](Self::as_str) produces; any other string
    /// is `None`.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "identity" => Some(Self::Identity),
            "operational" => Some(Self::Operational),
            _ => None,
        }
    }

    /// The role byte of a persisted key entry: `0x00` operational, `0x01`
    /// identity (`17-persistence-and-storage.md` §17.8).
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        match self {
            Self::Operational => 0x00,
            Self::Identity => 0x01,
        }
    }

    /// Parses a role byte that [`to_byte`](Self::to_byte) produces; any other
    /// byte is `None`.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x00 => Some(Self::Operational),
            0x01 => Some(Self::Identity),
            _ => None,
        }
    }
}

/// Opaque handle to a cryptographic key managed by a [`KeyCustody`] implementation.
///
/// The handle is an integer identifier. Implementations map this to actual key
/// material stored internally (e.g., in a `HashMap`, Secure Enclave slot, or
/// Android Keystore alias). The raw private key never leaves the custody
/// boundary.
///
/// **An implementation issues each id once over the life of its store,
/// restarts included, and never reissues the id of a destroyed key.** A
/// holder that recorded a handle destroys by it after a crash and treats
/// [`PlatformError::KeyNotFound`] as already destroyed, so a reissued id
/// would let that retry destroy a newer, unrelated key
/// (`17-persistence-and-storage.md` §17.3).
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
/// Contains the raw public key bytes — Ed25519 (32 bytes), P-256
/// signing (33-byte compressed SEC1), or HPKE P-256 (65-byte uncompressed SEC1).
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

/// A signature produced by [`KeyCustody::sign`].
///
/// Contains the raw 64-byte Ed25519 signature `R ‖ S`.
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

/// A 32-byte shared secret produced by [`KeyCustody::dh_agree`]: the P-256
/// ECDH x-coordinate.
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

/// A per-context pseudonym derived via [`KeyCustody::derive_pseudonym`] or
/// [`KeyCustody::derive_rotatable_pseudonym`] (§9.10.4).
///
/// A pseudonym is a P-256 point with no private key: no protocol message is
/// signed under it, so no custody stores one. `routing_id` is
/// `SHA-256("scp-pseudonym-routing-v1:" || compressed point)`, the 32-byte
/// value every routing field carries. Both constructors take a validated point
/// (§9.5) and compute the routing id, so a held value is always well-formed,
/// whichever custody backend or host adapter produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pseudonym {
    public_key: scp_crypto::p256::P256PublicKey,
    routing_id: [u8; 32],
}

impl Pseudonym {
    /// The pseudonym whose point is `public_key`.
    #[must_use]
    pub fn new(public_key: scp_crypto::p256::P256PublicKey) -> Self {
        Self {
            routing_id: scp_crypto::pseudonym::pseudonym_routing_id(&public_key),
            public_key,
        }
    }

    /// Validates a pseudonym point a custody returned.
    ///
    /// # Errors
    ///
    /// [`PlatformError::PseudonymRejected`] when `point` is not a 33-byte SEC1
    /// compressed P-256 point on the curve; the message names which.
    pub fn from_point(point: &[u8]) -> Result<Self, PlatformError> {
        use scp_crypto::p256::{COMPRESSED_POINT_LEN, P256PublicKey};
        if point.len() != COMPRESSED_POINT_LEN {
            return Err(PlatformError::PseudonymRejected(format!(
                "pseudonym point must be a {COMPRESSED_POINT_LEN}-byte compressed P-256 point, got {} bytes",
                point.len()
            )));
        }
        P256PublicKey::from_sec1(point)
            .map(Self::new)
            .map_err(|e| PlatformError::PseudonymRejected(format!("invalid pseudonym point: {e}")))
    }

    /// The P-256 pseudonym point.
    #[must_use]
    pub const fn public_key(&self) -> &scp_crypto::p256::P256PublicKey {
        &self.public_key
    }

    /// The 32-byte pseudonym routing id (§9.10.4).
    #[must_use]
    pub const fn routing_id(&self) -> &[u8; 32] {
        &self.routing_id
    }
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

impl CustodyType {
    /// The key-entry custody type (`09-security-model.md` §9.7.4.2
    /// definitions, the 45-byte key entry) a key held under this custody
    /// type discloses.
    ///
    /// `InMemory` and `Software` keys are copyable software keys, so both
    /// disclose `Software`. A `Hardware` key discloses the keystore this
    /// target ships: the Secure Enclave on Apple targets, the Android
    /// Keystore on Android, and on every other target the TPM or hardware
    /// security module this type's own documentation names, which is `Hsm`.
    #[must_use]
    pub const fn key_entry_custody_type(self) -> scp_did::CustodyType {
        match self {
            Self::InMemory | Self::Software => scp_did::CustodyType::Software,
            Self::Hardware => {
                if cfg!(any(target_os = "ios", target_os = "macos")) {
                    scp_did::CustodyType::SecureEnclave
                } else if cfg!(target_os = "android") {
                    scp_did::CustodyType::AndroidKeystore
                } else {
                    scp_did::CustodyType::Hsm
                }
            }
        }
    }
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
///
/// The token addresses this device at its push platform, so it is handled as
/// a secret: the bytes are wiped when the value drops, and `Debug` prints
/// their length only.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushToken(Zeroizing<Vec<u8>>);

impl PushToken {
    /// Creates a new push token from raw bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Returns a reference to the raw token bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Whether the token holds no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Consumes this value and returns the raw token bytes, still wiped on
    /// drop.
    #[must_use]
    pub fn into_bytes(self) -> Zeroizing<Vec<u8>> {
        self.0
    }
}

impl std::fmt::Debug for PushToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PushToken(<{} bytes redacted>)", self.0.len())
    }
}

/// A wake signal produced by [`Push::handle_notification`].
///
/// Indicates that the application should wake up and process pending messages.
/// §10.7 of the infrastructure spec states: "Push payloads MUST contain a wake
/// signal and nothing else. No context ID, no sender identifier, no message
/// preview, no metadata of any kind." A wake signal must therefore not vary
/// with the payload it was produced from. `WakeSignal` holds `&'static` bytes,
/// so returning the borrowed payload or a temporary copy of it does not
/// compile (the two examples below). The type does not stop a signal that
/// varies with the payload: an implementation can leak payload bytes with
/// `Vec::leak`, pick one of several `'static` constants by payload content, or
/// slice a `static` table at an index read from the payload. The conformance
/// check `scp_testing::conformance::push::check_fixed_wake_signal` is what
/// rejects an adapter whose signal differs across the payloads it sends,
/// however the signal was built, and fails an adapter that accepts a payload
/// no device receipt rule of §10.7.1 step 5 accepts. `InMemoryPush`, the test
/// double behind the `testing` feature (ADR-062 §0), accepts only the wake
/// bodies of the §10.7.1 step 5 wake-signal table and returns the APNs body's
/// bytes for each. See ADR-006.
///
/// ```
/// use scp_platform::WakeSignal;
///
/// const WAKE: &[u8] = br#"{"aps":{"content-available":1}}"#;
/// assert_eq!(WakeSignal::new(WAKE).payload(), WAKE);
/// ```
///
/// Bytes borrowed from a notification payload do not compile:
///
/// ```compile_fail,E0521
/// use scp_platform::WakeSignal;
///
/// fn from_payload(payload: &[u8]) -> WakeSignal {
///     WakeSignal::new(payload)
/// }
/// ```
///
/// Nor does a copy of them:
///
/// ```compile_fail,E0716
/// use scp_platform::WakeSignal;
///
/// fn from_payload(payload: &[u8]) -> WakeSignal {
///     WakeSignal::new(&payload.to_vec())
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WakeSignal {
    payload: &'static [u8],
}

impl WakeSignal {
    /// Creates a wake signal holding `payload`, a constant the [`Push`]
    /// implementation returns for every notification it accepts (§10.7).
    #[must_use]
    pub const fn new(payload: &'static [u8]) -> Self {
        Self { payload }
    }

    /// Returns the wake signal bytes.
    #[must_use]
    pub const fn payload(&self) -> &'static [u8] {
        self.payload
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
///
/// [`KeyEventSigner`](scp_kel::KeyEventSigner)'s methods and
/// [`generate_key_event_keypair`](Self::generate_key_event_keypair) have no
/// default body (SCP-345), so an implementor that omits `sign_change` does
/// not compile:
///
/// ```compile_fail,E0046
/// use core::future::{Future, ready};
/// use scp_platform::{
///     CustodyProbe, CustodyType, IndexedSignature, KeyCustody, KeyEventSignError, KeyEventSigner,
///     KeyHandle, KeyType, MaybeSend, PlatformError, ProbeSignature, Pseudonym, PublicKey,
///     SharedSecret, Signature, SigningChange,
/// };
///
/// struct Custody;
///
/// impl KeyEventSigner for Custody {
///     type Member = KeyHandle;
///
///     fn sign_probe(
///         &self,
///         _member: &KeyHandle,
///         _probe: &CustodyProbe,
///     ) -> impl Future<Output = Result<ProbeSignature, KeyEventSignError>> + MaybeSend {
///         ready(Err(KeyEventSignError::MemberNotFound))
///     }
/// }
///
/// impl KeyCustody for Custody {
///     fn generate_keypair(
///         &self,
///         _key_type: KeyType,
///     ) -> impl Future<Output = Result<KeyHandle, PlatformError>> + Send {
///         ready(Err(PlatformError::Unsupported("no key")))
///     }
///
///     fn generate_key_event_keypair(
///         &self,
///     ) -> impl Future<Output = Result<KeyHandle, PlatformError>> + Send {
///         ready(Err(PlatformError::Unsupported("no key-event key")))
///     }
///
///     fn generate_identity_keypair(
///         &self,
///     ) -> impl Future<Output = Result<KeyHandle, PlatformError>> + Send {
///         ready(Err(PlatformError::Unsupported("no identity key")))
///     }
///
///     fn sign(
///         &self,
///         _key: &KeyHandle,
///         _data: &[u8],
///     ) -> impl Future<Output = Result<Signature, PlatformError>> + Send {
///         ready(Err(PlatformError::Unsupported("no sign")))
///     }
///
///     fn public_key(
///         &self,
///         _key: &KeyHandle,
///     ) -> impl Future<Output = Result<PublicKey, PlatformError>> + Send {
///         ready(Err(PlatformError::Unsupported("no public key")))
///     }
///
///     fn destroy_key(&self, _key: &KeyHandle) -> impl Future<Output = Result<(), PlatformError>> + Send {
///         ready(Err(PlatformError::Unsupported("no destroy")))
///     }
///
///     fn dh_agree(
///         &self,
///         _key: &KeyHandle,
///         _peer_public: &[u8],
///     ) -> impl Future<Output = Result<SharedSecret, PlatformError>> + Send {
///         ready(Err(PlatformError::Unsupported("no agreement")))
///     }
///
///     fn derive_pseudonym(
///         &self,
///         _key: &KeyHandle,
///         _context_id: &[u8],
///     ) -> impl Future<Output = Result<Pseudonym, PlatformError>> + Send {
///         ready(Err(PlatformError::Unsupported("no pseudonym")))
///     }
///
///     fn derive_rotatable_pseudonym(
///         &self,
///         _key: &KeyHandle,
///         _context_id: &[u8],
///         _pseudonym_epoch: u64,
///     ) -> impl Future<Output = Result<Pseudonym, PlatformError>> + Send {
///         ready(Err(PlatformError::Unsupported("no pseudonym")))
///     }
///
///     fn custody_type(&self, _key: &KeyHandle) -> CustodyType {
///         CustodyType::Software
///     }
/// }
/// ```
///
/// Nor does one that omits the key-event mint:
///
/// ```compile_fail,E0046
/// use core::future::{Future, ready};
/// use scp_platform::{
///     CustodyProbe, CustodyType, IndexedSignature, KeyCustody, KeyEventSignError, KeyEventSigner,
///     KeyHandle, KeyType, MaybeSend, PlatformError, ProbeSignature, Pseudonym, PublicKey,
///     SharedSecret, Signature, SigningChange,
/// };
///
/// struct Custody;
///
/// impl KeyEventSigner for Custody {
///     type Member = KeyHandle;
///
///     fn sign_change(
///         &self,
///         _member: &KeyHandle,
///         _change: &SigningChange,
///     ) -> impl Future<Output = Result<IndexedSignature, KeyEventSignError>> + MaybeSend {
///         ready(Err(KeyEventSignError::MemberNotFound))
///     }
///
///     fn sign_probe(
///         &self,
///         _member: &KeyHandle,
///         _probe: &CustodyProbe,
///     ) -> impl Future<Output = Result<ProbeSignature, KeyEventSignError>> + MaybeSend {
///         ready(Err(KeyEventSignError::MemberNotFound))
///     }
/// }
///
/// impl KeyCustody for Custody {
///     fn generate_keypair(
///         &self,
///         _key_type: KeyType,
///     ) -> impl Future<Output = Result<KeyHandle, PlatformError>> + Send {
///         ready(Err(PlatformError::Unsupported("no key")))
///     }
///
///     fn generate_identity_keypair(
///         &self,
///     ) -> impl Future<Output = Result<KeyHandle, PlatformError>> + Send {
///         ready(Err(PlatformError::Unsupported("no identity key")))
///     }
///
///     fn sign(
///         &self,
///         _key: &KeyHandle,
///         _data: &[u8],
///     ) -> impl Future<Output = Result<Signature, PlatformError>> + Send {
///         ready(Err(PlatformError::Unsupported("no sign")))
///     }
///
///     fn public_key(
///         &self,
///         _key: &KeyHandle,
///     ) -> impl Future<Output = Result<PublicKey, PlatformError>> + Send {
///         ready(Err(PlatformError::Unsupported("no public key")))
///     }
///
///     fn destroy_key(&self, _key: &KeyHandle) -> impl Future<Output = Result<(), PlatformError>> + Send {
///         ready(Err(PlatformError::Unsupported("no destroy")))
///     }
///
///     fn dh_agree(
///         &self,
///         _key: &KeyHandle,
///         _peer_public: &[u8],
///     ) -> impl Future<Output = Result<SharedSecret, PlatformError>> + Send {
///         ready(Err(PlatformError::Unsupported("no agreement")))
///     }
///
///     fn derive_pseudonym(
///         &self,
///         _key: &KeyHandle,
///         _context_id: &[u8],
///     ) -> impl Future<Output = Result<Pseudonym, PlatformError>> + Send {
///         ready(Err(PlatformError::Unsupported("no pseudonym")))
///     }
///
///     fn derive_rotatable_pseudonym(
///         &self,
///         _key: &KeyHandle,
///         _context_id: &[u8],
///         _pseudonym_epoch: u64,
///     ) -> impl Future<Output = Result<Pseudonym, PlatformError>> + Send {
///         ready(Err(PlatformError::Unsupported("no pseudonym")))
///     }
///
///     fn custody_type(&self, _key: &KeyHandle) -> CustodyType {
///         CustodyType::Software
///     }
/// }
/// ```
///
/// The positive control, identical but for the omitted method:
///
/// ```
/// use core::future::{Future, ready};
/// use scp_platform::{
///     CustodyProbe, CustodyType, IndexedSignature, KeyCustody, KeyEventSignError, KeyEventSigner,
///     KeyHandle, KeyType, MaybeSend, PlatformError, ProbeSignature, Pseudonym, PublicKey,
///     SharedSecret, Signature, SigningChange,
/// };
///
/// struct Custody;
///
/// impl KeyEventSigner for Custody {
///     type Member = KeyHandle;
///
///     fn sign_change(
///         &self,
///         _member: &KeyHandle,
///         _change: &SigningChange,
///     ) -> impl Future<Output = Result<IndexedSignature, KeyEventSignError>> + MaybeSend {
///         ready(Err(KeyEventSignError::MemberNotFound))
///     }
///
///     fn sign_probe(
///         &self,
///         _member: &KeyHandle,
///         _probe: &CustodyProbe,
///     ) -> impl Future<Output = Result<ProbeSignature, KeyEventSignError>> + MaybeSend {
///         ready(Err(KeyEventSignError::MemberNotFound))
///     }
/// }
///
/// impl KeyCustody for Custody {
///     fn generate_keypair(
///         &self,
///         _key_type: KeyType,
///     ) -> impl Future<Output = Result<KeyHandle, PlatformError>> + Send {
///         ready(Err(PlatformError::Unsupported("no key")))
///     }
///
///     fn generate_key_event_keypair(
///         &self,
///     ) -> impl Future<Output = Result<KeyHandle, PlatformError>> + Send {
///         ready(Err(PlatformError::Unsupported("no key-event key")))
///     }
///
///     fn generate_identity_keypair(
///         &self,
///     ) -> impl Future<Output = Result<KeyHandle, PlatformError>> + Send {
///         ready(Err(PlatformError::Unsupported("no identity key")))
///     }
///
///     fn sign(
///         &self,
///         _key: &KeyHandle,
///         _data: &[u8],
///     ) -> impl Future<Output = Result<Signature, PlatformError>> + Send {
///         ready(Err(PlatformError::Unsupported("no sign")))
///     }
///
///     fn public_key(
///         &self,
///         _key: &KeyHandle,
///     ) -> impl Future<Output = Result<PublicKey, PlatformError>> + Send {
///         ready(Err(PlatformError::Unsupported("no public key")))
///     }
///
///     fn destroy_key(&self, _key: &KeyHandle) -> impl Future<Output = Result<(), PlatformError>> + Send {
///         ready(Err(PlatformError::Unsupported("no destroy")))
///     }
///
///     fn dh_agree(
///         &self,
///         _key: &KeyHandle,
///         _peer_public: &[u8],
///     ) -> impl Future<Output = Result<SharedSecret, PlatformError>> + Send {
///         ready(Err(PlatformError::Unsupported("no agreement")))
///     }
///
///     fn derive_pseudonym(
///         &self,
///         _key: &KeyHandle,
///         _context_id: &[u8],
///     ) -> impl Future<Output = Result<Pseudonym, PlatformError>> + Send {
///         ready(Err(PlatformError::Unsupported("no pseudonym")))
///     }
///
///     fn derive_rotatable_pseudonym(
///         &self,
///         _key: &KeyHandle,
///         _context_id: &[u8],
///         _pseudonym_epoch: u64,
///     ) -> impl Future<Output = Result<Pseudonym, PlatformError>> + Send {
///         ready(Err(PlatformError::Unsupported("no pseudonym")))
///     }
///
///     fn custody_type(&self, _key: &KeyHandle) -> CustodyType {
///         CustodyType::Software
///     }
/// }
/// ```
pub trait KeyCustody: Send + Sync + scp_kel::KeyEventSigner<Member = KeyHandle> {
    /// Generate a new keypair of the specified type.
    ///
    /// Ed25519 keys may be hardware-backed (Secure Enclave, Keystore).
    ///
    /// Returns an opaque [`KeyHandle`] that references the generated key.
    ///
    /// # Errors
    ///
    /// [`PlatformError::WrongKeyType`] for [`KeyType::P256KeyEvent`], whose
    /// one mint is [`generate_key_event_keypair`](Self::generate_key_event_keypair)
    /// (see [`refuse_key_event_mint`]).
    fn generate_keypair(
        &self,
        key_type: KeyType,
    ) -> impl Future<Output = Result<KeyHandle, PlatformError>> + Send;

    /// Generate a key-event key: a P-256 key in the [`KeyRole::Operational`]
    /// role, recorded as [`KeyType::P256KeyEvent`] (`09-security-model.md`
    /// §9.7.4.2 R10; SCP-345). This is the type's one mint.
    ///
    /// The key signs only through [`KeyEventSigner`](scp_kel::KeyEventSigner):
    /// [`sign`](Self::sign) and [`dh_agree`](Self::dh_agree) refuse it with
    /// [`PlatformError::WrongKeyType`], and both pseudonym derivations with
    /// [`PlatformError::NotIdentityKey`]. Its public key is the 33-byte
    /// compressed SEC1 point.
    ///
    /// # Errors
    ///
    /// Any error the substrate returns when it cannot generate or keep the
    /// key. A custody that cannot hold a key-event key returns
    /// [`PlatformError::Unsupported`] or the refusal its other mints give.
    fn generate_key_event_keypair(
        &self,
    ) -> impl Future<Output = Result<KeyHandle, PlatformError>> + Send;

    /// Generate the identity key (`#0`) of a new identity: an Ed25519 key in
    /// the identity role.
    ///
    /// A key's role is fixed when custody first holds it. Only an identity
    /// key may be the source of [`derive_pseudonym`](Self::derive_pseudonym)
    /// and [`derive_rotatable_pseudonym`](Self::derive_rotatable_pseudonym)
    /// (§9.10.4.A). A key from [`generate_keypair`](Self::generate_keypair)
    /// is operational and never derives. [`import_ed25519_signing_key`](Self::import_ed25519_signing_key)
    /// installs the new identity key of a migrated identity, so it also
    /// holds its key in the identity role.
    ///
    /// Software backends draw exactly as `generate_keypair(KeyType::Ed25519)`
    /// does, so the ADR-046 byte parity holds whichever of the two mints the
    /// identity key.
    ///
    /// # Errors
    ///
    /// As [`generate_keypair`](Self::generate_keypair). A backend that holds
    /// no identity keys returns [`PlatformError::Unsupported`].
    fn generate_identity_keypair(
        &self,
    ) -> impl Future<Output = Result<KeyHandle, PlatformError>> + Send;

    /// Sign data with an Ed25519 key, or a 32-byte digest with a
    /// [`KeyType::P256Signing`] key.
    ///
    /// For a P-256 key, `data` is the digest itself (prehash, §9.5.1) and the
    /// result is the 64-byte low-`s` `r ‖ s`. Software backends use RFC 6979
    /// nonces; a hardware signer may use random nonces, so callers must not
    /// rely on P-256 signatures being deterministic.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::KeyNotFound`] if the handle is invalid.
    /// Returns [`PlatformError::WrongKeyType`] if the handle refers to a
    /// key-agreement key ([`KeyType::HpkeP256`]).
    /// Returns [`PlatformError::CustodyError`] if a P-256 key is given `data`
    /// that is not 32 bytes.
    fn sign(
        &self,
        key: &KeyHandle,
        data: &[u8],
    ) -> impl Future<Output = Result<Signature, PlatformError>> + Send;

    /// Return the public key for a handle.
    ///
    /// Ed25519 handles return 32 bytes, [`KeyType::P256Signing`]
    /// handles the 33-byte compressed SEC1 point, and
    /// [`KeyType::HpkeP256`] handles the 65-byte uncompressed SEC1 point.
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
    /// No pseudonym key exists to destroy: a pseudonym has no private key, and
    /// a derivation from a destroyed identity fails with key-not-found
    /// (`SCP-CRYPTO-4006`, `09-security-model.md` §9.10.4.A).
    ///
    /// The destroyed key's id is never issued again (see [`KeyHandle`]), so
    /// every later call with `key` returns [`PlatformError::KeyNotFound`].
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::KeyNotFound`] if the handle is already invalid.
    fn destroy_key(
        &self,
        key: &KeyHandle,
    ) -> impl Future<Output = Result<(), PlatformError>> + Send;

    /// Perform Diffie-Hellman key agreement with a [`KeyType::HpkeP256`]
    /// key. `peer_public` is exactly the 65-byte uncompressed SEC1 point
    /// (`0x04 || x || y`, RFC 9180 §7.1.1 `SerializePublicKey`), on the
    /// curve and not the identity; a compressed point is rejected. The
    /// result is the ECDH x-coordinate.
    ///
    /// Returns the 32-byte shared secret. The private key never leaves the
    /// custody boundary — the scalar multiplication happens inside the adapter.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::KeyNotFound`] if the handle is invalid.
    /// Returns [`PlatformError::WrongKeyType`] if the handle refers to a
    /// signing key ([`KeyType::Ed25519`] or [`KeyType::P256Signing`]).
    /// Returns [`PlatformError::CustodyError`] if `peer_public` is malformed
    /// for the handle's curve.
    fn dh_agree(
        &self,
        key: &KeyHandle,
        peer_public: &[u8],
    ) -> impl Future<Output = Result<SharedSecret, PlatformError>> + Send;

    /// Derive a deterministic, context-scoped pseudonym (v1, non-rotatable).
    ///
    /// Algorithm:
    ///   1. `seed = HMAC-SHA256(pseudonym_secret, context_id || "scp-pseudonym")`
    ///   2. `d = (int(HKDF-Expand-SHA256(seed, "SCP-PSEUDONYM-P256-V1", 48)) mod (n − 1)) + 1`
    ///      (FIPS 186-5 A.2.1), and the pseudonym is the point `d·G`; `d` is discarded
    ///
    /// The HMAC key is the 32-byte `pseudonym_secret`, NEVER the public key (public
    /// key bytes would be a membership-enumeration oracle, §9.10.4.A). For SOFTWARE
    /// keys the `pseudonym_secret` is HKDF-derived from the private seed and is
    /// cross-platform deterministic (pinned by §25.19 vectors). For HARDWARE keys
    /// (Secure Enclave, Keystore TEE, HSM) the private key is non-exportable, so the
    /// `pseudonym_secret` is a device-local value computed inside the boundary;
    /// hardware pseudonyms are therefore device-local BY DESIGN, not cross-platform
    /// identical. The Rust software backends share this derivation via
    /// [`scp_crypto::pseudonym::derive_pseudonym`].
    ///
    /// The returned [`Pseudonym`] is the point and its routing id; the custody
    /// stores nothing for it.
    ///
    /// For contexts that support pseudonym rotation (BLACK-001 mitigation),
    /// use [`derive_rotatable_pseudonym`](KeyCustody::derive_rotatable_pseudonym) instead.
    ///
    /// The pseudonym dies with its identity (`09-security-model.md` §9.10.4.A):
    /// once the identity is destroyed, deriving from it fails with
    /// key-not-found (`SCP-CRYPTO-4006`).
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::KeyNotFound`] if the handle is invalid.
    /// Returns [`PlatformError::NotIdentityKey`] if the handle is not an
    /// identity key ([`KeyRole::Identity`]): an operational key of any type,
    /// Ed25519 included. Returns [`PlatformError::WrongKeyType`] (with
    /// `expected` [`KeyType::Ed25519`]) for an identity key that is not
    /// Ed25519. The identity key is Ed25519 (§9.10.4.A).
    fn derive_pseudonym(
        &self,
        key: &KeyHandle,
        context_id: &[u8],
    ) -> impl Future<Output = Result<Pseudonym, PlatformError>> + Send;

    /// Derive a rotatable, epoch-scoped pseudonym (v2).
    ///
    /// Mitigates relay-side pseudonym correlation (BLACK-001) by including a
    /// rotation epoch in the HMAC derivation, producing a different pseudonym
    /// for each epoch within the same context.
    ///
    /// Algorithm:
    ///   1. `seed = HMAC-SHA256(pseudonym_secret, context_id || epoch_BE || "scp-pseudonym-v2")`
    ///   2. the point `d·G` from `seed` exactly as in v1
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
    /// The pseudonym dies with its identity (`09-security-model.md` §9.10.4.A):
    /// once the identity is destroyed, deriving from it fails with
    /// key-not-found (`SCP-CRYPTO-4006`).
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::KeyNotFound`] if the handle is invalid.
    /// Returns [`PlatformError::NotIdentityKey`] if the handle is not an
    /// identity key ([`KeyRole::Identity`]): an operational key of any type,
    /// Ed25519 included. Returns [`PlatformError::WrongKeyType`] (with
    /// `expected` [`KeyType::Ed25519`]) for an identity key that is not
    /// Ed25519. The identity key is Ed25519 (§9.10.4.A).
    fn derive_rotatable_pseudonym(
        &self,
        key: &KeyHandle,
        context_id: &[u8],
        pseudonym_epoch: u64,
    ) -> impl Future<Output = Result<Pseudonym, PlatformError>> + Send;

    /// Returns the custody type for a given key handle.
    ///
    /// This is a synchronous query against local state — no I/O is required.
    fn custody_type(&self, key: &KeyHandle) -> CustodyType;

    /// Import an existing Ed25519 private key (raw 32-byte seed) as a key in
    /// the [`KeyRole::Identity`] role, returning a fresh [`KeyHandle`].
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
/// Used for diagnostics, SDK UX (e.g., "Your pre-rotation key is on a
/// hardware token — please tap your `YubiKey`"), and the method-by-profile
/// check identity creation runs through
/// [`declared_custody_type`](Self::declared_custody_type)
/// (`09-security-model.md` §9.7.4.1 item 4). The custody instance itself
/// stays the isolation boundary: a kind declares a method, and the check
/// refuses a method the profile does not offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PreRotationCustodyKind {
    /// In-process registry. Satisfies the §9.7.4.1 §3 type-level isolation
    /// requirement (separate custody object, distinct handle type) but does
    /// NOT satisfy the substrate isolation requirement — the pre-rotation key
    /// co-resides in the same process memory as operational keys.
    ///
    /// **Not reachable from a shipped build.** The only implementation that
    /// reports this kind is `InMemoryPreRotationCustody`, which lives in this
    /// crate's `#[cfg(feature = "testing")]` `testing` module (ADR-062
    /// §Decision 6) — a test-harness nullifier, never compiled into a shipped
    /// artifact. A production build therefore has *no* `PreRotationCustody`
    /// backend at all: identity creation fails closed with
    /// `IdentityError::NoIndependentSubstrate`, surfaced across every bridge as
    /// `SCP-IDENT-1100`. Real backends (passkey-PRF, hardware token, Shamir,
    /// …) are tracked by #1729 / RFC #2130.
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

impl PreRotationCustodyKind {
    /// The `CustodyType` the kind declares for the commitment entry it backs
    /// (`09-security-model.md` §9.7.4.2 definitions; §9.7.4.1 item 4, "Method
    /// by profile"), or `None` where the kind names no one method.
    ///
    /// `SecondaryDeviceEnclave` names a device rather than a method, and
    /// `Callback` names whichever method the host callback runs, so neither
    /// declares a type, and a caller that needs one refuses the custody.
    /// `PlatformCloudKeyStore` is a synced platform passkey store, so it
    /// declares `Passkey`. `InMemory` keeps its key in process memory, the
    /// operational path's own copyable substrate, so it declares `Software`.
    #[must_use]
    pub const fn declared_custody_type(self) -> Option<scp_did::CustodyType> {
        match self {
            Self::HardwareSecurityKey => Some(scp_did::CustodyType::Fido2Token),
            Self::EncryptedOfflineBackup => Some(scp_did::CustodyType::EncryptedOfflineBackup),
            Self::ShamirSecretSharing => Some(scp_did::CustodyType::ShamirShares),
            Self::PaperBackupBip39 => Some(scp_did::CustodyType::PaperBackup),
            Self::PlatformCloudKeyStore => Some(scp_did::CustodyType::Passkey),
            Self::InMemory => Some(scp_did::CustodyType::Software),
            Self::SecondaryDeviceEnclave | Self::Callback => None,
        }
    }
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
/// # No backend ships today
///
/// The only implementation of this trait in the tree is
/// `InMemoryPreRotationCustody`, and it is test-harness-only — it
/// lives in this crate's `#[cfg(feature = "testing")]` `testing`
/// module (ADR-062 §Decision 6), so it is not compiled into a
/// shipped artifact. It is also process-memory only, satisfying the
/// trait's type-level isolation but not §9.7.4.1 §3 substrate
/// isolation.
///
/// A shipped build consequently has no backend to select at all, and
/// identity creation fails closed with
/// `IdentityError::NoIndependentSubstrate` (`SCP-IDENT-1100`) rather
/// than substituting the nullifier. Production backends are tracked
/// by #1729 / RFC #2130.
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
    /// ([`zeroize::Zeroizing`] — wipes on drop, so
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
    /// re-import them into [`KeyCustody`] as the new identity key, in the
    /// [`KeyRole::Identity`] role (the canonical use of the pre-rotation key
    /// per ADR-003 §4b).
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

/// Names one next-set key a [`NextSetCustody`] holds (`09-security-model.md`
/// §9.7.4.1, §9.7.4.2 R10).
///
/// A distinct type from [`KeyHandle`] and [`PreRotationKeyHandle`], so no
/// operational or pre-rotation handle reaches a next-set custody. A handle is
/// meaningful only to the custody that generated it.
///
/// **A custody issues each id once over the life of its store, restarts
/// included, and never reissues the id of a destroyed key**, because a
/// holder retrying a destroy after a crash treats
/// [`NextSetCustodyError::HandleNotFound`] as already destroyed, and a
/// reissued id would let that retry destroy a newer next-set key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NextSetKeyHandle(u64);

impl NextSetKeyHandle {
    /// A handle over the raw identifier `id`, for a [`NextSetCustody`]
    /// implementation allocating ids in its own store.
    #[must_use]
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// The raw identifier.
    #[must_use]
    pub const fn id(&self) -> u64 {
        self.0
    }
}

/// Why a [`NextSetCustody`] lifecycle operation failed.
///
/// Signing failures are [`KeyEventSignError`](scp_kel::KeyEventSignError),
/// which the [`KeyEventSigner`](scp_kel::KeyEventSigner) supertrait returns.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NextSetCustodyError {
    /// The custody holds no key under the handle: never generated here, or
    /// destroyed.
    #[error("next-set key handle not found")]
    HandleNotFound,
    /// The custody substrate is unavailable. The message names the failure and
    /// carries no key material or handle bytes.
    #[error("next-set custody unavailable: {0}")]
    Unavailable(String),
    /// The custody's persistence failed. The message carries no key material.
    #[error("next-set custody storage failed: {0}")]
    Storage(String),
    /// The custody offers neither [`seal_backup`](NextSetCustody::seal_backup)
    /// nor [`restore`](NextSetCustody::restore): every next-set custody that
    /// is not headless refuses both (`09-security-model.md` §9.7.4.1 item 4,
    /// the sealing window).
    #[error("this next-set custody offers no backup method")]
    MethodNotOffered,
}

/// The encoded width of an encrypted offline backup of a next-set key
/// (`09-security-model.md` §9.18.17): version, salt, nonce, ciphertext, tag.
pub const ENCRYPTED_BACKUP_BYTES: usize = 77;

/// The encoded width of one Shamir share of a next-set key
/// (`09-security-model.md` §9.18.17): version, x, and 32-byte y.
pub const SHAMIR_SHARE_BYTES: usize = 34;

/// The number of Shamir shares a seal emits (`09-security-model.md`
/// §9.7.4.1 item 4, the 3-of-5 split).
pub const SHAMIR_SHARE_COUNT: usize = 5;

/// The number of Shamir shares a restore combines (`09-security-model.md`
/// §9.7.4.1 item 4, the 3-of-5 split).
pub const SHAMIR_THRESHOLD: usize = 3;

/// Where the passphrase of an encrypted offline backup comes from
/// (`09-security-model.md` §9.7.4.1 item 4, the sealing window).
pub enum PassphraseSource {
    /// The custody generates the passphrase: the 12-word BIP39 English
    /// mnemonic of 16 bytes from the operating system's CSPRNG.
    Generate,
    /// The caller supplies the passphrase. The custody refuses an empty one.
    Supplied(zeroize::Zeroizing<String>),
}

impl std::fmt::Debug for PassphraseSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Generate => f.write_str("Generate"),
            Self::Supplied(_) => f.write_str("Supplied(<redacted>)"),
        }
    }
}

/// The copyable method a [`NextSetCustody::seal_backup`] call names
/// (`09-security-model.md` §9.7.4.1 item 4, the headless methods).
#[derive(Debug)]
pub enum BackupRequest {
    /// The encrypted offline backup, under a passphrase from `passphrase`.
    Encrypted {
        /// The passphrase's source.
        passphrase: PassphraseSource,
    },
    /// The 3-of-5 Shamir split.
    Shamir,
    /// The 24-word BIP39 paper backup.
    Paper,
}

impl BackupRequest {
    /// The custody kind whose method this request names. A headless custody
    /// refuses, with [`NextSetCustodyError::MethodNotOffered`], a request
    /// whose kind differs from its own
    /// [`custody_kind`](NextSetCustody::custody_kind).
    #[must_use]
    pub const fn custody_kind(&self) -> PreRotationCustodyKind {
        match self {
            Self::Encrypted { .. } => PreRotationCustodyKind::EncryptedOfflineBackup,
            Self::Shamir => PreRotationCustodyKind::ShamirSecretSharing,
            Self::Paper => PreRotationCustodyKind::PaperBackupBip39,
        }
    }
}

/// The copyable artifact of one next-set key that
/// [`NextSetCustody::seal_backup`] emits (`09-security-model.md` §9.7.4.1
/// item 4).
///
/// [`NextSetCustody::restore`] takes a [`RestoreMaterial`], which
/// holds the three Shamir shares a restore combines where this type holds
/// the five a seal emits.
///
/// Its `Debug` output names the method and redacts every secret.
pub enum BackupArtifact {
    /// The encrypted offline backup and the passphrase that opens it: the
    /// generated one, or the one the caller supplied.
    Encrypted {
        /// The `ENCRYPTED_BACKUP_BYTES`-byte backup.
        backup: [u8; ENCRYPTED_BACKUP_BYTES],
        /// The passphrase.
        passphrase: zeroize::Zeroizing<String>,
    },
    /// The five Shamir shares a seal emits.
    Shamir {
        /// The shares, each `SHAMIR_SHARE_BYTES` bytes, held in place so no
        /// reallocation leaves a copy in freed memory.
        shares: [zeroize::Zeroizing<[u8; SHAMIR_SHARE_BYTES]>; SHAMIR_SHARE_COUNT],
    },
    /// The 24 BIP39 English words, joined by single ASCII spaces.
    Paper {
        /// The words.
        words: zeroize::Zeroizing<String>,
    },
}

impl std::fmt::Debug for BackupArtifact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Encrypted { .. } => f.debug_struct("Encrypted").finish_non_exhaustive(),
            Self::Shamir { shares } => f
                .debug_struct("Shamir")
                .field("share_count", &shares.len())
                .finish_non_exhaustive(),
            Self::Paper { .. } => f.debug_struct("Paper").finish_non_exhaustive(),
        }
    }
}

/// What [`NextSetCustody::restore`] reconstructs a next-set key from
/// (`09-security-model.md` §9.7.4.1 item 4, restore).
///
/// Its `Debug` output names the method and redacts every secret.
pub enum RestoreMaterial {
    /// An encrypted offline backup and the passphrase that opens it.
    Encrypted {
        /// The `ENCRYPTED_BACKUP_BYTES`-byte backup.
        backup: [u8; ENCRYPTED_BACKUP_BYTES],
        /// The passphrase.
        passphrase: zeroize::Zeroizing<String>,
    },
    /// Three of the five Shamir shares a seal emitted.
    Shamir {
        /// The shares, each `SHAMIR_SHARE_BYTES` bytes.
        shares: [zeroize::Zeroizing<[u8; SHAMIR_SHARE_BYTES]>; SHAMIR_THRESHOLD],
    },
    /// The 24 BIP39 English words, joined by single ASCII spaces.
    Paper {
        /// The words.
        words: zeroize::Zeroizing<String>,
    },
}

impl RestoreMaterial {
    /// The custody kind whose method this material belongs to. A headless
    /// custody refuses, with [`NextSetCustodyError::MethodNotOffered`],
    /// material whose kind differs from its own
    /// [`custody_kind`](NextSetCustody::custody_kind).
    #[must_use]
    pub const fn custody_kind(&self) -> PreRotationCustodyKind {
        match self {
            Self::Encrypted { .. } => PreRotationCustodyKind::EncryptedOfflineBackup,
            Self::Shamir { .. } => PreRotationCustodyKind::ShamirSecretSharing,
            Self::Paper { .. } => PreRotationCustodyKind::PaperBackupBip39,
        }
    }
}

impl std::fmt::Debug for RestoreMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Encrypted { .. } => f.debug_struct("Encrypted").finish_non_exhaustive(),
            Self::Shamir { shares } => f
                .debug_struct("Shamir")
                .field("share_count", &shares.len())
                .finish_non_exhaustive(),
            Self::Paper { .. } => f.debug_struct("Paper").finish_non_exhaustive(),
        }
    }
}

/// Custody of next-set keys: the keys a key event commits to and a later
/// event reveals (`09-security-model.md` §9.7.4.1, §9.7.4.2 R10).
///
/// A next-set member signs a key event through the
/// [`KeyEventSigner`](scp_kel::KeyEventSigner) supertrait and nothing else. No
/// method returns key material: [`reveal_public_key`](Self::reveal_public_key)
/// returns the 33-byte compressed SEC1 point. Spec 16 §16.12.3a lists the
/// behaviours every implementor passes.
///
/// [`KeyEventSigner`](scp_kel::KeyEventSigner)'s methods have no default
/// body, so an implementor that omits one does not compile:
///
/// ```compile_fail,E0046
/// use core::future::Future;
/// use scp_platform::{
///     BackupArtifact, BackupRequest, CustodyProbe, KeyEventSignError, KeyEventSigner,
///     MaybeSend, NextSetCustody, NextSetCustodyError, NextSetKeyHandle,
///     PreRotationCustodyKind, ProbeSignature, RestoreMaterial,
/// };
///
/// struct Partial;
///
/// impl KeyEventSigner for Partial {
///     type Member = NextSetKeyHandle;
///
///     fn sign_probe(
///         &self,
///         _member: &NextSetKeyHandle,
///         _probe: &CustodyProbe,
///     ) -> impl Future<Output = Result<ProbeSignature, KeyEventSignError>> + MaybeSend {
///         async { Err(KeyEventSignError::MemberNotFound) }
///     }
/// }
///
/// impl NextSetCustody for Partial {
///     fn generate(
///         &self,
///     ) -> impl Future<Output = Result<NextSetKeyHandle, NextSetCustodyError>> + Send {
///         async { Err(NextSetCustodyError::HandleNotFound) }
///     }
///
///     fn reveal_public_key(
///         &self,
///         _handle: &NextSetKeyHandle,
///     ) -> impl Future<Output = Result<[u8; 33], NextSetCustodyError>> + Send {
///         async { Err(NextSetCustodyError::HandleNotFound) }
///     }
///
///     fn destroy(
///         &self,
///         _handle: &NextSetKeyHandle,
///     ) -> impl Future<Output = Result<(), NextSetCustodyError>> + Send {
///         async { Err(NextSetCustodyError::HandleNotFound) }
///     }
///
///     fn seal_backup(
///         &self,
///         _handle: &NextSetKeyHandle,
///         _request: BackupRequest,
///     ) -> impl Future<Output = Result<BackupArtifact, NextSetCustodyError>> + Send {
///         async { Err(NextSetCustodyError::MethodNotOffered) }
///     }
///
///     fn restore(
///         &self,
///         _material: RestoreMaterial,
///         _expected_commitment: [u8; 32],
///     ) -> impl Future<Output = Result<NextSetKeyHandle, NextSetCustodyError>> + Send {
///         async { Err(NextSetCustodyError::MethodNotOffered) }
///     }
///
///     fn custody_kind(&self) -> PreRotationCustodyKind {
///         PreRotationCustodyKind::Callback
///     }
/// }
/// ```
///
/// The positive control, identical but for `sign_change`:
///
/// ```
/// use core::future::Future;
/// use scp_platform::{
///     BackupArtifact, BackupRequest, CustodyProbe, IndexedSignature, KeyEventSignError,
///     KeyEventSigner, MaybeSend, NextSetCustody, NextSetCustodyError, NextSetKeyHandle,
///     PreRotationCustodyKind, ProbeSignature, RestoreMaterial, SigningChange,
/// };
///
/// struct Partial;
///
/// impl KeyEventSigner for Partial {
///     type Member = NextSetKeyHandle;
///
///     fn sign_change(
///         &self,
///         _member: &NextSetKeyHandle,
///         _change: &SigningChange,
///     ) -> impl Future<Output = Result<IndexedSignature, KeyEventSignError>> + MaybeSend {
///         async { Err(KeyEventSignError::MemberNotFound) }
///     }
///
///     fn sign_probe(
///         &self,
///         _member: &NextSetKeyHandle,
///         _probe: &CustodyProbe,
///     ) -> impl Future<Output = Result<ProbeSignature, KeyEventSignError>> + MaybeSend {
///         async { Err(KeyEventSignError::MemberNotFound) }
///     }
/// }
///
/// impl NextSetCustody for Partial {
///     fn generate(
///         &self,
///     ) -> impl Future<Output = Result<NextSetKeyHandle, NextSetCustodyError>> + Send {
///         async { Err(NextSetCustodyError::HandleNotFound) }
///     }
///
///     fn reveal_public_key(
///         &self,
///         _handle: &NextSetKeyHandle,
///     ) -> impl Future<Output = Result<[u8; 33], NextSetCustodyError>> + Send {
///         async { Err(NextSetCustodyError::HandleNotFound) }
///     }
///
///     fn destroy(
///         &self,
///         _handle: &NextSetKeyHandle,
///     ) -> impl Future<Output = Result<(), NextSetCustodyError>> + Send {
///         async { Err(NextSetCustodyError::HandleNotFound) }
///     }
///
///     fn seal_backup(
///         &self,
///         _handle: &NextSetKeyHandle,
///         _request: BackupRequest,
///     ) -> impl Future<Output = Result<BackupArtifact, NextSetCustodyError>> + Send {
///         async { Err(NextSetCustodyError::MethodNotOffered) }
///     }
///
///     fn restore(
///         &self,
///         _material: RestoreMaterial,
///         _expected_commitment: [u8; 32],
///     ) -> impl Future<Output = Result<NextSetKeyHandle, NextSetCustodyError>> + Send {
///         async { Err(NextSetCustodyError::MethodNotOffered) }
///     }
///
///     fn custody_kind(&self) -> PreRotationCustodyKind {
///         PreRotationCustodyKind::Callback
///     }
/// }
/// ```
pub trait NextSetCustody: Send + Sync + scp_kel::KeyEventSigner<Member = NextSetKeyHandle> {
    /// Generates a next-set key and returns its handle.
    ///
    /// # Errors
    ///
    /// [`NextSetCustodyError::Unavailable`] or
    /// [`NextSetCustodyError::Storage`] when the substrate cannot generate or
    /// keep the key.
    fn generate(
        &self,
    ) -> impl std::future::Future<Output = Result<NextSetKeyHandle, NextSetCustodyError>> + Send;

    /// The key's public key, a 33-byte compressed SEC1 P-256 point.
    ///
    /// # Errors
    ///
    /// [`NextSetCustodyError::HandleNotFound`] when the custody holds no key
    /// under `handle`.
    fn reveal_public_key(
        &self,
        handle: &NextSetKeyHandle,
    ) -> impl std::future::Future<Output = Result<[u8; 33], NextSetCustodyError>> + Send;

    /// Destroys the key, so every later call with `handle` fails. The id is
    /// never issued again (see [`NextSetKeyHandle`]).
    ///
    /// # Errors
    ///
    /// [`NextSetCustodyError::HandleNotFound`] when the custody holds no key
    /// under `handle`.
    fn destroy(
        &self,
        handle: &NextSetKeyHandle,
    ) -> impl std::future::Future<Output = Result<(), NextSetCustodyError>> + Send;

    /// Emits the copyable artifact `request` names for the key under
    /// `handle`, wipes the key's scalar from the custody, and keeps its
    /// public key (`09-security-model.md` §9.7.4.1 item 4, the sealing
    /// window). Only a headless custody seals, and only by the method its
    /// [`custody_kind`](Self::custody_kind) declares. The sealing-window
    /// errors §9.7.4.1 names arrive with the headless custody.
    ///
    /// # Errors
    ///
    /// - [`NextSetCustodyError::MethodNotOffered`] from every custody that is
    ///   not headless, whatever `request` names, and from a headless custody
    ///   when [`BackupRequest::custody_kind`] differs from its own kind.
    /// - [`NextSetCustodyError::HandleNotFound`] from a headless custody when
    ///   `handle` names no key it holds.
    fn seal_backup(
        &self,
        handle: &NextSetKeyHandle,
        request: BackupRequest,
    ) -> impl std::future::Future<Output = Result<BackupArtifact, NextSetCustodyError>> + Send;

    /// Reconstructs a key from `material` inside the custody and returns its
    /// handle, never its scalar (`09-security-model.md` §9.7.4.1 item 4,
    /// restore). `expected_commitment` is the pre-rotation commitment the
    /// caller expects the restored key to derive. Only a headless custody
    /// restores, and only material of the method its
    /// [`custody_kind`](Self::custody_kind) declares. The check of
    /// `expected_commitment`, and the error that reports a mismatch, arrive
    /// with the headless custody.
    ///
    /// # Errors
    ///
    /// [`NextSetCustodyError::MethodNotOffered`] from every custody that is
    /// not headless, whatever `material` holds, and from a headless custody
    /// when [`RestoreMaterial::custody_kind`] differs from its own kind.
    fn restore(
        &self,
        material: RestoreMaterial,
        expected_commitment: [u8; 32],
    ) -> impl std::future::Future<Output = Result<NextSetKeyHandle, NextSetCustodyError>> + Send;

    /// The substrate this custody keeps its keys in (ADR-054), a fixed value
    /// per implementation. It is security-relevant: `Identity::create` checks
    /// the method it declares against the config's `CustodyProfile` and
    /// refuses a method that profile does not admit as the next set's one
    /// member (`09-security-model.md` §9.7.4.1 item 4), and writes that
    /// method into the inception's commitment entry, which the signed
    /// preimage, and so the identifier, hashes. An implementation returns
    /// the kind of the substrate it actually uses, because a misstated kind
    /// passes the profile check falsely and signs a false method into the
    /// identity's log.
    fn custody_kind(&self) -> PreRotationCustodyKind;
}

/// Device attestation trait.
///
/// Abstracts platform-specific device attestation (Apple App Attest, Android
/// `SafetyNet` / Play Integrity). ADR-006, the platform abstraction, in
/// `.docs/adrs/phase-1.md` defines this trait signature.
///
/// `InMemoryDeviceAttestation`, the `testing`-gated implementation in
/// `crate::testing`, mints tokens carrying the byte prefix
/// `scp-test-attestation-v1:` followed by a sequence number. Its
/// [`verify`](DeviceAttestation::verify) returns `true` for a token carrying
/// that prefix and `false` for every token that does not. Two unit tests in
/// that module, `verify_foreign_token_returns_false` and
/// `verify_empty_token_returns_false`, pin the rejecting branch.
///
/// Neither platform adapter implements this trait. The Swift
/// `AppleDeviceAttestation` adapter conforms to the `UniFFI`
/// `DeviceAttestationProvider` callback interface in
/// `crates/scp-ffi/uniffi/src/lib.rs`, which has declared no verifier since
/// ADR-021 defined it. That adapter carries no verifier either, because the
/// maintainer ruled on 2026-09-26 that reading-side verification belongs to
/// the keri workstream (ADR-025, the Apple platform adapter, in
/// `.docs/adrs/phase-5.md`). §9.3.1 of `.docs/specs/09-security-model.md`
/// states how a reader verifies an Apple App Attest attestation object, and
/// story SCP-316, still pending, specifies that reader; no code verifies a
/// device attestation yet. OQ-22 of
/// `.docs/specs/27-attestations.md` keeps open which of the two traits is
/// normative.
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
/// (APNs, FCM). See ADR-006.
pub trait Push: Send + Sync {
    /// Register for push notifications and return a platform-specific token.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::PushError`] with
    /// [`PushFailureKind::ProviderFailed`](crate::error::PushFailureKind::ProviderFailed)
    /// if registration fails.
    fn register(&self) -> impl Future<Output = Result<PushToken, PlatformError>> + Send;

    /// Handle an incoming push notification payload and produce a wake signal.
    ///
    /// Returns one fixed [`WakeSignal`] for every payload the implementation
    /// accepts, and may reject a payload instead. §10.7 of the infrastructure
    /// spec states: "Push payloads MUST contain a wake signal and nothing else.
    /// No context ID, no sender identifier, no message preview, no metadata of
    /// any kind." The signal must therefore not vary with `payload`: a signal
    /// that did would hand the caller whatever a relay put there. Spec
    /// §16.12.5 and ADR-006 state this contract for every implementation.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformError::PushError`] with
    /// [`PushFailureKind::WakePayloadInvalid`](crate::error::PushFailureKind::WakePayloadInvalid)
    /// if the payload is not the platform's wake signal.
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
// Software key helpers (software_platform only)
// ---------------------------------------------------------------------------

/// Signs a 32-byte digest with a software P-256 key: the shared
/// [`KeyCustody::sign`] path of every software backend for
/// [`KeyType::P256Signing`] handles.
///
/// # Errors
///
/// [`PlatformError::CustodyError`] when `data` is not 32 bytes, or when
/// signing fails.
#[cfg(all(
    feature = "software_platform",
    any(feature = "file", feature = "sqlite", feature = "testing")
))]
pub(crate) fn sign_p256_digest(
    key: &scp_crypto::p256::P256SecretKey,
    data: &[u8],
) -> Result<Signature, PlatformError> {
    let digest: &[u8; 32] = data.try_into().map_err(|_| {
        PlatformError::CustodyError(format!(
            "a P-256 signing key signs a 32-byte digest, got {} bytes",
            data.len()
        ))
    })?;
    scp_crypto::p256::sign_prehash_rfc6979(key, digest)
        .map(|sig| Signature::new(sig.to_vec()))
        .map_err(|e| PlatformError::CustodyError(format!("P-256 signing: {e}")))
}

/// Signs a key-event digest (a [`SigningChange`](scp_kel::SigningChange)'s
/// `D` or a [`CustodyProbe`](scp_kel::CustodyProbe)'s raw digest) with a
/// software P-256 key, giving the 64-byte raw-form signature: RFC 6979
/// deterministic ECDSA, low-`s` (`09-security-model.md` §9.7.4.2, "Signature
/// form"). The caller wraps it as
/// [`IndexedSignature::Raw`](scp_kel::IndexedSignature::Raw) or
/// [`ProbeSignature::raw`](scp_kel::ProbeSignature::raw).
///
/// # Errors
///
/// [`PlatformError::CustodyError`] when the signature cannot be computed.
#[cfg(all(
    feature = "software_platform",
    any(feature = "file", feature = "sqlite", feature = "testing")
))]
pub(crate) fn sign_key_event_digest(
    key: &scp_crypto::p256::P256SecretKey,
    digest: &[u8; 32],
) -> Result<[u8; 64], PlatformError> {
    scp_crypto::p256::sign_prehash_rfc6979(key, digest)
        .map_err(|e| PlatformError::CustodyError(format!("P-256 key-event signing: {e}")))
}

/// Parses the peer public key of a [`KeyType::HpkeP256`] key agreement.
///
/// The peer must be exactly the 65-byte uncompressed SEC1 point
/// `0x04 || x || y` (RFC 9180 §7.1.1), on the curve and not the identity.
/// Every backend and bridge uses this one check.
///
/// # Errors
///
/// [`PlatformError::CustodyError`] on any other length, a prefix other than
/// `0x04`, an off-curve point, or the identity.
pub fn hpke_p256_peer(
    peer_public: &[u8],
) -> Result<scp_crypto::p256::P256PublicKey, PlatformError> {
    scp_crypto::p256::P256PublicKey::from_uncompressed(peer_public)
        .map_err(|e| PlatformError::CustodyError(format!("P-256 peer public key: {e}")))
}

/// Performs ECDH between a software [`KeyType::HpkeP256`] key and a peer
/// that passes [`hpke_p256_peer`]: the shared [`KeyCustody::dh_agree`] path
/// of every software backend.
///
/// # Errors
///
/// [`PlatformError::CustodyError`] when `peer_public` fails
/// [`hpke_p256_peer`].
#[cfg(all(
    feature = "software_platform",
    any(feature = "file", feature = "sqlite", feature = "testing")
))]
pub(crate) fn p256_dh_agree(
    key: &scp_crypto::p256::P256SecretKey,
    peer_public: &[u8],
) -> Result<SharedSecret, PlatformError> {
    let peer = hpke_p256_peer(peer_public)?;
    let shared = scp_crypto::p256::ecdh_p256(key, &peer);
    Ok(SharedSecret::new(*shared))
}

/// Rebuilds a persisted P-256 key from its 32-byte scalar, rejecting zero and
/// values `>= n`.
///
/// # Errors
///
/// [`PlatformError::StorageError`] when the stored scalar is not a valid
/// P-256 private key.
#[cfg(all(
    feature = "software_platform",
    any(feature = "file", feature = "sqlite")
))]
pub(crate) fn p256_key_from_stored(
    scalar: &[u8; 32],
) -> Result<scp_crypto::p256::P256SecretKey, PlatformError> {
    scp_crypto::p256::P256SecretKey::from_scalar_bytes(scalar).map_err(|e| {
        PlatformError::StorageError(format!("stored P-256 scalar is not a valid key: {e}"))
    })
}

/// Generates a fresh P-256 scalar from the OS RNG by rejection sampling, for
/// the persistent software backends and `InMemoryNextSetCustody`.
///
/// # Errors
///
/// [`PlatformError::CustodyError`] when 8 consecutive draws are all invalid
/// scalars (probability below 2^-256; a broken RNG, never bad luck).
#[cfg(all(
    feature = "software_platform",
    any(feature = "file", feature = "sqlite", feature = "testing")
))]
pub(crate) fn generate_p256_os_rng() -> Result<scp_crypto::p256::P256SecretKey, PlatformError> {
    use rand::RngCore as _;
    for _ in 0..8 {
        let mut scalar = zeroize::Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(scalar.as_mut());
        if let Ok(key) = scp_crypto::p256::P256SecretKey::from_scalar_bytes(&scalar) {
            return Ok(key);
        }
    }
    Err(PlatformError::CustodyError(
        "OS RNG produced no valid P-256 scalar in 8 draws".into(),
    ))
}

/// Requires a pseudonym-derivation source to be an Ed25519 identity key
/// (§9.10.4.A).
///
/// Every custody that records roles shares this check, the software backends
/// and the callback adapter alike. The role is checked first, so an operational key of any type fails as
/// [`PlatformError::NotIdentityKey`].
///
/// # Errors
///
/// [`PlatformError::NotIdentityKey`] for a source in the operational role.
/// [`PlatformError::WrongKeyType`] with `expected` [`KeyType::Ed25519`] for
/// an identity source that is not Ed25519.
pub const fn require_derive_source(role: KeyRole, key_type: KeyType) -> Result<(), PlatformError> {
    if !matches!(role, KeyRole::Identity) {
        return Err(PlatformError::NotIdentityKey);
    }
    // §9.10.4.A: the identity key is Ed25519.
    if !matches!(key_type, KeyType::Ed25519) {
        return Err(PlatformError::WrongKeyType {
            expected: KeyType::Ed25519,
            actual: key_type,
        });
    }
    Ok(())
}

/// Refuses [`KeyType::P256KeyEvent`] as an argument to
/// [`KeyCustody::generate_keypair`].
///
/// Every `generate_keypair` implementation calls this first: a key-event
/// key's one mint is [`KeyCustody::generate_key_event_keypair`] (SCP-345).
///
/// # Errors
///
/// [`PlatformError::WrongKeyType`] with `expected`
/// [`KeyType::P256Signing`] and `actual` [`KeyType::P256KeyEvent`].
pub const fn refuse_key_event_mint(key_type: KeyType) -> Result<(), PlatformError> {
    if matches!(key_type, KeyType::P256KeyEvent) {
        return Err(PlatformError::WrongKeyType {
            expected: KeyType::P256Signing,
            actual: KeyType::P256KeyEvent,
        });
    }
    Ok(())
}

/// Every key type, listed through an exhaustive match so a new variant
/// fails to compile here until every key-type byte table covers it.
#[cfg(test)]
pub(crate) fn all_key_types() -> [KeyType; 4] {
    let all = [
        KeyType::Ed25519,
        KeyType::P256Signing,
        KeyType::HpkeP256,
        KeyType::P256KeyEvent,
    ];
    for t in all {
        match t {
            KeyType::Ed25519 | KeyType::P256Signing | KeyType::HpkeP256 | KeyType::P256KeyEvent => {
            }
        }
    }
    all
}

/// Test-only: asserts that `encode` gives each key type a distinct byte that
/// `decode` maps back, and that `decode` refuses every other byte.
#[cfg(test)]
pub(crate) fn assert_key_type_bijection(
    table: &str,
    encode: impl Fn(KeyType) -> u8,
    decode: impl Fn(u8) -> Option<KeyType>,
) {
    let codes: Vec<u8> = all_key_types().into_iter().map(&encode).collect();
    let mut distinct = codes.clone();
    distinct.sort_unstable();
    distinct.dedup();
    assert_eq!(
        distinct.len(),
        codes.len(),
        "{table}: codes collide {codes:?}"
    );
    for t in all_key_types() {
        assert_eq!(decode(encode(t)), Some(t), "{table}: {t:?}");
    }
    for byte in 0..=u8::MAX {
        if !codes.contains(&byte) {
            assert_eq!(decode(byte), None, "{table}: byte {byte} decodes");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{KeyRole, KeyType, PushToken, all_key_types, assert_key_type_bijection};

    /// `Debug` of a push token prints its length and none of its bytes, in
    /// text or in the decimal list a derived `Debug` would print.
    #[test]
    fn push_token_debug_prints_no_token_bytes() {
        let token = PushToken::new(b"secret-apns-token".to_vec());
        let printed = format!("{token:?} {token:#?}");
        assert!(!printed.contains("secret"), "{printed}");
        assert!(!printed.contains("115, 101, 99"), "{printed}");
        assert!(printed.contains("17 bytes redacted"), "{printed}");
    }

    /// The SQLite and custody-record table maps the key types one-to-one and
    /// refuses every byte it does not assign; `file.rs` checks File's §17.8
    /// table with the same helper.
    #[test]
    fn key_type_byte_tables_are_bijections() {
        assert_key_type_bijection(
            "storage_code",
            KeyType::storage_code,
            KeyType::from_storage_code,
        );
        assert_eq!(
            all_key_types().map(KeyType::storage_code),
            [0, 2, 3, 4],
            "the SQLite rows already on disk fix these codes"
        );
    }

    /// Only the key-event type is refused as a `generate_keypair` argument.
    #[test]
    fn refuse_key_event_mint_refuses_only_the_key_event_type() {
        for t in all_key_types() {
            let refused = super::refuse_key_event_mint(t);
            if t == KeyType::P256KeyEvent {
                assert!(matches!(
                    refused,
                    Err(crate::error::PlatformError::WrongKeyType {
                        expected: KeyType::P256Signing,
                        actual: KeyType::P256KeyEvent,
                    })
                ));
            } else {
                assert!(refused.is_ok(), "{t:?}");
            }
        }
    }

    /// Every key type and role names itself in the host contract and parses
    /// back; a near miss in case or spelling parses to nothing.
    #[test]
    fn host_contract_names_round_trip() {
        for t in all_key_types() {
            assert_eq!(KeyType::parse(t.as_str()), Some(t));
        }
        assert_eq!(KeyType::P256Signing.as_str(), "p256");
        assert_eq!(KeyType::HpkeP256.as_str(), "hpke-p256");
        assert_eq!(KeyType::P256KeyEvent.as_str(), "p256-key-event");
        for r in [KeyRole::Identity, KeyRole::Operational] {
            assert_eq!(KeyRole::parse(r.as_str()), Some(r));
        }
        // `"x25519"` named a key type the custody contract no longer has.
        for bad in [
            "P256",
            "",
            "hpke_p256",
            "Identity",
            "admin",
            "x25519",
            "p256_key_event",
            "p256-keyevent",
        ] {
            assert_eq!(KeyType::parse(bad), None, "{bad}");
            assert_eq!(KeyRole::parse(bad), None, "{bad}");
        }
    }

    /// Each next-set kind declares the §9.7.4.2 custody type of its one
    /// method, and the two kinds that name no one method declare none.
    #[test]
    fn next_set_kinds_declare_their_method() {
        use super::PreRotationCustodyKind as Kind;
        use scp_did::CustodyType as Type;
        let table = [
            (Kind::HardwareSecurityKey, Some(Type::Fido2Token)),
            (
                Kind::EncryptedOfflineBackup,
                Some(Type::EncryptedOfflineBackup),
            ),
            (Kind::ShamirSecretSharing, Some(Type::ShamirShares)),
            (Kind::PaperBackupBip39, Some(Type::PaperBackup)),
            (Kind::PlatformCloudKeyStore, Some(Type::Passkey)),
            (Kind::InMemory, Some(Type::Software)),
            (Kind::SecondaryDeviceEnclave, None),
            (Kind::Callback, None),
        ];
        for (kind, declared) in table {
            assert_eq!(kind.declared_custody_type(), declared, "{kind:?}");
        }
    }

    /// Software and in-memory keys disclose `Software`; a hardware key
    /// discloses the keystore of the target the test runs on.
    #[test]
    fn operational_custody_types_map_to_key_entry_types() {
        use super::CustodyType;
        use scp_did::CustodyType as Type;
        assert_eq!(
            CustodyType::InMemory.key_entry_custody_type(),
            Type::Software
        );
        assert_eq!(
            CustodyType::Software.key_entry_custody_type(),
            Type::Software
        );
        let hardware = if cfg!(any(target_os = "ios", target_os = "macos")) {
            Type::SecureEnclave
        } else if cfg!(target_os = "android") {
            Type::AndroidKeystore
        } else {
            Type::Hsm
        };
        assert_eq!(CustodyType::Hardware.key_entry_custody_type(), hardware);
    }
}
