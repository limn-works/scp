//! Broadcast key lifecycle and `BroadcastEnvelope` seal/open for broadcast contexts.
//!
//! Broadcast contexts (spec section 5.14) use per-author AES-256-GCM broadcast
//! keys instead of MLS group encryption. Each author holds a broadcast key with
//! a monotonic epoch counter. Key rotation generates a fresh random key (not
//! HKDF-derived) to provide key independence — compromise of one epoch reveals
//! nothing about other epochs. See ADR-007 for the sender-side key layer design
//! and §5.14.2 for the broadcast-specific key lifecycle.
//!
//! # Key Lifecycle
//!
//! 1. Author generates initial broadcast key (epoch 0) via [`generate_broadcast_key`].
//! 2. Normal operation: seal content with [`seal_broadcast`].
//! 3. On block: rotate via [`rotate_broadcast_key`], which increments epoch and
//!    emits a [`BroadcastKeyEpochAdvance`] event.
//! 4. Subscribers request new key via the pull-based protocol (SCP-227).
//!
//! # `BroadcastEnvelope`
//!
//! [`seal_broadcast`] encrypts a payload with the author's current broadcast key
//! (AES-256-GCM) and packages it into a [`BroadcastEnvelope`].
//! [`open_broadcast`] decrypts using the author's broadcast key at the specified
//! epoch.
//!
//! # AAD Binding (Security)
//!
//! The `author_did` and `key_epoch` fields in [`BroadcastEnvelope`] are cleartext
//! metadata that must be authenticated by the AEAD tag. Both [`seal_broadcast`]
//! and [`open_broadcast`] bind these fields as Additional Authenticated Data
//! (AAD) in the AES-256-GCM construction using a length-prefixed binary format:
//! `[4-byte DID length (BE)][DID bytes][8-byte epoch (BE)]`.
//! This prevents attribution forgery by context members who possess the
//! broadcast key (issue #228, cryptographer review finding 1, RED-210).
//!
//! **BREAKING**: This changes the wire format. Envelopes sealed without AAD
//! cannot be opened by this version (and vice versa).

use aes_gcm::aead::Payload;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use ed25519_dalek::Signer;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{SenderKey, SenderKeyError};

/// AES-256-GCM nonce size in bytes.
const NONCE_SIZE: usize = 12;

// ---------------------------------------------------------------------------
// BroadcastKey
// ---------------------------------------------------------------------------

/// Per-author AES-256-GCM broadcast key with epoch counter.
///
/// Each author in a broadcast context holds one of these. The key material is
/// a random 32-byte AES-256 key. The epoch is a monotonic counter incremented
/// on each rotation (triggered by blocking). Key material is freshly generated
/// on rotation -- not HKDF-derived -- to provide key independence per section 5.14.2.
///
/// Key material is zeroized on drop via the inner [`SenderKey`]. Clone is
/// retained for production use in `BroadcastAuthorState`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct BroadcastKey {
    /// The underlying 32-byte AES-256 key (reuses [`SenderKey`] for consistency).
    key: SenderKey,
    /// Monotonic epoch counter. Starts at 0, increments on each rotation.
    epoch: u64,
    /// The DID of the author who owns this broadcast key.
    author_did: String,
}

impl BroadcastKey {
    /// Constructs a `BroadcastKey` from its component parts.
    ///
    /// Used by [`crate::context::broadcast::BroadcastContext::publish`] to
    /// bridge from the context-layer `AuthorState` (which stores a `SenderKey`
    /// and epoch) to the crypto-layer `BroadcastKey` required by
    /// [`seal_broadcast`].
    #[must_use]
    pub const fn from_parts(key: SenderKey, epoch: u64, author_did: String) -> Self {
        Self {
            key,
            epoch,
            author_did,
        }
    }

    /// Returns a reference to the underlying AES-256 key material.
    #[must_use]
    pub const fn key(&self) -> &SenderKey {
        &self.key
    }

    /// Returns the current epoch of this broadcast key.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns the DID of the author who owns this broadcast key.
    #[must_use]
    pub fn author_did(&self) -> &str {
        &self.author_did
    }
}

impl std::fmt::Debug for BroadcastKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BroadcastKey")
            .field("key", &"[REDACTED]")
            .field("epoch", &self.epoch)
            .field("author_did", &self.author_did)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// BroadcastKeyEpochAdvance
// ---------------------------------------------------------------------------

/// Event emitted when an author rotates their broadcast key to a new epoch.
///
/// This is the broadcast-mode equivalent of [`SenderKeyEpochAdvance`] from
/// `key_protocol.rs`. In broadcast contexts, this travels as a relay message
/// (not an MLS application message). Maps to `EventType::KeyEpochAdvance` in
/// the event log per §5.14.10.
///
/// [`SenderKeyEpochAdvance`]: super::SenderKeyEpochAdvance
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BroadcastKeyEpochAdvance {
    /// The DID of the author who rotated their broadcast key.
    pub author_did: String,
    /// The new epoch number after rotation.
    pub new_epoch: u64,
    /// Unix timestamp in milliseconds when the rotation occurred.
    pub timestamp: u64,
}

// ---------------------------------------------------------------------------
// BroadcastEnvelope
// ---------------------------------------------------------------------------

/// Encrypted broadcast message envelope per §5.14.5.
///
/// Contains AES-256-GCM encrypted content along with all 8 spec-defined fields
/// (minus `content_hash` per ADR-038). The `encrypted_content` field uses the
/// same wire format as [`encrypt_sender_layer`]: `nonce (12 bytes) || ciphertext || tag (16 bytes)`.
///
/// The `author_did` and `key_epoch` fields are authenticated via AES-256-GCM
/// AAD binding (length-prefixed binary format). Tampering with either field
/// causes AEAD tag verification to fail on decryption. See issue #228.
///
/// The `signature` field is an Ed25519 signature over the canonical hash
/// `SHA-256("SCP-BROADCAST-ENVELOPE-V1:" || len(context_id) || context_id || len(author_did) || author_did || sequence || timestamp || key_epoch)`.
/// Verified BEFORE decryption in [`open_broadcast`] to reject forgeries early.
/// See issue #352.
///
/// [`encrypt_sender_layer`]: super::encrypt::encrypt_sender_layer
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BroadcastEnvelope {
    /// The context ID this envelope belongs to.
    pub context_id: String,
    /// The DID of the author who sealed this envelope.
    pub author_did: String,
    /// Monotonically increasing per-author sequence number within this context.
    /// Used for replay detection: receivers reject `sequence <= last_seen`.
    pub sequence: u64,
    /// Unix timestamp in milliseconds when the message was sealed.
    pub timestamp: u64,
    /// The broadcast key epoch used to encrypt the content.
    pub key_epoch: u64,
    /// Optional provenance metadata for cross-context data flows (§7.7.1).
    pub provenance: Option<crate::provenance::DataProvenance>,
    /// Ed25519 signature over `canonical_hash("SCP-BROADCAST-ENVELOPE-V1:", ...)`
    /// with fields: `context_id`, `author_did`, `sequence`, `timestamp`, `key_epoch`.
    #[serde(with = "crate::serde_util::serde_signature_64")]
    pub signature: [u8; 64],
    /// AES-256-GCM encrypted payload: `nonce || ciphertext || auth_tag`.
    /// Bounded to 512 KiB on deserialization to prevent OOM (#347).
    #[serde(with = "crate::serde_util::serde_bounded_bytes")]
    pub encrypted_content: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

/// Generates a new per-author broadcast key at epoch 0.
///
/// Creates a fresh random 32-byte AES-256 key using the platform's
/// cryptographically secure RNG. Called when an author is granted the
/// `messagesWrite` role in a broadcast context per §5.14.2 step 1.
///
/// # Arguments
///
/// * `author_did` — The DID of the author who will own this broadcast key.
#[must_use]
pub fn generate_broadcast_key(author_did: &str) -> BroadcastKey {
    let key = super::generate_sender_key();
    BroadcastKey {
        key,
        epoch: 0,
        author_did: author_did.to_owned(),
    }
}

// ---------------------------------------------------------------------------
// Key rotation
// ---------------------------------------------------------------------------

/// Rotates a broadcast key: increments epoch, generates a new key, and emits
/// a [`BroadcastKeyEpochAdvance`] event.
///
/// Called when an author blocks a subscriber per §5.14.2 step 3 and §5.14.8.
/// The new key is freshly generated (not HKDF-derived) per §5.14.2 to provide
/// key independence across epochs.
///
/// # Arguments
///
/// * `current_key` — The author's current broadcast key to rotate.
/// * `timestamp` — Unix timestamp in milliseconds for the epoch advance event.
///
/// # Errors
///
/// Returns [`SenderKeyError::EpochOverflow`] if the epoch counter is at
/// `u64::MAX` and cannot be incremented.
pub fn rotate_broadcast_key(
    current_key: &BroadcastKey,
    timestamp: u64,
) -> Result<(BroadcastKey, BroadcastKeyEpochAdvance), SenderKeyError> {
    let new_epoch = current_key
        .epoch
        .checked_add(1)
        .ok_or(SenderKeyError::EpochOverflow)?;

    let new_key_material = super::generate_sender_key();

    let new_key = BroadcastKey {
        key: new_key_material,
        epoch: new_epoch,
        author_did: current_key.author_did.clone(),
    };

    let advance = BroadcastKeyEpochAdvance {
        author_did: current_key.author_did.clone(),
        new_epoch,
        timestamp,
    };

    Ok((new_key, advance))
}

// ---------------------------------------------------------------------------
// AAD construction
// ---------------------------------------------------------------------------

/// Constructs the Additional Authenticated Data (AAD) for `BroadcastEnvelope`
/// AES-256-GCM operations.
///
/// Format: length-prefixed binary — `[4-byte DID length (BE)][DID bytes][8-byte epoch (BE)]`.
/// This binds the cleartext metadata fields to the AEAD tag, preventing
/// attribution forgery and epoch substitution by context members who possess
/// the broadcast key. Both [`seal_broadcast`] and [`open_broadcast`] use this
/// identical construction.
///
/// The binary format is canonically parseable by construction. The previous
/// colon-delimited string format (`"{did}:{epoch}"`) was ambiguous because
/// DIDs themselves contain colons (e.g., `did:dht:abc`, `did:web:host:path`).
///
/// See issue #228, cryptographer review finding 1, RED-210.
#[allow(clippy::cast_possible_truncation)] // DID strings are always < 4 GiB
fn build_broadcast_aad(author_did: &str, key_epoch: u64) -> Vec<u8> {
    let did_bytes = author_did.as_bytes();
    let mut aad = Vec::with_capacity(4 + did_bytes.len() + 8);
    aad.extend_from_slice(&(did_bytes.len() as u32).to_be_bytes());
    aad.extend_from_slice(did_bytes);
    aad.extend_from_slice(&key_epoch.to_be_bytes());
    aad
}

// ---------------------------------------------------------------------------
// Seal / Open
// ---------------------------------------------------------------------------

/// Parameters for [`seal_broadcast`] beyond the broadcast key and payload.
///
/// Groups the metadata fields required by the expanded `BroadcastEnvelope`
/// (issue #352, §5.14.5).
pub struct SealBroadcastParams<'a> {
    /// The context ID for this broadcast message.
    pub context_id: &'a str,
    /// The per-author monotonic sequence number for this message.
    pub sequence: u64,
    /// Unix timestamp in milliseconds when the message is sealed.
    pub timestamp: u64,
    /// Optional provenance metadata (§7.7.1).
    pub provenance: Option<crate::provenance::DataProvenance>,
    /// The author's Ed25519 signing key for the envelope signature.
    pub signing_key: &'a ed25519_dalek::SigningKey,
}

/// Constructs the canonical signing payload for a `BroadcastEnvelope`.
///
/// Uses [`canonical_hash`] with domain separator `"SCP-BROADCAST-ENVELOPE-V1:"`
/// and length-prefixed variable-length fields, matching the pattern used by
/// [`compute_block_notification_hash`] in `key_protocol.rs`.
///
/// Field order: `context_id`, `author_did`, `sequence`, `timestamp`, `key_epoch`.
///
/// Used by both [`seal_broadcast`] (sign) and [`open_broadcast`] (verify).
fn build_signing_payload(
    context_id: &str,
    author_did: &str,
    sequence: u64,
    timestamp: u64,
    key_epoch: u64,
) -> [u8; 32] {
    use crate::crypto::canonical::{CanonicalField, canonical_hash};

    canonical_hash(
        "SCP-BROADCAST-ENVELOPE-V1:",
        &[
            CanonicalField::VarBytes(context_id.as_bytes()),
            CanonicalField::VarBytes(author_did.as_bytes()),
            CanonicalField::U64(sequence),
            CanonicalField::U64(timestamp),
            CanonicalField::U64(key_epoch),
        ],
    )
}

/// Encrypts a payload with the author's broadcast key and packages it into a
/// [`BroadcastEnvelope`].
///
/// Uses AES-256-GCM with a random 12-byte nonce per invocation. The wire
/// format matches [`encrypt_sender_layer`]: `nonce (12 bytes) || ciphertext || auth_tag (16 bytes)`.
///
/// The `author_did` and `key_epoch` from the broadcast key are bound as
/// Additional Authenticated Data (AAD) in the AES-256-GCM construction.
/// This cryptographically authenticates the cleartext metadata fields,
/// preventing attribution forgery. See issue #228.
///
/// The envelope is signed with the author's Ed25519 key over the canonical
/// concatenation of metadata fields. The signature is verified BEFORE
/// decryption in [`open_broadcast`] to reject forgeries early (issue #352).
///
/// # Arguments
///
/// * `key` — The author's current broadcast key.
/// * `payload` — The plaintext content to encrypt.
/// * `params` — Metadata and signing key for the expanded envelope fields.
///
/// # Errors
///
/// - [`SenderKeyError::EncryptionFailed`] if AES-256-GCM fails.
/// - [`SenderKeyError::SigningFailed`] if Ed25519 signing fails.
///
/// [`encrypt_sender_layer`]: super::encrypt::encrypt_sender_layer
pub fn seal_broadcast(
    key: &BroadcastKey,
    payload: &[u8],
    params: &SealBroadcastParams<'_>,
) -> Result<BroadcastEnvelope, SenderKeyError> {
    let cipher = Aes256Gcm::new_from_slice(key.key.as_bytes())
        .map_err(|e| SenderKeyError::EncryptionFailed(e.to_string()))?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let aad = build_broadcast_aad(&key.author_did, key.epoch);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: payload,
                aad: &aad,
            },
        )
        .map_err(|e| SenderKeyError::EncryptionFailed(e.to_string()))?;

    let mut encrypted_content = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    encrypted_content.extend_from_slice(&nonce_bytes);
    encrypted_content.extend_from_slice(&ciphertext);

    // Sign over canonical field concatenation.
    let signing_payload = build_signing_payload(
        params.context_id,
        &key.author_did,
        params.sequence,
        params.timestamp,
        key.epoch,
    );
    let signature = params
        .signing_key
        .try_sign(&signing_payload)
        .map_err(|e| SenderKeyError::SigningFailed(e.to_string()))?;

    Ok(BroadcastEnvelope {
        context_id: params.context_id.to_owned(),
        author_did: key.author_did.clone(),
        sequence: params.sequence,
        timestamp: params.timestamp,
        key_epoch: key.epoch,
        provenance: params.provenance.clone(),
        signature: signature.to_bytes(),
        encrypted_content,
    })
}

/// Internal: decrypts a `BroadcastEnvelope` without signature verification.
///
/// Used by both [`open_broadcast`] (after signature check) and
/// [`open_broadcast_trusted`] (for projection layer which already holds
/// the decryption key).
fn decrypt_envelope(
    key: &BroadcastKey,
    envelope: &BroadcastEnvelope,
) -> Result<Vec<u8>, SenderKeyError> {
    if key.epoch != envelope.key_epoch {
        return Err(SenderKeyError::EpochMismatch {
            expected: key.epoch,
            actual: envelope.key_epoch,
        });
    }

    if envelope.encrypted_content.len() < NONCE_SIZE {
        return Err(SenderKeyError::CiphertextTooShort {
            actual: envelope.encrypted_content.len(),
            minimum: NONCE_SIZE,
        });
    }

    let (nonce_bytes, encrypted) = envelope.encrypted_content.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(key.key.as_bytes())
        .map_err(|e| SenderKeyError::EncryptionFailed(e.to_string()))?;

    let aad = build_broadcast_aad(&envelope.author_did, envelope.key_epoch);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: encrypted,
                aad: &aad,
            },
        )
        .map_err(|_| SenderKeyError::AuthenticationFailed)
}

/// Decrypts a [`BroadcastEnvelope`] using the author's broadcast key, with
/// Ed25519 signature verification.
///
/// Verification order (issue #352):
/// 1. Verify Ed25519 signature over canonical metadata BEFORE decryption.
/// 2. Check epoch match.
/// 3. Decrypt AES-256-GCM with AAD binding.
///
/// This ordering rejects forgeries cheaply (signature check is ~10x cheaper
/// than AES-GCM decrypt) and prevents chosen-ciphertext probing.
///
/// # Arguments
///
/// * `key` — The author's broadcast key at the epoch specified in the envelope.
/// * `envelope` — The sealed broadcast envelope to decrypt.
/// * `verifying_key` — The author's Ed25519 verifying key for signature check.
///
/// # Errors
///
/// - [`SenderKeyError::VerificationFailed`] if the Ed25519 signature is invalid.
/// - [`SenderKeyError::EpochMismatch`] if the key epoch does not match the envelope epoch.
/// - [`SenderKeyError::CiphertextTooShort`] if the encrypted content is too short.
/// - [`SenderKeyError::AuthenticationFailed`] if the AEAD tag verification fails
///   (including AAD mismatch from tampered `author_did` or `key_epoch`).
pub fn open_broadcast(
    key: &BroadcastKey,
    envelope: &BroadcastEnvelope,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<Vec<u8>, SenderKeyError> {
    // Step 1: Verify signature BEFORE decryption (issue #352).
    let signing_payload = build_signing_payload(
        &envelope.context_id,
        &envelope.author_did,
        envelope.sequence,
        envelope.timestamp,
        envelope.key_epoch,
    );
    let signature = ed25519_dalek::Signature::from_bytes(&envelope.signature);
    verifying_key
        .verify_strict(&signing_payload, &signature)
        .map_err(|e| {
            SenderKeyError::VerificationFailed(format!("signature verification failed: {e}"))
        })?;

    // Steps 2-3: Epoch check + decrypt.
    decrypt_envelope(key, envelope)
}

/// Decrypts a [`BroadcastEnvelope`] without signature verification.
///
/// This is for trusted contexts where the caller already possesses the
/// decryption key (e.g., the projection layer which holds all broadcast keys
/// for contexts it projects). The AEAD tag still provides integrity over both
/// the ciphertext and the AAD-bound metadata fields.
///
/// **Security note:** Only use when the caller is already trusted (holds the
/// broadcast key). Peer-to-peer consumers MUST use [`open_broadcast`] which
/// verifies the Ed25519 signature before decryption.
///
/// # Errors
///
/// - [`SenderKeyError::EpochMismatch`] if the key epoch does not match the envelope epoch.
/// - [`SenderKeyError::CiphertextTooShort`] if the encrypted content is too short.
/// - [`SenderKeyError::AuthenticationFailed`] if the AEAD tag verification fails.
pub fn open_broadcast_trusted(
    key: &BroadcastKey,
    envelope: &BroadcastEnvelope,
) -> Result<Vec<u8>, SenderKeyError> {
    decrypt_envelope(key, envelope)
}

// ---------------------------------------------------------------------------
// Replay detection
// ---------------------------------------------------------------------------

/// Maximum number of distinct authors tracked by [`BroadcastReplayDetector`].
///
/// When this limit is reached, the entry with the oldest (lowest) timestamp
/// is evicted to make room for the new author. This prevents unbounded memory
/// growth from a flood of distinct author DIDs.
const REPLAY_DETECTOR_MAX_AUTHORS: usize = 10_000;

/// Per-author sequence tracker for broadcast replay detection.
///
/// Maintains the last-seen sequence number per author DID. Messages with
/// `sequence <= last_seen` are rejected as replays (§5.14.5).
///
/// Bounded to [`REPLAY_DETECTOR_MAX_AUTHORS`] entries. When full, the entry
/// with the lowest timestamp is evicted (oldest-first).
#[derive(Debug, Default)]
pub struct BroadcastReplayDetector {
    /// Map of author DID to (last-seen sequence number, last-seen timestamp).
    last_seen: std::collections::HashMap<String, (u64, u64)>,
}

impl BroadcastReplayDetector {
    /// Creates a new empty replay detector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Checks whether a message should be accepted (not a replay).
    ///
    /// Returns `true` and updates the tracker if `sequence > last_seen` for
    /// the given author. Returns `false` if `sequence <= last_seen` (replay).
    ///
    /// When the detector is at capacity and a new author is seen, the entry
    /// with the oldest timestamp is evicted.
    pub fn check_and_advance(&mut self, author_did: &str, sequence: u64, timestamp: u64) -> bool {
        if let Some(entry) = self.last_seen.get_mut(author_did) {
            if sequence > entry.0 {
                *entry = (sequence, timestamp);
                return true;
            }
            return false;
        }

        // New author — evict oldest if at capacity.
        if self.last_seen.len() >= REPLAY_DETECTOR_MAX_AUTHORS {
            if let Some(oldest_key) = self
                .last_seen
                .iter()
                .min_by_key(|(_, (_, ts))| *ts)
                .map(|(k, _)| k.clone())
            {
                self.last_seen.remove(&oldest_key);
            }
        }

        self.last_seen
            .insert(author_did.to_owned(), (sequence, timestamp));
        true
    }

    /// Returns the last-seen sequence for an author, or `None` if never seen.
    #[must_use]
    pub fn last_seen(&self, author_did: &str) -> Option<u64> {
        self.last_seen.get(author_did).map(|(seq, _)| *seq)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Test signing key (deterministic for reproducible tests).
    fn test_signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[0xAA; 32])
    }

    /// Seals a broadcast envelope with test defaults.
    fn test_seal(key: &BroadcastKey, payload: &[u8]) -> BroadcastEnvelope {
        let sk = test_signing_key();
        let params = SealBroadcastParams {
            context_id: "test-ctx",
            sequence: 1,
            timestamp: 1_700_000_000_000,
            provenance: None,
            signing_key: &sk,
        };
        seal_broadcast(key, payload, &params).unwrap()
    }

    /// Opens a broadcast envelope using the trusted (no signature check) path.
    /// Used in tests that focus on AEAD behavior rather than signatures.
    fn test_open(
        key: &BroadcastKey,
        envelope: &BroadcastEnvelope,
    ) -> Result<Vec<u8>, SenderKeyError> {
        open_broadcast_trusted(key, envelope)
    }

    // -----------------------------------------------------------------------
    // Key generation tests
    // -----------------------------------------------------------------------

    #[test]
    fn generate_broadcast_key_produces_32_byte_key() {
        let key = generate_broadcast_key("did:dht:alice");
        assert_eq!(key.key().as_bytes().len(), 32);
    }

    #[test]
    fn generate_broadcast_key_starts_at_epoch_zero() {
        let key = generate_broadcast_key("did:dht:alice");
        assert_eq!(key.epoch(), 0);
    }

    #[test]
    fn generate_broadcast_key_stores_author_did() {
        let key = generate_broadcast_key("did:dht:alice");
        assert_eq!(key.author_did(), "did:dht:alice");
    }

    #[test]
    fn generate_broadcast_key_produces_distinct_keys() {
        let key1 = generate_broadcast_key("did:dht:alice");
        let key2 = generate_broadcast_key("did:dht:alice");
        assert_ne!(key1.key().as_bytes(), key2.key().as_bytes());
    }

    #[test]
    fn broadcast_key_debug_redacts_material() {
        let key = generate_broadcast_key("did:dht:alice");
        let debug = format!("{key:?}");
        assert!(debug.contains("REDACTED"));
        assert!(debug.contains("did:dht:alice"));
        assert!(debug.contains("epoch: 0"));
    }

    // -----------------------------------------------------------------------
    // Key rotation tests
    // -----------------------------------------------------------------------

    #[test]
    fn rotate_broadcast_key_increments_epoch() {
        let key = generate_broadcast_key("did:dht:alice");
        let (rotated, _advance) = rotate_broadcast_key(&key, 1_000_000).unwrap();
        assert_eq!(rotated.epoch(), 1);
    }

    #[test]
    fn rotate_broadcast_key_generates_new_key_material() {
        let key = generate_broadcast_key("did:dht:alice");
        let (rotated, _advance) = rotate_broadcast_key(&key, 1_000_000).unwrap();
        assert_ne!(key.key().as_bytes(), rotated.key().as_bytes());
    }

    #[test]
    fn rotate_broadcast_key_preserves_author_did() {
        let key = generate_broadcast_key("did:dht:alice");
        let (rotated, _advance) = rotate_broadcast_key(&key, 1_000_000).unwrap();
        assert_eq!(rotated.author_did(), "did:dht:alice");
    }

    #[test]
    fn rotate_broadcast_key_emits_epoch_advance_event() {
        let key = generate_broadcast_key("did:dht:alice");
        let (_rotated, advance) = rotate_broadcast_key(&key, 1_000_000).unwrap();
        assert_eq!(advance.author_did, "did:dht:alice");
        assert_eq!(advance.new_epoch, 1);
        assert_eq!(advance.timestamp, 1_000_000);
    }

    #[test]
    fn rotate_broadcast_key_successive_rotations() {
        let key0 = generate_broadcast_key("did:dht:alice");
        let (key1, adv1) = rotate_broadcast_key(&key0, 1_000).unwrap();
        let (key2, adv2) = rotate_broadcast_key(&key1, 2_000).unwrap();
        let (key3, adv3) = rotate_broadcast_key(&key2, 3_000).unwrap();

        assert_eq!(key1.epoch(), 1);
        assert_eq!(key2.epoch(), 2);
        assert_eq!(key3.epoch(), 3);

        assert_eq!(adv1.new_epoch, 1);
        assert_eq!(adv2.new_epoch, 2);
        assert_eq!(adv3.new_epoch, 3);

        assert_ne!(key0.key().as_bytes(), key1.key().as_bytes());
        assert_ne!(key1.key().as_bytes(), key2.key().as_bytes());
        assert_ne!(key2.key().as_bytes(), key3.key().as_bytes());
    }

    #[test]
    fn rotate_broadcast_key_rejects_epoch_overflow() {
        let key = BroadcastKey {
            key: super::super::generate_sender_key(),
            epoch: u64::MAX,
            author_did: "did:dht:alice".to_owned(),
        };
        let result = rotate_broadcast_key(&key, 1_000_000);
        assert!(matches!(result, Err(SenderKeyError::EpochOverflow)));
    }

    // -----------------------------------------------------------------------
    // BroadcastKeyEpochAdvance serialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn epoch_advance_serialization_roundtrip() {
        let advance = BroadcastKeyEpochAdvance {
            author_did: "did:dht:alice".to_owned(),
            new_epoch: 42,
            timestamp: 1_700_000_000_000,
        };
        let json = serde_json::to_string(&advance).unwrap();
        let deserialized: BroadcastKeyEpochAdvance = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, advance);
    }

    #[test]
    fn epoch_advance_msgpack_serialization_roundtrip() {
        let advance = BroadcastKeyEpochAdvance {
            author_did: "did:dht:bob".to_owned(),
            new_epoch: 7,
            timestamp: 1_700_000_000_000,
        };
        let bytes = rmp_serde::to_vec(&advance).unwrap();
        let deserialized: BroadcastKeyEpochAdvance = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(deserialized, advance);
    }

    // -----------------------------------------------------------------------
    // Seal / open roundtrip tests
    // -----------------------------------------------------------------------

    #[test]
    fn seal_open_roundtrip_succeeds() {
        let key = generate_broadcast_key("did:dht:alice");
        let plaintext = b"hello broadcast world";
        let envelope = test_seal(&key, plaintext);

        assert_eq!(envelope.author_did, "did:dht:alice");
        assert_eq!(envelope.key_epoch, 0);

        let decrypted = test_open(&key, &envelope).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn seal_open_empty_payload() {
        let key = generate_broadcast_key("did:dht:alice");
        let envelope = test_seal(&key, b"");
        let decrypted = test_open(&key, &envelope).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn open_with_wrong_epoch_fails() {
        let key0 = generate_broadcast_key("did:dht:alice");
        let envelope = test_seal(&key0, b"secret");

        let (key1, _advance) = rotate_broadcast_key(&key0, 1_000).unwrap();

        let result = test_open(&key1, &envelope);
        assert!(matches!(
            result,
            Err(SenderKeyError::EpochMismatch {
                expected: 1,
                actual: 0
            })
        ));
    }

    #[test]
    fn open_with_wrong_key_fails() {
        let key_alice = generate_broadcast_key("did:dht:alice");
        let key_bob = generate_broadcast_key("did:dht:bob");
        let envelope = test_seal(&key_alice, b"alice only");

        let wrong_key = BroadcastKey {
            key: key_bob.key.clone(),
            epoch: 0,
            author_did: key_alice.author_did.clone(),
        };
        let result = test_open(&wrong_key, &envelope);
        assert!(matches!(result, Err(SenderKeyError::AuthenticationFailed)));
    }

    #[test]
    fn open_with_tampered_ciphertext_fails() {
        let key = generate_broadcast_key("did:dht:alice");
        let mut envelope = test_seal(&key, b"tamper test");

        let tamper_idx = NONCE_SIZE + 1;
        if tamper_idx < envelope.encrypted_content.len() {
            envelope.encrypted_content[tamper_idx] ^= 0xFF;
        }

        let result = test_open(&key, &envelope);
        assert!(matches!(result, Err(SenderKeyError::AuthenticationFailed)));
    }

    #[test]
    fn open_with_too_short_ciphertext_fails() {
        let key = generate_broadcast_key("did:dht:alice");
        let envelope = BroadcastEnvelope {
            context_id: "test-ctx".to_owned(),
            author_did: "did:dht:alice".to_owned(),
            sequence: 1,
            timestamp: 1_700_000_000_000,
            key_epoch: 0,
            provenance: None,
            signature: [0u8; 64],
            encrypted_content: vec![0u8; 5],
        };
        let result = test_open(&key, &envelope);
        assert!(matches!(
            result,
            Err(SenderKeyError::CiphertextTooShort {
                actual: 5,
                minimum: 12
            })
        ));
    }

    #[test]
    fn seal_produces_nonce_plus_ciphertext_plus_tag() {
        let key = generate_broadcast_key("did:dht:alice");
        let plaintext = b"size check";
        let envelope = test_seal(&key, plaintext);
        assert_eq!(
            envelope.encrypted_content.len(),
            NONCE_SIZE + plaintext.len() + 16
        );
    }

    #[test]
    fn seal_open_after_rotation_with_correct_key() {
        let key0 = generate_broadcast_key("did:dht:alice");
        let (key1, _advance) = rotate_broadcast_key(&key0, 1_000).unwrap();

        let sk = test_signing_key();
        let params = SealBroadcastParams {
            context_id: "test-ctx",
            sequence: 1,
            timestamp: 1_700_000_000_000,
            provenance: None,
            signing_key: &sk,
        };
        let envelope = seal_broadcast(&key1, b"post-rotation", &params).unwrap();
        assert_eq!(envelope.key_epoch, 1);

        let decrypted = test_open(&key1, &envelope).unwrap();
        assert_eq!(decrypted, b"post-rotation");
    }

    #[test]
    fn broadcast_envelope_serialization_roundtrip() {
        let key = generate_broadcast_key("did:dht:alice");
        let envelope = test_seal(&key, b"serde test");

        let json = serde_json::to_string(&envelope).unwrap();
        let deserialized: BroadcastEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, envelope);
    }

    // -----------------------------------------------------------------------
    // AAD tampering detection tests (issue #228)
    // -----------------------------------------------------------------------

    #[test]
    fn open_with_tampered_author_did_fails() {
        // Seal with Alice's key, then forge the envelope's author_did to Bob.
        // The AAD mismatch must cause AEAD tag verification to fail.
        let key_alice = generate_broadcast_key("did:dht:alice");
        let mut forged_envelope = test_seal(&key_alice, b"alice's message");

        // Forge: change author_did in the envelope but keep everything else.
        forged_envelope.author_did = "did:dht:bob".to_owned();

        // Open with a key that has the forged author_did (same key material,
        // same epoch) to match the envelope's metadata. The AAD will differ
        // because the DID bytes are different (bob vs alice).
        let forged_key = BroadcastKey {
            key: key_alice.key.clone(),
            epoch: 0,
            author_did: "did:dht:bob".to_owned(),
        };
        let result = test_open(&forged_key, &forged_envelope);
        assert!(
            matches!(result, Err(SenderKeyError::AuthenticationFailed)),
            "tampered author_did must cause AEAD failure, got {result:?}"
        );
    }

    #[test]
    fn open_with_tampered_key_epoch_fails() {
        // Seal at epoch 0, then forge the envelope to claim epoch 5.
        // Create a key at epoch 5 with the same key material.
        // The AAD mismatch must cause AEAD tag verification to fail.
        let key = generate_broadcast_key("did:dht:alice");
        let mut forged_envelope = test_seal(&key, b"epoch zero content");

        // Forge: change key_epoch in the envelope.
        forged_envelope.key_epoch = 5;

        // Create a key with epoch 5 but same key material (simulating an
        // attacker who has the key bytes and wants to replay at a different
        // epoch).
        let forged_key = BroadcastKey {
            key: key.key.clone(),
            epoch: 5,
            author_did: "did:dht:alice".to_owned(),
        };
        let result = test_open(&forged_key, &forged_envelope);
        assert!(
            matches!(result, Err(SenderKeyError::AuthenticationFailed)),
            "tampered key_epoch must cause AEAD failure, got {result:?}"
        );
    }

    #[test]
    fn open_with_both_author_and_epoch_tampered_fails() {
        // Seal as Alice at epoch 0, forge to Bob at epoch 3.
        let key_alice = generate_broadcast_key("did:dht:alice");
        let mut forged_envelope = test_seal(&key_alice, b"double forge test");

        forged_envelope.author_did = "did:dht:mallory".to_owned();
        forged_envelope.key_epoch = 3;

        let forged_key = BroadcastKey {
            key: key_alice.key.clone(),
            epoch: 3,
            author_did: "did:dht:mallory".to_owned(),
        };
        let result = test_open(&forged_key, &forged_envelope);
        assert!(
            matches!(result, Err(SenderKeyError::AuthenticationFailed)),
            "tampered author_did + key_epoch must cause AEAD failure, got {result:?}"
        );
    }

    #[test]
    fn aad_binding_verified_on_build_broadcast_aad() {
        // Verify the AAD construction is deterministic and uses the
        // length-prefixed binary format:
        //   [4-byte DID length (BE)][DID bytes][8-byte epoch (BE)]
        let aad = build_broadcast_aad("did:dht:alice", 42);
        let did_bytes = b"did:dht:alice";
        let mut expected = Vec::new();
        expected.extend_from_slice(&(did_bytes.len() as u32).to_be_bytes());
        expected.extend_from_slice(did_bytes);
        expected.extend_from_slice(&42_u64.to_be_bytes());
        assert_eq!(aad, expected);

        let aad_zero = build_broadcast_aad("did:dht:bob", 0);
        let did_bytes_bob = b"did:dht:bob";
        let mut expected_zero = Vec::new();
        expected_zero.extend_from_slice(&(did_bytes_bob.len() as u32).to_be_bytes());
        expected_zero.extend_from_slice(did_bytes_bob);
        expected_zero.extend_from_slice(&0_u64.to_be_bytes());
        assert_eq!(aad_zero, expected_zero);

        let aad_max = build_broadcast_aad("did:dht:charlie", u64::MAX);
        let did_bytes_charlie = b"did:dht:charlie";
        let mut expected_max = Vec::new();
        expected_max.extend_from_slice(&(did_bytes_charlie.len() as u32).to_be_bytes());
        expected_max.extend_from_slice(did_bytes_charlie);
        expected_max.extend_from_slice(&u64::MAX.to_be_bytes());
        assert_eq!(aad_max, expected_max);
    }

    #[test]
    fn aad_empty_author_did_produces_correct_binary_layout() {
        // Empty DID: 4-byte zero length prefix + no DID bytes + 8-byte epoch.
        let aad = build_broadcast_aad("", 42);
        assert_eq!(
            aad,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 42],
            "empty DID must produce [4-byte zero length][8-byte epoch BE]"
        );
    }

    #[test]
    fn seal_open_roundtrip_with_colons_in_did() {
        // DIDs naturally contain colons (did:web:example.com:path:sub).
        // The length-prefixed binary AAD format must handle this without
        // ambiguity. This was the original bug: colon-delimited string
        // AAD was unparseable for DIDs containing colons.
        let key = generate_broadcast_key("did:web:example.com:path:sub");
        let plaintext = b"colon-heavy DID roundtrip";
        let envelope = test_seal(&key, plaintext);
        let decrypted = test_open(&key, &envelope).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn seal_open_with_signature_verification() {
        // Full roundtrip with Ed25519 signature verification via open_broadcast.
        let key = generate_broadcast_key("did:dht:alice");
        let sk = test_signing_key();
        let vk = sk.verifying_key();
        let params = SealBroadcastParams {
            context_id: "test-ctx",
            sequence: 1,
            timestamp: 1_700_000_000_000,
            provenance: None,
            signing_key: &sk,
        };
        let envelope = seal_broadcast(&key, b"signed message", &params).unwrap();
        let decrypted = open_broadcast(&key, &envelope, &vk).unwrap();
        assert_eq!(decrypted, b"signed message");
    }

    #[test]
    fn open_with_wrong_verifying_key_fails() {
        // Seal with one key, try to verify with a different key.
        let key = generate_broadcast_key("did:dht:alice");
        let envelope = test_seal(&key, b"wrong key test");

        let wrong_signing = ed25519_dalek::SigningKey::from_bytes(&[0xBB; 32]);
        let wrong_verifying = wrong_signing.verifying_key();

        let result = open_broadcast(&key, &envelope, &wrong_verifying);
        assert!(
            matches!(result, Err(SenderKeyError::VerificationFailed(_))),
            "wrong verifying key must fail, got {result:?}"
        );
    }

    #[test]
    fn replay_detector_accepts_increasing_sequences() {
        let mut detector = BroadcastReplayDetector::new();
        assert!(detector.check_and_advance("did:dht:alice", 1, 1000));
        assert!(detector.check_and_advance("did:dht:alice", 2, 2000));
        assert!(detector.check_and_advance("did:dht:alice", 5, 5000));
        assert_eq!(detector.last_seen("did:dht:alice"), Some(5));
    }

    #[test]
    fn replay_detector_rejects_duplicate_and_old_sequences() {
        let mut detector = BroadcastReplayDetector::new();
        assert!(detector.check_and_advance("did:dht:alice", 3, 3000));
        assert!(!detector.check_and_advance("did:dht:alice", 3, 3000)); // duplicate
        assert!(!detector.check_and_advance("did:dht:alice", 1, 1000)); // old
        assert!(detector.check_and_advance("did:dht:alice", 4, 4000)); // new
    }

    #[test]
    fn replay_detector_tracks_authors_independently() {
        let mut detector = BroadcastReplayDetector::new();
        assert!(detector.check_and_advance("did:dht:alice", 1, 1000));
        assert!(detector.check_and_advance("did:dht:bob", 1, 1000));
        assert!(!detector.check_and_advance("did:dht:alice", 1, 1000));
        assert!(detector.check_and_advance("did:dht:bob", 2, 2000));
    }

    #[test]
    fn replay_detector_evicts_oldest_when_full() {
        let mut detector = BroadcastReplayDetector::new();
        // Fill to capacity.
        for i in 0..super::REPLAY_DETECTOR_MAX_AUTHORS {
            assert!(detector.check_and_advance(&format!("did:dht:author-{i}"), 1, i as u64));
        }
        // The oldest entry (timestamp 0 = "did:dht:author-0") should be evicted.
        assert!(detector.check_and_advance("did:dht:new-author", 1, 20_000));
        assert_eq!(detector.last_seen("did:dht:author-0"), None);
        assert_eq!(detector.last_seen("did:dht:new-author"), Some(1));
    }

    // -----------------------------------------------------------------------
    // Deserialization size limit tests (#347)
    // -----------------------------------------------------------------------

    #[test]
    fn oversized_broadcast_envelope_rejected_on_deser() {
        // A BroadcastEnvelope with >512 KiB encrypted_content must be rejected
        // during deserialization to prevent OOM from untrusted input (#347).
        //
        // We construct a valid-shaped envelope with 1 MiB of encrypted_content,
        // serialize it to MessagePack (which is the wire format), then verify
        // that deserialization fails with the bounded-bytes error.
        use crate::serde_util::BOUNDED_BYTES_MAX;

        // Build a helper struct that serializes the same field names but uses
        // raw serde_bytes (no bound) so we can create the oversized payload.
        #[derive(serde::Serialize)]
        struct UnboundedEnvelope {
            author_did: String,
            key_epoch: u64,
            #[serde(with = "serde_bytes")]
            encrypted_content: Vec<u8>,
        }

        let oversized = UnboundedEnvelope {
            author_did: "did:dht:test".to_owned(),
            key_epoch: 0,
            encrypted_content: vec![0xAB; BOUNDED_BYTES_MAX + 1],
        };

        let serialized = rmp_serde::to_vec_named(&oversized).unwrap();
        let result = rmp_serde::from_slice::<BroadcastEnvelope>(&serialized);
        assert!(result.is_err(), "should reject >512 KiB encrypted_content");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("exceeds"),
            "error should mention size limit: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // Property-based tests
    // -----------------------------------------------------------------------

    proptest! {
        #[test]
        #[allow(clippy::unwrap_used)]
        fn seal_open_roundtrip_arbitrary_payload(
            plaintext in proptest::collection::vec(any::<u8>(), 0..2048)
        ) {
            let key = generate_broadcast_key("did:dht:proptest");
            let envelope = test_seal(&key, &plaintext);
            let decrypted = test_open(&key, &envelope).unwrap();
            prop_assert_eq!(plaintext, decrypted);
        }
    }
}
