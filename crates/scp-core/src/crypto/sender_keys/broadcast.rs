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

use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
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
/// Contains AES-256-GCM encrypted content along with the metadata needed for
/// decryption and verification. The `encrypted_content` field uses the same
/// wire format as [`encrypt_sender_layer`]: `nonce (12 bytes) || ciphertext || tag (16 bytes)`.
///
/// [`encrypt_sender_layer`]: super::encrypt::encrypt_sender_layer
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BroadcastEnvelope {
    /// The DID of the author who sealed this envelope.
    pub author_did: String,
    /// The broadcast key epoch used to encrypt the content.
    pub key_epoch: u64,
    /// AES-256-GCM encrypted payload: `nonce || ciphertext || auth_tag`.
    #[serde(with = "serde_bytes")]
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
// Seal / Open
// ---------------------------------------------------------------------------

/// Encrypts a payload with the author's broadcast key and packages it into a
/// [`BroadcastEnvelope`].
///
/// Uses AES-256-GCM with a random 12-byte nonce per invocation. The wire
/// format matches [`encrypt_sender_layer`]: `nonce (12 bytes) || ciphertext || auth_tag (16 bytes)`.
///
/// # Arguments
///
/// * `key` — The author's current broadcast key.
/// * `payload` — The plaintext content to encrypt.
///
/// # Errors
///
/// Returns [`SenderKeyError::EncryptionFailed`] if the AES-256-GCM operation fails.
///
/// [`encrypt_sender_layer`]: super::encrypt::encrypt_sender_layer
pub fn seal_broadcast(
    key: &BroadcastKey,
    payload: &[u8],
) -> Result<BroadcastEnvelope, SenderKeyError> {
    let cipher = Aes256Gcm::new_from_slice(key.key.as_bytes())
        .map_err(|e| SenderKeyError::EncryptionFailed(e.to_string()))?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|e| SenderKeyError::EncryptionFailed(e.to_string()))?;

    let mut encrypted_content = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    encrypted_content.extend_from_slice(&nonce_bytes);
    encrypted_content.extend_from_slice(&ciphertext);

    Ok(BroadcastEnvelope {
        author_did: key.author_did.clone(),
        key_epoch: key.epoch,
        encrypted_content,
    })
}

/// Decrypts a [`BroadcastEnvelope`] using the author's broadcast key.
///
/// Verifies that the envelope's `key_epoch` matches the provided key's epoch.
/// If the epochs do not match, returns [`SenderKeyError::EpochMismatch`].
/// Then decrypts the AES-256-GCM ciphertext and verifies the authentication tag.
///
/// # Arguments
///
/// * `key` — The author's broadcast key at the epoch specified in the envelope.
/// * `envelope` — The sealed broadcast envelope to decrypt.
///
/// # Errors
///
/// - [`SenderKeyError::EpochMismatch`] if the key epoch does not match the envelope epoch.
/// - [`SenderKeyError::CiphertextTooShort`] if the encrypted content is too short.
/// - [`SenderKeyError::AuthenticationFailed`] if the AEAD tag verification fails.
pub fn open_broadcast(
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

    cipher
        .decrypt(nonce, encrypted)
        .map_err(|_| SenderKeyError::AuthenticationFailed)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use proptest::prelude::*;

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
        let envelope = seal_broadcast(&key, plaintext).unwrap();

        assert_eq!(envelope.author_did, "did:dht:alice");
        assert_eq!(envelope.key_epoch, 0);

        let decrypted = open_broadcast(&key, &envelope).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn seal_open_empty_payload() {
        let key = generate_broadcast_key("did:dht:alice");
        let envelope = seal_broadcast(&key, b"").unwrap();
        let decrypted = open_broadcast(&key, &envelope).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn open_with_wrong_epoch_fails() {
        let key0 = generate_broadcast_key("did:dht:alice");
        let envelope = seal_broadcast(&key0, b"secret").unwrap();

        let (key1, _advance) = rotate_broadcast_key(&key0, 1_000).unwrap();

        let result = open_broadcast(&key1, &envelope);
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
        let envelope = seal_broadcast(&key_alice, b"alice only").unwrap();

        let forged_envelope = BroadcastEnvelope {
            author_did: envelope.author_did.clone(),
            key_epoch: 0,
            encrypted_content: envelope.encrypted_content.clone(),
        };

        let wrong_key = BroadcastKey {
            key: key_bob.key.clone(),
            epoch: 0,
            author_did: key_alice.author_did.clone(),
        };
        let result = open_broadcast(&wrong_key, &forged_envelope);
        assert!(matches!(result, Err(SenderKeyError::AuthenticationFailed)));
    }

    #[test]
    fn open_with_tampered_ciphertext_fails() {
        let key = generate_broadcast_key("did:dht:alice");
        let mut envelope = seal_broadcast(&key, b"tamper test").unwrap();

        let tamper_idx = NONCE_SIZE + 1;
        if tamper_idx < envelope.encrypted_content.len() {
            envelope.encrypted_content[tamper_idx] ^= 0xFF;
        }

        let result = open_broadcast(&key, &envelope);
        assert!(matches!(result, Err(SenderKeyError::AuthenticationFailed)));
    }

    #[test]
    fn open_with_too_short_ciphertext_fails() {
        let key = generate_broadcast_key("did:dht:alice");
        let envelope = BroadcastEnvelope {
            author_did: "did:dht:alice".to_owned(),
            key_epoch: 0,
            encrypted_content: vec![0u8; 5],
        };
        let result = open_broadcast(&key, &envelope);
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
        let envelope = seal_broadcast(&key, plaintext).unwrap();
        assert_eq!(
            envelope.encrypted_content.len(),
            NONCE_SIZE + plaintext.len() + 16
        );
    }

    #[test]
    fn seal_open_after_rotation_with_correct_key() {
        let key0 = generate_broadcast_key("did:dht:alice");
        let (key1, _advance) = rotate_broadcast_key(&key0, 1_000).unwrap();

        let envelope = seal_broadcast(&key1, b"post-rotation").unwrap();
        assert_eq!(envelope.key_epoch, 1);

        let decrypted = open_broadcast(&key1, &envelope).unwrap();
        assert_eq!(decrypted, b"post-rotation");
    }

    #[test]
    fn broadcast_envelope_serialization_roundtrip() {
        let key = generate_broadcast_key("did:dht:alice");
        let envelope = seal_broadcast(&key, b"serde test").unwrap();

        let json = serde_json::to_string(&envelope).unwrap();
        let deserialized: BroadcastEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, envelope);
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
            let envelope = seal_broadcast(&key, &plaintext).unwrap();
            let decrypted = open_broadcast(&key, &envelope).unwrap();
            prop_assert_eq!(plaintext, decrypted);
        }
    }
}
