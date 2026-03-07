//! Content access key layer for SCP (ADR-038, §9.17).
//!
//! Each context member holds an AES-256 access key generated at join time.
//! Content Encryption Keys (CEKs) are wrapped with each intended recipient's
//! access key using AES-256-KW (RFC 3394). Deleting a member's access key
//! makes stored ciphertext undecryptable — cryptographic revocation that
//! the sender-key layer alone cannot provide.
//!
//! # Modules
//!
//! - [`wrapping`] — CEK generation, AES-256-KW wrapping/unwrapping, and the
//!   `WrappedContent` wire format for content encryption.
//!
//! # Key Types
//!
//! - [`AccessKey`] — Per-member AES-256 access key for content decryption.
//! - [`ContentEncryptionKey`] — Ephemeral per-message AES-256 key.
//! - [`WrappedCek`] — A CEK wrapped with a member's access key (40 bytes).
//! - [`WrappedContent`] — Ciphertext + nonce + per-recipient wrapped CEKs.
//! - [`AccessKeyError`] — Error type for access key operations.

pub mod wrapping;

use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ---------------------------------------------------------------------------
// AccessKey
// ---------------------------------------------------------------------------

/// Per-member access key for content decryption in a context.
///
/// Generated at join time, destroyed on revocation. Used to wrap/unwrap
/// Content Encryption Keys (CEKs) via AES-256-KW (RFC 3394).
///
/// See ADR-038 §1 and §9.17.1.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AccessKey {
    /// AES-256 key material (32 bytes).
    key: [u8; 32],
}

impl AccessKey {
    /// Creates an access key from raw 32-byte key material.
    ///
    /// Used when reconstructing a key from HPKE-decrypted bytes during
    /// the access key distribution protocol.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { key: bytes }
    }

    /// Returns a reference to the raw 32-byte key material.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

impl std::fmt::Debug for AccessKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessKey")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

/// Generates a random 32-byte AES-256 access key.
///
/// Uses the platform's cryptographically secure random number generator.
#[must_use]
pub fn generate_access_key() -> AccessKey {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    AccessKey { key: bytes }
}

// ---------------------------------------------------------------------------
// ContentEncryptionKey
// ---------------------------------------------------------------------------

/// Content Encryption Key — ephemeral, per-message.
///
/// Generated fresh for each message, used once for AES-256-GCM content
/// encryption, then discarded after being wrapped for each recipient.
/// See ADR-038 §1 and §9.17.1.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ContentEncryptionKey {
    /// AES-256 key material (32 bytes).
    key: [u8; 32],
}

impl ContentEncryptionKey {
    /// Generates a fresh random 32-byte CEK.
    ///
    /// Uses the platform's cryptographically secure random number generator.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self { key: bytes }
    }

    /// Creates a CEK from raw 32-byte key material.
    ///
    /// Used when unwrapping a CEK from AES-256-KW.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { key: bytes }
    }

    /// Returns a reference to the raw 32-byte key material.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

impl std::fmt::Debug for ContentEncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContentEncryptionKey")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

// ---------------------------------------------------------------------------
// WrappedCek
// ---------------------------------------------------------------------------

/// A CEK wrapped (encrypted) with a member's access key.
///
/// Uses AES-256-KW (RFC 3394). The 32-byte CEK becomes 40 bytes after
/// wrapping (32-byte key + 8-byte integrity check value). See ADR-038 §4
/// and §9.17.3.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedCek {
    /// Truncated SHA-256 of the member's DID (first 8 bytes).
    /// Used as lookup key — prevents DID publication in the wire format.
    #[serde(with = "serde_member_id")]
    pub member_id: [u8; 8],
    /// AES-256-KW wrapped CEK (40 bytes: 32-byte key + 8-byte integrity check).
    #[serde(with = "serde_wrapped_key")]
    pub wrapped_key: [u8; 40],
}

// ---------------------------------------------------------------------------
// WrappedContent
// ---------------------------------------------------------------------------

/// Content with per-member access-key-wrapped CEKs.
///
/// This is the wire format for the access key layer. The `wrapped_ceks` field
/// uses `Vec<WrappedCek>` (not `HashMap`) for deterministic serialization.
/// Integrity is verified by AES-256-GCM's authentication tag — no separate
/// content hash field (storing SHA-256(plaintext) alongside ciphertext would
/// create a plaintext confirmation oracle). See ADR-038 §4 and §9.17.3.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedContent {
    /// AES-256-GCM encrypted content.
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
    /// AES-256-GCM nonce (12 bytes).
    #[serde(with = "serde_nonce")]
    pub nonce: [u8; 12],
    /// Per-recipient wrapped CEKs, ordered by `member_id` for deterministic
    /// serialization. Recipients scan linearly for their `member_id`.
    pub wrapped_ceks: Vec<WrappedCek>,
}

// ---------------------------------------------------------------------------
// AccessKeyError
// ---------------------------------------------------------------------------

/// Errors produced by access key operations.
///
/// Each variant covers a distinct failure mode in the content access key layer.
/// See ADR-038 for the access key design.
#[derive(Debug, thiserror::Error)]
pub enum AccessKeyError {
    /// AES-256-GCM encryption failed.
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),

    /// AES-256-GCM authentication tag verification failed.
    ///
    /// The ciphertext was tampered with, corrupted, or encrypted with a
    /// different key. This covers AEAD tag mismatch (content tampering)
    /// and AAD mismatch (cross-context ciphertext relocation).
    #[error("integrity check failed: AEAD tag verification failure")]
    IntegrityFailure,

    /// AES-256-KW integrity check failed during CEK unwrapping.
    ///
    /// The wrapped CEK was tampered with or the wrong access key was used.
    #[error("key unwrap failed: AES-256-KW integrity check failure")]
    KeyUnwrapFailed,

    /// The recipient's `member_id` was not found in the `wrapped_ceks` list.
    ///
    /// This member is not a recipient of the message — no CEK was wrapped
    /// for them.
    #[error("not a recipient: member_id not found in wrapped_ceks")]
    NotRecipient,

    /// The wrapped key has an invalid length (expected 40 bytes).
    #[error("invalid wrapped key length: expected 40 bytes, got {0}")]
    InvalidWrappedKeyLength(usize),

    /// `MessagePack` serialization or deserialization failed.
    #[error("serialization failed: {0}")]
    SerializationFailed(String),
}

// ---------------------------------------------------------------------------
// Helper: compute_member_id
// ---------------------------------------------------------------------------

/// Computes the `member_id` for a DID: first 8 bytes of SHA-256(`member_did`).
///
/// Used as a truncated hash lookup key in `WrappedContent::wrapped_ceks` to
/// avoid publishing full DIDs in the wire format. Collision probability is
/// negligible for context sizes up to millions of members. See ADR-038 §4.
#[must_use]
pub fn compute_member_id(member_did: &str) -> [u8; 8] {
    let hash = Sha256::digest(member_did.as_bytes());
    let mut id = [0u8; 8];
    id.copy_from_slice(&hash[..8]);
    id
}

// ---------------------------------------------------------------------------
// Serde helpers for fixed-size arrays
// ---------------------------------------------------------------------------

/// Serde helper for `[u8; 8]` (`member_id`).
mod serde_member_id {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    // Serde `with` attribute requires `&T` signature — cannot pass by value.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn serialize<S: Serializer>(data: &[u8; 8], serializer: S) -> Result<S::Ok, S::Error> {
        data.as_slice().serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 8], D::Error> {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        bytes.try_into().map_err(|v: Vec<u8>| {
            serde::de::Error::custom(format!("expected 8 bytes, got {}", v.len()))
        })
    }
}

/// Serde helper for `[u8; 40]` (`wrapped_key`).
mod serde_wrapped_key {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(data: &[u8; 40], serializer: S) -> Result<S::Ok, S::Error> {
        data.as_slice().serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 40], D::Error> {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        bytes.try_into().map_err(|v: Vec<u8>| {
            serde::de::Error::custom(format!("expected 40 bytes, got {}", v.len()))
        })
    }
}

/// Serde helper for `[u8; 12]` (nonce).
mod serde_nonce {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(data: &[u8; 12], serializer: S) -> Result<S::Ok, S::Error> {
        data.as_slice().serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 12], D::Error> {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        bytes.try_into().map_err(|v: Vec<u8>| {
            serde::de::Error::custom(format!("expected 12 bytes, got {}", v.len()))
        })
    }
}

// ---------------------------------------------------------------------------
// Re-exports
// ---------------------------------------------------------------------------

pub use wrapping::{unwrap_cek, unwrap_content, wrap_cek, wrap_content};

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn generate_access_key_produces_32_bytes() {
        let key = generate_access_key();
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn generate_access_key_produces_distinct_keys() {
        let key1 = generate_access_key();
        let key2 = generate_access_key();
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn access_key_debug_redacts_material() {
        let key = generate_access_key();
        let debug = format!("{key:?}");
        assert!(debug.contains("REDACTED"));
        assert!(
            !debug.contains(", "),
            "debug output should not contain raw byte values"
        );
    }

    #[test]
    fn content_encryption_key_generate_produces_32_bytes() {
        let cek = ContentEncryptionKey::generate();
        assert_eq!(cek.as_bytes().len(), 32);
    }

    #[test]
    fn content_encryption_key_generate_produces_distinct_keys() {
        let cek1 = ContentEncryptionKey::generate();
        let cek2 = ContentEncryptionKey::generate();
        assert_ne!(cek1.as_bytes(), cek2.as_bytes());
    }

    #[test]
    fn content_encryption_key_debug_redacts_material() {
        let cek = ContentEncryptionKey::generate();
        let debug = format!("{cek:?}");
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn compute_member_id_produces_8_bytes() {
        let id = compute_member_id("did:dht:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH");
        assert_eq!(id.len(), 8);
    }

    #[test]
    fn compute_member_id_deterministic() {
        let did = "did:dht:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";
        let id1 = compute_member_id(did);
        let id2 = compute_member_id(did);
        assert_eq!(id1, id2);
    }

    #[test]
    fn compute_member_id_distinct_for_different_dids() {
        let id_alice =
            compute_member_id("did:dht:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktA");
        let id_bob = compute_member_id("did:dht:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktB");
        assert_ne!(id_alice, id_bob);
    }

    #[test]
    fn access_key_from_bytes_roundtrip() {
        let key = generate_access_key();
        let bytes = *key.as_bytes();
        let reconstructed = AccessKey::from_bytes(bytes);
        assert_eq!(reconstructed.as_bytes(), key.as_bytes());
    }

    #[test]
    fn content_encryption_key_from_bytes_roundtrip() {
        let cek = ContentEncryptionKey::generate();
        let bytes = *cek.as_bytes();
        let reconstructed = ContentEncryptionKey::from_bytes(bytes);
        assert_eq!(reconstructed.as_bytes(), cek.as_bytes());
    }
}
