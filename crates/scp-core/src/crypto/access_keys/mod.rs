//! Per-member access key lifecycle for SCP content access control.
//!
//! Each member in an SCP context holds a per-member AES-256 access key
//! generated at join time. Access keys are used to wrap Content Encryption
//! Keys (CEKs) so that revoking a member's access key makes stored content
//! undecryptable — retroactive revocation that the sender key layer alone
//! cannot achieve.
//!
//! Access keys are distributed via the same pull-based HPKE protocol as
//! sender keys (§9.16.2), but with a distinct domain separator
//! (`"scp-access-key-v1"`) to prevent cross-protocol key confusion.
//!
//! See ADR-038 §2 in `.docs/adrs/phase-6.md` and spec §9.17.
//!
//! # Modules
//!
//! - [`lifecycle`] — Key generation, rotation, revocation, and epoch management.
//! - [`wire`] — Wire types for access key request/response protocol.

pub mod lifecycle;
pub mod wire;

use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ---------------------------------------------------------------------------
// AccessKey
// ---------------------------------------------------------------------------

/// Per-member AES-256 access key with context binding and epoch counter.
///
/// Each member in a context holds one access key. The key material is a
/// random 32-byte AES-256 key used to wrap/unwrap Content Encryption Keys
/// (CEKs) via AES-256-KW (RFC 3394). The epoch is a monotonic counter
/// incremented on revocation+restoration or context-wide rotation.
///
/// Key material is zeroized on drop to prevent sensitive bytes from
/// persisting in freed memory.
///
/// See spec §9.17.1 and ADR-038 §2.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct AccessKey {
    /// 32-byte AES-256 key material.
    key: [u8; 32],
    /// The context this access key belongs to.
    context_id: String,
    /// The DID of the member who owns this access key.
    member_did: String,
    /// Monotonic epoch counter. Starts at 0, increments on each rotation
    /// (revocation+restoration or context-wide rotation).
    epoch: u64,
}

impl AccessKey {
    /// Constructs an `AccessKey` from its component parts.
    ///
    /// Used by [`wire::open_access_key_response`] to reconstruct an access
    /// key from HPKE-decrypted bytes and metadata.
    #[must_use]
    pub const fn from_parts(
        key: [u8; 32],
        context_id: String,
        member_did: String,
        epoch: u64,
    ) -> Self {
        Self {
            key,
            context_id,
            member_did,
            epoch,
        }
    }

    /// Returns a reference to the raw 32-byte key material.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    /// Returns the context ID this access key belongs to.
    #[must_use]
    pub fn context_id(&self) -> &str {
        &self.context_id
    }

    /// Returns the DID of the member who owns this access key.
    #[must_use]
    pub fn member_did(&self) -> &str {
        &self.member_did
    }

    /// Returns the current epoch of this access key.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }
}

impl std::fmt::Debug for AccessKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessKey")
            .field("key", &"[REDACTED]")
            .field("context_id", &self.context_id)
            .field("member_did", &self.member_did)
            .field("epoch", &self.epoch)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// AccessKeyError
// ---------------------------------------------------------------------------

/// Errors produced by access key operations.
///
/// Each variant covers a distinct failure mode in the content access key
/// layer. See ADR-038 and spec §9.17.
#[derive(Debug, thiserror::Error)]
pub enum AccessKeyError {
    /// HPKE encryption (seal) failed.
    #[error("HPKE encryption failed: {0}")]
    HpkeEncryptionFailed(String),

    /// HPKE decryption (open) failed.
    #[error("HPKE decryption failed: {0}")]
    HpkeDecryptionFailed(String),

    /// Ed25519 signature verification failed due to malformed input.
    #[error("verification failed: {0}")]
    VerificationFailed(String),

    /// Ed25519 signing operation failed.
    #[error("signing failed: {0}")]
    SigningFailed(String),

    /// JSON serialization failed.
    #[error("serialization failed: {0}")]
    SerializationFailed(String),

    /// A key custody operation failed.
    #[error("key custody error: {0}")]
    KeyCustodyError(String),

    /// The epoch counter overflowed (reached `u64::MAX`).
    #[error("epoch counter overflow: already at u64::MAX")]
    EpochOverflow,

    /// The access key request timestamp is too old (replay protection).
    #[error("stale access key request: timestamp outside freshness window")]
    StaleRequest,

    /// The system clock is unavailable or before the Unix epoch.
    #[error("clock error: {0}")]
    ClockError(#[from] crate::time::ClockError),
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

/// Generates a new per-member access key at epoch 0.
///
/// Creates a fresh random 32-byte AES-256 key using the platform's
/// cryptographically secure RNG. Called when a member joins a context
/// (triggered by `AddMember` governance action execution) per §9.17.2
/// step 1.
///
/// # Arguments
///
/// * `context_id` — The context this access key belongs to.
/// * `member_did` — The DID of the member who will own this access key.
#[must_use]
pub fn generate_access_key(context_id: &str, member_did: &str) -> AccessKey {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    AccessKey {
        key,
        context_id: context_id.to_owned(),
        member_did: member_did.to_owned(),
        epoch: 0,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn generate_access_key_produces_32_bytes() {
        let key = generate_access_key("ctx-1", "did:dht:alice");
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn generate_access_key_starts_at_epoch_zero() {
        let key = generate_access_key("ctx-1", "did:dht:alice");
        assert_eq!(key.epoch(), 0);
    }

    #[test]
    fn generate_access_key_stores_context_id() {
        let key = generate_access_key("ctx-1", "did:dht:alice");
        assert_eq!(key.context_id(), "ctx-1");
    }

    #[test]
    fn generate_access_key_stores_member_did() {
        let key = generate_access_key("ctx-1", "did:dht:alice");
        assert_eq!(key.member_did(), "did:dht:alice");
    }

    #[test]
    fn generate_access_key_produces_distinct_keys() {
        let key1 = generate_access_key("ctx-1", "did:dht:alice");
        let key2 = generate_access_key("ctx-1", "did:dht:alice");
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn access_key_debug_redacts_material() {
        let key = generate_access_key("ctx-1", "did:dht:alice");
        let debug = format!("{key:?}");
        assert!(debug.contains("REDACTED"));
        assert!(debug.contains("ctx-1"));
        assert!(debug.contains("did:dht:alice"));
        assert!(debug.contains("epoch: 0"));
        // Ensure no raw key bytes leak. The key field shows "[REDACTED]",
        // not a 32-element array with comma-separated digits like "0, 0, 0".
        assert!(
            !debug.contains("[0, "),
            "debug output should not contain raw byte values"
        );
    }

    #[test]
    fn access_key_from_parts_roundtrip() {
        let key_bytes = [42u8; 32];
        let key = AccessKey::from_parts(
            key_bytes,
            "ctx-test".to_owned(),
            "did:dht:bob".to_owned(),
            5,
        );
        assert_eq!(key.as_bytes(), &key_bytes);
        assert_eq!(key.context_id(), "ctx-test");
        assert_eq!(key.member_did(), "did:dht:bob");
        assert_eq!(key.epoch(), 5);
    }

    #[test]
    fn access_key_serialization_roundtrip() {
        let key = generate_access_key("ctx-1", "did:dht:alice");
        let bytes = rmp_serde::to_vec(&key).unwrap();
        let deserialized: AccessKey = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(deserialized.as_bytes(), key.as_bytes());
        assert_eq!(deserialized.context_id(), key.context_id());
        assert_eq!(deserialized.member_did(), key.member_did());
        assert_eq!(deserialized.epoch(), key.epoch());
    }
}
