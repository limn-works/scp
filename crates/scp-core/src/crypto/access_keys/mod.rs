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
pub mod wrapping;

use std::collections::HashMap;

use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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

    /// AES-256-GCM encryption failed.
    #[error("content encryption failed: {0}")]
    EncryptionFailed(String),

    /// AES-256-GCM authentication tag verification failed.
    #[error("integrity check failed: AEAD tag verification failure")]
    IntegrityFailure,

    /// AES-256-KW integrity check failed during CEK unwrapping.
    #[error("key unwrap failed: AES-256-KW integrity check failure")]
    KeyUnwrapFailed,

    /// The recipient's `member_id` was not found in the `wrapped_ceks` list.
    #[error("not a recipient: member_id not found in wrapped_ceks")]
    NotRecipient,

    /// The wrapped key has an invalid length (expected 40 bytes).
    #[error("invalid wrapped key length: expected 40 bytes, got {0}")]
    InvalidWrappedKeyLength(usize),
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
    key: [u8; 32],
}

impl ContentEncryptionKey {
    /// Generates a fresh random 32-byte CEK.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self { key: bytes }
    }

    /// Creates a CEK from raw 32-byte key material.
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

/// A CEK wrapped with a member's access key via AES-256-KW (RFC 3394).
///
/// The 32-byte CEK becomes 40 bytes after wrapping (32-byte key + 8-byte
/// integrity check value). See ADR-038 §4 and §9.17.3.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedCek {
    /// Truncated SHA-256 of the member's DID (first 8 bytes).
    #[serde(with = "serde_member_id")]
    pub member_id: [u8; 8],
    /// AES-256-KW wrapped CEK (40 bytes).
    #[serde(with = "serde_wrapped_key")]
    pub wrapped_key: [u8; 40],
}

// ---------------------------------------------------------------------------
// WrappedContent
// ---------------------------------------------------------------------------

/// Content with per-member access-key-wrapped CEKs.
///
/// Uses `Vec<WrappedCek>` (not `HashMap`) for deterministic serialization.
/// Integrity verified by AES-256-GCM's authentication tag — no separate
/// content hash. See ADR-038 §4 and §9.17.3.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedContent {
    /// AES-256-GCM encrypted content.
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
    /// AES-256-GCM nonce (12 bytes).
    #[serde(with = "serde_nonce")]
    pub nonce: [u8; 12],
    /// Per-recipient wrapped CEKs.
    pub wrapped_ceks: Vec<WrappedCek>,
}

// ---------------------------------------------------------------------------
// Helper: compute_member_id
// ---------------------------------------------------------------------------

/// Computes the `member_id` for a DID: first 8 bytes of SHA-256(`member_did`).
#[must_use]
pub fn compute_member_id(member_did: &str) -> [u8; 8] {
    let hash = Sha256::digest(member_did.as_bytes());
    let mut id = [0u8; 8];
    id.copy_from_slice(&hash[..8]);
    id
}

// ---------------------------------------------------------------------------
// ContentAccessState — per-member access state (ADR-038, §9.17)
// ---------------------------------------------------------------------------

/// Per-member content access state within a context.
///
/// Represents the four access levels a member can have. Transitions are
/// one-way (decreasing access) until an explicit `RestoreReadAccess` or
/// `RestoreWriteAccess` governance action (§9.17.2 step 5).
///
/// The forward-only restoration guarantee (§9.16.8) means that unblocking
/// grants future access only — historical content encrypted during the
/// block period remains permanently inaccessible because the old access
/// key was destroyed and is never re-distributed.
///
/// See ADR-038, spec §9.17, §9.16.7, §9.16.8.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ContentAccessState {
    /// Full read and write access. The member can decrypt all content
    /// and send new encrypted content. Default state after joining a context.
    Full,

    /// Read-only access. The member can decrypt content but cannot send
    /// new encrypted content. Reached via `RevokeWriteAccess`.
    ReadOnly,

    /// Presence-only. The member is visible in the context but cannot
    /// decrypt content or send. Reached via `RevokeReadAccess` from
    /// `ReadOnly`, or directly via governance.
    PresenceOnly,

    /// Not a member. All keys destroyed, no access. Reached via block
    /// or full revocation.
    NonMember,
}

impl ContentAccessState {
    /// Attempts to transition to a new state. Returns `Ok(new_state)` if
    /// the transition is valid (one-way: decreasing access), or `Err(self)`
    /// if the transition would increase access without a governance Restore
    /// action.
    ///
    /// The ordering is: `Full > ReadOnly > PresenceOnly > NonMember`.
    /// Only transitions to equal or lower access levels are permitted.
    /// Governance restore actions bypass this check via
    /// [`restore_to`](Self::restore_to).
    ///
    /// # Errors
    ///
    /// Returns `Err(current_state)` if the requested transition would
    /// increase the access level.
    pub const fn transition_to(self, target: Self) -> Result<Self, Self> {
        if target.ordinal() >= self.ordinal() {
            Ok(target)
        } else {
            Err(self)
        }
    }

    /// Restores access to a higher level via an explicit governance action.
    ///
    /// This is the ONLY mechanism that can increase the access level.
    /// Forward-only restoration (§9.16.8): the restored member gets a
    /// new access key at a new epoch — historical content from the
    /// revocation period remains inaccessible.
    #[must_use]
    pub const fn restore_to(self, target: Self) -> Self {
        target
    }

    /// Returns the ordinal for ordering comparisons.
    /// Higher ordinal = more restricted access.
    /// Full=0, ReadOnly=1, PresenceOnly=2, NonMember=3.
    const fn ordinal(self) -> u8 {
        match self {
            Self::Full => 0,
            Self::ReadOnly => 1,
            Self::PresenceOnly => 2,
            Self::NonMember => 3,
        }
    }

    /// Returns `true` if the member has read access (can decrypt content).
    #[must_use]
    pub const fn can_read(self) -> bool {
        matches!(self, Self::Full | Self::ReadOnly)
    }

    /// Returns `true` if the member has write access (can send content).
    #[must_use]
    pub const fn can_write(self) -> bool {
        matches!(self, Self::Full)
    }
}

// ---------------------------------------------------------------------------
// AccessKeyStore — in-memory store for per-member access keys
// ---------------------------------------------------------------------------

/// In-memory store for access keys, keyed by `(context_id, member_did)`.
///
/// Each SCP context member holds one access key. The store provides
/// CRUD operations and bulk operations for block-related key destruction.
///
/// Mirrors the structure of [`SenderKeyStore`](crate::crypto::sender_keys::SenderKeyStore)
/// with a nested `HashMap<context_id, HashMap<member_did, AccessKey>>`.
///
/// See ADR-038 §2, spec §9.17.
#[derive(Debug, Default)]
pub struct AccessKeyStore {
    /// Maps `context_id -> (member_did -> AccessKey)`.
    keys: HashMap<String, HashMap<String, AccessKey>>,
}

impl AccessKeyStore {
    /// Creates a new, empty access key store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Retrieves the access key for a given context and member DID.
    ///
    /// Returns `None` if no key is stored for the given pair.
    #[must_use]
    pub fn get(&self, context_id: &str, member_did: &str) -> Option<&AccessKey> {
        self.keys.get(context_id)?.get(member_did)
    }

    /// Stores or updates the access key for a given context and member DID.
    pub fn set(&mut self, context_id: &str, member_did: &str, key: AccessKey) {
        self.keys
            .entry(context_id.to_owned())
            .or_default()
            .insert(member_did.to_owned(), key);
    }

    /// Removes the access key for a given context and member DID.
    ///
    /// Returns the removed key if it existed, or `None` otherwise.
    pub fn remove(&mut self, context_id: &str, member_did: &str) -> Option<AccessKey> {
        let inner = self.keys.get_mut(context_id)?;
        let removed = inner.remove(member_did);
        if inner.is_empty() {
            self.keys.remove(context_id);
        }
        removed
    }

    /// Returns all access keys for a given context, keyed by member DID.
    #[must_use]
    pub fn get_all(&self, context_id: &str) -> HashMap<String, AccessKey> {
        self.keys
            .get(context_id)
            .map(|inner| {
                inner
                    .iter()
                    .map(|(did, key)| (did.clone(), key.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Returns `true` if the store contains a key for the given pair.
    #[must_use]
    pub fn contains(&self, context_id: &str, member_did: &str) -> bool {
        self.keys
            .get(context_id)
            .is_some_and(|inner| inner.contains_key(member_did))
    }
}

// ---------------------------------------------------------------------------
// Serde helpers for fixed-size arrays
// ---------------------------------------------------------------------------

mod serde_member_id {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

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

    // -----------------------------------------------------------------------
    // ContentAccessState tests (SCP-CAC-006 AC-11, AC-12, AC-13)
    // -----------------------------------------------------------------------

    #[test]
    fn content_access_state_default_is_full() {
        let state = ContentAccessState::Full;
        assert!(state.can_read());
        assert!(state.can_write());
    }

    #[test]
    fn content_access_state_read_only_can_read_not_write() {
        let state = ContentAccessState::ReadOnly;
        assert!(state.can_read());
        assert!(!state.can_write());
    }

    #[test]
    fn content_access_state_presence_only_no_access() {
        let state = ContentAccessState::PresenceOnly;
        assert!(!state.can_read());
        assert!(!state.can_write());
    }

    #[test]
    fn content_access_state_non_member_no_access() {
        let state = ContentAccessState::NonMember;
        assert!(!state.can_read());
        assert!(!state.can_write());
    }

    #[test]
    fn content_access_state_transition_full_to_read_only() {
        let state = ContentAccessState::Full;
        let result = state.transition_to(ContentAccessState::ReadOnly);
        assert_eq!(result, Ok(ContentAccessState::ReadOnly));
    }

    #[test]
    fn content_access_state_transition_full_to_presence_only() {
        let state = ContentAccessState::Full;
        let result = state.transition_to(ContentAccessState::PresenceOnly);
        assert_eq!(result, Ok(ContentAccessState::PresenceOnly));
    }

    #[test]
    fn content_access_state_transition_full_to_non_member() {
        let state = ContentAccessState::Full;
        let result = state.transition_to(ContentAccessState::NonMember);
        assert_eq!(result, Ok(ContentAccessState::NonMember));
    }

    #[test]
    fn content_access_state_transition_read_only_to_presence_only() {
        let state = ContentAccessState::ReadOnly;
        let result = state.transition_to(ContentAccessState::PresenceOnly);
        assert_eq!(result, Ok(ContentAccessState::PresenceOnly));
    }

    #[test]
    fn content_access_state_transition_read_only_to_non_member() {
        let state = ContentAccessState::ReadOnly;
        let result = state.transition_to(ContentAccessState::NonMember);
        assert_eq!(result, Ok(ContentAccessState::NonMember));
    }

    #[test]
    fn content_access_state_transition_same_state_is_ok() {
        let state = ContentAccessState::ReadOnly;
        let result = state.transition_to(ContentAccessState::ReadOnly);
        assert_eq!(result, Ok(ContentAccessState::ReadOnly));
    }

    #[test]
    fn content_access_state_cannot_increase_access() {
        // ReadOnly -> Full is forbidden.
        let state = ContentAccessState::ReadOnly;
        let result = state.transition_to(ContentAccessState::Full);
        assert_eq!(result, Err(ContentAccessState::ReadOnly));

        // PresenceOnly -> ReadOnly is forbidden.
        let state = ContentAccessState::PresenceOnly;
        let result = state.transition_to(ContentAccessState::ReadOnly);
        assert_eq!(result, Err(ContentAccessState::PresenceOnly));

        // NonMember -> Full is forbidden.
        let state = ContentAccessState::NonMember;
        let result = state.transition_to(ContentAccessState::Full);
        assert_eq!(result, Err(ContentAccessState::NonMember));
    }

    #[test]
    fn content_access_state_restore_bypasses_one_way_constraint() {
        let state = ContentAccessState::NonMember;
        let restored = state.restore_to(ContentAccessState::Full);
        assert_eq!(restored, ContentAccessState::Full);

        let state = ContentAccessState::PresenceOnly;
        let restored = state.restore_to(ContentAccessState::ReadOnly);
        assert_eq!(restored, ContentAccessState::ReadOnly);
    }

    #[test]
    fn content_access_state_serialization_roundtrip() {
        for state in [
            ContentAccessState::Full,
            ContentAccessState::ReadOnly,
            ContentAccessState::PresenceOnly,
            ContentAccessState::NonMember,
        ] {
            let bytes = rmp_serde::to_vec(&state).unwrap();
            let decoded: ContentAccessState = rmp_serde::from_slice(&bytes).unwrap();
            assert_eq!(decoded, state);
        }
    }

    // -----------------------------------------------------------------------
    // AccessKeyStore tests
    // -----------------------------------------------------------------------

    #[test]
    fn access_key_store_set_and_get() {
        let mut store = AccessKeyStore::new();
        let key = generate_access_key("ctx-1", "did:dht:alice");
        let expected = *key.as_bytes();
        store.set("ctx-1", "did:dht:alice", key);
        let retrieved = store.get("ctx-1", "did:dht:alice");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().as_bytes(), &expected);
    }

    #[test]
    fn access_key_store_get_nonexistent() {
        let store = AccessKeyStore::new();
        assert!(store.get("ctx-1", "did:dht:nobody").is_none());
    }

    #[test]
    fn access_key_store_remove() {
        let mut store = AccessKeyStore::new();
        let key = generate_access_key("ctx-1", "did:dht:alice");
        store.set("ctx-1", "did:dht:alice", key);
        let removed = store.remove("ctx-1", "did:dht:alice");
        assert!(removed.is_some());
        assert!(store.get("ctx-1", "did:dht:alice").is_none());
    }

    #[test]
    fn access_key_store_remove_cleans_empty_context() {
        let mut store = AccessKeyStore::new();
        store.set(
            "ctx-1",
            "did:dht:alice",
            generate_access_key("ctx-1", "did:dht:alice"),
        );
        store.remove("ctx-1", "did:dht:alice");
        assert!(store.keys.is_empty());
    }

    #[test]
    fn access_key_store_contains() {
        let mut store = AccessKeyStore::new();
        assert!(!store.contains("ctx-1", "did:dht:alice"));
        store.set(
            "ctx-1",
            "did:dht:alice",
            generate_access_key("ctx-1", "did:dht:alice"),
        );
        assert!(store.contains("ctx-1", "did:dht:alice"));
        assert!(!store.contains("ctx-1", "did:dht:bob"));
    }

    #[test]
    fn access_key_store_get_all() {
        let mut store = AccessKeyStore::new();
        store.set(
            "ctx-1",
            "did:dht:alice",
            generate_access_key("ctx-1", "did:dht:alice"),
        );
        store.set(
            "ctx-1",
            "did:dht:bob",
            generate_access_key("ctx-1", "did:dht:bob"),
        );
        store.set(
            "ctx-2",
            "did:dht:charlie",
            generate_access_key("ctx-2", "did:dht:charlie"),
        );
        let all = store.get_all("ctx-1");
        assert_eq!(all.len(), 2);
        assert!(all.contains_key("did:dht:alice"));
        assert!(all.contains_key("did:dht:bob"));
    }

    #[test]
    fn access_key_store_get_all_empty_context() {
        let store = AccessKeyStore::new();
        let all = store.get_all("ctx-nonexistent");
        assert!(all.is_empty());
    }

    #[test]
    fn access_key_store_set_overwrites() {
        let mut store = AccessKeyStore::new();
        let key1 = generate_access_key("ctx-1", "did:dht:alice");
        let key2 = generate_access_key("ctx-1", "did:dht:alice");
        let key2_bytes = *key2.as_bytes();
        store.set("ctx-1", "did:dht:alice", key1);
        store.set("ctx-1", "did:dht:alice", key2);
        assert_eq!(
            store.get("ctx-1", "did:dht:alice").unwrap().as_bytes(),
            &key2_bytes
        );
    }
}
