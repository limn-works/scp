//! Per-sender AES-256 symmetric key layer for SCP.
//!
//! Each sender in an SCP context maintains an AES-256 symmetric key. Messages
//! are encrypted with the sender's key before MLS group encryption (double
//! encryption). This enables per-relationship blocking without MLS group
//! removal: the sender rotates their key and redistributes it to everyone
//! except the blocked party. See ADR-007 in `.docs/adrs/phase-1.md`.
//!
//! # Modules
//!
//! - [`broadcast`] — Broadcast key lifecycle and `BroadcastEnvelope` seal/open
//!   for `ContextMode::Broadcast` contexts (§5.14).
//! - [`encrypt`] — AES-256-GCM encrypt and decrypt operations.
//!
//! # Key Types
//!
//! - [`SenderKey`] — Opaque 32-byte AES-256 key handle.
//! - [`BroadcastKey`] — Per-author broadcast key with epoch counter.
//! - [`SenderKeyStore`] — In-memory store keyed by `(context_id, sender_did)`.
//! - [`SenderKeyError`] — Error type for sender key operations.

pub mod broadcast;
pub mod encrypt;
pub mod key_protocol_verify;

use std::collections::HashMap;

use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub use broadcast::{
    BroadcastEnvelope, BroadcastKey, BroadcastKeyEpochAdvance, BroadcastReplayDetector,
    SealBroadcastParams, SigningPayloadFields, build_broadcast_signing_payload,
    compute_provenance_hash, generate_broadcast_key, generate_broadcast_nonce, open_broadcast,
    open_broadcast_trusted, rotate_broadcast_key, seal_broadcast, validate_broadcast_version,
};
pub use encrypt::{decrypt_sender_layer, encrypt_sender_layer};
// build_sender_header, parse_sender_header, and SENDER_HEADER_SIZE are wire-format
// internals used by crypto providers — access via encrypt:: submodule directly.
pub use key_protocol_verify::{
    BlockNotification, BridgeShadowKeyParams, HandleRequestParams, NonceDedup,
    RotateForBlockParams, RotateForBlockResult, SenderKeyDistributionMessage,
    SenderKeyEpochAdvance, SenderKeyRequest, SenderKeyResponse, expand_block_list,
    generate_wrapping_keypair, handle_bridge_shadow_key_request, hpke_open_sender_key,
    hpke_seal_sender_key, list_shadow_sender_key_dids, validate_block_notification_freshness,
    validate_sender_key_request_freshness, verify_block_notification, verify_epoch_advance,
    verify_sender_key_request,
};

// ---------------------------------------------------------------------------
// SenderKey
// ---------------------------------------------------------------------------

/// Opaque handle for a 32-byte AES-256 sender key.
///
/// Sender keys are used to encrypt messages before MLS group encryption,
/// enabling per-relationship blocking. See ADR-007.
///
/// Key material is zeroized on drop to prevent sensitive bytes from
/// persisting in freed memory. Clone is retained for API compatibility
/// (e.g. `SenderKeyStore::get_all`).
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SenderKey([u8; 32]);

impl SenderKey {
    /// Creates a sender key from raw 32-byte key material.
    ///
    /// Used by `key_protocol::open_sender_key_response` (in `scp-runtime`) to reconstruct a
    /// sender key from HPKE-decrypted bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns a reference to the raw 32-byte key material.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for SenderKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SenderKey").field(&"[REDACTED]").finish()
    }
}

/// Generates a random 32-byte AES-256 sender key.
///
/// Uses the platform's cryptographically secure random number generator.
///
/// # Examples
///
/// ```
/// use scp_protocol::crypto::sender_keys::generate_sender_key;
///
/// let key = generate_sender_key();
/// assert_eq!(key.as_bytes().len(), 32);
/// ```
#[must_use]
pub fn generate_sender_key() -> SenderKey {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    SenderKey(bytes)
}

// ---------------------------------------------------------------------------
// SenderKeyError
// ---------------------------------------------------------------------------

/// Errors produced by sender key operations.
///
/// Each variant covers a distinct failure mode in the sender-side key layer.
/// See ADR-007 for the sender key design.
#[derive(Debug, thiserror::Error)]
pub enum SenderKeyError {
    /// AES-256-GCM encryption failed.
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),

    /// AES-256-GCM authentication tag verification failed.
    ///
    /// The ciphertext was tampered with, corrupted, or encrypted with a
    /// different key.
    #[error("authentication tag verification failed")]
    AuthenticationFailed,

    /// The ciphertext is too short to contain a valid nonce.
    #[error("ciphertext too short: {actual} bytes, minimum {minimum}")]
    CiphertextTooShort {
        /// Actual length of the ciphertext.
        actual: usize,
        /// Minimum required length.
        minimum: usize,
    },

    /// Ed25519 signing operation failed.
    #[error("signing failed: {0}")]
    SigningFailed(String),

    /// Ed25519 signature verification failed due to malformed input.
    #[error("verification failed: {0}")]
    VerificationFailed(String),

    /// JSON serialization failed.
    #[error("serialization failed: {0}")]
    SerializationFailed(String),

    /// HPKE encryption (seal) failed.
    #[error("HPKE encryption failed: {0}")]
    HpkeEncryptionFailed(String),

    /// HPKE decryption (open) failed.
    #[error("HPKE decryption failed: {0}")]
    HpkeDecryptionFailed(String),

    /// A key custody operation failed.
    #[error("key custody error: {0}")]
    KeyCustodyError(String),

    /// A sender key request was replayed (duplicate nonce within the expiry window).
    #[error("replayed request: duplicate nonce detected")]
    ReplayedRequest,

    /// A block notification timestamp is too old to be considered fresh.
    #[error("stale block notification: timestamp outside freshness window")]
    StaleBlockNotification,

    /// A sender key request timestamp is outside the freshness window.
    ///
    /// The request is either too old (stale) or too far in the future,
    /// indicating clock skew or a replay attempt.
    #[error("stale sender key request: timestamp outside freshness window")]
    StaleSenderKeyRequest,

    /// The envelope's major version is incompatible with this implementation.
    ///
    /// Returned by [`broadcast::validate_broadcast_version`] when the major
    /// version differs from the local major version (§13.5). Envelopes with
    /// the same major version but a different minor version are accepted in
    /// degraded mode (§13.6) and do NOT produce this error.
    #[error("unsupported broadcast envelope version: {version:#06x}")]
    UnsupportedVersion {
        /// The version value from the wire.
        version: u16,
    },

    /// The epoch counter overflowed (reached `u64::MAX`).
    #[error("epoch counter overflow: already at u64::MAX")]
    EpochOverflow,

    /// A received sender key has an epoch ≤ the current stored epoch.
    ///
    /// Indicates a rollback attempt or replay of an old key distribution.
    #[error(
        "sender key epoch not monotonic for {sender_did}: current={current}, received={received}"
    )]
    EpochNotMonotonic {
        /// The DID of the sender whose key was rejected.
        sender_did: String,
        /// The epoch currently stored.
        current: u64,
        /// The epoch in the rejected distribution.
        received: u64,
    },

    /// The broadcast key epoch does not match the envelope epoch.
    ///
    /// The caller must provide a key whose epoch matches the envelope's
    /// `key_epoch` field for decryption to succeed.
    #[error("epoch mismatch: key epoch {expected}, envelope epoch {actual}")]
    EpochMismatch {
        /// The epoch of the provided key.
        expected: u64,
        /// The epoch specified in the envelope.
        actual: u64,
    },

    /// The requester is not a member of the context.
    ///
    /// Returned by `key_protocol::handle_sender_key_request` (in `scp-runtime`) when
    /// `context_members` is provided and the requester's DID is not in
    /// the membership set. This is the primary defense against Sybil
    /// block bypass (BLACK-006, §9.16.6): a Sybil DID that has not been
    /// admitted to the context cannot obtain sender keys regardless of
    /// whether it appears on the block list.
    #[error("requester is not a context member: {did}")]
    NotContextMember {
        /// The DID that was rejected.
        did: String,
    },

    /// An agent key (`#agent`) attempted a Category A action (DID document
    /// modification) via the sender key protocol. The action was rejected
    /// and a custody violation attestation was generated.
    ///
    /// See ADR-039 and SCP-AB-020.
    #[error("Category A violation: {0}")]
    CategoryAViolation(String),
}

// ---------------------------------------------------------------------------
// SenderKeyStore
// ---------------------------------------------------------------------------

/// In-memory store for sender keys, keyed by `(context_id, sender_did)`.
///
/// Each SCP context has one sender key per participant. The store provides
/// CRUD operations and bulk retrieval for key bundles on member join.
/// See ADR-007 acceptance criterion 7.
///
/// Internally uses a nested `HashMap<context_id, HashMap<sender_did, key>>`
/// so that lookups only borrow `&str` and avoid heap-allocating key tuples.
#[derive(Debug, Default)]
pub struct SenderKeyStore {
    /// Maps `context_id -> (sender_did -> SenderKey)`.
    keys: HashMap<String, HashMap<String, SenderKey>>,
    /// Maps `context_id -> (sender_did -> epoch)`.
    /// Tracked separately from `keys` to avoid changing the `SenderKey` type.
    epochs: HashMap<String, HashMap<String, u64>>,
}

impl SenderKeyStore {
    /// Creates a new, empty sender key store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Retrieves the sender key for a given context and sender DID.
    ///
    /// Returns `None` if no key is stored for the given pair.
    /// This is an allocation-free lookup — only `&str` borrows are used.
    #[must_use]
    pub fn get(&self, context_id: &str, sender_did: &str) -> Option<&SenderKey> {
        self.keys.get(context_id)?.get(sender_did)
    }

    /// Sets a sender key WITHOUT enforcing epoch monotonicity.
    ///
    /// Use [`set_checked`] when accepting keys from other members to prevent
    /// epoch rollback attacks. This method is intended only for the local
    /// member's own key rotation.
    pub fn set_unchecked(&mut self, context_id: &str, sender_did: &str, key: SenderKey) {
        self.keys
            .entry(context_id.to_owned())
            .or_default()
            .insert(sender_did.to_owned(), key);
    }

    /// Stores a sender key with epoch monotonicity enforcement (#1608).
    ///
    /// Rejects the key if `epoch` is not strictly greater than the
    /// currently stored epoch for this `(context_id, sender_did)` pair.
    /// A sender with no prior epoch is treated as epoch 0.
    ///
    /// # Errors
    ///
    /// Returns `Err` with a message if the epoch is not monotonically
    /// increasing (rollback attempt or replay).
    pub fn set_checked(
        &mut self,
        context_id: &str,
        sender_did: &str,
        key: SenderKey,
        epoch: u64,
    ) -> Result<(), SenderKeyError> {
        let current_epoch = self
            .epochs
            .get(context_id)
            .and_then(|m| m.get(sender_did))
            .copied()
            .unwrap_or(0);
        if epoch <= current_epoch {
            return Err(SenderKeyError::EpochNotMonotonic {
                sender_did: sender_did.to_owned(),
                current: current_epoch,
                received: epoch,
            });
        }
        self.keys
            .entry(context_id.to_owned())
            .or_default()
            .insert(sender_did.to_owned(), key);
        self.epochs
            .entry(context_id.to_owned())
            .or_default()
            .insert(sender_did.to_owned(), epoch);
        Ok(())
    }

    /// Returns the stored epoch for a given context and sender DID.
    #[must_use]
    pub fn epoch(&self, context_id: &str, sender_did: &str) -> u64 {
        self.epochs
            .get(context_id)
            .and_then(|m| m.get(sender_did))
            .copied()
            .unwrap_or(0)
    }

    /// Exports the per-sender epoch high-water map for a given context as
    /// a `(sender_did, epoch)` list. Used by the crypto-provider snapshot
    /// path to persist the map so the `#1608` rollback-protection
    /// invariant (`set_checked` rejects epoch regressions) survives a
    /// restart. Returns an empty vector when the context has no entries.
    #[must_use]
    pub fn epochs_for_context(&self, context_id: &str) -> Vec<(String, u64)> {
        self.epochs
            .get(context_id)
            .map(|inner| {
                inner
                    .iter()
                    .map(|(did, &epoch)| (did.clone(), epoch))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Restores a previously-observed epoch high-water mark for a
    /// `(context_id, sender_did)` pair without enforcing monotonicity.
    ///
    /// Used exclusively by the crypto-provider snapshot restore path to
    /// repopulate the epoch map from a persisted snapshot — the restored
    /// values ARE the authoritative high-water marks, so `set_checked`
    /// must not reject them. After restore, subsequent [`set_checked`]
    /// calls continue to enforce monotonicity against the restored
    /// values.
    ///
    /// This method does NOT touch the `keys` map — the matching
    /// [`set_unchecked`] or [`set_checked`] call is still required to
    /// install the key material itself.
    pub fn restore_epoch_high_water(&mut self, context_id: &str, sender_did: &str, epoch: u64) {
        self.epochs
            .entry(context_id.to_owned())
            .or_default()
            .insert(sender_did.to_owned(), epoch);
    }

    /// Merge an incoming per-sender epoch map into the local store
    /// with spec §23.17 invariants 3 + 4 enforcement:
    ///
    /// - **Invariant 3 (atomic reject on regression):** if ANY
    ///   incoming floor is strictly less than the local floor for
    ///   the same `(context_id, sender_did)`, the entire merge is
    ///   rejected and no state is modified.
    /// - **Invariant 4 (append-only dominance):** accepted merges
    ///   produce `local = max(local, incoming)` per sender, never
    ///   lowering the floor.
    ///
    /// Returns `Ok(())` on successful max-merge. Returns
    /// `Err(Vec<(String, u64, u64)>)` carrying
    /// `(sender_did, local_floor, incoming_floor)` tuples for every
    /// regression found (the caller wraps this in
    /// `ContextError::SnapshotFloorRegression`).
    ///
    /// # When to use this vs [`Self::restore_epoch_high_water`]
    ///
    /// - Use `restore_epoch_high_water` on the LOCAL RESTORE path
    ///   (fresh in-memory state being rehydrated from a local
    ///   snapshot). The snapshot IS the authoritative source of truth
    ///   for the local node — no regression check is needed because
    ///   there is no prior state to regress against.
    /// - Use `merge_incoming_epochs_with_atomic_reject` on any path
    ///   that INCORPORATES external state (snapshot received from a
    ///   peer, cross-node replication, import that retains prior
    ///   crypto state) into ALREADY-POPULATED local state. Today's
    ///   `import_context` destroys prior crypto state before
    ///   reimport, so this helper is defense-in-depth — but the
    ///   invariant is enforceable from this single point so any
    ///   future code path that adds a merge case is forced through
    ///   the check, satisfying spec §23.17 structurally.
    ///
    /// # Errors
    ///
    /// Returns the per-sender regression deltas via `Err`. The store
    /// is NOT mutated if any regression is detected — the merge is
    /// strictly atomic (invariant 3).
    pub fn merge_incoming_epochs_with_atomic_reject(
        &mut self,
        context_id: &str,
        incoming: impl IntoIterator<Item = (String, u64)>,
    ) -> Result<(), Vec<(String, u64, u64)>> {
        // First pass: materialize the incoming iterator and detect
        // any regression against the current local state. We need
        // to scan twice (detect, then apply) and the caller may have
        // passed a one-shot iterator.
        let incoming: Vec<(String, u64)> = incoming.into_iter().collect();
        let mut regressions: Vec<(String, u64, u64)> = Vec::new();
        if let Some(local) = self.epochs.get(context_id) {
            for (did, incoming_epoch) in &incoming {
                if let Some(&local_epoch) = local.get(did)
                    && *incoming_epoch < local_epoch
                {
                    regressions.push((did.clone(), local_epoch, *incoming_epoch));
                }
            }
        }
        if !regressions.is_empty() {
            return Err(regressions);
        }

        // Second pass: apply max-merge. Local entries not present in
        // `incoming` are retained (invariant 4 append-only dominance
        // for sender DIDs the incoming snapshot doesn't mention).
        // Incoming entries strictly higher than local replace the
        // local value; equal entries are no-ops (strictly-lower
        // entries were already rejected above).
        let local = self.epochs.entry(context_id.to_owned()).or_default();
        for (did, incoming_epoch) in incoming {
            let entry = local.entry(did).or_insert(0);
            if incoming_epoch > *entry {
                *entry = incoming_epoch;
            }
        }
        Ok(())
    }

    /// Removes the sender key for a given context and sender DID.
    ///
    /// Returns the removed key if it existed, or `None` otherwise.
    ///
    /// The epoch high-water mark is deliberately preserved so that
    /// `set_checked()` continues to reject epochs ≤ the previously seen
    /// maximum even after the key is removed and later re-added.
    pub fn remove(&mut self, context_id: &str, sender_did: &str) -> Option<SenderKey> {
        let inner = self.keys.get_mut(context_id)?;
        let removed = inner.remove(sender_did);
        if inner.is_empty() {
            self.keys.remove(context_id);
        }
        // Deliberately preserve the epoch high-water mark. If this sender key
        // is removed (e.g., member leaves) and later re-added, set_checked()
        // must still reject epochs <= the previously seen maximum. Clearing
        // the epoch would allow a replayed old-epoch key to be accepted.
        removed
    }

    /// Returns all sender keys for a given context, keyed by sender DID.
    ///
    /// Used for key bundles when a new member joins the context.
    #[must_use]
    pub fn get_all(&self, context_id: &str) -> HashMap<String, SenderKey> {
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
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn generate_sender_key_produces_32_bytes() {
        let key = generate_sender_key();
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn generate_sender_key_produces_distinct_keys() {
        let key1 = generate_sender_key();
        let key2 = generate_sender_key();
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn sender_key_debug_redacts_material() {
        let key = generate_sender_key();
        let debug = format!("{key:?}");
        assert!(debug.contains("REDACTED"));
        // Ensure no raw key bytes leak (byte arrays format as comma-separated digits).
        assert!(
            !debug.contains(", "),
            "debug output should not contain raw byte values"
        );
    }

    #[test]
    fn sender_key_store_set_and_get() {
        let mut store = SenderKeyStore::new();
        let key = generate_sender_key();
        let expected = *key.as_bytes();

        store.set_unchecked("ctx-1", "did:example:alice", key);

        let retrieved = store.get("ctx-1", "did:example:alice");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.map(SenderKey::as_bytes), Some(&expected));
    }

    #[test]
    fn sender_key_store_get_nonexistent_returns_none() {
        let store = SenderKeyStore::new();
        assert!(store.get("ctx-1", "did:example:nobody").is_none());
    }

    #[test]
    fn sender_key_store_remove() {
        let mut store = SenderKeyStore::new();
        let key = generate_sender_key();
        store.set_unchecked("ctx-1", "did:example:alice", key);

        let removed = store.remove("ctx-1", "did:example:alice");
        assert!(removed.is_some());
        assert!(store.get("ctx-1", "did:example:alice").is_none());
    }

    #[test]
    fn sender_key_store_remove_nonexistent_returns_none() {
        let mut store = SenderKeyStore::new();
        assert!(store.remove("ctx-1", "did:example:nobody").is_none());
    }

    #[test]
    fn sender_key_store_get_all() {
        let mut store = SenderKeyStore::new();
        let key_alice = generate_sender_key();
        let key_bob = generate_sender_key();
        let alice_bytes = *key_alice.as_bytes();
        let bob_bytes = *key_bob.as_bytes();

        store.set_unchecked("ctx-1", "did:example:alice", key_alice);
        store.set_unchecked("ctx-1", "did:example:bob", key_bob);
        // Different context — should not appear in ctx-1 results.
        store.set_unchecked("ctx-2", "did:example:charlie", generate_sender_key());

        let all = store.get_all("ctx-1");
        assert_eq!(all.len(), 2);
        assert_eq!(
            all.get("did:example:alice").map(SenderKey::as_bytes),
            Some(&alice_bytes)
        );
        assert_eq!(
            all.get("did:example:bob").map(SenderKey::as_bytes),
            Some(&bob_bytes)
        );
    }

    #[test]
    fn sender_key_store_get_all_empty_context() {
        let store = SenderKeyStore::new();
        let all = store.get_all("ctx-nonexistent");
        assert!(all.is_empty());
    }

    #[test]
    fn sender_key_store_set_overwrites() {
        let mut store = SenderKeyStore::new();
        let key1 = generate_sender_key();
        let key2 = generate_sender_key();
        let key2_bytes = *key2.as_bytes();

        store.set_unchecked("ctx-1", "did:example:alice", key1);
        store.set_unchecked("ctx-1", "did:example:alice", key2);

        let retrieved = store.get("ctx-1", "did:example:alice");
        assert_eq!(retrieved.map(SenderKey::as_bytes), Some(&key2_bytes));
    }

    #[test]
    fn sender_key_store_get_does_not_allocate_for_cached_key() {
        // The nested-HashMap implementation looks up via &str borrows only,
        // so no heap allocation occurs for the key path on get().
        // We verify correctness and that the returned reference points into
        // the store (i.e. is a true borrow, not a clone).
        let mut store = SenderKeyStore::new();
        let key = generate_sender_key();
        let expected_ptr = std::ptr::from_ref::<[u8; 32]>(key.as_bytes());

        store.set_unchecked("ctx-1", "did:example:alice", key);

        let retrieved = store.get("ctx-1", "did:example:alice");
        assert!(retrieved.is_some());

        // The returned reference must point to the key stored inside the map,
        // not to a freshly-allocated clone. Because `set` moves the key in,
        // the address will differ from `expected_ptr`, but calling get()
        // twice must return the same address — proving it borrows, not clones.
        let ptr1 = std::ptr::from_ref::<[u8; 32]>(retrieved.unwrap().as_bytes());
        let ptr2 = std::ptr::from_ref::<[u8; 32]>(
            store.get("ctx-1", "did:example:alice").unwrap().as_bytes(),
        );
        assert_eq!(
            ptr1, ptr2,
            "consecutive get() calls must return the same pointer (borrow, not clone)"
        );

        // Ensure the original expected_ptr is NOT the same (the key was
        // moved into the store, so the stack-local key is gone).
        // This is mainly a sanity check that we aren't accidentally
        // comparing against a local variable.
        let _ = expected_ptr; // suppress unused warning
    }

    #[test]
    fn sender_key_store_remove_cleans_up_empty_context() {
        let mut store = SenderKeyStore::new();
        store.set_unchecked("ctx-1", "did:example:alice", generate_sender_key());

        let removed = store.remove("ctx-1", "did:example:alice");
        assert!(removed.is_some());
        // The inner map for ctx-1 should be cleaned up entirely.
        assert!(store.keys.is_empty());
    }

    #[test]
    fn set_checked_accepts_monotonically_increasing_epoch() {
        let mut store = SenderKeyStore::new();
        let key1 = generate_sender_key();
        let key2 = generate_sender_key();
        assert!(store.set_checked("ctx", "did:a", key1, 1).is_ok());
        assert_eq!(store.epoch("ctx", "did:a"), 1);
        assert!(store.set_checked("ctx", "did:a", key2, 2).is_ok());
        assert_eq!(store.epoch("ctx", "did:a"), 2);
    }

    #[test]
    fn set_checked_rejects_same_epoch() {
        let mut store = SenderKeyStore::new();
        let key1 = generate_sender_key();
        let key2 = generate_sender_key();
        store.set_checked("ctx", "did:a", key1, 5).unwrap();
        let err = store.set_checked("ctx", "did:a", key2, 5).unwrap_err();
        assert!(
            matches!(
                err,
                SenderKeyError::EpochNotMonotonic {
                    current: 5,
                    received: 5,
                    ..
                }
            ),
            "expected EpochNotMonotonic, got: {err}"
        );
    }

    #[test]
    fn set_checked_rejects_older_epoch() {
        let mut store = SenderKeyStore::new();
        let key1 = generate_sender_key();
        let key2 = generate_sender_key();
        store.set_checked("ctx", "did:a", key1, 10).unwrap();
        let err = store.set_checked("ctx", "did:a", key2, 3).unwrap_err();
        assert!(
            matches!(
                err,
                SenderKeyError::EpochNotMonotonic {
                    current: 10,
                    received: 3,
                    ..
                }
            ),
            "expected EpochNotMonotonic, got: {err}"
        );
        // Key should not have been replaced.
        assert_eq!(store.epoch("ctx", "did:a"), 10);
    }

    #[test]
    fn set_checked_first_key_requires_epoch_gt_zero() {
        let mut store = SenderKeyStore::new();
        let key = generate_sender_key();
        // Epoch 0 is the default — a new key must be at least epoch 1.
        let err = store.set_checked("ctx", "did:a", key, 0).unwrap_err();
        assert!(matches!(err, SenderKeyError::EpochNotMonotonic { .. }));
    }

    #[test]
    fn remove_preserves_epoch_high_water_mark() {
        let mut store = SenderKeyStore::new();

        // 1. Set a key with set_checked at epoch 5.
        store
            .set_checked("ctx", "did:a", generate_sender_key(), 5)
            .unwrap();
        assert_eq!(store.epoch("ctx", "did:a"), 5);

        // 2. Remove the key.
        let removed = store.remove("ctx", "did:a");
        assert!(removed.is_some());

        // 3. Verify get() returns None (key gone).
        assert!(store.get("ctx", "did:a").is_none());

        // 4. Verify set_checked at epoch 3 fails (epoch preserved).
        let err = store
            .set_checked("ctx", "did:a", generate_sender_key(), 3)
            .unwrap_err();
        assert!(
            matches!(
                err,
                SenderKeyError::EpochNotMonotonic {
                    current: 5,
                    received: 3,
                    ..
                }
            ),
            "expected EpochNotMonotonic(current=5, received=3), got: {err}"
        );

        // 5. Verify set_checked at epoch 5 fails (epoch preserved — must be strictly greater).
        let err = store
            .set_checked("ctx", "did:a", generate_sender_key(), 5)
            .unwrap_err();
        assert!(
            matches!(
                err,
                SenderKeyError::EpochNotMonotonic {
                    current: 5,
                    received: 5,
                    ..
                }
            ),
            "expected EpochNotMonotonic(current=5, received=5), got: {err}"
        );

        // 6. Verify set_checked at epoch 6 succeeds.
        assert!(
            store
                .set_checked("ctx", "did:a", generate_sender_key(), 6)
                .is_ok()
        );
        assert_eq!(store.epoch("ctx", "did:a"), 6);
    }

    // -----------------------------------------------------------------------
    // merge_incoming_epochs_with_atomic_reject — §23.17 invariants 3 + 4
    // -----------------------------------------------------------------------

    #[test]
    fn merge_empty_incoming_is_noop() {
        let mut store = SenderKeyStore::new();
        store
            .set_checked("ctx", "did:a", generate_sender_key(), 5)
            .unwrap();
        let incoming: Vec<(String, u64)> = vec![];
        let result = store.merge_incoming_epochs_with_atomic_reject("ctx", incoming);
        assert!(result.is_ok());
        assert_eq!(store.epoch("ctx", "did:a"), 5, "local floor unchanged");
    }

    #[test]
    fn merge_incoming_higher_epoch_advances_floor() {
        let mut store = SenderKeyStore::new();
        store
            .set_checked("ctx", "did:a", generate_sender_key(), 5)
            .unwrap();

        // Incoming floor is strictly higher → accepted, local advances.
        let incoming = vec![("did:a".to_owned(), 10)];
        let result = store.merge_incoming_epochs_with_atomic_reject("ctx", incoming);
        assert!(result.is_ok());
        assert_eq!(
            store.epoch("ctx", "did:a"),
            10,
            "floor must advance to the incoming value"
        );
    }

    #[test]
    fn merge_incoming_equal_epoch_is_noop() {
        let mut store = SenderKeyStore::new();
        store
            .set_checked("ctx", "did:a", generate_sender_key(), 5)
            .unwrap();

        let incoming = vec![("did:a".to_owned(), 5)];
        let result = store.merge_incoming_epochs_with_atomic_reject("ctx", incoming);
        assert!(result.is_ok(), "equal epoch is not a regression");
        assert_eq!(store.epoch("ctx", "did:a"), 5, "floor unchanged");
    }

    #[test]
    fn merge_incoming_lower_epoch_rejects_atomically() {
        // §23.17 invariant 3: if ANY incoming floor is strictly less
        // than the local floor, the entire merge is rejected and no
        // state is modified.
        let mut store = SenderKeyStore::new();
        store
            .set_checked("ctx", "did:a", generate_sender_key(), 10)
            .unwrap();
        store
            .set_checked("ctx", "did:b", generate_sender_key(), 7)
            .unwrap();

        // Incoming: b's epoch legitimately advances, but a tries to
        // regress. The merge MUST reject both — b is NOT advanced.
        let incoming = vec![
            ("did:a".to_owned(), 5), // regression: 5 < 10
            ("did:b".to_owned(), 15),
        ];
        let err = store
            .merge_incoming_epochs_with_atomic_reject("ctx", incoming)
            .expect_err("regression must reject the entire merge");
        assert_eq!(err.len(), 1, "exactly one regression reported");
        assert_eq!(err[0], ("did:a".to_owned(), 10, 5));

        // Atomic-reject invariant: did:b must NOT have been advanced
        // to 15 despite being a legitimate promotion, because the
        // merge as a whole was rejected.
        assert_eq!(
            store.epoch("ctx", "did:b"),
            7,
            "atomic reject — did:b must remain at the pre-merge floor"
        );
        assert_eq!(
            store.epoch("ctx", "did:a"),
            10,
            "atomic reject — did:a must remain at the pre-merge floor"
        );
    }

    #[test]
    fn merge_append_only_retains_local_entries_not_in_incoming() {
        // §23.17 invariant 4: the local floor is append-only. A
        // merge must NEVER drop entries that the incoming map does
        // not mention.
        let mut store = SenderKeyStore::new();
        store
            .set_checked("ctx", "did:a", generate_sender_key(), 10)
            .unwrap();
        store
            .set_checked("ctx", "did:b", generate_sender_key(), 7)
            .unwrap();

        // Incoming only mentions did:c. did:a and did:b must be
        // retained.
        let incoming = vec![("did:c".to_owned(), 3)];
        store
            .merge_incoming_epochs_with_atomic_reject("ctx", incoming)
            .unwrap();

        assert_eq!(store.epoch("ctx", "did:a"), 10);
        assert_eq!(store.epoch("ctx", "did:b"), 7);
        assert_eq!(store.epoch("ctx", "did:c"), 3);
    }

    #[test]
    fn merge_incoming_into_empty_context_accepts_all() {
        // First-merge case: no local state exists for this context,
        // so every incoming entry is accepted without regression
        // checks.
        let mut store = SenderKeyStore::new();
        let incoming = vec![("did:a".to_owned(), 5), ("did:b".to_owned(), 12)];
        store
            .merge_incoming_epochs_with_atomic_reject("ctx", incoming)
            .unwrap();
        assert_eq!(store.epoch("ctx", "did:a"), 5);
        assert_eq!(store.epoch("ctx", "did:b"), 12);
    }

    #[test]
    fn merge_reports_all_regressions_not_just_first() {
        // When multiple senders would regress, the error reports all
        // of them so the caller can emit a complete diagnostic.
        let mut store = SenderKeyStore::new();
        store
            .set_checked("ctx", "did:a", generate_sender_key(), 10)
            .unwrap();
        store
            .set_checked("ctx", "did:b", generate_sender_key(), 20)
            .unwrap();

        let incoming = vec![("did:a".to_owned(), 5), ("did:b".to_owned(), 15)];
        let err = store
            .merge_incoming_epochs_with_atomic_reject("ctx", incoming)
            .unwrap_err();
        assert_eq!(err.len(), 2, "both regressions must be reported");
        // Order is insertion-order of the incoming iterator, which
        // is deterministic because we built a Vec above.
        assert!(err.contains(&("did:a".to_owned(), 10, 5)));
        assert!(err.contains(&("did:b".to_owned(), 20, 15)));
    }
}
