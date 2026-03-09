//! Access key lifecycle operations: revocation, restoration, context-wide
//! rotation, and SDK-mandated state destruction on block events.
//!
//! These operations manage the full lifecycle of per-member access keys
//! beyond initial generation (which is in the parent module). Revocation
//! deletes the access key and increments epoch. Restoration generates a
//! new key at the incremented epoch. Context-wide rotation generates new
//! keys for all members while retaining old keys for historical access.
//!
//! The block event handlers implement Layer 2 (SDK-mandated state
//! destruction, §9.16.7) and Layer 3 (access key deletion, §9.17) for
//! both the blocker and blocked party sides. All destruction is
//! synchronous — no background tasks — per §9.16.7 timing requirement.
//!
//! See spec §9.17.2 (steps 3-6), §9.16.7, §9.16.8, and ADR-038 §2.

use super::{AccessKey, AccessKeyError, AccessKeyStore, ContentAccessState, generate_access_key};
use crate::crypto::sender_keys::{BlockNotification, SenderKeyStore, verify_block_notification};

// ---------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------

/// Result of revoking a member's access key.
///
/// Contains the new epoch after revocation. The access key itself is
/// deleted — the caller must remove it from the `ProtocolStore` and
/// notify other members.
///
/// See spec §9.17.2 step 3 and §9.17.5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationResult {
    /// The member whose access key was revoked.
    pub member_did: String,
    /// The context the revocation applies to.
    pub context_id: String,
    /// The epoch counter after revocation (incremented from the revoked
    /// key's epoch). A new key generated on restoration will use this epoch.
    pub new_epoch: u64,
}

/// Revokes a member's access key: computes the next epoch and signals
/// deletion.
///
/// The caller is responsible for:
/// 1. Deleting the access key from `ProtocolStore`.
/// 2. Broadcasting an `AccessKeyRevoked` event to all context members.
/// 3. Each member's SDK purging the target's access key from their key store.
///
/// See spec §9.17.2 step 3 and §9.17.5.
///
/// # Errors
///
/// Returns [`AccessKeyError::EpochOverflow`] if the epoch counter is at
/// `u64::MAX` and cannot be incremented.
pub fn revoke_access_key(current_key: &AccessKey) -> Result<RevocationResult, AccessKeyError> {
    let new_epoch = current_key
        .epoch
        .checked_add(1)
        .ok_or(AccessKeyError::EpochOverflow)?;

    Ok(RevocationResult {
        member_did: current_key.member_did().to_owned(),
        context_id: current_key.context_id().to_owned(),
        new_epoch,
    })
}

// ---------------------------------------------------------------------------
// Restoration
// ---------------------------------------------------------------------------

/// Restores access for a previously revoked member by generating a new
/// access key at the given epoch.
///
/// The new key is used for future CEK wrapping only. Historical wrapped
/// CEKs used the old (deleted) access key — they are permanently
/// inaccessible. This enforces the forward-only restoration guarantee.
///
/// See spec §9.17.2 step 5.
///
/// # Arguments
///
/// * `context_id` — The context to restore access in.
/// * `member_did` — The DID of the member to restore.
/// * `epoch` — The epoch for the new key (from [`RevocationResult::new_epoch`]).
#[must_use]
pub fn restore_access_key(context_id: &str, member_did: &str, epoch: u64) -> AccessKey {
    let mut key = generate_access_key(context_id, member_did);
    key.epoch = epoch;
    key
}

// ---------------------------------------------------------------------------
// Context-wide rotation
// ---------------------------------------------------------------------------

/// Result of a context-wide access key rotation.
///
/// Contains all newly generated access keys for the context members.
/// Old keys are NOT included — the caller is responsible for retaining
/// old keys locally for historical message decryption.
///
/// See spec §9.17.2 step 6.
#[derive(Debug)]
pub struct RotationResult {
    /// Newly generated access keys for all members.
    pub new_keys: Vec<AccessKey>,
    /// The new epoch applied to all rotated keys.
    pub new_epoch: u64,
}

/// Rotates access keys for all members in a context.
///
/// Generates a new access key for each member at `current_epoch + 1`.
/// The caller is responsible for:
/// 1. Retaining old keys locally for historical message decryption.
/// 2. Distributing new keys to each member via the HPKE protocol.
/// 3. Using new keys for future CEK wrapping.
///
/// See spec §9.17.2 step 6.
///
/// # Arguments
///
/// * `context_id` — The context to rotate keys for.
/// * `member_dids` — The DIDs of all current members.
/// * `current_epoch` — The current epoch before rotation.
///
/// # Errors
///
/// Returns [`AccessKeyError::EpochOverflow`] if the epoch counter is at
/// `u64::MAX` and cannot be incremented.
pub fn rotate_all_access_keys(
    context_id: &str,
    member_dids: &[&str],
    current_epoch: u64,
) -> Result<RotationResult, AccessKeyError> {
    let new_epoch = current_epoch
        .checked_add(1)
        .ok_or(AccessKeyError::EpochOverflow)?;

    let new_keys = member_dids
        .iter()
        .map(|did| restore_access_key(context_id, did, new_epoch))
        .collect();

    Ok(RotationResult {
        new_keys,
        new_epoch,
    })
}

// ---------------------------------------------------------------------------
// SDK-mandated state destruction on block event (§9.16.7)
// ---------------------------------------------------------------------------

/// Result of handling a verified block notification on the blocked party's
/// side (Layer 2 + Layer 3 destruction).
///
/// Returned by [`handle_block_as_blocked_party`]. The caller uses this to
/// confirm what was destroyed.
///
/// See spec §9.16.7.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockDestructionResult {
    /// The context where destruction occurred.
    pub context_id: String,
    /// The DID of the blocker whose material was destroyed.
    pub blocker_did: String,
    /// Number of sender key epochs deleted from the blocker.
    pub sender_keys_deleted: usize,
    /// Whether the blocker's access key was deleted from local store.
    pub access_key_deleted: bool,
    /// Number of cached plaintext entries purged (tracked externally;
    /// set to 0 here — the caller is responsible for purging application-
    /// layer caches and reporting the count).
    pub plaintext_entries_purged: usize,
}

/// Handles a received block notification on the blocked party's side.
///
/// **Verification first (§9.16.3 step 6):** The block notification
/// signature is verified against the blocker's Active Signing Key (or
/// Agent Signing Key). If verification fails, the notification is
/// discarded and this function returns `None` — no destruction occurs.
/// The caller SHOULD log the anomaly for detection.
///
/// **On valid notification (§9.16.7):**
/// 1. Deletes all sender key epochs from the blocker in this context.
/// 2. Signals that cached plaintext from the blocker must be purged
///    (the caller handles application-layer cache purging).
/// 3. Deletes the blocker's access key from the local store.
///
/// **Timing (§9.16.7):** This function is synchronous. Destruction MUST
/// complete before the SDK processes subsequent messages. The caller
/// MUST NOT process any further messages until this returns.
///
/// # Arguments
///
/// * `notification` — The deserialized [`BlockNotification`] received
///   from the MLS application message.
/// * `context_id` — The context where the block applies.
/// * `blocker_public_key` — The blocker's Active Signing Key or Agent
///   Signing Key bytes (32-byte Ed25519 verifying key) from their DID
///   document.
/// * `sender_key_store` — The blocked party's sender key store (mutated
///   to remove the blocker's keys).
/// * `access_key_store` — The blocked party's access key store (mutated
///   to remove the blocker's access key).
///
/// # Returns
///
/// `Some(BlockDestructionResult)` if the notification was valid and
/// destruction occurred. `None` if the signature was invalid (discard +
/// anomaly log).
pub fn handle_block_as_blocked_party(
    notification: &BlockNotification,
    context_id: &str,
    blocker_public_key: &[u8],
    sender_key_store: &mut SenderKeyStore,
    access_key_store: &mut AccessKeyStore,
) -> Option<BlockDestructionResult> {
    // Step 1: Verify the block notification signature.
    let valid =
        verify_block_notification(notification, context_id, blocker_public_key).unwrap_or(false);
    if !valid {
        // Invalid signature — discard. Caller should log anomaly.
        return None;
    }

    let blocker_did = &notification.blocker;

    // Step 2: Delete all sender key epochs from the blocker (Layer 2, item 1).
    // SenderKeyStore stores one key per (context_id, sender_did) — remove it.
    let sender_keys_deleted =
        usize::from(sender_key_store.remove(context_id, blocker_did).is_some());

    // Step 3: Delete the blocker's access key from local store (Layer 3).
    let access_key_deleted = access_key_store.remove(context_id, blocker_did).is_some();

    // Step 4: Cached plaintext purging is the caller's responsibility
    // (application-layer caches — message databases, search indices).
    // We report 0 here; the caller tracks their own purge count.

    Some(BlockDestructionResult {
        context_id: context_id.to_owned(),
        blocker_did: blocker_did.to_owned(),
        sender_keys_deleted,
        access_key_deleted,
        plaintext_entries_purged: 0,
    })
}

/// Handles the blocker's side of access key deletion on block initiation.
///
/// When Alice blocks Dave, Alice's SDK deletes Dave's access key from
/// her local access key store (Layer 3, §9.17). This prevents Alice from
/// wrapping future CEKs for Dave.
///
/// # Arguments
///
/// * `access_key_store` — The blocker's access key store (mutated to
///   remove the target's key).
/// * `context_id` — The context where the block applies.
/// * `target_did` — The DID of the member being blocked.
///
/// # Returns
///
/// `true` if the target's access key was found and deleted, `false` if
/// no key existed.
pub fn handle_block_as_blocker(
    access_key_store: &mut AccessKeyStore,
    context_id: &str,
    target_did: &str,
) -> bool {
    access_key_store.remove(context_id, target_did).is_some()
}

// ---------------------------------------------------------------------------
// ContentAccessState transition helpers (§9.17, ADR-038)
// ---------------------------------------------------------------------------

/// Result of a `RevokeReadAccess` governance action on the content access
/// key layer.
///
/// Contains metadata about what was destroyed so the caller can log and
/// propagate the revocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeReadAccessResult {
    /// The DID whose read access was revoked.
    pub member_did: String,
    /// The context where the revocation applies.
    pub context_id: String,
    /// Whether the member's access key was deleted.
    pub access_key_deleted: bool,
    /// The new content access state after revocation.
    pub new_state: ContentAccessState,
}

/// Executes `RevokeReadAccess` for a member: destroys their access key
/// and transitions their state to [`ContentAccessState::PresenceOnly`].
///
/// **Destruction (§9.17.2 step 3):**
/// - Deletes the member's access key from the store.
/// - Future messages will not include a wrapped CEK for the member.
/// - Historical content remains permanently inaccessible because the
///   access key needed to unwrap historical CEKs is destroyed.
///
/// # Arguments
///
/// * `access_key_store` — Access key store (mutated to remove member's key).
/// * `context_id` — The context where read access is revoked.
/// * `member_did` — The DID of the member losing read access.
/// * `current_state` — The member's current content access state.
///
/// # Errors
///
/// Returns `Err(current_state)` if the state transition is invalid
/// (member already at `NonMember`, which is more restricted than
/// `PresenceOnly`).
pub fn revoke_read_access(
    access_key_store: &mut AccessKeyStore,
    context_id: &str,
    member_did: &str,
    current_state: ContentAccessState,
) -> Result<RevokeReadAccessResult, ContentAccessState> {
    let new_state = current_state.transition_to(ContentAccessState::PresenceOnly)?;
    let access_key_deleted = access_key_store.remove(context_id, member_did).is_some();

    Ok(RevokeReadAccessResult {
        member_did: member_did.to_owned(),
        context_id: context_id.to_owned(),
        access_key_deleted,
        new_state,
    })
}

/// Result of a `RevokeWriteAccess` governance action on the content access
/// key layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeWriteAccessResult {
    /// The DID whose write access was revoked.
    pub member_did: String,
    /// The context where the revocation applies.
    pub context_id: String,
    /// The new content access state after revocation.
    pub new_state: ContentAccessState,
}

/// Executes `RevokeWriteAccess` for a member: transitions their state
/// to [`ContentAccessState::ReadOnly`].
///
/// **Sender key exclusion:** The caller is responsible for excluding
/// the member from future sender key distribution. The member retains
/// their access key and can still decrypt content — they just cannot
/// send new encrypted content.
///
/// # Arguments
///
/// * `context_id` — The context where write access is revoked.
/// * `member_did` — The DID of the member losing write access.
/// * `current_state` — The member's current content access state.
///
/// # Errors
///
/// Returns `Err(current_state)` if the state transition is invalid
/// (member already at `PresenceOnly` or `NonMember`, which is more
/// restricted than `ReadOnly`).
pub fn revoke_write_access(
    context_id: &str,
    member_did: &str,
    current_state: ContentAccessState,
) -> Result<RevokeWriteAccessResult, ContentAccessState> {
    let new_state = current_state.transition_to(ContentAccessState::ReadOnly)?;

    Ok(RevokeWriteAccessResult {
        member_did: member_did.to_owned(),
        context_id: context_id.to_owned(),
        new_state,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Revocation tests
    // -----------------------------------------------------------------------

    #[test]
    fn revoke_access_key_increments_epoch() {
        let key = generate_access_key("ctx-1", "did:dht:alice");
        let result = revoke_access_key(&key).unwrap();
        assert_eq!(result.new_epoch, 1);
    }

    #[test]
    fn revoke_access_key_preserves_metadata() {
        let key = generate_access_key("ctx-1", "did:dht:alice");
        let result = revoke_access_key(&key).unwrap();
        assert_eq!(result.member_did, "did:dht:alice");
        assert_eq!(result.context_id, "ctx-1");
    }

    #[test]
    fn revoke_access_key_rejects_epoch_overflow() {
        let key = AccessKey::from_parts(
            [0u8; 32],
            "ctx-1".to_owned(),
            "did:dht:alice".to_owned(),
            u64::MAX,
        );
        let result = revoke_access_key(&key);
        assert!(matches!(result, Err(AccessKeyError::EpochOverflow)));
    }

    // -----------------------------------------------------------------------
    // Restoration tests
    // -----------------------------------------------------------------------

    #[test]
    fn restore_access_key_uses_provided_epoch() {
        let restored = restore_access_key("ctx-1", "did:dht:alice", 5);
        assert_eq!(restored.epoch(), 5);
    }

    #[test]
    fn restore_access_key_generates_fresh_key_material() {
        let restored1 = restore_access_key("ctx-1", "did:dht:alice", 1);
        let restored2 = restore_access_key("ctx-1", "did:dht:alice", 1);
        assert_ne!(restored1.as_bytes(), restored2.as_bytes());
    }

    #[test]
    fn restore_access_key_preserves_context_and_did() {
        let restored = restore_access_key("ctx-1", "did:dht:alice", 3);
        assert_eq!(restored.context_id(), "ctx-1");
        assert_eq!(restored.member_did(), "did:dht:alice");
    }

    #[test]
    fn revoke_then_restore_roundtrip() {
        let original = generate_access_key("ctx-1", "did:dht:alice");
        let revocation = revoke_access_key(&original).unwrap();
        let restored = restore_access_key(
            &revocation.context_id,
            &revocation.member_did,
            revocation.new_epoch,
        );

        // New key material (forward-only restoration).
        assert_ne!(original.as_bytes(), restored.as_bytes());
        // Epoch incremented.
        assert_eq!(restored.epoch(), 1);
        // Context and DID preserved.
        assert_eq!(restored.context_id(), "ctx-1");
        assert_eq!(restored.member_did(), "did:dht:alice");
    }

    // -----------------------------------------------------------------------
    // Context-wide rotation tests
    // -----------------------------------------------------------------------

    #[test]
    fn rotate_all_access_keys_generates_keys_for_all_members() {
        let members = ["did:dht:alice", "did:dht:bob", "did:dht:charlie"];
        let result = rotate_all_access_keys("ctx-1", &members, 0).unwrap();
        assert_eq!(result.new_keys.len(), 3);
        assert_eq!(result.new_epoch, 1);
    }

    #[test]
    fn rotate_all_access_keys_sets_correct_epoch() {
        let members = ["did:dht:alice", "did:dht:bob"];
        let result = rotate_all_access_keys("ctx-1", &members, 4).unwrap();
        for key in &result.new_keys {
            assert_eq!(key.epoch(), 5);
        }
    }

    #[test]
    fn rotate_all_access_keys_generates_distinct_key_material() {
        let members = ["did:dht:alice", "did:dht:bob"];
        let result = rotate_all_access_keys("ctx-1", &members, 0).unwrap();
        assert_ne!(result.new_keys[0].as_bytes(), result.new_keys[1].as_bytes());
    }

    #[test]
    fn rotate_all_access_keys_assigns_correct_dids() {
        let members = ["did:dht:alice", "did:dht:bob"];
        let result = rotate_all_access_keys("ctx-1", &members, 0).unwrap();
        assert_eq!(result.new_keys[0].member_did(), "did:dht:alice");
        assert_eq!(result.new_keys[1].member_did(), "did:dht:bob");
    }

    #[test]
    fn rotate_all_access_keys_rejects_epoch_overflow() {
        let members = ["did:dht:alice"];
        let result = rotate_all_access_keys("ctx-1", &members, u64::MAX);
        assert!(matches!(result, Err(AccessKeyError::EpochOverflow)));
    }

    #[test]
    fn rotate_all_access_keys_empty_members() {
        let members: [&str; 0] = [];
        let result = rotate_all_access_keys("ctx-1", &members, 0).unwrap();
        assert!(result.new_keys.is_empty());
        assert_eq!(result.new_epoch, 1);
    }

    #[test]
    fn successive_rotations_increment_epoch() {
        let members = ["did:dht:alice"];
        let r1 = rotate_all_access_keys("ctx-1", &members, 0).unwrap();
        let r2 = rotate_all_access_keys("ctx-1", &members, r1.new_epoch).unwrap();
        let r3 = rotate_all_access_keys("ctx-1", &members, r2.new_epoch).unwrap();
        assert_eq!(r1.new_epoch, 1);
        assert_eq!(r2.new_epoch, 2);
        assert_eq!(r3.new_epoch, 3);
    }

    // -----------------------------------------------------------------------
    // Block handler tests (SCP-CAC-006)
    // -----------------------------------------------------------------------

    mod block_handler_tests {
        use super::*;
        use crate::crypto::sender_keys::{
            BlockNotification, SenderKeyStore, generate_sender_key, send_block_notification,
        };
        use crate::identity::SigningKeyId;
        use scp_platform::testing::InMemoryKeyCustody;
        use scp_platform::traits::{KeyCustody, KeyType};

        /// Creates a custody + signing key for test use.
        async fn make_custody_and_key() -> (InMemoryKeyCustody, scp_platform::traits::KeyHandle) {
            let custody = InMemoryKeyCustody::new();
            let handle = custody
                .generate_keypair(KeyType::Ed25519)
                .await
                .expect("key gen");
            (custody, handle)
        }

        /// Creates a valid block notification signed by the given key custody.
        async fn make_valid_notification(
            custody: &InMemoryKeyCustody,
            key: &scp_platform::traits::KeyHandle,
            context_id: &str,
            initiator_did: &str,
            target_did: &str,
        ) -> (BlockNotification, Vec<u8>) {
            let msg = send_block_notification(
                custody,
                key,
                context_id,
                initiator_did,
                target_did,
                SigningKeyId::Active,
            )
            .await
            .expect("send_block_notification should succeed");
            let notification: BlockNotification =
                rmp_serde::from_slice(&msg).expect("deserialize notification");
            let pubkey = custody.public_key(key).await.expect("get pubkey");
            (notification, pubkey.into_bytes())
        }

        // -------------------------------------------------------------------
        // AC-1: Blocked party deletes all sender key epochs from blocker
        // -------------------------------------------------------------------

        #[tokio::test]
        async fn blocked_party_deletes_sender_keys_on_valid_notification() {
            let (custody, key) = make_custody_and_key().await;
            let (notification, pubkey) =
                make_valid_notification(&custody, &key, "ctx-1", "did:dht:alice", "did:dht:dave")
                    .await;

            // Set up Dave's stores with Alice's sender key.
            let mut sender_store = SenderKeyStore::new();
            sender_store.set("ctx-1", "did:dht:alice", generate_sender_key());
            let mut access_store = AccessKeyStore::new();

            let result = handle_block_as_blocked_party(
                &notification,
                "ctx-1",
                &pubkey,
                &mut sender_store,
                &mut access_store,
            );

            assert!(result.is_some());
            let result = result.unwrap();
            assert_eq!(result.sender_keys_deleted, 1);
            // Sender key should be gone.
            assert!(sender_store.get("ctx-1", "did:dht:alice").is_none());
        }

        // -------------------------------------------------------------------
        // AC-3: Blocked party deletes blocker's access key
        // -------------------------------------------------------------------

        #[tokio::test]
        async fn blocked_party_deletes_access_key_on_valid_notification() {
            let (custody, key) = make_custody_and_key().await;
            let (notification, pubkey) =
                make_valid_notification(&custody, &key, "ctx-1", "did:dht:alice", "did:dht:dave")
                    .await;

            let mut sender_store = SenderKeyStore::new();
            let mut access_store = AccessKeyStore::new();
            access_store.set(
                "ctx-1",
                "did:dht:alice",
                generate_access_key("ctx-1", "did:dht:alice"),
            );

            let result = handle_block_as_blocked_party(
                &notification,
                "ctx-1",
                &pubkey,
                &mut sender_store,
                &mut access_store,
            );

            assert!(result.is_some());
            let result = result.unwrap();
            assert!(result.access_key_deleted);
            assert!(access_store.get("ctx-1", "did:dht:alice").is_none());
        }

        // -------------------------------------------------------------------
        // AC-4: Destruction is synchronous (by design — function is not async)
        // -------------------------------------------------------------------

        #[tokio::test]
        async fn destruction_is_synchronous() {
            // The function `handle_block_as_blocked_party` is synchronous
            // (not async). This test verifies that all state changes are
            // visible immediately after the call returns.
            let (custody, key) = make_custody_and_key().await;
            let (notification, pubkey) =
                make_valid_notification(&custody, &key, "ctx-1", "did:dht:alice", "did:dht:dave")
                    .await;

            let mut sender_store = SenderKeyStore::new();
            sender_store.set("ctx-1", "did:dht:alice", generate_sender_key());
            let mut access_store = AccessKeyStore::new();
            access_store.set(
                "ctx-1",
                "did:dht:alice",
                generate_access_key("ctx-1", "did:dht:alice"),
            );

            // Synchronous call — not awaited, not spawned.
            let result = handle_block_as_blocked_party(
                &notification,
                "ctx-1",
                &pubkey,
                &mut sender_store,
                &mut access_store,
            );

            // Immediately after return, state is destroyed.
            assert!(result.is_some());
            assert!(sender_store.get("ctx-1", "did:dht:alice").is_none());
            assert!(access_store.get("ctx-1", "did:dht:alice").is_none());
        }

        // -------------------------------------------------------------------
        // AC-5: Blocker deletes target's access key on block initiation
        // -------------------------------------------------------------------

        #[test]
        fn blocker_deletes_target_access_key() {
            let mut access_store = AccessKeyStore::new();
            access_store.set(
                "ctx-1",
                "did:dht:dave",
                generate_access_key("ctx-1", "did:dht:dave"),
            );

            let deleted = handle_block_as_blocker(&mut access_store, "ctx-1", "did:dht:dave");
            assert!(deleted);
            assert!(access_store.get("ctx-1", "did:dht:dave").is_none());
        }

        #[test]
        fn blocker_delete_returns_false_if_no_key() {
            let mut access_store = AccessKeyStore::new();
            let deleted = handle_block_as_blocker(&mut access_store, "ctx-1", "did:dht:dave");
            assert!(!deleted);
        }

        // -------------------------------------------------------------------
        // AC-6: Signature verified against blocker's key before destruction
        // -------------------------------------------------------------------

        #[tokio::test]
        async fn signature_verified_before_destruction() {
            let (custody, key) = make_custody_and_key().await;
            let (notification, pubkey) =
                make_valid_notification(&custody, &key, "ctx-1", "did:dht:alice", "did:dht:dave")
                    .await;

            let mut sender_store = SenderKeyStore::new();
            sender_store.set("ctx-1", "did:dht:alice", generate_sender_key());
            let mut access_store = AccessKeyStore::new();
            access_store.set(
                "ctx-1",
                "did:dht:alice",
                generate_access_key("ctx-1", "did:dht:alice"),
            );

            // Valid signature — destruction should occur.
            let result = handle_block_as_blocked_party(
                &notification,
                "ctx-1",
                &pubkey,
                &mut sender_store,
                &mut access_store,
            );
            assert!(result.is_some());
        }

        // -------------------------------------------------------------------
        // AC-7: Invalid signature causes discard without destruction
        // -------------------------------------------------------------------

        #[tokio::test]
        async fn invalid_signature_causes_discard_no_destruction() {
            let (custody, key) = make_custody_and_key().await;
            let (notification, _valid_pubkey) =
                make_valid_notification(&custody, &key, "ctx-1", "did:dht:alice", "did:dht:dave")
                    .await;

            let mut sender_store = SenderKeyStore::new();
            sender_store.set("ctx-1", "did:dht:alice", generate_sender_key());
            let mut access_store = AccessKeyStore::new();
            access_store.set(
                "ctx-1",
                "did:dht:alice",
                generate_access_key("ctx-1", "did:dht:alice"),
            );

            // Use a WRONG public key — signature should fail.
            let wrong_pubkey = [0u8; 32];
            let result = handle_block_as_blocked_party(
                &notification,
                "ctx-1",
                &wrong_pubkey,
                &mut sender_store,
                &mut access_store,
            );

            // Should return None (discard).
            assert!(result.is_none());
            // State should NOT be destroyed.
            assert!(sender_store.get("ctx-1", "did:dht:alice").is_some());
            assert!(access_store.get("ctx-1", "did:dht:alice").is_some());
        }

        #[tokio::test]
        async fn wrong_context_causes_discard_no_destruction() {
            let (custody, key) = make_custody_and_key().await;
            let (notification, pubkey) =
                make_valid_notification(&custody, &key, "ctx-1", "did:dht:alice", "did:dht:dave")
                    .await;

            let mut sender_store = SenderKeyStore::new();
            sender_store.set("ctx-1", "did:dht:alice", generate_sender_key());
            let mut access_store = AccessKeyStore::new();
            access_store.set(
                "ctx-1",
                "did:dht:alice",
                generate_access_key("ctx-1", "did:dht:alice"),
            );

            // Verify with WRONG context — signature check should fail.
            let result = handle_block_as_blocked_party(
                &notification,
                "ctx-WRONG",
                &pubkey,
                &mut sender_store,
                &mut access_store,
            );

            assert!(result.is_none());
            assert!(sender_store.get("ctx-1", "did:dht:alice").is_some());
            assert!(access_store.get("ctx-1", "did:dht:alice").is_some());
        }

        // -------------------------------------------------------------------
        // AC-9: Access key deletion on both sides (blocker and blocked)
        // -------------------------------------------------------------------

        #[tokio::test]
        async fn access_key_deleted_on_both_sides() {
            let (custody, key) = make_custody_and_key().await;
            let (notification, pubkey) =
                make_valid_notification(&custody, &key, "ctx-1", "did:dht:alice", "did:dht:dave")
                    .await;

            // Blocker's side: Alice deletes Dave's access key.
            let mut blocker_store = AccessKeyStore::new();
            blocker_store.set(
                "ctx-1",
                "did:dht:dave",
                generate_access_key("ctx-1", "did:dht:dave"),
            );
            let blocker_deleted =
                handle_block_as_blocker(&mut blocker_store, "ctx-1", "did:dht:dave");
            assert!(blocker_deleted);
            assert!(blocker_store.get("ctx-1", "did:dht:dave").is_none());

            // Blocked party's side: Dave deletes Alice's access key.
            let mut blocked_sender_store = SenderKeyStore::new();
            let mut blocked_access_store = AccessKeyStore::new();
            blocked_access_store.set(
                "ctx-1",
                "did:dht:alice",
                generate_access_key("ctx-1", "did:dht:alice"),
            );
            let result = handle_block_as_blocked_party(
                &notification,
                "ctx-1",
                &pubkey,
                &mut blocked_sender_store,
                &mut blocked_access_store,
            );
            assert!(result.is_some());
            assert!(result.unwrap().access_key_deleted);
            assert!(blocked_access_store.get("ctx-1", "did:dht:alice").is_none());
        }

        // -------------------------------------------------------------------
        // AC-8: Sender key deletion on verified block notification
        // -------------------------------------------------------------------

        #[tokio::test]
        async fn sender_key_deleted_on_verified_notification() {
            let (custody, key) = make_custody_and_key().await;
            let (notification, pubkey) =
                make_valid_notification(&custody, &key, "ctx-1", "did:dht:alice", "did:dht:dave")
                    .await;

            let mut sender_store = SenderKeyStore::new();
            sender_store.set("ctx-1", "did:dht:alice", generate_sender_key());
            // Also have a sender key for another context — should NOT be affected.
            sender_store.set("ctx-2", "did:dht:alice", generate_sender_key());
            let mut access_store = AccessKeyStore::new();

            let result = handle_block_as_blocked_party(
                &notification,
                "ctx-1",
                &pubkey,
                &mut sender_store,
                &mut access_store,
            );

            assert!(result.is_some());
            assert_eq!(result.unwrap().sender_keys_deleted, 1);
            // ctx-1 key gone, ctx-2 key intact.
            assert!(sender_store.get("ctx-1", "did:dht:alice").is_none());
            assert!(sender_store.get("ctx-2", "did:dht:alice").is_some());
        }

        // -------------------------------------------------------------------
        // No keys to delete — graceful handling
        // -------------------------------------------------------------------

        #[tokio::test]
        async fn no_keys_to_delete_still_succeeds() {
            let (custody, key) = make_custody_and_key().await;
            let (notification, pubkey) =
                make_valid_notification(&custody, &key, "ctx-1", "did:dht:alice", "did:dht:dave")
                    .await;

            let mut sender_store = SenderKeyStore::new();
            let mut access_store = AccessKeyStore::new();

            let result = handle_block_as_blocked_party(
                &notification,
                "ctx-1",
                &pubkey,
                &mut sender_store,
                &mut access_store,
            );

            assert!(result.is_some());
            let result = result.unwrap();
            assert_eq!(result.sender_keys_deleted, 0);
            assert!(!result.access_key_deleted);
        }
    }

    // -----------------------------------------------------------------------
    // RevokeReadAccess / RevokeWriteAccess tests (SCP-CAC-006 AC-14, AC-15)
    // -----------------------------------------------------------------------

    mod revocation_tests {
        use super::*;

        // AC-14: RevokeReadAccess triggers plaintext + access key destruction
        #[test]
        fn revoke_read_access_deletes_access_key() {
            let mut store = AccessKeyStore::new();
            store.set(
                "ctx-1",
                "did:dht:dave",
                generate_access_key("ctx-1", "did:dht:dave"),
            );

            let result = revoke_read_access(
                &mut store,
                "ctx-1",
                "did:dht:dave",
                ContentAccessState::Full,
            );

            assert!(result.is_ok());
            let result = result.unwrap();
            assert!(result.access_key_deleted);
            assert_eq!(result.new_state, ContentAccessState::PresenceOnly);
            assert!(store.get("ctx-1", "did:dht:dave").is_none());
        }

        #[test]
        fn revoke_read_access_from_read_only() {
            let mut store = AccessKeyStore::new();
            store.set(
                "ctx-1",
                "did:dht:dave",
                generate_access_key("ctx-1", "did:dht:dave"),
            );

            let result = revoke_read_access(
                &mut store,
                "ctx-1",
                "did:dht:dave",
                ContentAccessState::ReadOnly,
            );

            assert!(result.is_ok());
            let result = result.unwrap();
            assert_eq!(result.new_state, ContentAccessState::PresenceOnly);
        }

        #[test]
        fn revoke_read_access_from_presence_only_is_noop() {
            let mut store = AccessKeyStore::new();
            let result = revoke_read_access(
                &mut store,
                "ctx-1",
                "did:dht:dave",
                ContentAccessState::PresenceOnly,
            );
            // Already at PresenceOnly — transition to same is ok.
            assert!(result.is_ok());
        }

        #[test]
        fn revoke_read_access_from_non_member_fails() {
            let mut store = AccessKeyStore::new();
            let result = revoke_read_access(
                &mut store,
                "ctx-1",
                "did:dht:dave",
                ContentAccessState::NonMember,
            );
            // NonMember -> PresenceOnly would be an increase. Fails.
            assert!(result.is_err());
        }

        // AC-15: RevokeWriteAccess triggers sender key exclusion
        #[test]
        fn revoke_write_access_transitions_to_read_only() {
            let result = revoke_write_access("ctx-1", "did:dht:dave", ContentAccessState::Full);

            assert!(result.is_ok());
            let result = result.unwrap();
            assert_eq!(result.new_state, ContentAccessState::ReadOnly);
        }

        #[test]
        fn revoke_write_access_from_read_only_is_noop() {
            let result = revoke_write_access("ctx-1", "did:dht:dave", ContentAccessState::ReadOnly);
            // Already at ReadOnly — transition to same is ok.
            assert!(result.is_ok());
        }

        #[test]
        fn revoke_write_access_from_presence_only_fails() {
            let result =
                revoke_write_access("ctx-1", "did:dht:dave", ContentAccessState::PresenceOnly);
            // PresenceOnly -> ReadOnly would be an increase. Fails.
            assert!(result.is_err());
        }

        #[test]
        fn revoke_write_access_does_not_delete_access_key() {
            // RevokeWriteAccess only changes state — the member retains
            // their access key for reading.
            let mut store = AccessKeyStore::new();
            store.set(
                "ctx-1",
                "did:dht:dave",
                generate_access_key("ctx-1", "did:dht:dave"),
            );

            let result = revoke_write_access("ctx-1", "did:dht:dave", ContentAccessState::Full);
            assert!(result.is_ok());
            // Access key should still be present.
            assert!(store.get("ctx-1", "did:dht:dave").is_some());
        }
    }
}
