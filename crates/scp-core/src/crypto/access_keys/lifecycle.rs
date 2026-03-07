//! Access key lifecycle operations: revocation, restoration, and
//! context-wide rotation.
//!
//! These operations manage the full lifecycle of per-member access keys
//! beyond initial generation (which is in the parent module). Revocation
//! deletes the access key and increments epoch. Restoration generates a
//! new key at the incremented epoch. Context-wide rotation generates new
//! keys for all members while retaining old keys for historical access.
//!
//! See spec §9.17.2 (steps 3-6) and ADR-038 §2.

use super::{AccessKey, AccessKeyError, generate_access_key};

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
}
