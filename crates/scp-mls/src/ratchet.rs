//! MLS ratcheting and update operations for SCP.
//!
//! This module implements post-compromise security (Update proposals) on top
//! of the [`ScpMlsGroup`] wrapper. A receiving member merges the resulting
//! Commit through [`crate::encrypt::decrypt_with_sender_did`] or
//! [`crate::encrypt::decrypt_with_membership_changes`].
//!
//! # Operations
//!
//! - [`propose_update`] — Issue an MLS Update proposal that generates a fresh
//!   HPKE key pair and ratchets the sender's path, providing post-compromise
//!   security. Recommended interval: every 24 hours.
//!
//! See ADR-001 acceptance criteria 6 and 7.

use openmls::prelude::*;
use tls_codec::Serialize as TlsSerializeTrait;

use crate::error::MlsError;
use crate::group::ScpMlsGroup;

/// Issues an MLS Update proposal and immediately commits it.
///
/// The Update generates a fresh HPKE key pair and ratchets the sender's path
/// in the tree, providing post-compromise security. After the Update+Commit
/// is processed by all members, any prior compromise of the sender's state
/// becomes useless for future messages.
///
/// Recommended interval: every 24 hours for active contexts.
///
/// # Arguments
///
/// * `group` - The MLS group to update within. Must be active.
///
/// # Returns
///
/// The Commit message as an [`MlsMessageOut`] that must be sent to all
/// group members. Members merge it through
/// [`crate::encrypt::decrypt_with_sender_did`].
///
/// # Errors
///
/// Returns [`MlsError::GroupDestroyed`] if the group has been destroyed.
/// Returns [`MlsError::UpdateFailed`] if the Update proposal or Commit
/// generation fails.
/// Returns [`MlsError::MergePendingCommitFailed`] if merging the pending
/// commit fails.
///
/// See ADR-001 acceptance criterion 7.
pub fn propose_update(group: &mut ScpMlsGroup) -> Result<MlsMessageOut, MlsError> {
    let signer = group.signer.as_ref().ok_or(MlsError::GroupDestroyed)?;

    // self_update() generates an Update proposal, builds a Commit that includes
    // it, and stages the commit. It returns a CommitMessageBundle containing the
    // Commit (and optionally a Welcome if there were pending Add proposals).
    let g = group.group.as_mut().ok_or(MlsError::GroupDestroyed)?;
    let bundle = g
        .self_update(&group.provider, signer, LeafNodeParameters::default())
        .map_err(|e| MlsError::UpdateFailed(e.to_string()))?;

    // Extract the Commit message.
    let commit = bundle.into_commit();

    // Merge the pending commit to advance the group epoch locally.
    let g = group.group.as_mut().ok_or(MlsError::GroupDestroyed)?;
    g.merge_pending_commit(&group.provider)
        .map_err(|e| MlsError::MergePendingCommitFailed(e.to_string()))?;

    Ok(commit)
}

/// Issues an MLS Update proposal that preserves the `scp_wrapping_key`
/// `LeafNode` extension, immediately committing it.
///
/// This is the production-path variant of [`propose_update`] that ensures
/// the wrapping key remains stable across MLS epoch advances, as required
/// by §9.16.1. The wrapping key does NOT rotate on MLS Updates — only on
/// identity key rotation (§9.12) or suspected compromise.
///
/// # Arguments
///
/// * `group` - The MLS group to update within. Must be active.
/// * `wrapping_pubkey` - The 32-byte X25519 public key to include in the
///   `scp_wrapping_key` `LeafNode` extension. Must be the same key that was
///   originally published at context join time, unless this is an identity
///   key rotation.
///
/// # Errors
///
/// Returns [`MlsError::GroupDestroyed`] if the group has been destroyed.
/// Returns [`MlsError::UpdateFailed`] if the Update proposal or Commit
/// generation fails.
/// Returns [`MlsError::MergePendingCommitFailed`] if merging the pending
/// commit fails.
///
/// See spec §9.16.1, ADR-001 acceptance criterion 7.
pub fn propose_update_with_wrapping_key(
    group: &mut ScpMlsGroup,
    wrapping_pubkey: &[u8; 32],
) -> Result<MlsMessageOut, MlsError> {
    let signer = group.signer.as_ref().ok_or(MlsError::GroupDestroyed)?;

    let leaf_params =
        crate::wrapping_extension::leaf_node_params_with_wrapping_key(wrapping_pubkey)?;

    let g = group.group.as_mut().ok_or(MlsError::GroupDestroyed)?;
    let bundle = g
        .self_update(&group.provider, signer, leaf_params)
        .map_err(|e| MlsError::UpdateFailed(e.to_string()))?;

    let commit = bundle.into_commit();

    let g = group.group.as_mut().ok_or(MlsError::GroupDestroyed)?;
    g.merge_pending_commit(&group.provider)
        .map_err(|e| MlsError::MergePendingCommitFailed(e.to_string()))?;

    Ok(commit)
}

/// Serializes an [`MlsMessageOut`] to bytes for transmission.
///
/// Convenience function for converting any MLS message (Commit, Welcome, etc.)
/// from [`propose_update`] or [`add_member`](crate::group::add_member) into
/// byte vectors suitable for transport.
///
/// # Errors
///
/// Returns [`MlsError::CommitProcessingFailed`] if TLS serialization fails.
pub fn serialize_mls_message(message: &MlsMessageOut) -> Result<Vec<u8>, MlsError> {
    message
        .tls_serialize_detached()
        .map_err(|e| MlsError::CommitProcessingFailed(format!("serializing MLS message: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::ScpCredential;
    use crate::epoch_grace::EpochGraceStore;
    use crate::group::{add_member, create_group, generate_key_package, join_group};
    use scp_clock::SystemClock;

    #[allow(clippy::unwrap_used)]
    fn test_credential(name: &str) -> ScpCredential {
        ScpCredential::new(
            format!("did:dht:z6Mk{name}"),
            None,
            scp_did::SigningKeyId::Active,
        )
        .unwrap()
    }

    /// Helper: set up Alice and Bob in a shared group at epoch 1.
    /// Returns (`alice_group`, `bob_group`).
    #[allow(clippy::unwrap_used)]
    fn setup_alice_bob() -> (ScpMlsGroup, ScpMlsGroup) {
        let alice_cred = test_credential("alice");
        let mut alice_group = create_group(&alice_cred, &SystemClock).unwrap();

        let bob_cred = test_credential("bob");
        let (bob_kp_bundle, bob_signer, bob_provider) =
            generate_key_package(&bob_cred, &SystemClock).unwrap();
        let bob_kp: KeyPackageIn = bob_kp_bundle.key_package().clone().into();

        let add_result = add_member(&mut alice_group, bob_kp, &SystemClock).unwrap();

        let bob_group =
            join_group(&add_result.welcome, bob_provider, bob_signer, &SystemClock).unwrap();

        (alice_group, bob_group)
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn propose_update_advances_epoch() {
        let (mut alice_group, _bob_group) = setup_alice_bob();
        let epoch_before = alice_group.epoch().unwrap();

        let _commit = propose_update(&mut alice_group).unwrap();

        let epoch_after = alice_group.epoch().unwrap();
        assert_eq!(
            epoch_after,
            epoch_before + 1,
            "epoch should advance after update"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn propose_update_returns_serializable_commit() {
        let (mut alice_group, _bob_group) = setup_alice_bob();

        let commit = propose_update(&mut alice_group).unwrap();
        let bytes = serialize_mls_message(&commit).unwrap();

        assert!(!bytes.is_empty(), "serialized commit should not be empty");
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn propose_update_on_destroyed_group_fails() {
        let (mut alice_group, _bob_group) = setup_alice_bob();
        crate::group::destroy_group(&mut alice_group).unwrap();

        let result = propose_update(&mut alice_group);
        assert!(
            result.is_err(),
            "propose_update must fail on destroyed group"
        );
    }

    /// Grace window: after one epoch advance (N→N+1), messages encrypted
    /// under epoch N are still decryptable because `max_past_epochs = 2`
    /// retains past epoch message secrets in `OpenMLS`'s `MessageSecretsStore`.
    ///
    /// This is the core grace window test: Alice sends a Commit advancing
    /// the epoch, Bob sends a message encrypted under the old epoch (within
    /// the 30s grace window), and Alice can still decrypt it.
    ///
    /// **Documented finding (SCP-171, issue #324):** `OpenMLS`'s
    /// `merge_staged_commit()` and `merge_pending_commit()` automatically
    /// call `delete_previous_epoch_keypairs()`, which removes the previous
    /// epoch's encryption key pairs. However, `max_past_epochs = 2` ensures
    /// message secrets are retained for 2 past epochs, allowing decryption
    /// of in-flight messages during the grace window. Forward secrecy is
    /// enforced by bounded retention (2 epochs) plus the `EpochGraceStore`
    /// time bound (30s).
    #[test]
    #[allow(clippy::unwrap_used)]
    fn grace_window_old_epoch_ciphertext_decryptable_within_window() {
        use crate::encrypt::{decrypt, encrypt, serialize_ciphertext};

        let (mut alice_group, mut bob_group) = setup_alice_bob();

        // Bob encrypts a message at epoch 1 (before the epoch advance).
        let old_epoch = bob_group.epoch().unwrap();
        let ciphertext_msg = encrypt(&mut bob_group, b"message at old epoch").unwrap();
        let ciphertext_bytes = serialize_ciphertext(&ciphertext_msg).unwrap();

        // Alice issues an update, advancing her group to epoch 2.
        let commit = propose_update(&mut alice_group).unwrap();
        let commit_bytes = serialize_mls_message(&commit).unwrap();

        // Alice processes Bob's old-epoch ciphertext AFTER advancing her own
        // epoch. With max_past_epochs=2, Alice retains epoch 1 message secrets
        // and can decrypt the in-flight message.
        //
        // Note: Alice advanced via propose_update (merge_pending_commit), so
        // she's the committer. Bob hasn't processed
        // the commit yet, so his message was encrypted at epoch 1.
        // Alice should still be able to decrypt it thanks to retained secrets.
        let result = decrypt(&mut alice_group, &ciphertext_bytes);
        assert!(
            result.is_ok(),
            "old-epoch ciphertext must be decryptable within grace window \
             (max_past_epochs=2 retains epoch {old_epoch} secrets)"
        );

        // Also verify Bob can process the commit and advance.
        crate::encrypt::decrypt_with_sender_did(&mut bob_group, &commit_bytes).unwrap();
        assert_eq!(bob_group.epoch().unwrap(), old_epoch + 1);
    }

    /// Grace window with expired time: after the 30-second grace window
    /// closes, the `EpochGraceStore` rejects messages from old epochs.
    ///
    /// This test verifies the SCP-layer enforcement: even though `OpenMLS`
    /// might still hold the message secrets (`max_past_epochs=2`), the
    /// `EpochGraceStore` enforces the 30-second time boundary.
    ///
    /// We use `with_max_capacity(1)` and add a second epoch to force the
    /// first to be evicted, simulating time-based expiry without accessing
    /// private fields.
    #[test]
    #[allow(clippy::unwrap_used)]
    fn grace_window_expired_epoch_rejected_by_grace_store() {
        // Use capacity=1 so adding epoch 2 evicts epoch 1, simulating
        // what happens after the 30s grace window expires.
        let mut grace_store = EpochGraceStore::with_max_capacity(1);

        grace_store.add_epoch(1);
        assert!(grace_store.is_in_grace(1), "epoch 1 should be in grace");

        // Adding epoch 2 evicts epoch 1 (capacity=1).
        grace_store.add_epoch(2);

        // After eviction, the grace store rejects epoch 1.
        assert!(
            !grace_store.is_in_grace(1),
            "epoch 1 must NOT be in grace after eviction — \
             the EpochGraceStore enforces the boundary (§9.7)"
        );
        assert!(
            grace_store.is_in_grace(2),
            "epoch 2 should still be in grace"
        );
    }

    /// Forward secrecy after 3 epoch advances: with `max_past_epochs = 2`,
    /// only epochs N+1 and N+2 are retained at epoch N+3. Epoch N's message
    /// secrets have been evicted from `MessageSecretsStore`, so ciphertext
    /// from epoch N is undecryptable.
    ///
    /// This verifies the bounded retention guarantee: two consecutive epoch
    /// advances (N→N+1→N+2) keep epoch N accessible, but a third advance
    /// (→N+3) evicts it.
    #[test]
    #[allow(clippy::unwrap_used)]
    fn forward_secrecy_epoch_n_undecryptable_after_three_advances() {
        use crate::encrypt::{decrypt, encrypt, serialize_ciphertext};

        let (mut alice_group, mut bob_group) = setup_alice_bob();

        // Alice encrypts at epoch 1.
        let ciphertext_msg = encrypt(&mut alice_group, b"epoch 1 secret").unwrap();
        let ciphertext_bytes = serialize_ciphertext(&ciphertext_msg).unwrap();

        // Advance three times: epoch 1 → 2 → 3 → 4.
        // With max_past_epochs=2, at epoch 4 only epochs 2 and 3 are retained.
        for _ in 0..3 {
            let commit = propose_update(&mut alice_group).unwrap();
            let commit_bytes = serialize_mls_message(&commit).unwrap();
            crate::encrypt::decrypt_with_sender_did(&mut bob_group, &commit_bytes).unwrap();
        }

        assert_eq!(bob_group.epoch().unwrap(), 4);

        // Epoch 1 message secrets have been evicted (only epochs 2 and 3
        // retained with max_past_epochs=2). Decryption must fail.
        let result = decrypt(&mut bob_group, &ciphertext_bytes);
        assert!(
            result.is_err(),
            "ciphertext from epoch 1 must be undecryptable at epoch 4 \
             (only 2 past epochs retained, forward secrecy enforced)"
        );
    }

    /// Verify that after exactly 2 epoch advances (N→N+1→N+2), epoch N's
    /// ciphertext is still decryptable because `max_past_epochs = 2` retains
    /// it. This is the boundary case: 2 past epochs retained means epoch N
    /// is the oldest retained epoch at epoch N+2.
    #[test]
    #[allow(clippy::unwrap_used)]
    fn grace_window_epoch_n_still_decryptable_after_two_advances() {
        use crate::encrypt::{decrypt, encrypt, serialize_ciphertext};

        let (mut alice_group, mut bob_group) = setup_alice_bob();

        // Bob encrypts at epoch 1.
        let ciphertext_msg = encrypt(&mut bob_group, b"epoch 1 secret").unwrap();
        let ciphertext_bytes = serialize_ciphertext(&ciphertext_msg).unwrap();

        // Advance twice: epoch 1 → 2 → 3. At epoch 3, max_past_epochs=2
        // retains epochs 1 and 2.
        for _ in 0..2 {
            let commit = propose_update(&mut alice_group).unwrap();
            let commit_bytes = serialize_mls_message(&commit).unwrap();
            crate::encrypt::decrypt_with_sender_did(&mut bob_group, &commit_bytes).unwrap();
        }

        assert_eq!(alice_group.epoch().unwrap(), 3);

        // Alice should still be able to decrypt epoch 1 ciphertext because
        // max_past_epochs=2 means epochs 1 and 2 are both retained.
        let result = decrypt(&mut alice_group, &ciphertext_bytes);
        assert!(
            result.is_ok(),
            "ciphertext from epoch 1 must still be decryptable at epoch 3 \
             (max_past_epochs=2 retains 2 past epochs)"
        );
    }
}
