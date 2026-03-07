//! MLS ratcheting and update operations for SCP.
//!
//! This module implements epoch advancement (Commit processing) and
//! post-compromise security (Update proposals) on top of the
//! [`ScpMlsGroup`] wrapper.
//!
//! # Operations
//!
//! - [`process_commit`] — Process an incoming Commit message, advancing the
//!   group to a new epoch while placing the old epoch into the grace window.
//! - [`propose_update`] — Issue an MLS Update proposal that generates a fresh
//!   HPKE key pair and ratchets the sender's path, providing post-compromise
//!   security. Recommended interval: every 24 hours.
//!
//! See ADR-001 acceptance criteria 6 and 7.

use openmls::prelude::*;
use tls_codec::{Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait};

use super::epoch_grace::EpochGraceStore;
use super::error::MlsError;
use super::group::ScpMlsGroup;

/// Processes an incoming Commit message, advancing the group to a new epoch.
///
/// The old epoch is placed into the [`EpochGraceStore`] so that in-flight
/// messages encrypted under it can still be decrypted during the grace window.
///
/// # Arguments
///
/// * `group` - The MLS group receiving the Commit. Must be active.
/// * `commit_bytes` - The serialized Commit message bytes (TLS-serialized
///   `MlsMessageOut` from the committer).
/// * `grace_store` - The epoch grace store where the old epoch will be tracked.
///
/// # Errors
///
/// Returns [`MlsError::GroupDestroyed`] if the group has been destroyed.
/// Returns [`MlsError::CommitProcessingFailed`] if the Commit message cannot
/// be deserialized, processed, or merged.
///
/// See ADR-001 acceptance criterion 6.
pub fn process_commit(
    group: &mut ScpMlsGroup,
    commit_bytes: &[u8],
    grace_store: &mut EpochGraceStore,
) -> Result<(), MlsError> {
    // Record the current epoch before processing the Commit. This epoch will
    // enter the grace window after the Commit is merged.
    let g = group.group.as_ref().ok_or(MlsError::GroupDestroyed)?;
    let old_epoch = g.epoch().as_u64();

    // Deserialize the Commit bytes into an MlsMessageIn.
    let message_in = MlsMessageIn::tls_deserialize(&mut &*commit_bytes)
        .map_err(|e| MlsError::CommitProcessingFailed(format!("deserializing commit: {e}")))?;

    // Convert to a ProtocolMessage for processing.
    let protocol_message = message_in.try_into_protocol_message().map_err(|e| {
        MlsError::CommitProcessingFailed(format!("extracting protocol message: {e}"))
    })?;

    // Process the message — this validates the Commit and produces a StagedCommit.
    let g = group.group.as_mut().ok_or(MlsError::GroupDestroyed)?;
    let processed = g
        .process_message(&group.provider, protocol_message)
        .map_err(|e| MlsError::CommitProcessingFailed(e.to_string()))?;

    // Extract the staged commit from the processed message.
    let staged_commit = match processed.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged) => *staged,
        _ => {
            return Err(MlsError::CommitProcessingFailed(
                "message is not a Commit".to_string(),
            ));
        }
    };

    // Merge the staged commit to advance the group to the new epoch.
    let g = group.group.as_mut().ok_or(MlsError::GroupDestroyed)?;
    g.merge_staged_commit(&group.provider, staged_commit)
        .map_err(|e| MlsError::CommitProcessingFailed(format!("merging staged commit: {e}")))?;

    // Place the old epoch into the grace window. In-flight messages encrypted
    // under this epoch can still be decrypted until the grace window closes
    // (30 seconds or until all members send in the new epoch).
    //
    // add_epoch() enforces capacity bounds and returns any epochs that were
    // expired or evicted. OpenMLS handles its own key material deletion
    // internally (via delete_previous_epoch_keypairs during commit merges),
    // so we do not need to explicitly delete key material here. The expired
    // epochs list is available for logging/diagnostics if needed.
    let _expired_epochs = grace_store.add_epoch(old_epoch);

    Ok(())
}

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
/// group members. Members will process this via [`process_commit`].
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
        super::wrapping_extension::leaf_node_params_with_wrapping_key(wrapping_pubkey)?;

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
/// Convenience function for converting Commit messages from [`propose_update`]
/// into byte vectors suitable for transport.
///
/// # Errors
///
/// Returns [`MlsError::CommitProcessingFailed`] if TLS serialization fails.
pub fn serialize_commit(message: &MlsMessageOut) -> Result<Vec<u8>, MlsError> {
    message
        .tls_serialize_detached()
        .map_err(|e| MlsError::CommitProcessingFailed(format!("serializing commit: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::mls::credential::ScpCredential;
    use crate::crypto::mls::group::{add_member, create_group, generate_key_package, join_group};

    #[allow(clippy::unwrap_used)]
    fn test_credential(name: &str) -> ScpCredential {
        ScpCredential::new(
            format!("did:dht:z6Mk{name}"),
            None,
            scp_identity::SigningKeyId::Active,
        )
        .unwrap()
    }

    /// Helper: set up Alice and Bob in a shared group at epoch 1.
    /// Returns (`alice_group`, `bob_group`).
    #[allow(clippy::unwrap_used)]
    fn setup_alice_bob() -> (ScpMlsGroup, ScpMlsGroup) {
        let alice_cred = test_credential("alice");
        let mut alice_group = create_group(&alice_cred).unwrap();

        let bob_cred = test_credential("bob");
        let (bob_kp_bundle, bob_signer, bob_provider) = generate_key_package(&bob_cred).unwrap();
        let bob_kp: KeyPackageIn = bob_kp_bundle.key_package().clone().into();

        let add_result = add_member(&mut alice_group, bob_kp).unwrap();

        let bob_group = join_group(&add_result.welcome, bob_provider, bob_signer).unwrap();

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
        let bytes = serialize_commit(&commit).unwrap();

        assert!(!bytes.is_empty(), "serialized commit should not be empty");
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn process_commit_advances_bobs_epoch() {
        let (mut alice_group, mut bob_group) = setup_alice_bob();
        let mut grace_store = EpochGraceStore::new();

        let bob_epoch_before = bob_group.epoch().unwrap();

        // Alice issues an update, producing a Commit.
        let commit = propose_update(&mut alice_group).unwrap();
        let commit_bytes = serialize_commit(&commit).unwrap();

        // Bob processes the Commit.
        process_commit(&mut bob_group, &commit_bytes, &mut grace_store).unwrap();

        let bob_epoch_after = bob_group.epoch().unwrap();
        assert_eq!(
            bob_epoch_after,
            bob_epoch_before + 1,
            "Bob's epoch should advance after processing Alice's commit"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn process_commit_adds_old_epoch_to_grace_store() {
        let (mut alice_group, mut bob_group) = setup_alice_bob();
        let mut grace_store = EpochGraceStore::new();

        let bob_old_epoch = bob_group.epoch().unwrap();

        let commit = propose_update(&mut alice_group).unwrap();
        let commit_bytes = serialize_commit(&commit).unwrap();

        process_commit(&mut bob_group, &commit_bytes, &mut grace_store).unwrap();

        assert!(
            grace_store.is_in_grace(bob_old_epoch),
            "old epoch should be in grace window after processing commit"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn process_commit_on_destroyed_group_fails() {
        let (mut alice_group, mut bob_group) = setup_alice_bob();
        let mut grace_store = EpochGraceStore::new();

        let commit = propose_update(&mut alice_group).unwrap();
        let commit_bytes = serialize_commit(&commit).unwrap();

        crate::crypto::mls::group::destroy_group(&mut bob_group).unwrap();

        let result = process_commit(&mut bob_group, &commit_bytes, &mut grace_store);
        assert!(
            result.is_err(),
            "process_commit must fail on destroyed group"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn propose_update_on_destroyed_group_fails() {
        let (mut alice_group, _bob_group) = setup_alice_bob();
        crate::crypto::mls::group::destroy_group(&mut alice_group).unwrap();

        let result = propose_update(&mut alice_group);
        assert!(
            result.is_err(),
            "propose_update must fail on destroyed group"
        );
    }

    #[test]
    fn process_commit_rejects_garbage_bytes() {
        let (_alice_group, mut bob_group) = setup_alice_bob();
        let mut grace_store = EpochGraceStore::new();

        let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let result = process_commit(&mut bob_group, &garbage, &mut grace_store);
        assert!(
            result.is_err(),
            "process_commit must reject malformed bytes"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn multiple_updates_advance_epoch_correctly() {
        let (mut alice_group, mut bob_group) = setup_alice_bob();
        let mut grace_store = EpochGraceStore::new();
        let initial_epoch = bob_group.epoch().unwrap();

        // Perform 3 sequential updates.
        for i in 0u64..3 {
            let commit = propose_update(&mut alice_group).unwrap();
            let commit_bytes = serialize_commit(&commit).unwrap();
            process_commit(&mut bob_group, &commit_bytes, &mut grace_store).unwrap();

            assert_eq!(
                bob_group.epoch().unwrap(),
                initial_epoch + i + 1,
                "epoch should advance correctly after update {i}"
            );
        }

        // All 3 old epochs should be in the grace store.
        assert_eq!(grace_store.len(), 3);
        for i in 0u64..3 {
            assert!(grace_store.is_in_grace(initial_epoch + i));
        }
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
        use crate::crypto::mls::encrypt::{decrypt, encrypt, serialize_ciphertext};

        let (mut alice_group, mut bob_group) = setup_alice_bob();
        let mut grace_store = EpochGraceStore::new();

        // Bob encrypts a message at epoch 1 (before the epoch advance).
        let old_epoch = bob_group.epoch().unwrap();
        let ciphertext_msg = encrypt(&mut bob_group, b"message at old epoch").unwrap();
        let ciphertext_bytes = serialize_ciphertext(&ciphertext_msg).unwrap();

        // Alice issues an update, advancing her group to epoch 2.
        let commit = propose_update(&mut alice_group).unwrap();
        let commit_bytes = serialize_commit(&commit).unwrap();

        // Alice processes Bob's old-epoch ciphertext AFTER advancing her own
        // epoch. With max_past_epochs=2, Alice retains epoch 1 message secrets
        // and can decrypt the in-flight message.
        //
        // Note: Alice advanced via propose_update (merge_pending_commit), not
        // via process_commit, so she's the committer. Bob hasn't processed
        // the commit yet, so his message was encrypted at epoch 1.
        // Alice should still be able to decrypt it thanks to retained secrets.
        let result = decrypt(&mut alice_group, &ciphertext_bytes);
        assert!(
            result.is_ok(),
            "old-epoch ciphertext must be decryptable within grace window \
             (max_past_epochs=2 retains epoch {old_epoch} secrets)"
        );

        // Also verify Bob can process the commit and advance.
        process_commit(&mut bob_group, &commit_bytes, &mut grace_store).unwrap();
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
        use crate::crypto::mls::encrypt::{decrypt, encrypt, serialize_ciphertext};

        let (mut alice_group, mut bob_group) = setup_alice_bob();
        let mut grace_store = EpochGraceStore::new();

        // Alice encrypts at epoch 1.
        let ciphertext_msg = encrypt(&mut alice_group, b"epoch 1 secret").unwrap();
        let ciphertext_bytes = serialize_ciphertext(&ciphertext_msg).unwrap();

        // Advance three times: epoch 1 → 2 → 3 → 4.
        // With max_past_epochs=2, at epoch 4 only epochs 2 and 3 are retained.
        for _ in 0..3 {
            let commit = propose_update(&mut alice_group).unwrap();
            let commit_bytes = serialize_commit(&commit).unwrap();
            process_commit(&mut bob_group, &commit_bytes, &mut grace_store).unwrap();
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
        use crate::crypto::mls::encrypt::{decrypt, encrypt, serialize_ciphertext};

        let (mut alice_group, mut bob_group) = setup_alice_bob();
        let mut grace_store = EpochGraceStore::new();

        // Bob encrypts at epoch 1.
        let ciphertext_msg = encrypt(&mut bob_group, b"epoch 1 secret").unwrap();
        let ciphertext_bytes = serialize_ciphertext(&ciphertext_msg).unwrap();

        // Advance twice: epoch 1 → 2 → 3. At epoch 3, max_past_epochs=2
        // retains epochs 1 and 2.
        for _ in 0..2 {
            let commit = propose_update(&mut alice_group).unwrap();
            let commit_bytes = serialize_commit(&commit).unwrap();
            process_commit(&mut bob_group, &commit_bytes, &mut grace_store).unwrap();
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

    /// Verify that the epoch expiration callback fires during `process_commit`
    /// when the grace store is at capacity and must evict old epochs.
    #[test]
    #[allow(clippy::unwrap_used)]
    fn process_commit_triggers_callback_on_grace_store_eviction() {
        use std::cell::RefCell;
        use std::rc::Rc;

        let (mut alice_group, mut bob_group) = setup_alice_bob();
        let evicted = Rc::new(RefCell::new(Vec::<u64>::new()));
        let evicted_clone = Rc::clone(&evicted);

        // Use a very small grace store that will evict quickly.
        let mut grace_store = EpochGraceStore::with_max_capacity(2);
        grace_store.set_on_epoch_expired(Box::new(move |epochs| {
            evicted_clone.borrow_mut().extend_from_slice(epochs);
        }));

        // Advance 3 times to fill and then exceed the grace store capacity.
        for _ in 0..3 {
            let commit = propose_update(&mut alice_group).unwrap();
            let commit_bytes = serialize_commit(&commit).unwrap();
            process_commit(&mut bob_group, &commit_bytes, &mut grace_store).unwrap();
        }

        // The grace store has capacity 2, so the first epoch should have been
        // evicted when the third was added.
        let evicted_epochs = evicted.borrow();
        assert!(
            !evicted_epochs.is_empty(),
            "callback should have been invoked for evicted epoch"
        );
        assert_eq!(
            grace_store.len(),
            2,
            "grace store should be at capacity, not over"
        );
    }
}
