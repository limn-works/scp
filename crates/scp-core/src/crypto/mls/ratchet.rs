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
    if group.destroyed {
        return Err(MlsError::GroupDestroyed);
    }

    // Record the current epoch before processing the Commit. This epoch will
    // enter the grace window after the Commit is merged.
    let old_epoch = group.group.epoch().as_u64();

    // Deserialize the Commit bytes into an MlsMessageIn.
    let message_in = MlsMessageIn::tls_deserialize(&mut &*commit_bytes)
        .map_err(|e| MlsError::CommitProcessingFailed(format!("deserializing commit: {e}")))?;

    // Convert to a ProtocolMessage for processing.
    let protocol_message = message_in.try_into_protocol_message().map_err(|e| {
        MlsError::CommitProcessingFailed(format!("extracting protocol message: {e}"))
    })?;

    // Process the message — this validates the Commit and produces a StagedCommit.
    let processed = group
        .group
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
    group
        .group
        .merge_staged_commit(&group.provider, staged_commit)
        .map_err(|e| MlsError::CommitProcessingFailed(format!("merging staged commit: {e}")))?;

    // Place the old epoch into the grace window. In-flight messages encrypted
    // under this epoch can still be decrypted until the grace window closes
    // (30 seconds or until all members send in the new epoch).
    grace_store.add_epoch(old_epoch);

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
    if group.destroyed {
        return Err(MlsError::GroupDestroyed);
    }

    // self_update() generates an Update proposal, builds a Commit that includes
    // it, and stages the commit. It returns a CommitMessageBundle containing the
    // Commit (and optionally a Welcome if there were pending Add proposals).
    let bundle = group
        .group
        .self_update(
            &group.provider,
            &group.signer,
            LeafNodeParameters::default(),
        )
        .map_err(|e| MlsError::UpdateFailed(e.to_string()))?;

    // Extract the Commit message.
    let commit = bundle.into_commit();

    // Merge the pending commit to advance the group epoch locally.
    group
        .group
        .merge_pending_commit(&group.provider)
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

    fn test_credential(name: &str) -> ScpCredential {
        ScpCredential::new(format!("did:dht:z6Mk{name}"), None)
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
}
