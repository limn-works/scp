//! MLS group lifecycle operations for SCP.
//!
//! This module implements the core group management wrapper around `OpenMLS`'s
//! `MlsGroup`. Every SCP context maps to one MLS group. The wrapper exposes
//! SCP-specific operations and hides `OpenMLS` internals behind a clean interface.
//!
//! # Operations
//!
//! - [`create_group`] — Create a new MLS group with the creator as the sole member.
//! - [`add_member`] — Add a member via their pre-published `KeyPackage`.
//! - [`remove_member`] — Remove a member by their leaf index.
//! - [`destroy_group`] — Destroy all MLS group state.
//!
//! # Ciphersuite
//!
//! All groups use `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` — no
//! ciphersuite negotiation. See ADR-001 for the rationale.

use std::ops::Deref;

use super::credential::ScpCredential;
use super::error::MlsError;
use super::storage::ScpMlsProvider;
use openmls::messages::group_info::GroupInfo;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use tls_codec::{Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait};

/// The single ciphersuite used by all SCP MLS groups.
///
/// `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` provides:
/// - X25519 for key exchange (DHKEM)
/// - AES-128-GCM for authenticated encryption
/// - SHA-256 for hashing
/// - Ed25519 for digital signatures
///
/// No ciphersuite negotiation is supported. This eliminates downgrade attacks
/// and simplifies the implementation. See ADR-001 for the rationale.
pub const SCP_CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

// ---------------------------------------------------------------------------
// ZeroizingSigner — defense-in-depth wrapper for upstream SignatureKeyPair
// ---------------------------------------------------------------------------

/// Wrapper around `openmls_basic_credential::SignatureKeyPair` that documents
/// the zeroization gap and ensures eager drop semantics.
///
/// `SignatureKeyPair` stores its Ed25519 private key in a plain `Vec<u8>` and
/// does not implement [`Zeroize`] or [`ZeroizeOnDrop`](zeroize::ZeroizeOnDrop).
/// The `private` field is not publicly accessible (only available behind the
/// `test-utils` feature), so we cannot zeroize it from outside the crate
/// without `unsafe` code.
///
/// This wrapper provides:
/// 1. **Documentation of the gap** — future upstream support for `Zeroize` on
///    `SignatureKeyPair` would close this.
/// 2. **Eager drop via [`ZeroizingSigner::take`]** — `destroy_group` uses
///    `take()` to drop the key material as early as possible.
/// 3. **Centralized ownership** — all `SignatureKeyPair` storage in
///    `ScpMlsGroup` goes through this type.
///
/// **Upstream limitation:** Full zeroization requires `openmls_basic_credential`
/// to implement `Zeroize` on `SignatureKeyPair`. See issue #82.
pub(crate) struct ZeroizingSigner(Option<SignatureKeyPair>);

impl ZeroizingSigner {
    /// Wraps a `SignatureKeyPair` in a zeroizing wrapper.
    const fn new(inner: SignatureKeyPair) -> Self {
        Self(Some(inner))
    }

    /// Returns a reference to the inner `SignatureKeyPair`, or `None` after
    /// destruction.
    const fn as_ref(&self) -> Option<&SignatureKeyPair> {
        self.0.as_ref()
    }

    /// Takes the inner `SignatureKeyPair` out, leaving `None`. Used by
    /// `destroy_group` for eager cleanup.
    const fn take(&mut self) -> Option<SignatureKeyPair> {
        self.0.take()
    }
}

impl Deref for ZeroizingSigner {
    type Target = Option<SignatureKeyPair>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Wrapper around an `OpenMLS` `MlsGroup` that enforces SCP conventions.
///
/// `ScpMlsGroup` holds the MLS group state, the provider (crypto + storage),
/// and the local member's signing key. It exposes SCP-specific lifecycle
/// operations: create, add member, remove member, destroy.
///
/// # Ownership
///
/// Each `ScpMlsGroup` owns its provider and signer. The provider contains
/// the in-memory storage for this group's MLS state. The signer is the local
/// member's Ed25519 signing key used for MLS commits and proposals.
///
/// See ADR-001 for the MLS wrapper design.
pub struct ScpMlsGroup {
    /// The underlying `OpenMLS` group. `None` after [`destroy_group`]
    /// drops the MLS state (tree secrets, epoch keys, etc.).
    pub(crate) group: Option<MlsGroup>,
    /// The MLS provider (crypto + storage) for this group.
    pub(crate) provider: ScpMlsProvider,
    /// The local member's Ed25519 signing key pair, wrapped in
    /// [`ZeroizingSigner`] for best-effort zeroization on drop.
    /// Inner `Option` is `None` after [`destroy_group`] drops the
    /// private key material.
    pub(crate) signer: ZeroizingSigner,
    /// Whether the group has been destroyed.
    pub(crate) destroyed: bool,
}

impl ScpMlsGroup {
    /// Returns a reference to the underlying `OpenMLS` `MlsGroup`.
    ///
    /// Use this for read-only inspection of group state (members, epoch, etc.).
    /// Mutable operations should go through the wrapper methods.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::GroupDestroyed`] if the group has been destroyed.
    pub fn inner(&self) -> Result<&MlsGroup, MlsError> {
        self.group.as_ref().ok_or(MlsError::GroupDestroyed)
    }

    /// Returns a reference to the provider for this group.
    #[must_use]
    pub const fn provider(&self) -> &ScpMlsProvider {
        &self.provider
    }

    /// Returns the group's current epoch number.
    ///
    /// The epoch advances with each Commit (add member, remove member, update).
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::GroupDestroyed`] if the group has been destroyed.
    pub fn epoch(&self) -> Result<u64, MlsError> {
        let g = self.group.as_ref().ok_or(MlsError::GroupDestroyed)?;
        Ok(g.epoch().as_u64())
    }

    /// Returns the group ID as bytes.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::GroupDestroyed`] if the group has been destroyed.
    pub fn group_id(&self) -> Result<&[u8], MlsError> {
        let g = self.group.as_ref().ok_or(MlsError::GroupDestroyed)?;
        Ok(g.group_id().as_slice())
    }

    /// Returns the list of group members.
    ///
    /// Each member includes their leaf index, credential, and public keys.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::GroupDestroyed`] if the group has been destroyed.
    pub fn members(&self) -> Result<Vec<Member>, MlsError> {
        let g = self.group.as_ref().ok_or(MlsError::GroupDestroyed)?;
        Ok(g.members().collect())
    }

    /// Returns the local member's own leaf index in the group tree.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::GroupDestroyed`] if the group has been destroyed.
    pub fn own_leaf_index(&self) -> Result<LeafNodeIndex, MlsError> {
        let g = self.group.as_ref().ok_or(MlsError::GroupDestroyed)?;
        Ok(g.own_leaf_index())
    }

    /// Signs data using the local member's MLS signing key.
    ///
    /// This is the key that `open_envelope` resolves from the MLS group tree
    /// when verifying inner envelope signatures (SCP-177). Inner envelopes
    /// must be signed with this key for `open_envelope` verification to pass.
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::GroupDestroyed`] if the group has been destroyed.
    /// Returns [`MlsError::EncryptionFailed`] if signing fails.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, MlsError> {
        let signer = self.signer.as_ref().ok_or(MlsError::GroupDestroyed)?;
        openmls_traits::signatures::Signer::sign(signer, data)
            .map_err(|e| MlsError::EncryptionFailed(format!("signing failed: {e:?}")))
    }

    /// Returns the local member's MLS signing public key bytes.
    ///
    /// This is the Ed25519 public key stored in the member's leaf node in the
    /// MLS tree. `open_envelope` resolves this key from the sender's leaf node
    /// to verify inner envelope signatures (SCP-177).
    ///
    /// # Errors
    ///
    /// Returns [`MlsError::GroupDestroyed`] if the group has been destroyed.
    pub fn signer_public_key(&self) -> Result<Vec<u8>, MlsError> {
        let signer = self.signer.as_ref().ok_or(MlsError::GroupDestroyed)?;
        Ok(signer.to_public_vec())
    }
}

/// Creates a new MLS group with the creator as the sole member.
///
/// The group uses [`SCP_CIPHERSUITE`]
/// (`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`) and starts at epoch 0.
/// The creator's identity is embedded in the group via an [`ScpCredential`]
/// containing their DID and optional UCAN token.
///
/// # Arguments
///
/// * `credential` - The creator's SCP credential (DID + optional UCAN).
///
/// # Returns
///
/// An [`ScpMlsGroup`] wrapping the newly created `OpenMLS` group. The group
/// has exactly one member: the creator.
///
/// # Errors
///
/// Returns [`MlsError::CredentialSerializationFailed`] if the credential
/// cannot be serialized. Returns [`MlsError::GroupCreationFailed`] if
/// `OpenMLS` group creation fails.
///
/// See ADR-001 acceptance criterion 1.
pub fn create_group(credential: &ScpCredential) -> Result<ScpMlsGroup, MlsError> {
    let provider = ScpMlsProvider::default();

    // Generate an Ed25519 signing key pair for the creator.
    let signer = SignatureKeyPair::new(SCP_CIPHERSUITE.signature_algorithm())
        .map_err(|e| MlsError::GroupCreationFailed(format!("signature key generation: {e}")))?;

    // Store the signer's keys in the provider's key store so OpenMLS can
    // look them up during group operations.
    signer
        .store(provider.storage())
        .map_err(|e| MlsError::StorageError(format!("storing signature key: {e}")))?;

    // Serialize the SCP credential into the MLS BasicCredential identity field.
    let credential_bytes = credential.to_bytes()?;
    let basic_credential = BasicCredential::new(credential_bytes);
    let credential_with_key = CredentialWithKey {
        credential: basic_credential.into(),
        signature_key: signer.to_public_vec().into(),
    };

    // Configure the group with the SCP ciphersuite. The ratchet tree
    // extension is enabled so that Welcome messages include the full tree,
    // allowing new members to join without out-of-band tree distribution.
    let group_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(SCP_CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build();

    // Create the MLS group with the creator as the sole member.
    let group = MlsGroup::new(
        &provider,
        &signer,
        &group_create_config,
        credential_with_key,
    )
    .map_err(|e| MlsError::GroupCreationFailed(e.to_string()))?;

    Ok(ScpMlsGroup {
        group: Some(group),
        provider,
        signer: ZeroizingSigner::new(signer),
        destroyed: false,
    })
}

/// The result of adding a member to an MLS group.
///
/// Contains the MLS messages that must be distributed to complete the
/// add operation: a Welcome message for the new member and a Commit
/// message for existing members.
pub struct AddMemberResult {
    /// The MLS Commit message that advances the group epoch.
    /// Must be sent to all existing group members.
    pub commit: MlsMessageOut,
    /// The MLS Welcome message, HPKE-encrypted to the new member's
    /// `KeyPackage`. Contains all group state the new member needs to
    /// decrypt future messages.
    pub welcome: MlsMessageOut,
    /// Optional group info that may be needed by external parties.
    pub group_info: Option<GroupInfo>,
}

/// Adds a member to the group using their pre-published `KeyPackage`.
///
/// The operation produces a Commit (epoch advance) and a Welcome message.
/// The Welcome is HPKE-encrypted to the new member's `KeyPackage` and contains
/// all group state they need to participate. After this call returns
/// successfully, the pending commit has been merged and the group epoch has
/// advanced.
///
/// # Arguments
///
/// * `group` - The MLS group to add the member to. Must be active.
/// * `key_package` - The new member's pre-published `KeyPackage`, signed by
///   their Ed25519 key and containing their SCP credential.
///
/// # Returns
///
/// An [`AddMemberResult`] containing the Commit and Welcome messages.
///
/// # Errors
///
/// Returns [`MlsError::GroupDestroyed`] if the group has been destroyed.
/// Returns [`MlsError::AddMemberFailed`] if `OpenMLS` rejects the add operation.
/// Returns [`MlsError::MergePendingCommitFailed`] if committing fails.
///
/// See ADR-001 acceptance criterion 2.
pub fn add_member(
    group: &mut ScpMlsGroup,
    key_package: KeyPackageIn,
) -> Result<AddMemberResult, MlsError> {
    // Validate the key package.
    let verified_key_package = key_package
        .validate(group.provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|e| MlsError::AddMemberFailed(format!("key package validation: {e}")))?;

    let signer = group.signer.as_ref().ok_or(MlsError::GroupDestroyed)?;
    let g = group.group.as_mut().ok_or(MlsError::GroupDestroyed)?;

    // Add the member to the group. Returns (commit, welcome, group_info).
    // Both commit and welcome are MlsMessageOut.
    let (commit, welcome, group_info) = g
        .add_members(
            &group.provider,
            signer,
            core::slice::from_ref(&verified_key_package),
        )
        .map_err(|e| MlsError::AddMemberFailed(e.to_string()))?;

    // Merge the pending commit to advance the group epoch locally.
    let g = group.group.as_mut().ok_or(MlsError::GroupDestroyed)?;
    g.merge_pending_commit(&group.provider)
        .map_err(|e| MlsError::MergePendingCommitFailed(e.to_string()))?;

    Ok(AddMemberResult {
        commit,
        welcome,
        group_info,
    })
}

/// The result of removing a member from an MLS group.
///
/// Contains the Commit message that must be distributed to remaining members
/// to advance the epoch and ratchet to new key material.
pub struct RemoveMemberResult {
    /// The MLS Commit message that advances the group epoch.
    /// Must be sent to all remaining group members. The removed member
    /// cannot derive new epoch keys from this Commit.
    pub commit: MlsMessageOut,
    /// Optional group info.
    pub group_info: Option<GroupInfo>,
}

/// Removes a member from the group by their leaf index.
///
/// The operation produces a Commit that advances the epoch. All remaining
/// members ratchet to new key material. The removed member cannot derive
/// new epoch keys. Cost is O(log n) via MLS tree structure.
///
/// After this call returns successfully, the pending commit has been merged
/// and the group epoch has advanced.
///
/// # Arguments
///
/// * `group` - The MLS group to remove the member from. Must be active.
/// * `leaf_index` - The leaf index of the member to remove. Obtain this from
///   the group's member list via [`ScpMlsGroup::members`].
///
/// # Returns
///
/// A [`RemoveMemberResult`] containing the Commit message.
///
/// # Errors
///
/// Returns [`MlsError::GroupDestroyed`] if the group has been destroyed.
/// Returns [`MlsError::RemoveMemberFailed`] if `OpenMLS` rejects the remove
/// operation (e.g., invalid leaf index, removing self).
/// Returns [`MlsError::MergePendingCommitFailed`] if committing fails.
///
/// See ADR-001 acceptance criterion 3.
pub fn remove_member(
    group: &mut ScpMlsGroup,
    leaf_index: LeafNodeIndex,
) -> Result<RemoveMemberResult, MlsError> {
    let signer = group.signer.as_ref().ok_or(MlsError::GroupDestroyed)?;
    let g = group.group.as_mut().ok_or(MlsError::GroupDestroyed)?;

    // Remove the member. Returns (commit, optional_welcome, group_info).
    let (commit, _welcome, group_info) = g
        .remove_members(&group.provider, signer, core::slice::from_ref(&leaf_index))
        .map_err(|e| MlsError::RemoveMemberFailed(e.to_string()))?;

    // Merge the pending commit to advance the group epoch locally.
    let g = group.group.as_mut().ok_or(MlsError::GroupDestroyed)?;
    g.merge_pending_commit(&group.provider)
        .map_err(|e| MlsError::MergePendingCommitFailed(e.to_string()))?;

    Ok(RemoveMemberResult { commit, group_info })
}

/// Destroys all MLS group state.
///
/// After destruction, the group cannot be used for any operation. All tree
/// secrets, epoch key schedules, and application key material are released.
/// Historical messages encrypted under this group become physically unreadable
/// once the in-memory state is dropped.
///
/// This is the operation triggered by ephemeral context closure (spec
/// section 9.7.2).
///
/// # Arguments
///
/// * `group` - The MLS group to destroy.
///
/// # Errors
///
/// Returns [`MlsError::GroupDestroyed`] if the group has already been
/// destroyed.
///
/// See ADR-001 acceptance criterion 9.
pub fn destroy_group(group: &mut ScpMlsGroup) -> Result<(), MlsError> {
    if group.destroyed {
        return Err(MlsError::GroupDestroyed);
    }

    // Eagerly drop cryptographic state. `Option::take` moves the value out,
    // leaving `None`, and the taken value is dropped at the end of the
    // statement. This releases:
    //   - MlsGroup: tree secrets, epoch key schedules, ratchet state
    //   - SignatureKeyPair: Ed25519 private key (Vec<u8>)
    drop(group.group.take());
    drop(group.signer.take());

    // Replace the provider with a fresh empty instance. The old provider's
    // MemoryStorage contains encryption key pairs, key packages, and other
    // MLS artifacts — dropping it releases all of that key material.
    group.provider = ScpMlsProvider::default();

    // Mark the group as destroyed so all future operations are rejected.
    group.destroyed = true;

    Ok(())
}

/// Generates a `KeyPackage` for a participant, suitable for offline member
/// addition.
///
/// The `KeyPackage` is signed by the participant's Ed25519 key and contains
/// their SCP credential. It uses [`SCP_CIPHERSUITE`].
///
/// # Arguments
///
/// * `credential` - The participant's SCP credential (DID + optional UCAN).
///
/// # Returns
///
/// A tuple of (`KeyPackageBundle`, `SignatureKeyPair`, `ScpMlsProvider`).
/// The `KeyPackageBundle` contains the public `KeyPackage` that should be
/// published, plus private keys stored in the provider. The provider and
/// signer must be retained by the participant to later join a group via a
/// Welcome message.
///
/// # Errors
///
/// Returns [`MlsError::CredentialSerializationFailed`] if the credential
/// cannot be serialized.
/// Returns [`MlsError::KeyPackageGenerationFailed`] if key package
/// generation fails.
pub fn generate_key_package(
    credential: &ScpCredential,
) -> Result<(KeyPackageBundle, SignatureKeyPair, ScpMlsProvider), MlsError> {
    let provider = ScpMlsProvider::default();

    let signer = SignatureKeyPair::new(SCP_CIPHERSUITE.signature_algorithm())
        .map_err(|e| MlsError::KeyPackageGenerationFailed(format!("signer generation: {e}")))?;

    signer
        .store(provider.storage())
        .map_err(|e| MlsError::StorageError(format!("storing signature key: {e}")))?;

    let credential_bytes = credential.to_bytes()?;
    let basic_credential = BasicCredential::new(credential_bytes);
    let credential_with_key = CredentialWithKey {
        credential: basic_credential.into(),
        signature_key: signer.to_public_vec().into(),
    };

    let key_package_bundle = KeyPackage::builder()
        .build(SCP_CIPHERSUITE, &provider, &signer, credential_with_key)
        .map_err(|e| MlsError::KeyPackageGenerationFailed(e.to_string()))?;

    Ok((key_package_bundle, signer, provider))
}

/// Joins a group from a Welcome message received after being added.
///
/// The new member processes the Welcome message to reconstruct the group
/// state and become an active participant. The Welcome contains all group
/// state the new member needs to decrypt future messages.
///
/// # Arguments
///
/// * `welcome` - A reference to the Welcome message (as `MlsMessageOut`)
///   from the add operation's [`AddMemberResult`].
/// * `provider` - The MLS provider that holds the new member's key material
///   (from [`generate_key_package`]).
/// * `signer` - The new member's signing key pair (from [`generate_key_package`]).
///
/// # Returns
///
/// An [`ScpMlsGroup`] wrapping the joined group.
///
/// # Errors
///
/// Returns [`MlsError::WelcomeProcessingFailed`] if the Welcome message
/// cannot be processed.
pub fn join_group(
    welcome: &MlsMessageOut,
    provider: ScpMlsProvider,
    signer: SignatureKeyPair,
) -> Result<ScpMlsGroup, MlsError> {
    // Serialize MlsMessageOut to bytes, then deserialize as MlsMessageIn.
    // This is the production-path conversion (no test-utils feature required).
    let serialized = welcome
        .tls_serialize_detached()
        .map_err(|e| MlsError::WelcomeProcessingFailed(format!("serializing welcome: {e}")))?;

    let welcome_in = MlsMessageIn::tls_deserialize(&mut serialized.as_slice())
        .map_err(|e| MlsError::WelcomeProcessingFailed(format!("deserializing welcome: {e}")))?;

    // Extract the Welcome from the MlsMessageIn body.
    let welcome_body = welcome_in.extract();
    let MlsMessageBodyIn::Welcome(welcome) = welcome_body else {
        return Err(MlsError::WelcomeProcessingFailed(
            "message is not a Welcome".to_string(),
        ));
    };

    let join_config = MlsGroupJoinConfig::builder().build();

    let staged_welcome = StagedWelcome::new_from_welcome(&provider, &join_config, welcome, None)
        .map_err(|e| MlsError::WelcomeProcessingFailed(e.to_string()))?;

    let group = staged_welcome
        .into_group(&provider)
        .map_err(|e| MlsError::WelcomeProcessingFailed(e.to_string()))?;

    Ok(ScpMlsGroup {
        group: Some(group),
        provider,
        signer: ZeroizingSigner::new(signer),
        destroyed: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::unwrap_used)]
    fn test_credential(name: &str) -> ScpCredential {
        ScpCredential::new(format!("did:dht:z6Mk{name}"), None).unwrap()
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn create_group_returns_group_with_one_member() {
        let cred = test_credential("alice");
        let group = create_group(&cred).unwrap();

        let members = group.members().unwrap();
        assert_eq!(members.len(), 1, "group should have exactly one member");

        let epoch = group.epoch().unwrap();
        assert_eq!(epoch, 0, "new group should be at epoch 0");
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn create_group_uses_scp_ciphersuite() {
        let cred = test_credential("alice");
        let group = create_group(&cred).unwrap();

        let inner = group.inner().unwrap();
        assert_eq!(
            inner.ciphersuite(),
            SCP_CIPHERSUITE,
            "group must use SCP ciphersuite"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn create_group_embeds_scp_credential() {
        let cred = test_credential("alice");
        let group = create_group(&cred).unwrap();

        let members = group.members().unwrap();
        assert_eq!(members.len(), 1);

        let member = &members[0];
        let basic_cred = BasicCredential::try_from(member.credential.clone()).unwrap();
        let decoded = ScpCredential::from_bytes(basic_cred.identity()).unwrap();
        assert_eq!(decoded.did, cred.did);
        assert_eq!(decoded.ucan_token, cred.ucan_token);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn add_member_returns_welcome_and_commit() {
        let alice_cred = test_credential("alice");
        let mut alice_group = create_group(&alice_cred).unwrap();

        let bob_cred = test_credential("bob");
        let (bob_kp_bundle, _bob_signer, _bob_provider) = generate_key_package(&bob_cred).unwrap();

        let bob_kp: KeyPackageIn = bob_kp_bundle.key_package().clone().into();
        let result = add_member(&mut alice_group, bob_kp).unwrap();

        // Verify we got both messages.
        assert!(
            !result.commit.tls_serialize_detached().unwrap().is_empty(),
            "commit message should not be empty"
        );
        assert!(
            !result.welcome.tls_serialize_detached().unwrap().is_empty(),
            "welcome message should not be empty"
        );

        // Verify epoch advanced.
        let epoch = alice_group.epoch().unwrap();
        assert_eq!(epoch, 1, "epoch should advance to 1 after add");

        // Verify member count increased.
        let members = alice_group.members().unwrap();
        assert_eq!(members.len(), 2, "group should have two members after add");
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn add_member_welcome_allows_joining() {
        let alice_cred = test_credential("alice");
        let mut alice_group = create_group(&alice_cred).unwrap();

        let bob_cred = test_credential("bob");
        let (bob_kp_bundle, bob_signer, bob_provider) = generate_key_package(&bob_cred).unwrap();

        let bob_kp: KeyPackageIn = bob_kp_bundle.key_package().clone().into();
        let result = add_member(&mut alice_group, bob_kp).unwrap();

        // Bob joins using the Welcome message.
        let bob_group = join_group(&result.welcome, bob_provider, bob_signer).unwrap();

        // Both Alice and Bob should see 2 members.
        let alice_members = alice_group.members().unwrap();
        let bob_members = bob_group.members().unwrap();
        assert_eq!(alice_members.len(), 2);
        assert_eq!(bob_members.len(), 2);

        // Both should be at epoch 1.
        assert_eq!(alice_group.epoch().unwrap(), 1);
        assert_eq!(bob_group.epoch().unwrap(), 1);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn remove_member_advances_epoch() {
        let alice_cred = test_credential("alice");
        let mut alice_group = create_group(&alice_cred).unwrap();

        // Add Bob.
        let bob_cred = test_credential("bob");
        let (bob_kp_bundle, _bob_signer, _bob_provider) = generate_key_package(&bob_cred).unwrap();
        let bob_kp: KeyPackageIn = bob_kp_bundle.key_package().clone().into();
        let _add_result = add_member(&mut alice_group, bob_kp).unwrap();

        // Epoch should be 1 after add.
        assert_eq!(alice_group.epoch().unwrap(), 1);

        // Find Bob's leaf index (not Alice's own).
        let alice_own_index = alice_group.own_leaf_index().unwrap();
        let members = alice_group.members().unwrap();
        let bob_member = members.iter().find(|m| m.index != alice_own_index).unwrap();

        // Remove Bob.
        let remove_result = remove_member(&mut alice_group, bob_member.index).unwrap();

        // Verify epoch advanced to 2.
        assert_eq!(alice_group.epoch().unwrap(), 2);

        // Verify only Alice remains.
        let members = alice_group.members().unwrap();
        assert_eq!(members.len(), 1, "only alice should remain");

        // Verify commit is non-empty.
        assert!(
            !remove_result
                .commit
                .tls_serialize_detached()
                .unwrap()
                .is_empty(),
            "commit should not be empty"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn destroy_group_prevents_further_operations() {
        let cred = test_credential("alice");
        let mut group = create_group(&cred).unwrap();

        destroy_group(&mut group).unwrap();

        // All operations should return GroupDestroyed.
        assert!(group.epoch().is_err());
        assert!(group.members().is_err());
        assert!(group.group_id().is_err());
        assert!(group.inner().is_err());
        assert!(group.own_leaf_index().is_err());

        // Double destroy should also error.
        assert!(destroy_group(&mut group).is_err());
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn destroy_group_releases_crypto_state() {
        let cred = test_credential("alice");
        let mut group = create_group(&cred).unwrap();

        // Before destroy: group and signer are Some.
        assert!(group.group.is_some());
        assert!(group.signer.is_some());

        destroy_group(&mut group).unwrap();

        // After destroy: group and signer are None, provider is fresh.
        assert!(
            group.group.is_none(),
            "MLS group must be dropped on destroy"
        );
        assert!(
            group.signer.is_none(),
            "signing key must be dropped on destroy"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn destroy_group_then_add_member_fails() {
        let cred = test_credential("alice");
        let mut group = create_group(&cred).unwrap();
        destroy_group(&mut group).unwrap();

        let bob_cred = test_credential("bob");
        let (bob_kp_bundle, _signer, _provider) = generate_key_package(&bob_cred).unwrap();
        let bob_kp: KeyPackageIn = bob_kp_bundle.key_package().clone().into();

        let result = add_member(&mut group, bob_kp);
        assert!(result.is_err());
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn generate_key_package_produces_valid_package() {
        let cred = test_credential("bob");
        let (kp_bundle, _signer, _provider) = generate_key_package(&cred).unwrap();

        // The key package should use the SCP ciphersuite.
        assert_eq!(
            kp_bundle.key_package().ciphersuite(),
            SCP_CIPHERSUITE,
            "key package must use SCP ciphersuite"
        );
    }
}
