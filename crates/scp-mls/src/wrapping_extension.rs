//! MLS `LeafNode` `scp_wrapping_key` extension for stable wrapping keypairs.
//!
//! Each member in an SCP context maintains a single dedicated X25519 keypair
//! used exclusively for HPKE wrapping of sender key distributions (§9.16.1,
//! §9.16.2). The public key is published as an MLS `LeafNode` extension named
//! `scp_wrapping_key` so that other members can read it from the MLS tree
//! when processing [`SenderKeyRequest`](scp_protocol::crypto::sender_keys::SenderKeyRequest)
//! messages.
//!
//! # Extension Type ID
//!
//! Uses `0xFF01` from the RFC 9420 §17.3 private-use range (`0xFF00–0xFFFF`).
//!
//! # Stability
//!
//! The wrapping keypair does NOT rotate on MLS Updates or epoch advances. It
//! remains stable across epochs so that sender key distributions can always
//! be unwrapped, even by members who are offline during epoch transitions.
//! The wrapping keypair rotates only on:
//!
//! 1. Identity key rotation (§9.12).
//! 2. Suspected compromise.
//!
//! On rotation, the member publishes the new wrapping public key in their
//! `LeafNode` extension via an MLS Update and re-distributes their current
//! sender key to all non-blocked members using the new wrapping keys.
//!
//! See spec §9.16.1 for the full design.

use openmls::prelude::*;

use crate::error::MlsError;

/// Extension type ID for `scp_wrapping_key` in the RFC 9420 §17.3
/// private-use range.
pub const SCP_WRAPPING_KEY_EXTENSION_TYPE: u16 = 0xFF01;

/// Size of the raw X25519 public key in bytes.
const X25519_PUBLIC_KEY_SIZE: usize = 32;

/// Creates an `Extension::Unknown` containing the `scp_wrapping_key` extension
/// with the given 32-byte X25519 public key.
///
/// # Panics
///
/// Panics (debug only) if `public_key` is not exactly 32 bytes.
#[must_use]
pub fn make_wrapping_key_extension(public_key: &[u8; X25519_PUBLIC_KEY_SIZE]) -> Extension {
    Extension::Unknown(
        SCP_WRAPPING_KEY_EXTENSION_TYPE,
        UnknownExtension(public_key.to_vec()),
    )
}

/// Extracts the 32-byte X25519 wrapping public key from an
/// `scp_wrapping_key` extension, if present.
///
/// Returns `None` if the extension is not present. Returns an error if
/// the extension is present but the payload is not exactly 32 bytes.
///
/// # Errors
///
/// Returns [`MlsError::ExtensionError`] if the extension data is malformed.
pub fn extract_wrapping_key(
    extensions: &Extensions<LeafNode>,
) -> Result<Option<[u8; X25519_PUBLIC_KEY_SIZE]>, MlsError> {
    let unknown = extensions.unknown(SCP_WRAPPING_KEY_EXTENSION_TYPE);
    match unknown {
        None => Ok(None),
        Some(ext) => {
            let bytes: [u8; X25519_PUBLIC_KEY_SIZE] =
                ext.0.as_slice().try_into().map_err(|_| {
                    MlsError::ExtensionError(format!(
                        "scp_wrapping_key extension must be {X25519_PUBLIC_KEY_SIZE} bytes, got {}",
                        ext.0.len()
                    ))
                })?;
            Ok(Some(bytes))
        }
    }
}

/// Builds `Capabilities` that include support for the `scp_wrapping_key`
/// extension type, in addition to the SCP ciphersuite defaults.
///
/// `OpenMLS` validates that any extension present on a `LeafNode` has its
/// type listed in the node's capabilities (`valn0107`). This function
/// constructs capabilities with `ExtensionType::Unknown(0xFF01)` declared.
#[must_use]
pub fn scp_capabilities_with_wrapping_key() -> Capabilities {
    Capabilities::new(
        None, // default versions
        None, // default ciphersuites
        Some(&[ExtensionType::Unknown(SCP_WRAPPING_KEY_EXTENSION_TYPE)]),
        None, // default proposals
        None, // default credentials
    )
}

/// Builds `LeafNodeParameters` containing the `scp_wrapping_key` extension.
///
/// Used by [`propose_update_with_wrapping_key`](crate::ratchet::propose_update_with_wrapping_key)
/// to preserve the wrapping key across MLS Update proposals, and by
/// identity key rotation to publish a new wrapping key.
///
/// # Errors
///
/// Returns [`MlsError::ExtensionError`] if the extension list cannot be
/// constructed.
pub fn leaf_node_params_with_wrapping_key(
    wrapping_pubkey: &[u8; X25519_PUBLIC_KEY_SIZE],
) -> Result<LeafNodeParameters, MlsError> {
    let ext = make_wrapping_key_extension(wrapping_pubkey);

    let extensions = Extensions::<LeafNode>::single(ext).map_err(|e| {
        MlsError::ExtensionError(format!("failed to create wrapping key extension list: {e}"))
    })?;

    Ok(LeafNodeParameters::builder()
        .with_extensions(extensions)
        .build())
}

/// Extracts the `scp_wrapping_key` from the local member's own `LeafNode`.
///
/// Reads the own leaf node's extensions and returns the 32-byte X25519
/// public key if present.
///
/// # Errors
///
/// Returns [`MlsError::GroupDestroyed`] if the group has been destroyed.
/// Returns [`MlsError::MemberNotFound`] if the own leaf node is unavailable.
/// Returns [`MlsError::ExtensionError`] if the extension data is malformed.
pub fn extract_own_wrapping_key(
    group: &crate::group::ScpMlsGroup,
) -> Result<Option<[u8; X25519_PUBLIC_KEY_SIZE]>, MlsError> {
    let g = group.inner()?;
    let own_index = g.own_leaf_index().u32();
    let leaf = g
        .own_leaf_node()
        .ok_or(MlsError::MemberNotFound(own_index))?;
    extract_wrapping_key(leaf.extensions())
}

/// Extracts the `scp_wrapping_key` from a member's `LeafNode`, identified by
/// their DID in the SCP credential.
///
/// For the local member, reads `own_leaf_node()` directly which provides
/// full access to the `LeafNode` extensions. For remote members, the wrapping
/// public key should be obtained from the `ProtocolRepository` where it was
/// persisted at join time, since `OpenMLS` does not expose other members'
/// `LeafNode` extensions through its public API.
///
/// # Errors
///
/// Returns [`MlsError::GroupDestroyed`] if the group has been destroyed.
/// Returns [`MlsError::MemberNotFound`] if the local member's DID does not
///   match `target_did` (use `ProtocolRepository::load_wrapping_public_key` for
///   remote members instead).
/// Returns [`MlsError::ExtensionError`] if the extension data is malformed.
pub fn extract_member_wrapping_key(
    group: &crate::group::ScpMlsGroup,
    target_did: &str,
) -> Result<Option<[u8; X25519_PUBLIC_KEY_SIZE]>, MlsError> {
    let g = group.inner()?;

    // Check if target is the local member — we can access own leaf node.
    if let Some(own_leaf) = g.own_leaf_node()
        && let Ok(basic) = BasicCredential::try_from(own_leaf.credential().clone())
        && let Ok(cred) = crate::credential::ScpCredential::from_bytes(basic.identity())
        && cred.did == target_did
    {
        return extract_wrapping_key(own_leaf.extensions());
    }

    // Remote members' extensions are not accessible through OpenMLS's public
    // API. The caller should use ProtocolRepository::load_wrapping_public_key()
    // for remote members' wrapping keys.
    Err(MlsError::MemberNotFound(u32::MAX))
}

/// Finds a member's leaf index by their DID in the SCP credential.
///
/// Iterates over all group members, deserializes each member's
/// `ScpCredential`, and returns the `LeafNodeIndex` of the member
/// whose DID matches `target_did`.
///
/// # Errors
///
/// Returns [`MlsError::MemberNotFound`] if no member with the given DID
/// is found in the group.
pub fn find_leaf_index_by_did(
    group: &MlsGroup,
    target_did: &str,
) -> Result<LeafNodeIndex, MlsError> {
    for member in group.members() {
        if let Ok(basic) = BasicCredential::try_from(member.credential.clone())
            && let Ok(cred) = crate::credential::ScpCredential::from_bytes(basic.identity())
            && cred.did == target_did
        {
            return Ok(member.index);
        }
    }
    Err(MlsError::MemberNotFound(u32::MAX))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::doc_markdown)]
mod tests {
    use super::*;

    #[test]
    fn make_and_extract_wrapping_key_roundtrip() {
        let key = [42u8; 32];
        let ext = make_wrapping_key_extension(&key);

        assert_eq!(
            ext.extension_type(),
            ExtensionType::Unknown(SCP_WRAPPING_KEY_EXTENSION_TYPE)
        );

        // Build an Extensions<LeafNode> with the wrapping key.
        let extensions = Extensions::<LeafNode>::single(ext).unwrap();
        let extracted = extract_wrapping_key(&extensions).unwrap();
        assert_eq!(extracted, Some(key));
    }

    #[test]
    fn extract_wrapping_key_returns_none_when_absent() {
        let extensions = Extensions::<LeafNode>::default();
        let extracted = extract_wrapping_key(&extensions).unwrap();
        assert_eq!(extracted, None);
    }

    #[test]
    fn extract_wrapping_key_rejects_wrong_size() {
        let ext = Extension::Unknown(
            SCP_WRAPPING_KEY_EXTENSION_TYPE,
            UnknownExtension(vec![1, 2, 3]), // only 3 bytes, not 32
        );
        let extensions = Extensions::<LeafNode>::single(ext).unwrap();
        let result = extract_wrapping_key(&extensions);
        assert!(result.is_err());
    }

    #[test]
    fn scp_capabilities_contains_wrapping_key_type() {
        let caps = scp_capabilities_with_wrapping_key();
        assert!(
            caps.extensions()
                .contains(&ExtensionType::Unknown(SCP_WRAPPING_KEY_EXTENSION_TYPE)),
            "capabilities must list scp_wrapping_key extension type"
        );
    }

    #[test]
    fn leaf_node_params_with_wrapping_key_creates_valid_params() {
        let key = [7u8; 32];
        let params = leaf_node_params_with_wrapping_key(&key).unwrap();
        let extensions = params.extensions().unwrap();
        let extracted = extract_wrapping_key(extensions).unwrap();
        assert_eq!(extracted, Some(key));
    }

    // -----------------------------------------------------------------------
    // MLS group integration tests
    // -----------------------------------------------------------------------

    fn test_credential(name: &str) -> crate::credential::ScpCredential {
        crate::credential::ScpCredential::new(
            format!("did:dht:z6Mk{name}"),
            None,
            scp_primitives::SigningKeyId::Active,
        )
        .unwrap()
    }

    /// AC: join context -> extract LeafNode -> scp_wrapping_key present with
    /// 32-byte X25519 public key.
    #[test]
    fn create_group_with_wrapping_key_includes_extension() {
        let cred = test_credential("alice");
        let wrapping_key = [0xAA_u8; 32];

        let group =
            crate::group::create_group_with_wrapping_key(&cred, Some(&wrapping_key)).unwrap();

        // Extract the own wrapping key from the LeafNode.
        let extracted = extract_own_wrapping_key(&group).unwrap();
        assert_eq!(
            extracted,
            Some(wrapping_key),
            "own leaf node must contain scp_wrapping_key extension"
        );
    }

    /// AC: join context (via KeyPackage) -> extract LeafNode -> scp_wrapping_key
    /// present.
    #[test]
    fn key_package_with_wrapping_key_carries_extension_through_join() {
        let alice_cred = test_credential("alice");
        let alice_wrapping = [0xAA_u8; 32];
        let mut alice_group =
            crate::group::create_group_with_wrapping_key(&alice_cred, Some(&alice_wrapping))
                .unwrap();

        let bob_cred = test_credential("bob");
        let bob_wrapping = [0xBB_u8; 32];
        let (bob_kp, bob_signer, bob_provider) =
            crate::group::generate_key_package_with_wrapping_key(&bob_cred, Some(&bob_wrapping))
                .unwrap();

        let bob_kp_in: KeyPackageIn = bob_kp.key_package().clone().into();
        let add_result = crate::group::add_member(&mut alice_group, bob_kp_in).unwrap();

        let bob_group =
            crate::group::join_group(&add_result.welcome, bob_provider, bob_signer).unwrap();

        // Bob's own wrapping key should be present after joining.
        let bob_extracted = extract_own_wrapping_key(&bob_group).unwrap();
        assert_eq!(
            bob_extracted,
            Some(bob_wrapping),
            "Bob's own leaf node must contain scp_wrapping_key after joining"
        );
    }

    /// AC: advance MLS epoch via Commit -> extract LeafNode -> scp_wrapping_key
    /// is identical to pre-advance value.
    #[test]
    fn wrapping_key_stable_across_epoch_advance() {
        let alice_cred = test_credential("alice");
        let wrapping_key = [0xCC_u8; 32];
        let mut alice_group =
            crate::group::create_group_with_wrapping_key(&alice_cred, Some(&wrapping_key)).unwrap();

        // Add Bob to enable epoch advance.
        let bob_cred = test_credential("bob");
        let bob_wrapping = [0xDD_u8; 32];
        let (bob_kp, bob_signer, bob_provider) =
            crate::group::generate_key_package_with_wrapping_key(&bob_cred, Some(&bob_wrapping))
                .unwrap();
        let bob_kp_in: KeyPackageIn = bob_kp.key_package().clone().into();
        let add_result = crate::group::add_member(&mut alice_group, bob_kp_in).unwrap();

        let mut bob_group =
            crate::group::join_group(&add_result.welcome, bob_provider, bob_signer).unwrap();

        // Alice performs an update WITH her wrapping key to preserve it.
        let commit =
            crate::ratchet::propose_update_with_wrapping_key(&mut alice_group, &wrapping_key)
                .unwrap();
        let commit_bytes = crate::ratchet::serialize_mls_message(&commit).unwrap();

        // Bob processes Alice's commit.
        let mut grace_store = crate::epoch_grace::EpochGraceStore::new();
        crate::ratchet::process_commit(&mut bob_group, &commit_bytes, &mut grace_store).unwrap();

        // Alice's wrapping key should be unchanged after the update.
        let alice_extracted = extract_own_wrapping_key(&alice_group).unwrap();
        assert_eq!(
            alice_extracted,
            Some(wrapping_key),
            "scp_wrapping_key must remain identical after epoch advance"
        );
    }

    /// AC: rotate identity key -> new wrapping key published via MLS Update ->
    /// scp_wrapping_key has changed.
    #[test]
    fn wrapping_key_rotates_on_identity_key_rotation() {
        let cred = test_credential("alice");
        let original_key = [0xAA_u8; 32];
        let mut group =
            crate::group::create_group_with_wrapping_key(&cred, Some(&original_key)).unwrap();

        // Add Bob so we can do updates.
        let bob_cred = test_credential("bob");
        let (bob_kp, _bob_signer, _bob_provider) =
            crate::group::generate_key_package(&bob_cred).unwrap();
        let bob_kp_in: KeyPackageIn = bob_kp.key_package().clone().into();
        let _add_result = crate::group::add_member(&mut group, bob_kp_in).unwrap();

        // Simulate identity key rotation: generate a NEW wrapping key and
        // publish it via update.
        let new_key = [0xFF_u8; 32];
        let _commit =
            crate::ratchet::propose_update_with_wrapping_key(&mut group, &new_key).unwrap();

        // After the update, the wrapping key should be the new value.
        let extracted = extract_own_wrapping_key(&group).unwrap();
        assert_eq!(
            extracted,
            Some(new_key),
            "scp_wrapping_key must change after rotation"
        );
        assert_ne!(
            extracted,
            Some(original_key),
            "scp_wrapping_key must differ from original after rotation"
        );
    }
}
