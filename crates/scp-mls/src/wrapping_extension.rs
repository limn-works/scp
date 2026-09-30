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

/// Extracts the `scp_wrapping_key` that the leaf claiming `target_did`
/// publishes.
///
/// The leaf is found by [`find_leaf_index_by_did`], which holds the lookup
/// rule. The DID it matches is the leaf's self-asserted `BasicCredential`
/// identity. The returned key is the key that the one leaf claiming that DID
/// publishes: the leaf's signature binds the key to the leaf, not to a verified
/// DID. A caller that seals a secret to this key must first verify the
/// DID-to-leaf binding, which the leaf-signing and custody slice owns (ADR-057
/// T4 residual (3), the self-certifying directory; §23.13, Event Verification
/// During Reconciliation).
///
/// # Errors
///
/// Returns [`MlsError::GroupDestroyed`] if the group has been destroyed.
/// Returns [`MlsError::MemberNotFound`] if no leaf claims `target_did`, or the
///   leaf is absent from the tree.
/// Returns [`MlsError::DuplicateMemberDid`] if more than one leaf claims a
///   `target_did` that is not the local member's DID.
/// Returns [`MlsError::ExtensionError`] if the extension data is malformed.
pub fn extract_member_wrapping_key(
    group: &crate::group::ScpMlsGroup,
    target_did: &str,
) -> Result<Option<[u8; X25519_PUBLIC_KEY_SIZE]>, MlsError> {
    let g = group.inner()?;
    let idx = find_leaf_index_by_did(g, target_did)?;
    let leaf = g
        .public_group()
        .leaf(idx)
        .ok_or_else(|| MlsError::MemberNotFound(idx.u32()))?;
    extract_wrapping_key(leaf.extensions())
}

/// The DID in an SCP `BasicCredential`, or `None` when the credential is not
/// one.
fn credential_did(credential: &Credential) -> Option<String> {
    let basic = BasicCredential::try_from(credential.clone()).ok()?;
    crate::credential::ScpCredential::from_bytes(basic.identity())
        .ok()
        .map(|c| c.did)
}

/// Finds the leaf index of the leaf that claims `target_did`.
///
/// The DID is each leaf's self-asserted `BasicCredential` identity, decoded as
/// an `ScpCredential`. When `target_did` is the local member's DID, the lookup
/// resolves to the local member's own leaf, even when other leaves claim the
/// same DID. For any other DID, exactly one leaf must claim it. The returned
/// index names the leaf that claims the DID, not a leaf verified to belong to
/// the DID's holder: nothing here binds a DID to a leaf. A caller that seals a
/// secret to that leaf's keys must first verify the DID-to-leaf binding, which
/// the leaf-signing and custody slice owns (ADR-057 T4 residual (3), the
/// self-certifying directory; §23.13, Event Verification During
/// Reconciliation).
///
/// # Errors
///
/// Returns [`MlsError::MemberNotFound`] if no leaf claims `target_did`.
/// Returns [`MlsError::DuplicateMemberDid`] if more than one leaf claims a
///   `target_did` that is not the local member's DID.
pub fn find_leaf_index_by_did(
    group: &MlsGroup,
    target_did: &str,
) -> Result<LeafNodeIndex, MlsError> {
    if let Some(own) = group.own_leaf_node()
        && credential_did(own.credential()).as_deref() == Some(target_did)
    {
        return Ok(group.own_leaf_index());
    }
    let mut claims = group
        .members()
        .filter(|m| credential_did(&m.credential).as_deref() == Some(target_did))
        .map(|m| m.index);
    let idx = claims.next().ok_or(MlsError::MemberNotFound(u32::MAX))?;
    if claims.next().is_some() {
        return Err(MlsError::DuplicateMemberDid(target_did.to_owned()));
    }
    Ok(idx)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::doc_markdown)]
mod tests {
    use super::*;
    use scp_clock::SystemClock;

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
            scp_did::SigningKeyId::Active,
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
            crate::group::create_group_with_wrapping_key(&cred, Some(&wrapping_key), &SystemClock)
                .unwrap();

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
        let mut alice_group = crate::group::create_group_with_wrapping_key(
            &alice_cred,
            Some(&alice_wrapping),
            &SystemClock,
        )
        .unwrap();

        let bob_cred = test_credential("bob");
        let bob_wrapping = [0xBB_u8; 32];
        let (bob_kp, bob_signer, bob_provider) =
            crate::group::generate_key_package_with_wrapping_key(
                &bob_cred,
                Some(&bob_wrapping),
                &SystemClock,
            )
            .unwrap();

        let bob_kp_in: KeyPackageIn = bob_kp.key_package().clone().into();
        let add_result =
            crate::group::add_member(&mut alice_group, bob_kp_in, &SystemClock).unwrap();

        let bob_group =
            crate::group::join_group(&add_result.welcome, bob_provider, bob_signer, &SystemClock)
                .unwrap();

        // Bob's own wrapping key should be present after joining.
        let bob_extracted = extract_own_wrapping_key(&bob_group).unwrap();
        assert_eq!(
            bob_extracted,
            Some(bob_wrapping),
            "Bob's own leaf node must contain scp_wrapping_key after joining"
        );
    }

    /// Each member reads the other's stable wrapping key from the tree, and a
    /// DID that is not a member yields `MemberNotFound`.
    #[test]
    fn extract_member_wrapping_key_reads_remote_member_key() {
        let alice_cred = test_credential("alice");
        let alice_wrapping = [0xA1_u8; 32];
        let mut alice_group = crate::group::create_group_with_wrapping_key(
            &alice_cred,
            Some(&alice_wrapping),
            &SystemClock,
        )
        .unwrap();

        let bob_cred = test_credential("bob");
        let bob_wrapping = [0xB2_u8; 32];
        let (bob_kp, bob_signer, bob_provider) =
            crate::group::generate_key_package_with_wrapping_key(
                &bob_cred,
                Some(&bob_wrapping),
                &SystemClock,
            )
            .unwrap();
        let bob_kp_in: KeyPackageIn = bob_kp.key_package().clone().into();
        let add_result =
            crate::group::add_member(&mut alice_group, bob_kp_in, &SystemClock).unwrap();
        let bob_group =
            crate::group::join_group(&add_result.welcome, bob_provider, bob_signer, &SystemClock)
                .unwrap();

        assert_eq!(
            extract_member_wrapping_key(&alice_group, &bob_cred.did).unwrap(),
            Some(bob_wrapping),
            "Alice must read Bob's wrapping key from the tree"
        );
        assert_eq!(
            extract_member_wrapping_key(&bob_group, &alice_cred.did).unwrap(),
            Some(alice_wrapping),
            "Bob must read Alice's wrapping key from the tree"
        );
        assert_eq!(
            extract_member_wrapping_key(&alice_group, &alice_cred.did).unwrap(),
            Some(alice_wrapping),
            "the local member's own key is read through the same path"
        );
        let carol_cred = test_credential("carol");
        assert!(matches!(
            extract_member_wrapping_key(&alice_group, &carol_cred.did),
            Err(MlsError::MemberNotFound(_))
        ));
    }

    /// Two leaves claim Bob's DID (leaf 1, then leaf 2). A remote lookup of
    /// that DID fails closed, while the member at leaf 2 resolves its own DID to
    /// its own leaf, not to the lower-indexed leaf 1 a first-match scan returns.
    #[test]
    fn extract_member_wrapping_key_duplicate_did_fails_closed_except_for_own_did() {
        let alice_cred = test_credential("alice");
        let alice_wrapping = [0xA1_u8; 32];
        let mut alice_group = crate::group::create_group_with_wrapping_key(
            &alice_cred,
            Some(&alice_wrapping),
            &SystemClock,
        )
        .unwrap();

        let bob_cred = test_credential("bob");
        let mut add_bob = |wrapping: [u8; 32]| {
            let (kp, signer, provider) = crate::group::generate_key_package_with_wrapping_key(
                &bob_cred,
                Some(&wrapping),
                &SystemClock,
            )
            .unwrap();
            let kp_in: KeyPackageIn = kp.key_package().clone().into();
            let added = crate::group::add_member(&mut alice_group, kp_in, &SystemClock).unwrap();
            (added, signer, provider)
        };
        let _first = add_bob([0xB1_u8; 32]);
        let (second, second_signer, second_provider) = add_bob([0xB2_u8; 32]);
        let second_group = crate::group::join_group(
            &second.welcome,
            second_provider,
            second_signer,
            &SystemClock,
        )
        .unwrap();
        assert_eq!(second_group.own_leaf_index().unwrap().u32(), 2);

        assert!(matches!(
            extract_member_wrapping_key(&alice_group, &bob_cred.did),
            Err(MlsError::DuplicateMemberDid(did)) if did == bob_cred.did
        ));
        assert_eq!(
            extract_member_wrapping_key(&second_group, &bob_cred.did).unwrap(),
            Some([0xB2_u8; 32]),
            "the local member's own DID resolves to its own leaf"
        );
        assert_eq!(
            extract_member_wrapping_key(&second_group, &alice_cred.did).unwrap(),
            Some(alice_wrapping),
            "a DID exactly one leaf claims still resolves"
        );
    }

    /// `find_leaf_index_by_did` holds the lookup rule: with two leaves claiming
    /// Bob's DID (leaves 1 and 2), a remote lookup fails closed, the member at
    /// leaf 2 resolves its own DID to leaf 2 (a first-match scan returns leaf 1),
    /// a DID one leaf claims resolves to that leaf, and an unclaimed DID is
    /// `MemberNotFound`.
    #[test]
    fn find_leaf_index_by_did_duplicate_and_own_did() {
        let alice_cred = test_credential("alice");
        let mut alice_group = crate::group::create_group(&alice_cred, &SystemClock).unwrap();
        let bob_cred = test_credential("bob");
        let mut add_bob = || {
            let (kp, signer, provider) =
                crate::group::generate_key_package(&bob_cred, &SystemClock).unwrap();
            let kp_in: KeyPackageIn = kp.key_package().clone().into();
            let added = crate::group::add_member(&mut alice_group, kp_in, &SystemClock).unwrap();
            (added, signer, provider)
        };
        let _first = add_bob();
        let (second, second_signer, second_provider) = add_bob();
        let second_group = crate::group::join_group(
            &second.welcome,
            second_provider,
            second_signer,
            &SystemClock,
        )
        .unwrap();

        assert!(matches!(
            find_leaf_index_by_did(alice_group.inner().unwrap(), &bob_cred.did),
            Err(MlsError::DuplicateMemberDid(did)) if did == bob_cred.did
        ));
        let second_inner = second_group.inner().unwrap();
        assert_eq!(
            find_leaf_index_by_did(second_inner, &bob_cred.did)
                .unwrap()
                .u32(),
            2,
            "the local member's own DID resolves to its own leaf"
        );
        assert_eq!(
            find_leaf_index_by_did(second_inner, &alice_cred.did)
                .unwrap()
                .u32(),
            0
        );
        assert!(matches!(
            find_leaf_index_by_did(second_inner, &test_credential("carol").did),
            Err(MlsError::MemberNotFound(_))
        ));
    }

    /// AC: advance MLS epoch via Commit -> extract LeafNode -> scp_wrapping_key
    /// is identical to pre-advance value.
    #[test]
    fn wrapping_key_stable_across_epoch_advance() {
        let alice_cred = test_credential("alice");
        let wrapping_key = [0xCC_u8; 32];
        let mut alice_group = crate::group::create_group_with_wrapping_key(
            &alice_cred,
            Some(&wrapping_key),
            &SystemClock,
        )
        .unwrap();

        // Add Bob to enable epoch advance.
        let bob_cred = test_credential("bob");
        let bob_wrapping = [0xDD_u8; 32];
        let (bob_kp, bob_signer, bob_provider) =
            crate::group::generate_key_package_with_wrapping_key(
                &bob_cred,
                Some(&bob_wrapping),
                &SystemClock,
            )
            .unwrap();
        let bob_kp_in: KeyPackageIn = bob_kp.key_package().clone().into();
        let add_result =
            crate::group::add_member(&mut alice_group, bob_kp_in, &SystemClock).unwrap();

        let mut bob_group =
            crate::group::join_group(&add_result.welcome, bob_provider, bob_signer, &SystemClock)
                .unwrap();

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
            crate::group::create_group_with_wrapping_key(&cred, Some(&original_key), &SystemClock)
                .unwrap();

        // Add Bob so we can do updates.
        let bob_cred = test_credential("bob");
        let (bob_kp, _bob_signer, _bob_provider) =
            crate::group::generate_key_package(&bob_cred, &SystemClock).unwrap();
        let bob_kp_in: KeyPackageIn = bob_kp.key_package().clone().into();
        let _add_result = crate::group::add_member(&mut group, bob_kp_in, &SystemClock).unwrap();

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
