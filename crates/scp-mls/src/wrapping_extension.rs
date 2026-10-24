//! MLS `LeafNode` `scp_wrapping_key` extension for stable wrapping keypairs.
//!
//! Each member in an SCP context maintains a single dedicated DHKEM(P-256)
//! keypair used exclusively for HPKE wrapping of sender key distributions (§9.16.1,
//! §9.16.2). The public key is published as an MLS `LeafNode` extension named
//! `scp_wrapping_key` so that other members can read it from the MLS tree
//! when processing [`SenderKeyRequest`](scp_protocol::crypto::sender_keys::SenderKeyRequest)
//! messages.
//!
//! # Extension Type ID
//!
//! Uses `0xFF01` from the RFC 9420 §17.3 private-use range (`0xFF00–0xFFFF`).
//! The payload is the 65-byte SEC1 uncompressed P-256 point (09 §9.5), and
//! every read validates the point before returning it.
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
use scp_protocol::crypto::hpke::p256::P256Point;

/// Extension type ID for `scp_wrapping_key` in the RFC 9420 §17.3
/// private-use range.
pub const SCP_WRAPPING_KEY_EXTENSION_TYPE: u16 = 0xFF01;

/// Size of the `scp_wrapping_key` payload in bytes: a SEC1 uncompressed P-256
/// point.
pub const P256_WRAPPING_KEY_SIZE: usize = 65;

/// Creates an `Extension::Unknown` containing the `scp_wrapping_key` extension
/// with the given 65-byte uncompressed P-256 public key.
#[must_use]
pub fn make_wrapping_key_extension(public_key: &[u8; P256_WRAPPING_KEY_SIZE]) -> Extension {
    Extension::Unknown(
        SCP_WRAPPING_KEY_EXTENSION_TYPE,
        UnknownExtension(public_key.to_vec()),
    )
}

/// Extracts the 65-byte P-256 wrapping public key from an `scp_wrapping_key`
/// extension, if present.
///
/// Returns `None` if the extension is not present. A present payload passes
/// §9.5 point validation
/// ([`P256Point`]):
/// exactly 65 bytes, led by `0x04`, on the curve.
///
/// # Errors
///
/// Returns [`MlsError::ExtensionError`] if the extension payload fails that
/// validation.
pub fn extract_wrapping_key(
    extensions: &Extensions<LeafNode>,
) -> Result<Option<P256Point>, MlsError> {
    extensions
        .unknown(SCP_WRAPPING_KEY_EXTENSION_TYPE)
        .map(|ext| {
            P256Point::try_from(ext.0.as_slice())
                .map_err(|e| MlsError::ExtensionError(format!("scp_wrapping_key extension: {e}")))
        })
        .transpose()
}

/// The ciphersuites every SCP leaf lists in its capabilities, in this order:
/// `0x0001` (X25519, AES-128-GCM, Ed25519), `0x0002` (P-256, AES-128-GCM,
/// P-256) and `0x0003` (X25519, ChaCha20-Poly1305, Ed25519).
///
/// openmls 0.9.0 filled these in when the caller passed `None`. Later openmls
/// fills in nothing (an unset list is empty, and building a leaf whose
/// capabilities omit its own ciphersuite fails), so every SCP builder passes
/// this list. A leaf's capabilities are signed into its `LeafNode`, so
/// changing it changes every published `KeyPackage`.
pub(crate) const SCP_LEAF_CIPHERSUITES: [Ciphersuite; 3] = [
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
    Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
    Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
];

/// The credential types every SCP leaf lists: Basic alone, the type
/// `ScpCredential` encodes to. openmls 0.9.0 filled this in for `None`, as it
/// did [`SCP_LEAF_CIPHERSUITES`].
pub(crate) const SCP_LEAF_CREDENTIALS: [CredentialType; 1] = [CredentialType::Basic];

/// Builds `Capabilities` that include support for the `scp_wrapping_key`
/// extension type, in addition to [`SCP_LEAF_CIPHERSUITES`] and
/// [`SCP_LEAF_CREDENTIALS`].
///
/// `OpenMLS` validates that any extension present on a `LeafNode` has its
/// type listed in the node's capabilities (`valn0107`). This function
/// constructs capabilities with `ExtensionType::Unknown(0xFF01)` declared.
#[must_use]
pub fn scp_capabilities_with_wrapping_key() -> Capabilities {
    Capabilities::new(
        None, // default versions
        Some(&SCP_LEAF_CIPHERSUITES),
        Some(&[ExtensionType::Unknown(SCP_WRAPPING_KEY_EXTENSION_TYPE)]),
        None, // no proposal types beyond the RFC 9420 defaults
        Some(&SCP_LEAF_CREDENTIALS),
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
    wrapping_pubkey: &[u8; P256_WRAPPING_KEY_SIZE],
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
/// Reads the own leaf node's extensions and returns the 65-byte P-256
/// public key if present.
///
/// # Errors
///
/// Returns [`MlsError::GroupDestroyed`] if the group has been destroyed.
/// Returns [`MlsError::MemberNotFound`] if the own leaf node is unavailable.
/// Returns [`MlsError::ExtensionError`] if the extension data is malformed.
pub fn extract_own_wrapping_key(
    group: &crate::group::ScpMlsGroup,
) -> Result<Option<P256Point>, MlsError> {
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
/// For the local member's DID, reads `own_leaf_node()` and returns the key the
/// local leaf publishes. For any other DID it returns
/// [`MlsError::MemberNotFound`]. openmls 0.9.0 exposes every remote leaf
/// (`MlsGroup::public_group().leaf(index)`), so the tree could be read; SCP
/// deliberately offers no remote lookup yet, because a remote lookup must first
/// bind the identifier to leaves:
///
/// - A leaf's credential identifier is self-asserted. It is trustworthy only on
///   a leaf whose `KeyPackage` attestation verified (§9.7.1 of the security model
///   spec), which binds the leaf's keys, its `scp_wrapping_key` among them, to
///   the identifier.
/// - One identity may hold several leaves, one per device, that share one
///   wrapping key (§10.8.1 of the infrastructure spec), so a lookup by
///   identifier names a set of leaves, not one leaf.
///
/// That binding belongs to the leaf-signing and custody slice (ADR-057 T4
/// residual (3), the self-certifying directory; §23.13, Event Verification
/// During Reconciliation). Until it lands, a remote member's stable wrapping key
/// is needed only on the proactive/offline PUSH path (§9.16.1), where the key
/// holder caches it from the added `KeyPackage` at `add_member` time. The
/// canonical new-member key exchange is the PULL protocol (§9.16.2), which
/// carries a fresh ephemeral wrapping key inline in each `SenderKeyRequest` and
/// needs no stable-key lookup.
///
/// # Errors
///
/// Returns [`MlsError::GroupDestroyed`] if the group has been destroyed.
/// Returns [`MlsError::MemberNotFound`] if `target_did` is not the local
///   member's DID.
/// Returns [`MlsError::ExtensionError`] if the extension data is malformed.
pub fn extract_member_wrapping_key(
    group: &crate::group::ScpMlsGroup,
    target_did: &str,
) -> Result<Option<P256Point>, MlsError> {
    let g = group.inner()?;

    // Check if target is the local member — we can access own leaf node.
    if let Some(own_leaf) = g.own_leaf_node()
        && let Ok(basic) = BasicCredential::try_from(own_leaf.credential().clone())
        && let Ok(cred) = crate::credential::ScpCredential::from_bytes(basic.identity())
        && cred.did == target_did
    {
        return extract_wrapping_key(own_leaf.extensions());
    }

    // No remote lookup until the identifier-to-leaf binding lands (see this
    // function's doc comment). A joiner does not need remote stable wrapping
    // keys: it exchanges sender keys via the pull protocol (§9.16.2), which
    // carries a fresh ephemeral wrapping key inline in each `SenderKeyRequest`.
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
    use scp_clock::SystemClock;

    use scp_crypto::p256::testing::valid_uncompressed_point as point;

    fn extensions_with(payload: Vec<u8>) -> Extensions<LeafNode> {
        Extensions::<LeafNode>::single(Extension::Unknown(
            SCP_WRAPPING_KEY_EXTENSION_TYPE,
            UnknownExtension(payload),
        ))
        .unwrap()
    }

    #[test]
    fn make_and_extract_wrapping_key_roundtrip() {
        let key = point(42);
        let ext = make_wrapping_key_extension(&key);

        assert_eq!(
            ext.extension_type(),
            ExtensionType::Unknown(SCP_WRAPPING_KEY_EXTENSION_TYPE)
        );

        // Build an Extensions<LeafNode> with the wrapping key.
        let extensions = Extensions::<LeafNode>::single(ext).unwrap();
        let extracted = extract_wrapping_key(&extensions).unwrap();
        assert_eq!(
            extracted,
            Some(scp_protocol::crypto::hpke::p256::P256Point::try_from(key).unwrap())
        );
    }

    #[test]
    fn extract_wrapping_key_returns_none_when_absent() {
        let extensions = Extensions::<LeafNode>::default();
        let extracted = extract_wrapping_key(&extensions).unwrap();
        assert_eq!(extracted, None);
    }

    /// The 0xFF01 payload must be a valid 65-byte uncompressed P-256
    /// point. 3, 32, 33 and 66 bytes, a wrong prefix, and an off-curve point are
    /// all rejected with `ExtensionError`.
    #[test]
    fn extract_wrapping_key_rejects_invalid_points() {
        let valid = point(1);
        let mut wrong_prefix = valid;
        wrong_prefix[0] = 0x02;
        let mut off_curve = [0u8; 65];
        off_curve[0] = 0x04;
        off_curve[64] = 1; // x = 0, y = 1 is not on P-256
        let mut compressed = valid[..33].to_vec();
        compressed[0] = 0x02;
        let mut long = valid.to_vec();
        long.push(0);
        for payload in [
            vec![1, 2, 3],
            vec![0x04; 32],
            compressed,
            long,
            wrong_prefix.to_vec(),
            off_curve.to_vec(),
        ] {
            let len = payload.len();
            let result = extract_wrapping_key(&extensions_with(payload));
            assert!(
                matches!(result, Err(MlsError::ExtensionError(_))),
                "{len}-byte payload must be rejected, got {result:?}"
            );
        }
        assert_eq!(
            extract_wrapping_key(&extensions_with(valid.to_vec())).unwrap(),
            Some(scp_protocol::crypto::hpke::p256::P256Point::try_from(valid).unwrap())
        );
    }

    /// A real cs2 `KeyPackage` carries the 65-byte key: the adder's
    /// admission reports it, and the joiner reads the same key back through
    /// `extract_member_wrapping_key` on its own leaf.
    #[test]
    fn cs2_key_package_carries_65_byte_wrapping_key() {
        let bob_cred = test_credential("bob");
        let bob_wrapping = point(0xBB);
        let (bob_kp, bob_signer, bob_provider) =
            crate::group::generate_key_package(&bob_cred, &bob_wrapping, &SystemClock).unwrap();
        assert_eq!(
            bob_kp.key_package().ciphersuite(),
            crate::group::SCP_CIPHERSUITE
        );
        let bob_kp_in: KeyPackageIn = bob_kp.key_package().clone().into();

        let mut alice_group =
            crate::group::create_group(&test_credential("alice"), &point(0xAA), &SystemClock)
                .unwrap();
        let add = crate::group::add_member(&mut alice_group, bob_kp_in, &SystemClock).unwrap();
        assert_eq!(add.admitted_did, bob_cred.did);
        assert_eq!(
            add.admitted_wrapping_key,
            scp_protocol::crypto::hpke::p256::P256Point::try_from(bob_wrapping).unwrap()
        );
        let bob_group =
            crate::group::join_group(&add.welcome, bob_provider, bob_signer, &SystemClock).unwrap();
        assert_eq!(
            extract_member_wrapping_key(&bob_group, &bob_cred.did).unwrap(),
            Some(scp_protocol::crypto::hpke::p256::P256Point::try_from(bob_wrapping).unwrap())
        );
    }

    #[test]
    fn scp_capabilities_contains_wrapping_key_type() {
        let caps = scp_capabilities_with_wrapping_key();
        crate::capability_lists::assert_exact(&caps, &[SCP_WRAPPING_KEY_EXTENSION_TYPE]);
        assert!(
            caps.extensions()
                .contains(&ExtensionType::Unknown(SCP_WRAPPING_KEY_EXTENSION_TYPE)),
            "capabilities must list scp_wrapping_key extension type"
        );
    }

    #[test]
    fn leaf_node_params_with_wrapping_key_creates_valid_params() {
        let key = point(7);
        let params = leaf_node_params_with_wrapping_key(&key).unwrap();
        let extensions = params.extensions().unwrap();
        let extracted = extract_wrapping_key(extensions).unwrap();
        assert_eq!(
            extracted,
            Some(scp_protocol::crypto::hpke::p256::P256Point::try_from(key).unwrap())
        );
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
    /// the 65-byte P-256 public key.
    #[test]
    fn create_group_with_wrapping_key_includes_extension() {
        let cred = test_credential("alice");
        let wrapping_key = point(0xAA);

        let group = crate::group::create_group(&cred, &wrapping_key, &SystemClock).unwrap();

        // Extract the own wrapping key from the LeafNode.
        let extracted = extract_own_wrapping_key(&group).unwrap();
        assert_eq!(
            extracted,
            Some(scp_protocol::crypto::hpke::p256::P256Point::try_from(wrapping_key).unwrap()),
            "own leaf node must contain scp_wrapping_key extension"
        );
    }

    /// AC: join context (via KeyPackage) -> extract LeafNode -> scp_wrapping_key
    /// present.
    #[test]
    fn key_package_with_wrapping_key_carries_extension_through_join() {
        let alice_cred = test_credential("alice");
        let alice_wrapping = point(0xAA);
        let mut alice_group =
            crate::group::create_group(&alice_cred, &alice_wrapping, &SystemClock).unwrap();

        let bob_cred = test_credential("bob");
        let bob_wrapping = point(0xBB);
        let (bob_kp, bob_signer, bob_provider) =
            crate::group::generate_key_package(&bob_cred, &bob_wrapping, &SystemClock).unwrap();

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
            Some(scp_protocol::crypto::hpke::p256::P256Point::try_from(bob_wrapping).unwrap()),
            "Bob's own leaf node must contain scp_wrapping_key after joining"
        );
    }

    /// The local member's DID returns the key its own leaf publishes, on the
    /// creator and on a Welcome joiner. A remote member's DID returns
    /// `MemberNotFound` even though the remote leaf publishes a key (SCP offers
    /// no remote lookup), and so does a DID that is not a member.
    #[test]
    fn extract_member_wrapping_key_reads_only_the_local_member() {
        let alice_cred = test_credential("alice");
        let alice_wrapping = scp_crypto::p256::testing::uncompressed_point_for(&alice_cred.did);
        let mut alice_group =
            crate::group::create_group(&alice_cred, &alice_wrapping, &SystemClock).unwrap();

        let bob_cred = test_credential("bob");
        let bob_wrapping = scp_crypto::p256::testing::uncompressed_point_for(&bob_cred.did);
        let (bob_kp, bob_signer, bob_provider) =
            crate::group::generate_key_package(&bob_cred, &bob_wrapping, &SystemClock).unwrap();
        let bob_kp_in: KeyPackageIn = bob_kp.key_package().clone().into();
        let add_result =
            crate::group::add_member(&mut alice_group, bob_kp_in, &SystemClock).unwrap();
        let bob_group =
            crate::group::join_group(&add_result.welcome, bob_provider, bob_signer, &SystemClock)
                .unwrap();

        assert_eq!(
            extract_member_wrapping_key(&alice_group, &alice_cred.did).unwrap(),
            Some(P256Point::try_from(alice_wrapping).unwrap()),
            "the local member's DID returns its own leaf's key"
        );
        assert_eq!(
            extract_member_wrapping_key(&bob_group, &bob_cred.did).unwrap(),
            Some(P256Point::try_from(bob_wrapping).unwrap()),
            "a Welcome joiner's own DID returns its own leaf's key"
        );
        assert!(matches!(
            extract_member_wrapping_key(&alice_group, &bob_cred.did),
            Err(MlsError::MemberNotFound(_))
        ));
        assert!(matches!(
            extract_member_wrapping_key(&bob_group, &alice_cred.did),
            Err(MlsError::MemberNotFound(_))
        ));
        assert!(matches!(
            extract_member_wrapping_key(&alice_group, &test_credential("carol").did),
            Err(MlsError::MemberNotFound(_))
        ));
    }

    /// AC: advance MLS epoch via Commit -> extract LeafNode -> scp_wrapping_key
    /// is identical to pre-advance value.
    #[test]
    fn wrapping_key_stable_across_epoch_advance() {
        let alice_cred = test_credential("alice");
        let wrapping_key = point(0xCC);
        let mut alice_group =
            crate::group::create_group(&alice_cred, &wrapping_key, &SystemClock).unwrap();

        // Add Bob to enable epoch advance.
        let bob_cred = test_credential("bob");
        let bob_wrapping = point(0xDD);
        let (bob_kp, bob_signer, bob_provider) =
            crate::group::generate_key_package(&bob_cred, &bob_wrapping, &SystemClock).unwrap();
        let bob_kp_in: KeyPackageIn = bob_kp.key_package().clone().into();
        let add_result =
            crate::group::add_member(&mut alice_group, bob_kp_in, &SystemClock).unwrap();

        let mut bob_group =
            crate::group::join_group(&add_result.welcome, bob_provider, bob_signer, &SystemClock)
                .unwrap();

        // Alice performs an update WITH her wrapping key to preserve it.
        let commit = crate::ratchet::propose_update_with_wrapping_key(
            &mut alice_group,
            &wrapping_key,
            &SystemClock,
        )
        .unwrap()
        .commit;
        let commit_bytes = crate::ratchet::serialize_mls_message(&commit).unwrap();

        // Bob processes Alice's commit.
        crate::encrypt::decrypt_with_sender_did(&mut bob_group, &commit_bytes).unwrap();

        // Alice's wrapping key should be unchanged after the update.
        let alice_extracted = extract_own_wrapping_key(&alice_group).unwrap();
        assert_eq!(
            alice_extracted,
            Some(scp_protocol::crypto::hpke::p256::P256Point::try_from(wrapping_key).unwrap()),
            "scp_wrapping_key must remain identical after epoch advance"
        );
    }

    /// AC: rotate identity key -> new wrapping key published via MLS Update ->
    /// scp_wrapping_key has changed.
    #[test]
    fn wrapping_key_rotates_on_identity_key_rotation() {
        let cred = test_credential("alice");
        let original_key = point(0xAA);
        let mut group = crate::group::create_group(&cred, &original_key, &SystemClock).unwrap();

        // Add Bob so we can do updates.
        let bob_cred = test_credential("bob");
        let (bob_kp, _bob_signer, _bob_provider) = crate::group::generate_key_package(
            &bob_cred,
            &scp_crypto::p256::testing::uncompressed_point_for(&bob_cred.did),
            &SystemClock,
        )
        .unwrap();
        let bob_kp_in: KeyPackageIn = bob_kp.key_package().clone().into();
        let _add_result = crate::group::add_member(&mut group, bob_kp_in, &SystemClock).unwrap();

        // Simulate identity key rotation: generate a NEW wrapping key and
        // publish it via update.
        let new_key = point(0xFF);
        let _commit =
            crate::ratchet::propose_update_with_wrapping_key(&mut group, &new_key, &SystemClock)
                .unwrap()
                .commit;

        // After the update, the wrapping key should be the new value.
        let extracted = extract_own_wrapping_key(&group).unwrap();
        assert_eq!(
            extracted,
            Some(scp_protocol::crypto::hpke::p256::P256Point::try_from(new_key).unwrap()),
            "scp_wrapping_key must change after rotation"
        );
        assert_ne!(
            extracted,
            Some(scp_protocol::crypto::hpke::p256::P256Point::try_from(original_key).unwrap()),
            "scp_wrapping_key must differ from original after rotation"
        );
    }
}
