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

use super::error::MlsError;

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
/// Used by [`propose_update_with_wrapping_key`](super::ratchet::propose_update_with_wrapping_key)
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
    group: &super::group::ScpMlsGroup,
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
    group: &super::group::ScpMlsGroup,
    target_did: &str,
) -> Result<Option<[u8; X25519_PUBLIC_KEY_SIZE]>, MlsError> {
    let g = group.inner()?;

    // Check if target is the local member — we can access own leaf node.
    if let Some(own_leaf) = g.own_leaf_node()
        && let Ok(basic) = BasicCredential::try_from(own_leaf.credential().clone())
        && let Ok(cred) = super::credential::ScpCredential::from_bytes(basic.identity())
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
            && let Ok(cred) = super::credential::ScpCredential::from_bytes(basic.identity())
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

    fn test_credential(name: &str) -> super::super::credential::ScpCredential {
        super::super::credential::ScpCredential::new(
            format!("did:dht:z6Mk{name}"),
            None,
            scp_identity::SigningKeyId::Active,
        )
        .unwrap()
    }

    /// AC: join context -> extract LeafNode -> scp_wrapping_key present with
    /// 32-byte X25519 public key.
    #[test]
    fn create_group_with_wrapping_key_includes_extension() {
        let cred = test_credential("alice");
        let wrapping_key = [0xAA_u8; 32];

        let group = super::super::group::create_group_with_wrapping_key(&cred, Some(&wrapping_key))
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
        let mut alice_group =
            super::super::group::create_group_with_wrapping_key(&alice_cred, Some(&alice_wrapping))
                .unwrap();

        let bob_cred = test_credential("bob");
        let bob_wrapping = [0xBB_u8; 32];
        let (bob_kp, bob_signer, bob_provider) =
            super::super::group::generate_key_package_with_wrapping_key(
                &bob_cred,
                Some(&bob_wrapping),
            )
            .unwrap();

        let bob_kp_in: KeyPackageIn = bob_kp.key_package().clone().into();
        let add_result = super::super::group::add_member(&mut alice_group, bob_kp_in).unwrap();

        let bob_group =
            super::super::group::join_group(&add_result.welcome, bob_provider, bob_signer).unwrap();

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
            super::super::group::create_group_with_wrapping_key(&alice_cred, Some(&wrapping_key))
                .unwrap();

        // Add Bob to enable epoch advance.
        let bob_cred = test_credential("bob");
        let bob_wrapping = [0xDD_u8; 32];
        let (bob_kp, bob_signer, bob_provider) =
            super::super::group::generate_key_package_with_wrapping_key(
                &bob_cred,
                Some(&bob_wrapping),
            )
            .unwrap();
        let bob_kp_in: KeyPackageIn = bob_kp.key_package().clone().into();
        let add_result = super::super::group::add_member(&mut alice_group, bob_kp_in).unwrap();

        let mut bob_group =
            super::super::group::join_group(&add_result.welcome, bob_provider, bob_signer).unwrap();

        // Alice performs an update WITH her wrapping key to preserve it.
        let commit = super::super::ratchet::propose_update_with_wrapping_key(
            &mut alice_group,
            &wrapping_key,
        )
        .unwrap();
        let commit_bytes = super::super::ratchet::serialize_mls_message(&commit).unwrap();

        // Bob processes Alice's commit.
        let mut grace_store = super::super::epoch_grace::EpochGraceStore::new();
        super::super::ratchet::process_commit(&mut bob_group, &commit_bytes, &mut grace_store)
            .unwrap();

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
            super::super::group::create_group_with_wrapping_key(&cred, Some(&original_key))
                .unwrap();

        // Add Bob so we can do updates.
        let bob_cred = test_credential("bob");
        let (bob_kp, _bob_signer, _bob_provider) =
            super::super::group::generate_key_package(&bob_cred).unwrap();
        let bob_kp_in: KeyPackageIn = bob_kp.key_package().clone().into();
        let _add_result = super::super::group::add_member(&mut group, bob_kp_in).unwrap();

        // Simulate identity key rotation: generate a NEW wrapping key and
        // publish it via update.
        let new_key = [0xFF_u8; 32];
        let _commit =
            super::super::ratchet::propose_update_with_wrapping_key(&mut group, &new_key).unwrap();

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

    /// AC: generate_wrapping_keypair produces distinct 32-byte keypairs.
    #[test]
    fn generate_wrapping_keypair_produces_valid_keypair() {
        let (pub1, sec1) = crate::crypto::sender_keys::key_protocol::generate_wrapping_keypair();
        let (pub2, sec2) = crate::crypto::sender_keys::key_protocol::generate_wrapping_keypair();

        assert_eq!(pub1.len(), 32);
        assert_eq!(sec1.len(), 32);
        assert_ne!(pub1, pub2, "wrapping keypairs must be distinct");
        assert_ne!(sec1, sec2, "wrapping secret keys must be distinct");

        // Verify the public key is derived from the secret key.
        let secret = x25519_dalek::StaticSecret::from(sec1);
        let derived_pub = x25519_dalek::PublicKey::from(&secret);
        assert_eq!(
            pub1,
            derived_pub.to_bytes(),
            "public key must derive from secret key"
        );
    }

    /// AC: send SenderKeyRequest -> response is HPKE-sealed to the requester's
    /// wrapping key -> requester decrypts successfully.
    #[tokio::test]
    async fn sender_key_request_response_with_wrapping_key() {
        use crate::crypto::sender_keys::key_protocol::{
            HandleRequestParams, NonceDedup, handle_sender_key_request, open_sender_key_response,
            request_sender_key,
        };
        use scp_platform::testing::InMemoryKeyCustody;
        use scp_platform::traits::{KeyCustody, KeyType};
        use scp_protocol::crypto::sender_keys::generate_sender_key;
        use std::collections::HashSet;

        let custody = InMemoryKeyCustody::new();

        // Alice: the sender with a sender key.
        let _alice_signing = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let sender_key = generate_sender_key();

        // Bob: the requester who needs the key.
        let bob_signing = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let bob_pubkey = custody.public_key(&bob_signing).await.unwrap();

        // Bob creates a request with an ephemeral wrapping key.
        let clock = scp_primitives::SystemClock;
        let request_result = request_sender_key(
            &custody,
            &bob_signing,
            "did:dht:bob",
            "did:dht:alice",
            1,
            &clock,
        )
        .await
        .unwrap();

        let request: scp_protocol::crypto::sender_keys::SenderKeyRequest =
            rmp_serde::from_slice(&request_result.request_message).unwrap();

        // Alice handles the request.
        let block_list: HashSet<String> = HashSet::new();
        let mut nonce_dedup = NonceDedup::new();
        let response_bytes = handle_sender_key_request(
            &request,
            bob_pubkey.as_bytes(),
            &HandleRequestParams {
                sender_key: &sender_key,
                context_id: "ctx-roundtrip",
                sender_did: "did:dht:alice",
                epoch: 1,
                block_list: &block_list,
                context_members: None,
                now_secs: request.timestamp,
            },
            &mut nonce_dedup,
        )
        .await
        .unwrap()
        .expect("Alice should respond to non-blocked Bob");

        let response: scp_protocol::crypto::sender_keys::SenderKeyResponse =
            rmp_serde::from_slice(&response_bytes).unwrap();

        // Bob decrypts the response using his ephemeral wrapping key handle.
        let recovered = open_sender_key_response(
            &custody,
            &request_result.wrapping_key_handle,
            "ctx-roundtrip",
            &response,
        )
        .await
        .unwrap();

        assert_eq!(
            recovered.as_bytes(),
            sender_key.as_bytes(),
            "Bob must recover Alice's sender key"
        );
    }

    /// AC: tamper with wrapping key -> HPKE open fails.
    /// The `SenderKeyRequest` signature covers the `wrapping_pubkey`, so
    /// tampering with the wrapping key causes signature verification failure.
    #[tokio::test]
    async fn tampered_wrapping_key_prevents_decryption() {
        use crate::crypto::sender_keys::key_protocol::{
            HandleRequestParams, NonceDedup, generate_wrapping_keypair, handle_sender_key_request,
            request_sender_key,
        };
        use scp_platform::testing::InMemoryKeyCustody;
        use scp_platform::traits::{KeyCustody, KeyType};
        use scp_protocol::crypto::sender_keys::generate_sender_key;
        use std::collections::HashSet;

        let custody = InMemoryKeyCustody::new();

        let _alice_signing = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let sender_key = generate_sender_key();

        let bob_signing = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let bob_pubkey = custody.public_key(&bob_signing).await.unwrap();

        let clock = scp_primitives::SystemClock;
        let request_result = request_sender_key(
            &custody,
            &bob_signing,
            "did:dht:bob",
            "did:dht:alice",
            1,
            &clock,
        )
        .await
        .unwrap();

        let mut request: scp_protocol::crypto::sender_keys::SenderKeyRequest =
            rmp_serde::from_slice(&request_result.request_message).unwrap();

        // Tamper: replace Bob's wrapping pubkey with a random key.
        let (fake_pub, _fake_sec) = generate_wrapping_keypair();
        request.wrapping_pubkey = fake_pub;

        // Alice handles the tampered request. The signature covers the
        // wrapping_pubkey, so verification must fail.
        let block_list: HashSet<String> = HashSet::new();
        let mut nonce_dedup = NonceDedup::new();
        let result = handle_sender_key_request(
            &request,
            bob_pubkey.as_bytes(),
            &HandleRequestParams {
                sender_key: &sender_key,
                context_id: "ctx-roundtrip",
                sender_did: "did:dht:alice",
                epoch: 1,
                block_list: &block_list,
                context_members: None,
                now_secs: request.timestamp,
            },
            &mut nonce_dedup,
        )
        .await;

        // The tampered request should fail signature verification.
        assert!(
            result.is_err(),
            "tampered wrapping key must cause signature verification failure"
        );
    }

    /// Conformance test: sender-keys-wrapping-stable-001
    ///
    /// Each member maintains a stable wrapping keypair per context, published
    /// as the `scp_wrapping_key` `LeafNode` extension.
    #[test]
    fn sender_keys_wrapping_stable_001() {
        use crate::crypto::sender_keys::key_protocol::generate_wrapping_keypair;

        let (pub_key, sec_key) = generate_wrapping_keypair();

        // 1. Wrapping keypair is valid (public derives from secret).
        let secret = x25519_dalek::StaticSecret::from(sec_key);
        let derived_pub = x25519_dalek::PublicKey::from(&secret);
        assert_eq!(pub_key, derived_pub.to_bytes(), "public key derivation");

        // 2. Extension publishes 32-byte X25519 public key.
        let ext = make_wrapping_key_extension(&pub_key);
        assert_eq!(
            ext.extension_type(),
            ExtensionType::Unknown(SCP_WRAPPING_KEY_EXTENSION_TYPE),
            "extension type ID must be 0xFF01"
        );

        // 3. Create group with wrapping key -> LeafNode contains extension.
        let cred = test_credential("conformance");
        let group =
            super::super::group::create_group_with_wrapping_key(&cred, Some(&pub_key)).unwrap();
        let extracted = extract_own_wrapping_key(&group).unwrap();
        assert_eq!(extracted, Some(pub_key), "wrapping key in LeafNode");

        // 4. Extension survives as the same value across MLS Updates when
        //    the wrapping key is explicitly preserved.
        let bob_cred = test_credential("bob");
        let (bob_kp, _bob_signer, _bob_provider) =
            super::super::group::generate_key_package(&bob_cred).unwrap();
        let bob_kp_in: KeyPackageIn = bob_kp.key_package().clone().into();

        let mut group_mut = group;
        let _add = super::super::group::add_member(&mut group_mut, bob_kp_in).unwrap();

        let _commit =
            super::super::ratchet::propose_update_with_wrapping_key(&mut group_mut, &pub_key)
                .unwrap();

        let after_update = extract_own_wrapping_key(&group_mut).unwrap();
        assert_eq!(
            after_update,
            Some(pub_key),
            "wrapping key must be stable across epoch advance"
        );

        // 5. Wrapping key can be rotated (identity key rotation simulation).
        let (new_pub, _new_sec) = generate_wrapping_keypair();
        let _commit2 =
            super::super::ratchet::propose_update_with_wrapping_key(&mut group_mut, &new_pub)
                .unwrap();

        let after_rotation = extract_own_wrapping_key(&group_mut).unwrap();
        assert_eq!(
            after_rotation,
            Some(new_pub),
            "wrapping key must change on rotation"
        );
        assert_ne!(
            after_rotation,
            Some(pub_key),
            "rotated key must differ from original"
        );
    }
}
