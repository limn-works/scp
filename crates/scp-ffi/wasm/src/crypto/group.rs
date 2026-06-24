//! WASM-local MLS group lifecycle operations.
//!
//! Ports `scp_core::crypto::mls::group` into a WASM-compatible form. Uses
//! `OpenMlsRustCrypto` (in-memory provider) since the WASM bridge cannot use
//! the platform `Storage` backend.
//!
//! All operations are synchronous (no tokio, no async).
//!
//! # Ciphersuite
//!
//! All groups use `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` — no
//! ciphersuite negotiation. See ADR-001 for the rationale.

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use tls_codec::{Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait};

use super::credential::WasmScpCredential;
use super::error::WasmCryptoError;

/// The single ciphersuite used by all SCP MLS groups.
///
/// `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` provides:
/// - X25519 for key exchange (DHKEM)
/// - AES-128-GCM for authenticated encryption
/// - SHA-256 for hashing
/// - Ed25519 for digital signatures
///
/// No ciphersuite negotiation. See ADR-001.
pub const SCP_CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Wrapper around an `OpenMLS` `MlsGroup` for WASM.
///
/// Holds the MLS group state, the in-memory crypto provider, and the local
/// member's signing key. All operations are synchronous.
pub struct WasmMlsGroup {
    /// The underlying `OpenMLS` group. `None` after destruction.
    group: Option<MlsGroup>,
    /// The MLS provider (crypto + in-memory storage).
    provider: OpenMlsRustCrypto,
    /// Ed25519 signing key pair. `None` after destruction.
    ///
    /// # Zeroization gap
    ///
    /// `SignatureKeyPair` (`OpenMLS` upstream) stores the private key in
    /// a plain `Vec<u8>` and does NOT implement `Zeroize` or `ZeroizeOnDrop`.
    /// On drop, the key material remains in WASM linear memory until
    /// overwritten by the allocator. scp-core mitigates this with
    /// `EagerDropSigner`; the WASM bridge accepts the residue risk because
    /// WASM linear memory is same-origin isolated.
    signer: Option<SignatureKeyPair>,
}

impl WasmMlsGroup {
    /// Creates a new MLS group with the creator as the sole member.
    ///
    /// The group uses [`SCP_CIPHERSUITE`] and starts at epoch 0.
    ///
    /// # Errors
    ///
    /// Returns an error if credential serialization or group creation fails.
    pub fn create_group(credential: &WasmScpCredential) -> Result<Self, WasmCryptoError> {
        let provider = OpenMlsRustCrypto::default();

        let signer = SignatureKeyPair::new(SCP_CIPHERSUITE.signature_algorithm()).map_err(|e| {
            WasmCryptoError::GroupCreationFailed(format!("signature key generation: {e}"))
        })?;

        signer.store(provider.storage()).map_err(|e| {
            WasmCryptoError::GroupCreationFailed(format!("storing signature key: {e}"))
        })?;

        let credential_bytes = credential.to_bytes()?;
        let basic_credential = BasicCredential::new(credential_bytes);
        let credential_with_key = CredentialWithKey {
            credential: basic_credential.into(),
            signature_key: signer.to_public_vec().into(),
        };

        // max_past_epochs(2) matches scp-core for grace window compatibility.
        let group_create_config = MlsGroupCreateConfig::builder()
            .ciphersuite(SCP_CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .max_past_epochs(2)
            .build();

        let group = MlsGroup::new(
            &provider,
            &signer,
            &group_create_config,
            credential_with_key,
        )
        .map_err(|e| WasmCryptoError::GroupCreationFailed(e.to_string()))?;

        Ok(Self {
            group: Some(group),
            provider,
            signer: Some(signer),
        })
    }

    /// Adds a member to the group using their pre-published `KeyPackage`.
    ///
    /// Returns `(commit_bytes, welcome_bytes)` — TLS-serialized MLS messages.
    ///
    /// # Errors
    ///
    /// Returns an error if the group is destroyed or the add operation fails.
    pub fn add_member(
        &mut self,
        key_package: KeyPackageIn,
    ) -> Result<(Vec<u8>, Vec<u8>), WasmCryptoError> {
        let verified_key_package = key_package
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|e| {
                WasmCryptoError::AddMemberFailed(format!("key package validation: {e}"))
            })?;

        let signer = self
            .signer
            .as_ref()
            .ok_or(WasmCryptoError::GroupDestroyed)?;
        let g = self.group.as_mut().ok_or(WasmCryptoError::GroupDestroyed)?;

        let (commit, welcome, _group_info) = g
            .add_members(
                &self.provider,
                signer,
                core::slice::from_ref(&verified_key_package),
            )
            .map_err(|e| WasmCryptoError::AddMemberFailed(e.to_string()))?;

        // Merge the pending commit.
        let g = self.group.as_mut().ok_or(WasmCryptoError::GroupDestroyed)?;
        g.merge_pending_commit(&self.provider)
            .map_err(|e| WasmCryptoError::MergePendingCommitFailed(e.to_string()))?;

        // TLS-serialize for transport.
        let commit_bytes = commit
            .tls_serialize_detached()
            .map_err(|e| WasmCryptoError::AddMemberFailed(format!("serializing commit: {e}")))?;
        let welcome_bytes = welcome
            .tls_serialize_detached()
            .map_err(|e| WasmCryptoError::AddMemberFailed(format!("serializing welcome: {e}")))?;

        Ok((commit_bytes, welcome_bytes))
    }

    /// Removes a member from the group by their leaf index.
    ///
    /// Returns `commit_bytes` — TLS-serialized commit message.
    ///
    /// # Errors
    ///
    /// Returns an error if the group is destroyed or the remove operation fails.
    pub fn remove_member(&mut self, member: &LeafNodeIndex) -> Result<Vec<u8>, WasmCryptoError> {
        let signer = self
            .signer
            .as_ref()
            .ok_or(WasmCryptoError::GroupDestroyed)?;
        let g = self.group.as_mut().ok_or(WasmCryptoError::GroupDestroyed)?;

        let (commit, _welcome, _group_info) = g
            .remove_members(&self.provider, signer, core::slice::from_ref(member))
            .map_err(|e| WasmCryptoError::RemoveMemberFailed(e.to_string()))?;

        // Merge the pending commit.
        let g = self.group.as_mut().ok_or(WasmCryptoError::GroupDestroyed)?;
        g.merge_pending_commit(&self.provider)
            .map_err(|e| WasmCryptoError::MergePendingCommitFailed(e.to_string()))?;

        commit
            .tls_serialize_detached()
            .map_err(|e| WasmCryptoError::RemoveMemberFailed(format!("serializing commit: {e}")))
    }

    /// Resolves the [`LeafNodeIndex`] of the group member whose SCP credential
    /// carries `member_did`.
    ///
    /// Scans every current group member, decodes each member's
    /// [`BasicCredential`] into a [`WasmScpCredential`], and returns the leaf
    /// index of the first member whose `did` matches. Returns `Ok(None)` when
    /// no current member carries that DID.
    ///
    /// Mirrors native `find_leaf_index_by_did`
    /// (`scp_runtime::crypto::mls::wrapping_extension`): MLS does not key its
    /// tree by DID, so removal-by-DID must map the SCP identity to its leaf
    /// before calling [`remove_member`](Self::remove_member).
    ///
    /// # Errors
    ///
    /// Returns [`WasmCryptoError::GroupDestroyed`] if the group has been
    /// destroyed.
    pub fn leaf_index_for_did(
        &self,
        member_did: &str,
    ) -> Result<Option<LeafNodeIndex>, WasmCryptoError> {
        let g = self.group.as_ref().ok_or(WasmCryptoError::GroupDestroyed)?;
        for member in g.members() {
            if let Ok(basic) = BasicCredential::try_from(member.credential.clone())
                && let Ok(scp_cred) = WasmScpCredential::from_bytes(basic.identity())
                && scp_cred.did == member_did
            {
                return Ok(Some(member.index));
            }
        }
        Ok(None)
    }

    /// Removes the group member identified by `member_did`, returning the
    /// TLS-serialized commit that evicts them from the MLS group.
    ///
    /// Resolves the DID to its leaf via [`leaf_index_for_did`](Self::leaf_index_for_did)
    /// and delegates to [`remove_member`](Self::remove_member).
    ///
    /// A missing MLS leaf is a NO-OP, not an error: it returns an empty commit
    /// (`Ok(Vec::new())`) and logs a warning to the browser console. This matches native
    /// `MlsCryptoProvider::remove_member`, which returns
    /// `RemoveMemberOutput::default()` (empty commit) for a member with no MLS
    /// leaf. The governance/`WasmContextManager` layer is authoritative for
    /// membership; the crypto layer only manages MLS group state. A member who
    /// is in the context's membership set but was never MLS-added (or is the
    /// local member under a different DID in a multi-identity environment) is
    /// removed from membership by the dispatch layer regardless, and there is
    /// no MLS key schedule to advance. The eviction security property — a
    /// removed member can no longer derive the group key — rests on the MLS
    /// epoch advance, which only exists when the member actually held a leaf.
    ///
    /// # Errors
    ///
    /// Returns [`WasmCryptoError::GroupDestroyed`] if the group has been
    /// destroyed, or [`WasmCryptoError::RemoveMemberFailed`] if a leaf IS found
    /// but the underlying remove/commit serialization fails. Those are genuine
    /// MLS failures and must propagate so the dispatch layer can fail closed
    /// (keep the member rather than report a removal that did not cut the key).
    pub fn remove_member_by_did(&mut self, member_did: &str) -> Result<Vec<u8>, WasmCryptoError> {
        // `leaf_index_for_did` propagates `GroupDestroyed` (group is None) as a
        // genuine error; `Ok(None)` means the DID has no MLS leaf.
        let Some(leaf_index) = self.leaf_index_for_did(member_did)? else {
            // Diagnostic only — the no-op behaviour (empty commit) is the
            // contract. `web_sys::console` is unavailable on non-wasm32 test
            // targets, so gate the log to the browser build.
            #[cfg(target_arch = "wasm32")]
            web_sys::console::warn_1(
                &format!(
                    "[SCP] remove_member_by_did: member DID '{member_did}' not found in MLS \
                     group leaf nodes — member may not have been MLS-added"
                )
                .into(),
            );
            return Ok(Vec::new());
        };
        self.remove_member(&leaf_index)
    }

    /// Joins a group from a Welcome message.
    ///
    /// The `welcome_bytes` must be TLS-serialized `MlsMessageOut` bytes
    /// containing a Welcome. The `holder` must be the `WasmMlsGroup` returned
    /// by `generate_key_package` — it contains the provider and signer
    /// that hold the private key material matching the `KeyPackage` that was
    /// sent to the adder.
    ///
    /// # Errors
    ///
    /// Returns an error if the Welcome cannot be processed.
    pub fn join_from_welcome(welcome_bytes: &[u8], holder: Self) -> Result<Self, WasmCryptoError> {
        let provider = holder.provider;
        let signer = holder.signer;

        // Deserialize the Welcome.
        let welcome_in = MlsMessageIn::tls_deserialize(&mut &*welcome_bytes).map_err(|e| {
            WasmCryptoError::WelcomeProcessingFailed(format!("deserializing welcome: {e}"))
        })?;

        let welcome_body = welcome_in.extract();
        let MlsMessageBodyIn::Welcome(welcome) = welcome_body else {
            return Err(WasmCryptoError::WelcomeProcessingFailed(
                "message is not a Welcome".to_string(),
            ));
        };

        // max_past_epochs(2) must match create_group.
        let join_config = MlsGroupJoinConfig::builder().max_past_epochs(2).build();

        let staged_welcome =
            StagedWelcome::new_from_welcome(&provider, &join_config, welcome, None)
                .map_err(|e| WasmCryptoError::WelcomeProcessingFailed(e.to_string()))?;

        let group = staged_welcome
            .into_group(&provider)
            .map_err(|e| WasmCryptoError::WelcomeProcessingFailed(e.to_string()))?;

        Ok(Self {
            group: Some(group),
            provider,
            signer,
        })
    }

    /// Generates a `KeyPackage` for a participant.
    ///
    /// Returns `(key_package_bytes, WasmMlsGroup)` where `key_package_bytes`
    /// is TLS-serialized and the `WasmMlsGroup` holds the private key material
    /// needed to later join via Welcome. Pass the returned `WasmMlsGroup` to
    /// `join_from_welcome` when the Welcome message arrives.
    ///
    /// # Errors
    ///
    /// Returns an error if key package generation fails.
    pub fn generate_key_package(
        credential: &WasmScpCredential,
    ) -> Result<(Vec<u8>, Self), WasmCryptoError> {
        let provider = OpenMlsRustCrypto::default();

        let signer = SignatureKeyPair::new(SCP_CIPHERSUITE.signature_algorithm()).map_err(|e| {
            WasmCryptoError::KeyPackageGenerationFailed(format!("signer generation: {e}"))
        })?;

        signer.store(provider.storage()).map_err(|e| {
            WasmCryptoError::KeyPackageGenerationFailed(format!("storing signature key: {e}"))
        })?;

        let credential_bytes = credential.to_bytes()?;
        let basic_credential = BasicCredential::new(credential_bytes);
        let credential_with_key = CredentialWithKey {
            credential: basic_credential.into(),
            signature_key: signer.to_public_vec().into(),
        };

        let key_package_bundle = KeyPackage::builder()
            .build(SCP_CIPHERSUITE, &provider, &signer, credential_with_key)
            .map_err(|e| WasmCryptoError::KeyPackageGenerationFailed(e.to_string()))?;

        let kp_bytes = key_package_bundle
            .key_package()
            .tls_serialize_detached()
            .map_err(|e| {
                WasmCryptoError::KeyPackageGenerationFailed(format!("serializing key package: {e}"))
            })?;

        Ok((
            kp_bytes,
            Self {
                group: None, // No group yet — will be set when joining via Welcome.
                provider,
                signer: Some(signer),
            },
        ))
    }

    /// Encrypts plaintext as an MLS application message.
    ///
    /// # Errors
    ///
    /// Returns an error if the group is destroyed or encryption fails.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, WasmCryptoError> {
        let signer = self
            .signer
            .as_ref()
            .ok_or(WasmCryptoError::GroupDestroyed)?;
        let g = self.group.as_mut().ok_or(WasmCryptoError::GroupDestroyed)?;

        let mls_out = g
            .create_message(&self.provider, signer, plaintext)
            .map_err(|e| WasmCryptoError::EncryptionFailed(e.to_string()))?;

        mls_out
            .tls_serialize_detached()
            .map_err(|e| WasmCryptoError::EncryptionFailed(format!("serializing: {e}")))
    }

    /// Decrypts an MLS application message from raw TLS-serialized bytes.
    ///
    /// Prefer [`mls_decrypt`](super::encrypt::mls_decrypt) which pre-validates
    /// the wire bytes before calling into `OpenMLS`.
    ///
    /// # Errors
    ///
    /// Returns an error if the group is destroyed, decryption fails, or the
    /// message is not an application message.
    pub fn decrypt(&mut self, mls_ciphertext: &[u8]) -> Result<Vec<u8>, WasmCryptoError> {
        let mls_in = MlsMessageIn::tls_deserialize(&mut &*mls_ciphertext)
            .map_err(|e| WasmCryptoError::DecryptionFailed(format!("deserializing: {e}")))?;

        let protocol_msg = mls_in.try_into_protocol_message().map_err(|_| {
            WasmCryptoError::DecryptionFailed("message is not a protocol message".to_string())
        })?;

        self.decrypt_protocol_message(protocol_msg)
    }

    /// Decrypts a pre-validated `ProtocolMessage`.
    ///
    /// Called by [`mls_decrypt`](super::encrypt::mls_decrypt) after TLS
    /// deserialization and message-type validation have already succeeded.
    ///
    /// # Errors
    ///
    /// Returns an error if the group is destroyed, AEAD decryption fails,
    /// or the message is not an application message.
    pub fn decrypt_protocol_message(
        &mut self,
        protocol_msg: ProtocolMessage,
    ) -> Result<Vec<u8>, WasmCryptoError> {
        let g = self.group.as_mut().ok_or(WasmCryptoError::GroupDestroyed)?;

        let processed = g
            .process_message(&self.provider, protocol_msg)
            .map_err(|e| WasmCryptoError::DecryptionFailed(e.to_string()))?;

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app_msg) => Ok(app_msg.into_bytes()),
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                // Process staged commits to advance the group epoch.
                let g = self.group.as_mut().ok_or(WasmCryptoError::GroupDestroyed)?;
                g.merge_staged_commit(&self.provider, *staged_commit)
                    .map_err(|e| {
                        WasmCryptoError::DecryptionFailed(format!("merging staged commit: {e}"))
                    })?;
                Err(WasmCryptoError::NotApplicationMessage)
            }
            ProcessedMessageContent::ProposalMessage(_)
            | ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
                Err(WasmCryptoError::NotApplicationMessage)
            }
        }
    }

    /// Destroys the MLS group state.
    ///
    /// After destruction, all operations will return `GroupDestroyed`.
    pub fn destroy(&mut self) {
        drop(self.group.take());
        drop(self.signer.take());
        self.provider = OpenMlsRustCrypto::default();
    }

    /// Returns the current epoch number.
    ///
    /// # Errors
    ///
    /// Returns [`WasmCryptoError::GroupDestroyed`] if the group is destroyed.
    pub fn epoch(&self) -> Result<u64, WasmCryptoError> {
        let g = self.group.as_ref().ok_or(WasmCryptoError::GroupDestroyed)?;
        Ok(g.epoch().as_u64())
    }

    /// Returns a reference to the inner provider.
    #[must_use]
    pub const fn provider(&self) -> &OpenMlsRustCrypto {
        &self.provider
    }

    /// Returns `true` if the group has been destroyed.
    #[must_use]
    pub const fn is_destroyed(&self) -> bool {
        self.group.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::credential::WasmSigningKeyId;

    #[allow(clippy::unwrap_used)]
    fn test_credential(name: &str) -> WasmScpCredential {
        WasmScpCredential::new(
            format!("did:dht:z6Mk{name}"),
            None,
            WasmSigningKeyId::Active,
        )
        .unwrap()
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn create_group_starts_at_epoch_0() {
        let cred = test_credential("alice");
        let group = WasmMlsGroup::create_group(&cred).unwrap();
        assert_eq!(group.epoch().unwrap(), 0);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn generate_key_package_produces_bytes() {
        let cred = test_credential("bob");
        let (kp_bytes, _holder) = WasmMlsGroup::generate_key_package(&cred).unwrap();
        assert!(
            !kp_bytes.is_empty(),
            "key package bytes should not be empty"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn add_member_returns_commit_and_welcome() {
        let alice_cred = test_credential("alice");
        let mut alice_group = WasmMlsGroup::create_group(&alice_cred).unwrap();

        let bob_cred = test_credential("bob");
        let (bob_kp_bytes, _bob_holder) = WasmMlsGroup::generate_key_package(&bob_cred).unwrap();

        let bob_kp_in = KeyPackageIn::tls_deserialize(&mut &*bob_kp_bytes).unwrap();
        let (commit_bytes, welcome_bytes) = alice_group.add_member(bob_kp_in).unwrap();

        assert!(!commit_bytes.is_empty());
        assert!(!welcome_bytes.is_empty());
        assert_eq!(alice_group.epoch().unwrap(), 1);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn join_from_welcome_works() {
        let alice_cred = test_credential("alice");
        let mut alice_group = WasmMlsGroup::create_group(&alice_cred).unwrap();

        let bob_cred = test_credential("bob");
        let (bob_kp_bytes, bob_holder) = WasmMlsGroup::generate_key_package(&bob_cred).unwrap();

        let bob_kp_in = KeyPackageIn::tls_deserialize(&mut &*bob_kp_bytes).unwrap();
        let (_commit_bytes, welcome_bytes) = alice_group.add_member(bob_kp_in).unwrap();

        let bob_group = WasmMlsGroup::join_from_welcome(&welcome_bytes, bob_holder).unwrap();

        assert_eq!(alice_group.epoch().unwrap(), 1);
        assert_eq!(bob_group.epoch().unwrap(), 1);
    }

    #[test]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    fn leaf_index_for_did_resolves_added_member_and_remove_by_did_evicts() {
        let alice_cred = test_credential("alice");
        let mut alice_group = WasmMlsGroup::create_group(&alice_cred).unwrap();

        let bob_cred = test_credential("bob");
        let (bob_kp_bytes, _bob_holder) = WasmMlsGroup::generate_key_package(&bob_cred).unwrap();
        let bob_kp_in = KeyPackageIn::tls_deserialize(&mut &*bob_kp_bytes).unwrap();
        alice_group.add_member(bob_kp_in).unwrap();

        // Bob's DID resolves to a real leaf index (the second leaf — Alice is
        // the creator at leaf 0).
        let bob_index = alice_group
            .leaf_index_for_did(&bob_cred.did)
            .unwrap()
            .expect("Bob's DID must resolve to an MLS leaf after add");
        let alice_index = alice_group
            .leaf_index_for_did(&alice_cred.did)
            .unwrap()
            .expect("Alice's DID must resolve to her own leaf");
        assert_ne!(
            bob_index, alice_index,
            "Alice and Bob must occupy distinct leaves"
        );

        // A DID that is not a member resolves to None (not an error).
        assert!(
            alice_group
                .leaf_index_for_did("did:dht:z6MkNotAMember")
                .unwrap()
                .is_none(),
            "a non-member DID must resolve to None"
        );

        // remove_member_by_did evicts Bob and advances the epoch.
        let epoch_before = alice_group.epoch().unwrap();
        let commit = alice_group.remove_member_by_did(&bob_cred.did).unwrap();
        assert!(!commit.is_empty(), "eviction must produce a commit");
        assert_eq!(
            alice_group.epoch().unwrap(),
            epoch_before + 1,
            "removing a member must advance the MLS epoch"
        );

        // Bob is no longer resolvable after eviction.
        assert!(
            alice_group
                .leaf_index_for_did(&bob_cred.did)
                .unwrap()
                .is_none(),
            "the evicted member's DID must no longer resolve to a leaf"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    fn remove_member_by_did_is_noop_for_non_member() {
        let alice_cred = test_credential("alice");
        let mut alice_group = WasmMlsGroup::create_group(&alice_cred).unwrap();

        let epoch_before = alice_group.epoch().unwrap();

        // No member with this DID has an MLS leaf. This matches native
        // `MlsCryptoProvider::remove_member`: a missing leaf is a NO-OP that
        // returns an empty commit (the governance layer is authoritative for
        // membership; the crypto layer only manages MLS state). It must NOT
        // error and must NOT advance the epoch.
        let commit = alice_group
            .remove_member_by_did("did:dht:z6MkGhostMember")
            .expect("missing-leaf removal must be a no-op, not an error");
        assert!(
            commit.is_empty(),
            "a missing-leaf removal must produce an empty commit (no-op)"
        );
        assert_eq!(
            alice_group.epoch().unwrap(),
            epoch_before,
            "a missing-leaf removal must NOT advance the MLS epoch"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    fn remove_member_by_did_errors_on_destroyed_group() {
        let alice_cred = test_credential("alice");
        let mut alice_group = WasmMlsGroup::create_group(&alice_cred).unwrap();

        // A destroyed group (group is None) is a genuine MLS failure:
        // `leaf_index_for_did` returns `GroupDestroyed`, which must propagate as
        // an error so the dispatch layer fails closed (keeps the member) rather
        // than reporting a removal that never cut the key.
        alice_group.destroy();
        let err = alice_group
            .remove_member_by_did("did:dht:z6MkAnyone")
            .expect_err("removal against a destroyed group must error");
        assert!(
            matches!(err, WasmCryptoError::GroupDestroyed),
            "destroyed-group removal must be GroupDestroyed, got {err:?}"
        );
    }

    // NOTE: OpenMLS cannot decrypt your own messages. A two-party setup is
    // required for encrypt/decrypt round-trip tests. This is tested in the
    // state module's integration tests.

    #[test]
    #[allow(clippy::unwrap_used)]
    fn encrypt_produces_bytes() {
        let alice_cred = test_credential("alice");
        let mut alice_group = WasmMlsGroup::create_group(&alice_cred).unwrap();

        // Need at least 2 members to encrypt (OpenMLS requires it for app messages
        // in some configurations, but single-member groups can still encrypt).
        let ciphertext = alice_group.encrypt(b"hello world").unwrap();
        assert!(!ciphertext.is_empty(), "ciphertext should not be empty");
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn destroy_prevents_further_operations() {
        let cred = test_credential("alice");
        let mut group = WasmMlsGroup::create_group(&cred).unwrap();

        group.destroy();

        assert!(group.is_destroyed());
        assert!(group.epoch().is_err());
        assert!(group.encrypt(b"test").is_err());
        assert!(group.decrypt(b"test").is_err());
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn two_party_encrypt_decrypt_roundtrip() {
        let alice_cred = test_credential("alice");
        let mut alice_group = WasmMlsGroup::create_group(&alice_cred).unwrap();

        let bob_cred = test_credential("bob");
        let (bob_kp_bytes, bob_holder) = WasmMlsGroup::generate_key_package(&bob_cred).unwrap();

        let bob_kp_in = KeyPackageIn::tls_deserialize(&mut &*bob_kp_bytes).unwrap();
        let (_commit_bytes, welcome_bytes) = alice_group.add_member(bob_kp_in).unwrap();

        let mut bob_group = WasmMlsGroup::join_from_welcome(&welcome_bytes, bob_holder).unwrap();

        // Alice encrypts, Bob decrypts.
        let plaintext = b"secret message from alice to bob";
        let ciphertext = alice_group.encrypt(plaintext).unwrap();
        let decrypted = bob_group.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
