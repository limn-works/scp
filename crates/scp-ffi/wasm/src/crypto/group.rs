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
