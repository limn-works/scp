//! Orchestration layer combining MLS encryption and sender key layer.
//!
//! `WasmCryptoState` holds both an MLS group and a sender key store, providing
//! a single entry point for the full double-encryption pipeline:
//! sender key encrypt -> MLS encrypt (on send) and
//! MLS decrypt -> sender key decrypt (on receive).

use std::collections::HashMap;

use zeroize::Zeroize;

use super::error::WasmCryptoError;
use super::group::WasmMlsGroup;
use super::sender_key::{
    SenderKey, decrypt_sender_layer, encrypt_sender_layer, generate_sender_key,
};

/// Combined MLS + sender key state for a single context.
///
/// Owns the MLS group and manages per-sender AES-256 keys. The double
/// encryption pipeline is:
///
/// **Send:** `plaintext` -> sender key encrypt -> MLS encrypt -> `ciphertext`
/// **Receive:** `ciphertext` -> MLS decrypt -> sender key decrypt -> `plaintext`
pub struct WasmCryptoState {
    /// The MLS group for this context.
    pub mls_group: WasmMlsGroup,
    /// This participant's own sender key.
    pub local_sender_key: SenderKey,
    /// Sender keys from other participants, keyed by DID.
    pub sender_key_store: HashMap<String, SenderKey>,
}

impl WasmCryptoState {
    /// Creates a new crypto state for a context.
    ///
    /// Creates the MLS group with the creator as sole member and generates
    /// a fresh sender key.
    ///
    /// # Errors
    ///
    /// Returns an error if MLS group creation fails.
    pub fn new_for_context(creator_did: &str) -> Result<Self, WasmCryptoError> {
        let credential = super::credential::WasmScpCredential::new(
            creator_did.to_string(),
            None,
            super::credential::WasmSigningKeyId::Active,
        )?;

        let mls_group = WasmMlsGroup::create_group(&credential)?;
        let local_sender_key = generate_sender_key();

        Ok(Self {
            mls_group,
            local_sender_key,
            sender_key_store: HashMap::new(),
        })
    }

    /// Encrypts a message using the full double-encryption pipeline.
    ///
    /// 1. Encrypt with the local sender key (AES-256-GCM with AAD).
    /// 2. Encrypt the result with MLS.
    ///
    /// # Errors
    ///
    /// Returns an error if either encryption layer fails.
    pub fn encrypt_message(
        &mut self,
        plaintext: &[u8],
        context_id: &str,
        sender_did: &str,
        epoch: u64,
        sequence: u64,
    ) -> Result<Vec<u8>, WasmCryptoError> {
        // Layer 1: sender key encrypt.
        let sender_encrypted = encrypt_sender_layer(
            &self.local_sender_key,
            plaintext,
            context_id,
            sender_did,
            epoch,
            sequence,
        )?;

        // Layer 2: MLS encrypt.
        self.mls_group.encrypt(&sender_encrypted)
    }

    /// Decrypts a message using the full double-decryption pipeline.
    ///
    /// 1. Decrypt with MLS.
    /// 2. Decrypt with the sender's key (looked up by DID).
    ///
    /// # Errors
    ///
    /// Returns an error if either decryption layer fails, or if the sender's
    /// key is not in the store.
    pub fn decrypt_message(
        &mut self,
        ciphertext: &[u8],
        context_id: &str,
        sender_did: &str,
        epoch: u64,
        sequence: u64,
    ) -> Result<Vec<u8>, WasmCryptoError> {
        // Layer 1: MLS decrypt.
        let mls_decrypted = self.mls_group.decrypt(ciphertext)?;

        // Layer 2: sender key decrypt.
        let sender_key = self.sender_key_store.get(sender_did).ok_or_else(|| {
            WasmCryptoError::SenderKeyError(format!("no sender key for DID '{sender_did}'"))
        })?;

        Ok(decrypt_sender_layer(
            sender_key,
            &mls_decrypted,
            context_id,
            sender_did,
            epoch,
            sequence,
        )?)
    }

    /// Destroys all crypto state (MLS group + sender keys).
    ///
    /// Eagerly zeroizes the local sender key rather than waiting for
    /// `WasmCryptoState` to be dropped.
    pub fn destroy(&mut self) {
        self.mls_group.destroy();
        // SenderKey implements ZeroizeOnDrop, so clearing the map will
        // zeroize each key as it's dropped.
        self.sender_key_store.clear();
        // Eagerly zeroize the local sender key. The old value is overwritten
        // in-place, triggering Zeroize on the inner [u8; 32].
        self.local_sender_key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::credential::{WasmScpCredential, WasmSigningKeyId};
    use crate::crypto::sender_key::generate_sender_key;
    use openmls::prelude::*;
    use tls_codec::Deserialize as TlsDeserializeTrait;

    const ALICE_DID: &str = "did:dht:z6MkAlice";
    const BOB_DID: &str = "did:dht:z6MkBob";
    const CTX_ID: &str = "ctx-test-crypto-state";

    #[test]
    #[allow(clippy::unwrap_used)]
    fn new_for_context_creates_valid_state() {
        let state = WasmCryptoState::new_for_context(ALICE_DID).unwrap();
        assert!(!state.mls_group.is_destroyed());
        assert_eq!(state.mls_group.epoch().unwrap(), 0);
        assert_eq!(state.local_sender_key.as_bytes().len(), 32);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn full_encrypt_decrypt_chain() {
        // Set up Alice's state (creator).
        let mut alice_state = WasmCryptoState::new_for_context(ALICE_DID).unwrap();

        // Generate Bob's key package.
        let bob_cred =
            WasmScpCredential::new(BOB_DID.to_string(), None, WasmSigningKeyId::Active).unwrap();
        let (bob_kp_bytes, bob_holder) = WasmMlsGroup::generate_key_package(&bob_cred).unwrap();

        // Alice adds Bob.
        let bob_kp_in = KeyPackageIn::tls_deserialize(&mut &*bob_kp_bytes).unwrap();
        let (_commit, welcome) = alice_state.mls_group.add_member(bob_kp_in).unwrap();

        // Bob joins from Welcome using the holder from generate_key_package.
        let bob_mls_group = WasmMlsGroup::join_from_welcome(&welcome, bob_holder).unwrap();
        let bob_sender_key = generate_sender_key();

        let mut bob_state = WasmCryptoState {
            mls_group: bob_mls_group,
            local_sender_key: bob_sender_key,
            sender_key_store: HashMap::new(),
        };

        // Exchange sender keys: Alice gives Bob her sender key, Bob gives Alice his.
        bob_state.sender_key_store.insert(
            ALICE_DID.to_string(),
            SenderKey::from_bytes(*alice_state.local_sender_key.as_bytes()),
        );
        alice_state.sender_key_store.insert(
            BOB_DID.to_string(),
            SenderKey::from_bytes(*bob_state.local_sender_key.as_bytes()),
        );

        // Alice encrypts a message.
        let plaintext = b"encrypted via double layer";
        let ciphertext = alice_state
            .encrypt_message(plaintext, CTX_ID, ALICE_DID, 1, 0)
            .unwrap();

        // Bob decrypts.
        let decrypted = bob_state
            .decrypt_message(&ciphertext, CTX_ID, ALICE_DID, 1, 0)
            .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn decrypt_fails_without_sender_key() {
        // Set up Alice's state.
        let mut alice_state = WasmCryptoState::new_for_context(ALICE_DID).unwrap();

        // Generate Bob and add to group so Alice can encrypt.
        let bob_cred =
            WasmScpCredential::new(BOB_DID.to_string(), None, WasmSigningKeyId::Active).unwrap();
        let (bob_kp_bytes, bob_holder) = WasmMlsGroup::generate_key_package(&bob_cred).unwrap();

        let bob_kp_in = KeyPackageIn::tls_deserialize(&mut &*bob_kp_bytes).unwrap();
        let (_commit, welcome) = alice_state.mls_group.add_member(bob_kp_in).unwrap();

        let bob_mls_group = WasmMlsGroup::join_from_welcome(&welcome, bob_holder).unwrap();
        let mut bob_state = WasmCryptoState {
            mls_group: bob_mls_group,
            local_sender_key: generate_sender_key(),
            sender_key_store: HashMap::new(),
            // Deliberately NOT adding Alice's sender key.
        };

        let plaintext = b"should fail";
        let ciphertext = alice_state
            .encrypt_message(plaintext, CTX_ID, ALICE_DID, 1, 0)
            .unwrap();

        let result = bob_state.decrypt_message(&ciphertext, CTX_ID, ALICE_DID, 1, 0);
        assert!(result.is_err());
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn destroy_prevents_further_operations() {
        let mut state = WasmCryptoState::new_for_context(ALICE_DID).unwrap();
        state.destroy();

        assert!(state.mls_group.is_destroyed());
        assert!(
            state
                .encrypt_message(b"test", CTX_ID, ALICE_DID, 0, 0)
                .is_err()
        );
    }
}
