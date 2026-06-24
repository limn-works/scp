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

    /// Evicts a member from the MLS group by their DID.
    ///
    /// Returns the TLS-serialized commit that removes the member from the group
    /// key schedule. This is the hard security boundary of governance member
    /// removal: after this commit is processed, the evicted member can no longer
    /// derive the group's encryption keys. Mirrors native
    /// `MlsCrypto::remove_member` (called FIRST in
    /// `scp_runtime::context::governance_helpers::execute_remove_member`).
    ///
    /// # Errors
    ///
    /// Returns an error if the group is destroyed or no MLS leaf carries the
    /// given DID (governance verifies membership before calling, so a miss is a
    /// real state divergence — see
    /// [`WasmMlsGroup::remove_member_by_did`](super::group::WasmMlsGroup::remove_member_by_did)).
    pub fn governance_remove_from_group(
        &mut self,
        member_did: &str,
    ) -> Result<Vec<u8>, WasmCryptoError> {
        self.mls_group.remove_member_by_did(member_did)
    }

    /// Drops the evicted member's stored sender key, zeroizing it if present.
    ///
    /// Mirrors native `MlsCrypto::remove_member_sender_key`: after a member is
    /// removed, their sender key is no longer needed and is wiped from memory.
    /// `SenderKey` is `ZeroizeOnDrop`, so removing it from the store zeroizes
    /// the key material as it drops. A no-op if the member had no stored key.
    pub fn governance_remove_sender_key(&mut self, member_did: &str) {
        // The removed value is zeroized when it drops (SenderKey: ZeroizeOnDrop).
        drop(self.sender_key_store.remove(member_did));
    }

    /// Rotates this participant's local sender key, zeroizing the old key.
    ///
    /// Mirrors native `MlsCrypto::rotate_sender_key` (spec §9.16.4): after a
    /// member is removed, the remaining members rotate their sender keys so the
    /// evicted member's knowledge of any prior sender key grants no future
    /// sender-layer plaintext. That is this rotation's entire security purpose —
    /// denying the evicted member the sender layer.
    ///
    /// NOTE: this rotation does NOT, by itself, distribute the new key. WASM
    /// `encrypt_message` emits only the double-ciphertext and never attaches
    /// `local_sender_key`, so there is no cross-member sender-key distribution
    /// path on this bridge for encrypted (non-broadcast) MLS contexts — that is
    /// a pre-existing gap, separate from eviction. The operative lockout for the
    /// evicted member is the MLS layer-2 eviction (epoch advance): once the
    /// removal commit lands, the removed member can no longer derive the group
    /// keys, so MLS decryption of any later message fails regardless of
    /// sender-key state. The eviction security property therefore holds
    /// independently of whether the rotated sender key is ever redistributed.
    pub fn governance_rotate_sender_key(&mut self) {
        // Eagerly zeroize the old key in place before overwriting, rather than
        // relying solely on the drop of the replaced value.
        self.local_sender_key.zeroize();
        self.local_sender_key = generate_sender_key();
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

    const CAROL_DID: &str = "did:dht:z6MkCarol";

    /// Security proof for governance member eviction: after Alice evicts Bob
    /// from the MLS group and rotates her sender key, Bob's stale crypto state
    /// can NO LONGER decrypt Alice's subsequent messages, while a still-present
    /// member (Carol) can. This is the cross-cutting guarantee the WASM
    /// `dispatch_remove_member` fix restores — previously WASM removed a member
    /// from governance state but did zero MLS work, leaving the evicted member
    /// able to decrypt.
    ///
    /// Three members are required because `OpenMLS` cannot decrypt its own
    /// messages: Alice (creator) needs Carol to verify her own sends still work
    /// for current members after the eviction.
    #[test]
    #[allow(clippy::unwrap_used)]
    fn evicted_member_cannot_decrypt_after_removal_and_rotation() {
        // Alice creates the context.
        let mut alice_state = WasmCryptoState::new_for_context(ALICE_DID).unwrap();

        // Alice adds Bob.
        let bob_cred =
            WasmScpCredential::new(BOB_DID.to_string(), None, WasmSigningKeyId::Active).unwrap();
        let (bob_kp_bytes, bob_holder) = WasmMlsGroup::generate_key_package(&bob_cred).unwrap();
        let bob_kp_in = KeyPackageIn::tls_deserialize(&mut &*bob_kp_bytes).unwrap();
        let (_commit_bob, welcome_bob) = alice_state.mls_group.add_member(bob_kp_in).unwrap();
        let bob_mls_group = WasmMlsGroup::join_from_welcome(&welcome_bob, bob_holder).unwrap();
        let mut bob_state = WasmCryptoState {
            mls_group: bob_mls_group,
            local_sender_key: generate_sender_key(),
            sender_key_store: HashMap::new(),
        };

        // Alice adds Carol. Bob must process Alice's add-Carol commit so his MLS
        // group stays in lockstep with the group epoch up to the eviction.
        let carol_cred =
            WasmScpCredential::new(CAROL_DID.to_string(), None, WasmSigningKeyId::Active).unwrap();
        let (carol_kp_bytes, carol_holder) =
            WasmMlsGroup::generate_key_package(&carol_cred).unwrap();
        let carol_kp_in = KeyPackageIn::tls_deserialize(&mut &*carol_kp_bytes).unwrap();
        let (commit_carol, welcome_carol) = alice_state.mls_group.add_member(carol_kp_in).unwrap();
        // Bob applies the add-Carol commit (a non-application message: it merges
        // the staged commit and returns NotApplicationMessage).
        assert!(
            bob_state.mls_group.decrypt(&commit_carol).is_err(),
            "processing a commit returns NotApplicationMessage, not plaintext"
        );
        let carol_mls_group =
            WasmMlsGroup::join_from_welcome(&welcome_carol, carol_holder).unwrap();
        let mut carol_state = WasmCryptoState {
            mls_group: carol_mls_group,
            local_sender_key: generate_sender_key(),
            sender_key_store: HashMap::new(),
        };

        // Sender-key exchange: every member learns Alice's current sender key so
        // they can decrypt her sends (the sender-key layer under MLS).
        bob_state.sender_key_store.insert(
            ALICE_DID.to_string(),
            SenderKey::from_bytes(*alice_state.local_sender_key.as_bytes()),
        );
        carol_state.sender_key_store.insert(
            ALICE_DID.to_string(),
            SenderKey::from_bytes(*alice_state.local_sender_key.as_bytes()),
        );

        // Sanity: before eviction, both Bob and Carol can decrypt Alice's send.
        let epoch_pre = alice_state.mls_group.epoch().unwrap();
        let pre_plaintext = b"before eviction";
        let pre_ct = alice_state
            .encrypt_message(pre_plaintext, CTX_ID, ALICE_DID, epoch_pre, 0)
            .unwrap();
        // Bob and Carol each decrypt their own copy. Decryption mutates MLS
        // state, so encrypt twice (once per recipient) at the same epoch/seq.
        let pre_ct_carol = alice_state
            .encrypt_message(pre_plaintext, CTX_ID, ALICE_DID, epoch_pre, 1)
            .unwrap();
        assert_eq!(
            bob_state
                .decrypt_message(&pre_ct, CTX_ID, ALICE_DID, epoch_pre, 0)
                .unwrap(),
            pre_plaintext,
            "Bob must be able to decrypt before he is evicted"
        );
        assert_eq!(
            carol_state
                .decrypt_message(&pre_ct_carol, CTX_ID, ALICE_DID, epoch_pre, 1)
                .unwrap(),
            pre_plaintext,
            "Carol must be able to decrypt before the eviction"
        );

        // --- The governance eviction: remove Bob from the MLS group, drop his
        // sender key, and rotate Alice's sender key (mirrors native
        // execute_remove_member ordering). ---
        let evict_commit = alice_state.governance_remove_from_group(BOB_DID).unwrap();
        alice_state.governance_remove_sender_key(BOB_DID);
        alice_state.governance_rotate_sender_key();

        // Carol applies the eviction commit so her MLS epoch tracks Alice's.
        assert!(
            carol_state.mls_group.decrypt(&evict_commit).is_err(),
            "the eviction commit is a non-application message for Carol"
        );
        // Bob, were he honest, would also process the commit — but a removed
        // member's processing of his own removal does not grant him the new
        // epoch's secrets. We leave Bob's stale state as-is (the realistic
        // adversary: he keeps his pre-eviction keys and tries to decrypt).

        // Carol receives Alice's rotated sender key. WASM has no cross-member
        // sender-key distribution path for encrypted MLS contexts (a pre-existing
        // gap), so the test hands the key over directly to isolate and prove the
        // MLS-eviction security property: it must hold even when the rotated
        // sender key IS available to a remaining member.
        carol_state.sender_key_store.insert(
            ALICE_DID.to_string(),
            SenderKey::from_bytes(*alice_state.local_sender_key.as_bytes()),
        );

        // Alice sends after the eviction at the new epoch.
        let epoch_post = alice_state.mls_group.epoch().unwrap();
        assert_eq!(
            epoch_post,
            epoch_pre + 1,
            "the eviction commit must advance the MLS epoch"
        );
        let post_plaintext = b"after eviction - bob must not read this";
        let post_ct = alice_state
            .encrypt_message(post_plaintext, CTX_ID, ALICE_DID, epoch_post, 0)
            .unwrap();

        // SECURITY ASSERTION: Bob's stale state cannot decrypt — his MLS group
        // is stuck at the old epoch and AEAD decryption fails on the new-epoch
        // ciphertext.
        assert!(
            bob_state
                .decrypt_message(&post_ct, CTX_ID, ALICE_DID, epoch_post, 0)
                .is_err(),
            "an evicted member MUST NOT be able to decrypt messages sent after \
             his removal — this is the security boundary the MLS eviction restores"
        );

        // LIVENESS ASSERTION: Carol, still a member, decrypts Alice's send.
        let post_ct_carol = alice_state
            .encrypt_message(post_plaintext, CTX_ID, ALICE_DID, epoch_post, 1)
            .unwrap();
        assert_eq!(
            carol_state
                .decrypt_message(&post_ct_carol, CTX_ID, ALICE_DID, epoch_post, 1)
                .unwrap(),
            post_plaintext,
            "a remaining member MUST still be able to decrypt after the eviction"
        );
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
