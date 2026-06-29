//! Orchestration layer combining MLS encryption and sender key layer.
//!
//! `WasmCryptoState` holds both an MLS group and a sender key store, providing
//! a single entry point for the full double-encryption pipeline:
//! sender key encrypt -> MLS encrypt (on send) and
//! MLS decrypt -> sender key decrypt (on receive).
//!
//! The sender-layer wire format and epoch semantics mirror the native
//! `scp-runtime` MLS crypto provider (`crypto/mls/provider.rs`) so that WASM
//! and native cross-decrypt (§9.16.1). In particular:
//!
//! - Each MLS application plaintext is `epoch (8B BE) || sequence (8B BE) ||
//!   sender_key_ciphertext` (the shared
//!   [`build_sender_header`](scp_protocol::crypto::sender_keys::encrypt::build_sender_header)
//!   framing). The `epoch` is this participant's per-context
//!   **`sender_key_epoch`** (§9.16.5: monotonic, initialized to 1 on keygen,
//!   incremented ONLY on block/rotation events — NOT on MLS epoch advances).
//! - Recipients reconstruct the AEAD AAD from the parsed header (the header is
//!   authoritative), enforce the epoch-poisoning ceiling
//!   ([`MAX_EPOCH_ADVANCE`](scp_protocol::crypto::sender_keys::MAX_EPOCH_ADVANCE))
//!   BEFORE recording the replay tracker, then reject replays/reorders via a
//!   per-sender `(last_epoch, last_sequence)` tracker.

use std::collections::HashMap;

use zeroize::Zeroize;

use super::error::WasmCryptoError;
use super::group::WasmMlsGroup;
use super::sender_key::{
    MAX_EPOCH_ADVANCE, SenderKey, SenderKeyStore, build_sender_header, decrypt_sender_layer,
    encrypt_sender_layer, generate_sender_key, parse_sender_header,
};

/// The sender-key epoch a freshly generated key starts at (§9.16.5).
///
/// Mirrors native `MlsCryptoProvider` which seeds `sender_key_epoch = 1` at
/// keygen (`provider.rs`). Starting at 1 (not 0) keeps the first application
/// message's 8-byte big-endian epoch prefix as `0x0000000000000001`, which can
/// never collide with the 4-byte `SCPM_MAGIC` management prefix (§9.16.1).
pub const INITIAL_SENDER_KEY_EPOCH: u64 = 1;

/// Combined MLS + sender key state for a single context.
///
/// Owns the MLS group and manages per-sender AES-256 keys. The double
/// encryption pipeline is:
///
/// **Send:** `plaintext` -> sender key encrypt -> prepend header -> MLS encrypt
/// **Receive:** MLS decrypt -> parse header -> ceiling + replay -> sender key
/// decrypt -> `plaintext`
pub struct WasmCryptoState {
    /// The MLS group for this context.
    pub mls_group: WasmMlsGroup,
    /// This participant's own sender key.
    pub local_sender_key: SenderKey,
    /// The raw `context_id` string this state belongs to.
    ///
    /// Used as the [`SenderKeyStore`] outer key and as the AEAD-AAD context
    /// binding (§9.16.1 binds the RAW string, not the hex of its hash —
    /// matching native `seal`/`open` and the Phase 1 AAD convergence). A
    /// [`WasmCryptoState`] is single-context, so this never changes after
    /// construction.
    pub context_id: String,
    /// This participant's monotonic sender-key epoch (§9.16.5). Initialized to
    /// [`INITIAL_SENDER_KEY_EPOCH`] on keygen; incremented ONLY on block /
    /// rotation events (NOT on MLS epoch advances). Fed into BOTH the AEAD AAD
    /// and the 16-byte header on every send.
    pub sender_key_epoch: u64,
    /// Sender keys from other participants, keyed by `(context_id, sender_did)`
    /// in the shared [`SenderKeyStore`]. The store also tracks per-sender epoch
    /// high-water marks (`set_checked` monotonicity) and supports the
    /// epoch-poisoning ceiling lookup on the receive path.
    pub sender_key_store: SenderKeyStore,
    /// Receive-side replay detection: `sender_did -> (last_epoch,
    /// last_sequence)`. A message with `epoch < last_epoch` or `(epoch ==
    /// last_epoch && sequence <= last_sequence)` is rejected (§9.16.1). Mirrors
    /// native's `recv_sequence_tracker`.
    pub recv_sequence_tracker: HashMap<String, (u64, u64)>,
}

impl WasmCryptoState {
    /// Creates a new crypto state for a context.
    ///
    /// Creates the MLS group with the creator as sole member and generates
    /// a fresh sender key (epoch [`INITIAL_SENDER_KEY_EPOCH`]).
    ///
    /// # Errors
    ///
    /// Returns an error if MLS group creation fails.
    pub fn new_for_context(context_id: &str, creator_did: &str) -> Result<Self, WasmCryptoError> {
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
            context_id: context_id.to_owned(),
            sender_key_epoch: INITIAL_SENDER_KEY_EPOCH,
            sender_key_store: SenderKeyStore::new(),
            recv_sequence_tracker: HashMap::new(),
        })
    }

    /// Records a remote member's sender key in the store WITHOUT epoch
    /// monotonicity enforcement.
    ///
    /// WASM has no cross-member sender-key distribution path for encrypted MLS
    /// contexts (a pre-existing gap; the keys are exchanged out-of-band by
    /// tests and, in production, would be installed by a future distribution
    /// path). This setter mirrors the old bare-`HashMap::insert` semantics so
    /// callers that already trust the source can install a key. The remote
    /// sender's epoch high-water (used by the receive ceiling) is advanced only
    /// by observing that sender's message headers; a bare install therefore
    /// leaves it at its prior value (0 for a first install). The receive
    /// ceiling tolerates this because it permits up to `MAX_EPOCH_ADVANCE`
    /// above the stored high-water.
    pub fn insert_sender_key(&mut self, sender_did: &str, key: SenderKey) {
        let context_id = self.context_id.clone();
        self.sender_key_store
            .set_unchecked(&context_id, sender_did, key);
    }

    /// Encrypts a message using the full double-encryption pipeline.
    ///
    /// 1. Encrypt with the local sender key (AES-256-GCM with AAD binding the
    ///    raw `context_id`, `sender_did`, `self.sender_key_epoch`, and
    ///    `sequence`).
    /// 2. Prepend the 16-byte `epoch || sequence` header (§9.16.1) — the epoch
    ///    is `self.sender_key_epoch`, NOT the MLS group epoch.
    /// 3. MLS-encrypt the framed result.
    ///
    /// # Errors
    ///
    /// Returns an error if either encryption layer fails.
    pub fn encrypt_message(
        &mut self,
        plaintext: &[u8],
        context_id: &str,
        sender_did: &str,
        sequence: u64,
    ) -> Result<Vec<u8>, WasmCryptoError> {
        let epoch = self.sender_key_epoch;

        // Layer 1: sender key encrypt. The epoch bound into the AAD is the
        // sender-key epoch (§9.16.5), matching the header below.
        let sender_encrypted = encrypt_sender_layer(
            &self.local_sender_key,
            plaintext,
            context_id,
            sender_did,
            epoch,
            sequence,
        )?;

        // Prepend the 16-byte epoch || sequence header (§9.16.1). The same
        // `epoch` feeds the AAD and the header so the receive side reconstructs
        // an identical AAD from the parsed header.
        let with_header = build_sender_header(epoch, sequence, &sender_encrypted);

        // Layer 2: MLS encrypt.
        self.mls_group.encrypt(&with_header)
    }

    /// Decrypts a message using the full double-decryption pipeline.
    ///
    /// 1. MLS-decrypt to recover the framed sender-layer plaintext.
    /// 2. Parse the 16-byte `epoch || sequence` header — the header is
    ///    AUTHORITATIVE (matching native `open`).
    /// 3. Enforce the epoch-poisoning ceiling (§9.16.1) BEFORE recording the
    ///    replay tracker: reject `epoch > store.epoch(ctx, sender) +
    ///    MAX_EPOCH_ADVANCE` so a `u64::MAX` header cannot poison the tracker.
    /// 4. Reject replays/reorders against the per-sender
    ///    `(last_epoch, last_sequence)` tracker.
    /// 5. Sender-key-decrypt using the PARSED epoch/sequence, then record the
    ///    tracker only on success.
    ///
    /// # Errors
    ///
    /// Returns an error if MLS decryption fails, the header is malformed, the
    /// epoch exceeds the ceiling, the message is a replay/reorder, the sender's
    /// key is not in the store, or AEAD verification fails.
    pub fn decrypt_message(
        &mut self,
        ciphertext: &[u8],
        context_id: &str,
        sender_did: &str,
    ) -> Result<Vec<u8>, WasmCryptoError> {
        // Layer 1: MLS decrypt.
        let mls_decrypted = self.mls_group.decrypt(ciphertext)?;

        // Step 2: parse the authoritative epoch || sequence header.
        let (epoch, sequence, sender_ciphertext) = parse_sender_header(&mls_decrypted)?;

        // Step 3: epoch-poisoning ceiling (§9.16.1), enforced BEFORE the replay
        // tracker is touched. Without this guard a single header carrying
        // `epoch = u64::MAX` would advance `recv_sequence_tracker` and
        // permanently lock out all subsequent legitimate messages from this
        // sender (self-DoS / persistent per-receiver poisoning). Mirrors native
        // `open`'s receive ceiling.
        let stored_high_water = self.sender_key_store.epoch(context_id, sender_did);
        let allowed_epoch_ceiling = stored_high_water.saturating_add(MAX_EPOCH_ADVANCE);
        if epoch > allowed_epoch_ceiling {
            return Err(WasmCryptoError::SenderKeyError(format!(
                "sender key epoch {epoch} exceeds ceiling {allowed_epoch_ceiling} \
                 (stored high-water {stored_high_water}, MAX_EPOCH_ADVANCE {MAX_EPOCH_ADVANCE})"
            )));
        }

        // Step 4: replay/reorder detection. Reject epoch/sequence <= last seen
        // for this sender (§9.16.1). The tracker is consulted BEFORE insert so a
        // duplicate (epoch, sequence) or an older one is refused.
        if let Some(&(last_epoch, last_seq)) = self.recv_sequence_tracker.get(sender_did)
            && (epoch < last_epoch || (epoch == last_epoch && sequence <= last_seq))
        {
            return Err(WasmCryptoError::SenderKeyError(
                "replay or reorder detected".to_owned(),
            ));
        }

        // Look up the sender's key BEFORE recording the tracker so a missing
        // key does not advance the tracker (a message we cannot decrypt is not
        // "seen" for replay purposes).
        let sender_key = self
            .sender_key_store
            .get(context_id, sender_did)
            .ok_or_else(|| {
                WasmCryptoError::SenderKeyError(format!("no sender key for DID '{sender_did}'"))
            })?
            .clone();

        // Step 5a: sender-key decrypt using the PARSED epoch/sequence (the
        // header is authoritative). The AAD binds the raw context_id string
        // (§9.16.1), matching `encrypt_message` and native `seal`.
        let plaintext = decrypt_sender_layer(
            &sender_key,
            sender_ciphertext,
            context_id,
            sender_did,
            epoch,
            sequence,
        )?;

        // Step 5b: record the tracker only after a SUCCESSFUL decrypt, so a
        // forged-but-undecryptable header cannot advance the replay floor.
        self.recv_sequence_tracker
            .insert(sender_did.to_owned(), (epoch, sequence));

        Ok(plaintext)
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
    /// A member who is in the context's membership set but carries no MLS leaf
    /// (e.g. never MLS-added) is a NO-OP that returns an empty commit — matching
    /// native `MlsCryptoProvider::remove_member`, because the governance layer
    /// is authoritative for membership and the crypto layer only manages MLS
    /// state.
    ///
    /// Self-removal is likewise an empty-commit no-op, matching BOTH of native's
    /// self-removal mechanisms: the self-DID short-circuit (provider.rs:1041)
    /// and the own-leaf skip in the scan (provider.rs:1060). This holds even in
    /// a pathological duplicate-DID tree — a second leaf carrying the local DID
    /// is NOT evicted, mirroring native. See
    /// [`WasmMlsGroup::remove_member_by_did`](super::group::WasmMlsGroup::remove_member_by_did).
    ///
    /// # Errors
    ///
    /// Returns an error if the group is destroyed, or if a leaf IS found but the
    /// underlying remove/commit serialization fails — genuine MLS failures that
    /// must propagate so the dispatch layer can fail closed (keep the member).
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
    ///
    /// The sender's epoch high-water mark in the store is deliberately
    /// PRESERVED (`SenderKeyStore::remove` keeps it) so a later replayed
    /// old-epoch key for the same DID is still rejected by `set_checked`.
    pub fn governance_remove_sender_key(&mut self, member_did: &str) {
        // The removed value is zeroized when it drops (SenderKey: ZeroizeOnDrop).
        let context_id = self.context_id.clone();
        drop(self.sender_key_store.remove(&context_id, member_did));
    }

    /// Rotates this participant's local sender key, zeroizing the old key, and
    /// advances the sender-key epoch (§9.16.5).
    ///
    /// Mirrors native `MlsCrypto::rotate_sender_key` (spec §9.16.4): after a
    /// member is removed, the remaining members rotate their sender keys so the
    /// evicted member's knowledge of any prior sender key grants no future
    /// sender-layer plaintext. That is this rotation's entire security purpose —
    /// denying the evicted member the sender layer.
    ///
    /// This is WASM's analogue of native's block/rotation-driven epoch advance:
    /// the new key is bound to a strictly higher `sender_key_epoch`, so the
    /// first message sent after rotation carries an advanced epoch in both its
    /// AAD and its header. The increment is saturating — at `u64::MAX` the epoch
    /// stays pinned rather than wrapping to 0, which would (a) violate
    /// monotonicity and (b) collide with `SCPM_MAGIC` framing assumptions. A
    /// context that genuinely exhausts `u64::MAX` rotations is not reachable.
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
        // Advance the epoch monotonically (saturating at u64::MAX).
        self.sender_key_epoch = self.sender_key_epoch.saturating_add(1);
    }

    /// Destroys all crypto state (MLS group + sender keys).
    ///
    /// Eagerly zeroizes the local sender key rather than waiting for
    /// `WasmCryptoState` to be dropped.
    pub fn destroy(&mut self) {
        self.mls_group.destroy();
        // SenderKey implements ZeroizeOnDrop, so replacing the store will
        // zeroize each key as the old store is dropped.
        self.sender_key_store = SenderKeyStore::new();
        self.recv_sequence_tracker.clear();
        // Eagerly zeroize the local sender key. The old value is overwritten
        // in-place, triggering Zeroize on the inner [u8; 32].
        self.local_sender_key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::credential::{WasmScpCredential, WasmSigningKeyId};
    use crate::crypto::sender_key::{SENDER_HEADER_SIZE, generate_sender_key};
    use openmls::prelude::*;
    use tls_codec::Deserialize as TlsDeserializeTrait;

    const ALICE_DID: &str = "did:dht:z6MkAlice";
    const BOB_DID: &str = "did:dht:z6MkBob";
    const CTX_ID: &str = "ctx-test-crypto-state";

    /// Builds a `WasmCryptoState` for a member who joined via Welcome, with the
    /// given MLS group and a fresh sender key (epoch 1, empty trackers).
    fn member_state(context_id: &str, mls_group: WasmMlsGroup) -> WasmCryptoState {
        WasmCryptoState {
            mls_group,
            local_sender_key: generate_sender_key(),
            context_id: context_id.to_owned(),
            sender_key_epoch: INITIAL_SENDER_KEY_EPOCH,
            sender_key_store: SenderKeyStore::new(),
            recv_sequence_tracker: HashMap::new(),
        }
    }

    /// Adds `member_did` to `adder`'s group and returns a `WasmCryptoState` for
    /// the new member built from the resulting Welcome.
    #[allow(clippy::unwrap_used)]
    fn add_member_and_build(adder: &mut WasmCryptoState, member_did: &str) -> WasmCryptoState {
        let cred =
            WasmScpCredential::new(member_did.to_string(), None, WasmSigningKeyId::Active).unwrap();
        let (kp_bytes, holder) = WasmMlsGroup::generate_key_package(&cred).unwrap();
        let kp_in = KeyPackageIn::tls_deserialize(&mut &*kp_bytes).unwrap();
        let (_commit, welcome) = adder.mls_group.add_member(kp_in).unwrap();
        let group = WasmMlsGroup::join_from_welcome(&welcome, holder).unwrap();
        member_state(&adder.context_id, group)
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn new_for_context_creates_valid_state() {
        let state = WasmCryptoState::new_for_context(CTX_ID, ALICE_DID).unwrap();
        assert!(!state.mls_group.is_destroyed());
        assert_eq!(state.mls_group.epoch().unwrap(), 0);
        assert_eq!(state.local_sender_key.as_bytes().len(), 32);
        // Sender-key epoch starts at 1 (§9.16.5), independent of the MLS epoch.
        assert_eq!(state.sender_key_epoch, 1);
        assert_eq!(state.context_id, CTX_ID);
    }

    /// The header KAT: `build_sender_header(1, 0, ct)` lays out epoch BE,
    /// sequence BE, then ciphertext, and `SENDER_HEADER_SIZE == 16`.
    #[test]
    #[allow(clippy::unwrap_used)]
    fn header_kat_layout_and_size() {
        assert_eq!(SENDER_HEADER_SIZE, 16);
        let ct = b"ct";
        let header = build_sender_header(1, 0, ct);
        // epoch (8B BE) = 1
        assert_eq!(&header[0..8], &1u64.to_be_bytes());
        // sequence (8B BE) = 0
        assert_eq!(&header[8..16], &0u64.to_be_bytes());
        // remainder is the ciphertext verbatim
        assert_eq!(&header[16..], ct);

        let (epoch, sequence, data) = parse_sender_header(&header).unwrap();
        assert_eq!(epoch, 1);
        assert_eq!(sequence, 0);
        assert_eq!(data, ct);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn full_encrypt_decrypt_chain() {
        let mut alice_state = WasmCryptoState::new_for_context(CTX_ID, ALICE_DID).unwrap();
        let mut bob_state = add_member_and_build(&mut alice_state, BOB_DID);

        // Exchange sender keys: Alice gives Bob her sender key, Bob gives Alice his.
        bob_state.insert_sender_key(
            ALICE_DID,
            SenderKey::from_bytes(*alice_state.local_sender_key.as_bytes()),
        );
        alice_state.insert_sender_key(
            BOB_DID,
            SenderKey::from_bytes(*bob_state.local_sender_key.as_bytes()),
        );

        // Alice encrypts a message. The header epoch is Alice's sender_key_epoch
        // (1), NOT the MLS group epoch.
        let plaintext = b"encrypted via double layer";
        let ciphertext = alice_state
            .encrypt_message(plaintext, CTX_ID, ALICE_DID, 0)
            .unwrap();

        // Bob decrypts — epoch/sequence are parsed from the header, not supplied.
        let decrypted = bob_state
            .decrypt_message(&ciphertext, CTX_ID, ALICE_DID)
            .unwrap();

        assert_eq!(decrypted, plaintext);
        // Bob's tracker recorded (epoch 1, sequence 0).
        assert_eq!(
            bob_state.recv_sequence_tracker.get(ALICE_DID),
            Some(&(1u64, 0u64))
        );
    }

    /// Replay rejection: an older (epoch, sequence) is refused after a newer
    /// one, and a duplicate (epoch, sequence) is refused.
    #[test]
    #[allow(clippy::unwrap_used)]
    fn replay_and_reorder_rejected() {
        let mut alice_state = WasmCryptoState::new_for_context(CTX_ID, ALICE_DID).unwrap();
        let mut bob_state = add_member_and_build(&mut alice_state, BOB_DID);
        bob_state.insert_sender_key(
            ALICE_DID,
            SenderKey::from_bytes(*alice_state.local_sender_key.as_bytes()),
        );

        // Alice sends seq 1, then seq 2, then a duplicate of seq 1 (re-encrypted
        // at the SAME sender-layer epoch/seq — MLS is stateful so the outer
        // frame differs, but the parsed header is identical).
        let ct_seq1 = alice_state
            .encrypt_message(b"first", CTX_ID, ALICE_DID, 1)
            .unwrap();
        let ct_seq2 = alice_state
            .encrypt_message(b"second", CTX_ID, ALICE_DID, 2)
            .unwrap();
        let ct_seq1_dup = alice_state
            .encrypt_message(b"first-again", CTX_ID, ALICE_DID, 1)
            .unwrap();

        // Deliver seq 2 first — accepted (tracker empty).
        assert_eq!(
            bob_state
                .decrypt_message(&ct_seq2, CTX_ID, ALICE_DID)
                .unwrap(),
            b"second"
        );
        // Now seq 1 (older) — rejected as a reorder/replay.
        assert!(
            bob_state
                .decrypt_message(&ct_seq1, CTX_ID, ALICE_DID)
                .is_err(),
            "an older (epoch, sequence) must be rejected after a newer one"
        );
        // The same-seq duplicate is likewise rejected.
        assert!(
            bob_state
                .decrypt_message(&ct_seq1_dup, CTX_ID, ALICE_DID)
                .is_err(),
            "a duplicate (epoch, sequence) must be rejected"
        );
    }

    /// A first-decrypt that FAILS (no sender key) must not advance the replay
    /// tracker, so a later legitimate message at the same sequence is accepted.
    #[test]
    #[allow(clippy::unwrap_used)]
    fn failed_decrypt_does_not_advance_tracker() {
        let mut alice_state = WasmCryptoState::new_for_context(CTX_ID, ALICE_DID).unwrap();
        let mut bob_state = add_member_and_build(&mut alice_state, BOB_DID);

        // Bob does NOT yet have Alice's sender key. Alice's first send fails to
        // decrypt at the sender-key layer (after MLS), and must not advance the
        // tracker.
        let ct1 = alice_state
            .encrypt_message(b"one", CTX_ID, ALICE_DID, 1)
            .unwrap();
        assert!(bob_state.decrypt_message(&ct1, CTX_ID, ALICE_DID).is_err());
        assert!(!bob_state.recv_sequence_tracker.contains_key(ALICE_DID));

        // Now Bob receives Alice's key out-of-band and a fresh send at seq 1
        // (the original was never "seen") decrypts fine.
        bob_state.insert_sender_key(
            ALICE_DID,
            SenderKey::from_bytes(*alice_state.local_sender_key.as_bytes()),
        );
        let ct1b = alice_state
            .encrypt_message(b"one-b", CTX_ID, ALICE_DID, 1)
            .unwrap();
        assert_eq!(
            bob_state.decrypt_message(&ct1b, CTX_ID, ALICE_DID).unwrap(),
            b"one-b"
        );
    }

    /// Epoch-ceiling: a header epoch beyond `store.epoch + MAX_EPOCH_ADVANCE`
    /// (here `u64::MAX`) is rejected and the replay tracker is NOT advanced.
    #[test]
    #[allow(clippy::unwrap_used)]
    fn epoch_ceiling_rejects_and_does_not_advance_tracker() {
        let mut alice_state = WasmCryptoState::new_for_context(CTX_ID, ALICE_DID).unwrap();
        let mut bob_state = add_member_and_build(&mut alice_state, BOB_DID);
        bob_state.insert_sender_key(
            ALICE_DID,
            SenderKey::from_bytes(*alice_state.local_sender_key.as_bytes()),
        );

        // Forge Alice's sender_key_epoch to u64::MAX so her next send carries a
        // poisoning header epoch. (Alice is the adversary against Bob's tracker.)
        alice_state.sender_key_epoch = u64::MAX;
        let poisoned = alice_state
            .encrypt_message(b"poison", CTX_ID, ALICE_DID, 0)
            .unwrap();
        assert!(
            bob_state
                .decrypt_message(&poisoned, CTX_ID, ALICE_DID)
                .is_err(),
            "an epoch beyond store.epoch + MAX_EPOCH_ADVANCE must be rejected"
        );
        // Tracker NOT advanced: no entry recorded for Alice.
        assert!(
            !bob_state.recv_sequence_tracker.contains_key(ALICE_DID),
            "a ceiling-rejected message must not advance the replay tracker"
        );
    }

    /// `governance_rotate_sender_key` increments `sender_key_epoch`, and the new
    /// epoch is bound into BOTH the header and the AAD of the next send (a peer
    /// holding the rotated key decrypts; a wrong epoch in the AAD would fail).
    #[test]
    #[allow(clippy::unwrap_used)]
    fn rotate_advances_epoch_in_header_and_aad() {
        let mut alice_state = WasmCryptoState::new_for_context(CTX_ID, ALICE_DID).unwrap();
        let mut bob_state = add_member_and_build(&mut alice_state, BOB_DID);

        assert_eq!(alice_state.sender_key_epoch, 1);
        alice_state.governance_rotate_sender_key();
        assert_eq!(
            alice_state.sender_key_epoch, 2,
            "rotation must advance the sender-key epoch"
        );

        // Bob receives Alice's ROTATED key.
        bob_state.insert_sender_key(
            ALICE_DID,
            SenderKey::from_bytes(*alice_state.local_sender_key.as_bytes()),
        );

        let ct = alice_state
            .encrypt_message(b"after rotation", CTX_ID, ALICE_DID, 0)
            .unwrap();
        let pt = bob_state.decrypt_message(&ct, CTX_ID, ALICE_DID).unwrap();
        assert_eq!(pt, b"after rotation");
        assert_eq!(
            bob_state.recv_sequence_tracker.get(ALICE_DID),
            Some(&(2u64, 0u64)),
            "the tracker must record the rotated epoch parsed from the header"
        );
    }

    /// Replay protection is IN-SESSION ONLY, matching native's foreign-node
    /// behavior: a freshly established WASM crypto state starts with an EMPTY
    /// receive-sequence tracker, an empty per-sender epoch high-water store, and
    /// `sender_key_epoch` at the initial value. Native deliberately DROPS its
    /// freshness/replay cache from the portable cross-party export (a foreign
    /// node has no authority over it and a fresh node opens its own receive
    /// window — see `scp-runtime` `export_import.rs`). WASM converges: the
    /// receive window is rebuilt live as messages arrive within the session, and
    /// is never seeded from an importable snapshot (which would let a signed-but-
    /// malicious creator reopen replay or poison a third-party sender's epoch
    /// high-water, bypassing the `MAX_EPOCH_ADVANCE` ceiling).
    #[test]
    #[allow(clippy::unwrap_used)]
    fn fresh_crypto_state_starts_with_empty_replay_window() {
        // A creator-established state.
        let alice_state = WasmCryptoState::new_for_context(CTX_ID, ALICE_DID).unwrap();
        assert!(
            alice_state.recv_sequence_tracker.is_empty(),
            "a fresh crypto state must start with an empty receive replay window"
        );
        assert!(
            alice_state
                .sender_key_store
                .epochs_for_context(CTX_ID)
                .is_empty(),
            "a fresh crypto state must start with no per-sender epoch high-water"
        );
        assert_eq!(
            alice_state.sender_key_epoch, INITIAL_SENDER_KEY_EPOCH,
            "a fresh crypto state must start at the initial sender-key epoch"
        );

        // A member-established state (joined via Welcome) likewise starts fresh —
        // there is no cross-party tracker injection path.
        let mut alice_state = alice_state;
        let bob_state = add_member_and_build(&mut alice_state, BOB_DID);
        assert!(
            bob_state.recv_sequence_tracker.is_empty(),
            "a Welcome-joined crypto state must start with an empty receive window"
        );
        assert!(
            bob_state
                .sender_key_store
                .epochs_for_context(CTX_ID)
                .is_empty(),
            "a Welcome-joined crypto state must start with no epoch high-water"
        );
        assert_eq!(bob_state.sender_key_epoch, INITIAL_SENDER_KEY_EPOCH);
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
        // Alice creates the context and adds Bob.
        let mut alice_state = WasmCryptoState::new_for_context(CTX_ID, ALICE_DID).unwrap();
        let mut bob_state = add_member_and_build(&mut alice_state, BOB_DID);

        // Alice adds Carol. Bob must process Alice's add-Carol commit so his MLS
        // group stays in lockstep with the group epoch up to the eviction.
        let carol_cred =
            WasmScpCredential::new(CAROL_DID.to_string(), None, WasmSigningKeyId::Active).unwrap();
        let (carol_kp_bytes, carol_holder) =
            WasmMlsGroup::generate_key_package(&carol_cred).unwrap();
        let carol_kp_in = KeyPackageIn::tls_deserialize(&mut &*carol_kp_bytes).unwrap();
        let (commit_carol, welcome_carol) = alice_state.mls_group.add_member(carol_kp_in).unwrap();
        assert!(
            bob_state.mls_group.decrypt(&commit_carol).is_err(),
            "processing a commit returns NotApplicationMessage, not plaintext"
        );
        let carol_mls_group =
            WasmMlsGroup::join_from_welcome(&welcome_carol, carol_holder).unwrap();
        let mut carol_state = member_state(CTX_ID, carol_mls_group);

        // Sender-key exchange: every member learns Alice's current sender key.
        bob_state.insert_sender_key(
            ALICE_DID,
            SenderKey::from_bytes(*alice_state.local_sender_key.as_bytes()),
        );
        carol_state.insert_sender_key(
            ALICE_DID,
            SenderKey::from_bytes(*alice_state.local_sender_key.as_bytes()),
        );

        // Sanity: before eviction, both Bob and Carol can decrypt Alice's send.
        let pre_plaintext = b"before eviction";
        let pre_ct = alice_state
            .encrypt_message(pre_plaintext, CTX_ID, ALICE_DID, 0)
            .unwrap();
        let pre_ct_carol = alice_state
            .encrypt_message(pre_plaintext, CTX_ID, ALICE_DID, 1)
            .unwrap();
        assert_eq!(
            bob_state
                .decrypt_message(&pre_ct, CTX_ID, ALICE_DID)
                .unwrap(),
            pre_plaintext,
            "Bob must be able to decrypt before he is evicted"
        );
        assert_eq!(
            carol_state
                .decrypt_message(&pre_ct_carol, CTX_ID, ALICE_DID)
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

        // Carol receives Alice's rotated sender key (WASM has no cross-member
        // distribution path; the test hands it over to isolate the MLS-eviction
        // property — it must hold even when the rotated key IS available).
        carol_state.insert_sender_key(
            ALICE_DID,
            SenderKey::from_bytes(*alice_state.local_sender_key.as_bytes()),
        );

        // Alice sends after the eviction. The sender-key header now carries
        // Alice's advanced sender_key_epoch (2).
        let post_plaintext = b"after eviction - bob must not read this";
        let post_ct = alice_state
            .encrypt_message(post_plaintext, CTX_ID, ALICE_DID, 0)
            .unwrap();

        // SECURITY ASSERTION: Bob's stale state cannot decrypt — his MLS group
        // is stuck at the old epoch and AEAD decryption fails on the new-epoch
        // ciphertext.
        assert!(
            bob_state
                .decrypt_message(&post_ct, CTX_ID, ALICE_DID)
                .is_err(),
            "an evicted member MUST NOT be able to decrypt messages sent after \
             his removal — this is the security boundary the MLS eviction restores"
        );

        // LIVENESS ASSERTION: Carol, still a member, decrypts Alice's send.
        let post_ct_carol = alice_state
            .encrypt_message(post_plaintext, CTX_ID, ALICE_DID, 1)
            .unwrap();
        assert_eq!(
            carol_state
                .decrypt_message(&post_ct_carol, CTX_ID, ALICE_DID)
                .unwrap(),
            post_plaintext,
            "a remaining member MUST still be able to decrypt after the eviction"
        );
    }

    /// Governance-layer parity for native's self-DID short-circuit
    /// (provider.rs:1041) in a pathological duplicate-DID tree. A second leaf
    /// carries Alice's OWN DID; `governance_remove_from_group(own_did)` must be
    /// an empty-commit no-op that does NOT evict the duplicate leaf and does NOT
    /// advance the epoch — matching native, which evicts neither leaf.
    #[test]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    fn governance_remove_self_did_no_op_in_dup_did_tree() {
        let mut alice_state = WasmCryptoState::new_for_context(CTX_ID, ALICE_DID).unwrap();

        // Add a second leaf carrying Alice's SAME DID but a fresh signing key.
        let dup_cred =
            WasmScpCredential::new(ALICE_DID.to_string(), None, WasmSigningKeyId::Active).unwrap();
        let (dup_kp_bytes, _dup_holder) = WasmMlsGroup::generate_key_package(&dup_cred).unwrap();
        let dup_kp_in = KeyPackageIn::tls_deserialize(&mut &*dup_kp_bytes).unwrap();
        alice_state.mls_group.add_member(dup_kp_in).unwrap();

        let epoch_after_add = alice_state.mls_group.epoch().unwrap();

        // Self-removal via the governance entry point is an empty no-op.
        let commit = alice_state
            .governance_remove_from_group(ALICE_DID)
            .expect("self-DID governance removal in a dup-DID tree must be a no-op");
        assert!(
            commit.is_empty(),
            "self-DID governance removal must produce an empty commit"
        );
        assert_eq!(
            alice_state.mls_group.epoch().unwrap(),
            epoch_after_add,
            "self-DID governance removal must NOT advance the epoch (duplicate \
             leaf NOT evicted, matching native's short-circuit)"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn decrypt_fails_without_sender_key() {
        let mut alice_state = WasmCryptoState::new_for_context(CTX_ID, ALICE_DID).unwrap();
        // Deliberately NOT adding Alice's sender key to Bob.
        let mut bob_state = add_member_and_build(&mut alice_state, BOB_DID);

        let plaintext = b"should fail";
        let ciphertext = alice_state
            .encrypt_message(plaintext, CTX_ID, ALICE_DID, 0)
            .unwrap();

        let result = bob_state.decrypt_message(&ciphertext, CTX_ID, ALICE_DID);
        assert!(result.is_err());
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn destroy_prevents_further_operations() {
        let mut state = WasmCryptoState::new_for_context(CTX_ID, ALICE_DID).unwrap();
        state.destroy();

        assert!(state.mls_group.is_destroyed());
        assert!(
            state
                .encrypt_message(b"test", CTX_ID, ALICE_DID, 0)
                .is_err()
        );
    }
}
