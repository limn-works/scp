//! Double-encryption (§9.16) orchestration for a single context.
//!
//! [`ContextCryptoState`] holds an MLS group ([`scp_mls::ScpMlsGroup`]) and a
//! sender-key store, providing the full SCP double-encryption pipeline:
//! sender-key encrypt → MLS encrypt (on send) and MLS decrypt → sender-key
//! decrypt (on receive).
//!
//! This restores the *shape* of the deleted WASM bridge's `WasmCryptoState`
//! (the pinned `1a3b41a5e^` restoration source named by ADR-057), but every
//! body calls the **shared** `scp-mls` MLS state machine and the **shared**
//! `scp_protocol::crypto::sender_keys` layer rather than a wasm-local
//! re-implementation. There is exactly one MLS implementation and one
//! sender-key implementation; this struct only sequences them.
//!
//! The sender-layer wire format mirrors the native runtime so a native member
//! and a browser member cross-decrypt (§9.16.1):
//!
//! - Each MLS application plaintext is `epoch (8B BE) || sequence (8B BE) ||
//!   sender_key_ciphertext` (the shared
//!   [`build_sender_header`](scp_protocol::crypto::sender_keys::encrypt::build_sender_header)).
//!   The `epoch` is this participant's monotonic per-context **sender-key
//!   epoch** (§9.16.5: initialized to 1 on keygen, advanced only on
//!   block/rotation — NOT on MLS epoch advances).
//! - Recipients reconstruct the AEAD AAD from the parsed header (the header is
//!   authoritative), enforce the epoch-poisoning ceiling
//!   ([`MAX_EPOCH_ADVANCE`](scp_protocol::crypto::sender_keys::MAX_EPOCH_ADVANCE))
//!   BEFORE recording the replay tracker, then reject replays/reorders via a
//!   per-sender `(last_epoch, last_sequence)` tracker.

use std::collections::HashMap;

use scp_mls::ScpMlsGroup;
use scp_mls::encrypt::{
    InboundChange, decrypt_with_membership_changes, encrypt, serialize_ciphertext,
};
use scp_protocol::crypto::sender_keys::encrypt::{
    build_sender_header, decrypt_sender_layer, encrypt_sender_layer, parse_sender_header,
};
use scp_protocol::crypto::sender_keys::{
    MAX_EPOCH_ADVANCE, SenderKey, SenderKeyStore, generate_sender_key,
};

use crate::error::ClientError;

/// The sender-key epoch a freshly generated key starts at (§9.16.5).
///
/// Mirrors the native `MlsCryptoProvider`, which seeds `sender_key_epoch = 1`
/// at keygen. Starting at 1 (not 0) keeps the first application message's
/// 8-byte big-endian epoch prefix as `0x0000000000000001`, which can never
/// collide with the 4-byte `SCPM_MAGIC` management prefix (§9.16.1).
pub const INITIAL_SENDER_KEY_EPOCH: u64 = 1;

/// The outcome of decrypting an inbound MLS message.
///
/// Distinguishes an application message (carrying recovered plaintext and the
/// sender DID) from a control message. A control message is further split into
/// an **add-only membership-changing Commit** (carrying the DIDs the Commit
/// added, recovered from the staged commit before merge — see
/// [`decrypt_with_membership_changes`]), an **unsupported (Remove-bearing)
/// Commit** that `scp-mls` rejected *without merging* (leaving MLS + SCP state
/// consistent), and a bare proposal. The driver maps an application message into
/// a `MessageReceived` event, mirrors an add Commit's membership change onto its
/// event log + membership set (so existing members converge with the committer
/// and the new joiner), maps the unsupported variant to a fail-closed error, and
/// treats a proposal as a silent cache.
#[derive(Clone, PartialEq, Eq)]
pub enum Inbound {
    /// An application message: recovered plaintext plus the sender's DID.
    Application {
        /// The sender's DID, extracted from the MLS credential.
        sender_did: String,
        /// The fully decrypted plaintext.
        plaintext: Vec<u8>,
    },
    /// An **add-only** Commit that advanced the group epoch. `scp-mls` has
    /// already merged it; `added_dids` are the SCP DIDs the Commit's Add
    /// proposals add (in proposal order), for the driver to mirror onto its
    /// SCP-layer membership + event log.
    Commit {
        /// The committer's DID, extracted from the MLS credential.
        sender_did: String,
        /// DIDs added by this Commit's Add proposals.
        added_dids: Vec<String>,
    },
    /// A Commit carrying one or more Remove proposals, which the participant
    /// driver does not converge. `scp-mls` **dropped the staged commit without
    /// merging**, so the MLS group is still on its pre-Commit epoch and remains
    /// consistent with the driver's SCP-layer state. The driver maps this to a
    /// fail-closed [`ClientError::UnsupportedMembershipChange`] without further
    /// mutating state.
    UnsupportedMembershipChange {
        /// The committer's DID, extracted from the MLS credential.
        sender_did: String,
        /// DIDs the rejected Commit's Remove proposals would evict, read from
        /// the pre-merge tree.
        removed_dids: Vec<String>,
    },
    /// A bare proposal cached by `scp-mls`; no membership change is committed.
    Proposal {
        /// The sender's DID, extracted from the MLS credential.
        sender_did: String,
    },
}

impl std::fmt::Debug for Inbound {
    /// Manual `Debug` that REDACTS the decrypted plaintext.
    ///
    /// Per ADR-057 the tab boundary is the plaintext boundary: a
    /// `{:?}`-formatted [`Inbound::Application`] must never leak the recovered
    /// cleartext into logs, panics, or test output. Only the byte length is
    /// printed; the control variants forward their (non-secret) fields. Mirrors
    /// the redacting `Debug` on the underlying [`InboundChange`].
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Application {
                sender_did,
                plaintext,
            } => f
                .debug_struct("Application")
                .field("sender_did", sender_did)
                .field(
                    "plaintext",
                    &format_args!("<redacted {} bytes>", plaintext.len()),
                )
                .finish(),
            Self::Commit {
                sender_did,
                added_dids,
            } => f
                .debug_struct("Commit")
                .field("sender_did", sender_did)
                .field("added_dids", added_dids)
                .finish(),
            Self::UnsupportedMembershipChange {
                sender_did,
                removed_dids,
            } => f
                .debug_struct("UnsupportedMembershipChange")
                .field("sender_did", sender_did)
                .field("removed_dids", removed_dids)
                .finish(),
            Self::Proposal { sender_did } => f
                .debug_struct("Proposal")
                .field("sender_did", sender_did)
                .finish(),
        }
    }
}

/// Combined MLS + sender-key state for a single context.
///
/// Owns the MLS group and this participant's sender key, plus the store of
/// other members' sender keys and the receive-side replay tracker. The double
/// encryption pipeline is:
///
/// **Send:** `plaintext` → sender-key encrypt → prepend header → MLS encrypt
/// **Receive:** MLS decrypt → parse header → ceiling + replay → sender-key
/// decrypt → `plaintext`
pub struct ContextCryptoState {
    /// The MLS group for this context (shared `scp-mls` type).
    pub mls_group: ScpMlsGroup,
    /// This participant's own sender key.
    pub local_sender_key: SenderKey,
    /// The raw `context_id` string this state belongs to. Used as the
    /// [`SenderKeyStore`] outer key and as the AEAD-AAD context binding
    /// (§9.16.1 binds the RAW string, matching native `seal`/`open`).
    pub context_id: String,
    /// This participant's monotonic sender-key epoch (§9.16.5). Initialized to
    /// [`INITIAL_SENDER_KEY_EPOCH`]; advanced only on block/rotation. Fed into
    /// BOTH the AEAD AAD and the 16-byte header on every send.
    pub sender_key_epoch: u64,
    /// Other participants' sender keys, keyed by `(context_id, sender_did)`.
    pub sender_key_store: SenderKeyStore,
    /// Receive-side replay detection: `sender_did → (last_epoch,
    /// last_sequence)`. A message with `epoch < last_epoch` or `(epoch ==
    /// last_epoch && sequence <= last_sequence)` is rejected (§9.16.1).
    pub recv_sequence_tracker: HashMap<String, (u64, u64)>,
}

impl ContextCryptoState {
    /// Builds crypto state around an already-constructed MLS group.
    ///
    /// Generates a fresh local sender key at [`INITIAL_SENDER_KEY_EPOCH`] and
    /// starts with empty trackers (a fresh receive replay window — §9.16.1).
    #[must_use]
    pub fn from_group(context_id: impl Into<String>, mls_group: ScpMlsGroup) -> Self {
        Self {
            mls_group,
            local_sender_key: generate_sender_key(),
            context_id: context_id.into(),
            sender_key_epoch: INITIAL_SENDER_KEY_EPOCH,
            sender_key_store: SenderKeyStore::new(),
            recv_sequence_tracker: HashMap::new(),
        }
    }

    /// Returns a copy of this participant's local sender-key bytes.
    ///
    /// Used by the out-of-band sender-key exchange (the driver has no in-tab
    /// cross-member sender-key distribution path — see ADR-057 and the
    /// `MISSING SEAM` note in the crate root). A future distribution slice
    /// replaces hand-off-by-copy with HPKE-sealed distribution over the MLS
    /// tree's `scp_wrapping_key` extension (§9.16.1).
    #[must_use]
    pub const fn local_sender_key_bytes(&self) -> [u8; 32] {
        *self.local_sender_key.as_bytes()
    }

    /// Records a remote member's sender key in the store.
    ///
    /// This installs a key the caller already trusts (the test harness "dumb
    /// pipe" / a future distribution path). It does not advance the remote
    /// sender's epoch high-water; that is advanced only by observing that
    /// sender's message headers, and the receive ceiling tolerates the gap by
    /// permitting up to [`MAX_EPOCH_ADVANCE`] above the stored high-water.
    pub fn insert_sender_key(&mut self, sender_did: &str, key: SenderKey) {
        let context_id = self.context_id.clone();
        self.sender_key_store
            .set_unchecked(&context_id, sender_did, key);
    }

    /// Encrypts a message through the full double-encryption pipeline.
    ///
    /// 1. Sender-key encrypt (AES-256-GCM, AAD binds the raw `context_id`,
    ///    `sender_did`, `self.sender_key_epoch`, and `sequence`).
    /// 2. Prepend the 16-byte `epoch || sequence` header (§9.16.1) — the epoch
    ///    is `self.sender_key_epoch`, NOT the MLS group epoch.
    /// 3. MLS-encrypt the framed result and TLS-serialize for transport.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] if either encryption layer or the wire
    /// serialization fails.
    pub fn encrypt_message(
        &mut self,
        plaintext: &[u8],
        sender_did: &str,
        sequence: u64,
    ) -> Result<Vec<u8>, ClientError> {
        let epoch = self.sender_key_epoch;
        let context_id = self.context_id.clone();

        // Layer 1: sender-key encrypt. The epoch bound into the AAD is the
        // sender-key epoch (§9.16.5), matching the header below.
        let sender_encrypted = encrypt_sender_layer(
            &self.local_sender_key,
            plaintext,
            &context_id,
            sender_did,
            epoch,
            sequence,
        )?;

        // Prepend the 16-byte epoch || sequence header (§9.16.1). The same
        // `epoch` feeds the AAD and the header so the receiver reconstructs an
        // identical AAD from the parsed header.
        let with_header = build_sender_header(epoch, sequence, &sender_encrypted);

        // Layer 2: MLS encrypt, then serialize the wire frame.
        let mls_out = encrypt(&mut self.mls_group, &with_header)?;
        Ok(serialize_ciphertext(&mls_out)?)
    }

    /// Decrypts an inbound MLS message through the full double-decryption
    /// pipeline, classifying it as application, membership-changing Commit, or
    /// bare proposal.
    ///
    /// For a control message the sender-key layer is not involved:
    /// - an **add-only Commit** is merged by `scp-mls` (its added DIDs recovered
    ///   from the staged commit before merge) and [`Inbound::Commit`] is
    ///   returned;
    /// - a **Remove-bearing Commit** is rejected by `scp-mls` *without merging*
    ///   (the group stays on its current epoch, MLS + SCP state consistent) and
    ///   [`Inbound::UnsupportedMembershipChange`] is returned;
    /// - a bare proposal is cached and [`Inbound::Proposal`] is returned.
    ///
    /// For an application message:
    /// 1. Parse the 16-byte `epoch || sequence` header — authoritative.
    /// 2. Enforce the epoch-poisoning ceiling (§9.16.1) BEFORE touching the
    ///    replay tracker, so a `u64::MAX` header cannot poison it.
    /// 3. Reject replays/reorders against the per-sender tracker.
    /// 4. Sender-key-decrypt using the PARSED epoch/sequence, then record the
    ///    tracker only on success.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] if MLS decryption fails, the header is
    /// malformed, the epoch exceeds the ceiling, the message is a
    /// replay/reorder, the sender's key is not in the store, or AEAD
    /// verification fails.
    pub fn decrypt_message(&mut self, ciphertext: &[u8]) -> Result<Inbound, ClientError> {
        // Layer 2 (outer): MLS decrypt + classify. `scp-mls` merges any staged
        // commit internally (recovering its Add/Remove DIDs before the merge)
        // and surfaces the sender DID from the credential.
        let decrypted = decrypt_with_membership_changes(&mut self.mls_group, ciphertext)?;
        let (sender_did, framed) = match decrypted {
            InboundChange::Application {
                plaintext,
                sender_did,
            } => (sender_did, plaintext),
            InboundChange::Commit {
                sender_did,
                added_dids,
            } => {
                return Ok(Inbound::Commit {
                    sender_did,
                    added_dids,
                });
            }
            InboundChange::UnsupportedMembershipChange {
                sender_did,
                removed_dids,
            } => {
                return Ok(Inbound::UnsupportedMembershipChange {
                    sender_did,
                    removed_dids,
                });
            }
            InboundChange::Proposal { sender_did } => {
                return Ok(Inbound::Proposal { sender_did });
            }
        };

        let context_id = self.context_id.clone();

        // Parse the authoritative epoch || sequence header.
        let (epoch, sequence, sender_ciphertext) = parse_sender_header(&framed)?;

        // Epoch-poisoning ceiling (§9.16.1), enforced BEFORE the replay tracker
        // is touched. Without it a header carrying `epoch = u64::MAX` would
        // advance the tracker and permanently lock out this sender (self-DoS /
        // persistent per-receiver poisoning). Mirrors native `open`.
        let stored_high_water = self.sender_key_store.epoch(&context_id, &sender_did);
        let allowed_epoch_ceiling = stored_high_water.saturating_add(MAX_EPOCH_ADVANCE);
        if epoch > allowed_epoch_ceiling {
            return Err(ClientError::Driver(format!(
                "sender key epoch {epoch} exceeds ceiling {allowed_epoch_ceiling} \
                 (stored high-water {stored_high_water}, MAX_EPOCH_ADVANCE {MAX_EPOCH_ADVANCE})"
            )));
        }

        // Replay/reorder detection. Reject epoch/sequence <= last seen for this
        // sender (§9.16.1). Consulted BEFORE insert so a duplicate or older
        // (epoch, sequence) is refused.
        if let Some(&(last_epoch, last_seq)) = self.recv_sequence_tracker.get(&sender_did)
            && (epoch < last_epoch || (epoch == last_epoch && sequence <= last_seq))
        {
            return Err(ClientError::Driver("replay or reorder detected".to_owned()));
        }

        // Look up the sender's key BEFORE recording the tracker, so a missing
        // key does not advance the tracker (an undecryptable message is not
        // "seen" for replay purposes).
        let sender_key = self
            .sender_key_store
            .get(&context_id, &sender_did)
            .ok_or_else(|| ClientError::Driver(format!("no sender key for DID '{sender_did}'")))?
            .clone();

        // Layer 1 (inner): sender-key decrypt using the PARSED epoch/sequence
        // (the header is authoritative). The AAD binds the raw context_id
        // string (§9.16.1), matching `encrypt_message` and native `seal`.
        let plaintext = decrypt_sender_layer(
            &sender_key,
            sender_ciphertext,
            &context_id,
            &sender_did,
            epoch,
            sequence,
        )?;

        // Record the tracker only after a SUCCESSFUL decrypt, so a
        // forged-but-undecryptable header cannot advance the replay floor.
        self.recv_sequence_tracker
            .insert(sender_did.clone(), (epoch, sequence));

        Ok(Inbound::Application {
            sender_did,
            plaintext,
        })
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use openmls::prelude::KeyPackageIn;
    use scp_did::SigningKeyId;
    use scp_mls::group::{add_member, create_group, generate_key_package, join_group};
    use scp_mls::{ScpCredential, SignatureKeyPair};
    use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};

    const CTX: &str = "ctx-crypto-state-unit";
    const ALICE: &str = "did:key:z6MkAliceCryptoStateUnitFixtureAAAAAAAAAAA";
    const BOB: &str = "did:key:z6MkBobCryptoStateUnitFixtureBBBBBBBBBBBBB";

    #[allow(clippy::unwrap_used)]
    fn credential(did: &str) -> ScpCredential {
        ScpCredential::new(did.to_owned(), None, SigningKeyId::Active).unwrap()
    }

    /// Builds Alice (creator) and Bob (Welcome-joined) crypto states sharing one
    /// MLS group, with sender keys exchanged both ways.
    #[allow(clippy::unwrap_used)]
    fn alice_and_bob() -> (ContextCryptoState, ContextCryptoState) {
        let mut alice =
            ContextCryptoState::from_group(CTX, create_group(&credential(ALICE)).unwrap());

        let (bundle, signer, provider): (_, SignatureKeyPair, _) =
            generate_key_package(&credential(BOB)).unwrap();
        let kp_bytes = bundle.key_package().tls_serialize_detached().unwrap();
        let kp_in = KeyPackageIn::tls_deserialize(&mut &*kp_bytes).unwrap();
        let result = add_member(&mut alice.mls_group, kp_in).unwrap();

        let bob_group = join_group(&result.welcome, provider, signer).unwrap();
        let mut bob = ContextCryptoState::from_group(CTX, bob_group);

        // Exchange sender keys (out-of-band, mirroring the driver's MISSING SEAM).
        bob.insert_sender_key(ALICE, SenderKey::from_bytes(alice.local_sender_key_bytes()));
        alice.insert_sender_key(BOB, SenderKey::from_bytes(bob.local_sender_key_bytes()));
        (alice, bob)
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn full_double_encryption_round_trip() {
        let (mut alice, mut bob) = alice_and_bob();
        let ct = alice.encrypt_message(b"hello bob", ALICE, 0).unwrap();
        match bob.decrypt_message(&ct).unwrap() {
            Inbound::Application {
                sender_did,
                plaintext,
            } => {
                assert_eq!(sender_did, ALICE);
                assert_eq!(plaintext, b"hello bob");
            }
            other => panic!("expected an application message, got {other:?}"),
        }
        assert_eq!(bob.recv_sequence_tracker.get(ALICE), Some(&(1u64, 0u64)));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn decrypt_classifies_add_commit_with_added_did() {
        // An EXISTING member decrypting an add-Commit must classify it as
        // Inbound::Commit carrying the added DID, so the driver can mirror the
        // MemberJoined leaf. Setup: Alice creates, adds Carol (Carol joins as
        // the existing member), then Alice adds Bob and Carol processes that
        // second Commit.
        const CAROL: &str = "did:key:z6MkCarolCryptoStateUnitFixtureCCCCCCCCC";

        let mut alice =
            ContextCryptoState::from_group(CTX, create_group(&credential(ALICE)).unwrap());

        // Carol joins as an existing member.
        let (carol_bundle, carol_signer, carol_provider): (_, SignatureKeyPair, _) =
            generate_key_package(&credential(CAROL)).unwrap();
        let carol_kp_in = KeyPackageIn::tls_deserialize(
            &mut &*carol_bundle.key_package().tls_serialize_detached().unwrap(),
        )
        .unwrap();
        let add_carol = add_member(&mut alice.mls_group, carol_kp_in).unwrap();
        let mut carol = ContextCryptoState::from_group(
            CTX,
            join_group(&add_carol.welcome, carol_provider, carol_signer).unwrap(),
        );

        // Alice adds Bob; Carol (existing member) processes the Commit.
        let (bob_bundle, _bob_signer, _bob_provider): (_, SignatureKeyPair, _) =
            generate_key_package(&credential(BOB)).unwrap();
        let bob_kp_in = KeyPackageIn::tls_deserialize(
            &mut &*bob_bundle.key_package().tls_serialize_detached().unwrap(),
        )
        .unwrap();
        let add_bob = add_member(&mut alice.mls_group, bob_kp_in).unwrap();
        let commit_bytes = add_bob.commit.tls_serialize_detached().unwrap();

        match carol.decrypt_message(&commit_bytes).unwrap() {
            Inbound::Commit {
                sender_did,
                added_dids,
            } => {
                assert_eq!(sender_did, ALICE, "committer is Alice");
                assert_eq!(added_dids, vec![BOB.to_owned()], "Bob's DID surfaced");
            }
            other => panic!("expected Inbound::Commit, got {other:?}"),
        }
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn replay_and_reorder_rejected() {
        let (mut alice, mut bob) = alice_and_bob();
        let ct1 = alice.encrypt_message(b"first", ALICE, 1).unwrap();
        let ct2 = alice.encrypt_message(b"second", ALICE, 2).unwrap();
        let ct1_dup = alice.encrypt_message(b"first-again", ALICE, 1).unwrap();

        assert!(
            bob.decrypt_message(&ct2).is_ok(),
            "newer seq accepted first"
        );
        assert!(
            bob.decrypt_message(&ct1).is_err(),
            "older (epoch,seq) rejected as reorder/replay"
        );
        assert!(
            bob.decrypt_message(&ct1_dup).is_err(),
            "duplicate (epoch,seq) rejected"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn failed_decrypt_does_not_advance_tracker() {
        // Bob lacks Alice's sender key, so the first decrypt fails at the inner
        // layer and must not advance the replay floor.
        let mut alice =
            ContextCryptoState::from_group(CTX, create_group(&credential(ALICE)).unwrap());
        let (bundle, signer, provider): (_, SignatureKeyPair, _) =
            generate_key_package(&credential(BOB)).unwrap();
        let kp_bytes = bundle.key_package().tls_serialize_detached().unwrap();
        let kp_in = KeyPackageIn::tls_deserialize(&mut &*kp_bytes).unwrap();
        let result = add_member(&mut alice.mls_group, kp_in).unwrap();
        let bob_group = join_group(&result.welcome, provider, signer).unwrap();
        let mut bob = ContextCryptoState::from_group(CTX, bob_group);

        let ct = alice.encrypt_message(b"one", ALICE, 1).unwrap();
        assert!(bob.decrypt_message(&ct).is_err(), "no sender key → fails");
        assert!(
            !bob.recv_sequence_tracker.contains_key(ALICE),
            "a failed decrypt must not advance the tracker"
        );

        // After receiving the key out-of-band, a fresh send at seq 1 decrypts.
        bob.insert_sender_key(ALICE, SenderKey::from_bytes(alice.local_sender_key_bytes()));
        let ct_b = alice.encrypt_message(b"one-b", ALICE, 1).unwrap();
        assert!(bob.decrypt_message(&ct_b).is_ok());
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn epoch_poisoning_ceiling_rejects_and_does_not_advance_tracker() {
        let (mut alice, mut bob) = alice_and_bob();
        // Forge Alice's epoch to u64::MAX so her next header poisons the ceiling.
        alice.sender_key_epoch = u64::MAX;
        let poisoned = alice.encrypt_message(b"poison", ALICE, 0).unwrap();
        assert!(
            bob.decrypt_message(&poisoned).is_err(),
            "epoch beyond store.epoch + MAX_EPOCH_ADVANCE must be rejected"
        );
        assert!(
            !bob.recv_sequence_tracker.contains_key(ALICE),
            "a ceiling-rejected message must not advance the replay tracker"
        );
    }

    #[test]
    fn debug_redacts_application_plaintext() {
        // ADR-057: the tab boundary is the plaintext boundary. A `{:?}`-formatted
        // Inbound::Application must print the byte length, NEVER the cleartext.
        let secret = b"TOP-SECRET-PLAINTEXT-NEVER-LOG-ME";
        let inbound = Inbound::Application {
            sender_did: ALICE.to_owned(),
            plaintext: secret.to_vec(),
        };
        let rendered = format!("{inbound:?}");
        assert!(
            !rendered.contains("TOP-SECRET-PLAINTEXT-NEVER-LOG-ME"),
            "Debug must NOT leak the decrypted plaintext, got: {rendered}"
        );
        assert!(
            rendered.contains("<redacted") && rendered.contains(&format!("{} bytes", secret.len())),
            "Debug must report a redacted byte length, got: {rendered}"
        );
        // The sender DID is not secret and may be shown.
        assert!(
            rendered.contains(ALICE),
            "sender DID may appear: {rendered}"
        );
    }
}
