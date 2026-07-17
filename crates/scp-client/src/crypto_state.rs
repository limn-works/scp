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

use scp_clock::Clock;
use scp_mls::ScpMlsGroup;
use scp_mls::encrypt::{
    InboundChange, decrypt_with_membership_changes, encrypt, serialize_ciphertext,
};
use scp_protocol::context::builder::{
    MANAGEMENT_MSG_MAGIC, MAX_MANAGEMENT_PAYLOAD_SIZE, try_strip_management_prefix,
};
use scp_protocol::context::pseudonym::is_pseudonym_announcement_payload;
use scp_protocol::crypto::sender_keys::encrypt::{
    build_sender_header, decrypt_sender_layer, encrypt_sender_layer, parse_sender_header,
};
use scp_protocol::crypto::sender_keys::{
    MAX_EPOCH_ADVANCE, SenderKey, SenderKeyDistributionMessage, SenderKeyResponse, SenderKeyStore,
    generate_sender_key, hpke_open_sender_key, hpke_seal_sender_key,
};
// `generate_wrapping_keypair` is reached only from the `#[cfg(test)]` `from_group`
// constructor and the unit tests (every production path threads a caller-supplied
// keypair via `from_group_with_wrapping`), so its import is test-only.
#[cfg(test)]
use scp_protocol::crypto::sender_keys::generate_wrapping_keypair;
use zeroize::Zeroizing;

use crate::error::ClientError;

/// Size of the HPKE-sealed sender key ciphertext (`ct = ciphertext || tag`):
/// 32-byte key + 16-byte AES-128-GCM tag (§9.16.2).
const HPKE_SEALED_KEY_SIZE: usize = 48;

/// A single HPKE-sealed sender-key distribution the driver must deliver.
///
/// `ciphertext` is a full MLS-encrypted **management** frame (§9.16.1): the
/// sender's §9.16 sender key, HPKE-sealed to `target_did`'s stable
/// `scp_wrapping_key`, wrapped in a `SenderKeyDistributionMessage`, tagged with
/// [`MANAGEMENT_MSG_MAGIC`], and MLS-encrypted. It rides the SAME wire path as an
/// application message: the transport hands `ciphertext` to `target_did`'s
/// [`ScpClient::receive_message`](crate::ScpClient::receive_message), which
/// MLS-decrypts it, strips the magic, HPKE-opens the key with its wrapping
/// secret, and installs it. `target_did` is a **delivery hint** for the in-tab
/// dumb pipe — the confidentiality of the sealed key rests on the HPKE seal to
/// the recipient's wrapping key, not on MLS routing (any group member can
/// MLS-decrypt the frame, but only `target_did` can HPKE-open it).
///
/// # Delivery ordering (caller contract)
///
/// The `ciphertext` is an MLS application frame sealed at the sealer's *current*
/// MLS epoch. A recipient more than `max_past_epochs` (2) behind that epoch cannot
/// MLS-decrypt it, and [`ScpClient::receive_message`](crate::ScpClient::receive_message)
/// returns an error rather than silently dropping the key. The caller must
/// therefore deliver a distribution only once the recipient has reached the
/// membership epoch it was sealed at (in the in-tab test harness: deliver after
/// every member has processed the add-Commit), and **re-drive** a distribution
/// whose delivery errored. Re-driving to a member offline during the push is the
/// documented pull-path residual (ADR-057 T4, §9.16.2).
#[derive(Clone)]
pub struct SenderKeyDistribution {
    /// The DID the distribution is sealed for (the in-tab delivery hint).
    pub target_did: String,
    /// The MLS-encrypted management frame carrying the HPKE-sealed sender key.
    pub ciphertext: Vec<u8>,
}

impl std::fmt::Debug for SenderKeyDistribution {
    /// The ciphertext is an opaque MLS frame (no cleartext key), but keep Debug
    /// terse — print the target DID and the frame length only.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SenderKeyDistribution")
            .field("target_did", &self.target_did)
            .field(
                "ciphertext",
                &format_args!("[{} bytes]", self.ciphertext.len()),
            )
            .finish()
    }
}

/// The sender-key epoch a freshly generated key starts at (§9.16.5).
///
/// Mirrors the native `MlsCryptoProvider`, which seeds `sender_key_epoch = 1`
/// at keygen. Starting at 1 (not 0) keeps the first application message's
/// 8-byte big-endian epoch prefix as `0x0000000000000001`, whose leading 4
/// bytes are `00 00 00 00` — disjoint from the 4-byte `SCPM_MAGIC` management
/// prefix (§9.16.1). An epoch's high 4 bytes could only equal `SCPM_MAGIC` at
/// epoch ≥ 2^32. `MAX_EPOCH_ADVANCE` is a per-message *rate* window (not an
/// absolute cap), and each local rotation advances the epoch by one, so
/// reaching 2^32 would take ~4.3 billion monotonically-accepted advances —
/// operationally unreachable rather than hard-bounded. Crucially, classification
/// never rests on disjointness alone: the independent `sender_did ==
/// mls_sender_did` binding (see
/// [`ContextCryptoState::install_incoming_distribution`]) is the load-bearing
/// guard, so a collision even at epoch ≥ 2^32 could not misroute a frame.
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
    ///
    /// Application messages are **not** convergent event-log leaves (ADR-011
    /// exclusion taxonomy §2: `MessageSent` is per-author with no total delivery
    /// order), so they bind no convergent timestamp — the driver records the
    /// message as local history (a `MessageSent` / `MessageReceived`
    /// `ContextEvent`), not as a Merkle leaf.
    Application {
        /// The sender's DID, extracted from the MLS credential.
        sender_did: String,
        /// The fully decrypted plaintext.
        plaintext: Vec<u8>,
    },
    /// A Commit that advanced the group epoch. `scp-mls` has already merged it;
    /// `added_dids` are the SCP DIDs the Commit's Add proposals add (in proposal
    /// order), for the driver to mirror onto its SCP-layer membership + event
    /// log. Empty for a no-add Commit (e.g. a self-update).
    Commit {
        /// The committer's DID, extracted from the MLS credential.
        sender_did: String,
        /// DIDs added by this Commit's Add proposals.
        added_dids: Vec<String>,
        /// The `scp_wrapping_key` public keys of the added members, 1:1 with
        /// `added_dids` (recovered from each Add proposal's `KeyPackage` leaf,
        /// fail-closed if absent — §9.16.1, ADR-057). The driver records each in
        /// its member-wrapping-key directory and HPKE-seals its own sender key to
        /// each new member (the bystander re-distribution trigger, INVARIANT 2).
        added_wrapping_keys: Vec<[u8; 32]>,
        /// The **authenticated** convergent committer timestamp (Unix seconds),
        /// recovered from the Commit's verified MLS AAD *before* the merge and
        /// adopted **verbatim** by `scp-mls` (ADR-057). The driver stamps this on
        /// each mirrored `MemberJoined` leaf. `Some` only for an add-Commit;
        /// `None` for a no-add Commit, which stamps no leaf.
        committer_timestamp_secs: Option<u64>,
    },
    /// A peer's §9.16 sender key was HPKE-opened and installed from an in-tab
    /// distribution (a management message — §9.16.1/§9.16.2). No application
    /// payload, no event-log leaf, no `ContextEvent`: the driver persists the
    /// updated sender-key store and reports nothing to the application. Carries
    /// the DID and epoch of the installed key for observability/tests.
    SenderKeyInstalled {
        /// The DID whose sender key was installed.
        sender_did: String,
        /// The sender-key epoch that was installed.
        epoch: u64,
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
                added_wrapping_keys,
                committer_timestamp_secs,
            } => f
                .debug_struct("Commit")
                .field("sender_did", sender_did)
                .field("added_dids", added_dids)
                .field(
                    "added_wrapping_keys",
                    &format_args!("[{} keys]", added_wrapping_keys.len()),
                )
                .field("committer_timestamp_secs", committer_timestamp_secs)
                .finish(),
            Self::SenderKeyInstalled { sender_did, epoch } => f
                .debug_struct("SenderKeyInstalled")
                .field("sender_did", sender_did)
                .field("epoch", epoch)
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

/// The relay channel an inbound frame arrived on (§9.10.4).
///
/// App data and pseudonym announcements are §9.16 application messages that share
/// one per-sender sequence counter, but they travel on **different** relay
/// routing IDs — app data on a peer's pseudonym, announcements on the shared
/// `context_routing_id`. Because those two channels are unordered relative to each
/// other, a single shared per-sender replay floor would let a higher-sequence app
/// message, arriving first, drop a lower-sequence announcement as a "replay" — so
/// the peer would never learn the announced pseudonym. The channel selects a
/// **separate** per-sender replay floor for each, so the two never interfere
/// (§9.10.4 announcement reorder). Announcements are idempotent registry updates,
/// so their floor is in-memory-only (a restart re-processes a backfilled
/// announcement harmlessly — the static pseudonym is re-recorded identically; the
/// durable routing state is the persisted peer registry).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvChannel {
    /// A peer's application data, addressed to this member's pseudonym.
    App,
    /// A pseudonym announcement, on the shared `context_routing_id`.
    Announcement,
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
    /// Receive-side replay detection for **app data** (the [`RecvChannel::App`]
    /// channel): `sender_did → (last_epoch, last_sequence)`. A message with
    /// `epoch < last_epoch` or `(epoch == last_epoch && sequence <= last_sequence)`
    /// is rejected (§9.16.1).
    pub recv_sequence_tracker: HashMap<String, (u64, u64)>,
    /// Receive-side replay detection for **pseudonym announcements** (the
    /// [`RecvChannel::Announcement`] channel), kept SEPARATE from the app-data
    /// floor so the two unordered channels do not drop each other's messages
    /// (§9.10.4 announcement reorder — see [`RecvChannel`]). In-memory only:
    /// announcements are idempotent and the durable routing state is the persisted
    /// peer registry, so this floor is not snapshotted.
    pub recv_announcement_tracker: HashMap<String, (u64, u64)>,
    /// This participant's **stable wrapping public key** (X25519, §9.16.1). Peers
    /// HPKE-seal their sender keys to it; it is published in this member's MLS
    /// leaf `scp_wrapping_key` extension and transported in the member-wrapping-key
    /// directory. Stable across MLS epochs (does not rotate on Update).
    pub wrapping_public: [u8; 32],
    /// This participant's **stable wrapping secret key** (X25519, §9.16.1). Used
    /// to HPKE-open sender-key distributions sealed to [`Self::wrapping_public`].
    /// Zeroized on drop; never printed (no `Debug` on this struct).
    pub wrapping_secret: Zeroizing<[u8; 32]>,
    /// The member-wrapping-key **directory**: `did → scp_wrapping_key`. This IS
    /// the authoritative member set (ADR-057 sender-key distribution INVARIANT 1):
    /// there is no parallel `members: Vec<String>` that could drift out of step —
    /// every member recorded here is recorded *with* the wrapping key a peer needs
    /// to HPKE-seal a sender key to it, by construction. Includes this member's
    /// own entry (`did → wrapping_public`); the seal loop skips self.
    pub member_wrapping_keys: HashMap<String, [u8; 32]>,
}

impl ContextCryptoState {
    /// Builds crypto state around an already-constructed MLS group, generating a
    /// **fresh** stable wrapping keypair (§9.16.1).
    ///
    /// Generates a fresh local sender key at [`INITIAL_SENDER_KEY_EPOCH`], a fresh
    /// X25519 wrapping keypair, an empty member-wrapping-key directory, and empty
    /// trackers (a fresh receive replay window — §9.16.1).
    ///
    /// **Test-only** (`#[cfg(test)]`): every production path — creator and joiner
    /// alike — uses [`Self::from_group_with_wrapping`] with the keypair already
    /// published in the MLS leaf / `KeyPackage` (`create_context` /
    /// `generate_key_package_for_join`), so the wrapping key peers HPKE-seal to is
    /// the one this state can HPKE-open with. This self-generating constructor
    /// mints a *fresh* wrapping keypair that matches no published leaf, so a
    /// production caller would silently install a member no peer can seal to; it
    /// exists only for single-member / unit-test states where no `KeyPackage` was
    /// pre-published. Gated `#[cfg(test)]` so it can never be reached in a shipped
    /// build.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn from_group(context_id: impl Into<String>, mls_group: ScpMlsGroup) -> Self {
        let (wrapping_public, wrapping_secret) = generate_wrapping_keypair();
        Self::from_group_with_wrapping(context_id, mls_group, wrapping_public, wrapping_secret)
    }

    /// Builds crypto state around an already-constructed MLS group with a
    /// **caller-supplied** stable wrapping keypair (§9.16.1).
    ///
    /// The driver threads the keypair generated at
    /// [`generate_key_package_for_join`](crate::ScpClient::generate_key_package_for_join)
    /// (and published in the joiner's `KeyPackage` leaf) through
    /// [`join_context_encrypted`](crate::ScpClient::join_context_encrypted), so
    /// the wrapping key this crypto state HPKE-opens distributions with is the
    /// SAME key peers HPKE-seal to — the joiner can therefore decrypt the sender
    /// keys sealed to its published wrapping key. The creator path likewise passes
    /// the keypair it embedded in its own leaf.
    #[must_use]
    pub fn from_group_with_wrapping(
        context_id: impl Into<String>,
        mls_group: ScpMlsGroup,
        wrapping_public: [u8; 32],
        wrapping_secret: [u8; 32],
    ) -> Self {
        Self {
            mls_group,
            local_sender_key: generate_sender_key(),
            context_id: context_id.into(),
            sender_key_epoch: INITIAL_SENDER_KEY_EPOCH,
            sender_key_store: SenderKeyStore::new(),
            recv_sequence_tracker: HashMap::new(),
            recv_announcement_tracker: HashMap::new(),
            wrapping_public,
            wrapping_secret: Zeroizing::new(wrapping_secret),
            member_wrapping_keys: HashMap::new(),
        }
    }

    /// Records a member in the wrapping-key directory (§9.16.1, INVARIANT 1).
    ///
    /// The directory IS the member set: a member is only ever recorded here
    /// together with the wrapping key a peer needs to seal a sender key to it, so
    /// the two can never drift apart. Idempotent-overwrite (a re-record with a
    /// rotated wrapping key updates it).
    pub fn record_member_wrapping_key(&mut self, member_did: &str, wrapping_key: [u8; 32]) {
        self.member_wrapping_keys
            .insert(member_did.to_owned(), wrapping_key);
    }

    /// The member-wrapping-key directory as a sorted `(did, wrapping_key)` list.
    ///
    /// Sorted by DID for deterministic transport ordering. Used to populate
    /// [`AddMemberOutput::wrapping_keys`](crate::AddMemberOutput) (all members
    /// incl. self) so a joiner adopts the full directory.
    #[must_use]
    pub fn wrapping_keys_snapshot(&self) -> Vec<(String, [u8; 32])> {
        let mut out: Vec<(String, [u8; 32])> = self
            .member_wrapping_keys
            .iter()
            .map(|(did, wk)| (did.clone(), *wk))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// HPKE-seals this participant's current sender key to a single recipient and
    /// frames it as an MLS-encrypted **management** message (§9.16.1/§9.16.2).
    ///
    /// Mirrors the native `MlsCryptoProvider` push distribution: seal → wrap in a
    /// `SenderKeyDistributionMessage::KeyResponse` (with a zeroed `request_nonce`,
    /// since this is a proactive push, not a reply to a pull request) → prepend
    /// [`MANAGEMENT_MSG_MAGIC`] → MLS-encrypt. Advancing the MLS send ratchet
    /// (via `encrypt`) is a real send and must be persisted by the caller.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] if HPKE sealing, the (defensive)
    /// [`MAX_MANAGEMENT_PAYLOAD_SIZE`] bound, serialization, or the MLS encrypt
    /// fails.
    pub fn seal_sender_key_distribution(
        &mut self,
        local_did: &str,
        target_did: &str,
        target_wrapping_key: &[u8; 32],
    ) -> Result<SenderKeyDistribution, ClientError> {
        let (sealed_vec, ephemeral_pubkey) = hpke_seal_sender_key(
            self.local_sender_key.as_bytes(),
            target_wrapping_key,
            &self.context_id,
            local_did,
            self.sender_key_epoch,
        )?;
        let hpke_sealed_key: [u8; HPKE_SEALED_KEY_SIZE] =
            sealed_vec.try_into().map_err(|v: Vec<u8>| {
                ClientError::Driver(format!(
                    "HPKE seal produced {} bytes, expected {HPKE_SEALED_KEY_SIZE}",
                    v.len()
                ))
            })?;

        let response = SenderKeyResponse {
            sender_did: local_did.to_owned(),
            epoch: self.sender_key_epoch,
            hpke_sealed_key,
            ephemeral_pubkey,
            // Proactive push — not a reply to a pull request, so no nonce to echo.
            request_nonce: [0u8; 16],
        };
        let payload = SenderKeyDistributionMessage::KeyResponse(response).to_bytes()?;

        // Defensive: the management payload must fit the §9.16.1 64 KiB bound. A
        // distribution is ~100 bytes, so this can only trip on a corrupt encoder.
        if payload.len() > MAX_MANAGEMENT_PAYLOAD_SIZE {
            return Err(ClientError::Driver(format!(
                "sender key distribution payload {} exceeds MAX_MANAGEMENT_PAYLOAD_SIZE {MAX_MANAGEMENT_PAYLOAD_SIZE}",
                payload.len()
            )));
        }

        let mut tagged = Vec::with_capacity(MANAGEMENT_MSG_MAGIC.len() + payload.len());
        tagged.extend_from_slice(&MANAGEMENT_MSG_MAGIC);
        tagged.extend_from_slice(&payload);

        let mls_out = encrypt(&mut self.mls_group, &tagged)?;
        let ciphertext = serialize_ciphertext(&mls_out)?;
        Ok(SenderKeyDistribution {
            target_did: target_did.to_owned(),
            ciphertext,
        })
    }

    /// HPKE-seals this participant's current sender key to every recipient in
    /// `recipients` **except itself**, returning one distribution per peer.
    ///
    /// Also stores this participant's own key under its own DID in the sender-key
    /// store (mirrors the native provider, keeping the store self-consistent for
    /// the snapshot). The caller supplies the recipient set (the wrapping-key
    /// directory, minus or including self — self is skipped here regardless).
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] if any seal/frame fails; the seal loop is
    /// all-or-nothing (a failure aborts before returning any distribution).
    pub fn distribute_local_key_to(
        &mut self,
        local_did: &str,
        recipients: &[(String, [u8; 32])],
    ) -> Result<Vec<SenderKeyDistribution>, ClientError> {
        // Keep the local member's own key discoverable in the store under its DID
        // (mirrors native `distribute_sender_key`).
        let context_id = self.context_id.clone();
        self.sender_key_store
            .set_unchecked(&context_id, local_did, self.local_sender_key.clone());

        let mut distributions = Vec::new();
        for (did, wrapping_key) in recipients {
            if did == local_did {
                continue;
            }
            distributions.push(self.seal_sender_key_distribution(local_did, did, wrapping_key)?);
        }
        Ok(distributions)
    }

    /// Rotates this participant's sender key and re-distributes it to every member
    /// in the wrapping-key directory (§9.16.5).
    ///
    /// Generates a fresh AES-256 sender key, increments the monotonic
    /// `sender_key_epoch` (checked — overflow is a hard error), stores the new key
    /// under this member's own DID, and HPKE-seals it to every other member's
    /// wrapping key. Returns the distributions the driver delivers. The new epoch
    /// is bound into every seal, so recipients accept it under `set_checked`
    /// monotonicity and reject any stale earlier-epoch key.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Driver`] on epoch overflow, or a seal/frame error.
    pub fn rotate_sender_key(
        &mut self,
        local_did: &str,
    ) -> Result<Vec<SenderKeyDistribution>, ClientError> {
        self.local_sender_key = generate_sender_key();
        self.sender_key_epoch = self.sender_key_epoch.checked_add(1).ok_or_else(|| {
            ClientError::Driver("sender key epoch overflow (already at u64::MAX)".to_owned())
        })?;
        let recipients = self.wrapping_keys_snapshot();
        self.distribute_local_key_to(local_did, &recipients)
    }

    /// HPKE-opens and installs a peer's sender key from an in-tab **management**
    /// distribution (§9.16.1/§9.16.2), returning [`Inbound::SenderKeyInstalled`].
    ///
    /// Enforces, in order (all BEFORE any store mutation):
    /// 1. **Sender-DID binding** — the sealed key's claimed `sender_did` MUST
    ///    equal the MLS credential DID of the frame's sender (`mls_sender_did`), so
    ///    a member cannot attribute a key to a DID it does not control.
    /// 2. **Epoch-poisoning ceiling** ([`MAX_EPOCH_ADVANCE`]) against the stored
    ///    high-water, so a `u64::MAX` epoch cannot wedge future rotations.
    /// 3. **HPKE open** with this member's wrapping secret — fails closed if the
    ///    distribution was sealed to a different recipient's wrapping key.
    /// 4. **Monotonic install** via `set_checked` (rejects a stale/replayed epoch).
    fn install_incoming_distribution(
        &mut self,
        mls_sender_did: &str,
        payload: &[u8],
    ) -> Result<Inbound, ClientError> {
        if payload.len() > MAX_MANAGEMENT_PAYLOAD_SIZE {
            return Err(ClientError::Driver(format!(
                "management payload {} exceeds MAX_MANAGEMENT_PAYLOAD_SIZE {MAX_MANAGEMENT_PAYLOAD_SIZE}",
                payload.len()
            )));
        }
        let SenderKeyDistributionMessage::KeyResponse(response) =
            SenderKeyDistributionMessage::from_bytes(payload)?
        else {
            return Err(ClientError::Driver(
                "unexpected management message; only a sender-key distribution \
                 (KeyResponse) is delivered in-tab"
                    .to_owned(),
            ));
        };

        // (1) Sender-DID binding: only the frame's authenticated MLS sender may
        // distribute a key attributed to itself.
        if response.sender_did != mls_sender_did {
            return Err(ClientError::Driver(format!(
                "sender key distribution DID mismatch: claimed '{}', MLS frame sender '{mls_sender_did}'",
                response.sender_did
            )));
        }

        // (2) Epoch-poisoning ceiling BEFORE any store/tracker mutation (§9.16.1).
        let stored_high_water = self
            .sender_key_store
            .epoch(&self.context_id, &response.sender_did);
        let allowed_epoch_ceiling = stored_high_water.saturating_add(MAX_EPOCH_ADVANCE);
        if response.epoch > allowed_epoch_ceiling {
            return Err(ClientError::Driver(format!(
                "sender key distribution epoch {} exceeds ceiling {allowed_epoch_ceiling} \
                 (stored high-water {stored_high_water}, MAX_EPOCH_ADVANCE {MAX_EPOCH_ADVANCE})",
                response.epoch
            )));
        }

        // (3) HPKE open — fails closed for a distribution sealed to another
        // recipient's wrapping key.
        let sender_key = hpke_open_sender_key(
            &response.hpke_sealed_key,
            &response.ephemeral_pubkey,
            &self.wrapping_secret,
            &self.context_id,
            &response.sender_did,
            response.epoch,
        )?;

        // (4) Monotonic install (#1608): rejects a stale/replayed epoch.
        let context_id = self.context_id.clone();
        self.sender_key_store.set_checked(
            &context_id,
            &response.sender_did,
            sender_key,
            response.epoch,
        )?;

        Ok(Inbound::SenderKeyInstalled {
            sender_did: response.sender_did,
            epoch: response.epoch,
        })
    }

    /// Returns a copy of this participant's local sender-key bytes.
    ///
    /// **Test-only** (`#[cfg(test)]`): the production sender-key exchange is the
    /// in-tab HPKE distribution over the `scp_wrapping_key` extension (§9.16.1/
    /// §9.16.2) — there is no out-of-band hand-off on any production path. This
    /// helper only lets the crate's own unit tests exercise the double-encryption
    /// pipeline (`encrypt_message` / `decrypt_message`) in isolation, by seeding a
    /// peer's key directly rather than driving a full distribution round.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn local_sender_key_bytes(&self) -> [u8; 32] {
        *self.local_sender_key.as_bytes()
    }

    /// Records a remote member's sender key in the store directly.
    ///
    /// **Test-only** (`#[cfg(test)]`): the production install path is
    /// [`Self::install_incoming_distribution`], reached from `decrypt_message`
    /// when an HPKE-sealed distribution arrives — no code trusts a caller-supplied
    /// key in production. This helper only seeds a peer's key for the crate's own
    /// double-encryption unit tests. It does not advance the remote sender's epoch
    /// high-water; that is advanced only by observing that sender's message
    /// headers, and the receive ceiling tolerates the gap by permitting up to
    /// [`MAX_EPOCH_ADVANCE`] above the stored high-water.
    #[cfg(test)]
    pub(crate) fn insert_sender_key(&mut self, sender_did: &str, key: SenderKey) {
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
    /// An application message is **not** a convergent event-log leaf (ADR-011
    /// exclusion taxonomy §2: `MessageSent` is per-author with no total delivery
    /// order), so — unlike an add-Commit — it binds NO convergent-timestamp AAD.
    /// It is plain MLS-encrypted; convergence does not apply.
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

        // Layer 2: plain MLS encrypt (application messages bind no convergent
        // timestamp — ADR-011), then serialize the wire frame.
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
    pub fn decrypt_message(
        &mut self,
        ciphertext: &[u8],
        clock: &dyn Clock,
        channel: RecvChannel,
    ) -> Result<Inbound, ClientError> {
        // Layer 2 (outer): MLS decrypt + classify. `scp-mls` merges any staged
        // commit internally (recovering its Add/Remove DIDs before the merge)
        // and surfaces the sender DID from the credential. `clock` re-validates
        // any add-Commit's KeyPackage `Lifetime` against the hardened driver
        // clock before merge (ADR-057 §Prereq-1).
        let decrypted = decrypt_with_membership_changes(&mut self.mls_group, ciphertext, clock)?;
        let (sender_did, framed) = match decrypted {
            InboundChange::Application {
                plaintext,
                sender_did,
            } => (sender_did, plaintext),
            InboundChange::Commit {
                sender_did,
                added_dids,
                added_wrapping_keys,
                committer_timestamp_secs,
            } => {
                return Ok(Inbound::Commit {
                    sender_did,
                    added_dids,
                    added_wrapping_keys,
                    committer_timestamp_secs,
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

        // Management-message branch (§9.16.1 exclusivity): the SCPM_MAGIC check
        // occurs EXACTLY here, at the MLS-plaintext → application boundary — no
        // other layer strips or tests it. A management frame is MLS-encrypted only
        // (no §9.16 sender-key layer); an in-tab management message is a sender-key
        // distribution. `framed` is the decrypted MLS plaintext; `sender_did` is
        // its authenticated MLS credential DID.
        //
        // Disjointness (§9.16.1): an application message's first 4 bytes are the
        // high 4 bytes of the big-endian sender-key epoch. For every reachable
        // epoch (< 2^32) those bytes are `00 00 00 00`, which cannot equal
        // SCPM_MAGIC (`53 43 50 4D`), so this branch and the application path
        // below are mutually exclusive. A collision would require epoch ≥ 2^32;
        // that is operationally unreachable (each rotation advances by one, so
        // ~4.3 billion monotonic advances would be needed — `MAX_EPOCH_ADVANCE`
        // is a per-message rate window, not an absolute cap) rather than
        // hard-bounded, AND the sender-DID binding in
        // `install_incoming_distribution` is an independent guard, so
        // classification never rests on disjointness alone.
        if let Some(payload) = try_strip_management_prefix(&framed) {
            return self.install_incoming_distribution(&sender_did, payload);
        }

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

        // Replay/reorder detection against the PER-CHANNEL floor (§9.16.1,
        // §9.10.4). App data and announcements track separately (see
        // [`RecvChannel`]) so a higher-seq app message cannot drop a lower-seq
        // announcement (or vice versa) across the two unordered relay channels.
        // Consulted BEFORE insert so a duplicate or older `(epoch, sequence)` is
        // refused.
        let channel_tracker = match channel {
            RecvChannel::App => &self.recv_sequence_tracker,
            RecvChannel::Announcement => &self.recv_announcement_tracker,
        };
        if let Some(&(last_epoch, last_seq)) = channel_tracker.get(&sender_did)
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

        // Content/channel binding (defense-in-depth — M-E). The `channel` was
        // selected from the RELAY-supplied routing id, so a hostile relay that
        // re-routes a frame onto the wrong channel could otherwise advance the wrong
        // per-channel floor (a floor-poisoning refinement) or slip an app message
        // through the announcement path (or vice versa). The PRIMARY guarantee
        // against duplicate delivery is openmls's per-generation replay protection
        // (a re-decrypt of the same MLS generation is rejected at Layer 2 above);
        // this binds the DECRYPTED content type to its channel as defense-in-depth:
        //   - the Announcement channel carries ONLY tagged `PseudonymAnnouncement`s;
        //   - the App channel carries ONLY non-announcement app data.
        // A mismatch is DROPPED here, BEFORE any floor advance, so a mis-routed
        // frame cannot poison a floor.
        let is_announcement = is_pseudonym_announcement_payload(&plaintext);
        let channel_matches = match channel {
            RecvChannel::Announcement => is_announcement,
            RecvChannel::App => !is_announcement,
        };
        if !channel_matches {
            return Err(ClientError::ChannelContentMismatch);
        }

        // Advance the PER-CHANNEL floor only AFTER a successful decrypt AND a
        // confirmed content/channel match, so neither a forged-but-undecryptable
        // header nor a mis-routed frame can advance it.
        match channel {
            RecvChannel::App => &mut self.recv_sequence_tracker,
            RecvChannel::Announcement => &mut self.recv_announcement_tracker,
        }
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
    use scp_clock::SystemClock;
    use scp_did::SigningKeyId;
    use scp_mls::group::{
        add_member, add_member_with_convergent_timestamp, create_group, generate_key_package,
        generate_key_package_with_wrapping_key, join_group,
    };
    use scp_mls::{ScpCredential, SignatureKeyPair};
    use scp_protocol::context::pseudonym::{PSEUDONYM_ANNOUNCEMENT_TAG, PseudonymAnnouncement};
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
        let mut alice = ContextCryptoState::from_group(
            CTX,
            create_group(&credential(ALICE), &SystemClock).unwrap(),
        );

        let (bundle, signer, provider): (_, SignatureKeyPair, _) =
            generate_key_package(&credential(BOB), &SystemClock).unwrap();
        let kp_bytes = bundle.key_package().tls_serialize_detached().unwrap();
        let kp_in = KeyPackageIn::tls_deserialize(&mut &*kp_bytes).unwrap();
        let result = add_member(&mut alice.mls_group, kp_in, &SystemClock).unwrap();

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
        match bob
            .decrypt_message(&ct, &SystemClock, RecvChannel::App)
            .unwrap()
        {
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

        let mut alice = ContextCryptoState::from_group(
            CTX,
            create_group(&credential(ALICE), &SystemClock).unwrap(),
        );

        // Carol joins as an existing member.
        let (carol_bundle, carol_signer, carol_provider): (_, SignatureKeyPair, _) =
            generate_key_package(&credential(CAROL), &SystemClock).unwrap();
        let carol_kp_in = KeyPackageIn::tls_deserialize(
            &mut &*carol_bundle.key_package().tls_serialize_detached().unwrap(),
        )
        .unwrap();
        let add_carol = add_member(&mut alice.mls_group, carol_kp_in, &SystemClock).unwrap();
        let mut carol = ContextCryptoState::from_group(
            CTX,
            join_group(&add_carol.welcome, carol_provider, carol_signer).unwrap(),
        );

        // Alice adds Bob; Carol (existing member) processes the Commit. Bob's
        // KeyPackage must publish a wrapping key or the add is rejected pre-merge
        // (ADR-057 sender-key distribution INVARIANT 3).
        let bob_wk = [0xBB_u8; 32];
        let (bob_bundle, _bob_signer, _bob_provider): (_, SignatureKeyPair, _) =
            generate_key_package_with_wrapping_key(&credential(BOB), Some(&bob_wk), &SystemClock)
                .unwrap();
        let bob_kp_in = KeyPackageIn::tls_deserialize(
            &mut &*bob_bundle.key_package().tls_serialize_detached().unwrap(),
        )
        .unwrap();
        // ADR-057: the add-Bob commit binds a convergent timestamp into its
        // AAD; the existing member Carol recovers + validates it on receive.
        let ts = SystemClock.now_secs();
        let add_bob =
            add_member_with_convergent_timestamp(&mut alice.mls_group, bob_kp_in, &SystemClock, ts)
                .unwrap();
        let commit_bytes = add_bob.commit.tls_serialize_detached().unwrap();

        match carol
            .decrypt_message(&commit_bytes, &SystemClock, RecvChannel::App)
            .unwrap()
        {
            Inbound::Commit {
                sender_did,
                added_dids,
                added_wrapping_keys,
                committer_timestamp_secs,
            } => {
                assert_eq!(sender_did, ALICE, "committer is Alice");
                assert_eq!(added_dids, vec![BOB.to_owned()], "Bob's DID surfaced");
                assert_eq!(
                    added_wrapping_keys,
                    vec![bob_wk],
                    "Bob's wrapping key surfaced from the Add proposal's leaf (1:1 with added_dids)"
                );
                assert_eq!(
                    committer_timestamp_secs,
                    Some(ts),
                    "the authenticated convergent timestamp is recovered from the Commit AAD and adopted verbatim"
                );
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
            bob.decrypt_message(&ct2, &SystemClock, RecvChannel::App)
                .is_ok(),
            "newer seq accepted first"
        );
        assert!(
            bob.decrypt_message(&ct1, &SystemClock, RecvChannel::App)
                .is_err(),
            "older (epoch,seq) rejected as reorder/replay"
        );
        assert!(
            bob.decrypt_message(&ct1_dup, &SystemClock, RecvChannel::App)
                .is_err(),
            "duplicate (epoch,seq) rejected"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn announcement_and_app_channels_have_independent_replay_floors() {
        // S2 (§9.10.4 channel reorder): app data and announcements share the
        // per-sender sequence but travel on different, unordered relay channels. A
        // SHARED replay floor would drop a lower-sequence announcement that arrives
        // after a higher-sequence app message. With per-channel floors, it is
        // accepted on the Announcement channel even though the same sequence is
        // rejected on the App channel (whose floor already advanced).
        //
        // The Announcement channel now also enforces the M-E content/channel
        // binding, so its frames MUST carry a real tagged `PseudonymAnnouncement`
        // (an app payload on that channel is rejected as `ChannelContentMismatch`,
        // covered separately in `announcement_channel_rejects_app_payload`). This
        // test keeps the floor concern isolated by sending well-formed
        // announcements on the Announcement channel.
        let (mut alice, mut bob) = alice_and_bob();
        let announcement_payload = || -> Vec<u8> {
            rmp_serde::to_vec_named(&PseudonymAnnouncement {
                tag: PSEUDONYM_ANNOUNCEMENT_TAG.to_owned(),
                member_did: ALICE.to_owned(),
                pseudonym: [7u8; 32],
            })
            .unwrap()
        };

        // App message at seq 5 → advances Bob's APP floor for Alice to 5.
        let app5 = alice.encrypt_message(b"app-5", ALICE, 5).unwrap();
        assert!(
            bob.decrypt_message(&app5, &SystemClock, RecvChannel::App)
                .is_ok()
        );

        // A tagged announcement at seq 3 (LOWER) arriving on the ANNOUNCEMENT
        // channel is ACCEPTED — the announcement floor is independent of the app
        // floor (and the content/channel binding is satisfied).
        let ann3 = alice
            .encrypt_message(&announcement_payload(), ALICE, 3)
            .unwrap();
        assert!(
            bob.decrypt_message(&ann3, &SystemClock, RecvChannel::Announcement)
                .is_ok(),
            "a lower-seq announcement on the announcement channel is accepted despite \
             the higher app-channel floor"
        );

        // A seq-3 APP message on the APP channel is REJECTED (app floor is 5) —
        // confirming the app floor is untouched by the announcement.
        let app3_on_app = alice.encrypt_message(b"app-3", ALICE, 3).unwrap();
        assert!(
            bob.decrypt_message(&app3_on_app, &SystemClock, RecvChannel::App)
                .is_err(),
            "seq 3 on the app channel is a replay/reorder (app floor already at 5)"
        );

        // And a replay of the announcement (seq 3 again on Announcement) is rejected
        // by the announcement floor, which advanced to 3.
        let ann3_dup = alice
            .encrypt_message(&announcement_payload(), ALICE, 3)
            .unwrap();
        assert!(
            bob.decrypt_message(&ann3_dup, &SystemClock, RecvChannel::Announcement)
                .is_err(),
            "the announcement channel still rejects its own replay"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn announcement_channel_rejects_app_payload_and_app_channel_rejects_announcement() {
        // M-E (§9.10.4 content/channel binding, defense-in-depth): the channel is
        // selected from the RELAY-supplied routing id, so a hostile/buggy relay can
        // re-route a frame onto the wrong channel. The DECRYPTED content type is
        // bound to its channel: an app payload delivered on the Announcement channel
        // — and a tagged announcement delivered on the App channel — are both
        // DROPPED as `ChannelContentMismatch`, BEFORE any per-channel floor advances.
        let (mut alice, mut bob) = alice_and_bob();

        // An APP payload mis-routed onto the ANNOUNCEMENT channel is rejected...
        let app_on_ann = alice.encrypt_message(b"app-data", ALICE, 1).unwrap();
        assert!(
            matches!(
                bob.decrypt_message(&app_on_ann, &SystemClock, RecvChannel::Announcement),
                Err(ClientError::ChannelContentMismatch)
            ),
            "app data on the announcement channel is a content/channel mismatch"
        );
        // ...and did NOT poison the announcement floor (no entry recorded for Alice).
        assert!(
            !bob.recv_announcement_tracker.contains_key(ALICE),
            "a mis-routed frame must not advance the announcement floor"
        );

        // Symmetrically, a tagged ANNOUNCEMENT mis-routed onto the APP channel is
        // rejected and does not poison the app floor.
        let ann = PseudonymAnnouncement {
            tag: PSEUDONYM_ANNOUNCEMENT_TAG.to_owned(),
            member_did: ALICE.to_owned(),
            pseudonym: [9u8; 32],
        };
        let ann_on_app = alice
            .encrypt_message(&rmp_serde::to_vec_named(&ann).unwrap(), ALICE, 2)
            .unwrap();
        assert!(
            matches!(
                bob.decrypt_message(&ann_on_app, &SystemClock, RecvChannel::App),
                Err(ClientError::ChannelContentMismatch)
            ),
            "an announcement on the app channel is a content/channel mismatch"
        );
        assert!(
            !bob.recv_sequence_tracker.contains_key(ALICE),
            "a mis-routed frame must not advance the app floor"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn failed_decrypt_does_not_advance_tracker() {
        // Bob lacks Alice's sender key, so the first decrypt fails at the inner
        // layer and must not advance the replay floor.
        let mut alice = ContextCryptoState::from_group(
            CTX,
            create_group(&credential(ALICE), &SystemClock).unwrap(),
        );
        let (bundle, signer, provider): (_, SignatureKeyPair, _) =
            generate_key_package(&credential(BOB), &SystemClock).unwrap();
        let kp_bytes = bundle.key_package().tls_serialize_detached().unwrap();
        let kp_in = KeyPackageIn::tls_deserialize(&mut &*kp_bytes).unwrap();
        let result = add_member(&mut alice.mls_group, kp_in, &SystemClock).unwrap();
        let bob_group = join_group(&result.welcome, provider, signer).unwrap();
        let mut bob = ContextCryptoState::from_group(CTX, bob_group);

        let ct = alice.encrypt_message(b"one", ALICE, 1).unwrap();
        assert!(
            bob.decrypt_message(&ct, &SystemClock, RecvChannel::App)
                .is_err(),
            "no sender key → fails"
        );
        assert!(
            !bob.recv_sequence_tracker.contains_key(ALICE),
            "a failed decrypt must not advance the tracker"
        );

        // After receiving the key out-of-band, a fresh send at seq 1 decrypts.
        bob.insert_sender_key(ALICE, SenderKey::from_bytes(alice.local_sender_key_bytes()));
        let ct_b = alice.encrypt_message(b"one-b", ALICE, 1).unwrap();
        assert!(
            bob.decrypt_message(&ct_b, &SystemClock, RecvChannel::App)
                .is_ok()
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn epoch_poisoning_ceiling_rejects_and_does_not_advance_tracker() {
        let (mut alice, mut bob) = alice_and_bob();
        // Forge Alice's epoch to u64::MAX so her next header poisons the ceiling.
        alice.sender_key_epoch = u64::MAX;
        let poisoned = alice.encrypt_message(b"poison", ALICE, 0).unwrap();
        assert!(
            bob.decrypt_message(&poisoned, &SystemClock, RecvChannel::App)
                .is_err(),
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

    // -----------------------------------------------------------------------
    // ADR-057 sender-key distribution (§9.16.1/§9.16.2)
    // -----------------------------------------------------------------------

    /// Builds Alice (creator) and Bob (Welcome-joined) crypto states sharing one
    /// MLS group, each with a KNOWN stable wrapping keypair published in its leaf,
    /// and each other's wrapping key recorded in its directory — the substrate for
    /// the in-tab distribution tests.
    #[allow(clippy::unwrap_used)]
    fn distribution_pair() -> (ContextCryptoState, ContextCryptoState) {
        use scp_mls::group::{
            add_member, create_group_with_wrapping_key, generate_key_package_with_wrapping_key,
            join_group,
        };

        let (alice_wpub, alice_wsec) = generate_wrapping_keypair();
        let alice_group =
            create_group_with_wrapping_key(&credential(ALICE), Some(&alice_wpub), &SystemClock)
                .unwrap();
        let mut alice =
            ContextCryptoState::from_group_with_wrapping(CTX, alice_group, alice_wpub, alice_wsec);

        let (bob_wpub, bob_wsec) = generate_wrapping_keypair();
        let (bundle, signer, provider): (_, SignatureKeyPair, _) =
            generate_key_package_with_wrapping_key(&credential(BOB), Some(&bob_wpub), &SystemClock)
                .unwrap();
        let kp_in = KeyPackageIn::tls_deserialize(
            &mut &*bundle.key_package().tls_serialize_detached().unwrap(),
        )
        .unwrap();
        let add = add_member(&mut alice.mls_group, kp_in, &SystemClock).unwrap();
        let bob_group = join_group(&add.welcome, provider, signer).unwrap();
        let mut bob =
            ContextCryptoState::from_group_with_wrapping(CTX, bob_group, bob_wpub, bob_wsec);

        for state in [&mut alice, &mut bob] {
            state.record_member_wrapping_key(ALICE, alice_wpub);
            state.record_member_wrapping_key(BOB, bob_wpub);
        }
        (alice, bob)
    }

    #[test]
    fn management_magic_is_disjoint_from_application_epoch_prefix() {
        // §9.16.1 disjointness: an application frame starts with the 8-byte BE
        // sender-key epoch, so its first 4 bytes are the epoch's high 4 bytes. For
        // every reachable epoch (< 2^32, held there by `MAX_EPOCH_ADVANCE`'s
        // monotonic ceiling) those bytes are `00 00 00 00`, which can never equal
        // SCPM_MAGIC (`53 43 50 4D`). This is what lets the single magic check at
        // the MLS-plaintext boundary classify the frame — backstopped, never
        // replaced, by the independent sender-DID binding.
        // The disjointness argument holds only for reachable epochs (< 2^32);
        // pinned at compile time since both operands are constants.
        const {
            assert!(INITIAL_SENDER_KEY_EPOCH < (1u64 << 32));
        }
        let header = build_sender_header(INITIAL_SENDER_KEY_EPOCH, 0, b"ct");
        assert_eq!(
            &header[..4],
            &[0u8; 4],
            "an application header's first 4 bytes are the high bytes of an epoch ≥ 1 (zero)"
        );
        assert_ne!(
            &header[..MANAGEMENT_MSG_MAGIC.len()],
            &MANAGEMENT_MSG_MAGIC[..],
            "the application epoch prefix must be disjoint from SCPM_MAGIC"
        );
        assert!(
            try_strip_management_prefix(&header).is_none(),
            "an application header must NOT be classified as a management message"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used, clippy::expect_used)]
    fn shared_hpke_cross_target_roundtrip_and_wrong_recipient_fails() {
        // The seal/open functions are the SAME shared `scp-protocol` code the native
        // runtime uses, so a native member and a browser member interoperate by
        // construction. Seal a key to Alice's wrapping key; only Alice's secret
        // opens it, and Bob's secret does NOT.
        let (alice_wpub, alice_wsec) = generate_wrapping_keypair();
        let (_bob_wpub, bob_wsec) = generate_wrapping_keypair();
        let key = generate_sender_key();

        let (sealed, enc) =
            hpke_seal_sender_key(key.as_bytes(), &alice_wpub, CTX, ALICE, 1).unwrap();

        let opened = hpke_open_sender_key(&sealed, &enc, &alice_wsec, CTX, ALICE, 1)
            .expect("the sealed-to recipient opens it");
        assert_eq!(
            opened.as_bytes(),
            key.as_bytes(),
            "cross-decrypt recovers the key"
        );

        assert!(
            hpke_open_sender_key(&sealed, &enc, &bob_wsec, CTX, ALICE, 1).is_err(),
            "a wrong-recipient wrapping secret must fail to open (fail-closed)"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used, clippy::panic)]
    fn distribution_installs_peer_key_and_message_decrypts() {
        let (mut alice, mut bob) = distribution_pair();
        let bob_wk = *alice.member_wrapping_keys.get(BOB).unwrap();

        // Alice seals her sender key to Bob and frames it as a management message.
        let dist = alice
            .seal_sender_key_distribution(ALICE, BOB, &bob_wk)
            .unwrap();
        assert_eq!(dist.target_did, BOB);

        // Bob receives it: HPKE-opens + installs, returning SenderKeyInstalled.
        match bob
            .decrypt_message(&dist.ciphertext, &SystemClock, RecvChannel::App)
            .unwrap()
        {
            Inbound::SenderKeyInstalled { sender_did, epoch } => {
                assert_eq!(sender_did, ALICE);
                assert_eq!(epoch, INITIAL_SENDER_KEY_EPOCH);
            }
            other => panic!("expected SenderKeyInstalled, got {other:?}"),
        }

        // A subsequent application message from Alice now decrypts under the
        // distributed key — the sender key was delivered ONLY over the wrapping-key
        // extension mesh, never out-of-band.
        let ct = alice.encrypt_message(b"hi bob", ALICE, 0).unwrap();
        match bob
            .decrypt_message(&ct, &SystemClock, RecvChannel::App)
            .unwrap()
        {
            Inbound::Application {
                sender_did,
                plaintext,
            } => {
                assert_eq!(sender_did, ALICE);
                assert_eq!(plaintext, b"hi bob");
            }
            other => panic!("expected Application, got {other:?}"),
        }
    }

    /// Builds an MLS-encrypted management frame from `alice` carrying an
    /// (attacker-chosen) `response`, for the negative distribution tests.
    #[allow(clippy::unwrap_used)]
    fn frame_distribution(alice: &mut ContextCryptoState, response: SenderKeyResponse) -> Vec<u8> {
        let payload = SenderKeyDistributionMessage::KeyResponse(response)
            .to_bytes()
            .unwrap();
        let mut tagged = MANAGEMENT_MSG_MAGIC.to_vec();
        tagged.extend_from_slice(&payload);
        let mls_out = encrypt(&mut alice.mls_group, &tagged).unwrap();
        serialize_ciphertext(&mls_out).unwrap()
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn distribution_sender_did_mismatch_is_rejected() {
        let (mut alice, mut bob) = distribution_pair();
        let bob_wk = *alice.member_wrapping_keys.get(BOB).unwrap();
        // Seal under a FORGED sender DID (so HPKE info/aad are self-consistent for
        // the forged DID and the open succeeds), but Alice authors the MLS frame —
        // so the MLS credential sender (Alice) ≠ the claimed sender_did.
        let forged = "did:key:z6MkForgedSenderDidNotAliceNotBobXXXXXXXXX";
        let (sealed, enc) =
            hpke_seal_sender_key(alice.local_sender_key.as_bytes(), &bob_wk, CTX, forged, 1)
                .unwrap();
        let response = SenderKeyResponse {
            sender_did: forged.to_owned(),
            epoch: 1,
            hpke_sealed_key: sealed.try_into().unwrap(),
            ephemeral_pubkey: enc,
            request_nonce: [0u8; 16],
        };
        let ct = frame_distribution(&mut alice, response);
        let err = bob
            .decrypt_message(&ct, &SystemClock, RecvChannel::App)
            .unwrap_err();
        assert!(
            matches!(err, ClientError::Driver(ref m) if m.contains("DID mismatch")),
            "a sender-DID mismatch must be rejected, got {err:?}"
        );
        assert!(
            bob.sender_key_store.get(CTX, forged).is_none(),
            "a rejected distribution must not install any key"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn distribution_epoch_ceiling_rejects_without_store_mutation() {
        let (mut alice, mut bob) = distribution_pair();
        let bob_wk = *alice.member_wrapping_keys.get(BOB).unwrap();
        // A u64::MAX epoch far exceeds the stored high-water + MAX_EPOCH_ADVANCE.
        let (sealed, enc) = hpke_seal_sender_key(
            alice.local_sender_key.as_bytes(),
            &bob_wk,
            CTX,
            ALICE,
            u64::MAX,
        )
        .unwrap();
        let response = SenderKeyResponse {
            sender_did: ALICE.to_owned(),
            epoch: u64::MAX,
            hpke_sealed_key: sealed.try_into().unwrap(),
            ephemeral_pubkey: enc,
            request_nonce: [0u8; 16],
        };
        let ct = frame_distribution(&mut alice, response);
        let err = bob
            .decrypt_message(&ct, &SystemClock, RecvChannel::App)
            .unwrap_err();
        assert!(
            matches!(err, ClientError::Driver(ref m) if m.contains("ceiling")),
            "a u64::MAX epoch must be rejected by the poisoning ceiling, got {err:?}"
        );
        assert!(
            bob.sender_key_store.get(CTX, ALICE).is_none(),
            "a ceiling-rejected distribution must not install any key (no mutation)"
        );
        assert_eq!(
            bob.sender_key_store.epoch(CTX, ALICE),
            0,
            "the sender's high-water must not be poisoned"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn distribution_oversized_management_payload_rejected() {
        let (mut alice, mut bob) = distribution_pair();
        // A management payload larger than the §9.16.1 64 KiB bound.
        let mut tagged = MANAGEMENT_MSG_MAGIC.to_vec();
        tagged.extend(std::iter::repeat_n(0u8, MAX_MANAGEMENT_PAYLOAD_SIZE + 1));
        let mls_out = encrypt(&mut alice.mls_group, &tagged).unwrap();
        let ct = serialize_ciphertext(&mls_out).unwrap();
        let err = bob
            .decrypt_message(&ct, &SystemClock, RecvChannel::App)
            .unwrap_err();
        assert!(
            matches!(err, ClientError::Driver(ref m) if m.contains("MAX_MANAGEMENT_PAYLOAD_SIZE")),
            "an oversized management payload must be rejected, got {err:?}"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn wrong_recipient_distribution_fails_to_open() {
        // Alice seals to CAROL's wrapping key but the frame is delivered to Bob:
        // Bob's wrapping secret cannot open a key sealed to Carol (fail-closed).
        let (mut alice, mut bob) = distribution_pair();
        let (carol_wpub, _carol_wsec) = generate_wrapping_keypair();
        let (sealed, enc) = hpke_seal_sender_key(
            alice.local_sender_key.as_bytes(),
            &carol_wpub,
            CTX,
            ALICE,
            1,
        )
        .unwrap();
        let response = SenderKeyResponse {
            sender_did: ALICE.to_owned(),
            epoch: 1,
            hpke_sealed_key: sealed.try_into().unwrap(),
            ephemeral_pubkey: enc,
            request_nonce: [0u8; 16],
        };
        let ct = frame_distribution(&mut alice, response);
        let err = bob
            .decrypt_message(&ct, &SystemClock, RecvChannel::App)
            .unwrap_err();
        assert!(
            matches!(err, ClientError::SenderKey(_)),
            "a distribution sealed to another recipient must fail to open, got {err:?}"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used, clippy::panic)]
    fn rotate_sender_key_redistributes_and_stale_epoch_rejected() {
        // Establish the epoch-1 mesh: Alice → Bob, and Alice sends under epoch 1.
        let (mut alice, mut bob) = distribution_pair();
        let bob_wk = *alice.member_wrapping_keys.get(BOB).unwrap();
        let dist1 = alice
            .seal_sender_key_distribution(ALICE, BOB, &bob_wk)
            .unwrap();
        bob.decrypt_message(&dist1.ciphertext, &SystemClock, RecvChannel::App)
            .unwrap();

        // Capture an epoch-1 ciphertext BEFORE rotation.
        let stale_ct = alice.encrypt_message(b"epoch-1 msg", ALICE, 5).unwrap();

        // Alice rotates: fresh key, epoch 2, re-seals to every directory member.
        let rotations = alice.rotate_sender_key(ALICE).unwrap();
        assert_eq!(alice.sender_key_epoch, INITIAL_SENDER_KEY_EPOCH + 1);
        assert_eq!(rotations.len(), 1, "one distribution to Bob (self skipped)");
        assert_eq!(rotations[0].target_did, BOB);
        bob.decrypt_message(&rotations[0].ciphertext, &SystemClock, RecvChannel::App)
            .unwrap();

        // A message under the NEW key/epoch decrypts at Bob.
        let fresh_ct = alice.encrypt_message(b"epoch-2 msg", ALICE, 0).unwrap();
        match bob
            .decrypt_message(&fresh_ct, &SystemClock, RecvChannel::App)
            .unwrap()
        {
            Inbound::Application { plaintext, .. } => assert_eq!(plaintext, b"epoch-2 msg"),
            other => panic!("expected Application under the rotated key, got {other:?}"),
        }

        // The pre-rotation (epoch-1) ciphertext is now stale: Bob's replay tracker
        // advanced to epoch 2, so an epoch-1 header is rejected as a reorder.
        assert!(
            bob.decrypt_message(&stale_ct, &SystemClock, RecvChannel::App)
                .is_err(),
            "a stale pre-rotation (epoch-1) message must be rejected after rotation"
        );
    }
}
