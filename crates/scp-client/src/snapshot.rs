//! Serializable per-context participant snapshot (ADR-057 T2, §17.9.1).
//!
//! [`ContextSnapshot`] captures everything the driver needs to resume a single
//! context after the tab is closed and reopened: the MLS crypto state (via the
//! shared [`ScpMlsGroup::serialize_state`](scp_mls::ScpMlsGroup::serialize_state)
//! primitive), the §9.16 sender-key state (local key, per-sender key store,
//! epoch high-water floors, receive-replay tracker), the canonical event-log
//! event stream, the membership set with per-member outgoing sequence counters,
//! and a §9.9.3 checkpoint (the event-log Merkle root). It is the read/write unit
//! the driver persists through the injected [`Storage`](crate::Storage) backend
//! — an in-memory backend (a valid production choice for ephemeral, no-persist
//! clients; also convenient in tests) or `IndexedDB`/OPFS in a browser (ADR-057
//! component 3).
//!
//! # Crash / consistency (ADR-057)
//!
//! A single-tab driver has no actor to serialize per-context writes; instead the
//! driver writes ONE snapshot blob per context via a single `Storage::put` after
//! each state-mutating op completes. A `put` is the atomic unit, so a crash
//! leaves either the last fully-committed snapshot or the prior one — never a
//! torn intra-context state.
//!
//! **What the checkpoint covers.** On restore the `event_log_root` checkpoint
//! is recomputed from the replayed event stream and compared to the recorded
//! root; a mismatch fails the restore closed. This is a **torn-write /
//! corruption / truncation** consistency guard on the *event log* — the recorded
//! root lives inside the same blob, so it is NOT a tamper-resistance mechanism
//! (a party who can rewrite the blob recomputes the root to match). The MLS
//! state, sender keys, and the anti-replay floors (`recv_sequence_tracker`,
//! `sender_key_epochs`) are outside the checkpoint; their integrity — and thus
//! resistance to a blob-rollback that re-opens the §9.16 replay window — rests
//! entirely on the `Storage` backend providing **authenticated** encryption at
//! rest (see the security note below), exactly the ADR-057 tab-custody boundary.
//! The `§9.9.3` recompute is sync-available, as the ADR notes.
//!
//! # The receive buffer IS persisted (and why)
//!
//! The pull-based receive buffer ([`PerContextState::event_buffer`]) — local
//! message history awaiting `drain_events` — round-trips in this snapshot (as
//! `buffered_events`, a variant-aware [`BufferedEvent`] list holding a sender's
//! own `MessageSent` and a receiver's `MessageReceived`), so a message sent or
//! decrypted before a crash-before-drain is delivered exactly once after restore
//! rather than lost. A received message cannot be recovered by relay re-delivery:
//! decrypting it already advanced the MLS ratchet, and that advance is persisted
//! in `mls_state`, so on restore openmls rejects the re-delivered ciphertext with
//! *"the requested secret was deleted to preserve forward secrecy."* Persisting
//! the buffer keeps the persisted `recv_sequence_tracker` floor consistent with
//! the persisted MLS ratchet — both advance together on decrypt and are captured
//! together. This is decrypted plaintext, so it relies on the backend's
//! encryption at rest (below). (`snapshot_restore.rs` pins both the
//! deliver-exactly-once and the FS-rejection properties.)
//!
//! # What this snapshot does NOT carry
//!
//! - **The injected dependencies** — the [`Signer`](crate::Signer),
//!   [`Storage`](crate::Storage), and [`Clock`](scp_clock::Clock) are supplied at
//!   [`ScpClient::new`](crate::ScpClient::new); they are not snapshot state.
//! - **Pending-join material** — the private half of an unconsumed `KeyPackage`
//!   is persisted **separately**, as its own `scp-client/pending/{id}` blob by the
//!   driver (not inside this per-context snapshot), and restored the same way, so
//!   an interrupted join resumes on reopen.
//!
//! # Security — this blob carries raw private key material
//!
//! The MLS state (signer + epoch/HPKE secrets) and the sender keys are private.
//! The blob is NOT self-encrypting and NOT self-authenticating: the `Storage`
//! backend MUST provide **authenticated** encryption at rest (an AEAD-backed
//! store, not merely a confidential one). Confidentiality keeps the keys secret;
//! authentication is what actually prevents a blob-rollback from lowering an
//! anti-replay floor on restore (the checkpoint above does not cover those
//! fields). This is §17.5 and the ADR-057 tab custody/plaintext boundary. The
//! snapshot's key-bearing fields are zeroized after serialization/reconstruction.

use std::collections::{HashMap, VecDeque};

use scp_event_log::tree::{append_unsigned_event, root};
use scp_event_log::{Event, EventLog};
use scp_mls::ScpMlsGroup;
use scp_protocol::context::membership::ContextEvent;
use scp_protocol::crypto::sender_keys::{SenderKey, SenderKeyStore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::context::PerContextState;
use crate::crypto_state::ContextCryptoState;
use crate::error::ClientError;

/// The on-disk format version of a [`ContextSnapshot`].
///
/// Written into every snapshot and checked on read. A blob whose version this
/// build does not understand is rejected (fail closed) rather than
/// mis-deserialized. Bump this when the snapshot shape changes; SCP is
/// pre-release, so there is no legacy-format migration path — an unknown version
/// is a hard error.
///
/// **v2** widened the persisted receive buffer from `MessageReceived`-only pairs
/// to a variant-aware [`BufferedEvent`] (the driver now also buffers a sender's
/// own `MessageSent` local history — ADR-011 / ADR-057 T3). Pre-release: no
/// migration, a v1 blob is rejected as an unknown version.
pub const SNAPSHOT_FORMAT_VERSION: u16 = 2;

/// A buffered, decrypted-but-undrained context event, in serializable form.
///
/// The participant driver buffers two variants of local message history for
/// [`crate::ScpClient::drain_events`]: a sender's own `MessageSent` (recorded on
/// [`crate::ScpClient::send_message`]) and a receiver's `MessageReceived`
/// (recorded on [`crate::ScpClient::receive_message`]). Neither is a convergent
/// event-log leaf (ADR-011 exclusion taxonomy §2), so both live only in this
/// buffer; persisting them keeps the persisted `recv_sequence_tracker` / MLS
/// ratchet consistent with what the tab had decrypted/sent before a
/// crash-before-drain. Both carry decrypted plaintext, so both depend on the
/// backend's encryption at rest (see the module security note) and are zeroized.
#[derive(Serialize, Deserialize)]
enum BufferedEvent {
    /// A message this participant sent (its own local `MessageSent` history).
    Sent {
        /// The sender's DID (this participant).
        sender_did: String,
        /// The per-sender sequence number stamped on the send.
        sequence_number: u64,
        /// The (plaintext) payload that was sent.
        payload: Vec<u8>,
    },
    /// A message this participant received and decrypted (`MessageReceived`).
    Received {
        /// The sender's DID (a peer).
        sender_did: String,
        /// The decrypted plaintext payload.
        payload: Vec<u8>,
    },
}

/// A serializable snapshot of one context's participant state.
///
/// Round-trips through [`Self::capture`] / [`Self::restore`] and
/// [`Self::to_bytes`] / [`Self::from_bytes`]. See the module docs for the
/// security contract and the crash/consistency model.
#[derive(Serialize, Deserialize)]
pub struct ContextSnapshot {
    /// Format version (see [`SNAPSHOT_FORMAT_VERSION`]).
    format_version: u16,
    /// The context id this snapshot belongs to.
    context_id: String,
    /// The DID of the identity that owns this snapshot (the client's DID at
    /// capture time). Restore rejects a snapshot whose owner does not match the
    /// restoring client's DID — a snapshot's MLS/sender-key state belongs to one
    /// identity and must not be adopted under another.
    owner_did: String,
    /// The MLS crypto state, serialized by
    /// [`ScpMlsGroup::serialize_state`](scp_mls::ScpMlsGroup::serialize_state).
    mls_state: Vec<u8>,
    /// This participant's own §9.16 sender key.
    local_sender_key: SenderKey,
    /// This participant's monotonic sender-key epoch (§9.16.5).
    sender_key_epoch: u64,
    /// Other members' sender keys for this context: `(sender_did, key)` pairs.
    sender_key_entries: Vec<(String, SenderKey)>,
    /// Per-sender epoch high-water floors for this context: `(sender_did, epoch)`
    /// pairs. Persisted so the sender-key rollback-protection floor survives a
    /// restart (mirrors the native runtime crypto snapshot, §17.9.1).
    sender_key_epochs: Vec<(String, u64)>,
    /// Receive-replay tracker: `(sender_did, last_epoch, last_sequence)`.
    /// Persisted so a replay/reorder window is not re-opened across a restart.
    recv_sequence_tracker: Vec<(String, u64, u64)>,
    /// The full ordered event-log stream. Replayed on restore to reconstruct a
    /// byte-identical [`EventLog`] (same leaves, same root — §9.9.3).
    events: Vec<Event>,
    /// The pull-based receive buffer — decrypted-but-undrained local message
    /// history as variant-aware [`BufferedEvent`]s, in FIFO order. Persisted so a
    /// message sent or decrypted before a crash-before-drain is NOT lost: it
    /// survives in the encrypted-at-rest snapshot and is returned by
    /// `drain_events` after restore (a received message cannot be recovered by
    /// relay re-delivery — decrypting it already advanced and persisted the MLS
    /// forward-secrecy ratchet). This is decrypted plaintext, so it depends on the
    /// backend's encryption at rest (see the module security note). The driver
    /// buffers `MessageSent` (a sender's own history) and `MessageReceived`, so
    /// [`BufferedEvent`]'s two variants are its complete representation.
    buffered_events: Vec<BufferedEvent>,
    /// The membership set (member DIDs).
    members: Vec<String>,
    /// Per-member next-outgoing message sequence numbers: `(did, sequence)`.
    member_sequence_numbers: Vec<(String, u64)>,
    /// The §9.9.3 checkpoint: the event-log Merkle root at snapshot time. On
    /// restore, the root recomputed from `events` MUST equal this, or the blob is
    /// rejected as a torn/corrupt/truncated event stream. This binds the event
    /// log only (the root is stored in-blob, so it is not tamper-resistant — see
    /// the module security note); it is a consistency guard, not authentication.
    event_log_root: [u8; 32],
}

// SECURITY: manual `Debug` redacts key material and the (potentially sensitive)
// event payloads. `Clone` is intentionally NOT derived — the snapshot holds raw
// sender keys and the MLS signer/epoch secrets and must not be freely
// duplicated.
impl std::fmt::Debug for ContextSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContextSnapshot")
            .field("format_version", &self.format_version)
            .field("context_id", &self.context_id)
            .field("owner_did", &self.owner_did)
            .field(
                "mls_state",
                &format_args!("[{} bytes, REDACTED]", self.mls_state.len()),
            )
            .field("local_sender_key", &"[REDACTED]")
            .field("sender_key_epoch", &self.sender_key_epoch)
            .field(
                "sender_key_entries",
                &format_args!("[{} entries, REDACTED]", self.sender_key_entries.len()),
            )
            .field("sender_key_epochs", &self.sender_key_epochs)
            .field("recv_sequence_tracker", &self.recv_sequence_tracker)
            .field("events", &format_args!("[{} events]", self.events.len()))
            .field(
                "buffered_events",
                &format_args!("[{} events, REDACTED]", self.buffered_events.len()),
            )
            .field("members", &self.members)
            .field("member_sequence_numbers", &self.member_sequence_numbers)
            .field("event_log_root", &hex_root(&self.event_log_root))
            .finish()
    }
}

impl ContextSnapshot {
    /// Captures the current state of `state` (belonging to `context_id`, owned by
    /// `owner_did`) into a serializable snapshot.
    ///
    /// `owner_did` is the capturing client's DID; [`Self::restore`] rejects a
    /// snapshot whose `owner_did` does not match the restoring client, so one
    /// identity's MLS/sender-key state can never be adopted under another.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Mls`] if the MLS group state cannot be serialized
    /// (destroyed group, poisoned provider lock), or [`ClientError::Driver`] if
    /// the receive buffer holds an event other than `MessageReceived` (an
    /// internal invariant violation — the driver only ever buffers that variant).
    pub fn capture(
        context_id: &str,
        owner_did: &str,
        state: &PerContextState,
    ) -> Result<Self, ClientError> {
        let crypto: &ContextCryptoState = &state.crypto;
        let mls_state = crypto.mls_group.serialize_state()?;

        let sender_key_entries: Vec<(String, SenderKey)> = crypto
            .sender_key_store
            .get_all(&crypto.context_id)
            .into_iter()
            .collect();
        let sender_key_epochs = crypto
            .sender_key_store
            .epochs_for_context(&crypto.context_id);
        let recv_sequence_tracker: Vec<(String, u64, u64)> = crypto
            .recv_sequence_tracker
            .iter()
            .map(|(did, (epoch, seq))| (did.clone(), *epoch, *seq))
            .collect();

        let member_sequence_numbers: Vec<(String, u64)> = state
            .member_sequence_numbers
            .iter()
            .map(|(did, seq)| (did.clone(), *seq))
            .collect();

        // Convert the receive buffer (decrypted-but-undrained local history) into
        // the persisted variant-aware form. The driver buffers `MessageSent` (a
        // sender's own history) and `MessageReceived`; any other variant is an
        // internal invariant violation and fails closed rather than being silently
        // dropped (the payload is never logged).
        let mut buffered_events = Vec::with_capacity(state.event_buffer.len());
        for event in &state.event_buffer {
            match event {
                ContextEvent::MessageSent {
                    sender_did,
                    sequence_number,
                    payload,
                } => buffered_events.push(BufferedEvent::Sent {
                    sender_did: sender_did.0.clone(),
                    sequence_number: *sequence_number,
                    payload: payload.clone(),
                }),
                ContextEvent::MessageReceived {
                    sender_did,
                    payload,
                } => buffered_events.push(BufferedEvent::Received {
                    sender_did: sender_did.0.clone(),
                    payload: payload.clone(),
                }),
                _ => {
                    return Err(ClientError::Driver(
                        "receive buffer holds an event that is neither MessageSent nor \
                         MessageReceived; only those are buffered by the participant driver"
                            .to_owned(),
                    ));
                }
            }
        }

        Ok(Self {
            format_version: SNAPSHOT_FORMAT_VERSION,
            context_id: context_id.to_owned(),
            owner_did: owner_did.to_owned(),
            mls_state,
            local_sender_key: crypto.local_sender_key.clone(),
            sender_key_epoch: crypto.sender_key_epoch,
            sender_key_entries,
            sender_key_epochs,
            recv_sequence_tracker,
            events: state.events(),
            buffered_events,
            members: state.members.clone(),
            member_sequence_numbers,
            event_log_root: state.event_log_root(),
        })
    }

    /// Reconstructs a live [`PerContextState`] from this snapshot, verifying the
    /// `owner_did` binding and the §9.9.3 checkpoint.
    ///
    /// First rejects a snapshot whose `owner_did` does not equal
    /// `expected_owner_did` (the restoring client's DID) — adopting another
    /// identity's MLS/sender-key state would be an identity confusion. Then
    /// rebuilds the crypto state (MLS group + sender keys), the receive buffer,
    /// replays the event stream into a fresh [`EventLog`], restores membership and
    /// sequence counters, and — crucially — recomputes the event-log Merkle root
    /// and compares it to the recorded checkpoint. A mismatch means the persisted
    /// event stream and its recorded root disagree (a torn/corrupt/truncated
    /// blob), so restore fails closed. (This binds the event log only; whole-blob
    /// authenticity rests on the backend's authenticated encryption at rest — see
    /// the module security note.)
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::StorageIdentityMismatch`] if the snapshot belongs to
    /// a different identity, [`ClientError::Mls`] if the MLS state cannot be
    /// reconstructed, [`ClientError::EventLog`] if the persisted event stream does
    /// not chain cleanly on replay, or [`ClientError::StorageCorrupt`] if the
    /// recomputed checkpoint does not match the recorded root.
    pub fn restore(mut self, expected_owner_did: &str) -> Result<PerContextState, ClientError> {
        // Identity binding: reject another identity's snapshot before touching any
        // crypto state (cheapest fail-closed check).
        if self.owner_did != expected_owner_did {
            return Err(ClientError::StorageIdentityMismatch(format!(
                "snapshot for context '{}' is owned by '{}', not this client '{expected_owner_did}'",
                self.context_id, self.owner_did,
            )));
        }

        // Reconstruct crypto state.
        let mls_group = ScpMlsGroup::deserialize_state(&self.mls_state)?;

        let mut sender_key_store = SenderKeyStore::new();
        // Restore epoch high-water floors FIRST (authoritative marks), then the
        // key material. The two maps are independent (`restore_epoch_high_water`
        // touches only epochs, `set_unchecked` only keys), so no floor is lost.
        for (did, epoch) in std::mem::take(&mut self.sender_key_epochs) {
            sender_key_store.restore_epoch_high_water(&self.context_id, &did, epoch);
        }
        for (did, key) in std::mem::take(&mut self.sender_key_entries) {
            sender_key_store.set_unchecked(&self.context_id, &did, key);
        }

        let recv_sequence_tracker: HashMap<String, (u64, u64)> =
            std::mem::take(&mut self.recv_sequence_tracker)
                .into_iter()
                .map(|(did, epoch, seq)| (did, (epoch, seq)))
                .collect();

        // Move the local sender key out, leaving a zeroed placeholder that is
        // wiped when the snapshot drops.
        let local_sender_key =
            std::mem::replace(&mut self.local_sender_key, SenderKey::from_bytes([0u8; 32]));

        let crypto = ContextCryptoState {
            mls_group,
            local_sender_key,
            context_id: self.context_id.clone(),
            sender_key_epoch: self.sender_key_epoch,
            sender_key_store,
            recv_sequence_tracker,
        };

        // Rebuild the event log by replaying the persisted stream through the
        // canonical append path (validates chaining), then verify the checkpoint.
        let mut event_log = EventLog::new(self.context_id.clone());
        for event in &self.events {
            append_unsigned_event(&mut event_log, event)?;
        }
        let recomputed = root(&event_log);
        if recomputed != self.event_log_root {
            // `self` (and its key material) is zeroized by `Drop` on return.
            return Err(ClientError::StorageCorrupt(format!(
                "checkpoint mismatch for context '{}': recomputed event-log root {} \
                 does not match the recorded root {} (torn/corrupt/truncated snapshot)",
                self.context_id,
                hex_root(&recomputed),
                hex_root(&self.event_log_root),
            )));
        }

        let member_sequence_numbers: HashMap<String, u64> =
            std::mem::take(&mut self.member_sequence_numbers)
                .into_iter()
                .collect();

        // Rebuild the receive buffer (decrypted-but-undrained local history) in
        // FIFO order, so a message sent or decrypted before the tab closed is
        // delivered exactly once after restore (a received message cannot be
        // recovered by relay re-delivery — the MLS ratchet that decrypted it is
        // persisted and advanced).
        let event_buffer: VecDeque<ContextEvent> = std::mem::take(&mut self.buffered_events)
            .into_iter()
            .map(|event| match event {
                BufferedEvent::Sent {
                    sender_did,
                    sequence_number,
                    payload,
                } => ContextEvent::MessageSent {
                    sender_did: sender_did.into(),
                    sequence_number,
                    payload,
                },
                BufferedEvent::Received {
                    sender_did,
                    payload,
                } => ContextEvent::MessageReceived {
                    sender_did: sender_did.into(),
                    payload,
                },
            })
            .collect();

        let state = PerContextState {
            crypto,
            event_log,
            members: std::mem::take(&mut self.members),
            member_sequence_numbers,
            event_buffer,
            // A restored context IS the last durable state — nothing has diverged,
            // so it is unpoisoned by construction (the poison flag is in-memory
            // session state, never serialized).
            poisoned: false,
        };

        // `self` (and any residual key material) is zeroized by `Drop` on return.
        Ok(state)
    }

    /// Serializes this snapshot to a `MessagePack` blob for storage.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::StorageCorrupt`] if the snapshot cannot be
    /// serialized into a durable blob (unreachable for a well-formed snapshot).
    pub fn to_bytes(&self) -> Result<Vec<u8>, ClientError> {
        rmp_serde::to_vec_named(self)
            .map_err(|e| ClientError::StorageCorrupt(format!("serializing context snapshot: {e}")))
    }

    /// Deserializes a snapshot from a `MessagePack` blob, rejecting an unknown
    /// format version.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::StorageCorrupt`] if the blob cannot be deserialized
    /// or carries a format version this build does not understand.
    pub fn from_bytes(blob: &[u8]) -> Result<Self, ClientError> {
        let snapshot: Self = rmp_serde::from_slice(blob).map_err(|e| {
            ClientError::StorageCorrupt(format!("deserializing context snapshot: {e}"))
        })?;
        if snapshot.format_version != SNAPSHOT_FORMAT_VERSION {
            return Err(ClientError::StorageCorrupt(format!(
                "unsupported context snapshot format version {} (this build understands {})",
                snapshot.format_version, SNAPSHOT_FORMAT_VERSION
            )));
        }
        Ok(snapshot)
    }

    /// The context id this snapshot belongs to.
    #[must_use]
    pub fn context_id(&self) -> &str {
        &self.context_id
    }

    /// Zeroizes the secret-bearing fields (`mls_state`, sender keys, and the
    /// buffered decrypted plaintext). `SenderKey` already zeroizes on drop; this
    /// clears the MLS blob, the sender-key entry copies, and the buffered
    /// plaintext explicitly so they do not linger (the tab is the plaintext
    /// boundary — ADR-057).
    fn zeroize_secrets(&mut self) {
        self.mls_state.zeroize();
        self.local_sender_key.zeroize();
        for (_, key) in &mut self.sender_key_entries {
            key.zeroize();
        }
        for event in &mut self.buffered_events {
            match event {
                BufferedEvent::Sent { payload, .. } | BufferedEvent::Received { payload, .. } => {
                    payload.zeroize();
                }
            }
        }
    }
}

// SECURITY: the snapshot carries the MLS signer/epoch secrets (inside
// `mls_state`) and sender keys. `SenderKey` already zeroizes on drop, but the
// `mls_state` blob does not — zeroize every key-bearing field when the snapshot
// is dropped so private material never lingers in freed memory, on any path
// (capture, restore, error).
impl Drop for ContextSnapshot {
    fn drop(&mut self) {
        self.zeroize_secrets();
    }
}

/// Renders a 32-byte root as a short hex string for diagnostics (never secret —
/// the Merkle root is public).
fn hex_root(root: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for byte in root {
        use std::fmt::Write as _;
        let _ = write!(s, "{byte:02x}");
    }
    s
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::crypto_state::ContextCryptoState;
    use scp_clock::SystemClock;
    use scp_did::SigningKeyId;
    use scp_event_log::EventType;
    use scp_mls::ScpCredential;
    use scp_mls::group::create_group;

    const CTX: &str = "ctx-snapshot-unit";
    const CREATOR: &str = "did:key:z6MkSnapshotUnitCreatorFixtureAAAAAAAAAAAAA";

    /// Builds a fresh single-member context state (creator only, one leaf).
    fn fresh_state() -> PerContextState {
        let credential =
            ScpCredential::new(CREATOR.to_owned(), None, SigningKeyId::Active).unwrap();
        let crypto =
            ContextCryptoState::from_group(CTX, create_group(&credential, &SystemClock).unwrap());
        let mut state = PerContextState::new(CTX, CREATOR, crypto);
        state
            .append_log_event(EventType::ContextCreated, CREATOR, Vec::new(), 1_000)
            .unwrap();
        state
    }

    #[test]
    fn round_trip_through_bytes_reconstructs_the_log() {
        let state = fresh_state();
        let original_root = state.event_log_root();
        let original_count = state.event_log_leaf_count();

        let blob = ContextSnapshot::capture(CTX, CREATOR, &state)
            .unwrap()
            .to_bytes()
            .unwrap();
        let restored = ContextSnapshot::from_bytes(&blob)
            .unwrap()
            .restore(CREATOR)
            .unwrap();

        assert_eq!(restored.event_log_root(), original_root);
        assert_eq!(restored.event_log_leaf_count(), original_count);
        assert_eq!(restored.members, vec![CREATOR.to_owned()]);
    }

    #[test]
    fn buffered_messages_round_trip() {
        // Both buffered variants — a sender's own MessageSent and a receiver's
        // MessageReceived — survive capture/restore in FIFO order and are
        // delivered exactly once after restore.
        let mut state = fresh_state();
        state.push_event(ContextEvent::MessageSent {
            sender_did: CREATOR.to_owned().into(),
            sequence_number: 7,
            payload: b"my own send".to_vec(),
        });
        state.push_event(ContextEvent::MessageReceived {
            sender_did: "did:key:zPeer".to_owned().into(),
            payload: b"undrained".to_vec(),
        });

        let blob = ContextSnapshot::capture(CTX, CREATOR, &state)
            .unwrap()
            .to_bytes()
            .unwrap();
        let mut restored = ContextSnapshot::from_bytes(&blob)
            .unwrap()
            .restore(CREATOR)
            .unwrap();

        let drained = restored.drain_events();
        assert_eq!(drained.len(), 2, "both buffered events survive");
        match &drained[0] {
            ContextEvent::MessageSent {
                sender_did,
                sequence_number,
                payload,
            } => {
                assert_eq!(sender_did.0, CREATOR);
                assert_eq!(*sequence_number, 7);
                assert_eq!(payload.as_slice(), b"my own send");
            }
            other => panic!("expected the buffered MessageSent first, got {other:?}"),
        }
        match &drained[1] {
            ContextEvent::MessageReceived {
                sender_did,
                payload,
            } => {
                assert_eq!(sender_did.0, "did:key:zPeer");
                assert_eq!(payload.as_slice(), b"undrained");
            }
            other => panic!("expected the buffered MessageReceived second, got {other:?}"),
        }
        assert!(
            restored.drain_events().is_empty(),
            "the buffered messages are delivered exactly once"
        );
    }

    #[test]
    fn owner_mismatch_fails_closed() {
        let state = fresh_state();
        let snapshot = ContextSnapshot::capture(CTX, CREATOR, &state).unwrap();
        // A different client attempts to restore CREATOR's snapshot.
        match snapshot.restore("did:key:zSomeoneElse") {
            Err(ClientError::StorageIdentityMismatch(msg)) => {
                assert!(msg.contains(CREATOR), "got: {msg}");
            }
            Err(other) => panic!("expected StorageIdentityMismatch, got {other:?}"),
            Ok(_) => panic!("expected a foreign-owner snapshot to be rejected"),
        }
    }

    #[test]
    fn checkpoint_mismatch_fails_closed() {
        let state = fresh_state();
        let mut snapshot = ContextSnapshot::capture(CTX, CREATOR, &state).unwrap();
        // Corrupt the recorded checkpoint so it no longer matches the event
        // stream the snapshot carries — simulating a torn/corrupt blob.
        snapshot.event_log_root[0] ^= 0xFF;

        match snapshot.restore(CREATOR) {
            Err(ClientError::StorageCorrupt(msg)) => {
                assert!(msg.contains("checkpoint mismatch"), "got: {msg}");
            }
            Err(other) => panic!("expected a StorageCorrupt checkpoint error, got {other:?}"),
            Ok(_) => panic!("expected the corrupted checkpoint to be rejected"),
        }
    }

    #[test]
    fn unknown_format_version_is_rejected() {
        let state = fresh_state();
        let mut snapshot = ContextSnapshot::capture(CTX, CREATOR, &state).unwrap();
        snapshot.format_version = SNAPSHOT_FORMAT_VERSION + 1;
        let blob = snapshot.to_bytes().unwrap();

        let err = ContextSnapshot::from_bytes(&blob).unwrap_err();
        match err {
            ClientError::StorageCorrupt(msg) => {
                assert!(
                    msg.contains("unsupported context snapshot format version"),
                    "got: {msg}"
                );
            }
            other => panic!("expected a StorageCorrupt version error, got {other:?}"),
        }
    }

    #[test]
    fn garbage_blob_is_rejected() {
        let err = ContextSnapshot::from_bytes(b"not a snapshot").unwrap_err();
        assert!(matches!(err, ClientError::StorageCorrupt(_)));
    }
}
