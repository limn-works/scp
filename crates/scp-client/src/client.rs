//! The single-threaded SCP participant driver.
//!
//! [`ScpClient`] is the in-tab participant: a per-context state map accessed
//! synchronously, with op methods that sequence the shared `scp-mls` /
//! `scp-protocol` / `scp-event-log` logic. It restores the deleted WASM
//! bridge's proven *shape* (a per-context state map, op methods named
//! `create_context` / `generate_key_package_for_join` / `add_member` /
//! `join_context_encrypted` / `send_message` / `receive_message` /
//! `drain_events` / `close_context`, and a pull-based event model) while
//! calling shared protocol code for every body.
//!
//! Single-threaded throughout: no tokio, no actors. The driver owns its state
//! by `&mut self`; there is no internal concurrency. A browser runs one of
//! these per tab.
//!
//! # Scope fence (ADR-057)
//!
//! Participant message path ONLY: create / generate-key-package / add-member /
//! join / send / receive-decrypt / process-commit / close, plus the event-log
//! leaves for those events. No economy, governance voting, broadcast hosting,
//! cross-context saga coordination, tools, discovery, or UCAN minting — those
//! require always-on hosts and live node-side. The fence is enforced
//! mechanically by the crate's dependency set (no `scp-runtime` /
//! `scp-identity` / `tokio`).

use std::collections::HashMap;
use std::sync::Arc;

use openmls::prelude::{KeyPackageBundle, KeyPackageIn, MlsMessageOut, ProtocolVersion};
use scp_event_log::{Event, EventType};
use scp_mls::group::{
    add_member, create_group, destroy_group, generate_key_package, join_group_from_bytes,
    key_package_in_did,
};
use scp_mls::{InMemoryMlsProvider, ScpCredential, SignatureKeyPair};
use scp_primitives::Clock;
use scp_protocol::context::membership::ContextEvent;
use scp_protocol::crypto::sender_keys::SenderKey;
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};

use crate::context::PerContextState;
use crate::crypto_state::{ContextCryptoState, Inbound};
use crate::error::ClientError;
use crate::signer::Signer;
use crate::storage::Storage;

/// Pending join material a prospective member retains between generating its
/// `KeyPackage` and processing the resulting Welcome.
///
/// `generate_key_package` produces a `(bundle, signer, provider)` triple; the
/// public `KeyPackage` (serialized) is handed to the adder, but the matching
/// private `signer` + `provider` MUST be retained by the joiner to process the
/// Welcome. This struct holds that retained half, keyed by context id on the
/// client.
struct PendingJoin {
    signer: SignatureKeyPair,
    provider: InMemoryMlsProvider,
}

/// The result of adding a member: the wire bytes the driver must distribute,
/// plus the convergent committer timestamp the adder stamped on its
/// `MemberJoined` leaf.
///
/// `commit` goes to all *existing* members. They apply it via
/// [`ScpClient::receive_message`], which classifies it as a membership-changing
/// Commit, advances their MLS epoch, and — using `committer_timestamp_secs`
/// transported here exactly as [`SendOutput::committer_timestamp_secs`] is for
/// messages — appends the identical `MemberJoined` leaf so their event log and
/// membership set converge with the committer's and the joiner's.
///
/// `welcome` goes to the *new* member, who applies it via
/// [`ScpClient::join_context_encrypted`] and replays `event_log` (which already
/// contains the committer-stamped `MemberJoined` leaf), so the joiner's log is
/// byte-identical to the committer's.
#[derive(Debug, Clone)]
pub struct AddMemberOutput {
    /// TLS-serialized MLS Commit for existing members.
    pub commit: Vec<u8>,
    /// TLS-serialized MLS Welcome for the new member.
    pub welcome: Vec<u8>,
    /// The convergent committer timestamp (Unix seconds) the adder stamped on
    /// its `MemberJoined` leaf. Transported to existing members alongside
    /// `commit` so their mirrored `MemberJoined` leaf carries the SAME
    /// timestamp and converges byte-for-byte (§9.9.3). The joiner does not need
    /// it separately — its copy already rides inside `event_log`.
    pub committer_timestamp_secs: u64,
    /// The adder's full event-log stream AFTER the add (the prior context
    /// history plus the new `MemberJoined` leaf). The joiner replays this
    /// verbatim to reconstruct a byte-identical log and converge to the same
    /// Merkle root (§7.3.1 context-state import, §9.9.3 convergence).
    pub event_log: Vec<Event>,
    /// The adder's membership set after the add. The joiner adopts it so both
    /// sides agree on who is in the context without re-deriving it.
    pub members: Vec<String>,
}

/// The result of sending a message: the wire ciphertext, plus the convergent
/// committer timestamp the sender stamped on its `MessageSent` leaf.
///
/// Every recipient MUST stamp the same `committer_timestamp_secs` on their
/// own `MessageSent` leaf (passed to [`ScpClient::receive_message`]) so the
/// leaves converge byte-for-byte across members (§9.9.3). The timestamp travels
/// with the ciphertext exactly as a signed SCP envelope's `created_at` does on
/// the native path.
#[derive(Debug, Clone)]
pub struct SendOutput {
    /// TLS-serialized MLS ciphertext for delivery to peers.
    pub ciphertext: Vec<u8>,
    /// The convergent committer timestamp (Unix seconds) the sender stamped.
    pub committer_timestamp_secs: u64,
}

/// The single-threaded SCP participant driver.
pub struct ScpClient {
    /// This participant's on-device DID identity.
    signer: Arc<dyn Signer>,
    /// Out-of-band snapshot storage (`IndexedDB` in a browser; in-memory here).
    /// Held from construction so the dependency is explicit and the snapshot
    /// seam is ready for a later slice without an API change.
    #[allow(dead_code)]
    storage: Arc<dyn Storage>,
    /// Hardened time source. Used for committer-assigned event-log leaf
    /// timestamps; in a browser this is the hardened clock (ADR-057
    /// Prerequisite 1), never an un-captured `Date.now()`.
    clock: Arc<dyn Clock>,
    /// Per-context participant state, keyed by context id.
    contexts: HashMap<String, PerContextState>,
    /// Retained join material per context id, between key-package generation
    /// and Welcome processing.
    pending_joins: HashMap<String, PendingJoin>,
}

impl ScpClient {
    /// Constructs a participant driver with the given on-device identity,
    /// storage backend, and hardened clock.
    #[must_use]
    pub fn new(signer: Arc<dyn Signer>, storage: Arc<dyn Storage>, clock: Arc<dyn Clock>) -> Self {
        Self {
            signer,
            storage,
            clock,
            contexts: HashMap::new(),
            pending_joins: HashMap::new(),
        }
    }

    /// This participant's DID.
    #[must_use]
    pub fn did(&self) -> &str {
        self.signer.did()
    }

    /// Builds an [`ScpCredential`] for this participant's identity.
    fn credential(&self) -> Result<ScpCredential, ClientError> {
        Ok(ScpCredential::new(
            self.signer.did().to_owned(),
            None,
            self.signer.signing_key_id(),
        )?)
    }

    /// Returns the per-context state, or [`ClientError::UnknownContext`].
    fn context_mut(&mut self, context_id: &str) -> Result<&mut PerContextState, ClientError> {
        self.contexts
            .get_mut(context_id)
            .ok_or_else(|| ClientError::UnknownContext(context_id.to_owned()))
    }

    // ----------------------------------------------------------------------
    // Lifecycle
    // ----------------------------------------------------------------------

    /// Creates a new encrypted context with this participant as sole member.
    ///
    /// Builds the MLS group (creator-only), seeds the §9.16 crypto state, and
    /// appends the first event-log leaf (`ContextCreated`) stamped with the
    /// creator's convergent creation timestamp.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::ContextAlreadyExists`] if the id is already held,
    /// or an [`ClientError::Mls`] / [`ClientError::EventLog`] if group creation
    /// or the leaf append fails.
    pub fn create_context(&mut self, context_id: &str) -> Result<(), ClientError> {
        if self.contexts.contains_key(context_id) {
            return Err(ClientError::ContextAlreadyExists(context_id.to_owned()));
        }
        let credential = self.credential()?;
        let mls_group = create_group(&credential)?;
        let crypto = ContextCryptoState::from_group(context_id, mls_group);
        let creator_did = self.signer.did().to_owned();
        let mut state = PerContextState::new(context_id, &creator_did, crypto);

        // Convergent creation timestamp: the creator stamps it once; peers copy
        // it when they import context state (a later slice). Here the creator is
        // the only member, so it is simply this client's clock reading.
        let created_at = self.clock.now_secs();
        state.append_log_event(
            EventType::ContextCreated,
            &creator_did,
            Vec::new(),
            created_at,
        )?;

        self.contexts.insert(context_id.to_owned(), state);
        Ok(())
    }

    /// Generates a single-use `KeyPackage` so this participant can be added to
    /// `context_id` by an existing member.
    ///
    /// Returns the TLS-serialized public `KeyPackage` bytes to hand to the
    /// adder. The matching private join material (signer + provider) is retained
    /// internally, keyed by `context_id`, and consumed by
    /// [`Self::join_context_encrypted`] when the Welcome arrives. Calling this
    /// again for the same context replaces the prior pending material.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Mls`] if key-package generation fails, or
    /// [`ClientError::Codec`] if the public key package cannot be serialized.
    pub fn generate_key_package_for_join(
        &mut self,
        context_id: &str,
    ) -> Result<Vec<u8>, ClientError> {
        let credential = self.credential()?;
        let (bundle, signer, provider): (KeyPackageBundle, _, InMemoryMlsProvider) =
            generate_key_package(&credential)?;

        let kp_bytes = bundle
            .key_package()
            .tls_serialize_detached()
            .map_err(|e| ClientError::Codec(format!("serializing key package: {e}")))?;

        self.pending_joins
            .insert(context_id.to_owned(), PendingJoin { signer, provider });

        Ok(kp_bytes)
    }

    /// Adds a member to `context_id` from their serialized `KeyPackage`.
    ///
    /// Produces the MLS Commit (for existing members) and Welcome (for the new
    /// member), records the new member in the membership set, and appends a
    /// `MemberJoined` event-log leaf. The new member's DID is recovered from the
    /// key package's embedded SCP credential, so the caller does not supply it
    /// separately.
    ///
    /// The returned [`AddMemberOutput`] carries the adder's full event-log
    /// stream and membership snapshot so the joiner can replay them and converge
    /// to the same Merkle root (§7.3.1 context-state import).
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::UnknownContext`] if the context is not held,
    /// [`ClientError::Codec`] if the key package cannot be deserialized, or
    /// [`ClientError::Mls`] / [`ClientError::EventLog`] on MLS or leaf failure.
    pub fn add_member(
        &mut self,
        context_id: &str,
        key_package_bytes: &[u8],
    ) -> Result<AddMemberOutput, ClientError> {
        let new_member_did = key_package_member_did(key_package_bytes)?;
        let timestamp = self.clock.now_secs();
        let committer_did = self.signer.did().to_owned();

        let state = self.context_mut(context_id)?;

        let key_package_in = KeyPackageIn::tls_deserialize(&mut &*key_package_bytes)
            .map_err(|e| ClientError::Codec(format!("deserializing key package: {e}")))?;

        let result = add_member(&mut state.crypto.mls_group, key_package_in)?;
        let commit = serialize_message(&result.commit)?;
        let welcome = serialize_message(&result.welcome)?;

        state.add_member_record(&new_member_did);
        state.append_log_event(
            EventType::MemberJoined,
            &committer_did,
            Vec::new(),
            timestamp,
        )?;

        Ok(AddMemberOutput {
            commit,
            welcome,
            committer_timestamp_secs: timestamp,
            event_log: state.events(),
            members: state.members.clone(),
        })
    }

    /// Joins `context_id` from a Welcome message, becoming an active member.
    ///
    /// Consumes the pending join material retained by a prior
    /// [`Self::generate_key_package_for_join`] for this context, processes the
    /// Welcome into an [`scp_mls::ScpMlsGroup`], builds the §9.16 crypto state,
    /// and **replays the adder's event-log stream verbatim** so the joiner's log
    /// is byte-identical to the adder's and converges to the same Merkle root
    /// (§7.3.1, §9.9.3). The joiner does not synthesize its own join leaf — it
    /// adopts the adder's, which already records the join.
    ///
    /// `prior_event_log` is [`AddMemberOutput::event_log`] from the adder;
    /// `members` is [`AddMemberOutput::members`]. Both travel alongside the
    /// Welcome.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Driver`] if there is no pending join material for
    /// the context, [`ClientError::ContextAlreadyExists`] if already joined, or
    /// [`ClientError::Mls`] / [`ClientError::EventLog`] on Welcome processing or
    /// replay failure (a replay stream that does not chain cleanly is rejected).
    pub fn join_context_encrypted(
        &mut self,
        context_id: &str,
        welcome_bytes: &[u8],
        prior_event_log: &[Event],
        members: &[String],
    ) -> Result<(), ClientError> {
        if self.contexts.contains_key(context_id) {
            return Err(ClientError::ContextAlreadyExists(context_id.to_owned()));
        }
        let pending = self.pending_joins.remove(context_id).ok_or_else(|| {
            ClientError::Driver(format!(
                "no pending key package for context '{context_id}'; call \
                 generate_key_package_for_join first"
            ))
        })?;

        // `join_group_from_bytes` is the wire-path variant: it deserializes the
        // Welcome (as `MlsMessageIn`) internally, so the driver never has to
        // name the inbound MLS message type.
        let mls_group = join_group_from_bytes(welcome_bytes, pending.provider, pending.signer)?;
        let crypto = ContextCryptoState::from_group(context_id, mls_group);
        let self_did = self.signer.did().to_owned();

        // Start from an EMPTY log and replay the adder's stream verbatim, so the
        // joiner reconstructs a byte-identical log (identical leaves, identical
        // root) rather than synthesizing fresh leaves at the wrong positions.
        let mut state = PerContextState::new_empty(context_id, crypto);
        for event in prior_event_log {
            state.replay_event(event)?;
        }

        // Adopt the adder's membership snapshot; ensure self is present.
        for member in members {
            state.add_member_record(member);
        }
        state.add_member_record(&self_did);

        self.contexts.insert(context_id.to_owned(), state);
        Ok(())
    }

    // ----------------------------------------------------------------------
    // Message path
    // ----------------------------------------------------------------------

    /// Encrypts and "sends" an application message in `context_id`.
    ///
    /// Runs the full §9.16 double-encryption pipeline, appends a `MessageSent`
    /// event-log leaf (committer = this sender, convergent timestamp = this
    /// sender's clock reading, which every recipient copies onto their
    /// `MessageReceived`-driven leaf), increments this sender's sequence, and
    /// returns the wire ciphertext for the transport to deliver to peers.
    ///
    /// There is no relay in the MVP; the returned bytes are handed directly to
    /// recipients' [`Self::receive_message`] by the test harness "dumb pipe".
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::UnknownContext`] if the context is not held, or
    /// [`ClientError::Mls`] / [`ClientError::SenderKey`] /
    /// [`ClientError::EventLog`] on a layer failure.
    pub fn send_message(
        &mut self,
        context_id: &str,
        plaintext: &[u8],
    ) -> Result<SendOutput, ClientError> {
        let sender_did = self.signer.did().to_owned();
        let timestamp = self.clock.now_secs();
        let state = self.context_mut(context_id)?;

        let sequence = state.next_sequence(&sender_did);
        let ciphertext = state
            .crypto
            .encrypt_message(plaintext, &sender_did, sequence)?;

        state.append_log_event(EventType::MessageSent, &sender_did, Vec::new(), timestamp)?;

        Ok(SendOutput {
            ciphertext,
            committer_timestamp_secs: timestamp,
        })
    }

    /// Receives an inbound MLS message in `context_id`: decrypts an application
    /// message, or applies a membership-changing Commit, converging the event
    /// log either way.
    ///
    /// - **Application message** → produces a `MessageReceived` event (buffered
    ///   for [`Self::drain_events`]) and appends a `MessageSent` leaf stamped
    ///   with the supplied `committer_timestamp_secs`, so the receiver's log
    ///   converges with the sender's. Returns `true`.
    /// - **Membership-changing Commit (add)** → advances the MLS epoch and, for
    ///   each member the Commit adds, appends the SAME convergent
    ///   `MemberJoined` leaf the committer appended — committer DID + the
    ///   transported `committer_timestamp_secs` ([`AddMemberOutput::committer_timestamp_secs`])
    ///   — and records the added member. This is what makes an EXISTING member's
    ///   log and membership set converge with the committer's and the new
    ///   joiner's in a multi-party context (§9.9.3). Returns `false` (no
    ///   application payload was produced).
    /// - **Bare proposal** → cached by `scp-mls`; no leaf, returns `false`.
    ///
    /// `committer_timestamp_secs` is the convergent timestamp the committer
    /// stamped: on a `MessageSent` leaf for an application message
    /// ([`SendOutput::committer_timestamp_secs`]), or on the `MemberJoined`
    /// leaf for an add Commit ([`AddMemberOutput::committer_timestamp_secs`]).
    ///
    // SECURITY (ADR-057, leaf-signing/custody slice): `committer_timestamp_secs`
    // is presently an UNAUTHENTICATED value transported alongside the ciphertext.
    // It is NOT bound to the MLS ciphertext (it is not part of the §9.16 AEAD
    // AAD) and the event-log leaves it stamps are unsigned, so a hostile relay
    // (or any in-path attacker) could forge or alter it and drive this receiver's
    // `MessageSent` / `MemberJoined` leaf — and thus its Merkle root — away from
    // the honest committer's, breaking convergence. The MVP "dumb pipe" is a
    // trusted in-process test harness, so this is acceptable ONLY until a real
    // relay/transport is wired. Before that wiring, this timestamp MUST be bound
    // into a signed leaf or a signed transport envelope (so a recipient verifies
    // the committer's signature over the timestamp) rather than trusted on the
    // wire.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::UnknownContext`] if the context is not held,
    /// [`ClientError::UnsupportedMembershipChange`] if the Commit removes a
    /// member (Slice 2 has no convergent removal-leaf transport). In that case
    /// `scp-mls` rejected the Commit *before* merging, so the context's MLS
    /// epoch, SCP membership, and event log are left mutually consistent
    /// (pre-remove) and the context stays usable — the driver surfaces the gap
    /// rather than half-applying it. Otherwise returns a crypto/leaf error on
    /// failure.
    pub fn receive_message(
        &mut self,
        context_id: &str,
        ciphertext: &[u8],
        committer_timestamp_secs: u64,
    ) -> Result<bool, ClientError> {
        let state = self.context_mut(context_id)?;
        match state.crypto.decrypt_message(ciphertext)? {
            Inbound::Application {
                sender_did,
                plaintext,
            } => {
                state.append_log_event(
                    EventType::MessageSent,
                    &sender_did,
                    Vec::new(),
                    committer_timestamp_secs,
                )?;
                state.push_event(ContextEvent::MessageReceived {
                    sender_did: sender_did.into(),
                    payload: plaintext,
                });
                Ok(true)
            }
            Inbound::UnsupportedMembershipChange {
                sender_did: _committer_did,
                removed_dids,
            } => {
                // Slice 2 is the participant add path. A Commit that EVICTS a
                // member has no convergent removal-leaf transport yet (there is
                // no committer-side op that stamps a `MemberLeft` leaf with a
                // convergent timestamp to transport, the way `add_member`
                // transports one for adds). Merging it while dropping the
                // membership leaf would silently diverge this member's log from
                // the committer's — exactly the bug this method fixes for adds.
                //
                // FAIL-CLOSED WITHOUT SKEW: `scp-mls` already REJECTED this
                // Commit *before* merging (it inspected the staged commit's
                // Remove proposals and dropped the StagedCommit), so the MLS
                // group is still on its pre-Commit epoch and this context's MLS
                // state, SCP membership set, and event log all remain mutually
                // consistent (pre-remove). The context is left fully usable; we
                // simply surface the gap to the caller rather than silently
                // diverging. The caller may keep using the context on the old
                // epoch.
                Err(ClientError::UnsupportedMembershipChange(format!(
                    "received a Commit removing {} member(s) ({}); convergent \
                     removal is out of ADR-057 Slice 2 scope",
                    removed_dids.len(),
                    removed_dids.join(", ")
                )))
            }
            Inbound::Commit {
                sender_did: committer_did,
                added_dids,
            } => {
                // For each added member, append the identical convergent
                // `MemberJoined` leaf the committer appended: actor = committer
                // DID, timestamp = transported convergent T, empty payload. The
                // sequence + prev_hash are recomputed from this member's
                // current log, which (by the convergence invariant) is at the
                // same state the committer's was before the add — so the leaf is
                // byte-identical. Then record the member in the membership set.
                for added_did in &added_dids {
                    state.append_log_event(
                        EventType::MemberJoined,
                        &committer_did,
                        Vec::new(),
                        committer_timestamp_secs,
                    )?;
                    state.add_member_record(added_did);
                }
                Ok(false)
            }
            Inbound::Proposal { .. } => Ok(false),
        }
    }

    /// Drains all buffered receive events for `context_id` in FIFO order.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::UnknownContext`] if the context is not held.
    pub fn drain_events(&mut self, context_id: &str) -> Result<Vec<ContextEvent>, ClientError> {
        Ok(self.context_mut(context_id)?.drain_events())
    }

    /// Closes and removes `context_id`, destroying its crypto state.
    ///
    /// Destroying the MLS group releases the group key schedule, after which no
    /// further message in this context can be decrypted by this participant
    /// (forward secrecy — ADR-057 lose-device-lose-history). Returns
    /// [`ClientError::UnknownContext`] if the context is not held.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::UnknownContext`] if the context is not held.
    pub fn close_context(&mut self, context_id: &str) -> Result<(), ClientError> {
        let mut state = self
            .contexts
            .remove(context_id)
            .ok_or_else(|| ClientError::UnknownContext(context_id.to_owned()))?;
        destroy_group(&mut state.crypto.mls_group)?;
        self.pending_joins.remove(context_id);
        Ok(())
    }

    // ----------------------------------------------------------------------
    // Sender-key exchange (out-of-band — see crate root MISSING SEAM note)
    // ----------------------------------------------------------------------

    /// Returns this participant's local sender-key bytes for `context_id`.
    ///
    /// The driver has no in-tab cross-member sender-key distribution path (a
    /// pre-existing gap inherited from the deleted bridge; ADR-057 defers
    /// HPKE-sealed distribution over the MLS `scp_wrapping_key` extension to a
    /// later slice). For the MVP the caller hands these bytes to peers
    /// out-of-band and they install them via [`Self::install_sender_key`].
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::UnknownContext`] if the context is not held.
    pub fn local_sender_key_bytes(&self, context_id: &str) -> Result<[u8; 32], ClientError> {
        self.contexts
            .get(context_id)
            .map(|s| s.crypto.local_sender_key_bytes())
            .ok_or_else(|| ClientError::UnknownContext(context_id.to_owned()))
    }

    /// Installs a peer's sender key for `context_id` (received out-of-band).
    ///
    /// See [`Self::local_sender_key_bytes`] for why distribution is out-of-band
    /// in the MVP.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::UnknownContext`] if the context is not held.
    pub fn install_sender_key(
        &mut self,
        context_id: &str,
        sender_did: &str,
        key_bytes: [u8; 32],
    ) -> Result<(), ClientError> {
        let state = self.context_mut(context_id)?;
        state
            .crypto
            .insert_sender_key(sender_did, SenderKey::from_bytes(key_bytes));
        Ok(())
    }

    // ----------------------------------------------------------------------
    // Queries
    // ----------------------------------------------------------------------

    /// Returns the member DIDs of `context_id`, or `None` if not held.
    #[must_use]
    pub fn member_dids(&self, context_id: &str) -> Option<Vec<String>> {
        self.contexts.get(context_id).map(|s| s.members.clone())
    }

    /// Returns the event-log Merkle root for `context_id`, or `None` if not held.
    #[must_use]
    pub fn event_log_root(&self, context_id: &str) -> Option<[u8; 32]> {
        self.contexts
            .get(context_id)
            .map(PerContextState::event_log_root)
    }

    /// Returns the event-log leaf count for `context_id`, or `None` if not held.
    #[must_use]
    pub fn event_log_leaf_count(&self, context_id: &str) -> Option<u64> {
        self.contexts
            .get(context_id)
            .map(PerContextState::event_log_leaf_count)
    }

    /// Returns the event-log leaf hashes (sequence order) for `context_id`, or
    /// `None` if not held.
    ///
    /// Used to assert the §9.9.3 per-leaf convergence property: two members'
    /// leaves for the same logical event are byte-identical.
    #[must_use]
    pub fn event_log_leaf_hashes(&self, context_id: &str) -> Option<Vec<[u8; 32]>> {
        self.contexts
            .get(context_id)
            .map(PerContextState::event_log_leaf_hashes)
    }

    /// Returns the MLS group epoch for `context_id`.
    ///
    /// The MLS epoch advances on every applied Commit. It is exposed so callers
    /// (and convergence/consistency tests) can observe that the MLS layer and the
    /// SCP layer stay in step — e.g. that a rejected (Remove-bearing) Commit did
    /// NOT half-advance the epoch while leaving membership/log behind.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::UnknownContext`] if the context is not held, or
    /// [`ClientError::Mls`] if the MLS group has been destroyed.
    pub fn mls_epoch(&self, context_id: &str) -> Result<u64, ClientError> {
        let state = self
            .contexts
            .get(context_id)
            .ok_or_else(|| ClientError::UnknownContext(context_id.to_owned()))?;
        Ok(state.crypto.mls_group.epoch()?)
    }
}

/// Serializes an MLS message to wire bytes.
fn serialize_message(message: &MlsMessageOut) -> Result<Vec<u8>, ClientError> {
    message
        .tls_serialize_detached()
        .map_err(|e| ClientError::Codec(format!("serializing MLS message: {e}")))
}

/// Recovers the SCP DID embedded in a serialized key package's leaf credential.
///
/// The driver names the new member by reading their credential out of the key
/// package, rather than trusting a separately-supplied DID, so the membership
/// record and the MLS leaf cannot disagree.
fn key_package_member_did(key_package_bytes: &[u8]) -> Result<String, ClientError> {
    let key_package_in = KeyPackageIn::tls_deserialize(&mut &*key_package_bytes)
        .map_err(|e| ClientError::Codec(format!("deserializing key package: {e}")))?;
    let did = key_package_in_did(&key_package_in, ProtocolVersion::Mls10)?;
    Ok(did)
}
