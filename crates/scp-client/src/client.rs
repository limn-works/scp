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
use scp_clock::Clock;
use scp_event_log::{Event, EventType};
use scp_mls::group::{
    add_member_with_convergent_timestamp, create_group, destroy_group, generate_key_package,
    join_group_from_bytes, key_package_in_did,
};
use scp_mls::{
    InMemoryMlsProvider, ScpCredential, SignatureKeyPair, restore_pending_join,
    serialize_pending_join,
};
use scp_protocol::context::membership::ContextEvent;
use scp_protocol::crypto::sender_keys::SenderKey;
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};

use crate::context::PerContextState;
use crate::crypto_state::{ContextCryptoState, Inbound};
use crate::error::ClientError;
use crate::signer::Signer;
use crate::snapshot::ContextSnapshot;
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

/// The result of adding a member: the wire bytes the driver must distribute.
///
/// `commit` goes to all *existing* members. They apply it via
/// [`ScpClient::receive_message`], which classifies it as a membership-changing
/// Commit, advances their MLS epoch, and appends the identical `MemberJoined`
/// leaf so their event log and membership set converge with the committer's and
/// the joiner's. The convergent committer timestamp each existing member stamps
/// on that leaf is **bound into the Commit's authenticated MLS AAD** (ADR-057
///) — covered by the committer's leaf signature and the `PrivateMessage`
/// AEAD tag — so a receiver recovers it from the *verified* frame rather than a
/// loose transported `u64` a relay could forge. It is therefore no longer
/// carried as a separate field here.
///
/// `welcome` goes to the *new* member, who applies it via
/// [`ScpClient::join_context_encrypted`] and replays `event_log` (which already
/// contains the committer-stamped `MemberJoined` leaf), so the joiner's log is
/// byte-identical to the committer's.
#[derive(Debug, Clone)]
pub struct AddMemberOutput {
    /// TLS-serialized MLS Commit for existing members. Its authenticated AAD
    /// carries the convergent committer timestamp (ADR-057).
    pub commit: Vec<u8>,
    /// TLS-serialized MLS Welcome for the new member.
    pub welcome: Vec<u8>,
    /// The adder's full event-log stream AFTER the add (the prior context
    /// history plus the new `MemberJoined` leaf). The joiner replays this
    /// verbatim to reconstruct a byte-identical log and converge to the same
    /// Merkle root (§7.3.1 context-state import, §9.9.3 convergence).
    pub event_log: Vec<Event>,
    /// The adder's membership set after the add. The joiner adopts it so both
    /// sides agree on who is in the context without re-deriving it.
    pub members: Vec<String>,
}

/// The lifecycle status of a context id, as reported by
/// [`ScpClient::context_status`].
///
/// This is the **non-throwing predicate form** of the poison guard. The mutating
/// ops and the `Result`-returning queries raise [`ClientError::ContextPoisoned`]
/// on a diverged context, and the `Option`-returning observers report a poisoned
/// context as `None` (indistinguishable from absent); this enum instead lets a
/// caller distinguish all three states — usable, needs-reconstruction, and
/// unknown — and pick the right terminal path for a poisoned context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextStatus {
    /// The context is held and its durable and in-memory state agree: every op is
    /// available.
    Live,
    /// The context is held but **poisoned** — a persist failed after its in-memory
    /// state advanced irreversibly, so durable and live state diverged. Every
    /// mutating op (and every `Result`-returning query) refuses it with
    /// [`ClientError::ContextPoisoned`]. Two mutually-exclusive terminal paths:
    /// **RECOVER** (discard this client and rebuild via [`ScpClient::new`] from the
    /// last durable snapshot) or **ABANDON** ([`ScpClient::close_context`], which
    /// deletes the durable snapshot and permanently forfeits recovery). See
    /// [`ClientError::ContextPoisoned`].
    Poisoned,
    /// No context with this id is held by this client — it was never created or
    /// joined, or it was closed.
    Absent,
}

/// The single-threaded SCP participant driver.
pub struct ScpClient {
    /// This participant's on-device DID identity.
    signer: Arc<dyn Signer>,
    /// Out-of-band snapshot storage (`IndexedDB`/OPFS in a browser; in-memory
    /// here). The driver writes one participant snapshot (and one pending-join
    /// blob) per context here after each state-mutating op, and restores them all
    /// by key-prefix enumeration in [`Self::new`] when a tab reopens (ADR-057 T2).
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
    /// Constructs a participant driver, restoring any persisted state.
    ///
    /// Takes the on-device identity, storage backend, and hardened clock, and
    /// **restores** any contexts and pending joins the backend holds for this
    /// identity (ADR-057 T2).
    ///
    /// This is the single canonical constructor and the ONLY restore path: a
    /// browser tab reopening reconstructs its live state here, from the durable
    /// snapshots the driver wrote after each mutating op. An empty store yields a
    /// fresh client — there is no separate "load" call and no boolean to check.
    ///
    /// Restore is **atomic and fails closed**: every persisted context and pending
    /// join is reconstructed and checkpoint/owner-verified before any is installed;
    /// a single corrupt or foreign snapshot fails the whole construction, so a
    /// caller never observes a half-restored client.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::StorageBackend`] if the backend enumeration/read
    /// fails, [`ClientError::StorageCorrupt`] if a persisted snapshot is corrupt,
    /// truncated, an unknown version, or fails its §9.9.3 checkpoint,
    /// [`ClientError::StorageIdentityMismatch`] if a snapshot belongs to a
    /// different identity, or [`ClientError::Mls`] / [`ClientError::EventLog`] if
    /// the crypto/event-log state cannot be reconstructed.
    pub fn new(
        signer: Arc<dyn Signer>,
        storage: Arc<dyn Storage>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, ClientError> {
        let mut client = Self {
            signer,
            storage,
            clock,
            contexts: HashMap::new(),
            pending_joins: HashMap::new(),
        };
        client.restore_from_storage()?;
        Ok(client)
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

    /// Returns the per-context state for a *live* (non-poisoned) context, or an
    /// error.
    ///
    /// This is the accessor every state-mutating op routes through, so the poison
    /// guard is enforced in exactly one place: a context whose durable state
    /// diverged from its in-memory state (a persist failed after the ratchet
    /// advanced) is refused with [`ClientError::ContextPoisoned`] rather than
    /// advanced or exposed further. Returns [`ClientError::UnknownContext`] if the
    /// context is not held. ([`Self::close_context`] deliberately does NOT go
    /// through here — closing a poisoned context is the safe escape hatch.)
    fn context_mut(&mut self, context_id: &str) -> Result<&mut PerContextState, ClientError> {
        let state = self
            .contexts
            .get_mut(context_id)
            .ok_or_else(|| ClientError::UnknownContext(context_id.to_owned()))?;
        if state.poisoned {
            return Err(ClientError::ContextPoisoned {
                context_id: context_id.to_owned(),
            });
        }
        Ok(state)
    }

    /// Returns a shared reference to a *live* (non-poisoned) context, or an error.
    ///
    /// The read-path twin of [`Self::context_mut`]: [`ClientError::UnknownContext`]
    /// if the context is not held, [`ClientError::ContextPoisoned`] if it diverged.
    /// Used by the `Result`-returning queries so a poisoned context surfaces the
    /// loud diagnostic.
    fn context_ref(&self, context_id: &str) -> Result<&PerContextState, ClientError> {
        let state = self
            .contexts
            .get(context_id)
            .ok_or_else(|| ClientError::UnknownContext(context_id.to_owned()))?;
        if state.poisoned {
            return Err(ClientError::ContextPoisoned {
                context_id: context_id.to_owned(),
            });
        }
        Ok(state)
    }

    /// Returns a *live* context for an `Option`-returning pure observer: `None`
    /// for both "not held" and "poisoned".
    ///
    /// A poisoned context has no trustworthy state to report to a pure observer —
    /// its in-memory root / members / counts reflect an advance that never reached
    /// durable storage — so it reports as absent here rather than handing back
    /// misleading state. The loud [`ClientError::ContextPoisoned`] diagnostic is
    /// delivered by every `Result`-returning op (mutating ops, [`Self::mls_epoch`],
    /// [`Self::local_sender_key_bytes`]) instead.
    fn live_context_ref(&self, context_id: &str) -> Option<&PerContextState> {
        self.contexts.get(context_id).filter(|s| !s.poisoned)
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
    /// or the leaf append fails. A [`ClientError::StorageBackend`] from the
    /// initial persist **poisons** the freshly-created context (its in-memory
    /// state exists but was never durably recorded); reconstruct via [`Self::new`].
    pub fn create_context(&mut self, context_id: &str) -> Result<(), ClientError> {
        if self.contexts.contains_key(context_id) {
            return Err(ClientError::ContextAlreadyExists(context_id.to_owned()));
        }
        let credential = self.credential()?;
        // ADR-057 §Prereq-1: the creator's own MLS leaf `Lifetime` is stamped
        // from the hardened driver clock, not openmls's internal one.
        let mls_group = create_group(&credential, self.clock.as_ref())?;
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
        self.persist_context(context_id)?;
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
    /// Returns [`ClientError::Mls`] if key-package generation or pending-material
    /// serialization fails, [`ClientError::Codec`] if the public key package
    /// cannot be serialized, or [`ClientError::StorageBackend`] if persisting the
    /// pending-join blob fails.
    pub fn generate_key_package_for_join(
        &mut self,
        context_id: &str,
    ) -> Result<Vec<u8>, ClientError> {
        let credential = self.credential()?;
        // ADR-057 §Prereq-1: the published KeyPackage `Lifetime` is stamped from
        // the hardened driver clock, not openmls's internal one.
        let (bundle, signer, provider): (KeyPackageBundle, _, InMemoryMlsProvider) =
            generate_key_package(&credential, self.clock.as_ref())?;

        let kp_bytes = bundle
            .key_package()
            .tls_serialize_detached()
            .map_err(|e| ClientError::Codec(format!("serializing key package: {e}")))?;

        // Persist the pending-join material (the private KeyPackage half) BEFORE
        // returning the public key package, so a crash after handing the KP to the
        // adder but before persistence cannot orphan the join — a reopened tab
        // restores this pending material and can still complete the join.
        //
        // The blob is bound to BOTH this client's DID and the context id, so a
        // swapped pending blob cannot silently drive this identity into a group
        // under another leaf, nor bind this key package to the wrong context. The
        // bindings are verified on restore ([`Self::restore_from_storage`]).
        let pending_blob =
            serialize_pending_join(&provider, &signer, self.signer.did(), context_id)?;
        self.storage
            .put(&Self::pending_key(context_id), pending_blob)
            .map_err(|e| {
                ClientError::StorageBackend(format!(
                    "persisting pending join for context '{context_id}': {e}"
                ))
            })?;

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
    /// [`ClientError::ContextPoisoned`] if the context has been poisoned by a
    /// prior failed persist, [`ClientError::Codec`] if the key package cannot be
    /// deserialized, or [`ClientError::Mls`] / [`ClientError::EventLog`] on MLS or
    /// leaf failure. A [`ClientError::StorageBackend`] from the post-add persist
    /// **poisons** the context.
    pub fn add_member(
        &mut self,
        context_id: &str,
        key_package_bytes: &[u8],
    ) -> Result<AddMemberOutput, ClientError> {
        // ADR-057 §Prereq-1: validate the joiner's KeyPackage `Lifetime` against
        // the hardened driver clock. Captured as an `Arc` clone before the
        // `state` mutable borrow below, so the clock reference and the mutable
        // context borrow do not alias `self` simultaneously.
        let clock = Arc::clone(&self.clock);
        let new_member_did = key_package_member_did(key_package_bytes, clock.as_ref())?;
        let timestamp = self.clock.now_secs();
        let committer_did = self.signer.did().to_owned();

        let state = self.context_mut(context_id)?;

        let key_package_in = KeyPackageIn::tls_deserialize(&mut &*key_package_bytes)
            .map_err(|e| ClientError::Codec(format!("deserializing key package: {e}")))?;

        // ADR-057: bind the convergent committer timestamp into the
        // Commit's authenticated MLS AAD, so existing members recover the SAME
        // value from the verified frame and stamp a byte-identical `MemberJoined`
        // leaf — rather than trusting a loose transported `u64` a relay could
        // forge. The identical `timestamp` is stamped on the committer's own leaf
        // just below.
        let result = add_member_with_convergent_timestamp(
            &mut state.crypto.mls_group,
            key_package_in,
            clock.as_ref(),
            timestamp,
        )?;
        let commit = serialize_message(&result.commit)?;
        let welcome = serialize_message(&result.welcome)?;

        state.add_member_record(&new_member_did);
        state.append_log_event(
            EventType::MemberJoined,
            &committer_did,
            Vec::new(),
            timestamp,
        )?;

        let output = AddMemberOutput {
            commit,
            welcome,
            event_log: state.events(),
            members: state.members.clone(),
        };
        // The `state` borrow ends above (the output owns clones), so the snapshot
        // write can re-borrow `self`. Persist the post-add state (new MLS epoch,
        // membership, MemberJoined leaf) before returning.
        self.persist_context(context_id)?;
        Ok(output)
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
    /// the context, [`ClientError::ContextAlreadyExists`] if already joined,
    /// [`ClientError::Mls`] / [`ClientError::EventLog`] on Welcome processing or
    /// replay failure (a replay stream that does not chain cleanly is rejected),
    /// or [`ClientError::StorageBackend`] if persisting the joined context or
    /// deleting the consumed pending blob fails. A persist failure **poisons** the
    /// freshly-joined context (its state advanced in memory but was not durably
    /// recorded); reconstruct via [`Self::new`], which restores the still-present
    /// pending material and lets the join be retried.
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
        // Persist the joined context FIRST, then delete the now-consumed pending
        // material. Ordering matters: a crash between the two leaves a durable
        // context plus a stale pending blob (harmless — the context already exists,
        // so restore skips the stale blob and `close_context` clears it), never a
        // consumed KeyPackage with no context to show for it.
        self.persist_context(context_id)?;
        self.storage
            .delete(&Self::pending_key(context_id))
            .map_err(|e| {
                ClientError::StorageBackend(format!(
                    "deleting consumed pending join for context '{context_id}': {e}"
                ))
            })?;
        Ok(())
    }

    // ----------------------------------------------------------------------
    // Message path
    // ----------------------------------------------------------------------

    /// Encrypts and "sends" an application message in `context_id`, returning the
    /// wire ciphertext.
    ///
    /// Mints one convergent committer timestamp from this sender's hardened clock
    /// and uses it for BOTH sides of the convergence: it is stamped on this
    /// sender's own `MessageSent` leaf AND bound into the MLS ciphertext's
    /// authenticated AAD (ADR-057), so every recipient recovers the SAME
    /// value from the *verified* frame and stamps a byte-identical leaf. Runs the
    /// full §9.16 double-encryption pipeline, appends the `MessageSent` leaf,
    /// increments this sender's sequence, and returns the ciphertext for the
    /// transport to deliver to peers.
    ///
    /// There is no relay in the MVP; the returned bytes are handed directly to
    /// recipients' [`Self::receive_message`] by the test harness "dumb pipe".
    /// Because the convergent timestamp now rides *inside* the authenticated
    /// ciphertext, the recipient no longer needs (and no longer accepts) it as a
    /// separate transported value.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::UnknownContext`] if the context is not held,
    /// [`ClientError::ContextPoisoned`] if the context has been poisoned by a
    /// prior failed persist, or [`ClientError::Mls`] / [`ClientError::SenderKey`] /
    /// [`ClientError::EventLog`] on a layer failure. A [`ClientError::StorageBackend`]
    /// from the post-send persist **poisons** the context: the message's state
    /// advanced in memory but was not durably recorded, so `Err` (and thus no
    /// ciphertext) is returned and the context refuses further ops.
    pub fn send_message(
        &mut self,
        context_id: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ClientError> {
        let sender_did = self.signer.did().to_owned();
        // Mint the convergent timestamp ONCE: the same value is bound into the
        // ciphertext AAD (via `encrypt_message`) and stamped on the local leaf.
        let timestamp = self.clock.now_secs();
        let state = self.context_mut(context_id)?;

        let sequence = state.next_sequence(&sender_did);
        let ciphertext =
            state
                .crypto
                .encrypt_message(plaintext, &sender_did, sequence, timestamp)?;

        state.append_log_event(EventType::MessageSent, &sender_did, Vec::new(), timestamp)?;

        // The `state` borrow ends above; persist the post-send state (advanced
        // sender sequence + ratchet, new MessageSent leaf) before returning.
        self.persist_context(context_id)?;
        Ok(ciphertext)
    }

    /// Receives an inbound MLS message in `context_id`: decrypts an application
    /// message, or applies a membership-changing Commit, converging the event
    /// log either way.
    ///
    /// The convergent committer timestamp each leaf is stamped with is recovered
    /// from the message's own **authenticated** MLS AAD (ADR-057), not
    /// supplied by the caller — so this method takes only the ciphertext.
    ///
    /// - **Application message** → produces a `MessageReceived` event (buffered
    ///   for [`Self::drain_events`]) and appends a `MessageSent` leaf stamped with
    ///   the authenticated timestamp recovered from the frame, so the receiver's
    ///   log converges with the sender's. Returns `true`.
    /// - **Membership-changing Commit (add)** → advances the MLS epoch and, for
    ///   each member the Commit adds, appends the SAME convergent `MemberJoined`
    ///   leaf the committer appended — committer DID + the authenticated timestamp
    ///   recovered from the Commit AAD — and records the added member. This is
    ///   what makes an EXISTING member's log and membership set converge with the
    ///   committer's and the new joiner's in a multi-party context (§9.9.3).
    ///   Returns `false` (no application payload was produced).
    /// - **Bare proposal** → cached by `scp-mls`; no leaf, returns `false`.
    ///
    /// # Convergent-timestamp authentication (ADR-057)
    ///
    /// The timestamp stamped on each leaf is bound into the message's
    /// `FramedContent.authenticated_data` at send/commit time by the committer,
    /// and is covered by the committer's MLS leaf signature and — under the
    /// `PURE_CIPHERTEXT` policy — the `PrivateMessage` AEAD tag. `scp-mls`
    /// recovers it from openmls's *verified* `ProcessedMessage::aad()` (after
    /// signature + AEAD verification) and window-validates it against the injected
    /// clock before this method ever stamps a leaf. So the value is authenticated,
    /// not trusted on the wire: a hostile relay that alters it breaks the AEAD tag
    /// and the frame is rejected at decrypt, and no member other than the
    /// committer can author a frame carrying it. There is no loose transported
    /// `u64` left for an in-path attacker to forge.
    ///
    /// Two residuals remain, each out of this slice's scope:
    /// - **Joiner-trusts-adder replay.** A *new* joiner adopts the adder's
    ///   replayed event-log stream verbatim (via [`Self::join_context_encrypted`]);
    ///   independently re-verifying each historical leaf against a per-leaf
    ///   committer signature is the leaf-signing / custody slice, not this one.
    /// - **In-window authenticated committer lie.** The AAD binding proves *who*
    ///   authored the timestamp and the window proves it is *plausible*, but a
    ///   malicious *committer* can still bind a plausible-but-false value anywhere
    ///   inside the receiver's window. That is the pre-existing MLS
    ///   insider-equivocation class (a malicious committer can already fork
    ///   receivers by sending different commits to different members); the window
    ///   bounds it, it does not eliminate it.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::UnknownContext`] if the context is not held,
    /// [`ClientError::ContextPoisoned`] if the context has been poisoned by a
    /// prior failed persist,
    /// [`ClientError::UnsupportedMembershipChange`] if the Commit removes a
    /// member (Slice 2 has no convergent removal-leaf transport). In that case
    /// `scp-mls` rejected the Commit *before* merging, so the context's MLS
    /// epoch, SCP membership, and event log are left mutually consistent
    /// (pre-remove) and the context stays usable — the driver surfaces the gap
    /// rather than half-applying it. Returns [`ClientError::Mls`] wrapping a
    /// convergent-timestamp failure (missing / malformed / implausible AAD —
    /// ADR-057) if the frame carries no authenticated timestamp, a
    /// malformed one, or one outside the plausibility window; for an add-Commit
    /// this is raised *pre-merge*, so the epoch is unchanged. Otherwise returns a
    /// crypto/leaf error on failure. A [`ClientError::StorageBackend`] from the
    /// post-receive persist **poisons** the context (the decrypt already advanced
    /// the durable ratchet's in-memory counterpart, so the diverged state cannot
    /// be safely reused).
    pub fn receive_message(
        &mut self,
        context_id: &str,
        ciphertext: &[u8],
    ) -> Result<bool, ClientError> {
        // ADR-057 §Prereq-1: captured before the `state` mutable borrow so the
        // hardened clock (used to re-validate any add-Commit's KeyPackage
        // `Lifetime`) and the mutable context borrow do not alias `self`.
        let clock = Arc::clone(&self.clock);
        let state = self.context_mut(context_id)?;
        // Any successful `decrypt_message` mutates persistent MLS state — it
        // ratchets forward (application), merges a staged commit (add Commit), or
        // caches a proposal in the provider store. So every non-error outcome is
        // persisted after the `state` borrow ends. Only the rejected
        // Remove-bearing Commit (which `scp-mls` dropped BEFORE merging, leaving
        // MLS + SCP state unchanged) returns without a write.
        let application = match state.crypto.decrypt_message(ciphertext, clock.as_ref())? {
            Inbound::Application {
                sender_did,
                plaintext,
                committer_timestamp_secs,
            } => {
                // The timestamp is the authenticated value `scp-mls` recovered
                // from the frame's verified AAD (ADR-057) — not a caller
                // input — so the mirrored leaf converges with the sender's.
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
                true
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
                // epoch. No state changed, so no snapshot is written.
                return Err(ClientError::UnsupportedMembershipChange(format!(
                    "received a Commit removing {} member(s) ({}); convergent \
                     removal is out of ADR-057 Slice 2 scope",
                    removed_dids.len(),
                    removed_dids.join(", ")
                )));
            }
            Inbound::Commit {
                sender_did: committer_did,
                added_dids,
                committer_timestamp_secs,
            } => {
                // For each added member, append the identical convergent
                // `MemberJoined` leaf the committer appended: actor = committer
                // DID, timestamp = the authenticated convergent value `scp-mls`
                // recovered from the Commit's verified AAD (ADR-057), empty
                // payload. The sequence + prev_hash are recomputed from this
                // member's current log, which (by the convergence invariant) is
                // at the same state the committer's was before the add — so the
                // leaf is byte-identical. Then record the member in the
                // membership set.
                for added_did in &added_dids {
                    state.append_log_event(
                        EventType::MemberJoined,
                        &committer_did,
                        Vec::new(),
                        committer_timestamp_secs,
                    )?;
                    state.add_member_record(added_did);
                }
                false
            }
            Inbound::Proposal { .. } => false,
        };
        // `state` borrow ends above. Persist the mutated MLS/log/membership state.
        self.persist_context(context_id)?;
        Ok(application)
    }

    /// Drains all buffered receive events for `context_id` in FIFO order,
    /// persisting the now-emptied buffer.
    ///
    /// The receive buffer round-trips through the snapshot, so draining mutates
    /// persisted state: the emptied buffer is persisted before the events are
    /// returned, so a restore does not re-deliver already-drained messages. An
    /// empty drain changes nothing and skips the write.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::UnknownContext`] if the context is not held,
    /// [`ClientError::ContextPoisoned`] if the context has been poisoned by a
    /// prior failed persist, or [`ClientError::StorageBackend`] /
    /// [`ClientError::Mls`] if persisting the emptied buffer fails (which also
    /// **poisons** the context — the buffer was emptied in memory but the emptied
    /// state was not durably recorded, so a restore would re-deliver the drained
    /// messages).
    pub fn drain_events(&mut self, context_id: &str) -> Result<Vec<ContextEvent>, ClientError> {
        let events = self.context_mut(context_id)?.drain_events();
        if !events.is_empty() {
            self.persist_context(context_id)?;
        }
        Ok(events)
    }

    /// Closes and removes `context_id`, destroying its crypto state.
    ///
    /// Destroying the MLS group releases the group key schedule, after which no
    /// further message in this context can be decrypted by this participant
    /// (forward secrecy — ADR-057 lose-device-lose-history).
    ///
    /// # Close is ABANDON, not RECOVER
    ///
    /// For a **poisoned** context (see [`ClientError::ContextPoisoned`]) there are
    /// two mutually-exclusive terminal paths, and this method is the abandoning one:
    /// - **RECOVER** — discard this client and rebuild via [`ScpClient::new`] over
    ///   the same storage; restore rebuilds the context from its last *durable*
    ///   snapshot, unpoisoned by construction. The durable snapshot is preserved.
    /// - **ABANDON** — this method. It deletes the durable snapshot, so closing a
    ///   poisoned context **permanently forfeits recovery**: once closed there is
    ///   no last-durable state left to reconstruct from. Use it to deliberately
    ///   discard a diverged (or any) context.
    ///
    /// Closing is the safe escape hatch for a poisoned context: unlike every other
    /// op it does not go through the poison guard, so a diverged context can always
    /// be discarded and closed cleanly (the durable deletes are safe and idempotent
    /// regardless of poison).
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::UnknownContext`] if the context is not held, or
    /// [`ClientError::StorageBackend`] if deleting the pending-join blob or the
    /// persisted snapshot fails. On such a failure the in-memory context is left
    /// intact — still held, and still whatever it already was (live or poisoned) —
    /// and no crypto state is torn down, so the close can be retried. The delete
    /// ordering below ensures a partial failure preserves, rather than strands, the
    /// recoverable snapshot.
    pub fn close_context(&mut self, context_id: &str) -> Result<(), ClientError> {
        if !self.contexts.contains_key(context_id) {
            return Err(ClientError::UnknownContext(context_id.to_owned()));
        }
        // Delete the DURABLE state before touching in-memory state — a
        // forward-secrecy invariant: were the order reversed, a delete that failed
        // after the in-memory teardown would leave a context in-memory-gone but
        // still durably present, and a reopened tab would restore a "closed"
        // context. There is no manifest to update: restore enumerates by prefix, so
        // a deleted blob is simply never listed, and `delete` is idempotent, so a
        // retry after a partial failure is safe.
        //
        // Delete the pending-join blob FIRST and the context snapshot LAST. The
        // context snapshot is the recoverable state — the one [`Self::new`] restores
        // from — whereas the pending blob only matters for an unfinished join. If
        // the two deletes are not atomic and the first succeeds but the second
        // fails, this ordering leaves the *context snapshot* present, so a healthy
        // context stays recoverable and the caller can retry the close — rather than
        // deleting the recoverable snapshot first and then stranding the pending
        // blob with no snapshot. (A healthy context usually has no pending blob at
        // all, so its delete is a harmless idempotent no-op.)
        //
        // The non-resurrection guarantee is stated against the SYNCHRONOUS store
        // the driver sees. Under the browser write-behind model (see the
        // `scp-client-wasm` storage module docs) that store is an in-memory mirror
        // whose deletes are flushed to durable `IndexedDB` asynchronously; the
        // guarantee holds against the durable store ONLY if the embedder flushes in
        // FIFO order, so a crash cannot lose these deletes while keeping a later
        // write. That FIFO flush is the embedder's obligation, not something this
        // crate can enforce.
        self.storage
            .delete(&Self::pending_key(context_id))
            .map_err(|e| {
                ClientError::StorageBackend(format!(
                    "deleting pending join for context '{context_id}': {e}"
                ))
            })?;
        self.storage
            .delete(&Self::ctx_key(context_id))
            .map_err(|e| {
                ClientError::StorageBackend(format!(
                    "deleting snapshot for context '{context_id}': {e}"
                ))
            })?;
        // Durable state is gone; tear down in-memory state. Destroying the MLS
        // group releases the group key schedule, after which no further message in
        // this context can be decrypted by this participant (forward secrecy —
        // ADR-057 lose-device-lose-history).
        self.pending_joins.remove(context_id);
        if let Some(mut state) = self.contexts.remove(context_id) {
            destroy_group(&mut state.crypto.mls_group)?;
        }
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
    /// Returns [`ClientError::UnknownContext`] if the context is not held, or
    /// [`ClientError::ContextPoisoned`] if the context diverged.
    pub fn local_sender_key_bytes(&self, context_id: &str) -> Result<[u8; 32], ClientError> {
        Ok(self
            .context_ref(context_id)?
            .crypto
            .local_sender_key_bytes())
    }

    /// Installs a peer's sender key for `context_id` (received out-of-band).
    ///
    /// See [`Self::local_sender_key_bytes`] for why distribution is out-of-band
    /// in the MVP.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::UnknownContext`] if the context is not held,
    /// [`ClientError::ContextPoisoned`] if the context has been poisoned by a
    /// prior failed persist, or [`ClientError::StorageBackend`] if persisting the
    /// updated sender-key store fails (which also **poisons** the context).
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
        // `state` borrow ends; persist the updated sender-key store so a restored
        // client can still decrypt this peer's messages.
        self.persist_context(context_id)?;
        Ok(())
    }

    // ----------------------------------------------------------------------
    // Queries
    // ----------------------------------------------------------------------

    /// Returns the ids of every context this client holds (live and poisoned
    /// alike), sorted.
    ///
    /// A reopened tab uses this to list the conversations restore reconstructed
    /// from storage — without it, a fresh client would hold its restored contexts
    /// but expose no way to enumerate them. Poisoned contexts ARE listed (they are
    /// still held; the caller may need to see them to know a reconstruction is due),
    /// so this is the one query that does not filter poison.
    #[must_use]
    pub fn context_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.contexts.keys().cloned().collect();
        ids.sort();
        ids
    }

    /// Reports whether `context_id` is [`Live`](ContextStatus::Live),
    /// [`Poisoned`](ContextStatus::Poisoned), or [`Absent`](ContextStatus::Absent)
    /// — the non-throwing predicate form of the poison guard.
    ///
    /// Unlike the mutating ops and `Result`-returning queries (which raise
    /// [`ClientError::ContextPoisoned`] on a diverged context) and the `Option`
    /// observers (which collapse "poisoned" into `None`, indistinguishable from
    /// "absent"), this lets a caller cleanly branch on all three states — for
    /// example, to decide between RECOVER and ABANDON for a poisoned context (see
    /// [`ContextStatus`]) without provoking the error.
    #[must_use]
    pub fn context_status(&self, context_id: &str) -> ContextStatus {
        match self.contexts.get(context_id) {
            None => ContextStatus::Absent,
            Some(state) if state.poisoned => ContextStatus::Poisoned,
            Some(_) => ContextStatus::Live,
        }
    }

    /// Returns the member DIDs of `context_id`, or `None` if not held (or
    /// poisoned — see [`Self::live_context_ref`]).
    #[must_use]
    pub fn member_dids(&self, context_id: &str) -> Option<Vec<String>> {
        self.live_context_ref(context_id).map(|s| s.members.clone())
    }

    /// Returns the event-log Merkle root for `context_id`, or `None` if not held
    /// (or poisoned — see [`Self::live_context_ref`]).
    #[must_use]
    pub fn event_log_root(&self, context_id: &str) -> Option<[u8; 32]> {
        self.live_context_ref(context_id)
            .map(PerContextState::event_log_root)
    }

    /// Returns the event-log leaf count for `context_id`, or `None` if not held
    /// (or poisoned — see [`Self::live_context_ref`]).
    #[must_use]
    pub fn event_log_leaf_count(&self, context_id: &str) -> Option<u64> {
        self.live_context_ref(context_id)
            .map(PerContextState::event_log_leaf_count)
    }

    /// Returns the event-log leaf hashes (sequence order) for `context_id`, or
    /// `None` if not held (or poisoned — see [`Self::live_context_ref`]).
    ///
    /// Used to assert the §9.9.3 per-leaf convergence property: two members'
    /// leaves for the same logical event are byte-identical.
    #[must_use]
    pub fn event_log_leaf_hashes(&self, context_id: &str) -> Option<Vec<[u8; 32]>> {
        self.live_context_ref(context_id)
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
    /// Returns [`ClientError::UnknownContext`] if the context is not held,
    /// [`ClientError::ContextPoisoned`] if the context diverged, or
    /// [`ClientError::Mls`] if the MLS group has been destroyed.
    pub fn mls_epoch(&self, context_id: &str) -> Result<u64, ClientError> {
        let state = self.context_ref(context_id)?;
        Ok(state.crypto.mls_group.epoch()?)
    }

    // ----------------------------------------------------------------------
    // Persistence (ADR-057 T2 — snapshot/restore through the Storage backend)
    // ----------------------------------------------------------------------

    /// Key prefix for a context's participant snapshot blob. One blob per context
    /// is the atomicity unit (a single `put`); contexts are enumerated by this
    /// prefix on restore — there is no separate manifest to keep consistent.
    const CTX_KEY_PREFIX: &'static str = "scp-client/ctx/";

    /// Key prefix for a context's pending-join material blob (the private half of
    /// an unconsumed `KeyPackage`), retained between
    /// [`Self::generate_key_package_for_join`] and
    /// [`Self::join_context_encrypted`].
    const PENDING_KEY_PREFIX: &'static str = "scp-client/pending/";

    /// The storage key holding `context_id`'s participant snapshot.
    fn ctx_key(context_id: &str) -> String {
        format!("{}{context_id}", Self::CTX_KEY_PREFIX)
    }

    /// The storage key holding `context_id`'s pending-join material.
    fn pending_key(context_id: &str) -> String {
        format!("{}{context_id}", Self::PENDING_KEY_PREFIX)
    }

    /// Writes `context_id`'s current state to storage as a single snapshot blob,
    /// **poisoning the context** if the write fails.
    ///
    /// Called at the end of every state-mutating op — *after* the in-memory state
    /// has already advanced irreversibly (the MLS ratchet cannot be un-advanced,
    /// and the op has already appended its event-log leaf). The blob is one atomic
    /// `put`, so a crash leaves either the last committed snapshot or the prior one
    /// — never a torn intra-context state (ADR-057 crash-consistency). There is no
    /// manifest to keep in step: restore enumerates by key prefix.
    ///
    /// If persistence fails on ANY step (serialization or the backend write), the
    /// durable snapshot is now strictly older than the live in-memory state: the
    /// two have diverged. This method sets the context's poison flag before
    /// propagating the error, so every subsequent op refuses the diverged context
    /// with [`ClientError::ContextPoisoned`] rather than handing out ciphertext /
    /// leaves no peer or reopened tab will ever see. The caller recovers by
    /// reconstructing via [`Self::new`] from the last durable snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::UnknownContext`] if the context is not held,
    /// [`ClientError::Mls`] if the MLS state cannot be serialized,
    /// [`ClientError::StorageCorrupt`] if the snapshot cannot be serialized, or
    /// [`ClientError::StorageBackend`] if the backend write fails. Every failure
    /// but `UnknownContext` poisons the context.
    fn persist_context(&mut self, context_id: &str) -> Result<(), ClientError> {
        let outcome = self.build_and_put(context_id);
        if outcome.is_err() {
            // The persist failed AFTER the in-memory ratchet/leaf advanced.
            // Durable and live state have diverged — poison the context so no
            // further op can advance or expose the fork. (`UnknownContext` cannot
            // reach here for a real context, but the guard is harmless if it did.)
            if let Some(state) = self.contexts.get_mut(context_id) {
                state.poisoned = true;
            }
        }
        outcome
    }

    /// Serializes `context_id`'s current state and writes the single snapshot
    /// blob. The build/serialize happens inside a scope so the structured snapshot
    /// (with its key material) is zeroized on drop before the blob leaves for
    /// storage. Pure "do the write" half of [`Self::persist_context`]; the poison
    /// bookkeeping lives in the caller.
    fn build_and_put(&self, context_id: &str) -> Result<(), ClientError> {
        let blob = {
            let state = self
                .contexts
                .get(context_id)
                .ok_or_else(|| ClientError::UnknownContext(context_id.to_owned()))?;
            ContextSnapshot::capture(context_id, self.signer.did(), state)?.to_bytes()?
        };
        self.storage
            .put(&Self::ctx_key(context_id), blob)
            .map_err(|e| {
                ClientError::StorageBackend(format!("persisting context '{context_id}': {e}"))
            })
    }

    /// Reconstructs every persisted context and pending join for this identity
    /// into the freshly-constructed client. See [`Self::new`] for the atomicity
    /// and fail-closed contract; this is its implementation.
    ///
    /// Contexts and pending joins are each enumerated by key prefix, reconstructed
    /// and (for contexts) checkpoint/owner-verified into staging vectors; only
    /// after ALL succeed are they installed. A single `?` on a corrupt/foreign
    /// snapshot returns before any install, so the half-built client is dropped and
    /// construction fails closed.
    fn restore_from_storage(&mut self) -> Result<(), ClientError> {
        // --- Contexts: enumerate by prefix, reconstruct + verify, stage. ---
        let ctx_keys = self
            .storage
            .list_keys(Self::CTX_KEY_PREFIX)
            .map_err(|e| ClientError::StorageBackend(format!("listing persisted contexts: {e}")))?;
        let mut staged_contexts: Vec<(String, PerContextState)> =
            Vec::with_capacity(ctx_keys.len());
        for key in ctx_keys {
            let context_id = key
                .strip_prefix(Self::CTX_KEY_PREFIX)
                .unwrap_or(&key)
                .to_owned();
            let blob = self.read_listed_key(&key)?;
            let snapshot = ContextSnapshot::from_bytes(&blob)?;
            // The blob is keyed by context id; its embedded id must match, or the
            // backend returned the wrong blob (key collision / backend bug).
            if snapshot.context_id() != context_id {
                return Err(ClientError::StorageCorrupt(format!(
                    "snapshot under key '{key}' carries a different context id '{}'",
                    snapshot.context_id()
                )));
            }
            // Owner binding is verified inside `restore` against this client's DID.
            let state = snapshot.restore(self.signer.did())?;
            staged_contexts.push((context_id, state));
        }

        // --- Pending joins: enumerate by prefix, reconstruct, stage. ---
        // A pending blob whose context was already restored is stale (the join
        // completed and the delete was lost to a crash); skip it rather than
        // resurrect a consumed KeyPackage.
        let restored_ids: std::collections::HashSet<&str> =
            staged_contexts.iter().map(|(id, _)| id.as_str()).collect();
        let pending_keys = self
            .storage
            .list_keys(Self::PENDING_KEY_PREFIX)
            .map_err(|e| ClientError::StorageBackend(format!("listing pending joins: {e}")))?;
        let mut staged_pending: Vec<(String, PendingJoin)> = Vec::with_capacity(pending_keys.len());
        for key in pending_keys {
            let context_id = key
                .strip_prefix(Self::PENDING_KEY_PREFIX)
                .unwrap_or(&key)
                .to_owned();
            if restored_ids.contains(context_id.as_str()) {
                continue;
            }
            let blob = self.read_listed_key(&key)?;
            // `restore_pending_join` returns the identity + context the blob was
            // bound to at capture; verify BOTH here, fail closed. A swapped blob
            // that belongs to another identity is an identity confusion
            // (StorageIdentityMismatch); one whose embedded context id disagrees
            // with its storage key is a corrupt/mislabeled blob (StorageCorrupt).
            let (provider, signer, bound_owner_did, bound_context_id) =
                restore_pending_join(&blob)?;
            if bound_owner_did != self.signer.did() {
                return Err(ClientError::StorageIdentityMismatch(format!(
                    "pending join under key '{key}' is bound to identity \
                     '{bound_owner_did}', not this client '{}'",
                    self.signer.did()
                )));
            }
            if bound_context_id != context_id {
                return Err(ClientError::StorageCorrupt(format!(
                    "pending join under key '{key}' carries a different context id \
                     '{bound_context_id}'"
                )));
            }
            staged_pending.push((context_id, PendingJoin { signer, provider }));
        }

        // All snapshots reconstructed + verified cleanly — commit atomically.
        for (id, state) in staged_contexts {
            self.contexts.insert(id, state);
        }
        for (id, pending) in staged_pending {
            self.pending_joins.insert(id, pending);
        }
        Ok(())
    }

    /// Reads a key that `list_keys` just reported. A `None` here means the key
    /// vanished between the enumeration and the read (a concurrent delete or a
    /// backend inconsistency), which fails closed rather than being treated as a
    /// benign absence — restore is all-or-nothing.
    fn read_listed_key(&self, key: &str) -> Result<Vec<u8>, ClientError> {
        self.storage
            .get(key)
            .map_err(|e| ClientError::StorageBackend(format!("reading '{key}': {e}")))?
            .ok_or_else(|| {
                ClientError::StorageBackend(format!(
                    "listed key '{key}' vanished before it could be read"
                ))
            })
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
fn key_package_member_did(
    key_package_bytes: &[u8],
    clock: &dyn Clock,
) -> Result<String, ClientError> {
    let key_package_in = KeyPackageIn::tls_deserialize(&mut &*key_package_bytes)
        .map_err(|e| ClientError::Codec(format!("deserializing key package: {e}")))?;
    // ADR-057 §Prereq-1: `key_package_in_did` re-validates the accepted
    // `Lifetime` against the hardened clock, so this naming path accepts exactly
    // the key packages `add_member` accepts.
    let did = key_package_in_did(&key_package_in, ProtocolVersion::Mls10, clock)?;
    Ok(did)
}
