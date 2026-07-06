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
//! cross-context saga coordination, outlets, discovery, or UCAN minting — those
//! require always-on hosts and live node-side. The fence is enforced
//! mechanically by the crate's dependency set (no `scp-runtime` /
//! `scp-identity` / `tokio`).

use std::collections::HashMap;
use std::sync::Arc;

use openmls::prelude::{KeyPackageBundle, KeyPackageIn, MlsMessageOut, ProtocolVersion};
use scp_clock::Clock;
use scp_event_log::{Event, EventType};
use scp_mls::group::{
    add_member_with_convergent_timestamp, create_group_with_wrapping_key, destroy_group,
    generate_key_package_with_wrapping_key, join_group_from_bytes, key_package_in_did,
    key_package_in_wrapping_key,
};
use scp_mls::{
    InMemoryMlsProvider, ScpCredential, SignatureKeyPair, restore_pending_join,
    serialize_pending_join,
};
use scp_protocol::context::membership::ContextEvent;
use scp_protocol::crypto::sender_keys::generate_wrapping_keypair;
use serde::{Deserialize, Serialize};
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};
use zeroize::Zeroizing;

use crate::context::PerContextState;
use crate::crypto_state::{ContextCryptoState, Inbound, SenderKeyDistribution};
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
    /// The stable wrapping public key embedded in this join's published
    /// `KeyPackage` leaf (§9.16.1). Adopted into the joined context's crypto state
    /// so the key peers HPKE-seal sender keys to matches the one this member can
    /// HPKE-open with.
    wrapping_public: [u8; 32],
    /// The matching wrapping secret. Zeroized on drop.
    wrapping_secret: Zeroizing<[u8; 32]>,
}

/// The persisted form of a pending join: the `scp-mls` pending-join blob plus the
/// stable wrapping keypair this member published in its `KeyPackage` leaf.
///
/// The wrapping keypair MUST survive a tab-reopen-mid-join, or the completed join
/// would install a *different* wrapping key than the one peers already HPKE-seal
/// to (from the published `KeyPackage`), and the joiner could never open their
/// distributions. The `scp-mls` pending blob (its own `MessagePack`) is embedded
/// verbatim so no `scp-mls` API change is needed.
#[derive(Serialize, Deserialize)]
struct PersistedPendingJoin {
    /// The `scp-mls` `serialize_pending_join` blob (provider + signer + bindings).
    mls_blob: Vec<u8>,
    /// The published wrapping public key.
    wrapping_public: [u8; 32],
    /// The matching wrapping secret. Zeroized after reconstruction.
    wrapping_secret: [u8; 32],
}

impl Drop for PersistedPendingJoin {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.wrapping_secret.zeroize();
    }
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
    /// The adder's member-wrapping-key **directory** after the add — every member
    /// (existing + self + the new joiner) as `(did, scp_wrapping_key)`. The joiner
    /// adopts it as its own directory (the authoritative member set, ADR-057
    /// sender-key distribution INVARIANT 1) so it can HPKE-seal its sender key to
    /// every existing member. This replaces a bare member-DID list: the DIDs are
    /// the directory keys, so there is no parallel collection to drift.
    pub wrapping_keys: Vec<(String, [u8; 32])>,
    /// The adder's own §9.16 sender key, HPKE-sealed to the new joiner (one
    /// distribution). The adder is the committer, so no bystander mirrors this add
    /// for it — the adder must seal to the joiner itself, or the joiner would never
    /// receive the adder's key. Delivered to the joiner via
    /// [`ScpClient::receive_message`].
    pub sender_key_distributions: Vec<SenderKeyDistribution>,
}

/// The outcome of [`ScpClient::receive_message`]: whether an application message
/// was produced, plus any sender-key distributions the receive triggered.
///
/// A **bystander** processing an add-Commit HPKE-seals its own sender key to each
/// newly-added member (ADR-057 sender-key distribution INVARIANT 2) and surfaces
/// those here; the driver's caller delivers them to their targets. Application
/// messages, sender-key installs, no-add Commits, and proposals produce no
/// distributions.
#[derive(Debug, Clone, Default)]
pub struct ReceiveOutput {
    /// `true` if an application message was decrypted and buffered as a
    /// `MessageReceived` event for [`ScpClient::drain_events`]; `false` for a
    /// Commit, a sender-key install, or a bare proposal.
    pub application: bool,
    /// Sender-key distributions this receive triggered (the bystander
    /// re-distribution trigger — empty except when processing an add-Commit as an
    /// existing member).
    pub sender_key_distributions: Vec<SenderKeyDistribution>,
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
    /// [`Self::rotate_sender_key`]) instead.
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
        // ADR-057 §9.16.1: generate this context's stable wrapping keypair once,
        // publish the public key in the creator's own MLS leaf `scp_wrapping_key`
        // extension, and seed the crypto state with the matching secret so peers
        // can HPKE-seal sender keys to it. ADR-057 §Prereq-1: the creator's own MLS
        // leaf `Lifetime` is stamped from the hardened driver clock.
        let (wrapping_public, wrapping_secret) = generate_wrapping_keypair();
        let mls_group = create_group_with_wrapping_key(
            &credential,
            Some(&wrapping_public),
            self.clock.as_ref(),
        )?;
        let crypto = ContextCryptoState::from_group_with_wrapping(
            context_id,
            mls_group,
            wrapping_public,
            wrapping_secret,
        );
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
        // ADR-057 §9.16.1: generate this join's stable wrapping keypair and publish
        // the public key in the KeyPackage leaf `scp_wrapping_key` extension, so
        // the adder and every bystander can HPKE-seal their sender keys to it. The
        // secret is retained (and persisted below) so the joined context opens with
        // the SAME key. ADR-057 §Prereq-1: the KeyPackage `Lifetime` is stamped
        // from the hardened driver clock.
        let (wrapping_public, wrapping_secret) = generate_wrapping_keypair();
        let (bundle, signer, provider): (KeyPackageBundle, _, InMemoryMlsProvider) =
            generate_key_package_with_wrapping_key(
                &credential,
                Some(&wrapping_public),
                self.clock.as_ref(),
            )?;

        let kp_bytes = bundle
            .key_package()
            .tls_serialize_detached()
            .map_err(|e| ClientError::Codec(format!("serializing key package: {e}")))?;

        // Persist the pending-join material (the private KeyPackage half PLUS the
        // wrapping keypair) BEFORE returning the public key package, so a crash
        // after handing the KP to the adder but before persistence cannot orphan
        // the join — a reopened tab restores this pending material and can still
        // complete the join with the SAME wrapping key it published.
        //
        // The blob is bound to BOTH this client's DID and the context id, so a
        // swapped pending blob cannot silently drive this identity into a group
        // under another leaf, nor bind this key package to the wrong context. The
        // bindings are verified on restore ([`Self::restore_from_storage`]).
        let mls_blob = serialize_pending_join(&provider, &signer, self.signer.did(), context_id)?;
        let pending_blob = {
            let persisted = PersistedPendingJoin {
                mls_blob,
                wrapping_public,
                wrapping_secret,
            };
            rmp_serde::to_vec_named(&persisted).map_err(|e| {
                ClientError::StorageCorrupt(format!("serializing pending join: {e}"))
            })?
        };
        self.storage
            .put(&Self::pending_key(context_id), pending_blob)
            .map_err(|e| {
                ClientError::StorageBackend(format!(
                    "persisting pending join for context '{context_id}': {e}"
                ))
            })?;

        self.pending_joins.insert(
            context_id.to_owned(),
            PendingJoin {
                signer,
                provider,
                wrapping_public,
                wrapping_secret: Zeroizing::new(wrapping_secret),
            },
        );

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

        let key_package_in = KeyPackageIn::tls_deserialize(&mut &*key_package_bytes)
            .map_err(|e| ClientError::Codec(format!("deserializing key package: {e}")))?;

        // ADR-057 §9.16.1: read the joiner's published stable wrapping key from the
        // SAME validated KeyPackage the add consumes, so the adder can HPKE-seal
        // its sender key to the joiner. Fail-closed if the leaf carries no wrapping
        // extension (INVARIANT 3): a member no peer can seal to must not be
        // admitted. Read BEFORE the `state` mutable borrow (a fresh-provider
        // validation that does not touch `self`).
        let new_member_wrapping_key =
            key_package_in_wrapping_key(&key_package_in, ProtocolVersion::Mls10, clock.as_ref())?;

        let state = self.context_mut(context_id)?;

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

        state.add_member_record(&new_member_did, new_member_wrapping_key);
        state.append_log_event(
            EventType::MemberJoined,
            &committer_did,
            Vec::new(),
            timestamp,
        )?;

        // ADR-057 sender-key distribution: the adder is the committer, so no
        // bystander mirrors this add for it — it must HPKE-seal its OWN sender key
        // to the new joiner here, or the joiner would never receive the adder's
        // key. (Existing members seal their keys to the joiner as bystanders when
        // they process this Commit; the joiner seals its key to everyone on join.)
        let sender_key_distributions = vec![state.crypto.seal_sender_key_distribution(
            &committer_did,
            &new_member_did,
            &new_member_wrapping_key,
        )?];

        let output = AddMemberOutput {
            commit,
            welcome,
            event_log: state.events(),
            wrapping_keys: state.crypto.wrapping_keys_snapshot(),
            sender_key_distributions,
        };
        // The `state` borrow ends above (the output owns clones), so the snapshot
        // write can re-borrow `self`. Persist the post-add state (new MLS epoch,
        // membership, MemberJoined leaf, advanced send ratchet from the seal)
        // before returning.
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
    /// `wrapping_keys` is [`AddMemberOutput::wrapping_keys`] (the adder's
    /// member-wrapping-key directory). Both travel alongside the Welcome.
    ///
    /// Returns the joiner's own sender-key distributions: the joiner HPKE-seals
    /// its §9.16 sender key to every existing member (adopted from `wrapping_keys`)
    /// so they can decrypt its messages. The caller delivers each to its
    /// `target_did` via [`Self::receive_message`].
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Driver`] if there is no pending join material for
    /// the context, [`ClientError::ContextAlreadyExists`] if already joined,
    /// [`ClientError::Mls`] / [`ClientError::EventLog`] on Welcome processing,
    /// replay failure (a replay stream that does not chain cleanly is rejected),
    /// or a sender-key seal failure, or [`ClientError::StorageBackend`] if
    /// persisting the joined context or deleting the consumed pending blob fails. A
    /// persist failure **poisons** the freshly-joined context (its state advanced
    /// in memory but was not durably recorded); reconstruct via [`Self::new`],
    /// which restores the still-present pending material and lets the join be
    /// retried.
    pub fn join_context_encrypted(
        &mut self,
        context_id: &str,
        welcome_bytes: &[u8],
        prior_event_log: &[Event],
        wrapping_keys: &[(String, [u8; 32])],
    ) -> Result<Vec<SenderKeyDistribution>, ClientError> {
        if self.contexts.contains_key(context_id) {
            return Err(ClientError::ContextAlreadyExists(context_id.to_owned()));
        }
        let pending = self.pending_joins.remove(context_id).ok_or_else(|| {
            ClientError::Driver(format!(
                "no pending key package for context '{context_id}'; call \
                 generate_key_package_for_join first"
            ))
        })?;

        // Adopt the wrapping keypair this join published in its KeyPackage leaf, so
        // the joined context HPKE-opens distributions with the SAME key peers
        // sealed to (read before `pending`'s MLS material is moved into the join).
        // Held in `Zeroizing` so the stack copy is wiped on scope exit; the crypto
        // state re-wraps its own copy in `Zeroizing` (`from_group_with_wrapping`).
        let wrapping_public = pending.wrapping_public;
        let wrapping_secret = Zeroizing::new(*pending.wrapping_secret);

        // `join_group_from_bytes` is the wire-path variant: it deserializes the
        // Welcome (as `MlsMessageIn`) internally, so the driver never has to
        // name the inbound MLS message type.
        let mls_group = join_group_from_bytes(welcome_bytes, pending.provider, pending.signer)?;
        let crypto = ContextCryptoState::from_group_with_wrapping(
            context_id,
            mls_group,
            wrapping_public,
            *wrapping_secret,
        );
        let self_did = self.signer.did().to_owned();

        // Start from an EMPTY log and replay the adder's stream verbatim, so the
        // joiner reconstructs a byte-identical log (identical leaves, identical
        // root) rather than synthesizing fresh leaves at the wrong positions.
        let mut state = PerContextState::new_empty(context_id, crypto);
        for event in prior_event_log {
            state.replay_event(event)?;
        }

        // Adopt the adder's wrapping-key directory (existing members incl. the
        // adder), then add self with its own published wrapping key. This IS the
        // membership set (ADR-057 INVARIANT 1).
        //
        // SECURITY (ADR-057 T4 residual — "self-certifying directory"): these
        // existing-member wrapping keys arrive in the adder's transported
        // `wrapping_keys` snapshot, which — like the replayed event-log stream and
        // the Welcome itself — is trusted from the adder, NOT independently
        // authenticated against each member's signed leaf. A malicious adder could
        // substitute member M's wrapping key so the joiner seals its sender key to a
        // key M cannot open (M never decrypts the joiner → targeted within-group
        // downgrade). The blast radius is bounded: the adder is already the trusted
        // bootstrap source, and a substituted-key holder still cannot strip the
        // outer MLS layer. The authenticated source is each member's signed
        // `scp_wrapping_key` leaf extension in the (now Welcome-embedded) ratchet
        // tree; sourcing recipients from there is blocked only because openmls does
        // not expose remote leaf extensions via its public API, and lands with the
        // leaf-signing / custody slice (§23.13) — the same residual T3/T4 name for
        // the convergent timestamp. Triggers 1 (adder→joiner) and 3
        // (bystander→joiner) do NOT share this gap: they read the wrapping key from
        // a validated KeyPackage / Add proposal.
        for (member_did, member_wrapping_key) in wrapping_keys {
            state.add_member_record(member_did, *member_wrapping_key);
        }
        state.add_member_record(&self_did, wrapping_public);

        // ADR-057 sender-key distribution: the joiner HPKE-seals its own sender key
        // to every existing member (the directory minus self), so they can decrypt
        // the joiner's messages. Returned for the caller to deliver.
        let recipients = state.crypto.wrapping_keys_snapshot();
        let distributions = state
            .crypto
            .distribute_local_key_to(&self_did, &recipients)?;

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
        Ok(distributions)
    }

    // ----------------------------------------------------------------------
    // Message path
    // ----------------------------------------------------------------------

    /// Encrypts and "sends" an application message in `context_id`, returning the
    /// wire ciphertext.
    ///
    /// Runs the full §9.16 double-encryption pipeline, increments this sender's
    /// sequence, records the sent message as **local history** (a `MessageSent`
    /// [`ContextEvent`] buffered for [`Self::drain_events`], matching the native
    /// runtime's `finalize_send`), and returns the ciphertext for the transport
    /// to deliver to peers.
    ///
    /// # `MessageSent` is not a convergent event-log leaf
    ///
    /// Per ADR-011 exclusion taxonomy §2 (`.docs/adrs/phase-2.md`), an
    /// application message is per-author with no total delivery order over a real
    /// relay, so it is **excluded** from the canonical §9.9.3 Merkle log: it is
    /// local `ContextEvent` history only (as on the native path, until ADR-051).
    /// This method therefore appends **no** event-log leaf and binds **no**
    /// convergent-timestamp AAD — the message is plain MLS-encrypted. The event
    /// log (and its Merkle root) is unchanged by a send.
    ///
    /// There is no relay in the MVP; the returned bytes are handed directly to
    /// recipients' [`Self::receive_message`] by the test harness "dumb pipe".
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::UnknownContext`] if the context is not held,
    /// [`ClientError::ContextPoisoned`] if the context has been poisoned by a
    /// prior failed persist, or [`ClientError::Mls`] / [`ClientError::SenderKey`]
    /// on a layer failure. A [`ClientError::StorageBackend`] from the post-send
    /// persist **poisons** the context: the message's state advanced in memory
    /// but was not durably recorded, so `Err` (and thus no ciphertext) is returned
    /// and the context refuses further ops.
    pub fn send_message(
        &mut self,
        context_id: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ClientError> {
        let sender_did = self.signer.did().to_owned();
        let state = self.context_mut(context_id)?;

        let sequence = state.next_sequence(&sender_did);
        let ciphertext = state
            .crypto
            .encrypt_message(plaintext, &sender_did, sequence)?;

        // Record the sent message as local history (not a convergent leaf —
        // ADR-011). This mirrors the native runtime's `finalize_send`, which
        // returns a local `MessageSent` ContextEvent; the driver buffers it for
        // `drain_events`.
        state.push_event(ContextEvent::MessageSent {
            sender_did: sender_did.into(),
            sequence_number: sequence,
            payload: plaintext.to_vec(),
        });

        // The `state` borrow ends above; persist the post-send state (advanced
        // sender sequence + ratchet, buffered MessageSent) before returning.
        self.persist_context(context_id)?;
        Ok(ciphertext)
    }

    /// Receives an inbound MLS message in `context_id`: decrypts an application
    /// message, or applies a membership-changing Commit, converging the event
    /// log either way.
    ///
    /// A **membership** leaf (`MemberJoined`) is stamped with the convergent
    /// committer timestamp recovered from the Commit's own **authenticated** MLS
    /// AAD (ADR-057), not supplied by the caller — so this method takes only the
    /// ciphertext. Application messages are not convergent leaves (ADR-011), so a
    /// received message stamps no leaf.
    ///
    /// - **Application message** → produces a `MessageReceived` event (buffered
    ///   for [`Self::drain_events`]) and appends **no** event-log leaf (ADR-011
    ///   excludes `MessageSent` from the convergent Merkle log). Returns `true`.
    /// - **Membership-changing Commit (add)** → advances the MLS epoch and, for
    ///   each member the Commit adds, appends the SAME convergent `MemberJoined`
    ///   leaf the committer appended — committer DID + the authenticated timestamp
    ///   recovered from the Commit AAD and adopted **verbatim** — and records the
    ///   added member. This is what makes an EXISTING member's log and membership
    ///   set converge with the committer's and the new joiner's in a multi-party
    ///   context (§9.9.3). Returns `false` (no application payload was produced).
    /// - **No-add Commit** (e.g. a self-update) → advances the MLS epoch, stamps
    ///   no leaf, records no member. Returns `false`.
    /// - **Bare proposal** → cached by `scp-mls`; no leaf, returns `false`.
    ///
    /// # Convergent-timestamp authentication (ADR-057)
    ///
    /// The timestamp stamped on each `MemberJoined` leaf is bound into the
    /// Commit's `FramedContent.authenticated_data` at commit time by the
    /// committer, and is covered by the committer's MLS leaf signature and — under
    /// the `PURE_CIPHERTEXT` policy — the `PrivateMessage` AEAD tag. `scp-mls`
    /// recovers it from openmls's *verified* `ProcessedMessage::aad()` (after
    /// signature + AEAD verification) and every receiver adopts it **verbatim** —
    /// there is no receiver-side plausibility window (a per-receiver clock verdict
    /// would itself be a §9.9.3 violation: honest members whose clocks straddled
    /// the value would diverge). So the value is authenticated, not trusted on the
    /// wire: a hostile relay that alters it breaks the AEAD tag and the frame is
    /// rejected at decrypt, and no member other than the committer can author a
    /// frame carrying it. There is no loose transported `u64` left for an in-path
    /// attacker to forge.
    ///
    /// Two residuals remain, each out of this slice's scope:
    /// - **Joiner-trusts-adder replay.** A *new* joiner adopts the adder's
    ///   replayed event-log stream verbatim (via [`Self::join_context_encrypted`]);
    ///   independently re-verifying each historical leaf against a per-leaf
    ///   committer signature is the leaf-signing / custody slice, not this one.
    /// - **Authenticated committer lie.** The AAD binding proves *who* authored
    ///   the timestamp, but a malicious *committer* can still bind a false value.
    ///   That is the pre-existing MLS insider-equivocation class (a malicious
    ///   committer can already fork receivers by sending different commits to
    ///   different members); it is bounded once per-leaf committer signatures land
    ///   (ADR-057 §23.13), not by re-adjudicating the value on receive.
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
    /// convergent-timestamp failure (missing / malformed AAD — ADR-057) if an
    /// add-Commit carries no authenticated timestamp or a malformed one; this is
    /// raised *pre-merge*, so the epoch is unchanged. Otherwise returns a
    /// crypto/leaf error on failure. A [`ClientError::StorageBackend`] from the
    /// post-receive persist **poisons** the context (the decrypt already advanced
    /// the durable ratchet's in-memory counterpart, so the diverged state cannot
    /// be safely reused).
    pub fn receive_message(
        &mut self,
        context_id: &str,
        ciphertext: &[u8],
    ) -> Result<ReceiveOutput, ClientError> {
        // ADR-057 §Prereq-1: captured before the `state` mutable borrow so the
        // hardened clock (used to re-validate any add-Commit's KeyPackage
        // `Lifetime`) and the mutable context borrow do not alias `self`.
        let clock = Arc::clone(&self.clock);
        // This member's own DID — needed as the `local_did` when it seals its own
        // sender key to a member a bystander add introduces (INVARIANT 2).
        let self_did = self.signer.did().to_owned();
        let state = self.context_mut(context_id)?;
        // Any successful `decrypt_message` mutates persistent MLS state — it
        // ratchets forward (application), merges a staged commit (add Commit),
        // installs an incoming sender key (management distribution), or caches a
        // proposal in the provider store. So every non-error outcome is persisted
        // after the `state` borrow ends. Only the rejected Remove-bearing Commit
        // (which `scp-mls` dropped BEFORE merging, leaving MLS + SCP state
        // unchanged) returns without a write.
        let outcome = match state.crypto.decrypt_message(ciphertext, clock.as_ref())? {
            Inbound::Application {
                sender_did,
                plaintext,
            } => {
                // ADR-011 exclusion taxonomy §2: a received application message is
                // NOT a convergent Merkle leaf, so NO event-log leaf is appended —
                // the message is buffered as local `MessageReceived` history only
                // (matching the native runtime). The event log / Merkle root is
                // unchanged by a received message.
                state.push_event(ContextEvent::MessageReceived {
                    sender_did: sender_did.into(),
                    payload: plaintext,
                });
                ReceiveOutput {
                    application: true,
                    sender_key_distributions: Vec::new(),
                }
            }
            Inbound::SenderKeyInstalled { .. } => {
                // A peer's sender key was HPKE-opened and installed into the store
                // by `decrypt_message` (§9.16.1/§9.16.2). No application payload, no
                // leaf, no ContextEvent — just persist the updated store below so a
                // reopened tab keeps the key.
                ReceiveOutput {
                    application: false,
                    sender_key_distributions: Vec::new(),
                }
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
                added_wrapping_keys,
                committer_timestamp_secs,
            } => {
                // A no-add Commit (e.g. a self-update) has `committer_timestamp_secs
                // == None` and empty `added_dids` by construction: it advanced the
                // MLS epoch inside `scp-mls` but stamps no membership leaf and
                // records no member. An add-Commit carries `Some(timestamp)`.
                let mut sender_key_distributions = Vec::new();
                if let Some(timestamp) = committer_timestamp_secs {
                    // For each added member, append the identical convergent
                    // `MemberJoined` leaf the committer appended: actor = committer
                    // DID, timestamp = the authenticated convergent value `scp-mls`
                    // recovered from the Commit's verified AAD and adopted verbatim
                    // (ADR-057), empty payload. The sequence + prev_hash are
                    // recomputed from this member's current log, which (by the
                    // convergence invariant) is at the same state the committer's
                    // was before the add — so the leaf is byte-identical. Then
                    // record the member in the wrapping-key directory (with the
                    // wrapping key `scp-mls` recovered from the Add proposal, 1:1
                    // with `added_dids`).
                    //
                    // ADR-057 sender-key distribution INVARIANT 2 (bystander
                    // re-distribution): this existing member also HPKE-seals its OWN
                    // sender key to each newly-added member, so the new member can
                    // decrypt this member's messages. Without this, push
                    // distribution is incomplete — the joiner only learns the
                    // adder's key (from the add) and its own, never the bystanders'.
                    for (added_did, added_wrapping_key) in
                        added_dids.iter().zip(added_wrapping_keys.iter())
                    {
                        state.append_log_event(
                            EventType::MemberJoined,
                            &committer_did,
                            Vec::new(),
                            timestamp,
                        )?;
                        state.add_member_record(added_did, *added_wrapping_key);
                        sender_key_distributions.push(state.crypto.seal_sender_key_distribution(
                            &self_did,
                            added_did,
                            added_wrapping_key,
                        )?);
                    }
                }
                ReceiveOutput {
                    application: false,
                    sender_key_distributions,
                }
            }
            Inbound::Proposal { .. } => ReceiveOutput::default(),
        };
        // `state` borrow ends above. Persist the mutated MLS/log/membership state
        // (including any send-ratchet advance from a bystander re-distribution).
        self.persist_context(context_id)?;
        Ok(outcome)
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
    // Sender-key rotation (§9.16.5)
    // ----------------------------------------------------------------------

    /// Rotates this participant's §9.16 sender key and re-distributes it to every
    /// member (§9.16.5), returning the distributions to deliver.
    ///
    /// Generates a fresh sender key, increments the monotonic sender-key epoch,
    /// and HPKE-seals the new key to every other member's stable wrapping key. The
    /// caller delivers each returned [`SenderKeyDistribution`] to its `target_did`
    /// via [`Self::receive_message`]; recipients accept the higher epoch under
    /// `set_checked` monotonicity and reject any stale earlier-epoch key.
    ///
    /// Note: an in-tab MVP has no signed `SenderKeyEpochAdvance` notification and
    /// no pull path — rotation is an unsigned push over the same
    /// management-message channel as the join/add distributions. Peers that are
    /// offline during the push do not receive the new key until a future push
    /// (the offline-re-drive gap is a documented residual pending the pull path).
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::UnknownContext`] if the context is not held,
    /// [`ClientError::ContextPoisoned`] if the context diverged,
    /// [`ClientError::Driver`] on sender-key-epoch overflow, or a seal/frame error.
    /// A [`ClientError::StorageBackend`] from the post-rotation persist **poisons**
    /// the context (the new key advanced in memory but was not durably recorded).
    pub fn rotate_sender_key(
        &mut self,
        context_id: &str,
    ) -> Result<Vec<SenderKeyDistribution>, ClientError> {
        let self_did = self.signer.did().to_owned();
        let state = self.context_mut(context_id)?;
        let distributions = state.crypto.rotate_sender_key(&self_did)?;
        // `state` borrow ends; persist the rotated key + advanced send ratchet.
        self.persist_context(context_id)?;
        Ok(distributions)
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
        self.live_context_ref(context_id)
            .map(PerContextState::member_dids)
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
            // Unwrap the scp-client pending envelope (the scp-mls blob + the
            // published wrapping keypair). The wrapping secret is zeroized when the
            // `PersistedPendingJoin` drops at the end of this iteration.
            let persisted: PersistedPendingJoin = rmp_serde::from_slice(&blob).map_err(|e| {
                ClientError::StorageCorrupt(format!(
                    "deserializing pending join under key '{key}': {e}"
                ))
            })?;
            // `restore_pending_join` returns the identity + context the blob was
            // bound to at capture; verify BOTH here, fail closed. A swapped blob
            // that belongs to another identity is an identity confusion
            // (StorageIdentityMismatch); one whose embedded context id disagrees
            // with its storage key is a corrupt/mislabeled blob (StorageCorrupt).
            let (provider, signer, bound_owner_did, bound_context_id) =
                restore_pending_join(&persisted.mls_blob)?;
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
            staged_pending.push((
                context_id,
                PendingJoin {
                    signer,
                    provider,
                    wrapping_public: persisted.wrapping_public,
                    wrapping_secret: Zeroizing::new(persisted.wrapping_secret),
                },
            ));
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
