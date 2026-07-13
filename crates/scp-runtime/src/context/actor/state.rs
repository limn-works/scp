//! Per-context actor state — the `&mut`-owned payload of a `ContextActor`.
//!
//! # Clippy allows
//!
//! `doc_markdown` / `too_long_first_doc_paragraph` — doc prose cites
//! plan section titles and field names that would be overly churny to
//! wrap in backticks throughout.
#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//!
//! Per ADR-049 §1 (`ContextActor owns state by move`) and plan
//! §"ContextActor", this module defines the SHAPE of the state an actor
//! owns — the state model the commit-12 migration moved off the
//! now-deleted `ContextManager`.
//!
//! # Split from `manager/mod.rs`
//!
//! The legacy `ContextManager` carried its own `pub(crate)
//! PerContextState` in the now-deleted `crate::context::manager` module —
//! that type was consumed through
//! the `per-context-state Mutex` lock-based model that ADR-049 deleted.
//! The actor's state type here is a SUPERSET-COMPATIBLE shape: every field
//! the legacy struct owned is represented here (so the commit 12b+
//! handler-body migrations moved calls mechanically off `manager.field`
//! onto `state.field`), plus the new per-actor fields (`saga_pending`,
//! `welcome_scratchpad`, `send_tracker`, `recv_tracker`, split mode
//! state) that the legacy struct did not own.
//!
//! The two types coexisted through the commit ladder (commit 6 through
//! commit 12); the legacy state struct stayed byte-identical apart from
//! the `pub(crate)` field elevations commit 12a added so the actor could
//! name the sub-struct types. Commits 12b-12c migrated handler bodies to
//! take `&mut actor::PerContextState`. Commit 12d deleted the legacy
//! `ContextManager`; the legacy state type was removed in the same
//! mechanical pass.
//!
//! # Origin — the fields-only landing
//!
//! [`PerContextState`], [`ContextCryptoState`], and [`BroadcastState`]
//! first landed as a fields-only mirror of every field the legacy
//! manager's own `PerContextState` + `MlsCryptoProvider::contexts[ctx_id]`
//! owned, giving the handler migration a complete field-set destination so
//! each move off `manager.foo` onto `state.foo` was mechanical. That
//! migration is complete: the handlers read and mutate this actor-owned
//! state directly, and the legacy manager and its `Supervisor::dispatch_*`
//! method bodies no longer exist.
//!
//! The MLS group handle on [`ContextCryptoState`] is `Option<ScpMlsGroup>`
//! (not `ScpMlsGroup` non-optional as the legacy provider held it),
//! because actors spawn before any MLS state is constructed — Create /
//! Join handlers populate it. This is the only shape divergence from the
//! legacy layout; all other fields are stored in the same types the
//! legacy manager used.
//!
//! # Construction
//!
//! Production construction now goes through
//! `Supervisor::spawn_actor_with_state`, which hands each
//! [`ContextActor`](crate::context::actor::ContextActor) its owned
//! [`actor::PerContextState`](PerContextState). The test
//! constructors [`PerContextState::new_for_test_encrypted`] and
//! [`PerContextState::new_for_test_broadcast`] additionally build the
//! state from minimum inputs to prove the shape is both structurally
//! complete and constructible.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use scp_clock::{Clock, SystemClock};
use scp_did::DID;
use scp_event_log::checkpoint::ConsistencyCheckpoint;
use scp_protocol::context::broadcast::BroadcastContext as ProtocolBroadcastContext;
use scp_protocol::context::membership::{MembershipState, ReceiveBuffer};
use scp_protocol::context::roles::ContextRoleState;
use scp_protocol::crypto::sender_keys::{NonceDedup, SenderKey, SenderKeyStore};
use scp_protocol::crypto::ucan::validate::InMemoryProofResolver;
use scp_protocol::envelope::{ReorderBuffer, SequenceTracker};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::context::ContextHandle;
use crate::context::actor::sequence::SendSequenceTracker;
use crate::context::state::{
    AccessControlState, CommitFaultMarker, EpochState, GovernanceState, MigrationState,
    PendingCommit, TtlState,
};
use crate::context::supervisor::saga_journal::SagaId;
use crate::context::supervisor::saga_prepared_state::SagaPreparedState;
use crate::economy::adapter::PaymentReceipt;
use scp_mls::group::ScpMlsGroup;

// ---------------------------------------------------------------------------
// Lifecycle state (per-actor, actor-owned)
// ---------------------------------------------------------------------------

/// Per-actor lifecycle state. Not the same as
/// [`scp_protocol::context::ContextState`] — that is the protocol-level
/// seven-state FSM (Creating / Active / Closing / Closed / Expired /
/// MigratingOut / Tombstoned).
///
/// [`ContextLifecycleState`] is the ACTOR's internal lifecycle and drives
/// the supervisor's respawn-on-panic decisions and the pause/shutdown
/// control commands. Mapping between the two is one-way (actor observes
/// protocol state changes on commit of lifecycle handlers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextLifecycleState {
    /// Normal operation — command dispatch loop is processing commands.
    Open,
    /// `LifecycleControlCommand::Pause` received; command dispatch is
    /// blocked on persist-sync completion.
    Closing,
    /// Terminal. The actor's `run()` loop has exited; the handle in the
    /// supervisor's `actors` map is stale and should be removed.
    Closed,
}

// ---------------------------------------------------------------------------
// WelcomeProcessing — multi-step Welcome scratchpad (plan §"Welcome
// scratchpad")
// ---------------------------------------------------------------------------

/// Scratchpad held by the actor during a multi-step Welcome processing
/// flow (MLS StagedWelcome + consumed KP reference). Split from the old
/// `MlsCryptoProvider::pending_joins` global per plan §"MlsCryptoProvider
/// dissolution": the `StagedWelcome` lives here (per-context), the KP
/// reservation lives on the `KeyPackageStoreActor`.
///
/// # Supersession of the single-slot provider path
///
/// The [`Self::kp_reservation`] handle pairs with the per-identity
/// [`KeyPackageStoreActor`](crate::context::supervisor::key_package_actor::KeyPackageStoreActor)
/// `reserved` map, which **supersedes** the legacy single-slot
/// `MlsCryptoProvider::pending_joins` (`ArcSwapOption`): a Welcome flow
/// reserves a KP (recording the `ReservationId` here), joins from the returned
/// signer-state, then confirms (success) or cancels (failure) the reservation.
/// Because reservations are keyed by id, concurrent Welcomes for distinct
/// contexts never clobber one another — the single-slot provider could hold
/// only one outstanding KP-for-join at a time.
///
/// # ADR-049 Phase 2J crash-safety classification (spawn-from-Welcome)
///
/// This scratchpad is **transient handshake state, NOT persisted** (not in any
/// class of the §9 snapshot). The
/// [`Supervisor::spawn_actor_from_welcome`](crate::context::supervisor::Supervisor::spawn_actor_from_welcome)
/// entrypoint fuses the join and durably consumes the KeyPackage BEFORE the
/// joiner actor is spawned, so a freshly-spawned joiner carries
/// `welcome_scratchpad: None` — there is nothing authorization-critical left in
/// it to survive a crash. The picked-up crypto the joiner obtains (the joined
/// MLS group + its own sender key) is **Class M**: it lives in the
/// supervisor-owned crypto provider `Arc`, is captured into the fail-closed
/// initial snapshot's `mls_crypto_state`, and is max-merged on respawn (spec
/// §23.17.2 Invariant 2) via the existing crypto snapshot/restore path — so it
/// round-trips through snapshot/respawn without any new snapshot field here.
#[derive(Debug, Default)]
pub struct WelcomeProcessing {
    /// Opaque bytes of the OpenMLS `StagedWelcome`. Zeroized on drop
    /// because the staged welcome contains pre-commit group-epoch key
    /// material (plan §"MlsCryptoProvider dissolution" row
    /// `pending_joins`).
    pub staged_welcome: Zeroizing<Vec<u8>>,
    /// The reservation ID held by the `KeyPackageStoreActor`.
    /// Populated at Welcome-Reserve time; consumed at ConfirmConsume
    /// (success) or CancelReservation (failure). A
    /// [`ReservationId`](crate::context::supervisor::key_package_actor::ReservationId)
    /// newtype (not a bare `String`) so it cannot be transposed with a
    /// `KpRef`.
    pub kp_reservation: Option<crate::context::supervisor::key_package_actor::ReservationId>,
}

// ---------------------------------------------------------------------------
// Broadcast-publish reservation (ADR-049 §SequenceReservation, two-phase
// mailbox publish)
// ---------------------------------------------------------------------------

/// Opaque identifier for an in-flight broadcast-publish reservation.
///
/// Minted at phase 1 (`ReserveBroadcastPublish`) and echoed back by the
/// caller at phase 2 (`ApplyBroadcastPublish`) so the actor can match the
/// apply to the exact reservation it issued. Random per reservation so a
/// stale or replayed apply cannot collide with a live reservation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BroadcastReservationId(pub String);

impl BroadcastReservationId {
    /// Mint a fresh random reservation id.
    #[must_use]
    pub fn new_random() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }
}

/// State the actor holds between the two phases of a broadcast publish.
///
/// Phase 1 ([`reserve_broadcast_publish`]) reserves the broadcast
/// sequence and records everything the seal will need so phase 2
/// ([`apply_broadcast_publish`]) is deterministic — the apply seals with
/// the EXACT `reserved_sequence`, `timestamp`, and `nonce` the caller
/// signed, so the signature remains valid. The `payload` itself is not
/// signed (the signing payload binds only a `None`-provenance hash), so
/// the caller supplies it at apply time.
///
/// Held in [`PerContextState::pending_broadcast_publishes`]. If the apply
/// never arrives the reservation is rolled back (the reserved sequence is
/// returned to the author's counter when it is still the head).
///
/// [`reserve_broadcast_publish`]: crate::context::broadcast_helpers::reserve_broadcast_publish
/// [`apply_broadcast_publish`]: crate::context::broadcast_helpers::apply_broadcast_publish
#[derive(Debug, Clone)]
pub struct PendingBroadcastPublish {
    /// Author DID this reservation belongs to.
    pub author_did: DID,
    /// The broadcast sequence reserved for this publish (consumed from
    /// the author's `next_sequence` at phase 1). The apply phase seals
    /// with exactly this value.
    pub reserved_sequence: u64,
    /// The author's broadcast key epoch at reservation time. Carried so
    /// apply can detect an epoch change between phases (key rotation) and
    /// reject a stale reservation rather than seal under the wrong key.
    pub key_epoch: u64,
    /// Unix-ms timestamp captured at reservation time and bound into the
    /// signed payload; apply seals with the same value.
    pub timestamp: u64,
    /// AES-256-GCM nonce captured at reservation time and bound into the
    /// signed payload; apply seals with the same value.
    pub nonce: [u8; 12],
}

// ---------------------------------------------------------------------------
// RecvSequenceTracker — minimal skeleton for the actor's anti-replay counter
// ---------------------------------------------------------------------------

/// Per-sender receive-sequence high-water mark. Commit 6 carries the type
/// so `PerContextState` compiles; the real anti-replay logic migrates
/// from `manager/messaging.rs` in commit 8.
#[derive(Debug, Default)]
pub struct RecvSequenceTracker {
    /// Per-sender DID → last-seen sequence number.
    per_sender: HashMap<DID, u64>,
}

impl RecvSequenceTracker {
    /// Fresh tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            per_sender: HashMap::new(),
        }
    }

    /// Last-seen sequence number for a sender, or `0` if unseen.
    #[must_use]
    pub fn last_seen(&self, sender: &DID) -> u64 {
        self.per_sender.get(sender).copied().unwrap_or(0)
    }

    /// Record a newly-observed sequence number. Returns `true` iff the
    /// update was strictly monotonic (i.e. accepted).
    pub fn record(&mut self, sender: DID, sequence: u64) -> bool {
        let entry = self.per_sender.entry(sender).or_insert(0);
        if sequence > *entry {
            *entry = sequence;
            true
        } else {
            false
        }
    }
}

// ---------------------------------------------------------------------------
// ContextEventLog — skeleton wrapper for the actor's RFC-6962 log view
// ---------------------------------------------------------------------------

/// Skeleton wrapper around [`scp_event_log::EventLog`] matching the shape
/// the actor will own. Full wiring (persistence, append, proof) lands with
/// the messaging handler migration in commit 8.
///
/// The inner `EventLog` is boxed to keep `PerContextState` movable by
/// value (an `EventLog` holds a large internal vector). No `Debug` /
/// `Default` derives — `scp_event_log::EventLog` implements neither at
/// the library boundary.
pub struct ContextEventLog {
    /// Underlying RFC-6962 Merkle tree event log.
    pub tree: scp_event_log::EventLog,
}

// ---------------------------------------------------------------------------
// Broadcast-mode state (plan §"Broadcast contexts")
// ---------------------------------------------------------------------------

/// State owned by a broadcast-mode `ContextActor`. Mirrors the per-author
/// AES-256-GCM key layer described in plan §"Broadcast contexts", spec
/// §5.14.2–§5.14.8. Every field is the authoritative, per-actor destination
/// for the broadcast-mode state that legacy `MlsCryptoProvider::broadcast_keys`
/// and `PerContextState.broadcast_context` split across two structures.
///
/// Commit 12a populates the field set; commit 12b+ migrates the broadcast
/// handler body to operate on `&mut BroadcastState` directly.
#[derive(Debug, Default)]
pub struct BroadcastState {
    /// Per-author broadcast keys (AES-256, rotated at author epoch).
    pub author_keys: HashMap<DID, AuthorKeyEntry>,
    /// Blocked authors. Subscribers refuse to decrypt their messages.
    pub blocked_authors: HashSet<DID>,
    /// Per-author receive-sequence high-water mark.
    pub recv_sequence_trackers: HashMap<DID, BroadcastRecvTracker>,
    /// Local identity's broadcast-send sequence counter.
    pub local_send_sequence: u64,
    /// Subscribers (DIDs that may receive). Authoritative locally; relay
    /// enforces routing but does not govern subscription.
    pub subscribers: HashSet<DID>,
    /// Queue of pending per-author key rotations. Plan §"Broadcast
    /// contexts" requires the broadcast handler to stage rotation events
    /// (triggered by block / epoch rollover / policy change) and apply
    /// them asynchronously — this queue is the per-actor staging area.
    /// Drained by the broadcast handler when the rotation landing
    /// pre-conditions (subscribers notified, new key distributed) are
    /// met. No legacy equivalent on `MlsCryptoProvider` — legacy applied
    /// rotations inline under the `broadcast_keys: Mutex<...>` lock.
    pub pending_key_rotations: VecDeque<PendingBroadcastKeyRotation>,
}

/// One broadcast author's key material. Zeroized on drop.
#[derive(Debug)]
pub struct AuthorKeyEntry {
    /// 32-byte AES-256 broadcast key. Wrapped in `Zeroizing` so rotation
    /// or crash zero the bytes even if a snapshot persist is in flight.
    pub key: Zeroizing<[u8; 32]>,
    /// Author's epoch counter — incremented on rotation.
    pub epoch: u64,
    /// Unix ms when this key entry was created.
    pub created_at_ms: u64,
}

/// Per-author broadcast anti-replay state.
#[derive(Debug, Default, Clone, Copy)]
pub struct BroadcastRecvTracker {
    /// Last-seen author epoch. Older epochs are silently dropped.
    pub last_seen_epoch: u64,
    /// Last-seen sequence number in `last_seen_epoch`.
    pub last_seen_sequence: u64,
}

/// Pending broadcast-key-rotation entry queued on
/// [`BroadcastState::pending_key_rotations`].
///
/// Each entry stages one author's next key epoch: the new 32-byte AES-256
/// key, the next epoch counter, and the Unix-ms timestamp the rotation was
/// queued at (so the broadcast handler can enforce grace windows and
/// deterministic ordering on drain). The key is wrapped in `Zeroizing`
/// because a rotation that is cancelled between Prepare and Commit must
/// not leave key material lingering in the queue.
#[derive(Debug)]
pub struct PendingBroadcastKeyRotation {
    /// The author whose key is being rotated.
    pub author: DID,
    /// The new 32-byte AES-256 broadcast key. Zeroized on drop.
    pub new_key: Zeroizing<[u8; 32]>,
    /// The epoch number this rotation advances to.
    pub new_epoch: u64,
    /// Unix-ms timestamp when the rotation was queued.
    pub queued_at_ms: u64,
}

// ---------------------------------------------------------------------------
// Encrypted-mode state (skeleton)
// ---------------------------------------------------------------------------

/// State owned by an encrypted-mode (MLS) `ContextActor`. Mirrors the
/// legacy `MlsCryptoProvider::contexts[ctx_id]`
/// (`crate::crypto::mls::provider::ContextCryptoState`) field-for-field.
///
/// # MLS group is `Option<ScpMlsGroup>`, not `ScpMlsGroup`
///
/// Legacy `MlsCryptoProvider` builds the MLS group synchronously inside
/// `create_context` / `join_from_welcome` and inserts the
/// `ContextCryptoState` only afterwards — so its `mls_group` field is
/// non-optional. The actor model separates actor spawn (supervisor puts a
/// live handle in the registry) from MLS group construction (a Create /
/// Join handler runs inside the actor's dispatch loop). Between those
/// two events `mls_group` is `None`. Commit 12b's lifecycle handler
/// migration populates the `Some` path.
///
/// # `sender_key` is `Option<SenderKey>`
///
/// Same rationale as `mls_group`: generated inside the Create / Join
/// handlers, `None` before then. The AES-256 byte buffer is zeroized on
/// drop via the underlying `SenderKey`'s `ZeroizeOnDrop` derive.
///
/// # Non-derives
///
/// Cannot derive `Debug` because [`ScpMlsGroup`] does not implement
/// `Debug` (it holds OpenMLS handles that would leak epoch secrets via
/// `{:?}`). A manual `Debug` impl redacts the MLS group and sender key
/// fields for log-safety. Cannot derive `Default` because
/// [`ScpMlsGroup`] has no `Default` (construction requires real MLS
/// crypto). The manual [`Default`] impl produces `None` for the MLS
/// group and sender key — semantically correct for the actor model
/// (actor spawns before the Create / Join handler populates the group).
pub struct ContextCryptoState {
    /// The `OpenMLS` group for this context. `None` until a Create or
    /// Join handler builds the group; `Some(ScpMlsGroup)` in steady state.
    /// Legacy field: `MlsCryptoProvider::ContextCryptoState::mls_group`
    /// (provider.rs:210), held non-optionally because legacy inserted
    /// the containing struct into the map only after construction.
    pub mls_group: Option<ScpMlsGroup>,

    /// The local member's AES-256 sender key for this context (spec
    /// §9.16.1). `None` until a Create / Join handler generates it.
    /// Legacy field: `MlsCryptoProvider::ContextCryptoState::sender_key`
    /// (provider.rs:212).
    pub sender_key: Option<SenderKey>,

    /// Sender key store tracking per-member keys for blocking /
    /// distribution. Mirrors legacy
    /// `MlsCryptoProvider::ContextCryptoState::sender_key_store`
    /// (provider.rs:214).
    pub sender_key_store: SenderKeyStore,

    /// Sender key epoch counter (incremented on each key rotation).
    /// Mirrors legacy
    /// `MlsCryptoProvider::ContextCryptoState::sender_key_epoch`
    /// (provider.rs:216).
    pub sender_key_epoch: u64,

    /// Pending sender-key-distribution messages queued for drain:
    /// `(target_did, serialized_message)`. Mirrors legacy
    /// `MlsCryptoProvider::ContextCryptoState::pending_distributions`
    /// (provider.rs:221). The send-side sequence counter that legacy
    /// kept on the same struct (`send_sequence: u64`) lives on
    /// [`PerContextState::send_tracker`](PerContextState::send_tracker)
    /// instead.
    pub pending_distributions: Vec<(String, Vec<u8>)>,

    /// Nonce deduplication cache for sender-key requests (replay
    /// protection). Mirrors legacy
    /// `MlsCryptoProvider::ContextCryptoState::nonce_dedup`
    /// (provider.rs:223).
    pub nonce_dedup: NonceDedup,

    /// Remote members' X25519 wrapping public keys, keyed by DID.
    /// Populated from key packages during `add_member`. Mirrors legacy
    /// `MlsCryptoProvider::ContextCryptoState::member_wrapping_keys`
    /// (provider.rs:226).
    pub member_wrapping_keys: HashMap<String, [u8; 32]>,

    /// Receive-side sequence tracking for MLS replay detection.
    /// Maps `sender_did` -> (`last_epoch`, `last_sequence`).
    ///
    /// # DOC-DRIFT / DORMANT (ADR-049 PR-6 read-authority switch)
    ///
    /// This field is a DORMANT PR-7 target and is NOT written or read by any
    /// production path. The provider's former live `recv_sequence_tracker` mirror
    /// has been DELETED and the AUTHORITATIVE receive-side `(epoch, sequence)`
    /// anti-replay floor now lives in the Supervisor-owned Class-M registry
    /// (`context/supervisor/floors.rs`), gated fail-closed at the
    /// `decrypt_and_dispatch` seam. PR-7 (key-move / `take_crypto_state`) MUST NOT
    /// rebuild a recv anti-replay mirror on this field — doing so would
    /// reintroduce the split-brain / lagging-mirror class this switch closed. If
    /// PR-7 needs the recv floor, it must read the registry, not this field.
    ///
    /// # Why this lives on `ContextCryptoState` (not `PerContextState`)
    ///
    /// The receive-side MLS sender-key anti-replay is encrypted-mode-
    /// specific: broadcast contexts track per-author replay protection
    /// on [`BroadcastState::recv_sequence_trackers`] instead (spec
    /// §5.14). Placing this field on the encrypted variant mirrors
    /// that split.
    ///
    /// # Distinct from `recv_tracker` on `PerContextState`
    ///
    /// [`PerContextState::recv_tracker`](PerContextState::recv_tracker)
    /// is the actor-shape per-member WIRE-sequence tracker used by the
    /// per-context reorder / delivery path. This field is the
    /// MLS sender-key layer `(epoch, sequence)` pair that [`open`]
    /// reads in the provider (see provider.rs:1211-1221 for the
    /// authoritative algorithm). Commit 12b.2 migrates that deliver-
    /// path read/write onto this field.
    ///
    /// [`open`]: crate::crypto::mls::provider::MlsCryptoProvider::open
    pub recv_sequence_tracker: HashMap<String, (u64, u64)>,
}

impl std::fmt::Debug for ContextCryptoState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact the MLS group and sender key — the former holds OpenMLS
        // epoch secrets, the latter is raw AES-256 key material. All
        // other fields are safe to print: counters, non-secret byte
        // arrays, and store types that already redact on their own.
        f.debug_struct("ContextCryptoState")
            .field(
                "mls_group",
                &if self.mls_group.is_some() {
                    "Some(<REDACTED>)"
                } else {
                    "None"
                },
            )
            .field(
                "sender_key",
                &if self.sender_key.is_some() {
                    "Some(<REDACTED>)"
                } else {
                    "None"
                },
            )
            .field("sender_key_store", &self.sender_key_store)
            .field("sender_key_epoch", &self.sender_key_epoch)
            .field(
                "pending_distributions",
                &format_args!("[{} entries]", self.pending_distributions.len()),
            )
            .field("nonce_dedup", &self.nonce_dedup)
            .field(
                "member_wrapping_keys",
                &format_args!("[{} entries]", self.member_wrapping_keys.len()),
            )
            .field(
                "recv_sequence_tracker",
                &format_args!("[{} entries]", self.recv_sequence_tracker.len()),
            )
            .finish()
    }
}

impl Default for ContextCryptoState {
    fn default() -> Self {
        Self {
            mls_group: None,
            sender_key: None,
            sender_key_store: SenderKeyStore::new(),
            sender_key_epoch: 0,
            pending_distributions: Vec::new(),
            nonce_dedup: NonceDedup::new(),
            member_wrapping_keys: HashMap::new(),
            recv_sequence_tracker: HashMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// ContextRouting — discriminated union over the §9.10.4 routing strategy
// ---------------------------------------------------------------------------

/// Per-context routing strategy (§9.10.4, §5.14).
///
/// This is the *routing axis*: how outbound application ciphertext is
/// addressed at the transport layer. It is orthogonal to
/// [`ContextModeState`] (the *crypto axis*: MLS vs. per-author broadcast
/// keys). The two MUST agree — an [`ContextModeState::Encrypted`] context
/// is always [`ContextRouting::Pseudonymous`] and a
/// [`ContextModeState::Broadcast`] context is always
/// [`ContextRouting::Broadcast`]. Construction enforces this and the
/// encrypted send path `debug_assert!`s it.
///
/// # Why an enum instead of `Option<[u8; 32]>` + a map
///
/// The previous shape carried `local_pseudonym: Option<[u8; 32]>` plus a
/// free-standing `pseudonym_registry`. That made "encrypted context with no
/// pseudonym" representable, and the send path papered over it by unioning
/// the shared `context_routing_id(context_id)` into the fan-out — a value any
/// relay can derive from the public context ID. A relay that received the
/// identical MLS blob at the shared RID could correlate every sender in the
/// context, defeating the unlinkability the pseudonym scheme exists to
/// provide. Making "encrypted-without-pseudonym" *unrepresentable* deletes
/// that fallback at the type level: an encrypted context always carries a
/// real `local_pseudonym`, and application data only ever fans out to known
/// peer pseudonyms.
///
/// Exactly one variant is present per context; there is no `Option` or
/// "unknown" state. Constructors build the correct variant from
/// [`ContextModeState`]-equivalent mode information at
/// creation / join / restore time.
///
/// `DID` is `#[serde(transparent)]` over `String`, so the serialized wire
/// format for `pseudonym_registry` is a plain string-keyed map — wire
/// compatible with the historical `HashMap<String, [u8; 32]>` snapshot field.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum ContextRouting {
    /// Encrypted (MLS) context. The local member's pseudonym routing ID is
    /// pre-derived at the FFI boundary via `KeyCustody::derive_pseudonym`.
    /// Peers' pseudonyms are learned via `PseudonymAnnouncement` MLS
    /// application messages and keyed by DID so `send_message` can fan out
    /// to each member's pseudonym.
    Pseudonymous {
        /// This member's pseudonym-derived routing ID.
        ///
        /// Private: the only constructors are [`ContextRouting::for_mode`] and
        /// deserialization. Keeping the field private means external code cannot
        /// build a `Pseudonymous` variant with an arbitrary (e.g. zero or
        /// reserved) pseudonym outside the constructor's discipline, so the
        /// "encrypted-without-a-real-pseudonym is unrepresentable" guarantee is
        /// type-enforced rather than convention. Serde can still (de)serialize a
        /// private field — the persisted wire format is unchanged.
        #[serde(with = "serde_bytes")]
        local_pseudonym: [u8; 32],
        /// Known members' pseudonym routing IDs, keyed by DID. Private for the
        /// same reason as `local_pseudonym`; mutate via [`peer_registry_mut`].
        ///
        /// [`peer_registry_mut`]: ContextRouting::peer_registry_mut
        pseudonym_registry: HashMap<DID, [u8; 32]>,
    },
    /// Broadcast context. Uses `SHA-256(context_id)` as the shared routing ID
    /// per spec §5.14; no pseudonym state is retained. Broadcast contexts are
    /// still content-encrypted (per-author AES-256-GCM) — this enum splits on
    /// the *routing strategy*, not on whether encryption is in use.
    Broadcast,
}

impl ContextRouting {
    /// Builds the routing variant for a context from its broadcast flag and
    /// the caller-derived local pseudonym (§9.10.4, §5.14).
    ///
    /// Broadcast contexts ignore `local_pseudonym` and carry no pseudonym
    /// state. Encrypted contexts embed the pseudonym verbatim and start with
    /// an empty peer registry (peers are learned via `PseudonymAnnouncement`).
    ///
    /// Threading a concrete `[u8; 32]` (not an `Option`) through the encrypted
    /// branch makes "encrypted context with no pseudonym" unrepresentable —
    /// the FFI boundary hard-fails pseudonym derivation for encrypted contexts
    /// before this is ever reached, so there is no silent fall-back to the
    /// shared routing ID.
    #[must_use]
    pub fn for_mode(is_broadcast: bool, local_pseudonym: [u8; 32]) -> Self {
        if is_broadcast {
            Self::Broadcast
        } else {
            Self::Pseudonymous {
                local_pseudonym,
                pseudonym_registry: HashMap::new(),
            }
        }
    }

    /// Returns the local member's pseudonym routing ID for a pseudonymous
    /// (encrypted) context, or `None` for a broadcast context.
    #[must_use]
    pub const fn local_pseudonym(&self) -> Option<[u8; 32]> {
        match self {
            Self::Pseudonymous {
                local_pseudonym, ..
            } => Some(*local_pseudonym),
            Self::Broadcast => None,
        }
    }

    /// Returns a read-only view of the peer pseudonym registry for a
    /// pseudonymous (encrypted) context, or `None` for a broadcast context.
    #[must_use]
    pub const fn peer_registry(&self) -> Option<&HashMap<DID, [u8; 32]>> {
        match self {
            Self::Pseudonymous {
                pseudonym_registry, ..
            } => Some(pseudonym_registry),
            Self::Broadcast => None,
        }
    }

    /// Returns a mutable view of the peer pseudonym registry for a
    /// pseudonymous (encrypted) context, or `None` for a broadcast context.
    #[must_use]
    pub const fn peer_registry_mut(&mut self) -> Option<&mut HashMap<DID, [u8; 32]>> {
        match self {
            Self::Pseudonymous {
                pseudonym_registry, ..
            } => Some(pseudonym_registry),
            Self::Broadcast => None,
        }
    }

    /// Returns `true` if this is a broadcast-routed context.
    #[must_use]
    pub const fn is_broadcast(&self) -> bool {
        matches!(self, Self::Broadcast)
    }

    /// Sets the local member's pseudonym. No-op on a broadcast context, which
    /// carries no pseudonym state.
    pub const fn set_local_pseudonym(&mut self, p: [u8; 32]) {
        if let Self::Pseudonymous {
            local_pseudonym, ..
        } = self
        {
            *local_pseudonym = p;
        }
    }
}

// ---------------------------------------------------------------------------
// ContextModeState — discriminated union over encrypted / broadcast
// ---------------------------------------------------------------------------

/// Discriminated union over the two context modes. Matches the plan's
/// contract: exactly one variant is present per actor; the mode is set
/// at actor construction and never changes.
///
/// Both variants are boxed so the enum's stack footprint (and the stack
/// footprint of every [`PerContextState`] that carries it) is bounded
/// by a pointer regardless of which variant is present.
/// [`ContextCryptoState`] is ~1.8 KB (dominated by the
/// [`scp_mls::group::ScpMlsGroup`]'s internal OpenMLS
/// storage) and [`BroadcastState`] is ~232 bytes (per-author maps +
/// rotation queue); boxing both avoids the `large_enum_variant` clippy
/// finding and prevents any future per-variant growth from forcing
/// another stack-size change.
#[derive(Debug)]
pub enum ContextModeState {
    /// Standard MLS-encrypted context.
    Encrypted(Box<ContextCryptoState>),
    /// Broadcast context (per-author AES-256-GCM, no MLS group).
    Broadcast(Box<BroadcastState>),
}

impl ContextModeState {
    /// Is this context in broadcast mode?
    #[must_use]
    pub const fn is_broadcast(&self) -> bool {
        matches!(self, Self::Broadcast(_))
    }

    /// Is this context in encrypted (MLS) mode?
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        matches!(self, Self::Encrypted(_))
    }
}

// ---------------------------------------------------------------------------
// ClassSState — the actor's Class-S (fail-closed-persist) state subset
// ---------------------------------------------------------------------------

/// The Class-S subset of [`PerContextState`] (ADR-049 §9).
///
/// Groups the cross-context-saga fields whose mutation is a security-critical
/// downward-authorization or anti-replay transition that MUST be persisted
/// fail-closed before the operation is acknowledged. A ≤50 ms coalesce-window
/// rollback of any of these re-opens a window the caller already observed as
/// closed (a replay, a re-invoke, a double-settle).
///
/// This is a behaviour-neutral DATA SPLIT: the fields keep their `pub(crate)`
/// visibility and existing call sites reach them through the lengthened path
/// `class_s.<field>`. Privatizing them behind a persist-on-commit mutator
/// boundary (so the fail-closed invariant becomes a compile error to violate,
/// retiring the source-text gate) is a separate later PR.
///
/// # Not `Clone`
///
/// `saga_pending` holds [`SagaPreparedState`], which deliberately implements
/// no `Clone` / `Serialize` (the §9.4.3 bearer-leak barrier), and
/// `xctx_nonce_dedup` is a [`NonceDedup`] cache. So [`Self::snapshot`] /
/// [`Self::restore`] project through the sanctioned mirrors
/// ([`SagaPreparedStateSnapshot`](crate::context::supervisor::saga_prepared_state::SagaPreparedStateSnapshot),
/// [`NonceDedup::entries`] / [`NonceDedup::from_entries_with_ttl`]); the three
/// committed/reservation witnesses are `Clone` and snapshot by clone.
pub struct ClassSState {
    /// Staged cross-context saga mutations awaiting Commit or Abort. Plan
    /// §"Cross-context saga protocol" restricts to at most one entry —
    /// concurrent sagas against the same actor are serialized by
    /// rejecting new Prepare while this map is non-empty.
    pub(crate) saga_pending: HashMap<SagaId, SagaPreparedState>,

    /// Target-side (B-owned) anti-replay nonce-dedup cache for cross-context
    /// outlet invocation (spec §6.2.4 "Freshness / anti-replay"). Keyed by the
    /// 16-byte envelope `nonce`; bounded 10,000-entry / 5-minute-TTL /
    /// oldest-first eviction (the same [`NonceDedup`] discipline §6.2.2 uses).
    /// **B — the Prepare-B verifying party — owns this cache**: the
    /// freshness/replay state lives where the authorization decision is made,
    /// since Prepare-A runs on the caller's actor and cannot authoritatively
    /// dedup against B's state. Prepare-B rejects a duplicate nonce and records
    /// a fresh one on accept.
    ///
    /// **Class-S persisted — crash survival is load-bearing.** This cache IS
    /// captured into the Class-S snapshot (its `(nonce, accepted-at-secs)`
    /// entries are serialized by `xctx_nonce_dedup_snapshot`) and rehydrated on
    /// restore (`NonceDedup::from_entries_with_ttl`). It is NOT reconstructable
    /// freshness state: if it were dropped from the snapshot, a crash between
    /// accept and the coalesce-window persist would clear the seen-nonce set and
    /// re-open the §6.2.4 replay window an attacker could exploit by replaying a
    /// captured envelope across the restart boundary. The persistence + restore
    /// of this cache is what closes that window; do not delete it from the
    /// snapshot.
    ///
    /// **Replay-bound invariant (defense-in-depth).** The cache is bounded by
    /// `NONCE_DEDUP_CAPACITY` (10,000) with oldest-first eviction; the replay
    /// guarantee holds only while the *TTL*
    /// ([`SAGA_NONCE_DEDUP_TTL_SECS`](crate::context::actor::handlers::saga::SAGA_NONCE_DEDUP_TTL_SECS),
    /// 600 s — 2× the freshness skew tolerance), not eviction, is what drops an
    /// entry. That requires the maximum number of distinct nonces a caller can
    /// land within the TTL window to stay safely below the capacity. The
    /// per-interface §6.2.0.2 inbound rate limit
    /// (`InboundPolicy::max_calls_per_minute`) caps that accept rate: worst-case
    /// `max_calls_per_minute × (SAGA_NONCE_DEDUP_TTL_SECS / 60)` distinct nonces
    /// over the window. The default (60/min ⇒ 600 over the 10-minute window)
    /// holds with a ~16× margin; the [`crate::context::actor::handlers::saga`]
    /// tests assert a ≥2× margin against the default and a documented
    /// configuration ceiling so a future high `max_calls_per_minute` cannot
    /// silently erode the eviction-based bound.
    pub(crate) xctx_nonce_dedup: NonceDedup,

    /// Target-side (B-owned) durable capture of COMMITTED cross-context outlet
    /// invocations, keyed by `SagaId` (spec §6.2.4 "Exactly-once execution with
    /// durable output capture"). Populated at Commit-B settle with the captured
    /// outlet output, the signed [`CrossContextOutletReceipt`](scp_protocol::context::outlets::cross_context_saga::CrossContextOutletReceipt),
    /// and the `outlet_invoked_event_id`, so a Commit replayed after a crash
    /// (§17.16.4) re-emits the STORED output and the IDENTICAL signed receipt —
    /// NEVER re-invoking the outlet, never minting a fresh event id.
    ///
    /// **Class S** — synchronously persisted fail-closed (ADR-049 §9), the same
    /// discipline as [`Self::saga_pending`]: a crash that rolled the capture
    /// back behind an acked Commit-B would re-invoke the outlet on replay and
    /// re-sign a divergent receipt, breaking the exactly-once + receipt-
    /// reproducibility guarantees. Survives same-node restore; dropped (like
    /// `saga_pending`) on cross-node export/import — a foreign node must never
    /// drive local Commit replay.
    ///
    /// **Retention bound.** A `SagaId`-keyed idempotency witness; one entry per
    /// committed cross-context invocation, retained for the lifetime of the
    /// context. It is intentionally append-only over the saga-journal retention
    /// horizon: an entry is load-bearing only while a crash-replayed Commit
    /// could still re-drive this saga (§17.16.4), i.e. until the saga journal
    /// itself can no longer surface the saga for replay. Past that horizon an
    /// entry is dead weight, so this map's compaction is tied to (and must not
    /// outlive) saga-journal compaction — when the journal gains a retention cut
    /// (the point past which replay is impossible), this map is pruned to the
    /// same horizon. Until that seam exists the map grows with committed-saga
    /// count; this note exists so that growth is a tracked retention decision,
    /// not a silent leak. No speculative compaction is built here.
    pub(crate) xctx_committed_outputs:
        HashMap<SagaId, crate::context::supervisor::saga_prepared_state::CommittedOutletInvocation>,

    /// Caller-side (A-owned) durable set of COMMITTED cross-context outlet
    /// invocations, keyed by `SagaId` (spec §6.2.4 "Commit", caller side;
    /// §17.16.4 crash recovery: "A re-acks its `CrossContextOutletInvoked` append
    /// and re-settles escrow as a no-op"). Commit-A inserts the `SagaId` here as
    /// the idempotency witness BEFORE acking; a replayed Commit-A finds the
    /// witness and re-acks without re-settling the escrow or re-appending the
    /// `CrossContextOutletInvoked` record.
    ///
    /// **Class S** — synchronously persisted fail-closed (ADR-049 §9): without
    /// it, a crash that rolled the witness back behind an acked Commit-A would
    /// double-settle the escrow on replay. Survives same-node restore; dropped
    /// on cross-node export/import (a foreign saga must never drive local replay).
    ///
    /// **Retention bound.** Same discipline as
    /// [`Self::xctx_committed_outputs`]: one `SagaId` per committed Commit-A,
    /// retained for the context's lifetime and load-bearing only while a
    /// crash-replayed Commit-A could still re-drive the saga (§17.16.4). Its
    /// compaction is tied to saga-journal retention — pruned to the journal's
    /// retention horizon once that horizon exists. Until then it grows with
    /// committed-saga count; documented here so the growth is a tracked
    /// retention decision rather than a silent memory-growth vector. No
    /// speculative compaction is built here.
    pub(crate) xctx_committed_invocations: std::collections::HashSet<SagaId>,

    /// Caller-side (A-owned) durable reversal records for in-flight
    /// cross-context outlet-invocation Prepare-A reservations, keyed by `SagaId`
    /// (spec §6.2.4 "Reservation release on every terminal path"). Prepare-A
    /// inserts a [`CallerReservationRecord`](crate::context::supervisor::saga_prepared_state::CallerReservationRecord)
    /// here in the SAME Class-S snapshot as the velocity / budget /
    /// hard-rate-limit deduction + escrow authorization it persists, so the
    /// deduction and the means to reverse it land atomically.
    ///
    /// **Why this exists.** The live
    /// [`OutletEconomyReservation`](crate::context::outlets_helpers::OutletEconomyReservation)
    /// RAII carrier that normally reverses a caller reservation lives ONLY in
    /// the supervisor's in-memory saga context and dies with an actor/process
    /// crash. A `PreparingB`-window crash drives a CLEAN abort
    /// (`Abort { reservation: None }`) to the caller actor; without a durable
    /// record the persisted deduction could never be reversed and the external
    /// escrow never voided — a durable over-charge + escrow leak. This map lets
    /// the crash-recovery abort reverse the reservation BY `SagaId`, without the
    /// carrier.
    ///
    /// **Carrier-authoritative; record is the crash-only fallback.** The live
    /// `Abort { Some(reservation) }` and Commit-A paths reverse / settle via the
    /// carrier, then CONSUME the record (remove without re-reversing). The
    /// record's own reversal runs ONLY on the carrier-absent `Abort { None }`
    /// path, so the two reversal paths are mutually exclusive by construction —
    /// a saga is never double-reversed.
    ///
    /// **Class S** — synchronously persisted fail-closed (ADR-049 §9): a crash
    /// that rolled an inserted record back behind an acked Prepare-A would lose
    /// the only durable reversal handle for a deduction that DID persist.
    /// Survives same-node restore; dropped on cross-node export/import (caller
    /// economy is local — a foreign node must never drive local reversal),
    /// exactly like [`Self::xctx_committed_invocations`].
    ///
    /// **Retention bound.** One entry per in-flight caller Prepare-A; consumed
    /// (removed) on EVERY terminal path — Commit-A success, live abort, and
    /// crash-recovery abort — so the map holds only genuinely in-flight caller
    /// reservations and does not accumulate over the context lifetime.
    pub(crate) xctx_caller_reservations: std::collections::HashMap<
        SagaId,
        crate::context::supervisor::saga_prepared_state::CallerReservationRecord,
    >,

    /// §7.3.8 value-caveat runtime enforcement counters, keyed by the
    /// invocation-authorizing UCAN's CID. One [`CaveatCounters`] record per
    /// delegation holds the durable `max_calls` / `amount_max_cumulative` /
    /// `rate_window` accounting the local synchronous caveat check
    /// ([`InvocationCaveats::check_invocation_local`](scp_protocol::trust::caveats::InvocationCaveats::check_invocation_local))
    /// cannot enforce on its own.
    ///
    /// **Class S — consumed capacity must NEVER un-consume.** A committed
    /// consume rides the fail-closed Class-S persist (ADR-049 §9): it is
    /// mutated ONLY inside a `commit_class_s_keep`-family closure, so a ≤50 ms
    /// coalesce-window crash after the caller observed the invocation succeed
    /// cannot roll the consume back and re-open the spend/rate window. The
    /// `class_c_view()` (coalesced best-effort) path MUST NOT touch this map.
    ///
    /// **Not a `NonceDedup`-style bounded cache.** Entries accumulate one per
    /// distinct invocation-authorizing UCAN CID observed in this context;
    /// whole-token revocation is the eviction seam (a later slice). Same-node
    /// restore rehydrates the map; cross-node public export strips it (a
    /// foreign node starts its own accounting) — see the snapshot wiring.
    pub(crate) caveat_counters: HashMap<String, crate::trust::caveat_counters::CaveatCounters>,

    /// Fix-D durable crash-recovery records for in-flight STREAMING
    /// reservations, keyed by the stream `request_id` (hex). Each
    /// [`StreamReservationRecord`](crate::context::outlets::invoke::StreamReservationRecord)
    /// captures the §5.4.5 open-time escrow HOLD + the §7.3.8 `AmountCumulative`
    /// counter reserve a stream open debited, so the restore-time
    /// [`ReconcileStreamReservations`](crate::context::actor::commands::OutletsCommand::ReconcileStreamReservations)
    /// sweep can RELEASE them when the off-mailbox pump — a `tokio` task that
    /// SURVIVES an actor crash + respawn — would otherwise strand them (its
    /// close-time settle lands on the respawned instance, mismatches the bumped
    /// generation, and is dropped by the confused-deputy guard).
    ///
    /// **Class S — a persisted reserve must NEVER lose its release handle.**
    /// Inserted at pump open in the SAME fail-closed `commit_class_s_keep` family
    /// as (after) the durable reservations it tracks, so the reserve and the
    /// means to reverse it survive a coalesce-window crash together (ADR-049 §9).
    /// Consumed (removed) on EVERY terminal path — the clean close-time settle
    /// AND the crash-recovery sweep — so the map holds only genuinely in-flight
    /// streams and does not accumulate. Same-node restore rehydrates it;
    /// cross-node public export strips it (invoker economy + counters are local),
    /// exactly like [`Self::caveat_counters`].
    pub(crate) stream_reservations:
        HashMap<String, crate::context::outlets::invoke::StreamReservationRecord>,
}

/// Lossless, `Clone`-able mirror of [`ClassSState`] (ADR-049 §9).
///
/// The live sub-struct cannot derive `Clone` (its `saga_pending` holds the
/// non-`Clone` §9.4.3 bearer-barrier [`SagaPreparedState`], and
/// `xctx_nonce_dedup` is a cache). This snapshot captures each field through
/// its sanctioned mirror so [`ClassSState::restore`] can rebuild a value-stable
/// copy. Used only for the in-memory snapshot/restore round-trip — the on-disk
/// [`ContextSnapshot`](crate::context::state::ContextSnapshot) format is
/// unchanged (these fields continue to serialize as their existing flat
/// snapshot fields).
#[allow(
    dead_code,
    reason = "ADR-049 §9 PR2a is a behaviour-neutral data split + mirror snapshot. The snapshot/restore mirror's first PRODUCTION consumer is the later privatization PR (restore wiring through the mutator-combinator boundary); for now it is exercised by the crate-internal lossless round-trip unit test. Mirrors the PR1 ClassSCell scaffolding precedent."
)]
pub struct ClassSStateSnapshot {
    /// Mirror of [`ClassSState::saga_pending`], each entry projected through
    /// [`SagaPreparedStateSnapshot::from_prepared`](crate::context::supervisor::saga_prepared_state::SagaPreparedStateSnapshot::from_prepared).
    pub(crate) saga_pending:
        HashMap<SagaId, crate::context::supervisor::saga_prepared_state::SagaPreparedStateSnapshot>,
    /// `(nonce → first-seen-secs)` entries of [`ClassSState::xctx_nonce_dedup`].
    pub(crate) xctx_nonce_dedup_entries: HashMap<[u8; 16], u64>,
    /// TTL of [`ClassSState::xctx_nonce_dedup`], captured so restore rebuilds
    /// the same replay window via
    /// [`NonceDedup::from_entries_with_ttl`].
    pub(crate) xctx_nonce_dedup_ttl_secs: u64,
    /// Mirror of [`ClassSState::xctx_committed_outputs`].
    pub(crate) xctx_committed_outputs:
        HashMap<SagaId, crate::context::supervisor::saga_prepared_state::CommittedOutletInvocation>,
    /// Mirror of [`ClassSState::xctx_committed_invocations`].
    pub(crate) xctx_committed_invocations: std::collections::HashSet<SagaId>,
    /// Mirror of [`ClassSState::xctx_caller_reservations`].
    pub(crate) xctx_caller_reservations: std::collections::HashMap<
        SagaId,
        crate::context::supervisor::saga_prepared_state::CallerReservationRecord,
    >,
    /// Mirror of [`ClassSState::caveat_counters`]. [`CaveatCounters`] is
    /// `Clone`, so this snapshots by direct clone (no projection needed).
    pub(crate) caveat_counters: HashMap<String, crate::trust::caveat_counters::CaveatCounters>,
    /// Mirror of [`ClassSState::stream_reservations`] (Fix-D). The
    /// [`StreamReservationRecord`](crate::context::outlets::invoke::StreamReservationRecord)
    /// is `Clone` + serde, so this snapshots by direct clone (no projection).
    pub(crate) stream_reservations:
        HashMap<String, crate::context::outlets::invoke::StreamReservationRecord>,
}

#[allow(
    dead_code,
    reason = "ADR-049 §9 PR2a is a behaviour-neutral data split + mirror snapshot. The snapshot/restore mirror's first PRODUCTION consumer is the later privatization PR (restore wiring through the mutator-combinator boundary); for now it is exercised by the crate-internal lossless round-trip unit test. Mirrors the PR1 ClassSCell scaffolding precedent."
)]
impl ClassSState {
    /// Project this Class-S subset onto its `Clone`-able mirror (ADR-049 §9).
    /// Lossless inverse of [`Self::restore`].
    #[must_use]
    pub(crate) fn snapshot(&self) -> ClassSStateSnapshot {
        use crate::context::supervisor::saga_prepared_state::SagaPreparedStateSnapshot;
        ClassSStateSnapshot {
            saga_pending: self
                .saga_pending
                .iter()
                .map(|(id, prepared)| {
                    (
                        id.clone(),
                        SagaPreparedStateSnapshot::from_prepared(prepared),
                    )
                })
                .collect(),
            xctx_nonce_dedup_entries: self.xctx_nonce_dedup.entries(),
            xctx_nonce_dedup_ttl_secs: self.xctx_nonce_dedup.ttl_secs(),
            xctx_committed_outputs: self.xctx_committed_outputs.clone(),
            xctx_committed_invocations: self.xctx_committed_invocations.clone(),
            xctx_caller_reservations: self.xctx_caller_reservations.clone(),
            caveat_counters: self.caveat_counters.clone(),
            stream_reservations: self.stream_reservations.clone(),
        }
    }

    /// Restore this Class-S subset from its mirror (ADR-049 §9), rehydrating
    /// `saga_pending` via `into_prepared` and `xctx_nonce_dedup` from its
    /// captured entries + TTL. Lossless inverse of [`Self::snapshot`].
    pub(crate) fn restore(&mut self, snap: ClassSStateSnapshot) {
        self.saga_pending = snap
            .saga_pending
            .into_iter()
            .map(|(id, mirror)| (id, mirror.into_prepared()))
            .collect();
        self.xctx_nonce_dedup = NonceDedup::from_entries_with_ttl(
            snap.xctx_nonce_dedup_entries,
            snap.xctx_nonce_dedup_ttl_secs,
        );
        self.xctx_committed_outputs = snap.xctx_committed_outputs;
        self.xctx_committed_invocations = snap.xctx_committed_invocations;
        self.xctx_caller_reservations = snap.xctx_caller_reservations;
        self.caveat_counters = snap.caveat_counters;
        self.stream_reservations = snap.stream_reservations;
    }
}

// ---------------------------------------------------------------------------
// PerContextState — the actor's owned state payload
// ---------------------------------------------------------------------------

/// Per-context actor state. Owned by exactly one [`ContextActor`](crate::context::actor::ContextActor) for its
/// entire lifetime; no interior mutability, no locks, no `Arc`.
///
/// Field set is the contract the plan's handler signatures rely on
/// (§"ContextActor" dispatch loop + §"Submodule organization"). Every
/// field is populated in production by the actor-shape handlers; the
/// [`Self::new_for_test_encrypted`] / [`Self::new_for_test_broadcast`]
/// fixtures default the rest for test use.
///
/// # Field-for-field parity with the deleted legacy state
///
/// This struct owns every field the now-deleted legacy per-context state
/// carried, so the completed handler-body migration moved each call
/// mechanically off `manager.foo` onto `state.foo`. The new-per-actor
/// fields at the bottom of the struct (`send_tracker`, `recv_tracker`,
/// `saga_pending`, `welcome_scratchpad`, `lifecycle_state`, `mode`) have
/// no legacy equivalent — they replace the `per-context-state Mutex`
/// lock-based model.
///
/// # Field readers
///
/// Every field is read and mutated directly by the actor-shape handlers
/// and their helper modules — there is no dead code here, and no
/// `#[allow(dead_code)]` is applied. The private-type sub-state fields
/// are all live: `governance` (e.g. `handlers/governance.rs` off
/// `state.governance.engine`), `epoch` (`handlers/trust_recovery.rs`
/// reading `state.epoch.mls_epoch`), `ttl` (`ContextActor::reconcile_timers`
/// reading `state.ttl.timer.deadline_unix_secs`), and `access` (the governance,
/// messaging, and queries helpers reading `state.access.access_key_store`
/// and `state.access.read_exclusion_list`).
pub struct PerContextState {
    // -----------------------------------------------------------------
    // Identity + lifetime fields
    // -----------------------------------------------------------------
    /// Deterministic context identifier (SHA-256 of canonical creation
    /// parameters — spec §5.2). Stable for the actor's entire lifetime.
    pub context_id: [u8; 32],

    /// Unix-ms timestamp of first actor instantiation for this context.
    /// Preserved across respawn via snapshot — new actor instances for
    /// the same context share one `created_at`.
    ///
    /// This is a LOCAL instantiation timestamp (the creating/restoring
    /// member's clock) and is NOT convergent across members — do not use
    /// it as a base for any cross-member deadline. The convergent
    /// creator-assigned creation time lives in
    /// [`Self::creation_timestamp_secs`].
    pub created_at: u64,

    /// Convergent creator-assigned context-creation timestamp (Unix
    /// seconds). This is the identical value the creator stamped on the
    /// `ContextCreated` event-log leaf and that every member copies
    /// (§7.3.1, §9.9.3) — NOT each member's local `now()`. It is the
    /// convergent base for deadlines derived from creation time (e.g. the
    /// TTL expiry deadline = `creation_timestamp_secs + params.ttl`), so
    /// every member computes the identical absolute deadline regardless of
    /// when their local timer was armed. Carried through the export
    /// snapshot so restore/import preserve the convergent base rather than
    /// re-deriving from importer-local `now()`.
    pub creation_timestamp_secs: u64,

    /// Monotonic generation counter inherited from legacy
    /// [`crate::context::state::PerContextState::generation`]
    /// (manager/mod.rs). Legacy used it to detect the confused-deputy
    /// scenario on lock-drop / re-acquire. The actor model does not
    /// rely on a generation counter (each actor IS a generation in
    /// the supervisor's `DashMap<String, ContextActorHandle>`), but
    /// 12a carries the field field-for-field so 12b+ handler migrations
    /// can keep populating it until every consumer is ported. 12d will
    /// drop the field if no consumer survives the handler migration.
    pub generation: u64,

    /// Full-fat context handle (creation params, lifecycle FSM). Mirrors
    /// legacy `state::PerContextState::handle`.
    pub handle: ContextHandle,

    // -----------------------------------------------------------------
    // Membership + role fields
    // -----------------------------------------------------------------
    /// Legacy membership record (per-DID role / tokens / sequence).
    /// Mirrors legacy `state::PerContextState::membership`. Coexists
    /// with [`Self::members`] during the 12a→12d window: the shim still
    /// delegates to legacy and reads the rich `MembershipState`; the
    /// 12b+ handler-body migrations decide per-handler which of the two
    /// storage sites to authoritatively consolidate onto before 12d
    /// removes the unused one.
    pub membership: MembershipState,

    /// Active-member DID set — the simpler companion to
    /// [`Self::membership`]. The original skeleton field (commits 6-11);
    /// retained for parity with the shim's accessor surface.
    pub members: HashSet<DID>,

    /// Roles, ceiling, and assignments. Mirrors legacy
    /// `state::PerContextState::role_state`.
    pub role_state: ContextRoleState,

    // -----------------------------------------------------------------
    // Event buffers + logs
    // -----------------------------------------------------------------
    /// RFC-6962 Merkle event log. `None` until the first event; some
    /// actor constructions (test fixtures, mid-restore) run with it
    /// unset. Wraps [`scp_event_log::EventLog`] for the actor's
    /// `EventLogPersistence` path.
    pub event_log: Option<ContextEventLog>,

    /// Receive event buffer (bounded 1000-entry deque). Mirrors legacy
    /// `state::PerContextState::receive_buffer`.
    pub receive_buffer: ReceiveBuffer,

    /// RECENT per-payee payment receipts captured in this context (spec
    /// §19.11). Bounded, in-memory, lost on actor respawn — NOT the complete
    /// persisted payment history.
    ///
    /// `PaymentReceived` is per-payee application activity, excluded from the
    /// canonical Merkle log (ADR-011 amendment exclusion taxonomy §2). Receipts
    /// are surfaced from this local buffer — NOT the durable event log — by the
    /// `payment_history` query, so the count diverges per member without
    /// perturbing the convergent `event_log_merkle_root` (§9.9.3).
    ///
    /// # Bounded ring (oldest-evicted)
    ///
    /// Capacity is capped at
    /// [`DEFAULT_BUFFER_CAPACITY`](scp_protocol::context::membership::DEFAULT_BUFFER_CAPACITY)
    /// — the same bound as the sibling `receive_buffer` ring — so a long-lived
    /// paid context cannot grow this buffer without limit (memory-growth DoS).
    /// When the buffer is full a new receipt evicts the oldest (`pop_front`
    /// before `push_back`). This buffer is therefore a SLIDING WINDOW of the
    /// most recent captures, NOT the authoritative payment ledger; the full
    /// persisted history is a separate, store-backed surface (not yet wired —
    /// see [`crate::economy::receipt::payment_history`]).
    pub payment_receipts: VecDeque<PaymentReceipt>,

    // -----------------------------------------------------------------
    // Mode-specific state
    // -----------------------------------------------------------------
    /// Broadcast-mode metadata (SCP-227). `Some` for `ContextMode::Broadcast`,
    /// `None` for encrypted contexts. Distinct from
    /// [`Self::mode`](ContextModeState) — the `mode` field carries the
    /// per-author AES-256-GCM keys ([`BroadcastState`]); this field
    /// carries the subscriber roster, admission policy, and author
    /// state the `BroadcastContext` type owns at the spec layer (spec
    /// §5.14). Mirrors legacy
    /// `state::PerContextState::broadcast_context`.
    pub broadcast_context: Option<ProtocolBroadcastContext>,

    /// Active migration state (§5.11A). `Some` when the context is in
    /// `MigratingOut` state. Mirrors legacy
    /// `state::PerContextState::migration_state`.
    pub migration_state: Option<MigrationState>,

    // -----------------------------------------------------------------
    // Governance + economy
    // -----------------------------------------------------------------
    /// Governance engine + proposals + tooling per-context state
    /// (ADR-031). Mirrors legacy `state::PerContextState::governance`.
    /// Type is elevated from private to `pub(crate)` by commit 12a so
    /// the actor can carry it; field visibility matches the type
    /// (`pub(crate)`) because the `GovernanceState` struct itself cannot
    /// be named outside this crate. Commit 12d deletes both it and the
    /// legacy manager module together.
    pub(crate) governance: GovernanceState,

    // -----------------------------------------------------------------
    // MLS + access control + TTL
    // -----------------------------------------------------------------
    /// MLS epoch + reconnection state (§5.9, §23.11). Mirrors legacy
    /// `state::PerContextState::epoch`. Type is elevated from private
    /// to `pub(crate)` by commit 12a; field visibility matches.
    pub(crate) epoch: EpochState,

    /// Access-control / CEK-wrapping exclusion list (ADR-038, §9.17).
    /// Mirrors legacy `state::PerContextState::access`. Type is
    /// elevated from private to `pub(crate)` by commit 12a; field
    /// visibility matches.
    ///
    /// This is the sole authoritative storage site for the
    /// `access_key_store`: commit 12d removed the vestigial duplicate
    /// that briefly lived on [`ContextCryptoState`].
    pub(crate) access: AccessControlState,

    /// TTL timer + extension state (SCP-021). Mirrors legacy
    /// `state::PerContextState::ttl`. Type is elevated from private
    /// to `pub(crate)` by commit 12a; field visibility matches.
    pub(crate) ttl: TtlState,

    // -----------------------------------------------------------------
    // Pseudonyms / routing (§9.10.4, §5.14)
    // -----------------------------------------------------------------
    /// Per-context routing strategy (§9.10.4, §5.14).
    ///
    /// Encrypted contexts carry the member's pre-derived pseudonym routing
    /// ID and a registry of peer pseudonyms keyed by DID. Broadcast contexts
    /// use a shared routing ID and carry no pseudonym state. The variant is
    /// fixed at creation / join / restore time and MUST agree with
    /// [`Self::mode`](ContextModeState).
    pub routing: ContextRouting,

    // -----------------------------------------------------------------
    // Anti-replay + reorder buffers (§9.8.2, §9.8.5)
    // -----------------------------------------------------------------
    /// Per-sender sequence tracker for anti-replay protection (§9.8.2).
    /// Mirrors legacy `state::PerContextState::sequence_tracker`.
    pub sequence_tracker: SequenceTracker,

    /// Per-sender reorder buffer for out-of-order message delivery
    /// (§9.8.5). Mirrors legacy
    /// `state::PerContextState::reorder_buffer`.
    pub reorder_buffer: ReorderBuffer,

    // -----------------------------------------------------------------
    // MLS Commit retry + checkpointing (§9.9.3, PR #1606 C6)
    // -----------------------------------------------------------------
    /// Persistent retry queue for MLS Commit broadcasts that failed at
    /// the transport layer after local state already mutated (PR
    /// #1606 C6). Mirrors legacy
    /// `state::PerContextState::pending_commits`.
    pub pending_commits: VecDeque<PendingCommit>,

    /// Fail-close marker set when a `PendingCommit` exhausts its retry
    /// budget. While `Some`, all context-mutating operations return
    /// `ContextError::CommitBroadcastFault` until cleared. Mirrors
    /// legacy `state::PerContextState::commit_fault`.
    pub commit_fault: Option<CommitFaultMarker>,

    /// Number of event-log appends since the last consistency
    /// checkpoint (§9.9.3). Mirrors legacy
    /// `state::PerContextState::checkpoint_events_since`.
    pub checkpoint_events_since: u64,

    /// Unix timestamp (seconds) of the last consistency checkpoint
    /// (§9.9.3). Mirrors legacy
    /// `state::PerContextState::checkpoint_last_time_secs`.
    pub checkpoint_last_time_secs: u64,

    /// Locally generated consistency checkpoints for equivocation
    /// detection (§9.9.3). Mirrors legacy
    /// `state::PerContextState::checkpoints`.
    pub checkpoints: Vec<ConsistencyCheckpoint>,

    /// Set of distinct divergent checkpoints `(event_count, merkle_root)`
    /// already recorded per remote checkpoint sender DID (§9.9.3 replay
    /// defense). A re-presented divergence whose `(count, remote_merkle_root)`
    /// is already in the sender's set is a no-op in
    /// `compare_remote_checkpoint`. A NEW root at an already-seen count is
    /// treated as fresh evidence — two members can equivocate with different
    /// forged roots at the same height, and each is a distinct §9.9.4 security
    /// event.
    ///
    /// This in-memory set is the SOLE dedup mechanism. A divergence is NOT
    /// appended to the durable Merkle event log: an equivocation record is
    /// minted locally by the receiver and is not part of the
    /// sender-authenticated leaf sequence, so logging it would let two honest
    /// receivers compute divergent roots for the same context and
    /// false-positive the very §9.9.3 detection it records. Because there is no
    /// durable append, there is no `local_count` advance and therefore no
    /// durable cross-respawn backstop: the set resets to empty when a new actor
    /// instance respawns. The bounded consequence is that the FIRST
    /// re-presentation of a previously-seen divergence after a respawn re-emits
    /// one duplicate alert — an acceptable, bounded duplicate notification of a
    /// real §9.9.4 event, not a correctness or replay-amplification bug.
    ///
    /// Emission of the §9.9.4 alert is ALWAYS-ON; only INSERTION into this set
    /// is cap-gated. Bounded per sender at
    /// [`scp_protocol::sync::MAX_SEQUENTIAL_COMMITS`] distinct entries: once a
    /// sender's set is full the alert is still EMITTED (a §9.9.4 security event
    /// is never silently discarded) but no further `(count, root)` is inserted,
    /// capping the memory a malicious sender can pin.
    pub last_seen_remote_checkpoint: HashMap<DID, HashSet<(u64, [u8; 32])>>,

    // -----------------------------------------------------------------
    // New actor-shape fields (no legacy equivalent)
    // -----------------------------------------------------------------
    /// Send-sequence counter with RAII rollback
    /// ([`SequenceReservation`](crate::context::actor::SequenceReservation)).
    /// Replaces the legacy per-sender `MembershipState::next_sequence_number`
    /// as authoritative in 12d; coexists until then.
    pub send_tracker: SendSequenceTracker,

    /// Per-sender receive-sequence high-water marks for anti-replay.
    pub recv_tracker: RecvSequenceTracker,

    /// Target-side (B-owned) UCAN proof store for cross-context outlet
    /// invocation (spec §6.2.4 normative (1)). Maps a `ucan_proof_id` — the
    /// INDEX carried on the `CrossContextOutletInvoke` envelope, never the proof
    /// bytes — to the resolved [`UcanToken`](scp_protocol::crypto::ucan::UcanToken).
    /// At Prepare-B the target resolves the carried `ucan_proof_id` against THIS
    /// store and re-runs the full §7 validation re-bound to the carried
    /// `caller_did` + `outlet_registration_id` (the confused-deputy defense). The
    /// store doubles as the delegation-chain `ProofResolver` for that
    /// validation. Empty until a gated outlet interface is established; the
    /// freshness/replay state ([`ClassSState::xctx_nonce_dedup`]) and this store
    /// both live where the authorization decision is made — on B's actor.
    ///
    /// Not part of the Class-S snapshot: it is reconstructable interface state
    /// repopulated when the outlet interface is (re-)established, never
    /// authorization secrecy whose coalesce-window rollback re-opens a replay.
    pub xctx_ucan_proofs: InMemoryProofResolver,

    /// Class-S cross-context-saga state (ADR-049 §9). Groups the staged-saga
    /// slot, the B-owned anti-replay nonce-dedup cache, and the three durable
    /// committed/reservation witnesses whose ≤50 ms coalesce-window rollback
    /// would re-open a replay / re-invoke / double-settle window the caller
    /// already observed as closed. See [`ClassSState`] for the per-field
    /// security rationale. Privatized to `pub(in crate::context)`: the field is
    /// unnameable outside `crate::context`, and within it the ONLY mutable reach
    /// is through the [`ClassSCell`](crate::context::actor::class_s::ClassSCell)
    /// persist-on-commit combinators (no `state_mut`, no `DerefMut`). The `&mut`
    /// in the snapshot/serialization paths (`build_snapshot_from_state`) reads it
    /// shared. ADR-049 §9.
    pub(in crate::context) class_s: ClassSState,

    /// In-flight broadcast-publish reservations awaiting their apply
    /// phase (ADR-049 §SequenceReservation). Phase 1
    /// (`ReserveBroadcastPublish`) reserves a broadcast sequence and
    /// inserts a [`PendingBroadcastPublish`] here keyed by a fresh
    /// [`BroadcastReservationId`]; the caller signs the broadcast signing
    /// payload outside the actor (the `KeyCustody` signer is not
    /// mailbox-addressable), then phase 2 (`ApplyBroadcastPublish`)
    /// removes the entry and seals with the reserved sequence. A
    /// reservation that is never applied (signing failed, caller dropped)
    /// is rolled back so the sequence is not burned — matching the legacy
    /// single-phase behavior where a signing failure preceded any
    /// increment. Empty outside an in-flight publish.
    pub pending_broadcast_publishes: HashMap<BroadcastReservationId, PendingBroadcastPublish>,

    /// Scratchpad held during multi-step MLS Welcome processing. `None`
    /// outside an active Welcome flow.
    pub welcome_scratchpad: Option<WelcomeProcessing>,

    /// Actor-internal lifecycle. Distinct from protocol-level
    /// [`scp_protocol::context::ContextState`]; see
    /// [`ContextLifecycleState`] for discussion.
    pub lifecycle_state: ContextLifecycleState,

    /// Mode-specific state. Exactly one of the two variants is present,
    /// set at actor construction and never changed.
    pub mode: ContextModeState,
}

/// Construct an empty [`ContextRoleState`] for test-fixture use only.
/// Production construction goes through
/// [`ContextRoleState::new`] which enforces ceiling / role-definition
/// validation and auto-assigns the creator to the `admin` role. The
/// skeleton test path does not touch role logic, so a hand-rolled
/// empty shape is sufficient.
fn empty_role_state_for_test() -> ContextRoleState {
    // ADR-049 §9: `ContextRoleState`'s `ceiling` / `suspended_capabilities` fields
    // are private, so the skeleton is built via the crate's `empty_for_test`
    // constructor rather than a cross-crate struct literal.
    ContextRoleState::empty_for_test()
}

impl PerContextState {
    /// Read-only view of the staged cross-context saga slot
    /// ([`ClassSState::saga_pending`]). A `pub` accessor (the field itself is
    /// `pub(crate)` on the Class-S sub-struct) so the SDK-visible shape
    /// integration test can witness the slot without naming the crate-internal
    /// sub-struct path.
    #[inline]
    #[must_use]
    pub const fn saga_pending(&self) -> &HashMap<SagaId, SagaPreparedState> {
        &self.class_s.saga_pending
    }

    /// Construct a fresh encrypted-mode actor state for test use. Populates
    /// every field with a sensible default (empty collections, zero
    /// counters, `None` optionals). The production construction path for
    /// 12b+ handler migrations will supply real values from snapshots or
    /// from governance-config.
    ///
    /// `context_id` is the canonical 32-byte SHA-256; `created_at` is
    /// Unix-ms. `admin_did` seeds the governance engine (`SingleAdminEngine`)
    /// and owns all context-creation authority in the fixture.
    #[must_use]
    pub fn new_for_test_encrypted(context_id: [u8; 32], created_at: u64, admin_did: DID) -> Self {
        let context_id_hex = hex_encode_context_id(&context_id);
        Self::new_for_test_with_mode(
            context_id,
            created_at,
            admin_did,
            &context_id_hex,
            ContextModeState::Encrypted(Box::<ContextCryptoState>::default()),
        )
    }

    /// Construct a fresh broadcast-mode actor state for test use. Same
    /// role as [`Self::new_for_test_encrypted`].
    #[must_use]
    pub fn new_for_test_broadcast(context_id: [u8; 32], created_at: u64, admin_did: DID) -> Self {
        let context_id_hex = hex_encode_context_id(&context_id);
        Self::new_for_test_with_mode(
            context_id,
            created_at,
            admin_did,
            &context_id_hex,
            ContextModeState::Broadcast(Box::<BroadcastState>::default()),
        )
    }

    fn new_for_test_with_mode(
        context_id: [u8; 32],
        created_at: u64,
        admin_did: DID,
        context_id_str: &str,
        mode: ContextModeState,
    ) -> Self {
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let handle = ContextHandle::new(
            context_id_str.to_owned(),
            scp_protocol::context::ContextParams::default(),
        );
        // Routing axis mirrors the crypto axis: encrypted ⇒ pseudonymous,
        // broadcast ⇒ broadcast. Test fixtures start the pseudonymous
        // registry empty with a zero local pseudonym; a real local pseudonym
        // is supplied by the FFI boundary in production constructors.
        let routing = if mode.is_broadcast() {
            ContextRouting::Broadcast
        } else {
            ContextRouting::Pseudonymous {
                local_pseudonym: [0u8; 32],
                pseudonym_registry: HashMap::new(),
            }
        };
        Self {
            context_id,
            created_at,
            // Test fixtures reuse the local instantiation timestamp as the
            // convergent creation time; production sources it from the
            // creator-assigned `ContextCreated` leaf value.
            creation_timestamp_secs: created_at,
            generation: 0,
            handle,
            membership: MembershipState::new(),
            members: HashSet::new(),
            role_state: empty_role_state_for_test(),
            event_log: None,
            receive_buffer: ReceiveBuffer::new(),
            payment_receipts: VecDeque::new(),
            broadcast_context: None,
            migration_state: None,
            governance: GovernanceState::new_fresh_for_actor(context_id_str, admin_did, clock),
            epoch: EpochState::new_fresh_for_actor(context_id_str),
            access: AccessControlState::new_empty_for_actor(),
            ttl: TtlState::new_fresh_for_actor(),
            routing,
            sequence_tracker: SequenceTracker::new(),
            reorder_buffer: ReorderBuffer::default(),
            pending_commits: VecDeque::new(),
            commit_fault: None,
            checkpoint_events_since: 0,
            checkpoint_last_time_secs: 0,
            checkpoints: Vec::new(),
            last_seen_remote_checkpoint: HashMap::new(),
            send_tracker: SendSequenceTracker::new(),
            recv_tracker: RecvSequenceTracker::new(),
            xctx_ucan_proofs: InMemoryProofResolver::new(),
            class_s: ClassSState {
                saga_pending: HashMap::new(),
                // Seed the PRODUCTION saga dedup TTL (strictly longer than the
                // freshness skew, BLACK-XCTX-01) in the test fixture too, so
                // handler tests run the same anti-replay window the prod spawn /
                // restore sites build — `NonceDedup::new()`'s default 300s TTL is
                // coterminous with the skew tolerance, the condition the spec
                // FORBIDS, and would make test-window behaviour diverge from
                // production.
                xctx_nonce_dedup: NonceDedup::with_ttl(
                    crate::context::actor::handlers::saga::SAGA_NONCE_DEDUP_TTL_SECS,
                ),
                xctx_committed_outputs: HashMap::new(),
                xctx_committed_invocations: std::collections::HashSet::new(),
                xctx_caller_reservations: std::collections::HashMap::new(),
                caveat_counters: HashMap::new(),
                stream_reservations: HashMap::new(),
            },
            pending_broadcast_publishes: HashMap::new(),
            welcome_scratchpad: None,
            lifecycle_state: ContextLifecycleState::Open,
            mode,
        }
    }
}

/// Encode a 32-byte context ID as lowercase hex. Used by test fixtures
/// to derive stable string identifiers for the fields that require a
/// `String` context ID (`NonceTracker`, `EventLog`, `ContextHandle`).
fn hex_encode_context_id(id: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for byte in id {
        use std::fmt::Write;
        // `write!` into a `String` is infallible; the inner Result is
        // `Ok(())` for all `u8` inputs. Swallow the `Result` to keep
        // this helper infallible.
        let _ = write!(s, "{byte:02x}");
    }
    s
}

// ---------------------------------------------------------------------------
// WrappingKeyPair — per-identity X25519 keypair held by the supervisor
// ---------------------------------------------------------------------------

/// X25519 wrapping keypair held in the supervisor's per-identity map
/// (`DashMap<DID, ArcSwap<WrappingKeyPair>>`). Secret bytes are wrapped
/// in `Zeroizing` so rotation zeros the prior keypair when the last
/// `Arc<WrappingKeyPair>` drops.
#[derive(Debug)]
pub struct WrappingKeyPair {
    /// 32-byte X25519 public key.
    pub public: [u8; 32],
    /// 32-byte X25519 secret key. Zeroized on drop.
    pub secret: Zeroizing<[u8; 32]>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn test_admin() -> DID {
        DID("did:example:admin".to_owned())
    }

    /// §9.10.4: `ContextRouting::for_mode` makes "encrypted context with no
    /// pseudonym" unrepresentable — the encrypted branch always carries a
    /// concrete `[u8; 32]`, never an `Option`, and exposes peer-registry
    /// accessors. The broadcast branch carries no pseudonym state at all.
    #[test]
    fn context_routing_for_mode_encrypted_carries_pseudonym_and_registry() {
        let pseudonym = [11u8; 32];
        let routing = ContextRouting::for_mode(false, pseudonym);
        assert!(!routing.is_broadcast());
        assert_eq!(routing.local_pseudonym(), Some(pseudonym));
        assert!(routing.peer_registry().is_some_and(HashMap::is_empty));
    }

    #[test]
    fn context_routing_for_mode_broadcast_has_no_pseudonym_state() {
        let routing = ContextRouting::for_mode(true, [11u8; 32]);
        assert!(routing.is_broadcast());
        assert_eq!(routing.local_pseudonym(), None);
        assert!(routing.peer_registry().is_none());
    }

    #[test]
    fn set_local_pseudonym_updates_encrypted_noops_broadcast() {
        let mut enc = ContextRouting::for_mode(false, [1u8; 32]);
        enc.set_local_pseudonym([2u8; 32]);
        assert_eq!(enc.local_pseudonym(), Some([2u8; 32]));

        let mut bc = ContextRouting::Broadcast;
        bc.set_local_pseudonym([2u8; 32]);
        assert!(bc.is_broadcast(), "broadcast routing has no pseudonym slot");
        assert_eq!(bc.local_pseudonym(), None);
    }

    #[test]
    fn peer_registry_mut_inserts_for_encrypted_none_for_broadcast() {
        let mut enc = ContextRouting::for_mode(false, [1u8; 32]);
        enc.peer_registry_mut()
            .expect("encrypted has a registry")
            .insert(DID("did:key:peer".to_owned()), [4u8; 32]);
        assert_eq!(enc.peer_registry().map(HashMap::len), Some(1));

        let mut bc = ContextRouting::Broadcast;
        assert!(bc.peer_registry_mut().is_none());
    }

    /// §9.10.4: `ContextRouting` round-trips through the snapshot serde format.
    /// The `DID`-keyed registry serializes with plain string keys (DID is
    /// `serde(transparent)`), so it is wire-compatible with the historical
    /// `HashMap<String, [u8; 32]>` snapshot field.
    #[test]
    fn context_routing_serde_roundtrip() {
        let mut routing = ContextRouting::for_mode(false, [5u8; 32]);
        routing
            .peer_registry_mut()
            .expect("registry")
            .insert(DID("did:key:peer".to_owned()), [6u8; 32]);
        let json = serde_json::to_string(&routing).expect("serialize");
        assert!(
            json.contains("did:key:peer"),
            "registry key serializes as a plain DID string: {json}"
        );
        let back: ContextRouting = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.local_pseudonym(), Some([5u8; 32]));
        assert_eq!(
            back.peer_registry()
                .and_then(|r| r.get(&DID("did:key:peer".to_owned())).copied()),
            Some([6u8; 32])
        );

        let bc_json = serde_json::to_string(&ContextRouting::Broadcast).expect("serialize");
        let bc_back: ContextRouting = serde_json::from_str(&bc_json).expect("deserialize");
        assert!(bc_back.is_broadcast());
    }

    /// B1 (serde): `ContextSnapshot` persists the ABSOLUTE convergent
    /// `ttl_deadline_secs` (mapped from `state.ttl.timer.deadline_unix_secs`)
    /// and round-trips it verbatim. A legacy snapshot lacking the field (it
    /// predates `ttl_deadline_secs`, having carried the retired RELATIVE
    /// `ttl_remaining_secs`) decodes as `None` via `#[serde(default)]`, so the
    /// restore path falls back to the `creation + ttl` re-derivation.
    #[test]
    fn snapshot_roundtrip_preserves_ttl_deadline_secs() {
        const T0: u64 = 1_700_000_000;
        const DEADLINE: u64 = T0 + 3600;

        let mut state = PerContextState::new_for_test_encrypted([0x77u8; 32], T0, test_admin());
        state.ttl.timer.deadline_unix_secs = Some(DEADLINE);
        let snap = crate::context::manager_methods::snapshot_context(&state);
        assert_eq!(
            snap.ttl_deadline_secs,
            Some(DEADLINE),
            "snapshot must carry the absolute deadline off the live timer"
        );

        // Full serde round-trip preserves the absolute deadline verbatim.
        let json = serde_json::to_string(&snap).expect("serialize snapshot");
        let back: crate::context::state::ContextSnapshot =
            serde_json::from_str(&json).expect("deserialize snapshot");
        assert_eq!(back.ttl_deadline_secs, Some(DEADLINE));

        // Legacy snapshot: the field is simply absent (predates this field).
        let mut value: serde_json::Value = serde_json::from_str(&json).expect("to value");
        value
            .as_object_mut()
            .expect("snapshot is a JSON object")
            .remove("ttl_deadline_secs");
        let legacy: crate::context::state::ContextSnapshot =
            serde_json::from_value(value).expect("legacy snapshot decodes with the field absent");
        assert_eq!(
            legacy.ttl_deadline_secs, None,
            "a legacy snapshot lacking ttl_deadline_secs must decode as None (#[serde(default)])"
        );
    }

    #[test]
    fn encrypted_constructor_places_encrypted_mode() {
        let s = PerContextState::new_for_test_encrypted([0u8; 32], 42, test_admin());
        assert!(s.mode.is_encrypted());
        assert!(!s.mode.is_broadcast());
        assert_eq!(s.created_at, 42);
        assert_eq!(s.lifecycle_state, ContextLifecycleState::Open);
        assert_eq!(s.send_tracker.last_issued(), 0);
        assert!(s.class_s.saga_pending.is_empty());
        assert!(s.members.is_empty());
        assert!(s.welcome_scratchpad.is_none());
        assert!(s.event_log.is_none());
    }

    #[test]
    fn broadcast_constructor_places_broadcast_mode() {
        let s = PerContextState::new_for_test_broadcast([1u8; 32], 7, test_admin());
        assert!(s.mode.is_broadcast());
        assert!(!s.mode.is_encrypted());
        if let ContextModeState::Broadcast(b) = &s.mode {
            assert_eq!(b.local_send_sequence, 0);
            assert!(b.author_keys.is_empty());
            assert!(b.blocked_authors.is_empty());
            assert!(b.subscribers.is_empty());
            assert!(b.pending_key_rotations.is_empty());
        } else {
            panic!("expected broadcast mode");
        }
    }

    #[test]
    fn encrypted_mode_has_empty_crypto_state() {
        let s = PerContextState::new_for_test_encrypted([2u8; 32], 99, test_admin());
        match &s.mode {
            ContextModeState::Encrypted(cs) => {
                assert!(cs.mls_group.is_none(), "mls_group starts None");
                assert!(cs.sender_key.is_none(), "sender_key starts None");
                assert_eq!(cs.sender_key_epoch, 0);
                assert!(cs.pending_distributions.is_empty());
                assert!(cs.member_wrapping_keys.is_empty());
            }
            ContextModeState::Broadcast(_) => panic!("expected encrypted mode"),
        }
    }

    /// Exhaustive-destructure witness that every field on
    /// [`PerContextState`] is populated by the test fixture. The
    /// destructuring pattern intentionally does NOT use `..` — adding a
    /// new field on [`PerContextState`] without updating this pattern
    /// breaks the build, which forward-locks 12b+ against silent field
    /// drops. This is the crate-internal counterpart to
    /// `tests/actor_state_shape.rs`'s accessor-based witness; `pub(crate)`
    /// typed fields (`governance`, `epoch`, `access`, `ttl`) can only be
    /// named from inside the crate.
    #[test]
    fn encrypted_constructor_populates_every_per_context_field() {
        let s = PerContextState::new_for_test_encrypted([3u8; 32], 12, test_admin());
        let PerContextState {
            context_id,
            created_at,
            creation_timestamp_secs,
            generation,
            handle,
            membership,
            members,
            role_state,
            event_log,
            receive_buffer,
            payment_receipts,
            broadcast_context,
            migration_state,
            governance,
            epoch,
            access,
            ttl,
            routing,
            sequence_tracker,
            reorder_buffer,
            pending_commits,
            commit_fault,
            checkpoint_events_since,
            checkpoint_last_time_secs,
            checkpoints,
            last_seen_remote_checkpoint,
            send_tracker,
            recv_tracker,
            xctx_ucan_proofs,
            class_s,
            pending_broadcast_publishes,
            welcome_scratchpad,
            lifecycle_state,
            mode,
        } = s;

        // Class-S sub-struct: exhaustively destructure so a new Class-S field
        // forces an update here too (forward-lock against silent field drops).
        let ClassSState {
            saga_pending,
            xctx_nonce_dedup,
            xctx_committed_outputs,
            xctx_committed_invocations,
            xctx_caller_reservations,
            caveat_counters,
            stream_reservations,
        } = class_s;

        // Identity + lifetime.
        assert_eq!(context_id, [3u8; 32]);
        assert_eq!(created_at, 12);
        // Test fixture mirrors the convergent creation time onto the local
        // instantiation timestamp.
        assert_eq!(creation_timestamp_secs, 12);
        assert_eq!(generation, 0);
        assert_eq!(handle.context_id().len(), 64);

        // Membership + role.
        assert_eq!(membership.count(), 0);
        assert!(members.is_empty());
        assert!(role_state.members.is_empty());

        // Event buffers + logs.
        assert!(event_log.is_none());
        assert_eq!(receive_buffer.len(), 0);
        assert!(payment_receipts.is_empty());

        // Mode-specific metadata.
        assert!(broadcast_context.is_none());
        assert!(migration_state.is_none());

        // Governance / epoch / access / ttl — internals are `pub(crate)`
        // on the legacy manager module; taking a reference witnesses
        // the field is reachable and initialized.
        let _ = &governance;
        let _ = &epoch;
        let _ = &access;
        let _ = &ttl;

        // Routing — encrypted contexts are pseudonymous with an empty
        // peer registry and a (zero, in the test fixture) local pseudonym.
        assert!(!routing.is_broadcast());
        assert!(routing.local_pseudonym().is_some());
        assert!(routing.peer_registry().is_some_and(HashMap::is_empty));

        // Anti-replay + reorder buffers.
        let _ = &sequence_tracker;
        let _ = &reorder_buffer;

        // Commit retry + checkpointing.
        assert_eq!(pending_commits.len(), 0);
        assert!(commit_fault.is_none());
        assert_eq!(checkpoint_events_since, 0);
        assert_eq!(checkpoint_last_time_secs, 0);
        assert!(checkpoints.is_empty());
        assert!(last_seen_remote_checkpoint.is_empty());

        // New actor-shape fields.
        assert_eq!(send_tracker.last_issued(), 0);
        let _ = recv_tracker.last_seen(&DID("did:example:any".to_owned()));
        assert!(saga_pending.is_empty());
        // B-owned cross-context outlet-invoke validation state starts empty: no
        // UCAN proofs indexed, no nonces seen (spec §6.2.4).
        assert!(xctx_ucan_proofs.proofs.is_empty());
        {
            let mut dedup = xctx_nonce_dedup;
            assert!(!dedup.is_replayed(&[0u8; 16], 0));
        }
        // No committed cross-context outlet invocations on a fresh context
        // (target-side durable output capture + caller-side commit witness).
        assert!(xctx_committed_outputs.is_empty());
        assert!(xctx_committed_invocations.is_empty());
        // No in-flight caller-side cross-context reservations on a fresh context.
        assert!(xctx_caller_reservations.is_empty());
        // No §7.3.8 caveat counters recorded on a fresh context.
        assert!(caveat_counters.is_empty());
        // No in-flight streaming reservation recovery records on a fresh context.
        assert!(stream_reservations.is_empty());
        assert!(pending_broadcast_publishes.is_empty());
        assert!(welcome_scratchpad.is_none());
        assert_eq!(lifecycle_state, ContextLifecycleState::Open);

        // Mode.
        match mode {
            ContextModeState::Encrypted(_) => {}
            ContextModeState::Broadcast(_) => panic!("expected encrypted mode"),
        }
    }

    /// Companion exhaustive destructure for broadcast mode. Pattern is
    /// identical to the encrypted test; if the two diverge on which
    /// fields are populated it is caught here.
    #[test]
    fn broadcast_constructor_populates_every_per_context_field() {
        let s = PerContextState::new_for_test_broadcast([4u8; 32], 13, test_admin());
        let PerContextState {
            context_id: _,
            created_at: _,
            creation_timestamp_secs: _,
            generation: _,
            handle: _,
            membership: _,
            members: _,
            role_state: _,
            event_log: _,
            receive_buffer: _,
            payment_receipts: _,
            broadcast_context: _,
            migration_state: _,
            governance: _,
            epoch: _,
            access: _,
            ttl: _,
            routing,
            sequence_tracker: _,
            reorder_buffer: _,
            pending_commits: _,
            commit_fault: _,
            checkpoint_events_since: _,
            checkpoint_last_time_secs: _,
            checkpoints: _,
            last_seen_remote_checkpoint: _,
            send_tracker: _,
            recv_tracker: _,
            xctx_ucan_proofs: _,
            class_s:
                ClassSState {
                    saga_pending: _,
                    xctx_nonce_dedup: _,
                    xctx_committed_outputs: _,
                    xctx_committed_invocations: _,
                    xctx_caller_reservations: _,
                    caveat_counters: _,
                    stream_reservations: _,
                },
            pending_broadcast_publishes: _,
            welcome_scratchpad: _,
            lifecycle_state: _,
            mode,
        } = s;

        // Routing axis must agree with the crypto axis: broadcast mode ⇒
        // broadcast routing, with no pseudonym state.
        assert!(routing.is_broadcast());
        assert!(routing.local_pseudonym().is_none());
        assert!(routing.peer_registry().is_none());

        match mode {
            ContextModeState::Broadcast(b) => {
                assert!(b.pending_key_rotations.is_empty());
                assert!(b.recv_sequence_trackers.is_empty());
            }
            ContextModeState::Encrypted(_) => panic!("expected broadcast mode"),
        }
    }

    /// Exhaustive-destructure witness for [`ContextCryptoState`]. Same
    /// forward-lock as [`encrypted_constructor_populates_every_per_context_field`].
    #[test]
    fn context_crypto_state_default_populates_every_field() {
        let c = ContextCryptoState::default();
        let ContextCryptoState {
            mls_group,
            sender_key,
            sender_key_store,
            sender_key_epoch,
            pending_distributions,
            nonce_dedup,
            member_wrapping_keys,
            recv_sequence_tracker,
        } = c;

        assert!(mls_group.is_none());
        assert!(sender_key.is_none());
        let _ = &sender_key_store;
        assert_eq!(sender_key_epoch, 0);
        assert!(pending_distributions.is_empty());
        let _ = &nonce_dedup;
        assert!(member_wrapping_keys.is_empty());
        assert!(
            recv_sequence_tracker.is_empty(),
            "recv_sequence_tracker starts empty",
        );
    }

    /// Exhaustive-destructure witness for [`BroadcastState`]. Catches
    /// silent field drops the same way as the PerContextState tests.
    #[test]
    fn broadcast_state_default_populates_every_field() {
        let b = BroadcastState::default();
        let BroadcastState {
            author_keys,
            blocked_authors,
            recv_sequence_trackers,
            local_send_sequence,
            subscribers,
            pending_key_rotations,
        } = b;
        assert!(author_keys.is_empty());
        assert!(blocked_authors.is_empty());
        assert!(recv_sequence_trackers.is_empty());
        assert_eq!(local_send_sequence, 0);
        assert!(subscribers.is_empty());
        assert!(pending_key_rotations.is_empty());
    }

    #[test]
    fn recv_tracker_rejects_replay() {
        let mut t = RecvSequenceTracker::new();
        let did = DID("did:example:alice".to_owned());
        assert!(t.record(did.clone(), 1));
        assert!(t.record(did.clone(), 2));
        // Replay of 2 is rejected.
        assert!(!t.record(did.clone(), 2));
        // Older sequence is rejected.
        assert!(!t.record(did.clone(), 1));
        // Jump forward is fine.
        assert!(t.record(did.clone(), 10));
        assert_eq!(t.last_seen(&did), 10);
    }

    #[test]
    fn recv_tracker_unseen_sender_is_zero() {
        let t = RecvSequenceTracker::new();
        let did = DID("did:example:eve".to_owned());
        assert_eq!(t.last_seen(&did), 0);
    }

    #[test]
    fn wrapping_keypair_secret_is_zeroizing() {
        // `Zeroizing` drop zeros the byte buffer; we assert the type-level
        // contract by constructing one and reading the public bytes.
        let kp = WrappingKeyPair {
            public: [0x11; 32],
            secret: Zeroizing::new([0x22; 32]),
        };
        assert_eq!(kp.public, [0x11; 32]);
        // Zeroization on drop is asserted by `Zeroizing`'s own tests; we
        // assert here only that the field compiles under `Zeroizing<[u8;32]>`.
        drop(kp);
    }

    /// ADR-049 §9 PR2a: the Class-S sub-struct mirror snapshot/restore is a
    /// LOSSLESS round-trip. Populate `ClassSState` (incl. a staged saga + a
    /// recorded nonce + the three committed/reservation witnesses) and
    /// `GovernanceClassS` (executed-proposals + threshold + spending-nonce
    /// tracker), snapshot both, MUTATE the live state, then restore — and assert
    /// the observable state matches the pre-mutation snapshot. This is what makes
    /// the mirror methods non-dead-code and proves the §9.4.3 bearer-barrier
    /// (`saga_pending` is not `Clone`) survives the mirror without loss.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn class_s_and_governance_class_s_snapshot_restore_is_lossless() {
        use crate::context::supervisor::saga_journal::SagaId;
        use crate::context::supervisor::saga_prepared_state::{
            CallerReservationRecord, CommittedOutletInvocation,
            CrossContextOutletInvocationPrepared, SagaPreparedState,
        };

        let mut state =
            PerContextState::new_for_test_encrypted([0xC5u8; 32], 1_700_000_000, test_admin());

        // --- Populate ClassSState ---
        let saga_a = SagaId("saga-lossless-a".to_owned());
        state.class_s.saga_pending.insert(
            saga_a.clone(),
            SagaPreparedState::CrossContextOutletInvocation(CrossContextOutletInvocationPrepared {
                caller_context_id: [0x1Au8; 32],
                target_context_id: [0x2Bu8; 32],
                caller_did: DID("did:example:lossless-caller".to_owned()),
                outlet_registration_id: "lossless-outlet-v1".to_owned(),
                ucan_proof_id: "lossless-ucan".to_owned(),
                recorded_timestamp_ms: 1_700_000_000_123,
                recorded_nonce: [0x3Cu8; 16],
                recorded_chain_depth: 2,
            }),
        );
        state
            .class_s
            .xctx_nonce_dedup
            .record([0x3Cu8; 16], 1_700_000_000);

        let receipt =
            scp_protocol::context::outlets::cross_context_saga::CrossContextOutletReceipt::sign(
                &ed25519_dalek::SigningKey::from_bytes(&[0x4Du8; 32]),
                scp_protocol::context::outlets::cross_context_saga::CrossContextOutletReceiptFields {
                    caller_context_id: [0x1Au8; 32],
                    target_context_id: [0x2Bu8; 32],
                    caller_did: "did:example:lossless-caller".to_owned(),
                    nonce: [0x3Cu8; 16],
                    outlet_registration_id: "lossless-outlet-v1".to_owned(),
                    output_jcs: br#"{"ok":1}"#.to_vec(),
                    outlet_invoked_event_id: "OutletInvoked:saga-lossless-committed".to_owned(),
                    chain_depth: 2,
                    timestamp_ms: 1_700_000_000_123,
                },
            )
            .expect("receipt signs");
        let committed_saga = SagaId("saga-lossless-committed".to_owned());
        state.class_s.xctx_committed_outputs.insert(
            committed_saga.clone(),
            CommittedOutletInvocation {
                receipt,
                output_bytes: br#"{"ok":1}"#.to_vec(),
                outlet_invoked_event_id: "OutletInvoked:saga-lossless-committed".to_owned(),
            },
        );
        state
            .class_s
            .xctx_committed_invocations
            .insert(committed_saga.clone());
        let reservation_saga = SagaId("saga-lossless-reservation".to_owned());
        let reservation_record = CallerReservationRecord {
            actor_did: DID("did:example:lossless-caller".to_owned()),
            deducted_cost: None,
            needs_hard_rate_limit_refund: true,
            recorded_at_secs: 1_700_000_000,
            escrow_authorization: None,
        };
        state
            .class_s
            .xctx_caller_reservations
            .insert(reservation_saga.clone(), reservation_record.clone());

        // --- Populate GovernanceClassS ---
        let executed_id = [0x5Eu8; 32];
        state
            .governance
            .class_s
            .executed_proposals
            .insert(executed_id, 1_700_000_000);
        state
            .governance
            .class_s
            .threshold_signers
            .push(DID("did:example:signer-1".to_owned()));
        state.governance.class_s.threshold_value = 3;
        // Seed a consumed spending-UCAN nonce so the tracker carries durable
        // state. Seed via `from_snapshot` (explicit entries) rather than
        // `.record()` so the test does not depend on wall-clock freshness — the
        // entry's presence after the round-trip is what proves the tracker
        // survives losslessly.
        let spend_nonce = "1700000000000-aabbccddeeff00112233445566778899".to_owned();
        let mut spend_entries = HashMap::new();
        spend_entries.insert(spend_nonce.clone(), (1_700_000_000_u64, u64::MAX));
        state.governance.class_s.spending_nonce_tracker =
            scp_protocol::crypto::ucan::nonce::NonceTracker::from_snapshot(
                hex_encode_context_id(&[0xC5u8; 32]),
                Arc::new(SystemClock) as Arc<dyn Clock>,
                spend_entries,
            );

        // --- Snapshot BOTH sub-structs (the lossless mirror) ---
        let class_s_snap = state.class_s.snapshot();
        let gov_snap = state.governance.class_s.snapshot();
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);

        // --- MUTATE the live state away from the snapshot ---
        state.class_s.saga_pending.clear();
        state.class_s.xctx_nonce_dedup = NonceDedup::new();
        state.class_s.xctx_committed_outputs.clear();
        state.class_s.xctx_committed_invocations.clear();
        state.class_s.xctx_caller_reservations.clear();
        state.governance.class_s.executed_proposals.clear();
        state.governance.class_s.threshold_signers.clear();
        state.governance.class_s.threshold_value = 0;
        state.governance.class_s.spending_nonce_tracker =
            scp_protocol::crypto::ucan::nonce::NonceTracker::new(
                "wiped".to_owned(),
                Arc::clone(&clock),
            );

        // --- RESTORE from the snapshots ---
        state.class_s.restore(class_s_snap);
        state.governance.class_s.restore(gov_snap, &clock);

        // --- Assert observable state is value-stable ---
        // saga_pending: the staged variant + its eight journaled fields survive.
        assert_eq!(state.class_s.saga_pending.len(), 1);
        // Single-variant enum: the bind is irrefutable.
        let SagaPreparedState::CrossContextOutletInvocation(inner) = state
            .class_s
            .saga_pending
            .get(&saga_a)
            .expect("saga restored");
        assert_eq!(inner.caller_context_id, [0x1Au8; 32]);
        assert_eq!(inner.target_context_id, [0x2Bu8; 32]);
        assert_eq!(inner.caller_did.0, "did:example:lossless-caller");
        assert_eq!(inner.outlet_registration_id, "lossless-outlet-v1");
        assert_eq!(inner.ucan_proof_id, "lossless-ucan");
        assert_eq!(inner.recorded_timestamp_ms, 1_700_000_000_123);
        assert_eq!(inner.recorded_nonce, [0x3Cu8; 16]);
        assert_eq!(inner.recorded_chain_depth, 2);
        // xctx_nonce_dedup: the recorded nonce + TTL survive (a fresh replay of
        // the same nonce within the TTL is still detected).
        assert!(
            state
                .class_s
                .xctx_nonce_dedup
                .entries()
                .contains_key(&[0x3Cu8; 16]),
            "recorded nonce survives the round-trip"
        );
        assert_eq!(
            state.class_s.xctx_nonce_dedup.ttl_secs(),
            crate::context::actor::handlers::saga::SAGA_NONCE_DEDUP_TTL_SECS,
            "the dedup TTL survives the round-trip"
        );
        // committed outputs / invocations / reservations.
        assert!(
            state
                .class_s
                .xctx_committed_outputs
                .contains_key(&committed_saga)
        );
        assert!(
            state
                .class_s
                .xctx_committed_invocations
                .contains(&committed_saga)
        );
        assert_eq!(
            state
                .class_s
                .xctx_caller_reservations
                .get(&reservation_saga),
            Some(&reservation_record)
        );

        // GovernanceClassS.
        assert!(
            state
                .governance
                .class_s
                .executed_proposals
                .contains_key(&executed_id)
        );
        assert_eq!(
            state.governance.class_s.threshold_signers,
            vec![DID("did:example:signer-1".to_owned())]
        );
        assert_eq!(state.governance.class_s.threshold_value, 3);
        // The spending-nonce tracker rehydrates value-stable: the consumed nonce
        // entry survives the snapshot/restore round-trip (so a future replay
        // would still be caught once the freshness window is re-entered).
        assert!(
            state
                .governance
                .class_s
                .spending_nonce_tracker
                .snapshot_entries()
                .contains_key(&spend_nonce),
            "restored spending-nonce tracker retains the recorded nonce"
        );
    }
}
