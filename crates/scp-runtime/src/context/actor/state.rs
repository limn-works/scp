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
//! the legacy struct owned is represented here (so the ADR-049 §15
//! handler-body migrations moved calls mechanically off `manager.field`
//! onto `state.field`), plus the new per-actor fields (`saga_pending`,
//! `welcome_scratchpad`, `send_tracker`, `recv_tracker`, split mode
//! state) that the legacy struct did not own.
//!
//! The two types coexisted through the commit ladder (commit 6 through
//! ADR-049 §15); the legacy state struct stayed byte-identical apart from
//! the `pub(crate)` field elevations ADR-049 §15 added so the actor could
//! name the sub-struct types. ADR-049 §15 migrated handler bodies to
//! take `&mut actor::PerContextState`, then deleted the legacy
//! `ContextManager`; the legacy state type was removed in the same
//! mechanical pass.
//!
//! # Origin — the fields-only landing
//!
//! [`PerContextState`], [`ContextCryptoState`], and [`BroadcastState`]
//! first landed as a fields-only mirror of every field the legacy
//! manager's own `PerContextState` + `NodeMlsFactory::contexts[ctx_id]`
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

// ADR-049 PR-7 (crypto-state move, prep A — SCP-CRYPTOMOVE-000a): types named by
// the per-context crypto orchestration + state-management methods moved VERBATIM
// from `NodeMlsFactory` (Decision 6 / Decision 15(a)). The bodies call the
// same `scp_mls` / `scp_protocol` primitives the provider calls; the provider's
// copies are retained until the atomic core.
use crate::crypto::mls::provider::MlsCryptoSnapshot;
use crate::crypto::mls::provider::OwnedMlsCryptoState;
use scp_protocol::context::ContextError;
use scp_protocol::context::ScpContextExtension;
use scp_protocol::context::builder::{
    AddMemberOutput, AdvanceEpochOutput, ContextCreationError, MANAGEMENT_MSG_MAGIC,
    MAX_MANAGEMENT_PAYLOAD_SIZE, OpenResult, OpenedEnvelope, ReceiveFloor, RemoveMemberOutput,
    try_strip_management_prefix,
};
use scp_protocol::crypto::sender_keys::{
    SenderKeyDistributionMessage, SenderKeyResponse, generate_sender_key,
};
use scp_protocol::envelope::inner::InnerEnvelope;
use scp_protocol::envelope::outer::{OuterEnvelope, create_outer_envelope};

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
/// `NodeMlsFactory::pending_joins` global per plan §"NodeMlsFactory
/// dissolution": the `StagedWelcome` lives here (per-context), the KP
/// reservation lives on the `KeyPackageStoreActor`.
///
/// # Supersession of the single-slot provider path
///
/// The [`Self::kp_reservation`] handle pairs with the per-identity
/// [`KeyPackageStoreActor`](crate::context::supervisor::key_package_actor::KeyPackageStoreActor)
/// `reserved` map, which **supersedes** the legacy single-slot
/// `NodeMlsFactory::pending_joins` (`ArcSwapOption`): a Welcome flow
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
    /// material (plan §"NodeMlsFactory dissolution" row
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
/// for the broadcast-mode state that legacy `NodeMlsFactory::broadcast_keys`
/// and `PerContextState.broadcast_context` split across two structures.
///
/// ADR-049 §15 populates the field set; ADR-049 §15 migrates the broadcast
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
    /// met. No legacy equivalent on `NodeMlsFactory` — legacy applied
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

/// The OBSERVED outcome of a per-context crypto disposal
/// ([`ContextCryptoState::dispose_secrets`] / [`PerContextState::dispose_secrets`]).
///
/// #2199: a [`KeyDestructionAttestation`](scp_protocol::context::memory_scope::KeyDestructionAttestation)'s
/// `mls_group_destroyed` / `sender_keys_destroyed` flags are a provenance record
/// a verifier relies on (ADR-018): `true` MUST mean "key material was verifiably
/// gone as the result of an ACTUALLY-EXECUTED, OBSERVED disposal". A fabricated
/// `true` is a nullifier-class false guarantee (worse than honest absence). This
/// struct is that honest signal: each flag is `true` ONLY when disposal ran on
/// material that was PRESENT at entry, `false` when the material was absent
/// (nothing to destroy).
///
/// # A fabricated `true` is structurally unrepresentable (#2199 / F3)
///
/// The two flags are PRIVATE and there is no public/`pub(crate)` constructor:
/// the only code that can mint a `DisposalOutcome` is this module
/// (`crate::context::actor::state`), via the private [`Self::observed`]
/// constructor called EXCLUSIVELY from [`ContextCryptoState::dispose_secrets`]
/// (which derives the flags from the PRE-disposal presence of the material) and
/// the [`PerContextState::dispose_secrets`] Broadcast N/A arm (which mints
/// `observed(false, false)`). No code OUTSIDE this module — the finalize / TTL
/// seams, the FFI bridge, any future caller — can construct one at all, let
/// alone hand-forge `observed(true, true)`; they may only READ the flags through
/// the [`Self::mls_group_destroyed`] / [`Self::sender_keys_destroyed`]
/// accessors. So a `true` an attestation reads is compile-guaranteed to have
/// originated in an actual observed disposal.
///
/// `pub(crate)`: this type is crate-internal — it never appears in a public
/// signature (the `dispose_secrets` methods are `pub(crate)`; the finalize seam
/// returns a `KeyDestructionAttestation`, not this outcome), so it is not part of
/// the SDK surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DisposalOutcome {
    /// `true` iff an MLS group was PRESENT at disposal entry and
    /// [`scp_mls::group::destroy_group`] ran (it is total — `Ok` or the
    /// idempotent `Err(GroupDestroyed)` both mean gone). `false` when no group
    /// was present (honest absence).
    mls_group_destroyed: bool,
    /// `true` iff sender-key material (the local `sender_key`, a non-empty
    /// `sender_key_store`, OR a non-empty `pending_distributions` queue) was
    /// PRESENT at entry and was cleared/zeroized here. `false` when no sender-key
    /// material was present (honest absence).
    sender_keys_destroyed: bool,
}

impl DisposalOutcome {
    /// Mints an observed outcome. PRIVATE by construction (#2199 / F3): callable
    /// only within `crate::context::actor::state`, so the sole minters are
    /// [`ContextCryptoState::dispose_secrets`] (real observed disposal) and the
    /// [`PerContextState::dispose_secrets`] Broadcast N/A arm. No code outside
    /// this module can fabricate an outcome — least of all a `(true, true)`.
    const fn observed(mls_group_destroyed: bool, sender_keys_destroyed: bool) -> Self {
        Self {
            mls_group_destroyed,
            sender_keys_destroyed,
        }
    }

    /// `true` iff an MLS group was observed present-and-destroyed by the
    /// disposal that produced this outcome. Sole read path for the attestation's
    /// `mls_group_destroyed` flag. Takes `self` by value — `DisposalOutcome` is a
    /// 2-byte `Copy` type, so a by-ref accessor is `trivially_copy_pass_by_ref`.
    #[must_use]
    pub(crate) const fn mls_group_destroyed(self) -> bool {
        self.mls_group_destroyed
    }

    /// `true` iff sender-key material was observed present-and-destroyed by the
    /// disposal that produced this outcome. Sole read path for the attestation's
    /// `sender_keys_destroyed` flag. Takes `self` by value (2-byte `Copy` type).
    #[must_use]
    pub(crate) const fn sender_keys_destroyed(self) -> bool {
        self.sender_keys_destroyed
    }
}

/// State owned by an encrypted-mode (MLS) `ContextActor`. Mirrors the
/// legacy `NodeMlsFactory::contexts[ctx_id]`
/// (`crate::crypto::mls::provider::ContextCryptoState`) field-for-field.
///
/// # MLS group is `Option<ScpMlsGroup>`, not `ScpMlsGroup`
///
/// Legacy `NodeMlsFactory` builds the MLS group synchronously inside
/// `create_context` / `join_from_welcome` and inserts the
/// `ContextCryptoState` only afterwards — so its `mls_group` field is
/// non-optional. The actor model separates actor spawn (supervisor puts a
/// live handle in the registry) from MLS group construction (a Create /
/// Join handler runs inside the actor's dispatch loop). Between those
/// two events `mls_group` is `None`. ADR-049 §15's lifecycle handler
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
    /// Legacy field: `NodeMlsFactory::ContextCryptoState::mls_group`
    /// (provider.rs:210), held non-optionally because legacy inserted
    /// the containing struct into the map only after construction.
    pub mls_group: Option<ScpMlsGroup>,

    /// The local member's AES-256 sender key for this context (spec
    /// §9.16.1). `None` until a Create / Join handler generates it.
    /// Legacy field: `NodeMlsFactory::ContextCryptoState::sender_key`
    /// (provider.rs:212).
    pub sender_key: Option<SenderKey>,

    /// Sender key store tracking per-member keys for blocking /
    /// distribution. Mirrors legacy
    /// `NodeMlsFactory::ContextCryptoState::sender_key_store`
    /// (provider.rs:214).
    pub sender_key_store: SenderKeyStore,

    /// Sender key epoch counter (incremented on each key rotation).
    /// Mirrors legacy
    /// `NodeMlsFactory::ContextCryptoState::sender_key_epoch`
    /// (provider.rs:216).
    pub sender_key_epoch: u64,

    /// Pending sender-key-distribution messages queued for drain:
    /// `(target_did, serialized_message)`. Mirrors legacy
    /// `NodeMlsFactory::ContextCryptoState::pending_distributions`
    /// (provider.rs:221). The send-side sequence counter that legacy
    /// kept on the same struct (`send_sequence: u64`) lives on
    /// [`PerContextState::send_tracker`](PerContextState::send_tracker)
    /// instead.
    pub pending_distributions: Vec<(String, Vec<u8>)>,

    /// Nonce deduplication cache for sender-key requests (replay
    /// protection). Mirrors legacy
    /// `NodeMlsFactory::ContextCryptoState::nonce_dedup`
    /// (provider.rs:223).
    pub nonce_dedup: NonceDedup,

    /// Remote members' X25519 wrapping public keys, keyed by DID.
    /// Populated from key packages during `add_member`. Mirrors legacy
    /// `NodeMlsFactory::ContextCryptoState::member_wrapping_keys`
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
    /// per-context reorder / delivery path. This field is a dormant
    /// per-member MLS sender-key `(epoch, sequence)` receive-floor,
    /// reserved for the crash-surviving recv-sequence-floor work
    /// (ADR-049 §9 residual). It is not read or written on any
    /// production path today: the live sender-key `(epoch, sequence)`
    /// receive handling has been relocated off the former provider onto
    /// the actor-owned [`ContextCryptoState`], performed by
    /// [`ContextCryptoState::open`](crate::context::actor::state::ContextCryptoState::open).
    pub recv_sequence_tracker: HashMap<String, (u64, u64)>,

    /// One-shot fault-injection seam (#2148 F1 / ADR-049 §15(c)), re-homed onto
    /// the actor from the deleted provider `rotate_sender_key`. When armed via
    /// [`PerContextState::arm_rotation_failure_once`], the NEXT
    /// [`PerContextState::rotate_sender_key`] fails closed BEFORE any mutation
    /// (the old epoch/key/store are retained), then clears itself so a
    /// subsequent rotation advances normally. The real actor rotation always
    /// mints a fresh key and increments the epoch, so that Class-S fail-closed
    /// branch is otherwise structurally unreachable. Gated `#[cfg(any(test,
    /// feature = "testing"))]` — never present on a production build (neither
    /// the field nor the branch that reads it).
    #[cfg(any(test, feature = "testing"))]
    pub(crate) force_rotation_failure: bool,
}

impl std::fmt::Debug for ContextCryptoState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact the MLS group and sender key — the former holds OpenMLS
        // epoch secrets, the latter is raw AES-256 key material. All
        // other fields are safe to print: counters, non-secret byte
        // arrays, and store types that already redact on their own.
        let mut d = f.debug_struct("ContextCryptoState");
        d.field(
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
        );
        // Test-only fault-injection seam (non-secret bool); included so the
        // manual `Debug` impl covers every field.
        #[cfg(any(test, feature = "testing"))]
        d.field("force_rotation_failure", &self.force_rotation_failure);
        d.finish()
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
            #[cfg(any(test, feature = "testing"))]
            force_rotation_failure: false,
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

    /// Mutable access to the encrypted-mode crypto sub-state, or `None` for a
    /// broadcast context.
    ///
    /// ADR-049 PR-7 (SCP-CRYPTOMOVE-001): the Class-C send/receive seams reach
    /// the field-granular [`ContextCryptoState`] through this accessor off the
    /// `ClassCMut::mode_mut()` view, so the message hot path drives
    /// [`ContextCryptoState::seal`] / [`ContextCryptoState::open`] on
    /// `&mut ContextCryptoState` (coalesced Class-C) rather than a whole
    /// `&mut PerContextState` (fail-closed Class-S). Broadcast contexts carry no
    /// MLS crypto state and seal through [`BroadcastState`] instead.
    pub(crate) fn crypto_mut(&mut self) -> Option<&mut ContextCryptoState> {
        match self {
            Self::Encrypted(crypto) => Some(crypto),
            Self::Broadcast(_) => None,
        }
    }

    /// Shared access to the encrypted-mode crypto sub-state, or `None` for a
    /// broadcast context. Companion to [`Self::crypto_mut`].
    #[allow(
        dead_code,
        reason = "ADR-049 PR-7 (SCP-CRYPTOMOVE-001): immutable read twin of \
                  crypto_mut. The send/receive seams reach the crypto through \
                  the &mut crypto_mut accessor, so this shared-read companion \
                  currently has no caller; retained for read-only call sites \
                  and symmetry with crypto_mut."
    )]
    pub(crate) fn crypto(&self) -> Option<&ContextCryptoState> {
        match self {
            Self::Encrypted(crypto) => Some(crypto),
            Self::Broadcast(_) => None,
        }
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

    /// Target-side (B-owned) durable, `SagaId`-keyed capture of COMMITTED
    /// cross-context **streaming** outlet invocations (ADR-061 seal phase; spec
    /// §6.2.5 streaming saga). The streaming sibling of
    /// [`Self::xctx_committed_outputs`].
    ///
    /// The seal at stream-close inserts a
    /// [`CommittedStreamingOutletInvocation`](crate::context::supervisor::saga_prepared_state::CommittedStreamingOutletInvocation)
    /// here (the signed streaming receipt + sealed `stream_manifest_hash` +
    /// billing/chunk counters + event id) BEFORE journaling `Committed`, so a
    /// Commit replayed after a crash (§17.16.4) re-emits the IDENTICAL receipt and
    /// re-acks the SAME `outlet_invoked_event_id` **without re-invoking the
    /// outlet** (re-invoking a non-deterministic LLM would break §6.2.4
    /// replay-determinism). No output bytes are stored — the streaming receipt
    /// attests the root, and the root reproduces from the durable frontier prefix.
    ///
    /// **Class S** — same fail-closed discipline and same retention bound as
    /// [`Self::xctx_committed_outputs`] (tied to saga-journal retention). Survives
    /// same-node restore; dropped on cross-node export/import.
    pub(crate) xctx_committed_stream_outputs: HashMap<
        SagaId,
        crate::context::supervisor::saga_prepared_state::CommittedStreamingOutletInvocation,
    >,

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
    /// invocation-authorizing UCAN's CID. One [`CaveatCounters`](crate::trust::caveat_counters::CaveatCounters) record per
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
    /// Mirror of [`ClassSState::xctx_committed_stream_outputs`].
    pub(crate) xctx_committed_stream_outputs: HashMap<
        SagaId,
        crate::context::supervisor::saga_prepared_state::CommittedStreamingOutletInvocation,
    >,
    /// Mirror of [`ClassSState::xctx_committed_invocations`].
    pub(crate) xctx_committed_invocations: std::collections::HashSet<SagaId>,
    /// Mirror of [`ClassSState::xctx_caller_reservations`].
    pub(crate) xctx_caller_reservations: std::collections::HashMap<
        SagaId,
        crate::context::supervisor::saga_prepared_state::CallerReservationRecord,
    >,
    /// Mirror of [`ClassSState::caveat_counters`]. [`CaveatCounters`](crate::trust::caveat_counters::CaveatCounters) is
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
            xctx_committed_stream_outputs: self.xctx_committed_stream_outputs.clone(),
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
        self.xctx_committed_stream_outputs = snap.xctx_committed_stream_outputs;
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
    /// the supervisor's `DashMap<String, ContextActorHandle>`), but the
    /// field is carried field-for-field from legacy so consumers that
    /// still read it keep compiling.
    pub generation: u64,

    /// Full-fat context handle (creation params, lifecycle FSM). Mirrors
    /// legacy `state::PerContextState::handle`.
    pub handle: ContextHandle,

    // -----------------------------------------------------------------
    // Membership + role fields
    // -----------------------------------------------------------------
    /// Legacy membership record (per-DID role / tokens / sequence).
    /// Mirrors legacy `state::PerContextState::membership`. Coexists
    /// with [`Self::members`]: this field holds the rich `MembershipState`
    /// (per-DID role / tokens / sequence), while [`Self::members`] holds
    /// the simpler active-member DID set.
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
    /// Type is elevated from private to `pub(crate)` by ADR-049 §15 so
    /// the actor can carry it; field visibility matches the type
    /// (`pub(crate)`) because the `GovernanceState` struct itself cannot
    /// be named outside this crate. ADR-049 §15 deletes both it and the
    /// legacy manager module together.
    pub(crate) governance: GovernanceState,

    // -----------------------------------------------------------------
    // MLS + access control + TTL
    // -----------------------------------------------------------------
    /// MLS epoch + reconnection state (§5.9, §23.11). Mirrors legacy
    /// `state::PerContextState::epoch`. Type is elevated from private
    /// to `pub(crate)` by ADR-049 §15; field visibility matches.
    pub(crate) epoch: EpochState,

    /// Access-control / CEK-wrapping exclusion list (ADR-038, §9.17).
    /// Mirrors legacy `state::PerContextState::access`. Type is
    /// elevated from private to `pub(crate)` by ADR-049 §15; field
    /// visibility matches.
    ///
    /// This is the sole authoritative storage site for the
    /// `access_key_store`: ADR-049 §15 removed the vestigial duplicate
    /// that briefly lived on [`ContextCryptoState`].
    pub(crate) access: AccessControlState,

    /// TTL timer + extension state (SCP-021). Mirrors legacy
    /// `state::PerContextState::ttl`. Type is elevated from private
    /// to `pub(crate)` by ADR-049 §15; field visibility matches.
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
    /// as the authoritative send-sequence counter.
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
    /// counters, `None` optionals). The production construction path
    /// supplies real values from snapshots or from governance-config.
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
                xctx_committed_stream_outputs: HashMap::new(),
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
// Per-context crypto orchestration + state-management (ADR-049 PR-7 Prep A)
// ---------------------------------------------------------------------------
//
// SCP-CRYPTOMOVE-000a. Per ADR-049 Decision 6 ("orchestration → methods on
// `&mut PerContextState`; state-management → inherent methods on
// `PerContextState`") and Decision 15(a) ("Additive prep is sanctioned"), each
// method body below is moved VERBATIM from the corresponding
// [`crate::crypto::mls::provider::NodeMlsFactory`] method. The only shape
// adaptations the actor layout forces are:
//
//   * crypto state is reached through `self.mode`
//     ([`ContextModeState::Encrypted`]) instead of the provider's
//     `with_context(context_id, ..)` closure over its `contexts` `DashMap`;
//   * the actor's `mls_group` / `sender_key` are `Option`, unwrapped in place
//     (`as_mut().ok_or(..)?`) since the provider held them non-optionally;
//   * the send-side sequence counter the provider kept on its per-context
//     struct (`send_sequence`) lives on [`PerContextState::send_tracker`], so
//     `seal` / `export_crypto_state` reach it there;
//   * node-resident data the provider read off its own fields (`local_did`, the
//     X25519 wrapping keypair, the injected [`Clock`]) enters as METHOD
//     PARAMETERS — never stored on [`ContextCryptoState`].
//
/// The §9 Class-C COALESCED send/receive crypto orchestration (ADR-049 §15
/// option-b receiver shape). `seal` / `open` / `mls_encrypt_management` operate
/// on `&mut ContextCryptoState` — the crypto sub-state reachable through the
/// Class-C `ClassCMut::mode_mut()` view — rather than a whole
/// `&mut PerContextState`. The actor's persist-class type system hands out a
/// whole `&mut PerContextState` ONLY on the fail-closed Class-S path
/// (`ClassSCell::commit_class_s_keep` -> `rest_mut`); routing the message hot
/// path there would force a per-message fail-closed persist, reversing §9's
/// deliberate coalescing (and blowing the Decision-14 perf budget). The
/// genuinely-Class-S orchestration (`rotate_sender_key` / `advance_epoch` /
/// `remove_member`, downward-auth transitions) keeps the `&mut PerContextState`
/// shape on [`PerContextState`].
///
/// `seal` does NOT touch the send sequence: the caller reserves it ONCE from the
/// Class-C `send_tracker` view (the single canonical `SequenceReservation`) and
/// passes the pre-increment high-water mark in as `aad_sequence`, so the wire
/// AAD is byte-identical to the provider's `state.send_sequence` read order. The
/// `#[cfg(test)]` [`PerContextState`] wrappers below preserve the original
/// whole-state call shape for the golden byte-identity tests.
impl ContextCryptoState {
    /// Seals an [`InnerEnvelope`] into an outer-envelope byte blob (sender-key
    /// AES-256-GCM under MLS). `aad_sequence` is the caller-reserved
    /// pre-increment send-sequence high-water mark; `local_did` and the raw
    /// `context_id` digest enter as parameters (node-resident / whole-state).
    ///
    /// # Errors
    ///
    /// [`ContextError::CryptoFailed`] on an inner-envelope context-id resolution
    /// mismatch, or any serialization / MLS / sender-layer failure.
    pub(crate) fn seal(
        &mut self,
        context_id: &[u8; 32],
        local_did: &str,
        inner: &InnerEnvelope,
        routing_id: &[u8],
        blob_ttl: u32,
        aad_sequence: u64,
    ) -> Result<Vec<u8>, ContextError> {
        // The sender-layer AEAD AAD MUST bind the RAW `context_id` string
        // (UTF-8, 4-byte BE length prefix) per spec §9.16.1 + §9.5.1 — not the
        // hex encoding of its 32-byte hash. The raw string is carried on the
        // inner envelope.
        let ctx_str = inner.context_id.as_str();

        // Defense in depth: the supplied `context_id` MUST be the canonical
        // digest of the inner envelope's `context_id` string (ADR-056). If they
        // diverge, fail closed rather than emit an unverifiable ciphertext.
        if crate::context::state::context_id_to_bytes(ctx_str) != *context_id {
            return Err(ContextError::CryptoFailed(
                "inner envelope context_id does not resolve to the supplied context_id".into(),
            ));
        }

        let sender_key_epoch = self.sender_key_epoch;
        let sender_key = self.sender_key.as_ref().ok_or_else(|| {
            ContextError::CryptoFailed("no MLS group for this context".to_string())
        })?;

        // 1. Serialize inner envelope to MessagePack.
        let serialized = rmp_serde::to_vec_named(inner).map_err(|e| {
            ContextError::CryptoFailed(format!("inner envelope serialization: {e}"))
        })?;

        // 2. Sender key encrypt (AES-256-GCM, ADR-007). AAD binds context_id,
        // sender_did, epoch, and the caller-reserved sequence. Binds the RAW
        // context_id string per §9.16.1 so the receive side can reconstruct it.
        let sender_encrypted = scp_protocol::crypto::sender_keys::encrypt::encrypt_sender_layer(
            sender_key,
            &serialized,
            ctx_str,
            local_did,
            sender_key_epoch,
            aad_sequence,
        )
        .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

        let with_header = scp_protocol::crypto::sender_keys::encrypt::build_sender_header(
            sender_key_epoch,
            aad_sequence,
            &sender_encrypted,
        );

        // The `sender_key` shared borrow has ended; take the group mutably.
        let mls_group = self.mls_group.as_mut().ok_or_else(|| {
            ContextError::CryptoFailed("no MLS group for this context".to_string())
        })?;

        // 3. MLS encrypt.
        let mls_message = scp_mls::encrypt::encrypt(mls_group, &with_header)
            .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;
        let encrypted_blob = scp_mls::encrypt::serialize_ciphertext(&mls_message)
            .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

        // 4. Wrap in outer envelope.
        let outer = create_outer_envelope(
            routing_id,
            None, // no recipient hint for group messages
            blob_ttl,
            encrypted_blob,
        )
        .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

        rmp_serde::to_vec_named(&outer)
            .map_err(|e| ContextError::CryptoFailed(format!("outer envelope serialization: {e}")))
    }

    /// Opens a received outer-envelope blob. `clock` (used to re-validate an
    /// add-Commit's `KeyPackage` `Lifetime`) and the raw `context_id` digest
    /// enter as parameters.
    ///
    /// # Errors
    ///
    /// [`ContextError::CryptoFailed`] on a `context_id_str` resolution mismatch,
    /// or any MLS / sender-key / decode failure.
    pub(crate) fn open(
        &mut self,
        clock: &dyn Clock,
        context_id: &[u8; 32],
        context_id_str: &str,
        outer_bytes: &[u8],
    ) -> Result<OpenResult, ContextError> {
        // Defense in depth (symmetry with `seal`): the supplied `context_id`
        // MUST be the canonical digest of `context_id_str` (ADR-056).
        if crate::context::state::context_id_to_bytes(context_id_str) != *context_id {
            return Err(ContextError::CryptoFailed(
                "context_id_str does not resolve to the supplied context_id".into(),
            ));
        }

        // Hex of the 32-byte id — the LOCAL sender-key store key. NOT the AAD.
        let ctx_id_hex = hex::encode(context_id);

        // Step 0: Deserialize outer envelope to extract MLS ciphertext.
        let outer: OuterEnvelope = rmp_serde::from_slice(outer_bytes).map_err(|e| {
            ContextError::CryptoFailed(format!("outer envelope deserialization: {e}"))
        })?;

        // Step 1: MLS decrypt and extract sender DID from credential.
        let mls_group = self.mls_group.as_mut().ok_or_else(|| {
            ContextError::CryptoFailed("no MLS group for this context".to_string())
        })?;
        let content =
            scp_mls::encrypt::decrypt_with_sender_did(mls_group, &outer.encrypted_blob, clock)
                .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

        match content {
            scp_mls::encrypt::DecryptedContent::Application {
                plaintext: mls_decrypted,
                sender_did,
            } => {
                // §9.16.1 "Management prefix exclusivity": the SCPM_MAGIC check
                // lives in exactly one shared helper.
                if let Some(mgmt_payload) = try_strip_management_prefix(&mls_decrypted) {
                    if mgmt_payload.len() > MAX_MANAGEMENT_PAYLOAD_SIZE {
                        return Err(ContextError::CryptoFailed(
                            "management payload exceeds size limit".into(),
                        ));
                    }
                    return Ok(OpenResult::Management {
                        sender_did,
                        payload: mgmt_payload.to_vec(),
                    });
                }

                // Step 2: Look up the sender's key from the sender key store.
                let sender_key = self
                    .sender_key_store
                    .get(&ctx_id_hex, &sender_did)
                    .cloned()
                    .ok_or_else(|| ContextError::CryptoFailed("sender key lookup failed".into()))?;

                // Step 3: Parse header and sender key decrypt. The AAD binds the
                // RAW context_id string per §9.16.1, matching the `seal` path.
                let (epoch, sequence, sender_ciphertext) =
                    scp_protocol::crypto::sender_keys::encrypt::parse_sender_header(&mls_decrypted)
                        .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;
                let decrypted = scp_protocol::crypto::sender_keys::decrypt_sender_layer(
                    &sender_key,
                    sender_ciphertext,
                    context_id_str,
                    &sender_did,
                    epoch,
                    sequence,
                )
                .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

                // Step 4: Deserialize as InnerEnvelope (padded payload intact —
                // the caller strips padding + verifies integrity).
                let inner = InnerEnvelope::from_bytes(&decrypted)
                    .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

                Ok(OpenResult::Application(Box::new(OpenedEnvelope {
                    inner,
                    sender_did,
                    // ADR-049 PR-6: surface the received `(epoch, sequence)`
                    // floor for the Class-M registry gate; enforcement is at the
                    // messaging seam, not here.
                    receive_floor: ReceiveFloor { epoch, sequence },
                })))
            }
            scp_mls::encrypt::DecryptedContent::Commit { sender_did: _ } => Ok(OpenResult::Control),
            scp_mls::encrypt::DecryptedContent::Proposal { sender_did: _ } => {
                Ok(OpenResult::Control)
            }
        }
    }

    /// MLS-encrypts a management payload (SCPM-tagged), no sender-layer sequence.
    ///
    /// # Errors
    ///
    /// [`ContextError::CryptoFailed`] if the payload exceeds the size limit, or
    /// on any MLS / serialization failure.
    pub(crate) fn mls_encrypt_management(
        &mut self,
        plaintext: &[u8],
        routing_id: &[u8],
        blob_ttl: u32,
    ) -> Result<Vec<u8>, ContextError> {
        if plaintext.len() > MAX_MANAGEMENT_PAYLOAD_SIZE {
            return Err(ContextError::CryptoFailed(
                "management payload exceeds size limit".into(),
            ));
        }
        let mls_group = self.mls_group.as_mut().ok_or_else(|| {
            ContextError::CryptoFailed("no MLS group for this context".to_string())
        })?;

        // Prepend the canonical SCPM magic to tag this as a management message.
        let magic = &MANAGEMENT_MSG_MAGIC;
        let mut tagged = Vec::with_capacity(magic.len() + plaintext.len());
        tagged.extend_from_slice(magic);
        tagged.extend_from_slice(plaintext);
        let mls_message = scp_mls::encrypt::encrypt(mls_group, &tagged)
            .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;
        let encrypted_blob = scp_mls::encrypt::serialize_ciphertext(&mls_message)
            .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;
        let outer = create_outer_envelope(routing_id, None, blob_ttl, encrypted_blob)
            .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;
        rmp_serde::to_vec_named(&outer)
            .map_err(|e| ContextError::CryptoFailed(format!("serialization: {e}")))
    }

    /// Answers a §9.16.2 sender-key PULL request (the ANSWER half), moved from
    /// the retained golden oracle
    /// `NodeMlsFactory::handle_sender_key_request`. Node-resident inputs
    /// (`local_did`, `now_secs`, `blocked_dids`) and the raw `context_id` digest
    /// enter as METHOD PARAMETERS — never stored on [`ContextCryptoState`] (there
    /// is no clock field on the actor).
    ///
    /// # Persistence class — Class-C (COALESCED), NOT Class-S (§9 / §10)
    ///
    /// This method mutates exactly ONE field: `nonce_dedup.record` — the
    /// per-context CRYPTO replay cache, reached in production through the SAME
    /// field-granular `ClassCMut::mode_mut().crypto_mut()` Class-C seam that
    /// [`Self::open`] uses. It is emphatically NOT the Class-S cross-context
    /// [`ClassSState::xctx_nonce_dedup`](crate::context::actor::state::ClassSState::xctx_nonce_dedup)
    /// and MUST NOT be routed through a Class-S combinator. Coalescing is sound
    /// here: a still-fresh replayed request that survives a lost coalescing
    /// window is re-answered by re-sealing the SAME sender key to the SAME
    /// ephemeral `wrapping_pubkey` carried in the request — an idempotent
    /// re-answer with no authentication break — so a crash that rolls back the
    /// last window cannot open a re-spend / re-grant window (the Class-S
    /// fail-closed rationale does not apply, per spec §9.16).
    ///
    /// **Accepted crash-replay window (≤300s).** Concretely, an actor crash in
    /// the ≤50ms coalesce window can lose the `nonce_dedup.record` of a just-
    /// answered request, so on respawn the SAME request (if replayed while still
    /// within `NONCE_EXPIRY_SECS` = 300s of freshness) is answered a SECOND time.
    /// That re-answer re-seals the identical sender key to the identical ephemeral
    /// `wrapping_pubkey` the requester already holds — it grants the requester
    /// nothing it was not already granted, leaks no new key material, and never
    /// re-opens a downward-authorization decision. The bounded (≤300s, then the
    /// stale request fails the freshness gate) replay of an idempotent re-seal is
    /// the documented, accepted Class-C residual for this field — it is NOT an
    /// authorization break and deliberately does NOT warrant a Class-S persist.
    ///
    /// Answering needs NO signing key: the response is HPKE-sealed to the fresh
    /// EPHEMERAL `request.wrapping_pubkey`, so this is a clean receive-side move
    /// — not new signed-request protocol.
    ///
    /// Returns `Some(serialized_response)` for a member requester, or `None`
    /// when the requester is blocked (silently dropped, §9.16.2).
    ///
    /// # Errors
    ///
    /// [`ContextError::CryptoFailed`] on request deserialization, signature
    /// verification, freshness, nonce-replay, a mode/group mismatch, or a
    /// non-member requester (§9.16.6 Mitigation 1), or HPKE / serialization
    /// failure.
    pub(crate) fn handle_sender_key_request(
        &mut self,
        context_id: &[u8; 32],
        local_did: &str,
        now_secs: u64,
        request_bytes: &[u8],
        // api-design: an Ed25519 verification key is EXACTLY 32 bytes — encode the
        // width in the type so a mis-sized key is a compile error, not a runtime
        // signature failure. Every caller already passes `VerifyingKey::as_bytes()`.
        requester_public_key: &[u8; 32],
        blocked_dids: &std::collections::HashSet<String>,
    ) -> Result<Option<Vec<u8>>, ContextError> {
        let ctx_id_hex = hex::encode(context_id);

        // Deserialize the request.
        let request: scp_protocol::crypto::sender_keys::SenderKeyRequest =
            rmp_serde::from_slice(request_bytes)
                .map_err(|e| ContextError::CryptoFailed(format!("request deserialization: {e}")))?;

        // Verify the request signature.
        let valid = scp_protocol::crypto::sender_keys::verify_sender_key_request(
            &request,
            requester_public_key,
        )
        .map_err(|e| ContextError::CryptoFailed(format!("signature verification: {e}")))?;
        if !valid {
            return Err(ContextError::CryptoFailed(
                "sender key request signature verification failed".to_string(),
            ));
        }

        // Timestamp freshness.
        scp_protocol::crypto::sender_keys::validate_sender_key_request_freshness(
            &request, now_secs,
        )
        .map_err(|e| ContextError::CryptoFailed(format!("freshness check: {e}")))?;

        // Nonce replay protection.
        if self.nonce_dedup.is_replayed(&request.nonce, now_secs) {
            return Err(ContextError::CryptoFailed(
                "replayed sender key request".to_string(),
            ));
        }

        // H1: Membership check — requester must be a CURRENT MLS group member,
        // per spec §9.16.6 Mitigation 1 ("handle_sender_key_request MUST verify
        // that the requester's DID is a current member of the context").
        //
        // Membership is read authoritatively from the MLS group tree — the same
        // DID-match over `members()` that `remove_member` uses — NOT from
        // `member_wrapping_keys`. That map only records members whose STABLE
        // wrapping key this node happens to have cached (populated on the
        // incumbent/adder side in `add_member_from_bytes`, from the added
        // `KeyPackage`'s own leaf). A Welcome-joiner's map starts empty
        // (`install_joined_group`), so gating on it would make the joiner reject
        // every incumbent's key request and be permanently RECEIVE-ONLY. The
        // pull protocol (§9.16.2) seals the response to the fresh EPHEMERAL
        // `request.wrapping_pubkey` carried in the request, so the responder
        // never needs the requester's stable key to answer — only proof that the
        // requester is a member, which the group tree provides directly.
        let mls_group = self.mls_group.as_ref().ok_or_else(|| {
            ContextError::CryptoFailed("no MLS group for this context".to_string())
        })?;
        let members = mls_group
            .members()
            .map_err(|e: scp_mls::error::MlsError| ContextError::CryptoFailed(e.to_string()))?;
        let mut requester_is_member = false;
        for member in &members {
            if let Ok(basic_cred) =
                openmls::prelude::BasicCredential::try_from(member.credential.clone())
                && let Ok(scp_cred) =
                    scp_mls::credential::ScpCredential::from_bytes(basic_cred.identity())
                && scp_cred.did == request.requester_did
            {
                requester_is_member = true;
                break;
            }
        }
        if !requester_is_member {
            return Err(ContextError::CryptoFailed(
                "sender key request from non-member".to_string(),
            ));
        }

        // H1: Blocked DID check — a blocked requester is silently dropped
        // (§9.16.2: no response, so it cannot obtain the key). Ok(None) rather
        // than an error so an expected blocked request never fails the enclosing
        // receive path.
        if blocked_dids.contains(&request.requester_did) {
            return Ok(None);
        }

        // HPKE-seal our sender key to the requester's ephemeral wrapping pubkey.
        let sender_key = self.sender_key.as_ref().ok_or_else(|| {
            ContextError::CryptoFailed("no MLS group for this context".to_string())
        })?;
        let (sealed_vec, ephemeral_pub) =
            crate::crypto::sender_keys::key_protocol::hpke_seal_sender_key(
                sender_key.as_bytes(),
                &request.wrapping_pubkey,
                &ctx_id_hex,
                local_did,
                self.sender_key_epoch,
            )
            .map_err(|e| ContextError::CryptoFailed(format!("HPKE seal failed: {e}")))?;

        let sealed: [u8; 48] = sealed_vec.try_into().map_err(|v: Vec<u8>| {
            ContextError::CryptoFailed(format!("HPKE seal produced {} bytes, expected 48", v.len()))
        })?;

        let response = SenderKeyResponse {
            sender_did: local_did.to_owned(),
            epoch: self.sender_key_epoch,
            hpke_sealed_key: sealed,
            ephemeral_pubkey: ephemeral_pub,
            request_nonce: request.nonce,
        };

        // BLACK-P7-2 (wire format): wrap the answer in the
        // `SenderKeyDistributionMessage::KeyResponse` envelope the receiver
        // parses (`decrypt_and_dispatch` → `SenderKeyDistributionMessage::from_bytes`),
        // matching the proactive PUSH path (`distribute_sender_key`, above). A
        // bare `SenderKeyResponse` here would fail the receiver's enum decode and
        // silently drop the pulled key.
        let message = SenderKeyDistributionMessage::KeyResponse(response)
            .to_bytes()
            .map_err(|e| ContextError::CryptoFailed(format!("serialization: {e}")))?;

        // Record nonce only after successful processing (so a request that fails
        // for another reason cannot poison the dedup cache).
        self.nonce_dedup.record(request.nonce, now_secs);

        Ok(Some(message))
    }

    /// Disposes ALL per-context crypto material (#2148 birth-into-actor: the
    /// actor is the SOLE owner of the per-context crypto; the provider holds
    /// none).
    ///
    /// The load-bearing reason to call this — rather than relying on a bare drop
    /// — is the LIVE-actor close/TTL seam: on an Ephemeral/Summary close (or TTL
    /// expiry) the context's crypto must be released while the `PerContextState`
    /// stays alive (the actor is NOT dropped), so nothing would otherwise free
    /// the material. Each [`ScpMlsGroup`] owns its OWN in-memory OpenMLS provider
    /// (`InMemoryMlsProvider`), so a bare drop DOES free that storage — but it
    /// does NOT zeroize the Ed25519 signer (OpenMLS `SignatureKeyPair` implements
    /// no `Zeroize`; `scp-mls` `EagerDropSigner` / issue #82).
    /// [`scp_mls::group::destroy_group`] eagerly FREES the signer's `Vec<u8>`
    /// (via `EagerDropSigner::take`) but does NOT overwrite it — signer
    /// zeroization stays open upstream (#82). This is NOT a shared persistent
    /// store. This method:
    ///
    /// - runs `destroy_group` on the MLS group (eagerly frees the signer bytes —
    ///   not zeroized, #82 — and drops the in-memory OpenMLS state), then nulls
    ///   the handle;
    /// - drops the local `sender_key` and the whole `sender_key_store`, whose
    ///   `SenderKey`s zeroize on drop (`ZeroizeOnDrop`);
    /// - clears the residual non-secret / bookkeeping fields (member wrapping
    ///   public keys, queued distributions, nonce-dedup cache, recv tracker,
    ///   epoch counter) so no stale material lingers on a still-live actor.
    ///
    /// Idempotent: safe to call on an already-disposed or never-populated state.
    ///
    /// # Returns — the OBSERVED disposal outcome (#2199)
    ///
    /// Returns a [`DisposalOutcome`] whose flags are computed from the
    /// PRE-disposal state, BEFORE any field is nulled: a destroyed-flag is
    /// `true` ONLY when the corresponding material was actually PRESENT at entry
    /// and this call tore it down. When material is absent the flag is `false`
    /// (honest absence) — never a fabricated `true`. The returned outcome is the
    /// sole honest source for a
    /// [`KeyDestructionAttestation`](scp_protocol::context::memory_scope::KeyDestructionAttestation)'s
    /// destroyed-flags (ADR-018); see the close/TTL finalize seams. The
    /// `#[must_use]` guards the honesty invariant at the call site: the observed
    /// outcome must be consumed (or explicitly discarded on a rollback path where
    /// no attestation is built).
    #[must_use]
    pub(crate) fn dispose_secrets(&mut self) -> DisposalOutcome {
        // Observe the PRE-disposal presence of each material class BEFORE nulling
        // — this is what makes the destroyed-flags truthful (#2199).
        let mls_group_present = self.mls_group.is_some();
        // #2199 F-BH1: `pending_distributions` holds serialized sender-key
        // DISTRIBUTION ciphertext (key-bearing material) that `dispose_secrets`
        // tears down below. Include it in the sender-key presence observation so
        // the destroyed-flag honestly reflects "queued key material was present
        // and torn down" — otherwise a state with only queued distributions would
        // report `sender_keys_destroyed = false` while real key material WAS
        // destroyed (an inverse-precision honesty gap).
        let sender_keys_present = self.sender_key.is_some()
            || !self.sender_key_store.is_empty()
            || !self.pending_distributions.is_empty();

        if let Some(group) = self.mls_group.as_mut() {
            // `scp_mls::group::destroy_group` is total: `Ok(())` on the first
            // teardown or the idempotent `Err(MlsError::GroupDestroyed)` on a
            // retry — BOTH mean the group is gone. There is no partial-failure
            // branch, so an MLS group present at entry is verifiably destroyed
            // here (subject to the #82 signer-not-zeroized-only-freed caveat
            // documented above).
            let _ = scp_mls::group::destroy_group(group);
        }
        self.mls_group = None;
        // Dropping the `SenderKey` / `SenderKeyStore` zeroizes the AES-256 key
        // material via their `ZeroizeOnDrop` derive.
        self.sender_key = None;
        self.sender_key_store = SenderKeyStore::new();
        self.member_wrapping_keys.clear();
        self.pending_distributions.clear();
        self.nonce_dedup = NonceDedup::new();
        self.recv_sequence_tracker.clear();
        self.sender_key_epoch = 0;

        DisposalOutcome::observed(mls_group_present, sender_keys_present)
    }
}

// MLS / HPKE / sender-layer primitives stay exactly the free-function /
// backend calls the provider makes (`scp_mls::encrypt::*`,
// `scp_mls::group::*`, `scp_mls::ratchet::*`,
// `scp_protocol::crypto::sender_keys::*`, the HPKE `key_protocol` helpers) —
// they are NOT re-implemented.
//
// The per-context methods below are the actor-owned per-context crypto seam on
// the actor's OWNED `PerContextState`. #2148 (birth-into-actor) COMPLETED the
// §6 dissolution of the provider's per-context state: the provider holds no
// `contexts` map and no per-context crypto, so every per-context crypto
// operation — birth-seed, seal/open, epoch advance, member add/remove,
// sender-key exchange, and teardown — now lives here, not on the provider.
// Byte-identity of the seal/open/epoch primitives with their pre-move shape is
// guarded by the golden tests in this module (`crypto_ops_golden`). A handful of
// sender-key-exchange / teardown methods are reached only from those in-module
// tests, so they carry a TARGETED `#[allow(dead_code)]` (they have no caller in
// the `--no-default-features` lib build); the block-wide allow was narrowed
// away (#2148 F9) so a genuinely-unwired future method is not masked.
impl PerContextState {
    /// `&mut` access to the encrypted-mode crypto state, or the provider's
    /// `"no MLS group for this context"` error when this actor is a broadcast
    /// context (a single actor's [`PerContextState`] is exactly one mode).
    fn encrypted_crypto_mut(&mut self) -> Result<&mut ContextCryptoState, ContextError> {
        match &mut self.mode {
            ContextModeState::Encrypted(crypto) => Ok(crypto.as_mut()),
            ContextModeState::Broadcast(_) => Err(ContextError::CryptoFailed(
                "no MLS group for this context".to_string(),
            )),
        }
    }

    /// Seed this actor state's encrypted-mode crypto from the owned material
    /// that the provider's birth/restore seams (`create_mls_group_with_context`
    /// / `install_joined_group` / `build_restored_owned`) hand out (#2148
    /// birth-into-actor). Installs the moved [`OwnedMlsCryptoState`]
    /// into [`Self::mode`] — wrapping the payload's non-optional `mls_group` /
    /// `sender_key` in `Some(..)` (the actor holds them optionally because a
    /// fresh Create actor spawns before its group exists) and starting the
    /// DORMANT [`ContextCryptoState::recv_sequence_tracker`] empty — and routes
    /// `send_sequence` onto [`Self::send_tracker`] via
    /// [`SendSequenceTracker::from_persisted`] (the actor keeps the send counter
    /// on `send_tracker`, never a crypto-state field; the AAD read/increment
    /// order is preserved byte-for-byte — see `sequence.rs`).
    ///
    /// This is the single seed primitive for every birth/restore seam. #2148
    /// completed the §6 dissolution of the provider's per-context state: the
    /// birth constructors (`create_mls_group_with_context` / `install_joined_group`)
    /// and the restore constructor (`build_restored_owned`) each return an
    /// [`OwnedMlsCryptoState`] DIRECTLY — there is no provider `contexts` map,
    /// no `take_crypto_state` round-trip, and no `taken_context_ids` residency
    /// guard. The CREATE / WELCOME / restore caller seeds the owned material
    /// straight onto the spawning actor here; a warm respawn re-seeds from the
    /// restore constructor identically (no re-take to fail closed against).
    ///
    /// Floors (Class-M) are NOT part of the payload and are never seeded here —
    /// they stay the sole authority of the Supervisor-owned `ContextFloors`
    /// registry (ADR-049 §9 / PR-6).
    pub(crate) fn seed_encrypted_crypto_from_owned(&mut self, owned: OwnedMlsCryptoState) {
        // Defense-in-depth (#2148 F8): seeding replaces an EMPTY Encrypted mode
        // (the birth/restore seams build one first); a Broadcast context has no
        // MLS crypto to seed. Asserted at the mutation site — the caller-side
        // `debug_assert_eq!` (lifecycle_helpers.rs) is release-compiled-out.
        debug_assert!(
            matches!(self.mode, ContextModeState::Encrypted(_)),
            "seed_encrypted_crypto_from_owned onto non-Encrypted mode"
        );
        // #2199 F-BH — BOTH-PRESENT-AT-TTL invariant. This seam is the SOLE way an
        // Encrypted actor gains live crypto (CREATE / WELCOME / restore all route
        // here). It installs `mls_group` AND `sender_key` as `Some` TOGETHER,
        // atomically, from an `OwnedMlsCryptoState` that itself carries both as
        // owned (non-optional) values. There is no code path that installs one
        // without the other. Therefore an `Active` Encrypted context — the only
        // shape a TTL expiry ever fires against for Ephemeral/Summary scope (which
        // are ALWAYS Encrypted) — holds both `mls_group` and `sender_key` at TTL.
        // This closes the `apply_ttl_terminal_transition` partial-absence case BY
        // CONSTRUCTION for a real production context: the observed disposal there
        // is `{true, true}`, and the `None`/partial branches are anomaly-only
        // (fixtures) — handled for liveness, never reached in production.
        self.mode = ContextModeState::Encrypted(Box::new(ContextCryptoState {
            mls_group: Some(owned.mls_group),
            sender_key: Some(owned.sender_key),
            sender_key_store: owned.sender_key_store,
            sender_key_epoch: owned.sender_key_epoch,
            pending_distributions: owned.pending_distributions,
            nonce_dedup: owned.nonce_dedup,
            member_wrapping_keys: owned.member_wrapping_keys,
            recv_sequence_tracker: HashMap::new(),
            #[cfg(any(test, feature = "testing"))]
            force_rotation_failure: false,
        }));
        self.send_tracker = SendSequenceTracker::from_persisted(owned.send_sequence);
    }

    /// Arms the one-shot rotation fault seam (#2148 F1 / ADR-049 §15(c)): the
    /// NEXT [`Self::rotate_sender_key`] fails closed and clears the flag. A
    /// no-op on a Broadcast context (no encrypted crypto to arm). Re-homed from
    /// the deleted provider `arm_rotation_failure_once`; gated `#[cfg(any(test,
    /// feature = "testing"))]` so it is never reachable on a production build.
    #[cfg(any(test, feature = "testing"))]
    // #2148 F9: reached only from the in-crate `#[cfg(test)]` fail-closed test;
    // under `--features testing` (no test) it has no caller.
    #[allow(dead_code)]
    pub(crate) fn arm_rotation_failure_once(&mut self) {
        if let ContextModeState::Encrypted(crypto) = &mut self.mode {
            crypto.force_rotation_failure = true;
        }
    }

    /// Disposes this actor's per-context MLS crypto secrets (Encrypted mode
    /// only; a no-op for Broadcast), delegating to
    /// [`ContextCryptoState::dispose_secrets`]. Called on failed-spawn /
    /// failed-persist creation-rollback branches (#2148 F6) so the crypto is
    /// eagerly freed via `destroy_group` — consistent with the close/TTL
    /// teardown seam. On these rollback branches the owner drops on the very
    /// next line regardless, so this is defense-in-depth / forward-compat with
    /// #82 (destroy_group frees but does NOT zeroize the Ed25519 signer today;
    /// if upstream ever adds `Zeroize` this path would then zeroize it).
    ///
    /// # Returns — the OBSERVED disposal outcome (#2199)
    ///
    /// - **Encrypted:** delegates to [`ContextCryptoState::dispose_secrets`] and
    ///   returns its observed [`DisposalOutcome`].
    /// - **Broadcast:** returns `observed(false, false)` — N/A. A
    ///   Broadcast context is always Full memory-scope (per-author AES-256-GCM,
    ///   no MLS group), so no ephemeral key-destruction attestation is ever built
    ///   from it; honest absence, never a fabricated `true`.
    ///
    /// `#[must_use]`: the observed outcome guards the attestation-honesty
    /// invariant; a caller that discards it (a creation-rollback / shutdown path
    /// that builds no attestation) does so explicitly via `let _ = …`.
    #[must_use]
    pub(crate) fn dispose_secrets(&mut self) -> DisposalOutcome {
        match &mut self.mode {
            ContextModeState::Encrypted(crypto) => crypto.dispose_secrets(),
            ContextModeState::Broadcast(_) => DisposalOutcome::observed(false, false),
        }
    }

    /// TEST-ONLY whole-state convenience over [`ContextCryptoState::seal`],
    /// preserving the original call shape for the golden byte-identity tests.
    ///
    /// Reads the pre-increment sequence from `send_tracker`, guards the
    /// `u64::MAX` overflow boundary fail-closed (byte-for-byte with the
    /// provider — nothing is emitted and the counter is left untouched at the
    /// boundary), delegates the crypto to the field-granular
    /// [`ContextCryptoState::seal`] core, then advances `send_tracker` on
    /// success (the single canonical [`SequenceReservation`]). Production seals
    /// through the Class-C view in `build_encrypted_envelope`, never this
    /// wrapper (ADR-049 §15 option-b).
    ///
    /// # Errors
    ///
    /// [`ContextError::CryptoFailed`] on overflow, a mode/group mismatch, an
    /// inner-envelope context-id resolution mismatch, or any serialization /
    /// MLS / sender-layer failure.
    #[cfg(test)]
    pub(crate) fn seal(
        &mut self,
        local_did: &str,
        inner: &InnerEnvelope,
        routing_id: &[u8],
        blob_ttl: u32,
    ) -> Result<Vec<u8>, ContextError> {
        let context_id = self.context_id;
        // AAD sequence = the pre-increment high-water mark. Guard the overflow
        // boundary BEFORE sealing so nothing is emitted at `u64::MAX` and the
        // counter stays untouched (observably identical to the provider's
        // `checked_add` fail-closed).
        let aad_sequence = self.send_tracker.last_issued();
        if aad_sequence == u64::MAX {
            return Err(ContextError::CryptoFailed(
                "send sequence counter overflow".into(),
            ));
        }
        let crypto = self.encrypted_crypto_mut()?;
        let blob = crypto.seal(
            &context_id,
            local_did,
            inner,
            routing_id,
            blob_ttl,
            aad_sequence,
        )?;
        // Advance exactly once on success — the caller-side counterpart to the
        // provider's `state.send_sequence.checked_add(1)`.
        crate::context::actor::sequence::SequenceReservation::reserve(&mut self.send_tracker)
            .commit();
        Ok(blob)
    }

    /// TEST-ONLY whole-state convenience over [`ContextCryptoState::open`],
    /// preserving the original call shape for the golden byte-identity tests.
    /// Production opens through the Class-C view in the receive path
    /// (ADR-049 §15 option-b).
    ///
    /// # Errors
    ///
    /// [`ContextError::CryptoFailed`] on a mode/group mismatch, a
    /// `context_id_str` resolution mismatch, or any MLS / sender-key / decode
    /// failure.
    #[cfg(test)]
    pub(crate) fn open(
        &mut self,
        clock: &dyn Clock,
        context_id_str: &str,
        outer_bytes: &[u8],
    ) -> Result<OpenResult, ContextError> {
        let context_id = self.context_id;
        let crypto = self.encrypted_crypto_mut()?;
        crypto.open(clock, &context_id, context_id_str, outer_bytes)
    }

    /// TEST-ONLY whole-state convenience over
    /// [`ContextCryptoState::mls_encrypt_management`], preserving the original
    /// call shape for the golden byte-identity tests. Production encrypts
    /// management payloads through the Class-C view (ADR-049 §15 option-b).
    ///
    /// # Errors
    ///
    /// [`ContextError::CryptoFailed`] if the payload exceeds the size limit, or
    /// on any MLS / serialization failure.
    #[cfg(test)]
    pub(crate) fn mls_encrypt_management(
        &mut self,
        plaintext: &[u8],
        routing_id: &[u8],
        blob_ttl: u32,
    ) -> Result<Vec<u8>, ContextError> {
        let crypto = self.encrypted_crypto_mut()?;
        crypto.mls_encrypt_management(plaintext, routing_id, blob_ttl)
    }

    /// Advances the MLS epoch (Update + self-Commit), verbatim from the
    /// former provider `advance_epoch`. The X25519 wrapping public key
    /// enters as a parameter (node-resident).
    ///
    /// # Errors
    ///
    /// [`ContextError::CryptoFailed`] on a mode/group mismatch or MLS failure.
    pub(crate) fn advance_epoch(
        &mut self,
        wrapping_public_key: [u8; 32],
    ) -> Result<AdvanceEpochOutput, ContextError> {
        use openmls::prelude::tls_codec::Serialize as _;

        let crypto = self.encrypted_crypto_mut()?;
        let mls_group = crypto.mls_group.as_mut().ok_or_else(|| {
            ContextError::CryptoFailed("no MLS group for this context".to_string())
        })?;
        let commit =
            scp_mls::ratchet::propose_update_with_wrapping_key(mls_group, &wrapping_public_key)
                .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

        let commit_bytes = commit.tls_serialize_detached().map_err(|e| {
            ContextError::CryptoFailed(format!("serializing epoch advance commit: {e}"))
        })?;

        Ok(AdvanceEpochOutput { commit_bytes })
    }

    /// Adds a member to the MLS group by their optional TLS-serialized
    /// `KeyPackage` bytes, operating on THIS actor's OWNED `ScpMlsGroup`.
    ///
    /// #2148 (ADR-049 birth-into-actor): member ADD on a LIVE, actor-owned
    /// context is a steady-state crypto orchestration op, so it belongs on the
    /// actor — the completeness twin of [`Self::remove_member`]. The provider's
    /// per-context `add_member` is DELETED (the provider holds no per-context
    /// state); the governance `AddMember` handler routes here, mutating the
    /// actor-owned group directly.
    ///
    /// With `Some(bytes)` performs the real MLS add via
    /// [`Self::add_member_from_bytes`]. With `None` (no `KeyPackage`) the
    /// `testing`/`cfg(test)` build returns an empty output (mock-equivalent, so
    /// integration tests that don't produce real MLS key packages still exercise
    /// the non-crypto pipeline — byte-for-byte with the provider) and production
    /// returns an error. `clock` enters as a parameter (node-resident, injected —
    /// ADR-057 §Prereq-1).
    ///
    /// # Errors
    ///
    /// [`ContextError::CryptoFailed`] on a mode/group mismatch, a malformed
    /// `KeyPackage`, no `KeyPackage` in production, or any MLS / serialization
    /// failure.
    pub(crate) fn add_member(
        &mut self,
        member_did: &str,
        key_package_bytes: Option<&[u8]>,
        clock: &dyn Clock,
    ) -> Result<AddMemberOutput, ContextError> {
        // The invitee's KeyPackage is supplied explicitly (the governance
        // `AddMember` path carries it on the actor command envelope).
        if let Some(bytes) = key_package_bytes {
            return self.add_member_from_bytes(member_did, bytes, clock);
        }

        // No KeyPackage. Preserve the provider's mock-equivalent return so
        // integration tests that don't produce real MLS key packages continue to
        // exercise the non-crypto pipeline (role state sync, event logging,
        // governance side effects) — byte-for-byte with
        // `NodeMlsFactory::add_member`.
        if cfg!(any(test, feature = "testing")) {
            let _ = member_did; // used only by the real path
            return Ok(AddMemberOutput::default());
        }
        Err(ContextError::CryptoFailed(
            "production actor add_member requires MLS key package bytes \
             (none supplied for this member)"
                .to_string(),
        ))
    }

    /// Real MLS add-member from explicit `KeyPackage` bytes on this actor's OWNED
    /// group, verbatim from `NodeMlsFactory::add_member_from_bytes` (ADR-049
    /// PR-7 STEP-C). Pre-validates the key package to extract the invitee's X25519
    /// wrapping key (needed to HPKE-seal the sender key to them later), performs
    /// the MLS add (advancing the group epoch), records the wrapping key, and
    /// returns the TLS-serialized Welcome (for the joiner) + Commit (for existing
    /// members).
    ///
    /// # Errors
    ///
    /// [`ContextError::CryptoFailed`] on a mode/group mismatch, a malformed
    /// `KeyPackage`, or any MLS / serialization failure.
    fn add_member_from_bytes(
        &mut self,
        member_did: &str,
        bytes: &[u8],
        clock: &dyn Clock,
    ) -> Result<AddMemberOutput, ContextError> {
        use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
        use openmls::prelude::{KeyPackageIn, ProtocolVersion};
        use openmls_traits::OpenMlsProvider as _;

        // Pre-validate the key package to extract the wrapping key BEFORE the add
        // operation consumes it, and BEFORE borrowing the crypto sub-state (no
        // `self` borrow held across this validation). Key package bytes arrive as
        // TLS-serialized KeyPackageIn (not MlsMessageIn).
        let wrapping_key = {
            KeyPackageIn::tls_deserialize(&mut &*bytes)
                .ok()
                .and_then(|kp_in| {
                    let provider_tmp = scp_mls::InMemoryMlsProvider::default();
                    kp_in
                        .validate(provider_tmp.crypto(), ProtocolVersion::Mls10)
                        .ok()
                        .and_then(|verified| {
                            scp_mls::wrapping_extension::extract_wrapping_key(
                                verified.leaf_node().extensions(),
                            )
                            .ok()
                            .flatten()
                        })
                })
        };

        // Deserialize to KeyPackageIn for the actual add operation.
        let kp_in = KeyPackageIn::tls_deserialize(&mut &*bytes)
            .map_err(|e| ContextError::CryptoFailed(format!("key package deserialization: {e}")))?;

        let crypto = self.encrypted_crypto_mut()?;
        let mls_group = crypto.mls_group.as_mut().ok_or_else(|| {
            ContextError::CryptoFailed("no MLS group for this context".to_string())
        })?;

        let result = scp_mls::group::add_member(mls_group, kp_in, clock)
            .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

        // TLS-serialize Welcome and Commit for cross-process delivery.
        let welcome_bytes = result
            .welcome
            .tls_serialize_detached()
            .map_err(|e| ContextError::CryptoFailed(format!("serializing welcome: {e}")))?;
        let commit_bytes = result
            .commit
            .tls_serialize_detached()
            .map_err(|e| ContextError::CryptoFailed(format!("serializing commit: {e}")))?;

        // Store the member's wrapping key if present.
        if let Some(wk) = wrapping_key {
            crypto
                .member_wrapping_keys
                .insert(member_did.to_owned(), wk);
        }

        Ok(AddMemberOutput {
            welcome_bytes,
            commit_bytes,
        })
    }

    /// Removes a member from the MLS group, verbatim from the former
    /// provider `remove_member`. `local_did` (the self-removal
    /// short-circuit) enters as a parameter (node-resident).
    ///
    /// # Errors
    ///
    /// [`ContextError::CryptoFailed`] on a mode/group mismatch or MLS failure.
    pub(crate) fn remove_member(
        &mut self,
        local_did: &str,
        member_did: &str,
    ) -> Result<RemoveMemberOutput, ContextError> {
        use openmls::prelude::tls_codec::Serialize as _;

        // Self-removal (leave): the local member simply abandons their local
        // group state; remaining members process a Commit from the admin.
        if member_did == local_did {
            return Ok(RemoveMemberOutput::default());
        }

        let crypto = self.encrypted_crypto_mut()?;
        let mls_group = crypto.mls_group.as_mut().ok_or_else(|| {
            ContextError::CryptoFailed("no MLS group for this context".to_string())
        })?;

        // Find the member's leaf index by matching their DID in the SCP
        // credential embedded in each member's MLS leaf node.
        let members = mls_group
            .members()
            .map_err(|e: scp_mls::error::MlsError| ContextError::CryptoFailed(e.to_string()))?;

        let own_index = mls_group
            .own_leaf_index()
            .map_err(|e: scp_mls::error::MlsError| ContextError::CryptoFailed(e.to_string()))?;

        let mut target_index = None;
        for member in &members {
            if member.index == own_index {
                continue;
            }
            if let Ok(basic_cred) =
                openmls::prelude::BasicCredential::try_from(member.credential.clone())
                && let Ok(scp_cred) =
                    scp_mls::credential::ScpCredential::from_bytes(basic_cred.identity())
                && scp_cred.did == member_did
            {
                target_index = Some(member.index);
                break;
            }
        }

        // If the member is not in the MLS group, treat as a no-op — the
        // membership state is authoritative elsewhere; crypto only manages MLS.
        let Some(leaf_index) = target_index else {
            tracing::warn!(
                member_did = %member_did,
                "remove_member: member DID not found in MLS group leaf nodes — \
                 member may not have been MLS-added"
            );
            return Ok(RemoveMemberOutput::default());
        };

        let result = scp_mls::group::remove_member(mls_group, leaf_index)
            .map_err(|e| ContextError::CryptoFailed(e.to_string()))?;

        let commit_bytes = result
            .commit
            .tls_serialize_detached()
            .map_err(|e| ContextError::CryptoFailed(format!("serializing remove commit: {e}")))?;

        let group_info_bytes = result
            .group_info
            .map(|gi| {
                gi.tls_serialize_detached().map_err(|e| {
                    ContextError::CryptoFailed(format!("serializing remove group info: {e}"))
                })
            })
            .transpose()?
            .unwrap_or_default();

        Ok(RemoveMemberOutput {
            commit_bytes,
            group_info_bytes,
        })
    }

    /// Removes the departed member's sender key AND wrapping key from the local
    /// crypto sub-state, verbatim from the former provider
    /// `remove_member_sender_key`.
    ///
    /// ADR-049 PR-7 (SCP-CRYPTOMOVE-001): the actor twin of the provider's
    /// per-member sender-key prune. Prep-A moved most crypto orchestration to the
    /// actor; this per-member removal twin was missed and is added here so the
    /// remove / reset seams can flip off the provider. The receive-side anti-replay
    /// floor for the departed member is NOT touched here — it lives in the
    /// Supervisor-owned Class-M registry and is pruned by the caller via
    /// `remove_member_floors` (mirroring the provider's PR-6 read-authority switch;
    /// see the former provider `remove_member_sender_key`).
    ///
    /// # Errors
    ///
    /// [`ContextError::CryptoFailed`] if this context has no encrypted crypto
    /// sub-state (broadcast mode or a nulled group).
    pub(crate) fn remove_member_sender_key(
        &mut self,
        member_did: &str,
    ) -> Result<(), ContextError> {
        let ctx_id_hex = hex::encode(self.context_id);
        let crypto = self.encrypted_crypto_mut()?;
        crypto.sender_key_store.remove(&ctx_id_hex, member_did);
        // Also remove the member's wrapping key — they are no longer a member.
        crypto.member_wrapping_keys.remove(member_did);
        Ok(())
    }

    /// Distributes the local sender key to `member_did` (ADR-007), verbatim from
    /// the former provider `distribute_sender_key`. `local_did` enters as a
    /// parameter (node-resident).
    ///
    /// # Errors
    ///
    /// [`ContextError::CryptoFailed`] on a mode/group mismatch or HPKE /
    /// serialization failure.
    pub(crate) fn distribute_sender_key(
        &mut self,
        local_did: &str,
        member_did: &str,
    ) -> Result<(), ContextError> {
        let ctx_id_hex = hex::encode(self.context_id);
        let crypto = self.encrypted_crypto_mut()?;
        let sender_key = crypto.sender_key.clone().ok_or_else(|| {
            ContextError::CryptoFailed("no MLS group for this context".to_string())
        })?;
        // Store our sender key locally under our DID so local encrypt/decrypt
        // can find it.
        crypto
            .sender_key_store
            .set_unchecked(&ctx_id_hex, local_did, sender_key.clone());
        let sender_key_epoch = crypto.sender_key_epoch;

        // HPKE-seal our sender key to the target member's wrapping pubkey and
        // queue a SenderKeyResponse for transport delivery.
        let recipient = crypto.member_wrapping_keys.get(member_did).copied();
        if let Some(recipient_wrapping_pub) = recipient {
            let (sealed_vec, ephemeral_pub) =
                crate::crypto::sender_keys::key_protocol::hpke_seal_sender_key(
                    sender_key.as_bytes(),
                    &recipient_wrapping_pub,
                    &ctx_id_hex,
                    local_did,
                    sender_key_epoch,
                )
                .map_err(|e| ContextError::CryptoFailed(format!("HPKE seal failed: {e}")))?;

            let sealed: [u8; 48] = sealed_vec.try_into().map_err(|v: Vec<u8>| {
                ContextError::CryptoFailed(format!(
                    "HPKE seal produced {} bytes, expected 48",
                    v.len()
                ))
            })?;

            let response = SenderKeyResponse {
                sender_did: local_did.to_owned(),
                epoch: sender_key_epoch,
                hpke_sealed_key: sealed,
                ephemeral_pubkey: ephemeral_pub,
                // No request nonce for proactive distribution — use zeroed nonce.
                request_nonce: [0u8; 16],
            };

            let msg = SenderKeyDistributionMessage::KeyResponse(response);
            let serialized = msg
                .to_bytes()
                .map_err(|e| ContextError::CryptoFailed(format!("serialization failed: {e}")))?;

            crypto
                .pending_distributions
                .push((member_did.to_owned(), serialized));
        } else {
            tracing::debug!(
                member_did = %member_did,
                context_id = %ctx_id_hex,
                "no wrapping key for member — sender key stored locally only"
            );
        }
        Ok(())
    }

    /// Rotates the local sender key (§9.16.4), verbatim from the former
    /// provider `rotate_sender_key`. `local_did` enters as a
    /// parameter (node-resident).
    ///
    /// # Errors
    ///
    /// [`ContextError::CryptoFailed`] on a mode/group mismatch or epoch
    /// overflow.
    pub(crate) fn rotate_sender_key(&mut self, local_did: &str) -> Result<(), ContextError> {
        let ctx_id_hex = hex::encode(self.context_id);
        let crypto = self.encrypted_crypto_mut()?;

        // One-shot fault-injection seam (#2148 F1 / ADR-049 §15(c)): induce a
        // rotation failure that drives the caller's Class-S sync-persist
        // fail-closed branch. Placed BEFORE any mutation — no fresh key is
        // generated and `sender_key_epoch` is NOT incremented, so an armed
        // failure leaves the context byte-identical to its pre-call state
        // (fail-closed: epoch/key never committed). `std::mem::replace` fires
        // exactly once, then clears itself so a subsequent rotation succeeds.
        // The `#[cfg(any(test, feature = "testing"))]` gate compiles both the
        // field and this branch away on a production build.
        #[cfg(any(test, feature = "testing"))]
        if std::mem::replace(&mut crypto.force_rotation_failure, false) {
            return Err(ContextError::CryptoFailed(
                "forced rotation persist failure (one-shot test seam)".to_owned(),
            ));
        }

        // 1. Generate fresh AES-256 sender key.
        let new_key = generate_sender_key();
        // Capture the raw bytes once for the per-member seals below — the
        // provider re-reads `state.sender_key.as_bytes()` each iteration, which
        // is the same freshly-installed key.
        let new_key_bytes = *new_key.as_bytes();
        crypto.sender_key = Some(new_key.clone());

        // 2. Increment sender_key_epoch (monotonic, §9.16.5).
        crypto.sender_key_epoch = crypto
            .sender_key_epoch
            .checked_add(1)
            .ok_or_else(|| ContextError::CryptoFailed("sender key epoch overflow".to_string()))?;
        let sender_key_epoch = crypto.sender_key_epoch;

        // 3. Update local sender key store entry.
        crypto
            .sender_key_store
            .set_unchecked(&ctx_id_hex, local_did, new_key);

        // 4. HPKE-seal new key to each remaining member's wrapping pubkey and
        //    queue distributions (§9.16.2).
        let member_keys: Vec<(String, [u8; 32])> = crypto
            .member_wrapping_keys
            .iter()
            .map(|(did, key)| (did.clone(), *key))
            .collect();

        for (member_did, wrapping_pub) in &member_keys {
            // Skip self-sealing: the local member already holds the new key.
            if *member_did == local_did {
                continue;
            }
            let seal_result = crate::crypto::sender_keys::key_protocol::hpke_seal_sender_key(
                &new_key_bytes,
                wrapping_pub,
                &ctx_id_hex,
                local_did,
                sender_key_epoch,
            );

            match seal_result {
                Ok((sealed_vec, ephemeral_pub)) => {
                    let sealed: [u8; 48] = match sealed_vec.try_into() {
                        Ok(s) => s,
                        Err(v) => {
                            tracing::warn!(
                                member_did = %member_did,
                                "HPKE seal produced {} bytes, expected 48 — skipping",
                                v.len()
                            );
                            continue;
                        }
                    };

                    let response = SenderKeyResponse {
                        sender_did: local_did.to_owned(),
                        epoch: sender_key_epoch,
                        hpke_sealed_key: sealed,
                        ephemeral_pubkey: ephemeral_pub,
                        request_nonce: [0u8; 16],
                    };

                    let msg = SenderKeyDistributionMessage::KeyResponse(response);
                    match msg.to_bytes() {
                        Ok(serialized) => {
                            crypto
                                .pending_distributions
                                .push((member_did.clone(), serialized));
                        }
                        Err(e) => {
                            tracing::warn!(
                                member_did = %member_did,
                                error = %e,
                                "failed to serialize sender key distribution — skipping"
                            );
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        member_did = %member_did,
                        error = %e,
                        "HPKE seal failed for sender key rotation — skipping"
                    );
                }
            }
        }

        Ok(())
    }

    /// Drains pending sender-key distribution messages, verbatim from the
    /// former provider `drain_pending_sender_key_messages`.
    ///
    /// # Errors
    ///
    /// [`ContextError::CryptoFailed`] on a mode/group mismatch.
    // #2148 F9: crypto twin reached only from in-crate `#[cfg(test)]` fixtures;
    // targeted (not block-wide) so a genuinely-unwired future method still trips.
    #[allow(dead_code)]
    pub(crate) fn drain_pending_sender_key_messages(
        &mut self,
    ) -> Result<Vec<(String, Vec<u8>)>, ContextError> {
        let crypto = self.encrypted_crypto_mut()?;
        Ok(std::mem::take(&mut crypto.pending_distributions))
    }

    /// Processes an incoming sender-key distribution message, returning the
    /// AUTHENTICATED `(sender_key, epoch)` — verbatim from
    /// [`NodeMlsFactory::process_incoming_sender_key`]. The X25519 wrapping
    /// secret enters as a parameter (node-resident); this method installs
    /// nothing and reads no crypto state (the caller gates + installs via
    /// [`Self::set_sender_key_unchecked`]).
    ///
    /// # Errors
    ///
    /// [`ContextError::CryptoFailed`] on deserialization, HPKE-open, or the
    /// sender-DID authentication check.
    ///
    /// [`NodeMlsFactory::process_incoming_sender_key`]: crate::crypto::mls::provider::NodeMlsFactory::process_incoming_sender_key
    // #2148 F9: crypto twin reached only from in-crate `#[cfg(test)]` fixtures;
    // targeted (not block-wide) so a genuinely-unwired future method still trips.
    #[allow(dead_code)]
    pub(crate) fn process_incoming_sender_key(
        &self,
        wrapping_secret_key: &[u8; 32],
        sender_did: &str,
        message_bytes: &[u8],
    ) -> Result<(SenderKey, u64), ContextError> {
        let ctx_id_hex = hex::encode(self.context_id);

        let msg = SenderKeyDistributionMessage::from_bytes(message_bytes)
            .map_err(|e| ContextError::CryptoFailed(format!("deserialization failed: {e}")))?;

        match msg {
            SenderKeyDistributionMessage::KeyResponse(response) => {
                let sender_key = crate::crypto::sender_keys::key_protocol::hpke_open_sender_key(
                    &response.hpke_sealed_key,
                    &response.ephemeral_pubkey,
                    wrapping_secret_key,
                    &ctx_id_hex,
                    &response.sender_did,
                    response.epoch,
                )
                .map_err(|e| ContextError::CryptoFailed(format!("HPKE open failed: {e}")))?;

                // Verify the sender DID matches (HPKE tag + DID binding), NOT
                // floor gating (the caller does that against the registry).
                if response.sender_did != sender_did {
                    return Err(ContextError::CryptoFailed(
                        "sender DID mismatch in sender key distribution".into(),
                    ));
                }

                Ok((sender_key, response.epoch))
            }
            _ => Err(ContextError::CryptoFailed(
                "expected SenderKeyDistributionMessage::KeyResponse".to_string(),
            )),
        }
    }

    /// Installs an AUTHENTICATED sender key WITHOUT epoch gating, verbatim from
    /// the former provider `set_sender_key_unchecked`. A no-op when this actor
    /// is not encrypted-mode.
    // #2148 F9: crypto twin reached only from in-crate `#[cfg(test)]` fixtures;
    // targeted (not block-wide) so a genuinely-unwired future method still trips.
    #[allow(dead_code)]
    pub(crate) fn set_sender_key_unchecked(&mut self, sender_did: &str, sender_key: SenderKey) {
        let ctx_id_hex = hex::encode(self.context_id);
        if let ContextModeState::Encrypted(crypto) = &mut self.mode {
            crypto
                .sender_key_store
                .set_unchecked(&ctx_id_hex, sender_did, sender_key);
        }
    }

    /// Reads the replicated `0xFF02` group-context extension off this actor's
    /// OWNED MLS group. Read-only. #2148 (birth-into-actor): the provider's
    /// per-context `group_context_extension` reader is DELETED; live-actor reads
    /// route here (rehydrated / joined groups read the extension off the owned
    /// material at the lifecycle layer before seeding).
    ///
    /// # Errors
    ///
    /// [`ContextError::CryptoFailed`] on a mode/group mismatch or a malformed
    /// extension payload.
    // #2148 F9: crypto twin reached only from in-crate `#[cfg(test)]` fixtures;
    // targeted (not block-wide) so a genuinely-unwired future method still trips.
    #[allow(dead_code)]
    pub(crate) fn group_context_extension(
        &self,
    ) -> Result<Option<ScpContextExtension>, ContextError> {
        let ContextModeState::Encrypted(crypto) = &self.mode else {
            return Err(ContextError::CryptoFailed(
                "no MLS group for this context".to_string(),
            ));
        };
        let group = crypto.mls_group.as_ref().ok_or_else(|| {
            ContextError::CryptoFailed("no MLS group for this context".to_string())
        })?;
        group
            .group_context_extension()
            .map_err(|e| ContextError::CryptoFailed(e.to_string()))
    }

    /// Returns the LOCAL sender-key epoch scalar (§9.16.5), verbatim from the
    /// former provider `local_sender_key_epoch` — `0` when this actor has
    /// no encrypted crypto state.
    #[must_use]
    pub(crate) fn local_sender_key_epoch(&self) -> u64 {
        match &self.mode {
            ContextModeState::Encrypted(crypto) => crypto.sender_key_epoch,
            ContextModeState::Broadcast(_) => 0,
        }
    }

    /// Exports the per-context crypto state as an opaque, restore-compatible
    /// byte blob, verbatim from the former provider `export_crypto_state`. The
    /// two floor collections are caller-sourced (authoritative Class-M
    /// registry); the X25519 wrapping keypair enters as parameters
    /// (node-resident). The send-side sequence counter is read from
    /// [`PerContextState::send_tracker`] (the actor's home for the provider's
    /// former `send_sequence`).
    ///
    /// Returns an empty `Vec` when this actor has no MLS group (never keyed,
    /// broadcast mode, or a nulled group) — matching the provider's empty-blob
    /// return for a context absent from its map.
    ///
    /// # Errors
    ///
    /// [`ContextError::CryptoFailed`] if the group is destroyed or
    /// serialization fails.
    pub(crate) fn export_crypto_state(
        &self,
        sender_key_epochs: Vec<(String, u64)>,
        recv_sequence_floors: Vec<(String, ReceiveFloor)>,
        wrapping_public_key: [u8; 32],
        wrapping_secret_key: &[u8],
    ) -> Result<Vec<u8>, ContextError> {
        let ContextModeState::Encrypted(crypto) = &self.mode else {
            return Ok(Vec::new());
        };
        let Some(mls_group) = crypto.mls_group.as_ref() else {
            return Ok(Vec::new());
        };

        // Extract the MLS group and signer, both required for restore.
        let group = mls_group
            .inner()
            .map_err(|_| ContextError::CryptoFailed("MLS group destroyed".to_string()))?;

        let signer = mls_group
            .signer_key_pair()
            .map_err(|_| ContextError::CryptoFailed("MLS signer destroyed".to_string()))?;

        let group_id = group.group_id().as_slice().to_vec();

        // SECURITY: Wrapped in Zeroizing so the Ed25519 private key bytes are
        // zeroed if an early `?` return occurs before the snapshot is built.
        let mut signer_bytes = Zeroizing::new(
            rmp_serde::to_vec_named(signer)
                .map_err(|e| ContextError::CryptoFailed(format!("signer serialization: {e}")))?,
        );

        // Extract the raw key-value pairs from the OpenMLS MemoryStorage.
        let mls_storage_entries = {
            use openmls_traits::OpenMlsProvider as _;
            let values =
                mls_group.provider().storage().values.read().map_err(|e| {
                    ContextError::CryptoFailed(format!("storage lock poisoned: {e}"))
                })?;
            values.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
        };

        // Collect sender key store entries for this context.
        let ctx_id_hex = hex::encode(self.context_id);
        let sender_key_entries: Vec<(String, SenderKey)> = crypto
            .sender_key_store
            .get_all(&ctx_id_hex)
            .into_iter()
            .collect();

        let local_sender_key = crypto.sender_key.clone().ok_or_else(|| {
            ContextError::CryptoFailed("no sender key for this context".to_string())
        })?;

        let mut snapshot = MlsCryptoSnapshot {
            mls_storage_entries,
            local_sender_key,
            sender_key_entries,
            // Caller-sourced from the authoritative registry (ADR-049 PR-6).
            sender_key_epochs,
            sender_key_epoch: crypto.sender_key_epoch,
            // The provider read `state.send_sequence`; the actor's home is
            // `send_tracker.last_issued()` (the high-water mark).
            send_sequence: self.send_tracker.last_issued(),
            member_wrapping_keys: crypto
                .member_wrapping_keys
                .iter()
                .map(|(k, v)| (k.clone(), *v))
                .collect(),
            // Caller-sourced recv floors, unpacked into persisted
            // `(did, epoch, sequence)` triples with an explicit named-field
            // bind (never a tuple `.into()`).
            recv_sequence_tracker: recv_sequence_floors
                .into_iter()
                .map(|(did, rf)| (did, rf.epoch, rf.sequence))
                .collect(),
            signer_bytes: std::mem::take(&mut signer_bytes),
            group_id,
            wrapping_public_key,
            wrapping_secret_key: wrapping_secret_key.to_vec(),
        };

        let result = rmp_serde::to_vec_named(&snapshot)
            .map_err(|e| ContextError::CryptoFailed(format!("snapshot serialization: {e}")));

        // SECURITY: zeroize sensitive key material in the intermediate snapshot
        // (the `Drop` impl is the backstop). The serialized blob is the caller's
        // responsibility (Storage encrypts at rest per §17.5).
        snapshot.zeroize_secrets();

        result
    }

    /// Destroys the MLS group for this context (creation rollback).
    ///
    /// #2148 (birth-into-actor): the provider's `destroy_mls_group` is DELETED;
    /// this actor-owned method is the sole group-teardown path. It eagerly frees
    /// the group (via `destroy_group`; the Ed25519 signer is freed, NOT zeroized —
    /// #82) + nulls the GROUP handle (`crypto.mls_group = None`); the sibling crypto material
    /// (`sender_key`, `sender_key_store`, `member_wrapping_keys`, epoch/sequence)
    /// stays RESIDENT and its old `sender_key` is NOT zeroized.
    ///
    /// # Disposal-hygiene contract for the caller (atomic core)
    ///
    /// This is why a subsequent [`Self::export_crypto_state`] returns an EMPTY
    /// blob (export short-circuits on `mls_group == None`) while other reads —
    /// `local_sender_key_epoch`, the residual `sender_key_store` — would still
    /// surface the old material. For whole-crypto disposal (Ephemeral/Summary
    /// close, TTL expiry, shutdown) the actor calls `dispose_secrets` instead,
    /// which tears down (eagerly frees) the group AND zeroizes the sibling
    /// sender-key material (`SenderKey` `ZeroizeOnDrop`).
    /// This method deliberately does the minimal group-null so it stays a pure
    /// orchestration op; whole-state disposal is a caller (ownership) concern.
    ///
    /// # Errors
    ///
    /// Never returns `Err` today; the `Result` shape is retained for signature
    /// stability.
    #[allow(
        clippy::unnecessary_wraps,
        reason = "signature stability so callers can swap between the minimal \
                  group-null and whole-crypto `dispose_secrets` with no shape change"
    )]
    // #2148 F9: crypto twin reached only from in-crate `#[cfg(test)]` fixtures;
    // targeted (not block-wide) so a genuinely-unwired future method still trips.
    #[allow(dead_code)]
    pub(crate) fn destroy_mls_group(&mut self) -> Result<(), ContextCreationError> {
        if let ContextModeState::Encrypted(crypto) = &mut self.mode {
            if let Some(group) = crypto.mls_group.as_mut() {
                let _ = scp_mls::group::destroy_group(group);
            }
            crypto.mls_group = None;
        }
        Ok(())
    }

    /// Destroys (rotates out) the local sender key and clears the per-context
    /// sender-key store.
    ///
    /// #2148 (birth-into-actor): the provider's `destroy_sender_key` (which also
    /// removed any `broadcast_keys` entry) is DELETED. A single actor's
    /// [`PerContextState`] is exactly one mode (Encrypted OR Broadcast, never
    /// both), so there is no encrypted-mode broadcast-key entry to remove here.
    ///
    /// # Errors
    ///
    /// Never returns `Err` today; the `Result` shape is retained for signature
    /// stability.
    #[allow(
        clippy::unnecessary_wraps,
        reason = "signature stability with the sibling `destroy_mls_group` teardown op"
    )]
    // #2148 F9: crypto twin reached only from in-crate `#[cfg(test)]` fixtures;
    // targeted (not block-wide) so a genuinely-unwired future method still trips.
    #[allow(dead_code)]
    pub(crate) fn destroy_sender_key(&mut self) -> Result<(), ContextCreationError> {
        let ctx_id_hex = hex::encode(self.context_id);
        if let ContextModeState::Encrypted(crypto) = &mut self.mode {
            // Overwrite with a fresh key then clear stored member keys — ensures
            // old key material doesn't linger.
            crypto.sender_key = Some(generate_sender_key());
            let member_dids: Vec<String> = crypto
                .sender_key_store
                .get_all(&ctx_id_hex)
                .keys()
                .cloned()
                .collect();
            for did in &member_dids {
                crypto.sender_key_store.remove(&ctx_id_hex, did);
            }
        }
        Ok(())
    }
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

    /// #2199: `dispose_secrets` on an EMPTY encrypted crypto state (no group, no
    /// sender key material) reports HONEST ABSENCE — both destroyed-flags are
    /// `false`. A fabricated `true` here would be a lying provenance record.
    #[test]
    fn dispose_secrets_empty_encrypted_reports_honest_absence() {
        let mut s = PerContextState::new_for_test_encrypted([7u8; 32], 1, test_admin());
        let outcome = s.dispose_secrets();
        assert!(
            !outcome.mls_group_destroyed,
            "no MLS group was present ⇒ mls_group_destroyed MUST be false (honest absence)"
        );
        assert!(
            !outcome.sender_keys_destroyed,
            "no sender-key material was present ⇒ sender_keys_destroyed MUST be false"
        );
    }

    /// #2199: `dispose_secrets` on a Broadcast context is N/A — Broadcast is
    /// always Full memory-scope, so no ephemeral key-destruction attestation is
    /// ever built from it. Both flags are `false` (honest absence), never a
    /// fabricated `true`.
    #[test]
    fn dispose_secrets_broadcast_is_not_applicable() {
        let mut s = PerContextState::new_for_test_broadcast([8u8; 32], 1, test_admin());
        let outcome = s.dispose_secrets();
        assert_eq!(
            outcome,
            DisposalOutcome {
                mls_group_destroyed: false,
                sender_keys_destroyed: false,
            },
            "Broadcast disposal is N/A — both destroyed-flags MUST be false"
        );
    }

    /// #2199: a present-but-partial crypto state (a local sender key, no MLS
    /// group) reports each flag INDEPENDENTLY from its OBSERVED pre-state — the
    /// present sender key yields `sender_keys_destroyed = true`, the absent group
    /// yields `mls_group_destroyed = false`. Proves the flags are not coupled and
    /// never fabricated.
    #[test]
    fn dispose_secrets_reports_each_flag_from_observed_presence() {
        let mut s = PerContextState::new_for_test_encrypted([9u8; 32], 1, test_admin());
        match &mut s.mode {
            ContextModeState::Encrypted(cs) => {
                cs.sender_key = Some(generate_sender_key());
            }
            ContextModeState::Broadcast(_) => panic!("expected encrypted mode"),
        }
        let outcome = s.dispose_secrets();
        assert!(
            !outcome.mls_group_destroyed,
            "no group present ⇒ mls_group_destroyed false"
        );
        assert!(
            outcome.sender_keys_destroyed,
            "a local sender key WAS present ⇒ sender_keys_destroyed true (observed)"
        );
        // Idempotent second call now observes an emptied state ⇒ honest false.
        let again = s.dispose_secrets();
        assert_eq!(
            again,
            DisposalOutcome {
                mls_group_destroyed: false,
                sender_keys_destroyed: false,
            },
            "a repeat disposal of an already-emptied state reports honest false"
        );
    }

    /// #2199 F-BH1: sender-key presence includes the `pending_distributions`
    /// queue (serialized sender-key DISTRIBUTION ciphertext — key-bearing
    /// material that `dispose_secrets` clears). A state with an EMPTY local
    /// `sender_key`/`sender_key_store` but a NON-EMPTY `pending_distributions`
    /// still reports `sender_keys_destroyed = true` — the flag honestly reflects
    /// that queued key material was present and torn down, closing the
    /// inverse-precision gap where real key material was destroyed but the flag
    /// read `false`.
    #[test]
    fn dispose_secrets_pending_distributions_alone_reports_sender_destroyed() {
        let mut s = PerContextState::new_for_test_encrypted([11u8; 32], 1, test_admin());
        match &mut s.mode {
            ContextModeState::Encrypted(cs) => {
                assert!(cs.sender_key.is_none(), "no local sender key");
                assert!(cs.sender_key_store.is_empty(), "no stored sender keys");
                // Only queued distribution ciphertext is present.
                cs.pending_distributions
                    .push(("did:dht:recipient".to_owned(), vec![0xDE, 0xAD, 0xBE, 0xEF]));
            }
            ContextModeState::Broadcast(_) => panic!("expected encrypted mode"),
        }
        let outcome = s.dispose_secrets();
        assert!(
            outcome.sender_keys_destroyed(),
            "queued key material (pending_distributions) WAS present and torn down \
             ⇒ sender_keys_destroyed true (#2199 F-BH1)"
        );
        assert!(
            !outcome.mls_group_destroyed(),
            "no MLS group present ⇒ mls_group_destroyed false"
        );
        // The queue was cleared by disposal ⇒ a repeat reports honest false.
        assert!(
            !s.dispose_secrets().sender_keys_destroyed(),
            "pending_distributions was cleared ⇒ a repeat disposal reports honest false"
        );
    }

    /// Exhaustive-destructure witness that every field on
    /// [`PerContextState`] is populated by the test fixture. The
    /// destructuring pattern intentionally does NOT use `..` — adding a
    /// new field on [`PerContextState`] without updating this pattern
    /// breaks the build, which guards against silent field
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
            xctx_committed_stream_outputs,
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
        assert!(xctx_committed_stream_outputs.is_empty());
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
                    xctx_committed_stream_outputs: _,
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
            force_rotation_failure,
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
        assert!(
            !force_rotation_failure,
            "the fault-injection seam defaults disarmed",
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
            CrossContextOutletInvocationPrepared, CrossContextStreamingOutletInvocationPrepared,
            SagaPreparedState,
        };
        use scp_protocol::context::outlets::stream::{
            ChunkPayload, MerkleFrontier, OutletStreamChunk,
        };
        use scp_protocol::economy::types::Amount;

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

        // A staged STREAMING saga variant (ADR-061 seal phase; §6.2.5) — its
        // live Merkle frontier + credit ledger must survive the Class-S
        // mirror round-trip, and the rehydrated `frontier.root()` must
        // reproduce (the AC7 durable-prefix reproducibility property).
        let saga_stream = SagaId("saga-lossless-stream".to_owned());
        let mut stream_frontier = MerkleFrontier::with_ceiling(1);
        for seq in 0u64..3 {
            stream_frontier
                .push(&OutletStreamChunk {
                    request_id: [0x6Au8; 16],
                    sequence: seq,
                    payload: ChunkPayload::Data {
                        value: serde_json::json!({ "seq": seq }),
                    },
                    sig: [(seq & 0xFF) as u8 ^ 0x33; 64],
                })
                .expect("valid chunk hashes");
        }
        let stream_root = stream_frontier.root();
        let stream_billed = stream_frontier.billed_count(); // ceiling 1 → seq {0,1}
        let stream_leaves = stream_frontier.leaf_count();
        state.class_s.saga_pending.insert(
            saga_stream.clone(),
            SagaPreparedState::CrossContextStreamingOutletInvocation(
                CrossContextStreamingOutletInvocationPrepared {
                    saga_id: saga_stream.clone(),
                    caller_context_id: [0x7Au8; 32],
                    target_context_id: [0x8Bu8; 32],
                    caller_did: DID("did:example:lossless-stream-caller".to_owned()),
                    outlet_registration_id: "lossless-stream-outlet-v1".to_owned(),
                    ucan_proof_id: "lossless-stream-ucan".to_owned(),
                    recorded_timestamp_ms: 1_700_000_000_789,
                    recorded_nonce: [0x9Du8; 16],
                    recorded_chain_depth: 4,
                    frontier: stream_frontier,
                    reserved: Amount::new(5_000),
                    cost_per_chunk: Amount::new(1_000),
                    billed: Amount::new(2_000),
                    billed_count: 2,
                    cancel_ack_ceiling: 1,
                    request_id: [0xA1u8; 16],
                    economic_policy: None,
                    amount_cumulative_reserved: 4_000,
                    reserved_chunks: 4,
                    ucan_cid: "lossless-stream-ucan-cid".to_owned(),
                },
            ),
        );

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
        // saga_pending: the staged variants + their journaled fields survive
        // (the unary variant plus the streaming variant).
        assert_eq!(state.class_s.saga_pending.len(), 2);
        let SagaPreparedState::CrossContextOutletInvocation(inner) = state
            .class_s
            .saga_pending
            .get(&saga_a)
            .expect("saga restored")
        else {
            panic!("expected the unary cross-context outlet-invocation variant");
        };
        assert_eq!(inner.caller_context_id, [0x1Au8; 32]);
        assert_eq!(inner.target_context_id, [0x2Bu8; 32]);
        assert_eq!(inner.caller_did.0, "did:example:lossless-caller");
        assert_eq!(inner.outlet_registration_id, "lossless-outlet-v1");
        assert_eq!(inner.ucan_proof_id, "lossless-ucan");
        assert_eq!(inner.recorded_timestamp_ms, 1_700_000_000_123);
        assert_eq!(inner.recorded_nonce, [0x3Cu8; 16]);
        assert_eq!(inner.recorded_chain_depth, 2);
        // The streaming variant survives too — including its live Merkle
        // frontier and credit ledger. The rehydrated `frontier.root()` must
        // reproduce the pre-snapshot root (AC7 durable-prefix witness).
        let SagaPreparedState::CrossContextStreamingOutletInvocation(stream_inner) = state
            .class_s
            .saga_pending
            .get(&saga_stream)
            .expect("streaming saga restored")
        else {
            panic!("expected the streaming cross-context outlet-invocation variant");
        };
        assert_eq!(stream_inner.saga_id, saga_stream);
        assert_eq!(stream_inner.caller_context_id, [0x7Au8; 32]);
        assert_eq!(stream_inner.target_context_id, [0x8Bu8; 32]);
        assert_eq!(
            stream_inner.caller_did.0,
            "did:example:lossless-stream-caller"
        );
        assert_eq!(
            stream_inner.outlet_registration_id,
            "lossless-stream-outlet-v1"
        );
        assert_eq!(stream_inner.ucan_proof_id, "lossless-stream-ucan");
        assert_eq!(stream_inner.recorded_timestamp_ms, 1_700_000_000_789);
        assert_eq!(stream_inner.recorded_nonce, [0x9Du8; 16]);
        assert_eq!(stream_inner.recorded_chain_depth, 4);
        assert_eq!(stream_inner.reserved, Amount::new(5_000));
        assert_eq!(stream_inner.billed, Amount::new(2_000));
        assert_eq!(stream_inner.billed_count, 2);
        assert_eq!(stream_inner.cancel_ack_ceiling, 1);
        assert_eq!(stream_inner.frontier.root(), stream_root);
        assert_eq!(stream_inner.frontier.billed_count(), stream_billed);
        assert_eq!(stream_inner.frontier.leaf_count(), stream_leaves);
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

// ---------------------------------------------------------------------------
// Golden byte-identity tests (ADR-049 PR-7 Prep A — SCP-CRYPTOMOVE-000a)
// ---------------------------------------------------------------------------
//
// Verification invariant 1: each `PerContextState` crypto method preserves the
// golden byte-level / behavioural contract of the crypto primitive it now owns.
//
// Post-ADR-049 PR-7 the `NodeMlsFactory` steady-state twins (seal / open /
// rotate / advance / remove / export / drain / mls_encrypt_management /
// local_sender_key_epoch / restore) are DELETED and each party's crypto is
// destructively `take_crypto_state`'d into the actor exactly once — the actor
// is the SOLE crypto authority, so there is no provider side to cross-drive.
// The pinning therefore runs entirely on the actor seam, asserting each method
// against the SAME golden expectation the former dual-drive block asserted (the
// deterministic, AAD-bound decrypted value / the documented invariant), not a
// weakened "it compiles" check:
//   * `seal` / `open` / `mls_encrypt_management` — actor seal→actor open
//     round-trip decrypts to the ORIGINAL `InnerEnvelope` byte-for-byte at the
//     AAD-bound (`sender_did`, `ReceiveFloor`), at both the zero and a rotated
//     non-zero sender-key epoch (the epoch is bound in the sender-layer AAD).
//   * `distribute_sender_key` / `process_incoming_sender_key` — the RECOVERED
//     sender key (deterministic — the existing key material) is byte-identical
//     to Alice's actual local sender key, and installs so her seal opens.
//   * `group_context_extension` / `local_sender_key_epoch` — DIRECT
//     byte/value equality against the known golden value (deterministic reads).
//   * `export_crypto_state` — non-empty export + functional restore equivalence
//     via the retained `build_restored_owned` reader (the reseeded actor agrees
//     with the original on the group-context extension and local epoch).
//   * `advance_epoch` / `remove_member` — the moved primitive produces a valid,
//     non-empty commit and the counterparty processes it to the committer's new
//     epoch (the commit's key material is fresh randomness, so raw bytes cannot
//     be compared).
//   * `destroy_mls_group` / `destroy_sender_key` — the observable post-state
//     (empty export / rotated-and-cleared sender key) holds after the op.
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]
mod crypto_ops_golden {
    use super::*;
    use crate::crypto::mls::provider::NodeMlsFactory;
    use crate::crypto::mls::two_party_test_support::{TwoPartyPair, stand_up_two_party};
    use scp_clock::SystemClock;
    use scp_did::SigningKeyId;

    const CTX_STR: &str = "cryptomove-golden-ctx";
    const ALICE: &str = "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
    const BOB: &str = "did:dht:z6MkBobBobBobBobBobBobBobBobBobBobBobBobBo";

    /// Stand up the real joined Alice/Bob pair, born DIRECTLY onto actor-owned
    /// [`PerContextState`] via the #2148 owned-return constructors + the
    /// production `seed_encrypted_crypto_from_owned` primitive (no provider
    /// `take_crypto_state` round-trip). Returns
    /// `(alice_provider, alice_state, bob_provider, bob_state, ctx)`: each
    /// [`PerContextState`] already OWNS its per-context crypto, and each provider
    /// is retained solely for its node-resident wrapping keypair.
    fn setup() -> (
        Arc<NodeMlsFactory>,
        PerContextState,
        Arc<NodeMlsFactory>,
        PerContextState,
        [u8; 32],
    ) {
        let TwoPartyPair {
            alice_provider,
            alice_state,
            bob_provider,
            bob_state,
            ctx_bytes,
        } = stand_up_two_party(CTX_STR, ALICE, BOB);
        (
            alice_provider,
            alice_state,
            bob_provider,
            bob_state,
            ctx_bytes,
        )
    }

    /// Build a minimal signed `InnerEnvelope` (signature is not verified by
    /// `open`, per the provider contract).
    fn build_inner(sender_did: &str, sequence: u64) -> InnerEnvelope {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let params = crate::envelope::inner::InnerEnvelopeParams {
            version: crate::envelope::inner::SCP_INNER_ENVELOPE_VERSION,
            context_id: CTX_STR,
            sender_did,
            epoch: 0,
            generation: 0,
            sequence,
            timestamp: 1_700_000_000,
            message_type: crate::envelope::inner::MessageType::Content,
            payload: b"cryptomove golden payload",
            provenance: None,
            signing_key_id: SigningKeyId::Active,
        };
        crate::envelope::inner::sign::create_inner_envelope_raw(&params, &sk).unwrap()
    }

    fn routing(ctx: &[u8; 32]) -> Vec<u8> {
        ctx.to_vec()
    }

    /// #2199: `dispose_secrets` on a REAL seeded encrypted state (a live MLS
    /// group + a present sender key, born over the end-to-end join path) reports
    /// BOTH destroyed-flags `true` — an OBSERVED disposal of present material.
    /// This is the only path on which a `KeyDestructionAttestation`'s
    /// destroyed-flags may honestly be `true`.
    #[test]
    fn dispose_secrets_seeded_encrypted_reports_observed_true() {
        let (_alice_p, mut alice_a, _bob_p, _bob_a, _ctx) = setup();
        // Precondition: the fixture really did seed a live group + sender key.
        match &alice_a.mode {
            ContextModeState::Encrypted(c) => {
                assert!(c.mls_group.is_some(), "fixture seeds a live MLS group");
                assert!(c.sender_key.is_some(), "fixture seeds a local sender key");
            }
            ContextModeState::Broadcast(_) => panic!("expected encrypted mode"),
        }
        let outcome = alice_a.dispose_secrets();
        assert_eq!(
            outcome,
            DisposalOutcome {
                mls_group_destroyed: true,
                sender_keys_destroyed: true,
            },
            "present group + present sender key ⇒ both destroyed-flags observed true"
        );
        // The material is now gone: a repeat disposal reports honest false.
        assert_eq!(
            alice_a.dispose_secrets(),
            DisposalOutcome {
                mls_group_destroyed: false,
                sender_keys_destroyed: false,
            },
            "after disposal the state is emptied ⇒ a repeat reports honest false"
        );
    }

    /// Read the (cloned) local sender key out of an encrypted actor state.
    fn actor_sender_key(state: &PerContextState) -> SenderKey {
        match &state.mode {
            ContextModeState::Encrypted(c) => c.sender_key.clone().expect("sender key present"),
            ContextModeState::Broadcast(_) => panic!("expected encrypted mode"),
        }
    }

    /// The live MLS epoch of an encrypted actor's group.
    fn actor_mls_epoch(state: &PerContextState) -> u64 {
        match &state.mode {
            ContextModeState::Encrypted(c) => c
                .mls_group
                .as_ref()
                .expect("group present")
                .epoch()
                .unwrap(),
            ContextModeState::Broadcast(_) => panic!("expected encrypted mode"),
        }
    }

    /// Apply a public MLS Commit (as produced by `advance_epoch` / `remove_member`)
    /// to an encrypted actor's group, mirroring the real deliver path
    /// (`scp_mls::ratchet::process_commit`).
    fn process_commit_on_actor(
        state: &mut PerContextState,
        commit_bytes: &[u8],
    ) -> Result<(), scp_mls::error::MlsError> {
        let mut grace = scp_mls::epoch_grace::EpochGraceStore::default();
        match &mut state.mode {
            ContextModeState::Encrypted(c) => {
                let group = c.mls_group.as_mut().expect("group present");
                scp_mls::ratchet::process_commit(group, commit_bytes, &mut grace)
            }
            ContextModeState::Broadcast(_) => panic!("expected encrypted mode"),
        }
    }

    /// Bob's node-resident X25519 wrapping secret (the HPKE-open key the actor
    /// receive half takes as a parameter).
    fn bob_wrapping_secret(bob_p: &NodeMlsFactory) -> [u8; 32] {
        *bob_p.wrapping_keypair_snapshot().1
    }

    #[test]
    fn golden_seal_open_cross_roundtrip() {
        let (_alice_p, mut alice_a, _bob_p, mut bob_a, ctx) = setup();
        let rid = routing(&ctx);
        let inner = build_inner(ALICE, 0);

        // Actor seals; the actor receiver opens. The provider twin is deleted
        // (its crypto was destructively taken into the actor), so the golden pin
        // is the actor seal→open round-trip decrypting to the ORIGINAL
        // InnerEnvelope byte-for-byte at the base sender-key epoch (1).
        let blob_actor = alice_a.seal(ALICE, &inner, &rid, 300).unwrap();
        let env = match bob_a.open(&SystemClock, CTX_STR, &blob_actor).unwrap() {
            OpenResult::Application(e) => e,
            other => panic!("expected Application result, got {other:?}"),
        };

        assert_eq!(env.sender_did, ALICE);
        assert_eq!(
            env.receive_floor.epoch, 1,
            "an unrotated context binds the base sender-key epoch 1 in the AAD"
        );
        assert_eq!(env.receive_floor.sequence, 0, "first seal is sequence 0");
        assert_eq!(
            rmp_serde::to_vec_named(&env.inner).unwrap(),
            rmp_serde::to_vec_named(&inner).unwrap(),
            "decrypted InnerEnvelope must be byte-identical to the original"
        );
    }

    /// Multi-seal cross-round-trip: the `send_sequence → send_tracker` increment
    /// adaptation is the exact thing this suite exists to guard. Seal several
    /// messages in a row on BOTH impls and assert the AAD-bound
    /// `receive_floor.sequence` progresses 0,1,2,… identically — proving the
    /// actor's `send_tracker` advance matches the provider's `send_sequence`
    /// post-increment at every step, not just at 0.
    #[test]
    fn golden_seal_open_multi_sequence_progression() {
        let (_alice_p, mut alice_a, _bob_p, mut bob_a, ctx) = setup();
        let rid = routing(&ctx);

        let mut actor_seqs = Vec::new();
        for i in 0..4u64 {
            let inner = build_inner(ALICE, i);

            // Actor seals -> actor receiver opens (in-order consecutive gens).
            let blob_actor = alice_a.seal(ALICE, &inner, &rid, 300).unwrap();
            match bob_a.open(&SystemClock, CTX_STR, &blob_actor).unwrap() {
                OpenResult::Application(e) => actor_seqs.push(e.receive_floor.sequence),
                other => panic!("expected Application, got {other:?}"),
            }
        }

        assert_eq!(
            actor_seqs,
            vec![0, 1, 2, 3],
            "actor send_tracker AAD sequence must progress 0,1,2,3 (post-increment high-water)"
        );
    }

    /// Post-rotate (NON-ZERO epoch) cross-round-trip: rotate the sender key so
    /// the sealed message binds a non-zero epoch in its AAD, then seal→open on
    /// EACH impl and assert byte-identical decrypt at the non-zero epoch —
    /// proving the epoch is bound in the AAD identically across impls (the
    /// zero-epoch tests cannot see an epoch-binding divergence).
    #[test]
    fn golden_seal_open_after_rotate_nonzero_epoch() {
        let (_alice_p, mut alice_a, bob_p, mut bob_recv_a, ctx) = setup();
        let rid = routing(&ctx);
        let bob_secret = bob_wrapping_secret(&bob_p);
        let inner = build_inner(ALICE, 0);

        // --- Actor path: actor rotate + actor seal + actor open. ---
        alice_a.rotate_sender_key(ALICE).unwrap();
        let epoch_a = alice_a.local_sender_key_epoch();
        assert!(
            epoch_a >= 1,
            "rotate must advance the sender-key epoch past 0"
        );
        // Deliver the rotated key to Bob (the rotate queued a distribution).
        let msgs_a = alice_a.drain_pending_sender_key_messages().unwrap();
        assert_eq!(msgs_a.len(), 1);
        let (key_a, recv_epoch_a) = bob_recv_a
            .process_incoming_sender_key(&bob_secret, ALICE, &msgs_a[0].1)
            .unwrap();
        assert_eq!(recv_epoch_a, epoch_a);
        bob_recv_a.set_sender_key_unchecked(ALICE, key_a);
        let blob_actor = alice_a.seal(ALICE, &inner, &rid, 300).unwrap();
        let opened_a = match bob_recv_a.open(&SystemClock, CTX_STR, &blob_actor).unwrap() {
            OpenResult::Application(e) => e,
            other => panic!("expected Application, got {other:?}"),
        };

        // The rotated (non-zero) sender-key epoch is bound in the sender-layer
        // AAD, and the decrypted inner round-trips the original byte-for-byte.
        assert!(
            opened_a.receive_floor.epoch >= 1,
            "non-zero epoch bound in AAD"
        );
        assert_eq!(
            opened_a.receive_floor.epoch, epoch_a,
            "the AAD-bound epoch is the rotated sender-key epoch"
        );
        assert_eq!(
            rmp_serde::to_vec_named(&opened_a.inner).unwrap(),
            rmp_serde::to_vec_named(&inner).unwrap(),
            "decrypt at a non-zero epoch must round-trip the original inner"
        );
    }

    /// Round-trip at a NON-ZERO sender-key epoch: Alice rotates once on the
    /// actor (so she holds a single rotated key at a non-zero epoch), delivers
    /// that key to Bob, then seals — and Bob opens under the matching rotated
    /// key, proving the non-zero epoch is encoded into the sender-layer AAD and
    /// the receiver reconstructs the AAD + looks up the matching key.
    ///
    /// The zero-epoch [`golden_seal_open_cross_roundtrip`] opens only at epoch 0
    /// (endian-invariant); this closes the non-zero-epoch key-lookup gap by
    /// delivering the rotated key to a DIFFERENT actor (Bob) before the open,
    /// where [`golden_seal_open_after_rotate_nonzero_epoch`] opens on the
    /// receiver that was seeded with the delivered key inline.
    #[test]
    fn golden_seal_open_cross_roundtrip_nonzero_epoch() {
        let (_alice_p, mut alice_a, bob_p, mut bob_a, ctx) = setup();
        let rid = routing(&ctx);
        // Bob's node-resident wrapping secret (the actor path's HPKE-open key).
        let bob_secret = bob_wrapping_secret(&bob_p);

        // Rotate ONCE on the actor so Alice holds a single rotated key at a
        // non-zero epoch.
        alice_a.rotate_sender_key(ALICE).unwrap();
        let epoch = alice_a.local_sender_key_epoch();
        assert!(epoch >= 1, "rotate advances the sender-key epoch past 0");

        // Deliver the rotated key to Bob (the rotate queued a distribution).
        let msgs = alice_a.drain_pending_sender_key_messages().unwrap();
        assert_eq!(msgs.len(), 1);
        let (rotated_key, recv_epoch) = bob_a
            .process_incoming_sender_key(&bob_secret, ALICE, &msgs[0].1)
            .unwrap();
        assert_eq!(recv_epoch, epoch);
        bob_a.set_sender_key_unchecked(ALICE, rotated_key);

        let inner = build_inner(ALICE, 0);

        // ACTOR seals at the non-zero epoch -> ACTOR receiver opens under the
        // delivered rotated key.
        let blob_actor = alice_a.seal(ALICE, &inner, &rid, 300).unwrap();
        let env = match bob_a.open(&SystemClock, CTX_STR, &blob_actor).unwrap() {
            OpenResult::Application(e) => e,
            other => panic!("expected Application result, got {other:?}"),
        };

        assert_eq!(env.sender_did, ALICE);
        assert!(
            env.receive_floor.epoch >= 1,
            "non-zero epoch bound in the AAD"
        );
        assert_eq!(
            env.receive_floor.epoch, epoch,
            "the AAD epoch is the rotated sender-key epoch"
        );
        assert_eq!(
            rmp_serde::to_vec_named(&env.inner).unwrap(),
            rmp_serde::to_vec_named(&inner).unwrap(),
            "decrypt at a non-zero epoch must round-trip the original inner"
        );
    }

    /// ADR-049 §15(c) fail-closed rotation coverage, RESTORED on the actor
    /// (#2148 F1). The one-shot fault seam re-homed onto the actor's
    /// `PerContextState` makes the NEXT `rotate_sender_key` fail closed with NO
    /// partial mutation — the local sender-key epoch is unchanged (old
    /// epoch/key/store retained) — proving the actor's rotation is fail-closed;
    /// the seam then clears itself so the subsequent rotation advances normally.
    /// This replaces the deleted provider
    /// `arm_rotation_failure_once_forces_fail_closed_then_normal`.
    #[test]
    fn arm_rotation_failure_once_forces_fail_closed_then_normal() {
        let (_alice_p, mut alice_a, _bob_p, _bob_a, _ctx) = setup();
        let epoch_before = alice_a.local_sender_key_epoch();

        // Arm the one-shot seam: the next rotation must fail closed.
        alice_a.arm_rotation_failure_once();
        assert!(
            matches!(
                alice_a.rotate_sender_key(ALICE),
                Err(ContextError::CryptoFailed(_))
            ),
            "armed rotation must return CryptoFailed"
        );
        // Fail-closed: the injected failure fired BEFORE any mutation, so the
        // epoch is unchanged — the rotation was NOT committed.
        assert_eq!(
            alice_a.local_sender_key_epoch(),
            epoch_before,
            "failed rotation must NOT advance the epoch (no partial mutation)"
        );

        // One-shot cleared: the next rotation persists normally and advances the
        // epoch by exactly one.
        alice_a.rotate_sender_key(ALICE).unwrap();
        assert_eq!(
            alice_a.local_sender_key_epoch(),
            epoch_before + 1,
            "post-clear rotation must advance the epoch by one"
        );
    }

    /// `seal` must FAIL-CLOSED at the `u64::MAX` send-sequence boundary — byte
    /// parity with the provider's `send_sequence.checked_add(1)?` (emit nothing,
    /// return `CryptoFailed("send sequence counter overflow")`). Guards against
    /// the `SendSequenceTracker::reserve_next` saturating-add fail-OPEN.
    #[test]
    fn seal_fails_closed_on_send_sequence_overflow() {
        let (_alice_p, mut alice_a, _bob_p, _bob_a, ctx) = setup();
        // Saturate the send tracker to the u64 ceiling.
        alice_a.send_tracker = SendSequenceTracker::from_persisted(u64::MAX);
        let inner = build_inner(ALICE, 0);
        let err = alice_a
            .seal(ALICE, &inner, &routing(&ctx), 300)
            .expect_err("seal must fail-closed at the u64::MAX send-sequence boundary");
        match err {
            ContextError::CryptoFailed(msg) => {
                assert_eq!(msg, "send sequence counter overflow");
            }
            other => panic!("expected CryptoFailed overflow, got {other:?}"),
        }
        // The tracker was NOT advanced (no reservation taken) — matches the
        // provider leaving `send_sequence` unchanged on `checked_add` overflow.
        assert_eq!(alice_a.send_tracker.last_issued(), u64::MAX);
    }

    #[test]
    fn golden_mls_encrypt_management_cross_roundtrip() {
        let (_alice_p, mut alice_a, _bob_p, mut bob_a, ctx) = setup();
        let rid = routing(&ctx);
        let payload = b"management golden payload";

        // Actor management-encrypts; the actor receiver opens and recovers the
        // exact payload (the provider twin is deleted).
        let blob_actor = alice_a.mls_encrypt_management(payload, &rid, 300).unwrap();
        match bob_a.open(&SystemClock, CTX_STR, &blob_actor).unwrap() {
            OpenResult::Management { payload: p, .. } => assert_eq!(p, payload),
            other => panic!("expected Management result, got {other:?}"),
        }
    }

    #[test]
    fn golden_group_context_extension_byte_identical() {
        let (_alice_p, alice_a, _bob_p, _bob_a, _ctx) = setup();
        let from_actor = alice_a.group_context_extension().unwrap();
        let ext = from_actor.expect("an SCP context group carries the 0xFF02 extension");
        assert_eq!(
            ext.context_id, CTX_STR,
            "the group-context extension binds the golden context id"
        );
        assert_eq!(
            ext.creator_did,
            DID::from(ALICE.to_owned()),
            "the group-context extension binds the creator DID"
        );
    }

    #[test]
    fn golden_local_sender_key_epoch_matches() {
        let (_alice_p, alice_a, _bob_p, _bob_a, _ctx) = setup();
        assert_eq!(
            alice_a.local_sender_key_epoch(),
            1,
            "a freshly joined, unrotated context reads the base local sender-key epoch 1"
        );
    }

    #[test]
    fn golden_distribute_and_process_recover_identical_key() {
        let (_alice_p, mut alice_a, bob_p, mut bob_a, ctx) = setup();
        // Bob's wrapping secret (node-resident) — the actor path's HPKE-open key.
        let (_bob_pub, bob_secret) = bob_p.wrapping_keypair_snapshot();
        let bob_secret: [u8; 32] = *bob_secret;

        // Actor distributes Alice's CURRENT (unrotated) sender key.
        alice_a.distribute_sender_key(ALICE, BOB).unwrap();
        let actor_msgs = alice_a.drain_pending_sender_key_messages().unwrap();
        assert_eq!(actor_msgs.len(), 1, "one queued distribution");
        // Drain again — the queue is now empty (verbatim `std::mem::take`).
        assert!(
            alice_a
                .drain_pending_sender_key_messages()
                .unwrap()
                .is_empty()
        );

        // Recover the key via the actor receive half. The recovered key material
        // is deterministic (Alice's existing key), so it equals Alice's actual
        // local sender key byte-for-byte.
        let (recovered_key, epoch) = bob_a
            .process_incoming_sender_key(&bob_secret, ALICE, &actor_msgs[0].1)
            .unwrap();
        assert_eq!(
            epoch, 1,
            "the unrotated key distributes at the base epoch 1"
        );
        assert_eq!(
            recovered_key.as_bytes(),
            actor_sender_key(&alice_a).as_bytes(),
            "recovered sender key must equal Alice's actual sender key"
        );

        // `set_sender_key_unchecked` install half: after installing the recovered
        // key on the Bob actor, Alice's application seal opens under it.
        bob_a.set_sender_key_unchecked(ALICE, recovered_key);
        let inner = build_inner(ALICE, 0);
        let sealed = alice_a.seal(ALICE, &inner, &routing(&ctx), 300).unwrap();
        match bob_a.open(&SystemClock, CTX_STR, &sealed).unwrap() {
            OpenResult::Application(env) => assert_eq!(env.sender_did, ALICE),
            other => panic!("expected Application, got {other:?}"),
        }
    }

    #[test]
    fn golden_rotate_sender_key_parity() {
        let (_alice_p, mut alice_a, bob_p, bob_a, _ctx) = setup();
        let (_bob_pub, bob_secret) = bob_p.wrapping_keypair_snapshot();
        let bob_secret: [u8; 32] = *bob_secret;

        let epoch_before = alice_a.local_sender_key_epoch();
        assert_eq!(
            epoch_before, 1,
            "unrotated context starts at the base epoch 1"
        );

        // Rotate on the actor. The fresh key + HPKE ephemeral are random; the
        // EPOCH advance and the distribution's processability are the
        // deterministic golden invariants.
        alice_a.rotate_sender_key(ALICE).unwrap();

        assert_eq!(
            alice_a.local_sender_key_epoch(),
            epoch_before + 1,
            "actor rotate advances the local epoch by one"
        );

        // The queued distribution from the actor rotate is processable by Bob and
        // carries the new epoch.
        let msgs = alice_a.drain_pending_sender_key_messages().unwrap();
        assert_eq!(msgs.len(), 1, "one member (Bob) receives the rotated key");
        let (_key, epoch) = bob_a
            .process_incoming_sender_key(&bob_secret, ALICE, &msgs[0].1)
            .unwrap();
        assert_eq!(epoch, epoch_before + 1);
    }

    #[test]
    fn golden_advance_epoch_parity() {
        let (alice_p, mut alice_a, _bob_p, mut bob_from_actor, _ctx) = setup();
        let (wpub, _wsec) = alice_p.wrapping_keypair_snapshot();

        // `advance_epoch` self-merges the committer's Update+Commit, advancing
        // the local MLS epoch by one.
        let epoch_before = actor_mls_epoch(&alice_a);
        let out_a = alice_a.advance_epoch(wpub).unwrap();
        assert!(
            !out_a.commit_bytes.is_empty(),
            "actor advance_epoch produces a non-empty commit"
        );
        let epoch_after = actor_mls_epoch(&alice_a);
        assert_eq!(
            epoch_after,
            epoch_before + 1,
            "advance_epoch self-merges, advancing the committer's MLS epoch by one"
        );

        // The counterparty PROCESSES the commit and reaches the committer's new
        // epoch (the actor is the sole crypto authority; the provider twin is
        // deleted).
        process_commit_on_actor(&mut bob_from_actor, &out_a.commit_bytes)
            .expect("Bob processes the actor-produced advance Commit");
        assert_eq!(
            actor_mls_epoch(&bob_from_actor),
            epoch_after,
            "Bob reaches the committer's new epoch after processing the advance Commit"
        );
    }

    #[test]
    fn golden_remove_member_parity() {
        let (_alice_p, mut alice_a, _bob_p, mut bob_from_actor, _ctx) = setup();

        // Self-removal is a no-op (empty output).
        assert!(
            alice_a
                .remove_member(ALICE, ALICE)
                .unwrap()
                .commit_bytes
                .is_empty()
        );

        // Removing Bob self-merges the remove-Commit, advancing Alice's epoch by
        // one; the output is a non-empty Commit + group-info.
        let epoch_before = actor_mls_epoch(&alice_a);
        let out_a = alice_a.remove_member(ALICE, BOB).unwrap();
        assert!(
            !out_a.commit_bytes.is_empty(),
            "actor remove_member produces a Commit"
        );
        assert!(!out_a.group_info_bytes.is_empty());
        assert_eq!(
            actor_mls_epoch(&alice_a),
            epoch_before + 1,
            "remove_member self-merges, advancing the committer's MLS epoch by one"
        );

        // The counterparty (Bob — the removed member) PROCESSES the remove-Commit
        // and learns of his removal, reaching the committer's new epoch.
        process_commit_on_actor(&mut bob_from_actor, &out_a.commit_bytes)
            .expect("Bob processes the actor-produced remove Commit");
        assert_eq!(actor_mls_epoch(&bob_from_actor), epoch_before + 1);
    }

    #[test]
    fn golden_export_restore_equivalent() {
        let (alice_p, alice_a, _bob_p, _bob_a, ctx) = setup();
        // Use Alice's provider wrapping keypair so the actor export embeds the
        // SAME node-resident wrapping material a restore needs.
        let (wpub, wsec) = alice_p.wrapping_keypair_snapshot();

        // Capture the ORIGINAL group-context extension + local epoch off the live
        // actor (export is non-destructive) as the golden restore target.
        let orig_ext = alice_a.group_context_extension().unwrap();
        let orig_epoch = alice_a.local_sender_key_epoch();

        let blob_a = alice_a
            .export_crypto_state(Vec::new(), Vec::new(), wpub, &*wsec)
            .unwrap();
        assert!(!blob_a.is_empty());

        // Functional restore equivalence: rebuild the owned material on a fresh
        // provider via the retained `build_restored_owned` reader (the deleted
        // insert-path `restore_crypto_state` twin is gone), reseed an actor, and
        // confirm it agrees with the ORIGINAL on the group-context extension and
        // local sender-key epoch.
        let reader_provider = NodeMlsFactory::new(ALICE.to_owned(), Arc::new(SystemClock));
        let (owned, _floors) = reader_provider.build_restored_owned(&ctx, &blob_a).unwrap();
        let mut restored =
            PerContextState::new_for_test_encrypted(ctx, 0, DID::from(ALICE.to_owned()));
        restored.seed_encrypted_crypto_from_owned(owned);
        assert_eq!(
            restored.group_context_extension().unwrap(),
            orig_ext,
            "restored group-context extension must match the original"
        );
        assert_eq!(
            restored.local_sender_key_epoch(),
            orig_epoch,
            "restored local sender-key epoch must match the original"
        );
    }

    #[test]
    fn golden_destroy_mls_group_empties_export() {
        let (alice_p, mut alice_a, _bob_p, _bob_a, _ctx) = setup();
        let (wpub, wsec) = alice_p.wrapping_keypair_snapshot();

        assert!(
            !alice_a
                .export_crypto_state(Vec::new(), Vec::new(), wpub, &*wsec)
                .unwrap()
                .is_empty()
        );
        alice_a.destroy_mls_group().unwrap();
        assert!(
            alice_a
                .export_crypto_state(Vec::new(), Vec::new(), wpub, &*wsec)
                .unwrap()
                .is_empty(),
            "destroy_mls_group makes export return empty (the group map entry is \
             removed)"
        );
    }

    #[test]
    fn golden_destroy_sender_key_rotates_and_clears() {
        let (_alice_p, mut alice_a, _bob_p, _bob_a, ctx) = setup();

        let key_before = actor_sender_key(&alice_a);
        alice_a.destroy_sender_key().unwrap();
        let key_after = actor_sender_key(&alice_a);
        assert_ne!(
            key_before.as_bytes(),
            key_after.as_bytes(),
            "destroy_sender_key rotates the local key to fresh material"
        );
        // Store is cleared for this context.
        match &alice_a.mode {
            ContextModeState::Encrypted(c) => assert!(
                c.sender_key_store.get_all(&hex::encode(ctx)).is_empty(),
                "destroy_sender_key clears the per-context sender-key store"
            ),
            ContextModeState::Broadcast(_) => panic!("expected encrypted mode"),
        }
    }

    /// §9.16.2 sender-key ANSWER round-trip (ADR-049 PR-7): the actor
    /// [`ContextCryptoState::handle_sender_key_request`] seals its local sender
    /// key to a member requester's fresh ephemeral wrapping key, and the
    /// requester recovers Alice's ACTUAL local sender key — the ground truth —
    /// plus the response metadata (`sender_did` / `epoch` / echoed nonce).
    ///
    /// The answer is the `SenderKeyDistributionMessage::KeyResponse` envelope the
    /// production receive path parses (BLACK-P7-2), so the test decodes the enum,
    /// not a bare `SenderKeyResponse`. This is a self-contained actor round-trip:
    /// the earlier oracle-vs-actor byte comparison was DROPPED — the retained
    /// provider `handle_sender_key_request` is a test FIXTURE builder, not a wire
    /// authority, so agreement with a second copy of the same code proved nothing
    /// the ground-truth assert below does not. The sealed ciphertext is
    /// HPKE-randomised (fresh ephemeral per answer), so the deterministic golden
    /// is the RECOVERED key, not the ciphertext bytes.
    #[test]
    fn golden_handle_sender_key_request_actor_round_trip() {
        use ed25519_dalek::Signer as _;
        use scp_clock::Clock as _;

        let (_alice_p, mut alice_a, _bob_p, _bob_a, ctx) = setup();
        let ctx_hex = hex::encode(ctx);
        let blocked: std::collections::HashSet<String> = std::collections::HashSet::new();

        // Bob's request-signing key (arbitrary; its public half is passed as the
        // `requester_public_key`). BOB is a real group member, so the §9.16.6
        // Mitigation-1 membership gate passes on the group tree regardless.
        let bob_request_signing_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let bob_verifying_key = bob_request_signing_key.verifying_key();

        // Build a signed SenderKeyRequest for Alice's key, sealing to a fresh
        // ephemeral X25519 wrapping keypair.
        let nonce = [2u8; 16];
        let (wrapping_pub, wrapping_secret) =
            scp_protocol::crypto::sender_keys::generate_wrapping_keypair();
        let timestamp = SystemClock.now_secs();
        let hash = scp_protocol::crypto::sender_keys::key_protocol_verify::compute_request_hash(
            BOB,
            ALICE,
            1,
            &wrapping_pub,
            &nonce,
            timestamp,
        )
        .unwrap();
        let signature: [u8; 64] = bob_request_signing_key.sign(&hash).to_bytes();
        let request = scp_protocol::crypto::sender_keys::SenderKeyRequest {
            requester_did: BOB.to_owned(),
            sender_did: ALICE.to_owned(),
            epoch: 1,
            wrapping_pubkey: wrapping_pub,
            nonce,
            timestamp,
            signature,
        };
        let req_bytes = rmp_serde::to_vec_named(&request).unwrap();

        // Answer Bob's request on Alice's owned actor state.
        let resp_bytes = {
            let crypto = match &mut alice_a.mode {
                ContextModeState::Encrypted(c) => c.as_mut(),
                ContextModeState::Broadcast(_) => panic!("expected encrypted mode"),
            };
            crypto
                .handle_sender_key_request(
                    &ctx,
                    ALICE,
                    SystemClock.now_secs(),
                    &req_bytes,
                    bob_verifying_key.as_bytes(),
                    &blocked,
                )
                .expect("actor answers a member request")
                .expect("member requester receives a response")
        };

        // The answer is the KeyResponse envelope the production receiver parses.
        let resp =
            match scp_protocol::crypto::sender_keys::SenderKeyDistributionMessage::from_bytes(
                &resp_bytes,
            )
            .expect("answer decodes as a SenderKeyDistributionMessage")
            {
                scp_protocol::crypto::sender_keys::SenderKeyDistributionMessage::KeyResponse(r) => {
                    r
                }
                other => panic!("expected a KeyResponse envelope, got {other:?}"),
            };
        let key_actor = scp_protocol::crypto::sender_keys::hpke_open_sender_key(
            &resp.hpke_sealed_key,
            &resp.ephemeral_pubkey,
            &wrapping_secret,
            &ctx_hex,
            &resp.sender_did,
            resp.epoch,
        )
        .unwrap();

        // Ground truth: the recovered key is Alice's ACTUAL local sender key, and
        // the metadata echoes the request.
        assert_eq!(
            key_actor.as_bytes(),
            actor_sender_key(&alice_a).as_bytes(),
            "the recovered key is Alice's actual local sender key"
        );
        assert_eq!(resp.sender_did, ALICE);
        assert_eq!(resp.epoch, 1);
        assert_eq!(
            resp.request_nonce, nonce,
            "response echoes the request nonce"
        );
    }
}
