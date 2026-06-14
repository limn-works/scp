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
//! owns across the commit-12 migration off `ContextManager`.
//!
//! # Split from `manager/mod.rs`
//!
//! The legacy `ContextManager` carries its own `pub(crate)
//! PerContextState` in the deleted `crate::context::manager` module —
//! that type was consumed through
//! the `per-context-state Mutex` lock-based model that ADR-049 deletes.
//! The actor's state type here is a SUPERSET-COMPATIBLE shape: every field
//! the legacy struct owns is represented here (so commit 12b+ handler-body
//! migrations move calls mechanically off `manager.field` onto
//! `state.field`), plus the new per-actor fields (`saga_pending`,
//! `welcome_scratchpad`, `send_tracker`, `recv_tracker`, split mode
//! state) that the legacy struct did not own.
//!
//! The two types coexist during the commit ladder (commit 6 through
//! commit 12). The legacy `state::PerContextState` remains
//! byte-identical — no changes to it apart from the `pub(crate)` field
//! elevations commit 12a adds so the actor can name the sub-struct types.
//! Commits 12b-12c migrate handler bodies to take `&mut
//! actor::PerContextState`. Commit 12d deletes the legacy
//! `ContextManager`, at which point the legacy type is removed in the
//! same mechanical pass.
//!
//! # Commit 12a — fields-only
//!
//! Commit 12a populates [`PerContextState`], [`ContextCryptoState`], and
//! [`BroadcastState`] with every field the legacy manager's
//! [`crate::context::state::PerContextState`] +
//! `MlsCryptoProvider::contexts[ctx_id]` owns. No handler body moves
//! here — the shim still delegates through `ContextManager` via
//! `view.manager()`. The purpose is to give 12b+ a complete field-set
//! destination so each handler migration is a mechanical move from
//! `manager.foo` to `state.foo`.
//!
//! The MLS group handle on [`ContextCryptoState`] is `Option<ScpMlsGroup>`
//! (not `ScpMlsGroup` non-optional as the legacy provider held it),
//! because actors spawn before any MLS state is constructed — Create /
//! Join handlers in 12b+ populate it. This is the only shape divergence
//! from legacy; all other fields are stored in the same type the legacy
//! manager uses.
//!
//! # Construction
//!
//! This commit does NOT wire production construction — the production
//! construction path still lives on `ContextManager` and hands the shim
//! a legacy `state::PerContextState`. Commit 12b (messaging handler
//! migration) is the first production call site that constructs an
//! [`actor::PerContextState`](PerContextState). Until then the test
//! constructors [`PerContextState::new_for_test_encrypted`] and
//! [`PerContextState::new_for_test_broadcast`] are the only call sites
//! and exist to prove the shape is both structurally complete and
//! constructible from minimum inputs.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use scp_event_log::EventLog as MerkleEventLog;
use scp_event_log::checkpoint::ConsistencyCheckpoint;
use scp_identity::DID;
use scp_primitives::{Clock, SystemClock};
use scp_protocol::context::broadcast::BroadcastContext as ProtocolBroadcastContext;
use scp_protocol::context::membership::{MembershipState, ReceiveBuffer};
use scp_protocol::context::roles::ContextRoleState;
use scp_protocol::crypto::access_keys::AccessKeyStore;
use scp_protocol::crypto::sender_keys::{NonceDedup, SenderKey, SenderKeyStore};
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
use crate::crypto::mls::group::ScpMlsGroup;

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
/// (`crate::crypto::mls::provider::ContextCryptoState`) field-for-field,
/// plus the `AccessControlState.access_key_store` field which spec §9.17
/// scopes to encrypted contexts only (broadcast contexts use the
/// per-author AES-GCM layer in [`BroadcastState`] instead).
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
    /// Maps `sender_did` -> (`last_epoch`, `last_sequence`). Mirror of
    /// legacy field
    /// `MlsCryptoProvider::ContextCryptoState::recv_sequence_tracker`
    /// at `crates/scp-runtime/src/crypto/mls/provider.rs:229`.
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
    /// ContextManager-level reorder / delivery path. This field is the
    /// MLS sender-key layer `(epoch, sequence)` pair that [`open`]
    /// reads in the provider (see provider.rs:1211-1221 for the
    /// authoritative algorithm). Commit 12b.2 migrates that deliver-
    /// path read/write onto this field.
    ///
    /// [`open`]: crate::crypto::mls::provider::MlsCryptoProvider::open
    pub recv_sequence_tracker: HashMap<String, (u64, u64)>,

    /// Per-member access-key store for content-encryption-key wrapping
    /// (spec §9.17, ADR-038). Scoped to encrypted contexts: legacy
    /// stored this on
    /// [`AccessControlState::access_key_store`](crate::context::state::AccessControlState)
    /// on every `PerContextState` — per task §2, commit 12a hoists the
    /// field to [`ContextCryptoState`] because it is encrypted-mode-
    /// specific (broadcast contexts use the per-author AES-GCM layer
    /// on [`BroadcastState`]). The [`AccessControlState`] field on
    /// [`PerContextState`](PerContextState) remains populated for the
    /// shim window so 12b+ handler migrations can pick whichever
    /// storage site to authoritatively consolidate onto.
    pub access_key_store: AccessKeyStore,
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
            .field("access_key_store", &self.access_key_store)
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
            access_key_store: AccessKeyStore::new(),
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
/// [`crate::context::state::ContextModeState`]-equivalent mode information at
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
/// [`crate::crypto::mls::group::ScpMlsGroup`]'s internal OpenMLS
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
// PerContextState — the actor's owned state payload
// ---------------------------------------------------------------------------

/// Per-context actor state. Owned by exactly one [`ContextActor`](crate::context::actor::ContextActor) for its
/// entire lifetime; no interior mutability, no locks, no `Arc`.
///
/// Field set is the contract the plan's handler signatures rely on
/// (§"ContextActor" dispatch loop + §"Submodule organization"). Every
/// field listed here is populated by commits 12b+ in production; the
/// [`Self::new_for_test_encrypted`] / [`Self::new_for_test_broadcast`]
/// fixtures default the rest for test use.
///
/// # Field-for-field parity with legacy
///
/// Commit 12a mirrors every field on
/// [`crate::context::state::PerContextState`] so 12b+ handler-body
/// migrations move calls mechanically off `manager.foo` onto
/// `state.foo`. The new-per-actor fields at the bottom of the struct
/// (`send_tracker`, `recv_tracker`, `saga_pending`, `welcome_scratchpad`,
/// `lifecycle_state`, `mode`) have no legacy equivalent — they replace
/// the `per-context-state Mutex` lock-based model.
///
/// # Dead-code in commit 12a
///
/// The 12a fields-only commit populates every field but wires no
/// handler callers — the `view.manager()` shim still delegates to
/// `ContextManager` for every mutation. Per-field `#[allow(dead_code)]`
/// markers are intentionally NOT applied: the struct-level
/// `#[allow(dead_code)]` below covers unused private-type fields
/// (`governance`, `epoch`, `access`, `ttl`) until 12b+ handlers read
/// them. All other fields are already reachable via their `pub`
/// accessors from existing shim or test code.
#[allow(
    dead_code,
    reason = "Commit 12a of ADR-049 is fields-only; 12b+ handler migrations wire the first production readers of `governance`/`epoch`/`access`/`ttl`. See `.docs/adrs/ADR-049-actor-per-context.md` §Commit ladder."
)]
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
    pub created_at: u64,

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
    /// `EventLogPersistence` path; not the same as
    /// [`Self::merkle_tree`] (the in-memory RFC-6962 tree legacy held
    /// for proof generation).
    pub event_log: Option<ContextEventLog>,

    /// In-memory RFC-6962 Merkle tree (ADR-011) parallel to the
    /// persisted event log. Used by `manager/messaging.rs` for O(log n)
    /// inclusion / consistency proofs. Mirrors legacy
    /// `state::PerContextState::merkle_tree`. Not persisted — rebuilt
    /// from `MerkleEventLogProvider` on `restore_context` /
    /// `import_context` per legacy comment.
    pub merkle_tree: MerkleEventLog,

    /// Receive event buffer (bounded 1000-entry deque). Mirrors legacy
    /// `state::PerContextState::receive_buffer`.
    pub receive_buffer: ReceiveBuffer,

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
    /// Note: per task §2, the `access_key_store` sub-field of this
    /// struct is also duplicated on
    /// [`ContextCryptoState::access_key_store`] — encrypted contexts
    /// have both storage sites available; 12b+ handler migrations pick
    /// one. 12d removes the unused one.
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

    /// Highest `(event_count, timestamp)` observed per remote checkpoint
    /// sender DID (§9.9.3 replay defense). A remote checkpoint that is not
    /// strictly newer than the last-seen pair for that sender is a no-op
    /// in `compare_remote_checkpoint`: it neither re-appends an
    /// `EquivocationDetected` event nor re-bumps `checkpoint_events_since`.
    /// Without this, a relay can replay one signed divergent checkpoint
    /// unboundedly to inflate the event log and flood the receive buffer
    /// with duplicate alerts.
    pub last_seen_remote_checkpoint: HashMap<DID, (u64, u64)>,

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

    /// Staged cross-context saga mutations awaiting Commit or Abort. Plan
    /// §"Cross-context saga protocol" restricts to at most one entry —
    /// concurrent sagas against the same actor are serialized by
    /// rejecting new Prepare while this map is non-empty.
    pub saga_pending: HashMap<SagaId, SagaPreparedState>,

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
    ContextRoleState {
        context_id: String::new(),
        creator_did: String::new(),
        ceiling: scp_protocol::context::roles::CapabilityCeiling::new(std::iter::empty()),
        role_definitions: HashMap::new(),
        assignments: HashMap::new(),
        members: HashSet::new(),
        member_capabilities: HashMap::new(),
        suspended_capabilities: HashMap::new(),
    }
}

impl PerContextState {
    /// Pushes an event to the receive buffer and, if a broadcast channel
    /// is provided, sends a sanitized copy there too. Mirrors the
    /// security invariants of the standalone
    /// [`crate::context::state::emit_event_into`] helper:
    ///
    /// - `WelcomeGenerated` events carry MLS key material and are NEVER
    ///   sent on the broadcast channel (receive buffer only).
    /// - `MessageReceived` / `MessageSent` payloads contain decrypted
    ///   plaintext and are stripped (replaced with empty `Vec`) before
    ///   broadcast to preserve encryption-as-access-control.
    pub(crate) fn emit_event(
        &mut self,
        event: scp_protocol::context::membership::ContextEvent,
        context_id: &str,
        tx: Option<
            &tokio::sync::broadcast::Sender<(
                String,
                scp_protocol::context::membership::ContextEvent,
            )>,
        >,
    ) {
        crate::context::state::emit_event_into(&mut self.receive_buffer, event, context_id, tx);
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
            generation: 0,
            handle,
            membership: MembershipState::new(),
            members: HashSet::new(),
            role_state: empty_role_state_for_test(),
            event_log: None,
            merkle_tree: MerkleEventLog::new(context_id_str.to_owned()),
            receive_buffer: ReceiveBuffer::new(),
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
            saga_pending: HashMap::new(),
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

    #[test]
    fn encrypted_constructor_places_encrypted_mode() {
        let s = PerContextState::new_for_test_encrypted([0u8; 32], 42, test_admin());
        assert!(s.mode.is_encrypted());
        assert!(!s.mode.is_broadcast());
        assert_eq!(s.created_at, 42);
        assert_eq!(s.lifecycle_state, ContextLifecycleState::Open);
        assert_eq!(s.send_tracker.last_issued(), 0);
        assert!(s.saga_pending.is_empty());
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
            generation,
            handle,
            membership,
            members,
            role_state,
            event_log,
            merkle_tree,
            receive_buffer,
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
            saga_pending,
            pending_broadcast_publishes,
            welcome_scratchpad,
            lifecycle_state,
            mode,
        } = s;

        // Identity + lifetime.
        assert_eq!(context_id, [3u8; 32]);
        assert_eq!(created_at, 12);
        assert_eq!(generation, 0);
        assert_eq!(handle.context_id().len(), 64);

        // Membership + role.
        assert_eq!(membership.count(), 0);
        assert!(members.is_empty());
        assert!(role_state.members.is_empty());

        // Event buffers + logs.
        assert!(event_log.is_none());
        assert_eq!(merkle_tree.leaves().len(), 0);
        assert_eq!(receive_buffer.len(), 0);

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
            generation: _,
            handle: _,
            membership: _,
            members: _,
            role_state: _,
            event_log: _,
            merkle_tree: _,
            receive_buffer: _,
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
            saga_pending: _,
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
            access_key_store,
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
        let _ = &access_key_store;
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
}
