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
//! owns between commit 6 (this commit, the skeleton) and commit 12 (the
//! full migration off `ContextManager`).
//!
//! # Split from `manager/mod.rs`
//!
//! The legacy `ContextManager` carries its own `pub(super)
//! PerContextState` in
//! [`crate::context::manager::mod`] — that type is consumed through
//! the `Mutex<PerContextState>` lock-based model that ADR-049 deletes.
//! The actor's state type here is a separate shape: it drops the generation
//! counter (actor identity replaces it), hoists the broadcast-vs-encrypted
//! split into a [`ContextModeState`] discriminated union, and carries the
//! new per-actor fields (`saga_pending`, `welcome_scratchpad`,
//! `send_tracker`, `recv_tracker`) that the legacy struct did not own.
//!
//! The two types coexist during the commit ladder (commit 6 through
//! commit 12). The legacy `manager::PerContextState` remains
//! byte-identical — no changes to it — while commits 7-11 migrate handler
//! bodies to take `&mut actor::PerContextState`. Commit 12 deletes the
//! legacy `ContextManager`, at which point the legacy type is removed in
//! the same mechanical pass.
//!
//! # Construction
//!
//! This commit does NOT construct `PerContextState` instances anywhere —
//! the actor struct in [`crate::context::actor::ContextActor`] takes one
//! by move in its constructor, but no caller yet spawns an actor. Commit 7
//! wires the first construction path (query-path load from snapshot). The
//! type therefore carries only field definitions and a no-arg `new_for_test`
//! helper used by skeleton unit tests.

use std::collections::{HashMap, HashSet};

use scp_identity::DID;
use scp_protocol::context::roles::ContextRoleState;
use zeroize::Zeroizing;

use crate::context::actor::sequence::SendSequenceTracker;
use crate::context::supervisor::saga_journal::SagaId;
use crate::context::supervisor::saga_prepared_state::SagaPreparedState;

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
    /// Crash-count budget exhausted (3 panics in 60s per ADR-049 §10).
    /// The supervisor will NOT respawn; operator intervention required.
    Poisoned,
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
/// The field set is placeholder for commit 6 — the actual `StagedWelcome`
/// bytes plus the `KpRef` land when `handlers/lifecycle.rs` migrates in
/// commit 9. Keeping the type as a marker now lets the actor state shape
/// compile.
#[derive(Debug, Default)]
pub struct WelcomeProcessing {
    /// Opaque bytes of the OpenMLS `StagedWelcome`. Zeroized on drop
    /// because the staged welcome contains pre-commit group-epoch key
    /// material (plan §"MlsCryptoProvider dissolution" row
    /// `pending_joins`).
    pub staged_welcome: Zeroizing<Vec<u8>>,
    /// The `KpRef` reservation ID held by the `KeyPackageStoreActor`.
    /// Populated at Welcome-Reserve time; consumed at ConfirmConsume
    /// (success) or CancelReservation (failure).
    pub kp_reservation: Option<String>,
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
/// AES-256-GCM key layer described in plan §"Broadcast contexts" — the
/// existing `BroadcastKeyState` in `MlsCryptoProvider` is the starting
/// point; commit 11 reconciles the exact field set when
/// `handlers/broadcast.rs` migrates.
///
/// Fields on this struct are the **contract** for what the actor must own
/// in broadcast mode. Reconciliation against the current
/// `BroadcastKeyState` happens at migration time, not in this skeleton
/// commit.
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

// ---------------------------------------------------------------------------
// Encrypted-mode state (skeleton)
// ---------------------------------------------------------------------------

/// State owned by an encrypted-mode (MLS) `ContextActor`. The full field
/// set (MLS group handle, sender-key registry, access-key CEK store)
/// moves from `MlsCryptoProvider::contexts` in commits 7-12. Commit 6
/// lands the placeholder so `ContextModeState` has both variants.
///
/// The type is intentionally opaque — consumers from `handlers/*.rs`
/// access it via inherent methods (landing per-handler in later commits)
/// rather than peeking at fields directly.
#[derive(Debug, Default)]
pub struct ContextCryptoState {
    // Fields populated in commit 7+. Until then this carries no state —
    // the marker type is enough to make `ContextModeState::Encrypted`
    // expressible on `PerContextState`.
}

// ---------------------------------------------------------------------------
// ContextModeState — discriminated union over encrypted / broadcast
// ---------------------------------------------------------------------------

/// Discriminated union over the two context modes. Matches the plan's
/// contract: exactly one variant is present per actor; the mode is set
/// at actor construction and never changes.
#[derive(Debug)]
pub enum ContextModeState {
    /// Standard MLS-encrypted context.
    Encrypted(ContextCryptoState),
    /// Broadcast context (per-author AES-256-GCM, no MLS group).
    Broadcast(BroadcastState),
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

/// Per-context actor state. Owned by exactly one [`ContextActor`] for its
/// entire lifetime; no interior mutability, no locks, no `Arc`.
///
/// Field set is the contract the plan's handler signatures rely on
/// (§"ContextActor" dispatch loop + §"Submodule organization"). Every
/// field listed here is populated in later commits; none carry the
/// `Default` value in production.
pub struct PerContextState {
    /// Deterministic context identifier (SHA-256 of canonical creation
    /// parameters — spec §5.2). Stable for the actor's entire lifetime.
    pub context_id: [u8; 32],

    /// Unix-ms timestamp of first actor instantiation for this context.
    /// Preserved across respawn via snapshot — new actor instances for
    /// the same context share one `created_at`.
    pub created_at: u64,

    /// Active member set.
    pub members: HashSet<DID>,

    /// Roles, ceiling, and assignments.
    pub role_state: ContextRoleState,

    /// RFC-6962 Merkle event log. `None` until the first event; some
    /// actor constructions (test fixtures, mid-restore) run with it unset.
    pub event_log: Option<ContextEventLog>,

    /// Send-sequence counter with RAII rollback
    /// ([`SequenceReservation`](crate::context::actor::SequenceReservation)).
    pub send_tracker: SendSequenceTracker,

    /// Per-sender receive-sequence high-water marks for anti-replay.
    pub recv_tracker: RecvSequenceTracker,

    /// Staged cross-context saga mutations awaiting Commit or Abort. Plan
    /// §"Cross-context saga protocol" restricts to at most one entry —
    /// concurrent sagas against the same actor are serialized by
    /// rejecting new Prepare while this map is non-empty.
    pub saga_pending: HashMap<SagaId, SagaPreparedState>,

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
    /// Construct a fresh encrypted-mode actor state. Used by test fixtures
    /// and by the skeleton unit tests below — the production construction
    /// path lands in commit 7 when the lifecycle handler migrates.
    #[must_use]
    pub fn new_for_test_encrypted(context_id: [u8; 32], created_at: u64) -> Self {
        Self {
            context_id,
            created_at,
            members: HashSet::new(),
            role_state: empty_role_state_for_test(),
            event_log: None,
            send_tracker: SendSequenceTracker::new(),
            recv_tracker: RecvSequenceTracker::new(),
            saga_pending: HashMap::new(),
            welcome_scratchpad: None,
            lifecycle_state: ContextLifecycleState::Open,
            mode: ContextModeState::Encrypted(ContextCryptoState::default()),
        }
    }

    /// Construct a fresh broadcast-mode actor state. Same role as
    /// [`Self::new_for_test_encrypted`].
    #[must_use]
    pub fn new_for_test_broadcast(context_id: [u8; 32], created_at: u64) -> Self {
        Self {
            context_id,
            created_at,
            members: HashSet::new(),
            role_state: empty_role_state_for_test(),
            event_log: None,
            send_tracker: SendSequenceTracker::new(),
            recv_tracker: RecvSequenceTracker::new(),
            saga_pending: HashMap::new(),
            welcome_scratchpad: None,
            lifecycle_state: ContextLifecycleState::Open,
            mode: ContextModeState::Broadcast(BroadcastState::default()),
        }
    }
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

    #[test]
    fn encrypted_constructor_places_encrypted_mode() {
        let s = PerContextState::new_for_test_encrypted([0u8; 32], 42);
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
        let s = PerContextState::new_for_test_broadcast([1u8; 32], 7);
        assert!(s.mode.is_broadcast());
        assert!(!s.mode.is_encrypted());
        if let ContextModeState::Broadcast(b) = &s.mode {
            assert_eq!(b.local_send_sequence, 0);
            assert!(b.author_keys.is_empty());
            assert!(b.blocked_authors.is_empty());
            assert!(b.subscribers.is_empty());
        } else {
            panic!("expected broadcast mode");
        }
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
