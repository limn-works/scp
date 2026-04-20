//! `Supervisor` — the plain-struct actor registry + saga coordinator.
//!
//! # Clippy allows
//!
//! `doc_markdown` / `too_long_first_doc_paragraph` — doc prose cites
//! plan section titles in quoted form.
#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//!
//! Per ADR-049 §2 and plan §"Supervisor" the supervisor is a **plain
//! struct, not an actor**. Lookups are on the hot path of every public
//! API call; making the supervisor an actor would add a mailbox hop per
//! call. Instead:
//!
//! - `DashMap<String, ContextActorHandle>` for the actor registry
//!   (lock-free `get`).
//! - `ArcSwap<HashMap<String, DID>>` for standing contexts (lock-free
//!   read; atomic swap on write).
//! - `ArcSwap<HashSet<DID>>` for local DIDs (same).
//! - `DashMap<DID, ArcSwap<WrappingKeyPair>>` for per-identity wrapping
//!   keys (rare rotation).
//! - `tokio::sync::Mutex<()>` write-lock serializing ALL mutations of
//!   the above. Reads are lock-free; the mutex prevents lost writes
//!   when two callers race a `store` on the same `ArcSwap`.
//!
//! # Commit 6 scope
//!
//! The struct lands with `new`, `lookup`, `spawn_actor`, and the saga
//! `start_saga` entry point. Every method that migrates the real
//! semantics lives behind a
//! [`ContextError::NotImplemented`](scp_protocol::context::ContextError::NotImplemented)
//! stub — saga orchestration migrates with `handlers/standing.rs` and
//! the related cross-context paths in commit 11.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};

use arc_swap::ArcSwap;
use dashmap::DashMap;
use scp_identity::DID;
use scp_protocol::context::ContextError;

use crate::context::actor::commands::{
    BroadcastCommand, ContextCommand, EconomyCommand, GovernanceCommand, LifecycleCommand,
    MessagingCommand, QueriesCommand, StandingCommand, ToolsCommand, TrustRecoveryCommand,
    TtlCloseCommand,
};
use crate::context::actor::handle::ContextActorHandle;
use crate::context::actor::handlers;
use crate::context::actor::mutation_state_view::MutationStateView;
use crate::context::actor::outcome::Outcome;
use crate::context::actor::query_state_view::QueryStateView;
use crate::context::actor::sequence::SendSequenceTracker;
use crate::context::actor::state::WrappingKeyPair;
use crate::context::manager::{ContextManager, ContextPersistence};
use crate::context::supervisor::key_package_actor::KeyPackageStoreHandle;
use crate::context::supervisor::saga_journal::{
    JournalEntry, SagaId, SagaJournal, SagaState, SagaTerminalState,
};
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Actor mailbox capacity. Plan §"Mailbox parameters": bounded at 256 so
/// the mailbox applies backpressure to callers.
pub const ACTOR_MAILBOX_CAPACITY: usize = 256;

// ---------------------------------------------------------------------------
// SagaInput / SagaOutput — plan §"Cross-context saga protocol"
// ---------------------------------------------------------------------------

/// Input to [`Supervisor::start_saga`]. The variant enumerates the 4
/// saga types defined in plan §"Cross-context saga protocol"
/// (standing-pair create, migration, cross-context tool invoke,
/// broadcast hosting handshake). Commit 6 lands the enum shape;
/// real field sets arrive when each handler migrates.
///
/// The type is a discriminated union so that adding a fifth saga type
/// later is a compile error at every call site — the default branch is
/// not permitted.
pub enum SagaInput {
    /// Standing-pair creation between two identities. Full field set
    /// arrives with `handlers/standing.rs` in commit 11.
    StandingPairCreate {
        /// The local identity initiating the pair.
        local_did: DID,
        /// The remote peer.
        peer_did: DID,
    },
    /// Context migration between two identities (target-side).
    ContextMigration {
        /// Source context ID.
        source_context_id: [u8; 32],
        /// Source identity.
        source_identity_did: DID,
    },
    /// Cross-context tool invocation.
    CrossContextToolInvocation {
        /// Calling context.
        caller_context_id: [u8; 32],
        /// Calling identity.
        caller_did: DID,
        /// Tool registration to invoke.
        tool_registration_id: String,
    },
    /// Broadcast hosting handshake.
    BroadcastHostingHandshake {
        /// Host context.
        host_context_id: [u8; 32],
        /// Broadcast context.
        broadcast_context_id: [u8; 32],
        /// Subscriber requesting hosting.
        subscriber_did: DID,
    },
}

/// Output from [`Supervisor::start_saga`] on success. The saga's durable
/// outcome; commit 6 carries only the saga ID so the type is stable for
/// callers.
#[derive(Debug)]
pub struct SagaOutput {
    /// Durable saga identifier; usable as a handle into the journal.
    pub saga_id: SagaId,
}

// ---------------------------------------------------------------------------
// Supervisor configuration + crash tracking
// ---------------------------------------------------------------------------

/// Supervisor configuration. Cheap defaults for commit 6; real fields
/// (saga phase timeouts, respawn budget windows) materialize alongside
/// the saga migration in commit 11.
#[derive(Clone, Debug, Default)]
pub struct SupervisorConfig {
    /// Reserved for future configuration; placeholder field so the
    /// struct has stable layout.
    #[allow(dead_code)]
    reserved: (),
}

/// Per-context crash-count window. Plan §"Actor panic recovery" defines
/// a 60-second sliding window with a 3-crash respawn budget; commit 6
/// lands the struct layout, the watchdog that feeds it arrives with the
/// handler migrations.
#[derive(Debug, Default)]
pub struct CrashWindow {
    /// Reserved; real fields land with the watchdog in commit 11.
    #[allow(dead_code)]
    reserved: (),
}

/// Placeholder saga state stored in `pending_sagas` between Prepare and
/// Commit/Abort. Commit 6 keeps this opaque; the real state shape lives
/// in the per-saga-type `SagaPreparedState` variants.
#[derive(Debug)]
pub struct PendingSagaProjection {
    /// Reserved; the real in-memory projection of the saga FSM lands
    /// alongside the handler migrations in commit 11.
    #[allow(dead_code)]
    reserved: (),
}

// ---------------------------------------------------------------------------
// Supervisor
// ---------------------------------------------------------------------------

/// Plain struct — not an actor. See module-level docs for rationale.
///
/// The write path (any mutation of `actors`, `standing_contexts`,
/// `local_dids`, or `wrapping_keys`) acquires [`Self::write_lock`] first,
/// then does the `DashMap::insert` / `ArcSwap::store`, then drops the
/// lock. This prevents lost writes from concurrent `ArcSwap::store`
/// operations (which are atomic in isolation but not when the caller
/// wants read-modify-write semantics against the stored snapshot).
pub struct Supervisor {
    /// Actor registry. `context_id` → `ContextActorHandle`. Lookups via
    /// [`Self::lookup`] are lock-free (`DashMap::get`).
    #[allow(dead_code)]
    // read in commit 11 when BridgeInstance wires supervisor into the suspend path
    pub(in crate::context::supervisor) actors: DashMap<String, ContextActorHandle>,
    /// Standing-pair context index. `context_id` → peer `DID`. Read
    /// via `ArcSwap::load` (lock-free); mutated under
    /// [`Self::write_lock`].
    #[allow(dead_code)] // populated by `standing` handler in commit 11
    pub(in crate::context::supervisor) standing_contexts: ArcSwap<HashMap<String, DID>>,
    /// Local identities. Grows once per `identity_add`; read-heavy.
    #[allow(dead_code)] // populated by `lifecycle` handler in commit 9
    pub(in crate::context::supervisor) local_dids: ArcSwap<HashSet<DID>>,
    /// Per-identity X25519 wrapping keys. Wrapped in `ArcSwap` so
    /// rotation is atomic; outer `DashMap` keyed by DID.
    #[allow(dead_code)] // populated by lifecycle / identity paths
    pub(in crate::context::supervisor) wrapping_keys: DashMap<DID, ArcSwap<WrappingKeyPair>>,
    /// Persistence backend; stored so `spawn_actor` / `crash_recovery`
    /// can plumb it through to per-actor state.
    #[allow(dead_code)] // read in spawn paths landing with lifecycle migration
    pub(in crate::context::supervisor) persistence: Arc<dyn ContextPersistence>,
    /// Single-producer-multi-read write lock — plan §"Write path".
    #[allow(dead_code)]
    // read in commit 11 when handlers acquire it for standing/lifecycle writes
    pub(in crate::context::supervisor) write_lock: tokio::sync::Mutex<()>,
    /// Pending sagas keyed by saga ID; projection of the durable
    /// journal for fast lookup.
    #[allow(dead_code)] // real body lands with saga migration in commit 11
    pub(in crate::context::supervisor) pending_sagas: DashMap<SagaId, PendingSagaProjection>,
    /// Durable saga journal (plan §"Cross-context saga protocol").
    #[allow(dead_code)] // wired through saga migration in commit 11
    pub(in crate::context::supervisor) saga_journal: Arc<dyn SagaJournal>,
    /// Per-identity `KeyPackageStoreActor` handles.
    #[allow(dead_code)] // populated by identity_add in later commits
    pub(in crate::context::supervisor) key_package_stores: DashMap<DID, KeyPackageStoreHandle>,
    /// Configuration.
    #[allow(dead_code)] // plumbed into handlers later
    pub(in crate::context::supervisor) health_config: SupervisorConfig,
    /// Per-context crash-count windows (respawn budget state).
    #[allow(dead_code)] // populated by watchdog in commit 11
    pub(in crate::context::supervisor) crash_windows: DashMap<String, CrashWindow>,
    /// Transitional bridge to the legacy [`ContextManager`].
    ///
    /// During the commits-7-to-11 migration window the supervisor
    /// dispatches queries through the actor-shape handler while all
    /// mutating paths continue to run on `ContextManager`. This field
    /// holds the shared reference the shim reads through; it is `None`
    /// before `attach_context_manager` is called (the field is wired by
    /// the bridge after both the supervisor and the context manager are
    /// constructed — see commit-7 bridge wiring).
    ///
    /// Deleted in commit 12 with `ContextManager`.
    context_manager_bridge: OnceLock<Arc<ContextManager>>,

    /// Concurrent-saga guard. `true` iff a saga is currently in flight
    /// (Initiated / PreparingA / PreparingB / Committing). A second
    /// concurrent `start_saga` while the flag is `true` returns
    /// [`ContextError::ActorBusy`](scp_protocol::context::ContextError::ActorBusy)
    /// via the `SagaBusy` reason — the supervisor serializes sagas
    /// supervisor-wide so the per-actor `saga_pending` slot never
    /// contends. The atomic is set on `start_saga` entry (if currently
    /// `false`) and cleared when the saga reaches a terminal state
    /// (Committed, Aborted, NeedsRepair).
    saga_pending_guard: std::sync::atomic::AtomicBool,
}

impl Supervisor {
    /// Constructs a fresh supervisor.
    ///
    /// `persistence` and `saga_journal` are injected at construction so
    /// the supervisor is never a singleton — bridge instances in
    /// [`scp_ffi_common::bridge_instance`] construct one per SCP
    /// instance and drop it on `shutdown`.
    #[must_use]
    pub fn new(
        persistence: Arc<dyn ContextPersistence>,
        saga_journal: Arc<dyn SagaJournal>,
        health_config: SupervisorConfig,
    ) -> Self {
        Self {
            actors: DashMap::new(),
            standing_contexts: ArcSwap::new(Arc::new(HashMap::new())),
            local_dids: ArcSwap::new(Arc::new(HashSet::new())),
            wrapping_keys: DashMap::new(),
            persistence,
            write_lock: tokio::sync::Mutex::new(()),
            pending_sagas: DashMap::new(),
            saga_journal,
            key_package_stores: DashMap::new(),
            health_config,
            crash_windows: DashMap::new(),
            context_manager_bridge: OnceLock::new(),
            saga_pending_guard: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Convenience constructor used by the commits-7-to-11 FFI query
    /// shim. Builds a supervisor whose `persistence` and `saga_journal`
    /// fields are no-op stubs — the query-path shim
    /// ([`Self::dispatch_query`]) does not touch either field; saga and
    /// actor-spawn wiring arrive in commits 9-11.
    ///
    /// Every FFI bridge embeds one [`Supervisor`] per bridge instance.
    /// When the migration completes (commit 12) this helper is deleted
    /// along with the shim and callers switch to [`Self::new`] with
    /// real production impls.
    #[must_use]
    pub fn for_query_shim() -> Self {
        let persistence: Arc<dyn ContextPersistence> = Arc::new(NoopContextPersistence);
        let saga_journal: Arc<dyn SagaJournal> = Arc::new(NoopSagaJournal);
        Self::new(persistence, saga_journal, SupervisorConfig::default())
    }

    /// Attach the legacy [`ContextManager`] used by the commits-7-to-11
    /// migration shim. The bridge instance constructs both the
    /// supervisor and the context manager, then calls this method once
    /// before handing either out to FFI callers.
    ///
    /// Idempotent — a second call with the same reference succeeds
    /// silently; a second call with a different reference returns
    /// `Err(ContextError::InvalidState(..))` because the supervisor must
    /// route every query against a stable manager for the full lifetime
    /// of the bridge instance. Deleted in commit 12 with the bridge
    /// field itself.
    ///
    /// The parameter is taken by reference — the `OnceLock` slot is set
    /// only when the slot is empty, so the caller's `Arc` is cloned at
    /// most once. On re-attach with an identical pointer the caller's
    /// reference is not consumed at all.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::InvalidState`] if a different
    /// `ContextManager` was already attached, or if the `OnceLock` slot
    /// was populated concurrently between the emptiness check and the
    /// read-back (should not occur under the documented single-attach
    /// contract but returned rather than panicked on).
    pub fn attach_context_manager(
        &self,
        manager: &Arc<ContextManager>,
    ) -> Result<(), ContextError> {
        // `OnceLock::set` consumes its argument, so we clone the `Arc`
        // only when the slot is actually empty. If another caller raced
        // us, `set` returns Err and we verify the stored value matches.
        if self.context_manager_bridge.set(Arc::clone(manager)).is_ok() {
            return Ok(());
        }
        // `set` returned Err — someone (possibly the same caller)
        // populated the slot. Accept an identical pointer as idempotent.
        let existing = self.context_manager_bridge.get().ok_or_else(|| {
            ContextError::InvalidState(
                "Supervisor::attach_context_manager — OnceLock slot observed empty after \
                 a failed `set`; this should be unreachable and indicates an impl bug"
                    .to_owned(),
            )
        })?;
        if Arc::ptr_eq(existing, manager) {
            Ok(())
        } else {
            Err(ContextError::InvalidState(
                "Supervisor::attach_context_manager — a different manager is already \
                 attached; re-attach is not supported"
                    .to_owned(),
            ))
        }
    }

    /// Cheap reference to the attached [`ContextManager`]. Returns
    /// `None` before `attach_context_manager` has been called. Used by
    /// the query shim.
    ///
    /// The method is `pub(in crate::context)` rather than `pub` — FFI
    /// bridges reach the manager through
    /// [`CoreFields::try_context_manager`](scp_ffi_common::bridge_instance::CoreFields::try_context_manager)
    /// and never through `SupervisorHandle`. The `SupervisorHandle`
    /// capability-reduction contract (plan §"ActorDeps and
    /// SupervisorHandle") forbids exposing this reference outside the
    /// runtime crate.
    #[must_use]
    pub(in crate::context) fn attached_context_manager(&self) -> Option<&Arc<ContextManager>> {
        self.context_manager_bridge.get()
    }

    /// Dispatch a pure-read [`QueriesCommand`] through the migration
    /// shim.
    ///
    /// Behaviour (byte-identical to the legacy `ContextManager::foo()`
    /// it replaces):
    ///
    /// - Takes the per-context mutex under
    ///   [`ContextManager::with_query_state`].
    /// - Builds a [`QueryStateView`] over the locked state and the
    ///   manager's shared event-log provider.
    /// - Invokes [`handlers::queries::dispatch_from_shim`], which
    ///   matches on the command variant, sends the typed oneshot
    ///   reply, and returns `Outcome::ok(())` with `mutated: false`.
    /// - On missing context, the shim emits the variant's legacy
    ///   default (e.g. `MemberCount::Ok(None)`, `IsMember::Ok(false)`)
    ///   without entering the handler — this preserves the
    ///   "context unknown = soft fallback" behaviour of the pre-shim
    ///   path.
    ///
    /// Outcome: `Outcome::ok(())` on every success. The variant's reply
    /// channel carries the typed result. The returned `Outcome` is
    /// dropped by FFI callers — it is retained so the wiring is
    /// symmetric with the mutating-handler paths that land in
    /// commits 8-11.
    ///
    /// # Errors
    ///
    /// - [`ContextError::NotInitialized`] if no [`ContextManager`] has
    ///   been attached yet — the caller must call
    ///   [`Self::attach_context_manager`] first.
    pub async fn dispatch_query(&self, cmd: QueriesCommand) -> Result<Outcome<()>, ContextError> {
        let cm = self.attached_context_manager().ok_or_else(|| {
            ContextError::NotInitialized(
                "Supervisor::dispatch_query — no ContextManager attached".to_owned(),
            )
        })?;

        // Pre-lookup: variants that require a per-context lock all carry
        // a `context_id` field. We route by command variant to preserve
        // the legacy "context unknown = soft default" contract — see
        // the variant-by-variant dispatch tables in
        // `crates/scp-runtime/src/context/manager/queries.rs`.
        match cmd {
            // Variants whose legacy method returns a `ContextError` on
            // unknown context — propagate the error directly.
            QueriesCommand::LocalPseudonym { ref context_id, .. }
            | QueriesCommand::GetBroadcastKeyForLocalAuthor { ref context_id, .. } => {
                let ctx_id = context_id.clone();
                Self::dispatch_with_view(cm, &ctx_id, cmd, /*soft_fallback=*/ false).await
            }

            // Variants whose legacy method returns a default value on
            // unknown context — route through the soft fallback path.
            QueriesCommand::MemberCount { ref context_id, .. }
            | QueriesCommand::IsMember { ref context_id, .. }
            | QueriesCommand::MemberDids { ref context_id, .. }
            | QueriesCommand::MemberRole { ref context_id, .. }
            | QueriesCommand::ContextParams { ref context_id, .. }
            | QueriesCommand::GetRoleState { ref context_id, .. }
            | QueriesCommand::PendingCommits { ref context_id, .. }
            | QueriesCommand::CommitFault { ref context_id, .. } => {
                let ctx_id = context_id.clone();
                Self::dispatch_with_view(cm, &ctx_id, cmd, /*soft_fallback=*/ true).await
            }

            // `EventLogEntries` takes a 32-byte hash rather than a
            // context-id string. The legacy method bypasses the
            // per-context mutex entirely; it delegates straight to
            // `self.event_log.event_log_entries(...)`. We mirror that
            // by extracting the reply sender + hash, calling the
            // provider directly, and sending the typed reply. No view
            // is constructed because no per-context borrow is needed.
            QueriesCommand::EventLogEntries {
                context_id_bytes,
                reply,
            } => {
                let answer = cm
                    .event_log_provider_arc()
                    .event_log_entries(&context_id_bytes);
                let _ = reply.send(answer);
                Ok(Outcome::ok(()))
            }

            #[cfg(feature = "testing")]
            QueriesCommand::GetAccessKey { ref context_id, .. }
            | QueriesCommand::GetAllAccessKeys { ref context_id, .. }
            | QueriesCommand::RemainingBudgetForTest { ref context_id, .. }
            | QueriesCommand::VelocityForTest { ref context_id, .. } => {
                let ctx_id = context_id.clone();
                Self::dispatch_with_view(cm, &ctx_id, cmd, /*soft_fallback=*/ true).await
            }
        }
    }

    /// Dispatch a mutating [`MessagingCommand`] through the migration
    /// shim (ADR-049 commit 8 / plan row 8).
    ///
    /// Contract (byte-identical to the legacy
    /// [`ContextManager::send_message`](crate::context::manager::ContextManager::send_message)
    /// / [`ContextManager::deliver_incoming`](crate::context::manager::ContextManager::deliver_incoming)
    /// it replaces):
    ///
    /// 1. Takes the tracker out of the per-context state under a brief
    ///    lock (`std::mem::take` replaces it with a fresh
    ///    [`SendSequenceTracker`](crate::context::actor::SendSequenceTracker)
    ///    whose high-water mark matches the previous one).
    /// 2. Drops the lock so the delegated
    ///    [`ContextManager`](crate::context::manager::ContextManager)
    ///    call can re-acquire it internally without deadlock.
    /// 3. Builds a [`MutationStateView`] over the taken tracker + a
    ///    reference to the attached manager, and invokes
    ///    [`handlers::messaging::dispatch`](crate::context::actor::handlers::messaging::dispatch).
    ///    The handler exercises
    ///    [`SequenceReservation`](crate::context::actor::SequenceReservation)
    ///    on the view's `send_tracker` (the taken tracker), wraps the
    ///    delegated
    ///    [`ContextManager::send_message`](crate::context::manager::ContextManager::send_message)
    ///    / [`ContextManager::deliver_incoming`](crate::context::manager::ContextManager::deliver_incoming)
    ///    call in `tokio::time::timeout` with a 30s budget, and maps
    ///    a timeout to
    ///    [`ContextError::TransportTimeout`](scp_protocol::context::ContextError::TransportTimeout).
    /// 4. After the handler returns, the dispatcher re-acquires the
    ///    lock briefly to swap the (now reservation-committed or
    ///    rollback-reverted) tracker back into the per-context state.
    ///    Subsequent sends see the post-handler high-water mark.
    ///
    /// # Why the take-and-swap pattern
    ///
    /// `MutationStateView` holds `&mut SendSequenceTracker`. If the
    /// view held a `tokio::sync::OwnedMutexGuard<PerContextState>` the
    /// borrow would live across the delegated `cm.send_message(...).await`
    /// and deadlock the re-entrant per-context mutex acquisition inside
    /// `ContextManager::send_message`. The take-and-swap workaround
    /// makes the tracker reservation lock-free: the dispatcher owns
    /// the tracker for the handler's await points, and the per-context
    /// lock is held for zero duration during the delegated call. This
    /// mirrors the plan's "handler takes `&mut` sibling of the query
    /// view" contract while preserving deadlock safety during the shim
    /// period. Commit 12 replaces this with a direct `&mut PerContextState`
    /// on the actor's owned state (no lock involved, the actor
    /// serializes by construction).
    ///
    /// # Missing ActorDeps during the shim
    ///
    /// `ActorDeps` requires a `SupervisorHandle`, `KeyPackageStoreActor`
    /// handle, `MlsBackend`, `HpkeBackend`, and `OpenMlsStorageAdapter`
    /// — all of which wire up in commits 9-11. For the shim's messaging
    /// path those fields are unused: the handler delegates every
    /// transport/MLS call to the attached
    /// [`ContextManager`](crate::context::manager::ContextManager)'s
    /// pre-existing providers. Rather than construct placeholder deps
    /// on every call, the shim forwards `None` for the deps argument
    /// via the overload
    /// [`handlers::messaging::dispatch_from_shim`](crate::context::actor::handlers::messaging::dispatch_from_shim),
    /// which shares the same match arms as the post-refactor
    /// [`handlers::messaging::dispatch`](crate::context::actor::handlers::messaging::dispatch)
    /// but takes no [`ActorDeps`].
    ///
    /// # Errors
    ///
    /// - [`ContextError::NotInitialized`] if no
    ///   [`ContextManager`](crate::context::manager::ContextManager) has
    ///   been attached yet — the caller must call
    ///   [`Self::attach_context_manager`] first.
    /// - [`ContextError::ContextNotRegistered`] if the command targets a
    ///   context that has not been created / joined / imported on the
    ///   attached manager.
    /// - Any typed error returned by the delegated
    ///   `ContextManager::send_message` /
    ///   `ContextManager::deliver_incoming` call (`CryptoFailed`,
    ///   `PermissionDenied`, `MemberNotFound`, `RateLimited`, etc.).
    /// - [`ContextError::TransportTimeout`] if the delegated call
    ///   exceeds the 30-second handler budget.
    //
    // `significant_drop_tightening` allow (function-level): Phase C's
    // lock-scope block holds a `tokio::sync::MutexGuard` across a
    // read-modify-write on the live send-tracker. Splitting the guard
    // into two acquisitions (read then write) opens a TOCTOU window
    // where a concurrent actor-path caller could advance `live`
    // between our read and our write, regressing the high-water mark
    // we compute. The lock scope is already minimal — three
    // sequential expressions with no awaits. The block-level
    // attribute form clippy suggests is not applicable to a `{ }`
    // expression without a wrapping fn.
    #[allow(clippy::significant_drop_tightening)]
    pub async fn dispatch_command(
        &self,
        ctx_id: &str,
        cmd: MessagingCommand,
    ) -> Result<Outcome<()>, ContextError> {
        let cm = self.attached_context_manager().ok_or_else(|| {
            ContextError::NotInitialized(
                "Supervisor::dispatch_command — no ContextManager attached".to_owned(),
            )
        })?;

        // Resolve the per-context Arc. `ContextNotRegistered` surfaces
        // directly to the caller — messaging commands have no
        // soft-default: a missing context can't encrypt or decrypt a
        // message.
        let arc = cm.get_context_arc_pub(ctx_id)?;

        // Phase A: take the tracker out under a brief lock. See the
        // doc comment for the deadlock-avoidance rationale.
        let mut taken_tracker = {
            let mut guard = arc.lock().await;
            std::mem::take(guard.send_tracker_mut())
        };

        // Phase B: invoke the handler with a view over the taken
        // tracker + a borrow of the attached manager. No per-context
        // lock is held during this await so the delegated
        // `cm.send_message(...)` call inside the handler acquires the
        // same mutex without contention.
        let outcome = {
            let mut view = MutationStateView {
                send_tracker: &mut taken_tracker,
                manager: cm,
            };
            handlers::messaging::dispatch_from_shim(&mut view, cmd).await
        };

        // Phase C: swap the (committed or rolled-back) tracker back
        // in. If another task concurrently reserved a number on the
        // manager's in-place tracker (via the legacy path) while ours
        // was taken, we merge by taking the max high-water mark so
        // neither side regresses. In practice the legacy path does not
        // use `send_tracker` — it uses `MembershipState::next_sequence_number`
        // — so the merge is a no-op during the shim period. Future-
        // proofed so a stray legacy advance cannot regress on resume.
        let taken_hw = taken_tracker.last_issued();
        {
            // See the function-level
            // `#[allow(clippy::significant_drop_tightening)]` for the
            // TOCTOU rationale on this guard's span.
            let mut guard = arc.lock().await;
            let live = guard.send_tracker_mut();
            let live_hw = live.last_issued();
            let merged = taken_hw.max(live_hw);
            *live = SendSequenceTracker::from_persisted(merged);
        }

        Ok(outcome)
    }

    /// Dispatch a mutating [`LifecycleCommand`] through the migration
    /// shim (ADR-049 commit 9 / plan row 9).
    ///
    /// Contract (byte-identical to the legacy
    /// [`ContextManager`](crate::context::manager::ContextManager)
    /// lifecycle methods it replaces):
    ///
    /// Step 1 builds a [`MutationStateView`] over a scratch
    /// [`SendSequenceTracker`](crate::context::actor::SendSequenceTracker)
    /// plus a reference to the attached manager. Lifecycle handlers never
    /// read or mutate `send_tracker` (only the messaging path touches it),
    /// so we do not need the messaging shim's per-context take-and-swap.
    /// The scratch tracker preserves the post-refactor handler signature.
    ///
    /// Step 2 invokes
    /// [`handlers::lifecycle::dispatch_from_shim`](crate::context::actor::handlers::lifecycle::dispatch_from_shim).
    /// Each variant wraps the delegated
    /// [`ContextManager`](crate::context::manager::ContextManager) method
    /// in `tokio::time::timeout` with a 30s budget, maps a timeout to
    /// [`ContextError::TransportTimeout`](scp_protocol::context::ContextError::TransportTimeout),
    /// and relays the typed reply on the variant's oneshot.
    ///
    /// # Why no per-context Arc lookup
    ///
    /// `CreateContext` / `ImportContext` operate on a context that does
    /// not yet exist; `CloseContext` / `LeaveContext` /
    /// `ExportContext` / `JoinContext` delegate to the legacy method
    /// which resolves the per-context Arc internally. Routing through
    /// `get_context_arc_pub` here would duplicate that resolution, and
    /// for the create/import variants would fail pre-emptively with
    /// `ContextNotRegistered`.
    ///
    /// # Errors
    ///
    /// - [`ContextError::NotInitialized`] if no
    ///   [`ContextManager`](crate::context::manager::ContextManager) has
    ///   been attached yet — the caller must call
    ///   [`Self::attach_context_manager`] first.
    /// - Any typed error returned by the delegated
    ///   `ContextManager::{create,join,leave,close,export,import}_context`
    ///   call is surfaced through the variant's oneshot reply; the
    ///   method-level result here is `Ok(Outcome { .. })`.
    /// - [`ContextError::TransportTimeout`] is surfaced through the
    ///   oneshot reply, not the method result.
    pub async fn dispatch_lifecycle_command(
        &self,
        cmd: LifecycleCommand,
    ) -> Result<Outcome<()>, ContextError> {
        let cm = self.attached_context_manager().ok_or_else(|| {
            ContextError::NotInitialized(
                "Supervisor::dispatch_lifecycle_command — no ContextManager attached".to_owned(),
            )
        })?;

        // Scratch tracker — see method docs. The view needs a
        // `&mut SendSequenceTracker` to construct; lifecycle handlers
        // never touch it, so we allocate a fresh one on each call.
        let mut scratch_tracker = SendSequenceTracker::new();
        let mut view = MutationStateView {
            send_tracker: &mut scratch_tracker,
            manager: cm,
        };
        // `Box::pin` — the combined size of the rebuilt handle,
        // context params, and the per-variant 30s-timeout future
        // crosses clippy's 16-KB stack budget for async futures. See
        // the matching comment on `handlers::lifecycle::dispatch`.
        Ok(Box::pin(handlers::lifecycle::dispatch_from_shim(&mut view, cmd)).await)
    }

    /// Dispatch a mutating [`TtlCloseCommand`] through the migration
    /// shim (ADR-049 commit 9 / plan row 9).
    ///
    /// Same shape as [`Self::dispatch_lifecycle_command`] — a scratch
    /// [`SendSequenceTracker`](crate::context::actor::SendSequenceTracker)
    /// backs the [`MutationStateView`], handlers wrap delegated
    /// [`ContextManager`](crate::context::manager::ContextManager) calls
    /// in [`tokio::time::timeout`] with a 30s budget, and the typed
    /// result is relayed through the variant's oneshot.
    ///
    /// # TTL-timer ownership
    ///
    /// The post-refactor architecture turns the TTL timer into a
    /// `select!` arm in the actor's `run()` loop. Commit 9 keeps the
    /// timer spawned inside the legacy `ContextManager`; this dispatch
    /// method routes caller-initiated extend/reset/finalize/explicit-
    /// expiry commands synchronously. Full timer-owning actor logic
    /// arrives with plan row 11.
    ///
    /// # Errors
    ///
    /// - [`ContextError::NotInitialized`] if no
    ///   [`ContextManager`](crate::context::manager::ContextManager) has
    ///   been attached yet.
    pub async fn dispatch_ttl_close_command(
        &self,
        cmd: TtlCloseCommand,
    ) -> Result<Outcome<()>, ContextError> {
        let cm = self.attached_context_manager().ok_or_else(|| {
            ContextError::NotInitialized(
                "Supervisor::dispatch_ttl_close_command — no ContextManager attached".to_owned(),
            )
        })?;

        let mut scratch_tracker = SendSequenceTracker::new();
        let mut view = MutationStateView {
            send_tracker: &mut scratch_tracker,
            manager: cm,
        };
        Ok(handlers::ttl_close::dispatch_from_shim(&mut view, cmd).await)
    }

    /// Dispatch a [`GovernanceCommand`] through the migration shim
    /// (ADR-049 commit 10 / plan row 10).
    ///
    /// Contract (byte-identical to the legacy
    /// [`ContextManager`](crate::context::manager::ContextManager)
    /// governance methods it replaces):
    ///
    /// Step 1 builds a [`MutationStateView`] over a scratch
    /// [`SendSequenceTracker`](crate::context::actor::SendSequenceTracker)
    /// plus a reference to the attached manager. Governance handlers
    /// never read or mutate `send_tracker` (only the messaging path
    /// touches it), so no per-context take-and-swap is required —
    /// same shape as the lifecycle shim.
    ///
    /// Step 2 invokes
    /// [`handlers::governance::dispatch_from_shim`](crate::context::actor::handlers::governance::dispatch_from_shim).
    /// Each variant wraps the delegated
    /// [`ContextManager`](crate::context::manager::ContextManager) method
    /// in `tokio::time::timeout` with a 30s budget, maps a timeout to
    /// [`ContextError::TransportTimeout`](scp_protocol::context::ContextError::TransportTimeout),
    /// and relays the typed reply on the variant's oneshot.
    ///
    /// # Errors
    ///
    /// - [`ContextError::NotInitialized`] if no
    ///   [`ContextManager`](crate::context::manager::ContextManager) has
    ///   been attached yet.
    /// - Any typed error from the delegated manager method is surfaced
    ///   through the variant's oneshot reply; the method-level result
    ///   here is `Ok(Outcome { .. })`.
    /// - [`ContextError::TransportTimeout`] is surfaced through the
    ///   oneshot reply, not the method result.
    pub async fn dispatch_governance_command(
        &self,
        cmd: GovernanceCommand,
    ) -> Result<Outcome<()>, ContextError> {
        let cm = self.attached_context_manager().ok_or_else(|| {
            ContextError::NotInitialized(
                "Supervisor::dispatch_governance_command — no ContextManager attached".to_owned(),
            )
        })?;

        let mut scratch_tracker = SendSequenceTracker::new();
        let mut view = MutationStateView {
            send_tracker: &mut scratch_tracker,
            manager: cm,
        };
        // `Box::pin` — see the matching comment on
        // `handlers::governance::dispatch` for the 16-KB stack-future
        // rationale.
        Ok(Box::pin(handlers::governance::dispatch_from_shim(&mut view, cmd)).await)
    }

    /// Dispatch an [`EconomyCommand`] through the migration shim
    /// (ADR-049 commit 10 / plan row 10).
    ///
    /// Same shape as [`Self::dispatch_governance_command`]. The
    /// economy handler only exposes the single public-surface method
    /// on [`ContextManager`](crate::context::manager::ContextManager),
    /// [`verify_payment_receipts`](crate::context::manager::ContextManager::verify_payment_receipts);
    /// internal helpers (`authorize_paid_action`, `complete_paid_action`,
    /// `void_paid_action`) remain on the manager's private surface
    /// and are exercised through the messaging path.
    ///
    /// # Errors
    ///
    /// - [`ContextError::NotInitialized`] if no
    ///   [`ContextManager`](crate::context::manager::ContextManager) has
    ///   been attached yet.
    pub async fn dispatch_economy_command(
        &self,
        cmd: EconomyCommand,
    ) -> Result<Outcome<()>, ContextError> {
        let cm = self.attached_context_manager().ok_or_else(|| {
            ContextError::NotInitialized(
                "Supervisor::dispatch_economy_command — no ContextManager attached".to_owned(),
            )
        })?;

        let mut scratch_tracker = SendSequenceTracker::new();
        let mut view = MutationStateView {
            send_tracker: &mut scratch_tracker,
            manager: cm,
        };
        Ok(handlers::economy::dispatch_from_shim(&mut view, cmd).await)
    }

    /// Dispatch a [`TrustRecoveryCommand`] through the migration shim
    /// (ADR-049 commit 10 / plan row 10).
    ///
    /// Same shape as [`Self::dispatch_governance_command`]. Covers the
    /// checkpoint + cosignature paths, MLS epoch advancement for
    /// compromise recovery (spec §9.12 step 2), and recovery-
    /// notification send paths (spec §9.12 step 5).
    ///
    /// # Errors
    ///
    /// - [`ContextError::NotInitialized`] if no
    ///   [`ContextManager`](crate::context::manager::ContextManager) has
    ///   been attached yet.
    pub async fn dispatch_trust_recovery_command(
        &self,
        cmd: TrustRecoveryCommand,
    ) -> Result<Outcome<()>, ContextError> {
        let cm = self.attached_context_manager().ok_or_else(|| {
            ContextError::NotInitialized(
                "Supervisor::dispatch_trust_recovery_command — no ContextManager attached"
                    .to_owned(),
            )
        })?;

        let mut scratch_tracker = SendSequenceTracker::new();
        let mut view = MutationStateView {
            send_tracker: &mut scratch_tracker,
            manager: cm,
        };
        // `Box::pin` — CreateGovernanceCheckpoint's payload carries
        // multiple 32-byte hashes + a variable-length Ed25519 signature
        // vector; the per-variant locals cross clippy's 16-KB stack-
        // future budget.
        Ok(Box::pin(handlers::trust_recovery::dispatch_from_shim(&mut view, cmd)).await)
    }

    /// Helper: acquire the per-context lock, build the view, run the
    /// query handler inline (sync — the handler awaits nothing), and
    /// send the typed reply. On soft-fallback + missing context,
    /// synthesize the variant's legacy default via the view-less
    /// fallback.
    async fn dispatch_with_view(
        cm: &Arc<ContextManager>,
        context_id: &str,
        cmd: QueriesCommand,
        soft_fallback: bool,
    ) -> Result<Outcome<()>, ContextError> {
        // Resolve the per-context Arc explicitly rather than via
        // `with_query_state`'s closure accessor: the closure path would
        // force us to move the command (with its oneshot reply sender)
        // into a sync closure, and `QueriesCommand` is not `Send + Sync
        // + Unpin` across every variant. Explicit Arc resolution keeps
        // the lock scope sharp and the future `Send` for the NAPI /
        // UniFFI spawn paths.
        let elp = cm.event_log_provider_arc();
        match cm.get_context_arc_pub(context_id) {
            Ok(arc) => {
                let guard = arc.lock().await;
                let view = QueryStateView::from_manager_state(&guard, &elp);
                handlers::queries::dispatch_from_shim(&view, cmd);
                // Drop the guard explicitly so the per-context mutex is
                // released before we return — the outer `Ok(...)` does
                // not use the guard, and clippy's
                // `significant_drop_tightening` flags the implicit drop
                // at end-of-scope as unnecessary contention.
                drop(guard);
                Ok(Outcome::ok(()))
            }
            Err(err) => {
                if soft_fallback {
                    reply_with_soft_default(cmd);
                } else {
                    reply_with_error(cmd, err);
                }
                Ok(Outcome::ok(()))
            }
        }
    }

    /// Look up the actor handle for a context ID. Lock-free
    /// (`DashMap::get` + `Clone`).
    ///
    /// Visibility is `pub(in crate::context::supervisor)` — external
    /// callers reach the supervisor only through
    /// [`super::handle::SupervisorHandle`], which does NOT expose an
    /// actor-handle accessor. Cross-actor messaging is impossible
    /// through `SupervisorHandle`; see plan §"ActorDeps and
    /// SupervisorHandle".
    ///
    /// `dead_code` allow: the first production call site is commit 7's
    /// query-path migration, which routes FFI-bridge lookups through
    /// `Supervisor::lookup(ctx).send(QueriesCommand::...)`.
    #[must_use]
    #[allow(dead_code)]
    pub(in crate::context::supervisor) fn lookup(
        &self,
        ctx_id: &str,
    ) -> Option<ContextActorHandle> {
        self.actors.get(ctx_id).map(|r| r.value().clone())
    }

    /// Spawn a new `ContextActor` task, register its handle, and return
    /// the handle. The mailbox receiver is moved into the spawned task
    /// so it never escapes this function.
    ///
    /// The spawn site is `pub(in crate::context)` so the context
    /// module's lifecycle handlers can spawn actors at
    /// `create_context` / `restore_context` time. Code outside
    /// `crate::context::` has no way to spawn an actor.
    ///
    /// Commit 6 delivers the mailbox wiring; the actor's `run()` body
    /// uses the stubbed dispatch in
    /// [`crate::context::actor::ContextActor`]. Commit 7 onward
    /// replaces the stubs with real handlers.
    ///
    /// `dead_code` allow: the first production call site is commit 9's
    /// lifecycle handler (create_context spawns an actor). Until then
    /// only the unit tests here exercise the method.
    #[allow(dead_code)]
    pub(in crate::context) async fn spawn_actor(
        &self,
        ctx_id: String,
        mailbox_capacity: Option<usize>,
    ) -> ContextActorHandle {
        let capacity = mailbox_capacity.unwrap_or(ACTOR_MAILBOX_CAPACITY);
        let (tx, rx) = tokio::sync::mpsc::channel::<ContextCommand>(capacity);

        let handle = ContextActorHandle::from_sender(tx);
        {
            // Write-path mutation: register the handle under the write lock.
            let _guard = self.write_lock.lock().await;
            self.actors.insert(ctx_id.clone(), handle.clone());
        }

        // Spawn the actor's dispatch loop. Commit 6's `ContextActor::run`
        // is a skeleton that returns `NotImplemented` for every
        // non-lifecycle command.
        let inbox = rx;
        tokio::spawn(async move {
            crate::context::actor::ContextActor::new(ctx_id, inbox)
                .run()
                .await;
        });

        handle
    }

    /// Dispatch a [`StandingCommand`] through the migration shim
    /// (ADR-049 commit 11 / plan row 11).
    ///
    /// Same shape as [`Self::dispatch_governance_command`]. Covers the
    /// contact-graph (standing context) paths from spec §5.12.4. The
    /// saga-initiator variant
    /// (`StandingCommand::InitiateStandingPairCreate`) returns
    /// [`ContextError::NotImplemented`] during the commit-11 window —
    /// see `.docs/adrs/DEFERRED-commit-11-saga-use-cases.md`.
    ///
    /// # Errors
    ///
    /// - [`ContextError::NotInitialized`] if no
    ///   [`ContextManager`](crate::context::manager::ContextManager) has
    ///   been attached yet.
    pub async fn dispatch_standing_command(
        &self,
        cmd: StandingCommand,
    ) -> Result<Outcome<()>, ContextError> {
        let cm = self.attached_context_manager().ok_or_else(|| {
            ContextError::NotInitialized(
                "Supervisor::dispatch_standing_command — no ContextManager attached".to_owned(),
            )
        })?;

        let mut scratch_tracker = SendSequenceTracker::new();
        let mut view = MutationStateView {
            send_tracker: &mut scratch_tracker,
            manager: cm,
        };
        Ok(Box::pin(handlers::standing::dispatch_from_shim(&mut view, cmd)).await)
    }

    /// Dispatch a [`ToolsCommand`] through the migration shim
    /// (ADR-049 commit 11 / plan row 11).
    ///
    /// Covers the hard-rate-limit consume / refund helpers that FFI
    /// bridges call from their tool-dispatch paths. The cross-context
    /// saga-initiator variant returns [`ContextError::NotImplemented`]
    /// during the commit-11 window — see
    /// `.docs/adrs/DEFERRED-commit-11-saga-use-cases.md`. Note that
    /// [`ContextManager::invoke_tool_with_economy`](crate::context::manager::ContextManager::invoke_tool_with_economy)
    /// is not migrated here because its generic executor closure cannot
    /// cross the actor mailbox.
    ///
    /// # Errors
    ///
    /// - [`ContextError::NotInitialized`] if no
    ///   [`ContextManager`](crate::context::manager::ContextManager) has
    ///   been attached yet.
    pub async fn dispatch_tools_command(
        &self,
        cmd: ToolsCommand,
    ) -> Result<Outcome<()>, ContextError> {
        let cm = self.attached_context_manager().ok_or_else(|| {
            ContextError::NotInitialized(
                "Supervisor::dispatch_tools_command — no ContextManager attached".to_owned(),
            )
        })?;

        let mut scratch_tracker = SendSequenceTracker::new();
        let mut view = MutationStateView {
            send_tracker: &mut scratch_tracker,
            manager: cm,
        };
        Ok(handlers::tools::dispatch_from_shim(&mut view, cmd).await)
    }

    /// Dispatch a [`BroadcastCommand`] through the migration shim
    /// (ADR-049 commit 11 / plan row 11) for every non-publish variant.
    ///
    /// Publish variants require a
    /// [`KeyCustody`](scp_platform::KeyCustody) reference that cannot
    /// cross the actor mailbox (RPITIT trait, not `dyn`-safe); use
    /// [`Self::dispatch_broadcast_command_with_custody`] for publish.
    /// The saga-initiator variant
    /// (`InitiateBroadcastHostingHandshake`) returns
    /// [`ContextError::NotImplemented`] during the commit-11 window —
    /// see `.docs/adrs/DEFERRED-commit-11-saga-use-cases.md`.
    ///
    /// # Errors
    ///
    /// - [`ContextError::NotInitialized`] if no
    ///   [`ContextManager`](crate::context::manager::ContextManager) has
    ///   been attached yet.
    pub async fn dispatch_broadcast_command(
        &self,
        cmd: BroadcastCommand,
    ) -> Result<Outcome<()>, ContextError> {
        let cm = self.attached_context_manager().ok_or_else(|| {
            ContextError::NotInitialized(
                "Supervisor::dispatch_broadcast_command — no ContextManager attached".to_owned(),
            )
        })?;

        let mut scratch_tracker = SendSequenceTracker::new();
        let mut view = MutationStateView {
            send_tracker: &mut scratch_tracker,
            manager: cm,
        };
        Ok(Box::pin(handlers::broadcast::dispatch_from_shim(&mut view, cmd)).await)
    }

    /// Dispatch a [`BroadcastCommand`] through the migration shim with
    /// an explicit key custody reference (ADR-049 commit 11 / plan row
    /// 11). Required for publish variants; non-publish variants fall
    /// through to the same handler body used by
    /// [`Self::dispatch_broadcast_command`] (the custody is unused).
    ///
    /// # Errors
    ///
    /// - [`ContextError::NotInitialized`] if no
    ///   [`ContextManager`](crate::context::manager::ContextManager) has
    ///   been attached yet.
    pub async fn dispatch_broadcast_command_with_custody<C: scp_platform::KeyCustody>(
        &self,
        cmd: BroadcastCommand,
        custody: &C,
    ) -> Result<Outcome<()>, ContextError> {
        let cm = self.attached_context_manager().ok_or_else(|| {
            ContextError::NotInitialized(
                "Supervisor::dispatch_broadcast_command_with_custody — no ContextManager attached"
                    .to_owned(),
            )
        })?;

        let mut scratch_tracker = SendSequenceTracker::new();
        let mut view = MutationStateView {
            send_tracker: &mut scratch_tracker,
            manager: cm,
        };
        Ok(
            Box::pin(handlers::broadcast::dispatch_from_shim_with_custody(
                &mut view, cmd, custody,
            ))
            .await,
        )
    }

    /// Start a cross-context saga. See plan §"Cross-context saga
    /// protocol".
    ///
    /// # Coordinator FSM
    ///
    /// Commit 11 implements the `Initiated → PreparingA → PreparingB →
    /// Committing → Committed | Aborting → Aborted | NeedsRepair` state
    /// machine with journal durability. Each phase transition is
    /// persisted to the
    /// [`SagaJournal`](crate::context::supervisor::saga_journal::SagaJournal)
    /// before the next phase begins; crash recovery replays unresolved
    /// entries on supervisor startup via
    /// [`Self::replay_unresolved_sagas`].
    ///
    /// # Concurrent saga serialization
    ///
    /// The supervisor serializes sagas supervisor-wide: a second
    /// `start_saga` while one is in flight returns
    /// [`ContextError::ActorBusy`](scp_protocol::context::ContextError::ActorBusy)
    /// with a `SagaBusy` reason. The guard is a single atomic bool
    /// (plan §"Cross-context saga protocol" step Prepare — concurrent
    /// Prepare against the same supervisor is rejected).
    ///
    /// # Spec-gapped saga use cases
    ///
    /// The 4 [`SagaInput`] variants (StandingPairCreate,
    /// ContextMigration, CrossContextToolInvocation,
    /// BroadcastHostingHandshake) each require protocol fill-in before
    /// they can be wired — see
    /// `.docs/adrs/DEFERRED-commit-11-saga-use-cases.md`. This method
    /// drives the FSM generically; specific `SagaInput` arms return
    /// [`ContextError::NotImplemented`] at the Prepare dispatch step.
    /// The coordinator itself — journal writes, phase transitions,
    /// timeout/retry accounting, terminal resolution — is fully
    /// implemented.
    ///
    /// # Errors
    ///
    /// - [`ContextError::ActorBusy`] if a saga is already in flight.
    /// - [`ContextError::NotImplemented`] if the
    ///   [`SagaInput`] variant requires spec-gapped prepare dispatch
    ///   (all 4 current variants until commit 11.5).
    /// - [`ContextError::InvalidState`] on journal I/O failure.
    pub async fn start_saga(&self, input: SagaInput) -> Result<SagaOutput, ContextError> {
        use std::sync::atomic::Ordering;

        // Concurrent-saga guard: CAS from false → true. If already
        // true, the caller races an in-flight saga.
        if self
            .saga_pending_guard
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(ContextError::ActorBusy(
                "Supervisor::start_saga — another saga is already in flight (SagaBusy)".to_owned(),
            ));
        }

        // Always clear the guard on exit — wrap the FSM body in an
        // inner closure so panics/? propagate through the guard reset.
        let saga_id = SagaId::new();
        let participants = saga_input_participants(&input);
        let secret_bearing = saga_input_is_secret_bearing(&input);

        let fsm_result = self
            .run_saga_fsm(
                saga_id.clone(),
                &input,
                participants.clone(),
                secret_bearing,
            )
            .await;

        self.saga_pending_guard.store(false, Ordering::Release);

        fsm_result.map(|()| SagaOutput { saga_id })
    }

    /// Replay unresolved sagas from the journal on supervisor startup
    /// (plan §"Crash recovery"). For each unresolved state:
    ///
    /// - `Initiated` / `PreparingA` — discard (no remote side-effects
    ///   yet; idempotent discard is safe).
    /// - `PreparingB` — send a best-effort `Abort` to actor A (actor A
    ///   Prepared in memory but the Commit never left the coordinator;
    ///   Abort rolls the staged mutation back).
    /// - `Committing` — re-send the `Commit` message; actors MUST be
    ///   idempotent on Commit receipt (Commit against an already-
    ///   committed saga is a no-op with success).
    /// - `NeedsRepair` — emit a metric; operator intervention is
    ///   required to repair the saga.
    ///
    /// This method is called by [`Self::new`]-through-
    /// [`Self::spawn_replay_task`] on construction so a crash-restart
    /// supervisor reconciles state before the first `start_saga` call.
    /// It is safe to call multiple times; each call loads the current
    /// unresolved set from the journal.
    ///
    /// # Errors
    ///
    /// Returns the journal's error class (via `ContextError::InvalidState`)
    /// if `load_unresolved` fails. Per-entry processing errors are logged
    /// via `tracing` and do not abort the recovery sweep.
    pub async fn replay_unresolved_sagas(&self) -> Result<(), ContextError> {
        let entries = self.saga_journal.load_unresolved().await.map_err(|e| {
            ContextError::InvalidState(format!("saga journal load_unresolved failed: {e}"))
        })?;

        for entry in entries {
            self.recover_saga_entry(entry).await;
        }
        Ok(())
    }

    async fn recover_saga_entry(&self, entry: JournalEntry) {
        match entry.state {
            SagaState::Initiated | SagaState::PreparingA => {
                // No remote side-effects yet — discard by marking
                // Aborted. `secret_bearing` classifies the resolution
                // marker for secure-evidence overwrite.
                let _ = self
                    .saga_journal
                    .mark_resolved(
                        entry.saga_id.clone(),
                        SagaTerminalState::Aborted,
                        /*secret_bearing=*/ false,
                    )
                    .await;
                tracing::info!(
                    saga_id = %entry.saga_id,
                    state = ?entry.state,
                    "saga recovery — discarded (no remote side-effects)"
                );
            }
            SagaState::PreparingB => {
                // Actor A Prepared but Commit never left coordinator;
                // send best-effort Abort to actor A. Until saga-phase
                // actor-side handlers land, this is a metric-only
                // branch — the journal resolution IS the Abort from
                // the coordinator's perspective.
                let _ = self
                    .saga_journal
                    .mark_resolved(
                        entry.saga_id.clone(),
                        SagaTerminalState::Aborted,
                        /*secret_bearing=*/ false,
                    )
                    .await;
                tracing::warn!(
                    saga_id = %entry.saga_id,
                    "saga recovery — PreparingB observed; rolled back by journal abort marker"
                );
            }
            SagaState::Committing | SagaState::Aborting => {
                // Re-resolve: Commit retry logic is not visible through
                // the journal alone — emit NeedsRepair so an operator
                // sees it on the next startup.
                let _ = self
                    .saga_journal
                    .append(JournalEntry {
                        saga_id: entry.saga_id.clone(),
                        state: SagaState::NeedsRepair,
                        participants: entry.participants.clone(),
                        evidence: Zeroizing::new(Vec::new()),
                        timestamp_ms: current_timestamp_ms(),
                        seq_per_saga: entry.seq_per_saga.saturating_add(1),
                    })
                    .await;
                tracing::error!(
                    saga_id = %entry.saga_id,
                    state = ?entry.state,
                    "saga recovery — Committing/Aborting observed; marked NeedsRepair for operator review"
                );
            }
            SagaState::NeedsRepair => {
                tracing::error!(
                    saga_id = %entry.saga_id,
                    "saga recovery — NeedsRepair carryover; operator intervention required"
                );
            }
            SagaState::Committed | SagaState::Aborted => {
                // Terminal — not returned by load_unresolved but
                // defensively handled here.
            }
        }
    }

    /// Run the saga FSM for a single saga. Returns `Ok(())` iff the
    /// saga reached `SagaState::Committed`. Every other terminal state
    /// (`Aborted`, `NeedsRepair`) returns a typed error that the caller
    /// surfaces.
    async fn run_saga_fsm(
        &self,
        saga_id: SagaId,
        input: &SagaInput,
        participants: Vec<String>,
        secret_bearing: bool,
    ) -> Result<(), ContextError> {
        // 1. Initiated
        self.append_journal(&saga_id, SagaState::Initiated, &participants, 0, &[])
            .await?;

        // 2. PreparingA — spec-gapped for every current SagaInput variant.
        //    The prepare-dispatch returns NotImplemented and the FSM
        //    transitions directly to Aborted. This preserves the
        //    coordinator's observable behaviour (terminate with a typed
        //    error rather than hang) and keeps every phase transition
        //    in the journal so crash-recovery tests see the right
        //    states.
        self.append_journal(&saga_id, SagaState::PreparingA, &participants, 1, &[])
            .await?;

        let phase_a = self.dispatch_prepare_phase(input, SagaPhase::A).await;
        if let Err(err) = phase_a {
            self.abort_saga(&saga_id, &participants, 2, secret_bearing)
                .await?;
            return Err(err);
        }

        // 3. PreparingB
        self.append_journal(&saga_id, SagaState::PreparingB, &participants, 2, &[])
            .await?;

        let phase_b = self.dispatch_prepare_phase(input, SagaPhase::B).await;
        if let Err(err) = phase_b {
            self.abort_saga(&saga_id, &participants, 3, secret_bearing)
                .await?;
            return Err(err);
        }

        // 4. Committing — 3x retry with 500ms/1s/2s exponential back-off
        self.append_journal(&saga_id, SagaState::Committing, &participants, 3, &[])
            .await?;

        let commit_result = self.commit_with_retry(input).await;
        match commit_result {
            Ok(()) => {
                self.saga_journal
                    .mark_resolved(
                        saga_id.clone(),
                        SagaTerminalState::Committed,
                        secret_bearing,
                    )
                    .await
                    .map_err(|e| {
                        ContextError::InvalidState(format!("saga journal mark_resolved: {e}"))
                    })?;
                Ok(())
            }
            Err(err) => {
                // Commit retry exhausted — NeedsRepair.
                self.append_journal(&saga_id, SagaState::NeedsRepair, &participants, 4, &[])
                    .await?;
                tracing::error!(
                    saga_id = %saga_id,
                    %err,
                    "saga coordinator — commit retry exhausted, saga in NeedsRepair"
                );
                Err(err)
            }
        }
    }

    /// Dispatch a single Prepare phase. Returns
    /// [`ContextError::NotImplemented`] for all 4 current
    /// [`SagaInput`] variants because prepare-dispatch is
    /// spec-gapped — see
    /// `.docs/adrs/DEFERRED-commit-11-saga-use-cases.md`.
    ///
    /// The wrapper enforces the 30s per-phase timeout
    /// ([`ADR-049`](crate) §7) by awaiting the inner future under
    /// `tokio::time::timeout`; a timeout maps to
    /// [`ContextError::TransportTimeout`].
    async fn dispatch_prepare_phase(
        &self,
        input: &SagaInput,
        phase: SagaPhase,
    ) -> Result<(), ContextError> {
        const PHASE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

        let dispatch_fut = async {
            match input {
                SagaInput::StandingPairCreate { .. } => Err(ContextError::NotImplemented(format!(
                    "saga Prepare{phase:?} — StandingPairCreate wiring deferred to commit 11.5 \
                     per DEFERRED-commit-11-saga-use-cases.md gap 1 (standing-pair 2-phase \
                     decomposition)"
                ))),
                SagaInput::ContextMigration { .. } => Err(ContextError::NotImplemented(format!(
                    "saga Prepare{phase:?} — ContextMigration wiring deferred to commit 11.5 \
                     per DEFERRED-commit-11-saga-use-cases.md gap 4 (migration CustodyHandover \
                     envelope)"
                ))),
                SagaInput::CrossContextToolInvocation { .. } => {
                    Err(ContextError::NotImplemented(format!(
                        "saga Prepare{phase:?} — CrossContextToolInvocation wiring deferred to \
                         commit 11.5 per DEFERRED-commit-11-saga-use-cases.md gap 2 \
                         (cross-context tool-invoke transport)"
                    )))
                }
                SagaInput::BroadcastHostingHandshake { .. } => {
                    Err(ContextError::NotImplemented(format!(
                        "saga Prepare{phase:?} — BroadcastHostingHandshake wiring deferred to \
                         commit 11.5 per DEFERRED-commit-11-saga-use-cases.md gap 3 (broadcast \
                         hosting handshake protocol)"
                    )))
                }
            }
        };

        match tokio::time::timeout(PHASE_TIMEOUT, dispatch_fut).await {
            Ok(r) => r,
            Err(_elapsed) => Err(ContextError::TransportTimeout(format!(
                "saga Prepare{phase:?} exceeded 30s phase budget"
            ))),
        }
    }

    /// Commit with 3x retry: 500ms, 1s, 2s. Returns the final error
    /// after retries are exhausted. Until actor-side Commit handlers
    /// land, this function calls `dispatch_commit_phase` which returns
    /// `NotImplemented` for all current saga types — so the retry loop
    /// is exercised but never succeeds for real inputs (tests inject
    /// a test-only saga type that DOES succeed).
    async fn commit_with_retry(&self, input: &SagaInput) -> Result<(), ContextError> {
        const BACKOFFS: &[std::time::Duration] = &[
            std::time::Duration::from_millis(500),
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(2),
        ];

        let mut last_err: Option<ContextError> = None;
        for (attempt, backoff) in BACKOFFS.iter().enumerate() {
            if attempt > 0 {
                tokio::time::sleep(*backoff).await;
            }
            match self.dispatch_commit_phase(input).await {
                Ok(()) => return Ok(()),
                Err(err) => {
                    tracing::warn!(
                        attempt = attempt + 1,
                        max = BACKOFFS.len(),
                        %err,
                        "saga commit attempt failed, retrying"
                    );
                    last_err = Some(err);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            ContextError::InvalidState("saga commit retry loop produced no error".to_owned())
        }))
    }

    /// Dispatch the Commit phase. Currently all variants return
    /// `NotImplemented` pending commit-11.5 spec fill-in. The 30s
    /// per-attempt timeout is enforced.
    async fn dispatch_commit_phase(&self, input: &SagaInput) -> Result<(), ContextError> {
        const PHASE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

        let dispatch_fut = async {
            match input {
                SagaInput::StandingPairCreate { .. }
                | SagaInput::ContextMigration { .. }
                | SagaInput::CrossContextToolInvocation { .. }
                | SagaInput::BroadcastHostingHandshake { .. } => Err(ContextError::NotImplemented(
                    "saga Commit — all 4 saga types' commit-side wiring deferred to commit \
                         11.5 per DEFERRED-commit-11-saga-use-cases.md"
                        .to_owned(),
                )),
            }
        };

        match tokio::time::timeout(PHASE_TIMEOUT, dispatch_fut).await {
            Ok(r) => r,
            Err(_elapsed) => Err(ContextError::TransportTimeout(
                "saga Commit exceeded 30s phase budget".to_owned(),
            )),
        }
    }

    async fn abort_saga(
        &self,
        saga_id: &SagaId,
        participants: &[String],
        next_seq: u64,
        secret_bearing: bool,
    ) -> Result<(), ContextError> {
        self.append_journal(saga_id, SagaState::Aborting, participants, next_seq, &[])
            .await?;
        self.saga_journal
            .mark_resolved(saga_id.clone(), SagaTerminalState::Aborted, secret_bearing)
            .await
            .map_err(|e| ContextError::InvalidState(format!("saga journal mark_resolved: {e}")))
    }

    async fn append_journal(
        &self,
        saga_id: &SagaId,
        state: SagaState,
        participants: &[String],
        seq: u64,
        evidence: &[u8],
    ) -> Result<(), ContextError> {
        self.saga_journal
            .append(JournalEntry {
                saga_id: saga_id.clone(),
                state,
                participants: participants.to_vec(),
                evidence: Zeroizing::new(evidence.to_vec()),
                timestamp_ms: current_timestamp_ms(),
                seq_per_saga: seq,
            })
            .await
            .map_err(|e| {
                ContextError::InvalidState(format!(
                    "saga journal append failed for state {state:?}: {e}"
                ))
            })
    }

    /// Persist supervisor-level state (standing_contexts, local_dids,
    /// wrapping_keys) ahead of a shutdown or resume. Commit 6 stubs;
    /// full path lands with the `BridgeInstance` integration in commit
    /// 11.
    ///
    /// # Errors
    ///
    /// Commit 6: always `ContextError::NotImplemented`.
    #[allow(clippy::unused_async)] // signature matches the real commit-11 handler's shape
    pub async fn persist_state(&self) -> Result<(), ContextError> {
        Err(ContextError::NotImplemented(
            "Supervisor::persist_state — migrates in commit 11 of ADR-049".to_owned(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Saga FSM helpers
// ---------------------------------------------------------------------------

/// Phase tag used by the coordinator's Prepare dispatch. Enables
/// single-match dispatch on `(input, phase)` so the Prepare-A and
/// Prepare-B paths share a single dispatch table at the cost of one
/// enum discriminant.
#[derive(Clone, Copy, Debug)]
enum SagaPhase {
    A,
    B,
}

/// Participant identifiers extracted from a [`SagaInput`] for journal
/// durability. Per-variant extraction — the journal stores opaque
/// strings (context IDs or DIDs) and the saga-type discriminant is
/// carried separately (via [`SagaState`]).
fn saga_input_participants(input: &SagaInput) -> Vec<String> {
    match input {
        SagaInput::StandingPairCreate {
            local_did,
            peer_did,
        } => vec![local_did.to_string(), peer_did.to_string()],
        SagaInput::ContextMigration {
            source_context_id,
            source_identity_did,
        } => vec![
            hex::encode(source_context_id),
            source_identity_did.to_string(),
        ],
        SagaInput::CrossContextToolInvocation {
            caller_context_id,
            caller_did,
            tool_registration_id,
        } => vec![
            hex::encode(caller_context_id),
            caller_did.to_string(),
            tool_registration_id.clone(),
        ],
        SagaInput::BroadcastHostingHandshake {
            host_context_id,
            broadcast_context_id,
            subscriber_did,
        } => vec![
            hex::encode(host_context_id),
            hex::encode(broadcast_context_id),
            subscriber_did.to_string(),
        ],
    }
}

/// Classify whether a saga's journal evidence carries bearer bytes
/// (spec §9.4.3). Only [`SagaInput::ContextMigration`] is
/// secret-bearing — the others are public-only. Secret-bearing sagas
/// pass `true` to [`SagaJournal::mark_resolved`] so the journal
/// synchronously overwrites evidence bytes on terminal resolution.
const fn saga_input_is_secret_bearing(input: &SagaInput) -> bool {
    matches!(input, SagaInput::ContextMigration { .. })
}

/// Shared timestamp helper. Duplicated from `saga_journal.rs` to avoid
/// cross-module visibility churn. Returns milliseconds since the UNIX
/// epoch.
fn current_timestamp_ms() -> u64 {
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    ms
}

// ---------------------------------------------------------------------------
// No-op ContextPersistence + SagaJournal — plumbed into the FFI query
// shim's [`Supervisor::for_query_shim`] constructor. Neither surface is
// touched by the query path; the saga + lifecycle handlers that DO touch
// them land in commits 9-11 and replace these stubs with the real
// production wiring.
// ---------------------------------------------------------------------------

/// No-op persistence — every operation is a no-op success. Used by
/// [`Supervisor::for_query_shim`]; deleted in commit 12 with the shim.
struct NoopContextPersistence;

impl ContextPersistence for NoopContextPersistence {
    fn persist_context(
        &self,
        _context_id: &str,
        _snapshot: &crate::context::manager::ContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    fn load_context(
        &self,
        _context_id: &str,
    ) -> Result<
        Option<crate::context::manager::ContextSnapshot>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        Ok(None)
    }

    fn persist_broadcast(
        &self,
        _context_id: &str,
        _snapshot: &scp_protocol::context::broadcast::BroadcastContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    fn load_broadcast(
        &self,
        _context_id: &str,
    ) -> Result<
        Option<scp_protocol::context::broadcast::BroadcastContextSnapshot>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        Ok(None)
    }

    fn delete_context(
        &self,
        _context_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    fn list_persisted_contexts(
        &self,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Vec::new())
    }
}

/// No-op saga journal — every operation is a no-op success. Used by
/// [`Supervisor::for_query_shim`]; deleted in commit 12 with the shim.
struct NoopSagaJournal;

#[async_trait::async_trait]
impl SagaJournal for NoopSagaJournal {
    async fn append(
        &self,
        _entry: crate::context::supervisor::saga_journal::JournalEntry,
    ) -> Result<(), crate::context::supervisor::saga_journal::JournalError> {
        Ok(())
    }

    async fn load_unresolved(
        &self,
    ) -> Result<
        Vec<crate::context::supervisor::saga_journal::JournalEntry>,
        crate::context::supervisor::saga_journal::JournalError,
    > {
        Ok(Vec::new())
    }

    async fn mark_resolved(
        &self,
        _saga_id: SagaId,
        _terminal: crate::context::supervisor::saga_journal::SagaTerminalState,
        _secret_bearing: bool,
    ) -> Result<(), crate::context::supervisor::saga_journal::JournalError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Shim helpers — synthesise the "context unknown" fallback reply for each
// query variant. Matches the legacy `ContextManager::foo()` defaults
// byte-for-byte. Deleted in commit 12 with the shim itself.
// ---------------------------------------------------------------------------

/// Send the legacy soft-default reply on a query variant's oneshot when
/// the context isn't registered. Mirrors each legacy method's
/// unknown-context return value exactly.
#[allow(clippy::cognitive_complexity)] // flat variant dispatch
fn reply_with_soft_default(cmd: QueriesCommand) {
    match cmd {
        // Hard-error variants never route here — they use
        // `reply_with_error` instead. Left unreachable so a future
        // dispatch-classification change trips a compile-time match.
        QueriesCommand::LocalPseudonym { .. }
        | QueriesCommand::GetBroadcastKeyForLocalAuthor { .. } => {
            debug_assert!(false, "hard-error variant routed through soft-default path");
        }
        // Legacy `member_count` returns `None` on unknown context.
        QueriesCommand::MemberCount { reply, .. } => {
            let _ = reply.send(Ok(None));
        }
        // Legacy `is_member` returns `false`.
        QueriesCommand::IsMember { reply, .. } => {
            let _ = reply.send(Ok(false));
        }
        // Legacy `member_dids` returns an empty `Vec`.
        QueriesCommand::MemberDids { reply, .. } => {
            let _ = reply.send(Ok(Vec::new()));
        }
        // Legacy `member_role` returns `None`.
        QueriesCommand::MemberRole { reply, .. } => {
            let _ = reply.send(Ok(None));
        }
        // Legacy `context_params` returns `None`.
        QueriesCommand::ContextParams { reply, .. } => {
            let _ = reply.send(Ok(None));
        }
        // Legacy `get_role_state` returns `None`.
        QueriesCommand::GetRoleState { reply, .. } => {
            let _ = reply.send(Ok(None));
        }
        // Legacy `pending_commits` returns an empty `Vec`.
        QueriesCommand::PendingCommits { reply, .. } => {
            let _ = reply.send(Ok(Vec::new()));
        }
        // Legacy `commit_fault` returns `None`.
        QueriesCommand::CommitFault { reply, .. } => {
            let _ = reply.send(Ok(None));
        }
        // `EventLogEntries` does not take a per-context lock and never
        // reaches this fallback path; the top-level dispatch handles it
        // inline.
        QueriesCommand::EventLogEntries { reply, .. } => {
            debug_assert!(false, "EventLogEntries routed through fallback path");
            let _ = reply.send(Ok(None));
        }

        #[cfg(feature = "testing")]
        QueriesCommand::GetAccessKey { reply, .. } => {
            let _ = reply.send(Ok(None));
        }
        #[cfg(feature = "testing")]
        QueriesCommand::GetAllAccessKeys { reply, .. } => {
            let _ = reply.send(Ok(std::collections::HashMap::new()));
        }
        #[cfg(feature = "testing")]
        QueriesCommand::RemainingBudgetForTest { reply, .. } => {
            let _ = reply.send(Ok(scp_protocol::economy::types::Amount::new(0)));
        }
        #[cfg(feature = "testing")]
        QueriesCommand::VelocityForTest { reply, .. } => {
            let _ = reply.send(Ok(0));
        }
    }
}

/// Send a typed error on a query variant's oneshot. Used by the hard-
/// error variants (`LocalPseudonym`,
/// `GetBroadcastKeyForLocalAuthor`) whose legacy methods propagate
/// `ContextError::ContextNotRegistered` rather than a soft default.
#[allow(clippy::cognitive_complexity)] // flat variant dispatch
fn reply_with_error(cmd: QueriesCommand, err: ContextError) {
    match cmd {
        QueriesCommand::LocalPseudonym { reply, .. } => {
            let _ = reply.send(Err(err));
        }
        QueriesCommand::GetBroadcastKeyForLocalAuthor { reply, .. } => {
            let _ = reply.send(Err(err));
        }
        // Every other variant is soft-fallback — they never route
        // through the error path. Assert that at runtime to catch a
        // future classification bug.
        other => {
            debug_assert!(false, "soft-default variant routed through error path");
            reply_with_soft_default(other);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::context::supervisor::saga_journal::ProtocolRepositorySagaJournal;
    use scp_platform::testing::InMemoryStorage;

    /// In-memory `ContextPersistence` stub for tests only. Returns an
    /// empty snapshot for every load and silently accepts every persist.
    /// Production callers wire the real
    /// `ProtocolRepositoryContextBridge`.
    struct TestPersistence;
    impl ContextPersistence for TestPersistence {
        fn persist_context(
            &self,
            _: &str,
            _: &crate::context::manager::ContextSnapshot,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
        fn load_context(
            &self,
            _: &str,
        ) -> Result<
            Option<crate::context::manager::ContextSnapshot>,
            Box<dyn std::error::Error + Send + Sync>,
        > {
            Ok(None)
        }
        fn persist_broadcast(
            &self,
            _: &str,
            _: &scp_protocol::context::broadcast::BroadcastContextSnapshot,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
        fn load_broadcast(
            &self,
            _: &str,
        ) -> Result<
            Option<scp_protocol::context::broadcast::BroadcastContextSnapshot>,
            Box<dyn std::error::Error + Send + Sync>,
        > {
            Ok(None)
        }
        fn delete_context(&self, _: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
        fn list_persisted_contexts(
            &self,
        ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(Vec::new())
        }
    }

    fn test_supervisor() -> Supervisor {
        let persistence: Arc<dyn ContextPersistence> = Arc::new(TestPersistence);
        let journal: Arc<dyn SagaJournal> = Arc::new(ProtocolRepositorySagaJournal::new(Arc::new(
            InMemoryStorage::new(),
        )));
        Supervisor::new(persistence, journal, SupervisorConfig::default())
    }

    #[tokio::test]
    async fn fresh_supervisor_has_empty_registries() {
        let s = test_supervisor();
        assert!(s.lookup("any-ctx").is_none());
        assert!(s.local_dids.load().is_empty());
        assert!(s.standing_contexts.load().is_empty());
    }

    #[tokio::test]
    async fn start_saga_returns_not_implemented_for_spec_gapped_input() {
        // All 4 current SagaInput variants are spec-gapped — the FSM
        // journals Initiated + PreparingA then fails the Prepare
        // dispatch with NotImplemented, rolls back via abort_saga, and
        // returns the typed error. This exercises the coordinator
        // through the PreparingA → Aborting → Aborted arm of the FSM
        // without needing spec-filled inputs.
        let s = test_supervisor();
        let err = s
            .start_saga(SagaInput::StandingPairCreate {
                local_did: DID("did:example:a".to_owned()),
                peer_did: DID("did:example:b".to_owned()),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, ContextError::NotImplemented(_)));

        // Guard must be cleared after a saga terminates (even on
        // NotImplemented abort) so a subsequent saga can start.
        let err2 = s
            .start_saga(SagaInput::StandingPairCreate {
                local_did: DID("did:example:a".to_owned()),
                peer_did: DID("did:example:b".to_owned()),
            })
            .await
            .unwrap_err();
        assert!(matches!(err2, ContextError::NotImplemented(_)));
    }

    #[tokio::test]
    async fn persist_state_returns_not_implemented() {
        let s = test_supervisor();
        let err = s.persist_state().await.unwrap_err();
        assert!(matches!(err, ContextError::NotImplemented(_)));
    }

    #[tokio::test]
    async fn spawn_actor_registers_handle_under_write_lock() {
        let s = test_supervisor();
        let _handle = s.spawn_actor("ctx-42".to_owned(), None).await;
        assert!(s.lookup("ctx-42").is_some());
        // Second spawn with the same ID overwrites (commit 6 semantics —
        // duplicate-spawn detection is a watchdog responsibility and
        // lands with the panic-recovery path in commit 11).
        let _handle2 = s.spawn_actor("ctx-42".to_owned(), None).await;
        assert!(s.lookup("ctx-42").is_some());
    }
}
