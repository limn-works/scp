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

use crate::context::actor::commands::{ContextCommand, QueriesCommand};
use crate::context::actor::handle::ContextActorHandle;
use crate::context::actor::handlers;
use crate::context::actor::outcome::Outcome;
use crate::context::actor::query_state_view::QueryStateView;
use crate::context::actor::state::WrappingKeyPair;
use crate::context::manager::{ContextManager, ContextPersistence};
use crate::context::supervisor::key_package_actor::KeyPackageStoreHandle;
use crate::context::supervisor::saga_journal::{SagaId, SagaJournal};

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

    /// Start a cross-context saga. See plan §"Cross-context saga
    /// protocol".
    ///
    /// Commit 6 stubs the method with
    /// [`ContextError::NotImplemented`]; commit 11 implements the full
    /// Initiated → PreparingA → PreparingB → Committing → Committed
    /// FSM with journal durability.
    ///
    /// # Errors
    ///
    /// Commit 6: always `ContextError::NotImplemented`.
    #[allow(clippy::unused_async)] // signature matches the real commit-11 handler's shape
    pub async fn start_saga(&self, _input: SagaInput) -> Result<SagaOutput, ContextError> {
        Err(ContextError::NotImplemented(
            "Supervisor::start_saga — migrates in commit 11 of ADR-049".to_owned(),
        ))
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
    async fn start_saga_returns_not_implemented() {
        let s = test_supervisor();
        let err = s
            .start_saga(SagaInput::StandingPairCreate {
                local_did: DID("did:example:a".to_owned()),
                peer_did: DID("did:example:b".to_owned()),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, ContextError::NotImplemented(_)));
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
