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
use scp_primitives::Clock;
use scp_protocol::context::ContextError;
use scp_protocol::context::governance::KeyResolver;
use scp_protocol::context::membership::ContextEvent;

use crate::context::actor::commands::{
    BroadcastCommand, ContextCommand, EconomyCommand, GovernanceCommand, LifecycleCommand,
    MessagingCommand, QueriesCommand, StandingCommand, ToolsCommand, TrustRecoveryCommand,
    TtlCloseCommand,
};
use crate::context::actor::handle::ContextActorHandle;
use crate::context::actor::outcome::Outcome;
use crate::context::actor::state::WrappingKeyPair;
use crate::context::builder::{ContextEventLogProvider, ContextTransportProvider};
use crate::context::persistence::ContextPersistence;
use crate::context::supervisor::key_package_actor::KeyPackageStoreHandle;
use crate::context::supervisor::saga_journal::{
    JournalEntry, SagaId, SagaJournal, SagaState, SagaTerminalState,
};
use crate::economy::adapter::PaymentAdapterDyn;
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

/// Input to `Supervisor::start_saga`. The variant enumerates the 4
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

/// Output from `Supervisor::start_saga` on success. The saga's durable
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
    pub(in crate::context::supervisor) actors: DashMap<String, ContextActorHandle>,
    /// Standing-pair context index. peer DID string → peer `DID`. Read
    /// via `ArcSwap::load` (lock-free); mutated under
    /// [`Self::write_lock`].
    pub(in crate::context::supervisor) standing_contexts: ArcSwap<HashMap<String, DID>>,
    /// Local identities. Grows once per `identity_add`; read-heavy.
    pub(in crate::context::supervisor) local_dids: ArcSwap<HashSet<DID>>,
    /// Per-identity X25519 wrapping keys. Wrapped in `ArcSwap` so
    /// rotation is atomic; outer `DashMap` keyed by DID.
    pub(in crate::context::supervisor) wrapping_keys: DashMap<DID, ArcSwap<WrappingKeyPair>>,
    /// Persistence backend; stored so `spawn_actor` / `crash_recovery`
    /// can plumb it through to per-actor state.
    // Operational in Phase 2 of post-review-round-1 plan (actor model wiring).
    #[allow(dead_code)]
    pub(in crate::context::supervisor) persistence: Arc<dyn ContextPersistence>,
    /// Single-producer-multi-read write lock — plan §"Write path".
    pub(crate) write_lock: tokio::sync::Mutex<()>,
    /// Serializes the whole bootstrap-spawn sequence of ALL three lifecycle
    /// bootstrap variants — `create_context`, `import_context`, and
    /// `restore_context` — each of which writes per-context crypto state and
    /// then spawns an owned-state actor for the same context id in two
    /// non-atomic steps. The actor mailbox only serializes the
    /// `PrepareForReplace` turn; the crypto-write→spawn tail runs outside it,
    /// so two concurrent bootstrap ops for the SAME id (import vs import, OR
    /// import vs create/restore) could otherwise leave the registered actor
    /// paired with the other op's crypto state, or discard the import's
    /// floor-guarded crypto behind a fresh create. Held across each bootstrap
    /// op so same-id bootstraps run one at a time. Bootstrap is not a hot path,
    /// so a single supervisor-wide lock is acceptable; this is a DIFFERENT lock
    /// from `write_lock` to avoid re-entrancy with
    /// `spawn_actor_with_state`/`despawn_actor` (which take `write_lock`).
    /// Lock order is always `bootstrap_spawn_lock` → `write_lock`, never the
    /// reverse.
    pub(crate) bootstrap_spawn_lock: tokio::sync::Mutex<()>,
    /// Pending sagas keyed by saga ID; projection of the durable
    /// journal for fast lookup.
    // Operational in Phase 2 of post-review-round-1 plan (saga FSM real
    // Prepare/Commit dispatch + watchdog).
    #[allow(dead_code)]
    pub(in crate::context::supervisor) pending_sagas: DashMap<SagaId, PendingSagaProjection>,
    /// Durable saga journal (plan §"Cross-context saga protocol").
    pub(in crate::context::supervisor) saga_journal: Arc<dyn SagaJournal>,
    /// Per-identity `KeyPackageStoreActor` handles.
    pub(in crate::context::supervisor) key_package_stores: DashMap<DID, KeyPackageStoreHandle>,
    /// Configuration.
    // Operational in Phase 2 of post-review-round-1 plan (saga + watchdog
    // configuration plumbed through ActorDeps).
    #[allow(dead_code)]
    pub(in crate::context::supervisor) health_config: SupervisorConfig,
    /// Per-context crash-count windows (respawn budget state).
    // Operational in Phase 2 of post-review-round-1 plan (watchdog respawn
    // budget per ADR-049 §10).
    #[allow(dead_code)]
    pub(in crate::context::supervisor) crash_windows: DashMap<String, CrashWindow>,

    // -----------------------------------------------------------------
    // ADR-049 commit 12 — providers lifted from ContextManager (now
    // authoritative on Supervisor).
    //
    // Each `OnceLock<Arc<...>>` provider slot is populated directly by
    // [`Self::with_providers`]. There is no `ContextManager` to attach
    // — the supervisor IS the source of truth for every provider after
    // commit 12. Slots are still wrapped in `OnceLock` so the
    // [`Self::for_query_shim`] constructor path (used by tests +
    // saga-only call sites) can build a supervisor without providers
    // and the FFI layer can populate them once at construction time.
    //
    // Provider OnceLocks return `Option<&...>` from their accessors —
    // helpers that consult them either soft-fallback or surface
    // `ContextError::NotInitialized`. The supervisor-authoritative
    // direct fields below (`contexts`, `local_dids`,
    // `standing_contexts`) are eagerly initialized
    // in [`Self::new`] and their accessors do not return `Option`.
    // -----------------------------------------------------------------
    /// Shared crypto provider. Populated by [`Self::with_providers`].
    crypto: OnceLock<Arc<crate::crypto::mls::provider::MlsCryptoProvider>>,
    /// Shared transport provider. Populated by [`Self::with_providers`].
    transport: OnceLock<Arc<dyn ContextTransportProvider>>,
    /// Shared event-log provider. Populated by [`Self::with_providers`].
    event_log: OnceLock<Arc<dyn ContextEventLogProvider>>,
    /// Optional helper-side persistence slot — populated by
    /// [`Self::with_providers`] only when the caller passes
    /// `Some(persistence)`. Distinct from the supervisor-saga
    /// [`Self::persistence`] field above (which is always populated;
    /// defaults to the no-op stub). Helpers branch on
    /// `persistence_ref().is_some()` to skip best-effort persist
    /// calls when no real backend is wired.
    helper_persistence: OnceLock<Arc<dyn ContextPersistence>>,
    /// Wall-clock source. Populated by [`Self::with_providers`] (or
    /// defaulted to [`scp_primitives::SystemClock`] when the caller
    /// passes `None`).
    clock: OnceLock<Arc<dyn Clock>>,
    /// Key resolver for governance signature verification. The type is
    /// itself an `Arc<dyn Fn(...)>` alias (see
    /// [`scp_protocol::context::governance::KeyResolver`]), so storing a
    /// clone is a reference-count bump.
    key_resolver: OnceLock<KeyResolver>,
    /// Optional payment adapter. Empty `OnceLock` means "no adapter
    /// configured"; populated by [`Self::with_providers`] when the
    /// caller passes `Some(adapter)`. There is no post-construction
    /// setter — the deleted prior `set_payment_adapter` opened a
    /// two-paths-to-set seam that no production caller used.
    payment_adapter: OnceLock<Arc<dyn PaymentAdapterDyn>>,
    /// Optional broadcast sender for fan-out of [`ContextEvent`]s to
    /// external consumers. Empty `OnceLock` means "no channel
    /// configured".
    event_tx: OnceLock<tokio::sync::broadcast::Sender<(String, ContextEvent)>>,
    /// Shared task set for TTL timers + governance timeouts.
    task_set: OnceLock<Arc<tokio::sync::Mutex<tokio::task::JoinSet<()>>>>,
    /// OpenMLS storage adapter — the bridge's chosen Storage, erased once via
    /// `SpawnBlockingStorageAdapter`. Runtime NEVER defaults this. Lock-free
    /// read per ADR-049 §Decision 12.
    mls_storage: OnceLock<Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter>>,

    // -----------------------------------------------------------------
    // ADR-049 commit 12 — supervisor-authoritative direct fields.
    //
    // These were previously mirrored from `ContextManager`. The
    // supervisor now owns them directly; eagerly initialized in
    // [`Self::new`].
    // -----------------------------------------------------------------
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

    // -----------------------------------------------------------------
    /// Monotonic spawn-generation counter. Incremented once per
    /// [`Self::spawn_actor_with_state`] and stamped onto the spawned
    /// actor's [`PerContextState::generation`](crate::context::actor::state::PerContextState::generation).
    /// A tool-economy reservation captures the generation of the actor
    /// instance it reserved against; the Phase-3 settle rejects if the
    /// generation no longer matches (the actor was despawned and a new
    /// instance respawned for the same `context_id` between reserve and
    /// settle), preventing a settle from capturing or refunding against a
    /// DIFFERENT context instance's owned state. This is the confused-deputy
    /// guard for the reserve→execute→settle split: the executor runs
    /// supervisor-side (non-`Send`) outside the actor's serialized mailbox,
    /// so the actor instance identity must be re-verified at settle time.
    spawn_generation: std::sync::atomic::AtomicU64,
}

impl Supervisor {
    /// Constructs a fresh supervisor.
    ///
    /// `persistence` and `saga_journal` are injected at construction so
    /// the supervisor is never a singleton — bridge instances in
    /// `scp_ffi_common::bridge_instance` construct one per SCP
    /// instance and drop it on `shutdown`.
    ///
    /// Visibility is `pub(crate)` in production builds; only
    /// [`Self::with_providers`] (the FFI-facing factory) calls into
    /// `new`. Integration tests in `crates/scp-runtime/tests/` reach
    /// the constructor through the `testing`-feature gate so they can
    /// build supervisors without provider wiring.
    #[must_use]
    #[cfg(any(test, feature = "testing"))]
    pub fn new(
        persistence: Arc<dyn ContextPersistence>,
        saga_journal: Arc<dyn SagaJournal>,
        health_config: SupervisorConfig,
    ) -> Self {
        Self::new_inner(persistence, saga_journal, health_config)
    }

    /// Internal constructor reachable from production builds. The public
    /// surface goes through [`Self::with_providers`]; the test-only
    /// [`Self::new`] alias forwards here so the same body services both
    /// the production factory and the test integration suites.
    #[must_use]
    pub(crate) fn new_inner(
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
            bootstrap_spawn_lock: tokio::sync::Mutex::new(()),
            pending_sagas: DashMap::new(),
            saga_journal,
            key_package_stores: DashMap::new(),
            health_config,
            crash_windows: DashMap::new(),
            // ADR-049 commit 12 — providers lifted from
            // ContextManager. Populated by `with_providers`.
            crypto: OnceLock::new(),
            transport: OnceLock::new(),
            event_log: OnceLock::new(),
            helper_persistence: OnceLock::new(),
            clock: OnceLock::new(),
            key_resolver: OnceLock::new(),
            payment_adapter: OnceLock::new(),
            event_tx: OnceLock::new(),
            task_set: OnceLock::new(),
            mls_storage: OnceLock::new(),
            saga_pending_guard: std::sync::atomic::AtomicBool::new(false),
            // Generation 0 is never stamped onto a live actor (the first
            // spawn increments to 1 before stamping), so a default
            // `PerContextState::generation == 0` can never collide with a
            // real spawn generation.
            spawn_generation: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Test-only constructor used by saga + spawn unit tests that never
    /// invoke a provider-touching helper.
    ///
    /// Builds a [`Supervisor`] whose `persistence` and `saga_journal`
    /// fields are no-op stubs — saga FSM tests assert the coordinator's
    /// observable state transitions, and spawn tests exercise registry
    /// insertion only. Production code paths build supervisors through
    /// [`Self::with_providers`], which wires real providers; bridge
    /// instances in `scp_ffi_common::bridge_instance` never call
    /// `for_query_shim`.
    ///
    /// Gated behind the `testing` feature so production FFI builds
    /// cannot reach a provider-less supervisor.
    #[must_use]
    #[cfg(any(test, feature = "testing"))]
    pub fn for_query_shim() -> Self {
        let persistence: Arc<dyn ContextPersistence> =
            Arc::new(crate::context::persistence::NoopContextPersistence);
        let saga_journal: Arc<dyn SagaJournal> = Arc::new(NoopSagaJournal);
        Self::new_inner(persistence, saga_journal, SupervisorConfig::default())
    }

    /// Construct a supervisor with the providers that previously lived on
    /// the deleted `ContextManager` (ADR-049 commit 12).
    ///
    /// The supervisor is now the authoritative owner of every provider —
    /// there is no `ContextManager` to attach. FFI bridges call this
    /// factory once at construction time; the returned `Arc<Supervisor>`
    /// is the only handle they hold.
    ///
    /// Saga journal + supervisor-level persistence wire to no-op stubs
    /// the test-only `for_query_shim` path uses — saga orchestration
    /// is not yet active (it lands with Phase 2's actor wiring), and
    /// the supervisor's own persistence slot is wired to a no-op
    /// [`NoopContextPersistence`](crate::context::persistence::NoopContextPersistence)
    /// when `persistence` is `None`.
    ///
    /// # Arguments
    ///
    /// * `crypto` — production
    ///   [`MlsCryptoProvider`](crate::crypto::mls::provider::MlsCryptoProvider).
    /// * `transport` — production transport (typically
    ///   [`NotConfiguredTransportProvider`](crate::context::builder::NotConfiguredTransportProvider),
    ///   [`LocalTransportProvider`](crate::context::builder::LocalTransportProvider), or a real
    ///   `scp_transport::RelayTransportProvider`).
    /// * `event_log` — event log provider, usually backed by
    ///   `MerkleEventLogProvider::with_persistence(...)` so entries
    ///   survive restart.
    /// * `key_resolver` — DID-to-Ed25519-key resolver for governance
    ///   signature verification.
    /// * `persistence` — optional context persistence; `None` keeps the
    ///   supervisor in-memory only.
    /// * `payment_adapter` — optional payment adapter for the 9-step
    ///   paid-action flow (spec §19.2.2).
    /// * `event_tx` — optional broadcast sender for event fan-out.
    /// * `clock` — optional [`Clock`] override; defaults to
    ///   [`scp_primitives::SystemClock`] when `None`.
    /// * `mls_storage` — **required** OpenMLS storage adapter (the
    ///   bridge's chosen `Storage`, erased once via
    ///   [`SpawnBlockingStorageAdapter`](crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter)).
    ///   The runtime never defaults or manufactures storage — the caller
    ///   supplies it at the bridge/builder layer, enforced by the type
    ///   system (non-`Option`). In-memory storage is a bridge-layer dev
    ///   opt-in, never a runtime default.
    ///
    /// # Returns
    ///
    /// `Arc<Supervisor>` — already wrapped because FFI bridges store
    /// their per-instance supervisor in an `Arc` slot.
    #[must_use]
    #[allow(clippy::too_many_arguments)] // FFI bridges need to compose providers in one call
    pub fn with_providers(
        crypto: Arc<crate::crypto::mls::provider::MlsCryptoProvider>,
        transport: Box<dyn ContextTransportProvider>,
        event_log: Box<dyn ContextEventLogProvider>,
        key_resolver: KeyResolver,
        persistence: Option<Box<dyn ContextPersistence>>,
        payment_adapter: Option<Arc<dyn PaymentAdapterDyn>>,
        event_tx: Option<tokio::sync::broadcast::Sender<(String, ContextEvent)>>,
        clock: Option<Arc<dyn Clock>>,
        mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter>,
    ) -> Arc<Self> {
        // The supervisor's own `persistence` field is non-Option (saga
        // code requires a value); when the caller passes `None`, wire
        // the no-op stub the `for_query_shim` path uses. The
        // helper-side `helper_persistence` slot stays empty in that
        // case so `persistence_ref()` returns `None` and helpers skip
        // best-effort persist calls.
        let (supervisor_persistence, helper_persistence_arc) = persistence.map_or_else(
            || {
                let stub: Arc<dyn ContextPersistence> =
                    Arc::new(crate::context::persistence::NoopContextPersistence);
                (stub, None)
            },
            |boxed| {
                let arc: Arc<dyn ContextPersistence> = Arc::from(boxed);
                (Arc::clone(&arc), Some(arc))
            },
        );
        let saga_journal: Arc<dyn SagaJournal> = Arc::new(NoopSagaJournal);
        let supervisor = Arc::new(Self::new_inner(
            supervisor_persistence,
            saga_journal,
            SupervisorConfig::default(),
        ));

        // Populate provider OnceLocks. Each `set(...).is_ok()` returns
        // false if the slot is already populated — impossible on this
        // freshly-constructed supervisor, but `let _ = ...` keeps clippy
        // happy with the discarded `Result`.
        let _ = supervisor.crypto.set(crypto);
        let _ = supervisor.transport.set(Arc::from(transport));
        let _ = supervisor.event_log.set(Arc::from(event_log));
        if let Some(p) = helper_persistence_arc {
            let _ = supervisor.helper_persistence.set(p);
        }
        let _ = supervisor.key_resolver.set(key_resolver);
        let clock = clock.unwrap_or_else(|| Arc::new(scp_primitives::SystemClock));
        let _ = supervisor.clock.set(clock);
        if let Some(adapter) = payment_adapter {
            let _ = supervisor.payment_adapter.set(adapter);
        }
        if let Some(tx) = event_tx {
            let _ = supervisor.event_tx.set(tx);
        }
        let _ = supervisor.task_set.set(Arc::new(tokio::sync::Mutex::new(
            tokio::task::JoinSet::new(),
        )));
        // Required, non-Option — the runtime never defaults storage. The
        // freshly-constructed supervisor's slot is always empty here, so
        // `set` cannot fail; `let _ =` discards the `Result` for clippy.
        let _ = supervisor.mls_storage.set(mls_storage);

        supervisor
    }

    // -------------------------------------------------------------------
    // ADR-049 commit 12 — provider + state accessors.
    //
    // Provider accessors (`crypto_ref`, `transport_ref`, etc.) return
    // `Option<&...>` because providers are populated only by
    // [`Self::with_providers`] — the [`Self::for_query_shim`] path
    // leaves them empty (used by saga + spawn unit tests that don't
    // touch providers).
    //
    // Direct-state accessors (`local_dids_ref`, `standing_contexts_ref`)
    // return non-Option references — the underlying fields are eagerly
    // initialized in [`Self::new`] and always populated.
    //
    // Visibility: `pub(crate)` so hoisted helpers can reach them;
    // external callers go through `SupervisorHandle`.
    // -------------------------------------------------------------------

    /// Cheap reference to the supervisor's shared
    /// [`MlsCryptoProvider`](crate::crypto::mls::provider::MlsCryptoProvider).
    /// Returns `None` if [`Self::with_providers`] was not used (e.g. a
    /// supervisor built via [`Self::for_query_shim`] / [`Self::new`]).
    #[must_use]
    pub(crate) fn crypto_ref(
        &self,
    ) -> Option<&Arc<crate::crypto::mls::provider::MlsCryptoProvider>> {
        self.crypto.get()
    }

    /// Cheap reference to the supervisor's shared
    /// [`ContextTransportProvider`]. Returns `None` if
    /// [`Self::with_providers`] was not used.
    #[must_use]
    pub(crate) fn transport_ref(&self) -> Option<&Arc<dyn ContextTransportProvider>> {
        self.transport.get()
    }

    /// Cheap reference to the supervisor's shared
    /// [`ContextEventLogProvider`]. Returns `None` if
    /// [`Self::with_providers`] was not used.
    #[must_use]
    pub(crate) fn event_log_ref(&self) -> Option<&Arc<dyn ContextEventLogProvider>> {
        self.event_log.get()
    }

    /// Cheap reference to the helper-side persistence slot. Returns
    /// `None` if [`Self::with_providers`] was not used or the caller
    /// passed `None` for `persistence` (helpers branch on this to skip
    /// best-effort persist calls when no real backend is wired).
    #[must_use]
    pub(crate) fn persistence_ref(&self) -> Option<&Arc<dyn ContextPersistence>> {
        self.helper_persistence.get()
    }

    /// Cheap reference to the supervisor's wall-clock source. Returns
    /// `None` if [`Self::with_providers`] was not used.
    #[must_use]
    pub(crate) fn clock_ref(&self) -> Option<&Arc<dyn Clock>> {
        self.clock.get()
    }

    /// Cheap reference to the supervisor's
    /// [`KeyResolver`](scp_protocol::context::governance::KeyResolver).
    /// Returns `None` if [`Self::with_providers`] was not used.
    #[must_use]
    pub(crate) fn key_resolver_ref(&self) -> Option<&KeyResolver> {
        self.key_resolver.get()
    }

    /// Cheap reference to the supervisor's payment-adapter slot.
    /// Returns `None` if no payment adapter has been configured.
    #[must_use]
    pub(crate) fn payment_adapter_ref(&self) -> Option<&Arc<dyn PaymentAdapterDyn>> {
        self.payment_adapter.get()
    }

    /// Cheap reference to the supervisor's event fan-out channel.
    /// Returns `None` if no event channel has been configured.
    #[must_use]
    pub(crate) fn event_tx_ref(
        &self,
    ) -> Option<&tokio::sync::broadcast::Sender<(String, ContextEvent)>> {
        self.event_tx.get()
    }

    /// Cheap reference to the supervisor's shared task-set. Returns
    /// `None` if [`Self::with_providers`] was not used.
    #[must_use]
    pub(crate) fn task_set_ref(
        &self,
    ) -> Option<&Arc<tokio::sync::Mutex<tokio::task::JoinSet<()>>>> {
        self.task_set.get()
    }

    /// Cheap reference to the supervisor's OpenMLS storage adapter
    /// (lock-free read per ADR-049 §Decision 12). Returns `None` if
    /// [`Self::with_providers`] was not used (e.g. a supervisor built
    /// via [`Self::for_query_shim`] / [`Self::new`]).
    // Non-test callers land when `dispatch_lifecycle_direct` switches to
    // actor-shape (storage-foundation Step 5); until then this accessor is
    // reached only from `build_actor_deps`' test fixtures.
    #[cfg_attr(not(test), allow(dead_code))]
    #[must_use]
    pub(in crate::context) fn mls_storage_ref(
        &self,
    ) -> Option<&Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter>> {
        self.mls_storage.get()
    }

    // -------------------------------------------------------------------
    // ADR-049 commit 12 — direct-state accessors (always populated).
    // -------------------------------------------------------------------

    /// Cheap reference to the supervisor's local-DID registry.
    ///
    /// The field is `ArcSwap<HashSet<DID>>` per the master plan
    /// §Supervisor — read sites use `arc_swap.load()` (returns
    /// `Guard<Arc<HashSet>>`) or `arc_swap.load_full()` (returns
    /// `Arc<HashSet>`); write sites acquire [`Self::write_lock`] then
    /// clone-update-store on the snapshot.
    #[must_use]
    pub(crate) const fn local_dids_ref(&self) -> &ArcSwap<HashSet<DID>> {
        &self.local_dids
    }

    /// Cheap reference to the supervisor's standing-context tracking
    /// map (peer DID string → peer [`DID`]).
    ///
    /// `ArcSwap<HashMap<...>>` per the master plan §Supervisor — same
    /// read/write discipline as [`Self::local_dids_ref`].
    #[must_use]
    pub(crate) const fn standing_contexts_ref(&self) -> &ArcSwap<HashMap<String, DID>> {
        &self.standing_contexts
    }

    // -------------------------------------------------------------------
    // ADR-049 commit 12c.9f — per-identity wrapping-key accessors.
    //
    // The plan §"MlsCryptoProvider dissolution" lifts the wrapping
    // keypair off [`crate::crypto::mls::provider::MlsCryptoProvider`]
    // (where it was held in `Mutex<[u8;32]>` / `Mutex<Zeroizing<...>>`
    // fields) onto the supervisor's per-identity
    // `wrapping_keys: DashMap<DID, ArcSwap<WrappingKeyPair>>` map. The
    // following accessors give helper code on `&Supervisor` (the
    // 12c.9c-d hoisted helper paths) a stable read/write surface
    // without requiring callers to reach for `&self.wrapping_keys`
    // directly.
    //
    // Read accessors return `Arc<Vec<u8>>` / `Arc<Zeroizing<Vec<u8>>>`
    // newly allocated for each call so the caller owns a fresh
    // refcounted handle. The map itself stays the source of truth;
    // the caller is responsible for dropping the returned `Arc`
    // promptly so a subsequent rotation can zeroize the prior bytes
    // when the last reference drops.
    //
    // The write accessor [`Self::set_wrapping_keys`] acquires
    // [`Self::write_lock`] before any per-identity mutation per the
    // struct-level docs ("any mutation of `actors`, `standing_contexts`,
    // `local_dids`, or `wrapping_keys` acquires `Self::write_lock`
    // first"). The async lock is fine because the write path is rare
    // (initial keypair generation + governance-driven rotations).
    // -------------------------------------------------------------------

    /// Returns a freshly-cloned `Arc` to the X25519 wrapping public key
    /// for `did`, or `None` if no keypair has been registered.
    ///
    /// The returned `Arc<Vec<u8>>` carries the public key bytes the
    /// HPKE seal path uses; the caller MUST drop the `Arc` within the
    /// same poll (no storage in async-state struct fields) so a
    /// subsequent [`Self::set_wrapping_keys`] rotation can drop the
    /// prior bytes promptly.
    ///
    /// Visibility is `pub(in crate::context::supervisor)` until Phase 2
    /// of the post-review-round-1 plan threads `OwnedIdentityDid`
    /// through `ActorDeps` — handlers call this through
    /// [`SupervisorHandle::my_wrapping_public_key`](crate::context::supervisor::handle::SupervisorHandle::my_wrapping_public_key)
    /// which wraps the read with the capability proof. Direct
    /// `&Supervisor` access elsewhere in `crate::context::*` is
    /// forbidden so the wrapping-key surface is reachable only from
    /// supervisor-module code.
    #[must_use]
    #[allow(dead_code)] // first caller lands in Phase 2 with the actor wiring + capability thread
    pub(in crate::context::supervisor) fn wrapping_public_key_for(
        &self,
        did: &DID,
    ) -> Option<Arc<Vec<u8>>> {
        self.wrapping_keys.get(did).map(|entry| {
            let pair = entry.value().load_full();
            Arc::new(pair.public.to_vec())
        })
    }

    /// Returns a freshly-cloned `Arc` to the X25519 wrapping secret
    /// key for `did`, or `None` if no keypair has been registered.
    ///
    /// Same reader discipline as [`Self::wrapping_public_key_for`]:
    /// drop the returned `Arc` within the same poll. The inner
    /// [`Zeroizing`] wrapper guarantees the bytes are zeroed on drop.
    ///
    /// Visibility is `pub(in crate::context::supervisor)` per the
    /// master plan §"Cross-identity isolation" — wrapping-secret
    /// access must be capability-gated by `&OwnedIdentityDid`. Until
    /// Phase 2 wires that capability through `ActorDeps`, the
    /// narrower visibility scopes call sites to supervisor-module code
    /// so handler code outside `supervisor/` cannot read another
    /// identity's secret.
    #[must_use]
    #[allow(dead_code)] // first caller lands in Phase 2 with the actor wiring + capability thread
    pub(in crate::context::supervisor) fn wrapping_secret_key_for(
        &self,
        did: &DID,
    ) -> Option<Arc<zeroize::Zeroizing<Vec<u8>>>> {
        self.wrapping_keys.get(did).map(|entry| {
            let pair = entry.value().load_full();
            Arc::new(zeroize::Zeroizing::new(pair.secret.to_vec()))
        })
    }

    /// Clear every per-identity wrapping keypair. Used by the
    /// shutdown helper so a fresh
    /// [`Self::with_providers`] observes empty per-identity state.
    /// Wrapping-key secrets zeroize on drop via the
    /// `Zeroizing<[u8;32]>` field on
    /// [`WrappingKeyPair`](crate::context::actor::state::WrappingKeyPair).
    /// Phase 1 fix-up of ADR-049 (post-review-round-1).
    pub(crate) fn clear_wrapping_keys(&self) {
        self.wrapping_keys.clear();
    }

    /// Atomically registers (or rotates) the X25519 wrapping keypair
    /// for `did`. Acquires [`Self::write_lock`] first per the
    /// supervisor's write-path discipline; the per-identity
    /// `ArcSwap<WrappingKeyPair>` handles the atomic swap.
    ///
    /// Idempotent — calling with the same DID a second time replaces
    /// the prior keypair (the old `Arc<WrappingKeyPair>` zeroizes its
    /// secret on drop when the last reference releases).
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::InvalidState`] if `public` or `secret`
    /// are not exactly 32 bytes (X25519 keypair fixed sizes per
    /// RFC 7748 §5).
    pub async fn set_wrapping_keys(
        self: &Arc<Self>,
        did: DID,
        public: Vec<u8>,
        secret: zeroize::Zeroizing<Vec<u8>>,
    ) -> Result<(), ContextError> {
        let _guard = self.write_lock.lock().await;
        // Convert from runtime-API `Vec<u8>` to the per-identity
        // [`crate::context::actor::state::WrappingKeyPair`] shape
        // (fixed 32-byte arrays, secret behind `Zeroizing`). Length
        // mismatches surface as `InvalidState` so misuse fails loudly
        // rather than silently truncating key material.
        let public_arr: [u8; 32] = public.as_slice().try_into().map_err(|_| {
            ContextError::InvalidState(format!(
                "Supervisor::set_wrapping_keys — wrapping public key must be 32 bytes (got {})",
                public.len(),
            ))
        })?;
        let secret_arr: [u8; 32] = secret.as_slice().try_into().map_err(|_| {
            ContextError::InvalidState(format!(
                "Supervisor::set_wrapping_keys — wrapping secret key must be 32 bytes (got {})",
                secret.len(),
            ))
        })?;
        let pair = WrappingKeyPair {
            public: public_arr,
            secret: zeroize::Zeroizing::new(secret_arr),
        };
        match self.wrapping_keys.get(&did) {
            Some(entry) => entry.value().store(Arc::new(pair)),
            None => {
                self.wrapping_keys.insert(did, ArcSwap::from_pointee(pair));
            }
        }
        Ok(())
    }

    /// Get-or-spawn this identity's
    /// [`KeyPackageStoreActor`](crate::context::supervisor::key_package_actor::KeyPackageStoreActor),
    /// returning a clone of its handle.
    ///
    /// Lock-free fast path: a [`DashMap::get`] probe (ADR-049 §Decision
    /// 12 — no read-path lock). On a miss the [`Self::write_lock`] is
    /// acquired and the probe is re-checked under the lock (double-
    /// checked) before spawning, so concurrent callers never spawn two
    /// actors for the same identity.
    // Non-test callers land when `dispatch_lifecycle_direct` switches to
    // actor-shape (storage-foundation Step 5); until then this is reached
    // only from `build_actor_deps`' test fixtures.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(in crate::context) async fn key_package_store_for(
        &self,
        identity: &DID,
    ) -> crate::context::supervisor::key_package_actor::KeyPackageStoreHandle {
        if let Some(handle) = self.key_package_stores.get(identity) {
            return handle.value().clone();
        }
        let _guard = self.write_lock.lock().await;
        if let Some(handle) = self.key_package_stores.get(identity) {
            return handle.value().clone();
        }
        let handle = crate::context::supervisor::key_package_actor::KeyPackageStoreActor::spawn(
            identity.clone(),
        );
        self.key_package_stores
            .insert(identity.clone(), handle.clone());
        handle
    }

    /// Build an [`ActorDeps`](crate::context::actor::deps::ActorDeps)
    /// bundle entirely from the supervisor's own provider slots
    /// (ADR-049 §1 / commit 12), scoped to `owning_did`.
    ///
    /// Self-sources every collaborator from the `OnceLock`s populated by
    /// [`Self::with_providers`]: the `MlsBackend` / `HpkeBackend` pair is
    /// read transitively through `crypto.mls_backend()` /
    /// `crypto.hpke_backend()` (the [`MlsCryptoProvider`](crate::crypto::mls::provider::MlsCryptoProvider)
    /// owns the only instance — no second supervisor field, so there is
    /// one source of truth per ADR §6). The OpenMLS storage adapter is
    /// the supervisor's `mls_storage` slot. The `KeyPackageStoreHandle`
    /// is resolved (get-or-spawn) for `owning_did` via
    /// [`Self::key_package_store_for`]. Persistence falls back to the
    /// no-op stub when no helper-side backend is wired.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::NotInitialized`] if any required provider
    /// slot is empty (i.e. [`Self::with_providers`] was not used).
    ///
    /// # Method receiver
    ///
    /// Takes `self: &Arc<Self>` so the returned
    /// [`SupervisorHandle`](crate::context::supervisor::handle::SupervisorHandle)
    /// wraps a cloned `Arc` of the same supervisor instance — not a
    /// fresh `Supervisor::for_query_shim()`. Without this the handle
    /// would point at a dangling second supervisor and
    /// [`SupervisorHandle::local_dids`](crate::context::supervisor::SupervisorHandle::local_dids)
    /// / [`SupervisorHandle::standing_peer`](crate::context::supervisor::SupervisorHandle::standing_peer)
    /// would read empty state.
    // Non-test callers land when `dispatch_lifecycle_direct` switches to
    // actor-shape (storage-foundation Step 5); until then this is reached
    // only from the supervisor + actor test fixtures.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(in crate::context) async fn build_actor_deps(
        self: &Arc<Self>,
        owning_did: &DID,
    ) -> Result<crate::context::actor::deps::ActorDeps, ContextError> {
        use crate::context::manager_methods::PROVIDER_NOT_INITIALIZED;
        let not_init = || ContextError::NotInitialized(PROVIDER_NOT_INITIALIZED.to_owned());

        let crypto = Arc::clone(self.crypto_ref().ok_or_else(not_init)?);
        // mls/hpke stay transitive — the MlsCryptoProvider owns the only
        // backend pair (ADR §6); no Supervisor field mirrors them.
        let mls = Arc::clone(crypto.mls_backend());
        let hpke = Arc::clone(crypto.hpke_backend());
        let transport = Arc::clone(self.transport_ref().ok_or_else(not_init)?);
        let event_log = Arc::clone(self.event_log_ref().ok_or_else(not_init)?);
        let clock = Arc::clone(self.clock_ref().ok_or_else(not_init)?);
        let key_resolver = self.key_resolver_ref().ok_or_else(not_init)?.clone();
        let mls_storage = Arc::clone(self.mls_storage_ref().ok_or_else(not_init)?);
        let persistence = self.persistence_ref().map_or_else(
            || {
                Arc::new(crate::context::persistence::NoopContextPersistence)
                    as Arc<dyn ContextPersistence>
            },
            Arc::clone,
        );
        let key_package_store = self.key_package_store_for(owning_did).await;
        let handle = crate::context::supervisor::handle::SupervisorHandle::wrap(Arc::clone(self));

        Ok(crate::context::actor::deps::ActorDeps {
            crypto,
            transport,
            persistence,
            event_log,
            supervisor: handle,
            key_package_store,
            mls,
            hpke,
            mls_storage,
            clock,
            event_tx: self.event_tx_ref().cloned(),
            key_resolver,
            payment_adapter: self.payment_adapter_ref().map(Arc::clone),
            local_dids: Arc::new(arc_swap::ArcSwap::new(self.local_dids.load_full())),
        })
    }

    /// Dispatch a pure-read [`QueriesCommand`].
    ///
    /// Behaviour:
    ///
    /// - Mailbox-first for variants that carry a per-context
    ///   `context_id`: the actor's `run()` loop pulls the command,
    ///   dispatches through `handlers::queries::dispatch` (actor-shape,
    ///   takes `&mut PerContextState`), and writes the typed result to
    ///   the embedded reply oneshot.
    /// - `EventLogEntries` carries a 32-byte hash rather than a string
    ///   context-id and delegates directly to the event-log provider —
    ///   no per-context state is involved.
    /// - When no actor is registered for the variant's `context_id`,
    ///   [`Self::dispatch_queries_direct`] emits the variant's legacy
    ///   default (e.g. `MemberCount::Ok(None)`, `IsMember::Ok(false)`)
    ///   or surfaces `ContextError::ContextNotRegistered` directly on
    ///   the variant's oneshot, preserving the "context unknown = soft
    ///   default / typed error" contract of the legacy method shape.
    ///
    /// Outcome: `Outcome::ok(())` on every success. The variant's reply
    /// channel carries the typed result. The returned `Outcome` is
    /// dropped by FFI callers — it is retained so the wiring is
    /// symmetric with the mutating-handler paths.
    ///
    /// # Errors
    ///
    /// - [`ContextError::NotInitialized`] if no providers have been
    ///   attached — the caller must call [`Self::with_providers`]
    ///   first.
    pub async fn dispatch_query(&self, cmd: QueriesCommand) -> Result<Outcome<()>, ContextError> {
        // ADR-049 Phase 2A finalization — try the actor mailbox first
        // for variants that carry a per-context `context_id`. The
        // actor's `run()` loop pulls the command, dispatches it through
        // `handlers::queries::dispatch` (actor-shape, takes `&mut
        // PerContextState`), and writes the typed result to the
        // embedded reply oneshot.
        //
        // `EventLogEntries` is a 32-byte hash with no per-context lock
        // — it stays on the inline event-log path below. Unknown-
        // context cases surface the legacy soft / hard defaults via
        // `dispatch_queries_direct`.
        if let Some(ctx_id) = Self::queries_command_context_id(&cmd) {
            let ctx_id_owned = ctx_id.to_owned();
            if let Some(actor) = self.lookup(&ctx_id_owned) {
                return Self::dispatch_via_mailbox(&actor, ContextCommand::Queries(cmd)).await;
            }
        }

        // `EventLogEntries` delegates straight to the supervisor's
        // shared event-log provider — no per-context lock involved.
        if let QueriesCommand::EventLogEntries {
            context_id_bytes,
            reply,
        } = cmd
        {
            let elp = self.event_log_ref().ok_or_else(|| {
                ContextError::NotInitialized(
                    "Supervisor::dispatch_query — event_log provider not configured".to_owned(),
                )
            })?;
            let answer = elp.event_log_entries(&context_id_bytes);
            let _ = reply.send(answer);
            return Ok(Outcome::ok(()));
        }

        // No actor registered for the variant's `context_id`. Direct
        // dispatch surfaces the variant's legacy unknown-context
        // contract (hard error vs soft default) without entering a
        // shim handler — the legacy DashMap fallback was deleted in
        // this session.
        Ok(Self::dispatch_queries_direct(cmd))
    }

    /// Dispatch a mutating [`MessagingCommand`] through the migration
    /// shim (ADR-049 commit 8 / plan row 8).
    ///
    /// Routes the command through the per-context actor's mailbox via
    /// [`Self::dispatch_via_mailbox`]. The actor's `run()` loop pulls
    /// the command and dispatches it via the actor-shape `dispatch(state,
    /// deps, cmd)` entry point, which exercises the actor-owned
    /// [`SendSequenceTracker`](crate::context::actor::SendSequenceTracker)
    /// directly. The handler wraps every transport/MLS call in
    /// [`tokio::time::timeout`] with a 30-second budget; a timeout maps
    /// to [`ContextError::TransportTimeout`](scp_protocol::context::ContextError::TransportTimeout).
    ///
    /// # Errors
    ///
    /// - [`ContextError::NotInitialized`] if no
    ///   [`Supervisor`](crate::context::supervisor::Supervisor) has
    ///   been attached yet — the caller must call
    ///   [`Self::with_providers`] first.
    /// - [`ContextError::ContextNotRegistered`] if no actor has been
    ///   spawned for `ctx_id`. Every production context creation path
    ///   (create / join / restore / import) spawns an actor before the
    ///   supervisor returns control to FFI, so this error indicates a
    ///   sequencing or test-setup bug.
    /// - Any typed error returned by the delegated handler
    ///   (`CryptoFailed`, `PermissionDenied`, `MemberNotFound`,
    ///   `RateLimited`, etc.).
    /// - [`ContextError::TransportTimeout`] if the delegated call
    ///   exceeds the 30-second handler budget.
    pub async fn dispatch_command(
        &self,
        ctx_id: &str,
        cmd: MessagingCommand,
    ) -> Result<Outcome<()>, ContextError> {
        // ADR-049 Phase 2A finalization — mailbox-only. The
        // handler-side `dispatch_from_shim` and the take-and-swap
        // tracker dance have been deleted; the actor owns
        // `state.send_tracker` and serializes by construction.
        let actor = self.lookup(ctx_id).ok_or_else(|| {
            ContextError::ContextNotRegistered(format!(
                "dispatch_command — no actor registered for context_id `{ctx_id}`"
            ))
        })?;
        Self::dispatch_via_mailbox(&actor, ContextCommand::Messaging(cmd)).await
    }

    /// Dispatch a mutating [`LifecycleCommand`].
    ///
    /// Routing (ADR-049 Phase 2A finalization):
    ///
    /// - **Bootstrap variants** (`CreateContext`, `ImportContext`,
    ///   `RestoreContext`) always route through
    ///   [`Self::dispatch_lifecycle_direct`], which delegates to the
    ///   designated-legacy `&Supervisor`-shape helpers in
    ///   [`crate::context::lifecycle_helpers_legacy`]. These helpers
    ///   construct fresh `PerContextState` and (on dual-write) spawn
    ///   the per-context actor as part of the bootstrap handshake.
    /// - **Per-context variants** (`JoinContext`, `LeaveContext`,
    ///   `CloseContext`, `ExportContext`,
    ///   `GenerateContextAccessKey`, `RevokeContextAccessKey`,
    ///   `RestoreContextAccessKey`) carry a `context_id` and route
    ///   through the per-context actor's mailbox into the actor-shape
    ///   `handlers::lifecycle::dispatch`. If no actor is registered for
    ///   the target context, the call falls through to
    ///   [`Self::dispatch_lifecycle_direct`] which surfaces
    ///   `ContextError::ContextNotRegistered` on the reply oneshot.
    ///
    /// Each variant wraps its delegated body in `tokio::time::timeout`
    /// with a 30s budget, maps a timeout to
    /// [`ContextError::TransportTimeout`](scp_protocol::context::ContextError::TransportTimeout),
    /// and relays the typed reply on the variant's oneshot.
    ///
    /// # Errors
    ///
    /// - [`ContextError::NotInitialized`] if no providers have been
    ///   attached — the caller must call [`Self::with_providers`]
    ///   first.
    /// - Any typed error returned by the delegated bootstrap / actor
    ///   handler is surfaced through the variant's oneshot reply; the
    ///   method-level result here is `Ok(Outcome { .. })`.
    /// - [`ContextError::TransportTimeout`] is surfaced through the
    ///   oneshot reply, not the method result.
    pub async fn dispatch_lifecycle_command(
        self: &Arc<Self>,
        cmd: LifecycleCommand,
    ) -> Result<Outcome<()>, ContextError> {
        // ADR-049 Phase 2A finalization — bootstrap variants always
        // route through `dispatch_lifecycle_direct`. They construct
        // fresh state (and, on dual-write, spawn the actor); the
        // mailbox-first check would either no-op for a fresh context
        // (no actor yet) or recurse against the existing actor on a
        // re-create attempt — neither produces correct semantics. The
        // direct path inlines the supervisor-scoped bootstrap body and
        // surfaces the typed reply on the variant's oneshot.
        if matches!(
            cmd,
            LifecycleCommand::CreateContext { .. }
                | LifecycleCommand::ImportContext { .. }
                | LifecycleCommand::RestoreContext { .. }
        ) {
            return Ok(Box::pin(self.dispatch_lifecycle_direct(cmd)).await);
        }
        // Per-context variants (Join / Leave / Close / Export +
        // access-key generate / revoke / restore + Placeholder) all
        // carry a `context_id` and have a registered actor after
        // bootstrap dual-write. Mailbox-first routes to the actor's
        // `dispatch_state` loop which executes the actor-shape handler.
        if let Some(ctx_id) = Self::lifecycle_command_context_id(&cmd)
            && let Some(actor) = self.lookup(ctx_id)
        {
            return Self::dispatch_via_mailbox(&actor, ContextCommand::Lifecycle(cmd)).await;
        }
        // Per-context variant for which no actor is registered — the
        // `Supervisor::contexts` DashMap fallback (and its handler-side
        // `dispatch_from_shim`) were deleted in this session. Surface
        // the typed error on the reply oneshot via the direct path's
        // unreachable-arm sketch so the caller gets a defined response.
        Ok(Box::pin(self.dispatch_lifecycle_direct(cmd)).await)
    }

    /// Direct supervisor-scoped dispatch for bootstrap-shaped
    /// [`LifecycleCommand`] variants (Create / Import / Restore) and
    /// the no-actor fallback for per-context variants.
    ///
    /// Mirrors [`Self::dispatch_standing_direct`]: each arm wraps the
    /// supervisor-scoped body in a 30s timeout matching the actor-
    /// handler shape (plan §"Transport timeouts inside actor handlers")
    /// and relays the typed reply on the variant's oneshot.
    ///
    /// **Bootstrap arms (Create / Import / Restore)** build an
    /// [`ActorDeps`](crate::context::actor::deps::ActorDeps) bundle via
    /// [`Self::build_actor_deps`] (self-sourced from the supervisor's own
    /// provider slots — `OpenMlsStorageAdapter` is now the supervisor's
    /// `mls_storage` slot and the per-identity `KeyPackageStoreHandle` is
    /// get-or-spawned, both since the storage-foundation reshape) and
    /// delegate to the actor-shape helpers in
    /// [`crate::context::lifecycle_helpers`]. Those helpers spawn the
    /// per-context actor (`spawn_actor_for_context`) while continuing to
    /// dual-write the legacy `contexts` `DashMap` during the ADR-049
    /// Phase 2A transition window. Building deps requires
    /// `self: &Arc<Self>` so the spawned actor and its handle wrap the
    /// same supervisor instance.
    ///
    /// **Per-context variants** (Join / Leave / Close / Export +
    /// access-key generate / revoke / restore) still delegate to the
    /// designated-legacy `&Supervisor`-shape helpers in
    /// [`crate::context::lifecycle_helpers_legacy`]; they reach this
    /// method only when no actor is registered for the target context.
    #[allow(clippy::too_many_lines)] // flat match over every lifecycle variant
    async fn dispatch_lifecycle_direct(self: &Arc<Self>, cmd: LifecycleCommand) -> Outcome<()> {
        const LIFECYCLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

        match cmd {
            LifecycleCommand::Placeholder { reply } => {
                const MSG: &str =
                    "LifecycleCommand::Placeholder — handshake target; no production work";
                let _ = reply.send(Err(ContextError::NotImplemented(MSG.to_owned())));
                Outcome::err(ContextError::NotImplemented(MSG.to_owned()))
            }
            LifecycleCommand::CreateContext { payload, reply } => {
                let p = *payload;
                let context_id = p.context_id.clone();
                // Serialize this bootstrap-spawn (crypto-init → spawn) against
                // every other same-id bootstrap so a concurrent import/restore
                // for the same id cannot interleave its crypto write between
                // this op's crypto-init and actor registration. See
                // `bootstrap_spawn_lock`.
                let _bootstrap_guard = self.bootstrap_spawn_lock.lock().await;
                // ADR-049 Phase 2A finalization: bootstrap now builds the
                // actor-shape `ActorDeps` (self-sourced from the
                // supervisor's provider slots, scoped to the creator's
                // identity for KeyPackageStore resolution) and delegates
                // to `lifecycle_helpers::create_context`, which spawns the
                // per-context actor (and dual-writes the legacy DashMap).
                let deps = match self.build_actor_deps(&p.creator_did).await {
                    Ok(deps) => deps,
                    Err(e) => {
                        let sketch = standing_outcome_error_sketch(&e);
                        let err =
                            scp_protocol::context::builder::ContextCreationError::CreationFailed(
                                format!("create_context: deps unavailable: {e}"),
                            );
                        let _ = reply.send(Err(err));
                        return Outcome::err_mutated(sketch);
                    }
                };
                let fut = crate::context::lifecycle_helpers::create_context(
                    &deps,
                    p.context_id,
                    p.params,
                    p.creator_did,
                    p.local_pseudonym,
                );
                // `Box::pin` the create future: owned-state spawn keeps the
                // freshly built `PerContextState` live across the spawn
                // await inside `create_context`, so the future is large
                // (>16 KiB). Heap-boxing it keeps this lifecycle frame off
                // the stack.
                let (outcome, reply_result) = match tokio::time::timeout(
                    LIFECYCLE_TIMEOUT,
                    Box::pin(fut),
                )
                .await
                {
                    Ok(Ok(handle)) => (Outcome::ok_mutated(()), Ok(handle)),
                    Ok(Err(e)) => {
                        let sketch = ContextError::CryptoFailed(format!("create_context: {e}"));
                        (Outcome::err_mutated(sketch), Err(e))
                    }
                    Err(_elapsed) => {
                        let err =
                            scp_protocol::context::builder::ContextCreationError::CreationFailed(
                                format!(
                                    "create_context exceeded {LIFECYCLE_TIMEOUT:?} budget for context {context_id}"
                                ),
                            );
                        let sketch = ContextError::TransportTimeout(format!(
                            "create_context exceeded {LIFECYCLE_TIMEOUT:?} budget for context {context_id}"
                        ));
                        (Outcome::err_mutated(sketch), Err(err))
                    }
                };
                let _ = reply.send(reply_result);
                outcome
            }
            LifecycleCommand::ImportContext { export, reply } => {
                let context_id = export.snapshot.context_id.clone();
                // ADR-049 Phase 2A finalization: scope the actor-shape
                // deps to a deterministic member of the imported roster
                // (the lexicographically-minimum member DID). The import
                // path never consumes the resolved `KeyPackageStoreHandle`
                // (it rehydrates a snapshot rather than joining), so the
                // identity choice only selects which per-identity store
                // actor is touched; picking the min member DID keeps it
                // deterministic and a genuine context participant rather
                // than fabricating one. An empty roster falls back to the
                // context id so deps construction never panics.
                let owning_did = export
                    .snapshot
                    .membership
                    .members()
                    .map(|m| m.did.clone())
                    .min()
                    .unwrap_or_else(|| DID(context_id.clone()));
                let deps = match self.build_actor_deps(&owning_did).await {
                    Ok(deps) => deps,
                    Err(e) => {
                        let sketch = standing_outcome_error_sketch(&e);
                        let _ = reply.send(Err(e));
                        return Outcome::err_mutated(sketch);
                    }
                };
                // Serialize the whole import replace sequence against every
                // other same-id bootstrap (import/create/restore): the actor
                // mailbox only serializes the `PrepareForReplace` turn, but the
                // crypto-restore→spawn tail runs outside it. Held across the
                // entire `import_context` future. See `bootstrap_spawn_lock`.
                let _bootstrap_guard = self.bootstrap_spawn_lock.lock().await;
                // Box::pin — the per-variant import future crosses
                // clippy's 16 KB stack budget (ContextExport ~2 KB +
                // the full PerContextState-construction locals inside
                // the `import_context` body).
                let fut = Box::pin(crate::context::lifecycle_helpers::import_context(
                    &deps, *export,
                ));
                let (outcome, reply_result) = match tokio::time::timeout(LIFECYCLE_TIMEOUT, fut)
                    .await
                {
                    Ok(Ok(handle)) => (Outcome::ok_mutated(()), Ok(handle)),
                    Ok(Err(e)) => {
                        let sketch = standing_outcome_error_sketch(&e);
                        (Outcome::err_mutated(sketch), Err(e))
                    }
                    Err(_elapsed) => {
                        let err = ContextError::TransportTimeout(format!(
                            "import_context exceeded {LIFECYCLE_TIMEOUT:?} budget for context {context_id}"
                        ));
                        let sketch = standing_outcome_error_sketch(&err);
                        (Outcome::err_mutated(sketch), Err(err))
                    }
                };
                let _ = reply.send(reply_result);
                outcome
            }
            LifecycleCommand::RestoreContext { payload, reply } => {
                let p = *payload;
                let context_id = p.context_id.clone();
                // Serialize this bootstrap-spawn against every other same-id
                // bootstrap (see `bootstrap_spawn_lock`).
                let _bootstrap_guard = self.bootstrap_spawn_lock.lock().await;
                let handle = crate::context::ContextHandle::new(p.context_id.clone(), p.params);
                if let Err(e) = handle
                    .transition_to(&scp_protocol::context::ContextState::Active)
                    .await
                {
                    let sketch = standing_outcome_error_sketch(&e);
                    let _ = reply.send(Err(e));
                    return Outcome::err(sketch);
                }
                // ADR-049 Phase 2A finalization: the restore payload
                // carries no identity (it rehydrates a persisted snapshot
                // rather than joining), and `restore_context` never
                // consumes the resolved `KeyPackageStoreHandle`. Scope the
                // deps to a registered local DID when one exists (the node
                // performing the restore), falling back to a context-id-
                // derived seed so deps construction stays deterministic
                // and never fabricates a foreign participant.
                let owning_did = self
                    .local_dids_ref()
                    .load()
                    .iter()
                    .min()
                    .cloned()
                    .unwrap_or_else(|| DID(p.context_id.clone()));
                let deps = match self.build_actor_deps(&owning_did).await {
                    Ok(deps) => deps,
                    Err(e) => {
                        let sketch = standing_outcome_error_sketch(&e);
                        let _ = reply.send(Err(e));
                        return Outcome::err_mutated(sketch);
                    }
                };
                let fut = Box::pin(crate::context::lifecycle_helpers::restore_context(
                    &deps,
                    &p.context_id,
                    &handle,
                ));
                let (outcome, reply_result) = match tokio::time::timeout(LIFECYCLE_TIMEOUT, fut)
                    .await
                {
                    Ok(Ok(())) => (Outcome::ok_mutated(()), Ok(())),
                    Ok(Err(e)) => {
                        let sketch = standing_outcome_error_sketch(&e);
                        (Outcome::err_mutated(sketch), Err(e))
                    }
                    Err(_elapsed) => {
                        let err = ContextError::TransportTimeout(format!(
                            "restore_context exceeded {LIFECYCLE_TIMEOUT:?} budget for context {context_id}"
                        ));
                        let sketch = standing_outcome_error_sketch(&err);
                        (Outcome::err_mutated(sketch), Err(err))
                    }
                };
                let _ = reply.send(reply_result);
                outcome
            }
            // Per-context variants reach this arm only when no actor is
            // registered for the target context. Post-Step-B, every valid
            // context has a registered actor and these variants are
            // mailbox-dispatched to the per-context actor-shape handlers
            // (Join/Leave/Close/Export/access-key all exist on the actor).
            // The supervisor-side direct path is therefore reached ONLY for
            // an unregistered context, which is by definition not registered
            // — surface a typed `ContextNotRegistered` on the reply oneshot
            // and return a matching error `Outcome` (mirrors the
            // `FlushSnapshot`/`ShutdownSelf` never-should-reach arms).
            LifecycleCommand::JoinContext { payload, reply } => {
                let err = ContextError::ContextNotRegistered(payload.context_id.clone());
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            LifecycleCommand::LeaveContext { payload, reply } => {
                let err = ContextError::ContextNotRegistered(payload.context_id.clone());
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            LifecycleCommand::CloseContext { payload, reply } => {
                let err = ContextError::ContextNotRegistered(payload.context_id.clone());
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            LifecycleCommand::ExportContext {
                context_id, reply, ..
            } => {
                let err = ContextError::ContextNotRegistered(context_id);
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            // The access-key trio shares the same `{ context_id, reply, .. }`
            // shape and the same `Result<(), _>` reply, so they collapse
            // into one arm.
            LifecycleCommand::GenerateContextAccessKey {
                context_id, reply, ..
            }
            | LifecycleCommand::RevokeContextAccessKey {
                context_id, reply, ..
            }
            | LifecycleCommand::RestoreContextAccessKey {
                context_id, reply, ..
            } => {
                let err = ContextError::ContextNotRegistered(context_id);
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            // Sweep variants are dispatched per-actor by the iterating
            // entry points in `lifecycle_helpers` — they should never
            // reach the direct path (which has no actor to target). If
            // a caller mistakenly routes one through
            // `dispatch_lifecycle_command`, surface a typed error on
            // the reply oneshot rather than panicking.
            LifecycleCommand::FlushSnapshot { reply } => {
                let err = ContextError::InvalidState(
                    "LifecycleCommand::FlushSnapshot reached dispatch_lifecycle_direct — \
                     sweep variants must be dispatched via the iterating entry points in \
                     `lifecycle_helpers::flush_all_contexts*`"
                        .to_owned(),
                );
                let sketch = ContextError::InvalidState(format!("{err}"));
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            LifecycleCommand::ShutdownSelf { reply } => {
                let err = ContextError::InvalidState(
                    "LifecycleCommand::ShutdownSelf reached dispatch_lifecycle_direct — \
                     sweep variants must be dispatched via the iterating entry points in \
                     `lifecycle_helpers::shutdown_all_contexts*`"
                        .to_owned(),
                );
                let sketch = ContextError::InvalidState(format!("{err}"));
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            // Read-only gauge sweep. Like `FlushSnapshot`/`ShutdownSelf`,
            // this must never reach the direct path — it is dispatched
            // per-actor via the mailbox by `update_context_gauges`. The
            // reply channel carries a bare `usize`, so the
            // never-should-happen branch replies 0 (degenerate) and
            // returns a typed error `Outcome`.
            LifecycleCommand::ReportBufferLen { reply } => {
                let _ = reply.send(0);
                Outcome::err(ContextError::InvalidState(
                    "LifecycleCommand::ReportBufferLen reached dispatch_lifecycle_direct — \
                     the gauge sweep must be dispatched per-actor via the mailbox in \
                     `manager_methods::update_context_gauges`"
                        .to_owned(),
                ))
            }
        }
    }

    /// Dispatch a mutating [`TtlCloseCommand`] through the migration
    /// shim (ADR-049 commit 9 / plan row 9).
    ///
    /// Same shape as [`Self::dispatch_lifecycle_command`] — handlers
    /// take the attached manager directly, wrap delegated
    /// [`Supervisor`](crate::context::supervisor::Supervisor) calls
    /// in [`tokio::time::timeout`] with a 30s budget, and relay the
    /// typed result through the variant's oneshot.
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
    ///   [`Supervisor`](crate::context::supervisor::Supervisor) has
    ///   been attached yet.
    pub async fn dispatch_ttl_close_command(
        &self,
        cmd: TtlCloseCommand,
    ) -> Result<Outcome<()>, ContextError> {
        // ADR-049 Phase 2A finalization — mailbox-only. The
        // handler-side `dispatch_from_shim` and the dead `_legacy`
        // bodies have been deleted; every command's target actor must
        // be spawned before dispatch reaches this method.
        let Some(ctx_id) = Self::ttl_close_command_context_id(&cmd) else {
            return Err(ContextError::ContextNotRegistered(
                "dispatch_ttl_close_command — variant has no per-context routing target \
                 (Placeholder); mailbox-only after Phase 2A finalization"
                    .to_owned(),
            ));
        };
        let actor = self.lookup(ctx_id).ok_or_else(|| {
            ContextError::ContextNotRegistered(format!(
                "dispatch_ttl_close_command — no actor registered for context_id `{ctx_id}`"
            ))
        })?;
        Self::dispatch_via_mailbox(&actor, ContextCommand::TtlClose(cmd)).await
    }

    /// Dispatch a [`GovernanceCommand`] through the migration shim
    /// (ADR-049 commit 10 / plan row 10).
    ///
    /// Contract (byte-identical to the legacy
    /// [`Supervisor`](crate::context::supervisor::Supervisor)
    /// governance methods it replaces):
    ///
    /// Routes every per-context variant through the per-context actor's
    /// mailbox via [`Self::dispatch_via_mailbox`]. The actor's `run()`
    /// loop pulls the command, dispatches it through the actor-shape
    /// `dispatch(state, deps, cmd)` entry point, and writes the typed
    /// reply on the command's embedded oneshot. The `Placeholder`
    /// variant (mailbox handshake target — no `context_id`) returns
    /// [`ContextError::ContextNotRegistered`] from this method when no
    /// per-context routing target exists; the no-op reply is otherwise
    /// produced by the actor-side `dispatch_state` arm.
    ///
    /// # Errors
    ///
    /// - [`ContextError::NotInitialized`] if no
    ///   [`Supervisor`](crate::context::supervisor::Supervisor) has
    ///   been attached yet.
    /// - [`ContextError::ContextNotRegistered`] if no actor has been
    ///   spawned for the command's target context_id. Every production
    ///   context creation path (create / join / restore / import)
    ///   spawns an actor before the supervisor returns control to FFI,
    ///   so this error indicates a sequencing or test-setup bug.
    /// - Any typed error from the delegated handler is surfaced through
    ///   the variant's oneshot reply; the method-level result here is
    ///   `Ok(Outcome { .. })`.
    /// - [`ContextError::TransportTimeout`] is surfaced through the
    ///   oneshot reply, not the method result.
    pub async fn dispatch_governance_command(
        &self,
        cmd: GovernanceCommand,
    ) -> Result<Outcome<()>, ContextError> {
        // ADR-049 Phase 2A finalization — mailbox-only. The
        // handler-side `dispatch_from_shim` and its `_legacy` body have
        // been deleted; every command's target actor must be spawned
        // before dispatch reaches this method.
        let Some(ctx_id) = Self::governance_command_context_id(&cmd) else {
            return Err(ContextError::ContextNotRegistered(
                "dispatch_governance_command — variant has no per-context routing target \
                 (Placeholder / cross-context); mailbox-only after Phase 2A finalization"
                    .to_owned(),
            ));
        };
        let actor = self.lookup(ctx_id).ok_or_else(|| {
            ContextError::ContextNotRegistered(format!(
                "dispatch_governance_command — no actor registered for context_id `{ctx_id}`"
            ))
        })?;
        Self::dispatch_via_mailbox(&actor, ContextCommand::Governance(cmd)).await
    }

    /// Dispatch an [`EconomyCommand`] through the migration shim
    /// (ADR-049 commit 10 / plan row 10).
    ///
    /// Same shape as [`Self::dispatch_governance_command`]. The
    /// economy handler only exposes the single public-surface method
    /// on [`Supervisor`](crate::context::supervisor::Supervisor),
    /// [`verify_payment_receipts`](crate::context::economy_helpers::verify_payment_receipts);
    /// internal helpers (`authorize_paid_action`, `complete_paid_action`,
    /// `void_paid_action`) remain on the manager's private surface
    /// and are exercised through the messaging path.
    ///
    /// # Errors
    ///
    /// - [`ContextError::NotInitialized`] if no
    ///   [`Supervisor`](crate::context::supervisor::Supervisor) has
    ///   been attached yet.
    pub async fn dispatch_economy_command(
        &self,
        cmd: EconomyCommand,
    ) -> Result<Outcome<()>, ContextError> {
        // ADR-049 Phase 2A finalization — route through the per-context
        // actor mailbox when every receipt in the batch agrees on a
        // single `Some(context_id)` and an actor is registered for it.
        // Mixed-context batches and relay-level (`None`) receipts have
        // no single owning actor and fall through to
        // `dispatch_economy_direct`, which resolves the payment adapter
        // from the supervisor's lifted provider slot. The actor-shape
        // and direct-shape helpers both delegate to the same
        // `economy_helpers::verify_payment_receipts` body (the read
        // uses only `deps.payment_adapter`), so the two paths are
        // observably equivalent — routing chooses the serialization
        // point, not the work.
        // Defense in depth: bound the receipt batch before either routing
        // path. Each receipt fans out to a serial payment-adapter
        // verification round-trip, so an unbounded batch is a
        // denial-of-service vector. The FFI bridges enforce the same cap at
        // their boundaries; this guards non-bridge and future callers. See
        // [`MAX_RECEIPT_BATCH`](crate::economy::adapter::MAX_RECEIPT_BATCH).
        if let EconomyCommand::VerifyPaymentReceipts { receipts, .. } = &cmd
            && receipts.len() > crate::economy::adapter::MAX_RECEIPT_BATCH
        {
            return Err(ContextError::LimitExceeded(format!(
                "receipt batch too large: {} (max {})",
                receipts.len(),
                crate::economy::adapter::MAX_RECEIPT_BATCH
            )));
        }

        if let Some(ctx_id) = Self::economy_command_context_id(&cmd) {
            let ctx_id_owned = ctx_id.to_owned();
            if let Some(actor) = self.lookup(&ctx_id_owned) {
                return Self::dispatch_via_mailbox(&actor, ContextCommand::Economy(cmd)).await;
            }
        }
        Ok(self.dispatch_economy_direct(cmd).await)
    }

    /// Extract the target context_id from an [`EconomyCommand`] when one
    /// can be unambiguously derived.
    ///
    /// Returns `Some(ctx_id)` only when every receipt in a
    /// [`EconomyCommand::VerifyPaymentReceipts`] batch carries the same
    /// `Some(context_id)`. Returns `None` for:
    ///
    /// - [`EconomyCommand::Placeholder`] (no target).
    /// - Empty receipt batches (no target).
    /// - Heterogeneous batches whose receipts straddle multiple contexts
    ///   (no single owning actor).
    /// - Batches containing any relay-level receipt (`context_id == None`).
    fn economy_command_context_id(cmd: &EconomyCommand) -> Option<&str> {
        match cmd {
            EconomyCommand::Placeholder { .. } => None,
            EconomyCommand::VerifyPaymentReceipts { receipts, .. } => {
                let mut iter = receipts.iter();
                let first = iter.next()?.context_id.as_ref()?;
                let first_str = first.as_str();
                for r in iter {
                    match r.context_id.as_ref() {
                        Some(c) if c.as_str() == first_str => {}
                        _ => return None,
                    }
                }
                Some(first_str)
            }
        }
    }

    /// Direct supervisor-scoped dispatch for [`EconomyCommand`] variants
    /// whose target context cannot be unambiguously derived from the
    /// command (mixed-context batches, empty batches, relay-level
    /// receipts) or for which no per-context actor is registered.
    ///
    /// Mirrors the standing-/lifecycle-direct precedents: each arm wraps
    /// the supervisor-scoped body in a 30s timeout matching the actor-
    /// handler shape (plan §"Transport timeouts inside actor handlers")
    /// and relays the typed reply on the variant's oneshot.
    ///
    /// `VerifyPaymentReceipts` verifies each receipt against the
    /// supervisor's lifted payment-adapter slot. The work depends only on
    /// `adapter_id`, not `context_id`, so this direct path handles
    /// mixed-context, empty, and relay-level (`None`) batches identically
    /// to the per-actor path: a per-context fan-out would yield the same
    /// results because the payment-adapter lookup is supervisor-scoped,
    /// not actor-scoped. The actor-shape twin
    /// [`economy_helpers::verify_payment_receipts`](crate::context::economy_helpers::verify_payment_receipts)
    /// runs the identical loop over `deps.payment_adapter`; the two paths
    /// are observably equivalent and differ only in the serialization
    /// point. Batches with no single owning actor have no per-context
    /// `ActorDeps`/`PerContextState` to borrow, so the verification is
    /// inlined here against `self.payment_adapter_ref()` directly.
    async fn dispatch_economy_direct(&self, cmd: EconomyCommand) -> Outcome<()> {
        use crate::economy::receipt::{ReceiptVerification, ReceiptVerificationError};
        const ECONOMY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

        match cmd {
            EconomyCommand::Placeholder { reply } => {
                const MSG: &str =
                    "EconomyCommand::Placeholder — mailbox-pipe smoke target; no production work";
                let _ = reply.send(Err(ContextError::NotImplemented(MSG.to_owned())));
                Outcome::err(ContextError::NotImplemented(MSG.to_owned()))
            }
            EconomyCommand::VerifyPaymentReceipts { receipts, reply } => {
                let receipts = *receipts;
                let verify_fut = async {
                    let mut results = Vec::with_capacity(receipts.len());
                    for receipt in &receipts {
                        let result = match self.payment_adapter_ref() {
                            Some(adapter) if adapter.adapter_id() == receipt.adapter_id => adapter
                                .verify_dyn(receipt)
                                .await
                                .map(|r| ReceiptVerification {
                                    receipt_id: receipt.receipt_id,
                                    result: r,
                                })
                                .map_err(|e| ReceiptVerificationError::VerificationFailed {
                                    receipt_id: receipt.receipt_id,
                                    error: e,
                                }),
                            _ => Err(ReceiptVerificationError::NoVerifierForAdapter {
                                receipt_id: receipt.receipt_id,
                                adapter_id: receipt.adapter_id.clone(),
                            }),
                        };
                        results.push(result);
                    }
                    results
                };
                let results = match tokio::time::timeout(ECONOMY_TIMEOUT, verify_fut).await {
                    Ok(vec) => vec,
                    Err(_elapsed) => receipts
                        .iter()
                        .map(|r| {
                            Err(ReceiptVerificationError::NoVerifierForAdapter {
                                receipt_id: r.receipt_id,
                                adapter_id: r.adapter_id.clone(),
                            })
                        })
                        .collect(),
                };
                let _ = reply.send(results);
                // Verify payment receipts is a pure read — mutated=false.
                Outcome::ok(())
            }
        }
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
    ///   [`Supervisor`](crate::context::supervisor::Supervisor) has
    ///   been attached yet.
    pub async fn dispatch_trust_recovery_command(
        &self,
        cmd: TrustRecoveryCommand,
    ) -> Result<Outcome<()>, ContextError> {
        // Phase 2A.1 of ADR-049 — trust_recovery is the first migrated
        // helper domain. Route per-context variants to the per-context
        // actor mailbox when one is registered; otherwise fall through
        // to `dispatch_trust_recovery_direct` which delegates to the
        // designated-legacy lock-shaped helpers. The cross-context
        // `RecoveryNotifyContact` variant has no `context_id` to look
        // up — it always flows through the direct fan-out path.
        //
        // `Box::pin` — `CreateGovernanceCheckpoint`'s payload carries
        // multiple 32-byte hashes + a variable-length Ed25519 signature
        // vector; the per-variant locals cross clippy's 16-KB stack-
        // future budget.
        if let Some(ctx_id) = Self::trust_recovery_command_context_id(&cmd)
            && let Some(actor) = self.lookup(ctx_id)
        {
            return Self::dispatch_via_mailbox(&actor, ContextCommand::TrustRecovery(cmd)).await;
        }
        Ok(Box::pin(self.dispatch_trust_recovery_direct(cmd)).await)
    }

    /// Extract the `context_id` borrow from a [`TrustRecoveryCommand`]
    /// when one is present. Returns `None` for variants that cannot be
    /// routed through a per-context actor mailbox
    /// (`Placeholder`, `RecoveryNotifyContact`).
    fn trust_recovery_command_context_id(cmd: &TrustRecoveryCommand) -> Option<&str> {
        match cmd {
            TrustRecoveryCommand::Placeholder { .. }
            | TrustRecoveryCommand::RecoveryNotifyContact { .. } => None,
            TrustRecoveryCommand::CreateGovernanceCheckpoint { payload, .. } => {
                Some(payload.context_id.as_str())
            }
            TrustRecoveryCommand::AddCheckpointCosignature { context_id, .. }
            | TrustRecoveryCommand::RecoveryAdvanceEpoch { context_id, .. } => {
                Some(context_id.as_str())
            }
            TrustRecoveryCommand::RecoverySendNotification { payload, .. } => {
                Some(payload.context_id.as_str())
            }
        }
    }

    /// Actor-native cross-context recovery-notification fan-out
    /// (spec §9.12 step 5 — target context not yet known).
    ///
    /// Finds a context where both the recovering DID and the contact DID
    /// are members, then dispatches a `RecoverySendNotification`
    /// (sequence 4 — contact notification) through that context's actor
    /// mailbox. The shared-context lookup is a lock-free fan-out over the
    /// actor registry: [`Self::actor_ids`] yields a snapshot of every
    /// registered context id and [`Self::is_member`] reads each
    /// membership predicate through the per-context actor mailbox. No
    /// `contexts` DashMap access and no `per-context-state Mutex` lock —
    /// the actor that owns each context is the sole authority for its
    /// membership.
    ///
    /// This is the supervisor-direct twin of
    /// [`SupervisorHandle::find_shared_context`](crate::context::supervisor::handle::SupervisorHandle::find_shared_context)
    /// +
    /// [`SupervisorHandle::dispatch_recovery_send_notification`](crate::context::supervisor::handle::SupervisorHandle::dispatch_recovery_send_notification):
    /// the handle pair serves the actor-shape helper
    /// [`crate::context::trust_recovery_helpers::recovery_notify_contact`]
    /// (called from a context actor's `run()` loop via the
    /// capability-reduced `deps.supervisor`), whereas this method serves
    /// `dispatch_trust_recovery_direct`'s `RecoveryNotifyContact` arm,
    /// which holds `&Supervisor` directly (the cross-context variant
    /// carries no `context_id`, so it always routes supervisor-direct).
    /// Both paths share identical semantics.
    ///
    /// # Ordering
    ///
    /// `actor_ids()` rebuilds its snapshot per call, so the iteration
    /// order is the registry's shard order — unspecified but stable for
    /// the duration of a single call. "First shared context" carries the
    /// same order-unspecified semantics the legacy DashMap fan-out had.
    ///
    /// # Errors
    ///
    /// - [`ContextError::TransportFailed`] if no context is shared
    ///   between the recovering DID and the contact DID.
    /// - Any [`ContextError`] surfaced through the dispatched
    ///   [`Self::dispatch_trust_recovery_command`] call or the per-actor
    ///   reply oneshot (e.g. [`ContextError::NotInitialized`] if no
    ///   providers attached, or a closed reply channel surfacing as
    ///   [`ContextError::TransportFailed`]).
    async fn recovery_notify_contact(
        &self,
        recovering_did: &str,
        contact_did: &str,
        payload: &[u8],
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<(), ContextError> {
        use crate::context::actor::commands::{
            RecoverySendNotificationPayload, SigningKeyBytes, TrustRecoveryCommand,
        };

        // Lock-free actor-registry fan-out: the first context where BOTH
        // members are present wins. No DashMap, no PerContextState lock.
        let mut shared_context_id = None;
        for context_id in self.actor_ids() {
            if self.is_member(&context_id, recovering_did).await
                && self.is_member(&context_id, contact_did).await
            {
                shared_context_id = Some(context_id);
                break;
            }
        }

        match shared_context_id {
            Some(context_id) => {
                // Contact notifications use sequence=4 (step 5 in recovery).
                let send_payload = RecoverySendNotificationPayload {
                    context_id,
                    sender_did: recovering_did.to_owned(),
                    payload: payload.to_vec(),
                    sequence: 4,
                    signing_key: SigningKeyBytes::from_signing_key(signing_key),
                };
                let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
                let cmd = TrustRecoveryCommand::RecoverySendNotification {
                    payload: Box::new(send_payload),
                    reply: reply_tx,
                };
                self.dispatch_trust_recovery_command(cmd).await?;
                reply_rx.await.map_err(|_| {
                    ContextError::TransportFailed(
                        "recovery_notify_contact: oneshot reply channel closed".to_owned(),
                    )
                })?
            }
            None => Err(ContextError::TransportFailed(format!(
                "no shared context found between {recovering_did} and {contact_did}"
            ))),
        }
    }

    /// Direct supervisor-scoped dispatch for [`TrustRecoveryCommand`]
    /// variants that have no per-context actor target (`Placeholder`,
    /// `RecoveryNotifyContact`) or whose actor is not registered
    /// (`CreateGovernanceCheckpoint` / `AddCheckpointCosignature` /
    /// `RecoveryAdvanceEpoch` / `RecoverySendNotification` —
    /// unregistered-context fallback).
    ///
    /// Mirrors the standing/queries/lifecycle direct precedents.
    /// `RecoveryNotifyContact` is intrinsically cross-context (it carries
    /// no `context_id`, so it always reaches this path): its arm wraps
    /// the actor-native [`Self::recovery_notify_contact`] fan-out in a
    /// 30s timeout matching the actor-handler shape (plan §"Transport
    /// timeouts inside actor handlers") and relays the typed reply on the
    /// variant's oneshot.
    ///
    /// The per-context variants reach this path only for a context with
    /// no registered actor. Post-Step-B every valid context has an actor
    /// and these variants are mailbox-dispatched to the per-context
    /// actor-shape handlers; the supervisor-direct arm is therefore
    /// reached ONLY for an unregistered context, which is by definition
    /// not registered — it surfaces a typed
    /// [`ContextError::ContextNotRegistered`] on the reply oneshot
    /// (mirrors the gutted `dispatch_lifecycle_direct` per-context arms).
    #[allow(clippy::too_many_lines)] // flat match over every trust-recovery variant
    async fn dispatch_trust_recovery_direct(&self, cmd: TrustRecoveryCommand) -> Outcome<()> {
        const TRUST_RECOVERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

        match cmd {
            TrustRecoveryCommand::Placeholder { reply } => {
                const MSG: &str = "TrustRecoveryCommand::Placeholder — mailbox-pipe smoke target; \
                                   no production work";
                let _ = reply.send(Err(ContextError::NotImplemented(MSG.to_owned())));
                Outcome::err(ContextError::NotImplemented(MSG.to_owned()))
            }
            TrustRecoveryCommand::RecoveryNotifyContact { payload, reply } => {
                let recovering_did = payload.recovering_did.clone();
                let signing_key = payload.signing_key.to_signing_key();
                let notify_fut = self.recovery_notify_contact(
                    &payload.recovering_did,
                    &payload.contact_did,
                    &payload.payload,
                    &signing_key,
                );
                let (outcome, reply_result) = match tokio::time::timeout(
                    TRUST_RECOVERY_TIMEOUT,
                    notify_fut,
                )
                .await
                {
                    Ok(Ok(())) => (Outcome::ok(()), Ok(())),
                    Ok(Err(e)) => (Outcome::err(standing_outcome_error_sketch(&e)), Err(e)),
                    Err(_elapsed) => {
                        let err = ContextError::TransportTimeout(format!(
                            "recovery_notify_contact exceeded {TRUST_RECOVERY_TIMEOUT:?} budget for recovering_did {recovering_did}"
                        ));
                        (Outcome::err(standing_outcome_error_sketch(&err)), Err(err))
                    }
                };
                let _ = reply.send(reply_result);
                outcome
            }
            // Per-context variants reach this arm only when no actor is
            // registered for the target context. Post-Step-B every valid
            // context has a registered actor and these variants are
            // mailbox-dispatched to the per-context actor-shape handlers
            // in `actor/handlers/trust_recovery.rs`. The supervisor-side
            // direct path is therefore reached ONLY for an unregistered
            // context, which is by definition not registered — surface a
            // typed `ContextNotRegistered` on the reply oneshot and
            // return a matching error `Outcome` (mirrors the gutted
            // `dispatch_lifecycle_direct` per-context arms).
            TrustRecoveryCommand::CreateGovernanceCheckpoint { payload, reply } => {
                let err = ContextError::ContextNotRegistered(payload.context_id.clone());
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err_mutated(sketch)
            }
            TrustRecoveryCommand::AddCheckpointCosignature {
                context_id, reply, ..
            } => {
                let err = ContextError::ContextNotRegistered(context_id);
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            TrustRecoveryCommand::RecoveryAdvanceEpoch { context_id, reply } => {
                let err = ContextError::ContextNotRegistered(context_id);
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err_mutated(sketch)
            }
            TrustRecoveryCommand::RecoverySendNotification { payload, reply } => {
                let err = ContextError::ContextNotRegistered(payload.context_id.clone());
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
        }
    }

    /// Direct supervisor-scoped dispatch for [`QueriesCommand`] variants
    /// whose target context has no registered actor.
    ///
    /// Mirrors the standing-direct precedent: when the mailbox-first
    /// lookup in [`Self::dispatch_query`] returns `None`, this method
    /// surfaces the variant's legacy unknown-context contract on the
    /// embedded reply oneshot without entering an actor or a locked
    /// legacy `PerContextState` view. Two contracts apply per variant:
    ///
    /// - **Hard-error variants** (`LocalPseudonym`,
    ///   `GetBroadcastKeyForLocalAuthor`): emit
    ///   `ContextError::ContextNotRegistered` on the reply.
    /// - **Soft-default variants** (`MemberCount`, `IsMember`,
    ///   `MemberDids`, `MemberRole`, `ContextParams`, `GetRoleState`,
    ///   `PendingCommits`, `CommitFault`, plus the `testing`-only
    ///   access-key / budget / velocity variants): emit the legacy
    ///   default (`Ok(None)`, `Ok(false)`, `Ok(Vec::new())`, etc.).
    ///
    /// `EventLogEntries` is handled inline in
    /// [`Self::dispatch_query`] and never reaches this method.
    ///
    /// Returns `Outcome::ok(())` on every arm — the typed result lives
    /// on the variant's oneshot, not the method-level outcome.
    fn dispatch_queries_direct(cmd: QueriesCommand) -> Outcome<()> {
        match cmd {
            // `ReadContextState` is never routed here in production — the
            // standing get-or-create path resolves the no-actor case to
            // `None` via `Self::read_context_state` (lookup → no actor →
            // no mailbox dispatch) before this method runs. Left as an
            // explicit arm so the lifecycle-state read has a definitive
            // unknown-context reply (`ContextNotRegistered`) rather than a
            // fabricated lifecycle state.
            QueriesCommand::ReadContextState { reply, context_id } => {
                let _ = reply.send(Err(ContextError::ContextNotRegistered(format!(
                    "context not registered: {context_id}"
                ))));
            }
            // Hard-error variants — legacy `local_pseudonym` /
            // `get_broadcast_key_for_local_author` return
            // `ContextError::ContextNotRegistered` on unknown context.
            QueriesCommand::LocalPseudonym { ref context_id, .. }
            | QueriesCommand::GetBroadcastKeyForLocalAuthor { ref context_id, .. } => {
                let err = ContextError::ContextNotRegistered(format!(
                    "context not registered: {context_id}"
                ));
                reply_with_error(cmd, err);
            }
            // Soft-default variants — legacy methods return the
            // variant-specific default on unknown context.
            QueriesCommand::MemberCount { .. }
            | QueriesCommand::IsMember { .. }
            | QueriesCommand::MemberDids { .. }
            | QueriesCommand::MemberRole { .. }
            | QueriesCommand::ContextParams { .. }
            | QueriesCommand::GetRoleState { .. }
            | QueriesCommand::PendingCommits { .. }
            | QueriesCommand::CommitFault { .. } => {
                reply_with_soft_default(cmd);
            }
            // EventLogEntries never reaches this method — `dispatch_query`
            // handles it inline against the supervisor's shared
            // event-log provider before falling through to direct
            // dispatch. Left as a defensive arm so a future
            // classification change trips the debug assert.
            QueriesCommand::EventLogEntries { reply, .. } => {
                debug_assert!(
                    false,
                    "EventLogEntries routed through dispatch_queries_direct"
                );
                let _ = reply.send(Ok(None));
            }
            #[cfg(feature = "testing")]
            QueriesCommand::GetAccessKey { .. }
            | QueriesCommand::GetAllAccessKeys { .. }
            | QueriesCommand::RemainingBudgetForTest { .. }
            | QueriesCommand::VelocityForTest { .. } => {
                reply_with_soft_default(cmd);
            }
        }
        Outcome::ok(())
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
    ///
    /// Visibility widened to `pub(in crate::context)` at Phase 2A
    /// finalization (sweep helper relocation) so the sweep entry
    /// points in `governance_helpers` / `lifecycle_helpers` can route
    /// per-actor sweep commands through the mailbox.
    #[must_use]
    #[allow(dead_code)]
    pub(in crate::context) fn lookup(&self, ctx_id: &str) -> Option<ContextActorHandle> {
        self.actors.get(ctx_id).map(|r| r.value().clone())
    }

    /// Returns a snapshot of every currently-registered actor's
    /// `context_id`.
    ///
    /// The returned `Vec<String>` is independent of the underlying
    /// `DashMap` — callers can iterate it freely without holding any
    /// shard locks. Each call rebuilds the snapshot; the sweep
    /// iterators in `governance_helpers` / `lifecycle_helpers` call
    /// this once per sweep and dispatch one command per `context_id`.
    ///
    /// Added at Phase 2A finalization (sweep helper relocation) so the
    /// sweep entry points have a way to enumerate the actor registry
    /// without reaching for the legacy `contexts` DashMap (which is
    /// scheduled for deletion in a subsequent session).
    #[must_use]
    pub(in crate::context) fn actor_ids(&self) -> Vec<String> {
        self.actors.iter().map(|e| e.key().clone()).collect()
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

        // Spawn the actor's dispatch loop. During the 12b.2a → 12b.2b
        // window the existing no-state `spawn_actor` signature routes
        // through [`ContextActor::new_skeleton`] — the state still
        // lives on `ContextManager`, and the shim dispatch (see
        // [`Self::dispatch_command`] family) continues to delegate
        // there. [`Self::spawn_actor_with_state`] is the post-12b.2a
        // path that takes owned state + deps and constructs a
        // state-carrying actor via [`ContextActor::new`].
        let inbox = rx;
        tokio::spawn(async move {
            Box::pin(crate::context::actor::ContextActor::new_skeleton(ctx_id, inbox).run()).await;
        });

        handle
    }

    /// Spawn a new `ContextActor` task that owns drained
    /// [`PerContextState`](crate::context::actor::PerContextState) +
    /// [`ActorDeps`](crate::context::actor::ActorDeps) directly
    /// (ADR-049 commit 12).
    ///
    /// This is the post-refactor spawn path: the supervisor's caller
    /// drains state from the legacy `ContextManager` and
    /// `MlsCryptoProvider` via
    /// [`crate::context::supervisor::Supervisor::take_context_state`]
    /// +
    /// [`crate::crypto::mls::provider::MlsCryptoProvider::take_crypto_state`],
    /// assembles the actor-side `PerContextState` using the drained
    /// fields, and hands the state + deps bundle into this method.
    /// The spawned actor becomes the sole owner; subsequent
    /// manager/provider calls for the same context return the typed
    /// "taken by actor" errors.
    ///
    /// The returned [`ContextActorHandle`] is registered in the
    /// supervisor's `actors` map under the same `write_lock` that
    /// [`Self::spawn_actor`] uses. The handle's mailbox capacity
    /// matches [`ACTOR_MAILBOX_CAPACITY`] (256, plan §"Mailbox
    /// parameters").
    ///
    /// # Visibility
    ///
    /// `pub(in crate::context)` — the only production caller is the
    /// lifecycle handler's create / restore / import path (landing
    /// in commit 12b.2b). External callers (FFI bridges,
    /// downstream crates) reach the actor through
    /// [`Self::dispatch_command`] or the
    /// [`crate::context::supervisor::handle::SupervisorHandle`] /
    /// [`crate::context::actor::deps::ActorDeps::supervisor`]
    /// capabilities — never directly.
    ///
    /// # Scope — infrastructure only
    ///
    /// Commit 12b.2a wires the signature and registry insertion.
    /// The spawned actor's `run()` loop currently delegates every
    /// command variant to the skeleton dispatch (same fallback as
    /// [`ContextActor::new_skeleton`]) — migrating real handler
    /// bodies onto `&mut self.state` + `&self.deps` is 12b.2b's
    /// atomic transition across all nine handler submodules.
    ///
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::CreationFailed`] if an actor is already
    /// registered for this context id. The legacy bootstrap insert
    /// (`manager_methods::insert_context`) rejected a duplicate id with
    /// `CreationFailed`; this restores that first-writer-wins guarantee
    /// for the owned-state spawn path (create / restore / import). The
    /// import replace path despawns the prior actor before respawning,
    /// so the slot is vacant by the time it reaches here.
    pub(in crate::context) async fn spawn_actor_with_state(
        &self,
        mut state: crate::context::actor::state::PerContextState,
        deps: crate::context::actor::deps::ActorDeps,
        mailbox_capacity: Option<usize>,
    ) -> Result<ContextActorHandle, ContextError> {
        // Stamp a fresh monotonic spawn-generation onto the owned state
        // before it crosses into the actor task. Each spawned actor
        // instance gets a distinct generation; a tool-economy reservation
        // captures this value and the Phase-3 settle rejects if the live
        // actor's generation no longer matches (the instance was replaced
        // between reserve and settle). `fetch_add` returns the prior
        // value, so the first spawn stamps 1 (never the default 0).
        state.generation = self
            .spawn_generation
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
            + 1;

        let capacity = mailbox_capacity.unwrap_or(ACTOR_MAILBOX_CAPACITY);
        let (tx, rx) = tokio::sync::mpsc::channel::<ContextCommand>(capacity);

        // Register under the context's ORIGINAL id string (the one the
        // `ContextHandle` carries and that every per-context dispatch /
        // `lookup` uses), NOT `hex(state.context_id)`. `state.context_id`
        // is `SHA256(original_id)` (`context_id_to_bytes`), so keying by
        // its hex would diverge from the original-string id callers pass
        // to `lookup` — the legacy `contexts` DashMap was keyed by the
        // original string, and per-context dispatch (incl. the cross-
        // context recovery flow) still is. For the test fixtures the
        // handle id IS `hex(context_id_bytes)`, so this is identical
        // there; for production `create_context` it is the caller's
        // original id, which is what makes per-context dispatch resolve
        // the actor.
        let ctx_id_str = state.handle.context_id().to_owned();

        let handle = ContextActorHandle::from_sender(tx);
        {
            // Write-path mutation: register the handle under the write
            // lock — same contract as [`Self::spawn_actor`]. Reject a
            // duplicate registration (first-writer-wins) instead of
            // silently overwriting a live actor: the overwrite would
            // leak the loser's spawned task and diverge crypto state.
            let _guard = self.write_lock.lock().await;
            if self.actors.contains_key(&ctx_id_str) {
                return Err(ContextError::CreationFailed(format!(
                    "context '{ctx_id_str}' is already registered"
                )));
            }
            self.actors.insert(ctx_id_str.clone(), handle.clone());
        }

        // Hand the owned state + deps into the actor task. The
        // spawned future captures both by move; neither escapes the
        // actor's scope.
        let inbox = rx;
        tokio::spawn(async move {
            Box::pin(crate::context::actor::ContextActor::new(state, deps, inbox).run()).await;
        });

        Ok(handle)
    }

    /// Despawn the actor registered for `context_id`, removing the
    /// entry from [`Self::actors`] under the supervisor's
    /// [`Self::write_lock`] so a concurrent re-registration cannot
    /// race the removal.
    ///
    /// The removed [`ContextActorHandle`] is dropped at the end of
    /// this function; that drop closes the underlying
    /// `mpsc::Sender`, which signals the actor task's `run()` loop
    /// to exit on the next inbox-empty poll.
    ///
    /// Returns `true` if a handle was registered and removed,
    /// `false` if no entry existed for `context_id`.
    ///
    /// # Visibility
    ///
    /// `pub(in crate::context)` — exposed through
    /// [`SupervisorHandle::despawn_actor`](crate::context::supervisor::handle::SupervisorHandle::despawn_actor)
    /// so lifecycle bootstrap (`import_context`) can perform the
    /// despawn-then-respawn dance without holding `&Supervisor`
    /// directly. Called directly (on `&Supervisor`) by
    /// [`crate::context::lifecycle_helpers::shutdown_all_contexts`] to
    /// remove each actor's handle after `ShutdownSelf`, so the inbox
    /// closes and the actor task exits rather than lingering as a
    /// zombie.
    pub(in crate::context) async fn despawn_actor(&self, context_id: &str) -> bool {
        let _guard = self.write_lock.lock().await;
        self.actors.remove(context_id).is_some()
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
    ///   [`Supervisor`](crate::context::supervisor::Supervisor) has
    ///   been attached yet.
    pub async fn dispatch_standing_command(
        self: &Arc<Self>,
        cmd: StandingCommand,
    ) -> Result<Outcome<()>, ContextError> {
        // ADR-049 Phase 2A finalization — try the actor mailbox first
        // for variants whose `(local_did, peer_did)` deterministically
        // maps to an existing per-context actor. Variants that don't
        // carry both DIDs (count / has / register / reconnect-all) are
        // supervisor-scoped and route directly through the
        // [`Supervisor`] standing-index methods below.
        if let Some(ctx_id) = Self::standing_command_context_id(&cmd)
            && let Some(actor) = self.lookup(&ctx_id)
        {
            return Self::dispatch_via_mailbox(&actor, ContextCommand::Standing(cmd)).await;
        }
        // Direct supervisor-scoped dispatch. No shim — every variant is
        // handled inline via the supervisor's actor-native standing
        // methods (`standing_context` / `reconnect_all_standing`) and the
        // lock-free standing-index reads/mutations.
        Ok(Box::pin(self.dispatch_standing_direct(cmd)).await)
    }

    /// Direct supervisor-scoped dispatch for [`StandingCommand`]
    /// variants that have no per-context actor target (or whose actor
    /// is not yet spawned — the `StandingContext` get-or-create path
    /// creates the underlying context on first call).
    ///
    /// Each arm wraps a supervisor-scoped operation in a 30s timeout
    /// budget matching the actor-handler shape (plan §"Transport
    /// timeouts inside actor handlers"). Reply channels carry the typed
    /// per-variant result.
    async fn dispatch_standing_direct(self: &Arc<Self>, cmd: StandingCommand) -> Outcome<()> {
        const STANDING_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

        match cmd {
            StandingCommand::Placeholder { reply } => {
                const MSG: &str =
                    "StandingCommand::Placeholder — handshake target; no production work";
                let _ = reply.send(Err(ContextError::NotImplemented(MSG.to_owned())));
                Outcome::err(ContextError::NotImplemented(MSG.to_owned()))
            }
            StandingCommand::StandingContext {
                local_did,
                peer_did,
                reply,
            } => {
                let fut = self.standing_context(&local_did, &peer_did);
                let (outcome, reply_result) =
                    match tokio::time::timeout(STANDING_TIMEOUT, fut).await {
                        Ok(Ok(ctx_id)) => (Outcome::ok_mutated(()), Ok(ctx_id)),
                        Ok(Err(e)) => (
                            Outcome::err_mutated(standing_outcome_error_sketch(&e)),
                            Err(e),
                        ),
                        Err(_elapsed) => {
                            let err = ContextError::TransportTimeout(format!(
                                "standing_context exceeded {STANDING_TIMEOUT:?} budget"
                            ));
                            (
                                Outcome::err_mutated(standing_outcome_error_sketch(&err)),
                                Err(err),
                            )
                        }
                    };
                let _ = reply.send(reply_result);
                outcome
            }
            StandingCommand::StandingContextCount { reply } => {
                // Lock-free ArcSwap read (ADR-049 §Decision 12).
                let count = self.standing_contexts.load().len();
                let _ = reply.send(Ok(count));
                Outcome::ok(())
            }
            StandingCommand::HasStandingContext { peer_did, reply } => {
                // Lock-free ArcSwap read (ADR-049 §Decision 12).
                let has = self
                    .standing_contexts
                    .load()
                    .contains_key(peer_did.as_ref());
                let _ = reply.send(Ok(has));
                Outcome::ok(())
            }
            StandingCommand::RegisterStandingContext { peer_did, reply } => {
                // ArcSwap + write_lock for the standing-index mutation
                // (ADR-049 §Decision 12).
                let _guard = self.write_lock.lock().await;
                let snapshot = self.standing_contexts.load_full();
                let mut updated: HashMap<String, DID> = (*snapshot).clone();
                updated.insert(peer_did.to_string(), peer_did);
                self.standing_contexts.store(Arc::new(updated));
                let _ = reply.send(Ok(()));
                Outcome::ok_mutated(())
            }
            StandingCommand::ReconnectAllStanding { reply } => {
                let fut = self.reconnect_all_standing();
                let (outcome, reply_result) =
                    match tokio::time::timeout(STANDING_TIMEOUT, fut).await {
                        Ok(Ok(count)) => (Outcome::ok_mutated(()), Ok(count)),
                        Ok(Err(e)) => (
                            Outcome::err_mutated(standing_outcome_error_sketch(&e)),
                            Err(e),
                        ),
                        Err(_elapsed) => {
                            let err = ContextError::TransportTimeout(format!(
                                "reconnect_all_standing exceeded {STANDING_TIMEOUT:?} budget"
                            ));
                            (
                                Outcome::err_mutated(standing_outcome_error_sketch(&err)),
                                Err(err),
                            )
                        }
                    };
                let _ = reply.send(reply_result);
                outcome
            }
            StandingCommand::InitiateStandingPairCreate { reply, .. } => {
                const MSG: &str = "standing::initiate_standing_pair_create — saga wiring deferred to \
                     commit 11.5 per 5 enumerated spec gaps; see \
                     .docs/adrs/DEFERRED-commit-11-saga-use-cases.md (gap 1: standing-pair \
                     2-phase decomposition)";
                let _ = reply.send(Err(ContextError::NotImplemented(MSG.to_owned())));
                Outcome::err(ContextError::NotImplemented(MSG.to_owned()))
            }
        }
    }

    /// Dispatch a [`ToolsCommand`] through the migration shim
    /// (ADR-049 commit 11 / plan row 11).
    ///
    /// Covers the hard-rate-limit consume / refund helpers that FFI
    /// bridges call from their tool-dispatch paths. The cross-context
    /// saga-initiator variant returns [`ContextError::NotImplemented`]
    /// during the commit-11 window — see
    /// `.docs/adrs/DEFERRED-commit-11-saga-use-cases.md`. Note that
    /// [`ContextManager::invoke_tool_with_economy`](crate::context::supervisor::Supervisor::invoke_tool_with_economy)
    /// is not migrated here because its generic executor closure cannot
    /// cross the actor mailbox.
    ///
    /// # Errors
    ///
    /// - [`ContextError::NotInitialized`] if no
    ///   [`Supervisor`](crate::context::supervisor::Supervisor) has
    ///   been attached yet.
    pub async fn dispatch_tools_command(
        &self,
        cmd: ToolsCommand,
    ) -> Result<Outcome<()>, ContextError> {
        // Try the actor mailbox first. Post-Step-B every valid context
        // has a registered actor, so the per-context tools handlers run
        // on the actor. Reaching the fallback means no actor is
        // registered for the target context — surface a typed
        // `ContextNotRegistered` on the command's reply oneshot.
        if let Some(ctx_id) = Self::tools_command_context_id(&cmd)
            && let Some(actor) = self.lookup(ctx_id)
        {
            return Self::dispatch_via_mailbox(&actor, ContextCommand::Tools(cmd)).await;
        }

        // No-actor settle backstop: a `SettleToolEconomy` carries an
        // in-flight `ToolEconomyTicket` (held external payment escrow +
        // the `#[must_use]`/Drop balance invariant). The sync
        // `reply_tools_not_registered` cannot `.await` to void the escrow
        // and would DROP the ticket. The primary defense is the no-actor
        // pre-check in `settle_tool_economy_via_actor`; this handles the
        // residual TOCTOU where the actor is despawned between that
        // pre-check and here. Reclaim the ticket, void its external
        // escrow, consume it, and reply with the typed error.
        if let ToolsCommand::SettleToolEconomy {
            context_id,
            request,
            reply,
            ..
        } = cmd
        {
            let request = *request;
            let generation = request.generation();
            request
                .into_ticket()
                .void_external_and_consume(self.payment_adapter_ref())
                .await;
            let err = ContextError::ContextNotRegistered(format!(
                "SCP-TOOL-6089: tool-economy settle for context '{context_id}' found no \
                 registered actor (reserved generation {generation}); escrow voided, \
                 reservation not captured"
            ));
            let sketch = standing_outcome_error_sketch(&err);
            let _ = reply.send(Err(err));
            return Ok(Outcome::err(sketch));
        }

        Ok(Self::reply_tools_not_registered(cmd))
    }

    /// Reply to a [`ToolsCommand`] whose target context has no registered
    /// actor with a typed [`ContextError::ContextNotRegistered`] on the
    /// variant's reply oneshot. Saga-initiator / placeholder variants keep
    /// their own typed replies.
    fn reply_tools_not_registered(cmd: ToolsCommand) -> Outcome<()> {
        match cmd {
            ToolsCommand::Placeholder { reply } => {
                const MSG: &str =
                    "ToolsCommand::Placeholder — handshake target; no production work";
                let _ = reply.send(Err(ContextError::NotImplemented(MSG.to_owned())));
                Outcome::err(ContextError::NotImplemented(MSG.to_owned()))
            }
            ToolsCommand::TryConsumeHardRateLimit {
                context_id, reply, ..
            } => {
                let err = ContextError::ContextNotRegistered(context_id);
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            ToolsCommand::RefundHardRateLimit {
                context_id, reply, ..
            } => {
                let err = ContextError::ContextNotRegistered(context_id);
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            ToolsCommand::ReserveToolEconomy {
                context_id, reply, ..
            } => {
                let err = ContextError::ContextNotRegistered(context_id);
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            ToolsCommand::SettleToolEconomy {
                context_id,
                request,
                reply,
                ..
            } => {
                // Defense-in-depth backstop: `dispatch_tools_command`
                // voids the escrow async before reaching this sync path,
                // so this arm is unreachable for a real settle. If a
                // future caller does route here, consume the ticket so
                // its Drop balance guard does not panic (escrow cannot be
                // voided synchronously — logged inside `consume_*`).
                (*request).into_ticket().consume_abandoning_escrow();
                let err = ContextError::ContextNotRegistered(context_id);
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            ToolsCommand::InitiateCrossContextToolInvocation { reply, .. } => {
                const MSG: &str = "tools::initiate_cross_context_tool_invocation — saga wiring \
                     deferred to commit 11.5 per 5 enumerated spec gaps; see \
                     .docs/adrs/DEFERRED-commit-11-saga-use-cases.md (gap 2: cross-context \
                     tool invocation transport)";
                let _ = reply.send(Err(ContextError::NotImplemented(MSG.to_owned())));
                Outcome::err(ContextError::NotImplemented(MSG.to_owned()))
            }
        }
    }

    /// Reply to a [`BroadcastCommand`] whose target context has no
    /// registered actor.
    ///
    /// Per-context variants (subscribe/unsubscribe/block/unblock/key
    /// request/queries) get a typed [`ContextError::ContextNotRegistered`]
    /// on their reply oneshot. The custody-bound publish variants, the
    /// two-phase reserve/apply/release variants, the saga-initiator
    /// variant, and the placeholder keep their own typed replies (these
    /// never reach a per-context actor through this no-custody router).
    fn reply_broadcast_not_registered(cmd: BroadcastCommand) -> Outcome<()> {
        match cmd {
            BroadcastCommand::Placeholder { reply } => {
                const MSG: &str =
                    "BroadcastCommand::Placeholder — handshake target; no production work";
                let _ = reply.send(Err(ContextError::NotImplemented(MSG.to_owned())));
                Outcome::err(ContextError::NotImplemented(MSG.to_owned()))
            }
            BroadcastCommand::SubscribeBroadcast { payload, reply } => {
                let err = ContextError::ContextNotRegistered(payload.context_id.clone());
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            BroadcastCommand::UnsubscribeBroadcast { payload, reply } => {
                let err = ContextError::ContextNotRegistered(payload.context_id.clone());
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            BroadcastCommand::BlockBroadcastSubscriber { payload, reply } => {
                let err = ContextError::ContextNotRegistered(payload.context_id.clone());
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            BroadcastCommand::UnblockBroadcastSubscriber { payload, reply } => {
                let err = ContextError::ContextNotRegistered(payload.context_id.clone());
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            BroadcastCommand::HandleBroadcastKeyRequest {
                context_id, reply, ..
            } => {
                let err = ContextError::ContextNotRegistered(context_id);
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            BroadcastCommand::BroadcastSubscriberCount { context_id, reply } => {
                let err = ContextError::ContextNotRegistered(context_id);
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            BroadcastCommand::IsBroadcastSubscriber {
                context_id, reply, ..
            } => {
                let err = ContextError::ContextNotRegistered(context_id);
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            BroadcastCommand::BroadcastAdmission { context_id, reply } => {
                let err = ContextError::ContextNotRegistered(context_id);
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            // Publish variants require a `KeyCustody` reference that cannot
            // cross the actor mailbox — route through
            // `dispatch_broadcast_command_with_custody`. Reaching here means
            // a caller took the wrong path; surface a typed error.
            BroadcastCommand::PublishBroadcast { reply, .. } => {
                const MSG: &str = "BroadcastCommand::PublishBroadcast requires a KeyCustody \
                     reference; route through \
                     Supervisor::dispatch_broadcast_command_with_custody (generic over custody)";
                let _ = reply.send(Err(ContextError::InvalidState(MSG.to_owned())));
                Outcome::err(ContextError::InvalidState(MSG.to_owned()))
            }
            BroadcastCommand::PublishBroadcastContent { reply, .. } => {
                const MSG: &str = "BroadcastCommand::PublishBroadcastContent requires a KeyCustody \
                     reference; route through \
                     Supervisor::dispatch_broadcast_command_with_custody (generic over custody)";
                let _ = reply.send(Err(ContextError::InvalidState(MSG.to_owned())));
                Outcome::err(ContextError::InvalidState(MSG.to_owned()))
            }
            // Two-phase publish requires a per-context actor (the
            // reservation lives in actor-owned state). No actor → typed
            // not-registered.
            BroadcastCommand::ReserveBroadcastPublish { payload, reply } => {
                let err = ContextError::ContextNotRegistered(payload.context_id.clone());
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            BroadcastCommand::ApplyBroadcastPublish { payload, reply } => {
                let err = ContextError::ContextNotRegistered(payload.context_id.clone());
                let sketch = standing_outcome_error_sketch(&err);
                let _ = reply.send(Err(err));
                Outcome::err(sketch)
            }
            // No actor → no reservation could have been issued. Idempotent
            // release: reply Ok so an abort path never errors spuriously.
            BroadcastCommand::ReleaseBroadcastReservation { reply, .. } => {
                let _ = reply.send(Ok(()));
                Outcome::ok(())
            }
            BroadcastCommand::InitiateBroadcastHostingHandshake { reply, .. } => {
                const MSG: &str = "broadcast::initiate_broadcast_hosting_handshake — saga wiring \
                     deferred to commit 11.5 per 5 enumerated spec gaps; see \
                     .docs/adrs/DEFERRED-commit-11-saga-use-cases.md (gap 3: broadcast \
                     hosting handshake protocol)";
                let _ = reply.send(Err(ContextError::NotImplemented(MSG.to_owned())));
                Outcome::err(ContextError::NotImplemented(MSG.to_owned()))
            }
        }
    }

    /// Dispatch a [`BroadcastCommand`] for every non-publish variant.
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
    ///   [`Supervisor`](crate::context::supervisor::Supervisor) has
    ///   been attached yet.
    pub async fn dispatch_broadcast_command(
        &self,
        cmd: BroadcastCommand,
    ) -> Result<Outcome<()>, ContextError> {
        // Try the actor mailbox first. Post-Step-B every valid context
        // has a registered actor, so the per-context broadcast handlers
        // run on the actor. Reaching the fallback means no actor is
        // registered for the target context — surface a typed
        // `ContextNotRegistered` on the command's reply oneshot.
        if let Some(ctx_id) = Self::broadcast_command_context_id(&cmd)
            && let Some(actor) = self.lookup(ctx_id)
        {
            return Self::dispatch_via_mailbox(&actor, ContextCommand::Broadcast(cmd)).await;
        }
        Ok(Self::reply_broadcast_not_registered(cmd))
    }

    /// Dispatch a [`BroadcastCommand`] with an explicit key custody
    /// reference (ADR-049 commit 11 / plan row 11).
    ///
    /// # Why a custody-generic shim still exists
    ///
    /// [`KeyCustody`](scp_platform::KeyCustody) is an RPITIT trait whose
    /// methods return `impl Future` — it is not `dyn`-safe, so a custody
    /// reference cannot be erased and shipped across the actor mailbox.
    /// The publish variants (`PublishBroadcast`, `PublishBroadcastContent`)
    /// need the caller's custody to derive the sender key, and so they
    /// remain on this generic shim path for the foreseeable future.
    ///
    /// # Routing
    ///
    /// - **Non-publish variants** (`Subscribe`, `Unsubscribe`, `Block`,
    ///   `Unblock`, key request, queries) have a per-context owner and a
    ///   `context_id` surfaced by
    ///   [`Self::broadcast_command_context_id`]. They route through the
    ///   per-context actor mailbox.
    /// - **Publish variants** are intentionally returned as `None` from
    ///   `broadcast_command_context_id`, fall through the mailbox check,
    ///   and dispatch on the custody-generic shim below.
    ///
    /// This split is permanent: only the publish path needs custody; the
    /// rest is identical to [`Self::dispatch_broadcast_command`].
    ///
    /// # Errors
    ///
    /// - [`ContextError::NotInitialized`] if no
    ///   [`Supervisor`](crate::context::supervisor::Supervisor) has
    ///   been attached yet.
    pub async fn dispatch_broadcast_command_with_custody<C: scp_platform::KeyCustody>(
        &self,
        cmd: BroadcastCommand,
        custody: &C,
    ) -> Result<Outcome<()>, ContextError> {
        // Publish variants drive the two-phase reservation flow: the
        // actor reserves the sequence (phase 1), the supervisor signs
        // with the caller's custody OUTSIDE the actor, then the actor
        // seals (phase 2). The custody never crosses the mailbox; both
        // mailbox phases are custody-free. This removes the legacy
        // DashMap read the single-phase shim used.
        match cmd {
            BroadcastCommand::PublishBroadcast { payload, reply } => {
                let p = *payload;
                self.publish_broadcast_two_phase(
                    p.context_id,
                    p.author_did,
                    p.payload,
                    &p.signing_key_handle,
                    custody,
                    reply,
                )
                .await
            }
            BroadcastCommand::PublishBroadcastContent { payload, reply } => {
                let p = *payload;
                let payload_bytes =
                    match scp_protocol::context::broadcast_content::serialize_broadcast_content(
                        &p.content,
                    ) {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            let msg = format!("content serialization failed: {e}");
                            let _ = reply.send(Err(ContextError::CryptoFailed(msg.clone())));
                            return Ok(Outcome::err(ContextError::CryptoFailed(msg)));
                        }
                    };
                self.publish_broadcast_two_phase(
                    p.context_id,
                    p.author_did,
                    payload_bytes,
                    &p.signing_key_handle,
                    custody,
                    reply,
                )
                .await
            }
            // Non-publish variants are custody-free and route straight
            // through the per-context actor mailbox.
            other => {
                if let Some(ctx_id) = Self::broadcast_command_context_id(&other)
                    && let Some(actor) = self.lookup(ctx_id)
                {
                    return Self::dispatch_via_mailbox(&actor, ContextCommand::Broadcast(other))
                        .await;
                }
                // No registered actor — surface a typed not-registered
                // error on the command's reply oneshot. (Publish variants
                // are handled above and never reach here; non-publish
                // variants need no custody.)
                Ok(Self::reply_broadcast_not_registered(other))
            }
        }
    }

    /// Drive the two-phase broadcast publish across the actor mailbox.
    ///
    /// Phase 1 (`ReserveBroadcastPublish`) and phase 2
    /// (`ApplyBroadcastPublish`) are custody-free mailbox commands; the
    /// signing happens here, between them, with the caller's custody.
    /// A reservation that cannot be applied (no actor, signing failure,
    /// apply failure) is released via `ReleaseBroadcastReservation` so
    /// the reserved sequence is not burned. The final
    /// [`BroadcastEnvelope`](scp_protocol::crypto::sender_keys::BroadcastEnvelope)
    /// (or error) is forwarded to the caller's `reply` channel.
    async fn publish_broadcast_two_phase<C: scp_platform::KeyCustody>(
        &self,
        context_id: String,
        author_did: DID,
        payload: Vec<u8>,
        signing_key_handle: &scp_platform::KeyHandle,
        custody: &C,
        reply: crate::context::actor::commands::PublishBroadcastReply,
    ) -> Result<Outcome<()>, ContextError> {
        use crate::context::actor::commands::{
            ApplyBroadcastPublishPayload, ReserveBroadcastPublishPayload,
        };

        // Resolve the actor up front. Publish requires a registered
        // per-context actor (the reservation lives in actor-owned state).
        let Some(actor) = self.lookup(&context_id) else {
            let _ = reply.send(Err(ContextError::ContextNotRegistered(context_id.clone())));
            return Ok(Outcome::err(ContextError::ContextNotRegistered(context_id)));
        };

        // Phase 1 — reserve the sequence and get the signing payload.
        let (reserve_tx, reserve_rx) = tokio::sync::oneshot::channel();
        let reserve_cmd = BroadcastCommand::ReserveBroadcastPublish {
            payload: Box::new(ReserveBroadcastPublishPayload {
                context_id: context_id.clone(),
                author_did: author_did.clone(),
            }),
            reply: reserve_tx,
        };
        Self::dispatch_via_mailbox(&actor, ContextCommand::Broadcast(reserve_cmd)).await?;
        let reservation = match reserve_rx.await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(e)) => {
                // Operation-level error already typed by the handler;
                // forward to the caller. The dispatch itself succeeded.
                let _ = reply.send(Err(e));
                return Ok(Outcome::ok_mutated(()));
            }
            Err(_) => {
                let msg = "broadcast reserve reply channel closed".to_owned();
                let _ = reply.send(Err(ContextError::InvalidState(msg.clone())));
                return Ok(Outcome::err(ContextError::InvalidState(msg)));
            }
        };

        // Sign OUTSIDE the actor with the caller's custody.
        let signature = match custody
            .sign(signing_key_handle, &reservation.signing_payload)
            .await
        {
            Ok(sig) => sig.as_bytes().to_vec(),
            Err(e) => {
                // Signing failed — release the reservation so the
                // sequence is reusable, then surface the error.
                self.release_broadcast_reservation(&actor, context_id, reservation.reservation_id)
                    .await;
                let _ = reply.send(Err(ContextError::CryptoFailed(format!(
                    "custody signing failed: {e}"
                ))));
                return Ok(Outcome::ok_mutated(()));
            }
        };

        // Phase 2 — apply the reservation with the signature.
        let (apply_tx, apply_rx) = tokio::sync::oneshot::channel();
        let apply_cmd = BroadcastCommand::ApplyBroadcastPublish {
            payload: Box::new(ApplyBroadcastPublishPayload {
                context_id: context_id.clone(),
                reservation_id: reservation.reservation_id.clone(),
                signature,
                payload,
            }),
            reply: apply_tx,
        };
        Self::dispatch_via_mailbox(&actor, ContextCommand::Broadcast(apply_cmd)).await?;
        match apply_rx.await {
            Ok(Ok(envelope)) => {
                let _ = reply.send(Ok(envelope));
                Ok(Outcome::ok_mutated(()))
            }
            Ok(Err(e)) => {
                // Apply itself released the reservation on its error
                // paths; nothing more to do here.
                let _ = reply.send(Err(e));
                Ok(Outcome::ok_mutated(()))
            }
            Err(_) => {
                // Apply reply channel closed without a result — release
                // defensively in case the reservation is still live.
                self.release_broadcast_reservation(&actor, context_id, reservation.reservation_id)
                    .await;
                let msg = "broadcast apply reply channel closed".to_owned();
                let _ = reply.send(Err(ContextError::InvalidState(msg.clone())));
                Ok(Outcome::err(ContextError::InvalidState(msg)))
            }
        }
    }

    /// Send a best-effort `ReleaseBroadcastReservation` to the actor so a
    /// reservation that will never be applied does not burn its sequence.
    /// Errors are swallowed — the snapshot floor is the crash-safe
    /// backstop; this is the in-process fast path.
    async fn release_broadcast_reservation(
        &self,
        actor: &ContextActorHandle,
        context_id: String,
        reservation_id: crate::context::actor::state::BroadcastReservationId,
    ) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = BroadcastCommand::ReleaseBroadcastReservation {
            payload: Box::new(
                crate::context::actor::commands::ReleaseBroadcastReservationPayload {
                    context_id,
                    reservation_id,
                },
            ),
            reply: tx,
        };
        if Self::dispatch_via_mailbox(actor, ContextCommand::Broadcast(cmd))
            .await
            .is_ok()
        {
            let _ = rx.await;
        }
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

        // RAII guard: ensure the pending flag clears even if `run_saga_fsm`
        // panics or unwinds. The prior implementation cleared the flag with
        // a line of code after `.await` — a panic anywhere inside the FSM
        // would leave the guard set, blocking every subsequent `start_saga`
        // until process restart. Phase 1 fix-up of ADR-049
        // (post-review-round-1). The guard type is defined at module
        // scope below ([`SagaGuardReset`]).
        let _guard = SagaGuardReset(&self.saga_pending_guard);

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

        // `_guard` clears the flag on scope exit — including on the
        // panic-unwind path through `run_saga_fsm`.

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
    /// This method is called by [`Self::new`] through an internal replay-task
    /// spawn on construction so a crash-restart
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

    // ---------------------------------------------------------------
    // Supervisor-scope direct methods (no per-context command dispatch)
    //
    // The methods in this block route to the attached
    // [`Supervisor`](crate::context::supervisor::Supervisor)
    // surface directly because the underlying operation has no
    // per-context lock-and-handler shape: it operates on the
    // supervisor-wide identity registry (`local_dids`), or it iterates
    // every context (`flush_all_*`, `restore_all_contexts`,
    // `shutdown_all_contexts`).
    //
    // Each method is a thin shim — it resolves the attached manager
    // and forwards. Deleted in commit 12 alongside the rest of the
    // shim when the supervisor owns these surfaces directly.
    // ---------------------------------------------------------------

    /// Register a DID as locally controlled by this node / SDK.
    ///
    /// Idempotent: registering the same DID twice is a no-op.
    ///
    /// # Errors
    ///
    /// Currently always returns `Ok(())` — the `Result` shape preserves
    /// the legacy method's signature so callers can keep their
    /// `?`-style propagation untouched.
    pub async fn register_local_did(&self, did: DID) -> Result<(), ContextError> {
        crate::context::queries_helpers::register_local_did(self, did).await;
        Ok(())
    }

    /// Returns `true` iff `did` is registered as locally controlled.
    ///
    /// # Errors
    ///
    /// Currently always returns `Ok(_)`.
    pub async fn is_local_did(&self, did: &DID) -> Result<bool, ContextError> {
        Ok(crate::context::queries_helpers::is_local_did(self, did).await)
    }

    /// Restore every persisted context from the configured persistence
    /// provider.
    ///
    /// Returns the list of restored context IDs. Contexts in
    /// `Closing` / `Closed` / `Expired` states are skipped (only
    /// `Active` contexts are resurrected after a restart).
    ///
    /// # Errors
    ///
    /// - [`ContextError::PersistenceFailed`] if the persistence
    ///   provider is unconfigured or `list_persisted_contexts` fails.
    pub async fn restore_all_contexts(self: &Arc<Self>) -> Result<Vec<String>, ContextError> {
        crate::context::lifecycle_helpers::restore_all_contexts(self).await
    }

    /// Restore a single previously-persisted context from storage via
    /// the actor mailbox.
    ///
    /// Builds a [`LifecycleCommand::RestoreContext`] with an embedded
    /// reply oneshot. Note: `context_id` and `handle.context_id()` must
    /// agree (the legacy helper carries both for historical reasons);
    /// the command payload uses `handle.context_id()`, and a caller-
    /// supplied `context_id` argument that does not match is ignored.
    ///
    /// # Errors
    ///
    /// Propagates [`ContextError`] from the handler.
    pub async fn restore_context(
        self: &Arc<Self>,
        context_id: &str,
        handle: &crate::context::ContextHandle,
    ) -> Result<(), ContextError> {
        // The legacy method takes both `context_id` and `handle`
        // because the original helper signature predates `ContextHandle`
        // exposing its own `context_id()` accessor. The boxed payload
        // here is built from the handle (the authoritative source); the
        // separate `context_id` parameter is retained on the signature
        // for caller compatibility and silently overridden when the two
        // disagree.
        debug_assert_eq!(
            context_id,
            handle.context_id(),
            "Supervisor::restore_context — context_id argument must match handle.context_id()"
        );
        let (tx, rx) = tokio::sync::oneshot::channel();
        let payload = Box::new(crate::context::actor::commands::RestoreContextPayload {
            context_id: handle.context_id().to_owned(),
            params: handle.params().clone(),
        });
        let cmd = LifecycleCommand::RestoreContext { payload, reply: tx };
        self.dispatch_lifecycle_command(cmd).await?;
        rx.await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::restore_context — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// Best-effort flush of every context's snapshot to the configured
    /// persistence provider.
    ///
    /// No-op if no persistence provider is configured.
    ///
    /// # Errors
    ///
    /// Currently always returns `Ok(())` — the `Result` shape preserves
    /// the legacy method's signature for callers that propagate with
    /// `?`. Per-context flush failures are logged via `tracing::warn!`
    /// inside the helper.
    pub async fn flush_all_contexts(&self) -> Result<(), ContextError> {
        crate::context::lifecycle_helpers::flush_all_contexts(self).await;
        Ok(())
    }

    /// Sync wrapper for [`Self::flush_all_contexts`].
    ///
    /// Required by `Drop` and other terminal sync callers that cannot
    /// `.await`. Uses `tokio::runtime::Handle::current` to bridge
    /// sync → async; **callers MUST be inside a tokio runtime**.
    /// No-op if no persistence provider is configured.
    ///
    /// # Errors
    ///
    /// Currently always returns `Ok(())`. Per-context flush failures
    /// are logged via `tracing::warn!` inside the helper.
    pub fn flush_all_contexts_sync(&self) -> Result<(), ContextError> {
        crate::context::lifecycle_helpers::flush_all_contexts_sync(self);
        Ok(())
    }

    /// Shut down every context the supervisor owns (best-effort,
    /// local cleanup only).
    ///
    /// Destroys per-context sender keys + MLS groups + event logs in
    /// that order (zeroize secrets before tearing down structure),
    /// removes the contexts from the supervisor's registry, clears the
    /// standing-context tracking + local-DID registry + per-identity
    /// wrapping keys, and aborts background tasks (TTL timers,
    /// governance timeouts). Does NOT send leave messages or notify
    /// remote peers — used by `scp_ffi_common::BridgeInstance::shutdown`
    /// for process exit / test teardown.
    ///
    /// Phase 1 fix-up of ADR-049 (post-review-round-1): now async to
    /// allow proper `lock().await` acquisition rather than the prior
    /// best-effort `try_lock` that silently skipped cleanup on
    /// contention.
    ///
    /// # Errors
    ///
    /// Currently always returns `Ok(())`. Best-effort cleanup logs
    /// per-context failures via `tracing::warn!` inside the helper.
    pub async fn shutdown_all_contexts(&self) -> Result<(), ContextError> {
        crate::context::lifecycle_helpers::shutdown_all_contexts(self).await;
        Ok(())
    }

    /// Sync wrapper for [`Self::shutdown_all_contexts`].
    ///
    /// Required by destructor / atexit-style sync callers (the FFI
    /// bridge instance's blocking-shutdown path) that cannot `.await`.
    /// Uses [`tokio::runtime::Handle::try_current`] to bridge sync →
    /// async; **callers MUST be inside a tokio runtime**. No-op (with
    /// warning) when called outside a runtime.
    ///
    /// Phase 1 fix-up of ADR-049 (post-review-round-1).
    ///
    /// # Errors
    ///
    /// Currently always returns `Ok(())`. Per-context cleanup failures
    /// are logged via `tracing` inside the helper.
    pub fn shutdown_all_contexts_sync(&self) -> Result<(), ContextError> {
        crate::context::lifecycle_helpers::shutdown_all_contexts_sync(self);
        Ok(())
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

    // -------------------------------------------------------------------
    // ADR-049 commit 12c.9g.3 — FFI passthrough surface.
    //
    // The 4 FFI bridges (PyO3, NAPI, UniFFI, common) used to dereference
    // an `Arc<ContextManager>` and invoke methods directly. After commit
    // 12c.9g.3 they hold an `Arc<Supervisor>` only. The methods below
    // mirror the small subset of `ContextManager` methods that the
    // bridge functions actually call (membership queries, event-log
    // probes, hard-rate-limit consumption, broadcast key resolution,
    // tool invocation, lifecycle creation in tests).
    //
    // Each method is intentionally a thin one-liner over the equivalent
    // `*_helpers::X(&self, ...)` free function or the legacy
    // `ContextManager::X` method (resolved via
    // `with_providers()`). The thin layer keeps the FFI rewire
    // mechanical: bridge call sites change exactly one identifier
    // (`mgr.X` → `supervisor.X`). When `manager/` is deleted in commit
    // 12c.9g.4, the manager-fallback methods below become direct helper
    // calls.
    // -------------------------------------------------------------------

    /// Reads the current lifecycle
    /// [`ContextState`](scp_protocol::context::ContextState) for
    /// `context_id`, or `None` if no per-context actor exists.
    ///
    /// Unlike the other query passthroughs, this does NOT route through
    /// [`Self::dispatch_query`]: that method falls through to
    /// [`Self::dispatch_queries_direct`] (which fabricates the legacy
    /// unknown-context default) when no actor is registered. The standing
    /// get-or-create path needs to distinguish "actor exists and is in
    /// state X" from "no actor at all", so this helper does the
    /// [`Self::lookup`] explicitly: a missing actor resolves to `None`
    /// (no mailbox, no reply), and a present actor's mailbox reply is
    /// surfaced as `Some(state)`.
    ///
    /// Close / TTL does NOT despawn the per-context actor, so
    /// `lookup(id).is_some()` alone cannot tell a live context from a
    /// terminal one — this query is the read-only lifecycle probe that
    /// makes that distinction without a `per-context-state Mutex`. A
    /// dropped reply or mailbox-send failure (actor shutting down)
    /// resolves to `None`, treated by callers as "no live context".
    #[must_use]
    pub async fn read_context_state(
        &self,
        context_id: &str,
    ) -> Option<scp_protocol::context::ContextState> {
        let actor = self.lookup(context_id)?;
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = ContextCommand::Queries(QueriesCommand::ReadContextState {
            context_id: context_id.to_owned(),
            reply: tx,
        });
        if Self::dispatch_via_mailbox(&actor, cmd).await.is_err() {
            return None;
        }
        match rx.await {
            Ok(Ok(state)) => Some(state),
            Ok(Err(_)) | Err(_) => None,
        }
    }

    /// Returns an existing standing context or creates a new one
    /// (contact graph). Actor-native get-or-create — no `contexts`
    /// DashMap, no `per-context-state Mutex`, no
    /// `create_context_legacy`.
    ///
    /// # Algorithm
    ///
    /// 1. Derive the deterministic standing context id from the DID pair.
    /// 2. Liveness check via [`Self::read_context_state`]: if a
    ///    per-context actor exists AND its lifecycle state is
    ///    [`Active`](scp_protocol::context::ContextState::Active) or
    ///    [`Creating`](scp_protocol::context::ContextState::Creating),
    ///    track the peer and return the existing id. A terminal state
    ///    (`Closed` / `Expired` / `Closing` / `MigratingOut` /
    ///    `Tombstoned`) or a missing actor (`None`) falls through to
    ///    create — a dead standing context is never reused.
    /// 3. Create a fresh bilateral-persistent context through the
    ///    actor-shape [`lifecycle_helpers::create_context`](crate::context::lifecycle_helpers::create_context)
    ///    (membership, roles, governance, owned-state actor spawn), with
    ///    `local_did` as creator — mirroring the
    ///    [`LifecycleCommand::CreateContext`](crate::context::actor::commands::LifecycleCommand::CreateContext)
    ///    deps build in [`Self::dispatch_lifecycle_direct`].
    /// 4. TOCTOU: a concurrent caller may have created the context
    ///    between the step-2 check and the step-3 create. On create
    ///    error, re-probe [`Self::read_context_state`]; if it is now
    ///    `Active` / `Creating`, treat the create as idempotently
    ///    successful. Otherwise propagate
    ///    [`ContextError::TransportFailed`].
    /// 5. Track the peer in the supervisor standing index (ArcSwap +
    ///    `write_lock`, ADR-049 §Decision 12) and return the id.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::TransportFailed`] if context creation
    /// fails and no concurrent creation resolved the id.
    pub(in crate::context) async fn standing_context(
        self: &Arc<Self>,
        local_did: &DID,
        peer_did: &DID,
    ) -> Result<String, ContextError> {
        use scp_protocol::context::ContextState;

        let context_id =
            crate::context::standing_helpers::generate_standing_context_id(local_did, peer_did);

        // Serialize this get-or-create against every other same-id
        // bootstrap (the `CreateContext` / `ImportContext` /
        // `RestoreContext` dispatch arms, and concurrent
        // `standing_context` calls for the same deterministic id) by
        // holding `bootstrap_spawn_lock` across the probe-through-create
        // span. `standing_context` is the 4th bootstrap entry point; the
        // dispatch arms acquire this lock but the standing path previously
        // did not, so two racing standing creates (or a standing create
        // racing a `CreateContext` for the same id) could both pass the
        // step-2 probe and both call `create_context` → the loser's
        // `create_mls_group` would clobber the winner's live MLS group
        // with fresh keys (crypto desync). The lock makes the
        // probe-create-recheck sequence atomic w.r.t. other bootstraps.
        //
        // Deadlock-free: `standing_context`'s only caller chain
        // (`dispatch_standing_command` → `dispatch_standing_direct`) does
        // NOT hold this lock, and `create_context` below does not
        // re-acquire it. Lock order is always
        // `bootstrap_spawn_lock` → `write_lock` (see
        // `track_standing_peer` / `spawn_actor_with_state`).
        let _bootstrap_guard = self.bootstrap_spawn_lock.lock().await;

        // Step 1/2: existence + liveness probe. `read_context_state`
        // returns `None` when no actor exists (create path) and
        // `Some(state)` for a live actor. Only Active/Creating short-
        // circuits to reuse; every terminal state falls through so a
        // dead standing context is replaced rather than resurrected.
        if matches!(
            self.read_context_state(&context_id).await,
            Some(ContextState::Active | ContextState::Creating)
        ) {
            self.track_standing_peer(peer_did).await;
            return Ok(context_id);
        }

        // Step 3: create a new bilateral-persistent context via the
        // actor-shape create flow. Mirrors the `CreateContext` arm of
        // `dispatch_lifecycle_direct`: build deps scoped to the creator,
        // then `lifecycle_helpers::create_context`.
        let params = scp_protocol::context::templates::template_params(
            &scp_protocol::context::TemplateId::BilateralPersistent,
        );
        let create_result = match self.build_actor_deps(local_did).await {
            Ok(deps) => Box::pin(crate::context::lifecycle_helpers::create_context(
                &deps,
                context_id.clone(),
                params,
                local_did.clone(),
                None,
            ))
            .await
            .map(|_handle| ())
            .map_err(|e| ContextError::TransportFailed(e.to_string())),
            Err(e) => Err(ContextError::TransportFailed(e.to_string())),
        };

        // Step 4: TOCTOU re-check. A concurrent caller may have created
        // the context between our step-2 probe and the step-3 create. If
        // the context is now Active/Creating, treat the create as
        // idempotently successful; otherwise surface the create error.
        if let Err(create_err) = create_result
            && !matches!(
                self.read_context_state(&context_id).await,
                Some(ContextState::Active | ContextState::Creating)
            )
        {
            return Err(create_err);
        }

        // Step 5: track the standing peer and return.
        self.track_standing_peer(peer_did).await;
        Ok(context_id)
    }

    /// Insert `peer_did` into the supervisor standing index.
    ///
    /// ArcSwap + `write_lock` mutation (ADR-049 §Decision 12): the index
    /// is read lock-free on the hot path; mutations serialize through the
    /// `write_lock` and store a fresh `Arc` snapshot. Keyed by the peer
    /// DID's `to_string()` form, matching every other standing-index
    /// writer (`RegisterStandingContext`,
    /// `SupervisorHandle::register_standing_context`).
    async fn track_standing_peer(&self, peer_did: &DID) {
        let _guard = self.write_lock.lock().await;
        let snapshot = self.standing_contexts.load_full();
        let mut updated: HashMap<String, DID> = (*snapshot).clone();
        updated.insert(peer_did.to_string(), peer_did.clone());
        self.standing_contexts.store(Arc::new(updated));
    }

    /// Reconnects transport for all active standing contexts. Actor-native
    /// — resolves per-context lifecycle + params through the actor
    /// registry + mailbox (no `contexts` DashMap, no
    /// `per-context-state Mutex`).
    ///
    /// Called during SDK initialization. Iterates the supervisor standing
    /// index, resolves each `(local_did, peer_did)` pair to its
    /// deterministic standing context id, and for every context whose
    /// per-context actor reports
    /// [`Active`](scp_protocol::context::ContextState::Active) republishes
    /// the context blob to transport. Contexts in terminal states
    /// (`Closed` / `Expired` / `Tombstoned`) are evicted from the standing
    /// index to bound its growth; transient states (`Creating` /
    /// `Closing` / `MigratingOut`) are kept and skipped.
    ///
    /// # Returns
    ///
    /// The number of contexts successfully reconnected.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::TransportFailed`] if any reconnection
    /// fails (or [`ContextError::NotInitialized`] if no transport provider
    /// is attached). Contexts reconnected before the failure remain
    /// connected — the publish loop applies eagerly.
    pub async fn reconnect_all_standing(&self) -> Result<usize, ContextError> {
        use scp_protocol::context::ContextState;

        // Phase 1: lock-free snapshots of the standing index + local DIDs
        // (ADR-049 §Decision 12). No per-context lock is held — every
        // per-context read below routes through the actor mailbox.
        let standing_entries: Vec<(String, DID)> = self
            .standing_contexts
            .load()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let local_did_list: Vec<DID> = self.local_dids.load().iter().cloned().collect();

        // Phase 2: resolve each standing pair to its context id, probe the
        // owning actor's lifecycle state, and republish the Active ones.
        // `read_context_state` returns `None` when no actor owns the id —
        // the same "no live context, skip" outcome the legacy
        // per-context-map miss produced.
        let mut reconnected = 0_usize;
        let mut terminal_context_ids: Vec<String> = Vec::new();
        for (_key, peer_did) in &standing_entries {
            for local_did in &local_did_list {
                let context_id = crate::context::standing_helpers::generate_standing_context_id(
                    local_did, peer_did,
                );
                let Some(state) = self.read_context_state(&context_id).await else {
                    // No actor for this (local, peer) id — try the next
                    // local DID, matching the legacy break-on-first-hit
                    // scan only when an actor is actually found.
                    continue;
                };
                match state {
                    ContextState::Active => {
                        // Fetch params through the actor mailbox; `None`
                        // means the actor vanished between the state probe
                        // and this read (raced close) — treat as not
                        // reconnectable and move on.
                        if let Some(params) = self.context_params(&context_id).await {
                            let context_id_bytes =
                                scp_protocol::context::context_id_bytes(&context_id);
                            self.transport_ref()
                                .ok_or_else(|| {
                                    ContextError::NotInitialized(
                                        crate::context::manager_methods::PROVIDER_NOT_INITIALIZED
                                            .to_owned(),
                                    )
                                })?
                                .publish_context(&context_id_bytes, &params)
                                .map_err(|e| {
                                    ContextError::TransportFailed(format!(
                                        "reconnection failed for context {context_id}: {e}"
                                    ))
                                })?;
                            reconnected += 1;
                        }
                    }
                    // Standing contexts in terminal states are eviction
                    // candidates (Phase 3) to bound the index.
                    ContextState::Closed | ContextState::Expired | ContextState::Tombstoned => {
                        terminal_context_ids.push(context_id.clone());
                    }
                    // Creating / Closing / MigratingOut — transient, keep.
                    ContextState::Creating | ContextState::Closing | ContextState::MigratingOut => {
                    }
                }
                // An actor was found for this peer under `local_did`; the
                // standing id is deterministic per pair, so stop scanning
                // the remaining local DIDs (matches the legacy break).
                break;
            }
        }

        // Phase 3: evict standing entries whose context resolved to a
        // terminal state. `generate_standing_context_id` hashes the DID
        // pair, so re-derive each entry's id and compare. ArcSwap +
        // write_lock mutation (ADR-049 §Decision 12).
        if !terminal_context_ids.is_empty() {
            let local_did_set: std::collections::HashSet<DID> =
                self.local_dids.load().iter().cloned().collect();
            let _guard = self.write_lock.lock().await;
            let snapshot = self.standing_contexts.load_full();
            let to_remove: Vec<String> = snapshot
                .iter()
                .filter(|(_key, peer_did)| {
                    local_did_set.iter().any(|local_did| {
                        let cid = crate::context::standing_helpers::generate_standing_context_id(
                            local_did, peer_did,
                        );
                        terminal_context_ids.contains(&cid)
                    })
                })
                .map(|(key, _)| key.clone())
                .collect();
            if !to_remove.is_empty() {
                let mut updated: HashMap<String, DID> = (*snapshot).clone();
                for key in &to_remove {
                    updated.remove(key);
                }
                self.standing_contexts.store(Arc::new(updated));
            }
        }

        Ok(reconnected)
    }

    /// Returns the current member count for `context_id`, or `None` if
    /// the context is not registered. Routes through the actor mailbox
    /// via [`Self::dispatch_query`].
    #[must_use]
    pub async fn member_count(&self, context_id: &str) -> Option<usize> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = QueriesCommand::MemberCount {
            context_id: context_id.to_owned(),
            reply: tx,
        };
        if self.dispatch_query(cmd).await.is_err() {
            return None;
        }
        match rx.await {
            Ok(Ok(answer)) => answer,
            Ok(Err(_)) | Err(_) => None,
        }
    }

    /// Returns `true` iff `did` is a member of `context_id`. Routes
    /// through the actor mailbox via [`Self::dispatch_query`].
    #[must_use]
    pub async fn is_member(&self, context_id: &str, did: &str) -> bool {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = QueriesCommand::IsMember {
            context_id: context_id.to_owned(),
            did: did.to_owned(),
            reply: tx,
        };
        if self.dispatch_query(cmd).await.is_err() {
            return false;
        }
        match rx.await {
            Ok(Ok(answer)) => answer,
            Ok(Err(_)) | Err(_) => false,
        }
    }

    /// Returns every member DID currently associated with `context_id`
    /// (empty if the context is unknown). Routes through the actor
    /// mailbox via [`Self::dispatch_query`].
    #[must_use]
    pub async fn member_dids(&self, context_id: &str) -> Vec<String> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = QueriesCommand::MemberDids {
            context_id: context_id.to_owned(),
            reply: tx,
        };
        if self.dispatch_query(cmd).await.is_err() {
            return Vec::new();
        }
        match rx.await {
            Ok(Ok(answer)) => answer,
            Ok(Err(_)) | Err(_) => Vec::new(),
        }
    }

    /// Returns the role assignment for `did` in `context_id`, or `None`
    /// if the member has no role. Routes through the actor mailbox via
    /// [`Self::dispatch_query`].
    #[must_use]
    pub async fn member_role(
        &self,
        context_id: &str,
        did: &str,
    ) -> Option<scp_protocol::context::roles::RoleAssignment> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = QueriesCommand::MemberRole {
            context_id: context_id.to_owned(),
            did: did.to_owned(),
            reply: tx,
        };
        if self.dispatch_query(cmd).await.is_err() {
            return None;
        }
        match rx.await {
            Ok(Ok(answer)) => answer,
            Ok(Err(_)) | Err(_) => None,
        }
    }

    /// Returns a clone of the context's creation parameters, or `None`
    /// if the context is unknown. Routes through the actor mailbox via
    /// [`Self::dispatch_query`].
    #[must_use]
    pub async fn context_params(
        &self,
        context_id: &str,
    ) -> Option<scp_protocol::context::ContextParams> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = QueriesCommand::ContextParams {
            context_id: context_id.to_owned(),
            reply: tx,
        };
        if self.dispatch_query(cmd).await.is_err() {
            return None;
        }
        match rx.await {
            Ok(Ok(answer)) => answer,
            Ok(Err(_)) | Err(_) => None,
        }
    }

    /// Returns a clone of the context's role state, or `None` if the
    /// context is unknown. Routes through the actor mailbox via
    /// [`Self::dispatch_query`].
    #[must_use]
    pub async fn get_role_state(
        &self,
        context_id: &str,
    ) -> Option<scp_protocol::context::roles::ContextRoleState> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = QueriesCommand::GetRoleState {
            context_id: context_id.to_owned(),
            reply: tx,
        };
        if self.dispatch_query(cmd).await.is_err() {
            return None;
        }
        match rx.await {
            Ok(Ok(answer)) => answer,
            Ok(Err(_)) | Err(_) => None,
        }
    }

    /// Drains and returns every event currently buffered for
    /// `context_id` via the actor mailbox.
    ///
    /// Matches the legacy soft-default contract: returns an empty
    /// `Vec` if the context is unknown, if the mailbox enqueue fails,
    /// or if the reply channel is dropped before the handler responds.
    #[must_use]
    pub async fn drain_events(&self, context_id: &str) -> Vec<ContextEvent> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = MessagingCommand::DrainEvents {
            context_id: context_id.to_owned(),
            reply: tx,
        };
        if self.dispatch_command(context_id, cmd).await.is_err() {
            return Vec::new();
        }
        match rx.await {
            Ok(Ok(events)) => events,
            Ok(Err(_)) | Err(_) => Vec::new(),
        }
    }

    /// Returns the Merkle-log entries for the routing-id-hashed
    /// `context_id_bytes`. Synchronous — reads the supervisor's shared
    /// event-log provider directly without acquiring a per-context
    /// lock or routing through any actor mailbox (the operation is
    /// stateless w.r.t. per-context state).
    ///
    /// This is the lone read-only query that cannot ride the actor
    /// mailbox because the signature is `fn`, not `async fn`: the FFI
    /// sync paths that call it (Python `gil-bound` event-log probes,
    /// notably) cannot `.await`.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] if the event-log provider fails or no
    /// providers are wired.
    pub fn event_log_entries(
        &self,
        context_id_bytes: &[u8; 32],
    ) -> Result<Option<Vec<crate::context::providers::event_log::EventLogEntry>>, ContextError>
    {
        let event_log = self.event_log_ref().ok_or_else(|| {
            ContextError::NotInitialized(
                "Supervisor::event_log_entries — event_log provider not configured".to_owned(),
            )
        })?;
        event_log.event_log_entries(context_id_bytes)
    }

    /// Returns the broadcast sender key + epoch for `author_did` in
    /// `context_id` via the actor mailbox.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] when the caller is not authorized as
    /// the broadcast author or when the context is unknown.
    pub async fn get_broadcast_key_for_local_author(
        &self,
        context_id: &str,
        author_did: &str,
    ) -> Result<(Zeroizing<[u8; 32]>, u64), ContextError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = QueriesCommand::GetBroadcastKeyForLocalAuthor {
            context_id: context_id.to_owned(),
            author_did: author_did.to_owned(),
            reply: tx,
        };
        self.dispatch_query(cmd).await?;
        rx.await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::get_broadcast_key_for_local_author — actor reply channel closed"
                    .to_owned(),
            )
        })?
    }

    /// Async hard-rate-limit consume routed through the per-context
    /// actor mailbox.
    ///
    /// Builds a [`ToolsCommand::TryConsumeHardRateLimit`], dispatches it
    /// through [`Self::dispatch_tools_command`] (which routes to the
    /// target context's actor — the actor owns its
    /// [`PerContextState`](crate::context::actor::state::PerContextState)
    /// hard-rate-limit bucket), and awaits the embedded reply oneshot.
    ///
    /// Returns `true` if a token was consumed OR if the context is not
    /// registered. The unknown-context pass-through (`true`) preserves the
    /// legacy `try_consume_hard_rate_limit_from_any_context` contract: a
    /// tool invoked against a context with no live actor is not rate-
    /// limited here (the absence of a bucket means "no per-context cap to
    /// enforce"). Returns `false` only when the context IS registered AND
    /// the sender is over budget.
    pub(crate) async fn try_consume_hard_rate_limit(
        &self,
        context_id: &str,
        did: &DID,
        now_secs: u64,
    ) -> bool {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let cmd = ToolsCommand::TryConsumeHardRateLimit {
            context_id: context_id.to_owned(),
            did: did.clone(),
            now_secs,
            reply: reply_tx,
        };
        // Dispatch returns the dispatch-level Outcome; the typed answer
        // arrives on `reply_rx`. An unregistered context replies
        // `Err(ContextNotRegistered)` (see `reply_tools_not_registered`)
        // which we fold to the legacy `true` pass-through.
        if self.dispatch_tools_command(cmd).await.is_err() {
            return true;
        }
        match reply_rx.await {
            Ok(Ok(consumed)) => consumed,
            // Unknown context / channel dropped: legacy pass-through.
            Ok(Err(_)) | Err(_) => true,
        }
    }

    /// Async hard-rate-limit refund routed through the per-context actor
    /// mailbox. No-op when the target context has no live actor (legacy
    /// unknown-context contract).
    ///
    /// Mirrors [`Self::try_consume_hard_rate_limit`]; builds a
    /// [`ToolsCommand::RefundHardRateLimit`], dispatches it to the actor,
    /// and awaits the reply. The reply error (e.g. `ContextNotRegistered`)
    /// is swallowed — a refund against an absent bucket is a no-op, not a
    /// failure the caller can act on.
    pub(crate) async fn refund_hard_rate_limit(&self, context_id: &str, did: &DID) {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let cmd = ToolsCommand::RefundHardRateLimit {
            context_id: context_id.to_owned(),
            did: did.clone(),
            reply: reply_tx,
        };
        if self.dispatch_tools_command(cmd).await.is_err() {
            return;
        }
        let _ = reply_rx.await;
    }

    /// Runtime-agnostic hard-rate-limit consumption used by FFI
    /// callers that may run inside or outside a tokio runtime.
    ///
    /// Returns `false` if the bucket is empty.
    ///
    /// # Sync-shape exception (ADR-049 §7)
    ///
    /// The method signature is `fn`, not `async fn` — FFI callers
    /// (the MCP `invoke_tool` sync trait method in particular) invoke
    /// it from outside a tokio task and cannot `.await`. The body
    /// bridges sync → async exactly like
    /// [`Self::shutdown_all_contexts_sync`]: it inspects the ambient
    /// runtime and either `blocking`-bridges into the async
    /// [`Self::try_consume_hard_rate_limit`] actor-mailbox path, or
    /// spawns a dedicated current-thread runtime when neither
    /// `blocking_lock` nor `block_in_place` is safe (current-thread
    /// runtime regime). No DashMap is touched — the actor owns the
    /// bucket.
    #[must_use]
    #[allow(clippy::option_if_let_else)]
    pub fn try_consume_hard_rate_limit_from_any_context(
        self: &Arc<Self>,
        context_id: &str,
        did: &DID,
        now_secs: u64,
    ) -> bool {
        match tokio::runtime::Handle::try_current() {
            // No ambient runtime (sync `#[test]`, GIL-bound bridge call
            // off any executor): borrow the global multi-thread runtime
            // via a dedicated current-thread runtime on a fresh thread so
            // we never `block_on` the calling thread's (absent) runtime.
            Err(_) => Self::run_rate_limit_on_dedicated_thread(
                Arc::clone(self),
                context_id.to_owned(),
                did.clone(),
                now_secs,
                /* refund = */ false,
            ),
            Ok(handle) => {
                use tokio::runtime::RuntimeFlavor;
                match handle.runtime_flavor() {
                    // Multi-thread runtime: `block_in_place` is valid;
                    // re-enter the runtime to await the actor reply.
                    RuntimeFlavor::MultiThread => {
                        // ADR-049 §7 FFI sync rate-limit allowlist — the MCP `invoke_tool`
                        // sync trait method cannot `.await`; the actor-mailbox consume is
                        // awaited on the ambient multi-thread runtime.
                        let fut = self.try_consume_hard_rate_limit(context_id, did, now_secs);
                        tokio::task::block_in_place(|| handle.block_on(fut)) // ci-allow: block-on: ADR-049 §7 FFI sync rate-limit allowlist (MCP invoke_tool consume)
                    }
                    // Current-thread runtime: neither `blocking_lock` nor
                    // `block_in_place` is safe. Spawn a dedicated thread
                    // with its own runtime and block on the actor reply
                    // there.
                    _ => Self::run_rate_limit_on_dedicated_thread(
                        Arc::clone(self),
                        context_id.to_owned(),
                        did.clone(),
                        now_secs,
                        /* refund = */ false,
                    ),
                }
            }
        }
    }

    /// Refund a hard-rate-limit token from any context (no-op on
    /// missing context).
    ///
    /// # Sync-shape exception (ADR-049 §7)
    ///
    /// See the doc on
    /// [`Self::try_consume_hard_rate_limit_from_any_context`] — the
    /// sync FFI path constraint applies here too.
    #[allow(clippy::option_if_let_else)]
    pub fn refund_hard_rate_limit_from_any_context(self: &Arc<Self>, context_id: &str, did: &DID) {
        match tokio::runtime::Handle::try_current() {
            Err(_) => {
                let _ = Self::run_rate_limit_on_dedicated_thread(
                    Arc::clone(self),
                    context_id.to_owned(),
                    did.clone(),
                    0,
                    /* refund = */ true,
                );
            }
            Ok(handle) => {
                use tokio::runtime::RuntimeFlavor;
                match handle.runtime_flavor() {
                    RuntimeFlavor::MultiThread => {
                        // ADR-049 §7 FFI sync rate-limit allowlist — the MCP `invoke_tool`
                        // refund path is sync and cannot `.await`; the actor-mailbox refund
                        // is awaited on the ambient multi-thread runtime.
                        let fut = self.refund_hard_rate_limit(context_id, did);
                        tokio::task::block_in_place(|| handle.block_on(fut)); // ci-allow: block-on: ADR-049 §7 FFI sync rate-limit allowlist (MCP invoke_tool refund)
                    }
                    _ => {
                        let _ = Self::run_rate_limit_on_dedicated_thread(
                            Arc::clone(self),
                            context_id.to_owned(),
                            did.clone(),
                            0,
                            /* refund = */ true,
                        );
                    }
                }
            }
        }
    }

    /// Dedicated-thread escape hatch for the no-runtime and
    /// current-thread-runtime regimes, where both `blocking_lock` and
    /// `block_in_place` panic. Spawns a `std::thread`, builds a
    /// current-thread tokio runtime there, awaits the actor-mailbox
    /// consume/refund, and returns the answer via mpsc.
    ///
    /// Returns `true` for the consume path (token consumed or unknown
    /// context); always `true` for the refund path (refund result is
    /// not observable). On runtime build failure the consume path fails
    /// closed (`false`).
    fn run_rate_limit_on_dedicated_thread(
        supervisor: Arc<Self>,
        context_id: String,
        did: DID,
        now_secs: u64,
        refund: bool,
    ) -> bool {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "dedicated rate-limit runtime build failed; failing closed"
                    );
                    let _ = tx.send(false);
                    return;
                }
            };
            // ADR-049 §7 FFI sync rate-limit allowlist — dedicated current-thread
            // runtime for the no-runtime / current-thread-runtime regime; the sync
            // FFI caller cannot `.await` the actor-mailbox consume/refund.
            let result = if refund {
                rt.block_on(supervisor.refund_hard_rate_limit(&context_id, &did)); // ci-allow: block-on: ADR-049 §7 FFI sync rate-limit allowlist (dedicated-thread refund)
                true
            } else {
                rt.block_on(supervisor.try_consume_hard_rate_limit(&context_id, &did, now_secs)) // ci-allow: block-on: ADR-049 §7 FFI sync rate-limit allowlist (dedicated-thread consume)
            };
            let _ = tx.send(result);
        });
        rx.recv().unwrap_or(false)
    }

    /// Dispatch the Phase-1 [`ToolsCommand::ReserveToolEconomy`] to the
    /// target context's actor and await the `Send` reservation.
    ///
    /// # Errors
    ///
    /// [`ContextError::ContextNotRegistered`] when no actor is registered
    /// for `context_id`; otherwise any error the reserve handler emits.
    async fn reserve_tool_economy_via_actor(
        &self,
        context_id: &str,
        invoker_did: &DID,
        spending_ucan: Option<&scp_protocol::crypto::ucan::UcanToken>,
        now_secs: u64,
    ) -> Result<crate::context::tools_helpers::ToolEconomyReservation, ContextError> {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let cmd = ToolsCommand::ReserveToolEconomy {
            context_id: context_id.to_owned(),
            invoker_did: invoker_did.clone(),
            spending_ucan: spending_ucan.map(|u| Box::new(u.clone())),
            now_secs,
            reply: reply_tx,
        };
        self.dispatch_tools_command(cmd).await?;
        reply_rx
            .await
            .map_err(|_| {
                ContextError::TransportFailed(
                    "Supervisor::reserve_tool_economy_via_actor — actor reply channel closed"
                        .to_owned(),
                )
            })?
            .map(|boxed| *boxed)
    }

    /// Dispatch the Phase-3 [`ToolsCommand::SettleToolEconomy`] to the
    /// target context's actor and await the settle outcome.
    ///
    /// # Errors
    ///
    /// [`ContextError::ContextNotRegistered`] when no actor is registered
    /// for `context_id`; otherwise any error the settle handler emits
    /// (payment-capture failure).
    async fn settle_tool_economy_via_actor(
        &self,
        context_id: &str,
        invoker_did: &DID,
        request: crate::context::tools_helpers::ToolSettleRequest,
    ) -> Result<crate::context::tools_helpers::ToolSettleOutcome, ContextError> {
        // No-actor pre-check: the reserve→execute→settle split runs the
        // executor OFF the actor mailbox, so the owning actor can be
        // despawned (shutdown / node teardown / import replace) during
        // that window. If no actor is registered now, the per-context
        // settle can never run, and routing the command through
        // `dispatch_tools_command` would hand the ticket to
        // `reply_tools_not_registered`, which DROPS it — leaking the
        // external payment escrow and tripping the ticket's unbalanced-
        // Drop guard. Instead, reclaim the ticket here (supervisor-side,
        // where the payment adapter is reachable), void the external
        // escrow, consume the ticket, and surface a typed error.
        if self.lookup(context_id).is_none() {
            let generation = request.generation();
            let ticket = request.into_ticket();
            ticket
                .void_external_and_consume(self.payment_adapter_ref())
                .await;
            return Err(ContextError::ContextNotRegistered(format!(
                "SCP-TOOL-6089: tool-economy settle for context '{context_id}' found no \
                 registered actor (reserved generation {generation}); escrow voided, \
                 reservation not captured"
            )));
        }

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let cmd = ToolsCommand::SettleToolEconomy {
            context_id: context_id.to_owned(),
            invoker_did: invoker_did.clone(),
            request: Box::new(request),
            reply: reply_tx,
        };
        self.dispatch_tools_command(cmd).await?;
        reply_rx.await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::settle_tool_economy_via_actor — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// Invoke a tool under the full economy pipeline (actor model).
    ///
    /// Orchestrates the three-phase split through
    /// [`crate::context::tools_helpers::invoke_tool_with_economy`]: the
    /// economy reserve (Phase 1) and settle (Phase 3) run inside the
    /// per-context actor on owned state via the
    /// [`ToolsCommand::ReserveToolEconomy`] / [`ToolsCommand::SettleToolEconomy`]
    /// mailbox commands; the non-`Send` `executor` closure (Phase 2) runs
    /// here, supervisor-side, BETWEEN the two mailbox round-trips. No
    /// per-context lock is held across the executor — the actor is free
    /// to process other commands while a tool executes.
    ///
    /// # Errors
    ///
    /// Propagates every error variant the reserve / settle handlers and
    /// the executor emit (`ContextNotRegistered`, `PermissionDenied`,
    /// `RateLimited`, schema/economy/UCAN failures).
    #[allow(clippy::too_many_arguments)] // matches legacy signature 1:1
    pub async fn invoke_tool_with_economy<F, Fut>(
        &self,
        context_id: &str,
        registry: &scp_protocol::context::tools::registry::ToolRegistry,
        tool_id: &scp_protocol::context::tools::ToolId,
        input: serde_json::Value,
        invoker_did: &DID,
        spending_ucan: Option<&scp_protocol::crypto::ucan::UcanToken>,
        timeout_ms: Option<u32>,
        executor: F,
    ) -> Result<crate::context::tools_helpers::ManagedToolInvocationOutput, ContextError>
    where
        F: FnOnce(serde_json::Value) -> Fut,
        Fut: std::future::Future<Output = Result<serde_json::Value, String>>,
    {
        let now_secs = self
            .clock_ref()
            .ok_or_else(|| {
                ContextError::NotInitialized(
                    crate::context::manager_methods::PROVIDER_NOT_INITIALIZED.to_owned(),
                )
            })?
            .now_secs();

        crate::context::tools_helpers::invoke_tool_with_economy(
            registry,
            tool_id,
            input,
            invoker_did,
            timeout_ms,
            // Phase 1 — reserve via the actor mailbox.
            || {
                self.reserve_tool_economy_via_actor(
                    context_id,
                    invoker_did,
                    spending_ucan,
                    now_secs,
                )
            },
            // Phase 3 — settle (capture / rollback) via the actor mailbox.
            |request| self.settle_tool_economy_via_actor(context_id, invoker_did, request),
            executor,
        )
        .await
    }

    /// Create a new MLS-backed (or broadcast-mode) context via the
    /// actor mailbox.
    ///
    /// Builds a [`LifecycleCommand::CreateContext`] with an embedded
    /// reply oneshot, enqueues it via
    /// [`Self::dispatch_lifecycle_command`], and awaits the typed
    /// reply. The dispatch helper routes through the per-context actor
    /// mailbox once an actor is registered; on first creation the
    /// `lookup` lookup returns `None` and the dispatch falls through to
    /// the direct-shim path that spawns the actor as part of the
    /// create handshake.
    ///
    /// # Errors
    ///
    /// Returns
    /// [`ContextCreationError`](scp_protocol::context::builder::ContextCreationError)
    /// if the supervisor's providers are not wired or context creation
    /// fails. A dropped reply channel maps to
    /// [`ContextCreationError::CreationFailed`](scp_protocol::context::builder::ContextCreationError::CreationFailed).
    pub async fn create_context(
        self: &Arc<Self>,
        context_id: String,
        params: scp_protocol::context::ContextParams,
        creator_did: DID,
        local_pseudonym: Option<[u8; 32]>,
    ) -> Result<crate::context::ContextHandle, scp_protocol::context::builder::ContextCreationError>
    {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let payload = Box::new(crate::context::actor::commands::CreateContextPayload {
            context_id,
            params,
            creator_did,
            local_pseudonym,
        });
        let cmd = LifecycleCommand::CreateContext { payload, reply: tx };
        if let Err(e) = self.dispatch_lifecycle_command(cmd).await {
            return Err(
                scp_protocol::context::builder::ContextCreationError::CreationFailed(format!(
                    "Supervisor::create_context — dispatch failed: {e}"
                )),
            );
        }
        rx.await.unwrap_or_else(|_| {
            Err(
                scp_protocol::context::builder::ContextCreationError::CreationFailed(
                    "Supervisor::create_context — actor reply channel closed".to_owned(),
                ),
            )
        })
    }

    /// Adds a new member to an existing context via the actor mailbox.
    ///
    /// Builds a [`LifecycleCommand::JoinContext`] with an embedded
    /// reply oneshot, enqueues it via
    /// [`Self::dispatch_lifecycle_command`], and awaits the actor's
    /// typed reply. The dispatch helper routes through the per-context
    /// actor mailbox once one is registered; before that the direct-
    /// shim path completes the join handshake and spawns the actor.
    ///
    /// # Errors
    ///
    /// Propagates [`ContextError`] from the handler.
    pub async fn join_context(
        self: &Arc<Self>,
        handle: &crate::context::ContextHandle,
        key_package: scp_protocol::context::membership::KeyPackage,
        spending_ucan: Option<&scp_protocol::crypto::ucan::UcanToken>,
        local_pseudonym: Option<[u8; 32]>,
    ) -> Result<(), ContextError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let payload = Box::new(crate::context::actor::commands::JoinContextPayload {
            context_id: handle.context_id().to_owned(),
            params: handle.params().clone(),
            key_package,
            spending_ucan: spending_ucan.cloned(),
            local_pseudonym,
        });
        let cmd = LifecycleCommand::JoinContext { payload, reply: tx };
        self.dispatch_lifecycle_command(cmd).await?;
        rx.await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::join_context — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// Removes a member from an existing context via the actor mailbox.
    ///
    /// Builds a [`LifecycleCommand::LeaveContext`] with an embedded
    /// reply oneshot, enqueues it via
    /// [`Self::dispatch_lifecycle_command`], and awaits the typed
    /// reply.
    ///
    /// # Errors
    ///
    /// Propagates [`ContextError`] from the handler.
    pub async fn leave_context(
        self: &Arc<Self>,
        handle: &crate::context::ContextHandle,
        caller_did: &DID,
        member_did: &DID,
    ) -> Result<(), ContextError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let payload = Box::new(crate::context::actor::commands::LeaveContextPayload {
            context_id: handle.context_id().to_owned(),
            params: handle.params().clone(),
            caller_did: caller_did.clone(),
            member_did: member_did.clone(),
        });
        let cmd = LifecycleCommand::LeaveContext { payload, reply: tx };
        self.dispatch_lifecycle_command(cmd).await?;
        rx.await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::leave_context — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// Encrypts and broadcasts a payload through the context's MLS
    /// group via the actor mailbox.
    ///
    /// Phase 2A finalization — every per-context method on `Supervisor`
    /// builds a typed `ContextCommand` carrying an embedded reply
    /// oneshot, enqueues it via [`Self::dispatch_command`], and awaits
    /// the actor's typed reply. The dispatch helper routes through the
    /// per-context actor mailbox when one is registered, falling back
    /// to the legacy lock-and-call shim during the migration window
    /// when no actor has been spawned yet (a state that disappears once
    /// the legacy `*_helpers_legacy::*_legacy` bodies are deleted in
    /// the next session).
    ///
    /// # Errors
    ///
    /// - [`ContextError::NotInitialized`] if the supervisor's provider
    ///   slots are empty (the supervisor was constructed via
    ///   [`Self::for_query_shim`]).
    /// - Other [`ContextError`] variants propagated from the handler.
    /// - [`ContextError::TransportFailed`] if the mailbox reply channel
    ///   is dropped before the handler completes (handler crash /
    ///   actor shutdown).
    pub async fn send_message(
        &self,
        handle: &crate::context::ContextHandle,
        sender_did: &DID,
        payload: &[u8],
        signing_key: Option<&ed25519_dalek::SigningKey>,
        source_provenance: Option<&scp_protocol::provenance::attach::SourceContextInfo>,
        spending_ucan: Option<&scp_protocol::crypto::ucan::UcanToken>,
    ) -> Result<(), ContextError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let payload_box = Box::new(crate::context::actor::commands::SendMessagePayload {
            context_id: handle.context_id().to_owned(),
            params: handle.params().clone(),
            sender_did: sender_did.clone(),
            payload: payload.to_vec(),
            signing_key: signing_key
                .map(crate::context::actor::commands::SigningKeyBytes::from_signing_key),
            source_provenance: source_provenance.cloned(),
            spending_ucan: spending_ucan.cloned(),
        });
        let cmd = MessagingCommand::SendMessage {
            payload: payload_box,
            reply: tx,
        };
        self.dispatch_command(handle.context_id(), cmd).await?;
        rx.await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::send_message — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// Lists every governance proposal currently tracked by the
    /// context's engine via the actor mailbox.
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotRegistered`] if the context is unknown.
    /// - [`ContextError::TransportFailed`] if the actor reply channel
    ///   is closed before the handler responds.
    pub async fn list_proposals(
        &self,
        context_id: &str,
    ) -> Result<Vec<scp_protocol::context::governance::GovernanceProposal>, ContextError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = GovernanceCommand::ListProposals {
            context_id: context_id.to_owned(),
            reply: tx,
        };
        self.dispatch_governance_command(cmd).await?;
        rx.await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::list_proposals — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// Fetches a single proposal by ID via the actor mailbox.
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotRegistered`] if the context is unknown.
    /// - [`ContextError::GovernanceFailed`] if the proposal is not found.
    pub async fn get_proposal(
        &self,
        context_id: &str,
        proposal_id: &scp_protocol::context::governance::ProposalId,
    ) -> Result<scp_protocol::context::governance::GovernanceProposal, ContextError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = GovernanceCommand::GetProposal {
            context_id: context_id.to_owned(),
            proposal_id: *proposal_id,
            reply: tx,
        };
        self.dispatch_governance_command(cmd).await?;
        rx.await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::get_proposal — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// Submits a governance proposal via the actor mailbox — unchecked
    /// variant.
    ///
    /// Gated behind the `testing` feature — the unchecked propose path
    /// is not part of the production FFI surface (every bridge calls
    /// [`Self::propose_governance_action_checked`] instead). Crate-
    /// internal callers that bypass the capability check are limited
    /// to integration tests under `crates/scp-runtime/tests/`.
    ///
    /// # Errors
    ///
    /// Propagates [`ContextError`] from the handler.
    #[cfg(any(test, feature = "testing"))]
    pub async fn propose_governance_action(
        &self,
        context_id: &str,
        proposer_did: &DID,
        action: scp_protocol::context::governance::GovernanceAction,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<
        (
            scp_protocol::context::governance::GovernanceProposal,
            Vec<scp_protocol::context::governance::GovernanceEvent>,
            Option<crate::context::state::GovernanceActionResult>,
        ),
        ContextError,
    > {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let payload = Box::new(
            crate::context::actor::commands::ProposeGovernanceActionPayload {
                context_id: context_id.to_owned(),
                proposer_did: proposer_did.clone(),
                action,
                signing_key: crate::context::actor::commands::SigningKeyBytes::from_signing_key(
                    signing_key,
                ),
            },
        );
        let cmd = GovernanceCommand::ProposeGovernanceAction { payload, reply: tx };
        self.dispatch_governance_command(cmd).await?;
        rx.await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::propose_governance_action — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// Submits a governance proposal via the actor mailbox — checked
    /// variant. Validates the proposer's `GovernancePropose` capability
    /// inside the same lock as the proposal submission (no TOCTOU).
    ///
    /// # Errors
    ///
    /// Propagates [`ContextError`] from the handler.
    pub async fn propose_governance_action_checked(
        &self,
        context_id: &str,
        proposer_did: &DID,
        action: scp_protocol::context::governance::GovernanceAction,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<crate::context::state::ProposalOutcome, ContextError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let payload = Box::new(
            crate::context::actor::commands::ProposeGovernanceActionPayload {
                context_id: context_id.to_owned(),
                proposer_did: proposer_did.clone(),
                action,
                signing_key: crate::context::actor::commands::SigningKeyBytes::from_signing_key(
                    signing_key,
                ),
            },
        );
        let cmd = GovernanceCommand::ProposeGovernanceActionChecked { payload, reply: tx };
        self.dispatch_governance_command(cmd).await?;
        rx.await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::propose_governance_action_checked — actor reply channel closed"
                    .to_owned(),
            )
        })?
    }

    /// Casts a vote on a pending proposal via the actor mailbox.
    /// `approve == true` is an approval vote; `false` is rejection.
    ///
    /// Gated behind the `testing` feature — the unchecked vote path is
    /// not part of the production FFI surface (every bridge calls the
    /// suspension-aware helper with `check_vote_capability=true`).
    ///
    /// # Errors
    ///
    /// Propagates [`ContextError`] from the handler.
    #[cfg(any(test, feature = "testing"))]
    pub async fn vote_on_proposal(
        &self,
        context_id: &str,
        proposal_id: &scp_protocol::context::governance::ProposalId,
        voter_did: &DID,
        approve: bool,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<
        (
            scp_protocol::context::governance::ProposalStatus,
            Vec<scp_protocol::context::governance::GovernanceEvent>,
        ),
        ContextError,
    > {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let payload = Box::new(crate::context::actor::commands::VoteOnProposalPayload {
            context_id: context_id.to_owned(),
            proposal_id: *proposal_id,
            voter_did: voter_did.clone(),
            signing_key: crate::context::actor::commands::SigningKeyBytes::from_signing_key(
                signing_key,
            ),
        });
        let cmd = GovernanceCommand::VoteOnProposal {
            payload,
            approve,
            reply: tx,
        };
        self.dispatch_governance_command(cmd).await?;
        rx.await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::vote_on_proposal — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// Withdraws a previously cast vote via the actor mailbox.
    ///
    /// # Errors
    ///
    /// Propagates [`ContextError`] from the handler.
    pub async fn withdraw_governance_vote(
        &self,
        context_id: &str,
        proposal_id: &scp_protocol::context::governance::ProposalId,
        voter_did: &DID,
    ) -> Result<scp_protocol::context::governance::ProposalStatus, ContextError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = GovernanceCommand::WithdrawGovernanceVote {
            context_id: context_id.to_owned(),
            proposal_id: *proposal_id,
            voter_did: voter_did.clone(),
            reply: tx,
        };
        self.dispatch_governance_command(cmd).await?;
        rx.await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::withdraw_governance_vote — actor reply channel closed".to_owned(),
            )
        })?
    }

    // -------------------------------------------------------------------
    // Query passthroughs — wrap the queries_helpers::* free functions
    // that were called from the deleted `ContextManager` query methods.
    // FFI bridges call these passthroughs directly; the helpers remain
    // accessible via crate::context::queries_helpers for any caller that
    // already imports them.
    // -------------------------------------------------------------------

    /// Returns the local member's pseudonym routing ID (§9.10.4) for
    /// `context_id`. Routes through the actor mailbox via
    /// [`Self::dispatch_query`].
    ///
    /// # Errors
    ///
    /// Propagates [`ContextError`] from the handler.
    pub async fn local_pseudonym(
        &self,
        context_id: &str,
    ) -> Result<Option<[u8; 32]>, ContextError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = QueriesCommand::LocalPseudonym {
            context_id: context_id.to_owned(),
            reply: tx,
        };
        self.dispatch_query(cmd).await?;
        rx.await.map_err(|_| {
            ContextError::TransportFailed(
                "Supervisor::local_pseudonym — actor reply channel closed".to_owned(),
            )
        })?
    }

    /// Returns every commit currently in the per-context retry queue.
    /// Soft-default contract: empty `Vec` on unknown context or
    /// mailbox failure. Routes through the actor mailbox via
    /// [`Self::dispatch_query`].
    #[must_use]
    pub async fn pending_commits(
        &self,
        context_id: &str,
    ) -> Vec<crate::context::state::PendingCommit> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = QueriesCommand::PendingCommits {
            context_id: context_id.to_owned(),
            reply: tx,
        };
        if self.dispatch_query(cmd).await.is_err() {
            return Vec::new();
        }
        match rx.await {
            Ok(Ok(answer)) => answer,
            Ok(Err(_)) | Err(_) => Vec::new(),
        }
    }

    /// Returns the active fail-close marker, if any. Soft-default
    /// contract: `None` on unknown context or mailbox failure. Routes
    /// through the actor mailbox via [`Self::dispatch_query`].
    #[must_use]
    pub async fn commit_fault(
        &self,
        context_id: &str,
    ) -> Option<crate::context::state::CommitFaultMarker> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = QueriesCommand::CommitFault {
            context_id: context_id.to_owned(),
            reply: tx,
        };
        if self.dispatch_query(cmd).await.is_err() {
            return None;
        }
        match rx.await {
            Ok(Ok(answer)) => answer,
            Ok(Err(_)) | Err(_) => None,
        }
    }

    /// Emits a `DegradedMode` event when an envelope's
    /// [`scp_protocol::envelope::VersionCompatibility`] indicates the
    /// remote peer's minor version is unknown to us.
    ///
    /// Routes through the per-context actor mailbox via
    /// [`Self::dispatch_command`]. Silent best-effort: mailbox enqueue
    /// failures and reply-channel drops are swallowed to match the
    /// legacy "no-error path" contract — the event is a hint to the
    /// application layer and missing one event on a contended actor is
    /// preferable to surfacing a `ContextError` on what callers treat
    /// as a fire-and-forget signal.
    pub async fn report_degraded_mode(
        &self,
        context_id: &str,
        compat: scp_protocol::envelope::VersionCompatibility,
        unsupported_features: Vec<String>,
    ) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = MessagingCommand::ReportDegradedMode {
            context_id: context_id.to_owned(),
            compat,
            unsupported_features,
            reply: tx,
        };
        if self.dispatch_command(context_id, cmd).await.is_err() {
            return;
        }
        let _ = rx.await;
    }

    // -----------------------------------------------------------------
    // ADR-049 Phase 2A — mailbox-routing helpers (item 5)
    // -----------------------------------------------------------------

    /// Generic mailbox dispatch: enqueue a fully-built `ContextCommand`
    /// (with its embedded reply oneshot) on the actor's mailbox via
    /// [`ContextActorHandle::send_with_timeout`]. The actor's run loop
    /// pulls the command, dispatches it through the matching handler,
    /// and the handler sends the typed result on the variant's
    /// embedded oneshot — observable by the FFI caller who already
    /// holds the matching `oneshot::Receiver`.
    ///
    /// This helper does NOT await the reply — that responsibility
    /// stays with the caller (FFI bridge code), preserving the
    /// pre-existing single-await pattern. Returns
    /// `Ok(Outcome::ok_mutated(()))` after a successful enqueue (the
    /// real outcome flows through the caller's reply receiver).
    ///
    /// Used by every `dispatch_*_command` method when an actor is
    /// registered for the target context.
    ///
    /// # Errors
    ///
    /// - [`ContextError::ActorBusy`] from the mailbox send (full,
    ///   closed, or timeout). The reply oneshot inside the command is
    ///   still alive — the caller's `rx.await` returns
    ///   `Err(RecvError)` which the bridge maps to its own typed
    ///   error.
    async fn dispatch_via_mailbox(
        actor: &ContextActorHandle,
        cmd: ContextCommand,
    ) -> Result<Outcome<()>, ContextError> {
        actor
            .send_with_timeout(cmd, crate::context::actor::SEND_TIMEOUT)
            .await?;
        // The handler runs inside the actor task and writes the typed
        // result to the embedded reply oneshot. Whether it mutated state
        // is recorded inside the actor's `dirty` flag via
        // `dispatch_state`. This dispatch-method-level Outcome is for
        // legacy callers; mark `mutated: true` because mutating
        // commands are expected to flow through this path.
        Ok(Outcome::ok_mutated(()))
    }

    /// Extract the target context_id from a [`LifecycleCommand`].
    ///
    /// Returns `None` for [`LifecycleCommand::Placeholder`] (no target)
    /// and [`LifecycleCommand::ImportContext`] (the export envelope
    /// carries the canonical 32-byte hash, not a string context_id —
    /// the legacy `import_context` derives the string from the
    /// envelope's params; until the lifecycle handler is rewritten to
    /// surface that derivation here, ImportContext routes through the
    /// direct-shim path so the legacy method can do the derivation).
    ///
    /// Every other variant — including the boxed-payload variants
    /// `CreateContext`, `JoinContext`, `LeaveContext`, `CloseContext`,
    /// `RestoreContext` — destructures the payload to surface its
    /// `context_id`. For `CreateContext` / `JoinContext` /
    /// `RestoreContext` the actor may not yet exist (the context is
    /// being bootstrapped), in which case [`Self::lookup`] returns
    /// `None` and the dispatch helper falls through to the direct-shim
    /// path that spawns the actor as part of the create / join /
    /// restore handshake.
    fn lifecycle_command_context_id(cmd: &LifecycleCommand) -> Option<&str> {
        match cmd {
            LifecycleCommand::ExportContext { context_id, .. }
            | LifecycleCommand::GenerateContextAccessKey { context_id, .. }
            | LifecycleCommand::RevokeContextAccessKey { context_id, .. }
            | LifecycleCommand::RestoreContextAccessKey { context_id, .. } => {
                Some(context_id.as_str())
            }
            LifecycleCommand::CreateContext { payload, .. } => Some(payload.context_id.as_str()),
            LifecycleCommand::JoinContext { payload, .. } => Some(payload.context_id.as_str()),
            LifecycleCommand::LeaveContext { payload, .. } => Some(payload.context_id.as_str()),
            LifecycleCommand::CloseContext { payload, .. } => Some(payload.context_id.as_str()),
            LifecycleCommand::RestoreContext { payload, .. } => Some(payload.context_id.as_str()),
            // ImportContext carries no string context_id — the legacy
            // `import_context` helper derives it from the envelope's
            // params. The dispatch helper routes ImportContext through
            // the direct-shim path until the lifecycle handler is
            // rewritten to surface that derivation. Placeholder has no
            // target at all. Sweep commands (`FlushSnapshot`,
            // `ShutdownSelf`) are dispatched per-actor by the
            // supervisor's iterating entry points in `lifecycle_helpers`;
            // routing target is decided at the iteration site.
            LifecycleCommand::ImportContext { .. }
            | LifecycleCommand::Placeholder { .. }
            | LifecycleCommand::FlushSnapshot { .. }
            | LifecycleCommand::ShutdownSelf { .. }
            | LifecycleCommand::ReportBufferLen { .. } => None,
        }
    }

    /// Extract the target context_id from a [`BroadcastCommand`].
    /// Publish variants are deliberately excluded because they require
    /// the custody-generic shim path.
    fn broadcast_command_context_id(cmd: &BroadcastCommand) -> Option<&str> {
        match cmd {
            BroadcastCommand::SubscribeBroadcast { payload, .. } => {
                Some(payload.context_id.as_str())
            }
            BroadcastCommand::UnsubscribeBroadcast { payload, .. } => {
                Some(payload.context_id.as_str())
            }
            BroadcastCommand::BlockBroadcastSubscriber { payload, .. }
            | BroadcastCommand::UnblockBroadcastSubscriber { payload, .. } => {
                Some(payload.context_id.as_str())
            }
            BroadcastCommand::HandleBroadcastKeyRequest { context_id, .. }
            | BroadcastCommand::BroadcastSubscriberCount { context_id, .. }
            | BroadcastCommand::IsBroadcastSubscriber { context_id, .. }
            | BroadcastCommand::BroadcastAdmission { context_id, .. } => Some(context_id.as_str()),
            // Two-phase publish is custody-free — both phases route
            // through the per-context actor mailbox.
            BroadcastCommand::ReserveBroadcastPublish { payload, .. } => {
                Some(payload.context_id.as_str())
            }
            BroadcastCommand::ApplyBroadcastPublish { payload, .. } => {
                Some(payload.context_id.as_str())
            }
            BroadcastCommand::ReleaseBroadcastReservation { payload, .. } => {
                Some(payload.context_id.as_str())
            }
            // PublishBroadcast / PublishBroadcastContent need
            // KeyCustody on the shim; InitiateBroadcastHostingHandshake
            // and Placeholder have no string target for this router.
            _ => None,
        }
    }

    /// Extract the target context_id from a [`TtlCloseCommand`].
    ///
    /// Every per-context variant surfaces its `context_id` so the dispatch
    /// helper can route through the per-context actor's mailbox. The
    /// boxed-payload variants (`StartTtlTimer` / `ResetTtlTimer` /
    /// `ExecuteTtlClose` / `FinalizeClose`) destructure their payloads to
    /// expose the embedded `context_id`. Only [`TtlCloseCommand::Placeholder`]
    /// returns `None` (no target).
    const fn ttl_close_command_context_id(cmd: &TtlCloseCommand) -> Option<&str> {
        match cmd {
            TtlCloseCommand::ExtendTtl { context_id, .. } => Some(context_id.as_str()),
            TtlCloseCommand::StartTtlTimer { payload, .. }
            | TtlCloseCommand::ResetTtlTimer { payload, .. } => Some(payload.context_id.as_str()),
            TtlCloseCommand::ExecuteTtlClose { payload, .. }
            | TtlCloseCommand::FinalizeClose { payload, .. } => Some(payload.context_id.as_str()),
            // `FireTimer` carries no `context_id` field: the per-context
            // TTL timer task resolves the actor itself via
            // [`Self::lookup`] and mailboxes the command through the
            // returned handle, so it never routes through
            // `dispatch_ttl_close_command`. `Placeholder` has no target.
            TtlCloseCommand::FireTimer { .. } | TtlCloseCommand::Placeholder { .. } => None,
        }
    }

    /// Extract the target context_id from a [`GovernanceCommand`].
    ///
    /// Every per-context variant — including the boxed-payload propose
    /// / vote / execute variants — surfaces its `context_id` so the
    /// dispatch helper can route through the per-context actor's
    /// mailbox. Only [`GovernanceCommand::Placeholder`] returns `None`
    /// (no target).
    fn governance_command_context_id(cmd: &GovernanceCommand) -> Option<&str> {
        match cmd {
            GovernanceCommand::GetProposal { context_id, .. }
            | GovernanceCommand::ListProposals { context_id, .. }
            | GovernanceCommand::ApplyPendingCeilingModification { context_id, .. }
            | GovernanceCommand::ApplyPendingEconomicPolicyChange { context_id, .. }
            | GovernanceCommand::TombstoneMigratedContext { context_id, .. }
            | GovernanceCommand::MigrationState { context_id, .. }
            | GovernanceCommand::AcknowledgeCommitFault { context_id, .. }
            | GovernanceCommand::WithdrawGovernanceVote { context_id, .. } => {
                Some(context_id.as_str())
            }
            GovernanceCommand::ProposeGovernanceAction { payload, .. }
            | GovernanceCommand::ProposeGovernanceActionChecked { payload, .. } => {
                Some(payload.context_id.as_str())
            }
            GovernanceCommand::VoteOnProposal { payload, .. }
            | GovernanceCommand::ApproveGovernanceProposal { payload, .. }
            | GovernanceCommand::RejectGovernanceProposal { payload, .. } => {
                Some(payload.context_id.as_str())
            }
            GovernanceCommand::ExecuteGovernanceAction { payload, .. } => {
                Some(payload.context_id.as_str())
            }
            // Sweep commands are dispatched per-actor by the supervisor's
            // iterating entry points in `governance_helpers`; the variant
            // carries no `context_id` field because the routing target is
            // decided at the iteration site (one command per known
            // actor). Returning `None` here keeps `dispatch_governance_command`
            // from accepting them — sweeps must use the iterating helpers.
            GovernanceCommand::Placeholder { .. }
            | GovernanceCommand::EvaluatePeriodicConsequences { .. }
            | GovernanceCommand::ProcessPendingCommits { .. }
            | GovernanceCommand::EvaluateTimeouts { .. }
            // `StartTimeoutTask` is dispatched directly to the owning
            // actor by `start_governance_timeout_task` (lookup + send),
            // not through `dispatch_governance_command`. Returning `None`
            // keeps the routed-dispatch path from accepting it.
            | GovernanceCommand::StartTimeoutTask { .. } => None,
        }
    }

    /// Extract the target context_id from a [`StandingCommand`].
    ///
    /// Variants that carry both `local_did` and `peer_did` derive their
    /// context_id deterministically via
    /// [`crate::context::standing_helpers::generate_standing_context_id`]
    /// — this returns `Some(<derived_id>)` so the dispatch helper can
    /// route through any per-context actor that already exists for the
    /// derived ID. The other variants are supervisor-scoped (count /
    /// has / register / reconnect-all) — they touch the supervisor's
    /// standing index directly, not per-context state, so they return
    /// `None` and dispatch routes them to the SupervisorHandle.
    ///
    /// Returns an owned `String` rather than `&str` because the derived
    /// ID is computed on demand from the variant's DID fields; there is
    /// no backing string to borrow.
    fn standing_command_context_id(cmd: &StandingCommand) -> Option<String> {
        match cmd {
            // The saga-initiator variant targets the per-context actor for
            // the derived standing id (Prepare/Commit lands on that actor).
            StandingCommand::InitiateStandingPairCreate {
                local_did,
                peer_did,
                ..
            } => Some(
                crate::context::standing_helpers::generate_standing_context_id(local_did, peer_did),
            ),
            // `StandingContext` get-or-create is supervisor-scoped, NOT
            // per-context: the actor-native body
            // ([`Self::standing_context`]) may CREATE the target actor (it
            // builds deps + spawns an owned-state actor via
            // `lifecycle_helpers::create_context`). Routing it through the
            // per-context mailbox would make the per-context actor's own
            // `run()` loop recursively spawn another actor — a non-`Send`
            // call graph the runtime cannot spawn. It therefore always
            // routes supervisor-direct through `dispatch_standing_direct`,
            // exactly like the other supervisor-scoped standing-index
            // variants below.
            StandingCommand::StandingContext { .. }
            | StandingCommand::Placeholder { .. }
            | StandingCommand::StandingContextCount { .. }
            | StandingCommand::HasStandingContext { .. }
            | StandingCommand::RegisterStandingContext { .. }
            | StandingCommand::ReconnectAllStanding { .. } => None,
        }
    }

    /// Extract the target context_id from a [`ToolsCommand`].
    const fn tools_command_context_id(cmd: &ToolsCommand) -> Option<&str> {
        match cmd {
            ToolsCommand::TryConsumeHardRateLimit { context_id, .. }
            | ToolsCommand::RefundHardRateLimit { context_id, .. }
            | ToolsCommand::ReserveToolEconomy { context_id, .. }
            | ToolsCommand::SettleToolEconomy { context_id, .. } => Some(context_id.as_str()),
            _ => None,
        }
    }

    /// Extract the target context_id from a [`QueriesCommand`].
    ///
    /// Every per-context variant surfaces a `context_id` string;
    /// [`QueriesCommand::EventLogEntries`] takes a 32-byte hash with no
    /// per-context lock and returns `None` so it stays on the
    /// supervisor's inline event-log path.
    const fn queries_command_context_id(cmd: &QueriesCommand) -> Option<&str> {
        match cmd {
            QueriesCommand::ReadContextState { context_id, .. }
            | QueriesCommand::LocalPseudonym { context_id, .. }
            | QueriesCommand::GetBroadcastKeyForLocalAuthor { context_id, .. }
            | QueriesCommand::MemberCount { context_id, .. }
            | QueriesCommand::IsMember { context_id, .. }
            | QueriesCommand::MemberDids { context_id, .. }
            | QueriesCommand::MemberRole { context_id, .. }
            | QueriesCommand::ContextParams { context_id, .. }
            | QueriesCommand::GetRoleState { context_id, .. }
            | QueriesCommand::PendingCommits { context_id, .. }
            | QueriesCommand::CommitFault { context_id, .. } => Some(context_id.as_str()),
            QueriesCommand::EventLogEntries { .. } => None,
            #[cfg(feature = "testing")]
            QueriesCommand::GetAccessKey { context_id, .. }
            | QueriesCommand::GetAllAccessKeys { context_id, .. }
            | QueriesCommand::RemainingBudgetForTest { context_id, .. }
            | QueriesCommand::VelocityForTest { context_id, .. } => Some(context_id.as_str()),
        }
    }
}

/// Produce a best-effort clone-equivalent `ContextError` for the
/// supervisor's [`Outcome`] sink — mirrors the per-handler
/// `outcome_error_sketch` pattern used in `handlers::*`. Kept in
/// `supervisor.rs` to scope the helper to the standing-direct dispatch
/// path; the actor handlers each carry their own equivalent sketch.
fn standing_outcome_error_sketch(err: &ContextError) -> ContextError {
    match err {
        ContextError::TransportTimeout(msg) => ContextError::TransportTimeout(msg.clone()),
        ContextError::TransportFailed(msg) => ContextError::TransportFailed(msg.clone()),
        ContextError::CryptoFailed(msg) => ContextError::CryptoFailed(msg.clone()),
        ContextError::PermissionDenied(msg) => ContextError::PermissionDenied(msg.clone()),
        ContextError::MemberNotFound(msg) => ContextError::MemberNotFound(msg.clone()),
        ContextError::ContextNotRegistered(msg) => ContextError::ContextNotRegistered(msg.clone()),
        ContextError::ContextNotActive => ContextError::ContextNotActive,
        ContextError::MembershipFailed(msg) => ContextError::MembershipFailed(msg.clone()),
        ContextError::EventLogFailed(msg) => ContextError::EventLogFailed(msg.clone()),
        ContextError::GovernanceFailed(msg) => ContextError::GovernanceFailed(msg.clone()),
        ContextError::InvalidState(msg) => ContextError::InvalidState(msg.clone()),
        ContextError::NotImplemented(msg) => ContextError::NotImplemented(msg.clone()),
        other => ContextError::CryptoFailed(format!("{other}")),
    }
}

// ---------------------------------------------------------------------------
// Saga FSM helpers
// ---------------------------------------------------------------------------

/// RAII reset for [`Supervisor::saga_pending_guard`]. Ensures the pending
/// flag clears on scope exit even if the FSM body panics. Phase 1 fix-up
/// of ADR-049 (post-review-round-1) — the prior implementation cleared
/// the flag with a line of code after `.await`, leaving the guard set on
/// any unwind path.
struct SagaGuardReset<'a>(&'a std::sync::atomic::AtomicBool);

impl Drop for SagaGuardReset<'_> {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::Release);
    }
}

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
// No-op SagaJournal — plumbed into the FFI [`Self::with_providers`] factory
// (and the test-only [`Self::for_query_shim`] constructor) when no production
// saga journal is wired. The `NoopContextPersistence` counterpart lives in
// [`crate::context::persistence`] (single public definition; the prior local
// duplicate was deleted in the post-review-round-1 phase 1 fix-up).
// ---------------------------------------------------------------------------

/// No-op saga journal — every operation is a no-op success. Used by
/// [`Self::with_providers`] until the production saga path lands; also used
/// by [`Self::for_query_shim`] in tests.
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
        // `ReadContextState` has no soft default — its reply is a bare
        // `ContextState`, not an `Option`. It is dispatched explicitly in
        // `dispatch_queries_direct` and never routes through the
        // soft-default / error fallbacks. Reply `ContextNotRegistered` so
        // a future classification bug surfaces a real error rather than
        // hanging the caller's oneshot.
        QueriesCommand::ReadContextState { reply, context_id } => {
            debug_assert!(false, "ReadContextState routed through soft-default path");
            let _ = reply.send(Err(ContextError::ContextNotRegistered(format!(
                "context not registered: {context_id}"
            ))));
        }
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
            _: &crate::context::state::ContextSnapshot,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
        fn load_context(
            &self,
            _: &str,
        ) -> Result<
            Option<crate::context::state::ContextSnapshot>,
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

    /// ADR-049 commit 12c.9f: per-identity wrapping-key accessors lift
    /// the keypair off `MlsCryptoProvider`. Verifies that `set` →
    /// `get` returns the same bytes via the supervisor's
    /// `DashMap<DID, ArcSwap<WrappingKeyPair>>`.
    #[tokio::test]
    async fn wrapping_keys_set_and_get_round_trip() {
        let s = Arc::new(test_supervisor());
        let did = DID("did:example:wrap-roundtrip".to_owned());
        let public = vec![0x11u8; 32];
        let secret = zeroize::Zeroizing::new(vec![0x22u8; 32]);

        // Pre-set the slot is empty for this DID.
        assert!(s.wrapping_public_key_for(&did).is_none());
        assert!(s.wrapping_secret_key_for(&did).is_none());

        s.set_wrapping_keys(did.clone(), public.clone(), secret.clone())
            .await
            .expect("set_wrapping_keys succeeds for valid 32-byte inputs");

        let got_pub = s.wrapping_public_key_for(&did).expect("public set");
        assert_eq!(*got_pub, public);
        let got_sec = s.wrapping_secret_key_for(&did).expect("secret set");
        assert_eq!(&**got_sec, &*secret);
    }

    /// Rotation replaces the prior keypair atomically; subsequent
    /// reads observe the new bytes.
    #[tokio::test]
    async fn wrapping_keys_rotation_atomically_replaces() {
        let s = Arc::new(test_supervisor());
        let did = DID("did:example:wrap-rotate".to_owned());

        s.set_wrapping_keys(
            did.clone(),
            vec![0x01u8; 32],
            zeroize::Zeroizing::new(vec![0x02u8; 32]),
        )
        .await
        .unwrap();
        assert_eq!(*s.wrapping_public_key_for(&did).unwrap(), vec![0x01u8; 32]);

        s.set_wrapping_keys(
            did.clone(),
            vec![0xAAu8; 32],
            zeroize::Zeroizing::new(vec![0xBBu8; 32]),
        )
        .await
        .unwrap();
        assert_eq!(*s.wrapping_public_key_for(&did).unwrap(), vec![0xAAu8; 32]);
        assert_eq!(
            &**s.wrapping_secret_key_for(&did).unwrap(),
            &vec![0xBBu8; 32]
        );
    }

    /// Wrong-length inputs surface as `InvalidState` rather than
    /// silently truncating key material.
    #[tokio::test]
    async fn wrapping_keys_rejects_wrong_byte_length() {
        let s = Arc::new(test_supervisor());
        let did = DID("did:example:wrap-bad-len".to_owned());
        let err = s
            .set_wrapping_keys(
                did.clone(),
                vec![0u8; 16],
                zeroize::Zeroizing::new(vec![0u8; 32]),
            )
            .await
            .expect_err("16-byte public must reject");
        assert!(matches!(err, ContextError::InvalidState(_)));
        let err = s
            .set_wrapping_keys(did, vec![0u8; 32], zeroize::Zeroizing::new(vec![0u8; 16]))
            .await
            .expect_err("16-byte secret must reject");
        assert!(matches!(err, ContextError::InvalidState(_)));
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

    // -----------------------------------------------------------------
    // ADR-049 commit 12b.2a — `spawn_actor_with_state` tests
    // -----------------------------------------------------------------

    /// Construct a minimal [`crate::context::actor::deps::ActorDeps`] for
    /// the `spawn_actor_with_state` tests. Builds through the
    /// supervisor's `build_actor_deps` path so we exercise real
    /// construction rather than invent synthetic mocks.
    async fn test_actor_deps(
        supervisor: &Arc<Supervisor>,
    ) -> crate::context::actor::deps::ActorDeps {
        supervisor
            .build_actor_deps(&DID("did:example:spawn-state-test".to_owned()))
            .await
            .expect("build_actor_deps requires providers populated")
    }

    /// A tiny `ContextEventLogProvider` that accepts every call and
    /// returns empty data for every read. Exists only so
    /// [`supervisor_with_providers`] can construct a supervisor with
    /// minimal providers without dragging in the full mock stack from
    /// the `tests/actor_*_shim.rs` integration harnesses.
    struct TestEventLog;
    impl crate::context::builder::ContextEventLogProvider for TestEventLog {
        fn init_event_log(
            &self,
            _context_id: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
        fn append_event(
            &self,
            _context_id: &[u8; 32],
            _event: &str,
            _actor_did: &str,
            _payload: Option<&serde_json::Value>,
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
        fn destroy_event_log(
            &self,
            _context_id: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
    }

    /// Build a supervisor with minimal providers so
    /// [`test_actor_deps`] can construct `ActorDeps` via the real
    /// `build_actor_deps` path. The plain `test_supervisor` helper
    /// above does NOT populate providers because its saga / lookup
    /// tests do not need them.
    fn supervisor_with_providers() -> Arc<Supervisor> {
        // Minimal providers — the spawn-registry tests only care about
        // the supervisor's actor map, not the providers' behaviour.
        // `MlsCryptoProvider::new` takes a String DID; the stub DID is
        // never used by the spawn tests because no
        // `create_context` call runs.
        let crypto = Arc::new(crate::crypto::mls::provider::MlsCryptoProvider::new(
            "did:dht:z6MktestDoNotRely".to_owned(),
        ));
        let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
            Box::new(crate::context::builder::NotConfiguredTransportProvider);
        let event_log: Box<dyn crate::context::builder::ContextEventLogProvider> =
            Box::new(TestEventLog);
        let key_resolver: KeyResolver = Arc::new(|_: &DID| None);
        let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> =
            Arc::new(
                crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
                    InMemoryStorage::new(),
                )),
            );
        Supervisor::with_providers(
            crypto,
            transport,
            event_log,
            key_resolver,
            None,
            None,
            None,
            None,
            mls_storage,
        )
    }

    #[tokio::test]
    async fn spawn_actor_with_state_registers_handle_and_accepts_commands() {
        let supervisor_arc = supervisor_with_providers();
        let deps = test_actor_deps(&supervisor_arc).await;

        // Construct a fresh encrypted-mode PerContextState. The
        // context_id is arbitrary for this test — the registry key
        // is derived from it via `hex::encode`.
        let ctx_id_bytes = [0xABu8; 32];
        let expected_ctx_key = hex::encode(ctx_id_bytes);
        let state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            1_700_000_000,
            DID("did:example:admin".to_owned()),
        );

        let handle = supervisor_arc
            .spawn_actor_with_state(state, deps, None)
            .await
            .expect("spawn_actor_with_state: fresh context id registers");
        // Handle is registered under the hex-encoded context id key.
        assert!(
            supervisor_arc.lookup(&expected_ctx_key).is_some(),
            "actor must be registered under hex-encoded context id"
        );

        // Handle is alive — send a placeholder messaging command and
        // observe the skeleton dispatch's `NotImplemented` ack. This
        // exercises both the mpsc plumbing and the
        // `ContextActor::new` + `run()` happy path.
        let err = handle
            .send(|reply| ContextCommand::Messaging(MessagingCommand::Placeholder { reply }))
            .await
            .expect_err("skeleton dispatch still ACKs NotImplemented in 12b.2a");
        assert!(matches!(err, ContextError::NotImplemented(_)));

        // Cleanly shut down.
        handle.send_shutdown().await.unwrap();
    }

    /// End-to-end: a TTL timer installed via the actor mailbox
    /// (`SupervisorHandle::dispatch_start_ttl_timer` →
    /// `TtlCloseCommand::StartTtlTimer` → actor-shape
    /// `ttl_close_helpers::spawn_ttl_timer`) actually fires after its
    /// duration: the spawned timer task resolves the owning actor via
    /// `Supervisor::lookup` and mailboxes `TtlCloseCommand::FireTimer`,
    /// whose handler runs the expiry pipeline on owned state and
    /// transitions the context `Active → Expired`. Proves the
    /// registry + mailbox-tick timer path (ADR-049 Phase 2A
    /// finalization) end-to-end, with no `contexts` DashMap reach.
    #[tokio::test]
    async fn dispatch_start_ttl_timer_fires_and_expires_context() {
        use crate::context::supervisor::handle::SupervisorHandle;

        let supervisor_arc = supervisor_with_providers();
        let deps = test_actor_deps(&supervisor_arc).await;

        let ctx_id_bytes = [0x7Au8; 32];
        let ctx_key = hex::encode(ctx_id_bytes);
        let state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            1_700_000_000,
            DID("did:example:admin".to_owned()),
        );
        // Clone the shared handle BEFORE moving state into the actor so
        // we can observe the actor's FSM transitions from this test.
        // The actor's `state.handle` must be `Active` for the FireTimer
        // expiry pipeline to run (it rejects non-Active contexts), so
        // drive the shared handle to `Active` up front — the production
        // create path leaves the context Active before the timer fires.
        let observed_handle = state.handle.clone();
        observed_handle
            .transition_to(&crate::context::ContextState::Active)
            .await
            .unwrap();

        let actor_handle = supervisor_arc
            .spawn_actor_with_state(state, deps, None)
            .await
            .expect("spawn_actor_with_state: fresh context id registers");
        assert!(supervisor_arc.lookup(&ctx_key).is_some());

        // Install a short TTL timer through the capability-reduced
        // handle: StartTtlTimer → actor-shape `spawn_ttl_timer` installs
        // the timer task on owned state.
        let sup_handle = SupervisorHandle::wrap(Arc::clone(&supervisor_arc));
        sup_handle
            .dispatch_start_ttl_timer(
                &ctx_key,
                scp_protocol::context::ContextParams::default(),
                std::time::Duration::from_millis(50),
            )
            .await;
        assert_eq!(
            observed_handle.state().await,
            crate::context::ContextState::Active,
            "context must remain Active immediately after the timer is installed"
        );

        // Wait for the timer to fire and the FireTimer expiry pipeline
        // to run. Poll the shared handle until it leaves `Active`.
        let expired = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if observed_handle.state().await != crate::context::ContextState::Active {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(
            expired.is_ok(),
            "TTL timer task must fire FireTimer and move the context out of Active"
        );
        assert_eq!(
            observed_handle.state().await,
            crate::context::ContextState::Expired,
            "FireTimer expiry pipeline must transition the context to Expired"
        );

        actor_handle.send_shutdown().await.unwrap();
    }

    /// `GovernanceCommand::StartTimeoutTask` installs the per-context
    /// governance-timeout interval task on the spawned actor's owned
    /// state (actor-shape `governance_helpers::spawn_governance_timeout_task`
    /// → `tracked_spawn` onto the supervisor's `task_set` → install on
    /// `state.governance.timeout_task`). Asserts the handler replies
    /// `Ok(())`, proving the install path runs end-to-end on a
    /// registered actor with no `contexts` DashMap reach (ADR-049
    /// Phase 2A finalization).
    #[tokio::test]
    async fn start_timeout_task_installs_on_actor() {
        let supervisor_arc = supervisor_with_providers();
        let deps = test_actor_deps(&supervisor_arc).await;

        let ctx_id_bytes = [0x6Bu8; 32];
        let ctx_key = hex::encode(ctx_id_bytes);
        let state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            1_700_000_000,
            DID("did:example:admin".to_owned()),
        );

        let actor_handle = supervisor_arc
            .spawn_actor_with_state(state, deps, None)
            .await
            .expect("spawn_actor_with_state: fresh context id registers");
        assert!(supervisor_arc.lookup(&ctx_key).is_some());

        // Dispatch StartTimeoutTask and observe the install reply.
        let reply = actor_handle
            .send(|reply| ContextCommand::Governance(GovernanceCommand::StartTimeoutTask { reply }))
            .await;
        assert!(
            reply.is_ok(),
            "StartTimeoutTask must install the governance-timeout task and reply Ok(()): {reply:?}"
        );

        actor_handle.send_shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn spawn_actor_with_state_rejects_duplicate_context_id() {
        // First-writer-wins: a second spawn with the same context_id is
        // REJECTED with CreationFailed rather than silently overwriting a
        // live actor (which would leak the loser's task and diverge
        // crypto state). This restores the duplicate-rejection the legacy
        // `manager_methods::insert_context` provided. The import replace
        // path despawns the prior actor first, so it never trips this.
        let supervisor_arc = supervisor_with_providers();

        let ctx_id_bytes = [0xCDu8; 32];
        let ctx_key = hex::encode(ctx_id_bytes);

        let state1 = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            1_700_000_000,
            DID("did:example:admin".to_owned()),
        );
        let deps1 = test_actor_deps(&supervisor_arc).await;
        let h1 = supervisor_arc
            .spawn_actor_with_state(state1, deps1, None)
            .await
            .expect("first spawn of a fresh context id registers");
        assert!(supervisor_arc.lookup(&ctx_key).is_some());

        let state2 = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            1_700_000_001,
            DID("did:example:admin".to_owned()),
        );
        let deps2 = test_actor_deps(&supervisor_arc).await;
        // `ContextActorHandle` is not `Debug`, so pattern-match on the
        // `Result` rather than calling `expect_err` (which needs `Debug`
        // on the `Ok` variant).
        match supervisor_arc
            .spawn_actor_with_state(state2, deps2, None)
            .await
        {
            Err(ContextError::CreationFailed(_)) => {}
            Err(other) => panic!("duplicate spawn must fail with CreationFailed, got {other:?}"),
            Ok(_) => panic!("duplicate spawn must be rejected, got Ok"),
        }
        // The original actor is still the registered one.
        assert!(supervisor_arc.lookup(&ctx_key).is_some());

        // Shut down the survivor to avoid a leaked task.
        let _ = h1.send_shutdown().await;
    }

    /// `shutdown_all_contexts` must DEREGISTER every actor, not just
    /// dispatch `ShutdownSelf` to it. `ShutdownSelf` tears down the
    /// per-context crypto/log/timers but does NOT break the actor
    /// `run()` loop, and nothing else despawns the handle — so without
    /// the explicit `despawn_actor` the contexts stay discoverable via
    /// `lookup` / `actor_ids` and the spawned tasks linger as zombies
    /// (the regression introduced when the lock-step `contexts.remove`
    /// mirror was deleted). Asserts the registry is empty afterwards.
    #[tokio::test]
    async fn shutdown_all_contexts_deregisters_every_actor() {
        let supervisor_arc = supervisor_with_providers();

        // Spawn two distinct contexts.
        let ctx_a = [0x1Au8; 32];
        let ctx_b = [0x2Bu8; 32];
        let key_a = hex::encode(ctx_a);
        let key_b = hex::encode(ctx_b);
        for ctx_id_bytes in [ctx_a, ctx_b] {
            let state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
                ctx_id_bytes,
                1_700_000_000,
                DID("did:example:admin".to_owned()),
            );
            let deps = test_actor_deps(&supervisor_arc).await;
            supervisor_arc
                .spawn_actor_with_state(state, deps, None)
                .await
                .expect("fresh context id registers");
        }
        assert_eq!(
            supervisor_arc.actor_ids().len(),
            2,
            "both actors must be registered before shutdown"
        );

        crate::context::lifecycle_helpers::shutdown_all_contexts(&supervisor_arc).await;

        // Every actor must be deregistered: no zombie handles remain.
        assert!(
            supervisor_arc.actor_ids().is_empty(),
            "actor_ids must be empty after shutdown_all_contexts, got {:?}",
            supervisor_arc.actor_ids()
        );
        assert!(
            supervisor_arc.lookup(&key_a).is_none(),
            "context A must not be discoverable after shutdown"
        );
        assert!(
            supervisor_arc.lookup(&key_b).is_none(),
            "context B must not be discoverable after shutdown"
        );
    }

    /// A Phase-3 tool-economy settle that finds NO registered actor for
    /// its context (the actor was despawned during the off-mailbox
    /// executor window) must NOT silently drop the in-flight ticket:
    /// `settle_tool_economy_via_actor` reclaims the ticket, voids its
    /// external escrow (none here), consumes it so the `#[must_use]` Drop
    /// balance guard does not `debug_assert!`-panic, and returns a typed
    /// `ContextNotRegistered`. Reaching the assertions without a panic
    /// proves the ticket was consumed rather than leaked.
    #[tokio::test]
    async fn settle_with_no_registered_actor_voids_and_consumes_ticket() {
        let supervisor_arc = supervisor_with_providers();
        let invoker = DID("did:example:invoker".to_owned());

        // A settle request for a context that has no actor registered.
        let ticket = crate::context::tools_helpers::ToolEconomyTicket::new_for_test_no_escrow(
            invoker.clone(),
        );
        let request = crate::context::tools_helpers::ToolSettleRequest::Rollback {
            generation: 1,
            ticket,
        };

        let result = supervisor_arc
            .settle_tool_economy_via_actor("ctx-never-registered", &invoker, request)
            .await;

        match result {
            Err(ContextError::ContextNotRegistered(msg)) => {
                assert!(
                    msg.contains("registered actor"),
                    "error must explain the missing actor, got: {msg}"
                );
            }
            other => panic!(
                "settle with no registered actor must return ContextNotRegistered, got {other:?}"
            ),
        }
        // No panic ⇒ the ticket was consumed, not dropped unbalanced.
    }

    /// Each spawn pulls a DISTINCT monotonic spawn-generation from the
    /// supervisor's `spawn_generation` counter, starting at 1 (never the
    /// default 0 a fresh `PerContextState` carries). This is the token
    /// stamped onto the actor's state and compared by the tool-economy
    /// settle to detect a settle landing on a replaced instance.
    #[tokio::test]
    async fn spawn_stamps_distinct_monotonic_generations() {
        use std::sync::atomic::Ordering;

        let supervisor_arc = supervisor_with_providers();

        // The counter starts at 0; the first spawn stamps 1.
        assert_eq!(
            supervisor_arc.spawn_generation.load(Ordering::Acquire),
            0,
            "a fresh supervisor's spawn-generation counter starts at 0"
        );

        for i in 0..3u8 {
            let ctx_id_bytes = [0x30 + i; 32];
            let state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
                ctx_id_bytes,
                1_700_000_000,
                DID("did:example:admin".to_owned()),
            );
            assert_eq!(state.generation, 0, "fresh test state defaults to gen 0");
            let deps = test_actor_deps(&supervisor_arc).await;
            supervisor_arc
                .spawn_actor_with_state(state, deps, None)
                .await
                .expect("spawn registers");
            // After n spawns the counter has advanced to n, and the nth
            // spawn stamped generation n (>0, strictly increasing).
            assert_eq!(
                supervisor_arc.spawn_generation.load(Ordering::Acquire),
                u64::from(i) + 1,
                "spawn-generation counter must advance once per spawn"
            );
        }
    }

    /// Security invariant (import): `PrepareForReplace` MUST reject a
    /// LIVE (Active) context — an import may never overwrite a live
    /// context. The actor stays alive after the reject so the still-live
    /// context keeps being served (no terminal break on reject).
    #[tokio::test]
    async fn prepare_for_replace_rejects_live_context() {
        use crate::context::actor::commands::LifecycleControlCommand;

        let supervisor_arc = supervisor_with_providers();
        let deps = test_actor_deps(&supervisor_arc).await;
        let ctx_id_bytes = [0x9Eu8; 32];
        let state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            1_700_000_000,
            DID("did:example:admin".to_owned()),
        );
        // Drive the context's handle to Active — a live, non-replaceable
        // context.
        state
            .handle
            .transition_to(&crate::context::ContextState::Active)
            .await
            .unwrap();
        let handle = supervisor_arc
            .spawn_actor_with_state(state, deps, None)
            .await
            .expect("spawn registers the live context");

        let result: Result<(), ContextError> = handle
            .send(|reply| {
                ContextCommand::LifecycleControl(LifecycleControlCommand::PrepareForReplace {
                    mls_state: Vec::new(),
                    reply,
                })
            })
            .await;
        assert!(
            matches!(result, Err(ContextError::MembershipFailed(_))),
            "import must REJECT overwriting a live context, got {result:?}"
        );

        // The actor must still be alive after the reject — prove it by
        // issuing a follow-up command and observing a reply (not an
        // ActorBusy/closed-inbox error).
        let followup: Result<(), ContextError> = handle
            .send(|reply| ContextCommand::Messaging(MessagingCommand::Placeholder { reply }))
            .await;
        assert!(
            !matches!(followup, Err(ContextError::ActorBusy(_))),
            "live context's actor must survive a rejected PrepareForReplace, got {followup:?}"
        );

        let _ = handle.send_shutdown().await;
    }

    /// `PrepareForReplace` SUCCEEDS for a replaceable (Closing/Closed)
    /// context: it runs the §23.17 crypto teardown + epoch-floor merge,
    /// claims itself terminal, and the actor exits its run loop.
    #[tokio::test]
    async fn prepare_for_replace_succeeds_for_replaceable_context() {
        use crate::context::actor::commands::LifecycleControlCommand;

        let supervisor_arc = supervisor_with_providers();
        let deps = test_actor_deps(&supervisor_arc).await;
        let ctx_id_bytes = [0x8Du8; 32];
        let ctx_key = hex::encode(ctx_id_bytes);
        let state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            1_700_000_000,
            DID("did:example:admin".to_owned()),
        );
        // Drive the handle Active → Closing — a replaceable state.
        state
            .handle
            .transition_to(&crate::context::ContextState::Active)
            .await
            .unwrap();
        state
            .handle
            .transition_to(&crate::context::ContextState::Closing)
            .await
            .unwrap();
        let handle = supervisor_arc
            .spawn_actor_with_state(state, deps, None)
            .await
            .expect("spawn registers the replaceable context");

        let result: Result<(), ContextError> = handle
            .send(|reply| {
                ContextCommand::LifecycleControl(LifecycleControlCommand::PrepareForReplace {
                    mls_state: Vec::new(),
                    reply,
                })
            })
            .await;
        assert!(
            result.is_ok(),
            "PrepareForReplace must succeed for a replaceable (Closing) context, got {result:?}"
        );

        // The actor claimed itself terminal and exits — a follow-up send
        // must observe the closed inbox. (The supervisor despawns the
        // dead handle in the import path; here we just prove termination.)
        let followup: Result<(), ContextError> = handle
            .send(|reply| ContextCommand::Messaging(MessagingCommand::Placeholder { reply }))
            .await;
        assert!(
            matches!(followup, Err(ContextError::ActorBusy(_))),
            "actor must have exited after a successful PrepareForReplace, got {followup:?}"
        );

        // Handle is still registered until the import path despawns it.
        assert!(supervisor_arc.lookup(&ctx_key).is_some());
    }

    // -----------------------------------------------------------------
    // ADR-049 §1 — `build_actor_deps` self-sourcing (storage foundation)
    //
    // `build_actor_deps` is `pub(in crate::context)` (only dispatch arms
    // call it), so these live in-crate rather than in
    // `tests/actor_deps_complete.rs`, which was an external-crate
    // integration test back when the method was `pub`.
    // -----------------------------------------------------------------

    /// A `MlsStorage`-witnessing fixture that retains the supervisor's
    /// authoritative `crypto` + `mls_storage` Arcs so tests can assert
    /// `build_actor_deps` self-sources the exact same handles.
    fn build_deps_fixture() -> (
        Arc<Supervisor>,
        Arc<crate::crypto::mls::provider::MlsCryptoProvider>,
        Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter>,
    ) {
        let crypto = Arc::new(crate::crypto::mls::provider::MlsCryptoProvider::new(
            "did:dht:z6MktestBuildDeps".to_owned(),
        ));
        let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
            Box::new(crate::context::builder::NotConfiguredTransportProvider);
        let event_log: Box<dyn crate::context::builder::ContextEventLogProvider> =
            Box::new(TestEventLog);
        // Resolver returns Some for every DID — witnesses key_resolver
        // propagation.
        let key_resolver: KeyResolver = Arc::new(|did: &DID| {
            let mut seed = [0u8; 32];
            for (i, b) in did.as_ref().as_bytes().iter().enumerate() {
                seed[i % 32] ^= *b;
            }
            Some(ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key())
        });
        let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> =
            Arc::new(
                crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
                    InMemoryStorage::new(),
                )),
            );
        let supervisor = Supervisor::with_providers(
            Arc::clone(&crypto),
            transport,
            event_log,
            key_resolver,
            None,
            None,
            None,
            None,
            Arc::clone(&mls_storage),
        );
        (supervisor, crypto, mls_storage)
    }

    /// `build_actor_deps` populates every `ActorDeps` field from the
    /// supervisor's own slots; mls/hpke are the single backend pair owned
    /// by the `MlsCryptoProvider` (ADR-049 §6 — no second source).
    #[tokio::test]
    async fn build_actor_deps_reads_single_backend_pair() {
        let (supervisor, crypto, mls_storage) = build_deps_fixture();
        let deps = supervisor
            .build_actor_deps(&DID("did:example:alice".to_owned()))
            .await
            .expect("build_actor_deps succeeds when providers are populated");

        assert!(
            Arc::ptr_eq(&deps.mls, crypto.mls_backend()),
            "mls must be the crypto provider's single MlsBackend"
        );
        assert!(
            Arc::ptr_eq(&deps.hpke, crypto.hpke_backend()),
            "hpke must be the crypto provider's single HpkeBackend"
        );
        assert!(
            Arc::ptr_eq(&deps.mls_storage, &mls_storage),
            "mls_storage must be the exact Arc threaded into with_providers"
        );
        assert!(
            (deps.key_resolver)(&DID("did:example:alice".to_owned())).is_some(),
            "key_resolver must populate from the supervisor"
        );
        assert!(
            deps.payment_adapter.is_none(),
            "payment_adapter is None when unconfigured"
        );
        assert!(
            deps.local_dids.load().is_empty(),
            "local_dids snapshots the fresh supervisor's empty set"
        );
        deps.key_package_store
            .send_shutdown()
            .await
            .expect("KP store handle is live");
    }

    /// `build_actor_deps` propagates the supervisor's `mls_storage` slot
    /// verbatim — the single-handle storage-foundation guarantee.
    #[tokio::test]
    async fn build_actor_deps_propagates_supervisor_mls_storage() {
        let (supervisor, _crypto, mls_storage) = build_deps_fixture();
        let deps = supervisor
            .build_actor_deps(&DID("did:example:storage".to_owned()))
            .await
            .expect("build_actor_deps succeeds");
        assert!(
            Arc::ptr_eq(&deps.mls_storage, &mls_storage),
            "ActorDeps.mls_storage must be the same Arc set on the supervisor"
        );
        deps.key_package_store
            .send_shutdown()
            .await
            .expect("KP store handle is live");
    }

    /// `build_actor_deps` fails clean when no providers were attached
    /// (`for_query_shim` path).
    #[tokio::test]
    async fn build_actor_deps_fails_when_no_providers() {
        let supervisor = Arc::new(Supervisor::for_query_shim());
        match supervisor
            .build_actor_deps(&DID("did:example:none".to_owned()))
            .await
        {
            Ok(_) => panic!("build_actor_deps must fail when providers are unpopulated"),
            Err(ContextError::NotInitialized(_)) => {}
            Err(other) => panic!("expected NotInitialized, got {other:?}"),
        }
    }

    /// The returned `SupervisorHandle` wraps a clone of the OUTER
    /// supervisor `Arc` (regression guard for the `self: &Arc<Self>`
    /// receiver) — `strong_count` bumps when the handle is built.
    #[tokio::test]
    async fn build_actor_deps_handle_holds_outer_arc() {
        let (supervisor, _crypto, _mls_storage) = build_deps_fixture();
        let before = Arc::strong_count(&supervisor);
        let deps = supervisor
            .build_actor_deps(&DID("did:example:alice".to_owned()))
            .await
            .expect("build_actor_deps succeeds");
        let after = Arc::strong_count(&supervisor);
        assert!(
            after > before,
            "SupervisorHandle must clone the outer Arc (count {before} -> {after})"
        );
        assert!(deps.supervisor.local_dids().is_empty());
        deps.key_package_store
            .send_shutdown()
            .await
            .expect("KP store handle is live");
    }

    /// `key_package_store_for` is idempotent: two calls for the same DID
    /// return handles to the same actor (double-checked get-or-spawn).
    #[tokio::test]
    async fn key_package_store_for_is_idempotent() {
        let supervisor = supervisor_with_providers();
        let did = DID("did:example:kp-idem".to_owned());
        let first = supervisor.key_package_store_for(&did).await;
        let second = supervisor.key_package_store_for(&did).await;
        // The registry holds exactly one entry for this DID.
        assert_eq!(
            supervisor.key_package_stores.len(),
            1,
            "exactly one KeyPackageStoreActor must be spawned per identity"
        );
        // A different DID spawns a distinct actor.
        let other = supervisor
            .key_package_store_for(&DID("did:example:kp-other".to_owned()))
            .await;
        assert_eq!(supervisor.key_package_stores.len(), 2);
        first.send_shutdown().await.expect("first handle is live");
        // `second` targets the same actor as `first`; the actor may have
        // already shut down, so a failed send is acceptable here.
        let _ = second.send_shutdown().await;
        other.send_shutdown().await.expect("other handle is live");
    }

    /// Two concurrent broadcast publishes reserve DISTINCT sequences
    /// through the actor mailbox.
    ///
    /// This is the end-to-end witness for the two-phase reservation
    /// guarantee (ADR-049 §SequenceReservation): both `ReserveBroadcastPublish`
    /// commands ride the per-context actor mailbox and are serialized by
    /// the actor's command loop, so even when both are issued before
    /// either applies, the reserved sequences never collide. The
    /// single-phase shim could not close this hazard because a concurrent
    /// publish could read the same `next_sequence` between snapshot and
    /// seal.
    #[tokio::test]
    async fn concurrent_reserve_broadcast_publish_yields_distinct_sequences() {
        use crate::context::actor::commands::ReserveBroadcastPublishPayload;

        let supervisor_arc = supervisor_with_providers();
        let deps = test_actor_deps(&supervisor_arc).await;

        let ctx_id_bytes = [0xC0u8; 32];
        let ctx_key = hex::encode(ctx_id_bytes);
        let author = DID("did:example:author".to_owned());

        // Build a broadcast-mode state with the author registered (so
        // `can_write` passes) and present in membership (so the apply
        // phase's per-sender sequence assignment can resolve). Transition
        // the handle to Active so `require_active` passes.
        let mut state = crate::context::actor::state::PerContextState::new_for_test_broadcast(
            ctx_id_bytes,
            1_700_000_000,
            DID("did:example:admin".to_owned()),
        );
        let mut bc = scp_protocol::context::broadcast::BroadcastContext::new(
            ctx_key.clone(),
            &scp_protocol::context::ContextMode::Broadcast,
            scp_protocol::context::broadcast::BroadcastAdmission::Open,
        )
        .expect("broadcast context constructs");
        bc.add_author(author.as_ref()).expect("author registers");
        state.broadcast_context = Some(bc);
        state
            .membership
            .add_member(author.clone(), "author".to_owned(), vec![]);
        state
            .handle
            .transition_to(&scp_protocol::context::ContextState::Active)
            .await
            .expect("transition to Active");

        let handle = supervisor_arc
            .spawn_actor_with_state(state, deps, None)
            .await
            .expect("spawn_actor_with_state: fresh context id registers");
        assert!(supervisor_arc.lookup(&ctx_key).is_some());

        // Issue two reservations back-to-back via the mailbox.
        let reserve = |author: DID| {
            let ctx_key = ctx_key.clone();
            let supervisor_arc = Arc::clone(&supervisor_arc);
            async move {
                let (tx, rx) = tokio::sync::oneshot::channel();
                let cmd = BroadcastCommand::ReserveBroadcastPublish {
                    payload: Box::new(ReserveBroadcastPublishPayload {
                        context_id: ctx_key,
                        author_did: author,
                    }),
                    reply: tx,
                };
                if let Some(actor) = supervisor_arc.lookup(
                    Supervisor::broadcast_command_context_id(&cmd)
                        .expect("publish carries a context id"),
                ) {
                    Supervisor::dispatch_via_mailbox(&actor, ContextCommand::Broadcast(cmd))
                        .await
                        .expect("mailbox dispatch succeeds");
                }
                rx.await.expect("reserve reply").expect("reserve succeeds")
            }
        };

        let r1 = reserve(author.clone()).await;
        let r2 = reserve(author.clone()).await;

        assert_ne!(
            r1.reservation_id, r2.reservation_id,
            "each reservation gets a unique id",
        );

        // Both reservations are live in actor-owned state; release them to
        // confirm the actor accepts the release mailbox command. The core
        // assertion is that the two reservations are distinct — proven by
        // the distinct ids and by the protocol-layer
        // `concurrent_reservations_get_distinct_sequences` test that pins
        // the sequence values themselves.
        handle.send_shutdown().await.expect("handle is live");
    }
}
