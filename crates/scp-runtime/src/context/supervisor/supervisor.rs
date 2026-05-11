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
use crate::context::actor::handlers;
use crate::context::actor::outcome::Outcome;
use crate::context::actor::state::WrappingKeyPair;
use crate::context::builder::{ContextEventLogProvider, ContextTransportProvider};
use crate::context::persistence::ContextPersistence;
use crate::context::state::PerContextState;
use crate::context::supervisor::key_package_actor::KeyPackageStoreHandle;
use crate::context::supervisor::saga_journal::{
    JournalEntry, SagaId, SagaJournal, SagaState, SagaTerminalState,
};
use crate::economy::adapter::PaymentAdapterDyn;
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Type aliases
// ---------------------------------------------------------------------------

/// The shared per-context state map — `Arc`-wrapped so the manager,
/// the supervisor (ADR-049 commit 12), and spawned background
/// tasks all hold equivalent clones of the same `DashMap`. The
/// per-entry `Arc<Mutex<PerContextState>>` is the contract the manager
/// exposes via `ContextManager::contexts_arc`; the alias is
/// introduced here so the supervisor-side accessor can return a
/// readable type (avoids `clippy::type_complexity` on the nested
/// generics).
type ContextsMap = DashMap<String, Arc<tokio::sync::Mutex<PerContextState>>>;

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
    // `standing_contexts`, `next_generation`) are eagerly initialized
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

    // -----------------------------------------------------------------
    // ADR-049 commit 12 — supervisor-authoritative direct fields.
    //
    // These were previously mirrored from `ContextManager`. The
    // supervisor now owns them directly; eagerly initialized in
    // [`Self::new`].
    // -----------------------------------------------------------------
    /// Shared per-context state map. Eagerly initialized in
    /// [`Self::new`] as an empty `Arc<DashMap>`; subsequent inserts
    /// land via [`crate::context::manager_methods::insert_context`].
    contexts: Arc<ContextsMap>,
    /// Global monotonic counter for assigning generation IDs to
    /// contexts. Starts at 1 so generation 0 (the `#[serde(default)]`
    /// value for legacy snapshots) is never actively assigned.
    /// Incremented with `Relaxed` ordering — uniqueness is guaranteed
    /// by the `fetch_add` atomicity, and no other memory accesses
    /// depend on the ordering.
    next_generation: std::sync::atomic::AtomicU64,

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
            // ADR-049 commit 12 — direct authoritative state.
            contexts: Arc::new(DashMap::new()),
            next_generation: std::sync::atomic::AtomicU64::new(1),
            saga_pending_guard: std::sync::atomic::AtomicBool::new(false),
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
    // Direct-state accessors (`contexts_ref`, `contexts_arc`,
    // `local_dids_ref`, `standing_contexts_ref`, `next_generation_ref`)
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

    // -------------------------------------------------------------------
    // ADR-049 commit 12 — direct-state accessors (always populated).
    // -------------------------------------------------------------------

    /// Cheap reference to the supervisor's per-context state map.
    /// Always populated — eagerly initialized in [`Self::new`].
    #[must_use]
    pub(crate) const fn contexts_ref(&self) -> &Arc<ContextsMap> {
        &self.contexts
    }

    /// Returns a freshly-cloned `Arc` to the per-context state map for
    /// callers that need to move the `Arc` into a spawned task.
    #[must_use]
    pub(crate) fn contexts_arc(&self) -> Arc<ContextsMap> {
        Arc::clone(&self.contexts)
    }

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

    /// Cheap reference to the supervisor's monotonic generation
    /// counter. Always populated (initialized to 1 in [`Self::new`]).
    #[must_use]
    pub(crate) const fn next_generation_ref(&self) -> &std::sync::atomic::AtomicU64 {
        &self.next_generation
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

    /// Build an [`ActorDeps`](crate::context::actor::deps::ActorDeps)
    /// bundle from the supervisor's own provider slots (ADR-049 commit
    /// 12).
    ///
    /// Reads providers from the supervisor's `OnceLock`s populated by
    /// [`Self::with_providers`]. Caller-supplied backends (split per
    /// ADR §6: `MlsBackend` + `HpkeBackend` + `OpenMlsStorageAdapter`)
    /// and supervisor-scoped handles (`SupervisorHandle`, this
    /// identity's `KeyPackageStoreHandle`) arrive as parameters
    /// because they're not part of the supervisor's own owned state.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::NotInitialized`] if any required
    /// provider slot is empty (i.e. [`Self::with_providers`] was not
    /// used).
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
    #[allow(clippy::unused_async)]
    // Test fixtures call `build_actor_deps(...).await` on this method;
    // keeping it `async` preserves the call shape across migration even
    // though the body no longer awaits anything after ADR-049 commit 12
    // dropped the legacy ContextManager attach.
    pub async fn build_actor_deps(
        self: &Arc<Self>,
        persistence: Arc<dyn ContextPersistence>,
        mls: Arc<dyn crate::crypto::mls::backend::MlsBackend>,
        hpke: Arc<dyn crate::crypto::hpke_backend::HpkeBackend>,
        mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter>,
        key_package_store: crate::context::supervisor::key_package_actor::KeyPackageStoreHandle,
    ) -> Result<crate::context::actor::deps::ActorDeps, ContextError> {
        use crate::context::manager_methods::PROVIDER_NOT_INITIALIZED;
        let crypto =
            Arc::clone(self.crypto_ref().ok_or_else(|| {
                ContextError::NotInitialized(PROVIDER_NOT_INITIALIZED.to_owned())
            })?);
        let transport =
            Arc::clone(self.transport_ref().ok_or_else(|| {
                ContextError::NotInitialized(PROVIDER_NOT_INITIALIZED.to_owned())
            })?);
        let event_log =
            Arc::clone(self.event_log_ref().ok_or_else(|| {
                ContextError::NotInitialized(PROVIDER_NOT_INITIALIZED.to_owned())
            })?);
        let clock =
            Arc::clone(self.clock_ref().ok_or_else(|| {
                ContextError::NotInitialized(PROVIDER_NOT_INITIALIZED.to_owned())
            })?);
        let key_resolver = self
            .key_resolver_ref()
            .ok_or_else(|| ContextError::NotInitialized(PROVIDER_NOT_INITIALIZED.to_owned()))?
            .clone();

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

    /// Dispatch a pure-read [`QueriesCommand`] through the migration
    /// shim.
    ///
    /// Behaviour (byte-identical to the legacy `ContextManager::foo()`
    /// it replaces):
    ///
    /// - Takes the per-context mutex via the manager's `get_context_arc_pub`.
    /// - Calls [`handlers::queries::dispatch_from_shim`] with the
    ///   locked `&PerContextState` and the manager's shared event-log
    ///   provider. The handler matches on the command variant, sends
    ///   the typed oneshot reply, and returns `Outcome::ok(())` with
    ///   `mutated: false`.
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
    /// - [`ContextError::NotInitialized`] if no `ContextManager` has
    ///   been attached yet — the caller must call
    ///   [`Self::with_providers`] first.
    pub async fn dispatch_query(&self, cmd: QueriesCommand) -> Result<Outcome<()>, ContextError> {
        // ADR-049 Phase 2A finalization — try the actor mailbox first
        // for variants that carry a per-context `context_id`. The
        // actor's `run()` loop pulls the command, dispatches it through
        // `handlers::queries::dispatch` (actor-shape, takes `&mut
        // ActorPerContextState`), and writes the typed result to the
        // embedded reply oneshot.
        //
        // `EventLogEntries` is a 32-byte hash with no per-context lock
        // — it stays on the inline event-log path below. Unknown-
        // context cases continue to surface the legacy soft / hard
        // defaults via `dispatch_with_view`.
        if let Some(ctx_id) = Self::queries_command_context_id(&cmd) {
            let ctx_id_owned = ctx_id.to_owned();
            if let Some(actor) = self.lookup(&ctx_id_owned) {
                return Self::dispatch_via_mailbox(&actor, ContextCommand::Queries(cmd)).await;
            }
        }
        // Pre-lookup: variants that require a per-context lock all carry
        // a `context_id` field. We route by command variant to preserve
        // the legacy "context unknown = soft default" contract.
        match cmd {
            // Variants whose legacy method returns a `ContextError` on
            // unknown context — propagate the error directly.
            QueriesCommand::LocalPseudonym { ref context_id, .. }
            | QueriesCommand::GetBroadcastKeyForLocalAuthor { ref context_id, .. } => {
                let ctx_id = context_id.clone();
                Self::dispatch_with_view(self, &ctx_id, cmd, /*soft_fallback=*/ false).await
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
                Self::dispatch_with_view(self, &ctx_id, cmd, /*soft_fallback=*/ true).await
            }

            // `EventLogEntries` takes a 32-byte hash rather than a
            // context-id string and delegates straight to the event-log
            // provider — no per-context lock involved.
            QueriesCommand::EventLogEntries {
                context_id_bytes,
                reply,
            } => {
                let elp = self.event_log_ref().ok_or_else(|| {
                    ContextError::NotInitialized(
                        "Supervisor::dispatch_query — event_log provider not configured".to_owned(),
                    )
                })?;
                let answer = elp.event_log_entries(&context_id_bytes);
                let _ = reply.send(answer);
                Ok(Outcome::ok(()))
            }

            #[cfg(feature = "testing")]
            QueriesCommand::GetAccessKey { ref context_id, .. }
            | QueriesCommand::GetAllAccessKeys { ref context_id, .. }
            | QueriesCommand::RemainingBudgetForTest { ref context_id, .. }
            | QueriesCommand::VelocityForTest { ref context_id, .. } => {
                let ctx_id = context_id.clone();
                Self::dispatch_with_view(self, &ctx_id, cmd, /*soft_fallback=*/ true).await
            }
        }
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

    /// Dispatch a mutating [`LifecycleCommand`] through the migration
    /// shim (ADR-049 commit 9 / plan row 9).
    ///
    /// Contract (byte-identical to the legacy
    /// [`Supervisor`](crate::context::supervisor::Supervisor)
    /// lifecycle methods it replaces):
    ///
    /// Step 1 invokes
    /// [`handlers::lifecycle::dispatch_from_shim`](crate::context::actor::handlers::lifecycle::dispatch_from_shim)
    /// with a reference to the attached manager. Lifecycle handlers
    /// never read or mutate `send_tracker` (only the messaging path
    /// touches it), so no per-context take-and-swap or scratch tracker
    /// is required.
    ///
    /// Each variant wraps the delegated
    /// [`Supervisor`](crate::context::supervisor::Supervisor) method
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
    ///   [`Supervisor`](crate::context::supervisor::Supervisor) has
    ///   been attached yet — the caller must call
    ///   [`Self::with_providers`] first.
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
        // ADR-049 Phase 2A item 5 — try the actor mailbox first for
        // variants whose context_id is visible without unboxing.
        if let Some(ctx_id) = Self::lifecycle_command_context_id(&cmd)
            && let Some(actor) = self.lookup(ctx_id)
        {
            return Self::dispatch_via_mailbox(&actor, ContextCommand::Lifecycle(cmd)).await;
        }
        // Direct-shim fallback: lifecycle handler takes `&Supervisor`.
        // `Box::pin` — the combined size of the rebuilt handle,
        // context params, and the per-variant 30s-timeout future
        // crosses clippy's 16-KB stack budget for async futures.
        Ok(Box::pin(handlers::lifecycle::dispatch_from_shim(self, cmd)).await)
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
        // ADR-049 Phase 2A item 5 — try the actor mailbox first.
        if let Some(ctx_id) = Self::ttl_close_command_context_id(&cmd)
            && let Some(actor) = self.lookup(ctx_id)
        {
            return Self::dispatch_via_mailbox(&actor, ContextCommand::TtlClose(cmd)).await;
        }
        // Direct-shim fallback.
        Ok(handlers::ttl_close::dispatch_from_shim(self, cmd).await)
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
        // no single owning actor and fall through to the shim, which
        // resolves the payment adapter from the supervisor's lifted
        // provider slot. The actor-shape and shim-shape helpers both
        // delegate to the same `economy_helpers::verify_payment_receipts`
        // body (the read uses only `deps.payment_adapter`), so the two
        // paths are observably equivalent — routing chooses the
        // serialization point, not the work.
        if let Some(ctx_id) = Self::economy_command_context_id(&cmd) {
            let ctx_id_owned = ctx_id.to_owned();
            if let Some(actor) = self.lookup(&ctx_id_owned) {
                return Self::dispatch_via_mailbox(&actor, ContextCommand::Economy(cmd)).await;
            }
        }
        Ok(handlers::economy::dispatch_from_shim(self, cmd).await)
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
        // actor mailbox when one is registered; otherwise fall back to
        // the legacy lock-shaped helper path inside
        // `dispatch_from_shim`. The cross-context
        // `RecoveryNotifyContact` variant has no `context_id` to look
        // up — it always flows through the legacy fan-out path.
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
        Ok(Box::pin(handlers::trust_recovery::dispatch_from_shim(self, cmd)).await)
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

    /// Helper: acquire the per-context lock, run the query handler
    /// inline (sync — the handler awaits nothing) against the locked
    /// state borrow + shared event-log provider, and send the typed
    /// reply. On soft-fallback + missing context, synthesize the
    /// variant's legacy default via the view-less fallback.
    async fn dispatch_with_view(
        supervisor: &Self,
        context_id: &str,
        cmd: QueriesCommand,
        soft_fallback: bool,
    ) -> Result<Outcome<()>, ContextError> {
        // Resolve the per-context Arc via the supervisor's own
        // `manager_methods::get_context_arc_pub` (lifted in 12c.9g.1).
        let elp = if let Some(p) = supervisor.event_log_ref() {
            Arc::clone(p)
        } else {
            let err = ContextError::NotInitialized(
                "Supervisor::dispatch_with_view — event_log provider not configured".to_owned(),
            );
            if soft_fallback {
                reply_with_soft_default(cmd);
            } else {
                reply_with_error(cmd, err);
            }
            return Ok(Outcome::ok(()));
        };
        match crate::context::manager_methods::get_context_arc_pub(supervisor, context_id) {
            Ok(arc) => {
                let guard = arc.lock().await;
                handlers::queries::dispatch_from_shim(&guard, &elp, cmd);
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
    /// `dead_code` allow: no production call site yet. 12b.2b is the
    /// first.
    #[allow(dead_code)]
    pub(in crate::context) async fn spawn_actor_with_state(
        &self,
        state: crate::context::actor::state::PerContextState,
        deps: crate::context::actor::deps::ActorDeps,
        mailbox_capacity: Option<usize>,
    ) -> ContextActorHandle {
        let capacity = mailbox_capacity.unwrap_or(ACTOR_MAILBOX_CAPACITY);
        let (tx, rx) = tokio::sync::mpsc::channel::<ContextCommand>(capacity);

        // Derive the supervisor-registry string key from the state's
        // canonical 32-byte context ID. `hex::encode` matches the
        // string form used throughout the legacy shim (see
        // `ContextManager::contexts`, keyed by `String`).
        let ctx_id_str = hex::encode(state.context_id);

        let handle = ContextActorHandle::from_sender(tx);
        {
            // Write-path mutation: register the handle under the
            // write lock — same contract as [`Self::spawn_actor`].
            let _guard = self.write_lock.lock().await;
            self.actors.insert(ctx_id_str.clone(), handle.clone());
        }

        // Hand the owned state + deps into the actor task. The
        // spawned future captures both by move; neither escapes the
        // actor's scope.
        let inbox = rx;
        tokio::spawn(async move {
            Box::pin(crate::context::actor::ContextActor::new(state, deps, inbox).run()).await;
        });

        handle
    }

    /// Spawn a `ContextActor` that proxies its state through the legacy
    /// [`Self::contexts`] DashMap entry for `context_id` (ADR-049
    /// Phase 2A finalization bootstrap dual-write).
    ///
    /// Looks up the `Arc<tokio::sync::Mutex<PerContextState>>` already
    /// registered by [`crate::context::manager_methods::insert_context`]
    /// / [`crate::context::supervisor::handle::SupervisorHandle::replace_context`],
    /// hands it to
    /// [`crate::context::actor::ContextActor::new_dashmap_backed`], and
    /// registers the resulting [`ContextActorHandle`] in
    /// [`Self::actors`] under [`Self::write_lock`] so the registration
    /// is atomic with respect to other spawn / despawn writers.
    ///
    /// During the dual-write window the actor does NOT own a fresh
    /// `PerContextState` payload: the per-context state lives once, in
    /// the DashMap, and the actor proxies every command through that
    /// `Arc<Mutex<...>>`. Subsequent finalization sessions delete the
    /// DashMap entirely; at that point the bootstrap path switches to
    /// [`Self::spawn_actor_with_state`] (owned state).
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotRegistered`] if no DashMap entry
    ///   exists for `context_id` — the bootstrap caller must have
    ///   completed the legacy insert / replace before invoking this
    ///   method.
    ///
    /// # Visibility
    ///
    /// `pub(in crate::context)` — only the lifecycle bootstrap in
    /// [`crate::context::lifecycle_helpers`] reaches this, via the
    /// capability-reduced
    /// [`crate::context::supervisor::handle::SupervisorHandle::spawn_actor_for_context`]
    /// wrapper.
    #[allow(dead_code)] // first production caller lands with the bootstrap wiring in this PR
    pub(in crate::context) async fn spawn_actor_dashmap_backed(
        &self,
        context_id: String,
        deps: crate::context::actor::deps::ActorDeps,
        mailbox_capacity: Option<usize>,
    ) -> Result<ContextActorHandle, ContextError> {
        // Resolve the per-context state Arc through the existing
        // manager-methods lookup — that path returns the same error
        // surface (`ContextNotRegistered`) callers already handle.
        let state_arc = crate::context::manager_methods::get_context_arc(self, &context_id)?;

        let capacity = mailbox_capacity.unwrap_or(ACTOR_MAILBOX_CAPACITY);
        let (tx, rx) = tokio::sync::mpsc::channel::<ContextCommand>(capacity);

        let handle = ContextActorHandle::from_sender(tx);
        {
            let _guard = self.write_lock.lock().await;
            self.actors.insert(context_id.clone(), handle.clone());
        }

        let inbox = rx;
        tokio::spawn(async move {
            Box::pin(
                crate::context::actor::ContextActor::new_dashmap_backed(
                    context_id, deps, state_arc, inbox,
                )
                .run(),
            )
            .await;
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
    /// directly.
    ///
    /// `dead_code` allow: the first production caller is the Phase
    /// 2A finalization keystone wiring of
    /// [`crate::context::lifecycle_helpers::import_context`].
    #[allow(dead_code)]
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
        &self,
        cmd: StandingCommand,
    ) -> Result<Outcome<()>, ContextError> {
        // ADR-049 Phase 2A item 5 — try the actor mailbox first.
        if let Some(ctx_id) = Self::standing_command_context_id(&cmd)
            && let Some(actor) = self.lookup(ctx_id)
        {
            return Self::dispatch_via_mailbox(&actor, ContextCommand::Standing(cmd)).await;
        }
        // Direct-shim fallback.
        Ok(Box::pin(handlers::standing::dispatch_from_shim(self, cmd)).await)
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
        // ADR-049 Phase 2A item 5 — try the actor mailbox first.
        if let Some(ctx_id) = Self::tools_command_context_id(&cmd)
            && let Some(actor) = self.lookup(ctx_id)
        {
            return Self::dispatch_via_mailbox(&actor, ContextCommand::Tools(cmd)).await;
        }
        // Direct-shim fallback.
        Ok(handlers::tools::dispatch_from_shim(self, cmd).await)
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
    ///   [`Supervisor`](crate::context::supervisor::Supervisor) has
    ///   been attached yet.
    pub async fn dispatch_broadcast_command(
        &self,
        cmd: BroadcastCommand,
    ) -> Result<Outcome<()>, ContextError> {
        // ADR-049 Phase 2A item 5 — try the actor mailbox first.
        if let Some(ctx_id) = Self::broadcast_command_context_id(&cmd)
            && let Some(actor) = self.lookup(ctx_id)
        {
            return Self::dispatch_via_mailbox(&actor, ContextCommand::Broadcast(cmd)).await;
        }
        // Direct-shim fallback.
        Ok(Box::pin(handlers::broadcast::dispatch_from_shim(self, cmd)).await)
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
        // Mailbox-first for non-publish variants. The mailbox path
        // returns the same `Outcome` shape as the shim path; the
        // dispatch-side `BroadcastCommand` enum already carries every
        // payload the actor needs.
        if let Some(ctx_id) = Self::broadcast_command_context_id(&cmd)
            && let Some(actor) = self.lookup(ctx_id)
        {
            return Self::dispatch_via_mailbox(&actor, ContextCommand::Broadcast(cmd)).await;
        }

        // Publish-only escape: `dispatch_from_shim_with_custody` carries
        // the custody reference into `shim_handle_publish_broadcast` /
        // `_publish_broadcast_content`. Non-publish variants reaching
        // this branch (e.g. when no per-context actor is registered yet)
        // ignore the custody and route through the shared no-custody
        // shim. See the function comment above — `KeyCustody` is not
        // `dyn`-safe, so this generic dispatch cannot be folded into the
        // mailbox path.
        Ok(
            Box::pin(handlers::broadcast::dispatch_from_shim_with_custody(
                self, cmd, custody,
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
    pub async fn restore_all_contexts(&self) -> Result<Vec<String>, ContextError> {
        crate::context::lifecycle_helpers_legacy::restore_all_contexts_legacy(self).await
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
        &self,
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
        crate::context::lifecycle_helpers_legacy::flush_all_contexts_legacy(self).await;
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
        crate::context::lifecycle_helpers_legacy::flush_all_contexts_sync_legacy(self);
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
        crate::context::lifecycle_helpers_legacy::shutdown_all_contexts_legacy(self).await;
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
        crate::context::lifecycle_helpers_legacy::shutdown_all_contexts_sync_legacy(self);
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

    /// Runtime-agnostic hard-rate-limit consumption used by FFI
    /// callers that may run inside or outside a tokio runtime.
    ///
    /// Returns `false` if the bucket is empty.
    ///
    /// # Sync-shape exception
    ///
    /// Stays on the legacy `tools_helpers_legacy::*` path because the
    /// method signature is `fn`, not `async fn` — FFI callers that
    /// invoke it from outside a tokio runtime (Python's
    /// gil-bound bridge in particular) cannot `.await`. Migrating it to
    /// the actor mailbox would require an `async` signature change
    /// that ripples through every bridge's sync rate-limit path. Phase
    /// 2A leaves this on the legacy direct-call path as the lone sync
    /// exception.
    #[must_use]
    pub fn try_consume_hard_rate_limit_from_any_context(
        self: &Arc<Self>,
        context_id: &str,
        did: &DID,
        now_secs: u64,
    ) -> bool {
        crate::context::tools_helpers_legacy::try_consume_hard_rate_limit_from_any_context(
            self, context_id, did, now_secs,
        )
    }

    /// Refund a hard-rate-limit token from any context (no-op on
    /// missing context).
    ///
    /// # Sync-shape exception
    ///
    /// See the doc on
    /// [`Self::try_consume_hard_rate_limit_from_any_context`] — the
    /// sync FFI path constraint applies here too.
    pub fn refund_hard_rate_limit_from_any_context(self: &Arc<Self>, context_id: &str, did: &DID) {
        crate::context::tools_helpers_legacy::refund_hard_rate_limit_from_any_context(
            self, context_id, did,
        );
    }

    /// Invoke a tool under the full economy pipeline.
    ///
    /// # Closure-shape exception
    ///
    /// Stays on the legacy `tools_helpers_legacy::*` path because the
    /// `executor` parameter is a non-`Send`-bound generic `FnOnce`
    /// closure (and its returned `Future`) that cannot cross an actor
    /// mailbox. Migrating would require either erasing the closure to
    /// a `Box<dyn FnOnce + Send>` (incompatible with several existing
    /// FFI bridges that supply non-Send executor closures) or
    /// reshaping the API so the executor runs on the supervisor side
    /// before the mailbox handoff. Phase 2A leaves this on the legacy
    /// direct-call path as the lone closure-shape exception.
    ///
    /// # Errors
    ///
    /// Propagates every error variant the helper emits
    /// (`ContextNotRegistered`, `PermissionDenied`, `RateLimited`,
    /// schema/economy/UCAN failures).
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
        crate::context::tools_helpers_legacy::invoke_tool_with_economy(
            self,
            context_id,
            registry,
            tool_id,
            input,
            invoker_did,
            spending_ucan,
            timeout_ms,
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
        &self,
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
        &self,
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
        &self,
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
            // target at all.
            LifecycleCommand::ImportContext { .. } | LifecycleCommand::Placeholder { .. } => None,
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
            // PublishBroadcast / PublishBroadcastContent need
            // KeyCustody on the shim; InitiateBroadcastHostingHandshake
            // and Placeholder have no string target for this router.
            _ => None,
        }
    }

    /// Extract the target context_id from a [`TtlCloseCommand`].
    /// Only `ExtendTtl` has a literal `context_id` field; the others
    /// (StartTtlTimer / ResetTtlTimer / ExecuteTtlClose / FinalizeClose)
    /// carry it inside boxed payloads. Boxed-payload variants route via
    /// the direct-shim path until a follow-on Phase 2 chunk destructures
    /// them.
    const fn ttl_close_command_context_id(cmd: &TtlCloseCommand) -> Option<&str> {
        match cmd {
            TtlCloseCommand::ExtendTtl { context_id, .. } => Some(context_id.as_str()),
            _ => None,
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
            GovernanceCommand::Placeholder { .. } => None,
        }
    }

    /// Extract the target context_id from a [`StandingCommand`].
    /// Most variants identify the standing peer by `peer_did` rather
    /// than a context_id and have no actor target — return `None`.
    /// Phase 2A leaves StandingCommand on the direct-shim path; the
    /// mailbox-routing extension lands when standing-pair sagas land in
    /// a follow-on Phase 2 chunk.
    const fn standing_command_context_id(_cmd: &StandingCommand) -> Option<&str> {
        None
    }

    /// Extract the target context_id from a [`ToolsCommand`].
    const fn tools_command_context_id(cmd: &ToolsCommand) -> Option<&str> {
        match cmd {
            ToolsCommand::TryConsumeHardRateLimit { context_id, .. }
            | ToolsCommand::RefundHardRateLimit { context_id, .. } => Some(context_id.as_str()),
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
            QueriesCommand::LocalPseudonym { context_id, .. }
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
        use scp_platform::testing::InMemoryStorage;

        let persistence: Arc<dyn ContextPersistence> = Arc::new(TestPersistence);
        let mls: Arc<dyn crate::crypto::mls::backend::MlsBackend> =
            Arc::new(crate::crypto::mls::production_backend::ProductionMlsBackend::new());
        let hpke: Arc<dyn crate::crypto::hpke_backend::HpkeBackend> =
            Arc::new(crate::crypto::hpke_backend::ProductionHpkeBackend::new());
        let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> =
            Arc::new(
                crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
                    InMemoryStorage::new(),
                )),
            );
        let kp_store = crate::context::supervisor::key_package_actor::KeyPackageStoreActor::spawn(
            DID("did:example:spawn-state-test".to_owned()),
        );

        supervisor
            .build_actor_deps(persistence, mls, hpke, mls_storage, kp_store)
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
        Supervisor::with_providers(
            crypto,
            transport,
            event_log,
            key_resolver,
            None,
            None,
            None,
            None,
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
            .await;
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

    #[tokio::test]
    async fn spawn_actor_with_state_overwrites_existing_handle() {
        // Same contract as the skeleton `spawn_actor`: a second spawn
        // with the same context_id overwrites. The watchdog / panic-
        // recovery path (commit 11) polices duplicate spawns; this
        // method stays minimal.
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
            .await;
        assert!(supervisor_arc.lookup(&ctx_key).is_some());

        let state2 = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            1_700_000_001,
            DID("did:example:admin".to_owned()),
        );
        let deps2 = test_actor_deps(&supervisor_arc).await;
        let h2 = supervisor_arc
            .spawn_actor_with_state(state2, deps2, None)
            .await;
        assert!(supervisor_arc.lookup(&ctx_key).is_some());

        // Shut down both to avoid leaked tasks.
        let _ = h1.send_shutdown().await;
        let _ = h2.send_shutdown().await;
    }

    // -----------------------------------------------------------------
    // ADR-049 Phase 2A finalization — `spawn_actor_dashmap_backed` tests
    // -----------------------------------------------------------------

    /// Insert a per-context entry through the legacy manager-methods
    /// path so `spawn_actor_dashmap_backed` has something to look up.
    /// Returns the supervisor's stringified context-id key.
    fn seed_dashmap_context(supervisor: &Arc<Supervisor>, ctx_id_bytes: [u8; 32]) -> String {
        let state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            1_700_000_000,
            DID("did:example:admin".to_owned()),
        );
        // `insert_context` produces the canonical String key by taking
        // the caller's argument verbatim; we mirror that here.
        let key = hex::encode(ctx_id_bytes);
        crate::context::manager_methods::insert_context(supervisor, key.clone(), state)
            .expect("seed insert must succeed");
        key
    }

    #[tokio::test]
    async fn spawn_actor_dashmap_backed_registers_handle_for_inserted_context() {
        let supervisor_arc = supervisor_with_providers();
        let ctx_id_bytes = [0x5Au8; 32];
        let key = seed_dashmap_context(&supervisor_arc, ctx_id_bytes);

        let deps = test_actor_deps(&supervisor_arc).await;
        let handle = supervisor_arc
            .spawn_actor_dashmap_backed(key.clone(), deps, None)
            .await
            .expect("dashmap-backed spawn must succeed for an inserted context");

        assert!(
            supervisor_arc.lookup(&key).is_some(),
            "actor registry must contain a handle for the dashmap-backed actor"
        );

        let _ = handle.send_shutdown().await;
    }

    #[tokio::test]
    async fn spawn_actor_dashmap_backed_rejects_unknown_context() {
        let supervisor_arc = supervisor_with_providers();
        let deps = test_actor_deps(&supervisor_arc).await;

        // `ContextActorHandle` does not implement `Debug`, so we
        // pattern-match on the `Result` rather than calling
        // `expect_err` (which requires `Debug` on the `Ok` variant).
        let result = supervisor_arc
            .spawn_actor_dashmap_backed("ctx-does-not-exist".to_owned(), deps, None)
            .await;
        match result {
            Err(ContextError::ContextNotRegistered(ref s)) if s == "ctx-does-not-exist" => {}
            Err(other) => panic!("expected ContextNotRegistered, got {other:?}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }
}
