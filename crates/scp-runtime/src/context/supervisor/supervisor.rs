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
use crate::context::actor::sequence::SendSequenceTracker;
use crate::context::actor::state::WrappingKeyPair;
use crate::context::builder::{ContextEventLogProvider, ContextTransportProvider};
use crate::context::manager::{ContextPersistence, PerContextState};
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
/// the supervisor (ADR-049 commit 12c.9b), and spawned background
/// tasks all hold equivalent clones of the same `DashMap`. The
/// per-entry `Arc<Mutex<PerContextState>>` is the contract the manager
/// exposes via [`ContextManager::contexts_arc`]; the alias is
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
    /// configured"; populated by [`Self::with_providers`] or the
    /// post-construction setter [`Self::set_payment_adapter`].
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
    // These were previously mirrored from [`ContextManager`]. The
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

    /// Construct a supervisor with the providers that previously lived on
    /// [`crate::context::manager::ContextManager`] (ADR-049 commit 12).
    ///
    /// The supervisor is now the authoritative owner of every provider —
    /// there is no `ContextManager` to attach. FFI bridges call this
    /// factory once at construction time; the returned `Arc<Supervisor>`
    /// is the only handle they hold.
    ///
    /// Saga journal + supervisor-level persistence wire to no-op stubs
    /// the [`Self::for_query_shim`] path uses — saga orchestration is
    /// not yet active in the FFI bridges (it lands with the watchdog
    /// migration in commit 12c.10), and the supervisor's own
    /// persistence slot is wired to a no-op
    /// [`NoopContextPersistence`] when `persistence` is `None`.
    ///
    /// # Arguments
    ///
    /// * `crypto` — production
    ///   [`MlsCryptoProvider`](crate::crypto::mls::provider::MlsCryptoProvider).
    /// * `transport` — production transport (typically
    ///   [`scp_core::context::NotConfiguredTransportProvider`],
    ///   [`scp_core::context::LocalTransportProvider`], or a real
    ///   [`scp_transport::RelayTransportProvider`]).
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
        let supervisor_persistence: Arc<dyn ContextPersistence>;
        let helper_persistence_arc: Option<Arc<dyn ContextPersistence>>;
        match persistence {
            Some(boxed) => {
                let arc: Arc<dyn ContextPersistence> = Arc::from(boxed);
                supervisor_persistence = Arc::clone(&arc);
                helper_persistence_arc = Some(arc);
            }
            None => {
                supervisor_persistence = Arc::new(NoopContextPersistence);
                helper_persistence_arc = None;
            }
        }
        let saga_journal: Arc<dyn SagaJournal> = Arc::new(NoopSagaJournal);
        let supervisor = Arc::new(Self::new(
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

    /// Install a payment adapter post-construction. First call wins;
    /// subsequent calls return [`ContextError::InvalidState`].
    ///
    /// Used by FFI bridges that compose the payment adapter after
    /// [`Self::with_providers`] runs (typically because the adapter
    /// depends on a DID resolver wired at a later stage).
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::InvalidState`] if a payment adapter has
    /// already been configured.
    pub fn set_payment_adapter(
        &self,
        adapter: Arc<dyn PaymentAdapterDyn>,
    ) -> Result<(), ContextError> {
        self.payment_adapter.set(adapter).map_err(|_| {
            ContextError::InvalidState(
                "Supervisor::set_payment_adapter — payment adapter already configured".to_owned(),
            )
        })
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
    pub(crate) fn contexts_ref(&self) -> &Arc<ContextsMap> {
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
    pub(crate) fn local_dids_ref(&self) -> &ArcSwap<HashSet<DID>> {
        &self.local_dids
    }

    /// Cheap reference to the supervisor's standing-context tracking
    /// map (peer DID string → peer [`DID`]).
    ///
    /// `ArcSwap<HashMap<...>>` per the master plan §Supervisor — same
    /// read/write discipline as [`Self::local_dids_ref`].
    #[must_use]
    pub(crate) fn standing_contexts_ref(&self) -> &ArcSwap<HashMap<String, DID>> {
        &self.standing_contexts
    }

    /// Cheap reference to the supervisor's monotonic generation
    /// counter. Always populated (initialized to 1 in [`Self::new`]).
    #[must_use]
    pub(crate) fn next_generation_ref(&self) -> &std::sync::atomic::AtomicU64 {
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
    #[must_use]
    #[allow(dead_code)] // first caller lands in 12c.10 with the dissolution finale
    pub(crate) fn wrapping_public_key_for(&self, did: &DID) -> Option<Arc<Vec<u8>>> {
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
    #[must_use]
    #[allow(dead_code)] // first caller lands in 12c.10 with the dissolution finale
    pub(crate) fn wrapping_secret_key_for(
        &self,
        did: &DID,
    ) -> Option<Arc<zeroize::Zeroizing<Vec<u8>>>> {
        self.wrapping_keys.get(did).map(|entry| {
            let pair = entry.value().load_full();
            Arc::new(zeroize::Zeroizing::new(pair.secret.to_vec()))
        })
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
    /// [`SupervisorHandle::local_dids`] / [`SupervisorHandle::standing_peer`]
    /// would read empty state.
    pub async fn build_actor_deps(
        self: &Arc<Self>,
        persistence: Arc<dyn ContextPersistence>,
        mls: Arc<dyn crate::crypto::mls::backend::MlsBackend>,
        hpke: Arc<dyn crate::crypto::hpke_backend::HpkeBackend>,
        mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter>,
        key_package_store: crate::context::supervisor::key_package_actor::KeyPackageStoreHandle,
    ) -> Result<crate::context::actor::deps::ActorDeps, ContextError> {
        const ATTACHED: &str =
            "Supervisor::build_actor_deps — provider slot empty (call with_providers first)";
        let transport = Arc::clone(
            self.transport_ref()
                .ok_or_else(|| ContextError::NotInitialized(ATTACHED.to_owned()))?,
        );
        let event_log = Arc::clone(
            self.event_log_ref()
                .ok_or_else(|| ContextError::NotInitialized(ATTACHED.to_owned()))?,
        );
        let clock = Arc::clone(
            self.clock_ref()
                .ok_or_else(|| ContextError::NotInitialized(ATTACHED.to_owned()))?,
        );
        let key_resolver = self
            .key_resolver_ref()
            .ok_or_else(|| ContextError::NotInitialized(ATTACHED.to_owned()))?
            .clone();

        let handle = crate::context::supervisor::handle::SupervisorHandle::wrap(Arc::clone(self));

        Ok(crate::context::actor::deps::ActorDeps {
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
    /// - [`ContextError::NotInitialized`] if no [`ContextManager`] has
    ///   been attached yet — the caller must call
    ///   [`Self::attach_context_manager`] first.
    pub async fn dispatch_query(&self, cmd: QueriesCommand) -> Result<Outcome<()>, ContextError> {
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
    /// 3. Invokes
    ///    [`handlers::messaging::dispatch_from_shim`](crate::context::actor::handlers::messaging::dispatch_from_shim)
    ///    with the attached manager Arc and a `&mut` borrow of the
    ///    taken tracker. The handler exercises
    ///    [`SequenceReservation`](crate::context::actor::SequenceReservation)
    ///    on that tracker, wraps the delegated
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
    /// The handler takes `&mut SendSequenceTracker`. If the dispatcher
    /// held a `tokio::sync::OwnedMutexGuard<PerContextState>` the
    /// borrow would live across the delegated `cm.send_message(...).await`
    /// and deadlock the re-entrant per-context mutex acquisition inside
    /// `ContextManager::send_message`. The take-and-swap workaround
    /// makes the tracker reservation lock-free: the dispatcher owns
    /// the tracker for the handler's await points, and the per-context
    /// lock is held for zero duration during the delegated call. This
    /// preserves deadlock safety during the shim period. Commit 12
    /// replaces this with a direct `&mut PerContextState` on the
    /// actor's owned state (no lock involved, the actor serializes by
    /// construction).
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
        // Resolve the per-context Arc via the supervisor's lifted
        // `manager_methods::get_context_arc_pub`. `ContextNotRegistered`
        // surfaces directly to the caller — messaging commands have no
        // soft-default: a missing context can't encrypt or decrypt a
        // message.
        let arc = crate::context::manager_methods::get_context_arc_pub(self, ctx_id)?;

        // Phase A: take the tracker out under a brief lock. See the
        // doc comment for the deadlock-avoidance rationale.
        let mut taken_tracker = {
            let mut guard = arc.lock().await;
            std::mem::take(guard.send_tracker_mut())
        };

        // Phase B: invoke the handler with the attached manager + a
        // mutable borrow of the taken tracker. No per-context lock is
        // held during this await so the delegated
        // `cm.send_message(...)` call inside the handler acquires the
        // same mutex without contention.
        // ADR-049 commit 12c.9c — messaging handler takes `&Supervisor`
        // so it can read lifted provider slots directly; `cm` is
        // resolved from `self.attached_context_manager()` inside the
        // handler's `handle_send_message` helper.
        let outcome = handlers::messaging::dispatch_from_shim(self, &mut taken_tracker, cmd).await;

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
    /// Step 1 invokes
    /// [`handlers::lifecycle::dispatch_from_shim`](crate::context::actor::handlers::lifecycle::dispatch_from_shim)
    /// with a reference to the attached manager. Lifecycle handlers
    /// never read or mutate `send_tracker` (only the messaging path
    /// touches it), so no per-context take-and-swap or scratch tracker
    /// is required.
    ///
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
        // ADR-049 commit 12 — lifecycle handler takes `&Supervisor`.
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
    /// [`ContextManager`](crate::context::manager::ContextManager) calls
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
    ///   [`ContextManager`](crate::context::manager::ContextManager) has
    ///   been attached yet.
    pub async fn dispatch_ttl_close_command(
        &self,
        cmd: TtlCloseCommand,
    ) -> Result<Outcome<()>, ContextError> {
        // ADR-049 commit 12 — ttl_close handler takes `&Supervisor`.
        Ok(handlers::ttl_close::dispatch_from_shim(self, cmd).await)
    }

    /// Dispatch a [`GovernanceCommand`] through the migration shim
    /// (ADR-049 commit 10 / plan row 10).
    ///
    /// Contract (byte-identical to the legacy
    /// [`ContextManager`](crate::context::manager::ContextManager)
    /// governance methods it replaces):
    ///
    /// Step 1 invokes
    /// [`handlers::governance::dispatch_from_shim`](crate::context::actor::handlers::governance::dispatch_from_shim)
    /// with a reference to the attached manager. Governance handlers
    /// never read or mutate `send_tracker` (only the messaging path
    /// touches it), so no per-context take-and-swap or scratch tracker
    /// is required — same shape as the lifecycle shim.
    ///
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
        // ADR-049 commit 12 — governance handler takes `&Supervisor`.
        // `Box::pin` — see the matching comment on
        // `handlers::governance::dispatch` for the 16-KB stack-future
        // rationale.
        Ok(Box::pin(handlers::governance::dispatch_from_shim(self, cmd)).await)
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
        // ADR-049 commit 12 — economy handler takes `&Supervisor`.
        Ok(handlers::economy::dispatch_from_shim(self, cmd).await)
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
        // ADR-049 commit 12 — trust-recovery handler takes `&Supervisor`.
        // `Box::pin` — CreateGovernanceCheckpoint's payload carries
        // multiple 32-byte hashes + a variable-length Ed25519 signature
        // vector; the per-variant locals cross clippy's 16-KB stack-
        // future budget.
        Ok(Box::pin(handlers::trust_recovery::dispatch_from_shim(self, cmd)).await)
    }

    /// Helper: acquire the per-context lock, run the query handler
    /// inline (sync — the handler awaits nothing) against the locked
    /// state borrow + shared event-log provider, and send the typed
    /// reply. On soft-fallback + missing context, synthesize the
    /// variant's legacy default via the view-less fallback.
    async fn dispatch_with_view(
        supervisor: &Supervisor,
        context_id: &str,
        cmd: QueriesCommand,
        soft_fallback: bool,
    ) -> Result<Outcome<()>, ContextError> {
        // Resolve the per-context Arc via the supervisor's own
        // `manager_methods::get_context_arc_pub` (lifted in 12c.9g.1).
        let elp = match supervisor.event_log_ref() {
            Some(p) => Arc::clone(p),
            None => {
                let err = ContextError::NotInitialized(
                    "Supervisor::dispatch_with_view — event_log provider not configured".to_owned(),
                );
                if soft_fallback {
                    reply_with_soft_default(cmd);
                } else {
                    reply_with_error(cmd, err);
                }
                return Ok(Outcome::ok(()));
            }
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
            crate::context::actor::ContextActor::new_skeleton(ctx_id, inbox)
                .run()
                .await;
        });

        handle
    }

    /// Spawn a new `ContextActor` task that owns drained
    /// [`PerContextState`](crate::context::actor::PerContextState) +
    /// [`ActorDeps`](crate::context::actor::ActorDeps) directly
    /// (ADR-049 commit 12b.2a).
    ///
    /// This is the post-refactor spawn path: the supervisor's caller
    /// drains state from the legacy `ContextManager` and
    /// `MlsCryptoProvider` via
    /// [`crate::context::manager::ContextManager::take_context_state`]
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
            crate::context::actor::ContextActor::new(state, deps, inbox)
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
        // ADR-049 commit 12 — standing handler takes `&Supervisor`.
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
        // ADR-049 commit 12 — tools handler takes `&Supervisor`.
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
    ///   [`ContextManager`](crate::context::manager::ContextManager) has
    ///   been attached yet.
    pub async fn dispatch_broadcast_command(
        &self,
        cmd: BroadcastCommand,
    ) -> Result<Outcome<()>, ContextError> {
        // ADR-049 commit 12 — broadcast handlers take `&Supervisor`.
        Ok(Box::pin(handlers::broadcast::dispatch_from_shim(self, cmd)).await)
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
        // ADR-049 commit 12 — see `dispatch_broadcast_command`.
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

    // ---------------------------------------------------------------
    // Supervisor-scope direct methods (no per-context command dispatch)
    //
    // The methods in this block route to the attached
    // [`ContextManager`](crate::context::manager::ContextManager)
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
    pub async fn register_local_did(&self, did: DID) -> Result<(), ContextError> {
        crate::context::queries_helpers::register_local_did(self, did).await;
        Ok(())
    }

    /// Returns `true` iff `did` is registered as locally controlled.
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
        crate::context::lifecycle_helpers::restore_all_contexts(self).await
    }

    /// Best-effort flush of every context's snapshot to the configured
    /// persistence provider.
    ///
    /// No-op if no persistence provider is configured.
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
    /// standing-context tracking, and aborts background tasks (TTL
    /// timers, governance timeouts). Does NOT send leave messages or
    /// notify remote peers — used by
    /// [`scp_ffi_common::BridgeInstance::shutdown`] for process exit /
    /// test teardown.
    pub fn shutdown_all_contexts(&self) -> Result<(), ContextError> {
        crate::context::lifecycle_helpers::shutdown_all_contexts(self);
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
    // `attached_context_manager()`). The thin layer keeps the FFI rewire
    // mechanical: bridge call sites change exactly one identifier
    // (`mgr.X` → `supervisor.X`). When `manager/` is deleted in commit
    // 12c.9g.4, the manager-fallback methods below become direct helper
    // calls.
    // -------------------------------------------------------------------

    /// Passthrough to
    /// [`crate::context::queries_helpers::member_count`] — returns the
    /// current member count for `context_id`, or `None` if the context
    /// is not registered.
    #[must_use]
    pub async fn member_count(&self, context_id: &str) -> Option<usize> {
        crate::context::queries_helpers::member_count(self, context_id).await
    }

    /// Passthrough to [`crate::context::queries_helpers::is_member`] —
    /// returns `true` iff `did` is a member of `context_id`.
    #[must_use]
    pub async fn is_member(&self, context_id: &str, did: &str) -> bool {
        crate::context::queries_helpers::is_member(self, context_id, did).await
    }

    /// Passthrough to
    /// [`crate::context::queries_helpers::member_dids`] — returns every
    /// member DID currently associated with `context_id` (empty if the
    /// context is unknown).
    #[must_use]
    pub async fn member_dids(&self, context_id: &str) -> Vec<String> {
        crate::context::queries_helpers::member_dids(self, context_id).await
    }

    /// Passthrough to
    /// [`crate::context::queries_helpers::member_role`] — returns the
    /// role assignment for `did` in `context_id`, or `None` if the
    /// member has no role.
    #[must_use]
    pub async fn member_role(
        &self,
        context_id: &str,
        did: &str,
    ) -> Option<scp_protocol::context::roles::RoleAssignment> {
        crate::context::queries_helpers::member_role(self, context_id, did).await
    }

    /// Passthrough to
    /// [`crate::context::queries_helpers::context_params`] — returns a
    /// clone of the context's creation parameters, or `None` if the
    /// context is unknown.
    #[must_use]
    pub async fn context_params(
        &self,
        context_id: &str,
    ) -> Option<scp_protocol::context::ContextParams> {
        crate::context::queries_helpers::context_params(self, context_id).await
    }

    /// Passthrough to
    /// [`crate::context::queries_helpers::get_role_state`] — returns a
    /// clone of the context's role state, or `None` if the context is
    /// unknown.
    #[must_use]
    pub async fn get_role_state(
        &self,
        context_id: &str,
    ) -> Option<scp_protocol::context::roles::ContextRoleState> {
        crate::context::queries_helpers::get_role_state(self, context_id).await
    }

    /// Passthrough to
    /// [`crate::context::queries_helpers::drain_events`] — drains and
    /// returns every event currently buffered for `context_id`.
    #[must_use]
    pub async fn drain_events(&self, context_id: &str) -> Vec<ContextEvent> {
        crate::context::queries_helpers::drain_events(self, context_id).await
    }

    /// Passthrough to
    /// [`crate::context::queries_helpers::event_log_entries`] —
    /// returns the Merkle-log entries for the routing-id-hashed
    /// `context_id_bytes`.
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
        crate::context::queries_helpers::event_log_entries(self, context_id_bytes)
    }

    /// Passthrough to
    /// [`crate::context::queries_helpers::get_broadcast_key_for_local_author`]
    /// — returns the broadcast sender key + epoch for `author_did` in
    /// `context_id`.
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
        crate::context::queries_helpers::get_broadcast_key_for_local_author(
            self, context_id, author_did,
        )
        .await
    }

    /// Runtime-agnostic hard-rate-limit consumption used by FFI
    /// callers that may run inside or outside a tokio runtime.
    ///
    /// Returns `false` if the bucket is empty.
    #[must_use]
    pub fn try_consume_hard_rate_limit_from_any_context(
        self: &Arc<Self>,
        context_id: &str,
        did: &DID,
        now_secs: u64,
    ) -> bool {
        crate::context::tools_helpers::try_consume_hard_rate_limit_from_any_context(
            self, context_id, did, now_secs,
        )
    }

    /// Refund a hard-rate-limit token from any context (no-op on
    /// missing context).
    pub fn refund_hard_rate_limit_from_any_context(self: &Arc<Self>, context_id: &str, did: &DID) {
        crate::context::tools_helpers::refund_hard_rate_limit_from_any_context(
            self, context_id, did,
        );
    }

    /// Invoke a tool under the full economy pipeline.
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
    ) -> Result<crate::context::manager::tools::ManagedToolInvocationOutput, ContextError>
    where
        F: FnOnce(serde_json::Value) -> Fut,
        Fut: std::future::Future<Output = Result<serde_json::Value, String>>,
    {
        crate::context::tools_helpers::invoke_tool_with_economy(
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

    /// Passthrough to
    /// [`crate::context::lifecycle_helpers::create_context`] — used by
    /// FFI integration tests that need to bypass the full bridge
    /// lifecycle entry points.
    ///
    /// # Errors
    ///
    /// Returns [`scp_protocol::context::ContextCreationError`] if the
    /// supervisor's providers are not wired or context creation fails.
    pub async fn create_context(
        &self,
        context_id: String,
        params: scp_protocol::context::ContextParams,
        creator_did: DID,
        local_pseudonym: Option<[u8; 32]>,
    ) -> Result<crate::context::ContextHandle, scp_protocol::context::builder::ContextCreationError>
    {
        crate::context::lifecycle_helpers::create_context(
            self,
            context_id,
            params,
            creator_did,
            local_pseudonym,
        )
        .await
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
}
