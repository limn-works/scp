//! Context Manager -- central coordinator for context lifecycle.
//!
//! The [`ContextManager`] owns the provider implementations and exposes the
//! public API for context creation, membership, and messaging. It delegates
//! to [`super::builder::create_context`] for the two-phase commit flow.
//!
//! Providers are injected through the constructor, making the manager fully
//! testable with mock implementations. See ADR-008 in
//! `.docs/adrs/phase-2.md` for the full context lifecycle specification.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, OnceLock, Weak};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};

use super::ContextHandle;
use super::builder::{
    ContextEventLogProvider, ContextTransportProvider, create_context as builder_create_context,
};
use super::governance::timeout::{DeadlockDetectionState, GovernanceTimeoutTask};
use super::supervisor::Supervisor;
use super::ttl::{CloseResult, TtlExtension, TtlTimer};
use scp_identity::DID;
use scp_primitives::Clock;
use scp_protocol::context::broadcast::{
    BroadcastAdmission, BroadcastContext, BroadcastContextSnapshot, GovernanceBanResult,
};
// Re-exported for `manager/tests/{broadcast,queries,trust_recovery}.rs` test
// modules which reach `super::KeyRequestDecision`. After the broadcast hoist
// in commit 12c.4 the `manager/mod.rs` `use` for this type went away (the
// hoisted helpers import directly from `scp_protocol::context::broadcast`),
// so the test re-export is the only remaining consumer in this module.
use scp_protocol::context::builder::ContextCreationError;

use crate::crypto::mls::provider::MlsCryptoProvider;
use scp_protocol::context::governance::{
    AccessScope, CheckpointAttestationStatus, ContextCheckpoint, CosignedCheckpoint,
    GovernanceAction, GovernanceContext, GovernanceEngine, GovernanceEvent, GovernanceModelConfig,
    GovernanceProposal, KeyResolver, ProposalId, ProposalStatus, PruningPolicy, SingleAdminEngine,
    majority::MajorityVoteEngine,
    mls_integration::{CoordinationRecord, EpochCoordinator},
    multisig::ThresholdEngine,
    unanimity::UnanimityEngine,
};
use scp_protocol::context::membership::{ContextEvent, KeyPackage, MembershipState, ReceiveBuffer};
use scp_protocol::context::params::GovernanceModel;
use scp_protocol::context::params::{ContextMode, TemplateId, ToolRegistration};
use scp_protocol::context::roles::{
    self, Capability, CapabilityCeiling, ContextRoleState, RoleAssignment,
};
use scp_protocol::context::tools::interface::ToolInterface;
use scp_protocol::context::{ContextError, ContextParams, ContextState};
use scp_protocol::economy::budget::MemberBudgetTracker;
use scp_protocol::economy::types::EconomicPolicy;
use scp_protocol::trust::consequence::{
    ConsequenceRule, TriggeredConsequence, evaluate_consequence_rules,
};
use tracing::instrument;
use zeroize::Zeroizing;

mod broadcast;
pub(crate) mod economy;
pub(crate) mod governance;
pub(crate) mod lifecycle;
pub(crate) mod messaging;
mod queries;
pub(crate) mod standing;
pub(crate) mod tools;
mod trust_recovery;
pub(crate) mod ttl_close;


// ---------------------------------------------------------------------------
// Re-exports — types/constants/free helpers now physically live in
// `crate::context::state` and `crate::context::persistence`. The
// re-exports below preserve the legacy `manager::X` paths used by the
// submodule files in this directory while the submodules' `impl
// ContextManager {}` blocks are unwound. Once the submodules and
// `ContextManager` itself are deleted, this file goes away.
// ---------------------------------------------------------------------------

#[allow(unused_imports)]
pub use crate::context::persistence::ContextPersistence;
// Public re-exports for the FFI bridges and downstream tests.
#[allow(unused_imports)]
pub use crate::context::state::{
    COMMIT_RETRY_BACKOFFS, CommitFaultMarker, CommitOperation, ContentKeysRotatedResult,
    ContextSnapshot, GovernanceActionResult, GovernanceReconfiguredResult, MAX_COMMIT_AGE_SECS,
    MAX_COMMIT_RETRIES, MAX_PENDING_COMMITS, MigrationProposedResult, MigrationState,
    PendingCeilingModification, PendingCommit, PendingEconomicPolicyChange, ProposalOutcome,
    RestoreAccessResult, RevokeResult, SuspendMemberResult, VelocityTrackerSnapshot,
    commit_retry_backoff,
};
// Crate-internal re-exports for helpers + supervisor.
#[allow(unused_imports)]
pub(crate) use crate::context::state::{
    AccessControlState, CEILING_CHANGE_NOTIFICATION_PERIOD_SECS, ContextGeneration,
    ECONOMIC_POLICY_NOTIFICATION_PERIOD_SECS, EXECUTED_PROPOSALS_TTL_SECS, EpochState,
    GovernanceState, MAX_REGISTERED_TOOLS, MAX_THRESHOLD_SIGNERS, MAX_TOOL_INTERFACES,
    PSEUDONYM_ANNOUNCEMENT_TAG, PerContextState, PseudonymAnnouncement, TtlState,
    build_governance_engine, context_id_to_bytes, create_governance_engine,
    mint_governance_tokens, push_welcome_event, require_active, require_migrating_out,
    restore_governance_engine_from_snapshot, restore_grace_store_from_snapshot,
    strip_event_payload, validate_governance_consistency, validate_governance_model,
};


// ---------------------------------------------------------------------------
// ContextManagerBuilder
// ---------------------------------------------------------------------------

/// Step-by-step builder for [`ContextManager`].
///
/// Provides a more ergonomic API than the raw constructors. Required
/// providers can be set individually, or use [`.storage()`](Self::storage)
/// to auto-wire persistence and event log from a single `EncryptedStorage` impl.
///
/// # Required
///
/// * `crypto` — always required (no sensible default for MLS operations).
///
/// # Optional with defaults
///
/// * `transport` — defaults to [`LocalTransportProvider`](super::builder::LocalTransportProvider) (all ops succeed).
/// * `event_log` — defaults to [`MerkleEventLogProvider::new()`](super::providers::MerkleEventLogProvider::new) (in-memory).
/// * `persistence` — defaults to `None` (no crash recovery).
/// * `key_resolver` — defaults to a no-op resolver that returns `None`.
///
/// # `.storage()` convenience
///
/// Calling `.storage(my_storage)` auto-constructs:
/// 1. A `ProtocolRepository<S>` wrapping the storage.
/// 2. A `ProtocolRepositoryContextBridge<S>` for context persistence.
/// 3. A `ProtocolRepositoryEventLogBridge<S>` for event log persistence.
/// 4. A `MerkleEventLogProvider` backed by that persistence.
///
/// This replaces ~8 lines of manual wiring with a single call.
pub struct ContextManagerBuilder {
    crypto: Option<Arc<MlsCryptoProvider>>,
    transport: Option<Box<dyn ContextTransportProvider>>,
    event_log: Option<Box<dyn ContextEventLogProvider>>,
    persistence: Option<Box<dyn ContextPersistence>>,
    key_resolver: Option<KeyResolver>,
    clock: Option<Arc<dyn Clock>>,
    payment_adapter: Option<Arc<dyn crate::economy::adapter::PaymentAdapterDyn>>,
}

impl ContextManagerBuilder {
    /// Creates a new builder with all fields unset.
    #[must_use]
    fn new() -> Self {
        Self {
            crypto: None,
            transport: None,
            event_log: None,
            persistence: None,
            key_resolver: None,
            clock: None,
            payment_adapter: None,
        }
    }

    /// Sets the crypto provider (required).
    #[must_use]
    pub fn crypto(mut self, crypto: Arc<MlsCryptoProvider>) -> Self {
        self.crypto = Some(crypto);
        self
    }

    /// Sets the transport provider.
    ///
    /// If not called, defaults to [`LocalTransportProvider`](super::builder::LocalTransportProvider).
    #[must_use]
    pub fn transport(mut self, transport: Box<dyn ContextTransportProvider>) -> Self {
        self.transport = Some(transport);
        self
    }

    /// Sets the event log provider.
    ///
    /// If not called (and `.storage()` is not used), defaults to
    /// [`MerkleEventLogProvider::new()`](super::providers::MerkleEventLogProvider::new) (in-memory, no persistence).
    #[must_use]
    pub fn event_log(mut self, event_log: Box<dyn ContextEventLogProvider>) -> Self {
        self.event_log = Some(event_log);
        self
    }

    /// Sets the context persistence provider.
    ///
    /// If not called, no persistence is configured (in-memory only).
    #[must_use]
    pub fn persistence(mut self, persistence: Box<dyn ContextPersistence>) -> Self {
        self.persistence = Some(persistence);
        self
    }

    /// Sets the key resolver for governance vote verification.
    ///
    /// If not called, defaults to a no-op resolver that returns `None`
    /// for all DIDs (governance voting will not verify signatures).
    #[must_use]
    pub fn key_resolver(mut self, key_resolver: KeyResolver) -> Self {
        self.key_resolver = Some(key_resolver);
        self
    }

    /// Sets the clock for time-dependent operations.
    ///
    /// If not called, defaults to [`scp_primitives::SystemClock`].
    #[must_use]
    pub fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = Some(clock);
        self
    }

    /// Sets the payment adapter for the 9-step paid action flow (spec §19.2.2).
    ///
    /// If not called, paid action entry points skip the payment rail
    /// integration while still enforcing budget tracking.
    #[must_use]
    pub fn payment_adapter(
        mut self,
        adapter: Arc<dyn crate::economy::adapter::PaymentAdapterDyn>,
    ) -> Self {
        self.payment_adapter = Some(adapter);
        self
    }

    /// Auto-wires persistence and event log from a single `EncryptedStorage` impl.
    ///
    /// Constructs a [`ProtocolRepository`](crate::store::ProtocolRepository), then
    /// creates both the context persistence bridge and event log persistence
    /// bridge, plus a [`MerkleEventLogProvider`](super::providers::MerkleEventLogProvider)
    /// backed by that persistence. This replaces ~8 lines of manual wiring.
    ///
    /// Calling this overwrites any previously set `persistence` and `event_log`.
    #[must_use]
    pub fn storage<S: scp_platform::EncryptedStorage + 'static>(mut self, storage: S) -> Self {
        let store = std::sync::Arc::new(crate::store::ProtocolRepository::new(storage));
        let persistence = Box::new(crate::store::context::ProtocolRepositoryContextBridge::new(
            store.clone(),
        ));
        let event_log_persistence =
            crate::store::context::ProtocolRepositoryEventLogBridge::new(store);
        let event_log = Box::new(super::providers::MerkleEventLogProvider::with_persistence(
            std::sync::Arc::new(event_log_persistence),
        ));
        self.persistence = Some(persistence);
        self.event_log = Some(event_log);
        self
    }

    /// Builds the [`ContextManager`].
    ///
    /// # Errors
    ///
    /// Returns an error if the `crypto` provider was not set (the only
    /// required field).
    pub fn build(self) -> Result<ContextManager, ContextManagerBuildError> {
        let crypto = self.crypto.ok_or(ContextManagerBuildError::MissingCrypto)?;

        let transport: Box<dyn ContextTransportProvider> = self
            .transport
            .unwrap_or_else(|| Box::new(super::builder::LocalTransportProvider));

        let event_log: Box<dyn ContextEventLogProvider> = self
            .event_log
            .unwrap_or_else(|| Box::new(super::providers::MerkleEventLogProvider::new()));

        let key_resolver = self
            .key_resolver
            .unwrap_or_else(|| Arc::new(|_: &DID| None));

        let clock = self
            .clock
            .unwrap_or_else(|| Arc::new(scp_primitives::SystemClock));

        let mut manager = match self.persistence {
            Some(persistence) => ContextManager::with_persistence(
                crypto,
                transport,
                event_log,
                persistence,
                key_resolver,
            ),
            None => ContextManager::new(crypto, transport, event_log, key_resolver),
        };
        manager.clock = clock;
        manager.payment_adapter = self.payment_adapter;
        Ok(manager)
    }
}

/// Error returned when [`ContextManagerBuilder::build`] fails.
#[derive(Debug, thiserror::Error)]
pub enum ContextManagerBuildError {
    /// The `crypto` provider is required but was not set.
    #[error("crypto provider is required — call .crypto() before .build()")]
    MissingCrypto,
}

// ---------------------------------------------------------------------------
// ContextManager
// ---------------------------------------------------------------------------

/// Central coordinator for SCP context lifecycle operations.
///
/// `ContextManager` holds the injected providers for crypto, transport, and
/// event log operations and exposes the public API for context creation,
/// membership (join/leave), and messaging (send).
///
/// # Thread Safety
///
/// `ContextManager` is `Send + Sync` when all providers are `Send + Sync`
/// (which is enforced by the trait bounds). It is safe to share across
/// threads and async tasks. Per-context state is protected by a
/// `tokio::sync::Mutex` which does not poison on panic.
///
/// # Examples
///
/// ```ignore
/// let manager = ContextManager::new(crypto, transport, event_log, key_resolver);
/// let handle = manager.create_context("ctx-1".into(), params, "did:key:creator".into(), None).await?;
/// assert_eq!(handle.state().await, ContextState::Active);
/// ```
pub struct ContextManager {
    /// Provider for MLS group and sender key operations.
    ///
    /// Stored as `Arc` (not `Box`) so the provider can be shared with
    /// spawned TTL timer tasks that need crypto access for key destruction
    /// on context expiry (SCP-169).
    crypto: Arc<MlsCryptoProvider>,
    /// Provider for relay connectivity and publication.
    transport: Arc<dyn ContextTransportProvider>,
    /// Provider for event log initialisation and append.
    ///
    /// Stored as `Arc` (not `Box`) so the provider can be shared with
    /// spawned TTL timer tasks that need event log access for logging
    /// `ContextExpired` events on context expiry (SCP-169).
    event_log: Arc<dyn ContextEventLogProvider>,
    /// Optional provider for persisting full context and broadcast state
    /// across process restarts. When `Some`, the manager persists context
    /// state after every mutating operation (best-effort).
    persistence: Option<Arc<dyn ContextPersistence>>,
    /// DIDs controlled by the local node/SDK.
    ///
    /// Used for defense-in-depth validation in
    /// [`handle_broadcast_key_request`](Self::handle_broadcast_key_request):
    /// the method verifies the `author_did` is locally controlled before
    /// processing the request. While transport-layer auth (spec section
    /// 9.16.6) is the primary enforcement mechanism, this check prevents
    /// misuse if the method is called from an unexpected context.
    ///
    /// Populated via [`register_local_did`](Self::register_local_did).
    /// Uses `RwLock` because reads (validation checks) are frequent and
    /// writes (DID registration) are rare.
    local_dids: RwLock<HashSet<DID>>,
    /// Per-context state, keyed by `context_id` string.
    ///
    /// Each context has its own `tokio::sync::Mutex` so operations on
    /// different contexts never serialize against each other (`DashMap`
    /// shard locks are released immediately after cloning the `Arc`).
    ///
    /// Wrapped in `Arc` so spawned background tasks (TTL expiry, governance
    /// timeout) can clone the outer `Arc<DashMap>` and access contexts by ID
    /// without holding a reference to the entire `ContextManager`.
    contexts: Arc<DashMap<String, Arc<Mutex<PerContextState>>>>,
    /// Resolver that maps a DID to its Ed25519 verifying key for governance
    /// vote signature verification (spec §5.9, ADR-031). Passed through to
    /// governance engines at creation and restoration time.
    key_resolver: KeyResolver,
    /// Clock for time-dependent operations.
    ///
    /// Injected via constructors / builder to allow test clock injection.
    /// Defaults to [`scp_primitives::SystemClock`].
    clock: Arc<dyn Clock>,
    /// Standing bilateral contexts indexed by peer DID string (contact graph).
    ///
    /// Maps peer DID string to the peer's [`DID`]. The context ID is derived
    /// deterministically via [`standing::generate_standing_context_id`], and
    /// the context handle lives in [`Self::contexts`]. This map tracks which
    /// peers have standing contexts without duplicating handle storage.
    standing_contexts: Mutex<HashMap<String, DID>>,
    /// Optional payment adapter for the 9-step paid action flow (spec §19.2.2).
    ///
    /// When `Some`, `authorize_paid_action`→`complete_paid_action` runs the
    /// full escrow flow via this adapter. When `None`, paid action entry
    /// points skip payment (free context) while still enforcing budget
    /// tracking via `evaluate_cost` and `record_spend`.
    ///
    /// Set via [`set_payment_adapter`](Self::set_payment_adapter) or the builder.
    payment_adapter: Option<Arc<dyn crate::economy::adapter::PaymentAdapterDyn>>,
    /// Shared task set for TTL timers and governance timeout tasks.
    ///
    /// Background tasks spawned by [`spawn_ttl_timer`](Self::spawn_ttl_timer) and
    /// [`start_governance_timeout_task`](Self::start_governance_timeout_task) are
    /// added to this `JoinSet`. When the `ContextManager` is dropped, all tasks
    /// in the set are automatically cancelled, providing structured lifecycle
    /// management. Prerequisite for Phase B (`DashMap` per-context locking).
    ///
    /// Wrapped in `Arc<Mutex<_>>` because `JoinSet` requires `&mut self` for
    /// `spawn` and is not `Sync`.
    task_set: Arc<tokio::sync::Mutex<tokio::task::JoinSet<()>>>,
    /// Global monotonic counter for assigning generation IDs to contexts.
    ///
    /// Starts at 1 so that generation 0 (the `#[serde(default)]` value for
    /// legacy snapshots) is never actively assigned. Incremented with
    /// `Relaxed` ordering — uniqueness is guaranteed by the `fetch_add`
    /// atomicity, and no other memory accesses depend on the ordering.
    next_generation: std::sync::atomic::AtomicU64,
    /// Optional broadcast channel for notifying external consumers of context
    /// events (e.g., webhook dispatchers in scp-node). When `Some`, every event
    /// pushed to a per-context `ReceiveBuffer` is also sent on this channel as
    /// `(context_id, ContextEvent)`. Lagging receivers lose events (bounded
    /// channel) — this is acceptable because webhook delivery is best-effort.
    ///
    /// Created via [`with_event_channel`](Self::with_event_channel).
    event_tx: Option<tokio::sync::broadcast::Sender<(String, ContextEvent)>>,
    /// Weak back-pointer to the owning [`Supervisor`] (ADR-049 commit
    /// 12c.9c).
    ///
    /// Populated by [`Supervisor::attach_context_manager`] via
    /// [`Self::set_supervisor`]. `Weak` (not `Arc`) to break the
    /// [`Supervisor`] ↔ [`ContextManager`] ownership cycle: the
    /// [`Supervisor`] owns an [`Arc<ContextManager>`] through its
    /// `context_manager_bridge` slot, and this field points back at the
    /// [`Supervisor`] via a non-owning [`Weak`] — so dropping the
    /// [`Supervisor`] drops the [`ContextManager`] drops the `Weak`
    /// without leaking.
    ///
    /// Read through [`Self::supervisor`]. Used by the messaging,
    /// broadcast, governance, and economy forwarders in
    /// `manager/{messaging,broadcast,governance,economy}.rs` to reach
    /// the hoisted helpers that now take `&Supervisor` rather than
    /// `&ContextManager` (ADR-049 commit 12c.9c). Deleted alongside the
    /// manager itself in commit 12c.9h.
    supervisor: OnceLock<Weak<Supervisor>>,
}

// Nursery lint — false-positives on async functions holding tokio::sync::MutexGuard
// across block boundaries. The lock-snapshot-persist pattern is intentional.
#[allow(clippy::significant_drop_tightening)]
impl ContextManager {
    /// Creates a new `ContextManager` with the given providers.
    ///
    /// All providers are boxed trait objects, allowing any implementation
    /// to be injected (production implementations, test mocks, etc.).
    ///
    /// # Arguments
    ///
    /// * `crypto` -- Provider for MLS and sender key operations.
    /// * `transport` -- Provider for relay connectivity and publication.
    /// * `event_log` -- Provider for event log initialisation and append.
    /// * `key_resolver` -- Resolver for DID-to-Ed25519 key mapping (governance vote verification).
    #[must_use]
    pub fn new(
        crypto: Arc<MlsCryptoProvider>,
        transport: Box<dyn ContextTransportProvider>,
        event_log: Box<dyn ContextEventLogProvider>,
        key_resolver: KeyResolver,
    ) -> Self {
        Self {
            crypto,
            transport: Arc::from(transport),
            event_log: Arc::from(event_log),
            persistence: None,
            local_dids: RwLock::new(HashSet::new()),
            contexts: Arc::new(DashMap::new()),
            key_resolver,
            clock: Arc::new(scp_primitives::SystemClock),
            standing_contexts: Mutex::new(HashMap::new()),
            payment_adapter: None,
            task_set: Arc::new(tokio::sync::Mutex::new(tokio::task::JoinSet::new())),
            next_generation: std::sync::atomic::AtomicU64::new(1),
            event_tx: None,
            // ADR-049 commit 12c.9c — populated by
            // `Supervisor::attach_context_manager` via
            // `set_supervisor`. Empty until the owning Supervisor
            // attaches this manager.
            supervisor: OnceLock::new(),
        }
    }

    /// Creates a new `ContextManager` with persistence support.
    ///
    /// Same as [`new`](Self::new) but additionally accepts a
    /// [`ContextPersistence`] provider. When provided, the manager
    /// persists full context and broadcast state after every mutating
    /// operation (best-effort: errors logged, not propagated).
    ///
    /// # Arguments
    ///
    /// * `crypto` -- Provider for MLS and sender key operations.
    /// * `transport` -- Provider for relay connectivity and publication.
    /// * `event_log` -- Provider for event log initialisation and append.
    /// * `persistence` -- Provider for context state persistence.
    /// * `key_resolver` -- Resolver for DID-to-Ed25519 key mapping (governance vote verification).
    #[must_use]
    pub fn with_persistence(
        crypto: Arc<MlsCryptoProvider>,
        transport: Box<dyn ContextTransportProvider>,
        event_log: Box<dyn ContextEventLogProvider>,
        persistence: Box<dyn ContextPersistence>,
        key_resolver: KeyResolver,
    ) -> Self {
        Self {
            crypto,
            transport: Arc::from(transport),
            event_log: Arc::from(event_log),
            persistence: Some(Arc::from(persistence)),
            local_dids: RwLock::new(HashSet::new()),
            contexts: Arc::new(DashMap::new()),
            key_resolver,
            clock: Arc::new(scp_primitives::SystemClock),
            standing_contexts: Mutex::new(HashMap::new()),
            payment_adapter: None,
            task_set: Arc::new(tokio::sync::Mutex::new(tokio::task::JoinSet::new())),
            next_generation: std::sync::atomic::AtomicU64::new(1),
            event_tx: None,
            // ADR-049 commit 12c.9c — see matching comment in `new`.
            supervisor: OnceLock::new(),
        }
    }

    /// Returns a [`ContextManagerBuilder`] for step-by-step assembly.
    ///
    /// The builder provides a more ergonomic API than the raw constructors,
    /// with optional defaults and a `.storage()` method that auto-wires
    /// persistence and event log bridges from a single `Storage` impl.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let manager = ContextManager::builder()
    ///     .crypto(Box::new(my_crypto))
    ///     .storage(my_storage)  // auto-wires persistence + event log
    ///     .build()?;
    /// ```
    #[must_use]
    pub fn builder() -> ContextManagerBuilder {
        ContextManagerBuilder::new()
    }

    /// Removes all registered contexts from the manager.
    ///
    /// This is a best-effort teardown: it clears the `DashMap` and cancels
    /// all background tasks (TTL timers, governance timeouts) associated
    /// with each context. MLS groups are destroyed via the crypto provider.
    ///
    /// Used by [`scp_ffi_common::BridgeInstance::shutdown`] to clean up
    /// context state during bridge lifecycle teardown.
    ///
    /// Does NOT send leave messages to relays or notify remote peers —
    /// this is a local cleanup operation for process exit / test teardown.
    pub fn shutdown_all_contexts(&self) {
        // Collect IDs first to avoid holding DashMap shard locks while
        // performing cleanup (which may acquire per-context mutexes).
        let context_ids: Vec<String> = self
            .contexts
            .iter()
            .map(|entry| entry.key().clone())
            .collect();

        for context_id in &context_ids {
            let ctx_id_bytes = context_id_to_bytes(context_id);

            // Destroy sender key BEFORE MLS group. The MLS crypto provider
            // stores both in the same internal HashMap entry — destroy_mls_group
            // removes the entry entirely, making a subsequent destroy_sender_key
            // a no-op (key not zeroized). Ordering: zeroize secrets first,
            // then tear down the group structure.
            if let Err(e) = self.crypto.destroy_sender_key(&ctx_id_bytes) {
                tracing::debug!(
                    context_id = %context_id,
                    error = %e,
                    "failed to destroy sender key during shutdown — may already be gone"
                );
            }
            if let Err(e) = self.crypto.destroy_mls_group(&ctx_id_bytes) {
                tracing::debug!(
                    context_id = %context_id,
                    error = %e,
                    "failed to destroy MLS group during shutdown — may already be gone"
                );
            }
            if let Err(e) = self.event_log.destroy_event_log(&ctx_id_bytes) {
                tracing::debug!(
                    context_id = %context_id,
                    error = %e,
                    "failed to destroy event log during shutdown — may already be gone"
                );
            }

            // Remove from the DashMap (drops the Arc, which may drop the
            // PerContextState if no other references exist).
            self.contexts.remove(context_id);
        }

        // Clear standing contexts tracking.
        if let Ok(mut standing) = self.standing_contexts.try_lock() {
            standing.clear();
        }

        // Abort all background tasks (TTL timers, governance timeouts).
        // Best-effort: if the mutex is contended, tasks will be cleaned
        // up when their contexts are dropped.
        if let Ok(mut tasks) = self.task_set.try_lock() {
            tasks.abort_all();
        }

        tracing::info!(
            removed_count = context_ids.len(),
            "shutdown: removed all contexts and aborted background tasks"
        );
    }

    // -----------------------------------------------------------------
    // Persistence flush (sync, best-effort)
    // -----------------------------------------------------------------

    /// Per-context lock-acquisition budget used by
    /// [`Self::flush_all_contexts`]. Kept intentionally short: the flush
    /// happens on the shutdown / suspend path and must complete even when
    /// some contexts are wedged. Contexts that cannot be locked within this
    /// window receive a degraded snapshot with `needs_reconnect = true`
    /// so the restore path sees the reconnect signal rather than a missing
    /// context.
    const FLUSH_LOCK_BUDGET: std::time::Duration = std::time::Duration::from_millis(250);

    /// Persists all contexts as a best-effort snapshot flush. Async variant.
    ///
    /// Iterates the context map and, for each context, attempts to acquire
    /// its `Mutex` with a bounded timeout (see [`Self::FLUSH_LOCK_BUDGET`]).
    /// On successful acquisition, takes a full snapshot and persists it.
    /// On lock timeout, persists a **degraded** snapshot with
    /// `needs_reconnect = true` and an empty `mls_crypto_state` so the
    /// restore path fires the reconnection pipeline (AC3 bug fix).
    ///
    /// Intended for use by [`BridgeInstance::suspend`] and
    /// [`BridgeInstance::shutdown_core_async`] to flush state before
    /// transport is torn down or MLS groups are destroyed. Errors from
    /// individual contexts are logged and do not abort the flush.
    ///
    /// No-op if no persistence provider is configured.
    pub async fn flush_all_contexts(&self) {
        if !self.has_persistence() {
            return;
        }
        // Collect Arcs first to avoid holding DashMap shard locks.
        let arcs = self.collect_context_arcs();
        let mut flushed = 0usize;
        let mut degraded = 0usize;
        for (context_id, arc) in arcs {
            match tokio::time::timeout(Self::FLUSH_LOCK_BUDGET, arc.lock()).await {
                Ok(ctx) => {
                    let snapshot = Self::snapshot_context(&ctx);
                    let bc_snapshot = ctx
                        .broadcast_context
                        .as_ref()
                        .map(BroadcastContext::to_snapshot);
                    drop(ctx);
                    self.persist_context_snapshot(&context_id, snapshot);
                    if let Some(ref bcs) = bc_snapshot {
                        self.persist_broadcast_snapshot(&context_id, bcs);
                    }
                    flushed += 1;
                }
                Err(_elapsed) => {
                    // Lock was held past the budget — a task is holding the
                    // context mutex for longer than the flush is willing to
                    // wait. Persist a degraded snapshot that marks the
                    // context as needing reconnection on restore (§23.11).
                    self.persist_degraded_snapshot(&context_id);
                    degraded += 1;
                }
            }
        }
        tracing::debug!(
            flushed,
            degraded,
            "flush_all_contexts: flushed {} context(s), {} degraded (lock timeout)",
            flushed,
            degraded,
        );
    }

    /// Sync wrapper for [`Self::flush_all_contexts`].
    ///
    /// Required by `Drop` and other terminal sync callers that cannot
    /// `.await`. Uses [`tokio::runtime::Handle::current`] to block on the
    /// async flush. **Callers MUST be inside a tokio runtime** — this is
    /// the invariant for every sync shutdown path in the codebase.
    pub fn flush_all_contexts_sync(&self) {
        if !self.has_persistence() {
            return;
        }
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                // `block_on` from inside a runtime worker thread would
                // deadlock; `block_in_place` + `block_on` is the idiomatic
                // way to bridge sync → async from a multi-thread runtime.
                tokio::task::block_in_place(|| {
                    handle.block_on(self.flush_all_contexts());
                });
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "flush_all_contexts_sync called outside tokio runtime; \
                     skipping flush — context state may not be persisted"
                );
            }
        }
    }

    /// Persists a degraded `ContextSnapshot` for a context whose lock
    /// could not be acquired within the flush budget. The snapshot carries
    /// `needs_reconnect = true` and empty `mls_crypto_state` so the
    /// restore path triggers the §23.11 reconnection pipeline.
    ///
    /// A degraded snapshot is strictly better than no snapshot: callers of
    /// `restore_context` that find no entry for a known context have no
    /// reconnect signal and will silently drop the context. With this
    /// snapshot, the reconnection pipeline fires on the next resume.
    fn persist_degraded_snapshot(&self, context_id: &str) {
        let Some(ref persistence) = self.persistence else {
            return;
        };
        // Try to pull the context's current params and membership from
        // the contexts map without locking the mutex (we already know
        // the lock is held). Fall back to minimal fields if the context
        // has been removed concurrently.
        let snapshot = Self::build_degraded_snapshot(context_id);
        if let Err(e) = persistence.persist_context(context_id, &snapshot) {
            crate::metrics::record_persistence_failure();
            tracing::warn!(
                context_id = %context_id,
                error = %e,
                "failed to persist degraded context snapshot"
            );
        } else {
            tracing::warn!(
                context_id = %context_id,
                "persisted degraded snapshot (needs_reconnect=true) — \
                 context lock could not be acquired within flush budget"
            );
        }
    }

    /// Builds a minimal `ContextSnapshot` marked for reconnection.
    ///
    /// The payload is intentionally empty beyond the `context_id` and
    /// `needs_reconnect = true` flag — the restore path re-derives the
    /// rest from the reconnection pipeline. Uses `Default` values for
    /// every field that is not observable externally.
    fn build_degraded_snapshot(context_id: &str) -> ContextSnapshot {
        let role_state = scp_protocol::context::roles::ContextRoleState {
            context_id: context_id.to_owned(),
            creator_did: String::new(),
            ceiling: scp_protocol::context::roles::CapabilityCeiling::new(std::iter::empty::<
                scp_protocol::context::roles::Capability,
            >()),
            role_definitions: std::collections::HashMap::new(),
            assignments: std::collections::HashMap::new(),
            members: std::collections::HashSet::new(),
            member_capabilities: std::collections::HashMap::new(),
            suspended_capabilities: std::collections::HashMap::new(),
        };
        ContextSnapshot {
            context_id: context_id.to_owned(),
            state: ContextState::Active,
            context_params: ContextParams::default(),
            membership: MembershipState::new(),
            role_state,
            executed_proposals: std::collections::HashSet::new(),
            ttl_remaining_secs: None,
            registered_tools: Vec::new(),
            read_exclusion_list: std::collections::HashSet::new(),
            tool_interfaces: Vec::new(),
            threshold_signers: Vec::new(),
            threshold_value: 0,
            pruning_policy: None,
            governance_model_config: None,
            economic_policy: None,
            budget_tracker: scp_protocol::economy::budget::MemberBudgetTracker::new(),
            approved_proposals: std::collections::HashMap::new(),
            next_proposal_seq: 0,
            governance_freeze: None,
            pending_ceiling_modification: None,
            pending_economic_policy_change: None,
            mls_epoch: 0,
            epoch_coordination_records: Vec::new(),
            grace_entries: Vec::new(),
            needs_reconnect: true,
            mls_crypto_state: Vec::new(),
            migration_state: None,
            access_key_store: scp_protocol::crypto::access_keys::AccessKeyStore::new(),
            consequence_rules: Vec::new(),
            participation_cache: std::collections::HashMap::new(),
            velocity_tracker: None,
            velocity_tracker_state: None,
            cooldown_until: std::collections::HashMap::new(),
            proposal_timestamps: std::collections::HashMap::new(),
            message_pricing: None,
            hard_rate_limit_config: None,
            hard_rate_limit_state: std::collections::HashMap::new(),
            spending_nonce_tracker_state: std::collections::HashMap::new(),
            pending_commits: std::collections::VecDeque::new(),
            commit_fault: None,
            checkpoint_events_since: 0,
            checkpoint_last_time_secs: 0,
            generation: 0,
            local_pseudonym: None,
            pseudonym_registry: std::collections::HashMap::new(),
        }
    }

    /// Attaches a bounded broadcast channel for external event consumers.
    ///
    /// After calling this, every event pushed to a per-context
    /// `ReceiveBuffer` is also sent on the channel as
    /// `(context_id, ContextEvent)`. Lagging receivers lose events —
    /// this is acceptable because external consumers (e.g., webhook
    /// dispatchers) treat delivery as best-effort.
    ///
    /// Returns `&mut Self` for chaining.
    ///
    /// # Arguments
    ///
    /// * `capacity` — bounded channel capacity. `1024` is a sensible
    ///   default for most deployments. Values are clamped to
    ///   `[1, MAX_EVENT_CHANNEL_CAPACITY]` to prevent resource exhaustion.
    pub fn with_event_channel(&mut self, capacity: usize) -> &mut Self {
        /// Maximum broadcast channel capacity to prevent unbounded memory
        /// allocation from untrusted callers.
        const MAX_EVENT_CHANNEL_CAPACITY: usize = 8192;

        let clamped = capacity.clamp(1, MAX_EVENT_CHANNEL_CAPACITY);
        let (tx, _rx) = tokio::sync::broadcast::channel(clamped);
        self.event_tx = Some(tx);
        self
    }

    /// Returns a new [`tokio::sync::broadcast::Receiver`] for the event
    /// channel, if one was configured via [`with_event_channel`](Self::with_event_channel).
    ///
    /// Each call returns an independent receiver. Multiple consumers
    /// (e.g., webhook dispatcher, metrics collector) can subscribe
    /// concurrently.
    #[must_use]
    pub fn subscribe_events(
        &self,
    ) -> Option<tokio::sync::broadcast::Receiver<(String, ContextEvent)>> {
        self.event_tx
            .as_ref()
            .map(tokio::sync::broadcast::Sender::subscribe)
    }

    // -----------------------------------------------------------------
    // Per-context lock helpers (DashMap → Arc<Mutex<PerContextState>>)
    // -----------------------------------------------------------------

    /// Acquires the per-context `Mutex`. Returns an owned guard (the
    /// `Arc` is cloned so the `DashMap` shard lock is released
    /// immediately) and a [`ContextGeneration`] token for later
    /// reacquire verification.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::ContextNotRegistered`] if `context_id`
    /// is not in the map.
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::manager_methods::lock_context`] free function
    /// (ADR-049 commit 12c.9g.1). Deleted in commit 12c.9g.4.
    pub(crate) async fn lock_context(
        &self,
        context_id: &str,
    ) -> Result<
        (
            tokio::sync::OwnedMutexGuard<PerContextState>,
            ContextGeneration,
        ),
        ContextError,
    > {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::lock_context — Supervisor must be attached".to_owned(),
            )
        })?;
        crate::context::manager_methods::lock_context(&sup, context_id).await
    }

    /// Reacquires the per-context `Mutex` and verifies the generation
    /// counter matches `token`. Detects the confused-deputy scenario
    /// where the context was removed and recreated between lock release
    /// and reacquire (same `context_id`, different state).
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotRegistered`] if the context is gone.
    /// - [`ContextError::PermissionDenied`] if the generation changed.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::manager_methods::relock_context`] free function
    /// (ADR-049 commit 12c.9g.1). Deleted in commit 12c.9g.4.
    pub(crate) async fn relock_context(
        &self,
        token: &ContextGeneration,
    ) -> Result<tokio::sync::OwnedMutexGuard<PerContextState>, ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::relock_context — Supervisor must be attached".to_owned(),
            )
        })?;
        crate::context::manager_methods::relock_context(&sup, token).await
    }

    /// Clones the `Arc<Mutex<PerContextState>>` for a context without
    /// locking the per-context mutex. Used when the caller needs the
    /// `Arc` but will lock it later.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::ContextNotRegistered`] if the context is
    /// not in the map.
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::manager_methods::get_context_arc`] free function
    /// (ADR-049 commit 12c.9g.1). Deleted in commit 12c.9g.4.
    pub(crate) fn get_context_arc(
        &self,
        context_id: &str,
    ) -> Result<Arc<Mutex<PerContextState>>, ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::get_context_arc — Supervisor must be attached".to_owned(),
            )
        })?;
        crate::context::manager_methods::get_context_arc(&sup, context_id)
    }

    // -------------------------------------------------------------------
    // Commit 7 / ADR-049 — transitional read accessors for the
    // actor-per-context query shim. Deleted in commit 12.
    // -------------------------------------------------------------------

    /// `pub(crate)` variant of [`Self::get_context_arc`]. Used by the
    /// commit-7 query shim on
    /// [`Supervisor::dispatch_query`](crate::context::supervisor::supervisor::Supervisor::dispatch_query)
    /// to resolve the per-context Arc outside the `manager/` submodule
    /// without exposing the inner Mutex contents.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::ContextNotRegistered`] if the context is
    /// unknown.
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::manager_methods::get_context_arc_pub`] free
    /// function (ADR-049 commit 12c.9g.1). Deleted in commit 12c.9g.4.
    pub(crate) fn get_context_arc_pub(
        &self,
        context_id: &str,
    ) -> Result<Arc<Mutex<PerContextState>>, ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::get_context_arc_pub — Supervisor must be attached".to_owned(),
            )
        })?;
        crate::context::manager_methods::get_context_arc_pub(&sup, context_id)
    }

    /// Destructively move per-context state out of the manager's
    /// `contexts` map so a [`crate::context::actor::ContextActor`] can
    /// own it directly (ADR-049 commit 12b.2a).
    ///
    /// After `Ok` return:
    /// - `self.contexts[context_id]` is absent.
    /// - Every subsequent [`Self::get_context_arc`] /
    ///   [`Self::lock_context`] / [`Self::relock_context`] /
    ///   [`Self::get_context_arc_pub`] call for `context_id` returns
    ///   [`ContextError::ContextNotRegistered`] — the same error those
    ///   methods already produce when a context is unknown. This matches
    ///   the plan's "actor took ownership" contract: legacy surfaces
    ///   observe the state as gone; the actor holds the authoritative
    ///   copy.
    ///
    /// # Return shape
    ///
    /// Returns the `Arc<Mutex<PerContextState>>` wholesale rather than
    /// draining the inner struct. The actor's construction helper
    /// (landing in commit 12b.2b) locks the Mutex once, moves the state
    /// via [`tokio::sync::Mutex::into_inner`] (which requires sole Arc
    /// ownership after any outstanding `get_context_arc` clones drop),
    /// and discards the Mutex. Handing the Arc through avoids an async
    /// lock acquisition on the manager side and keeps the drain purely
    /// on the actor side where it's cheap.
    ///
    /// # Concurrency
    ///
    /// The `DashMap::remove` is atomic. Any caller that cloned the Arc
    /// via [`Self::get_context_arc`] BEFORE the remove still holds a
    /// live reference and can lock the Mutex — but `PerContextState` is
    /// `!Sync` under the Mutex and the actor's construction helper
    /// drains the state under its own lock acquisition, so the race
    /// resolves by timing: either (a) the in-flight call completes
    /// before the actor locks (state is drained to the actor after),
    /// or (b) the actor locks first and the in-flight call sees the
    /// post-drain default / empty state. Production call sites
    /// serialize spawn-vs-mutation through the supervisor's
    /// `write_lock` or the bridge's suspend flow; this method does not
    /// itself need an async lock.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::ContextNotRegistered`] if `context_id` is
    /// not in the `contexts` map (already taken or never created —
    /// indistinguishable from the manager's POV since the manager does
    /// not track the "taken" predicate; the supervisor's
    /// `actors` registry is the authoritative "actor owns this context"
    /// signal).
    ///
    /// # Scope — infrastructure only
    ///
    /// Commit 12b.2a wires the move path but no production site calls
    /// it. Commit 12b.2b is the first call site; see
    /// `.docs/adrs/ADR-049-actor-per-context.md` §Commit ladder
    /// row 12b.2b.
    ///
    /// `dead_code` allow: no production caller yet. The crate-local
    /// unit tests here exercise the method; 12b.2b removes the allow
    /// when the lifecycle handler's create/restore path invokes it.
    #[allow(dead_code)]
    pub(crate) fn take_context_state(
        &self,
        context_id: &str,
    ) -> Result<Arc<Mutex<PerContextState>>, ContextError> {
        let (_, arc) = self
            .contexts
            .remove(context_id)
            .ok_or_else(|| ContextError::ContextNotRegistered(context_id.to_owned()))?;
        Ok(arc)
    }

    /// Cheap reference to the manager's shared
    /// [`ContextEventLogProvider`]. Used by the query shim to expose
    /// Merkle event-log reads (e.g. `event_log_entries`) without cloning
    /// the provider per call.
    #[must_use]
    pub(crate) fn event_log_provider_arc(&self) -> Arc<dyn ContextEventLogProvider> {
        Arc::clone(&self.event_log)
    }

    // -------------------------------------------------------------------
    // Commit 12a.5 / ADR-049 — transitional accessors feeding
    // `ActorDeps` construction on the supervisor side. Each returns the
    // legacy manager's field by cheap clone (every target is `Arc`,
    // `Option<Arc>`, or a `KeyResolver` typealias that is itself an
    // `Arc`). Deleted in commit 12 with the legacy manager.
    //
    // Gated on the `testing` feature because the only caller is
    // [`Supervisor::build_actor_deps_from_attached`](crate::context::supervisor::supervisor::Supervisor::build_actor_deps_from_attached),
    // which is itself feature-gated. CI always builds with `testing`
    // enabled so these accessors are always compiled and linted by the
    // ratchet; production builds omit them to keep the manager's
    // public-ish surface area minimal during the shim window.
    // -------------------------------------------------------------------

    /// Cheap reference to the manager's shared
    /// [`ContextTransportProvider`]. Used by the actor-deps builder on
    /// [`Supervisor`](crate::context::supervisor::supervisor::Supervisor)
    /// to populate [`ActorDeps::transport`](crate::context::actor::deps::ActorDeps::transport).
    #[cfg(feature = "testing")]
    #[must_use]
    pub(crate) fn transport_provider_arc(&self) -> Arc<dyn ContextTransportProvider> {
        Arc::clone(&self.transport)
    }

    /// Cheap reference to the manager's `Clock`. Used by the actor-deps
    /// builder to populate [`ActorDeps::clock`](crate::context::actor::deps::ActorDeps::clock).
    #[cfg(feature = "testing")]
    #[must_use]
    pub(crate) fn clock_arc(&self) -> Arc<dyn Clock> {
        Arc::clone(&self.clock)
    }

    /// Cheap reference to the manager's wall-clock source.
    ///
    /// Returns `&Arc<dyn Clock>` so callers can `Arc::clone` only when
    /// they need ownership, and pass `&*clock` to helpers that take
    /// `&dyn Clock`. Used by the hoisted `messaging_helpers::send_message`
    /// / `deliver_incoming` free functions to satisfy their explicit-
    /// collaborator signatures without re-derefing through `self.clock`
    /// every callsite (ADR-049 commit 12c.1).
    #[must_use]
    pub(crate) const fn clock_ref(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    /// Cheap reference to the manager's `KeyResolver`. Used by the
    /// hoisted `messaging_helpers` free functions' explicit-collaborator
    /// signatures (ADR-049 commit 12c.1). Returns `&KeyResolver` so
    /// callers can pass without cloning the inner `Arc`.
    #[must_use]
    pub(crate) const fn key_resolver_ref(&self) -> &scp_protocol::context::governance::KeyResolver {
        &self.key_resolver
    }

    /// Cheap reference to the manager's `local_dids` set. Used by the
    /// hoisted `messaging_helpers::deliver_incoming` free function
    /// (ADR-049 commit 12c.1). Commit 12c.2 migrates the handler to
    /// read from `ActorDeps::local_dids` (`Arc<ArcSwap<...>>`) instead.
    #[must_use]
    pub(crate) const fn local_dids_ref(&self) -> &RwLock<HashSet<DID>> {
        &self.local_dids
    }

    /// Cheap reference to the manager's shared
    /// [`ContextCryptoProvider`]. Used by the hoisted
    /// `messaging_helpers` messaging transitives
    /// (`encrypt_and_send`, `decrypt_and_dispatch`) so their free-function
    /// bodies can reach the provider without cloning the `Arc`
    /// (ADR-049 commit 12c.1b). Non-feature-gated because the hoisted
    /// free functions are compiled in every build configuration (unlike
    /// the `testing`-gated `transport_provider_arc` / `clock_arc`
    /// accessors which only feed the actor-deps builder).
    #[must_use]
    pub(crate) const fn crypto_ref(&self) -> &Arc<MlsCryptoProvider> {
        &self.crypto
    }

    /// Cheap reference to the manager's shared
    /// [`ContextTransportProvider`]. Used by the hoisted
    /// `messaging_helpers::encrypt_and_send` free function so it can
    /// fan-out send envelopes across routing IDs without cloning the
    /// `Arc` (ADR-049 commit 12c.1b). See [`Self::crypto_ref`] for the
    /// non-feature-gated rationale.
    #[must_use]
    pub(crate) const fn transport_ref(&self) -> &Arc<dyn ContextTransportProvider> {
        &self.transport
    }

    /// Cheap reference to the manager's shared
    /// [`ContextEventLogProvider`]. Used by the hoisted
    /// `messaging_helpers::finalize_send` /
    /// `validate_and_drain_timeouts` / `buffer_ahead_message` /
    /// `deliver_message_and_drain_buffered` free functions so they can
    /// append durable log entries and read the Merkle root without
    /// cloning the `Arc` (ADR-049 commit 12c.1b). See
    /// [`Self::crypto_ref`] for the non-feature-gated rationale.
    #[must_use]
    pub(crate) const fn event_log_ref(&self) -> &Arc<dyn ContextEventLogProvider> {
        &self.event_log
    }

    /// Cheap reference to the manager's optional event fan-out
    /// [`broadcast::Sender`]. Returns `Option<&Sender>` so the hoisted
    /// `messaging_helpers` free functions can thread it into
    /// [`PerContextState::emit_event`] without cloning the `Sender` per
    /// call (ADR-049 commit 12c.1b). Non-feature-gated — the hoisted
    /// free functions are compiled in every build configuration.
    #[must_use]
    pub(crate) const fn event_tx_ref(
        &self,
    ) -> Option<&tokio::sync::broadcast::Sender<(String, ContextEvent)>> {
        self.event_tx.as_ref()
    }

    /// Cheap reference to the manager's optional persistence provider.
    /// Used by the hoisted
    /// `lifecycle_helpers::{finalize_close, load_persisted_context_state}`
    /// free functions so they can delete / read per-context state from the
    /// underlying store without cloning the `Arc` (ADR-049 commit 12c.2).
    /// Non-feature-gated — the hoisted free functions are compiled in
    /// every build configuration.
    #[must_use]
    pub(crate) const fn persistence_ref(&self) -> Option<&Arc<dyn ContextPersistence>> {
        self.persistence.as_ref()
    }

    /// Cheap reference to the manager's per-context generation counter.
    /// Used by the hoisted `lifecycle_helpers::{create_context,
    /// import_context}` free functions so they can stamp new
    /// [`PerContextState::generation`] values without going through a
    /// private field (ADR-049 commit 12c.2).
    ///
    /// Note: `insert_context` already stamps a fresh generation when
    /// inserting, so call sites typically read `fetch_add` for the
    /// `PerContextState::generation` field's initial value — the later
    /// `insert_context` stamp overwrites it.
    #[must_use]
    pub(crate) const fn next_generation_ref(&self) -> &std::sync::atomic::AtomicU64 {
        &self.next_generation
    }

    /// Cheap reference to the manager's shared task-set. Used by the
    /// hoisted `lifecycle_helpers::spawn_ttl_timer` free function so it
    /// can install the per-context TTL timer into the same `JoinSet` as
    /// the legacy method (ADR-049 commit 12c.2). Returns
    /// `&Arc<Mutex<JoinSet<()>>>` so callers can `Arc::clone` only when
    /// they need ownership for a spawned task.
    #[must_use]
    pub(crate) const fn task_set_ref(&self) -> &Arc<tokio::sync::Mutex<tokio::task::JoinSet<()>>> {
        &self.task_set
    }

    /// Cheap reference to the manager's optional event fan-out channel.
    /// Used by the actor-deps builder to populate
    /// [`ActorDeps::event_tx`](crate::context::actor::deps::ActorDeps::event_tx).
    /// Legacy stores `Sender` (not `Receiver`), which is cheap to clone
    /// (arc + atomic counter).
    #[cfg(feature = "testing")]
    #[must_use]
    pub(crate) fn event_tx_opt(
        &self,
    ) -> Option<tokio::sync::broadcast::Sender<(String, ContextEvent)>> {
        self.event_tx.clone()
    }

    /// Cheap clone of the manager's `KeyResolver`. Used by the actor-
    /// deps builder to populate
    /// [`ActorDeps::key_resolver`](crate::context::actor::deps::ActorDeps::key_resolver).
    /// `KeyResolver` is itself an `Arc<dyn Fn(...)>` typealias, so this
    /// is a reference-count bump.
    #[cfg(feature = "testing")]
    #[must_use]
    pub(crate) fn key_resolver_clone(&self) -> scp_protocol::context::governance::KeyResolver {
        Arc::clone(&self.key_resolver)
    }

    /// Cheap reference to the manager's optional payment adapter. Used
    /// by the actor-deps builder to populate
    /// [`ActorDeps::payment_adapter`](crate::context::actor::deps::ActorDeps::payment_adapter).
    #[cfg(feature = "testing")]
    #[must_use]
    pub(crate) fn payment_adapter_opt(
        &self,
    ) -> Option<Arc<dyn crate::economy::adapter::PaymentAdapterDyn>> {
        self.payment_adapter.clone()
    }

    /// Cheap reference to the manager's optional payment adapter. Used
    /// by the hoisted `economy_helpers::verify_payment_receipts` free
    /// function so it can read the adapter without cloning the `Arc`
    /// (ADR-049 commit 12c.3). Non-feature-gated — the hoisted free
    /// function is compiled in every build configuration. Returns
    /// `Option<&Arc<...>>` so callers can still `Arc::clone` when they
    /// need ownership.
    #[must_use]
    pub(crate) const fn payment_adapter_ref(
        &self,
    ) -> Option<&Arc<dyn crate::economy::adapter::PaymentAdapterDyn>> {
        self.payment_adapter.as_ref()
    }

    /// Populate the [`Weak<Supervisor>`] back-pointer on this manager
    /// (ADR-049 commit 12c.9c).
    ///
    /// Called exactly once by [`Supervisor::attach_context_manager`]
    /// during the two-way attach. Idempotent on identical input: a
    /// second call with the same upgraded [`Arc<Supervisor>`] is a
    /// no-op (the `OnceLock::set` returns `Err` but identity matches);
    /// a second call with a different upgraded [`Arc<Supervisor>`]
    /// returns [`ContextError::InvalidState`] — re-attach is not
    /// supported.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::InvalidState`] if a different
    /// [`Supervisor`] is already bound. The identity check compares
    /// upgraded [`Arc`] pointers (`Arc::ptr_eq`). If the previously-
    /// bound supervisor has already been dropped (upgrade yields
    /// `None`), identity cannot be confirmed and the call errors — but
    /// this path is unreachable in practice: the supervisor owns the
    /// manager, so the manager observing its supervisor dropped would
    /// mean the manager itself is mid-drop.
    pub(in crate::context) fn set_supervisor(
        &self,
        weak: &Weak<Supervisor>,
    ) -> Result<(), ContextError> {
        // `OnceLock::set` consumes the argument, so we clone the
        // `Weak` only when the slot is empty — avoiding a spurious
        // refcount bump on the idempotent re-attach path.
        if self.supervisor.set(weak.clone()).is_ok() {
            return Ok(());
        }
        // Slot already populated — accept identical pointer as idempotent.
        let existing = self
            .supervisor
            .get()
            .ok_or_else(|| {
                ContextError::InvalidState(
                    "ContextManager::set_supervisor — OnceLock slot observed empty after a \
                     failed `set`; this should be unreachable and indicates an impl bug"
                        .to_owned(),
                )
            })?
            .upgrade();
        let incoming = weak.upgrade();
        match (existing, incoming) {
            (Some(e), Some(i)) if Arc::ptr_eq(&e, &i) => Ok(()),
            _ => Err(ContextError::InvalidState(
                "ContextManager::set_supervisor — a different Supervisor is already \
                 attached; re-attach is not supported"
                    .to_owned(),
            )),
        }
    }

    /// Upgrade the stored [`Weak<Supervisor>`] back-pointer into an
    /// [`Arc<Supervisor>`].
    ///
    /// Returns `None` if [`Supervisor::attach_context_manager`] has
    /// not been called (slot empty) or the [`Supervisor`] has been
    /// dropped (`Weak::upgrade` returns `None`). The `Weak` path is
    /// unreachable in practice — the supervisor owns the manager, so
    /// the manager cannot outlive its supervisor — but the accessor
    /// returns `Option` to avoid panicking inside getters.
    ///
    /// Callers on the forwarder path (`manager/{messaging, broadcast,
    /// governance, economy}.rs`) unwrap the `Option` with
    /// `.expect("ContextManager::supervisor — Supervisor must be
    /// attached before forwarder invocation")` because the forwarders
    /// are only reachable through FFI/test paths that call
    /// [`Supervisor::attach_context_manager`] during bridge
    /// construction (see `crates/scp-ffi/common/src/bridge_instance.rs`).
    #[must_use]
    pub(in crate::context) fn supervisor(&self) -> Option<Arc<Supervisor>> {
        self.supervisor.get().and_then(Weak::upgrade)
    }

    /// Cheap reference to the manager's `standing_contexts` map. Used by
    /// the hoisted `standing_helpers::{standing_context,
    /// standing_context_count, has_standing_context,
    /// register_standing_context, reconnect_all_standing}` free functions
    /// so they can read/mutate the standing-pair tracking map without
    /// reaching through a private field (ADR-049 commit 12c.4).
    /// Non-feature-gated — the hoisted free functions are compiled in
    /// every build configuration. Returns `&Mutex<HashMap<...>>` so
    /// callers can `lock().await` directly.
    #[must_use]
    pub(crate) const fn standing_contexts_ref(&self) -> &Mutex<HashMap<String, DID>> {
        &self.standing_contexts
    }

    // -------------------------------------------------------------------
    // Commit 9 / ADR-049 — transitional lifecycle / TTL shim accessors.
    // Deleted in commit 12 with the shim itself.
    // -------------------------------------------------------------------

    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::lifecycle_helpers::start_ttl_timer`] free
    /// function (ADR-049 commit 12c.2). Retained for signature
    /// stability during the migration window; deleted in a later
    /// commit alongside every other `ContextManager` lifecycle surface.
    #[allow(dead_code)] // Forwarder preserved for symmetry; see doc comment.
    pub(crate) async fn start_ttl_timer(
        &self,
        context_id: &str,
        duration: std::time::Duration,
        handle: crate::context::ContextHandle,
    ) {
        let Some(sup) = self.supervisor() else {
            tracing::error!(
                context_id,
                "ContextManager::start_ttl_timer — Supervisor detached; skipping"
            );
            return;
        };
        crate::context::lifecycle_helpers::start_ttl_timer(&sup, context_id, duration, handle)
            .await;
    }

    /// Last-issued actor-shape send-sequence number for a context.
    /// Acquires the per-context lock briefly. Used by the messaging
    /// shim integration test (ADR-049 commit 8) to verify
    /// [`SequenceReservation`](crate::context::actor::SequenceReservation)
    /// rollback / commit semantics through the public path.
    ///
    /// Returns `None` if the context is unknown. Deleted in commit 12
    /// with the shim.
    ///
    /// Gated on the `testing` cargo feature so the accessor is never
    /// callable from production code — the CI clippy configuration
    /// builds with the feature enabled, so the method is always
    /// compiled and linted.
    ///
    /// # Errors
    ///
    /// None — returns `None` on unknown context rather than a typed
    /// error so the accessor composes with test-path parity helpers
    /// that use `Option`-based soft defaults.
    #[must_use]
    #[cfg(feature = "testing")]
    pub async fn send_tracker_last_issued(&self, context_id: &str) -> Option<u64> {
        let arc = self.get_context_arc(context_id).ok()?;
        let guard = arc.lock().await;
        Some(guard.send_tracker_last_issued())
    }

    /// Insert a new context into the map. Returns an error if
    /// `context_id` is already registered.
    ///
    /// Assigns a monotonically increasing generation counter so that
    /// [`relock_context`](Self::relock_context) can detect remove-and-recreate
    /// races.
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::manager_methods::insert_context`] free function
    /// (ADR-049 commit 12c.9g.1). Deleted in commit 12c.9g.4.
    pub(crate) fn insert_context(
        &self,
        context_id: String,
        state: PerContextState,
    ) -> Result<(), ContextCreationError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextCreationError::CreationFailed(
                "ContextManager::insert_context — Supervisor must be attached".to_owned(),
            )
        })?;
        crate::context::manager_methods::insert_context(&sup, context_id, state)
    }

    /// Remove a context from the map, returning its state `Arc` if it existed.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::manager_methods::remove_context`] free function
    /// (ADR-049 commit 12c.9g.1). Deleted in commit 12c.9g.4.
    #[allow(dead_code)] // Forwarder unreachable post-12c.9g.2 helper rewire; deleted in 12c.9g.4.
    pub(crate) fn remove_context(&self, context_id: &str) -> Option<Arc<Mutex<PerContextState>>> {
        let sup = self.supervisor()?;
        crate::context::manager_methods::remove_context(&sup, context_id)
    }

    /// Check if a context is registered.
    #[allow(dead_code)] // Available for callers added as contexts migrate.
    pub(super) fn context_exists(&self, context_id: &str) -> bool {
        self.contexts.contains_key(context_id)
    }

    /// Number of registered contexts.
    #[allow(dead_code)] // ADR-049 commit 12c.9g.1: only caller (`update_context_gauges`) hoisted to free function.
    pub(super) fn context_count(&self) -> usize {
        self.contexts.len()
    }

    /// Clone the `Arc<DashMap>` for use in spawned background tasks that
    /// outlive the borrow of `&self`.
    pub(crate) fn contexts_arc(&self) -> Arc<DashMap<String, Arc<Mutex<PerContextState>>>> {
        Arc::clone(&self.contexts)
    }

    /// Collect all context `Arc`s. Releases `DashMap` shard locks immediately.
    ///
    /// Useful for iteration patterns that need to lock individual contexts
    /// without holding shard locks (metrics, reconnection scans).
    pub(super) fn collect_context_arcs(&self) -> Vec<(String, Arc<Mutex<PerContextState>>)> {
        self.contexts
            .iter()
            .map(|entry| (entry.key().clone(), Arc::clone(entry.value())))
            .collect()
    }

    /// Increment the checkpoint counter for a context. Best-effort: silently
    /// skips if the context is not found (e.g., removed concurrently).
    #[allow(dead_code)] // Available for callers added as contexts migrate.
    pub(super) async fn increment_checkpoint_counter(&self, context_id: &str) {
        if let Ok(arc) = self.get_context_arc(context_id) {
            let mut guard = arc.lock().await;
            guard.checkpoint_events_since += 1;
        }
    }

    /// Returns `true` if a persistence provider is configured.
    ///
    /// Use this to guard snapshot creation so that expensive deep-clones
    /// of `PerContextState` are skipped when no persistence provider
    /// exists (the common case for most bridges).
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::manager_methods::has_persistence`] free function
    /// (ADR-049 commit 12c.9g.1). Deleted in commit 12c.9g.4.
    #[inline]
    pub(crate) fn has_persistence(&self) -> bool {
        // On a detached supervisor the helper returns `false` — observably
        // identical to the legacy method when there is no persistence.
        self.supervisor()
            .is_some_and(|sup| crate::context::manager_methods::has_persistence(&sup))
    }

    /// Persists a context snapshot if a persistence provider is configured.
    ///
    /// Best-effort: logs errors but does not propagate them to callers.
    /// In-memory state is authoritative; persistence is for crash recovery.
    ///
    /// # Ordering note
    ///
    /// The snapshot is captured under the contexts mutex lock, but
    /// `persist` is called after the lock is released. A concurrent
    /// mutation could therefore persist a stale snapshot (the second
    /// mutation's snapshot would overwrite it shortly after). This is
    /// low probability and acceptable for v1 -- the worst case is a
    /// single extra key-epoch replay on restart, which the pull-based
    /// key distribution protocol already handles idempotently.
    /// Updates operational gauge metrics (active contexts, buffer occupancy).
    ///
    /// Called after mutations that change context count or buffer state.
    /// Takes the contexts lock, so callers must NOT hold it. Best-effort:
    /// if no metrics recorder is installed, these are no-ops (#1467).
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::manager_methods::update_context_gauges`] free
    /// function (ADR-049 commit 12c.9g.1). Deleted in commit 12c.9g.4.
    #[allow(dead_code)] // Forwarder unreachable post-12c.9g.2 helper rewire; deleted in 12c.9g.4.
    pub(crate) fn update_context_gauges(&self) {
        let Some(sup) = self.supervisor() else {
            return;
        };
        crate::context::manager_methods::update_context_gauges(&sup);
    }

    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::manager_methods::persist_context_snapshot`] free
    /// function (ADR-049 commit 12c.9g.1). Deleted in commit 12c.9g.4.
    pub(crate) fn persist_context_snapshot(&self, context_id: &str, snapshot: ContextSnapshot) {
        let Some(sup) = self.supervisor() else {
            return;
        };
        crate::context::manager_methods::persist_context_snapshot(&sup, context_id, snapshot);
    }

    /// Persists a broadcast context snapshot if a persistence provider is
    /// configured. Best-effort: logs errors but does not propagate.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::manager_methods::persist_broadcast_snapshot`]
    /// free function (ADR-049 commit 12c.9g.1). Deleted in commit
    /// 12c.9g.4.
    pub(crate) fn persist_broadcast_snapshot(
        &self,
        context_id: &str,
        snapshot: &BroadcastContextSnapshot,
    ) {
        let Some(sup) = self.supervisor() else {
            return;
        };
        crate::context::manager_methods::persist_broadcast_snapshot(&sup, context_id, snapshot);
    }

    /// Initializes a `BroadcastContext` if the context is in Broadcast mode
    /// (SCP-227). Derives admission policy from `template_id` and registers
    /// the creator as the first author. Persists the initial broadcast state
    /// for crash recovery.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::manager_methods::init_broadcast_context`] free
    /// function (ADR-049 commit 12c.9g.1). Deleted in commit 12c.9g.4.
    #[allow(dead_code)] // Forwarder unreachable post-12c.9g.2 helper rewire; deleted in 12c.9g.4.
    pub(crate) fn init_broadcast_context(
        &self,
        context_id: &str,
        params: &ContextParams,
        creator_did: &DID,
    ) -> Result<Option<BroadcastContext>, ContextCreationError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextCreationError::CreationFailed(
                "ContextManager::init_broadcast_context — Supervisor must be attached".to_owned(),
            )
        })?;
        crate::context::manager_methods::init_broadcast_context(
            &sup,
            context_id,
            params,
            creator_did,
        )
    }

    /// Persists context and broadcast state if a persistence provider is configured.
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::manager_methods::persist_context_and_broadcast`]
    /// free function (ADR-049 commit 12c.9g.1). Deleted in commit
    /// 12c.9g.4.
    pub(crate) async fn persist_context_and_broadcast(&self, context_id: &str) {
        let Some(sup) = self.supervisor() else {
            return;
        };
        crate::context::manager_methods::persist_context_and_broadcast(&sup, context_id).await;
    }

    /// Takes a `ContextSnapshot` from the current `PerContextState`.
    ///
    /// Must be called while the contexts mutex is held (snapshot under lock).
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::manager_methods::snapshot_context`]
    /// free function (ADR-049 commit 12c.9g.3.5). Deleted in commit
    /// 12c.9g.4.
    #[allow(dead_code)] // Forwarder unreachable post-12c.9g.3.5 helper rewire; deleted in 12c.9g.4.
    pub(crate) fn snapshot_context(ctx: &PerContextState) -> ContextSnapshot {
        crate::context::manager_methods::snapshot_context(ctx)
    }

    /// Appends a `PaymentCaptureFailed` entry to the event log and pushes a
    /// matching [`ContextEvent::PaymentCaptureFailed`] to the receive buffer.
    ///
    /// Called by `capture_send_payment` and `capture_join_payment` when the
    /// payment adapter returns an error after a successful action (H19 audit
    /// trail). The budget deduction is NOT reversed — service was rendered (H8).
    ///
    /// # Errors on event-log append
    ///
    /// If the event log append fails, a warning is logged but the method
    /// does not propagate the error (best-effort, same as the outer capture).
    ///
    /// The method is `pub(crate)` so that unit tests can invoke it directly
    /// without needing to construct the internal `PaidActionAuthorization`
    /// type. Not part of the public API.
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::manager_methods::record_payment_capture_failure`]
    /// free function (ADR-049 commit 12c.9g.1). Deleted in commit
    /// 12c.9g.4.
    #[allow(dead_code)] // Forwarder unreachable post-12c.9g.2 helper rewire; deleted in 12c.9g.4.
    pub(crate) async fn record_payment_capture_failure(
        &self,
        context_id: &str,
        action: &str,
        actor_did: &DID,
        error_msg: &str,
        cost: Option<scp_protocol::economy::types::Amount>,
    ) {
        let Some(sup) = self.supervisor() else {
            tracing::error!(
                context_id,
                "ContextManager::record_payment_capture_failure — Supervisor is not attached; \
                 skipping (contract violation; see ADR-049 commit 12c.9g.1)"
            );
            return;
        };
        crate::context::manager_methods::record_payment_capture_failure(
            &sup, context_id, action, actor_did, error_msg, cost,
        )
        .await;
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(dead_code)] // Phase B test helper — callers added as tests migrate
#[allow(private_bounds)] // PerContextState is pub(super) but test helper is test-only
impl ContextManager {
    /// Test helper: acquires the per-context lock for direct state manipulation.
    pub(crate) async fn with_context_mut<F, R>(&self, context_id: &str, f: F) -> R
    where
        F: FnOnce(&mut PerContextState) -> R,
    {
        let arc = self
            .get_context_arc(context_id)
            .unwrap_or_else(|_| unreachable!("context not found in test"));
        let mut guard = arc.lock().await;
        f(&mut guard)
    }

    /// Test helper: returns a reference to the underlying `DashMap` for
    /// test-only assertions that need direct map access (e.g., checking
    /// entry presence, count, iteration).
    #[allow(private_interfaces)] // PerContextState is pub(super); tests are within the module.
    pub(crate) fn contexts_map(&self) -> &DashMap<String, Arc<Mutex<PerContextState>>> {
        &self.contexts
    }
}

// Compile-time assertion that `ContextManager` is `Send + Sync`.
const fn _assert_send_sync() {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ContextManager>();
}

// Tests directory deleted in ADR-049 commit 12 alongside the rest of
// `manager/`. The legacy ContextManager tests were either rewritten as
// helper-level unit tests or replaced by the Supervisor-level
// integration tests in `crates/scp-runtime/tests/` and
// `crates/scp-testing/tests/`.
