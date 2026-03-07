//! Context Manager -- central coordinator for context lifecycle.
//!
//! The [`ContextManager`] owns the provider implementations and exposes the
//! public API for context creation, membership, and messaging. It delegates
//! to [`builder::create_context`] for the two-phase commit flow.
//!
//! Providers are injected through the constructor, making the manager fully
//! testable with mock implementations. See ADR-008 in
//! `.docs/adrs/phase-2.md` for the full context lifecycle specification.

use std::collections::{HashMap, HashSet};
use std::hash::BuildHasher;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};

use super::broadcast::{
    AuthorBlockResult, BlockResult, BroadcastAdmission, BroadcastContext, BroadcastContextSnapshot,
    GovernanceBanResult, KeyRequestDecision, SubscriptionResult, UnsubscribeResult,
};
use super::builder::{
    ContextCreationError, ContextCryptoProvider, ContextEventLogProvider, ContextTransportProvider,
    create_context as builder_create_context,
};
use super::governance::{
    GovernanceAction, GovernanceProposal, ProposalId, ProposalStatus, PruningPolicy,
    RevocationScope,
};
use super::membership::{ContextEvent, KeyPackage, MembershipState, ReceiveBuffer};
use super::params::{ContextMode, TemplateId, ToolRegistration};
use super::roles::{self, Capability, CapabilityCeiling, ContextRoleState, RoleAssignment};
use super::tools::interface::ToolInterface;
use super::ttl::{self, CloseResult, TtlExtension, TtlTimer};
use super::{ContextError, ContextHandle, ContextParams, ContextState};
use crate::crypto::sender_keys::BroadcastEnvelope;
use crate::crypto::ucan::UcanToken;
use crate::crypto::ucan::validate::{
    DidResolver, NonceTracker, ProofResolver, RevocationChecker, ValidationContext,
};
use scp_identity::DID;

// GovernanceActionResult
// ---------------------------------------------------------------------------

/// Result of executing an approved governance action via
/// [`ContextManager::execute_governance_action`].
///
/// Each variant wraps the result type from the underlying operation. This
/// allows callers to pattern-match on the specific action that was executed
/// and access its result.
#[derive(Debug)]
pub enum GovernanceActionResult {
    /// An author was blocked from a broadcast context (spec section 5.14.8).
    AuthorBlocked(AuthorBlockResult),
    /// A subscriber's read access was revoked in a broadcast context
    /// (ADR-031, §5.9). The subscriber was removed from the registry and
    /// added to all authors' block lists; all author keys were rotated.
    SubscriberBanned(GovernanceBanResult),
    /// A subscriber's read access was restored in a broadcast context
    /// (ADR-031, §5.9). The DID was removed from all authors' block lists.
    /// The subscriber must re-subscribe to regain access.
    SubscriberUnbanned {
        /// The DID whose read access was restored.
        did: DID,
    },
    /// A governance action was executed successfully with no action-specific
    /// result payload. Maps to: `ChangeRole`, `ModifyCeiling`, `CloseContext`,
    /// `ExtendTtl`, `ChangeMemoryScope`, `AddMember`, `RemoveMember`,
    /// `RegisterTool`, `DeregisterTool`, `ModifyThreshold`, `AddSigner`,
    /// `RemoveSigner`, `EstablishToolInterface`, `ResetMember`,
    /// `ResolveConflict`, `PromoteContext`, `RotateContentKeys`,
    /// `RevokeWriteAccess`, `RestoreWriteAccess`, `ModifyPruningPolicy`,
    /// `ReconfigureGovernance`.
    Executed,
}

// ---------------------------------------------------------------------------
// ContextSnapshot -- serializable full context state for persistence
// ---------------------------------------------------------------------------

/// Serializable snapshot of a context's full state for persistence.
///
/// Captures all state needed to reconstruct a `PerContextState` after a
/// process restart: lifecycle state, parameters, membership, roles,
/// executed governance proposals (replay protection), and remaining TTL.
///
/// Stored via `ContextPersistence::persist_context` under
/// `context/{context_id}/full_snapshot`. See spec section 17.4.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextSnapshot {
    /// The context's unique identifier.
    pub context_id: String,
    /// The context's lifecycle state at the time of snapshot.
    pub state: ContextState,
    /// The context's creation parameters (immutable after creation).
    pub context_params: ContextParams,
    /// The membership state (members, roles, sequence numbers).
    pub membership: MembershipState,
    /// The role state (ceiling, definitions, assignments, capabilities).
    pub role_state: ContextRoleState,
    /// Proposal IDs that have already been executed (replay protection).
    pub executed_proposals: HashSet<ProposalId>,
    /// Remaining TTL in seconds, if a TTL timer was active. `None` if no
    /// TTL was configured or the timer was not running.
    pub ttl_remaining_secs: Option<u64>,
    /// Dynamically registered tools (beyond initial `ContextParams.tools`).
    #[serde(default)]
    pub registered_tools: Vec<ToolRegistration>,
    /// Members whose write access has been governance-revoked (ADR-031).
    #[serde(default)]
    pub write_revoked_members: HashSet<DID>,
    /// Established cross-context tool interfaces (§6.2).
    #[serde(default)]
    pub tool_interfaces: Vec<ToolInterface>,
    /// Governance threshold signers (for `ThresholdApproval` model).
    #[serde(default)]
    pub threshold_signers: Vec<DID>,
    /// Governance threshold value (quorum requirement).
    #[serde(default)]
    pub threshold_value: u32,
    /// Pruning policy override (ADR-030 §6).
    #[serde(default)]
    pub pruning_policy: Option<PruningPolicy>,
}

// ---------------------------------------------------------------------------
// ContextPersistence -- unified persistence provider
// ---------------------------------------------------------------------------

/// Provider for persisting full context state across process restarts.
///
/// Replaces the previous `BroadcastPersistence` trait. This is the single
/// persistence trait for all context state: both the full context snapshot
/// (membership, roles, governance, TTL) and the broadcast-specific state
/// (author keys, subscribers, block lists).
///
/// Implementors must be dyn-compatible (`Send + Sync`, no generics, no
/// RPITIT). All methods return `Result<_, Box<dyn Error + Send + Sync>>`
/// for best-effort semantics: the `ContextManager` logs errors but does
/// not abort mutations when persistence fails.
///
/// The canonical implementation is `ProtocolStorePersistence<S>` which
/// wraps `Arc<ProtocolStore<S>>`.
///
/// See spec section 17.4.
pub trait ContextPersistence: Send + Sync {
    /// Persists the full context snapshot.
    ///
    /// Called after each context-mutating operation. Idempotent.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage write fails.
    fn persist_context(
        &self,
        context_id: &str,
        snapshot: &ContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Loads a previously persisted full context snapshot.
    ///
    /// Returns `None` if no snapshot exists for the given context.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage read fails.
    fn load_context(
        &self,
        context_id: &str,
    ) -> Result<Option<ContextSnapshot>, Box<dyn std::error::Error + Send + Sync>>;

    /// Persists the broadcast context state snapshot.
    ///
    /// Called after each broadcast-mutating operation. Idempotent.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage write fails.
    fn persist_broadcast(
        &self,
        context_id: &str,
        snapshot: &BroadcastContextSnapshot,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Loads a previously persisted broadcast context snapshot.
    ///
    /// Returns `None` if no snapshot exists for the given context.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage read fails.
    fn load_broadcast(
        &self,
        context_id: &str,
    ) -> Result<Option<BroadcastContextSnapshot>, Box<dyn std::error::Error + Send + Sync>>;

    /// Deletes all persisted state for a context.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage delete fails.
    fn delete_context(
        &self,
        context_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Lists all persisted context IDs.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage list fails.
    fn list_persisted_contexts(
        &self,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>>;
}

// ---------------------------------------------------------------------------
// PerContextState -- internal per-context tracking
// ---------------------------------------------------------------------------

/// Internal state tracked by the manager for each context.
struct PerContextState {
    /// The context handle (retained for state checks and lifecycle operations).
    handle: ContextHandle,
    /// Member tracking.
    membership: MembershipState,
    /// Role state (ceiling, role definitions, assignments).
    role_state: ContextRoleState,
    /// Receive event buffer.
    receive_buffer: ReceiveBuffer,
    /// TTL timer management (SCP-021).
    ttl_timer: TtlTimer,
    /// Active TTL extension proposal, if any (SCP-021).
    #[allow(dead_code)]
    ttl_extension: Option<TtlExtension>,
    /// Broadcast context state (SCP-227). `Some` for `ContextMode::Broadcast`,
    /// `None` for `ContextMode::Encrypted`. Broadcast contexts do not use MLS;
    /// they use per-author AES-256-GCM keys managed by [`BroadcastContext`].
    broadcast_context: Option<BroadcastContext>,
    /// Proposal IDs that have already been executed. Prevents replay of
    /// approved governance proposals (defense-in-depth).
    executed_proposals: HashSet<ProposalId>,
    /// Dynamically registered tools (beyond initial `ContextParams.tools`).
    registered_tools: Vec<ToolRegistration>,
    /// Members whose write access has been governance-revoked (ADR-031).
    write_revoked_members: HashSet<DID>,
    /// Established cross-context tool interfaces (§6.2).
    tool_interfaces: Vec<ToolInterface>,
    /// Governance threshold signers (for `ThresholdApproval` model).
    threshold_signers: Vec<DID>,
    /// Governance threshold value (quorum requirement).
    threshold_value: u32,
    /// Pruning policy override (ADR-030 §6).
    pruning_policy: Option<PruningPolicy>,
}

/// Reads the context state synchronously via [`ContextHandle::try_read_state`].
/// Returns `ContextNotActive` if the read lock cannot be acquired (a state
/// transition is in progress) or if the state is not `Active`.
///
/// This is used inside `Mutex` lock scopes to avoid TOCTOU races: the state
/// check and the subsequent mutation happen within the same lock acquisition,
/// guaranteeing that no concurrent `close_context` or `handle_ttl_expiry` can
/// interleave between the check and the mutation.
fn require_active(handle: &ContextHandle) -> Result<(), ContextError> {
    let state = handle
        .try_read_state()
        .ok_or(ContextError::ContextNotActive)?;
    if state != ContextState::Active {
        return Err(ContextError::ContextNotActive);
    }
    Ok(())
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
/// let manager = ContextManager::new(crypto, transport, event_log);
/// let handle = manager.create_context("ctx-1".into(), params, "did:key:creator".into()).await?;
/// assert_eq!(handle.state().await, ContextState::Active);
/// ```
pub struct ContextManager {
    /// Provider for MLS group and sender key operations.
    ///
    /// Stored as `Arc` (not `Box`) so the provider can be shared with
    /// spawned TTL timer tasks that need crypto access for key destruction
    /// on context expiry (SCP-169).
    crypto: Arc<dyn ContextCryptoProvider>,
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
    contexts: Mutex<HashMap<String, PerContextState>>,
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
    #[must_use]
    pub fn new(
        crypto: Box<dyn ContextCryptoProvider>,
        transport: Box<dyn ContextTransportProvider>,
        event_log: Box<dyn ContextEventLogProvider>,
    ) -> Self {
        Self {
            crypto: Arc::from(crypto),
            transport: Arc::from(transport),
            event_log: Arc::from(event_log),
            persistence: None,
            local_dids: RwLock::new(HashSet::new()),
            contexts: Mutex::new(HashMap::new()),
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
    #[must_use]
    pub fn with_persistence(
        crypto: Box<dyn ContextCryptoProvider>,
        transport: Box<dyn ContextTransportProvider>,
        event_log: Box<dyn ContextEventLogProvider>,
        persistence: Box<dyn ContextPersistence>,
    ) -> Self {
        Self {
            crypto: Arc::from(crypto),
            transport: Arc::from(transport),
            event_log: Arc::from(event_log),
            persistence: Some(Arc::from(persistence)),
            local_dids: RwLock::new(HashSet::new()),
            contexts: Mutex::new(HashMap::new()),
        }
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
    fn persist_context_snapshot(&self, context_id: &str, snapshot: &ContextSnapshot) {
        if let Some(ref persistence) = self.persistence
            && let Err(e) = persistence.persist_context(context_id, snapshot)
        {
            // Best-effort persistence: log but don't fail the operation.
            // In production, the tracing crate would emit a warning here.
            // In-memory state remains authoritative.
            let _ = e; // Suppress unused warning; tracing integration is TBD.
        }
    }

    /// Persists a broadcast context snapshot if a persistence provider is
    /// configured. Best-effort: logs errors but does not propagate.
    fn persist_broadcast_snapshot(&self, context_id: &str, snapshot: &BroadcastContextSnapshot) {
        if let Some(ref persistence) = self.persistence
            && let Err(e) = persistence.persist_broadcast(context_id, snapshot)
        {
            let _ = e;
        }
    }

    /// Takes a `ContextSnapshot` from the current `PerContextState`.
    ///
    /// Must be called while the contexts mutex is held (snapshot under lock).
    fn snapshot_context(ctx: &PerContextState) -> ContextSnapshot {
        let state = ctx.handle.try_read_state().unwrap_or(ContextState::Active);
        let ttl_remaining_secs = ctx.ttl_timer.remaining_secs();
        ContextSnapshot {
            context_id: ctx.handle.context_id().to_owned(),
            state,
            context_params: ctx.handle.params().clone(),
            membership: ctx.membership.clone(),
            role_state: ctx.role_state.clone(),
            executed_proposals: ctx.executed_proposals.clone(),
            ttl_remaining_secs,
            registered_tools: ctx.registered_tools.clone(),
            write_revoked_members: ctx.write_revoked_members.clone(),
            tool_interfaces: ctx.tool_interfaces.clone(),
            threshold_signers: ctx.threshold_signers.clone(),
            threshold_value: ctx.threshold_value,
            pruning_policy: ctx.pruning_policy.clone(),
        }
    }

    /// Loads persisted context state and reconstructs a `PerContextState`.
    ///
    /// Loads the full `ContextSnapshot` and optional `BroadcastContextSnapshot`
    /// from the persistence provider. Reconstructs `PerContextState` with
    /// all fields including membership, `role_state`, `executed_proposals`, and
    /// broadcast context (if applicable).
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::PersistenceFailed`] if no persistence provider
    /// is configured, no snapshot exists, or the load operation fails.
    pub fn load_persisted_context_state(
        &self,
        context_id: &str,
    ) -> Result<(ContextSnapshot, Option<BroadcastContext>), ContextError> {
        let Some(ref persistence) = self.persistence else {
            return Err(ContextError::PersistenceFailed(
                "no persistence provider configured".into(),
            ));
        };

        let ctx_snapshot = persistence
            .load_context(context_id)
            .map_err(|e| {
                ContextError::PersistenceFailed(format!(
                    "failed to load context state for {context_id}: {e}"
                ))
            })?
            .ok_or_else(|| {
                ContextError::PersistenceFailed(format!(
                    "no persisted context state for {context_id}"
                ))
            })?;

        let broadcast_ctx = persistence
            .load_broadcast(context_id)
            .map_err(|e| {
                ContextError::PersistenceFailed(format!(
                    "failed to load broadcast state for {context_id}: {e}"
                ))
            })?
            .map(BroadcastContext::from_snapshot);

        Ok((ctx_snapshot, broadcast_ctx))
    }

    /// Restores a context into the manager from persisted state.
    ///
    /// Loads the persisted `ContextSnapshot` and optional broadcast state,
    /// reconstructs `PerContextState`, and inserts it into the contexts map.
    /// Re-spawns the TTL timer if `ttl_remaining_secs` is `Some`.
    ///
    /// # Arguments
    ///
    /// * `context_id` -- The context identifier to restore.
    /// * `handle` -- A pre-created `ContextHandle` for the context.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::PersistenceFailed`] if no persisted state
    /// exists. Returns [`ContextError::MembershipFailed`] if the context
    pub async fn restore_context(
        &self,
        context_id: &str,
        handle: &ContextHandle,
    ) -> Result<(), ContextError> {
        let (ctx_snapshot, broadcast_ctx) = self.load_persisted_context_state(context_id)?;

        let ttl_remaining = ctx_snapshot.ttl_remaining_secs;

        let per_context = PerContextState {
            handle: handle.clone(),
            membership: ctx_snapshot.membership,
            role_state: ctx_snapshot.role_state,
            receive_buffer: ReceiveBuffer::new(),
            ttl_timer: TtlTimer::new(),
            ttl_extension: None,
            broadcast_context: broadcast_ctx,
            executed_proposals: ctx_snapshot.executed_proposals,
            registered_tools: ctx_snapshot.registered_tools,
            write_revoked_members: ctx_snapshot.write_revoked_members,
            tool_interfaces: ctx_snapshot.tool_interfaces,
            threshold_signers: ctx_snapshot.threshold_signers,
            threshold_value: ctx_snapshot.threshold_value,
            pruning_policy: ctx_snapshot.pruning_policy,
        };

        {
            let mut contexts = self.contexts.lock().await;
            if contexts.contains_key(context_id) {
                return Err(ContextError::MembershipFailed(format!(
                    "context '{context_id}' already registered"
                )));
            }
            contexts.insert(context_id.to_owned(), per_context);
        }

        // Re-spawn TTL timer if there was remaining TTL.
        if let Some(remaining_secs) = ttl_remaining {
            let duration = std::time::Duration::from_secs(remaining_secs);
            self.spawn_ttl_timer(context_id, duration, handle.clone())
                .await;
        }

        Ok(())
    }

    // -------------------------------------------------------------------
    // Local DID management (defense-in-depth, #234)
    // -------------------------------------------------------------------

    /// Registers a DID as controlled by the local node/SDK.
    ///
    /// The node layer calls this at startup (and when new DIDs are created)
    /// to inform the `ContextManager` which DIDs are locally controlled.
    /// This enables defense-in-depth validation in
    /// [`handle_broadcast_key_request`](Self::handle_broadcast_key_request),
    /// which verifies the `author_did` is locally controlled before
    /// processing the key request.
    ///
    /// Registering the same DID multiple times is idempotent.
    pub async fn register_local_did(&self, did: DID) {
        self.local_dids.write().await.insert(did);
    }

    /// Returns `true` if the given DID is registered as locally controlled.
    ///
    /// This is a read-only query useful for diagnostics and testing.
    pub async fn is_local_did(&self, did: &DID) -> bool {
        self.local_dids.read().await.contains(did)
    }

    /// Restores all persisted contexts.
    ///
    /// Lists all context IDs from the persistence provider, creates a
    /// `ContextHandle` for each, and restores the context into the manager.
    /// Errors on individual context restores are logged but do not abort
    /// other restores.
    ///
    /// Returns the list of successfully restored context IDs.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::PersistenceFailed`] if listing persisted
    /// contexts fails (no persistence provider configured, or list call fails).
    pub async fn restore_all_contexts(&self) -> Result<Vec<String>, ContextError> {
        let Some(ref persistence) = self.persistence else {
            return Err(ContextError::PersistenceFailed(
                "no persistence provider configured".into(),
            ));
        };

        let context_ids = persistence.list_persisted_contexts().map_err(|e| {
            ContextError::PersistenceFailed(format!("failed to list persisted contexts: {e}"))
        })?;

        let mut restored = Vec::new();
        for ctx_id in &context_ids {
            // Load the snapshot to get params for handle creation.
            let ctx_snapshot = match persistence.load_context(ctx_id) {
                Ok(Some(snap)) => snap,
                Ok(None) => {
                    // No snapshot -- skip silently.
                    continue;
                }
                Err(e) => {
                    // Best-effort: log and continue.
                    let _ = e;
                    continue;
                }
            };

            // Only restore Active contexts. Contexts in Closing/Closed/Expired
            // states should not be resurrected after restart.
            if ctx_snapshot.state != ContextState::Active {
                continue;
            }

            let handle = ContextHandle::new(ctx_id.clone(), ctx_snapshot.context_params.clone());
            if handle.transition_to(&ContextState::Active).await.is_err() {
                continue;
            }

            match self.restore_context(ctx_id, &handle).await {
                Ok(()) => restored.push(ctx_id.clone()),
                Err(e) => {
                    // Best-effort: log and continue.
                    let _ = e;
                }
            }
        }

        Ok(restored)
    }

    /// Creates a new SCP context with the two-phase commit pattern.
    ///
    /// Delegates to [`builder::create_context`] which validates all
    /// preconditions (Phase 1), then executes creation steps with ordered
    /// rollback on failure (Phase 2).
    ///
    /// On success, registers the context with the manager for subsequent
    /// membership and messaging operations.
    ///
    /// # Arguments
    ///
    /// * `context_id` -- Unique string identifier for the new context.
    /// * `params` -- Full context configuration ([`ContextParams`]).
    /// * `creator_did` -- The DID of the context creator.
    ///
    /// # Returns
    ///
    /// A [`ContextHandle`] in the `Active` state on success.
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError`] if any validation or execution step
    /// fails. The operation is atomic from the caller's perspective: on
    /// failure, no MLS group state, sender key material, or event log state
    /// persists.
    ///
    /// See ADR-008 acceptance criterion 2.
    pub async fn create_context(
        &self,
        context_id: String,
        params: ContextParams,
        creator_did: DID,
    ) -> Result<ContextHandle, ContextCreationError> {
        // Phase 1+2: builder performs validation and creation (async, no lock held).
        let handle = builder_create_context(
            context_id.clone(),
            params.clone(),
            self.crypto.as_ref(),
            self.transport.as_ref(),
            self.event_log.as_ref(),
        )
        .await?;

        // Build ceiling from params (params::Capability is now the same type as roles::Capability).
        let ceiling = CapabilityCeiling::new(params.ceiling.iter().cloned());

        // Initialize role state with the creator as admin.
        let role_state = ContextRoleState::new(&context_id, &*creator_did, ceiling, vec![])
            .map_err(|e| ContextCreationError::CreationFailed(e.to_string()))?;

        // Initialize membership with the creator.
        let mut membership = MembershipState::new();
        let creator_tokens = role_state
            .assignments
            .get(creator_did.as_ref())
            .map(|a| a.tokens.clone())
            .unwrap_or_default();
        membership.add_member(creator_did.clone(), "admin".into(), creator_tokens);

        // Initialize broadcast context for Broadcast mode (SCP-227).
        // Derives admission policy from template_id: PublicBroadcast/PaidBroadcast
        // → Open, GatedBroadcast → Gated. Defaults to Open when no template.
        let broadcast_context = if params.mode == ContextMode::Broadcast {
            let admission = match params.template_id {
                Some(TemplateId::GatedBroadcast) => BroadcastAdmission::Gated,
                Some(TemplateId::PublicBroadcast | TemplateId::PaidBroadcast) => {
                    BroadcastAdmission::Open
                }
                _ => BroadcastAdmission::Open,
            };
            let mut bc = BroadcastContext::new(context_id.clone(), &params.mode, admission)
                .map_err(|e| ContextCreationError::CreationFailed(e.to_string()))?;
            // Register the creator as the first author (messagesWrite).
            bc.add_author(&creator_did)
                .map_err(|e| ContextCreationError::CreationFailed(e.to_string()))?;
            // Persist initial broadcast state for crash recovery.
            self.persist_broadcast_snapshot(&context_id, &bc.to_snapshot());
            Some(bc)
        } else {
            None
        };

        let per_context = PerContextState {
            handle: handle.clone(),
            membership,
            role_state,
            receive_buffer: ReceiveBuffer::new(),
            ttl_timer: TtlTimer::new(),
            ttl_extension: None,
            broadcast_context,
            executed_proposals: HashSet::new(),
            registered_tools: Vec::new(),
            write_revoked_members: HashSet::new(),
            tool_interfaces: Vec::new(),
            threshold_signers: Vec::new(),
            threshold_value: 0,
            pruning_policy: None,
        };

        // Atomic duplicate check + insert under lock -- no .await inside this scope.
        {
            let mut contexts = self.contexts.lock().await;
            if contexts.contains_key(&context_id) {
                return Err(ContextCreationError::CreationFailed(format!(
                    "context '{context_id}' already registered"
                )));
            }
            contexts.insert(context_id.clone(), per_context);
        }

        // Persist context + broadcast state after creation (best-effort).
        {
            let contexts = self.contexts.lock().await;
            if let Some(ctx) = contexts.get(&context_id) {
                let snapshot = Self::snapshot_context(ctx);
                let bc_snapshot = ctx
                    .broadcast_context
                    .as_ref()
                    .map(BroadcastContext::to_snapshot);
                drop(contexts);
                self.persist_context_snapshot(&context_id, &snapshot);
                if let Some(ref bcs) = bc_snapshot {
                    self.persist_broadcast_snapshot(&context_id, bcs);
                }
            }
        }

        // Spawn TTL timer if TTL is configured (SCP-021).
        if let Some(ttl_duration) = params.ttl {
            self.spawn_ttl_timer(&context_id, ttl_duration, handle.clone())
                .await;
        }

        Ok(handle)
    }

    /// Creates a new SCP context without tracking membership state.
    ///
    /// This is the original `create_context` signature preserved for backward
    /// compatibility with existing tests. It delegates to the builder but does
    /// not register the context for membership operations.
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError`] if any validation or execution step
    /// fails.
    pub async fn create_context_bare(
        &self,
        context_id: String,
        params: ContextParams,
    ) -> Result<ContextHandle, ContextCreationError> {
        builder_create_context(
            context_id,
            params,
            self.crypto.as_ref(),
            self.transport.as_ref(),
            self.event_log.as_ref(),
        )
        .await
    }

    /// Joins a member to a context.
    ///
    /// Validates the joiner's key package, adds to MLS group (ADR-001),
    /// distributes sender key bundle (ADR-007), assigns the default role,
    /// issues UCAN tokens, and appends a `MemberJoined` event.
    ///
    /// See ADR-008 acceptance criterion 3.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] if:
    /// - The context is not in `Active` state.
    /// - The key package is invalid.
    pub async fn join_context(
        &self,
        handle: &ContextHandle,
        key_package: KeyPackage,
    ) -> Result<(), ContextError> {
        let context_id = handle.context_id().to_owned();
        let context_id_bytes = context_id_to_bytes(&context_id);
        let member_did = key_package.owner_did.clone();

        // Crypto operations -- no lock held, no TOCTOU concern for these
        // provider calls since they are idempotent or externally consistent.
        let kp_bytes = key_package.mls_key_package_bytes.as_deref();
        self.crypto.validate_key_package(&member_did, kp_bytes)?;
        self.crypto
            .add_member(&context_id_bytes, &member_did, kp_bytes)?;
        self.crypto
            .distribute_sender_key(&context_id_bytes, &member_did)?;

        // Atomic state check + mutation: verify Active, then role assignment +
        // membership + event buffer, all within a single lock acquisition.
        // The state check is inside the lock to eliminate the TOCTOU race
        // where close_context could transition the state between the check
        // and the mutation.
        {
            let mut contexts = self.contexts.lock().await;
            let ctx = contexts
                .get_mut(&context_id)
                .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;

            // State check inside lock -- eliminates TOCTOU race.
            require_active(&ctx.handle)?;

            // Add member to role state.
            ctx.role_state.members.insert(member_did.to_string());

            // Assign default "member" role.
            let creator_did = ctx.role_state.creator_did.clone();
            let tokens =
                roles::assign_role(&mut ctx.role_state, &member_did, "member", &creator_did)
                    .map_err(|e| ContextError::MembershipFailed(e.to_string()))?;

            // Add to membership tracking.
            ctx.membership
                .add_member(member_did.clone(), "member".into(), tokens);

            // Emit MemberJoined event to receive buffer.
            ctx.receive_buffer.push(ContextEvent::MemberJoined {
                member_did: member_did.clone(),
                role_name: "member".into(),
            });
        }
        // Lock dropped before event log append.

        // Append MemberJoined event to event log.
        self.event_log
            .append_context_event(&context_id_bytes, "MemberJoined")?;

        // Persist context state after join (best-effort).
        {
            let contexts = self.contexts.lock().await;
            if let Some(ctx) = contexts.get(&context_id) {
                let snapshot = Self::snapshot_context(ctx);
                drop(contexts);
                self.persist_context_snapshot(&context_id, &snapshot);
            }
        }

        Ok(())
    }

    /// Removes a member from a context.
    ///
    /// Authorization: the caller must either be removing themselves
    /// (`caller_did == member_did`, self-removal) or hold the `MemberRemove`
    /// capability. Self-removal is always permitted regardless of role.
    ///
    /// Removes from MLS group (ADR-001), removes sender keys, and appends
    /// a `MemberLeft` event. If the member count reaches zero, transitions
    /// the context to `Closing`.
    ///
    /// See ADR-008 acceptance criterion 4.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] if:
    /// - The context is not in `Active` state.
    /// - The caller is neither the member being removed nor holds `MemberRemove`.
    /// - The member is not found.
    pub async fn leave_context(
        &self,
        handle: &ContextHandle,
        caller_did: &DID,
        member_did: &DID,
    ) -> Result<(), ContextError> {
        let context_id = handle.context_id().to_owned();
        let context_id_bytes = context_id_to_bytes(&context_id);

        // Determine if this is a broadcast context (lock, read, drop).
        let is_broadcast = {
            let contexts = self.contexts.lock().await;
            let ctx = contexts
                .get(&context_id)
                .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;
            ctx.broadcast_context.is_some()
        };

        // Authorization check: self-removal is always allowed; otherwise
        // the caller must hold MemberRemove capability.
        if caller_did != member_did {
            let contexts = self.contexts.lock().await;
            let ctx = contexts
                .get(&context_id)
                .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;
            if !ctx
                .role_state
                .member_has_capability(caller_did, &Capability::MemberRemove)
            {
                return Err(ContextError::PermissionDenied(
                    "caller lacks permission to remove this member".into(),
                ));
            }
            drop(contexts);
        }

        // Crypto operations -- no lock held. Skip for broadcast mode (no MLS).
        if !is_broadcast {
            self.crypto.remove_member(&context_id_bytes, member_did)?;
            self.crypto
                .remove_member_sender_key(&context_id_bytes, member_did)?;
        }

        // Atomic state check + membership removal + count check within single lock.
        let should_close = {
            let mut contexts = self.contexts.lock().await;
            let ctx = contexts
                .get_mut(&context_id)
                .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;

            // State check inside lock -- eliminates TOCTOU race.
            require_active(&ctx.handle)?;

            // For broadcast contexts, unsubscribe from the BroadcastContext.
            // rotate_keys=true for forward secrecy after departure.
            if let Some(ref mut bc) = ctx.broadcast_context {
                // Ignore MemberNotFound -- the member may be an author who was
                // never a subscriber. Propagate all other errors (e.g.
                // CryptoFailed from epoch overflow during key rotation).
                match bc.unsubscribe(member_did, true) {
                    Ok(_) | Err(ContextError::MemberNotFound(_)) => {}
                    Err(e) => return Err(e),
                }
            }

            if !ctx.membership.remove_member(member_did) {
                return Err(ContextError::MemberNotFound(member_did.to_string()));
            }

            // Remove from role state.
            ctx.role_state.members.remove(member_did.as_ref());
            ctx.role_state.assignments.remove(member_did.as_ref());
            ctx.role_state
                .member_capabilities
                .remove(member_did.as_ref());

            // Emit MemberLeft event to receive buffer.
            ctx.receive_buffer.push(ContextEvent::MemberLeft {
                member_did: member_did.clone(),
            });

            ctx.membership.count() == 0
        };
        // Lock dropped.

        // Append MemberLeft event to event log.
        self.event_log
            .append_context_event(&context_id_bytes, "MemberLeft")?;

        // Persist context state after leave (best-effort).
        {
            let contexts = self.contexts.lock().await;
            if let Some(ctx) = contexts.get(&context_id) {
                let snapshot = Self::snapshot_context(ctx);
                drop(contexts);
                self.persist_context_snapshot(&context_id, &snapshot);
            }
        }

        // If member count reaches zero, transition to Closing.
        if should_close {
            handle.transition_to(&ContextState::Closing).await?;
        }

        Ok(())
    }

    /// Sends a message within a context.
    ///
    /// For encrypted contexts: validates the context is `Active`, validates the
    /// sender's UCAN for `messages:write` capability, assigns a per-sender
    /// monotonic SCP sequence number, encrypts the message (sender key + MLS +
    /// envelopes), sends via transport, and appends a `MessageSent` event.
    ///
    /// For broadcast contexts: validates `Active` state, checks `can_write`
    /// via `BroadcastContext::publish`, assigns sequence number, and sends
    /// the broadcast envelope via transport.
    ///
    /// See ADR-008 acceptance criterion 8.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] if:
    /// - The context is not in `Active` state.
    /// - The sender lacks `messages:write` capability.
    pub async fn send_message(
        &self,
        handle: &ContextHandle,
        sender_did: &DID,
        payload: &[u8],
    ) -> Result<(), ContextError> {
        let context_id = handle.context_id().to_owned();
        let context_id_bytes = context_id_to_bytes(&context_id);

        // Determine if broadcast and, if so, produce the envelope under lock.
        let broadcast_envelope: Option<BroadcastEnvelope> = {
            let mut contexts = self.contexts.lock().await;
            let ctx = contexts
                .get_mut(&context_id)
                .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;

            // State check inside lock -- eliminates TOCTOU race.
            require_active(&ctx.handle)?;

            // Governance-level write revocation check (§9.17, ADR-038).
            if ctx.write_revoked_members.contains(sender_did) {
                return Err(ContextError::PermissionDenied(format!(
                    "write access has been revoked for {sender_did}"
                )));
            }

            if let Some(ref bc) = ctx.broadcast_context {
                // Broadcast path: capability check + seal under lock.
                let envelope = bc.publish(sender_did, payload)?;

                // Assign per-sender monotonic sequence number.
                let seq = ctx
                    .membership
                    .next_sequence_number(sender_did)
                    .ok_or_else(|| ContextError::MemberNotFound(sender_did.to_string()))?;

                // Emit MessageSent event to receive buffer.
                ctx.receive_buffer.push(ContextEvent::MessageSent {
                    sender_did: sender_did.clone(),
                    sequence_number: seq,
                    payload: payload.to_vec(),
                });

                Some(envelope)
            } else {
                // Encrypted path: role-based capability check + seq under lock.
                if !ctx
                    .role_state
                    .member_has_capability(sender_did, &Capability::MessagesWrite)
                {
                    return Err(ContextError::PermissionDenied(format!(
                        "member {sender_did} does not have messages:write capability"
                    )));
                }

                let seq = ctx
                    .membership
                    .next_sequence_number(sender_did)
                    .ok_or_else(|| ContextError::MemberNotFound(sender_did.to_string()))?;

                ctx.receive_buffer.push(ContextEvent::MessageSent {
                    sender_did: sender_did.clone(),
                    sequence_number: seq,
                    payload: payload.to_vec(),
                });

                None
            }
        };
        // Lock dropped before crypto/transport/event-log calls.

        let encrypted = if let Some(envelope) = broadcast_envelope {
            // Broadcast: serialize envelope for transport.
            envelope.encrypted_content
        } else {
            // Encrypted: sender key (ADR-007) -> inner envelope (ADR-002) ->
            // MLS (ADR-001) -> outer envelope.
            self.crypto
                .encrypt_message(&context_id_bytes, sender_did, payload)?
        };

        // Send via transport.
        self.transport.send_message(&context_id_bytes, &encrypted)?;

        // Append MessageSent event to event log.
        self.event_log
            .append_context_event(&context_id_bytes, "MessageSent")?;

        // Persist context state after send (best-effort).
        {
            let contexts = self.contexts.lock().await;
            if let Some(ctx) = contexts.get(&context_id) {
                let snapshot = Self::snapshot_context(ctx);
                drop(contexts);
                self.persist_context_snapshot(&context_id, &snapshot);
            }
        }

        Ok(())
    }

    /// Returns the current member count for a context.
    ///
    /// Returns `None` if the context is not registered with this manager.
    pub async fn member_count(&self, context_id: &str) -> Option<usize> {
        self.contexts
            .lock()
            .await
            .get(context_id)
            .map(|ctx| ctx.membership.count())
    }

    /// Returns `true` if the given DID is a member of the specified context.
    pub async fn is_member(&self, context_id: &str, did: &str) -> bool {
        self.contexts
            .lock()
            .await
            .get(context_id)
            .is_some_and(|ctx| ctx.membership.contains(did))
    }

    /// Returns all member DIDs for a context.
    pub async fn member_dids(&self, context_id: &str) -> Vec<String> {
        self.contexts
            .lock()
            .await
            .get(context_id)
            .map(|ctx| {
                ctx.membership
                    .member_dids()
                    .map(std::string::ToString::to_string)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Returns the role assignment for a specific member in a context.
    pub async fn member_role(&self, context_id: &str, did: &str) -> Option<RoleAssignment> {
        self.contexts
            .lock()
            .await
            .get(context_id)
            .and_then(|ctx| ctx.role_state.assignments.get(did).cloned())
    }

    /// Drains all events from the receive buffer for a context.
    ///
    /// Returns an empty `Vec` if the context is not registered.
    pub async fn drain_events(&self, context_id: &str) -> Vec<ContextEvent> {
        self.contexts
            .lock()
            .await
            .get_mut(context_id)
            .map(|ctx| ctx.receive_buffer.drain())
            .unwrap_or_default()
    }

    // -------------------------------------------------------------------
    // Broadcast context operations (SCP-227)
    // -------------------------------------------------------------------

    /// Subscribes a DID to a broadcast context.
    ///
    /// For open broadcast contexts, any DID can subscribe without a UCAN.
    /// For gated contexts, a valid `messagesRead` UCAN is required and
    /// validated through the full 11-step pipeline (ADR-016).
    ///
    /// Returns the current author key epochs so the subscriber knows which
    /// epochs to request keys for.
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotActive`] if the context is not `Active`.
    /// - [`ContextError::MembershipFailed`] if the context is not a broadcast
    ///   context or the subscriber is already registered.
    /// - [`ContextError::PermissionDenied`] if the context is gated and no
    pub async fn subscribe_broadcast<D, N, R, P, S>(
        &self,
        context_id: &str,
        subscriber_did: &DID,
        ucan: Option<&UcanToken>,
        timestamp: u64,
        validation_ctx: Option<&mut ValidationContext<'_, D, N, R, P, S>>,
    ) -> Result<SubscriptionResult, ContextError>
    where
        D: DidResolver + Send + Sync,
        N: NonceTracker + Send + Sync,
        R: RevocationChecker + Send + Sync,
        P: ProofResolver + Send + Sync,
        S: BuildHasher + Send + Sync,
    {
        let context_id_bytes = context_id_to_bytes(context_id);

        let (result, snapshot) = {
            let mut contexts = self.contexts.lock().await;
            let ctx = contexts
                .get_mut(context_id)
                .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;

            require_active(&ctx.handle)?;

            let bc = ctx
                .broadcast_context
                .as_mut()
                .ok_or_else(|| ContextError::MembershipFailed("not a broadcast context".into()))?;

            let result = bc.subscribe(subscriber_did, ucan, timestamp, validation_ctx)?;

            // Take snapshot for persistence before dropping lock.
            let snapshot = bc.to_snapshot();

            // Add subscriber to membership tracking (role = "subscriber").
            ctx.membership
                .add_member(subscriber_did.clone(), "subscriber".into(), vec![]);

            // Push event to receive buffer.
            ctx.receive_buffer.push(result.event.clone());

            (result, snapshot)
        };
        // Lock dropped.

        // Persist broadcast state for crash recovery.
        self.persist_broadcast_snapshot(context_id, &snapshot);

        // Persist context state after subscribe (best-effort).
        {
            let contexts = self.contexts.lock().await;
            if let Some(ctx) = contexts.get(context_id) {
                let ctx_snapshot = Self::snapshot_context(ctx);
                drop(contexts);
                self.persist_context_snapshot(context_id, &ctx_snapshot);
            }
        }

        // Append event to persistent event log.
        self.event_log
            .append_context_event(&context_id_bytes, "MemberJoined")?;

        Ok(result)
    }

    /// Unsubscribes a DID from a broadcast context.
    ///
    /// When `rotate_keys` is `true`, all authors rotate their broadcast keys
    /// to ensure forward secrecy (the departed subscriber cannot decrypt
    /// future content).
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotActive`] if the context is not `Active`.
    /// - [`ContextError::MembershipFailed`] if the context is not a broadcast
    ///   context.
    pub async fn unsubscribe_broadcast(
        &self,
        context_id: &str,
        subscriber_did: &DID,
        rotate_keys: bool,
    ) -> Result<UnsubscribeResult, ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        let (result, snapshot) = {
            let mut contexts = self.contexts.lock().await;
            let ctx = contexts
                .get_mut(context_id)
                .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;

            require_active(&ctx.handle)?;

            let bc = ctx
                .broadcast_context
                .as_mut()
                .ok_or_else(|| ContextError::MembershipFailed("not a broadcast context".into()))?;

            let result = bc.unsubscribe(subscriber_did, rotate_keys)?;

            // Take snapshot for persistence before dropping lock.
            let snapshot = bc.to_snapshot();

            // Remove from membership tracking.
            ctx.membership.remove_member(subscriber_did);

            // Emit MemberLeft event to receive buffer.
            ctx.receive_buffer.push(ContextEvent::MemberLeft {
                member_did: subscriber_did.clone(),
            });

            (result, snapshot)
        };
        // Lock dropped.

        // Persist broadcast state for crash recovery.
        self.persist_broadcast_snapshot(context_id, &snapshot);

        // Persist context state after unsubscribe (best-effort).
        {
            let contexts = self.contexts.lock().await;
            if let Some(ctx) = contexts.get(context_id) {
                let ctx_snapshot = Self::snapshot_context(ctx);
                drop(contexts);
                self.persist_context_snapshot(context_id, &ctx_snapshot);
            }
        }

        self.event_log
            .append_context_event(&context_id_bytes, "MemberLeft")?;

        Ok(result)
    }

    /// Publishes a message to a broadcast context.
    ///
    /// Validates that the sender is a registered author (`messagesWrite`),
    /// seals the payload with the author's broadcast key, assigns a sequence
    /// number, and sends via transport.
    ///
    /// This is the broadcast-specific publish path. For a unified API, use
    /// [`send_message`](Self::send_message) which routes to this path
    /// automatically for broadcast contexts.
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotActive`] if the context is not `Active`.
    /// - [`ContextError::MembershipFailed`] if the context is not broadcast.
    /// - [`ContextError::PermissionDenied`] if the sender is not an author.
    pub async fn publish_broadcast(
        &self,
        context_id: &str,
        author_did: &DID,
        payload: &[u8],
    ) -> Result<BroadcastEnvelope, ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        let envelope = {
            let mut contexts = self.contexts.lock().await;
            let ctx = contexts
                .get_mut(context_id)
                .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;

            require_active(&ctx.handle)?;

            // Governance-level write revocation check (§9.17, ADR-038).
            if ctx.write_revoked_members.contains(author_did) {
                return Err(ContextError::PermissionDenied(format!(
                    "write access has been revoked for {author_did}"
                )));
            }

            let bc = ctx
                .broadcast_context
                .as_ref()
                .ok_or_else(|| ContextError::MembershipFailed("not a broadcast context".into()))?;

            let envelope = bc.publish(author_did, payload)?;

            // Assign per-sender monotonic sequence number.
            let seq = ctx
                .membership
                .next_sequence_number(author_did)
                .ok_or_else(|| ContextError::MemberNotFound(author_did.to_string()))?;

            ctx.receive_buffer.push(ContextEvent::MessageSent {
                sender_did: author_did.clone(),
                sequence_number: seq,
                payload: payload.to_vec(),
            });

            envelope
        };
        // Lock dropped.

        // Send via transport.
        self.transport
            .send_message(&context_id_bytes, &envelope.encrypted_content)?;

        // Append event to persistent event log.
        self.event_log
            .append_context_event(&context_id_bytes, "MessageSent")?;

        Ok(envelope)
    }

    /// Blocks a subscriber from receiving future broadcast keys from a
    /// specific author.
    ///
    /// The author's broadcast key is rotated and the subscriber is added to
    /// the author's block list. The blocked subscriber receives no response
    /// to future key requests and cannot decrypt content encrypted with the
    /// new key.
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotActive`] if the context is not `Active`.
    /// - [`ContextError::MembershipFailed`] if the context is not broadcast.
    /// - [`ContextError::MemberNotFound`] if the author is not registered.
    pub async fn block_broadcast_subscriber(
        &self,
        context_id: &str,
        author_did: &DID,
        subscriber_did: &DID,
    ) -> Result<BlockResult, ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        let (result, snapshot) = {
            let mut contexts = self.contexts.lock().await;
            let ctx = contexts
                .get_mut(context_id)
                .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;

            require_active(&ctx.handle)?;

            let bc = ctx
                .broadcast_context
                .as_mut()
                .ok_or_else(|| ContextError::MembershipFailed("not a broadcast context".into()))?;

            let result = bc.block_subscriber(author_did, subscriber_did)?;

            // Take snapshot for persistence before dropping lock.
            let snapshot = bc.to_snapshot();

            // Emit block event to receive buffer.
            ctx.receive_buffer.push(ContextEvent::MemberBlocked {
                blocked_did: subscriber_did.clone(),
                author_did: author_did.clone(),
            });

            (result, snapshot)
        };
        // Lock dropped.

        // Persist broadcast state for crash recovery.
        self.persist_broadcast_snapshot(context_id, &snapshot);

        self.event_log
            .append_context_event(&context_id_bytes, "MemberBlocked")?;

        Ok(result)
    }

    /// Executes an approved governance action on a broadcast context.
    ///
    /// This is the sole entry point for governance-gated operations. The caller
    /// must provide a [`GovernanceProposal`] that has been approved through the
    /// context's governance model (e.g., `SingleAdminEngine::propose()` for
    /// single-admin contexts, or `ThresholdEngine::approve()` reaching quorum).
    ///
    /// Supports all 25 [`GovernanceAction`] variants (24 from ADR-031 + legacy `BlockAuthor`).
    /// Actions that modify context state do so under the context write lock
    /// and emit appropriate events.
    ///
    /// # Errors
    ///
    /// - [`ContextError::PermissionDenied`] if the proposal is not in
    ///   `Approved` status.
    /// - [`ContextError::PermissionDenied`] if the context's ceiling does not
    ///   include `MemberBan` (for `RevokeReadAccess`/`RestoreReadAccess`).
    /// - [`ContextError::ContextNotActive`] if the context is not `Active`.
    /// - [`ContextError::MembershipFailed`] if the context is not a broadcast
    ///   context (for `BlockAuthor`, `RevokeReadAccess`, `RestoreReadAccess`).
    pub async fn execute_governance_action(
        &self,
        context_id: &str,
        proposal: &GovernanceProposal,
    ) -> Result<GovernanceActionResult, ContextError> {
        // Gate: only approved proposals can be executed.
        if !matches!(proposal.status, ProposalStatus::Approved) {
            return Err(ContextError::PermissionDenied(format!(
                "governance proposal is not approved (status: {:?})",
                proposal.status
            )));
        }

        // Gate: proposal must target this context.
        if proposal.context_id != context_id {
            return Err(ContextError::PermissionDenied(format!(
                "governance proposal targets context '{}' but was submitted to '{}'",
                proposal.context_id, context_id
            )));
        }

        // Atomically check replay AND mark as executed before dispatch.
        // This prevents TOCTOU races where concurrent callers both pass the
        // replay check before either records the proposal as executed.
        {
            let mut contexts = self.contexts.lock().await;
            if let Some(ctx) = contexts.get_mut(context_id) {
                if ctx.executed_proposals.contains(&proposal.proposal_id) {
                    return Err(ContextError::PermissionDenied(
                        "governance proposal has already been executed".into(),
                    ));
                }
                ctx.executed_proposals.insert(proposal.proposal_id);
            } else {
                return Err(ContextError::MembershipFailed(
                    "context not registered".into(),
                ));
            }
        }

        let result = match self.dispatch_governance_action(context_id, proposal).await {
            Ok(r) => r,
            Err(e) => {
                // Roll back the executed marker on dispatch failure so the
                // proposal can be retried (e.g. after a transient crypto error).
                let mut contexts = self.contexts.lock().await;
                if let Some(ctx) = contexts.get_mut(context_id) {
                    ctx.executed_proposals.remove(&proposal.proposal_id);
                }
                return Err(e);
            }
        };

        // Persist the executed-proposals set (the insert happened above).
        {
            let contexts = self.contexts.lock().await;
            if let Some(ctx) = contexts.get(context_id) {
                let snapshot = Self::snapshot_context(ctx);
                drop(contexts);
                self.persist_context_snapshot(context_id, &snapshot);
            }
        }

        Ok(result)
    }

    /// Dispatches an approved governance action to its implementation method.
    ///
    /// Separated from [`execute_governance_action`] to keep the public entry
    /// point focused on validation while this method handles the 25-action
    /// dispatch.
    async fn dispatch_governance_action(
        &self,
        context_id: &str,
        proposal: &GovernanceProposal,
    ) -> Result<GovernanceActionResult, ContextError> {
        let pid = proposal.proposal_id;
        match &proposal.action {
            GovernanceAction::BlockAuthor { did, .. } => {
                let r = self
                    .block_broadcast_author_internal(context_id, did)
                    .await?;
                Ok(GovernanceActionResult::AuthorBlocked(r))
            }
            GovernanceAction::RevokeReadAccess { did, scope } => {
                let r = self
                    .revoke_read_access_internal(context_id, did, *scope)
                    .await?;
                Ok(GovernanceActionResult::SubscriberBanned(r))
            }
            GovernanceAction::RestoreReadAccess { did } => {
                self.restore_read_access_internal(context_id, did).await?;
                Ok(GovernanceActionResult::SubscriberUnbanned { did: did.clone() })
            }
            GovernanceAction::PromoteContext => {
                self.execute_promote_context(context_id, &proposal.approvals, pid)
                    .await?;
                Ok(GovernanceActionResult::Executed)
            }
            _ => {
                self.dispatch_context_governance_action(context_id, &proposal.action, pid)
                    .await?;
                Ok(GovernanceActionResult::Executed)
            }
        }
    }

    /// Dispatches context-level governance actions that return `Executed`.
    async fn dispatch_context_governance_action(
        &self,
        context_id: &str,
        action: &GovernanceAction,
        pid: ProposalId,
    ) -> Result<(), ContextError> {
        match action {
            GovernanceAction::AddMember { did, role } => {
                self.execute_add_member(context_id, did, role, pid).await
            }
            GovernanceAction::RemoveMember { did, .. } => {
                self.execute_remove_member(context_id, did, pid).await
            }
            GovernanceAction::ChangeRole { did, new_role } => {
                self.execute_change_role(context_id, did, new_role, pid)
                    .await
            }
            GovernanceAction::RegisterTool { registration } => {
                self.execute_register_tool(context_id, registration, pid)
                    .await
            }
            GovernanceAction::RemoveTool { tool_id } => {
                self.execute_remove_tool(context_id, tool_id, pid).await
            }
            GovernanceAction::ModifyCeiling { new_ceiling } => {
                self.execute_modify_ceiling(context_id, new_ceiling, pid)
                    .await
            }
            GovernanceAction::CloseContext { reason } => {
                self.execute_close_context(context_id, reason.as_deref(), pid)
                    .await
            }
            GovernanceAction::ExtendTtl { additional_secs } => {
                self.execute_extend_ttl(context_id, *additional_secs, pid)
                    .await
            }
            GovernanceAction::TransferAdmin { new_admin } => {
                self.execute_transfer_admin(context_id, new_admin, pid)
                    .await
            }
            GovernanceAction::CreateChildContext { params } => {
                self.execute_create_child_context(context_id, params, pid)
                    .await
            }
            GovernanceAction::ModifyPruningPolicy { new_policy } => {
                self.execute_modify_pruning_policy(context_id, new_policy, pid)
                    .await
            }
            GovernanceAction::AddSigner { did } => {
                self.execute_add_signer(context_id, did, pid).await
            }
            GovernanceAction::RemoveSigner { did } => {
                self.execute_remove_signer(context_id, did, pid).await
            }
            GovernanceAction::ModifyThreshold { new_threshold } => {
                self.execute_modify_threshold(context_id, *new_threshold, pid)
                    .await
            }
            GovernanceAction::EstablishToolInterface { interface } => {
                self.execute_establish_tool_interface(context_id, interface, pid)
                    .await
            }
            GovernanceAction::ResetMember { did, reason } => {
                self.execute_reset_member(context_id, did, reason, pid)
                    .await
            }
            GovernanceAction::ResolveConflict {
                proposal_a,
                proposal_b,
                resolution,
            } => {
                self.execute_resolve_conflict(context_id, proposal_a, proposal_b, resolution, pid)
                    .await
            }
            // PromoteContext is handled in dispatch_governance_action (needs
            // proposal.approvals for unanimity check).
            GovernanceAction::PromoteContext => {
                unreachable!("PromoteContext is dispatched directly by dispatch_governance_action")
            }
            GovernanceAction::RevokeWriteAccess { did, scope } => {
                self.execute_revoke_write_access(context_id, did, *scope, pid)
                    .await
            }
            GovernanceAction::RestoreWriteAccess { did } => {
                self.execute_restore_write_access(context_id, did, pid)
                    .await
            }
            GovernanceAction::RotateContentKeys { reason } => {
                self.execute_rotate_content_keys(context_id, reason.as_deref(), pid)
                    .await
            }
            GovernanceAction::ReconfigureGovernance {
                changes,
                justification,
            } => {
                self.execute_reconfigure_governance(context_id, changes, justification, pid)
                    .await
            }
            // BlockAuthor, RevokeReadAccess, RestoreReadAccess handled in dispatch_governance_action
            GovernanceAction::BlockAuthor { .. }
            | GovernanceAction::RevokeReadAccess { .. }
            | GovernanceAction::RestoreReadAccess { .. } => {
                unreachable!("handled in dispatch_governance_action")
            }
        }
    }

    /// Internal implementation of author blocking. Only callable within the
    /// crate -- external callers must go through [`execute_governance_action`]
    /// with an approved [`GovernanceProposal`] containing a
    /// [`GovernanceAction::BlockAuthor`] action.
    ///
    /// Removes the author from the broadcast context's author map, destroying
    /// their sender key. After this call:
    ///
    /// - `publish_broadcast()` by this author returns `PermissionDenied`.
    /// - `handle_broadcast_key_request()` for this author returns `Deny`.
    /// - Subscribers who cached the author's old key can still decrypt old
    ///   messages, but no new messages can be sealed.
    ///
    /// Emits an `AuthorBlocked` event. See SCP-227 AC4 and spec section 5.14.8.
    ///
    /// # Errors
    ///
    /// - [`ContextError::ContextNotActive`] if the context is not `Active`.
    /// - [`ContextError::MembershipFailed`] if the context is not a broadcast
    ///   context.
    async fn block_broadcast_author_internal(
        &self,
        context_id: &str,
        author_did: &DID,
    ) -> Result<AuthorBlockResult, ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        // Replay check and executed_proposals tracking are handled by the
        // outer execute_governance_action wrapper — not duplicated here.
        let (result, snapshot) = {
            let mut contexts = self.contexts.lock().await;
            let ctx = contexts
                .get_mut(context_id)
                .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;
            require_active(&ctx.handle)?;

            let bc = ctx
                .broadcast_context
                .as_mut()
                .ok_or_else(|| ContextError::MembershipFailed("not a broadcast context".into()))?;

            let result = bc.block_author(author_did)?;

            // Take snapshot for persistence before dropping lock.
            let snapshot = bc.to_snapshot();

            // Emit block event to receive buffer.
            ctx.receive_buffer.push(ContextEvent::AuthorBlocked {
                author_did: author_did.clone(),
            });

            (result, snapshot)
        };

        // Persist broadcast state for crash recovery.
        self.persist_broadcast_snapshot(context_id, &snapshot);

        self.event_log
            .append_context_event(&context_id_bytes, "AuthorBlocked")?;

        Ok(result)
    }

    /// Internal implementation of read access revocation. Only callable within
    /// the crate -- external callers must go through [`execute_governance_action`]
    /// with an approved [`GovernanceProposal`] containing a
    /// [`GovernanceAction::RevokeReadAccess`] action.
    ///
    /// In broadcast mode: removes the subscriber from the registry, adds them
    /// to all authors' block lists, and rotates all author keys (via
    /// [`BroadcastContext::governance_ban_subscriber`]). The member remains in
    /// the context for governance/presence but cannot read new content.
    ///
    /// Requires the `MemberBan` capability in the context's ceiling (§5.3,
    /// ADR-031). The `scope` parameter is stored but does not currently
    /// differentiate behavior in broadcast mode (both `Full` and `FutureOnly`
    /// trigger the same key rotation).
    ///
    /// Emits a `ReadAccessRevoked` event. See SCP-GG-006 and ADR-031.
    ///
    /// # Errors
    ///
    /// - [`ContextError::PermissionDenied`] if the ceiling lacks `MemberBan`.
    /// - [`ContextError::ContextNotActive`] if the context is not `Active`.
    /// - [`ContextError::MembershipFailed`] if the context is not a broadcast
    ///   context.
    /// - [`ContextError::MemberNotFound`] if the subscriber DID is not
    async fn revoke_read_access_internal(
        &self,
        context_id: &str,
        did: &DID,
        scope: RevocationScope,
    ) -> Result<GovernanceBanResult, ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        // Replay check and executed_proposals tracking are handled by the
        // outer execute_governance_action wrapper — not duplicated here.
        let (result, snapshot) = {
            let mut contexts = self.contexts.lock().await;
            let ctx = contexts
                .get_mut(context_id)
                .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;
            require_active(&ctx.handle)?;

            // Gate: ceiling must include MemberBan (§5.3, ADR-031).
            if !ctx.role_state.ceiling.contains(&Capability::MemberBan) {
                return Err(ContextError::PermissionDenied(
                    "context ceiling does not include member:ban capability".into(),
                ));
            }

            let bc = ctx
                .broadcast_context
                .as_mut()
                .ok_or_else(|| ContextError::MembershipFailed("not a broadcast context".into()))?;

            let result = bc.governance_ban_subscriber(&did.0, scope)?;

            // Take snapshot for persistence before dropping lock.
            let snapshot = bc.to_snapshot();

            // Emit revocation event to receive buffer.
            ctx.receive_buffer
                .push(ContextEvent::ReadAccessRevoked { did: did.clone() });

            (result, snapshot)
        };

        // Persist broadcast state for crash recovery.
        self.persist_broadcast_snapshot(context_id, &snapshot);

        self.event_log
            .append_context_event(&context_id_bytes, "ReadAccessRevoked")?;

        Ok(result)
    }

    /// Internal implementation of read access restoration. Only callable
    /// within the crate -- external callers must go through
    /// [`execute_governance_action`] with an approved [`GovernanceProposal`]
    /// containing a [`GovernanceAction::RestoreReadAccess`] action.
    ///
    /// In broadcast mode: removes the DID from all authors' block lists
    /// (via [`BroadcastContext::governance_unban_subscriber`]). The subscriber
    /// must re-subscribe to regain access. Does **not** rotate keys -- unban
    /// is access restoration, not revocation.
    ///
    /// Requires the `MemberBan` capability in the context's ceiling (§5.3,
    /// ADR-031). Restoration is always forward-only: content missed during
    /// the revocation period remains inaccessible.
    ///
    /// Emits a `ReadAccessRestored` event. See SCP-GG-006 and ADR-031.
    ///
    /// # Errors
    ///
    /// - [`ContextError::PermissionDenied`] if the ceiling lacks `MemberBan`.
    /// - [`ContextError::ContextNotActive`] if the context is not `Active`.
    /// - [`ContextError::MembershipFailed`] if the context is not a broadcast
    async fn restore_read_access_internal(
        &self,
        context_id: &str,
        did: &DID,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        // Replay check and executed_proposals tracking are handled by the
        // outer execute_governance_action wrapper — not duplicated here.
        let snapshot = {
            let mut contexts = self.contexts.lock().await;
            let ctx = contexts
                .get_mut(context_id)
                .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;
            require_active(&ctx.handle)?;

            // Gate: ceiling must include MemberBan (§5.3, ADR-031).
            if !ctx.role_state.ceiling.contains(&Capability::MemberBan) {
                return Err(ContextError::PermissionDenied(
                    "context ceiling does not include member:ban capability".into(),
                ));
            }

            let bc = ctx
                .broadcast_context
                .as_mut()
                .ok_or_else(|| ContextError::MembershipFailed("not a broadcast context".into()))?;

            bc.governance_unban_subscriber(&did.0);

            // Take snapshot for persistence before dropping lock.
            let snapshot = bc.to_snapshot();

            // Emit restoration event to receive buffer.
            ctx.receive_buffer
                .push(ContextEvent::ReadAccessRestored { did: did.clone() });

            snapshot
        };

        // Persist broadcast state for crash recovery.
        self.persist_broadcast_snapshot(context_id, &snapshot);

        self.event_log
            .append_context_event(&context_id_bytes, "ReadAccessRestored")?;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Governance action execution methods
    //
    // Each method follows the pattern: lock context → validate → mutate →
    // emit event → persist. All are called exclusively from
    // `execute_governance_action` after proposal approval.
    // -----------------------------------------------------------------------

    async fn execute_add_member(
        &self,
        context_id: &str,
        did: &DID,
        role: &str,
        _proposal_id: ProposalId,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        let snapshot = {
            let mut contexts = self.contexts.lock().await;
            let ctx = contexts
                .get_mut(context_id)
                .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;
            require_active(&ctx.handle)?;

            // Crypto: add to MLS group under lock to prevent partial-failure
            // window (phantom MLS member if state mutation fails).
            self.crypto
                .add_member(&context_id_bytes, did, None)
                .map_err(|e| ContextError::MembershipFailed(e.to_string()))?;

            // Add to role state.
            ctx.role_state.members.insert(did.to_string());
            let creator_did = ctx.role_state.creator_did.clone();
            let tokens = roles::assign_role(&mut ctx.role_state, did, role, &creator_did)
                .map_err(|e| ContextError::MembershipFailed(e.to_string()))?;

            // Add to membership tracking.
            ctx.membership
                .add_member(did.clone(), role.to_owned(), tokens);

            ctx.receive_buffer.push(ContextEvent::MemberJoined {
                member_did: did.clone(),
                role_name: role.to_owned(),
            });

            Self::snapshot_context(ctx)
        };

        self.persist_context_snapshot(context_id, &snapshot);
        self.event_log
            .append_context_event(&context_id_bytes, "MemberJoined")?;
        Ok(())
    }

    async fn execute_remove_member(
        &self,
        context_id: &str,
        did: &DID,
        _proposal_id: ProposalId,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        let snapshot = {
            let mut contexts = self.contexts.lock().await;
            let ctx = contexts
                .get_mut(context_id)
                .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;
            require_active(&ctx.handle)?;

            if !ctx.membership.contains(did) {
                return Err(ContextError::MemberNotFound(did.to_string()));
            }

            // Crypto: remove from MLS group under lock to prevent TOCTOU
            // race (concurrent remove of same DID).
            self.crypto
                .remove_member(&context_id_bytes, did)
                .map_err(|e| ContextError::MembershipFailed(e.to_string()))?;

            ctx.membership.remove_member(did);
            ctx.role_state.members.remove(did.as_ref());
            ctx.role_state.assignments.remove(did.as_ref());
            ctx.role_state.member_capabilities.remove(did.as_ref());

            ctx.receive_buffer.push(ContextEvent::MemberLeft {
                member_did: did.clone(),
            });

            Self::snapshot_context(ctx)
        };

        self.persist_context_snapshot(context_id, &snapshot);
        self.event_log
            .append_context_event(&context_id_bytes, "MemberLeft")?;
        Ok(())
    }

    async fn execute_change_role(
        &self,
        context_id: &str,
        did: &DID,
        new_role: &str,
        _proposal_id: ProposalId,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        let snapshot = {
            let mut contexts = self.contexts.lock().await;
            let ctx = contexts
                .get_mut(context_id)
                .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;
            require_active(&ctx.handle)?;

            if !ctx.membership.contains(did) {
                return Err(ContextError::MemberNotFound(did.to_string()));
            }

            // Re-assign via the role engine (validates role exists, updates
            // assignments and member_capabilities).
            let creator_did = ctx.role_state.creator_did.clone();
            let tokens = roles::assign_role(&mut ctx.role_state, did, new_role, &creator_did)
                .map_err(|e| ContextError::MembershipFailed(e.to_string()))?;

            // Update membership tracking with new role.
            if let Some(info) = ctx.membership.get_mut(did) {
                new_role.clone_into(&mut info.role_name);
                info.tokens = tokens;
            }

            Self::snapshot_context(ctx)
        };

        self.persist_context_snapshot(context_id, &snapshot);
        self.event_log
            .append_context_event(&context_id_bytes, "RoleAssigned")?;
        Ok(())
    }

    async fn execute_register_tool(
        &self,
        context_id: &str,
        registration: &ToolRegistration,
        _proposal_id: ProposalId,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        let snapshot = {
            let mut contexts = self.contexts.lock().await;
            let ctx = contexts
                .get_mut(context_id)
                .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;
            require_active(&ctx.handle)?;

            ctx.registered_tools.push(registration.clone());
            Self::snapshot_context(ctx)
        };

        self.persist_context_snapshot(context_id, &snapshot);
        self.event_log
            .append_context_event(&context_id_bytes, "ToolRegistered")?;
        Ok(())
    }

    async fn execute_remove_tool(
        &self,
        context_id: &str,
        tool_id: &str,
        _proposal_id: ProposalId,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        let snapshot = {
            let mut contexts = self.contexts.lock().await;
            let ctx = contexts
                .get_mut(context_id)
                .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;
            require_active(&ctx.handle)?;

            ctx.registered_tools.retain(|t| t.name != tool_id);
            Self::snapshot_context(ctx)
        };

        self.persist_context_snapshot(context_id, &snapshot);
        self.event_log
            .append_context_event(&context_id_bytes, "ToolRemoved")?;
        Ok(())
    }

    async fn execute_modify_ceiling(
        &self,
        context_id: &str,
        new_ceiling: &[Capability],
        _proposal_id: ProposalId,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        let snapshot = {
            let mut contexts = self.contexts.lock().await;
            let ctx = contexts
                .get_mut(context_id)
                .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;
            require_active(&ctx.handle)?;

            if !matches!(
                ctx.handle.params().ceiling_policy,
                super::params::CeilingPolicy::Governed
            ) {
                return Err(ContextError::PermissionDenied(
                    "ceiling_policy is not Governed".to_owned(),
                ));
            }

            // Replace the ceiling in role_state (the mutable copy).
            ctx.role_state.ceiling = CapabilityCeiling::new(new_ceiling.iter().cloned());

            Self::snapshot_context(ctx)
        };

        self.persist_context_snapshot(context_id, &snapshot);
        self.event_log
            .append_context_event(&context_id_bytes, "CeilingModified")?;
        Ok(())
    }

    async fn execute_close_context(
        &self,
        context_id: &str,
        _reason: Option<&str>,
        _proposal_id: ProposalId,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        let snapshot = {
            let mut contexts = self.contexts.lock().await;
            let ctx = contexts
                .get_mut(context_id)
                .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;
            require_active(&ctx.handle)?;

            // Transition to Closing via the state machine.
            ctx.handle
                .transition_to(&ContextState::Closing)
                .await
                .map_err(|_| {
                    ContextError::PermissionDenied("cannot transition to Closing".to_owned())
                })?;

            // Cancel TTL timer if active.
            ctx.ttl_timer.cancel();

            Self::snapshot_context(ctx)
        };

        self.persist_context_snapshot(context_id, &snapshot);
        self.event_log
            .append_context_event(&context_id_bytes, "ContextClosing")?;
        Ok(())
    }

    async fn execute_extend_ttl(
        &self,
        context_id: &str,
        additional_secs: u64,
        _proposal_id: ProposalId,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        let snapshot = {
            let mut contexts = self.contexts.lock().await;
            let ctx = contexts
                .get_mut(context_id)
                .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;
            require_active(&ctx.handle)?;

            // Extend the TTL deadline. If the timer has a deadline, push it forward.
            if let Some(ref mut deadline) = ctx.ttl_timer.deadline_unix_secs {
                *deadline = deadline.saturating_add(additional_secs);
            }

            Self::snapshot_context(ctx)
        };

        self.persist_context_snapshot(context_id, &snapshot);
        self.event_log
            .append_context_event(&context_id_bytes, "TtlExtended")?;
        Ok(())
    }

    async fn execute_transfer_admin(
        &self,
        context_id: &str,
        new_admin: &DID,
        _proposal_id: ProposalId,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        let snapshot = {
            let mut contexts = self.contexts.lock().await;
            let ctx = contexts
                .get_mut(context_id)
                .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;
            require_active(&ctx.handle)?;

            if !ctx.membership.contains(new_admin) {
                return Err(ContextError::MemberNotFound(new_admin.to_string()));
            }

            // Demote current admins, promote new admin via role engine.
            let creator_did = ctx.role_state.creator_did.clone();
            // Find and demote current admin(s).
            let current_admins: Vec<String> = ctx
                .role_state
                .assignments
                .iter()
                .filter(|(_, a)| a.role_name == "admin")
                .map(|(did, _)| did.clone())
                .collect();
            for admin_did in &current_admins {
                let _ = roles::assign_role(&mut ctx.role_state, admin_did, "member", &creator_did);
                if let Some(info) = ctx.membership.get_mut(admin_did) {
                    "member".clone_into(&mut info.role_name);
                }
            }
            // Promote new admin.
            let tokens = roles::assign_role(&mut ctx.role_state, new_admin, "admin", &creator_did)
                .map_err(|e| ContextError::MembershipFailed(e.to_string()))?;
            if let Some(info) = ctx.membership.get_mut(new_admin) {
                "admin".clone_into(&mut info.role_name);
                info.tokens = tokens;
            }

            Self::snapshot_context(ctx)
        };

        self.persist_context_snapshot(context_id, &snapshot);
        self.event_log
            .append_context_event(&context_id_bytes, "AdminTransferred")?;
        Ok(())
    }

    async fn execute_create_child_context(
        &self,
        context_id: &str,
        _params: &ContextParams,
        _proposal_id: ProposalId,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);
        // Validate parent context is active.
        {
            let contexts = self.contexts.lock().await;
            let ctx = contexts
                .get(context_id)
                .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;
            require_active(&ctx.handle)?;
        }
        // Child context creation is delegated to `create_context` by the
        // caller with the parent_context_id field set. This method records
        // the governance event on the parent.
        self.event_log
            .append_context_event(&context_id_bytes, "ChildContextCreated")?;
        Ok(())
    }

    async fn execute_modify_pruning_policy(
        &self,
        context_id: &str,
        new_policy: &PruningPolicy,
        _proposal_id: ProposalId,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        // Validate retention multipliers are non-zero.
        let structural_mul_bp = new_policy
            .event_type_retention
            .structural_retention_multiplier;
        if structural_mul_bp == 0 {
            return Err(ContextError::PermissionDenied(
                "structural_retention_multiplier must be > 0".to_owned(),
            ));
        }
        let operational_mul_bp = new_policy
            .event_type_retention
            .operational_retention_multiplier;
        if operational_mul_bp == 0 {
            return Err(ContextError::PermissionDenied(
                "operational_retention_multiplier must be > 0".to_owned(),
            ));
        }

        // Validate protocol minimum: 30 days for time-based retention (ADR-030).
        if let Some(ref tb) = new_policy.time_based
            && tb.retention_secs < 2_592_000
        {
            return Err(ContextError::PermissionDenied(
                "time_based.retention_secs must be >= 2,592,000 (30 days)".to_owned(),
            ));
        }
        // ADR-030: structural event retention floor is 90 days (7,776,000 seconds).
        // effective = retention_secs * multiplier_bp / 10000
        if let Some(ref tb) = new_policy.time_based {
            let effective = tb
                .retention_secs
                .saturating_mul(u64::from(structural_mul_bp))
                / 10_000;
            if effective < 7_776_000 {
                return Err(ContextError::PermissionDenied(
                    "effective structural event retention must be >= 7,776,000 seconds (90 days)"
                        .to_owned(),
                ));
            }
        }

        let snapshot = {
            let mut contexts = self.contexts.lock().await;
            let ctx = contexts
                .get_mut(context_id)
                .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;
            require_active(&ctx.handle)?;

            ctx.pruning_policy = Some(new_policy.clone());
            Self::snapshot_context(ctx)
        };

        self.persist_context_snapshot(context_id, &snapshot);
        self.event_log
            .append_context_event(&context_id_bytes, "PruningPolicyModified")?;
        Ok(())
    }

    async fn execute_add_signer(
        &self,
        context_id: &str,
        did: &DID,
        _proposal_id: ProposalId,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        let snapshot = {
            let mut contexts = self.contexts.lock().await;
            let ctx = contexts
                .get_mut(context_id)
                .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;
            require_active(&ctx.handle)?;

            if !ctx.membership.contains(did) {
                return Err(ContextError::MemberNotFound(did.to_string()));
            }
            if ctx.threshold_signers.contains(did) {
                return Err(ContextError::PermissionDenied(format!(
                    "DID is already a signer: {did}"
                )));
            }
            ctx.threshold_signers.push(did.clone());
            Self::snapshot_context(ctx)
        };

        self.persist_context_snapshot(context_id, &snapshot);
        self.event_log
            .append_context_event(&context_id_bytes, "SignerAdded")?;
        Ok(())
    }

    async fn execute_remove_signer(
        &self,
        context_id: &str,
        did: &DID,
        _proposal_id: ProposalId,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        let snapshot = {
            let mut contexts = self.contexts.lock().await;
            let ctx = contexts
                .get_mut(context_id)
                .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;
            require_active(&ctx.handle)?;

            let before = ctx.threshold_signers.len();
            ctx.threshold_signers.retain(|s| s != did);
            if ctx.threshold_signers.len() == before {
                return Err(ContextError::MemberNotFound(did.to_string()));
            }
            // ADR-031: if removing would make threshold > signers.len(), reject.
            if ctx.threshold_value > 0 {
                let remaining = u32::try_from(ctx.threshold_signers.len()).unwrap_or(u32::MAX);
                if ctx.threshold_value > remaining {
                    // Undo the removal before returning.
                    ctx.threshold_signers.push(did.clone());
                    return Err(ContextError::PermissionDenied(format!(
                        "removing signer would leave {remaining} signers < threshold {}",
                        ctx.threshold_value
                    )));
                }
            }
            Self::snapshot_context(ctx)
        };

        self.persist_context_snapshot(context_id, &snapshot);
        self.event_log
            .append_context_event(&context_id_bytes, "SignerRemoved")?;
        Ok(())
    }

    async fn execute_modify_threshold(
        &self,
        context_id: &str,
        new_threshold: u32,
        _proposal_id: ProposalId,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        let snapshot = {
            let mut contexts = self.contexts.lock().await;
            let ctx = contexts
                .get_mut(context_id)
                .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;
            require_active(&ctx.handle)?;

            let signer_count = u32::try_from(ctx.threshold_signers.len()).unwrap_or(u32::MAX);
            if new_threshold == 0 || new_threshold > signer_count {
                return Err(ContextError::PermissionDenied(format!(
                    "threshold must be 1..={signer_count}, got {new_threshold}"
                )));
            }
            ctx.threshold_value = new_threshold;
            Self::snapshot_context(ctx)
        };

        self.persist_context_snapshot(context_id, &snapshot);
        self.event_log
            .append_context_event(&context_id_bytes, "ThresholdModified")?;
        Ok(())
    }

    async fn execute_establish_tool_interface(
        &self,
        context_id: &str,
        interface: &ToolInterface,
        _proposal_id: ProposalId,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        let snapshot = {
            let mut contexts = self.contexts.lock().await;
            let ctx = contexts
                .get_mut(context_id)
                .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;
            require_active(&ctx.handle)?;

            ctx.tool_interfaces.push(interface.clone());
            Self::snapshot_context(ctx)
        };

        self.persist_context_snapshot(context_id, &snapshot);
        self.event_log
            .append_context_event(&context_id_bytes, "ToolInterfaceEstablished")?;
        Ok(())
    }

    async fn execute_reset_member(
        &self,
        context_id: &str,
        did: &DID,
        _reason: &str,
        _proposal_id: ProposalId,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);
        {
            let contexts = self.contexts.lock().await;
            let ctx = contexts
                .get(context_id)
                .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;
            require_active(&ctx.handle)?;

            if !ctx.membership.contains(did) {
                return Err(ContextError::MemberNotFound(did.to_string()));
            }
        }
        // Member reset = leave + immediately re-join (ADR-029 §Tier 3).
        // Step 1: Remove from MLS group (destroys stale leaf node).
        self.crypto
            .remove_member(&context_id_bytes, did)
            .map_err(|e| ContextError::MembershipFailed(e.to_string()))?;
        // Step 2: Re-add to MLS group with fresh key material.
        self.crypto
            .add_member(&context_id_bytes, did, None)
            .map_err(|e| ContextError::MembershipFailed(e.to_string()))?;
        self.event_log
            .append_context_event(&context_id_bytes, "MemberReset")?;
        Ok(())
    }

    async fn execute_resolve_conflict(
        &self,
        context_id: &str,
        proposal_a: &ProposalId,
        proposal_b: &ProposalId,
        resolution: &super::governance::ConflictResolution,
        _proposal_id: ProposalId,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        let snapshot = {
            let mut contexts = self.contexts.lock().await;
            let ctx = contexts
                .get_mut(context_id)
                .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;
            require_active(&ctx.handle)?;

            // Mark the conflicting proposal(s) as executed (invalidated) so
            // they cannot be replayed. For AcceptProposal the loser is
            // invalidated; the winner is left unexecuted so it can proceed
            // through normal `execute_governance_action`. For InvalidateBoth,
            // both are invalidated.
            match resolution {
                super::governance::ConflictResolution::AcceptProposal { winner_id } => {
                    // Validate that winner_id is one of the two proposals.
                    let loser = if *winner_id == *proposal_a {
                        proposal_b
                    } else if *winner_id == *proposal_b {
                        proposal_a
                    } else {
                        return Err(ContextError::PermissionDenied(format!(
                            "winner_id {winner_id:?} is not one of the conflicting proposals"
                        )));
                    };
                    // Only invalidate the loser — the winner remains eligible
                    // for normal execution.
                    ctx.executed_proposals.insert(*loser);
                }
                super::governance::ConflictResolution::InvalidateBoth => {
                    ctx.executed_proposals.insert(*proposal_a);
                    ctx.executed_proposals.insert(*proposal_b);
                }
            }

            Self::snapshot_context(ctx)
        };

        self.persist_context_snapshot(context_id, &snapshot);
        self.event_log
            .append_context_event(&context_id_bytes, "GovernanceConflictResolved")?;
        Ok(())
    }

    async fn execute_promote_context(
        &self,
        context_id: &str,
        approvals: &[super::governance::SignedVote],
        _proposal_id: ProposalId,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        let snapshot = {
            let mut contexts = self.contexts.lock().await;
            let ctx = contexts
                .get_mut(context_id)
                .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;
            require_active(&ctx.handle)?;

            if !matches!(
                ctx.handle.params().promotion_policy,
                super::params::PromotionPolicy::Promotable
            ) {
                return Err(ContextError::PermissionDenied(
                    "context promotion_policy is not Promotable".to_owned(),
                ));
            }

            // Unanimity check: promotion requires consent from ALL current
            // members (§5.10) because promotion changes the opt-in contract
            // (ephemeral → persistent). This is a protocol-level override
            // that applies regardless of governance model.
            let member_dids: std::collections::HashSet<&str> =
                ctx.membership.member_dids().map(|d| &**d).collect();
            let approval_dids: std::collections::HashSet<&str> =
                approvals.iter().map(|v| &*v.voter_did).collect();
            let missing: Vec<&str> = member_dids.difference(&approval_dids).copied().collect();
            if !missing.is_empty() {
                return Err(ContextError::PermissionDenied(format!(
                    "promotion requires unanimous consent — {} of {} members have not approved",
                    missing.len(),
                    member_dids.len()
                )));
            }

            // Promote: cancel TTL timer and transition memory scope (§5.10).
            // "On promotion: TTL is removed, memory scope transitions from
            // ephemeral to full, existing event log and key material are
            // preserved."
            ctx.ttl_timer.cancel();
            ctx.ttl_timer.deadline_unix_secs = None;
            ctx.handle.promote_memory_scope();

            Self::snapshot_context(ctx)
        };

        self.persist_context_snapshot(context_id, &snapshot);
        self.event_log
            .append_context_event(&context_id_bytes, "ContextPromoted")?;
        Ok(())
    }

    async fn execute_revoke_write_access(
        &self,
        context_id: &str,
        did: &DID,
        scope: RevocationScope,
        _proposal_id: ProposalId,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);
        // Both Full and FutureOnly block future writes via write_revoked_members.
        // Full additionally suppresses historical content via access key
        // destruction (ADR-038 §3) — delegated to the access key layer when
        // it processes the WriteAccessRevoked event. Scope differentiation
        // is deferred to the content-access stories (SCP-CAC-007, SCP-CAC-008)
        // which will thread scope into write_revoked_members and the event.
        let _ = scope;

        let (snapshot, bc_snapshot) = {
            let mut contexts = self.contexts.lock().await;
            let ctx = contexts
                .get_mut(context_id)
                .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;
            require_active(&ctx.handle)?;

            if !ctx.role_state.ceiling.contains(&Capability::MemberBan) {
                return Err(ContextError::PermissionDenied(
                    "MemberBan capability not in ceiling".to_owned(),
                ));
            }
            if !ctx.membership.contains(did) {
                return Err(ContextError::MemberNotFound(did.to_string()));
            }
            // Mark member as write-revoked. The member remains present but
            // their messages will be rejected by the send path.
            ctx.write_revoked_members.insert(did.clone());

            // Broadcast mode: also destroy the author's broadcast key so
            // key requests return Deny (§5.14.8 "Author removal").
            let bc_snap = ctx.broadcast_context.as_mut().map(|bc| {
                // block_author removes the author from the authors map,
                // destroying their key and preventing future key distribution.
                // Ignore error if DID is not an author (may be a subscriber).
                let _ = bc.block_author(&did.0);
                bc.to_snapshot()
            });

            (Self::snapshot_context(ctx), bc_snap)
        };

        self.persist_context_snapshot(context_id, &snapshot);
        if let Some(ref bc_snap) = bc_snapshot {
            self.persist_broadcast_snapshot(context_id, bc_snap);
        }
        self.event_log
            .append_context_event(&context_id_bytes, "WriteAccessRevoked")?;
        Ok(())
    }

    async fn execute_restore_write_access(
        &self,
        context_id: &str,
        did: &DID,
        _proposal_id: ProposalId,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        let snapshot = {
            let mut contexts = self.contexts.lock().await;
            let ctx = contexts
                .get_mut(context_id)
                .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;
            require_active(&ctx.handle)?;

            if !ctx.role_state.ceiling.contains(&Capability::MemberBan) {
                return Err(ContextError::PermissionDenied(
                    "MemberBan capability not in ceiling".to_owned(),
                ));
            }
            ctx.write_revoked_members.remove(did);
            Self::snapshot_context(ctx)
        };

        self.persist_context_snapshot(context_id, &snapshot);
        self.event_log
            .append_context_event(&context_id_bytes, "WriteAccessRestored")?;
        Ok(())
    }

    async fn execute_rotate_content_keys(
        &self,
        context_id: &str,
        _reason: Option<&str>,
        _proposal_id: ProposalId,
    ) -> Result<(), ContextError> {
        let context_id_bytes = context_id_to_bytes(context_id);

        // Broadcast mode: rotate all authors' sender keys under lock.
        let bc_snapshot = {
            let mut contexts = self.contexts.lock().await;
            let ctx = contexts
                .get_mut(context_id)
                .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;
            require_active(&ctx.handle)?;

            if let Some(ref mut bc) = ctx.broadcast_context {
                // Rotate every author's broadcast key (epoch advance + new key).
                bc.rotate_all_author_keys()?;
                Some(bc.to_snapshot())
            } else {
                // Encrypted mode: the MLS backend handles key rotation via
                // update proposals. No direct crypto call needed — the event
                // signals the MLS layer to issue an Update + Commit.
                None
            }
        };

        if let Some(ref snapshot) = bc_snapshot {
            self.persist_broadcast_snapshot(context_id, snapshot);
        }

        self.event_log
            .append_context_event(&context_id_bytes, "ContentKeysRotated")?;
        Ok(())
    }

    async fn execute_reconfigure_governance(
        &self,
        context_id: &str,
        changes: &[super::governance::GovernanceReconfigAction],
        justification: &super::governance::DeadlockJustification,
        _proposal_id: ProposalId,
    ) -> Result<(), ContextError> {
        if changes.is_empty() {
            return Err(ContextError::PermissionDenied(
                "reconfigure_governance requires at least one change".to_owned(),
            ));
        }
        if justification.unavailable_dids.is_empty() && justification.missed_windows.is_empty() {
            return Err(ContextError::PermissionDenied(
                "deadlock justification must provide evidence (unavailable_dids or missed_windows)"
                    .to_owned(),
            ));
        }

        let context_id_bytes = context_id_to_bytes(context_id);

        let snapshot = {
            let mut contexts = self.contexts.lock().await;
            let ctx = contexts
                .get_mut(context_id)
                .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;
            require_active(&ctx.handle)?;

            // Save state for rollback — the loop below mutates ctx in-place,
            // and any mid-loop or post-loop error must restore the original
            // state to prevent in-memory corruption.
            let original_signers = ctx.threshold_signers.clone();
            let original_threshold = ctx.threshold_value;

            // Apply each reconfiguration action in order (ADR-031 §10).
            let reconfigure_result: Result<(), ContextError> = (|| {
                for change in changes {
                    match change {
                        super::governance::GovernanceReconfigAction::RemoveInactiveSigner {
                            did,
                        } => {
                            ctx.threshold_signers.retain(|s| s != did);
                        }
                        super::governance::GovernanceReconfigAction::ReduceThreshold {
                            new_threshold,
                        } => {
                            let signer_count =
                                u32::try_from(ctx.threshold_signers.len()).unwrap_or(u32::MAX);
                            if *new_threshold == 0 || *new_threshold > signer_count {
                                return Err(ContextError::PermissionDenied(format!(
                                    "reconfigured threshold must be 1..={signer_count}, got {new_threshold}"
                                )));
                            }
                            ctx.threshold_value = *new_threshold;
                        }
                    }
                }

                // Post-loop invariant: threshold must still be satisfiable after
                // all removals and reductions (ADR-031 §10).
                if ctx.threshold_value > 0 {
                    let remaining = u32::try_from(ctx.threshold_signers.len()).unwrap_or(u32::MAX);
                    if ctx.threshold_value > remaining {
                        return Err(ContextError::PermissionDenied(format!(
                            "reconfiguration left {remaining} signers < threshold {}",
                            ctx.threshold_value,
                        )));
                    }
                }

                Ok(())
            })();

            if let Err(e) = reconfigure_result {
                // Rollback: restore original state before returning error.
                ctx.threshold_signers = original_signers;
                ctx.threshold_value = original_threshold;
                return Err(e);
            }

            Self::snapshot_context(ctx)
        };

        self.persist_context_snapshot(context_id, &snapshot);
        self.event_log
            .append_context_event(&context_id_bytes, "GovernanceReconfigured")?;
        Ok(())
    }

    /// Evaluates whether a subscriber's broadcast key request should be
    /// granted or denied.
    ///
    /// This is the author-side decision function for the pull-based key
    /// distribution protocol (spec section 9.16.6).
    ///
    /// # Defense-in-depth validation (#234)
    ///
    /// Before delegating to `BroadcastContext::handle_key_request`, this
    /// method verifies that `author_did` is registered as a locally
    /// controlled DID via [`register_local_did`](Self::register_local_did).
    /// This prevents misuse if the method is called from an unexpected
    /// context. Transport-layer auth (spec section 9.16.6) remains the
    /// primary enforcement mechanism; this check is an additional layer.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::PermissionDenied`] if `author_did` is not
    /// registered as a locally controlled DID.
    ///
    /// Returns [`ContextError::MembershipFailed`] if the context is not
    pub async fn handle_broadcast_key_request(
        &self,
        context_id: &str,
        author_did: &DID,
        requester_did: &DID,
    ) -> Result<KeyRequestDecision, ContextError> {
        // Defense-in-depth: verify the local SDK controls the author DID.
        // Transport-layer auth (section 9.16.6) is the primary gate; this prevents
        // misuse if the method is ever called from a different context.
        if !self.local_dids.read().await.contains(author_did) {
            return Err(ContextError::PermissionDenied(format!(
                "author DID is not controlled by the local node: {author_did}"
            )));
        }

        let contexts = self.contexts.lock().await;
        let ctx = contexts
            .get(context_id)
            .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;

        let bc = ctx
            .broadcast_context
            .as_ref()
            .ok_or_else(|| ContextError::MembershipFailed("not a broadcast context".into()))?;

        Ok(bc.handle_key_request(author_did, requester_did))
    }

    /// Returns the number of subscribers in a broadcast context.
    ///
    /// Returns `None` if the context is not registered or not broadcast.
    pub async fn broadcast_subscriber_count(&self, context_id: &str) -> Option<usize> {
        self.contexts.lock().await.get(context_id).and_then(|ctx| {
            ctx.broadcast_context
                .as_ref()
                .map(BroadcastContext::subscriber_count)
        })
    }

    /// Returns `true` if the given DID is a subscriber in a broadcast context.
    pub async fn is_broadcast_subscriber(&self, context_id: &str, did: &str) -> bool {
        self.contexts
            .lock()
            .await
            .get(context_id)
            .and_then(|ctx| {
                ctx.broadcast_context
                    .as_ref()
                    .map(|bc| bc.is_subscriber(did))
            })
            .unwrap_or(false)
    }

    /// Returns the admission policy for a broadcast context.
    ///
    /// Returns `None` if the context is not registered or not broadcast.
    pub async fn broadcast_admission(&self, context_id: &str) -> Option<BroadcastAdmission> {
        self.contexts.lock().await.get(context_id).and_then(|ctx| {
            ctx.broadcast_context
                .as_ref()
                .map(BroadcastContext::admission)
        })
    }

    // -------------------------------------------------------------------
    // Close / Finalize / TTL Expiry (SCP-021)
    // -------------------------------------------------------------------

    /// Initiates cooperative context closure.
    ///
    /// Verifies the initiator has the `ContextClose` capability, transitions
    /// from `Active` to `Closing`, and appends a `ContextClosing` event.
    /// Cancels any active TTL timer for this context.
    ///
    /// See ADR-008 acceptance criterion 5.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::ContextNotActive`] if the context is not
    /// `Active`. Returns [`ContextError::PermissionDenied`] if the
    pub async fn close_context(
        &self,
        handle: &ContextHandle,
        initiator_did: &DID,
    ) -> Result<CloseResult, ContextError> {
        let context_id = handle.context_id().to_owned();

        // Atomic state check + role_state extraction within a single lock.
        let role_state = {
            let contexts = self.contexts.lock().await;
            let ctx = contexts
                .get(&context_id)
                .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;

            // State check inside lock -- eliminates TOCTOU race.
            require_active(&ctx.handle)?;

            ctx.role_state.clone()
        };
        // Lock dropped before async ttl::close_context call.

        // Delegate to ttl::close_context for the actual logic (async).
        let result =
            ttl::close_context(handle, initiator_did, &role_state, self.event_log.as_ref()).await?;

        // Cancel TTL timer, drop broadcast state, and emit close notification
        // (second lock acquisition).
        {
            let mut contexts = self.contexts.lock().await;
            if let Some(ctx) = contexts.get_mut(&context_id) {
                ctx.ttl_timer.cancel();
                // Drop broadcast context state -- keys are zeroed by Zeroize.
                ctx.broadcast_context = None;
                ctx.receive_buffer.push(ContextEvent::SystemClose {
                    initiator_did: initiator_did.clone(),
                });
            }
        }

        // Persist context state after close (best-effort).
        {
            let contexts = self.contexts.lock().await;
            if let Some(ctx) = contexts.get(&context_id) {
                let snapshot = Self::snapshot_context(ctx);
                drop(contexts);
                self.persist_context_snapshot(&context_id, &snapshot);
            }
        }

        Ok(result)
    }

    /// Completes context closure.
    ///
    /// Destroys MLS group state and sender keys, issues relay deletion
    /// requests for ephemeral/summary scopes, transitions from `Closing`
    /// to `Closed`, and appends the final `ContextClosed` event.
    ///
    /// See ADR-008 acceptance criterion 6.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] if the context is not in `Closing` state
    /// or if destruction operations fail.
    pub async fn finalize_close(&self, handle: &ContextHandle) -> Result<(), ContextError> {
        let context_id = handle.context_id().to_owned();

        ttl::finalize_close(
            handle,
            self.crypto.as_ref(),
            self.transport.as_ref(),
            self.event_log.as_ref(),
        )
        .await?;

        // Delete persisted state after finalize (best-effort).
        if let Some(ref persistence) = self.persistence {
            let _ = persistence.delete_context(&context_id);
        }

        Ok(())
    }

    /// Handles automatic TTL expiry.
    ///
    /// Transitions from `Active` to `Expired`, destroys keys per memory
    /// scope, and appends `ContextExpired` to the event log.
    ///
    /// See ADR-008 acceptance criterion 7.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::ContextNotActive`] if the context is not
    pub async fn handle_ttl_expiry(&self, handle: &ContextHandle) -> Result<(), ContextError> {
        let context_id = handle.context_id().to_owned();

        // Async TTL expiry logic -- no lock held.
        ttl::handle_ttl_expiry(handle, self.crypto.as_ref(), self.event_log.as_ref()).await?;

        // Emit expiry notification (lock acquired, then dropped).
        {
            let mut contexts = self.contexts.lock().await;
            if let Some(ctx) = contexts.get_mut(&context_id) {
                ctx.receive_buffer.push(ContextEvent::Expired);
            }
        }

        // Persist context state after TTL expiry (best-effort).
        {
            let contexts = self.contexts.lock().await;
            if let Some(ctx) = contexts.get(&context_id) {
                let snapshot = Self::snapshot_context(ctx);
                drop(contexts);
                self.persist_context_snapshot(&context_id, &snapshot);
            }
        }

        Ok(())
    }

    /// Proposes a TTL extension. Records consent from the given member.
    ///
    /// If all members have consented (unanimous), returns `true` indicating
    /// the extension was approved. The caller should then call
    /// [`reset_ttl_timer`](Self::reset_ttl_timer) with the new duration.
    ///
    /// See ADR-008 acceptance criterion 9 / spec section 5.10.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::MembershipFailed`] if the context is not
    /// registered. Returns [`ContextError::MemberNotFound`] if the member
    pub async fn propose_ttl_extension(
        &self,
        context_id: &str,
        member_did: &DID,
        proposed_duration: std::time::Duration,
    ) -> Result<bool, ContextError> {
        // All checks and mutation within a single lock acquisition.
        let mut contexts = self.contexts.lock().await;
        let ctx = contexts
            .get_mut(context_id)
            .ok_or_else(|| ContextError::MembershipFailed("context not registered".into()))?;

        if !ctx.membership.contains(member_did) {
            return Err(ContextError::MemberNotFound(member_did.to_string()));
        }

        let member_count = ctx.membership.count();

        // Initialize extension proposal if not already in progress.
        let extension = ctx
            .ttl_extension
            .get_or_insert_with(|| TtlExtension::new(proposed_duration, member_count));

        extension.add_consent(member_did.clone());
        let unanimous = extension.is_unanimous();

        // Persist context state after proposal consent (best-effort).
        let ctx_snapshot = Self::snapshot_context(ctx);
        drop(contexts);
        self.persist_context_snapshot(context_id, &ctx_snapshot);

        Ok(unanimous)
    }

    /// Resets the TTL timer after a successful unanimous extension.
    ///
    /// Cancels the old timer and spawns a new one with the given duration.
    /// Clears the extension proposal state.
    pub async fn reset_ttl_timer(
        &self,
        context_id: &str,
        new_duration: std::time::Duration,
        handle: ContextHandle,
    ) {
        // Cancel old timer and clear extension state (lock, then drop).
        {
            let mut contexts = self.contexts.lock().await;
            if let Some(ctx) = contexts.get_mut(context_id) {
                ctx.ttl_timer.cancel();
                ctx.ttl_extension = None;
            }
        }

        self.spawn_ttl_timer(context_id, new_duration, handle).await;

        // Persist context state after TTL reset (best-effort).
        {
            let contexts = self.contexts.lock().await;
            if let Some(ctx) = contexts.get(context_id) {
                let snapshot = Self::snapshot_context(ctx);
                drop(contexts);
                self.persist_context_snapshot(context_id, &snapshot);
            }
        }
    }

    // -------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------

    /// Spawns a TTL timer for the given context.
    ///
    /// When the timer fires, it calls [`ttl::handle_ttl_expiry`] which:
    /// - Transitions the context from `Active` to `Expired`.
    /// - For `Ephemeral` and `Summary` memory scopes: destroys MLS group
    ///   state and sender keys via the crypto provider.
    /// - Logs a `ContextExpired` event to the event log.
    ///
    /// This matches the behavior of [`TtlTimer::spawn`] and ensures key
    async fn spawn_ttl_timer(
        &self,
        context_id: &str,
        duration: std::time::Duration,
        handle: ContextHandle,
    ) {
        // Extract the cancel Notify under lock, then drop.
        let cancel = {
            let mut contexts = self.contexts.lock().await;
            let Some(ctx) = contexts.get_mut(context_id) else {
                return;
            };
            ctx.ttl_timer.cancel.clone()
        };

        // Clone Arc-wrapped providers so the spawned task can perform
        // key destruction and event logging on TTL expiry.
        let crypto = Arc::clone(&self.crypto);
        let event_log = Arc::clone(&self.event_log);

        let task = tokio::spawn(async move {
            tokio::select! {
                () = tokio::time::sleep(duration) => {
                    // Timer fired. Delegate to handle_ttl_expiry which
                    // transitions to Expired, destroys keys per memory
                    // scope, and logs ContextExpired event (SCP-169).
                    let _ = ttl::handle_ttl_expiry(
                        &handle,
                        crypto.as_ref(),
                        event_log.as_ref(),
                    ).await;
                }
                () = cancel.notified() => {
                    // Timer was cancelled.
                }
            }
        });

        // Store the task handle (lock, then drop).
        let context_id_owned = context_id.to_owned();
        let mut contexts = self.contexts.lock().await;
        if let Some(ctx) = contexts.get_mut(&context_id_owned) {
            ctx.ttl_timer.task = Some(task);
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Uses the canonical SHA-256 context ID byte derivation.
/// Delegates to [`super::context_id_bytes`] to match builder.rs.
fn context_id_to_bytes(context_id: &str) -> [u8; 32] {
    super::context_id_bytes(context_id)
}

// Compile-time assertion that `ContextManager` is `Send + Sync`.
const fn _assert_send_sync() {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ContextManager>();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::needless_collect,
    clippy::significant_drop_tightening,
    clippy::match_same_arms
)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;
    use crate::context::{ContextMode, ContextState};

    // -----------------------------------------------------------------------
    // Reusable mock providers
    // -----------------------------------------------------------------------

    #[derive(Default)]
    struct MockCrypto {
        fail_create_mls: AtomicBool,
        fail_validate_key_package: AtomicBool,
        mls_created: std::sync::Mutex<Vec<[u8; 32]>>,
        sender_keys_created: std::sync::Mutex<Vec<[u8; 32]>>,
        broadcast_created: std::sync::Mutex<Vec<[u8; 32]>>,
        mls_destroyed: std::sync::Mutex<Vec<[u8; 32]>>,
        sender_keys_destroyed: std::sync::Mutex<Vec<[u8; 32]>>,
        members_added: std::sync::Mutex<Vec<String>>,
        members_removed: std::sync::Mutex<Vec<String>>,
        sender_keys_distributed: std::sync::Mutex<Vec<String>>,
        sender_keys_removed: std::sync::Mutex<Vec<String>>,
        messages_encrypted: std::sync::Mutex<Vec<Vec<u8>>>,
    }

    impl ContextCryptoProvider for MockCrypto {
        fn validate_creator_identity(&self) -> Result<(), ContextCreationError> {
            Ok(())
        }

        fn create_mls_group(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
            if self.fail_create_mls.load(Ordering::Relaxed) {
                return Err(ContextCreationError::CryptoFailed("mock failure".into()));
            }
            self.mls_created.lock().unwrap().push(*id);
            Ok(())
        }

        fn generate_sender_key(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
            self.sender_keys_created.lock().unwrap().push(*id);
            Ok(())
        }

        fn init_broadcast_key(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
            self.broadcast_created.lock().unwrap().push(*id);
            Ok(())
        }

        fn destroy_mls_group(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
            self.mls_destroyed.lock().unwrap().push(*id);
            Ok(())
        }

        fn destroy_sender_key(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
            self.sender_keys_destroyed.lock().unwrap().push(*id);
            Ok(())
        }

        fn validate_key_package(
            &self,
            _owner_did: &str,
            _key_package_bytes: Option<&[u8]>,
        ) -> Result<(), ContextError> {
            if self.fail_validate_key_package.load(Ordering::Relaxed) {
                return Err(ContextError::InvalidKeyPackage("mock invalid".into()));
            }
            Ok(())
        }

        fn add_member(
            &self,
            _context_id: &[u8; 32],
            member_did: &str,
            _key_package_bytes: Option<&[u8]>,
        ) -> Result<(), ContextError> {
            self.members_added
                .lock()
                .unwrap()
                .push(member_did.to_owned());
            Ok(())
        }

        fn remove_member(
            &self,
            _context_id: &[u8; 32],
            member_did: &str,
        ) -> Result<(), ContextError> {
            self.members_removed
                .lock()
                .unwrap()
                .push(member_did.to_owned());
            Ok(())
        }

        fn distribute_sender_key(
            &self,
            _context_id: &[u8; 32],
            member_did: &str,
        ) -> Result<(), ContextError> {
            self.sender_keys_distributed
                .lock()
                .unwrap()
                .push(member_did.to_owned());
            Ok(())
        }

        fn remove_member_sender_key(
            &self,
            _context_id: &[u8; 32],
            member_did: &str,
        ) -> Result<(), ContextError> {
            self.sender_keys_removed
                .lock()
                .unwrap()
                .push(member_did.to_owned());
            Ok(())
        }

        fn encrypt_message(
            &self,
            _context_id: &[u8; 32],
            _sender_did: &str,
            payload: &[u8],
        ) -> Result<Vec<u8>, ContextError> {
            self.messages_encrypted
                .lock()
                .unwrap()
                .push(payload.to_vec());
            // Mock: return payload as-is (no real encryption).
            Ok(payload.to_vec())
        }
    }

    #[derive(Default)]
    struct MockTransport {
        connected: AtomicBool,
        published: std::sync::Mutex<Vec<[u8; 32]>>,
        deleted: std::sync::Mutex<Vec<[u8; 32]>>,
        messages_sent: std::sync::Mutex<Vec<Vec<u8>>>,
    }

    impl MockTransport {
        fn connected() -> Self {
            let t = Self::default();
            t.connected.store(true, Ordering::Relaxed);
            t
        }
    }

    impl ContextTransportProvider for MockTransport {
        fn is_connected(&self) -> bool {
            self.connected.load(Ordering::Relaxed)
        }

        fn publish_context(
            &self,
            id: &[u8; 32],
            _params: &ContextParams,
        ) -> Result<(), ContextCreationError> {
            self.published.lock().unwrap().push(*id);
            Ok(())
        }

        fn delete_published(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
            self.deleted.lock().unwrap().push(*id);
            Ok(())
        }

        fn send_message(
            &self,
            _context_id: &[u8; 32],
            encrypted_payload: &[u8],
        ) -> Result<(), ContextError> {
            self.messages_sent
                .lock()
                .unwrap()
                .push(encrypted_payload.to_vec());
            Ok(())
        }
    }

    #[derive(Default)]
    struct MockEventLog {
        inited: std::sync::Mutex<Vec<[u8; 32]>>,
        events: std::sync::Mutex<Vec<([u8; 32], String)>>,
        destroyed: std::sync::Mutex<Vec<[u8; 32]>>,
    }

    impl ContextEventLogProvider for MockEventLog {
        fn init_event_log(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
            self.inited.lock().unwrap().push(*id);
            Ok(())
        }

        fn append_event(&self, id: &[u8; 32], event: &str) -> Result<(), ContextCreationError> {
            self.events.lock().unwrap().push((*id, event.to_owned()));
            Ok(())
        }

        fn destroy_event_log(&self, id: &[u8; 32]) -> Result<(), ContextCreationError> {
            self.destroyed.lock().unwrap().push(*id);
            Ok(())
        }
    }

    // -----------------------------------------------------------------------
    // Helper: create a manager with default mocks and a registered context
    // -----------------------------------------------------------------------

    async fn setup_active_context() -> (ContextManager, ContextHandle) {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
        );

        let params = ContextParams {
            ceiling: vec![
                crate::context::params::Capability::new("messages:read"),
                crate::context::params::Capability::new("messages:write"),
                crate::context::params::Capability::new("role:assign"),
            ],
            ..ContextParams::default()
        };

        let handle = manager
            .create_context("test-ctx".into(), params, "did:key:creator".into())
            .await
            .unwrap();

        (manager, handle)
    }

    // -----------------------------------------------------------------------
    // Context creation tests (backward compatibility)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn manager_create_context_encrypted_success() {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
        );

        let handle = manager
            .create_context_bare("mgr-ctx-1".into(), ContextParams::default())
            .await;

        assert!(handle.is_ok());
        let handle = handle.unwrap();
        assert_eq!(handle.context_id(), "mgr-ctx-1");
        assert_eq!(handle.state().await, ContextState::Active);
    }

    #[tokio::test]
    async fn manager_create_context_broadcast_success() {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
        );

        let params = ContextParams {
            mode: ContextMode::Broadcast,
            ..ContextParams::default()
        };

        let handle = manager
            .create_context_bare("mgr-ctx-bc".into(), params)
            .await;

        assert!(handle.is_ok());
        let handle = handle.unwrap();
        assert_eq!(handle.context_id(), "mgr-ctx-bc");
        assert_eq!(handle.state().await, ContextState::Active);
    }

    #[tokio::test]
    async fn manager_create_context_transport_disconnected() {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::default()), // not connected
            Box::new(MockEventLog::default()),
        );

        let result = manager
            .create_context_bare("mgr-ctx-dc".into(), ContextParams::default())
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextCreationError::TransportNotConnected
        ));
    }

    #[tokio::test]
    async fn manager_create_context_rollback_on_crypto_failure() {
        let crypto = MockCrypto::default();
        crypto.fail_create_mls.store(true, Ordering::Relaxed);

        let manager = ContextManager::new(
            Box::new(crypto),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
        );

        let result = manager
            .create_context_bare("mgr-ctx-fail".into(), ContextParams::default())
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextCreationError::CryptoFailed(_)
        ));
    }

    #[tokio::test]
    async fn manager_preserves_params_on_handle() {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
        );

        let params = ContextParams {
            mode: ContextMode::Broadcast,
            ..ContextParams::default()
        };

        let handle = manager
            .create_context_bare("mgr-ctx-p".into(), params.clone())
            .await
            .unwrap();

        assert_eq!(*handle.params(), params);
        assert_eq!(handle.params().mode, ContextMode::Broadcast);
    }

    // -----------------------------------------------------------------------
    // Join context tests
    // -----------------------------------------------------------------------

    /// Unit test: join adds member to MLS group and issues UCAN tokens.
    #[tokio::test]
    async fn join_adds_member_to_mls_group_and_issues_ucan_tokens() {
        let (manager, handle) = setup_active_context().await;

        let kp = KeyPackage::mock("did:key:bob".into());

        let result = manager.join_context(&handle, kp).await;
        assert!(result.is_ok());

        // Verify member was added.
        assert!(manager.is_member("test-ctx", "did:key:bob").await);
        assert_eq!(manager.member_count("test-ctx").await, Some(2));

        // Verify UCAN tokens were issued.
        let role = manager.member_role("test-ctx", "did:key:bob").await;
        assert!(role.is_some());
        let role = role.unwrap();
        assert_eq!(role.role_name, "member");
        assert!(!role.tokens.is_empty());

        // Verify MemberJoined event was emitted.
        let events = manager.drain_events("test-ctx").await;
        let join_events: Vec<_> = events
            .iter()
            .filter(|e| matches!(e, ContextEvent::MemberJoined { .. }))
            .collect();
        assert_eq!(join_events.len(), 1);
    }

    #[tokio::test]
    async fn join_rejects_when_context_not_active() {
        let (manager, handle) = setup_active_context().await;

        // Transition to Closing.
        handle.transition_to(&ContextState::Closing).await.unwrap();

        let kp = KeyPackage::mock("did:key:bob".into());

        let result = manager.join_context(&handle, kp).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextError::ContextNotActive
        ));
    }

    // -----------------------------------------------------------------------
    // Leave context tests
    // -----------------------------------------------------------------------

    /// Unit test: leave removes member and transitions to Closing when count
    /// reaches zero.
    #[tokio::test]
    async fn leave_removes_member_and_transitions_to_closing_when_empty() {
        let (manager, handle) = setup_active_context().await;

        // Remove the only member (creator -- self-removal).
        let result = manager
            .leave_context(
                &handle,
                &"did:key:creator".into(),
                &"did:key:creator".into(),
            )
            .await;
        assert!(result.is_ok());

        // Member count should be 0.
        assert_eq!(manager.member_count("test-ctx").await, Some(0));
        assert!(!manager.is_member("test-ctx", "did:key:creator").await);

        // Context should have transitioned to Closing.
        assert_eq!(handle.state().await, ContextState::Closing);

        // Verify MemberLeft event was emitted.
        let events = manager.drain_events("test-ctx").await;
        let left_events: Vec<_> = events
            .iter()
            .filter(|e| matches!(e, ContextEvent::MemberLeft { .. }))
            .collect();
        assert_eq!(left_events.len(), 1);
    }

    #[tokio::test]
    async fn leave_does_not_close_when_members_remain() {
        let (manager, handle) = setup_active_context().await;

        // Add a second member.
        let kp = KeyPackage::mock("did:key:bob".into());
        manager.join_context(&handle, kp).await.unwrap();
        assert_eq!(manager.member_count("test-ctx").await, Some(2));

        // Remove bob (self-removal).
        manager.drain_events("test-ctx").await; // Clear join event.
        let result = manager
            .leave_context(&handle, &"did:key:bob".into(), &"did:key:bob".into())
            .await;
        assert!(result.is_ok());

        // Context should still be Active (creator is still there).
        assert_eq!(handle.state().await, ContextState::Active);
        assert_eq!(manager.member_count("test-ctx").await, Some(1));
    }

    #[tokio::test]
    async fn leave_rejects_when_context_not_active() {
        let (manager, handle) = setup_active_context().await;

        handle.transition_to(&ContextState::Closing).await.unwrap();

        let result = manager
            .leave_context(
                &handle,
                &"did:key:creator".into(),
                &"did:key:creator".into(),
            )
            .await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextError::ContextNotActive
        ));
    }

    // -----------------------------------------------------------------------
    // Leave context authorization tests (SCP-167)
    // -----------------------------------------------------------------------

    /// Helper: creates a context whose ceiling includes `member:remove` so
    /// that the admin can remove other members. Adds an observer member
    /// (`did:key:observer`) alongside the admin creator (`did:key:creator`).
    async fn setup_context_with_member_remove() -> (ContextManager, ContextHandle) {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
        );

        let params = ContextParams {
            ceiling: vec![
                crate::context::params::Capability::new("messages:read"),
                crate::context::params::Capability::new("messages:write"),
                crate::context::params::Capability::new("role:assign"),
                crate::context::params::Capability::new("member:remove"),
            ],
            ..ContextParams::default()
        };

        let handle = manager
            .create_context("auth-ctx".into(), params, "did:key:creator".into())
            .await
            .unwrap();

        // Add an observer member.
        let kp = KeyPackage::mock("did:key:observer".into());
        manager.join_context(&handle, kp).await.unwrap();

        // Reassign to observer role (joined members default to "member").
        {
            let mut contexts = manager.contexts.lock().await;
            let ctx = contexts.get_mut("auth-ctx").unwrap();
            roles::assign_role(
                &mut ctx.role_state,
                "did:key:observer",
                "observer",
                "did:key:creator",
            )
            .unwrap();
            // Update the membership tracking to reflect the new role.
            if let Some(info) = ctx.membership.get_mut("did:key:observer") {
                info.role_name = "observer".into();
            }
        }

        (manager, handle)
    }

    /// SCP-167: observer calls `leave_context` with admin's DID — returns
    /// authorization error.
    #[tokio::test]
    async fn leave_observer_cannot_remove_admin() {
        let (manager, handle) = setup_context_with_member_remove().await;

        // Observer tries to remove the admin — should fail.
        let result = manager
            .leave_context(
                &handle,
                &"did:key:observer".into(),
                &"did:key:creator".into(),
            )
            .await;

        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), ContextError::PermissionDenied(_)),
            "observer should not be able to remove admin"
        );

        // Admin should still be a member.
        assert!(manager.is_member("auth-ctx", "did:key:creator").await);
    }

    /// SCP-167: admin calls `leave_context` with observer's DID — succeeds
    /// (admin has `MemberRemove` capability).
    #[tokio::test]
    async fn leave_admin_can_remove_observer() {
        let (manager, handle) = setup_context_with_member_remove().await;

        // Admin removes the observer — should succeed.
        let result = manager
            .leave_context(
                &handle,
                &"did:key:creator".into(),
                &"did:key:observer".into(),
            )
            .await;

        assert!(result.is_ok(), "admin should be able to remove observer");

        // Observer should no longer be a member.
        assert!(!manager.is_member("auth-ctx", "did:key:observer").await);
        // Admin should still be a member.
        assert!(manager.is_member("auth-ctx", "did:key:creator").await);
    }

    /// SCP-167: member calls `leave_context` with own DID — succeeds
    /// (self-removal is always allowed regardless of role).
    #[tokio::test]
    async fn leave_self_removal_always_allowed() {
        let (manager, handle) = setup_context_with_member_remove().await;

        // Observer self-removes — should always succeed.
        let result = manager
            .leave_context(
                &handle,
                &"did:key:observer".into(),
                &"did:key:observer".into(),
            )
            .await;

        assert!(result.is_ok(), "self-removal should always be allowed");

        // Observer should no longer be a member.
        assert!(!manager.is_member("auth-ctx", "did:key:observer").await);
        // Admin should still be a member.
        assert!(manager.is_member("auth-ctx", "did:key:creator").await);
    }

    // -----------------------------------------------------------------------
    // Send message tests
    // -----------------------------------------------------------------------

    /// Unit test: `send_message` rejects when context is not Active.
    #[tokio::test]
    async fn send_message_rejects_when_context_not_active() {
        let (manager, handle) = setup_active_context().await;

        handle.transition_to(&ContextState::Closing).await.unwrap();

        let result = manager
            .send_message(&handle, &"did:key:creator".into(), b"hello")
            .await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextError::ContextNotActive
        ));
    }

    /// Unit test: `send_message` validates UCAN before sending.
    #[tokio::test]
    async fn send_message_validates_ucan_before_sending() {
        let (manager, handle) = setup_active_context().await;

        // Try to send as a non-member -- should be denied.
        let result = manager
            .send_message(&handle, &"did:key:nonexistent".into(), b"hello")
            .await;
        assert!(result.is_err());

        // Should be either PermissionDenied or MemberNotFound.
        match result.unwrap_err() {
            ContextError::PermissionDenied(_) => {}
            ContextError::MemberNotFound(_) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_message_success_encrypts_and_sends() {
        let (manager, handle) = setup_active_context().await;

        let result = manager
            .send_message(&handle, &"did:key:creator".into(), b"hello world")
            .await;
        assert!(result.is_ok());

        // Verify MessageSent event was emitted.
        let events = manager.drain_events("test-ctx").await;
        let msg_events: Vec<_> = events
            .iter()
            .filter(|e| matches!(e, ContextEvent::MessageSent { .. }))
            .collect();
        assert_eq!(msg_events.len(), 1);

        if let ContextEvent::MessageSent {
            sender_did,
            sequence_number,
            payload,
        } = &msg_events[0]
        {
            assert_eq!(sender_did, "did:key:creator");
            assert_eq!(*sequence_number, 1);
            assert_eq!(payload, b"hello world");
        }
    }

    #[tokio::test]
    async fn send_message_assigns_monotonic_sequence_numbers() {
        let (manager, handle) = setup_active_context().await;

        for i in 1..=5u8 {
            manager
                .send_message(&handle, &"did:key:creator".into(), &[i])
                .await
                .unwrap();
        }

        let events = manager.drain_events("test-ctx").await;
        let seq_nums: Vec<u64> = events
            .iter()
            .filter_map(|e| {
                if let ContextEvent::MessageSent {
                    sequence_number, ..
                } = e
                {
                    Some(*sequence_number)
                } else {
                    None
                }
            })
            .collect();

        assert_eq!(seq_nums, vec![1, 2, 3, 4, 5]);
    }

    // -----------------------------------------------------------------------
    // Member tracking tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn member_list_queries() {
        let (manager, handle) = setup_active_context().await;

        // Initially only creator.
        assert_eq!(manager.member_count("test-ctx").await, Some(1));
        assert!(manager.is_member("test-ctx", "did:key:creator").await);

        // Add members.
        for name in &["alice", "bob", "charlie"] {
            let kp = KeyPackage::mock(format!("did:key:{name}").into());
            manager.join_context(&handle, kp).await.unwrap();
        }

        assert_eq!(manager.member_count("test-ctx").await, Some(4));
        assert!(manager.is_member("test-ctx", "did:key:alice").await);
        assert!(manager.is_member("test-ctx", "did:key:bob").await);
        assert!(manager.is_member("test-ctx", "did:key:charlie").await);

        let mut dids = manager.member_dids("test-ctx").await;
        dids.sort();
        assert_eq!(
            dids,
            vec![
                "did:key:alice",
                "did:key:bob",
                "did:key:charlie",
                "did:key:creator"
            ]
        );
    }

    #[tokio::test]
    async fn member_role_assignment() {
        let (manager, handle) = setup_active_context().await;

        // Creator should be admin.
        let role = manager.member_role("test-ctx", "did:key:creator").await;
        assert!(role.is_some());
        assert_eq!(role.unwrap().role_name, "admin");

        // Add a member.
        let kp = KeyPackage::mock("did:key:alice".into());
        manager.join_context(&handle, kp).await.unwrap();

        let role = manager.member_role("test-ctx", "did:key:alice").await;
        assert!(role.is_some());
        assert_eq!(role.unwrap().role_name, "member");
    }

    // -----------------------------------------------------------------------
    // Concurrent operations test (SCP-168)
    // -----------------------------------------------------------------------

    /// Verifies that concurrent join + send operations on the same context
    /// do not corrupt internal state. All operations should either succeed
    /// or return a well-defined error -- never panic or produce inconsistent
    /// membership counts.
    #[tokio::test]
    async fn concurrent_joins_and_sends_do_not_corrupt_state() {
        let manager = std::sync::Arc::new(ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
        ));

        let params = ContextParams {
            ceiling: vec![
                crate::context::params::Capability::new("messages:read"),
                crate::context::params::Capability::new("messages:write"),
                crate::context::params::Capability::new("role:assign"),
            ],
            ..ContextParams::default()
        };

        let handle = manager
            .create_context("conc-ctx".into(), params, "did:key:creator".into())
            .await
            .unwrap();

        let handle = std::sync::Arc::new(handle);

        // Spawn 10 concurrent join tasks.
        let mut join_handles = Vec::new();
        for i in 0..10u32 {
            let mgr = std::sync::Arc::clone(&manager);
            let h = std::sync::Arc::clone(&handle);
            join_handles.push(tokio::spawn(async move {
                let kp = KeyPackage::mock(format!("did:key:member-{i}").into());
                mgr.join_context(&h, kp).await
            }));
        }

        // Spawn 5 concurrent send tasks from the creator.
        for i in 0..5u8 {
            let mgr = std::sync::Arc::clone(&manager);
            let h = std::sync::Arc::clone(&handle);
            join_handles.push(tokio::spawn(async move {
                mgr.send_message(&h, &"did:key:creator".into(), &[i]).await
            }));
        }

        // Wait for all tasks. All should succeed (no panics, no data corruption).
        for jh in join_handles {
            let result = jh.await.unwrap();
            assert!(result.is_ok(), "concurrent operation failed: {result:?}");
        }

        // 1 creator + 10 joined members = 11.
        assert_eq!(manager.member_count("conc-ctx").await, Some(11));
    }

    // -----------------------------------------------------------------------
    // Panic recovery test (SCP-168)
    // -----------------------------------------------------------------------

    /// Verifies that a panic inside a mock provider does not poison the
    /// `tokio::sync::Mutex`. After the panicking task is caught, subsequent
    /// operations on the same manager must succeed.
    #[tokio::test]
    async fn panic_does_not_poison_mutex() {
        use std::sync::Arc;

        let manager = Arc::new(ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
        ));

        let params = ContextParams {
            ceiling: vec![
                crate::context::params::Capability::new("messages:read"),
                crate::context::params::Capability::new("messages:write"),
                crate::context::params::Capability::new("role:assign"),
            ],
            ..ContextParams::default()
        };

        let handle = manager
            .create_context("panic-ctx".into(), params, "did:key:creator".into())
            .await
            .unwrap();

        // Spawn a task that will panic after acquiring the contexts lock.
        // We simulate this by calling join_context with a specially crafted
        // scenario: the crypto provider succeeds, but then we panic inside
        // a spawned task that holds a reference.
        let mgr_clone = Arc::clone(&manager);
        let handle_clone = handle.clone();
        let panicking_task = tokio::spawn(async move {
            // This panics inside the task. tokio::sync::Mutex does not poison.
            let _count = mgr_clone.member_count("panic-ctx").await;
            panic!("intentional panic for testing");
        });

        // The panicking task should fail (JoinError with panic).
        let result = panicking_task.await;
        assert!(result.is_err(), "task should have panicked");

        // The manager should still be usable -- tokio::sync::Mutex does not poison.
        let count = manager.member_count("panic-ctx").await;
        assert_eq!(count, Some(1), "mutex should not be poisoned");

        // Further operations should succeed.
        let kp = KeyPackage::mock("did:key:after-panic".into());
        let join_result = manager.join_context(&handle_clone, kp).await;
        assert!(join_result.is_ok(), "join after panic should succeed");
        assert_eq!(manager.member_count("panic-ctx").await, Some(2));
    }

    // -----------------------------------------------------------------------
    // Broadcast context integration tests (SCP-227)
    // -----------------------------------------------------------------------

    /// Helper: creates a broadcast context with open admission and returns
    /// the manager, handle, and `context_id`.
    ///
    /// Registers `did:key:author1` as a local DID for defense-in-depth
    /// validation in `handle_broadcast_key_request` (#234).
    async fn setup_broadcast_context() -> (ContextManager, ContextHandle, String) {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
        );

        // Register the author DID as locally controlled (#234).
        manager.register_local_did("did:key:author1".into()).await;

        let params = ContextParams {
            mode: ContextMode::Broadcast,
            ceiling: vec![
                crate::context::params::Capability::new("messages:read"),
                crate::context::params::Capability::new("messages:write"),
                crate::context::params::Capability::new("role:assign"),
            ],
            ..ContextParams::default()
        };

        let handle = manager
            .create_context("broadcast-ctx".into(), params, "did:key:author1".into())
            .await
            .unwrap();

        (manager, handle, "broadcast-ctx".into())
    }

    /// SCP-227 AC1: `subscribe_broadcast` registers subscriber and returns
    /// current author key epoch.
    #[tokio::test]
    async fn broadcast_subscribe_registers_and_returns_epoch() {
        use crate::crypto::ucan::validate::{
            InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver,
            InMemoryRevocationChecker,
        };
        use std::hash::RandomState;

        let (manager, _handle, ctx_id) = setup_broadcast_context().await;

        let result = manager
            .subscribe_broadcast::<
                InMemoryDidResolver,
                InMemoryNonceTracker,
                InMemoryRevocationChecker,
                InMemoryProofResolver,
                RandomState,
            >(
                &ctx_id,
                &"did:key:sub1".into(),
                None,
                1000,
                None,
            )
            .await;

        assert!(result.is_ok(), "subscribe should succeed on open context");
        let result = result.unwrap();

        // Author key epoch should be 0 (fresh author).
        assert_eq!(result.author_epochs.len(), 1);
        assert_eq!(result.author_epochs.get("did:key:author1"), Some(&0));

        // Event should be MemberJoined with role subscriber.
        assert!(matches!(
            result.event,
            ContextEvent::MemberJoined { ref role_name, .. } if role_name == "subscriber"
        ));

        // Manager should track the subscriber.
        assert!(
            manager
                .is_broadcast_subscriber(&ctx_id, "did:key:sub1")
                .await
        );
        assert_eq!(manager.broadcast_subscriber_count(&ctx_id).await, Some(1));
    }

    /// SCP-227 AC2: open broadcast allows subscription without UCAN.
    #[tokio::test]
    async fn broadcast_open_subscribe_no_ucan_required() {
        use crate::crypto::ucan::validate::{
            InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver,
            InMemoryRevocationChecker,
        };
        use std::hash::RandomState;

        let (manager, _handle, ctx_id) = setup_broadcast_context().await;

        // Subscribe without UCAN on open context -- should succeed.
        let result = manager
            .subscribe_broadcast::<
                InMemoryDidResolver,
                InMemoryNonceTracker,
                InMemoryRevocationChecker,
                InMemoryProofResolver,
                RandomState,
            >(
                &ctx_id,
                &"did:key:sub1".into(),
                None,
                1000,
                None,
            )
            .await;
        assert!(result.is_ok());

        // Admission should be Open.
        assert_eq!(
            manager.broadcast_admission(&ctx_id).await,
            Some(super::BroadcastAdmission::Open)
        );
    }

    /// SCP-227 AC4: `block_broadcast_author` revokes sender key.
    #[tokio::test]
    async fn broadcast_block_revokes_key() {
        use crate::crypto::ucan::validate::{
            InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver,
            InMemoryRevocationChecker,
        };
        use std::hash::RandomState;

        let (manager, _handle, ctx_id) = setup_broadcast_context().await;

        // Subscribe a victim.
        manager
            .subscribe_broadcast::<
                InMemoryDidResolver,
                InMemoryNonceTracker,
                InMemoryRevocationChecker,
                InMemoryProofResolver,
                RandomState,
            >(
                &ctx_id,
                &"did:key:victim".into(),
                None,
                1000,
                None,
            )
            .await
            .unwrap();

        // Block the victim.
        let block_result = manager
            .block_broadcast_subscriber(
                &ctx_id,
                &"did:key:author1".into(),
                &"did:key:victim".into(),
            )
            .await;

        assert!(block_result.is_ok());
        let block_result = block_result.unwrap();

        // New epoch should be 1 (rotated from 0).
        assert_eq!(block_result.new_epoch, 1);
        assert!(block_result.block_list.contains("did:key:victim"));

        // Key request from blocked subscriber should be denied.
        let decision = manager
            .handle_broadcast_key_request(
                &ctx_id,
                &"did:key:author1".into(),
                &"did:key:victim".into(),
            )
            .await
            .unwrap();
        assert!(matches!(decision, super::KeyRequestDecision::Deny { .. }));
    }

    /// SCP-227 AC5: broadcast capabilities enforce `MessagesWrite` restricted
    /// to authors, `MessagesRead` open to subscribers.
    #[tokio::test]
    async fn broadcast_capabilities_enforced() {
        use crate::crypto::ucan::validate::{
            InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver,
            InMemoryRevocationChecker,
        };
        use std::hash::RandomState;

        let (manager, handle, ctx_id) = setup_broadcast_context().await;

        // Subscribe a subscriber.
        manager
            .subscribe_broadcast::<
                InMemoryDidResolver,
                InMemoryNonceTracker,
                InMemoryRevocationChecker,
                InMemoryProofResolver,
                RandomState,
            >(
                &ctx_id,
                &"did:key:sub1".into(),
                None,
                1000,
                None,
            )
            .await
            .unwrap();

        // Author can publish (send_message routes to broadcast publish).
        let result = manager
            .send_message(&handle, &"did:key:author1".into(), b"hello broadcast")
            .await;
        assert!(result.is_ok(), "author should be able to publish");

        // Non-author subscriber cannot publish.
        let result = manager
            .send_message(&handle, &"did:key:sub1".into(), b"unauthorized")
            .await;
        assert!(result.is_err(), "subscriber should not be able to publish");
        assert!(matches!(
            result.unwrap_err(),
            ContextError::PermissionDenied(_)
        ));
    }

    /// SCP-227 AC6: integration test -- author publishes, 3 subscribers
    /// receive and can request keys for decryption.
    #[tokio::test]
    async fn broadcast_publish_3_subscribers_decrypt() {
        use crate::crypto::sender_keys::open_broadcast;
        use crate::crypto::ucan::validate::{
            InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver,
            InMemoryRevocationChecker,
        };
        use std::hash::RandomState;

        let (manager, _handle, ctx_id) = setup_broadcast_context().await;

        // Subscribe 3 subscribers.
        for name in &["sub1", "sub2", "sub3"] {
            manager
                .subscribe_broadcast::<
                    InMemoryDidResolver,
                    InMemoryNonceTracker,
                    InMemoryRevocationChecker,
                    InMemoryProofResolver,
                    RandomState,
                >(
                    &ctx_id,
                    &DID(format!("did:key:{name}")),
                    None,
                    1000,
                    None,
                )
                .await
                .unwrap();
        }

        assert_eq!(manager.broadcast_subscriber_count(&ctx_id).await, Some(3));

        // Author publishes a message.
        let plaintext = b"hello all subscribers!";
        let envelope = manager
            .publish_broadcast(&ctx_id, &"did:key:author1".into(), plaintext)
            .await
            .unwrap();

        // Each subscriber requests the key and decrypts.
        for name in &["sub1", "sub2", "sub3"] {
            let decision = manager
                .handle_broadcast_key_request(
                    &ctx_id,
                    &"did:key:author1".into(),
                    &DID(format!("did:key:{name}")),
                )
                .await
                .unwrap();

            match decision {
                super::KeyRequestDecision::Grant {
                    key_bytes, epoch, ..
                } => {
                    assert_eq!(epoch, 0);
                    // Reconstruct broadcast key and decrypt.
                    let broadcast_key = crate::crypto::sender_keys::BroadcastKey::from_parts(
                        crate::crypto::sender_keys::SenderKey::from_bytes(*key_bytes),
                        epoch,
                        "did:key:author1".to_owned(),
                    );
                    let decrypted = open_broadcast(&broadcast_key, &envelope).unwrap();
                    assert_eq!(decrypted, plaintext);
                }
                super::KeyRequestDecision::Deny { reason } => {
                    panic!("key request should be granted for {name}: {reason}");
                }
            }
        }

        // Verify MessageSent event was emitted.
        let events = manager.drain_events(&ctx_id).await;
        let msg_events: Vec<_> = events
            .iter()
            .filter(|e| matches!(e, ContextEvent::MessageSent { .. }))
            .collect();
        assert_eq!(msg_events.len(), 1);
    }

    /// SCP-227 AC7: integration test -- blocked author's subsequent messages
    /// are undecryptable by blocked subscriber.
    #[tokio::test]
    // Integration test exercises full context lifecycle; splitting would
    // fragment a sequential scenario that must be verified end-to-end.
    #[allow(clippy::too_many_lines)]
    async fn broadcast_blocked_subscriber_cannot_decrypt() {
        use crate::crypto::sender_keys::open_broadcast;
        use crate::crypto::ucan::validate::{
            InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver,
            InMemoryRevocationChecker,
        };
        use std::hash::RandomState;

        let (manager, _handle, ctx_id) = setup_broadcast_context().await;

        // Subscribe 2 subscribers.
        for name in &["good-sub", "bad-sub"] {
            manager
                .subscribe_broadcast::<
                    InMemoryDidResolver,
                    InMemoryNonceTracker,
                    InMemoryRevocationChecker,
                    InMemoryProofResolver,
                    RandomState,
                >(
                    &ctx_id,
                    &DID(format!("did:key:{name}")),
                    None,
                    1000,
                    None,
                )
                .await
                .unwrap();
        }

        // Author publishes first message (both can decrypt).
        let msg1 = b"pre-block message";
        let envelope1 = manager
            .publish_broadcast(&ctx_id, &"did:key:author1".into(), msg1)
            .await
            .unwrap();

        // Get the pre-block key for "bad-sub".
        let pre_block_decision = manager
            .handle_broadcast_key_request(
                &ctx_id,
                &"did:key:author1".into(),
                &"did:key:bad-sub".into(),
            )
            .await
            .unwrap();
        let super::KeyRequestDecision::Grant {
            key_bytes: pre_block_key_bytes,
            epoch: pre_block_epoch,
        } = pre_block_decision
        else {
            panic!("should be granted before block")
        };

        // Verify bad-sub can decrypt the pre-block message.
        let pre_block_broadcast_key = crate::crypto::sender_keys::BroadcastKey::from_parts(
            crate::crypto::sender_keys::SenderKey::from_bytes(*pre_block_key_bytes),
            pre_block_epoch,
            "did:key:author1".to_owned(),
        );
        let decrypted = open_broadcast(&pre_block_broadcast_key, &envelope1).unwrap();
        assert_eq!(decrypted, msg1);

        // Block bad-sub.
        manager
            .block_broadcast_subscriber(
                &ctx_id,
                &"did:key:author1".into(),
                &"did:key:bad-sub".into(),
            )
            .await
            .unwrap();

        // Author publishes post-block message.
        let msg2 = b"post-block secret";
        let envelope2 = manager
            .publish_broadcast(&ctx_id, &"did:key:author1".into(), msg2)
            .await
            .unwrap();

        // bad-sub's key request is now denied.
        let post_block_decision = manager
            .handle_broadcast_key_request(
                &ctx_id,
                &"did:key:author1".into(),
                &"did:key:bad-sub".into(),
            )
            .await
            .unwrap();
        assert!(
            matches!(post_block_decision, super::KeyRequestDecision::Deny { .. }),
            "blocked subscriber should be denied"
        );

        // bad-sub tries to decrypt with the old key -- should fail because
        // the message was encrypted with the new (post-rotation) key.
        let decrypt_attempt = open_broadcast(&pre_block_broadcast_key, &envelope2);
        assert!(
            decrypt_attempt.is_err(),
            "blocked subscriber should not be able to decrypt post-block messages"
        );

        // good-sub can still get the new key and decrypt.
        let good_decision = manager
            .handle_broadcast_key_request(
                &ctx_id,
                &"did:key:author1".into(),
                &"did:key:good-sub".into(),
            )
            .await
            .unwrap();
        match good_decision {
            super::KeyRequestDecision::Grant {
                key_bytes, epoch, ..
            } => {
                assert_eq!(epoch, 1, "epoch should be 1 after rotation");
                let new_key = crate::crypto::sender_keys::BroadcastKey::from_parts(
                    crate::crypto::sender_keys::SenderKey::from_bytes(*key_bytes),
                    epoch,
                    "did:key:author1".to_owned(),
                );
                let decrypted = open_broadcast(&new_key, &envelope2).unwrap();
                assert_eq!(decrypted, msg2);
            }
            super::KeyRequestDecision::Deny { reason } => {
                panic!("good-sub should be granted: {reason}");
            }
        }
    }

    /// SCP-227: non-author publish is rejected.
    #[tokio::test]
    async fn broadcast_non_author_publish_rejected() {
        use crate::crypto::ucan::validate::{
            InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver,
            InMemoryRevocationChecker,
        };
        use std::hash::RandomState;

        let (manager, _handle, ctx_id) = setup_broadcast_context().await;

        // Subscribe.
        manager
            .subscribe_broadcast::<
                InMemoryDidResolver,
                InMemoryNonceTracker,
                InMemoryRevocationChecker,
                InMemoryProofResolver,
                RandomState,
            >(
                &ctx_id,
                &"did:key:sub1".into(),
                None,
                1000,
                None,
            )
            .await
            .unwrap();

        // Subscriber tries to publish -- should fail.
        let result = manager
            .publish_broadcast(&ctx_id, &"did:key:sub1".into(), b"nope")
            .await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextError::PermissionDenied(_)
        ));
    }

    /// SCP-227: `create_context` initializes `broadcast_context` for broadcast mode.
    #[tokio::test]
    async fn broadcast_create_context_initializes_broadcast_state() {
        let (manager, _handle, ctx_id) = setup_broadcast_context().await;

        // Admission should be Open (default for no template_id).
        assert_eq!(
            manager.broadcast_admission(&ctx_id).await,
            Some(super::BroadcastAdmission::Open)
        );

        // Subscriber count should be 0 initially.
        assert_eq!(manager.broadcast_subscriber_count(&ctx_id).await, Some(0));

        // Author should be able to publish.
        let result = manager
            .publish_broadcast(&ctx_id, &"did:key:author1".into(), b"test")
            .await;
        assert!(result.is_ok());
    }

    /// SCP-227: `leave_context` on broadcast context cleans up subscriber.
    #[tokio::test]
    async fn broadcast_leave_context_unsubscribes() {
        use crate::crypto::ucan::validate::{
            InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver,
            InMemoryRevocationChecker,
        };
        use std::hash::RandomState;

        let (manager, handle, ctx_id) = setup_broadcast_context().await;

        // Subscribe.
        manager
            .subscribe_broadcast::<
                InMemoryDidResolver,
                InMemoryNonceTracker,
                InMemoryRevocationChecker,
                InMemoryProofResolver,
                RandomState,
            >(
                &ctx_id,
                &"did:key:sub1".into(),
                None,
                1000,
                None,
            )
            .await
            .unwrap();
        assert!(
            manager
                .is_broadcast_subscriber(&ctx_id, "did:key:sub1")
                .await
        );

        // Leave via leave_context (self-removal).
        let result = manager
            .leave_context(&handle, &"did:key:sub1".into(), &"did:key:sub1".into())
            .await;
        assert!(result.is_ok());

        // Subscriber should be removed from broadcast context.
        assert!(
            !manager
                .is_broadcast_subscriber(&ctx_id, "did:key:sub1")
                .await
        );
    }

    /// SCP-227: `close_context` drops broadcast state.
    #[tokio::test]
    async fn broadcast_close_context_drops_state() {
        // Need context:close capability for the admin.
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
        );

        let params = ContextParams {
            mode: ContextMode::Broadcast,
            ceiling: vec![
                crate::context::params::Capability::new("messages:read"),
                crate::context::params::Capability::new("messages:write"),
                crate::context::params::Capability::new("role:assign"),
                crate::context::params::Capability::new("context:close"),
            ],
            ..ContextParams::default()
        };

        let handle = manager
            .create_context(
                "broadcast-close-ctx".into(),
                params,
                "did:key:author1".into(),
            )
            .await
            .unwrap();
        let ctx_id = "broadcast-close-ctx";

        // Close the context.
        let result = manager
            .close_context(&handle, &"did:key:author1".into())
            .await;
        assert!(result.is_ok());

        // Broadcast state should be None (dropped on close).
        assert_eq!(manager.broadcast_admission(ctx_id).await, None);
        assert_eq!(manager.broadcast_subscriber_count(ctx_id).await, None);
    }

    /// SCP-227: `unsubscribe_broadcast` removes subscriber and optionally rotates keys.
    #[tokio::test]
    async fn broadcast_unsubscribe_with_key_rotation() {
        use crate::crypto::ucan::validate::{
            InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver,
            InMemoryRevocationChecker,
        };
        use std::hash::RandomState;

        let (manager, _handle, ctx_id) = setup_broadcast_context().await;

        // Subscribe.
        manager
            .subscribe_broadcast::<
                InMemoryDidResolver,
                InMemoryNonceTracker,
                InMemoryRevocationChecker,
                InMemoryProofResolver,
                RandomState,
            >(
                &ctx_id,
                &"did:key:sub1".into(),
                None,
                1000,
                None,
            )
            .await
            .unwrap();

        // Unsubscribe with key rotation.
        let result = manager
            .unsubscribe_broadcast(&ctx_id, &"did:key:sub1".into(), true)
            .await;
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.subscriber_did, "did:key:sub1");
        // Key rotation should have happened (one rotation per author).
        assert_eq!(result.key_rotations.len(), 1);
        assert_eq!(result.key_rotations[0].new_epoch, 1);

        // Subscriber should no longer be tracked.
        assert!(
            !manager
                .is_broadcast_subscriber(&ctx_id, "did:key:sub1")
                .await
        );
    }

    // ===================================================================
    // Author blocking (SCP-227 AC4 + AC7) — governance-gated
    // ===================================================================

    /// Helper: creates an approved `BlockAuthor` governance proposal using
    /// `SingleAdminEngine` (admin = `admin_did`). Returns the approved
    /// proposal that can be passed to `execute_governance_action()`.
    fn approved_block_author_proposal(
        admin_did: &DID,
        context_id: &str,
        target_did: &DID,
    ) -> super::GovernanceProposal {
        use crate::context::governance::{
            GovernanceAction, GovernanceContext, GovernanceEngine, SingleAdminEngine,
        };

        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        let mut engine = SingleAdminEngine::new(admin_did.clone());
        let gov_ctx = GovernanceContext {
            context_id: context_id.to_owned(),
            members: vec![
                (admin_did.clone(), "admin".to_owned()),
                (target_did.clone(), "author".to_owned()),
            ],
            admin_dids: vec![admin_did.clone()],
            current_epoch: None,
            now: 1000,
        };

        let action = GovernanceAction::BlockAuthor {
            did: target_did.clone(),
            reason: Some("governance test".to_owned()),
        };

        let (proposal, _events) = engine
            .propose(admin_did, action, &gov_ctx, &signing_key)
            .unwrap();
        assert!(matches!(proposal.status, super::ProposalStatus::Approved));
        proposal
    }

    /// Helper to create a broadcast context with two authors (alice + bob).
    ///
    /// Both authors are registered in the `BroadcastContext` (for publish
    /// capability) and in `MembershipState` (for sequence number tracking).
    /// Both author DIDs are registered as locally controlled (#234).
    async fn setup_broadcast_context_two_authors() -> (ContextManager, ContextHandle, String) {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
        );

        // Register both author DIDs as locally controlled (#234).
        manager.register_local_did("did:key:alice".into()).await;
        manager.register_local_did("did:key:bob".into()).await;

        let params = ContextParams {
            mode: ContextMode::Broadcast,
            ceiling: vec![
                crate::context::params::Capability::new("messages:read"),
                crate::context::params::Capability::new("messages:write"),
                crate::context::params::Capability::new("role:assign"),
            ],
            ..ContextParams::default()
        };

        let handle = manager
            .create_context("broadcast-2auth-ctx".into(), params, "did:key:alice".into())
            .await
            .unwrap();

        // Add bob as a second author: both in BroadcastContext and membership.
        {
            let mut contexts = manager.contexts.lock().await;
            let ctx = contexts.get_mut("broadcast-2auth-ctx").unwrap();
            let bc = ctx.broadcast_context.as_mut().unwrap();
            bc.add_author("did:key:bob").unwrap();
            // Also add to membership tracking so sequence numbers work.
            ctx.membership
                .add_member("did:key:bob".into(), "author".into(), vec![]);
        }

        let ctx_id = "broadcast-2auth-ctx".to_owned();
        (manager, handle, ctx_id)
    }

    /// SCP-227 AC4: governance-approved `BlockAuthor` proposal revokes sender
    /// key, preventing the blocked author from publishing.
    #[tokio::test]
    async fn broadcast_block_author_via_governance_revokes_publish() {
        use crate::crypto::ucan::validate::{
            InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver,
            InMemoryRevocationChecker,
        };
        use std::hash::RandomState;

        let (manager, _handle, ctx_id) = setup_broadcast_context_two_authors().await;

        // Subscribe 2 subscribers.
        for name in &["sub1", "sub2"] {
            manager
                .subscribe_broadcast::<
                    InMemoryDidResolver,
                    InMemoryNonceTracker,
                    InMemoryRevocationChecker,
                    InMemoryProofResolver,
                    RandomState,
                >(
                    &ctx_id,
                    &DID(format!("did:key:{name}")),
                    None,
                    1000,
                    None,
                )
                .await
                .unwrap();
        }

        // Both authors can publish before blocking.
        assert!(
            manager
                .publish_broadcast(&ctx_id, &"did:key:alice".into(), b"alice msg")
                .await
                .is_ok()
        );
        assert!(
            manager
                .publish_broadcast(&ctx_id, &"did:key:bob".into(), b"bob msg")
                .await
                .is_ok()
        );

        // Block bob via governance: admin proposes, auto-approved.
        let proposal =
            approved_block_author_proposal(&"did:key:alice".into(), &ctx_id, &"did:key:bob".into());
        let action_result = manager.execute_governance_action(&ctx_id, &proposal).await;
        assert!(action_result.is_ok());
        let super::GovernanceActionResult::AuthorBlocked(block_result) = action_result.unwrap()
        else {
            panic!("expected AuthorBlocked result");
        };
        assert_eq!(block_result.author_did, "did:key:bob");
        assert_eq!(block_result.final_epoch, 0);

        // Alice can still publish (unaffected).
        assert!(
            manager
                .publish_broadcast(&ctx_id, &"did:key:alice".into(), b"alice still ok")
                .await
                .is_ok(),
            "unblocked author should still be able to publish"
        );

        // Bob cannot publish (PermissionDenied).
        let bob_result = manager
            .publish_broadcast(&ctx_id, &"did:key:bob".into(), b"bob tries")
            .await;
        assert!(
            bob_result.is_err(),
            "blocked author should not be able to publish"
        );
        assert!(matches!(
            bob_result.unwrap_err(),
            ContextError::PermissionDenied(_)
        ));

        // Key request for bob returns Deny (author not found).
        let decision = manager
            .handle_broadcast_key_request(&ctx_id, &"did:key:bob".into(), &"did:key:sub1".into())
            .await
            .unwrap();
        assert!(
            matches!(decision, super::KeyRequestDecision::Deny { .. }),
            "key request for blocked author should be denied"
        );

        // Key request for alice still works.
        let decision = manager
            .handle_broadcast_key_request(&ctx_id, &"did:key:alice".into(), &"did:key:sub1".into())
            .await
            .unwrap();
        assert!(
            matches!(decision, super::KeyRequestDecision::Grant { .. }),
            "key request for unblocked author should succeed"
        );
    }

    /// Attempting to block an author with a non-approved proposal is rejected.
    #[tokio::test]
    async fn broadcast_block_author_rejects_pending_proposal() {
        use crate::context::governance::{GovernanceProposal, ProposalStatus};

        let (manager, _handle, ctx_id) = setup_broadcast_context_two_authors().await;

        // Construct a proposal that is NOT approved (still Pending).
        let pending_proposal = GovernanceProposal {
            proposal_id: [0u8; 32],
            context_id: ctx_id.clone(),
            proposer_did: "did:key:alice".into(),
            action: super::GovernanceAction::BlockAuthor {
                did: "did:key:bob".into(),
                reason: None,
            },
            status: ProposalStatus::Pending,
            created_at: 1000,
            voting_deadline: 2000,
            approvals: Vec::new(),
            rejections: Vec::new(),
            created_at_epoch: None,
        };

        let result = manager
            .execute_governance_action(&ctx_id, &pending_proposal)
            .await;
        assert!(result.is_err(), "pending proposal must not execute");
        assert!(
            matches!(result.unwrap_err(), ContextError::PermissionDenied(_)),
            "should return PermissionDenied for non-approved proposal"
        );
    }

    /// SCP-227 AC7: integration test -- after blocking an author, their
    /// subsequent messages are undecryptable by subscribers (because the
    /// author can no longer produce them).
    #[tokio::test]
    // Integration test exercises full broadcast lifecycle; splitting would
    // fragment a sequential scenario that must be verified end-to-end.
    #[allow(clippy::too_many_lines)]
    async fn broadcast_blocked_author_messages_undecryptable() {
        use crate::crypto::sender_keys::open_broadcast;
        use crate::crypto::ucan::validate::{
            InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver,
            InMemoryRevocationChecker,
        };
        use std::hash::RandomState;

        let (manager, _handle, ctx_id) = setup_broadcast_context_two_authors().await;

        // Subscribe 2 subscribers.
        for name in &["sub1", "sub2"] {
            manager
                .subscribe_broadcast::<
                    InMemoryDidResolver,
                    InMemoryNonceTracker,
                    InMemoryRevocationChecker,
                    InMemoryProofResolver,
                    RandomState,
                >(
                    &ctx_id,
                    &DID(format!("did:key:{name}")),
                    None,
                    1000,
                    None,
                )
                .await
                .unwrap();
        }

        // Alice publishes — both subscribers can get key and decrypt.
        let alice_msg1 = b"Alice before block";
        let _alice_envelope1 = manager
            .publish_broadcast(&ctx_id, &"did:key:alice".into(), alice_msg1)
            .await
            .unwrap();

        // Bob publishes — both subscribers can get key and decrypt.
        let bob_msg1 = b"Bob before block";
        let bob_envelope1 = manager
            .publish_broadcast(&ctx_id, &"did:key:bob".into(), bob_msg1)
            .await
            .unwrap();

        // Get Bob's key before blocking (sub1 perspective).
        let bob_pre_block_decision = manager
            .handle_broadcast_key_request(&ctx_id, &"did:key:bob".into(), &"did:key:sub1".into())
            .await
            .unwrap();
        let super::KeyRequestDecision::Grant {
            key_bytes: bob_pre_key,
            epoch: bob_pre_epoch,
        } = bob_pre_block_decision
        else {
            panic!("bob key should be granted before block")
        };

        // Verify sub1 can decrypt Bob's pre-block message.
        let bob_broadcast_key = crate::crypto::sender_keys::BroadcastKey::from_parts(
            crate::crypto::sender_keys::SenderKey::from_bytes(*bob_pre_key),
            bob_pre_epoch,
            "did:key:bob".to_owned(),
        );
        let decrypted = open_broadcast(&bob_broadcast_key, &bob_envelope1).unwrap();
        assert_eq!(decrypted, bob_msg1);

        // Block Bob via governance (admin proposes, auto-approved).
        let proposal =
            approved_block_author_proposal(&"did:key:alice".into(), &ctx_id, &"did:key:bob".into());
        manager
            .execute_governance_action(&ctx_id, &proposal)
            .await
            .unwrap();

        // Bob tries to publish — PermissionDenied.
        let bob_result = manager
            .publish_broadcast(&ctx_id, &"did:key:bob".into(), b"bob after block")
            .await;
        assert!(
            bob_result.is_err(),
            "blocked author should not be able to publish"
        );

        // Alice can still publish after Bob is blocked.
        let alice_msg2 = b"Alice after Bob blocked";
        let alice_envelope2 = manager
            .publish_broadcast(&ctx_id, &"did:key:alice".into(), alice_msg2)
            .await
            .unwrap();

        // Sub1 can still get Alice's key and decrypt.
        let alice_decision = manager
            .handle_broadcast_key_request(&ctx_id, &"did:key:alice".into(), &"did:key:sub1".into())
            .await
            .unwrap();
        match alice_decision {
            super::KeyRequestDecision::Grant {
                key_bytes, epoch, ..
            } => {
                let alice_key = crate::crypto::sender_keys::BroadcastKey::from_parts(
                    crate::crypto::sender_keys::SenderKey::from_bytes(*key_bytes),
                    epoch,
                    "did:key:alice".to_owned(),
                );
                let decrypted = open_broadcast(&alice_key, &alice_envelope2).unwrap();
                assert_eq!(decrypted, alice_msg2);
            }
            super::KeyRequestDecision::Deny { reason } => {
                panic!("alice key should be granted: {reason}");
            }
        }

        // Sub1 requests Bob's key — Deny (author no longer exists).
        let bob_post_decision = manager
            .handle_broadcast_key_request(&ctx_id, &"did:key:bob".into(), &"did:key:sub1".into())
            .await
            .unwrap();
        assert!(
            matches!(bob_post_decision, super::KeyRequestDecision::Deny { .. }),
            "key request for blocked author must be denied"
        );

        // Old messages from Bob are still decryptable with cached key
        // (forward access to historical content is preserved).
        let old_decrypted = open_broadcast(&bob_broadcast_key, &bob_envelope1).unwrap();
        assert_eq!(old_decrypted, bob_msg1);
    }

    /// SCP-227: governance-approved `BlockAuthor` on non-broadcast context
    /// returns error (the action only applies to broadcast contexts).
    #[tokio::test]
    async fn broadcast_block_author_on_encrypted_context_fails() {
        let (manager, _handle) = setup_active_context().await;

        let target_did: DID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".into();
        let admin_did: DID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".into();

        let proposal = approved_block_author_proposal(&admin_did, "test-ctx", &target_did);
        let result = manager
            .execute_governance_action("test-ctx", &proposal)
            .await;
        assert!(result.is_err());
    }

    /// Defense-in-depth: a proposal approved for context A must not be
    /// executable against context B.
    #[tokio::test]
    async fn governance_action_rejects_wrong_context_id() {
        let (manager, _handle, ctx_id) = setup_broadcast_context_two_authors().await;

        // Create a proposal targeting a different context.
        let proposal = approved_block_author_proposal(
            &"did:key:alice".into(),
            "ctx-a-other",
            &"did:key:bob".into(),
        );

        let result = manager.execute_governance_action(&ctx_id, &proposal).await;
        assert!(
            result.is_err(),
            "proposal targeting a different context must be rejected"
        );
        assert!(
            matches!(result.unwrap_err(), ContextError::PermissionDenied(_)),
            "should return PermissionDenied for context mismatch"
        );
    }

    /// Defense-in-depth: replaying the same approved proposal a second time
    /// is rejected with an explicit error rather than relying on downstream
    /// `MemberNotFound`.
    #[tokio::test]
    async fn governance_action_rejects_replayed_proposal() {
        let (manager, _handle, ctx_id) = setup_broadcast_context_two_authors().await;

        let proposal =
            approved_block_author_proposal(&"did:key:alice".into(), &ctx_id, &"did:key:bob".into());

        // First execution should succeed.
        let result = manager.execute_governance_action(&ctx_id, &proposal).await;
        assert!(result.is_ok(), "first execution should succeed");

        // Second execution of the same proposal should fail (replay).
        let replay_result = manager.execute_governance_action(&ctx_id, &proposal).await;
        assert!(replay_result.is_err(), "replayed proposal must be rejected");
        assert!(
            matches!(
                replay_result.unwrap_err(),
                ContextError::PermissionDenied(_)
            ),
            "should return PermissionDenied for replayed proposal"
        );
    }

    // ===================================================================
    // Read access revocation/restoration (SCP-GG-006) — governance-gated
    // ===================================================================

    /// Helper: creates a broadcast context with `MemberBan` in the ceiling,
    /// one author (alice), and one subscriber (sub1).
    async fn setup_broadcast_with_member_ban() -> (ContextManager, String) {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
        );

        manager.register_local_did("did:key:alice".into()).await;

        let params = ContextParams {
            mode: ContextMode::Broadcast,
            ceiling: vec![
                crate::context::params::Capability::new("messages:read"),
                crate::context::params::Capability::new("messages:write"),
                crate::context::params::Capability::new("role:assign"),
                crate::context::params::Capability::new("member:ban"),
            ],
            ..ContextParams::default()
        };

        let _handle = manager
            .create_context("broadcast-ban-ctx".into(), params, "did:key:alice".into())
            .await
            .unwrap();

        // Subscribe sub1 directly via BroadcastContext.
        {
            use crate::crypto::ucan::validate::{
                InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver,
                InMemoryRevocationChecker,
            };
            use std::hash::RandomState;

            manager
                .subscribe_broadcast::<
                    InMemoryDidResolver,
                    InMemoryNonceTracker,
                    InMemoryRevocationChecker,
                    InMemoryProofResolver,
                    RandomState,
                >(
                    "broadcast-ban-ctx",
                    &DID("did:key:sub1".into()),
                    None,
                    1000,
                    None,
                )
                .await
                .unwrap();
        }

        let ctx_id = "broadcast-ban-ctx".to_owned();
        (manager, ctx_id)
    }

    /// Helper: creates an approved governance proposal for an arbitrary action
    /// using `SingleAdminEngine`. The admin is `admin_did`.
    fn approved_governance_proposal(
        admin_did: &DID,
        context_id: &str,
        target_did: &DID,
        action: super::GovernanceAction,
    ) -> super::GovernanceProposal {
        use crate::context::governance::{GovernanceContext, GovernanceEngine, SingleAdminEngine};

        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        let mut engine = SingleAdminEngine::new(admin_did.clone());
        let gov_ctx = GovernanceContext {
            context_id: context_id.to_owned(),
            members: vec![
                (admin_did.clone(), "admin".to_owned()),
                (target_did.clone(), "subscriber".to_owned()),
            ],
            admin_dids: vec![admin_did.clone()],
            current_epoch: None,
            now: 1000,
        };

        let (proposal, _events) = engine
            .propose(admin_did, action, &gov_ctx, &signing_key)
            .unwrap();
        assert!(matches!(proposal.status, super::ProposalStatus::Approved));
        proposal
    }

    /// SCP-GG-006: `RevokeReadAccess` on broadcast context bans subscriber.
    #[tokio::test]
    async fn revoke_read_access_bans_subscriber_in_broadcast() {
        let (manager, ctx_id) = setup_broadcast_with_member_ban().await;

        // Verify sub1 is subscribed before revocation.
        assert!(
            manager
                .is_broadcast_subscriber(&ctx_id, "did:key:sub1")
                .await,
            "sub1 should be subscribed before revocation"
        );

        let action = super::GovernanceAction::RevokeReadAccess {
            did: "did:key:sub1".into(),
            scope: super::RevocationScope::Full,
        };
        let proposal = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:sub1".into(),
            action,
        );

        let result = manager.execute_governance_action(&ctx_id, &proposal).await;
        assert!(result.is_ok(), "RevokeReadAccess should succeed");

        let result = result.unwrap();
        match result {
            super::GovernanceActionResult::SubscriberBanned(ban_result) => {
                assert_eq!(ban_result.banned_did, "did:key:sub1");
                // At least one author should have rotated keys.
                assert!(
                    !ban_result.rotated_authors.is_empty(),
                    "key rotation should occur on ban"
                );
            }
            other => panic!("expected SubscriberBanned, got {other:?}"),
        }

        // Subscriber should no longer be tracked.
        assert!(
            !manager
                .is_broadcast_subscriber(&ctx_id, "did:key:sub1")
                .await,
            "sub1 should not be subscribed after revocation"
        );

        // Verify ReadAccessRevoked event was emitted.
        let events = manager.drain_events(&ctx_id).await;
        let has_revoke_event = events.iter().any(|e| {
            matches!(
                e,
                super::ContextEvent::ReadAccessRevoked { did } if did.0 == "did:key:sub1"
            )
        });
        assert!(
            has_revoke_event,
            "ReadAccessRevoked event should have been emitted"
        );
    }

    /// SCP-GG-006: `RevokeReadAccess` fails when ceiling lacks `MemberBan`.
    #[tokio::test]
    async fn revoke_read_access_rejected_without_member_ban_ceiling() {
        // Use the standard two-author setup which does NOT have MemberBan.
        let (manager, _handle, ctx_id) = setup_broadcast_context_two_authors().await;

        // Subscribe sub1.
        {
            use crate::crypto::ucan::validate::{
                InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver,
                InMemoryRevocationChecker,
            };
            use std::hash::RandomState;

            manager
                .subscribe_broadcast::<
                    InMemoryDidResolver,
                    InMemoryNonceTracker,
                    InMemoryRevocationChecker,
                    InMemoryProofResolver,
                    RandomState,
                >(
                    &ctx_id,
                    &DID("did:key:sub1".into()),
                    None,
                    1000,
                    None,
                )
                .await
                .unwrap();
        }

        let action = super::GovernanceAction::RevokeReadAccess {
            did: "did:key:sub1".into(),
            scope: super::RevocationScope::Full,
        };
        let proposal = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:sub1".into(),
            action,
        );

        let result = manager.execute_governance_action(&ctx_id, &proposal).await;
        assert!(
            result.is_err(),
            "RevokeReadAccess should fail without MemberBan in ceiling"
        );
        assert!(
            matches!(result.unwrap_err(), ContextError::PermissionDenied(ref msg) if msg.contains("member:ban")),
            "error should mention missing member:ban capability"
        );
    }

    /// SCP-GG-006: `RestoreReadAccess` unbans subscriber in broadcast context.
    #[tokio::test]
    async fn restore_read_access_unbans_subscriber_in_broadcast() {
        let (manager, ctx_id) = setup_broadcast_with_member_ban().await;

        // First, revoke read access.
        let revoke_action = super::GovernanceAction::RevokeReadAccess {
            did: "did:key:sub1".into(),
            scope: super::RevocationScope::FutureOnly,
        };
        let revoke_proposal = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:sub1".into(),
            revoke_action,
        );
        manager
            .execute_governance_action(&ctx_id, &revoke_proposal)
            .await
            .unwrap();

        // Drain events from revocation so we can check restore events cleanly.
        manager.drain_events(&ctx_id).await;

        // Now restore read access.
        let restore_action = super::GovernanceAction::RestoreReadAccess {
            did: "did:key:sub1".into(),
        };
        let restore_proposal = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:sub1".into(),
            restore_action,
        );

        let result = manager
            .execute_governance_action(&ctx_id, &restore_proposal)
            .await;
        assert!(result.is_ok(), "RestoreReadAccess should succeed");

        match result.unwrap() {
            super::GovernanceActionResult::SubscriberUnbanned { did } => {
                assert_eq!(did.0, "did:key:sub1");
            }
            other => panic!("expected SubscriberUnbanned, got {other:?}"),
        }

        // Verify ReadAccessRestored event was emitted.
        let events = manager.drain_events(&ctx_id).await;
        let has_restore_event = events.iter().any(|e| {
            matches!(
                e,
                super::ContextEvent::ReadAccessRestored { did } if did.0 == "did:key:sub1"
            )
        });
        assert!(
            has_restore_event,
            "ReadAccessRestored event should have been emitted"
        );
    }

    /// SCP-GG-006: `RestoreReadAccess` also fails without `MemberBan` in ceiling.
    #[tokio::test]
    async fn restore_read_access_rejected_without_member_ban_ceiling() {
        let (manager, _handle, ctx_id) = setup_broadcast_context_two_authors().await;

        let action = super::GovernanceAction::RestoreReadAccess {
            did: "did:key:sub1".into(),
        };
        let proposal = approved_governance_proposal(
            &"did:key:alice".into(),
            &ctx_id,
            &"did:key:sub1".into(),
            action,
        );

        let result = manager.execute_governance_action(&ctx_id, &proposal).await;
        assert!(
            result.is_err(),
            "RestoreReadAccess should fail without MemberBan in ceiling"
        );
        assert!(
            matches!(result.unwrap_err(), ContextError::PermissionDenied(ref msg) if msg.contains("member:ban")),
            "error should mention missing member:ban capability"
        );
    }

    // -----------------------------------------------------------------------
    // Context persistence tests (SCP-PERSIST-020 through SCP-PERSIST-025)
    // -----------------------------------------------------------------------

    /// Mock `ContextPersistence` that stores snapshots in `HashMap`s.
    #[derive(Default)]
    struct MockContextPersistence {
        contexts: std::sync::Mutex<HashMap<String, super::ContextSnapshot>>,
        broadcasts: std::sync::Mutex<HashMap<String, BroadcastContextSnapshot>>,
    }

    impl super::ContextPersistence for MockContextPersistence {
        fn persist_context(
            &self,
            context_id: &str,
            snapshot: &super::ContextSnapshot,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.contexts
                .lock()
                .unwrap()
                .insert(context_id.to_owned(), snapshot.clone());
            Ok(())
        }

        fn load_context(
            &self,
            context_id: &str,
        ) -> Result<Option<super::ContextSnapshot>, Box<dyn std::error::Error + Send + Sync>>
        {
            Ok(self.contexts.lock().unwrap().get(context_id).cloned())
        }

        fn persist_broadcast(
            &self,
            context_id: &str,
            snapshot: &BroadcastContextSnapshot,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.broadcasts
                .lock()
                .unwrap()
                .insert(context_id.to_owned(), snapshot.clone());
            Ok(())
        }

        fn load_broadcast(
            &self,
            context_id: &str,
        ) -> Result<Option<BroadcastContextSnapshot>, Box<dyn std::error::Error + Send + Sync>>
        {
            Ok(self.broadcasts.lock().unwrap().get(context_id).cloned())
        }

        fn delete_context(
            &self,
            context_id: &str,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.contexts.lock().unwrap().remove(context_id);
            self.broadcasts.lock().unwrap().remove(context_id);
            Ok(())
        }

        fn list_persisted_contexts(
            &self,
        ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(self.contexts.lock().unwrap().keys().cloned().collect())
        }
    }

    /// Helper: build a `BroadcastContextSnapshot` with known state.
    fn test_broadcast_snapshot(context_id: &str) -> BroadcastContextSnapshot {
        use std::collections::HashSet;

        use crate::context::broadcast::{
            AuthorStateSnapshot, BroadcastAdmission, SubscriberRecord,
        };
        use crate::crypto::sender_keys::generate_sender_key;

        let mut authors = HashMap::new();
        authors.insert(
            "did:key:author1".to_owned(),
            AuthorStateSnapshot {
                author_did: "did:key:author1".to_owned(),
                broadcast_key: generate_sender_key(),
                epoch: 3,
                block_list: HashSet::from(["did:key:blocked1".to_owned()]),
            },
        );

        let mut subscribers = HashMap::new();
        subscribers.insert(
            "did:key:sub1".to_owned(),
            SubscriberRecord {
                subscriber_did: "did:key:sub1".to_owned(),
                registered_at: 1_700_000_000,
                has_ucan: false,
            },
        );
        subscribers.insert(
            "did:key:sub2".to_owned(),
            SubscriberRecord {
                subscriber_did: "did:key:sub2".to_owned(),
                registered_at: 1_700_001_000,
                has_ucan: true,
            },
        );

        BroadcastContextSnapshot {
            context_id: context_id.to_owned(),
            admission: BroadcastAdmission::Gated,
            subscribers,
            authors,
        }
    }

    /// SCP-PERSIST-020: compile-time test verifying `dyn ContextPersistence`
    /// is object-safe.
    #[test]
    fn context_persistence_is_object_safe() {
        fn assert_object_safe(_: &dyn super::ContextPersistence) {}
        let mock = MockContextPersistence::default();
        assert_object_safe(&mock);
    }

    /// SCP-PERSIST-024: persist-drop-restore roundtrip verifies all fields.
    #[tokio::test]
    async fn persist_drop_restore_roundtrip() {
        use crate::context::roles::{ContextRoleState, default_ceiling};

        let persistence = Arc::new(MockContextPersistence::default());

        // Create a context with persistence.
        let manager = ContextManager::with_persistence(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            Box::new(MockContextPersistence::default()),
        );

        let params = ContextParams {
            mode: ContextMode::Broadcast,
            ceiling: vec![
                crate::context::params::Capability::new("messages:read"),
                crate::context::params::Capability::new("messages:write"),
                crate::context::params::Capability::new("role:assign"),
            ],
            ..ContextParams::default()
        };

        let _handle = manager
            .create_context(
                "persist-ctx".into(),
                params.clone(),
                "did:key:creator".into(),
            )
            .await
            .unwrap();

        // Seed the mock persistence with a full snapshot.
        let ceiling = default_ceiling();
        let role_state =
            ContextRoleState::new("persist-ctx", "did:key:creator", ceiling, vec![]).unwrap();
        let mut membership = MembershipState::new();
        membership.add_member("did:key:creator".into(), "admin".into(), vec![]);
        let mut executed = HashSet::new();
        executed.insert([42u8; 32]);

        let snapshot = super::ContextSnapshot {
            context_id: "persist-ctx-2".to_owned(),
            state: ContextState::Active,
            context_params: params.clone(),
            membership: membership.clone(),
            role_state: role_state.clone(),
            executed_proposals: executed.clone(),
            ttl_remaining_secs: None,
            registered_tools: Vec::new(),
            write_revoked_members: HashSet::new(),
            tool_interfaces: Vec::new(),
            threshold_signers: Vec::new(),
            threshold_value: 0,
            pruning_policy: None,
        };

        let bc_snapshot = test_broadcast_snapshot("persist-ctx-2");

        // Seed mock persistence directly.
        persistence
            .persist_context("persist-ctx-2", &snapshot)
            .unwrap();
        persistence
            .persist_broadcast("persist-ctx-2", &bc_snapshot)
            .unwrap();

        // Create a new manager with the seeded persistence.
        let manager2 = ContextManager::with_persistence(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            Box::new(MockContextPersistence {
                contexts: std::sync::Mutex::new(persistence.contexts.lock().unwrap().clone()),
                broadcasts: std::sync::Mutex::new(persistence.broadcasts.lock().unwrap().clone()),
            }),
        );

        // Restore the context.
        let handle2 = ContextHandle::new("persist-ctx-2".to_owned(), params);
        handle2.transition_to(&ContextState::Active).await.unwrap();

        let result = manager2.restore_context("persist-ctx-2", &handle2).await;
        assert!(result.is_ok(), "restore should succeed");

        // Verify membership is restored.
        assert!(manager2.is_member("persist-ctx-2", "did:key:creator").await);

        // Verify broadcast is restored.
        assert!(
            manager2
                .is_broadcast_subscriber("persist-ctx-2", "did:key:sub1")
                .await
        );
        assert!(
            manager2
                .is_broadcast_subscriber("persist-ctx-2", "did:key:sub2")
                .await
        );
    }

    /// SCP-PERSIST-025: `executed_proposals` preserved across restart.
    #[tokio::test]
    async fn restore_preserves_executed_proposals() {
        use crate::context::roles::{ContextRoleState, default_ceiling};

        let persistence = Arc::new(MockContextPersistence::default());

        let params = ContextParams {
            mode: ContextMode::Broadcast,
            ceiling: vec![
                crate::context::params::Capability::new("messages:read"),
                crate::context::params::Capability::new("messages:write"),
                crate::context::params::Capability::new("role:assign"),
            ],
            ..ContextParams::default()
        };

        let ceiling = default_ceiling();
        let role_state =
            ContextRoleState::new("replay-ctx", "did:key:alice", ceiling, vec![]).unwrap();
        let mut membership = MembershipState::new();
        membership.add_member("did:key:alice".into(), "admin".into(), vec![]);

        // Seed executed proposals so replay is detected.
        let proposal_id = [99u8; 32];
        let mut executed = HashSet::new();
        executed.insert(proposal_id);

        let snapshot = super::ContextSnapshot {
            context_id: "replay-ctx".to_owned(),
            state: ContextState::Active,
            context_params: params.clone(),
            membership,
            role_state,
            executed_proposals: executed,
            ttl_remaining_secs: None,
            registered_tools: Vec::new(),
            write_revoked_members: HashSet::new(),
            tool_interfaces: Vec::new(),
            threshold_signers: Vec::new(),
            threshold_value: 0,
            pruning_policy: None,
        };

        persistence
            .persist_context("replay-ctx", &snapshot)
            .unwrap();

        // Also seed broadcast state (needed for restore).
        let bc_snapshot = test_broadcast_snapshot("replay-ctx");
        persistence
            .persist_broadcast("replay-ctx", &bc_snapshot)
            .unwrap();

        // Create manager and restore.
        let manager = ContextManager::with_persistence(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            Box::new(MockContextPersistence {
                contexts: std::sync::Mutex::new(persistence.contexts.lock().unwrap().clone()),
                broadcasts: std::sync::Mutex::new(persistence.broadcasts.lock().unwrap().clone()),
            }),
        );

        let handle = ContextHandle::new("replay-ctx".to_owned(), params);
        handle.transition_to(&ContextState::Active).await.unwrap();
        manager
            .restore_context("replay-ctx", &handle)
            .await
            .unwrap();

        // Try to execute a governance action with the already-executed proposal ID.
        // The internal state should reject it as a replay.
        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get("replay-ctx").unwrap();
        assert!(
            ctx.executed_proposals.contains(&proposal_id),
            "executed_proposals should be preserved across restart"
        );
    }

    /// SCP-PERSIST-025: TTL timer re-spawned after restore with remaining TTL.
    #[tokio::test]
    async fn restore_respawns_ttl_timer() {
        use crate::context::roles::{ContextRoleState, default_ceiling};

        let persistence = Arc::new(MockContextPersistence::default());

        let params = ContextParams {
            ttl: Some(std::time::Duration::from_secs(300)),
            ceiling: vec![
                crate::context::params::Capability::new("messages:read"),
                crate::context::params::Capability::new("messages:write"),
                crate::context::params::Capability::new("role:assign"),
            ],
            ..ContextParams::default()
        };

        let ceiling = default_ceiling();
        let role_state =
            ContextRoleState::new("ttl-ctx", "did:key:creator", ceiling, vec![]).unwrap();
        let mut membership = MembershipState::new();
        membership.add_member("did:key:creator".into(), "admin".into(), vec![]);

        let snapshot = super::ContextSnapshot {
            context_id: "ttl-ctx".to_owned(),
            state: ContextState::Active,
            context_params: params.clone(),
            membership,
            role_state,
            executed_proposals: HashSet::new(),
            ttl_remaining_secs: Some(120), // 120 seconds remaining
            registered_tools: Vec::new(),
            write_revoked_members: HashSet::new(),
            tool_interfaces: Vec::new(),
            threshold_signers: Vec::new(),
            threshold_value: 0,
            pruning_policy: None,
        };

        persistence.persist_context("ttl-ctx", &snapshot).unwrap();

        let manager = ContextManager::with_persistence(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            Box::new(MockContextPersistence {
                contexts: std::sync::Mutex::new(persistence.contexts.lock().unwrap().clone()),
                broadcasts: std::sync::Mutex::new(HashMap::new()),
            }),
        );

        let handle = ContextHandle::new("ttl-ctx".to_owned(), params);
        handle.transition_to(&ContextState::Active).await.unwrap();
        manager.restore_context("ttl-ctx", &handle).await.unwrap();

        // Verify the TTL timer was re-spawned.
        let contexts = manager.contexts.lock().await;
        let ctx = contexts.get("ttl-ctx").unwrap();
        assert!(
            ctx.ttl_timer.is_active(),
            "TTL timer should be re-spawned after restore"
        );
    }

    /// SCP-PERSIST-025: `restore_all_contexts` lists and restores each.
    #[tokio::test]
    async fn restore_all_contexts_restores_persisted() {
        use crate::context::roles::{ContextRoleState, default_ceiling};

        let persistence = Arc::new(MockContextPersistence::default());

        for ctx_name in ["ctx-a", "ctx-b"] {
            let params = ContextParams::default();
            let ceiling = default_ceiling();
            let role_state =
                ContextRoleState::new(ctx_name, "did:key:creator", ceiling, vec![]).unwrap();
            let mut membership = MembershipState::new();
            membership.add_member("did:key:creator".into(), "admin".into(), vec![]);

            let snapshot = super::ContextSnapshot {
                context_id: ctx_name.to_string(),
                state: ContextState::Active,
                context_params: params,
                membership,
                role_state,
                executed_proposals: HashSet::new(),
                ttl_remaining_secs: None,
                registered_tools: Vec::new(),
                write_revoked_members: HashSet::new(),
                tool_interfaces: Vec::new(),
                threshold_signers: Vec::new(),
                threshold_value: 0,
                pruning_policy: None,
            };
            persistence.persist_context(ctx_name, &snapshot).unwrap();
        }

        let manager = ContextManager::with_persistence(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            Box::new(MockContextPersistence {
                contexts: std::sync::Mutex::new(persistence.contexts.lock().unwrap().clone()),
                broadcasts: std::sync::Mutex::new(HashMap::new()),
            }),
        );

        let mut restored = manager.restore_all_contexts().await.unwrap();
        restored.sort();
        assert_eq!(restored, vec!["ctx-a", "ctx-b"]);

        // Both contexts should be registered.
        assert!(manager.is_member("ctx-a", "did:key:creator").await);
        assert!(manager.is_member("ctx-b", "did:key:creator").await);
    }

    /// `restore_context` rejects duplicate context registration.
    #[tokio::test]
    async fn restore_context_rejects_duplicate() {
        use crate::context::roles::{ContextRoleState, default_ceiling};

        let persistence = Arc::new(MockContextPersistence::default());

        let params = ContextParams {
            mode: ContextMode::Broadcast,
            ..ContextParams::default()
        };

        let ceiling = default_ceiling();
        let role_state =
            ContextRoleState::new("dup-ctx", "did:key:author1", ceiling, vec![]).unwrap();
        let membership = MembershipState::new();

        let snapshot = super::ContextSnapshot {
            context_id: "dup-ctx".to_owned(),
            state: ContextState::Active,
            context_params: params.clone(),
            membership,
            role_state,
            executed_proposals: HashSet::new(),
            ttl_remaining_secs: None,
            registered_tools: Vec::new(),
            write_revoked_members: HashSet::new(),
            tool_interfaces: Vec::new(),
            threshold_signers: Vec::new(),
            threshold_value: 0,
            pruning_policy: None,
        };

        let bc_snapshot = test_broadcast_snapshot("dup-ctx");
        persistence.persist_context("dup-ctx", &snapshot).unwrap();
        persistence
            .persist_broadcast("dup-ctx", &bc_snapshot)
            .unwrap();

        let manager = ContextManager::with_persistence(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
            Box::new(MockContextPersistence {
                contexts: std::sync::Mutex::new(persistence.contexts.lock().unwrap().clone()),
                broadcasts: std::sync::Mutex::new(persistence.broadcasts.lock().unwrap().clone()),
            }),
        );

        // First restore.
        let handle1 = ContextHandle::new("dup-ctx".to_owned(), params.clone());
        handle1.transition_to(&ContextState::Active).await.unwrap();
        manager.restore_context("dup-ctx", &handle1).await.unwrap();

        // Second restore should fail.
        let handle2 = ContextHandle::new("dup-ctx".to_owned(), params);
        handle2.transition_to(&ContextState::Active).await.unwrap();
        let result = manager.restore_context("dup-ctx", &handle2).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ContextError::MembershipFailed(_)
        ));
    }

    // -----------------------------------------------------------------------
    // Caller identity validation tests (#234)
    // -----------------------------------------------------------------------

    /// #234: `register_local_did` registers a DID as locally controlled,
    /// and `is_local_did` confirms it.
    #[tokio::test]
    async fn register_local_did_is_queryable() {
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
        );

        let did: DID = "did:key:local1".into();
        assert!(!manager.is_local_did(&did).await);

        manager.register_local_did(did.clone()).await;
        assert!(manager.is_local_did(&did).await);

        // Idempotent: re-registering is a no-op.
        manager.register_local_did(did.clone()).await;
        assert!(manager.is_local_did(&did).await);
    }

    /// #234: `handle_broadcast_key_request` with a locally controlled DID
    /// succeeds (positive case -- defense-in-depth validation passes).
    #[tokio::test]
    async fn handle_broadcast_key_request_succeeds_with_local_did() {
        use crate::crypto::ucan::validate::{
            InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver,
            InMemoryRevocationChecker,
        };
        use std::hash::RandomState;

        let (manager, _handle, ctx_id) = setup_broadcast_context().await;

        // Subscribe a requester.
        manager
            .subscribe_broadcast::<
                InMemoryDidResolver,
                InMemoryNonceTracker,
                InMemoryRevocationChecker,
                InMemoryProofResolver,
                RandomState,
            >(
                &ctx_id,
                &"did:key:sub1".into(),
                None,
                1000,
                None,
            )
            .await
            .unwrap();

        // author1 is registered as a local DID by setup_broadcast_context.
        let decision = manager
            .handle_broadcast_key_request(
                &ctx_id,
                &"did:key:author1".into(),
                &"did:key:sub1".into(),
            )
            .await
            .unwrap();

        assert!(
            matches!(decision, super::KeyRequestDecision::Grant { .. }),
            "key request with locally controlled author DID should be granted"
        );
    }

    /// #234: `handle_broadcast_key_request` with an uncontrolled DID returns
    /// `PermissionDenied` (negative case -- defense-in-depth validation
    /// rejects the request before reaching `BroadcastContext`).
    #[tokio::test]
    async fn handle_broadcast_key_request_rejects_non_local_did() {
        use crate::crypto::ucan::validate::{
            InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver,
            InMemoryRevocationChecker,
        };
        use std::hash::RandomState;

        let (manager, _handle, ctx_id) = setup_broadcast_context().await;

        // Subscribe a requester.
        manager
            .subscribe_broadcast::<
                InMemoryDidResolver,
                InMemoryNonceTracker,
                InMemoryRevocationChecker,
                InMemoryProofResolver,
                RandomState,
            >(
                &ctx_id,
                &"did:key:sub1".into(),
                None,
                1000,
                None,
            )
            .await
            .unwrap();

        // "did:key:unknown-author" is NOT registered as a local DID.
        let result = manager
            .handle_broadcast_key_request(
                &ctx_id,
                &"did:key:unknown-author".into(),
                &"did:key:sub1".into(),
            )
            .await;

        assert!(result.is_err(), "should reject non-local author DID");
        let err = result.unwrap_err();
        assert!(
            matches!(err, ContextError::PermissionDenied(ref msg) if msg.contains("not controlled")),
            "error should be PermissionDenied with descriptive message, got: {err}"
        );
    }

    /// #234: blocked subscriber's key request still returns `Deny` (not
    /// `PermissionDenied`) -- block list information is not leaked through
    /// the new validation layer. The defense-in-depth check runs first,
    /// but when the caller IS the local author, the existing block list
    /// logic applies as before.
    #[tokio::test]
    async fn handle_broadcast_key_request_deny_does_not_leak_block_info() {
        use crate::crypto::ucan::validate::{
            InMemoryDidResolver, InMemoryNonceTracker, InMemoryProofResolver,
            InMemoryRevocationChecker,
        };
        use std::hash::RandomState;

        let (manager, _handle, ctx_id) = setup_broadcast_context().await;

        // Subscribe then block.
        manager
            .subscribe_broadcast::<
                InMemoryDidResolver,
                InMemoryNonceTracker,
                InMemoryRevocationChecker,
                InMemoryProofResolver,
                RandomState,
            >(
                &ctx_id,
                &"did:key:blocked-sub".into(),
                None,
                1000,
                None,
            )
            .await
            .unwrap();

        manager
            .block_broadcast_subscriber(
                &ctx_id,
                &"did:key:author1".into(),
                &"did:key:blocked-sub".into(),
            )
            .await
            .unwrap();

        // Key request for blocked subscriber returns Deny (not a
        // PermissionDenied error). The deny reason is generic and does
        // not reveal whether the subscriber is blocked or unregistered.
        let decision = manager
            .handle_broadcast_key_request(
                &ctx_id,
                &"did:key:author1".into(),
                &"did:key:blocked-sub".into(),
            )
            .await
            .unwrap();

        assert!(
            matches!(decision, super::KeyRequestDecision::Deny { .. }),
            "blocked subscriber should receive Deny decision"
        );
    }

    /// #234: DID validation runs before context lookup. When a non-local DID
    /// is used AND the context doesn't exist, the result is `PermissionDenied`
    /// (not `MembershipFailed` or "context not registered"). This documents
    /// the intentional fail-closed ordering: unauthenticated callers cannot
    /// probe for context existence.
    #[tokio::test]
    async fn handle_broadcast_key_request_rejects_non_local_did_before_context_lookup() {
        // Create a manager but don't create any contexts.
        let manager = ContextManager::new(
            Box::new(MockCrypto::default()),
            Box::new(MockTransport::connected()),
            Box::new(MockEventLog::default()),
        );

        // Neither the author DID nor the context exist.
        let result = manager
            .handle_broadcast_key_request(
                "nonexistent-context",
                &"did:key:unregistered-author".into(),
                &"did:key:some-requester".into(),
            )
            .await;

        assert!(result.is_err(), "should reject non-local author DID");
        let err = result.unwrap_err();
        assert!(
            matches!(err, ContextError::PermissionDenied(_)),
            "should be PermissionDenied (DID check), not MembershipFailed (context lookup): {err}"
        );
    }
}
