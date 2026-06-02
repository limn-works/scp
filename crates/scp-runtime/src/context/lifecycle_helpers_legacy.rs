// Module-level allow — the legacy `&Supervisor` lock-and-call form held
// per-context guards across await points deliberately (narrowing changes
// lock-ordering semantics). The hoisted bodies preserve that shape;
// allowing the lint crate-locally keeps the hoist byte-identical to the
// legacy behavior.
#![allow(clippy::significant_drop_tightening)]

//! Legacy lifecycle-domain helpers
//! (ADR-049 Phase 2A.9, `lifecycle` domain migration).
//!
//! # Purpose
//!
//! This module preserves the pre-migration `&Supervisor` lock-and-call
//! lifecycle helper bodies for the Phase 2A shim fallback. The live
//! actor path now calls [`crate::context::lifecycle_helpers`], which
//! operates on actor-owned state directly via `&mut PerContextState +
//! &ActorDeps` (or `&ActorDeps` alone for bootstrap entry points that
//! construct fresh state); the shim path keeps these legacy twins
//! until Phase 2A finalization removes all `*_helpers_legacy.rs`
//! modules.
//!
//! # Behavior preservation
//!
//! Every hoisted free function is **behavior-preserving by
//! construction**. Every body is a verbatim copy of the pre-migration
//! `&Supervisor`-shaped helper. `self.X` was already replaced in
//! ADR-049 commit 12 by either:
//!
//! - `supervisor.X_ref().ok_or(NotInitialized)?` for provider slots
//!   lifted to the supervisor (crypto, transport, `event_log`,
//!   `event_tx`, clock, `local_dids`, `key_resolver`), or
//! - `manager_methods::X(supervisor, ...)` /
//!   `<domain>_helpers::X(supervisor, ...)` for the cross-domain and
//!   per-domain free-function helpers hoisted from `ContextManager`.
//!
//! # Legacy twins
//!
//! The `import`/`restore` bootstrap bodies (and their privates
//! `load_persisted_context_state` / `restore_event_log_best_effort`)
//! were deleted at Phase 2A finalization once their dispatch arms moved
//! to the actor-shape `lifecycle_helpers::{import,restore}_context`.
//! `create_context_legacy` survives only because two nested callers
//! (standing-pair second-context creation and the governance
//! child-context migration path) are still `&Supervisor`-shaped; it is
//! removed when those callers reach actor-shape (storage-foundation
//! Step 7).
//!
//! 1. [`export_context_legacy`] — full export body (snapshot + event
//!    log + signed export).
//! 2. [`create_context_legacy`] — full create body (validate, build
//!    `PerContextState`, finalize).
//! 3. [`finalize_create_legacy`] — gauges + governance timeout +
//!    persistence + TTL timer post-creation.
//! 4. [`join_context_legacy`] — F4 escrow dance + MLS add + sender-key
//!    distribute + membership mutate + capture.
//! 5. [`join_context_membership_legacy`] — Phase 4 membership mutations
//!    for join.
//! 6. [`capture_join_payment_legacy`] — Phase 5 escrow capture for
//!    join.
//! 7. [`leave_context_legacy`] — capability check + MLS remove + sender
//!    key cleanup + membership removal + close-on-empty.
//! 8. [`drain_and_deliver_sender_keys_legacy`] — sender-key
//!    distribution drain used by join / leave.
//! 9. [`close_context_legacy`] — single-arg forwarder into
//!    [`close_context_with_key_legacy`].
//! 10. [`close_context_with_key_legacy`] — full close body (gate +
//!     `ttl::close` + cancel timers + final checkpoint + persist).

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use scp_identity::DID;
use scp_protocol::context::builder::ContextCreationError;
use scp_protocol::context::governance::GovernanceModelConfig;
use scp_protocol::context::governance::mls_integration::EpochCoordinator;
use scp_protocol::context::membership::{ContextEvent, KeyPackage, MembershipState, ReceiveBuffer};
use scp_protocol::context::params::GovernanceModel;
use scp_protocol::context::roles::{self, Capability, CapabilityCeiling, ContextRoleState};
use scp_protocol::context::{ContextError, ContextParams, ContextState};
use scp_protocol::economy::budget::MemberBudgetTracker;

use crate::context::ContextHandle;
use crate::context::actor::sequence::SendSequenceTracker;
use crate::context::actor::state::{
    ContextCryptoState, ContextLifecycleState, ContextModeState, RecvSequenceTracker,
};
use crate::context::governance::timeout::{DeadlockDetectionState, GovernanceTimeoutTask};
use crate::context::governance_helpers_legacy;
use crate::context::manager_methods;
use crate::context::state::{
    self, AccessControlState, CommitOperation, EpochState, GovernanceState, PerContextState,
    TtlState,
};
use crate::context::supervisor::Supervisor;
use crate::context::ttl::{self, CloseResult, TtlTimer};

/// Shared expectation message for `Supervisor::with_providers()`
/// inside helpers (ADR-049 commit 12).
// Phase 1 fix-up of ADR-049 (post-review-round-1): per-helper
// `ATTACHED_EXPECT` constants consolidated to the single
// `PROVIDER_NOT_INITIALIZED` definition in `manager_methods`. The
// alias keeps existing call sites intact while routing every emission
// through one canonical message.
use crate::context::manager_methods::PROVIDER_NOT_INITIALIZED as ATTACHED_EXPECT;

// ---------------------------------------------------------------------------
// 1. export_context (top-level)
// ---------------------------------------------------------------------------

/// Exports a context's full state as a transferable `ContextExport`
/// (hoisted body of the legacy
/// [`ContextManager::export_context`](crate::context::lifecycle_helpers::export_context)).
///
/// Captures a `ContextSnapshot`, event log data, and MLS state (empty
/// until #333 lands), then produces a signed export that can be imported
/// into another manager instance.
///
/// # Collaborators
///
/// - `mgr` — manager reference used to reach cross-domain `pub(crate)`
///   helpers (`get_context_arc`, `snapshot_context`) and provider
///   accessors (`event_log_ref`, `clock_ref`).
///
/// # Errors
///
/// Returns [`ContextError::MembershipFailed`] if the context is not
/// registered, or a transport-/persistence-level error from the
/// underlying event-log export.
pub async fn export_context_legacy(
    supervisor: &Supervisor,
    context_id: &str,
    exporter_did: DID,
) -> Result<crate::context::export_import::ContextExport, ContextError> {
    let ctx_id_bytes = scp_protocol::context::context_id_bytes(context_id);

    let snapshot = {
        let ctx_arc = manager_methods::get_context_arc(supervisor, context_id).map_err(|_| {
            ContextError::MembershipFailed(format!(
                "context '{context_id}' not found — cannot export"
            ))
        })?;
        let guard = ctx_arc.lock().await;
        let ctx = &*guard;
        manager_methods::snapshot_context(ctx)
    };

    let event_log_data = supervisor
        .event_log_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?
        .export_event_log_data(&ctx_id_bytes)
        .unwrap_or_default();

    // MLS state is empty until #333 (MLS integration) lands.
    let mls_state = Vec::new();

    crate::context::export_import::create_export(
        snapshot,
        event_log_data,
        mls_state,
        exporter_did,
        crate::context::export_import::ExportScope::Full,
        &**supervisor
            .clock_ref()
            .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?,
    )
}

// ---------------------------------------------------------------------------
// 3. create_context (top-level)
// ---------------------------------------------------------------------------

/// Creates a new SCP context with the two-phase commit pattern (hoisted
/// body of the legacy
/// [`ContextManager::create_context`](crate::context::supervisor::Supervisor::create_context)).
///
/// See the legacy method's doc comment for the full semantics. Byte-
/// identical behavior.
#[allow(clippy::too_many_lines)] // Context creation initializes many subsystems including pseudonym routing.
pub async fn create_context_legacy(
    supervisor: &Supervisor,
    context_id: String,
    params: ContextParams,
    creator_did: DID,
    local_pseudonym: Option<[u8; 32]>,
) -> Result<ContextHandle, ContextCreationError> {
    let crypto = supervisor
        .crypto_ref()
        .ok_or_else(|| ContextCreationError::CreationFailed(ATTACHED_EXPECT.to_owned()))?;
    let transport = supervisor
        .transport_ref()
        .ok_or_else(|| ContextCreationError::CreationFailed(ATTACHED_EXPECT.to_owned()))?;
    let event_log = supervisor
        .event_log_ref()
        .ok_or_else(|| ContextCreationError::CreationFailed(ATTACHED_EXPECT.to_owned()))?;
    let clock = supervisor
        .clock_ref()
        .ok_or_else(|| ContextCreationError::CreationFailed(ATTACHED_EXPECT.to_owned()))?;
    let key_resolver = supervisor
        .key_resolver_ref()
        .ok_or_else(|| ContextCreationError::CreationFailed(ATTACHED_EXPECT.to_owned()))?;
    let next_generation = supervisor.next_generation_ref();
    // Defense-in-depth: verify creator's SDK version satisfies min_protocol_version.
    params.check_version_compatibility(scp_protocol::envelope::SCP_PROTOCOL_VERSION)?;
    state::validate_governance_model(&params.governance)?;
    crate::context::lifecycle_logic::validate_consequence_rules(
        &params.consequence_rules,
        &params.consequence_config,
    )?;
    scp_protocol::economy::policy::validate_economic_policy_metrics(
        params.economic_policy.as_ref(),
    )
    .map_err(|e| ContextCreationError::CreationFailed(e.to_string()))?;
    let governance_engine = state::create_governance_engine(
        &params.governance,
        &creator_did,
        Arc::clone(key_resolver),
    )?;
    let handle = crate::context::builder::create_context(
        context_id.clone(),
        params.clone(),
        crypto.as_ref(),
        transport.as_ref(),
        event_log.as_ref(),
        creator_did.as_ref(),
    )
    .await?;
    let ceiling = CapabilityCeiling::new(params.ceiling.iter().cloned());
    let role_state = ContextRoleState::new(&context_id, &*creator_did, ceiling, vec![], &**clock)
        .map_err(|e| ContextCreationError::CreationFailed(e.to_string()))?;
    let mut membership = MembershipState::new();
    let creator_tokens = role_state
        .assignments
        .get(creator_did.as_ref())
        .map(|a| a.tokens.clone())
        .unwrap_or_default();
    membership.add_member(creator_did.clone(), "admin".into(), creator_tokens);
    let broadcast_context =
        manager_methods::init_broadcast_context(supervisor, &context_id, &params, &creator_did)?;
    let (initial_threshold_signers, initial_threshold_value) = match &params.governance {
        GovernanceModel::Threshold { threshold, signers } => (signers.clone(), *threshold),
        _ => (Vec::new(), 0),
    };
    let initial_access_key_store =
        generate_initial_access_key_store_legacy(&context_id, &creator_did);
    let initial_members: HashSet<DID> = membership.members().map(|m| m.did.clone()).collect();
    // ADR-049 Phase 2A finalization keystone: branch the actor's
    // discriminated mode union on whether the supervisor returned a
    // broadcast roster (legacy create path mirrors the new-style create).
    let context_id_bytes = state::context_id_to_bytes(&context_id);
    let actor_members: HashSet<DID> = initial_members.clone();
    let mode = if broadcast_context.is_some() {
        ContextModeState::Broadcast(Box::<crate::context::actor::state::BroadcastState>::default())
    } else {
        ContextModeState::Encrypted(Box::<ContextCryptoState>::default())
    };
    let per_context = PerContextState {
        context_id: context_id_bytes,
        created_at: clock.now_secs(),
        generation: next_generation.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        handle: handle.clone(),
        membership,
        members: actor_members,
        governance: GovernanceState {
            engine: governance_engine,
            executed_proposals: HashMap::new(),
            approved_proposals: HashMap::new(),
            // H10: fresh contexts start with a zero monotonic counter.
            next_proposal_seq: 0,
            freeze: None,
            timeout_task: GovernanceTimeoutTask::new(),
            deadlock: DeadlockDetectionState::default(),
            threshold_signers: initial_threshold_signers,
            threshold_value: initial_threshold_value,
            pending_ceiling_modification: None,
            pending_economic_policy_change: None,
            registered_tools: Vec::new(),
            tool_interfaces: Vec::new(),
            pruning_policy: None,
            message_pricing: crate::context::lifecycle_logic::derive_message_pricing(
                params.economic_policy.as_ref(),
            ),
            hard_rate_limit: scp_protocol::economy::antispam::TokenBucketLimiter::new(
                scp_protocol::economy::antispam::HardRateLimitConfig::matrix_defaults(),
            ),
            economic_policy: params.economic_policy.clone(),
            budget_tracker: MemberBudgetTracker::new(),
            last_known_members: initial_members,
            pending_epoch_resets: Vec::new(),
            consequence_rules: params.consequence_rules.clone(),
            velocity_tracker: scp_protocol::economy::antispam::SenderVelocityTracker::new(60),
            participation_cache: HashMap::new(),
            cooldown_until: HashMap::new(),
            spending_nonce_tracker: scp_protocol::crypto::ucan::nonce::NonceTracker::new(
                context_id.clone(),
                Arc::clone(clock),
            ),
            revoked_spending_ucan_cids: HashSet::new(),
            proposal_timestamps: HashMap::new(),
        },
        role_state,
        receive_buffer: ReceiveBuffer::new(),
        broadcast_context,
        migration_state: None,
        epoch: EpochState {
            mls_epoch: 0,
            coordinator: EpochCoordinator::new(),
            grace_store: crate::crypto::mls::epoch_grace::EpochGraceStore::new(),
            needs_reconnect: false,
        },
        access: AccessControlState {
            read_exclusion_list: HashSet::new(),
            access_key_store: initial_access_key_store,
        },
        ttl: TtlState {
            timer: TtlTimer::with_clock(Arc::clone(clock)),
            extension: None,
        },
        sequence_tracker: scp_protocol::envelope::SequenceTracker::new(),
        reorder_buffer: scp_protocol::envelope::ReorderBuffer::default(),
        // PR #1606 C6: fresh contexts start with an empty commit retry
        // queue and no fail-close marker.
        pending_commits: VecDeque::new(),
        commit_fault: None,
        // Checkpoint tracking (§9.9.3): fresh counters for new contexts.
        checkpoint_events_since: 0,
        checkpoint_last_time_secs: clock.now_secs(),
        checkpoints: Vec::new(),
        merkle_tree: scp_event_log::EventLog::new(context_id.clone()),
        // §9.10.4: pseudonym routing. Only meaningful for encrypted
        // contexts; broadcast contexts ignore this field.
        local_pseudonym,
        pseudonym_registry: HashMap::new(),
        // ADR-049 commit 8: fresh actor-shape tracker at creation.
        send_tracker: SendSequenceTracker::new(),
        // ADR-049 Phase 2A finalization keystone: actor-shape collections
        // start empty at creation; lifecycle is Open.
        recv_tracker: RecvSequenceTracker::new(),
        saga_pending: HashMap::new(),
        welcome_scratchpad: None,
        lifecycle_state: ContextLifecycleState::Open,
        event_log: None,
        mode,
    };

    // Atomic check-and-insert — eliminates TOCTOU race between
    // contains_key and insert.
    manager_methods::insert_context(supervisor, context_id.clone(), per_context)?;
    finalize_create_legacy(supervisor, &context_id, params.ttl, &handle).await;
    Ok(handle)
}

// ---------------------------------------------------------------------------
// 4. finalize_create (transitive of create_context)
// ---------------------------------------------------------------------------

/// Post-creation finalization: gauges, governance timeout, persistence,
/// TTL timer (hoisted body of the legacy
/// `ContextManager::finalize_create`).
pub async fn finalize_create_legacy(
    supervisor: &Supervisor,
    context_id: &str,
    ttl_duration: Option<std::time::Duration>,
    handle: &ContextHandle,
) {
    manager_methods::update_context_gauges(supervisor).await;
    crate::context::governance_helpers_legacy::start_governance_timeout_task_legacy(
        supervisor, context_id,
    )
    .await;
    manager_methods::persist_context_and_broadcast(supervisor, context_id).await;
    if let Some(duration) = ttl_duration {
        crate::context::ttl_close_helpers_legacy::spawn_ttl_timer_legacy(
            supervisor,
            context_id,
            duration,
            handle.clone(),
        )
        .await;
    }
}

// ---------------------------------------------------------------------------
// 5. generate_initial_access_key_store (transitive of create_context)
// ---------------------------------------------------------------------------

/// Generates the initial access key store for context creation (§9.17.2).
/// Hoisted from the legacy private associated function
/// `ContextManager::generate_initial_access_key_store`.
fn generate_initial_access_key_store_legacy(
    context_id: &str,
    creator_did: &DID,
) -> scp_protocol::crypto::access_keys::AccessKeyStore {
    let mut store = scp_protocol::crypto::access_keys::AccessKeyStore::new();
    let key =
        scp_protocol::crypto::access_keys::generate_access_key(context_id, creator_did.as_ref());
    store.set(context_id, creator_did.as_ref(), key);
    store
}

// ---------------------------------------------------------------------------
// 6. join_context (top-level)
// ---------------------------------------------------------------------------

/// Joins a member to a context (hoisted body of the legacy
/// [`ContextManager::join_context`](crate::context::supervisor::Supervisor::join_context)).
///
/// Validates the joiner's key package, performs the F4 escrow dance
/// (economy + sybil + hard-rate-limit under lock, then authorize,
/// MLS add, sender-key distribute, membership mutate, capture),
/// and appends a `MemberJoined` event. Byte-identical to the legacy
/// method form.
#[allow(clippy::too_many_lines)]
pub async fn join_context_legacy(
    supervisor: &Supervisor,
    handle: &ContextHandle,
    key_package: KeyPackage,
    spending_ucan: Option<&scp_protocol::crypto::ucan::UcanToken>,
    local_pseudonym: Option<[u8; 32]>,
) -> Result<(), ContextError> {
    let crypto = supervisor
        .crypto_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let clock = supervisor
        .clock_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let key_resolver = supervisor
        .key_resolver_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let event_log = supervisor
        .event_log_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let context_id = handle.context_id().to_owned();
    let context_id_bytes = state::context_id_to_bytes(&context_id);
    let member_did = key_package.owner_did.clone();

    // Fast-fail: reject obviously incompatible versions before expensive
    // crypto ops (MLS group join, sender key derivation). Looks up the
    // stored context's params (not the caller-supplied handle params)
    // so this check is authoritative even when the caller passes an
    // ephemeral handle with default params (e.g. UniFFI bridge).
    {
        let ctx_arc = manager_methods::get_context_arc(supervisor, &context_id)
            .map_err(|_| ContextError::ContextNotRegistered(context_id.clone()))?;
        let guard = ctx_arc.lock().await;
        let ctx = &*guard;
        ctx.handle
            .params()
            .check_version_compatibility(scp_protocol::envelope::SCP_PROTOCOL_VERSION)?;
    }

    // Validate key package before any mutations (idempotent, no lock needed).
    let kp_bytes = key_package.mls_key_package_bytes.as_deref();
    crypto.validate_key_package(&member_did, kp_bytes)?;

    // Phase 1: Economy enforcement + sybil check under lock (budget deduction).
    // This happens BEFORE any crypto mutations so that a rejected payment
    // never grants MLS group access or sender keys.
    // Capture generation for confused-deputy detection on rollback reacquire.
    let (ticket, ctx_gen) = {
        let (mut guard, ctx_gen) = manager_methods::lock_context(supervisor, &context_id)
            .await
            .map_err(|_| ContextError::ContextNotRegistered(context_id.clone()))?;
        let ctx = &mut *guard;

        // State check inside lock -- eliminates TOCTOU race.
        state::require_active(&ctx.handle)?;

        // Defense-in-depth: re-check version compatibility under the
        // mutation lock. The early check above uses a separate lock
        // acquisition, so governance could theoretically change the
        // min_protocol_version between the two. This eliminates that
        // TOCTOU window.
        ctx.handle
            .params()
            .check_version_compatibility(scp_protocol::envelope::SCP_PROTOCOL_VERSION)?;

        // Economy enforcement (#1537, #1593) — auto-accept guard + join cost + spending UCAN.
        // Budget deduction happens here. The adapter escrow (authorize/complete/void)
        // runs after the lock is dropped. On adapter failure, the F4 EconomyTicket
        // rollback restores the deducted amount AND the velocity+hard-rate state.
        // M13: Sybil resistance check BEFORE economy enforcement so that
        // a rejected sybil attacker doesn't consume budget. Fail-closed.
        crate::context::lifecycle_logic::evaluate_sybil_resistance(
            ctx.handle.params().sybil_policy.as_ref(),
            &ctx.governance,
            &member_did,
            clock.now_secs(),
        )?;

        // Defense-in-depth hard rate limit on joins (Matrix-style token
        // bucket). On any subsequent failure we refund the token.
        let now_secs = clock.now_secs();
        if !ctx
            .governance
            .hard_rate_limit
            .try_consume(&member_did, now_secs)
        {
            return Err(ContextError::RateLimited {
                resource: "join".to_owned(),
                message: "hard rate limit exceeded for joiner".to_owned(),
            });
        }
        // Record the join in the velocity tracker so subsequent §19.7
        // escalation observes the same activity surface as message sends.
        // F5: capture the rollback token so a join failure refunds
        // THIS entry specifically rather than racing concurrent joiners.
        let velocity_token = ctx
            .governance
            .velocity_tracker
            .record_message(&member_did, now_secs);

        let member_count = ctx.membership.count();
        let deducted_cost = match crate::context::lifecycle_logic::enforce_join_economy(
            &mut ctx.governance,
            member_count,
            &member_did,
            now_secs,
            spending_ucan,
            &context_id,
            &**clock,
            key_resolver,
        ) {
            Ok(cost) => cost,
            Err(e) => {
                // No ticket exists yet — roll back inline under lock.
                ctx.governance
                    .velocity_tracker
                    .rollback(&member_did, velocity_token);
                ctx.governance.hard_rate_limit.refund(&member_did);
                return Err(e);
            }
        };
        // F4: wrap the Phase 1 state in an EconomyTicket so every
        // downstream error path (adapter, MLS, sender-key) is forced
        // to roll back velocity + hard_rate_limit + budget, not just
        // the budget.
        (
            crate::context::economy_logic::EconomyTicket {
                actor_did: member_did.clone(),
                deducted_cost,
                velocity_token,
                needs_hard_rate_limit_refund: true,
                consumed: false,
            },
            ctx_gen,
        )
    };

    // Phase 2: Authorize payment (escrow hold) BEFORE any crypto mutation.
    // If authorization fails, rollback the ticket — no MLS state was touched.
    let auth = match crate::context::economy_helpers_legacy::authorize_paid_action_legacy(
        supervisor,
        scp_protocol::economy::types::PaidActionType::ContextJoin,
        &member_did,
        &context_id,
    )
    .await
    {
        Ok(auth) => auth,
        Err(payment_err) => {
            crate::context::economy_logic::rollback_economy_ticket(
                supervisor,
                &context_id,
                ticket,
                &ctx_gen,
            )
            .await;
            return Err(payment_err);
        }
    };

    // Phase 3: MLS add_member + sender key distribution (crypto mutations).
    // On failure: void escrow + rollback ticket. No MLS rollback needed
    // because add_member itself failed (no state change occurred).
    let add_output = match crypto.add_member(&context_id_bytes, &member_did, kp_bytes) {
        Ok(output) => output,
        Err(e) => {
            if let Some(a) = auth {
                crate::context::economy_helpers_legacy::void_paid_action_legacy(
                    supervisor,
                    a,
                    &context_id,
                )
                .await;
            }
            crate::context::economy_logic::rollback_economy_ticket(
                supervisor,
                &context_id,
                ticket,
                &ctx_gen,
            )
            .await;
            return Err(e);
        }
    };

    if let Err(e) = crypto.distribute_sender_key(&context_id_bytes, &member_did) {
        // Sender key distribution failed after MLS add — rollback MLS state.
        let _ = crypto.remove_member(&context_id_bytes, &member_did);
        let _ = crypto.remove_member_sender_key(&context_id_bytes, &member_did);
        if let Some(a) = auth {
            crate::context::economy_helpers_legacy::void_paid_action_legacy(
                supervisor,
                a,
                &context_id,
            )
            .await;
        }
        crate::context::economy_logic::rollback_economy_ticket(
            supervisor,
            &context_id,
            ticket,
            &ctx_gen,
        )
        .await;
        return Err(e);
    }

    // Drain pending HPKE-sealed sender key distribution messages and
    // deliver them via the MLS management channel (§9.16.2).
    //
    // CRITICAL: distributions MUST be MLS-wrapped via
    // `mls_encrypt_management` so the receive-side dispatcher
    // (`decrypt_and_dispatch`) recognizes them as
    // `OpenResult::Management` and routes them through
    // `process_incoming_sender_key`. Sending the raw HPKE-sealed
    // bytes via `transport.send_message` would fail to deserialize
    // as an `OuterEnvelope` on the joiner side, causing silent
    // distribution loss (recoverable only via `SenderKeyRequest`).
    //
    // Helper semantics (matches the rotation path used by
    // `execute_remove_member`, `leave_context`, and `execute_rotate_content_keys`):
    //   - Drain failure (catastrophic, e.g. lock poisoned) → propagated
    //     and forces full rollback below.
    //   - Per-target encrypt/send failure → warned and continued. The
    //     joiner falls back to `SenderKeyRequest` to recover the key.
    //
    // Ordering invariant: this point is reached AFTER `add_member`
    // has merged the pending Commit on the inviter side, so the
    // inviter's MLS group already includes the new joiner in the
    // post-add epoch. The joiner can decrypt this management message
    // once they process the Welcome (delivered out-of-band via the
    // `WelcomeGenerated` event). If the joiner receives the
    // management message before the Welcome, their `crypto.open()`
    // call fails to decrypt and the `SenderKeyRequest` fallback
    // recovers the key.
    if let Err(e) = drain_and_deliver_sender_keys_legacy(supervisor, &context_id, &context_id_bytes)
    {
        // Drain failed catastrophically — roll back MLS state, sender
        // key, escrow, and economy ticket so the join is fully aborted.
        let _ = crypto.remove_member(&context_id_bytes, &member_did);
        let _ = crypto.remove_member_sender_key(&context_id_bytes, &member_did);
        if let Some(a) = auth {
            crate::context::economy_helpers_legacy::void_paid_action_legacy(
                supervisor,
                a,
                &context_id,
            )
            .await;
        }
        crate::context::economy_logic::rollback_economy_ticket(
            supervisor,
            &context_id,
            ticket,
            &ctx_gen,
        )
        .await;
        return Err(e);
    }

    // Phase 4: Membership mutation under lock. On failure: void escrow +
    // rollback ticket + rollback MLS state.
    if let Err(e) =
        join_context_membership_legacy(supervisor, &context_id, &member_did, add_output).await
    {
        let _ = crypto.remove_member(&context_id_bytes, &member_did);
        let _ = crypto.remove_member_sender_key(&context_id_bytes, &member_did);
        if let Some(a) = auth {
            crate::context::economy_helpers_legacy::void_paid_action_legacy(
                supervisor,
                a,
                &context_id,
            )
            .await;
        }
        crate::context::economy_logic::rollback_economy_ticket(
            supervisor,
            &context_id,
            ticket,
            &ctx_gen,
        )
        .await;
        return Err(e);
    }

    // Phase 4.5: Store local pseudonym after membership mutation succeeds.
    // The pseudonym was pre-derived by the FFI bridge; storing it here
    // makes it available for subsequent send_message fan-out (§9.10.4).
    if let Some(pseudonym) = local_pseudonym
        && let Ok(ctx_arc) = manager_methods::get_context_arc(supervisor, &context_id)
    {
        let mut guard = ctx_arc.lock().await;
        let ctx = &mut *guard;
        ctx.local_pseudonym = Some(pseudonym);
    }

    // Phase 5: Capture the escrow hold after all mutations succeeded.
    // Consume the ticket — commit returns the deducted cost for the
    // capture step and marks the ticket as committed so the Drop
    // guard stays quiet.
    let deducted_cost = crate::context::economy_logic::commit_economy_ticket(ticket);
    capture_join_payment_legacy(supervisor, auth, &member_did, &context_id, deducted_cost).await;

    // Append MemberJoined event to event log.
    event_log.append_context_event(&context_id_bytes, "MemberJoined", member_did.as_ref())?;
    {
        if let Ok(ctx_arc) = manager_methods::get_context_arc(supervisor, &context_id) {
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;
            ctx.checkpoint_events_since += 1;
        }
    }
    // Persist context state after join (best-effort).
    if manager_methods::has_persistence(supervisor)
        && let Ok(ctx_arc) = manager_methods::get_context_arc(supervisor, &context_id)
    {
        let guard = ctx_arc.lock().await;
        let ctx = &*guard;
        let snapshot = manager_methods::snapshot_context(ctx);
        manager_methods::persist_context_snapshot(supervisor, &context_id, snapshot);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// 7. join_context_membership (transitive of join_context)
// ---------------------------------------------------------------------------

/// Performs the membership state mutations for `join_context` (Phase 4)
/// — hoisted body of the legacy `ContextManager::join_context_membership`.
pub async fn join_context_membership_legacy(
    supervisor: &Supervisor,
    context_id: &str,
    member_did: &DID,
    add_output: scp_protocol::context::builder::AddMemberOutput,
) -> Result<(), ContextError> {
    let clock = supervisor
        .clock_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let event_log = supervisor
        .event_log_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let ctx_arc = manager_methods::get_context_arc(supervisor, context_id)
        .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
    let mut guard = ctx_arc.lock().await;
    let ctx = &mut *guard;

    state::require_active(&ctx.handle)?;

    crate::context::lifecycle_logic::post_join_bookkeeping(
        &mut ctx.governance,
        &ctx.receive_buffer,
        context_id,
        member_did,
        clock.now_secs(),
        event_log.as_ref(),
    );

    // Add member to role state.
    ctx.role_state.members.insert(member_did.to_string());

    // Assign default "member" role.
    //
    // H2 (related): Use system_assign_role to bypass the RoleAssign
    // capability check. The join handshake is a self-service flow that
    // already passed economy / sybil / capacity / version gates above —
    // re-checking `RoleAssign` against the creator would silently fail
    // every join after the creator has been demoted out of an admin
    // role. The default "member" role assignment carries no ambient
    // authority (it's the protocol-defined floor), so there is nothing
    // to authorize a second time. See `enforce_assign_role` and the
    // governance dispatch path in governance.rs for the same pattern.
    let creator_did = ctx.role_state.creator_did.clone();
    let tokens = roles::system_assign_role(&mut ctx.role_state, member_did, "member", &**clock)
        .map_err(|e| ContextError::MembershipFailed(e.to_string()))?;

    // Add to membership tracking.
    ctx.membership
        .add_member(member_did.clone(), "member".into(), tokens);

    // Generate access key for the new member (§9.17.2 step 2).
    // The inviter stores the key so `send_message` can wrap content
    // for this recipient. Key distribution to the joiner happens
    // via the Welcome payload / out-of-band key exchange.
    let member_access_key =
        scp_protocol::crypto::access_keys::generate_access_key(context_id, member_did);
    ctx.access
        .access_key_store
        .set(context_id, member_did, member_access_key);

    // Emit MemberJoined event to receive buffer.
    let join_event = ContextEvent::MemberJoined {
        member_did: member_did.clone(),
        role_name: "member".into(),
    };
    ctx.emit_event(join_event, context_id, supervisor.event_tx_ref());

    // Emit WelcomeGenerated event if the add produced a Welcome message.
    state::push_welcome_event(
        ctx,
        context_id,
        &DID(creator_did),
        member_did,
        add_output,
        supervisor.event_tx_ref(),
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// 8. capture_join_payment (transitive of join_context)
// ---------------------------------------------------------------------------

/// Captures the escrow hold after a successful join (Phase 5 of
/// `join_context`) — hoisted body of the legacy
/// `ContextManager::capture_join_payment`.
pub async fn capture_join_payment_legacy(
    supervisor: &Supervisor,
    auth: Option<crate::context::economy_logic::PaidActionAuthorization>,
    member_did: &DID,
    context_id: &str,
    deducted_cost: Option<scp_protocol::economy::types::Amount>,
) {
    if let Some(a) = auth
        && let Err(e) = crate::context::economy_helpers_legacy::complete_paid_action_legacy(
            supervisor, a, member_did, context_id,
        )
        .await
    {
        // H8: do NOT rollback budget — service was delivered (member joined).
        tracing::warn!(
            context_id,
            "payment capture failed after successful join: {e}"
        );
        // H19: append durable audit record to event log + receive buffer.
        manager_methods::record_payment_capture_failure(
            supervisor,
            context_id,
            "join_context",
            member_did,
            &e.to_string(),
            deducted_cost,
        )
        .await;
    }
}

// ---------------------------------------------------------------------------
// 9. leave_context (top-level)
// ---------------------------------------------------------------------------

/// Removes a member from a context (hoisted body of the legacy
/// [`ContextManager::leave_context`](crate::context::supervisor::Supervisor::leave_context)).
///
/// Self-removal is always permitted; otherwise requires `MemberRemove`
/// capability. Performs MLS `remove_member` (hard security boundary)
/// then sender-key cleanup (best-effort), broadcasts the resulting
/// Commit, rotates the sender key, and appends a `MemberLeft` event.
/// Byte-identical to the legacy method.
#[allow(clippy::too_many_lines)]
pub async fn leave_context_legacy(
    supervisor: &Supervisor,
    handle: &ContextHandle,
    caller_did: &DID,
    member_did: &DID,
) -> Result<(), ContextError> {
    let crypto = supervisor
        .crypto_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let event_log = supervisor
        .event_log_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let context_id = handle.context_id().to_owned();
    let context_id_bytes = state::context_id_to_bytes(&context_id);

    // Determine broadcast mode + authorization in a single lock acquire.
    // PR #1606 C6: also check the commit fault marker so a fail-closed
    // context refuses further leave operations until an operator
    // acknowledges the fault.
    // Use lock_context to capture a generation token for confused-deputy
    // detection in subsequent lock scopes (Phase B).
    let (is_broadcast, ctx_gen) = {
        let (guard, generation) = manager_methods::lock_context(supervisor, &context_id).await?;
        let ctx = &*guard;
        // Authorization: self-removal always allowed; otherwise MemberRemove required.
        if caller_did != member_did
            && !ctx
                .role_state
                .member_has_capability(caller_did, &Capability::MemberRemove)
        {
            return Err(ContextError::PermissionDenied(
                "caller lacks permission to remove this member".into(),
            ));
        }
        governance_helpers_legacy::check_commit_fault_legacy(ctx)?;
        (ctx.broadcast_context.is_some(), generation)
    };

    // Crypto operations -- no lock held. Skip for broadcast mode (no MLS).
    // H9: MLS group removal FIRST (hard security boundary), then sender
    // key cleanup as best-effort. MLS removal is the cryptographic
    // enforcement; sender key removal is defense-in-depth (§9.16).
    if !is_broadcast {
        let remove_output = crypto.remove_member(&context_id_bytes, member_did)?;
        if let Err(e) = crypto.remove_member_sender_key(&context_id_bytes, member_did) {
            tracing::warn!(
                context_id = %context_id,
                member = %member_did,
                error = %e,
                "remove_member_sender_key failed after MLS removal — \
                 sender key layer may retain stale key"
            );
        }

        // Broadcast the MLS Commit to remaining members so they can
        // advance their group epoch and ratchet key material. PR #1606 C6:
        // on transport failure, the commit is durably enqueued for retry.
        crate::context::governance_helpers_legacy::try_broadcast_commit_or_enqueue_legacy(
            supervisor,
            &context_id,
            remove_output.commit_bytes,
            CommitOperation::LeaveContext {
                member_did: member_did.clone(),
            },
            member_did.as_ref(),
        )
        .await?;

        // Rotate the local sender key and distribute to remaining members (§9.16.4).
        // M23: Non-fatal — MLS removal above is the hard security boundary.
        // If rotation fails, log but continue: returning Err here would leave
        // the system inconsistent (MLS removed, but caller thinks leave failed).
        if let Err(e) = crypto.rotate_sender_key(&context_id_bytes) {
            tracing::warn!(
                context_id = %context_id,
                error = %e,
                "rotate_sender_key failed after leave — \
                 remaining members retain old sender key"
            );
        }
        if let Err(e) =
            drain_and_deliver_sender_keys_legacy(supervisor, &context_id, &context_id_bytes)
        {
            tracing::warn!(
                context_id = %context_id,
                error = %e,
                "failed to deliver rotated sender keys after leave"
            );
        }
    }

    // Atomic state check + membership removal + count check within single lock.
    // Use relock_context for generation verification (Phase B).
    let should_close = {
        let mut guard = manager_methods::relock_context(supervisor, &ctx_gen).await?;
        let ctx = &mut *guard;

        // State check inside lock -- eliminates TOCTOU race.
        state::require_active(&ctx.handle)?;

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

        // Destroy the departing member's access key (§9.17.2, ADR-038).
        ctx.access
            .access_key_store
            .remove(&context_id, member_did.as_ref());

        // §9.10.4: remove the departing member's pseudonym routing ID.
        ctx.pseudonym_registry.remove(member_did);

        // Emit MemberLeft event to receive buffer.
        let left_event = ContextEvent::MemberLeft {
            member_did: member_did.clone(),
        };
        ctx.emit_event(left_event, &context_id, supervisor.event_tx_ref());

        ctx.membership.count() == 0
    };
    // Lock dropped.

    // Append MemberLeft event to event log.
    event_log.append_context_event(&context_id_bytes, "MemberLeft", member_did.as_ref())?;
    // Use relock_context for generation verification (Phase B).
    if let Ok(mut guard) = manager_methods::relock_context(supervisor, &ctx_gen).await {
        let ctx = &mut *guard;
        ctx.checkpoint_events_since += 1;
    } else {
        tracing::warn!(
            context_id = %context_id,
            "leave_context: generation mismatch — checkpoint counter not incremented"
        );
    }
    // Persist context state after leave (best-effort).
    if manager_methods::has_persistence(supervisor)
        && let Ok(guard) = manager_methods::relock_context(supervisor, &ctx_gen).await
    {
        let ctx = &*guard;
        let snapshot = manager_methods::snapshot_context(ctx);
        manager_methods::persist_context_snapshot(supervisor, &context_id, snapshot);
    }

    // If member count reaches zero, transition to Closing.
    if should_close {
        handle.transition_to(&ContextState::Closing).await?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// 10. drain_and_deliver_sender_keys (transitive of join / leave)
// ---------------------------------------------------------------------------

/// Drains pending sender key distribution messages and delivers them via
/// transport (§9.16.2). Hoisted body of the legacy
/// `ContextManager::drain_and_deliver_sender_keys`.
pub fn drain_and_deliver_sender_keys_legacy(
    supervisor: &Supervisor,
    context_id: &str,
    context_id_bytes: &[u8; 32],
) -> Result<(), ContextError> {
    let crypto = supervisor
        .crypto_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let transport = supervisor
        .transport_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let pending = crypto.drain_pending_sender_key_messages(context_id_bytes)?;
    if !pending.is_empty() {
        let routing_id = scp_protocol::context::context_routing_id(context_id);
        for (target_did, message) in pending {
            tracing::debug!(
                target_did = %target_did,
                context_id = %context_id,
                message_len = message.len(),
                "MLS-encrypting and sending rotated sender key distribution"
            );
            match crypto.mls_encrypt_management(
                context_id_bytes,
                &message,
                &routing_id,
                crate::context::messaging_helpers::DEFAULT_BLOB_TTL_SECS,
            ) {
                Ok(sealed) => {
                    if let Err(e) = transport.send_message(&routing_id, &sealed) {
                        tracing::warn!(target_did = %target_did, context_id = %context_id, error = %e, "failed to send rotated sender key");
                    }
                }
                Err(e) => {
                    tracing::warn!(target_did = %target_did, context_id = %context_id, error = %e, "MLS encryption of sender key distribution failed");
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 11. close_context (top-level, forwarder into close_context_with_key)
// ---------------------------------------------------------------------------

/// Initiates cooperative context closure (hoisted body of the legacy
/// [`ContextManager::close_context`](crate::context::lifecycle_helpers::close_context)).
///
/// For `SingleAdmin` governance: delegates to [`close_context_with_key`]
/// with no signing key. Multi-admin contexts are rejected — they must
/// route through the governance path.
pub async fn close_context_legacy(
    supervisor: &Supervisor,
    handle: &ContextHandle,
    initiator_did: &DID,
) -> Result<CloseResult, ContextError> {
    close_context_with_key_legacy(supervisor, handle, initiator_did, None).await
}

// ---------------------------------------------------------------------------
// 12. close_context_with_key (transitive of close_context)
// ---------------------------------------------------------------------------

/// Closes a context with an optional signing key for final checkpoint
/// generation (§9.9.3) — hoisted body of the legacy
/// [`ContextManager::close_context_with_key`](crate::context::supervisor::Supervisor::close_context_with_key).
///
/// See the legacy method's doc comment for the full `SingleAdmin` gate,
/// TTL / governance-timeout cancellation, and final-checkpoint policy.
/// Byte-identical behavior.
pub async fn close_context_with_key_legacy(
    supervisor: &Supervisor,
    handle: &ContextHandle,
    initiator_did: &DID,
    signing_key: Option<&ed25519_dalek::SigningKey>,
) -> Result<CloseResult, ContextError> {
    let event_log = supervisor
        .event_log_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let context_id = handle.context_id().to_owned();

    // Check governance model: multi-admin contexts must route through
    // governance (SCP-270, ADR-031). Only SingleAdmin contexts can use
    // the direct close_context path.
    // Capture generation for confused-deputy detection on reacquire.
    let (role_state, ctx_gen) = {
        let (guard, ctx_gen) = manager_methods::lock_context(supervisor, &context_id)
            .await
            .map_err(|_| ContextError::ContextNotRegistered(context_id.clone()))?;
        let ctx = &*guard;

        // State check inside lock -- eliminates TOCTOU race.
        state::require_active(&ctx.handle)?;

        // Gate: multi-admin models must use governance path.
        if !matches!(
            ctx.governance.engine.model_config(),
            GovernanceModelConfig::SingleAdmin { .. }
        ) {
            return Err(ContextError::PermissionDenied(
                "multi-admin contexts must close through governance \
                 (propose GovernanceAction::CloseContext)"
                    .to_owned(),
            ));
        }

        (ctx.role_state.clone(), ctx_gen)
    };
    // Lock dropped before async ttl::close_context call.

    // Delegate to ttl::close_context for the actual logic (async).
    let result = ttl::close_context(handle, initiator_did, &role_state, event_log.as_ref()).await?;

    // Cancel TTL timer, governance timeout task, drop broadcast state,
    // and emit close notification (second lock acquisition with generation
    // check for confused-deputy detection + ContextClose TOCTOU re-check).
    {
        if let Ok(mut guard) = manager_methods::relock_context(supervisor, &ctx_gen).await {
            let ctx = &mut *guard;

            // Fix C: Re-check ContextClose capability under the cleanup lock.
            // If capability was revoked between the first lock and this
            // reacquire, the state transition already happened (can't undo),
            // but we log a warning for auditability.
            if !ctx
                .role_state
                .member_has_capability(initiator_did.as_ref(), &Capability::ContextClose)
            {
                tracing::warn!(
                    context_id = %context_id,
                    initiator_did = %initiator_did,
                    "ContextClose capability revoked between lock acquisitions — \
                     state transition already committed, proceeding with cleanup"
                );
            }

            ctx.ttl.timer.cancel();
            ctx.governance.timeout_task.cancel();
            // Drop broadcast context state -- keys are zeroed by Zeroize.
            ctx.broadcast_context = None;

            // §9.10.4: clear pseudonym state on close. The local pseudonym
            // is derived from secret key material; zeroing it prevents
            // leaking the routing ID after context teardown.
            ctx.local_pseudonym = None;
            ctx.pseudonym_registry.clear();

            // Participation decay: clear participation cache and cooldown
            // state on context close (#1530).
            ctx.governance.decay_participation();

            // Final checkpoint before close (§9.9.3): force-create a
            // checkpoint to capture the terminal event log state. This
            // ensures equivocation detection covers the full context
            // lifetime. Best-effort: skip if no signing key is available.
            if let Some(sk) = signing_key
                && let Some(cp) =
                    crate::context::queries_helpers_legacy::force_create_checkpoint_legacy(
                        supervisor,
                        &context_id,
                        ctx,
                        initiator_did,
                        sk,
                    )
            {
                tracing::debug!(
                    context_id = %context_id,
                    event_count = cp.event_count,
                    "final checkpoint created on close (§9.9.3)"
                );
            }

            let close_event = ContextEvent::SystemClose {
                initiator_did: initiator_did.clone(),
            };
            ctx.emit_event(close_event, &context_id, supervisor.event_tx_ref());
        }
    }

    manager_methods::update_context_gauges(supervisor).await;

    // Persist context state after close (best-effort).
    if manager_methods::has_persistence(supervisor)
        && let Ok(guard) = manager_methods::relock_context(supervisor, &ctx_gen).await
    {
        let ctx = &*guard;
        let snapshot = manager_methods::snapshot_context(ctx);
        manager_methods::persist_context_snapshot(supervisor, &context_id, snapshot);
    }

    Ok(result)
}
