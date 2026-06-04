//! Lifecycle helpers — actor-shape signatures
//! (ADR-049 Phase 2A.9, `lifecycle` domain migration).
//!
//! # Purpose
//!
//! This module hosts lifecycle-domain helpers that operate on actor-owned
//! [`PerContextState`](crate::context::state::PerContextState) and
//! capability-reduced [`ActorDeps`](crate::context::actor::deps::ActorDeps).
//! The legacy `&Supervisor` lock-and-call bodies live in
//! [`crate::context::lifecycle_helpers_legacy`] until Phase 2A
//! finalization removes the shim fallback.
//!
//! # Pipeline shape
//!
//! Actor-owned state collapses the legacy lock dance: each command is
//! serialized through the per-context actor's mailbox, so per-context
//! mutations happen with `state` directly borrowed. The legacy
//! `lock_context` / `relock_context` confused-deputy generation guard
//! is no longer required because each actor IS its own generation.
//!
//! # Helpers
//!
//! Per-context (actor-shape `(&mut PerContextState, &ActorDeps, ...)`):
//!
//! 1. [`export_context`] — read-only state borrow + persistence-side
//!    snapshot construction; produces a signed [`ContextExport`].
//! 2. [`leave_context`] — capability check + MLS remove + sender-key
//!    cleanup + membership removal + close-on-empty.
//! 3. [`drain_and_deliver_sender_keys`] — drain pending sender-key
//!    distribution and MLS-wrap deliver via transport (used by both
//!    [`join_context`] and [`leave_context`]).
//! 4. [`close_context`] — single-arg forwarder into
//!    [`close_context_with_key`].
//! 5. [`close_context_with_key`] — full close body (governance gate +
//!    `ttl::close_context` + cancel timers + final checkpoint + persist).
//! 6. [`join_context`] — F4 escrow dance + MLS add + sender-key
//!    distribute + membership mutate + capture.
//! 7. [`join_context_membership`] — Phase 4 membership mutations for
//!    [`join_context`].
//! 8. [`capture_join_payment`] — Phase 5 escrow capture for
//!    [`join_context`].
//!
//! Bootstrap (build fresh state, then register through
//! [`SupervisorHandle`](crate::context::supervisor::handle::SupervisorHandle)):
//!
//! - [`create_context`] — full create body; builds and registers a fresh `PerContextState`.
//! - [`finalize_create`] — gauges + governance timeout + persistence + TTL timer post-creation.
//! - [`import_context`] — full import body (validate, restore crypto, build `PerContextState`, register).
//! - [`load_persisted_context_state`] — load context snapshot and broadcast state from persistence.
//! - [`restore_context`] — rebuild `PerContextState` from snapshot + register + start governance timeout + spawn TTL.
//!
//! `finalize_create` reaches the designated-legacy
//! `start_governance_timeout_task_legacy` via the shim escape (see
//! [`SupervisorHandle::shim_supervisor`](crate::context::supervisor::handle::SupervisorHandle::shim_supervisor))
//! because that helper iterates the contexts `DashMap` and stays
//! legacy-shape until the per-context governance-timeout actor lands.
//!
//! # Designated-legacy supervisor-scoped iteration helpers
//!
//! These iterate the contexts `DashMap` and inherently cannot move to
//! actor-owned shape — they live ONLY in
//! [`crate::context::lifecycle_helpers_legacy`]:
//!
//! - `restore_all_contexts_legacy`
//! - `flush_all_contexts_legacy` / `flush_all_contexts_sync_legacy`
//! - `shutdown_all_contexts_legacy` / `shutdown_all_contexts_sync_legacy`

#![allow(clippy::significant_drop_tightening)]

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
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::sequence::SendSequenceTracker;
use crate::context::actor::state::{
    ContextCryptoState, ContextLifecycleState, ContextModeState, PerContextState,
    RecvSequenceTracker,
};
use crate::context::governance::timeout::{DeadlockDetectionState, GovernanceTimeoutTask};
use crate::context::governance_helpers;
use crate::context::state::{
    self, AccessControlState, CommitOperation, EpochState, GovernanceState, TtlState,
};
use crate::context::ttl::{self, CloseResult, TtlTimer};

// ADR-049 Phase 2A finalization keystone (commit 12 phase 2A finalization
// — type unification, single PerContextState): the prior alias to the
// legacy struct was deleted alongside the struct itself. Every bootstrap
// call site now constructs the unified `PerContextState` directly. The
// contexts DashMap is still the production source of truth — subsequent
// finalization commits delete the DashMap and route bootstrap through
// `spawn_actor_with_state`.

// ---------------------------------------------------------------------------
// 1. export_context (per-context, read-only)
// ---------------------------------------------------------------------------

/// Exports a context's full state as a transferable
/// [`ContextExport`](crate::context::export_import::ContextExport).
///
/// Captures a `ContextSnapshot` from the actor-owned state, exports the
/// event log via `deps.event_log`, and produces a signed export.
///
/// # Errors
///
/// Returns a transport-/persistence-level error from the underlying
/// event-log export, or a crypto/clock failure during the signed-export
/// build.
pub fn export_context(
    state: &PerContextState,
    deps: &ActorDeps,
    exporter_did: DID,
) -> Result<crate::context::export_import::ContextExport, ContextError> {
    let context_id = state.handle.context_id();
    let ctx_id_bytes = scp_protocol::context::context_id_bytes(context_id);

    let snapshot = crate::context::messaging_helpers::build_snapshot_from_state(state);

    let event_log_data = deps
        .event_log
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
        &*deps.clock,
    )
}

// ---------------------------------------------------------------------------
// 2. leave_context (per-context)
// ---------------------------------------------------------------------------

/// Removes a member from a context.
///
/// Self-removal is always permitted; otherwise requires `MemberRemove`
/// capability. Performs MLS `remove_member` (hard security boundary)
/// then sender-key cleanup (best-effort), broadcasts the resulting
/// Commit, rotates the sender key, and appends a `MemberLeft` event.
///
/// # Errors
///
/// - [`ContextError::PermissionDenied`] if caller lacks `MemberRemove`
///   capability for non-self-removal.
/// - [`ContextError::ContextNotActive`] if the context's lifecycle
///   state is not Active.
/// - [`ContextError::MemberNotFound`] if `member_did` is not a member.
/// - Crypto / transport / event-log failures are propagated.
#[allow(clippy::too_many_lines)]
pub async fn leave_context(
    state: &mut PerContextState,
    deps: &ActorDeps,
    handle: &ContextHandle,
    caller_did: &DID,
    member_did: &DID,
) -> Result<(), ContextError> {
    let context_id = handle.context_id().to_owned();
    let context_id_bytes = state::context_id_to_bytes(&context_id);

    // PR #1606 C6: refuse if a commit fault marker is set.
    governance_helpers::check_commit_fault(state)?;

    // Authorization: self-removal always allowed; otherwise MemberRemove
    // required.
    if caller_did != member_did
        && !state
            .role_state
            .member_has_capability(caller_did, &Capability::MemberRemove)
    {
        return Err(ContextError::PermissionDenied(
            "caller lacks permission to remove this member".into(),
        ));
    }

    let is_broadcast = state.broadcast_context.is_some();

    // Crypto operations -- skip for broadcast mode (no MLS).
    // H9: MLS group removal FIRST (hard security boundary), then sender
    // key cleanup as best-effort. MLS removal is the cryptographic
    // enforcement; sender key removal is defense-in-depth (§9.16).
    if !is_broadcast {
        let remove_output = deps.crypto.remove_member(&context_id_bytes, member_did)?;
        if let Err(e) = deps
            .crypto
            .remove_member_sender_key(&context_id_bytes, member_did)
        {
            tracing::warn!(
                context_id = %context_id,
                member = %member_did,
                error = %e,
                "remove_member_sender_key failed after MLS removal — \
                 sender key layer may retain stale key"
            );
        }

        // Broadcast the MLS Commit to remaining members so they can
        // advance their group epoch and ratchet key material. PR #1606
        // C6: on transport failure, the commit is durably enqueued for
        // retry.
        governance_helpers::try_broadcast_commit_or_enqueue(
            state,
            deps,
            &context_id,
            remove_output.commit_bytes,
            &CommitOperation::LeaveContext {
                member_did: member_did.clone(),
            },
            member_did.as_ref(),
        )?;

        // Rotate the local sender key and distribute to remaining members
        // (§9.16.4). M23: Non-fatal — MLS removal above is the hard
        // security boundary. If rotation fails, log but continue.
        if let Err(e) = deps.crypto.rotate_sender_key(&context_id_bytes) {
            tracing::warn!(
                context_id = %context_id,
                error = %e,
                "rotate_sender_key failed after leave — \
                 remaining members retain old sender key"
            );
        }
        if let Err(e) = drain_and_deliver_sender_keys(deps, &context_id, &context_id_bytes) {
            tracing::warn!(
                context_id = %context_id,
                error = %e,
                "failed to deliver rotated sender keys after leave"
            );
        }
    }

    // State check + membership removal -- the actor owns state for the
    // duration of this command, so no relock dance is required.
    state::require_active(&state.handle)?;

    // For broadcast contexts, unsubscribe from the BroadcastContext.
    // rotate_keys=true for forward secrecy after departure.
    if let Some(ref mut bc) = state.broadcast_context {
        // Ignore MemberNotFound -- the member may be an author who was
        // never a subscriber. Propagate all other errors (e.g.
        // CryptoFailed from epoch overflow during key rotation).
        match bc.unsubscribe(member_did, true) {
            Ok(_) | Err(ContextError::MemberNotFound(_)) => {}
            Err(e) => return Err(e),
        }
    }

    if !state.membership.remove_member(member_did) {
        return Err(ContextError::MemberNotFound(member_did.to_string()));
    }

    // Remove from role state.
    state.role_state.members.remove(member_did.as_ref());
    state.role_state.assignments.remove(member_did.as_ref());
    state
        .role_state
        .member_capabilities
        .remove(member_did.as_ref());

    // Destroy the departing member's access key (§9.17.2, ADR-038).
    state
        .access
        .access_key_store
        .remove(&context_id, member_did.as_ref());

    // §9.10.4: remove the departing member's pseudonym routing ID.
    state.pseudonym_registry.remove(member_did);

    // Emit MemberLeft event to receive buffer.
    let left_event = ContextEvent::MemberLeft {
        member_did: member_did.clone(),
    };
    state::emit_event_into(
        &mut state.receive_buffer,
        left_event,
        &context_id,
        deps.event_tx.as_ref(),
    );

    let should_close = state.membership.count() == 0;

    // Append MemberLeft event to event log.
    deps.event_log
        .append_context_event(&context_id_bytes, "MemberLeft", member_did.as_ref())?;
    state.checkpoint_events_since += 1;

    // Persist context state after leave (best-effort).
    crate::context::messaging_helpers::persist_state_best_effort(state, deps, &context_id);

    // If member count reaches zero, transition to Closing.
    if should_close {
        handle.transition_to(&ContextState::Closing).await?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// 3. drain_and_deliver_sender_keys (per-context, transitive of join / leave)
// ---------------------------------------------------------------------------

/// Drains pending sender key distribution messages and delivers them via
/// transport (§9.16.2).
///
/// Helper semantics:
///   - Drain failure (catastrophic, e.g. lock poisoned) → propagated
///     and forces full rollback at the caller.
///   - Per-target encrypt/send failure → warned and continued. The
///     joiner falls back to `SenderKeyRequest` to recover the key.
///
/// # Errors
///
/// Returns a [`ContextError`] if the underlying drain call fails
/// catastrophically. Per-recipient send failures are logged but not
/// propagated (the receiver can recover via `SenderKeyRequest`).
pub fn drain_and_deliver_sender_keys(
    deps: &ActorDeps,
    context_id: &str,
    context_id_bytes: &[u8; 32],
) -> Result<(), ContextError> {
    let pending = deps
        .crypto
        .drain_pending_sender_key_messages(context_id_bytes)?;
    if !pending.is_empty() {
        let routing_id = scp_protocol::context::context_routing_id(context_id);
        for (target_did, message) in pending {
            tracing::debug!(
                target_did = %target_did,
                context_id = %context_id,
                message_len = message.len(),
                "MLS-encrypting and sending rotated sender key distribution"
            );
            match deps.crypto.mls_encrypt_management(
                context_id_bytes,
                &message,
                &routing_id,
                crate::context::messaging_helpers::DEFAULT_BLOB_TTL_SECS,
            ) {
                Ok(sealed) => {
                    if let Err(e) = deps.transport.send_message(&routing_id, &sealed) {
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
// 4. close_context (per-context, forwarder)
// ---------------------------------------------------------------------------

/// Initiates cooperative context closure.
///
/// For `SingleAdmin` governance: delegates to [`close_context_with_key`]
/// with no signing key. Multi-admin contexts are rejected — they must
/// route through the governance path
/// (`GovernanceAction::CloseContext`).
///
/// # Errors
///
/// See [`close_context_with_key`].
pub async fn close_context(
    state: &mut PerContextState,
    deps: &ActorDeps,
    handle: &ContextHandle,
    initiator_did: &DID,
) -> Result<CloseResult, ContextError> {
    close_context_with_key(state, deps, handle, initiator_did, None).await
}

// ---------------------------------------------------------------------------
// 5. close_context_with_key (per-context)
// ---------------------------------------------------------------------------

/// Closes a context with an optional signing key for final checkpoint
/// generation (§9.9.3).
///
/// Multi-admin contexts (any governance model other than `SingleAdmin`)
/// MUST close through the governance path. The actor-shape body
/// enforces that gate against `state.governance.engine.model_config()`.
///
/// # Errors
///
/// - [`ContextError::ContextNotActive`] if the context's lifecycle
///   state is not Active.
/// - [`ContextError::PermissionDenied`] if the governance model is not
///   `SingleAdmin` (the close must route through governance).
/// - Errors propagated from [`ttl::close_context`].
pub async fn close_context_with_key(
    state: &mut PerContextState,
    deps: &ActorDeps,
    handle: &ContextHandle,
    initiator_did: &DID,
    signing_key: Option<&ed25519_dalek::SigningKey>,
) -> Result<CloseResult, ContextError> {
    let context_id = handle.context_id().to_owned();

    // State check inside actor body -- eliminates TOCTOU race.
    state::require_active(&state.handle)?;

    // Gate: multi-admin models must use governance path (SCP-270, ADR-031).
    if !matches!(
        state.governance.engine.model_config(),
        GovernanceModelConfig::SingleAdmin { .. }
    ) {
        return Err(ContextError::PermissionDenied(
            "multi-admin contexts must close through governance \
             (propose GovernanceAction::CloseContext)"
                .to_owned(),
        ));
    }

    // Snapshot role_state for the ttl::close_context call.
    let role_state = state.role_state.clone();

    // Delegate to ttl::close_context for the lifecycle transition + role
    // gate (async).
    let result =
        ttl::close_context(handle, initiator_did, &role_state, deps.event_log.as_ref()).await?;

    // Fix C: Re-check ContextClose capability after the state transition
    // committed. If capability was revoked between the gate and the
    // cleanup, log a warning for auditability — the state transition
    // already happened (cannot undo).
    if !state
        .role_state
        .member_has_capability(initiator_did.as_ref(), &Capability::ContextClose)
    {
        tracing::warn!(
            context_id = %context_id,
            initiator_did = %initiator_did,
            "ContextClose capability revoked between gate and cleanup — \
             state transition already committed, proceeding with cleanup"
        );
    }

    state.ttl.timer.cancel();
    state.governance.timeout_task.cancel();
    // Drop broadcast context state -- keys are zeroed by Zeroize.
    state.broadcast_context = None;

    // §9.10.4: clear pseudonym state on close. The local pseudonym is
    // derived from secret key material; zeroing it prevents leaking
    // the routing ID after context teardown.
    state.local_pseudonym = None;
    state.pseudonym_registry.clear();

    // Participation decay: clear participation cache and cooldown state
    // on context close (#1530).
    state.governance.decay_participation();

    // Final checkpoint before close (§9.9.3): force-create a checkpoint
    // to capture the terminal event log state. This ensures
    // equivocation detection covers the full context lifetime.
    // Best-effort: skip if no signing key is available.
    if let Some(sk) = signing_key {
        let now = deps.clock.now_secs();
        let broadcast_context_is_none = state.broadcast_context.is_none();
        let mls_epoch = state.epoch.mls_epoch;
        let cp = crate::context::queries_helpers::force_create_checkpoint_fields(
            &context_id,
            broadcast_context_is_none,
            mls_epoch,
            &mut state.checkpoint_events_since,
            &mut state.checkpoint_last_time_secs,
            &mut state.checkpoints,
            initiator_did,
            sk,
            now,
            deps.event_log.as_ref(),
        );
        tracing::debug!(
            context_id = %context_id,
            event_count = cp.event_count,
            "final checkpoint created on close (§9.9.3)"
        );
    }

    let close_event = ContextEvent::SystemClose {
        initiator_did: initiator_did.clone(),
    };
    state::emit_event_into(
        &mut state.receive_buffer,
        close_event,
        &context_id,
        deps.event_tx.as_ref(),
    );

    // Metrics gauge refresh is a Supervisor-wide operation: it round-trips a
    // mailbox query to EVERY registered context actor -- including this one,
    // which is still executing inside its own close handler. Awaiting it here
    // self-deadlocks: the query parks in our own mailbox behind the command we
    // are still processing, so it cannot be answered until close returns, but
    // close cannot return until the query is answered -- it unwinds only when
    // the 30s send timeout fires (surfacing as `close_context exceeded 30s
    // budget`). Detach it: the close handler returns, this actor's command loop
    // frees, and the refresh then observes up-to-date state. Gauges are
    // eventually-consistent metrics, so fire-and-forget is the correct coupling.
    let supervisor = deps.supervisor.clone();
    tokio::spawn(async move {
        supervisor.update_context_gauges().await;
    });

    // Persist context state after close (best-effort).
    crate::context::messaging_helpers::persist_state_best_effort(state, deps, &context_id);

    Ok(result)
}

// ---------------------------------------------------------------------------
// 6. join_context (per-context)
// ---------------------------------------------------------------------------

/// Joins a member to a context.
///
/// Validates the joiner's key package, performs the F4 escrow dance
/// (economy + sybil + hard-rate-limit, then authorize, MLS add,
/// sender-key distribute, membership mutate, capture), and appends a
/// `MemberJoined` event.
///
/// Actor-owned state collapses the legacy three-phase lock dance. The
/// actor's mailbox already serializes per-context commands, so each
/// phase happens with `state` borrowed continuously.
///
/// # Errors
///
/// - [`ContextError::ContextNotRegistered`] if the context is unknown.
/// - [`ContextError::ContextNotActive`] if the lifecycle state is not
///   Active.
/// - [`ContextError::CryptoFailed`] / sybil / economy / version /
///   transport / event-log failures are propagated and the F4
///   `EconomyTicket` is rolled back.
#[allow(clippy::too_many_lines)]
pub async fn join_context(
    state: &mut PerContextState,
    deps: &ActorDeps,
    handle: &ContextHandle,
    key_package: KeyPackage,
    spending_ucan: Option<&scp_protocol::crypto::ucan::UcanToken>,
    local_pseudonym: Option<[u8; 32]>,
) -> Result<(), ContextError> {
    let context_id = handle.context_id().to_owned();
    let context_id_bytes = state::context_id_to_bytes(&context_id);
    let member_did = key_package.owner_did.clone();

    // Fast-fail: reject obviously incompatible versions before expensive
    // crypto ops (MLS group join, sender key derivation). Looks up the
    // stored context's params (not the caller-supplied handle params)
    // so this check is authoritative even when the caller passes an
    // ephemeral handle with default params (e.g. UniFFI bridge).
    state
        .handle
        .params()
        .check_version_compatibility(scp_protocol::envelope::SCP_PROTOCOL_VERSION)?;

    // Validate key package before any mutations (idempotent, no lock needed).
    let kp_bytes = key_package.mls_key_package_bytes.as_deref();
    deps.crypto.validate_key_package(&member_did, kp_bytes)?;

    // Phase 1: state + sybil + economy enforcement against actor-owned
    // state. This happens BEFORE any crypto mutations so that a rejected
    // payment never grants MLS group access or sender keys.
    state::require_active(&state.handle)?;

    // Defense-in-depth: re-check version compatibility after the eager
    // crypto validation. Governance could theoretically change the
    // min_protocol_version between the early check and here.
    state
        .handle
        .params()
        .check_version_compatibility(scp_protocol::envelope::SCP_PROTOCOL_VERSION)?;

    // M13: Sybil resistance check BEFORE economy enforcement so that
    // a rejected sybil attacker doesn't consume budget. Fail-closed.
    crate::context::lifecycle_logic::evaluate_sybil_resistance(
        state.handle.params().sybil_policy.as_ref(),
        &state.governance,
        &member_did,
        deps.clock.now_secs(),
    )?;

    // Defense-in-depth hard rate limit on joins (Matrix-style token
    // bucket). On any subsequent failure we refund the token.
    let now_secs = deps.clock.now_secs();
    if !state
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
    // F5: capture the rollback token so a join failure refunds THIS
    // entry specifically rather than racing concurrent joiners.
    let velocity_token = state
        .governance
        .velocity_tracker
        .record_message(&member_did, now_secs);

    let member_count = state.membership.count();
    let deducted_cost = match crate::context::lifecycle_logic::enforce_join_economy(
        &mut state.governance,
        member_count,
        &member_did,
        now_secs,
        spending_ucan,
        &context_id,
        &*deps.clock,
        &deps.key_resolver,
    ) {
        Ok(cost) => cost,
        Err(e) => {
            // No ticket exists yet — roll back inline against actor-owned
            // state.
            state
                .governance
                .velocity_tracker
                .rollback(&member_did, velocity_token);
            state.governance.hard_rate_limit.refund(&member_did);
            return Err(e);
        }
    };
    // F4: wrap the Phase 1 state in an EconomyTicket so every
    // downstream error path (adapter, MLS, sender-key) is forced
    // to roll back velocity + hard_rate_limit + budget, not just
    // the budget.
    let ticket = crate::context::economy_logic::EconomyTicket {
        actor_did: member_did.clone(),
        deducted_cost,
        velocity_token,
        needs_hard_rate_limit_refund: true,
        consumed: false,
    };

    // Phase 2: Authorize payment (escrow hold) BEFORE any crypto mutation.
    // If authorization fails, rollback the ticket — no MLS state touched.
    let auth = match crate::context::economy_helpers::authorize_paid_action(
        state,
        deps,
        scp_protocol::economy::types::PaidActionType::ContextJoin,
        &member_did,
        &context_id,
    )
    .await
    {
        Ok(auth) => auth,
        Err(payment_err) => {
            crate::context::economy_logic::rollback_economy_ticket_inline(
                &mut state.governance,
                ticket,
            );
            return Err(payment_err);
        }
    };

    // Phase 3: MLS add_member + sender key distribution (crypto mutations).
    // On failure: void escrow + rollback ticket. No MLS rollback needed
    // because add_member itself failed (no state change occurred).
    let add_output = match deps
        .crypto
        .add_member(&context_id_bytes, &member_did, kp_bytes)
    {
        Ok(output) => output,
        Err(e) => {
            if let Some(a) = auth {
                crate::context::economy_helpers::void_paid_action(state, deps, a, &context_id)
                    .await;
            }
            crate::context::economy_logic::rollback_economy_ticket_inline(
                &mut state.governance,
                ticket,
            );
            return Err(e);
        }
    };

    if let Err(e) = deps
        .crypto
        .distribute_sender_key(&context_id_bytes, &member_did)
    {
        // Sender key distribution failed after MLS add — rollback MLS state.
        let _ = deps.crypto.remove_member(&context_id_bytes, &member_did);
        let _ = deps
            .crypto
            .remove_member_sender_key(&context_id_bytes, &member_did);
        if let Some(a) = auth {
            crate::context::economy_helpers::void_paid_action(state, deps, a, &context_id).await;
        }
        crate::context::economy_logic::rollback_economy_ticket_inline(
            &mut state.governance,
            ticket,
        );
        return Err(e);
    }

    // Drain pending HPKE-sealed sender key distribution messages and
    // deliver them via the MLS management channel (§9.16.2). MLS-wrap
    // is mandatory — see comment on `drain_and_deliver_sender_keys`.
    if let Err(e) = drain_and_deliver_sender_keys(deps, &context_id, &context_id_bytes) {
        // Drain failed catastrophically — roll back MLS state, sender
        // key, escrow, and economy ticket so the join is fully aborted.
        let _ = deps.crypto.remove_member(&context_id_bytes, &member_did);
        let _ = deps
            .crypto
            .remove_member_sender_key(&context_id_bytes, &member_did);
        if let Some(a) = auth {
            crate::context::economy_helpers::void_paid_action(state, deps, a, &context_id).await;
        }
        crate::context::economy_logic::rollback_economy_ticket_inline(
            &mut state.governance,
            ticket,
        );
        return Err(e);
    }

    // Phase 4: Membership mutation. On failure: void escrow + rollback
    // ticket + rollback MLS state.
    if let Err(e) = join_context_membership(state, deps, &context_id, &member_did, add_output) {
        let _ = deps.crypto.remove_member(&context_id_bytes, &member_did);
        let _ = deps
            .crypto
            .remove_member_sender_key(&context_id_bytes, &member_did);
        if let Some(a) = auth {
            crate::context::economy_helpers::void_paid_action(state, deps, a, &context_id).await;
        }
        crate::context::economy_logic::rollback_economy_ticket_inline(
            &mut state.governance,
            ticket,
        );
        return Err(e);
    }

    // Phase 4.5: Store local pseudonym after membership mutation succeeds.
    if let Some(pseudonym) = local_pseudonym {
        state.local_pseudonym = Some(pseudonym);
    }

    // Phase 5: Capture the escrow hold after all mutations succeeded.
    // Consume the ticket — commit returns the deducted cost for the
    // capture step and marks the ticket as committed so the Drop
    // guard stays quiet.
    let deducted_cost = crate::context::economy_logic::commit_economy_ticket(ticket);
    capture_join_payment(state, deps, auth, &member_did, &context_id, deducted_cost).await;

    // Append MemberJoined event to event log.
    deps.event_log
        .append_context_event(&context_id_bytes, "MemberJoined", member_did.as_ref())?;
    state.checkpoint_events_since += 1;

    // Persist context state after join (best-effort).
    crate::context::messaging_helpers::persist_state_best_effort(state, deps, &context_id);

    Ok(())
}

// ---------------------------------------------------------------------------
// 7. join_context_membership (per-context, transitive of join_context)
// ---------------------------------------------------------------------------

/// Performs the membership state mutations for [`join_context`] (Phase 4).
///
/// # Errors
///
/// - [`ContextError::ContextNotActive`] if the context is no longer
///   Active.
/// - Errors from `roles::system_assign_role` propagated as
///   [`ContextError::MembershipFailed`].
pub fn join_context_membership(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    member_did: &DID,
    add_output: scp_protocol::context::builder::AddMemberOutput,
) -> Result<(), ContextError> {
    state::require_active(&state.handle)?;

    crate::context::lifecycle_logic::post_join_bookkeeping(
        &mut state.governance,
        &state.receive_buffer,
        context_id,
        member_did,
        deps.clock.now_secs(),
        deps.event_log.as_ref(),
    );

    // Add member to role state.
    state.role_state.members.insert(member_did.to_string());

    // Assign default "member" role.
    //
    // H2: Use system_assign_role to bypass the RoleAssign capability
    // check. The join handshake is a self-service flow that already
    // passed economy / sybil / capacity / version gates above —
    // re-checking `RoleAssign` against the creator would silently fail
    // every join after the creator has been demoted out of an admin
    // role. The default "member" role assignment carries no ambient
    // authority (it's the protocol-defined floor), so there is nothing
    // to authorize a second time.
    let creator_did = state.role_state.creator_did.clone();
    let tokens =
        roles::system_assign_role(&mut state.role_state, member_did, "member", &*deps.clock)
            .map_err(|e| ContextError::MembershipFailed(e.to_string()))?;

    // Add to membership tracking.
    state
        .membership
        .add_member(member_did.clone(), "member".into(), tokens);

    // Generate access key for the new member (§9.17.2 step 2).
    // The inviter stores the key so `send_message` can wrap content
    // for this recipient. Key distribution to the joiner happens via
    // the Welcome payload / out-of-band key exchange.
    let member_access_key =
        scp_protocol::crypto::access_keys::generate_access_key(context_id, member_did);
    state
        .access
        .access_key_store
        .set(context_id, member_did, member_access_key);

    // Emit MemberJoined event to receive buffer.
    let join_event = ContextEvent::MemberJoined {
        member_did: member_did.clone(),
        role_name: "member".into(),
    };
    state::emit_event_into(
        &mut state.receive_buffer,
        join_event,
        context_id,
        deps.event_tx.as_ref(),
    );

    // Emit WelcomeGenerated event if the add produced a Welcome message.
    // Mirrors `state::push_welcome_event` body inline because that helper
    // takes legacy `state::PerContextState` and we operate on the
    // actor-shape struct here.
    if !add_output.welcome_bytes.is_empty() {
        state::emit_event_into(
            &mut state.receive_buffer,
            ContextEvent::WelcomeGenerated {
                context_id: context_id.to_owned(),
                creator_did: DID(creator_did),
                member_did: member_did.clone(),
                welcome_bytes: scp_protocol::context::membership::RedactedBytes(
                    add_output.welcome_bytes,
                ),
                commit_bytes: scp_protocol::context::membership::RedactedBytes(
                    add_output.commit_bytes,
                ),
            },
            context_id,
            deps.event_tx.as_ref(),
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// 8. capture_join_payment (per-context, transitive of join_context)
// ---------------------------------------------------------------------------

/// Captures the escrow hold after a successful join (Phase 5 of
/// [`join_context`]).
///
/// Best-effort: capture failure is logged + audited via a
/// `PaymentCaptureFailed` event log entry but does NOT roll back the
/// budget (H8 — service was rendered).
pub async fn capture_join_payment(
    state: &mut PerContextState,
    deps: &ActorDeps,
    auth: Option<crate::context::economy_logic::PaidActionAuthorization>,
    member_did: &DID,
    context_id: &str,
    deducted_cost: Option<scp_protocol::economy::types::Amount>,
) {
    if let Some(a) = auth
        && let Err(e) = crate::context::economy_helpers::complete_paid_action(
            state, deps, a, member_did, context_id,
        )
        .await
    {
        // H8: do NOT rollback budget — service was delivered (member joined).
        tracing::warn!(
            context_id,
            "payment capture failed after successful join: {e}"
        );
        // H19: append durable audit record to event log + receive buffer.
        record_payment_capture_failure(
            state,
            deps,
            context_id,
            "join_context",
            member_did,
            &e.to_string(),
            deducted_cost,
        );
    }
}

/// Append a `PaymentCaptureFailed` durable event log entry plus the
/// matching receive-buffer push. Actor-shape inline replacement for
/// `manager_methods::record_payment_capture_failure`.
#[allow(clippy::too_many_arguments)]
fn record_payment_capture_failure(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    action: &str,
    actor_did: &DID,
    error_msg: &str,
    cost: Option<scp_protocol::economy::types::Amount>,
) {
    let context_id_bytes = scp_protocol::context::context_id_bytes(context_id);
    let payload = serde_json::json!({
        "action": action,
        "error": error_msg,
        "cost": cost.map(scp_protocol::economy::types::Amount::value),
    });
    if let Err(log_err) = deps.event_log.append_context_event_with_payload(
        &context_id_bytes,
        "PaymentCaptureFailed",
        actor_did.as_ref(),
        Some(&payload),
    ) {
        tracing::warn!(
            context_id,
            "failed to append PaymentCaptureFailed to event log: {log_err}"
        );
    }
    state.checkpoint_events_since += 1;
    let event = ContextEvent::PaymentCaptureFailed {
        action: action.to_owned(),
        actor_did: actor_did.clone(),
        error: error_msg.to_owned(),
        cost: cost.map(scp_protocol::economy::types::Amount::value),
    };
    state::emit_event_into(
        &mut state.receive_buffer,
        event,
        context_id,
        deps.event_tx.as_ref(),
    );
}

// ---------------------------------------------------------------------------
// 9. create_context (bootstrap; constructs fresh PerContextState)
// ---------------------------------------------------------------------------

/// Creates a new SCP context with the two-phase commit pattern.
///
/// Validates parameters, builds a fresh `PerContextState`, and
/// registers it through
/// [`SupervisorHandle::insert_context`](crate::context::supervisor::handle::SupervisorHandle::insert_context).
/// Calls [`finalize_create`] to set up gauges, governance timeout,
/// persistence, and TTL timer.
///
/// # Errors
///
/// - [`ContextCreationError::CreationFailed`] for version
///   incompatibility, governance / consequence-rule / economic-policy
///   validation failures, or supervisor registration failures.
/// - Crypto / transport / event-log failures during the initial MLS
///   group setup.
#[allow(clippy::too_many_lines)]
// Bootstrap entry points are callable from Phase 2A finalization's
// actor-spawn pipeline. The actor handler currently routes bootstrap
// commands through the shim path because the per-context actor that
// would own this state is not yet spawned at command-receipt time.
#[allow(dead_code)]
pub async fn create_context(
    deps: &ActorDeps,
    context_id: String,
    params: ContextParams,
    creator_did: DID,
    local_pseudonym: Option<[u8; 32]>,
) -> Result<ContextHandle, ContextCreationError> {
    // Defense-in-depth: verify creator's SDK version satisfies
    // min_protocol_version.
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
        Arc::clone(&deps.key_resolver),
    )?;
    let handle = crate::context::builder::create_context(
        context_id.clone(),
        params.clone(),
        deps.crypto.as_ref(),
        deps.transport.as_ref(),
        deps.event_log.as_ref(),
        creator_did.as_ref(),
    )
    .await?;
    let ceiling = CapabilityCeiling::new(params.ceiling.iter().cloned());
    let role_state =
        ContextRoleState::new(&context_id, &*creator_did, ceiling, vec![], &*deps.clock)
            .map_err(|e| ContextCreationError::CreationFailed(e.to_string()))?;
    let mut membership = MembershipState::new();
    let creator_tokens = role_state
        .assignments
        .get(creator_did.as_ref())
        .map(|a| a.tokens.clone())
        .unwrap_or_default();
    membership.add_member(creator_did.clone(), "admin".into(), creator_tokens);
    let broadcast_context =
        deps.supervisor
            .init_broadcast_context(&context_id, &params, &creator_did)?;
    let (initial_threshold_signers, initial_threshold_value) = match &params.governance {
        GovernanceModel::Threshold { threshold, signers } => (signers.clone(), *threshold),
        _ => (Vec::new(), 0),
    };
    let initial_access_key_store = generate_initial_access_key_store(&context_id, &creator_did);
    let initial_members: HashSet<DID> = membership.members().map(|m| m.did.clone()).collect();
    // ADR-049 §Decision 1: branch the actor's mode-discriminated union on
    // whether the supervisor returned a broadcast roster — the SCP-227
    // broadcast init path returns `Some(BroadcastContext)` iff
    // `params.mode == ContextMode::Broadcast`.
    let context_id_bytes = state::context_id_to_bytes(&context_id);
    let actor_members: HashSet<DID> = initial_members.clone();
    let mode = if broadcast_context.is_some() {
        ContextModeState::Broadcast(Box::<crate::context::actor::state::BroadcastState>::default())
    } else {
        ContextModeState::Encrypted(Box::<ContextCryptoState>::default())
    };
    let per_context = PerContextState {
        context_id: context_id_bytes,
        created_at: deps.clock.now_secs(),
        generation: 0, // assigned by SupervisorHandle::insert_context.
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
                Arc::clone(&deps.clock),
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
            timer: TtlTimer::with_clock(Arc::clone(&deps.clock)),
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
        checkpoint_last_time_secs: deps.clock.now_secs(),
        checkpoints: Vec::new(),
        merkle_tree: scp_event_log::EventLog::new(context_id.clone()),
        // §9.10.4: pseudonym routing. Only meaningful for encrypted
        // contexts; broadcast contexts ignore this field.
        local_pseudonym,
        pseudonym_registry: HashMap::new(),
        // ADR-049 commit 8: fresh actor-shape tracker at creation.
        send_tracker: SendSequenceTracker::new(),
        // ADR-049 Phase 2A finalization keystone (commit 12 phase 2A
        // finalization — type unification): the actor-owned state fields
        // start in their fresh-instance shapes. `event_log` is `None`
        // until the first event lands; the in-memory RFC-6962 Merkle
        // tree above is the proof-generation surface and is populated
        // lazily by the messaging handler.
        recv_tracker: RecvSequenceTracker::new(),
        saga_pending: HashMap::new(),
        pending_broadcast_publishes: HashMap::new(),
        welcome_scratchpad: None,
        lifecycle_state: ContextLifecycleState::Open,
        event_log: None,
        mode,
    };

    // Atomic check-and-insert — eliminates TOCTOU race between
    // contains_key and insert. Stamps a fresh generation atomically.
    deps.supervisor
        .insert_context(context_id.clone(), per_context)?;

    // ADR-049 Phase 2A finalization bootstrap dual-write: every
    // production context construction now populates BOTH the legacy
    // contexts DashMap (above) AND the actor registry. The actor
    // proxies its state through the same `Arc<Mutex<PerContextState>>`
    // the DashMap holds (`new_dashmap_backed` semantics — see
    // `Supervisor::spawn_actor_dashmap_backed`), so there is no
    // divergence during the transition window. Subsequent finalization
    // sessions delete the DashMap once every legacy consumer is
    // ported. Bootstrap keeps its `&ActorDeps` borrow alive for
    // `finalize_create` below; `clone_for_spawn` hands the actor task
    // an owned bundle without disturbing that borrow.
    let owned_deps = deps.clone_for_spawn();
    deps.supervisor
        .spawn_actor_for_context(context_id.clone(), owned_deps)
        .await
        .map_err(|e| ContextCreationError::CreationFailed(e.to_string()))?;

    finalize_create(deps, &context_id, params.ttl, &handle).await;
    Ok(handle)
}

// ---------------------------------------------------------------------------
// 10. finalize_create (transitive of create_context / restore_context / import_context)
// ---------------------------------------------------------------------------

/// Post-creation finalization: gauges, governance timeout, persistence,
/// TTL timer.
///
/// Runs after a fresh `PerContextState` has been registered through
/// [`SupervisorHandle::insert_context`](crate::context::supervisor::handle::SupervisorHandle::insert_context).
/// Reaches the supervisor through the handle for cross-context surfaces
/// (gauges, contexts-arc); the designated-legacy
/// `start_governance_timeout_task_legacy` is reached via the
/// [shim escape](
/// crate::context::supervisor::handle::SupervisorHandle::shim_supervisor)
/// because that helper iterates the contexts `DashMap` and stays
/// legacy-shape until the per-context governance-timeout actor lands.
pub async fn finalize_create(
    deps: &ActorDeps,
    context_id: &str,
    ttl_duration: Option<std::time::Duration>,
    handle: &ContextHandle,
) {
    deps.supervisor.update_context_gauges().await;
    // Install the governance-timeout interval task on the freshly-spawned
    // actor via the mailbox (registry + EvaluateTimeouts tick — no
    // DashMap reach).
    crate::context::governance_helpers::start_governance_timeout_task(&deps.supervisor, context_id)
        .await;
    deps.supervisor
        .persist_context_and_broadcast(context_id)
        .await;
    if let Some(duration) = ttl_duration {
        // Install the TTL timer by mailboxing StartTtlTimer to the
        // freshly-spawned actor: the actor owns `state.ttl.timer` and
        // installs the timer task on its own state (registry + mailbox
        // tick — no DashMap reach).
        deps.supervisor
            .dispatch_start_ttl_timer(context_id, handle.params().clone(), duration)
            .await;
    }
}

// ---------------------------------------------------------------------------
// 11. generate_initial_access_key_store (transitive of create_context)
// ---------------------------------------------------------------------------

/// Generates the initial access key store for context creation
/// (§9.17.2). Pure — no per-context state.
fn generate_initial_access_key_store(
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
// 12. import_context (bootstrap; constructs fresh PerContextState)
// ---------------------------------------------------------------------------

/// Imports a previously exported context.
///
/// Validates the export, performs the C3 per-instance wipe policy,
/// restores crypto state with epoch-floor regression guard, builds a
/// fresh `PerContextState` from the snapshot, and registers it
/// through
/// [`SupervisorHandle::replace_context`](crate::context::supervisor::handle::SupervisorHandle::replace_context).
/// Re-spawns the TTL timer if the export carried `ttl_remaining_secs`.
///
/// # Errors
///
/// - [`ContextError::MembershipFailed`] if the existing context is not
///   replaceable (only Closing/Closed/Expired/Tombstoned are
///   replaceable on import).
/// - [`ContextError::PersistenceFailed`] if any validation /
///   sanitization step rejects the imported snapshot (HRL, velocity,
///   pricing, MLS state restore).
/// - [`ContextError::InvalidState`] if the snapshot's lifecycle state
///   is anything other than `Active` or `Creating`.
/// - Crypto / event-log failures during state restore are propagated.
#[allow(clippy::too_many_lines)]
#[allow(dead_code)] // Bootstrap entry — see `create_context` rationale.
pub async fn import_context(
    deps: &ActorDeps,
    export: crate::context::export_import::ContextExport,
) -> Result<ContextHandle, ContextError> {
    // 1. Validate export.
    crate::context::export_import::validate_export_for_import(&export)?;
    // C3: Validate consequence rules on import. Uses
    // validate_against_config to enforce the opt-in gate for
    // RevokeAccess even on imported snapshots and rejects with the
    // canonical SCP-CTX-2092 envelope so SDK callers can detect
    // structural rejection by `.code` rather than message body.
    crate::context::lifecycle_logic::validate_consequence_rules_for_import(
        &export.snapshot.consequence_rules,
        &export.snapshot.context_params.consequence_config,
    )?;

    let context_id = export.snapshot.context_id.clone();
    let ctx_id_bytes = scp_protocol::context::context_id_bytes(&context_id);

    // 2. Existing-context replaceability check + crypto state cleanup.
    // The supervisor handle's replace_context performs the atomic
    // gate-and-replace under the supervisor's write_lock so a
    // concurrent caller cannot insert an Active context after the
    // replaceability check.
    deps.supervisor
        .with_existing_context_for_import(&context_id, |existing_state| {
            let is_replaceable = existing_state.handle.try_read_state().is_some_and(|s| {
                matches!(
                    s,
                    ContextState::Closing
                        | ContextState::Closed
                        | ContextState::Expired
                        | ContextState::Tombstoned
                )
            });
            if !is_replaceable {
                return Err(ContextError::MembershipFailed(format!(
                    "context '{context_id}' already exists — cannot import"
                )));
            }
            // §23.17 Invariant 3: capture per-sender epoch floors BEFORE
            // destroying crypto state so they can be validated against the
            // incoming snapshot (replay-based floor regression guard).
            let local_epoch_floors = deps.crypto.export_sender_key_epochs(&ctx_id_bytes);

            // Clean up old crypto state before reimport.
            let _ = deps.crypto.destroy_mls_group(&ctx_id_bytes);
            let _ = deps.crypto.destroy_sender_key(&ctx_id_bytes);

            // Restore incoming crypto state (if the export carries any).
            if !export.mls_state.is_empty() {
                deps.crypto
                    .restore_crypto_state(&ctx_id_bytes, &export.mls_state)
                    .map_err(|e| {
                        ContextError::PersistenceFailed(format!(
                            "import: crypto state restore failed: {e}"
                        ))
                    })?;
            }

            // §23.17 Invariant 3: validate that no per-sender epoch floor
            // regresses, and merge local floors back (max-merge) to
            // preserve Invariant 4. On failure, roll back the restored
            // crypto state.
            if let Err(e) = deps.crypto.validate_and_merge_epoch_floors(
                &ctx_id_bytes,
                local_epoch_floors,
                crate::crypto::mls::provider::MAX_EPOCH_ADVANCE,
            ) {
                // Rollback: destroy the just-restored crypto state.
                let _ = deps.crypto.destroy_mls_group(&ctx_id_bytes);
                let _ = deps.crypto.destroy_sender_key(&ctx_id_bytes);
                return Err(e);
            }
            Ok(())
        })
        .await?;
    // No-existing-context path: restore crypto state directly.
    if !deps.supervisor.has_context(&context_id) && !export.mls_state.is_empty() {
        deps.crypto
            .restore_crypto_state(&ctx_id_bytes, &export.mls_state)
            .map_err(|e| {
                ContextError::PersistenceFailed(format!("import: crypto state restore failed: {e}"))
            })?;
    }

    // 3. Import event log data if present.
    if !export.event_log_data.is_empty() {
        deps.event_log
            .import_event_log_data(&ctx_id_bytes, &export.event_log_data)?;
    }

    // 4. Reconstruct the ContextHandle.
    let handle = ContextHandle::new(context_id.clone(), export.snapshot.context_params.clone());

    // Transition to the state from the snapshot.
    match &export.snapshot.state {
        ContextState::Active => {
            handle.transition_to(&ContextState::Active).await?;
        }
        ContextState::Creating => {
            // Already in Creating state, nothing to do.
        }
        other => {
            return Err(ContextError::InvalidState(format!(
                "cannot import context in {other} state — only Active and Creating are supported"
            )));
        }
    }

    // 5. Reconstruct governance engine from snapshot.
    let governance_engine = state::restore_governance_engine_from_snapshot(
        &export.snapshot,
        Arc::clone(&deps.key_resolver),
    )?;

    // 6. Build PerContextState from the snapshot.
    let initial_members: HashSet<DID> = export
        .snapshot
        .membership
        .members()
        .map(|m| m.did.clone())
        .collect();

    // F6: Validate and sanitize persisted anti-spam snapshot state
    // BEFORE reconstructing the trackers. Tampered imports that
    // carry future timestamps (which would let a malicious sender
    // "pre-consume" future capacity) are rejected; stale entries
    // are clamped. Matches restore_context policy verbatim.
    let now_for_validation = deps.clock.now_secs();
    let hrl_config = export
        .snapshot
        .hard_rate_limit_config
        .clone()
        .unwrap_or_else(scp_protocol::economy::antispam::HardRateLimitConfig::matrix_defaults);
    hrl_config.validate().map_err(|e| {
        ContextError::PersistenceFailed(format!(
            "import: hard-rate-limit config validation failed: {e}"
        ))
    })?;
    let mut hrl_state = export.snapshot.hard_rate_limit_state.clone();
    scp_protocol::economy::antispam::TokenBucketLimiter::validate_and_sanitize_snapshot(
        &mut hrl_state,
        &hrl_config,
        now_for_validation,
        scp_protocol::economy::antispam::SNAPSHOT_CLOCK_SKEW_TOLERANCE_SECS,
    )
    .map_err(|e| {
        ContextError::PersistenceFailed(format!(
            "import: hard-rate-limit snapshot validation failed: {e}"
        ))
    })?;
    let validated_velocity_tracker = match export.snapshot.velocity_tracker_state.clone() {
        Some(vts) => {
            let mut entries = vts.entries;
            scp_protocol::economy::antispam::SenderVelocityTracker::validate_and_sanitize_snapshot(
                &mut entries,
                60,
                now_for_validation,
                scp_protocol::economy::antispam::SNAPSHOT_CLOCK_SKEW_TOLERANCE_SECS,
            )
            .map_err(|e| {
                ContextError::PersistenceFailed(format!(
                    "import: velocity snapshot validation failed: {e}"
                ))
            })?;
            scp_protocol::economy::antispam::SenderVelocityTracker::from_snapshot(60, entries)
        }
        None => scp_protocol::economy::antispam::SenderVelocityTracker::new(60),
    };
    let validated_message_pricing = export.snapshot.message_pricing.clone().or_else(|| {
        crate::context::lifecycle_logic::derive_message_pricing(
            export.snapshot.economic_policy.as_ref(),
        )
    });
    if let Some(ref pricing) = validated_message_pricing {
        pricing.validate().map_err(|e| {
            ContextError::PersistenceFailed(format!(
                "import: message pricing config validation failed: {e}"
            ))
        })?;
    }

    // C3: Clamp imported `cooldown_until` to a bounded horizon and drop
    // entries with out-of-range rule indices, mirroring the WASM bridge
    // `validate_imported_snapshot` policy.
    let mut sanitized_cooldown_until = export.snapshot.cooldown_until.clone();
    crate::context::lifecycle_logic::sanitize_cooldown_until(
        &mut sanitized_cooldown_until,
        &export.snapshot.consequence_rules,
        now_for_validation,
        "import",
    );

    // ADR-049 Phase 2A finalization keystone: import path is encrypted-only
    // (`broadcast_context: None` below). Derive the actor's `members` set
    // from the imported membership snapshot — `members()` enumerates the
    // current member DIDs in the post-validation `MembershipState`.
    let context_id_bytes = state::context_id_to_bytes(&context_id);
    let actor_members: HashSet<DID> = export
        .snapshot
        .membership
        .members()
        .map(|m| m.did.clone())
        .collect();
    let per_context = PerContextState {
        context_id: context_id_bytes,
        created_at: deps.clock.now_secs(),
        generation: 0, // assigned by SupervisorHandle on insert.
        handle: handle.clone(),
        membership: export.snapshot.membership,
        members: actor_members,
        role_state: export.snapshot.role_state,
        receive_buffer: ReceiveBuffer::new(),
        broadcast_context: None,
        migration_state: None,
        governance: GovernanceState {
            engine: governance_engine,
            executed_proposals: {
                let now = deps.clock.now_secs();
                export
                    .snapshot
                    .executed_proposals
                    .into_iter()
                    .map(|id| (id, now))
                    .collect()
            },
            // C3: Wipe `approved_proposals`. Importing approved-but-not-
            // yet-executed proposals lets a malicious snapshot pre-load
            // forged `RemoveMember` entries.
            // H10: Reset next_proposal_seq as well.
            next_proposal_seq: 0,
            approved_proposals: HashMap::new(),
            freeze: export.snapshot.governance_freeze,
            timeout_task: GovernanceTimeoutTask::new(),
            deadlock: DeadlockDetectionState::default(),
            threshold_signers: export.snapshot.threshold_signers,
            threshold_value: export.snapshot.threshold_value,
            pending_ceiling_modification: export.snapshot.pending_ceiling_modification,
            pending_economic_policy_change: export.snapshot.pending_economic_policy_change,
            registered_tools: export.snapshot.registered_tools,
            tool_interfaces: export.snapshot.tool_interfaces,
            pruning_policy: export.snapshot.pruning_policy,
            message_pricing: validated_message_pricing,
            hard_rate_limit: scp_protocol::economy::antispam::TokenBucketLimiter::from_snapshot(
                hrl_config, hrl_state,
            ),
            economic_policy: export.snapshot.economic_policy,
            // C3: Wipe `budget_tracker` (per-instance economic grants).
            budget_tracker: scp_protocol::economy::budget::MemberBudgetTracker::new(),
            last_known_members: initial_members,
            pending_epoch_resets: Vec::new(),
            consequence_rules: export.snapshot.consequence_rules,
            velocity_tracker: validated_velocity_tracker,
            // C3: Wipe `participation_cache` — rebuilt lazily.
            participation_cache: HashMap::new(),
            cooldown_until: sanitized_cooldown_until,
            // IMPORT path (not restore): start with a FRESH spending-
            // nonce tracker.
            spending_nonce_tracker: scp_protocol::crypto::ucan::nonce::NonceTracker::new(
                context_id.clone(),
                Arc::clone(&deps.clock),
            ),
            revoked_spending_ucan_cids: HashSet::new(),
            // C3: Wipe `proposal_timestamps`.
            proposal_timestamps: HashMap::new(),
        },
        epoch: EpochState {
            mls_epoch: export.snapshot.mls_epoch,
            coordinator: EpochCoordinator::from_records(
                export.snapshot.epoch_coordination_records,
                &context_id,
            ),
            grace_store: crate::crypto::mls::epoch_grace::EpochGraceStore::new(),
            needs_reconnect: false,
        },
        access: AccessControlState {
            read_exclusion_list: export.snapshot.read_exclusion_list,
            access_key_store: export.snapshot.access_key_store,
        },
        ttl: TtlState {
            timer: TtlTimer::with_clock(Arc::clone(&deps.clock)),
            extension: None,
        },
        sequence_tracker: scp_protocol::envelope::SequenceTracker::new(),
        reorder_buffer: scp_protocol::envelope::ReorderBuffer::default(),
        // PR #1606 C6: import path starts with an empty commit retry
        // queue and no fail-close marker.
        pending_commits: VecDeque::new(),
        commit_fault: None,
        // Checkpoint tracking (§9.9.3): fresh counters for imported
        // contexts.
        checkpoint_events_since: 0,
        checkpoint_last_time_secs: deps.clock.now_secs(),
        checkpoints: Vec::new(),
        // Fresh Merkle tree for imported contexts.
        merkle_tree: scp_event_log::EventLog::new(context_id.clone()),
        // §9.10.4: pseudonym state is local-instance — wiped on import.
        local_pseudonym: None,
        pseudonym_registry: HashMap::new(),
        // ADR-049 commit 8: fresh actor-shape tracker on import.
        send_tracker: SendSequenceTracker::new(),
        // ADR-049 Phase 2A finalization keystone: import path is
        // encrypted-only (`mode = ContextModeState::Encrypted(default)`).
        // Receive tracker, saga registry, and Welcome scratchpad start
        // empty; lifecycle is Open after the replaceability gate
        // succeeded and the snapshot validated.
        recv_tracker: RecvSequenceTracker::new(),
        saga_pending: HashMap::new(),
        pending_broadcast_publishes: HashMap::new(),
        welcome_scratchpad: None,
        lifecycle_state: ContextLifecycleState::Open,
        event_log: None,
        mode: ContextModeState::Encrypted(Box::<ContextCryptoState>::default()),
    };

    // 7. Register the context atomically (replace-if-exists).
    //
    // Before swapping the legacy DashMap entry, despawn any per-
    // context actor that was attached to the prior entry. The prior
    // actor's `state_arc` field references the about-to-be-removed
    // `Arc<Mutex<PerContextState>>`; once `replace_context` swaps in a
    // fresh `Arc<Mutex<...>>`, the stale actor would silently keep
    // serving the old state until its mailbox drains. Despawning
    // first closes that window (the handle's drop closes the mpsc
    // sender, which causes the actor's run-loop to exit on the next
    // inbox-empty poll).
    let _despawned = deps.supervisor.despawn_actor(&context_id).await;
    deps.supervisor
        .replace_context(context_id.clone(), per_context)
        .await
        .map_err(|e| ContextError::MembershipFailed(e.to_string()))?;

    // ADR-049 Phase 2A finalization bootstrap dual-write: import path
    // mirrors create/restore — populate the actor registry alongside
    // the legacy contexts DashMap. The new dashmap-backed actor
    // proxies the fresh `Arc<Mutex<PerContextState>>` registered by
    // `replace_context` above.
    let owned_deps = deps.clone_for_spawn();
    deps.supervisor
        .spawn_actor_for_context(context_id.clone(), owned_deps)
        .await
        .map_err(|e| ContextError::MembershipFailed(e.to_string()))?;

    deps.supervisor.update_context_gauges().await;

    // Start governance timeout task (ADR-031 §5) via the actor mailbox.
    crate::context::governance_helpers::start_governance_timeout_task(
        &deps.supervisor,
        &context_id,
    )
    .await;

    // 8. Persist if persistence is configured.
    deps.supervisor
        .persist_context_and_broadcast(&context_id)
        .await;

    // 9. Re-spawn TTL timer if there was remaining TTL. Mailbox
    // StartTtlTimer to the freshly-spawned actor (registry + mailbox
    // tick — no DashMap reach).
    if let Some(remaining_secs) = export.snapshot.ttl_remaining_secs {
        let duration = std::time::Duration::from_secs(remaining_secs);
        deps.supervisor
            .dispatch_start_ttl_timer(&context_id, handle.params().clone(), duration)
            .await;
    }

    Ok(handle)
}

// ---------------------------------------------------------------------------
// 13. load_persisted_context_state (per-context, read-only)
// ---------------------------------------------------------------------------

/// Loads a persisted context snapshot and optional broadcast state.
///
/// # Errors
///
/// Returns [`ContextError::PersistenceFailed`] if no persistence
/// provider is configured, no snapshot exists, or the load operation
/// fails.
#[allow(dead_code)] // Transitive of `restore_context` — see bootstrap rationale.
pub fn load_persisted_context_state(
    deps: &ActorDeps,
    context_id: &str,
) -> Result<
    (
        crate::context::state::ContextSnapshot,
        Option<scp_protocol::context::broadcast::BroadcastContext>,
    ),
    ContextError,
> {
    let ctx_snapshot = deps
        .persistence
        .load_context(context_id)
        .map_err(|e| {
            ContextError::PersistenceFailed(format!(
                "failed to load context state for {context_id}: {e}"
            ))
        })?
        .ok_or_else(|| {
            ContextError::PersistenceFailed(format!("no persisted context state for {context_id}"))
        })?;

    let broadcast_ctx = deps
        .persistence
        .load_broadcast(context_id)
        .map_err(|e| {
            ContextError::PersistenceFailed(format!(
                "failed to load broadcast state for {context_id}: {e}"
            ))
        })?
        .map(scp_protocol::context::broadcast::BroadcastContext::from_snapshot);

    Ok((ctx_snapshot, broadcast_ctx))
}

/// Best-effort event log restore from persistence.
#[allow(dead_code)] // Transitive of `restore_context` — see bootstrap rationale.
fn restore_event_log_best_effort(deps: &ActorDeps, context_id: &str) {
    use crate::context::state::context_id_to_bytes;
    let ctx_id_bytes = context_id_to_bytes(context_id);
    if let Err(e) = deps.event_log.restore_event_log(&ctx_id_bytes) {
        tracing::warn!(
            context_id = %context_id,
            error = %e,
            "failed to restore event log from persistence; \
             context will start with an empty event log"
        );
        let _ = deps.event_log.init_event_log(&ctx_id_bytes);
    }
}

// ---------------------------------------------------------------------------
// 14. restore_context (bootstrap; constructs fresh PerContextState)
// ---------------------------------------------------------------------------

/// Restores a context into the supervisor from persisted state.
///
/// Loads the persisted `ContextSnapshot` and optional broadcast state,
/// reconstructs `PerContextState`, and registers it through
/// [`SupervisorHandle::insert_context`](crate::context::supervisor::handle::SupervisorHandle::insert_context).
/// Re-spawns the TTL timer if `ttl_remaining_secs` is `Some`.
///
/// # Errors
///
/// Returns [`ContextError::PersistenceFailed`] if no persisted state
/// exists. Returns [`ContextError::MembershipFailed`] if the context
/// cannot be inserted (already registered).
#[tracing::instrument(skip_all, fields(context_id))]
#[allow(clippy::too_many_lines)]
#[allow(dead_code)] // Bootstrap entry — see `create_context` rationale.
pub async fn restore_context(
    deps: &ActorDeps,
    context_id: &str,
    handle: &ContextHandle,
) -> Result<(), ContextError> {
    use crate::context::governance::timeout::{DeadlockDetectionState, GovernanceTimeoutTask};
    use crate::context::lifecycle_logic::{
        derive_message_pricing, sanitize_cooldown_until, validate_consequence_rules_for_import,
    };
    use crate::context::state::{
        context_id_to_bytes, restore_governance_engine_from_snapshot,
        restore_grace_store_from_snapshot,
    };
    use scp_protocol::context::governance::mls_integration::EpochCoordinator;
    use scp_protocol::context::membership::ReceiveBuffer;

    let (mut ctx_snapshot, broadcast_ctx) = load_persisted_context_state(deps, context_id)?;
    restore_event_log_best_effort(deps, context_id);

    validate_consequence_rules_for_import(
        &ctx_snapshot.consequence_rules,
        &ctx_snapshot.context_params.consequence_config,
    )?;

    let now_for_cooldown = deps.clock.now_secs();
    sanitize_cooldown_until(
        &mut ctx_snapshot.cooldown_until,
        &ctx_snapshot.consequence_rules,
        now_for_cooldown,
        "restore",
    );
    let ttl_remaining = ctx_snapshot.ttl_remaining_secs;

    let governance_engine =
        restore_governance_engine_from_snapshot(&ctx_snapshot, Arc::clone(&deps.key_resolver))?;
    let (grace_store, needs_reconnect) =
        restore_grace_store_from_snapshot(context_id, &ctx_snapshot);

    if !ctx_snapshot.mls_crypto_state.is_empty() {
        let ctx_id_bytes = context_id_to_bytes(context_id);
        deps.crypto
            .restore_crypto_state(&ctx_id_bytes, &ctx_snapshot.mls_crypto_state)?;
    }

    let last_members: HashSet<scp_identity::DID> = ctx_snapshot
        .membership
        .members()
        .map(|m| m.did.clone())
        .collect();

    let now_for_validation = deps.clock.now_secs();
    let hrl_config = ctx_snapshot
        .hard_rate_limit_config
        .clone()
        .unwrap_or_else(scp_protocol::economy::antispam::HardRateLimitConfig::matrix_defaults);
    hrl_config.validate().map_err(|e| {
        ContextError::PersistenceFailed(format!(
            "restore: hard-rate-limit config validation failed: {e}"
        ))
    })?;
    let mut hrl_state = ctx_snapshot.hard_rate_limit_state.clone();
    scp_protocol::economy::antispam::TokenBucketLimiter::validate_and_sanitize_snapshot(
        &mut hrl_state,
        &hrl_config,
        now_for_validation,
        scp_protocol::economy::antispam::SNAPSHOT_CLOCK_SKEW_TOLERANCE_SECS,
    )
    .map_err(|e| {
        ContextError::PersistenceFailed(format!(
            "restore: hard-rate-limit snapshot validation failed: {e}"
        ))
    })?;
    let validated_velocity_tracker = match ctx_snapshot.velocity_tracker_state {
        Some(vts) => {
            let mut entries = vts.entries;
            scp_protocol::economy::antispam::SenderVelocityTracker::validate_and_sanitize_snapshot(
                &mut entries,
                60,
                now_for_validation,
                scp_protocol::economy::antispam::SNAPSHOT_CLOCK_SKEW_TOLERANCE_SECS,
            )
            .map_err(|e| {
                ContextError::PersistenceFailed(format!(
                    "restore: velocity snapshot validation failed: {e}"
                ))
            })?;
            scp_protocol::economy::antispam::SenderVelocityTracker::from_snapshot(60, entries)
        }
        None => scp_protocol::economy::antispam::SenderVelocityTracker::new(60),
    };
    let validated_message_pricing = ctx_snapshot
        .message_pricing
        .clone()
        .or_else(|| derive_message_pricing(ctx_snapshot.economic_policy.as_ref()));
    if let Some(ref pricing) = validated_message_pricing {
        pricing.validate().map_err(|e| {
            ContextError::PersistenceFailed(format!(
                "restore: message pricing config validation failed: {e}"
            ))
        })?;
    }

    // ADR-049 Phase 2A finalization keystone: restore path may rehydrate
    // either an encrypted or a broadcast context — branch on whether the
    // snapshot's broadcast state was reloadable (`broadcast_ctx` is
    // `Some(BroadcastContext)` for broadcast contexts, `None` for
    // encrypted). Members come from the membership snapshot.
    let context_id_bytes = state::context_id_to_bytes(context_id);
    let actor_members: HashSet<DID> = ctx_snapshot
        .membership
        .members()
        .map(|m| m.did.clone())
        .collect();
    let mode = if broadcast_ctx.is_some() {
        ContextModeState::Broadcast(Box::<crate::context::actor::state::BroadcastState>::default())
    } else {
        ContextModeState::Encrypted(Box::<ContextCryptoState>::default())
    };
    let per_context = PerContextState {
        context_id: context_id_bytes,
        created_at: deps.clock.now_secs(),
        generation: ctx_snapshot.generation, // SupervisorHandle stamps fresh if 0.
        handle: handle.clone(),
        membership: ctx_snapshot.membership,
        members: actor_members,
        governance: GovernanceState {
            engine: governance_engine,
            executed_proposals: {
                let now = deps.clock.now_secs();
                ctx_snapshot
                    .executed_proposals
                    .into_iter()
                    .map(|id| (id, now))
                    .collect()
            },
            next_proposal_seq: ctx_snapshot
                .next_proposal_seq
                .max(ctx_snapshot.approved_proposals.len() as u64),
            approved_proposals: ctx_snapshot.approved_proposals,
            freeze: ctx_snapshot.governance_freeze,
            timeout_task: GovernanceTimeoutTask::new(),
            deadlock: DeadlockDetectionState::default(),
            threshold_signers: ctx_snapshot.threshold_signers,
            threshold_value: ctx_snapshot.threshold_value,
            pending_ceiling_modification: ctx_snapshot.pending_ceiling_modification,
            pending_economic_policy_change: ctx_snapshot.pending_economic_policy_change,
            registered_tools: ctx_snapshot.registered_tools,
            tool_interfaces: ctx_snapshot.tool_interfaces,
            pruning_policy: ctx_snapshot.pruning_policy,
            message_pricing: validated_message_pricing,
            hard_rate_limit: scp_protocol::economy::antispam::TokenBucketLimiter::from_snapshot(
                hrl_config, hrl_state,
            ),
            economic_policy: ctx_snapshot.economic_policy,
            budget_tracker: ctx_snapshot.budget_tracker,
            last_known_members: last_members,
            pending_epoch_resets: Vec::new(),
            consequence_rules: ctx_snapshot.consequence_rules,
            velocity_tracker: validated_velocity_tracker,
            participation_cache: ctx_snapshot.participation_cache,
            cooldown_until: ctx_snapshot.cooldown_until,
            spending_nonce_tracker: scp_protocol::crypto::ucan::nonce::NonceTracker::from_snapshot(
                context_id.to_owned(),
                Arc::clone(&deps.clock),
                ctx_snapshot.spending_nonce_tracker_state,
            ),
            revoked_spending_ucan_cids: HashSet::new(),
            proposal_timestamps: ctx_snapshot.proposal_timestamps,
        },
        role_state: ctx_snapshot.role_state,
        receive_buffer: ReceiveBuffer::new(),
        broadcast_context: broadcast_ctx,
        migration_state: ctx_snapshot.migration_state,
        epoch: EpochState {
            mls_epoch: ctx_snapshot.mls_epoch,
            coordinator: EpochCoordinator::from_records(
                ctx_snapshot.epoch_coordination_records,
                context_id,
            ),
            grace_store,
            needs_reconnect,
        },
        access: AccessControlState {
            read_exclusion_list: ctx_snapshot.read_exclusion_list,
            access_key_store: ctx_snapshot.access_key_store,
        },
        ttl: TtlState {
            timer: crate::context::ttl::TtlTimer::with_clock(Arc::clone(&deps.clock)),
            extension: None,
        },
        sequence_tracker: scp_protocol::envelope::SequenceTracker::new(),
        reorder_buffer: scp_protocol::envelope::ReorderBuffer::default(),
        pending_commits: ctx_snapshot.pending_commits,
        commit_fault: ctx_snapshot.commit_fault,
        checkpoint_events_since: ctx_snapshot.checkpoint_events_since,
        checkpoint_last_time_secs: ctx_snapshot.checkpoint_last_time_secs,
        checkpoints: Vec::new(),
        merkle_tree: scp_event_log::EventLog::new(context_id.to_owned()),
        local_pseudonym: ctx_snapshot.local_pseudonym,
        pseudonym_registry: ctx_snapshot
            .pseudonym_registry
            .into_iter()
            .map(|(did_str, p)| (scp_identity::DID(did_str), p))
            .collect(),
        send_tracker: SendSequenceTracker::new(),
        // ADR-049 Phase 2A finalization keystone: restore path rehydrates
        // pending sagas / Welcome scratchpads as fresh — the legacy
        // snapshot format does not carry them, and restore is local
        // re-launch so cross-context sagas are restarted from scratch.
        recv_tracker: RecvSequenceTracker::new(),
        saga_pending: HashMap::new(),
        pending_broadcast_publishes: HashMap::new(),
        welcome_scratchpad: None,
        lifecycle_state: ContextLifecycleState::Open,
        event_log: None,
        mode,
    };

    deps.supervisor
        .insert_context(context_id.to_owned(), per_context)
        .map_err(|e| ContextError::MembershipFailed(e.to_string()))?;

    // ADR-049 Phase 2A finalization bootstrap dual-write: restore
    // path mirrors create — populate the actor registry alongside the
    // legacy contexts DashMap. The dashmap-backed actor proxies its
    // state through the same `Arc<Mutex<PerContextState>>` the
    // DashMap insert above produced.
    let owned_deps = deps.clone_for_spawn();
    deps.supervisor
        .spawn_actor_for_context(context_id.to_owned(), owned_deps)
        .await
        .map_err(|e| ContextError::MembershipFailed(e.to_string()))?;

    // Start governance timeout task (ADR-031 §5) via the actor mailbox.
    crate::context::governance_helpers::start_governance_timeout_task(&deps.supervisor, context_id)
        .await;

    // Re-spawn TTL timer if there was remaining TTL. Mailbox
    // StartTtlTimer to the freshly-spawned actor (registry + mailbox
    // tick — no DashMap reach).
    if let Some(remaining_secs) = ttl_remaining {
        let duration = std::time::Duration::from_secs(remaining_secs);
        deps.supervisor
            .dispatch_start_ttl_timer(context_id, handle.params().clone(), duration)
            .await;
    }

    Ok(())
}

// ===========================================================================
// Supervisor-iterating sweep entry points (Phase 2A finalization)
// ===========================================================================
//
// These are the non-legacy replacements for the `_legacy` lifecycle
// sweep helpers in `lifecycle_helpers_legacy.rs`. Each iterates
// [`Supervisor::actor_ids`](crate::context::supervisor::Supervisor::actor_ids)
// (the actor registry — NOT the legacy `Supervisor::contexts` DashMap)
// and dispatches one typed sweep command per actor via the per-actor
// mailbox.
//
// `restore_all_contexts` is the exception — it iterates PERSISTENCE
// (snapshots from the configured persistence provider) because no
// actors exist before restore. The body builds each context's
// payload from snapshot and calls `Supervisor::restore_context`,
// which routes the bootstrap variant through
// `dispatch_lifecycle_direct` (the only legitimate caller of the
// bootstrap-shape legacy helpers per ADR-049 §7 allowlist).
//
// Per-actor sweep bodies live in
// [`crate::context::actor::handlers::lifecycle`] as `handle_*_actor`
// functions, dispatched from the actor's `dispatch_actor_inner` arm
// for the matching `LifecycleCommand` variant.

/// Sweep entry point: restore every persisted context from the
/// configured persistence provider.
///
/// Returns the list of restored context IDs. Contexts in `Closing` /
/// `Closed` / `Expired` states are skipped (only `Active` contexts are
/// resurrected after a restart).
///
/// Relocates the legacy `restore_all_contexts_legacy` off direct
/// `Supervisor::contexts` `DashMap` insertion (the legacy body is now
/// deleted). The body
/// iterates persistence snapshots and dispatches one
/// `Supervisor::restore_context` call per snapshot — that ergonomic
/// method routes through the actor mailbox (after the bootstrap
/// `dispatch_lifecycle_direct` arm spawns the actor) so the resulting
/// actor registry is populated correctly.
///
/// # Errors
///
/// - [`ContextError::PersistenceFailed`] if the persistence provider
///   is unconfigured or `list_persisted_contexts` fails.
pub async fn restore_all_contexts(
    supervisor: &Arc<crate::context::supervisor::Supervisor>,
) -> Result<Vec<String>, ContextError> {
    let Some(persistence) = supervisor.persistence_ref() else {
        return Err(ContextError::PersistenceFailed(
            "no persistence provider configured".into(),
        ));
    };
    let context_ids = persistence.list_persisted_contexts().map_err(|e| {
        ContextError::PersistenceFailed(format!("failed to list persisted contexts: {e}"))
    })?;

    let mut restored = Vec::new();
    for ctx_id in &context_ids {
        let ctx_snapshot = match persistence.load_context(ctx_id) {
            Ok(Some(snap)) => snap,
            Ok(None) => continue,
            Err(e) => {
                tracing::warn!(
                    context_id = %ctx_id,
                    error = %e,
                    "failed to load context snapshot during restore"
                );
                continue;
            }
        };

        if ctx_snapshot.state != scp_protocol::context::ContextState::Active {
            continue;
        }

        let handle =
            crate::context::ContextHandle::new(ctx_id.clone(), ctx_snapshot.context_params.clone());

        match supervisor.restore_context(ctx_id, &handle).await {
            Ok(()) => restored.push(ctx_id.clone()),
            Err(e) => {
                tracing::warn!(
                    context_id = %ctx_id,
                    error = %e,
                    "failed to restore context"
                );
            }
        }
    }
    Ok(restored)
}

/// Sweep entry point: best-effort flush of every actor's snapshot to
/// the configured persistence provider.
///
/// Relocates the legacy `flush_all_contexts_legacy` off the
/// `Supervisor::contexts` `DashMap` (now deleted). Iterates the actor
/// registry and dispatches one
/// [`LifecycleCommand::FlushSnapshot`](crate::context::actor::commands::LifecycleCommand::FlushSnapshot)
/// per actor.
///
/// Best-effort: per-actor flush failures log via `tracing::warn!`
/// inside the handler. No-op if no persistence provider is configured.
pub async fn flush_all_contexts(supervisor: &crate::context::supervisor::Supervisor) {
    use crate::context::actor::commands::{ContextCommand, LifecycleCommand};

    if !crate::context::manager_methods::has_persistence(supervisor) {
        return;
    }

    let mut flushed = 0usize;
    for ctx_id in supervisor.actor_ids() {
        let Some(actor) = supervisor.lookup(&ctx_id) else {
            continue;
        };
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = ContextCommand::Lifecycle(LifecycleCommand::FlushSnapshot { reply: tx });
        if actor
            .send_with_timeout(cmd, crate::context::actor::SEND_TIMEOUT)
            .await
            .is_err()
        {
            continue;
        }
        if rx.await.is_ok() {
            flushed += 1;
        }
    }
    tracing::debug!(
        flushed,
        "flush_all_contexts: flushed {} context(s) via actor mailbox",
        flushed,
    );
}

/// Sync wrapper for [`flush_all_contexts`].
///
/// Required by `Drop` and other terminal sync callers that cannot
/// `.await`. Uses [`tokio::runtime::Handle::try_current`] +
/// [`tokio::task::block_in_place`] to bridge sync → async; **callers
/// MUST be inside a multi-thread tokio runtime** (per ADR-049 §7
/// allowlist for the FFI shutdown path). No-op if no persistence
/// provider is configured or if called outside a runtime.
pub fn flush_all_contexts_sync(supervisor: &crate::context::supervisor::Supervisor) {
    if !crate::context::manager_methods::has_persistence(supervisor) {
        return;
    }
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            tokio::task::block_in_place(|| {
                handle.block_on(flush_all_contexts(supervisor));
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

/// Sweep entry point: shut down every actor (best-effort, local
/// cleanup only).
///
/// Destroys per-context sender keys + MLS groups + event logs in that
/// order (zeroize secrets before tearing down structure) by dispatching
/// [`LifecycleCommand::ShutdownSelf`](crate::context::actor::commands::LifecycleCommand::ShutdownSelf)
/// to each actor; then removes each context from the legacy
/// `Supervisor::contexts` `DashMap` (kept in lock-step with the actor
/// registry by the bootstrap dual-write) and clears supervisor-level
/// state (standing contexts, local DIDs, wrapping keys, task set).
///
/// Relocates the legacy `shutdown_all_contexts_legacy` off the
/// `Supervisor::contexts` `DashMap` iteration (the legacy body is now
/// deleted). Used by
/// [`Supervisor::shutdown_all_contexts`](crate::context::supervisor::Supervisor::shutdown_all_contexts)
/// (and its sync wrapper) for process exit / test teardown. Does NOT
/// send leave messages or notify remote peers.
pub async fn shutdown_all_contexts(supervisor: &crate::context::supervisor::Supervisor) {
    use std::collections::{HashMap, HashSet};

    use crate::context::actor::commands::{ContextCommand, LifecycleCommand};

    let context_ids = supervisor.actor_ids();
    for ctx_id in &context_ids {
        let Some(actor) = supervisor.lookup(ctx_id) else {
            continue;
        };
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = ContextCommand::Lifecycle(LifecycleCommand::ShutdownSelf { reply: tx });
        if actor
            .send_with_timeout(cmd, crate::context::actor::SEND_TIMEOUT)
            .await
            .is_err()
        {
            continue;
        }
        let _ = rx.await;
        // Remove from the legacy contexts DashMap to keep it in
        // lock-step with the actor registry. The bootstrap dual-write
        // inserts in both; the shutdown sweep removes from both. The
        // DashMap dissolves entirely in a subsequent finalization
        // session.
        supervisor.contexts_ref().remove(ctx_id);
    }

    // Supervisor-level state clear. Acquired under the write_lock once
    // for the standing_contexts + local_dids stores so a concurrent
    // reader observes a coherent shutdown rather than a partially-
    // cleared registry.
    {
        let _guard = supervisor.write_lock.lock().await;
        supervisor
            .standing_contexts_ref()
            .store(std::sync::Arc::new(HashMap::new()));
        supervisor
            .local_dids_ref()
            .store(std::sync::Arc::new(HashSet::new()));
    }

    supervisor.clear_wrapping_keys();

    if let Some(task_set) = supervisor.task_set_ref() {
        let mut tasks = task_set.lock().await;
        tasks.abort_all();
    }

    tracing::info!(
        removed_count = context_ids.len(),
        "shutdown: removed all contexts via actor mailbox, cleared identity registries, \
         and aborted background tasks"
    );
}

/// Sync wrapper for [`shutdown_all_contexts`].
///
/// Required by destructor / atexit-style sync callers (the FFI bridge
/// instance's blocking-shutdown path) that cannot `.await`. Per
/// ADR-049 §7 allowlist for the FFI shutdown path — uses
/// [`tokio::runtime::Handle::try_current`] +
/// [`tokio::task::block_in_place`] to bridge sync → async; no-op
/// (with warning) when called outside a runtime.
pub fn shutdown_all_contexts_sync(supervisor: &crate::context::supervisor::Supervisor) {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            tokio::task::block_in_place(|| {
                handle.block_on(shutdown_all_contexts(supervisor));
            });
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "shutdown_all_contexts_sync called outside tokio runtime; \
                 skipping shutdown — per-actor resources will leak"
            );
        }
    }
}
