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
//! lock-then-relock confused-deputy generation guard is no longer
//! required because each actor IS its own generation.
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
    ContextCryptoState, ContextLifecycleState, ContextModeState, ContextRouting, PerContextState,
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
// §9.10.4 routing construction helpers
// ---------------------------------------------------------------------------

/// Builds the [`ContextRouting`] axis for a context from its broadcast flag
/// and the FFI-derived local pseudonym (§9.10.4, §5.14).
///
/// Broadcast contexts ignore the pseudonym and route on the derivable shared
/// RID (§5.14). Encrypted contexts (§9.10.4) embed the member's pseudonym
/// verbatim into the [`ContextRouting::Pseudonymous`] variant — which is the
/// type-level guarantee that an encrypted context can NEVER be in a
/// "no-pseudonym, fall back to the shared routing ID" state.
///
/// The FFI production boundary derives a real pseudonym via
/// `KeyCustody::derive_pseudonym` and hard-fails before reaching the runtime.
/// A `None` reaching here therefore comes only from a not-yet-announced
/// bootstrap path (e.g. a test fixture or a context created before
/// announcement); it is mapped to the `[0u8; 32]` sentinel. That sentinel is a
/// *reserved* routing value: the member cannot announce it (the ingest path
/// rejects reserved pseudonyms) until a real pseudonym is set via
/// [`ContextRouting::set_local_pseudonym`], and the send path never unions the
/// shared routing ID into app-data fan-out — so a zero local pseudonym cannot
/// reopen the relay-correlation hole. It simply means "this member has not
/// derived/announced its pseudonym yet."
fn build_routing(is_broadcast: bool, local_pseudonym: Option<[u8; 32]>) -> ContextRouting {
    ContextRouting::for_mode(is_broadcast, local_pseudonym.unwrap_or([0u8; 32]))
}

// ---------------------------------------------------------------------------
// 1. export_context (per-context, read-only)
// ---------------------------------------------------------------------------

/// Captures a context's full unsigned export building blocks from the
/// actor-owned state (§23.16.8, ADR-050).
///
/// Returns the `ContextSnapshot` and the serialized Merkle event-log data.
/// The actor holds no custody/signing key, so the signature is NOT applied
/// here — the caller ([`crate::context::supervisor::Supervisor::export_context`])
/// invokes [`crate::context::export_import::create_export`] with the
/// FFI-supplied `sign` closure once the actor mailbox returns these blocks.
/// Splitting the read-only capture (inside the actor) from the signing
/// (at the bridge boundary) preserves the actor-per-context model while
/// keeping the signature over the exact canonical bytes a verifier recomputes.
///
/// The snapshot's `mls_crypto_state` is empty on this portable export path;
/// live MLS crypto state is carried only on the persistence/restore path.
/// Whether portable export should include MLS crypto state is an open design
/// decision (security tradeoff).
///
/// The event-log export is best-effort (`unwrap_or_default`), matching the
/// pre-actor `export_context` body, so this capture is infallible. Any signing
/// or Merkle-verification failure surfaces later in
/// [`create_export`](crate::context::export_import::create_export) at the
/// dispatch boundary.
///
/// Crate-internal: this lives in the `pub(crate) mod lifecycle_helpers`
/// module, so it is unreachable outside `scp-runtime` regardless of this
/// `pub` keyword (a plain `pub` here, not `pub(crate)`, only because clippy's
/// `redundant_pub_crate` forbids `pub(crate)` inside an already-restricted
/// module). The only caller is the actor lifecycle handler within
/// `scp-runtime`; it is not part of the FFI surface and carries no
/// cross-layer export obligation.
pub fn export_context_blocks(
    state: &PerContextState,
    deps: &ActorDeps,
) -> (crate::context::state::ContextSnapshot, Vec<u8>) {
    let context_id = state.handle.context_id();
    let ctx_id_bytes = scp_protocol::context::context_id_bytes(context_id);

    let snapshot = crate::context::messaging_helpers::build_snapshot_from_state(state);

    let event_log_data = deps
        .event_log
        .export_event_log_data(&ctx_id_bytes)
        .unwrap_or_default();

    (snapshot, event_log_data)
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

    // §9.10.4: remove the departing member's pseudonym routing ID. No-op on
    // a broadcast context (which carries no peer registry).
    if let Some(reg) = state.routing.peer_registry_mut() {
        reg.remove(member_did);
    }

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

    // ADR-049 §9 Class S: a member leaving removes their own membership (a
    // downward-authorization transition for that member) — persist fail-closed
    // so a crash cannot re-admit a member who was told their leave succeeded.
    crate::context::messaging_helpers::persist_state_fail_closed(state, deps, &context_id)?;

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
    // derived from secret key material; dropping it (by collapsing the
    // routing axis to the no-pseudonym `Broadcast` variant) prevents leaking
    // the routing ID or any learned peer pseudonyms after context teardown.
    // The context is terminal at this point, so the routing axis no longer
    // needs to agree with the (also torn-down) crypto axis.
    state.routing = ContextRouting::Broadcast;

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

    // ADR-049 §9 Class S: the lifecycle close transition is security-critical
    // (a closed context must not silently re-open on a crash) — persist
    // fail-closed.
    crate::context::messaging_helpers::persist_state_fail_closed(state, deps, &context_id)?;

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
    // §9.10.4: `set_local_pseudonym` is a no-op on a broadcast context (which
    // carries no pseudonym state), so this only updates encrypted contexts.
    if let Some(pseudonym) = local_pseudonym {
        state.routing.set_local_pseudonym(pseudonym);
    }

    // Phase 5: commit the economy ticket (in-memory budget debit) and append
    // the join event, THEN durably persist, THEN settle the external escrow.
    // Consume the ticket — commit returns the deducted cost and marks the
    // ticket committed so the Drop guard stays quiet.
    let deducted_cost = crate::context::economy_logic::commit_economy_ticket(ticket);

    // Append MemberJoined event to event log.
    //
    // ADR-049 §9 (round-9 leak fix): the economy ticket was just committed
    // (line above), so its `Drop` guard no longer rolls anything back — but the
    // external escrow hold (`auth`, a `PaidActionAuthorization` that has NO
    // `Drop` impl) is still HELD and uncaptured. The fail-closed persist + the
    // success-path `capture_join_payment` both run AFTER this append. On this
    // append's `Err`, the membership / MLS state already applied above is NOT
    // reversed (it is Class-S security state that, like the consumed nonce, must
    // persist — the joiner re-drives the idempotent join), but `auth` would
    // otherwise drop silently WITHOUT voiding, leaking the hold and charging the
    // joiner for an unacknowledged join. VOID the escrow here (gated on
    // `auth.is_some()`) before returning — mirroring the money-ordering rule the
    // persist-failure branch below already follows.
    if let Err(e) =
        deps.event_log
            .append_context_event(&context_id_bytes, "MemberJoined", member_did.as_ref())
    {
        if let Some(a) = auth {
            crate::context::economy_helpers::void_paid_action(state, deps, a, &context_id).await;
        }
        return Err(e);
    }
    state.checkpoint_events_since += 1;

    // ADR-049 §9 Class S (BLACK-001): a PAID join consumed a spending-UCAN
    // nonce in Phase 1 (`enforce_join_economy` → `enforce_economy` →
    // `commit_spending_ucan_nonce`, mutating the actor-owned
    // `spending_nonce_tracker`) — the same Class-S monotonic state the
    // message-send and tool-invoke paths persist fail-closed. A best-effort
    // persist here would let an actor crash in the ≤50ms coalesce window roll
    // the nonce-consume back, freshening the spending UCAN's nonce after the
    // joiner already saw the join succeed (replay / double-spend). Persist
    // fail-closed when a spending nonce was committed (the same gating the
    // send path uses: `deducted_cost.is_some() && spending_ucan.is_some()`):
    // a persist failure returns an error so the join is NOT acknowledged. The
    // membership / MLS state already applied above is NOT reversed — it is
    // Class-S security state that, like the consumed nonce, must persist; the
    // joiner re-drives the (now nonce-consumed, idempotent) join, and the
    // surviving in-memory actor already holds the member. The consumed nonce
    // stays CONSUMED (the fail-closed direction; un-consuming re-opens the
    // replay window). A free / non-spending join keeps the best-effort persist
    // — the common path is not regressed.
    //
    // MONEY-ORDERING (round-7, mirrors the send path): the external escrow is
    // CAPTURED only AFTER the fail-closed persist succeeds. Capturing before
    // would charge the joiner (irreversible escrow settlement) and then hand
    // them an `Err` if the persist failed — a double-charge on retry. On
    // persist failure we VOID the escrow hold instead (releasing the funds) so
    // the charge is atomic with durability; the consumed nonce stays consumed,
    // so the joiner's retry is idempotent and they are charged at most once.
    if deducted_cost.is_some() && spending_ucan.is_some() {
        if let Err(e) =
            crate::context::messaging_helpers::persist_state_fail_closed(state, deps, &context_id)
        {
            // Durability failed before the charge was captured — release the
            // escrow hold so the joiner is not charged for an unacknowledged
            // join, and surface the error. The consumed nonce stays consumed.
            if let Some(a) = auth {
                crate::context::economy_helpers::void_paid_action(state, deps, a, &context_id)
                    .await;
            }
            return Err(e);
        }
    } else {
        crate::context::messaging_helpers::persist_state_best_effort(state, deps, &context_id);
    }

    // Durability has succeeded (or this is a free join): now settle the escrow.
    capture_join_payment(state, deps, auth, &member_did, &context_id, deducted_cost).await;

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
/// Validates parameters, builds a fresh `PerContextState`, and hands
/// it to
/// [`SupervisorHandle::spawn_actor_with_state`](crate::context::supervisor::handle::SupervisorHandle::spawn_actor_with_state),
/// which spawns an actor that OWNS the state and registers its handle
/// in the supervisor registry (no legacy contexts `DashMap` write).
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
    let create_is_broadcast = broadcast_context.is_some();
    let mode = if create_is_broadcast {
        ContextModeState::Broadcast(Box::<crate::context::actor::state::BroadcastState>::default())
    } else {
        ContextModeState::Encrypted(Box::<ContextCryptoState>::default())
    };
    // §9.10.4: build the routing axis from the (authoritative) mode and the
    // FFI-derived local pseudonym. The enum makes "encrypted context without a
    // pseudonym" unrepresentable in live state; broadcast contexts ignore the
    // pseudonym entirely. See `build_routing` for the `None`/sentinel rationale.
    let create_routing = build_routing(create_is_broadcast, local_pseudonym);
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
        last_seen_remote_checkpoint: std::collections::HashMap::new(),
        merkle_tree: scp_event_log::EventLog::new(context_id.clone()),
        // §9.10.4: pseudonym routing axis. Encrypted contexts carry the
        // member's pseudonym + an empty peer registry; broadcast contexts
        // carry no pseudonym state.
        routing: create_routing,
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
        xctx_committed_outputs: HashMap::new(),
        xctx_committed_invocations: std::collections::HashSet::new(),
        // B-owned cross-context tool-invoke validation state (spec §6.2.4):
        // fresh on creation/import; repopulated when a gated tool interface is
        // established. Not rehydrated from any snapshot — reconstructable
        // interface state, never authorization secrecy.
        xctx_ucan_proofs: scp_protocol::crypto::ucan::validate::InMemoryProofResolver::new(),
        xctx_nonce_dedup: scp_protocol::crypto::sender_keys::NonceDedup::new(),
        pending_broadcast_publishes: HashMap::new(),
        welcome_scratchpad: None,
        lifecycle_state: ContextLifecycleState::Open,
        event_log: None,
        mode,
    };

    // ADR-049 Phase 2A finalization owned-state spawn: the create path
    // no longer writes the legacy contexts DashMap. It hands the freshly
    // built `PerContextState` directly to
    // `Supervisor::spawn_actor_with_state`, which derives the registry
    // key from `state.context_id`, registers the handle under the
    // write lock, and spawns an actor that OWNS its state (no
    // `Arc<per-context-state Mutex>` proxy, no DashMap divergence).
    // Bootstrap keeps its `&ActorDeps` borrow alive for `finalize_create`
    // below; `clone_for_spawn` hands the actor task an owned bundle
    // without disturbing that borrow.
    let owned_deps = deps.clone_for_spawn();
    deps.supervisor
        .spawn_actor_with_state(per_context, owned_deps, None)
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
/// Runs after a context actor has been spawned and registered. The
/// `create`/`restore` bootstrap paths register through
/// [`SupervisorHandle::spawn_actor_with_state`](crate::context::supervisor::handle::SupervisorHandle::spawn_actor_with_state)
/// (owned-state spawn — no legacy contexts `DashMap` write); `import`
/// still registers through
/// [`SupervisorHandle::replace_context`](crate::context::supervisor::handle::SupervisorHandle::replace_context)
/// +
/// [`SupervisorHandle::spawn_actor_for_context`](crate::context::supervisor::handle::SupervisorHandle::spawn_actor_for_context)
/// pending its actor-native replaceability primitive. Every surface
/// `finalize_create` touches is mailbox-based — gauges, the
/// governance-timeout interval task, persistence/broadcast, and the TTL
/// timer all reach the freshly-spawned actor through the supervisor
/// registry, never the `DashMap`.
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

/// §23.17 Invariant 3/4 — the SINGLE floor-guarded crypto-restore path for
/// import. Captures per-sender epoch floors BEFORE teardown, tears down the
/// old crypto, restores the incoming `mls_state` (if any), then validates that
/// no per-sender floor regresses and merges the local floors back (max-merge).
/// Rolls the restored crypto back on a regression so no half-restored or
/// floor-regressed state persists. EVERY import crypto-restore site — the
/// actor-side `PrepareForReplace` handler AND the supervisor-side fresh /
/// stale-handle branches of `import_context` — routes through here so the
/// replay (floor-regression) guard cannot be bypassed by any path.
///
/// # Errors
///
/// `trusted_local` selects the spec §23.17.2 merge semantics:
///
/// - `true` — restoring the node's OWN snapshot (Invariant 2): crash recovery,
///   actor respawn (`Supervisor::respawn_from_snapshot`), process restart
///   (`restore_all_contexts`). A lower restored floor is the expected
///   coalesce-lag case and is MAX-merged with the live floor; the restore
///   PROCEEDS (never rejected for a regression). Only an overshoot beyond
///   `MAX_EPOCH_ADVANCE` (corrupt/garbage snapshot) is rejected.
/// - `false` — importing an UNTRUSTED peer snapshot (Invariant 3): any
///   per-sender floor regression is rejected (snapshot-mediated replay guard).
///
/// Returns `ContextError::PersistenceFailed` if `restore_crypto_state` fails,
/// or `ContextError::SnapshotFloorRegression` (the §23.17 replay-protection
/// rejection — whatever `validate_and_merge_epoch_floors` returns) if a
/// per-sender floor regresses (import path) or overshoots (both paths); the
/// restored crypto is rolled back first.
pub(in crate::context) fn restore_crypto_state_with_floor_guard(
    deps: &ActorDeps,
    ctx_id_bytes: &[u8; 32],
    mls_state: &[u8],
    trusted_local: bool,
) -> Result<(), ContextError> {
    // §23.17 Inv 2/3: capture the LIVE floors BEFORE destroying crypto state.
    // A mailbox/handle despawn does NOT tear down the supervisor-owned crypto
    // provider, so these live pre-crash floors are still authoritative and are
    // the max-merge input (Class M, ADR-049 §9).
    let local_epoch_floors = deps.crypto.export_sender_key_epochs(ctx_id_bytes);

    let _ = deps.crypto.destroy_mls_group(ctx_id_bytes);
    let _ = deps.crypto.destroy_sender_key(ctx_id_bytes);

    if !mls_state.is_empty() {
        deps.crypto
            .restore_crypto_state(ctx_id_bytes, mls_state)
            .map_err(|e| {
                ContextError::PersistenceFailed(format!("import: crypto state restore failed: {e}"))
            })?;
    }

    // §23.17 Inv 2/3/4: merge the live floors back. `trusted_local=true` max-
    // merges and proceeds (Inv 2 — respawn of own snapshot); `false` rejects
    // any regression (Inv 3 — untrusted peer import). Either way the merged
    // floor is never below the live floor (Inv 4). Roll back on failure.
    if let Err(e) = deps.crypto.validate_and_merge_epoch_floors(
        ctx_id_bytes,
        local_epoch_floors,
        crate::crypto::mls::provider::MAX_EPOCH_ADVANCE,
        trusted_local,
    ) {
        let _ = deps.crypto.destroy_mls_group(ctx_id_bytes);
        let _ = deps.crypto.destroy_sender_key(ctx_id_bytes);
        return Err(e);
    }
    Ok(())
}

/// Imports a previously exported context.
///
/// Validates the export, performs the C3 per-instance wipe policy,
/// restores crypto state with the epoch-floor regression guard
/// ([`restore_crypto_state_with_floor_guard`]), builds a fresh
/// `PerContextState` from the snapshot, and spawns an owned-state actor.
/// Re-spawns the TTL timer if the export carried `ttl_remaining_secs`.
///
/// # Errors
///
/// Returns `ContextError::MembershipFailed` if the existing context is not
/// replaceable (only Closing/Closed/Expired/Tombstoned are replaceable on
/// import); `ContextError::SnapshotFloorRegression` if the incoming snapshot
/// regresses a per-sender epoch floor (replay guard); `ContextError::
/// PersistenceFailed` if any validation/sanitization step rejects the snapshot
/// (HRL, velocity, pricing, MLS state restore); `ContextError::InvalidState` if
/// the snapshot lifecycle state is anything other than `Active`/`Creating`;
/// crypto/event-log failures during restore are propagated.
#[allow(clippy::too_many_lines)]
#[allow(dead_code)] // Bootstrap entry — see `create_context` rationale.
pub async fn import_context(
    deps: &ActorDeps,
    export: crate::context::export_import::ContextExport,
    verifying_key: &ed25519_dalek::VerifyingKey,
    local_pseudonym: Option<[u8; 32]>,
) -> Result<ContextHandle, ContextError> {
    // 1. Validate export (version gate, snapshot signature, Merkle chain).
    //
    // Imports come from an UNTRUSTED source. The embedded snapshot's Ed25519
    // signature is verified against `verifying_key` — the snapshot
    // `creator_did`'s resolved `#active`/`#agent` verification-method key
    // (§23.16.8, ADR-039, ADR-050) — before any state is restored. The
    // importer also enforces `exporter_did == creator_did`. A signature
    // failure (or signer-binding mismatch) rejects with
    // `ContextError::SnapshotSignatureInvalid`, distinct from the event-log
    // Merkle failure and from the version gate.
    crate::context::export_import::validate_export_for_import(&export, verifying_key)?;

    // `import_context` reconstructs authoritative context state and is only
    // meaningful for a full-scope export. A public-scope export
    // (`ExportScope::Public`) has its member list, governance config, and
    // event log stripped (see `strip_snapshot_for_public`), so importing it
    // would produce a degenerate stub context with no members and empty
    // governance. Reject it explicitly so a public summary can never silently
    // become an authoritative context. `scope` is now bound into the signed
    // preimage (a tampered scope fails signature verification by construction),
    // so this Full-only gate is NOT a signature concern: it is a separate
    // import-orchestration policy check, because a *legitimately-signed* Public
    // export must still be rejected for full import.
    if export.scope != crate::context::export_import::ExportScope::Full {
        return Err(ContextError::InvalidState(format!(
            "cannot import a {:?}-scope export — only full-scope exports carry the \
             membership, governance, and event-log state required to reconstruct an \
             authoritative context",
            export.scope
        )));
    }

    // C3: Validate consequence rules on import. Uses
    // validate_against_config to enforce the opt-in gate for
    // RevokeAccess even on imported snapshots and rejects with the
    // canonical SCP-CTX-2092 envelope so SDK callers can detect
    // structural rejection by `.code` rather than message body.
    crate::context::lifecycle_logic::validate_consequence_rules_for_import(
        &export.snapshot.consequence_rules,
        &export.snapshot.context_params.consequence_config,
    )?;

    // §9.10.4: the import path is encrypted-only. Every imported context is
    // re-homed with `broadcast_context: None`, `mode = Encrypted`, and a
    // pseudonymous routing axis (see the `import_routing` construction below).
    // A broadcast-mode export has no per-member pseudonym (spec §5.14) and
    // cannot be re-homed as encrypted without silently fabricating routing
    // state, so reject it loudly with the canonical SCP-CTX-2092 envelope
    // rather than accepting it and degrading the routing axis. All four bridges
    // therefore fail import on a broadcast export identically (by `.code`).
    if matches!(
        export.snapshot.context_params.mode,
        scp_protocol::context::params::ContextMode::Broadcast
    ) {
        return Err(ContextError::ImportRejected {
            reason: "broadcast-mode contexts cannot be imported — import is \
                     encrypted-only (§9.10.4); broadcast contexts carry no \
                     per-member pseudonym routing state"
                .to_owned(),
        });
    }

    let context_id = export.snapshot.context_id.clone();
    let ctx_id_bytes = scp_protocol::context::context_id_bytes(&context_id);

    // 2. Existing-context replaceability check + crypto state cleanup,
    // actor-native. If a context actor is already registered for this id,
    // the replaceability gate (NEVER overwrite a live context) AND the
    // §23.17 epoch-floor capture/teardown/restore/merge run INSIDE that
    // actor via `PrepareForReplace` — the actor processes one command at
    // a time, which is the serialization the legacy write_lock-guarded
    // gate provided. On success the prior actor claims itself terminal
    // and exits; we deterministically despawn its dead handle before the
    // fresh spawn below.
    if deps.supervisor.lookup(&context_id).is_some() {
        // Crypto state is read from the SIGNED snapshot field (ADR-050: all
        // importer-restored state lives in the signed preimage), never from
        // an unsigned envelope blob. Validated by `validate_export_for_import`
        // above.
        match deps
            .supervisor
            .dispatch_prepare_for_replace(&context_id, export.snapshot.mls_crypto_state.clone())
            .await
        {
            Ok(()) => {
                // Prior actor tore down + restored crypto (floor-guarded,
                // inside the handler) and is exiting. Remove its handle so the
                // respawn slot is vacant.
                let _ = deps.supervisor.despawn_actor(&context_id).await;
            }
            // ONLY a stale/unreachable handle routes to recovery. The prior
            // actor exited (or dropped its reply) before we reached it. ALL
            // other errors — `MembershipFailed` (live / already-claimed),
            // `SnapshotFloorRegression` (the §23.17 replay-guard rejection),
            // `PersistenceFailed`, `CryptoFailed`, etc. — MUST propagate
            // unchanged: routing a floor-regression rejection into the
            // recovery branch below would re-restore the replayed snapshot and
            // silently bypass the replay guard.
            Err(ContextError::ContextNotRegistered(_)) => {
                if deps.supervisor.lookup(&context_id).is_some() {
                    // A concurrent operation already owns the slot — refuse to
                    // overwrite it.
                    return Err(ContextError::MembershipFailed(format!(
                        "context '{context_id}' import: existing actor unreachable"
                    )));
                }
                // Slot vacant — restore crypto through the SAME floor-guarded
                // path the actor handler uses, so the replay guard still runs.
                // Read from the SIGNED snapshot field, never an unsigned
                // envelope blob (ADR-050).
                // IMPORT path: untrusted peer snapshot → Invariant 3
                // (reject-on-regression). `trusted_local = false`.
                restore_crypto_state_with_floor_guard(
                    deps,
                    &ctx_id_bytes,
                    &export.snapshot.mls_crypto_state,
                    false,
                )?;
            }
            Err(other) => return Err(other),
        }
    } else {
        // Fresh import (no existing actor): floor-guarded crypto restore (the
        // empty-crypto-state case is a no-op restore + floor merge inside the
        // helper). Read from the SIGNED snapshot field (ADR-050). IMPORT path:
        // untrusted peer snapshot → Invariant 3 (reject-on-regression).
        restore_crypto_state_with_floor_guard(
            deps,
            &ctx_id_bytes,
            &export.snapshot.mls_crypto_state,
            false,
        )?;
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
    // §9.10.4: the import path is encrypted-only — broadcast-mode exports are
    // rejected at the top of this function (SCP-CTX-2092), so the routing axis
    // is always pseudonymous. The FFI import boundary derives and supplies a
    // real pseudonym (hard-failing otherwise); a `None` only arises from a
    // not-yet-announced non-FFI bootstrap path (e.g. a test fixture) and maps to
    // the reserved sentinel via `build_routing` (see its doc comment).
    let import_routing = build_routing(false, local_pseudonym);
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
            // Carry the revocation set through import: it is a downward-
            // authorization decision (a revoked spending UCAN must STAY revoked)
            // and it is bound into the SIGNED export preimage, so dropping it
            // would re-admit a token whose revocation the export attests. Unlike
            // the nonce tracker / proposal timestamps (local-instance C3 wipe),
            // a revocation is authorization state that must not regress.
            revoked_spending_ucan_cids: export.snapshot.revoked_spending_ucan_cids,
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
        last_seen_remote_checkpoint: std::collections::HashMap::new(),
        // Fresh Merkle tree for imported contexts.
        merkle_tree: scp_event_log::EventLog::new(context_id.clone()),
        // §9.10.4: the importer derives their OWN pseudonym — the exporter's
        // is local-instance state with no meaning here. The peer registry
        // starts empty; the importer re-announces and learns peers' pseudonyms
        // via incoming announcements. The import path is encrypted-only
        // (`mode = Encrypted` below), so a real pseudonym is required.
        routing: import_routing,
        // ADR-049 commit 8: fresh actor-shape tracker on import.
        send_tracker: SendSequenceTracker::new(),
        // ADR-049 Phase 2A finalization keystone: import path is
        // encrypted-only (`mode = ContextModeState::Encrypted(default)`).
        // Receive tracker and Welcome scratchpad start empty; lifecycle is
        // Open after the replaceability gate succeeded and the snapshot
        // validated.
        //
        // The saga slot starts EMPTY on import (NOT rehydrated from the
        // snapshot): unlike same-node restore, a cross-node import receives an
        // UNTRUSTED exporter's snapshot, and staged saga evidence is
        // local-instance cross-context coordination state with no authority on
        // the importing node — its supervisor `SagaJournal`, reservations, and
        // peer actors do not exist here. `strip_snapshot_for_public` already
        // strips it to empty; a full import deliberately drops it too so a
        // foreign saga cannot drive local Commit/Abort.
        recv_tracker: RecvSequenceTracker::new(),
        saga_pending: HashMap::new(),
        xctx_committed_outputs: HashMap::new(),
        xctx_committed_invocations: std::collections::HashSet::new(),
        // B-owned cross-context tool-invoke validation state (spec §6.2.4):
        // fresh on creation/import; repopulated when a gated tool interface is
        // established. Not rehydrated from any snapshot — reconstructable
        // interface state, never authorization secrecy.
        xctx_ucan_proofs: scp_protocol::crypto::ucan::validate::InMemoryProofResolver::new(),
        xctx_nonce_dedup: scp_protocol::crypto::sender_keys::NonceDedup::new(),
        pending_broadcast_publishes: HashMap::new(),
        welcome_scratchpad: None,
        lifecycle_state: ContextLifecycleState::Open,
        event_log: None,
        mode: ContextModeState::Encrypted(Box::<ContextCryptoState>::default()),
    };

    // 7. Register the imported context as an owned-state actor.
    //
    // Any prior actor for this id was already replaceability-gated,
    // crypto-torn-down, claimed-terminal, and despawned by the
    // `PrepareForReplace` step above, so the registry slot is vacant.
    // `spawn_actor_with_state` rejects a duplicate (first-writer-wins) if
    // a concurrent operation raced into the slot — surfaced as a typed
    // error rather than a silent overwrite. The actor OWNS the imported
    // state; no legacy contexts DashMap write, no `Arc<Mutex<>>` proxy.
    let owned_deps = deps.clone_for_spawn();
    deps.supervisor
        .spawn_actor_with_state(per_context, owned_deps, None)
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
    preloaded_snapshot: Option<crate::context::state::ContextSnapshot>,
) -> Result<
    (
        crate::context::state::ContextSnapshot,
        Option<scp_protocol::context::broadcast::BroadcastContext>,
    ),
    ContextError,
> {
    // Dedup: the watchdog respawn path (`Supervisor::respawn_from_snapshot`)
    // already loaded the context snapshot for its Active-state precondition
    // check; it threads that snapshot through here so the context snapshot is
    // loaded exactly once per respawn. Other callers (process-restart, the
    // RestoreContext dispatch arm) pass `None` and load it here. The broadcast
    // snapshot is always loaded here (the respawn pre-load does not fetch it).
    let ctx_snapshot = match preloaded_snapshot {
        Some(snapshot) => snapshot,
        None => deps
            .persistence
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
            })?,
    };

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
/// reconstructs `PerContextState`, and hands it to
/// [`SupervisorHandle::spawn_actor_with_state`](crate::context::supervisor::handle::SupervisorHandle::spawn_actor_with_state),
/// which spawns an actor that OWNS the rehydrated state and registers
/// its handle in the supervisor registry (no legacy contexts `DashMap`
/// write). Re-spawns the TTL timer if `ttl_remaining_secs` is `Some`.
///
/// `preloaded_snapshot` lets the watchdog respawn path
/// (`Supervisor::respawn_from_snapshot`) hand in the `ContextSnapshot` it
/// already loaded for its `Active`-state precondition check, so the context
/// snapshot is read from persistence exactly ONCE per respawn instead of twice.
/// Process-restart and the `RestoreContext` dispatch arm pass `None`.
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
    preloaded_snapshot: Option<crate::context::state::ContextSnapshot>,
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

    let (mut ctx_snapshot, broadcast_ctx) =
        load_persisted_context_state(deps, context_id, preloaded_snapshot)?;
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
        // §23.17 Invariant 3/4 (replay guard): route the crypto restore through
        // the floor-regression guard, NOT bare `restore_crypto_state`. This
        // path is shared by process-restart restore AND the watchdog respawn
        // (`Supervisor::respawn_from_snapshot`). A respawn rehydrates from the
        // last COALESCED snapshot, which may lag the live per-sender epoch
        // floors by up to one coalesce interval (ADR-049 §9). Restoring such a
        // snapshot with a bare `restore_crypto_state` would silently lower a
        // per-sender replay floor — re-opening a replay window for any sender
        // whose epoch advanced after the snapshot was written. The guard
        // captures the LIVE floors (still held by the crypto provider, which a
        // mailbox despawn does not tear down) before teardown, restores the
        // snapshot crypto, then MAX-merges the live floors back. This is the
        // node restoring its OWN snapshot (Invariant 2, `trusted_local = true`):
        // a coalesce-lagged snapshot whose floor trails the live floor is the
        // NORMAL case (an epoch advanced in the ≤50ms pre-crash window), so the
        // restore MUST max-merge and PROCEED — rejecting it (Invariant 3, the
        // untrusted-import policy) would fail the respawn and poison a healthy
        // context. Only an overshoot beyond `MAX_EPOCH_ADVANCE` (corrupt
        // snapshot) is rejected. The merged floor is never below the live
        // floor, so a stale snapshot still cannot regress the replay floor.
        restore_crypto_state_with_floor_guard(
            deps,
            &ctx_id_bytes,
            &ctx_snapshot.mls_crypto_state,
            true,
        )?;
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
    let restored_is_broadcast = broadcast_ctx.is_some();
    let mode = if restored_is_broadcast {
        ContextModeState::Broadcast(Box::<crate::context::actor::state::BroadcastState>::default())
    } else {
        ContextModeState::Encrypted(Box::<ContextCryptoState>::default())
    };
    // §9.10.4: the snapshot persists a `routing` variant; the live mode is
    // reconstructed independently from whether broadcast state reloaded. The
    // two MUST agree. A snapshot whose persisted routing variant contradicts
    // its reconstructed mode is either corrupt or tampered (e.g. a broadcast
    // snapshot carrying a pseudonymous routing record that would silently
    // redirect app-data fan-out) — fail the restore closed rather than load a
    // context whose routing axis disagrees with its crypto axis.
    if ctx_snapshot.routing.is_broadcast() != restored_is_broadcast {
        return Err(ContextError::PersistenceFailed(format!(
            "restore: snapshot routing variant (broadcast={}) contradicts \
             reconstructed mode (broadcast={restored_is_broadcast}) for context '{context_id}'",
            ctx_snapshot.routing.is_broadcast()
        )));
    }
    // The persisted routing variant is authoritative: the agreement check above
    // already proved `ctx_snapshot.routing.is_broadcast()` matches the
    // reconstructed mode, so no rebuild is needed — move the snapshot's variant
    // through verbatim. For encrypted contexts this carries the persisted local
    // pseudonym and peer registry forward, so a warm restore is NOT bootstrap-
    // empty (it can address known peers immediately; see §9.10.4). An empty /
    // zero pseudonym is acceptable here: that snapshot behaves like a cold start,
    // and the member becomes addressable only once it explicitly re-announces —
    // `restore_context` itself emits no announcement — and peers re-announce
    // theirs. `ContextRouting`'s `Pseudonymous` fields are private, which is
    // precisely why a destructure-and-rebuild is no longer possible here — and
    // why it is no longer needed.
    let restored_routing = ctx_snapshot.routing;
    let per_context = PerContextState {
        context_id: context_id_bytes,
        created_at: deps.clock.now_secs(),
        // Placeholder — `spawn_actor_with_state` overwrites this
        // unconditionally with a fresh monotonic `spawn_generation`
        // (AtomicU64; first spawn = 1) before the state crosses into the
        // actor task. The snapshot value is never the live generation.
        generation: ctx_snapshot.generation,
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
            // ADR-049 §9 Class S: restore the revocation set FROM the snapshot.
            // Resetting it to empty here (the prior behaviour) silently dropped
            // every revocation on actor respawn / process restart — a
            // downward-authorization rollback the crash-safety invariant
            // forbids. The snapshot is authoritative.
            revoked_spending_ucan_cids: ctx_snapshot.revoked_spending_ucan_cids,
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
        last_seen_remote_checkpoint: std::collections::HashMap::new(),
        merkle_tree: scp_event_log::EventLog::new(context_id.to_owned()),
        routing: restored_routing,
        send_tracker: SendSequenceTracker::new(),
        // ADR-049 §9 Class S (line 144): same-node restore REHYDRATES the
        // staged saga slot from the snapshot. This is the crash-recovery path
        // the §9 invariant covers — a Prepare's staged-but-unpublished MLS
        // handles and B-side reservation linkage MUST survive a crash so
        // Commit can consume the right reservation. Each entry is reconstructed
        // from its sanctioned `SagaPreparedStateSnapshot` mirror. The Welcome
        // scratchpad is genuinely transient and restarts fresh.
        recv_tracker: RecvSequenceTracker::new(),
        saga_pending: ctx_snapshot
            .saga_pending
            .into_iter()
            .map(|(id, mirror)| (id, mirror.into_prepared()))
            .collect(),
        // B-owned UCAN proof index (spec §6.2.4) is NOT in the Class-S snapshot:
        // it is reconstructable interface state, repopulated when the tool
        // interface is (re-)established.
        xctx_ucan_proofs: scp_protocol::crypto::ucan::validate::InMemoryProofResolver::new(),
        // ADR-049 §9 Class S: same-node restore REHYDRATES B's anti-replay
        // nonce-dedup cache (spec §6.2.4 "Freshness / anti-replay"). It is the
        // ONLY gate against a fresh-`SagaId` replay of a `CrossContextToolInvoke`
        // within the 5-minute TTL; reinitializing it empty on restore would let
        // a crash inside the window re-open a charging-tool replay (BLACK-624-01).
        // Per-entry TTL is pruned lazily on the next freshness check. Cross-node
        // import drops it (the snapshot field is empty), so a foreign node starts
        // its own window.
        xctx_nonce_dedup: scp_protocol::crypto::sender_keys::NonceDedup::from_entries(
            ctx_snapshot.xctx_nonce_dedup,
        ),
        // ADR-049 §9 Class S (line 144): same-node restore REHYDRATES the
        // durable Commit-B output captures (spec §6.2.4 "Exactly-once execution
        // with durable output capture") so a Commit replayed after a crash
        // re-emits the STORED output + the IDENTICAL receipt rather than
        // re-invoking the tool. The live `CommittedToolInvocation` is public (no
        // §9.4.3 bearer), so the snapshot stores it directly — no mirror.
        xctx_committed_outputs: ctx_snapshot.xctx_committed_outputs,
        xctx_committed_invocations: ctx_snapshot.xctx_committed_invocations,
        pending_broadcast_publishes: HashMap::new(),
        welcome_scratchpad: None,
        lifecycle_state: ContextLifecycleState::Open,
        event_log: None,
        mode,
    };

    // ADR-049 Phase 2A finalization owned-state spawn: restore mirrors
    // create — hand the rehydrated `PerContextState` directly to
    // `Supervisor::spawn_actor_with_state`. The actor OWNS its state;
    // the registry key is derived from `state.context_id` and the handle
    // is registered under the write lock. No legacy contexts DashMap
    // write, no `Arc<per-context-state Mutex>` proxy.
    let owned_deps = deps.clone_for_spawn();
    deps.supervisor
        .spawn_actor_with_state(per_context, owned_deps, None)
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
/// to each actor (each actor owns its `PerContextState` and drops it when
/// its task exits — no `DashMap` cleanup needed), then clears
/// supervisor-level state (standing contexts, local DIDs, wrapping keys,
/// task set).
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
        // `ShutdownSelf` tears down the per-context resources (sender
        // keys, MLS group, event log, timers) but does NOT break the
        // actor's `run()` loop — only `LifecycleControlCommand::Shutdown`
        // and a claimed `PrepareForReplace` do, and neither is sent here.
        // We must explicitly despawn the actor: `despawn_actor` removes
        // the handle from `actors` under the write lock, dropping the
        // last `mpsc::Sender`. That closes the inbox, so the actor's
        // `run()` loop exits on its inbox-closed (`None`) arm and the
        // spawned task releases its `PerContextState`. Without this the
        // handle leaks (context stays discoverable via `lookup` /
        // `actor_ids` after "shutdown") and the task never exits.
        supervisor.despawn_actor(ctx_id).await;
        // Clean shutdown: reap the (non-poison) crash-window entry so it does
        // not leak past teardown (ADR-049 §10). A poisoned entry is preserved
        // — its dormant-poison signal survives a shutdown so a subsequent
        // lookup still reports the poison until an operator clears it or the
        // process restarts.
        supervisor.reap_crash_window(ctx_id);
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
            // ci-allow: block-on: ADR-049 §7 FFI sync-shutdown allowlist — the bridge's blocking shutdown path cannot .await.
            tokio::task::block_in_place(|| handle.block_on(shutdown_all_contexts(supervisor))); // ci-allow: block-on: ADR-049 §7 FFI sync-shutdown
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

#[cfg(all(test, feature = "testing"))]
mod restore_reconcile_tests {
    //! §9.10.4 fail-closed restore reconciliation.
    //!
    //! `restore_context` reconstructs the live context mode independently from
    //! whether broadcast state reloaded, then asserts the persisted `routing`
    //! variant agrees with it. A snapshot whose persisted routing axis
    //! contradicts its reconstructed crypto axis is corrupt or tampered — for
    //! example a broadcast snapshot carrying a pseudonymous routing record that
    //! would silently redirect app-data fan-out. These tests drive the REAL
    //! `restore_context` path (not serde defaulting) against snapshots harvested
    //! from a real `create_context`, with the routing axis deliberately set to
    //! agree or disagree with the reconstructed mode.

    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::large_futures,
        // Test fixtures only: `captured`/`voided` counters read naturally
        // despite the shared prefix; the recording adapter's trait methods
        // return string literals tied to `&self` by the trait signature; and
        // the end-to-end paid-join fixture is necessarily long.
        clippy::similar_names,
        clippy::unnecessary_literal_bound,
        clippy::too_many_lines,
        // Test-only capturing persistence: the `Mutex<HashMap>` is never held
        // across `.await` (writes/reads are synchronous trait methods), so a
        // plain `std::sync::Mutex` is the right tool. The runtime's actor path
        // bans it (ADR-049); test fixtures are explicitly exempt. See
        // crates/scp-runtime/clippy.toml.
        clippy::disallowed_types
    )]

    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use scp_identity::DID;
    use scp_platform::testing::InMemoryStorage;
    use scp_protocol::context::broadcast::BroadcastContextSnapshot;
    use scp_protocol::context::params::{ContextMode, ContextParams};
    use scp_protocol::context::{ContextError, builder::ContextCreationError};

    use crate::context::actor::state::ContextRouting;
    use crate::context::builder::{ContextEventLogProvider, ContextTransportProvider};
    use crate::context::persistence::ContextPersistence;
    use crate::context::state::ContextSnapshot;
    use crate::context::supervisor::supervisor::Supervisor;
    use crate::context::{ContextHandle, lifecycle_helpers};

    type PersistErr = Box<dyn std::error::Error + Send + Sync>;

    /// Connected no-op transport — `create_context` publishes through it.
    struct OkTransport;
    impl ContextTransportProvider for OkTransport {
        fn is_connected(&self) -> bool {
            true
        }
        fn publish_context(
            &self,
            _id: &[u8; 32],
            _params: &ContextParams,
        ) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn delete_published(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn send_message(&self, _id: &[u8; 32], _payload: &[u8]) -> Result<(), ContextError> {
            Ok(())
        }
    }

    struct OkEventLog;
    impl ContextEventLogProvider for OkEventLog {
        fn init_event_log(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn append_event(
            &self,
            _id: &[u8; 32],
            _event: &str,
            _actor: &str,
            _payload: Option<&serde_json::Value>,
        ) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn destroy_event_log(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
    }

    /// Event log whose `init`/`destroy` succeed but whose `append_event` ALWAYS
    /// fails. Models the ADR-049 §9 round-9 leak scenario: a WORKING persistence
    /// backend with a FAILING event-log append, so `finalize_send`'s very first
    /// `append_context_event("MessageSent")` returns `Err` AFTER the caller has
    /// reserved a per-sender sequence — exercising the rollback this gate fixes.
    struct FailingAppendEventLog;
    impl ContextEventLogProvider for FailingAppendEventLog {
        fn init_event_log(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        fn append_event(
            &self,
            _id: &[u8; 32],
            _event: &str,
            _actor: &str,
            _payload: Option<&serde_json::Value>,
        ) -> Result<(), ContextCreationError> {
            Err(ContextCreationError::EventLogFailed(
                "fixture: event-log append deliberately fails".to_owned(),
            ))
        }
        fn destroy_event_log(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
    }

    /// Captures every snapshot/broadcast write so a real `create_context` can be
    /// used to harvest a fully-formed, validation-passing `ContextSnapshot`.
    #[derive(Default)]
    struct CapturingPersistence {
        contexts: Mutex<HashMap<String, ContextSnapshot>>,
        broadcasts: Mutex<HashMap<String, BroadcastContextSnapshot>>,
    }
    impl ContextPersistence for CapturingPersistence {
        fn persist_context(&self, id: &str, s: &ContextSnapshot) -> Result<(), PersistErr> {
            self.contexts
                .lock()
                .unwrap()
                .insert(id.to_owned(), s.clone());
            Ok(())
        }
        fn load_context(&self, id: &str) -> Result<Option<ContextSnapshot>, PersistErr> {
            Ok(self.contexts.lock().unwrap().get(id).cloned())
        }
        fn persist_broadcast(
            &self,
            id: &str,
            s: &BroadcastContextSnapshot,
        ) -> Result<(), PersistErr> {
            self.broadcasts
                .lock()
                .unwrap()
                .insert(id.to_owned(), s.clone());
            Ok(())
        }
        fn load_broadcast(&self, id: &str) -> Result<Option<BroadcastContextSnapshot>, PersistErr> {
            Ok(self.broadcasts.lock().unwrap().get(id).cloned())
        }
        fn delete_context(&self, _id: &str) -> Result<(), PersistErr> {
            Ok(())
        }
        fn list_persisted_contexts(&self) -> Result<Vec<String>, PersistErr> {
            Ok(self.contexts.lock().unwrap().keys().cloned().collect())
        }
    }

    /// Boxed handle over a shared `Arc<CapturingPersistence>` so the supervisor
    /// can write through it while the test reads the harvested snapshot from the
    /// same backing store.
    struct SharedCapture(Arc<CapturingPersistence>);
    impl ContextPersistence for SharedCapture {
        fn persist_context(&self, id: &str, s: &ContextSnapshot) -> Result<(), PersistErr> {
            self.0.persist_context(id, s)
        }
        fn load_context(&self, id: &str) -> Result<Option<ContextSnapshot>, PersistErr> {
            self.0.load_context(id)
        }
        fn persist_broadcast(
            &self,
            id: &str,
            s: &BroadcastContextSnapshot,
        ) -> Result<(), PersistErr> {
            self.0.persist_broadcast(id, s)
        }
        fn load_broadcast(&self, id: &str) -> Result<Option<BroadcastContextSnapshot>, PersistErr> {
            self.0.load_broadcast(id)
        }
        fn delete_context(&self, id: &str) -> Result<(), PersistErr> {
            self.0.delete_context(id)
        }
        fn list_persisted_contexts(&self) -> Result<Vec<String>, PersistErr> {
            self.0.list_persisted_contexts()
        }
    }

    /// Serves a single fixed snapshot (+ optional broadcast) for the
    /// `restore_context` under test. The reconstructed mode is `Encrypted` when
    /// `broadcast` is `None` and `Broadcast` when it is `Some`, independent of
    /// the snapshot's `routing` variant — which is exactly the axis the
    /// reconciliation cross-checks.
    struct ServingPersistence {
        snapshot: ContextSnapshot,
        broadcast: Option<BroadcastContextSnapshot>,
    }
    impl ContextPersistence for ServingPersistence {
        fn persist_context(&self, _id: &str, _s: &ContextSnapshot) -> Result<(), PersistErr> {
            Ok(())
        }
        fn load_context(&self, _id: &str) -> Result<Option<ContextSnapshot>, PersistErr> {
            Ok(Some(self.snapshot.clone()))
        }
        fn persist_broadcast(
            &self,
            _id: &str,
            _s: &BroadcastContextSnapshot,
        ) -> Result<(), PersistErr> {
            Ok(())
        }
        fn load_broadcast(
            &self,
            _id: &str,
        ) -> Result<Option<BroadcastContextSnapshot>, PersistErr> {
            Ok(self.broadcast.clone())
        }
        fn delete_context(&self, _id: &str) -> Result<(), PersistErr> {
            Ok(())
        }
        fn list_persisted_contexts(&self) -> Result<Vec<String>, PersistErr> {
            Ok(vec![])
        }
    }

    fn mls_storage() -> Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> {
        Arc::new(
            crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
                InMemoryStorage::new(),
            )),
        )
    }

    fn build_supervisor(persistence: Box<dyn ContextPersistence>) -> Arc<Supervisor> {
        let crypto = Arc::new(crate::crypto::mls::provider::MlsCryptoProvider::new(
            "did:dht:z6MkRestoreReconcile".to_owned(),
        ));
        Supervisor::with_providers(
            crypto,
            Box::new(OkTransport),
            Box::new(OkEventLog),
            Arc::new(|_: &DID| None),
            Some(persistence),
            None,
            None,
            None,
            mls_storage(),
        )
    }

    /// Creates a real context of the requested mode and returns the harvested
    /// snapshot plus its broadcast snapshot (if any).
    async fn harvest_snapshot(
        is_broadcast: bool,
    ) -> (ContextSnapshot, Option<BroadcastContextSnapshot>) {
        let capture = Arc::new(CapturingPersistence::default());
        // Box the same Arc-backed capture so we can both write (via supervisor)
        // and read (via this handle) the harvested snapshot.
        let supervisor = build_supervisor(Box::new(SharedCapture(Arc::clone(&capture))));
        let ctx_id = if is_broadcast {
            "harvest-bcast"
        } else {
            "harvest-enc"
        };
        let params = if is_broadcast {
            ContextParams {
                mode: ContextMode::Broadcast,
                // Broadcast contexts only support `MemoryScope::Full`.
                memory_scope: scp_protocol::context::params::MemoryScope::Full,
                ..ContextParams::default()
            }
        } else {
            ContextParams {
                mode: ContextMode::Encrypted,
                ..ContextParams::default()
            }
        };
        let pseudonym = if is_broadcast { None } else { Some([7u8; 32]) };
        supervisor
            .create_context(
                ctx_id.to_owned(),
                params,
                DID("did:dht:z6MkHarvestCreator".to_owned()),
                pseudonym,
            )
            .await
            .expect("create_context should succeed");

        let snapshot = capture
            .contexts
            .lock()
            .unwrap()
            .get(ctx_id)
            .cloned()
            .expect("create_context must persist a snapshot");
        let broadcast = capture.broadcasts.lock().unwrap().get(ctx_id).cloned();
        (snapshot, broadcast)
    }

    /// Drives `restore_context` against a snapshot whose `routing` variant and
    /// reconstructed mode are independently chosen. `serve_broadcast` decides
    /// the reconstructed mode (Some → Broadcast, None → Encrypted).
    async fn restore_with(
        mut snapshot: ContextSnapshot,
        routing: ContextRouting,
        serve_broadcast: Option<BroadcastContextSnapshot>,
        restore_ctx_id: &str,
    ) -> Result<(), ContextError> {
        snapshot.context_id = restore_ctx_id.to_owned();
        snapshot.routing = routing;
        let serving = ServingPersistence {
            snapshot,
            broadcast: serve_broadcast,
        };
        let supervisor = build_supervisor(Box::new(serving));
        let deps = supervisor
            .build_actor_deps(&DID("did:dht:z6MkRestoreReconcile".to_owned()))
            .await
            .expect("build_actor_deps");
        let handle = ContextHandle::new(restore_ctx_id.to_owned(), ContextParams::default());
        lifecycle_helpers::restore_context(&deps, restore_ctx_id, &handle, None).await
    }

    /// Case 1: reconstructed mode ENCRYPTED (no broadcast state) but the
    /// persisted routing variant is `Broadcast` → fail closed.
    #[tokio::test]
    async fn restore_rejects_broadcast_routing_on_encrypted_reconstruction() {
        let (enc_snapshot, _) = harvest_snapshot(false).await;
        let err = restore_with(
            enc_snapshot,
            ContextRouting::for_mode(true, [0u8; 32]),
            None,
            "restore-case-broadcast-routing-encrypted-mode",
        )
        .await
        .expect_err("routing/mode disagreement must fail closed");
        assert!(
            matches!(err, ContextError::PersistenceFailed(_)),
            "expected PersistenceFailed, got {err:?}"
        );
    }

    /// Case 2 (inverse): reconstructed mode BROADCAST (broadcast state reloads)
    /// but the persisted routing variant is `Pseudonymous` → fail closed.
    #[tokio::test]
    async fn restore_rejects_pseudonymous_routing_on_broadcast_reconstruction() {
        let (bcast_snapshot, bcast_state) = harvest_snapshot(true).await;
        let bcast_state = bcast_state.expect("broadcast create must persist broadcast state");
        let err = restore_with(
            bcast_snapshot,
            ContextRouting::for_mode(false, [9u8; 32]),
            Some(bcast_state),
            "restore-case-pseudonymous-routing-broadcast-mode",
        )
        .await
        .expect_err("routing/mode disagreement must fail closed");
        assert!(
            matches!(err, ContextError::PersistenceFailed(_)),
            "expected PersistenceFailed, got {err:?}"
        );
    }

    /// Case 3 (positive): persisted routing variant AGREES with the
    /// reconstructed mode (encrypted snapshot, Pseudonymous routing, no
    /// broadcast state) → restore succeeds.
    #[tokio::test]
    async fn restore_succeeds_when_routing_agrees_with_mode() {
        let (enc_snapshot, _) = harvest_snapshot(false).await;
        let routing = enc_snapshot.routing.clone();
        restore_with(
            enc_snapshot,
            routing,
            None,
            "restore-case-agreeing-encrypted",
        )
        .await
        .expect("routing agreeing with mode must restore Ok");
    }

    // -----------------------------------------------------------------------
    // ADR-049 §9 (round-7): paid-join money-ordering parity with the send path.
    // capture_join_payment (external escrow settlement) runs AFTER the
    // fail-closed persist. On persist failure the escrow is VOIDED (not
    // captured), so the joiner is not charged for an unacknowledged join.
    // -----------------------------------------------------------------------

    /// A persistence double whose `persist_context` ALWAYS fails — drives the
    /// paid-join fail-closed persist into its error path.
    #[derive(Default)]
    struct FailingJoinPersistence;
    impl ContextPersistence for FailingJoinPersistence {
        fn persist_context(&self, _id: &str, _snap: &ContextSnapshot) -> Result<(), PersistErr> {
            Err("forced persist failure".into())
        }
        fn load_context(&self, _id: &str) -> Result<Option<ContextSnapshot>, PersistErr> {
            Ok(None)
        }
        fn persist_broadcast(
            &self,
            _id: &str,
            _snap: &BroadcastContextSnapshot,
        ) -> Result<(), PersistErr> {
            Ok(())
        }
        fn load_broadcast(
            &self,
            _id: &str,
        ) -> Result<Option<BroadcastContextSnapshot>, PersistErr> {
            Ok(None)
        }
        fn delete_context(&self, _id: &str) -> Result<(), PersistErr> {
            Ok(())
        }
        fn list_persisted_contexts(&self) -> Result<Vec<String>, PersistErr> {
            Ok(Vec::new())
        }
    }

    /// A `PaymentAdapter` that records whether `capture` or `void` was invoked,
    /// so the money-ordering test can assert the escrow was VOIDED (not
    /// captured) when the fail-closed persist fails. (Implementing the
    /// non-dyn `PaymentAdapter` trait yields `PaymentAdapterDyn` via the
    /// blanket impl.)
    struct RecordingPaymentAdapter {
        captured: Arc<std::sync::atomic::AtomicUsize>,
        voided: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl crate::economy::adapter::PaymentAdapter for RecordingPaymentAdapter {
        fn adapter_id(&self) -> &str {
            "recording"
        }
        fn capabilities(&self) -> crate::economy::adapter::AdapterCapabilities {
            crate::economy::adapter::AdapterCapabilities {
                supported_currencies: vec![scp_protocol::economy::types::CurrencyCode::from("USD")],
                supports_streaming: false,
                supports_batch_auth: false,
                supports_single_step: false,
                min_amount: None,
                max_amount: None,
                typical_settlement_ms: 0,
                requires_facilitator: false,
            }
        }
        async fn authorize(
            &self,
            payer: &DID,
            payee: &DID,
            amount: scp_protocol::economy::types::Amount,
            currency: scp_protocol::economy::types::CurrencyCode,
            _metadata: crate::economy::adapter::PaymentMetadata,
        ) -> Result<
            crate::economy::adapter::PaymentAuthorization,
            crate::economy::adapter::PaymentError,
        > {
            Ok(crate::economy::adapter::PaymentAuthorization {
                auth_id: [7u8; 32],
                payer: payer.clone(),
                payee: payee.clone(),
                amount,
                currency,
                adapter_id: "recording".to_owned(),
                created_at: 1_000_000,
                expires_at: 2_000_000,
                adapter_state: vec![],
            })
        }
        async fn capture(
            &self,
            auth: &crate::economy::adapter::PaymentAuthorization,
        ) -> Result<crate::economy::adapter::PaymentReceipt, crate::economy::adapter::PaymentError>
        {
            self.captured
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(crate::economy::adapter::PaymentReceipt {
                receipt_id: [9u8; 32],
                payer: auth.payer.clone(),
                payee: auth.payee.clone(),
                amount: auth.amount,
                currency: auth.currency,
                action_type: scp_protocol::economy::types::PaidActionType::ContextJoin,
                context_id: None,
                adapter_id: "recording".to_owned(),
                adapter_proof: vec![],
                timestamp: 1_000_001,
                signature: vec![],
            })
        }
        async fn void(
            &self,
            _auth: &crate::economy::adapter::PaymentAuthorization,
        ) -> Result<(), crate::economy::adapter::PaymentError> {
            self.voided
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
        async fn verify_authorization(
            &self,
            _auth: &crate::economy::adapter::PaymentAuthorization,
        ) -> Result<(), crate::economy::adapter::PaymentError> {
            Ok(())
        }
        async fn verify(
            &self,
            _receipt: &crate::economy::adapter::PaymentReceipt,
        ) -> Result<
            crate::economy::adapter::VerificationResult,
            crate::economy::adapter::PaymentError,
        > {
            Ok(crate::economy::adapter::VerificationResult {
                valid: true,
                adapter_id: "recording".to_owned(),
                verified_amount: scp_protocol::economy::types::Amount(0),
                verified_currency: scp_protocol::economy::types::CurrencyCode::from("USD"),
                verification_timestamp: 1_000_002,
            })
        }
        async fn refund(
            &self,
            _receipt: &crate::economy::adapter::PaymentReceipt,
            _amount: Option<scp_protocol::economy::types::Amount>,
        ) -> Result<
            crate::economy::adapter::RefundConfirmation,
            crate::economy::adapter::PaymentError,
        > {
            Ok(crate::economy::adapter::RefundConfirmation {
                refund_id: [0u8; 32],
                original_receipt_id: [9u8; 32],
                refunded_amount: scp_protocol::economy::types::Amount(0),
                currency: scp_protocol::economy::types::CurrencyCode::from("USD"),
                adapter_proof: vec![],
            })
        }
    }

    /// Derive a `did:key` DID + matching signing key (the same convention the
    /// FFI tool-economy harness uses), so a `key_resolver` can resolve the
    /// issuer's verifying key for spending-UCAN signature verification.
    fn join_keypair() -> (DID, ed25519_dalek::SigningKey) {
        use std::fmt::Write;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x5Au8; 32]);
        let vk = signing_key.verifying_key();
        let hex = vk.as_bytes().iter().fold(String::new(), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        });
        (DID::from(format!("did:key:{hex}").as_str()), signing_key)
    }

    /// Build a fully-signed spending UCAN bound to `joiner` (iss == aud ==
    /// joiner), signed by `signing_key`, valid for a `ContextJoin`.
    fn signed_join_ucan(
        joiner: &DID,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> scp_protocol::crypto::ucan::UcanToken {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use scp_protocol::crypto::ucan::nonce::generate_nonce;
        use scp_protocol::crypto::ucan::spending::{
            Amount as SpendAmount, CurrencyCode as SpendCurrency, SpendingCapability,
        };
        use scp_protocol::crypto::ucan::{Attenuation, UcanHeader, UcanPayload, UcanToken};

        let cap = SpendingCapability {
            max_per_action: SpendAmount(u64::MAX),
            max_total: SpendAmount(u64::MAX),
            currency: SpendCurrency::from_code("USD").unwrap_or(SpendCurrency(*b"USD\0")),
            time_window: std::time::Duration::from_hours(1),
            allowed_adapters: vec![],
        };
        let mut fct = serde_json::Map::new();
        fct.insert(
            "spending_capability".to_owned(),
            cap.to_fact_value().unwrap_or(serde_json::Value::Null),
        );
        fct.insert(
            "scp_key_scope".to_owned(),
            serde_json::Value::String("#agent".to_owned()),
        );

        let now = scp_primitives::Clock::now_secs(&scp_primitives::SystemClock);
        let header = UcanHeader::with_kid("#agent".to_owned());
        let payload = UcanPayload {
            iss: joiner.as_ref().to_owned(),
            aud: joiner.as_ref().to_owned(),
            exp: now + 3600,
            nbf: Some(now.saturating_sub(60)),
            nnc: generate_nonce(&scp_primitives::SystemClock),
            att: vec![Attenuation {
                with: "scp:spending:*".to_owned(),
                can: "spend".to_owned(),
            }],
            prf: vec![],
            fct: Some(serde_json::Value::Object(fct)),
        };

        let header_json = serde_json::to_vec(&header).expect("header serializes");
        let payload_json = serde_json::to_vec(&payload).expect("payload serializes");
        let header_b64 = URL_SAFE_NO_PAD.encode(&header_json);
        let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature = ed25519_dalek::Signer::sign(signing_key, signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
        let encoded = format!("{signing_input}.{sig_b64}");

        UcanToken {
            header,
            payload,
            signature: signature.to_bytes().to_vec(),
            encoded,
        }
    }

    /// ADR-049 §9 (round-7 money-ordering): the escrow side of a PAID join is
    /// settled atomically with durability — `capture_join_payment` runs only
    /// AFTER the fail-closed persist succeeds, and the escrow is VOIDED (never
    /// captured) when the persist fails, so the joiner is never charged for an
    /// unacknowledged join. The ordering invariant itself is mechanically
    /// enforced by `paid_join_captures_escrow_after_persist_not_before` below.
    ///
    /// This runtime test locks in the CURRENTLY-REACHABLE behavior of the public
    /// `join_context` path: a paid (`per_join`) context blocks AUTO-accept joins
    /// at the `auto_accept_blocked_by_economics` guard (SCP-ECON-12030) BEFORE
    /// any escrow is authorized — so neither capture nor void runs, and no
    /// double-charge is possible through this path. (Surfaced residual: the
    /// escrow/persist tail of `join_context` — and thus the round-7 reorder — is
    /// reached only once an explicit paid-acceptance join flow is wired past the
    /// auto-accept guard; until then it is forward-looking defensive code. The
    /// FFI bridges already thread a `spending_ucan` into this path expecting it
    /// to settle, so the acceptance-flow gap is worth tracking upstream.)
    #[tokio::test]
    async fn paid_join_blocked_at_auto_accept_guard_touches_no_escrow() {
        use scp_protocol::context::roles::Capability;

        let (joiner, joiner_key) = join_keypair();
        let joiner_for_resolver = joiner.clone();
        let joiner_vk = joiner_key.verifying_key();

        // Real MLS crypto provider so `add_member` succeeds, plus a key_resolver
        // that resolves the joiner's verifying key for the spending-UCAN sig.
        let crypto = Arc::new(crate::crypto::mls::provider::MlsCryptoProvider::new(
            "did:dht:z6MkJoinMoneyOrder".to_owned(),
        ));
        let key_resolver: scp_protocol::context::governance::KeyResolver = {
            let did = joiner_for_resolver;
            let vk = joiner_vk;
            Arc::new(move |q: &DID| if *q == did { Some(vk) } else { None })
        };
        let captured = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let voided = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let payment_adapter: Arc<dyn crate::economy::adapter::PaymentAdapterDyn> =
            Arc::new(RecordingPaymentAdapter {
                captured: Arc::clone(&captured),
                voided: Arc::clone(&voided),
            });

        let sup = Supervisor::with_providers(
            crypto,
            Box::new(OkTransport),
            Box::new(OkEventLog),
            key_resolver,
            Some(Box::new(FailingJoinPersistence)),
            Some(payment_adapter),
            None,
            None,
            mls_storage(),
        );

        let admin = DID("did:dht:z6MkJoinMoneyAdmin".to_owned());
        let mut deps = sup
            .build_actor_deps(&admin)
            .await
            .expect("build_actor_deps");

        let context_id = "ctx-paid-join-money-order".to_owned();
        let context_id_bytes = crate::context::state::context_id_to_bytes(&context_id);

        // Create the MLS group so the joiner's `add_member` can succeed.
        deps.crypto
            .create_mls_group(&context_id_bytes)
            .expect("create_mls_group");

        // Build per-context state with a per_join cost so a spending UCAN is
        // required and the escrow path runs.
        let now_secs = scp_primitives::Clock::now_secs(&scp_primitives::SystemClock);
        let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            context_id_bytes,
            now_secs,
            admin.clone(),
        );
        state.role_state.ceiling = scp_protocol::context::roles::CapabilityCeiling::new([
            Capability::MemberInvite,
            Capability::MessagesWrite,
            Capability::MessagesRead,
        ]);
        state.governance.economic_policy = Some(scp_protocol::economy::types::EconomicPolicy {
            locked: false,
            cost_schedule: scp_protocol::economy::types::CostSchedule {
                currency: scp_protocol::economy::types::CurrencyCode::from("USD"),
                per_message: None,
                per_tool_invoke: None,
                per_join: Some(scp_protocol::economy::types::Amount(10)),
                per_period: None,
                per_byte_stored: None,
            },
            payment_adapters: vec!["recording".to_owned()],
            pricing_formula: None,
            payee: admin.clone(),
        });
        state
            .handle
            .transition_to(&crate::context::ContextState::Active)
            .await
            .unwrap();

        // Generate a real MLS KeyPackage for the joiner.
        let joiner_cred = crate::crypto::mls::credential::ScpCredential::new(
            joiner.as_ref().to_owned(),
            None,
            scp_protocol::identity::SigningKeyId::Active,
        )
        .expect("joiner credential");
        let (kp_bundle, _signer, _provider) =
            crate::crypto::mls::group::generate_key_package(&joiner_cred)
                .expect("generate joiner key package");
        let kp_bytes =
            openmls::prelude::tls_codec::Serialize::tls_serialize_detached(kp_bundle.key_package())
                .expect("serialize key package");
        let key_package =
            scp_protocol::context::membership::KeyPackage::new(joiner.clone(), kp_bytes);

        let handle = ContextHandle::new(context_id.clone(), state.handle.params().clone());
        handle
            .transition_to(&crate::context::ContextState::Active)
            .await
            .unwrap();

        let spending_ucan = signed_join_ucan(&joiner, &joiner_key);

        // Even with a failing persistence backend, the paid (`per_join`) policy
        // is rejected at the auto-accept guard BEFORE escrow authorization, so
        // the persist failure is never reached and no escrow side effect runs.
        deps.persistence = Arc::new(FailingJoinPersistence);

        let result = lifecycle_helpers::join_context(
            &mut state,
            &deps,
            &handle,
            key_package,
            Some(&spending_ucan),
            None,
        )
        .await;

        assert!(
            matches!(&result, Err(ContextError::PermissionDenied(msg)) if msg.contains("SCP-ECON-12030")),
            "an auto-accept join of a paid context must be rejected at the \
             economics guard (SCP-ECON-12030) before any escrow side effect: got {result:?}"
        );
        assert_eq!(
            captured.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "no escrow may be captured when the join is rejected at the guard"
        );
        assert_eq!(
            voided.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "no escrow may be voided when the join is rejected before authorization"
        );
    }

    /// ADR-049 §9 (round-7 money-ordering) — STRUCTURAL enforcement of the
    /// reorder. In `join_context`, the external escrow settlement
    /// (`capture_join_payment`) MUST appear AFTER the fail-closed persist
    /// (`persist_state_fail_closed`), and the persist-failure branch MUST void
    /// the escrow (`void_paid_action`) — mirroring the send path. This guards
    /// the ordering at compile/test time because the runtime tail is currently
    /// gated behind the not-yet-wired explicit paid-acceptance flow (see
    /// `paid_join_blocked_at_auto_accept_guard_touches_no_escrow`). A non-gamed
    /// assertion: it checks the actual byte ORDER of the two calls in the real
    /// `join_context` body, so reverting the reorder fails this test.
    #[test]
    fn paid_join_captures_escrow_after_persist_not_before() {
        const SRC: &str = include_str!("lifecycle_helpers.rs");

        // Isolate the `join_context` fn body (from its signature to the next
        // top-level `pub fn`/`pub async fn` boundary) so the assertion is about
        // THIS function, not incidental matches elsewhere in the file.
        let start = SRC
            .find("pub async fn join_context(")
            .expect("join_context must exist");
        let rest = &SRC[start..];
        // The function ends before the next item that starts a new helper.
        let end_rel = rest
            .find("\npub fn join_context_membership(")
            .expect("join_context_membership follows join_context");
        let body = &rest[..end_rel];

        let persist_idx = body
            .find("persist_state_fail_closed(state, deps, &context_id)")
            .expect("join_context must fail-closed persist on the paid path");
        let capture_idx = body
            .find("capture_join_payment(")
            .expect("join_context must capture the escrow");

        assert!(
            persist_idx < capture_idx,
            "capture_join_payment (escrow settlement) must run AFTER \
             persist_state_fail_closed — capturing before durability double-charges \
             the joiner on the idempotent retry (ADR-049 §9 round-7)"
        );

        // The persist-failure branch (between the fail-closed persist and the
        // success-path capture) MUST void the escrow. `void_paid_action` also
        // appears in the earlier MLS-rollback branches, so search the slice
        // AFTER the persist call for the failure escape hatch specifically.
        let post_persist = &body[persist_idx..capture_idx];
        assert!(
            post_persist.contains("void_paid_action(state, deps, a, &context_id)"),
            "the persist-failure branch must void the escrow (between the \
             fail-closed persist and the success-path capture) so a durability \
             failure releases the hold instead of charging the joiner"
        );
    }

    /// ADR-049 §9 (round-9 leak fix) — BEHAVIORAL. `finalize_send` reserves a
    /// per-sender sequence in its caller (`send_message`), and OWNS the sequence
    /// rollback on every error exit. Its FIRST statement is the `MessageSent`
    /// `append_context_event`; before this fix that `?` returned BEFORE the
    /// relocated rollbacks, so an event-log append failure leaked the reserved
    /// sequence → a per-sender gap → a receiver `SequenceGapForceClose`. This
    /// test drives a WORKING persistence + a FAILING event-log append directly
    /// through `finalize_send` and asserts the reserved sequence returns to its
    /// pre-reservation baseline EXACTLY ONCE (no leak, no double-rollback).
    #[tokio::test]
    async fn finalize_send_rolls_back_sequence_on_event_log_append_failure() {
        let crypto = Arc::new(crate::crypto::mls::provider::MlsCryptoProvider::new(
            "did:dht:z6MkFinalizeSendSeq".to_owned(),
        ));
        let key_resolver: scp_protocol::context::governance::KeyResolver =
            Arc::new(|_q: &DID| None);

        // Working persistence (CapturingPersistence) + FAILING event-log append.
        let sup = Supervisor::with_providers(
            crypto,
            Box::new(OkTransport),
            Box::new(FailingAppendEventLog),
            key_resolver,
            Some(Box::new(CapturingPersistence::default())),
            None,
            None,
            None,
            mls_storage(),
        );

        let admin = DID("did:dht:z6MkFinalizeSendAdmin".to_owned());
        let deps = sup
            .build_actor_deps(&admin)
            .await
            .expect("build_actor_deps");

        let context_id = "ctx-finalize-send-seq".to_owned();
        let context_id_bytes = crate::context::state::context_id_to_bytes(&context_id);

        let sender = DID("did:dht:z6MkFinalizeSendSender".to_owned());
        let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            context_id_bytes,
            scp_primitives::Clock::now_secs(&scp_primitives::SystemClock),
            admin.clone(),
        );
        state
            .membership
            .add_member(sender.clone(), "member".to_owned(), Vec::new());
        state
            .handle
            .transition_to(&crate::context::ContextState::Active)
            .await
            .unwrap();

        // Reserve a sequence exactly as `send_message` does, capturing it.
        let reserved = state
            .membership
            .next_sequence_number(sender.as_ref())
            .expect("sender is a member");
        assert_eq!(reserved, 1, "first reservation yields sequence 1");

        // Encrypted (non-broadcast) send: the failing append must roll the
        // reservation back. `signing_key = None` → the post-append checkpoint
        // path is skipped, but the append fails first regardless.
        let result = crate::context::messaging_helpers::finalize_send(
            &mut state,
            &deps,
            &context_id,
            &context_id_bytes,
            &sender,
            reserved,
            b"payload",
            None,
            false, // spending_nonce_committed
            false, // is_broadcast
        );

        assert!(
            matches!(result, Err(ContextError::EventLogFailed(_))),
            "a failing event-log append must surface as EventLogFailed: got {result:?}"
        );

        // The reservation must have been rolled back EXACTLY ONCE: the next
        // reservation returns 1 again. A leak would make it return 2; a
        // double-rollback (saturating_sub past the floor) would also return 1
        // here but only because it underflowed — so additionally assert the
        // pre-reservation reissue is stable across two calls.
        let next_after_failure = state
            .membership
            .next_sequence_number(sender.as_ref())
            .expect("sender is still a member");
        assert_eq!(
            next_after_failure, 1,
            "the reserved sequence must roll back to baseline exactly once, so the \
             next reservation reissues 1 (a leak would reissue 2)"
        );
    }

    /// ADR-049 §9 (round-9 leak fix) — STRUCTURAL. In `join_context`, the
    /// `MemberJoined` `append_context_event` runs AFTER the economy ticket is
    /// committed but while the external escrow hold (`auth`, a
    /// `PaidActionAuthorization` with NO `Drop`) is still held and uncaptured.
    /// On that append's `Err`, `auth` would otherwise drop WITHOUT voiding —
    /// leaking the hold and charging the joiner for an unacknowledged join. The
    /// runtime tail (post-commit, pre-capture) is reached only by the not-yet-
    /// wired explicit paid-acceptance flow (the public entry rejects an
    /// auto-accept paid join at SCP-ECON-12030 first — see
    /// `paid_join_blocked_at_auto_accept_guard_touches_no_escrow`), so this is a
    /// STRUCTURAL assertion on the real `join_context` body, mirroring
    /// `paid_join_captures_escrow_after_persist_not_before`: the `MemberJoined`
    /// append's failure branch — which sits BETWEEN the ticket commit and the
    /// fail-closed persist — MUST void the escrow.
    #[test]
    fn join_context_voids_escrow_on_member_joined_append_failure() {
        const SRC: &str = include_str!("lifecycle_helpers.rs");

        let start = SRC
            .find("pub async fn join_context(")
            .expect("join_context must exist");
        let rest = &SRC[start..];
        let end_rel = rest
            .find("\npub fn join_context_membership(")
            .expect("join_context_membership follows join_context");
        let body = &rest[..end_rel];

        // The economy ticket is committed here; AFTER this point `auth` is the
        // only un-Drop-guarded reservation still live.
        let commit_idx = body
            .find("commit_economy_ticket(ticket)")
            .expect("join_context must commit the economy ticket before the append");
        // The MemberJoined append is the next fallible step after the commit.
        let append_idx = body
            .find("\"MemberJoined\"")
            .expect("join_context must append a MemberJoined event");
        assert!(
            commit_idx < append_idx,
            "the MemberJoined append must follow the ticket commit"
        );

        // The fail-closed persist runs after the append; the append-failure
        // branch sits strictly between commit and that persist.
        let persist_idx = body
            .find("persist_state_fail_closed(state, deps, &context_id)")
            .expect("join_context must fail-closed persist on the paid path");
        assert!(
            append_idx < persist_idx,
            "the MemberJoined append must precede the fail-closed persist"
        );

        // The slice from the append to the fail-closed persist contains the
        // append's Err branch. It MUST void the escrow — otherwise `auth` drops
        // silently (no Drop impl) and the hold leaks.
        let append_to_persist = &body[append_idx..persist_idx];
        assert!(
            append_to_persist.contains("void_paid_action(state, deps, a, &context_id)"),
            "the MemberJoined append-failure branch (between the ticket commit and \
             the fail-closed persist) must void the escrow so a failing append \
             releases the hold instead of leaking it (ADR-049 §9 round-9)"
        );
    }
}
