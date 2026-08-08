//! Lifecycle helpers — actor-shape signatures
//! (ADR-049 Phase 2A.9, `lifecycle` domain migration).
//!
//! # Purpose
//!
//! This module hosts lifecycle-domain helpers that operate on actor-owned
//! [`PerContextState`](crate::context::state::PerContextState) and
//! capability-reduced [`ActorDeps`](crate::context::actor::deps::ActorDeps).
//! Phase 2A finalization deleted the legacy `&Supervisor` lock-and-call
//! bodies (and the shim fallback); every lifecycle command now runs
//! through these actor-shape helpers.
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
//! 1. [`export_context_blocks`] — read-only state borrow + persistence-side
//!    snapshot construction; produces a signed [`ContextExport`](crate::context::export_import::ContextExport).
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
//! - [`finalize_create`] — gauges + persistence + TTL timer post-creation.
//! - [`import_context`] — full import body (validate, restore crypto, build `PerContextState`, register).
//! - [`load_persisted_context_state`] — load context snapshot and broadcast state from persistence.
//! - [`restore_context`] — rebuild `PerContextState` from snapshot + register + arm TTL deadline.
//!
//! Governance timeouts are ACTOR-OWNED (ADR-049 Decision-1 / finding A3):
//! the freshly-spawned per-context actor's `reconcile_timers` arms a 60 s
//! interval while the context is `Active`, so the bootstrap paths do NOT
//! install a governance-timeout task. They still arm the TTL deadline via
//! `SupervisorHandle::dispatch_start_ttl_timer` (which records
//! `state.ttl.timer.deadline_unix_secs` for the actor's TTL arm).
//!
//! # Supervisor-iterating sweep entry points
//!
//! These iterate the actor registry
//! ([`Supervisor::actor_ids`](crate::context::supervisor::Supervisor::actor_ids),
//! NOT a legacy `contexts` `DashMap`) and dispatch one typed sweep
//! command per actor through the per-context mailbox. They live in this
//! module:
//!
//! - [`restore_all_contexts`] (iterates persistence snapshots — no
//!   actors exist before restore)
//! - [`flush_all_contexts`] / [`flush_all_contexts_sync`]
//! - [`shutdown_all_contexts`] / [`shutdown_all_contexts_sync`]

#![allow(clippy::significant_drop_tightening)]

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use scp_did::DID;
use scp_protocol::context::builder::ContextCreationError;
use scp_protocol::context::governance::GovernanceModelConfig;
use scp_protocol::context::governance::mls_integration::EpochCoordinator;
use scp_protocol::context::membership::{ContextEvent, KeyPackage, MembershipState, ReceiveBuffer};
use scp_protocol::context::roles::{Capability, CapabilityCeiling, ContextRoleState};
use scp_protocol::context::{ContextError, ContextParams, ContextState};

use crate::context::ContextHandle;
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::sequence::SendSequenceTracker;
use crate::context::actor::state::{
    ContextCryptoState, ContextLifecycleState, ContextModeState, ContextRouting, PerContextState,
    RecvSequenceTracker,
};
use crate::context::governance::timeout::DeadlockDetectionState;
use crate::context::governance_helpers;
use crate::context::state::{
    self, AccessControlState, CommitOperation, EpochState, GovernanceState, TtlState,
};
use crate::context::ttl::{self, CloseResult, TtlTimer};

// ADR-049 Phase 2A finalization keystone (ADR-049 §15 phase 2A finalization
// — type unification, single PerContextState): the prior alias to the
// legacy struct was deleted alongside the struct itself. Every bootstrap
// call site now constructs the unified `PerContextState` directly and
// hands it to `spawn_actor_with_state`; the spawned actor OWNS the state
// and registers its handle in the supervisor registry. There is no legacy
// contexts `DashMap` — the actor registry is the single source of truth.

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
    // ADR-056: resolve to the canonical digest (matches `state.context_id` and
    // the crypto keys the snapshot exports), not a re-hash of the hex id.
    let ctx_id_bytes = state::context_id_to_bytes(context_id);

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
// ADR-049 §Decision 12: `state`/`transition_to` are now synchronous lock-free
// ArcSwap ops. Async is retained as the ContextManager helper API contract —
// callers await uniformly, and the crypto/transport/event-log provider calls
// regain await points under ADR-049 Decision 7 (async-provider-trait conversion).
#[allow(clippy::too_many_lines, clippy::unused_async)]
pub async fn leave_context(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    handle: &ContextHandle,
    caller_did: &DID,
    member_did: &DID,
) -> Result<(), ContextError> {
    let context_id = handle.context_id().to_owned();
    let context_id_bytes = state::context_id_to_bytes(&context_id);

    // ADR-049 §9 Class S: a member leaving removes their own membership (a
    // downward-authorization transition for that member) — STRUCTURAL fail-closed.
    // The removal body (MLS remove + membership/role/access/routing cleanup) runs
    // inside the Class-S `_keep` combinator's `rest_mut()` view, so the fail-closed
    // persist is performed BY the combinator (replacing the former inline
    // `persist_state_fail_closed`). KEEP-direction: a removal that did not durably
    // land is NOT rolled back in memory — re-admitting a member the caller was told
    // had left is the unsafe direction; the persist error is surfaced instead so the
    // leave is not acknowledged as durable. The closure body is synchronous; the
    // `MemberLeft` Merkle-leaf append and the close-on-empty transition (both now or
    // already async — under ADR-049 Decision 7 `EventLogPersistence` is async) run
    // AFTER the persist, outside the sync `_keep` closure. `check_commit_fault` reads
    // through the whole `&mut PerContextState` the view hands back. The MLS-Commit
    // broadcast also runs after this persist (async — Decision 7); on failure its
    // `commit_fault`/`pending_commits` bookkeeping is applied FAIL-CLOSED via a
    // second `commit_class_s_keep` (`apply_broadcast_failure`), because `commit_fault`
    // is a safety gate that must survive a crash before the coalesced persist tick.
    let (should_close, left_role_name, is_broadcast, mls_commit_bytes) = cell
        .commit_class_s_keep(deps, &context_id, |mut view| {
            let state = view.rest_mut();

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
            //
            // Capture the removal Commit bytes here; the ASYNC transport ops
            // (Commit broadcast, sender-key rotation + delivery) run AFTER the
            // fail-closed persist below, outside this synchronous `_keep` closure
            // (ADR-049 Decision 7 — `ContextTransportProvider` is now async and
            // cannot be awaited inside the sync closure). The membership removal
            // is fail-closed-persisted by the combinator; the Commit-broadcast
            // enqueue is Class-C (coalesced) and the sender-key rotation/delivery
            // are best-effort crypto/transport side-effects.
            let mls_commit_bytes = if is_broadcast {
                None
            } else {
                // ADR-049 PR-7 (SCP-CRYPTOMOVE-001): MLS removal + per-member
                // sender-key prune run on the actor's OWNED crypto state (the
                // `rest_mut()` view above), not the provider — this is the last
                // leave-path caller flipped off the deleted provider steady-state
                // twins. `local_did` is node-resident identity (retained on the
                // provider); the actor `remove_member` skips a self-leave.
                let local_did = deps.crypto.local_did();
                let remove_output = state.remove_member(local_did, member_did.as_ref())?;
                if let Err(e) = state.remove_member_sender_key(member_did.as_ref()) {
                    tracing::warn!(
                        context_id = %context_id,
                        member = %member_did,
                        error = %e,
                        "remove_member_sender_key failed after MLS removal — \
                         sender key layer may retain stale key"
                    );
                }
                // ADR-049 PR-6: prune the departed member's Class-M registry
                // floors (member-granular; siblings + local scalar retained).
                deps.supervisor
                    .remove_member_floors(&context_id_bytes, member_did);
                Some(remove_output.commit_bytes)
            };

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

            // Capture the leaving member's role name BEFORE the membership/role
            // strip below — the role held at departure, carried into the
            // subject-bearing MemberLeft leaf (ADR-011 amendment) so the
            // participation record (§7.3.2) attributes the self-leave to this
            // member with its role context.
            let left_role_name = state
                .membership
                .get(member_did.as_ref())
                .map(|info| info.role_name.clone())
                .unwrap_or_default();

            if !state.membership.remove_member(member_did) {
                return Err(ContextError::MemberNotFound(member_did.to_string()));
            }

            // Clean teardown of ALL per-DID role state (spec §5.6.1): members,
            // assignments, member_capabilities, AND suspended_capabilities. Replaces
            // the prior strip that left the departing DID's suspension dangling, so a
            // re-admitted same-DID member no longer inherits a phantom suspension.
            // `state.membership.remove_member` above already guarded not-found, so the
            // `-> bool` return is unused here. Inside `commit_class_s_keep`, so the
            // downward-auth suspension drop persists fail-closed (ADR-049 §9).
            state.role_state.remove_member(member_did.as_ref());

            // Destroy the departing member's access key (§9.17.2, ADR-038).
            state
                .access
                .access_key_store
                .remove(&context_id, member_did.as_ref());

            // Drop the departing member's CEK-exclusion entry (spec §5.6.1, §9.17) —
            // per-DID content-access state outside the role state. Mirrors
            // `execute_remove_member`, so a re-admitted same-DID member no longer
            // inherits a phantom read exclusion.
            state.access.read_exclusion_list.remove(member_did);

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

            Ok((should_close, left_role_name, is_broadcast, mls_commit_bytes))
        })
        .await?;

    // Async transport ops AFTER the Class-S removal persist (ADR-049 Decision 7:
    // `ContextTransportProvider` is async and cannot be awaited inside the
    // synchronous `_keep` closure above). The membership removal is already
    // fail-closed-persisted; the MLS-Commit broadcast's failure bookkeeping is
    // itself re-persisted FAIL-CLOSED (see below), while the sender-key rotation +
    // delivery are best-effort crypto/transport side-effects. The captured
    // `mls_commit_bytes` is the removal Commit already produced under the crypto
    // `Arc` (Class-M) inside the closure.
    if !is_broadcast {
        // Broadcast the MLS Commit to remaining members so they can advance their
        // group epoch and ratchet key material. Broadcast async (ADR-049 Decision
        // 7); on transport FAILURE the retry-queue bookkeeping is persisted
        // FAIL-CLOSED via `keep_broadcast_failure` (member departure is a
        // safety-gated site — see that helper's doc for why the second persist).
        if let Some(commit_bytes) = mls_commit_bytes
            && let Some(failure) = governance_helpers::try_broadcast_commit(
                deps,
                &context_id,
                commit_bytes,
                &CommitOperation::LeaveContext {
                    member_did: member_did.clone(),
                },
            )
            .await
        {
            governance_helpers::keep_broadcast_failure(cell, deps, &context_id, failure).await?;
        }

        // Rotate the local sender key and distribute to remaining members
        // (§9.16.4). ADR-049 PR-7: Class-S — the epoch bump is sync-persisted
        // fail-closed via `commit_class_s_keep` (a bumped-then-crash-lost epoch
        // would let the departed member's old key keep decrypting); anti-replay
        // backstop is the never-regressing registry floor (`mirror_forward`,
        // `?`-propagated). M23: sender-key rotation + distribution stays
        // best-effort — a rotate/persist failure is logged and the leave continues
        // (MLS removal above is the hard security boundary).
        let local_did = deps.crypto.local_did().to_owned();
        match cell
            .commit_class_s_keep(deps, &context_id, |mut v| {
                let s = v.rest_mut();
                s.rotate_sender_key(&local_did)?;
                Ok(s.local_sender_key_epoch())
            })
            .await
        {
            Ok(epoch) => {
                // ADR-049 PR-6/PR-7: advance the durably-bumped local epoch in the
                // authoritative floor registry (fail-closed backstop).
                crate::context::messaging_helpers::mirror_forward_local_sender_epoch(
                    deps,
                    &context_id_bytes,
                    epoch,
                )?;
            }
            Err(e) => {
                tracing::warn!(
                    context_id = %context_id,
                    error = %e,
                    "rotate_sender_key failed after leave — \
                     remaining members retain old sender key"
                );
            }
        }
        {
            // Drain through the actor's crypto state (same one the rotation just
            // populated); `&mut` view scoped so `cell` is free afterward.
            let mut view = cell.class_c_view();
            if let Err(e) =
                drain_and_deliver_sender_keys(deps, view.mode_mut().crypto_mut(), &context_id).await
            {
                tracing::warn!(
                    context_id = %context_id,
                    error = %e,
                    "failed to deliver rotated sender keys after leave"
                );
            }
        }
    }

    // Append the `MemberLeft` Merkle leaf AFTER the Class-S removal persist.
    // Under ADR-049 Decision 7 `EventLogPersistence` is async, so this append
    // cannot run inside the synchronous `_keep` closure above — the membership
    // removal is already fail-closed-persisted by the combinator; the Merkle
    // leaf is a separate durable record.
    //
    // Subject-bearing leaf (ADR-011 amendment): the payload carries the affected
    // member (`member_did`, which on a self-leave already equals `actor_did`) and
    // its role at departure, so the leaf shape is uniform with admin-driven
    // removals and the SDK reads `subject_did` consistently.
    //
    // Committer-assigned: the leaving member's clock — the source of the
    // `created_at` on its outgoing leave commit. This is the
    // convergent-by-construction value WHEN cross-member leaf replication lands:
    // the receive-side append path is currently dormant, so this leaf is
    // committer-appended-only and is NOT yet replicated to other members.
    // Cross-member convergence of membership leaves is the forward step under
    // ADR-051 (§7.3.1, §9.9.3).
    deps.event_log
        .append_membership_change_leaf(
            &context_id_bytes,
            scp_event_log::EventType::MemberLeft,
            member_did.as_ref(),
            member_did.as_ref(),
            &left_role_name,
            deps.clock.now_secs(),
        )
        .await?;
    *cell.class_c_view().checkpoint_events_since_mut() += 1;

    // If member count reaches zero, transition to Closing. Runs AFTER the
    // fail-closed persist above, matching the prior ordering.
    if should_close {
        handle.transition_to(&ContextState::Closing)?;
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
pub async fn drain_and_deliver_sender_keys(
    deps: &ActorDeps,
    crypto_state: Option<&mut crate::context::actor::state::ContextCryptoState>,
    context_id: &str,
) -> Result<(), ContextError> {
    // ADR-049 PR-7 (SCP-CRYPTOMOVE-001): drain + MLS-wrap the rotated sender-key
    // distributions through the actor's OWNED field-granular Class-C
    // `&mut ContextCryptoState` — the SAME crypto state the producer
    // (`rotate_sender_key` / `add_member`) populated, so producer and consumer
    // stay coherent. The provider steady-state twins
    // (`drain_pending_sender_key_messages` / `mls_encrypt_management`) are deleted;
    // there is no provider queue to fall back to. A broadcast context has no MLS
    // `ContextCryptoState` (`crypto_mut()` is `None`) and no sender-key
    // distributions — draining nothing is correct (rotation is skipped for
    // broadcast, so the queue is always empty here).
    let Some(crypto_state) = crypto_state else {
        return Ok(());
    };
    let pending = std::mem::take(&mut crypto_state.pending_distributions);
    if !pending.is_empty() {
        let routing_id = scp_protocol::context::context_routing_id(context_id);
        for (target_did, message) in pending {
            tracing::debug!(
                target_did = %target_did,
                context_id = %context_id,
                message_len = message.len(),
                "MLS-encrypting and sending rotated sender key distribution"
            );
            let sealed = crypto_state.mls_encrypt_management(
                &message,
                &routing_id,
                crate::context::messaging_helpers::DEFAULT_BLOB_TTL_SECS,
            );
            match sealed {
                Ok(sealed) => {
                    if let Err(e) = deps.transport.send_message(&routing_id, &sealed).await {
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
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    handle: &ContextHandle,
    initiator_did: &DID,
) -> Result<CloseResult, ContextError> {
    close_context_with_key(cell, deps, handle, initiator_did, None).await
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
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    handle: &ContextHandle,
    initiator_did: &DID,
    signing_key: Option<&ed25519_dalek::SigningKey>,
) -> Result<CloseResult, ContextError> {
    let context_id = handle.context_id().to_owned();

    // Pre-`ttl::close_context` GATES are read-only against the cell (`&*cell`
    // Deref → `&PerContextState`); they stage no Class-S mutation, so no persist
    // is owed for an early reject here.

    // State check inside actor body -- eliminates TOCTOU race.
    state::require_active(&cell.handle)?;

    // Gate: multi-admin models must use governance path (SCP-270, ADR-031).
    if !matches!(
        cell.governance.engine.model_config(),
        GovernanceModelConfig::SingleAdmin { .. }
    ) {
        return Err(ContextError::PermissionDenied(
            "multi-admin contexts must close through governance \
             (propose GovernanceAction::CloseContext)"
                .to_owned(),
        ));
    }

    // Snapshot role_state for the ttl::close_context call.
    let role_state = cell.role_state.clone();

    // Delegate to ttl::close_context for the lifecycle transition + role
    // gate (async). The initiator assigns the `ContextClosing` leaf timestamp
    // from its own clock — the same value stamped on the outgoing close
    // commit. This is the convergent-by-construction value WHEN cross-member
    // leaf replication lands; the receive-side append path is currently
    // dormant, so the leaf is committer-appended-only and is NOT yet
    // replicated to other members. Cross-member convergence is the forward
    // step under ADR-051 (§7.3.1, §9.9.3).
    //
    // This `.await` runs BEFORE the Class-S persist below and does NOT mutate
    // `PerContextState` (it drives the shared `handle` lifecycle FSM), so it
    // stays OUTSIDE the `_keep` combinator closure that wraps the subsequent
    // state mutations + fail-closed persist.
    let result = ttl::close_context(
        handle,
        initiator_did,
        &role_state,
        deps.event_log.as_ref(),
        deps.clock.now_secs(),
    )
    .await?;

    // ADR-049 §9 Class S: the lifecycle close transition is security-critical
    // (a closed context must not silently re-open on a crash) — STRUCTURAL
    // fail-closed. All post-transition state mutations (timer/timeout cancel,
    // broadcast/routing teardown, participation decay, final checkpoint, the
    // `SystemClose` emit) run inside the Class-S `_keep` combinator's
    // `rest_mut()` view, so the fail-closed persist is performed BY the
    // combinator (replacing the former inline `persist_state_fail_closed`).
    // KEEP-direction: a close that did not durably land is NOT rolled back in
    // memory — silently re-opening a closed context is the unsafe direction; the
    // persist error is surfaced instead. These mutations are all synchronous (the
    // self-deadlock-avoiding gauge refresh is a detached `tokio::spawn` that
    // borrows only `deps`), so they fit the sync `_keep` closure.
    cell.commit_class_s_keep(deps, &context_id, |mut view| {
        let state = view.rest_mut();

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

        // TTL + governance timers are actor-owned arms (ADR-049 finding A3):
        // the actor's `reconcile_timers` clears the governance interval once
        // this close leaves `Active`, and disarms the one-shot TTL arm on a
        // non-Active context. Clear the recorded TTL deadline HERE (durably, in
        // the fail-closed snapshot) so a stale absolute deadline cannot fire
        // against the closed context on a later restore and despawn it —
        // re-opening this very close window (BUG-1).
        state.ttl.timer.deadline_unix_secs = None;
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

        Ok(())
    })
    .await?;

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
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    handle: &ContextHandle,
    key_package: KeyPackage,
    spending_ucan: Option<&scp_protocol::crypto::ucan::UcanToken>,
    local_pseudonym: Option<[u8; 32]>,
) -> Result<(), ContextError> {
    // ADR-049 §9 Class-S cell seam: the join tail no longer derives a bare
    // `&mut PerContextState` via `state_mut()`. The Phase-1 READS below
    // (version / lifecycle / sybil gates) go through `&*cell` (the cell Derefs to
    // `&PerContextState`); the Class-C bookkeeping MUTATIONS (hard-rate-limit
    // consume + velocity record, and every later economy reversal) go through a
    // short-lived `cell.class_c_view()` re-borrowed at each step so it drops
    // before the next `.await` (NLL). The spending-nonce consume still routes
    // through `begin_class_s_conditional` / the deferred `ClassSCommitToken`
    // exactly as before — the keep-direction is unchanged.
    let context_id = handle.context_id().to_owned();
    let context_id_bytes = state::context_id_to_bytes(&context_id);
    let member_did = key_package.owner_did.clone();

    // Fast-fail: reject obviously incompatible versions before expensive
    // crypto ops (MLS group join, sender key derivation). Looks up the
    // stored context's params (not the caller-supplied handle params)
    // so this check is authoritative even when the caller passes an
    // ephemeral handle with default params (e.g. UniFFI bridge).
    cell.handle
        .params()
        .check_version_compatibility(scp_protocol::envelope::SCP_PROTOCOL_VERSION)?;

    // Validate key package before any mutations (idempotent, no lock needed).
    //
    // ADR-049 §15 / SCP-CRYPTOMOVE-000c: stateless KP validation routes through
    // the stateless `MlsBackend` (`deps.mls`) — the provider copy is retired from
    // the production call path (retained only as a test-exercised copy at
    // `crypto/mls/provider.rs`), and §15 grants it no carve-out
    // ("`validate_key_package` … becomes a stateless free-fn / `MlsBackend` method
    // over `&dyn Clock`"). `validate_key_package` runs the full validation
    // (signature / hardened-clock lifetime / ciphersuite) ONCE and returns the
    // authenticated `credential_did` extracted from the same validated leaf, so
    // the load-bearing binding (the KP credential DID MUST equal the envelope's
    // `owner_did`, formerly enforced inside the provider method) is preserved
    // here as a single validate-and-bind — no second parse or re-validation.
    // Under `cfg(test)`/`testing` a `None` KP is accepted (mock fixtures);
    // production requires real bytes.
    let kp_bytes = key_package.mls_key_package_bytes.as_deref();
    match kp_bytes {
        Some(bytes) => {
            let validated = deps
                .mls
                .validate_key_package(bytes, deps.clock.as_ref())
                .await
                .map_err(|e| ContextError::InvalidKeyPackage(e.to_string()))?;
            if member_did != validated.credential_did {
                return Err(ContextError::InvalidKeyPackage(
                    "key package credential DID does not match owner_did".to_string(),
                ));
            }
        }
        None => {
            if !cfg!(any(test, feature = "testing")) {
                return Err(ContextError::InvalidKeyPackage(
                    "production MlsBackend requires MLS key package bytes".to_string(),
                ));
            }
        }
    }

    // Phase 1: state + sybil + economy enforcement against actor-owned
    // state. This happens BEFORE any crypto mutations so that a rejected
    // payment never grants MLS group access or sender keys.
    state::require_active(&cell.handle)?;

    // Defense-in-depth: re-check version compatibility after the eager
    // crypto validation. Governance could theoretically change the
    // min_protocol_version between the early check and here.
    cell.handle
        .params()
        .check_version_compatibility(scp_protocol::envelope::SCP_PROTOCOL_VERSION)?;

    // M13: Sybil resistance check BEFORE economy enforcement so that
    // a rejected sybil attacker doesn't consume budget. Fail-closed.
    // Read-only: routed through `&*cell` (the shared sybil-policy + governance
    // reads), dropped before the Class-C mutations below.
    crate::context::lifecycle_logic::evaluate_sybil_resistance(
        cell.handle.params().sybil_policy.as_ref(),
        &cell.governance,
        &member_did,
        deps.clock.now_secs(),
    )?;

    // Defense-in-depth hard rate limit on joins (Matrix-style token
    // bucket). On any subsequent failure we refund the token. Class-C:
    // the hard-rate-limit consume + velocity record are routed through a
    // `class_c_view()` borrow that drops at the end of this block.
    let now_secs = deps.clock.now_secs();
    let velocity_token = {
        let mut view = cell.class_c_view();
        let gov = view.governance_class_c_mut();
        if !gov.hard_rate_limit_mut().try_consume(&member_did, now_secs) {
            return Err(ContextError::RateLimited {
                resource: "join".to_owned(),
                message: "hard rate limit exceeded for joiner".to_owned(),
                // Token-bucket hard limit: no exact refill instant to surface.
                retry_after_ms: None,
            });
        }
        // Record the join in the velocity tracker so subsequent §19.7
        // escalation observes the same activity surface as message sends.
        // F5: capture the rollback token so a join failure refunds THIS
        // entry specifically rather than racing concurrent joiners.
        gov.velocity_tracker_mut()
            .record_message(&member_did, now_secs)
    };

    // ADR-049 §9 Class S: route the join-path spending-nonce consume through the
    // DEFERRED-persist combinator. `enforce_join_economy` burns the nonce inside
    // the `begin_class_s_conditional` closure; the returned `Option<ClassSCommitToken>`
    // is `Some` only on the PAID branch (a non-zero cost AND a spending UCAN —
    // the same gating the Phase-5 fail-closed persist uses) and is held across
    // the MLS / membership `.await`s below, committed at Phase 5 (or by each
    // pre-finalize abort path, keep-direction). The combinator owns the cell for
    // the duration of its closure; the remaining body re-borrows the cell through
    // short-lived `class_c_view()` / `&*cell` borrows at each step (no
    // `state_mut()` escape hatch).
    let (deducted_cost, mut spending_nonce_token) =
        match cell.begin_class_s_conditional(&context_id, |mut view| {
            let state = view.rest_mut();
            let member_count = state.membership.count();
            let governance = &mut state.governance;
            let cost = crate::context::lifecycle_logic::enforce_join_economy(
                governance,
                member_count,
                &member_did,
                now_secs,
                spending_ucan,
                &context_id,
                &*deps.clock,
                &deps.key_resolver,
            )?;
            // A spending-UCAN nonce is burned iff a non-zero cost was charged AND
            // a spending UCAN was presented — the same gating the Phase-5
            // fail-closed persist uses.
            let did_consume_nonce = cost.is_some() && spending_ucan.is_some();
            Ok((cost, did_consume_nonce))
        }) {
            Ok(cost_and_token) => cost_and_token,
            Err(e) => {
                // No ticket and no token exist yet (the consume did not happen) —
                // roll back inline through the Class-C view (velocity entry +
                // hard-rate-limit token); the view drops before the early return.
                let mut view = cell.class_c_view();
                let gov = view.governance_class_c_mut();
                gov.velocity_tracker_mut()
                    .rollback(&member_did, velocity_token);
                gov.hard_rate_limit_mut().refund(&member_did);
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
    //
    // The authorize is SPLIT (ADR-049 §9 cell seam): the sync `prepare` half
    // reads state through `&*cell` and returns owned inputs (the borrow drops at
    // the call boundary), then the async `hold` half awaits the escrow create
    // with NO state borrow live — so the actor future stays `Send`
    // (`PerContextState` is `!Sync`). `None` from `prepare` means no adapter / no
    // policy / zero cost, i.e. the legacy `Ok(None)` short-circuit.
    let auth = match crate::context::economy_helpers::authorize_paid_action_prepare(
        &*cell,
        deps,
        scp_protocol::economy::types::PaidActionType::ContextJoin,
        &member_did,
    ) {
        None => None,
        Some(inputs) => match crate::context::economy_helpers::authorize_paid_action_hold(
            inputs,
            &member_did,
            &context_id,
        )
        .await
        {
            Ok(auth) => auth,
            Err(payment_err) => {
                // Keep-direction (ADR-049 §9): persist the burned nonce fail-closed
                // before the existing Class-C reversal. Both the nonce-commit and
                // the ticket rollback go through `&*cell` / a `class_c_view()` (no
                // `state_mut()`); the view inside `rollback_join_economy_ticket`
                // drops before the return.
                let err = crate::context::messaging_helpers::commit_send_nonce_token_on_abort(
                    spending_nonce_token.take(),
                    &*cell,
                    deps,
                    &context_id,
                    payment_err,
                )
                .await;
                rollback_join_economy_ticket(cell, ticket);
                return Err(err);
            }
        },
    };

    // Phase 3: MLS add_member + sender-key distribution (crypto mutations).
    // ADR-049 PR-7 (SCP-CRYPTOMOVE-001) STEP-C C2 JOIN seam: after the CREATE
    // seam the actor OWNS this context's crypto (`take_crypto_state`), so the
    // provider's `add_member` / `distribute_sender_key` now fail closed
    // ("owned by actor"). Route the WHOLE join crypto cluster through the actor's
    // OWNED `ContextCryptoState` instead (one-way take preserved — no crypto is
    // ever handed back to the provider). Member ADD advances the MLS epoch, which
    // is §9 Class-S (consistent with the `advance_epoch` / `rotate_sender_key`
    // rulings) and is reachable only through `rest_mut()` (the `PerContextState`
    // crypto methods hold no field-granular Class-C view), so the add + the
    // sender-key distribution are sync-persisted fail-closed via
    // `commit_class_s_keep`. `local_did` is node-resident (read off the provider,
    // which retains it as a birth-seam).
    let local_did = deps.crypto.local_did().to_owned();

    // add_member — Class-S. On failure NO MLS rollback is needed (the add itself
    // failed, so no member was added), matching the prior provider disposition.
    let add_output = match cell
        .commit_class_s_keep(deps, &context_id, |mut v| {
            v.rest_mut()
                .add_member(&member_did, kp_bytes, deps.clock.as_ref())
        })
        .await
    {
        Ok(output) => output,
        Err(e) => {
            // Keep-direction (ADR-049 §9): persist the burned nonce fail-closed
            // before the existing escrow-void + ticket rollback. Nonce-commit +
            // escrow-void run through `&*cell` (shared, no mutation); the ticket
            // rollback opens a `class_c_view()` that drops before the return.
            let err = crate::context::messaging_helpers::commit_send_nonce_token_on_abort(
                spending_nonce_token.take(),
                &*cell,
                deps,
                &context_id,
                e,
            )
            .await;
            if let Some(a) = auth {
                crate::context::economy_helpers::void_paid_action(deps, a, &context_id).await;
            }
            rollback_join_economy_ticket(cell, ticket);
            return Err(err);
        }
    };

    // distribute_sender_key — Class-S. On failure roll back the just-added member
    // on the ACTOR (best-effort MLS remove + sender-key prune) + the registry
    // floor, then the nonce/escrow/ticket rollback.
    if let Err(e) = cell
        .commit_class_s_keep(deps, &context_id, |mut v| {
            v.rest_mut().distribute_sender_key(&local_did, &member_did)
        })
        .await
    {
        // Sender-key distribution failed after MLS add — roll back the MLS state
        // on the actor's owned crypto (§9 Class-S, fail-closed persist).
        let _ = cell
            .commit_class_s_keep(deps, &context_id, |mut v| {
                let s = v.rest_mut();
                let _ = s.remove_member(&local_did, &member_did);
                s.remove_member_sender_key(&member_did)
            })
            .await;
        // ADR-049 PR-6: prune the departed member's Class-M registry floors
        // (member-granular; siblings + the local scalar retained).
        deps.supervisor
            .remove_member_floors(&context_id_bytes, &member_did);
        // Keep-direction (ADR-049 §9): persist the burned nonce fail-closed
        // before the existing escrow-void + ticket rollback.
        let err = crate::context::messaging_helpers::commit_send_nonce_token_on_abort(
            spending_nonce_token.take(),
            &*cell,
            deps,
            &context_id,
            e,
        )
        .await;
        if let Some(a) = auth {
            crate::context::economy_helpers::void_paid_action(deps, a, &context_id).await;
        }
        rollback_join_economy_ticket(cell, ticket);
        return Err(err);
    }

    // Drain pending HPKE-sealed sender-key distribution messages and deliver them
    // via the MLS management channel (§9.16.2). MLS-wrap is mandatory — see
    // comment on `drain_and_deliver_sender_keys`. ADR-049 PR-7: the producer is
    // now the ACTOR `distribute_sender_key` above (actor-owned queue), so drain
    // the ACTOR queue via the Class-C crypto view (`Some(..)`). The view is scoped
    // so it drops before any rollback below re-borrows `cell`.
    let drain_result = {
        let mut view = cell.class_c_view();
        drain_and_deliver_sender_keys(deps, view.mode_mut().crypto_mut(), &context_id).await
    };
    if let Err(e) = drain_result {
        // Drain failed catastrophically — roll back the MLS add on the actor,
        // the sender key, the registry floor, the escrow, and the economy ticket
        // so the join is fully aborted.
        let _ = cell
            .commit_class_s_keep(deps, &context_id, |mut v| {
                let s = v.rest_mut();
                let _ = s.remove_member(&local_did, &member_did);
                s.remove_member_sender_key(&member_did)
            })
            .await;
        // ADR-049 PR-6: prune the departed member's Class-M registry floors
        // (member-granular; siblings + the local scalar retained).
        deps.supervisor
            .remove_member_floors(&context_id_bytes, &member_did);
        // Keep-direction (ADR-049 §9): persist the burned nonce fail-closed
        // before the existing escrow-void + ticket rollback.
        let err = crate::context::messaging_helpers::commit_send_nonce_token_on_abort(
            spending_nonce_token.take(),
            &*cell,
            deps,
            &context_id,
            e,
        )
        .await;
        if let Some(a) = auth {
            crate::context::economy_helpers::void_paid_action(deps, a, &context_id).await;
        }
        rollback_join_economy_ticket(cell, ticket);
        return Err(err);
    }

    // Phase 4: Membership mutation. On failure: void escrow + rollback
    // ticket + rollback MLS state. Routed through `cell.class_c_view()` — the
    // membership / role / access / receive-buffer mutations are all Class-C.
    if let Err(e) = join_context_membership(
        &mut cell.class_c_view(),
        deps,
        &context_id,
        &member_did,
        add_output,
    ) {
        // Roll back the MLS add on the actor's owned crypto (§9 Class-S).
        let _ = cell
            .commit_class_s_keep(deps, &context_id, |mut v| {
                let s = v.rest_mut();
                let _ = s.remove_member(&local_did, &member_did);
                s.remove_member_sender_key(&member_did)
            })
            .await;
        // ADR-049 PR-6: prune the departed member's Class-M registry floors
        // (member-granular; siblings + the local scalar retained).
        deps.supervisor
            .remove_member_floors(&context_id_bytes, &member_did);
        // Keep-direction (ADR-049 §9): persist the burned nonce fail-closed
        // before the existing escrow-void + ticket rollback.
        let err = crate::context::messaging_helpers::commit_send_nonce_token_on_abort(
            spending_nonce_token.take(),
            &*cell,
            deps,
            &context_id,
            e,
        )
        .await;
        if let Some(a) = auth {
            crate::context::economy_helpers::void_paid_action(deps, a, &context_id).await;
        }
        rollback_join_economy_ticket(cell, ticket);
        return Err(err);
    }

    // Phase 4.5: Store local pseudonym after membership mutation succeeds.
    // §9.10.4: `set_local_pseudonym` is a no-op on a broadcast context (which
    // carries no pseudonym state), so this only updates encrypted contexts.
    // Routed through the Class-C routing view; the view drops immediately.
    if let Some(pseudonym) = local_pseudonym {
        cell.class_c_view()
            .routing_mut()
            .set_local_pseudonym(pseudonym);
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
    // Subject-bearing leaf (ADR-011 amendment): carry the joining member
    // (`member_did`, which on a self-join already equals `actor_did`) and the
    // default "member" role, so the leaf shape is uniform with admin-driven
    // adds and the SDK reads `subject_did` consistently. The participation
    // record (§7.3.2) attributes the join interval to this subject. A payload
    // encoding failure is folded into the same `ContextError::EventLogFailed`
    // the append would raise, so the fail-closed nonce/escrow handling below
    // covers it identically.
    //
    // Committer-assigned: the joining member's clock (captured once above as
    // `now_secs`) — the source of the `created_at` on its outgoing join commit.
    // Convergent-by-construction WHEN cross-member leaf replication lands; the
    // receive-side append path is currently dormant, so this leaf is
    // committer-appended-only and is NOT yet replicated to other members.
    // Cross-member convergence is the forward step under ADR-051 (§7.3.1,
    // §9.9.3).
    if let Err(e) = deps
        .event_log
        .append_membership_change_leaf(
            &context_id_bytes,
            scp_event_log::EventType::MemberJoined,
            member_did.as_ref(),
            member_did.as_ref(),
            "member",
            now_secs,
        )
        .await
    {
        // Keep-direction (ADR-049 §9): persist the burned nonce fail-closed
        // before voiding the escrow hold (mirrors the money-ordering rule
        // below). The membership / MLS state already applied is NOT reversed.
        let err = crate::context::messaging_helpers::commit_send_nonce_token_on_abort(
            spending_nonce_token.take(),
            &*cell,
            deps,
            &context_id,
            e,
        )
        .await;
        if let Some(a) = auth {
            crate::context::economy_helpers::void_paid_action(deps, a, &context_id).await;
        }
        return Err(err);
    }
    *cell.class_c_view().checkpoint_events_since_mut() += 1;

    // ADR-049 §9 Class S (BLACK-001): a PAID join consumed a spending-UCAN
    // nonce in Phase 1 (`enforce_join_economy` → `enforce_economy` →
    // `commit_spending_ucan_nonce`, mutating the actor-owned
    // `spending_nonce_tracker`) — the same Class-S monotonic state the
    // message-send and outlet-invoke paths persist fail-closed. A best-effort
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
    // The deferred token is `Some` exactly on the paid (nonce-burning) branch —
    // the same gating the legacy `deducted_cost.is_some() && spending_ucan.is_some()`
    // expressed.
    debug_assert_eq!(
        spending_nonce_token.is_some(),
        deducted_cost.is_some() && spending_ucan.is_some(),
        "spending-nonce token must be Some iff a paid join burned a nonce",
    );
    if let Some(t) = spending_nonce_token.take() {
        // Paid join: commit the deferred token (fail-closed persist, ADR-049 §9
        // keep-direction). On failure release the escrow hold so the joiner is
        // not charged for an unacknowledged join, then surface the error. The
        // consumed nonce stays consumed. `t.commit` + `void_paid_action` take a
        // shared `&PerContextState`, supplied via `&*cell`.
        if let Err(e) = t.commit(&*cell, deps, &context_id).await {
            if let Some(a) = auth {
                crate::context::economy_helpers::void_paid_action(deps, a, &context_id).await;
            }
            return Err(e);
        }
    } else {
        crate::context::messaging_helpers::persist_state_best_effort(&*cell, deps, &context_id)
            .await;
    }

    // Durability has succeeded (or this is a free join): now settle the escrow.
    // `capture_join_payment` takes the cell so its escrow-capture `.await` runs
    // OUTSIDE any view borrow and the receipt is surfaced through a `ClassCMut`.
    capture_join_payment(cell, deps, auth, &member_did, &context_id, deducted_cost).await;

    Ok(())
}

// ---------------------------------------------------------------------------
// 7. join_context_membership (per-context, transitive of join_context)
// ---------------------------------------------------------------------------

/// Performs the membership state mutations for [`join_context`] (Phase 4).
///
/// Takes a [`ClassCMut`](crate::context::actor::class_s::ClassCMut) view rather
/// than `&mut PerContextState`: every mutation here is Class-C (participation
/// cache, role state, membership set, access-key store, receive buffer), so it
/// routes through the field-granular accessors with no whole-state borrow and no
/// `state_mut()`. The §9 fail-closed invariant is unaffected — these are the
/// coalesce-persisted Class-C bookkeeping mutations the run loop flushes.
///
/// # Errors
///
/// - [`ContextError::ContextNotActive`] if the context is no longer
///   Active.
/// - Errors from `roles::system_assign_role` propagated as
///   [`ContextError::MembershipFailed`].
pub fn join_context_membership(
    view: &mut crate::context::actor::class_s::ClassCMut<'_>,
    deps: &ActorDeps,
    context_id: &str,
    member_did: &DID,
    add_output: scp_protocol::context::builder::AddMemberOutput,
) -> Result<(), ContextError> {
    state::require_active(view.handle_mut())?;

    // Participation bookkeeping needs `&mut participation_cache` held alongside
    // `&receive_buffer`. `split_class_c()` hands back both as disjoint borrows at
    // once (the `ConsequenceStateSplit` shape); the split drops before the
    // role / membership / access mutations below re-borrow the view.
    {
        let mut split = view.split_class_c();
        crate::context::lifecycle_logic::post_join_bookkeeping(
            split.governance.participation_cache_mut(),
            split.receive_buffer,
            context_id,
            member_did,
            deps.clock.now_secs(),
            deps.event_log.as_ref(),
        );
    }

    // Add member to role state + assign the default "member" role through the
    // field-granular Class-C role view (ADR-049 §9): structural member insert +
    // the view's `system_assign_role` (which mints + inserts assignments /
    // member_capabilities + runs the SHRINK-only suspension prune over its own
    // disjoint fields). No whole `&mut ContextRoleState`, no downward-auth GROW.
    //
    // H2: `system_assign_role` bypasses the RoleAssign capability check. The join
    // handshake is a self-service flow that already passed economy / sybil /
    // capacity / version gates above — re-checking `RoleAssign` against the creator
    // would silently fail every join after the creator has been demoted out of an
    // admin role. The default "member" role assignment carries no ambient authority
    // (it's the protocol-defined floor), so there is nothing to authorize again.
    let (creator_did, tokens) = {
        let mut rs = view.role_state_class_c_mut();
        rs.members_mut().insert(member_did.to_string());
        let creator_did = rs.creator_did().to_owned();
        let tokens = rs
            .system_assign_role(member_did, "member", &*deps.clock)
            .map_err(|e| ContextError::MembershipFailed(e.to_string()))?;
        (creator_did, tokens)
    };

    // Add to membership tracking.
    view.membership_class_c_mut()
        .add_member(member_did.clone(), "member".into(), tokens);

    // Generate access key for the new member (§9.17.2 step 2).
    // The inviter stores the key so `send_message` can wrap content
    // for this recipient. Key distribution to the joiner happens via
    // the Welcome payload / out-of-band key exchange.
    let member_access_key =
        scp_protocol::crypto::access_keys::generate_access_key(context_id, member_did);
    view.access_mut()
        .access_key_store
        .set(context_id, member_did, member_access_key);

    // Emit MemberJoined event to receive buffer.
    let join_event = ContextEvent::MemberJoined {
        member_did: member_did.clone(),
        role_name: "member".into(),
    };
    state::emit_event_into(
        view.receive_buffer_mut(),
        join_event,
        context_id,
        deps.event_tx.as_ref(),
    );

    // Emit WelcomeGenerated event if the add produced a Welcome message.
    if !add_output.welcome_bytes.is_empty() {
        state::emit_event_into(
            view.receive_buffer_mut(),
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
///
/// ADR-049 §9 Class-S cell seam: takes the `&mut ClassSCell` so the escrow
/// capture+verify `.await` ([`capture_and_verify_paid_action`](crate::context::economy_helpers::capture_and_verify_paid_action)) runs OUTSIDE any
/// view borrow, and the Class-C surfacing of the receipt (or the failure event)
/// is applied afterward through a short-lived `class_c_view()` — no
/// whole-`&mut PerContextState`, no `state_mut()`.
pub async fn capture_join_payment(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    auth: Option<crate::context::economy_logic::PaidActionAuthorization>,
    member_did: &DID,
    context_id: &str,
    deducted_cost: Option<scp_protocol::economy::types::Amount>,
) {
    let Some(a) = auth else { return };
    // Async capture + verify runs with NO state borrow held.
    match crate::context::economy_helpers::capture_and_verify_paid_action(a).await {
        Ok(Some(receipt)) => {
            // Surface the verified receipt through the Class-C view: emit the
            // local `ContextEvent::PaymentReceived`, then record it in the bounded
            // `payment_receipts` ring (ADR-051 §6 / §9.9.3; no durable leaf). The
            // two field `&mut` reborrows are taken one at a time (the view cannot
            // hand out both simultaneously) — sequencing matches the wrapper's
            // emit-then-record order, behaviour-neutral.
            let mut view = cell.class_c_view();
            crate::context::economy_helpers::emit_payment_received_event(
                view.receive_buffer_mut(),
                deps,
                &receipt,
                context_id,
            );
            crate::context::economy_helpers::record_payment_receipt(
                view.payment_receipts_mut(),
                &receipt,
            );
        }
        Ok(None) => {}
        Err(e) => {
            // H8: do NOT rollback budget — service was delivered (member joined).
            tracing::warn!(
                context_id,
                "payment capture failed after successful join: {e}"
            );
            // H19: surface the capture failure as a local `ContextEvent` (no
            // durable Merkle leaf — per-payee, non-convergent; ADR-051 §6 /
            // phase-2.md §2). Routed through the receive-buffer view.
            record_payment_capture_failure(
                cell.class_c_view().receive_buffer_mut(),
                deps,
                context_id,
                "join_context",
                member_did,
                &e.to_string(),
                deducted_cost,
            );
        }
    }
}

/// Surface a `PaymentCaptureFailed` as a local `ContextEvent` (receive-buffer
/// push + `event_tx` notification). Actor-shape inline replacement for
/// `manager_methods::record_payment_capture_failure`.
///
/// Per ADR-051 §6 / the phase-2.md ADR-011 amendment exclusion taxonomy §2, the
/// payment receipts (`PaymentReceived` / `PaymentCaptureFailed`) are per-payee,
/// non-convergent events appended by their payee alone — they are excluded from
/// the canonical Merkle log so two honest members derive the same
/// `event_log_merkle_root` (§9.9.3). The former durable
/// `EventType::PaymentCaptureFailed` append (and its `checkpoint_events_since`
/// increment) is removed; the `ContextEvent::PaymentCaptureFailed` emission
/// below is the sole surfacing of a capture failure.
#[allow(clippy::too_many_arguments)]
fn record_payment_capture_failure(
    receive_buffer: &mut ReceiveBuffer,
    deps: &ActorDeps,
    context_id: &str,
    action: &str,
    actor_did: &DID,
    error_msg: &str,
    cost: Option<scp_protocol::economy::types::Amount>,
) {
    let event = ContextEvent::PaymentCaptureFailed {
        action: action.to_owned(),
        actor_did: actor_did.clone(),
        error: error_msg.to_owned(),
        cost: cost.map(scp_protocol::economy::types::Amount::value),
    };
    state::emit_event_into(receive_buffer, event, context_id, deps.event_tx.as_ref());
}

/// Reverses a Phase-1 [`EconomyTicket`](crate::context::economy_logic::EconomyTicket)
/// for [`join_context`] through a `class_c_view()` borrow that drops before the
/// caller's early return (so the cell is free for the subsequent `.await`s).
///
/// Thin cell-holder wrapper over the shared
/// [`crate::context::economy_logic::rollback_economy_ticket_inline_view`] (also
/// driven by the send path): the velocity entry, hard-rate-limit token, and
/// budget debit are all Class-C, so they reverse through the field-granular
/// `GovernanceClassCMut` accessors with no whole-state borrow. Consumes the
/// ticket so its `Drop` guard stays quiet.
fn rollback_join_economy_ticket(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    ticket: crate::context::economy_logic::EconomyTicket,
) {
    // Shared with the send path: reverse the three Class-C governance fields
    // through the field-granular `GovernanceClassCMut` view. The `&mut view`
    // borrow drops before the caller's early return (so the cell is free for the
    // subsequent `.await`s).
    crate::context::economy_logic::rollback_economy_ticket_inline_view(
        cell.class_c_view().governance_class_c_mut(),
        ticket,
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
    // Creator assigns the ContextCreated leaf timestamp from its own clock.
    // This is the convergent-by-construction value WHEN cross-member leaf
    // replication lands (every member would copy it); the receive-side append
    // path is currently dormant, so the leaf is committer-appended-only —
    // cross-member convergence is the forward step under ADR-051 (§7.3.1,
    // §9.9.3). Independently of replication, the same value is stored on
    // `PerContextState::creation_timestamp_secs` below and used LOCALLY by
    // every member as the base for the TTL expiry deadline
    // (= creation + params.ttl), which IS computed identically on each member.
    let creation_timestamp_secs = deps.clock.now_secs();
    let (handle, created_owned_crypto) = crate::context::builder::create_context(
        context_id.clone(),
        params.clone(),
        deps.crypto.as_ref(),
        deps.transport.as_ref(),
        deps.event_log.as_ref(),
        creator_did.as_ref(),
        creation_timestamp_secs,
    )
    .await?;
    let ceiling = CapabilityCeiling::new(params.ceiling.iter().cloned());
    // `ContextRoleState::new` enforces the ceiling-entry grammar (spec §5.3.1.1):
    // a malformed entry fails here with `InvalidCeilingCategory`, preserved as a
    // typed error so the bridges surface the protocol error verbatim rather than
    // a flattened string.
    let role_state =
        ContextRoleState::new(&context_id, &*creator_did, ceiling, vec![], &*deps.clock).map_err(
            |e| match e {
                scp_protocol::context::roles::RoleError::InvalidCeilingCategory(inner) => {
                    ContextCreationError::InvalidCeilingCategory(inner)
                }
                other => ContextCreationError::CreationFailed(other.to_string()),
            },
        )?;
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
    let initial_access_key_store = generate_initial_access_key_store(&context_id, &creator_did);
    let initial_members: HashSet<DID> = membership.members().map(|m| m.did.clone()).collect();
    // ADR-049 §Decision 1: branch the actor's mode-discriminated union on
    // whether the supervisor returned a broadcast roster — the SCP-227
    // broadcast init path returns `Some(BroadcastContext)` iff
    // `params.mode == ContextMode::Broadcast`.
    //
    // ADR-056: `PerContextState.context_id` is the canonical 32-byte DIGEST.
    // For a real context id (`hex(digest)`) DECODE recovers the digest — it
    // does NOT re-hash the already-hex-encoded digest. This is what the
    // §6.2.4 cross-context outlet saga compares `target_context_id` against on
    // the wire, and the bytes the creation crypto (builder) keys under.
    let context_id_bytes = state::context_id_to_bytes(&context_id);
    // ADR-049 PR-4 §5: create-seed the supervisor floor registry so a
    // default-empty entry exists from creation (it then grows via
    // mirror-forward). Insert-if-absent — never resets an advanced entry.
    deps.supervisor.seed_context_floors(&context_id_bytes);
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
    let mut per_context = PerContextState {
        context_id: context_id_bytes,
        created_at: deps.clock.now_secs(),
        // Convergent creator-assigned creation time — the same value stamped on
        // the ContextCreated leaf above. Base for the convergent TTL deadline.
        creation_timestamp_secs,
        generation: 0, // assigned by SupervisorHandle::insert_context.
        handle: handle.clone(),
        membership,
        members: actor_members,
        // Shared fresh-context governance bucket (create + spawn-from-Welcome
        // build the identical set — see `state::fresh_governance_state`).
        governance: crate::context::state::fresh_governance_state(
            governance_engine,
            &params,
            initial_members,
            &context_id,
            Arc::clone(&deps.clock),
        ),
        role_state,
        receive_buffer: ReceiveBuffer::new(),
        payment_receipts: VecDeque::new(),
        broadcast_context,
        migration_state: None,
        epoch: EpochState {
            mls_epoch: 0,
            coordinator: EpochCoordinator::new(),
            // Native runtime injects the production SystemClock (ADR-057 §Prereq-2).
            grace_store: scp_mls::epoch_grace::EpochGraceStore::with_clock(std::sync::Arc::new(
                scp_clock::SystemClock,
            )),
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
        // §9.10.4: pseudonym routing axis. Encrypted contexts carry the
        // member's pseudonym + an empty peer registry; broadcast contexts
        // carry no pseudonym state.
        routing: create_routing,
        // ADR-049 commit 8: fresh actor-shape tracker at creation.
        send_tracker: SendSequenceTracker::new(),
        // ADR-049 Phase 2A finalization keystone (ADR-049 §15 phase 2A
        // finalization — type unification): the actor-owned state fields
        // start in their fresh-instance shapes. `event_log` is `None`
        // until the first event lands; the in-memory RFC-6962 Merkle
        // tree above is the proof-generation surface and is populated
        // lazily by the messaging handler.
        recv_tracker: RecvSequenceTracker::new(),
        // B-owned cross-context outlet-invoke validation state (spec §6.2.4):
        // fresh on creation/import; repopulated when a gated outlet interface is
        // established. Not rehydrated from any snapshot — reconstructable
        // interface state, never authorization secrecy.
        xctx_ucan_proofs: scp_protocol::crypto::ucan::validate::InMemoryProofResolver::new(),
        class_s: crate::context::actor::state::ClassSState {
            saga_pending: HashMap::new(),
            xctx_committed_outputs: HashMap::new(),
            xctx_committed_stream_outputs: HashMap::new(),
            xctx_committed_invocations: std::collections::HashSet::new(),
            // Caller-side cross-context reservation reversal records (spec §6.2.4):
            // fresh on create; cross-node import DROPS them (caller economy is
            // local — a foreign saga must never drive local reversal).
            xctx_caller_reservations: std::collections::HashMap::new(),
            xctx_nonce_dedup: scp_protocol::crypto::sender_keys::NonceDedup::with_ttl(
                crate::context::actor::handlers::saga::SAGA_NONCE_DEDUP_TTL_SECS,
            ),
            // §7.3.8 value-caveat counters: fresh on create.
            caveat_counters: HashMap::new(),
            // Fix-D streaming reservation recovery records: fresh on create.
            stream_reservations: HashMap::new(),
        },
        pending_broadcast_publishes: HashMap::new(),
        welcome_scratchpad: None,
        lifecycle_state: ContextLifecycleState::Open,
        event_log: None,
        mode,
    };

    // #2148 (ADR-049 birth-into-actor) CREATE seam: `builder::create_context`
    // above BIRTHS the MLS group + local sender key as OWNED material (Encrypted
    // mode only) and RETURNS it — no provider map is touched, so there is no
    // insert-then-`take_crypto_state` round-trip and no cross-map check-then-insert
    // to race (#2167 TOCTOU is impossible by construction). Deleting the provider's
    // `contexts`/`taken_context_ids` maps removes ONE redundant guard; it does NOT
    // make the registry write-lock insert the sole double-birth authority. The
    // durable double-birth / divergence authority is the global `bootstrap_spawn_lock`
    // (serializes all births node-wide) together with the supervisor's Precheck A
    // (live-actor) + Precheck D (durable first-writer-wins), which run UNDER that
    // lock; the registry write-lock insert at spawn guards only the in-memory
    // registry slot. SEED the owned crypto onto the actor's `PerContextState`
    // BEFORE the actor spawns — structurally
    // identical to the restore seam, leaving NO window where a live actor holds an
    // empty group. The send-sequence counter starts fresh at 0 for a newly-born
    // group (`OwnedMlsCryptoState::send_sequence == 0`), which `from_persisted`
    // inside `seed_encrypted_crypto_from_owned` installs. Broadcast contexts carry
    // `None` (the builder births no MLS group; the actor's `BroadcastState`, seeded
    // by `init_broadcast_context` above, is the authoritative broadcast-key home),
    // so nothing is seeded and the `Broadcast` mode stands. The two are exactly
    // anti-correlated (Encrypted ⇔ `Some` ⇔ `!create_is_broadcast`).
    debug_assert_eq!(
        created_owned_crypto.is_some(),
        !create_is_broadcast,
        "owned crypto is present iff the context is Encrypted (non-broadcast)"
    );
    if let Some(owned) = created_owned_crypto {
        per_context.seed_encrypted_crypto_from_owned(owned);
    }

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
/// registers through the actor-native replacement gate
/// [`SupervisorHandle::dispatch_prepare_for_replace`](crate::context::supervisor::handle::SupervisorHandle::dispatch_prepare_for_replace)
/// followed by
/// [`SupervisorHandle::spawn_actor_with_state`](crate::context::supervisor::handle::SupervisorHandle::spawn_actor_with_state).
/// Every surface
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
    // The governance-timeout interval is ACTOR-OWNED (ADR-049 Decision-1 /
    // finding A3): the freshly-spawned actor's `reconcile_timers` arms a
    // 60 s interval while the context is `Active` — no bootstrap mailbox
    // install is needed.
    deps.supervisor
        .persist_context_and_broadcast(context_id)
        .await;
    if ttl_duration.is_some() {
        // Install the TTL timer by mailboxing StartTtlTimer to the
        // freshly-spawned actor: the actor owns `state.ttl.timer` and
        // installs the timer task on its own state (registry + mailbox
        // tick — no DashMap reach).
        deps.supervisor
            // Create path: no explicit deadline — the actor handler derives the
            // convergent `creation_timestamp_secs + params.ttl` deadline.
            .dispatch_start_ttl_timer(context_id, handle.params().clone(), None)
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
/// import / respawn / restore. Tears down the old transient crypto, restores the
/// incoming `mls_state` (if any) — recovering the Class-M floors it carried —
/// then merges those floors INTO the authoritative Supervisor-owned Class-M
/// registry (ADR-049 PR-6). Rolls the restored crypto back on a rejected merge
/// so no half-restored or floor-regressed state persists. EVERY import
/// crypto-restore site — the actor-side `PrepareForReplace` handler AND the
/// supervisor-side fresh / stale-handle branches of `import_context` — routes
/// through here so the replay (floor-regression) guard cannot be bypassed.
///
/// The registry is the authoritative live floor home and is NOT torn down here,
/// so there is no pre-teardown "capture" step: the snapshot floors are the merge
/// INPUT (`incoming`) and the live registry floors are the merge target. The
/// registry merge guards on `incoming.is_empty()` (NOT the live floors), so a
/// COLD restart (empty live registry, non-empty snapshot) still POPULATES the
/// registry — closing the cold-restart replay window (D2).
///
/// # Errors
///
/// `trusted_local` selects the spec §23.17.2 merge semantics:
///
/// - `true` — restoring the node's OWN snapshot (Invariant 2): crash recovery,
///   actor respawn (`Supervisor::respawn_from_snapshot`), process restart
///   (`restore_all_contexts`). A lower restored floor is the expected
///   coalesce-lag case and is MAX-merged with the live registry floor; the
///   restore PROCEEDS (never rejected for a regression). Only an overshoot
///   beyond `MAX_EPOCH_ADVANCE` (corrupt/garbage snapshot) is rejected.
/// - `false` — importing an UNTRUSTED peer snapshot (Invariant 3): any
///   per-sender floor regression is rejected (snapshot-mediated replay guard).
///
/// Returns `Ok(Some(owned))` with the rebuilt OWNED crypto material for the
/// caller to seed onto a `PerContextState` (`import_context`), or `Ok(None)`
/// when the snapshot carried no MLS group (keyless / needs-reconnect). A
/// terminating caller (`PrepareForReplace`) drops the returned owned material —
/// it still runs the floor gate below but seeds nothing (ADR-049 PR-7 C3
/// seed-vs-terminal resolution).
///
/// `trusted_local` selects the spec §23.17.2 merge semantics:
///
/// - `true` — restoring the node's OWN snapshot (Invariant 2): crash recovery,
///   actor respawn, process restart. A lower restored floor is the expected
///   coalesce-lag case and is MAX-merged; the restore PROCEEDS (never rejected
///   for a regression). Only an overshoot beyond `MAX_EPOCH_ADVANCE` is rejected.
/// - `false` — importing an UNTRUSTED peer snapshot (Invariant 3): any per-sender
///   floor regression is rejected (snapshot-mediated replay guard).
///
/// # Errors
///
/// Returns `ContextError::PersistenceFailed` if the crypto rebuild fails, or
/// `ContextError::CryptoFailed` (from `From<FloorAdvanceError>`, the §23.17
/// replay-protection rejection the registry's `validate_and_merge_*` sink
/// returns) if a per-sender floor regresses (import path) or overshoots (both
/// paths); the just-built owned crypto is dropped on rejection (the `SenderKey`
/// zeroizes; the `ScpMlsGroup` / Ed25519 signer is freed, not zeroized - #82) and
/// the registry is left unchanged (atomic).
pub(in crate::context) fn restore_crypto_state_with_floor_guard(
    deps: &ActorDeps,
    ctx_id_bytes: &[u8; 32],
    mls_state: &[u8],
    trusted_local: bool,
) -> Result<Option<crate::crypto::mls::provider::OwnedMlsCryptoState>, ContextError> {
    // ADR-049 PR-6 (read-authority switch): the AUTHORITATIVE Class-M floors
    // live in the Supervisor-owned registry, which is NOT torn down by a
    // mailbox/handle despawn or a crypto restore. So there is no pre-teardown
    // "live capture" to take — the live floors are ALREADY in the registry and
    // are the max-merge target.
    //
    // #2148 (ADR-049 birth-into-actor): the crypto is ACTOR-owned end to end —
    // the provider holds NO per-context state at all (its `contexts` map and the
    // `destroy_mls_group` / `destroy_sender_key` teardown methods are DELETED).
    // This helper builds the restored crypto as OWNED material via
    // `build_restored_owned` (which touches no provider map) and RETURNS it for
    // the caller to seed (`import_context`) or drop (`PrepareForReplace`,
    // terminal). There is no stale provider-resident crypto to tear down first —
    // by construction no provider residency can exist.

    // Build the restored transient crypto as OWNED material (MLS group +
    // sender-key MATERIAL) and recover the Class-M floors the snapshot carried —
    // including the legacy back-compat lower bound — as the merge INPUT
    // (`incoming`). An empty `mls_state` yields no owned crypto and empty floors
    // (cold path / keyless needs-reconnect snapshot).
    let (owned, restored) = if mls_state.is_empty() {
        (
            None,
            crate::crypto::mls::provider::RestoredFloors::default(),
        )
    } else {
        let (owned, floors) = deps
            .crypto
            .build_restored_owned(ctx_id_bytes, mls_state)
            .map_err(|e| {
                ContextError::PersistenceFailed(format!("import: crypto state restore failed: {e}"))
            })?;
        (Some(owned), floors)
    };

    // Map the restore's `trusted_local` bool to the registry merge's §23.17.2
    // `MergePolicy` (identical mapping to the deleted provider twin): a
    // trusted-local respawn max-merges and tolerates the coalesce-lag regression
    // (Inv-2); an untrusted import rejects any regression (Inv-3). BOTH enforce
    // the epoch-poisoning overshoot ceiling.
    let policy = if trusted_local {
        scp_protocol::crypto::sender_keys::MergePolicy::MaxMergeTrustedLocal
    } else {
        scp_protocol::crypto::sender_keys::MergePolicy::RejectRegression
    };

    // THE D2 sink: merge the snapshot floors (`incoming`) INTO the authoritative
    // registry (`local` = the live, non-torn-down registry). ONE cross-axis
    // validating merge — BOTH the epoch AND the recv-sequence floors are validated
    // before EITHER is applied, so a rejection on either axis leaves the WHOLE
    // registry entry UNCHANGED (cross-axis atomicity; a prior sequential
    // two-merge form could commit the epoch axis then reject the recv axis with no
    // rollback). The merge guards on `incoming.is_empty()` — NOT on the live
    // floors — so on a COLD restart (empty live registry, NON-empty snapshot) it
    // RUNS and POPULATES the registry, closing D2. FAIL-CLOSED via `.map_err(..)?`
    // (rollback-on-Err), NOT log-and-drop. `From<FloorAdvanceError>` maps a
    // rejection to `ContextError::CryptoFailed`.
    //
    // Rollback: on rejection the just-built `owned` material is dropped at the `?`
    // return (the `SenderKey` zeroizes; the `ScpMlsGroup` / signer is freed, not
    // zeroized - #82) so no floor-regressed / half-restored state persists (BUG-1
    // atomicity). The registry itself is left UNCHANGED (validate-before-apply,
    // across both axes). Fail-closed by construction: a rejected restore is never
    // seeded onto an actor and writes no durable snapshot, so it cannot resurrect a
    // divergent second group for this id (there is no provider `taken_context_ids`
    // marker; #2148 deleted it, and `build_restored_owned` sets none).
    deps.supervisor
        .validate_and_merge_all_floors(
            ctx_id_bytes,
            restored.sender_epochs,
            restored.recv_sequence,
            scp_protocol::crypto::sender_keys::MAX_EPOCH_ADVANCE,
            policy,
        )
        .map_err(ContextError::from)?;

    Ok(owned)
}

/// Verifies a joined or rehydrated MLS group's committed `scp_context_params`
/// (`0xFF02`) group-context extension against the context's declared identity
/// and parameters (spec §5.13.3, finding FFI-02).
///
/// This is the single binding check shared by every point where an SCP context
/// group enters the live provider from a *caller-supplied* description of its
/// parameters:
///
/// - **join** (`Supervisor::spawn_actor_from_welcome`) — the joiner reads the
///   just-joined group's extension (before install) and verifies it against the
///   `WelcomeJoinRequest.params` the (untrusted) inviter supplied;
/// - **import** (`import_context`) and **restore / respawn** (`restore_context`)
///   — the layer reads the *rehydrated* group's extension and verifies it
///   against the snapshot's `context_params`.
///
/// It enforces validation **rule 1** (every SCP context group MUST carry the
/// `0xFF02` extension) plus **rules 2–6** (`context_id`, governance / ceiling
/// hashes, ceiling policy, mode, parent structure) and **rule 8** (the committed
/// genesis `creator_did` MUST equal the presented `creator_did`) via
/// [`ScpContextExtension::verify_against`](scp_protocol::context::ScpContextExtension::verify_against).
/// The extension is folded into the MLS key schedule at group creation, so it
/// is the group's cryptographic attestation of its own parameters: a malicious
/// inviter (or a forged / internally-inconsistent snapshot) that presents
/// benign `params` while the real group commits divergent
/// governance / ceiling / mode / `context_id` is refused here, *before* any
/// authority (governance engine, ceiling, admin set) is built from those
/// params.
///
/// `creator_did` is the genesis creator/admin the caller presents — the
/// (untrusted) bundle's `creator_did` on a Welcome-based join, or the snapshot's
/// `role_state.creator_did` on import/restore. Rule 8 refuses the group unless
/// it equals the `creator_did` the group cryptographically committed at
/// creation, so no authority is ever built for a substituted admin (the sole
/// anchor for DID-less governance models such as `SingleAdmin`).
///
/// `read` is the group-context-extension read outcome: `Ok(Some(ext))` =
/// present, `Ok(None)` = absent (a rule-1 violation — not an SCP context),
/// `Err(msg)` = the group is unreadable / the `0xFF02` payload is malformed.
/// On rejection the returned reason is prefixed with `site` so each caller can
/// wrap it in its site-idiomatic [`ContextError`] variant while sharing this
/// one check. Returns `Ok(())` only when the extension is present AND every
/// binding rule holds.
pub(in crate::context) fn verify_scp_context_binding(
    read: Result<Option<scp_protocol::context::ScpContextExtension>, String>,
    context_id: &str,
    creator_did: &str,
    params: &scp_protocol::context::ContextParams,
    site: &str,
) -> Result<(), String> {
    match read {
        Ok(Some(ext)) => ext
            .verify_against(
                &context_id.to_owned(),
                &scp_did::DID::from(creator_did.to_owned()),
                params,
            )
            .map_err(|e| {
                format!(
                    "{site} refused: scp_context_params (0xFF02) binding mismatch \
                     (§5.13.3 rules 2-6, 8): {e}"
                )
            }),
        Ok(None) => Err(format!(
            "{site} refused: the MLS group carries no scp_context_params (0xFF02) \
             group-context extension — not an SCP context (§5.13.3 rule 1)"
        )),
        Err(e) => Err(format!(
            "{site} refused: scp_context_params (0xFF02) group-context extension \
             unreadable (§5.13.3): {e}"
        )),
    }
}

/// Imports a previously exported context.
///
/// Validates the export, performs the C3 per-instance wipe policy,
/// restores crypto state with the epoch-floor regression guard
/// ([`restore_crypto_state_with_floor_guard`]), builds a fresh
/// `PerContextState` from the snapshot, and spawns an owned-state actor.
/// Re-spawns the TTL timer if the context carries a finite `params.ttl`,
/// re-arming the absolute convergent `ttl_deadline_secs` (or its
/// `creation + ttl` fallback).
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

    // SINGLE-SOURCE TTL-DEADLINE (ADR-049 §9, E3): reject a future-dated
    // `creation_timestamp_secs` BEFORE any side effect. The create base is the
    // prune-immune `creation_timestamp_secs + params.ttl` from the creator-signed
    // snapshot. `creation_timestamp_secs` is authenticated (the export signature +
    // `exporter_did == creator_did` binding were verified in
    // `validate_export_for_import` above), but a MALICIOUS creator can still
    // future-date their OWN creation instant to smuggle a long absolute
    // key-destruction deadline (`future + ttl`). A future-dated creation is
    // malformed — REJECT the import fail-closed HERE, at the very top, so the
    // rejection is genuinely SIDE-EFFECT-FREE: it must run BEFORE
    // `restore_crypto_state_with_floor_guard` (which installs an MLS group AND
    // sets the §23.17 replay floor from the future-dated snapshot epoch) and
    // BEFORE `import_event_log_data` (which persists the foreign log). Rejecting
    // AFTER those would orphan a resident MLS group + a persisted foreign log with
    // no teardown, and — worse — the replay floor already pinned from the
    // future-dated epoch could floor-reject a later LEGITIMATE import/restore of
    // the same context_id (griefing/DoS). This check only reads the (already
    // signature-validated) `creation_timestamp_secs` and the local clock, both
    // available immediately. A small clock-skew tolerance mirrors the anti-spam
    // snapshot validators below so a benignly-ahead exporter clock is not
    // rejected. (Forged `TtlExtended` EXTENSION leaves beyond consent remain the
    // creator-trust boundary cross-member convergence catches — the
    // import-legibility follow-up, #2102.)
    {
        let now_for_future_date_gate = deps.clock.now_secs();
        if export.snapshot.creation_timestamp_secs
            > now_for_future_date_gate
                .saturating_add(scp_protocol::economy::antispam::SNAPSHOT_CLOCK_SKEW_TOLERANCE_SECS)
        {
            return Err(ContextError::PersistenceFailed(format!(
                "import: creation_timestamp_secs {} is future-dated beyond import time {} \
                 (+{}s skew tolerance) — refusing a malformed export that could smuggle a \
                 long TTL key-destruction deadline (ADR-049 §9)",
                export.snapshot.creation_timestamp_secs,
                now_for_future_date_gate,
                scp_protocol::economy::antispam::SNAPSHOT_CLOCK_SKEW_TOLERANCE_SECS,
            )));
        }
    }

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

    // Ceiling-entry grammar enforcement on the IMPORTED ceiling (spec §5.3.1.1).
    // The imported `role_state` is taken from a signed snapshot produced by an
    // UNTRUSTED, possibly non-conformant peer. A valid signature authenticates the
    // ORIGIN, not the WELL-FORMEDNESS of the payload, so a non-conformant peer's
    // signed export could carry a malformed ceiling.
    //
    // Defense layering: well-formedness is primarily a TYPE-LEVEL invariant —
    // `CapabilityCeiling` has a validating `Deserialize` (`#[serde(try_from)]`),
    // so a malformed ceiling fails to even materialize when an export is decoded
    // FROM BYTES (`deserialize_export` / `rmp_serde::from_slice`). This explicit
    // re-validation is the belt-and-suspenders guard for the IN-MEMORY entry
    // point: `Supervisor::import_context` accepts an already-deserialized
    // `ContextExport` value (no serde at that boundary), so a programmatically
    // constructed export reaches here without crossing the validating
    // `Deserialize`. We re-validate and reject a malformed ceiling rather than
    // letting it poison a conformant importer's stored ceiling. (The snapshot
    // bypasses `ContextRoleState::new`, building `PerContextState` directly below.)
    export
        .snapshot
        .role_state
        .ceiling()
        .validate_entries()
        .map_err(|e| ContextError::ImportRejected {
            reason: format!("imported context ceiling has a malformed entry (spec §5.3.1.1): {e}"),
        })?;

    // §9.10.4: the import path is encrypted-only. Every imported context is
    // re-homed with `broadcast_context: None`, `mode = Encrypted`, and a
    // pseudonymous routing axis (see the `import_routing` construction below).
    // A broadcast-mode export has no per-member pseudonym (spec §5.14) and
    // cannot be re-homed as encrypted without silently fabricating routing
    // state, so reject it loudly with the canonical SCP-CTX-2092 envelope
    // rather than accepting it and degrading the routing axis. All three bridges
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
    // ADR-056: resolve the imported (64-hex) id to its canonical digest so the
    // import-path crypto cleanup keys under the same bytes the context's live
    // `PerContextState.context_id` will hold (set below via the same resolver).
    let ctx_id_bytes = state::context_id_to_bytes(&context_id);

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
        // importer-restored state lives in the signed preimage), never from an
        // unsigned envelope blob. Validated by `validate_export_for_import` above.
        // `PrepareForReplace` runs the §23.17 epoch-floor validate/merge GATE
        // inside the prior actor (rejecting a floor-regressed replay BEFORE the
        // actor claims itself terminal — a replayed import must never terminate a
        // context). ADR-049 PR-7 (SCP-CRYPTOMOVE-001) C3 seed-vs-terminal: that
        // TERMINATING actor seeds NO crypto onto itself (it is exiting); the
        // unified owned-crypto restore + seed below is done by THIS import flow
        // onto the fresh `PerContextState`.
        match deps
            .supervisor
            .dispatch_prepare_for_replace(&context_id, export.snapshot.mls_crypto_state.clone())
            .await
        {
            Ok(()) => {
                // Prior actor ran the floor gate and claimed itself terminal;
                // remove its dead handle so the respawn slot is vacant.
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
                // Slot vacant — fall through to the unified restore below.
            }
            Err(other) => return Err(other),
        }
    }

    // ADR-049 PR-7 (SCP-CRYPTOMOVE-001) C3 fold: rebuild the imported MLS crypto
    // as OWNED material (NO provider insert) and run the §23.17 replay-floor gate.
    // This is the SINGLE import-side restore for every branch above (a fresh
    // import, or a prior actor that was gated + despawned). IMPORT path: untrusted
    // peer snapshot → Invariant 3 (reject-on-regression), `trusted_local = false`.
    // An empty (keyless / needs-reconnect) snapshot yields `None` — no group is
    // seeded until a reconnect Welcome arrives. The owned group is bound-verified
    // just below and seeded onto the fresh `PerContextState` at "6b" further down.
    let imported_owned = restore_crypto_state_with_floor_guard(
        deps,
        &ctx_id_bytes,
        &export.snapshot.mls_crypto_state,
        false,
    )?;

    // §5.13.3 rule 1 (FFI-02, load-time binding). A non-empty restored crypto
    // blob yields OWNED MLS group material (`imported_owned`, ADR-049 PR-7 C3 —
    // no longer provider-resident). Verify that the group's committed
    // `scp_context_params` (`0xFF02`) extension binds the SAME context_id +
    // governance / ceiling / mode the SIGNED snapshot declares, BEFORE the
    // authoritative `PerContextState` (governance engine, ceiling, membership) is
    // built from those snapshot params below. The snapshot signature
    // authenticates the EXPORTER's identity — not the internal consistency of its
    // `context_params` field against the MLS group embedded in `mls_crypto_state`;
    // this closes that gap. A group with no `0xFF02` (not an SCP context) or any
    // rule 2-6 mismatch is rejected as a forged/corrupt import; the owned material
    // is dropped (the `SenderKey` zeroizes; the group / signer is freed, not
    // zeroized - #82) so no forged crypto is ever seeded (mirrors the
    // restore path's own rejection and the Welcome-join pre-install rejection). A
    // keyless (needs-reconnect) snapshot has `None` owned material and no group to
    // bind, so it is skipped — its group arrives later via a reconnect Welcome,
    // which verifies on the join path.
    if let Some(owned) = &imported_owned
        && let Err(reason) = verify_scp_context_binding(
            owned
                .mls_group
                .group_context_extension()
                .map_err(|e| e.to_string()),
            &context_id,
            export.snapshot.role_state.creator_did.as_str(),
            &export.snapshot.context_params,
            "context import",
        )
    {
        // On rejection the `imported_owned` material is dropped here (the
        // `SenderKey` zeroizes; the `ScpMlsGroup` / signer is freed, not zeroized -
        // #82) so no forged crypto is seeded; fail-closed by construction - the
        // rejected crypto is never seeded onto the actor and no durable snapshot is
        // written (there is no longer a provider `taken_context_ids` marker; #2148
        // deleted it). Read the extension from the OWNED group (ADR-049 PR-7 C3 - no
        // longer provider-resident).
        return Err(ContextError::ImportRejected { reason });
    }

    // 3. Import event log data if present.
    if !export.event_log_data.is_empty() {
        deps.event_log
            .import_event_log_data(&ctx_id_bytes, &export.event_log_data)
            .await?;
    }

    // 4. Reconstruct the ContextHandle.
    let handle = ContextHandle::new(context_id.clone(), export.snapshot.context_params.clone());

    // Transition to the state from the snapshot.
    match &export.snapshot.state {
        ContextState::Active => {
            handle.transition_to(&ContextState::Active)?;
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

    // NOTE: the future-dated `creation_timestamp_secs` reject (ADR-049 §9, E3) was
    // hoisted to the TOP of `import_context` (right after
    // `validate_export_for_import`) so it runs BEFORE any crypto/event-log side
    // effect — see that block for the full rationale (F2). It is NOT re-checked
    // here.

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
    // entries with out-of-range rule indices, per the
    // `validate_imported_snapshot` policy.
    let mut sanitized_cooldown_until = export.snapshot.cooldown_until.clone();
    crate::context::lifecycle_logic::sanitize_cooldown_until(
        &mut sanitized_cooldown_until,
        &export.snapshot.consequence_rules,
        now_for_validation,
        "import",
    );

    // SECURITY (§5.3.2, §19.3): re-pin the non-backdatable notification-window
    // floor on the UNTRUSTED import path. `observed_at` is the local
    // commit-processing clock that anchors the mandatory notification window's
    // lower bound (`is_effective` gates on `effective_at.max(observed_at +
    // PERIOD)`). It rides verbatim in the signed export snapshot, so a malicious
    // exporter could backdate BOTH `effective_at` (proposer-controlled) and
    // `observed_at` to collapse the window to zero on import. We therefore
    // re-pin `observed_at` to THIS importing member's local clock, restarting
    // the window from import time (conservative/safe). This is the same
    // re-pinning policy applied to the `cooldown_until` sanitization above.
    //
    // Note `observed_at` does NOT track `creation_timestamp_secs`, which is
    // consumed VERBATIM from the signed snapshot below
    // (`creation_timestamp_secs: export.snapshot.creation_timestamp_secs`): the
    // two have opposite trust models. `creation_timestamp_secs` is the
    // convergent creator-assigned value, authenticated by the snapshot
    // signature and bounded above by the TTL (`creation + ttl`), so backdating
    // only shortens the lifetime — verbatim is the convergent/fail-safe choice.
    // `observed_at`, by contrast, is the LOWER bound of the notification window
    // (`effective_at.max(observed_at + PERIOD)`), where a backdated value would
    // COLLAPSE the window — so it must be re-pinned to a local,
    // non-backdatable clock reading on the untrusted import path. The RESTORE
    // path (trusted self-respawn) keeps `observed_at` verbatim — re-pinning
    // there would let a crash-loop re-arm the window forever.
    let sanitized_pending_ceiling_modification = export
        .snapshot
        .pending_ceiling_modification
        .clone()
        .map(|mut p| {
            p.observed_at = now_for_validation;
            p
        });
    let sanitized_pending_economic_policy_change = export
        .snapshot
        .pending_economic_policy_change
        .clone()
        .map(|mut p| {
            p.observed_at = now_for_validation;
            p
        });

    // ADR-049 Phase 2A finalization keystone: import path is encrypted-only
    // (`broadcast_context: None` below). Derive the actor's `members` set
    // from the imported membership snapshot — `members()` enumerates the
    // current member DIDs in the post-validation `MembershipState`.
    //
    // ADR-056: `PerContextState.context_id` is the canonical 32-byte DIGEST —
    // DECODE the imported (64-hex) id rather than re-hash it, so the restored
    // crypto keys under the same digest the original creation did.
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
    let mut per_context = PerContextState {
        context_id: context_id_bytes,
        created_at: deps.clock.now_secs(),
        // Convergent creator-assigned creation time, consumed VERBATIM from the
        // creator-signed export snapshot (§7.3.1, §9.9.3). The signature and the
        // `exporter_did == creator_did` binding were verified in
        // `validate_export_for_import` before we reach this builder, so the value
        // is authenticated. Pass-4e (ADR-049 §9, E1/E3): this field IS the TTL
        // deadline BASE — `convergent_ttl_deadline` derives the arm from
        // `creation_timestamp_secs + params.ttl` (re-armed below), NOT from the
        // prunable event-log `ContextCreated` leaf. A malicious creator cannot
        // smuggle a long absolute key-destruction deadline via a future-dated
        // base because a future-dated `creation_timestamp_secs` is REJECTED at the
        // top of `import_context` (the E3 future-date gate) — the durable fix that
        // replaced pass-4d's in-memory `min(genesis_ts, import_now)` genesis-leaf
        // clamp (which was reversed on the next restart). There is NO clamp on
        // this path anymore; the reject is the whole guard.
        creation_timestamp_secs: export.snapshot.creation_timestamp_secs,
        generation: 0, // assigned by SupervisorHandle on insert.
        handle: handle.clone(),
        membership: export.snapshot.membership,
        members: actor_members,
        role_state: export.snapshot.role_state,
        receive_buffer: ReceiveBuffer::new(),
        payment_receipts: VecDeque::new(),
        broadcast_context: None,
        migration_state: None,
        governance: GovernanceState {
            engine: governance_engine,
            // C3: Wipe `approved_proposals`. Importing approved-but-not-
            // yet-executed proposals lets a malicious snapshot pre-load
            // forged `RemoveMember` entries.
            // H10: Reset next_proposal_seq as well.
            next_proposal_seq: 0,
            approved_proposals: HashMap::new(),
            freeze: export.snapshot.governance_freeze,
            deadlock: DeadlockDetectionState::default(),
            // SECURITY: `observed_at` re-pinned to local import time (see the
            // sanitization above) so a backdated signed export cannot collapse
            // the §5.3.2 / §19.3 notification window on import.
            pending_ceiling_modification: sanitized_pending_ceiling_modification,
            pending_economic_policy_change: sanitized_pending_economic_policy_change,
            registered_outlets: export.snapshot.registered_outlets,
            outlet_interfaces: export.snapshot.outlet_interfaces,
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
            // Carry the revocation set through import: it is a downward-
            // authorization decision (a revoked spending UCAN must STAY revoked)
            // and it is bound into the SIGNED export preimage, so dropping it
            // would re-admit a token whose revocation the export attests. Unlike
            // the nonce tracker / proposal timestamps (local-instance C3 wipe),
            // a revocation is authorization state that must not regress.
            revoked_spending_ucan_cids: export.snapshot.revoked_spending_ucan_cids,
            // C3: Wipe `proposal_timestamps`.
            proposal_timestamps: HashMap::new(),
            class_s: crate::context::state::GovernanceClassS {
                executed_proposals: {
                    let now = deps.clock.now_secs();
                    export
                        .snapshot
                        .executed_proposals
                        .into_iter()
                        .map(|id| (id, now))
                        .collect()
                },
                threshold_signers: export.snapshot.threshold_signers,
                threshold_value: export.snapshot.threshold_value,
                // IMPORT path (not restore): start with a FRESH spending-
                // nonce tracker.
                spending_nonce_tracker: scp_protocol::crypto::ucan::nonce::NonceTracker::new(
                    context_id.clone(),
                    Arc::clone(&deps.clock),
                ),
            },
        },
        epoch: EpochState {
            mls_epoch: export.snapshot.mls_epoch,
            coordinator: EpochCoordinator::from_records(
                export.snapshot.epoch_coordination_records,
                &context_id,
            ),
            // Native runtime injects the production SystemClock (ADR-057 §Prereq-2).
            grace_store: scp_mls::epoch_grace::EpochGraceStore::with_clock(std::sync::Arc::new(
                scp_clock::SystemClock,
            )),
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
        // B-owned cross-context outlet-invoke validation state (spec §6.2.4):
        // fresh on creation/import; repopulated when a gated outlet interface is
        // established. Not rehydrated from any snapshot — reconstructable
        // interface state, never authorization secrecy.
        xctx_ucan_proofs: scp_protocol::crypto::ucan::validate::InMemoryProofResolver::new(),
        class_s: crate::context::actor::state::ClassSState {
            saga_pending: HashMap::new(),
            xctx_committed_outputs: HashMap::new(),
            xctx_committed_stream_outputs: HashMap::new(),
            xctx_committed_invocations: std::collections::HashSet::new(),
            // Caller-side cross-context reservation reversal records (spec §6.2.4):
            // fresh on create; cross-node import DROPS them (caller economy is
            // local — a foreign saga must never drive local reversal).
            xctx_caller_reservations: std::collections::HashMap::new(),
            xctx_nonce_dedup: scp_protocol::crypto::sender_keys::NonceDedup::with_ttl(
                crate::context::actor::handlers::saga::SAGA_NONCE_DEDUP_TTL_SECS,
            ),
            // §7.3.8 value-caveat counters: fresh on create.
            caveat_counters: HashMap::new(),
            // Fix-D streaming reservation recovery records: fresh on create.
            stream_reservations: HashMap::new(),
        },
        pending_broadcast_publishes: HashMap::new(),
        welcome_scratchpad: None,
        lifecycle_state: ContextLifecycleState::Open,
        event_log: None,
        mode: ContextModeState::Encrypted(Box::<ContextCryptoState>::default()),
    };

    // 6b. ADR-049 PR-7 (SCP-CRYPTOMOVE-001) C3 import seed: SEED the OWNED crypto
    //     material rebuilt + floor-gated + binding-verified above directly onto
    //     the imported actor state before spawn — no provider round-trip, no
    //     `take_crypto_state` (`build_restored_owned` hands the crypto out as
    //     OWNED material and touches no provider map; the double-birth guard is the
    //     supervisor registry's atomic first-writer-wins insert, not a provider
    //     `taken_context_ids` marker - #2148 deleted that map). A keyless /
    //     needs-reconnect snapshot yielded
    //     `None` — nothing to seed; the actor keeps its default-empty encrypted
    //     mode until a reconnect Welcome arrives. (Import is encrypted-only — a
    //     broadcast export is rejected at the top of this function.)
    if let Some(owned) = imported_owned {
        per_context.seed_encrypted_crypto_from_owned(owned);
    }

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

    // Governance timeouts (ADR-031 §5) are ACTOR-OWNED (ADR-049
    // Decision-1 / finding A3): the spawned actor's `reconcile_timers`
    // arms the 60 s interval while `Active` — no bootstrap install needed.

    // 8. Persist if persistence is configured.
    deps.supervisor
        .persist_context_and_broadcast(&context_id)
        .await;

    // 9. Re-arm the TTL timer through the partitioned single-source deadline
    // (ADR-049 §9). The create BASE + PROMOTION come from the PRUNE-IMMUNE,
    // creator-signed snapshot: the base is `export.snapshot.creation_timestamp_secs
    // + params.ttl`, and a promoted import has `params.ttl == None` ⇒ `None` (no
    // arm), disarming a promoted import at the source (H1) — no `memory_scope`
    // gate. `creation_timestamp_secs` is authenticated (the export signature +
    // `exporter_did == creator_did` binding were verified in
    // `validate_export_for_import`) AND is REJECTED above if future-dated beyond
    // import time (E3), so a malicious creator cannot smuggle a long absolute
    // key-destruction deadline via the base. The prunable log (Merkle-validated
    // against the creator-signed `snapshot.event_log_merkle_root` before any field
    // was read — verify-before-restore, ADR-050) is read ONLY for the fail-safe
    // `TtlExtended` extension term. This DISSOLVES the M3 attack class: a malicious
    // exporter could sign an over-long `ttl_deadline_secs` scalar (`creation + 1yr`
    // while `params.ttl = 1h`), but the scalar is never consulted — the base is
    // `creation + 1h`.
    //
    // KNOWN RESIDUAL (import-legibility surface, tracked in #2102 — NOT closed
    // here): the fail-safe extension term is read from the foreign log WITHOUT
    // leaf-level authentication, so a forged `TtlExtended` leaf with a far-future
    // `new_deadline_unix` can LENGTHEN the imported deadline beyond consent. That
    // is the creator-trust boundary cross-member convergence catches (an honest
    // member's log carries no such leaf); durable leaf-level authz is deferred
    // with the rest of the import-legibility surface (#2102). The base-future-
    // dating + pruning vectors pass-4d listed here are CLOSED (E1/E3).
    let import_log_entries: Vec<scp_event_log::Event> =
        rmp_serde::from_slice(&export.event_log_data).unwrap_or_default();
    if let Some(deadline) = crate::context::ttl_close_helpers::convergent_ttl_deadline(
        &import_log_entries,
        export.snapshot.creation_timestamp_secs,
        handle.params().ttl.map(|t| t.as_secs()),
    ) {
        deps.supervisor
            .dispatch_start_ttl_timer(&context_id, handle.params().clone(), Some(deadline))
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
pub async fn load_persisted_context_state(
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
            .await
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

    // Broadcast security + roster state now rides the fail-closed `ContextSnapshot`
    // (ADR-049 §9 / §5.14.8 block-before-serve). It is no longer loaded through a
    // separate best-effort row; it deserializes atomically with `read_exclusion_list`
    // from the one snapshot, so a block / governance ban / key-epoch advance that
    // persisted fail-closed is present on restore by construction.
    let mut broadcast_ctx = ctx_snapshot
        .broadcast
        .clone()
        .map(scp_protocol::context::broadcast::BroadcastContext::from_snapshot);

    // Restore-path reconciliation (§5.14.8 block-before-serve, defense-in-depth).
    // Re-apply the durable `read_exclusion_list` (written ONLY by governance-ban
    // `execute_revoke`, fail-closed) into the restored broadcast block state: for
    // each excluded DID, drop from the subscriber registry + insert into every
    // author's block list. This closes any window where the restored per-author
    // block lists and the exclusion set could disagree (author registered after
    // the ban; legacy snapshot). A per-author UNILATERAL block does NOT write
    // `read_exclusion_list`, so this reconciliation cannot rescue that arm — that
    // is why the per-author block persists fail-closed at block time.
    if let Some(bc) = broadcast_ctx.as_mut() {
        bc.apply_read_exclusions(ctx_snapshot.read_exclusion_list.iter());
    }

    Ok((ctx_snapshot, broadcast_ctx))
}

/// Best-effort event log restore from persistence.
#[allow(dead_code)] // Transitive of `restore_context` — see bootstrap rationale.
async fn restore_event_log_best_effort(deps: &ActorDeps, context_id: &str) {
    use crate::context::state::context_id_to_bytes;
    let ctx_id_bytes = context_id_to_bytes(context_id);
    if let Err(e) = deps.event_log.restore_event_log(&ctx_id_bytes).await {
        tracing::warn!(
            context_id = %context_id,
            error = %e,
            "failed to restore event log from persistence; \
             context will start with an empty event log"
        );
        let _ = deps.event_log.init_event_log(&ctx_id_bytes).await;
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
/// write). Re-spawns the TTL timer if the context carries a finite
/// `params.ttl`, re-arming the absolute convergent deadline.
///
/// `preloaded_snapshot` lets the watchdog respawn path
/// (`Supervisor::respawn_from_snapshot`) hand in the `ContextSnapshot` it
/// already loaded for its `Active`-state precondition check, so the context
/// snapshot is read from persistence exactly ONCE per respawn instead of twice.
/// Process-restart and the `RestoreContext` dispatch arm pass `None`.
///
/// # The handle is built HERE, from the snapshot
///
/// This function owns construction of the restored [`ContextHandle`] — it is not
/// a parameter. The handle's [`ContextParams`] ARE the context's authority
/// envelope (mode, governance model, capability ceiling, ceiling policy, roles,
/// outlets, TTL, memory scope), they are installed verbatim on the rehydrated
/// `PerContextState`, and the next snapshot write persists them back. The only
/// correct source for them is the snapshot being restored, which this function
/// already loads — so accepting them from a caller would create a second source
/// for a value the snapshot owns, and every caller that lacked the real params
/// would have to invent them. (It did: all three FFI bridges passed
/// `ContextParams::default()`, silently replacing the real params with defaults
/// and making the #2028 Welcome-seam authority gate vacuous after any restore.
/// See [`RestoreContextPayload`](crate::context::actor::commands::RestoreContextPayload).)
///
/// The handle is also driven to [`ContextState::Active`] here, for the same
/// reason: a freshly-constructed handle starts in `Creating`, and every caller
/// previously had to remember to transition it. Owning both steps in one place
/// means a new call site cannot get either wrong.
///
/// Driving to `Active` unconditionally is precisely why the anti-resurrection
/// precondition also lives here: a terminal (`Closed` / `Expired` /
/// `Tombstoned`) snapshot must be refused BEFORE the handle is built, or restore
/// silently undoes closure. See the check on `ctx_snapshot.state` below.
///
/// # Errors
///
/// Returns [`ContextError::PersistenceFailed`] if no persisted state
/// exists. Returns [`ContextError::InvalidState`] if the persisted snapshot
/// records a state other than [`ContextState::Active`] (restoring it would
/// resurrect a closed / expired / tombstoned context). Returns
/// [`ContextError::MembershipFailed`] if the context cannot be inserted
/// (already registered).
#[tracing::instrument(skip_all, fields(context_id))]
#[allow(clippy::too_many_lines)]
#[allow(dead_code)] // Bootstrap entry — see `create_context` rationale.
pub async fn restore_context(
    deps: &ActorDeps,
    context_id: &str,
    preloaded_snapshot: Option<crate::context::state::ContextSnapshot>,
) -> Result<(), ContextError> {
    use crate::context::governance::timeout::DeadlockDetectionState;
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
        load_persisted_context_state(deps, context_id, preloaded_snapshot).await?;

    // Anti-resurrection precondition, on the PRIMITIVE.
    //
    // Restoring drives the handle to `Active` unconditionally (see below), so
    // without this a `Closed` / `Expired` / `Tombstoned` snapshot comes back as a
    // LIVE context: closure and expiry are undone, and the terminal state the
    // snapshot records is silently overwritten by the next persist. Two callers
    // already refused that — `restore_all_contexts` skips non-`Active` snapshots
    // and `Supervisor::respawn_from_snapshot` refuses to respawn a terminal one —
    // but the `LifecycleCommand::RestoreContext` dispatch arm, which is what all
    // three FFI bridges reach, had no check at all. Any SDK could resurrect a
    // closed context.
    //
    // The check belongs HERE for the same reason the handle is built here: the
    // snapshot is this context's single source of truth, this function already
    // holds it, and a precondition that lives only in some callers is a
    // precondition a new call site gets wrong. The two existing caller checks
    // remain as fast-paths — `restore_all_contexts` wants to SKIP a terminal
    // snapshot mid-sweep rather than log a failure per context, and
    // `respawn_from_snapshot` decides dormancy before spending respawn budget.
    if ctx_snapshot.state != scp_protocol::context::ContextState::Active {
        return Err(ContextError::InvalidState(format!(
            "restore refused: the persisted snapshot for '{context_id}' records state {:?}, not \
             Active. Restoring drives the context handle to Active, so admitting a terminal \
             snapshot would RESURRECT a closed/expired/tombstoned context as a live one.",
            ctx_snapshot.state
        )));
    }

    // The context's authoritative handle, built from the PERSISTED params — the
    // single source of truth for this context's authority envelope (see the
    // "handle is built HERE" section on this function). Nothing about the handle
    // comes from the caller: the id is the one whose snapshot we just loaded, and
    // the params are the ones that snapshot carries.
    //
    // Driven to `Active` immediately: a fresh `ContextHandle` starts in
    // `Creating`, the rehydrated state below hardcodes `lifecycle_state: Open`,
    // and the per-context builder installs this handle verbatim — so leaving it
    // in `Creating` would rehydrate a context whose handle state contradicts its
    // own snapshot. Callers no longer perform this transition.
    let handle = ContextHandle::new(context_id.to_owned(), ctx_snapshot.context_params.clone());
    handle.transition_to(&scp_protocol::context::ContextState::Active)?;
    let handle = &handle;

    restore_event_log_best_effort(deps, context_id).await;

    validate_consequence_rules_for_import(
        &ctx_snapshot.consequence_rules,
        &ctx_snapshot.context_params.consequence_config,
    )?;

    // Ceiling-entry grammar enforcement on the RESTORED ceiling (spec §5.3.1.1).
    // This is the self-respawn / process-restart path reading a LOCAL snapshot.
    // The construction invariant (`ContextRoleState::new` / `set_ceiling`) means a
    // malformed ceiling can never have been written to that snapshot in the first
    // place, and `CapabilityCeiling`'s validating `Deserialize`
    // (`#[serde(try_from)]`) rejects a malformed ceiling when a real on-disk
    // provider decodes the snapshot FROM BYTES. This explicit check is the
    // belt-and-suspenders guard for the IN-MEMORY path: a `ContextPersistence`
    // provider's `load_context` hands back an already-typed `ContextSnapshot`
    // value, which may not have crossed serde (e.g. an in-memory provider), so we
    // re-validate here as defense-in-depth against on-disk corruption rather than
    // an untrusted-peer threat. Reject a malformed restored ceiling rather than
    // silently rehydrating an actor with a poisoned authorization envelope.
    ctx_snapshot
        .role_state
        .ceiling()
        .validate_entries()
        .map_err(|e| {
            ContextError::PersistenceFailed(format!(
                "restore: persisted context ceiling has a malformed entry (spec §5.3.1.1): {e}"
            ))
        })?;

    let now_for_cooldown = deps.clock.now_secs();
    sanitize_cooldown_until(
        &mut ctx_snapshot.cooldown_until,
        &ctx_snapshot.consequence_rules,
        now_for_cooldown,
        "restore",
    );
    // Resolve the ABSOLUTE convergent TTL re-arm deadline through the partitioned
    // single-source deadline (§5.10 / §5.10.1, ADR-049 §9). The create BASE and
    // PROMOTION come from the PRUNE-IMMUNE snapshot (`creation_timestamp_secs` +
    // `params.ttl`): a finite `params.ttl` ⇒ base `creation + ttl`; a promoted
    // context has `params.ttl == None` ⇒ `None` (no re-arm), and that promotion
    // signal survives even a fully-pruned log. The prunable event log (hydrated by
    // `restore_event_log_best_effort` above) is read ONLY for the fail-safe
    // `TtlExtended` extension term (losing one only shortens). This REPLACES the
    // old trio of independent sources: the persisted `ttl_deadline_secs` scalar
    // (now a runtime cache, re-derived here, not trusted), the `creation + ttl`
    // `.or_else` fallback, and the `memory_scope != Full` gate at the dispatch
    // site (H1). `creation_timestamp_secs` is captured here — before the
    // per-context builder consumes `ctx_snapshot` fields — off the `Copy` field.
    let restore_ctx_id_bytes = context_id_to_bytes(context_id);
    let restore_creation_ts = ctx_snapshot.creation_timestamp_secs;
    let restore_log_entries = deps
        .event_log
        .event_log_entries(&restore_ctx_id_bytes)
        .ok()
        .flatten()
        .unwrap_or_default();
    let restore_ttl_deadline = crate::context::ttl_close_helpers::convergent_ttl_deadline(
        &restore_log_entries,
        restore_creation_ts,
        handle.params().ttl.map(|t| t.as_secs()),
    );

    let governance_engine =
        restore_governance_engine_from_snapshot(&ctx_snapshot, Arc::clone(&deps.key_resolver))?;
    let (grace_store, needs_reconnect) =
        restore_grace_store_from_snapshot(context_id, &ctx_snapshot);

    // #2148 (ADR-049 birth-into-actor) restore/respawn/cold-restart seam:
    // rehydrate the per-context MLS crypto as OWNED material and SEED it directly
    // onto the actor's `PerContextState` below (`build_restored_owned` → merge
    // floors → `seed_encrypted_crypto_from_owned`). This is the RESPAWN
    // (`Supervisor::respawn_from_snapshot`) AND COLD-RESTART
    // (`restore_all_contexts`) path — both reach here through `restore_context`.
    // `build_restored_owned` restores the node-level wrapping keypair as a `&self`
    // side effect (OBS-2 — NOT side-effect-free) but touches NO provider
    // per-context state (the provider holds none — its `contexts` map is DELETED).
    // The actor is the SOLE crypto authority by construction; there is no
    // provider-resident second home to tear down first.
    let mut restored_owned: Option<crate::crypto::mls::provider::OwnedMlsCryptoState> = None;
    if !ctx_snapshot.mls_crypto_state.is_empty() {
        let ctx_id_bytes = context_id_to_bytes(context_id);

        // §23.17 Invariant 2 (trusted-local self-respawn / process-restart):
        // reconstruct the per-context MLS crypto MATERIAL + the Class-M floors the
        // snapshot carried, returned OWNED (no provider insert). A respawn
        // rehydrates from the last COALESCED snapshot, which may lag the live
        // per-sender epoch floors by up to one coalesce interval (ADR-049 §9); the
        // max-merge below tolerates that lag.
        let (owned, restored_floors) = deps
            .crypto
            .build_restored_owned(&ctx_id_bytes, &ctx_snapshot.mls_crypto_state)
            .map_err(|e| {
                ContextError::PersistenceFailed(format!(
                    "restore: crypto state restore failed: {e}"
                ))
            })?;

        // THE D2 sink (OBS-1 / CM-005): max-merge the SNAPSHOT floors (`incoming`)
        // INTO the authoritative Supervisor-owned registry (`local` = the live,
        // never-torn-down registry). ONE cross-axis validating merge — BOTH the
        // epoch AND the recv-sequence floors are validated before EITHER is
        // applied, so a rejection on either axis leaves the WHOLE registry entry
        // unchanged. This is the node restoring its OWN snapshot
        // (`MaxMergeTrustedLocal`): a coalesce-lagged floor that trails the live
        // floor is the NORMAL case, so the merge MAX-merges and PROCEEDS (never
        // rejected for a lower restored floor); only a corrupt overshoot beyond
        // `MAX_EPOCH_ADVANCE` is rejected. The merged floor is never below the
        // live floor, so a stale snapshot cannot regress the replay floor. This
        // routes the cold-restart (empty-registry) floors through the SAME sink,
        // closing the D2 replay window on first boot. FAIL-CLOSED via
        // `.map_err(..)?`. On rejection the just-built `owned` material is dropped
        // here (the `SenderKey` zeroizes; the `ScpMlsGroup` / signer is freed, not
        // zeroized - #82); fail-closed by construction - a rejected restore is never
        // seeded and writes no durable snapshot, so the id cannot resurrect a
        // divergent second group. #2148 deleted the provider `taken_context_ids`
        // marker this comment referenced, and `build_restored_owned` sets none.
        deps.supervisor
            .validate_and_merge_all_floors(
                &ctx_id_bytes,
                restored_floors.sender_epochs,
                restored_floors.recv_sequence,
                scp_protocol::crypto::sender_keys::MAX_EPOCH_ADVANCE,
                scp_protocol::crypto::sender_keys::MergePolicy::MaxMergeTrustedLocal,
            )
            .map_err(ContextError::from)?;

        // §5.13.3 rule 1 (FFI-02, load-time binding). Verify the rehydrated
        // group's committed `scp_context_params` (`0xFF02`) extension binds the
        // SAME context_id + governance / ceiling / mode the snapshot's
        // `context_params` declares, BEFORE the authoritative `PerContextState`
        // is rebuilt from those params below. This is the trusted self-respawn /
        // process-restart path, so the primary threat is on-disk snapshot
        // corruption/divergence rather than a hostile peer — but rule 1 still
        // holds on load: a restored group that is not a `0xFF02`-carrying SCP
        // context, or whose committed params diverge, is a corrupt snapshot and
        // is rejected. Read the extension from the OWNED group (it is no longer
        // provider-resident). On rejection the `owned` material is dropped (the
        // `SenderKey` zeroizes; the group / signer is freed, not zeroized - #82);
        // fail-closed by construction - the rejected crypto is never seeded, so no
        // divergent crypto persists (no provider taken-marker exists post-#2148).
        if let Err(reason) = verify_scp_context_binding(
            owned
                .mls_group
                .group_context_extension()
                .map_err(|e| e.to_string()),
            context_id,
            ctx_snapshot.role_state.creator_did.as_str(),
            &ctx_snapshot.context_params,
            "context restore",
        ) {
            return Err(ContextError::PersistenceFailed(reason));
        }

        restored_owned = Some(owned);
    }

    let last_members: HashSet<scp_did::DID> = ctx_snapshot
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
    //
    // ADR-056: `PerContextState.context_id` is the canonical 32-byte DIGEST —
    // DECODE the (64-hex) id rather than re-hash it, so the rehydrated crypto
    // keys under the same digest the live context used before the restart.
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
    let mut per_context = PerContextState {
        context_id: context_id_bytes,
        created_at: deps.clock.now_secs(),
        // Convergent creator-assigned creation time, restored VERBATIM from the
        // persisted snapshot (same-node crash recovery). Carrying it forward —
        // rather than re-deriving from local `now()` — keeps the re-armed TTL
        // expiry deadline (`creation + ttl`) identical to what the context had
        // before the restart, so the timer-fired `ContextExpired`/`ContextClosed`
        // leaf stays convergent across members (§7.3.1, §9.9.3). The TTL timer is
        // re-armed below on the ABSOLUTE convergent deadline (the persisted
        // `ttl_deadline_secs`, or the `creation + ttl` fallback).
        creation_timestamp_secs: ctx_snapshot.creation_timestamp_secs,
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
            next_proposal_seq: ctx_snapshot
                .next_proposal_seq
                .max(ctx_snapshot.approved_proposals.len() as u64),
            approved_proposals: ctx_snapshot.approved_proposals,
            freeze: ctx_snapshot.governance_freeze,
            deadlock: DeadlockDetectionState::default(),
            pending_ceiling_modification: ctx_snapshot.pending_ceiling_modification,
            pending_economic_policy_change: ctx_snapshot.pending_economic_policy_change,
            registered_outlets: ctx_snapshot.registered_outlets,
            outlet_interfaces: ctx_snapshot.outlet_interfaces,
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
            // ADR-049 §9 Class S: restore the revocation set FROM the snapshot.
            // Resetting it to empty here (the prior behaviour) silently dropped
            // every revocation on actor respawn / process restart — a
            // downward-authorization rollback the crash-safety invariant
            // forbids. The snapshot is authoritative.
            revoked_spending_ucan_cids: ctx_snapshot.revoked_spending_ucan_cids,
            proposal_timestamps: ctx_snapshot.proposal_timestamps,
            class_s: crate::context::state::GovernanceClassS {
                executed_proposals: {
                    let now = deps.clock.now_secs();
                    ctx_snapshot
                        .executed_proposals
                        .into_iter()
                        .map(|id| (id, now))
                        .collect()
                },
                threshold_signers: ctx_snapshot.threshold_signers,
                threshold_value: ctx_snapshot.threshold_value,
                spending_nonce_tracker:
                    scp_protocol::crypto::ucan::nonce::NonceTracker::from_snapshot(
                        context_id.to_owned(),
                        Arc::clone(&deps.clock),
                        ctx_snapshot.spending_nonce_tracker_state,
                    ),
            },
        },
        role_state: ctx_snapshot.role_state,
        receive_buffer: ReceiveBuffer::new(),
        payment_receipts: VecDeque::new(),
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
        // B-owned UCAN proof index (spec §6.2.4) is NOT in the Class-S snapshot:
        // it is reconstructable interface state, repopulated when the outlet
        // interface is (re-)established.
        xctx_ucan_proofs: scp_protocol::crypto::ucan::validate::InMemoryProofResolver::new(),
        class_s: crate::context::actor::state::ClassSState {
            saga_pending: ctx_snapshot
                .saga_pending
                .into_iter()
                .map(|(id, mirror)| (id, mirror.into_prepared()))
                .collect(),
            // ADR-049 §9 Class S: same-node restore REHYDRATES B's anti-replay
            // nonce-dedup cache (spec §6.2.4 "Freshness / anti-replay"). It is the
            // ONLY gate against a fresh-`SagaId` replay of a `CrossContextOutletInvoke`
            // within the dedup TTL; reinitializing it empty on restore would let
            // a crash inside the window re-open a charging-outlet replay (BLACK-624-01).
            // Per-entry TTL is pruned lazily on the next freshness check. Cross-node
            // import drops it (the snapshot field is empty), so a foreign node starts
            // its own window. Rehydrated with the SAGA dedup TTL (strictly longer
            // than the freshness skew tolerance) so the restored window matches the
            // live one — see `SAGA_NONCE_DEDUP_TTL_SECS` (BLACK-XCTX-01).
            xctx_nonce_dedup: scp_protocol::crypto::sender_keys::NonceDedup::from_entries_with_ttl(
                ctx_snapshot.xctx_nonce_dedup,
                crate::context::actor::handlers::saga::SAGA_NONCE_DEDUP_TTL_SECS,
            ),
            // ADR-049 §9 Class S (line 144): same-node restore REHYDRATES the
            // durable Commit-B output captures (spec §6.2.4 "Exactly-once execution
            // with durable output capture") so a Commit replayed after a crash
            // re-emits the STORED output + the IDENTICAL receipt rather than
            // re-invoking the outlet. The live `CommittedOutletInvocation` is public (no
            // §9.4.3 bearer), so the snapshot stores it directly — no mirror.
            xctx_committed_outputs: ctx_snapshot.xctx_committed_outputs,
            xctx_committed_stream_outputs: ctx_snapshot.xctx_committed_stream_outputs,
            xctx_committed_invocations: ctx_snapshot.xctx_committed_invocations,
            // ADR-049 §9 Class S (spec §6.2.4): same-node restore REHYDRATES the
            // caller-side durable reservation reversal records so a crash-recovery
            // abort can reverse the caller deduction + void the escrow from the
            // record. Dropped on cross-node import (caller economy is local).
            xctx_caller_reservations: ctx_snapshot.xctx_caller_reservations,
            // §7.3.8 Class S: same-node restore REHYDRATES the value-caveat
            // counters so a consumed `max_calls` / `amount_max_cumulative` /
            // `rate_window` cap survives a crash rather than un-consuming (which
            // would re-open the spend/rate window). Pruning of the rate-window
            // ring buffer runs lazily on the next consume against the restored
            // wall clock, so a restart can only ever DROP stale timestamps —
            // never widen a window. Cross-node public export strips this map.
            caveat_counters: ctx_snapshot.caveat_counters,
            // Fix-D Class S: same-node restore REHYDRATES the streaming
            // reservation recovery records so the post-restore reconcile sweep
            // can RELEASE the escrow hold + cumulative counter reserve of any
            // stream whose off-mailbox pump survived the crash (its close-time
            // settle lands on the respawned generation and is dropped). Cross-
            // node public export strips this map (invoker economy is local).
            stream_reservations: ctx_snapshot.stream_reservations,
        },
        pending_broadcast_publishes: HashMap::new(),
        welcome_scratchpad: None,
        lifecycle_state: ContextLifecycleState::Open,
        event_log: None,
        mode,
    };

    // ADR-049 PR-7 (SCP-CRYPTOMOVE-001) C2: SEED the rehydrated owned crypto onto
    // the actor state (the actor is the SOLE crypto authority). This installs the
    // MLS group + local sender key (wrapping the non-optional owned payload in
    // `Some`, since a fresh Create actor spawns before its group exists) and
    // RESUMES the send-sequence counter via `SendSequenceTracker::from_persisted`
    // — NONCE-SAFETY: the send counter picks up from the persisted high-water
    // mark, NEVER resets (a reset would make the actor re-issue an already-emitted
    // (epoch, send_sequence) AAD pairing on the next seal). Floors are NOT seeded
    // here — the Supervisor-owned Class-M registry is authoritative and was
    // already merged above. Broadcast contexts carry no MLS crypto
    // (`restored_owned` is `None`) and keep their reconstructed `Broadcast` mode.
    if let Some(owned) = restored_owned {
        per_context.seed_encrypted_crypto_from_owned(owned);
    }

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

    // Fix-D — restore-time streaming crash-recovery sweep. The actor is now
    // resident with its Class-S state rehydrated (including any
    // `stream_reservations` records). Drive the reconcile ON the freshly-
    // respawned actor: it RELEASES the durable escrow hold + §7.3.8 cumulative
    // counter reserve of any stream whose off-mailbox pump survived the crash
    // (that pump's close-time settle now lands on the bumped generation and is
    // dropped) and clears the records. This is the streaming analog of the
    // §6.2.4 saga reconciliation, but scoped to the SAME restored context —
    // streaming has no cross-context saga journal, and the reservation is this
    // context's OWN owned state, so it runs regardless of generation. Best-
    // effort: a dispatch miss (context despawned again) leaves the records for
    // the next restart's sweep (idempotent) rather than failing the restore.
    match deps
        .supervisor
        .reconcile_stream_reservations_via_actor(context_id)
        .await
    {
        Ok(reconciled) if reconciled > 0 => {
            tracing::info!(
                context_id = %context_id,
                reconciled,
                "Fix-D: released stranded streaming reservations on restore \
                 (pump survived a crash — escrow + cumulative counter reserve refunded)"
            );
        }
        Ok(_) => {}
        Err(err) => {
            tracing::warn!(
                context_id = %context_id,
                "Fix-D: streaming reservation reconcile on restore failed \
                 (records left for the next restart's sweep): {err}"
            );
        }
    }

    // Governance timeouts (ADR-031 §5) are ACTOR-OWNED (ADR-049
    // Decision-1 / finding A3): the spawned actor's `reconcile_timers`
    // arms the 60 s interval while `Active` — no bootstrap install needed.

    // Re-arm the TTL timer from the single authoritative source. Mailbox
    // StartTtlTimer to the freshly-spawned actor (registry + mailbox tick — no
    // DashMap reach) IFF the `convergent_ttl_deadline` computed above
    // (`restore_ttl_deadline`) is `Some`. A `None` means either no finite TTL or
    // a PROMOTED context — in both cases the timer stays disarmed. Pass-4e
    // (ADR-049 §9): the disarm decision reads `params.ttl == None` (the SOLE
    // prune-immune promotion authority), NOT the `ContextPromoted` event-log leaf
    // — that leaf is a RECORD only and is not consulted for the arm. This is the
    // H1 fix at the source: it replaces the fragile `memory_scope != Full` gate
    // (which mis-classified a created-`Full`+ttl broadcast context as permanent
    // and left it stuck-open). A past deadline arms a `sleep(0)` idempotent
    // re-close, which is correct.
    if let Some(deadline) = restore_ttl_deadline {
        deps.supervisor
            .dispatch_start_ttl_timer(context_id, handle.params().clone(), Some(deadline))
            .await;
    }

    Ok(())
}

// ===========================================================================
// Supervisor-iterating sweep entry points (Phase 2A finalization)
// ===========================================================================
//
// These replaced the now-deleted legacy lifecycle sweep helpers
// (the `lifecycle_helpers_legacy` module is gone). Each iterates
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
// bootstrap-shape helpers per ADR-049 §7 allowlist).
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
    let context_ids = persistence.list_persisted_contexts().await.map_err(|e| {
        ContextError::PersistenceFailed(format!("failed to list persisted contexts: {e}"))
    })?;

    let mut restored = Vec::new();
    for ctx_id in &context_ids {
        let ctx_snapshot = match persistence.load_context(ctx_id).await {
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

        // The snapshot is loaded here only for the `state != Active`
        // anti-resurrection precondition; `restore_context` loads its own copy
        // and builds the context handle from it, so nothing about the restored
        // context's identity or params is passed across from this loop.
        match supervisor.restore_context(ctx_id).await {
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
        // Drop the authoritative Class-M floor registry entry on the same
        // teardown sweep (ADR-049) — the floor-registry twin of the crash-window
        // reap above. Harmless-but-tidy here (the whole Supervisor is about to be
        // dropped), but it keeps the registry floors' lifecycle aligned 1:1 with
        // crash_windows and leaves no per-context registry entry behind after a
        // shutdown sweep.
        let ctx_id_bytes = crate::context::state::context_id_to_bytes(ctx_id);
        supervisor.remove_context_floors(&ctx_id_bytes);
        // Drop the per-context stream admission-tracker registry entry on the
        // same teardown sweep (spec §5.4.5) — the streaming twin of the
        // crash-window / floor-registry reaps above, keeping the admission
        // registry from leaking past a shutdown.
        supervisor.reap_stream_admission(ctx_id);
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

    // No supervisor timer JoinSet to abort: TTL / governance timers are
    // ACTOR-OWNED arms (ADR-049 finding A3). Despawning each actor above
    // drops its inbox sender, so its `run()` loop exits and its owned timer
    // arms are dropped with the task — no separate teardown needed.

    tracing::info!(
        removed_count = context_ids.len(),
        "shutdown: removed all contexts via actor mailbox and cleared identity registries"
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
        // plain `std::sync::Mutex` is the right outlet. The runtime's actor path
        // bans it (ADR-049); test fixtures are explicitly exempt. See
        // crates/scp-runtime/clippy.toml.
        clippy::disallowed_types
    )]

    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use scp_did::DID;
    use scp_platform::in_memory::InMemoryStorage;
    use scp_protocol::context::broadcast::BroadcastContextSnapshot;
    use scp_protocol::context::params::{ContextMode, ContextParams};
    use scp_protocol::context::{ContextError, builder::ContextCreationError};

    use crate::context::actor::commands::LifecycleCommand;
    use crate::context::actor::state::ContextRouting;
    use crate::context::builder::{ContextEventLogProvider, ContextTransportProvider};
    use crate::context::persistence::ContextPersistence;
    use crate::context::state::ContextSnapshot;
    use crate::context::supervisor::supervisor::Supervisor;
    use crate::context::{ContextHandle, lifecycle_helpers};

    type PersistErr = Box<dyn std::error::Error + Send + Sync>;

    /// Connected no-op transport — `create_context` publishes through it.
    struct OkTransport;
    #[async_trait::async_trait]
    impl ContextTransportProvider for OkTransport {
        fn is_connected(&self) -> bool {
            true
        }
        async fn publish_context(
            &self,
            _id: &[u8; 32],
            _params: &ContextParams,
        ) -> Result<(), ContextCreationError> {
            Ok(())
        }
        async fn delete_published(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        async fn send_message(&self, _id: &[u8; 32], _payload: &[u8]) -> Result<(), ContextError> {
            Ok(())
        }
    }

    struct OkEventLog;
    #[async_trait::async_trait]
    impl ContextEventLogProvider for OkEventLog {
        async fn init_event_log(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        async fn append_event(
            &self,
            _id: &[u8; 32],
            _event: scp_event_log::EventType,
            _actor: &str,
            _payload: scp_event_log::EventPayload,
            _timestamp_secs: u64,
        ) -> Result<(), ContextCreationError> {
            Ok(())
        }
        async fn destroy_event_log(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
    }

    /// Event log whose `init`/`destroy` succeed but whose `append_event` ALWAYS
    /// fails. Models the ADR-049 §9 round-9 leak scenario: a WORKING persistence
    /// backend with a FAILING event-log append, so `finalize_send`'s very first
    /// `append_context_event("MessageSent")` returns `Err` AFTER the caller has
    /// reserved a per-sender sequence — exercising the rollback this gate fixes.
    struct FailingAppendEventLog;
    #[async_trait::async_trait]
    impl ContextEventLogProvider for FailingAppendEventLog {
        async fn init_event_log(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
        async fn append_event(
            &self,
            _id: &[u8; 32],
            _event: scp_event_log::EventType,
            _actor: &str,
            _payload: scp_event_log::EventPayload,
            _timestamp_secs: u64,
        ) -> Result<(), ContextCreationError> {
            Err(ContextCreationError::EventLogFailed(
                "fixture: event-log append deliberately fails".to_owned(),
            ))
        }
        async fn destroy_event_log(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
            Ok(())
        }
    }

    /// Captures every snapshot write so a real `create_context` can be used to
    /// harvest a fully-formed, validation-passing `ContextSnapshot` (broadcast
    /// state now rides `ContextSnapshot::broadcast`, ADR-049 §9 fold).
    #[derive(Default)]
    struct CapturingPersistence {
        contexts: Mutex<HashMap<String, ContextSnapshot>>,
    }
    #[async_trait::async_trait]
    impl ContextPersistence for CapturingPersistence {
        async fn persist_context(&self, id: &str, s: &ContextSnapshot) -> Result<(), PersistErr> {
            self.contexts
                .lock()
                .unwrap()
                .insert(id.to_owned(), s.clone());
            Ok(())
        }
        async fn load_context(&self, id: &str) -> Result<Option<ContextSnapshot>, PersistErr> {
            Ok(self.contexts.lock().unwrap().get(id).cloned())
        }
        async fn delete_context(&self, _id: &str) -> Result<(), PersistErr> {
            Ok(())
        }
        async fn list_persisted_contexts(&self) -> Result<Vec<String>, PersistErr> {
            Ok(self.contexts.lock().unwrap().keys().cloned().collect())
        }
    }

    /// Boxed handle over a shared `Arc<CapturingPersistence>` so the supervisor
    /// can write through it while the test reads the harvested snapshot from the
    /// same backing store.
    struct SharedCapture(Arc<CapturingPersistence>);
    #[async_trait::async_trait]
    impl ContextPersistence for SharedCapture {
        async fn persist_context(&self, id: &str, s: &ContextSnapshot) -> Result<(), PersistErr> {
            self.0.persist_context(id, s).await
        }
        async fn load_context(&self, id: &str) -> Result<Option<ContextSnapshot>, PersistErr> {
            self.0.load_context(id).await
        }
        async fn delete_context(&self, id: &str) -> Result<(), PersistErr> {
            self.0.delete_context(id).await
        }
        async fn list_persisted_contexts(&self) -> Result<Vec<String>, PersistErr> {
            self.0.list_persisted_contexts().await
        }
    }

    /// Serves a single fixed snapshot (+ optional broadcast) for the
    /// `restore_context` under test. The reconstructed mode is `Encrypted` when
    /// `broadcast` is `None` and `Broadcast` when it is `Some`, independent of
    /// the snapshot's `routing` variant — which is exactly the axis the
    /// reconciliation cross-checks.
    struct ServingPersistence {
        snapshot: ContextSnapshot,
    }
    #[async_trait::async_trait]
    impl ContextPersistence for ServingPersistence {
        async fn persist_context(&self, _id: &str, _s: &ContextSnapshot) -> Result<(), PersistErr> {
            Ok(())
        }
        async fn load_context(&self, _id: &str) -> Result<Option<ContextSnapshot>, PersistErr> {
            Ok(Some(self.snapshot.clone()))
        }
        async fn delete_context(&self, _id: &str) -> Result<(), PersistErr> {
            Ok(())
        }
        async fn list_persisted_contexts(&self) -> Result<Vec<String>, PersistErr> {
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
        let crypto = Arc::new(crate::crypto::mls::provider::NodeMlsFactory::new(
            "did:dht:z6MkRestoreReconcile".to_owned(),
            std::sync::Arc::new(scp_clock::SystemClock),
        ));
        Supervisor::with_providers(
            crypto,
            Box::new(OkTransport),
            Box::new(OkEventLog),
            Arc::new(|_: &DID, _: scp_did::SigningKeyId| None),
            Some(persistence),
            None,
            None,
            None,
            mls_storage(),
        )
    }

    /// Creates a real context of the requested mode under `ctx_id` and returns
    /// the harvested snapshot plus its broadcast snapshot (if any).
    ///
    /// The context is created under the SAME `ctx_id` the caller restores it
    /// under, so the group's creator-committed `scp_context_params` (`0xFF02`)
    /// extension binds that exact `context_id` — exactly as a real snapshot
    /// does. This lets the load-time §5.13.3 binding check pass on the honest
    /// round-trip (so the test then exercises the routing/mode reconciliation it
    /// targets) instead of tripping on an unrealistic id/extension divergence.
    async fn harvest_snapshot(
        ctx_id: &str,
        is_broadcast: bool,
    ) -> (ContextSnapshot, Option<BroadcastContextSnapshot>) {
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
        harvest_snapshot_with(ctx_id, params).await
    }

    /// [`harvest_snapshot`] with caller-chosen [`ContextParams`] — used by the
    /// restore-params test, which needs a genuinely non-default authority
    /// envelope to distinguish "restored from the snapshot" from "reconstructed
    /// from a default".
    async fn harvest_snapshot_with(
        ctx_id: &str,
        params: ContextParams,
    ) -> (ContextSnapshot, Option<BroadcastContextSnapshot>) {
        let capture = Arc::new(CapturingPersistence::default());
        // Box the same Arc-backed capture so we can both write (via supervisor)
        // and read (via this handle) the harvested snapshot.
        let supervisor = build_supervisor(Box::new(SharedCapture(Arc::clone(&capture))));
        let is_broadcast = params.mode == ContextMode::Broadcast;
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
        // Broadcast state rides the snapshot now (ADR-049 §9 fold) — read it back
        // from `snapshot.broadcast`, not a separate persisted broadcast row.
        let broadcast = snapshot.broadcast.clone();
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
        // Broadcast state now rides the snapshot (ADR-049 §9 fold); the
        // reconstructed mode is driven by `snapshot.broadcast` (Some → Broadcast,
        // None → Encrypted), exactly the axis the reconciliation cross-checks.
        snapshot.broadcast = serve_broadcast;
        let serving = ServingPersistence { snapshot };
        let supervisor = build_supervisor(Box::new(serving));
        let deps = supervisor
            .build_actor_deps(&DID("did:dht:z6MkRestoreReconcile".to_owned()))
            .await
            .expect("build_actor_deps");
        lifecycle_helpers::restore_context(&deps, restore_ctx_id, None).await
    }

    /// #2028 — restore installs the PERSISTED `ContextParams`, never a
    /// caller-supplied default.
    ///
    /// The restored [`ContextHandle`]'s params ARE the context's authority
    /// envelope: `PerContextState.handle` is installed from them verbatim, the
    /// TTL re-arm reads `handle.params().ttl`, the snapshot writer persists
    /// `handle.params().clone()` back to storage, and the #2028 Welcome-seam
    /// gate compares `handle.params().ceiling` against the live ceiling.
    ///
    /// Every FFI bridge dispatches `LifecycleCommand::RestoreContext` with only
    /// a context id; it holds no `ContextParams`. When the payload still carried
    /// a `params` field the bridges filled it with `ContextParams::default()`,
    /// so ANY restore through any SDK silently replaced the context's real
    /// ceiling, ceiling policy, governance model, mode, roles, outlets and TTL
    /// with defaults — and then PERSISTED those defaults over the real ones. The
    /// empty default ceiling additionally made the #2028 gate vacuous (an empty
    /// genesis set is trivially covered by any live ceiling), so the gate stayed
    /// present in the source while enforcing nothing: a false guarantee.
    ///
    /// This test drives the exact dispatch surface the bridges use and pins that
    /// the restored context reports the SNAPSHOT's params. Against the pre-fix
    /// code every assertion below fails — the restored context reported
    /// `ContextParams::default()`.
    #[tokio::test]
    async fn restore_installs_the_persisted_params_not_a_caller_default() {
        use scp_protocol::context::params::{CeilingPolicy, MemoryScope};
        use scp_protocol::context::roles::Capability;

        let ctx_id = "restore-installs-persisted-params-not-default";

        // A deliberately NON-default authority envelope: every field below
        // differs from `ContextParams::default()`, so a reconstructed default
        // cannot masquerade as a faithful restore on any of them.
        let params = ContextParams {
            mode: ContextMode::Encrypted,
            ceiling: vec![
                Capability::MessagesRead,
                Capability::MessagesWrite,
                Capability::MemberInvite,
            ],
            ceiling_policy: CeilingPolicy::Governed,
            memory_scope: MemoryScope::Full,
            ..ContextParams::default()
        };
        assert_ne!(
            params.ceiling,
            ContextParams::default().ceiling,
            "fixture precondition: the ceiling must differ from the default"
        );

        let (snapshot, _) = harvest_snapshot_with(ctx_id, params.clone()).await;
        assert_eq!(
            snapshot.context_params.ceiling, params.ceiling,
            "precondition: the harvested snapshot carries the real ceiling"
        );

        let supervisor = build_supervisor(Box::new(ServingPersistence { snapshot }));

        // The EXACT command shape all three FFI bridges dispatch — context id
        // only. There is no `params` field to get wrong any more; the point of
        // the test is that the restored context still ends up with the real ones.
        let (tx, rx) = tokio::sync::oneshot::channel();
        supervisor
            .dispatch_lifecycle_command(LifecycleCommand::RestoreContext {
                payload: Box::new(crate::context::actor::commands::RestoreContextPayload {
                    context_id: ctx_id.to_owned(),
                }),
                reply: tx,
            })
            .await
            .expect("dispatch RestoreContext");
        rx.await
            .expect("restore reply")
            .expect("restore succeeds against the harvested snapshot");

        let restored = supervisor
            .context_params(ctx_id)
            .await
            .expect("the params query must not fault")
            .expect("the restored context is registered and reports its params");

        assert_eq!(
            restored.ceiling, params.ceiling,
            "the restored context must carry the PERSISTED capability ceiling — a default \
             (empty) ceiling would make the #2028 Welcome-seam gate vacuous on every \
             post-restore path"
        );
        assert_eq!(
            restored.ceiling_policy,
            CeilingPolicy::Governed,
            "the restored context must carry the PERSISTED ceiling policy"
        );
        assert_eq!(
            restored.memory_scope,
            MemoryScope::Full,
            "the restored context must carry the PERSISTED memory scope"
        );
        assert_eq!(
            restored.mode,
            ContextMode::Encrypted,
            "the restored context must carry the PERSISTED mode"
        );
    }

    /// Case 1: reconstructed mode ENCRYPTED (no broadcast state) but the
    /// persisted routing variant is `Broadcast` → fail closed.
    #[tokio::test]
    async fn restore_rejects_broadcast_routing_on_encrypted_reconstruction() {
        let ctx_id = "restore-case-broadcast-routing-encrypted-mode";
        let (enc_snapshot, _) = harvest_snapshot(ctx_id, false).await;
        let err = restore_with(
            enc_snapshot,
            ContextRouting::for_mode(true, [0u8; 32]),
            None,
            ctx_id,
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
        let ctx_id = "restore-case-pseudonymous-routing-broadcast-mode";
        let (bcast_snapshot, bcast_state) = harvest_snapshot(ctx_id, true).await;
        let bcast_state = bcast_state.expect("broadcast create must persist broadcast state");
        let err = restore_with(
            bcast_snapshot,
            ContextRouting::for_mode(false, [9u8; 32]),
            Some(bcast_state),
            ctx_id,
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
        let ctx_id = "restore-case-agreeing-encrypted";
        let (enc_snapshot, _) = harvest_snapshot(ctx_id, false).await;
        let routing = enc_snapshot.routing.clone();
        restore_with(enc_snapshot, routing, None, ctx_id)
            .await
            .expect("routing agreeing with mode must restore Ok");
    }

    /// Restore must reject a persisted snapshot whose ceiling carries a malformed
    /// entry (spec §5.3.1.1). The construction invariant means a malformed ceiling
    /// can never have been written legitimately, so this is defense-in-depth
    /// against on-disk corruption — a poisoned authorization envelope must not be
    /// silently rehydrated.
    #[tokio::test]
    async fn restore_rejects_malformed_ceiling_entry() {
        let ctx_id = "restore-case-malformed-ceiling";
        let (mut enc_snapshot, _) = harvest_snapshot(ctx_id, false).await;
        let routing = enc_snapshot.routing.clone();
        // Inject a malformed (no-colon) custom directly into the backing set via
        // the test-only ceiling accessor, bypassing the construction invariant the
        // way a corrupt on-disk snapshot would.
        enc_snapshot
            .role_state
            .ceiling_mut()
            .capabilities_mut()
            .insert(scp_protocol::context::roles::Capability::Custom(
                "payments".to_owned(),
            ));
        let err = restore_with(enc_snapshot, routing, None, ctx_id)
            .await
            .expect_err("a malformed restored ceiling must fail closed");
        assert!(
            matches!(err, ContextError::PersistenceFailed(ref msg) if msg.contains("malformed")),
            "expected a PersistenceFailed citing the malformed ceiling, got {err:?}"
        );
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
    #[async_trait::async_trait]
    impl ContextPersistence for FailingJoinPersistence {
        async fn persist_context(
            &self,
            _id: &str,
            _snap: &ContextSnapshot,
        ) -> Result<(), PersistErr> {
            Err("forced persist failure".into())
        }
        async fn load_context(&self, _id: &str) -> Result<Option<ContextSnapshot>, PersistErr> {
            Ok(None)
        }
        async fn delete_context(&self, _id: &str) -> Result<(), PersistErr> {
            Ok(())
        }
        async fn list_persisted_contexts(&self) -> Result<Vec<String>, PersistErr> {
            Ok(Vec::new())
        }
    }

    /// Derive a `did:key` DID + matching signing key (the same convention the
    /// FFI outlet-economy harness uses), so a `key_resolver` can resolve the
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

        let now = scp_clock::Clock::now_secs(&scp_clock::SystemClock);
        let header = UcanHeader::with_kid("#agent".to_owned());
        let payload = UcanPayload {
            iss: joiner.as_ref().to_owned(),
            aud: joiner.as_ref().to_owned(),
            exp: now + 3600,
            nbf: Some(now.saturating_sub(60)),
            nnc: generate_nonce(&scp_clock::SystemClock),
            att: vec![Attenuation {
                with: "scp:spending:*".to_owned(),
                can: "spend".to_owned(),
            }],
            prf: vec![],
            fct: Some(serde_json::Value::Object(fct)),
            nb: None,
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
        let crypto = Arc::new(crate::crypto::mls::provider::NodeMlsFactory::new(
            "did:dht:z6MkJoinMoneyOrder".to_owned(),
            std::sync::Arc::new(scp_clock::SystemClock),
        ));
        let key_resolver: scp_protocol::context::governance::KeyResolver = {
            let did = joiner_for_resolver;
            let vk = joiner_vk;
            Arc::new(
                move |q: &DID, _kid: scp_did::SigningKeyId| {
                    if *q == did { Some(vk) } else { None }
                },
            )
        };
        let captured = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let voided = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let payment_adapter: Arc<dyn crate::economy::adapter::PaymentAdapterDyn> =
            Arc::new(crate::economy::adapter::CountingPaymentAdapter {
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

        // #2148 (ADR-049 birth-into-actor): no MLS group is birthed — this join
        // is rejected at the economics auto-accept guard (SCP-ECON-12030) BEFORE
        // any crypto `add_member` runs, so no group is needed.

        // Build per-context state with a per_join cost so a spending UCAN is
        // required and the escrow path runs.
        let now_secs = scp_clock::Clock::now_secs(&scp_clock::SystemClock);
        let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            context_id_bytes,
            now_secs,
            admin.clone(),
        );
        state
            .role_state
            .set_ceiling(scp_protocol::context::roles::CapabilityCeiling::new([
                Capability::MemberInvite,
                Capability::MessagesWrite,
                Capability::MessagesRead,
            ]))
            .expect("well-formed built-in ceiling");
        state.governance.economic_policy = Some(scp_protocol::economy::types::EconomicPolicy {
            locked: false,
            cost_schedule: scp_protocol::economy::types::CostSchedule {
                currency: scp_protocol::economy::types::CurrencyCode::from("USD"),
                per_message: None,
                per_outlet_call: None,
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
            .unwrap();

        // Generate a real MLS KeyPackage for the joiner.
        let joiner_cred = scp_mls::credential::ScpCredential::new(
            joiner.as_ref().to_owned(),
            None,
            scp_did::SigningKeyId::Active,
        )
        .expect("joiner credential");
        let (kp_bundle, _signer, _provider) =
            scp_mls::group::generate_key_package(&joiner_cred, &scp_clock::SystemClock)
                .expect("generate joiner key package");
        let kp_bytes =
            openmls::prelude::tls_codec::Serialize::tls_serialize_detached(kp_bundle.key_package())
                .expect("serialize key package");
        let key_package =
            scp_protocol::context::membership::KeyPackage::new(joiner.clone(), kp_bytes);

        let handle = ContextHandle::new(context_id.clone(), state.handle.params().clone());
        handle
            .transition_to(&crate::context::ContextState::Active)
            .unwrap();

        let spending_ucan = signed_join_ucan(&joiner, &joiner_key);

        // Even with a failing persistence backend, the paid (`per_join`) policy
        // is rejected at the auto-accept guard BEFORE escrow authorization, so
        // the persist failure is never reached and no escrow side effect runs.
        deps.persistence = Arc::new(FailingJoinPersistence);

        // `join_context` now takes the Class-S cell; wrap the owned state.
        let mut cell = crate::context::actor::class_s::ClassSCell::new(state);
        let result = lifecycle_helpers::join_context(
            &mut cell,
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

        // ADR-049 §9: the paid path's fail-closed persist now rides the deferred
        // `ClassSCommitToken`'s `commit` (which calls `persist_state_fail_closed`
        // internally) rather than an inline `persist_state_fail_closed` call. The
        // Phase-5 commit site is the `t.commit(&*cell, deps, &context_id)` below
        // (the cell seam routes the shared persist through `&*cell`); the ordering
        // invariant is asserted relative to it.
        let persist_idx = body
            .find("t.commit(&*cell, deps, &context_id)")
            .expect("join_context must commit the deferred fail-closed token on the paid path");
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
            post_persist.contains("void_paid_action(deps, a, &context_id)"),
            "the persist-failure branch must void the escrow (between the \
             fail-closed persist and the success-path capture) so a durability \
             failure releases the hold instead of charging the joiner"
        );
    }

    /// M12 / ADR-051 §6 (phase-2.md ADR-011 amendment exclusion taxonomy §2) —
    /// BEHAVIORAL. `MessageSent` is NO LONGER a durable Merkle leaf: it is a
    /// per-author, non-convergent event surfaced only as the local
    /// `ContextEvent::MessageSent`, so two honest members derive the same
    /// `event_log_merkle_root` (§9.9.3). Because `finalize_send` no longer issues
    /// a `MessageSent` `append_context_event`, a FAILING event-log append can no
    /// longer make `finalize_send` return `Err` for a plain send, and there is no
    /// append-failure sequence rollback. This test drives a WORKING persistence +
    /// a FAILING event-log append directly through `finalize_send` and asserts the
    /// send SUCCEEDS and the reserved sequence stays CONSUMED (the next
    /// reservation reissues 2) — pinning that the durable `MessageSent` append
    /// (and its former rollback-on-append-failure) is gone.
    #[tokio::test]
    async fn finalize_send_succeeds_without_durable_message_sent_append() {
        let crypto = Arc::new(crate::crypto::mls::provider::NodeMlsFactory::new(
            "did:dht:z6MkFinalizeSendSeq".to_owned(),
            std::sync::Arc::new(scp_clock::SystemClock),
        ));
        let key_resolver: scp_protocol::context::governance::KeyResolver =
            Arc::new(|_q: &DID, _kid: scp_did::SigningKeyId| None);

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
            scp_clock::Clock::now_secs(&scp_clock::SystemClock),
            admin.clone(),
        );
        state
            .membership
            .add_member(sender.clone(), "member".to_owned(), Vec::new());
        state
            .handle
            .transition_to(&crate::context::ContextState::Active)
            .unwrap();

        // Reserve a sequence exactly as `send_message` does, capturing it.
        let reserved = state
            .membership
            .next_sequence_number(sender.as_ref())
            .expect("sender is a member");
        assert_eq!(reserved, 1, "first reservation yields sequence 1");

        // Encrypted (non-broadcast) send: with `MessageSent` no longer a durable
        // leaf (M12), the FAILING event-log append is never invoked by
        // `finalize_send` for this send, so it SUCCEEDS. `signing_key = None`
        // skips the post-send checkpoint path. `finalize_send` is actor-shape
        // (ADR-049 §9): wrap the state in the owning `ClassSCell` for the call,
        // then reclaim it via `into_inner` for the post-send read below.
        let mut cell = crate::context::actor::class_s::ClassSCell::new(state);
        let result = crate::context::messaging_helpers::finalize_send(
            &mut cell,
            &deps,
            &context_id,
            &context_id_bytes,
            &sender,
            reserved,
            b"payload",
            None,
            None,  // no spending-nonce token (free send) — keeps best-effort persist
            false, // is_broadcast
        )
        .await;
        let mut state = cell.into_inner();

        assert!(
            result.is_ok(),
            "with MessageSent excluded from the durable log (M12), a failing \
             event-log append must NOT fail finalize_send: got {result:?}"
        );

        // The reserved sequence stays CONSUMED — there is no append-failure
        // rollback anymore — so the next reservation reissues 2.
        let next_after_send = state
            .membership
            .next_sequence_number(sender.as_ref())
            .expect("sender is still a member");
        assert_eq!(
            next_after_send, 2,
            "the reserved sequence stays consumed (no durable MessageSent append, \
             no append-failure rollback), so the next reservation reissues 2"
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
            .find("EventType::MemberJoined")
            .expect("join_context must append a MemberJoined event");
        assert!(
            commit_idx < append_idx,
            "the MemberJoined append must follow the ticket commit"
        );

        // The fail-closed persist runs after the append; the append-failure
        // branch sits strictly between commit and that persist. ADR-049 §9: the
        // paid path's fail-closed persist now rides the deferred token's
        // `t.commit(&*cell, deps, &context_id)` (Phase 5; cell seam).
        let persist_idx = body
            .find("t.commit(&*cell, deps, &context_id)")
            .expect("join_context must commit the deferred fail-closed token on the paid path");
        assert!(
            append_idx < persist_idx,
            "the MemberJoined append must precede the fail-closed persist"
        );

        // The slice from the append to the fail-closed persist contains the
        // append's Err branch. It MUST void the escrow — otherwise `auth` drops
        // silently (no Drop impl) and the hold leaks.
        let append_to_persist = &body[append_idx..persist_idx];
        assert!(
            append_to_persist.contains("void_paid_action(deps, a, &context_id)"),
            "the MemberJoined append-failure branch (between the ticket commit and \
             the fail-closed persist) must void the escrow so a failing append \
             releases the hold instead of leaking it (ADR-049 §9 round-9)"
        );
    }

    /// Wave B convergence: `complete_paid_action` records the receipt in the
    /// per-context local `payment_receipts` buffer and surfaces a local
    /// `ContextEvent::PaymentReceived`, but mints NO durable Merkle leaf — so
    /// `checkpoint_events_since` (which counts durable leaves) stays at 0. A
    /// per-payee `PaymentReceived` leaf would diverge across honest members and
    /// break §9.9.3 (ADR-051 §6 / phase-2.md exclusion taxonomy §2).
    #[tokio::test]
    async fn complete_paid_action_buffers_receipt_and_mints_no_durable_leaf() {
        use scp_protocol::context::membership::ContextEvent;

        let crypto = Arc::new(crate::crypto::mls::provider::NodeMlsFactory::new(
            "did:dht:z6MkPayConverge".to_owned(),
            std::sync::Arc::new(scp_clock::SystemClock),
        ));
        let key_resolver: scp_protocol::context::governance::KeyResolver =
            Arc::new(|_: &DID, _| None);
        let captured = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let voided = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let payment_adapter: Arc<dyn crate::economy::adapter::PaymentAdapterDyn> =
            Arc::new(crate::economy::adapter::CountingPaymentAdapter {
                captured: Arc::clone(&captured),
                voided: Arc::clone(&voided),
            });

        let admin = DID("did:dht:z6MkPayConvergeAdmin".to_owned());
        let sup = Supervisor::with_providers(
            crypto,
            Box::new(OkTransport),
            Box::new(OkEventLog),
            key_resolver,
            None,
            Some(payment_adapter),
            None,
            None,
            mls_storage(),
        );
        let deps = sup
            .build_actor_deps(&admin)
            .await
            .expect("build_actor_deps");

        let context_id = "ctx-pay-converge".to_owned();
        let context_id_bytes = crate::context::state::context_id_to_bytes(&context_id);
        let now_secs = scp_clock::Clock::now_secs(&scp_clock::SystemClock);
        let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            context_id_bytes,
            now_secs,
            admin.clone(),
        );
        // A per-message cost so a paid action authorizes + captures.
        state.governance.economic_policy = Some(scp_protocol::economy::types::EconomicPolicy {
            locked: false,
            cost_schedule: scp_protocol::economy::types::CostSchedule {
                currency: scp_protocol::economy::types::CurrencyCode::from("USD"),
                per_message: Some(scp_protocol::economy::types::Amount(10)),
                per_outlet_call: None,
                per_join: None,
                per_period: None,
                per_byte_stored: None,
            },
            payment_adapters: vec!["recording".to_owned()],
            pricing_formula: None,
            payee: admin.clone(),
        });

        // Sanity: no receipts and no durable leaves yet.
        assert!(state.payment_receipts.is_empty());
        assert_eq!(state.checkpoint_events_since, 0);

        let payer = DID("did:dht:z6MkPayer".to_owned());
        // Drive the prepare/hold split directly (the production join + send paths
        // both use it; there is no whole-`&mut` wrapper).
        let auth = {
            let inputs = crate::context::economy_helpers::authorize_paid_action_prepare(
                &state,
                &deps,
                scp_protocol::economy::types::PaidActionType::MessageSend,
                &payer,
            )
            .expect("prepare yields auth inputs for a per_message policy");
            crate::context::economy_helpers::authorize_paid_action_hold(inputs, &payer, &context_id)
                .await
                .expect("authorize_paid_action hold")
                .expect("a paid action is authorized for a per_message policy")
        };

        let receipt = crate::context::economy_helpers::complete_paid_action(
            &mut state,
            &deps,
            auth,
            &context_id,
        )
        .await
        .expect("complete_paid_action")
        .expect("a receipt is produced on capture");

        // The receipt is recorded in the local buffer (spec §19.11).
        assert_eq!(state.payment_receipts.len(), 1);
        assert_eq!(state.payment_receipts[0].receipt_id, receipt.receipt_id);

        // NO durable Merkle leaf was minted — the counter is untouched.
        assert_eq!(
            state.checkpoint_events_since, 0,
            "PaymentReceived must mint no durable leaf (ADR-051 §6 / §9.9.3)"
        );

        // A local `ContextEvent::PaymentReceived` was surfaced, carrying both
        // payer and payee from the receipt, with anchored == false.
        let events = state.receive_buffer.drain();
        let found = events.iter().find_map(|e| match e {
            ContextEvent::PaymentReceived {
                payer,
                payee,
                anchored,
                ..
            } => Some((payer.clone(), payee.clone(), *anchored)),
            _ => None,
        });
        let (ev_payer, ev_payee, ev_anchored) =
            found.expect("a local PaymentReceived event is emitted");
        assert_eq!(ev_payer, receipt.payer);
        assert_eq!(ev_payee, receipt.payee);
        assert!(
            !ev_anchored,
            "the surfaced receipt is unanchored pre-ADR-051"
        );

        // The capture ran exactly once and nothing was voided.
        assert_eq!(captured.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(voided.load(std::sync::atomic::Ordering::SeqCst), 0);

        // ---------------------------------------------------------------
        // Bounded ring: oldest-evicted at DEFAULT_BUFFER_CAPACITY.
        // ---------------------------------------------------------------
        // Pre-fill the buffer to exactly capacity with synthetic markers,
        // tagging the OLDEST so we can prove it is the one evicted. The
        // single real receipt captured above is dropped to make room.
        let cap = scp_protocol::context::membership::DEFAULT_BUFFER_CAPACITY;
        state.payment_receipts.clear();
        let oldest_id = [0x01u8; 32];
        for i in 0..cap {
            let mut id = [0u8; 32];
            id[0] = u8::try_from(i % 256).expect("i % 256 fits u8");
            id[1] = u8::try_from((i / 256) % 256).expect("fits u8");
            // The very first inserted marker carries the sentinel id so its
            // eviction is unambiguous.
            let id = if i == 0 { oldest_id } else { id };
            state
                .payment_receipts
                .push_back(crate::economy::adapter::PaymentReceipt {
                    receipt_id: id,
                    payer: payer.clone(),
                    payee: admin.clone(),
                    amount: scp_protocol::economy::types::Amount(1),
                    currency: scp_protocol::economy::types::CurrencyCode::from("USD"),
                    action_type: scp_protocol::economy::types::PaidActionType::MessageSend,
                    context_id: Some(context_id.clone()),
                    adapter_id: "recording".to_owned(),
                    adapter_proof: Vec::new(),
                    timestamp: i as u64,
                    anchored: false,
                    signature: Vec::new(),
                });
        }
        assert_eq!(
            state.payment_receipts.len(),
            cap,
            "buffer is pre-filled to exactly capacity"
        );
        assert!(
            state
                .payment_receipts
                .iter()
                .any(|r| r.receipt_id == oldest_id),
            "the oldest sentinel is present before the over-capacity push"
        );

        // One more real capture pushes past capacity, evicting the oldest.
        let auth2 = {
            let inputs = crate::context::economy_helpers::authorize_paid_action_prepare(
                &state,
                &deps,
                scp_protocol::economy::types::PaidActionType::MessageSend,
                &payer,
            )
            .expect("prepare yields auth inputs for a per_message policy (2)");
            crate::context::economy_helpers::authorize_paid_action_hold(inputs, &payer, &context_id)
                .await
                .expect("authorize_paid_action hold (2)")
                .expect("a paid action is authorized for a per_message policy (2)")
        };
        let receipt2 = crate::context::economy_helpers::complete_paid_action(
            &mut state,
            &deps,
            auth2,
            &context_id,
        )
        .await
        .expect("complete_paid_action (2)")
        .expect("a receipt is produced on capture (2)");

        // Length is held at the bound — oldest-evicted, not unbounded growth.
        assert_eq!(
            state.payment_receipts.len(),
            cap,
            "an over-capacity push must hold the buffer at DEFAULT_BUFFER_CAPACITY (oldest-evicted)"
        );
        // The oldest sentinel is gone.
        assert!(
            !state
                .payment_receipts
                .iter()
                .any(|r| r.receipt_id == oldest_id),
            "the oldest receipt must be evicted once the buffer is full"
        );
        // The newest real receipt is at the back.
        assert_eq!(
            state
                .payment_receipts
                .back()
                .expect("buffer is non-empty")
                .receipt_id,
            receipt2.receipt_id,
            "the newest receipt is pushed onto the back of the ring"
        );
    }

    // -----------------------------------------------------------------------
    // ADR-049 §9 — leave_context / close_context route their downward-auth
    // transition through `commit_class_s_keep` (FAIL-CLOSED, keep-direction).
    // These drive a FAILING persistence backend end-to-end and assert the
    // helper returns the §9 durability error AND the removal/close mutation is
    // RETAINED in memory (keep-direction: never rolled back on persist failure —
    // re-admitting a removed member / re-opening a closed context is unsafe).
    // -----------------------------------------------------------------------

    /// `leave_context` (broadcast self-removal) persists fail-closed: under a
    /// failing persistence backend it returns `PersistenceFailed`, and the
    /// member removal STAYS applied in memory (keep-direction).
    #[tokio::test]
    async fn leave_context_persist_failure_keeps_removal_fail_closed() {
        use scp_protocol::context::broadcast::{BroadcastAdmission, BroadcastContext};

        let sup = build_supervisor(Box::new(FailingJoinPersistence));
        let admin = DID("did:dht:z6MkLeaveFailClosed".to_owned());
        let deps = sup
            .build_actor_deps(&admin)
            .await
            .expect("build_actor_deps");

        let context_id = "ctx-leave-fail-closed".to_owned();
        let context_id_bytes = crate::context::state::context_id_to_bytes(&context_id);
        let now = scp_clock::Clock::now_secs(&scp_clock::SystemClock);

        // Broadcast-mode state: leave skips MLS (no crypto group needed), so the
        // whole removal body runs synchronously inside `commit_class_s_keep`.
        let mut state = crate::context::actor::state::PerContextState::new_for_test_broadcast(
            context_id_bytes,
            now,
            admin.clone(),
        );
        // The departing member must be on the authoritative roster for
        // `remove_member` to succeed and reach the persist.
        let leaver = DID("did:dht:z6MkLeaver".to_owned());
        state
            .membership
            .add_member(leaver.clone(), "member".to_owned(), Vec::new());
        state.broadcast_context = Some(
            BroadcastContext::new(
                context_id.clone(),
                &ContextMode::Broadcast,
                BroadcastAdmission::Open,
            )
            .expect("broadcast context"),
        );
        state
            .handle
            .transition_to(&crate::context::ContextState::Active)
            .unwrap();

        let handle = ContextHandle::new(context_id.clone(), state.handle.params().clone());
        handle
            .transition_to(&crate::context::ContextState::Active)
            .unwrap();

        let mut cell = crate::context::actor::class_s::ClassSCell::new(state);
        // Self-removal (caller == member): always permitted, no MemberRemove cap.
        let result =
            lifecycle_helpers::leave_context(&mut cell, &deps, &handle, &leaver, &leaver).await;

        assert!(
            matches!(&result, Err(ContextError::PersistenceFailed(_))),
            "a leave whose fail-closed persist fails must surface the §9 durability \
             error (not a silent ack): got {result:?}"
        );
        assert!(
            !cell.membership.contains(leaver.as_ref()),
            "keep-direction: the member removal STAYS in memory through a persist \
             failure — re-admitting a departed member is the unsafe direction"
        );
    }

    /// `close_context` persists fail-closed: under a failing persistence backend
    /// it returns `PersistenceFailed`, and the close teardown STAYS applied in
    /// memory (keep-direction — a closed context must not silently re-open).
    #[tokio::test]
    async fn close_context_persist_failure_keeps_close_fail_closed() {
        use scp_protocol::context::roles::Capability;

        let sup = build_supervisor(Box::new(FailingJoinPersistence));
        let admin = DID("did:dht:z6MkCloseFailClosed".to_owned());
        let deps = sup
            .build_actor_deps(&admin)
            .await
            .expect("build_actor_deps");

        let context_id = "ctx-close-fail-closed".to_owned();
        let context_id_bytes = crate::context::state::context_id_to_bytes(&context_id);
        let now = scp_clock::Clock::now_secs(&scp_clock::SystemClock);

        // Default test governance is SingleAdmin (the close-path model gate).
        let mut state = crate::context::actor::state::PerContextState::new_for_test_encrypted(
            context_id_bytes,
            now,
            admin.clone(),
        );
        // The initiator needs `ContextClose` (the `ttl::close_context` role gate).
        state.role_state.members.insert(admin.as_ref().to_owned());
        state.role_state.member_capabilities.insert(
            admin.as_ref().to_owned(),
            std::iter::once(Capability::ContextClose).collect(),
        );
        // A non-default routing axis so the close teardown's collapse to
        // `Broadcast` is observable as a retained mutation.
        state
            .handle
            .transition_to(&crate::context::ContextState::Active)
            .unwrap();

        let handle = ContextHandle::new(context_id.clone(), state.handle.params().clone());
        handle
            .transition_to(&crate::context::ContextState::Active)
            .unwrap();

        let mut cell = crate::context::actor::class_s::ClassSCell::new(state);
        let result = lifecycle_helpers::close_context(&mut cell, &deps, &handle, &admin).await;

        assert!(
            matches!(&result, Err(ContextError::PersistenceFailed(_))),
            "a close whose fail-closed persist fails must surface the §9 durability \
             error (not a silent ack): got {result:?}"
        );
        // Keep-direction: the close teardown (routing collapsed to `Broadcast`,
        // broadcast_context cleared) STAYS in memory through the persist failure —
        // silently re-opening a closed context is the unsafe direction.
        assert!(
            matches!(cell.routing, ContextRouting::Broadcast),
            "keep-direction: the close teardown's routing collapse is retained on \
             persist failure (a closed context must not re-open)"
        );
        assert!(
            cell.broadcast_context.is_none(),
            "keep-direction: the close teardown stays applied through persist failure"
        );
    }
}
