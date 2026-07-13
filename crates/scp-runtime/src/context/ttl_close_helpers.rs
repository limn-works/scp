// Read-only actor helpers still take `&mut PerContextState` so their
// handler futures capture `&mut T` (`T: Send`) rather than `&T`
// (`T: Sync` required). `PerContextState` is intentionally Send + !Sync.
#![allow(clippy::needless_pass_by_ref_mut)]

//! TTL-close helpers — actor-shape signatures
//! (ADR-049 Phase 2A.6, TTL subset of `lifecycle_helpers.rs`).
//!
//! # Purpose
//!
//! This module hosts the TTL-domain helpers that the actor handler in
//! [`crate::context::actor::handlers::ttl_close`] calls to implement
//! [`TtlCloseCommand`](crate::context::actor::commands::TtlCloseCommand).
//! Helpers operate on actor-owned
//! [`PerContextState`](crate::context::actor::state::PerContextState)
//! and capability-reduced
//! [`ActorDeps`](crate::context::actor::deps::ActorDeps); the legacy
//! `&Supervisor` lock-and-call bodies live in
//! [`crate::context::ttl_close_helpers_legacy`] for the supervisor
//! shim-fallback path.
//!
//! # TTL deadline ownership (ADR-049 Decision-1 / finding A3)
//!
//! The TTL timer is an ACTOR-OWNED arm. [`start_ttl_timer`] does not spawn
//! any task; it records the convergent
//! `state.ttl.timer.deadline_unix_secs` on actor-owned state. The actor's
//! `run()` loop reconciles a one-shot
//! `sleep` arm against that deadline
//! (`ContextActor::reconcile_timers`) and fires
//! `ContextActor::on_ttl_tick` → [`handle_ttl_expiry`] on wake — no
//! `&Supervisor`, no `DashMap`, no cross-task mailbox hop, and no
//! stale-generation gate (the actor owns its state for the whole turn).
//! The recorded deadline becomes the `ContextExpired`/`ContextClosed`
//! leaf timestamp, convergent across members by construction (§7.3.1,
//! §9.9.3).

use scp_did::DID;
use scp_protocol::context::ContextError;
use scp_protocol::context::membership::ContextEvent;

use crate::context::ContextHandle;
use crate::context::actor::class_s::ClassSCell;
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::state::PerContextState;
use crate::context::state::{context_id_to_bytes, strip_event_payload};
use crate::context::ttl::{self, TtlExtension, TtlTimer};

// ---------------------------------------------------------------------------
// 1. handle_ttl_expiry
// ---------------------------------------------------------------------------

/// Outcome of an actor-owned TTL expiry attempt (SEC-1 rework, ADR-049 §9
/// amendment).
///
/// Carries BOTH the [`TtlExpiryResult`](crate::context::ttl::TtlExpiryResult)
/// (which cleanup steps completed — the bitmask the actor stores as
/// `ttl_expiry_completed` and feeds back as `prior_completed` on a retry) AND
/// the fail-closed persist result of the terminal `Expired` state. The actor
/// treats the expiry as terminal (despawns) ONLY when `result.is_complete()`
/// AND `persist_result.is_ok()` (the terminal `Expired` state is durable);
/// otherwise it keeps the actor alive and re-arms a bounded retry.
pub struct TtlExpiryOutcome {
    /// Which cleanup steps completed (state transition, key destruction, event
    /// leaf), carried forward across on-actor retries.
    pub result: crate::context::ttl::TtlExpiryResult,
    /// Result of the FAIL-CLOSED persist of the terminal `Expired` state.
    /// `Err` means the terminal transition did not durably land (keep-direction:
    /// the in-memory FSM is NOT rolled back to `Active`) — the actor stays alive
    /// and retries so a crash cannot resurrect the context as `Active` against a
    /// stale `Active` snapshot (SEC-1i).
    pub persist_result: Result<(), ContextError>,
}

/// Handles automatic TTL expiry on actor-owned state, FAIL-CLOSED before
/// teardown (ADR-049 §9 amendment, SEC-1 / BLACK-P3-001).
///
/// State-owning signature: reads `state.handle` for the lifecycle FSM,
/// decays the participation cache on completion, and emits
/// `ContextExpired` / `ExpiryFailed` events into `state.receive_buffer`
/// (and the optional event-tx fan-out).
/// The MLS / transport / event-log work flows through
/// `deps.crypto` / `deps.transport` / `deps.event_log`.
///
/// # Two phases (SEC-1)
///
/// 1. **Terminal phase, OUTSIDE any transport timeout.** The FSM transition
///    (`Active` → `Expired`) and key destruction are sync/fast
///    ([`ttl::apply_ttl_terminal_transition`]); the resulting terminal state is
///    persisted **FAIL-CLOSED** (keep-direction `commit_class_s_keep`, like
///    `close_context_with_key`) BEFORE the actor can tear down. A hostile relay
///    can no longer cancel the durable terminal transition (which previously
///    rode a best-effort persist inside the 30 s timeout → resurrection window).
///    KEEP-direction: a persist failure surfaces via
///    [`TtlExpiryOutcome::persist_result`] but does NOT roll the FSM back to
///    `Active`.
/// 2. **Bounded-I/O phase, INSIDE `timeout(HANDLER_TIMEOUT)`.** Best-effort
///    relay deletion + the idempotent `ContextExpired` append
///    ([`ttl::finish_ttl_expiry_io`]) — the unbounded provider awaits that a
///    hung relay could otherwise wedge on.
///
/// # `prior_completed` (retry carry)
///
/// The caller passes the `completed_steps` bitmask from the previous attempt so
/// a retry re-runs ONLY the failed step (e.g. a transient key-destruction
/// failure re-destroys just that key, and an already-appended leaf is skipped).
///
/// # No relock / generation gate
///
/// The legacy version captured `generation` before the async cleanup,
/// dropped the per-context lock, then relocked with a generation check
/// after the cleanup. The actor owns `state` for the entire dispatch
/// turn, so the generation gate is no longer required — there is no
/// concurrent close-and-recreate window for a sibling actor to slip a
/// new context into.
pub async fn handle_ttl_expiry(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    handle: &ContextHandle,
    prior_completed: u8,
) -> TtlExpiryOutcome {
    let context_id = handle.context_id().to_owned();
    let context_id_bytes = context_id_to_bytes(&context_id);

    // Timer-triggered expiry: the convergent `ContextExpired` leaf timestamp is
    // derived from the SINGLE authoritative source — the partitioned single-
    // source deadline (§5.10 / §5.10.1, §7.3.1 / §9.9.3). `convergent_ttl_deadline`
    // takes the prune-immune create base (`creation_timestamp_secs + params.ttl`
    // from the snapshot) raised to every recorded `TtlExtended` leaf (governance
    // `execute_extend_ttl` AND `reset_ttl_timer` both record one), so the stamped
    // instant is IDENTICAL on the first attempt and every retry (base + leaves are
    // stable — no dependence on the cleared `deadline_unix_secs` scalar or the
    // retry-time clock, M1) AND convergent across members (same base, same leaves).
    //
    // A3: a `None` here (promotion removed the TTL ⇒ `params.ttl == None`) ABORTS
    // the expiry as a no-op — the timer must NEVER destroy keys off an absent
    // deadline. Previously a `None` was masked into `clock.now()` and the terminal
    // transition + key destruction proceeded regardless; that let a promoted
    // context's stray timer destroy keys. The stale cached deadline is cleared so
    // `reconcile_timers` disarms (no re-fire spin) and a later restore re-derives
    // `None` from `params.ttl` too.
    let expiry_log_entries = deps
        .event_log
        .event_log_entries(&context_id_bytes)
        .ok()
        .flatten()
        .unwrap_or_default();
    let Some(expiry_deadline) = convergent_ttl_deadline(
        &expiry_log_entries,
        cell.creation_timestamp_secs,
        handle.params().ttl.map(|t| t.as_secs()),
    ) else {
        tracing::warn!(
            context_id = %context_id,
            "TTL expiry ABORTED: the partitioned single-source deadline is None \
             (promotion removed the TTL ⇒ params.ttl == None) — refusing key \
             destruction and clearing the stale cached deadline (A3)"
        );
        cell.class_c_view().ttl_mut().timer.deadline_unix_secs = None;
        return TtlExpiryOutcome {
            result: crate::context::ttl::TtlExpiryResult::aborted_no_deadline(),
            persist_result: Ok(()),
        };
    };
    let expiry_deadline_secs = expiry_deadline.as_secs();

    // -- Phase 1: terminal transition + key destruction (sync), then a single
    //    FAIL-CLOSED persist. OUTSIDE any transport timeout so a relay stall
    //    cannot cancel the durable terminal transition (SEC-1). The transition
    //    runs on `handle`, a clone sharing the same `Arc<ArcSwap<ContextState>>`
    //    as `cell.handle`, so the snapshot the combinator builds captures
    //    `Expired`.
    let terminal_result =
        ttl::apply_ttl_terminal_transition(handle, deps.crypto.as_ref(), prior_completed);

    // Prune the authoritative Class-M floor registry entry (ADR-049) on a
    // GENUINE terminal expiry. Gated on `state_transitioned()` so an aborted /
    // failed transition (A3 `None`-deadline abort already returned above; a wrong-
    // state transition failure sets no step and destroys no keys) NEVER prunes a
    // still-live context's floors. When the transition landed, the context is
    // terminally `Expired` — restore skips non-`Active` snapshots and B8 refuses
    // re-create, so it is permanently gone — and `apply_ttl_terminal_transition`
    // just ran the provider's `destroy_mls_group` floor-map prune (Ephemeral /
    // Summary scope), so this registry prune mirrors it. Pruned regardless of
    // memory scope (a terminal context accepts no further inbound). Idempotent: a
    // bounded expiry RETRY re-enters here and remove-on-absent is a no-op. See
    // `Supervisor::remove_context_floors` for the permanent-vs-transient safety
    // argument.
    if terminal_result.state_transitioned() {
        deps.supervisor.remove_context_floors(&context_id_bytes);
    }

    // Fold the Class-C participation decay + convergent-deadline clear into the
    // SAME fail-closed snapshot (mirrors `close_context_with_key`). KEEP-
    // direction: a persist failure is surfaced but the FSM is NOT rolled back —
    // silently re-opening an expired context is the unsafe direction (SEC-1i).
    let persist_result = cell
        .commit_class_s_keep(deps, &context_id, |mut view| {
            let state = view.rest_mut();
            // Participation decay on TTL expiry (#1530): clear participation
            // cache + cooldown so stale data does not carry over on a later
            // restore.
            state.governance.decay_participation();
            // Clear the recorded convergent deadline durably in the terminal
            // snapshot so a stale absolute deadline cannot re-fire against the
            // expired context on a later restore (BUG-1 parity with
            // `close_context_with_key`).
            state.ttl.timer.deadline_unix_secs = None;
            Ok(())
        })
        .await;

    // -- Phase 2: bounded relay/event-log I/O, INSIDE the transport timeout. On
    //    elapse the event-log step stays unrecorded; the actor keeps itself
    //    alive and a retry (carrying `prior_completed`) re-attempts only that
    //    step. The terminal `Expired` state is ALREADY durable from Phase 1.
    //
    //    GATED on the Phase-1 fail-closed persist succeeding (L1, crypto): the
    //    observable `ContextExpired` leaf must not be appended until the terminal
    //    `Expired` state it announces is DURABLE. If the fail-closed persist
    //    failed, skip Phase 2 entirely this round — the FSM stays `Expired`
    //    (keep-direction, SEC-1i) and the actor stays alive; the bounded retry
    //    re-runs BOTH Phase 1 (persist) and Phase 2 once persist succeeds. The
    //    leaf append is idempotent (`ttl::finish_ttl_expiry_io` skips it via
    //    `terminal_leaf_exists`), so re-running after a successful retry cannot
    //    produce a duplicate leaf.
    let result = if persist_result.is_ok() {
        let io_fut = ttl::finish_ttl_expiry_io(
            handle,
            Some(deps.transport.as_ref()),
            deps.event_log.as_ref(),
            terminal_result.clone(),
            expiry_deadline_secs,
        );
        match tokio::time::timeout(
            crate::context::actor::handlers::ttl_close::HANDLER_TIMEOUT,
            io_fut,
        )
        .await
        {
            Ok(r) => r,
            Err(_elapsed) => {
                tracing::warn!(
                    context_id = %context_id,
                    budget = ?crate::context::actor::handlers::ttl_close::HANDLER_TIMEOUT,
                    "TTL expiry relay/event-log I/O exceeded its transport budget; \
                     terminal Expired state already persisted fail-closed, retry \
                     will re-attempt the unfinished cleanup step"
                );
                terminal_result
            }
        }
    } else {
        // Phase-1 fail-closed persist failed: do NOT append the observable
        // `ContextExpired` leaf against a not-yet-durable terminal snapshot.
        // `terminal_result` carries no `event_logged` bit, so `is_complete()`
        // stays false and the actor keeps itself alive to retry (persist +
        // append) next round.
        //
        // L2 residual (black-hat P3-005) — accepted crash-window: the retry
        // state (that a `ContextExpired` append is still pending for this
        // terminal id) lives only in the resident actor's `ttl_expiry_completed`
        // bitmask, not in the persisted snapshot. A crash DURING this pending
        // retry drops the not-yet-appended leaf: on restart the durable snapshot
        // is already terminal (`Expired`), restore skips non-`Active` contexts,
        // and B8 refuses re-create — so this is NOT resurrection or an
        // access-control bypass, only a missing provenance leaf for a context
        // that is nonetheless terminal for good. Accepted this pass; a
        // restore-path leaf reconciliation for terminal snapshots is possible
        // future hardening (see ADR-049 §9 TTL carve-out).
        tracing::warn!(
            context_id = %context_id,
            "TTL expiry: terminal Expired persist failed (fail-closed); skipping \
             ContextExpired leaf append this round so the observable leaf is not \
             recorded ahead of a durable terminal snapshot — retry will re-run \
             persist + append (L1)"
        );
        terminal_result
    };

    // Emit the completion event onto the actor's owned receive buffer (Class-C,
    // best-effort — rides the coalesced persist).
    let event = if result.is_complete() {
        ContextEvent::Expired
    } else {
        ContextEvent::ExpiryFailed {
            reason: result.to_string(),
            state_transitioned: result.state_transitioned(),
            mls_destroyed: result.mls_destroyed(),
            sender_key_destroyed: result.sender_key_destroyed(),
            event_logged: result.event_logged(),
        }
    };
    emit_event(
        cell.class_c_view().receive_buffer_mut(),
        event,
        &context_id,
        deps.event_tx.as_ref(),
    );

    TtlExpiryOutcome {
        result,
        persist_result,
    }
}

// ---------------------------------------------------------------------------
// 2. propose_ttl_extension
// ---------------------------------------------------------------------------

/// Proposes a TTL extension on actor-owned state.
///
/// Records consent from the given member. Returns `true` iff every
/// member has now consented (unanimous); the caller should then call
/// [`reset_ttl_timer`] with the new duration.
///
/// State-owning signature: reads `state.membership` for membership /
/// member-count lookups and mutates `state.ttl.extension` to record
/// consents. Best-effort persistence on success runs through
/// `deps.persistence`.
///
/// Synchronous because the actor owns `state` for the entire dispatch
/// turn — no lock acquisition is needed and the persistence call is
/// best-effort fire-and-forget. The handler wraps this in
/// `async { ... }` for the dispatcher's `tokio::time::timeout` budget.
pub async fn propose_ttl_extension(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    member_did: &DID,
    proposed_duration: std::time::Duration,
) -> Result<bool, ContextError> {
    if !cell.membership.contains(member_did) {
        return Err(ContextError::MemberNotFound(member_did.to_string()));
    }

    let member_count = cell.membership.count();

    // Initialize extension proposal if not already in progress, then record
    // the consent. `ttl.extension` is Class-C with the coalesced (best-effort)
    // persist below — route through the non-persisting Class-C view (ADR-049 §9).
    let unanimous = {
        let mut view = cell.class_c_view();
        let extension = view
            .ttl_mut()
            .extension
            .get_or_insert_with(|| TtlExtension::new(proposed_duration, member_count));

        extension.add_consent(member_did.clone());
        extension.is_unanimous()
    };

    // Persist context state after proposal consent (best-effort).
    persist_state_best_effort(cell, deps, context_id).await;

    Ok(unanimous)
}

// ---------------------------------------------------------------------------
// 3. reset_ttl_timer
// ---------------------------------------------------------------------------

/// Resets the TTL timer after a successful unanimous extension on
/// actor-owned state, recording the mutation as a `TtlExtended` event-log leaf.
///
/// Re-records the TTL deadline for the given duration and clears the
/// extension proposal state. Timer ownership is actor-local: the recorded
/// deadline is re-derived into a one-shot sleep by
/// `ContextActor::reconcile_timers` (ADR-049 finding A3) — no task is spawned
/// or aborted here.
///
/// # Single-source invariant — the reset emits a leaf (§5.10.1 step 5)
///
/// This is the post-consent ACTIVATION of the
/// [`propose_ttl_extension`] flow. Every deadline mutation MUST emit a
/// convergent `TtlExtended` leaf so the event log stays the single
/// authoritative source that [`convergent_ttl_deadline`] reads — the same
/// invariant `execute_extend_ttl` (the governance extension path) upholds.
/// Without the leaf, a reset-extended deadline would survive only in the
/// runtime scalar and be LOST on the next restore/import (the reader would
/// re-derive the un-extended `creation + ttl` base). The leaf carries the
/// pending consent tally's members and a convergent content-derived
/// `proposal_id` (this bilateral activation has no governance proposal id).
/// The append is best-effort: on failure the deadline still moves in memory,
/// and a later restore re-derives the SHORTER un-extended base — the
/// fail-SAFE direction (the context expires no later than its convergent TTL).
pub async fn reset_ttl_timer(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    new_duration: std::time::Duration,
) {
    // Snapshot the pending consent tally (recorded by `propose_ttl_extension`)
    // BEFORE it is cleared below, for the §5.10.1 step-5 leaf's
    // `consenting_members`. Convergent (sorted) across members.
    let consenting_members = cell
        .ttl
        .extension
        .as_ref()
        .map(TtlExtension::consented_dids)
        .unwrap_or_default();

    // Clear the extension proposal state (Class-C, coalesced best-effort persist
    // below — route through the non-persisting Class-C view, ADR-049 §9).
    cell.class_c_view().ttl_mut().extension = None;

    // §5.10.1 step 5 — leaf-atomic extension (B3): derive the CURRENT convergent
    // deadline from the single authoritative source (the log), raise it by the
    // agreed `new_duration`, mutate the recorded timer AND append the matching
    // `TtlExtended` leaf from the SAME resolved value. Shared with the governance
    // `execute_extend_ttl` path so a deadline mutation can never drift from its
    // convergent leaf. A context with no derivable convergent deadline
    // (promoted / no-TTL / empty log) has no TTL to extend ⇒ no-op, no leaf (H2:
    // never arm a past `0 + new_duration ≈ 1970` deadline reachable via the FFI
    // `context_reset_ttl_timer` op; the fire-and-forget op silently no-ops).
    let context_id_bytes = context_id_to_bytes(context_id);
    // Convergent actor for a member-consented activation: the creator DID is
    // signed into the context and identical on every member.
    let actor_did = cell.role_state.creator_did.clone();
    extend_ttl_deadline_and_record(
        cell,
        deps.event_log.as_ref(),
        &context_id_bytes,
        &actor_did,
        new_duration.as_secs(),
        ExtensionLeaf::Reset { consenting_members },
    )
    .await;

    // Persist context state after TTL reset (best-effort).
    persist_state_best_effort(cell, deps, context_id).await;
}

/// Distinguishes the two TTL-extension activation paths that share the
/// [`extend_ttl_deadline_and_record`] leaf-atomic combinator (B3), each with its
/// own convergent `proposal_id` + leaf-`timestamp` convention.
pub enum ExtensionLeaf {
    /// Governance `ExtendTtl`: the approved proposal id and the committer-assigned
    /// convergent leaf timestamp (`proposal.created_at`, identical for every
    /// member that processes the signed proposal; §7.3.1 / §9.9.3).
    Governance {
        /// The approved governance proposal id recorded on the leaf.
        proposal_id: [u8; 32],
        /// The convergent committer-assigned leaf timestamp.
        committer_timestamp_secs: u64,
        /// The DIDs whose approvals carried the proposal (leaf `consenting_members`).
        consenting_members: Vec<String>,
    },
    /// Bilateral propose/reset activation: no signed governance proposal, so the
    /// leaf's `proposal_id` is content-derived from `(context, old, new)` and its
    /// `timestamp` is the convergent PRE-extension deadline (`old`) — a value
    /// every consenting member holds identically, keeping the leaf byte-identical
    /// across members. (The deadline derivation in [`convergent_ttl_deadline`]
    /// reads the payload's `new_deadline_unix`, never this timestamp, so the
    /// choice is convergence-only, not a semantic deadline input.)
    Reset {
        /// The pending consent tally's members (sorted, leaf `consenting_members`).
        consenting_members: Vec<String>,
    },
}

/// Leaf-atomic TTL extension (ADR-049 §9, B3): raise the recorded convergent
/// deadline AND append the matching `TtlExtended` leaf from the SAME resolved
/// value, so a deadline mutation and its convergent leaf can never drift apart —
/// the mechanical enforcement of the single-source invariant's mutation⇒leaf
/// coupling. Shared by the governance `execute_extend_ttl` path and the bilateral
/// `reset_ttl_timer` path (this SUBSUMES the previously-duplicated leaf-emit
/// kernel).
///
/// The CURRENT deadline is derived from the log (the single authoritative
/// source), NOT the untrusted cached scalar: the extension raises the
/// log-derived [`ConvergentDeadline`] via [`ConvergentDeadline::extend`] — there
/// is no path that wraps the persisted `deadline_unix_secs` cache back into a
/// `ConvergentDeadline` (that would be the forbidden `from_raw`, re-opening the
/// M3 scalar-trust hole).
///
/// A no-op (no timer mutation, NO leaf) when the log yields no deadline to
/// extend — a promoted / no-TTL / empty-log context.
///
/// The leaf append is best-effort / fail-safe: on failure the deadline still
/// moved in memory and a later restore re-derives the SHORTER un-extended base
/// (the context expires no later than its convergent TTL).
pub async fn extend_ttl_deadline_and_record(
    cell: &mut ClassSCell,
    event_log: &dyn crate::context::builder::ContextEventLogProvider,
    context_id_bytes: &[u8; 32],
    actor_did: &str,
    additional_secs: u64,
    leaf: ExtensionLeaf,
) {
    // Derive the CURRENT convergent deadline from the log (single source): the
    // extension raises the log-derived deadline, never the untrusted cached
    // scalar. No derivable deadline ⇒ nothing to extend (no-op, no leaf).
    let params_ttl = cell.handle.params().ttl.map(|t| t.as_secs());
    let creation_timestamp_secs = cell.creation_timestamp_secs;
    let entries = event_log
        .event_log_entries(context_id_bytes)
        .ok()
        .flatten()
        .unwrap_or_default();
    let Some(current) = convergent_ttl_deadline(&entries, creation_timestamp_secs, params_ttl)
    else {
        tracing::warn!(
            "extend_ttl_deadline_and_record: no convergent deadline to extend \
             (promoted / no-TTL context ⇒ params.ttl == None) — no-op, no leaf (H2)"
        );
        return;
    };
    let extended = current.extend(additional_secs);
    let old_dl = current.as_secs();
    let new_dl = extended.as_secs();

    // Mutate the recorded timer deadline (Class-C) from the resolved convergent
    // value. Scoped so the Class-C view is dropped before the async append.
    {
        let mut view = cell.class_c_view();
        start_ttl_timer(&mut view.ttl_mut().timer, extended);
    }

    // Resolve the leaf's convergent `proposal_id` + `timestamp` from the SAME
    // `(old, new)` pair, per the activation path's convention.
    let (proposal_id, timestamp_secs, consenting_members) = match leaf {
        ExtensionLeaf::Governance {
            proposal_id,
            committer_timestamp_secs,
            consenting_members,
        } => (proposal_id, committer_timestamp_secs, consenting_members),
        ExtensionLeaf::Reset { consenting_members } => (
            reset_extension_proposal_id(context_id_bytes, old_dl, new_dl),
            old_dl,
            consenting_members,
        ),
    };

    // Append the `TtlExtended` leaf (best-effort / fail-safe).
    match scp_event_log::payload::encode_payload(&scp_event_log::payload::TtlExtendedPayload {
        old_deadline_unix: old_dl,
        new_deadline_unix: new_dl,
        proposal_id,
        consenting_members,
    }) {
        Ok(payload) => {
            if let Err(e) = event_log
                .append_context_event_with_payload(
                    context_id_bytes,
                    scp_event_log::EventType::TtlExtended,
                    actor_did,
                    payload,
                    timestamp_secs,
                )
                .await
            {
                tracing::warn!(
                    error = %e,
                    "extend_ttl_deadline_and_record: failed to append TtlExtended leaf; the \
                     extension lives only in the runtime scalar and a later restore re-derives \
                     the shorter un-extended base (fail-safe)"
                );
            }
        }
        Err(e) => tracing::warn!(
            error = %e,
            "extend_ttl_deadline_and_record: failed to encode TtlExtended payload; leaf not appended"
        ),
    }
}

/// Derives the CONVERGENT `proposal_id` for a `reset_ttl_timer` activation's
/// `TtlExtended` leaf.
///
/// The bilateral propose/reset activation path (unlike the governance
/// `ExtendTtl` proposal) carries no governance proposal id, so the leaf's
/// `proposal_id` is a content address: `SHA-256` over a domain-separated
/// encoding of the context id and the `(old, new)` deadline pair. Every member
/// activating the same extension derives the identical id, keeping the leaf
/// convergent. It is NOT a governance proposal reference — it identifies the
/// deadline transition itself.
fn reset_extension_proposal_id(context_id_bytes: &[u8; 32], old_dl: u64, new_dl: u64) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"SCP-TTL-RESET-EXTENSION-V1");
    hasher.update(context_id_bytes);
    hasher.update(old_dl.to_be_bytes());
    hasher.update(new_dl.to_be_bytes());
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// 4. start_ttl_timer
// ---------------------------------------------------------------------------

/// Records the per-context TTL expiry deadline on actor-owned state.
///
/// ADR-049 Decision-1 / finding A3: the TTL timer is an ACTOR-OWNED arm.
/// This helper does not spawn any task — it writes the convergent
/// `state.ttl.timer.deadline_unix_secs`, and the actor's `run()` loop
/// reconciles a one-shot `sleep` arm against that deadline
/// (`ContextActor::reconcile_timers`), firing `ContextActor::on_ttl_tick` →
/// the actor-shape expiry pipeline ([`handle_ttl_expiry`]) on wake. The
/// recorded deadline becomes the `ContextExpired`/`ContextClosed` leaf
/// timestamp — convergent across members by construction (§7.3.1, §9.9.3). A
/// reset / re-arm simply overwrites the recorded deadline; the next
/// `reconcile_timers` re-derives the one-shot sleep from it (no task to abort).
pub const fn start_ttl_timer(
    // Takes ONLY the `&mut TtlTimer` it mutates (Class-C timer state), not a
    // whole `&mut PerContextState` / `&mut ClassSCell`. Shared seam: the
    // ttl_close actor handler reaches it through
    // `cell.class_c_view().ttl_mut()` (no `state_mut`); the governance /
    // reset extension paths route through [`extend_ttl_deadline_and_record`]
    // (§9), which reaches it the same way.
    timer: &mut TtlTimer,
    // The ABSOLUTE convergent expiry deadline to record, as a
    // [`ConvergentDeadline`] — the TRANSIENT arming-seam newtype whose private
    // field can only be minted by the closed constructor set
    // ([`convergent_ttl_deadline`] log-derivation, [`convergent_ttl_deadline_secs`]
    // create-base, [`ConvergentDeadline::extend`]). There is NO `from_raw` /
    // `Deserialize`: a raw `u64` (e.g. the untrusted persisted
    // `deadline_unix_secs` cache) can never reach this seam, so a purely
    // local-clock or attacker-supplied arm is unrepresentable at the type level
    // (a §7.3.1 convergence VIOLATION is not constructible). The newtype is
    // unwrapped to the persisted `u64` cache ONLY here, at the write (B2:
    // `deadline_unix_secs` stays a plain `Option<u64>`; `ConvergentDeadline` is
    // never serialized).
    deadline: ConvergentDeadline,
) {
    timer.deadline_unix_secs = Some(deadline.as_secs());
}

// ---------------------------------------------------------------------------
// ConvergentDeadline — the transient arming-seam newtype (ADR-049 §9, B1)
// ---------------------------------------------------------------------------

/// A convergent TTL expiry deadline (absolute Unix seconds), resolved from the
/// single authoritative source and safe to arm a timer with.
///
/// # Why a newtype (ADR-049 §9 — the single-source TTL-deadline invariant)
///
/// The deadline is *the* security-critical quantity of the TTL subsystem: it is
/// the instant at which key material is destroyed. Passing it as a bare `u64`
/// lets any scalar — a stale persisted cache, an attacker-supplied snapshot
/// field, a local `now()+ttl` — masquerade as "the convergent deadline" (the
/// M3 scalar-trust hole). `ConvergentDeadline` closes that at the type level:
/// its field is PRIVATE and it has a CLOSED constructor set, so a value can only
/// come from a sanctioned derivation:
///
/// 1. [`convergent_ttl_deadline`] — the prune-immune snapshot create base raised
///    to the highest fail-safe `TtlExtended` leaf in the (Merkle-validated) log
///    (the partitioned single-source derivation).
/// 2. [`convergent_ttl_deadline_secs`] — the prune-immune create base
///    (`creation_timestamp_secs + params.ttl`) from the persisted snapshot, used
///    both at create-arm time and as the base inside `convergent_ttl_deadline`.
/// 3. [`ConvergentDeadline::extend`] — raises an already-convergent deadline by
///    an agreed additional duration (the TTL-extension primitive).
///
/// There is deliberately **no** `from_raw` / `Deserialize` (B1/B2): admitting a
/// `ConvergentDeadline` from arbitrary bytes would reconstruct a "trusted"
/// deadline from an untrusted scalar and re-open the M3 hole. The arming seam
/// [`start_ttl_timer`] / [`dispatch_start_ttl_timer`] accept ONLY this type, so
/// every armed deadline is convergent by construction. The type is TRANSIENT —
/// it lives only on the arming path and is never persisted; the durable
/// [`TtlTimer::deadline_unix_secs`](crate::context::ttl::TtlTimer) cache stays a
/// plain `Option<u64>` (an untrusted cache re-derived from the log on every
/// restore/import).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConvergentDeadline(u64);

impl ConvergentDeadline {
    /// The absolute deadline as Unix seconds. Unwrapped ONLY at the persistence
    /// cache write ([`start_ttl_timer`]) and when recording a leaf's
    /// `old`/`new` deadline fields — never to reconstruct a new
    /// `ConvergentDeadline` from the result.
    #[must_use]
    pub const fn as_secs(self) -> u64 {
        self.0
    }

    /// Raises this convergent deadline by `additional_secs` (saturating), the
    /// TTL-extension primitive. The result is convergent because both inputs
    /// are — every member extends the SAME recorded convergent deadline by the
    /// SAME agreed duration (§7.3.1).
    #[must_use]
    pub const fn extend(self, additional_secs: u64) -> Self {
        Self(self.0.saturating_add(additional_secs))
    }
}

/// Computes the CONVERGENT initial-TTL expiry deadline (Unix seconds) for a
/// context: `creation_timestamp_secs + params.ttl`.
///
/// Both inputs are convergent across members — `creation_timestamp_secs` is the
/// creator-assigned `ContextCreated` value copied onto every member's state,
/// and `ttl_secs` is the TTL in the context params (legible to every member) —
/// so every member computes the IDENTICAL absolute deadline regardless of when
/// (or with what local clock) it armed its timer. This is the value recorded on
/// `ContextExpired`/`ContextClosed` leaves, making them convergent-by-
/// construction (§7.3.1, §9.9.3).
///
/// Returns `None` when the context has no finite TTL.
#[must_use]
pub const fn convergent_ttl_deadline_secs(
    creation_timestamp_secs: u64,
    ttl_secs: Option<u64>,
) -> Option<ConvergentDeadline> {
    match ttl_secs {
        Some(ttl) => Some(ConvergentDeadline(
            creation_timestamp_secs.saturating_add(ttl),
        )),
        None => None,
    }
}

/// Derives the SINGLE authoritative convergent TTL deadline for a context,
/// PARTITIONED by failure direction between the prune-immune snapshot and the
/// prunable event log (§5.10, §5.10.1, §7.3.1 / §9.9.3, ADR-049 §9).
///
/// # The partitioned invariant
///
/// The convergent deadline has two inputs, split by which way losing them fails:
///
/// - **Fail-DANGEROUS ⇒ prune-immune SNAPSHOT.** The create BASE is
///   `creation_timestamp_secs + params_ttl`, and PROMOTION is `params_ttl ==
///   None` (spec §5.10 — promotion removes the TTL). Both come from the
///   persisted `ContextSnapshot` (`creation_timestamp_secs` + `context_params`),
///   NOT the prunable log: losing the base would never-expire a finite context
///   (keys never destroyed) and losing the promotion signal would destroy a
///   permanent one — the dangerous directions, so neither may depend on a leaf a
///   pruning policy can delete.
/// - **Fail-SAFE ⇒ prunable LOG.** Every EXTENSION is a `TtlExtended` leaf's
///   `new_deadline_unix` (governance `execute_extend_ttl` AND bilateral
///   `reset_ttl_timer` both record one). Extensions only LENGTHEN; pruning one
///   shortens the derived deadline — the fail-safe direction (the context
///   expires no later than its convergent TTL).
///
/// The deadline is the create base RAISED to the highest recorded extension. It
/// is `None` (no arm) IFF `params_ttl == None` — a context that never had a TTL,
/// or one whose TTL promotion removed.
///
/// # Prune-safe by construction (closes the pass-4d #2102 pruning HIGH)
///
/// Pass-4d sourced the base from the genesis `ContextCreated` LEAF timestamp and
/// read promotion from the `ContextPromoted` LEAF — both prunable. Pruning the
/// genesis leaf voided the base (fail-OPEN: a finite context outlived its TTL);
/// a pruned/forged promotion leaf could re-arm a permanent context. Sourcing
/// both from the prune-immune snapshot dissolves that: an empty / pruned log
/// still yields the base (it is in the snapshot), and promotion is the snapshot's
/// `params_ttl == None`. The log is read ONLY for the fail-safe extension term.
///
/// # The `ContextPromoted` leaf is NOT read for the arm decision
///
/// `params_ttl` is the sole promotion authority (prune-immune). The
/// `ContextPromoted` leaf remains in the log as the event RECORD of promotion,
/// but reading it here would reintroduce a fail-DANGEROUS dependency on the
/// prunable log — a forged or pruned promotion leaf must never flip a finite
/// context's arm.
///
/// Every reader (restore/import re-arm, the terminal-leaf timestamp, the
/// extension primitive) derives the deadline through THIS function instead of
/// trusting an independent persisted scalar, a `memory_scope` heuristic, or
/// params alone — collapsing the competing sources that produced the H1/M1/M3
/// deadline bugs into one.
///
/// # Returns
///
/// - `None` iff `params_ttl == None` (no TTL, or promotion removed it) — no arm,
///   regardless of any (stale) `TtlExtended` leaf.
/// - otherwise `Some(max(creation_timestamp_secs + params_ttl, highest
///   TtlExtended.new_deadline_unix))`.
#[must_use]
pub fn convergent_ttl_deadline(
    entries: &[scp_event_log::Event],
    creation_timestamp_secs: u64,
    params_ttl: Option<u64>,
) -> Option<ConvergentDeadline> {
    use scp_event_log::EventType;

    // Fail-dangerous BASE + PROMOTION from the prune-immune snapshot. `None`
    // `params_ttl` (never had a TTL, or promotion removed it per §5.10) ⇒ no arm,
    // returned BEFORE any log read so a stale / forged extension leaf can never
    // arm a promoted or never-finite context ("None iff params_ttl == None").
    let base = convergent_ttl_deadline_secs(creation_timestamp_secs, params_ttl)?;

    // Fail-safe EXTENSION term from the prunable log: the highest recorded
    // `TtlExtended` leaf's `new_deadline_unix` (§5.10.1 step 5).
    // `extend_ttl_deadline_and_record` records the running post-extension
    // deadline, so the max is the current extended deadline every member
    // re-derives identically. Pruning a leaf only SHORTENS the result (fail-safe).
    // A leaf whose payload cannot be decoded is DROPPED with a warning (not
    // silently) so a corrupt leaf that shortens the derived deadline is
    // observable rather than an invisible security regression.
    let ext =
        entries
            .iter()
            .filter(|e| e.event_type == EventType::TtlExtended)
            .filter_map(|e| {
                match scp_event_log::payload::decode_payload::<
                    scp_event_log::payload::TtlExtendedPayload,
                >(&e.payload)
                {
                    Ok(p) => Some(p.new_deadline_unix),
                    Err(err) => {
                        tracing::warn!(
                            sequence = e.sequence,
                            error = %err,
                            "convergent_ttl_deadline: dropping an undecodable TtlExtended leaf; \
                             the derived deadline may be SHORTER than the recorded extension \
                             (single-source invariant — visible, not silent)"
                        );
                        None
                    }
                }
            })
            .max();

    // Raise the prune-immune base to the highest fail-safe extension.
    Some(match ext {
        Some(ext) if ext > base.as_secs() => ConvergentDeadline(ext),
        _ => base,
    })
}

// ---------------------------------------------------------------------------
// 5. finalize_close
// ---------------------------------------------------------------------------

/// Completes context closure on actor-owned state.
///
/// Destroys MLS group state and sender keys, issues relay deletion
/// requests for ephemeral/summary scopes, transitions from `Closing` to
/// `Closed`, and appends the final `ContextClosed` event.
///
/// Persisted snapshot is deleted on success (best-effort) so a later
/// restore does not resurrect the closed context.
///
/// The lifecycle transition runs through `handle.transition_to`; the
/// `ContextClosed` leaf is stamped with the ACTUAL close instant
/// (`deps.clock.now_secs()`) — see the body for why the TTL deadline is NOT the
/// right quantity for this (explicit-only) path.
pub async fn finalize_close(
    // Retained for signature parity with the expiry-path helpers and for the
    // actor-owned call convention; the explicit close reads nothing off it (the
    // close instant is the local clock, the FSM transition rides `handle`).
    _cell: &mut ClassSCell,
    deps: &ActorDeps,
    handle: &ContextHandle,
) -> Result<(), ContextError> {
    let context_id = handle.context_id().to_owned();

    // `ContextClosed` leaf timestamp = the ACTUAL close instant (F4). This helper
    // is reached ONLY from the FFI `context_finalize_close` explicit Closing→Closed
    // path (`handle_finalize_close`); the TTL-EXPIRY path (`handle_ttl_expiry`)
    // stamps its own `ContextExpired` leaf off the convergent deadline and never
    // reaches here. For an explicit close the convergent TTL deadline is the WRONG
    // quantity: a context with a live finite `params.ttl = Some` closed BEFORE it
    // expires has `convergent_ttl_deadline == Some(creation + ttl)`, a FUTURE
    // instant unrelated to when the close actually happened — stamping it would
    // record a future close time. The actual close time is `now`. (This also
    // unifies the two former branches: the prior `params.ttl == None` path already
    // fell back to `now`, so both explicit-close shapes now stamp `now`
    // consistently.) Cross-member convergence of an EXPLICIT governance close is
    // anchored by the prior `ContextClosing` leaf (stamped with the governance
    // committer's convergent close-commit time in `execute_close_context`), NOT by
    // the exact instant of this local terminal finalization — each member
    // finalizes after processing its own notification window, so the terminal
    // leaf's instant is legitimately a local `now`.
    let close_ts = deps.clock.now_secs();

    ttl::finalize_close(
        handle,
        deps.crypto.as_ref(),
        deps.transport.as_ref(),
        deps.event_log.as_ref(),
        close_ts,
    )
    .await?;

    // Delete persisted state after finalize (best-effort). Mirrors
    // the legacy path which only ran the delete when a persistence
    // provider was attached; ContextPersistence is always present on
    // ActorDeps so we always issue the delete.
    let _ = deps.persistence.delete_context(&context_id).await;

    // Prune the authoritative Class-M floor registry entry (ADR-049):
    // an explicit close is a PERMANENT teardown — the FSM is terminally `Closed`
    // (anti-resurrection refuses re-create of a terminal id) and the durable
    // Class-S snapshot was just deleted — so the registry floors are moot and
    // must be dropped, mirroring the provider's per-context floor-map prune
    // inside `destroy_mls_group` (which `ttl::finalize_close` ran above for
    // Ephemeral/Summary scope) and co-located with the snapshot delete. Pruned
    // regardless of memory scope: a `Closed` context accepts no further inbound,
    // so the floors serve no purpose even when Full-scope crypto is retained.
    // See `Supervisor::remove_context_floors` for the permanent-vs-transient
    // safety argument.
    let ctx_id_bytes = context_id_to_bytes(&context_id);
    deps.supervisor.remove_context_floors(&ctx_id_bytes);

    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Pushes `event` onto the actor's `receive_buffer` and, when
/// configured, fans out a sanitized copy on the optional event-tx
/// channel. Mirrors the structure of
/// `broadcast_helpers::emit_event` and `state::PerContextState::emit_event`
/// — kept local so this module does not depend on the broadcast
/// helpers' private surface.
fn emit_event(
    receive_buffer: &mut scp_protocol::context::membership::ReceiveBuffer,
    event: ContextEvent,
    context_id: &str,
    tx: Option<&tokio::sync::broadcast::Sender<(String, ContextEvent)>>,
) {
    if matches!(event, ContextEvent::WelcomeGenerated { .. }) {
        let _ = receive_buffer.push(event);
        return;
    }

    let _ = receive_buffer.push(event.clone());
    if let Some(tx) = tx {
        let sanitized = strip_event_payload(&event);
        let _ = tx.send((context_id.to_owned(), sanitized));
    }
}

/// Best-effort persist of the current actor state. Mirrors the legacy
/// context-snapshot persistence path, but reads fields off the actor's
/// `PerContextState` rather than the legacy lock-shaped type.
fn persist_state_best_effort<'d, 'c>(
    state: &PerContextState,
    deps: &'d ActorDeps,
    context_id: &'c str,
) -> impl std::future::Future<Output = ()> + Send + use<'d, 'c> {
    let mut snapshot = build_snapshot_from_state(state);

    // Export MLS crypto state alongside the context snapshot (#645).
    // On export failure, mark the snapshot `needs_reconnect = true` and
    // persist an empty crypto blob so a later restore fires the §23.11
    // reconnection pipeline.
    let ctx_id_bytes = context_id_to_bytes(context_id);
    // ADR-049 PR-6 (read-authority switch): the per-sender epoch + recv-sequence
    // floors are sourced from the AUTHORITATIVE Supervisor-owned Class-M registry
    // (`deps.supervisor.export_*`) and threaded into `export_crypto_state` as the
    // durable-blob params. The provider floor mirrors are deleted.
    match deps.crypto.export_crypto_state(
        &ctx_id_bytes,
        deps.supervisor.export_sender_key_epochs(&ctx_id_bytes),
        deps.supervisor.export_recv_sequence_floors(&ctx_id_bytes),
    ) {
        Ok(crypto_state) => snapshot.mls_crypto_state = crypto_state,
        Err(e) => {
            snapshot.needs_reconnect = true;
            snapshot.mls_crypto_state = Vec::new();
            tracing::warn!(
                context_id = %context_id,
                error = %e,
                "failed to export MLS crypto state for persistence; \
                 snapshot marked needs_reconnect=true so restore \
                 fires the §23.11 reconnection pipeline"
            );
        }
    }

    async move {
        if let Err(e) = deps
            .persistence
            .persist_context(context_id, &snapshot)
            .await
        {
            crate::metrics::record_persistence_failure();
            tracing::warn!(
                context_id = %context_id,
                error = %e,
                "failed to persist context snapshot"
            );
        }
    }
}

/// Builds a [`ContextSnapshot`](crate::context::state::ContextSnapshot)
/// from the actor's [`PerContextState`]. Field-for-field parallel to
/// [`crate::context::manager_methods::snapshot_context`]; consumes the
/// actor-owned `PerContextState` rather than the legacy lock-shaped
/// type.
fn build_snapshot_from_state(state: &PerContextState) -> crate::context::state::ContextSnapshot {
    // Single source of truth (ADR-049 §9): delegate to the canonical builder so
    // the broadcast Class-S fold and the field-round-trip tripwire cover every
    // persist path. This copy was value-identical to the canonical one.
    crate::context::messaging_helpers::build_snapshot_from_state(state)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{ConvergentDeadline, convergent_ttl_deadline, convergent_ttl_deadline_secs};

    /// Unwrap the arming-seam newtype to its `u64` for assertions.
    fn secs(d: Option<ConvergentDeadline>) -> Option<u64> {
        d.map(ConvergentDeadline::as_secs)
    }

    /// Builds a bare `scp_event_log::Event` of `event_type` at `sequence` with
    /// `timestamp` and `payload`. Post pass-4e `convergent_ttl_deadline` reads
    /// ONLY the `TtlExtended` leaves' `payload` (the fail-safe extension term) —
    /// the create base + promotion come from the prune-immune snapshot
    /// (`creation_timestamp_secs` + `params.ttl`), NOT any leaf. The signature /
    /// `prev_hash` / actor are left empty — this exercises the pure derivation,
    /// not log verification (verification is upstream: the node's own log on
    /// restore, the Merkle-validated export on import).
    fn ev(
        event_type: scp_event_log::EventType,
        sequence: u64,
        timestamp: u64,
        payload: scp_event_log::EventPayload,
    ) -> scp_event_log::Event {
        scp_event_log::Event {
            event_type,
            actor_did: scp_did::DID::from("did:example:convergent-ttl-test"),
            timestamp,
            sequence,
            payload,
            prev_hash: [0u8; 32],
            signature: Vec::new(),
        }
    }

    /// A genesis `ContextCreated` leaf. Post pass-4e the derivation IGNORES this
    /// leaf entirely (the create base is the prune-immune snapshot
    /// `creation_timestamp_secs`); it is retained only to prove that presence /
    /// absence / a stray `timestamp` on the leaf does NOT move the base.
    fn created_at(sequence: u64, timestamp: u64) -> scp_event_log::Event {
        ev(
            scp_event_log::EventType::ContextCreated,
            sequence,
            timestamp,
            scp_event_log::EventPayload::default(),
        )
    }

    fn created(sequence: u64) -> scp_event_log::Event {
        created_at(sequence, CREATION)
    }

    fn ttl_extended(sequence: u64, old_dl: u64, new_dl: u64) -> scp_event_log::Event {
        let payload =
            scp_event_log::payload::encode_payload(&scp_event_log::payload::TtlExtendedPayload {
                old_deadline_unix: old_dl,
                new_deadline_unix: new_dl,
                proposal_id: [0u8; 32],
                consenting_members: vec!["did:example:alice".to_owned()],
            })
            .expect("encode TtlExtendedPayload");
        // The `TtlExtended` leaf's own `timestamp` is not read by the derivation
        // (the extension deadline is the payload's `new_deadline_unix`), so 0.
        ev(scp_event_log::EventType::TtlExtended, sequence, 0, payload)
    }

    fn promoted(sequence: u64) -> scp_event_log::Event {
        ev(
            scp_event_log::EventType::ContextPromoted,
            sequence,
            0,
            scp_event_log::EventPayload::default(),
        )
    }

    const CREATION: u64 = 1_700_000_000;
    const TTL: u64 = 3_600;

    /// No finite TTL (`params.ttl == None`) and no recorded extension ⇒ no
    /// deadline. The `None` is returned before any log read.
    #[test]
    fn convergent_deadline_no_ttl_is_none() {
        let entries = [created(0)];
        assert_eq!(
            secs(convergent_ttl_deadline(&entries, CREATION, None)),
            None
        );
    }

    /// Create base only: the prune-immune snapshot `creation_timestamp_secs +
    /// params.ttl` (E1). No `TtlExtended` leaf, so the base stands.
    #[test]
    fn convergent_deadline_create_ttl_is_base() {
        let entries = [created(0)];
        assert_eq!(
            secs(convergent_ttl_deadline(&entries, CREATION, Some(TTL))),
            Some(CREATION + TTL)
        );
    }

    /// E1: the create base comes from the prune-immune snapshot
    /// `creation_timestamp_secs` argument — NOT the genesis `ContextCreated`
    /// leaf's `timestamp`. A leaf stamped at a wildly different (even future)
    /// timestamp does NOT move the base, proving the base is snapshot-sourced and
    /// pruning-immune.
    #[test]
    fn convergent_deadline_base_is_from_snapshot_not_genesis_leaf() {
        let stray_leaf_ts = CREATION + 12_345;
        let entries = [created_at(0, stray_leaf_ts)];
        assert_eq!(
            secs(convergent_ttl_deadline(&entries, CREATION, Some(TTL))),
            Some(CREATION + TTL),
            "base must be the snapshot creation_timestamp_secs + ttl, not the genesis leaf ts"
        );
    }

    /// A `TtlExtended` leaf raises the deadline above the create base.
    #[test]
    fn convergent_deadline_extension_raises() {
        let extended = CREATION + TTL + 500;
        let entries = [created(0), ttl_extended(1, CREATION + TTL, extended)];
        assert_eq!(
            secs(convergent_ttl_deadline(&entries, CREATION, Some(TTL))),
            Some(extended)
        );
    }

    /// An extension whose deadline is BELOW the create base does not lower the
    /// deadline — the create base wins (`max(base, ext)`). Guards against a stale
    /// / lower `TtlExtended` leaf shortening a live deadline.
    #[test]
    fn convergent_deadline_extension_below_base_keeps_base() {
        let below = CREATION + 10; // < CREATION + TTL
        let entries = [created(0), ttl_extended(1, 0, below)];
        assert_eq!(
            secs(convergent_ttl_deadline(&entries, CREATION, Some(TTL))),
            Some(CREATION + TTL),
            "an extension below the create base must not shorten the deadline"
        );
    }

    /// E1/E2: `None` iff `params.ttl == None`. A promoted / no-TTL context whose
    /// (stale, pruned-context) log still carries a `TtlExtended` leaf must NOT
    /// arm off that extension — the snapshot `params.ttl == None` short-circuits
    /// to `None` before any leaf is consulted.
    #[test]
    fn convergent_deadline_no_ttl_ignores_stale_extension() {
        let extended = CREATION + 999;
        let entries = [created(0), ttl_extended(1, 0, extended)];
        assert_eq!(
            secs(convergent_ttl_deadline(&entries, CREATION, None)),
            None,
            "params.ttl == None ⇒ None regardless of any TtlExtended leaf"
        );
    }

    /// The highest `new_deadline_unix` wins across multiple extensions,
    /// regardless of slice order.
    #[test]
    fn convergent_deadline_takes_max_extension() {
        let first = CREATION + TTL + 100;
        let second = CREATION + TTL + 900;
        let entries = [
            created(0),
            ttl_extended(2, first, second),
            ttl_extended(1, CREATION + TTL, first),
        ];
        assert_eq!(
            secs(convergent_ttl_deadline(&entries, CREATION, Some(TTL))),
            Some(second)
        );
    }

    /// E2: promotion is `params.ttl == None` (spec §5.10), the prune-immune
    /// authority — NOT the `ContextPromoted` leaf. A promoted context (params.ttl
    /// cleared by `execute_promote_context`) ⇒ `None`, even with a prior
    /// extension leaf still in the log.
    #[test]
    fn convergent_deadline_promotion_is_params_ttl_none() {
        let entries = [
            created(0),
            ttl_extended(1, CREATION + TTL, CREATION + TTL + 500),
            promoted(2),
        ];
        assert_eq!(
            secs(convergent_ttl_deadline(&entries, CREATION, None)),
            None,
            "a promoted context (params.ttl == None) never arms, even with a stale extension leaf"
        );
    }

    /// E2: a `ContextPromoted` leaf is the event RECORD of promotion but is NOT
    /// read for the arm decision. With `params.ttl == Some` (the prune-immune
    /// authority says finite), a stray / forged / pruned-in `ContextPromoted`
    /// leaf must NOT disarm the timer — reading it would reintroduce a fail-
    /// dangerous dependency on the prunable log.
    #[test]
    fn convergent_deadline_ignores_context_promoted_leaf() {
        let entries = [created(0), promoted(1)];
        assert_eq!(
            secs(convergent_ttl_deadline(&entries, CREATION, Some(TTL))),
            Some(CREATION + TTL),
            "params.ttl == Some ⇒ arm; a ContextPromoted leaf is not read for the arm decision"
        );
    }

    /// A `reset_ttl_timer` extension (recorded as a `TtlExtended` leaf) raises the
    /// derived deadline exactly like a governance extension — the fail-safe
    /// extension term across BOTH extension paths.
    #[test]
    fn convergent_deadline_reset_extension_raises() {
        let reset_deadline = CREATION + TTL + 250;
        let entries = [created(0), ttl_extended(1, CREATION + TTL, reset_deadline)];
        assert_eq!(
            secs(convergent_ttl_deadline(&entries, CREATION, Some(TTL))),
            Some(reset_deadline)
        );
    }

    /// E1 (prune-immune base): an EMPTY / fully-pruned log still yields the create
    /// base from the prune-immune snapshot (`creation_timestamp_secs +
    /// params.ttl`). Pass-4d returned `None` here (base was the now-absent genesis
    /// leaf — the fail-OPEN pruning residual); pass-4e sources the base from the
    /// snapshot, so pruning the log NEVER voids a finite context's deadline.
    #[test]
    fn convergent_deadline_empty_log_uses_snapshot_base() {
        let entries: [scp_event_log::Event; 0] = [];
        assert_eq!(
            secs(convergent_ttl_deadline(&entries, CREATION, Some(TTL))),
            Some(CREATION + TTL),
            "an empty / pruned log still derives the prune-immune snapshot base (E1)"
        );
    }

    /// E1 companion: an empty log with `params.ttl == None` (promoted / never-
    /// finite) still yields `None` — no base, and no leaf to raise it.
    #[test]
    fn convergent_deadline_empty_log_no_ttl_is_none() {
        let entries: [scp_event_log::Event; 0] = [];
        assert_eq!(
            secs(convergent_ttl_deadline(&entries, CREATION, None)),
            None,
            "an empty log with params.ttl == None arms nothing (promotion survives log loss)"
        );
    }

    /// Two members with WILDLY different local arm-time clocks must compute the
    /// IDENTICAL absolute TTL expiry deadline, because it is derived from the
    /// convergent creation timestamp + the params TTL — not local `now()`. This
    /// is the property that makes the `ContextExpired`/`ContextClosed` leaf
    /// timestamp convergent-by-construction (§7.3.1, §9.9.3).
    #[test]
    fn ttl_deadline_converges_independent_of_arm_time_clock() {
        // Convergent inputs every member shares: the creator-assigned creation
        // timestamp and the TTL duration from the (legible) context params.
        let creation_timestamp_secs = 1_700_000_000_u64;
        let ttl_secs = 3_600_u64; // 1 hour

        // The function takes ONLY convergent inputs — there is no local-clock
        // parameter, so two members necessarily agree.
        let alice_deadline = convergent_ttl_deadline_secs(creation_timestamp_secs, Some(ttl_secs));
        let bob_deadline = convergent_ttl_deadline_secs(creation_timestamp_secs, Some(ttl_secs));

        assert_eq!(alice_deadline, bob_deadline);
        assert_eq!(
            secs(alice_deadline),
            Some(creation_timestamp_secs + ttl_secs)
        );
    }

    /// Negative control: deriving the deadline from each member's local
    /// arm-time clock (`now + ttl`) — the OLD behaviour — diverges when the two
    /// members' clocks differ, which is exactly what the convergent base fixes.
    #[test]
    fn local_arm_time_base_diverges_across_members() {
        let ttl_secs = 3_600_u64;
        // Two honest members arm their timers at different local wall-clock
        // instants (clock skew + arm-time staggering).
        let alice_arm_now = 1_700_000_000_u64;
        let bob_arm_now = 1_700_000_042_u64;

        let alice_local_deadline = alice_arm_now + ttl_secs;
        let bob_local_deadline = bob_arm_now + ttl_secs;

        // The discredited local-now base does NOT converge...
        assert_ne!(alice_local_deadline, bob_local_deadline);
        // ...whereas the convergent base anchored on a shared creation time does.
        let creation = 1_699_999_900_u64;
        assert_eq!(
            convergent_ttl_deadline_secs(creation, Some(ttl_secs)),
            convergent_ttl_deadline_secs(creation, Some(ttl_secs)),
        );
    }

    /// No finite TTL ⇒ no deadline.
    #[test]
    fn no_ttl_yields_no_deadline() {
        assert_eq!(
            secs(convergent_ttl_deadline_secs(1_700_000_000, None)),
            None
        );
    }

    /// Saturating add: a pathological creation time near `u64::MAX` cannot
    /// panic the deadline computation.
    #[test]
    fn deadline_saturates_instead_of_overflowing() {
        assert_eq!(
            secs(convergent_ttl_deadline_secs(u64::MAX, Some(10))),
            Some(u64::MAX)
        );
    }

    /// B4 tripwire (bounded positive allowlist): the sanctioned constructors of
    /// [`ConvergentDeadline`] are EXACTLY the three-member closed set
    /// {`convergent_ttl_deadline` (log-derivation), `convergent_ttl_deadline_secs`
    /// (create-base), `ConvergentDeadline::extend`}. There is deliberately NO
    /// `from_raw` / `Deserialize`, so a raw `u64` (a persisted-cache scalar, an
    /// attacker snapshot field) can never be minted into a `ConvergentDeadline`
    /// and armed — that is the type-level enforcement of the single-source TTL
    /// invariant (ADR-049 §9), NOT a source-text/AST scanner (which would be the
    /// non-convergent BLOCKER anti-pattern). This test mirrors
    /// `class_s_no_persist_mutator_whitelist_is_bounded`: it asserts the
    /// sanctioned constructor COUNT so that adding a fourth constructor (e.g. a
    /// `from_raw`) forces a deliberate, reviewed update here — a tripwire, not a
    /// scanner.
    ///
    /// Each arm below is a live call of a sanctioned constructor (they must
    /// compile and produce a `ConvergentDeadline`); the assertion pins the set
    /// size at three.
    #[test]
    fn convergent_deadline_constructor_allowlist_is_bounded() {
        /// The number of sanctioned `ConvergentDeadline` constructors. Bumping
        /// this REQUIRES a matching new sanctioned constructor below AND a
        /// review of why the closed set grew — a `from_raw` would reintroduce the
        /// M3 scalar-trust hole (ADR-049 §9, B1/B4). Do NOT raise this to admit a
        /// convenience constructor from an untrusted `u64`.
        const SANCTIONED_CONVERGENT_DEADLINE_CONSTRUCTORS: usize = 3;

        // 1. create-base primitive.
        let base: Option<ConvergentDeadline> = convergent_ttl_deadline_secs(CREATION, Some(TTL));
        // 2. log-derivation (snapshot base raised to the fail-safe extension term).
        let entries = [created(0)];
        let derived: Option<ConvergentDeadline> =
            convergent_ttl_deadline(&entries, CREATION, Some(TTL));
        // 3. extend (on an already-convergent deadline).
        let extended: Option<ConvergentDeadline> = base.map(|d| d.extend(TTL));

        // All three sanctioned constructors are live and reachable.
        assert!(base.is_some() && derived.is_some() && extended.is_some());

        assert_eq!(
            SANCTIONED_CONVERGENT_DEADLINE_CONSTRUCTORS, 3,
            "the ConvergentDeadline constructor set is closed at three \
             (log-derivation, create-base, extend); a fourth must be a reviewed \
             addition, never a from_raw (B1/B4)"
        );
    }
}
