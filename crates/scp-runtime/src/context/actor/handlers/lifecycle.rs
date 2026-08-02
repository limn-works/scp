//! Lifecycle handlers — see
//! [`LifecycleCommand`](crate::context::actor::commands::LifecycleCommand)
//! and ADR-049 Phase 2A.9 (`lifecycle` domain migration).
//!
//! # Single dispatch entry point
//!
//! - [`dispatch`] — actor-shape entry point. Takes `(&mut state,
//!   &deps, cmd)` and routes to actor-shape helpers in
//!   [`crate::context::lifecycle_helpers`] for per-context variants
//!   (Join / Leave / Close / Export), and to actor-shape helpers in
//!   [`crate::context::queries_helpers`] for access-key variants
//!   (Generate / Revoke / Restore). Used from the actor's
//!   [`dispatch_state`](crate::context::actor::ContextActor::dispatch_state)
//!   loop.
//!
//! Bootstrap variants (`CreateContext`, `ImportContext`, `RestoreContext`)
//! construct fresh `PerContextState` and cannot be routed against a
//! per-context actor that does not yet exist. They are handled by
//! [`Supervisor::dispatch_lifecycle_direct`](crate::context::supervisor::supervisor::Supervisor)
//! which delegates to the actor-shape bootstrap helpers in
//! [`crate::context::lifecycle_helpers`]. If a bootstrap variant
//! reaches this actor-shape dispatch (because an actor is already
//! registered for the target context_id — a re-create attempt), the
//! handler surfaces `ContextError::InvalidState` on the reply oneshot.
//!
//! The prior `dispatch_from_shim` entry point (`&Supervisor`-shape, used
//! by `Supervisor::dispatch_lifecycle_command`'s shim fallback) was
//! deleted in the Phase 2A finalization queries+lifecycle session.
//! Bootstrap routing now lands on `Supervisor::dispatch_lifecycle_direct`;
//! per-context and access-key routing lands on this method through the
//! actor mailbox.
//!
//! Each entry point carries a 30-second per-call transport budget per
//! ADR-049 §7.

use std::time::Duration;

use scp_protocol::context::ContextError;
use tokio::sync::oneshot;

use crate::context::ContextHandle;
use crate::context::actor::commands::{CloseContextReply, ExportContextReply, LifecycleCommand};
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::outcome::Outcome;
use crate::context::actor::state::PerContextState;

/// Per-call transport budget for lifecycle handlers. Plan §"Transport
/// timeouts inside actor handlers": 30 seconds.
pub const HANDLER_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Actor-shape dispatch (used from `dispatch_state`)
// ---------------------------------------------------------------------------

/// Actor-shape dispatch — routes `LifecycleCommand` against actor-owned
/// state.
///
/// Bootstrap commands (`CreateContext`, `RestoreContext`,
/// `ImportContext`) do NOT take `&mut state` — they construct fresh
/// state. They reach
/// [`Supervisor::dispatch_lifecycle_direct`](crate::context::supervisor::supervisor::Supervisor)
/// via the supervisor's lifecycle dispatch and never enter this actor
/// path; if one does reach the actor (re-create attempt against an
/// already-registered context), the handler surfaces
/// `ContextError::InvalidState` on the reply oneshot.
///
/// Per-context commands (`JoinContext`, `LeaveContext`, `CloseContext`,
/// `ExportContext`) operate against `&mut state` directly via the
/// actor-shape helpers in [`crate::context::lifecycle_helpers`].
///
/// Access-key commands (`GenerateContextAccessKey`,
/// `RevokeContextAccessKey`, `RestoreContextAccessKey`) call the
/// actor-shape helpers in [`crate::context::queries_helpers`] (Phase
/// 2A.10) directly on `&mut state` — no supervisor shim involved.
pub(crate) async fn dispatch(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    cmd: LifecycleCommand,
) -> Outcome<()> {
    Box::pin(dispatch_actor_inner(cell, deps, cmd)).await
}

#[allow(clippy::too_many_lines)]
async fn dispatch_actor_inner(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    cmd: LifecycleCommand,
) -> Outcome<()> {
    match cmd {
        LifecycleCommand::CreateContext { payload, reply } => {
            // Bootstrap variant must not reach the actor. The
            // supervisor routes Create / Import / Restore through
            // `dispatch_lifecycle_direct` before mailbox-first checks
            // run. If it gets here, an actor is already registered for
            // the target context_id — re-create against a live actor is
            // an invariant violation.
            let err = ContextError::InvalidState(format!(
                "CreateContext reached actor mailbox — context `{}` already has a registered actor",
                payload.context_id
            ));
            let sketch = outcome_error_sketch(&err);
            let _ = reply.send(Err(
                scp_protocol::context::builder::ContextCreationError::CreationFailed(format!(
                    "{err}"
                )),
            ));
            Outcome::err(sketch)
        }
        LifecycleCommand::JoinContext { payload, reply } => {
            let p = *payload;
            // JoinContext reaches the spending-nonce path (`enforce_join_economy`)
            // via `join_context`, so it is threaded the cell — as are the
            // leave/close arms below, which route their member-removal /
            // lifecycle-close fail-closed persists through the Class-S combinator.
            handle_join_context_actor(
                cell,
                deps,
                p.context_id,
                p.params,
                p.key_package,
                p.spending_ucan.as_ref(),
                p.local_pseudonym,
                reply,
            )
            .await
        }
        LifecycleCommand::LeaveContext { payload, reply } => {
            let p = *payload;
            handle_leave_context_actor(
                cell,
                deps,
                p.context_id,
                p.params,
                p.caller_did,
                p.member_did,
                reply,
            )
            .await
        }
        LifecycleCommand::CloseContext { payload, reply } => {
            let p = *payload;
            handle_close_context_actor(cell, deps, p.context_id, p.params, p.initiator_did, reply)
                .await
        }
        LifecycleCommand::ExportContext {
            context_id,
            exporter_did,
            reply,
        } => handle_export_context_actor(&*cell, deps, context_id, exporter_did, reply),
        LifecycleCommand::ImportContext { export, reply, .. } => {
            // Bootstrap variant — see `CreateContext` arm comment.
            let err = ContextError::InvalidState(format!(
                "ImportContext reached actor mailbox — context `{}` already has a registered actor",
                export.snapshot.context_id
            ));
            let sketch = outcome_error_sketch(&err);
            let _ = reply.send(Err(err));
            Outcome::err(sketch)
        }
        LifecycleCommand::RestoreContext { payload, reply } => {
            // Bootstrap variant — see `CreateContext` arm comment.
            let err = ContextError::InvalidState(format!(
                "RestoreContext reached actor mailbox — context `{}` already has a registered actor",
                payload.context_id
            ));
            let sketch = outcome_error_sketch(&err);
            let _ = reply.send(Err(err));
            Outcome::err(sketch)
        }
        LifecycleCommand::GenerateContextAccessKey {
            context_id,
            member_did,
            caller_did,
            reply,
        } => handle_generate_context_access_key_actor(
            cell,
            &context_id,
            &member_did,
            &caller_did,
            reply,
        ),
        LifecycleCommand::RevokeContextAccessKey {
            context_id,
            member_did,
            caller_did,
            reply,
        } => handle_revoke_context_access_key_actor(
            cell,
            &context_id,
            &member_did,
            &caller_did,
            reply,
        ),
        LifecycleCommand::RestoreContextAccessKey {
            context_id,
            member_did,
            caller_did,
            reply,
        } => handle_restore_context_access_key_actor(
            cell,
            &context_id,
            &member_did,
            &caller_did,
            reply,
        ),
        LifecycleCommand::FlushSnapshot { reply } => {
            handle_flush_snapshot_actor(&*cell, deps, reply).await
        }
        LifecycleCommand::ShutdownSelf { reply } => {
            handle_shutdown_self_actor(cell, deps, reply).await
        }
        LifecycleCommand::ReportBufferLen { reply } => {
            handle_report_buffer_len_actor(&*cell, reply)
        }
        LifecycleCommand::ClearNeedsReconnect { context_id, reply } => {
            handle_clear_needs_reconnect_actor(cell, &context_id, reply)
        }
        LifecycleCommand::IssueMlsUpdate { context_id, reply } => {
            handle_issue_mls_update_actor(cell, deps, &context_id, reply).await
        }
    }
}

// ---------------------------------------------------------------------------
// Actor-shape per-context handlers
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn handle_join_context_actor(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: String,
    params: scp_protocol::context::params::ContextParams,
    key_package: scp_protocol::context::membership::KeyPackage,
    spending_ucan: Option<&scp_protocol::crypto::ucan::UcanToken>,
    local_pseudonym: Option<[u8; 32]>,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let handle = ContextHandle::new(context_id.clone(), params);
    if let Err(e) = handle.transition_to(&scp_protocol::context::ContextState::Active) {
        let sketch = outcome_error_sketch(&e);
        let _ = reply.send(Err(e));
        return Outcome::err(sketch);
    }

    let join_fut = crate::context::lifecycle_helpers::join_context(
        cell,
        deps,
        &handle,
        key_package,
        spending_ucan,
        local_pseudonym,
    );

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, join_fut).await {
        Ok(Ok(())) => (Outcome::ok_mutated(()), Ok(())),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err_mutated(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "join_context exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

async fn handle_leave_context_actor(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: String,
    _params: scp_protocol::context::params::ContextParams,
    caller_did: scp_did::DID,
    member_did: scp_did::DID,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    // Drive the leave through a CLONE of the actor's own `cell.handle`,
    // NOT a freshly-constructed `ContextHandle::new(...)`. `ContextHandle`
    // holds its lifecycle state in a lock-free `Arc<ArcSwap<ContextState>>`,
    // so a clone SHARES the interior cell. When `leave_context` calls
    // `handle.transition_to(&ContextState::Closing)` (for the last-member
    // case where should_close is true), that transition lands on the SHARED
    // cell and `cell.handle.state()` then observes `Closing` — making the
    // context replaceable at the `import_context` replaceability gate.
    //
    // A separate `ContextHandle::new` owns its OWN fresh `Arc`, so the
    // Closing transition lands on a throwaway cell and `cell.handle` stays
    // `Active` forever — which makes a subsequent import reject with
    // "context already exists" (the gate sees a live context). The same
    // bug was present on `CloseContext` and fixed by cloning (see the
    // comment on `handle_close_context_actor`).
    //
    // The payload `_params` is unused: `cell.handle` already carries the
    // authoritative creation-time params.
    let handle = cell.handle.clone();

    let leave_fut = crate::context::lifecycle_helpers::leave_context(
        cell,
        deps,
        &handle,
        &caller_did,
        &member_did,
    );

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, leave_fut).await {
        Ok(Ok(())) => (Outcome::ok_mutated(()), Ok(())),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err_mutated(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "leave_context exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

async fn handle_close_context_actor(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: String,
    _params: scp_protocol::context::params::ContextParams,
    initiator_did: scp_did::DID,
    reply: CloseContextReply,
) -> Outcome<()> {
    // Drive the close through a CLONE of the actor's own `state.handle`,
    // NOT a freshly-constructed `ContextHandle::new(...)`. `ContextHandle`
    // holds its lifecycle state in a lock-free `Arc<ArcSwap<ContextState>>`,
    // so a clone SHARES the interior cell. `ttl::close_context` transitions
    // that shared state Active -> Closing; reading it back through
    // `state.handle` (e.g. the `import_context` replaceability gate's
    // `state.handle.state()`) then observes the terminal state.
    //
    // A separate `ContextHandle::new` owned its OWN fresh `Arc`, so the
    // Closing transition landed on a throwaway cell and `state.handle`
    // stayed `Active` forever — which made export -> close -> import
    // reject with "context already exists" (the gate saw a live context).
    // The payload `params` is ignored: `state.handle` already carries the
    // authoritative creation-time params, and they are immutable.
    //
    // `cell.handle.clone()` reads through the cell's `Deref` (the clone ends the
    // borrow before the `&mut cell` close call below).
    let handle = cell.handle.clone();

    let close_fut =
        crate::context::lifecycle_helpers::close_context(cell, deps, &handle, &initiator_did);

    let (outcome, reply_result) = match tokio::time::timeout(HANDLER_TIMEOUT, close_fut).await {
        Ok(Ok(result)) => (Outcome::ok_mutated(()), Ok(result)),
        Ok(Err(e)) => {
            let sketch = outcome_error_sketch(&e);
            (Outcome::err_mutated(sketch), Err(e))
        }
        Err(_elapsed) => {
            let err = ContextError::TransportTimeout(format!(
                "close_context exceeded {HANDLER_TIMEOUT:?} budget for context {context_id}"
            ));
            let sketch = outcome_error_sketch(&err);
            (Outcome::err_mutated(sketch), Err(err))
        }
    };

    let _ = reply.send(reply_result);
    outcome
}

fn handle_export_context_actor(
    state: &PerContextState,
    deps: &ActorDeps,
    _context_id: String,
    _exporter_did: scp_did::DID,
    reply: ExportContextReply,
) -> Outcome<()> {
    // Export is sync and read-only — no timeout wrapping needed. The actor
    // only captures the UNSIGNED export building blocks (snapshot + event-log
    // data); the snapshot signature is applied at the dispatch boundary
    // (`Supervisor::export_context`) where the FFI-supplied `sign` closure
    // lives, since the runtime holds no custody key (§23.16.8, ADR-050). The
    // capture is infallible (best-effort event-log export), but the reply
    // channel carries `Result` for shape parity with the other lifecycle
    // handlers.
    let blocks = crate::context::lifecycle_helpers::export_context_blocks(state, deps);
    let _ = reply.send(Ok(blocks));
    Outcome::ok(())
}

// ---------------------------------------------------------------------------
// Actor-shape access-key handlers (delegate to queries_helpers actor-shape)
// ---------------------------------------------------------------------------

fn handle_generate_context_access_key_actor(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    context_id: &str,
    member_did: &str,
    caller_did: &str,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    // Coalesced Class-C mutation (the run loop persists on `mutated`): route the
    // role/membership reads + access-key-store write through the non-persisting
    // `class_c_view()`. The field-narrowed helper takes the `ClassCMut` view, so
    // no whole-state `state_mut()` is taken.
    let result = crate::context::queries_helpers::generate_context_access_key(
        &mut cell.class_c_view(),
        context_id,
        member_did,
        caller_did,
    );
    let outcome = match &result {
        Ok(()) => Outcome::ok_mutated(()),
        Err(e) => Outcome::err_mutated(outcome_error_sketch(e)),
    };
    let _ = reply.send(result);
    outcome
}

fn handle_revoke_context_access_key_actor(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    context_id: &str,
    member_did: &str,
    caller_did: &str,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    // Coalesced Class-C mutation — see `handle_generate_context_access_key_actor`.
    let result = crate::context::queries_helpers::revoke_context_access_key(
        &mut cell.class_c_view(),
        context_id,
        member_did,
        caller_did,
    );
    let outcome = match &result {
        Ok(()) => Outcome::ok_mutated(()),
        Err(e) => Outcome::err_mutated(outcome_error_sketch(e)),
    };
    let _ = reply.send(result);
    outcome
}

fn handle_restore_context_access_key_actor(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    context_id: &str,
    member_did: &str,
    caller_did: &str,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    // Coalesced Class-C mutation — see `handle_generate_context_access_key_actor`.
    let result = crate::context::queries_helpers::restore_context_access_key(
        &mut cell.class_c_view(),
        context_id,
        member_did,
        caller_did,
    );
    let outcome = match &result {
        Ok(()) => Outcome::ok_mutated(()),
        Err(e) => Outcome::err_mutated(outcome_error_sketch(e)),
    };
    let _ = reply.send(result);
    outcome
}

// ---------------------------------------------------------------------------
// Shared utilities
// ---------------------------------------------------------------------------

/// Produce a best-effort clone-equivalent `ContextError` for the
/// handler's [`Outcome`] sink given a borrowed error that cannot be
/// cloned. Mirrors the pattern used in
/// [`handlers::messaging`](crate::context::actor::handlers::messaging).
fn outcome_error_sketch(err: &ContextError) -> ContextError {
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
        ContextError::InvalidState(msg) => ContextError::InvalidState(msg.clone()),
        other => ContextError::CryptoFailed(format!("{other}")),
    }
}

// ---------------------------------------------------------------------------
// Sweep handlers (Phase 2A finalization — sweep helper relocation)
// ---------------------------------------------------------------------------

/// Handle [`LifecycleCommand::FlushSnapshot`] (actor-shape).
///
/// Per-actor body of the relocated sweep. Builds a snapshot from
/// `&state`, exports the MLS crypto state via `deps.crypto`, and
/// persists both the context snapshot and any broadcast-context
/// snapshot via `deps.persistence`. Mirrors the per-context body of
/// `flush_all_contexts_legacy` (which iterated `Supervisor::contexts`).
///
/// Best-effort: persist failures log via `tracing::warn!` and
/// increment `crate::metrics::record_persistence_failure()`; the
/// reply oneshot always carries `Ok(())`.
// `Send` discipline (ADR-049 Decision 7): SYNC fn returning a future. The
// snapshot is built from `&PerContextState` in the synchronous prelude; the
// returned future captures only the owned `context_id` / `snapshot` / `reply`
// plus `deps`, so the actor future stays `Send`. An `async fn` would keep the
// `&PerContextState` parameter across the persist `.await` and be `!Send`.
fn handle_flush_snapshot_actor<'d>(
    state: &PerContextState,
    deps: &'d ActorDeps,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> impl std::future::Future<Output = Outcome<()>> + Send + use<'d> {
    use crate::context::state::context_id_to_bytes;

    let context_id = state.handle.context_id().to_owned();
    let mut snapshot = crate::context::manager_methods::snapshot_context(state);
    // Export MLS crypto state alongside the context snapshot (#645).
    // On export failure, mark snapshot needs_reconnect=true and persist
    // an empty crypto blob (AC3 bug 2 — same contract as
    // manager_methods::persist_context_snapshot).
    let ctx_id_bytes = context_id_to_bytes(&context_id);
    // ADR-049 PR-6 (read-authority switch): the per-sender epoch + recv-sequence
    // floors are sourced from the AUTHORITATIVE Supervisor-owned Class-M registry
    // (`deps.supervisor.export_*`) and threaded into `export_crypto_state` as the
    // durable-blob params. ADR-049 PR-7 (SCP-CRYPTOMOVE-001): the export now runs
    // on the actor's `state` (was the provider); the X25519 wrapping keypair enters
    // as params from the retained `deps.crypto.wrapping_keypair()`, and the send
    // sequence is read from `state.send_tracker` inside the twin.
    let (wrapping_public_key, wrapping_secret_key) = deps.crypto.wrapping_keypair();
    match state.export_crypto_state(
        deps.supervisor.export_sender_key_epochs(&ctx_id_bytes),
        deps.supervisor.export_recv_sequence_floors(&ctx_id_bytes),
        wrapping_public_key,
        &*wrapping_secret_key,
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
    // Broadcast security + roster state now rides the Class-S `ContextSnapshot`
    // (built by `snapshot_context` above), so the single `persist_context` write
    // covers it atomically — the prior separate best-effort `persist_broadcast`
    // write is gone (ADR-049 §9 / §5.14.8 block-before-serve).
    async move {
        if let Err(e) = deps
            .persistence
            .persist_context(&context_id, &snapshot)
            .await
        {
            crate::metrics::record_persistence_failure();
            tracing::warn!(
                context_id = %context_id,
                error = %e,
                "failed to persist context snapshot"
            );
        }
        let _ = reply.send(Ok(()));
        Outcome::ok(())
    }
}

/// Handle [`LifecycleCommand::ShutdownSelf`] (actor-shape).
///
/// Per-actor body of the relocated sweep. Destroys this actor's
/// per-context sender keys + MLS group + event log (in that order so
/// secrets are released before structure tears down; the `SenderKey`s
/// zeroize on drop, the MLS group/signer is freed — not zeroized, #82).
/// Mirrors the
/// per-context body of `shutdown_all_contexts_legacy`.
///
/// Best-effort: each destroy failure logs via `tracing::debug!` (the
/// resource may already be gone, e.g., the actor is being shutdown
/// twice) and the reply oneshot always carries `Ok(())`.
///
/// Supervisor-level cleanup (standing contexts, local DIDs, wrapping
/// keys, task set) is the iterating entry point's responsibility —
/// each actor only owns its own per-context resources.
// Sync-prelude + Send-future terminal (ADR-049 Decision 7 Send-discipline).
// `PerContextState` is `!Sync` (it holds the `dyn FnMut` event-emit sink), so a
// `&state` held across an `.await` would make this spawned actor future `!Send`.
// The `&state` (and `&deps`) work runs entirely in a SYNCHRONOUS prelude; the
// returned future captures ONLY owned `Send` data (the cloned `event_log` `Arc`,
// the owned `ctx_id_bytes` / `context_id`, and the `reply` sender). The
// precise-capture `+ use<>` bound excludes the input lifetimes, so the `&state`
// borrow ends before the returned `async move`.
fn handle_shutdown_self_actor(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> impl std::future::Future<Output = Outcome<()>> + Send + use<> {
    use crate::context::state::context_id_to_bytes;

    let context_id = cell.handle.context_id().to_owned();
    let ctx_id_bytes = context_id_to_bytes(&context_id);

    // #2148 (ADR-049 birth-into-actor) actor destroy seam — whole-crypto disposal.
    // The actor is the SOLE owner of the per-context crypto (the provider holds
    // NONE — its `destroy_mls_group` / `destroy_sender_key` teardown methods are
    // DELETED), so tear the ACTOR-OWNED material down explicitly through the
    // field-granular Class-C view (teardown is best-effort, not a fail-closed
    // persist obligation). Each `ScpMlsGroup` owns its own in-memory
    // `InMemoryMlsProvider`, so the epoch/group secrets are freed the moment the
    // `PerContextState` itself drops — a bare drop is NOT a leak of group storage.
    // The reason to dispose explicitly here is EAGER release: this close leaves
    // the `PerContextState` alive (a later respawn rehydrates it), so nothing else
    // frees the crypto until the state eventually drops — `dispose_secrets`
    // (OpenMLS `destroy_group`) releases it NOW. The Ed25519 signer is FREED, not
    // zeroized (`SignatureKeyPair` has no `Zeroize`, scp-mls #82) — same as a bare
    // drop, just eager.
    // A broadcast context carries no `ContextCryptoState` (`crypto_mut() == None`)
    // so this is a clean no-op there. NOT marked `mutated`: shutdown must not
    // persist an emptied crypto over the durable snapshot (a later respawn
    // rehydrates it).
    {
        let mut view = cell.class_c_view();
        if let Some(crypto) = view.mode_mut().crypto_mut() {
            // #2199: shutdown teardown builds no attestation — discard the observed
            // `DisposalOutcome` (the `#[must_use]` guards that the close/TTL seams,
            // which DO build the attestation, consume it).
            let _ = crypto.dispose_secrets();
        }
    }
    // No per-actor background timer tasks to cancel: the TTL + governance
    // timers are ACTOR-OWNED arms reconciled inside `ContextActor::run()`
    // (ADR-049 finding A3). This close leaves the context non-`Active`, so the
    // actor's `reconcile_timers` clears the governance interval on its next
    // turn, and the one-shot TTL arm is a no-op on a non-Active context.

    // Clone the event-log provider `Arc` so the async tail owns it (no `&deps`
    // borrow crosses the await). The event-log destroy still runs after the
    // MLS-group destroy (crypto released before the event-log structure).
    let event_log = std::sync::Arc::clone(&deps.event_log);
    async move {
        if let Err(e) = event_log.destroy_event_log(&ctx_id_bytes).await {
            tracing::debug!(
                context_id = %context_id,
                error = %e,
                "failed to destroy event log during shutdown — may already be gone"
            );
        }
        let _ = reply.send(Ok(()));
        // Shutdown mutates external resources (crypto, event log, task
        // handles) but does NOT mutate `state` itself — `cancel()` takes
        // `&self`. Mark non-mutated for the actor's dirty tracking.
        Outcome::ok(())
    }
}

/// Handle [`LifecycleCommand::ReportBufferLen`] (actor-shape).
///
/// Per-actor body of the gauge sweep. Reads this actor's
/// receive-buffer occupancy directly from owned `&state` and replies
/// with the length. Mirrors the per-context body of the legacy
/// `update_context_gauges`, which iterated `Supervisor::contexts` and
/// `try_lock`ed each `Arc<per-context-state Mutex>` to read
/// `receive_buffer.len()` (ADR-049 Phase 2A finalization — DashMap
/// removal). The actor owns its state, so no cross-actor lock is taken.
///
/// Read-only: returns `Outcome::ok(())` (`mutated = false`).
fn handle_report_buffer_len_actor(
    state: &PerContextState,
    reply: oneshot::Sender<usize>,
) -> Outcome<()> {
    let _ = reply.send(state.receive_buffer.len());
    Outcome::ok(())
}

/// Handle [`LifecycleCommand::ClearNeedsReconnect`] (actor-shape).
///
/// Clears the actor-owned `EpochState.needs_reconnect` flag (spec
/// §23.11) via
/// [`clear_needs_reconnect`](crate::context::queries_helpers::clear_needs_reconnect).
/// Called by the reconnection driver after the six-phase protocol
/// completes for a context. Synchronous; always replies `Ok(())`.
fn handle_clear_needs_reconnect_actor(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    context_id: &str,
    reply: oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    // Field-narrowed Class-C mutation: clear `needs_reconnect` through the
    // non-persisting `class_c_view().epoch_mut()` (coalesced persist via the run
    // loop's `mutated` flag), not a whole-state `state_mut()`.
    crate::context::queries_helpers::clear_needs_reconnect(cell.class_c_view().epoch_mut());
    tracing::debug!(
        context_id,
        "cleared needs_reconnect after reconnection (§23.11)"
    );
    let _ = reply.send(Ok(()));
    Outcome::ok_mutated(())
}

/// Handle [`LifecycleCommand::IssueMlsUpdate`] (actor-shape).
///
/// Issues an MLS Update proposal + self-Commit for post-compromise
/// security (§9.12 step 2) via
/// [`PerContextState::advance_epoch`](crate::context::actor::state::PerContextState::advance_epoch),
/// which preserves the `scp_wrapping_key` leaf extension (§9.16.1) and
/// advances the group epoch locally. Replies with the TLS-serialized MLS
/// Commit bytes for the caller to distribute to all members. Used by the
/// reconnection driver's Phase 5.
async fn handle_issue_mls_update_actor(
    cell: &mut crate::context::actor::class_s::ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    reply: oneshot::Sender<Result<Vec<u8>, ContextError>>,
) -> Outcome<()> {
    // Broadcast contexts have no MLS group — an Update is meaningless.
    // Pure read via `Deref` on the cell.
    if cell.broadcast_context.is_some() {
        let _ = reply.send(Err(ContextError::CryptoFailed(format!(
            "IssueMlsUpdate on broadcast context {context_id} — no MLS group to ratchet"
        ))));
        return Outcome::ok(());
    }

    // ADR-049 PR-7 (SCP-CRYPTOMOVE-001, advance_epoch ruling): the MLS epoch
    // advance is §9 Class-S — the MLS ratchet AND the `mls_epoch` counter that
    // `LocalMlsEpoch` reads must be durable before ack (a coalesced roll-back
    // would leave remaining members on a new epoch while this node still reports
    // the old one). Drive the actor's `advance_epoch` inside `commit_class_s_keep`
    // -> `rest_mut` so both ride the ONE fail-closed persist. The former SEPARATE
    // coalesced `epoch.mls_epoch += 1` mirror (an artifact of the old
    // provider-authoritative arch, where the provider ratcheted and the actor only
    // shadowed) is subsumed here: the actor `advance_epoch` ratchets the group but
    // does not itself bump the `mls_epoch` scalar, so the single authoritative bump
    // now lives in the Class-S closure. `wrapping_public_key` comes from the
    // retained `deps.crypto.wrapping_keypair()`.
    let wrapping_public_key = deps.crypto.wrapping_keypair().0;
    let result = cell
        .commit_class_s_keep(deps, context_id, |mut v| {
            let s = v.rest_mut();
            let out = s.advance_epoch(wrapping_public_key)?;
            s.epoch.mls_epoch = s.epoch.mls_epoch.saturating_add(1);
            Ok(out.commit_bytes)
        })
        .await;

    let mutated = result.is_ok();
    let _ = reply.send(result);
    if mutated {
        Outcome::ok_mutated(())
    } else {
        // advance_epoch (or its fail-closed persist) failed — preserve the
        // handler's existing disposition: report an unmutated error so the
        // post-dispatch persistence does not treat this turn as dirtying state
        // (the fail-closed persist inside the combinator is authoritative).
        Outcome::err(ContextError::CryptoFailed(format!(
            "IssueMlsUpdate failed for context {context_id}"
        )))
    }
}
