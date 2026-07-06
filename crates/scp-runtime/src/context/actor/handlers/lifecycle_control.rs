//! Lifecycle-control handlers — see
//! [`LifecycleControlCommand`](crate::context::actor::commands::LifecycleControlCommand)
//! and plan §"BridgeInstance actor integration".
//!
//! # Clippy allows
//!
//! `doc_markdown` / `too_long_first_doc_paragraph` — doc prose cites
//! plan section titles in quoted form.
#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//!
//! These handlers respond to supervisor-originated Pause / Shutdown /
//! PersistSync / PrepareForReplace commands, running on actor-owned
//! state: `Pause` flips `lifecycle_state` to `Closing` and `Shutdown`
//! flips it to `Closed` through the actor's Class-C view (ADR-049 §9).
//!
//! `PersistSync` acks with `Ok(())` (rather than `NotImplemented`) so
//! the `BridgeInstanceCore::suspend()` default trait method — which
//! sends `Pause` then `PersistSync` against the actor handle and
//! expects acks — can complete its suspend sequence. That arm is a
//! no-op today: handler mutations persist synchronously through the
//! per-handler persistence helpers, so there is no separate actor-side
//! persist buffer for `PersistSync` to flush.

use scp_protocol::context::{ContextError, ContextState};

use crate::context::actor::class_s::ClassSCell;
use crate::context::actor::commands::LifecycleControlCommand;
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::outcome::Outcome;
use crate::context::actor::state::ContextLifecycleState;

/// Dispatch a [`LifecycleControlCommand`] against actor state.
///
/// Handles lifecycle control commands synchronously and with an `Ok`
/// reply so the bridge's `suspend()` default body can complete. The
/// state mutations (e.g. flipping `lifecycle_state` to `Closing`) are
/// minimal and locally-owned — no persistence, no transport.
pub(crate) async fn dispatch(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    cmd: LifecycleControlCommand,
) -> Outcome<()> {
    match cmd {
        LifecycleControlCommand::Pause { reply } => {
            // Class-C lifecycle flag; coalesced persist (no per-site
            // persist today) — route through the non-persisting Class-C
            // view (ADR-049 §9).
            *cell.class_c_view().lifecycle_state_mut() = ContextLifecycleState::Closing;
            let _ = reply.send(Ok(()));
            Outcome::ok_mutated(())
        }
        LifecycleControlCommand::PersistSync { reply } => {
            // Nothing to persist through a dedicated actor-side buffer:
            // handler mutations persist synchronously via the
            // per-handler persistence helpers, so no pending buffer
            // remains to flush. Acking with Ok matches the semantics —
            // "persist buffer is empty, sync returns immediately".
            let _ = reply.send(Ok(()));
            Outcome::ok(())
        }
        LifecycleControlCommand::Shutdown { reply } => {
            *cell.class_c_view().lifecycle_state_mut() = ContextLifecycleState::Closed;
            let _ = reply.send(Ok(()));
            Outcome::ok_mutated(())
        }
        LifecycleControlCommand::PrepareForReplace { mls_state, reply } => {
            handle_prepare_for_replace(cell, deps, &mls_state, reply)
        }
        // The test-only fault-injection variant is intercepted by the
        // actor's `dispatch_state` (in `actor/mod.rs`) BEFORE it reaches
        // this handler, so it never actually arrives here. The arm exists
        // only to keep the match exhaustive when the `testing` feature adds
        // the variant — it must NOT panic (the handler panic-ban gate), so
        // it is a typed no-op.
        #[cfg(feature = "testing")]
        LifecycleControlCommand::TestInducePanic { .. } => Outcome::ok(()),
    }
}

/// Handle [`LifecycleControlCommand::PrepareForReplace`] — the
/// actor-native replacement gate for `import_context`.
///
/// Runs on the actor's OWN `&mut PerContextState`, so it is naturally
/// serialized with every other command this actor processes — that
/// serialization is what the legacy `write_lock`-guarded import gate
/// (`SupervisorHandle::with_existing_context_for_import`) provided.
///
/// Security invariant: an import MUST NOT overwrite a live context. The
/// handler rejects unless the context's lifecycle state is `Closing |
/// Closed | Expired | Tombstoned`. A second concurrent
/// `PrepareForReplace` is rejected by the terminal-claim check on
/// `state.lifecycle_state` (the first sets it to `Closed`). The crypto
/// teardown / epoch-floor validate+merge (§23.17 Inv 3/4) is a verbatim
/// move of the former import-gate closure. On success the actor claims
/// itself terminal and the run loop exits.
fn handle_prepare_for_replace(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    mls_state: &[u8],
    reply: tokio::sync::oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let ctx_id_bytes = cell.context_id;

    // Terminal-claim guard: a prior PrepareForReplace already claimed
    // (and is terminating) this actor. Reject the racing second import.
    if matches!(cell.lifecycle_state, ContextLifecycleState::Closed) {
        let _ = reply.send(Err(ContextError::MembershipFailed(
            "context is already being replaced".to_owned(),
        )));
        return Outcome::ok(());
    }

    // Security invariant: never overwrite a LIVE context. A `Poisoned`
    // context (ADR-049 §10) is dead — its actor exhausted the respawn budget
    // and is no longer serving the context — so it is replaceable, exactly
    // like the terminal states. Including it here lets an import / replace
    // recover a poisoned id without first requiring an operator `clear_poison`.
    let replaceable = matches!(
        cell.handle.state(),
        ContextState::Closing
            | ContextState::Closed
            | ContextState::Expired
            | ContextState::Tombstoned
            | ContextState::Poisoned
    );
    if !replaceable {
        let _ = reply.send(Err(ContextError::MembershipFailed(
            "context already exists — cannot import".to_owned(),
        )));
        return Outcome::ok(());
    }

    // §23.17 Invariant 3/4: capture-before-teardown + restore + validate/merge
    // the per-sender epoch floors (replay-regression guard), via the SINGLE
    // floor-guarded helper shared with the supervisor-side import branches so
    // no path can bypass the guard. On any failure (e.g. a
    // `SnapshotFloorRegression` replay rejection) the helper has already rolled
    // back the crypto; surface the error and leave the actor live (NO terminal
    // claim) so a rejected/replayed import cannot terminate a live context.
    // `PrepareForReplace` is driven by `import_context` — an UNTRUSTED peer
    // snapshot. Use Invariant 3 (reject-on-regression): `trusted_local = false`.
    if let Err(e) = crate::context::lifecycle_helpers::restore_crypto_state_with_floor_guard(
        deps,
        &ctx_id_bytes,
        mls_state,
        false,
    ) {
        let _ = reply.send(Err(e));
        return Outcome::ok(());
    }

    // Claim the slot terminal (rejects a racing second PrepareForReplace)
    // and signal run() to exit so the supervisor can despawn + respawn.
    // Class-C lifecycle flag, coalesced persist — non-persisting Class-C
    // view (ADR-049 §9).
    *cell.class_c_view().lifecycle_state_mut() = ContextLifecycleState::Closed;
    let _ = reply.send(Ok(()));
    Outcome::ok_mutated(())
}
