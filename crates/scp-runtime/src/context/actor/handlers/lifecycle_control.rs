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
//! These handlers respond to supervisor-originated Pause / Resume /
//! Shutdown / PersistSync commands. Commit 6 lands the dispatch stub
//! that ACKS with `Ok(())` for the lifecycle control commands — the
//! `BridgeInstanceCore::suspend()` default trait method sends `Pause`
//! and `PersistSync` against the actor handle and expects an ack so
//! the suspend flow completes.
//!
//! The ack-with-`Ok` (rather than `NotImplemented`) keeps the suspend
//! path from erroring out during commit 6. Actual persist-sync logic
//! migrates in commit 11; before that, the handler has no persist
//! buffer to flush because no state mutation has happened through the
//! actor path yet.

use scp_protocol::context::{ContextError, ContextState};

use crate::context::actor::commands::LifecycleControlCommand;
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::outcome::Outcome;
use crate::context::actor::state::{ContextLifecycleState, PerContextState};

/// Dispatch a [`LifecycleControlCommand`] against actor state.
///
/// Commit 6 handles lifecycle control commands synchronously and with
/// an `Ok` reply so the bridge's `suspend()` default body can complete.
/// The state mutations (e.g. flipping `lifecycle_state` to `Closing`)
/// are minimal and locally-owned — no persistence, no transport.
pub async fn dispatch(
    state: &mut PerContextState,
    deps: &ActorDeps,
    cmd: LifecycleControlCommand,
) -> Outcome<()> {
    match cmd {
        LifecycleControlCommand::Pause { reply } => {
            state.lifecycle_state = ContextLifecycleState::Closing;
            let _ = reply.send(Ok(()));
            Outcome::ok_mutated(())
        }
        LifecycleControlCommand::PersistSync { reply } => {
            // Commit 6: nothing to persist through the actor path yet
            // because the legacy `ContextManager` still owns mutating
            // paths. Acking with Ok matches the eventual semantics —
            // "persist buffer is empty, sync returns immediately".
            let _ = reply.send(Ok(()));
            Outcome::ok(())
        }
        LifecycleControlCommand::Shutdown { reply } => {
            state.lifecycle_state = ContextLifecycleState::Closed;
            let _ = reply.send(Ok(()));
            Outcome::ok_mutated(())
        }
        LifecycleControlCommand::PrepareForReplace { mls_state, reply } => {
            handle_prepare_for_replace(state, deps, &mls_state, reply)
        }
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
    state: &mut PerContextState,
    deps: &ActorDeps,
    mls_state: &[u8],
    reply: tokio::sync::oneshot::Sender<Result<(), ContextError>>,
) -> Outcome<()> {
    let ctx_id_bytes = state.context_id;

    // Terminal-claim guard: a prior PrepareForReplace already claimed
    // (and is terminating) this actor. Reject the racing second import.
    if matches!(state.lifecycle_state, ContextLifecycleState::Closed) {
        let _ = reply.send(Err(ContextError::MembershipFailed(
            "context is already being replaced".to_owned(),
        )));
        return Outcome::ok(());
    }

    // Security invariant: never overwrite a LIVE context.
    let replaceable = state.handle.try_read_state().is_some_and(|s| {
        matches!(
            s,
            ContextState::Closing
                | ContextState::Closed
                | ContextState::Expired
                | ContextState::Tombstoned
        )
    });
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
    if let Err(e) = crate::context::lifecycle_helpers::restore_crypto_state_with_floor_guard(
        deps,
        &ctx_id_bytes,
        mls_state,
    ) {
        let _ = reply.send(Err(e));
        return Outcome::ok(());
    }

    // Claim the slot terminal (rejects a racing second PrepareForReplace)
    // and signal run() to exit so the supervisor can despawn + respawn.
    state.lifecycle_state = ContextLifecycleState::Closed;
    let _ = reply.send(Ok(()));
    Outcome::ok_mutated(())
}
