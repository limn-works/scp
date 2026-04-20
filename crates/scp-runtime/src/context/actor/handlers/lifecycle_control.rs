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

use scp_protocol::context::ContextError;

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
    _deps: &ActorDeps,
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
    }
}

// Quiet the unused-import lint in configurations that don't exercise
// the tests. `ContextError` is referenced through the handler's
// `oneshot::Sender<Result<(), ContextError>>` type — keep the import
// visible so future migration diffs see the intended error type.
#[allow(dead_code)]
const _: fn() -> ContextError = || ContextError::ActorBusy(String::new());
