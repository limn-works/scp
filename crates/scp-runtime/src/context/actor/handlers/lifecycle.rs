//! Lifecycle handlers — see
//! [`LifecycleCommand`](crate::context::actor::commands::LifecycleCommand)
//! and plan §"Submodule organization".
//!
//! Commit 6 lands the dispatch stub. Real handlers (`create_context`,
//! `join_context`, `leave_context`, `close_context`) migrate in commit 9.

use scp_protocol::context::ContextError;

use crate::context::actor::commands::LifecycleCommand;
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::outcome::Outcome;
use crate::context::actor::state::PerContextState;

/// Dispatch a [`LifecycleCommand`] against actor state.
pub async fn dispatch(
    _state: &mut PerContextState,
    _deps: &ActorDeps,
    cmd: LifecycleCommand,
) -> Outcome<()> {
    match cmd {
        LifecycleCommand::Placeholder { reply } => {
            let err = ContextError::NotImplemented(
                "lifecycle handler — migrates in commit 9 of ADR-049".to_owned(),
            );
            let _ = reply.send(Err(err));
            Outcome::err(ContextError::NotImplemented(
                "lifecycle handler — migrates in commit 9 of ADR-049".to_owned(),
            ))
        }
    }
}
