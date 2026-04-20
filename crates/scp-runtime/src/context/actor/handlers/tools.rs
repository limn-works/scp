//! Tools handlers — see
//! [`ToolsCommand`](crate::context::actor::commands::ToolsCommand)
//! and spec §5.16 (cross-context tool invocation).
//!
//! Commit 6 lands the dispatch stub. Real handlers migrate in commit 11
//! alongside the other saga-initiator paths.

use scp_protocol::context::ContextError;

use crate::context::actor::commands::ToolsCommand;
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::outcome::Outcome;
use crate::context::actor::state::PerContextState;

/// Dispatch a [`ToolsCommand`] against actor state.
pub async fn dispatch(
    _state: &mut PerContextState,
    _deps: &ActorDeps,
    cmd: ToolsCommand,
) -> Outcome<()> {
    match cmd {
        ToolsCommand::Placeholder { reply } => {
            let err = ContextError::NotImplemented(
                "tools handler — migrates in commit 11 of ADR-049".to_owned(),
            );
            let _ = reply.send(Err(err));
            Outcome::err(ContextError::NotImplemented(
                "tools handler — migrates in commit 11 of ADR-049".to_owned(),
            ))
        }
    }
}
