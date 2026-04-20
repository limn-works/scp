//! Broadcast handlers — see
//! [`BroadcastCommand`](crate::context::actor::commands::BroadcastCommand)
//! and plan §"Broadcast contexts".
//!
//! Commit 6 lands the dispatch stub. Real handlers migrate in commit 11.

use scp_protocol::context::ContextError;

use crate::context::actor::commands::BroadcastCommand;
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::outcome::Outcome;
use crate::context::actor::state::PerContextState;

/// Dispatch a [`BroadcastCommand`] against actor state.
pub async fn dispatch(
    _state: &mut PerContextState,
    _deps: &ActorDeps,
    cmd: BroadcastCommand,
) -> Outcome<()> {
    match cmd {
        BroadcastCommand::Placeholder { reply } => {
            let err = ContextError::NotImplemented(
                "broadcast handler — migrates in commit 11 of ADR-049".to_owned(),
            );
            let _ = reply.send(Err(err));
            Outcome::err(ContextError::NotImplemented(
                "broadcast handler — migrates in commit 11 of ADR-049".to_owned(),
            ))
        }
    }
}
