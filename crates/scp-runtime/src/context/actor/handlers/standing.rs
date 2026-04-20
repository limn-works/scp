//! Standing-pair handlers — see
//! [`StandingCommand`](crate::context::actor::commands::StandingCommand)
//! and spec §5.15.7.
//!
//! Commit 6 lands the dispatch stub. Real handlers migrate in commit 11
//! alongside the rest of the saga-initiator paths.

use scp_protocol::context::ContextError;

use crate::context::actor::commands::StandingCommand;
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::outcome::Outcome;
use crate::context::actor::state::PerContextState;

/// Dispatch a [`StandingCommand`] against actor state.
pub async fn dispatch(
    _state: &mut PerContextState,
    _deps: &ActorDeps,
    cmd: StandingCommand,
) -> Outcome<()> {
    match cmd {
        StandingCommand::Placeholder { reply } => {
            let err = ContextError::NotImplemented(
                "standing handler — migrates in commit 11 of ADR-049".to_owned(),
            );
            let _ = reply.send(Err(err));
            Outcome::err(ContextError::NotImplemented(
                "standing handler — migrates in commit 11 of ADR-049".to_owned(),
            ))
        }
    }
}
