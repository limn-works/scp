//! Governance handlers — see
//! [`GovernanceCommand`](crate::context::actor::commands::GovernanceCommand)
//! and plan §"Submodule organization".
//!
//! Commit 6 lands the dispatch stub. The 28 governance actions (ADR-031)
//! migrate in commit 10.

use scp_protocol::context::ContextError;

use crate::context::actor::commands::GovernanceCommand;
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::outcome::Outcome;
use crate::context::actor::state::PerContextState;

/// Dispatch a [`GovernanceCommand`] against actor state.
pub async fn dispatch(
    _state: &mut PerContextState,
    _deps: &ActorDeps,
    cmd: GovernanceCommand,
) -> Outcome<()> {
    match cmd {
        GovernanceCommand::Placeholder { reply } => {
            let err = ContextError::NotImplemented(
                "governance handler — migrates in commit 10 of ADR-049".to_owned(),
            );
            let _ = reply.send(Err(err));
            Outcome::err(ContextError::NotImplemented(
                "governance handler — migrates in commit 10 of ADR-049".to_owned(),
            ))
        }
    }
}
