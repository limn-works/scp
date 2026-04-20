//! Economy handlers — see
//! [`EconomyCommand`](crate::context::actor::commands::EconomyCommand)
//! and spec §19.
//!
//! Commit 6 lands the dispatch stub. Real handlers migrate in commit 10.

use scp_protocol::context::ContextError;

use crate::context::actor::commands::EconomyCommand;
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::outcome::Outcome;
use crate::context::actor::state::PerContextState;

/// Dispatch an [`EconomyCommand`] against actor state.
pub async fn dispatch(
    _state: &mut PerContextState,
    _deps: &ActorDeps,
    cmd: EconomyCommand,
) -> Outcome<()> {
    match cmd {
        EconomyCommand::Placeholder { reply } => {
            let err = ContextError::NotImplemented(
                "economy handler — migrates in commit 10 of ADR-049".to_owned(),
            );
            let _ = reply.send(Err(err));
            Outcome::err(ContextError::NotImplemented(
                "economy handler — migrates in commit 10 of ADR-049".to_owned(),
            ))
        }
    }
}
