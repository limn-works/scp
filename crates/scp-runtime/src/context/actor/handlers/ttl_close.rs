//! TTL-close handlers — see
//! [`TtlCloseCommand`](crate::context::actor::commands::TtlCloseCommand)
//! and spec §5.8.
//!
//! Commit 6 lands the dispatch stub. Real handlers migrate in commit 9.

use scp_protocol::context::ContextError;

use crate::context::actor::commands::TtlCloseCommand;
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::outcome::Outcome;
use crate::context::actor::state::PerContextState;

/// Dispatch a [`TtlCloseCommand`] against actor state.
pub async fn dispatch(
    _state: &mut PerContextState,
    _deps: &ActorDeps,
    cmd: TtlCloseCommand,
) -> Outcome<()> {
    match cmd {
        TtlCloseCommand::Placeholder { reply } => {
            let err = ContextError::NotImplemented(
                "ttl-close handler — migrates in commit 9 of ADR-049".to_owned(),
            );
            let _ = reply.send(Err(err));
            Outcome::err(ContextError::NotImplemented(
                "ttl-close handler — migrates in commit 9 of ADR-049".to_owned(),
            ))
        }
    }
}
