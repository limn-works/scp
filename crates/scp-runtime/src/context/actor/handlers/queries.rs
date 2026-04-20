//! Query handlers — see
//! [`QueriesCommand`](crate::context::actor::commands::QueriesCommand).
//!
//! Queries are **pure-read**. Handlers take `&PerContextState` (shared
//! borrow) and MUST return `Outcome { mutated: false }`. The dispatch
//! signature below reflects the shared borrow.
//!
//! Commit 6 lands the dispatch stub — commit 7 is the first real
//! migration (queries are the lowest-blast-radius path per plan "commit
//! ladder").

use scp_protocol::context::ContextError;

use crate::context::actor::commands::QueriesCommand;
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::outcome::Outcome;
use crate::context::actor::state::PerContextState;

/// Dispatch a [`QueriesCommand`] against actor state.
///
/// Takes `&PerContextState` — query handlers MUST NOT mutate. The
/// `Outcome` returned has `mutated: false` by construction via
/// [`Outcome::err`] / [`Outcome::ok`].
pub async fn dispatch(
    _state: &PerContextState,
    _deps: &ActorDeps,
    cmd: QueriesCommand,
) -> Outcome<()> {
    match cmd {
        QueriesCommand::Placeholder { reply } => {
            let err = ContextError::NotImplemented(
                "queries handler — migrates in commit 7 of ADR-049".to_owned(),
            );
            let _ = reply.send(Err(err));
            Outcome::err(ContextError::NotImplemented(
                "queries handler — migrates in commit 7 of ADR-049".to_owned(),
            ))
        }
    }
}
