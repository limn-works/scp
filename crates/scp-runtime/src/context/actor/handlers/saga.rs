//! Saga-phase handlers — see
//! [`SagaPhaseMessage`](crate::context::actor::commands::SagaPhaseMessage)
//! and plan §"Cross-context saga protocol".
//!
//! Commit 6 lands the dispatch stub. Real handlers (Prepare, Commit,
//! Abort from the supervisor) migrate in commit 11 alongside the
//! saga-initiator paths.

use scp_protocol::context::ContextError;

use crate::context::actor::commands::SagaPhaseMessage;
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::outcome::Outcome;
use crate::context::actor::state::PerContextState;

/// Dispatch a [`SagaPhaseMessage`] against actor state.
pub async fn dispatch(
    _state: &mut PerContextState,
    _deps: &ActorDeps,
    cmd: SagaPhaseMessage,
) -> Outcome<()> {
    match cmd {
        SagaPhaseMessage::Placeholder { reply } => {
            let err = ContextError::NotImplemented(
                "saga-phase handler — migrates in commit 11 of ADR-049".to_owned(),
            );
            let _ = reply.send(Err(err));
            Outcome::err(ContextError::NotImplemented(
                "saga-phase handler — migrates in commit 11 of ADR-049".to_owned(),
            ))
        }
    }
}
