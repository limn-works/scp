//! Trust-recovery handlers — see
//! [`TrustRecoveryCommand`](crate::context::actor::commands::TrustRecoveryCommand)
//! and spec §23.17 (import floor reconciliation).
//!
//! Commit 6 lands the dispatch stub. Real handlers migrate in commit 10.

use scp_protocol::context::ContextError;

use crate::context::actor::commands::TrustRecoveryCommand;
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::outcome::Outcome;
use crate::context::actor::state::PerContextState;

/// Dispatch a [`TrustRecoveryCommand`] against actor state.
pub async fn dispatch(
    _state: &mut PerContextState,
    _deps: &ActorDeps,
    cmd: TrustRecoveryCommand,
) -> Outcome<()> {
    match cmd {
        TrustRecoveryCommand::Placeholder { reply } => {
            let err = ContextError::NotImplemented(
                "trust-recovery handler — migrates in commit 10 of ADR-049".to_owned(),
            );
            let _ = reply.send(Err(err));
            Outcome::err(ContextError::NotImplemented(
                "trust-recovery handler — migrates in commit 10 of ADR-049".to_owned(),
            ))
        }
    }
}
