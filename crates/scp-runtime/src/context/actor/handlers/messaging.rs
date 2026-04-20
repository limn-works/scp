//! Messaging handlers — see [`MessagingCommand`](crate::context::actor::commands::MessagingCommand)
//! and plan §"Submodule organization".
//!
//! Commit 6 lands the dispatch stub. Real handler bodies (`handle_send`,
//! `handle_deliver`, sender-key rotation, decrypt) migrate in commit 8.

use scp_protocol::context::ContextError;
use tokio::sync::oneshot;

use crate::context::actor::commands::MessagingCommand;
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::outcome::Outcome;
use crate::context::actor::state::PerContextState;

/// Dispatch a [`MessagingCommand`] against actor state. Commit 6 stub —
/// every variant replies `NotImplemented` and returns `Outcome::err`
/// with `mutated: false`.
pub async fn dispatch(
    _state: &mut PerContextState,
    _deps: &ActorDeps,
    cmd: MessagingCommand,
) -> Outcome<()> {
    match cmd {
        MessagingCommand::Placeholder { reply } => reply_not_implemented(reply),
    }
}

fn reply_not_implemented(reply: oneshot::Sender<Result<(), ContextError>>) -> Outcome<()> {
    let err = ContextError::NotImplemented(
        "messaging handler — migrates in commit 8 of ADR-049".to_owned(),
    );
    // Drop-tolerant: if the caller's receiver is gone, send returns Err.
    // That is the intentional cancellation path; we ignore the result.
    let _ = reply.send(Err(err));
    Outcome::err(ContextError::NotImplemented(
        "messaging handler — migrates in commit 8 of ADR-049".to_owned(),
    ))
}
