//! Push handlers: see
//! [`PushCommand`](crate::context::actor::commands::PushCommand) and
//! `10-infrastructure-and-self-hosting.md` §10.7.1.
//!
//! Read-only by construction: [`dispatch`] borrows the actor-owned state
//! shared, returns `Outcome { mutated: false }`, and answers each arm from
//! the matching helper in [`crate::context::push_helpers`].

use crate::context::actor::commands::PushCommand;
use crate::context::actor::outcome::Outcome;
use crate::context::actor::state::PerContextState;
use crate::context::push_helpers;

/// Actor-shape dispatch for a [`PushCommand`].
///
/// Synchronous: every arm is a pure read of `state`, so the actor's
/// `dispatch_state` calls it with a shared borrow of the cell's state and no
/// future holds the non-`Sync` cell.
pub(crate) fn dispatch(state: &PerContextState, cmd: PushCommand) -> Outcome<()> {
    match cmd {
        PushCommand::Routes { reply } => {
            let _ = reply.send(push_helpers::push_routes(state));
            Outcome::ok(())
        }
        PushCommand::WakeTarget { reply } => {
            let _ = reply.send(push_helpers::wake_target(state));
            Outcome::ok(())
        }
    }
}
