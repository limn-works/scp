#![allow(
    clippy::unused_async,
    clippy::doc_markdown,
    clippy::too_long_first_doc_paragraph
)]
//! Push handlers: see
//! [`PushCommand`](scp_runtime_core::context::actor::commands::PushCommand) and
//! `10-infrastructure-and-self-hosting.md` §10.7.1.
//!
//! Read-only by construction: [`dispatch`] borrows the actor-owned state
//! shared, returns `Outcome { mutated: false }`, and answers each arm from
//! the matching helper in [`crate::helpers`].

use crate::helpers;
use scp_runtime_core::context::actor::commands::PushCommand;
use scp_runtime_core::context::actor::outcome::Outcome;
use scp_runtime_core::context::actor::state::PerContextState;

/// Actor-shape dispatch for a [`PushCommand`].
///
/// Synchronous: every arm is a pure read of `state`, so the actor's
/// `dispatch_state` calls it with a shared borrow of the cell's state and no
/// future holds the non-`Sync` cell.
pub fn dispatch(state: &PerContextState, cmd: PushCommand) -> Outcome<()> {
    match cmd {
        PushCommand::Routes { reply } => {
            let _ = reply.send(scp_runtime_core::context::push_routes::push_routes(state));
            Outcome::ok(())
        }
        PushCommand::WakeTarget { reply } => {
            let _ = reply.send(helpers::wake_target(state));
            Outcome::ok(())
        }
    }
}
