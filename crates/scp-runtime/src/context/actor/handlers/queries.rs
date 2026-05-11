//! Query handlers — pure-read surface over per-context state.
//!
//! See [`QueriesCommand`](crate::context::actor::commands::QueriesCommand)
//! for the full variant set. Every handler takes a borrowed actor-owned
//! [`PerContextState`](crate::context::actor::state::PerContextState)
//! plus the capability-reduced [`ActorDeps`](crate::context::actor::deps::ActorDeps),
//! and returns `Outcome { mutated: false }` by construction — the
//! dispatch function uses [`Outcome::ok(())`](crate::context::actor::outcome::Outcome::ok)
//! on every arm.
//!
//! # Single dispatch entry point
//!
//! - [`dispatch`] — actor-shape entry point. Takes `(&state, &deps,
//!   cmd)` and routes to the actor-shape helpers in
//!   [`crate::context::queries_helpers`] which operate on
//!   actor-owned `PerContextState` directly. The actor's
//!   [`dispatch_state`](crate::context::actor::ContextActor::dispatch_state)
//!   loop is the only production caller.
//!
//! The prior `dispatch_from_shim` entry point (locked legacy state +
//! shared event-log provider) was deleted in the Phase 2A finalization
//! queries+lifecycle session. Unknown-context routing now lands on
//! [`Supervisor::dispatch_queries_direct`](crate::context::supervisor::supervisor::Supervisor)
//! which surfaces the variant's legacy default (or
//! `ContextError::ContextNotRegistered` for the hard-error variants)
//! directly on the reply oneshot.

use scp_protocol::context::ContextError;

use crate::context::actor::commands::QueriesCommand;
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::outcome::Outcome;
// ADR-049 Phase 2A finalization keystone (commit 12 phase 2A
// finalization — type unification, single PerContextState): the prior
// `ActorPerContextState` / legacy alias pair collapsed to a single
// type. The `ActorPerContextState` alias is preserved here purely as a
// variable-name affordance for the dispatch surface.
use crate::context::actor::state::PerContextState as ActorPerContextState;
use crate::context::queries_helpers;

/// Actor-shape dispatch — routes a [`QueriesCommand`] against the
/// actor's owned `&PerContextState` and `&ActorDeps`.
///
/// Each variant calls the matching actor-shape helper in
/// [`crate::context::queries_helpers`], which carries the read body
/// (no `&Supervisor`, no shim escape). Returns `Outcome { mutated:
/// false }` on every arm — read-only by construction.
///
/// # `local_dids` gate
///
/// [`QueriesCommand::GetBroadcastKeyForLocalAuthor`] requires the
/// `author_did` to be locally controlled. The actor reads its own
/// `deps.local_dids` snapshot to enforce this gate before calling the
/// per-context body — `local_dids` is supervisor-scoped (an `ArcSwap`
/// shared across all actors) and is not part of `state`.
///
/// `state` is taken as `&mut` even though every read variant only
/// borrows immutably, so the resulting future is `Send` (an `&PerContextState`
/// borrow makes the captured future non-`Send` because `PerContextState`
/// is not `Sync` — the per-context event callback is `dyn FnMut + Send`,
/// not `Send + Sync`). The actor's run loop owns `state` exclusively so
/// the upgraded borrow does not race; the body still treats `state` as
/// read-only — every helper called here takes `&PerContextState`.
#[allow(clippy::too_many_lines, clippy::needless_pass_by_ref_mut)]
pub(crate) async fn dispatch(
    state: &mut ActorPerContextState,
    deps: &ActorDeps,
    cmd: QueriesCommand,
) -> Outcome<()> {
    match cmd {
        QueriesCommand::LocalPseudonym {
            context_id: _,
            reply,
        } => {
            let answer = queries_helpers::local_pseudonym(state);
            let _ = reply.send(Ok(answer));
            Outcome::ok(())
        }

        QueriesCommand::GetBroadcastKeyForLocalAuthor {
            context_id: _,
            author_did,
            reply,
        } => {
            // local_dids gate: the author must be locally controlled.
            // local_dids lives on the supervisor (ArcSwap shared across
            // actors); read it from `deps`.
            let result = if deps.local_dids.load().contains(author_did.as_str()) {
                queries_helpers::get_broadcast_key_for_local_author(state, &author_did)
            } else {
                Err(ContextError::PermissionDenied(format!(
                    "author DID is not controlled by the local node: {author_did}"
                )))
            };
            let _ = reply.send(result);
            Outcome::ok(())
        }

        QueriesCommand::MemberCount {
            context_id: _,
            reply,
        } => {
            let answer = Some(queries_helpers::member_count(state));
            let _ = reply.send(Ok(answer));
            Outcome::ok(())
        }

        QueriesCommand::IsMember {
            context_id: _,
            did,
            reply,
        } => {
            let answer = queries_helpers::is_member(state, did.as_str());
            let _ = reply.send(Ok(answer));
            Outcome::ok(())
        }

        QueriesCommand::MemberDids {
            context_id: _,
            reply,
        } => {
            let answer = queries_helpers::member_dids(state);
            let _ = reply.send(Ok(answer));
            Outcome::ok(())
        }

        QueriesCommand::MemberRole {
            context_id: _,
            did,
            reply,
        } => {
            let answer = queries_helpers::member_role(state, did.as_str());
            let _ = reply.send(Ok(answer));
            Outcome::ok(())
        }

        QueriesCommand::ContextParams {
            context_id: _,
            reply,
        } => {
            let answer = Some(queries_helpers::context_params(state));
            let _ = reply.send(Ok(answer));
            Outcome::ok(())
        }

        QueriesCommand::GetRoleState {
            context_id: _,
            reply,
        } => {
            let answer = Some(queries_helpers::get_role_state(state));
            let _ = reply.send(Ok(answer));
            Outcome::ok(())
        }

        QueriesCommand::PendingCommits {
            context_id: _,
            reply,
        } => {
            let answer = queries_helpers::pending_commits(state);
            let _ = reply.send(Ok(answer));
            Outcome::ok(())
        }

        QueriesCommand::CommitFault {
            context_id: _,
            reply,
        } => {
            let answer = queries_helpers::commit_fault(state);
            let _ = reply.send(Ok(answer));
            Outcome::ok(())
        }

        QueriesCommand::EventLogEntries {
            context_id_bytes,
            reply,
        } => {
            // Shared event-log provider on `deps` — no per-context
            // state involved.
            let answer = queries_helpers::event_log_entries(deps, &context_id_bytes);
            let _ = reply.send(answer);
            Outcome::ok(())
        }

        #[cfg(feature = "testing")]
        QueriesCommand::GetAccessKey {
            context_id,
            member_did,
            reply,
        } => {
            let answer =
                queries_helpers::get_access_key(state, context_id.as_str(), member_did.as_str());
            let _ = reply.send(Ok(answer));
            Outcome::ok(())
        }

        #[cfg(feature = "testing")]
        QueriesCommand::GetAllAccessKeys { context_id, reply } => {
            let answer = queries_helpers::get_all_access_keys(state, context_id.as_str());
            let _ = reply.send(Ok(answer));
            Outcome::ok(())
        }

        #[cfg(feature = "testing")]
        QueriesCommand::RemainingBudgetForTest {
            context_id: _,
            member_did,
            reply,
        } => {
            let answer = queries_helpers::remaining_budget_for_test(state, &member_did);
            let _ = reply.send(Ok(answer));
            Outcome::ok(())
        }

        #[cfg(feature = "testing")]
        QueriesCommand::VelocityForTest {
            context_id: _,
            member_did,
            now_secs,
            reply,
        } => {
            let answer = queries_helpers::velocity_for_test(state, &member_did, now_secs);
            let _ = reply.send(Ok(answer));
            Outcome::ok(())
        }
    }
}
