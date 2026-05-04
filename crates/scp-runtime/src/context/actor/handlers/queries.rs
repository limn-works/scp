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
//! # Two dispatch entry points
//!
//! - [`dispatch`] — actor-shape entry point. Takes `(&state, &deps,
//!   cmd)` and routes to the actor-shape helpers in
//!   [`crate::context::queries_helpers`] which operate on
//!   actor-owned `PerContextState` directly. Wired into the actor's
//!   [`dispatch_state`](crate::context::actor::ContextActor::dispatch_state)
//!   loop in Phase 2A.10.
//! - [`dispatch_from_shim`] — legacy shim entry point. Takes the locked
//!   legacy `&crate::context::state::PerContextState` borrow plus the
//!   shared event-log provider and inlines the read bodies directly
//!   against the locked legacy state. Used by
//!   [`Supervisor::dispatch_query`](crate::context::supervisor::supervisor::Supervisor::dispatch_query)
//!   during the Phase 2A migration window for callers without an
//!   attached per-context actor.
//!
//! # Pre-lookup validation
//!
//! The shim on [`Supervisor::dispatch_query`](crate::context::supervisor::supervisor::Supervisor::dispatch_query)
//! resolves the `context_id` to a state borrow BEFORE calling the
//! shim entry point. A missing context is routed directly by the
//! supervisor to the variant's legacy default
//! (e.g. `MemberCount::Ok(None)`, `IsMember::Ok(false)`,
//! `MemberDids::Ok(Vec::new())`, etc.) — the shim handler functions here
//! never see a missing-context case. Variants whose legacy method
//! returns `ContextError::ContextNotRegistered` also route that error
//! through the supervisor before reaching the handler.
//!
//! For the actor-shape [`dispatch`], the per-context actor IS the
//! generation — `state` is always present once the actor has spawned
//! and bootstrap (Create / Join / Restore / Import) populated it.

use std::sync::Arc;

use scp_protocol::context::ContextError;
use zeroize::Zeroizing;

use crate::context::actor::commands::QueriesCommand;
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::outcome::Outcome;
use crate::context::actor::state::PerContextState as ActorPerContextState;
use crate::context::builder::ContextEventLogProvider;
use crate::context::queries_helpers;
use crate::context::state::PerContextState as LegacyPerContextState;

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

/// Shim-callable dispatch. Used by
/// [`Supervisor::dispatch_query`](crate::context::supervisor::supervisor::Supervisor::dispatch_query)
/// during the Phase 2A migration window — deleted in Phase 2A
/// finalization when the supervisor's contexts `DashMap` shim
/// dissolves and the actor's `run()` loop is the only caller of
/// [`dispatch`].
///
/// Reads inline against the locked legacy
/// `&crate::context::state::PerContextState` borrow plus the shared
/// event-log provider — `ActorDeps` is not synthesized for the shim
/// path because the supervisor would have to construct every actor
/// dependency (transport, MLS/HPKE backends, KP store) just to answer
/// a no-op query. The legacy state's accessor methods
/// (`state.local_pseudonym()`, `state.broadcast_context()`, …) carry
/// every borrow the read needs.
#[allow(clippy::too_many_lines)] // flat match over every query variant
pub(crate) fn dispatch_from_shim(
    state: &LegacyPerContextState,
    event_log: &Arc<dyn ContextEventLogProvider>,
    cmd: QueriesCommand,
) -> Outcome<()> {
    match cmd {
        QueriesCommand::LocalPseudonym {
            context_id: _,
            reply,
        } => {
            let answer = state.local_pseudonym().copied();
            let _ = reply.send(Ok(answer));
            Outcome::ok(())
        }

        QueriesCommand::GetBroadcastKeyForLocalAuthor {
            context_id: _,
            author_did,
            reply,
        } => {
            // Membership + key lookup. `author_did` is a locally-controlled
            // DID per the shim's pre-check (the shim enforces the
            // local-DID gate because `local_dids` is supervisor-scoped,
            // not part of the per-context state).
            let result = state.broadcast_context().map_or_else(
                || {
                    Err(ContextError::MembershipFailed(
                        "not a broadcast context".into(),
                    ))
                },
                |bc| {
                    bc.get_author(&author_did).map_or_else(
                        || {
                            Err(ContextError::MemberNotFound(format!(
                                "author not found: {author_did}"
                            )))
                        },
                        |author| {
                            let key_bytes = Zeroizing::new(*author.broadcast_key.as_bytes());
                            Ok((key_bytes, author.epoch))
                        },
                    )
                },
            );
            let _ = reply.send(result);
            Outcome::ok(())
        }

        QueriesCommand::MemberCount {
            context_id: _,
            reply,
        } => {
            let answer = Some(state.membership().count());
            let _ = reply.send(Ok(answer));
            Outcome::ok(())
        }

        QueriesCommand::IsMember {
            context_id: _,
            did,
            reply,
        } => {
            let answer = state.membership().contains(did.as_str());
            let _ = reply.send(Ok(answer));
            Outcome::ok(())
        }

        QueriesCommand::MemberDids {
            context_id: _,
            reply,
        } => {
            let answer: Vec<String> = state
                .membership()
                .member_dids()
                .map(std::string::ToString::to_string)
                .collect();
            let _ = reply.send(Ok(answer));
            Outcome::ok(())
        }

        QueriesCommand::MemberRole {
            context_id: _,
            did,
            reply,
        } => {
            let answer = state.role_state().assignments.get(did.as_str()).cloned();
            let _ = reply.send(Ok(answer));
            Outcome::ok(())
        }

        QueriesCommand::ContextParams {
            context_id: _,
            reply,
        } => {
            let answer = Some(state.handle().params().clone());
            let _ = reply.send(Ok(answer));
            Outcome::ok(())
        }

        QueriesCommand::GetRoleState {
            context_id: _,
            reply,
        } => {
            let answer = Some(state.role_state().clone());
            let _ = reply.send(Ok(answer));
            Outcome::ok(())
        }

        QueriesCommand::PendingCommits {
            context_id: _,
            reply,
        } => {
            let answer: Vec<_> = state.pending_commits().iter().cloned().collect();
            let _ = reply.send(Ok(answer));
            Outcome::ok(())
        }

        QueriesCommand::CommitFault {
            context_id: _,
            reply,
        } => {
            let answer = state.commit_fault().cloned();
            let _ = reply.send(Ok(answer));
            Outcome::ok(())
        }

        QueriesCommand::EventLogEntries {
            context_id_bytes,
            reply,
        } => {
            // Shared event-log provider passed in directly — the shim
            // populates the parameter from
            // `Supervisor::event_log_provider_arc()`. The handler
            // delegates without cloning.
            let answer = event_log.event_log_entries(&context_id_bytes);
            let _ = reply.send(answer);
            Outcome::ok(())
        }

        #[cfg(feature = "testing")]
        QueriesCommand::GetAccessKey {
            context_id,
            member_did,
            reply,
        } => {
            let answer = state
                .access_key_store()
                .get(context_id.as_str(), member_did.as_str())
                .cloned();
            let _ = reply.send(Ok(answer));
            Outcome::ok(())
        }

        #[cfg(feature = "testing")]
        QueriesCommand::GetAllAccessKeys { context_id, reply } => {
            let answer = state.access_key_store().get_all(context_id.as_str());
            let _ = reply.send(Ok(answer));
            Outcome::ok(())
        }

        #[cfg(feature = "testing")]
        QueriesCommand::RemainingBudgetForTest {
            context_id: _,
            member_did,
            reply,
        } => {
            let answer = state.budget_tracker().remaining(&member_did);
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
            let answer = state.velocity_tracker().get_velocity(&member_did, now_secs);
            let _ = reply.send(Ok(answer));
            Outcome::ok(())
        }
    }
}
