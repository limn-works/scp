//! Query handlers — pure-read surface over per-context state.
//!
//! See [`QueriesCommand`](crate::context::actor::commands::QueriesCommand)
//! for the full variant set. Every handler takes a
//! [`QueryStateView<'_>`](crate::context::actor::query_state_view::QueryStateView)
//! (shared borrow) and returns `Outcome { mutated: false }` by
//! construction — the dispatch function uses
//! [`Outcome::ok(())`](crate::context::actor::outcome::Outcome::ok) on
//! every arm. Mutating operations historically colocated in
//! `manager/queries.rs` (e.g. `drain_events`, `compare_remote_checkpoint`,
//! access-key management) are explicitly **not** migrated here: they
//! continue to route through the legacy `ContextManager` until their
//! owning handler file migrates in commits 8-11.
//!
//! Commit 7 (this commit): first real handler migration. The transitional
//! [`QueryStateView`](crate::context::actor::query_state_view::QueryStateView)
//! borrow adapter bridges legacy `manager::PerContextState` to the new
//! handler shape. View + this handler file are both deleted in commit 12
//! alongside `ContextManager`.
//!
//! # Pre-lookup validation
//!
//! The shim on [`Supervisor::dispatch_query`](crate::context::supervisor::supervisor::Supervisor::dispatch_query)
//! resolves the `context_id` to a view BEFORE calling this dispatch fn.
//! A missing context is routed directly by the shim to the variant's
//! legacy default (e.g. `MemberCount::Ok(None)`, `IsMember::Ok(false)`,
//! `MemberDids::Ok(Vec::new())`, etc.) — the handler functions here
//! never see a missing-context case. Variants whose legacy method
//! returns `ContextError::ContextNotRegistered` also route that error
//! through the shim before reaching the handler.

use scp_protocol::context::ContextError;
use zeroize::Zeroizing;

use crate::context::actor::commands::QueriesCommand;
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::outcome::Outcome;
use crate::context::actor::query_state_view::QueryStateView;

/// Dispatch a [`QueriesCommand`] against a per-context read view. Every
/// arm sends a typed reply on the variant's oneshot and returns
/// `Outcome::ok(())` — handlers never mutate state and therefore never
/// flip the actor's `dirty` flag.
///
/// Plan-conforming dispatch signature — matches the actor's
/// `run()` loop call shape (`handlers::queries::dispatch(&self.state,
/// &self.deps, cmd).await`). `deps` is accepted for symmetry with the
/// mutating handler contract landing in commits 8-11. Queries are
/// pure-read and do not use `deps`; the view already carries every
/// borrow (including the shared event-log provider).
///
/// This entry point is unused during the commits-7-to-11 migration
/// window — the live dispatch path goes through
/// [`dispatch_from_shim`], which does not require an `ActorDeps`
/// construction. The signature here is preserved so that commit 12's
/// actor-`run()` migration wires this function into the `select!` arm
/// without further churn.
pub async fn dispatch(
    view: &QueryStateView<'_>,
    _deps: &ActorDeps,
    cmd: QueriesCommand,
) -> Outcome<()> {
    dispatch_from_shim(view, cmd)
}

/// Shim-callable dispatch. Used by
/// [`Supervisor::dispatch_query`](crate::context::supervisor::supervisor::Supervisor::dispatch_query)
/// during the commits-7-to-11 migration window — deleted in commit 12
/// when the shim dissolves and the actor's `run()` loop is the only
/// caller of [`dispatch`].
///
/// Queries do not touch `ActorDeps`; requiring callers to synthesize an
/// `ActorDeps` instance just to read a member count would force the shim
/// into constructing every actor dependency (transport, MLS/HPKE
/// backends, KP store) before answering a no-op query. This entry point
/// exists to avoid that churn — it takes only the view and the command.
#[allow(clippy::too_many_lines)] // flat match over every query variant
pub(crate) fn dispatch_from_shim(view: &QueryStateView<'_>, cmd: QueriesCommand) -> Outcome<()> {
    match cmd {
        QueriesCommand::LocalPseudonym {
            context_id: _,
            reply,
        } => {
            let answer = view.local_pseudonym.copied();
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
            // not part of `QueryStateView`).
            let result = view.broadcast_context.map_or_else(
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
            let answer = Some(view.membership.count());
            let _ = reply.send(Ok(answer));
            Outcome::ok(())
        }

        QueriesCommand::IsMember {
            context_id: _,
            did,
            reply,
        } => {
            let answer = view.membership.contains(did.as_str());
            let _ = reply.send(Ok(answer));
            Outcome::ok(())
        }

        QueriesCommand::MemberDids {
            context_id: _,
            reply,
        } => {
            let answer: Vec<String> = view
                .membership
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
            let answer = view.role_state.assignments.get(did.as_str()).cloned();
            let _ = reply.send(Ok(answer));
            Outcome::ok(())
        }

        QueriesCommand::ContextParams {
            context_id: _,
            reply,
        } => {
            let answer = Some(view.handle.params().clone());
            let _ = reply.send(Ok(answer));
            Outcome::ok(())
        }

        QueriesCommand::GetRoleState {
            context_id: _,
            reply,
        } => {
            let answer = Some(view.role_state.clone());
            let _ = reply.send(Ok(answer));
            Outcome::ok(())
        }

        QueriesCommand::PendingCommits {
            context_id: _,
            reply,
        } => {
            let answer: Vec<_> = view.pending_commits.iter().cloned().collect();
            let _ = reply.send(Ok(answer));
            Outcome::ok(())
        }

        QueriesCommand::CommitFault {
            context_id: _,
            reply,
        } => {
            let answer = view.commit_fault.cloned();
            let _ = reply.send(Ok(answer));
            Outcome::ok(())
        }

        QueriesCommand::EventLogEntries {
            context_id_bytes,
            reply,
        } => {
            // Shared event-log provider borrowed through the view — the
            // shim populates the view's `event_log` field from
            // `ContextManager::event_log_provider_arc()`. The handler
            // delegates directly without cloning.
            let answer = view.event_log.event_log_entries(&context_id_bytes);
            let _ = reply.send(answer);
            Outcome::ok(())
        }

        #[cfg(feature = "testing")]
        QueriesCommand::GetAccessKey {
            context_id,
            member_did,
            reply,
        } => {
            let answer = view
                .access_key_store
                .get(context_id.as_str(), member_did.as_str())
                .cloned();
            let _ = reply.send(Ok(answer));
            Outcome::ok(())
        }

        #[cfg(feature = "testing")]
        QueriesCommand::GetAllAccessKeys { context_id, reply } => {
            let answer = view.access_key_store.get_all(context_id.as_str());
            let _ = reply.send(Ok(answer));
            Outcome::ok(())
        }

        #[cfg(feature = "testing")]
        QueriesCommand::RemainingBudgetForTest {
            context_id: _,
            member_did,
            reply,
        } => {
            let answer = view.budget_tracker.remaining(&member_did);
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
            let answer = view.velocity_tracker.get_velocity(&member_did, now_secs);
            let _ = reply.send(Ok(answer));
            Outcome::ok(())
        }
    }
}
