//! Query handlers — pure-read surface over per-context state.
//!
//! See [`QueriesCommand`](crate::context::actor::commands::QueriesCommand)
//! for the full variant set. Every handler takes a borrowed
//! [`PerContextState`](crate::context::state::PerContextState) plus the
//! shared event-log provider, and returns
//! `Outcome { mutated: false }` by construction — the dispatch function
//! uses [`Outcome::ok(())`](crate::context::actor::outcome::Outcome::ok)
//! on every arm. Mutating operations historically colocated in
//! `manager/queries.rs` (e.g. `drain_events`, `compare_remote_checkpoint`,
//! access-key management) are explicitly **not** migrated here: they
//! continue to route through the legacy `ContextManager` until their
//! owning handler file migrates in commits 8-11.
//!
//! # ADR-049 commit 12c.7 — direct dispatch
//!
//! Prior to 12c.7 each handler took a `QueryStateView<'_>` borrow
//! adapter that bundled per-field references plus the shared event-log
//! provider. Commit 12c.7 deletes that adapter: the supervisor now
//! passes the locked `&PerContextState` and the
//! `&Arc<dyn ContextEventLogProvider>` directly, and the handler reads
//! the same accessor methods (`state.membership()`, `state.role_state()`,
//! …) the adapter wrapped. Behaviour is byte-identical — the field set
//! the dispatch arms read is unchanged.
//!
//! # Pre-lookup validation
//!
//! The shim on [`Supervisor::dispatch_query`](crate::context::supervisor::supervisor::Supervisor::dispatch_query)
//! resolves the `context_id` to a state borrow BEFORE calling this
//! dispatch fn. A missing context is routed directly by the shim to the
//! variant's legacy default (e.g. `MemberCount::Ok(None)`,
//! `IsMember::Ok(false)`, `MemberDids::Ok(Vec::new())`, etc.) — the
//! handler functions here never see a missing-context case. Variants
//! whose legacy method returns `ContextError::ContextNotRegistered` also
//! route that error through the shim before reaching the handler.

use std::sync::Arc;

use scp_protocol::context::ContextError;
use zeroize::Zeroizing;

use crate::context::actor::commands::QueriesCommand;
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::outcome::Outcome;
use crate::context::builder::ContextEventLogProvider;
use crate::context::state::PerContextState;

/// Dispatch a [`QueriesCommand`] against a per-context read borrow. Every
/// arm sends a typed reply on the variant's oneshot and returns
/// `Outcome::ok(())` — handlers never mutate state and therefore never
/// flip the actor's `dirty` flag.
///
/// Plan-conforming dispatch signature — matches the actor's
/// `run()` loop call shape (`handlers::queries::dispatch(&self.state,
/// &self.deps, cmd).await`). `deps` is accepted for symmetry with the
/// mutating handler contract landing in commits 8-11. Queries are
/// pure-read and do not use `deps`; the per-context state plus the
/// shared event-log provider carry every borrow the handler needs.
///
/// This entry point is unused during the commits-7-to-11 migration
/// window — the live dispatch path goes through
/// [`dispatch_from_shim`], which is `fn` (sync) since no handler arm
/// awaits. The signature here is preserved so that commit 12's
/// actor-`run()` migration wires this function into the `select!` arm
/// without further churn.
///
/// `pub(crate)` because the parameter type
/// [`PerContextState`](crate::context::state::PerContextState) is
/// `pub(crate)` (it lives on the legacy `ContextManager` shim and is
/// deleted in commit 12). The actor's `run()` loop lives in the same
/// crate so this visibility is sufficient.
///
/// `dead_code` allow: the live dispatch path during the commits-7-to-11
/// migration window goes through [`dispatch_from_shim`] (sync, no
/// `ActorDeps` plumbing needed). This `dispatch` entry point is the
/// post-refactor signature the actor's `run()` loop will call in commit
/// 12; it has no production caller until then.
///
/// `future_not_send` allow: the body is synchronous (no awaits) — the
/// `async fn` shape only exists to match the post-refactor actor `run()`
/// loop's call site, which awaits each handler dispatch uniformly.
/// `PerContextState` is not `Sync` (the legacy manager's per-context
/// state holds an event-broadcast `dyn FnMut + Send` callback whose
/// type does not bound on Sync), so the captured `&PerContextState`
/// makes the future non-`Send`. The actor's run loop in commit 12 will
/// own the state by move, eliminating the borrow and this allow.
#[allow(dead_code, clippy::future_not_send)]
pub(crate) async fn dispatch(
    state: &PerContextState,
    _deps: &ActorDeps,
    event_log: &Arc<dyn ContextEventLogProvider>,
    cmd: QueriesCommand,
) -> Outcome<()> {
    dispatch_from_shim(state, event_log, cmd)
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
/// exists to avoid that churn — it takes the state borrow + the
/// shared event-log provider directly.
#[allow(clippy::too_many_lines)] // flat match over every query variant
pub(crate) fn dispatch_from_shim(
    state: &PerContextState,
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
            // `ContextManager::event_log_provider_arc()`. The handler
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
