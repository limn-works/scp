//! Transitional read-only state view for the query-handler migration
//! window (commits 7–11 of ADR-049). Deleted in commit 12 when
//! `manager::PerContextState` goes away and the actor's
//! [`PerContextState`](crate::context::actor::state::PerContextState)
//! absorbs every field the migrated query handlers read.
//!
//! # Why this type exists
//!
//! The commit-ladder plan (row 7, "First handler migration: queries") moves
//! the query handler bodies to `handlers::queries` on the new
//! handler-takes-`&State` shape **before** the actor's `PerContextState`
//! has absorbed the full field set it receives in commits 8–11. During
//! that window, the live query data still lives on
//! [`crate::context::manager::PerContextState`]. This type is the borrow
//! adapter that lets the new handler shape read the live state without
//! forcing the actor-state migration to happen in one giant commit — it
//! is **part of the shim architecture the plan sanctions**, not a DOA
//! decision. Row 12 of the commit ladder deletes it.
//!
//! # Contract
//!
//! - **Borrow-only.** No field owns data. Every field borrows into the
//!   live manager state under a held mutex guard. The view's lifetime is
//!   the guard's lifetime. No clones, no allocations.
//! - **Pure-read.** Handlers receive `&QueryStateView<'_>` (shared
//!   reference) and MUST NOT mutate anything reachable through it.
//!   Queries return `Outcome { mutated: false }` by construction.
//! - **Not a public API.** `pub(crate)` visibility. No FFI export. Not
//!   re-exported from `context::actor::mod` except for internal use.
//!
//! # Field set
//!
//! Every field corresponds to a legacy `ContextManager::queries` read.
//! The comment on each field cites the original query method name so the
//! deletion pass in commit 12 can mechanically verify coverage.

use std::sync::Arc;

use scp_protocol::context::broadcast::BroadcastContext;
use scp_protocol::context::membership::MembershipState;
use scp_protocol::context::roles::ContextRoleState;
use scp_protocol::crypto::access_keys::AccessKeyStore;
use scp_protocol::economy::antispam::SenderVelocityTracker;
use scp_protocol::economy::budget::MemberBudgetTracker;

use crate::context::ContextHandle;
use crate::context::builder::ContextEventLogProvider;
use crate::context::manager::{CommitFaultMarker, PendingCommit, PerContextState};

// ---------------------------------------------------------------------------
// QueryStateView<'a>
// ---------------------------------------------------------------------------

/// Read-only borrow adapter over `manager::PerContextState` used by the
/// migrated query handlers during the commit-7-to-12 window.
///
/// Every field is a borrowed reference into the live per-context state.
/// The caller (the query shim on
/// [`Supervisor::dispatch_query`](crate::context::supervisor::supervisor::Supervisor::dispatch_query))
/// builds the view under a mutex guard, passes it by reference to the
/// handler, and drops the guard after the handler returns. Handlers may
/// not clone, retain, or otherwise escape the borrows.
pub struct QueryStateView<'a> {
    /// Membership tracker (§5, §9.10). Source of `member_count`,
    /// `is_member`, `member_dids`.
    pub(crate) membership: &'a MembershipState,

    /// Role assignments, ceiling, suspensions. Source of `member_role`,
    /// `get_role_state`.
    pub(crate) role_state: &'a ContextRoleState,

    /// Local member's pseudonym routing ID (§9.10.4). `None` for legacy
    /// callers and for broadcast contexts. Source of `local_pseudonym`.
    pub(crate) local_pseudonym: Option<&'a [u8; 32]>,

    /// Broadcast context state. `None` for encrypted contexts. Source of
    /// `get_broadcast_key_for_local_author`.
    pub(crate) broadcast_context: Option<&'a BroadcastContext>,

    /// Context handle; backs `context_params`.
    pub(crate) handle: &'a ContextHandle,

    /// Pending MLS Commit retry queue (PR #1606 C6). Source of
    /// `pending_commits`.
    pub(crate) pending_commits: &'a std::collections::VecDeque<PendingCommit>,

    /// Active commit-fault marker (fail-close state). Source of
    /// `commit_fault`.
    pub(crate) commit_fault: Option<&'a CommitFaultMarker>,

    /// Per-member access-key store (ADR-038). Source of `get_access_key`
    /// and `get_all_access_keys` (both `#[cfg(feature = "testing")]`).
    ///
    /// `cfg_attr(not(feature = "testing"), allow(dead_code))` because
    /// the only consumers (the testing-gated `GetAccessKey` /
    /// `GetAllAccessKeys` query variants) compile out without the
    /// feature; the field is still constructed by
    /// [`Self::from_manager_state`] in every build to keep the borrow
    /// shape stable across feature flags.
    #[cfg_attr(not(feature = "testing"), allow(dead_code))]
    pub(crate) access_key_store: &'a AccessKeyStore,

    /// Per-member budget tracker. Source of `remaining_budget_for_test`
    /// (`#[cfg(feature = "testing")]`). See the `dead_code` rationale on
    /// [`Self::access_key_store`].
    #[cfg_attr(not(feature = "testing"), allow(dead_code))]
    pub(crate) budget_tracker: &'a MemberBudgetTracker,

    /// Per-member velocity tracker. Source of `velocity_for_test`
    /// (`#[cfg(feature = "testing")]`). See the `dead_code` rationale on
    /// [`Self::access_key_store`].
    #[cfg_attr(not(feature = "testing"), allow(dead_code))]
    pub(crate) velocity_tracker: &'a SenderVelocityTracker,

    /// Shared Merkle event-log provider. Backs
    /// [`QueriesCommand::EventLogEntries`](crate::context::actor::commands::QueriesCommand::EventLogEntries).
    /// The view holds a reference to the provider `Arc` rather than an
    /// owned clone — the shim on
    /// [`Supervisor::dispatch_query`](crate::context::supervisor::supervisor::Supervisor::dispatch_query)
    /// keeps the Arc alive for the view's lifetime.
    pub(crate) event_log: &'a Arc<dyn ContextEventLogProvider>,
}

impl<'a> QueryStateView<'a> {
    /// Construct a view borrowing into a live `PerContextState` held by
    /// the caller under a mutex guard, plus the shared event-log
    /// provider owned by the manager.
    ///
    /// Every borrow is via a typed accessor on `PerContextState`; the
    /// manager's private field visibilities are unchanged by this commit
    /// apart from the deliberate `pub(crate)` elevation of the struct
    /// itself (documented on `manager::PerContextState`).
    #[must_use]
    pub(crate) fn from_manager_state(
        state: &'a PerContextState,
        event_log: &'a Arc<dyn ContextEventLogProvider>,
    ) -> Self {
        Self {
            membership: state.membership(),
            role_state: state.role_state(),
            local_pseudonym: state.local_pseudonym(),
            broadcast_context: state.broadcast_context(),
            handle: state.handle(),
            pending_commits: state.pending_commits(),
            commit_fault: state.commit_fault(),
            access_key_store: state.access_key_store(),
            budget_tracker: state.budget_tracker(),
            velocity_tracker: state.velocity_tracker(),
            event_log,
        }
    }
}

// ---------------------------------------------------------------------------
// Compile-time witness: the view is Send so it can traverse await points
// inside `handlers::queries::dispatch`. Sync is NOT required — the view
// is only passed by shared reference, never cloned.
// ---------------------------------------------------------------------------

const fn _assert_send() {
    const fn assert_send<T: Send>() {}
    assert_send::<QueryStateView<'_>>();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    //! Compile-time tests. The view's semantics (actual query parity with
    //! the legacy `ContextManager` implementation) are covered by the
    //! integration test `actor_query_shim.rs` at the runtime-crate level,
    //! which exercises every variant through both the legacy and
    //! post-shim code paths and asserts identical results.

    use super::*;

    /// Compile-only check that every field is a shared reference with the
    /// view's lifetime. If a field ever carries an owned value, this
    /// function fails to compile because the expected reference type
    /// wouldn't match.
    #[allow(dead_code)]
    fn _ensure_borrow_shape<'a>(v: &QueryStateView<'a>) {
        let _: &'a MembershipState = v.membership;
        let _: &'a ContextRoleState = v.role_state;
        let _: Option<&'a [u8; 32]> = v.local_pseudonym;
        let _: Option<&'a BroadcastContext> = v.broadcast_context;
        let _: &'a ContextHandle = v.handle;
        let _: &'a std::collections::VecDeque<PendingCommit> = v.pending_commits;
        let _: Option<&'a CommitFaultMarker> = v.commit_fault;
        let _: &'a AccessKeyStore = v.access_key_store;
        let _: &'a MemberBudgetTracker = v.budget_tracker;
        let _: &'a SenderVelocityTracker = v.velocity_tracker;
        let _: &'a Arc<dyn ContextEventLogProvider> = v.event_log;
    }
}
