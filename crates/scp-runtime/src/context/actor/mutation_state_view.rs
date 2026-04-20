//! Transitional mutable state view for the mutating-handler migration
//! window (commits 8–11 of ADR-049). Mutable sibling of
//! [`QueryStateView`](super::query_state_view::QueryStateView); deleted
//! in commit 12 when `manager::PerContextState` goes away and the
//! actor's
//! [`PerContextState`](crate::context::actor::state::PerContextState)
//! absorbs every field the migrated mutation handlers write to.
//!
//! # Why this type exists
//!
//! The commit-ladder plan (row 8, "Migrate `handlers/messaging.rs`")
//! moves the send + deliver handler bodies to
//! [`handlers::messaging`](crate::context::actor::handlers::messaging)
//! on the new handler-takes-`&mut State` shape **before** the actor's
//! [`PerContextState`](crate::context::actor::state::PerContextState)
//! has absorbed the full field set the mutation handlers write to.
//! During that window, the live per-context state still lives on
//! [`crate::context::manager::PerContextState`]. This type is the
//! mutable borrow adapter that lets the new handler shape write the
//! live state without forcing the actor-state migration to happen in
//! one giant commit — it is **part of the shim architecture the plan
//! sanctions**, not a DOA decision. Row 12 of the commit ladder deletes
//! it.
//!
//! # Contract
//!
//! - **Mutable borrow + shared non-state resources.** The view holds
//!   `&'a mut manager::PerContextState` under a per-context mutex
//!   guard (supplied by the shim on
//!   [`Supervisor::dispatch_command`](crate::context::supervisor::supervisor::Supervisor::dispatch_command)),
//!   plus an `Arc<ContextManager>` reference for the shared non-state
//!   resources (transport, clock, key resolver, event log, event
//!   broadcast channel). No owned data. No clones.
//! - **Exactly one live borrow.** The `&mut` borrow of
//!   `PerContextState` guarantees serialization of mutation handler
//!   invocations per context, matching the actor's single-threaded
//!   state invariant (ADR-049 §1).
//! - **Not a public API.** `pub(crate)` visibility. No FFI export. Not
//!   re-exported from
//!   [`crate::context::actor`](crate::context::actor) outside the
//!   shim's internal use.
//!
//! # Shim boundary
//!
//! The shim carefully **does not** use [`Self`] to call back into
//! [`ContextManager::send_message`](crate::context::manager::ContextManager::send_message)
//! or
//! [`ContextManager::deliver_incoming`](crate::context::manager::ContextManager::deliver_incoming)
//! while holding the per-context mutex guard — those methods acquire
//! the same guard internally and would deadlock. The shim pattern is:
//!
//! 1. Acquire per-context guard, construct [`Self`], run the
//!    pre-phase work (reservation, pre-checks).
//! 2. Drop the guard.
//! 3. Call the legacy
//!    [`ContextManager`](crate::context::manager::ContextManager)
//!    method under `tokio::time::timeout(30s, ...)`.
//! 4. Re-acquire the guard, construct a fresh [`Self`], run the
//!    post-phase work (commit or roll back the reservation, record
//!    outcomes).
//!
//! The handler body in
//! [`handlers::messaging::dispatch`](crate::context::actor::handlers::messaging::dispatch)
//! orchestrates those phases explicitly; the view exists so each
//! phase's code reads as "take a mutable state view and a deps
//! bundle, do the work, return an `Outcome`" — identical to the
//! post-refactor actor handler signature.

use std::sync::Arc;

use crate::context::actor::SendSequenceTracker;
use crate::context::manager::{ContextManager, PerContextState};

// ---------------------------------------------------------------------------
// MutationStateView<'a>
// ---------------------------------------------------------------------------

/// Mutable borrow adapter over `manager::PerContextState` used by the
/// migrated mutation handlers during the commits-8-to-11 window.
///
/// Every field is a mutable reference into the live per-context state
/// or a shared-by-`Arc` handle on the owning
/// [`ContextManager`](crate::context::manager::ContextManager). The
/// caller (the mutation shim on
/// [`Supervisor::dispatch_command`](crate::context::supervisor::supervisor::Supervisor::dispatch_command))
/// builds the view under a mutex guard, passes it by reference to the
/// handler's pre/post phases, and drops the guard between phases so
/// the `ContextManager`'s internal per-context lock can re-acquire
/// without deadlock. Handlers may not clone, retain, or otherwise
/// escape the borrows.
pub struct MutationStateView<'a> {
    /// Send-sequence counter for RAII reservation. Mutated by
    /// [`crate::context::actor::SequenceReservation::reserve`] during
    /// the send-path pre-phase; committed (via
    /// [`crate::context::actor::SequenceReservation::commit`]) after
    /// the transport send succeeds, or rolled back on drop if the
    /// handler returns early.
    pub(crate) send_tracker: &'a mut SendSequenceTracker,

    /// Shared owner reference back to the
    /// [`ContextManager`](crate::context::manager::ContextManager)
    /// for access to resources the per-context state does not own:
    /// transport, clock, event log provider, key resolver, event
    /// broadcast channel, and the legacy
    /// [`send_message`](crate::context::manager::ContextManager::send_message)
    /// / [`deliver_incoming`](crate::context::manager::ContextManager::deliver_incoming)
    /// entry points the shim delegates to for byte-identical
    /// encryption / envelope construction.
    ///
    /// Held as `&'a Arc<ContextManager>` rather than `Arc<ContextManager>`
    /// so the view does not increment the refcount per construction —
    /// the shim caller keeps the manager alive for the handler's
    /// lifetime.
    pub(crate) manager: &'a Arc<ContextManager>,
}

impl<'a> MutationStateView<'a> {
    /// Construct a view borrowing mutably into a live `PerContextState`
    /// held by the caller under a mutex guard, plus a shared reference
    /// to the owning
    /// [`ContextManager`](crate::context::manager::ContextManager).
    ///
    /// The `send_tracker` borrow is obtained through the typed
    /// [`PerContextState::send_tracker_mut`](crate::context::manager::PerContextState::send_tracker_mut)
    /// accessor; `manager::PerContextState` field visibilities are
    /// unchanged by this commit apart from the deliberate `pub(crate)`
    /// elevation of the struct itself and the accessor method
    /// (documented on `manager::PerContextState`).
    ///
    /// The shim on
    /// [`Supervisor::dispatch_command`](crate::context::supervisor::supervisor::Supervisor::dispatch_command)
    /// does NOT call this constructor because holding the per-context
    /// mutex guard across the handler's delegated
    /// [`ContextManager::send_message`](crate::context::manager::ContextManager::send_message)
    /// await would deadlock (the manager re-acquires the same guard
    /// internally). The shim instead builds a view over a **take-and-
    /// swap** copy of the tracker — see the doc comment on
    /// [`Supervisor::dispatch_command`](crate::context::supervisor::supervisor::Supervisor::dispatch_command)
    /// for the lock-free protocol. This constructor is retained for
    /// (a) the post-refactor commit-12 actor path (the actor owns the
    /// state by move; no guard exists) and (b) direct test
    /// construction.
    #[must_use]
    #[allow(dead_code)] // See the doc comment above — retained for commit 12.
    pub(crate) const fn from_manager_state_mut(
        state: &'a mut PerContextState,
        manager: &'a Arc<ContextManager>,
    ) -> Self {
        Self {
            send_tracker: state.send_tracker_mut(),
            manager,
        }
    }

    /// Cheap reference to the owning manager. Used by the handler to
    /// call the byte-identical
    /// [`send_message`](crate::context::manager::ContextManager::send_message)
    /// / [`deliver_incoming`](crate::context::manager::ContextManager::deliver_incoming)
    /// implementations after the pre-phase has finished mutating
    /// local-state fields. Returning `&Arc<...>` (not `Arc<...>`)
    /// preserves the "no refcount bump" contract.
    #[must_use]
    pub(crate) const fn manager(&self) -> &Arc<ContextManager> {
        self.manager
    }
}

// ---------------------------------------------------------------------------
// Compile-time witness: the view is Send so it can traverse await
// points inside the handler dispatch. Sync is NOT required — the view
// is only passed by mutable reference, never cloned.
// ---------------------------------------------------------------------------

const fn _assert_send() {
    const fn assert_send<T: Send>() {}
    assert_send::<MutationStateView<'_>>();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    //! Compile-time tests. Observable semantics (shim routing, RAII
    //! rollback, timeout propagation) are covered by the integration
    //! test `actor_messaging_shim.rs` at the runtime-crate level.

    use super::*;

    /// Compile-only check that the mutable borrow shape matches the
    /// post-refactor actor handler signature — `send_tracker` is a
    /// `&mut SendSequenceTracker`, not an owned value.
    #[allow(dead_code)]
    fn _ensure_borrow_shape<'a>(v: &mut MutationStateView<'a>) {
        let _: &mut SendSequenceTracker = v.send_tracker;
        let _: &'a Arc<ContextManager> = v.manager;
    }
}
