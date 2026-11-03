//! Standing-context helpers — actor-shape signatures
//! (ADR-049 Phase 2A.2, `standing` domain migration).
//!
//! # Purpose
//!
//! This module hosts the standing-domain helpers that the actor handler
//! in [`crate::context::actor::handlers::standing`] calls to implement
//! [`StandingCommand`](scp_runtime_core::context::actor::commands::StandingCommand).
//!
//! # Phase 2A.2 migration
//!
//! The standing domain is supervisor-scoped: the standing index lives on
//! the supervisor. The count / has / register helpers here take
//! [`ActorDeps`] without `PerContextState` — they do not read or mutate
//! per-context state and route supervisor-scoped work through the
//! capability-reduced
//! [`SupervisorHandle`](scp_runtime_core::context::supervisor::SupervisorHandle)
//! embedded in `deps`.
//!
//! Get-or-create (`standing_context`) and `reconnect_all_standing` are
//! NOT exposed here: both are actor-native methods on the supervisor
//! ([`Supervisor::standing_context`](scp_runtime_core::context::supervisor::supervisor::Supervisor::standing_context),
//! [`Supervisor::reconnect_all_standing`](scp_runtime_core::context::supervisor::supervisor::Supervisor::reconnect_all_standing))
//! that resolve per-context lifecycle and params through the actor
//! registry and mailbox. Get-or-create may CREATE the target actor, so
//! routing it through a per-context actor handler would risk a
//! non-`Send` actor-spawns-actor recursion; it therefore dispatches
//! supervisor-direct.

use scp_did::DID;
use scp_protocol::context::ContextError;

use scp_runtime_core::context::actor::deps::ActorDeps;

// ---------------------------------------------------------------------------
// generate_standing_context_id (pure helper)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// standing_context — get-or-create is supervisor-scoped
// ---------------------------------------------------------------------------
//
// There is intentionally no actor-shape `standing_context(deps, ..)`
// helper here. Get-or-create is supervisor-scoped: the actor-native body
// ([`Supervisor::standing_context`](scp_runtime_core::context::supervisor::supervisor::Supervisor::standing_context))
// may CREATE the target per-context actor (build deps + spawn an
// owned-state actor via `lifecycle_helpers::create_context`). Wrapping
// that behind an `&ActorDeps` helper invoked from the per-context actor
// handler would make the actor's own `run()` loop recursively spawn
// another actor — a non-`Send` call graph the runtime cannot spawn. The
// two production entry points
// ([`SupervisorHandle::standing_context`](scp_runtime_core::context::supervisor::handle::SupervisorHandle)
// and `Supervisor::dispatch_standing_direct`'s `StandingContext` arm)
// therefore call `Supervisor::standing_context` directly.

// ---------------------------------------------------------------------------
// 2. standing_context_count
// ---------------------------------------------------------------------------

/// Returns the number of tracked standing contexts.
///
/// # Errors
///
/// [`ContextError::SupervisorShutDown`] when the Supervisor has dropped.
pub(super) fn standing_context_count(deps: &ActorDeps) -> Result<usize, ContextError> {
    deps.supervisor.standing_context_count()
}

// ---------------------------------------------------------------------------
// 3. has_standing_context
// ---------------------------------------------------------------------------

/// Returns `true` if a standing context exists for the given peer DID.
///
/// # Errors
///
/// [`ContextError::SupervisorShutDown`] when the Supervisor has dropped.
pub(super) fn has_standing_context(deps: &ActorDeps, peer_did: &DID) -> Result<bool, ContextError> {
    deps.supervisor.has_standing_context(peer_did)
}

// ---------------------------------------------------------------------------
// 4. register_standing_context
// ---------------------------------------------------------------------------

/// Registers an existing context as a standing context.
pub async fn register_standing_context(
    deps: &ActorDeps,
    peer_did: DID,
) -> Result<(), ContextError> {
    deps.supervisor.register_standing_context(peer_did).await
}

// ---------------------------------------------------------------------------
// 5. reconnect_all_standing
// ---------------------------------------------------------------------------

/// Reconnects transport for all active standing contexts.
///
/// # Errors
///
/// Returns [`ContextError::TransportFailed`] if any reconnection fails.
pub async fn reconnect_all_standing(deps: &ActorDeps) -> Result<usize, ContextError> {
    deps.supervisor.reconnect_all_standing().await
}
