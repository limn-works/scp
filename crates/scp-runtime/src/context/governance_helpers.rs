//! Governance helpers — actor-shape signatures
//! (ADR-049 Phase 2A.8, `governance` domain migration).
//!
//! # Purpose
//!
//! This module hosts governance-domain helpers that operate on
//! actor-owned [`PerContextState`](crate::context::actor::state::PerContextState)
//! and capability-reduced [`ActorDeps`](crate::context::actor::deps::ActorDeps).
//! The legacy `&Supervisor` lock-and-call bodies live in
//! [`crate::context::governance_helpers_legacy`] until Phase 2A
//! finalization removes the shim fallback.
//!
//! # Migration shape
//!
//! Phase 2A.8 lands as a multi-commit ladder. The opening commit
//! scaffolds a complete byte-identical legacy twin module
//! ([`crate::context::governance_helpers_legacy`]) and rewires every
//! shim caller (handler `dispatch_from_shim`, supervisor passthroughs,
//! lifecycle helpers, messaging helpers legacy) to consume the legacy
//! variants. This module is intentionally trimmed to the small set of
//! actor-shape-compatible helpers that have already migrated. As each
//! subsequent commit migrates an entry-point + its transitive helpers
//! to the actor-shape signature `(&mut PerContextState, &ActorDeps,
//! ...)`, those functions are added back here and wired through
//! [`crate::context::actor::handlers::governance::dispatch`].
//!
//! # Currently-migrated helpers
//!
//! - [`check_commit_fault_marker`] — fail-close gate for any helper that
//!   touches per-context state. The actor-shape `messaging_helpers`
//!   already calls it via `state.commit_fault.as_ref()`.
//!
//! Once all 14 entry points + transitive helpers are migrated,
//! Phase 2A finalization deletes
//! [`crate::context::governance_helpers_legacy`] and the supervisor's
//! `dispatch_from_shim` fallback in one swoop.

use scp_protocol::context::ContextError;

// ---------------------------------------------------------------------------
// check_commit_fault_marker (transitive helper, already actor-shape)
// ---------------------------------------------------------------------------

/// Field-disjoint variant of `check_commit_fault` used by both the
/// legacy [`crate::context::state::PerContextState`] and the
/// actor-shape
/// [`crate::context::actor::state::PerContextState`].
///
/// ADR-049 Phase 2A.7 — added so the actor-shape `messaging_helpers`
/// can drive the same fail-closed gate without going through the
/// legacy state struct.
///
/// # Errors
///
/// Returns [`ContextError::CommitBroadcastFault`] if the marker is `Some`.
pub fn check_commit_fault_marker(
    marker: Option<&crate::context::state::CommitFaultMarker>,
) -> Result<(), ContextError> {
    if let Some(marker) = marker {
        return Err(ContextError::CommitBroadcastFault {
            operation: marker.operation.label(),
            reason: marker.reason.clone(),
            attempts: marker.retry_count,
        });
    }
    Ok(())
}
