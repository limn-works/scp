//! Standing-context helpers — actor-shape signatures
//! (ADR-049 Phase 2A.2, `standing` domain migration).
//!
//! # Purpose
//!
//! This module hosts the standing-domain helpers that the actor handler
//! in [`crate::context::actor::handlers::standing`] calls to implement
//! [`StandingCommand`](crate::context::actor::commands::StandingCommand).
//!
//! # Phase 2A.2 migration
//!
//! The standing domain is supervisor-scoped: the standing index lives on
//! the supervisor, and standing-pair creation still delegates to the
//! legacy `create_context` flow until Phase 2C decomposes it into a
//! saga. These helpers therefore take [`ActorDeps`] without
//! `PerContextState`: they do not read or mutate per-context state and
//! route supervisor-scoped work through the capability-reduced
//! [`SupervisorHandle`](crate::context::supervisor::SupervisorHandle)
//! embedded in `deps`.
//!
//! The legacy lock-shaped bodies live in
//! [`crate::context::standing_helpers_legacy`] for the supervisor shim
//! fallback. Phase 2A finalization removes that module after every
//! domain routes through actor-owned state.

use scp_identity::DID;
use scp_protocol::context::ContextError;
use sha2::{Digest, Sha256};

use crate::context::actor::deps::ActorDeps;

// ---------------------------------------------------------------------------
// generate_standing_context_id (pure helper)
// ---------------------------------------------------------------------------

/// Generates a deterministic context ID for a standing context between two DIDs.
///
/// The ID is derived from both DIDs sorted lexicographically, ensuring the same
/// context ID is generated regardless of which peer initiates. Uses a
/// `standing:` prefix for namespace isolation and a truncated SHA-256 hash of
/// the sorted DID pair for the unique portion.
pub fn generate_standing_context_id(local_did: &DID, peer_did: &DID) -> String {
    let (a, b) = if local_did.as_ref() <= peer_did.as_ref() {
        (local_did.as_ref(), peer_did.as_ref())
    } else {
        (peer_did.as_ref(), local_did.as_ref())
    };
    let mut hasher = Sha256::new();
    hasher.update(b"standing:");
    hasher.update(a.as_bytes());
    hasher.update(b":");
    hasher.update(b.as_bytes());
    let hash = hasher.finalize();
    format!("standing-{}", hex::encode(hash))
}

// ---------------------------------------------------------------------------
// standing_context — get-or-create is supervisor-scoped
// ---------------------------------------------------------------------------
//
// There is intentionally no actor-shape `standing_context(deps, ..)`
// helper here. Get-or-create is supervisor-scoped: the actor-native body
// ([`Supervisor::standing_context`](crate::context::supervisor::supervisor::Supervisor::standing_context))
// may CREATE the target per-context actor (build deps + spawn an
// owned-state actor via `lifecycle_helpers::create_context`). Wrapping
// that behind an `&ActorDeps` helper invoked from the per-context actor
// handler would make the actor's own `run()` loop recursively spawn
// another actor — a non-`Send` call graph the runtime cannot spawn. The
// two production entry points
// ([`SupervisorHandle::standing_context`](crate::context::supervisor::handle::SupervisorHandle)
// and `Supervisor::dispatch_standing_direct`'s `StandingContext` arm)
// therefore call `Supervisor::standing_context` directly.

// ---------------------------------------------------------------------------
// 2. standing_context_count
// ---------------------------------------------------------------------------

/// Returns the number of tracked standing contexts.
pub fn standing_context_count(deps: &ActorDeps) -> usize {
    deps.supervisor.standing_context_count()
}

// ---------------------------------------------------------------------------
// 3. has_standing_context
// ---------------------------------------------------------------------------

/// Returns `true` if a standing context exists for the given peer DID.
pub fn has_standing_context(deps: &ActorDeps, peer_did: &DID) -> bool {
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
    deps.supervisor.register_standing_context(peer_did).await;
    Ok(())
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
