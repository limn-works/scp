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
//! the supervisor. The count / has / register helpers here take
//! [`ActorDeps`] without `PerContextState` — they do not read or mutate
//! per-context state and route supervisor-scoped work through the
//! capability-reduced
//! [`SupervisorHandle`](crate::context::supervisor::SupervisorHandle)
//! embedded in `deps`.
//!
//! Get-or-create (`standing_context`) and `reconnect_all_standing` are
//! NOT exposed here: both are actor-native methods on the supervisor
//! ([`Supervisor::standing_context`](crate::context::supervisor::supervisor::Supervisor::standing_context),
//! [`Supervisor::reconnect_all_standing`](crate::context::supervisor::supervisor::Supervisor::reconnect_all_standing))
//! that resolve per-context lifecycle and params through the actor
//! registry and mailbox. Get-or-create may CREATE the target actor, so
//! routing it through a per-context actor handler would risk a
//! non-`Send` actor-spawns-actor recursion; it therefore dispatches
//! supervisor-direct.

use scp_identity::DID;
use scp_protocol::context::ContextError;
use sha2::{Digest, Sha256};

use crate::context::actor::deps::ActorDeps;

// ---------------------------------------------------------------------------
// generate_standing_context_id (pure helper)
// ---------------------------------------------------------------------------

/// Derives the **raw 32-byte digest** for a standing context between two DIDs.
///
/// This is the canonical saga-evidence / wire form of the standing-pair
/// identity (spec §5.15.8: "the 32-byte `derived_context_id` used in saga
/// evidence is the raw digest before prefix and hex"). The digest is computed
/// over both DIDs sorted lexicographically, so it is symmetric:
/// `derive(A, B) == derive(B, A)`.
///
/// [`generate_standing_context_id`] wraps this digest with the `"standing-"`
/// display prefix + hex for the actor-registry key; the saga concurrency
/// gating (ADR-049 §3a, spec §5.15.4) reserves the RAW-digest hex
/// (`hex::encode(derive_standing_context_digest(..))`) so a standing-pair saga
/// and a cross-context / broadcast saga that share the same standing context
/// reserve the SAME canonical key and therefore overlap. Keeping the prefixed
/// id and the raw digest derived from one shared body guarantees they cannot
/// drift apart.
pub fn derive_standing_context_digest(local_did: &DID, peer_did: &DID) -> [u8; 32] {
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
    hasher.finalize().into()
}

/// Generates a deterministic context ID for a standing context between two DIDs.
///
/// The ID is derived from both DIDs sorted lexicographically, ensuring the same
/// context ID is generated regardless of which peer initiates. Uses a
/// `standing-` prefix for namespace isolation and the lowercase hex of the
/// 32-byte SHA-256 digest ([`derive_standing_context_digest`]) of the sorted
/// DID pair for the unique portion. The prefixed string is the actor-registry
/// key; the unprefixed raw digest is the saga-evidence / gating form
/// (spec §5.15.8).
pub fn generate_standing_context_id(local_did: &DID, peer_did: &DID) -> String {
    format!(
        "standing-{}",
        hex::encode(derive_standing_context_digest(local_did, peer_did))
    )
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
