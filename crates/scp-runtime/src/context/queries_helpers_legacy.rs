// Module-level allow — the legacy `&Supervisor` lock-and-call form held
// per-context guards across await points deliberately (narrowing changes
// lock-ordering semantics). The hoisted bodies preserve that shape;
// allowing the lint crate-locally keeps the hoist byte-identical to the
// legacy behavior.
#![allow(clippy::significant_drop_tightening)]

//! Designated-legacy queries-domain helpers
//! (ADR-049 Phase 2A.10, `queries` domain migration).
//!
//! # Purpose
//!
//! Survivors of the pre-migration `&Supervisor` lock-and-call queries
//! helper bodies. The actor path uses
//! [`crate::context::queries_helpers`] (actor-shape) for every query
//! variant; the remaining helpers in this module exist because the
//! supervisor's [`crate::context::supervisor::supervisor::Supervisor::dispatch_lifecycle_direct`]
//! path still needs to operate on contexts created by the legacy
//! bootstrap callers (`standing_helpers_legacy::standing_context_legacy`,
//! `governance_helpers_legacy::execute_create_child_context_legacy`) —
//! those callers run `create_context_legacy` which inserts into the
//! supervisor's contexts `DashMap` without spawning an actor. Until
//! those bootstrap paths migrate to the actor-shape, the no-actor
//! fallback locks the `DashMap` entry directly.
//!
//! # Surviving entries
//!
//! - **Access-key management** (`generate_context_access_key_legacy`,
//!   `revoke_context_access_key_legacy`,
//!   `restore_context_access_key_legacy`) — locked-DashMap twins of the
//!   actor-shape helpers in `queries_helpers`. Called from
//!   `dispatch_lifecycle_direct`'s no-actor fallback for the matching
//!   `LifecycleCommand` variants.
//! - **Checkpoint forcing** (`force_create_checkpoint_legacy`) — called
//!   transitively from `lifecycle_helpers_legacy::close_context_with_key_legacy`
//!   (which is itself reachable through the legacy
//!   `dispatch_lifecycle_direct` close path).
//!
//! Every other legacy free function in the prior version of this module
//! (the soft-default queries, the `*_for_test` accessors, the
//! `compare_remote_checkpoint` / `prove_*` checkpoint helpers) was
//! deleted during the Phase 2A finalization queries+lifecycle session.

use scp_identity::DID;
use scp_protocol::context::ContextError;
use scp_protocol::context::roles::Capability;

use crate::context::manager_methods;
use crate::context::state::PerContextState;
use crate::context::supervisor::Supervisor;

// ---------------------------------------------------------------------------
// Access-key management — locked-DashMap twins of the actor-shape helpers
// ---------------------------------------------------------------------------

/// Generates a fresh access key for a member and stores it in the
/// context's access key store (locked-DashMap form).
///
/// # Errors
///
/// - [`ContextError::ContextNotRegistered`] if the context is not
///   registered with this supervisor.
/// - [`ContextError::PermissionDenied`] if `caller_did` lacks the
///   `ContextClose` (admin) capability.
/// - [`ContextError::MemberNotFound`] if `member_did` is not a member
///   of the context.
pub async fn generate_context_access_key_legacy(
    supervisor: &Supervisor,
    context_id: &str,
    member_did: &str,
    caller_did: &str,
) -> Result<(), ContextError> {
    let ctx_arc = manager_methods::get_context_arc(supervisor, context_id)
        .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
    let mut guard = ctx_arc.lock().await;
    let ctx = &mut *guard;

    // Authorization: access key management requires admin (ContextClose).
    if !ctx
        .role_state
        .member_has_capability(caller_did, &Capability::ContextClose)
    {
        return Err(ContextError::PermissionDenied(
            "access key management requires admin capability".into(),
        ));
    }

    if !ctx.membership.contains(member_did) {
        return Err(ContextError::MemberNotFound(format!(
            "member not found: {member_did}"
        )));
    }

    let key = scp_protocol::crypto::access_keys::generate_access_key(context_id, member_did);
    ctx.access.access_key_store.set(context_id, member_did, key);
    Ok(())
}

/// Revokes (removes) a member's access key from the context's access
/// key store (locked-DashMap form).
///
/// # Errors
///
/// - [`ContextError::ContextNotRegistered`] if the context is not
///   registered with this supervisor.
/// - [`ContextError::PermissionDenied`] if `caller_did` lacks the
///   `ContextClose` (admin) capability.
/// - [`ContextError::MemberNotFound`] if no access key exists for
///   `member_did` in the context.
pub async fn revoke_context_access_key_legacy(
    supervisor: &Supervisor,
    context_id: &str,
    member_did: &str,
    caller_did: &str,
) -> Result<(), ContextError> {
    let ctx_arc = manager_methods::get_context_arc(supervisor, context_id)
        .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
    let mut guard = ctx_arc.lock().await;
    let ctx = &mut *guard;

    // Authorization: access key management requires admin (ContextClose).
    if !ctx
        .role_state
        .member_has_capability(caller_did, &Capability::ContextClose)
    {
        return Err(ContextError::PermissionDenied(
            "access key management requires admin capability".into(),
        ));
    }

    ctx.access
        .access_key_store
        .remove(context_id, member_did)
        .ok_or_else(|| {
            ContextError::MemberNotFound(format!("no access key found for member: {member_did}"))
        })?;
    Ok(())
}

/// Restores a member's access key by generating a new key at epoch 0
/// (locked-DashMap form).
///
/// # Errors
///
/// - [`ContextError::ContextNotRegistered`] if the context is not
///   registered with this supervisor.
/// - [`ContextError::PermissionDenied`] if `caller_did` lacks the
///   `ContextClose` (admin) capability.
/// - [`ContextError::MemberNotFound`] if `member_did` is not a member
///   of the context.
pub async fn restore_context_access_key_legacy(
    supervisor: &Supervisor,
    context_id: &str,
    member_did: &str,
    caller_did: &str,
) -> Result<(), ContextError> {
    let ctx_arc = manager_methods::get_context_arc(supervisor, context_id)
        .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
    let mut guard = ctx_arc.lock().await;
    let ctx = &mut *guard;

    // Authorization: access key management requires admin (ContextClose).
    if !ctx
        .role_state
        .member_has_capability(caller_did, &Capability::ContextClose)
    {
        return Err(ContextError::PermissionDenied(
            "access key management requires admin capability".into(),
        ));
    }

    if !ctx.membership.contains(member_did) {
        return Err(ContextError::MemberNotFound(format!(
            "member not found: {member_did}"
        )));
    }

    let key = scp_protocol::crypto::access_keys::generate_access_key(context_id, member_did);
    ctx.access.access_key_store.set(context_id, member_did, key);
    Ok(())
}

// ---------------------------------------------------------------------------
// Checkpoint forcing — called from lifecycle_helpers_legacy close path
// ---------------------------------------------------------------------------

/// Unconditionally creates a consistency checkpoint regardless of
/// whether the event/time thresholds have been reached.
///
/// Returns `None` if the supervisor's clock or event-log provider slots
/// are empty; otherwise delegates to
/// [`crate::context::queries_helpers::force_create_checkpoint_fields`]
/// and returns the produced checkpoint.
#[must_use]
pub fn force_create_checkpoint_legacy(
    supervisor: &Supervisor,
    context_id: &str,
    ctx: &mut PerContextState,
    sender_did: &DID,
    signing_key: &ed25519_dalek::SigningKey,
) -> Option<scp_event_log::checkpoint::ConsistencyCheckpoint> {
    let clock = supervisor.clock_ref()?;
    let event_log = supervisor.event_log_ref()?;
    let now = clock.now_secs();
    let cp = crate::context::queries_helpers::force_create_checkpoint_fields(
        context_id,
        ctx.broadcast_context.is_none(),
        ctx.epoch.mls_epoch,
        &mut ctx.checkpoint_events_since,
        &mut ctx.checkpoint_last_time_secs,
        &mut ctx.checkpoints,
        sender_did,
        signing_key,
        now,
        event_log.as_ref(),
    );
    Some(cp)
}
