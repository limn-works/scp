// Module-level allow — the legacy `&Supervisor` lock-and-call form held
// per-context guards across await points deliberately (narrowing changes
// lock-ordering semantics). The hoisted bodies preserve that shape;
// allowing the lint crate-locally keeps the hoist byte-identical to the
// legacy behavior.
//
// `dead_code` is allowed module-wide because this module is the
// transitional home for the pre-actor `&Supervisor`-shaped queries
// helpers consumed by the supervisor passthroughs and the actor handler
// shim path during the Phase 2A migration window. After Phase 2A
// finalization removes the shim fallback this module is deleted in one
// pass with the supervisor's contexts `DashMap`.
#![allow(clippy::significant_drop_tightening, dead_code)]

//! Legacy queries-domain helpers
//! (ADR-049 Phase 2A.10, `queries` domain migration).
//!
//! # Purpose
//!
//! This module preserves the pre-migration `&Supervisor` lock-and-call
//! queries helper bodies for the Phase 2A shim fallback. The live actor
//! path now calls [`crate::context::queries_helpers`], which operates
//! on actor-owned state directly via `&PerContextState + &ActorDeps`
//! (or `&mut` when the read path mutates state — `drain_events`,
//! `report_degraded_mode`, access-key management, checkpoint creation,
//! Merkle-tree sync); the shim path keeps these legacy twins until
//! Phase 2A finalization removes all `*_helpers_legacy.rs` modules.
//!
//! # Behavior preservation
//!
//! Every hoisted free function is **behavior-preserving by
//! construction**. Every body is a verbatim copy of the pre-migration
//! `&Supervisor`-shaped helper. `self.X` was already replaced in
//! ADR-049 commit 12 by either:
//!
//! - `supervisor.X_ref().ok_or(NotInitialized)?` for provider slots
//!   lifted to the supervisor (crypto, transport, `event_log`,
//!   `event_tx`, clock, `local_dids`, `key_resolver`), or
//! - `manager_methods::X(supervisor, ...)` for the cross-domain
//!   per-context lock acquisition path.
//!
//! # Designated-legacy supervisor-scoped helpers
//!
//! Some helpers inherently operate on supervisor-scoped state (the
//! `local_dids` ArcSwap, the cross-context event-log provider) rather
//! than per-context state. These have no actor-shape twin in
//! [`crate::context::queries_helpers`]:
//!
//! - [`register_local_did_legacy`] — mutates `supervisor.local_dids`
//!   under the supervisor's `write_lock`. Supervisor-scoped.
//! - [`is_local_did_legacy`] — reads `supervisor.local_dids`.
//!   Supervisor-scoped.
//! - [`event_log_entries_legacy`] — reads the shared event-log
//!   provider; the actor-shape twin
//!   [`crate::context::queries_helpers::event_log_entries`] takes
//!   `&deps` directly so the actor path does not synthesize a
//!   `&Supervisor`.

use std::collections::HashMap;

use scp_identity::DID;
use scp_protocol::context::membership::ContextEvent;
use scp_protocol::context::roles::{Capability, ContextRoleState, RoleAssignment};
use scp_protocol::context::{ContextError, ContextParams};
use zeroize::Zeroizing;

use crate::context::manager_methods;
use crate::context::providers::event_log::EventLogEntry;
use crate::context::state::{CommitFaultMarker, PendingCommit, PerContextState, context_id_to_bytes};
use crate::context::supervisor::Supervisor;

// Phase 1 fix-up of ADR-049 (post-review-round-1): per-helper
// `ATTACHED_EXPECT` constants consolidated to the single
// `PROVIDER_NOT_INITIALIZED` definition in `manager_methods`.
use crate::context::manager_methods::PROVIDER_NOT_INITIALIZED as ATTACHED_EXPECT;

// ===========================================================================
// Local DID / identity management — supervisor-scoped (designated-legacy)
// ===========================================================================

/// Registers a DID as controlled by the local node/SDK.
///
/// Supervisor-scoped — mutates `supervisor.local_dids` under the
/// supervisor's write lock. No per-context actor-shape twin exists
/// because the actor model serializes per-context, not supervisor-wide.
pub async fn register_local_did_legacy(supervisor: &Supervisor, did: DID) {
    // ArcSwap+write_lock pattern (ADR-049 §Decision 12). Reads are
    // lock-free; writes serialize on the supervisor write_lock to
    // avoid lost updates against the cloned snapshot.
    let _guard = supervisor.write_lock.lock().await;
    let snapshot = supervisor.local_dids_ref().load_full();
    let mut updated: std::collections::HashSet<DID> = (*snapshot).clone();
    updated.insert(did);
    supervisor
        .local_dids_ref()
        .store(std::sync::Arc::new(updated));
}

/// Returns `true` if the given DID is registered as locally controlled.
///
/// Supervisor-scoped read. No actor-shape twin.
///
/// `async` is preserved (despite no `await` after the §12 lock-free
/// read migration) to keep the signature symmetric with
/// `register_local_did_legacy` and the legacy method, matching the call
/// shape the FFI bridges + `Supervisor::is_local_did` passthrough
/// expect.
#[allow(clippy::unused_async)]
pub async fn is_local_did_legacy(supervisor: &Supervisor, did: &DID) -> bool {
    // Lock-free read (ADR-049 §Decision 12).
    supervisor.local_dids_ref().load().contains(did)
}

// ===========================================================================
// Per-context read queries
// ===========================================================================

/// Returns the local member's pseudonym routing ID for a context
/// (§9.10.4).
///
/// # Errors
///
/// Returns [`ContextError::ContextNotRegistered`] if the context is not
/// registered.
pub async fn local_pseudonym_legacy(
    supervisor: &Supervisor,
    context_id: &str,
) -> Result<Option<[u8; 32]>, ContextError> {
    let ctx_arc = manager_methods::get_context_arc(supervisor, context_id)
        .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
    let guard = ctx_arc.lock().await;
    Ok(guard.local_pseudonym)
}

/// Returns the broadcast key and epoch for a locally controlled author
/// in a broadcast context.
///
/// # Errors
///
/// - [`ContextError::ContextNotRegistered`] if the context is not registered
///   or is not a broadcast context.
/// - [`ContextError::PermissionDenied`] if `author_did` is not locally
///   controlled.
/// - [`ContextError::MemberNotFound`] if `author_did` is not a registered
///   author in the broadcast context.
pub async fn get_broadcast_key_for_local_author_legacy(
    supervisor: &Supervisor,
    context_id: &str,
    author_did: &str,
) -> Result<(Zeroizing<[u8; 32]>, u64), ContextError> {
    // Verify the DID is locally controlled (lock-free read, ADR-049
    // §Decision 12).
    if !supervisor.local_dids_ref().load().contains(author_did) {
        return Err(ContextError::PermissionDenied(format!(
            "author DID is not controlled by the local node: {author_did}"
        )));
    }

    let ctx_arc = manager_methods::get_context_arc(supervisor, context_id)
        .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
    let guard = ctx_arc.lock().await;
    let ctx = &*guard;

    let bc = ctx
        .broadcast_context
        .as_ref()
        .ok_or_else(|| ContextError::MembershipFailed("not a broadcast context".into()))?;

    let author = bc
        .get_author(author_did)
        .ok_or_else(|| ContextError::MemberNotFound(format!("author not found: {author_did}")))?;

    let key_bytes = Zeroizing::new(*author.broadcast_key.as_bytes());
    Ok((key_bytes, author.epoch))
}

/// Returns the current member count for a context.
pub async fn member_count_legacy(supervisor: &Supervisor, context_id: &str) -> Option<usize> {
    let arc = manager_methods::get_context_arc(supervisor, context_id).ok()?;
    let ctx = arc.lock().await;
    Some(ctx.membership.count())
}

/// Returns `true` if the given DID is a member of the specified context.
pub async fn is_member_legacy(supervisor: &Supervisor, context_id: &str, did: &str) -> bool {
    let Ok(arc) = manager_methods::get_context_arc(supervisor, context_id) else {
        return false;
    };
    let ctx = arc.lock().await;
    ctx.membership.contains(did)
}

/// Returns all member DIDs for a context.
pub async fn member_dids_legacy(supervisor: &Supervisor, context_id: &str) -> Vec<String> {
    let Ok(arc) = manager_methods::get_context_arc(supervisor, context_id) else {
        return Vec::new();
    };
    let ctx = arc.lock().await;
    ctx.membership
        .member_dids()
        .map(std::string::ToString::to_string)
        .collect()
}

/// Returns the role assignment for a specific member in a context.
pub async fn member_role_legacy(
    supervisor: &Supervisor,
    context_id: &str,
    did: &str,
) -> Option<RoleAssignment> {
    let arc = manager_methods::get_context_arc(supervisor, context_id).ok()?;
    let ctx = arc.lock().await;
    ctx.role_state.assignments.get(did).cloned()
}

/// Returns a clone of the context's creation parameters, or `None` if the
/// context is not registered with this manager.
pub async fn context_params_legacy(
    supervisor: &Supervisor,
    context_id: &str,
) -> Option<ContextParams> {
    let arc = manager_methods::get_context_arc(supervisor, context_id).ok()?;
    let ctx = arc.lock().await;
    Some(ctx.handle.params().clone())
}

/// Returns a clone of the role state for a context, or `None` if the
/// context is not registered.
pub async fn get_role_state_legacy(
    supervisor: &Supervisor,
    context_id: &str,
) -> Option<ContextRoleState> {
    let arc = manager_methods::get_context_arc(supervisor, context_id).ok()?;
    let ctx = arc.lock().await;
    Some(ctx.role_state.clone())
}

/// Returns a clone of the persistent MLS Commit retry queue for a context
/// (PR #1606 C6).
pub async fn pending_commits_legacy(
    supervisor: &Supervisor,
    context_id: &str,
) -> Vec<PendingCommit> {
    let Ok(arc) = manager_methods::get_context_arc(supervisor, context_id) else {
        return Vec::new();
    };
    let ctx = arc.lock().await;
    ctx.pending_commits.iter().cloned().collect()
}

/// Returns the active commit fault marker for a context, if any
/// (PR #1606 C6).
pub async fn commit_fault_legacy(
    supervisor: &Supervisor,
    context_id: &str,
) -> Option<CommitFaultMarker> {
    let arc = manager_methods::get_context_arc(supervisor, context_id).ok()?;
    let ctx = arc.lock().await;
    ctx.commit_fault.clone()
}

// ===========================================================================
// Receive buffer + degraded mode
// ===========================================================================

/// Drains all events from the receive buffer for a context.
pub async fn drain_events_legacy(supervisor: &Supervisor, context_id: &str) -> Vec<ContextEvent> {
    let Ok(arc) = manager_methods::get_context_arc(supervisor, context_id) else {
        return Vec::new();
    };
    let mut ctx = arc.lock().await;
    ctx.receive_buffer.drain()
}

/// Reports that a received envelope triggered degraded mode (§13.6) for a
/// context.
pub async fn report_degraded_mode_legacy(
    supervisor: &Supervisor,
    context_id: &str,
    compat: scp_protocol::envelope::VersionCompatibility,
    unsupported_features: Vec<String>,
) {
    if let scp_protocol::envelope::VersionCompatibility::DegradedMode {
        local_minor,
        remote_minor,
    } = compat
    {
        let local_major =
            scp_protocol::envelope::version_major(scp_protocol::envelope::SCP_PROTOCOL_VERSION);
        let remote_major = local_major; // same major guaranteed by VersionCompatibility
        if let Ok(ctx_arc) = manager_methods::get_context_arc(supervisor, context_id) {
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;
            let event = ContextEvent::DegradedMode {
                context_id: context_id.to_owned(),
                local_version: (local_major, local_minor),
                remote_version: (remote_major, remote_minor),
                unsupported_features,
            };
            ctx.emit_event(event, context_id, supervisor.event_tx_ref());
        }
    }
}

// ===========================================================================
// Event log passthrough — supervisor-scoped (designated-legacy)
// ===========================================================================

/// Returns the Merkle event log entries for a context.
///
/// Supervisor-scoped — reads the cross-context event-log provider on
/// the supervisor. The actor-shape twin
/// [`crate::context::queries_helpers::event_log_entries`] takes a
/// `&ActorDeps` directly so the actor path can serve the read without
/// dereferencing the supervisor.
///
/// # Errors
///
/// Returns [`ContextError`] if the event log provider fails.
pub fn event_log_entries_legacy(
    supervisor: &Supervisor,
    context_id: &[u8; 32],
) -> Result<Option<Vec<EventLogEntry>>, ContextError> {
    let event_log = supervisor
        .event_log_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    event_log.event_log_entries(context_id)
}

// ===========================================================================
// Access-key management
// ===========================================================================

/// Generates and stores a per-member access key for explicit lifecycle
/// management.
///
/// # Errors
///
/// - [`ContextError::ContextNotRegistered`] if the context is not
///   registered with this manager.
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
/// key store.
///
/// # Errors
///
/// - [`ContextError::ContextNotRegistered`] if the context is not
///   registered with this manager.
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

/// Restores a member's access key by generating a new key at epoch 0.
///
/// # Errors
///
/// - [`ContextError::ContextNotRegistered`] if the context is not
///   registered with this manager.
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

/// Stores an access key in a context's access key store.
pub async fn set_access_key_legacy(
    supervisor: &Supervisor,
    context_id: &str,
    member_did: &str,
    key: scp_protocol::crypto::access_keys::AccessKey,
) {
    if let Ok(ctx_arc) = manager_methods::get_context_arc(supervisor, context_id) {
        let mut guard = ctx_arc.lock().await;
        let ctx = &mut *guard;
        ctx.access.access_key_store.set(context_id, member_did, key);
    } else {
        tracing::error!(
            context_id,
            "set_access_key: context not registered or Supervisor not attached — skipping"
        );
    }
}

/// Removes a member's access key from a context's access key store.
pub async fn remove_access_key_legacy(
    supervisor: &Supervisor,
    context_id: &str,
    member_did: &str,
) {
    if let Ok(ctx_arc) = manager_methods::get_context_arc(supervisor, context_id) {
        let mut guard = ctx_arc.lock().await;
        let ctx = &mut *guard;
        ctx.access.access_key_store.remove(context_id, member_did);
    } else {
        tracing::error!(
            context_id,
            "remove_access_key: context not registered or Supervisor not attached — skipping"
        );
    }
}

// ===========================================================================
// Test-only accessors
// ===========================================================================

/// Injects an access key into a context's access key store. Test-only.
#[cfg(feature = "testing")]
pub async fn inject_access_key_legacy(
    supervisor: &Supervisor,
    context_id: &str,
    member_did: &str,
    key: scp_protocol::crypto::access_keys::AccessKey,
) {
    if let Ok(ctx_arc) = manager_methods::get_context_arc(supervisor, context_id) {
        let mut guard = ctx_arc.lock().await;
        let ctx = &mut *guard;
        ctx.access.access_key_store.set(context_id, member_did, key);
    } else {
        tracing::error!(
            context_id,
            "inject_access_key: context not registered or Supervisor not attached — skipping"
        );
    }
}

/// Retrieves a clone of the access key for a member in a context.
/// Test-only.
#[cfg(feature = "testing")]
pub async fn get_access_key_legacy(
    supervisor: &Supervisor,
    context_id: &str,
    member_did: &str,
) -> Option<scp_protocol::crypto::access_keys::AccessKey> {
    let arc = manager_methods::get_context_arc(supervisor, context_id).ok()?;
    let ctx = arc.lock().await;
    ctx.access
        .access_key_store
        .get(context_id, member_did)
        .cloned()
}

/// Retrieves clones of ALL access keys for a context. Test-only.
#[cfg(feature = "testing")]
pub async fn get_all_access_keys_legacy(
    supervisor: &Supervisor,
    context_id: &str,
) -> HashMap<String, scp_protocol::crypto::access_keys::AccessKey> {
    let Ok(arc) = manager_methods::get_context_arc(supervisor, context_id) else {
        return HashMap::new();
    };
    let ctx = arc.lock().await;
    ctx.access.access_key_store.get_all(context_id)
}

/// Grants budget to a member in a context. Test-only.
#[cfg(feature = "testing")]
pub async fn grant_budget_for_test_legacy(
    supervisor: &Supervisor,
    context_id: &str,
    member_did: &DID,
    amount: scp_protocol::economy::types::Amount,
) {
    if let Ok(ctx_arc) = manager_methods::get_context_arc(supervisor, context_id) {
        let mut guard = ctx_arc.lock().await;
        let ctx = &mut *guard;
        ctx.governance.budget_tracker.grant(member_did, amount);
    } else {
        tracing::error!(
            context_id,
            "grant_budget_for_test: context not registered or Supervisor not attached — skipping"
        );
    }
}

/// Returns the remaining budget for a member in a context. Test-only.
#[cfg(feature = "testing")]
pub async fn remaining_budget_for_test_legacy(
    supervisor: &Supervisor,
    context_id: &str,
    member_did: &DID,
) -> scp_protocol::economy::types::Amount {
    let Ok(arc) = manager_methods::get_context_arc(supervisor, context_id) else {
        return scp_protocol::economy::types::Amount::new(0);
    };
    let ctx = arc.lock().await;
    ctx.governance.budget_tracker.remaining(member_did)
}

/// Returns the per-DID velocity (number of recent paid actions) for
/// a member in a context within the velocity window. Test-only.
#[cfg(feature = "testing")]
pub async fn velocity_for_test_legacy(
    supervisor: &Supervisor,
    context_id: &str,
    member_did: &DID,
    now_secs: u64,
) -> u64 {
    let Ok(arc) = manager_methods::get_context_arc(supervisor, context_id) else {
        return 0;
    };
    let ctx = arc.lock().await;
    ctx.governance
        .velocity_tracker
        .get_velocity(member_did, now_secs)
}

// ===========================================================================
// Checkpoint operations (§9.9.3, ADR-011 AC-8)
// ===========================================================================

/// Creates a consistency checkpoint if one is due based on event count
/// or time interval thresholds.
///
/// A checkpoint is due when either:
/// - 50 events have been appended since the last checkpoint, or
/// - 10 minutes have elapsed since the last checkpoint.
pub fn create_checkpoint_if_due_legacy(
    supervisor: &Supervisor,
    context_id: &str,
    ctx: &mut PerContextState,
    sender_did: &DID,
    signing_key: &ed25519_dalek::SigningKey,
) -> Option<scp_event_log::checkpoint::ConsistencyCheckpoint> {
    // Synchronous helper; on detached Supervisor degrades to `None`
    // (no checkpoint created).
    let clock = supervisor.clock_ref()?;
    let event_log = supervisor.event_log_ref()?;
    let now = clock.now_secs();
    crate::context::queries_helpers::create_checkpoint_if_due_split(
        context_id,
        ctx.broadcast_context.is_none(),
        ctx.epoch.mls_epoch,
        &mut ctx.checkpoints,
        &mut ctx.checkpoint_events_since,
        &mut ctx.checkpoint_last_time_secs,
        sender_did,
        signing_key,
        now,
        event_log.as_ref(),
    )
}

/// Unconditionally creates a consistency checkpoint regardless of whether
/// the event/time thresholds have been reached.
pub fn force_create_checkpoint_legacy(
    supervisor: &Supervisor,
    context_id: &str,
    ctx: &mut PerContextState,
    sender_did: &DID,
    signing_key: &ed25519_dalek::SigningKey,
) -> Option<scp_event_log::checkpoint::ConsistencyCheckpoint> {
    // ADR-049 commit 12c.9d — returns `Option` so a detached attach
    // slot degrades to `None`. Clippy's `expect_used` / `panic` lints
    // are denied crate-wide, so we cannot fall through with `expect`.
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

/// Compares a remote checkpoint against local event log state for
/// equivocation detection (§9.9.3, ADR-011 AC-8).
///
/// # Errors
///
/// Returns [`ContextError::ContextNotRegistered`] if the context is
/// not registered.
/// Returns [`ContextError::MemberNotFound`] if the checkpoint sender
/// is not a member of the context.
/// Returns [`ContextError::CryptoFailed`] if the public key cannot be
/// resolved or the Ed25519 signature verification fails.
pub async fn compare_remote_checkpoint_legacy(
    supervisor: &Supervisor,
    context_id: &str,
    remote: &scp_event_log::checkpoint::ConsistencyCheckpoint,
) -> Result<scp_event_log::checkpoint::CheckpointComparison, ContextError> {
    let key_resolver = supervisor
        .key_resolver_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let event_log = supervisor
        .event_log_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    // Verify the sender is a member of this context.
    {
        let ctx_arc = manager_methods::get_context_arc(supervisor, context_id)
            .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
        let guard = ctx_arc.lock().await;
        let ctx = &*guard;
        if !ctx.membership.contains(remote.sender_did.as_ref()) {
            return Err(ContextError::MemberNotFound(format!(
                "checkpoint sender {} is not a member of context {context_id}",
                remote.sender_did
            )));
        }
    }

    // Verify checkpoint Ed25519 signature.
    let sender_pk = (key_resolver)(&remote.sender_did).ok_or_else(|| {
        ContextError::CryptoFailed(format!(
            "cannot resolve public key for checkpoint sender {}",
            remote.sender_did
        ))
    })?;
    scp_event_log::checkpoint::verify_checkpoint_signature(remote, &sender_pk).map_err(
        |reason| {
            ContextError::CryptoFailed(format!(
                "checkpoint signature verification failed: {reason}"
            ))
        },
    )?;

    let context_id_bytes = context_id_to_bytes(context_id);
    let local_root = event_log
        .event_log_merkle_root(&context_id_bytes)
        .unwrap_or([0u8; 32]);
    let local_count = event_log
        .event_log_entries(&context_id_bytes)
        .ok()
        .flatten()
        .map_or(0, |e| e.len() as u64);

    // Note: `prove_consistency` is NOT used here because consistency
    // proofs prove that a smaller version of the SAME log is a prefix
    // of a larger version. Cross-member equivocation detection compares
    // two DIFFERENT logs from different members — Merkle root comparison
    // is the correct mechanism (identical roots ⇒ identical event
    // sequences, per second-preimage resistance of SHA-256).
    let comparison = match local_count.cmp(&remote.event_count) {
        std::cmp::Ordering::Equal => {
            if local_root == remote.merkle_root {
                scp_event_log::checkpoint::CheckpointComparison::Consistent
            } else {
                scp_event_log::checkpoint::CheckpointComparison::Divergent {
                    first_divergent_event: None,
                }
            }
        }
        std::cmp::Ordering::Less => scp_event_log::checkpoint::CheckpointComparison::Behind {
            missing_events: remote.event_count - local_count,
        },
        std::cmp::Ordering::Greater => scp_event_log::checkpoint::CheckpointComparison::Ahead {
            extra_events: local_count - remote.event_count,
        },
    };

    // Emit EquivocationDetected event when divergent.
    if matches!(
        comparison,
        scp_event_log::checkpoint::CheckpointComparison::Divergent { .. }
    ) {
        tracing::warn!(
            context_id,
            remote_sender = %remote.sender_did,
            event_count = remote.event_count,
            "relay equivocation detected — divergent Merkle roots at same event count (§9.9.3)"
        );
        if let Err(e) = event_log.append_context_event(
            &context_id_bytes,
            "EquivocationDetected",
            remote.sender_did.as_ref(),
        ) {
            tracing::warn!(
                context_id,
                "failed to append EquivocationDetected to event log: {e}"
            );
        }
        if let Ok(ctx_arc) = manager_methods::get_context_arc(supervisor, context_id) {
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;
            ctx.checkpoint_events_since += 1;
            let event = ContextEvent::EquivocationDetected {
                context_id: context_id.to_owned(),
                remote_sender_did: remote.sender_did.clone(),
                event_count: remote.event_count,
            };
            ctx.emit_event(event, context_id, supervisor.event_tx_ref());
        }
    }

    Ok(comparison)
}

// ===========================================================================
// Merkle proof operations (ADR-011, #1535)
// ===========================================================================

/// Returns a Merkle inclusion proof for the event at the given index
/// in the per-context RFC 6962 event log.
///
/// # Errors
///
/// Returns [`ContextError::ContextNotRegistered`] if the context is unknown.
/// Returns [`ContextError::EventLogFailed`] if the leaf index is out of
/// bounds or the log is empty.
pub async fn prove_event_inclusion_legacy(
    supervisor: &Supervisor,
    context_id: &str,
    leaf_index: u64,
) -> Result<scp_event_log::proof::InclusionProof, ContextError> {
    let event_log = supervisor
        .event_log_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let ctx_arc = manager_methods::get_context_arc(supervisor, context_id)
        .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
    let mut guard = ctx_arc.lock().await;
    let ctx = &mut *guard;
    sync_merkle_tree_legacy(context_id, ctx, event_log.as_ref());
    scp_event_log::proof::prove_inclusion(&ctx.merkle_tree, leaf_index)
        .map_err(|e| ContextError::EventLogFailed(e.to_string()))
}

/// Returns a Merkle consistency proof between the tree at `old_size` and
/// the current tree size.
///
/// # Errors
///
/// Returns [`ContextError::ContextNotRegistered`] if the context is unknown.
/// Returns [`ContextError::EventLogFailed`] if `old_size` is 0, exceeds
/// the current size, or the log is empty.
pub async fn prove_event_consistency_legacy(
    supervisor: &Supervisor,
    context_id: &str,
    old_size: u64,
) -> Result<scp_event_log::proof::ConsistencyProof, ContextError> {
    let event_log = supervisor
        .event_log_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let ctx_arc = manager_methods::get_context_arc(supervisor, context_id)
        .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
    let mut guard = ctx_arc.lock().await;
    let ctx = &mut *guard;
    sync_merkle_tree_legacy(context_id, ctx, event_log.as_ref());
    let current_size = scp_event_log::tree::event_count(&ctx.merkle_tree);
    scp_event_log::proof::prove_consistency(&ctx.merkle_tree, old_size, current_size)
        .map_err(|e| ContextError::EventLogFailed(e.to_string()))
}

// ===========================================================================
// Merkle tree synchronization (private helper used by `prove_event_*`)
// ===========================================================================

/// Synchronizes the per-context Merkle tree with the
/// `MerkleEventLogProvider`.
///
/// Replays missing entries — each pre-computed hash is pushed as a raw
/// leaf and the internal tree structure (RFC 6962 interior nodes) is
/// rebuilt automatically by `push_leaf_raw`.
fn sync_merkle_tree_legacy(
    context_id: &str,
    ctx: &mut PerContextState,
    event_log: &dyn crate::context::builder::ContextEventLogProvider,
) {
    let context_id_bytes = context_id_to_bytes(context_id);
    // event_count returns u64; on 32-bit targets the log size is bounded
    // by available memory well below u32::MAX, so saturating is safe.
    let tree_count =
        usize::try_from(scp_event_log::tree::event_count(&ctx.merkle_tree)).unwrap_or(usize::MAX);

    if let Ok(Some(entries)) = event_log.event_log_entries(&context_id_bytes)
        && entries.len() > tree_count
    {
        for entry in entries.iter().skip(tree_count) {
            ctx.merkle_tree.push_leaf_raw(entry.hash);
        }
    }
}
