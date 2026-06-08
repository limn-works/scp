// Module-level allow — `dead_code` is allowed module-wide because this
// module is the authoritative home for query-domain free functions
// consumed by FFI bridges (PyO3 / NAPI / UniFFI / WASM) and by external
// test crates behind `feature = "testing"`. Several of the actor-shape
// helpers wired here have no in-tree caller until the supervisor's
// `dispatch_query` shim is deleted in Phase 2A finalization; until then
// the live FFI / test path still flows through
// [`crate::context::queries_helpers_legacy`] via the supervisor
// passthroughs.
#![allow(clippy::significant_drop_tightening, dead_code)]

//! Queries-domain helpers — actor-shape signatures
//! (ADR-049 Phase 2A.10, `queries` domain migration).
//!
//! # Purpose
//!
//! This module hosts query-domain helpers that operate on actor-owned
//! [`PerContextState`](crate::context::actor::state::PerContextState) and
//! capability-reduced [`ActorDeps`](crate::context::actor::deps::ActorDeps).
//! The legacy `&Supervisor` lock-and-call bodies live in
//! [`crate::context::queries_helpers_legacy`] until Phase 2A
//! finalization removes the shim fallback.
//!
//! # Pipeline shape
//!
//! Actor-owned state collapses the legacy lock dance: each query is
//! serialized through the per-context actor's mailbox, so per-context
//! reads borrow `state` directly. Mutating reads (`drain_events`,
//! `report_degraded_mode`, access-key management, checkpoint creation,
//! Merkle-tree sync used by `prove_event_*`) take `&mut state` without
//! the legacy lock-drop / re-acquire dance because the actor IS the
//! per-context generation.
//!
//! # Helpers
//!
//! Per-context read queries (actor-shape `(state: &PerContextState,
//! ...)`):
//!
//! - [`local_pseudonym`] — pseudonym routing ID lookup (§9.10.4).
//! - [`get_broadcast_key_for_local_author`] — broadcast author key +
//!   epoch lookup. Caller must verify the author DID is locally
//!   controlled (the actor sees its `deps.local_dids` snapshot).
//! - [`member_count`], [`is_member`], [`member_dids`], [`member_role`],
//!   [`context_params`], [`get_role_state`], [`pending_commits`],
//!   [`commit_fault`] — straight reads from `state`.
//!
//! Per-context mutating reads (actor-shape `(state: &mut
//! PerContextState, deps: &ActorDeps, ...)`):
//!
//! - [`drain_events`] — drains the receive buffer.
//! - [`report_degraded_mode`] — emits a `DegradedMode` event.
//! - [`generate_context_access_key`], [`revoke_context_access_key`],
//!   [`restore_context_access_key`], [`set_access_key`],
//!   [`remove_access_key`] — access-key store mutations.
//! - [`inject_access_key`], [`get_access_key`], [`get_all_access_keys`],
//!   [`grant_budget_for_test`], [`remaining_budget_for_test`],
//!   [`velocity_for_test`] — `#[cfg(feature = "testing")]` accessors.
//! - [`compare_remote_checkpoint`] — equivocation detection (§9.9.3).
//!   Mutates `checkpoint_events_since` on divergent compare.
//! - [`prove_event_inclusion`], [`prove_event_consistency`] — Merkle
//!   proofs. `sync_merkle_tree` mutation runs first.
//!
//! Field-disjoint actor-shape entries used by other domains:
//!
//! - [`event_log_entries`] — passthrough on `deps.event_log` (no per-
//!   context state).
//! - [`create_checkpoint_if_due`],
//!   [`force_create_checkpoint_fields`] — field-disjoint signatures
//!   used by `messaging_helpers` / `lifecycle_helpers` actor paths to
//!   drive §9.9.3 checkpointing.
//!
//! Pure helpers (no state, no deps):
//!
//! - [`verify_event_inclusion`], [`verify_event_consistency`].
//!
//! # Supervisor-scoped (designated-legacy)
//!
//! These helpers operate on supervisor-wide state, not per-context
//! state, so they take `&Supervisor` rather than
//! `&[mut] PerContextState`:
//!
//! - [`register_local_did`] / [`is_local_did`] — `local_dids` `ArcSwap` +
//!   `write_lock` mutations.
//!
//! Relocated from `queries_helpers_legacy` during Phase 2A
//! finalization; the `_legacy` suffix is dropped because there is no
//! per-context actor-shape twin to disambiguate against.

use std::collections::HashMap;

use scp_identity::DID;
use scp_protocol::context::membership::ContextEvent;
use scp_protocol::context::roles::{Capability, ContextRoleState, RoleAssignment};
use scp_protocol::context::{ContextError, ContextParams};
use zeroize::Zeroizing;

use crate::context::actor::deps::ActorDeps;
use crate::context::actor::state::PerContextState;
use crate::context::builder::ContextEventLogProvider;
use crate::context::providers::event_log::EventLogEntry;
use crate::context::state::{self, CommitFaultMarker, PendingCommit};

/// Maximum number of checkpoints retained per context. Older checkpoints
/// are drained when this limit is exceeded to prevent unbounded growth.
const MAX_RETAINED_CHECKPOINTS: usize = 100;

// ===========================================================================
// Per-context read queries (actor-shape)
// ===========================================================================

/// Returns the local member's pseudonym routing ID for a context
/// (§9.10.4).
///
/// Pure read — no `deps` reach. The actor's `state` already carries
/// the per-context pseudonym slot.
#[must_use]
pub const fn local_pseudonym(state: &PerContextState) -> Option<[u8; 32]> {
    state.local_pseudonym
}

/// Returns the broadcast key and epoch for an author in a broadcast
/// context.
///
/// # Caller responsibility
///
/// The caller MUST verify the `author_did` is locally controlled before
/// invoking this helper — the actor's `deps.local_dids` snapshot is
/// available for that check, but is supervisor-scoped (not part of
/// per-context `state`). The actor handler dispatch performs that
/// gate before invoking this body.
///
/// # Errors
///
/// - [`ContextError::MembershipFailed`] if the context is not in
///   broadcast mode.
/// - [`ContextError::MemberNotFound`] if `author_did` is not a registered
///   author in the broadcast context.
pub fn get_broadcast_key_for_local_author(
    state: &PerContextState,
    author_did: &str,
) -> Result<(Zeroizing<[u8; 32]>, u64), ContextError> {
    let bc = state
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
#[must_use]
pub fn member_count(state: &PerContextState) -> usize {
    state.membership.count()
}

/// Reads this actor's current lifecycle
/// [`ContextState`](scp_protocol::context::ContextState).
///
/// Read-only — borrows the owned `state.handle` and awaits its interior
/// read lock. The actor's dispatch loop owns `state` exclusively, so the
/// only writer of the handle's interior state is the actor itself (via a
/// lifecycle transition processed on the same single-threaded mailbox).
/// No concurrent writer can be mid-transition while this read runs, so
/// the definitive async `state()` read is used rather than the
/// non-blocking `try_read_state()` the legacy `per-context-state Mutex`
/// path required to dodge a cross-task TOCTOU.
///
/// `state` is taken as `&mut` even though the read only borrows the
/// handle immutably, so the resulting future is `Send`: an
/// `&PerContextState` borrow makes the captured future non-`Send`
/// because `PerContextState` is not `Sync` (its event callback is `dyn
/// FnMut + Send`, not `Send + Sync`). The actor's run loop owns `state`
/// exclusively so the upgraded borrow does not race — this matches the
/// `&mut` convention every read helper on the [`queries`](crate::context::actor::handlers::queries)
/// dispatch path already uses.
#[allow(clippy::needless_pass_by_ref_mut)]
pub async fn read_context_state(
    state: &mut PerContextState,
) -> scp_protocol::context::ContextState {
    state.handle.state().await
}

/// Returns `true` if the given DID is a member of the context.
#[must_use]
pub fn is_member(state: &PerContextState, did: &str) -> bool {
    state.membership.contains(did)
}

/// Returns all member DIDs for a context.
#[must_use]
pub fn member_dids(state: &PerContextState) -> Vec<String> {
    state
        .membership
        .member_dids()
        .map(std::string::ToString::to_string)
        .collect()
}

/// Returns the role assignment for a specific member.
#[must_use]
pub fn member_role(state: &PerContextState, did: &str) -> Option<RoleAssignment> {
    state.role_state.assignments.get(did).cloned()
}

/// Returns a clone of the context's creation parameters.
#[must_use]
pub fn context_params(state: &PerContextState) -> ContextParams {
    state.handle.params().clone()
}

/// Returns a clone of the role state for a context.
#[must_use]
pub fn get_role_state(state: &PerContextState) -> ContextRoleState {
    state.role_state.clone()
}

/// Returns a clone of the persistent MLS Commit retry queue (PR #1606
/// C6).
#[must_use]
pub fn pending_commits(state: &PerContextState) -> Vec<PendingCommit> {
    state.pending_commits.iter().cloned().collect()
}

/// Returns the active commit fault marker, if any (PR #1606 C6).
#[must_use]
pub fn commit_fault(state: &PerContextState) -> Option<CommitFaultMarker> {
    state.commit_fault.clone()
}

// ===========================================================================
// Receive buffer + degraded mode (actor-shape, mutating)
// ===========================================================================

/// Drains all events from the receive buffer.
pub fn drain_events(state: &mut PerContextState) -> Vec<ContextEvent> {
    state.receive_buffer.drain()
}

/// Reports that a received envelope triggered degraded mode (§13.6).
///
/// Emits a `DegradedMode` event into the receive buffer (and the
/// optional event broadcast channel from `deps.event_tx`).
pub fn report_degraded_mode(
    state: &mut PerContextState,
    deps: &ActorDeps,
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
        let event = ContextEvent::DegradedMode {
            context_id: context_id.to_owned(),
            local_version: (local_major, local_minor),
            remote_version: (remote_major, remote_minor),
            unsupported_features,
        };
        state::emit_event_into(
            &mut state.receive_buffer,
            event,
            context_id,
            deps.event_tx.as_ref(),
        );
    }
}

// ===========================================================================
// Event log passthrough (actor-shape)
// ===========================================================================

/// Returns the Merkle event log entries for a context.
///
/// Reads the shared event-log provider from `deps`. No per-context
/// state involved — the actor uses this entry to serve event-log reads
/// without dereferencing the supervisor.
///
/// # Errors
///
/// Propagates any [`ContextError`] from the event log provider.
pub fn event_log_entries(
    deps: &ActorDeps,
    context_id_bytes: &[u8; 32],
) -> Result<Option<Vec<EventLogEntry>>, ContextError> {
    deps.event_log.event_log_entries(context_id_bytes)
}

// ===========================================================================
// Access-key management (actor-shape, mutating)
// ===========================================================================

/// Generates and stores a per-member access key.
///
/// # Errors
///
/// - [`ContextError::PermissionDenied`] if `caller_did` lacks the
///   `ContextClose` (admin) capability.
/// - [`ContextError::MemberNotFound`] if `member_did` is not a member.
pub fn generate_context_access_key(
    state: &mut PerContextState,
    context_id: &str,
    member_did: &str,
    caller_did: &str,
) -> Result<(), ContextError> {
    // Authorization: access key management requires admin (ContextClose).
    if !state
        .role_state
        .member_has_capability(caller_did, &Capability::ContextClose)
    {
        return Err(ContextError::PermissionDenied(
            "access key management requires admin capability".into(),
        ));
    }

    if !state.membership.contains(member_did) {
        return Err(ContextError::MemberNotFound(format!(
            "member not found: {member_did}"
        )));
    }

    let key = scp_protocol::crypto::access_keys::generate_access_key(context_id, member_did);
    state
        .access
        .access_key_store
        .set(context_id, member_did, key);
    Ok(())
}

/// Revokes (removes) a member's access key from the access key store.
///
/// # Errors
///
/// - [`ContextError::PermissionDenied`] if `caller_did` lacks the
///   `ContextClose` (admin) capability.
/// - [`ContextError::MemberNotFound`] if no access key exists for
///   `member_did`.
pub fn revoke_context_access_key(
    state: &mut PerContextState,
    context_id: &str,
    member_did: &str,
    caller_did: &str,
) -> Result<(), ContextError> {
    // Authorization: access key management requires admin (ContextClose).
    if !state
        .role_state
        .member_has_capability(caller_did, &Capability::ContextClose)
    {
        return Err(ContextError::PermissionDenied(
            "access key management requires admin capability".into(),
        ));
    }

    state
        .access
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
/// - [`ContextError::PermissionDenied`] if `caller_did` lacks the
///   `ContextClose` (admin) capability.
/// - [`ContextError::MemberNotFound`] if `member_did` is not a member.
pub fn restore_context_access_key(
    state: &mut PerContextState,
    context_id: &str,
    member_did: &str,
    caller_did: &str,
) -> Result<(), ContextError> {
    // Authorization: access key management requires admin (ContextClose).
    if !state
        .role_state
        .member_has_capability(caller_did, &Capability::ContextClose)
    {
        return Err(ContextError::PermissionDenied(
            "access key management requires admin capability".into(),
        ));
    }

    if !state.membership.contains(member_did) {
        return Err(ContextError::MemberNotFound(format!(
            "member not found: {member_did}"
        )));
    }

    let key = scp_protocol::crypto::access_keys::generate_access_key(context_id, member_did);
    state
        .access
        .access_key_store
        .set(context_id, member_did, key);
    Ok(())
}

/// Stores an access key in the access key store. Best-effort — no
/// validation on `member_did`.
pub fn set_access_key(
    state: &mut PerContextState,
    context_id: &str,
    member_did: &str,
    key: scp_protocol::crypto::access_keys::AccessKey,
) {
    state
        .access
        .access_key_store
        .set(context_id, member_did, key);
}

/// Removes a member's access key. Best-effort — silently no-op if the
/// key is absent.
pub fn remove_access_key(state: &mut PerContextState, context_id: &str, member_did: &str) {
    state.access.access_key_store.remove(context_id, member_did);
}

// ===========================================================================
// Test-only accessors
// ===========================================================================

/// Injects an access key. Test-only.
#[cfg(feature = "testing")]
pub fn inject_access_key(
    state: &mut PerContextState,
    context_id: &str,
    member_did: &str,
    key: scp_protocol::crypto::access_keys::AccessKey,
) {
    state
        .access
        .access_key_store
        .set(context_id, member_did, key);
}

/// Retrieves a clone of a member's access key. Test-only.
#[cfg(feature = "testing")]
#[must_use]
pub fn get_access_key(
    state: &PerContextState,
    context_id: &str,
    member_did: &str,
) -> Option<scp_protocol::crypto::access_keys::AccessKey> {
    state
        .access
        .access_key_store
        .get(context_id, member_did)
        .cloned()
}

/// Retrieves clones of ALL access keys for a context. Test-only.
#[cfg(feature = "testing")]
#[must_use]
pub fn get_all_access_keys(
    state: &PerContextState,
    context_id: &str,
) -> HashMap<String, scp_protocol::crypto::access_keys::AccessKey> {
    state.access.access_key_store.get_all(context_id)
}

/// Grants budget to a member. Test-only.
#[cfg(feature = "testing")]
pub fn grant_budget_for_test(
    state: &mut PerContextState,
    member_did: &DID,
    amount: scp_protocol::economy::types::Amount,
) {
    state.governance.budget_tracker.grant(member_did, amount);
}

/// Returns the remaining budget for a member. Test-only.
#[cfg(feature = "testing")]
#[must_use]
pub fn remaining_budget_for_test(
    state: &PerContextState,
    member_did: &DID,
) -> scp_protocol::economy::types::Amount {
    state.governance.budget_tracker.remaining(member_did)
}

/// Returns the per-DID velocity for a member. Test-only.
#[cfg(feature = "testing")]
#[must_use]
pub fn velocity_for_test(state: &PerContextState, member_did: &DID, now_secs: u64) -> u64 {
    state
        .governance
        .velocity_tracker
        .get_velocity(member_did, now_secs)
}

// ===========================================================================
// Checkpoint operations (§9.9.3, ADR-011 AC-8) — actor-shape entries
// ===========================================================================

/// Creates a consistency checkpoint when due (§9.9.3 thresholds).
///
/// Takes per-field references so callers may pass disjoint sub-borrows
/// of the unified [`PerContextState`] (ADR-049 §Decision 1). The `now`
/// value is supplied by the caller (typically `deps.clock.now_secs()`)
/// so the body remains pure.
///
/// A checkpoint is due when either:
/// - 50 events have been appended since the last checkpoint, or
/// - 10 minutes have elapsed since the last checkpoint.
#[allow(clippy::too_many_arguments)] // Required to avoid a per-call wrapper struct allocation.
pub fn create_checkpoint_if_due(
    context_id: &str,
    broadcast_context_is_none: bool,
    mls_epoch: u64,
    checkpoints: &mut Vec<scp_event_log::checkpoint::ConsistencyCheckpoint>,
    checkpoint_events_since: &mut u64,
    checkpoint_last_time_secs: &mut u64,
    sender_did: &DID,
    signing_key: &ed25519_dalek::SigningKey,
    now: u64,
    event_log: &dyn ContextEventLogProvider,
) -> Option<scp_event_log::checkpoint::ConsistencyCheckpoint> {
    let events_due = *checkpoint_events_since >= 50;
    // Time-based checkpoints require at least one event — creating a
    // checkpoint for zero events is wasteful and indistinguishable from
    // the previous checkpoint.
    let time_due =
        *checkpoint_events_since > 0 && now.saturating_sub(*checkpoint_last_time_secs) >= 600;

    if !events_due && !time_due {
        return None;
    }

    let cp = build_checkpoint(
        context_id,
        broadcast_context_is_none,
        mls_epoch,
        sender_did,
        signing_key,
        now,
        event_log,
    );

    *checkpoint_events_since = 0;
    *checkpoint_last_time_secs = now;
    checkpoints.push(cp.clone());

    if checkpoints.len() > MAX_RETAINED_CHECKPOINTS {
        checkpoints.drain(..checkpoints.len() - MAX_RETAINED_CHECKPOINTS);
    }

    tracing::debug!(
        context_id,
        event_count = cp.event_count,
        "consistency checkpoint created (§9.9.3)"
    );

    Some(cp)
}

/// Unconditionally creates a consistency checkpoint regardless of
/// whether the event/time thresholds have been reached. Takes per-field
/// references so callers may pass disjoint sub-borrows of the unified
/// [`PerContextState`] (ADR-049 §Decision 1).
#[allow(clippy::too_many_arguments)]
pub fn force_create_checkpoint_fields(
    context_id: &str,
    broadcast_context_is_none: bool,
    mls_epoch: u64,
    checkpoint_events_since: &mut u64,
    checkpoint_last_time_secs: &mut u64,
    checkpoints: &mut Vec<scp_event_log::checkpoint::ConsistencyCheckpoint>,
    sender_did: &DID,
    signing_key: &ed25519_dalek::SigningKey,
    now: u64,
    event_log: &dyn ContextEventLogProvider,
) -> scp_event_log::checkpoint::ConsistencyCheckpoint {
    let cp = build_checkpoint(
        context_id,
        broadcast_context_is_none,
        mls_epoch,
        sender_did,
        signing_key,
        now,
        event_log,
    );

    *checkpoint_events_since = 0;
    *checkpoint_last_time_secs = now;
    checkpoints.push(cp.clone());

    if checkpoints.len() > MAX_RETAINED_CHECKPOINTS {
        checkpoints.drain(..checkpoints.len() - MAX_RETAINED_CHECKPOINTS);
    }

    tracing::info!(
        context_id,
        event_count = cp.event_count,
        "forced final checkpoint on context close (§9.9.3)"
    );

    cp
}

/// Builds a signed checkpoint from the current event log. Pure function
/// over the field slice the §9.9.3 canonical-hash inputs require.
fn build_checkpoint(
    context_id: &str,
    broadcast_context_is_none: bool,
    mls_epoch: u64,
    sender_did: &DID,
    signing_key: &ed25519_dalek::SigningKey,
    now: u64,
    event_log: &dyn ContextEventLogProvider,
) -> scp_event_log::checkpoint::ConsistencyCheckpoint {
    let context_id_bytes = state::context_id_to_bytes(context_id);
    let merkle_root = event_log
        .event_log_merkle_root(&context_id_bytes)
        .unwrap_or([0u8; 32]);
    let event_count = event_log
        .event_log_entries(&context_id_bytes)
        .ok()
        .flatten()
        .map_or(0, |entries| entries.len() as u64);

    // Encrypted contexts (no broadcast_context) use MLS epochs; broadcast
    // contexts do not use MLS and have no meaningful epoch.
    let epoch = if broadcast_context_is_none {
        Some(mls_epoch)
    } else {
        None
    };

    let canonical_hash = scp_event_log::checkpoint::compute_checkpoint_canonical_hash(
        context_id,
        sender_did.as_ref(),
        event_count,
        &merkle_root,
        epoch,
        now,
    );

    let signature = ed25519_dalek::Signer::sign(signing_key, &canonical_hash);

    scp_event_log::checkpoint::ConsistencyCheckpoint {
        context_id: context_id.to_owned(),
        sender_did: sender_did.clone(),
        event_count,
        merkle_root,
        epoch,
        timestamp: now,
        signature: signature.to_bytes().to_vec(),
    }
}

/// Compares a remote checkpoint against local event-log state for
/// equivocation detection (§9.9.3, ADR-011 AC-8).
///
/// Actor-shape — uses `deps.event_log`, `deps.key_resolver`, and
/// `deps.event_tx` directly; mutates `state.checkpoint_events_since`
/// and pushes a `ContextEvent::EquivocationDetected` event into the
/// receive buffer when divergent.
///
/// # Errors
///
/// - [`ContextError::MemberNotFound`] if the checkpoint sender is not a
///   member of the context.
/// - [`ContextError::CryptoFailed`] if the public key cannot be
///   resolved or the Ed25519 signature verification fails.
pub fn compare_remote_checkpoint(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    remote: &scp_event_log::checkpoint::ConsistencyCheckpoint,
) -> Result<scp_event_log::checkpoint::CheckpointComparison, ContextError> {
    // Verify the sender is a member of this context.
    if !state.membership.contains(remote.sender_did.as_ref()) {
        return Err(ContextError::MemberNotFound(format!(
            "checkpoint sender {} is not a member of context {context_id}",
            remote.sender_did
        )));
    }

    // Verify checkpoint Ed25519 signature.
    let sender_pk = (deps.key_resolver)(&remote.sender_did).ok_or_else(|| {
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

    let context_id_bytes = state::context_id_to_bytes(context_id);
    let local_root = deps
        .event_log
        .event_log_merkle_root(&context_id_bytes)
        .unwrap_or([0u8; 32]);
    let local_count = deps
        .event_log
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
        if let Err(e) = deps.event_log.append_context_event(
            &context_id_bytes,
            "EquivocationDetected",
            remote.sender_did.as_ref(),
        ) {
            tracing::warn!(
                context_id,
                "failed to append EquivocationDetected to event log: {e}"
            );
        }
        state.checkpoint_events_since += 1;
        let event = ContextEvent::EquivocationDetected {
            context_id: context_id.to_owned(),
            remote_sender_did: remote.sender_did.clone(),
            event_count: remote.event_count,
        };
        state::emit_event_into(
            &mut state.receive_buffer,
            event,
            context_id,
            deps.event_tx.as_ref(),
        );
    }

    Ok(comparison)
}

// ===========================================================================
// Merkle proof operations (ADR-011, #1535) — actor-shape
// ===========================================================================

/// Returns a Merkle inclusion proof for the event at `leaf_index` in
/// the per-context RFC 6962 event log.
///
/// Actor-shape — synchronizes the in-memory Merkle tree against the
/// shared event-log provider before constructing the proof.
///
/// # Errors
///
/// Returns [`ContextError::EventLogFailed`] if the leaf index is out of
/// bounds or the log is empty.
pub fn prove_event_inclusion(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    leaf_index: u64,
) -> Result<scp_event_log::proof::InclusionProof, ContextError> {
    sync_merkle_tree(context_id, state, deps.event_log.as_ref());
    scp_event_log::proof::prove_inclusion(&state.merkle_tree, leaf_index)
        .map_err(|e| ContextError::EventLogFailed(e.to_string()))
}

/// Returns a Merkle consistency proof between the tree at `old_size`
/// and the current tree size.
///
/// # Errors
///
/// Returns [`ContextError::EventLogFailed`] if `old_size` is 0, exceeds
/// the current size, or the log is empty.
pub fn prove_event_consistency(
    state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    old_size: u64,
) -> Result<scp_event_log::proof::ConsistencyProof, ContextError> {
    sync_merkle_tree(context_id, state, deps.event_log.as_ref());
    let current_size = scp_event_log::tree::event_count(&state.merkle_tree);
    scp_event_log::proof::prove_consistency(&state.merkle_tree, old_size, current_size)
        .map_err(|e| ContextError::EventLogFailed(e.to_string()))
}

/// Verifies a Merkle inclusion proof. Pure function — no state needed.
#[must_use]
pub fn verify_event_inclusion(proof: &scp_event_log::proof::InclusionProof) -> bool {
    scp_event_log::proof::verify_inclusion(proof)
}

/// Verifies a Merkle consistency proof. Pure function — no state needed.
#[must_use]
pub fn verify_event_consistency(proof: &scp_event_log::proof::ConsistencyProof) -> bool {
    scp_event_log::proof::verify_consistency(proof)
}

// ===========================================================================
// Merkle tree synchronization (private helper)
// ===========================================================================

/// Synchronizes the per-context Merkle tree with the event-log provider.
///
/// Replays missing entries — each pre-computed hash is pushed as a raw
/// leaf and the internal tree structure (RFC 6962 interior nodes) is
/// rebuilt automatically by `push_leaf_raw`.
fn sync_merkle_tree(
    context_id: &str,
    state: &mut PerContextState,
    event_log: &dyn ContextEventLogProvider,
) {
    let context_id_bytes = state::context_id_to_bytes(context_id);
    // event_count returns u64; on 32-bit targets the log size is bounded
    // by available memory well below u32::MAX, so saturating is safe.
    let tree_count =
        usize::try_from(scp_event_log::tree::event_count(&state.merkle_tree)).unwrap_or(usize::MAX);

    if let Ok(Some(entries)) = event_log.event_log_entries(&context_id_bytes)
        && entries.len() > tree_count
    {
        for entry in entries.iter().skip(tree_count) {
            state.merkle_tree.push_leaf_raw(entry.hash);
        }
    }
}

// ===========================================================================
// Supervisor-scoped helpers (designated-legacy — no per-context twin)
// ===========================================================================
//
// These helpers operate on supervisor-wide state (`local_dids` ArcSwap +
// `write_lock`), not per-context state. They have no `&mut PerContextState`
// twin because the actor model serializes per-context, not supervisor-wide.
// Relocated from `queries_helpers_legacy` in Phase 2A finalization.

/// Registers a DID as controlled by the local node/SDK.
///
/// Supervisor-scoped — mutates `supervisor.local_dids` under the
/// supervisor's write lock. No per-context actor-shape twin exists
/// because the actor model serializes per-context, not supervisor-wide.
pub async fn register_local_did(supervisor: &crate::context::supervisor::Supervisor, did: DID) {
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
/// [`register_local_did`] and the legacy method, matching the call
/// shape the FFI bridges + `Supervisor::is_local_did` passthrough
/// expect.
#[allow(clippy::unused_async)]
pub async fn is_local_did(supervisor: &crate::context::supervisor::Supervisor, did: &DID) -> bool {
    // Lock-free read (ADR-049 §Decision 12).
    supervisor.local_dids_ref().load().contains(did)
}
