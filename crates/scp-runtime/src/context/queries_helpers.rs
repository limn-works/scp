// Module-level allow — `dead_code` is allowed module-wide because this
// module is the authoritative home for query-domain free functions
// consumed by FFI bridges (PyO3 / NAPI / UniFFI) and by external
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
//! The pre-migration `&Supervisor` lock-and-call bodies have been removed
//! (Phase 2A finalization); this module is the sole home for these helpers.
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
//! - `inject_access_key`, `get_access_key`, `get_all_access_keys`,
//!   `grant_budget_for_test`, `remaining_budget_for_test`,
//!   `velocity_for_test` — `#[cfg(feature = "testing")]` accessors.
//! - [`compare_remote_checkpoint`] — equivocation detection (§9.9.3).
//!   Reads membership and mutates `last_seen_remote_checkpoint` +
//!   `receive_buffer` (via a `ClassCMut` view) on divergent compare.
//! - [`prove_event_inclusion`], [`prove_event_consistency`] — Merkle
//!   proofs. Delegate to the event-log provider, which builds the proof
//!   directly against its own canonical tree (no per-context twin tree).
//!
//! Field-disjoint actor-shape entries used by other domains:
//!
//! - [`event_log_entries`] — passthrough on `deps.event_log` (no per-
//!   context state).
//! - [`create_checkpoint_if_due_view`],
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

use scp_did::DID;
use scp_protocol::context::membership::{ContextEvent, ReceiveBuffer};
use scp_protocol::context::roles::{Capability, ContextRoleState, RoleAssignment};
use scp_protocol::context::{ContextError, ContextParams};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::context::actor::class_s::ClassCMut;
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::state::PerContextState;
use crate::context::builder::ContextEventLogProvider;
use crate::context::state::{self, CommitFaultMarker, EpochState, PendingCommit};

/// Maximum number of checkpoints retained per context. Older checkpoints
/// are drained when this limit is exceeded to prevent unbounded growth.
const MAX_RETAINED_CHECKPOINTS: usize = 100;

// ===========================================================================
// Per-context read queries (actor-shape)
// ===========================================================================

/// Returns the local member's pseudonym routing ID for a context
/// (§9.10.4).
///
/// Pure read — no `deps` reach. The actor's `state` carries the per-context
/// routing axis. Encrypted contexts return their pre-derived pseudonym;
/// broadcast contexts have no per-member pseudonym (spec §5.14) and return
/// [`ContextError::NotPseudonymousContext`] so callers can distinguish
/// "broadcast — no pseudonym" from a value-present read rather than silently
/// papering over the two with `None`.
///
/// # Errors
///
/// Returns [`ContextError::NotPseudonymousContext`] for a broadcast context.
pub fn local_pseudonym(state: &PerContextState) -> Result<[u8; 32], ContextError> {
    state
        .routing
        .local_pseudonym()
        .ok_or_else(|| ContextError::NotPseudonymousContext {
            context_id: state.handle.context_id().to_owned(),
        })
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

    let key_bytes = Zeroizing::new(*author.broadcast_key().as_bytes());
    Ok((key_bytes, author.epoch()))
}

/// Returns the current member count for a context.
#[must_use]
pub fn member_count(state: &PerContextState) -> usize {
    state.membership.count()
}

/// Returns the local MLS epoch for the context (§9.12).
///
/// `Some(epoch)` for an encrypted (MLS) context; `None` for a broadcast
/// context, which uses the per-author AES-GCM layer and carries no MLS
/// epoch. Mirrors the broadcast-vs-MLS discrimination used by
/// [`build_checkpoint`] (`broadcast_context.is_none()` ⇒ MLS).
///
/// Consumed by the reconnection driver's Phase 2 (`local_epoch`).
#[must_use]
pub const fn local_mls_epoch(state: &PerContextState) -> Option<u64> {
    if state.broadcast_context.is_some() {
        None
    } else {
        Some(state.epoch.mls_epoch)
    }
}

/// Returns whether the context's `EpochState` is flagged
/// `needs_reconnect` (spec §23.11).
///
/// The flag is set on respawn when crypto state could not be restored.
/// The reconnection driver consumes it at the FFI/SDK layer to decide
/// which contexts to drive through the six-phase protocol.
#[must_use]
pub const fn needs_reconnect(state: &PerContextState) -> bool {
    state.epoch.needs_reconnect
}

/// Clears the context's `EpochState.needs_reconnect` flag (spec §23.11).
///
/// Mutating — called by the reconnection driver after a context completes
/// the six-phase protocol successfully so a later restore does not
/// re-drive the already-synced context.
///
/// Field-narrowed (ADR-049 §9) to `&mut EpochState` so a cell-holder calls it
/// with `cell.class_c_view().epoch_mut()` (no whole-state `state_mut()`), while
/// a bare-`&mut PerContextState` holder passes `&mut state.epoch`. The
/// `needs_reconnect` flag is Class-C reconnection liveness state, not a
/// fail-closed Class-S witness.
pub const fn clear_needs_reconnect(epoch: &mut EpochState) {
    epoch.needs_reconnect = false;
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

/// Returns `true` iff this context holds a bidirectionally-approved
/// [`OutletInterface`](scp_protocol::context::outlets::interface::OutletInterface)
/// from `source_context_hex` to `target_context_hex` for `outlet_registration_id`
/// (spec §6.2.0.1 standing consent / §6.2.4 target-side authorize-before-reserve).
///
/// Both `approved_by_source` AND `approved_by_target` must be set — a one-sided
/// (proposed-but-unaccepted) interface does NOT count as established, so a
/// caller cannot ride an offer the target never accepted. All three id-form
/// fields are compared on the raw 64-hex digest form the establishing flow
/// stored (spec §6.2.4 id-form rule).
#[must_use]
pub fn has_established_outlet_interface(
    state: &PerContextState,
    source_context_hex: &str,
    target_context_hex: &str,
    outlet_registration_id: &str,
) -> bool {
    state.governance.outlet_interfaces.iter().any(|i| {
        i.approved_by_source
            && i.approved_by_target
            && i.source_context == source_context_hex
            && i.target_context == target_context_hex
            && i.outlet_id == outlet_registration_id
    })
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

/// Returns the payment receipts captured in this context (spec §19.11),
/// optionally narrowed by `filter`.
///
/// Reads the actor-owned `state.payment_receipts` local buffer — NOT the
/// durable Merkle log. `PaymentReceived` is per-payee application activity
/// excluded from the canonical log (ADR-011 amendment exclusion taxonomy §2),
/// so surfacing it from the local buffer is what keeps `event_log_merkle_root`
/// convergent across honest members (§9.9.3).
pub(super) fn payment_history(
    state: &PerContextState,
    filter: Option<&crate::economy::receipt::ReceiptFilter>,
) -> Vec<crate::economy::adapter::PaymentReceipt> {
    crate::economy::receipt::payment_history(&state.payment_receipts, filter)
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
    receive_buffer: &mut ReceiveBuffer,
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
        state::emit_event_into(receive_buffer, event, context_id, deps.event_tx.as_ref());
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
) -> Result<Option<Vec<scp_event_log::Event>>, ContextError> {
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
    view: &mut ClassCMut,
    context_id: &str,
    member_did: &str,
    caller_did: &str,
) -> Result<(), ContextError> {
    // Authorization: access key management requires admin (ContextClose).
    if !view
        .role_state_class_c_mut()
        .member_has_capability(caller_did, &Capability::ContextClose)
    {
        return Err(ContextError::PermissionDenied(
            "access key management requires admin capability".into(),
        ));
    }

    if !view.membership_class_c_mut().contains(member_did) {
        return Err(ContextError::MemberNotFound(format!(
            "member not found: {member_did}"
        )));
    }

    let key = scp_protocol::crypto::access_keys::generate_access_key(context_id, member_did);
    view.access_mut()
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
    view: &mut ClassCMut,
    context_id: &str,
    member_did: &str,
    caller_did: &str,
) -> Result<(), ContextError> {
    // Authorization: access key management requires admin (ContextClose).
    if !view
        .role_state_class_c_mut()
        .member_has_capability(caller_did, &Capability::ContextClose)
    {
        return Err(ContextError::PermissionDenied(
            "access key management requires admin capability".into(),
        ));
    }

    view.access_mut()
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
    view: &mut ClassCMut,
    context_id: &str,
    member_did: &str,
    caller_did: &str,
) -> Result<(), ContextError> {
    // Authorization: access key management requires admin (ContextClose).
    if !view
        .role_state_class_c_mut()
        .member_has_capability(caller_did, &Capability::ContextClose)
    {
        return Err(ContextError::PermissionDenied(
            "access key management requires admin capability".into(),
        ));
    }

    if !view.membership_class_c_mut().contains(member_did) {
        return Err(ContextError::MemberNotFound(format!(
            "member not found: {member_did}"
        )));
    }

    let key = scp_protocol::crypto::access_keys::generate_access_key(context_id, member_did);
    view.access_mut()
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
) -> std::collections::HashMap<String, scp_protocol::crypto::access_keys::AccessKey> {
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

/// Unconditionally creates a consistency checkpoint via a [`ClassCMut`] view,
/// the actor-shape sibling of [`force_create_checkpoint_fields`].
///
/// Identical semantics, but reaches the three Class-C checkpoint fields
/// (`checkpoint_events_since`, `checkpoint_last_time_secs`, `checkpoints`)
/// through the view's field-granular accessors — touched in SEPARATE
/// statements so each `&mut` borrow ends before the next, which is what lets
/// the actor handler drive this with no whole `&mut PerContextState`.
/// `broadcast_context_is_none` and `mls_epoch` are read by the caller from the
/// view (their borrows released) before this call. Returns the built checkpoint.
#[allow(clippy::too_many_arguments)]
pub fn force_create_checkpoint_view(
    view: &mut ClassCMut,
    context_id: &str,
    broadcast_context_is_none: bool,
    mls_epoch: u64,
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

    // Sequential per-field view accessors: each `&mut` borrow ends before the
    // next, so no whole `&mut PerContextState` (nor a 3-field simultaneous
    // borrow) is needed.
    *view.checkpoint_events_since_mut() = 0;
    *view.checkpoint_last_time_secs_mut() = now;
    {
        let checkpoints = view.checkpoints_mut();
        checkpoints.push(cp.clone());
        if checkpoints.len() > MAX_RETAINED_CHECKPOINTS {
            checkpoints.drain(..checkpoints.len() - MAX_RETAINED_CHECKPOINTS);
        }
    }

    tracing::info!(
        context_id,
        event_count = cp.event_count,
        "forced final checkpoint on context close (§9.9.3)"
    );

    cp
}

/// Creates a consistency checkpoint when due (§9.9.3 thresholds) via a
/// [`ClassCMut`] view — the actor-shape checkpoint entry for the send path.
///
/// Same §9.9.3 gating (50-event / 600-second thresholds) and semantics as the
/// unconditional [`force_create_checkpoint_view`], but reaches the three Class-C
/// checkpoint
/// fields (`checkpoint_events_since`, `checkpoint_last_time_secs`,
/// `checkpoints`) through the view's field-granular accessors, touched in
/// SEPARATE statements so each `&mut` borrow ends before the next — which is
/// what lets the send path drive this with no whole `&mut PerContextState` (nor
/// a 3-field simultaneous borrow). `broadcast_context_is_none` and `mls_epoch`
/// are read by the caller from the view (their borrows released) before this
/// call. Returns the built checkpoint when one was due, else `None`.
#[allow(clippy::too_many_arguments)]
pub fn create_checkpoint_if_due_view(
    view: &mut ClassCMut,
    context_id: &str,
    broadcast_context_is_none: bool,
    mls_epoch: u64,
    sender_did: &DID,
    signing_key: &ed25519_dalek::SigningKey,
    now: u64,
    event_log: &dyn ContextEventLogProvider,
) -> Option<scp_event_log::checkpoint::ConsistencyCheckpoint> {
    let events_since = *view.checkpoint_events_since_mut();
    let last_time = *view.checkpoint_last_time_secs_mut();
    let events_due = events_since >= 50;
    // Time-based checkpoints require at least one event — creating a checkpoint
    // for zero events is wasteful and indistinguishable from the previous one.
    let time_due = events_since > 0 && now.saturating_sub(last_time) >= 600;

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

    // Sequential per-field view accessors: each `&mut` borrow ends before the
    // next, so no whole `&mut PerContextState` (nor a 3-field simultaneous
    // borrow) is needed.
    *view.checkpoint_events_since_mut() = 0;
    *view.checkpoint_last_time_secs_mut() = now;
    {
        let checkpoints = view.checkpoints_mut();
        checkpoints.push(cp.clone());
        if checkpoints.len() > MAX_RETAINED_CHECKPOINTS {
            checkpoints.drain(..checkpoints.len() - MAX_RETAINED_CHECKPOINTS);
        }
    }

    tracing::debug!(
        context_id,
        event_count = cp.event_count,
        "consistency checkpoint created (§9.9.3)"
    );

    Some(cp)
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

/// Fail-closed authenticity gate for a remote checkpoint: the sender must
/// be a current member and the checkpoint's Ed25519 signature must verify
/// against the sender's resolved public key.
///
/// # Errors
///
/// - [`ContextError::MemberNotFound`] if the sender is not a member.
/// - [`ContextError::CryptoFailed`] if the public key cannot be resolved
///   or the signature verification fails.
fn verify_remote_checkpoint_authenticity(
    sender_is_member: bool,
    deps: &ActorDeps,
    context_id: &str,
    remote: &scp_event_log::checkpoint::ConsistencyCheckpoint,
) -> Result<(), ContextError> {
    if !sender_is_member {
        return Err(ContextError::MemberNotFound(format!(
            "checkpoint sender {} is not a member of context {context_id}",
            remote.sender_did
        )));
    }

    // A `ConsistencyCheckpoint` carries no field naming which verification
    // method signed it, so §23.12 item 1 of the sync spec tells a verifier to
    // try each operational signing key ADR-039 grants an acting agent —
    // `#active`, then `#agent` — and to accept the checkpoint when either one
    // verifies. `key_resolver` reads a key out of the sender's DID document
    // under `assertionMethod`, so a method an owner withdrew on rotation
    // supplies nothing: this code applies the current-key rule, and a key its
    // owner rotated away stops verifying a checkpoint here.
    //
    // Whether the current-key rule is the right rule for a checkpoint is OPEN.
    // §23.12 item 1 keeps that rule until a human decides, because it is the
    // narrower of the two candidates, and `.docs/specs/00-open-questions.md`
    // carries the entry. §23.13 paragraph 1 accepts a retained `#retired-{n}`
    // method on an event-log leaf, and a checkpoint reads both ways: it states
    // something about the past, which is the property that makes a leaf content,
    // and §9.9.3 of the security-model spec also feeds it into an equivocation
    // decision a client makes now.
    //
    // Trying only `#active` rejected every checkpoint agent software signed,
    // which §23.12 item 1 has always admitted.
    let mut failures = Vec::with_capacity(2);
    for signing_key_id in scp_did::SigningKeyId::OPERATIONAL {
        let Some(sender_pk) = (deps.key_resolver)(&remote.sender_did, signing_key_id) else {
            failures.push(format!(
                "{} names no usable key on the document of checkpoint sender {}",
                signing_key_id.as_fragment(),
                remote.sender_did
            ));
            continue;
        };
        match scp_event_log::checkpoint::verify_checkpoint_signature(remote, &sender_pk) {
            Ok(()) => return Ok(()),
            Err(reason) => failures.push(format!(
                "{} key of {} rejected a checkpoint signature: {reason}",
                signing_key_id.as_fragment(),
                remote.sender_did
            )),
        }
    }

    // Report every method tried, so an operator reading a log sees why each one
    // failed rather than why a last one did.
    Err(ContextError::CryptoFailed(format!(
        "checkpoint signature verification failed: {}",
        failures.join("; ")
    )))
}

/// Verify-and-classify CORE of [`compare_remote_checkpoint`]: runs the
/// membership + signature gate and the Merkle-root/count comparison WITHOUT
/// touching per-context state. `sender_is_member` is read by the caller (so the
/// caller chooses how it borrows the roster — a [`ClassCMut`] view accessor or a
/// bare-state field). Returns the [`CheckpointComparison`](scp_event_log::checkpoint::CheckpointComparison) plus
/// `Some(local_root)` when the result is `Divergent` (the caller then applies
/// the two Class-C field mutations — dedup + receive-buffer emit — in whatever
/// borrow shape it holds). This split is what lets BOTH the actor handler
/// (cell/view) and the receive path (`deliver_checkpoint_message`, bare state)
/// share one classify path while each applies the field writes itself.
///
/// # Errors
///
/// - [`ContextError::MemberNotFound`] if the checkpoint sender is not a member.
/// - [`ContextError::CryptoFailed`] if the public key cannot be resolved or the
///   Ed25519 signature verification fails.
fn classify_remote_checkpoint(
    sender_is_member: bool,
    deps: &ActorDeps,
    context_id: &str,
    remote: &scp_event_log::checkpoint::ConsistencyCheckpoint,
) -> Result<
    (
        scp_event_log::checkpoint::CheckpointComparison,
        Option<[u8; 32]>,
    ),
    ContextError,
> {
    // Membership + Ed25519 signature gate (fail-closed before any compare).
    verify_remote_checkpoint_authenticity(sender_is_member, deps, context_id, remote)?;

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
            // Constant-time root comparison: Merkle roots are integrity
            // values and the comparison gates a security-sensitive
            // equivocation decision, so match the `ct_eq` idiom the event
            // log's own consistency checks use (export_import.rs,
            // event_log.rs) rather than a short-circuiting `==`.
            if bool::from(local_root.ct_eq(&remote.merkle_root)) {
                scp_event_log::checkpoint::CheckpointComparison::Consistent
            } else {
                scp_event_log::checkpoint::CheckpointComparison::Divergent {
                    first_divergent_event: None,
                }
            }
        }
        std::cmp::Ordering::Less => {
            // Local is BEHIND the remote (fewer events) — the EXPECTED
            // post-offline case, NOT equivocation (which is keyed strictly
            // on equal count + different root, per the `Equal` arm above,
            // §9.9.3). Surface `Behind` so the caller drives catch-up.
            //
            // CONSISTENCY-PROOF CATCH-UP SEAM (§23.7 step 3, specified
            // separately): to confirm the fetched suffix genuinely extends
            // this member's own history (the relay did not rewrite held
            // events), the catch-up path must verify a Merkle CONSISTENCY
            // proof that the last-known root is a prefix of the remote root
            // (RFC 6962 §2.1.2; ADR-011). `prove_event_consistency` /
            // `verify_event_consistency` are the reachable building blocks;
            // the event-range fetch + proof exchange that consumes them is
            // specified separately. Do NOT implement that fetch here.
            scp_event_log::checkpoint::CheckpointComparison::Behind {
                missing_events: remote.event_count - local_count,
            }
        }
        std::cmp::Ordering::Greater => scp_event_log::checkpoint::CheckpointComparison::Ahead {
            extra_events: local_count - remote.event_count,
        },
    };

    let divergence_root = if matches!(
        comparison,
        scp_event_log::checkpoint::CheckpointComparison::Divergent { .. }
    ) {
        Some(local_root)
    } else {
        None
    };
    Ok((comparison, divergence_root))
}

/// Compares a remote checkpoint against local event-log state for
/// equivocation detection (§9.9.3, ADR-011 AC-8).
///
/// Actor-shape — uses `deps.event_log`, `deps.key_resolver`, and
/// `deps.event_tx` directly. Reads membership and mutates two Class-C fields
/// via the [`ClassCMut`] view: it records the divergent `(count, root)` in
/// `last_seen_remote_checkpoint` and pushes a
/// `ContextEvent::EquivocationDetected` event into the receive buffer when
/// divergent. The two `&mut` Class-C fields are touched SEQUENTIALLY through the
/// view accessors (freshness gate over `last_seen_remote_checkpoint`, then the
/// receive-buffer emit), so no whole `&mut PerContextState` is needed.
///
/// # Errors
///
/// - [`ContextError::MemberNotFound`] if the checkpoint sender is not a
///   member of the context.
/// - [`ContextError::CryptoFailed`] if the public key cannot be
///   resolved or the Ed25519 signature verification fails.
pub fn compare_remote_checkpoint(
    view: &mut ClassCMut,
    deps: &ActorDeps,
    context_id: &str,
    remote: &scp_event_log::checkpoint::ConsistencyCheckpoint,
) -> Result<scp_event_log::checkpoint::CheckpointComparison, ContextError> {
    // Membership read via the restricted `MembershipClassCMut` (this path never
    // mutates the roster); its borrow ends before the divergence recording below.
    let sender_is_member = view
        .membership_class_c_mut()
        .contains(remote.sender_did.as_ref());
    let (comparison, divergence_root) =
        classify_remote_checkpoint(sender_is_member, deps, context_id, remote)?;

    // Record an EquivocationDetected event in the receive buffer when divergent
    // (NOT appended to the durable Merkle log — see `emit_equivocation_alert`) —
    // deduped per distinct divergent checkpoint (replay defense). The two Class-C
    // `&mut` fields are touched SEQUENTIALLY through the view: the freshness gate
    // over `last_seen_remote_checkpoint` completes before the receive-buffer emit.
    if let Some(local_root) = divergence_root
        && divergence_is_fresh(view.last_seen_remote_checkpoint_mut(), context_id, remote)
    {
        emit_equivocation_alert(
            view.receive_buffer_mut(),
            deps,
            context_id,
            remote,
            local_root,
        );
    }

    Ok(comparison)
}

/// Records a divergent remote checkpoint as an `EquivocationDetected`
/// event in the in-memory receive buffer, but only ONCE per distinct
/// divergent checkpoint per remote sender.
///
/// Replay idempotency — per-sender `(event_count, remote_merkle_root)` set
/// (sole mechanism):
///
/// The divergence is NOT appended to the durable Merkle event log: an
/// equivocation record is minted locally by the receiver and is not part of
/// the sender-authenticated leaf sequence, so logging it would let two honest
/// receivers compute divergent roots for the same context and false-positive
/// the very §9.9.3 detection it records. Because the append no longer advances
/// `local_count`, the durable-length backstop that previously routed a
/// re-delivered checkpoint to the Ahead/Behind arm is gone; the per-sender set
/// below is therefore the SOLE dedup.
///
/// Per remote sender DID we track the set of distinct
/// `(event_count, remote_merkle_root)` divergences already recorded. A
/// re-presentation whose `(count, root)` is already present is a no-op; a NEW
/// root — even at an already-seen count — is fresh evidence (two members can
/// equivocate with different forged roots at the same height; each is a
/// distinct §9.9.4 security event). Keying on the root, not on a `>` timestamp
/// monotone, is what makes that distinct-root case fire.
///
/// The per-sender set is bounded at
/// [`scp_protocol::sync::MAX_SEQUENTIAL_COMMITS`] entries. Once full, the
/// alert is still EMITTED (a §9.9.4 security event is never silently
/// discarded) but no further `(count, root)` is inserted, so a malicious
/// sender cannot pin unbounded memory.
fn record_equivocation_if_fresh(
    last_seen_remote_checkpoint: &mut std::collections::HashMap<
        DID,
        std::collections::HashSet<(u64, [u8; 32])>,
    >,
    receive_buffer: &mut ReceiveBuffer,
    deps: &ActorDeps,
    context_id: &str,
    remote: &scp_event_log::checkpoint::ConsistencyCheckpoint,
    local_root: [u8; 32],
) {
    // Field-disjoint split so the two `&mut` Class-C fields are touched
    // SEQUENTIALLY — the freshness/dedup step over `last_seen_remote_checkpoint`
    // completes (its borrow ends) before the receive-buffer emit. This lets the
    // actor handler thread each `&mut` from a `ClassCMut` view in turn (the view
    // hands out one field `&mut` at a time), with no whole `&mut PerContextState`.
    if divergence_is_fresh(last_seen_remote_checkpoint, context_id, remote) {
        emit_equivocation_alert(receive_buffer, deps, context_id, remote, local_root);
    }
}

/// Freshness/dedup gate for a divergent remote checkpoint over the per-sender
/// `(event_count, remote_merkle_root)` set (Class-C field
/// `last_seen_remote_checkpoint`). Returns `true` when the caller MUST emit a
/// fresh `EquivocationDetected` alert: a NEW `(count, root)` (recorded, bounded
/// by [`scp_protocol::sync::MAX_SEQUENTIAL_COMMITS`]) or a distinct divergence
/// past the cap (still emitted, never silently dropped — §9.9.4). Returns
/// `false` for an exact `(count, root)` re-presentation (replay-suppressed).
fn divergence_is_fresh(
    last_seen_remote_checkpoint: &mut std::collections::HashMap<
        DID,
        std::collections::HashSet<(u64, [u8; 32])>,
    >,
    context_id: &str,
    remote: &scp_event_log::checkpoint::ConsistencyCheckpoint,
) -> bool {
    let incoming = (remote.event_count, remote.merkle_root);
    let seen = last_seen_remote_checkpoint
        .entry(remote.sender_did.clone())
        .or_default();

    if seen.contains(&incoming) {
        // Exact re-presentation of an already-recorded divergent
        // checkpoint (same count AND same remote root): the signature
        // already verified, so this is an authentic (but duplicate)
        // artifact — silently absorb it.
        tracing::debug!(
            context_id,
            remote_sender = %remote.sender_did,
            event_count = remote.event_count,
            "duplicate divergent checkpoint suppressed (replay defense, §9.9.3)"
        );
        return false;
    }

    // Bound the per-sender set: still emit the alert (never silently drop a
    // §9.9.4 security event) but stop growing the set once a sender has pinned
    // MAX_SEQUENTIAL_COMMITS distinct divergences.
    if (seen.len() as u64) < scp_protocol::sync::MAX_SEQUENTIAL_COMMITS {
        seen.insert(incoming);
    }
    true
}

/// Emits a fresh `EquivocationDetected` alert into the in-memory receive buffer
/// (Class-C field `receive_buffer`) and the optional broadcast channel, carrying
/// the full forensic roots. Deliberately NOT appended to the durable Merkle
/// event log: a receiver-minted leaf is not sender-authenticated, so appending
/// it would let two honest receivers diverge their own roots and false-positive
/// §9.9.3. The per-sender `(count, root)` set in [`divergence_is_fresh`] is the
/// sole replay-dedup.
fn emit_equivocation_alert(
    receive_buffer: &mut ReceiveBuffer,
    deps: &ActorDeps,
    context_id: &str,
    remote: &scp_event_log::checkpoint::ConsistencyCheckpoint,
    local_root: [u8; 32],
) {
    tracing::warn!(
        context_id,
        remote_sender = %remote.sender_did,
        event_count = remote.event_count,
        "relay equivocation detected — divergent Merkle roots at same event count (§9.9.3)"
    );

    let event = ContextEvent::EquivocationDetected {
        context_id: context_id.to_owned(),
        remote_sender_did: remote.sender_did.clone(),
        event_count: remote.event_count,
        local_merkle_root: local_root,
        remote_merkle_root: remote.merkle_root,
    };
    state::emit_event_into(receive_buffer, event, context_id, deps.event_tx.as_ref());
}

// ===========================================================================
// Merkle proof operations (ADR-011) — actor-shape
// ===========================================================================

/// Returns a Merkle inclusion proof for the event at `leaf_index` in
/// the per-context RFC 6962 event log.
///
/// Delegates to the event-log provider, which constructs the proof directly
/// against its own canonical [`scp_event_log::EventLog`] (the single proof
/// seam — there is no second per-context tree to keep in sync).
///
/// # Errors
///
/// Returns [`ContextError::EventLogFailed`] if no log exists for the context,
/// the leaf index is out of bounds, or the log is empty.
pub fn prove_event_inclusion(
    deps: &ActorDeps,
    context_id: &str,
    leaf_index: u64,
) -> Result<scp_event_log::proof::InclusionProof, ContextError> {
    let context_id_bytes = state::context_id_to_bytes(context_id);
    deps.event_log
        .prove_event_inclusion(&context_id_bytes, leaf_index)
}

/// Returns a Merkle consistency proof between the tree at `old_size`
/// and the current tree size.
///
/// Delegates to the event-log provider (the single proof seam).
///
/// # Errors
///
/// Returns [`ContextError::EventLogFailed`] if no log exists for the context,
/// `old_size` is 0, `old_size` exceeds the current size, or the log is empty.
pub fn prove_event_consistency(
    deps: &ActorDeps,
    context_id: &str,
    old_size: u64,
) -> Result<scp_event_log::proof::ConsistencyProof, ContextError> {
    let context_id_bytes = state::context_id_to_bytes(context_id);
    deps.event_log
        .prove_event_consistency(&context_id_bytes, old_size)
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

#[cfg(test)]
mod checkpoint_authenticity_tests {
    //! Which verification method verifies a `ConsistencyCheckpoint` signature.
    //!
    //! §23.12 item 1 of the sync spec admits `#active` or `#agent`, because a
    //! `ConsistencyCheckpoint` carries seven fields and none names a
    //! verification method. Earlier code resolved `#active` alone, so a
    //! checkpoint agent software signed was rejected.
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use std::sync::Arc;

    use scp_did::{DID, SigningKeyId};

    use super::{ContextError, verify_remote_checkpoint_authenticity};
    use crate::context::actor::deps::ActorDeps;
    use crate::context::supervisor::supervisor::Supervisor;

    const SENDER: &str = "did:example:checkpoint-sender";
    const CONTEXT_ID: &str = "ctx-checkpoint-authenticity";

    /// Builds `ActorDeps` whose `key_resolver` answers with `key` for
    /// `answers_for` and with `None` for the other operational method.
    async fn deps_resolving_only(
        answers_for: SigningKeyId,
        key: ed25519_dalek::VerifyingKey,
    ) -> ActorDeps {
        use scp_platform::in_memory::InMemoryStorage;

        let crypto = Arc::new(crate::crypto::mls::provider::NodeMlsFactory::new(
            SENDER.to_owned(),
            Arc::new(scp_clock::SystemClock),
        ));
        let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
            Box::new(crate::context::builder::NotConfiguredTransportProvider);
        let event_log: Box<dyn crate::context::builder::ContextEventLogProvider> =
            Box::new(super::equivocation_dedup_tests::CountingEventLog::default());
        let key_resolver: scp_protocol::context::governance::KeyResolver =
            Arc::new(move |_: &DID, requested: SigningKeyId| {
                (requested == answers_for).then_some(key)
            });
        let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> =
            Arc::new(
                crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
                    InMemoryStorage::new(),
                )),
            );

        let supervisor = Supervisor::with_providers(
            crypto,
            transport,
            event_log,
            key_resolver,
            None,
            None,
            None,
            None,
            mls_storage,
        );
        supervisor
            .build_actor_deps(&DID(SENDER.to_owned()))
            .await
            .expect("build_actor_deps")
    }

    /// Signs a checkpoint over its canonical hash, exactly as
    /// `generate_checkpoint` does.
    fn signed_checkpoint(
        signing_key: &ed25519_dalek::SigningKey,
    ) -> scp_event_log::checkpoint::ConsistencyCheckpoint {
        use ed25519_dalek::Signer;

        let mut checkpoint = scp_event_log::checkpoint::ConsistencyCheckpoint {
            context_id: CONTEXT_ID.to_owned(),
            sender_did: DID(SENDER.to_owned()),
            event_count: 7,
            merkle_root: [4u8; 32],
            epoch: Some(3),
            timestamp: 1_700_000_000,
            signature: Vec::new(),
        };
        let canonical = scp_event_log::checkpoint::compute_checkpoint_canonical_hash(
            &checkpoint.context_id,
            &checkpoint.sender_did,
            checkpoint.event_count,
            &checkpoint.merkle_root,
            checkpoint.epoch,
            checkpoint.timestamp,
        );
        checkpoint.signature = signing_key.sign(&canonical).to_bytes().to_vec();
        checkpoint
    }

    /// A checkpoint an `#agent` key signed verifies. Resolving `#active`
    /// alone rejected it.
    #[tokio::test]
    async fn an_agent_signed_checkpoint_verifies() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let deps = deps_resolving_only(SigningKeyId::Agent, signing_key.verifying_key()).await;
        let checkpoint = signed_checkpoint(&signing_key);

        verify_remote_checkpoint_authenticity(true, &deps, CONTEXT_ID, &checkpoint)
            .expect("an #agent-signed checkpoint must verify");
    }

    /// A checkpoint an `#active` key signed still verifies, so the `#agent`
    /// arm did not displace the first method a verifier tries.
    #[tokio::test]
    async fn an_active_signed_checkpoint_verifies() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[12u8; 32]);
        let deps = deps_resolving_only(SigningKeyId::Active, signing_key.verifying_key()).await;
        let checkpoint = signed_checkpoint(&signing_key);

        verify_remote_checkpoint_authenticity(true, &deps, CONTEXT_ID, &checkpoint)
            .expect("an #active-signed checkpoint must verify");
    }

    /// A checkpoint signed by a key the sender's document does not publish is
    /// rejected, and the rejection names every method a verifier tried.
    #[tokio::test]
    async fn a_checkpoint_signed_by_an_unpublished_key_is_rejected() {
        let published = ed25519_dalek::SigningKey::from_bytes(&[13u8; 32]);
        let forged = ed25519_dalek::SigningKey::from_bytes(&[14u8; 32]);
        let deps = deps_resolving_only(SigningKeyId::Active, published.verifying_key()).await;
        let checkpoint = signed_checkpoint(&forged);

        let error = verify_remote_checkpoint_authenticity(true, &deps, CONTEXT_ID, &checkpoint)
            .expect_err("a checkpoint signed by an unpublished key must not verify");
        let message = error.to_string();
        assert!(
            message.contains("#active") && message.contains("#agent"),
            "a rejection must name every method tried, got: {message}"
        );
    }

    /// A sender the roster does not carry is rejected before any key resolves.
    #[tokio::test]
    async fn a_checkpoint_from_a_non_member_is_rejected() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[15u8; 32]);
        let deps = deps_resolving_only(SigningKeyId::Active, signing_key.verifying_key()).await;
        let checkpoint = signed_checkpoint(&signing_key);

        let error = verify_remote_checkpoint_authenticity(false, &deps, CONTEXT_ID, &checkpoint)
            .expect_err("a non-member's checkpoint must not verify");
        assert!(
            matches!(error, ContextError::MemberNotFound(_)),
            "expected a membership rejection, got: {error:?}"
        );
    }
}

#[cfg(test)]
mod equivocation_dedup_tests {
    //! Focused unit coverage for the `record_equivocation_if_fresh` dedup
    //! gate (§9.9.3 replay defense). The per-sender `(count, root)` set is the
    //! SOLE dedup mechanism: a divergence is buffer-only and is NOT appended to
    //! the durable Merkle log (a receiver-minted equivocation record is not
    //! sender-authenticated, so logging it would let honest receivers diverge
    //! their roots and false-positive the very detection it records). With no
    //! durable append there is no `local_count` advance, so the gate's
    //! keyed-on-`(count, root)` behavior is the only thing standing between a
    //! re-presented divergence and a duplicate alert. These tests assert it by
    //! constructing state directly and calling the helper at a stable count,
    //! never advancing through `compare_remote_checkpoint`.
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use scp_did::DID;

    use super::record_equivocation_if_fresh;
    use crate::context::actor::deps::ActorDeps;
    use crate::context::actor::state::PerContextState;
    use crate::context::supervisor::supervisor::Supervisor;

    /// Event-log provider that counts `append_event` calls so the test can
    /// assert the dedup gate appends NOTHING to the durable Merkle log —
    /// equivocation alerts are buffer-only (§9.9.3). All other methods are
    /// no-ops.
    ///
    /// `pub(super)` so `checkpoint_authenticity_tests` shares it. That module
    /// reads no count — it asserts on signature verification, which appends
    /// nothing — and a second no-op provider next to this one would be this
    /// type minus its counter.
    #[derive(Default)]
    pub(super) struct CountingEventLog {
        appends: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl crate::context::builder::ContextEventLogProvider for CountingEventLog {
        async fn init_event_log(
            &self,
            _id: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }

        async fn append_event(
            &self,
            _id: &[u8; 32],
            _event: scp_event_log::EventType,
            _actor: &str,
            _payload: scp_event_log::EventPayload,
            _timestamp_secs: u64,
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            self.appends.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn destroy_event_log(
            &self,
            _id: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }
    }

    /// Builds a supervisor-backed `ActorDeps` whose event log counts
    /// appends, plus a fresh encrypted `PerContextState`. Mirrors the
    /// `actor::mod` test-deps assembly but threads the counting log so the
    /// dedup gate's append behavior is observable.
    async fn deps_with_counting_log(appends: Arc<AtomicUsize>) -> (ActorDeps, PerContextState) {
        use scp_platform::in_memory::InMemoryStorage;

        let crypto = Arc::new(crate::crypto::mls::provider::NodeMlsFactory::new(
            "did:dht:z6MktestEquivDedup".to_owned(),
            std::sync::Arc::new(scp_clock::SystemClock),
        ));
        let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
            Box::new(crate::context::builder::NotConfiguredTransportProvider);
        let event_log: Box<dyn crate::context::builder::ContextEventLogProvider> =
            Box::new(CountingEventLog { appends });
        let key_resolver: scp_protocol::context::governance::KeyResolver =
            Arc::new(|_: &scp_did::DID, _: scp_did::SigningKeyId| None);
        let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> =
            Arc::new(
                crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
                    InMemoryStorage::new(),
                )),
            );

        let supervisor = Supervisor::with_providers(
            crypto,
            transport,
            event_log,
            key_resolver,
            None,
            None,
            None,
            None,
            mls_storage,
        );
        let deps = supervisor
            .build_actor_deps(&DID("did:example:equiv-dedup".to_owned()))
            .await
            .expect("build_actor_deps");

        let state = PerContextState::new_for_test_encrypted(
            [9u8; 32],
            1_700_000_000,
            DID("did:example:admin".to_owned()),
        );
        (deps, state)
    }

    /// Forge a divergent remote checkpoint at a fixed count with a chosen
    /// remote Merkle root. The signature is never re-verified inside
    /// `record_equivocation_if_fresh` (authenticity is gated upstream in
    /// `compare_remote_checkpoint`), so an empty signature is faithful.
    fn checkpoint(
        sender: &str,
        event_count: u64,
        remote_root: [u8; 32],
    ) -> scp_event_log::checkpoint::ConsistencyCheckpoint {
        scp_event_log::checkpoint::ConsistencyCheckpoint {
            context_id: "0909090909090909090909090909090909090909090909090909090909090909"
                .to_owned(),
            sender_did: DID(sender.to_owned()),
            event_count,
            merkle_root: remote_root,
            epoch: Some(1),
            timestamp: 1_700_000_100,
            signature: Vec::new(),
        }
    }

    /// (a) The same `(count, root)` recorded twice yields exactly ONE
    /// buffered alert — the exact-divergence replay is suppressed by the
    /// per-sender `(count, root)` dedup set (now the SOLE dedup, since the
    /// equivocation event is no longer appended to the durable Merkle log).
    #[tokio::test]
    async fn same_count_same_root_dedups_to_one() {
        let appends = Arc::new(AtomicUsize::new(0));
        let (deps, mut state) = deps_with_counting_log(Arc::clone(&appends)).await;
        let remote = checkpoint("did:example:bob", 5, [0xAB; 32]);
        let local_root = [0xCD; 32];

        record_equivocation_if_fresh(
            &mut state.last_seen_remote_checkpoint,
            &mut state.receive_buffer,
            &deps,
            "ctx",
            &remote,
            local_root,
        );
        // Identical re-presentation: same sender, same count, same root.
        record_equivocation_if_fresh(
            &mut state.last_seen_remote_checkpoint,
            &mut state.receive_buffer,
            &deps,
            "ctx",
            &remote,
            local_root,
        );

        assert_eq!(
            appends.load(Ordering::SeqCst),
            0,
            "equivocation is buffer-only — it must NOT append a Merkle leaf (§9.9.3)"
        );
        assert_eq!(
            state.receive_buffer.drain_equivocation_alerts().len(),
            1,
            "exact-divergence replay must emit exactly one buffered alert"
        );
    }

    /// (b) The same `count` with a DIFFERENT root yields TWO appends and
    /// TWO alerts — the regression guard for keying on the root, not on a
    /// monotone `(count, timestamp)`. A monotone-only gate would suppress
    /// the second distinct forgery at the same height and discard a §9.9.4
    /// security event.
    #[tokio::test]
    async fn same_count_different_root_records_both() {
        let appends = Arc::new(AtomicUsize::new(0));
        let (deps, mut state) = deps_with_counting_log(Arc::clone(&appends)).await;
        let local_root = [0xCD; 32];

        let first = checkpoint("did:example:bob", 5, [0x11; 32]);
        let second = checkpoint("did:example:bob", 5, [0x22; 32]);
        record_equivocation_if_fresh(
            &mut state.last_seen_remote_checkpoint,
            &mut state.receive_buffer,
            &deps,
            "ctx",
            &first,
            local_root,
        );
        record_equivocation_if_fresh(
            &mut state.last_seen_remote_checkpoint,
            &mut state.receive_buffer,
            &deps,
            "ctx",
            &second,
            local_root,
        );

        assert_eq!(
            appends.load(Ordering::SeqCst),
            0,
            "equivocation alerts are buffer-only — never appended to the Merkle log (§9.9.3)"
        );
        assert_eq!(
            state.receive_buffer.drain_equivocation_alerts().len(),
            2,
            "distinct forged roots at the same height each emit an alert"
        );
    }

    /// (c) The per-sender set is bounded at `MAX_SEQUENTIAL_COMMITS`: once
    /// the set is full the gate STILL EMITS the buffered alert (a security
    /// event is never silently discarded) but stops growing the set, proving
    /// the cap holds and emission is never starved.
    #[tokio::test]
    async fn per_sender_set_is_bounded_and_still_emits() {
        let appends = Arc::new(AtomicUsize::new(0));
        let (deps, mut state) = deps_with_counting_log(Arc::clone(&appends)).await;
        let local_root = [0xCD; 32];
        let cap = scp_protocol::sync::MAX_SEQUENTIAL_COMMITS;

        // Pin the set full with `cap` distinct roots (distinct counts keep
        // every entry distinct). The first divergence is the one we will
        // later replay; because the set is full by then, that first
        // `(count, root)` is NOT retained, so the replay re-appends.
        let first = checkpoint("did:example:mallory", 0, [0x00; 32]);
        record_equivocation_if_fresh(
            &mut state.last_seen_remote_checkpoint,
            &mut state.receive_buffer,
            &deps,
            "ctx",
            &first,
            local_root,
        );
        for i in 1..cap {
            let mut root = [0u8; 32];
            root[0] = (i & 0xFF) as u8;
            root[1] = ((i >> 8) & 0xFF) as u8;
            let cp = checkpoint("did:example:mallory", i, root);
            record_equivocation_if_fresh(
                &mut state.last_seen_remote_checkpoint,
                &mut state.receive_buffer,
                &deps,
                "ctx",
                &cp,
                local_root,
            );
        }

        let seen_len = state
            .last_seen_remote_checkpoint
            .get(&DID("did:example:mallory".to_owned()))
            .map_or(0, std::collections::HashSet::len) as u64;
        assert_eq!(
            seen_len, cap,
            "the per-sender set must be capped at MAX_SEQUENTIAL_COMMITS"
        );

        // Drain the alerts buffered while filling the set, so the post-cap
        // emission is measured in isolation.
        let _ = state.receive_buffer.drain_equivocation_alerts();

        // One more distinct divergence past the cap: alert still EMITTED but
        // the set does NOT grow. Equivocation is buffer-only, so observe the
        // buffered alert rather than a Merkle append.
        let over = checkpoint("did:example:mallory", cap + 1, [0xFF; 32]);
        record_equivocation_if_fresh(
            &mut state.last_seen_remote_checkpoint,
            &mut state.receive_buffer,
            &deps,
            "ctx",
            &over,
            local_root,
        );
        assert_eq!(
            state.receive_buffer.drain_equivocation_alerts().len(),
            1,
            "a divergence past the cap must STILL emit (never silently dropped, §9.9.4)"
        );
        assert_eq!(
            appends.load(Ordering::SeqCst),
            0,
            "equivocation is buffer-only — no Merkle append at any point (§9.9.3)"
        );
        let seen_len_after = state
            .last_seen_remote_checkpoint
            .get(&DID("did:example:mallory".to_owned()))
            .map_or(0, std::collections::HashSet::len) as u64;
        assert_eq!(
            seen_len_after, cap,
            "the set must stay capped — the over-cap divergence is emitted but not inserted"
        );
    }
}
