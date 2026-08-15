// Module-level allow — `significant_drop_tightening` only.
//
// `dead_code` is deliberately NOT allowed module-wide. The module is declared
// `pub(crate) mod queries_helpers` in `context/mod.rs` and is re-exported
// nowhere, so no out-of-crate caller can exist and rustc's reachability
// analysis is exactly right about this module. (A prior module-wide
// `dead_code` allow claimed otherwise — that FFI bridges and `feature =
// "testing"` crates called in from outside — and the false claim masked seven
// genuinely unreferenced helpers.) Items that are intentionally
// call-site-free carry a per-item `#[allow(dead_code)]` naming the wiring that
// will consume them; the lint stays live for the rest of the module.
#![allow(clippy::significant_drop_tightening)]

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
//! reads borrow `state` directly. Mutating reads (`report_degraded_mode`,
//! access-key management, checkpoint creation, Merkle-tree sync used by
//! `prove_event_*`) take `&mut state` without the legacy lock-drop /
//! re-acquire dance because the actor IS the per-context generation.
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
//! - [`report_degraded_mode`] — emits a `DegradedMode` event.
//! - [`generate_context_access_key`], [`revoke_context_access_key`],
//!   [`restore_context_access_key`] — access-key store mutations.
//! - `get_access_key`, `get_all_access_keys`, `remaining_budget_for_test`,
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

// ===========================================================================
// Test-only accessors
// ===========================================================================

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
///
/// # Errors
///
/// Returns [`ContextError::EventLogFailed`] when the authoritative log is
/// unreachable — see [`build_checkpoint`]. The checkpoint counters are left
/// UNTOUCHED on that path, so the next attempt is still due; nothing is signed
/// and nothing is retained.
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
) -> Result<scp_event_log::checkpoint::ConsistencyCheckpoint, ContextError> {
    let cp = build_checkpoint(
        context_id,
        broadcast_context_is_none,
        mls_epoch,
        sender_did,
        signing_key,
        now,
        event_log,
    )?;

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

    Ok(cp)
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
///
/// # Errors
///
/// Returns [`ContextError::EventLogFailed`] when the authoritative log is
/// unreachable — see [`build_checkpoint`]. The view's checkpoint fields are left
/// UNTOUCHED on that path: nothing is signed and nothing is retained.
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
) -> Result<scp_event_log::checkpoint::ConsistencyCheckpoint, ContextError> {
    let cp = build_checkpoint(
        context_id,
        broadcast_context_is_none,
        mls_epoch,
        sender_did,
        signing_key,
        now,
        event_log,
    )?;

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

    Ok(cp)
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
///
/// # Errors
///
/// Returns [`ContextError::EventLogFailed`] when a checkpoint was due but the
/// authoritative log is unreachable — see [`build_checkpoint`]. The view's
/// checkpoint fields are left UNTOUCHED on that path, so the checkpoint stays
/// due and is retried on the next send rather than being silently skipped with
/// the counters reset.
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
) -> Result<Option<scp_event_log::checkpoint::ConsistencyCheckpoint>, ContextError> {
    let events_since = *view.checkpoint_events_since_mut();
    let last_time = *view.checkpoint_last_time_secs_mut();
    let events_due = events_since >= 50;
    // Time-based checkpoints require at least one event — creating a checkpoint
    // for zero events is wasteful and indistinguishable from the previous one.
    let time_due = events_since > 0 && now.saturating_sub(last_time) >= 600;

    if !events_due && !time_due {
        return Ok(None);
    }

    let cp = build_checkpoint(
        context_id,
        broadcast_context_is_none,
        mls_epoch,
        sender_did,
        signing_key,
        now,
        event_log,
    )?;

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

    Ok(Some(cp))
}

/// Builds a signed checkpoint over the AUTHORITATIVE event log.
///
/// # Security
///
/// A checkpoint is signed, non-repudiable evidence: peers that see the same
/// `event_count` with a different `merkle_root` raise
/// [`ContextEvent::EquivocationDetected`] against its signer (§9.9.3). Two
/// properties are therefore established by construction here:
///
/// - **ONE snapshot.** `event_count` and `merkle_root` both come from a single
///   [`ContextEventLogProvider::rebuild_event_log_for_proof`] snapshot — the
///   same single proof seam `event_log_verify` uses. Reading the root and the
///   count through two separate provider calls let a concurrent `append_event`
///   fall between them, so a *signed* pair could describe a tree state that
///   never existed — a spurious equivocation alarm as a pure race.
/// - **FAILS CLOSED.** An unreachable log yields an error, never a checkpoint.
///   The previous `unwrap_or([0u8; 32])` / `map_or(0, …)` defaults signed a
///   FABRICATED commitment: `[0u8; 32]` is not the empty-tree root (§25.8
///   Vector 15 is `SHA-256("")`), and an erroring root paired with a readable
///   count produced an all-zero root beside a real event count. Both violate
///   the established "provider `None` means UNKNOWN, never empty" rule, on the
///   one path whose output carries a signature.
///
/// The §9.9.3 field derivation and canonical hash come from
/// [`scp_event_log::checkpoint::UnsignedCheckpoint`], shared with every other
/// checkpoint producer in the workspace, so there is no second implementation
/// of the signed structure to drift.
///
/// # Errors
///
/// Returns [`ContextError::EventLogFailed`] when the authoritative log is
/// unreachable for the context (never initialised, or destroyed on actor
/// shutdown / create-rollback) or its replayed events break the hash chain.
fn build_checkpoint(
    context_id: &str,
    broadcast_context_is_none: bool,
    mls_epoch: u64,
    sender_did: &DID,
    signing_key: &ed25519_dalek::SigningKey,
    now: u64,
    event_log: &dyn ContextEventLogProvider,
) -> Result<scp_event_log::checkpoint::ConsistencyCheckpoint, ContextError> {
    let context_id_bytes = state::context_id_to_bytes(context_id);
    let log = event_log.rebuild_event_log_for_proof(&context_id_bytes)?;

    // Encrypted contexts (no broadcast_context) use MLS epochs; broadcast
    // contexts do not use MLS and have no meaningful epoch.
    let epoch = if broadcast_context_is_none {
        Some(mls_epoch)
    } else {
        None
    };

    let unsigned = scp_event_log::checkpoint::UnsignedCheckpoint::over_log(
        &log, context_id, sender_did, epoch, now,
    );
    let signature = ed25519_dalek::Signer::sign(signing_key, unsigned.canonical_hash());
    Ok(unsigned.into_signed(signature.to_bytes().to_vec()))
}

/// Fail-closed authenticity gate for a remote checkpoint: the sender must be a
/// current member and the checkpoint's Ed25519 signature must verify against the
/// sender's `signing_key_id` verification method, resolved from their DID
/// document.
///
/// # The signing key is DECLARED, not guessed
///
/// Spec `.docs/specs/09-security-model.md` §9.9.3 specifies the checkpoint
/// signature as "signed by sender's `#active` or `#agent` key (ADR-039);
/// equivocation detection applies to both", so BOTH verification methods must be
/// judgeable — accepting only `#active` would let a peer that equivocates while
/// signing under `#agent` escape detection entirely.
///
/// The way to accept both is to resolve the one the sender DECLARED, not to try
/// each in turn. ADR-039 (`.docs/adrs/phase-1.md`, MLS Impact) is explicit:
/// "Verifiers resolve the correct public key from the DID document **based on
/// this field**." Trying `#active` then `#agent` and accepting whichever
/// verifies would decouple the persona stamp from the signing key — exactly the
/// divergence ADR-039's Enforcement-Stack layer 2 exists to prevent, where the
/// stamp and the key "are chosen together from one persona and cannot diverge".
/// Under try-both, an `#agent`-signed checkpoint would be accepted while
/// declaring the `#active` persona, laundering an agent action into a human
/// attribution.
///
/// `signing_key_id` is therefore threaded from the enclosing
/// [`InnerEnvelope`](scp_protocol::envelope::inner::InnerEnvelope) that carried
/// the checkpoint — the same field
/// [`verify_and_unwrap`](crate::context::messaging_helpers::verify_and_unwrap)
/// already uses for the envelope's own signature, so the checkpoint inside is
/// judged under the same declared persona that authenticated the envelope
/// around it. The [`ConsistencyCheckpoint`](scp_event_log::checkpoint::ConsistencyCheckpoint)
/// struct itself carries no key id (neither as a field nor in the
/// `SCP-CHECKPOINT-V1:` canonical-hash preimage) precisely because ADR-011
/// criterion 8 places the verification method on the signature apparatus, not
/// alongside the key.
///
/// # Key classes other than `#active` / `#agent`
///
/// Refused by construction, with no runtime re-check: [`scp_did::SigningKeyId`]
/// admits exactly `Active` and `Agent`, so no other key class is nameable here.
/// A checkpoint actually signed by some other key — a device key, a rotated-out
/// key, a relay's key — does not verify against the declared method's resolved
/// public key and is refused with [`ContextError::CryptoFailed`].
///
/// # Errors
///
/// - [`ContextError::MemberNotFound`] if the sender is not a member.
/// - [`ContextError::CryptoFailed`] if the declared verification method is absent
///   from the sender's DID document (e.g. `#agent` declared but never added), or
///   if the signature does not verify against the key it resolves to.
fn verify_remote_checkpoint_authenticity(
    sender_is_member: bool,
    deps: &ActorDeps,
    context_id: &str,
    remote: &scp_event_log::checkpoint::ConsistencyCheckpoint,
    signing_key_id: scp_did::SigningKeyId,
) -> Result<(), ContextError> {
    if !sender_is_member {
        return Err(ContextError::MemberNotFound(format!(
            "checkpoint sender {} is not a member of context {context_id}",
            remote.sender_did
        )));
    }

    // Resolve EXACTLY the declared verification method (ADR-039). `None` means
    // that method is absent from the sender's DID document — a refusal, never a
    // reason to fall back to the other method.
    let sender_pk = (deps.key_resolver)(&remote.sender_did, signing_key_id).ok_or_else(|| {
        ContextError::CryptoFailed(format!(
            "cannot resolve verification method {signing_key_id} for checkpoint \
             sender {}",
            remote.sender_did
        ))
    })?;
    scp_event_log::checkpoint::verify_checkpoint_signature(remote, &sender_pk).map_err(|reason| {
        ContextError::CryptoFailed(format!(
            "checkpoint signature verification failed under {signing_key_id}: {reason}"
        ))
    })
}

/// Verify-and-classify CORE of [`compare_remote_checkpoint`]: runs the
/// membership + signature gate and the Merkle-root/count comparison WITHOUT
/// touching per-context state. Returns the
/// [`CheckpointComparison`](scp_event_log::checkpoint::CheckpointComparison)
/// plus `Some(local_root)` when the result is `Divergent`.
///
/// Splitting the state-free judgement out of
/// [`compare_remote_checkpoint`] keeps the accusation-forming logic
/// independently testable: it can be driven with a plain `sender_is_member`
/// boolean and asserted on its verdict alone, with no `PerContextState` and no
/// Class-C borrow in scope. `compare_remote_checkpoint` is its only caller; it
/// reads membership from its [`ClassCMut`] view and, on a `Divergent` verdict,
/// delegates the two Class-C field writes (dedup set + receive-buffer emit) to
/// [`record_equivocation_if_fresh`].
///
/// `signing_key_id` is the verification method the sender DECLARED on the
/// enclosing envelope; see [`verify_remote_checkpoint_authenticity`] for why the
/// judge resolves that method rather than trying both.
///
/// # Security — the judging side of the commitment
///
/// [`build_checkpoint`] is the side that SIGNS a `(event_count, merkle_root)`
/// commitment; this is the side that JUDGES a peer's. Both need the same two
/// properties, for the same reason:
///
/// - **ONE snapshot.** `local_count` and `local_root` come from a single
///   [`ContextEventLogProvider::rebuild_event_log_for_proof`] call. Reading them
///   through two separate provider calls let a concurrent `append_event` fall
///   between them, so the local side of the comparison could describe a tree
///   state that never existed — and the verdict it drives is an accusation.
/// - **FAILS CLOSED.** An unreachable local log is an ERROR, never a
///   comparison. The previous `unwrap_or([0u8; 32])` / `.ok().flatten()`
///   defaults made a provider failure indistinguishable from a real empty log,
///   and the fabricated pair was WRONG IN BOTH DIRECTIONS:
///   - a remote checkpoint at `event_count == 0` compared equal-count against
///     the fabricated `[0u8; 32]` (which is not even the empty-tree root —
///     that is `SHA-256("")`, §25.8 Vector 15) and classified `Divergent`,
///     raising [`ContextEvent::EquivocationDetected`] against an HONEST peer on
///     the strength of a value invented by an error path; and
///   - a remote checkpoint at any non-zero count compared against
///     `local_count = 0` and was silently classified `Behind` — benign
///     catch-up lag — so a GENUINE divergence went undetected.
///
/// A local log we cannot read must not produce a verdict about a peer's honesty
/// in either direction. This also restores consistency with the gate one line
/// above: [`verify_remote_checkpoint_authenticity`] already fails closed.
///
/// # Errors
///
/// - [`ContextError::MemberNotFound`] if the checkpoint sender is not a member.
/// - [`ContextError::CryptoFailed`] if the DECLARED verification method
///   (`signing_key_id`) is absent from the sender's DID document, the Ed25519
///   signature does not verify against the key it resolves to, or the checkpoint
///   is bound to a DIFFERENT `context_id` than the one being judged (the
///   signature covers the checkpoint's own `context_id`, so authenticity alone
///   does not bind it to this context).
/// - [`ContextError::EventLogFailed`] if the LOCAL authoritative log is
///   unreachable (never initialised, or destroyed on actor shutdown /
///   create-rollback) or its replayed events break the hash chain — the
///   comparison is refused rather than answered from a fabricated local state.
fn classify_remote_checkpoint(
    sender_is_member: bool,
    deps: &ActorDeps,
    context_id: &str,
    remote: &scp_event_log::checkpoint::ConsistencyCheckpoint,
    signing_key_id: scp_did::SigningKeyId,
) -> Result<
    (
        scp_event_log::checkpoint::CheckpointComparison,
        Option<[u8; 32]>,
    ),
    ContextError,
> {
    // Membership + Ed25519 signature gate (fail-closed before any compare).
    verify_remote_checkpoint_authenticity(
        sender_is_member,
        deps,
        context_id,
        remote,
        signing_key_id,
    )?;

    // Context binding. The signature above covers the checkpoint's OWN
    // `context_id`, so a validly-signed checkpoint naming a DIFFERENT context
    // clears the authenticity gate — and would then be compared against THIS
    // context's root, manufacturing a `Divergent` verdict (an equivocation
    // accusation) out of two logs that were never meant to match. Callers
    // currently bind `sender_did` to the MLS-authenticated envelope sender, but
    // the gate whose verdict depends on this equality belongs HERE, in the
    // judging function, not in one caller. Defense in depth, fail-closed.
    if remote.context_id != context_id {
        return Err(ContextError::CryptoFailed(format!(
            "checkpoint from {} is bound to context {}, not {context_id}: \
             refusing to judge it against this context's event log",
            remote.sender_did, remote.context_id
        )));
    }

    let context_id_bytes = state::context_id_to_bytes(context_id);
    // ONE snapshot — both sides of the local commitment describe the same tree
    // state by construction, and an unreachable log refuses rather than
    // fabricating one. See the Security section above.
    let local = deps
        .event_log
        .rebuild_event_log_for_proof(&context_id_bytes)
        .map_err(|e| {
            // Logged here, at the point of refusal, so no caller can drop the
            // remote checkpoint silently: "we could not check" must never look
            // like "consistent".
            tracing::error!(
                context_id,
                sender_did = %remote.sender_did,
                remote_event_count = remote.event_count,
                error = %e,
                "refusing to classify a remote consistency checkpoint: the LOCAL \
                 authoritative event log is unreachable, so no honest verdict about \
                 this peer is available (§9.9.3)"
            );
            ContextError::EventLogFailed(format!(
                "cannot classify remote checkpoint from {} for context {context_id}: \
                 local authoritative event log unreachable: {e}",
                remote.sender_did
            ))
        })?;
    let local_root = scp_event_log::tree::root(&local);
    let local_count = scp_event_log::tree::event_count(&local);

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
/// `deps.event_tx` directly. Reads membership through the restricted
/// `MembershipClassCMut` sub-view, and on a divergent verdict mutates exactly
/// two Class-C fields — it records the divergent `(count, root)` in
/// `last_seen_remote_checkpoint` and pushes a
/// `ContextEvent::EquivocationDetected` into the receive buffer. Those two
/// writes are handed to [`record_equivocation_if_fresh`] as an
/// [`EquivocationDedupSplit`], so the write surface is named in that helper's
/// signature rather than being a whole `&mut ClassCMut` the reader has to audit
/// the body for; no whole `&mut PerContextState` is needed anywhere on this path.
///
/// # Signing key
///
/// `signing_key_id` is the verification method the sender DECLARED on the
/// enclosing [`InnerEnvelope`](scp_protocol::envelope::inner::InnerEnvelope)
/// that carried this checkpoint. Both §9.9.3 methods are judgeable — `#active`
/// and `#agent` alike — but each checkpoint is verified against the ONE method
/// its sender declared, never against whichever of the two happens to verify;
/// see [`verify_remote_checkpoint_authenticity`].
///
/// # Errors
///
/// - [`ContextError::MemberNotFound`] if the checkpoint sender is not a
///   member of the context.
/// - [`ContextError::CryptoFailed`] if the declared `signing_key_id`
///   verification method is absent from the sender's DID document, if the
///   Ed25519 signature does not verify against the key that method resolves to,
///   or if the checkpoint is bound to a different `context_id`.
/// - [`ContextError::EventLogFailed`] if the LOCAL authoritative event log is
///   unreachable — see [`classify_remote_checkpoint`]. NOTHING is mutated on
///   that path: the error is raised before the divergence dedup set or the
///   receive buffer are touched, so a refusal can never emit
///   `EquivocationDetected` nor record a divergence that was never established.
pub fn compare_remote_checkpoint(
    view: &mut ClassCMut,
    deps: &ActorDeps,
    context_id: &str,
    remote: &scp_event_log::checkpoint::ConsistencyCheckpoint,
    signing_key_id: scp_did::SigningKeyId,
) -> Result<scp_event_log::checkpoint::CheckpointComparison, ContextError> {
    // Membership read via the restricted `MembershipClassCMut` (this path never
    // mutates the roster); its borrow ends before the divergence recording below.
    let sender_is_member = view
        .membership_class_c_mut()
        .contains(remote.sender_did.as_ref());
    let (comparison, divergence_root) =
        classify_remote_checkpoint(sender_is_member, deps, context_id, remote, signing_key_id)?;

    // Record an EquivocationDetected event in the receive buffer when divergent
    // (NOT appended to the durable Merkle log — see `emit_equivocation_alert`),
    // deduped per distinct divergent checkpoint (replay defense). The dedup +
    // emit pair is `record_equivocation_if_fresh`, whose doc carries the §9.9.3
    // replay/bounding semantics — it is the ONE implementation of that pair, so
    // the documented semantics are the production path (and the unit tests that
    // pin them exercise production, not a parallel copy).
    if let Some(local_root) = divergence_root {
        record_equivocation_if_fresh(
            view.equivocation_dedup_split(),
            deps,
            context_id,
            remote,
            local_root,
        );
    }

    Ok(comparison)
}

/// The two disjoint Class-C `&mut` fields [`record_equivocation_if_fresh`]
/// mutates, threaded as ONE struct so the caller holds both at once (they are
/// distinct fields of [`PerContextState`], so the borrow checker accepts the
/// simultaneous `&mut`). Produced by
/// [`ClassCMut::equivocation_dedup_split`](crate::context::actor::class_s::ClassCMut::equivocation_dedup_split).
///
/// Replaces a whole `&mut ClassCMut` parameter. That view reaches the ENTIRE
/// Class-C surface — members, role state, lifecycle state, epoch, access,
/// handle, event log — where the dedup+emit pair touches exactly these two
/// fields. Narrowing the parameter to the fields actually written keeps the
/// ADR-049 §9 reviewer signal intact: a reader of this signature can see the
/// whole mutation surface without reading the body, and a future edit that
/// wanted to reach further would have to widen the type deliberately rather
/// than doing it silently.
///
/// Both fields are Class-C (best-effort / coalesced), so this split hands out no
/// Class-S reach: `last_seen_remote_checkpoint` is receiver-minted equivocation
/// evidence rather than a sender-authenticated replay witness, and
/// `receive_buffer` is local delivery scratch.
pub struct EquivocationDedupSplit<'a> {
    /// `&mut` to the per-sender `(event_count, remote_merkle_root)` divergence
    /// dedup set (Class-C / §9.9.3).
    pub last_seen_remote_checkpoint:
        &'a mut std::collections::HashMap<DID, std::collections::HashSet<(u64, [u8; 32])>>,
    /// `&mut` to the local receive buffer the `EquivocationDetected` alert is
    /// minted into (Class-C / structural).
    pub receive_buffer: &'a mut ReceiveBuffer,
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
///
/// Called by [`compare_remote_checkpoint`] — the sole production judge — on
/// every divergent verdict, so the semantics documented above ARE the shipped
/// behavior and the unit tests below pin production, not a parallel copy.
fn record_equivocation_if_fresh(
    dedup: EquivocationDedupSplit<'_>,
    deps: &ActorDeps,
    context_id: &str,
    remote: &scp_event_log::checkpoint::ConsistencyCheckpoint,
    local_root: [u8; 32],
) {
    // The mutation surface is the two fields named in the parameter type and
    // nothing else — no whole `&mut PerContextState` and no whole `&mut
    // ClassCMut` is in scope here. Destructured up front (the
    // `CommitBroadcastBorrows` idiom) so the body names each borrow directly.
    // The ordering between them is load-bearing, not incidental: the alert is
    // emitted only after the divergence has been judged fresh.
    let EquivocationDedupSplit {
        last_seen_remote_checkpoint,
        receive_buffer,
    } = dedup;
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
//
// The four helpers below have no call site yet, so each carries its OWN
// `#[allow(dead_code)]` rather than a module-wide one — the lint stays live for
// the other ~60 items in this file. They are the building blocks the §23.7
// step-3 consistency-proof catch-up will call: the `Behind` arm of
// `classify_remote_checkpoint` (above) is the point where a member learns it
// is missing events, and confirming a fetched suffix genuinely EXTENDS its own
// history (rather than the relay having rewritten held events) requires
// proving/verifying an RFC 6962 §2.1.2 consistency proof from the last-known
// root. The event-range fetch and proof exchange that drive them are specified
// separately; these four are the local half and are complete as written.

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
#[allow(
    dead_code,
    reason = "§23.7 step-3 consistency-proof catch-up seam — see the section note above"
)]
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
#[allow(
    dead_code,
    reason = "§23.7 step-3 consistency-proof catch-up seam — see the section note above"
)]
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
#[allow(
    dead_code,
    reason = "§23.7 step-3 consistency-proof catch-up seam — see the section note above"
)]
pub fn verify_event_inclusion(proof: &scp_event_log::proof::InclusionProof) -> bool {
    scp_event_log::proof::verify_inclusion(proof)
}

/// Verifies a Merkle consistency proof. Pure function — no state needed.
#[must_use]
#[allow(
    dead_code,
    reason = "§23.7 step-3 consistency-proof catch-up seam — see the section note above"
)]
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
mod equivocation_dedup_tests {
    //! Focused unit coverage for the `record_equivocation_if_fresh` dedup
    //! gate (§9.9.3 replay defense). The per-sender `(count, root)` set is the
    //! SOLE dedup mechanism: a divergence is buffer-only and is NOT appended to
    //! the durable Merkle log (a receiver-minted equivocation record is not
    //! sender-authenticated, so logging it would let honest receivers diverge
    //! their roots and false-positive the very detection it records). With no
    //! durable append there is no `local_count` advance, so the gate's
    //! keyed-on-`(count, root)` behavior is the only thing standing between a
    //! re-presented divergence and a duplicate alert.
    //!
    //! `record_equivocation_if_fresh` is the PRODUCTION dedup+emit pair —
    //! `compare_remote_checkpoint` calls it on every divergent verdict — so these
    //! tests pin shipped behavior, not a parallel copy. They drive it through the
    //! same [`ClassCMut`] view the judge hands it, but construct the state
    //! directly and hold the count stable rather than advancing through
    //! `compare_remote_checkpoint`: the judge's authenticity gates (membership,
    //! signature, `context_id`) and its local-log snapshot are orthogonal to the
    //! dedup semantics under test and are covered by
    //! `remote_checkpoint_classification_tests`.
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use scp_did::DID;

    use super::{ClassCMut, record_equivocation_if_fresh};
    use crate::context::actor::deps::ActorDeps;
    use crate::context::actor::state::PerContextState;
    use crate::context::supervisor::supervisor::Supervisor;

    /// Event-log provider that counts `append_event` calls so the test can
    /// assert the dedup gate appends NOTHING to the durable Merkle log —
    /// equivocation alerts are buffer-only (§9.9.3). All other methods are
    /// no-ops.
    #[derive(Default)]
    struct CountingEventLog {
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

    /// Drives the production dedup gate over a bare `PerContextState` through
    /// the SAME [`EquivocationDedupSplit`] `compare_remote_checkpoint` hands it,
    /// taken from the same [`ClassCMut`] view. The view's borrow of `state` ends
    /// with this call, so each test can read the state fields back directly
    /// between invocations.
    fn record(
        state: &mut PerContextState,
        deps: &ActorDeps,
        remote: &scp_event_log::checkpoint::ConsistencyCheckpoint,
        local_root: [u8; 32],
    ) {
        let mut view = ClassCMut::from_state(state);
        record_equivocation_if_fresh(
            view.equivocation_dedup_split(),
            deps,
            "ctx",
            remote,
            local_root,
        );
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

        record(&mut state, &deps, &remote, local_root);
        // Identical re-presentation: same sender, same count, same root.
        record(&mut state, &deps, &remote, local_root);

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
        record(&mut state, &deps, &first, local_root);
        record(&mut state, &deps, &second, local_root);

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

        // Pin the set full with exactly `cap` distinct divergences: the
        // `count = 0` entry below plus `cap - 1` from the loop. Every count is
        // distinct, so no entry is dedup-suppressed and each one is inserted
        // while the set is still under the cap — leaving `seen.len() == cap`
        // for the over-cap probe further down. Nothing here is replayed; the
        // probe uses a divergence the set has never held.
        let first = checkpoint("did:example:mallory", 0, [0x00; 32]);
        record(&mut state, &deps, &first, local_root);
        for i in 1..cap {
            let mut root = [0u8; 32];
            root[0] = (i & 0xFF) as u8;
            root[1] = ((i >> 8) & 0xFF) as u8;
            let cp = checkpoint("did:example:mallory", i, root);
            record(&mut state, &deps, &cp, local_root);
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
        record(&mut state, &deps, &over, local_root);
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

#[cfg(test)]
mod checkpoint_authoritative_source_tests {
    //! A [`ConsistencyCheckpoint`](scp_event_log::checkpoint::ConsistencyCheckpoint)
    //! is signed, non-repudiable evidence: peers that see the same
    //! `event_count` with a different `merkle_root` raise
    //! `EquivocationDetected` against its signer (§9.9.3). These tests pin the
    //! two properties [`build_checkpoint`] must establish by construction —
    //! both were violated by the previous implementation:
    //!
    //! 1. The `(event_count, merkle_root)` pair comes from ONE authoritative
    //!    snapshot. It used to be read through two independent provider calls
    //!    (`event_log_merkle_root` and `event_log_entries`), so the two halves
    //!    of a SIGNED commitment could describe different tree states.
    //! 2. An unreachable log yields an error, never a checkpoint. It used to
    //!    fall back to `unwrap_or([0u8; 32])` / `map_or(0, …)` — a fabricated
    //!    commitment (`[0u8; 32]` is not the empty-tree root, which is
    //!    `SHA-256("")` per §25.8 Vector 15) carrying a real signature.
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use scp_did::DID;
    use scp_protocol::context::ContextError;

    use super::{build_checkpoint, force_create_checkpoint_fields};
    use crate::context::builder::ContextEventLogProvider;
    use crate::context::providers::event_log::MerkleEventLogProvider;

    /// A 64-hex context id, so `context_id_to_bytes` is the identity decode and
    /// the provider key is exactly these bytes.
    const CTX_HEX: &str = "aa00000000000000000000000000000000000000000000000000000000000011";

    fn ctx_bytes() -> [u8; 32] {
        crate::context::state::context_id_to_bytes(CTX_HEX)
    }

    fn signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
    }

    /// Seeds an honest provider with `n` chained lifecycle events.
    async fn honest_provider(n: u64) -> MerkleEventLogProvider {
        let provider = MerkleEventLogProvider::new();
        let id = ctx_bytes();
        provider.init_event_log(&id).await.unwrap();
        for i in 0..n {
            let event_type = if i == 0 {
                scp_event_log::EventType::ContextCreated
            } else {
                scp_event_log::EventType::MemberJoined
            };
            provider
                .append_event(
                    &id,
                    event_type,
                    "did:example:actor",
                    scp_event_log::EventPayload::default(),
                    1_700_000_000 + i,
                )
                .await
                .unwrap();
        }
        provider
    }

    /// Wraps an honest provider but answers the standalone `event_log_merkle_root`
    /// accessor with `root_answer`. Models the real hazard the two-call read
    /// had: the root accessor and the entries accessor are separate reads that
    /// can disagree — under a concurrent `append_event` benignly, under a
    /// hostile or buggy provider arbitrarily.
    struct DisagreeingRootProvider {
        inner: MerkleEventLogProvider,
        root_answer: Result<[u8; 32], ContextError>,
    }

    #[async_trait::async_trait]
    impl ContextEventLogProvider for DisagreeingRootProvider {
        async fn init_event_log(
            &self,
            id: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            self.inner.init_event_log(id).await
        }

        async fn append_event(
            &self,
            id: &[u8; 32],
            event: scp_event_log::EventType,
            actor: &str,
            payload: scp_event_log::EventPayload,
            timestamp_secs: u64,
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            self.inner
                .append_event(id, event, actor, payload, timestamp_secs)
                .await
        }

        async fn destroy_event_log(
            &self,
            id: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            self.inner.destroy_event_log(id).await
        }

        fn event_log_entries(
            &self,
            id: &[u8; 32],
        ) -> Result<Option<Vec<scp_event_log::Event>>, ContextError> {
            self.inner.event_log_entries(id)
        }

        fn event_log_merkle_root(&self, _id: &[u8; 32]) -> Result<[u8; 32], ContextError> {
            match &self.root_answer {
                Ok(root) => Ok(*root),
                Err(e) => Err(ContextError::EventLogFailed(e.to_string())),
            }
        }
    }

    /// A provider that reports NO LOG for the context — `Ok(None)` means
    /// UNKNOWN (never initialised, or destroyed on actor shutdown /
    /// create-rollback), never "empty".
    struct UnknownLogProvider;

    #[async_trait::async_trait]
    impl ContextEventLogProvider for UnknownLogProvider {
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
            Ok(())
        }

        async fn destroy_event_log(
            &self,
            _id: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }

        fn event_log_entries(
            &self,
            _id: &[u8; 32],
        ) -> Result<Option<Vec<scp_event_log::Event>>, ContextError> {
            Ok(None)
        }

        /// The old code path's other half: a root accessor that cheerfully
        /// answers even though the log is unknown. Together with the entries
        /// `None` this is exactly the `(0, [0u8; 32])` fabrication.
        fn event_log_merkle_root(&self, _id: &[u8; 32]) -> Result<[u8; 32], ContextError> {
            Ok([0u8; 32])
        }
    }

    /// The signed commitment must come from the ONE authoritative snapshot, not
    /// from the standalone root accessor. Fails against the pre-fix code, which
    /// signed the accessor's answer (here `[0xAA; 32]`) beside a count read from
    /// a *different* call.
    #[tokio::test]
    async fn signed_commitment_comes_from_one_snapshot_not_the_root_accessor() {
        let honest = honest_provider(3).await;
        let truthful_root = honest.event_log_merkle_root(&ctx_bytes()).unwrap();
        let provider = DisagreeingRootProvider {
            inner: honest,
            root_answer: Ok([0xAAu8; 32]),
        };

        let cp = build_checkpoint(
            CTX_HEX,
            true,
            9,
            &DID("did:example:signer".to_owned()),
            &signing_key(),
            1_700_000_100,
            &provider,
        )
        .expect("a readable authoritative log builds a checkpoint");

        assert_eq!(
            cp.merkle_root, truthful_root,
            "the signed root must be the replayed snapshot's root, never the \
             standalone accessor's answer"
        );
        assert_ne!(
            cp.merkle_root, [0xAAu8; 32],
            "the disagreeing accessor answer must not reach a signed field"
        );
        assert_eq!(cp.event_count, 3);
        assert_eq!(cp.epoch, Some(9));
        scp_event_log::checkpoint::verify_checkpoint_signature(&cp, &signing_key().verifying_key())
            .expect("the checkpoint signature must verify over its own fields");
    }

    /// The specific pre-fix defect: a readable entries list beside an ERRORING
    /// root accessor signed an all-zero root next to a real event count.
    #[tokio::test]
    async fn an_erroring_root_accessor_never_yields_a_signed_all_zero_root() {
        let honest = honest_provider(4).await;
        let truthful_root = honest.event_log_merkle_root(&ctx_bytes()).unwrap();
        let provider = DisagreeingRootProvider {
            inner: honest,
            root_answer: Err(ContextError::EventLogFailed("accessor down".into())),
        };

        let cp = build_checkpoint(
            CTX_HEX,
            true,
            1,
            &DID("did:example:signer".to_owned()),
            &signing_key(),
            1_700_000_200,
            &provider,
        )
        .expect("the snapshot is readable even when the root accessor is not");

        assert_eq!(cp.event_count, 4);
        assert_eq!(cp.merkle_root, truthful_root);
        assert_ne!(
            cp.merkle_root, [0u8; 32],
            "an all-zero root is a FABRICATED sentinel, not the empty-tree root"
        );
    }

    /// An UNKNOWN authoritative log must produce no checkpoint at all. Fails
    /// against the pre-fix code, which returned a signed `(0, [0u8; 32])`.
    #[tokio::test]
    async fn a_checkpoint_over_an_unknown_log_is_never_signed() {
        let err = build_checkpoint(
            CTX_HEX,
            true,
            0,
            &DID("did:example:signer".to_owned()),
            &signing_key(),
            1_700_000_300,
            &UnknownLogProvider,
        )
        .expect_err("an unknown authoritative log must not be signed over");
        assert!(
            matches!(err, ContextError::EventLogFailed(_)),
            "expected EventLogFailed, got: {err}"
        );
    }

    /// An EMPTY-but-live log is a distinct, honest state: it snapshots to a real
    /// zero-leaf tree whose root is `SHA-256("")`, NOT the `[0u8; 32]` sentinel
    /// the old fallback fabricated.
    #[tokio::test]
    async fn an_empty_but_live_log_signs_the_real_zero_leaf_root() {
        let provider = honest_provider(0).await;

        let cp = build_checkpoint(
            CTX_HEX,
            true,
            0,
            &DID("did:example:signer".to_owned()),
            &signing_key(),
            1_700_000_400,
            &provider,
        )
        .expect("an empty-but-live log is readable");

        assert_eq!(cp.event_count, 0);
        assert_ne!(
            cp.merkle_root, [0u8; 32],
            "the empty-tree root is SHA-256(\"\") (§25.8 Vector 15), not all zeros"
        );
        assert_eq!(
            cp.merkle_root,
            provider.event_log_merkle_root(&ctx_bytes()).unwrap()
        );
    }

    /// On the fail-closed path the checkpoint counters are left UNTOUCHED, so
    /// the checkpoint stays due and is retried rather than silently skipped.
    #[tokio::test]
    async fn a_refused_checkpoint_leaves_the_counters_due() {
        let mut events_since = 73u64;
        let mut last_time = 1_600_000_000u64;
        let mut checkpoints = Vec::new();

        let err = force_create_checkpoint_fields(
            CTX_HEX,
            true,
            0,
            &mut events_since,
            &mut last_time,
            &mut checkpoints,
            &DID("did:example:signer".to_owned()),
            &signing_key(),
            1_700_000_500,
            &UnknownLogProvider,
        )
        .expect_err("an unknown authoritative log must not be signed over");
        assert!(matches!(err, ContextError::EventLogFailed(_)));

        assert_eq!(events_since, 73, "counters must not be reset on refusal");
        assert_eq!(last_time, 1_600_000_000);
        assert!(
            checkpoints.is_empty(),
            "nothing may be retained when nothing was signed"
        );
    }
}

#[cfg(test)]
mod remote_checkpoint_classification_tests {
    //! The JUDGING side of the §9.9.3 commitment.
    //!
    //! [`classify_remote_checkpoint`] compares a peer's signed
    //! `(event_count, merkle_root)` against the LOCAL log, and a `Divergent`
    //! verdict raises [`ContextEvent::EquivocationDetected`] — an accusation of
    //! dishonesty against that peer. It therefore needs exactly the properties
    //! [`build_checkpoint`] needs on the signing side, and for a sharper reason:
    //! the producer side fabricating a commitment misleads its peers, while the
    //! judging side fabricating one FRAMES them.
    //!
    //! Previously the local side was read through two independent, individually
    //! fail-open provider calls (`event_log_merkle_root(...).unwrap_or([0u8;
    //! 32])` and `event_log_entries(...).ok().flatten().map_or(0, ...)`). An
    //! unreachable provider therefore produced `(0, [0u8; 32])` — a count and a
    //! root that describe no tree, `[0u8; 32]` not even being the empty-tree
    //! root — and the resulting verdict was wrong in BOTH directions: a remote
    //! checkpoint at count 0 was accused of equivocating, and a remote
    //! checkpoint at any other count was quietly filed as a benign catch-up
    //! state (`Behind`, since the fabricated `local_count = 0` is below every
    //! real count), missing a real divergence.
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use std::sync::Arc;

    use scp_did::DID;
    use scp_protocol::context::ContextError;

    use super::{classify_remote_checkpoint, compare_remote_checkpoint};
    use crate::context::actor::deps::ActorDeps;
    use crate::context::actor::state::PerContextState;
    use crate::context::builder::ContextEventLogProvider;
    use crate::context::providers::event_log::MerkleEventLogProvider;
    use crate::context::supervisor::supervisor::Supervisor;

    /// A 64-hex context id, so `context_id_to_bytes` is the identity decode.
    const CTX_HEX: &str = "0909090909090909090909090909090909090909090909090909090909090909";

    const SENDER: &str = "did:example:bob";

    /// The `#active` verification method, as DECLARED by the enclosing envelope
    /// (ADR-039). Judging is always relative to a declared method; there is no
    /// "unspecified" case for the judge to guess at.
    const ACTIVE: scp_did::SigningKeyId = scp_did::SigningKeyId::Active;

    /// The `#agent` verification method. Spec §9.9.3 makes equivocation
    /// detection apply under this method exactly as under `#active`.
    const AGENT: scp_did::SigningKeyId = scp_did::SigningKeyId::Agent;

    fn ctx_bytes() -> [u8; 32] {
        crate::context::state::context_id_to_bytes(CTX_HEX)
    }

    /// A provider that reports NO LOG for the context — `Ok(None)` means
    /// UNKNOWN (never initialised, or destroyed on actor shutdown /
    /// create-rollback), never "empty". Its standalone `event_log_merkle_root`
    /// cheerfully answers `[0u8; 32]`, which is precisely the pair the old
    /// fail-open read fabricated.
    struct UnreachableLogProvider;

    #[async_trait::async_trait]
    impl ContextEventLogProvider for UnreachableLogProvider {
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
            Ok(())
        }

        async fn destroy_event_log(
            &self,
            _id: &[u8; 32],
        ) -> Result<(), scp_protocol::context::builder::ContextCreationError> {
            Ok(())
        }

        fn event_log_entries(
            &self,
            _id: &[u8; 32],
        ) -> Result<Option<Vec<scp_event_log::Event>>, ContextError> {
            Ok(None)
        }

        fn event_log_merkle_root(&self, _id: &[u8; 32]) -> Result<[u8; 32], ContextError> {
            Ok([0u8; 32])
        }
    }

    /// Seeds a readable provider with `n` chained lifecycle events, stamping
    /// leaf timestamps from `timestamp_base`.
    ///
    /// The base is a parameter so a test can build a SECOND, genuinely
    /// different log at the SAME event count: differing leaf timestamps change
    /// the leaf preimages and therefore the Merkle root, which is the shape of
    /// two members served divergent histories (§9.9.3).
    async fn readable_provider_from(n: u64, timestamp_base: u64) -> MerkleEventLogProvider {
        let provider = MerkleEventLogProvider::new();
        let id = ctx_bytes();
        provider.init_event_log(&id).await.unwrap();
        for i in 0..n {
            let event_type = if i == 0 {
                scp_event_log::EventType::ContextCreated
            } else {
                scp_event_log::EventType::MemberJoined
            };
            provider
                .append_event(
                    &id,
                    event_type,
                    "did:example:actor",
                    scp_event_log::EventPayload::default(),
                    timestamp_base + i,
                )
                .await
                .unwrap();
        }
        provider
    }

    /// Seeds a readable provider with `n` chained lifecycle events.
    async fn readable_provider(n: u64) -> MerkleEventLogProvider {
        readable_provider_from(n, 1_700_000_000).await
    }

    /// The Merkle root a log of `n` events under [`CTX_HEX`] settles on — used
    /// to give a remote checkpoint a REAL root from a REAL log of that size,
    /// rather than an invented byte pattern.
    async fn root_of_log_with(n: u64) -> [u8; 32] {
        readable_provider(n)
            .await
            .event_log_merkle_root(&ctx_bytes())
            .unwrap()
    }

    /// Builds `ActorDeps` over `event_log`, with a key resolver that answers for
    /// [`SENDER`] ONLY and, for that DID, resolves each verification method to
    /// the key given for it: `active` for `#active`, `agent` for `#agent`.
    ///
    /// `None` models a DID document that carries no such verification method —
    /// the ordinary shape for `#agent` on a human-only member. Modelling the two
    /// methods as SEPARATE keys is what makes the ADR-039 declared-method
    /// behaviour observable: a resolver that answered the same key for both would
    /// make a persona mix-up indistinguishable from a correct resolution.
    async fn deps_over_methods(
        event_log: Box<dyn ContextEventLogProvider>,
        active: Option<ed25519_dalek::VerifyingKey>,
        agent: Option<ed25519_dalek::VerifyingKey>,
    ) -> ActorDeps {
        use scp_platform::in_memory::InMemoryStorage;

        let crypto = Arc::new(crate::crypto::mls::provider::NodeMlsFactory::new(
            "did:dht:z6MktestRemoteCheckpoint".to_owned(),
            Arc::new(scp_clock::SystemClock),
        ));
        let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
            Box::new(crate::context::builder::NotConfiguredTransportProvider);
        let key_resolver: scp_protocol::context::governance::KeyResolver =
            Arc::new(move |did: &DID, key_id: scp_did::SigningKeyId| {
                if did.as_ref() != SENDER {
                    return None;
                }
                match key_id {
                    scp_did::SigningKeyId::Active => active,
                    scp_did::SigningKeyId::Agent => agent,
                }
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
            .build_actor_deps(&DID("did:example:local".to_owned()))
            .await
            .expect("build_actor_deps")
    }

    /// [`deps_over_methods`] for the ordinary human-only member: `verifying_key`
    /// is [`SENDER`]'s `#active` key and their DID document carries no `#agent`
    /// key. Every checkpoint judged against these deps must therefore declare
    /// [`scp_did::SigningKeyId::Active`].
    async fn deps_over(
        event_log: Box<dyn ContextEventLogProvider>,
        verifying_key: ed25519_dalek::VerifyingKey,
    ) -> ActorDeps {
        deps_over_methods(event_log, Some(verifying_key), None).await
    }

    /// A GENUINELY SIGNED remote checkpoint bound to `context_id` — the
    /// authenticity gate must pass so the test exercises the code under test,
    /// not the signature check.
    fn signed_remote_for(
        signing_key: &ed25519_dalek::SigningKey,
        context_id: &str,
        event_count: u64,
        merkle_root: [u8; 32],
    ) -> scp_event_log::checkpoint::ConsistencyCheckpoint {
        let unsigned = scp_event_log::checkpoint::UnsignedCheckpoint::over_commitment(
            context_id,
            &DID(SENDER.to_owned()),
            event_count,
            merkle_root,
            Some(1),
            1_700_000_100,
        );
        let signature = ed25519_dalek::Signer::sign(signing_key, unsigned.canonical_hash());
        unsigned.into_signed(signature.to_bytes().to_vec())
    }

    /// A GENUINELY SIGNED remote checkpoint bound to [`CTX_HEX`], the context
    /// under judgement.
    fn signed_remote(
        signing_key: &ed25519_dalek::SigningKey,
        event_count: u64,
        merkle_root: [u8; 32],
    ) -> scp_event_log::checkpoint::ConsistencyCheckpoint {
        signed_remote_for(signing_key, CTX_HEX, event_count, merkle_root)
    }

    fn state_without_sender_as_member() -> PerContextState {
        PerContextState::new_for_test_encrypted(
            ctx_bytes(),
            1_700_000_000,
            DID("did:example:local".to_owned()),
        )
    }

    fn state_with_sender_as_member() -> PerContextState {
        let mut state = state_without_sender_as_member();
        state
            .membership
            .add_member(DID(SENDER.to_owned()), "member".to_owned(), Vec::new());
        state
    }

    /// An UNREACHABLE local log must REFUSE to classify, in both directions.
    ///
    /// Fails against the pre-fix code: `event_count: 0` was answered
    /// `Divergent` (an equivocation accusation built from `[0u8; 32]`), and
    /// `event_count: 7` was answered `Behind { missing_events: 7 }` — a real
    /// divergence filed as benign catch-up lag.
    #[tokio::test]
    async fn an_unreachable_local_log_refuses_to_judge_a_peer() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
        let deps = deps_over(
            Box::new(UnreachableLogProvider),
            signing_key.verifying_key(),
        )
        .await;

        for (event_count, label) in [
            (
                0u64,
                "zero count — the pre-fix FALSE-POSITIVE arm (Divergent)",
            ),
            (
                7u64,
                "non-zero count — the pre-fix FALSE-NEGATIVE arm (Behind)",
            ),
        ] {
            let remote = signed_remote(&signing_key, event_count, [0xAB; 32]);
            let err = classify_remote_checkpoint(true, &deps, CTX_HEX, &remote, ACTIVE)
                .expect_err(&format!("{label}: an unreachable local log must not judge"));
            assert!(
                matches!(err, ContextError::EventLogFailed(_)),
                "{label}: expected EventLogFailed, got: {err}"
            );
        }
    }

    /// The refusal must not emit `EquivocationDetected` nor record a divergence
    /// — a verdict that was never reached must leave no trace.
    #[tokio::test]
    async fn a_refusal_emits_no_equivocation_alert() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[6u8; 32]);
        let deps = deps_over(
            Box::new(UnreachableLogProvider),
            signing_key.verifying_key(),
        )
        .await;
        let mut cell =
            crate::context::actor::class_s::ClassSCell::new(state_with_sender_as_member());

        // Count 0 is the arm that USED to be answered `Divergent` and therefore
        // emitted an alert against this (honest) peer.
        let remote = signed_remote(&signing_key, 0, [0xAB; 32]);
        let err =
            compare_remote_checkpoint(&mut cell.class_c_view(), &deps, CTX_HEX, &remote, ACTIVE)
                .expect_err("an unreachable local log must not judge");
        assert!(matches!(err, ContextError::EventLogFailed(_)));

        let mut view = cell.class_c_view();
        assert!(
            view.receive_buffer_mut()
                .drain_equivocation_alerts()
                .is_empty(),
            "a refusal to judge must emit NO EquivocationDetected — the peer was \
             never shown to be dishonest"
        );
        assert!(
            view.last_seen_remote_checkpoint_mut().is_empty(),
            "a refusal must record no divergence in the dedup set"
        );
    }

    /// Positive control: over a READABLE log the same shape still detects a
    /// genuine divergence and emits the alert. Without this, the test above
    /// could pass for the wrong reason (e.g. a membership or signature gate
    /// rejecting first).
    #[tokio::test]
    async fn a_readable_log_still_detects_a_genuine_divergence() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let provider = readable_provider(3).await;
        let local_root = provider.event_log_merkle_root(&ctx_bytes()).unwrap();
        let deps = deps_over(Box::new(provider), signing_key.verifying_key()).await;
        let mut cell =
            crate::context::actor::class_s::ClassSCell::new(state_with_sender_as_member());

        // Equal count, DIFFERENT root — the §9.9.3 cryptographic equivocation
        // test.
        let remote = signed_remote(&signing_key, 3, [0xAB; 32]);
        assert_ne!(local_root, [0xAB; 32]);
        let comparison =
            compare_remote_checkpoint(&mut cell.class_c_view(), &deps, CTX_HEX, &remote, ACTIVE)
                .expect("a readable local log yields a verdict");
        assert!(
            matches!(
                comparison,
                scp_event_log::checkpoint::CheckpointComparison::Divergent { .. }
            ),
            "equal count + different root is Divergent (§9.9.3), got: {comparison:?}"
        );
        assert_eq!(
            cell.class_c_view()
                .receive_buffer_mut()
                .drain_equivocation_alerts()
                .len(),
            1,
            "a genuine divergence over a readable log must still alert"
        );
    }

    /// Positive control: over a READABLE log an agreeing peer is `Consistent`,
    /// and the local side of that comparison is the REPLAYED snapshot's root —
    /// so an empty-but-live log compares against `SHA-256("")`, never the
    /// `[0u8; 32]` sentinel the old fallback fabricated.
    #[tokio::test]
    async fn an_empty_but_live_log_compares_against_the_real_zero_leaf_root() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
        let provider = readable_provider(0).await;
        let empty_root = provider.event_log_merkle_root(&ctx_bytes()).unwrap();
        assert_ne!(
            empty_root, [0u8; 32],
            "the empty-tree root is SHA-256(\"\") (§25.8 Vector 15), not all zeros"
        );
        let deps = deps_over(Box::new(provider), signing_key.verifying_key()).await;

        let agreeing = signed_remote(&signing_key, 0, empty_root);
        let (comparison, divergence_root) =
            classify_remote_checkpoint(true, &deps, CTX_HEX, &agreeing, ACTIVE)
                .expect("an empty-but-live log yields a verdict");
        assert!(matches!(
            comparison,
            scp_event_log::checkpoint::CheckpointComparison::Consistent
        ));
        assert!(divergence_root.is_none());

        // And a peer claiming the fabricated all-zero root at the same count is
        // correctly Divergent — the sentinel is not a valid empty-log root.
        let sentinel = signed_remote(&signing_key, 0, [0u8; 32]);
        let (comparison, _) = classify_remote_checkpoint(true, &deps, CTX_HEX, &sentinel, ACTIVE)
            .expect("an empty-but-live log yields a verdict");
        assert!(matches!(
            comparison,
            scp_event_log::checkpoint::CheckpointComparison::Divergent { .. }
        ));
    }

    /// A checkpoint bound to a DIFFERENT context must be REFUSED, not judged.
    ///
    /// The Ed25519 signature covers the checkpoint's OWN `context_id`, so a
    /// validly-signed foreign checkpoint clears the authenticity gate. Without
    /// the binding check it would then be compared against THIS context's root
    /// — two unrelated logs — and the mismatch arm would raise
    /// `EquivocationDetected`: an accusation of dishonesty manufactured out of
    /// a category error. Both arms below are asserted, because "refused" must
    /// hold whether the foreign root happens to agree or disagree.
    #[tokio::test]
    async fn a_foreign_context_checkpoint_is_refused_not_judged() {
        /// A different 64-hex context id, distinct from [`CTX_HEX`].
        const FOREIGN_CTX_HEX: &str =
            "0707070707070707070707070707070707070707070707070707070707070707";

        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let provider = readable_provider(3).await;
        let local_root = provider.event_log_merkle_root(&ctx_bytes()).unwrap();
        let deps = deps_over(Box::new(provider), signing_key.verifying_key()).await;

        for (merkle_root, label) in [
            (
                local_root,
                "agreeing root — without the gate this returns Ok(Consistent), \
                 a verdict about a log that was never compared",
            ),
            (
                [0xAB; 32],
                "disagreeing root — without the gate this returns Divergent, \
                 framing an honest peer",
            ),
        ] {
            let foreign = signed_remote_for(&signing_key, FOREIGN_CTX_HEX, 3, merkle_root);
            let err = classify_remote_checkpoint(true, &deps, CTX_HEX, &foreign, ACTIVE)
                .expect_err(&format!("{label}: a foreign checkpoint must be refused"));
            assert!(
                matches!(err, ContextError::CryptoFailed(_)),
                "{label}: expected CryptoFailed, got: {err}"
            );
            assert!(
                err.to_string().contains(FOREIGN_CTX_HEX),
                "{label}: the refusal must name the context the checkpoint is \
                 actually bound to, got: {err}"
            );
        }

        // Control: the SAME shape, correctly bound to this context, is judged.
        let native = signed_remote_for(&signing_key, CTX_HEX, 3, local_root);
        let (comparison, _) = classify_remote_checkpoint(true, &deps, CTX_HEX, &native, ACTIVE)
            .expect("a correctly-bound checkpoint still yields a verdict");
        assert!(
            matches!(
                comparison,
                scp_event_log::checkpoint::CheckpointComparison::Consistent
            ),
            "the binding gate must not reject checkpoints bound to this context"
        );
    }

    // =====================================================================
    // The four §9.9.3 `CheckpointComparison` verdicts, over the production
    // judge.
    //
    // These four assertions are SCP-032's count/root unit-test criteria. They
    // previously ran against `classify_against_local`, a `#[cfg(test)]`
    // reimplementation of the arithmetic in `scp-event-log/src/checkpoint.rs`
    // that was on no production path and did not even mirror production (it
    // compared roots with `==` where the judge uses `ct_eq`). A fixture
    // satisfying a production acceptance criterion hid a real gap: `Ahead` had
    // NO assertion anywhere in production test coverage.
    // =====================================================================

    /// Equal count + equal root ⇒ `Consistent`, at an empty, an odd, and an
    /// even log size. No divergence root, so no equivocation alert.
    #[tokio::test]
    async fn equal_count_and_equal_root_is_consistent() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[10u8; 32]);

        for n in [0u64, 5, 10] {
            let provider = readable_provider(n).await;
            let local_root = provider.event_log_merkle_root(&ctx_bytes()).unwrap();
            let deps = deps_over(Box::new(provider), signing_key.verifying_key()).await;

            let agreeing = signed_remote(&signing_key, n, local_root);
            let (comparison, divergence_root) =
                classify_remote_checkpoint(true, &deps, CTX_HEX, &agreeing, ACTIVE)
                    .expect("a readable local log yields a verdict");
            assert_eq!(
                comparison,
                scp_event_log::checkpoint::CheckpointComparison::Consistent,
                "n = {n}: equal count + equal root is Consistent (§9.9.3)"
            );
            assert!(
                divergence_root.is_none(),
                "n = {n}: Consistent must carry no divergence root"
            );
        }
    }

    /// Two members whose logs genuinely diverge at the SAME event count ⇒
    /// `Divergent`, and the `EquivocationDetected` alert the verdict exists to
    /// raise is emitted.
    ///
    /// The remote root here is the REAL root of a REAL second log of the same
    /// size (built with a different leaf-timestamp base), not an invented byte
    /// pattern — the two-honest-members shape §9.9.3 describes.
    #[tokio::test]
    async fn two_members_with_divergent_logs_at_equal_count_is_equivocation() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);

        let local_provider = readable_provider(5).await;
        let local_root = local_provider.event_log_merkle_root(&ctx_bytes()).unwrap();

        // A second member's log: same context, same event count, different
        // history.
        let other_root = readable_provider_from(5, 1_800_000_000)
            .await
            .event_log_merkle_root(&ctx_bytes())
            .unwrap();
        assert_ne!(
            local_root, other_root,
            "the two logs must genuinely diverge for this to be the §9.9.3 test"
        );

        let deps = deps_over(Box::new(local_provider), signing_key.verifying_key()).await;
        let mut cell =
            crate::context::actor::class_s::ClassSCell::new(state_with_sender_as_member());

        let remote = signed_remote(&signing_key, 5, other_root);
        let comparison =
            compare_remote_checkpoint(&mut cell.class_c_view(), &deps, CTX_HEX, &remote, ACTIVE)
                .expect("a readable local log yields a verdict");
        assert_eq!(
            comparison,
            scp_event_log::checkpoint::CheckpointComparison::Divergent {
                first_divergent_event: None
            },
            "equal count + different root is Divergent (§9.9.3)"
        );
        assert_eq!(
            cell.class_c_view()
                .receive_buffer_mut()
                .drain_equivocation_alerts()
                .len(),
            1,
            "a divergent verdict must raise EquivocationDetected"
        );
    }

    /// Local has FEWER events than the remote ⇒ `Behind { missing_events }`.
    /// Benign catch-up lag, so no alert and no divergence root.
    #[tokio::test]
    async fn local_behind_the_remote_is_behind_not_equivocation() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[12u8; 32]);

        // Local: 7 events. Remote: a real 10-event log's count and root.
        let remote_root = root_of_log_with(10).await;
        let deps = deps_over(
            Box::new(readable_provider(7).await),
            signing_key.verifying_key(),
        )
        .await;
        let mut cell =
            crate::context::actor::class_s::ClassSCell::new(state_with_sender_as_member());

        let remote = signed_remote(&signing_key, 10, remote_root);
        let comparison =
            compare_remote_checkpoint(&mut cell.class_c_view(), &deps, CTX_HEX, &remote, ACTIVE)
                .expect("a readable local log yields a verdict");
        assert_eq!(
            comparison,
            scp_event_log::checkpoint::CheckpointComparison::Behind { missing_events: 3 }
        );
        assert!(
            cell.class_c_view()
                .receive_buffer_mut()
                .drain_equivocation_alerts()
                .is_empty(),
            "catch-up lag is not equivocation — no alert may be raised"
        );
    }

    /// Local has MORE events than the remote ⇒ `Ahead { extra_events }`.
    ///
    /// This is the variant that had NO production assertion at all: the
    /// `Greater` arm of the judge was reachable only through a test-only
    /// reimplementation in another crate.
    #[tokio::test]
    async fn local_ahead_of_the_remote_is_ahead_not_equivocation() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[13u8; 32]);

        // Local: 10 events. Remote: a real 4-event log's count and root.
        let remote_root = root_of_log_with(4).await;
        let deps = deps_over(
            Box::new(readable_provider(10).await),
            signing_key.verifying_key(),
        )
        .await;
        let mut cell =
            crate::context::actor::class_s::ClassSCell::new(state_with_sender_as_member());

        let remote = signed_remote(&signing_key, 4, remote_root);
        let comparison =
            compare_remote_checkpoint(&mut cell.class_c_view(), &deps, CTX_HEX, &remote, ACTIVE)
                .expect("a readable local log yields a verdict");
        assert_eq!(
            comparison,
            scp_event_log::checkpoint::CheckpointComparison::Ahead { extra_events: 6 }
        );
        assert!(
            cell.class_c_view()
                .receive_buffer_mut()
                .drain_equivocation_alerts()
                .is_empty(),
            "being ahead of a peer is not equivocation — no alert may be raised"
        );
    }

    // =====================================================================
    // The gates. A verdict about a received checkpoint is only as sound as
    // the three things established before the arithmetic runs: the sender is
    // a member, the signature verifies, and the checkpoint is bound to THIS
    // context (the third is asserted by
    // `a_foreign_context_checkpoint_is_refused_not_judged` above).
    // =====================================================================

    /// A checkpoint from a NON-MEMBER is refused, not judged — over a readable
    /// log whose root genuinely disagrees, so without the gate the arithmetic
    /// would have answered `Divergent` and accused a stranger.
    #[tokio::test]
    async fn a_non_member_checkpoint_is_refused_not_judged() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[14u8; 32]);
        let provider = readable_provider(3).await;
        let local_root = provider.event_log_merkle_root(&ctx_bytes()).unwrap();
        let deps = deps_over(Box::new(provider), signing_key.verifying_key()).await;

        let disagreeing = signed_remote(&signing_key, 3, [0xAB; 32]);
        assert_ne!(local_root, [0xAB; 32]);

        let mut cell =
            crate::context::actor::class_s::ClassSCell::new(state_without_sender_as_member());
        let err = compare_remote_checkpoint(
            &mut cell.class_c_view(),
            &deps,
            CTX_HEX,
            &disagreeing,
            ACTIVE,
        )
        .expect_err("a non-member's checkpoint must be refused");
        assert!(
            matches!(err, ContextError::MemberNotFound(_)),
            "expected MemberNotFound, got: {err}"
        );

        let mut view = cell.class_c_view();
        assert!(
            view.receive_buffer_mut()
                .drain_equivocation_alerts()
                .is_empty(),
            "a refused checkpoint must raise no EquivocationDetected"
        );
        assert!(
            view.last_seen_remote_checkpoint_mut().is_empty(),
            "a refused checkpoint must record no divergence"
        );

        // Control: the SAME checkpoint from a MEMBER is judged (and diverges),
        // so the refusal above is the membership gate and not some other stop.
        let mut member_cell =
            crate::context::actor::class_s::ClassSCell::new(state_with_sender_as_member());
        let comparison = compare_remote_checkpoint(
            &mut member_cell.class_c_view(),
            &deps,
            CTX_HEX,
            &disagreeing,
            ACTIVE,
        )
        .expect("a member's checkpoint is judged");
        assert!(matches!(
            comparison,
            scp_event_log::checkpoint::CheckpointComparison::Divergent { .. }
        ));
    }

    /// A checkpoint whose signature does NOT verify against the sender's
    /// resolved key is refused, not judged.
    ///
    /// This is the ADR-011 finding recorded at
    /// `.docs/audits/adr-audit-phase-1-3.md` ("Consistency Checkpoint Does Not
    /// Verify Remote Signature", HIGH) as a regression test: without the gate,
    /// a relay or any unauthenticated sender could forge a divergent
    /// checkpoint and make honest members accuse each other.
    #[tokio::test]
    async fn a_forged_checkpoint_signature_is_refused_not_judged() {
        let honest_key = ed25519_dalek::SigningKey::from_bytes(&[15u8; 32]);
        let forger_key = ed25519_dalek::SigningKey::from_bytes(&[16u8; 32]);
        assert_ne!(honest_key.verifying_key(), forger_key.verifying_key());

        let provider = readable_provider(3).await;
        let local_root = provider.event_log_merkle_root(&ctx_bytes()).unwrap();
        // The resolver answers with the HONEST key for SENDER.
        let deps = deps_over(Box::new(provider), honest_key.verifying_key()).await;
        let mut cell =
            crate::context::actor::class_s::ClassSCell::new(state_with_sender_as_member());

        // Signed by the forger, but claiming to be from SENDER.
        let forged = signed_remote(&forger_key, 3, [0xAB; 32]);
        assert_ne!(local_root, [0xAB; 32]);
        let err =
            compare_remote_checkpoint(&mut cell.class_c_view(), &deps, CTX_HEX, &forged, ACTIVE)
                .expect_err("a checkpoint with an unverifiable signature must be refused");
        assert!(
            matches!(err, ContextError::CryptoFailed(_)),
            "expected CryptoFailed, got: {err}"
        );

        let mut view = cell.class_c_view();
        assert!(
            view.receive_buffer_mut()
                .drain_equivocation_alerts()
                .is_empty(),
            "a forged checkpoint must not be able to raise EquivocationDetected"
        );
        assert!(
            view.last_seen_remote_checkpoint_mut().is_empty(),
            "a forged checkpoint must record no divergence"
        );

        // Control: the SAME divergent claim, genuinely signed by SENDER's key,
        // IS judged — so the refusal above is the signature gate.
        let genuine = signed_remote(&honest_key, 3, [0xAB; 32]);
        let comparison =
            compare_remote_checkpoint(&mut cell.class_c_view(), &deps, CTX_HEX, &genuine, ACTIVE)
                .expect("a genuinely signed checkpoint is judged");
        assert!(matches!(
            comparison,
            scp_event_log::checkpoint::CheckpointComparison::Divergent { .. }
        ));
    }

    // =====================================================================
    // The `#agent` verification method (§9.9.3 / ADR-039).
    //
    // Spec §9.9.3 specifies the checkpoint signature as "signed by sender's
    // `#active` or `#agent` key (ADR-039); equivocation detection applies to
    // both", and its tier-(a) requirement is normative: "a conformant member
    // MUST detect the divergence and surface it". The judge previously resolved
    // `SigningKeyId::Active` unconditionally, so an equivocating peer that
    // signed its checkpoints under `#agent` was never JUDGED at all — its
    // checkpoints were refused before the comparison ran, and it escaped
    // tier-(a) detection entirely, while honest `#agent` signers were locked
    // out.
    //
    // The fix threads the verification method the sender DECLARED on the
    // enclosing inner envelope. The tests below pin both halves of that: the
    // `#agent` method is now judgeable, AND it is judged only when it is the
    // declared one (ADR-039 — the persona stamp and the signing key are chosen
    // together and must not diverge, so a try-both resolver would be a
    // regression, not an equivalent fix).
    // =====================================================================

    /// An `#agent`-signed checkpoint that DIVERGES is judged `Divergent` and
    /// raises the `EquivocationDetected` alert — the §9.9.3 tier-(a) MUST that
    /// the `#active`-only resolution used to exempt an `#agent` signer from.
    ///
    /// The remote root is the REAL root of a REAL second log at the same event
    /// count, mirroring
    /// `two_members_with_divergent_logs_at_equal_count_is_equivocation` — the
    /// same two-honest-members shape, differing only in the signing persona.
    #[tokio::test]
    async fn an_agent_signed_divergent_checkpoint_is_judged_and_alerts() {
        let active_key = ed25519_dalek::SigningKey::from_bytes(&[17u8; 32]);
        let agent_key = ed25519_dalek::SigningKey::from_bytes(&[18u8; 32]);
        assert_ne!(active_key.verifying_key(), agent_key.verifying_key());

        let local_provider = readable_provider(5).await;
        let local_root = local_provider.event_log_merkle_root(&ctx_bytes()).unwrap();
        let other_root = readable_provider_from(5, 1_800_000_000)
            .await
            .event_log_merkle_root(&ctx_bytes())
            .unwrap();
        assert_ne!(
            local_root, other_root,
            "the two logs must genuinely diverge for this to be the §9.9.3 test"
        );

        let deps = deps_over_methods(
            Box::new(local_provider),
            Some(active_key.verifying_key()),
            Some(agent_key.verifying_key()),
        )
        .await;
        let mut cell =
            crate::context::actor::class_s::ClassSCell::new(state_with_sender_as_member());

        let remote = signed_remote(&agent_key, 5, other_root);
        let comparison =
            compare_remote_checkpoint(&mut cell.class_c_view(), &deps, CTX_HEX, &remote, AGENT)
                .expect("an #agent-signed checkpoint must be JUDGED, not refused (§9.9.3)");
        assert_eq!(
            comparison,
            scp_event_log::checkpoint::CheckpointComparison::Divergent {
                first_divergent_event: None
            },
            "equal count + different root is Divergent under #agent exactly as under #active"
        );
        assert_eq!(
            cell.class_c_view()
                .receive_buffer_mut()
                .drain_equivocation_alerts()
                .len(),
            1,
            "an #agent-key equivocator must raise EquivocationDetected (§9.9.3 tier (a))"
        );
    }

    /// An `#agent`-signed checkpoint that AGREES is `Consistent` — the honest
    /// `#agent` signer the `#active`-only resolution used to lock out with
    /// `CryptoFailed`. No alert, no divergence recorded.
    #[tokio::test]
    async fn an_agent_signed_consistent_checkpoint_is_consistent() {
        let active_key = ed25519_dalek::SigningKey::from_bytes(&[19u8; 32]);
        let agent_key = ed25519_dalek::SigningKey::from_bytes(&[20u8; 32]);
        assert_ne!(active_key.verifying_key(), agent_key.verifying_key());

        let provider = readable_provider(5).await;
        let local_root = provider.event_log_merkle_root(&ctx_bytes()).unwrap();
        let deps = deps_over_methods(
            Box::new(provider),
            Some(active_key.verifying_key()),
            Some(agent_key.verifying_key()),
        )
        .await;
        let mut cell =
            crate::context::actor::class_s::ClassSCell::new(state_with_sender_as_member());

        let agreeing = signed_remote(&agent_key, 5, local_root);
        let comparison =
            compare_remote_checkpoint(&mut cell.class_c_view(), &deps, CTX_HEX, &agreeing, AGENT)
                .expect("an honest #agent-signed checkpoint must be judged, not refused");
        assert_eq!(
            comparison,
            scp_event_log::checkpoint::CheckpointComparison::Consistent,
            "equal count + equal root is Consistent under #agent (§9.9.3)"
        );

        let mut view = cell.class_c_view();
        assert!(
            view.receive_buffer_mut()
                .drain_equivocation_alerts()
                .is_empty(),
            "an agreeing peer must raise no EquivocationDetected"
        );
        assert!(
            view.last_seen_remote_checkpoint_mut().is_empty(),
            "an agreeing peer must record no divergence"
        );
    }

    /// An `#agent`-signed checkpoint the local log is BEHIND is
    /// `Behind { missing_events }` — benign catch-up lag, no alert.
    ///
    /// The `#active` twin is
    /// [`local_behind_the_remote_is_behind_not_equivocation`]; this pins that
    /// the non-equivocation arms are persona-independent too. Without it the
    /// `#agent` coverage would stop at the two arms that touch the alert path,
    /// leaving open the possibility that a declared `#agent` reaches the
    /// signature gate but is mis-classified once past it — which is exactly the
    /// class of bug that would turn genuine catch-up lag into an accusation.
    #[tokio::test]
    async fn an_agent_signed_behind_checkpoint_is_behind_not_equivocation() {
        let active_key = ed25519_dalek::SigningKey::from_bytes(&[24u8; 32]);
        let agent_key = ed25519_dalek::SigningKey::from_bytes(&[25u8; 32]);
        assert_ne!(active_key.verifying_key(), agent_key.verifying_key());

        // Local: 7 events. Remote: a real 10-event log's count and root.
        let remote_root = root_of_log_with(10).await;
        let deps = deps_over_methods(
            Box::new(readable_provider(7).await),
            Some(active_key.verifying_key()),
            Some(agent_key.verifying_key()),
        )
        .await;
        let mut cell =
            crate::context::actor::class_s::ClassSCell::new(state_with_sender_as_member());

        let remote = signed_remote(&agent_key, 10, remote_root);
        let comparison =
            compare_remote_checkpoint(&mut cell.class_c_view(), &deps, CTX_HEX, &remote, AGENT)
                .expect("an #agent-signed checkpoint over a readable log yields a verdict");
        assert_eq!(
            comparison,
            scp_event_log::checkpoint::CheckpointComparison::Behind { missing_events: 3 },
            "being behind an #agent signer is catch-up lag, exactly as under #active"
        );
        assert!(
            cell.class_c_view()
                .receive_buffer_mut()
                .drain_equivocation_alerts()
                .is_empty(),
            "catch-up lag is not equivocation — no alert may be raised under #agent"
        );
    }

    /// An `#agent`-signed checkpoint the local log is AHEAD of is
    /// `Ahead { extra_events }` — no alert.
    ///
    /// The `#active` twin is [`local_ahead_of_the_remote_is_ahead_not_equivocation`].
    #[tokio::test]
    async fn an_agent_signed_ahead_checkpoint_is_ahead_not_equivocation() {
        let active_key = ed25519_dalek::SigningKey::from_bytes(&[26u8; 32]);
        let agent_key = ed25519_dalek::SigningKey::from_bytes(&[27u8; 32]);
        assert_ne!(active_key.verifying_key(), agent_key.verifying_key());

        // Local: 10 events. Remote: a real 4-event log's count and root.
        let remote_root = root_of_log_with(4).await;
        let deps = deps_over_methods(
            Box::new(readable_provider(10).await),
            Some(active_key.verifying_key()),
            Some(agent_key.verifying_key()),
        )
        .await;
        let mut cell =
            crate::context::actor::class_s::ClassSCell::new(state_with_sender_as_member());

        let remote = signed_remote(&agent_key, 4, remote_root);
        let comparison =
            compare_remote_checkpoint(&mut cell.class_c_view(), &deps, CTX_HEX, &remote, AGENT)
                .expect("an #agent-signed checkpoint over a readable log yields a verdict");
        assert_eq!(
            comparison,
            scp_event_log::checkpoint::CheckpointComparison::Ahead { extra_events: 6 },
            "being ahead of an #agent signer is not equivocation, exactly as under #active"
        );
        assert!(
            cell.class_c_view()
                .receive_buffer_mut()
                .drain_equivocation_alerts()
                .is_empty(),
            "being ahead of a peer is not equivocation — no alert may be raised under #agent"
        );
    }

    /// A checkpoint signed by a key that is NEITHER of the sender's two
    /// permitted verification methods — a device key, a rotated-out key, a
    /// relay's key — is refused with `CryptoFailed` under either declaration.
    ///
    /// [`scp_did::SigningKeyId`] admits only `Active` and `Agent`, so a third
    /// key class is not nameable in the DECLARATION; what this pins is that a
    /// third key class cannot get in through the SIGNATURE either, under either
    /// declared method.
    #[tokio::test]
    async fn a_checkpoint_signed_by_neither_permitted_key_class_is_refused() {
        let active_key = ed25519_dalek::SigningKey::from_bytes(&[21u8; 32]);
        let agent_key = ed25519_dalek::SigningKey::from_bytes(&[22u8; 32]);
        // A key the sender's DID document does not publish under EITHER
        // verification method.
        let other_class_key = ed25519_dalek::SigningKey::from_bytes(&[23u8; 32]);

        let provider = readable_provider(3).await;
        let local_root = provider.event_log_merkle_root(&ctx_bytes()).unwrap();
        assert_ne!(local_root, [0xAB; 32]);
        let deps = deps_over_methods(
            Box::new(provider),
            Some(active_key.verifying_key()),
            Some(agent_key.verifying_key()),
        )
        .await;

        for (declared, label) in [(ACTIVE, "declared #active"), (AGENT, "declared #agent")] {
            let mut cell =
                crate::context::actor::class_s::ClassSCell::new(state_with_sender_as_member());
            let foreign_class = signed_remote(&other_class_key, 3, [0xAB; 32]);
            let err = compare_remote_checkpoint(
                &mut cell.class_c_view(),
                &deps,
                CTX_HEX,
                &foreign_class,
                declared,
            )
            .expect_err(&format!(
                "{label}: a key outside #active/#agent must never be accepted"
            ));
            assert!(
                matches!(err, ContextError::CryptoFailed(_)),
                "{label}: expected CryptoFailed, got: {err}"
            );

            let mut view = cell.class_c_view();
            assert!(
                view.receive_buffer_mut()
                    .drain_equivocation_alerts()
                    .is_empty(),
                "{label}: a refused checkpoint must raise no EquivocationDetected"
            );
            assert!(
                view.last_seen_remote_checkpoint_mut().is_empty(),
                "{label}: a refused checkpoint must record no divergence"
            );
        }

        // Control: the SAME divergent claim, signed by a key the DID document
        // DOES publish and declared under that method, IS judged — so the
        // refusals above are the key-class boundary and not some other stop.
        let mut cell =
            crate::context::actor::class_s::ClassSCell::new(state_with_sender_as_member());
        let genuine = signed_remote(&agent_key, 3, [0xAB; 32]);
        let comparison =
            compare_remote_checkpoint(&mut cell.class_c_view(), &deps, CTX_HEX, &genuine, AGENT)
                .expect("a checkpoint under a published verification method is judged");
        assert!(matches!(
            comparison,
            scp_event_log::checkpoint::CheckpointComparison::Divergent { .. }
        ));
    }

    /// A checkpoint is verified against the DECLARED verification method and no
    /// other: an `#agent`-signed checkpoint declared `#active` is REFUSED, and
    /// an `#active`-signed one declared `#agent` is REFUSED — even though the
    /// other method would have verified in each case.
    ///
    /// This is the regression guard against "resolve `#active`, else try
    /// `#agent`, accept if either verifies". Try-both would pass both arms
    /// below, and in doing so would decouple the persona stamp from the signing
    /// key — the divergence ADR-039's Enforcement-Stack layer 2 exists to
    /// prevent, where the stamp and the key "are chosen together from one
    /// persona and cannot diverge". Under try-both an agent-signed checkpoint
    /// would be accepted while declaring the human persona, laundering an agent
    /// action into a human attribution.
    #[tokio::test]
    async fn a_checkpoint_is_judged_only_under_the_declared_verification_method() {
        let active_key = ed25519_dalek::SigningKey::from_bytes(&[24u8; 32]);
        let agent_key = ed25519_dalek::SigningKey::from_bytes(&[25u8; 32]);
        assert_ne!(active_key.verifying_key(), agent_key.verifying_key());

        let provider = readable_provider(3).await;
        let local_root = provider.event_log_merkle_root(&ctx_bytes()).unwrap();
        assert_ne!(local_root, [0xAB; 32]);
        let deps = deps_over_methods(
            Box::new(provider),
            Some(active_key.verifying_key()),
            Some(agent_key.verifying_key()),
        )
        .await;

        // Both verification methods resolve, so a refusal here can only be the
        // declared-method binding — not an absent key.
        for (signer, declared, label) in [
            (
                &agent_key,
                ACTIVE,
                "#agent-signed but declared #active — accepting this would attribute \
                 an agent action to the human persona",
            ),
            (
                &active_key,
                AGENT,
                "#active-signed but declared #agent — accepting this would attribute \
                 a human action to the agent persona",
            ),
        ] {
            let mut cell =
                crate::context::actor::class_s::ClassSCell::new(state_with_sender_as_member());
            let mismatched = signed_remote(signer, 3, [0xAB; 32]);
            let err = compare_remote_checkpoint(
                &mut cell.class_c_view(),
                &deps,
                CTX_HEX,
                &mismatched,
                declared,
            )
            .expect_err(&format!("{label}: must be refused"));
            assert!(
                matches!(err, ContextError::CryptoFailed(_)),
                "{label}: expected CryptoFailed, got: {err}"
            );

            let mut view = cell.class_c_view();
            assert!(
                view.receive_buffer_mut()
                    .drain_equivocation_alerts()
                    .is_empty(),
                "{label}: a refused checkpoint must raise no EquivocationDetected"
            );
            assert!(
                view.last_seen_remote_checkpoint_mut().is_empty(),
                "{label}: a refused checkpoint must record no divergence"
            );
        }

        // Controls: each key under ITS OWN declared method is judged, so the two
        // refusals above are the declared-method binding and nothing else.
        for (signer, declared, label) in [
            (&active_key, ACTIVE, "#active-signed, declared #active"),
            (&agent_key, AGENT, "#agent-signed, declared #agent"),
        ] {
            let mut cell =
                crate::context::actor::class_s::ClassSCell::new(state_with_sender_as_member());
            let matched = signed_remote(signer, 3, [0xAB; 32]);
            let comparison = compare_remote_checkpoint(
                &mut cell.class_c_view(),
                &deps,
                CTX_HEX,
                &matched,
                declared,
            )
            .expect(label);
            assert!(
                matches!(
                    comparison,
                    scp_event_log::checkpoint::CheckpointComparison::Divergent { .. }
                ),
                "{label}: must be judged"
            );
        }
    }

    /// A declared verification method that the sender's DID document does NOT
    /// carry is refused with `CryptoFailed` naming that method — never silently
    /// retried against the other one.
    ///
    /// This is the ordinary human-only member: `#active` published, no `#agent`
    /// key. A checkpoint arriving declared `#agent` has no key to check against,
    /// and "no key to check against" is a refusal to judge.
    #[tokio::test]
    async fn a_declared_method_absent_from_the_did_document_is_refused() {
        let active_key = ed25519_dalek::SigningKey::from_bytes(&[26u8; 32]);
        let agent_key = ed25519_dalek::SigningKey::from_bytes(&[27u8; 32]);

        let provider = readable_provider(3).await;
        // Human-only member: `#active` resolves, `#agent` is absent.
        let deps =
            deps_over_methods(Box::new(provider), Some(active_key.verifying_key()), None).await;
        let mut cell =
            crate::context::actor::class_s::ClassSCell::new(state_with_sender_as_member());

        let remote = signed_remote(&agent_key, 3, [0xAB; 32]);
        let err =
            compare_remote_checkpoint(&mut cell.class_c_view(), &deps, CTX_HEX, &remote, AGENT)
                .expect_err("an unresolvable declared verification method must be refused");
        assert!(
            matches!(err, ContextError::CryptoFailed(_)),
            "expected CryptoFailed, got: {err}"
        );
        assert!(
            err.to_string().contains("#agent"),
            "the refusal must name the verification method that could not be \
             resolved, got: {err}"
        );

        let mut view = cell.class_c_view();
        assert!(
            view.receive_buffer_mut()
                .drain_equivocation_alerts()
                .is_empty(),
            "a refused checkpoint must raise no EquivocationDetected"
        );
        assert!(
            view.last_seen_remote_checkpoint_mut().is_empty(),
            "a refused checkpoint must record no divergence"
        );
    }
}
