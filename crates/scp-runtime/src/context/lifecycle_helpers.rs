//! Lifecycle helpers — actor-shape signatures
//! (ADR-049 Phase 2A.9, `lifecycle` domain migration).
//!
//! # Purpose
//!
//! This module hosts lifecycle-domain helpers that operate on
//! actor-owned [`PerContextState`](crate::context::actor::state::PerContextState)
//! and capability-reduced [`ActorDeps`](crate::context::actor::deps::ActorDeps).
//! The legacy `&Supervisor` lock-and-call bodies live in
//! [`crate::context::lifecycle_helpers_legacy`] until Phase 2A
//! finalization removes the shim fallback.
//!
//! # Migration shape
//!
//! Phase 2A.9 mirrors the Phase 2A.6 TTL shape: every actor-shape
//! helper here is a thin wrapper that delegates the heavy lifting to
//! the matching `*_legacy` body via the
//! [`SupervisorHandle::shim_supervisor`](crate::context::supervisor::handle::SupervisorHandle::shim_supervisor)
//! escape. Three reasons drive this delegation choice:
//!
//! 1. The lifecycle bodies own the legacy contexts `DashMap`
//!    (`manager_methods::insert_context`, `lock_context`,
//!    `relock_context`, `get_context_arc`) which holds the only
//!    authoritative `PerContextState` for callers that have not yet
//!    been routed through a per-context actor mailbox.
//! 2. The lifecycle handler currently routes every command through
//!    the direct-shim path (no `dispatch_via_mailbox` fan-out for
//!    `LifecycleCommand` — see
//!    [`Supervisor::lifecycle_command_context_id`](crate::context::supervisor::Supervisor)
//!    which returns `None` for the major variants) so the actor's
//!    owned `PerContextState` is not yet the authoritative store.
//! 3. The bootstrap entry points (`create_context`, `restore_context`,
//!    `import_context`) construct a fresh legacy `PerContextState`
//!    and register it; they cannot pre-borrow `&mut state` because
//!    no actor exists yet for the context being created.
//!
//! Phase 2A finalization will dissolve the legacy contexts map and
//! collapse these wrappers into direct actor-state operations; until
//! then the actor-shape signatures here exist for handler-uniformity
//! and to let the dispatch arm in
//! [`crate::context::actor::ContextActor`] route lifecycle commands
//! identically to other migrated domains.
//!
//! # Top-level entry points (actor-handler dispatch targets)
//!
//! - [`export_context`] — capture snapshot + event-log + signed export.
//! - [`import_context`] — validate + restore crypto + register
//!   (bootstrap entry point).
//! - [`create_context`] — two-phase create + register + finalize
//!   (bootstrap entry point).
//! - [`join_context`] — F4 escrow dance: economy + sybil + hard-rate-
//!   limit + MLS add + sender-key distribute + membership mutate +
//!   capture.
//! - [`leave_context`] — capability check + MLS remove + sender-key
//!   cleanup + close-on-empty.
//! - [`drain_and_deliver_sender_keys`] — sender-key distribution drain
//!   used by join / leave.
//! - [`close_context`] — `SingleAdmin` gate + `ttl::close` + cancel
//!   timers + final checkpoint + persist.
//! - [`restore_context`] — rebuild `PerContextState` from snapshot +
//!   register + start governance timeout + spawn TTL (bootstrap entry
//!   point).
//!
//! # Transitive helpers (live in `_legacy.rs` only)
//!
//! `finalize_create`, `join_context_membership`, `capture_join_payment`,
//! `close_context_with_key`, `load_persisted_context_state` are
//! body-implementation details of the outer entry points. Because the
//! actor-shape outer wrappers delegate fully to the `_legacy` bodies
//! (which compose the transitives internally), the transitives have
//! no actor-shape caller until Phase 2A finalization replaces the
//! delegation with direct composition. They live ONLY in
//! [`crate::context::lifecycle_helpers_legacy`] for the duration of
//! the migration window.
//!
//! # Designated-legacy supervisor-scoped iteration helpers
//!
//! The following helpers iterate the contexts `DashMap` and inherently
//! cannot move to actor-owned shape — they live ONLY in
//! [`crate::context::lifecycle_helpers_legacy`] with no actor-shape
//! twin:
//!
//! - `restore_all_contexts_legacy` — sweeps persisted contexts on
//!   startup.
//! - `flush_all_contexts_legacy` / `flush_all_contexts_sync_legacy`
//!   — sweep the contexts map for shutdown flush.
//! - `shutdown_all_contexts_legacy` /
//!   `shutdown_all_contexts_sync_legacy` — sweep the contexts map
//!   for orderly shutdown.

use scp_identity::DID;
use scp_protocol::context::builder::ContextCreationError;
use scp_protocol::context::membership::KeyPackage;
use scp_protocol::context::{ContextError, ContextParams};

use crate::context::ContextHandle;
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::state::PerContextState;
use crate::context::ttl::CloseResult;

// ---------------------------------------------------------------------------
// 1. export_context
// ---------------------------------------------------------------------------

/// Exports a context's full state as a transferable `ContextExport`.
///
/// Actor-shape wrapper that delegates to
/// [`crate::context::lifecycle_helpers_legacy::export_context_legacy`]
/// via the [`SupervisorHandle::shim_supervisor`](crate::context::supervisor::handle::SupervisorHandle::shim_supervisor)
/// escape. See the legacy body for byte-identical semantics: snapshot
/// capture, event-log export, signed export construction.
///
/// `state` is currently not read here — the legacy body looks up
/// per-context state through the contexts `DashMap` via
/// `manager_methods::get_context_arc`. The `&mut PerContextState`
/// borrow is part of the actor-shape contract for signature uniformity
/// (and so the borrow crosses awaits without forcing `Sync` on
/// `PerContextState`).
///
/// # Errors
///
/// Returns [`ContextError::MembershipFailed`] if the context is not
/// registered, or a transport-/persistence-level error from the
/// underlying event-log export.
pub async fn export_context(
    _state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    exporter_did: DID,
) -> Result<crate::context::export_import::ContextExport, ContextError> {
    let supervisor = deps.supervisor.shim_supervisor();
    crate::context::lifecycle_helpers_legacy::export_context_legacy(
        supervisor.as_ref(),
        context_id,
        exporter_did,
    )
    .await
}

// ---------------------------------------------------------------------------
// 2. import_context (bootstrap — constructs fresh PerContextState)
// ---------------------------------------------------------------------------

/// Imports a previously exported context into the supervisor.
///
/// Bootstrap entry point — constructs a fresh legacy `PerContextState`
/// and registers it in the contexts `DashMap`. Takes only `&ActorDeps`
/// (no `&mut state`) because no actor exists for the context being
/// imported until registration completes.
///
/// Delegates to
/// [`crate::context::lifecycle_helpers_legacy::import_context_legacy`]
/// via the
/// [`SupervisorHandle::shim_supervisor`](crate::context::supervisor::handle::SupervisorHandle::shim_supervisor)
/// escape. See the legacy body for the full C3 per-instance wipe
/// policy, consequence-rule validation, and crypto-state restore
/// semantics.
///
/// # Errors
///
/// Returns [`ContextError`] from the legacy body — most commonly
/// `MembershipFailed` (already exists), `PersistenceFailed` (event-log
/// import), `InvalidState` (snapshot in non-importable state), or
/// `NotInitialized` (provider slot empty).
pub async fn import_context(
    deps: &ActorDeps,
    export: crate::context::export_import::ContextExport,
) -> Result<ContextHandle, ContextError> {
    let supervisor = deps.supervisor.shim_supervisor();
    crate::context::lifecycle_helpers_legacy::import_context_legacy(supervisor.as_ref(), export)
        .await
}

// ---------------------------------------------------------------------------
// 3. create_context (bootstrap — constructs fresh PerContextState)
// ---------------------------------------------------------------------------

/// Creates a new SCP context with the two-phase commit pattern.
///
/// Bootstrap entry point — constructs a fresh legacy `PerContextState`
/// and registers it in the contexts `DashMap`. Takes only `&ActorDeps`
/// (no `&mut state`) because no actor exists for the context being
/// created until registration completes.
///
/// Delegates to
/// [`crate::context::lifecycle_helpers_legacy::create_context_legacy`]
/// via the
/// [`SupervisorHandle::shim_supervisor`](crate::context::supervisor::handle::SupervisorHandle::shim_supervisor)
/// escape. See the legacy body for the full validation, MLS group
/// initialization, role-state construction, and post-creation
/// finalization sequence.
///
/// # Errors
///
/// Returns [`ContextCreationError`] from the legacy body — wrapping
/// validation failures, MLS init failures, or persistence failures.
pub async fn create_context(
    deps: &ActorDeps,
    context_id: String,
    params: ContextParams,
    creator_did: DID,
    local_pseudonym: Option<[u8; 32]>,
) -> Result<ContextHandle, ContextCreationError> {
    let supervisor = deps.supervisor.shim_supervisor();
    crate::context::lifecycle_helpers_legacy::create_context_legacy(
        supervisor.as_ref(),
        context_id,
        params,
        creator_did,
        local_pseudonym,
    )
    .await
}

// ---------------------------------------------------------------------------
// 4. join_context (top-level)
// ---------------------------------------------------------------------------

/// Joins a member to a context.
///
/// Actor-shape wrapper that delegates to
/// [`crate::context::lifecycle_helpers_legacy::join_context_legacy`]
/// via the
/// [`SupervisorHandle::shim_supervisor`](crate::context::supervisor::handle::SupervisorHandle::shim_supervisor)
/// escape. See the legacy body for the full F4 escrow dance:
/// economy / sybil / hard-rate-limit under lock, then authorize, MLS
/// add, sender-key distribute, membership mutate, capture.
///
/// `state` is currently not read here — the legacy body looks up
/// per-context state through the contexts `DashMap` via
/// `manager_methods::lock_context` / `relock_context`. The `&mut
/// PerContextState` borrow is part of the actor-shape contract for
/// signature uniformity.
///
/// # Errors
///
/// Returns [`ContextError`] for membership / capability / economy /
/// crypto failures. Each phase has its own rollback discipline; see
/// the legacy body for details.
pub async fn join_context(
    _state: &mut PerContextState,
    deps: &ActorDeps,
    handle: &ContextHandle,
    key_package: KeyPackage,
    spending_ucan: Option<&scp_protocol::crypto::ucan::UcanToken>,
    local_pseudonym: Option<[u8; 32]>,
) -> Result<(), ContextError> {
    let supervisor = deps.supervisor.shim_supervisor();
    crate::context::lifecycle_helpers_legacy::join_context_legacy(
        supervisor.as_ref(),
        handle,
        key_package,
        spending_ucan,
        local_pseudonym,
    )
    .await
}

// ---------------------------------------------------------------------------
// 5. leave_context (top-level)
// ---------------------------------------------------------------------------

/// Removes a member from a context.
///
/// Actor-shape wrapper that delegates to
/// [`crate::context::lifecycle_helpers_legacy::leave_context_legacy`]
/// via the
/// [`SupervisorHandle::shim_supervisor`](crate::context::supervisor::handle::SupervisorHandle::shim_supervisor)
/// escape. Self-removal is always permitted; otherwise requires
/// `MemberRemove` capability. Performs MLS `remove_member` (hard
/// security boundary) then sender-key cleanup (best-effort), broadcasts
/// the resulting Commit, rotates the sender key, and appends a
/// `MemberLeft` event.
///
/// `state` is currently not read here — the legacy body looks up
/// per-context state through the contexts `DashMap` via
/// `manager_methods::lock_context` / `relock_context`.
///
/// # Errors
///
/// Returns [`ContextError`] for permission / membership / crypto /
/// transport failures.
pub async fn leave_context(
    _state: &mut PerContextState,
    deps: &ActorDeps,
    handle: &ContextHandle,
    caller_did: &DID,
    member_did: &DID,
) -> Result<(), ContextError> {
    let supervisor = deps.supervisor.shim_supervisor();
    crate::context::lifecycle_helpers_legacy::leave_context_legacy(
        supervisor.as_ref(),
        handle,
        caller_did,
        member_did,
    )
    .await
}

// ---------------------------------------------------------------------------
// 9. drain_and_deliver_sender_keys (transitive of join / leave)
// ---------------------------------------------------------------------------

/// Drains pending sender key distribution messages and delivers them
/// via transport (§9.16.2).
///
/// Actor-shape wrapper that delegates to
/// [`crate::context::lifecycle_helpers_legacy::drain_and_deliver_sender_keys_legacy`]
/// via the
/// [`SupervisorHandle::shim_supervisor`](crate::context::supervisor::handle::SupervisorHandle::shim_supervisor)
/// escape.
///
/// # Errors
///
/// Returns [`ContextError::NotInitialized`] if the crypto or transport
/// provider is not configured.
pub fn drain_and_deliver_sender_keys(
    _state: &mut PerContextState,
    deps: &ActorDeps,
    context_id: &str,
    context_id_bytes: &[u8; 32],
) -> Result<(), ContextError> {
    let supervisor = deps.supervisor.shim_supervisor();
    crate::context::lifecycle_helpers_legacy::drain_and_deliver_sender_keys_legacy(
        supervisor.as_ref(),
        context_id,
        context_id_bytes,
    )
}

// ---------------------------------------------------------------------------
// 10. close_context (top-level, forwarder into close_context_with_key)
// ---------------------------------------------------------------------------

/// Initiates cooperative context closure.
///
/// Actor-shape wrapper that delegates to
/// [`crate::context::lifecycle_helpers_legacy::close_context_legacy`]
/// via the
/// [`SupervisorHandle::shim_supervisor`](crate::context::supervisor::handle::SupervisorHandle::shim_supervisor)
/// escape. For `SingleAdmin` governance: delegates to
/// [`close_context_with_key`] with no signing key. Multi-admin contexts
/// are rejected — they must route through the governance path.
///
/// # Errors
///
/// Returns [`ContextError::PermissionDenied`] for multi-admin contexts;
/// otherwise propagates errors from
/// [`close_context_with_key`].
pub async fn close_context(
    _state: &mut PerContextState,
    deps: &ActorDeps,
    handle: &ContextHandle,
    initiator_did: &DID,
) -> Result<CloseResult, ContextError> {
    let supervisor = deps.supervisor.shim_supervisor();
    crate::context::lifecycle_helpers_legacy::close_context_legacy(
        supervisor.as_ref(),
        handle,
        initiator_did,
    )
    .await
}

// ---------------------------------------------------------------------------
// 7. restore_context (bootstrap — constructs fresh PerContextState)
// ---------------------------------------------------------------------------

/// Restores a context into the supervisor from persisted state.
///
/// Bootstrap entry point — constructs a fresh legacy `PerContextState`
/// from the persisted snapshot and registers it in the contexts
/// `DashMap`. Takes only `&ActorDeps` (no `&mut state`) because no
/// actor exists for the context being restored until registration
/// completes.
///
/// Delegates to
/// [`crate::context::lifecycle_helpers_legacy::restore_context_legacy`]
/// via the
/// [`SupervisorHandle::shim_supervisor`](crate::context::supervisor::handle::SupervisorHandle::shim_supervisor)
/// escape. See the legacy body for the full snapshot-validation,
/// crypto-restore, and governance-engine reconstruction sequence.
///
/// # Errors
///
/// Returns [`ContextError::PersistenceFailed`] if no persisted state
/// exists. Returns [`ContextError::MembershipFailed`] if the context
/// cannot be inserted (already registered).
#[tracing::instrument(skip_all, fields(context_id))]
pub async fn restore_context(
    deps: &ActorDeps,
    context_id: &str,
    handle: &crate::context::ContextHandle,
) -> Result<(), ContextError> {
    let supervisor = deps.supervisor.shim_supervisor();
    crate::context::lifecycle_helpers_legacy::restore_context_legacy(
        supervisor.as_ref(),
        context_id,
        handle,
    )
    .await
}
