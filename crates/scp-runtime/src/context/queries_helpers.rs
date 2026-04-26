// Module-level allow — the legacy inherent-impl form in
// `manager/queries.rs` carried `#[allow(clippy::significant_drop_tightening)]`
// on its impl block. The hoisted bodies preserve the same lock-hold-across-await
// patterns deliberately (narrowing changes lock-ordering semantics); allowing
// the lint crate-locally keeps the hoist byte-identical to the legacy behavior.
//
// `dead_code` is allowed module-wide because this module is the
// authoritative home for query-domain free functions consumed by FFI
// bridges (PyO3 / NAPI / UniFFI / WASM) and by external test crates
// behind `feature = "testing"`. After ADR-049 commit 12 deleted the
// `ContextManager` forwarders, several public helpers (access-key
// management, checkpoint comparison, Merkle proofs, budget/velocity
// test accessors) lost their in-tree callers; they remain public so
// FFI bridges and tests can reach them. Where appropriate the
// `Supervisor` exposes a passthrough; where it does not, callers
// continue to use `crate::context::queries_helpers::X` directly.
#![allow(clippy::significant_drop_tightening, dead_code)]

//! Queries-domain helpers with explicit-collaborator signatures
//! (ADR-049 §12c.5).
//!
//! # Purpose
//!
//! This module hoists the query-domain methods that the actor-handler
//! shim path ([`crate::context::supervisor::supervisor::Supervisor::dispatch_query`])
//! and existing hoisted helpers (`messaging_helpers::finalize_send`,
//! `lifecycle_helpers::finalize_close`) reach via legacy
//! `ContextManager::X(...)` method calls. The hoist is the final
//! **pre-work** commit for the actor handler body migration (later
//! ADR-049 commits): handler bodies cannot take `&ContextManager` — they
//! take `&ActorDeps` and `&mut PerContextState` — so the methods they
//! call must accept explicit collaborators rather than reaching through
//! `self`. After this commit, every actor-handler-reachable method body
//! on [`Supervisor`](crate::context::supervisor::Supervisor) lives
//! in a sibling `*_helpers.rs` module; the legacy inherent methods are
//! one-line forwarders that are deleted alongside the outer shim in a
//! later ADR-049 commit.
//!
//! This file is the queries counterpart to
//! [`crate::context::messaging_helpers`] (12b.1, 12c.1, 12c.1b),
//! [`crate::context::lifecycle_helpers`] (12c.2),
//! [`crate::context::governance_helpers`] (12c.3b),
//! [`crate::context::economy_helpers`] (12c.3a),
//! [`crate::context::trust_recovery_helpers`] (12c.3a),
//! [`crate::context::standing_helpers`] (12c.4),
//! [`crate::context::tools_helpers`] (12c.4), and
//! [`crate::context::broadcast_helpers`] (12c.4).
//!
//! # Behavior preservation
//!
//! Every hoisted free function is **behavior-preserving by construction**.
//! Its body is a verbatim copy of the legacy inherent method's body with
//! `self.X` replaced by either:
//!
//! - `manager_methods::X(supervisor, ...)` for cross-domain helpers
//!   (12c.9g.1 hoist; helper bodies migrated to direct calls in
//!   commit 12c.9g.2), or
//! - `supervisor.X_ref().ok_or(NotInitialized)?` for provider slots
//!   lifted to the supervisor in ADR-049 commit 12c.9a-9b.
//!
//! The legacy inherent methods on
//! [`Supervisor`](crate::context::supervisor::Supervisor) remain as
//! one-line forwarders; they are deleted alongside the outer shim in a
//! later ADR-049 commit when the actor handler bodies own the queries
//! path directly.
//!
//! # Top-level methods hoisted
//!
//! Local DID / identity management (3):
//! [`register_local_did`], [`is_local_did`].
//!
//! Per-context read queries (10):
//! [`local_pseudonym`], [`get_broadcast_key_for_local_author`],
//! [`member_count`], [`is_member`], [`member_dids`], [`member_role`],
//! [`context_params`], [`get_role_state`], [`pending_commits`],
//! [`commit_fault`].
//!
//! Receive buffer + degraded mode (2):
//! [`drain_events`], [`report_degraded_mode`].
//!
//! Event log passthrough (1):
//! [`event_log_entries`].
//!
//! Access-key management (5):
//! [`generate_context_access_key`], [`revoke_context_access_key`],
//! [`restore_context_access_key`], [`set_access_key`],
//! [`remove_access_key`].
//!
//! Test-only accessors (6; `#[cfg(feature = "testing")]`):
//! [`inject_access_key`], [`get_access_key`], [`get_all_access_keys`],
//! [`grant_budget_for_test`], [`remaining_budget_for_test`],
//! [`velocity_for_test`].
//!
//! Checkpoint operations (3):
//! [`create_checkpoint_if_due`], [`force_create_checkpoint`],
//! [`compare_remote_checkpoint`]. The private helper
//! [`build_checkpoint`] (no `mgr` parameter — pure function over
//! a borrow of `PerContextState` and an event-log provider) is also
//! hoisted here.
//!
//! Merkle proof operations (4):
//! [`prove_event_inclusion`], [`prove_event_consistency`],
//! [`verify_event_inclusion`], [`verify_event_consistency`]. The
//! private helper [`sync_merkle_tree`] (no `mgr` parameter after hoist —
//! takes an explicit `&dyn ContextEventLogProvider`) is also hoisted
//! here.
//!
//! # Not hoisted (kept as inherent methods on `Supervisor`)
//!
//! `set_payment_adapter` was deleted in the post-review-round-1 phase 1
//! fix-up of ADR-049 — payment adapters are now passed exclusively into
//! [`Supervisor::with_providers`](crate::context::supervisor::Supervisor::with_providers)
//! at construction time. The two-paths-to-set seam had no production
//! callers.
//!
//! `event_log_provider` is a pure accessor that returns
//! `&dyn ContextEventLogProvider`; the modern accessor is
//! [`ContextManager::event_log_ref`](crate::context::supervisor::Supervisor::event_log_ref).
//! The legacy method remains as inherent for FFI-bridge backwards
//! compatibility.

use std::collections::HashMap;

use scp_identity::DID;
use scp_protocol::context::membership::ContextEvent;
use scp_protocol::context::roles::{Capability, ContextRoleState, RoleAssignment};
use scp_protocol::context::{ContextError, ContextParams};
use zeroize::Zeroizing;

use crate::context::builder::ContextEventLogProvider;
use crate::context::manager_methods;
use crate::context::providers::event_log::EventLogEntry;
use crate::context::state::{
    CommitFaultMarker, PendingCommit, PerContextState, context_id_to_bytes,
};
use crate::context::supervisor::Supervisor;

// Phase 1 fix-up of ADR-049 (post-review-round-1): per-helper
// `ATTACHED_EXPECT` constants consolidated to the single
// `PROVIDER_NOT_INITIALIZED` definition in `manager_methods`.
use crate::context::manager_methods::PROVIDER_NOT_INITIALIZED as ATTACHED_EXPECT;

/// Maximum number of checkpoints retained per context. Older checkpoints
/// are drained when this limit is exceeded to prevent unbounded growth.
///
/// Hoisted from the legacy
/// `crate::context::queries_helpers::MAX_RETAINED_CHECKPOINTS` private
/// constant (ADR-049 commit 12c.5). The legacy constant is removed
/// because its sole readers (`create_checkpoint_if_due` /
/// `force_create_checkpoint`) now live in this module.
const MAX_RETAINED_CHECKPOINTS: usize = 100;

// ===========================================================================
// Local DID / identity management
// ===========================================================================

/// Registers a DID as controlled by the local node/SDK.
///
/// Hoisted body of the legacy
/// [`ContextManager::register_local_did`](crate::context::supervisor::Supervisor::register_local_did)
/// (ADR-049 commit 12c.5). Byte-identical behavior.
pub async fn register_local_did(supervisor: &Supervisor, did: DID) {
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
/// Hoisted body of the legacy `ContextManager::is_local_did` method
/// (ADR-049 commit 12c.5). Byte-identical behavior.
///
/// `async` is preserved (despite no `await` after the §12 lock-free
/// read migration) to keep the signature symmetric with
/// `register_local_did` and the legacy method, matching the call shape
/// the FFI bridges + `Supervisor::is_local_did` passthrough expect.
#[allow(clippy::unused_async)]
pub async fn is_local_did(supervisor: &Supervisor, did: &DID) -> bool {
    // Lock-free read (ADR-049 §Decision 12).
    supervisor.local_dids_ref().load().contains(did)
}

// ===========================================================================
// Per-context read queries
// ===========================================================================

/// Returns the local member's pseudonym routing ID for a context
/// (§9.10.4).
///
/// Hoisted body of the legacy
/// [`ContextManager::local_pseudonym`](crate::context::supervisor::Supervisor::local_pseudonym)
/// (ADR-049 commit 12c.5). Byte-identical behavior.
///
/// # Errors
///
/// Returns [`ContextError::ContextNotRegistered`] if the context is not
/// registered.
pub async fn local_pseudonym(
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
/// Hoisted body of the legacy
/// [`ContextManager::get_broadcast_key_for_local_author`](crate::context::supervisor::Supervisor::get_broadcast_key_for_local_author)
/// (ADR-049 commit 12c.5). Byte-identical behavior.
///
/// # Errors
///
/// - [`ContextError::ContextNotRegistered`] if the context is not registered
///   or is not a broadcast context.
/// - [`ContextError::PermissionDenied`] if `author_did` is not locally
///   controlled.
/// - [`ContextError::MemberNotFound`] if `author_did` is not a registered
///   author in the broadcast context.
pub async fn get_broadcast_key_for_local_author(
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
///
/// Hoisted body of the legacy
/// [`ContextManager::member_count`](crate::context::supervisor::Supervisor::member_count)
/// (ADR-049 commit 12c.5). Byte-identical behavior.
pub async fn member_count(supervisor: &Supervisor, context_id: &str) -> Option<usize> {
    let arc = manager_methods::get_context_arc(supervisor, context_id).ok()?;
    let ctx = arc.lock().await;
    Some(ctx.membership.count())
}

/// Returns `true` if the given DID is a member of the specified context.
///
/// Hoisted body of the legacy
/// [`ContextManager::is_member`](crate::context::supervisor::Supervisor::is_member)
/// (ADR-049 commit 12c.5). Byte-identical behavior.
pub async fn is_member(supervisor: &Supervisor, context_id: &str, did: &str) -> bool {
    let Ok(arc) = manager_methods::get_context_arc(supervisor, context_id) else {
        return false;
    };
    let ctx = arc.lock().await;
    ctx.membership.contains(did)
}

/// Returns all member DIDs for a context.
///
/// Hoisted body of the legacy
/// [`ContextManager::member_dids`](crate::context::supervisor::Supervisor::member_dids)
/// (ADR-049 commit 12c.5). Byte-identical behavior.
pub async fn member_dids(supervisor: &Supervisor, context_id: &str) -> Vec<String> {
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
///
/// Hoisted body of the legacy
/// [`ContextManager::member_role`](crate::context::supervisor::Supervisor::member_role)
/// (ADR-049 commit 12c.5). Byte-identical behavior.
pub async fn member_role(
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
///
/// Hoisted body of the legacy
/// [`ContextManager::context_params`](crate::context::supervisor::Supervisor::context_params)
/// (ADR-049 commit 12c.5). Byte-identical behavior.
pub async fn context_params(supervisor: &Supervisor, context_id: &str) -> Option<ContextParams> {
    let arc = manager_methods::get_context_arc(supervisor, context_id).ok()?;
    let ctx = arc.lock().await;
    Some(ctx.handle.params().clone())
}

/// Returns a clone of the role state for a context, or `None` if the
/// context is not registered.
///
/// Hoisted body of the legacy
/// [`ContextManager::get_role_state`](crate::context::supervisor::Supervisor::get_role_state)
/// (ADR-049 commit 12c.5). Byte-identical behavior.
pub async fn get_role_state(supervisor: &Supervisor, context_id: &str) -> Option<ContextRoleState> {
    let arc = manager_methods::get_context_arc(supervisor, context_id).ok()?;
    let ctx = arc.lock().await;
    Some(ctx.role_state.clone())
}

/// Returns a clone of the persistent MLS Commit retry queue for a context
/// (PR #1606 C6).
///
/// Hoisted body of the legacy
/// [`ContextManager::pending_commits`](crate::context::supervisor::Supervisor::pending_commits)
/// (ADR-049 commit 12c.5). Byte-identical behavior.
pub async fn pending_commits(supervisor: &Supervisor, context_id: &str) -> Vec<PendingCommit> {
    let Ok(arc) = manager_methods::get_context_arc(supervisor, context_id) else {
        return Vec::new();
    };
    let ctx = arc.lock().await;
    ctx.pending_commits.iter().cloned().collect()
}

/// Returns the active commit fault marker for a context, if any
/// (PR #1606 C6).
///
/// Hoisted body of the legacy
/// [`ContextManager::commit_fault`](crate::context::supervisor::Supervisor::commit_fault)
/// (ADR-049 commit 12c.5). Byte-identical behavior.
pub async fn commit_fault(supervisor: &Supervisor, context_id: &str) -> Option<CommitFaultMarker> {
    let arc = manager_methods::get_context_arc(supervisor, context_id).ok()?;
    let ctx = arc.lock().await;
    ctx.commit_fault.clone()
}

// ===========================================================================
// Receive buffer + degraded mode
// ===========================================================================

/// Drains all events from the receive buffer for a context.
///
/// Hoisted body of the legacy
/// [`ContextManager::drain_events`](crate::context::supervisor::Supervisor::drain_events)
/// (ADR-049 commit 12c.5). Byte-identical behavior.
pub async fn drain_events(supervisor: &Supervisor, context_id: &str) -> Vec<ContextEvent> {
    let Ok(arc) = manager_methods::get_context_arc(supervisor, context_id) else {
        return Vec::new();
    };
    let mut ctx = arc.lock().await;
    ctx.receive_buffer.drain()
}

/// Reports that a received envelope triggered degraded mode (§13.6) for a
/// context.
///
/// Hoisted body of the legacy
/// [`ContextManager::report_degraded_mode`](crate::context::supervisor::Supervisor::report_degraded_mode)
/// (ADR-049 commit 12c.5). Byte-identical behavior.
pub async fn report_degraded_mode(
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
// Event log passthrough
// ===========================================================================

/// Returns the Merkle event log entries for a context.
///
/// Hoisted body of the legacy
/// [`ContextManager::event_log_entries`](crate::context::supervisor::Supervisor::event_log_entries)
/// (ADR-049 commit 12c.5). Byte-identical behavior.
///
/// # Errors
///
/// Returns [`ContextError`] if the event log provider fails.
pub fn event_log_entries(
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
/// Hoisted body of the legacy
/// [`ContextManager::generate_context_access_key`](crate::context::queries_helpers::generate_context_access_key)
/// (ADR-049 commit 12c.5). Byte-identical behavior.
///
/// # Errors
///
/// - [`ContextError::ContextNotRegistered`] if the context is not
///   registered with this manager.
/// - [`ContextError::MemberNotFound`] if `member_did` is not a member
///   of the context.
pub async fn generate_context_access_key(
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
/// Hoisted body of the legacy
/// [`ContextManager::revoke_context_access_key`](crate::context::queries_helpers::revoke_context_access_key)
/// (ADR-049 commit 12c.5). Byte-identical behavior.
///
/// # Errors
///
/// - [`ContextError::ContextNotRegistered`] if the context is not
///   registered with this manager.
/// - [`ContextError::MemberNotFound`] if no access key exists for
///   `member_did` in the context.
pub async fn revoke_context_access_key(
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
/// Hoisted body of the legacy
/// [`ContextManager::restore_context_access_key`](crate::context::queries_helpers::restore_context_access_key)
/// (ADR-049 commit 12c.5). Byte-identical behavior.
///
/// # Errors
///
/// - [`ContextError::ContextNotRegistered`] if the context is not
///   registered with this manager.
/// - [`ContextError::MemberNotFound`] if `member_did` is not a member
///   of the context.
pub async fn restore_context_access_key(
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
///
/// Hoisted body of the legacy
/// [`ContextManager::set_access_key`](crate::context::supervisor::Supervisor::set_access_key)
/// (ADR-049 commit 12c.5). Byte-identical behavior.
pub async fn set_access_key(
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
///
/// Hoisted body of the legacy
/// [`ContextManager::remove_access_key`](crate::context::supervisor::Supervisor::remove_access_key)
/// (ADR-049 commit 12c.5). Byte-identical behavior.
pub async fn remove_access_key(supervisor: &Supervisor, context_id: &str, member_did: &str) {
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
///
/// Hoisted body of the legacy
/// `ContextManager::inject_access_key` (ADR-049 commit 12c.5).
/// Byte-identical behavior.
#[cfg(feature = "testing")]
pub async fn inject_access_key(
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
///
/// Hoisted body of the legacy
/// `ContextManager::get_access_key` (ADR-049 commit 12c.5).
/// Byte-identical behavior.
#[cfg(feature = "testing")]
pub async fn get_access_key(
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
///
/// Hoisted body of the legacy
/// `ContextManager::get_all_access_keys` (ADR-049 commit 12c.5).
/// Byte-identical behavior.
#[cfg(feature = "testing")]
pub async fn get_all_access_keys(
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
///
/// Hoisted body of the legacy
/// `ContextManager::grant_budget_for_test` (ADR-049 commit 12c.5).
/// Byte-identical behavior.
#[cfg(feature = "testing")]
pub async fn grant_budget_for_test(
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
///
/// Hoisted body of the legacy
/// `ContextManager::remaining_budget_for_test` (ADR-049 commit 12c.5).
/// Byte-identical behavior.
#[cfg(feature = "testing")]
pub async fn remaining_budget_for_test(
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
///
/// Hoisted body of the legacy
/// `ContextManager::velocity_for_test` (ADR-049 commit 12c.5).
/// Byte-identical behavior.
#[cfg(feature = "testing")]
pub async fn velocity_for_test(
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
/// Hoisted body of the legacy
/// [`ContextManager::create_checkpoint_if_due`](crate::context::supervisor::Supervisor::create_checkpoint_if_due)
/// (ADR-049 commit 12c.5). Byte-identical behavior.
///
/// A checkpoint is due when either:
/// - 50 events have been appended since the last checkpoint, or
/// - 10 minutes have elapsed since the last checkpoint.
#[allow(clippy::used_underscore_binding)] // `_expired` — legacy binding preserved
pub fn create_checkpoint_if_due(
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
    let events_due = ctx.checkpoint_events_since >= 50;
    // Time-based checkpoints require at least one event — creating a
    // checkpoint for zero events is wasteful and indistinguishable from
    // the previous checkpoint.
    let time_due =
        ctx.checkpoint_events_since > 0 && now.saturating_sub(ctx.checkpoint_last_time_secs) >= 600;

    if !events_due && !time_due {
        return None;
    }

    let cp = build_checkpoint(
        context_id,
        ctx,
        sender_did,
        signing_key,
        now,
        event_log.as_ref(),
    );

    ctx.checkpoint_events_since = 0;
    ctx.checkpoint_last_time_secs = now;
    ctx.checkpoints.push(cp.clone());

    if ctx.checkpoints.len() > MAX_RETAINED_CHECKPOINTS {
        ctx.checkpoints
            .drain(..ctx.checkpoints.len() - MAX_RETAINED_CHECKPOINTS);
    }

    tracing::debug!(
        context_id,
        event_count = cp.event_count,
        "consistency checkpoint created (§9.9.3)"
    );

    Some(cp)
}

/// Unconditionally creates a consistency checkpoint regardless of whether
/// the event/time thresholds have been reached.
///
/// Hoisted body of the legacy
/// [`ContextManager::force_create_checkpoint`](crate::context::supervisor::Supervisor::force_create_checkpoint)
/// (ADR-049 commit 12c.5). Byte-identical behavior.
pub fn force_create_checkpoint(
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
    let cp = build_checkpoint(
        context_id,
        ctx,
        sender_did,
        signing_key,
        now,
        event_log.as_ref(),
    );

    ctx.checkpoint_events_since = 0;
    ctx.checkpoint_last_time_secs = now;
    ctx.checkpoints.push(cp.clone());

    if ctx.checkpoints.len() > MAX_RETAINED_CHECKPOINTS {
        ctx.checkpoints
            .drain(..ctx.checkpoints.len() - MAX_RETAINED_CHECKPOINTS);
    }

    tracing::info!(
        context_id,
        event_count = cp.event_count,
        "forced final checkpoint on context close (§9.9.3)"
    );

    Some(cp)
}

/// Builds a signed checkpoint from the current event log and context state.
///
/// Hoisted body of the legacy private
/// `ContextManager::build_checkpoint` associated function (ADR-049
/// commit 12c.5). Pure function — no supervisor parameter; takes an
/// explicit `&dyn ContextEventLogProvider` reference since the caller
/// already dereferenced `supervisor.event_log_ref()`. Byte-identical
/// behavior.
fn build_checkpoint(
    context_id: &str,
    ctx: &PerContextState,
    sender_did: &DID,
    signing_key: &ed25519_dalek::SigningKey,
    now: u64,
    event_log: &dyn ContextEventLogProvider,
) -> scp_event_log::checkpoint::ConsistencyCheckpoint {
    let context_id_bytes = context_id_to_bytes(context_id);
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
    let epoch = if ctx.broadcast_context.is_none() {
        Some(ctx.epoch.mls_epoch)
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

/// Compares a remote checkpoint against local event log state for
/// equivocation detection (§9.9.3, ADR-011 AC-8).
///
/// Hoisted body of the legacy
/// [`ContextManager::compare_remote_checkpoint`](crate::context::supervisor::Supervisor::compare_remote_checkpoint)
/// (ADR-049 commit 12c.5). Byte-identical behavior.
///
/// # Errors
///
/// Returns [`ContextError::ContextNotRegistered`] if the context is
/// not registered.
/// Returns [`ContextError::MemberNotFound`] if the checkpoint sender
/// is not a member of the context.
/// Returns [`ContextError::CryptoFailed`] if the public key cannot be
/// resolved or the Ed25519 signature verification fails.
pub async fn compare_remote_checkpoint(
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
// Merkle tree synchronization
// ===========================================================================

/// Synchronizes the per-context Merkle tree with the `MerkleEventLogProvider`.
///
/// Hoisted body of the legacy private
/// `ContextManager::sync_merkle_tree` method (ADR-049 commit 12c.5).
/// Takes an explicit `&dyn ContextEventLogProvider` reference since the
/// caller already dereferenced `supervisor.event_log_ref()`. Byte-
/// identical behavior.
fn sync_merkle_tree(
    context_id: &str,
    ctx: &mut PerContextState,
    event_log: &dyn ContextEventLogProvider,
) {
    let context_id_bytes = context_id_to_bytes(context_id);
    // event_count returns u64; on 32-bit targets the log size is bounded
    // by available memory well below u32::MAX, so saturating is safe.
    let tree_count =
        usize::try_from(scp_event_log::tree::event_count(&ctx.merkle_tree)).unwrap_or(usize::MAX);

    if let Ok(Some(entries)) = event_log.event_log_entries(&context_id_bytes)
        && entries.len() > tree_count
    {
        // Replay missing entries. Each entry's pre-computed hash is
        // pushed as a raw leaf — the internal tree structure (RFC 6962
        // interior nodes) is rebuilt automatically by `push_leaf_raw`.
        for entry in entries.iter().skip(tree_count) {
            ctx.merkle_tree.push_leaf_raw(entry.hash);
        }
    }
}

// ===========================================================================
// Merkle proof operations (ADR-011, #1535)
// ===========================================================================

/// Returns a Merkle inclusion proof for the event at the given index
/// in the per-context RFC 6962 event log.
///
/// Hoisted body of the legacy
/// [`ContextManager::prove_event_inclusion`](crate::context::supervisor::Supervisor::prove_event_inclusion)
/// (ADR-049 commit 12c.5). Byte-identical behavior.
///
/// # Errors
///
/// Returns [`ContextError::ContextNotRegistered`] if the context is unknown.
/// Returns [`ContextError::EventLogFailed`] if the leaf index is out of
/// bounds or the log is empty.
pub async fn prove_event_inclusion(
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
    sync_merkle_tree(context_id, ctx, event_log.as_ref());
    scp_event_log::proof::prove_inclusion(&ctx.merkle_tree, leaf_index)
        .map_err(|e| ContextError::EventLogFailed(e.to_string()))
}

/// Returns a Merkle consistency proof between the tree at `old_size` and
/// the current tree size.
///
/// Hoisted body of the legacy
/// [`ContextManager::prove_event_consistency`](crate::context::supervisor::Supervisor::prove_event_consistency)
/// (ADR-049 commit 12c.5). Byte-identical behavior.
///
/// # Errors
///
/// Returns [`ContextError::ContextNotRegistered`] if the context is unknown.
/// Returns [`ContextError::EventLogFailed`] if `old_size` is 0, exceeds
/// the current size, or the log is empty.
pub async fn prove_event_consistency(
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
    sync_merkle_tree(context_id, ctx, event_log.as_ref());
    let current_size = scp_event_log::tree::event_count(&ctx.merkle_tree);
    scp_event_log::proof::prove_consistency(&ctx.merkle_tree, old_size, current_size)
        .map_err(|e| ContextError::EventLogFailed(e.to_string()))
}

/// Verifies a Merkle inclusion proof. Pure function — no state needed.
///
/// Hoisted body of the legacy
/// [`ContextManager::verify_event_inclusion`](crate::context::supervisor::Supervisor::verify_event_inclusion)
/// (ADR-049 commit 12c.5). Byte-identical behavior.
#[must_use]
pub fn verify_event_inclusion(proof: &scp_event_log::proof::InclusionProof) -> bool {
    scp_event_log::proof::verify_inclusion(proof)
}

/// Verifies a Merkle consistency proof. Pure function — no state needed.
///
/// Hoisted body of the legacy
/// [`ContextManager::verify_event_consistency`](crate::context::supervisor::Supervisor::verify_event_consistency)
/// (ADR-049 commit 12c.5). Byte-identical behavior.
#[must_use]
pub fn verify_event_consistency(proof: &scp_event_log::proof::ConsistencyProof) -> bool {
    scp_event_log::proof::verify_consistency(proof)
}
