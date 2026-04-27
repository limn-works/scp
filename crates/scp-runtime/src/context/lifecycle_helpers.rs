// Module-level allow — the legacy inherent-impl forms in
// `manager/lifecycle.rs` and `manager/`ttl_close`.rs` both carried
// `#[allow(clippy::significant_drop_tightening)]` on their impl blocks.
// The hoisted bodies preserve the same lock-hold-across-await patterns
// deliberately (narrowing changes lock-ordering semantics across the
// per-context mutex); allowing the lint crate-locally keeps the hoist
// byte-identical to the legacy behavior.
#![allow(clippy::significant_drop_tightening)]

//! Lifecycle + TTL / close helpers with explicit-collaborator signatures
//! (ADR-049 commit 12).
//!
//! # Purpose
//!
//! This module hoists the lifecycle- and `ttl_close`-domain methods that the
//! actor handlers in
//! [`crate::context::actor::handlers::lifecycle`] /
//! [`crate::context::actor::handlers::ttl_close`] currently reach via
//! `view.manager().X(...)`. After ADR-049 commit 12 (`ContextManager`
//! deletion) every helper takes `&Supervisor`; Phase 2 of the
//! post-review-round-1 plan will retarget the handler-side helpers to
//! `&mut PerContextState + &ActorDeps`.
//!
//! This file is the lifecycle / `ttl_close` counterpart to
//! [`crate::context::messaging_helpers`] (commits 12b.1, 12c.1, 12c.1b).
//!
//! # Behavior preservation
//!
//! Every hoisted free function is **behavior-preserving by construction**.
//! Its body is a verbatim copy of the legacy inherent method's body with
//! `self.X` replaced by either:
//!
//! - `manager_methods::X(supervisor, ...)` /
//!   `<domain>_helpers::X(supervisor, ...)` for the cross-domain and
//!   per-domain free-function helpers hoisted from `ContextManager` in
//!   ADR-049 commit 12c.9g.1 (helper bodies migrated to direct calls in
//!   commit 12c.9g.2; no `mgr` derivation), or
//! - `supervisor.X_ref().ok_or(NotInitialized)?` for provider slots
//!   lifted to the supervisor (`crypto`, `transport`, `event_log`,
//!   `clock`, `key_resolver`, `local_dids` — see ADR-049 commit
//!   12c.9a-9b).
//!
//! The legacy inherent methods on
//! [`Supervisor`](crate::context::supervisor::Supervisor) remain as
//! one-line forwarders; they are deleted alongside the outer shim in a
//! later ADR-049 commit when the actor handler bodies own the lifecycle
//! / `ttl_close` path directly.
//!
//! # Top-level methods hoisted (actor-handler entry points)
//!
//! *Lifecycle handlers:* [`create_context`], [`join_context`],
//! [`leave_context`], [`close_context`], [`export_context`],
//! [`import_context`].
//!
//! *TTL-close handlers:* [`start_ttl_timer`], [`propose_ttl_extension`],
//! [`reset_ttl_timer`], [`handle_ttl_expiry`], [`finalize_close`].
//!
//! # Domain-internal transitives hoisted
//!
//! Private methods invoked from the top-level bodies that live inside the
//! lifecycle / `ttl_close` domain:
//!
//! - [`close_context_with_key`] — full close body (the outer
//!   `close_context` is a one-arg forwarder into this).
//! - [`finalize_create`] — post-creation finalization (gauges, governance
//!   timeout, persistence, TTL timer).
//! - [`join_context_membership`] — Phase 4 membership mutations for
//!   `join_context`.
//! - [`capture_join_payment`] — Phase 5 escrow capture for
//!   `join_context`.
//! - [`spawn_ttl_timer`] — timer spawning + task-set registration.
//! - [`drain_and_deliver_sender_keys`] — sender-key distribution drain
//!   used by join / leave.
//!
//! Cross-domain infrastructure (`lock_context`, `relock_context`,
//! `insert_context`, `get_context_arc`, `persist_context_snapshot`,
//! `update_context_gauges`, `init_broadcast_context`,
//! `record_payment_capture_failure`) is reached via
//! [`crate::context::manager_methods`] free functions on `&Supervisor`.
//! Other domain helpers (`authorize_paid_action`, `void_paid_action`,
//! `complete_paid_action`, `try_broadcast_commit_or_enqueue`,
//! `start_governance_timeout_task`, `force_create_checkpoint`) live in
//! their respective `*_helpers` modules with the same supervisor-receiver
//! signature.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use scp_identity::DID;
use scp_protocol::context::builder::ContextCreationError;
use scp_protocol::context::governance::GovernanceModelConfig;
use scp_protocol::context::governance::mls_integration::EpochCoordinator;
use scp_protocol::context::membership::{ContextEvent, KeyPackage, MembershipState, ReceiveBuffer};
use scp_protocol::context::params::GovernanceModel;
use scp_protocol::context::roles::{self, Capability, CapabilityCeiling, ContextRoleState};
use scp_protocol::context::{ContextError, ContextParams, ContextState};
use scp_protocol::economy::budget::MemberBudgetTracker;

use crate::context::ContextHandle;
use crate::context::governance::timeout::{DeadlockDetectionState, GovernanceTimeoutTask};
use crate::context::governance_helpers;
use crate::context::manager_methods;
use crate::context::state::{
    self, AccessControlState, CommitOperation, EpochState, GovernanceState, PerContextState,
    TtlState,
};
use crate::context::supervisor::Supervisor;
use crate::context::ttl::{self, CloseResult, TtlExtension, TtlTimer};

/// Shared expectation message for `Supervisor::with_providers()`
/// inside helpers (ADR-049 commit 12).
// Phase 1 fix-up of ADR-049 (post-review-round-1): per-helper
// `ATTACHED_EXPECT` constants consolidated to the single
// `PROVIDER_NOT_INITIALIZED` definition in `manager_methods`. The
// alias keeps existing call sites intact while routing every emission
// through one canonical message.
use crate::context::manager_methods::PROVIDER_NOT_INITIALIZED as ATTACHED_EXPECT;

// ---------------------------------------------------------------------------
// 1. export_context (top-level)
// ---------------------------------------------------------------------------

/// Exports a context's full state as a transferable `ContextExport`
/// (hoisted body of the legacy
/// [`ContextManager::export_context`](crate::context::lifecycle_helpers::export_context)).
///
/// Captures a `ContextSnapshot`, event log data, and MLS state (empty
/// until #333 lands), then produces a signed export that can be imported
/// into another manager instance.
///
/// # Collaborators
///
/// - `mgr` — manager reference used to reach cross-domain `pub(crate)`
///   helpers (`get_context_arc`, `snapshot_context`) and provider
///   accessors (`event_log_ref`, `clock_ref`).
///
/// # Errors
///
/// Returns [`ContextError::MembershipFailed`] if the context is not
/// registered, or a transport-/persistence-level error from the
/// underlying event-log export.
pub async fn export_context(
    supervisor: &Supervisor,
    context_id: &str,
    exporter_did: DID,
) -> Result<crate::context::export_import::ContextExport, ContextError> {
    let ctx_id_bytes = scp_protocol::context::context_id_bytes(context_id);

    let snapshot = {
        let ctx_arc = manager_methods::get_context_arc(supervisor, context_id).map_err(|_| {
            ContextError::MembershipFailed(format!(
                "context '{context_id}' not found — cannot export"
            ))
        })?;
        let guard = ctx_arc.lock().await;
        let ctx = &*guard;
        manager_methods::snapshot_context(ctx)
    };

    let event_log_data = supervisor
        .event_log_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?
        .export_event_log_data(&ctx_id_bytes)
        .unwrap_or_default();

    // MLS state is empty until #333 (MLS integration) lands.
    let mls_state = Vec::new();

    crate::context::export_import::create_export(
        snapshot,
        event_log_data,
        mls_state,
        exporter_did,
        crate::context::export_import::ExportScope::Full,
        &**supervisor
            .clock_ref()
            .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?,
    )
}

// ---------------------------------------------------------------------------
// 2. import_context (top-level)
// ---------------------------------------------------------------------------

/// Imports a previously exported context into the manager (hoisted body of
/// the legacy
/// [`ContextManager::import_context`](crate::context::lifecycle_helpers::import_context)).
///
/// See the legacy method's doc comment for the full C3 per-instance wipe
/// policy, consequence-rule validation, and crypto-state restore
/// semantics. Byte-identical behavior.
#[allow(clippy::too_many_lines)] // Reimport guard adds 10 lines to an already-100-line function.
pub async fn import_context(
    supervisor: &Supervisor,
    export: crate::context::export_import::ContextExport,
) -> Result<ContextHandle, ContextError> {
    let crypto = supervisor
        .crypto_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let clock = supervisor
        .clock_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let key_resolver = supervisor
        .key_resolver_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let event_log = supervisor
        .event_log_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let next_generation = supervisor.next_generation_ref();
    // 1. Validate export.
    crate::context::export_import::validate_export_for_import(&export)?;
    // C3: Validate consequence rules on import. Uses
    // validate_against_config to enforce the opt-in gate for
    // RevokeAccess even on imported snapshots and rejects with the
    // canonical SCP-CTX-2092 envelope so SDK callers can detect
    // structural rejection by `.code` rather than message body.
    crate::context::lifecycle_logic::validate_consequence_rules_for_import(
        &export.snapshot.consequence_rules,
        &export.snapshot.context_params.consequence_config,
    )?;

    let context_id = export.snapshot.context_id.clone();
    let ctx_id_bytes = scp_protocol::context::context_id_bytes(&context_id);

    // 2. Check context existence BEFORE importing event log data.
    //    If the context is Active, we must reject early — otherwise the
    //    event log import at step 3 would overwrite the Active context's
    //    Merkle chain before we discover the conflict.
    {
        if let Ok(ctx_arc) = manager_methods::get_context_arc(supervisor, &context_id) {
            let existing = ctx_arc.lock().await;
            let is_replaceable = existing.handle.try_read_state().is_some_and(|s| {
                matches!(
                    s,
                    ContextState::Closing
                        | ContextState::Closed
                        | ContextState::Expired
                        | ContextState::Tombstoned
                )
            });
            if !is_replaceable {
                return Err(ContextError::MembershipFailed(format!(
                    "context '{context_id}' already exists — cannot import"
                )));
            }
            // §23.17 Invariant 3: capture per-sender epoch floors BEFORE
            // destroying crypto state so they can be validated against the
            // incoming snapshot (replay-based floor regression guard).
            let local_epoch_floors = crypto.export_sender_key_epochs(&ctx_id_bytes);

            // Clean up old crypto state before reimport.
            let _ = crypto.destroy_mls_group(&ctx_id_bytes);
            let _ = crypto.destroy_sender_key(&ctx_id_bytes);

            // Restore incoming crypto state (if the export carries any).
            if !export.mls_state.is_empty() {
                crypto
                    .restore_crypto_state(&ctx_id_bytes, &export.mls_state)
                    .map_err(|e| {
                        ContextError::PersistenceFailed(format!(
                            "import: crypto state restore failed: {e}"
                        ))
                    })?;
            }

            // §23.17 Invariant 3: validate that no per-sender epoch floor
            // regresses, and merge local floors back (max-merge) to preserve
            // Invariant 4.  On failure, roll back the restored crypto state.
            if let Err(e) = crypto.validate_and_merge_epoch_floors(
                &ctx_id_bytes,
                local_epoch_floors,
                crate::crypto::mls::provider::MAX_EPOCH_ADVANCE,
            ) {
                // Rollback: destroy the just-restored crypto state so the
                // provider is not left with partially-merged floors.
                let _ = crypto.destroy_mls_group(&ctx_id_bytes);
                let _ = crypto.destroy_sender_key(&ctx_id_bytes);
                return Err(e);
            }
        } else if !export.mls_state.is_empty() {
            // Fresh slot (no prior context): restore crypto state directly.
            // No local floors to defend — `validate_and_merge_epoch_floors`
            // is a no-op when `local_floors` is empty, so the ceiling guard
            // does not apply on this path. We still restore so MLS group
            // and sender keys are available immediately after import.
            crypto
                .restore_crypto_state(&ctx_id_bytes, &export.mls_state)
                .map_err(|e| {
                    ContextError::PersistenceFailed(format!(
                        "import: crypto state restore failed: {e}"
                    ))
                })?;
        }
    }
    // Lock dropped — safe to proceed with event log import.

    // 3. Import event log data if present.
    if !export.event_log_data.is_empty() {
        event_log.import_event_log_data(&ctx_id_bytes, &export.event_log_data)?;
    }

    // 4. Reconstruct the ContextHandle.
    let handle = ContextHandle::new(context_id.clone(), export.snapshot.context_params.clone());

    // Transition to the state from the snapshot.
    match &export.snapshot.state {
        ContextState::Active => {
            handle.transition_to(&ContextState::Active).await?;
        }
        ContextState::Creating => {
            // Already in Creating state, nothing to do.
        }
        other => {
            return Err(ContextError::InvalidState(format!(
                "cannot import context in {other} state — only Active and Creating are supported"
            )));
        }
    }

    // 5. Reconstruct governance engine from snapshot.
    let governance_engine =
        state::restore_governance_engine_from_snapshot(&export.snapshot, Arc::clone(key_resolver))?;

    // 6. Build PerContextState from the snapshot.
    let initial_members: HashSet<DID> = export
        .snapshot
        .membership
        .members()
        .map(|m| m.did.clone())
        .collect();

    // F6: Validate and sanitize persisted anti-spam snapshot state
    // BEFORE reconstructing the trackers. Tampered imports that
    // carry future timestamps (which would let a malicious sender
    // "pre-consume" future capacity) are rejected; stale entries
    // are clamped. Matches restore_context policy verbatim.
    let now_for_validation = clock.now_secs();
    let hrl_config = export
        .snapshot
        .hard_rate_limit_config
        .clone()
        .unwrap_or_else(scp_protocol::economy::antispam::HardRateLimitConfig::matrix_defaults);
    hrl_config.validate().map_err(|e| {
        ContextError::PersistenceFailed(format!(
            "import: hard-rate-limit config validation failed: {e}"
        ))
    })?;
    let mut hrl_state = export.snapshot.hard_rate_limit_state.clone();
    scp_protocol::economy::antispam::TokenBucketLimiter::validate_and_sanitize_snapshot(
        &mut hrl_state,
        &hrl_config,
        now_for_validation,
        scp_protocol::economy::antispam::SNAPSHOT_CLOCK_SKEW_TOLERANCE_SECS,
    )
    .map_err(|e| {
        ContextError::PersistenceFailed(format!(
            "import: hard-rate-limit snapshot validation failed: {e}"
        ))
    })?;
    let validated_velocity_tracker = match export.snapshot.velocity_tracker_state.clone() {
        Some(vts) => {
            let mut entries = vts.entries;
            scp_protocol::economy::antispam::SenderVelocityTracker::validate_and_sanitize_snapshot(
                &mut entries,
                60,
                now_for_validation,
                scp_protocol::economy::antispam::SNAPSHOT_CLOCK_SKEW_TOLERANCE_SECS,
            )
            .map_err(|e| {
                ContextError::PersistenceFailed(format!(
                    "import: velocity snapshot validation failed: {e}"
                ))
            })?;
            scp_protocol::economy::antispam::SenderVelocityTracker::from_snapshot(60, entries)
        }
        None => scp_protocol::economy::antispam::SenderVelocityTracker::new(60),
    };
    let validated_message_pricing = export.snapshot.message_pricing.clone().or_else(|| {
        crate::context::lifecycle_logic::derive_message_pricing(
            export.snapshot.economic_policy.as_ref(),
        )
    });
    if let Some(ref pricing) = validated_message_pricing {
        pricing.validate().map_err(|e| {
            ContextError::PersistenceFailed(format!(
                "import: message pricing config validation failed: {e}"
            ))
        })?;
    }

    // C3: Clamp imported `cooldown_until` to a bounded horizon and
    // drop entries with out-of-range rule indices, mirroring the
    // WASM bridge `validate_imported_snapshot` policy. Without
    // this, an attacker can ship `cooldown_until[i] = u64::MAX` and
    // permanently disable a consequence rule.
    let mut sanitized_cooldown_until = export.snapshot.cooldown_until.clone();
    crate::context::lifecycle_logic::sanitize_cooldown_until(
        &mut sanitized_cooldown_until,
        &export.snapshot.consequence_rules,
        now_for_validation,
        "import",
    );

    let per_context = PerContextState {
        generation: next_generation.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        handle: handle.clone(),
        membership: export.snapshot.membership,
        role_state: export.snapshot.role_state,
        receive_buffer: ReceiveBuffer::new(),
        broadcast_context: None,
        migration_state: None,
        governance: GovernanceState {
            engine: governance_engine,
            executed_proposals: {
                let now = clock.now_secs();
                export
                    .snapshot
                    .executed_proposals
                    .into_iter()
                    .map(|id| (id, now))
                    .collect()
            },
            // C3: Wipe `approved_proposals`. Importing the
            // exporter's approved-but-not-yet-executed proposals
            // lets a malicious snapshot pre-load forged
            // `RemoveMember` entries — `check_proposer_eligibility`
            // would then permanently block the victim from
            // proposing. The legitimate set is rebuilt from the
            // imported event log on next governance evaluation.
            // H10: Reset next_proposal_seq as well — the exporter
            // could carry an arbitrary value (e.g. u64::MAX) to
            // rewind the importing instance's seq space and
            // reintroduce collision windows. Since approved_proposals
            // is wiped, reset to 0.
            next_proposal_seq: 0,
            approved_proposals: HashMap::new(),
            freeze: export.snapshot.governance_freeze,
            timeout_task: GovernanceTimeoutTask::new(),
            deadlock: DeadlockDetectionState::default(),
            threshold_signers: export.snapshot.threshold_signers,
            threshold_value: export.snapshot.threshold_value,
            pending_ceiling_modification: export.snapshot.pending_ceiling_modification,
            pending_economic_policy_change: export.snapshot.pending_economic_policy_change,
            registered_tools: export.snapshot.registered_tools,
            tool_interfaces: export.snapshot.tool_interfaces,
            pruning_policy: export.snapshot.pruning_policy,
            message_pricing: validated_message_pricing,
            hard_rate_limit: scp_protocol::economy::antispam::TokenBucketLimiter::from_snapshot(
                hrl_config, hrl_state,
            ),
            economic_policy: export.snapshot.economic_policy,
            // C3: Wipe `budget_tracker`. Budgets are per-instance
            // economic grants from `ApproveSpend` actions; a peer
            // import that carried `budget_tracker` could pre-fund
            // any DID for arbitrary spend on the importing node.
            budget_tracker: scp_protocol::economy::budget::MemberBudgetTracker::new(),
            last_known_members: initial_members,
            pending_epoch_resets: Vec::new(),
            consequence_rules: export.snapshot.consequence_rules,
            velocity_tracker: validated_velocity_tracker,
            // C3: Wipe `participation_cache`. The cache is
            // rebuilt lazily from the imported event log on
            // next proposer-eligibility check (see
            // `check_proposer_eligibility`). Inheriting the
            // exporter's cache lets it forge low-participation
            // verdicts against any DID it picks.
            participation_cache: HashMap::new(),
            cooldown_until: sanitized_cooldown_until,
            // IMPORT path (not restore): start with a FRESH
            // spending-nonce tracker regardless of what the
            // export carries. Three reasons:
            //   1. Nonce tracker state is per-local-instance
            //      anti-replay state with no meaning in an
            //      inter-instance transfer.
            //   2. The exporter may be untrusted; a malicious
            //      export could pre-populate the tracker with
            //      up to `DEFAULT_MAX_CAPACITY` attacker-chosen
            //      entries, a DoS on local memory with no
            //      forgery benefit.
            //   3. The importing instance has not yet consumed
            //      any spending UCANs — a fresh tracker cannot
            //      reopen a replay window.
            // The public-scope stripper already applies this
            // invariant; full-scope import matches. The
            // `restore_context` local-reload path MUST still
            // rehydrate from `spending_nonce_tracker_state` —
            // this divergence is deliberate.
            spending_nonce_tracker: scp_protocol::crypto::ucan::nonce::NonceTracker::new(
                context_id.clone(),
                Arc::clone(clock),
            ),
            revoked_spending_ucan_cids: HashSet::new(),
            // C3: Wipe `proposal_timestamps`. Earned-capacity rate
            // limits (§9.3) are per-instance counters. Inheriting
            // the exporter's history lets it starve victims of
            // proposal slots — every imported timestamp is a free
            // bite out of the importing node's enforcement window.
            proposal_timestamps: HashMap::new(),
        },
        epoch: EpochState {
            mls_epoch: export.snapshot.mls_epoch,
            coordinator: EpochCoordinator::from_records(
                export.snapshot.epoch_coordination_records,
                &context_id,
            ),
            grace_store: crate::crypto::mls::epoch_grace::EpochGraceStore::new(),
            needs_reconnect: false,
        },
        access: AccessControlState {
            read_exclusion_list: export.snapshot.read_exclusion_list,
            access_key_store: export.snapshot.access_key_store,
        },
        ttl: TtlState {
            timer: TtlTimer::with_clock(Arc::clone(clock)),
            extension: None,
        },
        sequence_tracker: scp_protocol::envelope::SequenceTracker::new(),
        reorder_buffer: scp_protocol::envelope::ReorderBuffer::default(),
        // PR #1606 C6: import path starts with an empty commit retry
        // queue and no fail-close marker. Pending commits in the source
        // export are not portable across instances — they reference the
        // exporter's MLS state which is not transferred via import.
        pending_commits: VecDeque::new(),
        commit_fault: None,
        // Checkpoint tracking (§9.9.3): fresh counters for imported contexts.
        checkpoint_events_since: 0,
        checkpoint_last_time_secs: clock.now_secs(),
        checkpoints: Vec::new(),
        // Fresh Merkle tree for imported contexts. Proofs cover
        // post-import events only (same rationale as restore_context).
        merkle_tree: scp_event_log::EventLog::new(context_id.clone()),
        // §9.10.4: pseudonym state is local-instance — wiped on import.
        // The importing member must re-derive and re-announce.
        local_pseudonym: None,
        pseudonym_registry: HashMap::new(),
        // ADR-049 commit 8: fresh actor-shape tracker on import.
        send_tracker: crate::context::actor::SendSequenceTracker::new(),
    };

    // 7. Register the context.
    //    Phase 1 fix-up of ADR-049 (post-review-round-1): hold
    //    `supervisor.write_lock` across the replaceability re-check +
    //    `remove_context` + `insert_context` sequence. The previous
    //    structure dropped the per-context lock between `is_replaceable`
    //    and `remove_context`, leaving a TOCTOU window where a
    //    concurrent caller could insert an Active context that we then
    //    silently overwrote. The supervisor's `write_lock` serializes
    //    all writes to `contexts`, closing that window.
    //
    //    The per-context lock can stay scoped tight inside the
    //    replaceability check — `write_lock` provides the cross-context
    //    serialization that matters for the remove+insert atomicity.
    {
        let _write_guard = supervisor.write_lock.lock().await;
        if let Ok(ctx_arc) = manager_methods::get_context_arc(supervisor, &context_id) {
            let existing = ctx_arc.lock().await;
            let is_replaceable = existing.handle.try_read_state().is_some_and(|s| {
                matches!(
                    s,
                    ContextState::Closing
                        | ContextState::Closed
                        | ContextState::Expired
                        | ContextState::Tombstoned
                )
            });
            if !is_replaceable {
                return Err(ContextError::MembershipFailed(format!(
                    "context '{context_id}' was concurrently registered during import"
                )));
            }
            // Drop the per-context guard before the remove call; the
            // outer `write_lock` keeps the remove+insert atomic with
            // respect to other writers.
            drop(existing);
        }
        manager_methods::remove_context(supervisor, &context_id);
        manager_methods::insert_context(supervisor, context_id.clone(), per_context)
            .map_err(|e| ContextError::MembershipFailed(e.to_string()))?;
    }

    manager_methods::update_context_gauges(supervisor);

    // Start governance timeout task (ADR-031 §5).
    crate::context::governance_helpers::start_governance_timeout_task(supervisor, &context_id)
        .await;

    // 8. Persist if persistence is configured.
    if manager_methods::has_persistence(supervisor)
        && let Ok(ctx_arc) = manager_methods::get_context_arc(supervisor, &context_id)
    {
        let guard = ctx_arc.lock().await;
        let ctx = &*guard;
        let snap = manager_methods::snapshot_context(ctx);
        manager_methods::persist_context_snapshot(supervisor, &context_id, snap);
    }

    // 9. Re-spawn TTL timer if there was remaining TTL.
    if let Some(remaining_secs) = export.snapshot.ttl_remaining_secs {
        let duration = std::time::Duration::from_secs(remaining_secs);
        spawn_ttl_timer(supervisor, &context_id, duration, handle.clone()).await;
    }

    Ok(handle)
}

// ---------------------------------------------------------------------------
// 3. create_context (top-level)
// ---------------------------------------------------------------------------

/// Creates a new SCP context with the two-phase commit pattern (hoisted
/// body of the legacy
/// [`ContextManager::create_context`](crate::context::supervisor::Supervisor::create_context)).
///
/// See the legacy method's doc comment for the full semantics. Byte-
/// identical behavior.
#[allow(clippy::too_many_lines)] // Context creation initializes many subsystems including pseudonym routing.
pub async fn create_context(
    supervisor: &Supervisor,
    context_id: String,
    params: ContextParams,
    creator_did: DID,
    local_pseudonym: Option<[u8; 32]>,
) -> Result<ContextHandle, ContextCreationError> {
    let crypto = supervisor
        .crypto_ref()
        .ok_or_else(|| ContextCreationError::CreationFailed(ATTACHED_EXPECT.to_owned()))?;
    let transport = supervisor
        .transport_ref()
        .ok_or_else(|| ContextCreationError::CreationFailed(ATTACHED_EXPECT.to_owned()))?;
    let event_log = supervisor
        .event_log_ref()
        .ok_or_else(|| ContextCreationError::CreationFailed(ATTACHED_EXPECT.to_owned()))?;
    let clock = supervisor
        .clock_ref()
        .ok_or_else(|| ContextCreationError::CreationFailed(ATTACHED_EXPECT.to_owned()))?;
    let key_resolver = supervisor
        .key_resolver_ref()
        .ok_or_else(|| ContextCreationError::CreationFailed(ATTACHED_EXPECT.to_owned()))?;
    let next_generation = supervisor.next_generation_ref();
    // Defense-in-depth: verify creator's SDK version satisfies min_protocol_version.
    params.check_version_compatibility(scp_protocol::envelope::SCP_PROTOCOL_VERSION)?;
    state::validate_governance_model(&params.governance)?;
    crate::context::lifecycle_logic::validate_consequence_rules(
        &params.consequence_rules,
        &params.consequence_config,
    )?;
    scp_protocol::economy::policy::validate_economic_policy_metrics(
        params.economic_policy.as_ref(),
    )
    .map_err(|e| ContextCreationError::CreationFailed(e.to_string()))?;
    let governance_engine = state::create_governance_engine(
        &params.governance,
        &creator_did,
        Arc::clone(key_resolver),
    )?;
    let handle = crate::context::builder::create_context(
        context_id.clone(),
        params.clone(),
        crypto.as_ref(),
        transport.as_ref(),
        event_log.as_ref(),
        creator_did.as_ref(),
    )
    .await?;
    let ceiling = CapabilityCeiling::new(params.ceiling.iter().cloned());
    let role_state = ContextRoleState::new(&context_id, &*creator_did, ceiling, vec![], &**clock)
        .map_err(|e| ContextCreationError::CreationFailed(e.to_string()))?;
    let mut membership = MembershipState::new();
    let creator_tokens = role_state
        .assignments
        .get(creator_did.as_ref())
        .map(|a| a.tokens.clone())
        .unwrap_or_default();
    membership.add_member(creator_did.clone(), "admin".into(), creator_tokens);
    let broadcast_context =
        manager_methods::init_broadcast_context(supervisor, &context_id, &params, &creator_did)?;
    let (initial_threshold_signers, initial_threshold_value) = match &params.governance {
        GovernanceModel::Threshold { threshold, signers } => (signers.clone(), *threshold),
        _ => (Vec::new(), 0),
    };
    let initial_access_key_store = generate_initial_access_key_store(&context_id, &creator_did);
    let initial_members: HashSet<DID> = membership.members().map(|m| m.did.clone()).collect();
    let per_context = PerContextState {
        generation: next_generation.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        handle: handle.clone(),
        membership,
        governance: GovernanceState {
            engine: governance_engine,
            executed_proposals: HashMap::new(),
            approved_proposals: HashMap::new(),
            // H10: fresh contexts start with a zero monotonic counter.
            next_proposal_seq: 0,
            freeze: None,
            timeout_task: GovernanceTimeoutTask::new(),
            deadlock: DeadlockDetectionState::default(),
            threshold_signers: initial_threshold_signers,
            threshold_value: initial_threshold_value,
            pending_ceiling_modification: None,
            pending_economic_policy_change: None,
            registered_tools: Vec::new(),
            tool_interfaces: Vec::new(),
            pruning_policy: None,
            message_pricing: crate::context::lifecycle_logic::derive_message_pricing(
                params.economic_policy.as_ref(),
            ),
            hard_rate_limit: scp_protocol::economy::antispam::TokenBucketLimiter::new(
                scp_protocol::economy::antispam::HardRateLimitConfig::matrix_defaults(),
            ),
            economic_policy: params.economic_policy.clone(),
            budget_tracker: MemberBudgetTracker::new(),
            last_known_members: initial_members,
            pending_epoch_resets: Vec::new(),
            consequence_rules: params.consequence_rules.clone(),
            velocity_tracker: scp_protocol::economy::antispam::SenderVelocityTracker::new(60),
            participation_cache: HashMap::new(),
            cooldown_until: HashMap::new(),
            spending_nonce_tracker: scp_protocol::crypto::ucan::nonce::NonceTracker::new(
                context_id.clone(),
                Arc::clone(clock),
            ),
            revoked_spending_ucan_cids: HashSet::new(),
            proposal_timestamps: HashMap::new(),
        },
        role_state,
        receive_buffer: ReceiveBuffer::new(),
        broadcast_context,
        migration_state: None,
        epoch: EpochState {
            mls_epoch: 0,
            coordinator: EpochCoordinator::new(),
            grace_store: crate::crypto::mls::epoch_grace::EpochGraceStore::new(),
            needs_reconnect: false,
        },
        access: AccessControlState {
            read_exclusion_list: HashSet::new(),
            access_key_store: initial_access_key_store,
        },
        ttl: TtlState {
            timer: TtlTimer::with_clock(Arc::clone(clock)),
            extension: None,
        },
        sequence_tracker: scp_protocol::envelope::SequenceTracker::new(),
        reorder_buffer: scp_protocol::envelope::ReorderBuffer::default(),
        // PR #1606 C6: fresh contexts start with an empty commit retry
        // queue and no fail-close marker.
        pending_commits: VecDeque::new(),
        commit_fault: None,
        // Checkpoint tracking (§9.9.3): fresh counters for new contexts.
        checkpoint_events_since: 0,
        checkpoint_last_time_secs: clock.now_secs(),
        checkpoints: Vec::new(),
        merkle_tree: scp_event_log::EventLog::new(context_id.clone()),
        // §9.10.4: pseudonym routing. Only meaningful for encrypted
        // contexts; broadcast contexts ignore this field.
        local_pseudonym,
        pseudonym_registry: HashMap::new(),
        // ADR-049 commit 8: fresh actor-shape tracker at creation.
        send_tracker: crate::context::actor::SendSequenceTracker::new(),
    };

    // Atomic check-and-insert — eliminates TOCTOU race between
    // contains_key and insert.
    manager_methods::insert_context(supervisor, context_id.clone(), per_context)?;
    finalize_create(supervisor, &context_id, params.ttl, &handle).await;
    Ok(handle)
}

// ---------------------------------------------------------------------------
// 4. finalize_create (transitive of create_context)
// ---------------------------------------------------------------------------

/// Post-creation finalization: gauges, governance timeout, persistence,
/// TTL timer (hoisted body of the legacy
/// `ContextManager::finalize_create`).
pub async fn finalize_create(
    supervisor: &Supervisor,
    context_id: &str,
    ttl_duration: Option<std::time::Duration>,
    handle: &ContextHandle,
) {
    manager_methods::update_context_gauges(supervisor);
    crate::context::governance_helpers::start_governance_timeout_task(supervisor, context_id).await;
    manager_methods::persist_context_and_broadcast(supervisor, context_id).await;
    if let Some(duration) = ttl_duration {
        spawn_ttl_timer(supervisor, context_id, duration, handle.clone()).await;
    }
}

// ---------------------------------------------------------------------------
// 5. generate_initial_access_key_store (transitive of create_context)
// ---------------------------------------------------------------------------

/// Generates the initial access key store for context creation (§9.17.2).
/// Hoisted from the legacy private associated function
/// `ContextManager::generate_initial_access_key_store`.
fn generate_initial_access_key_store(
    context_id: &str,
    creator_did: &DID,
) -> scp_protocol::crypto::access_keys::AccessKeyStore {
    let mut store = scp_protocol::crypto::access_keys::AccessKeyStore::new();
    let key =
        scp_protocol::crypto::access_keys::generate_access_key(context_id, creator_did.as_ref());
    store.set(context_id, creator_did.as_ref(), key);
    store
}

// ---------------------------------------------------------------------------
// 6. join_context (top-level)
// ---------------------------------------------------------------------------

/// Joins a member to a context (hoisted body of the legacy
/// [`ContextManager::join_context`](crate::context::supervisor::Supervisor::join_context)).
///
/// Validates the joiner's key package, performs the F4 escrow dance
/// (economy + sybil + hard-rate-limit under lock, then authorize,
/// MLS add, sender-key distribute, membership mutate, capture),
/// and appends a `MemberJoined` event. Byte-identical to the legacy
/// method form.
#[allow(clippy::too_many_lines)]
pub async fn join_context(
    supervisor: &Supervisor,
    handle: &ContextHandle,
    key_package: KeyPackage,
    spending_ucan: Option<&scp_protocol::crypto::ucan::UcanToken>,
    local_pseudonym: Option<[u8; 32]>,
) -> Result<(), ContextError> {
    let crypto = supervisor
        .crypto_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let clock = supervisor
        .clock_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let key_resolver = supervisor
        .key_resolver_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let event_log = supervisor
        .event_log_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let context_id = handle.context_id().to_owned();
    let context_id_bytes = state::context_id_to_bytes(&context_id);
    let member_did = key_package.owner_did.clone();

    // Fast-fail: reject obviously incompatible versions before expensive
    // crypto ops (MLS group join, sender key derivation). Looks up the
    // stored context's params (not the caller-supplied handle params)
    // so this check is authoritative even when the caller passes an
    // ephemeral handle with default params (e.g. UniFFI bridge).
    {
        let ctx_arc = manager_methods::get_context_arc(supervisor, &context_id)
            .map_err(|_| ContextError::ContextNotRegistered(context_id.clone()))?;
        let guard = ctx_arc.lock().await;
        let ctx = &*guard;
        ctx.handle
            .params()
            .check_version_compatibility(scp_protocol::envelope::SCP_PROTOCOL_VERSION)?;
    }

    // Validate key package before any mutations (idempotent, no lock needed).
    let kp_bytes = key_package.mls_key_package_bytes.as_deref();
    crypto.validate_key_package(&member_did, kp_bytes)?;

    // Phase 1: Economy enforcement + sybil check under lock (budget deduction).
    // This happens BEFORE any crypto mutations so that a rejected payment
    // never grants MLS group access or sender keys.
    // Capture generation for confused-deputy detection on rollback reacquire.
    let (ticket, ctx_gen) = {
        let (mut guard, ctx_gen) = manager_methods::lock_context(supervisor, &context_id)
            .await
            .map_err(|_| ContextError::ContextNotRegistered(context_id.clone()))?;
        let ctx = &mut *guard;

        // State check inside lock -- eliminates TOCTOU race.
        state::require_active(&ctx.handle)?;

        // Defense-in-depth: re-check version compatibility under the
        // mutation lock. The early check above uses a separate lock
        // acquisition, so governance could theoretically change the
        // min_protocol_version between the two. This eliminates that
        // TOCTOU window.
        ctx.handle
            .params()
            .check_version_compatibility(scp_protocol::envelope::SCP_PROTOCOL_VERSION)?;

        // Economy enforcement (#1537, #1593) — auto-accept guard + join cost + spending UCAN.
        // Budget deduction happens here. The adapter escrow (authorize/complete/void)
        // runs after the lock is dropped. On adapter failure, the F4 EconomyTicket
        // rollback restores the deducted amount AND the velocity+hard-rate state.
        // M13: Sybil resistance check BEFORE economy enforcement so that
        // a rejected sybil attacker doesn't consume budget. Fail-closed.
        crate::context::lifecycle_logic::evaluate_sybil_resistance(
            ctx,
            &member_did,
            clock.now_secs(),
        )?;

        // Defense-in-depth hard rate limit on joins (Matrix-style token
        // bucket). On any subsequent failure we refund the token.
        let now_secs = clock.now_secs();
        if !ctx
            .governance
            .hard_rate_limit
            .try_consume(&member_did, now_secs)
        {
            return Err(ContextError::RateLimited {
                resource: "join".to_owned(),
                message: "hard rate limit exceeded for joiner".to_owned(),
            });
        }
        // Record the join in the velocity tracker so subsequent §19.7
        // escalation observes the same activity surface as message sends.
        // F5: capture the rollback token so a join failure refunds
        // THIS entry specifically rather than racing concurrent joiners.
        let velocity_token = ctx
            .governance
            .velocity_tracker
            .record_message(&member_did, now_secs);

        let deducted_cost = match crate::context::lifecycle_logic::enforce_join_economy(
            ctx,
            &member_did,
            now_secs,
            spending_ucan,
            &context_id,
            &**clock,
            key_resolver,
        ) {
            Ok(cost) => cost,
            Err(e) => {
                // No ticket exists yet — roll back inline under lock.
                ctx.governance
                    .velocity_tracker
                    .rollback(&member_did, velocity_token);
                ctx.governance.hard_rate_limit.refund(&member_did);
                return Err(e);
            }
        };
        // F4: wrap the Phase 1 state in an EconomyTicket so every
        // downstream error path (adapter, MLS, sender-key) is forced
        // to roll back velocity + hard_rate_limit + budget, not just
        // the budget.
        (
            crate::context::economy_logic::EconomyTicket {
                actor_did: member_did.clone(),
                deducted_cost,
                velocity_token,
                needs_hard_rate_limit_refund: true,
                consumed: false,
            },
            ctx_gen,
        )
    };

    // Phase 2: Authorize payment (escrow hold) BEFORE any crypto mutation.
    // If authorization fails, rollback the ticket — no MLS state was touched.
    let auth = match crate::context::economy_helpers_legacy::authorize_paid_action_legacy(
        supervisor,
        scp_protocol::economy::types::PaidActionType::ContextJoin,
        &member_did,
        &context_id,
    )
    .await
    {
        Ok(auth) => auth,
        Err(payment_err) => {
            crate::context::economy_logic::rollback_economy_ticket(
                supervisor,
                &context_id,
                ticket,
                &ctx_gen,
            )
            .await;
            return Err(payment_err);
        }
    };

    // Phase 3: MLS add_member + sender key distribution (crypto mutations).
    // On failure: void escrow + rollback ticket. No MLS rollback needed
    // because add_member itself failed (no state change occurred).
    let add_output = match crypto.add_member(&context_id_bytes, &member_did, kp_bytes) {
        Ok(output) => output,
        Err(e) => {
            if let Some(a) = auth {
                crate::context::economy_helpers_legacy::void_paid_action_legacy(
                    supervisor,
                    a,
                    &context_id,
                )
                .await;
            }
            crate::context::economy_logic::rollback_economy_ticket(
                supervisor,
                &context_id,
                ticket,
                &ctx_gen,
            )
            .await;
            return Err(e);
        }
    };

    if let Err(e) = crypto.distribute_sender_key(&context_id_bytes, &member_did) {
        // Sender key distribution failed after MLS add — rollback MLS state.
        let _ = crypto.remove_member(&context_id_bytes, &member_did);
        let _ = crypto.remove_member_sender_key(&context_id_bytes, &member_did);
        if let Some(a) = auth {
            crate::context::economy_helpers_legacy::void_paid_action_legacy(
                supervisor,
                a,
                &context_id,
            )
            .await;
        }
        crate::context::economy_logic::rollback_economy_ticket(
            supervisor,
            &context_id,
            ticket,
            &ctx_gen,
        )
        .await;
        return Err(e);
    }

    // Drain pending HPKE-sealed sender key distribution messages and
    // deliver them via the MLS management channel (§9.16.2).
    //
    // CRITICAL: distributions MUST be MLS-wrapped via
    // `mls_encrypt_management` so the receive-side dispatcher
    // (`decrypt_and_dispatch`) recognizes them as
    // `OpenResult::Management` and routes them through
    // `process_incoming_sender_key`. Sending the raw HPKE-sealed
    // bytes via `transport.send_message` would fail to deserialize
    // as an `OuterEnvelope` on the joiner side, causing silent
    // distribution loss (recoverable only via `SenderKeyRequest`).
    //
    // Helper semantics (matches the rotation path used by
    // `execute_remove_member`, `leave_context`, and `execute_rotate_content_keys`):
    //   - Drain failure (catastrophic, e.g. lock poisoned) → propagated
    //     and forces full rollback below.
    //   - Per-target encrypt/send failure → warned and continued. The
    //     joiner falls back to `SenderKeyRequest` to recover the key.
    //
    // Ordering invariant: this point is reached AFTER `add_member`
    // has merged the pending Commit on the inviter side, so the
    // inviter's MLS group already includes the new joiner in the
    // post-add epoch. The joiner can decrypt this management message
    // once they process the Welcome (delivered out-of-band via the
    // `WelcomeGenerated` event). If the joiner receives the
    // management message before the Welcome, their `crypto.open()`
    // call fails to decrypt and the `SenderKeyRequest` fallback
    // recovers the key.
    if let Err(e) = drain_and_deliver_sender_keys(supervisor, &context_id, &context_id_bytes) {
        // Drain failed catastrophically — roll back MLS state, sender
        // key, escrow, and economy ticket so the join is fully aborted.
        let _ = crypto.remove_member(&context_id_bytes, &member_did);
        let _ = crypto.remove_member_sender_key(&context_id_bytes, &member_did);
        if let Some(a) = auth {
            crate::context::economy_helpers_legacy::void_paid_action_legacy(
                supervisor,
                a,
                &context_id,
            )
            .await;
        }
        crate::context::economy_logic::rollback_economy_ticket(
            supervisor,
            &context_id,
            ticket,
            &ctx_gen,
        )
        .await;
        return Err(e);
    }

    // Phase 4: Membership mutation under lock. On failure: void escrow +
    // rollback ticket + rollback MLS state.
    if let Err(e) = join_context_membership(supervisor, &context_id, &member_did, add_output).await
    {
        let _ = crypto.remove_member(&context_id_bytes, &member_did);
        let _ = crypto.remove_member_sender_key(&context_id_bytes, &member_did);
        if let Some(a) = auth {
            crate::context::economy_helpers_legacy::void_paid_action_legacy(
                supervisor,
                a,
                &context_id,
            )
            .await;
        }
        crate::context::economy_logic::rollback_economy_ticket(
            supervisor,
            &context_id,
            ticket,
            &ctx_gen,
        )
        .await;
        return Err(e);
    }

    // Phase 4.5: Store local pseudonym after membership mutation succeeds.
    // The pseudonym was pre-derived by the FFI bridge; storing it here
    // makes it available for subsequent send_message fan-out (§9.10.4).
    if let Some(pseudonym) = local_pseudonym
        && let Ok(ctx_arc) = manager_methods::get_context_arc(supervisor, &context_id)
    {
        let mut guard = ctx_arc.lock().await;
        let ctx = &mut *guard;
        ctx.local_pseudonym = Some(pseudonym);
    }

    // Phase 5: Capture the escrow hold after all mutations succeeded.
    // Consume the ticket — commit returns the deducted cost for the
    // capture step and marks the ticket as committed so the Drop
    // guard stays quiet.
    let deducted_cost = crate::context::economy_logic::commit_economy_ticket(ticket);
    capture_join_payment(supervisor, auth, &member_did, &context_id, deducted_cost).await;

    // Append MemberJoined event to event log.
    event_log.append_context_event(&context_id_bytes, "MemberJoined", member_did.as_ref())?;
    {
        if let Ok(ctx_arc) = manager_methods::get_context_arc(supervisor, &context_id) {
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;
            ctx.checkpoint_events_since += 1;
        }
    }
    // Persist context state after join (best-effort).
    if manager_methods::has_persistence(supervisor)
        && let Ok(ctx_arc) = manager_methods::get_context_arc(supervisor, &context_id)
    {
        let guard = ctx_arc.lock().await;
        let ctx = &*guard;
        let snapshot = manager_methods::snapshot_context(ctx);
        manager_methods::persist_context_snapshot(supervisor, &context_id, snapshot);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// 7. join_context_membership (transitive of join_context)
// ---------------------------------------------------------------------------

/// Performs the membership state mutations for `join_context` (Phase 4)
/// — hoisted body of the legacy `ContextManager::join_context_membership`.
pub async fn join_context_membership(
    supervisor: &Supervisor,
    context_id: &str,
    member_did: &DID,
    add_output: scp_protocol::context::builder::AddMemberOutput,
) -> Result<(), ContextError> {
    let clock = supervisor
        .clock_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let event_log = supervisor
        .event_log_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let ctx_arc = manager_methods::get_context_arc(supervisor, context_id)
        .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
    let mut guard = ctx_arc.lock().await;
    let ctx = &mut *guard;

    state::require_active(&ctx.handle)?;

    crate::context::lifecycle_logic::post_join_bookkeeping(
        ctx,
        context_id,
        member_did,
        clock.now_secs(),
        event_log.as_ref(),
    );

    // Add member to role state.
    ctx.role_state.members.insert(member_did.to_string());

    // Assign default "member" role.
    //
    // H2 (related): Use system_assign_role to bypass the RoleAssign
    // capability check. The join handshake is a self-service flow that
    // already passed economy / sybil / capacity / version gates above —
    // re-checking `RoleAssign` against the creator would silently fail
    // every join after the creator has been demoted out of an admin
    // role. The default "member" role assignment carries no ambient
    // authority (it's the protocol-defined floor), so there is nothing
    // to authorize a second time. See `enforce_assign_role` and the
    // governance dispatch path in governance.rs for the same pattern.
    let creator_did = ctx.role_state.creator_did.clone();
    let tokens = roles::system_assign_role(&mut ctx.role_state, member_did, "member", &**clock)
        .map_err(|e| ContextError::MembershipFailed(e.to_string()))?;

    // Add to membership tracking.
    ctx.membership
        .add_member(member_did.clone(), "member".into(), tokens);

    // Generate access key for the new member (§9.17.2 step 2).
    // The inviter stores the key so `send_message` can wrap content
    // for this recipient. Key distribution to the joiner happens
    // via the Welcome payload / out-of-band key exchange.
    let member_access_key =
        scp_protocol::crypto::access_keys::generate_access_key(context_id, member_did);
    ctx.access
        .access_key_store
        .set(context_id, member_did, member_access_key);

    // Emit MemberJoined event to receive buffer.
    let join_event = ContextEvent::MemberJoined {
        member_did: member_did.clone(),
        role_name: "member".into(),
    };
    ctx.emit_event(join_event, context_id, supervisor.event_tx_ref());

    // Emit WelcomeGenerated event if the add produced a Welcome message.
    state::push_welcome_event(
        ctx,
        context_id,
        &DID(creator_did),
        member_did,
        add_output,
        supervisor.event_tx_ref(),
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// 8. capture_join_payment (transitive of join_context)
// ---------------------------------------------------------------------------

/// Captures the escrow hold after a successful join (Phase 5 of
/// `join_context`) — hoisted body of the legacy
/// `ContextManager::capture_join_payment`.
pub async fn capture_join_payment(
    supervisor: &Supervisor,
    auth: Option<crate::context::economy_logic::PaidActionAuthorization>,
    member_did: &DID,
    context_id: &str,
    deducted_cost: Option<scp_protocol::economy::types::Amount>,
) {
    if let Some(a) = auth
        && let Err(e) = crate::context::economy_helpers_legacy::complete_paid_action_legacy(
            supervisor, a, member_did, context_id,
        )
        .await
    {
        // H8: do NOT rollback budget — service was delivered (member joined).
        tracing::warn!(
            context_id,
            "payment capture failed after successful join: {e}"
        );
        // H19: append durable audit record to event log + receive buffer.
        manager_methods::record_payment_capture_failure(
            supervisor,
            context_id,
            "join_context",
            member_did,
            &e.to_string(),
            deducted_cost,
        )
        .await;
    }
}

// ---------------------------------------------------------------------------
// 9. leave_context (top-level)
// ---------------------------------------------------------------------------

/// Removes a member from a context (hoisted body of the legacy
/// [`ContextManager::leave_context`](crate::context::supervisor::Supervisor::leave_context)).
///
/// Self-removal is always permitted; otherwise requires `MemberRemove`
/// capability. Performs MLS `remove_member` (hard security boundary)
/// then sender-key cleanup (best-effort), broadcasts the resulting
/// Commit, rotates the sender key, and appends a `MemberLeft` event.
/// Byte-identical to the legacy method.
#[allow(clippy::too_many_lines)]
pub async fn leave_context(
    supervisor: &Supervisor,
    handle: &ContextHandle,
    caller_did: &DID,
    member_did: &DID,
) -> Result<(), ContextError> {
    let crypto = supervisor
        .crypto_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let event_log = supervisor
        .event_log_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let context_id = handle.context_id().to_owned();
    let context_id_bytes = state::context_id_to_bytes(&context_id);

    // Determine broadcast mode + authorization in a single lock acquire.
    // PR #1606 C6: also check the commit fault marker so a fail-closed
    // context refuses further leave operations until an operator
    // acknowledges the fault.
    // Use lock_context to capture a generation token for confused-deputy
    // detection in subsequent lock scopes (Phase B).
    let (is_broadcast, ctx_gen) = {
        let (guard, generation) = manager_methods::lock_context(supervisor, &context_id).await?;
        let ctx = &*guard;
        // Authorization: self-removal always allowed; otherwise MemberRemove required.
        if caller_did != member_did
            && !ctx
                .role_state
                .member_has_capability(caller_did, &Capability::MemberRemove)
        {
            return Err(ContextError::PermissionDenied(
                "caller lacks permission to remove this member".into(),
            ));
        }
        governance_helpers::check_commit_fault(ctx)?;
        (ctx.broadcast_context.is_some(), generation)
    };

    // Crypto operations -- no lock held. Skip for broadcast mode (no MLS).
    // H9: MLS group removal FIRST (hard security boundary), then sender
    // key cleanup as best-effort. MLS removal is the cryptographic
    // enforcement; sender key removal is defense-in-depth (§9.16).
    if !is_broadcast {
        let remove_output = crypto.remove_member(&context_id_bytes, member_did)?;
        if let Err(e) = crypto.remove_member_sender_key(&context_id_bytes, member_did) {
            tracing::warn!(
                context_id = %context_id,
                member = %member_did,
                error = %e,
                "remove_member_sender_key failed after MLS removal — \
                 sender key layer may retain stale key"
            );
        }

        // Broadcast the MLS Commit to remaining members so they can
        // advance their group epoch and ratchet key material. PR #1606 C6:
        // on transport failure, the commit is durably enqueued for retry.
        crate::context::governance_helpers::try_broadcast_commit_or_enqueue(
            supervisor,
            &context_id,
            remove_output.commit_bytes,
            CommitOperation::LeaveContext {
                member_did: member_did.clone(),
            },
            member_did.as_ref(),
        )
        .await?;

        // Rotate the local sender key and distribute to remaining members (§9.16.4).
        // M23: Non-fatal — MLS removal above is the hard security boundary.
        // If rotation fails, log but continue: returning Err here would leave
        // the system inconsistent (MLS removed, but caller thinks leave failed).
        if let Err(e) = crypto.rotate_sender_key(&context_id_bytes) {
            tracing::warn!(
                context_id = %context_id,
                error = %e,
                "rotate_sender_key failed after leave — \
                 remaining members retain old sender key"
            );
        }
        if let Err(e) = drain_and_deliver_sender_keys(supervisor, &context_id, &context_id_bytes) {
            tracing::warn!(
                context_id = %context_id,
                error = %e,
                "failed to deliver rotated sender keys after leave"
            );
        }
    }

    // Atomic state check + membership removal + count check within single lock.
    // Use relock_context for generation verification (Phase B).
    let should_close = {
        let mut guard = manager_methods::relock_context(supervisor, &ctx_gen).await?;
        let ctx = &mut *guard;

        // State check inside lock -- eliminates TOCTOU race.
        state::require_active(&ctx.handle)?;

        // For broadcast contexts, unsubscribe from the BroadcastContext.
        // rotate_keys=true for forward secrecy after departure.
        if let Some(ref mut bc) = ctx.broadcast_context {
            // Ignore MemberNotFound -- the member may be an author who was
            // never a subscriber. Propagate all other errors (e.g.
            // CryptoFailed from epoch overflow during key rotation).
            match bc.unsubscribe(member_did, true) {
                Ok(_) | Err(ContextError::MemberNotFound(_)) => {}
                Err(e) => return Err(e),
            }
        }

        if !ctx.membership.remove_member(member_did) {
            return Err(ContextError::MemberNotFound(member_did.to_string()));
        }

        // Remove from role state.
        ctx.role_state.members.remove(member_did.as_ref());
        ctx.role_state.assignments.remove(member_did.as_ref());
        ctx.role_state
            .member_capabilities
            .remove(member_did.as_ref());

        // Destroy the departing member's access key (§9.17.2, ADR-038).
        ctx.access
            .access_key_store
            .remove(&context_id, member_did.as_ref());

        // §9.10.4: remove the departing member's pseudonym routing ID.
        ctx.pseudonym_registry.remove(member_did);

        // Emit MemberLeft event to receive buffer.
        let left_event = ContextEvent::MemberLeft {
            member_did: member_did.clone(),
        };
        ctx.emit_event(left_event, &context_id, supervisor.event_tx_ref());

        ctx.membership.count() == 0
    };
    // Lock dropped.

    // Append MemberLeft event to event log.
    event_log.append_context_event(&context_id_bytes, "MemberLeft", member_did.as_ref())?;
    // Use relock_context for generation verification (Phase B).
    if let Ok(mut guard) = manager_methods::relock_context(supervisor, &ctx_gen).await {
        let ctx = &mut *guard;
        ctx.checkpoint_events_since += 1;
    } else {
        tracing::warn!(
            context_id = %context_id,
            "leave_context: generation mismatch — checkpoint counter not incremented"
        );
    }
    // Persist context state after leave (best-effort).
    if manager_methods::has_persistence(supervisor)
        && let Ok(guard) = manager_methods::relock_context(supervisor, &ctx_gen).await
    {
        let ctx = &*guard;
        let snapshot = manager_methods::snapshot_context(ctx);
        manager_methods::persist_context_snapshot(supervisor, &context_id, snapshot);
    }

    // If member count reaches zero, transition to Closing.
    if should_close {
        handle.transition_to(&ContextState::Closing).await?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// 10. drain_and_deliver_sender_keys (transitive of join / leave)
// ---------------------------------------------------------------------------

/// Drains pending sender key distribution messages and delivers them via
/// transport (§9.16.2). Hoisted body of the legacy
/// `ContextManager::drain_and_deliver_sender_keys`.
pub fn drain_and_deliver_sender_keys(
    supervisor: &Supervisor,
    context_id: &str,
    context_id_bytes: &[u8; 32],
) -> Result<(), ContextError> {
    let crypto = supervisor
        .crypto_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let transport = supervisor
        .transport_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let pending = crypto.drain_pending_sender_key_messages(context_id_bytes)?;
    if !pending.is_empty() {
        let routing_id = scp_protocol::context::context_routing_id(context_id);
        for (target_did, message) in pending {
            tracing::debug!(
                target_did = %target_did,
                context_id = %context_id,
                message_len = message.len(),
                "MLS-encrypting and sending rotated sender key distribution"
            );
            match crypto.mls_encrypt_management(
                context_id_bytes,
                &message,
                &routing_id,
                crate::context::messaging_helpers::DEFAULT_BLOB_TTL_SECS,
            ) {
                Ok(sealed) => {
                    if let Err(e) = transport.send_message(&routing_id, &sealed) {
                        tracing::warn!(target_did = %target_did, context_id = %context_id, error = %e, "failed to send rotated sender key");
                    }
                }
                Err(e) => {
                    tracing::warn!(target_did = %target_did, context_id = %context_id, error = %e, "MLS encryption of sender key distribution failed");
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 11. close_context (top-level, forwarder into close_context_with_key)
// ---------------------------------------------------------------------------

/// Initiates cooperative context closure (hoisted body of the legacy
/// [`ContextManager::close_context`](crate::context::lifecycle_helpers::close_context)).
///
/// For `SingleAdmin` governance: delegates to [`close_context_with_key`]
/// with no signing key. Multi-admin contexts are rejected — they must
/// route through the governance path.
pub async fn close_context(
    supervisor: &Supervisor,
    handle: &ContextHandle,
    initiator_did: &DID,
) -> Result<CloseResult, ContextError> {
    close_context_with_key(supervisor, handle, initiator_did, None).await
}

// ---------------------------------------------------------------------------
// 12. close_context_with_key (transitive of close_context)
// ---------------------------------------------------------------------------

/// Closes a context with an optional signing key for final checkpoint
/// generation (§9.9.3) — hoisted body of the legacy
/// [`ContextManager::close_context_with_key`](crate::context::supervisor::Supervisor::close_context_with_key).
///
/// See the legacy method's doc comment for the full `SingleAdmin` gate,
/// TTL / governance-timeout cancellation, and final-checkpoint policy.
/// Byte-identical behavior.
pub async fn close_context_with_key(
    supervisor: &Supervisor,
    handle: &ContextHandle,
    initiator_did: &DID,
    signing_key: Option<&ed25519_dalek::SigningKey>,
) -> Result<CloseResult, ContextError> {
    let event_log = supervisor
        .event_log_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let context_id = handle.context_id().to_owned();

    // Check governance model: multi-admin contexts must route through
    // governance (SCP-270, ADR-031). Only SingleAdmin contexts can use
    // the direct close_context path.
    // Capture generation for confused-deputy detection on reacquire.
    let (role_state, ctx_gen) = {
        let (guard, ctx_gen) = manager_methods::lock_context(supervisor, &context_id)
            .await
            .map_err(|_| ContextError::ContextNotRegistered(context_id.clone()))?;
        let ctx = &*guard;

        // State check inside lock -- eliminates TOCTOU race.
        state::require_active(&ctx.handle)?;

        // Gate: multi-admin models must use governance path.
        if !matches!(
            ctx.governance.engine.model_config(),
            GovernanceModelConfig::SingleAdmin { .. }
        ) {
            return Err(ContextError::PermissionDenied(
                "multi-admin contexts must close through governance \
                 (propose GovernanceAction::CloseContext)"
                    .to_owned(),
            ));
        }

        (ctx.role_state.clone(), ctx_gen)
    };
    // Lock dropped before async ttl::close_context call.

    // Delegate to ttl::close_context for the actual logic (async).
    let result = ttl::close_context(handle, initiator_did, &role_state, event_log.as_ref()).await?;

    // Cancel TTL timer, governance timeout task, drop broadcast state,
    // and emit close notification (second lock acquisition with generation
    // check for confused-deputy detection + ContextClose TOCTOU re-check).
    {
        if let Ok(mut guard) = manager_methods::relock_context(supervisor, &ctx_gen).await {
            let ctx = &mut *guard;

            // Fix C: Re-check ContextClose capability under the cleanup lock.
            // If capability was revoked between the first lock and this
            // reacquire, the state transition already happened (can't undo),
            // but we log a warning for auditability.
            if !ctx
                .role_state
                .member_has_capability(initiator_did.as_ref(), &Capability::ContextClose)
            {
                tracing::warn!(
                    context_id = %context_id,
                    initiator_did = %initiator_did,
                    "ContextClose capability revoked between lock acquisitions — \
                     state transition already committed, proceeding with cleanup"
                );
            }

            ctx.ttl.timer.cancel();
            ctx.governance.timeout_task.cancel();
            // Drop broadcast context state -- keys are zeroed by Zeroize.
            ctx.broadcast_context = None;

            // §9.10.4: clear pseudonym state on close. The local pseudonym
            // is derived from secret key material; zeroing it prevents
            // leaking the routing ID after context teardown.
            ctx.local_pseudonym = None;
            ctx.pseudonym_registry.clear();

            // Participation decay: clear participation cache and cooldown
            // state on context close (#1530).
            ctx.governance.decay_participation();

            // Final checkpoint before close (§9.9.3): force-create a
            // checkpoint to capture the terminal event log state. This
            // ensures equivocation detection covers the full context
            // lifetime. Best-effort: skip if no signing key is available.
            if let Some(sk) = signing_key
                && let Some(cp) = crate::context::queries_helpers::force_create_checkpoint(
                    supervisor,
                    &context_id,
                    ctx,
                    initiator_did,
                    sk,
                )
            {
                tracing::debug!(
                    context_id = %context_id,
                    event_count = cp.event_count,
                    "final checkpoint created on close (§9.9.3)"
                );
            }

            let close_event = ContextEvent::SystemClose {
                initiator_did: initiator_did.clone(),
            };
            ctx.emit_event(close_event, &context_id, supervisor.event_tx_ref());
        }
    }

    manager_methods::update_context_gauges(supervisor);

    // Persist context state after close (best-effort).
    if manager_methods::has_persistence(supervisor)
        && let Ok(guard) = manager_methods::relock_context(supervisor, &ctx_gen).await
    {
        let ctx = &*guard;
        let snapshot = manager_methods::snapshot_context(ctx);
        manager_methods::persist_context_snapshot(supervisor, &context_id, snapshot);
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// 13. finalize_close (top-level)
// ---------------------------------------------------------------------------

/// Completes context closure (hoisted body of the legacy
/// [`ContextManager::finalize_close`](crate::context::lifecycle_helpers::finalize_close)).
///
/// Destroys MLS group state and sender keys, issues relay deletion
/// requests for ephemeral/summary scopes, transitions from `Closing`
/// to `Closed`, and appends the final `ContextClosed` event.
pub async fn finalize_close(
    supervisor: &Supervisor,
    handle: &ContextHandle,
) -> Result<(), ContextError> {
    let crypto = supervisor
        .crypto_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let transport = supervisor
        .transport_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let event_log = supervisor
        .event_log_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let context_id = handle.context_id().to_owned();

    ttl::finalize_close(
        handle,
        crypto.as_ref(),
        transport.as_ref(),
        event_log.as_ref(),
    )
    .await?;

    // Delete persisted state after finalize (best-effort).
    if let Some(persistence) = supervisor.persistence_ref() {
        let _ = persistence.delete_context(&context_id);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// 14. handle_ttl_expiry (top-level)
// ---------------------------------------------------------------------------

/// Handles automatic TTL expiry (hoisted body of the legacy
/// [`ContextManager::handle_ttl_expiry`](crate::context::lifecycle_helpers::handle_ttl_expiry)).
///
/// Transitions from `Active` to `Expired`, destroys keys per memory
/// scope, issues relay deletion requests for ephemeral/summary scopes,
/// and appends `ContextExpired` to the event log.
pub async fn handle_ttl_expiry(
    supervisor: &Supervisor,
    handle: &ContextHandle,
) -> Result<(), ContextError> {
    let crypto = supervisor
        .crypto_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let transport = supervisor
        .transport_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let event_log = supervisor
        .event_log_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED_EXPECT.to_owned()))?;
    let context_id = handle.context_id().to_owned();

    // Capture generation before async expiry work for confused-deputy
    // detection on reacquire.
    let ctx_gen = {
        let (_guard, generation) = manager_methods::lock_context(supervisor, &context_id)
            .await
            .map_err(|_| ContextError::ContextNotRegistered(context_id.clone()))?;
        generation
    };

    // Async TTL expiry logic -- no lock held. Pass transport for
    // best-effort relay ciphertext deletion (§5.11).
    let result = ttl::try_ttl_expiry_cleanup(
        handle,
        crypto.as_ref(),
        Some(transport.as_ref()),
        event_log.as_ref(),
        0,
    )
    .await;

    // Cancel governance timeout task, decay participation, and emit
    // appropriate event (lock acquired, then dropped, with generation check).
    {
        if let Ok(mut guard) = manager_methods::relock_context(supervisor, &ctx_gen).await {
            let ctx = &mut *guard;
            ctx.governance.timeout_task.cancel();
            // Participation decay on TTL expiry (#1530): clear
            // participation cache and cooldown state so stale data does
            // not carry over if the context is later restored.
            ctx.governance.decay_participation();
            if result.is_complete() {
                let event = ContextEvent::Expired;
                ctx.emit_event(event, &context_id, supervisor.event_tx_ref());
            } else {
                let event = ContextEvent::ExpiryFailed {
                    reason: result.to_string(),
                    state_transitioned: result.state_transitioned(),
                    mls_destroyed: result.mls_destroyed(),
                    sender_key_destroyed: result.sender_key_destroyed(),
                    event_logged: result.event_logged(),
                };
                ctx.emit_event(event, &context_id, supervisor.event_tx_ref());
            }
        } else {
            tracing::warn!(
                context_id = %context_id,
                "handle_ttl_expiry: generation mismatch — skipping state mutation"
            );
        }
    }

    // Persist context state after TTL expiry (best-effort).
    if manager_methods::has_persistence(supervisor)
        && let Ok(guard) = manager_methods::relock_context(supervisor, &ctx_gen).await
    {
        let ctx = &*guard;
        let snapshot = manager_methods::snapshot_context(ctx);
        manager_methods::persist_context_snapshot(supervisor, &context_id, snapshot);
    }

    if result.has_failures() {
        let msg = result.errors().join("; ");
        return Err(
            if !result.mls_destroyed() || !result.sender_key_destroyed() {
                ContextError::CryptoFailed(msg)
            } else {
                ContextError::EventLogFailed(msg)
            },
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// 15. propose_ttl_extension (top-level)
// ---------------------------------------------------------------------------

/// Proposes a TTL extension (hoisted body of the legacy
/// [`ContextManager::propose_ttl_extension`](crate::context::lifecycle_helpers::propose_ttl_extension)).
///
/// Records consent from the given member. Returns `true` iff every
/// member has now consented (unanimous); the caller should then call
/// [`reset_ttl_timer`] with the new duration.
pub async fn propose_ttl_extension(
    supervisor: &Supervisor,
    context_id: &str,
    member_did: &DID,
    proposed_duration: std::time::Duration,
) -> Result<bool, ContextError> {
    // All checks and mutation within a single lock acquisition.
    let ctx_arc = manager_methods::get_context_arc(supervisor, context_id)
        .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
    let mut guard = ctx_arc.lock().await;
    let ctx = &mut *guard;

    if !ctx.membership.contains(member_did) {
        return Err(ContextError::MemberNotFound(member_did.to_string()));
    }

    let member_count = ctx.membership.count();

    // Initialize extension proposal if not already in progress.
    let extension = ctx
        .ttl
        .extension
        .get_or_insert_with(|| TtlExtension::new(proposed_duration, member_count));

    extension.add_consent(member_did.clone());
    let unanimous = extension.is_unanimous();

    // Persist context state after proposal consent (best-effort).
    if manager_methods::has_persistence(supervisor) {
        let ctx_snapshot = manager_methods::snapshot_context(ctx);
        manager_methods::persist_context_snapshot(supervisor, context_id, ctx_snapshot);
    }

    Ok(unanimous)
}

// ---------------------------------------------------------------------------
// 16. reset_ttl_timer (top-level)
// ---------------------------------------------------------------------------

/// Resets the TTL timer after a successful unanimous extension (hoisted
/// body of the legacy
/// [`ContextManager::reset_ttl_timer`](crate::context::lifecycle_helpers::reset_ttl_timer)).
///
/// Cancels the old timer and spawns a new one with the given duration.
/// Clears the extension proposal state.
pub async fn reset_ttl_timer(
    supervisor: &Supervisor,
    context_id: &str,
    new_duration: std::time::Duration,
    handle: ContextHandle,
) {
    // Cancel old timer and clear extension state (lock, then drop).
    {
        if let Ok(ctx_arc) = manager_methods::get_context_arc(supervisor, context_id) {
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;
            ctx.ttl.timer.cancel();
            ctx.ttl.extension = None;
        }
    }

    spawn_ttl_timer(supervisor, context_id, new_duration, handle).await;

    // Persist context state after TTL reset (best-effort).
    if manager_methods::has_persistence(supervisor)
        && let Ok(ctx_arc) = manager_methods::get_context_arc(supervisor, context_id)
    {
        let guard = ctx_arc.lock().await;
        let ctx = &*guard;
        let snapshot = manager_methods::snapshot_context(ctx);
        manager_methods::persist_context_snapshot(supervisor, context_id, snapshot);
    }
}

// ---------------------------------------------------------------------------
// 17. start_ttl_timer (top-level shim, forwarder into spawn_ttl_timer)
// ---------------------------------------------------------------------------

/// Installs a TTL timer for the given context (hoisted body of the
/// legacy
/// [`ContextManager::start_ttl_timer`](crate::context::supervisor::Supervisor::start_ttl_timer)).
///
/// Thin shim that delegates to [`spawn_ttl_timer`] — the actor-shape
/// [`TtlCloseCommand::StartTtlTimer`](crate::context::actor::commands::TtlCloseCommand::StartTtlTimer)
/// handler uses this wrapper so it doesn't need to depend on the
/// `manager` submodule's private `spawn_ttl_timer` directly.
pub async fn start_ttl_timer(
    supervisor: &Supervisor,
    context_id: &str,
    duration: std::time::Duration,
    handle: ContextHandle,
) {
    spawn_ttl_timer(supervisor, context_id, duration, handle).await;
}

// ---------------------------------------------------------------------------
// 18. spawn_ttl_timer (transitive — shared by reset_ttl_timer, start_ttl_timer, import_context, finalize_create)
// ---------------------------------------------------------------------------

/// Spawns a TTL timer for the given context (hoisted body of the legacy
/// `ContextManager::spawn_ttl_timer`).
///
/// See the legacy method's doc comment for the full timer-fired /
/// cancelled select-arm semantics, generation-check handling, and
/// `ContextEvent::Expired` / `ContextEvent::ExpiryFailed` emission
/// policy. Byte-identical to the legacy method.
#[allow(clippy::too_many_lines)] // 12c.9g.2 widens the prelude (5 supervisor accessor probes vs 1 provider readiness check) by 14 lines so the spawn_blocking closure body fits within the previous 90-line budget — see commit message.
pub async fn spawn_ttl_timer(
    supervisor: &Supervisor,
    context_id: &str,
    duration: std::time::Duration,
    handle: ContextHandle,
) {
    let Some(crypto_ref) = supervisor.crypto_ref() else {
        tracing::error!(
            context_id,
            "spawn_ttl_timer: Supervisor is not attached — skipping"
        );
        return;
    };
    let Some(transport_ref) = supervisor.transport_ref() else {
        tracing::error!(
            context_id,
            "spawn_ttl_timer: Supervisor transport not initialized — skipping"
        );
        return;
    };
    let Some(event_log_ref) = supervisor.event_log_ref() else {
        tracing::error!(
            context_id,
            "spawn_ttl_timer: Supervisor event log not initialized — skipping"
        );
        return;
    };
    let contexts_ref_arc = supervisor.contexts_arc();
    let Some(task_set_arc) = supervisor.task_set_ref() else {
        tracing::error!(
            context_id,
            "spawn_ttl_timer: Supervisor task set not initialized — skipping"
        );
        return;
    };
    // Extract the cancel Notify and generation under lock, then drop.
    let (cancel, spawn_generation) = {
        let Ok(arc) = manager_methods::get_context_arc(supervisor, context_id) else {
            return;
        };
        let ctx = arc.lock().await;
        (ctx.ttl.timer.cancel.clone(), ctx.generation)
    };

    // Clone Arc-wrapped providers so the spawned task can perform
    // key destruction, relay deletion, and event logging on TTL expiry.
    let crypto = Arc::clone(crypto_ref);
    let transport = Arc::clone(transport_ref);
    let event_log = Arc::clone(event_log_ref);
    let event_tx = supervisor.event_tx_ref().cloned();
    let contexts_ref = contexts_ref_arc;
    let context_id_owned = context_id.to_owned();

    let abort_handle = {
        let mut task_set = task_set_arc.lock().await;
        task_set.spawn(async move {
            tokio::select! {
                () = tokio::time::sleep(duration) => {
                    // Timer fired. Run cleanup with exponential backoff
                    // retries (SCP-169, #612). Pass transport so relay
                    // ciphertext deletion happens on timer-initiated expiry
                    // (§5.11, #612 finding 2).
                    let result = ttl::run_ttl_expiry_with_retries(
                        &handle,
                        crypto.as_ref(),
                        Some(transport.as_ref()),
                        event_log.as_ref(),
                        &cancel,
                    ).await;

                    // Emit event to the receive buffer and decay governance
                    // state under a single lock acquisition (matches the
                    // synchronous handle_ttl_expiry path; H8 fix).
                    if let Some(entry) = contexts_ref.get(&context_id_owned) {
                        let ctx_arc = entry.value().clone();
                        drop(entry);
                        let mut guard = ctx_arc.lock().await;
                        let ctx = &mut *guard;
                        // Generation check: if the context was removed
                        // and recreated since this timer was spawned,
                        // the timer belongs to the old context — skip.
                        if ctx.generation != spawn_generation {
                            tracing::warn!(
                                context_id = %context_id_owned,
                                spawn_generation,
                                current_generation = ctx.generation,
                                "TTL timer fired for stale context generation; skipping"
                            );
                        } else if result.is_complete() {
                            let event = ContextEvent::Expired;
                            ctx.emit_event(event, &context_id_owned, event_tx.as_ref());
                            ctx.governance.timeout_task.cancel();
                            ctx.governance.decay_participation();
                        } else {
                            let event = ContextEvent::ExpiryFailed {
                                reason: result.to_string(),
                                state_transitioned: result.state_transitioned(),
                                mls_destroyed: result.mls_destroyed(),
                                sender_key_destroyed: result.sender_key_destroyed(),
                                event_logged: result.event_logged(),
                            };
                            ctx.emit_event(event, &context_id_owned, event_tx.as_ref());
                            ctx.governance.timeout_task.cancel();
                            ctx.governance.decay_participation();
                        }
                    }
                }
                () = cancel.notified() => {
                    // Timer was cancelled.
                }
            }
        })
    };

    // Store the abort handle for cancel/is_active checks (lock, then drop).
    let context_id_for_store = context_id.to_owned();
    if let Ok(ctx_arc) = manager_methods::get_context_arc(supervisor, &context_id_for_store) {
        let mut guard = ctx_arc.lock().await;
        let ctx = &mut *guard;
        ctx.ttl.timer.task = Some(abort_handle);
    }
}

// ---------------------------------------------------------------------------
// load_persisted_context_state — hoisted out of the deleted `ContextManager` (ADR-049 commit 12)
// ---------------------------------------------------------------------------

/// Loads a persisted context snapshot and optional broadcast state.
///
/// Hoisted body of the legacy
/// `ContextManager::load_persisted_context_state`
/// (ADR-049 commit 12). Byte-identical behavior.
///
/// # Errors
///
/// Returns [`ContextError::PersistenceFailed`] if no persistence
/// provider is configured, no snapshot exists, or the load operation
/// fails.
pub fn load_persisted_context_state(
    supervisor: &Supervisor,
    context_id: &str,
) -> Result<
    (
        crate::context::state::ContextSnapshot,
        Option<scp_protocol::context::broadcast::BroadcastContext>,
    ),
    ContextError,
> {
    let Some(persistence) = supervisor.persistence_ref() else {
        return Err(ContextError::PersistenceFailed(
            "no persistence provider configured".into(),
        ));
    };

    let ctx_snapshot = persistence
        .load_context(context_id)
        .map_err(|e| {
            ContextError::PersistenceFailed(format!(
                "failed to load context state for {context_id}: {e}"
            ))
        })?
        .ok_or_else(|| {
            ContextError::PersistenceFailed(format!("no persisted context state for {context_id}"))
        })?;

    let broadcast_ctx = persistence
        .load_broadcast(context_id)
        .map_err(|e| {
            ContextError::PersistenceFailed(format!(
                "failed to load broadcast state for {context_id}: {e}"
            ))
        })?
        .map(scp_protocol::context::broadcast::BroadcastContext::from_snapshot);

    Ok((ctx_snapshot, broadcast_ctx))
}

/// Best-effort event log restore from persistence (#636).
///
/// Hoisted from `ContextManager::restore_event_log_best_effort`
/// (ADR-049 commit 12). Byte-identical behavior.
fn restore_event_log_best_effort(supervisor: &Supervisor, context_id: &str) {
    use crate::context::state::context_id_to_bytes;
    let ctx_id_bytes = context_id_to_bytes(context_id);
    let Some(event_log) = supervisor.event_log_ref() else {
        return;
    };
    if let Err(e) = event_log.restore_event_log(&ctx_id_bytes) {
        tracing::warn!(
            context_id = %context_id,
            error = %e,
            "failed to restore event log from persistence; \
             context will start with an empty event log"
        );
        let _ = event_log.init_event_log(&ctx_id_bytes);
    }
}

// ---------------------------------------------------------------------------
// restore_context — hoisted out of the deleted `ContextManager` (ADR-049 commit 12)
// ---------------------------------------------------------------------------

/// Restores a context into the supervisor from persisted state.
///
/// Hoisted body of the legacy
/// `ContextManager::restore_context`
/// (ADR-049 commit 12). Byte-identical behavior.
///
/// Loads the persisted `ContextSnapshot` and optional broadcast state,
/// reconstructs `PerContextState`, and inserts it into the contexts
/// map. Re-spawns the TTL timer if `ttl_remaining_secs` is `Some`.
///
/// # Arguments
///
/// * `supervisor` — supervisor providing crypto / `event_log` / clock /
///   persistence accessors.
/// * `context_id` — the context identifier to restore.
/// * `handle` — a pre-created `ContextHandle` for the context.
///
/// # Errors
///
/// Returns [`ContextError::PersistenceFailed`] if no persisted state
/// exists. Returns [`ContextError::MembershipFailed`] if the context
/// cannot be inserted (already registered).
#[tracing::instrument(skip_all, fields(context_id))]
#[allow(clippy::too_many_lines)]
pub async fn restore_context(
    supervisor: &Supervisor,
    context_id: &str,
    handle: &crate::context::ContextHandle,
) -> Result<(), ContextError> {
    use crate::context::governance::timeout::{DeadlockDetectionState, GovernanceTimeoutTask};
    use crate::context::lifecycle_logic::{
        derive_message_pricing, sanitize_cooldown_until, validate_consequence_rules_for_import,
    };
    use crate::context::state::{
        context_id_to_bytes, restore_governance_engine_from_snapshot,
        restore_grace_store_from_snapshot,
    };
    use scp_protocol::context::governance::mls_integration::EpochCoordinator;
    use scp_protocol::context::membership::ReceiveBuffer;
    use std::collections::HashSet;

    const ATTACHED: &str = "lifecycle_helpers::restore_context: provider slot empty";

    let crypto = Arc::clone(
        supervisor
            .crypto_ref()
            .ok_or_else(|| ContextError::NotInitialized(ATTACHED.to_owned()))?,
    );
    let event_log = Arc::clone(
        supervisor
            .event_log_ref()
            .ok_or_else(|| ContextError::NotInitialized(ATTACHED.to_owned()))?,
    );
    let clock = Arc::clone(
        supervisor
            .clock_ref()
            .ok_or_else(|| ContextError::NotInitialized(ATTACHED.to_owned()))?,
    );
    let key_resolver = supervisor
        .key_resolver_ref()
        .ok_or_else(|| ContextError::NotInitialized(ATTACHED.to_owned()))?
        .clone();

    let (mut ctx_snapshot, broadcast_ctx) = load_persisted_context_state(supervisor, context_id)?;
    restore_event_log_best_effort(supervisor, context_id);

    validate_consequence_rules_for_import(
        &ctx_snapshot.consequence_rules,
        &ctx_snapshot.context_params.consequence_config,
    )?;

    let now_for_cooldown = clock.now_secs();
    sanitize_cooldown_until(
        &mut ctx_snapshot.cooldown_until,
        &ctx_snapshot.consequence_rules,
        now_for_cooldown,
        "restore",
    );
    let ttl_remaining = ctx_snapshot.ttl_remaining_secs;

    let governance_engine =
        restore_governance_engine_from_snapshot(&ctx_snapshot, key_resolver.clone())?;
    let (grace_store, needs_reconnect) =
        restore_grace_store_from_snapshot(context_id, &ctx_snapshot);

    if !ctx_snapshot.mls_crypto_state.is_empty() {
        let ctx_id_bytes = context_id_to_bytes(context_id);
        crypto.restore_crypto_state(&ctx_id_bytes, &ctx_snapshot.mls_crypto_state)?;
    }

    let last_members: HashSet<scp_identity::DID> = ctx_snapshot
        .membership
        .members()
        .map(|m| m.did.clone())
        .collect();

    let now_for_validation = clock.now_secs();
    let hrl_config = ctx_snapshot
        .hard_rate_limit_config
        .clone()
        .unwrap_or_else(scp_protocol::economy::antispam::HardRateLimitConfig::matrix_defaults);
    hrl_config.validate().map_err(|e| {
        ContextError::PersistenceFailed(format!(
            "restore: hard-rate-limit config validation failed: {e}"
        ))
    })?;
    let mut hrl_state = ctx_snapshot.hard_rate_limit_state.clone();
    scp_protocol::economy::antispam::TokenBucketLimiter::validate_and_sanitize_snapshot(
        &mut hrl_state,
        &hrl_config,
        now_for_validation,
        scp_protocol::economy::antispam::SNAPSHOT_CLOCK_SKEW_TOLERANCE_SECS,
    )
    .map_err(|e| {
        ContextError::PersistenceFailed(format!(
            "restore: hard-rate-limit snapshot validation failed: {e}"
        ))
    })?;
    let validated_velocity_tracker = match ctx_snapshot.velocity_tracker_state {
        Some(vts) => {
            let mut entries = vts.entries;
            scp_protocol::economy::antispam::SenderVelocityTracker::validate_and_sanitize_snapshot(
                &mut entries,
                60,
                now_for_validation,
                scp_protocol::economy::antispam::SNAPSHOT_CLOCK_SKEW_TOLERANCE_SECS,
            )
            .map_err(|e| {
                ContextError::PersistenceFailed(format!(
                    "restore: velocity snapshot validation failed: {e}"
                ))
            })?;
            scp_protocol::economy::antispam::SenderVelocityTracker::from_snapshot(60, entries)
        }
        None => scp_protocol::economy::antispam::SenderVelocityTracker::new(60),
    };
    let validated_message_pricing = ctx_snapshot
        .message_pricing
        .clone()
        .or_else(|| derive_message_pricing(ctx_snapshot.economic_policy.as_ref()));
    if let Some(ref pricing) = validated_message_pricing {
        pricing.validate().map_err(|e| {
            ContextError::PersistenceFailed(format!(
                "restore: message pricing config validation failed: {e}"
            ))
        })?;
    }

    let next_gen_ref = supervisor.next_generation_ref();
    let per_context = PerContextState {
        generation: if ctx_snapshot.generation == 0 {
            next_gen_ref.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        } else {
            ctx_snapshot.generation
        },
        handle: handle.clone(),
        membership: ctx_snapshot.membership,
        governance: GovernanceState {
            engine: governance_engine,
            executed_proposals: {
                let now = clock.now_secs();
                ctx_snapshot
                    .executed_proposals
                    .into_iter()
                    .map(|id| (id, now))
                    .collect()
            },
            next_proposal_seq: ctx_snapshot
                .next_proposal_seq
                .max(ctx_snapshot.approved_proposals.len() as u64),
            approved_proposals: ctx_snapshot.approved_proposals,
            freeze: ctx_snapshot.governance_freeze,
            timeout_task: GovernanceTimeoutTask::new(),
            deadlock: DeadlockDetectionState::default(),
            threshold_signers: ctx_snapshot.threshold_signers,
            threshold_value: ctx_snapshot.threshold_value,
            pending_ceiling_modification: ctx_snapshot.pending_ceiling_modification,
            pending_economic_policy_change: ctx_snapshot.pending_economic_policy_change,
            registered_tools: ctx_snapshot.registered_tools,
            tool_interfaces: ctx_snapshot.tool_interfaces,
            pruning_policy: ctx_snapshot.pruning_policy,
            message_pricing: validated_message_pricing,
            hard_rate_limit: scp_protocol::economy::antispam::TokenBucketLimiter::from_snapshot(
                hrl_config, hrl_state,
            ),
            economic_policy: ctx_snapshot.economic_policy,
            budget_tracker: ctx_snapshot.budget_tracker,
            last_known_members: last_members,
            pending_epoch_resets: Vec::new(),
            consequence_rules: ctx_snapshot.consequence_rules,
            velocity_tracker: validated_velocity_tracker,
            participation_cache: ctx_snapshot.participation_cache,
            cooldown_until: ctx_snapshot.cooldown_until,
            spending_nonce_tracker: scp_protocol::crypto::ucan::nonce::NonceTracker::from_snapshot(
                context_id.to_owned(),
                Arc::clone(&clock),
                ctx_snapshot.spending_nonce_tracker_state,
            ),
            revoked_spending_ucan_cids: HashSet::new(),
            proposal_timestamps: ctx_snapshot.proposal_timestamps,
        },
        role_state: ctx_snapshot.role_state,
        receive_buffer: ReceiveBuffer::new(),
        broadcast_context: broadcast_ctx,
        migration_state: ctx_snapshot.migration_state,
        epoch: EpochState {
            mls_epoch: ctx_snapshot.mls_epoch,
            coordinator: EpochCoordinator::from_records(
                ctx_snapshot.epoch_coordination_records,
                context_id,
            ),
            grace_store,
            needs_reconnect,
        },
        access: AccessControlState {
            read_exclusion_list: ctx_snapshot.read_exclusion_list,
            access_key_store: ctx_snapshot.access_key_store,
        },
        ttl: TtlState {
            timer: crate::context::ttl::TtlTimer::with_clock(Arc::clone(&clock)),
            extension: None,
        },
        sequence_tracker: scp_protocol::envelope::SequenceTracker::new(),
        reorder_buffer: scp_protocol::envelope::ReorderBuffer::default(),
        pending_commits: ctx_snapshot.pending_commits,
        commit_fault: ctx_snapshot.commit_fault,
        checkpoint_events_since: ctx_snapshot.checkpoint_events_since,
        checkpoint_last_time_secs: ctx_snapshot.checkpoint_last_time_secs,
        checkpoints: Vec::new(),
        merkle_tree: scp_event_log::EventLog::new(context_id.to_owned()),
        local_pseudonym: ctx_snapshot.local_pseudonym,
        pseudonym_registry: ctx_snapshot
            .pseudonym_registry
            .into_iter()
            .map(|(did_str, p)| (scp_identity::DID(did_str), p))
            .collect(),
        send_tracker: crate::context::actor::SendSequenceTracker::new(),
    };

    manager_methods::insert_context(supervisor, context_id.to_owned(), per_context)
        .map_err(|e| ContextError::MembershipFailed(e.to_string()))?;

    // Start governance timeout task (ADR-031 §5).
    crate::context::governance_helpers::start_governance_timeout_task(supervisor, context_id).await;

    // Re-spawn TTL timer if there was remaining TTL.
    if let Some(remaining_secs) = ttl_remaining {
        let duration = std::time::Duration::from_secs(remaining_secs);
        spawn_ttl_timer(supervisor, context_id, duration, handle.clone()).await;
    }

    let _ = event_log; // silence unused on this branch
    Ok(())
}

// ---------------------------------------------------------------------------
// restore_all_contexts — hoisted out of the deleted `ContextManager` (ADR-049 commit 12)
// ---------------------------------------------------------------------------

/// Restore every persisted context that's in `Active` state.
///
/// Hoisted body of the legacy
/// `ContextManager::restore_all_contexts`
/// (ADR-049 commit 12). Byte-identical behavior.
///
/// # Errors
///
/// Returns [`ContextError::PersistenceFailed`] if listing persisted
/// contexts fails (no persistence provider configured, or list call
/// fails).
#[tracing::instrument(skip_all)]
pub async fn restore_all_contexts(supervisor: &Supervisor) -> Result<Vec<String>, ContextError> {
    let Some(persistence) = supervisor.persistence_ref() else {
        return Err(ContextError::PersistenceFailed(
            "no persistence provider configured".into(),
        ));
    };

    let context_ids = persistence.list_persisted_contexts().map_err(|e| {
        ContextError::PersistenceFailed(format!("failed to list persisted contexts: {e}"))
    })?;

    let mut restored = Vec::new();
    for ctx_id in &context_ids {
        let ctx_snapshot = match persistence.load_context(ctx_id) {
            Ok(Some(snap)) => snap,
            Ok(None) => continue,
            Err(e) => {
                tracing::warn!(context_id = %ctx_id, error = %e, "failed to load context snapshot during restore");
                continue;
            }
        };

        if ctx_snapshot.state != ContextState::Active {
            continue;
        }

        let handle =
            crate::context::ContextHandle::new(ctx_id.clone(), ctx_snapshot.context_params.clone());
        if handle.transition_to(&ContextState::Active).await.is_err() {
            continue;
        }

        match restore_context(supervisor, ctx_id, &handle).await {
            Ok(()) => restored.push(ctx_id.clone()),
            Err(e) => {
                tracing::warn!(context_id = %ctx_id, error = %e, "failed to restore context");
            }
        }
    }

    Ok(restored)
}

// ---------------------------------------------------------------------------
// flush_all_contexts / flush_all_contexts_sync / shutdown_all_contexts
// (hoisted out of the deleted `ContextManager`, ADR-049 commit 12)
// ---------------------------------------------------------------------------

/// Per-context lock-acquisition budget used by [`flush_all_contexts`].
const FLUSH_LOCK_BUDGET: std::time::Duration = std::time::Duration::from_millis(250);

/// Persists all contexts as a best-effort snapshot flush. Async variant.
///
/// Hoisted body of the legacy
/// `ContextManager::flush_all_contexts`
/// (ADR-049 commit 12). Byte-identical behavior.
pub async fn flush_all_contexts(supervisor: &Supervisor) {
    if !manager_methods::has_persistence(supervisor) {
        return;
    }
    // Collect Arcs first to avoid holding DashMap shard locks.
    let arcs: Vec<(String, Arc<tokio::sync::Mutex<PerContextState>>)> = supervisor
        .contexts_ref()
        .iter()
        .map(|entry| (entry.key().clone(), Arc::clone(entry.value())))
        .collect();
    let mut flushed = 0usize;
    let mut degraded = 0usize;
    for (context_id, arc) in arcs {
        match tokio::time::timeout(FLUSH_LOCK_BUDGET, arc.lock()).await {
            Ok(ctx) => {
                let snapshot = manager_methods::snapshot_context(&ctx);
                let bc_snapshot = ctx
                    .broadcast_context
                    .as_ref()
                    .map(scp_protocol::context::broadcast::BroadcastContext::to_snapshot);
                drop(ctx);
                manager_methods::persist_context_snapshot(supervisor, &context_id, snapshot);
                if let Some(ref bcs) = bc_snapshot {
                    manager_methods::persist_broadcast_snapshot(supervisor, &context_id, bcs);
                }
                flushed += 1;
            }
            Err(_elapsed) => {
                persist_degraded_snapshot(supervisor, &context_id);
                degraded += 1;
            }
        }
    }
    tracing::debug!(
        flushed,
        degraded,
        "flush_all_contexts: flushed {} context(s), {} degraded (lock timeout)",
        flushed,
        degraded,
    );
}

/// Sync wrapper for [`flush_all_contexts`].
///
/// Hoisted body of the legacy
/// `ContextManager::flush_all_contexts_sync`
/// (ADR-049 commit 12). Byte-identical behavior.
pub fn flush_all_contexts_sync(supervisor: &Supervisor) {
    if !manager_methods::has_persistence(supervisor) {
        return;
    }
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            tokio::task::block_in_place(|| {
                handle.block_on(flush_all_contexts(supervisor));
            });
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "flush_all_contexts_sync called outside tokio runtime; \
                 skipping flush — context state may not be persisted"
            );
        }
    }
}

/// Sync wrapper for [`shutdown_all_contexts`].
///
/// Required by destructor / atexit-style sync callers (the FFI
/// bridge instance's blocking-shutdown path) that cannot `.await`
/// AND that may run on a `current_thread` tokio runtime where
/// `block_in_place` would panic. Phase 1 fix-up of ADR-049
/// (post-review-round-1): runs the same per-context destruction
/// sequence as the async [`shutdown_all_contexts`] but uses
/// `try_lock` for the supervisor write-lock + task-set acquisitions
/// — on contention, the in-flight cleanup degrades to best-effort
/// (state cleared on next async shutdown call). The destructor path
/// runs at most once per process exit, so the contention window is
/// vanishingly small.
pub fn shutdown_all_contexts_sync(supervisor: &Supervisor) {
    use crate::context::state::context_id_to_bytes;

    let context_ids: Vec<String> = supervisor
        .contexts_ref()
        .iter()
        .map(|entry| entry.key().clone())
        .collect();

    let crypto_opt = supervisor.crypto_ref().cloned();
    let event_log_opt = supervisor.event_log_ref().cloned();

    for context_id in &context_ids {
        let ctx_id_bytes = context_id_to_bytes(context_id);

        if let Some(ref crypto) = crypto_opt {
            if let Err(e) = crypto.destroy_sender_key(&ctx_id_bytes) {
                tracing::debug!(
                    context_id = %context_id,
                    error = %e,
                    "failed to destroy sender key during sync shutdown — may already be gone"
                );
            }
            if let Err(e) = crypto.destroy_mls_group(&ctx_id_bytes) {
                tracing::debug!(
                    context_id = %context_id,
                    error = %e,
                    "failed to destroy MLS group during sync shutdown — may already be gone"
                );
            }
        }
        if let Some(ref event_log) = event_log_opt
            && let Err(e) = event_log.destroy_event_log(&ctx_id_bytes)
        {
            tracing::debug!(
                context_id = %context_id,
                error = %e,
                "failed to destroy event log during sync shutdown — may already be gone"
            );
        }
        supervisor.contexts_ref().remove(context_id);
    }

    // Sync path: try_lock the write_lock once. On contention, log and
    // skip — the destructor path runs once per process exit; contention
    // is vanishingly rare, and the next async shutdown finishes the
    // work cleanly.
    if let Ok(_guard) = supervisor.write_lock.try_lock() {
        supervisor
            .standing_contexts_ref()
            .store(Arc::new(HashMap::new()));
        supervisor.local_dids_ref().store(Arc::new(HashSet::new()));
    } else {
        tracing::warn!(
            "shutdown_all_contexts_sync: supervisor write_lock contended; \
             standing_contexts and local_dids retain stale state"
        );
    }

    // Wrapping-key cleanup is lock-free (DashMap::clear).
    supervisor.clear_wrapping_keys();

    if let Some(task_set) = supervisor.task_set_ref() {
        if let Ok(mut tasks) = task_set.try_lock() {
            tasks.abort_all();
        } else {
            tracing::warn!(
                "shutdown_all_contexts_sync: task_set contended; \
                 background tasks not aborted"
            );
        }
    }

    tracing::info!(
        removed_count = context_ids.len(),
        "sync shutdown: removed all contexts and best-effort aborted background tasks"
    );
}

/// Persists a degraded `ContextSnapshot` for a context whose lock could
/// not be acquired within the flush budget.
fn persist_degraded_snapshot(supervisor: &Supervisor, context_id: &str) {
    let Some(persistence) = supervisor.persistence_ref() else {
        return;
    };
    let snapshot = build_degraded_snapshot(context_id);
    if let Err(e) = persistence.persist_context(context_id, &snapshot) {
        crate::metrics::record_persistence_failure();
        tracing::warn!(
            context_id = %context_id,
            error = %e,
            "failed to persist degraded context snapshot"
        );
    } else {
        tracing::warn!(
            context_id = %context_id,
            "persisted degraded snapshot (needs_reconnect=true) — \
             context lock could not be acquired within flush budget"
        );
    }
}

/// Builds a minimal `ContextSnapshot` marked for reconnection. Mirrors
/// `ContextManager::build_degraded_snapshot`.
fn build_degraded_snapshot(context_id: &str) -> crate::context::state::ContextSnapshot {
    use scp_protocol::context::ContextParams;
    use scp_protocol::context::membership::MembershipState;

    let role_state = scp_protocol::context::roles::ContextRoleState {
        context_id: context_id.to_owned(),
        creator_did: String::new(),
        ceiling: scp_protocol::context::roles::CapabilityCeiling::new(std::iter::empty::<
            scp_protocol::context::roles::Capability,
        >()),
        role_definitions: HashMap::new(),
        assignments: HashMap::new(),
        members: HashSet::new(),
        member_capabilities: HashMap::new(),
        suspended_capabilities: HashMap::new(),
    };
    crate::context::state::ContextSnapshot {
        context_id: context_id.to_owned(),
        state: ContextState::Active,
        context_params: ContextParams::default(),
        membership: MembershipState::new(),
        role_state,
        executed_proposals: HashSet::new(),
        ttl_remaining_secs: None,
        registered_tools: Vec::new(),
        read_exclusion_list: HashSet::new(),
        tool_interfaces: Vec::new(),
        threshold_signers: Vec::new(),
        threshold_value: 0,
        pruning_policy: None,
        governance_model_config: None,
        economic_policy: None,
        budget_tracker: scp_protocol::economy::budget::MemberBudgetTracker::new(),
        approved_proposals: HashMap::new(),
        next_proposal_seq: 0,
        governance_freeze: None,
        pending_ceiling_modification: None,
        pending_economic_policy_change: None,
        mls_epoch: 0,
        epoch_coordination_records: Vec::new(),
        grace_entries: Vec::new(),
        needs_reconnect: true,
        mls_crypto_state: Vec::new(),
        migration_state: None,
        access_key_store: scp_protocol::crypto::access_keys::AccessKeyStore::new(),
        consequence_rules: Vec::new(),
        participation_cache: HashMap::new(),
        velocity_tracker: None,
        velocity_tracker_state: None,
        cooldown_until: HashMap::new(),
        proposal_timestamps: HashMap::new(),
        message_pricing: None,
        hard_rate_limit_config: None,
        hard_rate_limit_state: HashMap::new(),
        spending_nonce_tracker_state: HashMap::new(),
        pending_commits: VecDeque::new(),
        commit_fault: None,
        checkpoint_events_since: 0,
        checkpoint_last_time_secs: 0,
        generation: 0,
        local_pseudonym: None,
        pseudonym_registry: HashMap::new(),
    }
}

/// Shut down every context the supervisor owns (best-effort, local
/// cleanup only).
///
/// Hoisted body of the legacy `ContextManager::shutdown_all_contexts`
/// (ADR-049 commit 12). Phase 1 fix-up of ADR-049
/// (post-review-round-1): now async, replacing the prior `try_lock`
/// best-effort pattern with awaited lock acquisitions. Also clears
/// `local_dids` and `wrapping_keys` so a fresh
/// [`Supervisor::with_providers`](crate::context::supervisor::Supervisor::with_providers)
/// observes empty per-identity state. Wrapping-key secrets zeroize on
/// drop via the `Zeroizing<[u8;32]>` field on `WrappingKeyPair`.
pub async fn shutdown_all_contexts(supervisor: &Supervisor) {
    use crate::context::state::context_id_to_bytes;

    let context_ids: Vec<String> = supervisor
        .contexts_ref()
        .iter()
        .map(|entry| entry.key().clone())
        .collect();

    let crypto_opt = supervisor.crypto_ref().cloned();
    let event_log_opt = supervisor.event_log_ref().cloned();

    for context_id in &context_ids {
        let ctx_id_bytes = context_id_to_bytes(context_id);

        if let Some(ref crypto) = crypto_opt {
            if let Err(e) = crypto.destroy_sender_key(&ctx_id_bytes) {
                tracing::debug!(
                    context_id = %context_id,
                    error = %e,
                    "failed to destroy sender key during shutdown — may already be gone"
                );
            }
            if let Err(e) = crypto.destroy_mls_group(&ctx_id_bytes) {
                tracing::debug!(
                    context_id = %context_id,
                    error = %e,
                    "failed to destroy MLS group during shutdown — may already be gone"
                );
            }
        }
        if let Some(ref event_log) = event_log_opt
            && let Err(e) = event_log.destroy_event_log(&ctx_id_bytes)
        {
            tracing::debug!(
                context_id = %context_id,
                error = %e,
                "failed to destroy event log during shutdown — may already be gone"
            );
        }

        supervisor.contexts_ref().remove(context_id);
    }

    // Clear supervisor-level state under the write lock. Acquired
    // once for the standing_contexts + local_dids stores so a
    // concurrent reader observes a coherent shutdown rather than a
    // partially-cleared registry.
    {
        let _guard = supervisor.write_lock.lock().await;
        supervisor
            .standing_contexts_ref()
            .store(Arc::new(HashMap::new()));
        supervisor.local_dids_ref().store(Arc::new(HashSet::new()));
    }

    // Wrapping-key cleanup. `clear_wrapping_keys` drops every
    // `ArcSwap<WrappingKeyPair>`; the inner `WrappingKeyPair`'s
    // `Zeroizing<[u8;32]>` secret zeroes on drop.
    supervisor.clear_wrapping_keys();

    if let Some(task_set) = supervisor.task_set_ref() {
        let mut tasks = task_set.lock().await;
        tasks.abort_all();
    }

    tracing::info!(
        removed_count = context_ids.len(),
        "shutdown: removed all contexts, cleared identity registries, and aborted background tasks"
    );
}
