//! Snapshot builders and the persist calls every domain and the actor run
//! loop share (ADR-070 §1.4): they read only `PerContextState` and write
//! only through `ActorDeps::persistence`.
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::state::PerContextState;
use crate::context::state;
use scp_protocol::context::ContextError;

/// Build the snapshot for `context_id` from owned actor state, threading in
/// the supervisor-owned MLS crypto state. Shared by the best-effort and
/// fail-closed persist paths. A crypto-export failure marks the snapshot
/// `needs_reconnect` (so restore fires the §23.11 reconnection pipeline)
/// rather than failing — the crypto state is Class M (crash-surviving), so a
/// transient export failure does not lose security state.
///
/// `pub(crate)` so the `ClassSCommitToken` deferred-persist terminals
/// (`commit` / `discharge_with`) can build the owned snapshot in their OWN
/// frame and drop the `&PerContextState` borrow BEFORE awaiting
/// [`persist_snapshot_fail_closed`]. `PerContextState` is `!Sync` (it holds a
/// `dyn FnMut` sink), so a `&PerContextState` held across an `.await` makes the
/// actor future `!Send` and fails `tokio::spawn`. Building the snapshot first
/// keeps the borrow off the await point (ADR-049 Decision 7).
///
/// # Errors
///
/// Returns [`ContextError::SupervisorShutDown`] when the Supervisor has
/// dropped, so no sender-epoch or receive-sequence floor export exists.
pub fn build_snapshot_for_persist(
    state: &PerContextState,
    deps: &ActorDeps,
    context_id: &str,
) -> Result<crate::context::state::ContextSnapshot, ContextError> {
    let mut snapshot = build_snapshot_from_state(state);
    // ADR-056: canonical digest, not a re-hash of the hex id.
    let ctx_id_bytes = state::context_id_to_bytes(context_id);
    // ADR-049 PR-6 (read-authority switch): the per-sender epoch + recv-sequence
    // floors are sourced from the AUTHORITATIVE Supervisor-owned Class-M registry
    // (`deps.supervisor.export_*`) and threaded into `export_crypto_state` as the
    // durable-blob params. ADR-049 PR-7 (SCP-CRYPTOMOVE-001): the export now runs
    // on the actor's `state` (was the provider), and the send sequence is read
    // from `state.send_tracker` inside the twin. The blob carries no wrapping
    // key: the identity's pair persists on its own (spec 09 §9.16.1).
    //
    // When the Supervisor has dropped (ADR-049 Decision 16) no floor export
    // exists; the error propagates, because a snapshot written with empty
    // floors would durably regress them.
    let sender_epochs = deps.supervisor.export_sender_key_epochs(&ctx_id_bytes)?;
    let recv_floors = deps.supervisor.export_recv_sequence_floors(&ctx_id_bytes)?;
    match state.export_crypto_state(sender_epochs, recv_floors) {
        Ok(crypto_state) => {
            snapshot.mls_crypto_state = crate::context::state::MlsCryptoState(crypto_state);
        }
        Err(e) => {
            snapshot.needs_reconnect = true;
            snapshot.mls_crypto_state = crate::context::state::MlsCryptoState::default();
            tracing::warn!(
                context_id = %context_id,
                error = %e,
                "failed to export MLS crypto state for persistence; \
                 snapshot marked needs_reconnect=true so restore \
                 fires the §23.11 reconnection pipeline"
            );
        }
    }
    Ok(snapshot)
}

/// Whether an MLS crypto export is durable enough to stand up a Welcome-JOINER.
///
/// [`build_snapshot_for_persist`] is deliberately FAIL-OPEN for existing
/// members: on an `export_crypto_state` failure it writes an EMPTY crypto blob
/// with `needs_reconnect = true` and the persist SUCCEEDS, so restore re-enters
/// the §23.11 reconnection pipeline. A Welcome-JOINER cannot reconnect-derive
/// (it would need a fresh Welcome), so for the spawn-from-Welcome entrypoint an
/// empty / errored crypto export is FATAL — a keyless snapshot there means a
/// live send-capable actor with no durable keys.
///
/// The persisted snapshot's crypto blob is a 1:1 copy of the
/// `export_crypto_state` result, so re-reading the live export tells the
/// entrypoint exactly what the snapshot carries WITHOUT depending on the
/// persistence backend supporting read-back (the test-only `NoOpContextPersistence`
/// and the `for_query_shim` path do not). Returns `true` only when the export
/// succeeded AND carries a non-empty blob.
///
/// The sole caller is `Supervisor::spawn_actor_from_welcome`, which the FFI
/// slice (pull request #2036) wired to production bridge consumers.
#[must_use]
pub fn welcome_snapshot_crypto_is_durable(
    export: &Result<zeroize::Zeroizing<Vec<u8>>, ContextError>,
) -> bool {
    matches!(export, Ok(blob) if !blob.is_empty())
}

/// Best-effort persist of the current actor state. Mirrors the legacy
/// Phase 3 snapshot persistence path, but reads from actor-owned state.
///
/// Internal cross-module persistence helper — `pub` only so the sibling
/// `crate::context` dispatch modules can call it; not part of the SDK surface.
///
/// **Persistence class.** Use this ONLY for state whose ≤50ms coalesce-window
/// rollback is acceptable (ADR-049 §9 Class C — liveness/structural state and
/// the accepted soft anti-spam residual: velocity / earned-capacity). For
/// security-critical monotonic state that does NOT survive an actor crash
/// (Class S — spending-nonce consume, executed-proposals, downward-authorization
/// transitions), use [`persist_state_fail_closed`] so a persist failure returns
/// an error instead of silently acknowledging an unpersisted mutation.
///
/// # Not `async fn` — `Send` discipline (ADR-049 Decision 7)
///
/// This is a SYNC fn returning a future, NOT an `async fn`. The
/// `&PerContextState` is consumed by [`build_snapshot_for_persist`] in the
/// synchronous prelude and is NOT captured by the returned future (which holds
/// only the owned snapshot + `deps` / `context_id`). `PerContextState` is
/// `!Sync` (it holds a `dyn FnMut` sink), so an `async fn` — which keeps its
/// `&PerContextState` parameter in the future for the whole future lifetime —
/// would make every awaiting actor handler `!Send` and fail `tokio::spawn`.
/// `use<'d, 'c>` precisely captures only the `deps` / `context_id` lifetimes
/// (edition 2024), excluding the `state` borrow.
pub fn persist_state_best_effort<'d, 'c>(
    state: &PerContextState,
    deps: &'d ActorDeps,
    context_id: &'c str,
) -> impl std::future::Future<Output = ()> + Send + use<'d, 'c> {
    let snapshot = build_snapshot_for_persist(state, deps, context_id);
    async move {
        // Bound by reference: a moved-out copy would give this future a second
        // `ContextSnapshot`-sized slot (clippy `large_futures`).
        let snapshot = match snapshot {
            Ok(ref snapshot) => snapshot,
            Err(e) => {
                scp_runtime_types::metrics::record_persistence_failure();
                tracing::warn!(
                    context_id = %context_id,
                    error = %e,
                    "context snapshot not persisted: no floor export"
                );
                return;
            }
        };
        if let Err(e) = deps.persistence.persist_context(context_id, snapshot).await {
            scp_runtime_types::metrics::record_persistence_failure();
            tracing::warn!(
                context_id = %context_id,
                error = %e,
                "failed to persist context snapshot"
            );
        }
    }
}

/// Fail-closed persist of the current actor state (ADR-049 §9 Class S).
///
/// Persists and, on failure, returns
/// [`ContextError::PersistenceFailed`] instead of swallowing the error — so a
/// security-critical mutation (spending-nonce consume, executed-proposals,
/// downward-authorization transition) is NEVER acknowledged to a caller unless
/// it is durable. The respawn crash-safety invariant (ADR-049 §9) forbids
/// returning `Ok` for such a mutation when the persist did not land: a coalesced
/// (best-effort) acknowledgment would let an actor crash roll the mutation back,
/// re-opening a replay / re-spend / re-grant window after the caller already
/// observed success.
///
/// The failure metric is still recorded for observability.
///
/// Internal cross-module persistence helper — `pub` only so the sibling
/// `crate::context` dispatch modules can call it; not part of the SDK surface.
///
/// # Errors
///
/// Returns [`ContextError::PersistenceFailed`] if the underlying
/// `persist_context` write fails, and [`ContextError::SupervisorShutDown`] when
/// [`build_snapshot_for_persist`] returns it.
///
/// # Not `async fn` — `Send` discipline (ADR-049 Decision 7)
///
/// SYNC fn returning a future (see [`persist_state_best_effort`] for the full
/// rationale): the `&PerContextState` is consumed in the synchronous prelude and
/// is NOT captured by the returned future, so every awaiting actor handler stays
/// `Send`.
pub fn persist_state_fail_closed<'d, 'c>(
    state: &PerContextState,
    deps: &'d ActorDeps,
    context_id: &'c str,
) -> impl std::future::Future<Output = Result<(), ContextError>> + Send + use<'d, 'c> {
    // Build the owned snapshot FIRST so the `&PerContextState` borrow is dropped
    // before the returned future — keeps this future `Send` (see
    // [`build_snapshot_for_persist`]).
    let snapshot = build_snapshot_for_persist(state, deps, context_id);
    // Matched by reference: `&snapshot?` would move the snapshot into a second
    // slot of this future (clippy `large_futures`).
    async move {
        match snapshot {
            Ok(ref snapshot) => persist_snapshot_fail_closed(snapshot, deps, context_id).await,
            Err(e) => Err(e),
        }
    }
}

/// Fail-closed persist of an ALREADY-BUILT snapshot (ADR-049 §9 Class S).
///
/// The `&PerContextState`-holding half of [`persist_state_fail_closed`] split
/// out so the `ClassSCommitToken` deferred-persist terminals can build the
/// snapshot in their own frame (dropping the `!Send` `&PerContextState` borrow)
/// and then await this owned-`&ContextSnapshot` persist. `ContextSnapshot` is
/// `Send`, so a caller holding `&snapshot` across the await stays `Send`.
///
/// Records the failure metric and logs on error, identically to
/// [`persist_state_fail_closed`].
///
/// # Errors
///
/// Returns [`ContextError::PersistenceFailed`] if the underlying
/// `persist_context` write fails.
pub async fn persist_snapshot_fail_closed(
    snapshot: &crate::context::state::ContextSnapshot,
    deps: &ActorDeps,
    context_id: &str,
) -> Result<(), ContextError> {
    deps.persistence
        .persist_context(context_id, snapshot)
        .await
        .map_err(|e| {
            scp_runtime_types::metrics::record_persistence_failure();
            tracing::error!(
                context_id = %context_id,
                error = %e,
                "fail-closed persist of security-critical state failed; \
                 operation rejected (ADR-049 §9 Class S)"
            );
            ContextError::PersistenceFailed(format!(
                "fail-closed persist failed for context '{context_id}': {e}"
            ))
        })
}

#[allow(clippy::too_many_lines)]
pub fn build_snapshot_from_state(
    state: &PerContextState,
) -> crate::context::state::ContextSnapshot {
    use crate::context::state::{GovernanceState, VelocityTrackerSnapshot};

    // ADR-049 §9 (white-hat P2): exhaustively destructure `GovernanceState` so a
    // NEW governance field forces a conscious persist decision AT COMPILE TIME.
    // Without this bind, a freshly-added field is invisible to both this builder
    // and the field-round-trip test — silently dropped from the snapshot and
    // lost across an actor crash. Every field is bound below: persisted fields
    // are threaded into the snapshot; genuinely-transient fields are `_`-prefixed
    // WITH a justification. Adding a field to `GovernanceState` will fail to
    // compile here until the author decides which bucket it belongs to.
    let GovernanceState {
        // --- Persisted: threaded into ContextSnapshot below. ---
        // `engine` is persisted via `governance_model_config: Some(engine.model_config())`.
        engine: _engine_persisted_as_model_config,
        approved_proposals: _approved_proposals,
        next_proposal_seq: _next_proposal_seq,
        freeze: _freeze,
        pending_ceiling_modification: _pending_ceiling_modification,
        pending_economic_policy_change: _pending_economic_policy_change,
        registered_outlets: _registered_outlets,
        outlet_interfaces: _outlet_interfaces,
        pruning_policy: _pruning_policy,
        economic_policy: _economic_policy,
        budget_tracker: _budget_tracker,
        consequence_rules: _consequence_rules,
        velocity_tracker: _velocity_tracker,
        participation_cache: _participation_cache,
        cooldown_until: _cooldown_until,
        message_pricing: _message_pricing,
        hard_rate_limit: _hard_rate_limit,
        revoked_spending_ucan_cids: _revoked_spending_ucan_cids,
        proposal_timestamps: _proposal_timestamps,
        // Class-S governance subset (ADR-049 §9): exhaustively destructured so a
        // NEW Class-S governance field forces a conscious persist decision here
        // too. `executed_proposals` / `threshold_signers` / `threshold_value` /
        // `spending_nonce_tracker` / `capability_requirements` are all persisted
        // into the snapshot below.
        class_s:
            crate::context::state::GovernanceClassS {
                executed_proposals: _executed_proposals,
                threshold_signers: _threshold_signers,
                threshold_value: _threshold_value,
                spending_nonce_tracker: _spending_nonce_tracker,
                capability_requirements: _capability_requirements,
            },
        // --- Transient: deliberately NOT persisted (rebuilt at restore). ---
        // `deadlock`: per-context deadlock-detection scratch state, recomputed
        // from the live proposal set after restore.
        deadlock: _deadlock_transient,
        // `last_known_members`: departure-detection cache for the timeout loop;
        // re-seeded from `membership` on the next tick.
        last_known_members: _last_known_members_transient,
        // `pending_epoch_resets`: drained each timeout tick; an in-flight reset
        // is re-driven by the member, not replayed from a snapshot.
        pending_epoch_resets: _pending_epoch_resets_transient,
    } = &state.governance;

    let context_state_value = state.handle.state();
    // Persist the ABSOLUTE convergent deadline verbatim (ADR-049 §9): restore/
    // import re-arm the SAME instant, so a create-window `None` re-derives from
    // `creation + ttl` and a prior extension is not recomputed away (D1/D2).
    let ttl_deadline_secs = state.ttl.timer.deadline_unix_secs;
    let grace_entries = state.epoch.grace_store.to_grace_entries();

    crate::context::state::ContextSnapshot {
        context_id: state.handle.context_id().to_owned(),
        creation_timestamp_secs: state.creation_timestamp_secs,
        state: context_state_value,
        context_params: state.handle.params().clone(),
        membership: state.membership.clone(),
        role_state: state.role_state.clone(),
        event_log_merkle_root: [0u8; 32],
        executed_proposals: state
            .governance
            .class_s
            .executed_proposals
            .keys()
            .copied()
            .collect(),
        ttl_deadline_secs,
        registered_outlets: state.governance.registered_outlets.clone(),
        read_exclusion_list: state.access.read_exclusion_list.clone(),
        outlet_interfaces: state.governance.outlet_interfaces.clone(),
        threshold_signers: state.governance.class_s.threshold_signers.clone(),
        threshold_value: state.governance.class_s.threshold_value,
        capability_requirements: state.governance.class_s.capability_requirements.clone(),
        pruning_policy: state.governance.pruning_policy.clone(),
        governance_model_config: Some(state.governance.engine.model_config()),
        economic_policy: state.governance.economic_policy.clone(),
        budget_tracker: state.governance.budget_tracker.clone(),
        approved_proposals: state.governance.approved_proposals.clone(),
        next_proposal_seq: state.governance.next_proposal_seq,
        governance_freeze: state.governance.freeze,
        pending_ceiling_modification: state.governance.pending_ceiling_modification.clone(),
        pending_economic_policy_change: state.governance.pending_economic_policy_change.clone(),
        mls_epoch: state.epoch.mls_epoch,
        epoch_coordination_records: state.epoch.coordinator.records().to_vec(),
        grace_entries,
        needs_reconnect: state.epoch.needs_reconnect,
        mls_crypto_state: crate::context::state::MlsCryptoState::default(),
        migration_state: state.migration_state.clone(),
        access_key_store: state.access.access_key_store.clone(),
        consequence_rules: state.governance.consequence_rules.clone(),
        participation_cache: state.governance.participation_cache.clone(),
        velocity_tracker: Some(state.governance.velocity_tracker.window_secs()),
        velocity_tracker_state: Some(VelocityTrackerSnapshot {
            window_secs: state.governance.velocity_tracker.window_secs(),
            entries: state.governance.velocity_tracker.snapshot_entries(),
        }),
        cooldown_until: state.governance.cooldown_until.clone(),
        proposal_timestamps: state.governance.proposal_timestamps.clone(),
        message_pricing: state.governance.message_pricing.clone(),
        hard_rate_limit_config: Some(state.governance.hard_rate_limit.config().clone()),
        hard_rate_limit_state: state.governance.hard_rate_limit.snapshot_entries(),
        spending_nonce_tracker_state: state
            .governance
            .class_s
            .spending_nonce_tracker
            .snapshot_entries(),
        revoked_spending_ucan_cids: state.governance.revoked_spending_ucan_cids.clone(),
        pending_commits: state.pending_commits.clone(),
        commit_fault: state.commit_fault.clone(),
        checkpoint_events_since: state.checkpoint_events_since,
        checkpoint_last_time_secs: state.checkpoint_last_time_secs,
        generation: state.generation,
        // §9.10.4: persist the routing axis verbatim. `ContextRouting` is the
        // single shared type between live state and the serialized snapshot,
        // so no field-by-field translation is needed.
        routing: state.routing.clone(),
        relay_urls: state.relay_urls.clone(),
        // ADR-049 §9 Class S (line 144): persist the staged saga slot through
        // its sanctioned serialization mirror so a Prepare's staged evidence
        // survives an actor crash. See [`saga_pending_snapshot`].
        saga_pending: saga_pending_snapshot(state),
        xctx_committed_outputs: xctx_committed_outputs_snapshot(state),
        xctx_committed_stream_outputs: xctx_committed_stream_outputs_snapshot(state),
        xctx_committed_invocations: xctx_committed_invocations_snapshot(state),
        // ADR-049 §9 Class S (spec §6.2.4): persist the caller-side durable
        // reservation reversal records so a `PreparingB`-window crash can reverse
        // the caller deduction + void the escrow without the in-memory carrier.
        xctx_caller_reservations: xctx_caller_reservations_snapshot(state),
        xctx_nonce_dedup: xctx_nonce_dedup_snapshot(state),
        // §7.3.8 Class S: persist the value-caveat counters so a consumed
        // `max_calls` / `amount_max_cumulative` / `rate_window` cap survives an
        // actor crash rather than un-consuming. See [`caveat_counters_snapshot`].
        caveat_counters: caveat_counters_snapshot(state),
        // Fix-D Class S: persist the streaming reservation recovery records so a
        // crash-restore can RELEASE the escrow hold + cumulative counter reserve
        // of any stream whose off-mailbox pump survived the crash. See
        // [`stream_reservations_snapshot`].
        stream_reservations: stream_reservations_snapshot(state),
        // §9.10.4.1 Class S: persist the rotation state so a crash after the
        // rotation's persist restores the new epoch with `announce_pending`.
        pseudonym_rotation: state.class_s.pseudonym_rotation.clone(),
        // ADR-049 §9 Class S (§5.14.8 block-before-serve): fold the broadcast
        // security + roster state (per-author key epochs, block lists, subscriber
        // registry) into the fail-closed snapshot so a block / governance ban /
        // key-epoch advance is durable BEFORE the operation acks. `None` for
        // non-broadcast contexts.
        broadcast: state
            .broadcast_context
            .as_ref()
            .map(scp_protocol::context::broadcast::BroadcastContext::to_snapshot),
    }
}

/// Project the actor-side `saga_pending` map onto its serializable Class-S
/// snapshot mirror (ADR-049 §9 line 144; spec §5.15.8 / §6.2.4 Prepare).
///
/// The live [`SagaPreparedState`](crate::context::supervisor::saga_prepared_state::SagaPreparedState)
/// enum keeps the §9.4.3 non-derive barrier, so the snapshot carries the
/// sanctioned
/// [`SagaPreparedStateSnapshot`](crate::context::supervisor::saga_prepared_state::SagaPreparedStateSnapshot)
/// mirror instead. Every snapshot builder (the canonical one here plus the
/// broadcast / ttl-close / trust-recovery / manager copies) routes through
/// THIS one helper, so a saga in flight is dropped by none of them.
#[must_use]
pub fn saga_pending_snapshot(
    state: &PerContextState,
) -> std::collections::HashMap<
    scp_runtime_types::context::supervisor::saga_journal::SagaId,
    crate::context::supervisor::saga_prepared_state::SagaPreparedStateSnapshot,
> {
    use crate::context::supervisor::saga_prepared_state::SagaPreparedStateSnapshot;
    state
        .class_s
        .saga_pending
        .iter()
        .map(|(id, prepared)| {
            (
                id.clone(),
                SagaPreparedStateSnapshot::from_prepared(prepared),
            )
        })
        .collect()
}

/// Build the Class-S snapshot projection of the actor's COMMITTED
/// cross-context outlet-invocation captures (spec §6.2.4 "Exactly-once
/// execution with durable output capture"; ADR-049 §9). The live
/// [`CommittedOutletInvocation`](crate::context::supervisor::saga_prepared_state::CommittedOutletInvocation)
/// carries no §9.4.3 bearer bytes (public receipt + output), so — unlike
/// [`saga_pending_snapshot`] — the snapshot stores it directly via `Clone`.
/// Used at every snapshot builder so a crash between Commit-B capture and the
/// next coalesced write cannot lose the durable output (which would re-invoke
/// the outlet on replay).
pub fn xctx_committed_outputs_snapshot(
    state: &PerContextState,
) -> std::collections::HashMap<
    scp_runtime_types::context::supervisor::saga_journal::SagaId,
    crate::context::supervisor::saga_prepared_state::CommittedOutletInvocation,
> {
    state.class_s.xctx_committed_outputs.clone()
}

/// Build the Class-S snapshot projection of the actor's COMMITTED cross-context
/// **streaming** outlet-invocation captures (ADR-061 seal phase; spec §6.2.5
/// streaming saga; ADR-049 §9). The streaming sibling of
/// [`xctx_committed_outputs_snapshot`]. The live
/// [`CommittedStreamingOutletInvocation`](crate::context::supervisor::saga_prepared_state::CommittedStreamingOutletInvocation)
/// carries no §9.4.3 bearer bytes (public receipt + sealed root), so the snapshot
/// stores it directly via `Clone`. Used at every snapshot builder so a crash
/// between the seal-close capture and the next coalesced write cannot lose the
/// durable witness (which would re-invoke the outlet on replay).
pub fn xctx_committed_stream_outputs_snapshot(
    state: &PerContextState,
) -> std::collections::HashMap<
    scp_runtime_types::context::supervisor::saga_journal::SagaId,
    crate::context::supervisor::saga_prepared_state::CommittedStreamingOutletInvocation,
> {
    state.class_s.xctx_committed_stream_outputs.clone()
}

/// Build the Class-S snapshot projection of the actor's caller-side (A-owned)
/// COMMITTED cross-context outlet-invocation witness set (spec §6.2.4 "Commit",
/// caller side; §17.16.4 crash recovery; ADR-049 §9). The live
/// [`ClassSState::xctx_committed_invocations`](crate::context::actor::state::ClassSState::xctx_committed_invocations)
/// is a `{SagaId}` idempotency-witness set carrying no §9.4.3 bearer bytes, so —
/// like [`xctx_committed_outputs_snapshot`] — the snapshot stores it directly
/// via `Clone`. Exists so EVERY snapshot builder projects this Class-S saga
/// field through ONE helper, exactly like its siblings
/// (`saga_pending_snapshot` / `xctx_committed_outputs_snapshot` /
/// `xctx_caller_reservations_snapshot` / `xctx_nonce_dedup_snapshot`) — no
/// Class-S saga field is centralized by convention alone. Without persisting it,
/// a crash that rolled the witness back behind an acked Commit-A would
/// double-settle the caller escrow on replay.
pub fn xctx_committed_invocations_snapshot(
    state: &PerContextState,
) -> std::collections::HashSet<scp_runtime_types::context::supervisor::saga_journal::SagaId> {
    state.class_s.xctx_committed_invocations.clone()
}

/// Build the Class-S snapshot projection of the actor's caller-side durable
/// reservation reversal records (spec §6.2.4 "Reservation release on every
/// terminal path"; §17.16.4 crash recovery; ADR-049 §9). The live
/// [`ClassSState::xctx_caller_reservations`](crate::context::actor::state::ClassSState::xctx_caller_reservations)
/// is a `{SagaId → CallerReservationRecord}` map whose values carry no §9.4.3
/// bearer bytes (public economy metadata), so — like
/// [`xctx_committed_invocations_snapshot`] — the snapshot stores it directly via
/// `Clone`. Exists so EVERY snapshot builder projects this Class-S saga field
/// through ONE helper, exactly like its siblings (`saga_pending_snapshot` /
/// `xctx_committed_outputs_snapshot` / `xctx_committed_invocations_snapshot` /
/// `xctx_nonce_dedup_snapshot`) — no Class-S saga field is centralized by
/// convention alone. Without persisting it, a `PreparingB`-window crash could
/// never reverse the caller's deduction or void the escrow from the durable
/// record, durably over-charging the caller.
pub fn xctx_caller_reservations_snapshot(
    state: &PerContextState,
) -> std::collections::HashMap<
    scp_runtime_types::context::supervisor::saga_journal::SagaId,
    crate::context::supervisor::saga_prepared_state::CallerReservationRecord,
> {
    state.class_s.xctx_caller_reservations.clone()
}

/// Build the Class-S snapshot projection of the actor's B-owned cross-context
/// nonce-dedup cache (spec §6.2.4 "Freshness / anti-replay"; ADR-049 §9). The
/// live [`NonceDedup`](scp_protocol::crypto::sender_keys::NonceDedup) projects
/// to a plain `{nonce → first-seen secs}` map via `entries()`. Persisting it at
/// every snapshot builder makes the replay-protection cache CRASH-SURVIVING: a
/// restart no longer reopens the 5-minute window for a fresh-`SagaId` replay of
/// a `CrossContextOutletInvoke` (BLACK-624-01). Same-node restore rehydrates it;
/// cross-node export/import drops it to empty (B's freshness state has no
/// authority on a foreign node).
pub fn xctx_nonce_dedup_snapshot(
    state: &PerContextState,
) -> std::collections::HashMap<[u8; 16], u64> {
    state.class_s.xctx_nonce_dedup.entries()
}

/// Build the Class-S snapshot projection of the actor's §7.3.8 value-caveat
/// counters (ADR-049 §9). The live
/// [`CaveatCounters`](crate::trust::caveat_counters::CaveatCounters) is a plain
/// `Clone` serde value, so — like `xctx_committed_invocations_snapshot` — the
/// snapshot stores the map directly. Exists so EVERY snapshot builder projects
/// this Class-S field through ONE helper, exactly like its siblings — no Class-S
/// field is centralized by convention alone. Without persisting it, a crash that
/// rolled a consumed cap back behind an acked invocation would re-open the
/// spend/rate window the counter closes.
pub fn caveat_counters_snapshot(
    state: &PerContextState,
) -> std::collections::HashMap<String, crate::trust::caveat_counters::CaveatCounters> {
    state.class_s.caveat_counters.clone()
}

/// Project [`ClassSState::stream_reservations`](crate::context::actor::state::ClassSState::stream_reservations)
/// onto its snapshot map (Fix-D). The live
/// [`StreamReservationRecord`](crate::context::outlets::invoke::StreamReservationRecord)
/// is a plain `Clone` serde value, so — like [`caveat_counters_snapshot`] — the
/// snapshot stores the map directly. Exists so EVERY snapshot builder projects
/// this Class-S field through ONE helper, exactly like its siblings. Without
/// persisting it, a crash while a stream's off-mailbox pump is mid-flight would
/// strand the open-time escrow hold + cumulative counter reserve (the pump's
/// close-time settle lands on the respawned generation and is dropped).
pub fn stream_reservations_snapshot(
    state: &PerContextState,
) -> std::collections::HashMap<String, crate::context::outlets::invoke::StreamReservationRecord> {
    state.class_s.stream_reservations.clone()
}
