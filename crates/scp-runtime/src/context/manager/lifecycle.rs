//! Context lifecycle: create, join, leave, restore, export, import.

use std::collections::VecDeque;

use super::{
    AccessControlState, Arc, BroadcastAdmission, BroadcastContext, Capability, CapabilityCeiling,
    ContextCreationError, ContextError, ContextHandle, ContextManager, ContextMode, ContextParams,
    ContextRoleState, ContextSnapshot, ContextState, DID, DeadlockDetectionState, EpochCoordinator,
    EpochState, GovernanceModelConfig, GovernanceState, GovernanceTimeoutTask, HashMap, HashSet,
    KeyPackage, MemberBudgetTracker, MembershipState, PerContextState, ReceiveBuffer, TemplateId,
    TtlState, TtlTimer, build_governance_engine, builder_create_context, context_id_to_bytes,
    instrument, mint_governance_tokens, restore_governance_engine_from_snapshot,
    restore_grace_store_from_snapshot, validate_governance_consistency,
};

/// Builds an [`IdentityDepthAssessment`] for a member in a context.
///
/// Shared by `evaluate_sybil_resistance` (join path) and `check_proposer_eligibility`
/// (governance path). Populates trust signals from available context state:
///
/// - **`ParticipationHistory`** — participation duration from the member's
///   cached `ParticipationRecord` (§9.3 trust signal table row 3).
/// - **`ParticipationRecord`** — participation count from the same record
///   (§9.3 row 4). Strength = number of events by the member.
/// - **`EconomicActivity`** — total spend from the budget tracker (§9.3
///   row 5 / §19). Only populated if the member has budget state.
///
/// External signals (social attestation, device attestation, endorsements)
/// require DID document resolution and attestation verification, which
/// are not yet wired at the `ContextManager` layer. Those categories remain
/// empty until the trust signal provider infrastructure is built.
pub(super) fn build_identity_assessment(
    member_did: &DID,
    governance: &super::GovernanceState,
    now: u64,
) -> scp_protocol::trust::sybil::IdentityDepthAssessment {
    use scp_protocol::trust::sybil::{TrustSignal, TrustSignalCategory};

    let mut signals = HashMap::new();

    // Populate from participation cache if the member has a record.
    if let Some(record) = governance.participation_cache.get(member_did.as_ref()) {
        signals.insert(
            TrustSignalCategory::ParticipationHistory,
            TrustSignal {
                category: TrustSignalCategory::ParticipationHistory,
                verified_at: record.computed_at,
                strength: record.participation_duration_seconds,
                details: None,
            },
        );
        signals.insert(
            TrustSignalCategory::ParticipationRecord,
            TrustSignal {
                category: TrustSignalCategory::ParticipationRecord,
                verified_at: record.computed_at,
                strength: record.participation_count,
                details: None,
            },
        );
    }

    // Populate economic activity from budget tracker.
    let total_spent = governance.budget_tracker.total_spent(member_did).0;
    if total_spent > 0 {
        signals.insert(
            TrustSignalCategory::EconomicActivity,
            TrustSignal {
                category: TrustSignalCategory::EconomicActivity,
                verified_at: now,
                strength: total_spent,
                details: None,
            },
        );
    }

    scp_protocol::trust::sybil::IdentityDepthAssessment::new(member_did.clone(), signals, now)
}

/// Validates all consequence rule string fields (defense-in-depth).
///
/// Called from `create_context` to catch internal callers that bypass FFI
/// validation. Rejects control characters, HTML-special characters, and
/// overly long strings.
pub fn validate_consequence_rules(
    rules: &[scp_protocol::trust::consequence::ConsequenceRule],
    config: &scp_protocol::context::params::ConsequenceConfig,
) -> Result<(), ContextCreationError> {
    for rule in rules {
        rule.validate_against_config(config).map_err(|e| {
            ContextCreationError::CreationFailed(format!("consequence rule validation failed: {e}"))
        })?;
    }
    Ok(())
}

/// Maximum permitted future cooldown horizon, in seconds.
///
/// Cooldown timestamps in an imported or restored snapshot are clamped
/// to `now + MAX_COOLDOWN_SECS`. A malicious snapshot that injects
/// `cooldown_until[i] = u64::MAX` would otherwise permanently disable
/// the targeted consequence rule. 30 days is well above any legitimate
/// cooldown window — the longest spec-defined consequence cooldowns are
/// measured in hours — so the clamp is non-disruptive in practice.
pub(super) const MAX_COOLDOWN_SECS: u64 = 30 * 24 * 60 * 60;

/// Sanitizes an imported or restored `cooldown_until` map in place.
///
/// Drops every entry whose key (rule index) is out of bounds for the
/// supplied `consequence_rules` vector — these would otherwise let an
/// attacker inject cooldown state for nonexistent rules and influence
/// future rule evaluation. Clamps every remaining timestamp to
/// `now + MAX_COOLDOWN_SECS`. Both events emit a warning so anomalies
/// are visible at runtime.
///
/// Mirrors the WASM bridge `validate_imported_snapshot` policy
/// (`crates/scp-ffi/wasm/src/manager.rs`), but applied to the runtime
/// `ContextManager` paths that the WASM bridge does not exercise.
pub fn sanitize_cooldown_until(
    cooldown_until: &mut HashMap<usize, u64>,
    consequence_rules: &[scp_protocol::trust::consequence::ConsequenceRule],
    now: u64,
    source: &str,
) {
    let max_ts = now.saturating_add(MAX_COOLDOWN_SECS);
    let rule_count = consequence_rules.len();
    cooldown_until.retain(|&rule_index, ts| {
        if rule_index >= rule_count {
            tracing::warn!(
                source = source,
                rule_index,
                rule_count,
                "dropping cooldown_until entry: rule_index out of bounds"
            );
            return false;
        }
        if *ts > max_ts {
            tracing::warn!(
                source = source,
                rule_index,
                original_ts = *ts,
                clamped_ts = max_ts,
                "clamping cooldown_until entry to MAX_COOLDOWN_SECS horizon"
            );
            *ts = max_ts;
        }
        true
    });
}

/// Validates imported `consequence_rules` against `consequence_config` and
/// returns [`ContextError::ImportRejected`] on failure.
///
/// Distinct from [`validate_consequence_rules`] which targets the
/// create-time path and returns [`ContextCreationError`]. This variant
/// is used by `import_context` and `restore_context` so the bridge
/// translators surface the canonical `SCP-CTX-2092` code.
pub fn validate_consequence_rules_for_import(
    rules: &[scp_protocol::trust::consequence::ConsequenceRule],
    config: &scp_protocol::context::params::ConsequenceConfig,
) -> Result<(), ContextError> {
    for (idx, rule) in rules.iter().enumerate() {
        rule.validate_against_config(config)
            .map_err(|e| ContextError::ImportRejected {
                reason: format!("consequence_rules[{idx}] invalid: {e}"),
            })?;
    }
    Ok(())
}

/// Performs sybil resistance evaluation for a join candidate (#1530).
///
/// Reads the `sybil_policy` from `ContextParams`. When `None`, passes
/// unconditionally (backward compatible). When `Some`, constructs an
/// [`IdentityDepthAssessment`] from the member's available trust signals
/// and delegates to [`scp_protocol::trust::sybil::evaluate_sybil_resistance`].
///
/// Currently, the `ContextManager` layer does not have access to external
/// trust signals (social attestations, device attestations, etc.), so the
/// assessment is constructed with an empty signal set. Contexts that set a
/// sybil policy with non-trivial requirements will reject members until
/// signal providers are wired in at a higher layer.
pub fn evaluate_sybil_resistance(
    ctx: &PerContextState,
    member_did: &DID,
    now: u64,
) -> Result<(), ContextError> {
    let Some(policy) = &ctx.handle.params().sybil_policy else {
        tracing::trace!(
            member = %member_did,
            "sybil resistance check: no policy configured, passing"
        );
        return Ok(());
    };

    let assessment = build_identity_assessment(member_did, &ctx.governance, now);

    scp_protocol::trust::sybil::evaluate_sybil_resistance(&assessment, policy, now, None)
        .map_err(|e| ContextError::PermissionDenied(format!("sybil resistance check failed: {e}")))
}

/// Initializes participation record and records budget spend for a new member (#1530, #1537).
pub fn post_join_bookkeeping(
    ctx: &mut PerContextState,
    context_id: &str,
    member_did: &DID,
    now: u64,
    event_log: &dyn super::super::builder::ContextEventLogProvider,
) {
    // Participation record initialization for the new member.
    let context_id_bytes = super::context_id_to_bytes(context_id);
    let merkle_root = event_log
        .event_log_merkle_root(&context_id_bytes)
        .unwrap_or([0u8; 32]);
    let join_events =
        super::governance::event_log_entries_for_consequences(ctx, context_id, now, event_log);
    if !join_events.is_empty()
        && let Ok(record) = scp_protocol::trust::participation::compute_participation_record(
            &join_events,
            member_did.as_ref(),
            context_id,
            merkle_root,
            now,
        )
    {
        ctx.governance
            .participation_cache
            .insert(member_did.to_string(), record);
    }
}

/// Returns the spec §19.7 default per-DID message pricing configuration.
///
/// Every context now uses the same baseline: per-DID escalating cost for
/// `MessageSend`, `ContextJoin`, and `ToolInvoke`, plus the Matrix-style
/// hard rate limit. The `_economic_policy` parameter is intentionally
/// unused — it is kept in the signature so call-sites stay symmetrical
/// with the old `derive_relay_pricing_config` while documenting that
/// pricing is uniform across all contexts. Per-context pricing
/// customization will land via governance in a follow-up PR.
#[allow(clippy::unnecessary_wraps)] // Option return kept for forward compat
// with per-context pricing customization landing via governance.
pub fn derive_message_pricing(
    _economic_policy: Option<&scp_protocol::economy::types::EconomicPolicy>,
) -> Option<scp_protocol::economy::antispam::ContextMessagePricingConfig> {
    Some(scp_protocol::economy::antispam::ContextMessagePricingConfig::spec_default())
}

/// Enforces economic policy for context joins (#1537, #1593).
///
/// Checks auto-accept guard, then delegates to the unified `enforce_economy`
/// which evaluates join cost, checks spending UCAN AND-composition (spec
/// §19.5), and records spend against the joiner's budget. No auto-grant —
/// budget must be explicitly approved via `ApproveSpend` governance action.
///
/// Returns the deducted cost (if any) so the caller can carry it in an
/// `EconomyTicket` and drain all refundable economic state together via
/// `rollback_economy_ticket` on subsequent failure (F4 escrow pattern).
pub fn enforce_join_economy(
    ctx: &mut PerContextState,
    joiner_did: &DID,
    now: u64,
    spending_ucan: Option<&scp_protocol::crypto::ucan::UcanToken>,
    context_id: &str,
    clock: &dyn scp_primitives::Clock,
    key_resolver: &scp_protocol::context::governance::KeyResolver,
) -> Result<Option<scp_protocol::economy::types::Amount>, ContextError> {
    if scp_protocol::economy::policy::auto_accept_blocked_by_economics(
        ctx.governance.economic_policy.as_ref(),
    ) {
        return Err(ContextError::PermissionDenied(
            "SCP-ECON-12030: paid context requires explicit acceptance".into(),
        ));
    }
    let pricing_default =
        scp_protocol::economy::antispam::ContextMessagePricingConfig::spec_default();
    // C1 (PR #1606): mirror messaging.rs split-borrow pattern so the new
    // immutable `revoked_spending_ucan_cids` borrow coexists with the
    // mutable budget/nonce borrows on disjoint fields of `governance`.
    let member_count = ctx.membership.count();
    let governance = &mut ctx.governance;
    let pricing = governance
        .message_pricing
        .as_ref()
        .unwrap_or(&pricing_default);
    super::economy::enforce_economy(super::economy::EnforceEconomyRequest {
        economic_policy: governance.economic_policy.as_ref(),
        budget_tracker: &mut governance.budget_tracker,
        velocity_tracker: &governance.velocity_tracker,
        member_count,
        action_type: scp_protocol::economy::types::PaidActionType::ContextJoin,
        actor_did: joiner_did,
        now,
        spending_ucan,
        action_label: "context:join",
        context_id,
        clock,
        pricing,
        nonce_tracker: &mut governance.spending_nonce_tracker,
        revoked_spending_ucan_cids: &governance.revoked_spending_ucan_cids,
        key_resolver,
    })
}

#[allow(clippy::significant_drop_tightening)]
impl ContextManager {
    /// Loads persisted context state and reconstructs a `PerContextState`.
    ///
    /// Loads the full `ContextSnapshot` and optional `BroadcastContextSnapshot`
    /// from the persistence provider. Reconstructs `PerContextState` with
    /// all fields including membership, `role_state`, `executed_proposals`, and
    /// broadcast context (if applicable).
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::PersistenceFailed`] if no persistence provider
    /// is configured, no snapshot exists, or the load operation fails.
    pub fn load_persisted_context_state(
        &self,
        context_id: &str,
    ) -> Result<(ContextSnapshot, Option<BroadcastContext>), ContextError> {
        let Some(ref persistence) = self.persistence else {
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
                ContextError::PersistenceFailed(format!(
                    "no persisted context state for {context_id}"
                ))
            })?;

        let broadcast_ctx = persistence
            .load_broadcast(context_id)
            .map_err(|e| {
                ContextError::PersistenceFailed(format!(
                    "failed to load broadcast state for {context_id}: {e}"
                ))
            })?
            .map(BroadcastContext::from_snapshot);

        Ok((ctx_snapshot, broadcast_ctx))
    }

    /// Restores a context into the manager from persisted state.
    ///
    /// Loads the persisted `ContextSnapshot` and optional broadcast state,
    /// reconstructs `PerContextState`, and inserts it into the contexts map.
    /// Re-spawns the TTL timer if `ttl_remaining_secs` is `Some`.
    ///
    /// # Arguments
    ///
    /// * `context_id` -- The context identifier to restore.
    /// * `handle` -- A pre-created `ContextHandle` for the context.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::PersistenceFailed`] if no persisted state
    /// exists. Returns [`ContextError::MembershipFailed`] if the context
    #[instrument(skip_all, fields(context_id))]
    #[allow(clippy::too_many_lines)] // Context restore requires reconstructing all substate; splitting would fragment the logic.
    pub async fn restore_context(
        &self,
        context_id: &str,
        handle: &ContextHandle,
    ) -> Result<(), ContextError> {
        let (mut ctx_snapshot, broadcast_ctx) = self.load_persisted_context_state(context_id)?;
        self.restore_event_log_best_effort(context_id);
        // C3: Validate consequence rules on restore — reject tampered
        // rules. Uses validate_against_config to enforce the opt-in
        // gate for RevokeAccess even on restore from persistence and
        // catches any consequence_config regression that snuck in
        // between snapshots. Local restore is "trusted" enough to
        // preserve budgets / participation_cache / proposal_timestamps
        // / approved_proposals as-is — but we still refuse to load
        // structurally inconsistent rules, since that path was the
        // entire vector of CVE C3.
        validate_consequence_rules_for_import(
            &ctx_snapshot.consequence_rules,
            &ctx_snapshot.context_params.consequence_config,
        )?;
        // C3: Clamp `cooldown_until` to bounded horizon and drop
        // entries with out-of-range rule indices. Even local snapshots
        // can drift after a crash mid-write or after a config change
        // shrinks `consequence_rules`.
        let now_for_cooldown = self.clock.now_secs();
        sanitize_cooldown_until(
            &mut ctx_snapshot.cooldown_until,
            &ctx_snapshot.consequence_rules,
            now_for_cooldown,
            "restore",
        );
        let ttl_remaining = ctx_snapshot.ttl_remaining_secs;
        // Reconstruct the governance engine from the persisted snapshot.
        let governance_engine =
            restore_governance_engine_from_snapshot(&ctx_snapshot, self.key_resolver.clone())?;
        // Restore the epoch grace store from persisted entries (§23.11
        // recovery-on-startup).
        let (grace_store, needs_reconnect) =
            restore_grace_store_from_snapshot(context_id, &ctx_snapshot);
        // Restore MLS crypto state from the persisted snapshot (#645).
        // This must happen before constructing PerContextState so the crypto
        // provider has the MLS group and sender keys available for subsequent
        // encrypt/decrypt operations.
        if !ctx_snapshot.mls_crypto_state.is_empty() {
            let ctx_id_bytes = context_id_to_bytes(context_id);
            self.crypto
                .restore_crypto_state(&ctx_id_bytes, &ctx_snapshot.mls_crypto_state)?;
        }

        let last_members: HashSet<DID> = ctx_snapshot
            .membership
            .members()
            .map(|m| m.did.clone())
            .collect();

        // F6: Validate and sanitize persisted anti-spam snapshot state
        // BEFORE reconstructing the trackers. Policy: stale entries get
        // clamped, future-beyond-skew entries are rejected. The 5s skew
        // tolerance matches governance NTP jitter bounds.
        let now_for_validation = self.clock.now_secs();
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
            // Always normalize to the spec §19.4 60-second window on
            // restore, even when the persisted snapshot used the old
            // 3600s default. Per-sender entries are preserved.
            Some(vts) => {
                let mut entries = vts.entries;
                scp_protocol::economy::antispam::SenderVelocityTracker
                    ::validate_and_sanitize_snapshot(
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

        let per_context = PerContextState {
            generation: if ctx_snapshot.generation == 0 {
                // Legacy snapshot without generation — assign a fresh one so
                // the restored context participates in confused-deputy detection.
                self.next_generation
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            } else {
                ctx_snapshot.generation
            },
            handle: handle.clone(),
            membership: ctx_snapshot.membership,
            governance: GovernanceState {
                engine: governance_engine,
                executed_proposals: {
                    let now = self.clock.now_secs();
                    ctx_snapshot
                        .executed_proposals
                        .into_iter()
                        .map(|id| (id, now))
                        .collect()
                },
                // H10: monotonic seq counter is persisted across restart so
                // proposals can never share a sequence number even within
                // the same wall-clock second. This is the LOCAL-TRUSTED
                // restore path — use the persisted value verbatim. Legacy
                // snapshots without the field deserialize as 0 via
                // `#[serde(default)]`; in that case we still bump past
                // the existing approved set so newly inserted proposals
                // don't collide with restored ones. If the persisted
                // value is already higher (the common case after the
                // first H10 snapshot), `max` preserves it.
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
                spending_nonce_tracker:
                    scp_protocol::crypto::ucan::nonce::NonceTracker::from_snapshot(
                        context_id.to_owned(),
                        Arc::clone(&self.clock),
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
                timer: TtlTimer::with_clock(Arc::clone(&self.clock)),
                extension: None,
            },
            sequence_tracker: scp_protocol::envelope::SequenceTracker::new(),
            reorder_buffer: scp_protocol::envelope::ReorderBuffer::default(),
            // PR #1606 C6: restore the persistent commit retry queue and
            // fail-close marker so retries continue across process restart.
            pending_commits: ctx_snapshot.pending_commits,
            commit_fault: ctx_snapshot.commit_fault,
            // Checkpoint tracking (§9.9.3): restore counters from snapshot.
            checkpoint_events_since: ctx_snapshot.checkpoint_events_since,
            checkpoint_last_time_secs: ctx_snapshot.checkpoint_last_time_secs,
            checkpoints: Vec::new(),
            // Merkle tree starts empty on restore. Events appended after
            // restore will be tracked; proofs cover post-restore events only.
            // Full rebuild strategy: replay EventLogEntry hashes via
            // push_leaf_raw from event_log_entries if full-history proofs
            // are needed. Deferred to the Welcome delivery plan (#1311)
            // which adds cross-process event log synchronization.
            merkle_tree: scp_event_log::EventLog::new(context_id.to_owned()),
            // §9.10.4: restore pseudonym routing state from snapshot.
            local_pseudonym: ctx_snapshot.local_pseudonym,
            pseudonym_registry: ctx_snapshot
                .pseudonym_registry
                .into_iter()
                .map(|(did_str, p)| (DID(did_str), p))
                .collect(),
            // ADR-049 commit 8: fresh actor-shape tracker. Restored
            // snapshots predate this field (shim period), so seed at zero
            // and let the legacy `MembershipState` per-sender tracker
            // continue to supply wire sequence numbers. Commit 12 rewires
            // snapshot persistence to seed this field from the persisted
            // high-water mark.
            send_tracker: crate::context::actor::SendSequenceTracker::new(),
        };

        // Atomic check-and-insert — eliminates TOCTOU race between
        // contains_key and insert.
        self.insert_context(context_id.to_owned(), per_context)
            .map_err(|e| ContextError::MembershipFailed(e.to_string()))?;

        // Start governance timeout task (ADR-031 §5).
        self.start_governance_timeout_task(context_id).await;

        // Re-spawn TTL timer if there was remaining TTL.
        if let Some(remaining_secs) = ttl_remaining {
            let duration = std::time::Duration::from_secs(remaining_secs);
            self.spawn_ttl_timer(context_id, duration, handle.clone())
                .await;
        }

        Ok(())
    }

    /// Best-effort event log restore from persistence (#636).
    fn restore_event_log_best_effort(&self, context_id: &str) {
        let ctx_id_bytes = context_id_to_bytes(context_id);
        if let Err(e) = self.event_log.restore_event_log(&ctx_id_bytes) {
            tracing::warn!(
                context_id = %context_id,
                error = %e,
                "failed to restore event log from persistence; \
                 context will start with an empty event log"
            );
            let _ = self.event_log.init_event_log(&ctx_id_bytes);
        }
    }

    /// Returns `true` if the given context needs to re-enter the
    /// reconnection protocol (§23.3) before processing new messages.
    ///
    /// This flag is set during [`restore_context`](Self::restore_context)
    /// when an epoch grace store inconsistency is detected (§23.11
    /// inconsistent state fallback step 3). The SDK MUST check this flag
    /// when a relay WebSocket connection is re-established for the context
    /// and initiate the reconnection protocol if set.
    ///
    /// Returns `false` if the context is not registered or does not need
    /// reconnection.
    #[instrument(skip_all, fields(context_id))]
    pub async fn context_needs_reconnect(&self, context_id: &str) -> bool {
        let Ok(arc) = self.get_context_arc(context_id) else {
            return false;
        };
        let ctx = arc.lock().await;
        ctx.epoch.needs_reconnect
    }

    /// Clears the `needs_reconnect` flag for a context after the
    /// reconnection protocol (§23.3) completes successfully.
    ///
    /// The SDK calls this after the 6-phase reconnection protocol has
    /// finished for the context. Once cleared, the context resumes
    /// normal message processing.
    ///
    /// Returns `true` if the flag was cleared, `false` if the context
    /// is not registered.
    #[instrument(skip_all, fields(context_id))]
    pub async fn clear_needs_reconnect(&self, context_id: &str) -> bool {
        if let Ok(ctx_arc) = self.get_context_arc(context_id) {
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;
            ctx.epoch.needs_reconnect = false;
            true
        } else {
            false
        }
    }

    /// Returns the IDs of all contexts that need to re-enter the
    /// reconnection protocol (§23.3) before processing new messages.
    ///
    /// The SDK SHOULD call this on startup after
    /// [`restore_all_contexts`](Self::restore_all_contexts) and whenever
    /// a relay WebSocket connection is re-established. For each returned
    /// context ID, the SDK initiates the reconnection protocol via
    /// [`execute_reconnection`](Self::execute_reconnection).
    #[instrument(skip_all)]
    pub async fn contexts_needing_reconnect(&self) -> Vec<String> {
        // Collect (key, Arc) pairs first to release DashMap shard locks before
        // awaiting per-context Mutexes. Holding a DashMap Ref across .await
        // would deadlock any concurrent shard access.
        let entries = self.collect_context_arcs();
        let mut result = Vec::new();
        for (context_id, arc) in entries {
            let ctx = arc.lock().await;
            if ctx.epoch.needs_reconnect {
                result.push(context_id);
            }
        }
        result
    }

    /// Builds a [`ReconnectionCoordinator`](crate::sync::hours_offline::ReconnectionCoordinator)
    /// for contexts that have the `needs_reconnect` flag set.
    ///
    /// This wires the `needs_reconnect` detection (§23.11 step 3) to the
    /// reconnection protocol execution (§23.3). The spec requires that
    /// "when message processing begins for the affected context, the SDK
    /// MUST detect the `needs_reconnect` flag and initiate the reconnection
    /// protocol before processing any new messages."
    ///
    /// The returned coordinator provides:
    /// - [`plan(now)`](crate::sync::hours_offline::ReconnectionCoordinator::plan) —
    ///   classify each context by offline tier.
    /// - [`execute(now, driver)`](crate::sync::hours_offline::ReconnectionCoordinator::execute) —
    ///   run the full six-phase reconnection protocol using the caller's
    ///   [`SyncPhaseDriver`](crate::sync::hours_offline::SyncPhaseDriver)
    ///   implementation.
    ///
    /// After the coordinator completes successfully, call
    /// [`clear_needs_reconnect`](Self::clear_needs_reconnect) for each
    /// context that achieved a terminal outcome (`FullyCaughtUp`,
    /// `FastForwarded`, `Reset`, `ContextGone`).
    ///
    /// # Arguments
    ///
    /// * `member_did` — The DID of the reconnecting member.
    /// * `last_relay_contacts` — Per-context last relay contact timestamps
    ///   (persisted in `ProtocolRepository` under
    ///   `sync/{context_id}/last_relay_contact`).
    ///
    /// # Returns
    ///
    /// `None` if no contexts need reconnection. Otherwise returns the
    /// coordinator and the list of context IDs that will be reconnected.
    #[instrument(skip_all)]
    pub async fn prepare_reconnection(
        &self,
        member_did: scp_identity::DID,
        last_relay_contacts: std::collections::HashMap<String, u64>,
    ) -> Option<(
        crate::sync::hours_offline::ReconnectionCoordinator,
        Vec<String>,
    )> {
        let needing = self.contexts_needing_reconnect().await;
        if needing.is_empty() {
            return None;
        }

        let coordinator = crate::sync::hours_offline::ReconnectionCoordinator::new(
            member_did,
            needing.clone(),
            last_relay_contacts,
        );
        Some((coordinator, needing))
    }

    /// Executes the reconnection protocol for all contexts with
    /// `needs_reconnect = true`, using the provided
    /// [`SyncPhaseDriver`](crate::sync::hours_offline::SyncPhaseDriver).
    ///
    /// This is the one-call convenience method that wires detection to
    /// execution: it calls [`prepare_reconnection`](Self::prepare_reconnection)
    /// to build a coordinator, then runs
    /// [`execute(now, driver)`](crate::sync::hours_offline::ReconnectionCoordinator::execute)
    /// to perform the six-phase protocol, and finally clears the
    /// `needs_reconnect` flag for each successfully reconnected context.
    ///
    /// # Arguments
    ///
    /// * `member_did` — The DID of the reconnecting member.
    /// * `now` — Current Unix timestamp (seconds) for tier classification.
    /// * `last_relay_contacts` — Per-context last relay contact timestamps.
    /// * `driver` — The SDK's [`SyncPhaseDriver`](crate::sync::hours_offline::SyncPhaseDriver)
    ///   implementation providing transport and MLS operations.
    ///
    /// # Returns
    ///
    /// `None` if no contexts need reconnection. Otherwise returns the
    /// [`ReconnectionReport`](crate::sync::hours_offline::ReconnectionReport).
    #[instrument(skip_all)]
    pub async fn execute_reconnection<D: crate::sync::hours_offline::SyncPhaseDriver>(
        &self,
        member_did: scp_identity::DID,
        now: u64,
        last_relay_contacts: std::collections::HashMap<String, u64>,
        driver: &D,
    ) -> Option<crate::sync::hours_offline::ReconnectionReport> {
        let (coordinator, _context_ids) = self
            .prepare_reconnection(member_did, last_relay_contacts)
            .await?;

        let report = coordinator.execute(now, driver).await;

        // Clear needs_reconnect for contexts that completed successfully.
        for result in &report.contexts_synced {
            let cleared = matches!(
                result.outcome,
                scp_protocol::sync::SyncOutcome::FullyCaughtUp
                    | scp_protocol::sync::SyncOutcome::FastForwarded { .. }
                    | scp_protocol::sync::SyncOutcome::Reset
                    | scp_protocol::sync::SyncOutcome::ContextGone
            );
            if cleared {
                self.clear_needs_reconnect(&result.context_id).await;
            }
        }

        Some(report)
    }

    /// Restores all persisted contexts.
    ///
    /// Lists all context IDs from the persistence provider, creates a
    /// `ContextHandle` for each, and restores the context into the manager.
    /// Errors on individual context restores are logged but do not abort
    /// other restores.
    ///
    /// Returns the list of successfully restored context IDs.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::PersistenceFailed`] if listing persisted
    /// contexts fails (no persistence provider configured, or list call fails).
    #[instrument(skip_all)]
    pub async fn restore_all_contexts(&self) -> Result<Vec<String>, ContextError> {
        let Some(ref persistence) = self.persistence else {
            return Err(ContextError::PersistenceFailed(
                "no persistence provider configured".into(),
            ));
        };

        let context_ids = persistence.list_persisted_contexts().map_err(|e| {
            ContextError::PersistenceFailed(format!("failed to list persisted contexts: {e}"))
        })?;

        let mut restored = Vec::new();
        for ctx_id in &context_ids {
            // Load the snapshot to get params for handle creation.
            let ctx_snapshot = match persistence.load_context(ctx_id) {
                Ok(Some(snap)) => snap,
                Ok(None) => {
                    // No snapshot -- skip silently.
                    continue;
                }
                Err(e) => {
                    tracing::warn!(context_id = %ctx_id, error = %e, "failed to load context snapshot during restore");
                    continue;
                }
            };

            // Only restore Active contexts. Contexts in Closing/Closed/Expired
            // states should not be resurrected after restart.
            if ctx_snapshot.state != ContextState::Active {
                continue;
            }

            let handle = ContextHandle::new(ctx_id.clone(), ctx_snapshot.context_params.clone());
            if handle.transition_to(&ContextState::Active).await.is_err() {
                continue;
            }

            match self.restore_context(ctx_id, &handle).await {
                Ok(()) => restored.push(ctx_id.clone()),
                Err(e) => {
                    tracing::warn!(context_id = %ctx_id, error = %e, "failed to restore context");
                }
            }
        }

        Ok(restored)
    }

    /// Exports the full state of a context for backup or migration.
    ///
    /// Returns a [`crate::context::export_import::ContextExport`] containing the context snapshot, serialized
    /// event log entries, and an opaque MLS state blob (empty until MLS
    /// integration lands via #333).
    ///
    /// # Arguments
    ///
    /// * `context_id` -- The context to export.
    /// * `exporter_did` -- The DID of the identity performing the export.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] if the context does not exist or event log
    /// export fails.
    #[instrument(skip_all, fields(context_id))]
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::lifecycle_helpers::export_context`] free
    /// function (ADR-049 commit 12c.2). Deleted in a later commit
    /// alongside every other `ContextManager` lifecycle surface.
    pub async fn export_context(
        &self,
        context_id: &str,
        exporter_did: DID,
    ) -> Result<crate::context::export_import::ContextExport, ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::export_context — Supervisor must be attached".to_owned(),
            )
        })?;
        crate::context::lifecycle_helpers::export_context(&sup, context_id, exporter_did).await
    }

    /// Imports a previously exported context into this manager.
    ///
    /// Validates the export (version check, Merkle chain integrity, root
    /// hash match) and restores the context state. The imported context
    /// becomes active and available for operations.
    ///
    /// # Arguments
    ///
    /// * `export` -- The exported context data to import.
    ///
    /// # Returns
    ///
    /// A [`ContextHandle`] for the imported context.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] if validation fails (unsupported version,
    /// Merkle mismatch, tampered events) or the context already exists.
    ///
    /// # Per-instance authorization-state wipe policy (C3)
    ///
    /// Imports come from an UNTRUSTED source — a peer's exported snapshot.
    /// A malicious or buggy export can carry attacker-chosen authorization
    /// state that has no meaning on the importing node and would expand
    /// the attacker's authority on import. To preclude that, this method
    /// wipes the following per-instance fields entirely after the snapshot
    /// is validated and never re-uses the imported value:
    ///
    /// - `budget_tracker` — wiped. Budgets are local economic grants that
    ///   stack across votes; inheriting them lets a peer pre-load arbitrary
    ///   spend headroom for any DID it picks.
    /// - `participation_cache` — wiped. Cache is rebuilt lazily from the
    ///   imported event log via [`check_proposer_eligibility`]; carrying
    ///   the exporter's cache lets it forge "low-participation" verdicts
    ///   against victims.
    /// - `proposal_timestamps` — wiped. Earned-capacity rate limits are
    ///   per-instance counters; importing pre-populated entries lets the
    ///   exporter starve a victim of proposal slots.
    /// - `approved_proposals` — wiped. Re-derived implicitly from the
    ///   imported event log on next governance evaluation; importing
    ///   forged `RemoveMember` entries would let an attacker permanently
    ///   block a victim from proposing.
    /// - `spending_nonce_tracker` — already wiped (see in-line comment in
    ///   the construction below). C3 extends the same policy class.
    ///
    /// Fields that are kept across import (but validated): `consequence_
    /// rules`, `consequence_config`, `cooldown_until`. The latter is
    /// clamped to a bounded horizon and out-of-bound rule indices are
    /// dropped.
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::lifecycle_helpers::import_context`] free
    /// function (ADR-049 commit 12c.2). Deleted in a later commit
    /// alongside every other `ContextManager` lifecycle surface.
    #[instrument(skip_all)]
    pub async fn import_context(
        &self,
        export: crate::context::export_import::ContextExport,
    ) -> Result<ContextHandle, ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::import_context — Supervisor must be attached".to_owned(),
            )
        })?;
        crate::context::lifecycle_helpers::import_context(&sup, export).await
    }

    /// Creates a new SCP context with the two-phase commit pattern.
    ///
    /// Delegates to [`crate::context::builder::create_context`] which validates all
    /// preconditions (Phase 1), then executes creation steps with ordered
    /// rollback on failure (Phase 2).
    ///
    /// On success, registers the context with the manager for subsequent
    /// membership and messaging operations.
    ///
    /// # Arguments
    ///
    /// * `context_id` -- Unique string identifier for the new context.
    /// * `params` -- Full context configuration ([`ContextParams`]).
    /// * `creator_did` -- The DID of the context creator.
    ///
    /// # Returns
    ///
    /// A [`ContextHandle`] in the `Active` state on success.
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError`] if any validation or execution step
    /// fails. The operation is atomic from the caller's perspective: on
    /// failure, no MLS group state, sender key material, or event log state
    /// persists.
    ///
    /// See ADR-008 acceptance criterion 2.
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::lifecycle_helpers::create_context`] free
    /// function (ADR-049 commit 12c.2). Deleted in a later commit
    /// alongside every other `ContextManager` lifecycle surface.
    #[instrument(skip_all, fields(context_id = %context_id))]
    pub async fn create_context(
        &self,
        context_id: String,
        params: ContextParams,
        creator_did: DID,
        local_pseudonym: Option<[u8; 32]>,
    ) -> Result<ContextHandle, ContextCreationError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextCreationError::CreationFailed(
                "ContextManager::create_context — Supervisor must be attached".to_owned(),
            )
        })?;
        crate::context::lifecycle_helpers::create_context(
            &sup,
            context_id,
            params,
            creator_did,
            local_pseudonym,
        )
        .await
    }

    /// Creates a new SCP context without tracking membership state.
    ///
    /// This is the original `create_context` signature preserved for backward
    /// compatibility with existing tests. It delegates to the builder but does
    /// not register the context for membership operations.
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError`] if any validation or execution step
    /// fails.
    /// Replaces the stored context's handle with a new one carrying the given
    /// params. Used by tests to simulate a context whose `min_protocol_version`
    /// was set by a different SDK version or received via sync.
    #[cfg(test)]
    pub(crate) async fn replace_stored_params(&self, context_id: &str, new_params: ContextParams) {
        if let Ok(ctx_arc) = self.get_context_arc(context_id) {
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;
            let new_handle = ContextHandle::new(context_id.to_owned(), new_params);
            // Preserve the current state. Use try_read_state() to avoid
            // deadlock: the per-context Mutex is already held, and
            // handle.state().await would await on the ContextHandle RwLock.
            // Fallback to Active if the read is contended (test-only method,
            // contention is unlikely).
            let current_state = ctx.handle.try_read_state().unwrap_or(ContextState::Active);
            let _ = new_handle.transition_to(&current_state).await;
            ctx.handle = new_handle;
        }
    }

    #[cfg(test)]
    pub(crate) async fn create_context_bare(
        &self,
        context_id: String,
        params: ContextParams,
    ) -> Result<ContextHandle, ContextCreationError> {
        builder_create_context(
            context_id,
            params,
            self.crypto.as_ref(),
            self.transport.as_ref(),
            self.event_log.as_ref(),
            "", // No actor DID available for bare context creation.
        )
        .await
    }

    /// Creates a new SCP context with explicit governance configuration
    /// (SCP-267, ADR-031).
    ///
    /// This is the full-configuration entry point for context creation. The
    /// `GovernanceModelConfig` carries all governance-specific parameters
    /// (signers, threshold, voting window, min participation, etc.). The
    /// `GovernanceModel` in `params.governance` must be consistent with the
    /// config variant.
    ///
    /// At creation time, `GovernancePropose` and `GovernanceVote` UCAN tokens
    /// are minted for designated voters per ADR-031 §6.
    ///
    /// # Errors
    ///
    /// Returns [`ContextCreationError`] if:
    /// - The `GovernanceModelConfig` is inconsistent with `params.governance`.
    /// - The config has invalid parameters (e.g., threshold > `signers.len()`).
    /// - Any builder validation or execution step fails.
    #[instrument(skip_all, fields(context_id = %context_id))]
    pub async fn create_context_with_governance(
        &self,
        context_id: String,
        params: ContextParams,
        creator_did: DID,
        governance_config: GovernanceModelConfig,
    ) -> Result<ContextHandle, ContextCreationError> {
        // Defense-in-depth: verify that the creator's SDK version satisfies the
        // min_protocol_version it is setting (same check as create_context).
        params.check_version_compatibility(scp_protocol::envelope::SCP_PROTOCOL_VERSION)?;

        // Validate consistency between GovernanceModel and GovernanceModelConfig.
        validate_governance_consistency(&params.governance, &governance_config)?;

        // Validate that pricing formula only references available metrics.
        scp_protocol::economy::policy::validate_economic_policy_metrics(
            params.economic_policy.as_ref(),
        )
        .map_err(|e| ContextCreationError::CreationFailed(e.to_string()))?;

        // H1 (PR #1606): mirror create_context's defense-in-depth check so
        // multi-admin contexts cannot bypass consequence-rule validation by
        // taking the with_governance entry point. Rejects threshold == 0,
        // empty Custom triggers, RemoveMember severities (governance-only),
        // and RevokeAccess without `allow_automatic_access_revocation` opt-in.
        validate_consequence_rules(&params.consequence_rules, &params.consequence_config)?;

        // Phase 1+2: builder performs validation and creation (async, no lock held).
        let handle = builder_create_context(
            context_id.clone(),
            params.clone(),
            self.crypto.as_ref(),
            self.transport.as_ref(),
            self.event_log.as_ref(),
            creator_did.as_ref(),
        )
        .await?;

        // Build ceiling from params.
        let ceiling = CapabilityCeiling::new(params.ceiling.iter().cloned());

        // Initialize role state with the creator as admin.
        let role_state =
            ContextRoleState::new(&context_id, &*creator_did, ceiling, vec![], &*self.clock)
                .map_err(|e| ContextCreationError::CreationFailed(e.to_string()))?;

        // Initialize membership with the creator.
        let mut membership = MembershipState::new();
        let creator_tokens = role_state
            .assignments
            .get(creator_did.as_ref())
            .map(|a| a.tokens.clone())
            .unwrap_or_default();
        membership.add_member(creator_did.clone(), "admin".into(), creator_tokens);

        // Initialize broadcast context for Broadcast mode (SCP-227).
        let broadcast_context = if params.mode == ContextMode::Broadcast {
            let admission = match params.template_id {
                Some(TemplateId::GatedBroadcast) => BroadcastAdmission::Gated,
                Some(TemplateId::PublicBroadcast | TemplateId::PaidBroadcast) => {
                    BroadcastAdmission::Open
                }
                _ => BroadcastAdmission::Open,
            };
            let mut bc = BroadcastContext::new(context_id.clone(), &params.mode, admission)
                .map_err(|e| ContextCreationError::CreationFailed(e.to_string()))?;
            bc.add_author(&creator_did)
                .map_err(|e| ContextCreationError::CreationFailed(e.to_string()))?;
            if self.has_persistence() {
                self.persist_broadcast_snapshot(&context_id, &bc.to_snapshot());
            }
            Some(bc)
        } else {
            None
        };

        let per_context = self.build_governed_context_state(
            handle.clone(),
            &context_id,
            &params,
            &creator_did,
            membership,
            role_state,
            broadcast_context,
            governance_config,
        )?;

        // Atomic check-and-insert — eliminates TOCTOU race between
        // contains_key and insert.
        self.insert_context(context_id.clone(), per_context)?;

        self.start_governance_timeout_task(&context_id).await;
        self.persist_context_and_broadcast(&context_id).await;

        // Spawn TTL timer if TTL is configured (SCP-021).
        if let Some(ttl_duration) = params.ttl {
            self.spawn_ttl_timer(&context_id, ttl_duration, handle.clone())
                .await;
        }

        Ok(handle)
    }

    /// Builds a [`PerContextState`] with governance engine, tokens, and threshold
    /// signers extracted from the governance config. Helper for
    /// [`create_context_with_governance`] to stay under the line-count lint.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)] // internal helper, not public API
    fn build_governed_context_state(
        &self,
        handle: ContextHandle,
        context_id: &str,
        params: &ContextParams,
        creator_did: &DID,
        membership: MembershipState,
        role_state: ContextRoleState,
        broadcast_context: Option<BroadcastContext>,
        governance_config: GovernanceModelConfig,
    ) -> Result<PerContextState, ContextCreationError> {
        // Extract threshold signers and value from GovernanceModelConfig before
        // it is consumed by build_governance_engine (ADR-031).
        let (initial_threshold_signers, initial_threshold_value) = match &governance_config {
            GovernanceModelConfig::Threshold {
                signers, threshold, ..
            } => (signers.clone(), *threshold),
            _ => (Vec::new(), 0),
        };

        // Construct the governance engine from the explicit config (SCP-267).
        let governance_engine = build_governance_engine(
            governance_config,
            vec![creator_did.clone()],
            self.key_resolver.clone(),
        )?;

        // Mint GovernancePropose and GovernanceVote UCAN tokens for designated
        // voters per ADR-031 §6 and store them in role_state.
        let governance_tokens = mint_governance_tokens(
            context_id,
            creator_did,
            governance_engine.as_ref(),
            &*self.clock,
        );

        let mut role_state = role_state;
        for token in &governance_tokens {
            let caps = role_state
                .member_capabilities
                .entry(token.aud.clone())
                .or_default();
            for att in &token.att {
                if att.with.ends_with("/GovernancePropose") {
                    caps.insert(Capability::GovernancePropose);
                } else if att.with.ends_with("/GovernanceVote") {
                    caps.insert(Capability::GovernanceVote);
                }
            }
        }

        Ok(PerContextState {
            generation: self
                .next_generation
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            handle,
            membership,
            role_state,
            receive_buffer: ReceiveBuffer::new(),
            broadcast_context,
            migration_state: None,
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
                message_pricing: derive_message_pricing(params.economic_policy.as_ref()),
                hard_rate_limit: scp_protocol::economy::antispam::TokenBucketLimiter::new(
                    scp_protocol::economy::antispam::HardRateLimitConfig::matrix_defaults(),
                ),
                economic_policy: params.economic_policy.clone(),
                budget_tracker: MemberBudgetTracker::new(),
                last_known_members: HashSet::from([creator_did.clone()]),
                pending_epoch_resets: Vec::new(),
                consequence_rules: params.consequence_rules.clone(),
                velocity_tracker: scp_protocol::economy::antispam::SenderVelocityTracker::new(60),
                participation_cache: HashMap::new(),
                cooldown_until: HashMap::new(),
                spending_nonce_tracker: scp_protocol::crypto::ucan::nonce::NonceTracker::new(
                    context_id.to_owned(),
                    Arc::clone(&self.clock),
                ),
                revoked_spending_ucan_cids: HashSet::new(),
                proposal_timestamps: HashMap::new(),
            },
            epoch: EpochState {
                mls_epoch: 0,
                coordinator: EpochCoordinator::new(),
                grace_store: crate::crypto::mls::epoch_grace::EpochGraceStore::new(),
                needs_reconnect: false,
            },
            access: AccessControlState {
                read_exclusion_list: HashSet::new(),
                // Generate access key for the creator (§9.17.2 step 1),
                // matching the pattern in create_context. Without this,
                // the creator cannot send messages that wrap content for
                // recipients or decrypt messages addressed to them.
                access_key_store: {
                    let mut store = scp_protocol::crypto::access_keys::AccessKeyStore::new();
                    let creator_key = scp_protocol::crypto::access_keys::generate_access_key(
                        context_id,
                        creator_did.as_ref(),
                    );
                    store.set(context_id, creator_did.as_ref(), creator_key);
                    store
                },
            },
            ttl: TtlState {
                timer: TtlTimer::with_clock(Arc::clone(&self.clock)),
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
            checkpoint_last_time_secs: self.clock.now_secs(),
            checkpoints: Vec::new(),
            merkle_tree: scp_event_log::EventLog::new(context_id.to_owned()),
            // §9.10.4: pseudonym routing — governance-path creation does not
            // yet support pseudonym injection. The FFI bridge can set this
            // later via the standard create_context path.
            local_pseudonym: None,
            pseudonym_registry: HashMap::new(),
            // ADR-049 commit 8: fresh actor-shape tracker.
            send_tracker: crate::context::actor::SendSequenceTracker::new(),
        })
    }

    /// Joins a member to a context.
    ///
    /// Validates the joiner's key package, adds to MLS group (ADR-001),
    /// distributes sender key bundle (ADR-007), assigns the default role,
    /// issues UCAN tokens, and appends a `MemberJoined` event.
    ///
    /// See ADR-008 acceptance criterion 3.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] if:
    /// - The context is not in `Active` state.
    /// - The key package is invalid.
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::lifecycle_helpers::join_context`] free
    /// function (ADR-049 commit 12c.2). Deleted in a later commit
    /// alongside every other `ContextManager` lifecycle surface.
    #[instrument(skip_all, fields(context_id = handle.context_id()))]
    pub async fn join_context(
        &self,
        handle: &ContextHandle,
        key_package: KeyPackage,
        spending_ucan: Option<&scp_protocol::crypto::ucan::UcanToken>,
        local_pseudonym: Option<[u8; 32]>,
    ) -> Result<(), ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::join_context — Supervisor must be attached".to_owned(),
            )
        })?;
        crate::context::lifecycle_helpers::join_context(
            &sup,
            handle,
            key_package,
            spending_ucan,
            local_pseudonym,
        )
        .await
    }

    /// Performs the membership state mutations for `join_context` (Phase 4).
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::lifecycle_helpers::join_context_membership`]
    /// free function (ADR-049 commit 12c.2). Retained for signature
    /// stability during the commits-9-to-11 migration window; deleted
    /// in a later commit alongside every other `ContextManager`
    /// lifecycle surface.
    #[allow(dead_code)] // Forwarder preserved for symmetry; see doc comment.
    pub(crate) async fn join_context_membership(
        &self,
        context_id: &str,
        member_did: &DID,
        add_output: scp_protocol::context::builder::AddMemberOutput,
    ) -> Result<(), ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::join_context_membership — Supervisor must be attached".to_owned(),
            )
        })?;
        crate::context::lifecycle_helpers::join_context_membership(
            &sup, context_id, member_did, add_output,
        )
        .await
    }

    /// Captures the escrow hold after a successful join (Phase 5 of
    /// `join_context`).
    ///
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::lifecycle_helpers::capture_join_payment`]
    /// free function (ADR-049 commit 12c.2). Retained for signature
    /// stability during the commits-9-to-11 migration window; deleted
    /// in a later commit alongside every other `ContextManager`
    /// lifecycle surface.
    #[allow(dead_code)] // Forwarder preserved for symmetry; see doc comment.
    pub(crate) async fn capture_join_payment(
        &self,
        auth: Option<super::economy::PaidActionAuthorization>,
        member_did: &DID,
        context_id: &str,
        deducted_cost: Option<scp_protocol::economy::types::Amount>,
    ) {
        let Some(sup) = self.supervisor() else {
            tracing::error!(
                context_id,
                "ContextManager::capture_join_payment — Supervisor detached; skipping"
            );
            return;
        };
        crate::context::lifecycle_helpers::capture_join_payment(
            &sup,
            auth,
            member_did,
            context_id,
            deducted_cost,
        )
        .await;
    }

    /// Sends a `PseudonymAnnouncement` to inform other members of this
    /// member's per-context routing ID (§9.10.4).
    ///
    /// Called by the FFI bridges after `create_context` or `join_context`
    /// succeeds with a pseudonym. The signing key is available
    /// at the FFI bridge layer but NOT in the runtime lifecycle methods, so
    /// this method is separated from the create/join paths.
    ///
    /// Best-effort: logs a warning but does not fail if the announcement
    /// cannot be sent (e.g. transport not yet connected, or the context is
    /// a single-member context with nobody to announce to).
    ///
    /// # Arguments
    ///
    /// * `handle` -- The context handle.
    /// * `sender_did` -- The announcing member's DID.
    /// * `signing_key` -- Ed25519 signing key for MLS application message.
    pub async fn send_pseudonym_announcement(
        &self,
        handle: &ContextHandle,
        sender_did: &DID,
        signing_key: &ed25519_dalek::SigningKey,
    ) {
        let context_id = handle.context_id().to_owned();
        let pseudonym = {
            let Ok(ctx_arc) = self.get_context_arc(&context_id) else {
                return;
            };
            let guard = ctx_arc.lock().await;
            guard.local_pseudonym
        };
        let Some(pseudonym) = pseudonym else {
            return;
        };
        let announcement = super::PseudonymAnnouncement {
            tag: super::PSEUDONYM_ANNOUNCEMENT_TAG.to_owned(),
            member_did: sender_did.as_ref().to_owned(),
            pseudonym,
        };
        let Ok(payload) = rmp_serde::to_vec_named(&announcement) else {
            tracing::warn!(
                context_id = %context_id,
                "failed to serialize pseudonym announcement"
            );
            return;
        };
        if let Err(e) = self
            .send_message(handle, sender_did, &payload, Some(signing_key), None, None)
            .await
        {
            tracing::warn!(
                context_id = %context_id,
                error = %e,
                "failed to send pseudonym announcement — other members will use shared routing"
            );
        }
    }

    /// Removes a member from a context.
    ///
    /// Authorization: the caller must either be removing themselves
    /// (`caller_did == member_did`, self-removal) or hold the `MemberRemove`
    /// capability. Self-removal is always permitted regardless of role.
    ///
    /// Removes from MLS group (ADR-001), removes sender keys, and appends
    /// a `MemberLeft` event. If the member count reaches zero, transitions
    /// the context to `Closing`.
    ///
    /// See ADR-008 acceptance criterion 4.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] if:
    /// - The context is not in `Active` state.
    /// - The caller is neither the member being removed nor holds `MemberRemove`.
    /// - The member is not found.
    /// Legacy one-line forwarder to the hoisted
    /// [`crate::context::lifecycle_helpers::leave_context`] free
    /// function (ADR-049 commit 12c.2). Deleted in a later commit
    /// alongside every other `ContextManager` lifecycle surface.
    #[instrument(skip_all, fields(context_id = handle.context_id()))]
    pub async fn leave_context(
        &self,
        handle: &ContextHandle,
        caller_did: &DID,
        member_did: &DID,
    ) -> Result<(), ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::leave_context — Supervisor must be attached".to_owned(),
            )
        })?;
        crate::context::lifecycle_helpers::leave_context(&sup, handle, caller_did, member_did).await
    }

    /// Drains pending sender key distribution messages and delivers them
    /// via transport (§9.16.2). Legacy one-line forwarder to the hoisted
    /// [`crate::context::lifecycle_helpers::drain_and_deliver_sender_keys`]
    /// free function (ADR-049 commit 12c.2). Deleted in a later commit
    /// alongside every other `ContextManager` lifecycle surface.
    pub(crate) fn drain_and_deliver_sender_keys(
        &self,
        context_id: &str,
        context_id_bytes: &[u8; 32],
    ) -> Result<(), ContextError> {
        let sup = self.supervisor().ok_or_else(|| {
            ContextError::NotInitialized(
                "ContextManager::drain_and_deliver_sender_keys — Supervisor must be attached"
                    .to_owned(),
            )
        })?;
        crate::context::lifecycle_helpers::drain_and_deliver_sender_keys(
            &sup,
            context_id,
            context_id_bytes,
        )
    }
}
