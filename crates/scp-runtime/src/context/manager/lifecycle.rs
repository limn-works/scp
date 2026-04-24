//! Context lifecycle: create, join, leave, restore, export, import.

use std::collections::VecDeque;

use super::{
    AccessControlState, Arc, BroadcastAdmission, BroadcastContext, Capability, CapabilityCeiling,
    CommitOperation, ContextCreationError, ContextError, ContextEvent, ContextHandle,
    ContextManager, ContextMode, ContextParams, ContextRoleState, ContextSnapshot, ContextState,
    DID, DeadlockDetectionState, EpochCoordinator, EpochState, GovernanceModel,
    GovernanceModelConfig, GovernanceState, GovernanceTimeoutTask, HashMap, HashSet, KeyPackage,
    MemberBudgetTracker, MembershipState, PerContextState, ReceiveBuffer, TemplateId, TtlState,
    TtlTimer, build_governance_engine, builder_create_context, context_id_to_bytes,
    create_governance_engine, instrument, mint_governance_tokens, push_welcome_event,
    require_active, restore_governance_engine_from_snapshot, restore_grace_store_from_snapshot,
    roles, validate_governance_consistency, validate_governance_model,
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
fn validate_consequence_rules(
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
fn sanitize_cooldown_until(
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
fn validate_consequence_rules_for_import(
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
pub(super) fn evaluate_sybil_resistance(
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
fn post_join_bookkeeping(
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
/// `MessageSend`, `ContextJoin`, and `OutletCall`, plus the Matrix-style
/// hard rate limit. The `_economic_policy` parameter is intentionally
/// unused — it is kept in the signature so call-sites stay symmetrical
/// with the old `derive_relay_pricing_config` while documenting that
/// pricing is uniform across all contexts. Per-context pricing
/// customization will land via governance in a follow-up PR.
#[allow(clippy::unnecessary_wraps)] // Option return kept for forward compat
// with per-context pricing customization landing via governance.
fn derive_message_pricing(
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
fn enforce_join_economy(
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
                registered_outlets: ctx_snapshot.registered_outlets,
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

    /// Generates the initial access key store for context creation (§9.17.2).
    fn generate_initial_access_key_store(
        context_id: &str,
        creator_did: &DID,
    ) -> scp_protocol::crypto::access_keys::AccessKeyStore {
        let mut store = scp_protocol::crypto::access_keys::AccessKeyStore::new();
        let key = scp_protocol::crypto::access_keys::generate_access_key(
            context_id,
            creator_did.as_ref(),
        );
        store.set(context_id, creator_did.as_ref(), key);
        store
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
    pub async fn export_context(
        &self,
        context_id: &str,
        exporter_did: DID,
    ) -> Result<crate::context::export_import::ContextExport, ContextError> {
        let ctx_id_bytes = scp_protocol::context::context_id_bytes(context_id);

        let snapshot = {
            let ctx_arc = self.get_context_arc(context_id).map_err(|_| {
                ContextError::MembershipFailed(format!(
                    "context '{context_id}' not found — cannot export"
                ))
            })?;
            let guard = ctx_arc.lock().await;
            let ctx = &*guard;
            Self::snapshot_context(ctx)
        };

        let event_log_data = self
            .event_log
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
            &*self.clock,
        )
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
    #[instrument(skip_all)]
    #[allow(clippy::too_many_lines)] // Reimport guard adds 10 lines to an already-100-line function.
    pub async fn import_context(
        &self,
        export: crate::context::export_import::ContextExport,
    ) -> Result<ContextHandle, ContextError> {
        // 1. Validate export.
        crate::context::export_import::validate_export_for_import(&export)?;
        // C3: Validate consequence rules on import. Uses
        // validate_against_config to enforce the opt-in gate for
        // RevokeAccess even on imported snapshots and rejects with the
        // canonical SCP-CTX-2092 envelope so SDK callers can detect
        // structural rejection by `.code` rather than message body.
        validate_consequence_rules_for_import(
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
            if let Ok(ctx_arc) = self.get_context_arc(&context_id) {
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
                let local_epoch_floors = self.crypto.export_sender_key_epochs(&ctx_id_bytes);

                // Clean up old crypto state before reimport.
                let _ = self.crypto.destroy_mls_group(&ctx_id_bytes);
                let _ = self.crypto.destroy_sender_key(&ctx_id_bytes);

                // Restore incoming crypto state (if the export carries any).
                if !export.mls_state.is_empty() {
                    self.crypto
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
                if let Err(e) = self.crypto.validate_and_merge_epoch_floors(
                    &ctx_id_bytes,
                    local_epoch_floors,
                    crate::crypto::mls::provider::MAX_EPOCH_ADVANCE,
                ) {
                    // Rollback: destroy the just-restored crypto state so the
                    // provider is not left with partially-merged floors.
                    let _ = self.crypto.destroy_mls_group(&ctx_id_bytes);
                    let _ = self.crypto.destroy_sender_key(&ctx_id_bytes);
                    return Err(e);
                }
            } else if !export.mls_state.is_empty() {
                // Fresh slot (no prior context): restore crypto state directly.
                // No local floors to defend — `validate_and_merge_epoch_floors`
                // is a no-op when `local_floors` is empty, so the ceiling guard
                // does not apply on this path. We still restore so MLS group
                // and sender keys are available immediately after import.
                self.crypto
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
            self.event_log
                .import_event_log_data(&ctx_id_bytes, &export.event_log_data)?;
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
            restore_governance_engine_from_snapshot(&export.snapshot, self.key_resolver.clone())?;

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
        let now_for_validation = self.clock.now_secs();
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
                scp_protocol::economy::antispam::SenderVelocityTracker
                    ::validate_and_sanitize_snapshot(
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
        let validated_message_pricing = export
            .snapshot
            .message_pricing
            .clone()
            .or_else(|| derive_message_pricing(export.snapshot.economic_policy.as_ref()));
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
        sanitize_cooldown_until(
            &mut sanitized_cooldown_until,
            &export.snapshot.consequence_rules,
            now_for_validation,
            "import",
        );

        let per_context = PerContextState {
            generation: self
                .next_generation
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            handle: handle.clone(),
            membership: export.snapshot.membership,
            role_state: export.snapshot.role_state,
            receive_buffer: ReceiveBuffer::new(),
            broadcast_context: None,
            migration_state: None,
            governance: GovernanceState {
                engine: governance_engine,
                executed_proposals: {
                    let now = self.clock.now_secs();
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
                registered_outlets: export.snapshot.registered_outlets,
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
                    Arc::clone(&self.clock),
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
                timer: TtlTimer::with_clock(Arc::clone(&self.clock)),
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
            checkpoint_last_time_secs: self.clock.now_secs(),
            checkpoints: Vec::new(),
            // Fresh Merkle tree for imported contexts. Proofs cover
            // post-import events only (same rationale as restore_context).
            merkle_tree: scp_event_log::EventLog::new(context_id.clone()),
            // §9.10.4: pseudonym state is local-instance — wiped on import.
            // The importing member must re-derive and re-announce.
            local_pseudonym: None,
            pseudonym_registry: HashMap::new(),
        };

        // 7. Register the context.
        //    Re-check replaceability under the lock to close the TOCTOU gap
        //    between step 2 (which dropped the lock for event log import) and
        //    this insertion. A concurrent `create_context` or `import_context`
        //    could have registered an Active context in the meantime.
        {
            if let Ok(ctx_arc) = self.get_context_arc(&context_id) {
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
            }
            self.remove_context(&context_id);
            self.insert_context(context_id.clone(), per_context)
                .map_err(|e| ContextError::MembershipFailed(e.to_string()))?;
        }

        self.update_context_gauges();

        // Start governance timeout task (ADR-031 §5).
        self.start_governance_timeout_task(&context_id).await;

        // 8. Persist if persistence is configured.
        if self.has_persistence()
            && let Ok(ctx_arc) = self.get_context_arc(&context_id)
        {
            let guard = ctx_arc.lock().await;
            let ctx = &*guard;
            let snap = Self::snapshot_context(ctx);
            self.persist_context_snapshot(&context_id, snap);
        }

        // 9. Re-spawn TTL timer if there was remaining TTL.
        if let Some(remaining_secs) = export.snapshot.ttl_remaining_secs {
            let duration = std::time::Duration::from_secs(remaining_secs);
            self.spawn_ttl_timer(&context_id, duration, handle.clone())
                .await;
        }

        Ok(handle)
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
    #[allow(clippy::too_many_lines)] // Context creation initializes many subsystems including pseudonym routing.
    #[instrument(skip_all, fields(context_id = %context_id))]
    pub async fn create_context(
        &self,
        context_id: String,
        params: ContextParams,
        creator_did: DID,
        local_pseudonym: Option<[u8; 32]>,
    ) -> Result<ContextHandle, ContextCreationError> {
        // Defense-in-depth: verify creator's SDK version satisfies min_protocol_version.
        params.check_version_compatibility(scp_protocol::envelope::SCP_PROTOCOL_VERSION)?;
        validate_governance_model(&params.governance)?;
        validate_consequence_rules(&params.consequence_rules, &params.consequence_config)?;
        scp_protocol::economy::policy::validate_economic_policy_metrics(
            params.economic_policy.as_ref(),
        )
        .map_err(|e| ContextCreationError::CreationFailed(e.to_string()))?;
        let governance_engine =
            create_governance_engine(&params.governance, &creator_did, self.key_resolver.clone())?;
        let handle = builder_create_context(
            context_id.clone(),
            params.clone(),
            self.crypto.as_ref(),
            self.transport.as_ref(),
            self.event_log.as_ref(),
            creator_did.as_ref(),
        )
        .await?;
        let ceiling = CapabilityCeiling::new(params.ceiling.iter().cloned());
        let role_state =
            ContextRoleState::new(&context_id, &*creator_did, ceiling, vec![], &*self.clock)
                .map_err(|e| ContextCreationError::CreationFailed(e.to_string()))?;
        let mut membership = MembershipState::new();
        let creator_tokens = role_state
            .assignments
            .get(creator_did.as_ref())
            .map(|a| a.tokens.clone())
            .unwrap_or_default();
        membership.add_member(creator_did.clone(), "admin".into(), creator_tokens);
        let broadcast_context = self.init_broadcast_context(&context_id, &params, &creator_did)?;
        let (initial_threshold_signers, initial_threshold_value) = match &params.governance {
            GovernanceModel::Threshold { threshold, signers } => (signers.clone(), *threshold),
            _ => (Vec::new(), 0),
        };
        let initial_access_key_store =
            Self::generate_initial_access_key_store(&context_id, &creator_did);
        let initial_members: HashSet<DID> = membership.members().map(|m| m.did.clone()).collect();
        let per_context = PerContextState {
            generation: self
                .next_generation
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
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
                registered_outlets: Vec::new(),
                tool_interfaces: Vec::new(),
                pruning_policy: None,
                message_pricing: derive_message_pricing(params.economic_policy.as_ref()),
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
                    Arc::clone(&self.clock),
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
            merkle_tree: scp_event_log::EventLog::new(context_id.clone()),
            // §9.10.4: pseudonym routing. Only meaningful for encrypted
            // contexts; broadcast contexts ignore this field.
            local_pseudonym,
            pseudonym_registry: HashMap::new(),
        };

        // Atomic check-and-insert — eliminates TOCTOU race between
        // contains_key and insert.
        self.insert_context(context_id.clone(), per_context)?;
        self.finalize_create(&context_id, params.ttl, &handle).await;
        Ok(handle)
    }

    /// Post-creation finalization: gauges, governance timeout, persistence, TTL timer.
    async fn finalize_create(
        &self,
        context_id: &str,
        ttl: Option<std::time::Duration>,
        handle: &ContextHandle,
    ) {
        self.update_context_gauges();
        self.start_governance_timeout_task(context_id).await;
        self.persist_context_and_broadcast(context_id).await;
        if let Some(ttl_duration) = ttl {
            self.spawn_ttl_timer(context_id, ttl_duration, handle.clone())
                .await;
        }
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
                registered_outlets: Vec::new(),
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
    #[allow(clippy::too_many_lines)]
    #[instrument(skip_all, fields(context_id = handle.context_id()))]
    pub async fn join_context(
        &self,
        handle: &ContextHandle,
        key_package: KeyPackage,
        spending_ucan: Option<&scp_protocol::crypto::ucan::UcanToken>,
        local_pseudonym: Option<[u8; 32]>,
    ) -> Result<(), ContextError> {
        let context_id = handle.context_id().to_owned();
        let context_id_bytes = context_id_to_bytes(&context_id);
        let member_did = key_package.owner_did.clone();

        // Fast-fail: reject obviously incompatible versions before expensive
        // crypto ops (MLS group join, sender key derivation). Looks up the
        // stored context's params (not the caller-supplied handle params)
        // so this check is authoritative even when the caller passes an
        // ephemeral handle with default params (e.g. UniFFI bridge).
        {
            let ctx_arc = self
                .get_context_arc(&context_id)
                .map_err(|_| ContextError::ContextNotRegistered(context_id.clone()))?;
            let guard = ctx_arc.lock().await;
            let ctx = &*guard;
            ctx.handle
                .params()
                .check_version_compatibility(scp_protocol::envelope::SCP_PROTOCOL_VERSION)?;
        }

        // Validate key package before any mutations (idempotent, no lock needed).
        let kp_bytes = key_package.mls_key_package_bytes.as_deref();
        self.crypto.validate_key_package(&member_did, kp_bytes)?;

        // Phase 1: Economy enforcement + sybil check under lock (budget deduction).
        // This happens BEFORE any crypto mutations so that a rejected payment
        // never grants MLS group access or sender keys.
        // Capture generation for confused-deputy detection on rollback reacquire.
        let (ticket, ctx_gen) = {
            let (mut guard, ctx_gen) = self
                .lock_context(&context_id)
                .await
                .map_err(|_| ContextError::ContextNotRegistered(context_id.clone()))?;
            let ctx = &mut *guard;

            // State check inside lock -- eliminates TOCTOU race.
            require_active(&ctx.handle)?;

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
            evaluate_sybil_resistance(ctx, &member_did, self.clock.now_secs())?;

            // Defense-in-depth hard rate limit on joins (Matrix-style token
            // bucket). On any subsequent failure we refund the token.
            let now_secs = self.clock.now_secs();
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

            let deducted_cost = match enforce_join_economy(
                ctx,
                &member_did,
                now_secs,
                spending_ucan,
                &context_id,
                &*self.clock,
                &self.key_resolver,
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
                super::economy::EconomyTicket {
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
        let auth = match self
            .authorize_paid_action(
                scp_protocol::economy::types::PaidActionType::ContextJoin,
                &member_did,
                &context_id,
            )
            .await
        {
            Ok(auth) => auth,
            Err(payment_err) => {
                super::economy::rollback_economy_ticket(self, &context_id, ticket, &ctx_gen).await;
                return Err(payment_err);
            }
        };

        // Phase 3: MLS add_member + sender key distribution (crypto mutations).
        // On failure: void escrow + rollback ticket. No MLS rollback needed
        // because add_member itself failed (no state change occurred).
        let add_output = match self
            .crypto
            .add_member(&context_id_bytes, &member_did, kp_bytes)
        {
            Ok(output) => output,
            Err(e) => {
                if let Some(a) = auth {
                    self.void_paid_action(a, &context_id).await;
                }
                super::economy::rollback_economy_ticket(self, &context_id, ticket, &ctx_gen).await;
                return Err(e);
            }
        };

        if let Err(e) = self
            .crypto
            .distribute_sender_key(&context_id_bytes, &member_did)
        {
            // Sender key distribution failed after MLS add — rollback MLS state.
            let _ = self.crypto.remove_member(&context_id_bytes, &member_did);
            let _ = self
                .crypto
                .remove_member_sender_key(&context_id_bytes, &member_did);
            if let Some(a) = auth {
                self.void_paid_action(a, &context_id).await;
            }
            super::economy::rollback_economy_ticket(self, &context_id, ticket, &ctx_gen).await;
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
        if let Err(e) = self.drain_and_deliver_sender_keys(&context_id, &context_id_bytes) {
            // Drain failed catastrophically — roll back MLS state, sender
            // key, escrow, and economy ticket so the join is fully aborted.
            let _ = self.crypto.remove_member(&context_id_bytes, &member_did);
            let _ = self
                .crypto
                .remove_member_sender_key(&context_id_bytes, &member_did);
            if let Some(a) = auth {
                self.void_paid_action(a, &context_id).await;
            }
            super::economy::rollback_economy_ticket(self, &context_id, ticket, &ctx_gen).await;
            return Err(e);
        }

        // Phase 4: Membership mutation under lock. On failure: void escrow +
        // rollback ticket + rollback MLS state.
        if let Err(e) = self
            .join_context_membership(&context_id, &member_did, add_output)
            .await
        {
            let _ = self.crypto.remove_member(&context_id_bytes, &member_did);
            let _ = self
                .crypto
                .remove_member_sender_key(&context_id_bytes, &member_did);
            if let Some(a) = auth {
                self.void_paid_action(a, &context_id).await;
            }
            super::economy::rollback_economy_ticket(self, &context_id, ticket, &ctx_gen).await;
            return Err(e);
        }

        // Phase 4.5: Store local pseudonym after membership mutation succeeds.
        // The pseudonym was pre-derived by the FFI bridge; storing it here
        // makes it available for subsequent send_message fan-out (§9.10.4).
        if let Some(pseudonym) = local_pseudonym
            && let Ok(ctx_arc) = self.get_context_arc(&context_id)
        {
            let mut guard = ctx_arc.lock().await;
            let ctx = &mut *guard;
            ctx.local_pseudonym = Some(pseudonym);
        }

        // Phase 5: Capture the escrow hold after all mutations succeeded.
        // Consume the ticket — commit returns the deducted cost for the
        // capture step and marks the ticket as committed so the Drop
        // guard stays quiet.
        let deducted_cost = super::economy::commit_economy_ticket(ticket);
        self.capture_join_payment(auth, &member_did, &context_id, deducted_cost)
            .await;

        // Append MemberJoined event to event log.
        self.event_log.append_context_event(
            &context_id_bytes,
            "MemberJoined",
            member_did.as_ref(),
        )?;
        {
            if let Ok(ctx_arc) = self.get_context_arc(&context_id) {
                let mut guard = ctx_arc.lock().await;
                let ctx = &mut *guard;
                ctx.checkpoint_events_since += 1;
            }
        }
        // Persist context state after join (best-effort).
        if self.has_persistence()
            && let Ok(ctx_arc) = self.get_context_arc(&context_id)
        {
            let guard = ctx_arc.lock().await;
            let ctx = &*guard;
            let snapshot = Self::snapshot_context(ctx);
            self.persist_context_snapshot(&context_id, snapshot);
        }

        Ok(())
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

    /// Performs the membership state mutations for `join_context` (Phase 4).
    ///
    /// Extracted to keep `join_context` within the clippy `too_many_lines` limit.
    /// Acquires the contexts lock, verifies Active state, then performs
    /// bookkeeping, role assignment, membership add, access key generation,
    /// and event buffer pushes.
    async fn join_context_membership(
        &self,
        context_id: &str,
        member_did: &DID,
        add_output: scp_protocol::context::builder::AddMemberOutput,
    ) -> Result<(), ContextError> {
        let ctx_arc = self
            .get_context_arc(context_id)
            .map_err(|_| ContextError::ContextNotRegistered(context_id.to_owned()))?;
        let mut guard = ctx_arc.lock().await;
        let ctx = &mut *guard;

        require_active(&ctx.handle)?;

        post_join_bookkeeping(
            ctx,
            context_id,
            member_did,
            self.clock.now_secs(),
            &*self.event_log,
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
        let tokens =
            roles::system_assign_role(&mut ctx.role_state, member_did, "member", &*self.clock)
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
        ctx.emit_event(join_event, context_id, self.event_tx.as_ref());

        // Emit WelcomeGenerated event if the add produced a Welcome message.
        push_welcome_event(
            ctx,
            context_id,
            &DID(creator_did),
            member_did,
            add_output,
            self.event_tx.as_ref(),
        );

        Ok(())
    }

    /// Captures the escrow hold after a successful join (Phase 5 of `join_context`).
    ///
    /// Best-effort: if capture fails, logs a warning but does NOT roll back
    /// the budget and does NOT fail the join (the member was already added).
    /// The service was rendered, so the budget deduction stands (H8).
    ///
    /// On failure a `PaymentCaptureFailed` entry is appended to the event log
    /// and pushed to the receive buffer to provide a durable audit trail (H19).
    async fn capture_join_payment(
        &self,
        auth: Option<super::economy::PaidActionAuthorization>,
        member_did: &DID,
        context_id: &str,
        deducted_cost: Option<scp_protocol::economy::types::Amount>,
    ) {
        if let Some(a) = auth
            && let Err(e) = self.complete_paid_action(a, member_did, context_id).await
        {
            // H8: do NOT rollback budget — service was delivered (member joined).
            tracing::warn!(
                context_id,
                "payment capture failed after successful join: {e}"
            );
            // H19: append durable audit record to event log + receive buffer.
            self.record_payment_capture_failure(
                context_id,
                "join_context",
                member_did,
                &e.to_string(),
                deducted_cost,
            )
            .await;
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
    #[allow(clippy::too_many_lines)]
    #[instrument(skip_all, fields(context_id = handle.context_id()))]
    pub async fn leave_context(
        &self,
        handle: &ContextHandle,
        caller_did: &DID,
        member_did: &DID,
    ) -> Result<(), ContextError> {
        let context_id = handle.context_id().to_owned();
        let context_id_bytes = context_id_to_bytes(&context_id);

        // Determine broadcast mode + authorization in a single lock acquire.
        // PR #1606 C6: also check the commit fault marker so a fail-closed
        // context refuses further leave operations until an operator
        // acknowledges the fault.
        // Use lock_context to capture a generation token for confused-deputy
        // detection in subsequent lock scopes (Phase B).
        let (is_broadcast, ctx_gen) = {
            let (guard, generation) = self.lock_context(&context_id).await?;
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
            Self::check_commit_fault(ctx)?;
            (ctx.broadcast_context.is_some(), generation)
        };

        // Crypto operations -- no lock held. Skip for broadcast mode (no MLS).
        // H9: MLS group removal FIRST (hard security boundary), then sender
        // key cleanup as best-effort. MLS removal is the cryptographic
        // enforcement; sender key removal is defense-in-depth (§9.16).
        if !is_broadcast {
            let remove_output = self.crypto.remove_member(&context_id_bytes, member_did)?;
            if let Err(e) = self
                .crypto
                .remove_member_sender_key(&context_id_bytes, member_did)
            {
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
            self.try_broadcast_commit_or_enqueue(
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
            if let Err(e) = self.crypto.rotate_sender_key(&context_id_bytes) {
                tracing::warn!(
                    context_id = %context_id,
                    error = %e,
                    "rotate_sender_key failed after leave — \
                     remaining members retain old sender key"
                );
            }
            if let Err(e) = self.drain_and_deliver_sender_keys(&context_id, &context_id_bytes) {
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
            let mut guard = self.relock_context(&ctx_gen).await?;
            let ctx = &mut *guard;

            // State check inside lock -- eliminates TOCTOU race.
            require_active(&ctx.handle)?;

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
            ctx.emit_event(left_event, &context_id, self.event_tx.as_ref());

            ctx.membership.count() == 0
        };
        // Lock dropped.

        // Append MemberLeft event to event log.
        self.event_log.append_context_event(
            &context_id_bytes,
            "MemberLeft",
            member_did.as_ref(),
        )?;
        // Use relock_context for generation verification (Phase B).
        if let Ok(mut guard) = self.relock_context(&ctx_gen).await {
            let ctx = &mut *guard;
            ctx.checkpoint_events_since += 1;
        } else {
            tracing::warn!(
                context_id = %context_id,
                "leave_context: generation mismatch — checkpoint counter not incremented"
            );
        }
        // Persist context state after leave (best-effort).
        if self.has_persistence()
            && let Ok(guard) = self.relock_context(&ctx_gen).await
        {
            let ctx = &*guard;
            let snapshot = Self::snapshot_context(ctx);
            self.persist_context_snapshot(&context_id, snapshot);
        }

        // If member count reaches zero, transition to Closing.
        if should_close {
            handle.transition_to(&ContextState::Closing).await?;
        }

        Ok(())
    }

    /// Drains pending sender key distribution messages and delivers them
    /// via transport (§9.16.2). Called after `rotate_sender_key` to send
    /// HPKE-sealed sender key responses to remaining members.
    pub(super) fn drain_and_deliver_sender_keys(
        &self,
        context_id: &str,
        context_id_bytes: &[u8; 32],
    ) -> Result<(), ContextError> {
        let pending = self
            .crypto
            .drain_pending_sender_key_messages(context_id_bytes)?;
        if !pending.is_empty() {
            let routing_id = scp_protocol::context::context_routing_id(context_id);
            for (target_did, message) in pending {
                tracing::debug!(
                    target_did = %target_did,
                    context_id = %context_id,
                    message_len = message.len(),
                    "MLS-encrypting and sending rotated sender key distribution"
                );
                match self.crypto.mls_encrypt_management(
                    context_id_bytes,
                    &message,
                    &routing_id,
                    super::messaging::DEFAULT_BLOB_TTL_SECS,
                ) {
                    Ok(sealed) => {
                        if let Err(e) = self.transport.send_message(&routing_id, &sealed) {
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
}
