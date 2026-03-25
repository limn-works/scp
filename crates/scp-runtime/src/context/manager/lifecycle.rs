//! Context lifecycle: create, join, leave, restore, export, import.

use super::{
    AccessControlState, Arc, BroadcastAdmission, BroadcastContext, Capability, CapabilityCeiling,
    ContextCreationError, ContextError, ContextEvent, ContextHandle, ContextManager, ContextMode,
    ContextParams, ContextRoleState, ContextSnapshot, ContextState, DID, DeadlockDetectionState,
    EpochCoordinator, EpochState, GovernanceModel, GovernanceModelConfig, GovernanceState,
    GovernanceTimeoutTask, HashMap, HashSet, KeyPackage, MemberBudgetTracker, MembershipState,
    PerContextState, ReceiveBuffer, TemplateId, TtlState, TtlTimer, build_governance_engine,
    builder_create_context, context_id_to_bytes, create_governance_engine, instrument,
    mint_governance_tokens, push_welcome_event, require_active,
    restore_governance_engine_from_snapshot, restore_grace_store_from_snapshot, roles,
    validate_governance_consistency, validate_governance_model,
};

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
    pub async fn restore_context(
        &self,
        context_id: &str,
        handle: &ContextHandle,
    ) -> Result<(), ContextError> {
        let (ctx_snapshot, broadcast_ctx) = self.load_persisted_context_state(context_id)?;
        self.restore_event_log_best_effort(context_id);
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
        let per_context = PerContextState {
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
                economic_policy: ctx_snapshot.economic_policy,
                budget_tracker: ctx_snapshot.budget_tracker,
                last_known_members: last_members,
                pending_epoch_resets: Vec::new(),
                consequence_rules: ctx_snapshot.consequence_rules,
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
                write_revoked_members: ctx_snapshot.write_revoked_members,
                read_revoked_members: ctx_snapshot.read_revoked_members,
                read_exclusion_list: ctx_snapshot.read_exclusion_list,
                access_key_store: ctx_snapshot.access_key_store,
            },
            ttl: TtlState {
                timer: TtlTimer::with_clock(Arc::clone(&self.clock)),
                extension: None,
            },
            sequence_tracker: scp_protocol::envelope::SequenceTracker::new(),
            reorder_buffer: scp_protocol::envelope::ReorderBuffer::default(),
        };

        {
            let mut contexts = self.contexts.lock().await;
            if contexts.contains_key(context_id) {
                return Err(ContextError::MembershipFailed(format!(
                    "context '{context_id}' already registered"
                )));
            }
            contexts.insert(context_id.to_owned(), per_context);
        }

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
        self.contexts
            .lock()
            .await
            .get(context_id)
            .is_some_and(|ctx| ctx.epoch.needs_reconnect)
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
        if let Some(ctx) = self.contexts.lock().await.get_mut(context_id) {
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
        self.contexts
            .lock()
            .await
            .iter()
            .filter(|(_, ctx)| ctx.epoch.needs_reconnect)
            .map(|(id, _)| id.clone())
            .collect()
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
            let contexts = self.contexts.lock().await;
            let ctx = contexts.get(context_id).ok_or_else(|| {
                ContextError::MembershipFailed(format!(
                    "context '{context_id}' not found — cannot export"
                ))
            })?;
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
    #[instrument(skip_all)]
    #[allow(clippy::too_many_lines)] // Reimport guard adds 10 lines to an already-100-line function.
    pub async fn import_context(
        &self,
        export: crate::context::export_import::ContextExport,
    ) -> Result<ContextHandle, ContextError> {
        // 1. Validate export.
        crate::context::export_import::validate_export_for_import(&export)?;

        let context_id = export.snapshot.context_id.clone();
        let ctx_id_bytes = scp_protocol::context::context_id_bytes(&context_id);

        // 2. Check context existence BEFORE importing event log data.
        //    If the context is Active, we must reject early — otherwise the
        //    event log import at step 3 would overwrite the Active context's
        //    Merkle chain before we discover the conflict.
        {
            let contexts = self.contexts.lock().await;
            if let Some(existing) = contexts.get(&context_id) {
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
                // Clean up old crypto state before reimport
                let _ = self.crypto.destroy_mls_group(&ctx_id_bytes);
                let _ = self.crypto.destroy_sender_key(&ctx_id_bytes);
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

        let per_context = PerContextState {
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
                approved_proposals: export.snapshot.approved_proposals,
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
                economic_policy: export.snapshot.economic_policy,
                budget_tracker: export.snapshot.budget_tracker,
                last_known_members: initial_members,
                pending_epoch_resets: Vec::new(),
                consequence_rules: export.snapshot.consequence_rules,
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
                write_revoked_members: export.snapshot.write_revoked_members,
                read_revoked_members: export.snapshot.read_revoked_members,
                read_exclusion_list: export.snapshot.read_exclusion_list,
                access_key_store: export.snapshot.access_key_store,
            },
            ttl: TtlState {
                timer: TtlTimer::with_clock(Arc::clone(&self.clock)),
                extension: None,
            },
            sequence_tracker: scp_protocol::envelope::SequenceTracker::new(),
            reorder_buffer: scp_protocol::envelope::ReorderBuffer::default(),
        };

        // 7. Register the context.
        //    Re-check replaceability under the lock to close the TOCTOU gap
        //    between step 2 (which dropped the lock for event log import) and
        //    this insertion. A concurrent `create_context` or `import_context`
        //    could have registered an Active context in the meantime.
        {
            let mut contexts = self.contexts.lock().await;
            if let Some(existing) = contexts.get(&context_id) {
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
            contexts.remove(&context_id);
            contexts.insert(context_id.clone(), per_context);
        }

        self.update_context_gauges().await;

        // Start governance timeout task (ADR-031 §5).
        self.start_governance_timeout_task(&context_id).await;

        // 8. Persist if persistence is configured.
        if self.has_persistence() {
            let contexts = self.contexts.lock().await;
            if let Some(ctx) = contexts.get(&context_id) {
                let snap = Self::snapshot_context(ctx);
                drop(contexts);
                self.persist_context_snapshot(&context_id, snap);
            }
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
    #[instrument(skip_all, fields(context_id = %context_id))]
    pub async fn create_context(
        &self,
        context_id: String,
        params: ContextParams,
        creator_did: DID,
    ) -> Result<ContextHandle, ContextCreationError> {
        // Defense-in-depth: verify creator's SDK version satisfies min_protocol_version.
        params.check_version_compatibility(scp_protocol::envelope::SCP_PROTOCOL_VERSION)?;
        validate_governance_model(&params.governance)?;
        let governance_engine =
            create_governance_engine(&params.governance, &creator_did, self.key_resolver.clone())?;
        let handle = builder_create_context(
            context_id.clone(),
            params.clone(),
            self.crypto.as_ref(),
            self.transport.as_ref(),
            self.event_log.as_ref(),
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
            handle: handle.clone(),
            membership,
            governance: GovernanceState {
                engine: governance_engine,
                executed_proposals: HashMap::new(),
                approved_proposals: HashMap::new(),
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
                economic_policy: params.economic_policy.clone(),
                budget_tracker: MemberBudgetTracker::new(),
                last_known_members: initial_members,
                pending_epoch_resets: Vec::new(),
                consequence_rules: Vec::new(),
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
                write_revoked_members: HashSet::new(),
                read_revoked_members: HashSet::new(),
                read_exclusion_list: HashSet::new(),
                access_key_store: initial_access_key_store,
            },
            ttl: TtlState {
                timer: TtlTimer::with_clock(Arc::clone(&self.clock)),
                extension: None,
            },
            sequence_tracker: scp_protocol::envelope::SequenceTracker::new(),
            reorder_buffer: scp_protocol::envelope::ReorderBuffer::default(),
        };

        {
            let mut contexts = self.contexts.lock().await;
            if contexts.contains_key(&context_id) {
                return Err(ContextCreationError::CreationFailed(format!(
                    "context '{context_id}' already registered"
                )));
            }
            contexts.insert(context_id.clone(), per_context);
        }
        self.update_context_gauges().await;
        self.start_governance_timeout_task(&context_id).await;
        self.persist_context_and_broadcast(&context_id).await;
        if let Some(ttl_duration) = params.ttl {
            self.spawn_ttl_timer(&context_id, ttl_duration, handle.clone())
                .await;
        }
        Ok(handle)
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
        let mut contexts = self.contexts.lock().await;
        if let Some(ctx) = contexts.get_mut(context_id) {
            let new_handle = ContextHandle::new(context_id.to_owned(), new_params);
            // Preserve the current state.
            let current_state = ctx.handle.state().await;
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

        // Phase 1+2: builder performs validation and creation (async, no lock held).
        let handle = builder_create_context(
            context_id.clone(),
            params.clone(),
            self.crypto.as_ref(),
            self.transport.as_ref(),
            self.event_log.as_ref(),
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

        // Atomic duplicate check + insert under lock.
        {
            let mut contexts = self.contexts.lock().await;
            if contexts.contains_key(&context_id) {
                return Err(ContextCreationError::CreationFailed(format!(
                    "context '{context_id}' already registered"
                )));
            }
            contexts.insert(context_id.clone(), per_context);
        }

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
    #[allow(clippy::too_many_arguments)] // internal helper, not public API
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
                economic_policy: params.economic_policy.clone(),
                budget_tracker: MemberBudgetTracker::new(),
                last_known_members: HashSet::new(),
                pending_epoch_resets: Vec::new(),
                consequence_rules: Vec::new(),
            },
            epoch: EpochState {
                mls_epoch: 0,
                coordinator: EpochCoordinator::new(),
                grace_store: crate::crypto::mls::epoch_grace::EpochGraceStore::new(),
                needs_reconnect: false,
            },
            access: AccessControlState {
                write_revoked_members: HashSet::new(),
                read_revoked_members: HashSet::new(),
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
    #[instrument(skip_all, fields(context_id = handle.context_id()))]
    pub async fn join_context(
        &self,
        handle: &ContextHandle,
        key_package: KeyPackage,
    ) -> Result<(), ContextError> {
        let context_id = handle.context_id().to_owned();
        let context_id_bytes = context_id_to_bytes(&context_id);
        let routing_id = scp_protocol::context::context_routing_id(&context_id);
        let member_did = key_package.owner_did.clone();

        // Fast-fail: reject obviously incompatible versions before expensive
        // crypto ops (MLS group join, sender key derivation). Looks up the
        // stored context's params (not the caller-supplied handle params)
        // so this check is authoritative even when the caller passes an
        // ephemeral handle with default params (e.g. UniFFI bridge).
        {
            let contexts = self.contexts.lock().await;
            let ctx = contexts
                .get(&context_id)
                .ok_or_else(|| ContextError::ContextNotRegistered(context_id.clone()))?;
            ctx.handle
                .params()
                .check_version_compatibility(scp_protocol::envelope::SCP_PROTOCOL_VERSION)?;
        }

        // Crypto operations -- no lock held, no TOCTOU concern for these
        // provider calls since they are idempotent or externally consistent.
        let kp_bytes = key_package.mls_key_package_bytes.as_deref();
        self.crypto.validate_key_package(&member_did, kp_bytes)?;
        let add_output = self
            .crypto
            .add_member(&context_id_bytes, &member_did, kp_bytes)?;
        self.crypto
            .distribute_sender_key(&context_id_bytes, &member_did)?;

        // Drain pending HPKE-sealed sender key distribution messages.
        // These are SenderKeyResponse payloads that need to be delivered
        // to the target member via transport (§9.16.2).
        let pending = self
            .crypto
            .drain_pending_sender_key_messages(&context_id_bytes)?;
        for (target_did, message) in pending {
            tracing::debug!(
                target_did = %target_did,
                context_id = %context_id,
                message_len = message.len(),
                "sending sender key distribution message"
            );
            if let Err(e) = self.transport.send_message(&routing_id, &message) {
                tracing::warn!(
                    target_did = %target_did,
                    context_id = %context_id,
                    error = %e,
                    "failed to send sender key distribution message — \
                     recipient must request key via SenderKeyRequest"
                );
            }
        }

        // Atomic state check + mutation: verify Active, then role assignment +
        // membership + event buffer, all within a single lock acquisition.
        // The state check is inside the lock to eliminate the TOCTOU race
        // where close_context could transition the state between the check
        // and the mutation.
        {
            let mut contexts = self.contexts.lock().await;
            let ctx = contexts
                .get_mut(&context_id)
                .ok_or_else(|| ContextError::ContextNotRegistered(context_id.clone()))?;

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

            // Add member to role state.
            ctx.role_state.members.insert(member_did.to_string());

            // Assign default "member" role.
            let creator_did = ctx.role_state.creator_did.clone();
            let tokens = roles::assign_role(
                &mut ctx.role_state,
                &member_did,
                "member",
                &creator_did,
                &*self.clock,
            )
            .map_err(|e| ContextError::MembershipFailed(e.to_string()))?;

            // Add to membership tracking.
            ctx.membership
                .add_member(member_did.clone(), "member".into(), tokens);

            // Generate access key for the new member (§9.17.2 step 2).
            // The inviter stores the key so `send_message` can wrap content
            // for this recipient. Key distribution to the joiner happens
            // via the Welcome payload / out-of-band key exchange.
            let member_access_key =
                scp_protocol::crypto::access_keys::generate_access_key(&context_id, &member_did);
            ctx.access
                .access_key_store
                .set(&context_id, &member_did, member_access_key);

            // Emit MemberJoined event to receive buffer.
            ctx.receive_buffer.push(ContextEvent::MemberJoined {
                member_did: member_did.clone(),
                role_name: "member".into(),
            });

            // Emit WelcomeGenerated event if the add produced a Welcome message.
            push_welcome_event(
                &mut ctx.receive_buffer,
                &context_id,
                &DID(creator_did),
                &member_did,
                add_output,
            );
        }
        // Lock dropped before event log append.

        // Append MemberJoined event to event log.
        self.event_log
            .append_context_event(&context_id_bytes, "MemberJoined")?;

        // Persist context state after join (best-effort).
        if self.has_persistence() {
            let contexts = self.contexts.lock().await;
            if let Some(ctx) = contexts.get(&context_id) {
                let snapshot = Self::snapshot_context(ctx);
                drop(contexts);
                self.persist_context_snapshot(&context_id, snapshot);
            }
        }

        Ok(())
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
    #[instrument(skip_all, fields(context_id = handle.context_id()))]
    pub async fn leave_context(
        &self,
        handle: &ContextHandle,
        caller_did: &DID,
        member_did: &DID,
    ) -> Result<(), ContextError> {
        let context_id = handle.context_id().to_owned();
        let context_id_bytes = context_id_to_bytes(&context_id);

        // Determine if this is a broadcast context (lock, read, drop).
        let is_broadcast = {
            let contexts = self.contexts.lock().await;
            let ctx = contexts
                .get(&context_id)
                .ok_or_else(|| ContextError::ContextNotRegistered(context_id.clone()))?;
            ctx.broadcast_context.is_some()
        };

        // Authorization check: self-removal is always allowed; otherwise
        // the caller must hold MemberRemove capability.
        if caller_did != member_did {
            let contexts = self.contexts.lock().await;
            let ctx = contexts
                .get(&context_id)
                .ok_or_else(|| ContextError::ContextNotRegistered(context_id.clone()))?;
            if !ctx
                .role_state
                .member_has_capability(caller_did, &Capability::MemberRemove)
            {
                return Err(ContextError::PermissionDenied(
                    "caller lacks permission to remove this member".into(),
                ));
            }
            drop(contexts);
        }

        // Crypto operations -- no lock held. Skip for broadcast mode (no MLS).
        if !is_broadcast {
            self.crypto.remove_member(&context_id_bytes, member_did)?;
            self.crypto
                .remove_member_sender_key(&context_id_bytes, member_did)?;
        }

        // Atomic state check + membership removal + count check within single lock.
        let should_close = {
            let mut contexts = self.contexts.lock().await;
            let ctx = contexts
                .get_mut(&context_id)
                .ok_or_else(|| ContextError::ContextNotRegistered(context_id.clone()))?;

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

            // Emit MemberLeft event to receive buffer.
            ctx.receive_buffer.push(ContextEvent::MemberLeft {
                member_did: member_did.clone(),
            });

            ctx.membership.count() == 0
        };
        // Lock dropped.

        // Append MemberLeft event to event log.
        self.event_log
            .append_context_event(&context_id_bytes, "MemberLeft")?;

        // Persist context state after leave (best-effort).
        if self.has_persistence() {
            let contexts = self.contexts.lock().await;
            if let Some(ctx) = contexts.get(&context_id) {
                let snapshot = Self::snapshot_context(ctx);
                drop(contexts);
                self.persist_context_snapshot(&context_id, snapshot);
            }
        }

        // If member count reaches zero, transition to Closing.
        if should_close {
            handle.transition_to(&ContextState::Closing).await?;
        }

        Ok(())
    }
}
