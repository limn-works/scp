//! TTL management and context close operations.

use super::{
    Arc, CloseResult, ContextError, ContextEvent, ContextHandle, ContextManager, DID,
    GovernanceModelConfig, TtlExtension, instrument, require_active, ttl,
};

#[allow(clippy::significant_drop_tightening)]
impl ContextManager {
    /// Initiates cooperative context closure.
    ///
    /// For `SingleAdmin` governance: verifies the initiator has the
    /// `ContextClose` capability, transitions from `Active` to `Closing`,
    /// and appends a `ContextClosing` event. Cancels any active TTL timer.
    ///
    /// For multi-admin governance models (`Threshold`, `Majority`,
    /// `Unanimity`): returns `PermissionDenied`. Multi-admin contexts MUST
    /// close through the governance path: `propose_governance_action` with
    /// `GovernanceAction::CloseContext` -> vote -> auto-execute on approval
    /// (SCP-270, ADR-031). This ensures all signers/voters can participate
    /// in the close decision.
    ///
    /// See ADR-008 acceptance criterion 5.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::ContextNotActive`] if the context is not
    /// `Active`. Returns [`ContextError::PermissionDenied`] if the context
    /// uses a multi-admin governance model (use governance proposal path
    /// instead) or if the initiator lacks `ContextClose` capability.
    #[instrument(skip_all, fields(context_id = handle.context_id()))]
    pub async fn close_context(
        &self,
        handle: &ContextHandle,
        initiator_did: &DID,
    ) -> Result<CloseResult, ContextError> {
        let context_id = handle.context_id().to_owned();

        // Check governance model: multi-admin contexts must route through
        // governance (SCP-270, ADR-031). Only SingleAdmin contexts can use
        // the direct close_context path.
        let role_state = {
            let contexts = self.contexts.lock().await;
            let ctx = contexts
                .get(&context_id)
                .ok_or_else(|| ContextError::ContextNotRegistered(context_id.clone()))?;

            // State check inside lock -- eliminates TOCTOU race.
            require_active(&ctx.handle)?;

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

            ctx.role_state.clone()
        };
        // Lock dropped before async ttl::close_context call.

        // Delegate to ttl::close_context for the actual logic (async).
        let result =
            ttl::close_context(handle, initiator_did, &role_state, self.event_log.as_ref()).await?;

        // Cancel TTL timer, governance timeout task, drop broadcast state,
        // and emit close notification (second lock acquisition).
        {
            let mut contexts = self.contexts.lock().await;
            if let Some(ctx) = contexts.get_mut(&context_id) {
                ctx.ttl.timer.cancel();
                ctx.governance.timeout_task.cancel();
                // Drop broadcast context state -- keys are zeroed by Zeroize.
                ctx.broadcast_context = None;

                // Participation decay: clear participation cache and cooldown
                // state on context close (#1530).
                ctx.governance.decay_participation();

                ctx.receive_buffer.push(ContextEvent::SystemClose {
                    initiator_did: initiator_did.clone(),
                });
            }
        }

        self.update_context_gauges().await;

        // Persist context state after close (best-effort).
        if self.has_persistence() {
            let contexts = self.contexts.lock().await;
            if let Some(ctx) = contexts.get(&context_id) {
                let snapshot = Self::snapshot_context(ctx);
                drop(contexts);
                self.persist_context_snapshot(&context_id, snapshot);
            }
        }

        Ok(result)
    }

    /// Completes context closure.
    ///
    /// Destroys MLS group state and sender keys, issues relay deletion
    /// requests for ephemeral/summary scopes, transitions from `Closing`
    /// to `Closed`, and appends the final `ContextClosed` event.
    ///
    /// See ADR-008 acceptance criterion 6.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] if the context is not in `Closing` state
    /// or if destruction operations fail.
    #[instrument(skip_all, fields(context_id = handle.context_id()))]
    pub async fn finalize_close(&self, handle: &ContextHandle) -> Result<(), ContextError> {
        let context_id = handle.context_id().to_owned();

        ttl::finalize_close(
            handle,
            self.crypto.as_ref(),
            self.transport.as_ref(),
            self.event_log.as_ref(),
        )
        .await?;

        // Delete persisted state after finalize (best-effort).
        if let Some(ref persistence) = self.persistence {
            let _ = persistence.delete_context(&context_id);
        }

        Ok(())
    }

    /// Handles automatic TTL expiry.
    ///
    /// Transitions from `Active` to `Expired`, destroys keys per memory
    /// scope, issues relay deletion requests for ephemeral/summary scopes,
    /// and appends `ContextExpired` to the event log.
    ///
    /// See ADR-008 acceptance criterion 7 and spec §5.10/§5.11.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::ContextNotActive`] if the context is not
    /// in `Active` state.
    #[instrument(skip_all, fields(context_id = handle.context_id()))]
    pub async fn handle_ttl_expiry(&self, handle: &ContextHandle) -> Result<(), ContextError> {
        let context_id = handle.context_id().to_owned();

        // Async TTL expiry logic -- no lock held. Pass transport for
        // best-effort relay ciphertext deletion (§5.11).
        let result = ttl::try_ttl_expiry_cleanup(
            handle,
            self.crypto.as_ref(),
            Some(self.transport.as_ref()),
            self.event_log.as_ref(),
            0,
        )
        .await;

        // Cancel governance timeout task, decay participation, and emit
        // appropriate event (lock acquired, then dropped).
        {
            let mut contexts = self.contexts.lock().await;
            if let Some(ctx) = contexts.get_mut(&context_id) {
                ctx.governance.timeout_task.cancel();
                // Participation decay on TTL expiry (#1530): clear
                // participation cache and cooldown state so stale data does
                // not carry over if the context is later restored.
                ctx.governance.decay_participation();
                if result.is_complete() {
                    ctx.receive_buffer.push(ContextEvent::Expired);
                } else {
                    ctx.receive_buffer.push(ContextEvent::ExpiryFailed {
                        reason: result.to_string(),
                        state_transitioned: result.state_transitioned(),
                        mls_destroyed: result.mls_destroyed(),
                        sender_key_destroyed: result.sender_key_destroyed(),
                        event_logged: result.event_logged(),
                    });
                }
            }
        }

        // Persist context state after TTL expiry (best-effort).
        if self.has_persistence() {
            let contexts = self.contexts.lock().await;
            if let Some(ctx) = contexts.get(&context_id) {
                let snapshot = Self::snapshot_context(ctx);
                drop(contexts);
                self.persist_context_snapshot(&context_id, snapshot);
            }
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

    /// Proposes a TTL extension. Records consent from the given member.
    ///
    /// If all members have consented (unanimous), returns `true` indicating
    /// the extension was approved. The caller should then call
    /// [`reset_ttl_timer`](Self::reset_ttl_timer) with the new duration.
    ///
    /// See ADR-008 acceptance criterion 9 / spec section 5.10.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::MembershipFailed`] if the context is not
    /// registered. Returns [`ContextError::MemberNotFound`] if the member
    #[instrument(skip_all, fields(context_id))]
    pub async fn propose_ttl_extension(
        &self,
        context_id: &str,
        member_did: &DID,
        proposed_duration: std::time::Duration,
    ) -> Result<bool, ContextError> {
        // All checks and mutation within a single lock acquisition.
        let mut contexts = self.contexts.lock().await;
        let ctx = contexts
            .get_mut(context_id)
            .ok_or_else(|| ContextError::ContextNotRegistered(context_id.to_owned()))?;

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
        if self.has_persistence() {
            let ctx_snapshot = Self::snapshot_context(ctx);
            drop(contexts);
            self.persist_context_snapshot(context_id, ctx_snapshot);
        }

        Ok(unanimous)
    }

    /// Resets the TTL timer after a successful unanimous extension.
    ///
    /// Cancels the old timer and spawns a new one with the given duration.
    /// Clears the extension proposal state.
    #[instrument(skip_all, fields(context_id))]
    pub async fn reset_ttl_timer(
        &self,
        context_id: &str,
        new_duration: std::time::Duration,
        handle: ContextHandle,
    ) {
        // Cancel old timer and clear extension state (lock, then drop).
        {
            let mut contexts = self.contexts.lock().await;
            if let Some(ctx) = contexts.get_mut(context_id) {
                ctx.ttl.timer.cancel();
                ctx.ttl.extension = None;
            }
        }

        self.spawn_ttl_timer(context_id, new_duration, handle).await;

        // Persist context state after TTL reset (best-effort).
        if self.has_persistence() {
            let contexts = self.contexts.lock().await;
            if let Some(ctx) = contexts.get(context_id) {
                let snapshot = Self::snapshot_context(ctx);
                drop(contexts);
                self.persist_context_snapshot(context_id, snapshot);
            }
        }
    }

    /// Spawns a TTL timer for the given context.
    ///
    /// When the timer fires, it runs [`ttl::run_ttl_expiry_with_retries`]
    /// which:
    /// - Transitions the context from `Active` to `Expired`.
    /// - For `Ephemeral` and `Summary` memory scopes: destroys MLS group
    ///   state and sender keys via the crypto provider.
    /// - Logs a `ContextExpired` event to the event log.
    ///
    /// On success, emits [`ContextEvent::Expired`] to the receive buffer.
    /// If all retries fail, emits [`ContextEvent::ExpiryFailed`] so the
    /// application layer can observe and react to the failure.
    ///
    /// This matches the behavior of [`TtlTimer::spawn`] and ensures key
    /// destruction and event logging use the manager's shared providers.
    pub(super) async fn spawn_ttl_timer(
        &self,
        context_id: &str,
        duration: std::time::Duration,
        handle: ContextHandle,
    ) {
        // Extract the cancel Notify under lock, then drop.
        let cancel = {
            let mut contexts = self.contexts.lock().await;
            let Some(ctx) = contexts.get_mut(context_id) else {
                return;
            };
            ctx.ttl.timer.cancel.clone()
        };

        // Clone Arc-wrapped providers so the spawned task can perform
        // key destruction, relay deletion, and event logging on TTL expiry.
        let crypto = Arc::clone(&self.crypto);
        let transport = Arc::clone(&self.transport);
        let event_log = Arc::clone(&self.event_log);
        let contexts_ref = Arc::clone(&self.contexts);
        let context_id_owned = context_id.to_owned();

        let task = tokio::spawn(async move {
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
                    let mut contexts = contexts_ref.lock().await;
                    if let Some(ctx) = contexts.get_mut(&context_id_owned) {
                        if result.is_complete() {
                            ctx.receive_buffer.push(ContextEvent::Expired);
                        } else {
                            ctx.receive_buffer.push(ContextEvent::ExpiryFailed {
                                reason: result.to_string(),
                                state_transitioned: result.state_transitioned(),
                                mls_destroyed: result.mls_destroyed(),
                                sender_key_destroyed: result.sender_key_destroyed(),
                                event_logged: result.event_logged(),
                            });
                        }
                        // Cancel the governance timeout task and clear
                        // participation cache, cooldown, proposal timestamps,
                        // and velocity tracker. Without this the in-memory
                        // governance state would persist after auto-expiry
                        // (#1530, H8). Mirrors handle_ttl_expiry and
                        // close_context. Must run under the same lock so the
                        // state is fully cleared before any other observer
                        // sees the Expired/ExpiryFailed event.
                        ctx.governance.timeout_task.cancel();
                        ctx.governance.decay_participation();
                    }
                    drop(contexts);
                }
                () = cancel.notified() => {
                    // Timer was cancelled.
                }
            }
        });

        // Store the task handle (lock, then drop).
        let context_id_for_store = context_id.to_owned();
        let mut contexts = self.contexts.lock().await;
        if let Some(ctx) = contexts.get_mut(&context_id_for_store) {
            ctx.ttl.timer.task = Some(task);
        }
    }
}
