//! Test access to private `Supervisor` state for the tests that moved to `scp-runtime`
//! (ADR-070 §6.2). Compiled only under the `testing` feature.

use super::{
    Arc, ArcSwap, BootstrapCrashWindow, CallerAbortReversal, Clock, CommitInProgressResolution,
    ContextActorHandle, ContextCommand, ContextError, ContextEventLogProvider, CrashWindow,
    CrossContextOutletReceipt, CrossContextSagaCtx, DID, DashMap, DivergenceMarkerPlan, HashMap,
    HashSet, IdentityWrappingKey, JournalEntry, KeyPackageStoreHandle, Outcome, PaymentAdapterDyn,
    RestoredContexts, RunSagaError, SagaError, SagaId, SagaInput, SagaJournal, SagaReject,
    SagaState, SinkHandoff, StreamAdmissionTracker, Supervisor, TrackedSpawner, XctxPrepared,
};
use crate::context::supervisor::floors::FloorAdvanceError;
use scp_protocol::context::builder::ReceiveFloor;
use scp_protocol::crypto::sender_keys::MergePolicy;

impl Supervisor {
    /// Test access to the `actors` field (ADR-070 §6.2).
    pub const fn actors_for_test(&self) -> &DashMap<String, ContextActorHandle> {
        &self.actors
    }

    /// Acquires the bootstrap-spawn lock (ADR-070 §6.2).
    pub fn lock_bootstrap_spawn_for_test(
        &self,
    ) -> impl std::future::Future<Output = tokio::sync::MutexGuard<'_, ()>> + '_ {
        self.bootstrap_spawn_lock.lock()
    }

    /// Acquires the bootstrap-spawn lock as an owned guard, so the future can
    /// move into a spawned task (ADR-070 §6.2).
    pub fn lock_bootstrap_spawn_owned_for_test(
        &self,
    ) -> impl std::future::Future<Output = tokio::sync::OwnedMutexGuard<()>> + Send + 'static {
        Arc::clone(&self.bootstrap_spawn_lock).lock_owned()
    }

    /// Whether the bootstrap-spawn lock is free at this instant (ADR-070 §6.2).
    pub fn bootstrap_spawn_lock_is_free_for_test(&self) -> bool {
        self.bootstrap_spawn_lock.try_lock().is_ok()
    }

    /// Test access to the `crash_windows` field (ADR-070 §6.2).
    pub const fn crash_windows_for_test(&self) -> &DashMap<String, CrashWindow> {
        &self.crash_windows
    }

    /// Test access to the `floors` field (ADR-070 §6.2).
    pub const fn floors_for_test(
        &self,
    ) -> &DashMap<[u8; 32], crate::context::supervisor::floors::ContextFloors> {
        &self.floors
    }

    /// Test access to the `key_package_stores` field (ADR-070 §6.2).
    pub const fn key_package_stores_for_test(&self) -> &DashMap<DID, KeyPackageStoreHandle> {
        &self.key_package_stores
    }

    /// Test access to the `kp_watchdog_processed_tx` field (ADR-070 §6.2).
    pub const fn kp_watchdog_processed_tx_for_test(&self) -> &tokio::sync::watch::Sender<u64> {
        &self.kp_watchdog_processed_tx
    }

    /// Test access to the `local_dids` field (ADR-070 §6.2).
    pub const fn local_dids_for_test(&self) -> &Arc<ArcSwap<HashSet<DID>>> {
        &self.local_dids
    }

    /// Test access to the `saga_journal` field (ADR-070 §6.2).
    pub fn saga_journal_for_test(&self) -> &Arc<dyn SagaJournal> {
        &self.saga_journal
    }

    /// Test access to the `shutdown_token` field (ADR-070 §6.2).
    pub const fn shutdown_token_for_test(&self) -> &tokio_util::sync::CancellationToken {
        &self.shutdown_token
    }

    /// Test access to the `spawn_generation` field (ADR-070 §6.2).
    pub const fn spawn_generation_for_test(&self) -> &std::sync::atomic::AtomicU64 {
        &self.spawn_generation
    }

    /// Test access to the `standing_contexts` field (ADR-070 §6.2).
    pub const fn standing_contexts_for_test(&self) -> &ArcSwap<HashMap<String, DID>> {
        &self.standing_contexts
    }

    /// Test access to the `task_tracker` field (ADR-070 §6.2).
    pub const fn task_tracker_for_test(&self) -> &tokio_util::task::TaskTracker {
        &self.task_tracker
    }

    /// How many holders share `did`'s wrapping-key load lock: the map entry,
    /// the running load's guard and every waiting load (ADR-070 §6.2). Zero
    /// when no load for `did` is in flight.
    pub fn wrapping_key_load_holders_for_test(&self, did: &DID) -> usize {
        self.wrapping_key_loads
            .get(did)
            .map_or(0, |lock| Arc::strong_count(lock.value()))
    }

    /// Test access to the `wrapping_keys` field (ADR-070 §6.2).
    pub const fn wrapping_keys_for_test(&self) -> &DashMap<DID, Arc<IdentityWrappingKey>> {
        &self.wrapping_keys
    }

    /// Test access to [`Self::abort_saga`] (ADR-070 §6.2).
    ///
    /// # Errors
    ///
    /// The errors of [`Self::abort_saga`].
    pub async fn abort_saga_for_test(
        &self,
        a0: &SagaId,
        a1: &[String],
        a2: u64,
        a3: bool,
        a4: Option<&mut CrossContextSagaCtx<'_>>,
    ) -> Result<(), ContextError> {
        self.abort_saga(a0, a1, a2, a3, a4).await
    }

    /// Test access to [`Self::abort_xctx_participants`] (ADR-070 §6.2).
    pub async fn abort_xctx_participants_for_test(
        &self,
        a0: &SagaId,
        a1: &mut CrossContextSagaCtx<'_>,
    ) -> CallerAbortReversal {
        self.abort_xctx_participants(a0, a1).await
    }

    /// Test access to [`Self::append_journal`] (ADR-070 §6.2).
    ///
    /// # Errors
    ///
    /// The errors of [`Self::append_journal`].
    pub async fn append_journal_for_test(
        &self,
        a0: &SagaId,
        a1: SagaState,
        a2: &[String],
        a3: u64,
        a4: &[u8],
    ) -> Result<(), ContextError> {
        self.append_journal(a0, a1, a2, a3, a4).await
    }

    /// Test access to [`Self::begin_bootstrap_window`] (ADR-070 §6.2).
    pub fn begin_bootstrap_window_for_test(&self, a0: &str) -> BootstrapCrashWindow<'_> {
        self.begin_bootstrap_window(a0)
    }

    /// Test access to [`Self::build_actor_deps`] (ADR-070 §6.2).
    ///
    /// # Errors
    ///
    /// The errors of [`Self::build_actor_deps`].
    pub async fn build_actor_deps_for_test(
        self: &Arc<Self>,
        a0: &DID,
    ) -> Result<crate::context::actor::deps::ActorDeps, ContextError> {
        self.build_actor_deps(a0).await
    }

    /// Test access to [`Self::caller_context_deleted_from_persistence`] (ADR-070 §6.2).
    pub async fn caller_context_deleted_from_persistence_for_test(&self, a0: &str) -> bool {
        self.caller_context_deleted_from_persistence(a0).await
    }

    /// Test access to [`Self::check_and_advance_recv_sequence`] (ADR-070 §6.2).
    ///
    /// # Errors
    ///
    /// The errors of [`Self::check_and_advance_recv_sequence`].
    pub fn check_and_advance_recv_sequence_for_test(
        &self,
        a0: &[u8; 32],
        a1: &str,
        a2: ReceiveFloor,
        a3: u64,
    ) -> Result<(), FloorAdvanceError> {
        self.check_and_advance_recv_sequence(a0, a1, a2, a3)
    }

    /// Test access to [`Self::check_and_advance_sender_epoch`] (ADR-070 §6.2).
    ///
    /// # Errors
    ///
    /// The errors of [`Self::check_and_advance_sender_epoch`].
    pub fn check_and_advance_sender_epoch_for_test(
        &self,
        a0: &[u8; 32],
        a1: &str,
        a2: u64,
        a3: u64,
    ) -> Result<(), FloorAdvanceError> {
        self.check_and_advance_sender_epoch(a0, a1, a2, a3)
    }

    /// Test access to [`Self::clear_kp_poison`] (ADR-070 §6.2).
    ///
    /// # Errors
    ///
    /// The errors of [`Self::clear_kp_poison`].
    pub async fn clear_kp_poison_for_test(self: &Arc<Self>, a0: &DID) -> Result<(), ContextError> {
        self.clear_kp_poison(a0).await
    }

    /// Test access to [`Self::clock_ref`] (ADR-070 §6.2).
    pub fn clock_ref_for_test(&self) -> Option<&Arc<dyn Clock>> {
        self.clock_ref()
    }

    /// Test access to [`Self::commit_a_settle`] (ADR-070 §6.2).
    ///
    /// # Errors
    ///
    /// The errors of [`Self::commit_a_settle`].
    pub async fn commit_a_settle_for_test(
        &self,
        a0: &SagaId,
        a1: &mut CrossContextSagaCtx<'_>,
        a2: &[u8],
        a3: &CrossContextOutletReceipt,
    ) -> Result<(), ContextError> {
        self.commit_a_settle(a0, a1, a2, a3).await
    }

    /// Test access to [`Self::crash_now_ms`] (ADR-070 §6.2).
    pub fn crash_now_ms_for_test(&self, a0: &'static str, a1: &str) -> u64 {
        self.crash_now_ms(a0, a1)
    }

    /// Test access to [`Self::crypto_ref`] (ADR-070 §6.2).
    pub fn crypto_ref_for_test(
        &self,
    ) -> Option<&Arc<crate::crypto::mls::provider::NodeMlsFactory>> {
        self.crypto_ref()
    }

    /// Test access to [`Self::despawn_for_replace`] (ADR-070 §6.2).
    pub async fn despawn_for_replace_for_test(&self, a0: &str) -> bool {
        self.despawn_for_replace(a0).await
    }

    /// Test access to [`Self::dispatch_recovery_send_notification_in_turn`] (ADR-070 §6.2).
    ///
    /// # Errors
    ///
    /// The errors of [`Self::dispatch_recovery_send_notification_in_turn`].
    pub async fn dispatch_recovery_send_notification_in_turn_for_test(
        self: &Arc<Self>,
        a0: Box<crate::context::actor::commands::RecoverySendNotificationPayload>,
        a1: tokio::sync::oneshot::Sender<Result<(), ContextError>>,
    ) -> Result<Outcome<()>, ContextError> {
        self.dispatch_recovery_send_notification_in_turn(a0, a1)
            .await
    }

    /// Test access to [`Self::dispatch_xctx_prepare_a`] (ADR-070 §6.2).
    ///
    /// # Errors
    ///
    /// The errors of [`Self::dispatch_xctx_prepare_a`].
    pub async fn dispatch_xctx_prepare_a_for_test(
        &self,
        a0: &SagaId,
        a1: &mut CrossContextSagaCtx<'_>,
    ) -> Result<(), SagaReject> {
        self.dispatch_xctx_prepare_a(a0, a1).await
    }

    /// Test access to [`Self::divergence_marker_plan`] (ADR-070 §6.2).
    #[must_use]
    pub fn divergence_marker_plan_for_test(
        a0: &CrossContextSagaCtx<'_>,
    ) -> Option<DivergenceMarkerPlan> {
        Self::divergence_marker_plan(a0)
    }

    /// Test access to [`Self::drain_terminal_reservation`] (ADR-070 §6.2).
    pub async fn drain_terminal_reservation_for_test(
        &self,
        a0: &SagaId,
        a1: bool,
        a2: &mut Option<crate::context::actor::commands::PreparedAFields>,
    ) {
        self.drain_terminal_reservation(a0, a1, a2).await;
    }

    /// Test access to [`Self::emit_divergence_markers`] (ADR-070 §6.2).
    pub async fn emit_divergence_markers_for_test(&self, a0: &SagaId, a1: DivergenceMarkerPlan) {
        self.emit_divergence_markers(a0, a1).await;
    }

    /// Test access to [`Self::end_bootstrap_window`] (ADR-070 §6.2).
    pub fn end_bootstrap_window_for_test(&self, a0: &str) {
        self.end_bootstrap_window(a0);
    }

    /// Test access to [`Self::event_log_ref`] (ADR-070 §6.2).
    pub fn event_log_ref_for_test(&self) -> Option<&Arc<dyn ContextEventLogProvider>> {
        self.event_log_ref()
    }

    /// Test access to [`Self::export_recv_sequence_floors`] (ADR-070 §6.2).
    pub fn export_recv_sequence_floors_for_test(
        &self,
        a0: &[u8; 32],
    ) -> Vec<(String, ReceiveFloor)> {
        self.export_recv_sequence_floors(a0)
    }

    /// Test access to [`Self::export_sender_key_epochs`] (ADR-070 §6.2).
    pub fn export_sender_key_epochs_for_test(&self, a0: &[u8; 32]) -> Vec<(String, u64)> {
        self.export_sender_key_epochs(a0)
    }

    /// Test access to [`Self::extract_abort_reservation`] (ADR-070 §6.2).
    #[must_use]
    pub fn extract_abort_reservation_for_test(
        a0: Box<ContextCommand>,
    ) -> Option<crate::context::actor::commands::PreparedAFields> {
        Self::extract_abort_reservation(a0)
    }

    /// Test access to [`Self::extract_commit_a_reservation`] (ADR-070 §6.2).
    #[must_use]
    pub fn extract_commit_a_reservation_for_test(
        a0: Box<ContextCommand>,
    ) -> Option<crate::context::actor::commands::PreparedAFields> {
        Self::extract_commit_a_reservation(a0)
    }

    /// Test access to [`Self::is_context_poisoned`] (ADR-070 §6.2).
    pub fn is_context_poisoned_for_test(&self, a0: &str) -> bool {
        self.is_context_poisoned(a0)
    }

    /// Test access to [`Self::key_package_store_for`] (ADR-070 §6.2).
    ///
    /// # Errors
    ///
    /// The errors of [`Self::key_package_store_for`].
    pub async fn key_package_store_for_for_test(
        self: &Arc<Self>,
        a0: &DID,
    ) -> Result<crate::context::supervisor::key_package_actor::KeyPackageStoreHandle, ContextError>
    {
        self.key_package_store_for(a0).await
    }

    /// Test access to [`Self::known_context_ids`] (ADR-070 §6.2).
    pub fn known_context_ids_for_test(&self) -> Vec<String> {
        self.known_context_ids()
    }

    /// Test access to [`Self::kp_crash_key`] (ADR-070 §6.2).
    #[must_use]
    pub fn kp_crash_key_for_test(a0: &DID) -> String {
        Self::kp_crash_key(a0)
    }

    /// Test access to [`Self::lift_run_saga_error`] (ADR-070 §6.2).
    #[must_use]
    pub fn lift_run_saga_error_for_test(a0: SagaId, a1: RunSagaError) -> SagaError {
        Self::lift_run_saga_error(a0, a1)
    }

    /// Test access to [`Self::load_wrapping_key`] (ADR-070 §6.2).
    ///
    /// # Errors
    ///
    /// The errors of [`Self::load_wrapping_key`].
    pub async fn load_wrapping_key_for_test(
        &self,
        a0: &DID,
    ) -> Result<Arc<IdentityWrappingKey>, ContextError> {
        self.load_wrapping_key(a0).await
    }

    /// Test access to [`Self::lookup_miss_error`] (ADR-070 §6.2).
    pub fn lookup_miss_error_for_test(&self, a0: &str, a1: String) -> ContextError {
        self.lookup_miss_error(a0, a1)
    }

    /// Test access to [`Self::mls_storage_ref`] (ADR-070 §6.2).
    pub fn mls_storage_ref_for_test(
        &self,
    ) -> Option<&Arc<dyn scp_runtime_types::crypto::mls::storage_adapter::OpenMlsStorageAdapter>>
    {
        self.mls_storage_ref()
    }

    /// Test access to [`Self::outlet_stream_admission_for`] (ADR-070 §6.2).
    pub fn outlet_stream_admission_for_for_test(
        &self,
        a0: &str,
    ) -> Arc<std::sync::RwLock<StreamAdmissionTracker>> {
        self.outlet_stream_admission_for(a0)
    }

    /// Test access to [`Self::payment_adapter_ref`] (ADR-070 §6.2).
    pub fn payment_adapter_ref_for_test(&self) -> Option<&Arc<dyn PaymentAdapterDyn>> {
        self.payment_adapter_ref()
    }

    /// Test access to [`Self::reconstruct_xctx_prepared`] (ADR-070 §6.2).
    #[must_use]
    pub fn reconstruct_xctx_prepared_for_test(a0: &JournalEntry) -> Option<XctxPrepared> {
        Self::reconstruct_xctx_prepared(a0)
    }

    /// Test access to [`Self::record_supervisor_repair`] (ADR-070 §6.2).
    pub async fn record_supervisor_repair_for_test(
        &self,
        a0: &SagaId,
        a1: &str,
        a2: scp_protocol::context::outlets::cross_context_saga::CommittedSide,
        a3: &str,
        a4: [u8; 16],
    ) {
        self.record_supervisor_repair(a0, a1, a2, a3, a4).await;
    }

    /// Test access to [`Self::recover_saga_entry`] (ADR-070 §6.2).
    pub async fn recover_saga_entry_for_test(&self, a0: JournalEntry) {
        self.recover_saga_entry(a0).await;
    }

    /// Test access to [`Self::recovery_send_notification_direct`] (ADR-070 §6.2).
    pub fn recovery_send_notification_direct_for_test<'a>(
        self: &'a Arc<Self>,
        a0: &str,
        a1: &str,
        a2: &[u8],
        a3: u64,
        a4: &crate::context::actor::signer::CommandSigner,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ContextError>> + Send + 'a>>
    {
        self.recovery_send_notification_direct(a0, a1, a2, a3, a4)
    }

    /// Test access to [`Self::redrive_caller_local_reversal`] (ADR-070 §6.2).
    pub async fn redrive_caller_local_reversal_for_test(
        &self,
        a0: &SagaId,
        a1: &str,
    ) -> CallerAbortReversal {
        self.redrive_caller_local_reversal(a0, a1).await
    }

    /// Test access to [`Self::redrive_xctx_commit_in_progress`] (ADR-070 §6.2).
    pub async fn redrive_xctx_commit_in_progress_for_test(
        &self,
        a0: &SagaId,
        a1: &XctxPrepared,
    ) -> CommitInProgressResolution {
        self.redrive_xctx_commit_in_progress(a0, a1).await
    }

    /// Test access to [`Self::redrive_xctx_prepare_in_progress`] (ADR-070 §6.2).
    pub async fn redrive_xctx_prepare_in_progress_for_test(
        &self,
        a0: &SagaId,
        a1: &XctxPrepared,
    ) -> CallerAbortReversal {
        self.redrive_xctx_prepare_in_progress(a0, a1).await
    }

    /// Test access to [`Self::refuse_if_shut_down`] (ADR-070 §6.2).
    ///
    /// # Errors
    ///
    /// The errors of [`Self::refuse_if_shut_down`].
    pub fn refuse_if_shut_down_for_test(&self, a0: &str) -> Result<(), ContextError> {
        self.refuse_if_shut_down(a0)
    }

    /// Test access to [`Self::release_stream_escrow`] (ADR-070 §6.2).
    pub async fn release_stream_escrow_for_test(
        self: &Arc<Self>,
        a0: &TrackedSpawner,
        a1: crate::context::outlets::dispatch::StreamEscrowTicket,
        a2: &str,
        a3: &DID,
    ) {
        self.release_stream_escrow(a0, a1, a2, a3).await;
    }

    /// Test access to [`Self::reserve_outlet_stream_economy_via_actor`] (ADR-070 §6.2).
    ///
    /// # Errors
    ///
    /// The errors of [`Self::reserve_outlet_stream_economy_via_actor`].
    pub async fn reserve_outlet_stream_economy_via_actor_for_test(
        &self,
        a0: &str,
        a1: &DID,
        a2: scp_protocol::economy::types::Amount,
        a3: u32,
        a4: Option<scp_protocol::economy::types::Amount>,
        a5: u64,
    ) -> Result<crate::context::shared::outlets::StreamEconomyReservation, ContextError> {
        self.reserve_outlet_stream_economy_via_actor(a0, a1, a2, a3, a4, a5)
            .await
    }

    /// Test access to [`Self::respawn_from_snapshot`] (ADR-070 §6.2).
    ///
    /// # Errors
    ///
    /// The errors of [`Self::respawn_from_snapshot`].
    pub async fn respawn_from_snapshot_for_test(
        self: &Arc<Self>,
        a0: &str,
        a1: &DID,
    ) -> Result<(), ContextError> {
        self.respawn_from_snapshot(a0, a1).await
    }

    /// Test access to [`Self::restore_all_contexts`] (ADR-070 §6.2).
    ///
    /// # Errors
    ///
    /// The errors of [`Self::restore_all_contexts`].
    pub async fn restore_all_contexts_for_test(
        self: &Arc<Self>,
    ) -> Result<RestoredContexts, ContextError> {
        self.restore_all_contexts().await
    }

    /// Test access to [`Self::reverse_stream_escrow_via_actor`] (ADR-070 §6.2).
    ///
    /// # Errors
    ///
    /// The errors of [`Self::reverse_stream_escrow_via_actor`].
    pub async fn reverse_stream_escrow_via_actor_for_test(
        &self,
        a0: &str,
        a1: &DID,
        a2: scp_protocol::economy::types::Amount,
    ) -> Result<(), ContextError> {
        self.reverse_stream_escrow_via_actor(a0, a1, a2).await
    }

    /// Test access to [`Self::sender_epoch_floor`] (ADR-070 §6.2).
    pub fn sender_epoch_floor_for_test(&self, a0: &[u8; 32], a1: &str) -> u64 {
        self.sender_epoch_floor(a0, a1)
    }

    /// Test access to [`Self::settle_outlet_economy_via_actor`] (ADR-070 §6.2).
    ///
    /// # Errors
    ///
    /// The errors of [`Self::settle_outlet_economy_via_actor`].
    pub async fn settle_outlet_economy_via_actor_for_test(
        &self,
        a0: &str,
        a1: &DID,
        a2: crate::context::shared::outlets::OutletSettleRequest,
    ) -> Result<crate::context::shared::outlets::OutletSettleOutcome, ContextError> {
        self.settle_outlet_economy_via_actor(a0, a1, a2).await
    }

    /// Test access to [`Self::settle_outlet_stream_via_actor`] (ADR-070 §6.2).
    ///
    /// # Errors
    ///
    /// The errors of [`Self::settle_outlet_stream_via_actor`].
    pub async fn settle_outlet_stream_via_actor_for_test(
        &self,
        a0: crate::context::outlets::invoke::StreamSettlement,
        a1: u64,
        a2: Option<SagaId>,
    ) -> Result<crate::context::actor::commands::StreamSettleApplication, ContextError> {
        self.settle_outlet_stream_via_actor(a0, a1, a2).await
    }

    /// Test access to [`Self::spawn_actor_with_state`] (ADR-070 §6.2).
    ///
    /// # Errors
    ///
    /// The errors of [`Self::spawn_actor_with_state`].
    pub async fn spawn_actor_with_state_for_test(
        self: &Arc<Self>,
        a0: crate::context::actor::state::PerContextState,
        a1: crate::context::actor::deps::ActorDeps,
        a2: Option<usize>,
    ) -> Result<ContextActorHandle, ContextError> {
        self.spawn_actor_with_state(a0, a1, a2).await
    }

    /// Test access to [`Self::spawn_tracked`] (ADR-070 §6.2).
    ///
    /// # Errors
    ///
    /// The errors of [`Self::spawn_tracked`].
    pub fn spawn_tracked_for_test<F>(
        &self,
        a0: &str,
        a1: F,
    ) -> Result<tokio::task::JoinHandle<F::Output>, ContextError>
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.spawn_tracked(a0, a1)
    }

    /// Test access to [`Self::spawn_tracked_on`] (ADR-070 §6.2).
    ///
    /// # Errors
    ///
    /// The errors of [`Self::spawn_tracked_on`].
    pub fn spawn_tracked_on_for_test<F>(
        &self,
        a0: SinkHandoff,
        a1: F,
        a2: &tokio::runtime::Handle,
    ) -> Result<tokio::task::JoinHandle<F::Output>, ContextError>
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.spawn_tracked_on(a0, a1, a2)
    }

    /// Test access to [`Self::standing_context`] (ADR-070 §6.2).
    ///
    /// # Errors
    ///
    /// The errors of [`Self::standing_context`].
    pub async fn standing_context_for_test(
        self: &Arc<Self>,
        a0: &DID,
        a1: &DID,
        a2: Vec<String>,
    ) -> Result<String, ContextError> {
        self.standing_context(a0, a1, a2).await
    }

    /// Test access to [`Self::tracked_spawner`] (ADR-070 §6.2).
    ///
    /// # Errors
    ///
    /// The errors of [`Self::tracked_spawner`].
    pub fn tracked_spawner_for_test(&self, a0: &str) -> Result<TrackedSpawner, ContextError> {
        self.tracked_spawner(a0)
    }

    /// Test access to [`Self::verify_commit_b_receipt`] (ADR-070 §6.2).
    ///
    /// # Errors
    ///
    /// The errors of [`Self::verify_commit_b_receipt`].
    pub fn verify_commit_b_receipt_for_test(
        a0: &SagaId,
        a1: &CrossContextSagaCtx<'_>,
        a2: &[u8],
    ) -> Result<CrossContextOutletReceipt, ContextError> {
        Self::verify_commit_b_receipt(a0, a1, a2)
    }

    /// Test access to [`Self::wrapping_key`] (ADR-070 §6.2).
    ///
    /// # Errors
    ///
    /// The errors of [`Self::wrapping_key`].
    pub fn wrapping_key_for_test(
        &self,
        a0: &DID,
    ) -> Result<Arc<IdentityWrappingKey>, ContextError> {
        self.wrapping_key(a0)
    }

    /// Test access to [`Self::xctx_prepared_evidence_bytes`] (ADR-070 §6.2).
    #[must_use]
    pub fn xctx_prepared_evidence_bytes_for_test(
        a0: &SagaInput,
        a1: &CrossContextSagaCtx<'_>,
    ) -> Option<Vec<u8>> {
        Self::xctx_prepared_evidence_bytes(a0, a1)
    }
}

impl Supervisor {
    /// Test access to [`Self::remove_member_floors`] (ADR-070 §6.2).
    pub fn remove_member_floors_for_test(&self, a0: &[u8; 32], a1: &str) {
        self.remove_member_floors(a0, a1);
    }

    /// Test access to [`Self::seed_context_floors`] (ADR-070 §6.2).
    pub fn seed_context_floors_for_test(&self, a0: &[u8; 32]) {
        self.seed_context_floors(a0);
    }

    /// Test access to [`Self::validate_and_merge_all_floors`] (ADR-070 §6.2).
    ///
    /// # Errors
    ///
    /// The errors of [`Self::validate_and_merge_all_floors`].
    pub fn validate_and_merge_all_floors_for_test(
        &self,
        a0: &[u8; 32],
        a1: Vec<(String, u64)>,
        a2: Vec<(String, ReceiveFloor)>,
        a3: u64,
        a4: MergePolicy,
    ) -> Result<(), FloorAdvanceError> {
        self.validate_and_merge_all_floors(a0, a1, a2, a3, a4)
    }

    /// Test access to [`Self::validate_and_merge_epoch_floors`] (ADR-070 §6.2).
    ///
    /// # Errors
    ///
    /// The errors of [`Self::validate_and_merge_epoch_floors`].
    pub fn validate_and_merge_epoch_floors_for_test(
        &self,
        a0: &[u8; 32],
        a1: Vec<(String, u64)>,
        a2: u64,
        a3: MergePolicy,
    ) -> Result<(), FloorAdvanceError> {
        self.validate_and_merge_epoch_floors(a0, a1, a2, a3)
    }

    /// Test access to [`Self::validate_and_merge_recv_sequence_floors`] (ADR-070 §6.2).
    ///
    /// # Errors
    ///
    /// The errors of [`Self::validate_and_merge_recv_sequence_floors`].
    pub fn validate_and_merge_recv_sequence_floors_for_test(
        &self,
        a0: &[u8; 32],
        a1: Vec<(String, ReceiveFloor)>,
        a2: MergePolicy,
    ) -> Result<(), FloorAdvanceError> {
        self.validate_and_merge_recv_sequence_floors(a0, a1, a2)
    }
}
