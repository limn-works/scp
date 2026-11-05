//! Items the lifecycle domain shares with core and with other domains.
//!
//! It holds code that reads or writes only core state and calls no domain
//! function, and the types and constants more than one crate names (ADR-070
//! Appendix).
use crate::context::ContextHandle;
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::state::PerContextState;
use scp_did::DID;
use scp_protocol::context::ContextError;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;

/// Returns the stored form of a context's relay set (§5.12.3.1 `relay_urls`).
///
/// Each URL that has a §9.18.2 canonical relay URL becomes that canonical URL,
/// and every other URL stays exactly as written. The function then keeps each
/// stored URL once, at its first position, so two spellings of one relay
/// collapse to one entry whichever source supplied the set (the creator, an
/// invitation bundle, or a snapshot). A URL with no canonical form never fails
/// the caller.
///
/// Every write of `PerContextState::relay_urls` goes through this function.
/// A Welcome joiner calls it after it verifies the bundle signature, which
/// covers the URLs as the creator sent them.
#[must_use]
pub fn normalize_relay_urls(relay_urls: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::with_capacity(relay_urls.len());
    relay_urls
        .into_iter()
        .map(|url| scp_did::canonical_node_url(&url).unwrap_or(url))
        .filter(|url| seen.insert(url.clone()))
        .collect()
}

/// Adds `member_did` to the MLS group and queues its sender-key distribution.
///
/// Both happen in the one Class-S step that records the Add (spec 09
/// §9.16.9). The join and the governance `AddMember` both call it, so the two
/// give one disposition.
///
/// The §9.10.4.1 membership trigger is recorded with the add. When the
/// distribution cannot be built, the add stands and the distribution is
/// reported as not built (`SenderKeyDistributionFailed`); the new member
/// requests the key (§9.16.2). An add that produced no Welcome (the
/// `testing` no-crypto pipeline, with no MLS group) queues nothing.
///
/// # Errors
///
/// The error of `PerContextState::add_member`; nothing is added then.
pub fn add_member_and_queue_distribution(
    state: &mut crate::context::actor::state::PerContextState,
    deps: &ActorDeps,
    member_did: &str,
    key_package: Option<&[u8]>,
) -> Result<scp_protocol::context::builder::AddMemberOutput, ContextError> {
    let local_did = deps.crypto.local_did();
    let output = state.add_member(member_did, key_package, deps.clock.as_ref())?;
    crate::context::actor::pseudonym_rotation::note_member_added(state, local_did, member_did);
    if !output.welcome_bytes.is_empty()
        && let Err(e) = state.distribute_sender_key(local_did, member_did, deps.event_tx.as_ref())
    {
        let context_id = state.handle.context_id().to_owned();
        crate::context::actor::state::DistributionFault::NotBuilt {
            target_did: member_did.to_owned(),
            reason: e.to_string(),
        }
        .report(
            &mut state.receive_buffer,
            &context_id,
            deps.event_tx.as_ref(),
        );
    }
    Ok(output)
}

/// Which queued sender-key distributions one pass of
/// `scp_runtime_lifecycle::helpers::drain_and_deliver_sender_keys` publishes (spec 09 §9.16.9 step 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DistributionScope {
    /// Only distributions never attempted: the publish right after a
    /// rotation or an Add, and the one after a `Live` delivery. A failed
    /// distribution waits for the governance timer or a full reconnection.
    NeverAttempted,
    /// Every queued distribution: the governance timer's tick and the
    /// re-send a full reconnection asks for (ADR-029, offline and sync
    /// strategy). A distribution restored with no attempt record is due here.
    All,
}

impl DistributionScope {
    /// Whether a pass of this scope publishes the queued distribution `entry`.
    #[must_use]
    pub const fn selects(self, entry: &crate::crypto::mls::provider::PendingDistribution) -> bool {
        match self {
            Self::NeverAttempted => entry.first_attempt_at.is_none(),
            Self::All => true,
        }
    }
}

/// Write progress of one first-state record, held in an `AtomicU8`.
///
/// A record is touched when its write was started: `IN_FLIGHT` (the write
/// future was dropped or has not returned, so it may have landed) or
/// `WRITTEN`. A rollback puts back only a touched record. `FAILED` means the
/// write returned an error, so the record keeps whatever the store held.
pub(crate) const RECORD_NOT_WRITTEN: u8 = 0;

/// The write was started and has not returned, so it may have landed.
pub(crate) const RECORD_IN_FLIGHT: u8 = 1;

/// The state a [`FirstStateRollback`] shares with its writes task and with
/// any rollback task it starts.
pub struct FirstStateRollbackInner {
    /// The store the first snapshot is written to and restored in.
    persistence: Arc<dyn crate::context::persistence::ContextPersistence>,
    /// The store the first `last_relay_contact` is written to and restored in.
    contacts: Arc<dyn crate::store::sync::RelayContactStore>,
    /// The Supervisor whose `pending_first_state` claim this guard holds and
    /// whose actor registry a rollback reads.
    supervisor: crate::context::supervisor::handle::SupervisorHandle,
    /// The context id the first-state records belong to.
    pub context_id: String,
    /// The snapshot and contact stored before the first write, set once by
    /// [`FirstStateRollback::capture_priors`].
    priors: std::sync::OnceLock<FirstStatePriors>,
    /// Write progress of the `last_relay_contact` record, a `RECORD_*` value.
    contact: std::sync::atomic::AtomicU8,
    /// Write progress of the snapshot record, a `RECORD_*` value.
    snapshot: std::sync::atomic::AtomicU8,
    /// `true` while no first-state writes task is running. The tracked task
    /// [`persist_first_state`] starts sets it `false` before the task can run
    /// and back to `true` when the task ends, by return, panic, runtime
    /// shutdown or a drop before its first poll. A write the operation's
    /// timeout abandoned keeps running, and [`Self::drain_writes`] waits for
    /// this flag before a rollback reads what was touched.
    writes_idle: tokio::sync::watch::Sender<bool>,
    /// Set when Supervisor shutdown abandoned the writes before they
    /// finished, so a write may still land and no rollback reads the
    /// records.
    abandoned: std::sync::atomic::AtomicBool,
    /// `true` while this guard holds the `pending_first_state` claim of its
    /// context id, which keeps every other bootstrap, restore and respawn of
    /// the id out until the guard commits or rolls back.
    claimed: std::sync::atomic::AtomicBool,
    /// Set by [`FirstStateRollback::commit`] or by the first rollback, so a
    /// guard rolls back at most once and never after its actor started.
    settled: std::sync::atomic::AtomicBool,
}

impl FirstStateRollbackInner {
    /// Stores the write progress `state`, a `RECORD_*` value, in `record`.
    fn mark(record: &std::sync::atomic::AtomicU8, state: u8) {
        record.store(state, std::sync::atomic::Ordering::SeqCst);
    }

    /// Whether the snapshot record and the contact record, in that order,
    /// were touched.
    fn touched(&self) -> (bool, bool) {
        (
            record_touched(self.snapshot.load(std::sync::atomic::Ordering::SeqCst)),
            record_touched(self.contact.load(std::sync::atomic::Ordering::SeqCst)),
        )
    }

    /// Releases the claim [`FirstStateRollback::new`] made, once.
    fn release_claim(&self) {
        if self
            .claimed
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            self.supervisor.release_first_state(&self.context_id);
        }
    }

    /// Writes the first `last_relay_contact`, then the first snapshot, and
    /// records each write's progress. Runs inside [`first_state_writes`], the
    /// tracked task [`persist_first_state`] starts, so it finishes even when
    /// the operation's future is dropped.
    ///
    /// # Errors
    ///
    /// [`ContextError::PersistenceFailed`] when either write fails; that
    /// record is marked `RECORD_FAILED` and the snapshot is not written after
    /// a failed contact write.
    async fn write_first_state(
        &self,
        now: u64,
        snapshot: &crate::context::state::ContextSnapshot,
    ) -> Result<(), ContextError> {
        let context_id = self.context_id.as_str();
        Self::mark(&self.contact, RECORD_IN_FLIGHT);
        if let Err(e) = self
            .contacts
            .store_last_relay_contact(context_id, now)
            .await
        {
            Self::mark(&self.contact, RECORD_FAILED);
            scp_runtime_types::metrics::record_persistence_failure();
            tracing::error!(
                context_id,
                error = %e,
                "first last_relay_contact write failed; the context is not started"
            );
            return Err(ContextError::PersistenceFailed(format!(
                "writing the first last_relay_contact of '{context_id}' failed: {e}"
            )));
        }
        Self::mark(&self.contact, RECORD_WRITTEN);
        Self::mark(&self.snapshot, RECORD_IN_FLIGHT);
        if let Err(e) = self.persistence.persist_context(context_id, snapshot).await {
            Self::mark(&self.snapshot, RECORD_FAILED);
            scp_runtime_types::metrics::record_persistence_failure();
            tracing::error!(
                context_id,
                error = %e,
                "first snapshot write failed; the context is not started (ADR-049 §9 Class S)"
            );
            return Err(ContextError::PersistenceFailed(format!(
                "fail-closed persist failed for context '{context_id}': {e}"
            )));
        }
        Self::mark(&self.snapshot, RECORD_WRITTEN);
        Ok(())
    }

    /// Waits for a first-state writes task the operation abandoned, so no
    /// write lands after the rollback reads the records' progress.
    /// [`FirstStateRollback::rollback`] runs it with `bootstrap_spawn_lock`
    /// released, because the wait can last [`FIRST_STATE_WRITES_DRAIN`] and
    /// every other bootstrap waits on that lock.
    /// [`FirstStateRollback::rollback_with_guard`] runs it
    /// under the guard its actor turn already holds, because releasing that
    /// guard in a turn could not be undone without waiting on the lock.
    ///
    /// # Errors
    ///
    /// [`ContextError::PersistenceFailed`] when the writes have not finished
    /// within [`FIRST_STATE_WRITES_DRAIN`], or Supervisor shutdown abandoned
    /// them: a write that may still land cannot be undone, so the records
    /// are kept.
    async fn drain_writes(&self) -> Result<(), ContextError> {
        let context_id = self.context_id.as_str();
        let mut idle = self.writes_idle.subscribe();
        match tokio::time::timeout(FIRST_STATE_WRITES_DRAIN, idle.wait_for(|idle| *idle)).await {
            // The writes' own result is in the record states read next. The
            // sender lives in `self`, so the wait cannot see it closed.
            Ok(Ok(_) | Err(_)) => {}
            Err(_elapsed) => {
                scp_runtime_types::metrics::record_persistence_failure();
                return Err(ContextError::PersistenceFailed(format!(
                    "the first-state writes of '{context_id}' did not finish within \
                     {FIRST_STATE_WRITES_DRAIN:?}; their records are kept"
                )));
            }
        }
        if self.abandoned.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(ContextError::PersistenceFailed(format!(
                "shutdown abandoned the first-state writes of '{context_id}' before they \
                 finished; their records are kept"
            )));
        }
        Ok(())
    }

    /// Puts back every touched record: the snapshot first, then the contact,
    /// and the contact only once the snapshot step returned `Ok`, so no
    /// stored snapshot is ever left without a contact (ADR-029
    /// Implementation). The caller has drained the writes
    /// ([`Self::drain_writes`]) and holds `bootstrap_spawn_lock`, so no
    /// bootstrap writes between this `lookup` and the restores.
    ///
    /// # Errors
    ///
    /// [`ContextError::InvalidState`] when a record was touched before its
    /// prior value was read, and [`ContextError::PersistenceFailed`] when a
    /// restore fails; a failed snapshot restore keeps the contact.
    async fn undo_locked(&self) -> Result<(), ContextError> {
        let context_id = self.context_id.as_str();
        let (snapshot_touched, contact_touched) = self.touched();
        if !snapshot_touched && !contact_touched {
            return Ok(());
        }
        // `persist_first_state` saw no registered actor before the writes,
        // and the claim this guard holds keeps every other bootstrap,
        // restore and respawn of the id out, so an actor registered now is
        // the one this operation spawned, and the records are its state. A
        // dropped Supervisor runs no actor.
        if let Ok(Some(_)) = self.supervisor.lookup(context_id) {
            tracing::warn!(
                context_id,
                "first-state rollback skipped: the operation's actor is registered"
            );
            return Ok(());
        }
        let priors = self.priors.get().ok_or_else(|| {
            ContextError::InvalidState(format!(
                "first-state rollback of '{context_id}': a record was written before its \
                 prior value was read"
            ))
        })?;
        if snapshot_touched {
            let restored = match &priors.snapshot {
                Some(prior) => self.persistence.persist_context(context_id, prior).await,
                None => self.persistence.delete_context(context_id).await,
            };
            restored.map_err(|e| {
                scp_runtime_types::metrics::record_persistence_failure();
                tracing::error!(
                    context_id,
                    error = %e,
                    "first-state rollback could not put back the snapshot; the \
                     last_relay_contact is kept"
                );
                ContextError::PersistenceFailed(format!(
                    "rolling back the first snapshot of '{context_id}' failed, so its \
                     last_relay_contact is kept: {e}"
                ))
            })?;
        }
        if contact_touched {
            let restored = match priors.contact {
                Some(prior) => {
                    self.contacts
                        .store_last_relay_contact(context_id, prior)
                        .await
                }
                None => self.contacts.delete_last_relay_contact(context_id).await,
            };
            restored.map_err(|e| {
                scp_runtime_types::metrics::record_persistence_failure();
                tracing::error!(
                    context_id,
                    error = %e,
                    "first-state rollback could not put back the last_relay_contact"
                );
                ContextError::PersistenceFailed(format!(
                    "rolling back the first last_relay_contact of '{context_id}' failed: {e}"
                ))
            })?;
        }
        Ok(())
    }

    /// The undo of a rollback that could not take `bootstrap_spawn_lock` in
    /// its own turn, run by a tracked task that holds the lock: it logs a
    /// failure, since no caller waits for it, then releases the claim.
    async fn finish_deferred_undo(self: Arc<Self>) {
        if let Err(error) = self.undo_locked().await {
            tracing::error!(
                context_id = self.context_id.as_str(),
                %error,
                "deferred first-state rollback failed; its records stay"
            );
        }
        self.release_claim();
    }
}

impl Drop for FirstStateRollbackInner {
    /// A guard whose rollback did not finish, because its writes did not
    /// drain, keeps the claim until the writes task and every rollback task
    /// holding this state end; the last of them releases it here.
    fn drop(&mut self) {
        self.release_claim();
    }
}

/// Puts back the first-state records of an operation whose actor never
/// started.
///
/// The operation is a create, Welcome join, import, standing-context create or
/// migration create that fails or times out before its actor starts (ADR-029
/// Implementation; ADR-049 Decision 9).
///
/// The operation's owner builds it before the operation's future and keeps
/// it outside any timeout, so a `LIFECYCLE_TIMEOUT` that drops the future
/// still reaches it. [`Self::new`] claims the context id, and
/// [`persist_first_state`] records the snapshot and contact stored before it
/// writes and each write's progress. The owner calls [`Self::commit`] once the actor is
/// registered, or on failure releases `bootstrap_spawn_lock` and calls
/// [`Self::rollback`], which waits for the writes with the lock released and
/// retakes it for the restores; the migration create, which runs in an
/// actor turn that already holds the lock, calls
/// [`Self::rollback_with_guard`]. A guard dropped unsettled with a touched
/// record runs its rollback on a tracked task.
///
/// The writes run in a tracked task, and a rollback waits for that task
/// before it reads which records were touched, so a write an operation's
/// timeout abandoned, on a blocking thread or in a host callback, cannot
/// land after the rollback. The claim keeps every other bootstrap, restore
/// and respawn of the id out while the lock is released.
pub struct FirstStateRollback {
    /// The state shared with the writes task and any rollback task.
    inner: Arc<FirstStateRollbackInner>,
}

impl FirstStateRollback {
    /// A guard for the first-state writes of `context_id`, over the stores
    /// `deps` writes to. It claims `context_id` in `pending_first_state`
    /// until it commits or rolls back, so an operation over an id whose
    /// earlier rollback is still running fails here, before any write.
    ///
    /// # Errors
    ///
    /// - [`ContextError::ActorBusy`] while another operation's first state of
    ///   `context_id` is unsettled; it is retryable.
    /// - [`ContextError::SupervisorShutDown`] when the Supervisor has
    ///   dropped.
    pub fn new(deps: &ActorDeps, context_id: &str) -> Result<Self, ContextError> {
        deps.supervisor.claim_first_state(context_id)?;
        Ok(Self {
            inner: Arc::new(FirstStateRollbackInner {
                persistence: Arc::clone(&deps.persistence),
                contacts: deps.supervisor.relay_contact_store()?,
                supervisor: deps.supervisor.clone(),
                context_id: context_id.to_owned(),
                priors: std::sync::OnceLock::new(),
                contact: std::sync::atomic::AtomicU8::new(RECORD_NOT_WRITTEN),
                snapshot: std::sync::atomic::AtomicU8::new(RECORD_NOT_WRITTEN),
                writes_idle: tokio::sync::watch::Sender::new(true),
                abandoned: std::sync::atomic::AtomicBool::new(false),
                claimed: std::sync::atomic::AtomicBool::new(true),
                settled: std::sync::atomic::AtomicBool::new(false),
            }),
        })
    }

    /// Keeps the written records and releases the claim: the operation's
    /// actor is registered.
    pub fn commit(&self) {
        self.inner
            .settled
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.inner.release_claim();
    }

    /// Test-only reach into [`Self::rollback`] for tests outside this crate.
    /// Compiled only under `testing`, so no production or bridge build
    /// reaches it (ADR-070 §4).
    ///
    /// # Errors
    ///
    /// Every error [`Self::rollback`] returns.
    #[cfg(any(test, feature = "testing"))]
    pub async fn rollback_for_test<G>(
        &self,
        relock: impl std::future::Future<Output = G>,
    ) -> Result<(), ContextError> {
        Self::rollback(self, relock).await
    }

    /// Puts back the records the operation touched; a no-op after
    /// [`Self::commit`] or an earlier rollback.
    ///
    /// The owner calls it with `bootstrap_spawn_lock` released and passes
    /// the lock's acquire as `relock`: the rollback waits for the writes
    /// first, which can take [`FIRST_STATE_WRITES_DRAIN`], then awaits
    /// `relock` and holds its guard through the `lookup` and the restores.
    ///
    /// # Errors
    ///
    /// [`ContextError::PersistenceFailed`] when the writes did not finish or
    /// putting back a record fails; a failed snapshot step keeps the
    /// contact.
    pub(in crate::context) async fn rollback<G>(
        &self,
        relock: impl std::future::Future<Output = G>,
    ) -> Result<(), ContextError> {
        if self
            .inner
            .settled
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            return Ok(());
        }
        // A failed drain keeps the claim: the writes may still land, and the
        // writes task's drop of the state releases it.
        self.inner.drain_writes().await?;
        let result = if self.inner.touched() == (false, false) {
            Ok(())
        } else {
            let _bootstrap_guard = relock.await;
            self.inner.undo_locked().await
        };
        self.inner.release_claim();
        result
    }

    /// The rollback of the migration create, which runs in the source
    /// context's actor turn under the `bootstrap_spawn_lock` guard its
    /// governance call reserved before its first record. It waits for the
    /// writes, reads what was touched and puts it back while still holding
    /// `guard`, then releases it, so it never waits for the lock and never
    /// returns a retryable `ActorBusy` after the call recorded its proposal
    /// or vote. The migration awaits its writes task to the end, so the wait
    /// returns at once unless shutdown abandoned the writes.
    ///
    /// # Errors
    ///
    /// As for [`Self::rollback`].
    pub async fn rollback_with_guard(
        &self,
        guard: tokio::sync::OwnedMutexGuard<()>,
    ) -> Result<(), ContextError> {
        if self
            .inner
            .settled
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            return Ok(());
        }
        // A failed drain keeps the claim, as in `rollback`.
        self.inner.drain_writes().await?;
        let result = if self.inner.touched() == (false, false) {
            Ok(())
        } else {
            self.inner.undo_locked().await
        };
        drop(guard);
        self.inner.release_claim();
        result
    }

    /// Reads the snapshot and contact stored before the first write.
    ///
    /// # Errors
    ///
    /// [`ContextError::PersistenceFailed`] when either read fails, and
    /// [`ContextError::InvalidState`] when this guard already captured them.
    async fn capture_priors(&self) -> Result<(), ContextError> {
        let inner = &self.inner;
        let context_id = inner.context_id.as_str();
        let snapshot = inner
            .persistence
            .load_context(context_id)
            .await
            .map_err(|e| {
                ContextError::PersistenceFailed(format!(
                    "reading the stored snapshot of '{context_id}' before its first write \
                 failed: {e}"
                ))
            })?;
        let contact = inner
            .contacts
            .load_last_relay_contact(context_id)
            .await
            .map_err(|e| {
                ContextError::PersistenceFailed(format!(
                    "reading the stored last_relay_contact of '{context_id}' before its \
                     first write failed: {e}"
                ))
            })?;
        inner
            .priors
            .set(FirstStatePriors { snapshot, contact })
            .map_err(|_| {
                ContextError::InvalidState(format!(
                    "the first state of '{context_id}' was already written under this guard"
                ))
            })
    }
}

impl Drop for FirstStateRollback {
    fn drop(&mut self) {
        if self
            .inner
            .settled
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            return;
        }
        let (snapshot_touched, contact_touched) = self.inner.touched();
        if !snapshot_touched && !contact_touched {
            self.inner.release_claim();
            return;
        }
        let context_id = self.inner.context_id.clone();
        // The task waits for the writes with the lock released, then takes
        // `bootstrap_spawn_lock` before its `lookup` and holds it through both
        // restores. The claim keeps every other bootstrap of the id out
        // meanwhile.
        let drained = {
            let inner = Arc::clone(&self.inner);
            async move {
                match inner.drain_writes().await {
                    Ok(()) => true,
                    Err(error) => {
                        tracing::error!(
                            context_id = inner.context_id.as_str(),
                            %error,
                            "first-state rollback of a dropped operation did not run; its \
                             records stay"
                        );
                        false
                    }
                }
            }
        };
        let inner = Arc::clone(&self.inner);
        if let Err(error) = self.inner.supervisor.spawn_under_bootstrap_spawn_lock(
            "first_state_rollback",
            drained,
            move || inner.finish_deferred_undo(),
        ) {
            scp_runtime_types::metrics::record_persistence_failure();
            tracing::error!(
                context_id,
                %error,
                "first-state rollback of a dropped operation could not start; its records stay"
            );
        }
    }
}

/// Folds a failed rollback into the operation's own failure: the stores
/// still hold records of a context with no actor, which the caller must see.
pub fn fold_rollback_failure(
    failure: &dyn std::fmt::Display,
    rollback: &ContextError,
) -> ContextError {
    ContextError::PersistenceFailed(format!("{failure}; {rollback}"))
}

/// Writes the first `last_relay_contact` of a context whose actor is about
/// to start, as the current time, then its first snapshot, both before the
/// spawn.
///
/// Create, Welcome join and import call it, and the standing-context and
/// migration creates reach it through `create_context`. The snapshot is
/// Class S state (ADR-049 Decision 9), and the contact is the value a later
/// full reconnection classifies the offline tier from (ADR-029
/// Implementation). The contact goes first, so no stored snapshot lacks a
/// contact. `rollback` records the values stored before and each write's
/// progress; the caller rolls back on failure. The
/// writes run in a tracked task `rollback` keeps, so a rollback after this
/// future is dropped waits for them.
///
/// # Errors
///
/// - [`ContextError::CreationFailed`] when an actor is registered for
///   `context_id`.
/// - [`ContextError::PersistenceFailed`] when reading the stored values, the
///   contact write, or the snapshot write fails, or the writes task ends
///   without finishing.
/// - [`ContextError::InvalidState`] when `rollback` guards another context
///   or already recorded a write.
/// - [`ContextError::SupervisorShutDown`] when the Supervisor has dropped or
///   shutdown has begun.
///
/// # Not `async fn`
///
/// The `&PerContextState` is consumed in the synchronous prelude, as in
/// [`crate::context::snapshot::persist_state_fail_closed`], so the
/// returned future is `Send`.
pub fn persist_first_state<'d, 'c, 'r>(
    state: &PerContextState,
    deps: &'d ActorDeps,
    context_id: &'c str,
    rollback: &'r FirstStateRollback,
) -> impl std::future::Future<Output = Result<(), ContextError>> + Send + use<'d, 'c, 'r> {
    let snapshot =
        crate::context::snapshot::build_snapshot_for_persist(state, deps, context_id).map(Box::new);
    async move {
        let inner = &rollback.inner;
        if inner.context_id != context_id {
            return Err(ContextError::InvalidState(format!(
                "the first-state guard of '{}' cannot record the writes of '{context_id}'",
                inner.context_id
            )));
        }
        if deps.supervisor.lookup(context_id)?.is_some() {
            return Err(ContextError::CreationFailed(format!(
                "context '{context_id}' has a running actor; its state is not overwritten"
            )));
        }
        let snapshot = snapshot?;
        rollback.capture_priors().await?;
        let shutdown = deps.supervisor.shutdown_signal()?;
        let now = deps.clock.now_secs();
        // The writes and the contact count as started from before the task
        // can run, so a guard dropped before its first poll still waits for
        // it and rolls back the write it goes on to make.
        inner.writes_idle.send_replace(false);
        FirstStateRollbackInner::mark(&inner.contact, RECORD_IN_FLIGHT);
        let writes = first_state_writes(Arc::clone(inner), now, snapshot, shutdown);
        // A refused spawn drops `writes`, whose idle guard marks the writes
        // idle again.
        let running = match deps.supervisor.spawn_tracked("first-state writes", writes) {
            Ok(handle) => handle,
            Err(e) => {
                FirstStateRollbackInner::mark(&inner.contact, RECORD_NOT_WRITTEN);
                return Err(e);
            }
        };
        running.await.map_err(|e| {
            ContextError::PersistenceFailed(format!(
                "the first-state writes of '{context_id}' ended without finishing: {e}"
            ))
        })?
    }
}

/// How a freshly spawned context's TTL timer is armed.
#[derive(Debug)]
pub enum TtlArming {
    /// No TTL timer: the context has no finite TTL, or a promoted import.
    Unarmed,
    /// The actor derives the convergent `creation_timestamp_secs + params.ttl`
    /// deadline (create, the Welcome join).
    CreateBase,
    /// The deadline derived from the imported event log (ADR-049 §9).
    Deadline(crate::context::supervisor::handle::ConvergentDeadline),
}

/// A context whose actor is registered and whose post-spawn wiring, the gauge
/// refresh and the TTL timer, has not run.
///
/// The handle is reachable only through [`Self::finalize`], so no bootstrap
/// returns a context without its TTL timer. The owner runs `finalize` after
/// it releases `bootstrap_spawn_lock`: the TTL install waits on the new
/// actor's mailbox, and a mailbox wait under that lock waits on any actor
/// whose turn waits for the lock, such as a migration source creating its
/// destination. The governance-timeout interval is actor-owned (ADR-049
/// Decision-1 / finding A3): the spawned actor's `reconcile_timers` arms it
/// while `Active`, so no install is needed.
#[derive(Debug)]
#[must_use = "run `finalize` after releasing `bootstrap_spawn_lock`"]
pub struct SpawnedContext {
    /// The handle of the spawned actor's context.
    pub handle: ContextHandle,
    /// How `finalize` arms the context's TTL timer.
    ttl: TtlArming,
}

impl SpawnedContext {
    /// A created or Welcome-joined context, whose TTL timer the actor arms
    /// from its creation timestamp when `params.ttl` is finite.
    pub const fn at_create_base(handle: ContextHandle) -> Self {
        let ttl = if handle.params().ttl.is_some() {
            TtlArming::CreateBase
        } else {
            TtlArming::Unarmed
        };
        Self { handle, ttl }
    }

    /// An imported context, whose TTL timer `finalize` arms as `ttl` says
    /// (the deadline derived from the imported event log, or unarmed).
    pub const fn with_ttl(handle: ContextHandle, ttl: TtlArming) -> Self {
        Self { handle, ttl }
    }

    /// Starts the gauge refresh, which no one awaits, and installs the TTL
    /// timer by mailboxing the actor, a wait bounded by the send and reply
    /// timeouts of
    /// [`SupervisorHandle::dispatch_start_ttl_timer`](crate::context::supervisor::handle::SupervisorHandle::dispatch_start_ttl_timer).
    ///
    /// # Errors
    ///
    /// [`ContextError::SupervisorShutDown`] when the Supervisor has dropped
    /// or shutdown has begun (ADR-049 Decision 16).
    pub async fn finalize(self, deps: &ActorDeps) -> Result<ContextHandle, ContextError> {
        let Self { handle, ttl } = self;
        deps.supervisor.update_context_gauges()?;
        let deadline = match ttl {
            TtlArming::Unarmed => return Ok(handle),
            TtlArming::CreateBase => None,
            TtlArming::Deadline(deadline) => Some(deadline),
        };
        deps.supervisor
            .dispatch_start_ttl_timer(handle.context_id(), handle.params().clone(), deadline)
            .await?;
        Ok(handle)
    }
}

/// Sweep entry point: flushes every actor's snapshot to the configured
/// persistence provider.
///
/// Relocates the legacy `flush_all_contexts_legacy` off the
/// `Supervisor::contexts` `DashMap` (now deleted). Iterates the actor
/// registry and dispatches one
/// [`LifecycleCommand::FlushSnapshot`](crate::context::actor::commands::LifecycleCommand::FlushSnapshot)
/// per actor. Every actor is flushed even after one fails. An actor that
/// despawned between the listing and the lookup holds nothing to flush, and
/// neither does one that left its `run()` loop on purpose between the lookup
/// and its reply: it recorded a Shutdown, a claimed `PrepareForReplace` or a
/// TTL expiry on its handle ([`ContextActorHandle::exited_deliberately`]),
/// so the flush skips it. No-op if no persistence provider is configured.
///
/// # Errors
///
/// The first actor's failure, in registry order, when any flush did not land
/// (ADR-049 Decision 9): the flush's own error; the mailbox send's error
/// (a full mailbox, or an inbox that closed without a deliberate exit); or
/// [`ContextError::ActorCrashed`] when the actor dropped its reply without a
/// deliberate exit, as a panic does. Each failure is also logged.
///
/// [`ContextActorHandle::exited_deliberately`]: crate::context::actor::ContextActorHandle
pub async fn flush_all_contexts(
    supervisor: &crate::context::supervisor::Supervisor,
) -> Result<(), ContextError> {
    use crate::context::actor::commands::{ContextCommand, LifecycleCommand};

    if !crate::context::manager_methods::has_persistence(supervisor) {
        return Ok(());
    }

    let mut flushed = 0usize;
    let mut first_error: Option<ContextError> = None;
    for ctx_id in supervisor.actor_ids() {
        let Some(actor) = supervisor.lookup(&ctx_id) else {
            continue;
        };
        let (tx, rx) = tokio::sync::oneshot::channel();
        let cmd = ContextCommand::Lifecycle(LifecycleCommand::FlushSnapshot { reply: tx });
        // An unanswered flush is skipped only when the actor recorded a
        // deliberate exit: a closed, replaced or expired context holds
        // nothing this sweep must persist. A reply the actor dropped for any
        // other reason, a panic included, is a flush that did not land.
        let unanswered = |e: ContextError| match actor.exited_deliberately() {
            Some(exit) => {
                tracing::debug!(
                    context_id = %ctx_id,
                    ?exit,
                    error = %e,
                    "flush_all_contexts: the actor exited on purpose before it flushed; skipped"
                );
                None
            }
            None => Some(e),
        };
        let flushed_one = match actor
            .send_with_timeout(cmd, crate::context::actor::SEND_TIMEOUT)
            .await
        {
            Ok(()) => match rx.await {
                Ok(result) => result,
                Err(_dropped) => match unanswered(ContextError::ActorCrashed(format!(
                    "the actor of {ctx_id} dropped its flush reply"
                ))) {
                    Some(e) => Err(e),
                    None => continue,
                },
            },
            Err(e) => match unanswered(e) {
                Some(e) => Err(e),
                None => continue,
            },
        };
        match flushed_one {
            Ok(()) => flushed += 1,
            Err(e) => {
                tracing::warn!(
                    context_id = %ctx_id,
                    error = %e,
                    "flush_all_contexts: the flush did not land"
                );
                first_error.get_or_insert(e);
            }
        }
    }
    tracing::debug!(
        flushed,
        "flush_all_contexts: flushed {} context(s) via actor mailbox",
        flushed,
    );
    first_error.map_or(Ok(()), Err)
}

/// Builds an [`IdentityDepthAssessment`](scp_protocol::trust::sybil::IdentityDepthAssessment) for a member in a context.
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
pub fn build_identity_assessment(
    member_did: &DID,
    governance: &crate::context::state::GovernanceState,
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

/// The write returned an error, so the record keeps what the store held.
pub(crate) const RECORD_FAILED: u8 = 2;

/// The write returned `Ok`.
pub(crate) const RECORD_WRITTEN: u8 = 3;

/// Whether a record whose write progress is `state` may have been written:
/// `RECORD_IN_FLIGHT` or `RECORD_WRITTEN`.
#[must_use]
const fn record_touched(state: u8) -> bool {
    matches!(state, RECORD_IN_FLIGHT | RECORD_WRITTEN)
}

/// The snapshot and `last_relay_contact` stored for a context before its
/// first-state writes began.
pub(crate) struct FirstStatePriors {
    /// The stored snapshot, or `None` when the store held none.
    snapshot: Option<crate::context::state::ContextSnapshot>,
    /// The stored `last_relay_contact`, or `None` when the store held none.
    contact: Option<u64>,
}

/// How long abandoned first-state writes may still run.
///
/// A rollback waits this long for writes its operation abandoned before it
/// gives up and keeps the records, and the writes run this long after
/// Supervisor shutdown begins before they are abandoned.
pub(crate) const FIRST_STATE_WRITES_DRAIN: std::time::Duration = std::time::Duration::from_secs(30);

/// The first-state writes task.
///
/// Its [`WritesIdleOnDrop`] is built before the future, so a future dropped
/// before its first poll still marks the writes idle. Once Supervisor shutdown
/// begins the writes run at most [`FIRST_STATE_WRITES_DRAIN`] longer and are
/// then abandoned, so shutdown, which awaits every tracked task, ends.
///
/// # Errors
///
/// The future resolves to the error of
/// [`FirstStateRollbackInner::write_first_state`], or to
/// [`ContextError::PersistenceFailed`] when Supervisor shutdown abandoned the
/// writes.
fn first_state_writes(
    inner: Arc<FirstStateRollbackInner>,
    now: u64,
    snapshot: Box<crate::context::state::ContextSnapshot>,
    shutdown: tokio_util::sync::CancellationToken,
) -> impl std::future::Future<Output = Result<(), ContextError>> + Send + 'static {
    let idle_on_exit = WritesIdleOnDrop(Arc::clone(&inner));
    async move {
        let _idle_on_exit = idle_on_exit;
        tokio::select! {
            written = inner.write_first_state(now, &snapshot) => written,
            () = async {
                shutdown.cancelled().await;
                tokio::time::sleep(FIRST_STATE_WRITES_DRAIN).await;
            } => {
                let context_id = inner.context_id.as_str();
                inner
                    .abandoned
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                scp_runtime_types::metrics::record_persistence_failure();
                tracing::error!(
                    context_id,
                    "shutdown abandoned the first-state writes before they finished; their \
                     records are kept"
                );
                Err(ContextError::PersistenceFailed(format!(
                    "shutdown abandoned the first-state writes of '{context_id}' before they \
                     finished"
                )))
            }
        }
    }
}

/// Sets a first-state guard's `writes_idle` when the writes future is
/// dropped: when it returns, panics, is cancelled, or is dropped before its
/// first poll.
///
/// [`first_state_writes`] builds it before the future, so the last case holds
/// too.
pub struct WritesIdleOnDrop(pub Arc<FirstStateRollbackInner>);

impl Drop for WritesIdleOnDrop {
    fn drop(&mut self) {
        self.0.writes_idle.send_replace(true);
    }
}

/// Test-only reach into fields that stay private to this crate. Compiled only
/// under `testing`, so no production or bridge build reaches them (ADR-070 §4).
#[cfg(any(test, feature = "testing"))]
impl FirstStateRollback {
    /// Marks the guard's writes in flight, as `persist_first_state` does.
    pub fn mark_writes_busy_for_test(&self) {
        self.inner.writes_idle.send_replace(false);
    }

    /// Whether the guard's writes are idle.
    #[must_use]
    pub fn writes_idle_for_test(&self) -> bool {
        *self.inner.writes_idle.borrow()
    }

    /// The first-state writes future over this guard's shared state.
    pub fn first_state_writes_for_test(
        &self,
        now: u64,
        snapshot: Box<crate::context::state::ContextSnapshot>,
        shutdown: tokio_util::sync::CancellationToken,
    ) -> impl std::future::Future<Output = Result<(), ContextError>> + Send + 'static {
        first_state_writes(Arc::clone(&self.inner), now, snapshot, shutdown)
    }
}
