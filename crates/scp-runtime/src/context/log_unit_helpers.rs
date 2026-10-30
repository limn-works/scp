//! The drain of queued event-log units (spec 17 §17.3 "Event log write
//! failures"; ADR-049 §9 Class S).
//!
//! An operation that writes event-log entries after its irreversible step
//! queues them as a pending log unit inside the fail-closed persist that
//! records the step. [`drain_pending_log_units`] writes the queue to the log
//! in order, one unit at a time:
//!
//! 1. take the provider's write gate and read the log's length;
//! 2. when the unit has no `base_seq`, reserve it at that length and persist
//!    the reservation through `commit_class_s_restore` (a failed persist
//!    leaves the unit unreserved);
//! 3. write the unit under the same gate: `Appended` or `AlreadyPresent`
//!    removes it through `commit_class_s_restore`; a `base_seq` past the
//!    log's end is reserved again at the log's length, once per unit per
//!    drain; any other misalignment sets the log fault, so the queue is
//!    written in FIFO order with no exception.
//!
//! The drain tells the provider whether units remain queued before it takes
//! the write gate and on every exit, so the provider's fence follows the
//! queue.
//!
//! Every reserve and removal persists through the restore combinator, so the
//! stored queue never holds a unit the in-memory queue has removed, and a
//! context whose in-memory queue is empty has an empty stored queue.

use scp_protocol::context::ContextError;

use crate::context::actor::class_s::{ClassSCell, ClassSCommitToken, ClassSMut};
use crate::context::actor::deps::ActorDeps;
use crate::context::builder::{UnitAppendError, UnitAppended};
use crate::context::state::{LeafSpec, LogFaultMarker, context_id_to_bytes};

/// What consequence enforcement owes after an operation's irreversible step
/// (spec 17 §17.3 "Event log write failures"; ADR-049 §9): the downward-auth
/// persist obligation and the durable consequence leaves.
///
/// [`Self::discharge`] queues the leaves as one pending log unit and
/// discharges the obligation, all in one fail-closed keep persist, so the stored state that holds the step's
/// mutations also holds its leaves. A caller that keeps the memory-first rule
/// takes the parts with [`Self::into_parts`] instead.
#[must_use = "a ConsequenceSink must be discharged; dropping it loses the consequence leaves"]
#[derive(Default)]
pub struct ConsequenceSink {
    /// The downward-auth fail-closed persist obligation the GROW methods arm.
    pub(crate) obligation: Option<ClassSCommitToken>,
    /// Durable consequence leaves, in the order the engine produced them.
    leaves: Vec<LeafSpec>,
}

impl ConsequenceSink {
    /// An empty sink.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a durable consequence leaf.
    pub fn push_leaf(&mut self, leaf: LeafSpec) {
        self.leaves.push(leaf);
    }

    /// The leaves staged so far, which a later evaluation in the same
    /// operation counts as evidence (spec 17 §17.3 "Event log write
    /// failures").
    pub fn staged_leaves(&self) -> &[LeafSpec] {
        &self.leaves
    }

    /// True when the sink owes nothing: no obligation and no leaf.
    pub const fn is_empty(&self) -> bool {
        self.obligation.is_none() && self.leaves.is_empty()
    }

    /// Takes the obligation and the leaves for a caller that keeps the
    /// memory-first rule after its step.
    pub(crate) fn into_parts(mut self) -> (Option<ClassSCommitToken>, Vec<LeafSpec>) {
        (self.obligation.take(), std::mem::take(&mut self.leaves))
    }

    /// Queues the leaves as one pending log unit and discharges the
    /// obligation in one fail-closed keep persist, then drains the queue. With nothing owed it does nothing.
    ///
    /// The drain's own failure leaves the unit queued for the next drain and
    /// is logged by [`drain_pending_log_units`]; it does not fail the
    /// operation, whose step is already taken.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::PersistenceFailed`] when the persist fails (the
    /// queued unit and the step's mutations stay in memory).
    pub async fn discharge(
        mut self,
        cell: &mut ClassSCell,
        deps: &ActorDeps,
        context_id: &str,
    ) -> Result<(), ContextError> {
        let obligation = self.obligation.take();
        let leaves = std::mem::take(&mut self.leaves);
        if obligation.is_none() && leaves.is_empty() {
            return Ok(());
        }
        let mutate = move |mut view: ClassSMut| {
            view.enqueue_log_unit(leaves);
            Ok(())
        };
        let result = match obligation {
            Some(token) => token.discharge_with(cell, deps, context_id, mutate).await,
            None => cell.commit_class_s_keep(deps, context_id, mutate).await,
        };
        let _ = drain_pending_log_units(cell, deps, context_id).await;
        result
    }
}

impl Drop for ConsequenceSink {
    fn drop(&mut self) {
        if !self.leaves.is_empty() {
            tracing::error!(
                leaves = self.leaves.len(),
                "ConsequenceSink dropped undischarged; consequence leaves are lost"
            );
        }
    }
}

/// Queues `leaves` as one pending log unit, counted toward the §9.9.3
/// checkpoint triggers, in one fail-closed keep persist that also carries
/// every in-memory mutation the step made before it (spec 17 §17.3 "Event log
/// write failures"). It does not drain: per-action helpers leave the drain to
/// the actor's next command.
///
/// # Errors
///
/// Returns [`ContextError::PersistenceFailed`] when the persist fails (the
/// queued unit and the step's mutations stay in memory).
pub async fn queue_log_unit(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    leaves: Vec<LeafSpec>,
) -> Result<(), ContextError> {
    cell.commit_class_s_keep(deps, context_id, move |mut view: ClassSMut| {
        view.enqueue_counted_log_unit(leaves);
        Ok(())
    })
    .await
}

/// Returns the leaves of `leaves` that neither the context's log nor its
/// queue already holds. A leaf matches a log entry identical in event type,
/// actor, payload and timestamp, or an equal queued leaf. A re-send after an
/// unanswered `LogUnitCommand` filters through it, so the record lands once
/// (spec 17 §17.3 "Event log write failures").
///
/// # Errors
///
/// Returns [`ContextError::EventLogFailed`] when the context has no event log,
/// or the provider's error when the log cannot be read: an unread log cannot
/// prove the leaf absent, so the caller retries instead of risking a second
/// copy.
pub fn leaves_absent_from_log_and_queue(
    cell: &ClassSCell,
    deps: &ActorDeps,
    context_id_bytes: &[u8; 32],
    leaves: Vec<LeafSpec>,
) -> Result<Vec<LeafSpec>, ContextError> {
    let entries = deps
        .event_log
        .event_log_entries(context_id_bytes)?
        .ok_or_else(|| {
            ContextError::EventLogFailed(format!(
                "no event log for context {}; a re-sent leaf cannot be proven absent",
                hex::encode(context_id_bytes)
            ))
        })?;
    Ok(leaves
        .into_iter()
        .filter(|leaf| {
            let in_log = entries.iter().any(|event| {
                event.event_type == leaf.event_type()
                    && event.actor_did.0 == leaf.actor_did()
                    && event.payload == *leaf.payload()
                    && event.timestamp == leaf.timestamp_secs()
            });
            let queued = cell
                .class_s
                .pending_log_units
                .iter()
                .any(|unit| unit.leaves.iter().any(|q| q == leaf));
            !in_log && !queued
        })
        .collect())
}

/// Plans one entry of a pending log unit before the operation's irreversible
/// step, checking it against the append's payload rules (spec 17 §17.3 "Event
/// log write failures"), so a payload that breaks them refuses the operation
/// before the step and never after it.
///
/// # Errors
///
/// Returns [`ContextError::EventLogFailed`] when the payload breaks the
/// append's payload rules for `event_type`.
pub fn plan_leaf(
    event_type: scp_event_log::EventType,
    actor_did: String,
    payload: scp_event_log::EventPayload,
    timestamp_secs: u64,
) -> Result<LeafSpec, ContextError> {
    LeafSpec::new(event_type, actor_did, payload, timestamp_secs)
}

/// Plans one entry whose payload is `payload` encoded as the log's payload
/// encoding, before the operation's step (spec 17 §17.3 "Event log write
/// failures").
///
/// # Errors
///
/// Returns [`ContextError::EventLogFailed`] when the payload does not encode
/// or breaks the append's payload rules for `event_type`.
pub fn plan_encoded_leaf<T: serde::Serialize>(
    event_type: scp_event_log::EventType,
    actor_did: &str,
    payload: &T,
    timestamp_secs: u64,
) -> Result<LeafSpec, ContextError> {
    plan_leaf(
        event_type,
        actor_did.to_owned(),
        scp_event_log::payload::encode_payload(payload)
            .map_err(|e| ContextError::EventLogFailed(e.to_string()))?,
        timestamp_secs,
    )
}

/// Plans a `MemberJoined` / `MemberLeft` leaf. It is the one encoder for that
/// leaf: [`ContextEventLogProvider::append_membership_change_leaf`] appends
/// the payload it plans, so a queued leaf and an appended one carry the same
/// bytes (spec 17 §17.3 "Event log write failures").
///
/// [`ContextEventLogProvider::append_membership_change_leaf`]:
///     crate::context::builder::ContextEventLogProvider::append_membership_change_leaf
///
/// # Errors
///
/// Returns [`ContextError::EventLogFailed`] when the payload does not encode
/// or breaks the append's payload rules.
pub fn plan_membership_change_leaf(
    event_type: scp_event_log::EventType,
    actor_did: &str,
    change: &scp_event_log::payload::MembershipChangePayload,
    timestamp_secs: u64,
) -> Result<LeafSpec, ContextError> {
    plan_leaf(
        event_type,
        actor_did.to_owned(),
        scp_event_log::payload::encode_payload(change)
            .map_err(|e| ContextError::EventLogFailed(e.to_string()))?,
        timestamp_secs,
    )
}

/// Plans a `RoleAssigned` leaf for `subject_did` taking `role`. It is the one
/// encoder for that leaf: the step that assigns the role queues the leaf it
/// plans, and only the pending-unit drain writes it (spec 17 §17.3 "Event log
/// write failures").
///
/// # Errors
///
/// Returns [`ContextError::EventLogFailed`] when the payload does not encode
/// or breaks the append's payload rules.
pub fn plan_role_assigned_leaf(
    actor_did: &str,
    subject_did: &str,
    role: &str,
    timestamp_secs: u64,
) -> Result<LeafSpec, ContextError> {
    plan_leaf(
        scp_event_log::EventType::RoleAssigned,
        actor_did.to_owned(),
        scp_event_log::payload::encode_payload(&scp_event_log::payload::RoleAssignedPayload {
            subject_did: subject_did.to_owned(),
            role: role.to_owned(),
        })
        .map_err(|e| ContextError::EventLogFailed(e.to_string()))?,
        timestamp_secs,
    )
}

/// Plans a `TtlExtended` leaf. It is the one encoder for that leaf: the
/// bilateral reset's fail-closed append writes the payload it plans (spec 17
/// §17.3 "Event log write failures").
///
/// # Errors
///
/// Returns [`ContextError::EventLogFailed`] when the payload does not encode
/// or breaks the append's payload rules.
pub fn plan_ttl_extended_leaf(
    actor_did: &str,
    extension: &scp_event_log::payload::TtlExtendedPayload,
    timestamp_secs: u64,
) -> Result<LeafSpec, ContextError> {
    plan_leaf(
        scp_event_log::EventType::TtlExtended,
        actor_did.to_owned(),
        scp_event_log::payload::encode_payload(extension).map_err(|e| {
            ContextError::EventLogFailed(format!("failed to encode TtlExtended payload: {e}"))
        })?,
        timestamp_secs,
    )
}

/// Plans an `OutletInvoked` leaf after the FULL §5.4.5:566 manifest check
/// over the `reassembled` chunk sequence. It is the one encoder for that leaf:
/// the receiving context queues the leaf it plans through
/// `LogUnitRequest::VerifiedOutletInvoked`, and only the pending-unit drain
/// writes it (spec 17 §17.3 "Event log write failures"). The leaf's own
/// construction then runs the event-local backstop.
///
/// # Errors
///
/// Returns [`ContextError::EventLogFailed`] when the manifest check rejects
/// the event, the event does not serialize, or the payload breaks the
/// append's payload rules.
pub fn plan_outlet_invoked_verified_leaf(
    event: &scp_protocol::context::outlets::lifecycle::OutletInvokedEvent,
    reassembled: &[scp_protocol::context::outlets::stream::OutletStreamChunk],
    actor_did: &str,
    timestamp_secs: u64,
) -> Result<LeafSpec, ContextError> {
    crate::context::outlets::stream::verify_outlet_invoked_event_manifest(event, reassembled)
        .map_err(|err| {
            ContextError::EventLogFailed(
                crate::context::outlets::stream::chunks_billed_error_to_event_log_error(err)
                    .to_string(),
            )
        })?;
    let data = serde_json::to_vec(event).map_err(|e| {
        ContextError::EventLogFailed(format!("failed to serialize OutletInvokedEvent: {e}"))
    })?;
    plan_leaf(
        scp_event_log::EventType::OutletInvoked,
        actor_did.to_owned(),
        scp_event_log::EventPayload { data },
        timestamp_secs,
    )
}

/// Plans one `KeyEpochAdvance` record per broadcast author whose key a
/// step rotated (§5.14.10; ADR-007 §5 for a broadcast block or unsubscribe),
/// in the order given. Each rotation
/// advances by exactly 1, so `old_epoch = new_epoch - 1`.
///
/// The records are known only once the rotation ran, so they are planned
/// inside the step's persist. A record that does not encode or breaks the
/// append's payload rules is logged at ERROR and skipped (SCP-349): the
/// rotation is already taken, and refusing it here would report a rotation
/// that landed as one that did not.
pub fn key_epoch_advance_leaves<'a>(
    advances: impl IntoIterator<Item = (&'a str, u64)>,
    timestamp_secs: u64,
    context_id: &str,
) -> Vec<LeafSpec> {
    advances
        .into_iter()
        .filter_map(|(author_did, new_epoch)| {
            plan_encoded_leaf(
                scp_event_log::EventType::KeyEpochAdvance,
                author_did,
                &scp_event_log::payload::KeyEpochAdvancePayload {
                    old_epoch: new_epoch.saturating_sub(1),
                    new_epoch,
                },
                timestamp_secs,
            )
            .inspect_err(|e| {
                tracing::error!(
                    context_id = %context_id,
                    author_did = %author_did,
                    error = %e,
                    "KeyEpochAdvance record refused after a key rotation — \
                     the event log is short one leaf for this author"
                );
            })
            .ok()
        })
        .collect()
}

/// True when the context has queued log units or a log fault, so a drain has
/// work to do.
pub fn has_log_unit_work(cell: &ClassSCell) -> bool {
    !cell.class_s.pending_log_units.is_empty() || cell.class_s.log_fault.is_some()
}

/// Drains the context's queued log units in order (spec 17 §17.3 "Event log
/// write failures"), then tells the provider whether units remain queued.
///
/// Clears the log fault when the queue empties and the log is loaded.
///
/// # Errors
///
/// Returns [`ContextError::EventLogFailed`] when the write gate, the append,
/// or the log read fails, or when a unit is misaligned (the log fault is set
/// then), and [`ContextError::PersistenceFailed`] when a reserve, a removal,
/// or the fault persist fails. Units not yet written stay queued.
pub async fn drain_pending_log_units(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
) -> Result<(), ContextError> {
    let context_id_bytes = context_id_to_bytes(context_id);
    sync_units_pending(cell, deps, &context_id_bytes);
    if !has_log_unit_work(cell) {
        return Ok(());
    }
    let drained = drain_queue(cell, deps, context_id, &context_id_bytes).await;
    sync_units_pending(cell, deps, &context_id_bytes);
    if let Err(e) = &drained {
        tracing::warn!(
            context_id,
            queued = cell.class_s.pending_log_units.len(),
            error = %e,
            "event log units stay queued; the next drain retries them"
        );
    }
    drained
}

/// Tells the provider whether the context's queue holds a unit, so the
/// provider's fence equals "the queue is non-empty" (spec 17 §17.3 "Event log
/// write failures").
fn sync_units_pending(cell: &ClassSCell, deps: &ActorDeps, context_id_bytes: &[u8; 32]) {
    deps.event_log
        .set_units_pending(context_id_bytes, !cell.class_s.pending_log_units.is_empty());
}

async fn drain_queue(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    context_id_bytes: &[u8; 32],
) -> Result<(), ContextError> {
    // Whether the front unit was already reserved again past the log's end in
    // this drain.
    let mut re_reserved = false;
    while let Some(front) = cell.class_s.pending_log_units.front() {
        let leaves: Vec<LeafSpec> = front.leaves.clone();
        let reserved = front.base_seq;
        let guard = deps
            .event_log
            .lock_for_unit(context_id_bytes)
            .await
            .map_err(|e| ContextError::EventLogFailed(e.to_string()))?;
        let base_seq = if let Some(base_seq) = reserved {
            base_seq
        } else {
            let base_seq = guard.log_len();
            cell.commit_class_s_restore(deps, context_id, |mut view| {
                view.set_front_log_unit_base(Some(base_seq));
                Ok(())
            })
            .await?;
            base_seq
        };
        match deps.event_log.append_unit(guard, base_seq, &leaves).await {
            Ok(UnitAppended::Appended | UnitAppended::AlreadyPresent) => {
                cell.commit_class_s_restore(deps, context_id, |mut view| {
                    view.pop_front_log_unit();
                    Ok(())
                })
                .await?;
                re_reserved = false;
            }
            Err(UnitAppendError::PastEnd { .. }) if !re_reserved => {
                // The unit is not in the log and nothing sits ahead of it:
                // reserve it again at the log's length.
                cell.commit_class_s_restore(deps, context_id, |mut view| {
                    view.set_front_log_unit_base(None);
                    Ok(())
                })
                .await?;
                re_reserved = true;
            }
            Err(
                UnitAppendError::PastEnd { base_seq, log_len }
                | UnitAppendError::Misaligned { base_seq, log_len },
            ) => {
                let detail = format!(
                    "queued event log unit misaligned: base_seq {base_seq}, log length {log_len}"
                );
                set_log_fault(
                    cell,
                    deps,
                    context_id,
                    LogFaultMarker {
                        base_seq,
                        log_len,
                        detail: detail.clone(),
                    },
                )
                .await?;
                return Err(ContextError::EventLogFailed(detail));
            }
            Err(UnitAppendError::Failed(e)) => {
                return Err(ContextError::EventLogFailed(e.to_string()));
            }
        }
    }
    if cell.class_s.log_fault.is_some() {
        match deps.event_log.event_log_entries(context_id_bytes) {
            Ok(Some(_)) => {
                cell.commit_class_s_keep(deps, context_id, |mut view| {
                    view.clear_log_fault();
                    Ok(())
                })
                .await?;
            }
            Ok(None) => {
                return Err(ContextError::EventLogFailed(format!(
                    "no event log for context {context_id}; the log fault stays set"
                )));
            }
            Err(e) => return Err(ContextError::EventLogFailed(e.to_string())),
        }
    }
    Ok(())
}

/// Sets the context's log fault through a keep persist: the marker stays in
/// memory when the persist fails, and the persist error is returned.
///
/// # Errors
///
/// Returns [`ContextError::PersistenceFailed`] when the persist fails.
pub async fn set_log_fault(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    marker: LogFaultMarker,
) -> Result<(), ContextError> {
    tracing::error!(
        context_id,
        base_seq = ?marker.base_seq,
        log_len = ?marker.log_len,
        detail = %marker.detail,
        "context event log faulted; mutations are refused until a drain succeeds"
    );
    cell.commit_class_s_keep(deps, context_id, |mut view| {
        view.set_log_fault(marker);
        Ok(())
    })
    .await
}

/// Fixtures the per-family tests of the queued log units share (spec 17
/// §17.3 "Event log write failures").
#[cfg(test)]
#[allow(clippy::expect_used)]
pub mod test_support {
    use std::sync::Arc;

    use scp_did::DID;
    use scp_event_log::EventType;
    use scp_platform::in_memory::InMemoryStorage;

    use crate::context::actor::class_s::PendingLogUnits;
    use crate::context::actor::deps::ActorDeps;
    use crate::context::builder::ContextEventLogProvider;
    use crate::context::persistence::ContextPersistence;
    use crate::context::providers::event_log::MerkleEventLogProvider;
    use crate::context::supervisor::faulty_storage::FaultyStorage;

    /// The durable leaves a `SuspendCapability` consequence produces, in order.
    pub const SUSPENSION_LEAVES: [EventType; 2] = [
        EventType::ConsequenceTriggered,
        EventType::ConsequenceEnforced,
    ];

    /// A Merkle event log stored through a [`FaultyStorage`] the test can fail.
    pub fn faulty_merkle_log() -> (MerkleEventLogProvider, Arc<FaultyStorage>) {
        let faulty = Arc::new(FaultyStorage::new(Arc::new(InMemoryStorage::new())));
        (merkle_log_over(&faulty), faulty)
    }

    /// A Merkle event log over `faulty`'s storage, as a restarted node builds
    /// it.
    pub fn merkle_log_over(faulty: &Arc<FaultyStorage>) -> MerkleEventLogProvider {
        let repo = Arc::new(crate::store::ProtocolRepository::new_for_testing(
            Arc::clone(faulty),
        ));
        MerkleEventLogProvider::with_persistence(Arc::new(
            crate::store::context::ProtocolRepositoryEventLogBridge::new(repo),
        ))
    }

    /// Fails every entry write of the context's log from here on.
    /// `FaultyStorage` matches keys by prefix, and every entry key of the log
    /// starts with `context/{hex}/merkle_event_log/g`.
    pub fn fail_log_entry_writes(faulty: &FaultyStorage, context_id_bytes: &[u8; 32]) {
        faulty.fail_store_prefix(&format!(
            "context/{}/merkle_event_log/g",
            hex::encode(context_id_bytes)
        ));
    }

    /// Initialises the context's log and appends the convergent
    /// `WarningCount` evidence against `target`: a `GovernanceAction` whose
    /// actor is someone else and whose payload `target_did` is `target`.
    pub async fn seed_warning_leaf(
        event_log: &dyn ContextEventLogProvider,
        context_id_bytes: &[u8; 32],
        target: &DID,
    ) {
        event_log
            .init_event_log(context_id_bytes)
            .await
            .expect("init event log");
        let payload = scp_event_log::EventPayload {
            data: serde_json::to_vec(&serde_json::json!({ "target_did": target.as_ref() }))
                .expect("serialize warning payload"),
        };
        event_log
            .append_event(
                context_id_bytes,
                EventType::GovernanceAction,
                "did:example:warning-issuer",
                payload,
                1_700_000_050,
            )
            .await
            .expect("seed governance warning leaf");
    }

    /// A `WarningCount` rule (threshold 1) that suspends `MessagesWrite`.
    pub fn suspend_messages_write_rule() -> scp_protocol::trust::consequence::ConsequenceRule {
        use scp_protocol::context::roles::Capability;
        use scp_protocol::trust::consequence::{
            ConsequenceAction, ConsequenceRule, ConsequenceTrigger, EnforcementSeverity,
        };
        ConsequenceRule {
            trigger: ConsequenceTrigger::WarningCount,
            action: ConsequenceAction::Enforcement(EnforcementSeverity::SuspendCapability {
                capabilities: vec![Capability::MessagesWrite],
            }),
            threshold: 1,
            window: std::time::Duration::from_hours(1),
        }
    }

    /// The event types of each queued unit, oldest first.
    pub fn queued_unit_types(units: &PendingLogUnits) -> Vec<Vec<EventType>> {
        units
            .iter()
            .map(|unit| {
                unit.leaves
                    .iter()
                    .map(crate::context::state::LeafSpec::event_type)
                    .collect()
            })
            .collect()
    }

    /// A snapshot store the supervisor writes through while the test reads
    /// the stored snapshot back, so a test can assert that a unit reached the
    /// persist that recorded its step and not only the in-memory queue.
    #[derive(Clone, Default)]
    pub struct SharedSnapshots(Arc<crate::context::providers::persistence::InMemoryPersistence>);

    impl SharedSnapshots {
        /// The stored snapshot of `context_id`, if any.
        pub async fn snapshot(
            &self,
            context_id: &str,
        ) -> Option<crate::context::state::ContextSnapshot> {
            self.0
                .load_context(context_id)
                .await
                .expect("the snapshot store reads")
        }

        /// The event types of each unit in the stored snapshot's queue,
        /// oldest first; empty when nothing was stored.
        pub async fn persisted_unit_types(&self, context_id: &str) -> Vec<Vec<EventType>> {
            self.0
                .load_context(context_id)
                .await
                .expect("the snapshot store reads")
                .map(|snapshot| {
                    snapshot
                        .pending_log_units
                        .iter()
                        .map(|unit| {
                            unit.leaves
                                .iter()
                                .map(crate::context::state::LeafSpec::event_type)
                                .collect()
                        })
                        .collect()
                })
                .unwrap_or_default()
        }
    }

    #[async_trait::async_trait]
    impl ContextPersistence for SharedSnapshots {
        async fn persist_context(
            &self,
            context_id: &str,
            snapshot: &crate::context::state::ContextSnapshot,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.0.persist_context(context_id, snapshot).await
        }
        async fn load_context(
            &self,
            context_id: &str,
        ) -> Result<
            Option<crate::context::state::ContextSnapshot>,
            Box<dyn std::error::Error + Send + Sync>,
        > {
            self.0.load_context(context_id).await
        }
        async fn delete_context(
            &self,
            context_id: &str,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.0.delete_context(context_id).await
        }
        async fn list_persisted_contexts(
            &self,
        ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
            self.0.list_persisted_contexts().await
        }
    }

    /// Supervisor-backed deps for `owner` over a Merkle log whose entry writes
    /// for `context_id` fail once [`fail_log_entry_writes`] runs, and a
    /// [`SharedSnapshots`] store. The log is initialised for `context_id`, so
    /// the failure a test sees is the refused entry write.
    pub async fn deps_over_faulty_log(
        owner: &str,
        context_id: &str,
    ) -> (ActorDeps, Arc<FaultyStorage>, SharedSnapshots) {
        let (log, faulty) = faulty_merkle_log();
        let snapshots = SharedSnapshots::default();
        let deps = deps_with(owner, Some(Box::new(snapshots.clone())), Box::new(log)).await;
        deps.event_log
            .init_event_log(&crate::context::state::context_id_to_bytes(context_id))
            .await
            .expect("init event log");
        (deps, faulty, snapshots)
    }

    /// The number of entries in the context's log.
    pub fn log_len(deps: &ActorDeps, context_id_bytes: &[u8; 32]) -> usize {
        deps.event_log
            .event_log_entries(context_id_bytes)
            .expect("the log reads")
            .map_or(0, |entries| entries.len())
    }

    /// The consequence evidence an operation reads before its step: `state`'s
    /// rules and queued units with `event_log` read in full.
    pub fn pre_step_evidence(
        state: &crate::context::actor::state::PerContextState,
        ctx: &str,
        event_log: &dyn ContextEventLogProvider,
    ) -> crate::context::governance_logic::PreStepEvidence {
        crate::context::governance_logic::PreStepEvidence::read(
            &state.governance.consequence_rules,
            &state.class_s.pending_log_units,
            ctx,
            event_log,
        )
        .expect("the log reads before the step")
    }

    /// Supervisor-backed deps for `owner` with `event_log`, the given
    /// persistence (`None` persists nothing and succeeds), and a test clock.
    pub async fn deps_with(
        owner: &str,
        persistence: Option<Box<dyn ContextPersistence>>,
        event_log: Box<dyn ContextEventLogProvider>,
    ) -> ActorDeps {
        use crate::context::supervisor::supervisor::Supervisor;

        let crypto = Arc::new(crate::crypto::mls::provider::NodeMlsFactory::new(
            owner.to_owned(),
            Arc::new(scp_clock::SystemClock),
        ));
        let transport: Box<dyn crate::context::builder::ContextTransportProvider> =
            Box::new(crate::context::builder::NotConfiguredTransportProvider);
        let key_resolver: scp_protocol::context::governance::KeyResolver = Arc::new(|_, _| None);
        let mls_storage: Arc<dyn crate::crypto::mls::storage_adapter::OpenMlsStorageAdapter> =
            Arc::new(
                crate::crypto::mls::storage_adapter::SpawnBlockingStorageAdapter::new(Arc::new(
                    InMemoryStorage::new(),
                )),
            );
        let clock: Arc<dyn scp_clock::Clock> = Arc::new(scp_clock::TestClock::new(1_700_000_000));
        let supervisor = Supervisor::with_providers(
            crypto,
            transport,
            event_log,
            key_resolver,
            persistence,
            None,
            None,
            Some(clock),
            mls_storage,
        );
        crate::context::supervisor::supervisor::leak_for_test(&supervisor);
        supervisor
            .build_actor_deps_loaded(&DID(owner.to_owned()))
            .await
            .expect("build_actor_deps")
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use scp_event_log::{EventPayload, EventType};

    use scp_protocol::context::ContextError;

    use super::drain_pending_log_units;
    use super::test_support::{deps_with, fail_log_entry_writes, faulty_merkle_log, log_len};
    use crate::context::actor::class_s::{ClassSCell, PendingLogUnits};
    use crate::context::actor::state::PerContextState;
    use crate::context::state::{LeafSpec, PendingLogUnit};

    const OWNER: &str = "did:dht:z6MkLogUnitFifo";

    fn tagged_payload(tag: u8) -> EventPayload {
        EventPayload {
            data: vec![0xC0, tag],
        }
    }

    fn tagged_leaf(tag: u8) -> LeafSpec {
        LeafSpec::new(
            EventType::MemberJoined,
            String::new(),
            tagged_payload(tag),
            1_700_000_000 + u64::from(tag),
        )
        .expect("a valid leaf")
    }

    /// The queue's journal holds every entry queued since it opened, in
    /// order, though a drain wrote and removed the first of them in between;
    /// entries queued before it opened or after it closed are not in it.
    #[tokio::test]
    async fn the_journal_keeps_entries_a_drain_wrote() {
        let ctx_id_bytes = [0x5Fu8; 32];
        let ctx = hex::encode(ctx_id_bytes);
        let (log, _faulty) = faulty_merkle_log();
        let deps = deps_with(OWNER, None, Box::new(log)).await;
        deps.event_log
            .init_event_log(&ctx_id_bytes)
            .await
            .expect("init event log");
        let mut cell = ClassSCell::new(PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            1_700_000_000,
            scp_did::DID(OWNER.to_owned()),
        ));
        let enqueue = |tag: u8| {
            move |mut v: crate::context::actor::class_s::ClassSMut<'_>| {
                v.enqueue_log_unit(vec![tagged_leaf(tag)]);
                Ok(())
            }
        };

        cell.commit_class_s_keep(&deps, &ctx, enqueue(1))
            .await
            .expect("the enqueue persists");
        cell.commit_class_s_keep(&deps, &ctx, |mut v| {
            v.begin_log_unit_journal();
            v.enqueue_log_unit(vec![tagged_leaf(2)]);
            Ok(())
        })
        .await
        .expect("the enqueue persists");
        drain_pending_log_units(&mut cell, &deps, &ctx)
            .await
            .expect("the drain writes both units");
        assert!(cell.class_s.pending_log_units.is_empty());
        cell.commit_class_s_keep(&deps, &ctx, enqueue(3))
            .await
            .expect("the enqueue persists");
        let mut journal = Vec::new();
        cell.commit_class_s_keep(&deps, &ctx, |mut v| {
            journal = v.take_log_unit_journal();
            Ok(())
        })
        .await
        .expect("the close persists");
        cell.commit_class_s_keep(&deps, &ctx, enqueue(4))
            .await
            .expect("the enqueue persists");

        assert_eq!(journal, vec![tagged_leaf(2), tagged_leaf(3)]);
        let mut reopened = vec![tagged_leaf(0)];
        cell.commit_class_s_keep(&deps, &ctx, |mut v| {
            reopened = v.take_log_unit_journal();
            Ok(())
        })
        .await
        .expect("the close persists");
        assert!(reopened.is_empty(), "a closed journal records nothing");
    }

    /// Spec 17 §17.3 "Event log write failures": while units are queued, a
    /// fail-closed append is refused, so it cannot take a queued unit's place.
    /// The drain that runs before the next command writes the queue first, in
    /// FIFO order, and the append that follows lands after it.
    #[tokio::test]
    async fn fail_closed_append_drains_queue_first_in_fifo_order() {
        let ctx_id_bytes = [0x5Eu8; 32];
        let ctx = hex::encode(ctx_id_bytes);
        let (log, faulty) = faulty_merkle_log();
        let deps = deps_with(OWNER, None, Box::new(log)).await;
        deps.event_log
            .init_event_log(&ctx_id_bytes)
            .await
            .expect("init event log");
        let mut cell = ClassSCell::new(PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            1_700_000_000,
            scp_did::DID(OWNER.to_owned()),
        ));

        // Two units are queued while the log rejects entry writes.
        fail_log_entry_writes(&faulty, &ctx_id_bytes);
        for unit in [vec![tagged_leaf(1), tagged_leaf(2)], vec![tagged_leaf(3)]] {
            cell.commit_class_s_keep(&deps, &ctx, |mut v| {
                v.enqueue_log_unit(unit);
                Ok(())
            })
            .await
            .expect("the enqueue persists");
            assert!(
                drain_pending_log_units(&mut cell, &deps, &ctx)
                    .await
                    .is_err(),
                "the log rejects the unit's write"
            );
        }
        assert_eq!(cell.class_s.pending_log_units.len(), 2);

        // The log recovers, but the queue is not yet drained: a fail-closed
        // append is refused rather than written ahead of the queue.
        faulty.clear_fail();
        let ahead = deps
            .event_log
            .append_event(
                &ctx_id_bytes,
                EventType::MemberJoined,
                "",
                tagged_payload(4),
                1_700_000_004,
            )
            .await;
        assert!(
            ahead.is_err(),
            "a fail-closed append while units are queued must be refused: {ahead:?}"
        );
        assert_eq!(log_len(&deps, &ctx_id_bytes), 0);

        // The drain before the next command writes the queue, then the append.
        drain_pending_log_units(&mut cell, &deps, &ctx)
            .await
            .expect("the drain writes both units");
        assert!(cell.class_s.pending_log_units.is_empty());
        deps.event_log
            .append_event(
                &ctx_id_bytes,
                EventType::MemberJoined,
                "",
                tagged_payload(4),
                1_700_000_004,
            )
            .await
            .expect("the append lands after the drain");

        let tags: Vec<u8> = deps
            .event_log
            .event_log_entries(&ctx_id_bytes)
            .expect("the log reads")
            .expect("the log exists")
            .iter()
            .map(|event| event.payload.data[1])
            .collect();
        assert_eq!(
            tags,
            vec![1, 2, 3, 4],
            "the queued units land first, oldest first, then the append"
        );
    }

    /// An active broadcast cell whose ceiling holds `MemberBan` and
    /// `ContextClose`, with `admin` and `target` as members and `author`
    /// registered.
    fn fence_cell(ctx_id_bytes: [u8; 32], admin: &str, target: &str, author: &str) -> ClassSCell {
        use scp_protocol::context::broadcast::{BroadcastAdmission, BroadcastContext};
        use scp_protocol::context::roles::{Capability, CapabilityCeiling, ContextRoleState};
        use scp_protocol::context::{ContextMode, ContextParams, ContextState};

        let did = |s: &str| scp_did::DID(s.to_owned());
        let ctx = hex::encode(ctx_id_bytes);
        let mut state =
            PerContextState::new_for_test_broadcast(ctx_id_bytes, 1_700_000_000, did(admin));
        let ceiling = [
            Capability::MessagesRead,
            Capability::MessagesWrite,
            Capability::MemberBan,
            Capability::ContextClose,
        ];
        state.handle = crate::context::ContextHandle::new(
            ctx.clone(),
            ContextParams {
                ceiling: ceiling.to_vec(),
                ttl: Some(std::time::Duration::from_secs(3_600)),
                ..ContextParams::default()
            },
        );
        state
            .handle
            .transition_to(&ContextState::Active)
            .expect("activate");
        state.role_state = ContextRoleState::new(
            ctx.clone(),
            admin,
            CapabilityCeiling::new(ceiling),
            Vec::new(),
            &scp_clock::SystemClock,
        )
        .expect("role state");
        state.role_state.members.insert(target.to_owned());
        state
            .membership
            .add_member(did(admin), "admin".to_owned(), vec![]);
        state
            .membership
            .add_member(did(target), "member".to_owned(), vec![]);
        let mut bc = BroadcastContext::new(ctx, &ContextMode::Broadcast, BroadcastAdmission::Open)
            .expect("broadcast context");
        bc.add_author(author).expect("add author");
        state.broadcast_context = Some(bc);
        ClassSCell::new(state)
    }

    const FENCE_ADMIN: &str = "did:dht:z6MkFenceAdmin";
    const FENCE_TARGET: &str = "did:dht:z6MkFenceTarget";
    const FENCE_AUTHOR: &str = "did:dht:z6MkFenceAuthor";
    const FENCE_SUBSCRIBER: &str = "did:dht:z6MkFenceSubscriber";

    /// The governance per-action, broadcast roster, and leave sites of
    /// `fence_refuses_no_after_step_write`, run in order, each with its result.
    async fn fence_member_sites(
        cell: &mut ClassSCell,
        deps: &crate::context::actor::deps::ActorDeps,
        ctx: &str,
        handle: &crate::context::ContextHandle,
    ) -> Vec<(&'static str, Result<(), ContextError>)> {
        use scp_protocol::context::roles::Capability;

        let did = |s: &str| scp_did::DID(s.to_owned());
        let suspend = crate::context::governance_helpers::execute_suspend_member(
            cell,
            deps,
            ctx,
            &did(FENCE_TARGET),
            &[Capability::MessagesWrite],
            crate::context::governance_helpers::CommitMeta {
                pid: [0x3C; 32],
                actor_did: FENCE_ADMIN,
                timestamp_secs: 1_700_000_010,
            },
        )
        .await;
        let block = crate::context::broadcast_helpers::block_broadcast_subscriber(
            cell,
            deps,
            ctx,
            &did(FENCE_AUTHOR),
            &did(FENCE_SUBSCRIBER),
        )
        .await
        .map(|_| ());
        let leave = crate::context::lifecycle_helpers::leave_context(
            cell,
            deps,
            handle,
            &did(FENCE_TARGET),
            &did(FENCE_TARGET),
        )
        .await;
        vec![("suspend", suspend), ("block", block), ("leave", leave)]
    }

    /// The typed log-unit command, saga divergence marker, and close sites of
    /// `fence_refuses_no_after_step_write`, run in order, each with its result
    /// and, for a mailbox command, its reply. The close runs last because it
    /// ends the context's mutations.
    async fn fence_command_sites(
        cell: &mut ClassSCell,
        deps: &crate::context::actor::deps::ActorDeps,
        handle: &crate::context::ContextHandle,
    ) -> Vec<(&'static str, Result<(), ContextError>)> {
        use crate::context::actor::commands::{
            LogUnitCommand, LogUnitRequest, SagaPhaseMessage, UnitDedup,
        };

        let (tx, rx) = tokio::sync::oneshot::channel();
        let unit = crate::context::actor::handlers::log_unit::dispatch(
            cell,
            deps,
            LogUnitCommand::Enqueue {
                request: LogUnitRequest::Leaves(vec![tagged_leaf(2)]),
                dedup: UnitDedup::None,
                reply: tx,
            },
        )
        .await
        .result;
        let unit_reply = rx.await.expect("the log-unit command replies");
        let (tx, rx) = tokio::sync::oneshot::channel();
        let marker = crate::context::actor::handlers::saga::dispatch(
            cell,
            deps,
            SagaPhaseMessage::EmitDivergenceMarker {
                saga_id: crate::context::supervisor::saga_journal::SagaId("saga-fence".to_owned()),
                nonce: [0xAB; 16],
                committed_side:
                    scp_protocol::context::outlets::cross_context_saga::CommittedSide::Target,
                committed_event_id: "evt-fence".to_owned(),
                committed_timestamp_secs: 1_700_000_020,
                signer: crate::context::actor::signer::CommandSigner::local_ed25519(
                    ed25519_dalek::SigningKey::from_bytes(&[0x99; 32]),
                ),
                reply: tx,
            },
        )
        .await
        .result;
        let marker_reply = rx.await.expect("the marker replies");
        let close = crate::context::lifecycle_helpers::close_context(
            cell,
            deps,
            handle,
            &scp_did::DID(FENCE_ADMIN.to_owned()),
        )
        .await
        .map(|_| ());
        vec![
            ("log-unit command", unit),
            ("log-unit command reply", unit_reply),
            ("divergence marker", marker),
            ("divergence marker reply", marker_reply),
            ("close", close),
        ]
    }

    /// Spec 17 §17.3 "Event log write failures": no write path survives that
    /// writes a leaf after its step, so a unit queued ahead of the log refuses
    /// no step. With one unit queued and the log refusing every entry write,
    /// one site from every family of after-step records runs: a governance
    /// per-action record, a broadcast roster record, a leave, the typed
    /// log-unit command the A-side records ride, a saga divergence marker, and
    /// a close. None fails; each queues its leaves behind the unit in the
    /// persist that recorded its step, and the log is untouched. Once the store
    /// heals, one drain writes every leaf in FIFO order.
    #[tokio::test]
    async fn fence_refuses_no_after_step_write() {
        use super::test_support::{deps_over_faulty_log, queued_unit_types};

        let ctx_id_bytes = [0x62u8; 32];
        let ctx = hex::encode(ctx_id_bytes);
        let (deps, faulty, snapshots) = deps_over_faulty_log(FENCE_ADMIN, &ctx).await;

        let mut cell = fence_cell(ctx_id_bytes, FENCE_ADMIN, FENCE_TARGET, FENCE_AUTHOR);
        let handle = cell.handle.clone();

        // One unit queued at base_seq 0 whose write the log refuses, and the
        // log refusing every entry write from here until it heals.
        fail_log_entry_writes(&faulty, &ctx_id_bytes);
        cell.commit_class_s_keep(&deps, &ctx, |mut v| {
            v.enqueue_log_unit(vec![tagged_leaf(1)]);
            Ok(())
        })
        .await
        .expect("the enqueue persists");
        assert!(
            drain_pending_log_units(&mut cell, &deps, &ctx)
                .await
                .is_err(),
            "the log refuses the unit's write"
        );

        let mut results = fence_member_sites(&mut cell, &deps, &ctx, &handle).await;
        results.extend(fence_command_sites(&mut cell, &deps, &handle).await);
        assert_eq!(results.len(), 8, "every site ran");
        for (site, result) in &results {
            assert!(
                result.is_ok(),
                "{site} must land; the queued unit refuses no step: {result:?}"
            );
        }

        let expected = vec![
            vec![EventType::MemberJoined],
            vec![EventType::MemberSuspended],
            vec![EventType::MemberBlocked, EventType::KeyEpochAdvance],
            vec![EventType::MemberLeft],
            vec![EventType::MemberJoined],
            vec![EventType::CrossContextDivergenceMarker],
            vec![EventType::ContextClosing],
        ];
        assert_eq!(
            queued_unit_types(&cell.class_s.pending_log_units),
            expected,
            "every site queued its leaves behind the unit, in order"
        );
        assert_eq!(
            snapshots.persisted_unit_types(&ctx).await,
            expected,
            "every unit is in the persist that recorded its step"
        );
        assert_eq!(log_len(&deps, &ctx_id_bytes), 0, "the log is untouched");

        // The store heals; one drain writes every leaf in FIFO order.
        faulty.clear_fail();
        drain_pending_log_units(&mut cell, &deps, &ctx)
            .await
            .expect("the drain writes the queue");
        assert!(cell.class_s.pending_log_units.is_empty());
        let written: Vec<EventType> = deps
            .event_log
            .event_log_entries(&ctx_id_bytes)
            .expect("the log reads")
            .expect("the log exists")
            .iter()
            .map(|entry| entry.event_type)
            .collect();
        assert_eq!(
            written,
            expected.concat(),
            "the drain writes the queued leaves oldest first"
        );
    }

    /// A unit queued ahead of the log at `base_seq`, and the cell holding it.
    fn cell_with_reserved_unit(
        ctx_id_bytes: [u8; 32],
        base_seq: u64,
        leaves: Vec<LeafSpec>,
    ) -> ClassSCell {
        let mut state = PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            1_700_000_000,
            scp_did::DID(OWNER.to_owned()),
        );
        state.class_s.pending_log_units = PendingLogUnits::validated(
            std::iter::once(PendingLogUnit {
                base_seq: Some(base_seq),
                leaves,
            })
            .collect(),
        )
        .expect("a valid unit");
        ClassSCell::new(state)
    }

    /// Spec 17 §17.3 "Event log write failures": the drain tells the provider
    /// whether units are queued even when it has nothing to write, so a
    /// respawned actor whose restored queue is empty clears a fence a failed
    /// drain left set, and the next append is accepted.
    #[tokio::test]
    async fn drain_with_no_unit_clears_a_stale_fence() {
        let ctx_id_bytes = [0x5Fu8; 32];
        let ctx = hex::encode(ctx_id_bytes);
        let (log, _faulty) = faulty_merkle_log();
        let deps = deps_with(OWNER, None, Box::new(log)).await;
        deps.event_log
            .init_event_log(&ctx_id_bytes)
            .await
            .expect("init event log");
        // A drain that failed before the respawn left the fence set.
        deps.event_log.set_units_pending(&ctx_id_bytes, true);
        let refused = deps
            .event_log
            .append_event(
                &ctx_id_bytes,
                EventType::MemberJoined,
                "",
                tagged_payload(1),
                1_700_000_001,
            )
            .await;
        assert!(
            refused.is_err(),
            "the fence refuses the append: {refused:?}"
        );

        let mut cell = ClassSCell::new(PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            1_700_000_000,
            scp_did::DID(OWNER.to_owned()),
        ));
        drain_pending_log_units(&mut cell, &deps, &ctx)
            .await
            .expect("an empty queue drains");
        deps.event_log
            .append_event(
                &ctx_id_bytes,
                EventType::MemberJoined,
                "",
                tagged_payload(1),
                1_700_000_001,
            )
            .await
            .expect("the fence follows the empty queue");
    }

    /// A unit reserved past the log's end (the log lost its tail before a
    /// restart) holds no slot another entry took: the drain reserves it again
    /// at the log's length and writes it, with no log fault.
    #[tokio::test]
    async fn unit_past_the_log_end_is_reserved_again() {
        let ctx_id_bytes = [0x60u8; 32];
        let ctx = hex::encode(ctx_id_bytes);
        let (log, _faulty) = faulty_merkle_log();
        let deps = deps_with(OWNER, None, Box::new(log)).await;
        deps.event_log
            .init_event_log(&ctx_id_bytes)
            .await
            .expect("init event log");
        let mut cell = cell_with_reserved_unit(ctx_id_bytes, 5, vec![tagged_leaf(7)]);

        drain_pending_log_units(&mut cell, &deps, &ctx)
            .await
            .expect("the unit is reserved again and written");
        assert!(cell.class_s.pending_log_units.is_empty());
        assert!(cell.class_s.log_fault.is_none(), "no log fault is set");
        let entries = deps
            .event_log
            .event_log_entries(&ctx_id_bytes)
            .expect("the log reads")
            .expect("the log exists");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].payload.data, tagged_payload(7).data);
    }

    /// A unit whose slot holds another entry sets the log fault and stays
    /// queued, and the fault refuses a mutation with `EventLogFailed`.
    #[tokio::test]
    async fn misaligned_unit_sets_the_log_fault_and_refuses_mutations() {
        let ctx_id_bytes = [0x61u8; 32];
        let ctx = hex::encode(ctx_id_bytes);
        let (log, _faulty) = faulty_merkle_log();
        let deps = deps_with(OWNER, None, Box::new(log)).await;
        deps.event_log
            .init_event_log(&ctx_id_bytes)
            .await
            .expect("init event log");
        for tag in 1..=3 {
            deps.event_log
                .append_event(
                    &ctx_id_bytes,
                    EventType::MemberJoined,
                    "",
                    tagged_payload(tag),
                    1_700_000_000 + u64::from(tag),
                )
                .await
                .expect("seed the log");
        }
        let mut cell = cell_with_reserved_unit(ctx_id_bytes, 1, vec![tagged_leaf(9)]);

        let drained = drain_pending_log_units(&mut cell, &deps, &ctx).await;
        assert!(
            matches!(drained, Err(ContextError::EventLogFailed(_))),
            "{drained:?}"
        );
        assert_eq!(
            cell.class_s.pending_log_units.len(),
            1,
            "the unit stays queued"
        );
        let marker = cell
            .class_s
            .log_fault
            .clone()
            .expect("the misalignment sets the log fault");
        assert_eq!((marker.base_seq, marker.log_len), (1, 3));
        assert_eq!(log_len(&deps, &ctx_id_bytes), 3, "the log is unchanged");

        let refused = crate::context::governance_helpers::execute_governance_action(
            &mut cell,
            &deps,
            &ctx,
            &[0u8; 32],
            Some(&scp_did::DID(OWNER.to_owned())),
            None,
            None,
        )
        .await;
        assert!(
            matches!(refused, Err(ContextError::EventLogFailed(_))),
            "the log fault refuses the mutation: {refused:?}"
        );
    }

    /// Spec 17 §17.3: a queue read back from storage is checked as an enqueue
    /// would have checked it.
    #[test]
    fn restored_queue_refuses_an_invalid_unit() {
        let empty = PendingLogUnits::validated(
            std::iter::once(PendingLogUnit {
                base_seq: None,
                leaves: Vec::new(),
            })
            .collect(),
        );
        assert!(
            matches!(empty, Err(ContextError::PersistenceFailed(_))),
            "{empty:?}"
        );

        // A stored entry that breaks the payload rules cannot be read back:
        // deserialization builds the leaf through `LeafSpec::new`.
        let mut stored = serde_json::to_value(PendingLogUnit {
            base_seq: None,
            leaves: vec![tagged_leaf(1)],
        })
        .expect("serialize a unit");
        stored["leaves"][0]["event_type"] =
            serde_json::to_value(EventType::OutletInvoked).expect("event type");
        stored["leaves"][0]["payload"] =
            serde_json::to_value(outlet_invoked_payload(2, 3)).expect("payload");
        let breach = serde_json::from_value::<PendingLogUnit>(stored);
        assert!(breach.is_err(), "{breach:?}");

        let valid = PendingLogUnits::validated(
            std::iter::once(PendingLogUnit {
                base_seq: Some(4),
                leaves: vec![tagged_leaf(1)],
            })
            .collect(),
        )
        .expect("a valid unit is restored");
        assert_eq!(valid.len(), 1);
    }

    /// Spec 17 §17.3 "Event log write failures": the membership planner plans
    /// the leaf its fail-closed builder wrapper appends, byte for byte, so a
    /// queued leaf and an appended one hash the same; the role and TTL
    /// planners, which have no wrapper, encode exactly their typed payload.
    #[tokio::test]
    async fn planners_match_their_builder_wrappers() {
        use crate::context::builder::ContextEventLogProvider;
        use crate::context::providers::event_log::MerkleEventLogProvider;
        use scp_event_log::payload::{
            MembershipChangePayload, RoleAssignedPayload, TtlExtendedPayload,
        };

        let provider = MerkleEventLogProvider::new();
        let ctx_id = [0x7Au8; 32];
        provider.init_event_log(&ctx_id).await.expect("init");
        let change = MembershipChangePayload {
            subject_did: "did:example:subject".to_owned(),
            role_name: "member".to_owned(),
        };
        let planned = super::plan_membership_change_leaf(
            EventType::MemberJoined,
            "did:example:admin",
            &change,
            1_700_000_001,
        )
        .expect("plans");
        provider
            .append_membership_change_leaf(
                &ctx_id,
                EventType::MemberJoined,
                "did:example:admin",
                &change,
                1_700_000_001,
            )
            .await
            .expect("appends");
        let appended = provider.entries(&ctx_id).expect("the log exists");
        assert_eq!(appended.len(), 1);
        assert_eq!(planned.event_type(), appended[0].event_type);
        assert_eq!(planned.actor_did(), appended[0].actor_did.as_ref());
        assert_eq!(planned.payload().data, appended[0].payload.data);
        assert_eq!(planned.timestamp_secs(), appended[0].timestamp);

        let role = super::plan_role_assigned_leaf(
            "did:example:admin",
            "did:example:subject",
            "admin",
            1_700_000_002,
        )
        .expect("plans");
        assert_eq!(role.event_type(), EventType::RoleAssigned);
        assert_eq!(role.actor_did(), "did:example:admin");
        assert_eq!(role.timestamp_secs(), 1_700_000_002);
        assert_eq!(
            role.payload().data,
            scp_event_log::payload::encode_payload(&RoleAssignedPayload {
                subject_did: "did:example:subject".to_owned(),
                role: "admin".to_owned(),
            })
            .expect("encodes")
            .data
        );

        let extension = TtlExtendedPayload {
            old_deadline_unix: 10,
            new_deadline_unix: 20,
            proposal_id: [3u8; 32],
            consenting_members: vec!["did:example:a".to_owned()],
        };
        let ttl = super::plan_ttl_extended_leaf("did:example:admin", &extension, 1_700_000_003)
            .expect("plans");
        assert_eq!(ttl.event_type(), EventType::TtlExtended);
        assert_eq!(
            ttl.payload().data,
            scp_event_log::payload::encode_payload(&extension)
                .expect("encodes")
                .data
        );
    }

    /// Spec 17 §17.3: an entry is checked against the append's payload rules
    /// when it is planned, before the step, so the enqueue after the step has
    /// nothing left to refuse.
    #[test]
    fn plan_leaf_refuses_a_payload_rule_breach() {
        let refused = super::plan_leaf(
            EventType::OutletInvoked,
            String::new(),
            outlet_invoked_payload(2, 3),
            1_700_000_000,
        );
        assert!(
            matches!(refused, Err(ContextError::EventLogFailed(_))),
            "{refused:?}"
        );
        super::plan_leaf(
            EventType::OutletInvoked,
            String::new(),
            outlet_invoked_payload(3, 3),
            1_700_000_000,
        )
        .expect("chunks_billed equal to the chunk count is admissible");
    }

    /// Spec 17 §17.3: every `LeafSpec` constructor yields only leaves the
    /// append's payload rules accept. `new` refuses a breach; `consequence`
    /// and `without_payload`, which do not check, build leaves the rules
    /// accept even from a payload that breaks the `OutletInvoked` rule. A
    /// payload rule added for a consequence type, or for an empty payload,
    /// fails this test.
    #[test]
    fn every_leaf_constructor_yields_a_leaf_the_payload_rules_accept() {
        use crate::context::providers::event_log::check_append_payload;
        use crate::context::state::ConsequenceLeafType;

        let refused = LeafSpec::new(
            EventType::OutletInvoked,
            String::new(),
            outlet_invoked_payload(2, 3),
            1_700_000_000,
        );
        assert!(
            matches!(refused, Err(ContextError::EventLogFailed(_))),
            "{refused:?}"
        );

        let payloads = [
            outlet_invoked_payload(2, 3),
            EventPayload {
                data: b"{\"any\":\"payload\"}".to_vec(),
            },
            EventPayload::default(),
        ];
        for leaf_type in ConsequenceLeafType::ALL {
            for payload in &payloads {
                let leaf =
                    LeafSpec::consequence(leaf_type, String::new(), payload.clone(), 1_700_000_000);
                check_append_payload(leaf.event_type(), leaf.payload())
                    .expect("the rules accept every consequence leaf");
            }
        }
        for event_type in [
            EventType::OutletInvoked,
            EventType::MemberJoined,
            EventType::GovernanceAction,
        ] {
            let leaf = LeafSpec::without_payload(event_type, String::new(), 1_700_000_000);
            check_append_payload(leaf.event_type(), leaf.payload())
                .expect("the rules accept an empty payload");
        }
        check_append_payload(EventType::RecoveryEpochAdvanced, &payloads[1])
            .expect("the recovery leaf, planned through `new`, has no payload rule");
    }

    /// An `OutletInvokedEvent` payload with the given chunk counts.
    fn outlet_invoked_payload(stream_chunk_count: u32, chunks_billed: u32) -> EventPayload {
        use scp_protocol::context::outlets::OutletStatus;
        use scp_protocol::context::outlets::lifecycle::OutletInvokedEvent;
        use scp_protocol::context::outlets::stream::StreamTerminalStatus;
        let event = OutletInvokedEvent {
            request_id: "00000000000000000000000000000001".to_owned(),
            outlet_id: "outlet-x".to_owned(),
            invoker_did: scp_did::DID("did:dht:z6MkInvoker".to_owned()),
            status: OutletStatus::Success,
            execution_time_ms: 5,
            input_hash: "0".repeat(64),
            output_hash: None,
            cost: None,
            stream_chunk_count,
            chunks_billed,
            stream_manifest_hash: [0x11; 32],
            stream_terminal_status: StreamTerminalStatus::Ok,
            cancel_ack_seq: None,
            audit_anomaly: None,
        };
        EventPayload {
            data: serde_json::to_vec(&event).expect("serialize the event"),
        }
    }
}
