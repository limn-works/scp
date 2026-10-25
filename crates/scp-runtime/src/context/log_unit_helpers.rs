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
//!    removes it through `commit_class_s_restore`; a slot taken by an append
//!    outside the queue resets `base_seq` and reserves again, once per unit
//!    per drain; any other misalignment sets the log fault.
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
/// persist obligation, the durable consequence leaves, and a failed log read.
///
/// [`Self::discharge`] queues the leaves as one pending log unit, sets the log
/// fault for a failed read, and discharges the obligation, all in one
/// fail-closed keep persist, so the stored state that holds the step's
/// mutations also holds its leaves. A caller that keeps the memory-first rule
/// takes the parts with [`Self::into_parts`] instead.
#[must_use = "a ConsequenceSink must be discharged; dropping it loses the consequence leaves and the log fault"]
#[derive(Default)]
pub struct ConsequenceSink {
    /// The downward-auth fail-closed persist obligation the GROW methods arm.
    pub(crate) obligation: Option<ClassSCommitToken>,
    /// Durable consequence leaves, in the order the engine produced them.
    leaves: Vec<LeafSpec>,
    /// The error of a log read after the step, which sets the log fault.
    read_fault: Option<String>,
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

    /// Records a log read that failed after the step.
    pub fn note_read_fault(&mut self, detail: String) {
        self.read_fault = Some(detail);
    }

    /// True when the sink owes nothing: no obligation, no leaf, no read fault.
    pub const fn is_empty(&self) -> bool {
        self.obligation.is_none() && self.leaves.is_empty() && self.read_fault.is_none()
    }

    /// Takes the obligation and the leaves for a caller that keeps the
    /// memory-first rule after its step. A recorded read fault is logged; such
    /// a caller never records one.
    pub(crate) fn into_parts(mut self) -> (Option<ClassSCommitToken>, Vec<LeafSpec>) {
        if let Some(detail) = self.read_fault.take() {
            tracing::warn!(
                detail,
                "event log read fault dropped by a memory-first caller"
            );
        }
        (self.obligation.take(), std::mem::take(&mut self.leaves))
    }

    /// Queues the leaves as one pending log unit, sets the log fault for a
    /// failed read, and discharges the obligation in one fail-closed keep
    /// persist, then drains the queue. With nothing owed it does nothing.
    ///
    /// The drain's own failure leaves the unit queued for the next drain and
    /// is logged by [`drain_pending_log_units`]; it does not fail the
    /// operation, whose step is already taken.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::PersistenceFailed`] when the persist fails (the
    /// queued unit, the fault, and the step's mutations stay in memory), or
    /// [`ContextError::EventLogFailed`] when a leaf breaks the payload rules
    /// (nothing is queued; the persist still runs).
    pub async fn discharge(
        mut self,
        cell: &mut ClassSCell,
        deps: &ActorDeps,
        context_id: &str,
    ) -> Result<(), ContextError> {
        let obligation = self.obligation.take();
        let leaves = std::mem::take(&mut self.leaves);
        let read_fault = self.read_fault.take();
        if obligation.is_none() && leaves.is_empty() && read_fault.is_none() {
            return Ok(());
        }
        if let Some(detail) = &read_fault {
            tracing::error!(
                context_id,
                detail = %detail,
                "event log unreadable after the step; the log fault is set"
            );
        }
        let mutate = move |mut view: ClassSMut| {
            if let Some(detail) = read_fault {
                view.set_log_fault(LogFaultMarker {
                    base_seq: None,
                    log_len: None,
                    detail,
                });
            }
            view.enqueue_log_unit(leaves)
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
        if !self.leaves.is_empty() || self.read_fault.is_some() {
            tracing::error!(
                leaves = self.leaves.len(),
                read_fault = self.read_fault.is_some(),
                "ConsequenceSink dropped undischarged; consequence leaves or a log fault are lost"
            );
        }
    }
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
    if !has_log_unit_work(cell) {
        return Ok(());
    }
    let context_id_bytes = context_id_to_bytes(context_id);
    let drained = drain_queue(cell, deps, context_id, &context_id_bytes).await;
    deps.event_log.set_units_pending(
        &context_id_bytes,
        !cell.class_s.pending_log_units.is_empty(),
    );
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

async fn drain_queue(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    context_id_bytes: &[u8; 32],
) -> Result<(), ContextError> {
    // Whether the front unit was already reserved again in this drain.
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
            Err(UnitAppendError::Misaligned {
                slot_taken: true, ..
            }) if !re_reserved => {
                // An append outside the queue took the slot and the unit is
                // absent: reserve it again at the log's length.
                cell.commit_class_s_restore(deps, context_id, |mut view| {
                    view.set_front_log_unit_base(None);
                    Ok(())
                })
                .await?;
                re_reserved = true;
            }
            Err(UnitAppendError::Misaligned {
                base_seq, log_len, ..
            }) => {
                let detail = format!(
                    "queued event log unit misaligned: base_seq {base_seq}, log length {log_len}"
                );
                set_log_fault(
                    cell,
                    deps,
                    context_id,
                    LogFaultMarker {
                        base_seq: Some(base_seq),
                        log_len: Some(log_len),
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
            .map(|unit| unit.leaves.iter().map(|leaf| leaf.event_type).collect())
            .collect()
    }

    /// The number of entries in the context's log.
    pub fn log_len(deps: &ActorDeps, context_id_bytes: &[u8; 32]) -> usize {
        deps.event_log
            .event_log_entries(context_id_bytes)
            .expect("the log reads")
            .map_or(0, |entries| entries.len())
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

    use super::drain_pending_log_units;
    use super::test_support::{deps_with, fail_log_entry_writes, faulty_merkle_log, log_len};
    use crate::context::actor::class_s::ClassSCell;
    use crate::context::actor::state::PerContextState;
    use crate::context::state::LeafSpec;

    const OWNER: &str = "did:dht:z6MkLogUnitFifo";

    fn tagged_payload(tag: u8) -> EventPayload {
        EventPayload {
            data: vec![0xC0, tag],
        }
    }

    fn tagged_leaf(tag: u8) -> LeafSpec {
        LeafSpec {
            event_type: EventType::MemberJoined,
            actor_did: String::new(),
            payload: tagged_payload(tag),
            timestamp_secs: 1_700_000_000 + u64::from(tag),
        }
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
            cell.commit_class_s_keep(&deps, &ctx, |mut v| v.enqueue_log_unit(unit))
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
}
