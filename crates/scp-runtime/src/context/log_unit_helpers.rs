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

use crate::context::actor::class_s::ClassSCell;
use crate::context::actor::deps::ActorDeps;
use crate::context::builder::{UnitAppendError, UnitAppended};
use crate::context::state::{LeafSpec, LogFaultMarker, context_id_to_bytes};

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
