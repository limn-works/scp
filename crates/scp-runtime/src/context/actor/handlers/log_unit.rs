//! Log-unit handlers: see
//! [`LogUnitCommand`](crate::context::actor::commands::LogUnitCommand) and
//! spec 17 §17.3 "Event log write failures".
//!
//! Code that runs outside a context's actor (the cross-context bridge, the
//! streaming seal task, the streaming close sink, crash recovery) queues the
//! context's event-log records through this handler, so only the actor's
//! drain writes the context's log and every record joins the queue's FIFO
//! tail behind the units the actor already queued.

use scp_protocol::context::ContextError;

use crate::context::actor::class_s::ClassSCell;
use crate::context::actor::commands::{LogUnitCommand, LogUnitRequest, UnitDedup};
use crate::context::actor::deps::ActorDeps;
use crate::context::actor::outcome::{Outcome, outcome_error_sketch};
use crate::context::log_unit_helpers;
use crate::context::state::LeafSpec;

/// Actor-shape dispatch for a [`LogUnitCommand`].
///
/// `Enqueue` plans the request's leaves, drops the leaves `UnitDedup::IfAbsent`
/// finds in the log or the queue, and queues the rest as one unit, counted
/// toward the §9.9.3 checkpoint, through `commit_class_s_restore`: a failed persist rolls the queue back and replies
/// the error, so a re-send cannot queue the unit twice. On a persisted enqueue
/// it drains and replies `Ok`; the unit is durable in the queue from then on.
pub(crate) async fn dispatch(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    cmd: LogUnitCommand,
) -> Outcome<()> {
    match cmd {
        LogUnitCommand::Enqueue {
            request,
            dedup,
            reply,
        } => {
            let context_id = cell.handle.context_id().to_owned();
            match enqueue(cell, deps, &context_id, request, dedup).await {
                Ok(queued) => {
                    if queued {
                        // The result is not returned: the unit is durable in
                        // the queue, the drain logs its own error, and the
                        // actor's next command drains again before it runs.
                        let _ = log_unit_helpers::drain_pending_log_units(cell, deps, &context_id)
                            .await;
                    }
                    let _ = reply.send(Ok(()));
                    Outcome::ok_mutated(())
                }
                Err(err) => {
                    let sketch = outcome_error_sketch(&err);
                    let _ = reply.send(Err(err));
                    Outcome::err(sketch)
                }
            }
        }
    }
}

/// Plans `request`, applies `dedup`, and queues the leaves left. Returns
/// whether a unit was queued.
async fn enqueue(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    request: LogUnitRequest,
    dedup: UnitDedup,
) -> Result<bool, ContextError> {
    let leaves: Vec<LeafSpec> = match request {
        LogUnitRequest::Leaves(leaves) => leaves,
        LogUnitRequest::VerifiedOutletInvoked {
            event,
            reassembled,
            actor_did,
            timestamp_secs,
        } => vec![log_unit_helpers::plan_outlet_invoked_verified_leaf(
            &event,
            &reassembled,
            &actor_did,
            timestamp_secs,
        )?],
    };
    let leaves = match dedup {
        UnitDedup::None => leaves,
        UnitDedup::IfAbsent => log_unit_helpers::leaves_absent_from_log_and_queue(
            cell,
            deps,
            &crate::context::state::context_id_to_bytes(context_id),
            leaves,
        )?,
    };
    if leaves.is_empty() {
        return Ok(false);
    }
    cell.commit_class_s_restore(deps, context_id, move |mut view| {
        view.enqueue_counted_log_unit(leaves);
        Ok(())
    })
    .await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use scp_event_log::{EventPayload, EventType};
    use scp_protocol::context::ContextError;
    use tokio::sync::oneshot;

    use super::dispatch;
    use crate::context::actor::class_s::ClassSCell;
    use crate::context::actor::commands::{LogUnitCommand, LogUnitRequest, UnitDedup};
    use crate::context::actor::state::PerContextState;
    use crate::context::log_unit_helpers::test_support::{
        deps_with, fail_log_entry_writes, faulty_merkle_log, log_len,
    };
    use crate::context::persistence::ContextPersistence;
    use crate::context::state::LeafSpec;

    const OWNER: &str = "did:dht:z6MkLogUnitHandler";

    /// Persistence whose `persist_context` always fails.
    struct FailPersistence;
    #[async_trait::async_trait]
    impl ContextPersistence for FailPersistence {
        async fn persist_context(
            &self,
            _: &str,
            _: &crate::context::state::ContextSnapshot,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Err("induced persist failure".into())
        }
        async fn load_context(
            &self,
            _: &str,
        ) -> Result<
            Option<crate::context::state::ContextSnapshot>,
            Box<dyn std::error::Error + Send + Sync>,
        > {
            Ok(None)
        }
        async fn delete_context(
            &self,
            _: &str,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
        async fn list_persisted_contexts(
            &self,
        ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(Vec::new())
        }
    }

    fn leaf(tag: u8) -> LeafSpec {
        LeafSpec::new(
            EventType::CrossContextOutletInvoked,
            "did:dht:z6MkCaller".to_owned(),
            EventPayload {
                data: vec![0xA0, tag],
            },
            1_700_000_000,
        )
        .expect("a valid leaf")
    }

    fn cell(ctx_id_bytes: [u8; 32]) -> ClassSCell {
        ClassSCell::new(PerContextState::new_for_test_encrypted(
            ctx_id_bytes,
            1_700_000_000,
            scp_did::DID(OWNER.to_owned()),
        ))
    }

    async fn enqueue(
        cell: &mut ClassSCell,
        deps: &crate::context::actor::deps::ActorDeps,
        leaves: Vec<LeafSpec>,
        dedup: UnitDedup,
    ) -> Result<(), ContextError> {
        let (reply, rx) = oneshot::channel();
        let _outcome = dispatch(
            cell,
            deps,
            LogUnitCommand::Enqueue {
                request: LogUnitRequest::Leaves(leaves),
                dedup,
                reply,
            },
        )
        .await;
        rx.await.expect("the handler replies")
    }

    /// A failed persist rolls the queue back and replies the error, so the
    /// sender sees the failure and nothing is queued or written.
    #[tokio::test]
    async fn a_failed_persist_rolls_the_queue_back() {
        let ctx_id_bytes = [0x71u8; 32];
        let (log, _faulty) = faulty_merkle_log();
        let deps = deps_with(OWNER, Some(Box::new(FailPersistence)), Box::new(log)).await;
        deps.event_log
            .init_event_log(&ctx_id_bytes)
            .await
            .expect("init event log");
        let mut cell = cell(ctx_id_bytes);

        let result = enqueue(&mut cell, &deps, vec![leaf(1)], UnitDedup::None).await;
        assert!(
            result.is_err(),
            "the persist failure reaches the sender: {result:?}"
        );
        assert!(
            cell.class_s.pending_log_units.is_empty(),
            "the failed persist leaves no queued unit"
        );
        assert_eq!(log_len(&deps, &ctx_id_bytes), 0, "nothing reached the log");
    }

    /// `IfAbsent` skips a leaf already in the log, so a re-sent leaf lands
    /// once; `None` queues it again.
    #[tokio::test]
    async fn if_absent_lands_a_resent_leaf_once() {
        let ctx_id_bytes = [0x72u8; 32];
        let (log, _faulty) = faulty_merkle_log();
        let deps = deps_with(OWNER, None, Box::new(log)).await;
        deps.event_log
            .init_event_log(&ctx_id_bytes)
            .await
            .expect("init event log");
        let mut cell = cell(ctx_id_bytes);

        enqueue(&mut cell, &deps, vec![leaf(1)], UnitDedup::IfAbsent)
            .await
            .expect("the first send queues and drains");
        assert_eq!(log_len(&deps, &ctx_id_bytes), 1);
        enqueue(&mut cell, &deps, vec![leaf(1)], UnitDedup::IfAbsent)
            .await
            .expect("the re-send succeeds");
        assert_eq!(
            log_len(&deps, &ctx_id_bytes),
            1,
            "the re-sent leaf is already in the log"
        );
        enqueue(&mut cell, &deps, vec![leaf(2)], UnitDedup::IfAbsent)
            .await
            .expect("a different leaf queues");
        assert_eq!(log_len(&deps, &ctx_id_bytes), 2, "a different leaf lands");
        enqueue(&mut cell, &deps, vec![leaf(1)], UnitDedup::None)
            .await
            .expect("an undeduplicated send queues");
        assert_eq!(
            log_len(&deps, &ctx_id_bytes),
            3,
            "without IfAbsent the same leaf lands again"
        );
    }

    /// `IfAbsent` also skips a leaf that waits in the queue: with the log's
    /// entry writes failing the first unit stays queued, and the re-send adds
    /// no second unit.
    #[tokio::test]
    async fn if_absent_skips_a_leaf_waiting_in_the_queue() {
        let ctx_id_bytes = [0x73u8; 32];
        let (log, faulty) = faulty_merkle_log();
        let deps = deps_with(OWNER, None, Box::new(log)).await;
        deps.event_log
            .init_event_log(&ctx_id_bytes)
            .await
            .expect("init event log");
        fail_log_entry_writes(&faulty, &ctx_id_bytes);
        let mut cell = cell(ctx_id_bytes);

        enqueue(&mut cell, &deps, vec![leaf(1)], UnitDedup::IfAbsent)
            .await
            .expect("the unit is durable in the queue though its drain failed");
        assert_eq!(cell.class_s.pending_log_units.iter().count(), 1);
        enqueue(&mut cell, &deps, vec![leaf(1)], UnitDedup::IfAbsent)
            .await
            .expect("the re-send succeeds");
        assert_eq!(
            cell.class_s.pending_log_units.iter().count(),
            1,
            "the re-sent leaf already waits in the queue"
        );
    }
}
