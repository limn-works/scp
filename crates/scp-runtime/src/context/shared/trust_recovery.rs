//! Items the `trust_recovery` domain shares with core and with other domains.
//!
//! It holds code that reads or writes only core state and calls no domain
//! function, and the types and constants more than one crate names (ADR-070
//! Appendix).
use crate::context::actor::class_s::ClassSCell;
use crate::context::actor::deps::ActorDeps;
use crate::context::state::context_id_to_bytes;
use crate::context::state::require_active;
use scp_did::DID;
use scp_protocol::context::ContextError;
use scp_protocol::context::governance::CheckpointAttestationStatus;
use scp_protocol::context::governance::ContextCheckpoint;

/// Creates a governance-aware checkpoint for a context.
///
/// State-owning signature: `state` carries the per-context governance/pruning
/// policy and lifecycle handle; `deps.clock` produces `created_at`;
/// `deps.event_log` prunes the log when the context configures a pruning
/// policy, and a failed prune fails the checkpoint.
///
/// Mutation surface: this helper does NOT mutate `state` — the
/// checkpoint object is returned by value and any pruning is delegated
/// to the event-log provider (which owns its own storage). The handler
/// flags this as `mutated: true` only because pruning has external side
/// effects worth coalescing into the actor's persist tick.
///
/// # Errors
///
/// The lifecycle error when the context is not active, and the event log's
/// error when the prune fails.
#[allow(clippy::too_many_arguments)]
pub async fn create_governance_checkpoint(
    cell: &mut ClassSCell,
    deps: &ActorDeps,
    context_id: &str,
    checkpoint_seq: u64,
    merkle_root: [u8; 32],
    event_count: u64,
    last_event_hash: [u8; 32],
    state_snapshot_hash: [u8; 32],
    creator_did: &DID,
    creator_signature: Vec<u8>,
) -> Result<ContextCheckpoint, ContextError> {
    require_active(&cell.handle)?;

    let (_, min_count) = cell.governance.engine.checkpoint_cosignature_requirements();
    let attestation_status = if min_count == 0 {
        CheckpointAttestationStatus::FullyAttested
    } else {
        CheckpointAttestationStatus::PartiallyAttested
    };

    // Capture pruning policy snapshot for the optional pruning step.
    let pruning_policy = cell.governance.pruning_policy.clone();

    let created_at = deps.clock.now_secs();

    let checkpoint = ContextCheckpoint {
        checkpoint_seq,
        merkle_root,
        event_count,
        last_event_hash,
        state_snapshot_hash,
        created_at,
        creator_did: creator_did.clone(),
        creator_signature,
        cosignatures: Vec::new(),
        attestation_status,
    };

    // Trigger event log pruning if a pruning policy is configured on the
    // context. A failed prune fails the checkpoint, with the
    // in-memory log unchanged (spec section 17.3, "Event log write
    // failures").
    if let Some(ref policy) = pruning_policy {
        let context_id_bytes = context_id_to_bytes(context_id);
        if deps
            .event_log
            .prune_before_checkpoint(&context_id_bytes, event_count, policy)
            .await?
            .is_some_and(|pruned| pruned > 0)
        {
            tracing::info!(
                context_id = %context_id,
                checkpoint_seq = checkpoint_seq,
                "pruned event log entries after governance checkpoint"
            );
        }
    }

    Ok(checkpoint)
}
