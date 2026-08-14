---
name: pr1540-checkpoint-equivocation
description: Adversarial review of #1540 checkpoint exchange + equivocation detection + reconnection driver; relay vs member attack surface
metadata:
  type: project
---

# #1540 — Checkpoint Exchange + Equivocation Detection + Reconnection Driver

Branch: feat/1540-checkpoint-equivocation-sync. Worktree agent-a1d30b67d4e9aa5bf.

**Why:** Adversarial review modeling malicious relay (no sig forge) + malicious member (signs own checkpoints).
**How to apply:** Reuse this model when reviewing sync / event-log consistency changes.

## Verdict: design is sound. No CRITICAL/HIGH viable exploit. 2 LOW/INFO.

### Vector 1 — targeted alert drain (no loss/reorder)
- `drain_equivocation_alerts` (membership.rs:1007) partitions buffer, keeps non-alerts in order, leaves `dropped_since_last_consume` untouched. CORRECT.
- Both `DrainEvents` (SDK delivery) and `DrainEquivocationAlerts` route through SAME actor mailbox (messaging dispatch) → serialized, no intra-actor race. NO relay timing window: relay-injected events flow through deliver_incoming → receive_buffer; equivocation events are emitted there too; a total `drain_events` between phases would consume them but the driver uses the TARGETED drain. No loss.

### Vector 2 — checkpoint replay amplification
- Freshness key `(event_count, timestamp)` BOTH signed by SCP-CHECKPOINT-V1 canonical hash (checkpoint.rs:1143). Relay CANNOT mutate either → relay replay is idempotent (record_equivocation_if_fresh suppresses). SOUND vs relay.
- Map `last_seen_remote_checkpoint: HashMap<DID,(u64,u64)>` bounded by membership: insert only reachable after `verify_remote_checkpoint_authenticity` requires `membership.contains(sender)`. BOUNDED.
- LOW (malicious MEMBER): a member signs own checkpoints → controls timestamp. Can mint N distinct divergent checkpoints at increasing (count,ts) → each appends one EquivocationDetected to local log + one receive-buffer alert. Bounded per send-event-count growth, not unbounded-per-relay. A malicious member is already detectable/attributable equivocation; amplification ≈ flooding own context. Acceptable.
- Self-interplay (NOT a bug): appending EquivocationDetected increments local_count (event_log_entries().len()). Both local checkpoint event_count AND compare local_count read same counter → move together, no honest-peer masking.

### Vector 3 — forensic evidence binding
- Roots persisted via append_context_event_with_payload + carried on ContextEvent::EquivocationDetected (local_merkle_root, remote_merkle_root). remote_merkle_root comes from the SIGNED checkpoint (sig covers merkle_root). local_root is own log. Cannot be poisoned by relay. SOUND.

### Vector 4 — epoch_reconciliation termination
- reconnect.rs:308 `while !pending.is_empty() && total_merged < limit`; break on merged_this_pass==0. pending capped `.take(limit)` (limit=max_sequential_commits default 100). Worst case O(limit²)=10k mailbox calls (pathological), but TERMINATION GUARANTEED. Relay cannot wedge (forged Commits rejected by OpenMLS epoch check; rejected blobs retried then fall out at steady state). INFO: O(limit²) cost note only.

### Vector 5 — count-skew evasion documented
- Documented at all 4 SDK surfaces (py scp.py:985, ts scp.ts:1501, swift:449, kotlin:689): perpetually-behind relay NOT detected; suffix consistency proof "specified separately". HONEST. Behind arm has CONSISTENCY-PROOF CATCH-UP SEAM comment (queries_helpers.rs:802) explicitly NOT implementing fetch. Not silently advertised as full detection.
