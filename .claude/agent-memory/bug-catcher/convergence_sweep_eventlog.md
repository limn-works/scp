---
name: convergence-sweep-eventlog
description: scp-runtime durable event-log append convergence sweep — which EventType appends are receiver-minted (non-convergent, §9.9.3 risk) vs send/local-action (convergent)
metadata:
  type: project
---

# §9.9.3 native↔WASM convergence sweep of scp-runtime durable appends

Commit f438acf0f removed `EventType::PseudonymAnnounced` (76→75, tag 59 retired as gap) — it was the last of the ADR-011-amendment exclusion trio (`MessageReceived`, `EquivocationDetected`, `PseudonymAnnounced`) still being durably Merkle-appended on a receive path. Removal verified correct + complete (grep `EventType::PseudonymAnnounced` empty; regression test `received_announcement_updates_registry_without_durable_append` genuinely asserts `any_append==false`; KAT tags stable).

**Why:** §9.9.3 equivocation detection + native↔WASM parity require every durable `append_*` to be CONVERGENT (every honest member appends identically + in-order). A receiver-minted, per-arrival-order leaf diverges honest roots → false-positive equivocation.

**How to apply:** classification rule — a durable append is BUG-class (non-convergent) iff it fires on the message-RECEIVE path, per-receiver, evaluated over receiver-local state (receive buffer + local `now`). Send-side / single-authoritative-actor / lifecycle-control appends are convergent.

## Remaining non-convergent durable append after f438acf0f (REPORTED)
`ConsequenceTriggered` / `ConsequenceEnforced` / `ConsequenceEnforcementFailed` / `ConsequenceEscalatedToSuspendAll` via `governance_logic::append_consequence_event` (governance_logic.rs:104/341/379/413/549/564), driven by `enforce_triggered_consequences` from the RECEIVE path: messaging_helpers.rs:678 (`run_buffered_post_delivery`), 2504 (`Recorded` direct path), 2610, 1833. Input = `event_log_entries_for_consequences` merges durable log + receiver-LOCAL receive buffer (cap 100, estimated timestamps spaced backward from each receiver's local `now`). Different receivers → different trigger points/payloads/none → divergent tree::root. SAME class as PseudonymAnnounced. BUT pre-existing; ADR-011 amendment names ONLY 3 exclusions and asserts everything else is durable — so this contradicts the ADR's own stated end state. Flagged in the convergence-sweep job, not the removal-correctness job.

## Convergent (OK) — send-side / local-action / single-authoritative-actor
- `MessageSent` (messaging_helpers.rs:1677 finalize_send; broadcast_helpers.rs:397 author seal) — sender's append IS the canonical record per ADR.
- broadcast_helpers MemberJoined/MemberLeft/MemberBlocked/MemberUnblocked (106/162/525/581) — host local governance action.
- governance_helpers.rs (~50 sites) — proposer/applier local governance.
- actor/handlers/governance.rs:1060 commit-retry ("system") — host reconciliation.
- ttl.rs ContextClosing/ContextClosed/ContextExpired — initiator/timer lifecycle control.
- economy_helpers PaymentReceived / messaging_helpers PaymentCaptureFailed — host local payment action.
- lifecycle_helpers MemberJoined/MemberLeft — member-management action handler.
- trust_recovery_helpers RecoveryEpochAdvanced (265) — recovery coordinator ("system:recovery") single-driver.
- run_buffered_post_delivery `Some(event_name)` channel (651) — now DEAD for received traffic (deliver_plaintext_or_announcement returns None for all received traffic); kept as future opt-in. OK.
