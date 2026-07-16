---
name: scp-out-046-streaming-saga-seal
description: SCP-OUT-046 streaming-saga seal-phase FSM alignment review (ADR-061 seal phase / ADR-049 §3a amendment / §6.2.4-5) at HEAD 18f6fd11c — CHANGES-NEEDED, 2 scar-tissue blockers
metadata:
  type: project
---

# SCP-OUT-046 Streaming-Saga Seal-Phase — Alignment Review (2026-07-15) — CHANGES-NEEDED

Branch feat/outlet-xctx-046-seal-fsm @ 18f6fd11c, `git diff origin/main..HEAD` (17 files, +7843/-3588; supervisor.rs mostly formatting churn). Story done. Realizes ADR-061 seal phase = §6.2.5 streaming saga (streaming × transactional).

**Why:** Coordinator asked to challenge 4 load-bearing decisions as potential scar tissue + hunt hidden deferrals.
**How to apply:** If re-reviewing OUT-046 or OUT-047/049, the 2 blockers below must be closed; the 4 challenged decisions are GROUNDED (don't re-litigate).

## 4 challenged decisions — ALL artifact-grounded
1. **No Prepare-A** (invoker pays via §5.4.5 StreamEscrow reserved in B at Commit-transition, supervisor.rs:6450 `open_outlet_stream_phase1` SAGA MODE; settled at seal-close saga.rs `settle_at_close`). GROUNDED: ADR-061 §64 "composes existing StreamEscrow"; mechanism §1 "Commit-transition confirms the reservation + triggers pump"; §5.4.5:572 "paid cross-context stream MUST use streaming saga". Unary Prepare-A caller-side escrow is unary-specific. NOT weakened. (Obs: ADR-061 §64 says "caller-side escrow settlement" but impl holds escrow in B — "caller-side"=invoker's payment settled vs best-effort zero-escrow, not a location claim; consistent.)
2. **Slot release @ Commit while escrow held** — EXACT match ADR-049 §3a(b) (ADR line 86). supervisor.rs:6728 `drop(reservation)`; escrow settles at close. `max_concurrent_outlet_stream_pumps` IS enforced (not just cited): pump_semaphore flows into open_stream_session (supervisor.rs:6655), permit held by B's pump feeding the seal task.
3. **Off-mailbox settlement** — consistent w/ ADR-049 actor model. Seal HANDLER (on-actor) computes StreamSettlement; off-mailbox seal task DISPATCHES it back via `settle_outlet_stream_via_actor` (supervisor.rs:11837) → `OutletsCommand::SettleOutletStream` to B's mailbox. Mutation lands ON actor; only dispatch origin off-mailbox (re-entrancy avoidance). Generation guard prevents cross-respawn misapply.
4. **AC7 custody split** — mechanism GROUNDED. Keyless autonomous sweep can't sign (real constraint: runtime holds no signing key, ADR-049) → witness-absent resolves to NeedsRepair + escrow HELD (specced §6.2.4 terminal), witness-present → Committed (supervisor.rs:7779). Key-bearing truncated close is a FULLY-BUILT method (supervisor.rs:6818 `recover_streaming_saga_truncated_close`), signs restored prefix, settles at prefix billed_count. Not a stub.

## BLOCKER 1 (scar tissue): fabricated SCP-OUT-047 citation
supervisor.rs:6793-6794 & 7776-7777 attribute the deferred FFI-reconnect key-bearing recovery driver to "SCP-OUT-047". SCP-OUT-047 story = streaming-saga INITIATION FFI surface only (open + poll_next); 0/10 ACs mention recover/reconnect/truncat/signing-key/recovery/crash/NeedsRepair/witness. Violates CLAUDE.md "never fabricate story references to justify gaps" + one-way artifact flow. SCP-OUT-049 mentions truncated-close but as CONFORMANCE VECTORS, not the production driver. FIX (upstream): amend a story (047 or new) to enumerate the reconnect/key-bearing recovery driver, or re-point the deferral to ADR-049 §3a's general FFI-surface-deferral (§70 precedent: method exists, production caller deferred).

## BLOCKER 2 (scar tissue): dead unbounded `reassembled` buffer in seal task
invoke.rs `run_streaming_saga_seal_task` (~4950-5158): `reassembled: Vec<OutletStreamChunk>` pushes every forwarded chunk (full Data payloads), UNBOUNDED — NO `max_retained_chunks` cap (best-effort sibling bridge HAS one at invoke.rs:4689). No post-loop reader (only `.last()` for next_seq @ 5090; A-side #135 leaf recorded from `outcome` not reassembled; line 5158 "reassembled is no longer needed"). Contradicts ADR-061:39/63 "never accumulates the full payload set in memory / two sinks write-through not buffering" — recreates the O(n) memory the O(log n) frontier exists to prevent. Header rustdoc (invoke.rs ~4909, ~4950) claims A-side recording "wired in the next slice" from reassembled, but #135 IS wired THIS slice & doesn't use it — stale comment concealing dead accumulation. FIX: drop the Vec, track last_sequence only.

## Solid (faithful)
Seal handler two-combinator (capture-restore + append-keep), replay re-emit verbatim (settlement:None), real frontier.root() (never [0u8;32]), SCP-XCTX-STREAM-RECEIPT-V1, dual-log (B OutletInvoked on-actor + A CrossContextOutletInvoked from sealed receipt convergent), AC8 single-commit (StreamCaptureAppend never 2PCs), AC4 O(log n) durable frontier + memory test. Class-S KEEP monotonic credit ledger, cost_per_chunk staged so seal reconstructs escrow after crash. Verdict: CHANGES-NEEDED (2 blockers; core mechanism sound).
