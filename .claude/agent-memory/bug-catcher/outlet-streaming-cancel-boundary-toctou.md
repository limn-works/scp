---
name: outlet-streaming-cancel-boundary-toctou
description: f96079706 (SCP-OUT-033/034/035 same-ctx streaming) — gate/accrual ceiling-snapshot TOCTOU over-bills 1 chunk at cancel boundary; append_outlet_invoked_verified dead in prod
metadata:
  type: project
---

# SCP-OUT-033/034/035 same-context streaming runtime (f96079706, branch feat/outlet-xctx-streaming-saga)

Review of the cancel-boundary billing "fix" (§5.4.5:530). Fix is correct on the DETERMINISTIC path but has a real concurrency defect + a dead-in-prod wiring gap.

## UPDATE 2026-07-14 — FIX 1 RE-REVIEW (commit 0b665ae4f) — VERIFIED CORRECT & COMPLETE
- The TOCTOU (FINDING 1) is now closed. The drop-recheck + bill + escrow accrue + record_billed_emission + next_seq bump + next_emission_seq publish are ALL in ONE `state.write()` block (dispatch.rs:3093-3136). `g.cancel_ack.billing_ceiling()` read (3098) and accrual (3110) share the same guard — record_cancel (also state.write) serializes fully before/after, NO interleave. Mirrors gate's `>=` drop: `if !terminal && seq >= ceiling { drop, continue }`.
- ingest_stream_chunk + outer_tx.send happen AFTER lock release, but frontier/terminal_summary are pump-LOCAL (single task, no shared-state race) and a dropped chunk `continue`s before both (never forwarded). A cancel landing post-release can only pin ceiling > seq for an already-billed chunk (seq < future ceiling) → no retroactive over-bill.
- No off-by-one: non-terminal not-dropped ⇒ seq<ceiling strictly ⇒ is_billable true (both escrow+frontier count it); dropped chunk doesn't bump next_seq so terminal (bypasses `!terminal`) takes cancel_ack_seq slot. Legit pre-cancel Data (seq<ceiling) never wrongly dropped.
- Escrow/credit/frontier stay consistent: frontier ceiling is unbounded (MerkleFrontier::new, dispatch.rs:2727), counts every ingested Data; we ingest exactly non-dropped chunks; under-lock is_billable(live ceiling) agrees for all non-dropped chunks. Close-time pump_recorded==manifest_reference (3280) ⇒ no false anomaly.
- Signing sequence UNCHANGED vs old (`seq=next_seq` before signing in both) — only the next_seq bump moved into the conditional lock. No new deadlock (no .await inside the write block; signer.await is before it). No double-send, terminal path intact.
- NIT (not a bug): gate window-1 `credit.try_consume()` decrements `remaining` for the boundary chunk that window-2 then drops — harmless (stream terminating, settlement is escrow-based, billed_emitted correctly NOT incremented, no consumed==billed invariant exists).
- Test pump_cancel_during_signing_..._round9_f1 (dispatch.rs:5032) is GENUINE + NON-VACUOUS: BarrierSigner parks sign call #6 (boundary Data seq5), test records cancel while parked (barrier guarantees gate ran Forward BEFORE cancel), asserts dropped-not-forwarded + billed==5 + terminal@5 + event.chunks_billed==5 + stream_chunk_count==6. Old code would forward+bill seq5 (billed=6, extra_data=1) → fails all three asserts.

## FINDING 1 (MEDIUM/HIGH) — gate/accrual ceiling-snapshot TOCTOU → over-bill by one at cancel boundary
- `run_stream_pump_v2` (dispatch.rs ~3017-3116) evaluates `apply_stream_chunk_gate` in one `state.write()` window (~3017-3040), DROPS the lock, does `try_build_signed_chunk(...).await` off-lock (~3053), then RE-ACQUIRES `state.write()` for accrual (~3082-3111).
- `apply_stream_chunk_gate` (invoke.rs:2550) drops non-terminal chunks at `sequence >= ceiling`; `accrue_data_chunk_if_billable`/`is_billable_chunk` (invoke.rs:2489) bill Data at `sequence <= ceiling`. Gate reads ceiling; accrual RE-READS `g.cancel_ack.billing_ceiling()` fresh.
- `apply_outlet_cancel_signed` (dispatch.rs:1118 `record_cancel`) runs on a SEPARATE task; on multi-thread tokio it can acquire the lock DURING the pump's signing await and pin `cancel_ack_seq = next_emission_seq`.
- Race: Data D at next_seq=5 passes gate with ceiling=MAX (Active) → Forward. Cancel lands during D's signing → cancel_ack_seq=5, ceiling now 5. Accrual: is_billable(seq 5, ceiling 5) = `5<=5` true → D BILLED (escrow accrue + frontier ingest + record_billed_emission). Terminal then lands at seq 6.
- Harm: (a) invoker over-billed 1 chunk's cost — the chunk in-flight at cancel_ack_seq that the commit's headline fix says must be dropped; (b) event `cancel_ack_seq=5` but actual terminal chunk at seq 6, violating §5.4.5:530(3) "terminal seq IS the cancel-ack sequence"; (c) INVISIBLE: escrow billed_count == frontier.billed_count == 6, self-consistent, passes the Frontier wire-check, no AuditAnomaly. Settlement (`escrow.settle_at_close()` dispatch.rs:3163) is WIRED in prod (ActorStreamSettlementSink) → real money.
- Root cause: gate outcome and billing decision use DIFFERENT ceiling snapshots across the signing await; the design's invariant ("no billable Data at cancel_ack slot") is only enforced at gate time, not re-checked at accrual after a concurrent cancel.
- Fix: in the accrual window re-evaluate against the live ceiling — if a cancel became Pending during signing and `final_chunk.sequence >= billing_ceiling()`, DROP (do not forward, do not bill, do not advance cursor), mirroring the gate's `>=` drop. Deterministic (pre-recorded-cancel) path is correct; only the interleave is broken and it is UNTESTED.

## FINDING 2 (MEDIUM) — append_outlet_invoked_verified is dead in production
- `MerkleEventLogProvider::append_outlet_invoked_verified` (providers/event_log.rs:266) + the `ChunksBilledSource::Sequence` full-manifest wire-rejection are referenced ONLY by their own tests (034 AC21/AC22). No production caller.
- The dispatch pump does the Frontier check INLINE (`verify_outlet_invoked_event_manifest` w/ Frontier source, dispatch.rs:3234+) then `sink.record`; it never calls append_outlet_invoked_verified. The inner invoke pump (one-shot) does `sink.record` with NO manifest verify (invoke.rs:3661-3681).
- Deeper (PRE-EXISTING, not this commit): there is NO production `impl OutletInvokedEventSink` anywhere — every impl is `#[cfg(test)]`. PyO3 bridge (scp-ffi/src/outlet_stream.rs:577) passes `None` for invoked_event_sink → streaming OutletInvokedEvent is never durably logged in prod; the `verify_chunks_billed`/manifest wire-rejection this commit "makes live" is un-exercised in prod. Settlement sink IS wired, event sink is not.

## Verified CLEAN
- monotonic_seq durable cursor (scp-ffi/common/outlet_stream_credit.rs): persist-before-return crash-safety correct, per-(context,request_id) key scoping correct, burned-value-skip acceptable (runtime requires strictly-increasing). Caller-lock contract documented.
- No double event emission: open_stream_session passes inner invoke_outlet `None` sink (dispatch.rs:2268); only outer pump emits.
- cancel_ack_seq threading: settlement reads cancel_ack_seq() BEFORE record_terminal (dispatch.rs:3164-65, correct order); inner pump always None; build_streaming_outlet_event (Some,Ok)->Cancelled mapping correct, (Some,Error) keeps Error.
- One-shot 2-chunk: inner pump one_shot_to_stream + framework End = 2 chunks, cancel_ack_seq=None. Correct.
- RFC-6962 independent KATs (protocol/stream.rs) genuinely independent (recursive split-at-largest-pow2 vs library iterative).
