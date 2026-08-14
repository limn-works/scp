---
name: scp-out-046-pr-a-streaming-variant-prep
description: SCP-OUT-046 PR-A (@541a89e3b) — streaming SagaPreparedState variant + MerkleFrontier serde type-half prep; COMPLETE for PR-A scope, behavioral half is PR-B
metadata:
  type: project
---

SCP-OUT-046 PR-A "seal-phase FSM prep" @541a89e3b (feat/outlet-xctx-streaming-phase2, wt scp-wt-slice3) — reviewed COMPLETE for PR-A scope.

**Why:** PR-A stages TYPES only (Class-S streaming saga variant + frontier serde); the seal-phase FSM + production constructor + O(log n) write-through pump are PR-B (same story). Legit "type shipped ahead of consumer" pattern (mirrors unary variant's serializable mirror shipping ahead of dispatch wiring; Phase-1 Sequence primitive).

**How to apply / findings (all verified, tests run green):**
- **AC4 type-half MET**: new `CrossContextStreamingOutletInvocationPrepared` (saga_prepared_state.rs:308) carries frontier(MerkleFrontier) + credit ledger(reserved/billed Amount, billed_count u32) + cancel_ack_ceiling, keyed by `saga_id: SagaId` + 8 replay-deterministic receipt inputs (mirrors unary). grep witness (MerkleFrontier + SagaId + frontier field) resolves to a REAL variant, not dead ref. AC4 behavioral half (memory-O(1), persist-before-forward) is PR-B — correct split.
- **Not a stub**: from_prepared/into_prepared arms FULLY implemented — all 14 fields projected+rehydrated, no None-placeholders; frontier embedded directly, round-trips bit-identical (root/billed_count/leaf_count reproduce). Snapshot mirror `CrossContextStreamingOutletInvocationSnapshot` derives Serialize/Deserialize/PartialEq/Eq. Live Prepared structs (unary:148, streaming:308) both correctly NON-derive (§9.4.3 bearer-barrier); enum stays non-Clone.
- **Match sites ALL covered**: production sites (saga.rs 1520/1661/1694/1060/1714/1863, class_s.rs:5489) are constructors or refutable if-let/let-else that only match unary — streaming never constructed in PR-A prod, so they never encounter it (fail-closed 13031 if they did). PR-B must revisit these to dispatch streaming. Test irrefutable binds → let-else+panic. supervisor.rs:21139 was a `SagaPreparedStateSnapshot` (not State) enum bind a naive grep missed → converted to matches!+if-let. Compiles + 3 new round-trip tests pass (snapshot_mirror_round_trips_cross_context_streaming_outlet, frontier_serde_round_trip_reproduces_root, class_s_..._snapshot_restore_is_lossless).
- **§6.2.5 clarification complete**: added "write-through with persist-before-forward ordering ... delivered set always a subset of sealed prefix". No dangling TBD. Variant omits no ADR-061 seal-shape field.
- **No cross-layer/FFI miss**: enum referenced ONLY in scp-runtime (0 hits in crates/scp-ffi + bindings). Class-S actor-local internal state, never crosses FFI. No capability-matrix/pipeline_wiring obligation (adds no SDK op) — correctly untouched.
- **LOW PR-B note (not a PR-A gap)**: struct `billed_count: u32` vs `frontier.billed_count(): u64` — u32 is CONSISTENT with all runtime credit-ledger types (invoke.rs:1597, dispatch.rs:837, stream_settlement_adapter.rs:472); the escrow cross-check narrowing is PR-B with existing precedent.

Story SCP-OUT-046 as a WHOLE remains INCOMPLETE until PR-B (receiver-promptness, slot-release, escrow-at-close, seal/finalize, crash-truncated-close, single-invocation tests, ACs 1-3/5-9). PR itself states this.
