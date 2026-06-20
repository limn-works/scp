---
name: eventlog-unification-phase2-final
description: Phase 2 event-log substrate swap FINAL state (HEAD 16a2cd42b) — shared merge_consequence_events seam, verify_merkle_chain rename, redundant-export-field removal, ADR-051. APPROVED.
metadata:
  type: project
---

Final state of Phase 2 (see [[eventlog-unification-phase2-substrate]] for the bf9266777 mid-state and [[eventlog-unification-adr011]] for Phase 1). Reviewed at HEAD `16a2cd42b`. Verdict APPROVED (double-zero gating).

**The two commits past bf9266777 are pure architectural improvements — convergence-by-construction:**
- `merge_consequence_events` now lives ONCE in `scp-protocol/src/trust/consequence.rs` (~219 LOC). Native (`governance_logic.rs::event_log_entries_for_consequences`, now a thin adapter) and WASM (`wasm/src/consequence.rs::merged_consequence_events`, now a thin adapter) BOTH delegate. Each caller only acquires its own Source 1 (event_log provider / `event_log_events()`) + Source 2 (`receive_buffer.event_log_entries()` / `event_buffer_events()`), both returning `&VecDeque<ContextEvent>` — IDENTICAL types + iteration order → byte-identical merged sets → §9.9.3 convergence enforced by SHARING ONE FN, not by hand-mirrored duplicate code (the old failure mode). This is the right seam.
- `verify_merkle_chain` → `recompute_event_log_root` (export_import.rs:464). Old name was a conceptual lie (RFC 6962 tree, not a hash-chain — pre-unification residue). New name is accurate. Mechanical rename, all call sites + tests updated.
- REMOVED redundant unsigned-envelope `merkle_root` field from the export struct + its "step 6" defense-in-depth ct_eq cross-check. Correct removal: an UNSIGNED mirror cross-checked against a SIGNED value adds zero security (attacker edits both). The authoritative check SURVIVES at export_import.rs:638 `computed_root.ct_eq(&export.snapshot.event_log_merkle_root)` (constant-time, vs SIGNED root). Exactly the redundant-recheck class CLAUDE.md warns against — removing it is a simplification win.

**Single source of truth CONFIRMED at final state:** no `merkle_tree` twin, no `EventLogEntry` bridge-local struct (both grep-0 in runtime+ffi). FFI common operates on `scp_event_log::Event` with one `event_type_label` (Debug form) string source.

**ADR-051 (`.docs/adrs/ADR-051-...md`, dated 2026-06-19) is a FORWARD PROGRAM ONLY — correctly NOT implemented here.** grep for frontierRoot/causal_dag/SCP-CHECKPOINT-V2/head_refs = ZERO in crates/. The ADR is exceptionally well-reasoned: governing theorem ("a derived record is automatic+convergent iff its trigger INPUT is convergent"); rejects convergent-velocity-clock with full alternatives analysis (median/multi-vantage/relay-ingest/beacon all dismantled); settles velocity=local-throttle + suspension=governance-commit (execution IS the record). phase-2.md ADR-011 amendment fully coherent with it (exclusion taxonomy, MessageSent/ToolInvoked enum comments cite ADR-051 end state).

**Three honest deferrals, all correctly marked (NOT completeness violations — they are the documented Phase-2/Phase-3 boundary, ADR-051 step-2 forward program):**
1. WASM↔native full governance EventType leaf parity — `#[ignore]`'d `wasm_native_full_governance_eventtype_parity_pending` (wasm_conformance.rs:2458) panics if un-ignored, enumerates ~40 unappended types. Phase 3 #1846.
2. Cross-member leaf replication — `#[ignore]`'d `two_real_members_converge_pending_cross_member_replication` (eventlog_convergence.rs:334). Doc honestly states tests HAND-FEED identical committer timestamps (proves leaf-construction rule) but do NOT drive real envelope receive/copy. ADR-051 forward step.
3. `payment_history` (receipt.rs:404) sliding-window ring buffer, NOT authoritative ledger — doc explicit, no SDK surface yet, spec §19.11 end state. PaymentReceived excluded from canonical log (correct convergence).

**Test quality is gold-standard:** eventlog_convergence.rs pairs every positive (equal convergent input→equal root) with a NEGATIVE CONTROL (per-author/per-member divergent input→divergent root), proving non-vacuity. Frozen tags 0-35 pinned. All four surfaces compile clean (event-log/protocol/runtime+tests/wasm32 bridge); zero todo!/unimplemented! in added lines.

ENV NOTE: temp dir `/private/tmp/claude-501/.../tasks/` hit ENOSPC mid-review; cleared with rm of *.output. Bash output files can fail to read if another claude process cleans them.
