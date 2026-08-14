---
name: eventlog-unification-phase2-head3d96
description: Phase 2 event-log substrate swap FINAL at HEAD 3d96058f5 — import observed_at re-pin + WASM governance empty-leaf parity + shared convergent ts + now_ms cfg-split. APPROVED, no findings.
metadata:
  type: project
---

Final merge-gating confirmation at HEAD `3d96058f5` (3 commits past [[eventlog-unification-phase2-head4cad]] `4cad781e5`). Both prior open items from the 4cad review are now CLOSED. Diff vs 4cad = 10 files, +526/-48. Native + WASM(wasm32) + host-test builds all `cargo check` clean.

**Item 1 (import observed_at re-pin) — CLOSED.** lifecycle_helpers.rs:1730+ `import_context` now re-pins `pending_ceiling_modification.observed_at` and `pending_economic_policy_change.observed_at` to `now_for_validation` (importer's local clock) on the UNTRUSTED export-import path; field replaced via `.clone().map(|mut p| { p.observed_at = now_for_validation; p })`. RESTORE (self-respawn) path keeps it verbatim (re-pinning would let a crash-loop re-arm the window forever — correct asymmetry). Mirrors the existing `creation_timestamp_secs` re-pin + `cooldown_until` sanitize precedents. New supervisor.rs:9126+ test `import_repins_observed_at_so_backdated_pending_change_is_not_effective` proves non-vacuity: backdates BOTH effective_at AND observed_at by 10×PERIOD, imports a real SIGNED Full export, asserts NOT effective at import_time+1 AND effective at import_time+PERIOD+1 (restart, not destroy). state.rs doc comments rewritten to state the invariant is held in-process AND re-established on import (removed false "monotonic clock" wording).

**Item 2 (FormulaChange::is_effective latent) — still latent, unchanged, still correct.** Zero live construction sites; observation only. Not touched this round.

**WASM governance empty-leaf parity — the substantive new work, SOUND.** manager.rs: 3 production append sites (`propose_governance_action`, `approve_governance_proposal`/vote-cast ×2, `withdraw_governance_vote`) flipped from `proposal_id.as_bytes()` → `b""`. This matches native, where `append_context_event` (builder.rs:187) calls `append_event` with `EventPayload::default()` (empty data) for these 3 EventTypes — VERIFIED the native producer is genuinely empty, so byte-identical leaf preimage across platforms (§9.9.3). proposal_id rides only on the buffer-only ContextEvent, never the durable Merkle leaf. lib.rs EventType doc comments rewritten "Durable leaf payload: EMPTY" for the 7 governance variants. Two WASM tests + one native test pin it:
- native `cross_impl_governance_proposal_vote_leaf_is_empty` (wasm_conformance.rs:2331) — drives REAL `append_context_event`, asserts empty.
- WASM `cross_impl_governance_proposal_vote_leaf_is_empty_wasm` — synthetic path + REGRESSION DETECTOR (asserts roots DIVERGE if proposal_id stamped → proves the fix is load-bearing, non-vacuous).
- WASM `real_governance_handlers_append_empty_leaves_wasm` — drives the REAL handlers end-to-end (4-member majority, quorum 3, stays Pending so all 3 append sites reachable), so flipping any production site back fails the build not just the synthetic test. This is the gold-standard "test the production path, not a hand-rolled echo" pattern.

**Shared convergent_consequence_timestamp — single seam.** governance_logic.rs DELETED its local copy; now imports `scp_protocol::trust::consequence::convergent_consequence_timestamp`. Body byte-identical (`evidence.iter().max_by_key(event_sequence).map_or(0, timestamp)`). Native + WASM now share ONE definition — removes a latent divergence class.

**Dense consequence sequence (consequence.rs:879+) — behavior-preserving.** `merge_consequence_events` now keys `sequence` on `buffer_events_accepted` (count of accepted events, contiguous) not raw `idx` (gappy when events skipped). Sequence is evidence-only metadata; `matches_trigger` never reads it (verified in prior reviews) → identical merged SETS across native/WASM. Pre-increment ordering correct (push uses pre-increment value, increments after).

**now_ms cfg-split (time.rs) — security-preserving.** wasm32 variant = hardened captured-`Date.now` (unchanged, the real browser build). Added `#[cfg(not(target_arch="wasm32"))]` SystemTime fallback so host-target tests can drive real WASM-bridge governance handlers needing a clock without a JS runtime. The fallback is COMPILED OUT of wasm32-unknown-unknown (verified: `cargo check --target wasm32-unknown-unknown` clean) → cannot weaken the production hardened-clock property. `wasm_bindgen::prelude::*` + inline_js extern also gated to wasm32 (dead on native).

**Substrate invariants re-verified at this HEAD:** single provider-owned RFC-6962 tree (no independently-mutated twin; state.merkle_tree is a read-through cache); ADR-011-amendment closed EventType taxonomy intact; no frontierRoot/causal_dag/Phase-3 leakage; clean seams for #1845 (deferred-#A bridge-local log deletion)/#1846 (WASM governance EventType append parity — note: this round adds the empty-leaf parity for proposal/vote/withdraw specifically)/#1847; honest deferrals `#[ignore]`-marked. No enforcement files touched; op surface unchanged.

VERDICT: APPROVED — final double-zero confirmation. No new findings; both prior open items resolved or remain correctly-latent. No DOA decisions.
