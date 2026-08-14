---
name: wasm-mls-eviction-c3f7fe48b
description: WASM governance RemoveMember MLS-eviction ROUND 4 (doc-only delta) @ c3f7fe48b — ALIGNED, zero findings, ships
metadata:
  type: project
---

# WASM governance RemoveMember MLS-eviction — ROUND 4 @ c3f7fe48b (branch fix/wasm-governance-mls-eviction, 2026-06-23)

VERDICT: ALIGNED, ZERO findings, SHIPS. Task #227. Continuation of [[wasm-mls-eviction-66a2c6a5c]] (round 3) / [[wasm_mls_eviction_b98c5b1a9]] (round 2) / [[wasm_mls_eviction_97c351df9]] (round 1).

**Branch:** HEAD c3f7fe48b, 6 commits off origin/main (ea0058cde→97c351df9→b98c5b1a9→f761c7d2b→66a2c6a5c→c3f7fe48b). Two-dot diff +1688/-11 across SAME 7 files as round 3 — functional set BYTE-IDENTICAL to round 3.

**Delta since round 3 = ONE commit c3f7fe48b, DOC/COMMENT-ONLY** (commit msg "zero runtime behavior change" — VERIFIED by reading all 3 hunks; no executable stmts/assertions/signatures/test bodies changed). Three accuracy-improving polishes:
1. `scp.ts:1362-1380` `@returns` JSDoc — corrects a round-2-class inaccuracy: old text said "Browser (WASM) callers MUST relay" on a method that is actually the NAPI/native unified path (auto-broadcasts). Now backend-scoped: native auto-broadcasts (caller need not relay) vs WASM browser MUST relay (ADR-034 no internal transport). Consistent with WASM-specific `context.rs:739-748` doc which independently still says WASM caller MUST relay → both agree on WASM obligation.
2. `group.rs:840-860` test docstring — removes overclaim (single-member `remove_member_by_did_short_circuits_on_self_did_before_scan` does NOT isolate the short-circuit; on 1-member group both self-DID short-circuit AND own-leaf skip independently yield empty no-op). Points to the real discriminator `remove_member_by_did_self_did_does_not_evict_duplicate_leaf` (dup non-own leaf carries local DID → only short-circuit prevents resolving+evicting it).
3. `manager.rs:3490-3510` inline comment — collapses duplicated sender-key-gap prose to a one-line pointer to canonical explanation at `WasmCryptoState::governance_rotate_sender_key` (`crypto/state.rs:170-193`). VERIFIED pointed-to explanation INTACT + complete (sender-key rotation purpose + WASM missing cross-member distribution gap is orthogonal to eviction b/c MLS epoch advance IS the lockout). No info lost.

**All substantive round-3 facts STAND** (re-affirmed, not re-derived): MLS-evict mirrors native byte-for-byte; convergent leaf (empty payload / executor actor_did / proposal.created_at, before GovernanceActionExecuted); missing-leaf no-op (#1294); self-removal short-circuit + own-leaf skip + dup-leaf parity; commit returned for relay; ADR-034 respected; sibling gaps (WASM AddMember no-MLS → #206/#1877; no commit-relay retry → ADR-034) correctly OUT; no spec/ADR change needed (§9.16.4 normative); artifact-flow honored.

LESSON: a doc-only follow-up round = (1) confirm git two-dot stat is identical to last pass except the new commit, (2) read the full new-commit diff to prove "zero behavior change" (no assertions/signatures/test bodies), (3) when a comment is COLLAPSED to a pointer, OPEN the pointed-to site and confirm it's intact+complete (don't trust "see X"), (4) when a doc is re-scoped per-backend, check the sibling backend-specific doc (context.rs vs scp.ts) for mutual consistency. Expected clean result delivered.
