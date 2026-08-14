---
name: pr2b-wasm-governance-fix12-7e5f6cfb6
description: #1900 PR-2b WASM governance FIX1 (invalidate imported Approved) + FIX2 (pin majority participation to native fixed 5000) review @ 7e5f6cfb6 — ALIGNED
metadata:
  type: project
---

# #1900 PR-2b WASM governance FIX 1+2 @ `7e5f6cfb6` (reviewed 2026-06-28) — ALIGNED, 0 blocking

Diff `d8089c583..7e5f6cfb6` (consequence.rs -3, manager.rs +269/-187). Branch worktree `1900-pr2b-wasm`.

**FIX 2 (participation floor): CONVERGES.** WASM `build_transient_governance_engine` majority arm now `MajorityVoteEngine::new(voters, 86_400, 5000, ..)` literal — byte-identical to native `create_governance_engine` (scp-runtime/src/context/state.rs:1771). Removed configurable `min_participation_bps` field from `ResolvedGovernance`, `PerContextState`, `WasmContextExportSnapshot`, `resolve_governance_config`, test setter. KEY FACT: native create path has NO participation wire field — `GovernanceModel::Majority` (params.rs:200, governance/mod.rs:1091) carries ONLY `eligible_voters`. Configurable `min_participation_bps` lives in `GovernanceModelConfig::Majority` (engine/snapshot config), always emitted as 5000 by `model_config()` at create (governance/mod.rs:2504). So native restore (state.rs:1909) reads configurable value but it's ALWAYS 5000 → dead configurability. WASM fixed-5000 = native always-5000. No tally divergence.

**DEADLINE-PARTICIPATION QUESTION (asked explicitly): NO remaining gap.** The 5000 floor applies ONLY in `MajorityVoteEngine::resolve` deadline branch (`context.now >= voting_deadline`, majority.rs:270). Early-approve (`approvals*2 > eligible`) never consults it. WASM DOES reach the deadline branch: `ingest_approve/ingest_reject` → `precheck_vote` → `PrecheckOutcome::Resolved(self.resolve())` when a vote arrives past deadline (majority.rs:378-384). WASM seeds `now_secs` from real `crate::time::now_ms()`. So WASM exercises the deadline floor with the SAME fixed 5000 → convergent. (WASM has no autonomous deadline-sweep resolution, but native doesn't either on this keyless path; resolution is vote-driven both sides.)

**FIX 1 (invalidate imported Approved): spec-consistent.** Replaced `rederive_imported_proposal_statuses` multi-party replay with UNCONDITIONAL invalidation of every imported `Approved` (single_admin AND multi-party). Rationale sound: imported votes carry no verifiable sigs; replay would let a malicious creator declare victim-DID `eligible_voters` + fabricate empty-sig Approved votes → forged quorum re-derived → executes via `context_execute_governance`. Consistent with native: `restore_governance_engine_from_snapshot` rebuilds an EMPTY engine, does NOT replay pending/resolved proposal status. Honest Approved already in `executed_proposals` replay set → strands nothing. New test `pr2b_import_forged_multiparty_quorum_not_executable` proves it.

**Provenance: CLEAN.** 86_400 + 5000 literals trace to ADR-031 (phase-6.md:2444-2451: voting_window default 86_400, min_participation default 5000=50%) AND native state.rs:1771. §9.9.3 cited for convergence. No phantom provenance in new comments. No #NNNN in source.

**Bonus hardening:** new `validate_imported_governance_sets` caps eligible_voters/threshold_signers at `WASM_MEMBER_CAP=10_000` + per-DID validates (DoS guard on import-replay O(proposals×votes×voters)). Sound — voter/signer ⊆ members.

**Remaining gaps TRACKED, not silent:** #1925 (OPEN) captures (a) native PyO3/NAPI/UniFFI don't wire governance_signers/threshold/voters (native multi-party silently collapses to single_admin) and (b) min_participation_bps artifact-flow decision (spec-first: make configurable field OR keep fixed 5000). Well-scoped, accurate file:lines.

**Verification:** WASM build clean (wasm32). clippy clean. 13/13 pr2b tests, 15/15 cross_impl_leaf_parity, 25/25 governance, import_context tests — all pass. `WasmContextExportSnapshot` is WASM-LOCAL (not shared w/ native); no deny_unknown_fields → snapshot field removal is fwd/back compatible (moot pre-release anyway).

**#1900 engine-layer convergence: SUBSTANTIVELY CONVERGED.** Majority now converges create + deadline. Remaining divergence (native bridge wiring) properly tracked in #1925.
