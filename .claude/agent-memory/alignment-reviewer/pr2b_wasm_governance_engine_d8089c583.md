---
name: pr2b-wasm-governance-engine-d8089c583
description: #1900 PR-2b alignment review — WASM adopts shared governance engine for quorum (commit d8089c583); ALIGNED at engine layer, but multi-party governance params unwired in ALL 3 native bridges (cross-bridge asymmetry finding)
metadata:
  type: project
---

# #1900 PR-2b WASM governance engine adoption @ d8089c583 (2026-06-28) — ALIGNED (engine layer), 2 cross-bridge gaps

Commit `d8089c583` "feat(governance): keyless ingest_proposal + WASM adopts shared engine for quorum". 9 files +2153/-176. Branch worktree 1900-pr2b-wasm.

**Why:** PR-2b completes #1877 native↔WASM governance convergence. Was BLOCKED (see cryptographer/pr2b-wasm-engine-adoption-blocker.md): PR-2a added keyless ingest_approve/reject ONLY, no keyless propose/seed; engine `proposals` map private. Unblock = add `TrustedVoteIngest::ingest_proposal(GovernanceProposal)` (additive, NOT on GovernanceEngine, native never reaches it). This commit is exactly that Opt-1 resolution.

**How to apply:** When reviewing further #1877/#1900 governance-convergence work, the engine-level tally is now SHARED & converged. The OPEN gap is bridge param-wiring (below), not the engine.

## Verified CONVERGENT (engine layer)
- WASM resolve_governance_config (manager.rs:392) mirrors native parse_governance (context_params.rs:185-228) collapse policy EXACTLY: threshold+empty-signers→single_admin; majority/unanimity+empty-voters→single_admin; collapse runs BEFORE threshold-floor check (same as native returning SingleAdmin before validate_governance_model).
- Defaults match native: governanceThreshold default 1 (native `unwrap_or(1)`), governanceMinParticipationBps default 5000 (native `MajorityVoteEngine::new(...,5000,...)` in create_governance_engine state.rs:~1775).
- Frozen-set invariant (item A): eligible_voters/min_participation_bps stored on PerContextState + export snapshot; engine denominator from frozen set NEVER live members.
- Quorum decision routes through transient engine via ingest_proposal + ingest_approve/reject (decide_vote_via_engine, build_transient_governance_engine manager.rs:5362). String-match `governance_quorum` arithmetic DELETED.
- Leaf §9.9.3 UNCHANGED: GovernanceActionExecuted leaf timestamp = proposal.created_at (committer-assigned per spec 07:127), actor_did = executor (committing member), payload = shared GovernanceActionExecutedPayload (encode_governance_action_executed_payload existed in PARENT commit — NOT changed; prompt's "empty payload" framing imprecise but conclusion holds). Replay guard keyed on canonical compute_proposal_id (no fresh-id double-execute).
- Import re-derivation (rederive_imported_proposal_statuses manager.rs:7891): replays carried votes through fresh frozen engine, overwrites snapshot status; single_admin Approved→Invalidated. Closes pre-baked-Approved forgery hole. SPEC-JUSTIFIED (defense-in-depth, untrusted snapshot).
- Conformance test wasm_keyless_ingest_matches_native_signed_threshold_decision (wasm_conformance.rs) drives native signed ThresholdEngine + keyless ingest, asserts same Approved.
- ingest_proposal (multisig/majority/unanimity) enforces proposer∈frozen-set + dup-id, stores verbatim (no re-tally/no sig verify). Native never reaches it (not on GovernanceEngine trait). SOUND additive.

## FINDING 1 (cross-bridge asymmetry, NEEDS DISCUSSION — not a PR-2b regression)
WASM is now the ONLY bridge that wires multi-party governance params. All 3 native bridges leave signers/voters/threshold UNWIRED → every native threshold/majority/unanimity context COLLAPSES to single_admin:
- PyO3: `crates/scp-ffi/src/context.rs:1189-1191` HARDCODES `governance_threshold/signers/voters: None` w/ comment "PyO3 bridge uses string-only governance for now". PyO3 is the REFERENCE bridge (100% coverage target).
- NAPI: `crates/scp-ffi/napi/src/context.rs:634` CommonContextParams uses `..Default::default()` → None.
- UniFFI: `crates/scp-ffi/uniffi/src/bridge.rs:5685` same `..Default::default()` → None.
This predates PR-2b (PR-2b only touches WASM + scp-protocol). But it means #1877 "native↔WASM convergence" is currently convergence of two paths only one of which (WASM) can actually instantiate a multi-party engine via a bridge. Native multi-party is reachable only via direct scp-runtime API, not any FFI bridge.

## FINDING 2 (native config gap)
`governance_min_participation_bps` does NOT exist in CommonContextParams (scp-ffi-common) at all — native Majority engine ALWAYS uses hardcoded 5000, never caller-configurable. WASM exposes configurable `governanceMinParticipationBps`. For true parity native common params need this field too.

## SDK legibility note
TS `ContextParams` (bindings/typescript/src/types.ts:27) advertises governance: "threshold"|"majority"|"unanimity" but provides NO typed fields for signer/voter/threshold/participation. contextCreate takes raw paramsJson string so a caller CAN pass governanceSigners etc., but the typed surface doesn't expose them (Agent-first API tenet: agent can't discover params from type signature). No cross-bridge SDK sends DIFFERENT param names — none send them at all yet.

## Scope verdict
Correctly scoped to PR-2b (WASM + ingest_proposal prereq). No unrelated drag. Correctly does NOT claim to close #1901 (remove_member) or #1846 (EventType leaves). #1900 NOT fully converged end-to-end until native bridges wire the same params (Findings 1+2) — that is downstream PR scope, should be a filed issue not silent.
