---
name: leaf-actor-did-convergence
description: Defensive review of fix/leaf-actor-did-convergence (native↔WASM §9.9.3 equivocation leaf alignment) — invariants, fail-closed, system-actor-did closed-set gap
metadata:
  type: project
---

# Leaf actor_did convergence review (branch fix/leaf-actor-did-convergence @ d7216140b, base b5b0eb02c)

Reviewed 2026-06-22. Branch aligns native↔WASM system-leaf actor_did + GovernanceActionExecuted executor stamp for §9.9.3 equivocation detection.

**Why:** cross-impl Merkle convergence — honest members at equal event_count must produce byte-identical leaves so divergence = equivocation signal.

**How to apply:** when reviewing leaf-producing code, the convergence invariant (identical bytes across impls/members) is the security property; treat any local `now()` / impl-specific string on a canonical leaf as a divergence bug.

## What this PR does (correct + well-engineered)
- Native dispatch_governance_action + finalize_governance_action now take executor_did; per-action leaves AND GovernanceActionExecuted leaf stamp executor (quorum-crossing voter, or proposer on auto-execute) not proposer.
- WASM quorum reorder: pending→resolved (Approved) BEFORE execute, so execute can resolve convergent leaf TS from proposal.created_at. Fail-closed: missing proposal → CTX_2041 error (not silent 0).
- WASM execute stamps initiator_did=voter on quorum, =proposer on auto-execute (matches native).
- System leaves: native ttl.rs stamps "system:timer"/"system:close"; WASM now matches. saga divergence marker "" → "system:saga".
- Executed-leaf TS = proposal.created_at on BOTH impls (convergent, tamper-evident). Payload = shared encode_payload(GovernanceActionExecutedPayload) both sides.

## Findings — UPDATE @ HEAD 2b668715c (both prior P2s now FIXED)
- **PRIOR P2 (system-actor const) — RESOLVED:** new crates/scp-event-log/src/system_actors.rs holds SYSTEM_TIMER/CLOSE/SAGA/CONSEQUENCE_ACTOR consts. Both native (ttl.rs, governance_logic.rs, saga.rs) and WASM (manager.rs) reference them → byte-parity by construction. KAT-pinned. Done well.
- **PRIOR P2 (encode unwrap_or_default) — RESOLVED:** WASM now uses encode_governance_action_executed_payload(...)? → fails closed, no empty-payload leaf. Mirrors native map_err?.
- Consequence-subject convergence (native proposer vs WASM executor) still SEPARATE tracked task #205. Native correctly keeps proposal.proposer_did as consequence subject (NOT executor) in finalize_governance_action — verified preserved.

## Re-review @ HEAD 501a44f6a (2026-06-22) — prior 2 LOWs now FIXED, APPROVED
- **encode-failure buffer asymmetry — FIXED:** manager.rs execute path now encodes `encode_governance_action_executed_payload(...)?` (L3163-3164) BEFORE `append_log_event` (leaf) and BEFORE `push_event` (buffer). Matches native ordering. Fail-closed: encode Err → no leaf, no buffer event, executed_proposals marker stays set (parity with native, which also leaves marker set on finalize encode Err — non-retriable terminal, but encode of 2 strings is unreachable).
- **ExtendTtl saturating — FIXED:** both dispatch ExtendTtl (L3308-3312) and the timeout ExtendTtl closure (L5451) now `*ttl = ttl.saturating_add(...)`.
- **Ceiling gate is a SOUND closed allowlist:** dispatch_ceiling_capability EXHAUSTIVE match (no wildcard) over all GovernanceAction variants → Option<&'static str>. New variant = compile error. The 5 ceiling-gated actions (SuspendCapability/SuspendAccess/RevokeAccess/RestoreAccess→member:ban, RegisterTool→tool:register, CreateChildContext→context_child:create, EstablishToolInterface→tool:interface) verified one-for-one against native execute_* helpers' `ceiling.contains(&Capability::X)`. ResetMember confirmed NO native ceiling gate → WASM None (correct). All else None (propose-time auth only). `ceiling_strings.contains(required)` EXACT membership matches native CapabilityCeiling::contains (only ToolInvoke wildcards; none of the 5 are ToolInvoke).
- **Per-member capability check REMOVAL is correct:** native execute_governance_action gates only status==Approved + ctx-id + replay + check_commit_fault (L4506-4525, verified) — NO per-member action-cap check. Removing WASM's per-member check fixes a real divergence (quorum voter holds only governance:vote, would mint 0 leaves where native mints 1). Direct-FFI execute path is replay-blocked for any Approved proposal (all Approved insertions immediately execute → executed_proposals set; only other resolved insertion is Rejected). No auth bypass.
- **dispatch-failure rollback SOUND:** WASM executed_proposals.insert BEFORE dispatch (L3113); dispatch Err → remove (L3123). Ceiling reject is inside dispatch (first thing, before any mutation, L3235) → rollback fires → no replay-slot leak. Quorum/auto paths also roll back the pending→resolved move (remove_resolved_proposal + re-insert pending_snapshot) on execute Err. Matches native retry semantics. No partial-state leak.
- **WASM ContextClosed convergent close_leaf_secs:** finalize_close (L6396+) now creation_timestamp_secs.saturating_add(ttl) for TTL contexts (== handle_ttl_expiry expiry_leaf_secs), local now_secs only for no-TTL governance close. Mirrors native ttl::finalize_close deadline_unix_secs.unwrap_or_else(now). Snapshot-import clamps only anti-replay TS, NOT creation/ttl (forged-future creation only shortens deadline = fail-safe). Good.
- **STALE COMMENT (nit):** context.rs L768-769 says initiator_did "capability checked inside execute_governance_action" — no longer true (per-member check removed). Harmless, misleading.
- All consequence.rs deltas are #[cfg(test)] cross_impl_leaf_parity KATs (10 new tests). Native governance_integration.rs adds matching scenarios (executor-not-proposer, voter-without-action-cap mints one leaf, out-of-ceiling generic/child/tool-interface). Convention now KAT-pinned BOTH sides with non-vacuity controls.
- saga "" → "system:saga" leaf-byte change: native-only leaf, no WASM counterpart yet, pre-release (no data) → fine. emit_divergence_marker test doesn't assert actor_did.

## Hardening (P2, bounded): add closed `is_system_actor(&str)->bool` allowlist match in system_actors.rs for future receive-side validation (positive whitelist).

## Fail-closed verdict: ADEQUATE
- executor_did derives from signed proposer_did / authenticated voter_did (capability-checked: governance:vote on voter). No silent default to wrong DID.
- WASM missing-proposal → typed error, not 0-timestamp leaf.
- Native executed leaf only reachable with &GovernanceProposal (no ambiguous committer).

## Invariant enforcement: CONVENTION + KAT, not by-construction
- cross_impl tests (consequence.rs cross_impl_leaf_parity) pin leaf bytes against native-reference reconstruction from shared scp_event_log primitives, with non-vacuity controls (pre-fix sentinel must diverge). Strong regression pin.
- BUT actor_did sentinel correctness is convention (string literal must match) — no compile-time/closed-set guarantee. That's the P2 above.

## ENVIRONMENT HAZARD (recurring)
Shared worktree slice45-actor-did got checked out OFF the target branch (onto feat/actor-2c-xctx-tool-saga) mid-review by a concurrent process. Confirmed via reflog. DO NOT trust the worktree HEAD; review via `git show <branch>:<file>` / `git diff base..branch`. Matches [[lesson_isolation_worktree_reuses_checked_out_branch]].
