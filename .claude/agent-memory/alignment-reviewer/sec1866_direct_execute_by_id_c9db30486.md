---
name: sec1866-direct-execute-by-id-c9db30486
description: SEC-1866 governance direct-execute quorum-bypass fix review at c9db30486 — ALIGNED, 1 phantom-provenance finding already remediated downstream
metadata:
  type: project
---

# SEC-1866 direct-execute governance by-id @ c9db30486 (2026-06-22) — ALIGNED

Reviewed `git show c9db30486` (parent a632c731a), branch fix/1866-direct-execute-trust. HEAD had already advanced to b321248e1 (later commits on top) — reviewed the SPECIFIED commit blob via `git show <sha>:<file>`, not working tree.

**The fix:** `execute_governance_action` (governance_helpers.rs:4499) changed from taking a caller-supplied `&GovernanceProposal` to `proposal_id: &ProposalId` + `executor_did: Option<&DID>`. Resolves authoritative proposal from `state.governance.engine.get_proposal(proposal_id)`; rejects untracked-or-not-Approved. WASM manager.rs resolves BOTH created_at AND tracked_action from its own pending/resolved maps (no action param on bridge surface). Same trust posture as #1845 (receiver-side derivation).

**Why ALIGNED:**
- ADR-031 (phase-6.md:2290) §1 engine=decision authority, sets Approved only at quorum; §4a SingleAdmin auto-approve. ADR-031 gates propose/approve/reject via UCAN but defines NO "execute capability" — execute = runtime applying already-authorized decision. Resolving action from engine = correct model enforcement.
- No convergence regression (#1865/#204/#205): executor_did still threaded Some(voter)/Some(proposer) on internal paths, None→tracked-proposer on direct. By-id change alters only HOW action+status sourced, not WHO is stamped on GovernanceActionExecuted leaf.
- By-id re-resolution sound: engine inserts on propose (governance/mod.rs:1619), NEVER evicts (no proposals.remove; status mutated in-place) → get_proposal always succeeds.
- Integration checklist complete: runtime fn → actor handler → 4 bridges (PyO3/UniFFI governance_execute, NAPI context_execute_governance_action, WASM context_execute_governance) → 4 SDK wrappers (Py/Swift/Kotlin/TS, all by-id) → pipeline_wiring.rs positive assertions (closed-by-construction: assert sig has proposal_id:&ProposalId + body calls engine.get_proposal; WASM has no action_json) → capability matrix notes updated.
- No-migration honored (caller-proposal shape deleted, no shim). action_json survives ONLY on propose surface (correct — quorum-gated creation).
- KATs genuine: scp-testing fullstack_direct_execute_rejects_forged_proposal_and_applies_no_change + ..._genuine_runs_once_then_replay_rejected; per-bridge forgery/replay (PyO3, WASM trio, native integration). Forgery asserts NO GovernanceActionExecuted leaf minted.

**FINDING (Low, ALREADY REMEDIATED):** at c9db30486, executor_did doc (~line 4509) cites `ADR-051 §6` — ADR-051 DOES NOT EXIST in .docs/ = phantom provenance. BUT pre-existing pattern (parent a632c731a had 6 ADR-051 refs in same file); later branch commits removed ALL of them (HEAD b321248e1 count=0). Valid cites ADR-031 §8 / spec §7.3.1 present.

**OBSERVATION (non-blocking):** all 4 bridges DID-validate `identity_did` but it is NOT forwarded to runtime / NOT used for caller capability check; executor stamped from tracked proposal's proposer. NOT a regression (parent had no caller check, was full-forgery-worse). Defensible (execution applies already-quorum-approved decision; replay protection = caller can trigger once, can't change outcome). Worth a doc note or defense-in-depth membership check.

GOTCHA: this branch's working tree / HEAD is AHEAD of the review-target SHA — always read the specified commit blob with `git show <sha>:<file>`, and re-check whether findings at the SHA are already fixed downstream before reporting as live.
