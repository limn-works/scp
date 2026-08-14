---
name: pr1900-pr2b-engine-proposal-persist-e3943b58
description: #1900 PR-2b WASM commit e3943b58 — persist engine-recorded proposal so past-deadline votes converge with native; ALIGNED
metadata:
  type: project
---

# #1900 PR-2b WASM vote-vector convergence @ `e3943b587` (2026-06-28) — ALIGNED

Single commit on top of [[pr1900_pr2b_wasm_quorum_final_f4e4d7c52]]. manager.rs (+) / wasm_conformance.rs (+140). 0 findings.

**The fix:** WASM vote endpoints (`propose_governance_action`, `approve_governance_proposal`, `reject_governance_proposal`) now PERSIST the engine's authoritative read-back proposal (`engine.get_proposal(&pid).cloned()` via new `TransientGovernanceEngine::get_proposal`) verbatim into `pending_proposals`, instead of optimistic `approvals.push(new_vote)` + `status = post_status`. `decide_vote_via_engine` return type changed `ProposalStatus` → `(ProposalStatus, GovernanceProposal)`.

**Why it converges (engine layer, verified):** native `approve`/`reject` (majority.rs:424-426/517-519) AND keyless `precheck_vote` (majority.rs:379-383, via `ingest_approve`) share the SAME past-deadline branch: `context.now >= voting_deadline` → `self.resolve(...)` returns WITHOUT pushing the vote; `push_and_resolve` never runs. `get_proposal` (majority.rs:595 = `self.proposals.get`) returns only pre-deadline votes on BOTH paths. native reads `engine.get_proposal` as its truth → byte-identical stored vote sets + status, late vote in NEITHER.

**Identity fields safe:** `ingest_proposal` (majority.rs:780) stores VERBATIM; engine only mutates approvals/rejections/status. created_at/proposer_did/action/voting_deadline/created_at_epoch unchanged. Normal-path vote byte-identical: `build_unsigned_vote` (mod.rs:927) = `{voter, vote, timestamp:now, sig:empty}` == old optimistic push (governance_context_for_engine stamps now=now_secs).

**Leaf parity preserved:** NO `append_log_event` / `GovernanceVoteCast`(b"") / `GovernanceProposalCreated`(b"") / `GovernanceActionExecuted` buffer-event touched. Only in-memory `pending_proposals` storage mechanism changed.

**Test:** `wasm_keyless_ingest_matches_native_past_deadline_majority_vote_sets` non-vacuous: seeds native+keyless engines identical (1 approve/0 reject/3 voters/5000bps), bob votes past deadline each, asserts status eq + approvals.len==1 both + rejection len eq + approver DID sets byte-identical. Participation 1*10000/3=3333<5000 → Rejected{InsufficientParticipation}. VERIFIED: conformance test passes (`--features testing`), all 16 `pr2b_*` wasm unit tests pass (incl new normal-approve-records-exactly-one + past-deadline assertions), wasm32 clippy clean.

**Hygiene:** no `#NNNN` in source. Gaps #1925/#1926/#1927 verified OPEN — tracked, not re-raised.

GOTCHA: worktree `1900-pr2b-wasm` HEAD WAS e3943b58 despite stale git-status snapshot showing branch `wasm/1877-slice1...`; `git log --oneline -2` confirmed. Run scp-runtime conformance with `--features testing` (target requires it).
