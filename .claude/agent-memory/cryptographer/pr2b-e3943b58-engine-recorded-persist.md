---
name: pr2b-e3943b58-engine-recorded-persist
description: #1900 PR-2b final commit e3943b58 — WASM persists engine's get_proposal read-back verbatim instead of optimistic push; GO. Closes past-deadline phantom-vote divergence.
metadata:
  type: project
---

# #1900 PR-2b e3943b58 — engine-recorded proposal persistence (GO)

Delta `git diff f4e4d7c52 e3943b58`: ONLY wasm/manager.rs + scp-runtime/tests/wasm_conformance.rs. **scp-protocol / ingest_proposal / signed path / import invalidation UNTOUCHED** — prior GO on those stands.

**Why:** Change `decide_vote_via_engine` to return `(ProposalStatus, GovernanceProposal)` where the GovernanceProposal is `engine.get_proposal(&pid).cloned()` (the engine's authoritative record), and have propose/approve/reject persist THAT verbatim into `pending_proposals` instead of `approvals.push(new_vote)`. Past-deadline majority: `MajorityVoteEngine::precheck_vote` returns `Resolved(self.resolve(...))` BEFORE `push_and_resolve` — auto-resolves WITHOUT recording the late vote (majority.rs precheck ~L148-149; push_and_resolve does the .push at ~L190-192). The old optimistic push recorded a phantom uncounted vote → native↔WASM vote-vector divergence. Now byte-identical.

**How to apply (crypto soundness — all 3 questions GO):**
1. **Keyless trust model preserved.** Seed = WASM's OWN stored proposal (ctx.pending_proposals, empty-sig votes WASM authored under the existing ADR-034 keyless boundary). `ingest_proposal` seeds verbatim but ENFORCES eligibility(proposer∈frozen set)+uniqueness+status-verbatim (terminal stays terminal → next vote ProposalNotPending). `get_proposal` = pure `self.proposals.get(pid)` read of the engine's OWN counted state (majority.rs:630, mod.rs default 1914). No attacker vote/status enters via read-back that wasn't already (a) in WASM's stored proposal under existing trust model or (b) deterministic engine tally output. Empty-sig votes no more "verified" than before — delta does NOT widen the no-verify boundary; it NARROWS divergence.
2. **Execute gate engine-driven, not vote-vectors.** `meets_quorum = matches!(post_status, ProposalStatus::Approved)` (manager.rs 5777 propose, 5929 approve) — post_status is the engine RETURN value. Stored status set Approved only on that. `execute_governance_action` top: `require_proposal_approved` (reads stored status field). Replay guard = `canonical_replay_key_for_tracked` = SHA-256(context_id, proposer, JCS(action), created_at) = canonical compute_proposal_id, NOT caller hex id → no double-execute via fresh id. Action resolved from TRACKED proposal, never caller-supplied. Persisted engine_proposal feeds only display (get_proposal JSON) + next-engine re-seed (ingest_proposal), NOT the execute decision.
3. Delta clean per name-only + `git diff -- crates/scp-protocol` empty.

**Validation strength:** conformance test `wasm_keyless_ingest_matches_native_past_deadline_majority_vote_sets` (wasm_conformance.rs:762) is an ORACLE test — runs native SIGNED engine + keyless ingest through same past-deadline scenario, asserts `native.get_proposal(pid)` == `wasm.get_proposal(pid)` for status + approvals.len + rejections.len. Plus pr2b_normal_approve_records_exactly_one_additional_vote pins the happy-path (in-window vote DOES count, grows 1→2).

GOTCHA: worktree Read tool returned STALE/mismatched manager.rs content (offsets landed in wrong section); HEAD was clean at e3943b58. Use `git show e3943b58:<path>` for authoritative reads in this worktree.

Known pre-existing/filed (do NOT re-raise): #1926, #1927.
