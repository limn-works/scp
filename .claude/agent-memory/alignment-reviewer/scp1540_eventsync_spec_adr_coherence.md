---
name: scp1540-eventsync-spec-adr-coherence
description: SCP-1540 sync/equivocation clarification review — spec §23 + ADR phase-6 catch-up = relay backfill + local consistency proof, NOT peer event-range wire msg; equivocation = inclusion proofs NOT majority. Removed unimplemented EventSyncRequest/Response structs.
metadata:
  type: project
---

# SCP-1540 Sync/Offline Catch-up + Equivocation Spec/ADR Coherence Review — APPROVE

Reviewed an UNCOMMITTED 2-file doc change in worktree `agent-ab493dd5e2689e3a6` (branch `worktree-agent-ab493dd5e2689e3a6`): `.docs/specs/23-sync-and-offline-strategy.md` (+8/-? small) + `.docs/adrs/phase-6.md` (-19 net, struct block removed).

**Reading A (already-approved decision) propagated:** catch-up "Behind" = relay Phase-1 backfill (`SUBSCRIBE` with `since`, §23.3 / ADR-004) + MLS receive-path auth (per-event sig §23.13¶1, sequence ordering ¶3, prev_hash chain ¶5) + LOCAL Merkle `verify_consistency` (RFC6962 §2.1.2, prefix proof) gated via `ct_eq` against the single already-authenticated signed `ConsistencyCheckpoint` (§23.12/§9.9.3). NO event-range wire message, NO peer-supplied proof. Equivocation (Divergent) = inclusion proofs, NOT majority vote.

**Verdict: APPROVE. 0 blocking, 0 material, 1 informational.**

## What I verified (all PASS)
1. **Struct removal safe.** `git grep EventSyncRequest|EventSyncResponse -- crates/` = ZERO consumers (exit 1). Never in §23.16 wire-format catalog (only CommitRangeRequest/Response there, which are epoch-keyed). `EventSyncResult` (local return type of `sync_event_log`) KEPT (phase-6.md:1617). Removal aligns ADR to upstream spec, not deleting a real wire format.
2. **Faithful propagation, one story.** Worktree scan: zero residual "majority"/"more members"/"event range recovery"/"EventSync struct" contradictions. All "majority" hits are corrective ("NOT a majority vote") or unrelated conflict-resolution principle (§23.6 "two or more members"). §23.7 step3, §23.13 ¶4+¶7, ADR step3+step4+module-table+`sync_event_log` bullets all coherent with §9.9.3 and security-model §9 line 336 (the authoritative source: consistency proofs = same-log catch-up; inclusion proofs NOT majority = cross-member equivocation).
3. **Step-4 equivocation correction is ADDITIVE, correct per §9.9.3.** §9.9.3 "Sybil-amplified equivocation defense" literally: "The Relay Consistency Protocol is NOT a majority vote. ANY divergence between ANY two honest members detects equivocation." Old "prefer event chain signed by more members" was a genuine DOWNSTREAM contradiction of upstream §9.9.3 — fix brings ADR/spec into line with upstream. Not a weakening.
4. **All cross-refs resolve.** §23.13 ¶1/¶3/¶5 paragraph citations exact (sig / sequence / prev_hash). §23.3+ADR-004 = relay store-and-forward backfill. ADR-011 = Merkle log. §23.16.2 CommitRangeRequest = epoch-keyed (from_epoch/to_epoch) MLS-Commit catch-up — genuinely distinct from event-log recovery; ADR's "MUST NOT be conflated" note is an IMPROVEMENT over old ADR step3 which conflated them ("CommitRangeRequest-style event range requests"). ADR "CommitRangeRequest (above)" resolves (defined ADR:1332/1361, above step3:1467).

## Informational (non-blocking)
- Spec §23.13 ¶4 still opens "If the backfill yields events with gaps..." then says "client MUST obtain the missing events via the Phase 1 relay backfill" — the gap-fill path is now ALSO relay backfill (same source that produced the gap). Logically the SDK retries/extends the `since` window; text is correct but a one-clause "retry/extend the backfill window" would make the same-source retry fully explicit. Pure clarity, not a contradiction.

## REVIEWER TRAP I HIT (lesson)
Changes were UNCOMMITTED in a WORKTREE. My first `git -C <worktree> diff` was correct, but I then ran greps with `cd /Users/alec/Developer/limn/scp` (the MAIN repo, branch `fix/sdk-coverage-fail-closed-and-parity`) which has NO changes to these files — so greps showed OLD text and looked like residual contradictions. `git status --short` returning EMPTY in main was the tell. ALWAYS run every verification grep with `cd <worktree>` (or `git -C <worktree>`), never the parent repo path. Matches existing memory `feedback_reviewers_check_branch`.
