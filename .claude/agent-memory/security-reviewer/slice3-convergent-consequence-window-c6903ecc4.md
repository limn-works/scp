---
name: slice3-convergent-consequence-window
description: Slice 3 PR#1859 convergent consequence-window anchor fix (c6903ecc4) — CLEAN, no new blocking findings
metadata:
  type: project
---

# Slice 3 — Convergent consequence-window anchor (PR #1859, HEAD c6903ecc4)

Worktree slice3-consequence-window, base 1f1ea7cd2 (Phase-2 substrate swap). 10 files, +311/-66.

## Change
`evaluate_consequence_rules` gains `convergent_now: u64`. Evidence window anchor now splits on
`is_convergent_trigger`: convergent triggers (WarningCount, Custom) anchor on `convergent_now`
(window `[convergent_now-window, convergent_now]`); non-convergent (MessageVelocity, ToolRateExceeded)
keep the local-clock `now`. `event_log_entries_for_consequences` now returns `(merged, convergent_now)`
where `convergent_now = max(Source-1 durable log timestamp)` captured BEFORE the buffer merge
(fallback `now` on empty log). Fixes §9.9.3 false-positive equivocation: skewed honest members
previously selected different evidence subsets of the same convergent events → divergent durable leaves.

## Soundness verification (all confirmed clean)
- Convergent triggers match ONLY GovernanceAction events. Source-2 buffer contributes ONLY MessageSent
  (merge_consequence_events `_ => continue` for all convergent types). So NO Source-2 local-clock
  timestamp can become convergent-trigger evidence — anchor on Source-1 max is exact.
- All ~8 prod callers pass convergent_now from the SAME event_log_entries_for_consequences call that
  produced events (or, WASM, from ctx.event_log_events() Source-1 max before merge). None missed; none
  feed merged-set timestamps into the anchor. Participation-record paths correctly discard `_convergent_now`.
- WASM mirror byte-identical to native: convergent_now from event_log_events() (same slice passed as
  log_entries to merge), same `now`-fallback on empty.
- convergent_consequence_timestamp draws max-by-sequence from evidence (convergent-only on durable path).
- TriggeredConsequence gains PartialEq/Eq for the new convergence pin test. Non-vacuity control test
  (skewed-anchor diverges) proves convergence comes from shared anchor, not vacuously.

## Accepted/known limitation (NOT a new finding)
Source-1 leaf timestamps are committer-assigned (proposal.created_at, signature-bound but proposer-chosen,
NOT future-bounded). Malicious quorum can future-date in EITHER direction (amplification: widen window to
sweep extra evidence; suppression: push max ahead so window_start slides past genuine older evidence).
Admin/quorum-gated, signed, attributable. KNOWN, accepted, documented (governance_logic.rs SECURITY
comment covers BOTH directions), tracked #1861. Local-clock ceiling deliberately NOT applied (would
reintroduce divergence). Disclosure is complete and accurate. Do NOT re-raise.

## Verdict: CLEAN — zero new blocking findings.
