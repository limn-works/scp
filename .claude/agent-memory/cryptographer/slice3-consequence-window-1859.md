---
name: slice3-consequence-window-1859
description: Slice 3 / PR #1859 convergent consequence evidence-window — SOUND review off 1f1ea7cd2..c6903ecc4
metadata:
  type: project
---

Slice 3 (PR #1859, branch slice3-consequence-window, HEAD c6903ecc4, base 1f1ea7cd2): convergent consequence evidence-window. **SOUND, no blocking findings.**

**What it does:** `evaluate_consequence_rules` gains a 5th param `convergent_now`. Window anchor splits on `is_convergent_trigger`: convergent triggers (WarningCount/Custom) use `[convergent_now - window, convergent_now]`; non-convergent (MessageVelocity/ToolRateExceeded) keep local `[now - window, now]`.

**Convergence proof:**
- `convergent_now = log_entries.iter().map(|e| e.timestamp).max().unwrap_or(now)` computed in `event_log_entries_for_consequences` (governance_logic.rs:659) BEFORE the buffer merge — Source-1 durable log ONLY, never the merged set.
- Convergent-trigger evidence (GovernanceAction bucket) comes EXCLUSIVELY from Source 1 in merge_consequence_events (consequence.rs:762-809). Source 2 buffer contributes only MessageSent (non-convergent). Clean clock-domain separation.
- Source-1 leaf timestamps are committer-assigned, byte-identical across honest members → anchor identical → window identical → evidence set identical → durable ConsequenceTriggered leaf byte-identical. Closes §9.9.3 false-positive equivocation.
- `convergent_consequence_timestamp` = max-by-sequence evidence ts; convergent because evidence is convergent.

**Caller audit (all 5-arg, verified):** messaging_helpers.rs (4 sites: 701/1850/2661/2779), tools/invoke.rs:850 (via ToolEconomyContext.convergent_now), tools_helpers.rs (reserve+settle), governance_helpers.rs:4334/4346 (proposer+target share one anchor), actor/handlers/governance.rs:792 (periodic sweep, one shared anchor over all members), wasm/consequence.rs:105 (faithful native mirror, same max-over-Source-1-before-merge). Participation-record paths (governance_helpers proposer-eligibility + finalize, lifecycle_logic.rs post_join) correctly discard `convergent_now` with `_` — it's consequence-window-only.

**Tests:** 2 new pins in consequence.rs — `convergent_window_anchor_converges_under_skewed_local_clocks` (now_a=1000 vs now_b=1250, same convergent_now=1000 → byte-identical results incl convergent_consequence_timestamp) + non-vacuity control `convergent_window_skewed_anchor_diverges` (anchor==local clock, event between anchors → diverges). Both pass. TriggeredConsequence gained PartialEq/Eq for assert_eq.

**Accepted/tracked limitation (#1861, NOT re-litigated):** Source-1 leaf ts are committer-assigned (proposal.created_at, sig-bound but proposer-chosen, NOT future-bounded). Convergent but forgeable in BOTH directions — amplification (widen window to sweep extra evidence, mint consequence vs victim) and suppression (push max ahead so window_start slides past genuine older warnings, evade own consequence). Admin/quorum-gated, attributable. Bounding non-forgeably = BFT median-time, deferred to convergent-wall-clock RFC. Local-clock ceiling deliberately NOT applied (would reintroduce divergence). Disclosure lives in governance_logic.rs:639-665 rustdoc + the two docs(trust) commits; both directions documented accurately. Same root class as ADR-051 floor-only clock work.
