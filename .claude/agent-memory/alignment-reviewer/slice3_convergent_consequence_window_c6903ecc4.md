---
name: slice3-convergent-consequence-window-c6903ecc4
description: Slice 3 (PR #1859) convergent consequence evidence-window @ c6903ecc4 off clean base 1f1ea7cd2 — ALIGNED, 0 blocking findings
metadata:
  type: project
---

# Slice 3 — convergent consequence evidence-window (PR #1859) @ `c6903ecc4` — ALIGNED, 0 findings

Worktree `/Users/alec/Developer/limn/scp/.claude/worktrees/slice3-consequence-window`. Merge-base==1f1ea7cd2 (true PR base, 3 commits ahead, NO phantom-deletion trap — unlike the Slice-2 worktree-behind-main gotcha). 10 files +311/-66.

**What it does:** Adds a `convergent_now` 5th param to `evaluate_consequence_rules` so convergent-trigger consequence rules (`WarningCount`, `Custom` — the ones that mint a durable `ConsequenceTriggered` Merkle leaf) anchor their evidence window on `[convergent_now - window, convergent_now]` instead of the evaluating member's skewed local `now`. Non-convergent triggers (`MessageVelocity`, `ToolRateExceeded` — local flow control, no durable leaf) keep the local `now` window. This makes the durable leaf byte-identical across honest members with skewed clocks → eliminates a false-positive §9.9.3 equivocation (Relay Consistency Protocol equal-count/equal-root) against honest members.

**Why ALIGNED (the convergent-annotation-fix checklist from convergence_three_slices memory):**
1. `convergent_now` = max timestamp of **Source-1 durable log entries**, computed in `event_log_entries_for_consequences` (governance_logic.rs:~668) BEFORE the buffer merge — NOT from merged set (which mixes Source-2 buffer events with local-clock estimated ts), NOT from local clock. Empty-log fallback = `now` (sound: no convergent-trigger evidence exists to anchor). Anchor from Source-1 only ✓.
2. Every caller threads the real value: ALL `evaluate_consequence_rules` consequence call sites pass `convergent_now` (signature arity change = compiler-enforced, no silent gap). Participation-record-only callers correctly discard with `_convergent_now` (governance_helpers 3182/4407, lifecycle_logic 247). ✓
3. WASM converges: `crates/scp-ffi/wasm/src/consequence.rs:~90` computes `convergent_now` identically (max `ctx.event_log_events()` ts before merge, `now_secs` fallback) → byte-parity with native. ✓
4. Downstream convergence helpers UNCHANGED: `convergent_consequence_timestamp`, `matches_trigger`, `merge_consequence_events` not edited (diff hunk-headers only). `is_convergent_trigger` is PRE-EXISTING const fn (base line 143) — consumed not redefined. Anchor-only change. ✓

**Tests:** positive `convergent_window_anchor_converges_under_skewed_local_clocks` (same events, now_a=1000 vs now_b=1250, same convergent_now → result_a==result_b, same leaf ts) + non-vacuous negative control `convergent_window_skewed_anchor_diverges` (event ts=1100 between skewed anchors → one member triggers, other doesn't → assert_ne). `TriggeredConsequence` gained `PartialEq, Eq` for the equality asserts.

**Accepted limitation (NOT a blocker — task pre-disclosed, tracked #1861):** SECURITY block in governance_logic.rs honestly + COMPLETELY discloses BOTH forgery directions: committer-assigned (proposer-chosen, signature-bound but not future-bounded) leaf timestamps mean a malicious admin/quorum could (amplification) future-date to widen window & mint a consequence, OR (suppression) push max ahead so window_start slides past genuine older evidence to evade one. Same root, same deferred fix = convergent-wall-clock RFC (BFT median-time/accountability). Explicitly justifies NOT applying a local-clock ceiling (would reintroduce the divergence this fix removes — consequence outcome is a convergent durable leaf, not a local app gate). Two doc commits (5f548c0b6 record limitation, c6903ecc4 add suppression direction per review) are pure additions to that block.

**Artifact-flow integrity:** no `#NNNN` issue refs in source (#1861 tracking lives outside code per feedback_no_issue_refs_in_code). §9.9.3 = Relay Consistency Protocol/equivocation — the exact property protected. `cargo check -p scp-protocol` clean. Scope honest: evidence-window anchor only, no scope creep.
