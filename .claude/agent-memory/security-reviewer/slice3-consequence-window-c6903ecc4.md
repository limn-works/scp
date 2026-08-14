---
name: slice3-consequence-window-c6903ecc4
description: Slice 3 PR#1859 convergent consequence evidence-window review — CLEAN, no new findings
metadata:
  type: project
---

# Slice 3 — convergent consequence-window (PR #1859, HEAD c6903ecc4, base 1f1ea7cd2)

CLEAN. No NEW blocking findings. Reviewed `git diff 1f1ea7cd2..HEAD` (10 files, +311/-66).

**Why:** Phase-2 substrate-swap follow-up. Fixes §9.9.3 false-positive equivocation: prior
consequence evidence window keyed on evaluating member's LOCAL clock `now`, so skewed honest
members selected different evidence subsets of the same convergent events → divergent durable
`ConsequenceTriggered` Merkle leaves.

**How to apply:** Reference when reviewing future convergent-window / consequence / §9.9.3 work,
or the open #1861 forgery follow-up.

## The change
`evaluate_consequence_rules` gains `convergent_now` param. Window anchor splits on
`is_convergent_trigger`: convergent (`WarningCount`/`Custom`) → `[convergent_now-window, convergent_now]`;
non-convergent (`MessageVelocity`/`ToolRateExceeded`) → local `[now-window, now]`.
`convergent_now = max(Source-1 durable log ts)` computed in `event_log_entries_for_consequences`
(governance_logic.rs:660) BEFORE buffer merge — never from merged set (which carries Source-2
buffer local-clock estimated ts). WASM parity: consequence.rs derives from `ctx.event_log_events()`
= `self.event_log.events()` (same `scp_event_log::Event` stream). Empty-log fallback = `now`.

## Verified sound
- convergent_now source = Source-1 only, pre-merge → not skew-dependent. Native + WASM byte-identical.
- Durability gate (consequence.rs:1253 `durable: is_convergent_trigger`) is INDEPENDENT of anchor →
  non-convergent triggers NEVER mint durable leaf regardless of window. Disclosure claim accurate.
- All callers thread anchor with the SAME-call events set; 3 participation-only paths discard as
  `_convergent_now` (correct — participation consumes no anchor). cargo check -p scp-protocol clean.
- Tests: convergent_window_anchor_converges_under_skewed_local_clocks (TriggeredConsequence now
  PartialEq/Eq) + non-vacuity control convergent_window_skewed_anchor_diverges.

## KNOWN/ACCEPTED (do NOT re-raise) — #1861
Committer-assigned (proposer-chosen, NOT future-bounded) Source-1 leaf timestamps → window anchor is
CONVERGENT but not NON-FORGEABLE. Malicious committer/quorum can future-date governance actions in
BOTH directions: amplification (widen window to mint false consequence) / suppression (push max ahead
so window_start slides past earned evidence to evade one). Admin/quorum-gated, signed, attributable.
Deferred to convergent-wall-clock RFC (#1861). Local-clock ceiling deliberately omitted (would
reintroduce the §9.9.3 divergence the fix removes). Disclosure at governance_logic.rs:640-659 covers
BOTH directions (c6903ecc4 added suppression per review). Complete + accurate.
