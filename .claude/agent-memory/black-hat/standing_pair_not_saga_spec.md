---
name: standing-pair-not-saga-spec
description: Adversarial review verdict on spec/standing-pair-not-a-saga-v2 (05-contexts §5.15.8 + consent allowlist-only) — no viable attack, no sibling
metadata:
  type: project
---

Branch `spec/standing-pair-not-a-saga-v2`, HEAD `aaa4e1460` (docs-only). Reviewed 2026-06-24.

**Verdict: no viable attack, no remaining sibling.** Consent model is closed by construction.

What the branch does:
- Recategorizes standing-pair creation as single-context async creation, NOT a cross-context saga (ADR-049 §3/§3a, specs 05/09, sdk-common). 3 sagas → 2 (tool-invoke §6.2.4, broadcast-host §5.14.13).
- Hardens auto-accept to **allowlist-only**: drops `SharedContext`/`Any`/`discovery_context` arms. `known_did` is the SOLE trigger. Default-deny (no default policy). Co-membership + discoverability explicitly NOT trust signals. No self-clear path on allowlist.
- §5.15.8 standing-pair: default-deny non-overridable (memory_scope:full); allowlist-or-prompt.
- Adopts §9.5.1 length-prefix for `derived_context_id` → injectivity unconditional, retires colon-freedom dependence. §3.8.1 canonical-DID is now agreement-only.

HEAD one-liner: re-attributes the orphan-destroy in the `did_lo`-ignores bullet (05-contexts §5.15.8 ~line 1848) from ambiguous "its later destroy" (grammatically `did_lo`, WRONG — survivor never destroys) to "**`did_hi`'s later destroy of that orphan**". Correct: `did_hi` destroys its own self-created orphan group; `did_lo` (survivor) never observes/destroys. Verified consistent with line 1849 (`did_hi` "destroys its self-created group"), line 1855 (convergence-window: "`did_hi` party joins `did_lo`'s group, then destroys its orphan"), line 1887 (get-or-create residual: same). NO regression — pure clarity-correctness fix.

Collision-resolution invariant (§5.15.8) sound: `{id-agreement(a0) → block-list → confirm-bound-creator(§9.7.1 BOTH cred.did==did_lo AND sig-key resolves in did_lo DID doc) → fresh-join(consumes single-use init key) → destroy}` atomic under per-context actor mutex + generation check. Forecloses forged-creator DoS, replayed-Welcome stale-destroy, confused-deputy recreate-then-destroy. Survivor (did_lo) ignore-rule local-only.

Honestly-disclosed residuals (bounded, NOT silent joins): (1) reflected-resolution DoS — off-path party who knows both DIDs forges convergence-candidate Welcomes (id publicly computable), forcing 1 un-throttled DID-resolve+sig-verify each, no join/state/fan-out; (2) fresh-DID fleet = N approval-prompts (not N joins), bounded by §9.3 minting cost. Both acceptable per spec.
