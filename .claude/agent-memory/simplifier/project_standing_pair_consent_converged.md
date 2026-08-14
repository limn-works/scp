---
name: standing-pair-consent-converged
description: §5.15.8 standing-pair consent model (spec/05-contexts.md) reached simplification convergence — no machinery growth, prose-alignment only
metadata:
  type: project
---

Branch `spec/standing-pair-not-a-saga-v2` (.docs/specs/05-contexts.md §5.15.8 + §5.12.2 provenance note) reached simplification convergence as of HEAD c81fcce95 (2026-06-24).

**Fact:** The consent model is "standing pair is NOT a saga" — async MLS create, consent-on-receipt gate, no saga journal / no secret_bearing apparatus. Convergence resolution = "did_lo's group survives; did_hi joins-then-destroys its orphan." Threat material + normative operational contracts live under one `#### Threat model and operational contracts` fence (renamed from the misleading `Threat-model residuals (reference)`).

**Why:** A multi-revision review loop was watched for non-convergence (over-engineering / ever-growing denylist / redundant enforcement). The recent commits added ZERO new machinery — they only (a) aligned all 6 did_hi convergence restatements to join-then-destroy ordering, (b) renamed the mislabeled fence so normative MUST-blocks under it aren't read as skippable "(reference)", (c) clarified Explicit→KnownDid provenance and ADR-049 §10 auto-revive cites. Prose-alignment is convergent, not the non-convergent denylist-growth pattern simplifier exists to block.

**How to apply:** If asked to re-review this spec, the simplification verdict is SHIP-READY; do not re-litigate the consent architecture. Only flag if a FUTURE edit adds new gates/limiters/state-machine machinery rather than tightening prose. The prose density is high but inherent to the adversarial threat-model domain — not over-engineering.
