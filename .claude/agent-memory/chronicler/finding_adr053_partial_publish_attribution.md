---
name: finding-adr053-partial-publish-attribution
description: ADR-053 (pre-rotation substrate isolation) rename + the §9.12-vs-§9.7.4.1 attribution slip found in its review
metadata:
  type: project
---

ADR-053 = "Pre-Rotation Key Custody — Substrate Isolation for Callback Custody" (Proposed, Phase 6). Standalone file `.docs/adrs/ADR-053-pre-rotation-custody-substrate-isolation.md`.

**Rename:** originally drafted as ADR-051, renamed to ADR-053 on branch `fix/sdk-coverage-fail-closed-and-parity` (commit 660eac83f) because ADR-051 was already taken by `ADR-051-causal-dag-application-event-ordering.md`. Several agent-memory notes (chronicler/api-design/cryptographer) still say "ADR-051 pre-rotation" — those are stale; the artifact is ADR-053.

**Finding (review 2026-06-22) — RESOLVED:** ADR-053 line 49 formerly mis-attributed the spec paragraph titled "Partial-publish recovery" to **§9.12**. Fixed on branch `fix/sdk-coverage-fail-closed-and-parity` (commit `06d15bb6a`): both line 49 AND line 86 now cite **§9.7.4.1**, consistent with each other and with the spec. Paragraph confirmed at `09-security-model.md:696`, under header `### 9.7.4.1` (:655), before `## 9.8` (:698). The remaining §9.12 refs in ADR-053 (lines 6, 10, 25) are correct & intentional (§9.12 = Compromise Recovery Protocol, distinct from the partial-publish paragraph). RE-VERIFIED APPROVED 2026-06-22 @ HEAD 06d15bb6a.

**Lesson consolidation (same branch):** branch now carries **4** lesson files, not 5. `coverage-gates-must-fail-closed.md` absorbed the former `fail-closed-gate-escape-hatch-must-be-verified` + `suffix-matcher-becomes-bypass-when-gate-fails-closed` content; `cross-sdk-method-naming-matches-canonical-sdk` also absent. The 4 current files: `coverage-gates-must-fail-closed.md`, `fromhandle-must-surface-all-protocol-significant-fields.md`, `identity-migration-cite-9.12-not-3.2.1.md`, `mock-test-must-not-invert-real-bridge-behavior.md`. All cross-ref links resolve (no dead links). CLAUDE.md enforcement list gained `scripts/check-sdk-coverage.py` (:111).

**Why:** the named paragraph is structurally §9.7.4.1; §9.12 is the general Compromise Recovery Protocol. Precise attribution matters for provenance.

**How to apply:** when reviewing ADR-053 cross-refs, the "Partial-publish recovery" paragraph = §9.7.4.1, NOT §9.12. The general migration discussion = §9.12. Spec anchors confirmed: §3.2.1 custody-migration (`03-identity.md:20`, DID-preserving), §9.12 (`:1150`), §9.7.4.1 (`:655`, items 1-7).
