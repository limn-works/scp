---
name: pr1875-ucan-ceiling-all-attestations
description: PR #1875 docs-only UCAN step-8 ceiling reword (all attestations, not invoked-only); ALIGNED with one stale-duplicate finding in phase-2.md:406
metadata:
  type: project
---

# PR #1875 `docs/ucan-ceiling-all-attestations` @ `dca0bcce9` (2026-06-22) — ALIGNED w/ 1 finding

DOCS-ONLY. Rewords UCAN pipeline **step 8 (Ceiling)** so the immutable capability ceiling is enforced over the token's **entire `att` attestation set**, not only the invoked capability. A token carrying ANY out-of-ceiling attestation is rejected even if the invoked capability is in-ceiling.

**Touched (4 locations, all consistent):**
- `.docs/specs/07-trust-validation-and-capabilities.md` §7.2.1 step 8 (the 11-step list) — updated
- same file §7.2 Layer-1 ASCII box — "Capability ceilings enforced over every attestation in a token" (line wrapped to 2 lines)
- same file role-assignment bullet — added "same all-attestations rule applies at mint time AND presentation time (step 8)"
- `.docs/adrs/phase-3.md` ADR-016 step 8 (line 748) — updated

**Artifact-flow: CORRECT.** Upstream spec clarification, not a new ADR. Tightens an existing step's scope; adds/reorders NO steps; stays within Layer-1 "100% validation / 0% trust / ceilings enforced" intent. Spec-clarification (not new ADR) is the right vehicle.

**Box formatting: INTACT.** Box was ALREADY ragged on main (line widths 63-65, not monospace-perfect). Wrapped line split one 63-wide line into two 63-wide lines, both start+end with `│`. No worse than surrounding box.

**FINDING (material, doc-consistency): `.docs/adrs/phase-2.md:406` left stale.**
ADR-009 (phase-2.md) carries a SECOND parallel restatement of the same 11-step pipeline. Its step 8 (line 406) STILL says old semantics: "Verify `required_capability` is within the context's immutable capability ceiling." Now contradicts §7.2.1 + ADR-016. NOT touched by PR.
- MITIGATION: phase-2.md:398 explicitly says "ADR-016 is the normative specification" — so ADR-009's list is self-declared non-normative restatement. Severity softened but still real phantom-provenance risk (an implementer reading ADR-009 step 8 gets the old rule). Should be fixed for consistency per CLAUDE.md completeness tenet.
- `check_ceiling(ceiling, capability) -> bool` helper at phase-2.md:422 takes a single capability — NOT contradictory (lower-level helper, callable per-att). Leave as-is.
- phase-3.md:681 ("a UCAN chain that grants a capability outside the ceiling is rejected") is ALREADY consistent — no change needed.

**Downstream readiness: UNAMBIGUOUS.** "every capability the token grants... entire attestation set (`att`) is checked" = clear instruction to core: iterate parsed `att` entries, reject if any is out-of-ceiling.

**GOTCHA (recurring):** grep over working tree hit `07...md:80` with OLD text because working tree is on a feature branch (`feat/actor-2c-xctx-tool-saga`), NOT the PR branch. Always `git show origin/<branch>:<file>` to read the actual branch content. Reviewers read working tree by default.
