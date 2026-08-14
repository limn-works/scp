---
name: defensive-code-standard-2026-07-03
description: Interrogation of the loop-scar-tissue / defensive-code.md guard change (invariant #9); where the trust-boundary carve-out is sound vs. fuzzy
metadata:
  type: project
---

Interrogated uncommitted change on branch worktree-harness-loop-guards (2026-07-03): new
`.docs/standards/defensive-code.md`, architecture.md §2.5.4 invariant #9 "Invalid states are
unrepresentable, not defended against", lesson `loop-scar-tissue-defensive-accretion.md`,
cross-refs in construction.md/sdk-common.md/rust.md, CLAUDE.md change-protocol additions, and
charter additions to simplifier/bug-catcher/inquisitor.

**Why:** guards against loop-driven defensive-code accretion (Ronacher "The Coming Loop").

**Verdict:** premise 1 HOLDS (failure mode real; strongest in-repo evidence is doc/gate
accretion, corroborated for defensive code by PR #1850 removing a divergence_marker untrusted
fallback). Premise 2 mostly HOLDS — the codebase's deliberate defense-in-depth is
OVERWHELMINGLY fail-closed-with-typed-error, which §2/§3 explicitly BLESS (not condemn). The
genuine friction is narrow: §5 "two guards for the same invariant is one too many" is in
tension with deliberately-kept belt-and-suspenders re-validation (lifecycle_helpers.rs
~1796/~2443 ceiling re-check for the in-memory import entry point). "Trust boundary" is
defined by enumeration but has a fuzzy edge: §1 "FFI/SDK arguments from host application" vs
§4 "producer in another module/crate is NOT a trust boundary" — an already-typed in-memory
`ContextExport`/`ContextSnapshot` sits exactly on that seam.

**Key structural finding:** the change adds "Defensive ADDITIONS" PR-section legibility but has
NO symmetric guard against a fix pass DELETING a legitimate fail-closed check while citing
invariant #9. The new failure mode (agent deletes a real guard) is under-guarded at the same
fuzzy edge.

**Altitude:** no ADR; principle lives as an architecture invariant + standard. Rejected
alternative (denylist gate) IS recorded in §7 + lesson, coherent with the pre-existing
over-engineering / non-convergent-enforcement guardrail already in CLAUDE.md. §7 clippy claim
verified TRUE (Cargo.toml:103-105 deny unwrap_used/expect_used/panic); the rule correctly
targets the gap clippy leaves (unwrap_or_default/.ok() are NOT clippy-linted).

**How to apply:** if this lands, watch future PRs for (a) §5 being wielded to delete
belt-and-suspenders re-validation at in-memory import boundaries, and (b) invariant #9 cited to
justify removing a fail-closed check. Both are the predicted misreads.
