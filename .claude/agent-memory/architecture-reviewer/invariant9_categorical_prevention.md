---
name: invariant9-categorical-prevention
description: Architecture §2.5.4 invariant #9 (invalid states unrepresentable) + ADR-058 + defensive-code.md — the anti-scar-tissue rule set and its two legitimate-redundancy carve-outs
metadata:
  type: project
---

Architecture invariant #9 "Invalid states are unrepresentable, not defended against" was added 2026-07-03 (branch worktree-harness-loop-guards, doc-only change).

Normative statement: `.docs/architecture.md` §2.5.4 invariant 9. Full rules: `.docs/standards/defensive-code.md`. Decision + rejected alternatives: `.docs/adrs/ADR-058-invariants-over-runtime-defense.md`. Failure mode: `.docs/lessons/loop-scar-tissue-defensive-accretion.md` (Ronacher "The Coming Loop").

**The rule:** parse-don't-validate at trust boundaries into types that exclude bad states; encode invariants in types then DELETE the runtime check; no `unwrap_or_default()`/`.ok()`-and-continue/silent-default on INTERNAL invariants (that is data-corruption-with-no-signal); fix the producer not the consumer.

**Enforcement is DELIBERATELY review-based, NOT a mechanical gate** (ADR-058 rejected-alt #1, load-bearing: a denylist scanner is unsound + non-convergent because the same spelling is mandatory at a boundary and a defect inside one). Do NOT add a gate for this.

**Two legitimate-redundancy carve-outs (NOT scar tissue, must NOT be deleted):**
1. Distinct entry paths not sharing the enforcing parse — canonical example `CapabilityCeiling::validate_entries()` at `lifecycle_helpers.rs:1807`/`:2452` (in-memory `import_context` bypasses the from-bytes validating `Deserialize`).
2. Defense-in-depth on a security-critical invariant no type can carry — authorization/capability scope, context membership, crypto well-formedness, DoS bounds. Example: `MAX_RECEIPT_BATCH` (economy/adapter.rs:231) enforced at BOTH FFI bridges (uniffi/napi/pyo3) AND supervisor chokepoint (supervisor.rs:3123).

**Charter reconciliation:** simplifier flags defensive scar tissue as BLOCKER but must respect carve-outs (over-firing is a finding against it; deleting a security control is "the security reviewers' domain"). white-hat/security-reviewer/cryptographer hold the opposite line: deleting/weakening a fail-closed control citing invariant #9 is a regression BLOCKER. PR descriptions carry symmetric "Defensive additions" + "Defensive removals" lines.

**Known latent non-compliance:** ambient `unwrap_or_default()`/`.ok()`-and-continue exist in current runtime code (the docs honestly acknowledge this). Rule is forward-looking/review-enforced on changes, not a retroactive sweep.
