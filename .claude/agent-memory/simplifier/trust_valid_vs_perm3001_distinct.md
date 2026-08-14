---
name: trust-valid-vs-perm3001-distinct
description: evaluateLayer1's VALID-* and PERM-3001 catch arms must stay separate; do NOT unify them despite a coincidental same result
metadata:
  type: project
---

In `bindings/typescript/src/trust.ts` `validateOneCapUri` (and Python `evaluate_trust`), the error handler has two distinct absorb arms that look unifiable but MUST stay separate.

- `[SCP-PERM-3001]` arm → routes through `__classifyUcanError` → `__PASSED_BEFORE`, yielding a PARTIALLY-true narrowed verdict (e.g. expiry failure leaves tokensValid/signaturesValid/withinCeiling/nonceValid/notRevoked = true).
- `[SCP-VALID-*]` arm → returns `ALL_LAYER1_FIELDS_FALSE` (the URI was rejected pre-flight, before the pipeline ran — nothing passed).

**Why:** A VALID-* message fed to `__classifyUcanError` would fall through to `"unknown"` → empty set → all-false, numerically identical to the explicit constant. This makes "just route VALID-* through the classifier too" look like a clean dedup. It is a trap: it works only by the coincidence that VALID-* text matches no UcanError prefix, couples boundary semantics to a non-collision, and erases the categorical distinction (pre-pipeline rejection vs in-pipeline failure).

**How to apply:** If a future PR proposes collapsing these two arms (or removing the explicit VALID-* branch), push back — the extra branch is the simpler-to-reason-about code. The 3-arm shape (two positive `if` on a closed code allowlist, then `throw`) is correct. Related: [[trust_ucan_error_classifier_not_a_gate]] (the prefix lists are bounded refinement, not a non-convergent gate).
