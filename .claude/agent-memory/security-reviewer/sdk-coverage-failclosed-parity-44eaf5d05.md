---
name: sdk-coverage-failclosed-parity-44eaf5d05
description: Security review of fix/sdk-coverage-fail-closed-and-parity (trust.ts regex error classification, assertTestHookAllowed, coverage_exemptions gate)
metadata:
  type: project
---

# fix/sdk-coverage-fail-closed-and-parity @ 44eaf5d05 (2026-06-20)

Reviewed TS `evaluateTrust` four-layer trust model, test-hook guards, and SDK coverage gate.
Verdict: no CRITICAL/HIGH. Design is fail-closed in the security-relevant direction.

## Key facts
- `trust.evaluateTrust` is an ADVISORY public SDK API. Returns a `TrustEvaluation` to the
  app/agent. NOTHING internal consumes `capabilityValidation` for an authz decision (grep
  confirmed empty). The real enforcement is `ucanValidate` itself (Rust 11-step pipeline),
  which throws. Misclassification only mislabels a *report field*, never bypasses protocol.
- Regex `/\[SCP-PERM-\d+\]/` replaced `instanceof UcanPermissionError` because NAPI
  `ucanValidate`/`eventLogQuery` bypass `mapBridgeError` and throw plain Error. Rust
  `UcanError`→`ScpNapiError::Permission` always renders `[{code}] permission error: {Display} — {advice}`.
  If marker/regex absent → code `throw`s (fail-closed). If classified `unknown` → `__PASSED_BEFORE.unknown`
  = empty set → all 6 fields false (fail-closed/pessimistic). Optimistic-start only relaxes within
  a *matched* SCP-PERM error per sequential pipeline semantics.
- `extract_scp_code` (napi error.rs) recovers embedded `SCP-PERM-` from runtime
  `PermissionDenied(String)` catch-all. So a non-UCAN-validator runtime error CAN surface with
  `[SCP-PERM-...]`. But its Display won't match any UcanError prefix → `unknown` → all-false. Safe.
- UcanError variants NOT in TS prefix lists: `invalid capability URI:`, `revocation unauthorized:`,
  `revocation failed:`. All → `unknown` → fail-closed. (LOW: list is a denylist, not closed over the
  enum; future variants default safe but silently.)

## Findings
- LOW: `__setBridgeForTests` (internal/bridge.ts) reads `globalThis.BUN_TEST`; `assertTestHookAllowed`
  (scp.ts) reads `process.env.BUN_TEST`. Bun sets the env var, not the global → former's BUN_TEST
  branch is dead under real `bun test` (NODE_ENV branches still work). Stricter than intended, not
  looser. Inconsistency, not a weakening.
- LOW/Observation: trust prefix lists are a denylist over the UcanError enum; a future variant whose
  Display isn't listed silently → `unknown`/all-false. Fail-closed but coverage is not mechanically
  pinned to the enum. Consider a Rust-side conformance test asserting every UcanError variant Display
  maps to a non-`unknown` category.
- coverage_exemptions gate: empty-string bypass IS closed (non-empty `reason.strip()` check + errors++).
  all-exempted-ops check requires >=1 statically-verified SDK, preventing prose-only bypass when all
  SDKs exempt simultaneously. Sound. ALIASES table widened but each is OR-of-symbols (still must match
  a real public symbol via AST). `check-sdk-coverage.py` is an enforcement file — only additive edits here.
- assertTestHookAllowed: positive allowlist (test/development/BUN_TEST), default-deny incl undefined.
  Only bypass is "attacker controls process env" = out of threat model. Sound.

## Good patterns
- Fail-closed everywhere: unmatched error → throw; unknown category → all-false; missing symbol → ERROR.
- Null-safe `(node.text or b"").decode("utf-8")` across all AST extractors (prior `.decode()` could NPE).
