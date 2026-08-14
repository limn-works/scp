---
name: project-sdk-coverage-gate-and-trust-parity
description: check-sdk-coverage.py design rationale + the TS/Python evaluateTrust UCAN-error-classification parity pattern; both are intentional, not over-engineering
metadata:
  type: project
---

Two recurring SCP structures a simplifier will re-encounter and should NOT flag as over-engineering:

**1. `scripts/check-sdk-coverage.py` ALIASES table (~242 alias lists).**
- It is a CI gate that AST-extracts public symbols from 4 SDKs (tree-sitter) and verifies every `true` cell in `.docs/standards/sdk-capability-matrix.json` has a real matching symbol.
- The matching strategy is a CLOSED, BOUNDED design: explicit ALIASES first, then a fixed set of auto-generated name variants (snake/camel/Pascal/domain-prefixed). Substring/suffix matching was DELETED on purpose (it let ~23 fabricated op names pass via suffix collision). This is the *correct* convergent shape — a positive whitelist, not an ever-growing denylist.
- The ALIASES table is large because cross-SDK method naming genuinely diverges (e.g. `tool_invoke`/`toolInvoke`, `governance_execute`/`governanceExecute`/`executeGovernanceAction`). Each entry is verified against real source. Size tracks real surface area, not accidental complexity. Do NOT recommend collapsing it into a fuzzy matcher — that reintroduces the exact false-positive class it was hardened against.
- `coverage_exemptions` + the `all_exempted_ops` check are a deliberate fail-closed escape hatch: a capability that resists static extraction can be exempted with a cited reason, but at least one SDK must be statically verified or the op errors. This guards against prose-bypass. Coherent, not redundant.
- The gate is a [[CLAUDE.md]] enforcement file (listed under "NEVER modify enforcement files to bypass failures"). Weakening it needs human approval.

**2. TS `evaluateTrust` + `__classifyUcanError` / `__PASSED_BEFORE` / `__extractCoreError` (bindings/typescript/src/trust.ts).**
- This is a faithful port of the Python reference `scp_sdk/trust.py` (`_classify_ucan_error`, `_PASSED_BEFORE`, `_extract_core_error`). Cross-SDK parity is a hard project requirement — the structure must mirror Python, even if a from-scratch TS design might differ.
- The prefix-list classification of UCAN errors into 11-pipeline-stage categories, then mapping each stage to the CapabilityValidation fields known-passed-before-it, is the intended model (ADR-017). Not gratuitous.
- The `instanceof` → `/[SCP-PERM-\d+]/` regex switch (commit 58cf17955) is a CORRECTNESS fix: `scp.ucanValidate`/`scp.eventLogQuery` in scp.ts call the native NAPI bridge directly and bypass `mapBridgeError`, so they throw plain `Error` with a code-prefix message, never the typed `UcanPermissionError`/`ContextError`. The old instanceof guards could never match. Regex is the right detection here.

**How to apply:** When reviewing changes to these files, judge them as parity ports and bounded-whitelist gates. Flag only genuine NEW complexity introduced beyond the established pattern, not the pattern itself.
