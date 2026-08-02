---
name: cross-sdk-shape-parity
description: SCP's agent-first tenet requires identical API shape across all 4 SDK bindings; common parity defects to flag
metadata:
  type: project
---

SCP's "agent-first API design" tenet (CLAUDE.md) mandates **identical shape across all language bindings** (Python, TypeScript, Swift, Kotlin) so an LLM writing correct code in one SDK writes correct code in all. The measure: correct code from the type signature + one example, no compile-retry loop.

**Why:** The SDK's primary author is an LLM; divergent shapes across bindings break that authorability and re-litigate the same operation per-language.

**How to apply:** When reviewing a multi-SDK change (esp. PRs whose goal is "parity"), build the operation × SDK matrix and check these recurring divergences:
- **Return type divergence** — e.g. Python parses JSON → `dict`, TS hands back raw `string`. Converge on the typed/parsed shape, not the raw blob.
- **JSON-string-as-parameter** — `receipts_json: str` is the least discoverable param. SDK wrappers should accept typed structures (`list[dict]` / typed array) and serialize internally before the bridge boundary; the bridge can keep `str`. Precedent: `AggregationInput.consequenceRules` is typed `ConsequenceRule[]`, SDK serializes to wire JSON.
- **Signature divergence** — same underlying bridge op exposed as module-fn-on-singleton in Python but instance-method-taking-`scp` in TS (e.g. `discover_contexts(query)` vs `discoverContexts(scp, query)`). Pick one calling convention, apply uniformly.
- **Name collisions in flat namespaces** — TS `index.ts` is a flat namespace; Python disambiguates by module path. Two ops sharing a base name (`evaluateTrust` four-layer vs `evaluateTrust`/`bridgeEvaluateTrust` tier-integer) collide in TS even though Python (`trust.evaluate_trust` vs `bridge.evaluate_trust`) is clean. Prefer distinct top-level names or keep module-scoped.

Convergence direction: when one SDK has the typed/structured shape and another the raw shape, drag the raw one UP to typed, not the typed one down.

Test-hook convention (TS): double-underscore prefix (`__setBridgeForTests`, `__extractCoreError`, `__classifyUcanError`, `__PASSED_BEFORE`) marks internal/test-only exports. `ForTests` suffix on seams. Guard production-shipped test seams with a runtime env check that throws outside test/dev.
