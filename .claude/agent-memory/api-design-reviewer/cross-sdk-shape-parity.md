---
name: cross-sdk-shape-parity
description: Recurring cross-SDK shape divergences to flag under the agent-first tenet, the direction to converge, and one divergence the binding substrate forces
metadata:
  type: project
---

When a change touches more than one SDK, build the operation × SDK matrix and check these
divergences, which past reviews found repeatedly:

- **Return type** — Python parses JSON into a `dict` while TypeScript hands back the raw
  `string`. Converge on the parsed, typed shape.
- **JSON string as a parameter** — `receipts_json: str` is the least discoverable parameter.
  The SDK wrapper accepts a typed structure and serializes it before the bridge boundary; the
  bridge may keep `str`. Precedent: `AggregationInput.consequenceRules` is typed
  `ConsequenceRule[]` and the SDK serializes it.
- **Calling convention** — one SDK exposes an operation as a module function over a
  singleton while another takes the `SCP` instance. Pick one convention for the operation.
- **Name collision in a flat namespace** — TypeScript `index.ts` is one flat namespace, while
  Python separates names by module path. Two operations sharing a base name collide only in
  TypeScript.
- **Untyped custody or state** — `custody: string` where a `CustodyType` enum exists, or a
  state accessor returning `String` beside an enum defined in the same file.
- **Different defaults** — a default that differs between SDKs (a custody default was
  `"in_memory"` in TypeScript and `FILE` in Python) breaks the "no silent security defaults"
  tenet.

Converge upward: when one SDK has the typed shape and another the raw shape, move the raw one
to the typed one.

**Forced divergence, do not flag:** TypeScript `evaluateTrust` takes a `Context` handle and
Python `evaluate_trust` takes a context-id string, because the NAPI `ucanValidate` and
`eventLogQuery` calls need a handle while PyO3 resolves the context by id.

**TypeScript test hooks:** a double-underscore prefix (`__setBridgeForTests`,
`__classifyUcanError`) marks an internal or test-only export, and a `ForTests` suffix marks a
seam. A test seam that ships in production needs a runtime check that throws outside test and
development.
