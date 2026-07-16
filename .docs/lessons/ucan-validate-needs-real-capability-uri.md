# UCAN Validate Requires a Real Capability URI — Never Pass `"*"`

> **Implementation status:** The client-side `att[0].with` extraction,
> `ucanValidate`-based Layer-1 evaluation, `__extractFirstCapabilityUri`,
> and the `_REVOCATION_PREFIXES` / `_PASSED_BEFORE` maps described in the
> Historical sections below were **superseded by ADR-059** (structured
> `ucan_evaluate` → `CapabilityValidation`). The bridge now returns six
> booleans directly; no string parsing or client-side URI extraction occurs.
>
> The **enduring principles** (intrinsic-mode vs authorization, closed
> allowlist over open denylist, bridge error routing, self-consistency not
> authorization) remain current and apply to the typed path.

## Current approach (ADR-059)

`evaluateTrust` / `evaluate_trust` calls the bridge in **intrinsic mode** —
no capability URI, nonce probed read-only (not consumed):

```ts
// trust.ts (TypeScript)
const result = await scp.ucanEvaluate(handle, token, subjectDid);
// result: CapabilityValidation { tokensValid, signaturesValid, withinCeiling,
//                                nonceValid, notRevoked, timeBoundsValid }
```

```python
# trust.py (Python)
result = instance.ucan_evaluate(context_id, token, None, subject_did)
# CapabilityValidation: .tokens_valid, .signatures_valid, .within_ceiling,
#                        .nonce_valid, .not_revoked, .time_bounds_valid
```

`presenting_agent_did` / `subject_did` is **required and non-defaulting** —
the bridge rejects empty/absent, preventing the audience check from becoming
a tautology (`aud == aud`). Pass the DID of the participant under assessment.

**Never call `ucanValidate(handle, token, "*")`** — the enforcing path
(which DOES consume the nonce and gate an action) requires a fully-qualified
`scp:ctx:{contextId}/{resource}:{action}` URI. Bare `"*"` is rejected at
URI-parse time before any cryptographic check runs, yielding an all-false
verdict that looks valid rather than crashing.

## Closed allowlist, not open denylist — for error absorption

The absorption logic is the security boundary of Layer 1: an absorbed error
becomes a (partial or all-false) trust verdict; a re-thrown error surfaces a
fault. Get the direction wrong and a genuine fault is laundered into a
plausible-looking verdict.

Under ADR-059, the Layer-1 absorption surface is narrow:
- The `ucan_evaluate` bridge op returns booleans on success and only throws
  for *malformed FFI input* (bad handle / token / presenting-agent DID).
- Layer 2 (`evaluate_trust`) folds `SCP-CTX-2076` (no participation facts
  yet) into a zeroed behavioral record; every other error re-throws.

**Rule:** for security-adjacent error absorption, enumerate what you absorb
(closed allowlist) and default to propagate. Never enumerate what you re-throw
(open denylist) and default to absorb — the default case is where new/unknown
faults land, and "absorb by default" turns every unmodeled fault into a false
verdict.

## Bridge error routing: don't route infrastructure faults to an absorbed code

A UCAN validation entrypoint has (at least) two failure classes — *the token
failed the protocol* vs *the infrastructure failed to evaluate it*. They MUST
carry distinct error codes, because a downstream absorber keys on the code to
decide visible-fault vs trust-verdict.

Never collapse an infrastructure fault (e.g. context-state lookup/writeback)
into the protocol-failure code just because it is convenient — always emit
`[SCP-CTX-2023]` for context-state faults (so they re-throw) and
`[SCP-PERM-3001]` only for real pipeline errors.

**Rule:** match the error code to the failure class, not to the convenient
catch block.

## What Layer 1 measures: self-consistency, NOT authorization

Layer 1 answers "is this token structurally valid, correctly signed, within
the context ceiling, unexpired, and unrevoked?" — measured against the
token's own declared capability set. It does **not** answer "does this token
authorize action X?" The intrinsic-mode `ucan_evaluate` skips the step-6
grant-match check and probes the nonce without consuming it, so the token
remains replayable.

Callers that need to verify authority for a specific operation must call
`scp.ucanValidate(handle, token, uri)` directly with a fully-qualified
capability URI. Do not treat a green Layer-1 `CapabilityValidation` as an
authorization decision.

## Historical: the `ucanValidate` + `att[0].with` extraction era (pre-ADR-059)

> **Note:** The following sections describe the old client-side implementation
> superseded by ADR-059. Preserved for context on the design trap.

### What happened

`evaluateTrust` / `evaluate_trust` was calling `ucanValidate(handle, token, "*")`.
This compiled and ran silently, but the bridge rejects `"*"` at URI-parse time
(`UcanError::InvalidCapabilityUri`) — before any cryptographic check runs.
Layer 1 returned all-false for every token, unconditionally.

### The old fix (now deleted)

The correct pre-ADR-059 approach was to extract the URI from `att[0].with`
and pass it to `ucanValidate`. ADR-059 replaced this entirely — `ucan_evaluate`
now receives no capability URI for intrinsic-mode evaluation; the bridge owns
att enumeration and returns six booleans directly.

### PERM-3001 and VALID-* allowlists

The old Layer-1 absorbed two categories of errors via `validateOneCapUri`
(TypeScript) / `except` handlers (Python):

- `[SCP-PERM-3001]` — pipeline failures (bad signature, ceiling violation,
  nonce reuse, etc.), each classified into the failing stage via the
  `__PASSED_BEFORE` / `_PASSED_BEFORE` map to yield a narrowed
  `CapabilityValidation`.
- `[SCP-VALID-*]` — URI boundary validation failures before the pipeline ran
  (e.g. control characters in `att[0].with`); these produced all-false.
- Re-throws: `[SCP-PERM-3030]` (handle-affinity misuse), `[SCP-CTX-2023]`
  (context-state faults), unknown codes.

Under ADR-059, `ucan_evaluate` returns booleans directly — no string
classification occurs, and the error-absorption surface collapsed to Layer 2's
single `SCP-CTX-2076` fold.

### `_PASSED_BEFORE` inference (superseded by ADR-059)

The old Layer 1 received one error *message string* when a token failed,
classified it into a pipeline stage by prefix-matching on Display text, then
inferred "everything before this stage must have passed" via the
`__PASSED_BEFORE` / `_PASSED_BEFORE` map. Two hidden assumptions made this
fragile:

1. **Fixed step ordering.** The map hardcoded the 11-step pipeline sequence.
   If `validate.rs` reordered steps, the inference silently reported wrong
   `true` fields.
2. **Message-string stability.** Reword a message and the classifier dropped
   to `"unknown"` → all-false, or misclassified into a more-passing category.

ADR-059 replaced this: the safe failure mode (all-false on unknown) meant any
Rust Display-string change was a silent regression. Typed results from
`ucan_evaluate` are stable and don't couple SDKs to prose.

### Multi-att limitation (superseded by ADR-059)

The old `evaluateLayer1` validated only the first declared capability URI
(`att[0].with`). A token with an out-of-ceiling `att[1]` and an in-ceiling
`att[0]` would produce `withinCeiling: true`. ADR-059's `ucan_evaluate`
moves att enumeration into the bridge; `withinCeiling` now reflects the
bridge's full evaluation.

### Revocation prefix narrowing (superseded by ADR-059)

`validate.rs` step 10 emits exactly `UcanError::TokenRevoked` → Display
`"token revoked: {cid}"`. Two other revocation-related messages exist but
are operational (admin-side revocation-management failures, never step-10
validation): `"revocation unauthorized: ..."`, `"revocation failed: ..."`.

The old `_REVOCATION_PREFIXES` / `REVOCATION_PREFIXES` constant had to
contain exactly one entry (`"token revoked:"`) to avoid misclassifying
operational messages as pipeline results. Under ADR-059, operational messages
produce a non-`PERM-3001` error code, which the SDK re-throws rather than
absorbs — the invariant is now enforced structurally by the typed path.

## See also

- `.docs/lessons/typescript-node-only-globals-break-browser.md` — a
  `Buffer`-based decode inside `__extractFirstCapabilityUri` (now deleted)
  silently broke cross-environment evaluation; the principle of feature-
  detecting Node globals still applies to any cross-environment utility code.
- `.docs/lessons/delegation-chain-full-validation.md` — every link in a
  delegation chain needs the full pipeline, not just structural checks.
