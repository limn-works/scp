# UCAN Validate Requires a Real Capability URI — Never Pass `"*"`

## What happened

`evaluateTrust` in both the TypeScript and Python SDK trust layers was calling `ucanValidate(handle, token, "*")`. This compiled and ran silently, but the bridge rejects `"*"` at URI-parse time (`UcanError::InvalidCapabilityUri`) — before any cryptographic check runs. Layer 1 returned `{ tokensValid: false, ... }` (all-false) for every token, unconditionally.

A false "all invalid" verdict looks like a legitimate trust evaluation result rather than a crash, making this a silent correctness bug, not a safe default.

## Root cause

The `capability_uri` argument to `ucanValidate` / `ucan_validate` must be a fully-qualified SCP capability URI: `scp:ctx:{contextId}/{resource}:{action}` (e.g. `scp:ctx:abc123/messages:write`). The bridge validates the token's attestation against this URI after signature verification. Bare wildcards (`"*"`) and bare actions (`"messages:write"`) are rejected.

The correct approach is to extract the URI the token was minted for from its own `att[0].with` field and pass that. This is safe because the bridge cryptographically re-verifies the entire token (signature, expiry, nonce, ceiling, revocation) before using the URI — the unverified read only selects which URI to ask the verifier about.

## Fix

```ts
// trust.ts — correct
const capUri = __extractFirstCapabilityUri(token); // reads att[0].with from unverified JWT payload; returns string | null
if (capUri === null) return ALL_LAYER1_FIELDS_FALSE;
await scp.ucanValidate(handle, token, capUri);
```

```python
# trust.py — correct
cap_uri = _extract_first_capability_uri(token)  # reads att[0]["with"]; returns str | None
if cap_uri is None:
    # fail-closed: no valid capabilities declared
    _set_all_false(cap_validation)
    break
await asyncio.to_thread(instance.ucan_validate, context_id, token, cap_uri)
```

## PERM-3001 and VALID-* closed allowlists

`validateOneCapUri` (TypeScript) / the `except` handlers in `evaluate_trust` (Python) absorb two categories of errors, both treated as "malformed token — all-false fail-closed":

**`[SCP-PERM-3001]`** — the one code every `UcanError` variant maps to, enforced by an exhaustive Rust match in `ucan_errors.rs`. This covers pipeline failures: bad signature, ceiling violation, nonce reuse, revocation, expiry, etc. Each failure is classified into the failing pipeline stage, and the `__PASSED_BEFORE` / `_PASSED_BEFORE` map yields a narrowed (partially-true) `CapabilityValidation`.

**`[SCP-VALID-*]`** — boundary validation failures emitted by the bridge's `validate_capability_uri` pre-flight **before** the UCAN pipeline runs. Examples: the URI extracted from `att[0].with` contains control characters or HTML-special characters. Because the URI itself is invalid, no pipeline stage runs and the result is all-false (identical to the null-URI path). TypeScript pattern:

```ts
if (/^\[SCP-PERM-3001\]/.test(msg)) {
  // narrowed verdict from pipeline stage classification
} else if (/^\[SCP-VALID-/.test(msg)) {
  return { ...ALL_LAYER1_FIELDS_FALSE }; // URI invalid → all-false
} else {
  throw error; // propagate genuine faults
}
```

Re-throws (both TS and Python):
- `[SCP-PERM-3030]` — handle-affinity misuse (the token's context handle belongs to a different SCP instance). This is a programming error and must propagate visibly.
- `[SCP-CTX-2023]` — context-state lookup/writeback faults.
- Any other code — unknown codes are genuine faults, not UCAN pipeline or URI-parse outcomes.

## Closed allowlist, not open denylist — for error absorption

The absorption logic is the security boundary of Layer 1: an absorbed error becomes
a (partial or all-false) trust verdict; a re-thrown error surfaces a fault. Get the
direction wrong and a genuine fault is laundered into a plausible-looking verdict.

Python originally used a **denylist**: absorb every `bridge.UcanError` *except*
`[SCP-PERM-3030]`. This is unsafe by construction — any future error code the bridge
learns to emit (a new fault class, a context-state error, a manager error) is
absorbed by default and silently folded into an all-false verdict. The safe posture
is TypeScript's **closed allowlist**: absorb **only** `[SCP-PERM-3001]` (plus the
`[SCP-VALID-*]` URI-boundary case), re-throw everything else. `[SCP-PERM-3030]`
needs no special carve-out — it simply does not start with `[SCP-PERM-3001]`, so it
re-raises automatically, and so does every unknown future code.

**Rule:** for security-adjacent error absorption, enumerate what you absorb (closed
allowlist) and default to propagate. Never enumerate what you re-throw (open
denylist) and default to absorb — the default case is where new/unknown faults land,
and "absorb by default" turns every unmodeled fault into a false verdict. Keep
Python and TypeScript in lockstep: Python's `if not error_msg.startswith("[SCP-PERM-3001]"): raise`
mirrors TS's `if (/^\[SCP-PERM-3001\]/.test(msg)) { ... } ... throw error`.

## Bridge error routing: don't route infrastructure faults to an absorbed code

Because Layer 1 absorbs `[SCP-PERM-3001]` silently, **which code a bridge stamps on a
failure decides whether that failure is visible.** A UCAN validation entrypoint has (at
least) two failure classes — *the token failed the protocol* vs *the infrastructure
failed to evaluate it*. They MUST carry distinct error codes, because a downstream
absorber keys on the code to decide visible-fault vs trust-verdict.

Never collapse an infrastructure fault (e.g. context-state lookup/writeback) into the
protocol-failure code just because it is convenient — always emit `[SCP-CTX-2023]` for
context-state faults (so they re-throw) and `[SCP-PERM-3001]` only for real pipeline
errors (so they absorb into a partial or all-false verdict).

**Rule:** match the error code to the failure class, not to the convenient catch block.

## Rules

- **Never pass `"*"` to `ucanValidate`** — it always fails, silently.
- **Never pass a bare action string** (`"messages:write"`) — must include the `scp:ctx:` prefix.
- **Wildcard context** is `scp:ctx:*/resource:action`, not `"*"`.
- **Extract from `att[0].with`** via `__extractFirstCapabilityUri(token)` for validation; the bridge re-verifies cryptographically.
- **Keep TypeScript and Python implementations in lockstep** — this is a cross-SDK trap.

## Detection

Symptom: `evaluateLayer1` / `evaluate_trust` always returns all-false (or `TrustEvaluation` with all fields `False`), even for tokens that were just minted and haven't expired.

## What Layer 1 measures: self-consistency, NOT authorization

Layer 1 answers "is this token structurally valid, correctly signed, within the
context ceiling, unexpired, and unrevoked?" — measured against the token's **OWN**
first declared capability (`att[0].with`). It does **not** answer "does this token
authorize action X?" There is no caller-supplied target capability in
`evaluateTrust` / `evaluate_trust`; the URI validated against comes from the token
itself. A token can therefore be fully Layer-1-valid and still not authorize the
operation the caller cares about.

Callers that need to verify authority for a specific operation must call
`scp.ucanValidate(handle, token, uri)` directly with a caller-supplied `uri`.
Do not treat a green Layer-1 `CapabilityValidation` as an authorization decision.
Binding a token to a subject (ensuring `aud == subjectDid`) is likewise the
upstream credential-issuance flow's job, not Layer 1's.

## Historical: `_PASSED_BEFORE` inference (superseded by ADR-059)

> **Note:** The Display-string classification approach described in this section was
> superseded by ADR-059 (structured `ucan_evaluate` → `CapabilityValidation`). The
> typed bridge op now returns six booleans directly; no string parsing occurs. This
> section is preserved as historical context explaining the design trap.

The old Layer 1 did not receive structured per-step results from the bridge. When a
token failed, it got one error *message string*, classified it into a pipeline stage
(`__classifyUcanError` / `_classify_ucan_error` — prefix matching on the Display text),
then inferred "everything before this stage must have passed" via the `__PASSED_BEFORE`
/ `_PASSED_BEFORE` map. Two hidden assumptions made this fragile:

1. **Fixed step ordering.** The map hardcoded the 11-step pipeline sequence. If
   `validate.rs` reordered steps, the inference silently reported wrong `true` fields.
2. **Message-string stability.** Reword a message in the Rust pipeline and the
   classifier drops to `"unknown"` → all-false, or misclassifies into a more-passing
   category.

**Why ADR-059 replaced this:** the safe failure mode (all-false on unknown) meant any
Rust Display-string change was a silent regression in SDK trust reporting. Typed results
from `ucan_evaluate` are stable and don't couple SDKs to prose.

## Multi-att limitation: only att[0] is validated

`evaluateLayer1` validates only the first declared capability URI (`att[0].with`). If a token declares multiple capabilities (e.g. `att = [{with: "scp:ctx:A"}, {with: "scp:ctx:B"}]`), only `att[0]` is sent to `ucanValidate`. `att[1]` and later entries are not checked.

This means a token with an out-of-ceiling `att[1]` and an in-ceiling `att[0]` will produce `withinCeiling: true`. Full multi-att ceiling validation requires bridge-level support (a single `ucanValidate` call that verifies ALL att entries against the ceiling, consuming the nonce only once). Until that support lands, the SDK validates att[0] only.

The bridge (SCP production) always mints single-att tokens, so this limitation does not affect normal operation.

## Revocation prefix narrowing: only `"token revoked:"` is a pipeline result

`validate.rs` step 10 emits exactly `UcanError::TokenRevoked` → Display `"token revoked: {cid}"`.
This is the *only* error a revoked token produces at the UCAN pipeline level.

Two other revocation-related messages exist but are **operational** (admin-side
revocation-management failures emitted by the revocation-store write path, never by
step-10 validation):

- `"revocation unauthorized: ..."` — the caller lacked permission to revoke
- `"revocation failed: ..."` — the write to the revocation store failed

These operational messages are NOT step-10 results. If they ever surface, they should
classify as `"unknown"` → all-false (fail-closed). They must be kept **out** of
`_REVOCATION_PREFIXES` (Python) and `REVOCATION_PREFIXES` (TypeScript) in both SDKs.

**Rule:** `_REVOCATION_PREFIXES` / `REVOCATION_PREFIXES` must contain exactly one entry:
`"token revoked:"`. Adding the operational prefixes is a regression — a genuinely-revoked
token could then be misclassified into a more-passing category if the Rust pipeline
messages ever changed, narrowing the `not_revoked` verdict incorrectly.

This cross-SDK invariant was previously pinned by `test_operational_errors_classify_as_unknown`
in `tests/test_ucan_conformance.py` (removed with ADR-059 — the typed `CapabilityValidation`
struct enforces the same property structurally). Under the typed path, operational messages
that don't match UCAN pipeline stages produce a non-`PERM-3001` error code, which the SDK
re-throws rather than absorbs — the invariant is now enforced by the absorption allowlist
itself rather than a conformance gate.

## See also

- `.docs/lessons/typescript-node-only-globals-break-browser.md` — the
  `__extractFirstCapabilityUri` payload decode used a Node-only `Buffer`, silently
  breaking `att[0].with` extraction (and thus all of Layer 1) in the browser.
- `.docs/lessons/delegation-chain-full-validation.md` — every link in a delegation
  chain needs the full pipeline, not just structural checks.
- `.docs/lessons/wasm-partial-ucan-validation.md` — the WASM pipeline is structurally
  partial; document what it actually checks.
