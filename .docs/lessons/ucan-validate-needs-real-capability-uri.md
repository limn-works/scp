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
- `[SCP-PERM-3000]` — WASM manager permission failures.
- Any other code — unknown codes are genuine faults, not UCAN pipeline or URI-parse outcomes.

## Rules

- **Never pass `"*"` to `ucanValidate`** — it always fails, silently.
- **Never pass a bare action string** (`"messages:write"`) — must include the `scp:ctx:` prefix.
- **Wildcard context** is `scp:ctx:*/resource:action`, not `"*"`.
- **Extract from `att[0].with`** via `__extractFirstCapabilityUri(token)` for validation; the bridge re-verifies cryptographically.
- **Keep TypeScript and Python implementations in lockstep** — this is a cross-SDK trap.

## Detection

Symptom: `evaluateLayer1` / `evaluate_trust` always returns all-false (or `TrustEvaluation` with all fields `False`), even for tokens that were just minted and haven't expired.

## Multi-att limitation: only att[0] is validated

`evaluateLayer1` validates only the first declared capability URI (`att[0].with`). If a token declares multiple capabilities (e.g. `att = [{with: "scp:ctx:A"}, {with: "scp:ctx:B"}]`), only `att[0]` is sent to `ucanValidate`. `att[1]` and later entries are not checked.

This means a token with an out-of-ceiling `att[1]` and an in-ceiling `att[0]` will produce `withinCeiling: true`. Full multi-att ceiling validation requires bridge-level support (a single `ucanValidate` call that verifies ALL att entries against the ceiling, consuming the nonce only once). Until that support lands, the SDK validates att[0] only.

The bridge (SCP production) always mints single-att tokens, so this limitation does not affect normal operation.
