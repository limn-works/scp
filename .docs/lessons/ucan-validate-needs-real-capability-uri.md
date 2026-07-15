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
- `[SCP-CTX-2023]` — context-state lookup/writeback faults (see "WASM error routing" below).
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

## WASM error routing: don't route infrastructure faults to an absorbed code

Because Layer 1 absorbs `[SCP-PERM-3001]` silently, **which code a bridge stamps on a
failure decides whether that failure is visible.** The WASM bridge originally wrapped
context-state lookup/writeback failures (`with_manager` errors) as
`UcanError::MalformedToken` → `[SCP-PERM-3001]`. That routed a genuine infrastructure
fault straight into the absorb path: WASM returned all-false where NAPI — which emits
`[SCP-CTX-2023]` via `ensure_registered` for the same runtime condition — correctly
re-threw. A silent WASM/NAPI parity break.

Fix pattern (`crates/scp-ffi/wasm/src/ucan.rs`): introduce a `WasmValidateError` enum
that separates the two failure classes at the source, so callers route each to the
right code:

```rust
enum WasmValidateError {
    Ucan(UcanError),  // step 1–11 pipeline failure → [SCP-PERM-3001] (absorbed by trust.ts)
    Context(String),  // with_manager state fault  → [SCP-CTX-2023]  (re-thrown by trust.ts)
}
```

`run_validate_ucan` returns `Context(_)` for every `with_manager` failure and
`Ucan(_)` only for real pipeline errors. Both `ucan_validate` and
`validate_tool_ucan_wasm` `match` on the enum and stamp the matching code.

**Rule:** a UCAN validation entrypoint has (at least) two failure classes — *the token
failed the protocol* vs *the infrastructure failed to evaluate it*. They MUST carry
distinct error codes, because a downstream absorber keys on the code to decide
visible-fault vs trust-verdict. Never collapse an infrastructure fault into the
protocol-failure code just because it is convenient (`MalformedToken(format!(...))`) —
match the sibling bridge's code for the equivalent condition.

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

## The `_PASSED_BEFORE` inference is a stringly-typed heuristic — treat it as fragile

Layer 1 does not receive structured per-step results from the bridge. When a token
fails, it gets one error *message string*, classifies it into a pipeline stage
(`__classifyUcanError` / `_classify_ucan_error` — prefix matching on the Display
text), then infers "everything before this stage must have passed" via the
`__PASSED_BEFORE` / `_PASSED_BEFORE` map. Two hidden assumptions make this fragile:

1. **Fixed step ordering.** The map hardcodes the 11-step pipeline sequence (parse →
   signatures → ceiling → nonce → revoked → expiry). If `validate.rs` reorders steps,
   the inference silently reports wrong `true` fields for every failure.
2. **Message-string stability.** Classification is prefix matching on `thiserror`
   Display strings. Reword a message in the Rust pipeline and the classifier drops to
   `"unknown"` → all-false, or worse, misclassifies into a more-passing category.

This is why the revocation-prefix set must contain *exactly* `"token revoked:"` and
must exclude the operational admin-side messages (see below): the classifier cannot
tell a step-10 pipeline result from an unrelated message that happens to share a
prefix. The safe failure mode is `"unknown"` → all-false; any change that lets a
non-pipeline message map to a passing stage is a regression. These string-coupling
invariants are pinned by conformance gates in both SDKs — if a gate goes red, find
why the bridge changed its message; do not adjust the prefixes to make it pass.

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

This cross-SDK invariant is pinned by the conformance gate
`test_operational_errors_classify_as_unknown` in `tests/test_ucan_conformance.py`.
If that gate is red, do not add the operational prefixes to fix it — find why the bridge
is emitting them from step 10 (it shouldn't be).

## See also

- `.docs/lessons/typescript-node-only-globals-break-browser.md` — the
  `__extractFirstCapabilityUri` payload decode used a Node-only `Buffer`, silently
  breaking `att[0].with` extraction (and thus all of Layer 1) in the browser.
- `.docs/lessons/delegation-chain-full-validation.md` — every link in a delegation
  chain needs the full pipeline, not just structural checks.
- `.docs/lessons/wasm-partial-ucan-validation.md` — the WASM pipeline is structurally
  partial; document what it actually checks.
