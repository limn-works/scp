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
const capUri = __extractCapabilityUri(token); // reads att[0].with from unverified JWT payload
if (capUri === null) return ALL_LAYER1_FIELDS_FALSE;
await scp.ucanValidate(handle, token, capUri);
```

```python
# trust.py — correct
cap_uri = att[0].get("with", "") if att else ""
if not cap_uri:
    return all_false_result
await asyncio.to_thread(instance.ucan_validate, context_id, token, cap_uri)
```

## Rules

- **Never pass `"*"` to `ucanValidate`** — it always fails, silently.
- **Never pass a bare action string** (`"messages:write"`) — must include the `scp:ctx:` prefix.
- **Wildcard context** is `scp:ctx:*/resource:action`, not `"*"`.
- **Extract from `att[0].with`** for validation; the bridge re-verifies cryptographically.
- **Keep TypeScript and Python implementations in lockstep** — this is a cross-SDK trap.

## Detection

Symptom: `evaluateLayer1` / `evaluate_trust` always returns all-false (or `TrustEvaluation` with all fields `False`), even for tokens that were just minted and haven't expired.
