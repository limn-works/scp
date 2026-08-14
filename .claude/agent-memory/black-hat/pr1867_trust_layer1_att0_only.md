---
name: pr1867-trust-layer1-att0-only
description: PR #1867 trust Layer-1 att[0]-only ceiling bypass + WASM PERM code audit findings
metadata:
  type: project
---

# PR #1867 (fix/sdk-coverage-fail-closed-and-parity) trust Layer-1 audit

Audited the trust-evaluation Layer-1 path at HEAD 205966ced.

## Confirmed real (but documented) weakness: att[1] ceiling bypass
- `evaluateLayer1` (bindings/typescript/src/trust.ts) + Python mirror validate ONLY `att[0].with` per token.
- ROOT CAUSE is deeper than the SDK: `validate_ucan` step 8 (crates/scp-protocol/src/crypto/ucan/validate.rs:591) calls `verify_ceiling_compliance(std::slice::from_ref(required_capability), ceiling)` — checks ONLY the single passed URI, NOT all `att` entries. Step 6 builds granted_caps from all att but only checks "includes required". Step 6b (Category A, line 582) DOES check all granted_caps.
- So a token `att[0]=in-ceiling, att[1]=out-of-ceiling-but-not-CategoryA` yields `withinCeiling:true`. The bridge ITSELF would not catch att[1] even if the SDK passed the whole token.
- Documented in `.docs/lessons/ucan-validate-needs-real-capability-uri.md` §Multi-att limitation + JSDoc. Mitigant: SCP production always mints single-att tokens. Category A (DID/identity) caps ARE caught regardless via step 6b.
- This is a protocol-level ceiling-enforcement gap (per-required-cap, not per-token), not a regression introduced by this PR. The PR's att[0]-only revert is correct (multi-att AND-intersect was broken by nonce-single-consumption).

## Closed / not exploitable
- Q2 absorption escape: `ucan_error_code` (crates/scp-ffi/common/src/ucan_errors.rs) is an EXHAUSTIVE match; EVERY UcanError variant → PERM_3001. New variants = compile error. So `/^\[SCP-PERM-3001\]/` absorbs all real UCAN failures; none escape. PERM_3000/3030 correctly re-thrown.
- Q3 injection: bridge error format is `[{code}] permission error: {message}` (code always pos 0, prepended). Attacker URI lands in `{message}`, never pos 0. `__classifyUcanError` uses `startsWith` on the FIXED variant prefix; embedded `{0}` attacker text is in the tail → cannot forge classification. Closed.
- Q5 WASM PERM fix: `validate_tool_ucan_wasm` (ucan.rs:573,584,596) now routes ALL three error paths through `ucan_error_code(&e)` returning `Some(code)`; caller `code.unwrap_or(PERM_3000)` (tools.rs) never falls back to 3000 for real UCAN errors. Fix verified present.
- Q4 `__extractAllCapabilityUris` side effects: pure base64url+JSON.parse, reads only .att/.with, Array.isArray guard, no proto-pollution (read-only), only [0] used. Benign (mild CPU on huge att array, caller's own token).
- Q6 test gate: `assertTestEnvironment` frozen at module load (_IS_TEST_ENVIRONMENT), Object.hasOwn anti-proto-pollution, fail-closed when process absent. Primary boundary = tsup DCE + exports map blocking deep import. Sound.

## Note
- `evaluateLayer1` calls `scp.ucanValidate(handle,token,capUri)` with NO presentingAgentDid (undefined) → audience binding to subjectDid NOT enforced here; documented as upstream issuer's job. Layer-1 = token self-consistency only.
