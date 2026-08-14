---
name: ts-trust-layer1-ucan-classifier
description: TS evaluateTrust Layer-1 infers UCAN sub-check pass/fail by string-matching UcanError Display text; fail-closed but Display-coupled. Parity with Python port.
metadata:
  type: project
---

`bindings/typescript/src/trust.ts` `evaluateTrust` Layer 1 (CapabilityValidation) does NOT get
per-check results from the bridge. All UCAN failures route through
`crates/scp-ffi/common/src/ucan_errors.rs::ucan_error_code` → single code `SCP-PERM-3001`.
So the SDK classifier (`__classifyUcanError`/`__PASSED_BEFORE`) infers WHICH sequential
pipeline step failed by `startsWith`-matching the `UcanError` **Display** text (e.g.
`"signature verification failed"`, `"token expired"`, `"nonce reused:"`).

**Why:** the 11-step validate.rs pipeline is sequential; on first failure it infers all
EARLIER steps passed (`__PASSED_BEFORE`). Optimistic-then-break-on-first-failure.

**How to apply:**
- This is **fail-closed**: unrecognized error → category `unknown` → `__PASSED_BEFORE.unknown`
  = empty set → ALL six CapabilityValidation fields `false`. A Display-string drift
  degrades to "nothing validated", never to a false-positive "valid". Safe direction.
- TS port is **exact parity** with Python `scp_sdk/trust.py` (same prefix lists, same match
  order signatures→ceiling→token_parse→nonce→revoked→expiry, same _PASSED_BEFORE). Keep them
  in lockstep — any UcanError Display change must update BOTH ports + the Rust `#[error(...)]`.
- Coupling risk (shared with Python, NOT a regression): if a `UcanError` `#[error("...")]`
  Display string in `crates/scp-protocol/src/crypto/ucan/mod.rs` is reworded, the matcher
  silently misclassifies → `unknown` → all-false. There is NO compile-time link between the
  Rust Display strings and the SDK prefix lists. A KAT/golden-string test pinning each
  variant's Display to the SDK prefix would close this. Consider for future hardening.
- `revocation unauthorized:` / `revocation failed:` / `invalid capability URI:` Display
  variants are NOT in either port's lists — but they are revoke-API / non-validate-path
  errors, unreachable from evaluateTrust Layer 1. Capability-URI parse failures on the
  validate path surface as `MalformedToken("unparseable capability URI in attestation:...")`
  → matches `malformed token: unparseable capability` → routes to `ceiling`. No gap.
- Gate soundness: `/\[SCP-PERM-\d+\]/` regex correctly fences UCAN errors (all route to
  PERM_3001); non-UCAN errors re-throw. Verified.
