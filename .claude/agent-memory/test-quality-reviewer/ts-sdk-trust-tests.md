---
name: ts-sdk-trust-tests
description: Test patterns & gaps in the TS SDK trust/bridge/identity-lifecycle test suite (fix/sdk-coverage-fail-closed-and-parity)
metadata:
  type: project
---

# TS SDK trust/parity test suite (bindings/typescript/tests)

Reviewed branch `fix/sdk-coverage-fail-closed-and-parity` (HEAD ae1fcecaa).

**Good patterns worth replicating:**
- `mock-bridge.ts` strict-by-default Proxy harness: unstubbed methods THROW (cryptographer finding M-1) so "verify-succeeds" tests can't pass trivially on `Promise.resolve(undefined)`. `SAFE_DEFAULT_METHODS` allowlist (suspend/resume/shutdown) is documented & bounded. This is the gold standard for mock realism here.
- `bridge-trust.test.ts` spy-bridge injection deliberately avoids the tautology trap: comment explicitly notes a local copy of the `??` chains would drift identically with the impl. Spies on real `evaluateTrust` arg-passing instead.
- Real-NAPI groups gate on an addon probe and `test.skip` with a reason string when absent — graceful, no false green.
- Trust classifier tests mirror Python `bindings/python/tests/test_trust.py` for cross-SDK lockstep.

**Gaps / weaknesses:**
- Cross-SDK parity is asymmetric: Python `test_trust.py` has ~111 cases, TS `trust.test.ts` ~46. TS exercises one representative per UCAN category + the malformed-token disambiguation cases, but skips many individual prefix strings (`invalid issuer:`, `circular delegation`, `attenuation violation`, `key scope mismatch`, `self-delegation`, several `malformed token:` variants, `nonce too old:`/`from the future:`/`invalid nonce format:`, `invalid time range:`, `expiry too far`). A typo'd prefix string in `trust.ts` would go undetected. Lockstep claim is partial.
- `__PASSED_BEFORE` describe block is a near-tautology — asserts the exported constant's contents against hardcoded expectations. Low ROI on its own; its value is realized only via the `evaluateTrust — Layer 1 field independence` integration tests, which DO exercise it through real classification.
- Real behavior of the tier mapping (0-3) lives in Rust `bridgeEvaluateTrust`; TS only tests defaults/passthrough. Tier semantics covered ONLY by the skipped-when-no-addon real-NAPI group. Correct layering, but means tier mapping is unverified in CI runs without the platform addon.

**Integration test `rejects→try/catch` conversion (HEAD commit):** purely mechanical, behavior-preserving. `.rejects.toThrow()` → manual try/catch + `toBeInstanceOf(Error)` + `.message` match. No coverage lost; assertions are equivalent or slightly stronger (instanceof Error added). Likely done to dodge a biome/bun lint rule on floating `.rejects`.
