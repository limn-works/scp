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

**UPDATE (2026-07-15, HEAD a3c0e6efb):**
- Browser-path test (`__extractFirstCapabilityUri` "works when Buffer not defined"): try/finally restores `globalThis.Buffer` even on assertion failure (correct); the delete→sync-call→restore has NO await so no cross-test interleaving (low flake). VERIFIED in bun: `delete globalThis.Buffer` succeeds, `typeof Buffer`→"undefined", atob/TextDecoder present → browser branch genuinely exercised. WEAKNESS (LOW): test never asserts the precondition (`expect(globalThis.Buffer).toBeUndefined()` after delete). If a runtime made Buffer non-configurable, delete silently no-ops → test passes via Node path = false green. trust.ts has NO `import Buffer` (relies on global) so the delete is load-bearing today.
- REVOCATION PREFIX NARROWING (commit 8ddce4ab0) removed "revocation unauthorized:"/"revocation failed:" from REVOCATION_PREFIXES in BOTH trust.ts and trust.py → they now classify "unknown" (all-false fail-closed) instead of "revoked" (partial-pass: tokens_valid/signatures_valid/within_ceiling/nonce_valid=TRUE). Python IS guarded by pre-existing `test_operational_errors_classify_as_unknown` in test_ucan_conformance.py (iterates Rust UcanError variants, unchanged on branch). **TS is UNGUARDED** — trust.test.ts only tests generic "something completely unexpected"→unknown; no assertion pins the two operational prefixes → re-adding them to trust.ts REVOCATION_PREFIXES silently downgrades fail-closed→partial-pass with zero test failure. MEDIUM, security-relevant. Fix: 2 assertions `__classifyUcanError("revocation unauthorized: x").toBe("unknown")` + failed variant.
- WASM ucan.rs PERM-3000→PERM-3001 change (all validation failures now route via shared `ucan_error_code`): no direct test, but mitigated — `ucan_error_code` (scp-ffi/common/ucan_errors.rs, unchanged) is an exhaustive match with a coherence test; WASM wiring not unit-testable in Rust harness. LOW.
- STRONG new Python tests (test_trust.py): PERM-3030 reraise builds a REAL JWT so bridge is actually reached (fa6d47034 fixed the short-circuit trap); test_multi_att_token_evaluates_att0_only pins uris_seen==[att0] only; test_declared_capability_uri_passed_to_bridge pins call_args[2]==real URI not "*"; VALID-*/null-uri/empty-att/malformed all assert assert_not_called/assert_called_once. Mutation-robust.

**Integration test `rejects→try/catch` conversion (earlier HEAD commit):** purely mechanical, behavior-preserving. `.rejects.toThrow()` → manual try/catch + `toBeInstanceOf(Error)` + `.message` match. No coverage lost; assertions are equivalent or slightly stronger (instanceof Error added). Likely done to dodge a biome/bun lint rule on floating `.rejects`.
