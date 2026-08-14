---
name: sdk-coverage-parity-review
description: Findings from reviewing fix/sdk-coverage-fail-closed-and-parity (TS trust/identity parity + Python wrappers + coverage gate)
metadata:
  type: project
---

# Review: fix/sdk-coverage-fail-closed-and-parity (HEAD 44eaf5d05)

**Why:** SDK cross-language parity additions (TS evaluateTrust four-layer + bridge-tier, identity-lifecycle wrappers, Python discover_contexts/economy_verify_payment_receipts) + 561-line rewrite of check-sdk-coverage.py gate.

## Good patterns worth replicating
- **bridge-trust.test.ts default-shape test**: injects a spy Bridge via `__setBridgeForTests` and asserts which args reach `bridgeEvaluateTrust`, instead of re-asserting the `??` default chains locally. Doc comment explicitly notes a local copy of the chains would be a tautology that drifts identically with the impl. Strong behavior-over-implementation design.
- **mock-bridge.ts strict-by-default** (cryptographer M-1): unstubbed methods throw rather than resolve undefined, so "verify-succeeds" assertions can't pass trivially. SAFE_DEFAULT_METHODS allowlist (suspend/resume/shutdown) is the bounded exception.
- trust.test.ts mirrors Python test_trust.py for the UCAN classifier — keeps cross-SDK classifier in lockstep.

## Gaps found
- **Identity.rotationEventJson getter: ZERO test coverage.** New public getter (identity.ts:117) with a MUST-distribute-to-members contract (spec §3.2.1). No mock test asserts it reads `_rawHandle.rotationEventJson`; real-NAPI migrate test never asserts it's populated.
- **trust.ts Layer-2 catch discriminator half-tested.** Tests cover the [SCP-CTX-] propagate-as-null path but NOT the re-raise branch (non-context error must propagate). Layer-1 has the symmetric test (non-UCAN ValidationError propagates) — Layer-2 is missing it.
- **check-sdk-coverage.py has NO self-tests** despite 561 changed lines incl. AST extractors that had a null-`.text` NPE (the `(child.text or b"").decode()` fix in last commit). A null-safety bug shipped that no test caught.

## Latent skip-guard weakness (pre-existing, NOT branch-introduced)
- Real-NAPI suites probe `new SCP({storage:in_memory})` + method-existence, then call `identityCreate("in_memory")` which throws `[SCP-IDENT-1008] in_memory custody not available` if the local addon lacks `allow_in_memory_custody`. Guard passes (constructor succeeds) but tests hard-FAIL instead of skipping. Affects integration.test.ts (80 fails locally), real-napi, and the NEW identity-lifecycle.test.ts (4 fails). CI builds the addon WITH the feature so it's green there. Fix: probe should attempt identityCreate in the guard and skip on IDENT-1008.

## integration.test.ts refactor
- `.rejects.toThrow()` → explicit try/catch + `toBeInstanceOf(Error)` + `.message.toMatch(...)`. Equivalent assertion strength; motivation appears to be matching plain-Error bridge throws. Not a regression.
