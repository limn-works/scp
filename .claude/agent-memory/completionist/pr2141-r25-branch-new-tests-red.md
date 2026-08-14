---
name: pr2141-r25-branch-new-tests-red
description: PR#2141 fix/sdk-coverage-fail-closed-and-parity @3de060e97 — branch-new test files ship RED (11 native-independent fails) + stale ADR-059 lesson
metadata:
  type: project
---

# PR #2141 R25 completeness review @3de060e97 (branch fix/sdk-coverage-fail-closed-and-parity, ahead of origin/main bc4464566)

VERDICT: INCOMPLETE (BLOCKER). The coverage gate itself passes (check-sdk-coverage.py PASS, self-test PASS, Bridge/register cell typescript:true + bridgeRegister alias correct, kotlin/swift register resolve by bare name, private-symbol exclusion `not name.startswith("_")` present). Python module IS importable now (956f8116b fixed the PaymentReceiptVerificationResult ImportError). But the branch ships FAILING tests in its OWN net-new test files.

**Why:** the review round fixed an import + matrix cell but NEITHER the Python (`pytest tests/`) NOR the TS (`bun test`) suite was run green afterward. Reading files ≠ running them.

**How to apply:** for any "SDK parity / fail-closed" branch, RUN the branch-new test files, don't just read them. Native-independent (mock/MagicMock) failures are unambiguous branch bugs regardless of whether the native addon is freshly built.

## Native-INDEPENDENT branch-new failures (definitive, no rebuild needed)
- `bindings/python/tests/test_sdk_parity_additions.py` (branch-new, absent on main): 3/7 fail.
  - 2× `test_discover_contexts_*` — `await discovery.discover_contexts(...)` but `discover_contexts` is SYNC `def -> list` (commit 689ca9828 made it a sync free-fn delegating to `context_discover`). `await <list>` → TypeError. Also cross-SDK DRIFT: TS `discoverContexts` is `async ...Promise<DiscoveryResult[]>`, Python is sync.
  - 1× `test_evaluate_trust_reraises_perm_3030_...` — VACUOUS: mocks `mock_bridge.ucan_validate.side_effect` but `evaluate_trust` (trust.py:988) calls `instance.ucan_evaluate(ctx,token,None,subject_did)` → DID NOT RAISE.
- `bindings/typescript/tests/scp-typed-errors.test.ts` (branch-new): 8/21 fail. Header asserts "Every SCP method that forwards to native wraps in try/catch → mapBridgeError", but `mapBridgeError` appears only 2× in src/scp.ts (lines 2384/2989). contextSend/eventLogQuery/governancePropose/outlet/identityRemove/identityExecuteRecovery do NOT wrap → raw Error propagates instead of typed ContextError/GovernanceError/etc. Typed-error surface INCOMPLETELY wired; branch tests catch it, left unfixed.

## Native-DEPENDENT failures (flag for rebuild-verify, do NOT attribute without `maturin develop`/napi build)
- Python test_real_ffi.py/test_scpid.py: 34 fail (e.g. "DID not found") — stale/unrebuilt `_scp_core.so` in review env suspected.
- TS identity-lifecycle.test.ts (branch-new): 7/11 fail — "Real NAPI" tests, need built addon.

## SHOULD-FIX artifact divergence
- `.docs/lessons/ucan-validate-needs-real-capability-uri.md` — touched THIS round (commit 3de060e97 removed WASM refs, marked _PASSED_BEFORE historical) but left stale: "## Multi-att limitation: only att[0] is validated" (line ~145: "out-of-ceiling att[1] + in-ceiling att[0] → withinCeiling:true") CONTRADICTS ADR-059 (phase-2.md §1992 "within_ceiling still enforces the all-attestation ceiling") + tested core (validate_ucan_step8_rejects_smuggled_out_of_ceiling_attestation / _accepts_multi_attestation_all_in_ceiling in ucan_validate_integration.rs). Also cites deleted `__extractFirstCapabilityUri`/`_extract_first_capability_uri` helpers as current "Fix" (grep: gone from bindings src; only a stale COMMENT in test_sdk_parity_additions.py:134). The commit's SIBLING sketch.md edit asserts the OPPOSITE ("bridge now evaluates all att entries") — same-commit self-contradiction. Fix lesson (downstream, one-way flow).
