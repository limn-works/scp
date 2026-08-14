---
name: perm3030-parity-coverage-asymmetry
description: Python evaluate_trust got a PERM-3030 re-raise unit test but the TS reference impl (trust.ts:461) it mirrors has none — asymmetric parity coverage
metadata:
  type: project
---

# PERM-3030 re-raise: parity coverage asymmetry (branch fix/sdk-coverage-fail-closed-and-parity)

Both `bindings/python/scp_sdk/trust.py:762` and `bindings/typescript/src/trust.ts:461` re-raise a `[SCP-PERM-3030]` handle-affinity error out of `evaluate_trust` rather than collapsing it to a false all-False CapabilityValidation. PERM-3030 = caller misuse (handle from a different SCP instance); must surface, not be absorbed.

- Python NOW has a dedicated unit test: `test_sdk_parity_additions.py::test_evaluate_trust_reraises_perm_3030_handle_affinity_error`. It is mutation-robust: delete the re-raise branch → error reclassifies to "unknown" → function returns normally → `pytest.raises` fails. Mock matches the real `_bridge()`/`_mock_name` seam exactly. GOOD test.
- TypeScript has NO unit test for `trust.ts:461` re-raise (grep `3030` in `tests/trust.test.ts` → none). The Python test's docstring even cites the TS line as its reference, yet the reference side is untested.

RULE: When a PR adds a test for a behavior on SDK-A and justifies it as "parity with SDK-B", verify SDK-B actually has the matching test. Parity claims are a tell for asymmetric coverage. Recommend adding a TS `evaluateTrust` PERM-3030 re-raise test (spy bridge whose `ucanValidate` throws `[SCP-PERM-3030] ...`, assert `evaluateTrust(...)` rejects).

RESOLVED at HEAD a2caec4a8 (re-reviewed 2026-06-21). TS now has `trust.test.ts:401` "PERM-3030 handle-affinity error re-throws instead of being classified" — mock-injected (not addon-gated), asserts `err === perm3030` (exact object identity). MUTATION-VERIFIED: deleting trust.ts:461 re-raise → test fails (threw=false). Python `test_sdk_parity_additions.py::...perm_3030...` ALSO mutation-verified (delete trust.py:762 → DID NOT RAISE). Both SDKs now symmetric and non-vacuous. Earlier-HEAD asymmetry closed.

Related: [[ts-routing-test-addon-dependence]] (same SDK, addon-gated test suspicion).
