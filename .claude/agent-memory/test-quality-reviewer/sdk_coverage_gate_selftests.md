---
name: sdk-coverage-gate-selftests
description: Test-quality findings for scripts/check-sdk-coverage.py self-tests + SDK parity tests (fix/sdk-coverage-fail-closed-and-parity)
metadata:
  type: project
---

# check-sdk-coverage.py self-tests (scripts/test_check_sdk_coverage.py)

Reviewed at commit 57840faab. 11 gate self-tests + 7 parity tests, all pass.

**Mutation-robustness VERIFIED by hand** (not just claimed in docstrings):
- Test 9 (`test_bare_name_does_not_satisfy_domain_prefixed_op`): re-adding `camel`/`op_name` bare candidates to `_check_operation_in_sdk` candidates list → test FAILS. Genuinely guards the PR's core security fix (bare-name removal that closed ~23 suffix-collision bypasses).
- Test 6 (`test_gate_fails_on_all_exempted_with_none_verified`): disabling the all-exempted guard block → test FAILS. Genuine.
- Tests assert on specific stdout error phrases ("no matching SDK symbol was found", "unexpected cell value", "all SDKs claiming coverage"), not just `returncode==1` — avoids the gate-selftest-over-determined antipattern (passing for the wrong reason).

**Good harness pattern**: `_build_wrapper` writes a subprocess wrapper that patches `MATRIX_PATH`/`SDK_PATHS`/`ALIASES` before `main()` — clean isolation, no global-state leak between tests. Each test uses tmp_path. No flakiness (no time/network/order deps).

**Stale docstring** (minor): module docstring lines 1-15 lists only tests 1-7; file actually has 11 tests (2b, 9, 10 added later). Non-blocking.

# Python SDK parity tests (test_sdk_parity_additions.py)

**PERM-3030 re-raise test is genuine, not mock-testing**: `evaluate_trust` (trust.py:770) checks `error_msg.startswith("[SCP-PERM-3030]")` on `str(exc)` where exc is caught as `bridge.UcanError`. Real PyO3 Display is `[{code}] permission error: {message}` (scp-ffi/src/error.rs:158). Test's `perm3030_msg = "[SCP-PERM-3030] permission error: handle belongs to a different SCP instance"` matches the real wire format exactly. TS counterpart (trust.test.ts:401) constructs `new Error("[SCP-PERM-3030]...")` matching the plain-Error NAPI contract and asserts `err === perm3030` (exact object re-thrown). Both faithful.

**Latent: `hasattr(bridge,"_mock_name")` test seam is in PRODUCTION code** (trust.py:744, aggregate_trust_input:865). A bare `MagicMock()` ALREADY satisfies `hasattr(_mock_name)` (returns None). So the explicit `mock_bridge._mock_name="mock_bridge"` line in the PERM-3030 test is redundant, and its comment is slightly misleading. Pre-existing pattern from #1549, not introduced here. A real bridge object must never have a `_mock_name` attr — currently safe but fragile.

**TypedDict narrowing (discovery.py DiscoveryResult/_TrustLevelDict/_ResolutionPathDict)**: `cast(DiscoveryResult, dict(item))` is typing-only (no runtime effect). Nothing runtime-observable to assert beyond dict shape pass-through, which the test does. Correct — no missing coverage here; the narrowing is a static-typing concern checked by the type checker, not pytest.

**economy_verify_payment_receipts test**: meaningfully asserts the documented gotcha (ok==True but valid==False on invalid-but-reachable receipt). Good — tests the contract callers actually depend on.
