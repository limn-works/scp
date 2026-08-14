# fix/sdk-coverage-fail-closed-and-parity @ HEAD 6bc9dfead -- 2026-06-22 -- APPROVED, ZERO findings

Re-review of the d70c3c272 branch family at new HEAD 6bc9dfead. The d70c3c272 BLOCKING
issue (broadcast_open_key alias missing → gate exit 1) is RESOLVED: alias now present
(check-sdk-coverage.py:501-506); gate exits 0 on REAL matrix (223 ops, 0 errors, 1 coverage-exempt
add_relay_url kotlin); branch's own test_gate_passes_on_real_matrix now PASSES. 11/11 self-tests pass.

## Security properties ALL SOUND (verified at this HEAD)
- Gate is positive ALLOWLIST (ALIASES) + exact domain-prefixed match ONLY. Suffix/substring match
  REMOVED (closed ~23 fabricated-name collisions). test_bare_name_does_not_satisfy_domain_prefixed_op
  locks this. Fail-closed: missing-SDK-key→err, unexpected-cell(non-bool/null)→err, false-without-exemption→err,
  empty/blank exemption reason→err, all-true-SDKs-exempted-none-verified→err (prevents prose-bypass).
- PERM-3030 re-raise anchored BOTH SDKs: ts trust.ts ~461 `/^\[SCP-PERM-3030\]/` AFTER `^\[SCP-PERM-\d+\]`
  guard, BEFORE __classifyUcanError; py trust.py:770 `error_msg.startswith("[SCP-PERM-3030]")` inside
  `except bridge.UcanError`, BEFORE _classify. Handle-affinity (wrong SCP instance) propagates as the
  programmer error it is — NOT absorbed into a false all-False CapabilityValidation. Regression test exists
  (test_evaluate_trust_reraises_perm_3030_handle_affinity_error).
- UCAN classify ordering IDENTICAL both SDKs: SIGNATURE_CHAIN → CEILING → TOKEN_PARSE → NONCE → REVOKED → EXPIRY.
  Specific `malformed token: DID not found`/`unparseable capability` route to signatures/ceiling BEFORE generic
  token_parse. NOT spoofable: thiserror #[error("fixed prefix: {interpolated}")] always puts attacker-influenced
  UCAN content as SUFFIX; startsWith matches the fixed Rust-type-determined prefix, not payload. `unknown` category
  → _PASSED_BEFORE=∅ → ALL fields false (fail-closed). Misclassification can only be conservative
  (delegation-chain parent-expiry → signatures, NOT expiry — proven by test).
- test-guard.ts: _ENV_AT_LOAD read once via IIFE at module load, _IS_TEST_ENVIRONMENT frozen const,
  Object.hasOwn (anti-prototype-pollution), fail-closed (false if process unavailable / NODE_ENV absent).
- BOTH native-swap hooks (__setBridgeForTests bridge.ts:836, __constructScpWithNativeForTests scp.ts:2903)
  assertTestEnvironment-gated AND not re-exported from index.ts; package.json exports map = {"."} only
  (no deep import of internal/bridge or scp) → tsup tree-shakes from dist/. Triple control.
- economy_verify_payment_receipts (scp.py:1756): thin json.dumps→bridge→json.loads passthrough. Bounds
  (MAX_RECEIPT_BATCH=10_000 adapter.rs:231, enforced economy.rs:485) + validity (all_valid fail-closed:
  starts true, cleared by ok==false OR valid==false, receipt.rs:171-203) enforced at Rust trust boundary —
  correct layer (Python-side limit would be cosmetic). No injection (JSON-serialize a dict).
- discovery.discover_contexts = passthrough to Rust context_discover (query validation in validate.rs);
  TypedDicts only. No Python-layer injection/format-string. CLAUDE.md change ADDS check-sdk-coverage.py to
  enforcement-protected list (strengthens governance). FFI/identity diffs = doc-comment citation fixes only
  (§3.2.1→§9.12, ADR-003 §4b). No secrets in diff.

## Tests run (all green)
- python3.12 scripts/check-sdk-coverage.py → EXIT 0, 0 errors
- pytest scripts/test_check_sdk_coverage.py → 11 passed
- pytest bindings/python/tests/test_sdk_parity_additions.py → 7 passed (incl PERM-3030 reraise)
- bun test trust → 51 pass / 1 skip / 0 fail

LESSON (carry forward): on fail-closed gate conversions, re-run gate vs REAL matrix + the branch's own
passes-on-real-matrix self-test, not just synthetic tests — that's what caught the d70c3c272 blocker.
