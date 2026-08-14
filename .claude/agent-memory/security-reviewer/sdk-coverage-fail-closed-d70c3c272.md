# fix/sdk-coverage-fail-closed-and-parity (HEAD d70c3c272) -- 2026-06-21

Review of SDK coverage gate hardening + PERM-3030 re-raise + test-env guard.

## Security properties: ALL SOUND
- PERM-3030 re-raise anchored at start in BOTH SDKs:
  - Python trust.py:770 `error_msg.startswith("[SCP-PERM-3030]")`
  - TS trust.ts:461 `/^\[SCP-PERM-3030\]/.test(msg)` (inside the PERM-\d+ block, ordering correct)
  - Handle-affinity (wrong SCP instance) error propagates BEFORE UCAN classification -> not absorbed into all-False CapabilityValidation. Correct.
- UCAN classification anchored (startsWith / ^) in both SDKs -- no substring misclassification.
- test-guard.ts: _IS_TEST_ENVIRONMENT frozen at module load (IIFE reads process.env once);
  isTestEnvironment() returns the frozen const; uses Object.hasOwn (prototype-pollution resistant). Sound.
- Coverage gate STRENGTHENED (fail-closed): removed bare op_name/camel/pascal/py_prefixed candidates +
  suffix-match fallback (allowed ~23 fabricated ops via collision). Now only ALIASES + domain-prefixed
  exact match. Added: missing-SDK-key error, unexpected-cell-value rejection, coverage_exemptions
  non-empty-reason check, all-exempted-ops-with-none-verified error. Self-tests are real mutation tests.
- FFI identity diffs = pure doc-comment citation fixes (§3.2.1 -> §9.12, ADR-003 §4b). No logic.
- mls/provider.rs diff = doc-comment only (stale "default impl/trait override" language removed; ContextManager
  -> context actor/receive handler rename). Sig-verify-deferred comment preserved. No logic.
- discovery.py = TypedDict+Literal + discover_contexts async. native.ts = issue-ref removal. Benign.

## BLOCKING (process/correctness, not a vuln -- gate fails SAFE):
- `Messaging/broadcast_open_key` matrix entry (all 4 SDKs true) has NO ALIASES entry. Op name lacks
  `messaging_` prefix so auto-gen `messagingBroadcastOpenKey` misses the real symbols
  (py `broadcast_open_key` scp.py:1138, ts/kotlin/swift `broadcastOpenKey`). Gate exits 1 with 4 errors.
- The branch's OWN self-test `test_gate_passes_on_real_matrix` FAILS (1 failed, 10 passed).
- Root cause: this branch flipped true-but-no-AST-match from WARNING (base: 84 warnings, exit 0) to
  hard ERROR, but didn't add the broadcast_open_key alias. All other broadcast_* ops HAVE aliases.
- FIX (legitimate coverage expansion): add
  ("Messaging","broadcast_open_key"): {python:["broadcast_open_key"], typescript:["broadcastOpenKey"],
   kotlin:["broadcastOpenKey"], swift:["broadcastOpenKey"]}

## Gotcha
- Base gate used warnings; new gate uses errors. When auditing fail-closed conversions, ALWAYS run the
  gate against the REAL matrix + the branch's own passes-on-real-matrix self-test, not just synthetic tests.
