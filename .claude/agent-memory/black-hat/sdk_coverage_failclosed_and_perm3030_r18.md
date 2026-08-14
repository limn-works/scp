---
name: sdk-coverage-failclosed-and-perm3030-r18
description: Review of branch fix/sdk-coverage-fail-closed-and-parity (HEAD c1fb5e042) — coverage gate, TS NATIVE_OVERRIDE symbol gate, PERM-3030 re-raise, UCAN classification
metadata:
  type: project
---

Branch fix/sdk-coverage-fail-closed-and-parity @ c1fb5e042. APPROVED — no new exploitable defect.

**Coverage gate (scripts/check-sdk-coverage.py):** AST tree-sitter symbol extraction + exact-match + ALIASES whitelist; substring matching REMOVED (was the ~23-fabricated-op bypass). Residuals, ALL authoring-trust (editing matrix == editing gate) + documented in .docs/lessons/ast-gate-checks-definition-not-name-resolution.md, NOT external attack surface, NOT regressed by this PR (PR tightened):
- BLACK-COV-1 (LOW/accepted): name-existence-not-resolution. A fabricated op named after any colliding symbol (`shutdown` collides in all 4 SDKs; `create/verify/load/resolve/send/close` collide in kotlin/swift) passes exit 0 covering a non-existent function. candidate list includes bare op_name/camel/pascal (lines 1056-1068). Proven by injecting FakeDomain/shutdown=true.
- BLACK-COV-2 (LOW): all-exempted guard (line 1219) only fires when set(exempted)==set(true) AND no verified. Mix one collision-verified SDK + N prose coverage_exemptions → guard never fires, N fake SDKs pass. Proven.
- BLACK-COV-3 (LOW/pre-existing/by-design): all-`null` operation passes with NO exemption and NO coverage_exemption (null=key-present → `continue`, line 1147). `false` demands exemption but `null` demands nothing → null is path of least resistance for silent exclusion. PR's missing-key check (1117-1126) is a NEW tightening (fully-absent key now errors).
- Self-tests (test_check_sdk_coverage.py, 9 pass) NON-vacuous: test2 uses unique `nonexistent_operation_zzzzzz` all-keys-present to isolate unmatched-true; documents+fixed prior masking pitfall.

**TS test-env / native-override gate — SOUND:**
- NATIVE_OVERRIDE = module-private `unique symbol` (Symbol(), NOT Symbol.for so no registry forge), scp.ts:486. Never written onto a persistent/exported object — only a transient options-bag key consumed by the constructor (scp.ts:542,2862) and discarded. No getOwnPropertySymbols enumeration path. This is the load-bearing primary gate.
- `#native` set in EXACTLY 2 sites, both in-constructor (override branch 544, real-addon 560), never mutated after. __setNativeForTests/replaceNativeWithMock REMOVED (round-3, BLACK-PR5-003).
- Both doors (__setBridgeForTests internal/bridge.ts:834, __constructScpWithNativeForTests scp.ts:2859) call assertTestEnvironment. NEITHER re-exported from index.ts (only BridgeTarget/BRIDGE_TARGET are). package.json exports map = `.` only → deep imports of internal/* blocked in bundled consumers.
- env-guard (test-guard.ts) = pure DiD: _ENV_AT_LOAD IIFE snapshot at module-load (runtime mutation can't flip), Object.hasOwn anti-proto-pollution. NODE_ENV=development counts as test, but irrelevant since hooks unreachable.

**PERM-3030 re-raise — SOUND:**
- napi_check_handle! runs FIRST in ucan_validate_on (napi/src/ucan.rs:200), before any UCAN logic → 3030 mutually exclusive with UCAN errors per call. HandleAffinityError → ScpNapiError::Permission code PERM_3030 (error.rs:543), formatted `[{code}] permission error: {msg}` → JS Error.message `[SCP-PERM-3030] permission error: ...`. TS regex `^\[SCP-PERM-3030\]` (trust.ts:461) + Python startswith("[SCP-PERM-3030]") (trust.py:762) match faithfully. No real UCAN error carries 3030; no 3030 lacks the prefix.

**UCAN classification — SOUND (no too-permissive misclass reachable):**
- ALL UcanError variants map to PERM_3001 (ucan_errors.rs:48, exhaustive match). So numeric code carries NO stage info; classification keys ENTIRELY on UcanError Display prefix (__extractCoreError strips `] permission error: ` head + ` — advice` em-dash suffix, then startsWith over ordered prefix lists sig→ceiling→token_parse→nonce→revoked→expiry).
- Anchoring at Rust format-string HEAD defeats content-injection: attacker-controlled {0} payloads appear AFTER the colon, can't shift the matched prefix. Verified every variant: classifies correctly OR to `unknown` (empty passed-set = all-false = fail-closed). RevocationUnauthorized/RevocationFailed/InvalidCapabilityUri → unknown (operation-side errors, safe). Em-dash-in-{0} truncation → empty core → unknown.
- __PASSED_BEFORE never includes the failing field; even hypothetical worst misclass stays fail-closed because no early-stage Display head matches a later prefix list.
- behavioralRecord: starts null, only populated on event-log success, zero aggregates honestly documented as not-computed (not fabricated). Catch filters ^\[SCP-CTX-\d+\] else propagate (fail-loud).

Harness: `python3.12 scripts/check-sdk-coverage.py` (needs tree-sitter-{python,typescript,kotlin,swift}); classifier probe via `bun run` importing __classifyUcanError/__extractCoreError from trust.ts.
