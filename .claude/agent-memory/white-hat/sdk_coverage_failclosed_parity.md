# Branch fix/sdk-coverage-fail-closed-and-parity Defense Review

HEAD a2caec4a8 (was adea2c3c7 in prior pass; +576 lines on coverage gate, behavioralRecord now populated, Bridge/register TS=false).
Focus: test-guard, evaluateTrust, coverage gate fail-closed, Bridge/register exemption, PERM-3030 format.

## Well-Defended (verified a2caec4a8)
- test-guard.ts: env frozen at IMPORT (IIFE consts). Object.hasOwn (no proto pollution). try/catch fail-closed→false. Error reports frozen _NODE_ENV_AT_LOAD. Primary security boundary documented as tsup DCE of getBridgeForTesting from dist/ + package.json exports map blocks deep import; env guard = defense-in-depth. 60 TS test-guard+trust tests pass.
- evaluateTrust (TS+Py): optimistic-then-overwrite-all-6-on-first-failure(break). unknown→∅ passed-set→all false=FAIL CLOSED. PERM-3030 RE-RAISED before classification (caller misuse, not UCAN fail). Non-[SCP-PERM-\d+] re-thrown. Layer2 non-[SCP-CTX-\d+] re-thrown. behavioralRecord now POPULATED (toolInvocations from ToolInvoked events; contextsParticipated/totalDuration/governanceActionsAgainst honestly 0 — documented "not computed, not fabricated"). Python identical (catches bridge.UcanError, startswith [SCP-PERM-3030]).
- PERM-3030 FORMAT STABLE: both bridges render "[SCP-PERM-NNNN] permission error: <msg>" via thiserror/Display. NAPI error.rs:69 `#[error("[{code}] permission error: {message}")]`; PyO3 error.rs:158 same. HandleAffinityError→PERM_3030 in both (napi error.rs:538, pyo3 error.rs:737 maps to ScpPyError::UcanError = the caught type). TS regex /^\[SCP-PERM-3030\]/ + Py startswith both match. Explicit re-raise tests in both SDKs.
- Coverage gate (check-sdk-coverage.py, 222 ops, 0 errors): MATCHING IS DOMAIN-PREFIX-ONLY + closed ALIASES table. Bare op_name/camel/pascal candidates REMOVED (commit 1679a75ac) — only domain_snake, domain_camel, Domain.op, Domain.camel + exact ALIASES. Fail-closed: true cell w/ no symbol + no coverage_exemptions = ERROR. Missing-SDK-key = ERROR. Non-bool/null cell = ERROR. Blank coverage_exemption reason = ERROR. all-exempted check (L1614): op_true_sdks and not op_verified_sdks and exempted==true → ERROR (≥1 SDK must be statically verified; prose can't be sole proof). Currently exactly 1 coverage-exempt (Lifecycle/add_relay_url kotlin, UniFFI-generated untracked file) with verified peers. 9 gate unit tests pass.
- Bridge/register TS=false+exemption CORRECT: no public bridgeRegister SDK fn (only on internal Bridge interface in internal/bridge.ts). Py/Kotlin/Swift true resolve to REAL distinct symbols (bridge.py:register, Kotlin bridgeRegister, Swift bridgeRegister — all grep-confirmed). Py alias ["register"] hits real bridge.py register.

## Findings (all LOW / not actionable)
- Coverage gate domain-prefix collision (theoretical): a true op X could pass if {domain}_{X} exists as an unrelated symbol. But by the strict domain-prefixed naming convention, such a symbol IS the wrapper by construction. Bounded, not exploitable. 250 cells match via auto domain-prefixed candidate — all genuine wrappers.
- evaluateTrust Layer2 thin facade: contexts/duration/governance hardcoded 0 (documented honesty gap, matches Python). Not security.
- Kotlin _walk recursive over-capture: acknowledged safe failure mode for fail-closed gate; bounded by closed ALIASES.

## Verdict: APPROVED — fail-closed by construction, format stable, Bridge/register correct. No BLOCKER/HIGH/MED.
