---
name: pr2141-r25-final-signoff
description: PR #2141 sdk-coverage-fail-closed-and-parity — final completionist pass @13aecbbbb; branch-new tests now GREEN, sole finding is a test-docstring overclaim
metadata:
  type: project
---

# PR #2141 R25 final completionist sign-off (@13aecbbbb)

**UPDATE @28623a226 (Pass 1 double-zero, 2 new commits a20eb5314+28623a226): COMPLETE/LGTM.**
The SOLE prior finding (docstring overclaim "Every SCP method wraps mapBridgeError")
is RESOLVED: scp-typed-errors.test.ts docstring now honestly scopes to "methods in
this PR's scope. Unmapped methods surface a bare Error; broadening coverage is tracked
in issue #2157." Python a20eb5314 wraps 8 methods via new centralized errors.py
`_coded_bridge_error` (identity_execute_recovery/identity_remove/context_member_count/
context_send/ucan_validate/governance_propose/event_log_query/outlet_invoke); trust.py
now IMPORTS it (deletes its local copy) AND the centralized regex is HARDENED from
unanchored `\[(SCP-...)` to anchored `^\s*\[(SCP-...)` — matches TS mapBridgeError
anchor discipline; safe because PyO3 formats `[code] category error: ...` (code at pos 0).
TS 28623a226 migrates 5 async methods (contextSend/contextMemberCount/
contextGovernancePropose/outletInvoke/ucanValidate) from `this.#native` to
`getBridge(this)` so wrapBridgeErrors Proxy maps them for free — VERIFIED signature-
clean against Bridge interface (contextSend normalizes payload→Uint8Array + spendingUcan
`?? null`; outletInvoke 7-arg order matches). eventLogQuery correctly NOT migrated
(getBridge sig takes EventFilter, SDK takes string filterJson) but STILL wrapped via
inline `throw mapBridgeError` at scp.ts:2452 → parity with Python event_log_query holds.
economy_verify_payment_receipts UNWRAPPED in BOTH Python (scp.py:2204) and TS
(scp.ts:2642 raw #native sync) = symmetric, present in matrix, gate checks presence not
wrapping ⇒ NOT a gap. Gate PASS 235 ops/0 err/0 empty cells; ALIASES Bridge/register
comment change accurate (bridgeRegister genuinely public bridge.ts:79 + index.ts:131,
matched by domain_camel auto-candidate). napi runtime.rs diff = main-merge nomenclature
rename (BridgeInMemoryStorage→EventLogInMemoryStorage), inert. ruff clean. CONSIDER
(pre-existing, #2157): TS gets typed errors for ~ALL getBridge methods free via Proxy
while Python hand-wraps only 8 ⇒ structural Python<TS wrapping-surface asymmetry; no
spec mandates uniformity, legitimately scoped to #2157, NOT introduced by this PR.

SUPERSEDES [[pr2141-r25-branch-new-tests-red]] — the RED blockers are FIXED.
Worktree /tmp/scp-review-r25 on `fix/sdk-coverage-fail-closed-and-parity`.

**Stale-base trap:** local `main`=3c168 is NOT origin/main=f2cee (origin/main NOT
ancestor of HEAD; branch merged an older origin/main at 3e8a29707). `git diff main...HEAD`
includes the whole merged main. Isolate branch work via `git show <sha>:` on the
post-merge commits, not the 3-dot diff.

## Verified COMPLETE
- **Coverage gate** (check-sdk-coverage.py): private-symbol filter at all 5 Python
  name-collection sites (`_extract_python_symbols` x2 top-level, `_extract_python_class`
  name-skip, `_extract_python_methods_from_block` x2). `startswith("_")` covers both
  `_name` and `__name`. TS/Kotlin/Swift already gate on export/visibility — Python was
  the only over-collector. Gate PASS 235 ops / 0 errors. Self-test 23/23 incl 3 new
  private-exclusion unit tests.
- **CapabilityValidation 6 fields** (tokens_valid, signatures_valid, within_ceiling,
  nonce_valid, not_revoked, time_bounds_valid) consistent: core validate.rs:977 → PyO3
  src/ucan.rs → NAPI napi/src/ucan.rs (camelCased) → UniFFI bridge.rs:1774 → Python
  trust.py (snake) → TS scp.ts (camel). toCapabilityValidation (bridge.ts:54) pins the
  shape in ONE place.
- **ucan_evaluate** exported PyO3 (ucan.rs:395) / NAPI (ucan_evaluate_on :356) / UniFFI
  (bridge.rs:14924), all with REQUIRED (non-defaulting) presenting_agent_did; Swift/Kotlin
  consume via UniFFI. Matrix UCAN/evaluate aliased for all 4 SDKs.
- **Tests non-vacuous**: scp-typed-errors mock STUBS bridge to reject, asserts SDK method
  rewraps into typed ScpError subclass (fails if unwrapped). TS 32/32 pass, Python parity
  7/7 pass (prior 3 RED fixed: async removed from sync discover_contexts, mock repointed to
  ucan_evaluate).
- **Lesson** (ucan-validate-needs-real-capability-uri.md) matches actual signatures EXACTLY:
  trust.py:990 `ucan_evaluate(context_id, token, None, subject_did)`, scp.ts:2881
  `ucanEvaluate(handle, token, subjectDid)`. Superseded att[0]/__extractFirstCapabilityUri
  content correctly marked Historical at top banner.
- **Regex anchors** consistent: errors.ts `/^\s*\[(SCP-[A-Z]+-\d+)\]/` == trust.py
  `r"^\s*\[(SCP-[A-Z]+-\d+)\]"` (re.search + `^` no-MULTILINE = match-at-start).
- **runtime.rs cfg-gate** (#[cfg(feature="allow_in_memory_custody")]) legit test fix, not
  an enforcement file. **getBridge restore** for 5 identity methods is REAL: createNativeBridge
  returns wrapBridgeErrors(bridge) (native.ts:2127), so those methods get typed errors via
  the Proxy chokepoint in production, not just under the mock.

## SOLE FINDING (artifact divergence, SHOULD-FIX)
scp-typed-errors.test.ts docstring claims "Every `SCP` method that forwards to the native
NAPI bridge wraps the call in try/catch mapBridgeError." FALSE. Two dispatch surfaces:
- `getBridge()` path → wrapBridgeErrors Proxy (central typed mapping).
- `this.#native` RAW addon (comment scp.ts:634 says "~180 methods use this.#native directly")
  → typed ONLY if inline mapBridgeError. Only ~10 of ~199 `this.#native.*` sites wrap.
So ~170 SDK methods surface bare `Error` not typed ScpError, contradicting the docstring +
sdk-common.md error hierarchy. Non-uniform WITHIN families: ucanValidate/Evaluate typed but
ucanMint/Delegate/Revoke not; contextGovernancePropose typed but Approve/Reject/Withdraw not;
identityRotateKey/Migrate typed (getBridge) but identityCreate/Load not (this.#native). NO
spec/story mandates uniformity ⇒ the ~170 untyped is pre-existing (CONSIDER: migrate
this.#native methods to getBridge for free central mapping, as the 5 identity methods were).
The concrete branch-introduced defect is the overclaiming docstring (the test file is NEW on
the branch). Fix: correct docstring to describe actual contract (specific set + Proxy), or
broaden wrapping.

LESSON: TS SDK has TWO error-mapping surfaces — wrapBridgeErrors Proxy (getBridge path only)
vs inline mapBridgeError (this.#native path). `this.#native` is the RAW unwrapped addon.
Count `this.#native.*` sites vs inline mapBridgeError to measure true typed-error coverage;
don't trust a "every method wraps" claim.
