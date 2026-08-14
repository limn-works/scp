---
name: pr2141-final-postmerge-bc3d88eef
description: PR #2141 final post-merge alignment @ bc3d88eef — ALIGNED, zero findings; prior POST-MERGE SHOULD-FIX resolved, SCP-302 done, att[0] limitation genuinely superseded
metadata:
  type: project
---

# PR #2141 FINAL @ bc3d88eef (fix/sdk-coverage-fail-closed-and-parity, /tmp/scp-review-r25, 2026-07-16) — ALIGNED, ZERO FINDINGS

Delta = 8 commits past e78795e90 (my prior POST-MERGE review). All 5 alignment questions + delta verified clean.

**Prior POST-MERGE SHOULD-FIX (stale sketch.md:813-821 att[0] note) NOW RESOLVED** by 3de060e97: dropped the att[0]-only `withinCeiling` comment (referenced DELETED `_extractFirstCapabilityUri` helpers + SCP-302 as "open"). SCP-302 is now status=**done** (main.json), and the merge brought ADR-059 typed `ucan_evaluate` which owns att-enumeration in the bridge — `withinCeiling` now reflects WHOLE-TOKEN all-att evaluation. So the long-running att[0]-only tension (rounds 3-4, SCP-302) is GENUINELY superseded, not just deferred. Kept nonceValid/timeBoundsValid (correctly expand to real 6-field CapabilityValidation struct).

**5 alignment questions — all ALIGNED:**
1. **Private-symbol exclusion** (check-sdk-coverage.py `_extract_python_symbols` :1183, `not name.startswith("_")`) — correctly filters the AVAILABLE set (symbols that exist), NOT the required set. Makes gate STRICTER/fail-closed: a public matrix capability can't be satisfied by a private helper. Brings Python to parity w/ TS extractor. CORRECT per stated design.
2. **evaluate_trust → ucan_evaluate intrinsic mode** — ALIGNED w/ ADR-059 (phase-2.md:1962, renumbered from ADR-057 per PR#1995) + spec §7.2.4:128. Intrinsic mode (capability=None) SKIPS step-6 grant-match, still runs all-att step-8 ceiling over token's own `att` set, read-only nonce (not consumed). trust.py:100-175 CapabilityValidation extensively + correctly documented ("DIAGNOSTIC NEVER authorization"; matches spec §7.2.4:148 "diagnostic is never an authorization decision").
3. **discover_contexts Python wrapper** (discovery.py:132) — clean alias for `discover()`, result shape (query→list[dict] w/ context_id/source/relay_active/...) matches TS `discoverContexts(scp,query)→DiscoveryResult[]` (discovery.ts:281). Sync-vs-async + scp-threading are established per-SDK idiom (Python free fn calls bare `_scp_core.context_discover`; instance-independent client-side discovery).
4. **economy_verify_payment_receipts dict return** (956f8116b) — matches bridge economy.rs:454 EXACTLY: `{all_valid: bool, results: [{receipt_id, ok, valid, result}]}`. Fixed a REAL breakage: merge kept branch scp.py importing deleted `PaymentReceiptVerificationResult` from main's economy.py → whole Python SDK unimportable at module load. Removed stale import + fixed annotation/docstring.
5. **Spec gaps / ADR violations / story mismatches** — NONE. All commit-msg ADR refs backed by real ADRs in consolidated phase docs (ADR-055 WASM-removal @phase-4.md:1468; ADR-059 @phase-2.md:1962). WASM bridge genuinely deleted (wasm.ts gone). No phantom provenance.

**Other delta commits verified:**
- 13c9e444d + bc3d88eef: TS `mapBridgeError` + Python `_SCP_CODE_RE` regex anchored to `^\s*\[CODE\]` — defense-in-depth mirroring existing mapSagaError discipline (embedded code-like substring can't masquerade as real code at position 0). Sound, bounded.
- 730e512e5: wired try/catch→mapBridgeError to 8 SCP methods the branch's typed-error tests assert; "multi-att limitation historical" reframe CORRECT (old client-side evaluateLayer1 att[0] extraction superseded by bridge-owned ucan_evaluate per §7.2.4:128).
- a3a22a7fd: restored getBridge(this) routing for 5 identity lifecycle methods (enables __setBridgeForTests spy injection) + added `#[cfg(feature="allow_in_memory_custody")]` to runtime.rs test using FfiKeyCustody::InMemory (test-only cfg-gate, correct).
- d52a0ec23: test fix — removed spurious @pytest.mark.asyncio/await on SYNC discover_contexts; switched mock target ucan_validate→ucan_evaluate (post-ADR-059 route). Legit, not gaming.
- 3713b0e1c: **enforcement-file (check-sdk-coverage.py) change — SAFE.** Removed `("Bridge","register")` typescript alias `["bridgeRegister"]`. VERIFIED inert: candidate builder (:1604-1609) auto-derives `domain_camel = _to_camel("bridge_register") = "bridgeRegister"`, an exported TS symbol (index.ts:131). Gate required-set + matching byte-identical after removal — NOT a weakening/exemption. Consistent w/ sibling `("Bridge","evaluate_trust")` which relies on bridgeEvaluateTrust auto-candidate w/ no explicit TS alias. Python `["register"]` alias retained (bare "register" not domain_camel-derivable, load-bearing).

VERDICT: ALIGNED. Zero BLOCKER/SHOULD-FIX/CONSIDER. Prior POST-MERGE SHOULD-FIX closed. PR converged.
