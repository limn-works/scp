---
name: sdk-coverage-failclosed-parity-ae8a306aa
description: Review of fix/sdk-coverage-fail-closed-and-parity @ ae8a306aa — prior LOW-1 (step 4b) CLOSED, PERM-3030 Python parity, §3.2.1→§9.12 surgical corrections
metadata:
  type: project
---

# fix/sdk-coverage-fail-closed-and-parity @ `ae8a306aa` (2026-06-21) — APPROVED (1 LOW carry-note)

7 commits past prior-round `1ed31cd8c` (see [[sdk-coverage-failclosed-parity-1ed31cd8c]]). Verdict APPROVED. The prior round's LOW-1 ("§9.12 step 4b" malformed citation, inconsistently fixed) is now FULLY CLOSED.

**Why:** Confirms convergence of the citation-cleanup + PERM-3030 parity; substrate for future rounds.
**How to apply:** Reuse the §9.12-vs-§3.2.1 distinction and the PERM-3030 parity verification chain.

## Prior LOW-1 CLOSED
- `git grep "step 4b"` across bindings/crates/docs = **NONE**. All §9.12 citations now clean form `spec §9.12, ADR-003 §4b`.
- `2d532a57b` §3.2.1→§9.12 corrections are SURGICAL: only DID-CHANGING migrate paths moved (wasm `WasmIdentityMigrationResult` rustdoc, kotlin example `migrateWithRotationEvent`, scp.py rotation_event). DID-PRESERVING custody-migration paths RETAIN §3.2.1 correctly (scp.py:639, Identity.kt:382 "5-step", napi/scp.rs:1242, ffi/identity.rs:2166). The §-distinction held precisely.
- `ae8a306aa` removed a doubled "§9.12 / §9.12, ADR-003 §4b" in IdentityAdvancedBridgeTest.kt:254 (cosmetic dedup).

## PERM-3030 parity (02cf55597) — GENUINE + behaviorally exact
- Python `evaluate_trust` (trust.py:762) adds `if error_msg.startswith("[SCP-PERM-3030]"): raise` BEFORE `_classify_ucan_error`. Was silently absorbing handle-affinity (caller-misuse) into a false all-False CapabilityValidation.
- Mirrors TS trust.ts:461 `if (/^\[SCP-PERM-3030\]/.test(msg)) throw error;` — same logical point (pre-classification), same semantics.
- Verified emission chain: PyO3 `From<HandleAffinityError> for ScpPyError` (error.rs:737) → `UcanError`/permission class, code `PERM_3030="SCP-PERM-3030"`; Display = `[{code}] permission error: {msg}` (error.rs:158) → rendered `[SCP-PERM-3030] permission error: ...` so `startswith("[SCP-PERM-3030]")` matches. Python errors.py:113 maps `UcanError`→`UcanPermissionError`; `bridge.UcanError` is what the catch covers. Bare `raise` re-propagates the same instance. Sound.
- Note: TS regex-anchored vs Python startswith — functionally identical.

## fbc6f9e22 test alignment — honest, NOT weakening
- trust.test.ts contextsParticipated `1`→`0`: aligns assertion to the honest-default change (fabricated `=1` removed prior round). toolInvocations len=2 unchanged. STRONGER truth-claim.
- discovery.py `DiscoveryResult(**dict(item))`→`cast(DiscoveryResult, dict(item))`: TypedDict-correct construction, drops `type: ignore`, runtime-identical. Improvement.

## Gate + lint verified on THIS HEAD
- `check-sdk-coverage.py`: EXIT 0, 222 ops, 0 errors, 1 legit coverage-exempt (kotlin `add_relay_url`/`addRelay` — tree-sitter-kotlin grammar can't parse generated backtick `@Throws` override nodes; documented), 0 all-exempted.
- `test_check_sdk_coverage.py` via pytest: **9 passed**.
- ruff check on touched python: clean.
- ADR-051 Status **Proposed**; ZERO impl leaked (grep PreRotationCustodyProvider/CallbackPreRotationCustody/import_seed_bytes in branch diff = empty). Correct spec-before-code sequencing.

## LOW (carry-note): one retained #1549 issue-ref
TS comment line 1880 (`internal/native.ts` family) retains `(#1549, ADR-048)` in a reworded line, while the SAME branch REMOVES `#1549` on 3 other lines (1875, 2160, 2564). Net effect = fewer issue refs (good). Per the no-issue-refs-in-code feedback, that one should also drop `#1549`. Pre-existing reference carried into a reworded line, not net-new — minor.
