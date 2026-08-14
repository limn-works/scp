---
name: pr2141-r25-merge-resolution
description: PR#2141 post-merge-conflict-resolution @3e8a29707 — NO BLOCKER; private-symbol gate hardening + test-guard.ts bridge-swap control both sound
metadata:
  type: project
---

# PR#2141 @3e8a29707 (fix/sdk-coverage-fail-closed-and-parity, post origin/main merge)

**Verdict: NO BLOCKER.** Merge of origin/main (156 commits: ADR-055 WASM removal, ADR-057 typed capability/trust) resolved cleanly.

**Why:** Branch is ~40 commits, most areas RESISTANT in prior rounds. This pass re-verified at the merged HEAD.
**How to apply:** If re-attacking this branch, these are already checked-clean at 3e8a29707.

## Verified clean this pass
- **Coverage gate private-symbol exclusion** (commit adfe9c710, closes my prior BLACK-R25-2): `_extract_python_symbols` now drops `_`-prefixed names. STRICTLY fail-closed — removing matchable symbols can only turn a true-cell into ERROR, never a false→pass. Gate PASSES (235 ops, 0 errors); 23 gate tests pass. No currently-true cell relied on a `_`-led Python symbol; no ALIASES target is underscore-led.
- **test-guard.ts** (NEW runtime security control, genuinely load-bearing): the bridge-swap hook `__setBridgeForTests` (supply-chain vector — malicious dep swapping native crypto bridge) calls `assertTestEnvironment`. Guard is frozen at module load (`_IS_TEST_ENVIRONMENT = _evaluateTestEnv(_ENV_AT_LOAD)`), fail-closed on absent process/NODE_ENV, `Object.hasOwn`-guarded vs prototype pollution. Runtime env mutation can't flip it.
- **Trust facade supersession**: scp.py Display-string classification (my prior BLACK-R25-1 [SCP-PERM-3001] allowlist) is GONE — replaced by ADR-057 typed path. No dangling reference. scp.py branch-unique add = `economy_verify_payment_receipts` (bounded 10k, honest ok≠valid docstring).
- **No conflict markers** in code (only `=======` RST underline in docs/index.rst, benign).
- **Insecure participation-verifier twins** (Kotlin 7097938f5 / Swift 23779139f) stayed DELETED post-merge; surviving `verifyParticipationRequirements` route to Rust core via UniFFI (ScpBindings.swift:17143 / uniffi.scp).
- **mapBridgeError** anchored regexes (`/^\s*\[.../`) + `startsWith(prefix)` present in errors.ts.

## LOW observation (not a finding)
test-guard treats `NODE_ENV=development` as trusted-enough to allow the native-bridge swap. Misconfigured prod running NODE_ENV=development would re-enable the hook for a co-resident malicious dep. Honestly documented in the docstring; net-new hardening over no guard. A stricter build could require an explicit opt-in flag instead of NODE_ENV=development. Defense-in-depth only.
