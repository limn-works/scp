---
name: sdk-coverage-failclosed-parity-review
description: Black-hat review of fix/sdk-coverage-fail-closed-and-parity (mapBridgeError, fail-closed coverage gate, test-guard hardening, SDK parity)
metadata:
  type: project
---

# Review: fix/sdk-coverage-fail-closed-and-parity

Branch `origin/fix/sdk-coverage-fail-closed-and-parity` (HEAD fc0b53543). Note: review worktree was checked out on a DIFFERENT branch (feat/actor-2c-xctx-tool-saga) — had to read review files via `git show origin/<branch>:path`. The on-disk scripts/check-sdk-coverage.py was the OLD version (still had suffix-match bypass); the review branch's version is hardened. ALWAYS verify which branch the working tree holds.

## Verdict: clean — mostly hardening. No CRITICAL/HIGH.

### Confirmed hardenings (not regressions)
- **test-guard fail-closed flip**: OLD `assertTestHookAllowed` blocked only `NODE_ENV==="production"` (denylist — unset/staging/empty all PASSED, letting `__constructScpWithNativeForTests` native-bridge injection run in prod-without-flag). NEW `assertTestEnvironment` (bindings/typescript/src/internal/test-guard.ts) is a positive allowlist: pass only if NODE_ENV in {test,development} OR BUN_TEST non-empty. Frozen at module load (runtime env mutation can't flip). Uses Object.hasOwn (prototype-pollution safe). Closes RED-PR5-007.
- **coverage gate suffix-match removal**: OLD gate (`_check_operation_in_sdk`) had step-3 suffix matching + bare op_name/camel/pascal/py_prefixed candidates → cross-domain collision (e.g. `scopeRegister` satisfied `Tools/register`; `Backdoor/send` satisfied bare `send`). REVIEW BRANCH removed suffix-match + bare candidates; only ALIASES + domain-prefixed exact match. Verified: `Backdoor/send` now False, legit alias still True.
- **all-exempted guard**: coverage_exemptions (prose escape hatch) is bounded — if ALL true-SDKs are exempted with none statically verified → ERROR. At least one SDK must be AST-verified. Sound.
- gate wired into CI (.github/workflows/ci.yml) + self-tests run first. Extraction failure = fail-closed (true entries become unmatched → exit 1).

### Non-findings verified
- quinn-proto: branch commit d0ace52 bumped 0.11.14→0.11.15, but origin/main already at 0.11.15 → net diff has NO quinn change. CVE RUSTSEC-2026-0185 fixed regardless. checksum matches registry.
- mapBridgeError regex `/\[([A-Z]+-[A-Z]+-\d+)\]/` linear, no ReDoS. First-match-wins; attacker embedding fake code only mis-classifies the ScpError SUBCLASS (cosmetic) — op already failed at bridge, no authz impact. Full message preserved (no new leakage vs pre-existing raw-throw behavior).
- getBridge moved INSIDE try/catch for 5 handle-based identity methods (rotateKey/migrate/addAgentKey/rotateAgentKey/removeAgentKey) — load failure now typed consistently. Correct.
- trust evaluate_trust (py + ts): optimistic-start, classify-on-first-failure, `unknown`→all-False (fail-closed). Only all-True path is no-throw from ucan_validate. PERM-3030 re-raised (caller misuse not absorbed). Parity confirmed.
- discovery.py/economy.py: pure serialization wrappers, all enforcement delegated to Rust bridge. No injection/eval/shell. valid≠ok distinction documented (anti-confused-deputy).

### LOW
- CI pip-installs tree-sitter-{python,ts,kotlin,swift} UNPINNED. Future grammar node-type renames would silently shrink extraction → but fails CLOSED (true entries unmatched). Robustness, not exploitable. Consider pinning.
