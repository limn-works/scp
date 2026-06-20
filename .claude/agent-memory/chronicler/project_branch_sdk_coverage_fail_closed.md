---
name: project-branch-sdk-coverage-fail-closed
description: Branch fix/sdk-coverage-fail-closed-and-parity — what it actually authored vs stale-base noise; ADR-051 added; check-sdk-coverage.py made fail-closed
metadata:
  type: project
---

Branch `fix/sdk-coverage-fail-closed-and-parity` (HEAD 681de196a as of 2026-06-20 re-review, post-rebase).

**What this branch actually authored** (vs `0c8f0b065`, the true merge-base) — only 3 `.docs/` files:
- ADR-051 (new, +100): pre-rotation custody substrate isolation, Status: Proposed. Closes the FFI callback-custody gap where pre-rotation key lands in `InMemoryPreRotationCustody` (same process memory) violating spec §9.7.4.1 §3 substrate isolation, plus the `import_ed25519_signing_key` Unsupported block that makes callback-custody migration unreachable. All spec/ADR/code refs verified accurate.
- sdk-capability-matrix.json (+7/-3): corrected rotate_key exemption reasons (bridge DOES export it; no SDK wrapper yet) + added a `coverage_exemptions` entry for Kotlin `addRelay` (generated UniFFI binding, not git-tracked, tree-sitter can't match).
- CLAUDE.md (+1): added `scripts/check-sdk-coverage.py` to the NEVER-modify-enforcement-files list. Correct — the script is now fail-closed.
- Plus code: made `check-sdk-coverage.py` fail-closed (true cells with no symbol + no `coverage_exemptions` → ERROR), removed suffix/substring matching (~23 fabricated names had passed via suffix collision), added `coverage_exemptions` escape hatch + all-exempted guard (≥1 SDK must be statically verified), added `scripts/test_check_sdk_coverage.py` (6 tests). Gate passes 0 errors on 221 ops; tests pass.

**Why:** SDK parity gaps + a coverage gate that string-matched too loosely.

**How to apply:** RESOLVED 2026-06-20 — branch is now **REBASED onto origin/main**: merge-base = `dabf13364` (== origin/main HEAD), `HEAD..origin/main` = 0 commits behind, two-dot and three-dot diffs are IDENTICAL (57 files, +3954/-462, no stale-base deletions). The earlier stale-base trap (huge phantom deletions of reconnect.rs/heartbeat/saga handlers/OwnedIdentityDid AST-gate text from predating #1826) is GONE. `git diff origin/main...HEAD` is now safe to read directly. Diff also (correctly) includes `crates/scp-runtime/src/crypto/mls/provider.rs` (14 stale MlsCryptoProvider doc-comments corrected — no crypto trait exists post-actor-refactor) and `.github/workflows/ci.yml` (+2: runs `scripts/test_check_sdk_coverage.py` gate self-tests before the gate). Repo lesson [[lesson-rebase-before-merge]] held (rebase before merge avoids squash-revert).
