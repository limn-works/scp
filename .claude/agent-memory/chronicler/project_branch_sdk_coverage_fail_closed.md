---
name: project-branch-sdk-coverage-fail-closed
description: Branch fix/sdk-coverage-fail-closed-and-parity — what it actually authored vs stale-base noise; ADR-051 added; check-sdk-coverage.py made fail-closed
metadata:
  type: project
---

Branch `fix/sdk-coverage-fail-closed-and-parity` (HEAD 1f4da9f3b as of 2026-06-20 review).

**What this branch actually authored** (vs `0c8f0b065`, the true merge-base) — only 3 `.docs/` files:
- ADR-051 (new, +100): pre-rotation custody substrate isolation, Status: Proposed. Closes the FFI callback-custody gap where pre-rotation key lands in `InMemoryPreRotationCustody` (same process memory) violating spec §9.7.4.1 §3 substrate isolation, plus the `import_ed25519_signing_key` Unsupported block that makes callback-custody migration unreachable. All spec/ADR/code refs verified accurate.
- sdk-capability-matrix.json (+7/-3): corrected rotate_key exemption reasons (bridge DOES export it; no SDK wrapper yet) + added a `coverage_exemptions` entry for Kotlin `addRelay` (generated UniFFI binding, not git-tracked, tree-sitter can't match).
- CLAUDE.md (+1): added `scripts/check-sdk-coverage.py` to the NEVER-modify-enforcement-files list. Correct — the script is now fail-closed.
- Plus code: made `check-sdk-coverage.py` fail-closed (true cells with no symbol + no `coverage_exemptions` → ERROR), removed suffix/substring matching (~23 fabricated names had passed via suffix collision), added `coverage_exemptions` escape hatch + all-exempted guard (≥1 SDK must be statically verified), added `scripts/test_check_sdk_coverage.py` (6 tests). Gate passes 0 errors on 221 ops; tests pass.

**Why:** SDK parity gaps + a coverage gate that string-matched too loosely.

**How to apply:** **CRITICAL — branch is 32 commits behind origin/main; merge-base is 0c8f0b065.** `git diff origin/main..HEAD` is MISLEADING: it shows huge deletions (reconnect.rs, heartbeat, saga handlers, OwnedIdentityDid AST-gate text in ADR-049 §5) that are STALE-BASE artifacts, NOT this branch's work. In particular origin/main #1826 already DROPPED the OwnedIdentityDid AST gate for compiler enforcement; this branch predates it and would appear to "revert" it. MUST `git rebase origin/main` before any merge, then re-diff with the two-dot against the new base. Use `git diff 0c8f0b065..HEAD -- <path>` to see only branch-authored changes. This matches the repo lesson [[lesson-rebase-before-merge]] (worktree branches cut before other PRs land revert them on squash).
