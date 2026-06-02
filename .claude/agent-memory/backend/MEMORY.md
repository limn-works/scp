# Backend Agent Memory (scoped)

- [project-adr-049-commit-4](project_adr_049_commit_4.md) — active work: ADR-049 actor-per-context, commit 4 (new traits + prod impls)
- [project-adr-049-phase-2a8-governance](project_adr_049_phase_2a8_governance.md) — Phase 2A.8 governance multi-commit ladder: scaffold/strip/migrate-incrementally pattern for ~6K LOC modules
- [project-adr-049-storage-foundation-step1](project_adr_049_storage_foundation_step1.md) — storage-foundation Step 1 (commit e8975ce05): mls_storage provider, build_actor_deps self-source, pub(in crate::context) test relocation, --no-verify mid-ladder, bridge worklist for Steps 2-4
- [feedback-worktree-absolute-path](feedback_worktree_absolute_path.md) — always use worktree path for edits; bare /Users/alec/Developer/limn/scp/ is main
- [feedback-no-git-checkout-paths](feedback_no_git_checkout_paths.md) — never `git stash` + `git checkout origin/X -- path/` to verify baseline; destroys uncommitted edits silently
- [feedback-read-tool-stale-verify-with-awk](feedback_read_tool_stale_verify_with_awk.md) — Read tool can return stale content disagreeing with disk; verify load-bearing lines with awk/grep before editing
- [project-adr-049-storage-foundation-step2](project_adr_049_storage_foundation_step2.md) — storage-foundation Step 2 (PyO3): mls_storage threading, fail-closed, SqliteKeyMaterial passphrase; NAPI/UniFFI only remaining broken; 3+3+4 pre-existing failures flagged
