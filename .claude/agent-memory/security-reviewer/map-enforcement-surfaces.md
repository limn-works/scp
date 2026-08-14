# MAP.md enforcement surfaces (branch worktree-codebase-map) — 2026-07-03

New map-freshness enforcement system. Files:
- scripts/check-map.py — structural + freshness gate (full / --diff / --staged / --status-areas)
- scripts/hooks/stop-map-freshness.sh — Stop hook, ADVISORY/fail-open, emits systemMessage
- scripts/hooks/pre-commit — fail-closed --staged step (coarse bash trigger + real gate)
- .claude/settings.json — new Stop hook wiring (follows CLAUDE_PROJECT_DIR quoted pattern)
- .github/workflows/ci.yml — map-check job (pull_request trigger, read-only token)

Findings from first review:
- MEDIUM: check_anchor symlink path traversal. `..`/absolute string guard on anchor does NOT
  stop a committed symlink under area_dir from resolving outside the tree; is_file()/read_text()
  follow it → blind file-content oracle + DoS in full mode (CI + local). Fix: realpath-confine
  target within area_dir.resolve(); don't follow symlinks. Tests have ZERO symlink coverage.
- LOW: Stop hook systemMessage carries attacker-influenced directory names (area = crates/<dir>)
  into agent/user surface. json.dumps CORRECTLY blocks structural/control-field injection;
  residual semantic prompt-injection limited by precondition (attacker dir must contain a
  session-changed file). Good mitigation, note residual.
- LOW: pre-commit NEEDS_MAP_CHECK coarse bash trigger uses unquoted `$STAGED_ALL`; git quotePath
  quoting of exotic filenames (newline/quote/non-ASCII) can skip the trigger → accidental
  fail-OPEN. Only defense-in-depth: CI map-check calls check-map.py directly (authoritative).
- LOW: ci.yml `git fetch origin ${{ github.base_ref }}` interpolates context into run script;
  base_ref is base-repo branch name (git-ref-constrained, not arbitrary) so low risk; prefer env binding.

Positive: pull_request (not _target) + read-only token = correct fork-PR posture. Stop hook
fail-open by construction (every path returns 0). python heredoc passes $areas as argv[1] quoted
(no shell injection). git subprocess uses list args, no shell=True.
