#!/usr/bin/env bash
# ─── Ralph Stop Guard ────────────────────────────────────────────
# Blocks the agent from exiting until status.md has been updated
# this iteration. Only active inside a Ralph loop (RALPH_ACTIVE=1).
# ─────────────────────────────────────────────────────────────────

# No-op outside Ralph
[ "$RALPH_ACTIVE" != "1" ] && exit 0

# No enforcement in dry-run
[ "$RALPH_DRY_RUN" = "1" ] && exit 0

INPUT=$(cat)

# Safety valve: if a stop hook already blocked this cycle, let it
# through to prevent infinite loops.
STOP_ACTIVE=$(echo "$INPUT" | jq -r '.stop_hook_active // false')
[ "$STOP_ACTIVE" = "true" ] && exit 0

# ─── Check: status.md updated this iteration ─────────────────────
# ralph.sh touches .iteration_marker at the start of each iteration.
# If status.md is older than the marker, the agent skipped the status update.

RALPH_DIR="${CLAUDE_PROJECT_DIR:-.}/.ralph"

if [ -f "$RALPH_DIR/.iteration_marker" ]; then
  if [ ! -f "$RALPH_DIR/status.md" ] || [ "$RALPH_DIR/status.md" -ot "$RALPH_DIR/.iteration_marker" ]; then
    cat >&2 <<'MSG'
You have not updated .ralph/status.md this iteration.

You must write a fresh status report before exiting:
  - Failing Tests (every currently-failing test)
  - Uncommitted Changes (if tests failed and code was not committed)
  - Fixed This Iteration (previously-failing tests now passing)
  - Tests Added / Updated
  - Outcomes (story ID or directive summary, pass/fail for each)

Also ensure all commits (if tests pass) and Vestige memory storage
are done before writing status.md — the write triggers an immediate kill.
MSG
    exit 2
  fi
fi

exit 0
