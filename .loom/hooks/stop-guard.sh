#!/usr/bin/env bash
# ─── Loom Stop Guard ────────────────────────────────────────────
# Blocks the agent from exiting until status.md has been updated
# this iteration. Also nudges about docs and memory.
# Only active inside a Loom loop (LOOM_ACTIVE=1).
# ─────────────────────────────────────────────────────────────────

# No-op outside Loom
[ "$LOOM_ACTIVE" != "1" ] && exit 0

# No enforcement in dry-run
[ "$LOOM_DRY_RUN" = "1" ] && exit 0

INPUT=$(cat)

# Safety valve: if a stop hook already blocked this cycle, let it
# through to prevent infinite loops.
STOP_ACTIVE=$(echo "$INPUT" | jq -r '.stop_hook_active // false')
[ "$STOP_ACTIVE" = "true" ] && exit 0

# ─── Check: status.md updated this iteration ─────────────────────
# start.sh touches .iteration_marker at the start of each iteration.
# If status.md is older than the marker, the agent skipped the status update.

LOOM_DIR="${CLAUDE_PROJECT_DIR:-.}/.loom"

if [ -f "$LOOM_DIR/.iteration_marker" ]; then
  if [ ! -f "$LOOM_DIR/status.md" ] || [ "$LOOM_DIR/status.md" -ot "$LOOM_DIR/.iteration_marker" ]; then
    cat >&2 <<'MSG'
You have not updated .loom/status.md this iteration.

You must write a fresh status report before exiting:
  - Failing Tests (every currently-failing test)
  - Uncommitted Changes (if tests failed and code was not committed)
  - Fixed This Iteration (previously-failing tests now passing)
  - Tests Added / Updated
  - Outcomes (story ID or directive summary, pass/fail for each)

Ensure all commits (if tests pass), documentation updates, and memory storage
are done before writing status.md — the write triggers an immediate kill.
MSG
    exit 2
  fi
fi

# ─── Nudge: docs and memory ──────────────────────────────────────
# Always nudge. Advisory (block + continue), not a hard gate.

jq -n '{
  decision: "block",
  reason: "Before finishing, check if this iteration warrants updates to:\n\nDocumentation:\n  - Root .docs/ and CLAUDE.md for project-wide knowledge (ADRs, specs, lessons, architecture)\n  - Feature-scoped .docs/ and CLAUDE.md (e.g. src/auth/.docs/) for feature-specific design notes, API decisions, and internal conventions\n  Create feature-scoped .docs/ directories when a feature area has design context worth preserving close to the code.\n\nMemory:\n  - If you discovered patterns, gotchas, or architectural decisions worth preserving, store them using available memory storage or tools so future iterations can benefit."
}'
