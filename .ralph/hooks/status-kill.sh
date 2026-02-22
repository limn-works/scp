#!/usr/bin/env bash
# ─── Ralph Status Kill ───────────────────────────────────────────
# Terminates the Claude instance the moment status.md is written.
# This is the hard guarantee that the loop actually loops — the
# agent cannot ignore this or "decide" to keep going.
# ─────────────────────────────────────────────────────────────────

# No-op outside Ralph
[ "$RALPH_ACTIVE" != "1" ] && exit 0

# No enforcement in dry-run
[ "$RALPH_DRY_RUN" = "1" ] && exit 0

INPUT=$(cat)
FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty')

if [[ "$FILE_PATH" == *"/.ralph/status.md" ]]; then
  jq -n '{
    continue: false,
    stopReason: "Iteration complete — status.md written. Restarting loop."
  }'
  exit 0
fi

exit 0
