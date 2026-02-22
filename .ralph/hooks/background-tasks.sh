#!/usr/bin/env bash
# ─── Ralph Background Task Launcher ────────────────────────────
# Forces all Task tool calls to run in background during Ralph
# loops. The orchestrator dispatches subagents and continues —
# results are delivered automatically on the next turn.
# Only active inside a Ralph loop (RALPH_ACTIVE=1).
# ─────────────────────────────────────────────────────────────────

# No-op outside Ralph
[ "$RALPH_ACTIVE" != "1" ] && exit 0

INPUT=$(cat)

# If already set to background, pass through
ALREADY_BG=$(echo "$INPUT" | jq -r '.tool_input.run_in_background // false')
[ "$ALREADY_BG" = "true" ] && exit 0

# Inject run_in_background: true into the tool input
UPDATED=$(echo "$INPUT" | jq '.tool_input.run_in_background = true')

jq -n --argjson updated "$UPDATED" '{
  hookSpecificOutput: {
    hookEventName: "PreToolUse",
    updatedInput: $updated.tool_input
  }
}'
