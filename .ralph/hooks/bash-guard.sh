#!/usr/bin/env bash
# ─── Ralph Bash Guard ────────────────────────────────────────────
# Blocks destructive shell commands during autonomous Ralph runs.
# Only active inside a Ralph loop (RALPH_ACTIVE=1).
# ─────────────────────────────────────────────────────────────────

# No-op outside Ralph
[ "$RALPH_ACTIVE" != "1" ] && exit 0

INPUT=$(cat)
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty')

[ -z "$COMMAND" ] && exit 0

# ─── Blocked patterns ────────────────────────────────────────────
# Each pattern is an extended regex checked against the full command.

BLOCKED=(
  'rm\s+-rf\s+/'
  'rm\s+-rf\s+~'
  'rm\s+-rf\s+\.\s*$'
  'git\s+push\s+.*--force'
  'git\s+push\s+-f\b'
  'git\s+reset\s+--hard'
  'git\s+clean\s+-f'
  'git\s+checkout\s+\.\s*$'
  'git\s+restore\s+\.\s*$'
  'git\s+branch\s+-D'
  'git\s+add\s+-A'
  'git\s+add\s+\.\s*$'
  'chmod\s+-R\s+777'
  'mkfs\.'
  '>\s*/dev/sd'
  'dd\s+if=.*of=/dev'
)

# Fast path: single combined regex check avoids 14 forks on every Bash call
BLOCKED_RE=$(IFS='|'; echo "${BLOCKED[*]}")
if echo "$COMMAND" | grep -qE "$BLOCKED_RE"; then
  # Match found — identify which pattern for the deny reason
  for pattern in "${BLOCKED[@]}"; do
    if echo "$COMMAND" | grep -qE "$pattern"; then
      jq -n --arg reason "Destructive command blocked by Ralph safety guard: matched pattern '$pattern'" '{
        hookSpecificOutput: {
          hookEventName: "PreToolUse",
          permissionDecision: "deny",
          permissionDecisionReason: $reason
        }
      }'
      exit 0
    fi
  done
fi

exit 0
