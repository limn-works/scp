#!/usr/bin/env bash
# ─── Ralph Interactive Tool Blocker ─────────────────────────────
# Blocks EnterPlanMode and AskUserQuestion during autonomous Ralph
# runs. No human is present — execute directly.
# Only active inside a Ralph loop (RALPH_ACTIVE=1).
# ─────────────────────────────────────────────────────────────────

# No-op outside Ralph
[ "$RALPH_ACTIVE" != "1" ] && exit 0

jq -n '{
  hookSpecificOutput: {
    hookEventName: "PreToolUse",
    permissionDecision: "deny",
    permissionDecisionReason: "No human is present. Execute directly."
  }
}'
