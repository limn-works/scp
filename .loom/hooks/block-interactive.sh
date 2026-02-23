#!/usr/bin/env bash
# ─── Loom Interactive Tool Blocker ─────────────────────────────
# Blocks EnterPlanMode and AskUserQuestion during autonomous Loom
# runs. No human is present — execute directly.
# Only active inside a Loom loop (LOOM_ACTIVE=1).
# ─────────────────────────────────────────────────────────────────

# No-op outside Loom
[ "$LOOM_ACTIVE" != "1" ] && exit 0

jq -n '{
  hookSpecificOutput: {
    hookEventName: "PreToolUse",
    permissionDecision: "deny",
    permissionDecisionReason: "No human is present. Execute directly."
  }
}'
