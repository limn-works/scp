#!/usr/bin/env bash
# ─── Ralph TaskOutput Blocker ───────────────────────────────────
# Prevents polling for subagent results during Ralph loops.
# Background subagent results are delivered automatically by
# Claude Code — polling via TaskOutput causes JSONL transcript
# leaks that pollute the orchestrator's context window.
# Only active inside a Ralph loop (RALPH_ACTIVE=1).
# ─────────────────────────────────────────────────────────────────

# No-op outside Ralph
[ "$RALPH_ACTIVE" != "1" ] && exit 0

jq -n '{
  hookSpecificOutput: {
    hookEventName: "PreToolUse",
    permissionDecision: "deny",
    permissionDecisionReason: "Do not poll for subagent results. Wait for them to be delivered automatically."
  }
}'
