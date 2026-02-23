#!/usr/bin/env bash
# ─── Loom TaskOutput Blocker ───────────────────────────────────
# Prevents polling for subagent results during Loom loops.
# Background subagent results are delivered automatically by
# Claude Code — polling via TaskOutput causes JSONL transcript
# leaks that pollute the orchestrator's context window.
# Only active inside a Loom loop (LOOM_ACTIVE=1).
# ─────────────────────────────────────────────────────────────────

# No-op outside Loom
[ "$LOOM_ACTIVE" != "1" ] && exit 0

jq -n '{
  hookSpecificOutput: {
    hookEventName: "PreToolUse",
    permissionDecision: "deny",
    permissionDecisionReason: "Do not poll for subagent results. Wait for them to be delivered automatically."
  }
}'
