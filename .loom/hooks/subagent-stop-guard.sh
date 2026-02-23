#!/usr/bin/env bash
# ─── Loom Subagent Stop Guard ───────────────────────────────────
# Validates that a subagent produced meaningful output before
# the orchestrator accepts its result. Only active in Loom loops.
# ─────────────────────────────────────────────────────────────────

# No-op outside Loom
[ "$LOOM_ACTIVE" != "1" ] && exit 0

# No enforcement in dry-run
[ "$LOOM_DRY_RUN" = "1" ] && exit 0

INPUT=$(cat)

MESSAGE=$(echo "$INPUT" | jq -r '.last_assistant_message // empty')

# If the subagent produced no output at all, block so the
# orchestrator knows something went wrong.
if [ -z "$MESSAGE" ] || [ ${#MESSAGE} -lt 10 ]; then
  jq -n --arg reason "Subagent returned no meaningful output. Log this failure in status.md and continue with remaining work." '{
    decision: "block",
    reason: $reason
  }'
  exit 0
fi

exit 0
