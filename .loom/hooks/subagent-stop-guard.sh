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

# ─── Nudge: docs and memory ──────────────────────────────────────
# Always nudge. Advisory (block + continue), not a hard gate.

jq -n '{
  decision: "block",
  reason: "Before finishing, check if your work warrants updates to:\n\nDocumentation:\n  - Root .docs/ and CLAUDE.md for project-wide knowledge (ADRs, specs, lessons, architecture)\n  - Feature-scoped .docs/ and CLAUDE.md (e.g. src/auth/.docs/) for feature-specific design notes, API decisions, and internal conventions\n  Create feature-scoped .docs/ directories when a feature area has design context worth preserving close to the code.\n\nMemory:\n  - If you discovered patterns, gotchas, or architectural decisions worth preserving, store them using available memory storage or tools so future iterations can benefit."
}'
