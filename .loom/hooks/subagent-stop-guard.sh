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

# ─── Check: documentation updated ──────────────────────────────
# Nudge subagents to maintain .docs artifacts alongside code changes.
# This is advisory (block + continue), not a hard gate.

DOCS_REMINDER=""

# Check if the subagent touched code but didn't mention .docs updates
if echo "$MESSAGE" | grep -qiE '(created|added|implemented|built|wrote)' && \
   ! echo "$MESSAGE" | grep -qiE '(\.docs|documentation|ADR|adr|lessons)'; then
  DOCS_REMINDER="Documentation reminder: If your changes introduce new patterns, architectural decisions, or lessons learned, update the relevant .docs/ artifacts:
  - Root .docs/ for project-wide knowledge (ADRs, specs, lessons, architecture)
  - Localized .docs/ dirs (e.g. crates/scp-core/.docs/) for crate-specific design notes, API decisions, and internal conventions
  Create localized .docs/ directories when a crate has design context worth preserving close to the code."
fi

if [ -n "$DOCS_REMINDER" ]; then
  jq -n --arg reason "$DOCS_REMINDER" '{
    decision: "block",
    reason: $reason
  }'
  exit 0
fi

exit 0
