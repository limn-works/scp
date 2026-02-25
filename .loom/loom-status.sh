#!/usr/bin/env bash
set -euo pipefail

# ─── Loom Status: Run Summary ──────────────────────────────────
# Parses master.log and status.md to display a summary of the
# current or most recent Loom run.
# ─────────────────────────────────────────────────────────────────

LOOM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_NAME="$(basename "$(dirname "$LOOM_DIR")")"
TMUX_SESSION="loom-${PROJECT_NAME}"
MASTER_LOG="$LOOM_DIR/logs/master.log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ─── Check if Loom is running ──────────────────────────────────
echo -e "${CYAN}${BOLD}Loom Status${NC}"
echo -e "${DIM}─────────────────────────────────────────${NC}"

if tmux has-session -t "$TMUX_SESSION" 2>/dev/null; then
  echo -e "  Status:  ${GREEN}${BOLD}RUNNING${NC} (tmux session: $TMUX_SESSION)"
else
  echo -e "  Status:  ${DIM}NOT RUNNING${NC}"
fi

# ─── Master log summary ────────────────────────────────────────
if [ ! -f "$MASTER_LOG" ]; then
  echo -e "\n  ${DIM}No master.log found. Loom hasn't run yet.${NC}"
  exit 0
fi

echo ""
echo -e "${CYAN}${BOLD}Iteration Summary${NC}"
echo -e "${DIM}─────────────────────────────────────────${NC}"

TOTAL=$(wc -l < "$MASTER_LOG" | tr -d ' ')
SUCCESS=$(grep -c '| exit-0 |' "$MASTER_LOG" 2>/dev/null || true)
TIMEOUT=$(grep -c '| timeout |' "$MASTER_LOG" 2>/dev/null || true)
HALTED=$(grep -c '| HALTED |' "$MASTER_LOG" 2>/dev/null || true)
FAILURES=$((TOTAL - SUCCESS - TIMEOUT - HALTED))
[ "$FAILURES" -lt 0 ] && FAILURES=0
TOTAL_SUBAGENTS=$(grep -oE 'subagents:[0-9]+' "$MASTER_LOG" 2>/dev/null | \
  awk -F: '{s+=$2} END {print s+0}' || echo 0)

echo -e "  Total iterations: ${BOLD}$TOTAL${NC}"
echo -e "  Succeeded:        ${GREEN}$SUCCESS${NC}"
echo -e "  Failed:           ${RED}$FAILURES${NC}"
echo -e "  Timed out:        ${YELLOW}$TIMEOUT${NC}"
echo -e "  Total subagents:  ${CYAN}$TOTAL_SUBAGENTS${NC}"

# Signal breakdown
SIG_SUCCESS=$(grep -cE '\| SUCCESS( \||$)' "$MASTER_LOG" 2>/dev/null || true)
SIG_PARTIAL=$(grep -cE '\| PARTIAL( \||$)' "$MASTER_LOG" 2>/dev/null || true)
SIG_FAILED=$(grep -cE '\| FAILED( \||$)' "$MASTER_LOG" 2>/dev/null || true)

echo ""
echo -e "${CYAN}${BOLD}Result Signals${NC}"
echo -e "${DIM}─────────────────────────────────────────${NC}"
echo -e "  SUCCESS:  ${GREEN}$SIG_SUCCESS${NC}"
echo -e "  PARTIAL:  ${YELLOW}$SIG_PARTIAL${NC}"
echo -e "  FAILED:   ${RED}$SIG_FAILED${NC}"

# ─── Last 5 iterations ─────────────────────────────────────────
echo ""
echo -e "${CYAN}${BOLD}Recent Iterations${NC}"
echo -e "${DIM}─────────────────────────────────────────${NC}"
tail -5 "$MASTER_LOG" | while IFS='|' read -r ts iter label status duration reason subagents; do
  # Trim whitespace
  ts=$(echo "$ts" | xargs)
  iter=$(echo "$iter" | xargs)
  label=$(echo "$label" | xargs)
  status=$(echo "$status" | xargs)
  duration=$(echo "$duration" | xargs)
  reason=$(echo "$reason" | xargs)
  subagents=$(echo "$subagents" | xargs)

  # Color by status
  case "$status" in
    exit-0)  sc="${GREEN}" ;;
    timeout) sc="${YELLOW}" ;;
    HALTED)  sc="${RED}" ;;
    *)       sc="${RED}" ;;
  esac

  local_line="  ${DIM}$ts${NC}  $iter  ${sc}$status${NC}  ${duration}  $reason"
  [ -n "$subagents" ] && local_line="$local_line  ${CYAN}$subagents${NC}"
  echo -e "$local_line"
done

# ─── Subagent Breakdown (latest iteration) ────────────────────
LATEST_SUBAGENT_LOG=$(ls -t "$LOOM_DIR/logs/"*-subagents.jsonl 2>/dev/null | head -1)
if [ -n "$LATEST_SUBAGENT_LOG" ] && [ -s "$LATEST_SUBAGENT_LOG" ]; then
  echo ""
  echo -e "${CYAN}${BOLD}Subagent Breakdown (latest)${NC}"
  echo -e "${DIM}─────────────────────────────────────────${NC}"
  jq -s '
    ([.[] | select(.event == "dispatch")] | length) as $dispatched |
    ([.[] | select(.event == "dispatch") | .index]) as $di |
    ([.[] | select(.event == "block_stop") | .index]) as $si |
    ($di | map(select(. as $i | $si | index($i))) | length) as $completed |
    "  Dispatched: \($dispatched)  Completed: \($completed)  Orphaned: \($dispatched - $completed)"
  ' "$LATEST_SUBAGENT_LOG" 2>/dev/null | tr -d '"' || true
  # Per-subagent timeline (dispatch + matched completions)
  jq -r '
    if .event == "dispatch" then
      "  \(.ts)  \u001b[0;33mDISPATCH\u001b[0m  idx:\(.index)  \(.tool_use_id)"
    elif .event == "block_stop" then
      "  \(.ts)  \u001b[0;32mCOMPLETE\u001b[0m  idx:\(.index)"
    else empty end
  ' "$LATEST_SUBAGENT_LOG" 2>/dev/null || true
fi

# ─── Current status.md ──────────────────────────────────────────
echo ""
echo -e "${CYAN}${BOLD}Current Status${NC}"
echo -e "${DIM}─────────────────────────────────────────${NC}"
if [ -f "$LOOM_DIR/status.md" ]; then
  # Show first 20 lines
  head -20 "$LOOM_DIR/status.md" | sed 's/^/  /'
  LINES=$(wc -l < "$LOOM_DIR/status.md" | tr -d ' ')
  if [ "$LINES" -gt 20 ]; then
    echo -e "  ${DIM}... ($((LINES - 20)) more lines)${NC}"
  fi
else
  echo -e "  ${DIM}(no status.md)${NC}"
fi
