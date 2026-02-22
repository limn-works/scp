#!/usr/bin/env bash
set -euo pipefail

# ─── Ralph Status: Run Summary ──────────────────────────────────
# Parses master.log and status.md to display a summary of the
# current or most recent Ralph run.
# ─────────────────────────────────────────────────────────────────

RALPH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_NAME="$(basename "$(dirname "$RALPH_DIR")")"
TMUX_SESSION="ralph-${PROJECT_NAME}"
MASTER_LOG="$RALPH_DIR/logs/master.log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ─── Check if Ralph is running ──────────────────────────────────
echo -e "${CYAN}${BOLD}Ralph Status${NC}"
echo -e "${DIM}─────────────────────────────────────────${NC}"

if tmux has-session -t "$TMUX_SESSION" 2>/dev/null; then
  echo -e "  Status:  ${GREEN}${BOLD}RUNNING${NC} (tmux session: $TMUX_SESSION)"
else
  echo -e "  Status:  ${DIM}NOT RUNNING${NC}"
fi

# ─── Master log summary ────────────────────────────────────────
if [ ! -f "$MASTER_LOG" ]; then
  echo -e "\n  ${DIM}No master.log found. Ralph hasn't run yet.${NC}"
  exit 0
fi

echo ""
echo -e "${CYAN}${BOLD}Iteration Summary${NC}"
echo -e "${DIM}─────────────────────────────────────────${NC}"

TOTAL=$(wc -l < "$MASTER_LOG" | tr -d ' ')
SUCCESS=$(grep -c '| exit-0 |' "$MASTER_LOG" 2>/dev/null || echo 0)
TIMEOUT=$(grep -c '| timeout |' "$MASTER_LOG" 2>/dev/null || echo 0)
HALTED=$(grep -c '| HALTED |' "$MASTER_LOG" 2>/dev/null || echo 0)
FAILURES=$((TOTAL - SUCCESS - TIMEOUT - HALTED))

echo -e "  Total iterations: ${BOLD}$TOTAL${NC}"
echo -e "  Succeeded:        ${GREEN}$SUCCESS${NC}"
echo -e "  Failed:           ${RED}$FAILURES${NC}"
echo -e "  Timed out:        ${YELLOW}$TIMEOUT${NC}"

# Signal breakdown
SIG_SUCCESS=$(grep -c '| SUCCESS$' "$MASTER_LOG" 2>/dev/null || echo 0)
SIG_PARTIAL=$(grep -c '| PARTIAL$' "$MASTER_LOG" 2>/dev/null || echo 0)
SIG_FAILED=$(grep -c '| FAILED$' "$MASTER_LOG" 2>/dev/null || echo 0)

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
tail -5 "$MASTER_LOG" | while IFS='|' read -r ts iter label status duration reason; do
  # Trim whitespace
  ts=$(echo "$ts" | xargs)
  iter=$(echo "$iter" | xargs)
  label=$(echo "$label" | xargs)
  status=$(echo "$status" | xargs)
  duration=$(echo "$duration" | xargs)
  reason=$(echo "$reason" | xargs)

  # Color by status
  case "$status" in
    exit-0)  sc="${GREEN}" ;;
    timeout) sc="${YELLOW}" ;;
    HALTED)  sc="${RED}" ;;
    *)       sc="${RED}" ;;
  esac

  echo -e "  ${DIM}$ts${NC}  $iter  ${sc}$status${NC}  ${duration}  $reason"
done

# ─── Current status.md ──────────────────────────────────────────
echo ""
echo -e "${CYAN}${BOLD}Current Status${NC}"
echo -e "${DIM}─────────────────────────────────────────${NC}"
if [ -f "$RALPH_DIR/status.md" ]; then
  # Show first 20 lines
  head -20 "$RALPH_DIR/status.md" | sed 's/^/  /'
  LINES=$(wc -l < "$RALPH_DIR/status.md" | tr -d ' ')
  if [ "$LINES" -gt 20 ]; then
    echo -e "  ${DIM}... ($((LINES - 20)) more lines)${NC}"
  fi
else
  echo -e "  ${DIM}(no status.md)${NC}"
fi
