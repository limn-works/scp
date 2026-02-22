#!/usr/bin/env bash
set -euo pipefail

# ─── Ralph: Autonomous Development Loop ──────────────────────────
# Runs Claude Code in a loop, reading instructions from prompt.md
# each iteration. Designed for tmux-based monitoring.
# ─────────────────────────────────────────────────────────────────

RALPH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$RALPH_DIR")"
PROJECT_NAME="$(basename "$PROJECT_DIR")"
LOG_FILE="$RALPH_DIR/ralph.log"
TMUX_SESSION="ralph-${PROJECT_NAME}"
MAX_ITERATIONS=500
# Default to tmux when running from a terminal (not inside Claude Code
# or already inside a tmux session from re-execution), but only if
# tmux is actually installed.
if [ -n "${CLAUDECODE:-}" ] || [ -n "${TMUX:-}" ] || ! command -v tmux &>/dev/null; then
  USE_TMUX=false
else
  USE_TMUX=true
fi
DRY_RUN=false
DIRECTIVE_FILE=""
TIMEOUT=3600
MAX_FAILURES=3
CONSECUTIVE_FAILURES=0

# ─── Sources (composable — multiple can be combined) ─────────────
SOURCES_LINEAR=""       # Linear query/URL
SOURCES_GITHUB=""       # GitHub query/URL/number
SOURCES_SLACK=""        # Slack permalink URL
SOURCES_PROMPT=""       # Inline text or file path
SOURCES_PIPED=""        # Piped stdin content

# ─── Worktree ────────────────────────────────────────────────────
USE_WORKTREE=""         # "" = auto, "yes", "no"
WORKTREE_DIR=""
WORKTREE_BRANCH=""
RESUME_WORKTREE=""

# ─── Colors (terminal only — stripped from log file) ─────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ─── Helpers ─────────────────────────────────────────────────────
die() { echo -e "${RED}Error: $1${NC}" >&2; exit 1; }

is_url() { [[ "$1" == http://* ]] || [[ "$1" == https://* ]]; }

has_sources() {
  [ -n "$SOURCES_LINEAR" ] || [ -n "$SOURCES_GITHUB" ] || \
  [ -n "$SOURCES_SLACK" ] || [ -n "$SOURCES_PROMPT" ] || [ -n "$SOURCES_PIPED" ]
}

short_hash() { head -c 4 /dev/urandom | xxd -p | head -c 6; }

# ─── Parse Arguments ────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case $1 in
    --max-iterations|-m)
      [[ $# -ge 2 ]] || die "$1 requires a value"
      MAX_ITERATIONS="$2"
      [[ "$MAX_ITERATIONS" =~ ^[0-9]+$ ]] || die "--max-iterations must be a positive integer, got '$MAX_ITERATIONS'"
      shift 2
      ;;
    --dry-run|-d)
      DRY_RUN=true
      shift
      ;;
    --timeout)
      [[ $# -ge 2 ]] || die "$1 requires a value in seconds"
      TIMEOUT="$2"
      [[ "$TIMEOUT" =~ ^[0-9]+$ ]] || die "--timeout must be a positive integer, got '$TIMEOUT'"
      shift 2
      ;;
    --max-failures)
      [[ $# -ge 2 ]] || die "$1 requires a value"
      MAX_FAILURES="$2"
      [[ "$MAX_FAILURES" =~ ^[0-9]+$ ]] || die "--max-failures must be a positive integer, got '$MAX_FAILURES'"
      shift 2
      ;;
    --prompt)
      [[ $# -ge 2 ]] || die "$1 requires text or a file path"
      SOURCES_PROMPT="$2"
      shift 2
      ;;
    --directive)
      # Legacy alias for --prompt
      [[ $# -ge 2 ]] || die "$1 requires text or a file path"
      SOURCES_PROMPT="$2"
      shift 2
      ;;
    --linear)
      [[ $# -ge 2 ]] || die "$1 requires a query, ticket ID, or URL"
      SOURCES_LINEAR="$2"
      shift 2
      ;;
    --github)
      [[ $# -ge 2 ]] || die "$1 requires a query, issue number, or URL"
      SOURCES_GITHUB="$2"
      shift 2
      ;;
    --slack)
      [[ $# -ge 2 ]] || die "$1 requires a Slack message permalink URL"
      SOURCES_SLACK="$2"
      shift 2
      ;;
    --worktree)
      USE_WORKTREE="yes"
      shift
      ;;
    --no-worktree)
      USE_WORKTREE="no"
      shift
      ;;
    --resume)
      [[ $# -ge 2 ]] || die "$1 requires a worktree path or branch name"
      RESUME_WORKTREE="$2"
      shift 2
      ;;
    -h|--help)
      cat <<'HELPEOF'
Usage: ralph.sh [OPTIONS]

Options:
  -m, --max-iterations N   Maximum loop iterations (default: 500)
  -d, --dry-run            Analyze one iteration without executing changes
  --timeout SECONDS        Per-iteration timeout (default: 3600)
  --max-failures N         Consecutive failures before halt (default: 3)
  -h, --help               Show this help

Sources (can be combined):
  --prompt TEXT_OR_PATH    Run with inline text or file as directive
  --linear QUERY_OR_URL   Fetch from Linear MCP, implement, update ticket
  --github QUERY_OR_URL   Fetch from GitHub via gh, implement, close issues
  --slack URL             Fetch Slack message context, implement

  Multiple sources can be combined:
    ralph.sh --linear PHN-42 --github 13 --prompt "Also fix lint"

  Without a source flag, runs in PRD mode (reads prd.json).
  A directive can also be piped via stdin:
    echo 'Fix all lint errors' | ralph.sh
    echo 'Only work on AC-001' | ralph.sh --dry-run

Worktree:
  --worktree              Force git worktree mode
  --no-worktree           Disable git worktree mode
  --resume PATH_OR_BRANCH Reuse existing worktree

  Worktree is on by default for --linear and --github,
  off for PRD, --prompt, --slack, and piped stdin.

Graceful stop:
  touch .ralph/.stop      Stop after the current iteration finishes
HELPEOF
      exit 0
      ;;
    *)
      die "Unknown option: $1"
      ;;
  esac
done

# ─── Piped stdin ─────────────────────────────────────────────────
if [ ! -t 0 ]; then
  PIPED="$(cat)"
  if [ -n "$PIPED" ]; then
    SOURCES_PIPED="$PIPED"
  fi
fi

# ─── Build Directive Content ─────────────────────────────────────
# Sources are composable. Each active source appends a section to
# the directive. If only --prompt points to an existing file and
# no other sources are active, use that file directly.

build_directive() {
  local parts=()

  # Linear
  if [ -n "$SOURCES_LINEAR" ]; then
    if is_url "$SOURCES_LINEAR"; then
      parts+=("## Linear Issue

Fetch the Linear issue at this URL using the Linear MCP tools:

$SOURCES_LINEAR

Read the issue details (title, description, acceptance criteria, comments). Implement everything described in the issue. After successful implementation, update the ticket status in Linear to reflect completion.")
    else
      parts+=("## Linear Issue

Search Linear using the Linear MCP tools for issues matching:

$SOURCES_LINEAR

Fetch the matching issue(s) and read their details (title, description, acceptance criteria, comments). Implement what's described. After successful implementation, update the ticket status in Linear to reflect completion.")
    fi
  fi

  # GitHub
  if [ -n "$SOURCES_GITHUB" ]; then
    if is_url "$SOURCES_GITHUB"; then
      parts+=("## GitHub Issue

Fetch the GitHub issue at this URL using \`gh\`:

\`\`\`bash
gh issue view \"$SOURCES_GITHUB\" --json title,body,comments,labels,state
\`\`\`

Read the issue details. Implement everything described. After successful implementation, comment on the issue with a summary of changes and close it:

\`\`\`bash
gh issue comment <number> --body \"Implemented in this iteration. <summary>\"
gh issue close <number>
\`\`\`")
    elif [[ "$SOURCES_GITHUB" =~ ^[0-9]+$ ]]; then
      parts+=("## GitHub Issue

Fetch GitHub issue #$SOURCES_GITHUB using \`gh\`:

\`\`\`bash
gh issue view $SOURCES_GITHUB --json title,body,comments,labels,state
\`\`\`

Read the issue details. Implement everything described. After successful implementation, comment on the issue with a summary of changes and close it:

\`\`\`bash
gh issue comment $SOURCES_GITHUB --body \"Implemented in this iteration. <summary>\"
gh issue close $SOURCES_GITHUB
\`\`\`")
    else
      parts+=("## GitHub Issues

Search GitHub issues matching this query using \`gh\`:

\`\`\`bash
gh issue list --search \"$SOURCES_GITHUB\" --json number,title,body,state --limit 10
\`\`\`

Review the matching issues. Implement what's described in the most relevant open issue(s). After successful implementation, comment on each resolved issue with a summary of changes and close it.")
    fi
  fi

  # Slack
  if [ -n "$SOURCES_SLACK" ]; then
    is_url "$SOURCES_SLACK" || die "--slack requires a Slack message permalink URL"
    parts+=("## Slack Context

Fetch the Slack message at this permalink:

$SOURCES_SLACK

Use any available Slack MCP tools or web fetch to read the message and its thread context. Understand what's being described or requested. Implement it.")
  fi

  # Prompt (inline text or file contents)
  if [ -n "$SOURCES_PROMPT" ]; then
    if [ -f "$SOURCES_PROMPT" ] && [ ${#parts[@]} -eq 0 ] && [ -z "$SOURCES_PIPED" ]; then
      # Only source is a file — use directly, skip composing
      DIRECTIVE_FILE="$SOURCES_PROMPT"
      return
    elif [ -f "$SOURCES_PROMPT" ]; then
      parts+=("## Additional Instructions

$(cat "$SOURCES_PROMPT")")
    else
      parts+=("## Additional Instructions

$SOURCES_PROMPT")
    fi
  fi

  # Piped stdin
  if [ -n "$SOURCES_PIPED" ]; then
    parts+=("## Additional Instructions

$SOURCES_PIPED")
  fi

  # Compose all parts into a single directive file
  if [ ${#parts[@]} -gt 0 ]; then
    local result="${parts[0]}"
    for ((i=1; i<${#parts[@]}; i++)); do
      result+=$'\n\n---\n\n'"${parts[$i]}"
    done
    printf '%s' "$result" > "$RALPH_DIR/.directive"
    DIRECTIVE_FILE="$RALPH_DIR/.directive"
  fi
}

if has_sources; then
  build_directive
fi

# ─── Worktree Auto-Detection ────────────────────────────────────
resolve_worktree() {
  if [ -z "$USE_WORKTREE" ]; then
    # Auto: on if any issue-tracker source is active
    if [ -n "$SOURCES_LINEAR" ] || [ -n "$SOURCES_GITHUB" ]; then
      USE_WORKTREE="yes"
    else
      USE_WORKTREE="no"
    fi
  fi
}

setup_worktree() {
  local base_dir="$HOME/.claude-worktrees/$PROJECT_NAME"
  local timestamp
  timestamp="$(date '+%Y%m%d-%H%M%S')"

  if [ -n "$RESUME_WORKTREE" ]; then
    # Resume existing worktree
    if [ -d "$RESUME_WORKTREE" ]; then
      WORKTREE_DIR="$RESUME_WORKTREE"
    elif [ -d "$base_dir/$RESUME_WORKTREE" ]; then
      WORKTREE_DIR="$base_dir/$RESUME_WORKTREE"
    else
      die "Cannot find worktree: $RESUME_WORKTREE"
    fi
    WORKTREE_BRANCH="$(git -C "$WORKTREE_DIR" branch --show-current 2>/dev/null)" || die "Failed to detect branch in worktree"
    log "${CYAN}Resuming worktree:${NC} $WORKTREE_DIR (branch: $WORKTREE_BRANCH)"
    return
  fi

  WORKTREE_BRANCH="ralph-${timestamp}-$(short_hash)"
  WORKTREE_DIR="$base_dir/$WORKTREE_BRANCH"

  mkdir -p "$base_dir"

  # Create branch and worktree
  git -C "$PROJECT_DIR" branch "$WORKTREE_BRANCH" HEAD
  git -C "$PROJECT_DIR" worktree add "$WORKTREE_DIR" "$WORKTREE_BRANCH"

  # Copy dotfiles that are typically gitignored but needed at runtime
  local dotfiles=(
    ".claude/settings.local.json"
    ".mcp.json"
    ".env"
  )

  for f in "${dotfiles[@]}"; do
    if [ -f "$PROJECT_DIR/$f" ]; then
      mkdir -p "$WORKTREE_DIR/$(dirname "$f")"
      cp "$PROJECT_DIR/$f" "$WORKTREE_DIR/$f"
    fi
  done

  # Copy .env.* variants
  for f in "$PROJECT_DIR"/.env.*; do
    [ -f "$f" ] && cp "$f" "$WORKTREE_DIR/"
  done

  # Copy secret/key files if present
  for pattern in ".secret*" "*.key" "*.pem"; do
    for f in "$PROJECT_DIR"/$pattern; do
      [ -f "$f" ] && cp "$f" "$WORKTREE_DIR/"
    done
  done

  log "${CYAN}Worktree created:${NC} $WORKTREE_DIR (branch: $WORKTREE_BRANCH)"
}

cleanup_worktree() {
  if [ -n "$WORKTREE_DIR" ] && [ -z "$RESUME_WORKTREE" ]; then
    # Only remove worktree if we created it (not resumed)
    # and there are no uncommitted changes
    if git -C "$WORKTREE_DIR" diff --quiet 2>/dev/null && \
       git -C "$WORKTREE_DIR" diff --cached --quiet 2>/dev/null; then
      git -C "$PROJECT_DIR" worktree remove "$WORKTREE_DIR" 2>/dev/null || true
      git -C "$PROJECT_DIR" branch -d "$WORKTREE_BRANCH" 2>/dev/null || true
      log "${DIM}Worktree cleaned up: $WORKTREE_DIR${NC}"
    else
      log "${YELLOW}Worktree has uncommitted changes, keeping: $WORKTREE_DIR${NC}"
    fi
  fi
}

# ─── Logging ─────────────────────────────────────────────────────
strip_ansi() {
  sed 's/\x1b\[[0-9;]*m//g'
}

log() {
  local ts
  ts="$(date '+%Y-%m-%d %H:%M:%S')"
  local line="${DIM}[$ts]${NC} $1"
  echo -e "$line"
  echo -e "$line" | strip_ansi >> "$LOG_FILE"
}

separator() {
  echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

master_log() {
  # Append a structured line to master.log
  # Format: timestamp | #iteration | label | status | duration | reason
  local iteration="$1" label="$2" status="$3" duration="$4" reason="$5"
  local ts
  ts="$(date '+%Y-%m-%d %H:%M:%S')"
  local log_dir="$RALPH_DIR/logs"
  mkdir -p "$log_dir"
  echo "$ts | #$iteration | $label | $status | ${duration}s | $reason" >> "$log_dir/master.log"
}

# ─── Timeout Detection ──────────────────────────────────────────
TIMEOUT_CMD=""
detect_timeout_cmd() {
  if command -v gtimeout &>/dev/null; then
    TIMEOUT_CMD="gtimeout"
  elif command -v timeout &>/dev/null; then
    TIMEOUT_CMD="timeout"
  fi
}

# ─── Result Signal Parsing ───────────────────────────────────────
parse_result_signal() {
  local log_file="$1"
  # Look for RALPH_RESULT:{SUCCESS,FAILED,PARTIAL,DONE}
  # in the last 50 lines of the iteration log
  local signal
  signal=$(tail -50 "$log_file" | grep -oE 'RALPH_RESULT:(SUCCESS|FAILED|PARTIAL|DONE)' | tail -1 || true)
  if [ -n "$signal" ]; then
    echo "${signal#RALPH_RESULT:}"
  else
    echo "UNKNOWN"
  fi
}

# ─── Preflight ───────────────────────────────────────────────────
if ! command -v claude &>/dev/null; then
  die "claude CLI not found in PATH"
fi

if [[ ! -f "$RALPH_DIR/prompt.md" ]]; then
  die "$RALPH_DIR/prompt.md not found"
fi

if [ -n "$DIRECTIVE_FILE" ]; then
  if [[ ! -f "$DIRECTIVE_FILE" ]]; then
    die "directive file not found: $DIRECTIVE_FILE"
  fi
  if [[ ! -f "$RALPH_DIR/directive.md" ]]; then
    die "$RALPH_DIR/directive.md template not found"
  fi
fi

# PRD mode requires prd.json
if ! has_sources; then
  if [[ ! -f "$RALPH_DIR/prd.json" ]]; then
    die "$RALPH_DIR/prd.json not found"
  fi
fi

detect_timeout_cmd
resolve_worktree

# ─── Environment ─────────────────────────────────────────────────
# Allow nested claude invocations (e.g. when ralph is started from
# within a Claude session via a /ralph skill).
unset CLAUDECODE

# Signal to hooks that we're inside a Ralph loop. Hooks check this
# variable and no-op when it's absent, so they don't affect normal
# Claude Code sessions.
export RALPH_ACTIVE=1

# ─── Cleanup ─────────────────────────────────────────────────────
cleanup() {
  rm -f "$RALPH_DIR/.directive" "$RALPH_DIR/.piped_directive" "$RALPH_DIR/.iteration_marker" "$RALPH_DIR/.stop" "$RALPH_DIR/.pid"
  cleanup_worktree
}
trap cleanup EXIT

# ─── Concurrency Guard ──────────────────────────────────────────
PID_FILE="$RALPH_DIR/.pid"
if [ -f "$PID_FILE" ]; then
  EXISTING_PID=$(cat "$PID_FILE")
  if kill -0 "$EXISTING_PID" 2>/dev/null; then
    die "Ralph is already running (PID $EXISTING_PID). Use 'touch .ralph/.stop' to stop it."
  else
    rm -f "$PID_FILE"
  fi
fi
echo $$ > "$PID_FILE"

# ─── Worktree Setup ─────────────────────────────────────────────
if [ "$USE_WORKTREE" = "yes" ]; then
  setup_worktree
  PROJECT_DIR="$WORKTREE_DIR"
fi

# ─── Tmux Launch ─────────────────────────────────────────────────
if $USE_TMUX; then
  if tmux has-session -t "$TMUX_SESSION" 2>/dev/null; then
    echo -e "${YELLOW}Ralph is already running in tmux session '$TMUX_SESSION'${NC}"
    echo -e "Attach: ${BOLD}tmux attach -t $TMUX_SESSION${NC}"
    echo -e "Kill:   ${BOLD}tmux kill-session -t $TMUX_SESSION${NC}"
    exit 1
  fi

  touch "$LOG_FILE"

  # Build flags to forward
  FORWARD_FLAGS="--max-iterations $MAX_ITERATIONS --timeout $TIMEOUT --max-failures $MAX_FAILURES"
  if $DRY_RUN; then FORWARD_FLAGS="$FORWARD_FLAGS --dry-run"; fi

  # Forward sources (each independently)
  [ -n "$SOURCES_LINEAR" ] && FORWARD_FLAGS="$FORWARD_FLAGS --linear $(printf '%q' "$SOURCES_LINEAR")"
  [ -n "$SOURCES_GITHUB" ] && FORWARD_FLAGS="$FORWARD_FLAGS --github $(printf '%q' "$SOURCES_GITHUB")"
  [ -n "$SOURCES_SLACK" ]  && FORWARD_FLAGS="$FORWARD_FLAGS --slack $(printf '%q' "$SOURCES_SLACK")"
  if [ -n "$SOURCES_PIPED" ]; then
    if [ -n "$SOURCES_PROMPT" ]; then
      printf '%s\n\n%s' "$SOURCES_PROMPT" "$SOURCES_PIPED" > "$RALPH_DIR/.piped_directive"
    else
      printf '%s' "$SOURCES_PIPED" > "$RALPH_DIR/.piped_directive"
    fi
    FORWARD_FLAGS="$FORWARD_FLAGS --prompt $(printf '%q' "$RALPH_DIR/.piped_directive")"
  elif [ -n "$SOURCES_PROMPT" ]; then
    FORWARD_FLAGS="$FORWARD_FLAGS --prompt $(printf '%q' "$SOURCES_PROMPT")"
  fi

  # Forward worktree overrides
  if [ "$USE_WORKTREE" = "yes" ] && [ -z "$RESUME_WORKTREE" ]; then
    FORWARD_FLAGS="$FORWARD_FLAGS --worktree"
  elif [ "$USE_WORKTREE" = "no" ]; then
    FORWARD_FLAGS="$FORWARD_FLAGS --no-worktree"
  fi
  if [ -n "$RESUME_WORKTREE" ]; then
    FORWARD_FLAGS="$FORWARD_FLAGS --resume $(printf '%q' "$RESUME_WORKTREE")"
  fi

  # Clear PID file so re-executed instance doesn't hit the concurrency guard
  # (this process is still alive when the tmux instance starts)
  rm -f "$PID_FILE"

  # Main pane: the ralph loop
  tmux new-session -d -s "$TMUX_SESSION" \
    "exec $0 $FORWARD_FLAGS"

  # Bottom-left: live status.md
  tmux split-window -v -t "$TMUX_SESSION" -p 28 \
    "exec watch -n 3 -t sh -c 'printf \"\\033[1;36m── status.md ──\\033[0m\\n\"; cat \"$RALPH_DIR/status.md\" 2>/dev/null || echo \"(empty)\"'"

  # Bottom-right: log tail
  tmux split-window -h -t "$TMUX_SESSION" \
    "exec tail -f \"$RALPH_DIR/logs/master.log\" 2>/dev/null || tail -f \"$LOG_FILE\""

  # Focus main pane
  tmux select-pane -t "$TMUX_SESSION:0.0"

  echo -e "${GREEN}Ralph launched in tmux session '${TMUX_SESSION}'${NC}"
  echo -e "  Attach:  ${BOLD}tmux attach -t $TMUX_SESSION${NC}"
  echo -e "  Kill:    ${BOLD}tmux kill-session -t $TMUX_SESSION${NC}"
  echo -e "  Stop:    ${BOLD}touch .ralph/.stop${NC} (finishes current iteration)"

  # Auto-attach when running from a terminal (not inside Claude Code)
  if [ -z "${CLAUDECODE:-}" ]; then
    exec tmux attach -t "$TMUX_SESSION"
  fi
  exit 0
fi

# ─── Mode label for logging ───────────────────────────────────────
MODE_LABEL=""
[ -n "$SOURCES_LINEAR" ] && MODE_LABEL="${MODE_LABEL:+$MODE_LABEL+}linear"
[ -n "$SOURCES_GITHUB" ] && MODE_LABEL="${MODE_LABEL:+$MODE_LABEL+}github"
[ -n "$SOURCES_SLACK" ]  && MODE_LABEL="${MODE_LABEL:+$MODE_LABEL+}slack"
[ -n "$SOURCES_PROMPT" ] && MODE_LABEL="${MODE_LABEL:+$MODE_LABEL+}prompt"
[ -n "$SOURCES_PIPED" ]  && MODE_LABEL="${MODE_LABEL:+$MODE_LABEL+}prompt"
MODE_LABEL="${MODE_LABEL:-prd}"

# ─── Banner ──────────────────────────────────────────────────────
echo -e "${CYAN}"
echo "  ╔═══════════════════════════════════════════╗"
echo "  ║            R A L P H   L O O P            ║"
echo "  ╚═══════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "  ${DIM}PID${NC}   ${BOLD}$$${NC}"
echo -e "  ${DIM}Mode${NC}  ${BOLD}$MODE_LABEL${NC}  ${DIM}|${NC}  ${DIM}Iter${NC} ${BOLD}$MAX_ITERATIONS${NC}  ${DIM}|${NC}  ${DIM}Timeout${NC} ${BOLD}${TIMEOUT}s${NC}"
echo -e "  ${DIM}Dir${NC}   $PROJECT_DIR"
if [ -n "$DIRECTIVE_FILE" ]; then
  echo -e "  ${DIM}Src${NC}   $DIRECTIVE_FILE"
fi
if [ "$USE_WORKTREE" = "yes" ]; then
  echo -e "  ${DIM}Tree${NC}  $WORKTREE_DIR"
fi
echo ""
echo -e "  ${CYAN}Graceful stop${NC}    touch .ralph/.stop"
echo -e "  ${CYAN}Kill${NC}             kill -TERM -$$"
echo -e "  ${CYAN}Tail log${NC}         tail -f .ralph/ralph.log"
echo -e "  ${CYAN}Status${NC}           cat .ralph/status.md"
echo -e "  ${CYAN}Master log${NC}       tail -f .ralph/logs/master.log"
echo ""

if $DRY_RUN; then
  log "${YELLOW}${BOLD}DRY RUN${NC} — analysis only, no changes will be made"
fi

# ─── Ensure log directory exists ────────────────────────────────
mkdir -p "$RALPH_DIR/logs"

# ─── Clean stale sentinels ──────────────────────────────────────
rm -f "$RALPH_DIR/.iteration_marker"

# ─── Main Loop ───────────────────────────────────────────────────
ITERATION=0

while [ "$ITERATION" -lt "$MAX_ITERATIONS" ]; do
  ITERATION=$((ITERATION + 1))

  # ─── Graceful stop: check for .stop sentinel ──
  if [ -f "$RALPH_DIR/.stop" ]; then
    log "${YELLOW}${BOLD}Graceful stop requested${NC} (.ralph/.stop found). Halting after iteration $((ITERATION - 1))."
    rm -f "$RALPH_DIR/.stop"
    break
  fi

  # ─── Circuit breaker: consecutive failures ──
  if [ "$CONSECUTIVE_FAILURES" -ge "$MAX_FAILURES" ]; then
    log "${RED}${BOLD}Circuit breaker tripped:${NC} $CONSECUTIVE_FAILURES consecutive failures. Halting."
    master_log "$ITERATION" "$MODE_LABEL" "HALTED" "0" "Circuit breaker: $CONSECUTIVE_FAILURES consecutive failures"
    break
  fi

  separator
  log "${BOLD}Iteration $ITERATION${NC} (failures: $CONSECUTIVE_FAILURES/$MAX_FAILURES)"
  separator

  # ─── Build prompt ───────────────────────────────────────────
  if [ -n "$DIRECTIVE_FILE" ]; then
    # Directive mode: read template, split on {{DIRECTIVE}} marker,
    # insert user's directive content between the halves.
    DIRECTIVE_CONTENT="$(cat "$DIRECTIVE_FILE")"
    PROMPT_TOP="$(sed '/^{{DIRECTIVE}}$/,$d' "$RALPH_DIR/directive.md")"
    PROMPT_BOTTOM="$(sed '1,/^{{DIRECTIVE}}$/d' "$RALPH_DIR/directive.md")"
    PROMPT="${PROMPT_TOP}${DIRECTIVE_CONTENT}"$'\n'"${PROMPT_BOTTOM}"
  else
    # Normal loop mode: full prompt.md orchestration with PRD
    PROMPT="$(cat "$RALPH_DIR/prompt.md")"
  fi

  # ─── Iteration marker for stop-guard hook ──
  touch "$RALPH_DIR/.iteration_marker"

  # ─── Dry-run: append analysis-only override ──
  if $DRY_RUN; then
    export RALPH_DRY_RUN=1

    if [ -n "$DIRECTIVE_FILE" ]; then
      read -r -d '' DRY_ADDENDUM <<'DRYEOF' || true

---

## !! DRY RUN — DO NOT EXECUTE !!

This is a **dry run**. Read status.md (Step 1), then analyze the directive (Step 2), but **stop there**.

**DO NOT** execute anything. Do not launch subagents. Do not create, modify, or delete any files.

Instead, output a structured analysis:

### 1. Status Assessment
Summarize what you found in status.md. Any failing tests relevant to the directive.

### 2. Directive Breakdown
How you would decompose this directive into parallelizable units of work.

### 3. Subagent Plan
One line per subagent you would launch and what it would do.

### 4. Estimated File Impact
Which files would likely be created or modified.

After outputting this report, exit immediately.
DRYEOF
    else
      read -r -d '' DRY_ADDENDUM <<'DRYEOF' || true

---

## !! DRY RUN — DO NOT EXECUTE !!

This is a **dry run**. Perform Steps 1 and 2 exactly as written (read status.md, read prd.json with jq waves), but **stop there**.

**DO NOT** execute Steps 3–4. Do not launch subagents. Do not create, modify, or delete any files.

Instead, output a structured analysis:

### 1. Status Assessment
Summarize what you found in status.md. List any failing tests that would be prioritized as fixes.

### 2. Story Selection
Which stories you would select for this iteration: story ID, title, and why each was chosen. Explain your parallelization rationale — why these stories can safely run concurrently.

### 3. Subagent Plan
One line per subagent you would launch: the story ID and a brief description of the assignment.

### 4. Estimated File Impact
Which files would likely be created or modified across all subagents.

After outputting this report, exit immediately.
DRYEOF
    fi

    PROMPT="$PROMPT"$'\n'"$DRY_ADDENDUM"
  fi

  cd "$PROJECT_DIR"

  # ─── Per-iteration log file ──
  ITER_LABEL="${MODE_LABEL}"
  ITER_LOG="$RALPH_DIR/logs/$(date '+%Y%m%d-%H%M%S')-${ITER_LABEL}.log"
  ITER_START=$(date +%s)

  # ─── Execute Claude with streaming output ──
  set +e
  if [ -n "$TIMEOUT_CMD" ] && [ "$TIMEOUT" -gt 0 ]; then
    $TIMEOUT_CMD --foreground "$TIMEOUT" claude -p \
      --dangerously-skip-permissions \
      --verbose \
      --output-format stream-json \
      --include-partial-messages \
      "$PROMPT" 2>>"$LOG_FILE" | \
      jq --unbuffered -rj 'select(.type == "stream_event" and .event.delta.type? == "text_delta") | .event.delta.text' 2>/dev/null | \
      tee >(strip_ansi | tee -a "$LOG_FILE" > "$ITER_LOG")
    CLAUDE_EXIT=${PIPESTATUS[0]}
  else
    claude -p \
      --dangerously-skip-permissions \
      --verbose \
      --output-format stream-json \
      --include-partial-messages \
      "$PROMPT" 2>>"$LOG_FILE" | \
      jq --unbuffered -rj 'select(.type == "stream_event" and .event.delta.type? == "text_delta") | .event.delta.text' 2>/dev/null | \
      tee >(strip_ansi | tee -a "$LOG_FILE" > "$ITER_LOG")
    CLAUDE_EXIT=${PIPESTATUS[0]}
  fi
  set -e

  ITER_END=$(date +%s)
  ITER_DURATION=$((ITER_END - ITER_START))

  # ─── Parse result signal from iteration output ──
  RESULT_SIGNAL=$(parse_result_signal "$ITER_LOG")

  # ─── Determine iteration status ──
  ITER_STATUS="unknown"
  ITER_REASON=""

  if [ "$CLAUDE_EXIT" -eq 124 ]; then
    ITER_STATUS="timeout"
    ITER_REASON="Timed out after ${TIMEOUT}s"
    log "${RED}Iteration $ITERATION timed out after ${TIMEOUT}s${NC}"
  elif [ "$CLAUDE_EXIT" -eq 0 ]; then
    ITER_STATUS="exit-0"
    ITER_REASON="$RESULT_SIGNAL"
    log "${GREEN}Iteration $ITERATION completed (exit 0, signal: $RESULT_SIGNAL)${NC}"
  else
    ITER_STATUS="exit-$CLAUDE_EXIT"
    ITER_REASON="$RESULT_SIGNAL"
    log "${YELLOW}Iteration $ITERATION finished (exit $CLAUDE_EXIT, signal: $RESULT_SIGNAL)${NC}"
  fi

  master_log "$ITERATION" "$ITER_LABEL" "$ITER_STATUS" "$ITER_DURATION" "$ITER_REASON"

  # ─── Done: no remaining work ──
  if [ "$RESULT_SIGNAL" = "DONE" ]; then
    log "${GREEN}${BOLD}All work complete.${NC} Halting loop."
    break
  fi

  # ─── Circuit breaker: check if status.md was updated ──
  if [ -f "$RALPH_DIR/.iteration_marker" ]; then
    if [ ! -f "$RALPH_DIR/status.md" ] || [ "$RALPH_DIR/status.md" -ot "$RALPH_DIR/.iteration_marker" ]; then
      # status.md not updated — count as failure
      CONSECUTIVE_FAILURES=$((CONSECUTIVE_FAILURES + 1))
      log "${YELLOW}status.md not updated — failure $CONSECUTIVE_FAILURES/$MAX_FAILURES${NC}"
    else
      # Success — reset counter
      CONSECUTIVE_FAILURES=0
    fi
  fi

  # ─── Dry-run: one iteration only, no cooldown ──
  if $DRY_RUN; then
    log "${GREEN}Dry run analysis complete.${NC}"
    break
  fi

done

if ! $DRY_RUN && [ "$ITERATION" -ge "$MAX_ITERATIONS" ]; then
  log "${YELLOW}${BOLD}Ralph completed $MAX_ITERATIONS iterations. Halting.${NC}"
  master_log "$ITERATION" "$MODE_LABEL" "MAX_ITER" "0" "Reached max iterations"
fi
