#!/usr/bin/env bash
set -euo pipefail

# ─── Loom: Autonomous Development Loop ──────────────────────────
# Runs Claude Code in a loop, reading instructions from prompt.md
# each iteration. Designed for tmux-based monitoring.
# ─────────────────────────────────────────────────────────────────

LOOM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$LOOM_DIR")"
PROJECT_NAME="$(basename "$PROJECT_DIR")"
LOG_FILE="$LOOM_DIR/loom.log"
TMUX_SESSION="loom-${PROJECT_NAME}"
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
SOURCES_NOTION=""       # Notion page URL or search query
SOURCES_SENTRY=""       # Sentry issue URL or search query
SOURCES_PROMPT=""       # Inline text or file path
SOURCES_PIPED=""        # Piped stdin content

# ─── Worktree ────────────────────────────────────────────────────
USE_WORKTREE=""         # "" = auto, "yes", "no"
WORKTREE_DIR=""
WORKTREE_BRANCH=""
RESUME_WORKTREE=""
CREATE_PR="yes"         # "yes" = push + PR after loop, "no" = skip

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
  [ -n "$SOURCES_SLACK" ] || [ -n "$SOURCES_NOTION" ] || \
  [ -n "$SOURCES_SENTRY" ] || [ -n "$SOURCES_PROMPT" ] || [ -n "$SOURCES_PIPED" ]
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
    --notion)
      [[ $# -ge 2 ]] || die "$1 requires a page URL or search query"
      SOURCES_NOTION="$2"
      shift 2
      ;;
    --sentry)
      [[ $# -ge 2 ]] || die "$1 requires an issue URL or search query"
      SOURCES_SENTRY="$2"
      shift 2
      ;;
    --worktree)
      [[ $# -ge 2 ]] || die "$1 requires true or false"
      USE_WORKTREE=$([ "$2" = "true" ] && echo "yes" || echo "no")
      shift 2
      ;;
    --pr)
      [[ $# -ge 2 ]] || die "$1 requires true or false"
      CREATE_PR=$([ "$2" = "true" ] && echo "yes" || echo "no")
      shift 2
      ;;
    --resume)
      if [[ $# -ge 2 ]] && [[ "$2" != --* ]]; then
        RESUME_WORKTREE="$2"
        shift 2
      else
        # Default to current directory
        RESUME_WORKTREE="."
        shift 1
      fi
      ;;
    -h|--help)
      cat <<'HELPEOF'
Usage: loom.sh [OPTIONS]

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
  --notion URL_OR_QUERY   Fetch Notion page via MCP, implement
  --sentry URL_OR_QUERY   Fetch Sentry issue via MCP, fix the error

  Multiple sources can be combined:
    loom.sh --linear PHN-42 --github 13 --prompt "Also fix lint"

  Without a source flag, runs in PRD mode (reads prd.json).
  A directive can also be piped via stdin:
    echo 'Fix all lint errors' | loom.sh
    echo 'Only work on AC-001' | loom.sh --dry-run

Worktree:
  --worktree              Git worktree isolation (default: on)
  --pr                    Push + PR after loop (default: on)
  --resume [PATH_OR_BRANCH] Reuse existing worktree (default: current dir)

Graceful stop:
  touch .loom/.stop      Stop after the current iteration finishes
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
  PIPED="$(timeout 1 cat 2>/dev/null || true)"
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

  # Notion
  if [ -n "$SOURCES_NOTION" ]; then
    if is_url "$SOURCES_NOTION"; then
      parts+=("## Notion Page

Fetch the Notion page at this URL using the Notion MCP tools:

$SOURCES_NOTION

Read the page content, including any sub-pages, databases, or linked references. Understand the requirements or spec described. Implement everything specified.")
    else
      parts+=("## Notion Page

Search Notion using the Notion MCP tools for pages matching:

$SOURCES_NOTION

Read the matching page(s) and their content, including sub-pages and linked references. Understand the requirements or spec described. Implement everything specified.")
    fi
  fi

  # Sentry
  if [ -n "$SOURCES_SENTRY" ]; then
    if is_url "$SOURCES_SENTRY"; then
      parts+=("## Sentry Issue

Fetch the Sentry issue at this URL using the Sentry MCP tools:

$SOURCES_SENTRY

Read the error details: exception type, stack trace, breadcrumbs, tags, and any linked issues. Identify the root cause from the stack trace. Fix the bug. Add a regression test that reproduces the error and verifies the fix.")
    else
      parts+=("## Sentry Issue

Search Sentry using the Sentry MCP tools for issues matching:

$SOURCES_SENTRY

Read the matching issue(s) and their error details: exception type, stack trace, breadcrumbs, tags. Identify the root cause from the stack trace. Fix the bug(s). Add regression tests that reproduce each error and verify the fix.")
    fi
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
    printf '%s' "$result" > "$LOOM_DIR/.directive"
    DIRECTIVE_FILE="$LOOM_DIR/.directive"
  fi
}

if has_sources; then
  build_directive
fi

# ─── Worktree Auto-Detection ────────────────────────────────────
resolve_worktree() {
  if [ -z "$USE_WORKTREE" ]; then
    USE_WORKTREE="yes"
  fi
}

setup_worktree() {
  local base_dir="$HOME/.claude-worktrees/$PROJECT_NAME"
  local timestamp
  timestamp="$(date '+%Y%m%d-%H%M%S')"

  if [ -n "$RESUME_WORKTREE" ]; then
    # Resume existing worktree
    if [ -d "$RESUME_WORKTREE" ]; then
      WORKTREE_DIR="$(cd "$RESUME_WORKTREE" && pwd)"
    elif [ -d "$base_dir/$RESUME_WORKTREE" ]; then
      WORKTREE_DIR="$base_dir/$RESUME_WORKTREE"
    else
      die "Cannot find worktree: $RESUME_WORKTREE"
    fi
    WORKTREE_BRANCH="$(git -C "$WORKTREE_DIR" branch --show-current 2>/dev/null)" || die "Failed to detect branch in worktree"
    log "${CYAN}Resuming worktree:${NC} $WORKTREE_DIR (branch: $WORKTREE_BRANCH)"
    return
  fi

  WORKTREE_BRANCH="loom-${timestamp}-$(short_hash)"
  WORKTREE_DIR="$base_dir/$WORKTREE_BRANCH"

  mkdir -p "$base_dir"

  # Create branch and worktree
  git -C "$PROJECT_DIR" branch "$WORKTREE_BRANCH" HEAD
  git -C "$PROJECT_DIR" worktree add "$WORKTREE_DIR" "$WORKTREE_BRANCH"

  # Copy dotfiles that are typically gitignored but needed at runtime
  local dotfiles=(
    ".claude/settings.json"
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
      # Only delete branch locally if it hasn't been pushed to a remote
      if ! git -C "$PROJECT_DIR" ls-remote --heads origin "$WORKTREE_BRANCH" 2>/dev/null | grep -q .; then
        git -C "$PROJECT_DIR" branch -d "$WORKTREE_BRANCH" 2>/dev/null || true
      fi
      log "${DIM}Worktree cleaned up: $WORKTREE_DIR${NC}"
    else
      log "${YELLOW}Worktree has uncommitted changes, keeping: $WORKTREE_DIR${NC}"
    fi
  fi
}

PR_CREATED=false

# ─── PR Creation ──────────────────────────────────────────────────
create_pr() {
  # Idempotent — only run once per loop
  if $PR_CREATED; then return 0; fi

  # Guard: only create PR if worktree mode and PR creation are both enabled
  if [ "$USE_WORKTREE" != "yes" ] || [ "$CREATE_PR" != "yes" ]; then
    return 0
  fi

  # Guard: need a branch name
  if [ -z "$WORKTREE_BRANCH" ]; then
    return 0
  fi

  # Guard: skip if no commits ahead of main
  local main_branch
  main_branch=$(git -C "$PROJECT_DIR" symbolic-ref refs/remotes/origin/HEAD 2>/dev/null | sed 's@^refs/remotes/origin/@@' || echo "main")
  local commits_ahead
  commits_ahead=$(git -C "$PROJECT_DIR" rev-list --count "${main_branch}..${WORKTREE_BRANCH}" 2>/dev/null || echo "0")
  if [ "$commits_ahead" -eq 0 ]; then
    log "${DIM}No commits on $WORKTREE_BRANCH — skipping PR creation${NC}"
    return 0
  fi

  # Push branch to origin
  log "${CYAN}Pushing branch $WORKTREE_BRANCH to origin...${NC}"
  if ! git -C "$PROJECT_DIR" push -u origin "$WORKTREE_BRANCH" 2>>"$LOG_FILE"; then
    log "${YELLOW}Failed to push branch — skipping PR creation${NC}"
    return 0
  fi

  # Build PR title and body based on mode
  local pr_title pr_body pr_labels="loom"

  case "$MODE_LABEL" in
    *github*)
      # Extract issue number from URL if present, otherwise use as-is
      if [[ "$SOURCES_GITHUB" =~ /issues/([0-9]+) ]]; then
        local issue_num="${BASH_REMATCH[1]}"
      else
        local issue_num="$SOURCES_GITHUB"
      fi
      pr_title="fix(loom): resolve #${issue_num}"
      pr_body="## Summary
Automated implementation for issue #${issue_num}.

Closes #${issue_num}

## Loom Run
- Branch: \`${WORKTREE_BRANCH}\`
- Mode: ${MODE_LABEL}
- Commits: ${commits_ahead}"
      ;;
    *linear*)
      local ticket_id="$SOURCES_LINEAR"
      pr_title="feat(loom): implement ${ticket_id}"
      pr_body="## Summary
Automated implementation for Linear ticket ${ticket_id}.

## Loom Run
- Branch: \`${WORKTREE_BRANCH}\`
- Mode: ${MODE_LABEL}
- Commits: ${commits_ahead}"
      ;;
    *prompt*)
      local short_prompt
      if [ -f "$SOURCES_PROMPT" ]; then
        short_prompt=$(head -c 50 "$SOURCES_PROMPT" | tr '\n' ' ')
      else
        short_prompt=$(echo "$SOURCES_PROMPT" | head -c 50 | tr '\n' ' ')
      fi
      pr_title="feat(loom): ${short_prompt}"
      pr_body="## Summary
Automated implementation from prompt directive.

## Loom Run
- Branch: \`${WORKTREE_BRANCH}\`
- Mode: ${MODE_LABEL}
- Commits: ${commits_ahead}"
      ;;
    prd)
      local story_ids
      story_ids=$(git -C "$PROJECT_DIR" log "${main_branch}..${WORKTREE_BRANCH}" --format="%s" 2>/dev/null | \
        grep -oE '[A-Z]+-[0-9]+' | sort -u | tr '\n' ' ' || true)
      if [ -n "$story_ids" ]; then
        pr_title="feat(loom): complete stories ${story_ids}"
      else
        pr_title="feat(loom): PRD iteration work"
      fi
      pr_body="## Summary
Automated PRD implementation by Loom.

## Loom Run
- Branch: \`${WORKTREE_BRANCH}\`
- Mode: ${MODE_LABEL}
- Commits: ${commits_ahead}
- Stories: ${story_ids:-none detected}"
      ;;
    *)
      pr_title="feat(loom): automated changes (${MODE_LABEL})"
      pr_body="## Summary
Automated changes by Loom.

## Loom Run
- Branch: \`${WORKTREE_BRANCH}\`
- Mode: ${MODE_LABEL}
- Commits: ${commits_ahead}"
      ;;
  esac

  # Ensure the label exists (create it if missing)
  gh label create "$pr_labels" --description "Automated by Loom" --color "6A0DAD" 2>/dev/null || true

  # Create the PR
  log "${CYAN}Creating PR...${NC}"
  local pr_url
  pr_url=$(gh pr create \
    --head "$WORKTREE_BRANCH" \
    --base "$main_branch" \
    --title "$pr_title" \
    --body "$pr_body" \
    --label "$pr_labels" \
    2>>"$LOG_FILE") || true

  if [ -n "$pr_url" ]; then
    PR_CREATED=true
    log "${GREEN}${BOLD}PR created:${NC} $pr_url"
    mkdir -p "$LOOM_DIR/logs"
    echo "$(date '+%Y-%m-%d %H:%M:%S') | PR | $pr_url | $WORKTREE_BRANCH" >> "$LOOM_DIR/logs/master.log"
  else
    log "${YELLOW}PR creation failed — branch pushed but PR not created${NC}"
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
  local log_dir="$LOOM_DIR/logs"
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
  # Look for LOOM_RESULT:{SUCCESS,FAILED,PARTIAL,DONE}
  # in the last 50 lines of the iteration log
  local signal
  signal=$(tail -50 "$log_file" | grep -oE 'LOOM_RESULT:(SUCCESS|FAILED|PARTIAL|DONE)' | tail -1 || true)
  if [ -n "$signal" ]; then
    echo "${signal#LOOM_RESULT:}"
  else
    echo "UNKNOWN"
  fi
}

# ─── Preflight ───────────────────────────────────────────────────
if ! command -v claude &>/dev/null; then
  die "claude CLI not found in PATH"
fi

if [[ ! -f "$LOOM_DIR/prompt.md" ]]; then
  die "$LOOM_DIR/prompt.md not found"
fi

if [ -n "$DIRECTIVE_FILE" ]; then
  if [[ ! -f "$DIRECTIVE_FILE" ]]; then
    die "directive file not found: $DIRECTIVE_FILE"
  fi
  if [[ ! -f "$LOOM_DIR/directive.md" ]]; then
    die "$LOOM_DIR/directive.md template not found"
  fi
fi

# PRD mode requires prd.json
if ! has_sources; then
  if [[ ! -f "$LOOM_DIR/prd.json" ]]; then
    die "$LOOM_DIR/prd.json not found"
  fi
fi

detect_timeout_cmd
resolve_worktree

# ─── Environment ─────────────────────────────────────────────────
# Allow nested claude invocations (e.g. when loom is started from
# within a Claude session via a /loom skill).
unset CLAUDECODE

# Signal to hooks that we're inside a Loom loop. Hooks check this
# variable and no-op when it's absent, so they don't affect normal
# Claude Code sessions.
export LOOM_ACTIVE=1

# ─── Cleanup ─────────────────────────────────────────────────────
cleanup() {
  # Only attempt PR creation if the loop actually ran iterations.
  # Prevents premature push on early exit (e.g. --resume with no work).
  if [ "${ITERATION:-0}" -gt 0 ]; then
    create_pr 2>/dev/null || true
  fi
  rm -f "$LOOM_DIR/.directive" "$LOOM_DIR/.piped_directive" "$LOOM_DIR/.iteration_marker" "$LOOM_DIR/.stop" "$LOOM_DIR/.pid"
  cleanup_worktree
}
trap cleanup EXIT

# ─── Concurrency Guard ──────────────────────────────────────────
PID_FILE="$LOOM_DIR/.pid"
if [ -f "$PID_FILE" ]; then
  EXISTING_PID=$(cat "$PID_FILE")
  if kill -0 "$EXISTING_PID" 2>/dev/null; then
    die "Loom is already running (PID $EXISTING_PID). Use 'touch .loom/.stop' to stop it."
  else
    rm -f "$PID_FILE"
  fi
fi
echo $$ > "$PID_FILE"

# ─── Worktree Setup ─────────────────────────────────────────────
if [ "$USE_WORKTREE" = "yes" ]; then
  setup_worktree
  PROJECT_DIR="$WORKTREE_DIR"
  # Repoint all runtime state into the worktree so concurrent looms
  # don't clobber each other. Source .loom/ keeps only checked-in files.
  SOURCE_LOOM_DIR="$LOOM_DIR"
  LOOM_DIR="$PROJECT_DIR/.loom"
  LOG_FILE="$LOOM_DIR/loom.log"
  rm -f "$SOURCE_LOOM_DIR/.pid"
  PID_FILE="$LOOM_DIR/.pid"
  echo $$ > "$PID_FILE"
  # Relocate composed directive into the worktree so concurrent looms
  # don't overwrite each other's directives.
  if [ -n "$DIRECTIVE_FILE" ] && [ "$DIRECTIVE_FILE" = "$SOURCE_LOOM_DIR/.directive" ]; then
    cp "$DIRECTIVE_FILE" "$LOOM_DIR/.directive"
    DIRECTIVE_FILE="$LOOM_DIR/.directive"
  fi
fi

# ─── MCP Capability Detection ────────────────────────────────
CAPABILITY_MAP=(
  # browser
  "playwright:browser"
  "chrome:browser"
  "puppeteer:browser"
  "browserbase:browser"
  # mobile
  "mobile:mobile"
  "mobile-mcp:mobile"
  "appium:mobile"
  # design
  "figma:design"
)

detect_mcp_capabilities() {
  local mcp_file="$PROJECT_DIR/.mcp.json"
  local caps=""
  if [ -f "$mcp_file" ]; then
    local servers
    servers=$(jq -r '.mcpServers // {} | keys[]' "$mcp_file" 2>/dev/null)
    LOOM_MCP_SERVERS=$(echo "$servers" | paste -sd, -)
    for server in $servers; do
      for mapping in "${CAPABILITY_MAP[@]}"; do
        if [ "$server" = "${mapping%%:*}" ]; then
          local cap="${mapping#*:}"
          [[ ",$caps," != *",$cap,"* ]] && caps="${caps:+$caps,}$cap"
        fi
      done
      # Unknown servers: expose by name as a capability
      local matched=false
      for mapping in "${CAPABILITY_MAP[@]}"; do
        [ "$server" = "${mapping%%:*}" ] && matched=true && break
      done
      $matched || caps="${caps:+$caps,}$server"
    done
  fi
  export LOOM_MCP_SERVERS="${LOOM_MCP_SERVERS:-}"
  export LOOM_CAPABILITIES="${caps:-}"
}

detect_mcp_capabilities

# ─── Tmux Launch ─────────────────────────────────────────────────
if $USE_TMUX; then
  if tmux has-session -t "$TMUX_SESSION" 2>/dev/null; then
    echo -e "${YELLOW}Loom is already running in tmux session '$TMUX_SESSION'${NC}"
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
  [ -n "$SOURCES_NOTION" ] && FORWARD_FLAGS="$FORWARD_FLAGS --notion $(printf '%q' "$SOURCES_NOTION")"
  [ -n "$SOURCES_SENTRY" ] && FORWARD_FLAGS="$FORWARD_FLAGS --sentry $(printf '%q' "$SOURCES_SENTRY")"
  if [ -n "$SOURCES_PIPED" ]; then
    if [ -n "$SOURCES_PROMPT" ]; then
      printf '%s\n\n%s' "$SOURCES_PROMPT" "$SOURCES_PIPED" > "$LOOM_DIR/.piped_directive"
    else
      printf '%s' "$SOURCES_PIPED" > "$LOOM_DIR/.piped_directive"
    fi
    FORWARD_FLAGS="$FORWARD_FLAGS --prompt $(printf '%q' "$LOOM_DIR/.piped_directive")"
  elif [ -n "$SOURCES_PROMPT" ]; then
    FORWARD_FLAGS="$FORWARD_FLAGS --prompt $(printf '%q' "$SOURCES_PROMPT")"
  fi

  # Forward worktree and PR overrides — always resume the already-created
  # worktree so the tmux child doesn't create a second orphaned one.
  if [ "$USE_WORKTREE" = "yes" ]; then
    FORWARD_FLAGS="$FORWARD_FLAGS --resume $(printf '%q' "$WORKTREE_DIR")"
  fi
  [ "$CREATE_PR" = "no" ] && FORWARD_FLAGS="$FORWARD_FLAGS --pr false"

  # Clear PID file so re-executed instance doesn't hit the concurrency guard
  # (this process is still alive when the tmux instance starts)
  rm -f "$PID_FILE"

  # Compute header height to match content exactly
  # Base: 3 (box) + 1 (PID/Mode) + 1 (Dir) + 1 (Stop) = 6
  HEADER_HEIGHT=6
  [ -n "$DIRECTIVE_FILE" ] && HEADER_HEIGHT=$((HEADER_HEIGHT + 1))
  [ "$USE_WORKTREE" = "yes" ] && HEADER_HEIGHT=$((HEADER_HEIGHT + 1))
  [ -n "${LOOM_CAPABILITIES:-}" ] && HEADER_HEIGHT=$((HEADER_HEIGHT + 1))

  # Use real terminal size so pane proportions are correct on attach
  TERM_COLS=$(tput cols 2>/dev/null || echo 80)
  TERM_LINES=$(tput lines 2>/dev/null || echo 50)

  # Main pane: the loom loop (LOOM_TMUX_CHILD tells the child to
  # write its banner to .header instead of stdout)
  tmux new-session -d -s "$TMUX_SESSION" -x "$TERM_COLS" -y "$TERM_LINES" \
    "LOOM_TMUX_CHILD=1 exec $0 $FORWARD_FLAGS"

  # Top: fixed header pane (always visible, sized to content)
  tmux split-window -v -b -t "$TMUX_SESSION:0.0" -l "$HEADER_HEIGHT" \
    "sh -c 'while true; do printf \"\\033[H\\033[J\"; cat \"$LOOM_DIR/.header\" 2>/dev/null || printf \"  Starting…\\n\"; sleep 2; done'"

  # Bottom-left: live status.md (compact, 10 lines)
  tmux split-window -v -t "$TMUX_SESSION:0.1" -l 10 \
    "exec watch -n 3 -t sh -c 'printf \"\\033[1;36m── status.md ──\\033[0m\\n\"; cat \"$LOOM_DIR/status.md\" 2>/dev/null || echo \"(empty)\"'"

  # Bottom-right: log tail
  tmux split-window -h -t "$TMUX_SESSION:0.2" \
    "exec tail -f \"$LOOM_DIR/logs/master.log\" 2>/dev/null || tail -f \"$LOG_FILE\""

  # Focus main pane and lock pane sizes on resize
  tmux select-pane -t "$TMUX_SESSION:0.1"
  tmux set-hook -t "$TMUX_SESSION" client-resized \
    "resize-pane -t 0.0 -y $HEADER_HEIGHT 2>/dev/null ; resize-pane -t 0.2 -y 10 2>/dev/null ; resize-pane -t 0.3 -y 10 2>/dev/null"

  echo -e "${GREEN}Loom launched in tmux session '${TMUX_SESSION}'${NC}"
  echo -e "  Attach:  ${BOLD}tmux attach -t $TMUX_SESSION${NC}"
  echo -e "  Kill:    ${BOLD}tmux kill-session -t $TMUX_SESSION${NC}"
  echo -e "  Stop:    ${BOLD}touch .loom/.stop${NC} (finishes current iteration)"

  # Auto-attach when running from a terminal (not inside Claude Code)
  if [ -z "${CLAUDECODE:-}" ]; then
    exec tmux attach -t "$TMUX_SESSION"
  fi
  # The tmux child owns all runtime state now — disable cleanup so the
  # parent doesn't delete files (.directive, .piped_directive) before
  # the async child reads them. The child handles its own cleanup.
  trap - EXIT
  exit 0
fi

# ─── Mode label for logging ───────────────────────────────────────
MODE_LABEL=""
[ -n "$SOURCES_LINEAR" ] && MODE_LABEL="${MODE_LABEL:+$MODE_LABEL+}linear"
[ -n "$SOURCES_GITHUB" ] && MODE_LABEL="${MODE_LABEL:+$MODE_LABEL+}github"
[ -n "$SOURCES_SLACK" ]  && MODE_LABEL="${MODE_LABEL:+$MODE_LABEL+}slack"
[ -n "$SOURCES_NOTION" ] && MODE_LABEL="${MODE_LABEL:+$MODE_LABEL+}notion"
[ -n "$SOURCES_SENTRY" ] && MODE_LABEL="${MODE_LABEL:+$MODE_LABEL+}sentry"
[ -n "$SOURCES_PROMPT" ] && MODE_LABEL="${MODE_LABEL:+$MODE_LABEL+}prompt"
[ -n "$SOURCES_PIPED" ]  && MODE_LABEL="${MODE_LABEL:+$MODE_LABEL+}prompt"
MODE_LABEL="${MODE_LABEL:-prd}"

# ─── Banner ──────────────────────────────────────────────────────
if [ "${LOOM_TMUX_CHILD:-}" = "1" ]; then
  # Compact banner for the fixed tmux header pane
  {
    echo -e "${CYAN}  ╔═══════════════════════════════════════════╗"
    echo "  ║             L O O M   L O O P             ║"
    echo -e "  ╚═══════════════════════════════════════════╝${NC}"
    echo -e "  ${DIM}PID${NC} ${BOLD}$$${NC}  ${DIM}|${NC}  ${DIM}Mode${NC} ${BOLD}$MODE_LABEL${NC}  ${DIM}|${NC}  ${DIM}Iter${NC} ${BOLD}$MAX_ITERATIONS${NC}  ${DIM}|${NC}  ${DIM}Timeout${NC} ${BOLD}${TIMEOUT}s${NC}"
    echo -e "  ${DIM}Dir${NC}   $PROJECT_DIR"
    [ -n "$DIRECTIVE_FILE" ] && echo -e "  ${DIM}Src${NC}   $DIRECTIVE_FILE"
    [ "${USE_WORKTREE:-}" = "yes" ] && echo -e "  ${DIM}Tree${NC}  $WORKTREE_DIR"
    [ -n "${LOOM_CAPABILITIES:-}" ] && echo -e "  ${DIM}MCPs${NC}  ${GREEN}$LOOM_CAPABILITIES${NC}"
    echo -en "  ${DIM}Stop${NC}  ${CYAN}touch $LOOM_DIR/.stop${NC}"
  } > "$LOOM_DIR/.header"
else
  echo -e "${CYAN}"
  echo "  ╔═══════════════════════════════════════════╗"
  echo "  ║             L O O M   L O O P             ║"
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
  if [ -n "$LOOM_CAPABILITIES" ]; then
    echo -e "  ${DIM}MCPs${NC}  ${GREEN}$LOOM_CAPABILITIES${NC}"
  fi
  echo ""
  echo -e "  ${CYAN}Graceful stop${NC}    touch $LOOM_DIR/.stop"
  echo -e "  ${CYAN}Kill${NC}             kill -TERM -$$"
  echo -e "  ${CYAN}Tail log${NC}         tail -f $LOG_FILE"
  echo -e "  ${CYAN}Status${NC}           cat $LOOM_DIR/status.md"
  echo -e "  ${CYAN}Master log${NC}       tail -f $LOOM_DIR/logs/master.log"
  echo ""
fi

if $DRY_RUN; then
  log "${YELLOW}${BOLD}DRY RUN${NC} — analysis only, no changes will be made"
fi

# ─── Ensure log directory exists ────────────────────────────────
mkdir -p "$LOOM_DIR/logs"

# ─── Clean stale sentinels ──────────────────────────────────────
rm -f "$LOOM_DIR/.iteration_marker"

# ─── Main Loop ───────────────────────────────────────────────────
ITERATION=0

while [ "$ITERATION" -lt "$MAX_ITERATIONS" ]; do
  ITERATION=$((ITERATION + 1))

  # ─── Graceful stop: check for .stop sentinel ──
  if [ -f "$LOOM_DIR/.stop" ]; then
    log "${YELLOW}${BOLD}Graceful stop requested${NC} (.loom/.stop found). Halting after iteration $((ITERATION - 1))."
    rm -f "$LOOM_DIR/.stop"
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
    PROMPT_TOP="$(sed '/^{{DIRECTIVE}}$/,$d' "$LOOM_DIR/directive.md")"
    PROMPT_BOTTOM="$(sed '1,/^{{DIRECTIVE}}$/d' "$LOOM_DIR/directive.md")"
    PROMPT="${PROMPT_TOP}${DIRECTIVE_CONTENT}"$'\n'"${PROMPT_BOTTOM}"
  else
    # Normal loop mode: full prompt.md orchestration with PRD
    PROMPT="$(cat "$LOOM_DIR/prompt.md")"
  fi

  # ─── Iteration marker for stop-guard hook ──
  touch "$LOOM_DIR/.iteration_marker"

  # ─── Dry-run: append analysis-only override ──
  if $DRY_RUN; then
    export LOOM_DRY_RUN=1

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
  ITER_LOG="$LOOM_DIR/logs/$(date '+%Y%m%d-%H%M%S')-${ITER_LABEL}.log"
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
  if [ -f "$LOOM_DIR/.iteration_marker" ]; then
    if [ ! -f "$LOOM_DIR/status.md" ] || [ "$LOOM_DIR/status.md" -ot "$LOOM_DIR/.iteration_marker" ]; then
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
  log "${YELLOW}${BOLD}Loom completed $MAX_ITERATIONS iterations. Halting.${NC}"
  master_log "$ITERATION" "$MODE_LABEL" "MAX_ITER" "0" "Reached max iterations"
fi
