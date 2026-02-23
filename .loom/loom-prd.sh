#!/usr/bin/env bash
set -euo pipefail

# ─── Loom PRD Generator ────────────────────────────────────────
# Generates .loom/prd.json from specification documents.
# Wraps `claude -p` with a structured generation prompt.
#
# Usage:
#   loom-prd.sh <files...> [--append] [--prefix PREFIX] [--max N]
#   loom-prd.sh spec.md sketch.md
#   loom-prd.sh --append planning-session-02.md
#   loom-prd.sh --prefix SCP spec.md
# ─────────────────────────────────────────────────────────────────

LOOM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$LOOM_DIR")"
PROJECT_NAME="$(basename "$PROJECT_DIR")"
PRD_FILE="$LOOM_DIR/prd.json"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

die() { echo -e "${RED}Error: $1${NC}" >&2; exit 1; }

# ─── Parse arguments ─────────────────────────────────────────────
FILES=()
APPEND=false
PREFIX=""
MAX_STORIES=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --append|-a)
      APPEND=true
      shift
      ;;
    --prefix|-p)
      [[ $# -ge 2 ]] || die "$1 requires a value"
      PREFIX="$2"
      shift 2
      ;;
    --max|-m)
      [[ $# -ge 2 ]] || die "$1 requires a value"
      MAX_STORIES="$2"
      shift 2
      ;;
    -h|--help)
      cat <<'EOF'
Usage: loom-prd.sh <files...> [OPTIONS]

Generates .loom/prd.json from specification documents using Claude.

Arguments:
  <files...>            One or more files to ingest (specs, planning docs, etc.)

Options:
  -a, --append          Add stories to existing PRD instead of replacing
  -p, --prefix PREFIX   Story ID prefix (default: project dir name, uppercased)
  -m, --max N           Maximum stories to generate
  -h, --help            Show this help

Examples:
  loom-prd.sh spec.md sketch.md
  loom-prd.sh --append planning-session-02.md
  loom-prd.sh --prefix SCP --max 60 spec.md
  loom-prd.sh *.md
EOF
      exit 0
      ;;
    -*)
      die "Unknown option: $1"
      ;;
    *)
      FILES+=("$1")
      shift
      ;;
  esac
done

[[ ${#FILES[@]} -gt 0 ]] || die "No input files specified. Run with --help for usage."

# Validate files exist
for f in "${FILES[@]}"; do
  [[ -f "$f" ]] || die "File not found: $f"
done

# Default prefix
if [ -z "$PREFIX" ]; then
  PREFIX=$(echo "$PROJECT_NAME" | tr '[:lower:]' '[:upper:]' | tr -cd 'A-Z' | head -c 5)
  [ -z "$PREFIX" ] && PREFIX="PRD"
fi

# ─── Preflight ───────────────────────────────────────────────────
command -v claude &>/dev/null || die "claude CLI not found in PATH"
command -v jq &>/dev/null || die "jq is required"

echo -e "${CYAN}${BOLD}Loom PRD Generator${NC}"
echo -e "${DIM}─────────────────────────────────────────${NC}"
echo -e "  ${DIM}Project${NC}  $PROJECT_NAME"
echo -e "  ${DIM}Prefix${NC}   $PREFIX"
echo -e "  ${DIM}Files${NC}    ${FILES[*]}"
echo -e "  ${DIM}Mode${NC}     $(if $APPEND; then echo "append"; else echo "create"; fi)"
[ -n "$MAX_STORIES" ] && echo -e "  ${DIM}Max${NC}      $MAX_STORIES stories"
echo ""

# ─── Build prompt ────────────────────────────────────────────────
PROMPT="You are a PRD generator for the Loom autonomous development system. Your job is to read specification documents and produce a structured prd.json file.

## Input Files

"

for f in "${FILES[@]}"; do
  PROMPT+="### $(basename "$f")

\`\`\`
$(cat "$f")
\`\`\`

"
done

# Include existing PRD context if appending
if $APPEND && [ -f "$PRD_FILE" ]; then
  PROMPT+="## Existing PRD (append mode)

There is an existing PRD. Here are the current gates and story IDs — do NOT duplicate or modify them. Continue numbering from after the last existing ID.

\`\`\`json
$(jq '{gates: .gates, existingStoryIds: [.stories[].id]}' "$PRD_FILE" 2>/dev/null || echo '{}')
\`\`\`

"
fi

PROMPT+="## Output Requirements

Generate a COMPLETE, VALID JSON object for .loom/prd.json. Output ONLY the JSON — no markdown fences, no commentary, no explanation.

### Schema

{
  \"project\": \"$PROJECT_NAME\",
  \"description\": \"One-line project description.\",
  \"gates\": [
    {
      \"id\": \"gate-N\",
      \"name\": \"Human-readable gate name\",
      \"priority\": \"P0|P1|P2\",
      \"status\": \"pending\",
      \"stories\": [\"$PREFIX-001\", ...]
    }
  ],
  \"stories\": [
    {
      \"id\": \"$PREFIX-001\",
      \"title\": \"Short imperative title\",
      \"gate\": \"gate-1\",
      \"priority\": \"P0|P1|P2\",
      \"severity\": \"critical|major|minor\",
      \"status\": \"pending\",
      \"files\": [\"src/path/to/file.ts\"],
      \"description\": \"What and why. Context for the implementer.\",
      \"acceptanceCriteria\": [\"Concrete, testable assertion\"],
      \"actionItems\": [\"Specific implementation step\"],
      \"blockedBy\": [],
      \"details\": {}
    }
  ]
}

### Required fields on every story
id, title, gate, priority, severity, status, files, description, acceptanceCriteria, actionItems, blockedBy, details

- severity: \"critical\" (blocking/security), \"major\" (significant), \"minor\" (cleanup/polish)
- actionItems: concrete implementation steps (what to do)
- acceptanceCriteria: concrete verification steps (what to check)
- details: object for arbitrary project-specific metadata (always present, use {} when empty). Common keys: protocolSection, designUrl, apiEndpoints, migrationSteps, currentBehavior, targetBehavior, etc.

### Rules

1. ATOMIC STORIES — each completable by a single AI agent in ~15-30 min of work. Split larger work.
2. ID FORMAT — $PREFIX-NNN with zero-padded 3-digit numbers starting at 001.
3. GATES — group stories into logical phases. P0 first (foundational/blocking), then P1 (core), then P2 (polish).
4. DEPENDENCIES — set blockedBy accurately. Only list true blockers. Maximize parallelism.
5. FILES — predict paths using project conventions.
6. ACCEPTANCE CRITERIA — concrete, testable. Not 'it works' but 'POST /api/x returns 200 with JWT'.
7. NO OVER-DECOMPOSITION — keep coupled work together. A model + its migration + its route = one story.
8. CRITICAL PATH FIRST — lowest story numbers on the critical path.
9. DESCRIPTION — enough context for autonomous implementation. Include spec references."

if [ -n "$MAX_STORIES" ]; then
  PROMPT+="
10. MAXIMUM $MAX_STORIES STORIES. Prioritize the most important work. Note omitted scope in the project description."
fi

if $APPEND; then
  PROMPT+="

APPEND MODE: Output only the NEW gates and stories to add. I will merge them with the existing PRD.
Format: {\"gates\": [...new gates...], \"stories\": [...new stories...]}"
fi

# ─── Execute ─────────────────────────────────────────────────────
echo -e "${CYAN}Generating PRD...${NC}"
echo ""

TMPFILE=$(mktemp)
trap "rm -f $TMPFILE" EXIT

if claude -p --output-format text "$PROMPT" > "$TMPFILE" 2>/dev/null; then
  # Strip any markdown fences if Claude wrapped the JSON
  sed -i.bak -E '/^```([jJ][sS][oO][nN])?[[:space:]]*$/d' "$TMPFILE" && rm -f "${TMPFILE}.bak"

  # Validate JSON
  if ! jq '.' "$TMPFILE" > /dev/null 2>&1; then
    echo -e "${RED}Claude produced invalid JSON. Raw output:${NC}"
    head -20 "$TMPFILE"
    die "Failed to generate valid PRD"
  fi

  if $APPEND && [ -f "$PRD_FILE" ]; then
    # Merge new content into existing PRD
    NEW_GATES=$(jq '.gates // []' "$TMPFILE")
    NEW_STORIES=$(jq '.stories // []' "$TMPFILE")

    jq --argjson ng "$NEW_GATES" --argjson ns "$NEW_STORIES" '
      .gates = (.gates + $ng) |
      .stories = (.stories + $ns)
    ' "$PRD_FILE" > "${PRD_FILE}.tmp" && mv "${PRD_FILE}.tmp" "$PRD_FILE"

    echo -e "${GREEN}${BOLD}PRD updated: $PRD_FILE${NC}"
  else
    # Replace entire PRD
    jq '.' "$TMPFILE" > "$PRD_FILE"
    echo -e "${GREEN}${BOLD}PRD generated: $PRD_FILE${NC}"
  fi

  # Summary
  echo ""
  STORY_COUNT=$(jq '.stories | length' "$PRD_FILE")
  GATE_COUNT=$(jq '.gates | length' "$PRD_FILE")
  BLOCKED=$(jq '[.stories[] | select(.blockedBy | length > 0)] | length' "$PRD_FILE")
  ROOT=$(jq '[.stories[] | select(.blockedBy | length == 0)] | length' "$PRD_FILE")

  echo -e "  Stories:  ${BOLD}$STORY_COUNT${NC}"
  echo -e "  Gates:    ${BOLD}$GATE_COUNT${NC}"
  echo -e "  Blocked:  $BLOCKED stories have dependencies"
  echo -e "  Root:     ${GREEN}$ROOT stories can start immediately${NC}"
  echo ""

  # Gate breakdown
  jq -r '.gates[] | "    \(.id)  \(.name)\t\(.priority)  \(.stories | length) stories"' "$PRD_FILE" 2>/dev/null | \
    column -t -s $'\t' || true

else
  die "Claude exited with an error. Check your API key and network connection."
fi
