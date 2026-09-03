#!/usr/bin/env bash
# Enforce the agent-definition contract stated in `.claude/agents/README.md`
# ("Every agent definition is a contract") and asserted by `CLAUDE.md` under
# "Agent execution rules": every standing agent definition in `.claude/agents/`
# states its verdict criterion, and marks its review dimensions as a recipe that
# serves the criterion instead of replacing it.
#
# Why this gate exists: pull request #2293, the concrete-prose writing standard,
# added that README paragraph and the CLAUDE.md sentence and edited zero agent
# definitions, so `CLAUDE.md` asserted a property that 28 of the 29 files did not
# hold. An orchestrator reading that sentence counts a dimension-exhausting "no
# findings" as a criterion-bound clean pass, which is the failure the sentence
# itself names.
#
# Scope — a positive, closed check over exactly two required shapes per file:
#   1. a level-2 heading `## Verdict criterion`, followed by a non-empty
#      paragraph stating what the agent confirms before it reports a verdict;
#   2. the recipe marker, which tells an agent that exhausting the file's
#      sections leaves the criterion unmet.
# The check reads structure. It does not judge whether a criterion is a good
# criterion, and it chases no spellings of a bad one: a human reviews the
# sentence, and this gate proves the sentence is present in every file.
#
# `README.md` carries the requirement rather than a criterion, so the check
# skips exactly that one file by name.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AGENT_DIR="$REPO_ROOT/.claude/agents"
HEADING='## Verdict criterion'
MARKER='They are a recipe, not the criterion.'

check_dir() {
  local dir="$1"
  local failures=0
  local checked=0
  local file base

  shopt -s nullglob
  for file in "$dir"/*.md; do
    base="$(basename "$file")"
    [ "$base" = "README.md" ] && continue
    checked=$((checked + 1))

    if ! grep -qxF "$HEADING" "$file"; then
      echo "  ✗ $base — no '$HEADING' section"
      failures=$((failures + 1))
      continue
    fi

    # The paragraph after the heading must carry text. `awk` prints the first
    # non-blank line following the heading; an empty result means the section
    # states no criterion.
    local body
    body="$(awk -v h="$HEADING" '
      $0 == h { seen = 1; next }
      seen && NF { print; exit }
    ' "$file")"
    if [ -z "$body" ]; then
      echo "  ✗ $base — '$HEADING' section is empty"
      failures=$((failures + 1))
      continue
    fi
    # A heading followed immediately by another heading states nothing.
    case "$body" in
      '#'*) echo "  ✗ $base — '$HEADING' section states no criterion"
            failures=$((failures + 1))
            continue ;;
    esac

    if ! grep -qF "$MARKER" "$file"; then
      echo "  ✗ $base — no recipe marker ('$MARKER')"
      failures=$((failures + 1))
      continue
    fi
  done
  shopt -u nullglob

  if [ "$checked" -eq 0 ]; then
    echo "  ✗ no agent definitions found under $dir"
    return 1
  fi
  echo "  checked $checked agent definitions"
  return "$((failures > 0 ? 1 : 0))"
}

# The self-test builds three definitions that each break one required shape and
# one that holds both, then asserts the check rejects the three and accepts the
# fourth. Without it, a check that returned success unconditionally would report
# a green gate over a repository that had lost every criterion.
self_test() {
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN

  printf -- '---\nname: good\n---\n\n%s\n\nReport PASS only when you can name the evidence.\n\nThe sections below name where gaps hide. %s\n\n## Rules\n\n- read\n' \
    "$HEADING" "$MARKER" > "$tmp/good.md"
  printf -- '---\nname: no-heading\n---\n\n## Rules\n\n- read\n' > "$tmp/no-heading.md"
  printf -- '---\nname: empty-section\n---\n\n%s\n\n## Rules\n\n- read\n' "$HEADING" > "$tmp/empty-section.md"
  printf -- '---\nname: no-marker\n---\n\n%s\n\nReport PASS only when you can name the evidence.\n\n## Rules\n\n- read\n' \
    "$HEADING" > "$tmp/no-marker.md"

  local out rc
  out="$(check_dir "$tmp" 2>&1)" && rc=0 || rc=$?
  if [ "$rc" -eq 0 ]; then
    echo "SELF-TEST FAILED: the check accepted three defective definitions"
    echo "$out"
    return 1
  fi
  local defect
  for defect in no-heading empty-section no-marker; do
    if ! printf '%s\n' "$out" | grep -q "$defect.md"; then
      echo "SELF-TEST FAILED: the check did not reject $defect.md"
      echo "$out"
      return 1
    fi
  done
  if printf '%s\n' "$out" | grep -q "good.md"; then
    echo "SELF-TEST FAILED: the check rejected a conforming definition"
    echo "$out"
    return 1
  fi

  rm -f "$tmp/no-heading.md" "$tmp/empty-section.md" "$tmp/no-marker.md"
  if ! check_dir "$tmp" > /dev/null 2>&1; then
    echo "SELF-TEST FAILED: the check rejected a directory holding only a conforming definition"
    return 1
  fi

  echo "✓ self-test: the check rejects a missing heading, an empty section, and a missing recipe marker"
  return 0
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit $?
fi

echo "Checking agent verdict criteria in .claude/agents/ …"
if check_dir "$AGENT_DIR"; then
  echo "✓ every agent definition states a verdict criterion and marks its recipe"
  exit 0
fi

cat <<'EOF'

Each agent definition under .claude/agents/ must carry:

  ## Verdict criterion

  <one sentence stating what the agent confirms before it reports a verdict>

  The sections below name where gaps of this kind usually hide. They are a recipe,
  not the criterion. Running every section still leaves the criterion unmet until
  you can state the sentence above about the work in front of you.

`.claude/agents/README.md` states the requirement, and `CLAUDE.md` asserts under
"Agent execution rules" that every standing definition already holds it.
EOF
exit 1
