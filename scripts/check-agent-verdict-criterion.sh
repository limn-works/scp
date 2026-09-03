#!/usr/bin/env bash
# check-agent-verdict-criterion.sh — CI gate requiring every agent definition in
# `.claude/agents/` to state the criterion its agent must satisfy before it
# reports a verdict, and to mark the rest of the file as recipe.
#
# ---------------------------------------------------------------------------
# WHY THIS EXISTS
# ---------------------------------------------------------------------------
# `CLAUDE.md` §Agent execution rules states that an agent which receives only a
# recipe satisfies the recipe and reports success, and that the same rule
# governs the standing agent definitions in `.claude/agents/`. Pull request
# #2293, the concrete-prose writing standard, wrote that sentence in the
# present indicative — as a description of the roster — while 20 of the 29
# definitions stated no criterion at all, and it bound the obligation only to
# whoever edited a definition next. A rule that describes a state nobody has to
# produce leaves an orchestrator reading `CLAUDE.md` believing every reviewer
# carries a criterion when most carried a checklist, so a reviewer that walked
# its dimensions and found nothing returned a clean pass that counted toward
# the double-zero merge gate.
#
# This gate makes the sentence in `CLAUDE.md` a property of the tree rather
# than a claim about it.
#
# ---------------------------------------------------------------------------
# WHAT THIS CHECKS (positive shape, closed by construction)
# ---------------------------------------------------------------------------
# For every `*.md` file in `.claude/agents/` except `README.md`, the file must
# carry all four properties:
#
#   1. a heading line reading exactly `## Verdict criterion`;
#   2. that heading standing before every other `## ` heading in the file, so
#      an agent reading the file top-down meets the criterion before the
#      recipe;
#   3. inside that section, a line `**Criterion:** <sentence>` carrying at
#      least 40 characters after the marker;
#   4. inside that section, a line `**Recipe:** <sentence>` carrying at least
#      40 characters after the marker.
#
# The check matches four fixed shapes against a fixed file set. It does not
# grow a list of forbidden spellings, and adding an agent definition extends
# the file set without editing this script.
#
# ---------------------------------------------------------------------------
# WHAT THIS DOES NOT CHECK
# ---------------------------------------------------------------------------
# No script can judge whether a criterion sentence states a real membership
# test rather than another checklist. This gate proves the section is present
# and non-empty; a human reviewer decides whether the sentence decides
# anything. `.claude/agents/README.md` §Every agent definition is a contract
# states the test that reviewer applies.
#
# ---------------------------------------------------------------------------
# USAGE
# ---------------------------------------------------------------------------
#   bash scripts/check-agent-verdict-criterion.sh
#   bash scripts/check-agent-verdict-criterion.sh --self-test
#
# Exit codes:
#   0  — every definition carries a criterion section
#   1  — at least one definition omits or empties it
#   2  — invocation error (the agents directory is missing)
#
# ---------------------------------------------------------------------------
# SELF-TEST
# ---------------------------------------------------------------------------
# `--self-test` plants five scratch files: a compliant definition (must PASS),
# a definition with no criterion section (must FAIL), a section with no
# `**Criterion:**` line (must FAIL), a section with no `**Recipe:**` line (must
# FAIL), and a section placed after another `## ` heading (must FAIL). It
# writes only into a temp directory and removes it. CI runs the self-test
# before the real scan, so a scan that reports success has already proven it
# can report failure.
#
# ---------------------------------------------------------------------------
# PORTABILITY
# ---------------------------------------------------------------------------
# POSIX bash 3.2 + awk. No GNU-specific flags, no ripgrep.

set -euo pipefail

AGENTS_DIR=".claude/agents"

# scan_file FILE
#   Prints one line per unmet property. Returns 1 when the file breaks any
#   property, 0 when the file carries all four.
scan_file() {
    local file="$1"
    local problems
    problems="$(
        awk '
        BEGIN { first = 1; in_frontmatter = 0; other_h2_first = 0
                has_section = 0; in_section = 0; has_criterion = 0; has_recipe = 0 }
        {
            # The YAML frontmatter holds a single-line JSON description that can
            # contain any text, so skip it rather than match headings inside it.
            if (first) { first = 0; if ($0 == "---") { in_frontmatter = 1; next } }
            if (in_frontmatter) { if ($0 == "---") in_frontmatter = 0; next }

            if ($0 ~ /^## /) {
                if ($0 == "## Verdict criterion") { has_section = 1; in_section = 1 }
                else { if (has_section == 0) other_h2_first = 1; in_section = 0 }
                next
            }
            if (in_section) {
                if ($0 ~ /^\*\*Criterion:\*\*/) {
                    t = $0; sub(/^\*\*Criterion:\*\*[ \t]*/, "", t)
                    if (length(t) >= 40) has_criterion = 1
                }
                if ($0 ~ /^\*\*Recipe:\*\*/) {
                    t = $0; sub(/^\*\*Recipe:\*\*[ \t]*/, "", t)
                    if (length(t) >= 40) has_recipe = 1
                }
            }
        }
        END {
            if (has_section == 0) {
                print "no `## Verdict criterion` heading"
            } else {
                if (other_h2_first == 1)
                    print "`## Verdict criterion` stands after another `## ` heading"
                if (has_criterion == 0)
                    print "the section has no `**Criterion:** <sentence>` line of 40 characters or more"
                if (has_recipe == 0)
                    print "the section has no `**Recipe:** <sentence>` line of 40 characters or more"
            }
        }' "$file"
    )"
    if [ -n "$problems" ]; then
        printf '%s\n' "$problems" | while IFS= read -r line; do
            printf '  %s: %s\n' "$file" "$line"
        done
        return 1
    fi
    return 0
}

# run_check DIR
#   Scans every agent definition in DIR. Returns 1 when any file breaks a
#   property, 0 when every file carries all four.
run_check() {
    local dir="$1"
    local failed=0
    local file
    local count=0
    for file in "$dir"/*.md; do
        [ -e "$file" ] || continue
        case "$(basename "$file")" in
            README.md) continue ;;
        esac
        count=$((count + 1))
        if ! scan_file "$file"; then
            failed=1
        fi
    done
    if [ "$count" -eq 0 ]; then
        echo "ERROR: $dir holds no agent definitions to check" >&2
        return 2
    fi
    return "$failed"
}

self_test() {
    echo "check-agent-verdict-criterion self-test..."
    local tmp rc=0
    tmp="$(mktemp -d)"

    # Fixture 1: compliant — MUST pass.
    mkdir -p "$tmp/good"
    cat >"$tmp/good/compliant.md" <<'EOF'
---
name: compliant
---

## Verdict criterion

**Criterion:** Report clean only when you have read the code that enforces every property the change claims.

**Recipe:** Everything below is the recipe: the dimensions where a gap usually hides, not the definition of a gap.

## Review Dimensions

- something
EOF
    if scan_file "$tmp/good/compliant.md" >/dev/null; then
        echo "  [ok] compliant definition accepted"
    else
        echo "  [FAIL] self-test: a compliant definition was rejected" >&2
        scan_file "$tmp/good/compliant.md" >&2 || true
        rc=1
    fi

    # Fixture 2: no criterion section — MUST fail.
    mkdir -p "$tmp/bad1"
    cat >"$tmp/bad1/no-section.md" <<'EOF'
---
name: no-section
---

You are a reviewer.

## What You Do

1. Model the adversary.
2. Abuse legitimate features.
EOF
    if scan_file "$tmp/bad1/no-section.md" >/dev/null; then
        echo "  [FAIL] self-test: a definition with no criterion section was accepted" >&2
        rc=1
    else
        echo "  [ok] missing criterion section detected"
    fi

    # Fixture 3: section present, no Criterion line — MUST fail.
    mkdir -p "$tmp/bad2"
    cat >"$tmp/bad2/no-criterion-line.md" <<'EOF'
---
name: no-criterion-line
---

## Verdict criterion

**Recipe:** Everything below is the recipe: the dimensions where a gap usually hides, not the definition of a gap.
EOF
    if scan_file "$tmp/bad2/no-criterion-line.md" >/dev/null; then
        echo "  [FAIL] self-test: a section with no **Criterion:** line was accepted" >&2
        rc=1
    else
        echo "  [ok] missing **Criterion:** line detected"
    fi

    # Fixture 4: section present, no Recipe line — MUST fail.
    mkdir -p "$tmp/bad3"
    cat >"$tmp/bad3/no-recipe-line.md" <<'EOF'
---
name: no-recipe-line
---

## Verdict criterion

**Criterion:** Report clean only when you have read the code that enforces every property the change claims.
EOF
    if scan_file "$tmp/bad3/no-recipe-line.md" >/dev/null; then
        echo "  [FAIL] self-test: a section with no **Recipe:** line was accepted" >&2
        rc=1
    else
        echo "  [ok] missing **Recipe:** line detected"
    fi

    # Fixture 5: criterion section buried below the recipe — MUST fail.
    mkdir -p "$tmp/bad4"
    cat >"$tmp/bad4/buried.md" <<'EOF'
---
name: buried
---

## What You Do

1. Model the adversary.

## Verdict criterion

**Criterion:** Report clean only when you have read the code that enforces every property the change claims.

**Recipe:** Everything below is the recipe: the dimensions where a gap usually hides, not the definition of a gap.
EOF
    if scan_file "$tmp/bad4/buried.md" >/dev/null; then
        echo "  [FAIL] self-test: a criterion section placed after the recipe was accepted" >&2
        rc=1
    else
        echo "  [ok] criterion section placed after another heading detected"
    fi

    # Fixture 6: an empty agents directory must be an invocation error, so a
    # scan that finds nothing can never be read as a pass.
    mkdir -p "$tmp/empty"
    set +e
    run_check "$tmp/empty" >/dev/null 2>&1
    local empty_rc=$?
    set -e
    if [ "$empty_rc" -eq 2 ]; then
        echo "  [ok] empty agents directory reported as an invocation error"
    else
        echo "  [FAIL] self-test: an empty agents directory returned $empty_rc, not 2" >&2
        rc=1
    fi

    rm -rf "$tmp"
    if [ "$rc" -eq 0 ]; then
        echo "check-agent-verdict-criterion self-test PASSED"
    fi
    return "$rc"
}

main() {
    if [ "${1:-}" = "--self-test" ]; then
        self_test
        return
    fi

    cd "$(git rev-parse --show-toplevel)"

    if [ ! -d "$AGENTS_DIR" ]; then
        echo "ERROR: $AGENTS_DIR does not exist" >&2
        return 2
    fi

    echo "Checking that every agent definition in $AGENTS_DIR states a verdict criterion..."
    if run_check "$AGENTS_DIR"; then
        echo "check-agent-verdict-criterion: OK"
        return 0
    fi

    cat >&2 <<'EOF'

ERROR: an agent definition above does not state the criterion its agent must
satisfy before it reports a verdict.

Add this section to the file, before every other `## ` heading:

    ## Verdict criterion

    **Criterion:** <one sentence naming what the agent must confirm, and which
    verdict it reports when the confirmation fails>

    **Recipe:** <one sentence saying that the rest of the file lists where the
    target usually hides, and that exhausting the list does not satisfy the
    criterion>

An agent handed a checklist and no criterion completes the checklist and
reports success. See `.claude/agents/README.md` §Every agent definition is a
contract, and `CLAUDE.md` §Agent execution rules.
EOF
    return 1
}

main "$@"
