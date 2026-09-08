#!/usr/bin/env bash
# run-tests.sh — exercise `scripts/check-agent-verdict-criterion.sh` against canned agent
# directories.
#
# WHAT THIS TESTS.
#   * The gate passes a directory whose every agent definition carries one
#     `## Verdict criterion` heading holding a `**Criterion:**` line and an
#     `**Indicators, not the criterion.**` line, and it names how many files it read, so a
#     run that read nothing cannot print the passing line.
#   * The gate fails a definition that carries no such heading, and it names that file. The
#     case puts the defect in the second of three files, and again in the third, because a
#     loop that stops at the first file it reads would otherwise pass.
#   * The gate fails a definition whose criterion section sits below another `## ` heading,
#     because an agent reads top-down and a recipe placed first stands in for the criterion.
#   * The gate fails a section that drops either label, and a section whose label carries
#     no sentence after it.
#   * The gate reads only up to the next heading, so a label written in a later section
#     does not satisfy the criterion section.
#   * The gate fails a definition carrying two `## Verdict criterion` headings, because two
#     criteria let an agent report against whichever one it already satisfies.
#   * The gate fails a directory holding no agent definition, and fails a directory that
#     does not exist. Both are the vacuous pass: a check that reads no file reports success
#     about nothing, which is the failure this whole workstream hunts.
#   * `README.md` carries no criterion of its own and is exempt: every passing case holds
#     one, so each also proves the exemption.
#
# HOW EACH CASE IS BUILT. `run_case` makes a temporary directory, writes a `README.md` and
# the case's agent files into it, runs the gate against that directory, and compares the
# exit status and the required output fragment against the case's expectation.
#
# Exit 0 when every case matches its expectation, 1 otherwise.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
CHECK="$REPO_ROOT/scripts/check-agent-verdict-criterion.sh"

if [[ ! -f "$CHECK" ]]; then
    echo "ERROR: $CHECK does not exist" >&2
    exit 1
fi

TMP_PARENT=$(mktemp -d)
trap 'rm -rf "$TMP_PARENT"' EXIT

passed=0
failed=0

CRITERION_LINE='**Criterion:** Report DONE only after you have read the code behind every claim.'
INDICATOR_LINE='**Indicators, not the criterion.** The sections below tell you where to look; the criterion above decides.'

# write_agent <path> <shape>
#   good          — one heading first, both labels, then a later section
#   none          — no heading at all
#   no-criterion  — the heading and the indicator label, no criterion label
#   no-indicator  — the heading and the criterion label, no indicator label
#   empty-label   — both labels present, the criterion label carrying no sentence
#   late-heading  — a `## Method` section above the criterion section
#   next-section  — the criterion label in the section, the indicator label after the
#                   next heading
#   duplicate     — two criterion headings, each complete
write_agent() {
    local path=$1 shape=$2
    {
        echo "---"
        echo "name: canned"
        echo "---"
        echo ""
        echo "You are a canned agent."
        echo ""
        case "$shape" in
            none) ;;
            late-heading)
                echo "## Method"
                echo ""
                echo "Read the diff."
                echo ""
                echo "## Verdict criterion"
                echo ""
                echo "$CRITERION_LINE"
                echo ""
                echo "$INDICATOR_LINE"
                echo ""
                ;;
            no-criterion)
                echo "## Verdict criterion"
                echo ""
                echo "$INDICATOR_LINE"
                echo ""
                ;;
            no-indicator)
                echo "## Verdict criterion"
                echo ""
                echo "$CRITERION_LINE"
                echo ""
                ;;
            empty-label)
                echo "## Verdict criterion"
                echo ""
                echo "**Criterion:**"
                echo ""
                echo "$INDICATOR_LINE"
                echo ""
                ;;
            next-section)
                echo "## Verdict criterion"
                echo ""
                echo "$CRITERION_LINE"
                echo ""
                echo "## Rules"
                echo ""
                echo "$INDICATOR_LINE"
                echo ""
                ;;
            duplicate)
                echo "## Verdict criterion"
                echo ""
                echo "$CRITERION_LINE"
                echo ""
                echo "$INDICATOR_LINE"
                echo ""
                echo "## Verdict criterion"
                echo ""
                echo "**Criterion:** Report DONE when the checklist below has no unticked box."
                echo ""
                echo "$INDICATOR_LINE"
                echo ""
                ;;
            good)
                echo "## Verdict criterion"
                echo ""
                echo "$CRITERION_LINE"
                echo ""
                echo "$INDICATOR_LINE"
                echo ""
                ;;
            *)
                echo "ERROR: unknown shape $shape" >&2
                exit 1
                ;;
        esac
        echo "## Method"
        echo ""
        echo "Read the diff."
    } >"$path"
}

# run_case <name> <expected-status> <required-output-fragment> <shape>...
#   Each shape produces one agent file, named agent-1.md, agent-2.md, and so on.
#   An empty shape list produces a directory holding only README.md.
run_case() {
    local name=$1 expected_status=$2 fragment=$3
    shift 3

    local dir
    dir=$(mktemp -d "$TMP_PARENT/case.XXXXXX")/agents
    mkdir -p "$dir"

    # The README states the requirement and carries no criterion of its own.
    printf '# Agent Model\n\nEvery agent file states its verdict criterion.\n' >"$dir/README.md"

    local i=0
    local shape
    for shape in "$@"; do
        i=$((i + 1))
        write_agent "$dir/agent-$i.md" "$shape"
    done

    if [[ "$name" == "directory absent" ]]; then
        rm -rf "$dir"
    fi

    local output status
    output=$(bash "$CHECK" "$dir" 2>&1)
    status=$?

    local ok=1
    if [[ "$status" -ne "$expected_status" ]]; then
        ok=0
        echo "FAIL [$name]: exit $status, expected $expected_status" >&2
    fi
    if [[ -n "$fragment" ]] && ! grep -qF -- "$fragment" <<<"$output"; then
        ok=0
        echo "FAIL [$name]: output does not hold '$fragment'" >&2
    fi

    if [[ "$ok" -eq 1 ]]; then
        passed=$((passed + 1))
        echo "PASS [$name]"
    else
        failed=$((failed + 1))
        echo "--- output ---" >&2
        echo "$output" >&2
        echo "--------------" >&2
    fi
}

run_case "every definition compliant" 0 "OK: 3 agent definitions" good good good
run_case "second definition has no criterion" 1 "agent-2.md states no verdict criterion" good none good
run_case "third definition has no criterion" 1 "agent-3.md states no verdict criterion" good good none
run_case "criterion label absent" 1 "agent-1.md holds no '**Criterion:**' line" no-criterion
run_case "indicator label absent" 1 "agent-1.md holds no '**Indicators, not the criterion.**' line" no-indicator
run_case "criterion label carries no sentence" 1 "agent-1.md carries '**Criterion:**' with nothing after it" empty-label
run_case "criterion section is not the first section" 1 "agent-1.md opens with the section '## Method'" late-heading
run_case "label after the next heading does not count" 1 "agent-1.md holds no '**Indicators, not the criterion.**' line" next-section
run_case "two criterion headings" 1 "agent-1.md carries 2" duplicate
run_case "directory holds no agent definition" 1 "holds no agent definition to check"
run_case "directory absent" 1 "agent directory not found" good

echo ""
echo "passed: $passed  failed: $failed"
[[ "$failed" -eq 0 ]]
