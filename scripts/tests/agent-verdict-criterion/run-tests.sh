#!/usr/bin/env bash
# run-tests.sh — exercise `scripts/check-agent-verdict-criterion.sh` against canned agent
# directories.
#
# WHAT THIS TESTS.
#   * The gate passes a directory whose every agent definition carries one
#     `## Verdict criterion` heading followed by two paragraphs, and it names how many
#     files it read, so a run that read nothing cannot print the passing line.
#   * The gate fails a definition that carries no such heading, and it names that file.
#     The case puts the defect in the second of three files, because a loop that stops at
#     the first file it reads would otherwise pass.
#   * The gate fails a section holding one paragraph and a section holding none, because
#     `.claude/agents/README.md` requires both the criterion sentence and the sentence
#     marking the remaining sections as indicators.
#   * The gate counts paragraphs only up to the next heading, so a criterion section
#     followed by a two-paragraph section still reports one paragraph and fails.
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

# write_agent <path> <shape>
#   good        — one heading, two paragraphs, then a later section
#   none        — no heading at all
#   one-para    — one heading, one paragraph
#   zero-para   — one heading, then the next heading with only blank lines between
#   next-head   — one heading, one paragraph, then a heading whose section holds two
#   duplicate   — two headings, each with two paragraphs
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
            zero-para)
                echo "## Verdict criterion"
                echo ""
                echo ""
                ;;
            one-para)
                echo "## Verdict criterion"
                echo ""
                echo "Report DONE only after you have read the code behind every claim."
                echo ""
                ;;
            next-head)
                echo "## Verdict criterion"
                echo ""
                echo "Report DONE only after you have read the code behind every claim."
                echo ""
                echo "## Rules"
                echo ""
                echo "First paragraph of a later section."
                echo ""
                echo "Second paragraph of a later section."
                echo ""
                ;;
            duplicate)
                echo "## Verdict criterion"
                echo ""
                echo "Report DONE only after you have read the code behind every claim."
                echo ""
                echo "The sections below tell you where to look; this criterion decides."
                echo ""
                echo "## Verdict criterion"
                echo ""
                echo "Report DONE when the checklist below has no unticked box."
                echo ""
                echo "The sections below tell you where to look; this criterion decides."
                echo ""
                ;;
            good)
                echo "## Verdict criterion"
                echo ""
                echo "Report DONE only after you have read the code behind every claim."
                echo ""
                echo "The sections below tell you where to look; this criterion decides."
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
run_case "criterion section holds one paragraph" 1 "agent-1.md holds 1 paragraph(s)" one-para
run_case "criterion section holds no paragraph" 1 "agent-1.md holds 0 paragraph(s)" zero-para
run_case "paragraphs after the next heading do not count" 1 "agent-1.md holds 1 paragraph(s)" next-head
run_case "two criterion headings" 1 "agent-1.md carries 2" duplicate
run_case "directory holds no agent definition" 1 "holds no agent definition to check"
run_case "directory absent" 1 "agent directory not found" good

echo ""
echo "passed: $passed  failed: $failed"
[[ "$failed" -eq 0 ]]
