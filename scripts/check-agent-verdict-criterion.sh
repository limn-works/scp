#!/usr/bin/env bash
# check-agent-verdict-criterion.sh — every standing agent definition states a verdict
# criterion and marks its review dimensions as indicators.
#
# WHY THIS EXISTS.
#   `.claude/agents/README.md` requires two things of every agent definition: one sentence
#   stating what the agent has to confirm before it reports a verdict, and a sentence
#   marking the rest of the file as the place to look rather than as the definition. The
#   CLAUDE.md rule "Write every agent prompt as a contract, never as your recipe" states
#   the same requirement for the standing definitions. Before this check existed, that
#   requirement bound only the author who happened to read the README: on the day the
#   README added it, twenty of the twenty-nine definitions held neither the word "verdict"
#   nor the word "criterion" anywhere in the file, and nothing reported that.
#
# WHAT THIS CHECK ESTABLISHES.
#   Every file matching `.claude/agents/*.md`, other than `README.md`, carries exactly one
#   `## Verdict criterion` heading, and that section holds two non-empty paragraphs before
#   the next heading. The check fails when the directory matches no agent file, so an
#   emptied or renamed directory reports a failure instead of passing over nothing.
#
# WHAT THIS CHECK DOES NOT ESTABLISH.
#   It reads the shape of the section, never the meaning of the sentences inside it. An
#   author can satisfy this check with a recipe written under the heading. A reviewer
#   reading the file decides whether the first paragraph states a criterion — what the
#   agent must confirm — and whether the second marks the remaining sections as
#   indicators. This check catches the absent section, which is the failure that shipped.
#
# Usage: bash scripts/check-agent-verdict-criterion.sh [agents-dir]
#   agents-dir defaults to `.claude/agents` under the repository root.

set -euo pipefail

HEADING='## Verdict criterion'

repo_root=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
agents_dir="${1:-${repo_root}/.claude/agents}"

if [[ ! -d ${agents_dir} ]]; then
    echo "FAIL: agent directory not found: ${agents_dir}" >&2
    exit 1
fi

shopt -s nullglob
agent_files=()
for path in "${agents_dir}"/*.md; do
    [[ $(basename "${path}") == "README.md" ]] && continue
    agent_files+=("${path}")
done
shopt -u nullglob

if [[ ${#agent_files[@]} -eq 0 ]]; then
    echo "FAIL: ${agents_dir} holds no agent definition to check." >&2
    echo "      A check that reads no file passes over nothing and proves nothing." >&2
    exit 1
fi

failures=0

for path in "${agent_files[@]}"; do
    name=$(basename "${path}")

    heading_count=$(grep -c -x -F "${HEADING}" "${path}" || true)
    if [[ ${heading_count} -eq 0 ]]; then
        echo "FAIL: ${name} states no verdict criterion." >&2
        echo "      Add a '${HEADING}' section: one sentence naming what this agent" >&2
        echo "      must confirm before it reports a verdict, then one sentence marking" >&2
        echo "      the remaining sections as indicators. See .claude/agents/README.md." >&2
        failures=$((failures + 1))
        continue
    fi
    if [[ ${heading_count} -gt 1 ]]; then
        echo "FAIL: ${name} carries ${heading_count} '${HEADING}' headings." >&2
        echo "      Two criteria let an agent pick the one it already satisfies." >&2
        failures=$((failures + 1))
        continue
    fi

    # Count the non-empty paragraphs between the heading and the next heading of any level.
    paragraphs=$(awk -v heading="${HEADING}" '
        $0 == heading { inside = 1; blank = 1; next }
        inside && /^#/ { exit }
        inside {
            if ($0 ~ /^[[:space:]]*$/) { blank = 1 }
            else if (blank) { count++; blank = 0 }
        }
        END { print count + 0 }
    ' "${path}")

    if [[ ${paragraphs} -lt 2 ]]; then
        echo "FAIL: ${name} holds ${paragraphs} paragraph(s) under '${HEADING}'; 2 are required." >&2
        echo "      The first states the criterion. The second marks the remaining" >&2
        echo "      sections as indicators, so an agent that exhausted them still knows" >&2
        echo "      it has not met the criterion." >&2
        failures=$((failures + 1))
    fi
done

if [[ ${failures} -gt 0 ]]; then
    echo "" >&2
    echo "${failures} agent definition(s) failed the verdict-criterion check." >&2
    exit 1
fi

echo "OK: ${#agent_files[@]} agent definitions each state a verdict criterion."
