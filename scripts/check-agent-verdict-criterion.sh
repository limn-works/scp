#!/usr/bin/env bash
# check-agent-verdict-criterion.sh — every standing agent definition states a verdict
# criterion and labels its remaining sections as indicators.
#
# WHY THIS EXISTS.
#   `.claude/agents/README.md` requires two things of every agent definition: one sentence
#   stating what the agent has to confirm before it reports a verdict, and one sentence
#   labelling the rest of the file as the place to look rather than as the definition. The
#   CLAUDE.md rule "Write every agent prompt as a contract, never as your recipe" states
#   the same requirement for the standing definitions. Before this check existed, that
#   requirement bound only the author who happened to read the README: on the day the
#   README added it, twenty of the twenty-nine definitions held neither the word "verdict"
#   nor the word "criterion" anywhere in the file, and nothing reported that.
#
# WHAT THIS CHECK ESTABLISHES.
#   Every file matching `.claude/agents/*.md`, other than `README.md`, carries exactly one
#   `## Verdict criterion` heading; that heading is the file's first `## ` heading, so an
#   agent reading top-down meets the criterion before any recipe; and the section holds one
#   line opening `**Criterion:**` and one line opening `**Indicators, not the criterion.**`,
#   each with text after the label. The check fails when the directory matches no agent
#   file, so an emptied or renamed directory reports a failure instead of passing over
#   nothing.
#
# WHAT THIS CHECK DOES NOT ESTABLISH.
#   It reads the shape of the section, never the meaning of the sentences inside it. An
#   author can satisfy this check with a recipe written on the `**Criterion:**` line. A
#   reviewer reading the file decides whether that line states what the agent must confirm
#   and whether the indicator line labels the remaining sections. This check catches the
#   absent section, which is the failure that shipped.
#
# Usage: bash scripts/check-agent-verdict-criterion.sh [agents-dir]
#   agents-dir defaults to `.claude/agents` under the repository root.

set -euo pipefail

HEADING='## Verdict criterion'
CRITERION_LABEL='**Criterion:**'
INDICATOR_LABEL='**Indicators, not the criterion.**'

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
        echo "      Add a '${HEADING}' section holding a '${CRITERION_LABEL}' line that" >&2
        echo "      names what this agent must confirm before it reports a verdict, and" >&2
        echo "      an '${INDICATOR_LABEL}' line that labels the" >&2
        echo "      remaining sections. See .claude/agents/README.md." >&2
        failures=$((failures + 1))
        continue
    fi
    if [[ ${heading_count} -gt 1 ]]; then
        echo "FAIL: ${name} carries ${heading_count} '${HEADING}' headings." >&2
        echo "      Two criteria let an agent report against whichever one it already" >&2
        echo "      satisfies." >&2
        failures=$((failures + 1))
        continue
    fi

    # The criterion section opens the file's sections: no other `## ` heading precedes it.
    first_section=$(grep -m1 -E '^## ' "${path}" || true)
    if [[ ${first_section} != "${HEADING}" ]]; then
        echo "FAIL: ${name} opens with the section '${first_section}', not '${HEADING}'." >&2
        echo "      An agent reads the file top-down, so a recipe placed above the" >&2
        echo "      criterion reaches the agent first and stands in for it." >&2
        failures=$((failures + 1))
        continue
    fi

    # Read the section body: from the heading to the next heading of any level.
    section=$(awk -v heading="${HEADING}" '
        $0 == heading { inside = 1; next }
        inside && /^#/ { exit }
        inside { print }
    ' "${path}")

    for label in "${CRITERION_LABEL}" "${INDICATOR_LABEL}"; do
        line=$(grep -m1 -F "${label}" <<<"${section}" || true)
        if [[ -z ${line} ]]; then
            echo "FAIL: ${name} holds no '${label}' line under '${HEADING}'." >&2
            failures=$((failures + 1))
            continue
        fi
        if [[ ${line} != "${label}"* ]]; then
            echo "FAIL: ${name} writes '${label}' mid-line; it opens its line." >&2
            failures=$((failures + 1))
            continue
        fi
        rest=${line#"${label}"}
        # Strip the leading and trailing whitespace, then require text.
        rest=${rest#"${rest%%[![:space:]]*}"}
        if [[ -z ${rest} ]]; then
            echo "FAIL: ${name} carries '${label}' with nothing after it." >&2
            echo "      A label with no sentence tells the agent nothing." >&2
            failures=$((failures + 1))
        fi
    done
done

if [[ ${failures} -gt 0 ]]; then
    echo "" >&2
    echo "${failures} agent-definition check(s) failed." >&2
    exit 1
fi

echo "OK: ${#agent_files[@]} agent definitions each state a verdict criterion."
