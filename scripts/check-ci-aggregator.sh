#!/usr/bin/env bash
#
# CI-aggregator coverage gate.
#
# THE CRITERION: the one required status check must observe the result of every job in
# `.github/workflows/ci.yml`. A job whose result no list names can fail while the required
# check reports success, and branch protection then merges the pull request.
#
# HOW THE WORKFLOW SATISFIES IT. The `ci` job at the bottom of that file declares
# `needs:`, which makes GitHub run it after every job it names and expose each result at
# `needs.<job>.result`, and its `run:` step copies those results into a `results` array and
# exits 1 on `failure` or `cancelled`. Both lists are written by hand. This gate reads the
# job names out of the workflow and requires each list to name every one of them apart from
# the aggregator itself, so a job added later fails here until both lists carry it.
#
# WHY `skipped` IS NOT A THIRD FAILING RESULT, stated rather than implied. Most jobs in
# that workflow are guarded by `if: needs.changes.outputs.<lane> == 'true'` and skip on a
# pull request that touches no file of their lane, which is the design. The defect this
# gate reports is a different one: a job GitHub never reports on at all, because no list
# asks for it.
#
# WHAT THIS COVERS THAT THE `needs:` LIST ALONE DOES NOT. `needs:` decides when the
# aggregator runs; the `results` array decides what it reads. A job named in `needs:` and
# absent from the array is waited for and then ignored, which is the failure this gate
# reports separately from the reverse one.
#
# WHY THE AGGREGATOR ALSO HAS TO CARRY `if: always()`. Without it GitHub skips the
# aggregator when any job it needs fails, and a skipped required check counts as a pass, so
# the same failure reaches `main` by a second route. The gate requires the key.
#
# WHY THIS GATE READS ONE WORKFLOW. `.github/workflows/ci.yml` is the only workflow in this
# repository whose jobs report through one collected result. `docs.yml`'s `publish-docs`
# job downloads the four documentation artifacts and deploys them on a release tag: it
# reads no `needs.<job>.result`, and `if: startsWith(github.ref, 'refs/tags/scp-core@')`
# keeps it off every pull request. `codeql.yml` reports its own job. `fuzz.yml` runs on a
# schedule and on `workflow_dispatch`, so no pull request waits on it. A second aggregator
# added later needs its own entry in this file, which does not discover one on its own.
#
# WHAT THE PARSE DOES NOT COVER, stated rather than implied: it reads job names as the
# keys indented two spaces under the top-level `jobs:` mapping, and reads the aggregator's
# `needs:` as a block sequence, a flow sequence, or a single scalar. A workflow that
# spells either construct some other way — a job key inside a merge anchor, a `needs:`
# built by an expression — yields names this gate does not see, and it fails on the
# resulting mismatch rather than passing over it. Reading the file with a YAML parser would
# remove that gap; `actions/setup-python@v5` installs an interpreter that ships no YAML
# parser, and adding a `pip install` puts a network fetch in front of a gate that
# otherwise needs none.

set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

CI_WORKFLOW=".github/workflows/ci.yml"
AGGREGATOR="ci"

fail=0
report() {
    printf 'FAIL: %s\n' "$1" >&2
    fail=1
}

# Print every job name the workflow declares.
#
# GitHub Actions puts the jobs mapping at the top level under `jobs:`, and each job's id is
# a key one level in. The awk starts at the `jobs:` line, so the two-space keys of `on:`,
# `env:`, and `permissions:` above it are not read as job names, and every key indented
# more than two spaces belongs to a job rather than naming one.
workflow_jobs() {
    awk '
        /^jobs:[[:space:]]*$/ { injobs = 1; next }
        injobs && /^[^[:space:]#]/ { exit }
        injobs && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ {
            name = $0
            sub(/^  /, "", name)
            sub(/:[[:space:]]*$/, "", name)
            print name
        }
    ' "$1"
}

# Print the lines of one job's block: its own properties, up to the next job key.
job_block() {
    awk -v job="$2" '
        $0 ~ "^  " job ":[[:space:]]*$" { injob = 1; next }
        injob && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ { exit }
        injob { print }
    ' "$1"
}

# Print every job name the aggregator's `needs:` key holds.
#
# Three spellings reach this: a block sequence under `needs:`, a flow sequence on the
# `needs:` line, and a single scalar on that line.
needs_entries() {
    awk '
        /^    needs:[[:space:]]*$/ { inblock = 1; next }
        inblock {
            if ($0 ~ /^[[:space:]]*#/) next
            if ($0 ~ /^[[:space:]]*$/) next
            if ($0 ~ /^      -[[:space:]]+[A-Za-z0-9_-]+[[:space:]]*$/) {
                name = $0
                sub(/^[[:space:]]*-[[:space:]]+/, "", name)
                sub(/[[:space:]]*$/, "", name)
                print name
                next
            }
            exit
        }
        /^    needs:[[:space:]]*\[/ {
            line = $0
            sub(/^[[:space:]]*needs:[[:space:]]*\[/, "", line)
            sub(/\].*$/, "", line)
            gsub(/[[:space:]]/, "", line)
            split(line, parts, ",")
            for (i in parts) if (parts[i] != "") print parts[i]
        }
        /^    needs:[[:space:]]+[A-Za-z0-9_-]+[[:space:]]*$/ {
            name = $0
            sub(/^[[:space:]]*needs:[[:space:]]+/, "", name)
            sub(/[[:space:]]*$/, "", name)
            print name
        }
    '
}

# Print every job name the aggregator's steps read a result of.
result_reads() {
    grep -oE 'needs\.[A-Za-z0-9_-]+\.result' | sed -E 's/^needs\.(.*)\.result$/\1/'
}

if [[ ! -f $CI_WORKFLOW ]]; then
    report "$CI_WORKFLOW does not exist, so the gate cannot check that the '$AGGREGATOR' job observes every job's result"
    exit 1
fi

jobs=$(workflow_jobs "$CI_WORKFLOW" | sort -u)
if [[ -z $jobs ]]; then
    report "$CI_WORKFLOW declares no jobs the gate can read, so it cannot check that the '$AGGREGATOR' job observes every job's result. Job ids are the keys indented two spaces under the top-level 'jobs:' mapping."
    exit 1
fi
if ! grep -qxF -- "$AGGREGATOR" <<< "$jobs"; then
    report "$CI_WORKFLOW declares no '$AGGREGATOR' job, and that job is the single required status check every other job's result reaches branch protection through"
    exit 1
fi

# Every job the aggregator has to observe: the workflow's jobs apart from the aggregator.
expected=$(grep -vxF -- "$AGGREGATOR" <<< "$jobs" | sort -u)
if [[ -z $expected ]]; then
    report "$CI_WORKFLOW declares the '$AGGREGATOR' job and no other job, so the gate has nothing to check and the workflow runs no check of its own"
    exit 1
fi

block=$(job_block "$CI_WORKFLOW" "$AGGREGATOR")
if [[ -z $block ]]; then
    report "$CI_WORKFLOW: the '$AGGREGATOR' job holds no properties the gate can read"
    exit 1
fi

if ! grep -qE '^    if:[[:space:]]*always\(\)[[:space:]]*$' <<< "$block"; then
    report "$CI_WORKFLOW: the '$AGGREGATOR' job does not carry 'if: always()'. Without it GitHub skips the job whenever one of the jobs it needs fails, and branch protection counts a skipped required check as a pass, so the failure merges."
fi

declared=$(needs_entries <<< "$block" | sort -u)
observed=$(result_reads <<< "$block" | sort -u)

while IFS= read -r job; do
    [[ -n $job ]] || continue
    if ! grep -qxF -- "$job" <<< "$declared"; then
        report "$CI_WORKFLOW: the '$AGGREGATOR' job's 'needs:' list does not name the '$job' job. GitHub exposes a result at needs.$job.result only for a job the aggregator needs, so the aggregator runs without waiting for '$job' and branch protection reports the required check green while that job is still running or already red. Add '$job' to that list and to the results array beneath it."
    fi
    if ! grep -qxF -- "$job" <<< "$observed"; then
        report "$CI_WORKFLOW: the '$AGGREGATOR' job's steps never read needs.$job.result, so a failure of the '$job' job leaves the required check green. Add \"\${{ needs.$job.result }}\" to the results array."
    fi
done <<< "$expected"

# The reverse direction: a name in either list that the workflow no longer declares. GitHub
# rejects a `needs:` entry naming no job, so that half fails the run rather than this gate;
# a stale results entry expands to an empty string, which the aggregator's loop reads as a
# pass, so the gate reports it here.
for name in $(printf '%s\n%s\n' "$declared" "$observed" | sed '/^$/d' | sort -u); do
    if [[ $name == "$AGGREGATOR" ]]; then
        report "$CI_WORKFLOW: the '$AGGREGATOR' job names itself in its own 'needs:' list or reads its own result, which GitHub rejects as a cycle"
        continue
    fi
    if ! grep -qxF -- "$name" <<< "$jobs"; then
        report "$CI_WORKFLOW: the '$AGGREGATOR' job names a '$name' job that this workflow does not declare. \${{ needs.$name.result }} expands to the empty string, which the job's loop reads as a pass. Delete the entry, or restore the job it was watching."
    fi
done

if [[ $fail -eq 0 ]]; then
    printf "OK: the '%s' job needs every job %s declares and reads every one of their results\n" \
        "$AGGREGATOR" "$CI_WORKFLOW"
    exit 0
fi
exit 1
