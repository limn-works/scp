#!/usr/bin/env bash
# run-tests.sh — exercise `scripts/check-ci-aggregator.sh` against canned workflows.
#
# WHAT THIS TESTS.
#   * The gate passes a workflow whose `ci` job needs every other job and reads every one
#     of their results, and it reads the `needs:` key in each of the three ways YAML
#     spells a sequence or a scalar there.
#   * The gate fails when the `ci` job's `needs:` list drops a job, when its results array
#     drops a job, and when it drops both — one case per direction, because a job named in
#     `needs:` and absent from the array is waited for and then ignored.
#   * The gate fails when the `ci` job drops `if: always()`, because GitHub then skips the
#     required check on the failure it exists to report and branch protection counts the
#     skip as a pass.
#   * The gate fails when either list names a job the workflow does not declare, and when
#     the `ci` job names itself.
#   * The gate fails rather than passing when it can read no workflow, no jobs, no `ci`
#     job, or no job other than `ci` — a green run that came from parsing nothing is the
#     one result a coverage gate must not produce.
#
# HOW EACH CASE IS BUILT. `run_case` makes a temporary directory, writes the gate into
# `scripts/`, and writes the case's workflow to `.github/workflows/ci.yml`. The gate `cd`s
# to its own parent's parent, so that directory becomes its repository root.
#
# Exit 0 when every case matches its expectation, 1 otherwise.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
CHECK="$REPO_ROOT/scripts/check-ci-aggregator.sh"

if [[ ! -f "$CHECK" ]]; then
    echo "ERROR: $CHECK does not exist" >&2
    exit 1
fi

TMP_PARENT=$(mktemp -d)
trap 'rm -rf "$TMP_PARENT"' EXIT

passed=0
failed=0

# ── The canned workflow ──────────────────────────────────────────────────────────────
#
# One generator produces every case's workflow, so a case differs from the passing one by
# exactly the defect it names.
#
#   OMIT_NEEDS    — a job name to leave out of the `ci` job's `needs:` list, or "".
#   OMIT_RESULT   — a job name whose result the `ci` job's step does not read, or "".
#   EXTRA_NEEDS   — a name to add to the `needs:` list that no job declares, or "".
#   EXTRA_RESULT  — a name whose result the step reads and that no job declares, or "".
#   NEEDS_STYLE   — "block", "flow", or "scalar": the three ways the generator spells the
#                   `needs:` key.
#   DROP_ALWAYS   — 1 leaves `if: always()` off the `ci` job, 0 writes it.
#   JOB_SET       — "full" writes three jobs plus `ci`, "only-ci" writes `ci` alone,
#                   "no-ci" writes the three jobs and no aggregator, "none" writes a
#                   workflow with an empty `jobs:` mapping.
OMIT_NEEDS=""
OMIT_RESULT=""
EXTRA_NEEDS=""
EXTRA_RESULT=""
NEEDS_STYLE="block"
DROP_ALWAYS=0
JOB_SET="full"

# The jobs the canned workflow declares besides the aggregator. `changes` and `check-draft`
# are the two the real workflow left out of both lists, and `rust-clippy` stands for the
# jobs that compile.
CANNED_JOBS=(check-draft changes rust-clippy)

emit_worker_jobs() {
    cat <<'YAML'
  check-draft:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Not a draft PR, proceeding"

  changes:
    needs: check-draft
    runs-on: ubuntu-latest
    outputs:
      rust: ${{ steps.filter.outputs.rust }}
    steps:
      - uses: dorny/paths-filter@v3
        id: filter
        with:
          filters: |
            rust:
              - 'crates/**'

  rust-clippy:
    needs: changes
    if: needs.changes.outputs.rust == 'true'
    runs-on: ubuntu-latest
    steps:
      - run: cargo clippy
YAML
}

# The names the aggregator's `needs:` list carries, in order.
#
# `${CANNED_JOBS[@]+...}` guards the expansion because bash 3.2, which macOS ships and
# every local run of this harness uses, treats an empty array under `set -u` as unbound.
needs_names() {
    local job
    for job in ${CANNED_JOBS[@]+"${CANNED_JOBS[@]}"}; do
        [[ $job == "$OMIT_NEEDS" ]] && continue
        printf '%s\n' "$job"
    done
    [[ -n $EXTRA_NEEDS ]] && printf '%s\n' "$EXTRA_NEEDS"
    return 0
}

emit_needs() {
    # `mapfile` arrived in bash 4, and macOS ships bash 3.2, so read the names into the
    # array a line at a time.
    local names=() line
    while IFS= read -r line; do
        [[ -n $line ]] || continue
        names+=("$line")
    done < <(needs_names)
    if (( ${#names[@]} == 0 )); then
        printf '    needs: []\n'
        return 0
    fi
    case "$NEEDS_STYLE" in
        block)
            printf '    needs:\n'
            local name
            for name in "${names[@]}"; do
                printf '      - %s\n' "$name"
            done
            ;;
        flow)
            local joined
            joined=$(printf '%s, ' "${names[@]}")
            printf '    needs: [%s]\n' "${joined%, }"
            ;;
        scalar)
            # One name only, which is the shape a job with a single dependency uses.
            printf '    needs: %s\n' "${names[0]}"
            ;;
        *)
            echo "ERROR: unknown NEEDS_STYLE '$NEEDS_STYLE'" >&2
            exit 1
            ;;
    esac
}

emit_ci_job() {
    printf '  ci:\n'
    [[ $DROP_ALWAYS -eq 0 ]] && printf '    if: always()\n'
    emit_needs
    printf '    runs-on: ubuntu-latest\n'
    printf '    steps:\n'
    printf '      - name: Check job results\n'
    printf '        run: |\n'
    printf '          results=( \\\n'
    local job
    for job in ${CANNED_JOBS[@]+"${CANNED_JOBS[@]}"}; do
        [[ $job == "$OMIT_RESULT" ]] && continue
        printf '            "${{ needs.%s.result }}" \\\n' "$job"
    done
    [[ -n $EXTRA_RESULT ]] && printf '            "${{ needs.%s.result }}" \\\n' "$EXTRA_RESULT"
    printf '          )\n'
    printf '          for r in "${results[@]}"; do\n'
    printf '            if [[ "$r" == "failure" || "$r" == "cancelled" ]]; then exit 1; fi\n'
    printf '          done\n'
}

emit_workflow() {
    printf 'name: CI\n\non:\n  pull_request:\n    branches: [main]\n\nenv:\n  CARGO_TERM_COLOR: always\n\njobs:\n'
    case "$JOB_SET" in
        full)
            emit_worker_jobs
            printf '\n'
            emit_ci_job
            ;;
        only-ci)
            CANNED_JOBS=()
            emit_ci_job
            ;;
        no-ci)
            emit_worker_jobs
            ;;
        none)
            printf '  # A jobs mapping holding no job.\n'
            ;;
        *)
            echo "ERROR: unknown JOB_SET '$JOB_SET'" >&2
            exit 1
            ;;
    esac
}

reset_case() {
    OMIT_NEEDS=""
    OMIT_RESULT=""
    EXTRA_NEEDS=""
    EXTRA_RESULT=""
    NEEDS_STYLE="block"
    DROP_ALWAYS=0
    JOB_SET="full"
    CANNED_JOBS=(check-draft changes rust-clippy)
}

# run_case <name> <expected exit> <required substring|""> [write-workflow: yes|no]
#
# A required substring of "" asserts only that the gate printed no FAIL line, which covers
# every message it can produce.
run_case() {
    local name=$1 want_exit=$2 want_msg=$3 write_workflow=${4:-yes}
    local root output actual_exit ok=1

    root="$TMP_PARENT/$name"
    mkdir -p "$root/scripts" "$root/.github/workflows"
    cp "$CHECK" "$root/scripts/"
    [[ $write_workflow == yes ]] && emit_workflow > "$root/.github/workflows/ci.yml"

    output=$(bash "$root/scripts/$(basename "$CHECK")" 2>&1)
    actual_exit=$?

    if [[ -n "$want_msg" ]] && ! grep -Fq -- "$want_msg" <<< "$output"; then
        echo "FAIL [$name]: output missing required substring: $want_msg" >&2
        ok=0
    fi
    if [[ -z "$want_msg" ]] && grep -Fq -- "FAIL" <<< "$output"; then
        echo "FAIL [$name]: output contains a FAIL line, and the case expects none" >&2
        ok=0
    fi
    if [[ $actual_exit -ne $want_exit ]]; then
        echo "FAIL [$name]: gate exited $actual_exit, expected $want_exit" >&2
        ok=0
    fi

    if [[ $ok -eq 1 ]]; then
        echo "PASS [$name]: exit=$actual_exit"
        passed=$((passed + 1))
    else
        echo "---- output begin ----" >&2
        echo "$output" >&2
        echo "---- output end ----" >&2
        failed=$((failed + 1))
    fi
    reset_case
}

# ── The workflow the gate accepts ────────────────────────────────────────────────────

run_case "every-job-needed-and-read" 0 ""

NEEDS_STYLE="flow"
run_case "needs-written-as-a-flow-sequence" 0 ""

# ── A job dropped from one list, then the other, then both ───────────────────────────
#
# One case per job the canned workflow declares, because the defect this gate reports on
# the real workflow was two specific jobs — `changes` and `check-draft` — missing from
# both lists while every compiling job was present in both.
for job_name in check-draft changes rust-clippy; do
    OMIT_NEEDS="$job_name"
    run_case "needs-drops-$job_name" 1 \
        "the 'ci' job's 'needs:' list does not name the '$job_name' job"

    OMIT_RESULT="$job_name"
    run_case "results-drop-$job_name" 1 \
        "the 'ci' job's steps never read needs.$job_name.result"

    OMIT_NEEDS="$job_name"
    OMIT_RESULT="$job_name"
    run_case "both-lists-drop-$job_name" 1 \
        "the 'ci' job's 'needs:' list does not name the '$job_name' job"
done

# The `scalar` spelling carries one name, so it drops the other two jobs from `needs:`
# while the results array still reads all three. The gate reports the two it dropped.
NEEDS_STYLE="scalar"
run_case "needs-written-as-a-scalar-drops-the-other-jobs" 1 \
    "the 'ci' job's 'needs:' list does not name the 'rust-clippy' job"

# ── The aggregator's own guards ──────────────────────────────────────────────────────

DROP_ALWAYS=1
run_case "aggregator-without-if-always" 1 \
    "the 'ci' job does not carry 'if: always()'"

EXTRA_RESULT="deleted-job"
run_case "results-read-a-job-the-workflow-does-not-declare" 1 \
    "names a 'deleted-job' job that this workflow does not declare"

EXTRA_NEEDS="deleted-job"
run_case "needs-name-a-job-the-workflow-does-not-declare" 1 \
    "names a 'deleted-job' job that this workflow does not declare"

EXTRA_NEEDS="ci"
run_case "aggregator-names-itself" 1 \
    "the 'ci' job names itself in its own 'needs:' list or reads its own result"

# ── The gate fails rather than passing on nothing ────────────────────────────────────

run_case "workflow-absent" 1 \
    "does not exist, so the gate cannot check that the 'ci' job observes every job's result" no

JOB_SET="none"
run_case "workflow-declares-no-jobs" 1 \
    "declares no jobs the gate can read"

JOB_SET="no-ci"
run_case "workflow-declares-no-ci-job" 1 \
    "declares no 'ci' job"

JOB_SET="only-ci"
run_case "workflow-declares-only-the-ci-job" 1 \
    "declares the 'ci' job and no other job"

echo
echo "passed=$passed failed=$failed"
[[ $failed -eq 0 ]]
