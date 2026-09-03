# A Gate That Finds Its Subject by Matching Source Text Reports OK When Nobody Rewords It

**Date:** 2026-09-03
**Source:** branch `ci/swift-bindings-regeneration-gate` — the workflow reader in
`scripts/check-toolchain-wiring.sh`, and the review finding that named three rewordings
which turned that gate green.

## The Rule

A gate that reads a structured configuration file — YAML, TOML, JSON — parses it with a
parser for that format and queries the parsed document. A gate that matches lines of the
file's text instead reads one spelling per pattern, and every other spelling of the same
document makes it find nothing. A check that finds nothing usually reports nothing, so
the rewording turns the gate green while the defect it exists to catch stays in the file.

The failure is worse than a missed defect. The gate keeps printing its OK line on every
later run, so a reader who checks whether the property holds reads an assertion the gate
never evaluated.

## What happened

`scripts/check-toolchain-wiring.sh` check 4 requires the job that reports a workflow's
verdict to branch protection to name every other job of that workflow in `needs:` and to
read each of their results. It found that job by matching two strings in
`.github/workflows/ci.yml`: the literal `always()` in the job's `if:`, and a literal
`needs.<name>.result` somewhere in the job. Check 2e requires every repository script a
paths-filtered job runs to appear in a filter guarding that job, and it collected each
job's lanes from the workflow's lines above that job's `steps:` key.

Six rewordings leave GitHub Actions' reading of the file unchanged and defeat one of those
matches:

1. `if: ${{ !cancelled() }}` in place of `if: always()`. GitHub Actions runs a job guarded
   by `!cancelled()` after a dependency fails, exactly as it runs one guarded by
   `always()`, so the aggregator still reports to branch protection.
2. A job-level `if:` key written below that job's `steps:` key. YAML mapping keys carry no
   required order.
3. A job header carrying a trailing comment, `  ci:  # the verdict job`.
4. A job header or a job key written in quotes: `  "ci":`, `  "if": always()`.
5. A job whose own keys sit at six spaces of indentation rather than four.
6. `${{ join(needs.*.result, ' ') }}` in place of one `${{ needs.<job>.result }}`
   expression per job. GitHub Actions expands that object filter over the job's `needs:`
   context.

Each one made the gate print `OK: every workflow's verdict job reads the result of every
job that workflow declares` while `changes` — the job that computes every paths-filter
output, and whose failure skips every lane at once — sat outside the aggregator's list.

## Why adding one pattern per spelling is the wrong repair

Three review passes on this file each surfaced another spelling. CLAUDE.md names that
count as the convergence signal: when more than about three passes keep producing a new
spelling of the same bypass, the approach is non-convergent, and the answer is to reframe
rather than to grind. The same file had already reframed once, for the same reason: check
3 read `.mise.toml` with `grep -E '^[[:space:]]*"?rust"?[[:space:]]*='`, which matched four
of the eight TOML spellings that put a `rust` key in the `tools` table, and it now reads
the document `tomllib` parses.

## The repair

`scripts/check-toolchain-wiring.sh` parses each workflow with PyYAML and prints one
tab-separated fact per line — which jobs the workflow declares, each job's `if:` value,
each `needs:` entry, each lane a job reads outside its steps, each `scripts/…` path a job
names, and each `needs.<job>.result` the job reads. Checks 2e and 4 query those facts. All
six rewordings above resolve to the same parsed document, so each one now produces the same
verdict as the spelling it replaced, and `scripts/tests/toolchain-wiring/run-tests.sh`
carries one case per rewording.

The verdict-job discovery rule also changed from a string to a set closed by GitHub's own
expression grammar. GitHub Actions applies an implicit `success()` to a job's `if:` unless
that expression names a status check function, and it defines exactly four of them:
`success()`, `always()`, `cancelled()`, and `failure()`. A job that runs after a dependency
does not succeed names one of the four; a job that names none of them never runs after a
dependency fails or skips. The gate matches those four identifiers rather than a list of
condition spellings someone keeps extending.

## The Lesson

1. Parse the format. A YAML, TOML, or JSON gate that greps is reading one spelling of a
   document that has many, and the ones it misses are the ones an author reaches for while
   tidying.
2. State the criterion as a set the target's own grammar closes, not as the strings you
   happened to see. GitHub defines four status check functions; that set is closed, and
   "the string `always()`" is not.
3. Make "I could not find my subject" a report, not a return. Check 4 keeps one silence —
   a workflow that declares no verdict job — and that silence is sound only because a
   required check whose job the workflow never declares stays pending and blocks the merge.
   Every other unfound subject fails the gate.
4. Test the rewording, not only the defect. Each new case in
   `scripts/tests/toolchain-wiring/run-tests.sh` writes a workflow GitHub Actions reads
   identically to the one it replaces, and asserts the gate reaches the same verdict. Each
   of them fails against the gate as it stood before this change.

See also `.docs/lessons/coverage-gates-must-fail-closed.md` (a gate that cannot find its
subject must fail, never warn) and
`.docs/lessons/ast-gate-checks-definition-not-name-resolution.md` (a positive whitelist
closed by construction beats a denylist chasing one more spelling).
