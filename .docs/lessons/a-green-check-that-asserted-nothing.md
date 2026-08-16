# A Green Check That Asserted Nothing: Six Ways CI Reported Success Over Zero Work

**Date:** 2026-08-16
**Source:** branch `fix/ci-enforces-what-it-claims` — `.github/workflows/ci.yml`, `scripts/check-cross-layer.sh`, `CLAUDE.md` §PRD stories

## The Rule

A check earns trust by rejecting something. Before you trust a passing check, make it
fail on the defect it exists to catch, and keep that failure as a test. Every defect
below produced a green check while the work behind it never ran, and every one of them
had passed review because the check *looked* like it was doing its job.

## The six failure shapes

**1. A command that treats "nothing matched" as success.** `cargo test -p scp-node --lib
pre_rotation_severance` exits 0 when the filter selects no test. The two tests it named
carry `#[cfg(not(feature = "testing"))]`, so any dependency edge that turned `testing` on
for that crate would delete them and leave a green lane over zero assertions. Measured on
this tree: `cargo test <filter>` with a name that matches nothing exits 0, while
`cargo nextest run --no-tests=fail -E 'test(name)'` exits 4. Prefer the command that
reports an empty selection.

**2. An aggregate that cannot tell "skipped" from "passed".** The `ci` job — the only
status check the repository ruleset requires — compared each dependency's result against
`failure` and `cancelled` and let every other value through. A path-filtered job that
skipped therefore produced the same verdict as a job that passed. A hand-written second
copy of the dependency list also let three enforcement jobs (pyi-generated,
construction-pattern, block-in-place) run without ever reaching the merge gate. Read the
dependency map with `toJSON(needs)` so the aggregate covers every dependency by
construction, and decide per job whether that job was supposed to run.

**3. A path filter narrower than the code it guards.** The `python`, `typescript`,
`kotlin` and `swift` filters listed each binding's own directory and its bridge
directory. All four bridges reach the whole Rust workspace through scp-core, so a pull
request touching only `crates/scp-runtime/` skipped all four test jobs and roughly 2,600
assertions executed zero times under a green check. When a job's real dependency closure
is nearly a whole tree, gate it on the filter for that tree rather than enumerating a
closure you must re-verify on every new dependency edge.

**4. `grep -q` inside a pipeline under `set -o pipefail`.** `grep -q` stops reading at its
first match and exits, which closes the pipe while the writer is still writing; the writer
dies of SIGPIPE and returns 141, and `pipefail` hands 141 to the caller even though grep
found the pattern. `scripts/check-cross-layer.sh` searched a 74 KB diff this way, so its
verdict depended on where the match sat: a name on the first line read as absent and the
gate rejected the pull request, while the same name on the last line read as present.
Write `grep PATTERN >/dev/null` instead, so grep reads its whole input.

**5. A job with no `timeout-minutes`.** GitHub's default per-job ceiling is 360 minutes.
No job in this workflow set a timeout, so one hang burned six runner-hours. Size each
budget from observed durations (`gh api repos/OWNER/REPO/actions/runs/<id>/jobs`).

**6. A document asserting that CI enforces something no workflow runs.** `CLAUDE.md`
stated "CI enforces this" about `scripts/validate-prd.py`. The only workflow referencing
that script was `.github/workflows/prd-validate.yml.disabled`, and GitHub never loads a
file with that suffix. Two rules follow. First, a sentence claiming mechanical enforcement
must name the job that performs it, so a reader can check the claim in one grep instead of
trusting it. Second, when a bulk change disables a category of workflows — that rename
disabled seven at once, all described as Claude-powered — check each file for steps
outside the category: this one held a plain Python validation step alongside a Claude
review step, and the step that needed no API key went dark with the step that did. Restore
the part that never belonged to the category, and leave the deliberate decision alone.

## The tests that hold these closed

- `scripts/tests/ci-gate/run-tests.sh` — asserts every job sets a `timeout-minutes`, that
  every job is a dependency of `ci`, that no `cargo test` in the workflow carries a
  test-name filter, that the four binding test jobs run on a Rust-only change, and that
  the aggregate rejects a skipped dependency the workflow selected to run.
- `scripts/tests/cross-layer/run-tests.sh` — plants an FFI export at the first line and at
  the last line of a 155 KB diff, proves the gate finds both, then plants a missing export
  and proves the gate still rejects it.
- `scripts/tests/prd-validate/run-tests.sh` — plants six violation classes and proves the
  PRD validator rejects each, and asserts the clean run reports a non-zero story count,
  because a validator that walked zero stories would exit 0 as well.

Both harnesses were run against the unfixed code first and failed on exactly the defect
they describe. A harness that has never failed has not been tested.
