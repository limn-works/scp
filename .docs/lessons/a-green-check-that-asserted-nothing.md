# A Green Check That Asserted Nothing: Six Ways CI Reported Success Over Zero Work

**Date:** 2026-08-16
**Source:** branch `fix/ci-enforces-what-it-claims` — `.github/workflows/ci.yml`, `.github/workflows/fuzz.yml`, `scripts/check-cross-layer.sh`

## Rule

A check earns trust by rejecting something. Before trusting a passing check, make it
fail on whichever defect it exists to catch, and keep that failure as a test. Every
defect below produced a green check while work behind it never ran, and every one passed
review because a check *looked* like it was doing its job.

## Six failure shapes

**1. A command that treats "nothing matched" as success.** `cargo test -p scp-node --lib
pre_rotation_severance` exits 0 when a filter selects no test. Two tests it named
carry `#[cfg(not(feature = "testing"))]`, so any dependency edge that turned `testing` on
for that crate would delete them and leave a green lane over zero assertions. Measured on
this tree: `cargo test <filter>` with a name that matches nothing exits 0, while
`cargo nextest run --no-tests=fail -E 'test(name)'` exits 4. Prefer whichever command
reports an empty selection.

**2. An aggregate that cannot tell "skipped" from "passed".** A `ci` job — one
status check this repository's ruleset requires — compared each dependency's result against
`failure` and `cancelled` and let every other value through. A path-filtered job that
skipped therefore produced one verdict with a job that passed. A hand-written second
copy of that dependency list also let three enforcement jobs (pyi-generated,
construction-pattern, block-in-place) run without ever reaching a merge gate. Read a
dependency map with `toJSON(needs)` so an aggregate covers every dependency by
construction, and decide per job whether that job was supposed to run.

**3. A path filter narrower than code it guards.** Filters named `python`, `typescript`,
`kotlin` and `swift` filters listed each binding's own directory and its bridge
directory. All four bridges reach every Rust workspace crate through scp-core, so a pull
request touching only `crates/scp-runtime/` skipped all four test jobs and roughly 2,600
assertions executed zero times under a green check. When a job's real dependency closure
is nearly a whole tree, gate it on a filter for that tree rather than enumerating a
closure you must re-verify on every new dependency edge.

**4. `grep -q` inside a pipeline under `set -o pipefail`.** `grep -q` stops reading at its
first match and exits, which closes a pipe while its writer is still writing; that writer
dies of SIGPIPE and returns 141, and `pipefail` hands 141 back even though grep found
that pattern. `scripts/check-cross-layer.sh` searched a 74 KB diff this way, so its
verdict depended on where a match sat: a name on a first line read as absent and this
gate rejected a pull request, while an identical name on a last line read as present.
Write `grep PATTERN >/dev/null` instead, so grep reads its whole input.

**5. A job with no `timeout-minutes`.** GitHub's default per-job ceiling is 360 minutes.
No job in this workflow set a timeout, so one hang burned six runner-hours. Size each
budget from observed durations (`gh api repos/OWNER/REPO/actions/runs/<id>/jobs`).

**6. A fixed budget over an unbounded operator input.** Fixing shape 5 introduced
this one. Two fuzz jobs pass a `workflow_dispatch` input to
libFuzzer as `-max_total_time`, which lets an operator set how long each job runs. A
budget sized for a scheduled run then cancels every dispatch asking for longer, killing
runs that previously completed. Before adding a ceiling to any job, check whether an
input decides that job's duration: an input qualifies when a step hands it to something
that decides how long that step runs. Where one does, bound that input to a closed option
list *and* size each budget per option — bounding alone forces one loose ceiling onto a
common scheduled path, and sizing alone leaves an operator able to request an unbounded
budget. Note two platform facts, both measured rather than assumed: GitHub expressions
carry no arithmetic, so `seconds / 60 + overhead` cannot be written and a budget must be
selected per option through `X == 'v' && minutes || …`; and GitHub validates a dispatch
input against a definition on a default branch, so a new option list cannot be exercised
from a feature branch.

## Tests holding these closed

- `scripts/tests/ci-gate/run-tests.sh` — asserts every job sets a `timeout-minutes`, that
  every job is a dependency of `ci`, that no `cargo test` in that workflow carries a
  test-name filter, that four binding test jobs run on a Rust-only change, that any job
  reading a runtime-scaling input sizes its budget from that input and covers every
  permitted option, and that an aggregate rejects a skipped dependency its condition
  selected to run.
- `scripts/tests/cross-layer/run-tests.sh` — plants an FFI export at a first line and at
  a last line of a 155 KB diff, proves that gate finds both, then plants a missing export
  and proves it still rejects that.

Both harnesses were run against unfixed code first and failed on exactly a defect each
describes. A harness that has never failed has not been tested.
