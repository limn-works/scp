# A Green Check That Asserted Nothing: Nine Ways CI Reported Success Over Zero Work

**Date:** 2026-08-16, extended 2026-08-17 and 2026-08-22
**Source:** branch `fix/ci-enforces-what-it-claims` — `.github/workflows/ci.yml`, `.github/workflows/fuzz.yml`, `.github/workflows/release.yml`, `scripts/check-cross-layer.sh`, `scripts/check-shipped-feature-graph.sh`

## Rule

A check earns trust by rejecting something. Before trusting a passing check, make it
fail on whichever defect it exists to catch, and keep that failure as a test. Every
defect below produced a green check while work behind it never ran, and every one passed
review because a check *looked* like it was doing its job.

## Nine failure shapes

**1. A command that treats "nothing matched" as success.** `cargo test -p scp-node --lib
pre_rotation_severance` exits 0 when a filter selects no test. Two tests it named
carry `#[cfg(not(feature = "testing"))]`, so any dependency edge that turned `testing` on
for that crate would delete them and leave a green lane over zero assertions. Measured on
this tree: `cargo test <filter>` with a name that matches nothing exits 0, while
`cargo nextest run --no-tests=fail -E 'test(name)'` exits 4. Prefer whichever command
reports an empty selection. A filter also hides after a `--`: job conformance in
release.yml ran `cargo test --release -p scp-testing -- conformance`, which hands
`conformance` to a libtest harness as a name filter, and that harness exits 0 when no
test name carries it. Read both sides of a `--` when auditing a test command.

**2. An aggregate that cannot tell "skipped" from "passed".** A `ci` job — one
status check this repository's ruleset requires — compared each dependency's result against
`failure` and `cancelled` and let every other value through. A path-filtered job that
skipped therefore produced one verdict with a job that passed. A hand-written second
copy of that dependency list also let three enforcement jobs (pyi-generated,
construction-pattern, block-in-place) run without ever reaching a merge gate. Read a
dependency map with `toJSON(needs)` so an aggregate covers every dependency by
construction, and decide per job whether that job was supposed to run.

**3. A path filter narrower than code it guards.** Filters named `python`, `typescript`,
`kotlin` and `swift` listed each binding's own directory and its bridge
directory. All four bridges reach every Rust workspace crate through scp-core, so a pull
request touching only `crates/scp-runtime/` skipped all four test jobs and roughly 2,600
assertions executed zero times under a green check. When a job's real dependency closure
is nearly a whole tree, gate it on a filter for that tree rather than enumerating a
closure you must re-verify on every new dependency edge. A `fuzz` filter showed the other
half of the same shape: it enumerated a closure and got it wrong, listing nine of the
thirteen crates `cargo tree -e no-dev` reaches from `fuzz/Cargo.toml`. It omitted
`scp-relay-client`, a direct dependency, along with `scp-core`, `scp-identity` and
`scp-platform`. Where you do enumerate a closure, compute it in a test rather than
copying it into a comment: `scripts/tests/ci-gate/ci_gate_selftest.py` rebuilds both
enumerated closures from `Cargo.toml` path dependencies and fails on a missing entry.

**4. `grep -q` inside a pipeline under `set -o pipefail`.** `grep -q` stops reading at its
first match and exits, which closes a pipe while its writer is still writing; that writer
dies of SIGPIPE and returns 141, and `pipefail` hands 141 back even though grep found
that pattern. `scripts/check-cross-layer.sh` searched a 74 KB diff this way, so its
verdict depended on where a match sat: a name on a first line read as absent and this
gate rejected a pull request, while an identical name on a last line read as present.
Write `grep PATTERN >/dev/null` instead, so grep reads its whole input. The same
construct sat in `scripts/check-shipped-feature-graph.sh`, the prove-absence gate that
ADR-062, capability injection, mandates in §Decision 6, where it probed a `cargo tree`
output for a `scp-testing v…` crate
node. There it failed OPEN rather than closed: `cargo tree -e no-dev -p scp-node` prints
96,898 bytes on this tree, and prepending one `scp-testing v0.1.0` line to that output
made `grep -q` report the harness crate ABSENT, which is the verdict that lets a shipped
artifact pass a zero-nullifier gate. Fixing one instance of this construct is not
finishing: grep every gate for `grep -q` inside a pipeline.

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

**7. A condition on every step of a job that carries none itself.** Job `rust-test` runs
`cargo nextest run --workspace`. It carried no job-level `if:` and instead repeated
`if: needs.changes.outputs.rust == 'true'` on seven steps, under a comment claiming each
matrix leg had to expand to report a status to branch protection. A renamed or misspelled
filter output therefore skipped all seven steps while that job reported success, and both
guards built to catch exactly that read job-level conditions only: an aggregate decides
whether a dependency was supposed to run by evaluating that dependency's own `if:`, and a
filter-key check scans job `if:` expressions for names `changes` never published. Gate a
job at job level, and let an aggregate judge the skip. Where a step genuinely needs its
own condition, that condition must name something other than a filter output —
`runner.os == 'Linux'` on a disk-cleanup step is fine.

**8. A loop over an empty input set that then publishes its output.** Job `sign-windows`
in release.yml Authenticode-signed every `.dll` a PowerShell pipeline returned, then
uploaded `windows-artifacts/` and `windows-cbindgen/` under artifact name
`windows-signed`. A pipeline over an empty file set runs zero times and exits 0, so a
Windows build leg that produced no binary published an artifact named as signed that
carried nothing signed. Job `rust` of build-matrix.yml is how such a leg arises: it ran a
POSIX `for` loop with no `shell:` declared, which GitHub read as PowerShell on that one
leg, so that leg failed before its first `cargo build` and uploaded nothing. A transform
step must assert its input set is non-empty before a publish step consumes its output.
The same step also swallowed a signing failure: `signtool` is a native command, so a
non-zero exit sets `$LASTEXITCODE` without stopping a pwsh script, and only a last
invocation's code reaches GitHub, so one failed signature among many passed as green.

**9. A new guard that reads an absent input as a benign value.** Fixing shapes 2 and 3
introduced two of these, in the guards those fixes added. `scripts/ci-aggregate-result.py`
refuses to guess at a `needs.changes.outputs.<key>` that job never published, because
reading it as `""` would compare unequal to every literal and hold a job at `skipped`
forever — and then read an absent `GITHUB_EVENT_NAME` as `""` anyway. Job `cross-layer`
carries `if: github.event_name == 'pull_request'`, so an empty event name made that
aggregate judge the condition false and accept a skipped `cross-layer` on a pull request:
measured, `NEEDS_JSON` reporting `cross-layer: skipped` with `GITHUB_EVENT_NAME` unset
exited 0. `path_dependency_closure` in `scripts/tests/ci-gate/ci_gate_selftest.py` read a
dependency spec carrying no `path` key as a dependency reaching no crate, and a
`dep = { workspace = true }` entry carries its `path` in a workspace manifest rather than
in a member manifest: measured on a two-crate fixture, that walk returned an empty closure
for a crate an inherited entry reaches, which would let `check_path_dep_closures` report a
`fuzz` or `typescript-wasm` filter complete while that filter omitted those directories —
shape 3 again, this time hidden inside a check written to catch shape 3. A guard states a
criterion over inputs it can read, so an input it cannot read stops it: this aggregate now
exits 3 on an absent event name, and this closure now resolves an inherited entry against
a workspace manifest and raises on an inherited name no workspace publishes.

## Tests holding these closed

- `scripts/tests/ci-gate/run-tests.sh` — asserts every job sets a `timeout-minutes`, that
  every job is a dependency of `ci`, that no `cargo test` in any workflow carries a
  test-name filter on either side of a `--`, that four binding test jobs run on a
  Rust-only change, that any job reading a runtime-scaling input sizes its budget from
  that input and covers every permitted option, that no step gates itself on a `changes`
  filter output, that the `fuzz` and `typescript-wasm` filters cover the path-dependency
  closure of the manifests they guard, that job `sign-windows` runs its non-empty-input
  guard before its upload, that an aggregate rejects a skipped dependency its
  condition selected to run, that an aggregate run without `GITHUB_EVENT_NAME` exits 3
  rather than accepting a skipped `cross-layer`, and that a closure over a two-crate
  fixture reaches a leaf whose entry reads `workspace = true` and raises on an inherited
  name no workspace publishes.
- `scripts/tests/cross-layer/run-tests.sh` — plants an FFI export at a first line and at
  a last line of a 155 KB diff, proves that gate finds both, then plants a missing export
  and proves it still rejects that.
- `scripts/tests/sign-windows/run-tests.sh` — runs `scripts/assert-nonempty-dll-set.sh`
  against fixture directories: a nested `.dll` is found, a directory holding only `.lib`
  and `.txt` is rejected, a directory that was never downloaded is rejected, and naming no
  directory at all is rejected.
- `scripts/check-shipped-feature-graph.sh --self-test` — builds a 200 KB synthetic
  `cargo tree` output with a `scp-testing v0.1.0` node on its first line and on its last
  line, and asserts the crate-node probe reports that node present in both, then asserts a
  tree carrying no such node still reads as absent.

Every harness above was run against unfixed code first and failed on exactly a defect it
describes. A harness that has never failed has not been tested.
