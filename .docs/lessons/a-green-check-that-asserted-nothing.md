# A Green Check That Asserted Nothing: Twelve Ways CI Reported Success Over Zero Work

**Date:** 2026-08-16, extended 2026-08-17, 2026-08-22, 2026-08-25, 2026-08-31 and 2026-09-01
**Source:** branch `fix/ci-enforces-what-it-claims` — `.github/workflows/ci.yml`, `.github/workflows/fuzz.yml`, `.github/workflows/release.yml`, `scripts/check-cross-layer.sh`, `scripts/check-shipped-feature-graph.sh`

## Rule

A check earns trust by rejecting something. Before trusting a passing check, make it
fail on whichever defect it exists to catch, and keep that failure as a test. Every
defect below produced a green check while work behind it never ran, and every one passed
review because a check *looked* like it was doing its job.

## Thirteen failure shapes

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
finishing: grep every gate for `grep -q` inside a pipeline. That grep found three more.
Fixing one instance inside one file is not finishing either. The first pass through
`scripts/check-shipped-feature-graph.sh` rewrote the per-artifact probe and left an
identical `printf | grep -qE` in `resolve_default_members_testing_crate`, 120 lines
below it, which probes the same crate node for the bare `cargo build` that
`.github/workflows/build-matrix.yml` runs at the workspace root. `cargo tree -e no-dev`
over every default member prints a superset of the 96,898-byte tree measured above, so
that second probe carried the same fail-open verdict on the same gate. A fixture
harness that drives one extracted function proves that one function reads its whole
input and says nothing about a second probe written elsewhere in the file, so
`assert_every_pipeline_reader_consumes_its_input` now reads the gate's own source and
rejects any pipeline stage that stops early. It decides that question rather than
sampling it: the commands this gate pipes into are `grep`, `sed`, `sort` and `comm`, and
only `grep` offers an early exit — `-q`/`--quiet`/`--silent` and `-m N`/`--max-count=N`.
`scripts/hooks/pretooluse-enforcement-files.sh`, which blocks an in-band write to any
enforcement file, ran `echo "$command_str" | grep -qE`, so an agent defeated it by making
its command long: measured, a 43-byte `tee` at a protected basename exited 2 (BLOCK), and
that same `tee` followed by a 166,933-byte heredoc exited 0 (ALLOW).
`scripts/check-saga-gating-granularity.sh` piped three supervisor function bodies into six
such probes; measured, a 194,118-byte body carrying `.contains(` on its second line
returned 141 under `grep -Fq` and 0 under `grep -F … >/dev/null`, and its
`extractor_has_no_standing_prefix` probe fails OPEN in that direction.
`scripts/tests/bridge-symmetry/run-tests.sh` matched a substring in gate output the same
way. Search for the construct, not for the file you already know about.

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

Two sibling jobs carried the identical loop, and the first round of this fix reached
neither. Job `sign-apple` piped
`find xcframework/ -name "*.a" -o -name "*.dylib"` into a `while read` loop and uploaded
`xcframework/` as `swift-xcframework-signed`, which job `publish-spm` then writes into
`bindings/swift/Package.swift` as a URL and a SHA-256, so every Swift Package Manager
consumer would install an unsigned XCFramework. Job `sign-maven` piped a `find` over
`*.aar`, `*.jar` and `*.pom` into a `while read` loop and uploaded `maven-artifacts/` as
`maven-signed`. A guard written for one job's file extension guards one job; the guard is
now `scripts/assert-nonempty-signing-set.sh`, which takes its `--name` globs from its
caller, and the ci-gate assertion selects its jobs by the `-signed` suffix on an uploaded
artifact name rather than by naming `sign-windows`.

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

**10. A check whose criterion names a narrower object than the defect it hunts.**
`check_path_dep_closures` stated its criterion over crate DIRECTORIES, and
`path_dependency_closure` returns a directory only for an entry carrying a `path` key. It
therefore could not require a filter to name the root `Cargo.toml`, even though it opens
that manifest itself to resolve every `workspace = true` entry, and could not require a
`Cargo.lock` either. Measured on this tree: `path_dependency_closure(fuzz/Cargo.toml)`
returned thirteen `crates/scp-*` directories and no manifest, and `'Cargo.toml' in
path_filters(jobs)['fuzz']` was `False`. So a dependency bump changing only `Cargo.toml`
and `Cargo.lock` — the shape of the h2 0.4.18 and rustls-webpki 0.103.13 advisory updates
— set `rust=true`, `fuzz=false` and `typescript-wasm=false`, skipped `fuzz-build`,
`typescript-wasm-check` and `scaffold-typescript-web-check`, and `scripts/ci-aggregate-result.py`
read all three skips as authorized. `resolution_manifests` now returns the workspace
manifest each crate in a closure inherits from, plus the lockfile of the workspace the
starting manifest resolves in, and `check_path_dep_closures` requires a filter to cover
both. It returns the root `Cargo.lock` for `typescript-wasm`, whose crate is workspace
member 15, and does not return it for `fuzz`, whose `fuzz/Cargo.toml` carries its own
`[workspace]` table and resolves against `fuzz/Cargo.lock`. Widen a criterion to name
every object the build reads, not the subset the walk already produced.

**11. A job that compiles an assertion and runs it in no lane.** Job
`rust-build-uniffi-production` ran `cargo build -p scp-ffi-uniffi --features server` and
nothing else, under a note reading "the uniffi test suite assumes in-memory custody and
does not compile in prod config, so a full prod-config test lane is a separate follow-up".
`identity_create_in_memory_rejected_without_feature` at `crates/scp-ffi/uniffi/src/lib.rs`
asserts that a shipped uniffi build rejects `in_memory` custody with SCP-IDENT-1008, and
it carries `#[cfg(not(feature = "testing"))]`. The three lanes that run uniffi tests —
`rust-test`, `rust-doc`, and the release conformance job — each enable
`scp-ffi-uniffi/testing`, which compiles that assertion out, so it executed nowhere while
`ci` reported success and `build-matrix.yml` shipped that bridge in an iOS XCFramework and
an Android AAR at tag time. The pass that fixed shape 1 in the pyo3 twin deleted that
job's identical note and left this one standing, which is shape 4's rule — fixing one
instance is not finishing — applied to a deferral rather than to a grep.

The note reported a real compile failure, unlike the pyo3 note beside it, and that
difference is what made the deferral survive review. Measured before this change,
`cargo test -p scp-ffi-uniffi --features server --lib --no-run` exited 101 with eight
resolution errors, all in `crates/scp-ffi/uniffi/src/bridge.rs`: four sites named
`testing`-gated items — the `pre_rotation_custody` field, `make_dht_with_signer`,
`DidCache`, `DualLayerResolver`, `NoOpRelayQuerier` — from tests carrying only
`#[cfg(test)]`. Adding `#[cfg(feature = "testing")]` to those four sites, and to the
`InMemoryDhtClient` import their tests were the last users of, makes that target compile
and moves no test out of a lane: job `rust-test` enables `scp-ffi-uniffi/testing` and runs
each of them there exactly as before. A compile failure is an impediment to fix, not a
reason to leave an assertion unrun: this one took five added attributes and one widened
import gate.
`check_shipped_build_assertions_run` in `scripts/tests/ci-gate/ci_gate_selftest.py` now
scans every `.rs` file under `crates/` for a test carrying
`#[cfg(not(feature = "testing"))]` and requires a command in the job its package is
paired with to select it BY NAME. A crate that gains such a test and names no lane fails
that check by name.

That check first shipped holding its two tables to two different strengths, which is
failure shape 11 written into the check that catches failure shape 11. For the three
bridge packages it asked whether a lane's command selected each assertion. For the two
packages `NON_BRIDGE_SHIPPED_ASSERTION_LANES` names — `scp-identity` and `scp-node` — it
asked only whether that table's job id was defined in `ci.yml`, then skipped the
per-assertion loop. Renaming `pre_rotation_severance_generate_fails_closed` out of job
fail-closed-pre-rotation's `-E 'test(pre_rotation_severance)'` filter would have left
that SCP-IDENT-1059 fail-closed proof running in no lane while both checks reported
success: the lane stays green because its sibling keeps the nextest selection non-empty
under `--no-tests=fail`, and the self-test stays green because the job id it asked about
still exists. Measured: with that filter narrowed to
`test(pre_rotation_severance_persistent)`, the check as first written passed 279 of 279
assertions, and the check as it now stands names
`pre_rotation_severance_generate_fails_closed` as running nowhere.

Two readers had to widen before one criterion could cover both tables. `--workspace`
selects every workspace member, so a reader of `-p` alone reported job `rust-test`'s
`cargo nextest run --workspace` as running no package at all; `command_covers_package`
now reads `--workspace`/`--all` and subtracts `--exclude`. A nextest `test(SUBSTRING)`
predicate matches every test whose name CONTAINS that substring, so a reader asking
whether a filter's text spells a test's full name reported
`-E 'test(pre_rotation_severance)'` as selecting neither scp-node assertion;
`command_selects` now reads the containment as nextest evaluates it. It models a union
of `test()` predicates joined by `+` or `|` and nothing else, because `-`, `not`, `and`,
`&` and the set functions can each REMOVE a test a `test()` predicate selected — a
filterset outside that grammar fails the check rather than passing on a guess.

**12. A check that reads one side of a two-sided wiring.** Two files name the same
filter keys. A `dorny/paths-filter` step defines them in its `filters:` block, and the
`changes` job publishes one output per key from a `steps.filter.outputs.<key>`
expression — nine such expressions in `.github/workflows/ci.yml` and one in
`.github/workflows/docs.yml`. `check_filter_outputs_gate_jobs` read the consumer side of
those outputs, `needs.changes.outputs.<key>`, and `resolve_operand` in
`scripts/ci-aggregate-result.py` exits 2 on a job condition naming an output `changes`
did not publish. Neither read the producer side. dorny/paths-filter publishes nothing
under a key its `filters:` block omits, so a misspelled key there reads as the empty
string, `'' == 'true'` evaluates false, and the output publishes the literal "false" on
every run — which `evaluate` reads as "this job was not supposed to run". Measured on
this tree: renaming `steps.filter.outputs.rust` to `steps.filter.outputs.ruts` at
ci.yml:53 left `python3.12 scripts/tests/ci-gate/ci_gate_selftest.py` reporting 296 of
296 assertions passed and `bash scripts/check-toolchain-wiring.sh` printing OK, while
each of the sixteen jobs whose `if:` reads that output skipped under a green `ci`. `check_filter_keys_agree`
now requires the keys a job reads off a paths-filter step and the keys that step defines
to be one set, in both directions: a key read and not defined publishes "false" forever,
and a key defined and not read gates no job. When one name is written in two files, check
both spellings against each other, not each against the reader that already agrees
with it.

**13. A feature check that reads the command and not the build.** The first revision of
`NON_BRIDGE_SHIPPED_ASSERTION_LANES` paired `scp-identity` with job `rust-test` under a
comment claiming nothing in this repository enables `scp-identity/testing`, and
`command_enables_testing` confirmed that claim by reading the command's `--features`
text alone. The claim was false one manifest away: `crates/scp-testing/Cargo.toml`
declares a normal dependency `scp-identity = { path = "../scp-identity", features =
["testing"] }`, and one cargo invocation resolves one feature set per package, so job
rust-test's `cargo nextest run --workspace` built scp-identity with `testing` on and
compiled out both of its `#[cfg(not(feature = "testing"))]` assertions
(`ephemeral_create_fails_closed_without_pre_rotation_backend` and
`persisted_create_fails_closed_without_pre_rotation_backend` in
`crates/scp-identity/src/config.rs`) — the two SCP-IDENT-1059 proofs that
`Identity::create` fails closed without a pre-rotation backend. The check then reported
each one running by name, because an unfiltered workspace command selects every test its
packages compile, and these two compiled in no lane. The lane's `--no-tests=fail`
guarded nothing either: that exit-4 guard fires on an empty selection, and a workspace
run over thousands of tests never selects zero. The fix runs both assertions in job
`fail-closed-pre-rotation` over a `-p scp-identity` build, which leaves scp-testing's
manifest out, and adds `command_unifies_testing`, which scans the manifests a command's
build includes — every non-excluded member for `--workspace`, each named package's
manifest plus its dev path dependencies and their no-dev closures for `-p` — for a
dependency entry or a `[features]` value enabling `<package>/testing`, and rejects the
lane instead of trusting the command's text. When a criterion is "feature X is off in
this build", read what the build resolves, not what the command spells.

## Tests holding these closed

- `scripts/tests/ci-gate/run-tests.sh` — asserts every job sets a `timeout-minutes`, that
  every job is a dependency of `ci`, that no `cargo test` in any workflow carries a
  test-name filter on either side of a `--`, that four binding test jobs run on a
  Rust-only change, that any job reading a runtime-scaling input sizes its budget from
  that input and covers every permitted option, that no step gates itself on a `changes`
  filter output, that the keys each `changes` job reads off its paths-filter step and the
  keys that step's `filters:` block defines are one set — with a rename planted in a
  re-parsed copy of each real workflow proving that comparison reports the defect from
  both ends — that each of the three production-config bridge jobs runs a test command
  over its own package with that package's `testing` feature absent, that every
  `#[cfg(not(feature = "testing"))]` test under `crates/` is selected by name by a
  command in the job its package is paired with, that the readers deciding that question
  answer nine synthetic cases correctly — `--workspace` covers a member, `--exclude`
  drops one, a `test()` predicate selects by substring, a renamed assertion falls out of
  that filter, an unfiltered command selects everything, and a filterset carrying a
  difference is refused rather than guessed at — that `command_unifies_testing` reads a
  `testing` edge out of a four-crate fixture workspace in each spelling (a member's
  normal dependency, an edge reached through a `-p` package's dependency closure, a self
  dev-dependency, an `--exclude`d member a selected member still compiles) and out of
  this repository's own `crates/scp-testing/Cargo.toml` against scp-identity, while
  reporting a `-p scp-identity` build clean — that the `fuzz` and
  `typescript-wasm` filters cover the path-dependency
  closure of the manifests they guard, that every release.yml job uploading a `-signed`
  artifact runs its non-empty-input guard before that upload and that all three known
  signing jobs stay inside that suffix match, that an aggregate rejects a skipped
  dependency its
  condition selected to run, that an aggregate run without `GITHUB_EVENT_NAME` exits 3
  rather than accepting a skipped `cross-layer`, and that a closure over a two-crate
  fixture reaches a leaf whose entry reads `workspace = true` and raises on an inherited
  name no workspace publishes, and that the manifest set a build resolves against holds
  the workspace manifest an inherited entry reads, holds that workspace's `Cargo.lock`
  once one exists, and holds no enclosing lockfile for a crate carrying its own
  `[workspace]` table.
- `scripts/check-shipped-feature-graph.sh --self-test` — four fixtures pad a synthetic
  `cargo tree` past 200 KB and assert `tree_names_scp_testing_crate` returns one verdict
  whether the `scp-testing v0.1.0` line sits first or last, and a fifth reads the gate's
  own source and rejects any pipeline stage that stops before its writer finishes.
- `scripts/tests/cross-layer/run-tests.sh` — plants an FFI export at a first line and at
  a last line of a 155 KB diff, proves that gate finds both, then plants a missing export
  and proves it still rejects that.
- `scripts/tests/signing-guard/run-tests.sh` — runs
  `scripts/assert-nonempty-signing-set.sh` against fixture directories for all three
  signing jobs: a nested `.dll` is found, a directory holding only `.lib` and `.txt` is
  rejected, an XCFramework carrying headers and an `Info.plist` but no `.a` or `.dylib` is
  rejected, a directory whose own name ends in `.a` does not count as a library, a Maven
  directory holding only a log and a `.module` file is rejected, a directory that was
  never downloaded is rejected, and naming no directory at all is rejected.
- `scripts/tests/enforcement-files-hook/run-tests.sh` — three cases pad a `tee`, a
  redirect and a `sed -i` at a protected file past 64 KB and assert the hook still exits 2.
- `scripts/check-saga-gating-granularity.sh --self-test` — fixture (h) pads each of three
  supervisor function bodies past 64 KB, leaving every token on an early line, and asserts
  that a supervisor satisfying every positive assertion is still accepted. That padding is
  live code carrying a `//` tail, because `has_overlap_reject_in_reserve` deletes every
  `//` tail before it opens the pipe: measured, 1200 comment padding lines made a
  71,117-byte body reach that probe as 6,227 bytes, which never fills a pipe buffer, so
  fixture (h) passed with `grep -Fq` restored inside that probe while the same mutation of
  either other probe failed it. The replacement padding measures 150,007 bytes raw and
  129,117 stripped.
  `assert_body_exceeds_pipe_buffer` now measures each padded body the way its probe
  measures it and fails the self-test by name when one falls under 65,536 bytes, so a
  verdict assertion cannot outlive the precondition it rests on. Fixtures (i) and (j)
  plant a `"standing-"` literal in the extractor, (i) in a short body and (j) on an early
  line of a padded one, and assert both are rejected: a failure of (i) alone means P5 is
  dead, and a failure of (j) alone means P5's verdict depends on how long that body is. P5
  carried no behavioral proof before, which is why its fail-open survived.
- `scripts/check-shipped-feature-graph.sh --self-test` — builds a 200 KB synthetic
  `cargo tree` output with a `scp-testing v0.1.0` node on its first line and on its last
  line, and asserts the crate-node probe reports that node present in both, then asserts a
  tree carrying no such node still reads as absent.

Every harness above was run against unfixed code first and failed on exactly a defect it
describes. A harness that has never failed has not been tested.
