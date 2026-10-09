# Route a Changed File to Every CI Lane Whose Behaviour It Decides

`.github/workflows/ci.yml` guards each language job with a `dorny/paths-filter` output, and
the aggregating `ci` job counts a skipped job as a pass. A file that no filter lists
therefore merges with every job that reads it skipped.

## Rules

- **Which paths need deliberate routing: those whose omission from a filter is invisible on
  an ordinary pull request.** Dropping `crates/**` from the `rust` filter is noticed within a
  day. Dropping `rust-toolchain.toml` skips the lanes only on the rare pull request that
  raises the pin, which is the one that most needs them.
- **Route a file to every lane whose behaviour it decides, not to the lane whose name
  matches it.** The toolchain pin selects the compiler for `pyo3-module` and
  `pyo3-module-macos` (`maturin develop`), `napi-addon`, `typescript-wasm-check`,
  `scaffold-typescript-web-check`, `kotlin-test`, `xcframework`,
  and `rust-docs` in `.github/workflows/docs.yml`, not only the `rust` lane. `.cargo/config.toml` decides every
  `wasm-pack build` through its `[target.wasm32-unknown-unknown]` stanza.
- **The workflow file that defines a lane decides that lane.** A commit that only rewrites a
  job's command otherwise skips that job and merges green. `ci.yml` lists itself in its
  `toolchain` filter, and a second time in the `fuzz` filter because the `fuzz` output reads
  that filter alone; `docs.yml` lists itself in its own `toolchain` filter.
- **Name such a file once.** The `changes` job declares one `toolchain` filter, and each
  lane's output reads `steps.filter.outputs.<lane> == 'true' ||
  steps.filter.outputs.toolchain == 'true'`. Check 2e of
  `scripts/check-toolchain-wiring.sh` reads the outputs out of the workflow, so a lane added
  later without that clause fails the gate.
- **A job that reads no prose skips on a prose-only change, through the `code` output.** The
  `code` filter lists every path a job compiles, executes, or feeds a gate as input, and its
  output ORs in `toolchain` like every other lane. Jobs that ran on every pull request but read
  only code (fail-closed-pre-rotation, shipped-feature-graph, wiping-allocator, protocol-deps,
  wasm-protocol, wasm-test, toolchain-wiring-cases, fix-round-check-selftest) are guarded by it. A job that reads a prose
  file needs a filter that selects that file: the `rust` filter lists `.docs/adrs/**`,
  `.docs/prds/**` and `.docs/standards/sdk-capability-matrix.json`, which rust-test reads. Job
  `toolchain-wiring` checks on every pull request that `AGENTS.md` keeps the two headings
  `pipeline_wiring.rs` asserts, because no filter of job `changes` selects `AGENTS.md`.
- **Split a suite whose checks read both prose and code, and prove the split covers it.**
  `scripts/tests/ci-gate/ci_gate_selftest.py` assigns each check to `docs` (it opens a file
  outside the `code` patterns, or lists tracked paths) or `rest`. Job
  ci-workflow-selftest-docs runs `--group docs` on every pull request, and job
  ci-workflow-selftest runs `--group rest` under `code`. The `group-partition` assertion fails
  when a check is in neither group or in both, so a new check cannot run in no job.
- **A positive list needs a coverage check, or a new file falls between it and prose.**
  `scripts/tests/ci-gate/ci_gate_selftest.py` (`prose-route`) lists every `git ls-files` path
  and fails on each one that the `code` output does not select and that is not prose: under
  `.docs/` or `.claude/`, a root-level `*.md`, or a `*.md` under `docs/guides/`.
- **`on: pull_request: paths:` needs no such routing**, because a required check whose
  workflow never starts stays pending and blocks the merge.

## Rejected: a `'**'` filter minus exclusions

dorny/paths-filter's `predicate-quantifier` defaults to `some`, so `'**'` makes the filter
true for every pull request and `!` exclusions subtract only under `some-with-excludes`,
which changes matching for every filter in the block. It would also run clippy, the test
lane, both production builds, cargo-deny, and the image build on every `.docs/`-only commit.
The `code` filter avoids both problems by listing directories and root files, with no `'**'`
and no `!` entry, and the `prose-route` check covers what such a list can miss.
