# A Green Check That Asserted Nothing

A check reports success in two situations that look identical in CI output: it met its
target and rejected nothing, or it never met its target. Before trusting a passing check,
make it fail on the defect it exists to catch, and keep that failure as a test. Every trap
below produced a green check in this repository while the work behind it never ran.

## Commands that succeed on an empty selection

- **`cargo test <filter>` exits 0 when the filter matches no test**, and so does
  `cargo test -- <filter>`, which hands the filter to libtest. Use
  `cargo nextest run --no-tests=fail -E 'test(name)'`, which exits 4 on an empty selection.
  Read both sides of a `--` when auditing a test command.
- **`--no-tests=fail` fires only on an empty selection.** A filterset that unions tests
  compiled out by a `testing` flip with tests that survive it still selects something after
  the flip, so the step stays green over zero fail-closed proofs. Run tests that vanish on a
  feature flip in their own `cargo nextest run`.
- **A `#[cfg(not(feature = "testing"))]` assertion runs nowhere when every lane enables
  `testing`**, including through feature unification: one cargo invocation resolves one
  feature set per package, so `crates/scp-testing/Cargo.toml` enabling
  `scp-identity/testing` compiles scp-identity's fail-closed tests out of every
  `--workspace` run. Decide "is feature X off in this build" from the manifests the build
  reads, not from the command's `--features` text.
- **A loop over an empty set exits 0 and then publishes.** A signing job whose file glob
  matched nothing uploaded an artifact named `*-signed` holding nothing signed. Assert the
  input set is non-empty before the publish step; `scripts/assert-nonempty-signing-set.sh`
  does this for every job that uploads a `-signed` artifact. In pwsh a failing native
  command sets `$LASTEXITCODE` without stopping the script, so check it after each call.

## Shell and tool traps

- **`grep -q` inside a pipeline under `set -o pipefail` can report a present match as
  absent.** `grep -q` exits at its first match, the writer dies of SIGPIPE with 141, and
  `pipefail` returns 141. The verdict then depends on where the match sits in a large input.
  Write `grep PATTERN >/dev/null`. The same applies to `grep -m N`. Search every gate for the
  construct, not only the file where you found it.
- **`grep -F` with a multi-line pattern is a per-line membership test**, so it accepts one
  line of a block or the block reversed. Compare a block with bash's
  `[[ $text == *"$block"* ]]`.
- **When a file has a grammar, read the parse.** A regex for a `rust` key in `.mise.toml`
  matched four of the eight TOML spellings; `tomllib` answers all of them.
- **`cargo tree -e features -p <root>` renders no edge for a feature the root package
  activates through its own `[features]` table.** Read cargo's resolved per-package list too
  (`cargo tree -e no-dev --target all --prefix none --format '{f}|{p}'`) and take the union
  with the edge rendering, which alone shows a `foo feature "default"` edge for a crate that
  declares no `default` feature.
- **`cargo tree` without `--target all` resolves only the host triple** and drops every
  `[target.'cfg(…)'.dependencies]` edge that is false there. A `testing` feature declared
  under `cfg(target_os = "ios")` shipped past the Linux-run gate that way.
- **A build tool can take its feature list from a config file.** maturin reads
  `[tool.maturin] features` from `bindings/python/pyproject.toml`, so a gate that reads only
  cargo command lines never sees the wheel's features.

## Workflow wiring traps

- **The `ci` aggregate must distinguish "skipped" from "passed".** Read the dependency map
  with `toJSON(needs)` so the aggregate covers every job by construction, and decide per job
  whether it was supposed to run (`scripts/ci-aggregate-result.py`).
- **Gate a job at job level, never with the same `if:` on every step.** A job whose steps
  all skip reports success, and the guards that catch a misspelled filter output read only
  job-level conditions.
- **A paths-filter key misspelled on the producer side publishes `"false"` forever.**
  dorny/paths-filter publishes nothing for a key its `filters:` block omits, so
  `'' == 'true'` holds every dependent job at skipped. Check that the keys read and the keys
  defined are one set, in both directions.
- **A filter written as a list of names stops covering when a member is added.** Write the
  closed pattern (`crates/**`); where a filter must stay narrower, compute its population
  from the manifests. `scripts/tests/ci-gate/ci_gate_selftest.py` rebuilds path-dependency
  closures, including the workspace `Cargo.toml` and `Cargo.lock` a closure resolves
  against, since a dependency bump touches only those two files.
- **A guard must stop on an input it cannot read.** Reading an absent `GITHUB_EVENT_NAME`, or
  a `workspace = true` dependency with no `path` key, as an empty value made two guards
  accept exactly the skip they were written to catch.
- **Every job needs `timeout-minutes`**, since GitHub's default is 360. Where a dispatch
  input sets how long a step runs, bound the input to a closed option list and size the
  budget per option; GitHub expressions have no arithmetic.
- **Two jobs running one tool under different flags are two checks, and the weaker one
  decides merges.** The required `rust-doc` job ran `cargo doc` without
  `--document-private-items`, so broken intra-doc links in private modules merged. A lint
  one crate declares runs in one crate: the workspace sets
  `rustdoc::broken_intra_doc_links = "forbid"` under `[workspace.lints.rustdoc]`, and
  `forbid` because a source-level `#![allow]` can lower `deny`.

## Where a check sits and what it enumerates

- **A check placed where its target cannot arise reports success forever.** A
  `RUSTUP_TOOLCHAIN` comparison in a GitHub job could never fire, because runners export no
  such variable; it now runs in `scripts/hooks/pre-commit`.
- **Enumerate the population, then require every member to be classified.** A check that
  names the members that must be present fails silently on the member nobody added.
  `scripts/check-toolchain-wiring.sh` enumerates every paths-filtered workflow and every
  root-level and cargo-config file from the tree. Derive the enumeration from the criterion,
  not from the examples in front of you: a "no slash in the path" rule missed
  `.cargo/config.toml`.
- **Decide whether a build reads a file by its path or manifest entry, not by a keyword in
  its text.** A search for a line-initial `FROM rust` failed on documentation that quoted a
  Dockerfile and missed an indented lowercase `from`.
- **An artifact no job builds is broken without anyone knowing.** The root `Dockerfile` had
  never been built in CI and failed three ways on its first build. Run such an artifact, and
  run a scheduled workflow with `gh workflow run <file> --ref <branch>`, before merging a
  repair to it.
- **A gate that reports absence carries a positive control on every run.**
  `scripts/check-shipped-feature-graph.sh` requires the resolver to report a known
  activation and requires the subset check to reject `-p scp-node --features testing`.
- **A condition that its own hard-coded input makes constant is not a check.** Trace the
  literal input to the condition; when every path ends at the same answer, the check tests
  the literal.

The tests that hold these closed live in `scripts/tests/ci-gate/`, `scripts/tests/cross-layer/`,
`scripts/tests/signing-guard/`,
`scripts/tests/toolchain-wiring/`, and the `--self-test` modes of
`scripts/check-shipped-feature-graph.sh` and `scripts/check-saga-gating-granularity.sh`. Each
one was run against the unfixed code first and failed.
