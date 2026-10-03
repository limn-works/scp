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
  `scaffold-typescript-web-check`, `kotlin-test`, `bridge-parity-kotlin`, `xcframework`,
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
- **`on: pull_request: paths:` needs no such routing**, because a required check whose
  workflow never starts stays pending and blocks the merge.

## Rejected: a `'**'` filter minus exclusions

dorny/paths-filter's `predicate-quantifier` defaults to `some`, so `'**'` makes the filter
true for every pull request and `!` exclusions subtract only under `some-with-excludes`,
which changes matching for every filter in the block. It would also run clippy, the test
lane, both production builds, cargo-deny, and the image build on every `.docs/`-only commit.
