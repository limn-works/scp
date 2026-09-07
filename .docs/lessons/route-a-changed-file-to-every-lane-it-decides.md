# Route a Changed File to Every CI Lane Whose Behaviour It Decides

**Problem**: `.github/workflows/ci.yml` guards each language job with a
`dorny/paths-filter` output, and the aggregating `ci` job fails only on a result of
`failure` or `cancelled`, so a skipped job reports success to branch protection. A file
that no filter lists therefore merges with every job that reads it skipped.

## Rules

- **The criterion for a path that needs routing: omitting it from its filter is invisible
  on an ordinary pull request.** Dropping `crates/**` from the `rust` filter skips the Rust
  lane on nearly every pull request, and someone notices within a day. Dropping
  `rust-toolchain.toml` skips that lane only on the rare pull request that raises the
  compiler pin — the one pull request that most needs the lane to run — and nobody notices.
  A gate covers the second class, and it says in its own output that an `OK` is not a claim
  that the filters are correct.
- **Route a file to every lane that guards a job whose behaviour the file decides, not to
  the lane whose name matches the file.** `rust-toolchain.toml` sits at the repository root
  and names a Rust version, which makes the `rust` filter the obvious single destination,
  and the compiler it selects reaches six other lanes: `python-test` runs
  `maturin develop`, `typescript-check` runs `cargo build -p scp-ffi-napi`,
  `typescript-wasm-check` and `scaffold-typescript-web-check` run `wasm-pack build`,
  `kotlin-test` runs `cargo build -p scp-ffi-uniffi`, and `swift-build-test` runs
  `bindings/swift/build-xcframework.sh`, which calls `cargo build`. A second workflow,
  `.github/workflows/docs.yml`, guards `rust-docs` the same way, and that job runs
  `cargo doc --workspace --no-deps --document-private-items`, which compiles every crate in
  the workspace.
- **A file that reaches a lane indirectly still decides that lane.** Cargo reads
  `.cargo/config.toml` out of every ancestor of the directory a command runs in, so its
  `[target.wasm32-unknown-unknown]` stanza selects getrandom's wasm backend for every
  `wasm-pack build`, and a `[build]` stanza added there changes what every crate compiles
  to.
- **Name the file once in the workflow, not once per lane and again in the gate.** Listing
  one path in seven filters, and asserting that membership with seven pairs in a gate, puts
  the path in fourteen places; both lists grow with the lanes and neither one tells anyone
  about a lane added later. The `changes` job declares one `toolchain` filter, and each
  lane's output reads
  `steps.filter.outputs.<lane> == 'true' || steps.filter.outputs.toolchain == 'true'`. The
  gate reads the set of output names out of the workflow rather than out of a list it
  holds, so a lane added later without that clause fails the gate.
- **`on: pull_request: paths:` needs no such routing, because it fails closed.** A required
  check whose workflow never starts stays pending and blocks the merge. The skipped-job
  mechanism is the one that reports success for a job nothing ran.

## Rejected alternative: write the filter as `'**'` plus exclusions

Inverting the default so an unlisted path runs the lane is the safe direction, and it would
retire the root-file classification the gate performs. Two things argue against it. First,
it does not work as written under the action's default: `dorny/paths-filter` documents its
`predicate-quantifier` input as defaulting to `some` — "File is included if it matches at
least one pattern" — so `'**'` alone makes the filter true for every pull request, and the
`!`-prefixed exclusions subtract only under `some-with-excludes`. Switching the quantifier
changes matching for every filter in the block at once. Second, the cost recurs on every
pull request: with `'**'` minus a directory list, a commit that touches only
`.claude/agent-memory/` or `.docs/` runs clippy, the test lane, both production builds,
cargo-deny, and the container image build, against a failure mode that arises only when
someone adds a Rust-compiling path outside `crates/`.

## See also

- `.docs/lessons/pin-the-rust-toolchain-or-ci-drifts-from-local.md` — the outage that made
  the pin a routed file.
- `.docs/lessons/a-gate-enumerates-its-population-and-reads-the-parse.md` — how the gate
  covering this routing enumerates the workflows and the root-level files.
