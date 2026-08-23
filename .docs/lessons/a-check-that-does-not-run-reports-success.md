# A Check That Does Not Run Reports Success, So Enumerate What Must Run From the Repository

**Date:** 2026-08-23
**Source:** branch `fix/clippy-1-98-chunks-exact` — a review of the toolchain-pin work found
two ways a pull request could merge with the Rust lane never having compiled, and both came
from a hand-written list that named fewer things than it claimed to.

## The Rule

GitHub reports a skipped job as a pass for a required status check, and it reports a job
whose dependency failed as skipped. A repository whose merge gate is one aggregator job
therefore has to decide two questions from the repository itself, never from a list
somebody maintains by hand:

1. **Which jobs must the aggregator observe?** Every job the workflow declares. A job the
   aggregator's `needs:` list omits runs unobserved, and a job its results array omits is
   waited for and then ignored.
2. **Which files must reach a lane's paths filter?** Every file a job of that lane reads
   while it compiles. A file no filter routes leaves the filter output `false`, skips every
   job the filter guards, and merges green.

Both answers are enumerable from the tree, so a gate reads them out of the tree, and a list
nobody updated fails the gate instead of passing silently.

## The Two Instances

### The aggregator did not watch the two jobs everything depends on

`.github/workflows/ci.yml` declared 52 jobs. The `ci` job's `needs:` list and its `results`
array each held 49 names, and the pull-request body said "the two lists agree exactly: 49
entries each, covering every job." The three the lists left out were `ci` itself, `changes`,
and `check-draft` — and `changes` and `check-draft` are the two jobs every other job depends
on.

A `changes` job that fails — a `filters:` block `dorny/paths-filter` cannot parse, a
checkout that errors — makes every job guarded by `if: needs.changes.outputs.<lane> ==
'true'` report `skipped`. The aggregator's loop exits 1 on `failure` and on `cancelled` and
on nothing else, so it would print "All CI jobs passed or were skipped", exit 0, and let a
pull request merge with zero compilation and zero tests having run.

`scripts/check-ci-aggregator.sh` now reads the job names out of the workflow and requires
both lists to name every one of them apart from the aggregator, and requires the aggregator
to carry `if: always()`, without which GitHub skips the required check on the very failure
it exists to report.

### A Markdown file was a compile input, and the gate's exemption list called it prose

`scripts/check-toolchain-wiring.sh` listed `CLAUDE.md` in `NO_RUST_JOB_READS` under the
comment "Documentation and licensing. No job compiles from them."
`crates/scp-testing/tests/integration/pipeline_wiring.rs` embeds that file with
`include_str!` and asserts that it holds two headings, and
`crates/scp-testing/Cargo.toml` declares that file as a test target, so
`cargo test --workspace` and `cargo clippy --workspace --all-targets` both compile it. A
pull request that renamed either heading would skip `rust-clippy` and `rust-test`, merge
green, and turn `cargo test --workspace` red on `main` for the next branch that touched
`crates/**`.

`include_str!` and `include_bytes!` make a file's extension irrelevant: a `.md`, a `.json`,
a `.py`, a `.ts`, a `.swift`, and a `.kt` are all compile inputs when a Rust source names
them. This repository embeds 49 files that hold no Rust, and the `rust` filter routed none
of them. Check 2e of the wiring gate now reads those calls out of `crates/**/*.rs`,
resolves each path against the calling file's directory, and requires a filter to route it —
including when `NO_RUST_JOB_READS` declares the file unread, which is the one claim in that
list the gate can falsify.

## What This Says About Exemption Lists

An exemption list is a set of claims the gate takes at face value. That is acceptable only
for the claims the gate cannot check. When a claim is mechanically checkable — "no compile
reads this file" is, because `include_str!` names its argument — check it, and let the list
carry only what is left.

## Related

- `.docs/lessons/pin-the-rust-toolchain-or-ci-drifts-from-local.md` — the pin work this
  review examined.
- `.docs/lessons/test-whitelist-masks-ci-red.md` — the same failure shape one layer down.
