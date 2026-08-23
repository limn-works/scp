# A Workspace-Wide `--examples` Lint Turns On the Feature It Is Meant to Exclude

**Date:** 2026-08-22
**Source:** branch `fix/rustls-webpki-advisories` — `crates/scp-node/examples/website.rs`
did not compile on a default build, no pull-request job rejected it, and the first
gate written to reject it accepted it.

## The Rule

A build target that ships to a user MUST be compiled by a job that gates the pull
request. `cargo package --list -p scp-node` lists `examples/website.rs`, so a broken
example ships to crates.io.

`scripts/check-examples-build-shipped.sh` carries three mechanisms, and deleting any one
of them reopens a bypass this repository has already measured:

1. **Lint one package at a time.** `cargo clippy --workspace --examples` unifies
   dev-dependency features across every member — `crates/scp-ffi` dev-depends on
   `scp-ffi-common` with `features = ["testing"]`, whose `testing` list carries
   `scp-node?/testing` — so every example compiles with `scp-node/testing` ON and the
   check goes inert.
2. **Iterate targets, not published files, when compiling.** `exclude = ["examples/*"]`
   empties the published set while the target still exists, and a file-driven loop skips
   the package in silence.
3. **Join published file to target on `src_path`, never on target name.** A
   `[[example]] path =` key can bind the name `website` to a decoy file while
   `examples/website.rs` still ships with no target. A name join sees the name on both
   sides and reports success for a file it never opened.

## Six rounds, nine bypasses, and what finally closed them

Nine distinct ways past this gate were found across six review rounds. The first
eight all shared one root: the check compared **names** or **shapes** rather than
the thing being asserted. What closed them was joining published file path to
target `src_path`, and iterating targets rather than files.

| Round | Bypass | Root |
|---|---|---|
| 1 | `cargo clippy --workspace --examples` | dev-dep unification turned `scp-node/testing` ON |
| 2 | (scope overclaimed, not a bypass) | comment promised more than the check delivers |
| 3 | `required-features = ["testing"]` | cargo skips the target and exits 0 |
| 4a | `autoexamples = false` | file ships, target absent, target-sourced list blind |
| 4b | any nullifier but `DhtMode::Memory` | dev-dependencies, unclosable |
| 4c | `required-features` as standing exemption | bought nothing, hid four examples |
| 5 | `cargo package --list` exit 101 swallowed | manifest error dropped a crate in silence |
| 6a | `[[example]] path = "examples/decoy/website.rs"` | name join saw `website` on both sides |
| 6b | `exclude = ["examples/*"]` | file-driven loop skipped the package |
| 6c | filename containing a space | unquoted `for` word-split past both checks |
| 7a | `examples/website/main.rs` directory layout | cargo auto-discovers it and publishes it; the enumerating regex matched only the flat form |
| 7b | `autoexamples = false` + a `cargo package --list` failure | the failure branch was gated on the crate having targets, which that key empties |

7a needed no manifest edit and no adversary. Cargo auto-discovers both
`examples/NAME.rs` and `examples/NAME/main.rs`; the check's regex encoded only the
first, and the comment above it stated the false rule as fact. A join is only as
sound as the set it enumerates, and the enumerator was wrong about cargo.

6a kept the reported count at eight and printed `── scp-node::website` for a file it
never opened. A check that joins on name reports success for whichever file the name
currently points at.

## `required-features` hides an example from CI and does not stop it shipping

`cargo package --list -p scp-runtime` lists all four of that crate's examples. So the
declaration is a CI-visibility switch, not a shipping switch, and any rule that reads
it as a statement about what ships is wrong.

This branch added `required-features = ["testing"]` to
`crates/scp-runtime/examples/identity.rs` on the premise that it could not build on
shipped features, then measured the premise and found it false:
`cargo clippy -p scp-runtime --example identity -- -D warnings` exits 0 on default
features, because `scp-runtime` dev-depends on `scp-testing`, whose NORMAL
`scp-core{testing}` edge resolves `scp-runtime/testing` ON. The declaration bought
nothing and removed the example from the check, so it was reverted. Coverage went
from four examples to eight.

See `.docs/lessons/first-boot-testing-needs-an-empty-state-directory.md` for the
measurement trap that nearly refuted one of the findings above.

## Measure a gate against the defect, never against the fixed tree

The workspace-wide line was written, run against the **fixed** tree, observed green, and
committed. Green on a fixed tree is the null result: it distinguishes nothing. Two
reviewers independently read the resolved features and reported that the line was inert.

Reintroducing `DhtMode::Memory` settled it:

| Invocation | `DhtMode::Memory` restored | `required-features` added | Clean tree |
|---|---|---|---|
| `cargo clippy --workspace --examples -- -D warnings` | **exit 0** | exit 0 | exit 0 |
| `cargo clippy -p scp-node --examples -- -D warnings` | exit 101, `E0599` | **exit 0** | exit 0 |
| `bash scripts/check-examples-build-shipped.sh` | exit 1, `E0599` | exit 1, names the target | exit 0 |

A fourth defect belongs in the same table and was found later: renaming
`crates/scp-node/README.md` makes `cargo package --list` exit 101, and an earlier
version of the check discarded that exit code, so scp-node dropped out in silence —
7 examples checked instead of 8, with `website.rs` never linted. The check now
surfaces it and exits 1.

Run a gate against the defect before committing it, and record both exit codes.

When a gate's comment overstates its reach, the next author reads the comment, believes
the property is proven, and stops checking. That is the extrapolation-as-contract failure
`CLAUDE.md` names, written into an enforcement file.

## What happened

ADR-062, capability injection, moved `DhtMode::Memory` behind
`#[cfg(feature = "testing")]` because its in-memory client is a §17.17.3 resolve
nullifier. `crates/scp-node/examples/website.rs` kept selecting that variant, so
`cargo check -p scp-node --examples` failed with `E0599` on a default build.

Three jobs each looked like they covered it and none did:

- `.github/workflows/ci.yml` runs `cargo clippy --workspace --all-targets` with
  `--features ...testing`, so the example compiled.
- `.github/workflows/build-matrix.yml` runs `cargo build --release` without
  `--examples`, and only on a release tag or a `workflow_call`.
- `.github/workflows/release.yml` runs `cargo clippy --workspace --all-targets` on
  default features, but on `workflow_dispatch` — after the merge, not before it.

## The trap in the obvious widening

Widening the pull-request job to `cargo clippy --workspace --all-targets` on default
features looks strictly better and fails today: `scp-ffi-uniffi`'s inline `#[cfg(test)]`
module in `src/bridge.rs` needs the `testing` feature and is a lib-test target, not a
`[[test]]` target, so it carries no `required-features` guard and cannot drop out. The
same defect makes `release.yml`'s clippy step red on any release tag.

Run the widened invocation before adopting it.

## What the check does not cover

The script header states this in full; it is the text an editor of the gate reads.
In short: cargo builds an example as a dev target and gives it the crate's
dev-dependencies, and no invocation switches that off, so the check proves that
every example target compiles in this workspace and proves neither that an example
compiles for someone who installs the crate nor anything about which constructs it
names. `DhtMode::Memory` was caught only because it sits behind `scp-node`'s OWN
`testing` feature, which scp-node's dev-dependencies do not enable.

One correction worth keeping: `scp-transport` has no `testing` feature of its own.
An earlier draft of this file said it did, and a reviewer caught it by reading the
manifest.

## How to apply

- Before writing that a job would have caught a break, name the job and read its trigger.
  A job gated on `push: tags:` or `workflow_dispatch` gates a release, not a pull request.
- When a feature flag moves a construct out of a shipped build, grep the whole repository
  for the construct's name — examples, the `README.md` beside the example, operator
  guides, and environment-variable tables. This branch found the same stale name in
  `crates/scp-node/examples/README.md`, `crates/scp-node/tests/self_host.rs`, two guides
  under `.docs/guides/`, and `docs/guides/relay-operations.md`, which advertised
  `SCP_NODE_DHT_MODE=memory` to operators when a shipped `scp-node` exits 1 on it.
- Search both documentation trees. This repository has `.docs/` and a separate lowercase
  `docs/`, and a sweep of one misses the other.

Filed as issue 2386, "release.yml's clippy step cannot pass: scp-ffi-uniffi's inline test
module needs the testing feature." It is filed rather than fixed because the two available
fixes are not equivalent, and one of them removes a release-time assertion — which
`CLAUDE.md` says a human approves.
