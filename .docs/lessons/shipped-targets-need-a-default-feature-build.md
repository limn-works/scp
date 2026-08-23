# A Workspace-Wide `--examples` Lint Turns On the Feature It Is Meant to Exclude

**Date:** 2026-08-22
**Source:** branch `fix/rustls-webpki-advisories` — `crates/scp-node/examples/website.rs`
did not compile on a default build, no pull-request job rejected it, and the first
gate written to reject it accepted it.

## The Rule

A build target that ships to a user MUST be compiled by a job that gates the pull
request, on the feature set that ships. `cargo package --list -p scp-node` lists
`examples/website.rs`, so a broken example ships to crates.io.

Lint examples **one package at a time**. `cargo clippy --workspace --examples` does not
enforce that property, and it does not merely under-enforce it — it turns the excluded
feature on. `--examples` selects dev units, and a workspace-wide selection then unifies
dev-dependency features across every member. In this workspace `crates/scp-ffi`
dev-depends on `scp-ffi-common` with `features = ["testing"]`, that crate's `testing`
list carries `scp-node?/testing`, the weak edge fires, and every example in the workspace
compiles with `scp-node/testing` ON.

Source the file list from `cargo package --list`, not from `cargo metadata` example
targets. The two sets differ in both directions: `autoexamples = false` removes a target
while the file still ships, and `required-features` removes a target from a filter while
the file still ships. `scripts/check-examples-build-shipped.sh` reads the published file
set, fails when a published `examples/NAME.rs` has no matching target, and loops per
package. Do not collapse the loop back into `--workspace`.

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

6a is the instructive one: it kept the reported count at eight and printed
`── scp-node::website` for a file it never opened. A check that reports success by
name will report success for the wrong file.

## Four rounds, six bypasses, and the reframe that ended it

Each review round produced a different way past this gate. `CLAUDE.md` names the
pattern: more than about three passes surfacing "a new spelling of the same bypass"
means the approach is non-convergent, so stop and reframe.

| Round | Bypass | Why it worked |
|---|---|---|
| 1 | `cargo clippy --workspace --examples` | A workspace-wide selection unifies dev-dependency features, so `scp-node/testing` was ON for every example. |
| 2 | (scope overclaimed, not a bypass) | The comment promised a property two live feature leaks broke. |
| 3 | `required-features = ["testing"]` on the example | Cargo skips a target whose required features are unmet, warns, and exits 0. |
| 4a | `autoexamples = false` plus a stray `examples/*.rs` | The file still ships; no target exists; a target-sourced list cannot see it. |
| 4b | Any nullifier other than `DhtMode::Memory` | Cargo gives an example its crate's dev-dependencies, which carry `scp-dht/testing` and `scp-platform/testing`. |
| 4c | `required-features` as a standing exemption | The four `scp-runtime` examples compile on default features anyway; the declaration only hid them. |

Rounds 1 through 3 were patched in the same shape each time, and each patch left the same shape in place, so the next round found another way past it. What ended it was changing where the check gets its truth.

**The reframe: ask what SHIPS, not what cargo selects.** `cargo package --list`
reports the files that reach crates.io. `cargo metadata` reports targets, and the
two sets differ in both directions — `autoexamples = false` removes a target while
the file still ships, and `required-features` removes a target from a filter while
the file still ships. Sourcing from the published file set closes 4a and 4c at once
and made the baseline ratchet that round 3 added unnecessary, so it was deleted.

**4b could not be closed, so the claim was withdrawn instead.** An example is a dev
target and cargo gives it the crate's dev-dependencies; no invocation switches that
off. The check therefore proves that a published example compiles for a consumer,
and proves nothing about which constructs it names. The script says so in the
imperative, because the earlier version's comment claimed the stronger property and
a reviewer had to measure it to find out otherwise.

Two guards remain load-bearing and must not be simplified away:

- **Per-package invocation.** Naming the package keeps dev-dependency unification
  to that package. The workspace-wide form is inert.
- **File-set sourcing.** A published `examples/NAME.rs` with no matching target is a
  failure, because nothing compiles it in CI or for a consumer.

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

Cargo builds an example as a dev target and gives it the crate's dev-dependencies. No
invocation switches that off, so the check cannot keep a test-only construct out of an
example, and it does not claim to.

**A dependency crate's `testing`, enabled by the linted crate's own dev-deps.**
`crates/scp-node/Cargo.toml` dev-depends on `scp-platform` and `scp-dht` with
`features = ["testing"]`, so an example naming `scp_platform::testing::InMemoryKeyCustody`
or `scp_dht::InMemoryDhtClient` compiles and passes.

**The same reach through a testing helper crate.** `scp-runtime` and `scp-transport`
dev-depend on `scp-testing`, whose **normal** dependencies carry `scp-platform{testing}`
and `scp-dht{testing}`. For `scp-runtime` that edge additionally resolves
`scp-runtime/testing` ON, through `scp-testing`'s normal `scp-core{testing}` dependency.
`scp-transport` has no `testing` feature of its own — an earlier draft of this file said
it did, which a reviewer caught by reading the manifest.

So the check proves that a published example compiles for someone who installs the crate.
It proves nothing about which constructs that example names. `DhtMode::Memory` was caught
only because it sits behind `scp-node`'s OWN `testing` feature, which scp-node's
dev-dependencies do not enable.

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
