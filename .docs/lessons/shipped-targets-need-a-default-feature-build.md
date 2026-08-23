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

`scripts/check-examples-build-shipped.sh` derives the package list from `cargo metadata`
and loops. Do not collapse the loop back into `--workspace`.

## Measure a gate against the defect, never against the fixed tree

The workspace-wide line was written, run against the **fixed** tree, observed green, and
committed. Green on a fixed tree is the null result: it distinguishes nothing. Two
reviewers independently read the resolved features and reported that the line was inert.

Reintroducing `DhtMode::Memory` settled it:

| Invocation | Bug present | Bug fixed |
|---|---|---|
| `cargo clippy --workspace --examples -- -D warnings` | **exit 0** | exit 0 |
| `cargo clippy -p scp-node --examples -- -D warnings` | exit 101, `E0599` | exit 0 |

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

Cargo gives an example its own crate's dev-dependencies, and no invocation switches that
off, so two leaks stay open and neither is closable.

**A dependency crate's `testing`, enabled by the linted crate's own dev-deps.**
`crates/scp-node/Cargo.toml` dev-depends on `scp-platform` and `scp-dht` with
`features = ["testing"]`, so `scp_platform::testing` stays reachable from a scp-node
example.

**A dev-dependency back-edge that re-enables the linted crate's own `testing`.**
`scp-runtime` and `scp-transport` dev-depend on `scp-testing`, whose **normal**
`scp-core{testing}` edge resolves `scp-runtime/testing` ON — which also satisfies the
`required-features` guards on those crates' own examples.

So the check rejects an example naming a construct behind its own crate's `testing`, in a
crate whose dev-dependency graph does not turn that feature back on. `scp-node` is the
only workspace member where that holds today. It proves nothing about a reader who copies
an example out and depends on the published crate.

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
