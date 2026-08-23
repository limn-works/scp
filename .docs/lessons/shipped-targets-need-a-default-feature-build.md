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

## Three bypasses on one gate is the signal to reframe

The gate took three review rounds, and each round produced a different way past it.
`CLAUDE.md` names that pattern: more than about three passes surfacing "a new spelling
of the same bypass" means the approach is non-convergent, so stop and reframe rather
than patch again.

| Round | Bypass | Why it worked |
|---|---|---|
| 1 | `cargo clippy --workspace --examples` | A workspace-wide selection unifies dev-dependency features, so `scp-node/testing` was ON for every example. |
| 2 | (scope overclaimed, not a bypass) | The comment promised a property two live feature leaks broke. |
| 3 | Add `required-features = ["testing"]` to the example | Cargo skips a target whose required features are unmet, warns, and exits 0. The loop read exit 0 as a pass. |

Patching round 3 in the same shape — special-casing `required-features` — would have
invited a fourth spelling. The reframe was to stop asking "does the loop pass?" and pin
the answer instead: `scripts/examples-shipped-baseline.txt` records which example targets
must build on default features, and the check fails when an entry leaves that set. A
manifest edit that removes an example from the check now changes a checked-in file, which
is the ratchet pattern this repository already uses for bridge symmetry and `OnceLock`
counts.

Two mechanics carry the property, and both are load-bearing:

- **Name each target.** `cargo clippy -p P --examples` silently no-ops when every example
  in `P` is feature-gated, and cargo's own "no targets matched" warning is not promoted by
  `-D warnings`. Naming a target whose required features are unmet is a hard error.
- **Ratchet the set.** Without the baseline, the count can fall to zero one manifest edit
  at a time and every job stays green.

## `required-features` hides an example from CI and does not stop it shipping

`cargo package --list -p scp-runtime` lists all four of that crate's examples, and all
four declare `required-features = ["testing"]`. So the declaration is a CI-visibility
switch, not a shipping switch. Any rule that reads it as a statement about what ships is
wrong. `crates/scp-runtime/examples/identity.rs` still ships while importing
`scp_dht::InMemoryDhtClient` and printing "Published to DHT successfully."

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
