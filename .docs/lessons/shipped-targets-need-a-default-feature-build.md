# A Gating Job Must Build Every Shipped Target on the Feature Set That Ships

**Date:** 2026-08-22
**Source:** branch `fix/rustls-webpki-advisories` — `crates/scp-node/examples/website.rs`
did not compile on a default build, and no pull-request job rejected it.

## The Rule

A build target that ships to a user — a binary, an example carried in the published
crate, a bin under a feature — MUST be compiled by a job that gates the pull request,
using the feature set that ships. A job that compiles the same target under a `testing`
feature does not discharge that obligation, and neither does a job whose trigger is a
release tag.

State the scope of such a job in its own comment, because the scope is narrower than it
reads. Cargo unifies a crate's dev-dependency features into an example or test build, so
`cargo clippy --workspace --examples` checks a crate's own default features and still
admits a `testing` feature that a dev-dependency edge turns on.

## What happened

ADR-062, capability injection, moved `DhtMode::Memory` behind `#[cfg(feature =
"testing")]` because its in-memory client is a §17.17.3 resolve nullifier.
`crates/scp-node/examples/website.rs` kept selecting that variant, so
`cargo check -p scp-node --examples` failed with `E0599` on a default build. The example
sat broken on `main`, and `cargo package --list -p scp-node` includes it, so the broken
file shipped in the published crate.

Three jobs each looked like they covered it and none did:

- `.github/workflows/ci.yml` runs `cargo clippy --workspace --all-targets` with
  `--features ...testing`. `scp-ffi`'s default `server` feature activates the optional
  `scp-node` dependency, and `scp-ffi-common`'s `testing` list carries
  `scp-node?/testing`, so feature unification turned `scp-node/testing` on and the
  example compiled.
- `.github/workflows/build-matrix.yml` runs `cargo build --release` without
  `--examples`, and only on a release tag or a `workflow_call`.
- `.github/workflows/release.yml` runs the class-correct
  `cargo clippy --workspace --all-targets -- -D warnings` on default features, but only
  on `workflow_dispatch`, which is after the merge rather than before it.

## The trap in the obvious fix

Widening the pull-request job to `cargo clippy --workspace --all-targets` on default
features looks strictly better and fails today: `scp-ffi-uniffi`'s inline `#[cfg(test)]`
module in `src/bridge.rs` needs the `testing` feature and is a lib-test target, not a
`[[test]]` target, so it carries no `required-features` guard and cannot drop out. The
same defect makes `release.yml`'s clippy step red on any release tag.

Check that a widened invocation is green before widening to it. "Strictly broader" is a
claim about coverage, not a claim about the tree compiling.

## How to apply

- Before writing that a job would have caught a break, name the job and read its trigger.
  A job gated on `push: tags:` or `workflow_dispatch` gates a release, not a pull request.
- When a feature flag moves a construct out of a shipped build, grep the whole repository
  for the construct's name — examples, `README.md` beside the example, operator guides,
  and environment-variable tables — not only the crate that defines it. This branch found
  the same stale name in `crates/scp-node/examples/README.md`,
  `crates/scp-node/tests/self_host.rs`, two guides under `.docs/guides/`, and
  `docs/guides/relay-operations.md`, which advertised `SCP_NODE_DHT_MODE=memory` to
  operators when a shipped `scp-node` exits 1 on that value.
