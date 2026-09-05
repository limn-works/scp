# `cargo tree -e features` Renders No Feature Edge For What The Root Package's Own `[features]` Table Activates

**Date:** 2026-09-03
**Source:** post-merge review of pull request #2305, which extended the G1
prove-absence gate to the scp-node and scp-relay binaries —
`scripts/check-shipped-feature-graph.sh`

## Rule

When a check derives a fact from a tool's rendered output, prove that the rendering
carries the fact. `cargo tree -e features` renders a feature edge — the line
`scp-dht feature "testing"` — for a feature that one package activates on another
package. It renders no such line for a feature that the package you selected with `-p`
activates through its own `[features]` table, because that root package's feature nodes
sit above the node cargo prints as the tree root. A check that greps feature edges out
of `cargo tree -e features -p <root>` therefore cannot observe the root's own feature
activations at all.

## What that cost

`scripts/check-shipped-feature-graph.sh` asserts that every shipped artifact's resolved
SCP-crate feature set is a subset of a permitted-production allowlist, and it derived
that set by grepping `scp-[a-z0-9-]+ feature "…"` lines out of
`cargo tree -e features,no-dev -p <artifact>`. Pull request #2305 added the scp-node and
scp-relay binaries to the gate's artifact list so that a later edit could not add a
`testing` edge to either binary and ship a nullifier unobserved.

Measured on this tree with cargo 1.98.0:

- `crates/scp-node/Cargo.toml` defines
  `testing = ["scp-dht/testing", "scp-platform/testing", "allow_unencrypted_storage"]`,
  which compiles `InMemoryDhtClient`, the `scp-platform` in-memory custody and
  attestation doubles, and `ProtocolRepository::new_for_testing`.
- The gate's extraction over `-p scp-node` and over `-p scp-node --features testing`
  produced a byte-identical 25-line set, and the whole `--features testing` tree printed
  the string `testing` zero times.
- `cargo tree … --prefix none --format '{f}|{p}'` on that same invocation reported
  `default,production-dht,testing|scp-dht …` and `…,testing|scp-platform …`, so cargo's
  resolver had every one of those features on.
- Appending a `[features]` table with `default = ["scp-transport/local-cache"]` to
  `crates/scp-relay/Cargo.toml` made the gate print
  `>> scp-relay () / OK — resolved SCP-crate feature set ⊆ permitted-production allowlist`
  and then `G1 PASSED`, exit status 0. No package outside scp-relay depends on scp-relay,
  so no other artifact entry backstopped that binary.

The two entries the pull request added were inert against the exact regression the
pull request named.

## The fix

Read two renderings of the same `cargo tree` resolution and take their union:

1. `cargo tree -e features,no-dev --target all <args>` for the feature edges, and
2. `cargo tree -e no-dev --target all --prefix none --format '{f}|{p}' <args>` for the
   features cargo resolved on each package node, the root included.

Neither rendering contains the other. Cargo renders a `foo feature "default"` edge for a
dependency taken with `default-features = true` even when `foo` defines no `default`
feature, and `{f}` then lists nothing for `foo` — `scp-core` on this tree is such a
package. So the gate reads both, and its fixture harness drives the pure
`extract_feature_edges`, `extract_package_features` and `merge_resolved_feature_sets`
with synthetic renderings of a poisoned scp-node tree.

`{f}` sits before `{p}` in the format string because a feature name never contains `|`
while a package's filesystem path may, so splitting on the first `|` is correct by
construction. `--prefix none` puts every node at column 0, so the `^scp-[a-z0-9-]+ v[0-9]`
anchor on the package field rejects an indented line and rejects a package whose name
merely ends in an SCP crate name.

## The class

The same extraction sat in two functions of that one gate — `resolve_scp_features` for
the per-artifact path and `resolve_default_members_features` for the bare-workspace
backstop — so the backstop was blind in the same way for every default member, each of
which cargo prints as its own tree root. Both now call one `resolve_feature_set`, so the
two paths cannot drift apart in what they observe.

Two live positive controls keep the repair honest, because a synthetic fixture cannot see
a cargo release that changes a rendering. Before the artifact loop,
`assert_resolver_sees_own_feature_table_activation` requires the resolver to report
`scp-ffi-common/server`, which `crates/scp-ffi/Cargo.toml` activates through its own
`server = ["scp-ffi-common/server", "dep:scp-node"]` list. After the default-members
check, `assert_positive_control_rejects_nullifier_build` requires the ⊆ check to reject
`-p scp-node --features testing`. Reverting the resolver to the edge rendering alone makes
both controls fail.

`scripts/check-protocol-deps.sh` also runs `cargo tree`, with `-p scp-protocol --edges
no-dev`. It reads crate-node presence rather than feature edges, so this rendering gap
does not reach it. A different `cargo tree` default does: without `--target all`, cargo
evaluates each `[target.'cfg(…)'.dependencies]` table against the runner's host triple and
discards every edge whose cfg is false there, and
`crates/scp-protocol/Cargo.toml` already carries such a table. Both scripts now pass
`--target all`, and `assert_every_cargo_tree_resolves_every_target` fails when any shell
script under `scripts/` runs `cargo tree` without it.
