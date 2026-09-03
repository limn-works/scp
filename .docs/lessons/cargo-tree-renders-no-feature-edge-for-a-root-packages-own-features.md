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

Measured on this tree at commit e6f75c06b6:

- `crates/scp-node/Cargo.toml` defines
  `testing = ["scp-dht/testing", "scp-platform/testing", "allow_unencrypted_storage"]`,
  which compiles `InMemoryDhtClient`, the `scp-platform` in-memory custody and
  attestation doubles, and `ProtocolRepository::new_for_testing`.
- The gate's extraction over `-p scp-node` and over `-p scp-node --features testing`
  produced a byte-identical 25-line set, and `grep -c 'feature "testing"'` over the
  whole `--features testing` tree returned 0.
- `cargo tree … --format '{p} {f}'` on that same invocation reported
  `scp-dht … default,production-dht,testing` and
  `scp-platform … encrypting,file,in-memory-push,in-memory-storage,software_platform,sqlite,testing`,
  so cargo's resolver had every one of those features on.
- Running the gate against a `crates/scp-node/Cargo.toml` carrying
  `default = ["testing"]` printed
  `>> scp-node () / OK — resolved SCP-crate feature set ⊆ permitted-production allowlist`.
- Running it against a `crates/scp-relay/Cargo.toml` carrying a `[features]` table with
  `default = ["scp-platform/testing"]` printed the same OK line for scp-relay, and no
  other artifact backstopped that binary.

The two entries the pull request added were inert against the exact regression the
pull request named.

## The fix

Read two renderings of the same `cargo tree` invocation and take their union:

1. `cargo tree -e features,no-dev <args>` for the feature edges, and
2. `cargo tree -e features,no-dev <args> --format '@@{f}@@{p}'` for the features cargo
   resolved on each package node, the root included.

Neither rendering contains the other. Cargo renders a `foo feature "default"` edge for a
dependency taken with `default-features = true` even when `foo` defines no `default`
feature, and `{f}` then lists nothing for `foo` — `scp-core` on this tree is such a
package. So the gate reads both, and its fixture harness drives the pure
`scp_features_from_trees` splitter with synthetic renderings of a poisoned scp-node tree.

The `@@` sentinels put `{f}` before `{p}` and delimit it on both sides, so a package path
carrying a space, a parenthesis, or cargo's `(*)` deduplication marker cannot be read as
a feature name.

## The class

The same extraction sat in two functions of that one gate — `resolve_scp_features` for
the per-artifact path and `resolve_default_members_features` for the bare-workspace
backstop — so the backstop was blind in the same way for every default member, each of
which cargo prints as its own tree root. Both now call one `resolve_feature_set`, so the
two paths cannot drift apart in what they observe.

`scripts/check-protocol-deps.sh` also runs `cargo tree`, with `-p scp-protocol --edges
no-dev`. It reads crate-node presence rather than feature edges, so this rendering gap
does not reach it.
