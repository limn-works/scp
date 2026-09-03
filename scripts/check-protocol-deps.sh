#!/usr/bin/env bash
# Verify scp-protocol has no async runtime dependencies in production.
set -euo pipefail

echo "Checking scp-protocol dependency tree..."

# async-trait is excluded: it's a proc-macro that generates trait impls at
# compile time and does not pull in an async runtime at run time.
#
# KNOWN LIMITATION: This check catches banned CRATE dependencies but does
# NOT catch direct std::time::SystemTime usage. SystemTime compiles on
# wasm32 but returns wrong values (epoch). The Clock trait enforcement
# (privatized free functions in scp-clock) handles that case.
# The WASM compilation check also does NOT catch SystemTime for the same
# reason — it compiles, just gives wrong results. Three complementary
# checks cover the sync invariant:
#   1. This script: no banned crate deps
#   2. check-protocol-sync.py: no async fn in production code (tree-sitter)
#   3. WASM compilation: no tokio/openmls (they don't compile on wasm32)
#   4. Clock trait: SystemTime access privatized in scp-clock
#
# `--target all` resolves the UNION of every target triple's dependency edges.
# Without it cargo evaluates each `[target.'cfg(…)'.dependencies]` table against
# the triple the runner compiles for and discards every edge whose cfg is false
# there, so a `tokio` declared under `cfg(target_os = "ios")` would be absent
# from the graph this check reads and this check would report success.
# crates/scp-protocol/Cargo.toml already carries a
# `[target.'cfg(target_arch = "wasm32")'.dependencies]` table, so the construct
# that hides an edge is in use in the very crate this gate guards. The fixture
# `assert_every_cargo_tree_resolves_every_target` in
# scripts/check-shipped-feature-graph.sh asserts this flag across every shell
# script under scripts/.
banned="tokio|scp-platform|openmls"
output=$(cargo tree -p scp-protocol --edges no-dev --target all 2>&1) || { echo "ERROR: cargo tree failed: $output"; exit 1; }
matches=$(echo "$output" | grep -iE "$banned" || true)

if [ -n "$matches" ]; then
    echo "ERROR: scp-protocol has banned dependencies:"
    echo "$matches"
    exit 1
fi

echo "scp-protocol dependency check passed: no async runtime deps."
