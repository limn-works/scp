#!/usr/bin/env bash
# Every example target ships inside its crate's published archive
# (`cargo package --list -p scp-node` lists `examples/website.rs`), so a shipped
# example must build without a feature that only a test harness turns on.
#
# WHAT THIS CHECK REJECTS: an example that names a construct behind its own
# crate's `testing` feature, in a crate whose dev-dependency graph does not turn
# that feature back on. Today `scp-node` is the only workspace member where that
# holds, and `DhtMode::Memory` in `crates/scp-node/examples/website.rs` is the
# defect it was measured against.
#
# WHAT IT DOES NOT REJECT, because cargo gives an example its own crate's
# dev-dependencies and no invocation switches that off:
#   (a) a construct behind a DEPENDENCY crate's `testing`, when the linted crate
#       dev-depends on it with that feature. `crates/scp-node/Cargo.toml` does
#       exactly that for `scp-platform` and `scp-dht`, so `scp_platform::testing`
#       stays reachable from a scp-node example.
#   (b) a construct behind the LINTED crate's own `testing`, when a dev-dependency
#       back-edge re-enables it. `scp-runtime` and `scp-transport` dev-depend on
#       `scp-testing`, whose NORMAL `scp-core{testing}` edge resolves
#       `scp-runtime/testing` ON — which also satisfies the `required-features`
#       guards on those crates' examples.
# Neither leak is closable: an example links its crate's dev-dependencies by
# definition. Do not write a comment here claiming otherwise.
#
# Package scope is load-bearing, and a future editor MUST NOT collapse this loop
# into `cargo clippy --workspace --examples`. A workspace-wide selection unifies
# dev-dependency features across ALL members: `crates/scp-ffi` dev-depends on
# `scp-ffi-common` with `features = ["testing"]`, that crate's `testing` list
# carries `scp-node?/testing`, and every example then compiles with
# `scp-node/testing` ON. Measured: the workspace-wide form exits 0 on the
# `DhtMode::Memory` defect; this loop exits 1.
#
# An example that genuinely needs a feature declares `required-features` in its
# crate manifest, and cargo skips it here. That declaration is the honest way to
# say an example is not a shipped demonstration.
set -euo pipefail

cd "$(dirname "$0")/.."

# Closed by construction: the package list comes from cargo's own metadata, so a
# crate that gains its first example is covered without editing this file.
PKGS="$(
  cargo metadata --no-deps --format-version 1 \
    | jq -r '.packages[] | select(any(.targets[]; .kind[] == "example")) | .name' \
    | sort
)"

if [ -z "$PKGS" ]; then
  echo "FAIL: cargo metadata reported no package owning an example target." >&2
  echo "      This check must not pass vacuously; investigate the metadata query." >&2
  exit 1
fi

echo "Linting examples on shipped (default) features:" $PKGS

status=0
for pkg in $PKGS; do
  echo "── $pkg"
  if ! cargo clippy -p "$pkg" --examples -- -D warnings; then
    echo "FAIL: $pkg has an example that does not build on its default features." >&2
    status=1
  fi
done

if [ "$status" -ne 0 ]; then
  echo >&2
  echo "A shipped example must build without a test-only feature. Either select a" >&2
  echo "production value, or declare 'required-features' for that example in its" >&2
  echo "crate manifest so cargo excludes it from a shipped build." >&2
fi
exit "$status"
