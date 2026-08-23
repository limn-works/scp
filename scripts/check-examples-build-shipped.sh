#!/usr/bin/env bash
# Every example target ships inside its crate's published archive
# (`cargo package --list -p scp-node` lists `examples/website.rs`), so a shipped
# example MUST compile on the feature set that ships.
#
# Package scope is load-bearing, and a future editor MUST NOT collapse this loop
# into `cargo clippy --workspace --examples`. `--examples` selects dev units, and
# a workspace-wide selection then unifies dev-dependency features across all
# members: `crates/scp-ffi/Cargo.toml` dev-depends on `scp-ffi-common` with
# `features = ["testing"]`, and that crate's `testing` list carries
# `scp-node?/testing`, so the weak edge fires and every example compiles with
# `scp-node/testing` ON. The workspace-wide form therefore accepts exactly the
# defect this check exists to reject: it exits 0 on an example selecting
# `DhtMode::Memory`. Linting one package at a time resolves that package's own
# features and nothing else.
#
# An example that genuinely needs a feature declares `required-features` in its
# crate manifest, and cargo skips it here. That declaration is the honest way to
# say an example is not a shipped demonstration; reaching a `testing`-gated
# construct without declaring it is not.
#
# What this check does NOT cover: cargo gives an example its own crate's
# dev-dependencies, and no invocation can switch that off, so an example that
# reaches a `testing` feature its OWN crate dev-depends on still compiles here.
# This check rejects an example that reaches a feature no shipped build of its
# crate enables. It does not prove an example compiles for someone who copies it
# out and depends on the published crate.
set -euo pipefail

cd "$(dirname "$0")/.."

# Closed by construction: the package list comes from cargo's own metadata, so a
# crate that gains its first example is covered without editing this file.
# `mapfile` needs bash 4; macOS ships bash 3.2, so read the list portably.
PKG_LIST="$(mktemp)"
trap 'rm -f "$PKG_LIST"' EXIT
cargo metadata --no-deps --format-version 1 | python3.12 -c '
import json, sys
meta = json.load(sys.stdin)
for pkg in sorted(p["name"] for p in meta["packages"]
                  if any("example" in t["kind"] for t in p["targets"])):
    print(pkg)
' > "$PKG_LIST"

PKGS=()
while IFS= read -r line; do
  [ -n "$line" ] && PKGS+=("$line")
done < "$PKG_LIST"

if [ "${#PKGS[@]}" -eq 0 ]; then
  echo "FAIL: cargo metadata reported no package owning an example target." >&2
  echo "      This check cannot pass vacuously; investigate the metadata query." >&2
  exit 1
fi

echo "Linting examples on shipped (default) features for ${#PKGS[@]} package(s): ${PKGS[*]}"

status=0
for pkg in "${PKGS[@]}"; do
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
