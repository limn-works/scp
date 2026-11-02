#!/usr/bin/env bash
# Compiles every example target in the workspace the way scripts/check-examples-compile.sh
# does, one `cargo clippy -p PKG --example NAME` per target, and asserts nothing.
#
# cache-warm.yml runs this to write the `clippy-examples` cache group, which rust-clippy's
# `examples` leg restores before it runs the gate. The gate denies warnings, scans example
# sources and checks the published file set; this script does none of that, because a push
# to `main` runs no gate the merge-queue run already ran on the same tree. Without
# `-- -D warnings` the command compiles the same units: clippy's arguments after `--`
# reach only the workspace members it lints, never a dependency the cache holds.
#
# Check `group coverage` in scripts/check-workflow-compile-steps.py fails when this file
# and the gate stop holding the same compiling cargo commands, so a change to the gate's
# invocation lands here in the same change.
set -euo pipefail

cd "$(dirname "$0")/.."

META="$(cargo metadata --no-deps --format-version 1)"

# package<TAB>target for every example target, in the gate's package and target order.
TARGETS="$(printf '%s' "$META" | jq -r '.packages[] | .name as $p | .targets[] | select(.kind[] == "example") | [$p, .name] | @tsv')"
[ -n "$TARGETS" ] || { echo "FAIL: cargo metadata reported no example target." >&2; exit 1; }

while IFS=$'\t' read -r pkg name; do
  echo "── $pkg::$name"
  cargo clippy -p "$pkg" --example "$name" </dev/null
done <<EOF
$TARGETS
EOF
