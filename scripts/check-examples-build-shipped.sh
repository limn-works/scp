#!/usr/bin/env bash
# Every `examples/*.rs` file a crate PUBLISHES must be a cargo example target that
# compiles, lint-clean, on that crate's default features.
#
# WHAT THIS PROVES, and the whole of it: a file that ships to crates.io under
# `examples/` compiles for someone who installs the published crate.
#
# WHAT IT EXPLICITLY DOES NOT PROVE: that an example avoids a test-only construct.
# It cannot. Cargo builds an example as a dev target and hands it the crate's
# dev-dependencies, and no cargo invocation switches that off, so an example
# naming `scp_dht::InMemoryDhtClient` compiles and passes here. Do not write a
# comment, or a commit message, claiming this check keeps nullifiers out of
# examples. It does not, and saying so would let the next author stop checking.
#
# Two mechanics are load-bearing. Do not simplify either away.
#   1. The file list comes from `cargo package --list`, not `cargo metadata`.
#      Metadata reports TARGETS, and `autoexamples = false` suppresses a target
#      while `cargo package` still ships the file. A published `examples/NAME.rs`
#      with no matching target is a failure here, because nothing compiles it.
#   2. Each package is linted on its own. `cargo clippy --workspace --examples`
#      unifies dev-dependency features across every member and turns
#      `scp-node/testing` ON, which makes the check inert.
#
# Compiling is also not running: `crates/scp-node/examples/website.rs` passes here
# and still exits 1 on a machine with no existing identity.
#
# See .docs/lessons/shipped-targets-need-a-default-feature-build.md for the
# measurements behind each claim above.
set -euo pipefail

cd "$(dirname "$0")/.."

status=0
checked=0

META="$(cargo metadata --no-deps --format-version 1)"
PKGS="$(printf '%s' "$META" | jq -r '.packages[].name' | sort)"

if [ -z "$PKGS" ]; then
  echo "FAIL: cargo metadata reported no workspace package." >&2
  exit 1
fi

for pkg in $PKGS; do
  # Never swallow this exit code. `cargo package --list` fails (101) on a manifest
  # error such as a `readme` pointing at a missing file, and treating that as
  # "this crate publishes no examples" would drop the crate out of the check in
  # silence -- the same invisible-gap failure the file-set sourcing exists to stop.
  if ! RAW="$(cargo package --list -p "$pkg" --allow-dirty 2>&1)"; then
    echo "FAIL: 'cargo package --list -p $pkg' failed, so its examples went unchecked." >&2
    printf '%s\n' "$RAW" >&2
    status=1
    continue
  fi

  # Only top-level `examples/*.rs` files are auto-discovered as targets; a file in
  # an examples/ subdirectory (e.g. examples/support/mod.rs) is a helper module.
  FILES="$(printf '%s\n' "$RAW" \
    | grep -E '^examples/[^/]+\.rs$' \
    | sed -e 's|^examples/||' -e 's|\.rs$||' \
    | sort || true)"
  [ -n "$FILES" ] || continue

  TARGETS="$(printf '%s' "$META" | jq -r --arg p "$pkg" '
      .packages[] | select(.name == $p)
      | .targets[] | select(.kind[] == "example") | .name
    ' | sort)"

  ORPHANS="$(comm -23 <(printf '%s\n' "$FILES") <(printf '%s\n' "$TARGETS") || true)"
  if [ -n "$ORPHANS" ]; then
    echo "FAIL: $pkg publishes these examples/*.rs files with no cargo example target:" >&2
    printf '  %s\n' $ORPHANS >&2
    echo "      Nothing compiles them, in CI or for a consumer. Remove 'autoexamples = false'," >&2
    echo "      add an explicit [[example]] entry, or stop publishing the file." >&2
    status=1
  fi

  for name in $FILES; do
    printf '%s\n' "$TARGETS" | grep -qx -- "$name" || continue
    checked=$((checked + 1))
    echo "── $pkg::$name"
    if ! cargo clippy -p "$pkg" --example "$name" -- -D warnings; then
      echo "FAIL: $pkg example '$name' does not build on its default features." >&2
      status=1
    fi
  done
done

if [ "$checked" -eq 0 ]; then
  echo "FAIL: no published example was checked. This check must not pass vacuously." >&2
  exit 1
fi

if [ "$status" -ne 0 ]; then
  echo >&2
  echo "A published example must build on its crate's default features, because that" >&2
  echo "is what someone who installs the crate has. Select a production construct" >&2
  echo "rather than a 'testing'-gated one." >&2
else
  echo "OK: $checked published example(s) build on shipped features."
fi
exit "$status"
