#!/usr/bin/env bash
# Every `examples/*.rs` file a crate publishes must be a cargo example target
# that compiles, lint-clean, on that crate's default features.
#
# WHAT THIS PROVES, and the whole of it: a file that ships to crates.io under
# `examples/` compiles for someone who installs the published crate. Nothing more.
#
# WHAT IT EXPLICITLY DOES NOT PROVE: that an example avoids a test-only
# construct. It cannot. Cargo builds an example as a dev target and gives it the
# crate's dev-dependencies, and no cargo invocation switches that off. Measured:
# `crates/scp-node/Cargo.toml` dev-depends on `scp-dht` and `scp-platform` with
# `features = ["testing"]`, so an example naming `scp_dht::InMemoryDhtClient` or
# `scp_platform::testing::InMemoryKeyCustody` compiles and this check passes it.
# `crates/scp-transport` reaches the same types through its `scp-testing`
# dev-dependency, whose NORMAL deps carry both with `testing` on. Do not write a
# comment here, or a commit message, claiming this check keeps nullifiers out of
# examples. It does not, and saying so would let the next author stop checking.
#
# WHY THE FILE LIST COMES FROM `cargo package --list`, NOT `cargo metadata`.
# Metadata reports example TARGETS. `autoexamples = false` in a crate manifest
# suppresses target auto-discovery while `cargo package` still ships the file, so
# a target-sourced list silently drops it and the check passes over a file no job
# ever compiles. Reading the published file set closes that: a shipped
# `examples/NAME.rs` with no corresponding target is itself a failure here.
#
# WHY PACKAGE SCOPE IS LOAD-BEARING. A future editor MUST NOT collapse this into
# `cargo clippy --workspace --examples`. A workspace-wide selection unifies
# dev-dependency features across ALL members: `crates/scp-ffi` dev-depends on
# `scp-ffi-common` with `features = ["testing"]`, that crate's `testing` list
# carries `scp-node?/testing`, and every example then compiles with
# `scp-node/testing` ON. Measured: the workspace-wide form exits 0 on an example
# selecting `DhtMode::Memory`; this loop exits 1.
#
# Compiling is also not running. `crates/scp-node/examples/website.rs` passes here
# and still exits 1 on a machine with no existing identity, because creating one
# needs a pre-rotation custody backend only a `testing` build has.
set -euo pipefail

cd "$(dirname "$0")/.."

status=0
checked=0

# Closed by construction: every workspace member is considered, so a crate that
# gains its first example is covered without editing this file.
PKGS="$(cargo metadata --no-deps --format-version 1 | jq -r '.packages[].name' | sort)"

if [ -z "$PKGS" ]; then
  echo "FAIL: cargo metadata reported no workspace package." >&2
  exit 1
fi

for pkg in $PKGS; do
  # Files this crate actually publishes, restricted to top-level examples/*.rs.
  # A file in an examples/ SUBDIRECTORY (e.g. examples/support/mod.rs) is a helper
  # module, not an auto-discovered target, so it is not expected to be one.
  FILES="$(
    cargo package --list -p "$pkg" --allow-dirty 2>/dev/null \
      | grep -E '^examples/[^/]+\.rs$' \
      | sed -e 's|^examples/||' -e 's|\.rs$||' \
      | sort || true
  )"
  [ -n "$FILES" ] || continue

  # Example targets cargo knows about for this crate.
  TARGETS="$(
    cargo metadata --no-deps --format-version 1 \
      | jq -r --arg p "$pkg" '
          .packages[] | select(.name == $p)
          | .targets[] | select(.kind[] == "example") | .name
        ' \
      | sort
  )"

  # A published example file with no target is compiled by nothing, ever.
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
