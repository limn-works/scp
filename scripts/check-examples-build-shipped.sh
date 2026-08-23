#!/usr/bin/env bash
# Every example target ships inside its crate's published archive
# (`cargo package --list -p scp-node` lists `examples/website.rs`), so a shipped
# example must build without a feature that only a test harness turns on.
#
# WHAT THIS CHECK PROVES
#   1. Every example target that does NOT declare `required-features` compiles,
#      lint-clean, under its own crate's default features.
#   2. The set of such targets never shrinks. `scripts/examples-shipped-baseline.txt`
#      pins it; a missing entry fails the check.
#
# WHY (2) EXISTS. Without it the check is defeated by a three-line manifest edit:
# declaring `required-features = ["testing"]` on an example makes cargo skip the
# target and exit 0, so the example returns to naming a test-only construct with
# every job green. The baseline turns that edit into a visible, reviewed diff, the
# way this repository's other ratchets do.
#
# WHY TARGETS ARE NAMED INDIVIDUALLY. `cargo clippy -p P --examples` silently
# no-ops when every example in P is feature-gated ("target filter 'examples'
# specified, but no targets matched" is a warning cargo emits itself, which
# `-D warnings` does not promote, and the exit code is 0). Naming a target whose
# `required-features` are unmet is a hard error instead, so nothing is skipped
# without the check noticing.
#
# WHY PACKAGE SCOPE IS LOAD-BEARING. A future editor MUST NOT collapse this into
# `cargo clippy --workspace --examples`. A workspace-wide selection unifies
# dev-dependency features across ALL members: `crates/scp-ffi` dev-depends on
# `scp-ffi-common` with `features = ["testing"]`, that crate's `testing` list
# carries `scp-node?/testing`, and every example then compiles with
# `scp-node/testing` ON. Measured: the workspace-wide form exits 0 on the
# `DhtMode::Memory` defect; this loop exits 1.
#
# WHAT THIS CHECK DOES NOT PROVE, because cargo gives an example its own crate's
# dev-dependencies and no invocation switches that off:
#   (a) A construct behind a DEPENDENCY crate's `testing`, when the linted crate
#       dev-depends on it with that feature. `crates/scp-node/Cargo.toml` does
#       exactly that for `scp-platform` and `scp-dht`, so `scp_platform::testing`
#       stays reachable from a scp-node example.
#   (b) A construct behind the LINTED crate's own `testing`, when a dev-dependency
#       back-edge re-enables it. `scp-runtime` and `scp-transport` dev-depend on
#       `scp-testing`, whose NORMAL `scp-core{testing}` edge resolves
#       `scp-runtime/testing` ON.
#   (c) That an example RUNS. Compiling is what this can measure; running is a
#       separate property. `crates/scp-node/examples/website.rs` compiles here and
#       still fails at runtime on a fresh storage directory, because
#       `IdentitySource::Persisted` needs a pre-rotation backend a shipped build
#       does not have.
# Do not write a comment here claiming otherwise.
set -euo pipefail

cd "$(dirname "$0")/.."

BASELINE="scripts/examples-shipped-baseline.txt"

# Closed by construction: the target list comes from cargo's own metadata, so a
# crate that gains an ungated example is covered without editing this file.
CURRENT="$(
  cargo metadata --no-deps --format-version 1 \
    | jq -r '
        .packages[]
        | .name as $p
        | .targets[]
        | select(.kind[] == "example")
        | select(((.["required-features"]) // []) | length == 0)
        | "\($p)::\(.name)"
      ' \
    | sort
)"

if [ -z "$CURRENT" ]; then
  echo "FAIL: cargo metadata reported no ungated example target." >&2
  echo "      This check must not pass vacuously; investigate the metadata query." >&2
  exit 1
fi

if [ ! -f "$BASELINE" ]; then
  echo "FAIL: $BASELINE is missing. It pins the set of examples that must build" >&2
  echo "      on shipped features; without it a manifest edit silently drops one." >&2
  exit 1
fi

# Ratchet: every baseline entry must still be an ungated example target.
MISSING="$(comm -23 <(grep -v '^#' "$BASELINE" | grep -v '^$' | sort) <(printf '%s\n' "$CURRENT") || true)"
if [ -n "$MISSING" ]; then
  echo "FAIL: these examples no longer build on shipped features:" >&2
  printf '  %s\n' $MISSING >&2
  echo >&2
  echo "An example leaves this set when it is deleted, renamed, or given" >&2
  echo "'required-features'. Declaring 'required-features' removes the example from" >&2
  echo "this check but NOT from the published crate, so it is not a way to ship an" >&2
  echo "example that names a test-only construct. Fix the example, or update" >&2
  echo "$BASELINE in the same commit so the change is reviewed." >&2
  exit 1
fi

echo "Linting examples on shipped (default) features:"
printf '  %s\n' $CURRENT

status=0
for target in $CURRENT; do
  pkg="${target%%::*}"
  name="${target##*::}"
  if ! cargo clippy -p "$pkg" --example "$name" -- -D warnings; then
    echo "FAIL: $pkg example '$name' does not build on its default features." >&2
    status=1
  fi
done

if [ "$status" -ne 0 ]; then
  echo >&2
  echo "A shipped example must build without a test-only feature. Select a" >&2
  echo "production value rather than a 'testing'-gated one." >&2
fi
exit "$status"
