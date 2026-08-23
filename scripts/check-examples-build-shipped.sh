#!/usr/bin/env bash
# Two assertions about example targets:
#
#   1. Every example target in the workspace compiles, lint-clean.
#   2. Every published `examples/*.rs` file IS the source of an example target.
#
# Assertion 2 joins on PATH, never on target name. A `[[example]] path = …` key
# can bind the target name `website` to `examples/decoy/website.rs` while
# `examples/website.rs` still ships with no target of its own; a name join sees
# `website` on both sides, reports no orphan, compiles the decoy, and prints
# `── scp-node::website` for a file it never opened. Measured: exit 0 with
# `DhtMode::Memory` sitting in the published file.
#
# WHAT THIS PROVES AND THE WHOLE OF IT. Assertion 1 compiles each example under
# the feature closure cargo gives a dev target, which is NOT the crate's default
# feature set and is NOT what a consumer of the published crate gets. Measured:
# `cargo clippy -p scp-runtime --example identity` builds with
# `--cfg feature="testing"` and `--cfg feature="allow_unencrypted_storage"`, while
# `scp-runtime` declares no `default` key at all. Cargo unifies a crate's
# dev-dependency features into its dev targets and no invocation switches that
# off, so per-package scope narrows the closure without emptying it. Cargo also
# strips path-only dev-dependencies from a published manifest, so an example
# importing one compiles here and cannot compile for a consumer —
# `crates/scp-transport/examples/relay-chat.rs` imports `scp_core` that way.
#
# Therefore this check CANNOT prove that an example compiles for someone who
# installs the crate, and CANNOT prove that an example avoids a test-only
# construct. Do not write a comment, a commit message, or a CI step description
# claiming either. Four earlier versions of this header claimed one or the other,
# and each time a reviewer had to measure to find out.
#
# WHAT IT DOES CATCH, measured:
#   - `crates/scp-node/examples/website.rs` naming `DhtMode::Memory`, because
#     scp-node's OWN `testing` feature is genuinely off in its dev closure. E0599.
#   - A published `examples/*.rs` that is no target's source, which
#     `autoexamples = false` and a redirected `path` key both produce.
#
# WHY ASSERTION 1 ITERATES TARGETS. `exclude = ["examples/*"]` empties the
# published file set while the target still exists; iterating published files
# would drop it from coverage in silence. Targets are what gets compiled.
#
# WHY PACKAGE SCOPE IS LOAD-BEARING. `cargo clippy --workspace --examples`
# unifies dev-dependency features across EVERY member: `crates/scp-ffi`
# dev-depends on `scp-ffi-common` with `features = ["testing"]`, whose `testing`
# list carries `scp-node?/testing`. Measured: the workspace-wide form exits 0 on
# the `DhtMode::Memory` defect; this loop exits 1.
#
# See .docs/lessons/shipped-targets-need-a-default-feature-build.md.
set -euo pipefail

cd "$(dirname "$0")/.."

status=0
checked=0

META="$(cargo metadata --no-deps --format-version 1)"

# name<TAB>manifest_dir<TAB>… for every workspace package.
PKG_TSV="$(printf '%s' "$META" | jq -r '.packages[] | [.name, (.manifest_path | sub("/Cargo.toml$"; ""))] | @tsv')"
[ -n "$PKG_TSV" ] || { echo "FAIL: cargo metadata reported no workspace package." >&2; exit 1; }

while IFS=$'\t' read -r pkg pkgdir; do
  [ -n "$pkg" ] || continue

  # target_name<TAB>src_path_relative_to_package_root
  TGT_TSV="$(printf '%s' "$META" | jq -r --arg p "$pkg" --arg d "$pkgdir/" '
      .packages[] | select(.name == $p)
      | .targets[] | select(.kind[] == "example")
      | [.name, (.src_path | ltrimstr($d))]
      | @tsv
    ')"

  # Never swallow this exit code: `cargo package --list` fails (101) on a manifest
  # error such as a `readme` naming a missing file, and treating that as "no
  # published examples" would drop the crate from assertion 2 in silence.
  if ! RAW="$(cargo package --list -p "$pkg" --allow-dirty 2>&1)"; then
    if [ -n "$TGT_TSV" ]; then
      echo "FAIL: 'cargo package --list -p $pkg' failed, so its published file set is unknown." >&2
      printf '%s\n' "$RAW" >&2
      status=1
    fi
  else
    # Every target's source path, one per line, for the path join below.
    SRCS="$(printf '%s' "$TGT_TSV" | cut -f2 | sort -u)"
    # Only top-level `examples/*.rs` is auto-discovered; a file in a subdirectory
    # (examples/support/mod.rs) is a helper module, not an expected target source.
    while IFS= read -r file; do
      [ -n "$file" ] || continue
      printf '%s\n' "$SRCS" | grep -qxF -- "$file" && continue
      echo "FAIL: $pkg publishes '$file', which is no example target's source." >&2
      echo "      Nothing compiles it, in CI or for a consumer. Give it an [[example]]" >&2
      echo "      entry, drop 'autoexamples = false', or stop publishing the file." >&2
      status=1
    done <<EOF
$(printf '%s\n' "$RAW" | grep -E '^examples/[^/]+\.rs$' || true)
EOF
  fi

  [ -n "$TGT_TSV" ] || continue
  while IFS=$'\t' read -r name src; do
    [ -n "$name" ] || continue
    checked=$((checked + 1))
    echo "── $pkg::$name  ($src)"
    if ! cargo clippy -p "$pkg" --example "$name" -- -D warnings; then
      echo "FAIL: $pkg example '$name' does not compile." >&2
      status=1
    fi
  done <<EOF
$TGT_TSV
EOF
done <<EOF
$PKG_TSV
EOF

[ "$checked" -gt 0 ] || { echo "FAIL: no example target was checked; this must not pass vacuously." >&2; exit 1; }

if [ "$status" -ne 0 ]; then
  echo >&2
  echo "Fix the example, or stop publishing a file no target compiles." >&2
else
  echo "OK: $checked example target(s) compile; every published examples/*.rs is a target source."
fi
exit "$status"
