#!/usr/bin/env bash
# Two assertions about example targets:
#
#   1. Every example target in the workspace compiles, lint-clean.
#   2. Every published `examples/*.rs` file IS the source of an example target.
#
# Assertion 2 joins on PATH, never on target name. A `[[example]] path = …` key can
# bind the target name `website` to `examples/decoy/website.rs` while
# `examples/website.rs` still ships with no target of its own. A join on name then
# matches `website` against `website` and finds no orphan. The check compiles the
# decoy and prints `── scp-node::website` for a file it never opened. Measured: exit
# 0 with `DhtMode::Memory` sitting in the published file.
#
# WHAT THIS PROVES AND THE WHOLE OF IT. Assertion 1 compiles each example under
# the feature closure cargo gives a dev target, which is NOT the crate's default
# feature set and is NOT what a consumer of the published crate gets. Measured:
# `cargo clippy -p scp-runtime --example identity` builds with
# `--cfg feature="testing"` and `--cfg feature="allow_unencrypted_storage"`, while
# `scp-runtime` declares no `default` key at all. Cargo unifies a crate's
# dev-dependency features into its dev targets and no invocation switches that
# off, so per-package scope narrows the closure without emptying it. Cargo also
# strips path-only DEV-dependencies from a published manifest, and with them the
# feature activations they carried, so an example relying on one compiles here and
# not for a consumer. `crates/scp-runtime/examples/identity.rs` is the live case:
# `scp-dht` and `scp-platform` survive publication as normal dependencies, but the
# `testing` feature that produces `InMemoryDhtClient` and `scp_platform::testing`
# comes only from scp-runtime's stripped dev-dependency edges.
#
# Therefore this check CANNOT prove that an example compiles for someone who
# installs the crate, and CANNOT prove that an example avoids a test-only
# construct. Do not write a comment, a commit message, or a CI step description
# claiming either. Four earlier versions of this header claimed one or the other,
# and each time a reviewer had to measure the rustc command line to establish that
# the claim was false.
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
# TWO RESIDUAL LIMITS, both structural, neither worth another mechanism:
#   - A target whose body sits behind `#[cfg(...)]` is counted and compiles to
#     nothing. `checked` counts targets, not lines, so coverage is an upper bound.
#   - Every remaining bypass needs write access to the crate under test. That is
#     the criterion, and it is wider than "edits the manifest": `crates/NAME/build.rs`
#     needs no manifest key at all, and a build script that prints
#     `cargo::rustc-cfg=feature="testing"` makes `DhtMode::Memory` exist for every
#     target of the package. `.cargo/config.toml` rustflags is the same class.
#     (A later attempt to reproduce that build script made the gate exit 1 instead,
#     because the injected cfg desynchronized the lib from its dependency features.
#     The criterion does not rest on the exit code either way: a writer of the crate
#     controls what its targets compile against.) Defending a gate
#     against a writer of its own subject is unbounded, so review covers it; the
#     enforcement-file hook deliberately protects this script and not the crates.
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
    # Unconditional. Gating this on the package having targets inverts it: an
    # `autoexamples = false` crate has none, which is exactly the state where a
    # published example file cannot be seen, so silence there is the failure mode
    # this branch exists to remove.
    echo "FAIL: 'cargo package --list -p $pkg' failed, so its published file set is unknown." >&2
    printf '%s\n' "$RAW" >&2
    status=1
  else
    # Every target's source path, one per line, for the path join below.
    SRCS="$(printf '%s' "$TGT_TSV" | cut -f2 | sort -u)"
    # Cargo auto-discovers BOTH `examples/NAME.rs` and `examples/NAME/main.rs`.
    # Measured: moving website.rs to examples/website/main.rs keeps the target and
    # keeps the file published, so a pattern matching only the flat form is blind to
    # a layout that needs no manifest edit at all. Any other file under examples/
    # (examples/support/mod.rs) is a helper module and is not expected to be a target.
    while IFS= read -r file; do
      [ -n "$file" ] || continue
      printf '%s\n' "$SRCS" | grep -qxF -- "$file" && continue
      echo "FAIL: $pkg publishes '$file', which is no example target's source." >&2
      echo "      Nothing compiles it, in CI or for a consumer. Give it an [[example]]" >&2
      echo "      entry, drop 'autoexamples = false', or stop publishing the file." >&2
      status=1
    done <<EOF
$(printf '%s\n' "$RAW" | grep -E '^examples/([^/]+\.rs|[^/]+/main\.rs)$' || true)
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
