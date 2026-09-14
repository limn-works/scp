#!/usr/bin/env bash
#
# Vendored-OpenSSL scope gate.
#
# CRITERION
# ---------
# `openssl-src` — the crate whose build script compiles OpenSSL from source so
# `openssl-sys` links it statically — appears in the shipped dependency graph of
# the PyPI wheel, and appears in the shipped dependency graph of no other artifact
# this repository ships.
#
# WHY EACH HALF IS A SEPARATE FAILURE
# -----------------------------------
# The wheel needs the vendored copy: `pip install` runs no linker and installs onto
# a machine whose OpenSSL this build never saw, so SQLCipher's crypto has to travel
# inside the wheel. `bindings/python/pyproject.toml` asks for it by naming
# `vendored-openssl` in its `[tool.maturin] features` array, which reaches
# `scp-platform/vendored-openssl` and from there adds
# `rusqlite/bundled-sqlcipher-vendored-openssl`. Drop that name and the wheel
# silently reverts to linking whatever libcrypto the build host happened to have,
# so this gate fails when `openssl-src` is absent from the wheel's graph.
#
# Every other shipped artifact must not get it. A statically embedded OpenSSL
# changes patch level only when someone bumps `Cargo.lock`, and nothing in this
# repository reports that copy as stale — `Rust / deny` reads the RustSec database
# over Rust crates, and no job runs an SBOM or container scanner. The `scp-relay`
# and `scp-node` binaries ship in a container whose operator patches OpenSSL by
# upgrading `libssl3` in the runtime layer; `Dockerfile` and
# `templates/personal-relay/README.md` both name that dynamic link as the reason
# they install `libssl3`. Pull request #2119 set the vendored feature in the
# workspace dependency table, which reached both binaries — the `Docker / relay and
# node image` job failed inside `openssl-src`'s build script — and left both
# recipes asserting a linkage the build no longer performed. This gate fails on the
# feature reaching any of the nine non-wheel configurations below, so the next
# workspace-wide edit is reported by name rather than by a Docker build breaking.
#
# WHAT THIS GATE DOES NOT DECIDE
# ------------------------------
# It reads dependency graphs, so it decides which crates a build compiles and never
# which shared library a finished binary loads. `scripts/check-shipped-feature-graph.sh`
# decides the complementary property, that every resolved SCP-crate feature of each
# shipped artifact sits on one permitted-production allowlist.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

VENDOR_CRATE="openssl-src"
PYPROJECT="bindings/python/pyproject.toml"

failures=0

# The nine shipped configurations that must not reach the vendored crate, spelled
# exactly as `scripts/check-shipped-feature-graph.sh` spells its ARTIFACTS entries:
# `<package>|<feature arguments>`, an empty argument string meaning default features.
# The two binaries build from `Dockerfile`; the six bridge rows build from the
# "Build shipped bridge artifacts" step of `.github/workflows/build-matrix.yml` in
# their default configuration and from `release.yml` in their `server` one.
ABSENT_CONFIGURATIONS=(
  "scp-node|"
  "scp-relay|"
  "scp-core|"
  "scp-ffi|"
  "scp-ffi-napi|"
  "scp-ffi-uniffi|"
  "scp-ffi|--no-default-features --features server"
  "scp-ffi-napi|--no-default-features --features server"
  "scp-ffi-uniffi|--no-default-features --features server"
)

# vendor_crate_occurrences <package> <feature-argument-string>
#   Emit the number of times the vendored crate appears in the package's shipped
#   dependency graph. `-e no-dev` drops dev-dependencies, which no shipped artifact
#   compiles; `--target all` resolves every target triple, so a cfg-gated edge that
#   is false on this runner stays visible.
vendor_crate_occurrences() {
  local pkg="$1" feature_args="$2" tree
  # shellcheck disable=SC2086  # feature_args carries several cargo arguments.
  tree="$(cargo tree -p "$pkg" $feature_args -e no-dev --target all --prefix none --format '{p}')"
  printf '%s\n' "$tree" | grep -cE "^${VENDOR_CRATE} v" || true
}

# wheel_feature_list
#   Emit the `[tool.maturin] features` array of the Python binding's project file
#   as one comma-joined cargo `--features` value. FAILS when the table carries no
#   `features` array, carries more than one, or carries a key this reader does not
#   model, because a configuration this reader cannot reproduce must not read as a
#   configuration it happened to guess.
wheel_feature_list() {
  local table lines
  table="$(awk '
    /^[[:space:]]*\[/ {
      in_table = ($0 ~ /^[[:space:]]*\[[[:space:]]*tool[[:space:]]*\.[[:space:]]*maturin[[:space:]]*\][[:space:]]*(#.*)?$/)
      next
    }
    in_table { print }
  ' "$PYPROJECT")"
  if printf '%s\n' "$table" | grep -qE '^[[:space:]]*(all-features|no-default-features)[[:space:]]*='; then
    echo "$PYPROJECT selects the wheel's cargo features with a key this reader does not model" >&2
    return 1
  fi
  lines="$(printf '%s\n' "$table" | grep -E '^[[:space:]]*features[[:space:]]*=' || true)"
  if [[ "$(printf '%s\n' "$lines" | grep -cE '.' || true)" != "1" ]]; then
    echo "$PYPROJECT does not carry exactly one [tool.maturin] features array" >&2
    return 1
  fi
  printf '%s\n' "$lines" | grep -oE '"[^"]+"' | tr -d '"' | paste -sd, -
}

echo "==> vendored-OpenSSL scope: $VENDOR_CRATE reaches the PyPI wheel and nothing else this repository ships"
echo

wheel_features="$(wheel_feature_list)" || {
  echo "FAIL — the wheel's cargo feature selection could not be read, so its graph was never resolved."
  exit 1
}
echo "--> wheel configuration read from $PYPROJECT: scp-ffi --features $wheel_features"

wheel_count="$(vendor_crate_occurrences scp-ffi "--features $wheel_features")"
if [[ "$wheel_count" -gt 0 ]]; then
  echo "    ok   — the wheel's graph reaches $VENDOR_CRATE, so the wheel carries its own OpenSSL"
else
  echo "    FAIL — the wheel's graph reaches no $VENDOR_CRATE."
  echo "           A wheel built from this tree links whatever libcrypto the build host"
  echo "           supplies, and installs onto machines that have a different one."
  echo "           Restore 'vendored-openssl' to the [tool.maturin] features array in"
  echo "           $PYPROJECT."
  failures=$((failures + 1))
fi
echo

echo "--> the nine shipped configurations that must reach no $VENDOR_CRATE"
for configuration in "${ABSENT_CONFIGURATIONS[@]}"; do
  pkg="${configuration%%|*}"
  feature_args="${configuration#*|}"
  count="$(vendor_crate_occurrences "$pkg" "$feature_args")"
  if [[ "$count" -eq 0 ]]; then
    echo "    ok   — $pkg [${feature_args:-default features}]"
  else
    echo "    FAIL — $pkg [${feature_args:-default features}] reaches $VENDOR_CRATE."
    echo "           This artifact would embed a statically compiled OpenSSL whose patch"
    echo "           level only a Cargo.lock bump changes, while Dockerfile and"
    echo "           templates/personal-relay/README.md tell an operator that upgrading"
    echo "           libssl3 patches it. Ask for the vendored build through"
    echo "           scp-platform/vendored-openssl on the one artifact that needs it,"
    echo "           never through the rusqlite feature list in a workspace or crate"
    echo "           dependency table."
    failures=$((failures + 1))
  fi
done
echo

if [[ "$failures" -eq 0 ]]; then
  echo "PASS — $VENDOR_CRATE reaches the PyPI wheel and reaches no other shipped artifact."
  exit 0
fi
echo "FAIL — $failures configuration(s) resolved the wrong way."
exit 1
