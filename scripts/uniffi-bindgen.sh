#!/usr/bin/env bash
# uniffi-bindgen.sh — build tools/uniffi-bindgen and run it with this script's arguments.
#
#   scripts/uniffi-bindgen.sh generate --library <cdylib> --language kotlin --out-dir <dir>
#
# tools/uniffi-bindgen/Cargo.toml says why the tool is a workspace of its own. Before it
# builds, this script fails unless every package tools/uniffi-bindgen/Cargo.lock names
# appears at the same version in the root Cargo.lock. The bindings carry checksums the
# library's own uniffi version computed, so a tool built from another uniffi version
# would read the library's metadata under a different contract; and the root lock is the
# one `cargo deny` checks, so no crate version reaches this build unchecked. A uniffi
# bump in the root lock fails here until tools/uniffi-bindgen/Cargo.lock follows it.
#
# The tool builds under the dev profile into tools/uniffi-bindgen/target, which no cargo
# cache group holds (scripts/check-workflow-compile-steps.py lists this script in
# SCRIPTS_COMPILING_ELSEWHERE).
#
# Exit codes: the tool's own, or 1 when the lock check or the build fails.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL_LOCK="$REPO_ROOT/tools/uniffi-bindgen/Cargo.lock"
ROOT_LOCK="$REPO_ROOT/Cargo.lock"

# One `name version` line per [[package]] entry of a Cargo.lock.
lock_packages() {
    awk '
        /^\[\[package\]\]/ { name = ""; next }
        /^name = "/ { name = $3; gsub(/"/, "", name); next }
        /^version = "/ && name != "" { version = $3; gsub(/"/, "", version); print name, version; name = "" }
    ' "$1" | sort -u
}

tool_packages="$(lock_packages "$TOOL_LOCK")"
if [[ -z "$tool_packages" ]]; then
    echo "uniffi-bindgen.sh: $TOOL_LOCK names no package" >&2
    exit 1
fi
missing="$(comm -23 <(printf '%s\n' "$tool_packages") <(lock_packages "$ROOT_LOCK" | command grep -v '^$'))"
# The tool's own package is the one entry the root lock cannot hold.
missing="$(printf '%s\n' "$missing" | command grep -v '^uniffi-bindgen 0\.0\.0$' || true)"
if [[ -n "$missing" ]]; then
    echo "uniffi-bindgen.sh: $TOOL_LOCK names packages the root Cargo.lock does not hold at the same version:" >&2
    printf '%s\n' "$missing" | sed 's/^/  /' >&2
    echo "Regenerate it from the root lock: cp Cargo.lock tools/uniffi-bindgen/Cargo.lock, then cargo metadata --manifest-path tools/uniffi-bindgen/Cargo.toml --format-version 1 >/dev/null" >&2
    exit 1
fi

cargo build --locked --quiet \
    --manifest-path "$REPO_ROOT/tools/uniffi-bindgen/Cargo.toml" \
    --target-dir "$REPO_ROOT/tools/uniffi-bindgen/target"
exec "$REPO_ROOT/tools/uniffi-bindgen/target/debug/uniffi-bindgen" "$@"
