#!/usr/bin/env bash
# uniffi-bindgen.sh — build tools/uniffi-bindgen and run it with this script's arguments.
#
#   scripts/uniffi-bindgen.sh generate --library <cdylib> --language kotlin --out-dir <dir>
#
# tools/uniffi-bindgen/Cargo.toml says why the tool is a workspace of its own. Before it
# builds, this script fails unless every package tools/uniffi-bindgen/Cargo.lock names
# appears in the root Cargo.lock with the same version, source and checksum. The bindings
# carry checksums the library's own uniffi version computed, so a tool built from another
# uniffi version would read the library's metadata under a different contract; and the
# root lock is the one `cargo deny` checks, advisories, licences and sources alike, so no
# crate reaches this build that the root lock's check has not seen. A uniffi bump in the
# root lock fails here until tools/uniffi-bindgen/Cargo.lock follows it.
#
# The tool builds under the dev profile into tools/uniffi-bindgen/target. The
# android-x86_64-testing cargo cache group holds that directory beside `target`
# (`workspaces` in kotlin-android-instrumented of .github/workflows/ci.yml and in
# .github/workflows/cache-warm.yml, whose writer runs the same command).
#
# `generate` must name `--language kotlin` and `--out-dir`. uniffi-bindgen exits 0 and
# writes nothing when the library holds no UniFFI metadata symbols (a stripped
# `.symtab`), so this script deletes `<out-dir>/uniffi/scp/scp.kt` before the tool runs
# and fails unless the tool wrote it again, non-empty. It then prints the file's SHA-256,
# as a `::notice` under GitHub Actions, where the annotations API serves it without a
# token, so two jobs' bindings can be compared byte for byte.
#
# Exit codes: the tool's own when the tool fails; otherwise 1 when an argument check, a
# lock file, the lock check, the build or the output check fails; 0 when all pass.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL_DIR="$REPO_ROOT/tools/uniffi-bindgen"
TOOL_LOCK="$TOOL_DIR/Cargo.lock"
ROOT_LOCK="$REPO_ROOT/Cargo.lock"

fail() {
    echo "uniffi-bindgen.sh: $*" >&2
    exit 1
}

expected=""
if [[ ${1:-} == generate ]]; then
    languages=()
    out_dir=""
    args=("${@:2}")
    i=0
    while ((i < ${#args[@]})); do
        arg="${args[i]}"
        case "$arg" in
            --language | -l) languages+=("${args[i + 1]:-}"); i=$((i + 1)) ;;
            --language=*) languages+=("${arg#*=}") ;;
            --out-dir | -o) out_dir="${args[i + 1]:-}"; i=$((i + 1)) ;;
            --out-dir=*) out_dir="${arg#*=}" ;;
        esac
        i=$((i + 1))
    done
    if [[ ${#languages[@]} -ne 1 || ${languages[0]} != kotlin ]]; then
        fail "generate names languages (${languages[*]:-none}); this script checks only the Kotlin output, so pass exactly --language kotlin"
    fi
    [[ -n $out_dir ]] || fail "generate names no --out-dir, so this script cannot check what the tool wrote"
    expected="$out_dir/uniffi/scp/scp.kt"
fi

[[ -f $TOOL_LOCK ]] || fail "$TOOL_LOCK does not exist"
[[ -f $ROOT_LOCK ]] || fail "$ROOT_LOCK does not exist"

# One `name version source checksum` line per [[package]] entry of a Cargo.lock, with
# `-` for a field the entry does not carry (a path package has no source, a git package
# no checksum).
lock_entries() {
    awk '
        function flush() {
            if (name != "") print name, version, (source == "" ? "-" : source), (checksum == "" ? "-" : checksum)
            name = version = source = checksum = ""
        }
        /^\[/ { flush(); next }
        /^name = "/ { name = $3; gsub(/"/, "", name); next }
        /^version = "/ { version = $3; gsub(/"/, "", version); next }
        /^source = "/ { source = $3; gsub(/"/, "", source); next }
        /^checksum = "/ { checksum = $3; gsub(/"/, "", checksum); next }
        END { flush() }
    ' "$1" | sort -u
}

tool_entries="$(lock_entries "$TOOL_LOCK")"
[[ -n $tool_entries ]] || fail "$TOOL_LOCK names no package"
root_entries="$(lock_entries "$ROOT_LOCK")"
missing="$(comm -23 <(printf '%s\n' "$tool_entries") <(printf '%s\n' "$root_entries"))"
# The tool's own path package is the one entry the root lock cannot hold.
missing="$(printf '%s\n' "$missing" | command grep -vx 'uniffi-bindgen 0\.0\.0 - -' || true)"
if [[ -n $missing ]]; then
    {
        echo "uniffi-bindgen.sh: $TOOL_LOCK names packages the root Cargo.lock does not hold with the same version, source and checksum (name version source checksum):"
        printf '%s\n' "$missing" | sed 's/^/  /'
        echo "Regenerate it from the root lock: cp Cargo.lock tools/uniffi-bindgen/Cargo.lock, then cargo metadata --manifest-path tools/uniffi-bindgen/Cargo.toml --format-version 1 >/dev/null"
    } >&2
    exit 1
fi

if ! cargo build --locked --quiet \
    --manifest-path "$TOOL_DIR/Cargo.toml" \
    --target-dir "$TOOL_DIR/target"; then
    fail "cargo build of $TOOL_DIR failed"
fi

[[ -z $expected ]] || rm -f "$expected"
"$TOOL_DIR/target/debug/uniffi-bindgen" "$@" || exit $?
[[ -z $expected ]] && exit 0

[[ -s $expected ]] || fail "uniffi-bindgen exited 0 and wrote no $expected; does the library hold its UniFFI metadata symbols?"
if command -v sha256sum >/dev/null 2>&1; then
    digest="$(sha256sum "$expected" | cut -d' ' -f1)"
else
    digest="$(shasum -a 256 "$expected" | cut -d' ' -f1)"
fi
if [[ ${GITHUB_ACTIONS:-} == true ]]; then
    echo "::notice title=uniffi-bindgen output::$expected sha256 $digest"
else
    echo "uniffi-bindgen.sh: $expected sha256 $digest"
fi
