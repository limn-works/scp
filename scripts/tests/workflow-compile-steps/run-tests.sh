#!/usr/bin/env bash
# run-tests.sh — exercise scripts/check-workflow-compile-steps.py against canned
# workflow directories.
#
# WHAT THIS TESTS.
#   * Check 1 (rust-cache groups) fails a step that names no `shared-key`, a step that
#     names `key` beside `shared-key`, a step that names no `save-if`, a group whose
#     every member has `save-if: false`, a group with two writers — counted across two
#     workflow files, because the cache cap is per repository — and a writer whose
#     `save-if` does not name `refs/heads/main`. It passes a group with one writer on
#     main and readers at `false`, including a writer whose `save-if` is a matrix
#     expression.
#   * Check 2 (uniffi-bindgen steps) fails a `cargo run` with no profile or target flags
#     whose `--library` sits under `target/<triple>/release` (the second-compile shape
#     from build-xcframework.sh and the Swift job of build-matrix.yml), one whose
#     `--library` sits under `target/release` (the Android job's path that no step
#     produced), and one that passes no `--library`. It passes a `cargo run` whose flags
#     name the library's directory, with `--release --target`, with `--profile release`
#     behind a `+toolchain` selector, and with a bare `cargo run` reading `target/debug`,
#     and it joins backslash-continued lines before reading a command.
#
# Each case is a directory under ./fixtures/ that the check reads through
# `--workflows-dir`. Exit 0 when every case matches its expectation, 1 otherwise.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
CHECK="$REPO_ROOT/scripts/check-workflow-compile-steps.py"
FIXTURES_DIR="$SCRIPT_DIR/fixtures"

PYTHON="python3"
command -v python3.12 >/dev/null 2>&1 && PYTHON="python3.12"

if [[ ! -f "$CHECK" ]]; then
    echo "ERROR: $CHECK does not exist" >&2
    exit 1
fi

# Fixture definitions — the three arrays stay in sync by position.
FIXTURES=(
    "good-groups-and-bindgen"
    "bad-cache-no-shared-key"
    "bad-cache-key-beside-shared-key"
    "bad-cache-no-save-if"
    "bad-cache-no-writer"
    "bad-cache-two-writers-across-files"
    "bad-cache-writer-off-main"
    "bad-bindgen-second-compile"
    "bad-bindgen-path-nothing-wrote"
    "bad-bindgen-no-library"
)
EXPECTED_EXITS=(
    "0"
    "1"
    "1"
    "1"
    "1"
    "1"
    "1"
    "1"
    "1"
    "1"
)
EXPECTED_SUBSTRINGS=(
    "OK: 4 rust-cache step(s) in 2 group(s)"
    "names no \`shared-key\`"
    "names both \`key\` and \`shared-key\`"
    "names no \`save-if\`"
    "has no step whose save-if is not false"
    "has 2 steps whose save-if is not false"
    "does not name refs/heads/main"
    "writes target/debug/ and the \`--library\` it reads is target/aarch64-apple-darwin/release/libscp_ffi_uniffi.dylib"
    "writes target/debug/ and the \`--library\` it reads is target/release/libscp_ffi_uniffi.so"
    "passes no \`--library\`"
)

passed=0
failed=0

for i in "${!FIXTURES[@]}"; do
    name="${FIXTURES[$i]}"
    expected_exit="${EXPECTED_EXITS[$i]}"
    expected_substr="${EXPECTED_SUBSTRINGS[$i]}"
    fixture_root="$FIXTURES_DIR/$name"

    if [[ ! -d "$fixture_root" ]]; then
        echo "FAIL [$name]: fixture directory $fixture_root does not exist" >&2
        failed=$((failed + 1))
        continue
    fi

    set +e
    output="$("$PYTHON" "$CHECK" --workflows-dir "$fixture_root" 2>&1)"
    actual_exit=$?
    set -e

    if [[ "$actual_exit" != "$expected_exit" ]]; then
        echo "FAIL [$name]: exit $actual_exit, expected $expected_exit" >&2
        echo "$output" >&2
        failed=$((failed + 1))
        continue
    fi
    if [[ "$output" != *"$expected_substr"* ]]; then
        echo "FAIL [$name]: output lacks '$expected_substr'" >&2
        echo "$output" >&2
        failed=$((failed + 1))
        continue
    fi
    echo "PASS [$name]"
    passed=$((passed + 1))
done

# The good fixture reports every good shape it holds; a case that passed for the wrong
# reason (a parser that saw no step at all) would print zero counts, so hold the
# bindgen count too.
set +e
good_output="$("$PYTHON" "$CHECK" --workflows-dir "$FIXTURES_DIR/good-groups-and-bindgen" 2>&1)"
set -e
if [[ "$good_output" == *"OK: 3 uniffi-bindgen step(s)"* ]]; then
    echo "PASS [good-groups-and-bindgen counts three bindgen steps]"
    passed=$((passed + 1))
else
    echo "FAIL [good-groups-and-bindgen counts three bindgen steps]: $good_output" >&2
    failed=$((failed + 1))
fi

echo "workflow-compile-steps: $passed passed, $failed failed"
[[ "$failed" -eq 0 ]]
