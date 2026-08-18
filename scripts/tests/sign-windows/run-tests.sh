#!/usr/bin/env bash
# Fixture tests for scripts/assert-nonempty-dll-set.sh.
#
# Job sign-windows in .github/workflows/release.yml signed every .dll a
# PowerShell pipeline returned and uploaded the result under artifact name
# `windows-signed`. That pipeline runs zero times over an empty file set and
# exits 0, so a Windows build leg producing no binary published an artifact
# named as signed that carried nothing signed. Each case below builds fixture
# directories and runs the real script against them.
set -euo pipefail

SCRIPT="$(cd "$(dirname "$0")/../.." && pwd)/assert-nonempty-dll-set.sh"
PASSED=0
FAILED=0

# run_case <name> <expected-exit> <arg>...
run_case() {
    local name="$1" expected="$2"
    shift 2
    local actual=0
    bash "$SCRIPT" "$@" >/dev/null 2>&1 || actual=$?
    if [[ "$actual" -eq "$expected" ]]; then
        echo "  ok    ${name} (exit ${actual})"
        PASSED=$((PASSED + 1))
    else
        echo "  FAIL  ${name} (exit ${actual}, want ${expected})"
        FAILED=$((FAILED + 1))
    fi
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/with-dll/release" "$WORK/empty" "$WORK/nested/a/b/c" "$WORK/other-files"
touch "$WORK/with-dll/release/scp_ffi_uniffi.dll"
touch "$WORK/nested/a/b/c/scp_ffi_napi.dll"
touch "$WORK/other-files/scp_ffi_uniffi.lib" "$WORK/other-files/README.txt"

echo "assert-nonempty-dll-set — a signing job must reject an empty input set"
run_case "one DLL beside an empty directory is accepted" 0 "$WORK/with-dll" "$WORK/empty"
run_case "a DLL nested three levels down is found" 0 "$WORK/nested"
run_case "two directories carrying no DLL are rejected" 1 "$WORK/empty" "$WORK/other-files"
run_case "a directory holding only .lib and .txt is rejected" 1 "$WORK/other-files"
run_case "a directory that does not exist is rejected" 1 "$WORK/never-downloaded"
run_case "a missing directory beside a populated one is rejected" 1 "$WORK/with-dll" "$WORK/never-downloaded"
run_case "naming no directory at all is rejected" 1

echo "${PASSED} passed, ${FAILED} failed"
[[ "$FAILED" -eq 0 ]]
