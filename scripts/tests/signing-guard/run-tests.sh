#!/usr/bin/env bash
# Fixture tests for scripts/assert-nonempty-signing-set.sh.
#
# Three jobs in .github/workflows/release.yml — sign-apple, sign-windows and
# sign-maven — iterate a file search, sign whatever it returned, and upload the
# directory holding it under an artifact name asserting a signature. A search
# that matches nothing makes the loop run zero times and exit 0, so a build leg
# that produced no binary published an artifact named as signed that carried
# nothing signed. The guard asserts every (directory, pattern) cell holds a
# file, because the directories arrive from independent build jobs and the
# patterns name independently produced artifact kinds: a sum across directories
# accepted an empty windows-artifacts/ beside a populated windows-cbindgen/,
# and an OR across patterns accepted a Maven bundle holding a pom and no AAR.
# Each case below builds fixture directories and runs the real script against
# them.
set -euo pipefail

SCRIPT="$(cd "$(dirname "$0")/../.." && pwd)/assert-nonempty-signing-set.sh"
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

# --- Windows fixtures (job sign-windows: *.dll in each of two directories) --
mkdir -p "$WORK/with-dll/release" "$WORK/second-dll" "$WORK/empty" \
    "$WORK/nested/a/b/c" "$WORK/other-files"
touch "$WORK/with-dll/release/scp_ffi_uniffi.dll"
touch "$WORK/second-dll/scp_ffi_uniffi.dll"
touch "$WORK/nested/a/b/c/scp_ffi_napi.dll"
touch "$WORK/other-files/scp_ffi_uniffi.lib" "$WORK/other-files/README.txt"

# --- Apple fixtures (job sign-apple: *.a) ----------------------------------
# An XCFramework whose slice directories carry the headers and the Info.plist
# but no static library — the shape the Windows leg produced when it uploaded
# .lib and .pdb files and no .dll.
mkdir -p "$WORK/xcframework-full/ios-arm64/Headers" \
    "$WORK/xcframework-dylib-only/macos-arm64" \
    "$WORK/xcframework-no-lib/ios-arm64/Headers"
touch "$WORK/xcframework-full/Info.plist" \
    "$WORK/xcframework-full/ios-arm64/libscp_ffi.a" \
    "$WORK/xcframework-full/ios-arm64/Headers/scp.h"
touch "$WORK/xcframework-dylib-only/macos-arm64/libscp_ffi.dylib"
touch "$WORK/xcframework-no-lib/Info.plist" \
    "$WORK/xcframework-no-lib/ios-arm64/Headers/scp.h"
# A DIRECTORY whose name ends in .a: an XCFramework slice can be a bundle, and
# codesign over a directory is not a signed library. `find -type f` must skip it.
mkdir -p "$WORK/xcframework-dir-named-a/ios-arm64/libscp_ffi.a"

# --- Maven fixtures (job sign-maven: *.aar and *.jar, each required) -------
mkdir -p "$WORK/maven-full" "$WORK/maven-pom-only" "$WORK/maven-aar-only" \
    "$WORK/maven-jar-only" "$WORK/maven-no-artifacts"
touch "$WORK/maven-full/scp-kt-0.1.0.aar" \
    "$WORK/maven-full/scp-kt-0.1.0-sources.jar" \
    "$WORK/maven-full/scp-kt-0.1.0.pom"
touch "$WORK/maven-pom-only/scp-kt-0.1.0.pom"
touch "$WORK/maven-aar-only/scp-kt-0.1.0.aar"
touch "$WORK/maven-jar-only/scp-kt-0.1.0-sources.jar"
touch "$WORK/maven-no-artifacts/build.log" "$WORK/maven-no-artifacts/scp-kt.module"

echo "assert-nonempty-signing-set — every (directory, pattern) cell must hold a file"

# sign-windows: *.dll in each of two directories from independent build jobs
run_case "two directories each carrying a DLL are accepted" 0 \
    --name '*.dll' "$WORK/with-dll" "$WORK/second-dll"
run_case "an empty directory beside a directory carrying a DLL is rejected" 1 \
    --name '*.dll' "$WORK/with-dll" "$WORK/empty"
run_case "a DLL-less directory beside a directory carrying a DLL is rejected" 1 \
    --name '*.dll' "$WORK/with-dll" "$WORK/other-files"
run_case "a DLL nested three levels down is found" 0 --name '*.dll' "$WORK/nested"
run_case "two directories carrying no DLL are rejected" 1 \
    --name '*.dll' "$WORK/empty" "$WORK/other-files"
run_case "a directory holding only .lib and .txt is rejected" 1 \
    --name '*.dll' "$WORK/other-files"
run_case "a directory that does not exist is rejected" 1 \
    --name '*.dll' "$WORK/never-downloaded"
run_case "a missing directory beside a populated one is rejected" 1 \
    --name '*.dll' "$WORK/with-dll" "$WORK/never-downloaded"

# sign-apple: *.a
run_case "an XCFramework carrying a static library is accepted" 0 \
    --name '*.a' "$WORK/xcframework-full"
run_case "an XCFramework carrying only a dylib and no static library is rejected" 1 \
    --name '*.a' "$WORK/xcframework-dylib-only"
run_case "an XCFramework carrying headers and a plist but no library is rejected" 1 \
    --name '*.a' "$WORK/xcframework-no-lib"
run_case "a directory whose name ends in .a does not count as a library" 1 \
    --name '*.a' "$WORK/xcframework-dir-named-a"

# sign-maven: *.aar and *.jar, each required on its own
run_case "a Maven bundle carrying an aar, a jar and a pom is accepted" 0 \
    --name '*.aar' --name '*.jar' "$WORK/maven-full"
run_case "a Maven bundle carrying only a pom is rejected" 1 \
    --name '*.aar' --name '*.jar' "$WORK/maven-pom-only"
run_case "a Maven bundle carrying an aar but no jar is rejected" 1 \
    --name '*.aar' --name '*.jar' "$WORK/maven-aar-only"
run_case "a Maven directory holding only a log and a module file is rejected" 1 \
    --name '*.aar' --name '*.jar' "$WORK/maven-no-artifacts"

# Per-cell over both axes: each directory satisfies one pattern and misses the
# other, so a sum over either axis alone would count one match per pattern and
# one match per directory and pass.
run_case "two patterns each matched in only one of two directories are rejected" 1 \
    --name '*.aar' --name '*.jar' "$WORK/maven-aar-only" "$WORK/maven-jar-only"

# Invocation errors
run_case "naming no directory at all is rejected" 1 --name '*.dll'
run_case "naming no pattern at all is rejected" 1 "$WORK/with-dll"
run_case "a --name with no glob after it is rejected" 1 "$WORK/with-dll" --name
run_case "an unknown option is rejected" 1 --name '*.dll' --quiet "$WORK/with-dll"

echo "${PASSED} passed, ${FAILED} failed"
[[ "$FAILED" -eq 0 ]]
