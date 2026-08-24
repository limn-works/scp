#!/usr/bin/env bash
# Fixture tests for scripts/assert-nonempty-signing-set.sh.
#
# Three jobs in .github/workflows/release.yml — sign-apple, sign-windows and
# sign-maven — iterate a file search, sign whatever it returned, and upload the
# directory holding it under an artifact name asserting a signature. A search
# that matches nothing makes the loop run zero times and exit 0, so a build leg
# that produced no binary published an artifact named as signed that carried
# nothing signed. Each case below builds fixture directories and runs the real
# script against them.
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

# --- Windows fixtures (job sign-windows: *.dll) ----------------------------
mkdir -p "$WORK/with-dll/release" "$WORK/empty" "$WORK/nested/a/b/c" "$WORK/other-files"
touch "$WORK/with-dll/release/scp_ffi_uniffi.dll"
touch "$WORK/nested/a/b/c/scp_ffi_napi.dll"
touch "$WORK/other-files/scp_ffi_uniffi.lib" "$WORK/other-files/README.txt"

# --- Apple fixtures (job sign-apple: *.a and *.dylib) ----------------------
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

# --- Maven fixtures (job sign-maven: *.aar, *.jar, *.pom) ------------------
mkdir -p "$WORK/maven-full" "$WORK/maven-pom-only" "$WORK/maven-no-artifacts"
touch "$WORK/maven-full/scp-kt-0.1.0.aar" \
    "$WORK/maven-full/scp-kt-0.1.0-sources.jar" \
    "$WORK/maven-full/scp-kt-0.1.0.pom"
touch "$WORK/maven-pom-only/scp-kt-0.1.0.pom"
touch "$WORK/maven-no-artifacts/build.log" "$WORK/maven-no-artifacts/scp-kt.module"

echo "assert-nonempty-signing-set — a signing job must reject an empty input set"

# sign-windows: *.dll
run_case "one DLL beside an empty directory is accepted" 0 \
    --name '*.dll' "$WORK/with-dll" "$WORK/empty"
run_case "a DLL nested three levels down is found" 0 --name '*.dll' "$WORK/nested"
run_case "two directories carrying no DLL are rejected" 1 \
    --name '*.dll' "$WORK/empty" "$WORK/other-files"
run_case "a directory holding only .lib and .txt is rejected" 1 \
    --name '*.dll' "$WORK/other-files"
run_case "a directory that does not exist is rejected" 1 \
    --name '*.dll' "$WORK/never-downloaded"
run_case "a missing directory beside a populated one is rejected" 1 \
    --name '*.dll' "$WORK/with-dll" "$WORK/never-downloaded"

# sign-apple: *.a and *.dylib
run_case "an XCFramework carrying a static library is accepted" 0 \
    --name '*.a' --name '*.dylib' "$WORK/xcframework-full"
run_case "an XCFramework carrying only a dylib is accepted" 0 \
    --name '*.a' --name '*.dylib' "$WORK/xcframework-dylib-only"
run_case "an XCFramework carrying headers and a plist but no library is rejected" 1 \
    --name '*.a' --name '*.dylib' "$WORK/xcframework-no-lib"
run_case "a directory whose name ends in .a does not count as a library" 1 \
    --name '*.a' --name '*.dylib' "$WORK/xcframework-dir-named-a"

# sign-maven: *.aar, *.jar, *.pom
run_case "a Maven bundle carrying an aar, a jar and a pom is accepted" 0 \
    --name '*.aar' --name '*.jar' --name '*.pom' "$WORK/maven-full"
run_case "a Maven bundle carrying only a pom is accepted" 0 \
    --name '*.aar' --name '*.jar' --name '*.pom' "$WORK/maven-pom-only"
run_case "a Maven directory holding only a log and a module file is rejected" 1 \
    --name '*.aar' --name '*.jar' --name '*.pom' "$WORK/maven-no-artifacts"

# Invocation errors
run_case "naming no directory at all is rejected" 1 --name '*.dll'
run_case "naming no pattern at all is rejected" 1 "$WORK/with-dll"
run_case "a --name with no glob after it is rejected" 1 "$WORK/with-dll" --name
run_case "an unknown option is rejected" 1 --name '*.dll' --quiet "$WORK/with-dll"

echo "${PASSED} passed, ${FAILED} failed"
[[ "$FAILED" -eq 0 ]]
