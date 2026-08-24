#!/usr/bin/env bash
#
# Fail when no file matching the named patterns sits under the named directories.
#
# WHY THIS EXISTS. Three jobs in .github/workflows/release.yml sign a set of
# files and then upload the directory holding them under an artifact name that
# says the contents are signed:
#
#   sign-apple   codesign over *.a and *.dylib under xcframework/,
#                uploaded as swift-xcframework-signed
#   sign-windows signtool over *.dll under windows-artifacts/ and
#                windows-cbindgen/, uploaded as windows-signed
#   sign-maven   gpg --detach-sign over *.aar, *.jar and *.pom under
#                maven-artifacts/, uploaded as maven-signed
#
# Each signing step iterates whatever its file search returned. A search that
# matches nothing makes the loop run zero times and exit 0, after which the
# upload publishes an artifact whose name asserts a signature the artifact does
# not carry. Job rust in .github/workflows/build-matrix.yml failed its
# x86_64-pc-windows-msvc leg on an undeclared shell, which is one way an empty
# set reaches a signing job; a relocated or renamed output inside an XCFramework
# or an AAR bundle is another.
#
# This script runs before signing, so a release fails before an unsigned bundle
# can be uploaded under a name that says it is signed.
# scripts/tests/signing-guard/run-tests.sh drives it with fixture directories.
#
# Usage:
#   assert-nonempty-signing-set.sh --name <glob> [--name <glob>]... <directory>...
#
# Every --name is a find(1) -name glob. A file matching ANY of them counts.
set -euo pipefail

patterns=()
directories=()

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --name)
            if [[ "$#" -lt 2 ]]; then
                echo "assert-nonempty-signing-set.sh: --name takes a glob" >&2
                exit 1
            fi
            patterns+=("$2")
            shift 2
            ;;
        --)
            shift
            while [[ "$#" -gt 0 ]]; do
                directories+=("$1")
                shift
            done
            ;;
        -*)
            echo "assert-nonempty-signing-set.sh: unknown option '$1'" >&2
            exit 1
            ;;
        *)
            directories+=("$1")
            shift
            ;;
    esac
done

if [[ "${#patterns[@]}" -eq 0 ]]; then
    echo "assert-nonempty-signing-set.sh: name at least one --name glob" >&2
    exit 1
fi

if [[ "${#directories[@]}" -eq 0 ]]; then
    echo "assert-nonempty-signing-set.sh: name at least one directory to search" >&2
    exit 1
fi

# Build one find(1) expression ORing every --name glob, so a single walk answers
# for all of them: \( -name A -o -name B ... \).
expression=()
for index in "${!patterns[@]}"; do
    if [[ "$index" -gt 0 ]]; then
        expression+=(-o)
    fi
    expression+=(-name "${patterns[$index]}")
done

total=0
for directory in "${directories[@]}"; do
    if [[ ! -d "$directory" ]]; then
        echo "assert-nonempty-signing-set.sh: '$directory' does not exist — a build leg uploaded no artifact for it" >&2
        exit 1
    fi
    # `find … | wc -l`, never `find … -quit` or a `grep -q`: a reader that stops
    # early closes a pipe while its writer is still writing, and `set -o
    # pipefail` then reports that writer's SIGPIPE exit status instead of a
    # count. scripts/check-cross-layer.sh shipped that bug.
    found="$(find "$directory" -type f \( "${expression[@]}" \) | wc -l | tr -d ' ')"
    echo "  $directory: $found file(s) matching ${patterns[*]}"
    total=$((total + found))
done

if [[ "$total" -eq 0 ]]; then
    echo "assert-nonempty-signing-set.sh: found 0 files matching ${patterns[*]} under ${directories[*]}. Signing nothing and uploading it as a signed artifact would publish unsigned binaries." >&2
    exit 1
fi

echo "assert-nonempty-signing-set.sh: $total file(s) matching ${patterns[*]} across ${#directories[@]} director(ies)"
