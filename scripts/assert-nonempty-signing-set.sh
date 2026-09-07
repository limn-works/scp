#!/usr/bin/env bash
#
# Fail unless every named directory holds at least one file matching every
# named pattern.
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
# WHY THE ASSERTION IS PER (DIRECTORY, PATTERN) CELL. The directories a signing
# job names arrive from independent build jobs, and the patterns name
# independently produced artifact kinds, so any weaker aggregation lets one
# populated cell mask another cell's empty set: a sum across directories
# accepted a windows-artifacts/ holding zero DLLs whenever windows-cbindgen/
# held one, and an OR across patterns accepted a Maven bundle holding a pom and
# no AAR. Every cell must be nonempty; a pattern that a build produces only
# sometimes does not belong in the invocation, because naming it would either
# fail every honest release or weaken the guard back into an OR.
#
# This script runs before signing, so a release fails before an unsigned bundle
# can be uploaded under a name that says it is signed.
# scripts/tests/signing-guard/run-tests.sh drives it with fixture directories.
#
# Usage:
#   assert-nonempty-signing-set.sh --name <glob> [--name <glob>]... <directory>...
#
# Every --name is a find(1) -name glob. Every directory must hold at least one
# file matching EACH of them.
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

empty_cells=()
for directory in "${directories[@]}"; do
    if [[ ! -d "$directory" ]]; then
        echo "assert-nonempty-signing-set.sh: '$directory' does not exist — a build leg uploaded no artifact for it" >&2
        exit 1
    fi
    for pattern in "${patterns[@]}"; do
        # `find … | wc -l`, never `find … -quit` or a `grep -q`: a reader that
        # stops early closes a pipe while its writer is still writing, and `set
        # -o pipefail` then reports that writer's SIGPIPE exit status instead
        # of a count. scripts/check-cross-layer.sh shipped that bug.
        found="$(find "$directory" -type f -name "$pattern" | wc -l | tr -d ' ')"
        echo "  $directory × $pattern: $found file(s)"
        if [[ "$found" -eq 0 ]]; then
            empty_cells+=("$directory × $pattern")
        fi
    done
done

if [[ "${#empty_cells[@]}" -gt 0 ]]; then
    echo "assert-nonempty-signing-set.sh: ${#empty_cells[@]} empty cell(s): ${empty_cells[*]}. A build leg produced none of an artifact this signing job exists to sign; uploading the bundle as a signed artifact would publish it with that artifact absent or unsigned." >&2
    exit 1
fi

echo "assert-nonempty-signing-set.sh: every cell of ${#directories[@]} director(ies) × ${#patterns[@]} pattern(s) holds at least one file"
