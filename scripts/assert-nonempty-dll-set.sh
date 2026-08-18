#!/usr/bin/env bash
#
# Fail when no .dll file sits under the named directories.
#
# Job sign-windows in .github/workflows/release.yml downloads two build
# artifacts, Authenticode-signs every .dll under them, and uploads the result
# under artifact name `windows-signed`. Its signing loop ran over whatever
# Get-ChildItem returned, and an empty set made that loop run zero times and
# exit 0, after which the upload published `windows-signed` carrying nothing
# signed. Job rust in .github/workflows/build-matrix.yml failed its
# x86_64-pc-windows-msvc leg on an undeclared shell, which is one way an empty
# set reaches that job.
#
# This script runs before signing, so it fails a release before an unsigned
# bundle can be uploaded. scripts/tests/sign-windows/run-tests.sh drives it with
# fixture directories.
#
# Usage: assert-nonempty-dll-set.sh <directory>...
set -euo pipefail

if [[ "$#" -eq 0 ]]; then
    echo "assert-nonempty-dll-set.sh: name at least one directory to search" >&2
    exit 1
fi

total=0
for directory in "$@"; do
    if [[ ! -d "$directory" ]]; then
        echo "assert-nonempty-dll-set.sh: '$directory' does not exist — a build leg uploaded no artifact for it" >&2
        exit 1
    fi
    # `find … | wc -l`, never `find … -quit` or a `grep -q`: a reader that stops
    # early closes a pipe while its writer is still writing, and `set -o
    # pipefail` then reports that writer's SIGPIPE exit status instead of a
    # count. scripts/check-cross-layer.sh shipped that bug.
    found="$(find "$directory" -type f -name '*.dll' | wc -l | tr -d ' ')"
    echo "  $directory: $found DLL(s)"
    total=$((total + found))
done

if [[ "$total" -eq 0 ]]; then
    echo "assert-nonempty-dll-set.sh: found 0 DLL files under $*. Signing nothing and uploading it as a signed artifact would publish unsigned binaries." >&2
    exit 1
fi

echo "assert-nonempty-dll-set.sh: $total DLL(s) present across $# director(ies)"
