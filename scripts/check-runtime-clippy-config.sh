#!/usr/bin/env bash
# check-runtime-clippy-config.sh — every scp-runtime* crate carries the same
# clippy.toml (ADR-070).
#
# Clippy reads only the configuration file nearest the crate being linted, so
# the workspace `.clippy.toml` does not reach a runtime crate. The ADR-049
# disallowed-types ban (std/tokio Mutex, tokio RwLock) and the openmls
# signer-storage disallowed-methods ban live in `crates/scp-runtime-core/clippy.toml`.
# ADR-070 split scp-runtime into 16 crates; a crate whose copy is missing or
# differs is linted without those bans. This gate requires every
# `crates/scp-runtime*/` directory to hold a `clippy.toml` byte-identical to
# core's copy.
#
# Usage:
#   bash scripts/check-runtime-clippy-config.sh             # check this repository
#   bash scripts/check-runtime-clippy-config.sh --self-test # prove the check fails on planted trees
#
# Exit codes:
#   0 — every runtime crate's clippy.toml matches core's
#   1 — a copy is missing or differs, no runtime crate directory exists, or a
#       self-test expectation failed

set -euo pipefail

REFERENCE_REL="crates/scp-runtime-core/clippy.toml"

# check_tree <root> — print one line per offending directory; return 1 on any.
check_tree() {
    local root="$1" reference="$1/$REFERENCE_REL" dir found=0 bad=0
    if [[ ! -f "$reference" ]]; then
        printf 'reference %s does not exist\n' "$REFERENCE_REL"
        return 1
    fi
    for dir in "$root"/crates/scp-runtime*/; do
        [[ -d "$dir" ]] || continue
        found=$((found + 1))
        if [[ ! -f "$dir/clippy.toml" ]]; then
            printf 'missing: %sclippy.toml\n' "${dir#"$root"/}"
            bad=1
        elif ! cmp -s "$dir/clippy.toml" "$reference"; then
            printf 'differs from %s: %sclippy.toml\n' "$REFERENCE_REL" "${dir#"$root"/}"
            bad=1
        fi
    done
    if [[ "$found" -eq 0 ]]; then
        printf 'no crates/scp-runtime*/ directory found\n'
        return 1
    fi
    return "$bad"
}

self_test() {
    local work rc=0 out
    work="$(mktemp -d "${TMPDIR:-/tmp}/runtime-clippy-config.XXXXXX")"
    trap 'rm -rf "$work"' RETURN

    # An identical tree passes.
    mkdir -p "$work/ok/crates/scp-runtime-core" "$work/ok/crates/scp-runtime-saga"
    printf 'disallowed-types = []\n' > "$work/ok/crates/scp-runtime-core/clippy.toml"
    cp "$work/ok/crates/scp-runtime-core/clippy.toml" "$work/ok/crates/scp-runtime-saga/clippy.toml"
    if ! out="$(check_tree "$work/ok")"; then
        printf 'SELF-TEST FAILED: an identical tree was rejected:\n%s\n' "$out" >&2
        rc=1
    fi

    # A missing copy fails.
    cp -R "$work/ok" "$work/missing"
    rm "$work/missing/crates/scp-runtime-saga/clippy.toml"
    if out="$(check_tree "$work/missing")" || [[ "$out" != *"missing: crates/scp-runtime-saga/clippy.toml"* ]]; then
        printf 'SELF-TEST FAILED: a missing clippy.toml was not reported:\n%s\n' "$out" >&2
        rc=1
    fi

    # A copy that differs by one byte fails.
    cp -R "$work/ok" "$work/differs"
    printf 'disallowed-types = []\n\n' > "$work/differs/crates/scp-runtime-saga/clippy.toml"
    if out="$(check_tree "$work/differs")" || [[ "$out" != *"differs from"*"crates/scp-runtime-saga/clippy.toml"* ]]; then
        printf 'SELF-TEST FAILED: a one-byte difference was not reported:\n%s\n' "$out" >&2
        rc=1
    fi

    # A tree with no runtime crate fails.
    mkdir -p "$work/empty/crates/scp-other"
    if out="$(check_tree "$work/empty")"; then
        printf 'SELF-TEST FAILED: a tree with no runtime crate passed\n' >&2
        rc=1
    fi

    if [[ "$rc" -eq 0 ]]; then
        printf 'self-test: identical tree passes; missing copy, one-byte difference and empty tree fail\n'
    fi
    return "$rc"
}

if [[ "${1:-}" == "--self-test" ]]; then
    self_test
    exit $?
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if out="$(check_tree "$REPO_ROOT")"; then
    printf 'PASSED: every crates/scp-runtime*/clippy.toml matches %s\n' "$REFERENCE_REL"
    exit 0
fi
printf 'FAILED: runtime crate clippy configuration drifted (ADR-070):\n%s\n' "$out" >&2
printf 'Copy %s into each listed crate unchanged.\n' "$REFERENCE_REL" >&2
exit 1
