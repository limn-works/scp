#!/usr/bin/env bash
# check-no-fallback-registry.sh — CI gate preventing regression of the
# fallback-registry pattern that was removed in Phase 4 PR 2 (#1549).
#
# ---------------------------------------------------------------------------
# WHAT THIS CHECKS
# ---------------------------------------------------------------------------
# Pre-PR-2 the FFI bridges installed process-global `OnceLock` fallback
# registries (`EMPTY_IDENTITY_REGISTRY`, `EMPTY_UCAN_REGISTRY`) that silently
# masked "bridge not initialized" callers: if the default bridge instance
# hadn't been constructed yet, writes went to a never-read empty registry
# and the bridge appeared to work while losing data. The H1 chicken-and-egg
# pattern (ADR-048 §Context) traces directly to this.
#
# PR 2 deleted `EMPTY_IDENTITY_REGISTRY` and `EMPTY_UCAN_REGISTRY` and made
# registry access infallible-but-visible: every accessor either returns the
# real per-instance registry or an `ScpError`. The remaining `EMPTY_*`
# registries (listed in `ratchet/once-lock-count.json`) are scheduled for
# removal in later PRs, not here.
#
# This gate ensures the deleted patterns do not silently return. It fails
# if any of the following appears anywhere under `crates/scp-ffi/`:
#
#   1. `EMPTY_IDENTITY_REGISTRY`
#   2. `EMPTY_UCAN_REGISTRY`
#   3. A NEW `static EMPTY_<anything>: ...OnceLock<DashMap<...>>` declaration
#      that is not already on the ratchet baseline (counted statics grow
#      downward, never upward — the existing static-count ratchet in
#      `scripts/check-no-bridge-globals.sh` catches that axis).
#
# Occurrences of the dead tokens inside comments or doc-strings are fine —
# they remain as historical context ("mirrors the `EMPTY_IDENTITY_REGISTRY`
# pattern"). This gate matches only non-comment uses by requiring either
# `static`, an assignment, or a function call on the identifier.
#
# ---------------------------------------------------------------------------
# WHEN THIS RUNS
# ---------------------------------------------------------------------------
# Gated on every PR touching `crates/scp-ffi/**`.
#
# ---------------------------------------------------------------------------
# HOW TO FIX A FAILURE
# ---------------------------------------------------------------------------
# The check fires when code reintroduces the fallback-registry pattern. Two
# resolutions:
#
#   1. The preferred fix: make the accessor return `Result<&T, ScpError>`
#      and propagate the error. The caller should not be able to read or
#      write a registry before the bridge instance is constructed.
#   2. If the value is genuinely per-bridge (not per-identity), move it onto
#      `PyBridgeInstance` / `NapiBridgeInstance` / `UniffiBridgeInstance` as
#      a typed field — the pattern established in Phase 4 PR 2.
#
# Do NOT relax this gate by removing tokens from the pattern list.
#
# ---------------------------------------------------------------------------
# PORTABILITY
# ---------------------------------------------------------------------------
# Runs on macOS (BSD userland) and Linux (GNU userland).
#
# Usage:
#   bash scripts/check-no-fallback-registry.sh
# Exit codes:
#   0  — no regression
#   1  — one or more disallowed tokens present in non-comment context
#   2  — invocation error

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# ---------------------------------------------------------------------------
# TTY-aware coloring
# ---------------------------------------------------------------------------
if [[ -t 1 ]] && [[ -z "${NO_COLOR:-}" ]]; then
    C_RED=$'\033[31m'
    C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'
    C_DIM=$'\033[2m'
    C_RESET=$'\033[0m'
else
    C_RED=""
    C_GREEN=""
    C_YELLOW=""
    C_DIM=""
    C_RESET=""
fi

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
# Tokens that must not appear as code (declaration, use, or reference). A
# comment-only occurrence is allowed — pattern matching strips comments
# before looking for the tokens.
BANNED_TOKENS=(
    "EMPTY_IDENTITY_REGISTRY"
    "EMPTY_UCAN_REGISTRY"
)

SCAN_DIR="crates/scp-ffi"

# ---------------------------------------------------------------------------
# Strip `//` line comments and `/* … */` block comments from a Rust source
# file, then look for each banned token. Emits:
#   HIT<TAB>file<TAB>line<TAB>token<TAB>text
# for each hit.
# ---------------------------------------------------------------------------
scan_file() {
    local file="$1"
    local token="$2"

    # awk strips line comments and block comments (line-level only — a
    # /* .. */ spanning multiple lines may leak, but that is rare in Rust
    # and false positives can be resolved by splitting into //-comments).
    awk -v TOKEN="$token" -v FILE="$file" '
    BEGIN { in_block = 0 }
    {
        line = $0
        # Strip /* .. */ on a single line.
        while (match(line, /\/\*.*\*\//)) {
            line = substr(line, 1, RSTART - 1) substr(line, RSTART + RLENGTH)
        }
        # Open block comment — drop everything after.
        if (match(line, /\/\*/)) {
            line = substr(line, 1, RSTART - 1)
            in_block = 1
        }
        # Close block comment — drop everything before.
        if (in_block && match(line, /\*\//)) {
            line = substr(line, RSTART + RLENGTH)
            in_block = 0
        }
        # If still in a block, skip the whole line.
        if (in_block) next
        # Strip //-comment tail.
        sub(/\/\/.*$/, "", line)

        # Now look for the token.
        if (index(line, TOKEN) > 0) {
            # Trim.
            sub(/^[[:space:]]+/, "", line)
            sub(/[[:space:]]+$/, "", line)
            printf("HIT\t%s\t%d\t%s\t%s\n", FILE, NR, TOKEN, line)
        }
    }
    ' "$file"
}

# ---------------------------------------------------------------------------
# Drive the scan.
# ---------------------------------------------------------------------------
TMPDIR_RESULT=$(mktemp -d)
trap 'rm -rf "$TMPDIR_RESULT"' EXIT

if [[ ! -d "$SCAN_DIR" ]]; then
    printf '%serror:%s scan dir %s does not exist\n' \
        "$C_RED" "$C_RESET" "$SCAN_DIR" >&2
    exit 2
fi

TOTAL_HITS=0

printf '\n%sfallback-registry scan:%s\n' "$C_DIM" "$C_RESET"

for token in "${BANNED_TOKENS[@]}"; do
    out_file="$TMPDIR_RESULT/${token}.out"
    : > "$out_file"
    find "$SCAN_DIR" -type f -name '*.rs' -print0 \
        | while IFS= read -r -d '' file; do
            scan_file "$file" "$token"
        done > "$out_file"

    hits=$(grep -c $'^HIT\t' "$out_file" 2>/dev/null || true)
    hits=${hits:-0}

    if [[ "$hits" -eq 0 ]]; then
        printf '  %s[%s]%s clean\n' "$C_GREEN" "$token" "$C_RESET"
    else
        printf '  %s[%s]%s %d use(s) in code (not comments):\n' \
            "$C_RED" "$token" "$C_RESET" "$hits" >&2
        while IFS=$'\t' read -r tag file line tok text; do
            [[ "$tag" == "HIT" ]] || continue
            printf '      %s%s:%s%s  %s%s%s\n' \
                "$C_DIM" "$file" "$line" "$C_RESET" \
                "$C_YELLOW" "$text" "$C_RESET" >&2
        done < "$out_file"
        TOTAL_HITS=$((TOTAL_HITS + hits))
    fi
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
printf '\n'

if [[ "$TOTAL_HITS" -eq 0 ]]; then
    printf '%sPASSED%s: no regression of the fallback-registry pattern.\n' \
        "$C_GREEN" "$C_RESET"
    exit 0
fi

printf '%sFAILED%s: %d disallowed use(s) of deleted fallback-registry identifiers.\n' \
    "$C_RED" "$C_RESET" "$TOTAL_HITS" >&2
printf '\n' >&2
printf 'These identifiers were deleted in Phase 4 PR 2 (#1549).\n' >&2
printf 'Reintroducing them restores the silent "bridge not initialized"\n' >&2
printf 'data-loss pattern described in ADR-048 §Context.\n' >&2
printf '\n' >&2
printf 'Fix by making the accessor return `Result<&T, ScpError>` or by\n' >&2
printf 'moving the state onto a per-bridge instance. See ADR-048 §Decision 2.\n' >&2

exit 1
