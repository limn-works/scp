#!/usr/bin/env bash
# check-handler-no-panic.sh — CI gate enforcing ADR-049 §10's panic ban in
# the per-context actor handlers.
#
# ---------------------------------------------------------------------------
# WHAT THIS CHECKS
# ---------------------------------------------------------------------------
# ADR-049 §10 ("Actor panic recovery") requires that the per-context actor
# handlers NEVER use the panic family of macros in production code. A panic
# inside a handler unwinds the actor task; the supervisor watchdog catches
# it but DELIBERATELY discards the panic payload (it may interpolate
# plaintext or key material via `format!`), so a panicking handler both
# burns respawn budget AND loses its error context. Handlers must return a
# typed `ContextError` instead — never panic.
#
# This gate fails if any of the following macros appear (as a macro CALL,
# i.e. followed by `!`) in PRODUCTION code under
# `crates/scp-runtime/src/context/actor/handlers/` OR in the dispatch hub
# `crates/scp-runtime/src/context/actor/mod.rs`:
#
#   panic!  unreachable!  unimplemented!  todo!
#   assert!  assert_eq!  assert_ne!
#   debug_assert!  debug_assert_eq!  debug_assert_ne!
#
# "Production code" = everything BEFORE the file's `#[cfg(test)]` line. Test
# modules (which legitimately use `assert*!`) live below that marker and are
# NOT scanned. The check asserts at most ONE `#[cfg(test)]` per file so the
# "scan everything before the first one" rule is unambiguous.
#
# DISPATCH HUB EXCEPTION (actor/mod.rs only): the dispatch hub carries the
# `#[cfg(feature = "testing")]`-gated `TestInducePanic` fault-injection seam
# — a `panic!` that exists solely to exercise the supervisor watchdog
# deterministically and CANNOT exist in a production build. Banned macros
# inside a `#[cfg(feature = "testing")]`-gated item are therefore NOT flagged
# in `actor/mod.rs`; a banned macro OUTSIDE such a gate (e.g. a new
# production `panic!` in `dispatch_state`) IS flagged. The handlers/*.rs
# files have NO such exception — they must never panic at all.
#
# ---------------------------------------------------------------------------
# WHEN THIS RUNS
# ---------------------------------------------------------------------------
# On every PR (cheap, no build). It is ADDITIVE coverage — it does not
# replace or weaken any existing enforcement script.
#
# ---------------------------------------------------------------------------
# HOW TO FIX A FAILURE
# ---------------------------------------------------------------------------
# Replace the panic-family macro with a typed error return:
#   - Map the failure to the appropriate `ContextError` variant and return
#     it (handlers return `Outcome<T>` / `Result<T, ContextError>`).
#   - An "impossible" branch that was `unreachable!()` should return a
#     descriptive `ContextError` (e.g. `ContextError::CryptoFailed(..)`) so a
#     logic bug surfaces as a recoverable error, not an actor crash.
#   - A genuine test assertion belongs inside the file's `#[cfg(test)]`
#     module, which this gate does not scan.
#
# Do NOT relax this gate by widening the exemption region or removing macros
# from the banned list.
#
# ---------------------------------------------------------------------------
# PORTABILITY
# ---------------------------------------------------------------------------
# Runs on macOS (BSD userland) and Linux (GNU userland). Pure awk + find.
#
# Usage:
#   bash scripts/check-handler-no-panic.sh
# Exit codes:
#   0  — no banned macro in production handler code
#   1  — one or more banned macros present, OR a file has >1 `#[cfg(test)]`
#   2  — invocation error (scan dir missing)

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

SCAN_DIR="crates/scp-runtime/src/context/actor/handlers"

if [[ ! -d "$SCAN_DIR" ]]; then
    printf '%serror:%s scan dir %s does not exist\n' \
        "$C_RED" "$C_RESET" "$SCAN_DIR" >&2
    exit 2
fi

# ---------------------------------------------------------------------------
# Scan one file. Emits, per offending line:
#   HIT<TAB>file<TAB>line<TAB>text
# and, if the file has more than one `#[cfg(test)]`, a single:
#   MULTITEST<TAB>file<TAB>count
#
# Only the region BEFORE the first `#[cfg(test)]` is scanned for banned
# macros (handlers keep their test module as the trailing block). The banned
# set is matched as a macro call: an identifier from the list immediately
# followed by `!`, on a word boundary so `reassert!`-style names do not
# false-match. Line comments are stripped first so a doc/comment mention is
# allowed.
# ---------------------------------------------------------------------------
scan_file() {
    local file="$1"
    awk -v FILE="$file" '
    BEGIN {
        in_block = 0
        seen_test = 0
        test_count = 0
        # Banned macro names (without the trailing !).
        split("panic unreachable unimplemented todo assert assert_eq assert_ne debug_assert debug_assert_eq debug_assert_ne", names, " ")
    }
    {
        raw = $0

        # Count `#[cfg(test)]` markers regardless of scan region.
        if (raw ~ /#\[cfg\(test\)\]/) {
            test_count++
            seen_test = 1
        }

        # Once we are at/after the first `#[cfg(test)]`, stop scanning for
        # banned macros (test code may legitimately assert/panic), but keep
        # counting markers above for the MULTITEST check.
        if (seen_test) next

        line = raw
        # Strip /* .. */ on a single line.
        while (match(line, /\/\*.*\*\//)) {
            line = substr(line, 1, RSTART - 1) substr(line, RSTART + RLENGTH)
        }
        # Open block comment — drop everything after, mark in-block.
        if (match(line, /\/\*/)) {
            line = substr(line, 1, RSTART - 1)
            in_block = 1
        }
        # Close block comment — drop everything before.
        if (in_block && match(line, /\*\//)) {
            line = substr(line, RSTART + RLENGTH)
            in_block = 0
        }
        if (in_block) next
        # Strip //-comment tail.
        sub(/\/\/.*$/, "", line)

        # Look for any banned macro CALL: name followed by `!`, with a
        # left word boundary (start of token, not preceded by [A-Za-z0-9_]).
        for (i in names) {
            pat = "(^|[^A-Za-z0-9_])" names[i] "!"
            if (match(line, pat)) {
                trimmed = line
                sub(/^[[:space:]]+/, "", trimmed)
                sub(/[[:space:]]+$/, "", trimmed)
                printf("HIT\t%s\t%d\t%s\n", FILE, NR, trimmed)
                break
            }
        }
    }
    END {
        if (test_count > 1) {
            printf("MULTITEST\t%s\t%d\n", FILE, test_count)
        }
    }
    ' "$file"
}

# ---------------------------------------------------------------------------
# Scan the dispatch hub (`actor/mod.rs`). Identical banned-macro detection as
# `scan_file`, with ONE additional exclusion: a banned macro inside a
# `#[cfg(feature = "testing")]`-gated item is skipped (the `TestInducePanic`
# fault-injection seam). Testing-gated regions are tracked by brace depth: a
# `#[cfg(feature = "testing")]` attribute marks the NEXT item as the start of
# a testing region; the region floor is the brace depth just before the item
# opens, and the region ends when the brace depth returns to that floor.
# Everything else is scanned exactly as production code, so a NEW production
# panic in `dispatch_state` (outside any testing gate) is still flagged.
# ---------------------------------------------------------------------------
scan_dispatch_hub() {
    local file="$1"
    awk -v FILE="$file" '
    BEGIN {
        in_block = 0
        seen_test = 0
        test_count = 0
        depth = 0            # running brace depth
        testing_pending = 0  # saw #[cfg(feature="testing")], awaiting item open
        in_testing = 0       # currently inside a testing-gated region
        testing_floor = 0    # brace depth to which the testing region returns
        split("panic unreachable unimplemented todo assert assert_eq assert_ne debug_assert debug_assert_eq debug_assert_ne", names, " ")
    }
    {
        raw = $0

        if (raw ~ /#\[cfg\(test\)\]/) {
            test_count++
            seen_test = 1
        }
        if (seen_test) next

        line = raw
        # Strip /* .. */ on a single line.
        while (match(line, /\/\*.*\*\//)) {
            line = substr(line, 1, RSTART - 1) substr(line, RSTART + RLENGTH)
        }
        if (match(line, /\/\*/)) {
            line = substr(line, 1, RSTART - 1)
            in_block = 1
        }
        if (in_block && match(line, /\*\//)) {
            line = substr(line, RSTART + RLENGTH)
            in_block = 0
        }
        if (in_block) next
        sub(/\/\/.*$/, "", line)

        # Detect the testing-feature gate. The gated item opens on a later
        # line; remember the depth at which it opens so we can find its end.
        if (line ~ /#\[cfg\(feature[[:space:]]*=[[:space:]]*"testing"\)\]/) {
            testing_pending = 1
        }

        # Count braces on this (comment-stripped) line to track depth.
        opens = gsub(/{/, "{", line)
        closes = gsub(/}/, "}", line)

        # If a testing gate is pending and this line opens the gated item
        # (net positive braces), enter the testing region. The floor is the
        # depth BEFORE this item opened.
        if (testing_pending && opens > 0) {
            in_testing = 1
            testing_floor = depth
            testing_pending = 0
        }

        # Scan for banned macros UNLESS inside a testing-gated region.
        if (!in_testing) {
            for (i in names) {
                pat = "(^|[^A-Za-z0-9_])" names[i] "!"
                if (match(line, pat)) {
                    trimmed = line
                    sub(/^[[:space:]]+/, "", trimmed)
                    sub(/[[:space:]]+$/, "", trimmed)
                    printf("HIT\t%s\t%d\t%s\n", FILE, NR, trimmed)
                    break
                }
            }
        }

        # Update running depth; close the testing region when we return to
        # the floor.
        depth += opens - closes
        if (in_testing && depth <= testing_floor) {
            in_testing = 0
        }
    }
    END {
        if (test_count > 1) {
            printf("MULTITEST\t%s\t%d\n", FILE, test_count)
        }
    }
    ' "$file"
}

DISPATCH_HUB="crates/scp-runtime/src/context/actor/mod.rs"

if [[ ! -f "$DISPATCH_HUB" ]]; then
    printf '%serror:%s dispatch hub %s does not exist\n' \
        "$C_RED" "$C_RESET" "$DISPATCH_HUB" >&2
    exit 2
fi

TMP_OUT=$(mktemp)
trap 'rm -f "$TMP_OUT"' EXIT

printf '\n%shandler panic-ban scan:%s %s\n' "$C_DIM" "$C_RESET" "$SCAN_DIR"

# Scan only top-level *.rs files in the handlers dir (the handler modules).
find "$SCAN_DIR" -maxdepth 1 -type f -name '*.rs' -print0 \
    | while IFS= read -r -d '' file; do
        scan_file "$file"
    done > "$TMP_OUT"

# Scan the dispatch hub with the testing-seam exclusion.
printf '%shandler panic-ban scan:%s %s\n' "$C_DIM" "$C_RESET" "$DISPATCH_HUB"
scan_dispatch_hub "$DISPATCH_HUB" >> "$TMP_OUT"

HITS=$(grep -c $'^HIT\t' "$TMP_OUT" 2>/dev/null || true)
HITS=${HITS:-0}
MULTI=$(grep -c $'^MULTITEST\t' "$TMP_OUT" 2>/dev/null || true)
MULTI=${MULTI:-0}

if [[ "$MULTI" -ne 0 ]]; then
    printf '\n%sFAILED%s: %d handler file(s) contain more than one `#[cfg(test)]`,\n' \
        "$C_RED" "$C_RESET" "$MULTI" >&2
    printf 'which makes the "scan everything before the first #[cfg(test)]" rule\n' >&2
    printf 'ambiguous. Consolidate the file into a single trailing test module.\n' >&2
    while IFS=$'\t' read -r tag file count; do
        [[ "$tag" == "MULTITEST" ]] || continue
        printf '      %s%s%s  (%s#[cfg(test)] markers: %s%s)\n' \
            "$C_DIM" "$file" "$C_RESET" "$C_YELLOW" "$count" "$C_RESET" >&2
    done < "$TMP_OUT"
fi

if [[ "$HITS" -ne 0 ]]; then
    printf '\n%sFAILED%s: %d banned panic-family macro use(s) in handler\n' \
        "$C_RED" "$C_RESET" "$HITS" >&2
    printf 'production code (ADR-049 §10 forbids panicking inside actor handlers):\n' >&2
    while IFS=$'\t' read -r tag file line text; do
        [[ "$tag" == "HIT" ]] || continue
        printf '      %s%s:%s%s  %s%s%s\n' \
            "$C_DIM" "$file" "$line" "$C_RESET" \
            "$C_YELLOW" "$text" "$C_RESET" >&2
    done < "$TMP_OUT"
    printf '\n' >&2
    printf 'Return a typed `ContextError` instead of panicking. A handler panic\n' >&2
    printf 'unwinds the actor; the supervisor watchdog catches it but discards the\n' >&2
    printf 'payload (it may carry key material), burning respawn budget for no\n' >&2
    printf 'diagnostic value. See ADR-049 §10.\n' >&2
fi

if [[ "$HITS" -ne 0 || "$MULTI" -ne 0 ]]; then
    exit 1
fi

printf '%sPASSED%s: no banned panic-family macros in handler production code.\n' \
    "$C_GREEN" "$C_RESET"
exit 0
