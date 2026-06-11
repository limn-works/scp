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
        # Strip whole double-quoted string literals FIRST (only outside an open
        # block comment, where string syntax is inactive). A string literal may
        # contain a literal `/*` or `*/` or `//` (e.g. `let s = "/* not a
        # comment";`); without removing strings the block-comment scanner would
        # mistake the in-string `/*` for a real block-comment open and wedge the
        # scanner (flip `in_block` permanently), silently swallowing every
        # following line and making the gate vacuously pass. Removing string
        # bodies up front is a lexer-lite step: banned macro CALLS are never
        # inside a string literal, so dropping string contents cannot hide a
        # real violation, and it cannot be abused to wedge the scanner.
        if (!in_block) {
            gsub(/"[^"]*"/, "", line)
        }
        # Strip the //-comment tail. A `//` line comment may still contain a
        # literal `/*` (e.g. a doc reference to `handlers/*.rs`); stripping the
        # line-comment tail before block-comment detection makes the block scan
        # see only real (code-region) `/*`/`*/` tokens.
        #
        # NOTE: this does not strip a `//` that itself sits inside an open
        # block comment — but `in_block` short-circuits below before the strip
        # matters, and a banned macro is never both inside a `/* */` block and
        # introduced by a trailing `//`, so the simplification is safe for the
        # purpose of this gate: catching macro CALLS in live code.
        if (!in_block) {
            sub(/\/\/.*$/, "", line)
        }
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

        # Count scanned (live, non-comment) lines so the harness can assert the
        # gate is not vacuous.
        if (line ~ /[^[:space:]]/) {
            scanned++
        }

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
        printf("SCANNED\t%s\t%d\n", FILE, scanned)
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

        # Detect the testing-feature gate on the RAW line, BEFORE any string /
        # comment stripping. The `"testing"` literal inside the attribute would
        # otherwise be removed by the string-literal strip below, breaking the
        # exclusion (the gated `TestInducePanic` panic would then be flagged).
        # The gate attribute is never inside a comment or string, so reading it
        # from `raw` is correct.
        if (raw ~ /#\[cfg\(feature[[:space:]]*=[[:space:]]*"testing"\)\]/) {
            testing_pending = 1
        }

        line = raw
        # Strip whole double-quoted string literals FIRST (see scan_file for the
        # rationale: a string-literal `/*` must not wedge the block-comment
        # scanner). Doing this before the brace count below also makes depth
        # tracking ignore braces that live inside string literals.
        if (!in_block) {
            gsub(/"[^"]*"/, "", line)
        }
        # Strip the //-comment tail (see scan_file for the rationale: a
        # `//` line comment containing a literal `/*` — e.g. the
        # `handlers/*.rs` doc reference at the TestInducePanic seam in this file —
        # must not be mistaken for an unterminated block comment, which would
        # wrongly suppress every following line, including the production
        # dispatch arms whose panics this gate exists to catch).
        if (!in_block) {
            sub(/\/\/.*$/, "", line)
        }
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

        # (Testing-feature gate already detected from `raw` above, before
        # string/comment stripping.) The gated item opens on a later line; the
        # brace count below finds the depth at which it opens.

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
            # Count scanned (live, non-comment, production) lines so the
            # harness can assert this scan is not vacuous.
            if (line ~ /[^[:space:]]/) {
                scanned++
            }
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
        printf("SCANNED\t%s\t%d\n", FILE, scanned)
    }
    ' "$file"
}

DISPATCH_HUB="crates/scp-runtime/src/context/actor/mod.rs"

if [[ ! -f "$DISPATCH_HUB" ]]; then
    printf '%serror:%s dispatch hub %s does not exist\n' \
        "$C_RED" "$C_RESET" "$DISPATCH_HUB" >&2
    exit 2
fi

# The per-context dispatch helper layer (`*_helpers.rs`) — the `execute_*`
# governance leaves and dispatch transitives the handlers call synchronously.
# A reachable panic here unwinds the same actor task as a handler panic.
HELPER_DIR="crates/scp-runtime/src/context"

if [[ ! -d "$HELPER_DIR" ]]; then
    printf '%serror:%s helper dir %s does not exist\n' \
        "$C_RED" "$C_RESET" "$HELPER_DIR" >&2
    exit 2
fi

# ---------------------------------------------------------------------------
# scan_helper_file — scan one per-context dispatch HELPER file
# (`crates/scp-runtime/src/context/*_helpers.rs`) for the REACHABLE-panic
# family only. ADR-049 §10 (round-9): the helper layer holds the `execute_*`
# governance leaves and the per-context dispatch transitives that the actor
# handlers call synchronously. A `panic!`/`unreachable!`/`unimplemented!`/`todo!`
# reached there unwinds the SAME actor task as a panic in a handler — the
# watchdog respawns and, on a deterministic re-trip, poisons the context (a
# self-DoS, see §10 BLACK-002). So a reachable panic in a helper is exactly as
# dangerous as one in a handler and is banned here.
#
# DIFFERENCES FROM `scan_file` (handlers), each deliberate:
#
#   1. BANNED SET = reachable panics ONLY: panic unreachable unimplemented todo.
#      The `assert*!` / `debug_assert*!` family is NOT banned in the helper
#      layer. A `debug_assert!` is compiled OUT of release builds, so it can
#      never unwind a production actor; the helpers legitimately use it as a
#      release-stripped invariant tripwire (e.g. a `Drop`-guard "ticket dropped
#      without commit" tripwire that ALSO logs + recovers in release). Banning
#      the always-compiled reachable-panic macros catches the real hazard the
#      round-9 `unreachable!→Err` conversion targets without forcing the removal
#      of legitimate debug tripwires. (Handlers stay assert-free via `scan_file`;
#      this carve-out is scoped to the helper layer only.)
#
#   2. TEST-REGION EXCLUSION by brace-depth, not a single `#[cfg(test)]` cutoff.
#      Helper files gate test/test-only code several ways — `#[cfg(test)]`,
#      `#[cfg(all(test, feature = "testing"))]`, `#[cfg(any(test, feature =
#      "testing"))]`, and bare `#[cfg(feature = "testing")]` test accessors that
#      are INTERSPERSED in production (not a single trailing module). The
#      "scan everything before the first #[cfg(test)]" model would mis-handle
#      these. Instead, any `#[cfg(...)]` attribute whose predicate mentions
#      `test` or `feature = "testing"` marks the NEXT item as a gated region,
#      tracked by brace depth exactly like the dispatch hub's testing-seam
#      exclusion; banned macros inside such a region are skipped. This both
#      ignores the trailing test module and the interspersed testing-only items.
#
# Emits, per offending line: HIT<TAB>file<TAB>line<TAB>text, plus a trailing
# SCANNED<TAB>file<TAB>count of live production lines inspected.
# ---------------------------------------------------------------------------
scan_helper_file() {
    local file="$1"
    awk -v FILE="$file" '
    BEGIN {
        in_block = 0
        depth = 0
        gated_pending = 0   # saw a test/testing #[cfg(...)], awaiting item open
        in_gated = 0        # currently inside a test/testing-gated region
        gated_floor = 0     # brace depth the gated region returns to
        # Reachable-panic family ONLY (assert/debug_assert intentionally absent).
        split("panic unreachable unimplemented todo", names, " ")
    }
    {
        raw = $0

        # Detect a test/testing cfg gate on the RAW line BEFORE string/comment
        # stripping (the `"testing"` literal would otherwise be stripped). Match
        # any #[cfg(...)] whose predicate references `test` (covers `test`,
        # `all(test, ..)`, `any(test, ..)`) OR `feature = "testing"`.
        if (raw ~ /#\[cfg\([^]]*\btest\b/ || \
            raw ~ /#\[cfg\([^]]*feature[[:space:]]*=[[:space:]]*"testing"/) {
            gated_pending = 1
        }

        line = raw
        if (!in_block) gsub(/"[^"]*"/, "", line)
        if (!in_block) sub(/\/\/.*$/, "", line)
        while (match(line, /\/\*.*\*\//)) {
            line = substr(line, 1, RSTART - 1) substr(line, RSTART + RLENGTH)
        }
        if (match(line, /\/\*/)) { line = substr(line, 1, RSTART - 1); in_block = 1 }
        if (in_block && match(line, /\*\//)) { line = substr(line, RSTART + RLENGTH); in_block = 0 }
        if (in_block) next

        opens = gsub(/{/, "{", line)
        closes = gsub(/}/, "}", line)

        # A pending test/testing gate opens its region at the first net-positive
        # brace line; the floor is the depth BEFORE this item opened.
        if (gated_pending && opens > 0) {
            in_gated = 1
            gated_floor = depth
            gated_pending = 0
        }

        if (!in_gated) {
            if (line ~ /[^[:space:]]/) scanned++
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

        depth += opens - closes
        if (in_gated && depth <= gated_floor) in_gated = 0
    }
    END {
        printf("SCANNED\t%s\t%d\n", FILE, scanned)
    }
    ' "$file"
}

# ---------------------------------------------------------------------------
# run_scan — scan a handlers dir + dispatch hub + the per-context helper layer,
# evaluate the results, print a verdict. Returns 0 on PASS, 1 on a banned-macro
# / MULTITEST / vacuous-scan failure. Factored out so the self-test below can
# drive it against synthetic fixtures (planted production panic, planted handler
# panic) and assert the gate actually catches them.
#
# Args:
#   $1 — handlers scan dir
#   $2 — dispatch hub file
#   $3 — verb for messages ("scan" for the real run, "self-test" otherwise)
#   $4 — (optional) helper-layer dir scanned for the reachable-panic family.
#        When empty (the self-test fixtures), the helper scan is skipped.
# ---------------------------------------------------------------------------
run_scan() {
    local scan_dir="$1"
    local dispatch_hub="$2"
    local label="${3:-scan}"
    local helper_dir="${4:-}"

    local tmp_out
    tmp_out=$(mktemp)

    printf '\n%shandler panic-ban %s:%s %s\n' \
        "$C_DIM" "$label" "$C_RESET" "$scan_dir"

    # Scan only top-level *.rs files in the handlers dir (the handler modules).
    find "$scan_dir" -maxdepth 1 -type f -name '*.rs' -print0 \
        | while IFS= read -r -d '' file; do
            scan_file "$file"
        done > "$tmp_out"

    # Scan the dispatch hub with the testing-seam exclusion.
    printf '%shandler panic-ban %s:%s %s\n' \
        "$C_DIM" "$label" "$C_RESET" "$dispatch_hub"
    scan_dispatch_hub "$dispatch_hub" >> "$tmp_out"

    # Scan the per-context dispatch helper layer for reachable panics.
    local helper_scanned=0 helper_min=0
    if [[ -n "$helper_dir" ]]; then
        printf '%shelper panic-ban %s:%s %s/*_helpers.rs\n' \
            "$C_DIM" "$label" "$C_RESET" "$helper_dir"
        find "$helper_dir" -maxdepth 1 -type f -name '*_helpers.rs' -print0 \
            | while IFS= read -r -d '' file; do
                scan_helper_file "$file"
            done >> "$tmp_out"
        helper_scanned=$(awk -F'\t' -v D="$helper_dir" \
            '$1=="SCANNED" && index($2, D)==1 {s+=$3} END{print s+0}' "$tmp_out")
        # The helper layer is several thousand production lines; a near-zero
        # count means the scanner wedged (and the gate would vacuously pass).
        helper_min=500
    fi

    local hits multi
    hits=$(grep -c $'^HIT\t' "$tmp_out" 2>/dev/null || true)
    hits=${hits:-0}
    multi=$(grep -c $'^MULTITEST\t' "$tmp_out" 2>/dev/null || true)
    multi=${multi:-0}

    # Vacuity guard: the dispatch hub MUST contribute a non-trivial number of
    # scanned production lines. A regression that wedges the scanner (e.g. a
    # `//` comment containing `/*` flipping the block-comment state and
    # silently swallowing the rest of the file — the exact bug this revision
    # fixes) would drop the hub's scanned count toward zero, making the gate
    # vacuously PASS. Treat a near-empty hub scan as a failure.
    local hub_scanned vacuous=0
    hub_scanned=$(awk -F'\t' -v F="$dispatch_hub" \
        '$1=="SCANNED" && $2==F {print $3}' "$tmp_out")
    hub_scanned=${hub_scanned:-0}
    # The dispatch hub is a large file; its production region is hundreds of
    # lines. A threshold well below the real count (which is in the hundreds)
    # but well above any plausible "wedged scanner" residue.
    local hub_min=100
    if [[ "$hub_scanned" -lt "$hub_min" ]]; then
        vacuous=1
    fi
    # Helper-layer vacuity: if a helper dir was scanned, it must contribute a
    # non-trivial line count (the helper layer is thousands of lines). A wedged
    # helper scanner would otherwise let a reachable panic slip through.
    if [[ -n "$helper_dir" && "$helper_scanned" -lt "$helper_min" ]]; then
        vacuous=1
    fi

    if [[ "$multi" -ne 0 ]]; then
        printf '\n%sFAILED%s: %d handler file(s) contain more than one `#[cfg(test)]`,\n' \
            "$C_RED" "$C_RESET" "$multi" >&2
        printf 'which makes the "scan everything before the first #[cfg(test)]" rule\n' >&2
        printf 'ambiguous. Consolidate the file into a single trailing test module.\n' >&2
        while IFS=$'\t' read -r tag file count; do
            [[ "$tag" == "MULTITEST" ]] || continue
            printf '      %s%s%s  (%s#[cfg(test)] markers: %s%s)\n' \
                "$C_DIM" "$file" "$C_RESET" "$C_YELLOW" "$count" "$C_RESET" >&2
        done < "$tmp_out"
    fi

    if [[ "$vacuous" -ne 0 ]]; then
        printf '\n%sFAILED%s: a scan is vacuous — dispatch hub scanned %d production\n' \
            "$C_RED" "$C_RESET" "$hub_scanned" >&2
        printf 'line(s) (expected >= %d), helper layer scanned %d line(s) (expected\n' \
            "$hub_min" "$helper_scanned" >&2
        printf '>= %d). A scanner has been wedged (likely a comment-stripping\n' \
            "$helper_min" >&2
        printf 'regression), so the panic ban is no longer enforced. Fix the scanner —\n' >&2
        printf 'do not lower the threshold.\n' >&2
    fi

    if [[ "$hits" -ne 0 ]]; then
        printf '\n%sFAILED%s: %d banned panic-family macro use(s) in handler\n' \
            "$C_RED" "$C_RESET" "$hits" >&2
        printf 'production code (ADR-049 §10 forbids panicking inside actor handlers):\n' >&2
        while IFS=$'\t' read -r tag file line text; do
            [[ "$tag" == "HIT" ]] || continue
            printf '      %s%s:%s%s  %s%s%s\n' \
                "$C_DIM" "$file" "$line" "$C_RESET" \
                "$C_YELLOW" "$text" "$C_RESET" >&2
        done < "$tmp_out"
        printf '\n' >&2
        printf 'Return a typed `ContextError` instead of panicking. A handler panic\n' >&2
        printf 'unwinds the actor; the supervisor watchdog catches it but discards the\n' >&2
        printf 'payload (it may carry key material), burning respawn budget for no\n' >&2
        printf 'diagnostic value. See ADR-049 §10.\n' >&2
    fi

    rm -f "$tmp_out"

    if [[ "$hits" -ne 0 || "$multi" -ne 0 || "$vacuous" -ne 0 ]]; then
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# SELF-TEST — before trusting the gate on real code, prove it is not dead.
# Build synthetic fixtures and assert the scanner CATCHES:
#   (1) a production `unreachable!()` planted in the dispatch hub AFTER a `//`
#       comment that contains a literal `/*` (the regression that made this
#       gate vacuously pass), and
#   (2) a `panic!()` planted in a handler file,
# while still EXCLUDING a `#[cfg(feature = "testing")]`-gated panic in the hub.
# If any expectation is violated, the gate fails loudly rather than silently
# rotting. Set NO_PANIC_GATE_SELFTEST=1 to skip (not recommended).
# ---------------------------------------------------------------------------
self_test() {
    local fixt
    fixt=$(mktemp -d)
    local fhandlers="$fixt/handlers"
    mkdir -p "$fhandlers"
    local fhub="$fixt/mod.rs"

    # A hub fixture that reproduces the real-code shape: a `//` comment that
    # contains a literal `/*` (the `handlers/*.rs` reference), a testing-gated
    # panic that MUST be excluded, and padding so the production scan is
    # non-trivial.
    #
    # CRITICAL ORDERING: the `/*`-bearing `//` wedge comment is placed FIRST,
    # BEFORE the padding. If a comment-stripping regression reappears (block-
    # comment detection runs before the `//`-tail strip, so the literal `/*`
    # flips `in_block` permanently), the wedge swallows EVERYTHING after it —
    # the padding AND the planted panic. The scanned-line count then collapses
    # toward zero, BELOW `hub_min`, so the vacuity guard fires and the self-test
    # FAILS. Were the padding placed first (the previous fixture), the regressed
    # scanner would still count the 150 padding lines (scanned >= hub_min),
    # masking the regression and letting the swallowed panic pass vacuously.
    # Ordering the wedge first makes the vacuity guard the independent safety
    # net for the wedge regression — even if the planted-panic HIT is missed.
    {
        printf 'fn dispatch_state() {\n'
        # The `//` comment carrying a literal `/*` (mirrors mod.rs:589) FIRST.
        printf '    // any `handlers/*.rs` module reference\n'
        # >= hub_min production lines of padding so a CORRECT scanner clears the
        # vacuity guard; a wedged scanner swallows all of this and drops below it.
        local i
        for ((i = 0; i < 150; i++)); do
            printf '    let _x%d = %d;\n' "$i" "$i"
        done
        # Testing-gated panic — MUST be excluded.
        printf '    #[cfg(feature = "testing")]\n'
        printf '    fn induce() {\n'
        printf '        panic!("testing seam");\n'
        printf '    }\n'
        # Production panic AFTER the `/*` comment + padding — MUST be caught by a
        # correct scanner, and swallowed (→ vacuity fail) by a wedged one.
        printf '    unreachable!("planted production panic");\n'
        printf '}\n'
    } > "$fhub"

    # A handler fixture with a planted production panic — MUST be caught.
    {
        printf 'pub fn dispatch() {\n'
        printf '    panic!("planted handler panic");\n'
        printf '}\n'
    } > "$fhandlers/planted.rs"

    local rc=0
    if run_scan "$fhandlers" "$fhub" "self-test" >/dev/null 2>&1; then
        printf '%sSELF-TEST FAILED%s: planted production panics were NOT caught.\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'The panic-ban gate is dead — it would pass even with a real\n' >&2
        printf 'production `panic!`/`unreachable!` in the actor dispatch hub.\n' >&2
        rc=1
    fi

    # Inverse fixture: a hub with ONLY the testing-gated panic (and enough
    # padding to clear the vacuity guard) MUST pass — confirms the testing
    # seam is still correctly excluded and the gate is not over-eager.
    local fhub_clean="$fixt/mod_clean.rs"
    {
        printf 'fn dispatch_state() {\n'
        # Wedge comment first (same ordering as the catching fixture).
        printf '    // any `handlers/*.rs` module reference\n'
        local j
        for ((j = 0; j < 150; j++)); do
            printf '    let _y%d = %d;\n' "$j" "$j"
        done
        printf '    #[cfg(feature = "testing")]\n'
        printf '    fn induce() {\n'
        printf '        panic!("testing seam");\n'
        printf '    }\n'
        printf '}\n'
    } > "$fhub_clean"
    local fhandlers_clean="$fixt/handlers_clean"
    mkdir -p "$fhandlers_clean"
    printf 'pub fn dispatch() {}\n' > "$fhandlers_clean/clean.rs"

    if ! run_scan "$fhandlers_clean" "$fhub_clean" "self-test" >/dev/null 2>&1; then
        printf '%sSELF-TEST FAILED%s: a clean hub with only a testing-gated panic\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'was wrongly flagged. The gate is over-eager (the `#[cfg(feature =\n' >&2
        printf '"testing")]` seam exclusion or the comment handling is broken).\n' >&2
        rc=1
    fi

    rm -rf "$fixt"
    return "$rc"
}

# ---------------------------------------------------------------------------
# self_test_helpers — prove the helper-layer scanner (`scan_helper_file`) is
# alive and correctly scoped. Drives synthetic `*_helpers.rs` fixtures and
# asserts it:
#   (1) CATCHES a production reachable panic (`unreachable!`),
#   (2) does NOT flag a production `debug_assert!` (release-stripped tripwire —
#       the deliberate helper-layer carve-out),
#   (3) does NOT flag a panic inside a `#[cfg(all(test, feature = "testing"))]`
#       module (the form lifecycle_helpers.rs uses),
#   (4) does NOT flag a panic inside a bare `#[cfg(feature = "testing")]` item
#       (the interspersed testing accessors in queries_helpers.rs).
# Set NO_PANIC_GATE_SELFTEST=1 to skip (not recommended).
# ---------------------------------------------------------------------------
self_test_helpers() {
    local fixt
    fixt=$(mktemp -d)
    local rc=0

    # (1)+(2): a production reachable panic AND a production debug_assert.
    {
        printf 'pub fn execute_thing() {\n'
        printf '    debug_assert!(false, "release-stripped tripwire");\n'
        printf '    unreachable!("planted helper reachable panic");\n'
        printf '}\n'
    } > "$fixt/a_helpers.rs"
    local out
    out=$(scan_helper_file "$fixt/a_helpers.rs")
    if ! grep -q $'^HIT\t.*unreachable' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: helper scanner did NOT catch a production reachable\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'panic (`unreachable!`) — the helper panic-ban is dead.\n' >&2
        rc=1
    fi
    if grep -q $'^HIT\t.*debug_assert' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: helper scanner flagged a `debug_assert!` — the\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'release-stripped-tripwire carve-out is broken (it must NOT be banned).\n' >&2
        rc=1
    fi

    # (3): a panic inside `#[cfg(all(test, feature = "testing"))]` — excluded.
    {
        printf 'pub fn prod_clean() { let _ = 1; }\n'
        printf '#[cfg(all(test, feature = "testing"))]\n'
        printf 'mod tests {\n'
        printf '    #[test]\n'
        printf '    fn t() { panic!("test panic ok"); }\n'
        printf '}\n'
    } > "$fixt/b_helpers.rs"
    out=$(scan_helper_file "$fixt/b_helpers.rs")
    if grep -q $'^HIT\t' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: helper scanner flagged a panic inside a\n' \
            "$C_RED" "$C_RESET" >&2
        printf '`#[cfg(all(test, feature = "testing"))]` test module (must be excluded).\n' >&2
        rc=1
    fi

    # (4): a panic inside a bare `#[cfg(feature = "testing")]` accessor — excluded.
    {
        printf 'pub fn prod_clean2() { let _ = 2; }\n'
        printf '#[cfg(feature = "testing")]\n'
        printf 'pub fn test_accessor() { todo!("testing-only accessor"); }\n'
    } > "$fixt/c_helpers.rs"
    out=$(scan_helper_file "$fixt/c_helpers.rs")
    if grep -q $'^HIT\t' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: helper scanner flagged a panic inside a bare\n' \
            "$C_RED" "$C_RESET" >&2
        printf '`#[cfg(feature = "testing")]` accessor (must be excluded).\n' >&2
        rc=1
    fi

    rm -rf "$fixt"
    return "$rc"
}

if [[ -z "${NO_PANIC_GATE_SELFTEST:-}" ]]; then
    if ! self_test; then
        exit 1
    fi
    if ! self_test_helpers; then
        printf '%sThe helper-layer panic-ban scanner is dead or mis-scoped — fix it.%s\n' \
            "$C_RED" "$C_RESET" >&2
        exit 1
    fi
    printf '%sself-test:%s gate catches planted panics, excludes the testing seam,\n' \
        "$C_DIM" "$C_RESET"
    printf '%s          %s and the helper scanner catches reachable panics while\n' \
        "$C_DIM" "$C_RESET"
    printf '%s          %s excluding debug_assert + test/testing-gated code.\n' \
        "$C_DIM" "$C_RESET"
fi

if run_scan "$SCAN_DIR" "$DISPATCH_HUB" "scan" "$HELPER_DIR"; then
    printf '%sPASSED%s: no banned panic-family macros in handler production code,\n' \
        "$C_GREEN" "$C_RESET"
    printf '%s        %s and no reachable panics in the per-context helper layer.\n' \
        "$C_DIM" "$C_RESET"
    exit 0
fi
exit 1
