#!/usr/bin/env bash
# check-no-kotlin-mutable-globals.sh — CI gate forbidding new top-level
# `var` declarations (and `object { … var … }` members) in the Kotlin SDK.
#
# ---------------------------------------------------------------------------
# WHAT THIS CHECKS
# ---------------------------------------------------------------------------
# Phase 4 (#1549) removed the process-wide default bridge instance and the
# `Scp.default` fallback. The Kotlin SDK holds no implicit per-process
# mutable state — all per-instance state lives on the `Scp` class.
#
# Kotlin's top-level `var` compiles to a backing field on the file's
# synthetic class, effectively a process-global. A `var` inside an
# `object X { … }` singleton is similarly process-global. Both shapes are
# forbidden by default; adding one requires an allowlist entry + a
# `// why:` comment on the declaration.
#
# The scan covers `bindings/kotlin/scp-kt/src/main/kotlin/` (NOT tests —
# tests often need `lateinit var` fixtures). UniFFI-generated bindings
# under `works/limn/scp/internal/uniffi/` are excluded — that tree is
# auto-generated and not subject to our multi-instance invariant.
#
# ---------------------------------------------------------------------------
# HOW TO FIX A FAILURE
# ---------------------------------------------------------------------------
# The usual cause: a new top-level `var` declaration (e.g. `var foo = 0`
# at file scope) or a `var` field on a `companion object` / `object` body.
#
#   1. Move the state onto the `Scp` class as a `val` backed by a
#      per-instance container. This is the canonical pattern.
#   2. If the state is genuinely a one-shot FFI addon (analog to the Rust
#      `RUNTIME` static), add the identifier to the ALLOWLIST below AND
#      add a `// why:` comment on the declaration.
#
# Do NOT use `@Suppress("TopLevelPropertyNaming")` to hide the issue —
# the grep pattern ignores annotations.
#
# ---------------------------------------------------------------------------
# PORTABILITY
# ---------------------------------------------------------------------------
# Runs on macOS (BSD userland) and Linux (GNU userland).
#
# Usage:
#   bash scripts/check-no-kotlin-mutable-globals.sh
# Exit codes:
#   0  — all top-level/object vars are allowlisted
#   1  — a disallowed declaration was added
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
# Allowlist of identifier names. Each entry must have a rationale comment.
# Currently empty — every piece of SDK state is per-instance on `Scp`.
# ---------------------------------------------------------------------------
ALLOWLIST=()

SCAN_DIR="bindings/kotlin/scp-kt/src/main/kotlin"

# Paths to exclude (prefixes under SCAN_DIR).
EXCLUDE_DIRS=(
    works/limn/scp/internal/uniffi
)

# ---------------------------------------------------------------------------
# Allowlist membership test.
# ---------------------------------------------------------------------------
is_allowlisted() {
    local name="$1"
    # bash 3.2 with `set -u` errors on `"${empty[@]}"`; guard on length.
    if [[ "${#ALLOWLIST[@]}" -eq 0 ]]; then
        return 1
    fi
    for allow in "${ALLOWLIST[@]}"; do
        [[ "$name" == "$allow" ]] && return 0
    done
    return 1
}

# ---------------------------------------------------------------------------
# Path-exclusion test.
# ---------------------------------------------------------------------------
is_excluded_path() {
    local p="$1"
    for ex in "${EXCLUDE_DIRS[@]}"; do
        case "$p" in
            "$SCAN_DIR/$ex"/*) return 0 ;;
        esac
    done
    return 1
}

# ---------------------------------------------------------------------------
# Scan one file. Detects two shapes:
#
#   (1) Top-level `var NAME …` — column 0, optionally with a visibility
#       modifier (`public|internal|private`) or `lateinit`. Matches:
#           var foo = 0
#           public var foo: String = ""
#           internal lateinit var foo: Bridge
#
#   (2) `var` inside an `object X { … }` or `companion object { … }` body.
#       Approximated by tracking `object`-block brace depth — a `var` at
#       any depth inside an `object` block is flagged. This catches both
#       `object Foo { var bar = 0 }` and `class Foo { companion object {
#       var baz = 0 } }` at any file depth.
#
# Function-local `var` (inside `fun` bodies) is naturally scoped and
# intentionally ignored.
#
# Emits one record per hit:
#   FAIL<TAB>file<TAB>line<TAB>kind<TAB>name<TAB>text
# where kind is TOPLEVEL or OBJECT.
# ---------------------------------------------------------------------------
scan_file() {
    local file="$1"

    awk -v FILE="$file" '
    BEGIN {
        # object_depth[] — stack. Each entry is the brace depth at which
        # an `object`/`companion object` block was opened. While any entry
        # is <= current brace_depth, we are inside that object body.
        object_count = 0
        brace_depth = 0
    }

    {
        line = $0

        # Strip // line comments (be conservative — do not handle /* */
        # spans; the Kotlin sources we scan do not use block comments for
        # significant code).
        comment_free = line
        sub(/\/\/.*$/, "", comment_free)

        # ------------------------------------------------------------------
        # (1) Top-level detection — only valid when brace_depth == 0.
        # ------------------------------------------------------------------
        if (brace_depth == 0) {
            # Match: [modifiers] [lateinit] var NAME …
            # Modifiers: public|internal|private|protected|open|final|
            #   abstract|override|annotation|const|external|inline|tailrec|
            #   suspend — common Kotlin hat. We only need a non-greedy
            #   whitespace-separated prefix, so accept any sequence of
            #   identifier-like words before `var`.
            if (match(comment_free, /^[[:space:]]*(@[A-Za-z_][A-Za-z0-9_.]*(\([^)]*\))?[[:space:]]*)*((public|internal|private|protected|open|final|abstract|override|annotation|const|external|inline|tailrec|suspend)[[:space:]]+)*(lateinit[[:space:]]+)?var[[:space:]]+[A-Za-z_][A-Za-z0-9_]*/)) {
                # Extract the name — everything after the final `var `.
                tmp = comment_free
                sub(/.*var[[:space:]]+/, "", tmp)
                if (match(tmp, /^[A-Za-z_][A-Za-z0-9_]*/)) {
                    name = substr(tmp, RSTART, RLENGTH)
                    printf("FAIL\t%s\t%d\tTOPLEVEL\t%s\t%s\n",
                        FILE, NR, name, line)
                }
            }
        }

        # ------------------------------------------------------------------
        # (2) object-body detection — before we update the depth, check if
        # the current line introduces an `object` block.
        # ------------------------------------------------------------------
        # `object X {`, `companion object {`, `companion object Name {`
        if (match(comment_free, /(^|[^A-Za-z0-9_])object[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*(:[^{]+)?\{/) \
            || match(comment_free, /(^|[^A-Za-z0-9_])companion[[:space:]]+object([[:space:]]+[A-Za-z_][A-Za-z0-9_]*)?[[:space:]]*(:[^{]+)?\{/)) {
            # Push the current (pre-line) brace_depth. Any `var` seen
            # until brace_depth returns to this level+1 or below is inside
            # an object body. (+1 because the `{` in this line opens a
            # new scope, so "inside the body" = brace_depth > push value.)
            object_stack[object_count] = brace_depth
            object_count++
        }

        # Are we currently inside any object block?
        in_object = 0
        for (i = 0; i < object_count; i++) {
            # object body starts AFTER its opening `{`, so we are inside
            # when brace_depth > object_stack[i].
            if (brace_depth > object_stack[i]) {
                in_object = 1
                break
            }
        }

        # If inside an object body, look for `var NAME`. Exclude `val` and
        # `fun` lines.
        if (in_object) {
            if (match(comment_free, /^[[:space:]]*(@[A-Za-z_][A-Za-z0-9_.]*(\([^)]*\))?[[:space:]]*)*((public|internal|private|protected|open|final|abstract|override|annotation|const|external|inline|tailrec|suspend)[[:space:]]+)*(lateinit[[:space:]]+)?var[[:space:]]+[A-Za-z_][A-Za-z0-9_]*/)) {
                tmp = comment_free
                sub(/.*var[[:space:]]+/, "", tmp)
                if (match(tmp, /^[A-Za-z_][A-Za-z0-9_]*/)) {
                    name = substr(tmp, RSTART, RLENGTH)
                    printf("FAIL\t%s\t%d\tOBJECT\t%s\t%s\n",
                        FILE, NR, name, line)
                }
            }
        }

        # ------------------------------------------------------------------
        # Update brace depth AFTER processing, so the current line sees
        # the pre-line depth. Also pop closed `object` stack entries.
        # ------------------------------------------------------------------
        open_n = gsub(/\{/, "{", comment_free)
        close_n = gsub(/\}/, "}", comment_free)
        brace_depth += (open_n - close_n)
        if (brace_depth < 0) brace_depth = 0

        # Pop stack entries whose scope has closed.
        while (object_count > 0 && brace_depth <= object_stack[object_count - 1]) {
            object_count--
        }
    }
    ' "$file"
}

# ---------------------------------------------------------------------------
# Drive the scan.
# ---------------------------------------------------------------------------
if [[ ! -d "$SCAN_DIR" ]]; then
    printf '%serror:%s scan dir %s does not exist\n' \
        "$C_RED" "$C_RESET" "$SCAN_DIR" >&2
    exit 2
fi

TMPDIR_RESULT=$(mktemp -d)
trap 'rm -rf "$TMPDIR_RESULT"' EXIT

OUT_FILE="$TMPDIR_RESULT/scan.out"
: > "$OUT_FILE"

while IFS= read -r -d '' file; do
    if is_excluded_path "$file"; then
        continue
    fi
    scan_file "$file" >> "$OUT_FILE"
done < <(find "$SCAN_DIR" -type f -name '*.kt' -print0)

# Filter allowlist after the fact.
FINAL_OUT="$TMPDIR_RESULT/final.out"
: > "$FINAL_OUT"
ALLOW_N=0
while IFS=$'\t' read -r tag file line kind name text; do
    [[ "$tag" == "FAIL" ]] || continue
    if is_allowlisted "$name"; then
        ALLOW_N=$((ALLOW_N + 1))
        continue
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$tag" "$file" "$line" "$kind" "$name" "$text" >> "$FINAL_OUT"
done < "$OUT_FILE"

FAIL_N=$(grep -c $'^FAIL\t' "$FINAL_OUT" 2>/dev/null || true)
FAIL_N=${FAIL_N:-0}

printf '\n%skotlin mutable-global scan:%s\n' "$C_DIM" "$C_RESET"
printf '  allowlisted=%d  failed=%d\n' "$ALLOW_N" "$FAIL_N"

if [[ "$FAIL_N" -eq 0 ]]; then
    printf '%sPASSED%s: no disallowed top-level/object vars.\n' \
        "$C_GREEN" "$C_RESET"
    exit 0
fi

printf '\n%sFAILED%s: %d disallowed mutable declaration(s).\n' \
    "$C_RED" "$C_RESET" "$FAIL_N" >&2
printf '\n' >&2
printf 'Offending declarations:\n' >&2
while IFS=$'\t' read -r tag file line kind name text; do
    [[ "$tag" == "FAIL" ]] || continue
    printf '  %s%s:%s%s  %s[%s]%s  %s%s%s\n' \
        "$C_DIM" "$file" "$line" "$C_RESET" \
        "$C_YELLOW" "$kind" "$C_RESET" \
        "$C_YELLOW" "$name" "$C_RESET" >&2
done < "$FINAL_OUT"
printf '\n' >&2
printf 'A new top-level or object-member `var` must either:\n' >&2
printf '  1. live on the `Scp` class so it is per-instance, or\n' >&2
printf '  2. be added to the ALLOWLIST in\n' >&2
printf '     scripts/check-no-kotlin-mutable-globals.sh with a\n' >&2
printf '     justifying `// why:` comment on the declaration itself.\n' >&2
printf '\n' >&2
printf 'See ADR-048-scp-multi-instance.md.\n' >&2
exit 1
