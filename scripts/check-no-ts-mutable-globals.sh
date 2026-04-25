#!/usr/bin/env bash
# check-no-ts-mutable-globals.sh — CI gate forbidding new module-scope
# `let` declarations in the TypeScript SDK (`bindings/typescript/src/`).
#
# ---------------------------------------------------------------------------
# WHAT THIS CHECKS
# ---------------------------------------------------------------------------
# Phase 4 (#1549) removed process-wide default bridge instances. The
# TypeScript SDK exposes a `SCP` class per instance and no longer tolerates
# a `let _defaultBridge: Bridge | null = null` module cache outside of the
# specific allowlisted FFI addon loaders.
#
# This gate grep-scans every `.ts` file under `bindings/typescript/src/`
# (EXCLUDING type declaration files `*.d.ts`). Any line of the form
#
#   let FOO ...
#
# at column 0 (i.e. unindented — module scope) fails unless the name is on
# the explicit ALLOWLIST below. Indented `let` declarations (inside a
# function / class method body) are naturally scoped and ignored.
#
# Tests (`bindings/typescript/tests/`) are not scanned — test fixtures use
# `let scp: SCP;` in `beforeEach` hooks and similar patterns.
#
# ---------------------------------------------------------------------------
# ALLOWLIST
# ---------------------------------------------------------------------------
# Each entry is a single identifier name. A `let` at module scope passes
# if its name is in the list — AND ONLY if it is on the list. The backing
# rationale is documented below and, separately, as a code-comment on the
# declaration itself.
#
# ---------------------------------------------------------------------------
# HOW TO FIX A FAILURE
# ---------------------------------------------------------------------------
# The usual cause: a new module-scope `let _cached: Addon | null = null`.
#
#   1. Move the state onto the `SCP` class or a factory it returns — this
#      is the canonical pattern for per-instance state and the one the
#      TypeScript SDK already uses everywhere else.
#   2. If the state is genuinely a one-time FFI addon loader (analog to
#      the Rust `RUNTIME` static), add the name to ALLOWLIST below AND
#      add a `// why:` comment above the declaration.
#
# Do NOT convert `let` to `var` to bypass the gate — the pattern matches
# `var` too. Do NOT move the declaration into a `(function(){})()` IIFE
# wrapper to hide it from column-0 grep — reviewers will notice.
#
# ---------------------------------------------------------------------------
# PORTABILITY
# ---------------------------------------------------------------------------
# Runs on macOS (BSD userland) and Linux (GNU userland). Uses only POSIX-
# compatible bash, awk, grep features.
#
# Usage:
#   bash scripts/check-no-ts-mutable-globals.sh
# Exit codes:
#   0  — all module-scope `let` declarations are allowlisted
#   1  — a disallowed module-scope `let` declaration was added
#   2  — invocation error (missing directory)

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
# Allowlist of module-scope `let` identifiers. Every entry is tied to a
# one-time FFI-addon cache — the direct TypeScript analog of the Rust
# `RUNTIME` static. Each backing source declaration carries a `// why:`
# comment.
# ---------------------------------------------------------------------------
ALLOWLIST=(
    # internal/bridge.ts — cached Bridge instance, initialized exactly once
    # on first async SDK call (napi or WASM path selected by BRIDGE_TARGET).
    # Reset-on-test-only helper `_resetBridge` exists for test isolation.
    _bridge
    # internal/wasm.ts — cached WASM module and its one-shot init promise.
    # WASM init is intrinsically per-process (wasm-bindgen `__wbindgen_init`
    # writes global state in the WebAssembly instance).
    _wasmModule
    _initPromise
    # scp.ts — lazy-resolved napi native constructor.
    _nativeScp
    # mcp.ts — cached napi addon handle for MCP bridge functions.
    _mcpAddon
    # server.ts — cached napi addon handle for Server bridge functions.
    _addon
    # internal/bridge.ts — WASM runtime is intrinsically process-wide
    # (wasm-bindgen writes global state in the WebAssembly instance);
    # cannot be per-SCP like the native bridge. See ADR-048.
    _wasmBridge
)

SCAN_DIR="bindings/typescript/src"

# ---------------------------------------------------------------------------
# Allowlist membership test.
# ---------------------------------------------------------------------------
is_allowlisted() {
    local name="$1"
    for allow in "${ALLOWLIST[@]}"; do
        [[ "$name" == "$allow" ]] && return 0
    done
    return 1
}

# ---------------------------------------------------------------------------
# Scan. Emits one record per hit:
#   ALLOW<TAB>file<TAB>line<TAB>name
#   FAIL<TAB>file<TAB>line<TAB>name
#
# Module-scope detection: a `let` or `var` declaration with no leading
# whitespace. TypeScript module-level code is always at column 0; any
# other position is inside a block.
# ---------------------------------------------------------------------------
scan_file() {
    local file="$1"
    local allow_list_str
    allow_list_str="$(printf '%s|' "${ALLOWLIST[@]}")"

    awk -v FILE="$file" -v ALLOW="$allow_list_str" '
    BEGIN {
        n = split(ALLOW, arr, "|")
        for (i = 1; i <= n; i++) {
            if (arr[i] != "") allow_map[arr[i]] = 1
        }
    }
    # Match `let NAME` or `var NAME` at column 0. `export let NAME` and
    # `export var NAME` are also module-scope and must be covered. `const`
    # is immutable by binding and passes this gate trivially.
    /^(export[[:space:]]+)?(let|var)[[:space:]]+[A-Za-z_$][A-Za-z0-9_$]*/ {
        line = $0
        # Peel the optional `export ` prefix.
        sub(/^(export[[:space:]]+)?(let|var)[[:space:]]+/, "", line)
        # The identifier is the leading run of identifier chars.
        if (match(line, /^[A-Za-z_$][A-Za-z0-9_$]*/)) {
            name = substr(line, RSTART, RLENGTH)
            if (name in allow_map) {
                printf("ALLOW\t%s\t%d\t%s\n", FILE, NR, name)
            } else {
                printf("FAIL\t%s\t%d\t%s\n", FILE, NR, name)
            }
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
    case "$file" in
        *.d.ts) continue ;;  # ambient type declarations — no runtime code
    esac
    scan_file "$file" >> "$OUT_FILE"
done < <(find "$SCAN_DIR" -type f -name '*.ts' -print0)

FAIL_N=$(grep -c $'^FAIL\t' "$OUT_FILE" 2>/dev/null || true)
ALLOW_N=$(grep -c $'^ALLOW\t' "$OUT_FILE" 2>/dev/null || true)
FAIL_N=${FAIL_N:-0}
ALLOW_N=${ALLOW_N:-0}

printf '\n%sts mutable-global scan:%s\n' "$C_DIM" "$C_RESET"
printf '  allowlisted=%d  failed=%d\n' "$ALLOW_N" "$FAIL_N"

if [[ "$FAIL_N" -eq 0 ]]; then
    printf '%sPASSED%s: no disallowed module-scope let/var in src/.\n' \
        "$C_GREEN" "$C_RESET"
    exit 0
fi

printf '\n%sFAILED%s: %d disallowed module-scope let/var declaration(s).\n' \
    "$C_RED" "$C_RESET" "$FAIL_N" >&2
printf '\n' >&2
printf 'Offending declarations:\n' >&2
while IFS=$'\t' read -r tag file line name; do
    [[ "$tag" == "FAIL" ]] || continue
    printf '  %s%s:%s%s  %s%s%s\n' \
        "$C_DIM" "$file" "$line" "$C_RESET" \
        "$C_YELLOW" "$name" "$C_RESET" >&2
done < "$OUT_FILE"
printf '\n' >&2
printf 'A new module-scope `let`/`var` must either:\n' >&2
printf '  1. live on a class (SCP, Context, …) so it is per-instance, or\n' >&2
printf '  2. be added to the ALLOWLIST in\n' >&2
printf '     scripts/check-no-ts-mutable-globals.sh with a justifying\n' >&2
printf '     `// why:` comment on the declaration itself.\n' >&2
printf '\n' >&2
printf 'See ADR-048-scp-multi-instance.md.\n' >&2
exit 1
