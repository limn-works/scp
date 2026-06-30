#!/usr/bin/env bash
# check-no-bridge-globals.sh — CI gate enforcing the "no new process-global
# statics in FFI bridges" invariant introduced by #1549 Phase 4.
#
# ---------------------------------------------------------------------------
# WHAT THIS CHECKS
# ---------------------------------------------------------------------------
# Every module-level `static` declaration in the three FFI bridges
#   crates/scp-ffi/src/        (PyO3   — #[pyfunction])
#   crates/scp-ffi/napi/src/   (NAPI   — #[napi])
#   crates/scp-ffi/uniffi/src/ (UniFFI — #[uniffi::export])
#   crates/scp-ffi/common/src/ (shared bridge-runtime helpers)
# must either
#   (a) be on the explicit allowlist of process-global statics that the plan
#       deliberately retained (RUNTIME, HANDLE_COUNT,
#       SHARED_DHT_CLIENT, INSTANCE_ID_COUNTER, or a `std::sync::Once` init
#       guard used for one-time setup like `tracing_subscriber::init`), OR
#   (b) be grandfathered against the ratchet baseline in
#       `ratchet/once-lock-count.json`.
#
# Case (b) previously covered the `EMPTY_*` fallback registries that existed
# while the default-instance façade was live. Phase 4 PR 4 (#1549) deleted
# `DEFAULT_BRIDGE_INSTANCE` along with every `EMPTY_*` registry, so the
# ratchet now floors at zero in every bridge (see
# `ratchet/once-lock-count.json`). The gate fails if the count goes **up** —
# i.e. a new module-level static was added.
#
# Function-local `static` declarations are scanned too when their type matches
# a process-global *sharing* primitive:
#   OnceLock<…>, LazyLock<…>, Mutex<…>, RwLock<…>,
#   parking_lot::Mutex<…>, parking_lot::RwLock<…>.
# These primitives all have the same 'static lifetime and cross-invocation
# sharing semantics as a module-level static — moving the declaration into a
# function body only changes the *namespace*, not the process-global behavior.
# A PR #1699 review flagged the old "function-local means ignored" rule as a
# loophole; widening here closes it.
#
# Function-local statics of *naturally function-scoped* types — atomics
# (`AtomicU64`, `AtomicBool`, …) used as local counters/flags, `Cell`,
# `RefCell` — remain ignored: they are not cross-invocation sharing primitives.
#
# Test-gated statics (inside `#[cfg(test)]` or `mod tests`) are ignored —
# tests are allowed to use whatever local singletons they need.
#
# ---------------------------------------------------------------------------
# WHEN THIS RUNS
# ---------------------------------------------------------------------------
# Gated on every PR touching `crates/scp-ffi/**` once PR 2 of the Phase 4
# remainder (#1549) lands.
#
# ---------------------------------------------------------------------------
# HOW TO FIX A FAILURE
# ---------------------------------------------------------------------------
# The usual cause: a new `static FOO: OnceLock<Bar> = OnceLock::new();` was
# added at module scope — or inside a helper fn body with one of the
# process-global sharing types (OnceLock / LazyLock / Mutex / RwLock /
# parking_lot::Mutex / parking_lot::RwLock). Function scope does NOT
# launder process-global semantics — it only changes the namespace. Do
# one of:
#
#   1. Move the state onto `PyBridgeInstance` / `NapiBridgeInstance` /
#      `UniffiBridgeInstance` (or their `CoreFields`) as a typed field. This
#      is the default — every new piece of per-bridge state belongs on the
#      bridge instance so that `SCP::new()` isolates it.
#
#   2. If the state is genuinely process-global (e.g. a tokio runtime slot,
#      a shared test-DHT client), extend the allowlist in this script AND
#      document why in a doc-comment on the static itself. Expect pushback.
#
# Do NOT simply bump the ratchet count to paper over a new static — that
# defeats the purpose of the gate. Adding to the allowlist or adding a new
# field on a bridge instance is always the right move.
#
# ---------------------------------------------------------------------------
# PORTABILITY
# ---------------------------------------------------------------------------
# Runs on macOS (BSD userland) and Linux (GNU userland). Uses only POSIX-
# compatible bash, awk, grep features.
#
# Usage:
#   bash scripts/check-no-bridge-globals.sh
# Exit codes:
#   0  — no new bridge globals (allowlisted + within ratchet)
#   1  — a module-level static was added that is neither allowlisted nor
#        within the ratchet baseline
#   2  — invocation error (missing directory, invalid ratchet JSON)

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
# Allowlist of module-level static NAMES that the plan deliberately retains
# as process-global. Any other module-level static is counted against the
# ratchet.
#
# `DEFAULT_BRIDGE_INSTANCE` was removed from this allowlist in Phase 4 PR 4
# (2026-04-19) — the OnceLock itself was deleted alongside the free-function
# façade in that PR, so any new occurrence is a regression, not a permitted
# global.
ALLOWLIST=(
    RUNTIME
    HANDLE_COUNT
    SHARED_DHT_CLIENT
    INSTANCE_ID_COUNTER
    # NETWORK: function-local `static NETWORK: OnceLock<Mutex<Option<FullStackNetwork>>>`
    # in crates/scp-ffi/napi/src/testing.rs — process-global by necessity for the
    # cross-test-file full-stack harness. The `testing` module is feature-gated
    # behind `allow_in_memory_custody` in lib.rs (`#[cfg(feature = "allow_in_memory_custody")] pub mod testing;`)
    # and is never compiled into production builds. See the doc-comment on the
    # declaration itself for the full rationale (PR #1699 review follow-up).
    NETWORK
)

# Per-bridge: label, directory
BRIDGES=(
    "pyo3|crates/scp-ffi/src"
    "napi|crates/scp-ffi/napi/src"
    "uniffi|crates/scp-ffi/uniffi/src"
    "common|crates/scp-ffi/common/src"
)

RATCHET_FILE="$REPO_ROOT/ratchet/once-lock-count.json"

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
# Scan one bridge.
#
# Emits one of:
#   ALLOW<TAB>file<TAB>line<TAB>name<TAB>type         — allowlisted (module- or fn-local)
#   ONCE<TAB>file<TAB>line<TAB>name<TAB>type          — `Once` init guard (allowlisted)
#   COUNT<TAB>file<TAB>line<TAB>name<TAB>type         — module-level, counted against ratchet
#   COUNT_FN_LOCAL<TAB>file<TAB>line<TAB>name<TAB>type — function-local sharing primitive, counted
#   TEST<TAB>file<TAB>line<TAB>name<TAB>type          — test-gated, ignored
#
# Strategy:
#   - Walk each `.rs` under the bridge dir line-by-line.
#   - Track `#[cfg(test)]` / `mod tests {` scope via brace balance.
#   - At brace depth 0 (module level), every `static NAME: TYPE` is a
#     candidate. Name determines ALLOW, type determines ONCE; fallback is
#     COUNT.
#   - At brace depth > 0 (function body), only `static NAME: TYPE` where
#     `TYPE` starts with / contains one of the process-global *sharing*
#     primitives (`OnceLock`, `LazyLock`, `Mutex`, `RwLock`,
#     `parking_lot::Mutex`, `parking_lot::RwLock`) is a candidate. Atomics
#     and `Cell` / `RefCell` are function-scoped by design and ignored.
#     Candidates are tagged ALLOW (by name) or COUNT_FN_LOCAL (counted
#     against the ratchet as a regular global would be). ONCE init guards
#     at function scope are rare but still tagged ONCE if they match.
# ---------------------------------------------------------------------------
scan_bridge() {
    local bridge_name="$1"
    local bridge_dir="$2"

    if [[ ! -d "$bridge_dir" ]]; then
        printf '%swarning:%s bridge dir %s does not exist, skipping %s\n' \
            "$C_YELLOW" "$C_RESET" "$bridge_dir" "$bridge_name" >&2
        return 0
    fi

    local allow_list_str
    # Use `|` as separator — BSD awk does not accept embedded newlines in -v
    # values, so flatten the allowlist into a single delimited string.
    allow_list_str="$(printf '%s|' "${ALLOWLIST[@]}")"

    # shellcheck disable=SC2016
    find "$bridge_dir" -type f -name '*.rs' -print0 \
        | while IFS= read -r -d '' file; do
            awk \
                -v FILE="$file" \
                -v ALLOW="$allow_list_str" '
            BEGIN {
                # Build allowlist map from the `|`-delimited input.
                n = split(ALLOW, arr, "|")
                for (i = 1; i <= n; i++) {
                    if (arr[i] != "") allow_map[arr[i]] = 1
                }
                # `in_test_depth > 0` ⇒ current line is inside a cfg(test)
                # or `mod tests { }` block.
                in_test_depth = 0
                pending_cfg_test = 0
                # Brace depth OUTSIDE any test mod. A module-level item is
                # one where brace_depth == 0 AND in_test_depth == 0.
                brace_depth = 0
                # True on the same line that opens a test mod — suppresses
                # double-counting of the `{` that appears on that line.
                entered_test_this_line = 0
            }

            {
                line = $0
                entered_test_this_line = 0

                # Count braces before doing anything else so brace_depth
                # reflects the depth AT this line (we always treat the
                # current line as being at the pre-line depth — static
                # declarations occur before the `{` that begins their
                # initializer, if any).
                # We compute open/close counts but defer applying them
                # until after we have decided whether this is a static.
                open_n = gsub(/\{/, "{", line)
                close_n = gsub(/\}/, "}", line)

                # Refresh line after gsub (gsub mutates line).
                line = $0

                # cfg(test) detection: look for `#[cfg(test)]` followed by
                # a `mod X {`.
                if (match(line, /#\[cfg\(test\)\]/)) {
                    pending_cfg_test = 1
                }
                # Also treat `mod tests {` as a test scope even without
                # #[cfg(test)] — many files use that convention.
                if (match(line, /mod[[:space:]]+tests[[:space:]]*\{/)) {
                    in_test_depth++
                    pending_cfg_test = 0
                    entered_test_this_line = 1
                }
                else if (pending_cfg_test && match(line, /mod[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*\{/)) {
                    in_test_depth++
                    pending_cfg_test = 0
                    entered_test_this_line = 1
                }
                else if (pending_cfg_test && match(line, /^[[:space:]]*$/) == 0 && match(line, /#\[/) == 0) {
                    pending_cfg_test = 0
                }

                # Look for a `static NAME: TYPE ...` declaration whenever we
                # are NOT in a test scope. Two cases:
                #   - brace_depth == 0: module-level static (always a
                #     candidate). Tagged ALLOW / ONCE / COUNT.
                #   - brace_depth  > 0: function-local static. Only a
                #     candidate when TYPE is a process-global *sharing*
                #     primitive (OnceLock / LazyLock / Mutex / RwLock /
                #     parking_lot::Mutex / parking_lot::RwLock). Atomics
                #     and Cell/RefCell are ignored. Tagged ALLOW / ONCE /
                #     COUNT_FN_LOCAL.
                # Patterns recognized:
                #   static NAME: TYPE = ... ;
                #   pub static NAME: TYPE = ... ;
                #   pub(crate) static NAME: TYPE = ... ;
                if (in_test_depth == 0) {
                    sp = "^[[:space:]]*(pub(\\([a-z]+\\))?[[:space:]]+)?static[[:space:]]+"
                    if (match(line, sp "[A-Za-z_][A-Za-z0-9_]*[[:space:]]*:")) {
                        # Extract name: everything between `static` and `:`.
                        tmp = line
                        sub(/^[[:space:]]*(pub(\([a-z]+\))?[[:space:]]+)?static[[:space:]]+/, "", tmp)
                        colon_pos = index(tmp, ":")
                        name = substr(tmp, 1, colon_pos - 1)
                        sub(/[[:space:]]+$/, "", name)
                        sub(/^[[:space:]]+/, "", name)
                        type_str = substr(tmp, colon_pos + 1)
                        sub(/^[[:space:]]+/, "", type_str)
                        # Strip trailing `= ...; or `=...`
                        eq_pos = index(type_str, "=")
                        if (eq_pos > 0) {
                            type_str = substr(type_str, 1, eq_pos - 1)
                        }
                        sub(/[[:space:]]+$/, "", type_str)
                        # Compact internal whitespace in type_str for
                        # reporting.
                        gsub(/[[:space:]]+/, " ", type_str)

                        # Detect a function-local sharing primitive. We
                        # match either a bare identifier followed by `<`
                        # or end-of-type, or a `parking_lot::` qualified
                        # form — these are the types whose semantics are
                        # unchanged by function scope.
                        is_sharing_type = 0
                        if (match(type_str, /(^|[^A-Za-z0-9_:])(OnceLock|LazyLock|Mutex|RwLock)([^A-Za-z0-9_]|$)/)) {
                            is_sharing_type = 1
                        } else if (match(type_str, /parking_lot::(Mutex|RwLock)([^A-Za-z0-9_]|$)/)) {
                            is_sharing_type = 1
                        }

                        # Skip function-local statics whose type is NOT a
                        # sharing primitive — those are naturally
                        # function-scoped (atomics, Cell, RefCell, etc.).
                        if (brace_depth == 0 || is_sharing_type) {
                            # Determine tag.
                            if (name in allow_map) {
                                tag = "ALLOW"
                            } else if (match(type_str, /(^|::)Once([^A-Za-z0-9_]|$)/)) {
                                # Once init guards (std::sync::Once or
                                # parking_lot::Once) are treated as
                                # allowlisted — they exist to run a
                                # one-shot init closure.
                                tag = "ONCE"
                            } else if (brace_depth > 0) {
                                # Function-local sharing primitive that
                                # is neither allowlisted nor a `Once`
                                # init guard — count it as a global by
                                # any other name.
                                tag = "COUNT_FN_LOCAL"
                            } else {
                                tag = "COUNT"
                            }

                            printf("%s\t%s\t%d\t%s\t%s\n",
                                tag, FILE, NR, name, type_str)
                        }
                    }
                }

                # Apply brace delta now so the NEXT line sees correct depth.
                #
                # `brace_depth` tracks absolute file brace nesting — it sees
                # every `{` and `}` including the one that opens a test mod.
                # `in_test_depth` is a counter of "braces below the entry
                # into a test scope" plus 1 for the entry itself. On the
                # line that enters a test mod, we already incremented
                # `in_test_depth` by 1 to represent the entry — consuming
                # the mods opening `{`. If we also applied the full
                # `(open_n - close_n)` delta to `in_test_depth` on that
                # line, the opening `{` would be double-counted and the
                # counter would never return to zero when the mod closes.
                # Skip that brace on the entry line only.
                test_brace_delta = (entered_test_this_line ? (open_n - 1 - close_n) : (open_n - close_n))
                brace_depth += (open_n - close_n)
                if (brace_depth < 0) brace_depth = 0
                in_test_depth += (in_test_depth > 0 ? test_brace_delta : 0)
                if (in_test_depth < 0) in_test_depth = 0
            }
            ' "$file"
        done
}

# ---------------------------------------------------------------------------
# Drive the scan
# ---------------------------------------------------------------------------
TMPDIR_RESULT=$(mktemp -d)
trap 'rm -rf "$TMPDIR_RESULT"' EXIT

for entry in "${BRIDGES[@]}"; do
    IFS='|' read -r bridge_name bridge_dir <<< "$entry"
    out_file="$TMPDIR_RESULT/$bridge_name.out"
    scan_bridge "$bridge_name" "$bridge_dir" > "$out_file"
done

# ---------------------------------------------------------------------------
# Load ratchet baseline
# ---------------------------------------------------------------------------
if [[ ! -f "$RATCHET_FILE" ]]; then
    printf '%serror:%s ratchet file missing: %s\n' \
        "$C_RED" "$C_RESET" "$RATCHET_FILE" >&2
    printf 'Create it with the current counts per bridge:\n' >&2
    for entry in "${BRIDGES[@]}"; do
        IFS='|' read -r bridge_name _ <<< "$entry"
        out_file="$TMPDIR_RESULT/$bridge_name.out"
        cnt=$(grep -c $'^COUNT\t' "$out_file" 2>/dev/null || true)
        cnt=${cnt:-0}
        printf '  %s: %d\n' "$bridge_name" "$cnt" >&2
    done
    exit 2
fi

# Extract baseline counts per bridge via python (avoids jq dependency).
# macOS bash 3.2 has no associative arrays — use a delimited string instead.
BASELINE_STR=$(python3.12 -c "
import json, sys
with open('$RATCHET_FILE') as f:
    data = json.load(f)
for k, v in data.get('bridges', {}).items():
    print(f'{k}={v}')
" 2>/dev/null) || {
    printf '%serror:%s failed to parse %s\n' \
        "$C_RED" "$C_RESET" "$RATCHET_FILE" >&2
    exit 2
}

# Helper: look up baseline count for a bridge name. Prints the count or the
# sentinel `MISSING`. Uses the `BASELINE_STR` multi-line string built above.
baseline_for() {
    local target="$1"
    local line
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local k="${line%%=*}"
        local v="${line#*=}"
        if [[ "$k" == "$target" ]]; then
            printf '%s' "$v"
            return 0
        fi
    done <<< "$BASELINE_STR"
    printf 'MISSING'
}

# ---------------------------------------------------------------------------
# Aggregate + compare to baseline
# ---------------------------------------------------------------------------
TOTAL_FAIL=0
TOTAL_COUNTED=0
TOTAL_ALLOW=0
TOTAL_ONCE=0

printf '\n%sbridge-globals scan:%s\n' "$C_DIM" "$C_RESET"

for entry in "${BRIDGES[@]}"; do
    IFS='|' read -r bridge_name _ <<< "$entry"
    out_file="$TMPDIR_RESULT/$bridge_name.out"

    count_mod_n=$(grep -c $'^COUNT\t' "$out_file" 2>/dev/null || true)
    count_fn_n=$(grep -c $'^COUNT_FN_LOCAL\t' "$out_file" 2>/dev/null || true)
    allow_n=$(grep -c $'^ALLOW\t' "$out_file" 2>/dev/null || true)
    once_n=$(grep -c $'^ONCE\t' "$out_file" 2>/dev/null || true)
    count_mod_n=${count_mod_n:-0}
    count_fn_n=${count_fn_n:-0}
    allow_n=${allow_n:-0}
    once_n=${once_n:-0}
    # Function-local sharing-primitive statics are counted against the
    # ratchet exactly like module-level ones — function scope doesn't
    # change process-global semantics.
    count_n=$((count_mod_n + count_fn_n))

    baseline="$(baseline_for "$bridge_name")"

    TOTAL_COUNTED=$((TOTAL_COUNTED + count_n))
    TOTAL_ALLOW=$((TOTAL_ALLOW + allow_n))
    TOTAL_ONCE=$((TOTAL_ONCE + once_n))

    if [[ "$baseline" == "MISSING" ]]; then
        printf '  %s[%s]%s counted=%d baseline=%sMISSING%s (add to ratchet)\n' \
            "$C_RED" "$bridge_name" "$C_RESET" "$count_n" "$C_RED" "$C_RESET" >&2
        TOTAL_FAIL=$((TOTAL_FAIL + 1))
        continue
    fi

    if [[ "$count_n" -gt "$baseline" ]]; then
        printf '  %s[%s]%s counted=%d baseline=%d %s(+%d, FAIL)%s\n' \
            "$C_RED" "$bridge_name" "$C_RESET" "$count_n" "$baseline" \
            "$C_RED" $((count_n - baseline)) "$C_RESET" >&2
        printf '    new/unratcheted statics:\n' >&2
        while IFS=$'\t' read -r tag file line name type_str; do
            case "$tag" in
                COUNT) scope_label="" ;;
                COUNT_FN_LOCAL) scope_label=" ${C_YELLOW}[fn-local]${C_RESET}" ;;
                *) continue ;;
            esac
            printf '      %s%s:%s%s  %sstatic %s%s  (%s%s%s)%s\n' \
                "$C_DIM" "$file" "$line" "$C_RESET" \
                "$C_YELLOW" "$name" "$C_RESET" \
                "$C_DIM" "$type_str" "$C_RESET" \
                "$scope_label" >&2
        done < "$out_file"
        TOTAL_FAIL=$((TOTAL_FAIL + 1))
    elif [[ "$count_n" -lt "$baseline" ]]; then
        printf '  %s[%s]%s counted=%d baseline=%d %s(-%d — ratchet can drop)%s\n' \
            "$C_GREEN" "$bridge_name" "$C_RESET" "$count_n" "$baseline" \
            "$C_GREEN" $((baseline - count_n)) "$C_RESET"
    else
        printf '  %s[%s]%s counted=%d baseline=%d (OK)\n' \
            "$C_GREEN" "$bridge_name" "$C_RESET" "$count_n" "$baseline"
    fi
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
printf '\n'
printf 'allowlisted=%d  once-guards=%d  counted=%d\n' \
    "$TOTAL_ALLOW" "$TOTAL_ONCE" "$TOTAL_COUNTED"

if [[ "$TOTAL_FAIL" -eq 0 ]]; then
    printf '%sPASSED%s: no new bridge globals beyond ratchet baseline.\n' \
        "$C_GREEN" "$C_RESET"
    exit 0
fi

printf '%sFAILED%s: %d bridge(s) exceed their ratchet baseline.\n' \
    "$C_RED" "$C_RESET" "$TOTAL_FAIL" >&2
printf '\n' >&2
printf 'New bridge globals must either:\n' >&2
printf '  1. live on PyBridgeInstance / NapiBridgeInstance / UniffiBridgeInstance\n' >&2
printf '     (preferred — per-instance isolation), or\n' >&2
printf '  2. be added to the allowlist in scripts/check-no-bridge-globals.sh\n' >&2
printf '     with a justifying doc-comment on the static.\n' >&2
printf '\n' >&2
printf 'Bumping the ratchet to accept a new global is NOT a valid fix.\n' >&2
printf '\n' >&2
printf 'See .docs/adrs/ADR-048-scp-multi-instance.md for rationale.\n' >&2

exit 1
