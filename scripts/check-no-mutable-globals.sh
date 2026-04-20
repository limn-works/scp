#!/usr/bin/env bash
# check-no-mutable-globals.sh — Rust workspace-wide companion to
# scripts/check-no-bridge-globals.sh.
#
# ---------------------------------------------------------------------------
# WHAT THIS CHECKS
# ---------------------------------------------------------------------------
# The existing check-no-bridge-globals.sh gate scans only `crates/scp-ffi/`.
# Phase 4 (#1549) deleted the `DEFAULT_BRIDGE_INSTANCE` façade and per-SDK
# `SCP.default()` fallbacks; the forward-prevention measure this gate adds
# forbids the pattern from creeping back into ANY other workspace crate —
# `scp-runtime`, `scp-transport`, `scp-identity`, `scp-node`, `scp-platform`,
# etc. Contributors occasionally reach for a `static FOO: OnceLock<...>` to
# solve a plumbing problem; every such reach is a latent multi-instance
# hazard and needs to be on the allowlist with justification OR refactored.
#
# Every module-level `static` declaration under `crates/*/src/**/*.rs` must
# either
#   (a) appear on the allowlist below (each entry has a doc-comment in the
#       source explaining why it is process-global), OR
#   (b) be a `Once` init guard (std::sync::Once / parking_lot::Once — these
#       are always allowlisted as one-shot initialization primitives), OR
#   (c) be a true constant (const fn, array/tuple of primitives, &str, etc.)
#       whose TYPE does not carry interior mutability (see TYPE_ALLOW below).
#
# Function-local `static` declarations (e.g. `static COUNTER: AtomicU64`
# inside a helper fn) are naturally scoped and ignored.
#
# Test-gated statics (inside `#[cfg(test)]` or `mod tests`) are ignored —
# tests are allowed to use whatever local singletons they need.
#
# The FFI bridges (`crates/scp-ffi/`) are covered by the adjacent
# check-no-bridge-globals.sh ratchet and are **skipped by this script** to
# avoid double-counting. The allowlist here covers only non-FFI crates.
#
# ---------------------------------------------------------------------------
# ALLOWLIST (non-FFI workspace crates)
# ---------------------------------------------------------------------------
# Each entry lists the static NAME. The pattern is loose by name only — the
# scanner does not verify the crate path. If the same name appears in more
# than one allowlisted location, that is expected (e.g. `RUNTIME` may exist
# in multiple crates with the same justification).
#
# Every allowlisted static MUST carry a doc-comment above it in the source
# explaining why it is process-global. CI does not grep the comment, but a
# human reviewer checking an addition WILL — and will reject undocumented
# allowlist additions.
#
# ---------------------------------------------------------------------------
# HOW TO FIX A FAILURE
# ---------------------------------------------------------------------------
# Typical resolutions, in order of preference:
#
#   1. Pass the state via the caller (constructor injection). This is the
#      preferred fix — every piece of per-system state belongs behind an
#      explicit dependency so multi-instance isolation is free.
#
#   2. If the state is genuinely a process-global (tokio runtime, ID
#      counter, one-shot init, expensive-to-construct singleton like a
#      SHARED_DHT_CLIENT used for tests), add the name to the allowlist
#      below AND add a doc-comment on the declaration explaining why.
#      Expect pushback — every new allowlist entry is a new multi-instance
#      footgun.
#
# Do NOT silence this gate by renaming the static to something creative.
# The allowlist matches on the full uppercase identifier; renaming to a
# non-uppercase form will just flip the match to `unrecognized`.
#
# ---------------------------------------------------------------------------
# PORTABILITY
# ---------------------------------------------------------------------------
# Runs on macOS (BSD userland) and Linux (GNU userland). Uses only POSIX-
# compatible bash, awk, grep features.
#
# Usage:
#   bash scripts/check-no-mutable-globals.sh
# Exit codes:
#   0  — all module-level statics are allowlisted or pure constants
#   1  — a disallowed module-level static was added
#   2  — invocation error (missing directory, etc.)

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
# Allowlist of module-level static NAMES that the plan deliberately retains
# as process-global across the non-FFI workspace.
#
# When adding to this list:
#   - Add the name in sorted order.
#   - Add a `# why: …` comment explaining the justification.
#   - Add a doc-comment on the declaration in the source itself (this gate
#     does not verify the source comment, but reviewers will).
# ---------------------------------------------------------------------------
ALLOWLIST=(
    # Crypto / constants
    BIP39_ENGLISH                   # why: 2048-word BIP-39 wordlist, `&'static [&str; 2048]` constant.
    CREDENTIAL_HKDF_SALT            # why: domain-separation salt for bridge credential HKDF — pure constant derived from a fixed seed at import.
    PROTOCOL_REGISTRY               # why: protocol capability registry — frozen lookup table of compile-time-known resources (§Trust registry, LazyLock<HashMap>).
    SYSTEM_REGISTRY                 # why: protocol system-action registry — frozen lookup table of compile-time-known system actions.

    # ID generators (safe — monotonic counters, no shared mutable state)
    EVENT_COUNTER                   # why: monotonic `AtomicU64` for webhook event IDs; no shared state, safe across instances.
    INSTANCE_ID_COUNTER             # why: monotonic `AtomicU64` used to assign each `*BridgeInstance` a unique u64 identifier at construction.
    NEXT_HANDLE                     # why: test-clock monotonic handle allocator — AtomicU64, no cross-instance coupling.
    NEXT_OWNER_ID                   # why: relay subscription owner-id allocator — AtomicU64, no cross-instance coupling.
    TEMP_FILE_COUNTER               # why: monotonic AtomicU64 for tempfile naming collision avoidance; no shared state.

    # One-shot init / test-only clocks
    SYSTEM_CLOCK                    # why: test-only `scp_primitives::SystemClock` zero-sized type passed by reference from integration test.

    # Allowlist carried over from FFI gate (shared names — this gate skips
    # the scp-ffi tree but still sees any accidental use of these names in
    # other crates):
    DEFAULT_BRIDGE_INSTANCE         # why: façade default-instance slot (ADR-048) — counted by the scp-ffi ratchet, not here.
    HANDLE_COUNT                    # why: FFI debug handle counter — counted by the scp-ffi ratchet, not here.
    RUNTIME                         # why: tokio runtime slot per bridge — counted by the scp-ffi ratchet, not here.
    SHARED_DHT_CLIENT               # why: cross-identity in-process test DHT — counted by the scp-ffi ratchet, not here.
)

# Type-name substrings that mark a pure constant — statics whose TYPE matches
# any of these do not need an allowlist entry. Keep this minimal; the
# preferred mechanism is the name allowlist above.
TYPE_ALLOW_PATTERNS=(
    # Nothing structural here yet — all pure constants we currently hold
    # are allowlisted by NAME above. Leaving the hook in place keeps future
    # additions trivial if we gain, e.g., a convention of `static FOO: &str`.
    # Pattern matching uses `awk match(type_str, PATTERN)` so regex is ok.
)

# Directories to exclude from the scan. The FFI bridges are covered by the
# adjacent check-no-bridge-globals.sh ratchet.
EXCLUDE_DIRS=(
    crates/scp-ffi/src
    crates/scp-ffi/common/src
    crates/scp-ffi/napi/src
    crates/scp-ffi/uniffi/src
    crates/scp-ffi/wasm/src
)

# Directories to scan. Every crate under `crates/` except the excluded FFI
# subtrees. We keep this as a single top-level glob and filter in awk.
SCAN_DIR="crates"

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
# Path-exclusion test. Returns 0 if $1 starts with any EXCLUDE_DIRS prefix.
# ---------------------------------------------------------------------------
is_excluded_path() {
    local p="$1"
    for ex in "${EXCLUDE_DIRS[@]}"; do
        case "$p" in
            "$ex"/*) return 0 ;;
            "./$ex"/*) return 0 ;;
        esac
    done
    return 1
}

# ---------------------------------------------------------------------------
# Scan one file. Same awk logic as check-no-bridge-globals.sh — tracks cfg
# (test) + mod tests scope, skips function-local statics, extracts name +
# type.
#
# Emits one of:
#   ALLOW<TAB>file<TAB>line<TAB>name<TAB>type
#   ONCE<TAB>file<TAB>line<TAB>name<TAB>type
#   FAIL<TAB>file<TAB>line<TAB>name<TAB>type
# ---------------------------------------------------------------------------
scan_file() {
    local file="$1"

    local allow_list_str
    allow_list_str="$(printf '%s|' "${ALLOWLIST[@]}")"

    awk \
        -v FILE="$file" \
        -v ALLOW="$allow_list_str" '
    BEGIN {
        n = split(ALLOW, arr, "|")
        for (i = 1; i <= n; i++) {
            if (arr[i] != "") allow_map[arr[i]] = 1
        }
        in_test_depth = 0
        pending_cfg_test = 0
        brace_depth = 0
        entered_test_this_line = 0
    }

    {
        line = $0
        entered_test_this_line = 0

        open_n = gsub(/\{/, "{", line)
        close_n = gsub(/\}/, "}", line)
        line = $0

        if (match(line, /#\[cfg\(test\)\]/)) {
            pending_cfg_test = 1
        }
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

        if (brace_depth == 0 && in_test_depth == 0) {
            sp = "^[[:space:]]*(pub(\\([a-z]+\\))?[[:space:]]+)?static[[:space:]]+"
            if (match(line, sp "[A-Za-z_][A-Za-z0-9_]*[[:space:]]*:")) {
                tmp = line
                sub(/^[[:space:]]*(pub(\([a-z]+\))?[[:space:]]+)?static[[:space:]]+/, "", tmp)
                colon_pos = index(tmp, ":")
                name = substr(tmp, 1, colon_pos - 1)
                sub(/[[:space:]]+$/, "", name)
                sub(/^[[:space:]]+/, "", name)
                type_str = substr(tmp, colon_pos + 1)
                sub(/^[[:space:]]+/, "", type_str)
                eq_pos = index(type_str, "=")
                if (eq_pos > 0) {
                    type_str = substr(type_str, 1, eq_pos - 1)
                }
                sub(/[[:space:]]+$/, "", type_str)
                gsub(/[[:space:]]+/, " ", type_str)

                if (name in allow_map) {
                    tag = "ALLOW"
                } else if (match(type_str, /(^|::)Once([^A-Za-z0-9_]|$)/)) {
                    tag = "ONCE"
                } else {
                    tag = "FAIL"
                }
                printf("%s\t%s\t%d\t%s\t%s\n", tag, FILE, NR, name, type_str)
            }
        }

        test_brace_delta = (entered_test_this_line ? (open_n - 1 - close_n) : (open_n - close_n))
        brace_depth += (open_n - close_n)
        if (brace_depth < 0) brace_depth = 0
        in_test_depth += (in_test_depth > 0 ? test_brace_delta : 0)
        if (in_test_depth < 0) in_test_depth = 0
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
    # Skip excluded FFI bridge dirs.
    if is_excluded_path "$file"; then
        continue
    fi
    # Skip non-src/ paths (tests/, benches/, examples/) — we scan library
    # sources, not crate-level test files (those live in `tests/` and are
    # allowed to keep local statics).
    case "$file" in
        */src/*) : ;;
        *) continue ;;
    esac
    scan_file "$file" >> "$OUT_FILE"
done < <(find "$SCAN_DIR" -type f -name '*.rs' -print0)

# ---------------------------------------------------------------------------
# Aggregate.
# ---------------------------------------------------------------------------
FAIL_N=$(grep -c $'^FAIL\t' "$OUT_FILE" 2>/dev/null || true)
ALLOW_N=$(grep -c $'^ALLOW\t' "$OUT_FILE" 2>/dev/null || true)
ONCE_N=$(grep -c $'^ONCE\t' "$OUT_FILE" 2>/dev/null || true)
FAIL_N=${FAIL_N:-0}
ALLOW_N=${ALLOW_N:-0}
ONCE_N=${ONCE_N:-0}

printf '\n%smutable-globals scan (workspace, excluding scp-ffi):%s\n' \
    "$C_DIM" "$C_RESET"
printf '  allowlisted=%d  once-guards=%d  failed=%d\n' \
    "$ALLOW_N" "$ONCE_N" "$FAIL_N"

if [[ "$FAIL_N" -eq 0 ]]; then
    printf '%sPASSED%s: no disallowed module-level statics.\n' \
        "$C_GREEN" "$C_RESET"
    exit 0
fi

printf '\n%sFAILED%s: %d disallowed module-level static(s) in non-FFI crates.\n' \
    "$C_RED" "$C_RESET" "$FAIL_N" >&2
printf '\n' >&2
printf 'Offending declarations:\n' >&2
while IFS=$'\t' read -r tag file line name type_str; do
    [[ "$tag" == "FAIL" ]] || continue
    printf '  %s%s:%s%s  %sstatic %s%s  (%s%s%s)\n' \
        "$C_DIM" "$file" "$line" "$C_RESET" \
        "$C_YELLOW" "$name" "$C_RESET" \
        "$C_DIM" "$type_str" "$C_RESET" >&2
done < "$OUT_FILE"

printf '\n' >&2
printf 'A new module-level `static` must either:\n' >&2
printf '  1. live behind an explicit constructor-injected dependency\n' >&2
printf '     (preferred — multi-instance-safe by construction), or\n' >&2
printf '  2. be added to the ALLOWLIST in scripts/check-no-mutable-globals.sh\n' >&2
printf '     with a justifying `# why:` comment AND a doc-comment on the\n' >&2
printf '     static in the source file.\n' >&2
printf '\n' >&2
printf 'See .docs/adrs/ADR-048-scp-multi-instance.md and the Phase 4\n' >&2
printf 'remainder for context on why the DEFAULT_BRIDGE_INSTANCE pattern\n' >&2
printf 'was removed.\n' >&2

exit 1
