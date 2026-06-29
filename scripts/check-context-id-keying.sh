#!/usr/bin/env bash
# check-context-id-keying.sh — CI gate enforcing the ADR-056 single-chokepoint
# invariant for context-id keying.
#
# ---------------------------------------------------------------------------
# WHY THIS EXISTS
# ---------------------------------------------------------------------------
# ADR-056 (Canonical Context Identity = 32-byte digest): a context's canonical
# identity IS its 32-byte digest; the id STRING is `hex(digest)`. The runtime
# MUST resolve a context-id string to keying bytes by DECODING the hex (for a
# real 64-hex id) — never by RE-HASHING it. Re-hashing a real id with the raw
# SHA-256 primitive `scp_protocol::context::context_id_bytes(id)` is a DOUBLE
# HASH (`SHA-256(hex(digest))`) that diverges from the digest the §6.2.4 wire
# saga, the MLS group, the sender keys, and the event log all address — the
# exact bug #1924 fixed (and which a missed straggler in `key_destruction.rs`
# would have silently re-introduced as a fail-OPEN on Ephemeral close).
#
# Every context-id → keying-bytes resolution MUST therefore funnel through the
# single chokepoint `crate::context::state::context_id_to_bytes`, which decodes
# a canonical 64-hex id and falls back to the raw SHA-256 primitive ONLY for
# synthetic / non-context labels that were never 64-hex.
#
# This gate is a CLOSED-ALLOWLIST tripwire on the raw primitive. It FAILS if
# any PRODUCTION site under `crates/scp-runtime/src/` calls the raw primitive
# `scp_protocol::context::context_id_bytes(...)` (qualified, or unqualified in
# a file that imports it) OUTSIDE a small, positively-enumerated allowlist:
#
#   (i)  the resolver's OWN fallback in `state.rs` — `context_id_to_bytes`
#        delegates to the raw primitive for non-64-hex labels; this is the
#        single permitted production call, by construction.
#   (ii) the documented synthetic `"identity-private-state"` site in
#        `supervisor.rs` (`recovery_send_notification_direct`, §9.12 PSK
#        rotation) — a never-registered pseudo-context that is never 64-hex and
#        is deliberately hashed; the direct call documents that this site is
#        the synthetic/non-context case.
#
# Test code is exempt: a `*_tests.rs` file (whole-file test module) or any
# occurrence at/after a file's first `#[cfg(test)]` marker (the conventional
# end-of-file test module) keys synthetic `"ctx-…"` / fixture labels and is
# free to call the primitive directly.
#
# This is a POSITIVE BOUNDED allowlist (two named production sites), not a
# denylist chasing spellings. It is NOT a proof of correctness — it is a
# tripwire that resists the COMMON failure mode (a new keying site copies the
# raw primitive instead of the chokepoint, as the original PR-A missed twice).
#
# ---------------------------------------------------------------------------
# USAGE
# ---------------------------------------------------------------------------
#   bash scripts/check-context-id-keying.sh             # scan the real tree
#   bash scripts/check-context-id-keying.sh --self-test # prove the gate is alive
#
# Exit codes:
#   0  — every raw-primitive call is allowlisted or in test scope
#   1  — a raw-primitive call appeared at a non-allowlisted production site,
#        or a self-test expectation failed
#   2  — invocation error (a scoped source directory is missing)
#
# ---------------------------------------------------------------------------
# PORTABILITY
# ---------------------------------------------------------------------------
# Runs on macOS (BSD userland) and Linux (GNU userland). POSIX bash + grep +
# awk only. No ripgrep, no GNU-specific flags.

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

# The raw SHA-256 primitive. Matches BOTH the fully-qualified call
# `scp_protocol::context::context_id_bytes(` and a bare `context_id_bytes(`
# call IN A FILE THAT IMPORTS the raw primitive (`use scp_protocol::context::{
# … context_id_bytes … }`). The bare `fn context_id_bytes` local wrappers in
# builder.rs / ttl.rs delegate to the chokepoint and are NOT the primitive —
# they live in files that do NOT import the raw symbol, so a bare call there is
# not flagged.
RAW_QUALIFIED='scp_protocol::context::context_id_bytes('
RAW_IMPORT_RE='use[[:space:]]+scp_protocol::context::\{[^}]*context_id_bytes'

# ---------------------------------------------------------------------------
# Positively-enumerated PRODUCTION allowlist.
#
# Format: "REPO_REL_PATH|ANCHOR_SUBSTRING|REASON"
#   REPO_REL_PATH  — exact source file permitted to hold a production call.
#   ANCHOR_SUBSTRING — a stable substring that MUST appear on the offending
#                      line for it to be allowlisted (pins the specific call,
#                      so a new unrelated call in the same file is still
#                      caught).
#   REASON         — why this site is permitted.
# ---------------------------------------------------------------------------
ALLOWLIST=(
    "crates/scp-runtime/src/context/state.rs|scp_protocol::context::context_id_bytes(context_id)|ADR-056 resolver fallback: context_id_to_bytes delegates to the raw primitive for non-64-hex labels"
    "crates/scp-runtime/src/context/supervisor/supervisor.rs|let context_id_bytes = scp_protocol::context::context_id_bytes(context_id)|ADR-056 synthetic identity-private-state (recovery_send_notification_direct, §9.12) — deliberately hashed, never a real 64-hex id"
)

# Directory scanned. ADR-056's chokepoint invariant is a scp-runtime property.
SCAN_DIR="crates/scp-runtime/src"

# ---------------------------------------------------------------------------
# is_allowlisted FILE LINE_TEXT  ->  0 if allowlisted, 1 otherwise
# ---------------------------------------------------------------------------
is_allowlisted() {
    local file="$1" line_text="$2" entry path anchor
    for entry in "${ALLOWLIST[@]}"; do
        IFS='|' read -r path anchor _reason <<< "$entry"
        if [[ "$file" == "$path" ]] && [[ "$line_text" == *"$anchor"* ]]; then
            return 0
        fi
    done
    return 1
}

# ---------------------------------------------------------------------------
# scan_tree ROOT  ->  prints "FILE:LINENO:TEXT" for every NON-allowlisted,
#                     NON-test production call of the raw primitive.
#
# Test scope (exempt):
#   - a file whose basename ends in `_tests.rs` (whole-file test module), OR
#   - an occurrence at/after the file's first `#[cfg(test)]` line.
#
# A bare `context_id_bytes(` call is only the raw primitive when the file
# imports the raw symbol; otherwise the bare name is a local delegating
# wrapper and is ignored.
# ---------------------------------------------------------------------------
scan_tree() {
    local root="$1"
    [[ -d "$root" ]] || { printf '%serror:%s scan dir missing: %s\n' "$C_RED" "$C_RESET" "$root" >&2; exit 2; }

    local f basename imports_raw cfgtest_line
    # NUL-safe file walk; only *.rs.
    while IFS= read -r -d '' f; do
        basename="${f##*/}"
        # Whole-file test modules: exempt entirely.
        [[ "$basename" == *_tests.rs ]] && continue

        # Does this file import the raw primitive unqualified?
        if grep -Eq "$RAW_IMPORT_RE" -- "$f" 2>/dev/null; then
            imports_raw=1
        else
            imports_raw=0
        fi

        # First #[cfg(test)] line (0 if none) — the conventional start of the
        # end-of-file test module. Everything at/after it is test scope.
        cfgtest_line="$(grep -n '#\[cfg(test)\]' -- "$f" 2>/dev/null | head -1 | cut -d: -f1)"
        [[ -z "$cfgtest_line" ]] && cfgtest_line=0

        # Emit every raw-primitive call line: qualified always; bare only when
        # the file imports the raw symbol.
        awk -v qualified="$RAW_QUALIFIED" \
            -v imports_raw="$imports_raw" \
            -v cfgtest="$cfgtest_line" \
            -v fname="$f" '
            # bare-call detector: context_id_bytes( NOT preceded by ":" (so not
            # the qualified form) and NOT a fn definition.
            {
                is_qualified = index($0, qualified) > 0
                is_bare = 0
                if (imports_raw == 1) {
                    if ($0 ~ /(^|[^:_[:alnum:]])context_id_bytes\(/ && $0 !~ /fn[[:space:]]+context_id_bytes/) {
                        is_bare = 1
                    }
                }
                if (is_qualified || is_bare) {
                    # Test scope: at/after the first #[cfg(test)] line.
                    if (cfgtest > 0 && NR >= cfgtest) next
                    printf "%s:%d:%s\n", fname, NR, $0
                }
            }
        ' "$f"
    done < <(find "$root" -name '*.rs' -type f -print0)
}

# ---------------------------------------------------------------------------
# run_real_check ROOT  ->  exit 0 (clean) / 1 (violation)
# ---------------------------------------------------------------------------
run_real_check() {
    local root="$1" raw fail=0 file lineno text
    raw="$(scan_tree "$root")"

    printf '\n%scontext-id keying scan (ADR-056 single chokepoint):%s\n' "$C_DIM" "$C_RESET"

    if [[ -z "$raw" ]]; then
        printf '  %sno production raw-primitive calls found at all%s\n' "$C_GREEN" "$C_RESET"
        printf '%sPASSED%s: every context-id keying site routes through context_id_to_bytes.\n' "$C_GREEN" "$C_RESET"
        return 0
    fi

    while IFS= read -r match; do
        [[ -z "$match" ]] && continue
        file="${match%%:*}"
        local rest="${match#*:}"
        lineno="${rest%%:*}"
        text="${rest#*:}"
        if is_allowlisted "$file" "$text"; then
            printf '  %s[allow]%s %s:%s\n' "$C_GREEN" "$C_RESET" "$file" "$lineno"
        else
            fail=1
            printf '  %s[DENY]%s %s:%s\n' "$C_RED" "$C_RESET" "$file" "$lineno"
            printf '      %s%s%s\n' "$C_DIM" "$text" "$C_RESET" >&2
        fi
    done <<< "$raw"

    if [[ "$fail" -eq 0 ]]; then
        printf '%sPASSED%s: every production raw-primitive call is allowlisted (ADR-056).\n' "$C_GREEN" "$C_RESET"
        return 0
    fi

    printf '\n%sFAILED%s: a production site calls the raw SHA-256 primitive\n' "$C_RED" "$C_RESET" >&2
    printf '`scp_protocol::context::context_id_bytes(...)` outside the ADR-056 allowlist.\n' >&2
    printf 'Route context-id keying through `crate::context::state::context_id_to_bytes`\n' >&2
    printf '(it DECODES a real 64-hex id and only hashes genuine non-context labels).\n' >&2
    printf 'See .docs/adrs/ADR-056-canonical-context-identity.md\n' >&2
    return 1
}

# ---------------------------------------------------------------------------
# Self-test: build a throwaway tree, plant (a) a forbidden production call
# [must DENY], (b) an allowlisted call [must ALLOW], (c) a test-scope call
# [must be exempt], and assert the gate's verdicts.
# ---------------------------------------------------------------------------
run_self_test() {
    local tmp ok=1
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' RETURN

    # Mirror the real allowlisted paths so the anchor match applies.
    mkdir -p "$tmp/crates/scp-runtime/src/context/supervisor"
    local state_f="$tmp/crates/scp-runtime/src/context/state.rs"
    local sup_f="$tmp/crates/scp-runtime/src/context/supervisor/supervisor.rs"
    local bad_f="$tmp/crates/scp-runtime/src/context/messaging_helpers.rs"
    local test_f="$tmp/crates/scp-runtime/src/context/export_import.rs"

    # (i) allowlisted resolver fallback in state.rs.
    {
        echo 'pub(crate) fn context_id_to_bytes(context_id: &str) -> [u8; 32] {'
        echo '    scp_protocol::context::context_id_bytes(context_id)'
        echo '}'
    } > "$state_f"

    # (ii) allowlisted synthetic site in supervisor.rs.
    {
        echo 'fn recovery_send_notification_direct(context_id: &str) {'
        echo '    let context_id_bytes = scp_protocol::context::context_id_bytes(context_id);'
        echo '}'
    } > "$sup_f"

    # (BAD) forbidden production call at a non-allowlisted site (before any test
    # module): MUST be denied.
    {
        echo 'pub fn destroy(context_id: &str) {'
        echo '    let ctx_bytes = scp_protocol::context::context_id_bytes(context_id);'
        echo '}'
    } > "$bad_f"

    # (TEST) a raw-primitive call inside an end-of-file #[cfg(test)] module:
    # MUST be exempt.
    {
        echo 'pub fn nothing() {}'
        echo '#[cfg(test)]'
        echo 'mod tests {'
        echo '    #[test]'
        echo '    fn t() {'
        echo '        let _ = scp_protocol::context::context_id_bytes("ctx-test");'
        echo '    }'
        echo '}'
    } > "$test_f"

    printf '%sself-test:%s planted 1 forbidden + 2 allowlisted + 1 test-scope call\n' "$C_DIM" "$C_RESET"

    # Expect the real-check logic to DENY the bad file and PASS none-else.
    local out rc=0
    out="$(SCAN_DIR_OVERRIDE="$tmp/crates/scp-runtime/src" run_real_check "$tmp/crates/scp-runtime/src" 2>&1)" || rc=$?

    # 1. The forbidden site must be flagged DENY.
    if grep -q "messaging_helpers.rs" <<< "$out" && grep -q "\[DENY\]" <<< "$out"; then
        printf '  %sOK%s   forbidden production call → DENY\n' "$C_GREEN" "$C_RESET"
    else
        printf '  %sFAIL%s forbidden production call was NOT denied\n' "$C_RED" "$C_RESET" >&2
        ok=0
    fi
    # 2. Overall verdict must be failure (rc != 0).
    if [[ "$rc" -ne 0 ]]; then
        printf '  %sOK%s   overall verdict = FAIL with a forbidden call present\n' "$C_GREEN" "$C_RESET"
    else
        printf '  %sFAIL%s gate passed despite a forbidden call\n' "$C_RED" "$C_RESET" >&2
        ok=0
    fi
    # 3. The allowlisted sites must NOT be denied.
    if grep -q "state.rs" <<< "$out" && grep -q "supervisor.rs" <<< "$out" && ! grep -E "state.rs.*\[DENY\]|supervisor.rs.*\[DENY\]" <<< "$out"; then
        printf '  %sOK%s   allowlisted sites → allow\n' "$C_GREEN" "$C_RESET"
    else
        printf '  %sFAIL%s an allowlisted site was misclassified\n' "$C_RED" "$C_RESET" >&2
        ok=0
    fi
    # 4. The test-scope call must be exempt (export_import never appears).
    if ! grep -q "export_import.rs" <<< "$out"; then
        printf '  %sOK%s   test-scope call → exempt\n' "$C_GREEN" "$C_RESET"
    else
        printf '  %sFAIL%s test-scope call was not exempted\n' "$C_RED" "$C_RESET" >&2
        ok=0
    fi

    if [[ "$ok" -eq 1 ]]; then
        printf '%sself-test PASSED%s\n' "$C_GREEN" "$C_RESET"
        return 0
    fi
    printf '%sself-test FAILED%s\n' "$C_RED" "$C_RESET" >&2
    return 1
}

# ---------------------------------------------------------------------------
# Entry-point
# ---------------------------------------------------------------------------
case "${1:-}" in
    --self-test)
        run_self_test
        ;;
    "")
        run_real_check "$SCAN_DIR"
        ;;
    *)
        printf '%serror:%s unknown argument: %s (use --self-test or no args)\n' "$C_RED" "$C_RESET" "$1" >&2
        exit 2
        ;;
esac
