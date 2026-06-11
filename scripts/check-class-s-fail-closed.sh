#!/usr/bin/env bash
# check-class-s-fail-closed.sh — CI gate enforcing ADR-049 §9's crash-safety
# invariant at the level of the CONSUME SITE, not just the snapshot field.
#
# ---------------------------------------------------------------------------
# WHAT THIS CHECKS
# ---------------------------------------------------------------------------
# ADR-049 §9 ("Respawn crash-safety invariant") classifies the spending-UCAN
# nonce tracker as Class S: a consumed nonce MUST be durably persisted
# (fail-closed) BEFORE the operation that consumed it is acknowledged to the
# caller. If a paid operation consumes a nonce and then replies via a
# best-effort (coalesced) persist, an actor crash in the ≤50ms coalesce window
# rolls the consume back — freshening the spending UCAN's nonce after the
# caller already saw success (replay / double-spend, BLACK-001).
#
# The sibling `security_critical_state_is_class_s_or_m_not_coalesced` test
# catches a security FIELD dropped from the snapshot builder. It does NOT catch
# a missed CONSUME SITE — a code path that mutates a Class-S field and then
# replies WITHOUT a fail-closed persist. That is exactly how the message-send
# and paid-join nonce-consume sites were missed in earlier rounds while the
# tool-invoke site was fixed: all three consume the same nonce via the same
# shared `enforce_economy` helper, but each is acknowledged by a DIFFERENT
# handler, and only one handler persisted fail-closed.
#
# This gate closes the CLASS structurally. The spending-nonce consume always
# flows through one of:
#
#   - `commit_spending_ucan_nonce(..)`        — the durable nonce insertion, OR
#   - `enforce_economy(..)`                   — the shared paid-action helper
#                                               that calls the above, OR
#   - `enforce_send_economy(..)` /            — the per-action wrappers around
#     `enforce_join_economy(..)`                `enforce_economy`.
#
# The gate scans every PRODUCTION (non-`#[cfg(test)]`) function in the runtime
# context module and, for any function whose body contains a consume call,
# REQUIRES that the SAME function body also references `persist_state_fail_closed`
# — UNLESS the function is one of the explicitly-allowlisted CONSUME HELPERS
# (`enforce_economy`, `enforce_send_economy`, `enforce_join_economy`), which
# are pass-throughs whose ACKNOWLEDGING handler persists fail-closed. Each
# allowlisted helper is paired below with the handler(s) that persist its
# consume and the crash-survival test(s) that cover it; a NEW consume site that
# is neither self-persisting nor an allowlisted helper FAILS this gate, forcing
# the author to add the fail-closed persist (or, if it is a new pass-through
# helper, to allowlist it AND wire a covering crash-survival test).
#
# ---------------------------------------------------------------------------
# THE ALLOWLISTED CONSUME HELPERS (pass-throughs; handler persists)
# ---------------------------------------------------------------------------
#   enforce_economy        — shared paid-action helper. Acknowledging handlers:
#                            send_message (-> finalize_send, fail-closed),
#                            join_context (fail-closed),
#                            reserve_tool_economy (fail-closed).
#                            Covered by the send / join / tool crash-survival
#                            tests below.
#   enforce_send_economy   — MessageSend wrapper. Handler: send_message ->
#                            finalize_send. Test:
#                            send_path_spending_nonce_consume_survives_crash_before_coalesce.
#   enforce_join_economy   — ContextJoin wrapper. Handler: join_context. Test:
#                            spending_nonce_consume_survives_crash_before_coalesce
#                            exercises the same persist_state_fail_closed
#                            primitive the join handler now calls.
#
# The terminal handlers (`reserve_tool_economy`, `send_message`/`finalize_send`,
# `join_context`) all call `commit_spending_ucan_nonce`/`enforce_*_economy` AND
# `persist_state_fail_closed` in the same function — so they satisfy the gate
# directly and need no allowlist entry.
#
# ---------------------------------------------------------------------------
# WHEN THIS RUNS
# ---------------------------------------------------------------------------
# On every PR (cheap, no build). ADDITIVE coverage — it does not replace or
# weaken any existing enforcement script or the field-round-trip test.
#
# ---------------------------------------------------------------------------
# HOW TO FIX A FAILURE
# ---------------------------------------------------------------------------
# Your function consumes a spending-UCAN nonce (Class S) and acknowledges the
# operation without a fail-closed persist. Either:
#   - Add `persist_state_fail_closed(state, deps, context_id)?` (gated on the
#     spending-nonce-committed condition) BEFORE the function returns success,
#     mirroring `reserve_tool_economy` / `finalize_send` / `join_context`; OR
#   - If your function is a NEW pass-through helper whose caller persists, add
#     it to CONSUME_HELPERS below WITH a comment naming the persisting handler
#     AND a crash-survival test that drives it through a crash-before-coalesce.
#
# Do NOT relax this gate by allowlisting a TERMINAL handler (one that actually
# replies to the caller) — that defeats the invariant. Only pass-through
# helpers belong on the allowlist.
#
# ---------------------------------------------------------------------------
# PORTABILITY
# ---------------------------------------------------------------------------
# Runs on macOS (BSD userland) and Linux (GNU userland). Pure awk + find.
#
# Usage:
#   bash scripts/check-class-s-fail-closed.sh
# Exit codes:
#   0  — every consume site persists fail-closed (or is an allowlisted helper)
#   1  — one or more consume sites acknowledge without a fail-closed persist,
#        or the self-test failed (the gate is dead)
#   2  — invocation error (scan dir missing)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

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

# The allowlisted pass-through CONSUME HELPERS (see header). Space-separated.
CONSUME_HELPERS="enforce_economy enforce_send_economy enforce_join_economy"

# PERSIST DELEGATES: a consuming handler whose fail-closed persist lives in a
# function it CALLS (not its own body) maps `handler:delegate`. The gate
# requires the DELEGATE's body to contain `persist_state_fail_closed` — so if
# the delegate ever regresses to best-effort-only, the handler is flagged
# again. The only such case today is `send_message`, whose acknowledgment +
# fail-closed persist live in `finalize_send`. Space-separated `name:delegate`.
PERSIST_DELEGATES="send_message:finalize_send"

SCAN_DIR="crates/scp-runtime/src/context"

# ---------------------------------------------------------------------------
# collect_failclosed — emit `FC<TAB>fnname` for every PRODUCTION function whose
# body contains `persist_state_fail_closed(`. Used to verify persist delegates.
# ---------------------------------------------------------------------------
collect_failclosed() {
    local file="$1"
    awk '
    BEGIN { in_block=0; seen_test=0; depth=0; in_fn=0; pending=0 }
    {
        raw=$0
        if (raw ~ /#\[cfg\(test\)\]/) seen_test=1
        if (seen_test) next
        line=raw
        if (!in_block) gsub(/"[^"]*"/, "", line)
        if (!in_block) sub(/\/\/.*$/, "", line)
        while (match(line, /\/\*.*\*\//)) line = substr(line,1,RSTART-1) substr(line,RSTART+RLENGTH)
        if (match(line, /\/\*/)) { line=substr(line,1,RSTART-1); in_block=1 }
        if (in_block && match(line, /\*\//)) { line=substr(line,RSTART+RLENGTH); in_block=0 }
        if (in_block) next
        if (!in_fn && line ~ /^[[:space:]]*(pub[[:space:]]*(\([^)]*\))?[[:space:]]+)?(async[[:space:]]+)?fn[[:space:]]+[A-Za-z0-9_]+/) {
            tmp=line
            sub(/^[[:space:]]*(pub[[:space:]]*(\([^)]*\))?[[:space:]]+)?(async[[:space:]]+)?fn[[:space:]]+/, "", tmp)
            sub(/[^A-Za-z0-9_].*$/, "", tmp)
            pending_fn=tmp; pending=1
        }
        opens=gsub(/{/,"{",line); closes=gsub(/}/,"}",line)
        if (pending && opens>0) { in_fn=1; fn_name=pending_fn; fn_floor=depth; fn_fc=0; pending=0 }
        if (in_fn && line ~ /persist_state_fail_closed[[:space:]]*\(/) fn_fc=1
        depth += opens - closes
        if (in_fn && depth <= fn_floor) {
            if (fn_fc) printf("FC\t%s\n", fn_name)
            in_fn=0
        }
    }
    ' "$file"
}

# ---------------------------------------------------------------------------
# scan_file — emit, per offending function, a line:
#   HIT<TAB>file<TAB>line<TAB>fnname
# where the function CONSUMED a spending nonce but neither persisted
# fail-closed (directly or via a verified delegate) nor is an allowlisted
# helper. Also emits:
#   SCANNED<TAB>file<TAB>count   (number of production functions inspected)
#
# `FC_FUNCS` is the space-separated set of functions known (from the first
# pass) to persist fail-closed; a delegating handler is satisfied only if its
# mapped delegate is in this set.
#
# Function tracking: a top-level (column-0) `fn NAME` / `pub fn NAME` /
# `pub(..) fn NAME` / `async fn NAME` opens a function; its body spans balanced
# braces from the first `{`. Only the region BEFORE the first `#[cfg(test)]` is
# scanned (test modules legitimately exercise the primitives directly).
# Comments and string literals are stripped so a doc mention of a primitive
# does not count as a consume call.
# ---------------------------------------------------------------------------
scan_file() {
    local file="$1"
    awk -v FILE="$file" -v HELPERS="$CONSUME_HELPERS" \
        -v DELEGATES="$PERSIST_DELEGATES" -v FC_FUNCS="${FC_FUNCS:-}" '
    BEGIN {
        in_block = 0
        seen_test = 0
        depth = 0
        in_fn = 0
        fn_name = ""
        fn_line = 0
        fn_consumes = 0
        fn_failclosed = 0
        scanned = 0
        n = split(HELPERS, harr, " ")
        for (i = 1; i <= n; i++) helper[harr[i]] = 1
        # Persist-delegate map: handler -> delegate.
        m = split(DELEGATES, darr, " ")
        for (i = 1; i <= m; i++) {
            split(darr[i], kv, ":")
            delegate[kv[1]] = kv[2]
        }
        # Functions known to persist fail-closed (first pass).
        k = split(FC_FUNCS, farr, " ")
        for (i = 1; i <= k; i++) fc[farr[i]] = 1
    }
    {
        raw = $0

        if (raw ~ /#\[cfg\(test\)\]/) { seen_test = 1 }
        if (seen_test) next

        line = raw
        # Strip string literals first (so a `/*` inside a string cannot wedge
        # the block-comment scanner, and so a primitive name inside a string
        # does not count).
        if (!in_block) gsub(/"[^"]*"/, "", line)
        # Strip //-comment tail.
        if (!in_block) sub(/\/\/.*$/, "", line)
        # Strip single-line /* .. */.
        while (match(line, /\/\*.*\*\//)) {
            line = substr(line, 1, RSTART - 1) substr(line, RSTART + RLENGTH)
        }
        # Open block comment.
        if (match(line, /\/\*/)) { line = substr(line, 1, RSTART - 1); in_block = 1 }
        # Close block comment.
        if (in_block && match(line, /\*\//)) { line = substr(line, RSTART + RLENGTH); in_block = 0 }
        if (in_block) next

        # Detect a top-level function definition (column 0, allowing pub/async
        # qualifiers). Capture the name. We only treat a fn as "open" once we
        # see its opening brace (which may be on the signature line or a later
        # line for multi-line signatures).
        if (!in_fn && line ~ /^[[:space:]]*(pub[[:space:]]*(\([^)]*\))?[[:space:]]+)?(async[[:space:]]+)?fn[[:space:]]+[A-Za-z0-9_]+/) {
            # Extract the function name.
            tmp = line
            sub(/^[[:space:]]*(pub[[:space:]]*(\([^)]*\))?[[:space:]]+)?(async[[:space:]]+)?fn[[:space:]]+/, "", tmp)
            sub(/[^A-Za-z0-9_].*$/, "", tmp)
            pending_fn = tmp
            pending_line = NR
            pending = 1
        }

        opens = gsub(/{/, "{", line)
        closes = gsub(/}/, "}", line)

        # If a function signature is pending and we see the opening brace, the
        # function body begins. depth BEFORE this line is the floor.
        if (pending && opens > 0) {
            in_fn = 1
            fn_name = pending_fn
            fn_line = pending_line
            fn_floor = depth
            fn_consumes = 0
            fn_failclosed = 0
            pending = 0
            scanned++
        }

        # Within a function body, look for consume calls + fail-closed persist.
        if (in_fn) {
            if (line ~ /commit_spending_ucan_nonce[[:space:]]*\(/) fn_consumes = 1
            if (line ~ /enforce_economy[[:space:]]*\(/) fn_consumes = 1
            if (line ~ /enforce_send_economy[[:space:]]*\(/) fn_consumes = 1
            if (line ~ /enforce_join_economy[[:space:]]*\(/) fn_consumes = 1
            if (line ~ /persist_state_fail_closed[[:space:]]*\(/) fn_failclosed = 1
        }

        depth += opens - closes

        # Function body closes when depth returns to its floor.
        if (in_fn && depth <= fn_floor) {
            # A consuming function is satisfied if it (a) persists fail-closed
            # in its own body, (b) is an allowlisted pass-through helper, or
            # (c) delegates persistence to a function that is KNOWN to persist
            # fail-closed (the delegate must be in the first-pass FC set — so a
            # delegate that regresses to best-effort re-flags the handler).
            satisfied = fn_failclosed || (fn_name in helper)
            if (!satisfied && (fn_name in delegate)) {
                if (delegate[fn_name] in fc) satisfied = 1
            }
            if (fn_consumes && !satisfied) {
                printf("HIT\t%s\t%d\t%s\n", FILE, fn_line, fn_name)
            }
            in_fn = 0
            fn_name = ""
        }
    }
    END {
        printf("SCANNED\t%s\t%d\n", FILE, scanned)
    }
    ' "$file"
}

# ---------------------------------------------------------------------------
# run_scan — scan a directory of *.rs files, evaluate, print verdict.
# Returns 0 PASS / 1 FAIL. Factored out so the self-test can drive it against
# synthetic fixtures.
#   $1 — scan dir
#   $2 — allowlist (space-separated helper names); passed via CONSUME_HELPERS
#   $3 — label
# ---------------------------------------------------------------------------
run_scan() {
    local scan_dir="$1"
    local label="${2:-scan}"

    local tmp_out
    tmp_out=$(mktemp)

    printf '\n%sclass-s consume-site %s:%s %s\n' \
        "$C_DIM" "$label" "$C_RESET" "$scan_dir"

    # First pass: collect every production function that persists fail-closed,
    # so persist-delegates can be verified in the second pass.
    FC_FUNCS=$(
        find "$scan_dir" -type f -name '*.rs' -print0 \
            | while IFS= read -r -d '' file; do
                collect_failclosed "$file"
            done | awk -F'\t' '$1=="FC"{print $2}' | sort -u | tr '\n' ' '
    )
    export FC_FUNCS

    # Second pass: the consume-site check.
    find "$scan_dir" -type f -name '*.rs' -print0 \
        | while IFS= read -r -d '' file; do
            scan_file "$file"
        done > "$tmp_out"

    local hits scanned_total
    hits=$(grep -c $'^HIT\t' "$tmp_out" 2>/dev/null || true)
    hits=${hits:-0}
    scanned_total=$(awk -F'\t' '$1=="SCANNED"{s+=$3} END{print s+0}' "$tmp_out")

    if [[ "$hits" -ne 0 ]]; then
        printf '\n%sFAILED%s: %d function(s) consume a spending-UCAN nonce (Class S)\n' \
            "$C_RED" "$C_RESET" "$hits" >&2
        printf 'and acknowledge WITHOUT a fail-closed persist (ADR-049 §9 / BLACK-001):\n' >&2
        while IFS=$'\t' read -r tag file line fn; do
            [[ "$tag" == "HIT" ]] || continue
            printf '      %s%s:%s%s  fn %s%s%s\n' \
                "$C_DIM" "$file" "$line" "$C_RESET" \
                "$C_YELLOW" "$fn" "$C_RESET" >&2
        done < "$tmp_out"
        printf '\n' >&2
        printf 'Add `persist_state_fail_closed(..)` before the function returns success\n' >&2
        printf '(gated on the spending-nonce-committed condition), mirroring\n' >&2
        printf 'reserve_tool_economy / finalize_send / join_context. If this is a NEW\n' >&2
        printf 'pass-through helper whose caller persists, add it to CONSUME_HELPERS\n' >&2
        printf 'in this script WITH a covering crash-survival test. See ADR-049 §9.\n' >&2
    fi

    rm -f "$tmp_out"

    # Vacuity guard: the runtime context module has many functions; a near-zero
    # scan means the function tracker is broken and the gate is vacuous.
    if [[ "${label}" == "scan" && "${scanned_total}" -lt 50 ]]; then
        printf '\n%sFAILED%s: consume-site scan is vacuous — only %d production\n' \
            "$C_RED" "$C_RESET" "$scanned_total" >&2
        printf 'function(s) inspected (expected >= 50). The function tracker is broken.\n' >&2
        return 1
    fi

    [[ "$hits" -eq 0 ]] && return 0
    return 1
}

# ---------------------------------------------------------------------------
# SELF-TEST — prove the gate is not dead. Build synthetic fixtures and assert:
#   (1) a function that consumes a nonce but does NOT persist fail-closed and is
#       NOT an allowlisted helper IS caught;
#   (2) a function that consumes AND persists fail-closed in the same body is
#       NOT flagged;
#   (3) an allowlisted helper that consumes without persisting is NOT flagged.
# Set NO_CLASS_S_SELFTEST=1 to skip (not recommended).
# ---------------------------------------------------------------------------
self_test() {
    local fixt
    fixt=$(mktemp -d)
    local fdir="$fixt/ctx"
    mkdir -p "$fdir"

    # (1) Missed consume site — MUST be caught. This mirrors the original
    # message-send miss: a handler that drives the consume (here via
    # enforce_send_economy) and acknowledges with only a best-effort persist.
    {
        printf 'pub async fn send_message_fixture() {\n'
        printf '    let _c = enforce_send_economy(state);\n'
        printf '    persist_state_best_effort(state, deps, ctx);\n'
        printf '}\n'
    } > "$fdir/missed.rs"

    # (2) Correctly fixed handler — MUST NOT be flagged.
    {
        printf 'pub async fn reserve_tool_economy_fixture() {\n'
        printf '    let _c = commit_spending_ucan_nonce(s, t);\n'
        printf '    persist_state_fail_closed(state, deps, ctx)?;\n'
        printf '}\n'
    } > "$fdir/fixed.rs"

    # (3) Allowlisted pass-through helper — MUST NOT be flagged.
    {
        printf 'pub fn enforce_economy() {\n'
        printf '    commit_spending_ucan_nonce(s, t);\n'
        printf '}\n'
    } > "$fdir/helper.rs"

    local rc=0

    # Expect a HIT on the missed fixture only. Capture the scan over the whole
    # fixture dir; it must flag exactly send_message_fixture. `FC_FUNCS` is
    # empty for the self-test (fixtures (1)-(3) do not exercise delegation).
    local out
    out=$(
        find "$fdir" -type f -name '*.rs' -print0 \
            | while IFS= read -r -d '' f; do FC_FUNCS="" scan_file "$f"; done
    )

    if ! grep -q $'^HIT\t.*\tsend_message_fixture$' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a consume-without-fail-closed site was NOT caught.\n' \
            "$C_RED" "$C_RESET" >&2
        rc=1
    fi
    if grep -q $'^HIT\t.*\treserve_tool_economy_fixture$' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a correctly fail-closed handler was wrongly flagged.\n' \
            "$C_RED" "$C_RESET" >&2
        rc=1
    fi
    if grep -q $'^HIT\t.*\tenforce_economy$' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: an allowlisted consume helper was wrongly flagged.\n' \
            "$C_RED" "$C_RESET" >&2
        rc=1
    fi

    # (4) Persist-delegate path. A handler that consumes and delegates its
    # fail-closed persist to a mapped delegate function is NOT flagged WHEN the
    # delegate is known to persist fail-closed, but IS flagged when the delegate
    # is NOT in the fail-closed set (delegate regressed to best-effort). This
    # exercises the same machinery `send_message` -> `finalize_send` relies on.
    local fdir2="$fixt/deleg"
    mkdir -p "$fdir2"
    {
        printf 'pub async fn deleg_handler() {\n'
        printf '    let _c = enforce_send_economy(state);\n'
        printf '    deleg_target(state, deps, ctx)\n'
        printf '}\n'
    } > "$fdir2/handler.rs"

    local out_ok out_bad
    # Delegate IS in the fail-closed set -> handler must NOT be flagged.
    out_ok=$(
        DELEGATES_BAK="$PERSIST_DELEGATES"
        find "$fdir2" -type f -name '*.rs' -print0 \
            | while IFS= read -r -d '' f; do
                PERSIST_DELEGATES="deleg_handler:deleg_target" FC_FUNCS="deleg_target" scan_file "$f"
            done
    )
    if grep -q $'^HIT\t.*\tdeleg_handler$' <<< "$out_ok"; then
        printf '%sSELF-TEST FAILED%s: a handler delegating to a fail-closed function was flagged.\n' \
            "$C_RED" "$C_RESET" >&2
        rc=1
    fi
    # Delegate is NOT in the fail-closed set (regressed) -> handler MUST be flagged.
    out_bad=$(
        find "$fdir2" -type f -name '*.rs' -print0 \
            | while IFS= read -r -d '' f; do
                PERSIST_DELEGATES="deleg_handler:deleg_target" FC_FUNCS="" scan_file "$f"
            done
    )
    if ! grep -q $'^HIT\t.*\tdeleg_handler$' <<< "$out_bad"; then
        printf '%sSELF-TEST FAILED%s: a handler whose delegate stopped persisting fail-closed\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'was NOT flagged — a delegate regression would slip through.\n' >&2
        rc=1
    fi

    rm -rf "$fixt"
    return "$rc"
}

if [[ ! -d "$SCAN_DIR" ]]; then
    printf '%serror:%s scan dir %s does not exist\n' \
        "$C_RED" "$C_RESET" "$SCAN_DIR" >&2
    exit 2
fi

if [[ -z "${NO_CLASS_S_SELFTEST:-}" ]]; then
    if ! self_test; then
        printf '%sThe class-S consume-site gate is dead — fix the scanner.%s\n' \
            "$C_RED" "$C_RESET" >&2
        exit 1
    fi
    printf '%sself-test:%s gate catches a missed consume site and clears fixed/helper sites.\n' \
        "$C_DIM" "$C_RESET"
fi

if run_scan "$SCAN_DIR" "scan"; then
    printf '%sPASSED%s: every spending-nonce consume site persists fail-closed (ADR-049 §9).\n' \
        "$C_GREEN" "$C_RESET"
    exit 0
fi
exit 1
