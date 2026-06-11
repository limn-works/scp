#!/usr/bin/env bash
# check-class-s-fail-closed.sh — CI gate enforcing ADR-049 §9's crash-safety
# invariant at the level of the MUTATION SITE, not just the snapshot field.
#
# ---------------------------------------------------------------------------
# WHAT THIS CHECKS
# ---------------------------------------------------------------------------
# ADR-049 §9 ("Respawn crash-safety invariant") classifies a set of mutations
# as Class S: a security-critical downward-authorization or anti-replay
# transition MUST be durably persisted (fail-closed) BEFORE the operation that
# performed it is acknowledged to the caller. If a handler performs such a
# mutation and then replies via a best-effort (coalesced) persist, an actor
# crash in the ≤50ms coalesce window rolls the mutation back — AFTER the caller
# already saw success. Examples of the resulting hazard:
#   - spending-UCAN nonce consume rolled back → replay / double-spend (BLACK-001)
#   - member ban / capability suspension rolled back → a banned member is
#     re-granted their capabilities after the caller was told the ban applied
#   - `executed_proposals` replay-marker rolled back → an executed governance
#     proposal can be replayed
#
# The sibling `security_critical_state_is_class_s_or_m_not_coalesced` test
# catches a security FIELD dropped from the snapshot builder. It does NOT catch
# a missed MUTATION SITE — a code path that performs a Class-S mutation and then
# replies WITHOUT a fail-closed persist. That is exactly how the message-send /
# paid-join nonce-consume sites (and, later, the `SuspendAccess` ban) were
# missed one-subsystem-at-a-time across earlier rounds. This gate closes the
# WHOLE class structurally so no future subsystem can silently reintroduce it.
#
# ---------------------------------------------------------------------------
# THE CLASS-S MUTATION MARKERS (the single source of truth: MUTATORS)
# ---------------------------------------------------------------------------
# A function whose body contains ANY of these markers performs a Class-S
# mutation and MUST persist fail-closed before acknowledging:
#
#   Spending-nonce consume (replay / double-spend):
#     commit_spending_ucan_nonce(  — the durable nonce insertion chokepoint
#     enforce_economy(             — shared paid-action helper (calls the above)
#     enforce_send_economy(        — MessageSend wrapper around enforce_economy
#     enforce_join_economy(        — ContextJoin wrapper around enforce_economy
#     spending_nonce_tracker.record(           — DIRECT tracker mutation, the
#     spending_nonce_tracker.check_and_record(   chokepoint-BYPASS that P1-B
#                                                closes: a handler that touches
#                                                the tracker directly instead of
#                                                via the chokepoint is still
#                                                detected. (The cross-crate FFI
#                                                `BridgeNonceTracker` adapter
#                                                lives OUTSIDE this scan dir, so
#                                                it is unaffected.)
#
#   Downward-authorization transitions (re-grant on rollback):
#     suspend_all(                 — strips a member's ENTIRE capability set
#     suspend_capabilities(        — strips a subset of a member's capabilities
#     membership.remove_member(    — removes a member's authorization
#
#   Anti-replay marker:
#     executed_proposals.insert(   — marks a governance proposal as executed
#
# ---------------------------------------------------------------------------
# HOW A MUTATING FUNCTION IS SATISFIED
# ---------------------------------------------------------------------------
# A function whose body contains a MUTATORS marker is satisfied iff one of:
#   (a) its OWN body also references `persist_state_fail_closed(` — the normal
#       case (every governance downward-auth `execute_*` leaf helper, the three
#       terminal economy handlers, `leave_context`); OR
#   (b) it is an allowlisted pass-through MUTATION HELPER (MUTATION_HELPERS) —
#       a pure-logic helper that mutates BORROWED sub-state (it has no `deps` /
#       full `PerContextState` and so CANNOT persist) and is persisted by its
#       acknowledging caller; OR
#   (c) it delegates persistence to a function listed in PERSIST_DELEGATES whose
#       body IS known (first pass) to persist fail-closed — so a delegate that
#       regresses to best-effort re-flags the handler; OR
#   (d) it is a documented Class-C carve-out (CLASS_C_EXCEPTIONS) — an
#       acknowledging function whose downward mutation is liveness/structural,
#       NOT authorization secrecy, so a coalesce-window rollback is benign. Each
#       carve-out is justified inline.
#
# A NEW mutating site that is none of the above FAILS this gate, forcing the
# author to add the fail-closed persist (or justify one of the allowlists).
#
# ---------------------------------------------------------------------------
# P1-A — THE ALLOWLIST/DETECTION COUPLING (no silent helper holes)
# ---------------------------------------------------------------------------
# Every MUTATION_HELPERS / CLASS_C_EXCEPTIONS entry that names a CALL-style
# pass-through (i.e. callers route a Class-S mutation THROUGH it, e.g.
# `enforce_economy`) MUST also appear as a MUTATORS marker — otherwise a caller
# could route a consume through an allowlisted-but-undetected helper and never
# be flagged. The gate ENFORCES this coupling: it derives the set of
# "pass-through helper names" and checks each is present in MUTATORS. Adding a
# pass-through helper to the allowlist without adding its `name(` marker to
# MUTATORS is itself a gate FAILURE. (Leaf mutators that are NOT call-style
# pass-throughs — e.g. `enforce_suspend`, which mutates inline rather than being
# something callers funnel a consume through — are exempt from the coupling
# requirement; they are flagged structurally via the markers they contain.)
#
# ---------------------------------------------------------------------------
# THE ALLOWLISTS
# ---------------------------------------------------------------------------
#   MUTATION_HELPERS (pass-throughs; acknowledging caller persists):
#     enforce_economy        — shared paid-action helper. Callers:
#                              send_message->finalize_send (FC), join_context (FC),
#                              reserve_tool_economy (FC).
#     enforce_send_economy   — MessageSend wrapper. Caller: finalize_send (FC).
#     enforce_join_economy   — ContextJoin wrapper. Caller: join_context (FC).
#     dispatch_enforcement_action / enforce_suspend / emit_failure_escalation —
#                              consequence-rule (anti-spam, §19.7) enforcement
#                              helpers in governance_logic.rs. They take a
#                              BORROWED `ConsequenceStateSplit` (no `deps`, no
#                              full state) and so CANNOT persist; their caller
#                              (`finalize_send`) persists. Consequence-triggered
#                              suspensions are the ACCEPTED Class-C anti-spam
#                              residual (§9): a coalesce-window rollback of an
#                              anti-spam suspension is benign (the next message
#                              re-triggers the rule).
#
#   PERSIST_DELEGATES (handler:delegate — delegate body must persist FC):
#     send_message:finalize_send       — send ack + FC persist live in finalize_send.
#     execute_governance_action:dispatch_governance_action
#                                       — the proposal-executed marker is inserted
#                                         in execute_governance_action; the
#                                         per-action downward-auth arm in
#                                         dispatch_governance_action persists it
#                                         fail-closed (same `state`). The delegate
#                                         contains `persist_state_fail_closed`, so
#                                         a regression of ALL its fail-closed arms
#                                         re-flags the entry point.
#
#   CLASS_C_EXCEPTIONS (acknowledges; mutation is liveness, not auth secrecy):
#     unsubscribe_broadcast  — a broadcast context is PUBLIC (no MLS group key,
#                              no capability secrecy). `membership.remove_member`
#                              there is subscription bookkeeping; a coalesce
#                              rollback re-admits a subscriber who can freely
#                              re-subscribe to public content. No authorization
#                              or key secrecy is re-granted. (Class C.)
#
# ---------------------------------------------------------------------------
# P1-B — THE CHOKEPOINT BYPASS (closed by the tracker markers above)
# ---------------------------------------------------------------------------
# White-hat P1-B: a handler could bypass the gate's nonce coverage by calling
# the spending-nonce tracker's `record(` / `check_and_record(` directly instead
# of through `commit_spending_ucan_nonce`. The `spending_nonce_tracker.record(`
# and `spending_nonce_tracker.check_and_record(` markers above close that hole:
# any direct tracker mutation in the scan dir is now a detected consume site.
# Scoping the marker to the `spending_nonce_tracker` receiver avoids false hits
# on the unrelated watchdog `WindowedCounter::record(now_ms)` and metrics
# `histogram!(..).record(..)` calls that also live in the scan dir.
#
# ---------------------------------------------------------------------------
# WHEN THIS RUNS
# ---------------------------------------------------------------------------
# On every PR (cheap, no build). ADDITIVE coverage — it does not replace or
# weaken any existing enforcement script or the field-round-trip test.
#
# ---------------------------------------------------------------------------
# PORTABILITY
# ---------------------------------------------------------------------------
# Runs on macOS (BSD userland) and Linux (GNU userland). Pure awk + find.
#
# Usage:
#   bash scripts/check-class-s-fail-closed.sh
# Exit codes:
#   0  — every Class-S mutation site persists fail-closed (or is allowlisted)
#   1  — one or more mutation sites acknowledge without a fail-closed persist,
#        a pass-through helper is allowlisted-but-undetected (P1-A coupling
#        broken), or the self-test failed (the gate is dead)
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

# ---------------------------------------------------------------------------
# MUTATORS — the single source of truth for Class-S mutation markers. A
# function whose body contains any of these must persist fail-closed before
# acknowledging (or be allowlisted). Space-separated awk-regex tokens; each is
# matched literally as a substring (regex metachars escaped where present).
# Keep this list and the header in sync.
# ---------------------------------------------------------------------------
MUTATORS="commit_spending_ucan_nonce( \
enforce_economy( \
enforce_send_economy( \
enforce_join_economy( \
spending_nonce_tracker.record( \
spending_nonce_tracker.check_and_record( \
suspend_all( \
suspend_capabilities( \
membership.remove_member( \
executed_proposals.insert("

# Allowlisted pass-through MUTATION HELPERS (acknowledging caller persists).
# Those that are CALL-STYLE pass-throughs (callers route a Class-S mutation
# through them) MUST also be present as a `name(` token in MUTATORS — the gate
# enforces this coupling (P1-A). Leaf mutators that mutate inline (and are
# therefore detected via the marker they contain rather than via their own
# name) need not appear in MUTATORS.
MUTATION_HELPERS="enforce_economy enforce_send_economy enforce_join_economy \
dispatch_enforcement_action enforce_suspend emit_failure_escalation"

# The subset of MUTATION_HELPERS that are CALL-STYLE pass-throughs — callers
# funnel a Class-S mutation THROUGH them, so each MUST have a paired `name(`
# marker in MUTATORS (P1-A coupling). The consequence-enforcement helpers
# (dispatch_enforcement_action / enforce_suspend / emit_failure_escalation) are
# leaf mutators (they call suspend_* inline), detected via those markers, and
# are intentionally NOT in this set.
MUTATION_PASSTHROUGHS="enforce_economy enforce_send_economy enforce_join_economy"

# PERSIST DELEGATES: a mutating handler whose fail-closed persist lives in a
# function it CALLS (not its own body) maps `handler:delegate`. The delegate's
# body must contain `persist_state_fail_closed` (first pass) — so a delegate
# that regresses to best-effort re-flags the handler.
PERSIST_DELEGATES="send_message:finalize_send \
execute_governance_action:dispatch_governance_action"

# CLASS-C carve-outs: acknowledging functions whose downward mutation is
# liveness/structural (not authorization secrecy), so a coalesce-window rollback
# is benign. Each MUST be justified in the header. Space-separated fn names.
CLASS_C_EXCEPTIONS="unsubscribe_broadcast"

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
# where the function performed a Class-S mutation (a MUTATORS marker) but
# neither persisted fail-closed (directly or via a verified delegate) nor is an
# allowlisted helper / Class-C carve-out. Also emits:
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
# does not count as a mutation.
# ---------------------------------------------------------------------------
scan_file() {
    local file="$1"
    awk -v FILE="$file" -v HELPERS="$MUTATION_HELPERS" \
        -v DELEGATES="$PERSIST_DELEGATES" -v FC_FUNCS="${FC_FUNCS:-}" \
        -v MUTATORS="$MUTATORS" -v CLASSC="$CLASS_C_EXCEPTIONS" '
    BEGIN {
        in_block = 0
        seen_test = 0
        depth = 0
        in_fn = 0
        fn_name = ""
        fn_line = 0
        fn_mutates = 0
        fn_failclosed = 0
        scanned = 0
        n = split(HELPERS, harr, " ")
        for (i = 1; i <= n; i++) if (harr[i] != "") helper[harr[i]] = 1
        c = split(CLASSC, carr, " ")
        for (i = 1; i <= c; i++) if (carr[i] != "") classc[carr[i]] = 1
        # Persist-delegate map: handler -> delegate.
        m = split(DELEGATES, darr, " ")
        for (i = 1; i <= m; i++) {
            if (darr[i] == "") continue
            split(darr[i], kv, ":")
            delegate[kv[1]] = kv[2]
        }
        # Functions known to persist fail-closed (first pass).
        k = split(FC_FUNCS, farr, " ")
        for (i = 1; i <= k; i++) if (farr[i] != "") fc[farr[i]] = 1
        # Class-S mutation markers (literal substrings).
        nm = split(MUTATORS, marr, " ")
    }
    {
        raw = $0

        if (raw ~ /#\[cfg\(test\)\]/) { seen_test = 1 }
        if (seen_test) next

        line = raw
        # Strip string literals first (so a `/*` inside a string cannot wedge
        # the block-comment scanner, and so a marker name inside a string does
        # not count).
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
            fn_mutates = 0
            fn_failclosed = 0
            pending = 0
            scanned++
        }

        # Within a function body, look for Class-S mutation markers + the
        # fail-closed persist. Markers are matched as literal substrings.
        if (in_fn) {
            for (mi = 1; mi <= nm; mi++) {
                if (marr[mi] != "" && index(line, marr[mi]) > 0) { fn_mutates = 1; break }
            }
            if (line ~ /persist_state_fail_closed[[:space:]]*\(/) fn_failclosed = 1
        }

        depth += opens - closes

        # Function body closes when depth returns to its floor.
        if (in_fn && depth <= fn_floor) {
            # A mutating function is satisfied if it (a) persists fail-closed in
            # its own body, (b) is an allowlisted pass-through helper, (c) is a
            # documented Class-C carve-out, or (d) delegates persistence to a
            # function KNOWN to persist fail-closed (delegate in the first-pass
            # FC set — so a delegate regression re-flags the handler).
            satisfied = fn_failclosed || (fn_name in helper) || (fn_name in classc)
            if (!satisfied && (fn_name in delegate)) {
                if (delegate[fn_name] in fc) satisfied = 1
            }
            if (fn_mutates && !satisfied) {
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
# check_passthrough_coupling — P1-A enforcement. Every CALL-STYLE pass-through
# helper (MUTATION_PASSTHROUGHS) MUST be present as a `name(` token in MUTATORS,
# so allowlisting a pass-through that callers route a consume through cannot
# create a detection hole. Prints offending names; returns 1 if any are missing.
# ---------------------------------------------------------------------------
check_passthrough_coupling() {
    local missing=""
    local h
    for h in $MUTATION_PASSTHROUGHS; do
        # MUTATORS holds `name(` tokens; require an exact `${h}(` token.
        case " $MUTATORS " in
            *" ${h}("*) : ;;
            *) missing="$missing $h" ;;
        esac
    done
    if [[ -n "$missing" ]]; then
        printf '\n%sFAILED%s (P1-A coupling): pass-through helper(s) are allowlisted\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'but NOT present as a detection marker in MUTATORS:%s\n' "$missing" >&2
        printf 'Add a `name(` token to MUTATORS for each, or the gate cannot see a\n' >&2
        printf 'consume routed through the allowlisted helper. See ADR-049 §9 (P1-A).\n' >&2
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# run_scan — scan a directory of *.rs files, evaluate, print verdict.
# Returns 0 PASS / 1 FAIL. Factored out so the self-test can drive it against
# synthetic fixtures.
#   $1 — scan dir
#   $2 — label
# ---------------------------------------------------------------------------
run_scan() {
    local scan_dir="$1"
    local label="${2:-scan}"

    local tmp_out
    tmp_out=$(mktemp)

    printf '\n%sclass-s mutation-site %s:%s %s\n' \
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

    # Second pass: the mutation-site check.
    find "$scan_dir" -type f -name '*.rs' -print0 \
        | while IFS= read -r -d '' file; do
            scan_file "$file"
        done > "$tmp_out"

    local hits scanned_total
    hits=$(grep -c $'^HIT\t' "$tmp_out" 2>/dev/null || true)
    hits=${hits:-0}
    scanned_total=$(awk -F'\t' '$1=="SCANNED"{s+=$3} END{print s+0}' "$tmp_out")

    if [[ "$hits" -ne 0 ]]; then
        printf '\n%sFAILED%s: %d function(s) perform a Class-S mutation (ADR-049 §9)\n' \
            "$C_RED" "$C_RESET" "$hits" >&2
        printf 'and acknowledge WITHOUT a fail-closed persist (downward-auth /\n' >&2
        printf 'anti-replay / spending-nonce — BLACK-001):\n' >&2
        while IFS=$'\t' read -r tag file line fn; do
            [[ "$tag" == "HIT" ]] || continue
            printf '      %s%s:%s%s  fn %s%s%s\n' \
                "$C_DIM" "$file" "$line" "$C_RESET" \
                "$C_YELLOW" "$fn" "$C_RESET" >&2
        done < "$tmp_out"
        printf '\n' >&2
        printf 'Add `persist_state_fail_closed(..)` before the function returns success,\n' >&2
        printf 'mirroring execute_suspend_member / execute_remove_member / finalize_send.\n' >&2
        printf 'If this is a NEW pass-through helper whose caller persists, add it to\n' >&2
        printf 'MUTATION_HELPERS (and, if call-style, a marker to MUTATORS) WITH a covering\n' >&2
        printf 'crash-survival test. If the mutation is genuinely liveness (not auth\n' >&2
        printf 'secrecy), add a justified CLASS_C_EXCEPTIONS entry. See ADR-049 §9.\n' >&2
    fi

    rm -f "$tmp_out"

    # Vacuity guard: the runtime context module has many functions; a near-zero
    # scan means the function tracker is broken and the gate is vacuous.
    if [[ "${label}" == "scan" && "${scanned_total}" -lt 50 ]]; then
        printf '\n%sFAILED%s: mutation-site scan is vacuous — only %d production\n' \
            "$C_RED" "$C_RESET" "$scanned_total" >&2
        printf 'function(s) inspected (expected >= 50). The function tracker is broken.\n' >&2
        return 1
    fi

    [[ "$hits" -eq 0 ]] && return 0
    return 1
}

# ---------------------------------------------------------------------------
# SELF-TEST — prove the gate is not dead. Build synthetic fixtures and assert:
#   (1) a function that performs a Class-S mutation (spending-nonce consume) but
#       does NOT persist fail-closed and is NOT allowlisted IS caught;
#   (2) a function that mutates AND persists fail-closed in the same body is NOT
#       flagged;
#   (3) an allowlisted pass-through helper that mutates without persisting is
#       NOT flagged;
#   (4) a delegate that regresses to best-effort re-flags the handler;
#   (5) a best-effort SuspendAccess (suspend_all) IS caught — the generalized
#       downward-auth marker (the round-7 miss, reverted);
#   (6) a `.record()` chokepoint-BYPASS handler IS caught (P1-B);
#   (7) the allowlist-hole attempt (a new pass-through helper allowlisted but
#       NOT added to MUTATORS) IS caught by the P1-A coupling check.
# Set NO_CLASS_S_SELFTEST=1 to skip (not recommended).
# ---------------------------------------------------------------------------
self_test() {
    local fixt
    fixt=$(mktemp -d)
    local fdir="$fixt/ctx"
    mkdir -p "$fdir"

    # (1) Missed spending-nonce consume — MUST be caught.
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

    # (5) Best-effort SuspendAccess (suspend_all) — MUST be caught. This is the
    # round-7 miss, reverted to best-effort.
    {
        printf 'pub fn suspend_access_fixture() {\n'
        printf '    state.role_state.suspend_all(did.as_ref());\n'
        printf '    persist_state_best_effort(state, deps, ctx);\n'
        printf '}\n'
    } > "$fdir/suspend.rs"

    # (6) Chokepoint-BYPASS via direct tracker mutation — MUST be caught (P1-B).
    {
        printf 'pub fn bypass_fixture() {\n'
        printf '    state.governance.spending_nonce_tracker.record(nnc, exp);\n'
        printf '    persist_state_best_effort(state, deps, ctx);\n'
        printf '}\n'
    } > "$fdir/bypass.rs"

    local rc=0
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
    if ! grep -q $'^HIT\t.*\tsuspend_access_fixture$' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a best-effort SuspendAccess (suspend_all) was NOT\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'caught — the generalized downward-auth marker is not wired.\n' >&2
        rc=1
    fi
    if ! grep -q $'^HIT\t.*\tbypass_fixture$' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a direct spending_nonce_tracker.record() bypass was\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'NOT caught — the P1-B chokepoint-bypass marker is not wired.\n' >&2
        rc=1
    fi

    # (4) Persist-delegate path. A handler that mutates and delegates its
    # fail-closed persist to a mapped delegate is NOT flagged WHEN the delegate
    # is known to persist fail-closed, but IS flagged when it is NOT.
    local fdir2="$fixt/deleg"
    mkdir -p "$fdir2"
    {
        printf 'pub async fn deleg_handler() {\n'
        printf '    let _c = enforce_send_economy(state);\n'
        printf '    deleg_target(state, deps, ctx)\n'
        printf '}\n'
    } > "$fdir2/handler.rs"

    local out_ok out_bad
    out_ok=$(
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

    # (7) P1-A allowlist-hole attempt. Temporarily allowlist a NEW pass-through
    # helper WITHOUT adding its marker to MUTATORS; the coupling check MUST fail.
    if (
        MUTATION_PASSTHROUGHS="$MUTATION_PASSTHROUGHS new_passthrough_helper" \
            check_passthrough_coupling 2>/dev/null
    ); then
        printf '%sSELF-TEST FAILED%s: a pass-through helper allowlisted WITHOUT a paired\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'MUTATORS marker was NOT caught by the P1-A coupling check.\n' >&2
        rc=1
    fi
    # And the real configuration MUST pass the coupling check.
    if ! check_passthrough_coupling 2>/dev/null; then
        printf '%sSELF-TEST FAILED%s: the live MUTATION_PASSTHROUGHS / MUTATORS configuration\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'violates the P1-A coupling invariant.\n' >&2
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
        printf '%sThe class-S mutation-site gate is dead — fix the scanner.%s\n' \
            "$C_RED" "$C_RESET" >&2
        exit 1
    fi
    printf '%sself-test:%s gate catches missed consume / suspend_all / .record() bypass\n' \
        "$C_DIM" "$C_RESET"
    printf '%s          %s sites, clears fixed/helper/delegate sites, and enforces P1-A.\n' \
        "$C_DIM" "$C_RESET"
fi

# P1-A coupling check on the LIVE configuration (also part of the gate proper).
if ! check_passthrough_coupling; then
    exit 1
fi

if run_scan "$SCAN_DIR" "scan"; then
    printf '%sPASSED%s: every Class-S mutation site persists fail-closed (ADR-049 §9).\n' \
        "$C_GREEN" "$C_RESET"
    exit 0
fi
exit 1
