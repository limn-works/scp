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
#     threshold_signers.retain(    — REMOVES a governance threshold signer
#                                    (execute_remove_signer / the
#                                    reconfigure-governance RemoveInactiveSigner
#                                    arm). `.push` is UPWARD (execute_add_signer,
#                                    allowlisted) and is deliberately NOT a
#                                    marker — only the removal is downward.
#     threshold_value=             — lowers/raises the governance threshold
#                                    (execute_modify_threshold / the
#                                    reconfigure-governance ReduceThreshold arm).
#                                    A weaker threshold rolled back in is a
#                                    downward governance-control transition.
#     role_state.ceiling=          — REPLACES the capability ceiling
#                                    (apply_pending_ceiling_modification, a
#                                    NON-`execute_` leaf that lowers the
#                                    effective ceiling — Seam 1/black-hat). A
#                                    crash that restores the prior, broader
#                                    ceiling re-grants removed authority.
#
#     The last two use the `=` ASSIGNMENT form (matched against the
#     assignment-normalized line; see `normalize_assign`) so the WRITE is
#     flagged but a read (`ceiling.contains`, `threshold_value > n`) or a
#     comparison (`threshold_value == n`) is not.
#
#     DELIBERATELY NOT A MARKER — `system_assign_role(`: it is
#     direction-AGNOSTIC (it is the single role-write primitive used for BOTH
#     upward grants — execute_add_member, join_context_membership — and downward
#     demotions — execute_change_role, execute_transfer_admin). Adding it would
#     false-flag the upward/neutral callers (a HIT, since the HIT rule does not
#     consult the governance allowlist) and the borrowed-state consequence
#     helper enforce_assign_role. Its DOWNWARD callers are already `execute_*`
#     leaves that persist fail-closed, so the round-9 fail-closed-by-DEFAULT
#     governance-leaf rule (GOVHIT) already re-flags either if it regressed to
#     best-effort — they need no marker.
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
# ROUND-9 KEYSTONE — FAIL-CLOSED-BY-DEFAULT FOR GOVERNANCE LEAVES
# ---------------------------------------------------------------------------
# The MUTATORS-marker rule closes the class along the spending-nonce / explicit
# downward-mutator axis, but a governance leaf can transition authorization
# DOWNWARD without tripping any marker. `execute_change_role` demoting a member
# writes role state directly; it carries no `suspend_*` / `remove_member` /
# `executed_proposals` token, so reverting it to a best-effort persist used to
# slip past the gate entirely (the white-hat round-7 hole). And a NEW
# downward-auth handler could be silenced just by adding it to a Class-C
# allowlist that the gate did not couple to anything.
#
# This gate therefore ALSO enforces a fail-closed-by-DEFAULT rule for the
# governance-leaf class: every `execute_*` governance leaf (the arms of
# dispatch_governance_action / dispatch_context_governance_action /
# dispatch_content_governance_action and the `execute_*` leaves they call) that
# persists BEST-EFFORT and does NOT also fail-close MUST be listed in
# CLASS_C_GOVERNANCE_LEAVES — the explicit allowlist of the genuinely UPWARD /
# NEUTRAL / PUBLIC leaves. A best-effort governance leaf that is NOT allowlisted
# FAILS (GOVHIT). So a downward-auth leaf either fail-closes or becomes a
# CONSCIOUS, reviewable allowlist add — it can never silently ride the coalesced
# path again.
#
# ALLOWLIST COUPLING (closes the uncoupled-allowlist hole): every entry in
# CLASS_C_GOVERNANCE_LEAVES (and CLASS_C_EXCEPTIONS) MUST name a function that
# actually exists in the scanned tree — a stale or mistyped entry FAILS the gate
# instead of silently exempting nothing (or, worse, a future fn that reuses the
# name). Governance-leaf allowlist entries must additionally be real `execute_*`
# leaves, so a non-leaf cannot be parked in the governance allowlist.
#
# The combined gate = (governance leaves fail-closed-or-allowlisted)
#                   + (every non-governance Class-S consume site fail-closed)
#                   + (both allowlists coupled to real functions).
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
executed_proposals.insert( \
threshold_signers.retain( \
threshold_value= \
role_state.ceiling="

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

# ---------------------------------------------------------------------------
# CLASS_C_GOVERNANCE_LEAVES — the FAIL-CLOSED-BY-DEFAULT governance allowlist
# (round-9 keystone, ADR-049 §9). The MUTATORS-marker rule above closes the
# class along the *spending-nonce / explicit downward-mutator* axis, but a
# governance leaf can transition authorization downward WITHOUT tripping any
# marker — e.g. `execute_change_role` demoting a member writes role state
# directly, contains no `suspend_*` / `remove_member` / `executed_proposals`
# token, and so reverting it to a best-effort persist slipped past the gate
# (the white-hat round-7 hole). Worse, a NEW downward-auth leaf could be
# silenced by adding it to `CLASS_C_EXCEPTIONS`, an allowlist the gate did not
# couple to anything.
#
# This allowlist inverts the default for the GOVERNANCE-LEAF class: any
# `execute_*` governance leaf (the arms of dispatch_governance_action /
# dispatch_context_governance_action / dispatch_content_governance_action and
# the `execute_*` leaves they call) whose body uses `persist_state_best_effort`
# MUST be listed here as a genuinely UPWARD / NEUTRAL / PUBLIC leaf, or the gate
# FAILS. A downward-auth leaf therefore either fail-closes (persist_state_
# fail_closed) or is a CONSCIOUS, reviewable allowlist add — it can no longer
# regress to best-effort silently, and a new downward handler cannot be hidden
# by an uncoupled exception entry.
#
# Each entry below is a real `execute_*` fn that legitimately rides best-effort
# (Class C) because its effect is upward (grants/adds authority), neutral
# (policy/config that does not lower anyone's authority), or public (no MLS
# key secrecy). The proposal-executed marker it co-persists is coalesced-ATOMIC
# with the effect (same snapshot, rolls back together, re-execution reproduces
# the single effect — no replay divergence; see ADR-049 §9). The list is
# verified against the actual dispatch arms; a stale/typo entry that names a
# non-existent fn is caught by the coupling check below.
#
#   Upward (grant/add authority — rollback re-removes, never re-grants):
#     execute_add_member           — adds a member
#     execute_restore_access       — restores previously-revoked access
#     execute_approve_spend        — approves a spend allowance
#     execute_promote_context      — promotes a probationary context
#     execute_add_signer           — ADDS a threshold signer (the DOWNWARD
#                                    counterparts execute_remove_signer /
#                                    execute_modify_threshold are fail-closed)
#     execute_extend_ttl           — extends lifetime (never shortens)
#   Neutral (policy/config/registration — no member authority lowered):
#     execute_register_tool        — registers a tool
#     execute_establish_tool_interface — establishes a tool interface
#     execute_set_economic_policy  — sets economic policy
#     execute_lock_economic_policy — locks economic policy (one-way latch)
#     execute_modify_hard_rate_limit   — adjusts the anti-spam rate cap
#     execute_modify_pruning_policy    — adjusts pruning policy
#     execute_propose_context_migration — opens a migration proposal
#     execute_cancel_context_migration  — cancels a pending migration proposal
CLASS_C_GOVERNANCE_LEAVES="execute_add_member execute_restore_access \
execute_approve_spend execute_promote_context execute_add_signer \
execute_extend_ttl execute_register_tool execute_establish_tool_interface \
execute_set_economic_policy execute_lock_economic_policy \
execute_modify_hard_rate_limit execute_modify_pruning_policy \
execute_propose_context_migration execute_cancel_context_migration"

SCAN_DIR="crates/scp-runtime/src/context"

# The fail-closed set used to be collected by a SEPARATE `collect_failclosed`
# awk parser (a near-duplicate of the function tracker in `scan_file`). It has
# been removed: `scan_file` now emits an `FC<TAB>fn` line per fail-closed
# function, so the first pass in `run_scan` drives the SAME scanner with an
# empty `FC_FUNCS` and harvests the `FC` lines — one parser, no twin to drift.

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
        -v MUTATORS="$MUTATORS" -v CLASSC="$CLASS_C_EXCEPTIONS" \
        -v GOVLEAVES="$CLASS_C_GOVERNANCE_LEAVES" '
    # normalize_assign — collapse whitespace around a bare assignment `=` so a
    # space-free ASSIGNMENT marker (`threshold_value=`, `role_state.ceiling=`)
    # matches the downward-auth write `x = y` but NOT a read or a comparison.
    # The relational / equality operators are protected first (mapped to control
    # bytes) so `==`, `!=`, `>=`, `<=` are never seen as a bare `=` — an
    # assignment marker therefore cannot false-match a comparison such as
    # `threshold_value == n`. (The protected bytes need not be restored: no
    # marker contains them.)
    function normalize_assign(s,   t) {
        t = s
        gsub(/==/, "\x01", t)
        gsub(/!=/, "\x02", t)
        gsub(/>=/, "\x03", t)
        gsub(/<=/, "\x04", t)
        gsub(/[[:space:]]*=[[:space:]]*/, "=", t)
        return t
    }
    BEGIN {
        in_block = 0
        seen_test = 0
        depth = 0
        in_fn = 0
        fn_name = ""
        fn_line = 0
        fn_mutates = 0
        fn_failclosed = 0
        fn_besteffort = 0
        scanned = 0
        n = split(HELPERS, harr, " ")
        for (i = 1; i <= n; i++) if (harr[i] != "") helper[harr[i]] = 1
        c = split(CLASSC, carr, " ")
        for (i = 1; i <= c; i++) if (carr[i] != "") classc[carr[i]] = 1
        # Fail-closed-by-default governance-leaf allowlist (round-9 keystone).
        g = split(GOVLEAVES, garr, " ")
        for (i = 1; i <= g; i++) if (garr[i] != "") govleaf[garr[i]] = 1
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

        # Trailing test-MODULE cutoff: once a top-level (column-0) test-gated
        # module opens, every line below it is test code and is not scanned.
        # The trailing test module is gated by a column-0 attribute in one of
        # these forms:
        #     #[cfg(test)]
        #     #[cfg(all(test, feature = "testing"))]   (e.g. lifecycle_helpers)
        #     #[cfg(any(test, feature = "testing"))]   (e.g. context/mod.rs)
        # The column-0 anchor (`^`) is deliberate: an INTERSPERSED testing-only
        # accessor (a single `#[cfg(any(test, ..))]` / `#[cfg(feature =
        # "testing")]` fn sitting INSIDE an impl/among production fns, always
        # indented) must NOT trigger the "skip rest of file" cutoff, or the
        # production fns BELOW it (e.g. the reserve_tool_economy consume sites in
        # tools_helpers.rs) would stop being scanned and the gate would go
        # vacuous. Indented test gates are left in the production stream; they
        # carry no Class-S marker, and the assignment markers (normalize_assign)
        # only fire on real writes. Every column-0 test gate in the scan tree is
        # verified to be a TRAILING module (no column-0 production fn follows).
        if (raw ~ /^#\[cfg\(test\)\]/ \
            || raw ~ /^#\[cfg\(all\(test[,)]/ \
            || raw ~ /^#\[cfg\(any\(test[,)]/) { seen_test = 1 }
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
            fn_besteffort = 0
            pending = 0
            scanned++
        }

        # Within a function body, look for Class-S mutation markers, the
        # fail-closed persist, AND the best-effort persist (round-9 keystone:
        # a governance leaf that best-effort-persists must be allowlisted).
        # Markers are matched as literal substrings against an
        # assignment-normalized copy of the line: whitespace around a bare `=`
        # is collapsed (`x = y` -> `x=y`) so a space-free ASSIGNMENT marker
        # (e.g. `threshold_value=`, `role_state.ceiling=`) matches the
        # downward-auth write while NOT matching a read or a comparison. The
        # relational/equality operators `== != >= <=` are protected first, so an
        # assignment marker can never false-match a comparison (e.g.
        # `threshold_value == n`). Markers without `=` (the original tracker /
        # suspend / remove_member / executed_proposals set) are unaffected —
        # collapsing `=` spacing cannot newly match a marker that has no `=`.
        if (in_fn) {
            mline = normalize_assign(line)
            for (mi = 1; mi <= nm; mi++) {
                if (marr[mi] != "" && index(mline, marr[mi]) > 0) { fn_mutates = 1; break }
            }
            if (line ~ /persist_state_fail_closed[[:space:]]*\(/) fn_failclosed = 1
            if (line ~ /persist_state_best_effort[[:space:]]*\(/) fn_besteffort = 1
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

            # Round-9 keystone — fail-closed-by-default for GOVERNANCE leaves.
            # An `execute_*` leaf (a dispatch arm / leaf the governance
            # dispatchers call) that persists best-effort and is NOT a
            # fail-closed leaf MUST be in CLASS_C_GOVERNANCE_LEAVES, else it is
            # a downward-auth leaf silently riding the coalesced path (the
            # round-7 hole). A leaf that ALSO fail-closes somewhere in its body
            # (e.g. a mixed FC+BE body) is not flagged — it already persists
            # fail-closed for its downward effect.
            if (fn_name ~ /^execute_/ && fn_besteffort && !fn_failclosed \
                && !(fn_name in govleaf)) {
                printf("GOVHIT\t%s\t%d\t%s\n", FILE, fn_line, fn_name)
            }

            # Emit every governance-leaf fn definition seen, so the allowlist
            # coupling check can verify each CLASS_C_GOVERNANCE_LEAVES entry
            # names a REAL function (catching a typo / stale entry).
            if (fn_name ~ /^execute_/) {
                printf("GOVFN\t%s\n", fn_name)
            }
            # Emit EVERY production fn definition seen, so the coupling check can
            # verify each CLASS_C_EXCEPTIONS entry names a real function too.
            printf("FNDEF\t%s\n", fn_name)
            # Emit the fail-closed set so the first pass can be driven by this
            # same scanner (no separate collect_failclosed parser needed): a
            # function that persists fail-closed in its own body is an `FC`.
            if (fn_failclosed) printf("FC\t%s\n", fn_name)

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
# check_allowlist_coupling — round-9 keystone. Every entry in
# CLASS_C_GOVERNANCE_LEAVES and CLASS_C_EXCEPTIONS MUST name a function that
# actually exists in the scanned tree (collected as the FNDEF / GOVFN sets in
# `$1`). A typo or a stale entry (a fn that was renamed/removed) therefore FAILS
# the gate instead of silently disabling enforcement for the real fn it was
# meant to cover — closing the white-hat "uncoupled allowlist" hole. Governance
# leaves are additionally required to be real `execute_*` defs (the GOVFN set),
# so a non-leaf cannot be parked in the governance allowlist.
#
# Args:
#   $1 — file holding the scan output (FNDEF / GOVFN lines)
# ---------------------------------------------------------------------------
check_allowlist_coupling() {
    local out_file="$1"
    local all_fns gov_fns
    all_fns=" $(awk -F'\t' '$1=="FNDEF"{print $2}' "$out_file" | sort -u | tr '\n' ' ') "
    gov_fns=" $(awk -F'\t' '$1=="GOVFN"{print $2}' "$out_file" | sort -u | tr '\n' ' ') "

    local missing_gov="" missing_exc="" e
    for e in $CLASS_C_GOVERNANCE_LEAVES; do
        case "$gov_fns" in
            *" $e "*) : ;;
            *) missing_gov="$missing_gov $e" ;;
        esac
    done
    for e in $CLASS_C_EXCEPTIONS; do
        case "$all_fns" in
            *" $e "*) : ;;
            *) missing_exc="$missing_exc $e" ;;
        esac
    done

    local rc=0
    if [[ -n "$missing_gov" ]]; then
        printf '\n%sFAILED%s (allowlist coupling): CLASS_C_GOVERNANCE_LEAVES entr(ies)\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'name no real `execute_*` governance leaf:%s\n' "$missing_gov" >&2
        printf 'A stale or mistyped allowlist entry silently disables fail-closed-by-\n' >&2
        printf 'default for the leaf it was meant to cover. Fix the name or remove it.\n' >&2
        rc=1
    fi
    if [[ -n "$missing_exc" ]]; then
        printf '\n%sFAILED%s (allowlist coupling): CLASS_C_EXCEPTIONS entr(ies) name no\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'real function:%s\n' "$missing_exc" >&2
        printf 'A stale Class-C carve-out would silently exempt nothing (or, worse, a\n' >&2
        printf 'future fn that reuses the name). Fix the name or remove it.\n' >&2
        rc=1
    fi
    return "$rc"
}

# ---------------------------------------------------------------------------
# run_scan — scan a directory of *.rs files, evaluate, print verdict.
# Returns 0 PASS / 1 FAIL. Factored out so the self-test can drive it against
# synthetic fixtures.
#   $1 — scan dir
#   $2 — label
#   $3 — (optional) "skip-coupling" to suppress the allowlist-coupling check
#        (the self-test fixtures use partial trees that lack the real leaves).
# ---------------------------------------------------------------------------
run_scan() {
    local scan_dir="$1"
    local label="${2:-scan}"
    local coupling="${3:-check-coupling}"

    local tmp_out
    tmp_out=$(mktemp)

    printf '\n%sclass-s mutation-site %s:%s %s\n' \
        "$C_DIM" "$label" "$C_RESET" "$scan_dir"

    # First pass: collect every production function that persists fail-closed,
    # so persist-delegates can be verified in the second pass. Driven by the
    # SAME `scan_file` scanner (it emits an `FC<TAB>fn` line per fail-closed
    # function), so there is a single function-tracking parser, not a twin.
    # `FC_FUNCS` is empty for this pass (delegate resolution is irrelevant when
    # we only want the FC set; the FC emission does not depend on it).
    FC_FUNCS=$(
        find "$scan_dir" -type f -name '*.rs' -print0 \
            | while IFS= read -r -d '' file; do
                FC_FUNCS="" scan_file "$file"
            done | awk -F'\t' '$1=="FC"{print $2}' | sort -u | tr '\n' ' '
    )
    export FC_FUNCS

    # Second pass: the mutation-site check.
    find "$scan_dir" -type f -name '*.rs' -print0 \
        | while IFS= read -r -d '' file; do
            scan_file "$file"
        done > "$tmp_out"

    local hits govhits scanned_total
    hits=$(grep -c $'^HIT\t' "$tmp_out" 2>/dev/null || true)
    hits=${hits:-0}
    govhits=$(grep -c $'^GOVHIT\t' "$tmp_out" 2>/dev/null || true)
    govhits=${govhits:-0}
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

    # Round-9 keystone — governance leaves that best-effort-persist but are not
    # allowlisted as upward/neutral/public.
    if [[ "$govhits" -ne 0 ]]; then
        printf '\n%sFAILED%s: %d governance leaf/leaves (ADR-049 §9) persist BEST-EFFORT\n' \
            "$C_RED" "$C_RESET" "$govhits" >&2
        printf 'but are NOT in CLASS_C_GOVERNANCE_LEAVES — a downward-authorization\n' >&2
        printf 'transition silently riding the coalesced (Class-C) path can roll back in\n' >&2
        printf 'the ≤50ms window AFTER the caller saw success, re-granting removed\n' >&2
        printf 'authority:\n' >&2
        while IFS=$'\t' read -r tag file line fn; do
            [[ "$tag" == "GOVHIT" ]] || continue
            printf '      %s%s:%s%s  fn %s%s%s\n' \
                "$C_DIM" "$file" "$line" "$C_RESET" \
                "$C_YELLOW" "$fn" "$C_RESET" >&2
        done < "$tmp_out"
        printf '\n' >&2
        printf 'If this leaf transitions authorization DOWNWARD, replace\n' >&2
        printf '`persist_state_best_effort` with `persist_state_fail_closed` (mirroring\n' >&2
        printf 'execute_change_role / execute_remove_signer / execute_modify_threshold).\n' >&2
        printf 'If it is genuinely UPWARD/NEUTRAL/PUBLIC, add it to\n' >&2
        printf 'CLASS_C_GOVERNANCE_LEAVES with a one-line justification — a CONSCIOUS,\n' >&2
        printf 'reviewable allowlist add. See ADR-049 §9 (round-9 keystone).\n' >&2
    fi

    # Round-9 keystone — allowlist coupling: every CLASS_C_GOVERNANCE_LEAVES /
    # CLASS_C_EXCEPTIONS entry must name a real function.
    local coupling_failed=0
    if [[ "$coupling" != "skip-coupling" ]]; then
        if ! check_allowlist_coupling "$tmp_out"; then
            coupling_failed=1
        fi
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

    if [[ "$hits" -eq 0 && "$govhits" -eq 0 && "$coupling_failed" -eq 0 ]]; then
        return 0
    fi
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
#       NOT added to MUTATORS) IS caught by the P1-A coupling check;
#   (11) a best-effort NON-`execute_` ceiling-lowering leaf IS caught via the
#        `role_state.ceiling=` assignment marker (Seam-1 / black-hat);
#   (12) a downward threshold mutation INLINED in a `dispatch_*` fn IS caught
#        via the `threshold_value=` assignment marker (Seam-2);
#   (13) an UPWARD signer add (`.push` + a `threshold_value >` read) is NOT
#        flagged — the threshold markers fire only on removal / assignment;
#   (14) a fail-closed signer removal (`.retain` + fail-closed persist) is NOT
#        flagged.
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

    # (11) Seam-1/black-hat — a NON-`execute_` ceiling-lowering leaf
    # (apply_pending_ceiling_modification-shaped) reverted to best-effort MUST
    # be caught by the `role_state.ceiling=` ASSIGNMENT marker. Its real name is
    # not `execute_*`, so ONLY the mutation marker (not the GOVHIT rule) sees it.
    {
        printf 'pub async fn apply_ceiling_fixture() {\n'
        printf '    state.role_state.ceiling = CapabilityCeiling::new(lowered);\n'
        printf '    persist_state_best_effort(state, deps, ctx);\n'
        printf '}\n'
    } > "$fdir/ceiling.rs"

    # (12) Seam-2 — a downward threshold mutation INLINED in a `dispatch_*` fn
    # (a non-`execute_` name) with a best-effort persist MUST be caught by the
    # `threshold_value=` ASSIGNMENT marker (the GOVHIT rule keys on `execute_*`
    # and would miss this).
    {
        printf 'pub fn dispatch_threshold_fixture() {\n'
        printf '    state.governance.threshold_value = weaker;\n'
        printf '    persist_state_best_effort(state, deps, ctx);\n'
        printf '}\n'
    } > "$fdir/dispatch_threshold.rs"

    # (13) UPWARD signer add (execute_add_signer-shaped `.push`) MUST NOT be
    # flagged by the new threshold markers — only `.retain` (removal) is a
    # marker, `.push` is not, and the `threshold_value >`/`>=` reads normalize
    # to non-`=` forms. Persists best-effort (it is genuinely upward). Named
    # non-`execute_` so the GOVHIT rule cannot mask a false HIT here.
    {
        printf 'pub fn add_signer_upward_fixture() {\n'
        printf '    if state.governance.threshold_value > remaining { return; }\n'
        printf '    state.governance.threshold_signers.push(did.clone());\n'
        printf '    persist_state_best_effort(state, deps, ctx);\n'
        printf '}\n'
    } > "$fdir/add_signer.rs"

    # (14) Downward signer REMOVAL fail-closed (execute_remove_signer-shaped)
    # MUST NOT be flagged — `.retain` is a marker but the fn fail-closes.
    {
        printf 'pub fn remove_signer_fixture() {\n'
        printf '    state.governance.threshold_signers.retain(|s| s != did);\n'
        printf '    persist_state_fail_closed(state, deps, ctx)?;\n'
        printf '}\n'
    } > "$fdir/remove_signer.rs"

    # (8) Round-9 keystone — a governance leaf that persists BEST-EFFORT and is
    # NOT in CLASS_C_GOVERNANCE_LEAVES MUST be caught (GOVHIT). This models a
    # downward-auth leaf (e.g. execute_change_role) reverted to best-effort: it
    # carries NO MUTATORS marker, so ONLY the fail-closed-by-default rule sees
    # it. `execute_demote_fixture` is not in the allowlist.
    {
        printf 'pub fn execute_demote_fixture() {\n'
        printf '    state.role_state.assign_role(did, lower_role);\n'
        printf '    persist_state_best_effort(state, deps, ctx);\n'
        printf '}\n'
    } > "$fdir/govleaf_bad.rs"

    # (9) Round-9 keystone — an allowlisted governance leaf that persists
    # best-effort MUST NOT be flagged. `execute_add_member` is a real
    # CLASS_C_GOVERNANCE_LEAVES entry (upward — adds authority).
    {
        printf 'pub fn execute_add_member() {\n'
        printf '    state.membership.add_member(did, role, tokens);\n'
        printf '    persist_state_best_effort(state, deps, ctx);\n'
        printf '}\n'
    } > "$fdir/govleaf_ok.rs"

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
    # (11) Seam-1/black-hat: a best-effort NON-`execute_` ceiling-lowering leaf
    # MUST be caught via the `role_state.ceiling=` assignment marker.
    if ! grep -q $'^HIT\t.*\tapply_ceiling_fixture$' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a best-effort ceiling-lowering leaf was NOT caught\n' \
            "$C_RED" "$C_RESET" >&2
        printf '— the `role_state.ceiling=` downward-auth assignment marker is not wired.\n' >&2
        rc=1
    fi
    # (12) Seam-2: a downward threshold mutation INLINED in a `dispatch_*` fn
    # (non-`execute_` name, best-effort) MUST be caught via `threshold_value=`.
    if ! grep -q $'^HIT\t.*\tdispatch_threshold_fixture$' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a best-effort inlined downward threshold mutation in\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'a dispatch_* fn was NOT caught — the `threshold_value=` marker is not wired.\n' >&2
        rc=1
    fi
    # (13) UPWARD signer add (`.push` + a `threshold_value >` read) MUST NOT be
    # flagged — `.push` is not a marker and the comparison normalizes to non-`=`.
    if grep -q $'^HIT\t.*\tadd_signer_upward_fixture$' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: an UPWARD signer add was wrongly flagged — a\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'threshold marker false-matched `.push` or a `threshold_value >` read.\n' >&2
        rc=1
    fi
    # (14) Downward signer REMOVAL that fail-closes MUST NOT be flagged.
    if grep -q $'^HIT\t.*\tremove_signer_fixture$' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a fail-closed signer removal was wrongly flagged\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'despite persisting fail-closed (the `.retain` marker ignored the persist).\n' >&2
        rc=1
    fi
    # (8) Round-9 keystone: a best-effort governance leaf NOT in the allowlist
    # MUST be caught via GOVHIT (the fail-closed-by-default rule). This is the
    # axis that the round-7 `execute_change_role` revert slipped past.
    if ! grep -q $'^GOVHIT\t.*\texecute_demote_fixture$' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a best-effort governance leaf NOT in\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'CLASS_C_GOVERNANCE_LEAVES was NOT caught — the fail-closed-by-default\n' >&2
        printf 'rule is not wired (a downward-auth leaf could ride best-effort silently).\n' >&2
        rc=1
    fi
    # (9) Round-9 keystone: an allowlisted (upward) governance leaf that persists
    # best-effort MUST NOT be flagged.
    if grep -q $'^GOVHIT\t.*\texecute_add_member$' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: an allowlisted upward governance leaf\n' \
            "$C_RED" "$C_RESET" >&2
        printf '(execute_add_member) was wrongly flagged by the fail-closed-by-default rule.\n' >&2
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

    # (10) Round-9 keystone — allowlist coupling. Build a synthetic scan output
    # naming ONE real governance leaf + one ordinary fn, then assert:
    #   - a ghost CLASS_C_GOVERNANCE_LEAVES entry (no matching GOVFN) FAILS;
    #   - a ghost CLASS_C_EXCEPTIONS entry (no matching FNDEF) FAILS;
    #   - the present names PASS.
    local cpl="$fixt/coupling_out.txt"
    {
        printf 'GOVFN\texecute_add_member\n'
        printf 'FNDEF\texecute_add_member\n'
        printf 'FNDEF\tunsubscribe_broadcast\n'
    } > "$cpl"
    if (
        CLASS_C_GOVERNANCE_LEAVES="execute_add_member execute_ghost_leaf" \
            check_allowlist_coupling "$cpl" 2>/dev/null
    ); then
        printf '%sSELF-TEST FAILED%s: a ghost CLASS_C_GOVERNANCE_LEAVES entry\n' \
            "$C_RED" "$C_RESET" >&2
        printf '(naming no real execute_* leaf) was NOT caught by the coupling check.\n' >&2
        rc=1
    fi
    if (
        CLASS_C_EXCEPTIONS="unsubscribe_broadcast ghost_exception_fn" \
            check_allowlist_coupling "$cpl" 2>/dev/null
    ); then
        printf '%sSELF-TEST FAILED%s: a ghost CLASS_C_EXCEPTIONS entry (naming no real\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'function) was NOT caught by the coupling check.\n' >&2
        rc=1
    fi
    if ! (
        CLASS_C_GOVERNANCE_LEAVES="execute_add_member" \
            CLASS_C_EXCEPTIONS="unsubscribe_broadcast" \
            check_allowlist_coupling "$cpl" 2>/dev/null
    ); then
        printf '%sSELF-TEST FAILED%s: a fully-coupled allowlist (every entry a real fn)\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'was wrongly flagged by the coupling check.\n' >&2
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
    printf '%s          %s + best-effort governance-leaf sites, clears fixed/helper/\n' \
        "$C_DIM" "$C_RESET"
    printf '%s          %s delegate/allowlisted sites, and enforces P1-A + allowlist coupling.\n' \
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
