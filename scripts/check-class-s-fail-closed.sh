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
# mutation and MUST persist fail-closed before acknowledging. Markers are
# matched against the in-flight LOGICAL line, not the bare physical line: a
# method-chain continuation (a line beginning with `.`) or an argument list with
# unclosed call-parens is coalesced onto the running statement before matching,
# so a marker whose contiguous token is split across physical lines (e.g. the
# `prepare_a` shape `state` / `.xctx_caller_reservations` / `.insert(..)`) still
# fires. See "MULTI-LINE MARKER MATCHING" in `scan_file` for the exact rule;
# self-test fixtures (16)/(17) regression-guard it.
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
#   Cross-context saga staging markers (ADR-049 §9 line 144; spec §5.15.8,
#   §6.2.4):
#     saga_pending.insert(         — STAGES (Prepare) cross-context saga
#                                    evidence into the actor's `saga_pending`
#                                    map. ADR-049 §9 line 144 lists
#                                    `saga_pending` Prepare/Commit/Abort
#                                    transitions in the synchronously-persisted
#                                    Class-S set. A crash that rolled a staged
#                                    slot back behind an acked Prepare orphans
#                                    the supervisor saga journal's reservation
#                                    linkage (a wedged saga that can neither
#                                    commit nor cleanly abort). The §6.2.4
#                                    Prepare/Commit/Abort handlers MUST persist
#                                    fail-closed before acking.
#     saga_pending.remove(         — CLEARS (Commit/Abort) the staged slot. The
#                                    same Class-S fail-closed contract applies:
#                                    a Commit/Abort that acks before persisting
#                                    the cleared slot could re-stage a stale
#                                    saga on a crash respawn.
#                                    (The struct-literal `saga_pending:` forms
#                                    in the snapshot builders use `:`, not a
#                                    method call, so they are NOT flagged — only
#                                    the live-state `.insert(` / `.remove(`
#                                    mutations are.)
#     xctx_nonce_dedup.record(     — RECORDS an accepted cross-context invoke
#                                    nonce in B's anti-replay dedup cache
#                                    (spec §6.2.4 "Freshness / anti-replay").
#                                    The cache is Class-S persisted (it is the
#                                    only gate against a fresh-SagaId replay
#                                    within the 5-min TTL); a coalesce-window
#                                    rollback that re-opened a recorded nonce
#                                    would re-admit a replay (BLACK-624-01). The
#                                    Prepare-B handler records then persists
#                                    fail-closed BEFORE acking.
#     xctx_caller_reservations.insert( — STAGES (Prepare-A) the caller-side
#                                    durable reservation reversal record (spec
#                                    §6.2.4 "Reservation release on every terminal
#                                    path"). It is the ONLY durable handle that
#                                    lets a `PreparingB`-window crash recovery
#                                    (`Abort { None }`) reverse the caller's
#                                    persisted velocity/budget/hard-rate-limit
#                                    deduction and void the escrow without the
#                                    in-memory carrier; a coalesce-window rollback
#                                    that lost it behind an acked Prepare-A would
#                                    leave the deduction durable with no reversal
#                                    handle — a permanent over-charge + escrow
#                                    leak. Prepare-A inserts it then persists
#                                    fail-closed BEFORE acking. (Only `.insert(`
#                                    is a marker: the Commit-A / abort `.remove(`
#                                    consumes ride the same fail-closed persist as
#                                    the witness/refund they accompany, or — on
#                                    the idempotent-replay branch — are redundant
#                                    with the already-durable commit witness.)
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
saga_pending.insert( \
saga_pending.remove( \
xctx_nonce_dedup.record( \
xctx_caller_reservations.insert( \
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
    # matches the downward-auth write `x = y` but NOT a read, a comparison, or a
    # match arm. The relational / equality operators AND the match-arm fat arrow
    # are protected first (mapped to control bytes) so `==`, `!=`, `>=`, `<=`,
    # and `=>` are never seen as a bare `=` — an assignment marker therefore
    # cannot false-match a comparison such as `threshold_value == n` NOR a match
    # arm such as `threshold_value => ...` (which, without the `=>` guard, would
    # collapse to `threshold_value=>` and spuriously match `threshold_value=`).
    # No such match arm exists today, and this is the fail-closed direction (it
    # would only ever over-alert, never hide a write), but the guard keeps the
    # marker precise. (The protected bytes need not be restored: no marker
    # contains them.)
    function normalize_assign(s,   t) {
        t = s
        gsub(/==/, "\x01", t)
        gsub(/!=/, "\x02", t)
        gsub(/>=/, "\x03", t)
        gsub(/<=/, "\x04", t)
        gsub(/=>/, "\x05", t)
        gsub(/[[:space:]]*=[[:space:]]*/, "=", t)
        return t
    }
    # strip_code — return the CODE SKELETON of one physical line: the line with
    # the CONTENT of every comment and literal removed, so that braces, parens,
    # quotes, and the `;` terminator that live INSIDE a literal or comment are
    # NOT counted by the downstream brace-depth / paren / terminator / marker
    # logic. The naive gsub it replaces (which stripped a double-quoted run with
    # a single regex) was UNSOUND on ordinary Rust: an escaped quote, a raw
    # string, or a char literal containing a brace left a real brace/quote in the
    # residue, miscounting the function-body brace depth and closing the function
    # PREMATURELY. Every Class-S mutation after the poison then became invisible
    # (a live gate bypass on legal, cargo-fmt-clean code).
    #
    # This is a single left-to-right character scanner. It carries FOUR pieces
    # of MULTI-LINE state across physical lines via awk globals (like the
    # pre-existing block_depth): block_depth (NESTING depth of in-flight block
    # comments — Rust block comments NEST), in_raw_string (inside a raw or
    # raw-byte string), raw_hash (the OPENING hash count of the in-flight raw
    # string, so the matching closer is found), and in_string (inside an ordinary
    # or byte string that was left UNTERMINATED at end of line — a Rust normal
    # string may span physical lines both via a trailing `\` continuation AND via
    # a bare literal newline). Removed literal/comment content is replaced by a
    # single space placeholder so adjacent code tokens never accidentally fuse;
    # code characters (including a brace/paren/terminator/marker token that
    # legitimately appears in CODE, not in a literal) are emitted verbatim so
    # markers still match.
    #
    # Lexical rules (Rust): a line comment runs to end of line; a block comment
    # NESTS — `/* a /* b */ c */` ends at the SECOND `*/`, so we carry a
    # block_depth COUNTER (each `/*` in code context increments, each `*/`
    # decrements) across lines rather than a boolean; a string or byte string
    # honors backslash escapes so an escaped quote does NOT end it AND may run
    # PAST end of line (carried by in_string until the unescaped closing `"`),
    # whether or not a trailing `\` continuation is present; a raw or raw-byte
    # string uses its opening hash count to find the closer and may span lines via
    # in_raw_string + raw_hash; a char literal is a single char or backslash-
    # escape between quotes and is DISTINGUISHED from a lifetime (a quote followed
    # by an identifier that is NOT closed two chars later is a lifetime and is
    # left as code, since it carries no brace).
    # scan_block_comment — advance through an in-flight (depth > 0) NESTED block
    # comment starting at offset `bi`, counting `/*` (open) and `*/` (close)
    # tokens to maintain block_depth. Returns the offset just past the token that
    # drove block_depth back to 0, or 0 if the line ends still inside the comment
    # (block_depth stays > 0, carried to the next physical line). Rust block
    # comments NEST: `/* a /* b */ c */` ends at the SECOND `*/`, so a boolean
    # "in_block" closed such a comment one `*/` early and leaked the trailing
    # ` c */` (and any braces inside it) into the code residue.
    function scan_block_comment(s, bi,   m, o2, c2t) {
        m = bi
        while (block_depth > 0) {
            o2 = index(substr(s, m), "/*")
            c2t = index(substr(s, m), "*/")
            if (c2t == 0) {
                # No close on the rest of the line: still inside the comment.
                # A trailing open `/*` (o2 != 0) only deepens an already-open
                # comment; depth is carried regardless. Signal "line consumed".
                return 0
            }
            if (o2 != 0 && o2 < c2t) {
                # A nested open precedes the next close: go deeper, resume after.
                block_depth++
                m = m + (o2 - 1) + 2
            } else {
                # The next close balances the innermost open.
                block_depth--
                m = m + (c2t - 1) + 2
            }
        }
        return m
    }
    function strip_code(s,   out, i, ch, n, c2, hashes, closer, j, k, nxt, nxt2) {
        out = ""
        n = length(s)
        i = 1

        # Continuation of a multi-line ordinary/byte string from a previous line.
        # Resume scanning for the unescaped closing `"` (honoring `\` escapes).
        if (in_string) {
            while (i <= n) {
                if (substr(s, i, 1) == "\\") { i += 2; continue }
                if (substr(s, i, 1) == "\"") { i++; in_string = 0; break }
                i++
            }
            if (in_string) {
                # Entire line is still inside the string (no closing quote).
                return out
            }
            out = out " "
        }
        # Continuation of a multi-line raw string from a previous line.
        if (in_raw_string) {
            closer = "\""
            for (k = 0; k < raw_hash; k++) closer = closer "#"
            j = index(substr(s, i), closer)
            if (j == 0) {
                # Entire line is still inside the raw string.
                return out
            }
            # Closer found: skip up to and including it, resume scanning after.
            i = i + (j - 1) + length(closer)
            in_raw_string = 0
            raw_hash = 0
            out = out " "
        }
        # Continuation of a multi-line NESTED block comment from a previous line.
        if (block_depth > 0) {
            j = scan_block_comment(s, i)
            if (j == 0) {
                # Entire line is still inside the (nested) block comment.
                return out
            }
            i = j
            out = out " "
        }

        while (i <= n) {
            ch = substr(s, i, 1)
            c2 = substr(s, i, 2)

            # Line comment: drop to end of line.
            if (c2 == "//") {
                break
            }
            # Block comment open (NESTING). Enter at depth 1 and let
            # scan_block_comment resolve any nested opens/closes on this line; if
            # the line ends still inside, block_depth carries to the next line.
            if (c2 == "/*") {
                block_depth++
                j = scan_block_comment(s, i + 2)
                if (j == 0) {
                    out = out " "
                    break
                }
                i = j
                out = out " "
                continue
            }
            # Raw string / raw byte string: an r or br, then zero-or-more hash,
            # then a double quote. The hash count fixes the closer.
            if (ch == "r" || (ch == "b" && substr(s, i + 1, 1) == "r")) {
                k = i + ((ch == "b") ? 2 : 1)
                hashes = 0
                while (substr(s, k, 1) == "#") { hashes++; k++ }
                if (substr(s, k, 1) == "\"") {
                    closer = "\""
                    for (j = 0; j < hashes; j++) closer = closer "#"
                    k = k + 1
                    j = index(substr(s, k), closer)
                    if (j == 0) {
                        in_raw_string = 1
                        raw_hash = hashes
                        out = out " "
                        break
                    }
                    i = k + (j - 1) + length(closer)
                    out = out " "
                    continue
                }
                # Not a raw string: fall through and emit the r/b as code.
            }
            # Ordinary string or byte string. A backslash escapes the next char,
            # so an escaped quote does NOT end the string. If the closing quote is
            # never found before end of line, the string is UNTERMINATED on this
            # physical line — it continues on the next line (Rust allows a normal
            # string to span lines via a trailing `\` continuation OR a bare
            # newline). Carry that via in_string so the leaked closing brace on a
            # later line is not miscounted.
            if (ch == "\"" || (ch == "b" && substr(s, i + 1, 1) == "\"")) {
                k = i + ((ch == "\"") ? 1 : 2)
                in_string = 1
                while (k <= n) {
                    if (substr(s, k, 1) == "\\") { k += 2; continue }
                    if (substr(s, k, 1) == "\"") { k++; in_string = 0; break }
                    k++
                }
                i = k
                out = out " "
                if (in_string) break
                continue
            }
            # Char literal vs lifetime. A quote begins a char literal iff what
            # follows is a single char (or a backslash escape) then a closing
            # quote; otherwise it is a lifetime and is left as code. SQ is the
            # single-quote character (built in BEGIN to keep it out of the awk
            # source, which is wrapped in shell single quotes).
            if (ch == SQ) {
                nxt = substr(s, i + 1, 1)
                if (nxt == "\\") {
                    # Backslash escape: scan to the closing quote. The escape
                    # protects whatever follows, including a quote or a brace.
                    k = i + 2
                    if (substr(s, k, 1) == "u" && substr(s, k + 1, 1) == "{") {
                        # Unicode escape: skip to the closing brace, then quote.
                        j = index(substr(s, k), "}")
                        if (j > 0) k = k + (j - 1) + 1
                    } else {
                        k = k + 1
                    }
                    if (substr(s, k, 1) == SQ) {
                        i = k + 1
                        out = out " "
                        continue
                    }
                    # Malformed: emit the quote as code and advance one.
                } else {
                    # Possible single-char literal: only if a closing quote sits
                    # exactly two chars on. Otherwise it is a lifetime and must
                    # be left as code.
                    nxt2 = substr(s, i + 2, 1)
                    if (nxt != "" && nxt2 == SQ) {
                        i = i + 3
                        out = out " "
                        continue
                    }
                    # Lifetime (or stray quote): fall through, emit as code.
                }
            }

            out = out ch
            i++
        }
        return out
    }
    BEGIN {
        SQ = sprintf("%c", 39)   # single-quote char (kept out of awk source)
        block_depth = 0
        in_raw_string = 0
        raw_hash = 0
        in_string = 0
        seen_test = 0
        depth = 0
        in_fn = 0
        fn_name = ""
        fn_line = 0
        fn_mutates = 0
        fn_failclosed = 0
        fn_besteffort = 0
        scanned = 0
        # chain_buf — the in-flight LOGICAL line: physical continuation lines (a
        # method-chain line beginning with `.`, or a line whose call-parens are
        # still unclosed) are coalesced into it before marker matching, so a
        # marker such as `xctx_caller_reservations.insert(` fires even when the
        # real call is split across `state` / `.xctx_caller_reservations` /
        # `.insert(..)` physical lines. Reset on a statement terminator and at
        # each function-body open. See the "MULTI-LINE MARKER MATCHING" header.
        chain_buf = ""
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

        # Reduce the physical line to its CODE SKELETON: the content of every
        # comment and literal (line/block comment, string, byte string, raw
        # string, raw byte string, char literal) is removed so that a brace,
        # paren, quote, `;`, or marker token INSIDE a literal/comment cannot be
        # miscounted by the brace-depth model, the paren/terminator logic, or the
        # marker match. `strip_code` carries the multi-line `block_depth` /
        # `in_raw_string` (+ `raw_hash`) / `in_string` state across physical
        # lines, so this is evaluated BEFORE the wave-10 empty-line carry and the
        # chain-join. The prior strip was UNSOUND on ordinary Rust: an escaped
        # quote, a raw string, or a char literal containing a brace left a real
        # brace/quote in the residue (wave-11), AND a NESTED block comment closed
        # one `*/` early while a multi-line ordinary/byte string was wrongly
        # treated as closed at EOL (wave-12) — each leaking a brace that closed
        # the function body early and blinding every later Class-S mutation.
        line = strip_code(raw)
        # A line that the scanner left fully inside an unterminated (nested) block
        # comment, raw string, or ordinary/byte string contributes no code: skip
        # it entirely (it can carry no fn definition, brace, or marker).
        # `strip_code` set the multi-line state for the NEXT line; the closer line
        # resumes scanning after the close.
        if (block_depth > 0 || in_raw_string || in_string) next

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
            chain_buf = ""
            pending = 0
            scanned++
        }

        # Within a function body, look for Class-S mutation markers, the
        # fail-closed persist, AND the best-effort persist (round-9 keystone:
        # a governance leaf that best-effort-persists must be allowlisted).
        #
        # MULTI-LINE MARKER MATCHING. Markers are matched against the in-flight
        # LOGICAL line (`chain_buf`), not the bare physical line, so a marker
        # whose contiguous token is split across a method-chain (e.g.
        #     state
        #         .xctx_caller_reservations
        #         .insert(saga_id.clone(), record);
        # — no single physical line contains `xctx_caller_reservations.insert(`)
        # still fires. A physical line is COALESCED onto the running buffer when
        # it is a continuation — its trimmed form begins with `.` (a method-chain
        # link), OR the buffer so far has more `(` than `)` (an argument list
        # spanning lines). Otherwise the buffer restarts at this line. The buffer
        # is reset on a statement terminator (a trailing `;`, `{`, or `}` once
        # call-parens are balanced) so an unrelated later statement cannot be
        # glued onto a stale prefix. This is a pure SUPERSET of the old
        # per-physical-line match: a marker that already matched one physical line
        # still matches (that line is always its own logical line or a prefix of
        # one), so no existing detection is weakened — only previously-dead
        # multi-line markers become live.
        #
        # The buffer is then assignment-normalized (whitespace around a bare `=`
        # collapsed, `x = y` -> `x=y`) so a space-free ASSIGNMENT marker (e.g.
        # `threshold_value=`, `role_state.ceiling=`) matches the downward-auth
        # write while NOT matching a read or a comparison. The relational/equality
        # operators `== != >= <=` are protected first, so an assignment marker can
        # never false-match a comparison (e.g. `threshold_value == n`). Markers
        # without `=` (the original tracker / suspend / remove_member /
        # executed_proposals set) are unaffected — collapsing `=` spacing cannot
        # newly match a marker that has no `=`.
        if (in_fn) {
            # Build the logical line. `trimmed` is the line with leading
            # whitespace removed (used only to detect a leading-`.` continuation).
            trimmed = line
            sub(/^[[:space:]]+/, "", trimmed)

            # EMPTY-LINE CARRY (the round-10 continuation-join fix). After comment
            # and string stripping a physical line can strip to EMPTY — it was a
            # comment-only line (`// ...`, a `/* .. */` whose text was removed) or
            # a genuinely blank line. Such a line carries NO token, NO paren, and
            # NO statement terminator, so it must be a TRANSPARENT no-op for the
            # logical-line buffer: carry `chain_buf` forward UNCHANGED rather than
            # letting the `else` branch reset it. Without this, an interposed
            # comment/blank line BETWEEN two method-chain links discarded the
            # accumulated receiver prefix (`state.xctx_caller_reservations`), so a
            # split-token marker (`xctx_caller_reservations.insert(`,
            # `saga_pending.insert(`, `membership.remove_member(`, ...) written
            # with a comment interposed never fired — and `rustfmt` PRESERVES such
            # an interposed comment, so the evasion survived `cargo fmt`. Carrying
            # the buffer makes any number of interposed comment/blank lines
            # anywhere in a chain transparent, so the split marker still glues.
            #
            # Correctness of the carry: an empty `line` contributes opens==0,
            # closes==0 (computed above), so it does not alter paren-depth or
            # `chain_unclosed`, and it cannot satisfy the `;`/`{`/`}` terminator —
            # there is nothing to re-account. After a COMPLETED statement the
            # buffer is already "" (reset at its terminator on the prior line), so
            # carrying "" forward across a trailing blank line is harmless and
            # cannot leak a stale prefix across a real statement boundary. We skip
            # the continuation/else decision, the marker re-scan (the buffer is
            # unchanged — no new match is possible), and the terminator reset (no
            # terminator on an empty line) for this physical line. `depth` is
            # still updated here via the (zero) opens/closes; the fn-close check
            # is skipped on this line but is inert — a function never closes on a
            # brace-free line (opens==closes==0 leaves `depth` unchanged), so
            # nothing else is affected.
            if (trimmed == "") {
                depth += opens - closes
                next
            }

            # Is the buffer mid-statement with an open call-paren? (more `(` than
            # `)` so far). Counted on the comment-stripped buffer.
            buf_opens = gsub(/\(/, "(", chain_buf)   # gsub returns the count
            buf_closes = gsub(/\)/, ")", chain_buf)  # (chain_buf itself unchanged
            chain_unclosed = (buf_opens > buf_closes) # in value — only counts)
            if (chain_buf != "" && (trimmed ~ /^\./ || chain_unclosed)) {
                # Continuation: append this physical line to the logical line,
                # with its LEADING whitespace stripped (the `trimmed` form) so a
                # marker token contiguous in source (`x.insert(`) is not split by
                # the continuation line indentation. Rust permits no whitespace
                # *inside* a `.method(` token, so a leading-`.` chain link glues
                # directly onto the receiver, and an arg-list continuation glues
                # directly after the open `(` — concatenating the trimmed forms
                # reproduces the single-line spelling for marker purposes.
                chain_buf = chain_buf trimmed
            } else {
                # New logical statement starts here.
                chain_buf = line
            }

            mline = normalize_assign(chain_buf)
            for (mi = 1; mi <= nm; mi++) {
                if (marr[mi] != "" && index(mline, marr[mi]) > 0) { fn_mutates = 1; break }
            }
            if (line ~ /persist_state_fail_closed[[:space:]]*\(/) fn_failclosed = 1
            if (line ~ /persist_state_best_effort[[:space:]]*\(/) fn_besteffort = 1

            # Reset the logical-line buffer at a statement terminator, but only
            # once call-parens are balanced (a `;`/`}` INSIDE an unclosed arg list
            # — e.g. a closure body — does not end the outer statement). Recount
            # on the freshly-extended buffer.
            r_opens = gsub(/\(/, "(", chain_buf)
            r_closes = gsub(/\)/, ")", chain_buf)
            if (r_opens <= r_closes && chain_buf ~ /[;{}][[:space:]]*$/) {
                chain_buf = ""
            }
        } else {
            chain_buf = ""
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
#   (21-24b) LEXICAL-STRIP SOUNDNESS — a Class-S mutation hidden BEHIND a poison
#        literal whose brace would, under the old naive string strip, close the
#        function body early IS still caught: (21) an escaped-quote string
#        containing a brace (`"x\"}"` — the verified evasion), (22) a raw string
#        containing a brace and a quote (`r#"a " } b"#`), (23) char literals
#        holding braces (`'}'`, `'{'`), (24) a brace-inflating string (`"{{{"`),
#        (24b) a byte string containing a brace (`b"}"`).
#   (25) the OVER-STRIP / false-positive guard — a CORRECTLY fail-closed function
#        carrying the same poison literals is NOT flagged (the marker and the
#        fail-closed persist are real code that must survive the strip).
#   (26-31) MULTI-LINE LITERAL/COMMENT STATE — a literal/comment spanning
#        physical lines must not leak a brace into the body model: (26) NESTED
#        block comment deflation (a commented-out `legacy(){}`'s `}` must stay in
#        the comment), (27) nested-comment INFLATION (a leaked `{` must not
#        swallow a separate later fn), (28) `\`-continuation string deflation,
#        (29) BARE-newline string deflation, (30) string INFLATION (a `{` on a
#        continuation line must not blind the later fn), (31) the OVER-STRIP guard
#        (a fail-closed fn carrying a nested comment + multi-line string is NOT
#        flagged).
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

    # (15) `=>` GUARD — a match arm that BINDS the marker identifier as the arm
    # pattern (`threshold_value => ...`) is NOT an assignment and MUST NOT be
    # flagged. Without the `=>` protection in normalize_assign, the fat arrow
    # would collapse to `threshold_value=>`, spuriously matching the
    # `threshold_value=` assignment marker. The fixture only READS via a match
    # arm and persists best-effort; named non-`execute_` so the GOVHIT rule can
    # not mask the result. No such arm exists in the tree today, but the guard
    # keeps the marker precise (fail-closed: it would only ever over-alert).
    {
        printf 'pub fn match_arm_guard_fixture() {\n'
        printf '    let label = match policy {\n'
        printf '        threshold_value => "t",\n'
        printf '        role_state.ceiling => "c",\n'
        printf '    };\n'
        printf '    persist_state_best_effort(state, deps, ctx);\n'
        printf '}\n'
    } > "$fdir/match_arm_guard.rs"

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

    # (16) MULTI-LINE MARKER — a Class-S mutation whose marker token
    # (`xctx_caller_reservations.insert(`) is split across a method-chain (the
    # `prepare_a` shape: a bare receiver line + two `.`-continuation lines, so NO
    # single physical line contains the contiguous token) WITHOUT a following
    # fail-closed persist MUST be caught. This fixture is the regression guard for
    # the continuation-join: before the join, this marker was DEAD (it never
    # matched any physical line); after it, the joined logical line reproduces the
    # single-line spelling and the marker fires. A best-effort persist here models
    # the hazard — a staged caller reversal record that could roll back behind an
    # acked Prepare-A. (Named non-`execute_` so the GOVHIT rule does not mask the
    # HIT — only the multi-line MUTATORS marker may catch it.)
    {
        printf 'pub async fn multiline_insert_missed_fixture() {\n'
        printf '    let record = ticket.to_caller_reservation_record(now);\n'
        printf '    state\n'
        printf '        .xctx_caller_reservations\n'
        printf '        .insert(saga_id.clone(), record);\n'
        printf '    persist_state_best_effort(state, deps, ctx);\n'
        printf '}\n'
    } > "$fdir/multiline_missed.rs"

    # (17) MULTI-LINE MARKER, SATISFIED — the same split-across-lines
    # `xctx_caller_reservations.insert(` chain, but the function DOES persist
    # fail-closed in its own body. The continuation-join must NOT make this a
    # false positive: the marker fires (mutation detected) but the fail-closed
    # persist satisfies it, so it is NOT flagged. This guards against an
    # over-aggressive join that would HIT every multi-line mutator regardless of
    # its (correct) fail-closed persist.
    {
        printf 'pub async fn multiline_insert_fixed_fixture() {\n'
        printf '    let record = ticket.to_caller_reservation_record(now);\n'
        printf '    state\n'
        printf '        .xctx_caller_reservations\n'
        printf '        .insert(saga_id.clone(), record);\n'
        printf '    persist_state_fail_closed(state, deps, ctx)?;\n'
        printf '}\n'
    } > "$fdir/multiline_fixed.rs"

    # (18) INTERPOSED-COMMENT CONTINUATION-JOIN — the round-10 bypass. The same
    # split `xctx_caller_reservations.insert(` chain as (16), but with a
    # comment-only line INTERPOSED BETWEEN two chain links. Before the
    # empty-line-carry fix, the interposed comment stripped to empty and the
    # `else` branch reset the logical-line buffer, discarding the
    # `state.xctx_caller_reservations` receiver prefix — so the split marker never
    # fired and a best-effort (NON-fail-closed) staged caller-reversal slipped the
    # gate. `rustfmt` PRESERVES the interposed comment, so the evasion survived
    # `cargo fmt`. With the carry, the comment is transparent and the marker
    # glues. Best-effort persist models the hazard → MUST be caught.
    {
        printf 'pub async fn multiline_comment_interposed_missed_fixture() {\n'
        printf '    let record = ticket.to_caller_reservation_record(now);\n'
        printf '    state\n'
        printf '        .xctx_caller_reservations\n'
        printf '        // record the reversal handle\n'
        printf '        .insert(saga_id.clone(), record);\n'
        printf '    persist_state_best_effort(state, deps, ctx);\n'
        printf '}\n'
    } > "$fdir/multiline_comment_interposed_missed.rs"

    # (19) INTERPOSED-BLANK-LINE CONTINUATION-JOIN — the same bypass via a
    # genuinely BLANK line between two chain links (the other way a stripped-empty
    # line can interpose). Same hazard, same fix: the blank line must be a
    # transparent no-op so the split marker still glues. Best-effort persist →
    # MUST be caught.
    {
        printf 'pub async fn multiline_blank_interposed_missed_fixture() {\n'
        printf '    let record = ticket.to_caller_reservation_record(now);\n'
        printf '    state\n'
        printf '        .xctx_caller_reservations\n'
        printf '\n'
        printf '        .insert(saga_id.clone(), record);\n'
        printf '    persist_state_best_effort(state, deps, ctx);\n'
        printf '}\n'
    } > "$fdir/multiline_blank_interposed_missed.rs"

    # (20) INTERPOSED-COMMENT CONTINUATION-JOIN, SATISFIED — the same
    # interposed-comment split chain as (18) but the function DOES persist
    # fail-closed. The empty-line carry must NOT make this a false positive: the
    # marker fires (mutation detected across the comment) but the fail-closed
    # persist satisfies it, so it is NOT flagged. Guards against an over-aggressive
    # carry that would HIT a properly-fail-closed multi-line mutator merely because
    # a comment was interposed in its chain.
    {
        printf 'pub async fn multiline_comment_interposed_fixed_fixture() {\n'
        printf '    let record = ticket.to_caller_reservation_record(now);\n'
        printf '    state\n'
        printf '        .xctx_caller_reservations\n'
        printf '        // record the reversal handle\n'
        printf '        .insert(saga_id.clone(), record);\n'
        printf '    persist_state_fail_closed(state, deps, ctx)?;\n'
        printf '}\n'
    } > "$fdir/multiline_comment_interposed_fixed.rs"

    # ----- LEXICAL-STRIP SOUNDNESS (wave-11) ----------------------------------
    # The brace-depth model that closes a function body depends on stripping the
    # CONTENT of every literal/comment BEFORE counting braces. The prior naive
    # string strip was unsound on ordinary Rust: an escaped quote, a raw string,
    # or a char literal containing a brace left a real brace in the residue,
    # closing the function PREMATURELY so every later Class-S mutation went
    # invisible. Each fixture below puts a poison literal BEFORE a best-effort
    # (NON fail-closed) Class-S mutation and asserts the gate STILL HITS — i.e.
    # the brace model survived the literal and the mutation is still detected.
    # SQ is the single-quote byte (\047), kept out of the single-quoted printf.
    local SQ
    SQ=$(printf '\047')

    # (21) ESCAPED-QUOTE STRING containing a brace. `"x\"}"` — the `\"` must NOT
    # end the string, so the `}` inside it must NOT be counted as a real brace.
    # Before the fix the residue `}` closed the fn body early and the mutation
    # below it was invisible (the verified evasion). MUST HIT.
    {
        printf 'pub async fn poison_escaped_quote_fixture() {\n'
        printf '    let s = "x\\"}";\n'
        printf '    state.xctx_caller_reservations.insert(saga_id, record);\n'
        printf '    persist_state_best_effort(state, deps, ctx);\n'
        printf '}\n'
    } > "$fdir/poison_escaped_quote.rs"

    # (22) RAW STRING containing a brace AND a quote. `r#"a " } b"#` — the inner
    # `"` must NOT end the string (only `"#` closes it), so neither the inner
    # quote nor the `}` may be counted. MUST HIT.
    {
        printf 'pub async fn poison_raw_string_fixture() {\n'
        printf '    let s = r#"a " } b"#;\n'
        printf '    state.xctx_caller_reservations.insert(saga_id, record);\n'
        printf '    persist_state_best_effort(state, deps, ctx);\n'
        printf '}\n'
    } > "$fdir/poison_raw_string.rs"

    # (23) CHAR LITERALS holding braces: a close brace then an open brace. Each
    # brace lives inside a char literal and must NOT alter the depth (a net-zero
    # pair that, if counted, would still corrupt the running depth mid-body).
    # MUST HIT. Uses SQ for the single quotes so the printf stays single-quoted.
    {
        printf 'pub async fn poison_char_brace_fixture() {\n'
        printf '    let close = %s}%s;\n' "$SQ" "$SQ"
        printf '    let open = %s{%s;\n' "$SQ" "$SQ"
        printf '    state.xctx_caller_reservations.insert(saga_id, record);\n'
        printf '    persist_state_best_effort(state, deps, ctx);\n'
        printf '}\n'
    } > "$fdir/poison_char_brace.rs"

    # (24) OPEN-BRACE INFLATION via an escaped-quote string carrying opening
    # braces: `"\"{{{"`. The leading `\"` is an escaped quote INSIDE the string,
    # so the whole `"\"{{{"` is one literal and the three `{` must NOT be
    # counted. Under the old naive strip the regex matched only `"\"` (stopping
    # at the backslash-quote) and left `{{{"` in the residue — three phantom
    # opens plus a stray quote — inflating the depth so the body never returned
    # to its floor and the mutation below went invisible. This is the inflation
    # cousin of the (21) evasion and, like it, is defeated only by an
    # escape-aware strip. MUST HIT.
    {
        printf 'pub async fn poison_brace_inflation_fixture() {\n'
        printf '    let s = "\\"{{{";\n'
        printf '    state.xctx_caller_reservations.insert(saga_id, record);\n'
        printf '    persist_state_best_effort(state, deps, ctx);\n'
        printf '}\n'
    } > "$fdir/poison_brace_inflation.rs"

    # (24b) BYTE STRING containing a brace. `b"}"` honors the same escape rules
    # as a plain string; the `}` inside must NOT be counted. MUST HIT.
    {
        printf 'pub async fn poison_byte_string_fixture() {\n'
        printf '    let s = b"}";\n'
        printf '    state.xctx_caller_reservations.insert(saga_id, record);\n'
        printf '    persist_state_best_effort(state, deps, ctx);\n'
        printf '}\n'
    } > "$fdir/poison_byte_string.rs"

    # (25) OVER-STRIP / FALSE-POSITIVE GUARD — a CORRECTLY fail-closed function
    # carrying the SAME poison literals. The stricter strip must NOT over-strip
    # real code: the mutation marker and the fail-closed persist below the
    # literals are real CODE and must survive stripping, so this MUST NOT HIT.
    {
        printf 'pub async fn poison_but_fail_closed_fixture() {\n'
        printf '    let a = "x\\"}";\n'
        printf '    let b = r#"a " } b"#;\n'
        printf '    let c = %s}%s;\n' "$SQ" "$SQ"
        printf '    state.xctx_caller_reservations.insert(saga_id, record);\n'
        printf '    persist_state_fail_closed(state, deps, ctx)?;\n'
        printf '}\n'
    } > "$fdir/poison_fail_closed.rs"

    # ----- MULTI-LINE LITERAL/COMMENT STATE (wave-12) -------------------------
    # The wave-11 strip is correct WITHIN a physical line but carried only
    # block-comment and raw-string state across lines, and modelled a block
    # comment as a BOOLEAN (first `*/` closes) rather than a NESTING counter.
    # Two classes of legal, rustc-accepted, cargo-fmt-clean Rust therefore still
    # leaked a brace into the function-body model:
    #   (A) a NESTED block comment — `/* a /* b */ c */` ends at the SECOND `*/`;
    #       the boolean closed it at the first, leaking ` c */` (+ any braces) as
    #       code;
    #   (B) a multi-line ORDINARY/BYTE string — a normal string may span physical
    #       lines via a trailing `\` continuation OR a bare newline; the prior
    #       scan treated an unterminated-at-EOL string as closed, so a `}` (or
    #       `{`) on the next line leaked.
    # A leaked `}` DEFLATES the body (closes the fn early → every later Class-S
    # mutation in that fn goes invisible); a leaked `{` INFLATES it (the fn never
    # re-balances → it swallows every SUBSEQUENT fn in the file). Each fixture
    # below proves one direction is now seen; the (31) guard proves no over-strip.

    # (26) NESTED-COMMENT DEFLATION — an inner `/* compute */` inside an outer
    # block comment must NOT close the outer comment; the `}` of the commented-out
    # `legacy() {}` must stay inside the comment, not leak and close the body
    # early. The best-effort Class-S mutation after the comment MUST be caught.
    {
        printf 'pub async fn nested_comment_deflation_fixture() {\n'
        printf '    /* old impl:\n'
        printf '       fn legacy() {\n'
        printf '           /* compute */ let b = compute();\n'
        printf '       }\n'
        printf '    */\n'
        printf '    state.xctx_caller_reservations.insert(saga_id, record);\n'
        printf '    persist_state_best_effort(state, deps, ctx);\n'
        printf '}\n'
    } > "$fdir/nested_comment_deflation.rs"

    # (27) NESTED-COMMENT INFLATION — the same nesting hazard, but the early
    # close (at the inner `*/`) exposes an UNBALANCED `{` (`fn leaked() {`) that
    # the real comment never closes. Under the boolean lexer the leaked `{`
    # inflated the FIRST fn's depth so it never returned to its floor and
    # SWALLOWED the SEPARATE later fn — blinding the whole file. A best-effort
    # Class-S mutation in that LATER fn MUST still be caught (proving the file is
    # not blinded). The poison fn itself fail-closes so it is not the HIT.
    {
        printf 'pub async fn nested_comment_inflation_poison_fixture() {\n'
        printf '    /* outer /* inner */ fn leaked() {\n'
        printf '       still inside the real comment, but a boolean lexer sees code\n'
        printf '    */\n'
        printf '    persist_state_fail_closed(state, deps, ctx)?;\n'
        printf '}\n'
        printf '\n'
        printf 'pub async fn nested_comment_inflation_victim_fixture() {\n'
        printf '    state.xctx_caller_reservations.insert(saga_id, record);\n'
        printf '    persist_state_best_effort(state, deps, ctx);\n'
        printf '}\n'
    } > "$fdir/nested_comment_inflation.rs"

    # (28) STRING-CONTINUATION DEFLATION (`\`-continuation) — an ordinary string
    # closed with a trailing `\` line-continuation carries the closing `}` onto
    # the continuation line, still INSIDE the string. The `}` must not leak and
    # close the body early. Best-effort Class-S mutation after it MUST be caught.
    {
        printf 'pub async fn string_backslash_cont_deflation_fixture() {\n'
        printf '    let _e = "payload must end with a closing brace \\\n'
        printf '              } here";\n'
        printf '    state.xctx_caller_reservations.insert(saga_id, record);\n'
        printf '    persist_state_best_effort(state, deps, ctx);\n'
        printf '}\n'
    } > "$fdir/string_backslash_cont_deflation.rs"

    # (29) STRING-CONTINUATION DEFLATION (BARE newline) — Rust allows a literal
    # newline inside a normal string with NO trailing `\`. The string runs across
    # the bare line break; the `}` on the next physical line is still inside the
    # string and must not leak. Best-effort Class-S mutation after it MUST be
    # caught. (Covers the general unterminated-at-EOL case, not only `\`.)
    {
        printf 'pub async fn string_bare_newline_deflation_fixture() {\n'
        printf '    let _e = "line one\n'
        printf '} line two";\n'
        printf '    state.xctx_caller_reservations.insert(saga_id, record);\n'
        printf '    persist_state_best_effort(state, deps, ctx);\n'
        printf '}\n'
    } > "$fdir/string_bare_newline_deflation.rs"

    # (30) STRING INFLATION — a multi-line ordinary string whose continuation
    # line (still inside the string to rustc) carries an UNBALANCED `{`. Under
    # the prior scan the string was treated as closed at the first EOL, so the
    # continuation line's `{` leaked, inflated the FIRST fn's depth, and SWALLOWED
    # the SEPARATE later fn (blinding the file). The best-effort Class-S mutation
    # in the LATER fn MUST still be caught. The poison fn fail-closes.
    {
        printf 'pub async fn string_inflation_poison_fixture() {\n'
        printf '    let _e = "this string is not closed on this line\n'
        printf '        and this continuation carries an opener { that rustc sees as string\n'
        printf '        and the string finally closes here";\n'
        printf '    persist_state_fail_closed(state, deps, ctx)?;\n'
        printf '}\n'
        printf '\n'
        printf 'pub async fn string_inflation_victim_fixture() {\n'
        printf '    state.xctx_caller_reservations.insert(saga_id, record);\n'
        printf '    persist_state_best_effort(state, deps, ctx);\n'
        printf '}\n'
    } > "$fdir/string_inflation.rs"

    # (31) OVER-STRIP / FALSE-POSITIVE GUARD (wave-12) — a CORRECTLY fail-closed
    # function carrying BOTH a nested block comment AND a multi-line string. The
    # nesting-/string-aware strip must not over-strip the real mutation marker and
    # fail-closed persist that follow the literals, so this MUST NOT HIT.
    {
        printf 'pub async fn multiline_literals_but_fail_closed_fixture() {\n'
        printf '    /* outer /* inner */ still in comment {\n'
        printf '    */\n'
        printf '    let _e = "a brace } in a string spanning\n'
        printf '              a bare newline { and closing here";\n'
        printf '    state.xctx_caller_reservations.insert(saga_id, record);\n'
        printf '    persist_state_fail_closed(state, deps, ctx)?;\n'
        printf '}\n'
    } > "$fdir/multiline_literals_fail_closed.rs"

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
    # (16) MULTI-LINE MARKER: a Class-S mutation whose marker token is split
    # across a method-chain (NO single physical line carries the contiguous
    # token) and which does NOT fail-close MUST be caught — the continuation-join
    # reproduces the single-line spelling so a previously-dead multi-line marker
    # fires. Regression guard for the `xctx_caller_reservations.insert(` (and
    # every multi-line marker) coverage.
    if ! grep -q $'^HIT\t.*\tmultiline_insert_missed_fixture$' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a Class-S mutation whose marker is split across a\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'method-chain (no single line carries the contiguous token) was NOT caught\n' >&2
        printf '— the continuation-join is not coalescing logical lines before marker match.\n' >&2
        rc=1
    fi
    # (17) MULTI-LINE MARKER, SATISFIED: the same split-across-lines mutation that
    # DOES persist fail-closed MUST NOT be flagged — the join must not turn a
    # correctly-persisted multi-line mutator into a false positive.
    if grep -q $'^HIT\t.*\tmultiline_insert_fixed_fixture$' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a multi-line Class-S mutation that DOES persist\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'fail-closed was wrongly flagged — the continuation-join is over-aggressive\n' >&2
        printf '(it ignored the fail-closed persist on the joined statement chain).\n' >&2
        rc=1
    fi
    # (18) INTERPOSED-COMMENT CONTINUATION-JOIN (round-10 bypass): a Class-S
    # mutation whose split marker has a COMMENT-ONLY line interposed between two
    # chain links, with a best-effort persist, MUST be caught. The empty-line
    # carry must keep the receiver prefix alive across the comment so the marker
    # still glues. (rustfmt preserves the interposed comment → it survives fmt.)
    if ! grep -q $'^HIT\t.*\tmultiline_comment_interposed_missed_fixture$' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a Class-S mutation with a COMMENT interposed between\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'two method-chain links was NOT caught — the empty-line carry is dropping the\n' >&2
        printf 'logical-line buffer on a stripped-empty comment line (the round-10 bypass).\n' >&2
        rc=1
    fi
    # (19) INTERPOSED-BLANK-LINE CONTINUATION-JOIN: the same bypass via a blank
    # line between two chain links MUST be caught.
    if ! grep -q $'^HIT\t.*\tmultiline_blank_interposed_missed_fixture$' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a Class-S mutation with a BLANK line interposed between\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'two method-chain links was NOT caught — the empty-line carry is dropping the\n' >&2
        printf 'logical-line buffer on a blank line.\n' >&2
        rc=1
    fi
    # (20) INTERPOSED-COMMENT CONTINUATION-JOIN, SATISFIED: the same
    # interposed-comment split chain that DOES persist fail-closed MUST NOT be
    # flagged — the carry must not turn a correctly-persisted multi-line mutator
    # with an interposed comment into a false positive.
    if grep -q $'^HIT\t.*\tmultiline_comment_interposed_fixed_fixture$' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a multi-line Class-S mutation with an interposed comment\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'that DOES persist fail-closed was wrongly flagged — the empty-line carry is\n' >&2
        printf 'over-aggressive (it ignored the fail-closed persist on the joined chain).\n' >&2
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
    # (15) `=>` guard: a match arm binding a marker identifier (`threshold_value
    # => ..`, `role_state.ceiling => ..`) is NOT an assignment and MUST NOT be
    # flagged. A regression that drops the `=>` protection in normalize_assign
    # would collapse the fat arrow to `threshold_value=>` and spuriously HIT.
    if grep -q $'^HIT\t.*\tmatch_arm_guard_fixture$' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a match arm binding a marker identifier was wrongly\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'flagged — the `=>` guard in normalize_assign is missing (a fat-arrow arm\n' >&2
        printf 'collapsed to a bare `=` and false-matched an assignment marker).\n' >&2
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

    # (21) LEXICAL STRIP — escaped-quote string containing a brace. The brace
    # inside `"x\"}"` must not be counted (the `\"` does not end the string), so
    # the fn body does not close early and the Class-S mutation below it is still
    # detected. MUST HIT. This is the verified evasion the wave-11 fix closes.
    if ! grep -q $'^HIT\t.*\tpoison_escaped_quote_fixture$' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a Class-S mutation hidden behind an ESCAPED-QUOTE\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'string containing a brace was NOT caught — the strip is not escape-aware\n' >&2
        printf 'and the brace model closed the function body prematurely.\n' >&2
        rc=1
    fi
    # (22) LEXICAL STRIP — raw string containing a brace and a quote. Only `"#`
    # closes `r#"a " } b"#`; the inner quote and brace must not be counted.
    # MUST HIT.
    if ! grep -q $'^HIT\t.*\tpoison_raw_string_fixture$' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a Class-S mutation hidden behind a RAW STRING\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'containing a brace/quote was NOT caught — the strip does not honor the\n' >&2
        printf 'raw-string hash-delimited closer.\n' >&2
        rc=1
    fi
    # (23) LEXICAL STRIP — char literals holding braces (`}` then `{`). A brace
    # inside a char literal must not alter brace depth. MUST HIT.
    if ! grep -q $'^HIT\t.*\tpoison_char_brace_fixture$' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a Class-S mutation hidden behind CHAR LITERALS\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'holding braces was NOT caught — the strip does not recognize char literals\n' >&2
        printf '(and a brace in a char literal corrupted the brace-depth model).\n' >&2
        rc=1
    fi
    # (24) LEXICAL STRIP — open-brace inflation via a `"{{{"` string. Braces in a
    # string must not inflate depth (which would swallow a later real `}` and
    # hide the mutation). MUST HIT.
    if ! grep -q $'^HIT\t.*\tpoison_brace_inflation_fixture$' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a Class-S mutation hidden behind a brace-INFLATING\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'escaped-quote string was NOT caught — the strip counted in-string opening\n' >&2
        printf 'braces left in the residue and the body never returned to its floor.\n' >&2
        rc=1
    fi
    # (24b) LEXICAL STRIP — byte string `b"}"` containing a brace. MUST HIT.
    if ! grep -q $'^HIT\t.*\tpoison_byte_string_fixture$' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a Class-S mutation hidden behind a BYTE STRING\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'containing a brace was NOT caught — the strip does not treat a byte\n' >&2
        printf 'string as a string literal.\n' >&2
        rc=1
    fi
    # (25) OVER-STRIP / FALSE-POSITIVE GUARD — a CORRECTLY fail-closed function
    # carrying the same poison literals MUST NOT be flagged. The mutation marker
    # and the fail-closed persist are real CODE below the literals and must
    # survive the strip; if the stricter scanner over-stripped real code (or
    # failed to see the fail-closed persist), this would wrongly HIT.
    if grep -q $'^HIT\t.*\tpoison_but_fail_closed_fixture$' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a CORRECTLY fail-closed function carrying poison\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'literals was wrongly flagged — the strip over-stripped real code or lost\n' >&2
        printf 'the fail-closed persist that follows the literals.\n' >&2
        rc=1
    fi

    # (26) NESTED-COMMENT DEFLATION — the `}` of a commented-out `legacy() {}`
    # inside a nested block comment must not leak and close the body early. The
    # best-effort Class-S mutation after the comment MUST be caught.
    if ! grep -q $'^HIT\t.*\tnested_comment_deflation_fixture$' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a Class-S mutation after a NESTED block comment was\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'NOT caught — the block-comment lexer is boolean (closes at the first `*/`)\n' >&2
        printf 'and a brace inside the comment leaked, closing the body prematurely.\n' >&2
        rc=1
    fi
    # (27) NESTED-COMMENT INFLATION — a leaked `{` from an early-closed nested
    # comment must NOT inflate the poison fn so it swallows the SEPARATE later fn.
    # The best-effort mutation in the LATER (victim) fn MUST still be caught.
    if ! grep -q $'^HIT\t.*\tnested_comment_inflation_victim_fixture$' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a leaked `{` from a NESTED block comment blinded the\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'rest of the file — the later (victim) fn was swallowed by an inflated body\n' >&2
        printf 'and its Class-S mutation went unscanned.\n' >&2
        rc=1
    fi
    # (28) STRING-CONTINUATION DEFLATION (`\`-continuation) — a `}` carried onto a
    # `\`-continuation line is still inside the string and must not leak. The
    # best-effort Class-S mutation after the string MUST be caught.
    if ! grep -q $'^HIT\t.*\tstring_backslash_cont_deflation_fixture$' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a Class-S mutation after a `\\`-CONTINUATION string\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'was NOT caught — the lexer treated the unterminated string as closed at EOL\n' >&2
        printf 'and a `}` on the continuation line leaked, closing the body prematurely.\n' >&2
        rc=1
    fi
    # (29) STRING-CONTINUATION DEFLATION (BARE newline) — a `}` on a bare-newline
    # continuation of a normal string is still inside the string and must not
    # leak. The best-effort Class-S mutation after it MUST be caught.
    if ! grep -q $'^HIT\t.*\tstring_bare_newline_deflation_fixture$' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a Class-S mutation after a BARE-NEWLINE multi-line\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'string was NOT caught — the lexer did not carry the unterminated-at-EOL\n' >&2
        printf 'string across the line break and a `}` inside it leaked.\n' >&2
        rc=1
    fi
    # (30) STRING INFLATION — a `{` on a string-continuation line must NOT inflate
    # the poison fn so it swallows the SEPARATE later fn. The best-effort mutation
    # in the LATER (victim) fn MUST still be caught.
    if ! grep -q $'^HIT\t.*\tstring_inflation_victim_fixture$' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a leaked `{` from a multi-line string blinded the rest\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'of the file — the later (victim) fn was swallowed by an inflated body and\n' >&2
        printf 'its Class-S mutation went unscanned.\n' >&2
        rc=1
    fi
    # (31) OVER-STRIP / FALSE-POSITIVE GUARD (wave-12) — a CORRECTLY fail-closed
    # function carrying both a nested block comment and a multi-line string MUST
    # NOT be flagged. The nesting-/string-aware strip must not over-strip the real
    # mutation marker and fail-closed persist that follow the literals.
    if grep -q $'^HIT\t.*\tmultiline_literals_but_fail_closed_fixture$' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a CORRECTLY fail-closed function carrying a nested\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'comment and a multi-line string was wrongly flagged — the strip over-stripped\n' >&2
        printf 'real code or lost the fail-closed persist that follows the literals.\n' >&2
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
