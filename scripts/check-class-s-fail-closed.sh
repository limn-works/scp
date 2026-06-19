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
#
# RECEIVER-ALIAS RESISTANCE (wave-23). A receiver-prefixed marker like
# `role_state.ceiling=` or `membership.remove_member(` is DEFEATED by idiomatic
# mutable-alias rebinding: `let rs = &mut state.role_state; rs.ceiling = ...` or
# `let m = &mut state.membership; m.remove_member(...)` carry NO
# `role_state.`/`membership.` prefix on the mutation line, so the receiver-pinned
# marker misses while the non-`execute_` Class-S handlers (prepare_a / prepare_b /
# apply_pending_ceiling_modification) have NO GOVHIT backstop. Closed two ways:
#   - The CEILING assignment marker is now ALSO present receiver-AGNOSTICALLY as
#     `.ceiling=` (every `.ceiling =` in the scan dir is a `role_state.ceiling`
#     write; reads normalize to `.ceiling(`/`.ceiling\x01` so cannot match). The
#     original `role_state.ceiling=` is retained (a redundant subset) so coverage
#     is only ever ADDED.
#   - The UNIQUELY-named state-field MUTATION markers (membership.remove_member,
#     executed_proposals.insert, threshold_signers.retain, saga_pending.insert/
#     remove, xctx_nonce_dedup.record, xctx_caller_reservations.insert) each gain
#     a `&mut.<field>` companion that matches the MUTABLE-ALIAS BORROW at its
#     borrow site. `normalize_borrow` collapses `&mut <recv>.<field>` (any
#     receiver path) to the canonical `&mut.<field>` token before the marker
#     scan, so the borrow that creates the alias is caught regardless of the
#     later mutation methods name. This is mutation-specific: a READ alias borrows
#     `&<recv>.<field>` (SHARED, no `&mut`) and so never collapses — read-only
#     accessors (`.get`/`.clone`/`.contains_key`/snapshot rehydration) are NOT
#     false-flagged. The `&mut.<field>` form also dodges the method-name collision
#     that a receiver-agnostic `.remove_member(` would have with the unrelated MLS
#     `crypto.remove_member(` (a different method on a different receiver).
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
role_state.ceiling= \
.ceiling= \
&mut.membership \
&mut.executed_proposals \
&mut.threshold_signers \
&mut.saga_pending \
&mut.xctx_nonce_dedup \
&mut.xctx_caller_reservations"

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
    # is_column0_code_line — TRUE iff the STRIPPED line is column-0 PRODUCTION
    # CONTENT: a non-blank, non-comment, non-attribute line that begins at column
    # 0 (no leading whitespace). This is the CLASSIFIER-FREE successor to the old
    # `is_column0_item_start` item-kind enumerator. It does NOT try to recognise
    # *what* item the line opens — only that a column-0 code line is present at
    # all. It is used both by the trailing-test-module DETECTOR (to find the first
    # real column-0 code line after a test gate, to decide mod-vs-item) and by the
    # NTTEST un-scanned-vacuum GUARD (to detect ANY production resume after the
    # closing brace of the trailing test module).
    #
    # WAVE-18 REFRAME. The prior `is_column0_item_start` enumerated every column-0
    # Rust item keyword + every fn/impl qualifier permutation + the single-ident
    # item-macro spelling. That enumeration leaked a NEW spelling every wave
    # (`unsafe fn`/`const fn`; `unsafe impl`/`unsafe trait`; `pub(crate) mod`; and
    # finally the path-qualified item macro `foo::bar! {}` — the MAJORITY macro
    # spelling, unrecognised because `::` falls outside the macro-ident char
    # class). That is the non-convergent "one-more-spelling" anti-pattern. The
    # NTTEST guard no longer needs to know the KIND of an item: with brace-depth
    # tracking of the test module (see the per-line block below), ANY column-0
    # production content after the closing brace of the module is a vacuum,
    # whatever its spelling. So it collapses to the three things that are NOT
    # production content — blank, comment-only, and attribute lines — and treats
    # everything else as a column-0 code line. No item/macro spelling can evade
    # it, because it matches no spelling: it matches the ABSENCE of the three
    # non-content shapes.
    #
    # `s` is assumed already STRIPPED (comment/string content removed) by the
    # caller, so a comment-only line is already empty here, and a token inside a
    # literal/comment cannot make a non-code line look like code.
    function is_column0_code_line(s) {
        # Blank or comment-only (stripped to empty / whitespace-only): not code.
        if (s ~ /^[[:space:]]*$/)
            return 0
        # Indented (leading whitespace): not a column-0 line — it is inside some
        # still-open block, never a top-level production resume.
        if (s ~ /^[[:space:]]/)
            return 0
        # A column-0 attribute line (`#[..]` / `#![..]`): not yet production
        # content — the DETECTOR / GUARD look PAST it to the item it decorates (a
        # `#[cfg(test)]` re-opening gate is handled explicitly by the caller).
        if (s ~ /^#!?\[/)
            return 0
        # Anything else at column 0 is production content (an item of ANY
        # spelling — fn / impl / trait / struct / a single-ident OR path-qualified
        # item macro / a re-opened `mod` — or any other top-level token).
        return 1
    }
    # is_column0_reopening_test_gate — TRUE iff the STRIPPED line is a column-0
    # `#[cfg(test)]` / `#[cfg(all(test..))]` / `#[cfg(any(test..))]` attribute,
    # i.e. a gate that may LEGITIMATELY re-open a SECOND test module after the
    # first. Used by the NTTEST guard to NOT fire on a second test gate (which is
    # not a production-region resume).
    function is_column0_reopening_test_gate(s) {
        return (s ~ /^#\[cfg\(test\)\]/ \
            || s ~ /^#\[cfg\(all\(test[,)]/ \
            || s ~ /^#\[cfg\(any\(test[,)]/)
    }
    # is_column0_mod_decl — TRUE iff the STRIPPED line is a column-0 `mod NAME`
    # declaration with optional visibility (`pub` / `pub(crate)` / `pub(in path)`).
    # The trailing-test-module DETECTOR uses it to recognise the `mod` that a
    # `#[cfg(test)]` gate decorates (vs an interspersed single item), keeping the
    # FULL visibility grammar so a `pub(crate) mod tests` / `pub(in path) mod`
    # (trailing OR a legitimate second test module) is recognised as a module and
    # not mistaken for a production resume — which would false-fire NTTEST on
    # perfectly legal Rust (a CI break).
    function is_column0_mod_decl(s,   vis) {
        vis = "(pub[[:space:]]*(\\([^)]*\\))?[[:space:]]+)?"
        return (s ~ ("^" vis "mod[[:space:]]"))
    }
    # is_test_cfg_attr_head — TRUE iff the STRIPPED line OPENS a column-0
    # test-cfg gate attribute, whether or not it is balanced on this one line.
    # `is_column0_reopening_test_gate` requires the WHOLE `#[cfg(..)]` on one
    # physical line; this companion recognises the OPENING of the same three
    # test-cfg shapes so the multi-line-attribute carry can remember that the
    # attribute it is consuming is a test gate and arm `pending_test_gate` when it
    # COMPLETES (a `#[cfg(all(test,\n feature="x"\n))]` split across lines). It is
    # deliberately scoped to the SAME `test` / `all(test` / `any(test` heads — it
    # does NOT broaden the carry to arbitrary multi-line attributes.
    function is_test_cfg_attr_head(s) {
        return (s ~ /^#\[cfg\(test[,)]/ \
            || s ~ /^#\[cfg\(test\)/ \
            || s ~ /^#\[cfg\(all\(test[,)]/ \
            || s ~ /^#\[cfg\(any\(test[,)]/)
    }
    # strip_leading_attr — return the remainder of a STRIPPED line AFTER a single
    # balanced leading column-0 `#[..]` / `#![..]` attribute (with its leading
    # whitespace trimmed), or "" if the line does not begin with a balanced
    # attribute. Used to recognise a SAME-LINE `#[cfg(test)] mod NAME {` (gate and
    # mod on ONE physical line): the leading attribute is consumed and the
    # remainder re-examined as a column-0 `mod` decl. Single-pass bracket scan
    # over `[`/`]`/`(`/`)` from the leading `#[`; returns the tail past the `]`
    # that closes the attribute to depth 0. Only fires for a balanced
    # single-physical-line attribute (a multi-line head returns "").
    # NOTE: this scanner does NOT need to be string-aware: every caller receives a
    # line that `strip_code` has already run over (`line = strip_code(raw)` precedes
    # fn-detection), so all string-literal content — including any `[`/`]` inside a
    # doc string — is removed before this function ever sees it. A `[`/`]` reaching
    # here is therefore always a real attribute bracket.
    function strip_leading_attr(s,   t, i, ch, d, started) {
        t = s
        sub(/^[[:space:]]+/, "", t)
        if (t !~ /^#!?\[/) return ""
        d = 0
        started = 0
        for (i = 1; i <= length(t); i++) {
            ch = substr(t, i, 1)
            if (ch == "[") { d++; started = 1 }
            else if (ch == "]") {
                d--
                if (started && d <= 0) {
                    t = substr(t, i + 1)
                    sub(/^[[:space:]]+/, "", t)
                    return t
                }
            }
        }
        return ""
    }
    # peel_leading_attrs — return `s` with leading whitespace trimmed and EVERY
    # balanced single-line leading `#[..]` attribute peeled off, so a same-physical-
    # line `#[rustfmt::skip] pub fn evil() { .. }` (or stacked `#[a] #[b] fn ..`)
    # exposes its underlying item for the fn-detector to recognise. `#[rustfmt::skip]`
    # PRESERVES hand-formatting, so attribute+item on one line is fmt-clean and
    # reachable — a bare `^[[:space:]]*(pub..)?fn` anchor rejects the leading `#[`
    # and would silently skip the function (and any Class-S mutation in its body,
    # AND its `execute_*` governance-leaf classification). Reuses `strip_leading_attr`
    # (the SAME primitive the NTTEST attr-peel uses — convergent, no new spelling
    # enumeration). An UNBALANCED leading attribute (a multi-line `#[..]` head)
    # stops the peel and returns the line as-is: the item is then on a LATER physical
    # line and is recognised there normally, so this must not misread the head line.
    function peel_leading_attrs(s,   t, peeled) {
        t = s
        sub(/^[[:space:]]+/, "", t)
        while (t ~ /^#!?\[/) {
            peeled = strip_leading_attr(t)
            if (peeled == "") return t
            t = peeled
        }
        return t
    }
    # is_production_remainder — TRUE iff the post-structural-close remainder of a
    # physical line (already code-stripped) carries column-0 PRODUCTION content:
    # after trimming leading whitespace it is non-empty and is neither an
    # attribute line (`#[..]`) nor a re-opening test gate. Used by the
    # close-line / multi-line-attr-closer resume re-evaluation (GAP-1): when a
    # test-module closing `}` — or a `)]` closing a multi-line attribute that
    # itself preceded a structural close — SHARES a physical line with production
    # code, that trailing production is a vacuum the bare `next` would silently
    # drop. The trim mirrors `is_column0_code_line` but is applied to a remainder
    # that does not itself begin at column 0 (it follows the closing brace).
    function is_production_remainder(s,   t) {
        t = s
        sub(/^[[:space:]]+/, "", t)
        if (t == "") return 0
        if (t ~ /^#!?\[/) return 0
        if (is_column0_reopening_test_gate(t)) return 0
        return 1
    }
    # is_attr_prefixed_production — TRUE iff a STRIPPED remainder is PRODUCTION
    # content possibly PREFIXED by one or more balanced leading `#[..]` attributes
    # on the SAME physical line — the wave-20 shape `#[rustfmt::skip] pub fn evil()
    # { ..class-s mutation.. }` (whole attribute + item on ONE line). `#[rustfmt::
    # skip]` is the directive to PRESERVE hand-formatting, so rustfmt leaves that
    # one-line shape byte-for-byte unchanged (and it compiles), so it is NOT fmt-
    # prevented: a bare `is_production_remainder` / `is_column0_code_line` sees the
    # leading `^#[` and returns 0 (they look PAST an attribute expecting the item on
    # a FOLLOWING line), silently swallowing the resume. We therefore PEEL each
    # balanced leading attribute via `strip_leading_attr` (the SAME primitive GAP-2
    # already trusts — convergent, no new spelling enumeration) and test the final
    # remainder. A re-opening `#[cfg(test)]` gate encountered while peeling is a
    # legitimate second test module, NOT production: return 0 so it does not
    # false-fire (the GAP-2 same-line gate+mod detector consumes a same-line
    # `#[cfg(test)] mod` before this is ever reached; this guard is belt-and-braces).
    # If the remainder after peeling all leading attributes is non-empty and is
    # itself neither a (further) attribute, blank, comment, nor a re-opening test
    # gate, it is production content. A `#[rustfmt::skip]` / `#[inline]` / any
    # balanced attribute(s) followed by a whole item ON THE SAME LINE is thereby
    # seen as production, not skipped.
    function is_attr_prefixed_production(s,   t, peeled) {
        t = s
        sub(/^[[:space:]]+/, "", t)
        if (t == "") return 0
        # Peel balanced leading attributes one at a time. A re-opening test gate
        # among them means a legitimate (second) test module is being entered, not
        # a production resume.
        while (t ~ /^#!?\[/) {
            if (is_column0_reopening_test_gate(t)) return 0
            peeled = strip_leading_attr(t)
            # strip_leading_attr returns "" if the leading attribute is NOT balanced
            # on this physical line (a multi-line attribute head). A multi-line head
            # is handled by the attr-carry, not here, so it is not a same-line
            # production resume: not flagged.
            if (peeled == "") return 0
            t = peeled
        }
        # After peeling every leading attribute, what remains decides it. The bare
        # production test (non-empty, not a re-opening gate) — note a residual
        # leading `#[` cannot occur here (the while-loop consumed all balanced
        # leading attributes, and an unbalanced head returned 0 above).
        if (t == "") return 0
        if (is_column0_reopening_test_gate(t)) return 0
        return 1
    }
    # brace_close_pos — given a STRIPPED line and the test-module CODE brace depth
    # BEFORE this line (`pre`), return the 1-based index of the `}` that brings the
    # running depth to 0 (the brace that CLOSES the trailing test module), or 0 if
    # the module does not close anywhere on this line. A single left-to-right brace
    # scan over the already-code-stripped line, so a `{`/`}` inside a
    # literal/comment (removed by `strip_code`) cannot mis-count. This finds the
    # close POSITIONALLY rather than by NET brace count, so a brace-BALANCED line
    # that both closes the module AND re-opens a brace for trailing production
    # (`} fn resumed() { .. }`) is still recognised as closing the module (net
    # count would stay > 0 and miss it — the GAP-1 close-line vacuum).
    function brace_close_pos(s, pre,   i, ch, d) {
        d = pre
        for (i = 1; i <= length(s); i++) {
            ch = substr(s, i, 1)
            if (ch == "{") d++
            else if (ch == "}") {
                d--
                if (d <= 0) return i
            }
        }
        return 0
    }
    # remainder_after_attr_close — given a STRIPPED line and the in-flight
    # multi-line ATTRIBUTE bracket depth BEFORE this line (`pre`, the net unclosed
    # `[`+`(`), return the substring AFTER the bracket (`]`/`)`) that brings the
    # combined depth to 0 — i.e. the production item that a multi-line attribute
    # closing `)]` decorates when it shares the physical line
    # (`)] fn sneaky_production() { .. }`). Empty if the attribute does not close
    # on this line, or nothing follows the closer. Mirrors the `attr_brk` /
    # `attr_brk_close` accounting (`[`/`(` open, `]`/`)` close) so the split point
    # matches the depth model exactly.
    function remainder_after_attr_close(s, pre,   i, ch, d) {
        d = pre
        for (i = 1; i <= length(s); i++) {
            ch = substr(s, i, 1)
            if (ch == "[" || ch == "(") d++
            else if (ch == "]" || ch == ")") {
                d--
                if (d <= 0) return substr(s, i + 1)
            }
        }
        return ""
    }
    # enter_test_module — ENTER a trailing test module on the line carrying its
    # `mod NAME {`, given that line CODE brace counts (`opens`/`closes`). Sets
    # `after_test_module=0`, `in_test_module=1`, and the module CODE brace depth.
    # A degenerate single-physical-line `mod x {}` (already balanced, depth <= 0)
    # is treated as immediately closed (its body had nothing to skip) and the
    # remainder of THIS physical line after the module-closing `}` is re-evaluated
    # for a same-line production resume (GAP-1), so a non-trailing
    # `#[cfg(test)] mod x {} fn resumed() {..}` is still surfaced. Shared by the
    # same-line gate+mod path (GAP-2) and the pending-gate path so both behave
    # identically. `line` (the stripped physical line) is read as a global.
    function enter_test_module(opens, closes,   close_pos, remainder) {
        after_test_module = 0
        in_test_module = 1
        # WAVE-20 (HOLE-1) — detect the degenerate same-line close POSITIONALLY,
        # not by NET brace count. The module opens at depth 0 before this line; find
        # the `}` that brings the running CODE depth back to 0. A NET count
        # (`opens - closes <= 0`) MISSES `#[cfg(test)] mod x {} pub fn resumed() {
        # ..class-s mutation.. }`: that line nets `opens-closes = 1` (the trailing
        # production fn re-opens a brace), so the `<= 0` branch was skipped and the
        # scanner stayed in_test_module at depth 1, ABSORBING the production fn body
        # (hiding its mutation). This is the SAME net-count flaw the in_test_module
        # close branch already fixed via `brace_close_pos`; `enter_test_module` was
        # left on net counting. Find the close positionally and re-eval the
        # remainder, mirroring the GAP-1 close-line path.
        close_pos = brace_close_pos(line, 0)
        if (close_pos > 0) {
            # The module opened AND closed on this one physical line.
            in_test_module = 0
            test_mod_depth = 0
            after_test_module = 1
            remainder = substr(line, close_pos + 1)
            # Re-evaluate the post-close remainder for a same-line production
            # vacuum, mirroring the in_test_module close branch. A leading balanced
            # attribute on the resume (`} #[rustfmt::skip] fn evil() {..}` shape on
            # the remainder) is peeled by is_attr_prefixed_production (HOLE-2).
            if (!nontrailing_hit && is_attr_prefixed_production(remainder)) {
                printf("NTTEST\t%s\t%d\t%s\n", FILE, test_gate_line, "non_trailing_test_module")
                nontrailing_hit = 1
            }
        } else {
            # A genuinely-trailing module (`mod t {` with body on later lines):
            # carry the CODE brace depth forward; the in_test_module close branch
            # finds the close on a later line.
            test_mod_depth = opens - closes
        }
    }
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
    # normalize_borrow — collapse a MUTABLE-ALIAS BORROW of a uniquely-named
    # Class-S state field, `&mut <recv-path>.<field>`, to the canonical
    # receiver-agnostic token `&mut.<field>`, so the field-mutation markers catch
    # the alias at its BORROW site regardless of how the alias is later spelled
    # (`let m = &mut state.membership; m.remove_member(...)`). Only the EXCLUSIVE
    # borrow form is collapsed: a SHARED read alias is `&<recv>.<field>` (no
    # `mut`), so reads / read accessors (`.get` / `.clone` / `.contains_key` /
    # snapshot rehydration) never match. The receiver path
    # (`[A-Za-z_][A-Za-z0-9_.]*`) is consumed greedily up to the FINAL `.<field>`
    # segment, so `&mut self.state.membership` collapses the same as
    # `&mut state.membership`. The replacement spec `\&...` emits a literal `&`
    # (an unescaped `&` in gsub means the matched text). Applied to the
    # assignment-normalized COPY only, so consuming a trailing boundary byte here
    # cannot perturb the statement-termination recount (it runs on chain_buf).
    function normalize_borrow(s,   t) {
        t = s
        gsub(/&mut[[:space:]]+[A-Za-z_][A-Za-z0-9_.]*\.membership/, "\\&mut.membership", t)
        gsub(/&mut[[:space:]]+[A-Za-z_][A-Za-z0-9_.]*\.executed_proposals/, "\\&mut.executed_proposals", t)
        gsub(/&mut[[:space:]]+[A-Za-z_][A-Za-z0-9_.]*\.threshold_signers/, "\\&mut.threshold_signers", t)
        gsub(/&mut[[:space:]]+[A-Za-z_][A-Za-z0-9_.]*\.saga_pending/, "\\&mut.saga_pending", t)
        gsub(/&mut[[:space:]]+[A-Za-z_][A-Za-z0-9_.]*\.xctx_nonce_dedup/, "\\&mut.xctx_nonce_dedup", t)
        gsub(/&mut[[:space:]]+[A-Za-z_][A-Za-z0-9_.]*\.xctx_caller_reservations/, "\\&mut.xctx_caller_reservations", t)
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
                # Count every remaining nested open `/*` so block_depth carries
                # the CORRECT depth to the next line (Rust block comments nest).
                # This branch is reached only when there is genuinely NO `*/` on
                # the remainder, so each remaining `/*` is an unambiguous
                # deepening. A boolean "carry regardless" UNDER-counted depth: a
                # nested `/*` that is the last comment-token on its physical line
                # was dropped, surfacing from the comment one level too early and
                # leaking the trailing comment braces into the code residue.
                while (o2 != 0) {
                    block_depth++
                    m = m + (o2 - 1) + 2
                    o2 = index(substr(s, m), "/*")
                }
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
        # FNQUAL — the FULL fn-qualifier-run PREFIX an item-defining fn signature
        # may carry: optional `pub` / `pub(..)` visibility, then any run of
        # `const` / `unsafe` / `async` / `extern "ABI"` qualifiers, then `fn` and
        # its trailing space. Hoisted to a single BEGIN-assigned string (the same
        # idiom is_column0_mod_decl uses for `vis`) so the fn-DETECT match and the
        # fn-NAME-strip below cannot silently desync — a prior copy-paste kept this
        # run written verbatim TWICE, where editing one copy and not the other
        # would break match-vs-extract agreement. The string form needs DOUBLED
        # backslashes (`\\(`) and escaped quotes (`\"`) so the awk regex compiles
        # to the byte-identical pattern the two inline literals used.
        FNQUAL = "^(pub[[:space:]]*(\\([^)]*\\))?[[:space:]]+)?((const|unsafe|async)[[:space:]]+|extern([[:space:]]+\"[^\"]*\")?[[:space:]]+)*fn[[:space:]]+"
        block_depth = 0
        in_raw_string = 0
        raw_hash = 0
        in_string = 0
        # Trailing-test-module brace-depth state (wave-18 reframe). The cutoff no
        # longer flips a single "skip rest of file" `seen_test` flag and then
        # classify every later column-0 line by item KIND; instead it TRACKS the
        # CODE brace depth of the trailing test module and treats ANY column-0
        # production content AFTER its closing brace as a non-trailing vacuum
        # (NTTEST).
        #   in_test_module     — currently inside a trailing test module body.
        #   test_mod_depth      — CODE brace depth WITHIN that module (the module
        #                         opens at depth 1 on its `mod .. {` line and CLOSES
        #                         when this returns to 0).
        #   after_test_module   — a trailing test module has CLOSED and we are
        #                         scanning for the first column-0 production resume.
        #   test_gate_line      — the gate line reported if a vacuum is found.
        #   nontrailing_hit     — NTTEST already fired for this file (fire once).
        #   pending_test_gate / pending_test_line — a column-0 `#[cfg(test)]` gate
        #                         is armed; the next column-0 code line decides
        #                         mod-vs-(interspersed item). The SAME pending-gate
        #                         path recognises a legitimate SECOND test module
        #                         after a prior one closed (a re-opening gate arms
        #                         it; the following `mod` is consumed as a module),
        #                         so no separate "second gate" state is needed.
        in_test_module = 0
        test_mod_depth = 0
        after_test_module = 0
        test_gate_line = 0
        nontrailing_hit = 0
        pending_test_gate = 0
        pending_test_line = 0
        # attr_bracket_depth — net unclosed `[` + `(` of an in-flight column-0
        # MULTI-LINE attribute (`#[derive(\n  ...\n)]`, `#[allow(\n  ...\n)]`).
        # A column-0 attribute whose brackets are unbalanced on its opening line
        # CONTINUES onto following physical lines (e.g. a bare `)]` closer at
        # column 0). Those continuation lines are NOT production content and MUST
        # NOT be mistaken by the mod-vs-item DETECTOR / NTTEST GUARD for a column-0
        # code line (else a `)]` closing a multi-line `#[allow(..)]` before a
        # `mod tests {` would wrongly decide "interspersed item" and skip the
        # module). Tracked here (with the same stripped-line bracket counts) so the
        # whole attribute, however many lines it spans, is transparent — the
        # classifier-free analogue of how `strip_code` carries multi-line literals.
        attr_bracket_depth = 0
        # attr_is_test_cfg — set when the in-flight multi-line attribute OPENED
        # with a test-cfg head (`#[cfg(all(test,` / `#[cfg(any(test,`). When the
        # attribute COMPLETES across lines, this arms `pending_test_gate` so a
        # MULTI-LINE test-cfg gate is recognised exactly like a single-line one
        # (GAP-3): without it, the multi-line gate is consumed as an opaque
        # attribute and the `mod` it decorates is scanned as production.
        attr_is_test_cfg = 0
        # attr_test_cfg_line — the physical line on which a multi-line test-cfg
        # gate OPENED, reported as the gate line when the gate completes (GAP-3).
        attr_test_cfg_line = 0
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
        #
        # MOVED ABOVE the test-MODULE cutoff (wave-14): the cutoff now matches the
        # STRIPPED `line`, not the raw physical line, so a `#[cfg(test)]` token
        # sitting INSIDE a string / comment cannot wrongly trigger the "skip rest
        # of file" cutoff and blind every later production mutation.
        line = strip_code(raw)
        # A line that the scanner left fully inside an unterminated (nested) block
        # comment, raw string, or ordinary/byte string contributes no code: skip
        # it entirely (it can carry no fn definition, brace, or marker).
        # `strip_code` set the multi-line state for the NEXT line; the closer line
        # resumes scanning after the close.
        if (block_depth > 0 || in_raw_string || in_string) next

        # Trailing test-MODULE handling — WAVE-18 BRACE-DEPTH REFRAME.
        #
        # Once a top-level (column-0) test-gated MODULE opens, its body is test
        # code and is NOT scanned for Class-S markers (test mutations exercise the
        # primitives directly and must not be flagged). The module is gated by a
        # column-0 attribute in one of these forms, IMMEDIATELY decorating a `mod`:
        #     #[cfg(test)]
        #     #[cfg(all(test, feature = "testing"))]   (e.g. lifecycle_helpers)
        #     #[cfg(any(test, feature = "testing"))]   (e.g. context/mod.rs)
        #
        # WHAT REPLACED WHAT. The pre-wave-18 cutoff flipped a single `seen_test`
        # flag and then `next`ed EVERY remaining line, TRUSTING (without checking)
        # that the test module was the LAST thing in the file. A separate NTTEST
        # GUARD re-asserted that trust by classifying every later column-0 line via
        # `is_column0_item_start` — an item-KIND enumerator that leaked a new
        # spelling every wave (`unsafe fn`/`const fn`; `unsafe impl`/`unsafe trait`;
        # `pub(crate) mod`; the path-qualified item macro `foo::bar! {}`). That is
        # the non-convergent "one-more-spelling" anti-pattern.
        #
        # Instead, we now TRACK the CODE brace depth of the test module and detect
        # its CLOSING brace structurally. After the module closes, ANY column-0
        # production content (whatever its item/macro spelling) is a non-trailing
        # vacuum — there is NOTHING to classify, so no spelling can evade the
        # guard. The ONLY shapes that legitimately follow a closed test module
        # WITHOUT being a vacuum are: blank / comment lines, attribute lines, and a
        # SECOND `#[cfg(test)]`-gated `mod` (a file may carry several test
        # modules); each is handled explicitly below.
        #
        # WAVE-14 ROOT-CAUSE (preserved): the module is recognised ONLY when the
        # test gate decorates a `mod` — NOT a column-0 test gate that decorates a
        # SINGLE production-compiled item (a testing-only `pub fn` / `impl` /
        # `pub use` that IS compiled into the `testing` feature and sits AMONG
        # production items, e.g. `context/mod.rs::test_supervisor`,
        # `SagaInput::test_cross_context_for_gating`, the `pub use` in
        # `supervisor/mod.rs`). Such an interspersed single-item gate carries no
        # Class-S marker and must stay in the production scan stream; only a
        # `mod`-form gate opens a module. The detector looks PAST blank / comment /
        # attribute lines (via `is_column0_code_line`) to the first real column-0
        # code line: a `mod` ⇒ module open; anything else ⇒ interspersed item (no
        # cutoff, the item falls through into the normal production scan below).

        # CODE brace counts for THIS stripped line, used to track the depth of
        # the test module (the same braces the production fn-body model counts
        # below via its own opens/closes — recounted here because the test
        # module tracking runs BEFORE the production fn block).
        tm_opens = gsub(/{/, "{", line)
        tm_closes = gsub(/}/, "}", line)

        if (in_test_module) {
            # Inside a trailing test module body: skip from the production scan.
            # The module CLOSES at the `}` that returns the running CODE brace
            # depth (starting at `test_mod_depth`) to 0. We find that close
            # POSITIONALLY (not by NET brace count), so a brace-BALANCED closing
            # line that both closes the module AND re-opens a brace for trailing
            # production (`} fn resumed_production() { .. }`) is still recognised
            # as a close — a net count would stay > 0 and miss the GAP-1 vacuum.
            tm_close_pos = brace_close_pos(line, test_mod_depth)
            if (tm_close_pos == 0) {
                # Module does not close on this line: carry the depth forward.
                test_mod_depth += tm_opens - tm_closes
                next
            }
            in_test_module = 0
            test_mod_depth = 0
            after_test_module = 1
            # GAP-1 — CONTENT ON THE MODULE-CLOSING LINE. When the closing `}`
            # SHARES a physical line with production code
            # (`} fn resumed_production() { ...class-s mutation... }`), a bare
            # `next` here would scan NEITHER the production on that line NOR its
            # Class-S mutation — a silent vacuum. Re-evaluate the remainder of THIS
            # physical line AFTER the brace that closed the module: if it is
            # column-0 production content (not blank / comment / attribute /
            # re-opening test gate), the module was NOT trailing and that trailing
            # production is an un-scanned vacuum. Fire NTTEST once, mirroring the
            # after-module guard below (which only sees the NEXT line and so would
            # miss same-line production). Fail-closed direction: a same-line
            # re-opening test gate in the remainder is treated as non-content (not
            # re-entered from a remainder), which can only ever over-report a
            # vacuum, never hide one. WAVE-20 (HOLE-2): the remainder may itself
            # begin with a balanced leading attribute (`} #[rustfmt::skip] pub fn
            # evil(){..}`); is_attr_prefixed_production peels it so the attribute-
            # prefixed whole-item resume is seen as production, not skipped.
            if (!nontrailing_hit \
                && is_attr_prefixed_production(substr(line, tm_close_pos + 1))) {
                printf("NTTEST\t%s\t%d\t%s\n", FILE, test_gate_line, "non_trailing_test_module")
                nontrailing_hit = 1
            }
            next
        }

        # MULTI-LINE ATTRIBUTE CARRY. A column-0 attribute whose `[`/`(` are not
        # balanced on its opening line (`#[allow(\n  clippy::a,\n  clippy::b\n)]`,
        # `#[derive(\n  Foo\n)]`) continues onto following physical lines — the
        # last of which is often a bare column-0 `)]`. Such continuation lines are
        # NOT production content; if the mod-vs-item DETECTOR or the NTTEST GUARD
        # saw a `)]` as a "column-0 code line" it would (a) wrongly conclude the
        # test gate decorated an interspersed item — skipping the `mod tests {`
        # that actually follows the closing `)]` — or (b) false-fire NTTEST. We
        # therefore carry the attribute bracket depth across lines (counting the
        # STRIPPED line so a `(`/`[` inside a literal/comment cannot miscount) and
        # SKIP every line until the attribute closes. A single-line attribute
        # (`#[cfg(test)]`) is balanced (depth 0) and is NOT skipped — the gate
        # detector below still sees it. `next` is taken for the opening line of a
        # multi-line attribute and all its continuation lines, exactly as for an
        # in-flight literal/comment.
        attr_brk = gsub(/[([]/, "&", line)   # `(` or `[` opens (count only)
        attr_brk_close = gsub(/[)\]]/, "&", line)   # `)` or `]` closes
        if (attr_bracket_depth > 0) {
            # Continuation of an in-flight multi-line attribute.
            attr_pre = attr_bracket_depth
            attr_bracket_depth += attr_brk - attr_brk_close
            if (attr_bracket_depth <= 0) {
                attr_bracket_depth = 0
                # The multi-line attribute COMPLETED on this line.
                if (attr_is_test_cfg) {
                    # GAP-3 — a MULTI-LINE test-cfg gate (`#[cfg(all(test,\n
                    # feature="x"\n))]`). Arm the pending test gate exactly as the
                    # single-line gate detector below does, so the `mod` it
                    # decorates (on a following line) is consumed as a test module
                    # rather than scanned as production. Anchor the reported gate
                    # line at the attribute OPENING line (recorded when the head
                    # was seen).
                    attr_is_test_cfg = 0
                    pending_test_gate = 1
                    pending_test_line = attr_test_cfg_line
                    next
                }
                # GAP-1 (attr-closer variant) — a NON-test multi-line attribute
                # whose closing `)]` SHARES a physical line with production
                # (`)] fn sneaky_production() { ... }`) AFTER a trailing test
                # module has closed would, with a bare `next`, silently drop that
                # production region. Re-evaluate the remainder after the `]` that
                # closed the attribute: if it is column-0 production content, the
                # module was NOT trailing — an un-scanned vacuum. (The attribute
                # decorates that production item; the item itself begins after the
                # closer on the same physical line.) WAVE-20 (HOLE-2): a SECOND
                # leading attribute on the decorated item (`)] #[inline] pub fn
                # x(){..}`) is peeled by is_attr_prefixed_production.
                if (after_test_module && !nontrailing_hit \
                    && is_attr_prefixed_production(remainder_after_attr_close(line, attr_pre))) {
                    printf("NTTEST\t%s\t%d\t%s\n", FILE, test_gate_line, "non_trailing_test_module")
                    nontrailing_hit = 1
                }
            }
            next
        }
        if (line ~ /^#!?\[/ && (attr_brk - attr_brk_close) > 0) {
            # Opening line of a MULTI-LINE attribute: arm the carry and skip it.
            # (A `#[cfg(test)]` re-opening gate is single-line/balanced, so it does
            # NOT enter here — it is matched by the gate detector below.)
            attr_bracket_depth = attr_brk - attr_brk_close
            # Remember whether this multi-line attribute is a test-cfg gate head
            # (`#[cfg(all(test,` / `#[cfg(any(test,`) so its completion can arm the
            # pending test gate (GAP-3). Record the OPENING line for the gate-line
            # report.
            if (is_test_cfg_attr_head(line)) {
                attr_is_test_cfg = 1
                attr_test_cfg_line = NR
            } else {
                attr_is_test_cfg = 0
            }
            next
        }

        # Detect the column-0 test gate that opens a trailing test module.
        #
        # ACCEPTED OVER-REPORT SHAPES (wave-20, CLASS-B fail-CLOSED): a multi-line
        # attribute `))]` closer SHARING a line with `mod {`, and a `mod NAME` whose
        # opening `{` is on the NEXT physical line, can over-report NTTEST. Both are
        # rustfmt-IMPOSSIBLE (cargo-fmt always separates the closer / opening brace
        # onto their own lines) with no live occurrence in the scan tree, so per the
        # convergence ceiling they are left as accepted fail-closed over-reports —
        # we do NOT enumerate further attribute/brace placements to chase them.
        #
        # GAP-2 — SAME-LINE `#[cfg(test)] mod NAME {`. The gate and the `mod` it
        # decorates may share ONE physical line. The reopening-gate test below is
        # prefix-anchored, so it would arm `pending_test_gate` and then look to the
        # NEXT line for the `mod` — leaving a same-line `mod {` to fall into the
        # production scanner (the test body scanned as production: a false HIT, and
        # a trailing production vacuum after it missed). Detect it here: a column-0
        # reopening test gate whose remainder, AFTER stripping the leading
        # attribute, is itself a column-0 `mod` decl IS a same-iteration module
        # entry. Consume it now (count this line braces as the module body) so
        # the body is not scanned and a real trailing production resume is still
        # caught by the after-module guard.
        if (is_column0_reopening_test_gate(line) \
            && is_column0_mod_decl(strip_leading_attr(line))) {
            if (!after_test_module) test_gate_line = NR
            pending_test_gate = 0
            enter_test_module(tm_opens, tm_closes)
            next
        }
        if (is_column0_reopening_test_gate(line)) {
            pending_test_gate = 1
            pending_test_line = NR
        } else if (pending_test_gate && is_column0_code_line(line)) {
            # First real column-0 code line after the gate decides mod-vs-item.
            # (Blank / comment / further attribute lines are skipped by
            # `is_column0_code_line` so the gate stays pending until a real code
            # line is reached.)
            if (is_column0_mod_decl(line)) {
                # A test MODULE opens here (the first trailing module, OR a
                # legitimate SECOND test module reached after a prior one closed —
                # this same `pending_test_gate` path handles both: a re-opening
                # `#[cfg(test)]` gate armed it and this `mod` is the module it
                # decorates). Record the gate line for the FIRST module only (a
                # second module must not overwrite the original gate line that an
                # eventual NTTEST reports). ENTER the module via brace depth: the
                # `mod .. {` line contributes `tm_opens` (>=1).
                if (!after_test_module) test_gate_line = pending_test_line
                pending_test_gate = 0
                enter_test_module(tm_opens, tm_closes)
                next
            }
            # else: interspersed single-item test gate — NOT a module. The item
            # falls through into the normal production scan stream below.
            pending_test_gate = 0
        }

        # NON-TRAILING test-module structural assertion (the un-scanned-vacuum
        # GUARD). Once a trailing test module has CLOSED (`after_test_module`), the
        # cutoff would have skipped everything below it. If ANY column-0 PRODUCTION
        # content follows, the module was NOT trailing — that production region is
        # an un-scanned vacuum where a Class-S mutation could hide. Flag it
        # (NTTEST) so the vacuum is surfaced rather than silently trusted.
        #
        # CONVERGENT GUARD (wave-18): there is NO item-kind classifier here. The
        # END of the module is found structurally (brace depth) and ANY column-0 code
        # line after it is a vacuum, regardless of the item/macro spelling that
        # resumes the region (`fn` / `impl` / `unsafe impl` / `unsafe trait` / a
        # re-opened `mod` / a single-ident OR path-qualified item macro / anything
        # else). This is immune to every present and future spelling because it
        # matches the ABSENCE of the three non-content shapes (blank, comment,
        # attribute) rather than enumerating the content shapes.
        #
        # The ONE shape that legitimately resumes at column 0 after a closed test
        # module WITHOUT being a vacuum is a SECOND `#[cfg(test)]`-gated `mod`.
        # That case never reaches the NTTEST branch below: the re-opening
        # `#[cfg(test)]` gate is matched by the DETECTOR above (which arms
        # `pending_test_gate`) and the `mod` it decorates is consumed there as a
        # module (re-entering `in_test_module` and taking `next`). So here we only
        # see a re-opening gate (skipped — its `mod` is handled above) or a real
        # production line. Any column-0 code line that is NOT such a gate — any
        # item spelling whatsoever — is the un-scanned vacuum.
        #
        # WAVE-20 (HOLE-2) — ATTRIBUTE-PREFIXED WHOLE-ITEM RESUME. A production item
        # resuming with a balanced leading attribute on the SAME physical line
        # (`#[rustfmt::skip] pub fn evil() { ..class-s mutation.. }`) is NOT caught
        # by `is_column0_code_line` (it excludes any `^#[` line, looking PAST the
        # attribute to a FOLLOWING line) AND does NOT enter the multi-line attr-carry
        # (the whole `#[attr] item` line is bracket-balanced). `#[rustfmt::skip]` is
        # the directive to PRESERVE hand-formatting, so this one-line shape is left
        # byte-for-byte unchanged by rustfmt (it is NOT fmt-prevented). We therefore
        # ALSO fire when is_attr_prefixed_production peels the balanced leading
        # attribute(s) and finds production content after — reusing strip_leading_attr
        # (the SAME primitive GAP-2 already trusts; convergent, no new enumeration).
        # is_attr_prefixed_production returns 0 for a re-opening `#[cfg(test)]` gate,
        # so a legitimate second test module is not false-fired.
        if (after_test_module && !nontrailing_hit) {
            if ((!is_column0_reopening_test_gate(line) && is_column0_code_line(line)) \
                || is_attr_prefixed_production(line)) {
                # A column-0 production code line (possibly attribute-prefixed) after
                # the module closed (a `mod` decorated by a re-opening gate was
                # consumed by the detector above and `next`ed before reaching here).
                # The test module was NOT trailing — an un-scanned vacuum.
                printf("NTTEST\t%s\t%d\t%s\n", FILE, test_gate_line, "non_trailing_test_module")
                nontrailing_hit = 1
            }
        }
        if (after_test_module) next

        # Detect a top-level function definition (column 0, allowing pub/async
        # qualifiers). Capture the name. We only treat a fn as "open" once we
        # see its opening brace (which may be on the signature line or a later
        # line for multi-line signatures).
        # Peel any same-line leading `#[..]` attribute(s) before testing the fn
        # anchor, so `#[rustfmt::skip] pub fn evil()` (fmt-clean — attribute + fn on
        # ONE physical line) is recognised, its body scanned for Class-S markers,
        # AND its `execute_*` governance-leaf class detected, exactly as a bare
        # `pub fn evil()`. `det` is whitespace-trimmed by `peel_leading_attrs`, so
        # the anchor drops the leading `^[[:space:]]*`. Brace counting below stays
        # on the FULL `line` (an attribute carries no `{`/`}`), so `depth` and the
        # fn-body floor are unaffected by the peel.
        #
        # ACCEPTED LIMITATION (CLASS-B, contrived, no live occurrence): a fn whose
        # signature is NOT at the start of its physical line — e.g. an ENTIRE module
        # body on one line, `#[rustfmt::skip] mod w { pub fn evil() {..} }` — is not
        # detected (the mid-line `pub fn` sits past a `mod w {` the leading-attr peel
        # does not span). Writing a whole module + fn on one physical line requires
        # `#[rustfmt::skip]` and is not a shape any formatted code produces; per
        # the convergence ceiling we do not chase it (an insider who can craft it can
        # equally edit this gate).
        # The optional leading qualifier run accepts the COMPLETE, bounded Rust
        # fn-qualifier grammar — `pub`/`pub(path)`, then any order/repetition of
        # `const` / `unsafe` / `async` / `extern "ABI"`. Earlier this anchor took
        # only `pub`/`async`, so `pub extern "C" fn evil() { ..class-s mutation.. }`
        # — fmt-clean and compiling under `#![forbid(unsafe_code)]` — was NOT
        # recognised and its mutation hid (a CLASS-A fail-open). `const fn`/`unsafe
        # fn` are non-carriers (const cannot do a `&mut` mutation; unsafe fn is
        # forbidden tree-wide), but recognising them is harmless (their bodies are
        # merely scanned) and `extern "C" fn` IS a live carrier. This is the same
        # finite qualifier grammar the NTTEST classifier already enumerates — bounded,
        # not the non-convergent one-more-spelling pattern.
        if (!in_fn) {
            det = peel_leading_attrs(line)
            if (det ~ (FNQUAL "[A-Za-z0-9_]+")) {
                tmp = det
                sub(FNQUAL, "", tmp)
                sub(/[^A-Za-z0-9_].*$/, "", tmp)
                pending_fn = tmp
                pending_line = NR
                pending = 1
            }
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

            mline = normalize_borrow(normalize_assign(chain_buf))
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

    local hits govhits nttest scanned_total
    hits=$(grep -c $'^HIT\t' "$tmp_out" 2>/dev/null || true)
    hits=${hits:-0}
    govhits=$(grep -c $'^GOVHIT\t' "$tmp_out" 2>/dev/null || true)
    govhits=${govhits:-0}
    nttest=$(grep -c $'^NTTEST\t' "$tmp_out" 2>/dev/null || true)
    nttest=${nttest:-0}
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

    # Structural guard — NON-TRAILING test module (wave-18 brace-depth reframe): a
    # column-0 test gate whose module does NOT close at EOF — ANY column-0
    # production content (whatever the item/macro spelling) follows the module's
    # closing brace. The trailing-test cutoff would skip that production region (an
    # un-scanned vacuum), so any Class-S mutation in it would go undetected. The
    # cutoff TRUSTS without asserting that every test module is trailing; this
    # asserts it by tracking the module's brace depth and flagging any production
    # resume after its close — with no item-kind classifier to leak a new spelling.
    if [[ "$nttest" -ne 0 ]]; then
        printf '\n%sFAILED%s: %d file(s) have a column-0 test gate (`#[cfg(test)]` /\n' \
            "$C_RED" "$C_RESET" "$nttest" >&2
        printf '`#[cfg(all(test,..))]` / `#[cfg(any(test,..))]`) whose module is FOLLOWED\n' >&2
        printf '(after its closing brace) by column-0 production content — a NON-trailing\n' >&2
        printf 'test module. The trailing-test cutoff would skip that production region,\n' >&2
        printf 'leaving an UN-SCANNED vacuum where a Class-S mutation could hide:\n' >&2
        while IFS=$'\t' read -r tag file line fn; do
            [[ "$tag" == "NTTEST" ]] || continue
            printf '      %s%s:%s%s  (column-0 test gate not trailing)\n' \
                "$C_DIM" "$file" "$line" "$C_RESET" >&2
        done < "$tmp_out"
        printf '\n' >&2
        printf 'Move the test module to the END of the file (it MUST be trailing), or split\n' >&2
        printf 'the production items above it into their own non-test region. The cutoff\n' >&2
        printf 'relies on the test module being the last thing in the file.\n' >&2
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

    if [[ "$hits" -eq 0 && "$govhits" -eq 0 && "$nttest" -eq 0 && "$coupling_failed" -eq 0 ]]; then
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
#   (35-45) NON-TRAILING TEST MODULE (the un-scanned-vacuum GUARD) — a column-0
#        test gate whose module is NOT the last thing in the file IS flagged
#        (NTTEST), while a genuinely-trailing module and a legitimate SECOND test
#        module are NOT: (35) a fn resumes after the module → HIT; (36) ordinary
#        trailing module → no HIT; (37) interspersed single-item test gate (not a
#        module) → its production mutation still scanned, no NTTEST; (38-41,43,44)
#        a production region resuming with various item/macro spellings → HIT;
#        (42,45) a legitimate second `#[cfg(test)] mod` (incl. `pub(crate) mod`) →
#        no HIT.
#   (46-48) WAVE-18 BRACE-DEPTH REFRAME — the NTTEST guard now finds the END of
#        the trailing test module by CODE BRACE DEPTH and flags ANY column-0
#        production content after it, with NO item-kind classifier (the prior
#        `is_column0_item_start` enumerator that leaked a new spelling every
#        wave is DELETED): (46) a path-qualified item macro
#        `scp_testing::storage_conformance! {}` resuming after the module → HIT
#        (the black-hat gap; non-vacuity: reverting the brace-depth logic stops
#        this HIT); (47) a genuinely-trailing module with a deeply-nested body
#        closing at EOF → no HIT (the tracker follows the body to its real closing
#        brace); (48) a module followed only by comments/blank lines → no HIT
#        (commentary is not production content).
#   (49-54) WAVE-19 LINE-GRANULARITY — close-line production resume (49), multi-
#        line-attribute-closer resume (50), same-line `#[cfg(test)] mod {}` trailing
#        (51) / non-trailing (52), multi-line test-cfg gate (53), and a NON-test
#        multi-line attr carry before a trailing module (54).
#   (55-56) WAVE-20 — (55) a DEGENERATE `#[cfg(test)] mod x {}` + same-line
#        production fn → HIT (entry-path positional close; pre-wave-20 NET count
#        absorbed the fn body); (56a/56b) an attribute-prefixed whole-item resume
#        (`#[rustfmt::skip] pub fn evil(){..}`) on its own line / sharing the
#        module-closing `}` line → HIT (is_attr_prefixed_production peels the
#        balanced leading attribute, which is fmt-clean and was silently swallowed);
#        (56c) a legitimate second `#[cfg(test)] mod` → no HIT (attr-peel returns 0
#        on a re-opening test gate).
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

    # (60) RECEIVER-ALIASED CEILING WRITE (wave-23 black-hat bypass). A ceiling
    # lowering through a `let rs = &mut state.role_state; rs.ceiling = ...` alias
    # carries NO `role_state.ceiling=` prefix on the write line, so PRE-fix the
    # receiver-pinned marker missed it (a non-execute_ handler with no GOVHIT
    # backstop). The receiver-AGNOSTIC `.ceiling=` marker MUST catch the aliased
    # best-effort write (HIT). Named non-execute_ so GOVHIT cannot mask it.
    {
        printf 'pub fn aliased_ceiling_fixture() {\n'
        printf '    let rs = &mut state.role_state;\n'
        printf '    rs.ceiling = CapabilityCeiling::new(lowered);\n'
        printf '    persist_state_best_effort(state, deps, ctx);\n'
        printf '}\n'
    } > "$fdir/aliased_ceiling.rs"

    # (61) RECEIVER-ALIASED xctx_caller_reservations INSERT. The reservation is
    # staged through a `let resv = &mut state.xctx_caller_reservations;
    # resv.insert(...)` alias, so the `xctx_caller_reservations.insert(` marker
    # misses on the insert line. The `&mut.xctx_caller_reservations` companion
    # MUST catch the mutable-alias BORROW (HIT). Best-effort persist.
    {
        printf 'pub fn aliased_xctx_reservation_fixture() {\n'
        printf '    let resv = &mut state.xctx_caller_reservations;\n'
        printf '    resv.insert(saga_id, record);\n'
        printf '    persist_state_best_effort(state, deps, ctx);\n'
        printf '}\n'
    } > "$fdir/aliased_xctx_reservation.rs"

    # (62) RECEIVER-ALIASED saga_pending INSERT — same evasion via `let sp = &mut
    # state.saga_pending; sp.insert(...)`. The `&mut.saga_pending` companion MUST
    # catch the borrow (HIT). Best-effort persist.
    {
        printf 'pub fn aliased_saga_pending_fixture() {\n'
        printf '    let sp = &mut state.saga_pending;\n'
        printf '    sp.insert(saga_id, pending);\n'
        printf '    persist_state_best_effort(state, deps, ctx);\n'
        printf '}\n'
    } > "$fdir/aliased_saga_pending.rs"

    # (63) RECEIVER-ALIASED membership REMOVE — `let m = &mut state.membership;
    # m.remove_member(...)`. A receiver-agnostic `.remove_member(` marker would
    # collide with the unrelated MLS `crypto.remove_member(`; the
    # `&mut.membership` borrow companion catches the alias WITHOUT that collision
    # (HIT). Best-effort persist.
    {
        printf 'pub fn aliased_membership_remove_fixture() {\n'
        printf '    let m = &mut state.membership;\n'
        printf '    m.remove_member(member_did);\n'
        printf '    persist_state_best_effort(state, deps, ctx);\n'
        printf '}\n'
    } > "$fdir/aliased_membership_remove.rs"

    # (64) READ-ALIAS CONTROL — a SHARED borrow `let r = &state.membership;`
    # followed by a READ (`r.contains_key`) MUST NOT be flagged: the borrow is
    # `&` (shared), not `&mut`, so `normalize_borrow` leaves it untouched and no
    # `&mut.membership` token appears. Guards the read-vs-write precision of the
    # companion markers. Best-effort persist (a pure read need not fail-close).
    {
        printf 'pub fn read_alias_membership_fixture() {\n'
        printf '    let r = &state.membership;\n'
        printf '    let present = r.contains_key(member_did);\n'
        printf '    let _ = present;\n'
        printf '    persist_state_best_effort(state, deps, ctx);\n'
        printf '}\n'
    } > "$fdir/read_alias_membership.rs"

    # (65) RECEIVER-ALIASED xctx_caller_reservations INSERT that DOES fail-close
    # MUST NOT be flagged — the companion borrow marker must still honour a
    # fail-closed persist (no false positive on a correctly-persisted alias).
    {
        printf 'pub fn aliased_xctx_reservation_fixed_fixture() {\n'
        printf '    let resv = &mut state.xctx_caller_reservations;\n'
        printf '    resv.insert(saga_id, record);\n'
        printf '    persist_state_fail_closed(state, deps, ctx)?;\n'
        printf '}\n'
    } > "$fdir/aliased_xctx_reservation_fixed.rs"

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

    # (57) ATTRIBUTE-PREFIXED FN on one physical line — the fn-detector blind spot.
    # `#[rustfmt::skip] pub fn ... {` keeps the attribute + signature on ONE line
    # (rustfmt::skip preserves it — fmt-clean and reachable). The bare
    # `^[[:space:]]*(pub..)?fn` anchor rejects the leading `#[`, so PRE-fix the fn
    # was never recognised and its best-effort `suspend_all` mutation was silently
    # swallowed. The detector now peels leading attributes (peel_leading_attrs), so
    # the fn IS recognised and the un-persisted mutation MUST be caught (HIT).
    {
        printf '#[rustfmt::skip] pub fn skip_regular_fixture() {\n'
        printf '    state.role_state.suspend_all(did.as_ref());\n'
        printf '    persist_state_best_effort(state, deps, ctx);\n'
        printf '}\n'
    } > "$fdir/skip_regular.rs"

    # (58) ATTRIBUTE-PREFIXED GOVERNANCE LEAF on one physical line. The `execute_*`
    # governance-leaf classification keys on the fn NAME the detector extracts; a
    # leading same-line `#[rustfmt::skip]` PRE-fix hid the whole fn, so the name was
    # never extracted and the downward-auth leaf (best-effort, not allowlisted,
    # carrying NO mutation marker) was swallowed. The peel exposes the name, so the
    # GOVHIT (fail-closed-by-default) rule MUST catch it.
    {
        printf '#[rustfmt::skip] pub fn execute_skip_gov_fixture() {\n'
        printf '    state.role_state.assign_role(did, lower_role);\n'
        printf '    persist_state_best_effort(state, deps, ctx);\n'
        printf '}\n'
    } > "$fdir/skip_gov.rs"

    # (59) QUALIFIER-RUN: a `pub extern "C" fn` (fmt-clean, compiles under
    # `#![forbid(unsafe_code)]`) with a best-effort `suspend_all` mutation MUST be
    # caught — the fn-anchor must accept the `extern "ABI"` qualifier, not only
    # `pub`/`async`. (Pre-fix the extern fn was unrecognised and its mutation hid.)
    {
        printf 'pub extern "C" fn extern_abi_fixture() {\n'
        printf '    state.role_state.suspend_all(did.as_ref());\n'
        printf '    persist_state_best_effort(state, deps, ctx);\n'
        printf '}\n'
    } > "$fdir/extern_abi.rs"

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

    # (32) TRAILING-NESTED-OPEN DEFLATION (wave-13) — a nested `/*` that is the
    # LAST comment-token on its physical line (no `*/` after it on that line).
    # The prior scanner carried the comment depth but did NOT increment for that
    # trailing nested open, so it under-counted depth by one and surfaced from the
    # comment one `*/` too EARLY, leaking the trailing ` } */` residue. The leaked
    # `}` closed the body prematurely (deflation) and the best-effort Class-S
    # mutation below went invisible. The comment is a properly nested+closed
    # `/* .. /* .. */ } */` (2 opens, 2 closes), so the code is legal,
    # cargo-fmt-clean Rust. Fixtures 26/27 only exercise SAME-LINE `/* inner */`;
    # this covers the last-token-on-line path. The mutation MUST be caught.
    {
        printf 'pub async fn nested_comment_trailing_open_deflation_fixture() {\n'
        printf '    /* legacy approach:\n'
        printf '       fn old() { /* helper open\n'
        printf '    */ } */\n'
        printf '    state.xctx_caller_reservations.insert(saga_id, record);\n'
        printf '    persist_state_best_effort(state, deps, ctx);\n'
        printf '}\n'
    } > "$fdir/nested_comment_trailing_open_deflation.rs"

    # (33) TRAILING-NESTED-OPEN INFLATION (wave-13) — the same trailing-open
    # hazard, but the early surface leaks a ` { */` residue. The leaked `{`
    # inflated the poison fn's depth so it never returned to its floor and
    # SWALLOWED the SEPARATE later fn — blinding the file. The best-effort Class-S
    # mutation in that LATER (victim) fn MUST still be caught (the file is not
    # blinded). The poison fn fail-closes so it is not the HIT.
    {
        printf 'pub async fn nested_comment_trailing_open_inflation_poison_fixture() {\n'
        printf '    /* legacy approach:\n'
        printf '       fn old() { /* helper open\n'
        printf '    */ { */\n'
        printf '    persist_state_fail_closed(state, deps, ctx)?;\n'
        printf '}\n'
        printf '\n'
        printf 'pub async fn nested_comment_trailing_open_inflation_victim_fixture() {\n'
        printf '    state.xctx_caller_reservations.insert(saga_id, record);\n'
        printf '    persist_state_best_effort(state, deps, ctx);\n'
        printf '}\n'
    } > "$fdir/nested_comment_trailing_open_inflation.rs"

    # (34) CHAR-LITERAL UNICODE-ESCAPE BRACE — branch-completeness (wave-13). The
    # `'\u{7d}'` / `'\u{7b}'` unicode-escape char literals carry a `}` / `{`
    # CODEPOINT inside the literal. The strip already handles this branch
    # correctly (black-hat verified), but it was the only brace-bearing literal
    # branch WITHOUT a poison fixture. The deflation variant (a `'\u{7d}'` `}`
    # before a best-effort mutation) MUST be caught — the brace inside the char
    # literal must be stripped, not leaked to close the body early. The fail-closed
    # variant (a `'\u{7b}'` `{` in a CORRECTLY fail-closed fn) is the over-strip
    # guard — it MUST NOT be flagged.
    {
        printf 'pub async fn char_unicode_escape_brace_deflation_fixture() {\n'
        printf "    let _close = '\\\\u{7d}';\n"
        printf "    let _open = '\\\\u{7b}';\n"
        printf '    state.xctx_caller_reservations.insert(saga_id, record);\n'
        printf '    persist_state_best_effort(state, deps, ctx);\n'
        printf '}\n'
        printf '\n'
        printf 'pub async fn char_unicode_escape_brace_fail_closed_fixture() {\n'
        printf "    let _open = '\\\\u{7b}';\n"
        printf "    let _close = '\\\\u{7d}';\n"
        printf '    state.xctx_caller_reservations.insert(saga_id, record);\n'
        printf '    persist_state_fail_closed(state, deps, ctx)?;\n'
        printf '}\n'
    } > "$fdir/char_unicode_escape_brace.rs"

    # (35) NON-TRAILING TEST MODULE (wave-14) — a column-0 test gate FOLLOWED by
    # a column-0 production item is NOT a trailing test module: the cutoff would
    # skip that production region (an un-scanned vacuum). MUST emit an NTTEST HIT.
    {
        printf 'pub async fn prod_before_test_fixture() {\n'
        printf '    persist_state_fail_closed(state, deps, ctx)?;\n'
        printf '}\n'
        printf '\n'
        printf '#[cfg(test)]\n'
        printf 'mod interspersed_tests {\n'
        printf '    fn a_test_helper() {}\n'
        printf '}\n'
        printf '\n'
        printf 'pub fn prod_after_test_fixture() {\n'
        printf '    state.xctx_caller_reservations.insert(saga_id, record);\n'
        printf '    persist_state_best_effort(state, deps, ctx);\n'
        printf '}\n'
    } > "$fdir/nontrailing_test_module.rs"

    # (36) TRAILING TEST MODULE (wave-14) — the legitimate shape: a column-0 test
    # gate with NO column-0 production item after it. MUST NOT emit an NTTEST HIT
    # (the over-restriction guard: an ordinary trailing test module is fine).
    {
        printf 'pub fn prod_only_fixture() {\n'
        printf '    persist_state_fail_closed(state, deps, ctx)?;\n'
        printf '}\n'
        printf '\n'
        printf '#[cfg(all(test, feature = "testing"))]\n'
        printf 'mod trailing_tests {\n'
        printf '    fn another_helper() {}\n'
        printf '    #[test]\n'
        printf '    fn it_works() {}\n'
        printf '}\n'
    } > "$fdir/trailing_test_module.rs"

    # (37) INTERSPERSED single-item test gate (wave-14 root-cause regression) — a
    # COLUMN-0 `#[cfg(any(test, feature = "testing"))]` decorating a SINGLE
    # production-compiled item (a testing-only `pub fn`), NOT a `mod`. It must NOT
    # trigger the trailing-module cutoff: the production Class-S mutation BELOW it
    # MUST still be scanned and (lacking a fail-closed persist) caught. This is the
    # exact shape — `context/mod.rs::test_supervisor`,
    # `SagaInput::test_cross_context_for_gating`, `supervisor/mod.rs`'s testing
    # `pub use` — that the prior raw-line cutoff wrongly skipped, silently
    # blinding the scanner over ~10k lines of production saga code.
    {
        printf '#[cfg(any(test, feature = "testing"))]\n'
        printf '#[must_use]\n'
        printf 'pub fn interspersed_test_helper_fixture() -> u8 {\n'
        printf '    0\n'
        printf '}\n'
        printf '\n'
        printf 'pub async fn prod_after_interspersed_gate_fixture() {\n'
        printf '    state.xctx_caller_reservations.insert(saga_id, record);\n'
        printf '    persist_state_best_effort(state, deps, ctx);\n'
        printf '}\n'
    } > "$fdir/interspersed_item_gate.rs"

    # (38) NON-TRAILING TEST MODULE resuming with a column-0 `const fn` /
    # `unsafe fn` (wave-15) — the prior NTTEST regex matched `unsafe impl` but
    # NOT a bare column-0 `unsafe fn`, and missed `const fn` entirely, so a
    # production region resuming with one of those after a trailing test module
    # would NOT raise NTTEST (an un-scanned vacuum). Both shapes here MUST emit an
    # NTTEST HIT now. (Non-exploitable today — forbid(unsafe_code) + const fn
    # cannot run a runtime state mutation — but the vacuum guard fires regardless.)
    {
        printf 'pub fn const_unsafe_prod_before_test_fixture() {\n'
        printf '    persist_state_fail_closed(state, deps, ctx)?;\n'
        printf '}\n'
        printf '\n'
        printf '#[cfg(test)]\n'
        printf 'mod const_unsafe_interspersed_tests {\n'
        printf '    fn a_test_helper() {}\n'
        printf '}\n'
        printf '\n'
        printf 'const fn prod_const_fn_after_test_fixture() -> u8 {\n'
        printf '    0\n'
        printf '}\n'
        printf '\n'
        printf 'unsafe fn prod_unsafe_fn_after_test_fixture() {\n'
        printf '    persist_state_best_effort(state, deps, ctx);\n'
        printf '}\n'
    } > "$fdir/nontrailing_const_unsafe_fn.rs"

    # (39) NON-TRAILING TEST MODULE resuming with a column-0 `mod resumed_prod {`
    # (wave-16) — a NON-test column-0 `mod` after a trailing test module re-opens
    # an entire INDENTED production region whose Class-S mutations the cutoff would
    # skip. This is the MOST material missed shape (an indented `state.x.insert()`
    # is invisible to the cutoff, never to a real scan). The prior NTTEST denylist
    # of fn permutations missed it entirely. It MUST now emit an NTTEST HIT.
    {
        printf 'pub fn mod_resume_prod_before_test_fixture() {\n'
        printf '    persist_state_fail_closed(state, deps, ctx)?;\n'
        printf '}\n'
        printf '\n'
        printf '#[cfg(test)]\n'
        printf 'mod mod_resume_interspersed_tests {\n'
        printf '    fn a_test_helper() {}\n'
        printf '}\n'
        printf '\n'
        printf 'mod resumed_prod {\n'
        printf '    pub fn f() {\n'
        printf '        state.xctx_caller_reservations.insert(saga_id, record);\n'
        printf '        persist_state_best_effort(state, deps, ctx);\n'
        printf '    }\n'
        printf '}\n'
    } > "$fdir/nontrailing_mod_resume.rs"

    # (40) NON-TRAILING TEST MODULE resuming with a column-0 `extern "C" fn`
    # (wave-16) — an `extern "ABI" fn` is a column-0 item start the prior denylist
    # did not list. It MUST now emit an NTTEST HIT (the shared item-start
    # classifier recognises the `extern "..."` qualifier run before `fn`).
    {
        printf 'pub fn extern_c_prod_before_test_fixture() {\n'
        printf '    persist_state_fail_closed(state, deps, ctx)?;\n'
        printf '}\n'
        printf '\n'
        printf '#[cfg(test)]\n'
        printf 'mod extern_c_interspersed_tests {\n'
        printf '    fn a_test_helper() {}\n'
        printf '}\n'
        printf '\n'
        printf 'extern "C" fn prod_extern_c_after_test_fixture() {\n'
        printf '    persist_state_best_effort(state, deps, ctx);\n'
        printf '}\n'
    } > "$fdir/nontrailing_extern_c_fn.rs"

    # (41) NON-TRAILING TEST MODULE resuming with a column-0 item-producing MACRO
    # invocation `make_things!{}` (wave-16) — a column-0 `ident! { .. }` can expand
    # to items, so a production region can resume through one. The prior denylist
    # missed it entirely. It MUST now emit an NTTEST HIT.
    {
        printf 'pub fn macro_item_prod_before_test_fixture() {\n'
        printf '    persist_state_fail_closed(state, deps, ctx)?;\n'
        printf '}\n'
        printf '\n'
        printf '#[cfg(test)]\n'
        printf 'mod macro_item_interspersed_tests {\n'
        printf '    fn a_test_helper() {}\n'
        printf '}\n'
        printf '\n'
        printf 'make_things!{}\n'
    } > "$fdir/nontrailing_item_macro.rs"

    # (42) LEGITIMATE SECOND TEST MODULE (wave-16 over-restriction guard) — a file
    # may carry MORE THAN ONE `#[cfg(test)]`-gated test `mod`. A second test gate +
    # `mod` after the first is NOT a production resume and MUST NOT emit an NTTEST
    # HIT (else the convergent guard would over-fire on perfectly legitimate
    # multi-test-module files).
    {
        printf 'pub fn second_test_mod_prod_fixture() {\n'
        printf '    persist_state_fail_closed(state, deps, ctx)?;\n'
        printf '}\n'
        printf '\n'
        printf '#[cfg(test)]\n'
        printf 'mod first_tests {\n'
        printf '    #[test]\n'
        printf '    fn it_works() {}\n'
        printf '}\n'
        printf '\n'
        printf '#[cfg(test)]\n'
        printf 'mod more_tests {\n'
        printf '    #[test]\n'
        printf '    fn it_also_works() {}\n'
        printf '}\n'
    } > "$fdir/second_test_module.rs"

    # (43) NON-TRAILING test module resuming with a column-0 `unsafe impl` whose
    # INDENTED body carries a best-effort Class-S mutation (wave-17). A QUALIFIED
    # NON-`fn` item (`unsafe impl`) is an item start that the prior classifier —
    # whose qualifier run was wired ONLY to `fn` — did NOT recognise, so a
    # production region resuming through it was an un-scanned vacuum (a Class-S
    # mutation in its body invisible to the cutoff). It MUST now emit an NTTEST
    # HIT (the generalised qualifier-run-before-any-keyword classifier).
    {
        printf 'pub fn unsafe_impl_prod_before_test_fixture() {\n'
        printf '    persist_state_fail_closed(state, deps, ctx)?;\n'
        printf '}\n'
        printf '\n'
        printf '#[cfg(test)]\n'
        printf 'mod unsafe_impl_interspersed_tests {\n'
        printf '    fn a_test_helper() {}\n'
        printf '}\n'
        printf '\n'
        printf 'unsafe impl Foo for Bar {\n'
        printf '    fn f(&self) {\n'
        printf '        state.xctx_caller_reservations.insert(saga_id, record);\n'
        printf '        persist_state_best_effort(state, deps, ctx);\n'
        printf '    }\n'
        printf '}\n'
    } > "$fdir/nontrailing_unsafe_impl.rs"

    # (44) NON-TRAILING test module resuming with a column-0 `unsafe trait` and a
    # `const`-qualified non-`fn` item (wave-17) — further QUALIFIED NON-`fn` item
    # shapes the fn-only qualifier wiring missed. Either resuming a production
    # region MUST emit an NTTEST HIT.
    {
        printf 'pub fn qualified_nonfn_prod_before_test_fixture() {\n'
        printf '    persist_state_fail_closed(state, deps, ctx)?;\n'
        printf '}\n'
        printf '\n'
        printf '#[cfg(test)]\n'
        printf 'mod qualified_nonfn_interspersed_tests {\n'
        printf '    fn a_test_helper() {}\n'
        printf '}\n'
        printf '\n'
        printf 'unsafe trait DangerousMarker {\n'
        printf '    fn marker(&self);\n'
        printf '}\n'
    } > "$fdir/nontrailing_qualified_nonfn.rs"

    # (45) LEGITIMATE SECOND TEST MODULE declared `pub(crate) mod more` /
    # `pub(in path) mod` (wave-17 over-restriction guard) — the second-test-module
    # accept previously matched the mod line with a NARROWER `^(pub )?mod` regex
    # than `is_column0_item_start`'s `vis` grammar, so a `pub(crate) mod` /
    # `pub(in path) mod` second test module fell through as a generic item and
    # FALSE-fired NTTEST on legal Rust. It MUST NOT emit an NTTEST HIT.
    {
        printf 'pub fn pubcrate_second_test_mod_prod_fixture() {\n'
        printf '    persist_state_fail_closed(state, deps, ctx)?;\n'
        printf '}\n'
        printf '\n'
        printf '#[cfg(test)]\n'
        printf 'mod first_tests {\n'
        printf '    #[test]\n'
        printf '    fn it_works() {}\n'
        printf '}\n'
        printf '\n'
        printf '#[cfg(test)]\n'
        printf 'pub(crate) mod more_tests {\n'
        printf '    #[test]\n'
        printf '    fn it_also_works() {}\n'
        printf '}\n'
        printf '\n'
        printf '#[cfg(test)]\n'
        printf 'pub(in crate::foo) mod even_more_tests {\n'
        printf '    #[test]\n'
        printf '    fn it_still_works() {}\n'
        printf '}\n'
    } > "$fdir/pubcrate_second_test_module.rs"

    # (46) NON-TRAILING test module resuming with a column-0 PATH-QUALIFIED item
    # macro `scp_testing::storage_conformance! { .. }` (wave-18 — the black-hat
    # gap, and the whole reason for the reframe). A path-qualified macro is the
    # MAJORITY macro spelling in the tree (`foo::bar!`), and the prior
    # single-ident `is_column0_item_start` macro branch (`^[A-Za-z_][A-Za-z0-9_]*!`)
    # did NOT match it — the `::` falls outside the ident char class — so a
    # production region resuming through one after a trailing test module was an
    # un-scanned vacuum (a Class-S mutation in the macro body invisible to the
    # cutoff). The brace-depth reframe is CLASSIFIER-FREE: after the test module
    # CLOSES, ANY column-0 production line (whatever the spelling) is a vacuum, so
    # this MUST now emit an NTTEST HIT. This is the non-vacuity proof for the
    # reframe — reverting the brace-depth logic makes this fixture stop HITting.
    {
        printf 'pub fn pathmacro_prod_before_test_fixture() {\n'
        printf '    persist_state_fail_closed(state, deps, ctx)?;\n'
        printf '}\n'
        printf '\n'
        printf '#[cfg(test)]\n'
        printf 'mod pathmacro_interspersed_tests {\n'
        printf '    fn a_test_helper() {}\n'
        printf '}\n'
        printf '\n'
        printf 'scp_testing::storage_conformance! {\n'
        printf '    fn generated(&self) {\n'
        printf '        state.xctx_caller_reservations.insert(saga_id, record);\n'
        printf '        persist_state_best_effort(state, deps, ctx);\n'
        printf '    }\n'
        printf '}\n'
    } > "$fdir/nontrailing_path_macro.rs"

    # (47) GENUINELY-TRAILING test module whose body carries NESTED
    # column-0-LOOKING content but CLOSES at EOF with nothing after it (wave-18).
    # The module body has deeply-nested helpers and a (test-only) Class-S mutation;
    # the brace-depth tracker must follow the body to its real closing `}` at EOF
    # and NOT mistake an inner construct for the module close. With nothing after
    # the closing brace, this is a legitimate trailing module and MUST NOT emit an
    # NTTEST HIT (over-restriction / premature-close guard for the brace tracker).
    {
        printf 'pub fn trailing_nested_prod_fixture() {\n'
        printf '    persist_state_fail_closed(state, deps, ctx)?;\n'
        printf '}\n'
        printf '\n'
        printf '#[cfg(test)]\n'
        printf 'mod trailing_nested_tests {\n'
        printf '    mod inner {\n'
        printf '        fn helper() {\n'
        printf '            if true {\n'
        printf '                let _ = || {\n'
        printf '                    state.xctx_caller_reservations.insert(saga_id, record);\n'
        printf '                };\n'
        printf '            }\n'
        printf '        }\n'
        printf '    }\n'
        printf '    #[test]\n'
        printf '    fn it_works() {}\n'
        printf '}\n'
    } > "$fdir/trailing_nested_test_module.rs"

    # (48) NON-TRAILING test module followed ONLY by comments / blank lines then
    # EOF (wave-18). After the module closes, the remaining lines are NOT
    # production content (a `//` comment strips to empty; a blank line is empty),
    # so `is_column0_code_line` rejects them and the guard MUST NOT fire. This
    # proves comments/blanks after the close are transparent — only a real
    # production item triggers NTTEST, never trailing commentary.
    {
        printf 'pub fn comments_after_close_prod_fixture() {\n'
        printf '    persist_state_fail_closed(state, deps, ctx)?;\n'
        printf '}\n'
        printf '\n'
        printf '#[cfg(test)]\n'
        printf 'mod comments_after_close_tests {\n'
        printf '    #[test]\n'
        printf '    fn it_works() {}\n'
        printf '}\n'
        printf '\n'
        printf '// A trailing explanatory comment after the test module.\n'
        printf '// Another comment line.\n'
        printf '\n'
        printf '/* a trailing block comment */\n'
        printf '\n'
    } > "$fdir/comments_after_close.rs"

    # (49) GAP-1 CLOSE-LINE PRODUCTION RESUME (wave-19) — a NON-trailing test
    # module whose closing `}` SHARES a physical line with a production fn
    # (`} fn resumed_production() { ..class-s mutation.. }`). The pre-wave-19 close
    # branch incremented the NET brace count (which a brace-BALANCED closing line
    # keeps > 0, so the module looked un-closed) OR, even on a net-zero line, took
    # a bare `next` that scanned NEITHER the production after the `}` NOR its
    # Class-S mutation — a silent vacuum. The brace-depth tracker now finds the
    # module-closing `}` POSITIONALLY and re-evaluates the line remainder after it;
    # the trailing production is a column-0 resume, so this MUST emit an NTTEST
    # HIT. Non-vacuity: reverting the positional close / remainder re-eval makes
    # this fixture stop HITting.
    {
        printf 'pub fn closeline_prod_before_fixture() {\n'
        printf '    persist_state_fail_closed(state, deps, ctx)?;\n'
        printf '}\n'
        printf '\n'
        printf '#[cfg(test)]\n'
        printf 'mod closeline_interspersed_tests {\n'
        printf '    fn a_test_helper() {}\n'
        printf '} pub fn closeline_resumed_production() {\n'
        printf '    state.xctx_caller_reservations.insert(saga_id, record);\n'
        printf '    persist_state_best_effort(state, deps, ctx);\n'
        printf '}\n'
    } > "$fdir/gap1_closeline_resume.rs"

    # (50) GAP-1 MULTI-LINE-ATTRIBUTE-CLOSER PRODUCTION RESUME (wave-19) — after a
    # trailing test module closes, a production fn is decorated by a MULTI-LINE
    # attribute whose closing `)]` SHARES a physical line with the fn
    # (`)] pub fn sneaky_production() { ..mutation.. }`). The attr-carry close
    # branch previously took a bare `next`, dropping the production region after
    # the `)]`. It now re-evaluates the remainder after the attribute closer; the
    # trailing production is a column-0 resume, so this MUST emit an NTTEST HIT.
    {
        printf 'pub fn attrcloser_prod_before_fixture() {\n'
        printf '    persist_state_fail_closed(state, deps, ctx)?;\n'
        printf '}\n'
        printf '\n'
        printf '#[cfg(test)]\n'
        printf 'mod attrcloser_interspersed_tests {\n'
        printf '    fn a_test_helper() {}\n'
        printf '}\n'
        printf '\n'
        printf '#[allow(\n'
        printf '    clippy::foo,\n'
        printf '    clippy::bar\n'
        # The production resume sits ENTIRELY on the `)]` closer line (a single
        # physical line, so no LATER column-0 line — e.g. a dangling `}` — can
        # trigger NTTEST instead). This makes the fixture a TRUE non-vacuity proof
        # for the attr-closer remainder branch: the NTTEST can ONLY come from
        # re-evaluating the post-`)]` remainder.
        printf ')] pub fn attrcloser_sneaky_production() { state.xctx_caller_reservations.insert(saga_id, record); persist_state_best_effort(state, deps, ctx); }\n'
    } > "$fdir/gap1_attrcloser_resume.rs"

    # (51) GAP-2 SAME-LINE GATE+MOD, TRAILING (wave-19) — a `#[cfg(test)] mod NAME
    # { .. }` with the gate AND the `mod` (and a test-only Class-S mutation in its
    # body) on ONE physical line, closing at EOF with nothing after it. The
    # pre-wave-19 detector armed the gate but only looked to the NEXT line for the
    # `mod`, so the same-line `mod {` fell into the production scanner and the
    # test-only mutation was FALSE-flagged. The same-line gate+mod is now consumed
    # as a test module in one iteration, so its body is NOT scanned and this MUST
    # NOT emit an NTTEST HIT or a (false) HIT on the test mutation.
    {
        printf 'pub fn sameline_trailing_prod_fixture() {\n'
        printf '    persist_state_fail_closed(state, deps, ctx)?;\n'
        printf '}\n'
        printf '\n'
        # Gate AND `mod {` share ONE physical line; the test body is on SEPARATE
        # (indented) lines so that, if the module is NOT recognised, the indented
        # test fn IS detected by the production scanner and its Class-S mutation
        # HITs — making this a load-bearing non-vacuity proof for the same-line
        # gate+mod recognition (revert it and `sameline_trailing_test_body` HITs).
        printf '#[cfg(test)] mod sameline_trailing_tests {\n'
        printf '    fn sameline_trailing_test_body() {\n'
        printf '        state.xctx_caller_reservations.insert(x, y);\n'
        printf '    }\n'
        printf '}\n'
    } > "$fdir/gap2_sameline_trailing.rs"

    # (52) GAP-2 SAME-LINE GATE+MOD, NON-TRAILING (wave-19) — a same-line
    # `#[cfg(test)] mod NAME { .. }` FOLLOWED by a column-0 production fn. The
    # module is recognised and consumed same-iteration; the production resume after
    # it is an un-scanned vacuum, so this MUST emit an NTTEST HIT.
    {
        printf 'pub fn sameline_nontrailing_prod_fixture() {\n'
        printf '    persist_state_fail_closed(state, deps, ctx)?;\n'
        printf '}\n'
        printf '\n'
        printf '#[cfg(test)] mod sameline_nontrailing_tests { fn a_test() {} }\n'
        printf '\n'
        printf 'pub fn sameline_resumed_production() {\n'
        printf '    state.xctx_caller_reservations.insert(saga_id, record);\n'
        printf '    persist_state_best_effort(state, deps, ctx);\n'
        printf '}\n'
    } > "$fdir/gap2_sameline_nontrailing.rs"

    # (53) GAP-3 MULTI-LINE TEST-CFG GATE, TRAILING (wave-19) — a
    # `#[cfg(all(test,\n feature = "testing"\n))]` gate SPLIT across physical lines
    # then a `mod NAME { .. }`, closing at EOF. The pre-wave-19 detector required
    # the whole `#[cfg(all(test,..))]` on one line, so the multi-line gate was
    # consumed as an opaque attribute and the `mod` it decorates was scanned as
    # production (its test-only body FALSE-flagged). The multi-line-attribute carry
    # now remembers a test-cfg head and arms the pending gate when it COMPLETES, so
    # the following `mod` is consumed as a test module. This MUST NOT emit an NTTEST
    # HIT or a (false) HIT on the test body.
    {
        printf 'pub fn multiline_cfg_prod_fixture() {\n'
        printf '    persist_state_fail_closed(state, deps, ctx)?;\n'
        printf '}\n'
        printf '\n'
        printf '#[cfg(all(test,\n'
        printf '    feature = "testing"\n'
        printf '))]\n'
        printf 'mod multiline_cfg_tests {\n'
        printf '    fn multiline_cfg_test_body() { state.xctx_caller_reservations.insert(x, y); }\n'
        printf '}\n'
    } > "$fdir/gap3_multiline_cfg_gate.rs"

    # (54) NIT-1 — MULTI-LINE NON-TEST ATTRIBUTE CARRY, TRAILING TEST MODULE
    # (wave-19). A `#[cfg(test)]` gate + `mod tests { .. }`, then a multi-line
    # `#[allow(\n clippy::foo,\n clippy::bar\n)]` whose bare `)]` closer sits at
    # column 0 BEFORE the (degenerate, immediately-closed) `mod` it decorates. The
    # `)]` closer must NOT be read as interspersed production (which would
    # mis-decide mod-vs-item and skip the module) NOR false-fire NTTEST. With
    # nothing but the decorated trailing test module after, this MUST NOT emit an
    # NTTEST HIT — exercising the `attr_bracket_depth` multi-line carry on a
    # NON-test attribute whose `)]` closer is column-0.
    {
        printf 'pub fn attrcarry_prod_fixture() {\n'
        printf '    persist_state_fail_closed(state, deps, ctx)?;\n'
        printf '}\n'
        printf '\n'
        printf '#[cfg(test)]\n'
        printf '#[allow(\n'
        printf '    clippy::foo,\n'
        printf '    clippy::bar\n'
        printf ')]\n'
        printf 'mod attrcarry_tests {\n'
        printf '    #[test]\n'
        printf '    fn it_works() {}\n'
        printf '}\n'
    } > "$fdir/attr_carry_trailing.rs"

    # (55) WAVE-20 HOLE-1 — DEGENERATE MODULE + SAME-LINE PRODUCTION RESUME. A
    # `#[cfg(test)] mod x {} pub fn resumed() {` with the degenerate (empty-body)
    # module AND a trailing production fn that OPENS a brace on the SAME physical
    # line (the fn BODY — carrying a Class-S mutation — spans the FOLLOWING lines).
    # That line nets `opens - closes = 1` (the trailing `fn .. {` re-opens a brace
    # the line does not close). The pre-wave-20 `enter_test_module` detected the
    # degenerate close via the NET brace count (`opens - closes <= 0`), so the `<= 0`
    # branch was SKIPPED, the scanner stayed in_test_module at depth 1 and ABSORBED
    # the production fn body — hiding its Class-S mutation (a silent vacuum). The
    # positional `brace_close_pos(line, 0)` close now finds the module-closing `}`
    # even on a net-positive line, so this MUST emit an NTTEST HIT. Non-vacuity:
    # revert the positional entry-path close → no NTTEST (silent).
    {
        printf 'pub fn hole1_prod_before_fixture() {\n'
        printf '    persist_state_fail_closed(state, deps, ctx)?;\n'
        printf '}\n'
        printf '\n'
        printf '#[cfg(test)] mod hole1_degenerate_tests {} pub fn hole1_resumed_production() {\n'
        printf '    state.xctx_caller_reservations.insert(saga_id, record);\n'
        printf '    persist_state_best_effort(state, deps, ctx);\n'
        printf '}\n'
    } > "$fdir/hole1_degenerate_sameline.rs"

    # (56) WAVE-20 HOLE-2 — ATTRIBUTE-PREFIXED WHOLE-ITEM SINGLE-LINE RESUME. After
    # a test module closes, a production item resumes with a balanced leading
    # `#[rustfmt::skip]` attribute AND the whole item on ONE physical line. Two
    # shapes, both fmt-CLEAN (`#[rustfmt::skip]` PRESERVES hand-formatting, so the
    # one-line shape is left byte-for-byte unchanged and compiles):
    #   (56a) the resume on its OWN line after the module's `}` (after-module guard);
    #   (56b) the close-line TWIN — the resume SHARES the module-closing `}` line
    #         (`} #[rustfmt::skip] pub fn evil(){..}`).
    # Pre-wave-20, both `is_column0_code_line` and `is_production_remainder` excluded
    # any `^#[` line (they look PAST an attribute to a FOLLOWING line) and the whole
    # `#[attr] item` line is bracket-balanced (so it does NOT enter the multi-line
    # attr-carry) → silently swallowed. is_attr_prefixed_production peels the leading
    # attribute (reusing strip_leading_attr) so BOTH MUST emit an NTTEST HIT.
    # Non-vacuity: revert the attr-peel → no NTTEST (silent).
    {
        printf 'pub fn hole2a_prod_before_fixture() {\n'
        printf '    persist_state_fail_closed(state, deps, ctx)?;\n'
        printf '}\n'
        printf '\n'
        printf '#[cfg(test)]\n'
        printf 'mod hole2a_interspersed_tests {\n'
        printf '    fn a_test_helper() {}\n'
        printf '}\n'
        printf '\n'
        printf '#[rustfmt::skip] pub fn hole2a_evil() { state.xctx_caller_reservations.insert(saga_id, record); persist_state_best_effort(state, deps, ctx); }\n'
    } > "$fdir/hole2a_attr_prefixed_ownline.rs"
    {
        printf 'pub fn hole2b_prod_before_fixture() {\n'
        printf '    persist_state_fail_closed(state, deps, ctx)?;\n'
        printf '}\n'
        printf '\n'
        printf '#[cfg(test)]\n'
        printf 'mod hole2b_interspersed_tests {\n'
        printf '    fn a_test_helper() {}\n'
        printf '} #[rustfmt::skip] pub fn hole2b_evil(){ state.xctx_caller_reservations.insert(saga_id, record); persist_state_best_effort(state, deps, ctx); }\n'
    } > "$fdir/hole2b_attr_prefixed_closeline.rs"

    # (56c) CONTROL — a LEGITIMATE second `#[cfg(test)] mod more {}` after the first
    # test module MUST NOT emit an NTTEST HIT (is_attr_prefixed_production must
    # return 0 for a re-opening test gate). Guards against the attr-peel false-firing
    # on a legal second test module.
    {
        printf 'pub fn hole2c_prod_before_fixture() {\n'
        printf '    persist_state_fail_closed(state, deps, ctx)?;\n'
        printf '}\n'
        printf '\n'
        printf '#[cfg(test)]\n'
        printf 'mod hole2c_first_tests {\n'
        printf '    fn a_test_helper() {}\n'
        printf '}\n'
        printf '\n'
        printf '#[cfg(test)]\n'
        printf 'mod hole2c_more {}\n'
    } > "$fdir/hole2c_second_test_mod_control.rs"

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
    # (60) RECEIVER-ALIASED CEILING write (`rs.ceiling =` via a `&mut
    # state.role_state` alias, best-effort) MUST be caught by the receiver-
    # agnostic `.ceiling=` marker. PRE-fix the receiver-pinned `role_state.ceiling=`
    # marker missed it (the black-hat wave-23 bypass).
    if ! grep -q $'^HIT\t.*\taliased_ceiling_fixture$' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a receiver-aliased best-effort ceiling write\n' \
            "$C_RED" "$C_RESET" >&2
        printf '(`rs.ceiling =`) was NOT caught — the receiver-agnostic `.ceiling=` marker\n' >&2
        printf 'is not wired (the alias-evasion bypass is open).\n' >&2
        rc=1
    fi
    # (61) RECEIVER-ALIASED xctx_caller_reservations insert (`resv.insert(` via a
    # `&mut state.xctx_caller_reservations` alias, best-effort) MUST be caught by
    # the `&mut.xctx_caller_reservations` borrow companion. PRE-fix missed.
    if ! grep -q $'^HIT\t.*\taliased_xctx_reservation_fixture$' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a receiver-aliased best-effort xctx reservation insert\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'was NOT caught — the `&mut.xctx_caller_reservations` borrow companion is not\n' >&2
        printf 'wired (the mutable-alias borrow bypass is open).\n' >&2
        rc=1
    fi
    # (62) RECEIVER-ALIASED saga_pending insert MUST be caught by the
    # `&mut.saga_pending` borrow companion.
    if ! grep -q $'^HIT\t.*\taliased_saga_pending_fixture$' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a receiver-aliased best-effort saga_pending insert was\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'NOT caught — the `&mut.saga_pending` borrow companion is not wired.\n' >&2
        rc=1
    fi
    # (63) RECEIVER-ALIASED membership remove (`m.remove_member(` via a `&mut
    # state.membership` alias) MUST be caught by the `&mut.membership` borrow
    # companion (NOT a receiver-agnostic `.remove_member(`, which would collide
    # with the unrelated MLS `crypto.remove_member(`).
    if ! grep -q $'^HIT\t.*\taliased_membership_remove_fixture$' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a receiver-aliased best-effort membership removal was\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'NOT caught — the `&mut.membership` borrow companion is not wired.\n' >&2
        rc=1
    fi
    # (64) READ-ALIAS CONTROL: a SHARED `&state.membership` read alias MUST NOT be
    # flagged — `normalize_borrow` collapses only `&mut` (exclusive) borrows, so a
    # read accessor (`r.contains_key`) leaves no `&mut.membership` token. Guards
    # the read-vs-write precision the wave-23 markers require.
    if grep -q $'^HIT\t.*\tread_alias_membership_fixture$' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a SHARED (`&`, read-only) membership alias was wrongly\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'flagged — `normalize_borrow` is collapsing a read borrow as if it were `&mut`\n' >&2
        printf '(read accessors would be false-positived).\n' >&2
        rc=1
    fi
    # (65) RECEIVER-ALIASED xctx reservation insert that DOES fail-close MUST NOT
    # be flagged — the borrow companion must honour a fail-closed persist.
    if grep -q $'^HIT\t.*\taliased_xctx_reservation_fixed_fixture$' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a receiver-aliased reservation insert that DOES persist\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'fail-closed was wrongly flagged — the borrow companion ignored the persist.\n' >&2
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
    # (57) Attribute-prefixed regular fn (`#[rustfmt::skip] pub fn` on one line)
    # with a best-effort `suspend_all` mutation MUST be caught — the fn-detector
    # must peel the leading attribute and scan the body. (Pre-fix: silently
    # swallowed because the fn was unrecognised.)
    if ! grep -q $'^HIT\t.*\tskip_regular_fixture$' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: an attribute-prefixed (`#[rustfmt::skip] pub fn`)\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'function with a best-effort Class-S mutation was NOT caught — the fn-detector\n' >&2
        printf 'is not peeling a same-line leading attribute (fail-open: a mutation hides).\n' >&2
        rc=1
    fi
    # (58) Attribute-prefixed governance leaf (`#[rustfmt::skip] pub fn execute_*`
    # on one line) NOT in the allowlist MUST be caught (GOVHIT) — proves the
    # `execute_*` name is still extracted (for fail-closed-by-default) after the
    # leading attribute is peeled.
    if ! grep -q $'^GOVHIT\t.*\texecute_skip_gov_fixture$' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: an attribute-prefixed (`#[rustfmt::skip]`) governance\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'leaf was NOT caught — the `execute_*` name is lost when the fn-detector does\n' >&2
        printf 'not peel a same-line leading attribute (fail-open: a downward leaf hides).\n' >&2
        rc=1
    fi
    # (59) `pub extern "C" fn` with a best-effort mutation MUST be caught — the
    # fn-anchor must accept the extern "ABI" qualifier (not only pub/async).
    if ! grep -q $'^HIT\t.*\textern_abi_fixture$' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a `pub extern "C" fn` with a best-effort Class-S\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'mutation was NOT caught — the fn-detector anchor rejects the extern "ABI"\n' >&2
        printf 'qualifier (fail-open: an extern-fn mutation hides).\n' >&2
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
    # (32) TRAILING-NESTED-OPEN DEFLATION — a nested `/*` that is the last
    # comment-token on its line must deepen block_depth, or the comment surfaces
    # one `*/` early and the leaked `}` closes the body prematurely. The
    # best-effort Class-S mutation after the comment MUST be caught.
    if ! grep -q $'^HIT\t.*\tnested_comment_trailing_open_deflation_fixture$' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a Class-S mutation after a block comment whose nested\n' \
            "$C_RED" "$C_RESET" >&2
        printf '`/*` was the LAST token on its line was NOT caught — scan_block_comment did\n' >&2
        printf 'not count the trailing nested open, under-counted depth, and surfaced one\n' >&2
        printf '`*/` early, leaking a `}` that closed the body prematurely.\n' >&2
        rc=1
    fi
    # (33) TRAILING-NESTED-OPEN INFLATION — the same under-count leaking a `{`
    # must NOT inflate the poison fn so it swallows the SEPARATE later fn. The
    # best-effort mutation in the LATER (victim) fn MUST still be caught.
    if ! grep -q $'^HIT\t.*\tnested_comment_trailing_open_inflation_victim_fixture$' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a leaked `{` from an under-counted trailing nested\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'block-comment open blinded the rest of the file — the later (victim) fn was\n' >&2
        printf 'swallowed by an inflated body and its Class-S mutation went unscanned.\n' >&2
        rc=1
    fi
    # (34) CHAR-LITERAL UNICODE-ESCAPE BRACE — branch-completeness. The `}` inside
    # a `'\u{7d}'` char literal must be stripped (not leak and deflate the body),
    # so the best-effort mutation after it MUST be caught; and a `'\u{7b}'` `{` in
    # a CORRECTLY fail-closed fn MUST NOT be flagged (over-strip / inflation guard).
    if ! grep -q $'^HIT\t.*\tchar_unicode_escape_brace_deflation_fixture$' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a Class-S mutation after a `\\u{7d}` unicode-escape char\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'literal was NOT caught — the `}` codepoint inside the char literal leaked and\n' >&2
        printf 'closed the body prematurely.\n' >&2
        rc=1
    fi
    if grep -q $'^HIT\t.*\tchar_unicode_escape_brace_fail_closed_fixture$' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a CORRECTLY fail-closed fn carrying `\\u{7b}` / `\\u{7d}`\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'unicode-escape char literals was wrongly flagged — the strip over-stripped\n' >&2
        printf 'real code or a brace inside the char literal leaked.\n' >&2
        rc=1
    fi
    # (35) NON-TRAILING test module — a column-0 test gate followed by a column-0
    # production item MUST emit an NTTEST HIT (the un-scanned-vacuum guard).
    if ! grep -q $'^NTTEST\t.*/nontrailing_test_module\.rs\t' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a NON-trailing test module (a column-0 test gate\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'followed by a column-0 production item) was NOT flagged — the cutoff would\n' >&2
        printf 'skip the production region below it, an un-scanned vacuum.\n' >&2
        rc=1
    fi
    # (36) TRAILING test module — a legitimate trailing `#[cfg(test)]` mod with no
    # column-0 production item after it MUST NOT emit an NTTEST HIT (over-restriction
    # guard).
    if grep -q $'^NTTEST\t.*/trailing_test_module\.rs\t' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: an ordinary TRAILING test module was wrongly flagged\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'as non-trailing — the structural assertion is over-restrictive.\n' >&2
        rc=1
    fi
    # (37) INTERSPERSED single-item test gate (root-cause regression) — the
    # column-0 `#[cfg(any(test,..))] pub fn` must NOT cut off the scan: the
    # production Class-S mutation below it MUST still be caught …
    if ! grep -q $'^HIT\t.*\tprod_after_interspersed_gate_fixture$' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a production Class-S mutation BELOW a column-0\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'interspersed single-item test gate was NOT caught — the cutoff wrongly\n' >&2
        printf 'treated the single-item `#[cfg(testing)]` gate as a trailing-module cutoff\n' >&2
        printf 'and blinded the scanner (the wave-14 root-cause regression).\n' >&2
        rc=1
    fi
    # … and the single-item gate must NOT be reported as a non-trailing test module
    # (it gates an item, not a `mod`, so there is no cutoff to be non-trailing).
    if grep -q $'^NTTEST\t.*/interspersed_item_gate\.rs\t' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a column-0 interspersed single-item test gate was\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'wrongly flagged as a non-trailing test MODULE (it gates an item, not a mod).\n' >&2
        rc=1
    fi
    # (38) NON-TRAILING test module resuming with a column-0 `const fn` /
    # `unsafe fn` (wave-15) — the production region after a trailing test module
    # resumes with a bare `const fn` / `unsafe fn` (no `pub`), which the prior
    # NTTEST regex did not match. It MUST now emit an NTTEST HIT (the un-scanned
    # vacuum guard, hardened for the const/unsafe fn shapes).
    if ! grep -q $'^NTTEST\t.*/nontrailing_const_unsafe_fn\.rs\t' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a NON-trailing test module resuming with a column-0\n' \
            "$C_RED" "$C_RESET" >&2
        printf '`const fn` / `unsafe fn` was NOT flagged — the un-scanned-vacuum guard regex\n' >&2
        printf 'misses the const/unsafe fn item-start shapes.\n' >&2
        rc=1
    fi
    # (39) NON-TRAILING test module resuming with a column-0 NON-test `mod` (the
    # most material missed shape — re-opens an entire indented production region).
    # The convergent guard MUST flag it (the shared item-start classifier
    # recognises `mod`).
    if ! grep -q $'^NTTEST\t.*/nontrailing_mod_resume\.rs\t' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a NON-trailing test module resuming with a column-0\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'NON-test `mod resumed_prod {` was NOT flagged — the convergent vacuum guard\n' >&2
        printf 'misses a re-opened indented production region (the most material bypass).\n' >&2
        rc=1
    fi
    # (40) NON-TRAILING test module resuming with a column-0 `extern "C" fn`.
    if ! grep -q $'^NTTEST\t.*/nontrailing_extern_c_fn\.rs\t' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a NON-trailing test module resuming with a column-0\n' \
            "$C_RED" "$C_RESET" >&2
        printf '`extern "C" fn` was NOT flagged — the convergent guard misses the extern-ABI\n' >&2
        printf 'fn item-start shape.\n' >&2
        rc=1
    fi
    # (41) NON-TRAILING test module resuming with a column-0 item-producing MACRO
    # invocation `make_things!{}`.
    if ! grep -q $'^NTTEST\t.*/nontrailing_item_macro\.rs\t' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a NON-trailing test module resuming with a column-0\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'item-producing macro invocation `make_things!{}` was NOT flagged — the convergent\n' >&2
        printf 'guard misses the item-macro item-start shape.\n' >&2
        rc=1
    fi
    # (42) LEGITIMATE SECOND test module (over-restriction guard) — a file with two
    # `#[cfg(test)]`-gated test `mod`s must NOT raise NTTEST: the second module is
    # a legitimate test module, not a production resume.
    if grep -q $'^NTTEST\t.*/second_test_module\.rs\t' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a LEGITIMATE second `#[cfg(test)]` test module was wrongly\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'flagged as a non-trailing production resume — the convergent guard over-fires on\n' >&2
        printf 'multi-test-module files.\n' >&2
        rc=1
    fi
    # (43) NON-TRAILING test module resuming with a column-0 `unsafe impl` (a
    # QUALIFIED NON-`fn` item) whose body carries a Class-S mutation MUST emit an
    # NTTEST HIT. FAILS pre-FIX-1 (the qualifier run was wired only to `fn`, so
    # `unsafe impl` was unrecognised and the indented mutation an un-scanned
    # vacuum).
    if ! grep -q $'^NTTEST\t.*/nontrailing_unsafe_impl\.rs\t' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a NON-trailing test module resuming with a column-0\n' \
            "$C_RED" "$C_RESET" >&2
        printf '`unsafe impl` (a qualified NON-fn item) was NOT flagged — the item-start\n' >&2
        printf 'classifier wires the qualifier run only to `fn`, leaving a qualified non-fn\n' >&2
        printf 'item an un-scanned vacuum.\n' >&2
        rc=1
    fi
    # (44) NON-TRAILING test module resuming with a column-0 `unsafe trait` /
    # `const`-qualified non-`fn` item MUST emit an NTTEST HIT (further qualified
    # non-fn shapes). FAILS pre-FIX-1.
    if ! grep -q $'^NTTEST\t.*/nontrailing_qualified_nonfn\.rs\t' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a NON-trailing test module resuming with a column-0\n' \
            "$C_RED" "$C_RESET" >&2
        printf '`unsafe trait` (a qualified NON-fn item) was NOT flagged — the qualifier run\n' >&2
        printf 'does not generalise to non-fn item keywords.\n' >&2
        rc=1
    fi
    # (45) LEGITIMATE SECOND test module declared `pub(crate) mod` / `pub(in path)
    # mod` MUST NOT emit an NTTEST HIT. FAILS pre-FIX-2 (the second-module accept
    # used a narrower `^(pub )?mod` regex than `is_column0_item_start`'s `vis`
    # grammar, so a `pub(crate) mod` second test module fell through as a generic
    # item and false-fired NTTEST on legal Rust — a CI break).
    if grep -q $'^NTTEST\t.*/pubcrate_second_test_module\.rs\t' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a LEGITIMATE second test module declared `pub(crate) mod`\n' \
            "$C_RED" "$C_RESET" >&2
        printf '/ `pub(in path) mod` was wrongly flagged NTTEST — the second-module accept uses\n' >&2
        printf 'a narrower visibility grammar than the item-start classifier.\n' >&2
        rc=1
    fi
    # (46) NON-TRAILING test module resuming with a column-0 PATH-QUALIFIED item
    # macro `scp_testing::storage_conformance! { .. }` (wave-18 — the black-hat
    # gap). The classifier-free brace-depth reframe MUST flag the production resume
    # after the module closes, regardless of the path-macro spelling that the prior
    # single-ident macro branch could not match. This is the non-vacuity proof:
    # reverting the brace-depth logic makes this assertion fail (no HIT).
    if ! grep -q $'^NTTEST\t.*/nontrailing_path_macro\.rs\t' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a NON-trailing test module resuming with a column-0\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'PATH-QUALIFIED item macro `scp_testing::storage_conformance! {}` was NOT\n' >&2
        printf 'flagged — the un-scanned-vacuum guard misses the path-macro item-start shape\n' >&2
        printf '(the black-hat gap the wave-18 brace-depth reframe closes).\n' >&2
        rc=1
    fi
    # (47) GENUINELY-TRAILING test module with deeply-nested column-0-LOOKING body
    # content closing at EOF MUST NOT emit an NTTEST HIT — the brace-depth tracker
    # must follow the body to its real closing brace and not close the module
    # early on an inner construct (premature-close / over-restriction guard).
    if grep -q $'^NTTEST\t.*/trailing_nested_test_module\.rs\t' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a genuinely-trailing test module with a nested body was\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'wrongly flagged NTTEST — the brace-depth tracker closed the module early on an\n' >&2
        printf 'inner construct instead of following it to the real closing brace at EOF.\n' >&2
        rc=1
    fi
    # (48) NON-TRAILING test module followed ONLY by comments / blank lines then
    # EOF MUST NOT emit an NTTEST HIT — comments and blanks are not production
    # content, so the guard must stay silent (only a real item triggers NTTEST).
    if grep -q $'^NTTEST\t.*/comments_after_close\.rs\t' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a test module followed only by comments / blank lines was\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'wrongly flagged NTTEST — trailing commentary was mistaken for a production\n' >&2
        printf 'resume (a `//`/`/* */` comment must strip to non-content).\n' >&2
        rc=1
    fi
    # (49) GAP-1 close-line production resume — a test module whose closing `}`
    # SHARES a physical line with a production fn MUST emit an NTTEST HIT (the
    # positional module-close + remainder re-eval). FAILS pre-wave-19 (the net
    # brace count kept the balanced closing line looking un-closed / the bare
    # `next` dropped the same-line production).
    if ! grep -q $'^NTTEST\t.*/gap1_closeline_resume\.rs\t' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a NON-trailing test module whose closing `}` shares a\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'physical line with a production fn was NOT flagged — the module-close is not\n' >&2
        printf 'found positionally, so same-line production is a silent un-scanned vacuum.\n' >&2
        rc=1
    fi
    # (50) GAP-1 multi-line-attribute-closer production resume — a production fn
    # decorated by a multi-line attribute whose `)]` closer shares its physical
    # line, after a trailing test module, MUST emit an NTTEST HIT. FAILS pre-wave-19
    # (the attr-carry close branch dropped the post-`)]` production region).
    if ! grep -q $'^NTTEST\t.*/gap1_attrcloser_resume\.rs\t' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a production fn whose multi-line-attribute `)]` closer\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'shares a physical line, resuming after a trailing test module, was NOT flagged\n' >&2
        printf '— the attr-carry close drops the same-line production after the closer.\n' >&2
        rc=1
    fi
    # (51) GAP-2 same-line gate+mod, TRAILING — a `#[cfg(test)] mod NAME { .. }` on
    # ONE physical line, closing at EOF, MUST NOT emit an NTTEST HIT and its
    # test-only body MUST NOT be scanned as production. FAILS pre-wave-19 (the
    # same-line `mod {` fell into the production scanner; the test body was
    # FALSE-flagged). Assert both: no NTTEST on the file …
    if grep -q $'^NTTEST\t.*/gap2_sameline_trailing\.rs\t' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a TRAILING same-line `#[cfg(test)] mod NAME { .. }` was\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'wrongly flagged NTTEST — the same-line gate+mod was not recognised as a module.\n' >&2
        rc=1
    fi
    # … and no (false) HIT on the test-only mutation in its body. This is the
    # load-bearing non-vacuity check: revert the same-line gate+mod recognition and
    # `sameline_trailing_test_body` is scanned as production and HITs.
    if grep -q $'^HIT\t.*\tsameline_trailing_test_body$' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: the test-only Class-S mutation inside a same-line\n' \
            "$C_RED" "$C_RESET" >&2
        printf '`#[cfg(test)] mod { .. }` body was wrongly scanned as production and flagged.\n' >&2
        rc=1
    fi
    # (52) GAP-2 same-line gate+mod, NON-TRAILING — a same-line gate+mod FOLLOWED by
    # a column-0 production fn MUST emit an NTTEST HIT (the production resume after
    # the recognised module is an un-scanned vacuum).
    if ! grep -q $'^NTTEST\t.*/gap2_sameline_nontrailing\.rs\t' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a same-line `#[cfg(test)] mod NAME { .. }` FOLLOWED by a\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'column-0 production fn was NOT flagged — the post-module production vacuum was\n' >&2
        printf 'missed (the same-line module entry must still arm the after-module guard).\n' >&2
        rc=1
    fi
    # (53) GAP-3 multi-line test-cfg gate, TRAILING — a `#[cfg(all(test,\n
    # feature="x"\n))]` gate split across lines then a `mod`, closing at EOF, MUST
    # NOT emit an NTTEST HIT and its test body MUST NOT be scanned. FAILS pre-wave-19
    # (the multi-line gate was an opaque attribute, the `mod` scanned as production).
    if grep -q $'^NTTEST\t.*/gap3_multiline_cfg_gate\.rs\t' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a TRAILING multi-line `#[cfg(all(test,..))]` gate was\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'wrongly flagged NTTEST — the multi-line test-cfg gate was not recognised.\n' >&2
        rc=1
    fi
    # The test body fn (`multiline_cfg_test_body`) carries a Class-S mutation; if
    # the multi-line gate is not recognised, that fn is scanned as production and
    # HITs. Assert it does NOT (this is the load-bearing non-vacuity check: revert
    # the multi-line test-cfg recognition and this fn HITs).
    if grep -q $'^HIT\t.*\tmultiline_cfg_test_body$' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: the test-only Class-S mutation inside a multi-line\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'test-cfg-gated `mod { .. }` body was wrongly scanned as production and flagged.\n' >&2
        rc=1
    fi
    # (54) NIT-1 — a multi-line NON-test `#[allow(..)]` whose `)]` closer sits at
    # column 0 between a `#[cfg(test)]` gate and the `mod tests` it decorates MUST
    # NOT emit an NTTEST HIT (the `)]` must not be read as interspersed production).
    # This exercises the `attr_bracket_depth` multi-line carry on a column-0 `)]`.
    if grep -q $'^NTTEST\t.*/attr_carry_trailing\.rs\t' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a column-0 multi-line-attribute `)]` closer before a\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'trailing test module was wrongly read as interspersed production (NTTEST) —\n' >&2
        printf 'the attr-carry did not keep the multi-line attribute transparent.\n' >&2
        rc=1
    fi
    # (55) WAVE-20 HOLE-1 — a degenerate `#[cfg(test)] mod x {}` + same-line
    # production fn (which re-opens a brace) MUST emit an NTTEST HIT. FAILS
    # pre-wave-20 (the NET brace count kept the module looking un-closed, absorbing
    # the production fn body — a silent vacuum). Non-vacuity: revert the positional
    # entry-path close → no NTTEST.
    if ! grep -q $'^NTTEST\t.*/hole1_degenerate_sameline\.rs\t' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a degenerate `#[cfg(test)] mod x {}` followed on the SAME\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'line by a production fn was NOT flagged — enter_test_module detected the\n' >&2
        printf 'degenerate close by NET brace count, not positionally, so the trailing\n' >&2
        printf 'production fn body was absorbed as test code (a silent un-scanned vacuum).\n' >&2
        rc=1
    fi
    # (56a) WAVE-20 HOLE-2 — an attribute-prefixed whole-item resume on its OWN line
    # after a test module (`#[rustfmt::skip] pub fn evil() { .. }`) MUST emit an
    # NTTEST HIT. FAILS pre-wave-20 (is_column0_code_line excluded the `^#[` line and
    # the balanced `#[attr] item` line did not enter the attr-carry → swallowed).
    if ! grep -q $'^NTTEST\t.*/hole2a_attr_prefixed_ownline\.rs\t' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: an attribute-prefixed (`#[rustfmt::skip]`) whole-item\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'production resume on its own line after a test module was NOT flagged — the\n' >&2
        printf 'after-module guard did not peel the leading attribute (is_attr_prefixed_\n' >&2
        printf 'production), so a fmt-clean attribute-prefixed resume is a silent vacuum.\n' >&2
        rc=1
    fi
    # (56b) WAVE-20 HOLE-2 close-line TWIN — the same attribute-prefixed whole-item
    # resume SHARING the module-closing `}` line (`} #[rustfmt::skip] pub fn
    # evil(){..}`) MUST emit an NTTEST HIT. FAILS pre-wave-20 (is_production_remainder
    # on the post-`}` remainder saw the leading `#[` and returned 0).
    if ! grep -q $'^NTTEST\t.*/hole2b_attr_prefixed_closeline\.rs\t' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: an attribute-prefixed whole-item resume SHARING the\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'module-closing `}` line was NOT flagged — the close-line remainder re-eval\n' >&2
        printf 'did not peel the leading attribute (is_attr_prefixed_production).\n' >&2
        rc=1
    fi
    # (56c) WAVE-20 HOLE-2 CONTROL — a LEGITIMATE second `#[cfg(test)] mod more {}`
    # after the first test module MUST NOT emit an NTTEST HIT (the attr-peel must
    # return 0 for a re-opening test gate — no false positive on legal Rust).
    if grep -q $'^NTTEST\t.*/hole2c_second_test_mod_control\.rs\t' <<< "$out"; then
        printf '%sSELF-TEST FAILED%s: a legitimate second `#[cfg(test)] mod` after the first\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'test module was wrongly flagged NTTEST — is_attr_prefixed_production false-\n' >&2
        printf 'fired on a re-opening test gate instead of returning 0.\n' >&2
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
