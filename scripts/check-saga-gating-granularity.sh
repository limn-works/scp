#!/usr/bin/env bash
# check-saga-gating-granularity.sh — CI gate enforcing ADR-049 §3a's
# per-participant-context-set saga concurrency GRANULARITY.
#
# ---------------------------------------------------------------------------
# WHY THIS EXISTS
# ---------------------------------------------------------------------------
# ADR-049 §3a (and spec §5.15.4) require that cross-context sagas serialize at
# the granularity of their PARTICIPANT CONTEXT SET, not supervisor-wide. A saga
# reserves the set of context-actors it spans; two sagas with DISJOINT sets run
# concurrently, and only an OVERLAP (a shared context) yields a typed SagaBusy.
# A single instance-wide guard (the as-built `AtomicBool`) lets one slow or
# stuck saga DoS every unrelated saga in the instance — and §3a's
# block-until-terminal FFI saga surface would expose that wedge to every
# binding. §3a therefore makes per-set gating a HARD, mechanically-enforced
# prerequisite for the `start_*_saga` FFI exports.
#
# This gate is a GRANULARITY TRIPWIRE. It is NOT a proof of correctness and it
# is NOT un-launderable: a sufficiently creative instance-wide wedge (an
# obscure field name AND an obscure scalar type the lists below do not name)
# could still slip past the negative scan. What it DOES do is (a) resist the
# COMMON rename/retype laundering of an instance-wide guard
# (`AtomicBool` → `Mutex<()>` → `Semaphore(1)` → a single `bool`/`u8`/count
# field, under any of the usual saga/inflight/pending/busy/gate/guard field
# names), and (b) POSITIVELY assert that the per-set reservation machinery is
# present and wired (the `reserved_saga_contexts` store, the
# `saga_participant_context_set` extractor, and an overlap-reject INSIDE
# `try_reserve_context_set` that `start_saga` actually CALLS). The SEMANTIC
# proof — disjoint sets run concurrently, an overlapping set is rejected
# SagaBusy, the reservation key is the canonical raw digest, and NeedsRepair
# releases the slot — lives in the `actor_saga_concurrent.rs` integration tests
# that CI runs; this gate additionally asserts those proving test functions
# exist by name so they cannot be silently deleted.
#
# ---------------------------------------------------------------------------
# WHAT THIS CHECKS (on crates/scp-runtime/src/context/supervisor/supervisor.rs)
# ---------------------------------------------------------------------------
# NEGATIVE assertion — FAIL if a saga-concurrency `Supervisor` field of an
#   instance-wide SCALAR type exists. Match the product of
#   "saga-concurrency field name" × "instance-wide scalar type". The NAME match
#   is widened beyond `saga*` to every plausible saga-concurrency field name
#   (`saga`/`inflight`/`in_flight`/`pending`/`busy`/`gate`/`guard`), and the
#   TYPE match is widened to every instance-wide scalar wedge:
#       (saga|inflight|in_flight|pending|busy|gate|guard)[_a-z0-9]* : ...
#         (Atomic(Bool|U8|U16|U32|U64|Usize|I8|I16|I32|I64|Isize)|Semaphore
#          |Mutex<()>|Mutex<bool>|Mutex<u8>|Mutex<u16>|Mutex<u32>
#          |Mutex<u64>|Mutex<usize>)
#   A field whose NAME is one of those AND whose TYPE is one of those
#   instance-wide scalars is exactly the wedge §3a forbids. The match is kept
#   NAME-scoped (not a blanket type-ban) so a LEGIT non-saga Supervisor field of
#   one of these types — e.g. `spawn_generation: AtomicU64` — is not flagged.
#   `Mutex<HashSet<...>>` (the per-set reservation) is NOT a scalar and is
#   deliberately allowed.
#
# POSITIVE assertions — FAIL if ANY of these is ABSENT (so deleting the guard
#   entirely, i.e. NO gating, also fails — per-set gating must be PRESENT):
#     (P1) the `reserved_saga_contexts` HashSet field (the per-set reservation
#          store);
#     (P2) the `saga_participant_context_set` extractor (computes the set a
#          saga reserves);
#     (P3) the overlap-reject: a `.contains(` membership check AND a typed
#          `SagaBusy`/`ActorBusy` error AND a real early-return `return Err(`,
#          all in CODE (not comments) INSIDE `fn try_reserve_context_set` (not
#          merely somewhere in the file). `//`-comment tails are stripped before
#          matching, so a gutted reject whose busy tokens survive only in an
#          explanatory comment (with the real reject replaced by a discarded
#          binding like `let _ = contended;`) does NOT satisfy P3;
#     (P4) `try_reserve_context_set` is CALLED in `fn start_saga` (the gate is
#          on the start path, not dead code);
#     (P5) `saga_participant_context_set` does NOT emit a `"standing-"`-prefixed
#          literal into the reserved set (catches a FIX-1 regression that would
#          reserve the display id instead of the canonical raw digest);
#     (P6) the proving integration-test functions exist by name in
#          `actor_saga_concurrent.rs` (the semantic proof CI runs).
#
# FFI ORDERING clause — if any `start_*_saga` export exists anywhere under
#   `crates/scp-ffi/`, the NEGATIVE assertion MUST pass (no instance-wide saga
#   guard may coexist with a shipped FFI saga surface). The §6.2.4 cross-context
#   tool saga (`tool_invoke_cross_context_saga`, which drives
#   `Supervisor::start_cross_context_tool_invocation_saga`) is now exported across
#   all three FFI bridges, so this clause is currently LOAD-BEARING — not a
#   vacuous pass.
#
# ---------------------------------------------------------------------------
# HOW TO FIX A FAILURE
# ---------------------------------------------------------------------------
# - Negative hit: you reintroduced an instance-wide saga guard. Replace it with
#   per-participant-context-set reservation (reserve the saga's whole context
#   set; reject only on overlap). See `Supervisor::try_reserve_context_set`.
# - Positive miss: the per-set gating was removed or renamed. Restore the
#   `reserved_saga_contexts` set, the `saga_participant_context_set` extractor,
#   and the overlap-reject. Do NOT weaken this gate — fix the code.
#
# This script is in the CLAUDE.md NEVER-WEAKEN enforcement list. The only
# legitimate edits are ADDITIVE (new assertions / wider coverage).
#
# ---------------------------------------------------------------------------
# PORTABILITY
# ---------------------------------------------------------------------------
# Runs on macOS (BSD userland) and Linux (GNU userland). POSIX bash + grep +
# find only. No ripgrep, no GNU-specific flags.
#
# Usage:
#   bash scripts/check-saga-gating-granularity.sh            # real check
#   bash scripts/check-saga-gating-granularity.sh --self-test # prove it's alive
# Exit codes:
#   0  — granularity correct (per-set gating present, no instance-wide guard)
#   1  — a negative hit, a positive miss, or a self-test failure
#   2  — invocation error (target file missing)

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

SUPERVISOR_REL="crates/scp-runtime/src/context/supervisor/supervisor.rs"
FFI_DIR="crates/scp-ffi"
TESTS_REL="crates/scp-runtime/tests/actor_saga_concurrent.rs"

# ---------------------------------------------------------------------------
# Instance-wide scalar saga-guard regex (the NEGATIVE pattern). A field whose
# NAME is a plausible saga-concurrency guard name and whose TYPE is an
# instance-wide scalar guard.
#
#   (saga|inflight|in_flight|pending|busy|gate|guard)[_a-z0-9]*
#                     — a field name that is, or begins with, one of the usual
#                       saga-concurrency guard names
#   [[:space:]]*:     — the field's `:` type separator
#   .*                — any qualified path before the type
#   (Atomic(Bool|U8|U16|U32|U64|Usize|I8|I16|I32|I64|Isize)|Semaphore
#    |Mutex<\(\)>|Mutex<bool>|Mutex<u8>|Mutex<u16>|Mutex<u32>|Mutex<u64>
#    |Mutex<usize>)
#                     — the instance-wide scalar guard types: any small atomic
#                       (signed OR unsigned), a Semaphore, or a Mutex over a
#                       unit / bool / small unsigned scalar.
#
# `Mutex<HashSet<...>>` (the per-set reservation) is NOT a scalar and is
# deliberately allowed. The name scoping keeps a LEGIT non-saga field of one of
# these scalar types (e.g. `spawn_generation: AtomicU64`) from being flagged.
# Uses a POSIX ERE (grep -E); `<`, `>`, `(`, `)` are escaped where they must be
# literal.
# ---------------------------------------------------------------------------
NEG_NAME='(saga|inflight|in_flight|pending|busy|gate|guard)[_a-z0-9]*'
NEG_TYPE='(Atomic(Bool|U8|U16|U32|U64|Usize|I8|I16|I32|I64|Isize)|Semaphore|Mutex<\(\)>|Mutex<bool>|Mutex<u8>|Mutex<u16>|Mutex<u32>|Mutex<u64>|Mutex<usize>)'
NEG_PATTERN="${NEG_NAME}[[:space:]]*:[[:space:]]*.*${NEG_TYPE}"

# ---------------------------------------------------------------------------
# scan_negative <file> — print each line in <file> that declares an
# instance-wide scalar saga guard (a NEGATIVE hit). Comments are NOT stripped
# here on purpose: a doc-comment that merely MENTIONS `AtomicBool` would be a
# false positive, so we additionally require the line to look like a FIELD
# DECLARATION (contains a `:` type separator and is not a `//`/`///` comment
# line). We strip line-comment tails first so a trailing `// ... AtomicBool`
# note cannot trip the gate, then match the negative pattern on the code part.
# ---------------------------------------------------------------------------
scan_negative() {
    local file="$1"
    awk -v PAT="$NEG_PATTERN" '
    {
        line = $0
        # Drop a //-comment tail so a code-free mention in a trailing comment
        # is not matched. (Block comments spanning the field are not a concern:
        # a field declaration is live code, not inside /* */.)
        sub(/\/\/.*$/, "", line)
        # Skip pure-comment / doc-comment lines outright.
        stripped = line
        sub(/^[[:space:]]+/, "", stripped)
        if (stripped ~ /^\/?\*/ || stripped == "") next
        if (line ~ PAT) {
            t = line
            sub(/^[[:space:]]+/, "", t)
            sub(/[[:space:]]+$/, "", t)
            printf("NEGHIT\t%d\t%s\n", NR, t)
        }
    }
    ' "$file"
}

# ---------------------------------------------------------------------------
# has_token <file> <fixed-string> — 0 if present, 1 if absent. Plain
# fixed-string search (grep -F) so regex metachars in the token are literal.
# ---------------------------------------------------------------------------
has_token() {
    grep -Fq -- "$2" "$1"
}

# ---------------------------------------------------------------------------
# fn_body <file> <fn-name> — print the body of the FIRST `fn <fn-name>(` in
# <file>, from the opening `{` to its matching `}`, by brace-depth counting.
# Rust string/char literals can technically contain unbalanced braces; the
# saga functions this gate inspects do not, so a plain brace count is
# sufficient (and the gate is a tripwire, not a parser). Emits nothing if the
# function is absent.
# ---------------------------------------------------------------------------
fn_body() {
    local file="$1" fn="$2"
    awk -v FN="fn ${fn}(" '
    BEGIN { found = 0; depth = 0; started = 0 }
    {
        if (!found && index($0, FN) > 0) { found = 1 }
        if (found) {
            line = $0
            n = length(line)
            for (i = 1; i <= n; i++) {
                c = substr(line, i, 1)
                if (c == "{") { depth++; started = 1 }
                else if (c == "}") { depth-- }
            }
            print line
            if (started && depth <= 0) { exit }
        }
    }
    ' "$file"
}

# ---------------------------------------------------------------------------
# has_overlap_reject_in_reserve <file> — 0 if the overlap-reject lives INSIDE
# `fn try_reserve_context_set`: a `.contains(` membership check AND a typed
# `SagaBusy`/`ActorBusy` rejection AND a real early-return `return Err(`, all
# within that function's body, all in CODE (P3). This is stricter than
# "somewhere in the file": it pins the reject to the reservation critical
# section. Before matching the tokens, `//`-comment tails are STRIPPED from the
# body so a gutted reject whose busy tokens survive only in an explanatory
# comment (e.g. `let _ = contended; // would be SagaBusy/ActorBusy`) does NOT
# count — the tokens must appear in live code. The additional `return Err(`
# requirement ensures a real early-return reject, not a discarded binding.
# Returns 0 (present) or 1 (absent).
# ---------------------------------------------------------------------------
has_overlap_reject_in_reserve() {
    local file="$1" body code
    body="$(fn_body "$file" 'try_reserve_context_set')"
    [[ -n "$body" ]] || return 1
    # Strip //-comment tails so tokens that appear ONLY in comments do not count
    # (a gutted reject with explanatory-comment-only tokens must NOT pass).
    code="$(printf '%s' "$body" | sed 's://.*$::')"
    printf '%s' "$code" | grep -Fq -- '.contains(' || return 1
    printf '%s' "$code" | grep -Fq -- 'SagaBusy' || return 1
    printf '%s' "$code" | grep -Fq -- 'ActorBusy' || return 1
    # The reject must be a real early-return, not a discarded binding.
    printf '%s' "$code" | grep -Eq -- 'return[[:space:]]+Err\(' || return 1
    return 0
}

# ---------------------------------------------------------------------------
# start_saga_calls_reserve <file> — 0 if `fn start_saga`'s body CALLS
# `try_reserve_context_set(` (P4): the per-set gating is on the start path, not
# dead code. Returns 0 (present) or 1 (absent).
# ---------------------------------------------------------------------------
start_saga_calls_reserve() {
    local file="$1" body
    body="$(fn_body "$file" 'start_saga')"
    [[ -n "$body" ]] || return 1
    printf '%s' "$body" | grep -Fq -- 'try_reserve_context_set(' || return 1
    return 0
}

# ---------------------------------------------------------------------------
# extractor_has_no_standing_prefix <file> — 0 if `fn saga_participant_context_set`
# does NOT emit a `"standing-"`-prefixed literal into the reserved set (P5).
# A FIX-1 regression would reserve the `"standing-"`-prefixed DISPLAY id instead
# of the canonical raw-digest hex, so a `"standing-"` string literal (or a call
# to `generate_standing_context_id`, which produces that prefix) appearing in
# the extractor body is the tell. Returns 0 (clean) or 1 (regression present).
# ---------------------------------------------------------------------------
extractor_has_no_standing_prefix() {
    local file="$1" body
    body="$(fn_body "$file" 'saga_participant_context_set')"
    # Absence of the function is a SEPARATE failure (P2); treat a missing body
    # as "clean" here so P5 does not double-count it.
    [[ -n "$body" ]] || return 0
    if printf '%s' "$body" | grep -Eq -- '"standing-|generate_standing_context_id'; then
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# tests_present <test-file> — 0 if ALL the proving integration-test functions
# exist by name in <test-file> (P6). These carry the SEMANTIC proof (disjoint
# concurrent, overlap busy, cross-type set-membership, NeedsRepair release)
# that CI runs; this gate asserts they cannot be silently deleted. Returns 0
# (all present) or 1 (any absent / file missing).
# ---------------------------------------------------------------------------
PROVING_TESTS=(
    'disjoint_participant_sets_run_concurrently'
    'overlapping_participant_sets_reject_busy'
    'overlap_is_set_membership_across_saga_types'
    'needs_repair_releases_reservation'
)
tests_present() {
    local file="$1" t
    [[ -f "$file" ]] || return 1
    for t in "${PROVING_TESTS[@]}"; do
        grep -Eq -- "fn[[:space:]]+${t}[[:space:]]*\(" "$file" || return 1
    done
    return 0
}

# ---------------------------------------------------------------------------
# ffi_has_saga_export <dir> — 0 if any `start_*_saga` export exists under the
# FFI dir, 1 otherwise. Matches `start_<anything>_saga` as a function-ish
# identifier (fn / pub fn / #[uniffi] export / napi). The match is on the
# IDENTIFIER token, so a doc reference also counts — conservative by design
# (the FFI clause only TIGHTENS the negative assertion).
# ---------------------------------------------------------------------------
ffi_has_saga_export() {
    local dir="$1"
    [[ -d "$dir" ]] || return 1
    # `start_*_saga` identifier anywhere under the FFI tree.
    if grep -REq -- 'start_[A-Za-z0-9_]*_saga' "$dir" --include='*.rs' 2>/dev/null; then
        return 0
    fi
    return 1
}

# ---------------------------------------------------------------------------
# run_check <supervisor-file> <ffi-dir> <label> — run the full granularity
# evaluation against the given target. Returns 0 PASS, 1 FAIL. Factored so the
# self-test can drive it against synthetic fixtures.
# ---------------------------------------------------------------------------
run_check() {
    local sup="$1"
    local ffi_dir="$2"
    local label="${3:-check}"
    local testfile="${4:-$TESTS_REL}"

    if [[ ! -f "$sup" ]]; then
        printf '%serror:%s supervisor file %s does not exist\n' \
            "$C_RED" "$C_RESET" "$sup" >&2
        return 2
    fi

    local fail=0

    printf '\n%ssaga-gating granularity %s:%s %s\n' \
        "$C_DIM" "$label" "$C_RESET" "$sup"

    # --- NEGATIVE: no instance-wide scalar saga guard -----------------------
    local neg
    neg="$(scan_negative "$sup" || true)"
    if [[ -n "$neg" ]]; then
        printf '\n%sFAILED (negative)%s: an instance-wide scalar saga-concurrency guard\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'is present. ADR-049 §3a forbids supervisor-wide saga gating of ANY\n' >&2
        printf 'scalar type — one stuck saga must not wedge unrelated, disjoint sagas.\n' >&2
        printf 'Use per-participant-context-set reservation instead.\n' >&2
        while IFS=$'\t' read -r tag ln txt; do
            [[ "$tag" == "NEGHIT" ]] || continue
            printf '      %s%s:%s%s  %s%s%s\n' \
                "$C_DIM" "$sup" "$ln" "$C_RESET" "$C_YELLOW" "$txt" "$C_RESET" >&2
        done <<< "$neg"
        fail=1
    fi

    # --- FFI ORDERING clause -----------------------------------------------
    # If any start_*_saga FFI export exists, the negative assertion MUST pass.
    # (When it does pass, `fail` is already 0 from the negative block; this
    # clause re-states the dependency and fails loudly if a guard coexists with
    # an FFI saga export.)
    if ffi_has_saga_export "$ffi_dir"; then
        if [[ -n "$neg" ]]; then
            printf '\n%sFAILED (FFI ordering)%s: a start_*_saga FFI export exists while an\n' \
                "$C_RED" "$C_RESET" >&2
            printf 'instance-wide saga guard is still present. §3a: the FFI saga surface\n' >&2
            printf 'MUST NOT ship until per-set gating replaces the instance-wide guard.\n' >&2
            fail=1
        else
            printf '%s  note:%s start_*_saga FFI export present; negative assertion is\n' \
                "$C_DIM" "$C_RESET"
            printf '%s       %s load-bearing and passes (no instance-wide guard).\n' \
                "$C_DIM" "$C_RESET"
        fi
    else
        printf '%s  note:%s no start_*_saga FFI export yet — FFI ordering clause armed\n' \
            "$C_DIM" "$C_RESET"
        printf '%s       %s (vacuous pass; prerequisite enforced the moment one lands).\n' \
            "$C_DIM" "$C_RESET"
    fi

    # --- POSITIVE: per-set gating must be PRESENT ---------------------------
    if ! has_token "$sup" 'reserved_saga_contexts'; then
        printf '\n%sFAILED (positive P1)%s: the `reserved_saga_contexts` HashSet field is\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'absent. Per-set gating must be PRESENT — removing the guard entirely\n' >&2
        printf '(no gating) is also a failure. Restore the per-set reservation store.\n' >&2
        fail=1
    fi
    if ! has_token "$sup" 'saga_participant_context_set'; then
        printf '\n%sFAILED (positive P2)%s: the `saga_participant_context_set` extractor\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'is absent. The reservation must reason over a saga'\''s participant CONTEXT\n' >&2
        printf 'SET (so disjoint sets run concurrently). Restore the extractor.\n' >&2
        fail=1
    fi
    if ! has_overlap_reject_in_reserve "$sup"; then
        printf '\n%sFAILED (positive P3)%s: the overlap-reject is absent from\n' \
            "$C_RED" "$C_RESET" >&2
        printf '`fn try_reserve_context_set`. The reservation critical section must\n' >&2
        printf 'reject an OVERLAPPING set with a typed SagaBusy/ActorBusy error via a\n' >&2
        printf '`.contains(` membership check AND a real early-return `return Err(` — all\n' >&2
        printf 'in live CODE, not just comments. Restore the overlap rejection there.\n' >&2
        fail=1
    fi
    if ! start_saga_calls_reserve "$sup"; then
        printf '\n%sFAILED (positive P4)%s: `fn start_saga` does not CALL\n' \
            "$C_RED" "$C_RESET" >&2
        printf '`try_reserve_context_set(`. Per-set gating must be on the start path,\n' >&2
        printf 'not dead code. Reserve the participant context set in `start_saga`.\n' >&2
        fail=1
    fi
    if ! extractor_has_no_standing_prefix "$sup"; then
        printf '\n%sFAILED (positive P5)%s: `fn saga_participant_context_set` emits a\n' \
            "$C_RED" "$C_RESET" >&2
        printf '`"standing-"`-prefixed literal (or calls `generate_standing_context_id`)\n' >&2
        printf 'into the reserved set. Standing-pair creation must reserve the CANONICAL\n' >&2
        printf 'raw-digest hex (`derive_standing_context_digest`), not the prefixed\n' >&2
        printf 'display id, or it cannot overlap the cross-context tool saga (§6.2.4) over the\n' >&2
        printf 'same standing context (spec §5.15.8). Reserve the raw digest.\n' >&2
        fail=1
    fi
    if ! tests_present "$testfile"; then
        printf '\n%sFAILED (positive P6)%s: a proving integration test is missing from\n' \
            "$C_RED" "$C_RESET" >&2
        printf '%s. The semantic proof (disjoint-concurrent, overlap-busy,\n' "$testfile" >&2
        printf 'cross-type set-membership, NeedsRepair-release) must exist by name:\n' >&2
        printf '  %s\n' "${PROVING_TESTS[*]}" >&2
        fail=1
    fi

    return "$fail"
}

# ---------------------------------------------------------------------------
# SELF-TEST — before trusting the gate on real code, prove it is not dead.
# Build synthetic supervisor fixtures and assert the gate:
#   (a) FAILS on an `saga*: AtomicBool` guard + a fake FFI start_*_saga export
#       (negative hit + FFI ordering),
#   (b) PASSES on the HashSet field + extractor + in-reserve overlap-reject +
#       start_saga-calls-reserve + raw-digest key + proving tests, with NO
#       instance-wide guard,
#   (c) FAILS when the guard is deleted and NO per-set reservation exists
#       (positive miss — absence-only must not pass),
#   (d) FAILS on an `inflight_guard: AtomicBool` (the NEG name-prefix bypass:
#       a non-`saga*`-named instance-wide wedge),
#   (e) FAILS on a `saga_x: Mutex<u8>` (the NEG type-list bypass: a small-scalar
#       Mutex instance-wide wedge).
#   (f) FAILS on a `saga_x: AtomicI64` (the NEG signed-atomic bypass: a SIGNED
#       atomic instance-wide wedge — same wedge as AtomicU64, just signed).
#   (g) FAILS on a supervisor whose `try_reserve_context_set` reject is GUTTED to
#       a discarded binding (`let _ = contended;`) with the busy tokens
#       (`SagaBusy`/`ActorBusy`) and the membership reasoning surviving ONLY in a
#       `//` comment (the P3 comment-only / no-real-`return Err` bypass). The
#       comment-strip + `return Err(` requirement must catch this.
# ---------------------------------------------------------------------------
self_test() {
    local fixt rc=0
    fixt="$(mktemp -d)"

    # A valid proving-test fixture so the P6 assertion passes for the fixtures
    # that are SUPPOSED to pass (b) — and so the FAIL fixtures fail on THEIR
    # intended assertion, not on a missing test file.
    local tests_ok="$fixt/tests_ok.rs"
    {
        printf '#[tokio::test] async fn disjoint_participant_sets_run_concurrently() {}\n'
        printf '#[tokio::test] async fn overlapping_participant_sets_reject_busy() {}\n'
        printf '#[tokio::test] async fn overlap_is_set_membership_across_saga_types() {}\n'
        printf '#[tokio::test] async fn needs_repair_releases_reservation() {}\n'
    } > "$tests_ok"

    # emit_good_supervisor <path> — a supervisor that satisfies EVERY positive
    # assertion (P1 store, P2 extractor, P3 reject-in-reserve, P4 start_saga
    # calls reserve, P5 raw-digest key / no "standing-" literal). The FAIL
    # fixtures start from this and inject exactly ONE defect so the self-test
    # proves the SPECIFIC assertion under test, not an incidental miss.
    emit_good_supervisor() {
        local path="$1"
        {
            printf 'struct Supervisor {\n'
            printf '    // The per-set reservation store (NOT an instance-wide scalar).\n'
            printf '    reserved_saga_contexts: std::sync::Mutex<HashSet<String>>,\n'
            printf '    spawn_generation: std::sync::atomic::AtomicU64,\n'
            printf '}\n'
            printf 'fn saga_participant_context_set(input: &SagaInput) -> Vec<String> {\n'
            printf '    vec![hex::encode(derive_standing_context_digest(a, b))]\n'
            printf '}\n'
            printf 'fn try_reserve_context_set(&self, set: &[String]) -> Result<R, E> {\n'
            printf '    if set.iter().find(|id| reserved.contains(*id)).is_some() {\n'
            printf '        return Err(ContextError::ActorBusy("... SagaBusy".into()));\n'
            printf '    }\n'
            printf '    Ok(reservation)\n'
            printf '}\n'
            printf 'pub async fn start_saga(&self, input: SagaInput) -> Result<O, E> {\n'
            printf '    let set = saga_participant_context_set(&input);\n'
            printf '    let _r = self.try_reserve_context_set(&set)?;\n'
            printf '    Ok(out)\n'
            printf '}\n'
        } > "$path"
    }

    # ---- fixture (a): `saga*: AtomicBool` guard + fake FFI saga export -> FAIL
    local sup_a="$fixt/sup_a.rs"
    emit_good_supervisor "$sup_a"
    # Inject the instance-wide wedge as a struct field (positives still present,
    # so this proves the NEGATIVE alone fails even beside correct per-set gating).
    printf 'struct Wedge { saga_pending_guard: std::sync::atomic::AtomicBool }\n' >> "$sup_a"
    local ffi_a="$fixt/ffi_a"
    mkdir -p "$ffi_a"
    printf 'pub fn start_standing_saga() {}\n' > "$ffi_a/exports.rs"

    if run_check "$sup_a" "$ffi_a" "self-test(a)" "$tests_ok" >/dev/null 2>&1; then
        printf '%sSELF-TEST FAILED (a)%s: a saga*: AtomicBool guard + a start_*_saga FFI\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'export was NOT rejected. The negative / FFI-ordering assertion is dead.\n' >&2
        rc=1
    fi

    # ---- fixture (b): full correct per-set gating, no instance-wide guard -> PASS
    local sup_b="$fixt/sup_b.rs"
    emit_good_supervisor "$sup_b"
    local ffi_b="$fixt/ffi_b"
    mkdir -p "$ffi_b"
    printf 'pub fn unrelated() {}\n' > "$ffi_b/exports.rs"

    if ! run_check "$sup_b" "$ffi_b" "self-test(b)" "$tests_ok" >/dev/null 2>&1; then
        printf '%sSELF-TEST FAILED (b)%s: correct per-set gating (store + extractor +\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'reject-in-reserve + start_saga-calls-reserve + raw-digest key + proving\n' >&2
        printf 'tests, no instance-wide guard) was wrongly rejected. The gate is over-eager.\n' >&2
        rc=1
    fi

    # ---- fixture (c): guard deleted, NO per-set reservation -> FAIL ---------
    # Absence of the instance-wide guard alone must NOT pass: per-set gating
    # must be PRESENT (P1..P6).
    local sup_c="$fixt/sup_c.rs"
    {
        printf 'struct Supervisor {\n'
        printf '    spawn_generation: std::sync::atomic::AtomicU64,\n'
        printf '}\n'
        printf 'fn start_saga(&self) { /* no gating at all */ }\n'
    } > "$sup_c"
    local ffi_c="$fixt/ffi_c"
    mkdir -p "$ffi_c"
    printf 'pub fn unrelated() {}\n' > "$ffi_c/exports.rs"

    if run_check "$sup_c" "$ffi_c" "self-test(c)" "$tests_ok" >/dev/null 2>&1; then
        printf '%sSELF-TEST FAILED (c)%s: a supervisor with NO saga gating at all (guard\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'deleted, no per-set reservation) was wrongly accepted. The POSITIVE\n' >&2
        printf 'assertions are dead — absence-of-guard must not pass.\n' >&2
        rc=1
    fi

    # ---- fixture (d): NEG name-prefix bypass — `inflight_guard: AtomicBool` ->
    # FAIL. A non-`saga*`-named instance-wide wedge must still be caught now that
    # the name match covers inflight/pending/busy/gate/guard. Positives present
    # + a fake FFI saga export so the negative/FFI-ordering clause is live.
    local sup_d="$fixt/sup_d.rs"
    emit_good_supervisor "$sup_d"
    printf 'struct Wedge { inflight_guard: std::sync::atomic::AtomicBool }\n' >> "$sup_d"
    local ffi_d="$fixt/ffi_d"
    mkdir -p "$ffi_d"
    printf 'pub fn start_broadcast_saga() {}\n' > "$ffi_d/exports.rs"

    if run_check "$sup_d" "$ffi_d" "self-test(d)" "$tests_ok" >/dev/null 2>&1; then
        printf '%sSELF-TEST FAILED (d)%s: a non-saga-named instance-wide wedge\n' \
            "$C_RED" "$C_RESET" >&2
        printf '(`inflight_guard: AtomicBool`) slipped past the negative scan. The NEG\n' >&2
        printf 'name match is too narrow — widen it to inflight/pending/busy/gate/guard.\n' >&2
        rc=1
    fi

    # ---- fixture (e): NEG type-list bypass — `saga_x: Mutex<u8>` -> FAIL.
    # A small-scalar Mutex is an instance-wide wedge the old type list missed.
    local sup_e="$fixt/sup_e.rs"
    emit_good_supervisor "$sup_e"
    printf 'struct Wedge { saga_x: std::sync::Mutex<u8> }\n' >> "$sup_e"
    local ffi_e="$fixt/ffi_e"
    mkdir -p "$ffi_e"
    printf 'pub fn start_tool_saga() {}\n' > "$ffi_e/exports.rs"

    if run_check "$sup_e" "$ffi_e" "self-test(e)" "$tests_ok" >/dev/null 2>&1; then
        printf '%sSELF-TEST FAILED (e)%s: a small-scalar Mutex wedge (`saga_x: Mutex<u8>`)\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'slipped past the negative scan. The NEG type list is too narrow — cover\n' >&2
        printf 'Mutex<u8|u16|u32|u64|usize> and the small atomics.\n' >&2
        rc=1
    fi

    # ---- fixture (f): NEG signed-atomic bypass — `saga_x: AtomicI64` -> FAIL.
    # A SIGNED atomic is the same instance-wide wedge as its unsigned twin: an
    # in-set field name (`saga_x`) over a single instance-wide scalar counter.
    # The old type list named only the UNSIGNED atomics, so `AtomicI64` (or any
    # AtomicI8|I16|I32|I64|Isize) slipped through. Positives present + a fake FFI
    # saga export so the negative/FFI-ordering clause is live.
    local sup_f="$fixt/sup_f.rs"
    emit_good_supervisor "$sup_f"
    printf 'struct Wedge { saga_x: std::sync::atomic::AtomicI64 }\n' >> "$sup_f"
    local ffi_f="$fixt/ffi_f"
    mkdir -p "$ffi_f"
    printf 'pub fn start_standing_saga() {}\n' > "$ffi_f/exports.rs"

    if run_check "$sup_f" "$ffi_f" "self-test(f)" "$tests_ok" >/dev/null 2>&1; then
        printf '%sSELF-TEST FAILED (f)%s: a signed-atomic wedge (`saga_x: AtomicI64`)\n' \
            "$C_RED" "$C_RESET" >&2
        printf 'slipped past the negative scan. The NEG type list named only the\n' >&2
        printf 'UNSIGNED atomics — cover AtomicI8|I16|I32|I64|Isize too.\n' >&2
        rc=1
    fi

    # ---- fixture (g): P3 comment-only / gutted-reject bypass -> FAIL.
    # Identical to emit_good_supervisor EXCEPT `try_reserve_context_set`'s real
    # reject is GUTTED: the `return Err(...)` is replaced by a discarded binding
    # (`let _ = contended;`) and the busy tokens (SagaBusy/ActorBusy) survive
    # ONLY in a `//` comment. The comment-strip + `return Err(` requirement in
    # has_overlap_reject_in_reserve must reject this (P3). No FFI saga export
    # here: the failure must come from P3, not the negative/FFI-ordering clause.
    local sup_g="$fixt/sup_g.rs"
    {
        printf 'struct Supervisor {\n'
        printf '    reserved_saga_contexts: std::sync::Mutex<HashSet<String>>,\n'
        printf '    spawn_generation: std::sync::atomic::AtomicU64,\n'
        printf '}\n'
        printf 'fn saga_participant_context_set(input: &SagaInput) -> Vec<String> {\n'
        printf '    vec![hex::encode(derive_standing_context_digest(a, b))]\n'
        printf '}\n'
        printf 'fn try_reserve_context_set(&self, set: &[String]) -> Result<R, E> {\n'
        printf '    if set.iter().find(|id| reserved.contains(*id)).is_some() {\n'
        printf '        // overlap -> would be ContextError::ActorBusy / SagaBusy\n'
        printf '        let _ = contended;\n'
        printf '    }\n'
        printf '    Ok(reservation)\n'
        printf '}\n'
        printf 'pub async fn start_saga(&self, input: SagaInput) -> Result<O, E> {\n'
        printf '    let set = saga_participant_context_set(&input);\n'
        printf '    let _r = self.try_reserve_context_set(&set)?;\n'
        printf '    Ok(out)\n'
        printf '}\n'
    } > "$sup_g"
    local ffi_g="$fixt/ffi_g"
    mkdir -p "$ffi_g"
    printf 'pub fn unrelated() {}\n' > "$ffi_g/exports.rs"

    if run_check "$sup_g" "$ffi_g" "self-test(g)" "$tests_ok" >/dev/null 2>&1; then
        printf '%sSELF-TEST FAILED (g)%s: a comment-only / gutted overlap-reject (no real\n' \
            "$C_RED" "$C_RESET" >&2
        printf '`return Err` with the busy tokens in code — the reject replaced by a\n' >&2
        printf 'discarded binding and SagaBusy/ActorBusy surviving only in a `//` comment)\n' >&2
        printf 'was wrongly accepted. The P3 comment-strip + `return Err(` requirement is\n' >&2
        printf 'dead — restore the comment-tail stripping and the early-return check.\n' >&2
        rc=1
    fi

    rm -rf "$fixt"
    return "$rc"
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if [[ "${1:-}" == "--self-test" ]]; then
    if self_test; then
        printf '%sself-test:%s gate catches saga*/inflight-named instance-wide guards of\n' \
            "$C_DIM" "$C_RESET"
        printf '%s          %s atomic and small-scalar-Mutex types (+ FFI export), accepts\n' \
            "$C_DIM" "$C_RESET"
        printf '%s          %s correct per-set gating, and rejects no-gating-at-all.\n' \
            "$C_DIM" "$C_RESET"
        exit 0
    fi
    printf '%sThe saga-gating granularity gate is dead or mis-scoped — fix it.%s\n' \
        "$C_RED" "$C_RESET" >&2
    exit 1
fi

if run_check "$SUPERVISOR_REL" "$FFI_DIR" "scan"; then
    printf '%sPASSED%s: saga concurrency is gated per-participant-context-set\n' \
        "$C_GREEN" "$C_RESET"
    printf '%s        %s (reserved_saga_contexts + saga_participant_context_set +\n' \
        "$C_DIM" "$C_RESET"
    printf '%s        %s overlap-reject), with no instance-wide saga guard. ADR-049 §3a.\n' \
        "$C_DIM" "$C_RESET"
    exit 0
fi
exit 1
