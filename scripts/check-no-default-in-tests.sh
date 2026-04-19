#!/usr/bin/env bash
# check-no-default-in-tests.sh — CI gate enforcing the "per-test SCP fixture"
# invariant introduced by #1549 Phase 4 PR 4.
#
# ---------------------------------------------------------------------------
# WHAT THIS CHECKS
# ---------------------------------------------------------------------------
# SDK tests must construct a fresh `SCP` instance per test (pytest
# function-scope fixture, bun test `beforeEach`, XCTest `setUp`, JUnit 5
# `@BeforeEach`) — NOT call the module-level free-function façade that
# routes through the process-wide default bridge instance
# (`DEFAULT_BRIDGE_INSTANCE`). Default-instance use in tests re-creates the
# serialization and cross-test leakage that ADR-048 was written to remove.
#
# The gate scans every test file in:
#   bindings/python/tests/           (pytest)
#   bindings/typescript/tests/       (bun test)
#   bindings/swift/Tests/            (XCTest)
#   bindings/kotlin/scp-kt/src/test/ (JUnit 5)
#
# and fails if any file calls a known free-function façade (e.g.
# `scp_sdk.context_create(...)`, `scpSdk.contextCreate(...)`, etc.) without
# an explicit opt-in tag of the form:
#
#   # SCP-DEFAULT-INSTANCE-OK: <reason>       (Python)
#   // SCP-DEFAULT-INSTANCE-OK: <reason>      (TypeScript / Swift / Kotlin)
#
# on the same line or within 2 lines above. The tag forces a deliberate,
# reviewable choice; the default is "migrate the test to a per-instance
# fixture" (see .docs/migration/phase-4.md for the recipe).
#
# Deprecation-decorator tests (test_deprecation.py, deprecation.test.ts,
# etc.) are exempt by filename because they MUST exercise the façade to
# verify the deprecation warning fires.
#
# ---------------------------------------------------------------------------
# WHEN THIS RUNS
# ---------------------------------------------------------------------------
# Gated on every PR touching `bindings/**`.
#
# ---------------------------------------------------------------------------
# HOW TO FIX A FAILURE
# ---------------------------------------------------------------------------
# Two paths:
#
#   1. Rewrite the test to use a per-test `SCP` fixture. This is the
#      default. See .docs/migration/phase-4.md § "Per-test SCP fixture".
#
#   2. If the test is deliberately exercising the default-instance path
#      (e.g. validating deprecation-warning behavior, or checking
#      cross-instance isolation), add the opt-in tag with a reason:
#
#        # SCP-DEFAULT-INSTANCE-OK: verifies DeprecationWarning on façade
#
#      The tag must appear on the offending line or within 2 lines above.
#
# Do NOT silence the gate by removing patterns from this script — that
# defeats the purpose.
#
# ---------------------------------------------------------------------------
# PORTABILITY
# ---------------------------------------------------------------------------
# Runs on macOS (BSD userland) and Linux (GNU userland). Uses POSIX-
# compatible bash features and grep -E; avoids awk regex features that
# differ across BSD/GNU awk (\b word boundaries, in particular).
#
# Usage:
#   bash scripts/check-no-default-in-tests.sh
# Exit codes:
#   0  — no unguarded free-function façade calls in test files
#   1  — one or more test files call the façade without the opt-in tag
#   2  — invocation error

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
# Configuration — façade call patterns per SDK.
#
# Patterns intentionally target the call shape `<prefix><name>(` where the
# prefix is the module-level namespace handle (`scp_sdk.`) or a function
# imported into the module namespace. We anchor on a non-word character
# before the identifier and require `(` after it to avoid matching attribute
# reads on class instances (`scp.context_create(` is NOT matched — only the
# free-function prefix forms are).
#
# The function-name alternation is the deprecated-free-function inventory
# derived from `@deprecated_default_instance` in bindings/python/scp_sdk/
# (as of Phase 4 PR 1). Adding a new free function? Append it here.
# ---------------------------------------------------------------------------

# Python free-function façade: `scp_sdk.<name>(` or a direct `<name>(` after
# `from scp_sdk import <name>`.
PY_FN_NAMES=$(cat <<'EOF'
context_create
context_join
context_leave
context_close
context_send
context_subscribe
context_invoke
context_import
identity_create
identity_load
identity_resolve
identity_rotate_key
ucan_issue
ucan_validate
ucan_delegate
policy_requires_payment
auto_accept_blocked
mint
delegate
revoke
handle_register
handle_lookup
handle_deregister
handle_ttl_expiry
petname_set
petname_get_for_did
petname_get_for_context
petname_remove
petname_remove_context
petname_resolve_did
petname_resolve_context
petname_set_context
discover
create_query
normalize_address
parse_address
address_resolve
connect_relay
budget_grant
budget_record_spend
budget_remaining
antispam_record
antispam_velocity
antispam_escalated_cost
estimate_cost
evaluate_formula
apply_pending_ceiling_modification
execute_governance_action
approve_governance_proposal
create_governance_checkpoint
get_governance_proposal
list_governance_proposals
add_checkpoint_cosignature
attach
check_media_capability
create_answer
create_offer
create_ice_candidate
initiate_session
activate_session
end_session
join_session
create_session_end
configure_stdio_allowlist
disable_stdio_allowlist
get_stdio_allowlist
reset_stdio_allowlist
evaluate_trust
aggregate_trust_input
evaluate_provenance_quality
check_policy_lock
check_chain_depth
create_shadow
finalize_close
interface_accept
interface_expose
interface_revoke
invoke_cross_context
register_local_did
EOF
)

# TypeScript / Swift / Kotlin free-function façade: camelCase variants.
# We match at `.name(` (prefixed object access) — pure lowercase `name(`
# would false-positive on local variables named the same thing.
TS_FN_NAMES=$(cat <<'EOF'
contextCreate
contextJoin
contextLeave
contextClose
contextSend
contextSubscribe
contextInvoke
contextImport
identityCreate
identityLoad
identityResolve
identityRotateKey
ucanIssue
ucanValidate
ucanDelegate
policyRequiresPayment
autoAcceptBlocked
handleRegister
handleLookup
handleDeregister
petnameSet
petnameGetForDid
petnameGetForContext
petnameRemove
discover
createQuery
budgetGrant
budgetRecordSpend
budgetRemaining
antispamRecord
antispamVelocity
estimateCost
executeGovernanceAction
approveGovernanceProposal
createGovernanceCheckpoint
addCheckpointCosignature
scpSuspend
scpResume
scpShutdown
registerLocalDid
EOF
)

# Build ERE alternation groups.
PY_ALTS=$(echo "$PY_FN_NAMES" | grep -v '^$' | paste -sd'|' -)
TS_ALTS=$(echo "$TS_FN_NAMES" | grep -v '^$' | paste -sd'|' -)

# Regex: module prefix or direct call-site for Python; `.name(` or `name(`
# at start-of-line for TS/Swift/Kotlin.
#
# Python:
#   `scp_sdk.<name>(`   — attribute access on the package
#   `^<name>(` / ` <name>(` preceded by a non-word char — top-level call
#     after `from scp_sdk import <name>`.
# Non-capturing groups, POSIX ERE compatible.
PY_RE="(scp_sdk\\.|[^A-Za-z_])($PY_ALTS)[[:space:]]*\\("

# TS / Swift / Kotlin:
#   `.<name>(` — object-method call; in tests this commonly appears as
#     `scpSdk.contextCreate(` or `NativeBindings.contextCreate(` (the
#     UniFFI object-style façade).
TS_RE="\\.($TS_ALTS)[[:space:]]*\\("

# Per-SDK inputs. Each entry:
#   LABEL::TEST_DIR::GLOB::REGEX::EXEMPT_FILENAME_REGEX
# Separator is `::` — must not appear in any regex. Single `|` is forbidden
# because the façade-call regex contains `|` alternations.
SDKS=(
    "python::bindings/python/tests::*.py::${PY_RE}::^(test_deprecation|conftest|__init__)\\.py$"
    "typescript::bindings/typescript/tests::*.test.ts::${TS_RE}::^(deprecation|mock-bridge)\\.test\\.ts$|^mock-bridge\\.ts$"
    "swift::bindings/swift/Tests::*.swift::${TS_RE}::Deprecation.*\\.swift$"
    "kotlin::bindings/kotlin/scp-kt/src/test::*.kt::${TS_RE}::Deprecation.*\\.kt$"
)

# ---------------------------------------------------------------------------
# Scan one SDK's test directory.
#
# For each matching test file (not exempt), find lines matching the regex.
# For each match, check the opt-in tag on the same line or within 2 lines
# above. Emit:
#   HIT<TAB>file<TAB>line<TAB>matched-text
# if unguarded.
# ---------------------------------------------------------------------------
scan_sdk() {
    local label="$1"
    local test_dir="$2"
    local glob="$3"
    local pattern="$4"
    local exempt_regex="$5"

    if [[ ! -d "$test_dir" ]]; then
        printf '%swarning:%s test dir %s does not exist, skipping %s\n' \
            "$C_YELLOW" "$C_RESET" "$test_dir" "$label" >&2
        return 0
    fi

    find "$test_dir" -type f -name "$glob" -print0 \
        | while IFS= read -r -d '' file; do
            local basename_f
            basename_f="$(basename "$file")"
            if [[ -n "$exempt_regex" ]] && [[ "$basename_f" =~ $exempt_regex ]]; then
                continue
            fi

            # grep -n to get line numbers for matches. Silence no-match (rc 1).
            local matches
            matches=$(grep -nE "$pattern" "$file" 2>/dev/null || true)
            [[ -z "$matches" ]] && continue

            # For each matched line, check the opt-in tag within a 3-line
            # window ending at the matched line.
            while IFS= read -r hit_line; do
                [[ -z "$hit_line" ]] && continue
                local line_num
                line_num="${hit_line%%:*}"
                local text
                text="${hit_line#*:}"

                # Window: [max(1, line_num-2), line_num].
                local start=$((line_num - 2))
                [[ "$start" -lt 1 ]] && start=1
                local end="$line_num"

                # Use sed to extract the window.
                local window
                window=$(sed -n "${start},${end}p" "$file" 2>/dev/null || true)
                if printf '%s' "$window" | grep -q 'SCP-DEFAULT-INSTANCE-OK:'; then
                    continue
                fi

                # Trim text to something readable (strip leading/trailing ws).
                local trimmed
                trimmed=$(printf '%s' "$text" \
                    | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' \
                    | cut -c1-120)
                printf 'HIT\t%s\t%s\t%s\n' "$file" "$line_num" "$trimmed"
            done <<< "$matches"
        done
}

# ---------------------------------------------------------------------------
# Drive the scan.
# ---------------------------------------------------------------------------
TMPDIR_RESULT=$(mktemp -d)
trap 'rm -rf "$TMPDIR_RESULT"' EXIT

TOTAL_HITS=0

printf '\n%sdefault-in-tests scan:%s\n' "$C_DIM" "$C_RESET"

for entry in "${SDKS[@]}"; do
    # Split on `::` without touching embedded `|` in the regex fields.
    # bash `read -d` can't use multi-char delimiters, so fall back to
    # awk/cut-based splitting: replace `::` with a control character and
    # then IFS on that.
    label="${entry%%::*}"
    rest="${entry#*::}"
    test_dir="${rest%%::*}"
    rest="${rest#*::}"
    glob="${rest%%::*}"
    rest="${rest#*::}"
    # The remaining payload is `REGEX::EXEMPT_REGEX` — but EXEMPT_REGEX
    # itself may contain `|` (TypeScript case: `...\\.test\\.ts$|^mock-bridge\\.ts$`).
    # Split only on the LAST `::` so EXEMPT_REGEX survives intact.
    pattern="${rest%::*}"
    exempt_regex="${rest##*::}"

    out_file="$TMPDIR_RESULT/$label.out"
    scan_sdk "$label" "$test_dir" "$glob" "$pattern" "$exempt_regex" > "$out_file" || true

    hits=$(grep -c $'^HIT\t' "$out_file" 2>/dev/null || true)
    hits=${hits:-0}

    if [[ "$hits" -eq 0 ]]; then
        printf '  %s[%s]%s clean\n' "$C_GREEN" "$label" "$C_RESET"
    else
        printf '  %s[%s]%s %d unguarded call(s):\n' "$C_RED" "$label" "$C_RESET" "$hits" >&2
        while IFS=$'\t' read -r tag file line text; do
            [[ "$tag" == "HIT" ]] || continue
            printf '      %s%s:%s%s  %s%s%s\n' \
                "$C_DIM" "$file" "$line" "$C_RESET" \
                "$C_YELLOW" "$text" "$C_RESET" >&2
        done < "$out_file"
        TOTAL_HITS=$((TOTAL_HITS + hits))
    fi
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
printf '\n'

if [[ "$TOTAL_HITS" -eq 0 ]]; then
    printf '%sPASSED%s: no unguarded free-function façade calls in test files.\n' \
        "$C_GREEN" "$C_RESET"
    exit 0
fi

printf '%sFAILED%s: %d unguarded call(s) to the default-instance façade in tests.\n' \
    "$C_RED" "$C_RESET" "$TOTAL_HITS" >&2
printf '\n' >&2
printf 'Tests must construct a fresh SCP instance per test. Either:\n' >&2
printf '  1. Rewrite the test to use a per-test SCP fixture (preferred —\n' >&2
printf '     see .docs/migration/phase-4.md § "Per-test SCP fixture").\n' >&2
printf '  2. Add the opt-in tag on the offending line or within 2 lines above:\n' >&2
printf '        # SCP-DEFAULT-INSTANCE-OK: <reason>       (Python)\n' >&2
printf '        // SCP-DEFAULT-INSTANCE-OK: <reason>      (TS / Swift / Kotlin)\n' >&2
printf '\n' >&2
printf 'See .docs/adrs/ADR-048-scp-multi-instance.md for the rationale.\n' >&2

exit 1
