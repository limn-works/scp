#!/usr/bin/env bash
# check-cross-layer.sh — CI gate ensuring new public functions in scp-protocol
# or scp-runtime have corresponding FFI bridge EXPORTS.
#
# For each new `pub fn X` added to scp-protocol/scp-runtime, the script checks
# that the SAME diff also adds a corresponding export in scp-ffi/ containing
# the function name (or a known alias like `py_X`). Just touching an
# unrelated FFI file is NOT sufficient.
#
# Exemptions:
#   - pub(crate) / pub(super) functions (not externally visible)
#   - Functions in tests/ or examples/ directories
#   - Functions inside #[cfg(test)] modules
#   - Validated exemption markers in PR body (see below for types)
#
# Exit 0: no new pub fns, or all have matching FFI exports, or exempt
# Exit 1: new pub fns without corresponding FFI exports
#
# Usage:
#   bash scripts/check-cross-layer.sh [diff-range]
#   # diff-range defaults to origin/$GITHUB_BASE_REF...HEAD or origin/main...HEAD
#
# Environment variables:
#   GITHUB_BASE_REF — base branch for PR (set by GitHub Actions)
#   PR_BODY         — PR description text (checked for [cross-layer-exempt])
#   PR_BODY_FILE    — path to file containing PR description

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# ---------------------------------------------------------------------------
# Determine diff range
# ---------------------------------------------------------------------------
if [[ $# -ge 1 ]]; then
    DIFF_RANGE="$1"
elif [[ -n "${GITHUB_BASE_REF:-}" ]]; then
    DIFF_RANGE="origin/${GITHUB_BASE_REF}...HEAD"
else
    DIFF_RANGE="origin/main...HEAD"
fi

# ---------------------------------------------------------------------------
# Collect new public function names from scp-protocol/scp-runtime
# ---------------------------------------------------------------------------
NEW_PUB_FNS=()
NEW_PUB_FN_NAMES=()

CORE_DIFF=$(git diff "$DIFF_RANGE" --unified=0 --diff-filter=ACMR -- \
    ':(glob)crates/scp-protocol/src/**/*.rs' \
    ':(glob)crates/scp-runtime/src/**/*.rs' \
    2>/dev/null || true)

if [[ -z "$CORE_DIFF" ]]; then
    echo "No changes to scp-protocol/src/ or scp-runtime/src/ detected."
    echo "PASSED: Cross-layer check not applicable."
    exit 0
fi

CURRENT_FILE=""
IN_CFG_TEST=0
IN_IMPL=0

while IFS= read -r line; do
    # Track which file we're in — parse both paths from git diff header
    if [[ "$line" =~ ^diff\ --git\ a/([^\ ]+)\ b/(.+)$ ]]; then
        CURRENT_FILE="${BASH_REMATCH[2]}"
        IN_CFG_TEST=0
        IN_IMPL=0
        continue
    fi

    # Skip files in tests/ or examples/ directories
    case "$CURRENT_FILE" in
        */tests/*|*/examples/*) continue ;;
    esac

    # Hunk headers: detect #[cfg(test)] and impl blocks in context
    # Git hunk headers show the enclosing scope after the second @@:
    #   @@ -100,5 +100,7 @@ impl ToolRegistry {
    if [[ "$line" =~ ^@@.*@@ ]]; then
        if [[ "$line" == *"cfg(test)"* ]]; then
            IN_CFG_TEST=1
        else
            IN_CFG_TEST=0
        fi
        # Detect impl blocks — methods on types are internal API, not standalone
        # protocol functions that need individual FFI exports. The type itself
        # is consumed by bridges through existing FFI functions.
        if [[ "$line" == *"impl "* ]]; then
            IN_IMPL=1
        else
            IN_IMPL=0
        fi
        continue
    fi

    # Track #[cfg(test)] in added lines
    if [[ "$line" == "+"*"#[cfg(test)]"* ]]; then
        IN_CFG_TEST=1
        continue
    fi

    # Only look at added lines
    [[ "$line" == "+"* ]] || continue
    [[ $IN_CFG_TEST -eq 0 ]] || continue
    # Skip methods inside impl blocks — they're consumed through the type,
    # not as standalone FFI exports
    [[ $IN_IMPL -eq 0 ]] || continue

    content="${line:1}"

    # Skip restricted visibility
    [[ "$content" != *"pub(crate)"* ]] || continue
    [[ "$content" != *"pub(super)"* ]] || continue

    # Match pub fn or pub async fn declarations
    if [[ "$content" =~ pub[[:space:]]+(async[[:space:]]+)?fn[[:space:]]+([a-zA-Z_][a-zA-Z0-9_]*) ]]; then
        fn_name="${BASH_REMATCH[2]}"
        NEW_PUB_FNS+=("${CURRENT_FILE}::${fn_name}")
        NEW_PUB_FN_NAMES+=("${fn_name}")
        NEW_PUB_FN_FILES+=("${CURRENT_FILE}")
        NEW_PUB_FN_KIND+=("fn")
    # Match pub struct/enum/type/trait (type-only items, not callable)
    elif [[ "$content" =~ pub[[:space:]]+(struct|enum|type|trait)[[:space:]]+([a-zA-Z_][a-zA-Z0-9_]*) ]]; then
        : # Types don't need FFI exports — skip silently
    fi
done <<< "$CORE_DIFF"

# ---------------------------------------------------------------------------
# No new public functions — nothing to check
# ---------------------------------------------------------------------------
if [[ ${#NEW_PUB_FNS[@]} -eq 0 ]]; then
    echo "No new public functions added to scp-protocol/scp-runtime."
    echo "PASSED: Cross-layer check not applicable."
    exit 0
fi

# ---------------------------------------------------------------------------
# Get the FFI diff (added lines only)
# ---------------------------------------------------------------------------
FFI_DIFF=$(git diff "$DIFF_RANGE" --unified=0 --diff-filter=ACMR -- \
    ':(glob)crates/scp-ffi/**/*.rs' \
    2>/dev/null || true)

# Collect all added lines from FFI diff into one string for searching
FFI_ADDED=""
if [[ -n "$FFI_DIFF" ]]; then
    FFI_ADDED=$(echo "$FFI_DIFF" | grep '^+' | grep -v '^+++' || true)
fi

# ---------------------------------------------------------------------------
# For each new pub fn, check if the FFI diff contains a matching export
# ---------------------------------------------------------------------------
UNMATCHED=()

for i in "${!NEW_PUB_FNS[@]}"; do
    fn_name="${NEW_PUB_FN_NAMES[$i]}"
    fn_full="${NEW_PUB_FNS[$i]}"

    # Check for the function name or common FFI aliases in FFI added lines
    # Patterns: exact name, py_ prefix (PyO3), snake_case, camelCase
    found=0

    if [[ -n "$FFI_ADDED" ]]; then
        # Exact name match (word boundary — prevents "send" matching "send_message")
        if echo "$FFI_ADDED" | grep -qw "$fn_name"; then
            found=1
        fi

        # PyO3 py_ prefix
        if [[ $found -eq 0 ]] && echo "$FFI_ADDED" | grep -qw "py_${fn_name}"; then
            found=1
        fi

        # camelCase conversion: foo_bar_baz → fooBarBaz
        # Use perl (not sed) — BSD sed on macOS doesn't support \U
        camel=$(echo "$fn_name" | perl -pe 's/_([a-z])/uc($1)/ge')
        if [[ $found -eq 0 ]] && echo "$FFI_ADDED" | grep -qw "$camel"; then
            found=1
        fi
    fi

    if [[ $found -eq 0 ]]; then
        UNMATCHED+=("$fn_full")
    fi
done

# ---------------------------------------------------------------------------
# All matched — success
# ---------------------------------------------------------------------------
if [[ ${#UNMATCHED[@]} -eq 0 ]]; then
    echo "Found ${#NEW_PUB_FNS[@]} new public function(s) in scp-protocol/scp-runtime."
    echo "All have corresponding FFI bridge exports."
    echo ""
    echo "Matched functions:"
    for fn in "${NEW_PUB_FNS[@]}"; do
        echo "  ✓ $fn"
    done
    echo ""
    echo "PASSED: Cross-layer check satisfied."
    exit 0
fi

# ---------------------------------------------------------------------------
# Some unmatched — check for exemption
# ---------------------------------------------------------------------------
echo "" >&2
echo "New public functions in scp-protocol/scp-runtime WITHOUT matching FFI bridge exports:" >&2
echo "" >&2
for fn in "${UNMATCHED[@]}"; do
    echo "  ✗ $fn" >&2
done
echo "" >&2

# Show which functions DID match for context
MATCHED_COUNT=$(( ${#NEW_PUB_FNS[@]} - ${#UNMATCHED[@]} ))
if [[ $MATCHED_COUNT -gt 0 ]]; then
    echo "($MATCHED_COUNT other function(s) matched FFI exports)" >&2
    echo "" >&2
fi

echo "For each unmatched function, either:" >&2
echo "  1. Add the FFI bridge export in this PR" >&2
echo "  2. Add a validated exemption marker in the PR body (see below)" >&2
echo "" >&2
echo "Valid exemption markers (one per line in PR body):" >&2
echo "  [cross-layer: pub-crate-visibility] <function_name>  — pub for cross-module Rust access, not SDK surface" >&2
echo "  [cross-layer: test-infrastructure] <function_name>   — test helpers, fixtures, mock types" >&2
echo "  [cross-layer: internal-crypto] <function_name>       — crypto construction helpers" >&2
echo "" >&2

# Load PR body
PR_TEXT=""
if [[ -n "${PR_BODY:-}" ]]; then
    PR_TEXT="$PR_BODY"
elif [[ -n "${PR_BODY_FILE:-}" && -f "${PR_BODY_FILE:-}" ]]; then
    PR_TEXT=$(cat "$PR_BODY_FILE")
fi

# Validate each exemption marker against the actual code
STILL_UNMATCHED=()
for i in "${!UNMATCHED[@]}"; do
    fn_full="${UNMATCHED[$i]}"
    # Extract function name (after ::)
    fn_name="${fn_full##*::}"
    # Extract file path (before ::)
    fn_file="${fn_full%%::*}"
    exempted=0

    # [cross-layer: pub-crate-visibility] — function could be pub(crate) but needs cross-crate access
    if echo "$PR_TEXT" | grep -q "\[cross-layer: pub-crate-visibility\].*${fn_name}"; then
        echo "  EXEMPT (pub-crate-visibility): $fn_full" >&2
        exempted=1
    fi

    # [cross-layer: test-infrastructure] — must be in a testing module or behind testing feature
    if [[ $exempted -eq 0 ]] && echo "$PR_TEXT" | grep -q "\[cross-layer: test-infrastructure\].*${fn_name}"; then
        if [[ "$fn_file" == *"/testing"* ]] || [[ "$fn_file" == *"/tests/"* ]] || grep -q "cfg.*feature.*testing" "$(git rev-parse --show-toplevel)/${fn_file}" 2>/dev/null; then
            echo "  EXEMPT (test-infrastructure): $fn_full" >&2
            exempted=1
        else
            echo "  INVALID EXEMPTION: $fn_full claimed test-infrastructure but file is not in a testing module" >&2
        fi
    fi

    # [cross-layer: internal-crypto] — must be in crypto/ directory
    if [[ $exempted -eq 0 ]] && echo "$PR_TEXT" | grep -q "\[cross-layer: internal-crypto\].*${fn_name}"; then
        if [[ "$fn_file" == *"/crypto/"* ]]; then
            echo "  EXEMPT (internal-crypto): $fn_full" >&2
            exempted=1
        else
            echo "  INVALID EXEMPTION: $fn_full claimed internal-crypto but file is not in crypto/" >&2
        fi
    fi

    if [[ $exempted -eq 0 ]]; then
        STILL_UNMATCHED+=("$fn_full")
    fi
done

echo "" >&2

if [[ ${#STILL_UNMATCHED[@]} -eq 0 ]]; then
    echo "All unmatched functions have valid exemptions."
    echo "PASSED (exempt): Cross-layer check satisfied via validated exemptions."
    exit 0
fi

echo "FAILED: ${#STILL_UNMATCHED[@]} function(s) without FFI exports or valid exemptions:" >&2
for fn in "${STILL_UNMATCHED[@]}"; do
    echo "  ✗ $fn" >&2
done
exit 1
