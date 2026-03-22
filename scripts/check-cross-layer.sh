#!/usr/bin/env bash
# check-cross-layer.sh — CI gate ensuring new public functions in scp-core
# (or scp-runtime after rename) have corresponding FFI bridge changes.
#
# When a PR adds `pub fn` or `pub async fn` to crates/scp-core/src/ (or
# crates/scp-runtime/src/), the same PR must also touch at least one file
# in crates/scp-ffi/. This prevents protocol logic from being built without
# bridge exports — the root cause of unwired code.
#
# Exemptions:
#   - pub(crate) functions (not externally visible)
#   - Functions in tests/ or examples/ directories
#   - Functions inside #[cfg(test)] modules
#   - PR body contains [cross-layer-exempt] with justification
#
# Exit 0: no new pub fns, or FFI files touched, or exempt
# Exit 1: new pub fns without FFI changes and no exemption
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
# Collect new public function lines from the diff
# ---------------------------------------------------------------------------
# We look at added lines (starting with +) in files under scp-core/src/ or
# scp-runtime/src/, excluding tests/, examples/, and pub(crate).

NEW_PUB_FNS=()

# Get the unified diff for core/runtime source files only.
# --diff-filter=ACMR: only Added, Copied, Modified, Renamed files.
# Use :(glob) prefix for recursive glob matching in git pathspecs.
DIFF_OUTPUT=$(git diff "$DIFF_RANGE" --unified=0 --diff-filter=ACMR -- \
    ':(glob)crates/scp-core/src/**/*.rs' \
    ':(glob)crates/scp-runtime/src/**/*.rs' \
    2>/dev/null || true)

if [[ -z "$DIFF_OUTPUT" ]]; then
    echo "No changes to scp-core/src/ or scp-runtime/src/ detected."
    echo "PASSED: Cross-layer check not applicable."
    exit 0
fi

CURRENT_FILE=""
IN_CFG_TEST=0

while IFS= read -r line; do
    # Track which file we're in
    if [[ "$line" =~ ^diff\ --git\ a/(.*) ]]; then
        CURRENT_FILE="${BASH_REMATCH[1]}"
        CURRENT_FILE="${CURRENT_FILE%% *}"
        # Remove the b/ prefix from the second path
        if [[ "$line" =~ b/(.*) ]]; then
            CURRENT_FILE="${BASH_REMATCH[1]}"
        fi
        IN_CFG_TEST=0
        continue
    fi

    # Skip files in tests/ or examples/ directories
    case "$CURRENT_FILE" in
        */tests/*|*/examples/*) continue ;;
    esac

    # Hunk headers: only use cfg(test) literal in context to detect test modules.
    # Git hunk headers show the nearest enclosing scope, which can be misleading
    # (e.g., code appended after mod tests shows "mod tests" in the context).
    # Only trust explicit #[cfg(test)] in the context, not bare "mod tests".
    if [[ "$line" =~ ^@@.*@@ ]]; then
        if [[ "$line" == *"cfg(test)"* ]]; then
            IN_CFG_TEST=1
        else
            # New hunk not inside cfg(test) — reset
            IN_CFG_TEST=0
        fi
        continue
    fi

    # Track #[cfg(test)] in added lines — everything after this in the
    # current hunk is test code
    if [[ "$line" == "+"*"#[cfg(test)]"* ]]; then
        IN_CFG_TEST=1
        continue
    fi

    # Only look at added lines
    if [[ "$line" != "+"* ]]; then
        continue
    fi

    # Skip if inside a #[cfg(test)] module
    if [[ $IN_CFG_TEST -eq 1 ]]; then
        continue
    fi

    # Strip the leading + for analysis
    content="${line:1}"

    # Skip pub(crate) — not externally visible
    if [[ "$content" == *"pub(crate)"* ]]; then
        continue
    fi

    # Skip pub(super) — not externally visible
    if [[ "$content" == *"pub(super)"* ]]; then
        continue
    fi

    # Match pub fn or pub async fn declarations
    if [[ "$content" =~ pub[[:space:]]+(async[[:space:]]+)?fn[[:space:]]+([a-zA-Z_][a-zA-Z0-9_]*) ]]; then
        fn_name="${BASH_REMATCH[2]}"
        NEW_PUB_FNS+=("${CURRENT_FILE}::${fn_name}")
    fi
done <<< "$DIFF_OUTPUT"

# ---------------------------------------------------------------------------
# No new public functions — nothing to check
# ---------------------------------------------------------------------------
if [[ ${#NEW_PUB_FNS[@]} -eq 0 ]]; then
    echo "No new public functions added to scp-core/scp-runtime."
    echo "PASSED: Cross-layer check not applicable."
    exit 0
fi

# ---------------------------------------------------------------------------
# Check if FFI bridge files were also touched
# ---------------------------------------------------------------------------
FFI_CHANGED=$(git diff "$DIFF_RANGE" --name-only --diff-filter=ACMR -- \
    'crates/scp-ffi/' 2>/dev/null || true)

if [[ -n "$FFI_CHANGED" ]]; then
    echo "Found ${#NEW_PUB_FNS[@]} new public function(s) in scp-core/scp-runtime."
    echo "FFI bridge files also changed — cross-layer requirement satisfied."
    echo ""
    echo "New public functions:"
    for fn in "${NEW_PUB_FNS[@]}"; do
        echo "  + $fn"
    done
    echo ""
    echo "FFI files changed:"
    echo "$FFI_CHANGED" | while IFS= read -r f; do echo "  ~ $f"; done
    echo ""
    echo "PASSED: Cross-layer check satisfied."
    exit 0
fi

# ---------------------------------------------------------------------------
# New pub fns exist but no FFI changes — check for exemption
# ---------------------------------------------------------------------------
echo "" >&2
echo "New public functions added to scp-core/scp-runtime WITHOUT FFI bridge changes:" >&2
echo "" >&2
for fn in "${NEW_PUB_FNS[@]}"; do
    echo "  + $fn" >&2
done
echo "" >&2

# Check for [cross-layer-exempt] in PR body
PR_TEXT=""
if [[ -n "${PR_BODY:-}" ]]; then
    PR_TEXT="$PR_BODY"
elif [[ -n "${PR_BODY_FILE:-}" && -f "${PR_BODY_FILE:-}" ]]; then
    PR_TEXT=$(cat "$PR_BODY_FILE")
fi

if [[ "$PR_TEXT" == *"[cross-layer-exempt]"* ]]; then
    echo "WARNING: New public functions added without FFI bridge changes." >&2
    echo "PR is marked [cross-layer-exempt] — proceeding with warning." >&2
    echo "" >&2
    echo "PASSED (exempt): Cross-layer check bypassed via [cross-layer-exempt]."
    exit 0
fi

echo "New public functions added to scp-core without FFI bridge changes." >&2
echo "Either add bridge exports or mark the PR with [cross-layer-exempt] and a justification." >&2
echo "" >&2
echo "FAILED: Cross-layer check failed."
exit 1
