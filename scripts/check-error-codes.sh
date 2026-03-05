#!/usr/bin/env bash
# check-error-codes.sh — CI gate enforcing SCP error code conformance.
#
# Scans source files for SCP error codes and verifies each one uses a
# canonical prefix with a number in the allocated range (sdk-common.md).
#
# Canonical prefixes and ranges:
#   SCP-IDENT-   1000-1999    SCP-CTX-     2000-2999
#   SCP-PERM-    3000-3999    SCP-CRYPTO-  4000-4999
#   SCP-TRANS-   5000-5999    SCP-TOOL-    6000-6999
#   SCP-VALID-   7000-7999    SCP-STORAGE- 8000-8999
#   SCP-ATTEST-  9000-9999    SCP-MCP-     10000-10999
#
# Exit 0 on success, 1 on any violation.
# Usage: ./scripts/check-error-codes.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

VIOLATIONS=0
CHECKED=0

check_code() {
    local file="$1"
    local line_num="$2"
    local code="$3"

    CHECKED=$((CHECKED + 1))

    local prefix number
    prefix="${code%-*}"   # e.g. SCP-IDENT, SCP-CTX
    number="${code##*-}"  # e.g. 1001, 2001

    if ! [[ "$number" =~ ^[0-9]+$ ]]; then
        echo "VIOLATION: $file:$line_num: $code — number part '$number' is not numeric"
        VIOLATIONS=$((VIOLATIONS + 1))
        return
    fi

    local num=$((10#$number))

    case "$prefix" in
        SCP-IDENT)    [[ $num -ge 1000 && $num -le 1999 ]] || { echo "VIOLATION: $file:$line_num: $code — IDENT range is 1000-1999"; VIOLATIONS=$((VIOLATIONS + 1)); } ;;
        SCP-CTX)      [[ $num -ge 2000 && $num -le 2999 ]] || { echo "VIOLATION: $file:$line_num: $code — CTX range is 2000-2999"; VIOLATIONS=$((VIOLATIONS + 1)); } ;;
        SCP-PERM)     [[ $num -ge 3000 && $num -le 3999 ]] || { echo "VIOLATION: $file:$line_num: $code — PERM range is 3000-3999"; VIOLATIONS=$((VIOLATIONS + 1)); } ;;
        SCP-CRYPTO)   [[ $num -ge 4000 && $num -le 4999 ]] || { echo "VIOLATION: $file:$line_num: $code — CRYPTO range is 4000-4999"; VIOLATIONS=$((VIOLATIONS + 1)); } ;;
        SCP-TRANS)    [[ $num -ge 5000 && $num -le 5999 ]] || { echo "VIOLATION: $file:$line_num: $code — TRANS range is 5000-5999"; VIOLATIONS=$((VIOLATIONS + 1)); } ;;
        SCP-TOOL)     [[ $num -ge 6000 && $num -le 6999 ]] || { echo "VIOLATION: $file:$line_num: $code — TOOL range is 6000-6999"; VIOLATIONS=$((VIOLATIONS + 1)); } ;;
        SCP-VALID)    [[ $num -ge 7000 && $num -le 7999 ]] || { echo "VIOLATION: $file:$line_num: $code — VALID range is 7000-7999"; VIOLATIONS=$((VIOLATIONS + 1)); } ;;
        SCP-STORAGE)  [[ $num -ge 8000 && $num -le 8999 ]] || { echo "VIOLATION: $file:$line_num: $code — STORAGE range is 8000-8999"; VIOLATIONS=$((VIOLATIONS + 1)); } ;;
        SCP-ATTEST)   [[ $num -ge 9000 && $num -le 9999 ]] || { echo "VIOLATION: $file:$line_num: $code — ATTEST range is 9000-9999"; VIOLATIONS=$((VIOLATIONS + 1)); } ;;
        SCP-MCP)      [[ $num -ge 10000 && $num -le 10999 ]] || { echo "VIOLATION: $file:$line_num: $code — MCP range is 10000-10999"; VIOLATIONS=$((VIOLATIONS + 1)); } ;;
        SCP-UNKNOWN)  ;; # Sentinel for unmapped bridge errors — allowed
        SCP-TEST)     ;; # Test sentinel — allowed
        *)
            # PRD story IDs (e.g. SCP-AB-016, SCP-PERSIST-062) use numbers
            # < 1000. Error codes start at 1000+. Skip story references.
            if [[ $num -ge 1000 ]]; then
                echo "VIOLATION: $file:$line_num: $code — non-canonical prefix '$prefix'"
                VIOLATIONS=$((VIOLATIONS + 1))
            fi
            ;;
    esac
}

cd "$REPO_ROOT"

# Scan source files for SCP error code literals.
# Matches patterns like "SCP-IDENT-1001", 'SCP-CTX-2001', `SCP-PERM-3001`
# Excludes: .git, target, build, node_modules, .docs (specs/ADRs use codes in prose),
#           sdk-common.md (the definition file itself), this script, CLAUDE.md files.
while IFS=: read -r file line_num content; do
    # Extract all SCP codes from the line
    while [[ "$content" =~ SCP-([A-Z]+)-([0-9]+) ]]; do
        full_code="SCP-${BASH_REMATCH[1]}-${BASH_REMATCH[2]}"
        check_code "$file" "$line_num" "$full_code"
        # Remove the matched code and continue scanning the line
        content="${content#*"$full_code"}"
    done
done < <(
    grep -rnE 'SCP-[A-Z]+-[0-9]+' \
        --include='*.rs' \
        --include='*.kt' \
        --include='*.swift' \
        --include='*.py' \
        --include='*.ts' \
        --include='*.js' \
        --exclude-dir='.git' \
        --exclude-dir='.claude' \
        --exclude-dir='.docs' \
        --exclude-dir='target' \
        --exclude-dir='build' \
        --exclude-dir='node_modules' \
        --exclude='check-error-codes.sh' \
        --exclude='sdk-common.md' \
        --exclude='CLAUDE.md' \
        . 2>/dev/null || true
)

echo ""
echo "Checked $CHECKED error code occurrences."

if [[ $VIOLATIONS -gt 0 ]]; then
    echo "FAILED: $VIOLATIONS violation(s) found."
    echo "See .docs/standards/sdk-common.md for canonical prefixes and ranges."
    exit 1
else
    echo "PASSED: All error codes conform to sdk-common.md ranges."
    exit 0
fi
