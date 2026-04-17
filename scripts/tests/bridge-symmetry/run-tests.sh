#!/usr/bin/env bash
# run-tests.sh — exercise check-bridge-symmetry.sh against canned fixtures.
#
# For each fixture under ./fixtures/, invoke check-bridge-symmetry.sh with
# SCP_BRIDGE_ROOT pointing at the fixture and assert the expected exit code
# and an expected substring in combined stdout+stderr.
#
# Scope note: these fixtures cover surface-area symmetry only. Call-ordering
# invariants are enforced by Layer B (`scripts/check-call-invariants.py`),
# which has its own fixture tests.
#
# Exit 0 if every fixture passes, 1 on any failure.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
CHECK="$REPO_ROOT/scripts/check-bridge-symmetry.sh"

if [[ ! -x "$CHECK" ]]; then
    echo "ERROR: $CHECK is not executable" >&2
    exit 1
fi

FIXTURES_DIR="$SCRIPT_DIR/fixtures"

# Fixture definitions — arrays must stay in sync.
FIXTURES=(
    "good-all-bridges"
    "bad-missing-napi"
    "good-exempt-missing"
    "bad-alias-in-test-module-only"
    "bad-alias-in-test-impl"
)
EXPECTED_EXITS=(
    "0"
    "1"
    "0"
    "1"
    "1"
)
EXPECTED_SUBSTRINGS=(
    "0 finding(s)"
    "bridge=napi missing operation widget_create"
    "0 finding(s)"
    "bridge=napi missing operation widget_create"
    "bridge=napi missing operation widget_create"
)

passed=0
failed=0

for i in "${!FIXTURES[@]}"; do
    name="${FIXTURES[$i]}"
    expected_exit="${EXPECTED_EXITS[$i]}"
    expected_substr="${EXPECTED_SUBSTRINGS[$i]}"
    fixture_root="$FIXTURES_DIR/$name"

    if [[ ! -d "$fixture_root" ]]; then
        echo "FAIL: fixture directory missing: $fixture_root" >&2
        failed=$((failed + 1))
        continue
    fi

    set +e
    output=$(SCP_BRIDGE_ROOT="$fixture_root" bash "$CHECK" 2>&1)
    actual_exit=$?
    set -e

    ok=1
    if [[ "$actual_exit" != "$expected_exit" ]]; then
        echo "FAIL [$name]: expected exit $expected_exit, got $actual_exit" >&2
        ok=0
    fi
    if ! echo "$output" | grep -Fq -- "$expected_substr"; then
        echo "FAIL [$name]: output missing expected substring: $expected_substr" >&2
        ok=0
    fi

    if [[ $ok -eq 1 ]]; then
        echo "PASS [$name]: exit=$actual_exit"
        passed=$((passed + 1))
    else
        echo "---- output begin ----" >&2
        echo "$output" >&2
        echo "---- output end ----" >&2
        failed=$((failed + 1))
    fi
done

echo ""
echo "bridge-symmetry fixture tests: $passed passed, $failed failed"
if [[ $failed -gt 0 ]]; then
    exit 1
fi
exit 0
