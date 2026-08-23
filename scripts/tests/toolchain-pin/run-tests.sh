#!/usr/bin/env bash
# run-tests.sh — exercise the paths-filter assertion in
# `scripts/check-toolchain-pin.sh` against canned `ci.yml` fixtures.
#
# WHAT THIS TESTS. `rust-toolchain.toml` selects the compiler for every Rust job in
# `.github/workflows/ci.yml`, and every one of those jobs is guarded by
# `if: needs.changes.outputs.rust == 'true'` while the `ci` job that aggregates every
# other job's result counts a skipped job as a pass. A pull request that raises the pin and changes nothing else
# therefore has to reach the `rust` paths filter, or clippy, the test lane, the build,
# and cargo-deny all skip and the bump merges on a compiler nothing compiled. The gate
# asserts that; these fixtures prove the assertion fires when the entry is missing and
# stays silent when it is present.
#
# HOW IT ISOLATES ONE ASSERTION. Each fixture is a temporary directory holding a copy
# of the gate under `scripts/` and one `ci.yml` under `.github/workflows/`. The gate
# `cd`s to its own parent's parent, so that directory becomes its repository root. None
# of the other locations the gate reads — `rust-toolchain.toml`, `.mise.toml`, the two
# container builds, `.docs/standards/rust.md`, `fuzz/rust-toolchain.toml` — exists
# there, so the gate exits 1 on every fixture and the tests below read the paths-filter
# message rather than the exit status. The real repository's own agreement is what the
# `enforcement / toolchain pin agreement` job checks by running the gate unmodified.
#
# Exit 0 when every fixture matches its expectation, 1 otherwise.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
CHECK="$REPO_ROOT/scripts/check-toolchain-pin.sh"
FIXTURES_DIR="$SCRIPT_DIR/fixtures"

if [[ ! -f "$CHECK" ]]; then
    echo "ERROR: $CHECK does not exist" >&2
    exit 1
fi

# Fixture definitions — the three arrays are indexed together and must stay in sync.
#
# REQUIRED_SUBSTRINGS holds the message the fixture must produce, and
# FORBIDDEN_SUBSTRINGS holds a message it must not. An empty string means the fixture
# makes no claim in that direction. Every paths-filter message the gate can print
# contains the words "paths filter", so forbidding that phrase on the passing fixture
# asserts the absence of all of them.
FIXTURES=(
    "good-filters-list-the-pins"
    "good-double-quoted-entries"
    "bad-rust-filter-omits-pin"
    "bad-no-rust-filter"
    "bad-fuzz-filter-omits-crate"
)
REQUIRED_SUBSTRINGS=(
    ""
    ""
    "the 'rust' paths filter does not list rust-toolchain.toml"
    "declares no 'rust:' paths filter with path entries"
    "the 'fuzz' paths filter does not list fuzz/**"
)
FORBIDDEN_SUBSTRINGS=(
    "paths filter"
    "paths filter"
    ""
    ""
    ""
)

# One parent directory for every fixture root, removed by a single trap. A per-iteration
# trap would be overwritten by the next iteration and leave directories behind whenever a
# `cp` failed under `set -e`.
TMP_PARENT=$(mktemp -d)
trap 'rm -rf "$TMP_PARENT"' EXIT

passed=0
failed=0

for i in "${!FIXTURES[@]}"; do
    name="${FIXTURES[$i]}"
    required="${REQUIRED_SUBSTRINGS[$i]}"
    forbidden="${FORBIDDEN_SUBSTRINGS[$i]}"
    fixture_ci="$FIXTURES_DIR/$name/.github/workflows/ci.yml"

    if [[ ! -f "$fixture_ci" ]]; then
        echo "FAIL [$name]: fixture workflow missing: $fixture_ci" >&2
        failed=$((failed + 1))
        continue
    fi

    tmp_root="$TMP_PARENT/$name"
    mkdir -p "$tmp_root/scripts" "$tmp_root/.github/workflows"
    cp "$CHECK" "$tmp_root/scripts/"
    cp "$fixture_ci" "$tmp_root/.github/workflows/ci.yml"

    set +e
    output=$(bash "$tmp_root/scripts/$(basename "$CHECK")" 2>&1)
    actual_exit=$?
    set -e

    ok=1
    if [[ -n "$required" ]] && ! grep -Fq -- "$required" <<< "$output"; then
        echo "FAIL [$name]: output missing required substring: $required" >&2
        ok=0
    fi
    if [[ -n "$forbidden" ]] && grep -Fq -- "$forbidden" <<< "$output"; then
        echo "FAIL [$name]: output contains forbidden substring: $forbidden" >&2
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
echo "toolchain-pin fixture tests: $passed passed, $failed failed"
if [[ $failed -gt 0 ]]; then
    exit 1
fi
exit 0
