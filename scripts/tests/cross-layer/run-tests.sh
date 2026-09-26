#!/usr/bin/env bash
# Fixture tests for scripts/check-cross-layer.sh.
#
# This gate searched its collected FFI diff with `echo "$FFI_ADDED" | grep -qw
# NAME` under `set -o pipefail`. `grep -q` stops reading at its first match, so
# `echo` died of SIGPIPE and returned 141, and pipefail handed 141 back even
# though grep had found that name. Whether this gate saw an FFI export
# therefore depended on how many bytes into a diff that export sat: a name near
# a top read as absent and this gate rejected a pull request, while an
# identical name near a bottom read as present.
#
# Each case below builds a scratch git repository, plants a diff, and runs a
# real gate script against it. Case 3 proves that fixing this did not weaken
# anything: a genuinely missing FFI export must still be rejected.
set -euo pipefail

GATE="$(cd "$(dirname "$0")/../.." && pwd)/check-cross-layer.sh"
PASSED=0
FAILED=0

# A haystack larger than a pipe buffer, so an early match triggers SIGPIPE.
filler() {
    local i
    for ((i = 0; i < 2500; i++)); do
        echo "// padding line ${i} — widens this FFI diff past a pipe buffer"
    done
}

# build_case <name> <marker-position: first|last|absent> <expected-exit>
run_case() {
    local name="$1" position="$2" expected="$3"
    local work
    work="$(mktemp -d)"

    mkdir -p "$work/scripts" "$work/crates/scp-protocol/src" "$work/crates/scp-ffi/src"
    cp "$GATE" "$work/scripts/check-cross-layer.sh"

    git -C "$work" init --quiet
    git -C "$work" config user.email "ci-gate-test@example.invalid"
    git -C "$work" config user.name "cross-layer fixture"
    echo "base" > "$work/README.md"
    git -C "$work" add -A
    git -C "$work" commit --quiet -m "base"
    local base
    base="$(git -C "$work" rev-parse HEAD)"

    cat > "$work/crates/scp-protocol/src/thing.rs" <<'RS'
pub fn cross_layer_fixture_operation(value: u32) -> u32 {
    value
}
RS

    {
        [[ "$position" == "first" ]] && echo "pub fn cross_layer_fixture_operation_export() {} // cross_layer_fixture_operation"
        filler
        [[ "$position" == "last" ]] && echo "pub fn cross_layer_fixture_operation_export() {} // cross_layer_fixture_operation"
        true
    } > "$work/crates/scp-ffi/src/bridge.rs"

    git -C "$work" add -A
    git -C "$work" commit --quiet -m "change"

    local actual=0
    bash "$work/scripts/check-cross-layer.sh" "${base}...HEAD" >/dev/null 2>&1 || actual=$?

    local bytes
    bytes=$(wc -c < "$work/crates/scp-ffi/src/bridge.rs" | tr -d ' ')
    if [[ "$actual" -eq "$expected" ]]; then
        echo "  ok    ${name} (FFI diff ${bytes} bytes, exit ${actual})"
        PASSED=$((PASSED + 1))
    else
        echo "  FAIL  ${name} (FFI diff ${bytes} bytes, exit ${actual}, want ${expected})"
        FAILED=$((FAILED + 1))
    fi
    rm -rf "$work"
}

echo "cross-layer gate — a verdict must not depend on where an export sits"
run_case "export on a first line of a large FFI diff is found" first 0
run_case "export on a last line of a large FFI diff is found" last 0
run_case "a genuinely missing export is still rejected" absent 1

echo "${PASSED} passed, ${FAILED} failed"
[[ "$FAILED" -eq 0 ]]
