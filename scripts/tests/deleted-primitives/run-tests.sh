#!/usr/bin/env bash
# run-tests.sh — exercise check-deleted-primitives.sh against fixture trees.
#
# Each case builds a scratch root holding every scope directory the ban list
# names, writes one fixture file into it, and runs the gate with
# SCP_DELETED_PRIMITIVES_ROOT pointing at that root. A clean root must pass;
# each fixture must fail with its token in the output.
#
# Exit 0 if every case passes, 1 on any failure.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
CHECK="$REPO_ROOT/scripts/check-deleted-primitives.sh"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/deleted-primitives.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# Every scope directory a ban entry names (the second `|` field).
SCOPES=$(grep -E '^    "[^"]*\|[^|]+\|[^|]+\|' "$CHECK" | cut -d'|' -f2 | sort -u)

new_root() {
    local root="$WORK/$1"
    mkdir -p "$root"
    while IFS= read -r scope; do
        mkdir -p "$root/$scope"
    done <<< "$SCOPES"
    printf '%s' "$root"
}

passed=0
failed=0

run_case() {
    local name="$1" expected_exit="$2" expected_substr="$3" root="$4"
    local out actual_exit=0
    out=$(SCP_DELETED_PRIMITIVES_ROOT="$root" bash "$CHECK" 2>&1) || actual_exit=$?
    if [[ "$actual_exit" == "$expected_exit" && "$out" == *"$expected_substr"* ]]; then
        echo "PASS: $name"
        passed=$((passed + 1))
    else
        echo "FAIL: $name (exit $actual_exit, expected $expected_exit; want substring: $expected_substr)"
        printf '%s\n' "$out" | tail -20
        failed=$((failed + 1))
    fi
}

run_case "clean-root" 0 "PASSED" "$(new_root clean)"

# The export callback in either spelling, in binding files the per-language
# entries do not name: a Kotlin build script, a generated C header, and each
# spelling in the other language's files.
root=$(new_root kotlin-snake)
printf 'fun export_signing_key_bytes(): ByteArray = ByteArray(32)\n' > "$root/bindings/Custody.kt"
run_case "snake-case-in-kotlin" 1 "[export_signing_key_bytes] 1 match(es) in bindings (*)" "$root"

root=$(new_root swift-header)
mkdir -p "$root/bindings/swift/Sources"
printf 'void exportSigningKeyBytes(void);\n' > "$root/bindings/swift/Sources/scp.h"
run_case "camel-case-in-c-header" 1 "[exportSigningKeyBytes] 1 match(es) in bindings (*)" "$root"

root=$(new_root gradle-script)
printf 'tasks.register("exportSigningKeyBytes")\n' > "$root/bindings/build.gradle.kts"
run_case "camel-case-in-gradle-script" 1 "[exportSigningKeyBytes] 1 match(es) in bindings (*)" "$root"

# A deleted NodeConfig placeholder redefined, and a capability-trait bound
# given a default (the persistence spec's mandatory-selection rule,
# SCP-CAPSEL-8000, §17.17.1 Selection Requirements).
root=$(new_root noop-custody)
printf 'pub struct NoOpCustody;\n' > "$root/crates/lib.rs"
run_case "noop-custody-redefined" 1 "[struct NoOpCustody[[:space:];{<(]] 1 match(es) in crates (*.rs)" "$root"

root=$(new_root noop-did-method)
printf 'pub struct NoOpDidMethod;\n' > "$root/crates/lib.rs"
run_case "noop-did-method-redefined" 1 "[struct NoOpDidMethod[[:space:];{<(]] 1 match(es) in crates (*.rs)" "$root"

root=$(new_root noop-storage)
printf 'pub struct NoOpStorage;\n' > "$root/crates/lib.rs"
run_case "noop-storage-redefined" 1 "[struct NoOpStorage[[:space:];{<(]] 1 match(es) in crates (*.rs)" "$root"

root=$(new_root defaulted-custody)
printf 'pub struct NodeConfig<K: KeyCustody = X> {}\n' > "$root/crates/config.rs"
run_case "defaulted-custody-parameter" 1 "[:[[:space:]]*KeyCustody[[:space:]]*=[[:space:]]*[A-Za-z]] 1 match(es) in crates (*.rs)" "$root"

root=$(new_root defaulted-did-method)
printf 'struct C<D: DidMethod = X> {}\n' > "$root/crates/config.rs"
run_case "defaulted-did-method-parameter" 1 "[:[[:space:]]*DidMethod[[:space:]]*=[[:space:]]*[A-Za-z]] 1 match(es) in crates (*.rs)" "$root"

root=$(new_root defaulted-storage)
printf 'struct C<S: Storage = X> {}\n' > "$root/crates/config.rs"
run_case "defaulted-storage-parameter" 1 "[:[[:space:]]*Storage[[:space:]]*=[[:space:]]*[A-Za-z]] 1 match(es) in crates (*.rs)" "$root"

root=$(new_root defaulted-encrypted-storage)
printf 'struct C<S: EncryptedStorage = X> {}\n' > "$root/crates/config.rs"
run_case "defaulted-encrypted-storage-parameter" 1 "[:[[:space:]]*EncryptedStorage[[:space:]]*=[[:space:]]*[A-Za-z]] 1 match(es) in crates (*.rs)" "$root"

# A type alias that names a DID method is not a defaulted bound.
root=$(new_root did-method-alias)
printf 'pub type ConcreteDidMethod = DidDht<A, B>;\n' > "$root/crates/lib.rs"
run_case "did-method-alias-passes" 0 "PASSED" "$root"

echo ""
echo "deleted-primitives fixture tests: $passed passed, $failed failed"
[[ $failed -eq 0 ]]
