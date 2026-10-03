#!/usr/bin/env bash
# Cases for the clippy scope in scripts/hooks/pre-commit.
#
# THE CRITERION: the hook lints the workspace members that hold a path the commit changes,
# plus every member that depends on one of them, and lints the whole workspace when a
# changed path can change lints or dependency resolution for members the commit did not
# touch. `scripts/pre-commit-clippy-scope.py` states the criterion in full.
#
# Each case builds a throwaway repository in `mktemp -d`, copies the real hook and the real
# scope script into it, and commits through that hook. `cargo` is a stub on PATH that
# records its arguments and exits 0; for `cargo metadata` it prints `metadata.json` beside
# this file, a member graph recorded from this workspace with its root replaced by
# `@ROOT@`. `python3.12` is a stub that records its arguments and runs the real interpreter
# only for the scope script. Each case reads the recorded `cargo clippy` command line and
# compares it with the exact command the criterion requires.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
HOOK="$REPO_ROOT/scripts/hooks/pre-commit"
SCOPE="$REPO_ROOT/scripts/pre-commit-clippy-scope.py"
METADATA="$HERE/metadata.json"
REAL_PYTHON="$(command -v python3.12)"
PASSED=0
FAILED=0

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A hook that runs this suite could export these, and each would point git at the outer
# repository instead of the fixture.
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES

STUBS="$WORK/bin"
LOG="$WORK/calls.log"
mkdir -p "$STUBS"
cat > "$STUBS/cargo" <<EOF
#!/usr/bin/env bash
echo "cargo \$*" >> "$LOG"
if [ "\${1:-}" = metadata ]; then
  if [ -n "\${SCOPE_TEST_METADATA_FAILS:-}" ]; then
    echo "error: failed to parse manifest" >&2
    exit 101
  fi
  sed "s#@ROOT@#\$(pwd -P)#g" "$METADATA"
fi
exit 0
EOF
cat > "$STUBS/python3.12" <<EOF
#!/usr/bin/env bash
echo "python3.12 \$*" >> "$LOG"
if [ "\${1:-}" = scripts/pre-commit-clippy-scope.py ]; then
  exec "$REAL_PYTHON" "\$@"
fi
exit 0
EOF
chmod +x "$STUBS/cargo" "$STUBS/python3.12"
export PATH="$STUBS:$PATH"

g() { git -c commit.gpgsign=false -c core.hooksPath=scripts/hooks "$@"; }

# new_repo <dir> — a repository on `main` holding one file per path the cases edit.
new_repo() {
    local dir="$1" f
    mkdir -p "$dir/scripts/hooks"
    cd "$dir"
    git init -q -b main
    git config user.name "pre-commit-clippy-scope test"
    git config user.email "test@example.invalid"
    cp "$HOOK" scripts/hooks/pre-commit
    chmod +x scripts/hooks/pre-commit
    cp "$SCOPE" scripts/pre-commit-clippy-scope.py
    for stub in check-resolved-rustc.sh check-protocol-deps.sh; do
        printf '#!/usr/bin/env bash\necho "%s" >> "%s"\nexit 0\n' "$stub" "$LOG" > "scripts/$stub"
    done
    for f in Cargo.toml crates/scp-relay/Cargo.toml crates/scp-relay/src/main.rs \
        crates/scp-relay/src/extra.rs crates/scp-protocol/src/lib.rs fuzz/src/lib.rs docs/notes.md; do
        mkdir -p "$(dirname "$f")"
        echo "// $f" > "$f"
    done
    git add -A
    git -c commit.gpgsign=false commit -q --no-verify -m "initial"
}

# edit <path> — change one line of a file and stage it.
edit() {
    echo "// edited $RANDOM" >> "$1"
    git add "$1"
}

ALL_FEATURES="scp-ffi-uniffi/testing,scp-ffi/testing,scp-ffi-napi/testing,scp-core/testing,scp-runtime/testing"
TAIL="--all-targets -- -D warnings"
# Every member whose library or tests compile against scp-protocol's library, read off the
# recorded graph by hand: scp-clock, scp-crypto, scp-did, scp-dht, scp-event-log, and
# scp-ffi-napi-test-stubs are the six members scp-protocol does not reach.
PROTOCOL_MEMBERS="scp-client scp-client-wasm scp-core scp-ffi scp-ffi-common scp-ffi-napi scp-ffi-uniffi scp-identity scp-mcp scp-media scp-mls scp-node scp-platform scp-protocol scp-relay scp-relay-client scp-relay-mock scp-runtime scp-testing scp-transport"
PROTOCOL_ARGS=""
for m in $PROTOCOL_MEMBERS; do PROTOCOL_ARGS="$PROTOCOL_ARGS -p $m"; done

# assert_clippy <name> <want: the exact `cargo clippy` line, or "none">
# Also requires that the toolchain check ran, and that both protocol checks ran, because
# the hook runs those whenever a `.rs` file changed, whatever the clippy scope is.
assert_clippy() {
    local name="$1" want="$2" got checks=yes
    got="$(command grep '^cargo clippy' "$LOG" 2>/dev/null || true)"
    [ -z "$got" ] && got=none
    for step in check-resolved-rustc.sh check-protocol-deps.sh "python3.12 scripts/check-protocol-sync.py"; do
        if ! command grep -q "^$step" "$LOG" 2>/dev/null; then checks="no ($step missing)"; fi
    done
    if [[ "$got" == "$want" && "$checks" == yes ]]; then
        echo "  ok    ${name}"
        PASSED=$((PASSED + 1))
    else
        echo "  FAIL  ${name}"
        echo "          want: ${want}"
        echo "          got:  ${got}"
        echo "          toolchain and protocol checks ran: ${checks}"
        FAILED=$((FAILED + 1))
    fi
}

echo "pre-commit — clippy lints the changed members and their dependents"

# Case 1: a leaf crate, which no member depends on.
new_repo "$WORK/leaf"
edit crates/scp-relay/src/main.rs
: > "$LOG"
g commit -q -m "leaf change" >/dev/null
assert_clippy "a change in leaf crate scp-relay lints scp-relay only" \
    "cargo clippy -p scp-relay $TAIL"

# Case 2: scp-protocol, which most members depend on.
new_repo "$WORK/protocol"
edit crates/scp-protocol/src/lib.rs
: > "$LOG"
g commit -q -m "protocol change" >/dev/null
assert_clippy "a change in scp-protocol lints scp-protocol and every member depending on it" \
    "cargo clippy${PROTOCOL_ARGS} --features $ALL_FEATURES $TAIL"

# Case 3: the root manifest beside a leaf change.
new_repo "$WORK/manifest"
edit Cargo.toml
edit crates/scp-relay/src/main.rs
: > "$LOG"
g commit -q -m "manifest change" >/dev/null
assert_clippy "a root Cargo.toml change lints the whole workspace" \
    "cargo clippy --workspace --features $ALL_FEATURES $TAIL"

# Case 4: a member manifest beside a change in that member.
new_repo "$WORK/member-manifest"
edit crates/scp-relay/Cargo.toml
edit crates/scp-relay/src/main.rs
: > "$LOG"
g commit -q -m "member manifest change" >/dev/null
assert_clippy "a member Cargo.toml change lints the whole workspace" \
    "cargo clippy --workspace --features $ALL_FEATURES $TAIL"

# Case 5: a .rs file in the standalone fuzz workspace.
new_repo "$WORK/fuzz"
edit fuzz/src/lib.rs
: > "$LOG"
g commit -q -m "fuzz change" >/dev/null
assert_clippy "a change only under fuzz/ runs no clippy and the commit succeeds" none

# Case 6: a commit that only deletes a .rs file changes what its crate compiles.
new_repo "$WORK/delete"
git rm -q crates/scp-relay/src/extra.rs
: > "$LOG"
g commit -q -m "delete a relay module" >/dev/null
assert_clippy "a commit that only deletes a .rs file in scp-relay lints scp-relay" \
    "cargo clippy -p scp-relay $TAIL"

# Case 7: a commit that only renames a .rs file out of scp-relay into the fuzz workspace.
new_repo "$WORK/rename"
mkdir -p fuzz/src
git mv crates/scp-relay/src/extra.rs fuzz/src/extra.rs
: > "$LOG"
g commit -q -m "move a relay module" >/dev/null
assert_clippy "a commit that only moves a .rs file out of scp-relay lints scp-relay" \
    "cargo clippy -p scp-relay $TAIL"

# Case 8: a merge. `feature` changes scp-relay, `main` changes scp-protocol, and `feature`
# merges `main`. Only scp-relay differs from the merged-in head, so only scp-relay is
# linted; a selection read from every staged path would also lint scp-protocol's dependents.
new_repo "$WORK/merge"
git checkout -q -b feature
edit crates/scp-relay/src/main.rs
git -c commit.gpgsign=false commit -q --no-verify -m "relay change on feature"
git checkout -q main
edit crates/scp-protocol/src/lib.rs
git -c commit.gpgsign=false commit -q --no-verify -m "protocol change on main"
git checkout -q feature
git merge -q --no-ff --no-commit main >/dev/null 2>&1
: > "$LOG"
g commit -q -m "merge main into feature" >/dev/null
assert_clippy "a merge selects from the files that differ from the merged-in head" \
    "cargo clippy -p scp-relay $TAIL"

# Case 9: cargo metadata fails, so the hook cannot read the member graph and must fail.
new_repo "$WORK/metadata-fails"
edit crates/scp-relay/src/main.rs
: > "$LOG"
if SCOPE_TEST_METADATA_FAILS=1 g commit -q -m "metadata fails" >/dev/null 2>&1; then
    echo "  FAIL  a commit whose clippy scope cannot be computed is rejected (the commit succeeded)"
    FAILED=$((FAILED + 1))
else
    echo "  ok    a commit whose clippy scope cannot be computed is rejected"
    PASSED=$((PASSED + 1))
fi

echo ""
echo "passed: ${PASSED}  failed: ${FAILED}"
[[ "$FAILED" -eq 0 ]]
