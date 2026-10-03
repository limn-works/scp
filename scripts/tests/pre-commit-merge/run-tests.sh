#!/usr/bin/env bash
# Cases for the language flags in scripts/hooks/pre-commit on a merge commit.
#
# THE CRITERION: the hook runs the Rust format and lint steps only when a Rust file this
# commit stages differs from the copy a merged-in head carries, or, on a commit that is not a
# merge, when the commit stages a Rust file at all. A merge that brings in a branch's Rust
# unchanged runs neither step, because that branch's CI already ran both over those files.
# The lint step also runs for a changed non-Rust path the clippy scope script selects, which
# `scripts/tests/pre-commit-clippy-scope/run-tests.sh` covers; no path these cases change
# meets that condition.
#
# Each case builds a throwaway repository in `mktemp -d`, copies the real hook and the real
# `scripts/pre-commit-clippy-scope.py` into it, and commits through that hook. `cargo` and
# `python3.12` are stubs on PATH that record their arguments and exit 0, so no case
# compiles anything; the case reads the record to learn which steps ran. The `python3.12`
# stub runs the real interpreter for the scope script, and the `cargo` stub answers
# `cargo metadata` with one workspace member in the fixture's `src/` directory. `scripts/check-resolved-rustc.sh` and `scripts/check-protocol-deps.sh`
# in the fixture are stubs that record the same way, so each case can also assert that the
# toolchain check ran on every commit.
set -euo pipefail

HOOK="$(cd "$(dirname "$0")/../.." && pwd)/hooks/pre-commit"
PASSED=0
FAILED=0

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A hook that runs this suite could export these, and each would point git at the outer
# repository instead of the fixture.
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES

STUBS="$WORK/bin"
LOG="$WORK/calls.log"
SCOPE="$(cd "$(dirname "$0")/../.." && pwd)/pre-commit-clippy-scope.py"
REAL_PYTHON="$(command -v python3.12)"
mkdir -p "$STUBS"
# The hook's clippy scope script asks `cargo metadata` for the member graph. The stub
# answers with one workspace member in `src/`, so a changed `.rs` file there selects that
# member and `docs/notes.md` selects nothing, and the stub runs the real interpreter for that script only.
cat > "$STUBS/cargo" <<EOF
#!/usr/bin/env bash
echo "cargo \$*" >> "$LOG"
if [ "\${1:-}" = metadata ]; then
  root="\$(pwd -P)"
  printf '{"workspace_root":"%s","workspace_members":["fixture"],"packages":[{"name":"fixture","id":"fixture","manifest_path":"%s/src/Cargo.toml","dependencies":[]}]}\n' "\$root" "\$root"
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

# new_repo <dir> — a repository on `main` holding one Rust file, one doc, and the hook.
new_repo() {
    local dir="$1"
    mkdir -p "$dir/src" "$dir/docs" "$dir/scripts/hooks"
    cd "$dir"
    git init -q -b main
    git config user.name "pre-commit-merge test"
    git config user.email "test@example.invalid"
    cp "$HOOK" scripts/hooks/pre-commit
    cp "$SCOPE" scripts/pre-commit-clippy-scope.py
    chmod +x scripts/hooks/pre-commit
    for stub in check-resolved-rustc.sh check-protocol-deps.sh; do
        printf '#!/usr/bin/env bash\necho "%s" >> "%s"\nexit 0\n' "$stub" "$LOG" > "scripts/$stub"
    done
    echo 'fn main() {}' > src/main.rs
    echo '# notes' > docs/notes.md
    git add -A
    git -c commit.gpgsign=false commit -q --no-verify -m "initial"
}

# assert_steps <name> <want-rust: yes|no>
assert_steps() {
    local name="$1" want="$2" got=no toolchain=no
    if command grep -q '^cargo clippy' "$LOG" 2>/dev/null; then got=yes; fi
    if command grep -q '^check-resolved-rustc.sh' "$LOG" 2>/dev/null; then toolchain=yes; fi
    if [[ "$got" == "$want" && "$toolchain" == yes ]]; then
        echo "  ok    ${name} (rust lint ran: ${got}, toolchain check ran: ${toolchain})"
        PASSED=$((PASSED + 1))
    else
        echo "  FAIL  ${name} (rust lint ran: ${got}, want ${want}; toolchain check ran: ${toolchain}, want yes)"
        sed 's/^/          /' "$LOG" 2>/dev/null || true
        FAILED=$((FAILED + 1))
    fi
}

# docs_branch_merging_rust_main <dir> — `main` changes the Rust file, `docs` changes the
# doc, and `docs` starts a merge of `main` without committing it.
docs_branch_merging_rust_main() {
    new_repo "$1"
    git checkout -q -b docs
    echo '# notes, revised' > docs/notes.md
    git -c commit.gpgsign=false commit -q --no-verify -am "docs change"
    git checkout -q main
    echo 'fn main() { println!("main"); }' > src/main.rs
    git -c commit.gpgsign=false commit -q --no-verify -am "rust change on main"
    git checkout -q docs
    git merge -q --no-ff --no-commit main >/dev/null 2>&1
}

echo "pre-commit — a merge runs a language step only for files that differ from the merged-in head"

# Case 1: the merge carries main's Rust unchanged.
docs_branch_merging_rust_main "$WORK/case1"
: > "$LOG"
g commit -q -m "merge main" >/dev/null
assert_steps "merge whose Rust matches MERGE_HEAD skips the Rust lint" no

# Case 2: the resolution edits the Rust file main brought in.
docs_branch_merging_rust_main "$WORK/case2"
echo 'fn main() { println!("resolved"); }' > src/main.rs
git add src/main.rs
: > "$LOG"
g commit -q -m "merge main, edit rust" >/dev/null
assert_steps "merge whose resolution changes a .rs file runs the Rust lint" yes

# Case 3: the merging branch itself changed a Rust file, so its copy differs from main's.
new_repo "$WORK/case3"
git checkout -q -b feature
echo 'pub fn lib() {}' > src/lib.rs
git add src/lib.rs
git -c commit.gpgsign=false commit -q --no-verify -m "rust change on feature"
git checkout -q main
echo '# notes, on main' > docs/notes.md
git -c commit.gpgsign=false commit -q --no-verify -am "docs change on main"
git checkout -q feature
git merge -q --no-ff --no-commit main >/dev/null 2>&1
# The resolution edits nothing, and the staged tree still differs from main in src/lib.rs,
# which main does not hold.
: > "$LOG"
g commit -q -m "merge main into feature" >/dev/null
assert_steps "merge where the branch's own .rs differs from MERGE_HEAD runs the Rust lint" yes

# Case 4: a plain commit that stages a Rust file.
new_repo "$WORK/case4"
echo 'fn main() { println!("plain"); }' > src/main.rs
git add src/main.rs
: > "$LOG"
g commit -q -m "plain rust commit" >/dev/null
assert_steps "plain commit staging a .rs file runs the Rust lint" yes

# Case 5: a plain commit that stages only a doc.
new_repo "$WORK/case5"
echo '# notes, plain' > docs/notes.md
git add docs/notes.md
: > "$LOG"
g commit -q -m "plain docs commit" >/dev/null
assert_steps "plain commit staging no .rs file skips the Rust lint" no

echo ""
echo "passed: ${PASSED}  failed: ${FAILED}"
[[ "$FAILED" -eq 0 ]]
