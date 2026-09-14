#!/usr/bin/env bash
# run-tests.sh — hold `scripts/fix-round-check.sh` to its two contract clauses.
#
# WHAT THIS TESTS, and why each case exists.
#
#   * THE REFUSAL. The script exits non-zero and starts no cargo command when the compiler
#     answering in this repository is not the version `rust-toolchain.toml` names. Case 1
#     puts a compiler reporting 1.2.3 on PATH and asserts both halves: the exit code, and
#     an empty invocation log from the stub cargo. The second half is the one that matters,
#     because a script that reports the mismatch and compiles anyway produces a result on
#     the wrong compiler while printing a line that says so, which
#     `.docs/lessons/pin-the-rust-toolchain-or-ci-drifts-from-local.md` records as the
#     failure that blocked the merge queue: a clippy run on a compiler the repository does
#     not name exits 0 and proves nothing.
#
#   * THE PROPAGATION. A non-zero exit from any step is a non-zero exit from the script.
#     The script runs four steps, and one case fails each: case 1 the toolchain step, case
#     2 the compile step, case 5 the format step, and case 6 the gates step. Each asserts
#     that the script exits non-zero, names that step as failed, and leaves the steps that
#     passed reported as passing. Case 3 fails nothing and asserts that the script exits 0
#     and names every step as passing.
#
#     EACH DIRECTION GUARDS THE OTHER. Case 3 exists so the failing cases are not vacuous:
#     without it, a script that always failed would satisfy every one of them. The failing
#     cases exist so case 3 is not vacuous, and two revisions of this file proved that they
#     are needed rather than tidy. One fixed the stub's `fmt` answer at 0, which left a
#     mutation that discards the format step's failure passing every assertion here. The
#     next covered three steps and not the gates step, which left a mutation deleting
#     `FAILED=1` from the gate-failure branch passing every assertion here.
#
#   * THE DERIVATION. Naming no crate makes the script read which files this branch
#     changed and compile the crates that own them, and cases 1, 2, 3, 4, 5 and 6 each name
#     one, so none of them reaches that code. Cases 7, 8 and 9 run the script with no
#     argument. Each runs a copy of it inside a fixture repository this harness builds under
#     a temporary directory, because `scripts/fix-round-check.sh` reads the repository that
#     holds it and this checkout's changed-file set is whatever the developer running this
#     suite has edited.
#
#     Case 7 asserts the derived set against a fixture holding one uncommitted edit and one
#     committed edit: both reach the set, `crates/scp-ffi/napi/src/lib.rs` resolves to
#     `scp-ffi-napi` rather than to `scp-ffi`, and the compile command carries the two
#     features that package owns and no feature of any other package.
#
#     Case 8 removes the fixture's `origin/main` ref and asserts that the run exits
#     non-zero and starts no `cargo check`. That is the fail-open the comment above
#     `changed_files` in `scripts/fix-round-check.sh` records: an earlier revision discarded
#     that git error, derived an empty crate set, skipped the compile step, and exited 0 on
#     a branch whose commits changed crate sources.
#
#     Case 9 changes one file that no crate directory holds and asserts the honest other
#     half of the same branch: the run skips the compile step, names in its summary that the
#     branch changed no file inside a workspace crate, and exits 0.
#
#   * THE MISSING GATE. A gate the runner's list names but the repository does not hold has
#     to fail the run. Case 3 runs against this repository, where all 28 exist, so it cannot
#     reach that branch. Case 10 deletes one gate from a fixture and asserts that the run
#     names it and exits non-zero.
#
# WHAT THE STUBS REPLACE, and what stays real. The cases replace `cargo`, `rustc`, and
# `rustup` with scripts on a PATH this harness leads with, because the contract clauses
# above are about what the script does with those three programs' answers, and a real
# `cargo check` of this workspace costs between ten minutes and an hour on a developer
# machine. Everything else stays real: case 3 runs the 28 enforcement gates
# `scripts/fix-round-check.sh` names against this repository's own files, so a gate the
# list names but the repository does not hold fails this test rather than being skipped.
#
# WHY THE PINNED VERSION IS READ RATHER THAN WRITTEN. Case 2 and case 3 need a `rustc` that
# agrees with the pin. The harness reads the channel out of `rust-toolchain.toml` at run
# time, so raising the pin does not turn these two cases into copies of case 1.
#
# WHO RUNS THIS SUITE. The `fix-round-check-selftest` job of `.github/workflows/ci.yml`
# runs it on every pull-request head, which is the head every fix round pushes. That job
# names no merge_group event, for the reason its own comment gives: one of the 28 gates
# case 3 runs reads an exemption out of the pull request's body, and a merge_group event
# publishes no body. The job installs what case 3 needs: the tree-sitter
# grammars nine Python gates parse with, the ruff `scripts/check-pyi-generated.sh` runs,
# the jq `scripts/check-bridge-symmetry.sh` requires, a Rust toolchain for the twelve
# `cargo tree` resolutions two gates run, and the base ref `scripts/check-cross-layer.sh`
# diffs against. A developer runs the same command by hand.
#
# Usage: bash scripts/tests/fix-round-check/run-tests.sh
# Exit: 0 when every case passes, 1 otherwise.

set -uo pipefail

if ! cd "$(dirname "$0")/../../.."; then
    printf 'run-tests: could not enter the repository root, so no case ran.\n' >&2
    exit 1
fi
REPO_ROOT=$(pwd -P)
SCRIPT="$REPO_ROOT/scripts/fix-round-check.sh"

if [[ ! -f $SCRIPT ]]; then
    printf 'run-tests: %s does not exist, so no case ran.\n' "$SCRIPT" >&2
    exit 1
fi

PIN_CHANNEL=$(sed -nE 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' "$REPO_ROOT/rust-toolchain.toml" | head -n 1)
if [[ -z $PIN_CHANNEL ]]; then
    printf 'run-tests: rust-toolchain.toml names no channel, so the cases have no version to agree with.\n' >&2
    exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
    printf 'run-tests: cargo is not on PATH, and the stub delegates `cargo tree` to it, so no case ran.\n' >&2
    exit 1
fi

FAILURES=0
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# Build a stub directory for one case.
#
#   $1 the directory the stubs go under, which also holds that case's cargo.log
#   $2 the version string the stub `rustc` reports
#   $3 the exit code the stub `cargo` returns for `cargo check`
#   $4 the exit code the stub `cargo` returns for `cargo fmt`
#   $5 the exit code a stub `python3.12` returns, or the empty string for no such stub
#
# The stub `cargo` answers `check`, `fmt`, and `metadata` itself and hands every other
# subcommand to the real cargo this harness found before it led PATH with the stub.
#
# WHICH SUBCOMMANDS THE STUB ANSWERS, and the criterion that decides: a subcommand belongs
# to the stub when the real one waits on the shared target directory's build lock, because
# this harness must finish in a bounded time on a machine where some other worktree is
# always compiling. `cargo check` waits by definition. `cargo fmt` waits because it resolves
# the workspace through a full `cargo metadata` first, and `cargo metadata` waits for the
# same reason. Measured on 2026-09-13: an earlier revision of this file delegated `fmt`, and
# one case sat in it for 87 minutes behind another worktree's `cargo clippy --workspace`
# until a 2400-second bound killed the run after case 1.
#
# `cargo tree` stays delegated, so the twelve resolutions inside
# `scripts/check-shipped-feature-graph.sh` and `scripts/check-protocol-deps.sh` read this
# repository and case 3 fails when either gate rejects the tree. `cargo tree` takes no build
# lock: measured at 12.9 seconds and 391 ms for those two gates while another worktree held
# it.
#
# WHAT THE STUBBED STEPS STILL PROVE. These cases test what the script does with a step's
# exit code, not whether cargo formats correctly. `.github/workflows/ci.yml` runs the real
# `cargo fmt --all -- --check` in its `rust-fmt` job on every pushed head.
#
# The stub appends its argument list to `$WORK/<case>/cargo.log`, so a case can assert that
# no cargo command ran.
#
# `rustc` and `rustup` are written as two separate files on purpose:
# `scripts/check-resolved-rustc.sh` skips its comparison only where the two names read one
# file that rustup installed, and two distinct files put it on the path that compares.
write_stubs() {
    local dir=$1 rustc_version=$2 cargo_check_rc=$3 cargo_fmt_rc=$4 python_rc=$5
    mkdir -p "$dir/bin"

    # A stub `python3.12` fails the gates step and no other.
    # `scripts/fix-round-check.sh` resolves its interpreter through
    # `command -v python3.12`, and nine of the 28 entries in its gate list run under it, so
    # a case that plants a failing one makes the gates step fail while the compile and
    # format steps pass. Cases that pass nothing here plant no such file and run the real
    # interpreter.
    if [[ -n $python_rc ]]; then
        cat > "$dir/bin/python3.12" <<EOF
#!/usr/bin/env bash
printf 'stub python3.12 refusing to run %s\n' "\$*" >&2
exit $python_rc
EOF
        chmod +x "$dir/bin/python3.12"
    fi

    cat > "$dir/bin/rustc" <<EOF
#!/usr/bin/env bash
printf 'rustc %s (0000000000 2020-01-01)\n' "$rustc_version"
EOF

    cat > "$dir/bin/rustup" <<'EOF'
#!/usr/bin/env bash
# A rustup that answers nothing. `scripts/check-resolved-rustc.sh` reads a failing
# subcommand as proof of nothing and compares the compiler, which is what these cases want.
exit 1
EOF

    cat > "$dir/bin/cargo" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$dir/cargo.log"
case "\$1" in
    check) exit $cargo_check_rc ;;
    fmt) exit $cargo_fmt_rc ;;
    metadata) printf '{"version":1,"target_directory":"$dir/stub-target-dir"}\n'; exit 0 ;;
esac
# Delegating means removing this directory from PATH first. The cargo on PATH here is a
# mise shim, and a shim re-resolves its tool through PATH, so a stub that kept itself on
# PATH and exec'd that shim got the shim back into the stub. Each hop added mise's exported
# environment, and after enough hops execve refused the call with "Argument list too long";
# the calling gate read that as a cargo failure and retried, which spun. Measured on
# 2026-09-13: one gate logged 17 identical \`cargo tree\` invocations in under ten minutes.
export PATH="\${PATH#"$dir/bin:"}"
exec cargo "\$@"
EOF

    chmod +x "$dir/bin/rustc" "$dir/bin/rustup" "$dir/bin/cargo"
}

# Run this repository's own `scripts/fix-round-check.sh` against one named crate, under the
# stubs above.
run_case() {
    local case_name=$1 rustc_version=$2 cargo_check_rc=$3 cargo_fmt_rc=${4:-0} python_rc=${5:-}
    local dir="$WORK/$case_name"
    write_stubs "$dir" "$rustc_version" "$cargo_check_rc" "$cargo_fmt_rc" "$python_rc"
    PATH="$dir/bin:$PATH" bash "$SCRIPT" scp-clock > "$dir/out.txt" 2>&1
    printf '%s' $? > "$dir/rc.txt"
}

# The gate paths `scripts/fix-round-check.sh` names, read out of its own GATES array. A
# fixture repository holds no enforcement gate, and the script counts a gate its list names
# but the repository does not hold as a failure, so each fixture plants an empty file at
# every one of those paths. An empty file is a program under both `bash` and `python3.12`,
# which are the two runners that array selects between, and it exits 0 under each.
gate_paths() {
    sed -n '/^GATES=(/,/^)/p' "$SCRIPT" | sed -nE 's|^[[:space:]]+(scripts/[^[:space:]]+)$|\1|p'
}

# Build a repository that is not this one, so a case decides which files its branch changed.
#
#   $1 the fixture directory
#
# `scripts/fix-round-check.sh` reads the repository holding it, through
# `cd "$(dirname "$0")/.."`, so each fixture holds a copy of that script, a copy of the
# resolved-compiler check that script runs as its first step, and a copy of
# `rust-toolchain.toml`, which that step reads.
#
# The fixture holds three manifests whose directories nest — `crates/scp-ffi` contains
# `crates/scp-ffi/napi` — because the longest-prefix rule in `crate_of_path` is what maps a
# napi source file to `scp-ffi-napi`, and a fixture with no nesting cannot separate that
# answer from `scp-ffi`. It also holds one file under no crate directory, which case 9
# changes.
#
# The commit passes `--no-gpg-sign` and `--no-verify` because a developer's global git
# configuration may sign every commit and may point `core.hooksPath` at this repository's
# hooks, and this fixture wants neither. `git update-ref` writes the remote-tracking ref
# `changed_files` takes its merge base against, so the fixture needs no network.
build_fixture() {
    local root=$1 g
    mkdir -p "$root/scripts" "$root/crates/scp-clock/src" "$root/crates/scp-ffi/src" \
        "$root/crates/scp-ffi/napi/src" "$root/notes"
    cp "$SCRIPT" "$root/scripts/fix-round-check.sh"
    cp "$REPO_ROOT/scripts/check-resolved-rustc.sh" "$root/scripts/check-resolved-rustc.sh"
    cp "$REPO_ROOT/rust-toolchain.toml" "$root/rust-toolchain.toml"

    while IFS= read -r g; do
        [[ -n $g ]] || continue
        mkdir -p "$root/$(dirname "$g")"
        : > "$root/$g"
    done < <(gate_paths)

    printf '[package]\nname = "scp-clock"\nversion = "0.0.0"\n' > "$root/crates/scp-clock/Cargo.toml"
    printf '[package]\nname = "scp-ffi"\nversion = "0.0.0"\n' > "$root/crates/scp-ffi/Cargo.toml"
    printf '[package]\nname = "scp-ffi-napi"\nversion = "0.0.0"\n' > "$root/crates/scp-ffi/napi/Cargo.toml"
    printf '// fixture source\n' > "$root/crates/scp-clock/src/lib.rs"
    printf '// fixture source\n' > "$root/crates/scp-ffi/src/lib.rs"
    printf '// fixture source\n' > "$root/crates/scp-ffi/napi/src/lib.rs"
    printf 'fixture note\n' > "$root/notes/note.md"

    git -C "$root" init -q -b main
    git -C "$root" add -A
    git -C "$root" -c user.email=fix-round-check@example.invalid -c user.name='fix-round-check tests' \
        commit -q --no-gpg-sign --no-verify -m 'fixture base'
    git -C "$root" update-ref refs/remotes/origin/main HEAD
}

# Append one line to a fixture file and commit it, so the merge-base half of
# `changed_files` reads that path.
fixture_commit() {
    local root=$1 path=$2
    printf '// committed edit\n' >> "$root/$path"
    git -C "$root" add -A
    git -C "$root" -c user.email=fix-round-check@example.invalid -c user.name='fix-round-check tests' \
        commit -q --no-gpg-sign --no-verify -m 'fixture edit'
}

# Run a fixture's own copy of the script with no crate argument, under stubs that pass.
#
# The stubs, the invocation log, and the two output files sit in `<fixture>.harness`, beside
# the fixture rather than inside it, because the run derives its crate set from
# `git status --porcelain` of the fixture and every file this harness wrote there would join
# that set as an untracked path. Each case reads the three files back from that directory.
run_fixture() {
    local root=$1 harness="$1.harness"
    write_stubs "$harness" "$PIN_CHANNEL" 0 0 ""
    PATH="$harness/bin:$PATH" bash "$root/scripts/fix-round-check.sh" > "$harness/out.txt" 2>&1
    printf '%s' $? > "$harness/rc.txt"
}

report() {
    local name=$1 ok=$2 detail=$3
    if [[ $ok -eq 0 ]]; then
        printf '  ok   %s\n' "$name"
    else
        printf '  FAIL %s — %s\n' "$name" "$detail" >&2
        FAILURES=$((FAILURES + 1))
    fi
}

printf 'fix-round-check tests (pin %s)\n' "$PIN_CHANNEL"

# ── Case 1: the refusal ──────────────────────────────────────────────────────────────
run_case wrong-toolchain 1.2.3 0
rc=$(cat "$WORK/wrong-toolchain/rc.txt")
if [[ $rc -eq 0 ]]; then
    report "case 1 exits non-zero on a compiler the pin does not name" 1 "the script exited 0"
else
    report "case 1 exits non-zero on a compiler the pin does not name" 0 ""
fi
if [[ -s "$WORK/wrong-toolchain/cargo.log" ]]; then
    report "case 1 starts no cargo command" 1 "the stub cargo ran: $(tr '\n' '|' < "$WORK/wrong-toolchain/cargo.log")"
else
    report "case 1 starts no cargo command" 0 ""
fi
if grep -q '1\.2\.3' "$WORK/wrong-toolchain/out.txt"; then
    report "case 1 names the compiler it found" 0 ""
else
    report "case 1 names the compiler it found" 1 "the output never mentions 1.2.3"
fi

# ── Case 2: the propagation ──────────────────────────────────────────────────────────
run_case failing-compile "$PIN_CHANNEL" 1
rc=$(cat "$WORK/failing-compile/rc.txt")
if [[ $rc -eq 0 ]]; then
    report "case 2 exits non-zero when cargo check fails" 1 "the script exited 0"
else
    report "case 2 exits non-zero when cargo check fails" 0 ""
fi
if grep -q 'compile FAILED' "$WORK/failing-compile/out.txt"; then
    report "case 2 names the compile step as failed" 0 ""
else
    report "case 2 names the compile step as failed" 1 "the summary holds no 'compile FAILED': $(tail -n 3 "$WORK/failing-compile/out.txt")"
fi
if grep -q '^check ' "$WORK/failing-compile/cargo.log"; then
    report "case 2 ran cargo check" 0 ""
else
    report "case 2 ran cargo check" 1 "the stub cargo log holds no check invocation"
fi

# ── Case 3: the control ──────────────────────────────────────────────────────────────
run_case passing "$PIN_CHANNEL" 0
rc=$(cat "$WORK/passing/rc.txt")
if [[ $rc -eq 0 ]]; then
    report "case 3 exits 0 when every step passes" 0 ""
else
    report "case 3 exits 0 when every step passes" 1 "the script exited $rc; output tail: $(tail -n 6 "$WORK/passing/out.txt")"
fi
if grep -q 'compile ok' "$WORK/passing/out.txt"; then
    report "case 3 names the compile step as passing" 0 ""
else
    report "case 3 names the compile step as passing" 1 "the summary holds no 'compile ok': $(tail -n 3 "$WORK/passing/out.txt")"
fi
if grep -q 'format ok' "$WORK/passing/out.txt"; then
    report "case 3 names the format step as passing" 0 ""
else
    report "case 3 names the format step as passing" 1 "the summary holds no 'format ok': $(tail -n 3 "$WORK/passing/out.txt")"
fi
if grep -q 'gates 28/28 passed' "$WORK/passing/out.txt"; then
    report "case 3 ran all 28 gates against this repository" 0 ""
else
    report "case 3 ran all 28 gates against this repository" 1 "the summary holds no 'gates 28/28 passed': $(tail -n 3 "$WORK/passing/out.txt")"
fi

# ── Case 5: the format step's failure reaches the exit code ──────────────────────────
#
# Case 2 fails only the compile step, so without this case the suite proves propagation
# from one step and nothing about the rest. The mutation it kills: replacing the format
# step's `run_step` call with a bare `cargo fmt --all -- --check` followed by
# `RAN+=("format ok 0s")` drops that step's failure on the floor, and every other assertion
# in this file still passes.
run_case failing-format "$PIN_CHANNEL" 0 1
rc=$(cat "$WORK/failing-format/rc.txt")
if [[ $rc -eq 0 ]]; then
    report "case 5 exits non-zero when cargo fmt fails" 1 "the script exited 0"
else
    report "case 5 exits non-zero when cargo fmt fails" 0 ""
fi
if grep -q 'format FAILED' "$WORK/failing-format/out.txt"; then
    report "case 5 names the format step as failed" 0 ""
else
    report "case 5 names the format step as failed" 1 "the summary holds no 'format FAILED': $(tail -n 3 "$WORK/failing-format/out.txt")"
fi
if grep -q 'compile ok' "$WORK/failing-format/out.txt"; then
    report "case 5 leaves the passing compile step reported as passing" 0 ""
else
    report "case 5 leaves the passing compile step reported as passing" 1 "the summary holds no 'compile ok': $(tail -n 3 "$WORK/failing-format/out.txt")"
fi

# ── Case 6: a failing gate reaches the exit code ─────────────────────────────────────
#
# Cases 2 and 5 fail the compile and format steps, and until this case no case failed a
# gate. The mutation it kills: deleting `FAILED=1` from the gate-failure branch of
# `scripts/fix-round-check.sh` lets a run print every failing gate, report the count in its
# summary, and still exit 0, which every other assertion in this file permits.
run_case failing-gate "$PIN_CHANNEL" 0 0 1
rc=$(cat "$WORK/failing-gate/rc.txt")
if [[ $rc -eq 0 ]]; then
    report "case 6 exits non-zero when a gate fails" 1 "the script exited 0"
else
    report "case 6 exits non-zero when a gate fails" 0 ""
fi
if grep -qE 'gates [0-9]+/[0-9]+ passed, [0-9]+ FAILED' "$WORK/failing-gate/out.txt"; then
    report "case 6 counts the failing gates in the summary" 0 ""
else
    report "case 6 counts the failing gates in the summary" 1 "the summary holds no gate-failure count: $(tail -n 3 "$WORK/failing-gate/out.txt")"
fi
if grep -q 'compile ok' "$WORK/failing-gate/out.txt"; then
    report "case 6 leaves the compile step reported as passing" 0 ""
else
    report "case 6 leaves the compile step reported as passing" 1 "the summary holds no 'compile ok': $(tail -n 3 "$WORK/failing-gate/out.txt")"
fi

# ── Case 4: an unknown crate ─────────────────────────────────────────────────────────
#
# Naming a package the workspace does not hold has to fail rather than check a smaller set,
# because a fix agent that mistypes a crate name would otherwise read a green result that
# compiled none of its edits.
write_stubs "$WORK/unknown-crate" "$PIN_CHANNEL" 0 0 ""
PATH="$WORK/unknown-crate/bin:$PATH" bash "$SCRIPT" scp-not-a-crate > "$WORK/unknown-crate/out.txt" 2>&1
rc=$?
if [[ $rc -eq 0 ]]; then
    report "case 4 rejects a package the workspace does not hold" 1 "the script exited 0"
else
    report "case 4 rejects a package the workspace does not hold" 0 ""
fi

# ── Case 7: the crate set derived from the files the branch changed ──────────────────
#
# Cases 1 through 6 each name a crate, so each takes the `$# -gt 0` branch and none of them
# runs `changed_files` or `crate_of_path`. This case runs the derivation against a fixture
# whose changed files it chose: one uncommitted edit under `crates/scp-clock`, and one
# committed edit under `crates/scp-ffi/napi`.
#
# The mutations it kills: dropping the `git diff "$base" HEAD` line leaves `scp-ffi-napi`
# out of the derived set, dropping the `git status --porcelain` line leaves `scp-clock` out,
# and replacing the longest-prefix comparison in `crate_of_path` with a first-match loop
# resolves the napi source file to `scp-ffi` and selects a package that owns none of the
# edits.
FIXTURE7="$WORK/derives-crates"
build_fixture "$FIXTURE7"
fixture_commit "$FIXTURE7" crates/scp-ffi/napi/src/lib.rs
printf '// uncommitted edit\n' >> "$FIXTURE7/crates/scp-clock/src/lib.rs"
run_fixture "$FIXTURE7"
rc=$(cat "$FIXTURE7.harness/rc.txt")
if [[ $rc -eq 0 ]]; then
    report "case 7 exits 0 when the derived crates compile" 0 ""
else
    report "case 7 exits 0 when the derived crates compile" 1 "the script exited $rc; output tail: $(tail -n 6 "$FIXTURE7.harness/out.txt")"
fi
if grep -qF 'crates scp-clock scp-ffi-napi (derived from the files this branch changed)' "$FIXTURE7.harness/out.txt"; then
    report "case 7 derives both edited crates and neither of the two it did not edit" 0 ""
else
    report "case 7 derives both edited crates and neither of the two it did not edit" 1 "the summary names another crate set: $(tail -n 3 "$FIXTURE7.harness/out.txt")"
fi
if grep -qF 'check -p scp-clock -p scp-ffi-napi --all-targets --features scp-ffi-napi/testing,scp-ffi-napi/outlet-capability-test-grant' "$FIXTURE7.harness/cargo.log"; then
    report "case 7 compiles the derived crates with the features they own" 0 ""
else
    report "case 7 compiles the derived crates with the features they own" 1 "the stub cargo log holds: $(tr '\n' '|' < "$FIXTURE7.harness/cargo.log")"
fi

# ── Case 8: no origin/main ref ───────────────────────────────────────────────────────
#
# The fixture holds an uncommitted edit under `crates/scp-clock`, so the working-tree half
# of `changed_files` would derive a crate, and then the merge-base call fails. The run has
# to end there: a committed edit this checkout cannot read would otherwise go uncompiled
# under a green verdict, which is the shape the comment above `changed_files` records.
#
# The mutation it kills: dropping the `return 1` from that failure branch, so
# `changed_files` returns 0 having listed the working tree alone, makes this run derive
# `scp-clock` by itself, compile it, and exit 0 over an unread committed edit.
FIXTURE8="$WORK/no-origin-main"
build_fixture "$FIXTURE8"
fixture_commit "$FIXTURE8" crates/scp-ffi/napi/src/lib.rs
printf '// uncommitted edit\n' >> "$FIXTURE8/crates/scp-clock/src/lib.rs"
git -C "$FIXTURE8" update-ref -d refs/remotes/origin/main
run_fixture "$FIXTURE8"
rc=$(cat "$FIXTURE8.harness/rc.txt")
if [[ $rc -eq 0 ]]; then
    report "case 8 exits non-zero when the checkout holds no merge base with origin/main" 1 "the script exited 0"
else
    report "case 8 exits non-zero when the checkout holds no merge base with origin/main" 0 ""
fi
if grep -q '^check ' "$FIXTURE8.harness/cargo.log" 2>/dev/null; then
    report "case 8 starts no cargo check" 1 "the stub cargo log holds: $(tr '\n' '|' < "$FIXTURE8.harness/cargo.log")"
else
    report "case 8 starts no cargo check" 0 ""
fi
if grep -qF 'holds no merge base between HEAD and origin/main' "$FIXTURE8.harness/out.txt"; then
    report "case 8 names the ref it could not read" 0 ""
else
    report "case 8 names the ref it could not read" 1 "the output never names the missing merge base: $(tail -n 3 "$FIXTURE8.harness/out.txt")"
fi

# ── Case 9: a branch that changed no file inside a crate ─────────────────────────────
#
# Case 8 asserts that a derivation which could not read the branch's files fails. This case
# asserts the other half: a derivation that read them and found no crate source among them
# skips the compile step, says so, and exits 0. Without it, a script that failed on every
# empty crate set would satisfy case 8 and tell a fix agent editing only documentation that
# its round is broken.
FIXTURE9="$WORK/no-crate-files"
build_fixture "$FIXTURE9"
fixture_commit "$FIXTURE9" notes/note.md
printf 'uncommitted note\n' >> "$FIXTURE9/notes/note.md"
run_fixture "$FIXTURE9"
rc=$(cat "$FIXTURE9.harness/rc.txt")
if [[ $rc -eq 0 ]]; then
    report "case 9 exits 0 when the branch changed no crate source" 0 ""
else
    report "case 9 exits 0 when the branch changed no crate source" 1 "the script exited $rc; output tail: $(tail -n 6 "$FIXTURE9.harness/out.txt")"
fi
if grep -qF 'crates none (derived from the files this branch changed)' "$FIXTURE9.harness/out.txt"; then
    report "case 9 names the empty crate set in its summary" 0 ""
else
    report "case 9 names the empty crate set in its summary" 1 "the summary names another crate set: $(tail -n 3 "$FIXTURE9.harness/out.txt")"
fi
if grep -qF 'compile: this branch changed no file inside a workspace crate' "$FIXTURE9.harness/out.txt"; then
    report "case 9 reports the compile step as skipped rather than as run" 0 ""
else
    report "case 9 reports the compile step as skipped rather than as run" 1 "the summary holds no skip reason: $(tail -n 3 "$FIXTURE9.harness/out.txt")"
fi
if grep -q '^check ' "$FIXTURE9.harness/cargo.log" 2>/dev/null; then
    report "case 9 starts no cargo check" 1 "the stub cargo log holds: $(tr '\n' '|' < "$FIXTURE9.harness/cargo.log")"
else
    report "case 9 starts no cargo check" 0 ""
fi

# ── Case 10: a gate the list names and the repository does not hold ──────────────────
#
# Every one of the 28 gates exists in this repository, so case 3 exercises the branch that
# runs a gate and never the branch that finds one absent. Deleting the `MISSING` branch from
# `scripts/fix-round-check.sh` would leave an absent gate uncounted and unreported: the run
# would print `gates 27/28 passed` and exit 0, having skipped a gate rather than failing on
# it. This case deletes one gate from a fixture that is otherwise the passing fixture of
# case 9.
FIXTURE10="$WORK/missing-gate"
build_fixture "$FIXTURE10"
MISSING_GATE=$(gate_paths | head -n 1)
rm -f "$FIXTURE10/$MISSING_GATE"
run_fixture "$FIXTURE10"
rc=$(cat "$FIXTURE10.harness/rc.txt")
if [[ $rc -eq 0 ]]; then
    report "case 10 exits non-zero when a gate the list names is absent" 1 "the script exited 0"
else
    report "case 10 exits non-zero when a gate the list names is absent" 0 ""
fi
if grep -qF "MISSING $MISSING_GATE" "$FIXTURE10.harness/out.txt"; then
    report "case 10 names the absent gate" 0 ""
else
    report "case 10 names the absent gate" 1 "the output never names $MISSING_GATE: $(tail -n 3 "$FIXTURE10.harness/out.txt")"
fi
if grep -qE 'gates [0-9]+/[0-9]+ passed, 1 FAILED' "$FIXTURE10.harness/out.txt"; then
    report "case 10 counts the absent gate as a failure rather than dropping it" 0 ""
else
    report "case 10 counts the absent gate as a failure rather than dropping it" 1 "the summary holds no gate-failure count: $(tail -n 3 "$FIXTURE10.harness/out.txt")"
fi

printf '\n'
if [[ $FAILURES -eq 0 ]]; then
    printf 'fix-round-check tests: every case passed.\n'
    exit 0
fi
printf 'fix-round-check tests: %d assertion(s) failed.\n' "$FAILURES" >&2
exit 1
