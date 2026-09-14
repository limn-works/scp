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
#   * THE GATE LIST AGAINST THE REPOSITORY, in both directions. A gate the runner's list
#     names and the repository does not hold has to fail the run, and so does a
#     `scripts/check-*` file the repository holds and neither of the runner's two arrays
#     names. Case 3 runs against this repository, where every gate the list names exists
#     and every check script is classified, so it reaches neither branch. Case 10 deletes
#     one gate from a fixture and asserts that the run names it and exits non-zero. Case 20
#     adds a check script to a fixture and asserts the same, which is the direction nothing
#     inside the runner's summary can report: both halves of the `N/N` it prints come from
#     its own GATES array, so a gate missing from that array shortens the pair rather than
#     failing the run. Case 3's assertion reads that count out of the array for the same
#     reason, rather than writing the literal.
#
#   * THE CHANGES THE RUNNER READS NO FILE OF. Cases 7, 8, 9 and 10 cover what the runner
#     compiles. Cases 11 through 15 cover what it says about what it did not compile,
#     because a fix agent pushes on the last lines of this output.
#
#     Case 11 changes one root-level file every workspace member compiles against and no
#     file under `crates/`, and asserts that the run exits non-zero and starts no `cargo
#     check`. That branch derived an empty crate set, recorded the compile step as skipped
#     and exited 0, which is a green verdict over zero compiled lines on a branch that
#     recompiles every member — the shape a compiler pin bump and a
#     `[workspace.dependencies]` bump both take.
#
#     Case 12 changes a file under `bindings/python/` and asserts that the summary names
#     that directory and the lint that no step ran. The runner reaches four of that
#     directory's files through its gates, so a reader who saw a green verdict without this
#     line would take the Python half of a round to have been checked.
#
#     Case 13 changes a file under `crates/scp-transport/` and asserts that the run issues
#     the second `cargo check` the `rust-clippy` job's second command mirrors. Without it,
#     an edit inside a `#[cfg(feature = "quic")]` module compiles nothing and reports
#     `compile ok`.
#
#     Case 14 leaves one edit uncommitted and asserts that the summary names
#     `scripts/check-cross-layer.sh` as the gate whose diff range holds no uncommitted edit.
#     That gate reads `git diff <merge base>...HEAD` and the other 28 read the working tree,
#     so its pass counts toward `gates N/N passed` over work it did not read.
#
#     Case 15 names one crate on the command line on a branch that changed another, and
#     asserts that the summary names the package the run left uncompiled.
#
#     Case 16 changes a file under `crates/scp-clock/`, one of the nine packages the
#     `wasm-protocol` job compiles for `wasm32-unknown-unknown`, and asserts that the
#     summary names that target and starts no wasm compile of its own. A host `cargo
#     check` accepts an API that target rejects.
#
#     Case 17 changes a workflow file and asserts that the summary names the two suites
#     the `ci-workflow-selftest` job runs over it. One gate the runner holds reads
#     workflow files for two rules of its own, which is not coverage of that edit.
#
#     Case 22 answers `cargo metadata` with an object holding no package list and asserts
#     that the summary names the feature set the compile step could not read, because a
#     run that activates a narrower feature set than the merge gate resolves and prints
#     `compile ok` says nothing about the modules it skipped.
#
#     Case 23 reads every `scripts/` program a job of `.github/workflows/ci.yml` starts,
#     subtracts the runner's own GATES array, and asserts that the `scripts/` entry of
#     UNRUN_LANES names every path that remains. The subtraction is the lane's own
#     criterion: the lane discloses a command CI runs that no step of the run starts, and
#     a path in GATES is a command the run does start. That entry is what a fix agent
#     editing an enforcement gate acts on, and a suite absent from it is a red CI job the
#     runner's output gave the agent no reason to expect. Two further assertions hold the
#     case's two inputs non-empty, because an empty lane line matches no suite name and an
#     empty suite list gives the comparison no iteration.
#
#     Case 25 holds the `.github/` entry of UNRUN_LANES to the suites an edit under
#     `.github/` can turn red, in both directions: a suite that reads a workflow file of
#     this repository and that the entry omits fails the case, and a suite the entry names
#     that reads no such file fails it too. A suite reaches a workflow file of this
#     repository only by resolving a path from the repository root, and the case reads that
#     evidence out of each suite's own directory rather than pinning a list of names.
#
#     Case 24 names a crate on the command line in a fixture whose `origin/main` ref is
#     deleted, and asserts that the run exits 0 and names `scripts/check-cross-layer.sh`
#     as a gate whose pass covers no line of the branch. That gate diffs against
#     `origin/main`, discards the git error an unresolvable range raises, and reads the
#     empty result as "not applicable", so its pass reaches the `gates N/N passed` count
#     over code it never read.
#
#   * THE MOVE BETWEEN CRATES. Git reports a rename as one filepair, so a runner that
#     reads `git status --porcelain` or `git diff --name-only` without `--no-renames` sees
#     the destination path alone and derives the destination package alone. Case 18
#     commits a move from one crate directory to another and case 19 leaves the same move
#     staged, and each asserts that both packages reach the derived set. Without them, a
#     round that moves a module leaves the origin crate's dangling `mod` item uncompiled
#     under a green verdict.
#
#   * THE FEATURES NO COMMAND LINE NAMES. `cargo clippy --workspace` resolves one feature
#     set across every member, and `cargo check -p <crate>` resolves that crate alone, so
#     a feature a sibling manifest requests is on in CI and off here. Case 21 answers
#     `cargo metadata` with three declarations of one dependency and asserts that the
#     compile command carries the features of the plain declaration and neither the
#     optional nor the target-specific one, because the workspace command activates
#     neither of those two either.
#
# WHAT THE STUBS REPLACE, and what stays real. The cases replace `cargo`, `rustc`, and
# `rustup` with scripts on a PATH this harness leads with, because the contract clauses
# above are about what the script does with those three programs' answers, and a real
# `cargo check` of this workspace costs between ten minutes and an hour on a developer
# machine. Everything else stays real: case 3 runs the 29 enforcement gates
# `scripts/fix-round-check.sh` names against this repository's own files, so a gate the
# list names but the repository does not hold fails this test rather than being skipped.
# One of those 29 gates imports PyYAML, which the standard library does not carry, so a
# developer whose interpreter lacks it sees case 3 fail on that gate; the runner prints the
# install command when it cannot import the library.
#
# WHY THE PINNED VERSION IS READ RATHER THAN WRITTEN. Case 2 and case 3 need a `rustc` that
# agrees with the pin. The harness reads the channel out of `rust-toolchain.toml` at run
# time, so raising the pin does not turn these two cases into copies of case 1.
#
# WHO RUNS THIS SUITE. The `fix-round-check-selftest` job of `.github/workflows/ci.yml`
# runs it on every pull-request head, which is the head every fix round pushes. That job
# names no merge_group event, for the reason its own comment gives: one of the 29 gates
# case 3 runs reads an exemption out of the pull request's body, and a merge_group event
# publishes no body. The job installs what case 3 needs: the tree-sitter
# grammars nine Python gates parse with, the PyYAML
# `scripts/check-workflow-compile-steps.py` reads every workflow file with, the ruff
# `scripts/check-pyi-generated.sh` runs,
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
    # `command -v python3.12`, and ten of the 29 entries in its gate list run under it, so
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
    metadata)
        # The runner reads two things out of this answer: the target directory its summary
        # names, and the dependency declarations its compile step derives a feature set
        # from. A case that wants the second writes its own JSON to metadata.json beside
        # these stubs; every other case gets the object below, which carries no package
        # list and drives the runner's "this run could not read them" branch.
        if [[ -f "$dir/metadata.json" ]]; then
            cat "$dir/metadata.json"
        else
            printf '{"version":1,"target_directory":"$dir/stub-target-dir"}\n'
        fi
        exit 0
        ;;
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
# It holds a fourth manifest, `crates/scp-transport`, because two of the three entries in
# the runner's EXTRA_FEATURE_CHECKS array name that package, and case 13 reads both
# `cargo check` commands they produce. It holds `bindings/python/scp_sdk/context.py` for
# case 12, `Cargo.toml` for case 11 and `.github/workflows/ci.yml` for case 17, and the
# fixture's base commit holds all three, so each case decides for itself whether its own
# edit to them is committed.
#
# The commit passes `--no-gpg-sign` and `--no-verify` because a developer's global git
# configuration may sign every commit and may point `core.hooksPath` at this repository's
# hooks, and this fixture wants neither. `git update-ref` writes the remote-tracking ref
# `changed_files` takes its merge base against, so the fixture needs no network.
build_fixture() {
    local root=$1 g
    mkdir -p "$root/scripts" "$root/crates/scp-clock/src" "$root/crates/scp-ffi/src" \
        "$root/crates/scp-ffi/napi/src" "$root/crates/scp-transport/src" \
        "$root/bindings/python/scp_sdk" "$root/.github/workflows" "$root/notes"
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
    printf '[package]\nname = "scp-transport"\nversion = "0.0.0"\n' > "$root/crates/scp-transport/Cargo.toml"
    printf '// fixture source\n' > "$root/crates/scp-transport/src/lib.rs"
    printf '# fixture binding source\n' > "$root/bindings/python/scp_sdk/context.py"
    printf 'name: fixture\n' > "$root/.github/workflows/ci.yml"
    printf '[workspace]\nmembers = ["crates/*"]\n' > "$root/Cargo.toml"
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
# The expected count is read out of the runner's own GATES array rather than written here,
# so this assertion reports a gate the array lost. Writing the literal would let a deletion
# from that array satisfy this case: both halves of the `N/N` the runner prints come from
# the array's own length, so a shorter array prints a shorter pair that still matches.
GATE_COUNT=$(gate_paths | wc -l | tr -d ' ')
if grep -q "gates $GATE_COUNT/$GATE_COUNT passed" "$WORK/passing/out.txt"; then
    report "case 3 ran all $GATE_COUNT gates against this repository" 0 ""
else
    report "case 3 ran all $GATE_COUNT gates against this repository" 1 "the summary holds no 'gates $GATE_COUNT/$GATE_COUNT passed': $(tail -n 3 "$WORK/passing/out.txt")"
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
# Every one of the 29 gates exists in this repository, so case 3 exercises the branch that
# runs a gate and never the branch that finds one absent. Deleting the `MISSING` branch from
# `scripts/fix-round-check.sh` would leave an absent gate uncounted and unreported: the run
# would print `gates 28/29 passed` and exit 0, having skipped a gate rather than failing on
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

# ── Case 11: a branch that changed only a workspace-wide input ───────────────────────
#
# `Cargo.toml` sits under no crate directory, so `crate_of_path` maps it to no package and
# the derived crate set is empty — the same branch case 9 takes. Case 9's branch changed a
# note, which no cargo command compiles; this one changed the table every member's manifest
# inherits from, which recompiles all 26. Exiting 0 there reports a green verdict over zero
# compiled lines, and this case asserts the run refuses it.
#
# The mutation it kills: deleting the `wide_list` branch of the empty-crate-set block in
# `scripts/fix-round-check.sh` restores the skip line and exit 0, and every other assertion
# in this file still passes.
FIXTURE11="$WORK/workspace-wide-input"
build_fixture "$FIXTURE11"
fixture_commit "$FIXTURE11" Cargo.toml
run_fixture "$FIXTURE11"
rc=$(cat "$FIXTURE11.harness/rc.txt")
if [[ $rc -eq 0 ]]; then
    report "case 11 exits non-zero when the branch changed only a workspace-wide input" 1 "the script exited 0; output tail: $(tail -n 6 "$FIXTURE11.harness/out.txt")"
else
    report "case 11 exits non-zero when the branch changed only a workspace-wide input" 0 ""
fi
if grep -qF 'which every workspace member compiles against' "$FIXTURE11.harness/out.txt"; then
    report "case 11 names the file no narrowed cargo check covers" 0 ""
else
    report "case 11 names the file no narrowed cargo check covers" 1 "the output never says why it compiled nothing: $(tail -n 3 "$FIXTURE11.harness/out.txt")"
fi
if grep -q '^check ' "$FIXTURE11.harness/cargo.log" 2>/dev/null; then
    report "case 11 starts no cargo check it cannot narrow" 1 "the stub cargo log holds: $(tr '\n' '|' < "$FIXTURE11.harness/cargo.log")"
else
    report "case 11 starts no cargo check it cannot narrow" 0 ""
fi

# ── Case 12: a branch that changed a file under bindings/ ────────────────────────────
#
# The runner runs no ruff, no biome, no detekt and no SwiftLint, and four of its gates read
# files under `bindings/`, so a summary that named only its two cargo omissions would tell
# a fix agent editing `bindings/python/` that CI has nothing left to reject.
#
# The mutation it kills: deleting the UNRUN_LANES loop from
# `scripts/fix-round-check.sh` leaves the run exiting 0 with no line about the directory it
# read no file of, and every other assertion in this file still passes.
FIXTURE12="$WORK/bindings-only"
build_fixture "$FIXTURE12"
fixture_commit "$FIXTURE12" bindings/python/scp_sdk/context.py
run_fixture "$FIXTURE12"
rc=$(cat "$FIXTURE12.harness/rc.txt")
if [[ $rc -eq 0 ]]; then
    report "case 12 exits 0 when the branch changed a binding source alone" 0 ""
else
    report "case 12 exits 0 when the branch changed a binding source alone" 1 "the script exited $rc; output tail: $(tail -n 6 "$FIXTURE12.harness/out.txt")"
fi
if grep -qF 'NOT CHECKED — 1 file(s) under bindings/python/' "$FIXTURE12.harness/out.txt"; then
    report "case 12 names the directory it read no file of" 0 ""
else
    report "case 12 names the directory it read no file of" 1 "the output holds no NOT CHECKED line for bindings/python/: $(tail -n 4 "$FIXTURE12.harness/out.txt")"
fi
if grep -qF 'ruff and pytest, which the python-lint and python-test jobs' "$FIXTURE12.harness/out.txt"; then
    report "case 12 names the programs and the CI jobs that run them" 0 ""
else
    report "case 12 names the programs and the CI jobs that run them" 1 "the NOT CHECKED line names no program: $(tail -n 4 "$FIXTURE12.harness/out.txt")"
fi

# ── Case 13: the optional-feature compile the workspace command does not reach ───────
#
# `.github/workflows/ci.yml` runs `cargo clippy -p scp-transport --features
# quic,http3,udp,coap --all-targets` as a second command of its `rust-clippy` job, under a
# comment recording that those transports "rotted undetected for months". A `cargo check`
# carrying no feature compiles none of the four modules, so an edit inside one of them
# reports `compile ok` having compiled nothing.
#
# The mutation it kills: emptying EXTRA_FEATURE_CHECKS in `scripts/fix-round-check.sh`
# leaves the run issuing one featureless `cargo check` and reporting `compile ok`, and
# every other assertion in this file still passes.
FIXTURE13="$WORK/optional-features"
build_fixture "$FIXTURE13"
fixture_commit "$FIXTURE13" crates/scp-transport/src/lib.rs
run_fixture "$FIXTURE13"
rc=$(cat "$FIXTURE13.harness/rc.txt")
if [[ $rc -eq 0 ]]; then
    report "case 13 exits 0 when both transport compiles pass" 0 ""
else
    report "case 13 exits 0 when both transport compiles pass" 1 "the script exited $rc; output tail: $(tail -n 6 "$FIXTURE13.harness/out.txt")"
fi
if grep -qF 'check -p scp-transport --all-targets --features quic,http3,udp,coap' "$FIXTURE13.harness/cargo.log"; then
    report "case 13 compiles the optional transports the workspace command never activates" 0 ""
else
    report "case 13 compiles the optional transports the workspace command never activates" 1 "the stub cargo log holds: $(tr '\n' '|' < "$FIXTURE13.harness/cargo.log")"
fi
if grep -qF 'check -p scp-transport --all-targets --features combined,local-cache' "$FIXTURE13.harness/cargo.log"; then
    report "case 13 compiles the blob-backend features the optional-feature test lane names" 0 ""
else
    report "case 13 compiles the blob-backend features the optional-feature test lane names" 1 "the stub cargo log holds: $(tr '\n' '|' < "$FIXTURE13.harness/cargo.log")"
fi

# ── Case 14: the gate whose diff range holds no uncommitted edit ─────────────────────
#
# `scripts/check-cross-layer.sh` decides from `git diff <merge base with origin/main>…HEAD`
# and the other 28 gates read the working tree, so on an uncommitted edit — one of the
# three input shapes the runner's own comment names as supported — that gate passes over
# work it never read and its pass counts toward `gates N/N passed`.
#
# The mutation it kills: deleting the `uncommitted_count` note from
# `scripts/fix-round-check.sh` leaves that pass unqualified, and every other assertion in
# this file still passes.
FIXTURE14="$WORK/uncommitted-edit"
build_fixture "$FIXTURE14"
printf '// uncommitted edit\n' >> "$FIXTURE14/crates/scp-clock/src/lib.rs"
run_fixture "$FIXTURE14"
rc=$(cat "$FIXTURE14.harness/rc.txt")
if [[ $rc -eq 0 ]]; then
    report "case 14 exits 0 on an uncommitted edit that compiles" 0 ""
else
    report "case 14 exits 0 on an uncommitted edit that compiles" 1 "the script exited $rc; output tail: $(tail -n 6 "$FIXTURE14.harness/out.txt")"
fi
if grep -qF 'NOT CHECKED — the 1 uncommitted path(s) in this working tree' "$FIXTURE14.harness/out.txt"; then
    report "case 14 counts the uncommitted paths one gate did not read" 0 ""
else
    report "case 14 counts the uncommitted paths one gate did not read" 1 "the output holds no NOT CHECKED line for the working tree: $(tail -n 4 "$FIXTURE14.harness/out.txt")"
fi
if grep -qF 'scripts/check-cross-layer.sh decides from git diff' "$FIXTURE14.harness/out.txt"; then
    report "case 14 names the gate and the range it decides from" 0 ""
else
    report "case 14 names the gate and the range it decides from" 1 "the NOT CHECKED line names no gate: $(tail -n 4 "$FIXTURE14.harness/out.txt")"
fi

# ── Case 15: a caller-named crate set narrower than the branch's own edits ───────────
#
# Naming a crate takes the `$# -gt 0` branch, which compiles the set the caller asked for.
# A fix agent that names one crate and edits two reads `compile ok` over a package the run
# never compiled, and no other line of the output names it.
#
# The mutation it kills: deleting the UNNAMED loop from `scripts/fix-round-check.sh` leaves
# that run silent about the second package, and every other assertion in this file passes.
FIXTURE15="$WORK/narrower-than-edits"
build_fixture "$FIXTURE15"
fixture_commit "$FIXTURE15" crates/scp-ffi/napi/src/lib.rs
HARNESS15="$FIXTURE15.harness"
write_stubs "$HARNESS15" "$PIN_CHANNEL" 0 0 ""
PATH="$HARNESS15/bin:$PATH" bash "$FIXTURE15/scripts/fix-round-check.sh" scp-clock \
    > "$HARNESS15/out.txt" 2>&1
printf '%s' $? > "$HARNESS15/rc.txt"
rc=$(cat "$HARNESS15/rc.txt")
if [[ $rc -eq 0 ]]; then
    report "case 15 exits 0 when the crate the caller named compiles" 0 ""
else
    report "case 15 exits 0 when the crate the caller named compiles" 1 "the script exited $rc; output tail: $(tail -n 6 "$HARNESS15/out.txt")"
fi
if grep -qF 'NOT CHECKED — scp-ffi-napi: this branch changed files these packages own' "$HARNESS15/out.txt"; then
    report "case 15 names the package the caller's crate set left out" 0 ""
else
    report "case 15 names the package the caller's crate set left out" 1 "the output holds no NOT CHECKED line for scp-ffi-napi: $(tail -n 4 "$HARNESS15/out.txt")"
fi
if grep -qF 'check -p scp-clock --all-targets' "$HARNESS15/cargo.log"; then
    report "case 15 compiles the crate set the caller asked for and no other" 0 ""
else
    report "case 15 compiles the crate set the caller asked for and no other" 1 "the stub cargo log holds: $(tr '\n' '|' < "$HARNESS15/cargo.log")"
fi

# ── Case 16: the wasm target the host compile does not reach ─────────────────────────
#
# The `wasm-protocol` job of `.github/workflows/ci.yml` runs one `cargo check` over nine
# packages for `wasm32-unknown-unknown`. `scp-clock` is one of them, and a host `cargo
# check` accepts an API that target rejects, so a run that compiled `scp-clock` for the
# host alone and printed `compile ok` would tell a fix agent that the wasm build is safe.
#
# The mutation it kills: deleting the SELECTED_WASM block from
# `scripts/fix-round-check.sh` leaves that run silent about the target it never compiled
# for, and every other assertion in this file still passes.
FIXTURE16="$WORK/wasm-target-crate"
build_fixture "$FIXTURE16"
fixture_commit "$FIXTURE16" crates/scp-clock/src/lib.rs
run_fixture "$FIXTURE16"
if grep -qF 'NOT CHECKED — scp-clock against wasm32-unknown-unknown' "$FIXTURE16.harness/out.txt"; then
    report "case 16 names the package it compiled for the host target alone" 0 ""
else
    report "case 16 names the package it compiled for the host target alone" 1 "the output holds no NOT CHECKED line for wasm32-unknown-unknown: $(tail -n 5 "$FIXTURE16.harness/out.txt")"
fi
if grep -qF 'wasm-protocol job' "$FIXTURE16.harness/out.txt"; then
    report "case 16 names the CI job that compiles for that target" 0 ""
else
    report "case 16 names the CI job that compiles for that target" 1 "the NOT CHECKED line names no job: $(tail -n 5 "$FIXTURE16.harness/out.txt")"
fi
if grep -qF -- '--target wasm32-unknown-unknown' "$FIXTURE16.harness/cargo.log"; then
    report "case 16 starts no wasm compile of its own" 1 "the stub cargo log holds: $(tr '\n' '|' < "$FIXTURE16.harness/cargo.log")"
else
    report "case 16 starts no wasm compile of its own" 0 ""
fi

# ── Case 17: a branch that changed a workflow file ───────────────────────────────────
#
# Three gates the runner holds read a workflow file, each for rules of its own and none as
# coverage of a workflow edit: `scripts/check-workflow-compile-steps.py` for its
# cache-group and bindgen rules, `scripts/check-toolchain-wiring.sh` for its
# container-build and paths-filter rules, and `scripts/check-shipped-feature-graph.sh` for
# the cargo invocations that ship an artifact. The `ci-workflow-selftest` job runs two
# suites over those files that no gate duplicates, so a run whose only output about a
# changed workflow was `gates N/N passed` would read as full coverage of that edit.
#
# The mutation it kills: deleting the `.github/` entry from UNRUN_LANES in
# `scripts/fix-round-check.sh` leaves that run silent, and every other assertion in this
# file still passes.
FIXTURE17="$WORK/workflow-edit"
build_fixture "$FIXTURE17"
fixture_commit "$FIXTURE17" .github/workflows/ci.yml
run_fixture "$FIXTURE17"
rc=$(cat "$FIXTURE17.harness/rc.txt")
if [[ $rc -eq 0 ]]; then
    report "case 17 exits 0 when the branch changed a workflow file alone" 0 ""
else
    report "case 17 exits 0 when the branch changed a workflow file alone" 1 "the script exited $rc; output tail: $(tail -n 6 "$FIXTURE17.harness/out.txt")"
fi
if grep -qF 'NOT CHECKED — 1 file(s) under .github/' "$FIXTURE17.harness/out.txt"; then
    report "case 17 names the workflow directory it ran no suite over" 0 ""
else
    report "case 17 names the workflow directory it ran no suite over" 1 "the output holds no NOT CHECKED line for .github/: $(tail -n 5 "$FIXTURE17.harness/out.txt")"
fi
if grep -qF 'ci-workflow-selftest job' "$FIXTURE17.harness/out.txt"; then
    report "case 17 names the suites and the CI job that runs them" 0 ""
else
    report "case 17 names the suites and the CI job that runs them" 1 "the NOT CHECKED line names no job: $(tail -n 5 "$FIXTURE17.harness/out.txt")"
fi

# ── Case 18: a file moved from one crate to another ──────────────────────────────────
#
# Git reports a rename as one filepair, so `git status --porcelain` prints
# `R  <origin> -> <destination>` and `git diff --name-only` prints the destination alone.
# A runner that read either without `--no-renames` derives the destination package by
# itself: the origin package keeps a `mod` item naming a file it no longer holds, this run
# compiles none of it, no NOT CHECKED line names it, and the run exits 0 — a green verdict
# over a branch the merge gate rejects.
#
# The mutation it kills: dropping `--no-renames` from either half of `changed_files` in
# `scripts/fix-round-check.sh` leaves `scp-ffi` out of the derived set, and every other
# assertion in this file still passes. Both halves are exercised, because git loses the
# origin path in a different place for each: this case commits the move, and case 19
# leaves it staged.
FIXTURE18="$WORK/committed-rename"
build_fixture "$FIXTURE18"
git -C "$FIXTURE18" mv crates/scp-ffi/src/lib.rs crates/scp-clock/src/moved.rs
git -C "$FIXTURE18" -c user.email=fix-round-check@example.invalid -c user.name='fix-round-check tests' \
    commit -q --no-gpg-sign --no-verify -m 'fixture rename'
run_fixture "$FIXTURE18"
rc=$(cat "$FIXTURE18.harness/rc.txt")
if [[ $rc -eq 0 ]]; then
    report "case 18 exits 0 when both sides of a committed rename compile" 0 ""
else
    report "case 18 exits 0 when both sides of a committed rename compile" 1 "the script exited $rc; output tail: $(tail -n 6 "$FIXTURE18.harness/out.txt")"
fi
if grep -qF 'crates scp-clock scp-ffi (derived from the files this branch changed)' "$FIXTURE18.harness/out.txt"; then
    report "case 18 derives the crate a committed rename moved the file out of" 0 ""
else
    report "case 18 derives the crate a committed rename moved the file out of" 1 "the summary names another crate set: $(tail -n 3 "$FIXTURE18.harness/out.txt")"
fi
if grep -qF 'check -p scp-clock -p scp-ffi --all-targets' "$FIXTURE18.harness/cargo.log"; then
    report "case 18 compiles both sides of the move" 0 ""
else
    report "case 18 compiles both sides of the move" 1 "the stub cargo log holds: $(tr '\n' '|' < "$FIXTURE18.harness/cargo.log")"
fi

# ── Case 19: a staged move the working-tree half has to report ───────────────────────
#
# Case 18 covers the `git diff` half of `changed_files`. This one covers the
# `git status --porcelain` half, which is the half a fix round hits: an agent stages a
# move and runs this script before committing.
FIXTURE19="$WORK/staged-rename"
build_fixture "$FIXTURE19"
git -C "$FIXTURE19" mv crates/scp-ffi/src/lib.rs crates/scp-clock/src/moved.rs
run_fixture "$FIXTURE19"
if grep -qF 'crates scp-clock scp-ffi (derived from the files this branch changed)' "$FIXTURE19.harness/out.txt"; then
    report "case 19 derives the crate a staged rename moved the file out of" 0 ""
else
    report "case 19 derives the crate a staged rename moved the file out of" 1 "the summary names another crate set: $(tail -n 3 "$FIXTURE19.harness/out.txt")"
fi

# ── Case 20: an enforcement gate the runner's list does not classify ─────────────────
#
# The GATES array of `scripts/fix-round-check.sh` is written by hand, and both halves of
# the `N/N` it prints come from that array's own length, so nothing inside that summary
# can report a gate the repository holds and the array lost. A fix round that read
# `gates N/N passed` would take it for the enforcement set and push into the job that runs
# the gate nobody added.
#
# The mutation it kills: deleting the `scripts/check-*` loop from
# `scripts/fix-round-check.sh` lets the unclassified gate below go unrun and unnamed, and
# every other assertion in this file still passes.
FIXTURE20="$WORK/unclassified-gate"
build_fixture "$FIXTURE20"
printf '#!/usr/bin/env bash\nexit 0\n' > "$FIXTURE20/scripts/check-brand-new-rule.sh"
run_fixture "$FIXTURE20"
rc=$(cat "$FIXTURE20.harness/rc.txt")
if [[ $rc -eq 0 ]]; then
    report "case 20 exits non-zero on a check script neither array names" 1 "the script exited 0; output tail: $(tail -n 6 "$FIXTURE20.harness/out.txt")"
else
    report "case 20 exits non-zero on a check script neither array names" 0 ""
fi
if grep -qF 'UNCLASSIFIED scripts/check-brand-new-rule.sh' "$FIXTURE20.harness/out.txt"; then
    report "case 20 names the gate it neither ran nor excused" 0 ""
else
    report "case 20 names the gate it neither ran nor excused" 1 "the output never names the unclassified gate: $(tail -n 5 "$FIXTURE20.harness/out.txt")"
fi

# ── Case 21: the features a sibling manifest activates on the selected package ───────
#
# `cargo clippy --workspace` resolves one feature set across every member, so a
# non-default feature that any member's dependency declaration requests is on for that
# dependency. `cargo check -p <crate>` resolves that crate alone and activates none of
# them, so a module gated on such a feature compiles in CI and nowhere in a fix round.
# Measured against this workspace: `crates/scp-platform/src/lib.rs` gates seven modules on
# features four sibling manifests request and no CI command names literally.
#
# The fixture's metadata answer carries three declarations of the same dependency, so this
# case pins the restriction as well as the rule: the plain one contributes, and the
# optional one and the target-specific one contribute nothing, because the workspace
# command activates neither and compiling under them would report a failure the merge gate
# never asks about.
#
# The mutation it kills: deleting the SIBLING_FEATURE_READER block from
# `scripts/fix-round-check.sh` leaves the run issuing a featureless `cargo check` over a
# package whose gated modules it then compiles no line of, and every other assertion in
# this file still passes.
FIXTURE21="$WORK/sibling-features"
build_fixture "$FIXTURE21"
fixture_commit "$FIXTURE21" crates/scp-clock/src/lib.rs
HARNESS21="$FIXTURE21.harness"
write_stubs "$HARNESS21" "$PIN_CHANNEL" 0 0 ""
cat > "$HARNESS21/metadata.json" <<'JSON'
{"version":1,"target_directory":"/stub-target-dir","packages":[
 {"name":"scp-clock","dependencies":[]},
 {"name":"scp-ffi","dependencies":[
  {"name":"scp-clock","features":["sqlite","apple"],"optional":false,"target":null},
  {"name":"scp-clock","features":["only-when-optional"],"optional":true,"target":null},
  {"name":"scp-clock","features":["only-on-ios"],"optional":false,"target":"cfg(target_os = \"ios\")"}
 ]}
]}
JSON
PATH="$HARNESS21/bin:$PATH" bash "$FIXTURE21/scripts/fix-round-check.sh" > "$HARNESS21/out.txt" 2>&1
printf '%s' $? > "$HARNESS21/rc.txt"
if grep -qF 'check -p scp-clock --all-targets --features scp-clock/apple,scp-clock/sqlite' "$HARNESS21/cargo.log"; then
    report "case 21 compiles the package under the features a sibling manifest requests" 0 ""
else
    report "case 21 compiles the package under the features a sibling manifest requests" 1 "the stub cargo log holds: $(tr '\n' '|' < "$HARNESS21/cargo.log")"
fi
if grep -qF 'only-when-optional' "$HARNESS21/cargo.log"; then
    report "case 21 activates no feature an optional declaration alone requests" 1 "the stub cargo log holds: $(tr '\n' '|' < "$HARNESS21/cargo.log")"
else
    report "case 21 activates no feature an optional declaration alone requests" 0 ""
fi
if grep -qF 'only-on-ios' "$HARNESS21/cargo.log"; then
    report "case 21 activates no feature a target-specific declaration alone requests" 1 "the stub cargo log holds: $(tr '\n' '|' < "$HARNESS21/cargo.log")"
else
    report "case 21 activates no feature a target-specific declaration alone requests" 0 ""
fi

# ── Case 22: the run that could not read those declarations says so ──────────────────
#
# Case 21 covers the run that read them. `cargo metadata` carries a 60-second bound and
# the interpreter that parses its output may be absent, and either way the compile step
# activates a narrower feature set than the merge gate resolves. Reporting `compile ok`
# over that difference without a line naming it is the shape this whole runner exists to
# prevent, so the fixture below answers `cargo metadata` with an object holding no package
# list and this case asserts the line.
#
# The mutation it kills: deleting the two NOTES branches beside the SIBLING_FEATURE_READER
# call leaves that run silent about the features it did not activate.
FIXTURE22="$WORK/unreadable-metadata"
build_fixture "$FIXTURE22"
fixture_commit "$FIXTURE22" crates/scp-clock/src/lib.rs
run_fixture "$FIXTURE22"
if grep -qF 'NOT CHECKED — the features a sibling manifest activates on scp-clock' "$FIXTURE22.harness/out.txt"; then
    report "case 22 names the feature set it could not read" 0 ""
else
    report "case 22 names the feature set it could not read" 1 "the output holds no NOT CHECKED line for the sibling feature set: $(tail -n 5 "$FIXTURE22.harness/out.txt")"
fi

# ── Case 23: the scripts/ lane against the suites CI runs over that directory ────────
#
# The `scripts/` entry of UNRUN_LANES is a hand-written enumeration, and a fix agent that
# edits an enforcement gate acts on it: the runner starts that gate against a clean tree,
# the gate passes, and the only program that proves the gate still rejects what it exists
# to reject is the fixture suite that entry names. A suite the entry omits is a red CI job
# the output gave the agent no reason to expect.
#
# This case reads every `scripts/` program that a job of `.github/workflows/ci.yml` starts
# with `bash` or with `python3.12 -m pytest`, subtracts the ones the runner's own GATES
# array starts, and fails when the entry names fewer than what remains. Adding a suite to
# CI without adding it there turns this case red rather than going unnoticed.
#
# THE SUBTRACTION IS THE CRITERION, and it is the lane's own: `scripts/fix-round-check.sh`
# admits an entry for a command CI runs that no step of the run starts. A path in GATES is
# a command the run does start, so the lane owes the reader nothing about it; every other
# path CI starts under `scripts/` is one the run leaves unread and the lane has to name.
# Reading the GATES array off the script rather than filtering on a `scripts/test…` name
# keeps this case closed: a suite a later round files under any other directory name still
# has to appear in the lane.
LANE_LINE=$(sed -n '/^UNRUN_LANES=(/,/^)/p' "$SCRIPT" | grep -F '"scripts/|')
LANE_SUITES=$(comm -23 \
    <(grep -oE 'run: *(bash|python3\.12 -m pytest) +scripts/[^ ]+' "$REPO_ROOT/.github/workflows/ci.yml" |
        sed -E 's/^.* //' | sort -u) \
    <(gate_paths | sort -u))
LANE_SUITE_COUNT=$(printf '%s' "$LANE_SUITES" | grep -c . || true)
LANE_MISSING=""
while IFS= read -r suite; do
    [[ -n $suite ]] || continue
    case $LANE_LINE in
        *"$suite"*) ;;
        *) LANE_MISSING+=" $suite" ;;
    esac
done <<< "$LANE_SUITES"
if [[ -z $LANE_MISSING ]]; then
    report "case 23 names every suite CI runs over scripts/ in the scripts/ lane" 0 ""
else
    report "case 23 names every suite CI runs over scripts/ in the scripts/ lane" 1 "the scripts/ entry of UNRUN_LANES omits:$LANE_MISSING"
fi
# The two inputs the assertion above reads, each asserted non-empty, because an empty one
# makes that assertion pass over nothing: an empty LANE_LINE matches no suite name, and an
# empty suite list gives the loop no iteration. A renamed UNRUN_LANES array, a reworded
# `run:` step in the workflow and a renamed GATES array each empty one of the two, and
# each would otherwise leave this case green while reading no lane at all.
if [[ -n $LANE_LINE ]]; then
    report "case 23 found the scripts/ entry it reads" 0 ""
else
    report "case 23 found the scripts/ entry it reads" 1 "scripts/fix-round-check.sh holds no UNRUN_LANES entry beginning \"scripts/|\", so the assertion above read an empty string and could not fail"
fi
if [[ $LANE_SUITE_COUNT -gt 0 ]]; then
    report "case 23 read a non-empty suite set out of .github/workflows/ci.yml" 0 ""
else
    report "case 23 read a non-empty suite set out of .github/workflows/ci.yml" 1 "subtracting the GATES array from the scripts/ programs .github/workflows/ci.yml starts left no path, so the assertion above iterated over nothing and could not fail"
fi

# ── Case 24: a caller-named run in a checkout that resolves no origin/main ───────────
#
# Naming a crate takes the `$# -gt 0` branch, which compiles that set whether or not
# `changed_files` answered, so this run reaches the gate loop with no merge base. One gate
# in that loop decides from the same ref: `scripts/check-cross-layer.sh` sets its range to
# `origin/main...HEAD`, discards the git error an unresolvable range raises, reads the
# empty result as "not applicable", and exits 0. Its pass then joins the `gates N/N
# passed` count over code it never read, and the summary has to say so.
#
# The mutation it kills: deleting the second NOTES entry of that branch from
# `scripts/fix-round-check.sh` leaves the run printing `gates N/N passed` with no line
# about the gate that examined nothing, and every other assertion in this file passes.
FIXTURE24="$WORK/caller-named-no-origin-main"
build_fixture "$FIXTURE24"
fixture_commit "$FIXTURE24" crates/scp-ffi/napi/src/lib.rs
git -C "$FIXTURE24" update-ref -d refs/remotes/origin/main
HARNESS24="$FIXTURE24.harness"
write_stubs "$HARNESS24" "$PIN_CHANNEL" 0 0 ""
PATH="$HARNESS24/bin:$PATH" bash "$FIXTURE24/scripts/fix-round-check.sh" scp-clock \
    > "$HARNESS24/out.txt" 2>&1
printf '%s' $? > "$HARNESS24/rc.txt"
rc=$(cat "$HARNESS24/rc.txt")
if [[ $rc -eq 0 ]]; then
    report "case 24 exits 0, which is why the note below is the only signal" 0 ""
else
    report "case 24 exits 0, which is why the note below is the only signal" 1 "the script exited $rc; output tail: $(tail -n 6 "$HARNESS24/out.txt")"
fi
if grep -qF 'NOT CHECKED — scripts/check-cross-layer.sh, for the whole of this run' "$HARNESS24/out.txt"; then
    report "case 24 names the gate whose pass covers no line of the branch" 0 ""
else
    report "case 24 names the gate whose pass covers no line of the branch" 1 "the output holds no NOT CHECKED line for scripts/check-cross-layer.sh: $(tail -n 6 "$HARNESS24/out.txt")"
fi
if grep -qF 'check -p scp-clock --all-targets' "$HARNESS24/cargo.log"; then
    report "case 24 compiles the crate the caller named although the ref is missing" 0 ""
else
    report "case 24 compiles the crate the caller named although the ref is missing" 1 "the stub cargo log holds: $(tr '\n' '|' < "$HARNESS24/cargo.log")"
fi

# ── Case 25: the .github/ lane against the suites that read this repository's workflows ─
#
# THE CRITERION the `.github/` entry of UNRUN_LANES states, and that this case holds it
# to: the entry names a suite when an edit under `.github/` can turn that suite red, and
# names no other. A suite reaches a workflow file of this repository only by resolving a
# path from the repository root, so a suite that builds its gate's whole input under
# `mktemp -d` stays green whatever `.github/workflows/` says, and naming it tells a fix
# agent that an edit to a workflow has coverage it does not have.
#
# EVIDENCE, not the criterion: a file of the suite's own directory holds a line naming a
# repository-root variable and a `workflows/` path together. `scripts/tests/ci-gate/
# ci_gate_selftest.py` writes `WORKFLOW = REPO / ".github/workflows/ci.yml"` and this file
# writes `"$REPO_ROOT/.github/workflows/ci.yml"`, while `scripts/tests/toolchain-wiring/
# run-tests.sh` writes `"$root/.github/workflows/ci.yml"` against a fixture tree it created
# and `scripts/tests/signing-guard/run-tests.sh` names no workflow path at all. A suite
# that roots a path at this repository under a variable spelled some other way fails this
# case rather than passing it, which sends a reader to this comment to widen the pattern.
#
# The case reads both sides: every suite that qualifies has to appear in the entry, and
# every suite the entry names has to qualify. It iterates LANE_SUITES, the set case 23
# above reads out of `.github/workflows/ci.yml` and subtracts the GATES array from, so a
# suite CI gains reaches this case too and a gate the run itself starts stays out of it —
# the `.github/` entry names those three gates in its own trailing sentence, as programs
# the run did start.
#
# The mutation it kills: adding `scripts/tests/signing-guard/run-tests.sh` back to the
# `.github/` entry of `scripts/fix-round-check.sh`, or dropping
# `scripts/tests/fix-round-check/run-tests.sh` from it, leaves a workflow edit reported
# against a suite set that does not match the suites the edit can red, and every other
# assertion in this file passes.
GITHUB_LANE_LINE=$(sed -n '/^UNRUN_LANES=(/,/^)/p' "$SCRIPT" | grep -F '".github/|')
GITHUB_LANE_WRONG=""
GITHUB_LANE_QUALIFIED=0
while IFS= read -r suite; do
    [[ -n $suite ]] || continue
    scan="$REPO_ROOT/$suite"
    if [[ -f $scan ]]; then
        suite_dir=$(dirname "$suite")
        [[ $suite_dir == scripts/tests/* ]] && scan="$REPO_ROOT/$suite_dir"
    fi
    qualifies=0
    grep -rqE 'REPO[A-Z_]*[^a-zA-Z0-9_].*workflows/' "$scan" 2>/dev/null && qualifies=1
    named=0
    case $GITHUB_LANE_LINE in
        *"$suite"*) named=1 ;;
    esac
    if [[ $qualifies -eq 1 && $named -eq 0 ]]; then
        GITHUB_LANE_WRONG+=" $suite(reads this repository's workflows, unnamed)"
    elif [[ $qualifies -eq 0 && $named -eq 1 ]]; then
        GITHUB_LANE_WRONG+=" $suite(named, reads no workflow file of this repository)"
    fi
    [[ $qualifies -eq 1 ]] && GITHUB_LANE_QUALIFIED=$((GITHUB_LANE_QUALIFIED + 1))
done <<< "$LANE_SUITES"
if [[ -z $GITHUB_LANE_WRONG ]]; then
    report "case 25 names in the .github/ lane every suite a workflow edit reds, and no other" 0 ""
else
    report "case 25 names in the .github/ lane every suite a workflow edit reds, and no other" 1 "the .github/ entry of UNRUN_LANES disagrees with the suites that read this repository's workflow files:$GITHUB_LANE_WRONG"
fi
# The two inputs the assertion above reads, each asserted non-empty for the reason case 23
# gives: an empty lane line matches no suite name, and a suite set holding no qualifying
# suite leaves the comparison with nothing to disagree about.
if [[ -n $GITHUB_LANE_LINE ]]; then
    report "case 25 found the .github/ entry it reads" 0 ""
else
    report "case 25 found the .github/ entry it reads" 1 "scripts/fix-round-check.sh holds no UNRUN_LANES entry beginning \".github/|\", so the assertion above read an empty string"
fi
if [[ $GITHUB_LANE_QUALIFIED -gt 0 ]]; then
    report "case 25 found at least one suite that reads this repository's workflow files" 0 ""
else
    report "case 25 found at least one suite that reads this repository's workflow files" 1 "no suite .github/workflows/ci.yml starts under scripts/ matched the repository-rooted workflow read this case looks for, so the assertion above compared an empty set and could not fail"
fi

printf '\n'
if [[ $FAILURES -eq 0 ]]; then
    printf 'fix-round-check tests: every case passed.\n'
    exit 0
fi
printf 'fix-round-check tests: %d assertion(s) failed.\n' "$FAILURES" >&2
exit 1
