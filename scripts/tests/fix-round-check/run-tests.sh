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
#     one `cargo check` for each feature set of that package that a cargo command in
#     `.github/workflows/ci.yml` names and the workspace command never activates. The
#     `rust-clippy` job lints two of them, the optional transports and the PostgreSQL and
#     S3 blob backends; the `rust-test-optional-features` job tests the third, the
#     blob-backend features `combined,local-cache`. Without them, an edit inside a
#     `#[cfg(feature = "quic")]` module compiles nothing and reports `compile ok`.
#
#     Case 13b changes a file under `crates/scp-node/` and one under `crates/scp-relay/`,
#     and asserts that the run compiles each package's `cloud-blobs` feature in a check of
#     its own over every target, scp-node's with `testing`, as the `rust-clippy` job does;
#     that check also compiles the backend-selection test target the
#     `rust-test-optional-features` job builds under the same features. It also asserts
#     that no check names both packages with `cloud-blobs` on.
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
#     `compile ok` says nothing about the modules it skipped. The same run cannot read
#     which package has an example target, so case 22 also asserts that the
#     `scripts/check-examples-compile.sh` assertion 1 line and its source-scan line each
#     name the changed package and say the run could not read the targets.
#
#     Case 22b changes scp-clock, scp-transport and scp-ffi under a metadata answer in
#     which only scp-transport owns an example, and scp-transport reaches scp-clock through
#     a dev-dependency. It asserts that the examples-gate assertion 1 line names scp-clock
#     and scp-transport and not scp-ffi, which no example compiles; that the line says the
#     gate lints every workspace library an example compiles; that the assertion 2 line
#     names all three packages and both example file forms, `examples/NAME.rs` and
#     `examples/NAME/main.rs`; that the assertion 1 source-scan line names scp-ffi, whose
#     `examples/` holds a helper and no target, and scp-transport and not scp-clock, and
#     that it and header item 8 name `scripts/check-examples-compile.sh` as the one
#     statement of the scan's rules instead of restating them; and that no gate-edit line
#     appears on a branch that left the gate alone. A run that drops any of the three lines, the
#     dependency walk or the reachability filter reports green over a change the
#     rust-clippy job turns red.
#
#     Case 22c changes only `scripts/check-examples-compile.sh` and asserts that the
#     summary names that gate as unrun over this repository's workspace, and that it prints
#     neither assertion line, because the run compiled no crate. GATES_NOT_RUN keeps the
#     run from starting that gate, so without this line an edit to it reads as covered.
#     A second fixture adds `scripts/check-fixture-unstarted.sh` to its copy of
#     GATES_NOT_RUN, edits it and `scripts/check-resolved-rustc.sh`, and asserts a line for
#     the added gate and none for the toolchain precondition the run starts, so the line
#     covers every unstarted GATES_NOT_RUN entry rather than one hardcoded path.
#
#     Case 22d asserts that every GATES_NOT_RUN path the runner never starts with `bash`
#     appears in the header's DOES-NOT-RUN list, and that the list names `cargo package
#     --list`, which the examples gate runs in the rust-clippy job. A NOT CHECKED line the
#     list has no entry for names a command the header never told the reader about.
#
#     Case 23 reads every `scripts/` program a job of `.github/workflows/ci.yml` starts
#     with `bash`, `python3`, `python3.12`, `python3.12 -m pytest` or a `./` path, on a
#     one-line `run:` step or inside a `run: |` block, subtracts the runner's own GATES
#     and GATES_NOT_RUN arrays, and asserts that the `scripts/` entry of UNRUN_LANES names
#     every path that remains. The subtraction is the lane's own criterion: the lane
#     discloses a command CI runs that no step of the run starts or names. A path in GATES
#     is a command the run does start. A path in GATES_NOT_RUN is one the run either starts
#     as its toolchain precondition or names in the header's DOES-NOT-RUN list, and case
#     22d fails when an unstarted GATES_NOT_RUN path is missing from that list, and case
#     22c fails when a branch edits an unstarted GATES_NOT_RUN path and the run prints no
#     NOT CHECKED line naming it, so the GATES_NOT_RUN subtraction holds only while cases
#     22c and 22d do. That entry is what a fix agent
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
# It holds a fourth manifest, `crates/scp-transport`, because three entries in the runner's
# EXTRA_FEATURE_CHECKS array name that package, and case 13 reads the three
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
# leaves the run issuing one featureless `cargo check` and reporting `compile ok`. Case 13
# catches that mutation for the scp-transport entries, and case 13b catches it for the
# scp-node and scp-relay entries.
FIXTURE13="$WORK/optional-features"
build_fixture "$FIXTURE13"
fixture_commit "$FIXTURE13" crates/scp-transport/src/lib.rs
run_fixture "$FIXTURE13"
rc=$(cat "$FIXTURE13.harness/rc.txt")
if [[ $rc -eq 0 ]]; then
    report "case 13 exits 0 when every scp-transport compile passes" 0 ""
else
    report "case 13 exits 0 when every scp-transport compile passes" 1 "the script exited $rc; output tail: $(tail -n 6 "$FIXTURE13.harness/out.txt")"
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
# The PostgreSQL and S3 backends compile only under features no workspace member's
# dependency declaration requests, and the `rust-clippy` job names them in its own command.
if grep -qF 'check -p scp-transport --all-targets --features sqlite-blob,redb-blob,postgres-blob,s3-blob,startup' "$FIXTURE13.harness/cargo.log"; then
    report "case 13 compiles the cloud blob backends the rust-clippy job lints" 0 ""
else
    report "case 13 compiles the cloud blob backends the rust-clippy job lints" 1 "the stub cargo log holds: $(tr '\n' '|' < "$FIXTURE13.harness/cargo.log")"
fi

# ── Case 13b: each binary's cloud-blobs feature in checks of its own ─────────────────
#
# CI lints and tests the PostgreSQL and S3 blob backends of the two binaries in one
# command per package. The `rust-clippy` job runs `cargo clippy -p scp-node --features cloud-blobs,testing
# --all-targets` and `cargo clippy -p scp-relay --features cloud-blobs --all-targets`, and the
# `rust-test-optional-features` job runs `cargo nextest run -p scp-node --features cloud-blobs,testing
# --test storage_backend_selection` and `cargo nextest run -p scp-relay --features cloud-blobs
# --test storage_backend`. A joint command would let cargo unify scp-transport's features
# across both packages, so one package's `cloud-blobs` would compile the backends into the
# other package and hide that package's own mis-wired `cloud-blobs`. Each package's
# `--all-targets` check compiles the test target its test-lane command builds, under the
# same features, so no separate check mirrors the test lane. The `rust-doc` job and
# `.github/workflows/docs.yml` turn on both packages' `cloud-blobs` in one command, because
# rustdoc needs only the backend modules compiled; this script mirrors no rustdoc command.
#
# The mutations it kills: deleting either the scp-node or the scp-relay entry from
# EXTRA_FEATURE_CHECKS (the two positive assertions), and a runner that issues one cargo
# command turning on cloud-blobs for both packages (the negative assertion). Today's runner
# passes one `-p` per EXTRA_FEATURE_CHECKS entry, so only a rewrite of that loop can emit
# such a command; the three probe logs below prove the negative assertion goes red on it.
FIXTURE13B="$WORK/binary-cloud-blobs"
build_fixture "$FIXTURE13B"
for crate in scp-node scp-relay; do
    mkdir -p "$FIXTURE13B/crates/$crate/src"
    printf '[package]\nname = "%s"\nversion = "0.0.0"\n' "$crate" > "$FIXTURE13B/crates/$crate/Cargo.toml"
    printf '// fixture source\n' > "$FIXTURE13B/crates/$crate/src/lib.rs"
done
fixture_commit "$FIXTURE13B" crates/scp-node/src/lib.rs
fixture_commit "$FIXTURE13B" crates/scp-relay/src/lib.rs
run_fixture "$FIXTURE13B"
rc=$(cat "$FIXTURE13B.harness/rc.txt")
if [[ $rc -eq 0 ]]; then
    report "case 13b exits 0 when the cloud-blobs compiles pass" 0 ""
else
    report "case 13b exits 0 when the cloud-blobs compiles pass" 1 "the script exited $rc; output tail: $(tail -n 6 "$FIXTURE13B.harness/out.txt")"
fi
for expected in \
    'check -p scp-node --all-targets --features cloud-blobs,testing' \
    'check -p scp-relay --all-targets --features cloud-blobs'; do
    if grep -qF -- "$expected" "$FIXTURE13B.harness/cargo.log"; then
        report "case 13b runs \`$expected\`" 0 ""
    else
        report "case 13b runs \`$expected\`" 1 "the stub cargo log holds: $(tr '\n' '|' < "$FIXTURE13B.harness/cargo.log")"
    fi
done
# A joint check is any one cargo invocation that names both packages and `cloud-blobs`,
# whatever the order of its `-p` flags and wherever its `--features` sits.
joint_cloud_blobs_check() {
    awk 'index($0, "scp-node") && index($0, "scp-relay") && index($0, "cloud-blobs") { found = 1 } END { exit !found }' "$1"
}
JOINT_PROBE="$WORK/joint-cloud-blobs-probe.log"
for mutant in \
    'check -p scp-node -p scp-relay --all-targets --features cloud-blobs' \
    'check -p scp-relay -p scp-node --all-targets --features scp-node/cloud-blobs,scp-relay/cloud-blobs' \
    'check --features cloud-blobs -p scp-node -p scp-relay --all-targets'; do
    printf 'check -p scp-node --all-targets\n%s\n' "$mutant" > "$JOINT_PROBE"
    if joint_cloud_blobs_check "$JOINT_PROBE"; then
        report "case 13b's joint-check detector rejects \`$mutant\`" 0 ""
    else
        report "case 13b's joint-check detector rejects \`$mutant\`" 1 "the detector passed a log whose second line is that joint check"
    fi
done
if joint_cloud_blobs_check "$FIXTURE13B.harness/cargo.log"; then
    report "case 13b starts no check that turns on cloud-blobs for both binaries at once" 1 "the stub cargo log holds: $(tr '\n' '|' < "$FIXTURE13B.harness/cargo.log")"
else
    report "case 13b starts no check that turns on cloud-blobs for both binaries at once" 0 ""
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

# Case 22's metadata answer holds no package list, so the run cannot tell which compiled
# package has an example target and names every one of them, saying why.
if grep -qF 'NOT CHECKED — scripts/check-examples-compile.sh assertion 1 over the example targets that compile scp-clock (this run could not read their targets' "$FIXTURE22.harness/out.txt"; then
    report "case 22 names the examples gate over every package when it cannot read targets" 0 ""
else
    report "case 22 names the examples gate over every package when it cannot read targets" 1 "the output holds no qualified NOT CHECKED line for scripts/check-examples-compile.sh: $(tail -n 6 "$FIXTURE22.harness/out.txt")"
fi
if grep -qF 'NOT CHECKED — scripts/check-examples-compile.sh assertion 1 source scan over scp-clock (this run could not read their targets' "$FIXTURE22.harness/out.txt"; then
    report "case 22 names the examples source scan over every package when it cannot read targets" 0 ""
else
    report "case 22 names the examples source scan over every package when it cannot read targets" 1 "the output holds no qualified source-scan line for scripts/check-examples-compile.sh: $(tail -n 6 "$FIXTURE22.harness/out.txt")"
fi

# ── Case 22b: the examples gate over the packages each of its assertions reads ──────
#
# `scripts/check-examples-compile.sh` assertion 1 lints every `example` target, one at a
# time, with clippy under `-D warnings`, which this runner does not run. Each example
# compiles against its package's dependency graph, so a changed package with no example
# of its own still reaches that gate through a dependent's example. Cargo builds a
# dev-dependency only for the package declaring it, so the walk takes dev edges from the
# example owner alone. The fixture changes three packages. Its metadata answer gives an
# example target to scp-transport, which reaches scp-clock through its own dev-dependency
# on scp-ffi-napi, and scp-ffi-napi dev-depends on scp-ffi, which no example compiles. The
# assertion 1 line must name scp-clock and scp-transport and must not name scp-ffi.
# Assertion 2 runs `cargo package --list` on every workspace package, so its line must
# name all three, scp-ffi included.
#
# The mutations it kills: deleting the assertion 1 entry leaves a change to an example
# reported green here and red in the rust-clippy job; dropping the dependency walk leaves
# scp-clock out; dropping the reachability filter, or following dev edges below the
# example owner, names scp-ffi; deleting the assertion 2 entry, or filtering it by
# reachability, leaves scp-ffi's change unnamed.
FIXTURE22B="$WORK/example-targets"
build_fixture "$FIXTURE22B"
fixture_commit "$FIXTURE22B" crates/scp-clock/src/lib.rs
fixture_commit "$FIXTURE22B" crates/scp-transport/src/lib.rs
fixture_commit "$FIXTURE22B" crates/scp-ffi/src/lib.rs
mkdir -p "$FIXTURE22B/crates/scp-ffi/examples/support"
fixture_commit "$FIXTURE22B" crates/scp-ffi/examples/support/helpers.rs
HARNESS22B="$FIXTURE22B.harness"
write_stubs "$HARNESS22B" "$PIN_CHANNEL" 0 0 ""
cat > "$HARNESS22B/metadata.json" <<'JSON'
{"version":1,"target_directory":"/stub-target-dir","packages":[
 {"name":"scp-clock","dependencies":[],"targets":[{"name":"scp_clock","kind":["lib"]}]},
 {"name":"scp-ffi","dependencies":[{"name":"scp-clock","kind":null}],"targets":[{"name":"scp_ffi","kind":["lib"]}]},
 {"name":"scp-ffi-napi","dependencies":[{"name":"scp-clock","kind":null},{"name":"serde","kind":null},{"name":"scp-ffi","kind":"dev"}],"targets":[{"name":"scp_ffi_napi","kind":["lib"]}]},
 {"name":"scp-transport","dependencies":[{"name":"scp-ffi-napi","kind":"dev"}],"targets":[{"name":"scp_transport","kind":["lib"]},{"name":"relay","kind":["example"]}]}
]}
JSON
PATH="$HARNESS22B/bin:$PATH" bash "$FIXTURE22B/scripts/fix-round-check.sh" > "$HARNESS22B/out.txt" 2>&1
if grep -qF 'NOT CHECKED — scripts/check-examples-compile.sh assertion 1 over the example targets that compile scp-clock, scp-transport:' "$HARNESS22B/out.txt"; then
    report "case 22b names the examples gate over the packages an example compiles" 0 ""
else
    report "case 22b names the examples gate over the packages an example compiles" 1 "the output holds no NOT CHECKED line naming scp-clock and scp-transport alone: $(tail -n 6 "$HARNESS22B/out.txt")"
fi
if grep -F 'check-examples-compile.sh assertion 1 over the example targets that compile' "$HARNESS22B/out.txt" | grep -qF 'scp-ffi'; then
    report "case 22b names no package that no example compiles" 1 "$(grep -F 'check-examples-compile.sh' "$HARNESS22B/out.txt")"
else
    report "case 22b names no package that no example compiles" 0 ""
fi
A2_LINE=$(grep -F 'NOT CHECKED — scripts/check-examples-compile.sh assertion 2 over ' "$HARNESS22B/out.txt")
if [[ $A2_LINE == *scp-clock* && $A2_LINE == *scp-ffi* && $A2_LINE == *scp-transport* ]]; then
    report "case 22b names every changed package for the published-file assertion" 0 ""
else
    report "case 22b names every changed package for the published-file assertion" 1 "the assertion 2 line reads: ${A2_LINE:-<absent>}"
fi
# check-examples-compile.sh rejects an orphaned examples/NAME/main.rs as well as an
# orphaned examples/NAME.rs, because cargo auto-discovers both forms; a line naming one
# form tells the reader the gate passes the other.
if [[ $A2_LINE == *examples/NAME.rs* && $A2_LINE == *examples/NAME/main.rs* ]]; then
    report "case 22b names both published example forms the assertion 2 check rejects" 0 ""
else
    report "case 22b names both published example forms the assertion 2 check rejects" 1 "the assertion 2 line reads: ${A2_LINE:-<absent>}"
fi
# scp-clock has no example of its own; the rust-clippy job lints it anyway, because the
# gate passes no --no-deps and clippy lints every workspace library an example compiles.
# A line whose reason covers example source alone sends the reader to the examples when
# the warning sits in scp-clock's lib.
if grep -F 'check-examples-compile.sh assertion 1 over the example targets that compile' "$HARNESS22B/out.txt" |
    grep -qF 'without --no-deps, so it lints the example and every workspace library that example compiles'; then
    report "case 22b says the examples gate lints each library an example compiles" 0 ""
else
    report "case 22b says the examples gate lints each library an example compiles" 1 "the assertion 1 line gives no library-lint reason: $(grep -F 'check-examples-compile.sh assertion 1' "$HARNESS22B/out.txt")"
fi
# Assertion 1's source scan reads every .rs file under examples/ in every package, with
# or without an example target, so its line must name scp-ffi, whose examples/ holds a
# helper and no target, and scp-transport, which owns a target, and must not name
# scp-clock, which has neither. The mutations it kills: seeding the scan line from the
# reachability walk leaves scp-ffi out and names scp-clock; seeding it from target owners
# alone leaves scp-ffi out; naming every compiled package names scp-clock.
SCAN_LINE=$(grep -F 'NOT CHECKED — scripts/check-examples-compile.sh assertion 1 source scan over ' "$HARNESS22B/out.txt")
if [[ $SCAN_LINE == *'source scan over scp-ffi, scp-transport:'* ]]; then
    report "case 22b names the source scan over each package with an example target or examples/" 0 ""
else
    report "case 22b names the source scan over each package with an example target or examples/" 1 "the source-scan line reads: ${SCAN_LINE:-<absent>}"
fi
# The source-scan line and header item 8 do not restate the scan's rules: each names
# scripts/check-examples-compile.sh as the one statement of them, so a rule the gate
# gains or drops leaves both texts true. scan_points_to_gate passes a text that carries
# that pointer and fails one that drops it.
scan_points_to_gate() {
    [[ $1 == *'scripts/check-examples-compile.sh'*' is the one statement of the rules that scan applies'* ]]
}
# Item 8's text, comment markers stripped and its lines joined with single spaces.
HEADER8=$(awk '/^#   8\./ { on = 1 } /^# USAGE/ { on = 0 } on' "$REPO_ROOT/scripts/fix-round-check.sh" \
    | sed -E 's/^#[[:space:]]*//' | tr '\n' ' ' | tr -s ' ')
if scan_points_to_gate "$SCAN_LINE" && scan_points_to_gate "$HEADER8" \
    && ! scan_points_to_gate "${SCAN_LINE/is the one statement/is one statement}" \
    && ! scan_points_to_gate "${HEADER8/is the one statement/is one statement}" \
    && ! scan_points_to_gate "${SCAN_LINE//scripts\/check-examples-compile.sh/the gate}"; then
    report "case 22b points the source-scan line and header item 8 to the examples gate for its rules" 0 ""
else
    report "case 22b points the source-scan line and header item 8 to the examples gate for its rules" 1 "the source-scan line reads: ${SCAN_LINE:-<absent>}; header item 8 reads: ${HEADER8:-<absent>}"
fi
if grep -qF 'NOT CHECKED — scripts/check-examples-compile.sh over this repository' "$HARNESS22B/out.txt"; then
    report "case 22b names no unrun gate edit on a branch that left the gate alone" 1 "$(grep -F 'check-examples-compile.sh over this repository' "$HARNESS22B/out.txt")"
else
    report "case 22b names no unrun gate edit on a branch that left the gate alone" 0 ""
fi

# ── Case 22c: a branch that edits the examples gate alone ───────────────────────────
#
# GATES_NOT_RUN lists scripts/check-examples-compile.sh, so no run starts it, and a
# branch that edits only that script derives no crate. The fixture suite the scripts/
# lane names runs the gate over throwaway workspaces, so without its own line the edit
# reads as covered while the rust-clippy job runs the gate over every workspace package.
#
# The mutation it kills: deleting the CHANGED loop after GATES_NOT_RUN leaves this run
# with no line naming the gate it never ran. The run compiles no crate, so header item 8
# says it prints neither assertion line; moving either line out of the branch that
# compiles a crate turns the second check red.
FIXTURE22C="$WORK/examples-gate-edit"
build_fixture "$FIXTURE22C"
fixture_commit "$FIXTURE22C" scripts/check-examples-compile.sh
run_fixture "$FIXTURE22C"
if grep -qF "NOT CHECKED — scripts/check-examples-compile.sh over this repository's workspace: this branch changed that gate" "$FIXTURE22C.harness/out.txt"; then
    report "case 22c names the examples gate an edit left unrun" 0 ""
else
    report "case 22c names the examples gate an edit left unrun" 1 "the output holds no NOT CHECKED line for the edited gate: $(tail -n 6 "$FIXTURE22C.harness/out.txt")"
fi
if grep -qE 'NOT CHECKED — scripts/check-examples-compile\.sh assertion [12] ' "$FIXTURE22C.harness/out.txt"; then
    report "case 22c prints no examples-gate assertion line on a run that compiled no crate" 1 "$(grep -F 'check-examples-compile.sh assertion' "$FIXTURE22C.harness/out.txt")"
else
    report "case 22c prints no examples-gate assertion line on a run that compiled no crate" 0 ""
fi

# The CHANGED loop reads GATES_NOT_RUN rather than one path, so a second unstarted entry
# gets the same line. This fixture adds `scripts/check-fixture-unstarted.sh` to its copy
# of that array, holds the file, and commits an edit to it and to the toolchain
# precondition. The mutation it kills: matching one literal path in that loop leaves the
# added entry without a line. Dropping the precondition skip prints a line claiming the
# run never started a gate it started first.
FIXTURE22E="$WORK/unstarted-gate-edit"
build_fixture "$FIXTURE22E"
sed -i.bak 's|^    scripts/check-examples-compile.sh$|&\
    scripts/check-fixture-unstarted.sh|' "$FIXTURE22E/scripts/fix-round-check.sh"
rm -f "$FIXTURE22E/scripts/fix-round-check.sh.bak"
printf '#!/usr/bin/env bash\nexit 0\n' > "$FIXTURE22E/scripts/check-fixture-unstarted.sh"
git -C "$FIXTURE22E" add -A
git -C "$FIXTURE22E" -c user.email=fix-round-check@example.invalid -c user.name='fix-round-check tests' \
    commit -q --no-gpg-sign --no-verify -m 'fixture unstarted gate'
git -C "$FIXTURE22E" update-ref refs/remotes/origin/main HEAD
printf '# committed edit\n' >> "$FIXTURE22E/scripts/check-fixture-unstarted.sh"
printf '# committed edit\n' >> "$FIXTURE22E/scripts/check-resolved-rustc.sh"
git -C "$FIXTURE22E" add -A
git -C "$FIXTURE22E" -c user.email=fix-round-check@example.invalid -c user.name='fix-round-check tests' \
    commit -q --no-gpg-sign --no-verify -m 'fixture edit'
run_fixture "$FIXTURE22E"
if ! sed -n '/^GATES_NOT_RUN=(/,/^)/p' "$FIXTURE22E/scripts/fix-round-check.sh" | grep -qF 'scripts/check-fixture-unstarted.sh'; then
    report "case 22c names any unstarted GATES_NOT_RUN gate an edit left unrun" 1 "the fixture's GATES_NOT_RUN gained no scripts/check-fixture-unstarted.sh entry, so this case tested nothing"
elif grep -qF "NOT CHECKED — scripts/check-fixture-unstarted.sh over this repository's workspace: this branch changed that gate, and this run never starts it" "$FIXTURE22E.harness/out.txt"; then
    report "case 22c names any unstarted GATES_NOT_RUN gate an edit left unrun" 0 ""
else
    report "case 22c names any unstarted GATES_NOT_RUN gate an edit left unrun" 1 "the output holds no NOT CHECKED line for the edited fixture gate: $(tail -n 8 "$FIXTURE22E.harness/out.txt")"
fi
if grep -qF 'NOT CHECKED — scripts/check-resolved-rustc.sh over this repository' "$FIXTURE22E.harness/out.txt"; then
    report "case 22c claims no unrun edit for the toolchain precondition the run starts" 1 "$(grep -F 'check-resolved-rustc.sh over this repository' "$FIXTURE22E.harness/out.txt")"
else
    report "case 22c claims no unrun edit for the toolchain precondition the run starts" 0 ""
fi
if grep -q '^  UNCLASSIFIED' "$FIXTURE22E.harness/out.txt"; then
    report "case 22c classifies the gate its fixture added" 1 "$(grep '^  UNCLASSIFIED' "$FIXTURE22E.harness/out.txt")"
else
    report "case 22c classifies the gate its fixture added" 0 ""
fi

# ── Case 22d: the DOES-NOT-RUN header names every gate the run never starts ──────────
#
# The header's DOES-NOT-RUN list is what a reader consults for the CI commands a green run
# leaves unproven, and a NOT CHECKED line the list has no entry for is a command the reader
# was never told about. Every GATES_NOT_RUN entry the script does not start as a `bash`
# command must appear between the list's heading and `# USAGE`. Deleting item 8 turns this
# case red; so does adding a compiling gate to GATES_NOT_RUN without a list entry.
HEADER_LIST=$(sed -n '/^# WHAT THIS SCRIPT DOES NOT RUN/,/^# USAGE/p' "$SCRIPT")
NOT_RUN_PATHS=$(sed -n '/^GATES_NOT_RUN=(/,/^)/p' "$SCRIPT" | grep -oE '^ *scripts/[^ ]+' | tr -d ' ')
HEADER_MISSING=""
while IFS= read -r gate; do
    [[ -n $gate ]] || continue
    grep -qE "^[^#]*bash $gate" "$SCRIPT" && continue
    [[ $HEADER_LIST == *"$gate"* ]] || HEADER_MISSING+=" $gate"
done <<< "$NOT_RUN_PATHS"
if [[ -n $HEADER_LIST && -n $NOT_RUN_PATHS && -z $HEADER_MISSING ]]; then
    report "case 22d names every unstarted GATES_NOT_RUN gate in the DOES-NOT-RUN list" 0 ""
else
    report "case 22d names every unstarted GATES_NOT_RUN gate in the DOES-NOT-RUN list" 1 "header list read ${#HEADER_LIST} bytes, GATES_NOT_RUN read: ${NOT_RUN_PATHS:-<none>}; missing:${HEADER_MISSING:-<none>}"
fi
if [[ $HEADER_LIST == *'cargo package --list'* ]]; then
    report "case 22d names cargo package --list in the DOES-NOT-RUN list" 0 ""
else
    report "case 22d names cargo package --list in the DOES-NOT-RUN list" 1 "the DOES-NOT-RUN list names no cargo package --list, which the examples gate runs in the rust-clippy job"
fi

# ── Case 23: the scripts/ lane against the suites CI runs over that directory ────────
#
# The `scripts/` entry of UNRUN_LANES is a hand-written enumeration, and a fix agent that
# edits an enforcement gate acts on it: the runner starts that gate against a clean tree,
# the gate passes, and the only program that proves the gate still rejects what it exists
# to reject is the fixture suite that entry names. A suite the entry omits is a red CI job
# the output gave the agent no reason to expect.
#
# This case reads every `scripts/` program that `.github/workflows/ci.yml` starts with
# `bash`, `python3`, `python3.12`, `python3.12 -m pytest` or a `./` path, wherever the
# start sits: on a one-line `run:` step or on any line of a `run: |` block. It subtracts
# the paths the runner's GATES and GATES_NOT_RUN arrays name, and fails when the entry
# names fewer than what remains. Adding a suite to CI without adding it there turns this
# case red rather than going unnoticed, whichever form of `run:` step starts it.
#
# THE SUBTRACTION IS THE CRITERION, and it is the lane's own: `scripts/fix-round-check.sh`
# admits an entry for a command CI runs that no step of the run starts. A path in GATES is
# a command the run does start, so the lane owes the reader nothing about it. A path in
# GATES_NOT_RUN is one the run either starts as its toolchain precondition or names in its
# DOES-NOT-RUN list, which case 22d holds, so the lane owes the reader nothing about it
# either. Every other path CI starts under `scripts/` is one the run leaves unread and the
# lane has to name. Reading both arrays off the script rather than filtering on a
# `scripts/test…` name keeps this case closed: a suite a later round files under any other
# directory name still has to appear in the lane.
ci_script_starts() {
    grep -oE '(bash +|python3(\.12)?( +-m +pytest)? +|\./)scripts/[^ "]+' | grep -oE 'scripts/[^ "]+$' | sort -u
}
# The extractor's own check, on a fixture holding each start form this case claims to
# read. A narrower pattern, such as one anchored on `run:`, drops the start inside the
# `run: |` block and turns this assertion red.
CI_STARTS_FIXTURE=$(ci_script_starts <<'YAML'
      - run: bash scripts/one-line.sh
      - run: |
          cargo clippy --workspace
          bash scripts/in-block.sh
      - run: python3.12 -m pytest scripts/tests/pytest-dir/ -v
      - run: python3 scripts/plain-python.py .github/workflows/ci.yml
      - run: ./scripts/dot-slash.sh --skip-build
YAML
)
CI_STARTS_WANT=$(printf '%s\n' scripts/dot-slash.sh scripts/in-block.sh scripts/one-line.sh scripts/plain-python.py scripts/tests/pytest-dir/ | sort -u)
if [[ $CI_STARTS_FIXTURE == "$CI_STARTS_WANT" ]]; then
    report "case 23 reads a scripts/ start in every run-step form" 0 ""
else
    report "case 23 reads a scripts/ start in every run-step form" 1 "wanted: $(echo $CI_STARTS_WANT); read: $(echo $CI_STARTS_FIXTURE)"
fi
LANE_LINE=$(sed -n '/^UNRUN_LANES=(/,/^)/p' "$SCRIPT" | grep -F '"scripts/|')
LANE_SUITES=$(comm -23 \
    <(ci_script_starts < "$REPO_ROOT/.github/workflows/ci.yml") \
    <({ gate_paths; printf '%s\n' "$NOT_RUN_PATHS"; } | sort -u))
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
# empty suite list gives the loop no iteration. A renamed UNRUN_LANES array empties the
# first, and a reworded `run:` step in the workflow that the extractor no longer reads
# empties the second; each would otherwise leave this case green while reading nothing.
if [[ -n $LANE_LINE ]]; then
    report "case 23 found the scripts/ entry it reads" 0 ""
else
    report "case 23 found the scripts/ entry it reads" 1 "scripts/fix-round-check.sh holds no UNRUN_LANES entry beginning \"scripts/|\", so the assertion above read an empty string and could not fail"
fi
if [[ $LANE_SUITE_COUNT -gt 0 ]]; then
    report "case 23 read a non-empty suite set out of .github/workflows/ci.yml" 0 ""
else
    report "case 23 read a non-empty suite set out of .github/workflows/ci.yml" 1 "subtracting the GATES and GATES_NOT_RUN arrays from the scripts/ programs .github/workflows/ci.yml starts left no path, so the assertion above iterated over nothing and could not fail"
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
# above reads out of `.github/workflows/ci.yml` and subtracts the GATES and GATES_NOT_RUN
# arrays from, so a suite CI gains reaches this case too and a gate the run itself starts
# or names in its DOES-NOT-RUN list stays out of it —
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
