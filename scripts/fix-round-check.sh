#!/usr/bin/env bash
#
# The check a fix round runs before it pushes.
#
# WHAT THIS SCRIPT IS FOR. A fix round reads two to five review findings, edits the files
# those findings cite, writes a test, checks the result, formats, commits, and pushes.
# Alec set the target for that round on 2026-09-11: "fix rounds should take minues." The
# round misses that target when the agent assembles cargo flags itself, because the three
# flag mistakes below each cost between ten minutes and an hour on this machine, and the
# agent discovers the cost only after paying it.
#
#   1. Compiling the whole workspace. `cargo clippy --workspace --all-targets` with the
#      feature set the `rust-clippy` job of `.github/workflows/ci.yml` names compiles 26
#      workspace members and every test target each one declares. That command is the
#      merge gate, and CI runs it on the pushed head. A fix agent that runs it locally
#      pays for it twice and blocks its own round on the local copy.
#   2. Compiling into a private target directory. `~/.cargo/config.toml` points every
#      worktree on this machine at one shared target directory, and a `CARGO_TARGET_DIR`
#      in the environment replaces it, which recompiles all 713 dependencies. Alec ruled
#      on that substitution on 2026-08-30, verbatim: "this is the reason we have a shared
#      build target, dummy."
#      `.docs/lessons/the-shared-target-directory-has-one-lock.md` records what that
#      directory costs a fix round today, and every measurement this file quotes.
#   3. Compiling on a compiler `rust-toolchain.toml` does not name. `RUSTUP_TOOLCHAIN`
#      replaces that file entirely, and a clippy run on the wrong compiler still exits 0,
#      because a lint the pinned release added reports as `unknown_lints`, which
#      `-D warnings` does not deny. The gate then passes and proves nothing.
#
# WHAT THIS SCRIPT RUNS, and the criterion that put each step in the list: a step belongs
# here when a fix agent's edit can falsify it in seconds of compute, and CI would
# otherwise report the failure twenty minutes later.
#
#   toolchain  `scripts/check-resolved-rustc.sh`, which compares the compiler this shell
#              resolves against the channel `rust-toolchain.toml` names. Measured at under
#              a second.
#   compile    `cargo check -p <crate> --all-targets` over the crates this run selects,
#              with the subset of the CI feature list those crates own, and one further
#              `cargo check` for each optional feature set a cargo command in
#              `.github/workflows/ci.yml` names for a selected package. This is the step
#              that takes minutes, and the one whose cost the summary line reports.
#   format     `cargo fmt --all -- --check`, the command the `rust-fmt` job of
#              `.github/workflows/ci.yml` runs. Measured at 2.83 seconds over the whole
#              workspace on 2026-09-13, and at more than three and a half minutes the same
#              day while another worktree's `cargo check` held the build lock, because
#              `cargo fmt` resolves the workspace through a full `cargo metadata` first.
#              rustfmt reads `rustfmt.toml`, so this step checks a change to that file
#              over every crate the manifests name.
#   gates      The 29 enforcement scripts that compile nothing and link nothing. Measured
#              together at 47 seconds on 2026-09-13, one run each, over the 28 the list
#              held that day.
#
# WHAT THIS SCRIPT CANNOT SHORTEN. Every worktree on this machine compiles into one shared
# target directory, and that directory has one build lock. Measured on 2026-09-13:
# `cargo check -p scp-protocol --all-targets` in a fresh worktree took 29 minutes 40
# seconds, of which 23 minutes 16 seconds was waiting for that lock behind another
# worktree's cargo, and 6 minutes 24 seconds was compiling. Every cargo command this script
# runs joins that one queue, so the summary line's seconds report a wait as readily as
# work. When cargo prints "Blocking waiting for file lock on build directory", the run is
# queued rather than compiling, and starting a second cargo command beside it lengthens the
# queue. `.docs/lessons/the-shared-target-directory-has-one-lock.md` records the whole
# decomposition, including the editor that queues on the same lock from another project.
#
# WHAT THIS SCRIPT DOES NOT RUN. THE CRITERION for this list: a command that a job of
# `.github/workflows/ci.yml` runs over a file a fix round can change, and that no step
# above starts. A green result from this script establishes nothing about any of them.
# After the summary, this script prints one line under the literal prefix `NOT CHECKED`
# for each entry below that this branch's changed files or this run's crate set reach,
# naming the directory and the file count or the packages, so a fix agent reads which of
# its own edits went unread rather than inferring it from this comment. Items 1, 2 and the
# `cargo doc`, `cargo deny` and `docker build` half of item 6 hold for every run whatever
# the branch changed, so the summary's `skipped` clause names them once instead.
#
#   1. `cargo nextest`, `cargo test` and `cargo build`, in every form, narrowed or not.
#      Each links one binary per test target, and every freshly written executable on
#      macOS pays a Gatekeeper assessment on its first exec: measured on 2026-09-13,
#      203 ms from queue to scan finished for a 16 KB binary, and 0 further assessments
#      on later execs of the same bytes. That cost per binary is small, but the link step
#      is not, and a workspace nextest links dozens. On 2026-09-11 that queue reached 31
#      minutes per item and a fix round died inside it. Nine jobs run one of those three
#      commands on the pushed head: `rust-test`, `rust-test-optional-features`,
#      `rust-test-napi-production`, `rust-build-pyo3-production`,
#      `rust-build-uniffi-production`, `fail-closed-pre-rotation`, and the three
#      `bridge-parity` jobs.
#   2. `cargo clippy`, in every form. The compile step runs `cargo check`, which reports
#      no clippy lint at all, so a `clippy::needless_borrow` in the file this round edited
#      passes here and fails in the `rust-clippy` job. That job is the merge gate, and it
#      also reads `.clippy.toml`, which is why this script treats no change to that file
#      as checkable.
#   3. The reverse dependencies of the crates the compile step selects. `cargo check -p`
#      compiles the named packages alone, so a changed public signature in `scp-protocol`
#      compiles here and fails to compile `scp-runtime` in CI.
#   4. Every per-language lint, type check and test lane: ruff and pytest over
#      `bindings/python/`, biome and `tsc` and `bun test` over `bindings/typescript/` and
#      `bindings/typescript-wasm/`, the scaffold build over `scaffolds/`, ktlint and
#      detekt and the Gradle test task over `bindings/kotlin/`, SwiftLint and SwiftFormat
#      and `swift build` over `bindings/swift/`, and `cargo check` inside `fuzz/` on the
#      nightly `fuzz/rust-toolchain.toml` names. Four of the gates below read files under
#      those directories, each for one property of its own, and a gate that reads one
#      property is not a lint of that language.
#   5. The uncommitted half of a working tree, for one gate.
#      `scripts/check-cross-layer.sh` decides from
#      `git diff <merge base with origin/main>...HEAD`, which holds no uncommitted edit,
#      so its pass covers the committed half alone. It is the one gate in the list below
#      that reads a diff range, and the other 28 read the working tree.
#   6. Every compile of a crate source that the native `cargo check` above does not
#      reach. `cargo check -p … --target wasm32-unknown-unknown` over scp-clock,
#      scp-crypto, scp-did, scp-protocol, scp-relay-client, scp-mls, scp-client,
#      scp-event-log and scp-client-wasm, which the `wasm-protocol` job runs and which
#      rejects a host-only API a native check accepts; `wasm-pack test` over
#      scp-client-wasm, which the `wasm-test` job runs; `cargo doc --workspace --no-deps
#      --document-private-items`, which the `rust-doc` job runs and which reports the
#      broken intra-doc links `cargo check` never reports; `cargo deny`, which the
#      `rust-deny` job runs over `deny.toml` and the lockfile; and the `docker build` of
#      `Dockerfile`, which the `docker-image` job runs. Each compiles a crate graph into
#      a target directory this script's `cargo check` never writes, so each costs a cold
#      build on first use, and the step criterion above admits a step a fix agent's edit
#      falsifies in seconds.
#   7. The suites that read `.github/` and `scripts/` and that no gate below duplicates:
#      `scripts/tests/ci-gate/run-tests.sh` and `scripts/tests/signing-guard/run-tests.sh`
#      in the `ci-workflow-selftest` job, `scripts/tests/toolchain-wiring/run-tests.sh`
#      and `scripts/tests/workflow-compile-steps/run-tests.sh` in the `toolchain-wiring`
#      job, and `scripts/tests/fix-round-check/run-tests.sh` in the
#      `fix-round-check-selftest` job. The last one runs the whole gate list below twice
#      against this repository, so running it from inside this script would run that list
#      three times in one invocation.
#
# USAGE
#   bash scripts/fix-round-check.sh [crate ...]
#
# Naming no crate makes the script derive the crate set from the files this branch
# changed, and print which crates it derived. Naming a crate that the workspace does not
# hold fails the run rather than checking a smaller set than the caller asked for. Naming
# a set narrower than the branch's own changed files compiles the set the caller asked
# for, and names in the summary every package the branch changed that this run left
# uncompiled.
#
# EXIT. 0 when every step this script ran exited 0. 1 when any step exited non-zero, when
# a named crate is absent from the workspace, when a gate script this list names does not
# exist, and when this branch changed a file that every workspace member compiles against
# while changing no file inside a workspace crate. No `-p`-narrowed `cargo check` covers
# that last shape, so a run that reported it as a skip would exit 0 having compiled zero
# lines of a change that recompiles all 26 members.
#
# The toolchain step is a precondition rather than one failure among several: a compile on
# a compiler the pin does not name reports lints that CI will not report and misses lints
# that CI will, so the script exits on that failure and starts no cargo command. Every
# later step runs even after an earlier one fails, so one round reports every failure
# rather than only the first.

set -uo pipefail

if ! cd "$(dirname "$0")/.."; then
    printf 'fix-round-check: this script could not enter its own repository root, so it checked nothing.\n' >&2
    exit 1
fi
REPO_ROOT=$(pwd -P)

# ── The environment the rest of this script runs in ──────────────────────────────────
#
# Both variables below are removed rather than reported, because a fix agent that receives
# a report has to act on it and rerun, and the correct action is the same every time.
# `scripts/check-resolved-rustc.sh` below then reports the compiler that remains, so
# removing the variable does not hide a compiler the pin does not name.
toolchain_note="RUSTUP_TOOLCHAIN was already unset"
if [[ -n ${RUSTUP_TOOLCHAIN:-} ]]; then
    toolchain_note="unset RUSTUP_TOOLCHAIN=$RUSTUP_TOOLCHAIN, so rustup reads rust-toolchain.toml"
    unset RUSTUP_TOOLCHAIN
fi

target_note="CARGO_TARGET_DIR was already unset"
if [[ -n ${CARGO_TARGET_DIR:-} ]]; then
    target_note="unset CARGO_TARGET_DIR=$CARGO_TARGET_DIR, so cargo's own configuration selects the shared cache"
    unset CARGO_TARGET_DIR
fi

if ! command -v cargo >/dev/null 2>&1; then
    printf 'fix-round-check: cargo is not on PATH, so this script compiled nothing and checked no formatting. Install rustup from https://rustup.rs, which reads rust-toolchain.toml.\n' >&2
    exit 1
fi

# `timeout` bounds the `cargo metadata` call below and each of the 29 gates, so 30 call
# sites depend on it. macOS ships neither `timeout` nor `gtimeout`, Homebrew's coreutils
# supplies both names, and `.mise.toml` provisions neither, so a checkout that installed
# only the prerequisites README.md lists has no such program. Without this guard every gate
# would exit 127, and the run would print 29 blocks reading "timeout: command not found"
# and report 29 enforcement violations that do not exist.
TIMEOUT=timeout
command -v "$TIMEOUT" >/dev/null 2>&1 || TIMEOUT=gtimeout
if ! command -v "$TIMEOUT" >/dev/null 2>&1; then
    printf 'fix-round-check: neither timeout nor gtimeout is on PATH, and this script bounds its cargo metadata call and every gate with one of them, so it checked nothing. Install GNU coreutils (brew install coreutils), then run this script again.\n' >&2
    exit 1
fi

# ── Precondition: the compiler this shell resolves ───────────────────────────────────
#
# `scripts/check-resolved-rustc.sh` holds the comparison for every caller in this
# repository, so this script reads its answer rather than restating the expression that
# reads the channel out of rust-toolchain.toml. It prints one line per finding and exits
# non-zero when the compiler answering here is not the version the pin names.
#
# This runs before any cargo command, and its failure ends the run. A `cargo check` on
# another compiler compiles into a separate hash space of the shared target directory,
# reports lints the pinned release does not report, and passes over lints it does, so the
# result answers a question the merge gate did not ask.
printf '── toolchain: bash scripts/check-resolved-rustc.sh\n'
toolchain_t0=$(date +%s)
if ! bash scripts/check-resolved-rustc.sh; then
    printf '\nfix-round-check: the compiler this shell resolves is not the one rust-toolchain.toml names, so this script started no cargo command and ran no gate. Fix the cause the line above names, then run this script again.\n' >&2
    exit 1
fi
toolchain_t1=$(date +%s)

# The directory cargo compiles into, for the summary line. `cargo metadata --no-deps
# --offline` reads the manifests and the lockfile and compiles nothing: measured three
# times in a row at 68, 68, and 72 ms on 2026-09-13. The same command under a concurrent
# `cargo check` of another worktree took two and a half minutes on the same day, for a
# reason that measurement did not establish, so the call carries a 60-second bound. The
# value it produces names a directory in one line of output and decides nothing, so a bound
# that expires prints that it expired and the run continues.
# `timeout` returns 124 for its own bound and the command's own status otherwise, and the
# two mean different things to a reader: 124 says the queue held the call, while a manifest
# cargo rejects makes it exit 1 in well under a second. An earlier revision printed the
# timeout message for both, which pointed a reader at the build lock while its own manifest
# was the fault.
metadata_rc=0
metadata=$("$TIMEOUT" 60 cargo metadata --no-deps --format-version 1 --offline 2>/dev/null) || metadata_rc=$?
if [[ $metadata_rc -eq 0 ]]; then
    target_dir=$(printf '%s' "$metadata" | sed -nE 's/.*"target_directory":"([^"]*)".*/\1/p')
    [[ -n $target_dir ]] || target_dir="(cargo metadata named no target directory)"
elif [[ $metadata_rc -eq 124 ]]; then
    target_dir="(cargo metadata did not answer within 60s, so this line names no target directory)"
else
    target_dir="(cargo metadata exited $metadata_rc, so this line names no target directory)"
fi

# ── The crate set ────────────────────────────────────────────────────────────────────
#
# Each workspace member's directory maps to its package name. The map is read from the
# manifests rather than from the directory names, because four members sit under
# `crates/scp-ffi/` whose directory names differ from their package names.
declare -a MANIFEST_DIRS=()
declare -a MANIFEST_NAMES=()
while IFS= read -r manifest; do
    name=$(sed -nE 's/^name[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' "$manifest" | head -n 1)
    [[ -n $name ]] || continue
    MANIFEST_DIRS+=("$(dirname "$manifest")")
    MANIFEST_NAMES+=("$name")
done < <(find crates -maxdepth 3 -name Cargo.toml -type f | sort)

if [[ ${#MANIFEST_NAMES[@]} -eq 0 ]]; then
    printf 'fix-round-check: no Cargo.toml under crates/, so this script could not resolve any crate.\n' >&2
    exit 1
fi

crate_exists() {
    local want=$1 n
    for n in "${MANIFEST_NAMES[@]}"; do
        [[ $n == "$want" ]] && return 0
    done
    return 1
}

# The package that owns a path, or the empty string. The longest matching manifest
# directory wins, so `crates/scp-ffi/napi/src/lib.rs` resolves to the napi package rather
# than to `scp-ffi`.
crate_of_path() {
    local path=$1 best="" best_len=0 i dir
    for i in "${!MANIFEST_DIRS[@]}"; do
        dir=${MANIFEST_DIRS[$i]}
        if [[ $path == "$dir"/* ]] && (( ${#dir} > best_len )); then
            best=${MANIFEST_NAMES[$i]}
            best_len=${#dir}
        fi
    done
    printf '%s' "$best"
}

# The files this branch changed: everything the working tree holds that differs from
# HEAD, plus every file the commits since the merge base with origin/main touched. A fix
# round runs this script with edits uncommitted, with edits committed, and with both.
#
# A FAILURE HERE ENDS A RUN THAT NAMED NO CRATE. An earlier revision discarded both git
# errors, so a checkout holding no `origin/main` ref — a single-branch clone, or an
# extracted tarball — produced an empty file list, an empty crate set, a skipped compile
# step, and exit 0. That is the shape this whole script exists to prevent: a green result
# that compiled nothing, on a branch whose commits changed crate sources. A run that named
# its own crates compiles that set either way, and states in its summary that it could not
# read the branch's files, so its NOT CHECKED lines are absent rather than empty.
changed_files() {
    local status base
    if ! status=$(git -C "$REPO_ROOT" status --porcelain); then
        printf 'fix-round-check: git status failed in %s, so this script could not read which files this branch changed.\n' "$REPO_ROOT" >&2
        return 1
    fi
    printf '%s\n' "$status" | sed -E 's/^.{3}//; s/^.* -> //'
    if ! base=$(git -C "$REPO_ROOT" merge-base HEAD origin/main 2>/dev/null); then
        printf 'fix-round-check: this checkout holds no merge base between HEAD and origin/main, so this script could not read which files this branch changed. Fetch origin/main, and this run derives its crate set and names every change it leaves unchecked.\n' >&2
        return 1
    fi
    git -C "$REPO_ROOT" diff --name-only "$base" HEAD
}

# The paths the working tree holds uncommitted, counted for the cross-layer note below.
uncommitted_count=0
if uncommitted=$(git -C "$REPO_ROOT" status --porcelain 2>/dev/null); then
    uncommitted_count=$(printf '%s\n' "$uncommitted" | sed '/^[[:space:]]*$/d' | wc -l | tr -d ' ')
fi

# NOTES holds one entry per change of this branch that no step of this run reads. The
# summary prints each under the literal prefix `NOT CHECKED`, because a fix agent reads the
# last lines of this output and pushes on them.
declare -a NOTES=()

# `changed_files` runs on every invocation rather than only on the derivation, because
# every NOT CHECKED line is computed from its answer. `set -o pipefail` is on, so a failing
# `changed_files` propagates through `sort -u`.
changed_rc=0
CHANGED=$(changed_files | sort -u) || changed_rc=$?

# The packages that own a newline-separated list of paths, each package named once.
crates_from_paths() {
    local paths=$1 f owner seen c
    declare -a found=()
    while IFS= read -r f; do
        [[ -n $f ]] || continue
        owner=$(crate_of_path "$f")
        [[ -n $owner ]] || continue
        seen=0
        for c in ${found[@]+"${found[@]}"}; do
            [[ $c == "$owner" ]] && seen=1
        done
        [[ $seen -eq 0 ]] && found+=("$owner")
    done <<< "$paths"
    printf '%s\n' ${found[@]+"${found[@]}"}
}

declare -a DERIVED=()
if [[ $changed_rc -eq 0 ]]; then
    while IFS= read -r c; do
        [[ -n $c ]] || continue
        DERIVED+=("$c")
    done < <(crates_from_paths "$CHANGED")
fi

declare -a CRATES=()
crate_source=""
if [[ $# -gt 0 ]]; then
    crate_source="named by the caller"
    for c in "$@"; do
        if ! crate_exists "$c"; then
            printf 'fix-round-check: %s is not a package in this workspace, so this script checked nothing. Run it with a package name from crates/*/Cargo.toml.\n' "$c" >&2
            exit 1
        fi
        CRATES+=("$c")
    done
    if [[ $changed_rc -ne 0 ]]; then
        NOTES+=("which files this branch changed: the line above states why this run could not read them, so this run names no unchecked change of its own")
    else
        # A caller-named set narrower than the branch's own edits compiles less than the
        # branch changed. The caller asked for that set, and no other line of this output
        # would say which of the branch's packages went uncompiled.
        declare -a UNNAMED=()
        for d in ${DERIVED[@]+"${DERIVED[@]}"}; do
            seen=0
            for c in "${CRATES[@]}"; do
                [[ $c == "$d" ]] && seen=1
            done
            [[ $seen -eq 0 ]] && UNNAMED+=("$d")
        done
        if [[ ${#UNNAMED[@]} -gt 0 ]]; then
            NOTES+=("$(IFS=' '; printf '%s' "${UNNAMED[*]}"): this branch changed files these packages own, and the caller named a crate set that leaves them out, so this run compiled none of them")
        fi
    fi
else
    crate_source="derived from the files this branch changed"
    if [[ $changed_rc -ne 0 ]]; then
        printf 'fix-round-check: the line above names why this script could not derive a crate set, so it compiled nothing and ran no gate.\n' >&2
        exit 1
    fi
    CRATES=(${DERIVED[@]+"${DERIVED[@]}"})
fi

# ── The changes this run reads no file of ────────────────────────────────────────────
#
# THE CRITERION for this list: a file that no `crates/<member>` directory holds and that
# every workspace member's compile reads, so a `cargo check` narrowed with `-p` proves
# nothing about a change to it. `Cargo.toml` carries the `[workspace.dependencies]` table
# every member's manifest inherits from, `Cargo.lock` fixes the version cargo resolves for
# each of those, `rust-toolchain.toml` names the compiler every member compiles on, and
# `.cargo/config.toml` sets the flags cargo passes to every rustc it starts.
#
# `rustfmt.toml` and `.clippy.toml` are absent from this list on purpose. The format step
# runs `cargo fmt --all` over every crate the manifests name, so this script checks a
# `rustfmt.toml` change in full. `.clippy.toml` changes what `cargo clippy` reports, and
# item 2 of the DOES-NOT-RUN list above already states that this script runs no clippy.
WORKSPACE_WIDE_INPUTS=(
    Cargo.toml
    Cargo.lock
    rust-toolchain.toml
    .cargo/config.toml
)

declare -a CHANGED_WIDE=()
if [[ $changed_rc -eq 0 ]]; then
    while IFS= read -r f; do
        [[ -n $f ]] || continue
        for w in "${WORKSPACE_WIDE_INPUTS[@]}"; do
            [[ $f == "$w" ]] && CHANGED_WIDE+=("$f")
        done
    done <<< "$CHANGED"
fi
wide_list=""
[[ ${#CHANGED_WIDE[@]} -gt 0 ]] && wide_list=$(IFS=' '; printf '%s' "${CHANGED_WIDE[*]}")

# THE CRITERION for this list: a directory whose sources a job of
# `.github/workflows/ci.yml` lints, type-checks, or tests with a program no step of this
# script starts. Each entry names the directory, then the programs, then the jobs that run
# them, so a reader acts on the line without opening the workflow file.
#
# `crates/` is absent because the compile, format and gate steps above read it, and the
# Rust commands they still leave unrun are the same for every run, which is why items 1,
# 2, 3 and 6 of the DOES-NOT-RUN list state them once rather than per changed file. The
# reverse-dependency line and the wasm line below are the two that name the packages a
# given run selected, so both are computed rather than listed here.
UNRUN_LANES=(
    "bindings/python/|ruff and pytest, which the python-lint and python-test jobs of .github/workflows/ci.yml run"
    "bindings/typescript/|biome, tsc and bun test, which the typescript-check job of .github/workflows/ci.yml runs"
    "bindings/typescript-wasm/|the wasm build and its lint, which the typescript-wasm-check job of .github/workflows/ci.yml runs"
    "scaffolds/|the scaffold build, check and lint, which the scaffold-typescript-web-check job of .github/workflows/ci.yml runs"
    "bindings/kotlin/|ktlint, detekt and the Gradle test task, which the kotlin-lint and kotlin-test jobs of .github/workflows/ci.yml run"
    "bindings/swift/|SwiftLint, SwiftFormat and swift build, which the swift-lint and swift-build-test jobs of .github/workflows/ci.yml run"
    "fuzz/|cargo check inside fuzz/ on the nightly fuzz/rust-toolchain.toml names, which the fuzz-build job of .github/workflows/ci.yml runs"
    ".github/|scripts/tests/ci-gate/run-tests.sh and scripts/tests/signing-guard/run-tests.sh, which the ci-workflow-selftest job of .github/workflows/ci.yml runs. One gate this run did start, scripts/check-workflow-compile-steps.py, read these files for its cache-group and bindgen rules alone"
    "scripts/|scripts/tests/ci-gate/run-tests.sh, scripts/tests/toolchain-wiring/run-tests.sh, scripts/tests/workflow-compile-steps/run-tests.sh and scripts/tests/fix-round-check/run-tests.sh, which the ci-workflow-selftest, toolchain-wiring and fix-round-check-selftest jobs of .github/workflows/ci.yml run"
)

if [[ $changed_rc -eq 0 ]]; then
    for lane in "${UNRUN_LANES[@]}"; do
        lane_prefix=${lane%%|*}
        lane_tools=${lane#*|}
        lane_count=0
        while IFS= read -r f; do
            [[ -n $f ]] || continue
            [[ $f == "$lane_prefix"* ]] && lane_count=$((lane_count + 1))
        done <<< "$CHANGED"
        [[ $lane_count -eq 0 ]] && continue
        NOTES+=("$lane_count file(s) under $lane_prefix: this run started none of $lane_tools")
    done
fi

if [[ $uncommitted_count -gt 0 ]]; then
    NOTES+=("the $uncommitted_count uncommitted path(s) in this working tree, for one gate: scripts/check-cross-layer.sh decides from git diff <merge base with origin/main>...HEAD, which holds no uncommitted edit, so its pass read the committed half alone. Commit those paths and run this script again to have that gate read them")
fi

# ── The steps ────────────────────────────────────────────────────────────────────────
FAILED=0
declare -a RAN=("toolchain ok $((toolchain_t1 - toolchain_t0))s")
declare -a SKIPPED=()

run_step() {
    local label=$1
    shift
    local t0 t1
    t0=$(date +%s)
    printf '\n── %s: %s\n' "$label" "$*"
    if "$@"; then
        t1=$(date +%s)
        RAN+=("$label ok $((t1 - t0))s")
    else
        t1=$(date +%s)
        RAN+=("$label FAILED $((t1 - t0))s")
        FAILED=1
    fi
}

# Step 2 — compile.
#
# The feature list is the one the `rust-clippy` job of `.github/workflows/ci.yml` names,
# narrowed to the packages this run selects. Cargo rejects `--features <pkg>/<feat>` for a
# package outside the selected set, so passing the whole CI list against one crate fails
# before it compiles anything.
CI_FEATURES=(
    scp-core/testing
    scp-runtime/testing
    scp-runtime/saga-witness-test-mint
    scp-ffi/testing
    scp-ffi/outlet-capability-test-grant
    scp-ffi-napi/testing
    scp-ffi-napi/outlet-capability-test-grant
    scp-ffi-uniffi/testing
    scp-ffi-uniffi/outlet-capability-test-grant
)

# Packages a cargo command in `.github/workflows/ci.yml` compiles under a feature the
# workspace command does not activate.
#
# THE CRITERION for this list: no `default` entry of the package's manifest activates the
# feature, and a cargo command in that workflow names it, so the module the feature gates
# compiles in CI and never in the `cargo check` above. The `rust-clippy` job records what
# the gap costs, on the command this list's first entry mirrors: the optional transports
# "rotted undetected for months (the quic feature stopped compiling)".
#
# Each entry runs as its own `cargo check`, the way CI runs each as its own command. One
# invocation carrying every feature would resolve a feature unification no CI command
# resolves, so a failure it reported would answer a question the merge gate never asks.
#
# `server` is absent from this list although three CI commands name it: `default =
# ["server"]` in the manifest of each of scp-ffi, scp-ffi-napi and scp-ffi-uniffi, so the
# `cargo check` above already compiles every module that feature gates.
EXTRA_FEATURE_CHECKS=(
    "scp-transport|quic,http3,udp,coap"
    "scp-transport|combined,local-cache"
    "scp-testing|sqlite"
)

# The packages the `wasm-protocol` job of `.github/workflows/ci.yml` compiles for
# `wasm32-unknown-unknown`, copied from the one `cargo check` that job runs. An edit to
# any of them can use an API that target does not carry — a thread, a file handle, a
# `std::time::SystemTime::now` — which the native `cargo check` above accepts and that job
# rejects. This script starts no wasm compile, for the reason item 6 of the DOES-NOT-RUN
# list gives, so a run that selects one of these names it in a NOT CHECKED line instead.
WASM_TARGET_CRATES=(
    scp-clock
    scp-crypto
    scp-did
    scp-protocol
    scp-relay-client
    scp-mls
    scp-client
    scp-event-log
    scp-client-wasm
)

crate_list="none"
[[ ${#CRATES[@]} -gt 0 ]] && crate_list=$(IFS=' '; printf '%s' "${CRATES[*]}")

if [[ ${#CRATES[@]} -eq 0 ]]; then
    # A branch that changed one of WORKSPACE_WIDE_INPUTS and no file under a crate
    # directory fails here rather than recording a skip. `cargo check -p` takes a package
    # name, this run has none to pass, and every one of the 26 members compiles against
    # each of those four files, so the only command that covers the change is the
    # workspace one this script refuses to start. Exit 1 says that the script reached no
    # verdict; exit 0 with a skip line would say that the change needed no compile.
    if [[ -n $wide_list ]]; then
        printf '\nfix-round-check: this branch changed %s, which every workspace member compiles against, and changed no file inside a workspace crate. `cargo check -p` needs a package name and this run derived none, so this script compiled zero lines of a change that recompiles all 26 members and it reports no compile verdict. Run `cargo check --workspace --all-targets` yourself, and read the rust-clippy job of .github/workflows/ci.yml on the pushed head.\n' "$wide_list" >&2
        RAN+=("compile FAILED 0s")
        FAILED=1
    else
        SKIPPED+=("compile: this branch changed no file inside a workspace crate, and naming none left nothing to check")
    fi
else
    declare -a PKG_ARGS=()
    for c in "${CRATES[@]}"; do PKG_ARGS+=(-p "$c"); done

    declare -a SELECTED_FEATURES=()
    for f in "${CI_FEATURES[@]}"; do
        pkg=${f%%/*}
        for c in "${CRATES[@]}"; do
            if [[ $c == "$pkg" ]]; then
                SELECTED_FEATURES+=("$f")
                break
            fi
        done
    done

    if [[ ${#SELECTED_FEATURES[@]} -gt 0 ]]; then
        feature_arg=$(IFS=,; printf '%s' "${SELECTED_FEATURES[*]}")
        run_step compile cargo check "${PKG_ARGS[@]}" --all-targets --features "$feature_arg"
    else
        run_step compile cargo check "${PKG_ARGS[@]}" --all-targets
    fi

    for entry in "${EXTRA_FEATURE_CHECKS[@]}"; do
        extra_pkg=${entry%%|*}
        extra_features=${entry#*|}
        for c in "${CRATES[@]}"; do
            [[ $c == "$extra_pkg" ]] || continue
            run_step "compile($extra_pkg:$extra_features)" \
                cargo check -p "$extra_pkg" --all-targets --features "$extra_features"
            break
        done
    done

    NOTES+=("the reverse dependencies of $crate_list: cargo check -p compiles the packages it names and none of their dependents, so a changed public signature compiles here and fails to compile its dependents in the rust-clippy job of .github/workflows/ci.yml")

    declare -a SELECTED_WASM=()
    for c in "${CRATES[@]}"; do
        for w in "${WASM_TARGET_CRATES[@]}"; do
            [[ $c == "$w" ]] && SELECTED_WASM+=("$c")
        done
    done
    if [[ ${#SELECTED_WASM[@]} -gt 0 ]]; then
        wasm_list=$(IFS=' '; printf '%s' "${SELECTED_WASM[*]}")
        NOTES+=("$wasm_list against wasm32-unknown-unknown: the compile above ran on this machine's host target alone, and the wasm-protocol job of .github/workflows/ci.yml compiles these packages for wasm32-unknown-unknown, which rejects a host-only API that compile accepted")
    fi
    if [[ -n $wide_list ]]; then
        NOTES+=("$wide_list: every workspace member compiles against these files, and this run compiled $crate_list alone")
    fi
fi

# Step 3 — format.
#
# This is the command the `rust-fmt` job of `.github/workflows/ci.yml` runs, unnarrowed.
# Scoping it to the crates this run selects would save nothing a reader could measure and
# would leave a changed Rust file outside those crates unformatted until CI reported it:
# measured on 2026-09-13, `cargo fmt --all -- --check` over the whole workspace took 2.83
# seconds against 0.59 seconds for one crate. `cargo fmt` runs rustfmt over the sources the
# manifests name and compiles nothing, so the whole-workspace form costs 2.83 seconds
# whether or not this run selects a crate, which is why it sits outside the block above.
run_step format cargo fmt --all -- --check

# Step 4 — the enforcement gates that execute no program cargo built.
#
# THE CRITERION for this list: running the script compiles nothing, links nothing, runs no
# program cargo produced, and takes no lock on the shared target directory, so its whole
# cost is reading repository files and, for one gate, resolving a dependency graph. Every
# gate that compiles or links belongs to CI, which runs it on the pushed head.
#
# WHAT THIS LIST HOLDS, against the repository: `scripts/` holds 31 files named
# `check-*`. This list names 29 of them. `scripts/check-resolved-rustc.sh` is the
# toolchain precondition this script runs before any cargo command, above, rather than one
# gate among these. The 31st is the one the criterion above excludes, named next.
#
# THE ONE GATE THIS LIST LEAVES OUT, and the measurement that decided it.
# `scripts/check-pure-helpers.sh` runs `cargo test -p scp-testing --test ffi_conformance`,
# which links a test binary and takes the build lock. Run on 2026-09-13 while another
# worktree's cargo held that lock, it printed "Blocking waiting for file lock on build
# directory" and compiled nothing for the 300 seconds before a timeout killed it. Its own
# job in `.github/workflows/ci.yml` runs the underlying Rust test on the pushed head.
#
# TWO GATES STAY IN THE LIST ALTHOUGH THEY START CARGO. `scripts/check-shipped-feature-
# graph.sh` runs eleven `cargo tree` resolutions and `scripts/check-protocol-deps.sh` runs
# one, and `cargo tree` compiles nothing and takes no build lock: the same 2026-09-13 run
# measured them at 12.9 seconds and 391 ms while another worktree held that lock.
#
# Measured on 2026-09-13, one run each, in the order below: 47 seconds for the 28 this
# list held that day. `scripts/check-workflow-compile-steps.py` joined it afterwards: the
# `toolchain-wiring` job of `.github/workflows/ci.yml` runs it beside
# `scripts/check-toolchain-wiring.sh`, which this list already held, and it reads every
# workflow file with PyYAML while starting no subprocess. It rejected this script's own CI
# job once, for a `Swatinem/rust-cache` step that named no cache group.
GATES=(
    scripts/check-agent-verdict-criterion.sh
    scripts/check-block-in-place.py
    scripts/check-bridge-instance-lifecycle.py
    scripts/check-bridge-symmetry.sh
    scripts/check-call-invariants.py
    scripts/check-construction-pattern.py
    scripts/check-cross-layer.sh
    scripts/check-deleted-primitives.sh
    scripts/check-doc-citations.py
    scripts/check-error-codes.sh
    scripts/check-handle-affinity.sh
    scripts/check-handler-no-panic.sh
    scripts/check-no-bridge-globals.sh
    scripts/check-no-fallback-registry.sh
    scripts/check-no-kotlin-mutable-globals.sh
    scripts/check-no-mutable-globals.sh
    scripts/check-no-mutable-module-globals.py
    scripts/check-no-panic-abort.sh
    scripts/check-no-shim-reexports.sh
    scripts/check-no-ts-mutable-globals.sh
    scripts/check-protocol-deps.sh
    scripts/check-protocol-sync.py
    scripts/check-pyi-generated.sh
    scripts/check-python-falsy-optionals.py
    scripts/check-saga-gating-granularity.sh
    scripts/check-sdk-coverage.py
    scripts/check-shipped-feature-graph.sh
    scripts/check-toolchain-wiring.sh
    scripts/check-workflow-compile-steps.py
)

PYTHON=python3.12
command -v "$PYTHON" >/dev/null 2>&1 || PYTHON=python3

# `scripts/check-workflow-compile-steps.py` imports PyYAML, which the standard library does
# not carry, so an interpreter without it fails that gate for a missing library rather than
# for a workflow defect. The run still counts the failure, because a gate that did not
# execute proved nothing; this line names the cause so a reader installs the library
# instead of reading a traceback as an enforcement violation.
if ! "$PYTHON" -c 'import yaml' >/dev/null 2>&1; then
    printf 'fix-round-check: %s cannot import yaml, which scripts/check-workflow-compile-steps.py parses every workflow file with, so that gate fails below for the missing library. Install it with: pip install '"'"'pyyaml>=6,<7'"'"'\n' "$PYTHON" >&2
fi

gates_t0=$(date +%s)
gate_failures=0
gate_ran=0
printf '\n── gates: %d enforcement scripts that compile nothing and take no build lock\n' "${#GATES[@]}"
for g in "${GATES[@]}"; do
    if [[ ! -f $g ]]; then
        printf '  MISSING %s — this list names a gate the repository does not hold.\n' "$g" >&2
        gate_failures=$((gate_failures + 1))
        continue
    fi
    case $g in
        *.py) runner=("$PYTHON" "$g") ;;
        *) runner=(bash "$g") ;;
    esac
    # Each gate carries a 300-second bound for the same reason the metadata call above
    # carries a 60-second one: two of these gates start `cargo tree`, neither passes
    # `--offline`, and a cargo command on this machine can sit in a queue for half an hour.
    # A gate that does not finish proved nothing, so the run reports that rather than
    # waiting. The bound is 300 seconds rather than 60 because the slowest gate measured on
    # 2026-09-13 took 12.9 seconds and the whole set took 47.
    out=$("$TIMEOUT" 300 "${runner[@]}" 2>&1)
    gate_rc=$?
    if [[ $gate_rc -eq 0 ]]; then
        gate_ran=$((gate_ran + 1))
    elif [[ $gate_rc -eq 124 ]]; then
        gate_failures=$((gate_failures + 1))
        printf '  TIMED OUT after 300s %s — it did not finish, so this run proved nothing about it.\n' "$g" >&2
    else
        gate_failures=$((gate_failures + 1))
        printf '  FAILED %s\n' "$g" >&2
        printf '%s\n' "$out" >&2
    fi
done
gates_t1=$(date +%s)
if [[ $gate_failures -gt 0 ]]; then
    FAILED=1
    RAN+=("gates ${gate_ran}/${#GATES[@]} passed, $gate_failures FAILED $((gates_t1 - gates_t0))s")
else
    RAN+=("gates ${gate_ran}/${#GATES[@]} passed $((gates_t1 - gates_t0))s")
fi

# ── The summary ──────────────────────────────────────────────────────────────────────
# `crate_list` is set above the compile step, because two of the NOT CHECKED lines name it.
#
# `IFS` joins an array on its FIRST character alone, so "; " would separate on ";" and drop
# the space. The loop writes the two-character separator the summary line reads with.
ran_list=""
for r in "${RAN[@]}"; do
    [[ -n $ran_list ]] && ran_list+="; "
    ran_list+="$r"
done
# The compile step runs `cargo check`, which emits no clippy lint at all, so this line
# names clippy in every form rather than the workspace one: a reader who saw "workspace
# cargo clippy" would take a narrowed clippy to have run over the crates it edited.
#
# This line names the two commands every run skips, and it closes by pointing at the NOT
# CHECKED lines below rather than by listing the rest, because the rest depends on which
# files the branch changed. An earlier revision ended the sentence after the two commands,
# which told a fix agent editing a binding source that nothing else was left to fail.
skip_list="cargo nextest, cargo test and cargo build in every form, and cargo clippy in every form, which the rust-test and rust-clippy jobs of .github/workflows/ci.yml run on the pushed head; the NOT CHECKED lines below name what this branch's own changed files reached, and the DOES-NOT-RUN section of this script states all seven kinds, cargo doc and cargo deny and the docker build among them"
for s in ${SKIPPED[@]+"${SKIPPED[@]}"}; do skip_list+="; $s"; done

printf '\nfix-round-check: crates %s (%s); target dir %s; %s; %s; ran %s; skipped %s.\n' \
    "$crate_list" "$crate_source" "$target_dir" "$toolchain_note" "$target_note" "$ran_list" "$skip_list"

# One line per change of this branch that no step above read, printed after the summary
# because a fix agent reads the end of this output and pushes on it. Each names what went
# unread and the CI job that reads it, so the line is actionable without this file.
if [[ ${#NOTES[@]} -eq 0 ]]; then
    # The summary above points a reader at these lines, so a run that produced none says
    # so rather than leaving the reader looking for output that is absent.
    printf 'fix-round-check: NOT CHECKED — no entry: this run compiled no crate and this branch changed no file any unrun lane reads.\n'
else
    for n in "${NOTES[@]}"; do
        printf 'fix-round-check: NOT CHECKED — %s.\n' "$n"
    done
fi

exit "$FAILED"
