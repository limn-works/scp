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
#   compile    `cargo check -p <crate> --all-targets` over the crates the caller names,
#              with the subset of the CI feature list those crates own. This is the step
#              that takes minutes, and the one whose cost the summary line reports.
#   format     `cargo fmt --all -- --check`, the command the `rust-fmt` job of
#              `.github/workflows/ci.yml` runs. Measured at 2.83 seconds over the whole
#              workspace on 2026-09-13, and at more than three and a half minutes the same
#              day while another worktree's `cargo check` held the build lock, because
#              `cargo fmt` resolves the workspace through a full `cargo metadata` first.
#   gates      The 28 enforcement scripts that compile nothing and link nothing. Measured
#              together at 47 seconds on 2026-09-13, one run each.
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
# WHAT THIS SCRIPT DOES NOT RUN, and why. `cargo nextest run --workspace` links one binary
# per test target, and every freshly written executable on macOS pays a Gatekeeper
# assessment on its first exec: measured on 2026-09-13, 203 ms from queue to scan finished
# for a 16 KB binary, and 0 further assessments on later execs of the same bytes. That cost
# per binary is small, but the link step is not, and a workspace nextest links dozens. On
# 2026-09-11 that queue reached 31 minutes per item and a fix round died inside it.
# Workspace clippy is the merge gate named above. The `rust-test` and `rust-clippy` jobs of
# `.github/workflows/ci.yml` run both on the pushed head, so a fix round that pushes a
# green result from this script and reads CI has run both exactly once.
#
# USAGE
#   bash scripts/fix-round-check.sh [crate ...]
#
# Naming no crate makes the script derive the crate set from the files this branch
# changed, and print which crates it derived. Naming a crate that the workspace does not
# hold fails the run rather than checking a smaller set than the caller asked for.
#
# EXIT. 0 when every step this script ran exited 0. 1 when any step exited non-zero, when
# a named crate is absent from the workspace, and when a gate script this list names does
# not exist.
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
if metadata=$(timeout 60 cargo metadata --no-deps --format-version 1 --offline 2>/dev/null); then
    target_dir=$(printf '%s' "$metadata" | sed -nE 's/.*"target_directory":"([^"]*)".*/\1/p')
    [[ -n $target_dir ]] || target_dir="(cargo metadata named no target directory)"
else
    target_dir="(cargo metadata did not answer within 60s, so this line names no target directory)"
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
changed_files() {
    git -C "$REPO_ROOT" status --porcelain 2>/dev/null | sed -E 's/^.{3}//; s/^.* -> //'
    local base
    if base=$(git -C "$REPO_ROOT" merge-base HEAD origin/main 2>/dev/null); then
        git -C "$REPO_ROOT" diff --name-only "$base" HEAD 2>/dev/null
    fi
}

CHANGED=$(changed_files | sort -u)

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
else
    crate_source="derived from the files this branch changed"
    while IFS= read -r f; do
        [[ -n $f ]] || continue
        owner=$(crate_of_path "$f")
        [[ -n $owner ]] || continue
        seen=0
        for c in ${CRATES[@]+"${CRATES[@]}"}; do
            [[ $c == "$owner" ]] && seen=1
        done
        [[ $seen -eq 0 ]] && CRATES+=("$owner")
    done <<< "$CHANGED"
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

if [[ ${#CRATES[@]} -eq 0 ]]; then
    SKIPPED+=("compile: this branch changed no file inside a workspace crate, and naming none left nothing to check")
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
# THE ONE GATE THIS LIST LEAVES OUT, and the measurement that decided it.
# `scripts/check-pure-helpers.sh` runs `cargo test -p scp-testing --test ffi_conformance`,
# which links a test binary and takes the build lock. Run on 2026-09-13 while another
# worktree's cargo held that lock, it printed "Blocking waiting for file lock on build
# directory" and compiled nothing for the 300 seconds before a timeout killed it. Its own
# job in `.github/workflows/ci.yml` runs the underlying Rust test on the pushed head.
#
# `scripts/check-shipped-feature-graph.sh` stays in the list although it starts eleven
# `cargo tree` resolutions, because `cargo tree` compiles nothing and takes no build lock:
# the same 2026-09-13 run measured it at 12.9 seconds while the build lock was held.
#
# Measured on 2026-09-13, one run each, in the order below: 47 seconds for all 28.
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
)

PYTHON=python3.12
command -v "$PYTHON" >/dev/null 2>&1 || PYTHON=python3

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
    if out=$("${runner[@]}" 2>&1); then
        gate_ran=$((gate_ran + 1))
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
crate_list="none"
[[ ${#CRATES[@]} -gt 0 ]] && crate_list=$(IFS=' '; printf '%s' "${CRATES[*]}")
ran_list=$(IFS='; '; printf '%s' "${RAN[*]}")
skip_list="cargo nextest and workspace cargo clippy, which the rust-test and rust-clippy jobs of .github/workflows/ci.yml run on the pushed head"
for s in ${SKIPPED[@]+"${SKIPPED[@]}"}; do skip_list+="; $s"; done

printf '\nfix-round-check: crates %s (%s); target dir %s; %s; %s; ran %s; skipped %s.\n' \
    "$crate_list" "$crate_source" "$target_dir" "$toolchain_note" "$target_note" "$ran_list" "$skip_list"

exit "$FAILED"
