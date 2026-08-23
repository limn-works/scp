#!/usr/bin/env bash
#
# Toolchain-wiring gate.
#
# `rust-toolchain.toml` is the one place this repository names a stable Rust version, and
# `fuzz/rust-toolchain.toml` the one place it names a nightly. Every consumer derives the
# version from one of those two files, so no two consumers can disagree. This gate checks
# the three things a derivation cannot establish on its own.
#
# ── CHECK 1: every container build proves which compiler it resolved ─────────────────
#
# THE CRITERION. A file that Docker builds from a `rust` base image compiles this
# workspace's crates on whatever compiler that image ships, unless the build brings
# `rust-toolchain.toml` in and rustup resolves it. The property that decides whether the
# build is correct is therefore the compiler the image actually resolves — not the text
# of any COPY line.
#
# So the container files assert it themselves. Each one carries the ASSERT_BLOCK below
# verbatim: three lines that read the channel out of the copied-in pin, read
# `rustc --version`, and fail the build when they differ. The gate requires that every
# discovered container file contains that block, and the block then proves the property
# at build time.
#
# Reading COPY lines instead does not converge, and two probes show why: a pin copied
# into a stage that never compiles passes such a check, and a legitimate whole-context
# copy written `COPY . /build` fails it. Docker's grammar admits many spellings of one
# effect, and the stage graph decides which copy reaches which compile. One canonical
# block, compared literally, has neither problem — and unlike a text check it cannot be
# satisfied by a build whose compiler is wrong.
#
# This replaces what the base tag used to say out loud. `FROM rust:1.98.0-slim-bookworm`
# named the compiler, so a stale tag was a string a gate could read; `FROM rust:slim-
# bookworm` names a Debian release and leaves the compiler to the copied-in file.
#
# WHAT THE SEARCH DOES NOT COVER, stated rather than implied: it matches a line-initial,
# uppercase `FROM`, which is how every container file in this repository writes it and how
# Docker's own documentation writes it. Docker also accepts a lowercase `from` and leading
# whitespace, so a container file written that way is not discovered. Under-detection is
# the failure mode; nothing this gate finds is rejected wrongly.
#
# ── CHECK 2: the CI paths filters route a change to the jobs that build from it ──────
#
# THE CRITERION: a change to a file that decides how a CI job compiles must make that job
# run. Each job in `.github/workflows/ci.yml` that compiles a crate of this workspace is
# guarded by `if: needs.changes.outputs.<filter> == 'true'`, and the `ci` job that
# aggregates every other job's result fails only on 'failure' or 'cancelled', so a skipped
# job reports success to branch protection. A file that no filter routes therefore merges
# with every job that reads it skipped and the aggregate green.
#
# The workflow satisfies that criterion in two pieces, and this gate checks each piece
# against the repository rather than against a list of paths someone remembered to add.
#
#   2a/2b — THE PIN, ROUTED BY CONSTRUCTION. `rust-toolchain.toml` selects the compiler
#   for every lane, not only the Rust lane: `python-test` runs `maturin develop`,
#   `typescript-check` runs `cargo build -p scp-ffi-napi`, `typescript-wasm-check` and
#   `scaffold-typescript-web-check` run `wasm-pack build`, `kotlin-test` runs
#   `cargo build -p scp-ffi-uniffi`, and `swift-build-test` runs `build-xcframework.sh`.
#   Listing the pin in each of those filters is a list that grows with the lanes. Instead
#   the workflow declares one `toolchain` filter holding the pin, and every output of the
#   `changes` job ORs that filter in. The gate reads the set of outputs out of the workflow,
#   so a lane added later without the OR fails here, and no list in this file has to learn
#   about it.
#
#   2c — ROOT-LEVEL FILES, CLASSIFIED EXHAUSTIVELY. A root-level file is the class whose
#   omission from a filter no ordinary pull request reveals: dropping `crates/**` from the
#   `rust` filter skips the Rust lane on nearly every pull request and someone notices
#   within a day, while dropping `.clippy.toml` skips it only on the rare pull request that
#   edits a lint threshold and changes nothing else. So the gate enumerates every
#   root-level file in the git tree and requires each one to be either routed — listed in
#   the `rust` filter or in the `toolchain` filter — or named in NO_RUST_JOB_READS below.
#   A file added at the root later is unclassified, and the gate fails until someone
#   decides which it is. That is the property a list of required entries did not have: an
#   entry nobody added was an entry nobody heard about.
#
#   2d — THE FUZZ PIN. `fuzz-build` runs `cargo check` with `working-directory: fuzz`,
#   where rustup resolves `fuzz/rust-toolchain.toml`, so the `fuzz` filter's `fuzz/**`
#   entry is what routes a change to that nightly.
#
# An `OK` from check 2 is not a claim that the filters are correct. It says the pin reaches
# every lane and that every root-level file is classified. A `rust` filter stripped of
# `crates/**` still passes, and it does not need this gate: that omission reveals itself.
#
# ── CHECK 3: mise names no Rust version source ───────────────────────────────────────
#
# THE CRITERION. mise exports one `RUSTUP_TOOLCHAIN` for every command it runs, computed
# from the directory the shell sat in, and `RUSTUP_TOOLCHAIN` overrides a
# `rust-toolchain.toml` entirely. This repository resolves two compilers by directory —
# stable for the workspace, the nightly `fuzz/rust-toolchain.toml` names for `fuzz/` — so
# one exported value cannot serve both, and any mise Rust version source puts every command
# in `fuzz/` on the root pin.
#
# A mise configuration file gives its rust tool a version through exactly two mechanisms,
# both defined by mise's own configuration grammar: a `rust` key in a `[tools]` table, and
# a `rust-toolchain.toml` registered as an idiomatic version file through
# `idiomatic_version_file_enable_tools`. The gate rejects both. rustup installs Rust
# instead, reading the toolchain file of whichever directory a command runs in.
#
# The gate FAILS CLOSED: a missing workflow, a missing filter, a filter with no path
# entries, a `changes` job with no outputs, an empty root-file listing, and an
# undiscoverable git tree are each failures, never skipped checks. See
# `.docs/lessons/coverage-gates-must-fail-closed.md`.
#
# Usage: bash scripts/check-toolchain-wiring.sh
set -euo pipefail

cd "$(dirname "$0")/.."

CI_WORKFLOW=".github/workflows/ci.yml"
MISE_CONFIG=".mise.toml"
PIN="rust-toolchain.toml"
TOOLCHAIN_FILTER="toolchain"

fail=0
report() {
    printf 'FAIL: %s\n' "$1" >&2
    fail=1
}

# ── Check 1 ──────────────────────────────────────────────────────────────────────────
#
# The canonical assertion, held here once. A container file must contain it verbatim.
# Changing it means changing this string and every container file in the same commit,
# which is what makes the change deliberate.
read -r -d '' ASSERT_BLOCK <<'BLOCK' || true
RUN pin="$(sed -nE 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' rust-toolchain.toml | head -n 1)"; \
    got="$(rustc --version | cut -d' ' -f2)"; \
    [ -n "$pin" ] && [ "$got" = "$pin" ] || { echo "image resolved rustc '$got'; rust-toolchain.toml names '$pin'" >&2; exit 1; }
BLOCK
# The heredoc ends the block with a newline; a container file may end there too, and
# `$(cat …)` drops trailing newlines, so drop it here as well and compare what remains.
ASSERT_BLOCK=${ASSERT_BLOCK%$'\n'}

# `--untracked` matters: a container build added but not yet committed is exactly the case
# a pre-push run has to catch, and plain `git grep` searches only the index. This file is
# excluded because it necessarily contains the block it looks for.
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    report "not inside a git working tree, so the gate cannot search for container builds"
else
    while IFS= read -r f; do
        [[ -n $f ]] || continue
        # A container build of this workspace is one whose base image is a `rust` image.
        # Match the image name after `FROM`, with or without a registry prefix or a tag,
        # and ignore a stage name (`FROM chef AS builder` names no image to pin).
        grep -qiE '^FROM[[:space:]]+([a-z0-9.:-]+/)*rust(:[^[:space:]]*)?([[:space:]]|$)' "$f" || continue
        # A byte-for-byte substring test over the whole file, so the block's three lines
        # match in order and unbroken. `grep -F` cannot do this: it splits a pattern
        # holding newlines into one pattern per line and matches when ANY of them matches,
        # so a file keeping a single line of the block — or all three lines reversed —
        # satisfies it. Measured on GNU grep 3.12, BSD grep 2.6.0-FreeBSD, and ugrep 7.8.4,
        # with and without `-z`.
        file_text=$(cat "$f")
        if [[ $file_text != *"$ASSERT_BLOCK"* ]]; then
            report "$f builds from a 'rust' base image and does not carry the ASSERT-PINNED-RUSTC block verbatim, so its build never checks which compiler the image resolved. Copy the block from $PIN's own consumer, the root Dockerfile, or from the ASSERT_BLOCK definition in this gate."
        fi
        # This gate and its cases are excluded because both necessarily contain the lines
        # they look for: the gate holds ASSERT_BLOCK, and the cases hold canned Dockerfiles
        # that they write into temporary directories at run time.
    done < <(git grep -l --untracked -E '^FROM[[:space:]]' \
        -- . ':!scripts/check-toolchain-wiring.sh' ':!scripts/tests/toolchain-wiring/*')
fi

# ── Check 2 ──────────────────────────────────────────────────────────────────────────
#
# Root-level files that no job in `ci.yml` reads while it compiles anything. Every other
# root-level file must appear in the `rust` filter or in the `toolchain` filter. Adding a
# file here is a claim that changing it cannot change what any compile produces, and the
# gate takes that claim at face value — it is the one judgement this check cannot make.
NO_RUST_JOB_READS=(
    # Documentation and licensing. No job compiles from them.
    "CHANGELOG.md"
    "CLAUDE.md"
    "CONTRIBUTING.md"
    "GETTING-STARTED.md"
    "LICENSE"
    "LICENSE-AGPL"
    "LICENSE-APACHE"
    "LICENSING.md"
    "README.md"
    "TESTING.md"
    # Local developer tooling. No CI job installs mise or runs docker compose; the
    # `docker-image` job builds `Dockerfile` directly.
    ".gitignore"
    ".mise.toml"
    "docker-compose.yml"
)

# Print the path entries of one filter, one per line.
#
# The filter block is a YAML literal scalar inside ci.yml, so read it as text: start at a
# line holding nothing but `<name>:`, take the `- <path>` lines that follow, skip comment
# and blank lines, and stop at the first line that is none of those. Each filter name
# appears exactly once in that form, because the `outputs:` block writes
# `rust: ${{ ... }}` with a value on the same line.
#
# The `sed` accepts the three ways YAML spells a scalar in a sequence — plain,
# single-quoted, double-quoted — and nothing else. An entry written in a fourth way, such
# as a flow sequence on the `<name>:` line, yields no path, and the caller then reports
# the filter as carrying none, which fails the gate rather than passing it.
filter_entries() {
    local wf=$1 name=$2
    awk -v key="$name" '
        $0 ~ "^[[:space:]]*" key ":[[:space:]]*$" { inblock = 1; next }
        inblock == 1 {
            if ($0 ~ /^[[:space:]]*#/) next
            if ($0 ~ /^[[:space:]]*$/) next
            if ($0 ~ /^[[:space:]]*-[[:space:]]/) { print; next }
            exit
        }
    ' "$wf" | sed -nE "s/^[[:space:]]*-[[:space:]]*[\"']?([^\"']*)[\"']?[[:space:]]*$/\1/p"
}

# Print `<output name>=<expression>` for every output the `changes` job declares.
#
# Scoped to that job: start at its header, stop at the next job header, and read the lines
# of its `outputs:` mapping. Reading the names out of the workflow is what makes check 2b
# closed by construction — a lane added later declares an output here, and the gate then
# requires that output to route the pin without anyone editing this file.
changes_job_outputs() {
    local wf=$1
    awk '
        /^  changes:[[:space:]]*$/ { injob = 1; next }
        injob && /^  [A-Za-z0-9_.-]+:[[:space:]]*$/ { exit }
        injob && /^    outputs:[[:space:]]*$/ { inoutputs = 1; next }
        inoutputs {
            if ($0 ~ /^[[:space:]]*#/) next
            if ($0 ~ /^[[:space:]]*$/) next
            if ($0 ~ /^      [A-Za-z0-9_.-]+:[[:space:]]*\$\{\{/) { print; next }
            exit
        }
    ' "$wf" | sed -E 's/^[[:space:]]*([A-Za-z0-9_.-]+):[[:space:]]*(.*)$/\1=\2/'
}

if [[ ! -f $CI_WORKFLOW ]]; then
    report "$CI_WORKFLOW does not exist, so the gate cannot check that the paths filters route a change to the jobs that build from it"
else
    # 2a — one filter holds the pin.
    toolchain_entries=$(filter_entries "$CI_WORKFLOW" "$TOOLCHAIN_FILTER")
    if [[ -z $toolchain_entries ]]; then
        report "$CI_WORKFLOW declares no '$TOOLCHAIN_FILTER:' paths filter with path entries, so nothing routes a change to $PIN"
    elif ! grep -qxF -- "$PIN" <<< "$toolchain_entries"; then
        report "$CI_WORKFLOW: the '$TOOLCHAIN_FILTER' paths filter does not list $PIN, so a pull request that raises the pin and changes nothing else leaves every filter output 'false', every job those filters guard skips, and the 'ci' aggregator job counts a skipped job as a pass"
    fi

    # 2b — every lane's output ORs that filter in.
    outputs=$(changes_job_outputs "$CI_WORKFLOW")
    if [[ -z $outputs ]]; then
        report "$CI_WORKFLOW: the 'changes' job declares no outputs, so the gate cannot check that a pin change reaches every lane"
    else
        while IFS= read -r line; do
            [[ -n $line ]] || continue
            output_name=${line%%=*}
            output_expr=${line#*=}
            # `fuzz` is the one lane the pin does not decide: `fuzz-build` runs
            # `cargo check` with `working-directory: fuzz`, where rustup resolves
            # `fuzz/rust-toolchain.toml` instead. Check 2d covers that file.
            if [[ $output_name == "fuzz" || $output_name == "$TOOLCHAIN_FILTER" ]]; then
                continue
            fi
            if [[ $output_expr != *"steps.filter.outputs.$TOOLCHAIN_FILTER"* ]]; then
                report "$CI_WORKFLOW: the 'changes' job's '$output_name' output does not read steps.filter.outputs.$TOOLCHAIN_FILTER, so a pull request that raises the pin skips every job that output guards, and the 'ci' aggregator job counts each skip as a pass"
            fi
        done <<< "$outputs"
    fi

    # 2c — every root-level file is routed or declared unread.
    rust_entries=$(filter_entries "$CI_WORKFLOW" "rust")
    if [[ -z $rust_entries ]]; then
        report "$CI_WORKFLOW declares no 'rust:' paths filter with path entries, so the gate cannot check which root-level files it routes"
    else
        root_files=$(git ls-files --cached --others --exclude-standard 2>/dev/null | grep -v '/' || true)
        if [[ -z $root_files ]]; then
            report "git listed no root-level files, so the gate cannot check that each one is routed to a lane or declared unread"
        else
            while IFS= read -r root_file; do
                [[ -n $root_file ]] || continue
                if grep -qxF -- "$root_file" <<< "$rust_entries"; then continue; fi
                if grep -qxF -- "$root_file" <<< "$toolchain_entries"; then continue; fi
                declared=0
                for unread in "${NO_RUST_JOB_READS[@]}"; do
                    if [[ $root_file == "$unread" ]]; then
                        declared=1
                        break
                    fi
                done
                if [[ $declared -eq 1 ]]; then continue; fi
                report "$root_file sits at the repository root and neither the 'rust' filter nor the '$TOOLCHAIN_FILTER' filter in $CI_WORKFLOW lists it, and NO_RUST_JOB_READS in this gate does not declare it unread. A pull request that changes only that file leaves the filter output 'false', every job the filter guards skips, and the 'ci' aggregator job counts a skipped job as a pass. List it in the filter that guards the jobs it decides, or declare it in NO_RUST_JOB_READS."
            done <<< "$root_files"
        fi
    fi

    # 2d — the fuzz nightly reaches the job that compiles on it.
    fuzz_entries=$(filter_entries "$CI_WORKFLOW" "fuzz")
    if [[ -z $fuzz_entries ]]; then
        report "$CI_WORKFLOW declares no 'fuzz:' paths filter with path entries, so nothing routes a change to fuzz/$PIN"
    elif ! grep -qxF -- 'fuzz/**' <<< "$fuzz_entries"; then
        report "$CI_WORKFLOW: the 'fuzz' paths filter does not list fuzz/**, so a pull request that raises the nightly in fuzz/$PIN skips 'fuzz-build', the one job that compiles on it, and the 'ci' aggregator job counts the skip as a pass"
    fi
fi

# ── Check 3 ──────────────────────────────────────────────────────────────────────────

if [[ ! -f $MISE_CONFIG ]]; then
    report "$MISE_CONFIG does not exist, so the gate cannot check that mise names no Rust version source"
else
    if grep -qE '^[[:space:]]*"?rust"?[[:space:]]*=' "$MISE_CONFIG"; then
        report "$MISE_CONFIG names a rust tool version. mise then exports RUSTUP_TOOLCHAIN with that version for every command it runs, which overrides fuzz/$PIN and puts 'cd fuzz && cargo fuzz run <target>' on the workspace's stable compiler, where cargo-fuzz's -Z flags are rejected. Delete the entry and let rustup read the toolchain file of each directory."
    fi
    if grep -E '^[[:space:]]*idiomatic_version_file_enable_tools[[:space:]]*=' "$MISE_CONFIG" | grep -q 'rust'; then
        report "$MISE_CONFIG registers rust-toolchain.toml as a mise version source through idiomatic_version_file_enable_tools. mise then exports RUSTUP_TOOLCHAIN with the channel it read, which overrides fuzz/$PIN and puts 'cd fuzz && cargo fuzz run <target>' on the workspace's stable compiler, where cargo-fuzz's -Z flags are rejected. Delete 'rust' from that setting and let rustup read the toolchain file of each directory."
    fi
fi

if [[ $fail -eq 0 ]]; then
    printf 'OK: every container build asserts it resolved the compiler %s names\n' "$PIN"
    printf 'OK: every lane in the ci.yml changes job routes a %s change, and every root-level file is routed or declared unread\n' "$PIN"
    printf 'OK: %s names no Rust version source, so rustup resolves each directory from its own toolchain file\n' "$MISE_CONFIG"
    exit 0
fi
exit 1
