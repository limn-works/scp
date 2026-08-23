#!/usr/bin/env bash
#
# Toolchain-wiring gate.
#
# `rust-toolchain.toml` is the one place this repository names a stable Rust version, and
# `fuzz/rust-toolchain.toml` the one place it names a nightly. Every consumer derives the
# version from one of those two files, so no two consumers can disagree. This gate checks
# the two things a derivation cannot establish on its own.
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
# THE CRITERION for what belongs in REQUIRED_FILTER_ENTRIES: a path whose omission from
# its filter no ordinary pull request reveals. Each job in `.github/workflows/ci.yml` that
# compiles a crate of this workspace is guarded by
# `if: needs.changes.outputs.<filter> == 'true'`, and the `ci` job that aggregates every
# other job's result fails only on 'failure' or 'cancelled', so a skipped job reports
# success to branch protection. Dropping `crates/**` from the `rust` filter skips the Rust
# lane on nearly every pull request, and someone notices within a day. Dropping
# `rust-toolchain.toml` skips a lane only on the rare pull request that raises the pin —
# the one that most needs the lane to run — and nobody notices. The gate covers the second
# class.
#
# Seven filters guard a job that compiles this workspace's crates, not one. `rust` guards
# clippy, the test lane, the build, cargo-deny, and the image build. `python` guards
# `maturin develop`, `typescript` guards `cargo build -p scp-ffi-napi`, `typescript-wasm`
# and `scaffold-typescript-web` guard `wasm-pack build`, `kotlin` guards
# `cargo build -p scp-ffi-uniffi`, and `swift` guards `build-xcframework.sh`. Every one of
# those seven compiles on the pinned compiler, so every one has to list the pin. The eighth
# filter, `fuzz`, guards a job that runs `cargo check` from `fuzz/`, where rustup resolves
# `fuzz/rust-toolchain.toml` instead, and `fuzz/**` already covers that file.
#
# It therefore does NOT establish that the filters are correct, and an `OK` is not that
# claim: a `rust` filter stripped of `crates/**` passes this gate. Do not grow the list
# past its criterion; a self-revealing omission needs no gate.
#
# The gate FAILS CLOSED: a missing workflow, a missing filter, a filter with no path
# entries, and an undiscoverable git tree are each failures, never skipped checks. See
# `.docs/lessons/coverage-gates-must-fail-closed.md`.
#
# Usage: bash scripts/check-toolchain-wiring.sh
set -euo pipefail

cd "$(dirname "$0")/.."

CI_WORKFLOW=".github/workflows/ci.yml"
PIN="rust-toolchain.toml"

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
        # `grep -F -f -` compares the block literally, line for line and in order.
        if ! grep -qzF -- "$ASSERT_BLOCK" "$f"; then
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
# "<filter name> <path entry>", one pair per line. Add a pair only when its omission would
# be invisible on an ordinary pull request; see THE CRITERION above.
REQUIRED_FILTER_ENTRIES=(
    # A pull request that raises the pin and changes nothing else.
    "rust rust-toolchain.toml"
    # A pull request that edits only the image recipe or its build context.
    "rust Dockerfile"
    "rust .dockerignore"
    # A pull request that edits only a clippy or rustfmt threshold. `rust-clippy` reads
    # the first and `rust-fmt` the second, and this filter guards both jobs.
    "rust .clippy.toml"
    "rust rustfmt.toml"
    # The same pull request that raises the pin, reaching the six other lanes that
    # compile this workspace's crates. `python-test` runs `maturin develop --release`,
    # `typescript-check` runs `cargo build -p scp-ffi-napi --release`,
    # `typescript-wasm-check` and `scaffold-typescript-web-check` run `wasm-pack build`
    # from the repository root, `kotlin-test` runs `cargo build -p scp-ffi-uniffi`, and
    # `swift-build-test` runs `bindings/swift/build-xcframework.sh --dev`. rustup applies
    # the pin to each of those commands, so a pin the filter does not route reaches a
    # compile that nothing checked.
    "python rust-toolchain.toml"
    "typescript rust-toolchain.toml"
    "typescript-wasm rust-toolchain.toml"
    "scaffold-typescript-web rust-toolchain.toml"
    "kotlin rust-toolchain.toml"
    "swift rust-toolchain.toml"
    # A pull request that raises the fuzz nightly, which lives under `fuzz/`.
    "fuzz fuzz/**"
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

for pair in "${REQUIRED_FILTER_ENTRIES[@]}"; do
    filter_name=${pair%% *}
    required_entry=${pair#* }
    if [[ ! -f $CI_WORKFLOW ]]; then
        report "$CI_WORKFLOW does not exist, so the gate cannot confirm that the '$filter_name' filter lists $required_entry"
        continue
    fi
    entries=$(filter_entries "$CI_WORKFLOW" "$filter_name")
    if [[ -z $entries ]]; then
        report "$CI_WORKFLOW declares no '$filter_name:' paths filter with path entries, so the gate cannot confirm that it lists $required_entry"
    elif ! grep -qxF -- "$required_entry" <<< "$entries"; then
        report "$CI_WORKFLOW: the '$filter_name' paths filter does not list $required_entry. A pull request that changes only that file leaves the filter output 'false', every job the filter guards skips, and the 'ci' aggregator job counts a skipped job as a pass."
    fi
done

if [[ $fail -eq 0 ]]; then
    printf 'OK: every container build asserts it resolved the compiler %s names\n' "$PIN"
    printf 'OK: the ci.yml paths filters route every listed file to the jobs that build from it\n'
    exit 0
fi
exit 1
