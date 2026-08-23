#!/usr/bin/env bash
# run-tests.sh — exercise both checks in `scripts/check-toolchain-wiring.sh` against
# canned repositories.
#
# WHAT THIS TESTS.
#   * Check 1 fails when a file that builds from a `rust` base image does not carry the
#     ASSERT-PINNED-RUSTC block verbatim, and stays silent when it does. That block is
#     what makes the build compare the compiler it resolved against the pin, so a
#     container that compiles on the base image's own compiler fails its own build.
#   * Check 2 fails when a `dorny/paths-filter` filter in `ci.yml` omits a declared
#     entry, and stays silent when every declared entry is present. Each job that compiles
#     a crate of this workspace is guarded by such a filter — seven filters guard one, not
#     only `rust` — and the `ci` job that aggregates every other job's result counts a
#     skipped job as a pass, so an omitted entry lets a change merge unbuilt. One case per
#     declared pair asserts the gate names that filter and that entry.
#
# HOW EACH CASE IS BUILT. `run_case` makes a temporary directory, copies the gate into
# `scripts/`, runs `git init` so the gate's `git grep` search has a work tree, writes the
# case's `ci.yml` from the `emit_ci` generator below, and writes its optional `Dockerfile`
# from a heredoc. The gate `cd`s to its own parent's parent, so that directory becomes its
# repository root.
#
# Exit 0 when every case matches its expectation, 1 otherwise.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
CHECK="$REPO_ROOT/scripts/check-toolchain-wiring.sh"

if [[ ! -f "$CHECK" ]]; then
    echo "ERROR: $CHECK does not exist" >&2
    exit 1
fi

TMP_PARENT=$(mktemp -d)
trap 'rm -rf "$TMP_PARENT"' EXIT

passed=0
failed=0

# ── The canned ci.yml ────────────────────────────────────────────────────────────────
#
# One generator produces every `ci.yml` the check-2 cases use, so a case differs from the
# passing one by exactly the omission it names. `OMIT` selects that omission: empty omits
# nothing, "<filter> <entry>" drops one path entry from one filter, and "<filter> *" drops
# the filter and its header. `run_case` calls its producer with no arguments, so the
# selection travels in this variable, and every case below sets it.
#
# Each entry list carries every pair `REQUIRED_FILTER_ENTRIES` declares for that filter,
# plus at least one entry the gate does not require, so dropping a required entry leaves
# the filter holding entries and the gate reports the omission rather than the empty
# filter. A pair added to the gate and not to the loop below still fails against the real
# `ci.yml` in CI; adding it below is what proves the gate reports that pair by name.
OMIT=""

# emit_filter <name> <entry>...
#
# Writes one filter block. Each block opens with a comment line and a blank line, and the
# entries alternate the two quote styles YAML accepts, so every case reads the gate's
# extractor against all three shapes its `sed` parses.
emit_filter() {
    local name=$1
    shift
    [[ "$name *" == "$OMIT" ]] && return 0
    printf '            %s:\n' "$name"
    printf '              # A comment inside a filter block, which the extractor skips.\n'
    printf '\n'
    local entry quote index=0
    for entry in "$@"; do
        [[ "$name $entry" == "$OMIT" ]] && continue
        if (( index % 2 == 0 )); then quote="'"; else quote='"'; fi
        printf '              - %s%s%s\n' "$quote" "$entry" "$quote"
        index=$((index + 1))
    done
}

emit_ci() {
    cat <<'YAML'
name: CI
jobs:
  changes:
    runs-on: ubuntu-latest
    # The real workflow names every filter here too, with a value on the same line. The
    # extractor must start no block on these lines, so every case carries them.
    outputs:
      rust: ${{ steps.filter.outputs.rust }}
      python: ${{ steps.filter.outputs.python }}
      typescript: ${{ steps.filter.outputs.typescript }}
      typescript-wasm: ${{ steps.filter.outputs.typescript-wasm }}
      scaffold-typescript-web: ${{ steps.filter.outputs.scaffold-typescript-web }}
      kotlin: ${{ steps.filter.outputs.kotlin }}
      swift: ${{ steps.filter.outputs.swift }}
      fuzz: ${{ steps.filter.outputs.fuzz }}
    steps:
      - uses: dorny/paths-filter@v3
        id: filter
        with:
          filters: |
YAML
    emit_filter rust 'crates/**' 'rust-toolchain.toml' 'Dockerfile' '.dockerignore' \
        '.clippy.toml' 'rustfmt.toml'
    emit_filter python 'bindings/python/**' 'rust-toolchain.toml'
    emit_filter typescript 'bindings/typescript/**' 'rust-toolchain.toml'
    emit_filter typescript-wasm 'bindings/typescript-wasm/**' 'rust-toolchain.toml'
    emit_filter scaffold-typescript-web 'scaffolds/typescript-web/**' 'rust-toolchain.toml'
    emit_filter kotlin 'bindings/kotlin/**' 'rust-toolchain.toml'
    emit_filter swift 'bindings/swift/**' 'rust-toolchain.toml'
    emit_filter fuzz 'crates/scp-protocol/**' 'fuzz/**'
}

# A ci.yml whose filters carry every declared entry. Cases that are not about check 2 use
# it so their only finding can come from check 1.
routing_ok() {
    # A prefix assignment on a function call persists in the caller in some bash
    # versions and not others, so assign on its own line and leave no doubt about
    # which cases run against the complete filter set.
    OMIT=""
    emit_ci
}

# run_case <name> <expected exit> <required substring|""> <ci.yml producer> [dockerfile producer]
#
# A required substring of "" asserts only that the gate printed no FAIL line, which covers
# every message it can produce.
run_case() {
    local name=$1 want_exit=$2 want_msg=$3 ci_producer=$4 docker_producer=${5:-}
    local root output actual_exit ok=1

    root="$TMP_PARENT/$name"
    mkdir -p "$root/scripts" "$root/.github/workflows"
    cp "$CHECK" "$root/scripts/"
    git -C "$root" init -q
    "$ci_producer" > "$root/.github/workflows/ci.yml"
    [[ -n $docker_producer ]] && "$docker_producer" > "$root/Dockerfile"

    output=$(bash "$root/scripts/$(basename "$CHECK")" 2>&1)
    actual_exit=$?

    if [[ -n "$want_msg" ]] && ! grep -Fq -- "$want_msg" <<< "$output"; then
        echo "FAIL [$name]: output missing required substring: $want_msg" >&2
        ok=0
    fi
    if [[ -z "$want_msg" ]] && grep -Fq -- "FAIL" <<< "$output"; then
        echo "FAIL [$name]: output contains a FAIL line, and the case expects none" >&2
        ok=0
    fi
    if [[ $actual_exit -ne $want_exit ]]; then
        echo "FAIL [$name]: gate exited $actual_exit, expected $want_exit" >&2
        ok=0
    fi

    if [[ $ok -eq 1 ]]; then
        echo "PASS [$name]: exit=$actual_exit"
        passed=$((passed + 1))
    else
        echo "---- output begin ----" >&2
        echo "$output" >&2
        echo "---- output end ----" >&2
        failed=$((failed + 1))
    fi
}

# ── Check 2: paths-filter routing ────────────────────────────────────────────────────

run_case "filters-list-every-entry" 0 "" routing_ok

# One case per pair the gate declares, so dropping a pair from the gate fails a case here
# rather than passing silently. `emit_ci` leaves out exactly the named entry, and the case
# asserts the gate names that filter and that entry in its message.
for pair in \
    "rust rust-toolchain.toml" \
    "rust Dockerfile" \
    "rust .dockerignore" \
    "rust .clippy.toml" \
    "rust rustfmt.toml" \
    "python rust-toolchain.toml" \
    "typescript rust-toolchain.toml" \
    "typescript-wasm rust-toolchain.toml" \
    "scaffold-typescript-web rust-toolchain.toml" \
    "kotlin rust-toolchain.toml" \
    "swift rust-toolchain.toml" \
    "fuzz fuzz/**"; do
    filter_name=${pair%% *}
    omitted_entry=${pair#* }
    OMIT="$pair"
    run_case "${filter_name}-filter-omits-${omitted_entry//\//-}" 1 \
        "the '$filter_name' paths filter does not list $omitted_entry" emit_ci
done

# A filter the workflow declares nowhere, which the gate reports as a filter carrying no
# path entries rather than passing over.
OMIT="rust *"
run_case "rust-filter-absent-entirely" 1 \
    "declares no 'rust:' paths filter with path entries" emit_ci

OMIT=""

# ── Check 1: every container build asserts the compiler it resolved ──────────────────
#
# The block below is written out literally rather than read from the gate, so that
# changing the gate's ASSERT_BLOCK without changing these cases fails here.

docker_carries_the_block() {
    cat <<'DOCKER'
FROM rust:slim-bookworm AS chef
WORKDIR /app
COPY rust-toolchain.toml rust-toolchain.toml
RUN pin="$(sed -nE 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' rust-toolchain.toml | head -n 1)"; \
    got="$(rustc --version | cut -d' ' -f2)"; \
    [ -n "$pin" ] && [ "$got" = "$pin" ] || { echo "image resolved rustc '$got'; rust-toolchain.toml names '$pin'" >&2; exit 1; }
RUN cargo install cargo-chef

FROM chef AS builder
COPY . .
RUN cargo build --release
DOCKER
}
run_case "container-carries-the-assertion" 0 "" routing_ok docker_carries_the_block

# A whole-context copy to a destination other than `.`. A check that read COPY lines
# rejected this legitimate recipe; requiring the assertion block accepts it, because the
# block is what proves the compiler.
docker_copies_context_elsewhere() {
    cat <<'DOCKER'
FROM rust:bookworm AS builder
WORKDIR /build
COPY . /build
RUN pin="$(sed -nE 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' rust-toolchain.toml | head -n 1)"; \
    got="$(rustc --version | cut -d' ' -f2)"; \
    [ -n "$pin" ] && [ "$got" = "$pin" ] || { echo "image resolved rustc '$got'; rust-toolchain.toml names '$pin'" >&2; exit 1; }
RUN cargo build --release
DOCKER
}
run_case "container-copies-context-to-another-path" 0 "" routing_ok docker_copies_context_elsewhere

docker_omits_the_block() {
    cat <<'DOCKER'
FROM rust:slim-bookworm AS builder
WORKDIR /app
COPY rust-toolchain.toml rust-toolchain.toml
RUN cargo build --release
DOCKER
}
run_case "container-omits-the-assertion" 1 \
    "does not carry the ASSERT-PINNED-RUSTC block verbatim" routing_ok docker_omits_the_block

# The pin reaches a stage that never compiles. A check that read COPY lines passed this;
# requiring the assertion in the file catches it, and the assertion itself would fail the
# build in the stage that does compile.
docker_pin_reaches_only_the_runtime_stage() {
    cat <<'DOCKER'
FROM rust:slim-bookworm AS builder
WORKDIR /app
COPY crates crates
RUN cargo build --release

FROM debian:bookworm-slim AS runtime
COPY rust-toolchain.toml /doc/rust-toolchain.toml
DOCKER
}
run_case "container-pins-only-a-stage-that-never-compiles" 1 \
    "does not carry the ASSERT-PINNED-RUSTC block verbatim" routing_ok \
    docker_pin_reaches_only_the_runtime_stage

# A stage that inherits from an earlier one, or from a non-rust image, names no `rust`
# image and needs no assertion of its own.
docker_names_no_rust_image() {
    cat <<'DOCKER'
FROM debian:bookworm-slim AS runtime
COPY --from=builder /app/target/release/scp-relay /usr/local/bin/scp-relay
DOCKER
}
run_case "container-names-no-rust-image" 0 "" routing_ok docker_names_no_rust_image

echo ""
echo "toolchain-wiring cases: $passed passed, $failed failed"
[[ $failed -eq 0 ]]
