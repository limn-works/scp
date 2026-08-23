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
#     entry, and stays silent when every declared entry is present. Every Rust job is
#     guarded by such a filter, and the `ci` job that aggregates every other job's result
#     counts a skipped job as a pass, so an omitted entry lets a change merge unbuilt.
#
# HOW EACH CASE IS BUILT. `run_case` makes a temporary directory, copies the gate into
# `scripts/`, runs `git init` so the gate's `git grep` search has a work tree, and writes
# the case's `ci.yml` and optional `Dockerfile` from heredocs. The gate `cd`s to its own
# parent's parent, so that directory becomes its repository root.
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

# A ci.yml whose two filters carry every declared entry. Cases that are not about check 2
# use it so their only finding can come from check 1.
routing_ok() {
    cat <<'YAML'
name: CI
jobs:
  changes:
    runs-on: ubuntu-latest
    outputs:
      rust: ${{ steps.filter.outputs.rust }}
      fuzz: ${{ steps.filter.outputs.fuzz }}
    steps:
      - uses: dorny/paths-filter@v3
        id: filter
        with:
          filters: |
            rust:
              - 'crates/**'
              # A comment inside a filter block, which the extractor skips.
              - 'rust-toolchain.toml'
              - "Dockerfile"

              - '.dockerignore'
              - '.clippy.toml'
              - 'rustfmt.toml'
            fuzz:
              - 'fuzz/**'
YAML
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

ci_rust_filter_omits_pin() {
    cat <<'YAML'
name: CI
jobs:
  changes:
    runs-on: ubuntu-latest
    outputs:
      rust: ${{ steps.filter.outputs.rust }}
      fuzz: ${{ steps.filter.outputs.fuzz }}
    steps:
      - uses: dorny/paths-filter@v3
        id: filter
        with:
          filters: |
            rust:
              - 'crates/**'
              - 'Dockerfile'
              - '.dockerignore'
            fuzz:
              - 'fuzz/**'
YAML
}
run_case "rust-filter-omits-the-pin" 1 \
    "the 'rust' paths filter does not list rust-toolchain.toml" ci_rust_filter_omits_pin

ci_rust_filter_omits_dockerfile() {
    cat <<'YAML'
name: CI
jobs:
  changes:
    runs-on: ubuntu-latest
    outputs:
      rust: ${{ steps.filter.outputs.rust }}
      fuzz: ${{ steps.filter.outputs.fuzz }}
    steps:
      - uses: dorny/paths-filter@v3
        id: filter
        with:
          filters: |
            rust:
              - 'crates/**'
              - 'rust-toolchain.toml'
              - '.dockerignore'
            fuzz:
              - 'fuzz/**'
YAML
}
run_case "rust-filter-omits-the-container-build" 1 \
    "the 'rust' paths filter does not list Dockerfile" ci_rust_filter_omits_dockerfile

ci_no_rust_filter() {
    cat <<'YAML'
name: CI
jobs:
  changes:
    runs-on: ubuntu-latest
    outputs:
      fuzz: ${{ steps.filter.outputs.fuzz }}
    steps:
      - uses: dorny/paths-filter@v3
        id: filter
        with:
          filters: |
            fuzz:
              - 'fuzz/**'
YAML
}
run_case "rust-filter-absent-entirely" 1 \
    "declares no 'rust:' paths filter with path entries" ci_no_rust_filter

ci_fuzz_filter_omits_crate() {
    cat <<'YAML'
name: CI
jobs:
  changes:
    runs-on: ubuntu-latest
    outputs:
      rust: ${{ steps.filter.outputs.rust }}
      fuzz: ${{ steps.filter.outputs.fuzz }}
    steps:
      - uses: dorny/paths-filter@v3
        id: filter
        with:
          filters: |
            rust:
              - 'crates/**'
              - 'rust-toolchain.toml'
              - 'Dockerfile'
              - '.dockerignore'
              - '.clippy.toml'
              - 'rustfmt.toml'
            fuzz:
              - 'fuzz/fuzz_targets/**'
YAML
}
run_case "fuzz-filter-omits-the-crate" 1 \
    "the 'fuzz' paths filter does not list fuzz/**" ci_fuzz_filter_omits_crate

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
