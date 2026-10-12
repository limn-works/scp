#!/usr/bin/env bash
#
# Download the registry index entries and the `.crate` sources of every package one
# workspace's Cargo.lock names, then take cargo offline for the rest of the job.
# `action.yml` beside this file is the one caller in CI; the arguments are positional so
# `scripts/tests/cargo-fetch-action/run-tests.sh` can run this file with a stub cargo.
#
# WHY A JOB FETCHES ONCE, UP FRONT. Cargo downloads the sparse index and the crate sources
# on demand, inside whichever build, test or lint command first needs them, and retries a
# failed request three times. In run 38171293381, job
# `Rust / test (macos-latest, transport-local)` could not resolve `index.crates.io`, cargo
# gave up after those three retries, and the job failed before it compiled anything, on a
# change that touched no Rust. This script makes every network
# request a job's cargo commands need in one step that retries far longer: each attempt runs
# with `CARGO_NET_RETRY=10`, and a failed attempt is retried with backoff, four attempts in
# all.
#
# WHY OFFLINE AFTERWARDS. After the fetch, every package the lockfile names is on disk, and
# `CARGO_NET_OFFLINE=true` makes cargo read only that copy. The variable goes to
# `$GITHUB_ENV`, so it reaches every later step of the job and every cargo command a script
# in such a step starts, which a `--offline` flag on each workflow line would not. A later
# network failure therefore cannot fail a build, test or lint step; a command that needs a
# package the fetch did not download fails with cargo's offline error, naming the package.
# `cargo fetch` without `--target` downloads the packages of every platform, so a
# wasm32, Android or Apple cross build in the same job resolves offline too. Before writing
# the variable this script proves the claim: `cargo metadata --all-features` under
# `CARGO_NET_OFFLINE=true` reads every package's manifest from disk, and it fails when any
# one is missing.
#
# WHY `--locked`. A fetch that rewrote Cargo.lock would download a dependency graph no
# reviewer saw. `--locked` fails the step instead, as it fails a build whose lockfile no
# longer matches its manifests.
#
# ORDER IN A JOB. This step runs after `./.github/actions/rust-toolchain` (cargo needs a
# compiler to resolve), after `Swatinem/rust-cache` (which restores `~/.cargo/registry`, so a
# warm fetch downloads only what changed, and which hashes every `CARGO*` variable its step
# sees into its cache key, so `CARGO_NET_OFFLINE` must not exist yet when it runs), and
# before every other cargo command. A `cargo install` runs before it, because installing a
# tool from crates.io needs the network. `scripts/tests/ci-gate/ci_gate_selftest.py` check
# `offline-cargo` holds every workflow job to that order.
#
# FAILURE IS TYPED, NEVER DEGRADED. Each case below exits non-zero with a `::error::` line
# naming the case: a missing working directory, a working directory with no Cargo.lock, a
# `CARGO_NET_OFFLINE` already in the environment (a step before this one took cargo offline
# or online by hand, or the job fetches twice), no writable `$GITHUB_ENV` or
# `$GITHUB_OUTPUT`, neither `CARGO_HOME` nor `HOME` set, a cargo that
# cannot report its version (a toolchain problem no retry fixes, so it is not retried), a
# fetch that failed on every attempt (the line carries cargo's own error chain), and an
# offline `cargo metadata` that fails after a fetch that succeeded.
#
# THE `cargo-home` OUTPUT. The step also writes the directory the packages landed in,
# `$CARGO_HOME` or `$HOME/.cargo`, to `$GITHUB_OUTPUT`. A step that builds inside a container
# (`PyO3/maturin-action` on a manylinux leg) receives `CARGO_NET_OFFLINE` but none of the
# runner's files, so it mounts `<cargo-home>/registry` into the container; without that
# mount the offline build inside it finds no package and fails.
#
# Usage: fetch.sh <working-directory> [toolchain]
# Environment:
#   GITHUB_ENV                          the file the runner reads later steps' variables from.
#   GITHUB_OUTPUT                       the file the runner reads this step's outputs from.
#   CARGO_FETCH_RETRY_DELAY_SECONDS     seconds before the second attempt, doubling before
#                                       each later one (default 10, so 10, 20, 40).
set -euo pipefail

ATTEMPTS=4
NET_RETRY=10

error() {
    # GitHub reads a workflow command up to the end of its line, so the message encodes `%`,
    # CR and LF the way the runner's command parser expects.
    local message=$1
    message=${message//'%'/'%25'}
    message=${message//$'\r'/'%0D'}
    message=${message//$'\n'/'%0A'}
    printf '::error title=cargo-fetch::%s\n' "$message"
}

directory=${1:-}
toolchain=${2:-}

if [[ -z $directory ]]; then
    error "fetch.sh needs a working directory as its first argument, so it fetched nothing."
    exit 2
fi
if [[ ! -d $directory ]]; then
    error "$directory is not a directory, so this step fetched nothing."
    exit 1
fi
if [[ ! -f $directory/Cargo.lock ]]; then
    error "$directory holds no Cargo.lock, so \`cargo fetch --locked\` has no package list to download and this step fetched nothing."
    exit 1
fi
if [[ -n $toolchain && ! $toolchain =~ ^[A-Za-z0-9._-]+$ ]]; then
    error "toolchain '$toolchain' is not a rustup toolchain name, so this step fetched nothing."
    exit 2
fi
if [[ -n ${CARGO_NET_OFFLINE+set} ]]; then
    error "CARGO_NET_OFFLINE is already '${CARGO_NET_OFFLINE}' before the fetch. Either a step before this one sets it, or this job fetches twice. Remove the earlier setting, or fetch once per job."
    exit 1
fi
if [[ -z ${GITHUB_ENV:-} || ! -w ${GITHUB_ENV} ]]; then
    error "GITHUB_ENV is '${GITHUB_ENV:-}', not a writable file, so this step cannot set CARGO_NET_OFFLINE for the steps after it."
    exit 1
fi
if [[ -z ${GITHUB_OUTPUT:-} || ! -w ${GITHUB_OUTPUT} ]]; then
    error "GITHUB_OUTPUT is '${GITHUB_OUTPUT:-}', not a writable file, so this step cannot report the cargo home a container build mounts."
    exit 1
fi
if [[ -n ${CARGO_HOME:-} ]]; then
    cargo_home=$CARGO_HOME
elif [[ -n ${HOME:-} ]]; then
    cargo_home=$HOME/.cargo
else
    error "Neither CARGO_HOME nor HOME is set, so this step cannot name the directory cargo downloads into."
    exit 1
fi
delay=${CARGO_FETCH_RETRY_DELAY_SECONDS:-10}
if [[ ! $delay =~ ^[0-9]+$ ]]; then
    error "CARGO_FETCH_RETRY_DELAY_SECONDS=$delay is not a whole number of seconds, so this step fetched nothing."
    exit 2
fi

cargo_cmd=(cargo)
if [[ -n $toolchain ]]; then cargo_cmd+=("+$toolchain"); fi

cd "$directory"

if ! version=$("${cargo_cmd[@]}" -V 2>&1); then
    error "${cargo_cmd[*]} -V failed in $directory, so no compiler resolves here and a fetch would fail the same way on every attempt. cargo said:
$version"
    exit 1
fi

log=$(mktemp)
trap 'rm -f "$log"' EXIT

attempt=1
status=0
while :; do
    printf 'cargo-fetch: attempt %d of %d: %s fetch --locked in %s (%s)\n' \
        "$attempt" "$ATTEMPTS" "${cargo_cmd[*]}" "$directory" "$version"
    # cargo writes its progress and its error chain to stderr; tee keeps both in the job log
    # and in $log, and pipefail makes the pipeline's status cargo's.
    if CARGO_NET_RETRY=$NET_RETRY "${cargo_cmd[@]}" fetch --locked 2>&1 | tee "$log"; then
        status=0
        break
    else
        status=$?
    fi
    if (( attempt >= ATTEMPTS )); then
        chain=$(awk '/^error/ {found = 1} found' "$log")
        [[ -n $chain ]] || chain=$(tail -n 20 "$log")
        error "${cargo_cmd[*]} fetch --locked in $directory failed on all $ATTEMPTS attempts (last exit status $status), each retrying every request $NET_RETRY times. cargo's error:
$chain"
        exit "$status"
    fi
    wait_seconds=$(( delay * (1 << (attempt - 1)) ))
    printf 'cargo-fetch: attempt %d failed with exit status %d; retrying in %ds\n' "$attempt" "$status" "$wait_seconds"
    sleep "$wait_seconds"
    attempt=$(( attempt + 1 ))
done

if ! CARGO_NET_OFFLINE=true "${cargo_cmd[@]}" metadata --locked --all-features --format-version 1 >/dev/null 2>"$log"; then
    error "${cargo_cmd[*]} fetch --locked succeeded in $directory, but an offline \`cargo metadata --locked --all-features\` there failed, so a later cargo command would reach for the network. cargo's error:
$(cat "$log")"
    exit 1
fi

printf 'cargo-home=%s\n' "$cargo_home" >> "$GITHUB_OUTPUT"
printf 'CARGO_NET_OFFLINE=true\n' >> "$GITHUB_ENV"
printf 'cargo-fetch: %s fetched on attempt %d of %d; every later step of this job runs cargo with CARGO_NET_OFFLINE=true\n' \
    "$directory" "$attempt" "$ATTEMPTS"
