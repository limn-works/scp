#!/usr/bin/env bash
#
# Install the Rust toolchain a toolchain file names, with only the components and targets
# the calling job compiles with, and make it the override of the directory that file sits
# in. `action.yml` beside this file is the one caller in CI; the arguments are positional so
# `scripts/tests/rust-toolchain-action/run-tests.sh` can run this file with a stub rustup.
#
# WHY A CI JOB DOES NOT LET RUSTUP INSTALL THE PIN ON FIRST USE. rustup installs a toolchain
# file's channel with every component and target the file lists the first time a compiler
# runs under it. `rust-toolchain.toml` lists 13 targets, clippy, rustfmt and
# rust-analyzer, so that implicit install took 24 to 44 seconds in every Rust job of
# merge-queue run 38006292987, and it made one download attempt: on 2026-10-10 job
# `Python / wheel (vendored OpenSSL)` died when rustup's download of cargo 1.98.0 hit
# `Connection timed out (os error 110)`, and job `Rust / clippy (packages-network)` died the
# same way inside `Swatinem/rust-cache`'s `rustc -vV`. This script installs the same channel
# under the minimal profile (rustc, cargo, rust-std), adds only what the job names, and
# retries a failed install with backoff.
#
# WHY AN OVERRIDE, AND WHY THE VERSION STAYS THE ONE THE FILE NAMES. A directory override
# outranks a toolchain file in the same directory, so after `rustup override set` a cargo
# command run here resolves the installed minimal toolchain and rustup installs nothing
# more on first use. The channel comes out of the toolchain file, so the file still names
# the only version: the override selects the same compiler, built from the same commit,
# that the file selects on a developer's machine, and rust-cache keys, which hash the
# compiler's `rustc -vV`, do not change. A nearer toolchain file still outranks this
# override, so `fuzz/` keeps resolving `fuzz/rust-toolchain.toml`. Job
# `enforcement / toolchain wiring` does not call this script: check 4 of
# `scripts/check-toolchain-wiring.sh` must see the checkout as a developer's shell sees it,
# with no override.
#
# FAILURE IS TYPED, NEVER DEGRADED. Each case below exits non-zero with a `::error::` line
# naming the case: an unreadable toolchain file or channel, a `RUSTUP_TOOLCHAIN` in the
# environment (it outranks the override, so the job would compile on some other
# toolchain), an install that failed on every attempt (the line carries rustup's own error
# chain), an override rustup refused, and a `rustc -V` in that directory that does not
# report the toolchain just installed.
#
# Usage: install.sh <toolchain-file> [components] [targets]
#   components and targets are comma- or space-separated lists; either may be empty.
# Environment:
#   RUST_TOOLCHAIN_RETRY_DELAY_SECONDS  seconds before the second attempt, doubling before
#                                       each later one (default 10, so 10, 20, 40).
set -euo pipefail

ATTEMPTS=4

error() {
    # GitHub reads a workflow command up to the end of its line, so the message encodes `%`,
    # CR and LF the way the runner's command parser expects.
    local message=$1
    message=${message//'%'/'%25'}
    message=${message//$'\r'/'%0D'}
    message=${message//$'\n'/'%0A'}
    printf '::error title=rust-toolchain::%s\n' "$message"
}

toolchain_file=${1:-}
components=${2:-}
targets=${3:-}

if [[ -z $toolchain_file ]]; then
    error "install.sh needs the path of a toolchain file as its first argument, so it installed nothing."
    exit 2
fi
if [[ ! -f $toolchain_file ]]; then
    error "$toolchain_file does not exist, so this step read no channel and installed nothing."
    exit 1
fi
delay=${RUST_TOOLCHAIN_RETRY_DELAY_SECONDS:-10}
if [[ ! $delay =~ ^[0-9]+$ ]]; then
    error "RUST_TOOLCHAIN_RETRY_DELAY_SECONDS=$delay is not a whole number of seconds, so this step installed nothing."
    exit 2
fi

# The same expression `scripts/check-resolved-rustc.sh` reads the channel with: the first
# `channel = "..."` line of the file.
channel=$(sed -nE 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' "$toolchain_file" | head -n 1)
if [[ -z $channel ]]; then
    error "$toolchain_file names no [toolchain] channel, so this step installed nothing."
    exit 1
fi

if [[ -n ${RUSTUP_TOOLCHAIN:-} ]]; then
    error "RUSTUP_TOOLCHAIN=$RUSTUP_TOOLCHAIN is set, and rustup applies it ahead of any directory override, so a cargo command in this job would compile on that toolchain instead of $channel. Remove the variable from the job's environment."
    exit 1
fi

directory=$(cd "$(dirname "$toolchain_file")" && pwd -P)

install_args=(toolchain install "$channel" --profile minimal --no-self-update)
for component in ${components//,/ }; do install_args+=(--component "$component"); done
for target in ${targets//,/ }; do install_args+=(--target "$target"); done

log=$(mktemp)
trap 'rm -f "$log"' EXIT

attempt=1
status=0
while :; do
    printf 'rust-toolchain: attempt %d of %d: rustup %s\n' "$attempt" "$ATTEMPTS" "${install_args[*]}"
    # rustup writes its progress and its error chain to stderr; tee keeps both in the job
    # log and in $log, and pipefail makes the pipeline's status rustup's.
    if rustup "${install_args[@]}" 2>&1 | tee "$log"; then
        status=0
        break
    else
        status=$?
    fi
    if (( attempt >= ATTEMPTS )); then
        # The error chain runs from the line rustup opens with `error:` through its
        # `Caused by:` list; the stack backtrace a runner's RUST_BACKTRACE appends after it
        # is left out.
        chain=$(awk '/^Stack backtrace:/ {exit} /^error:/ {found = 1} found' "$log")
        [[ -n $chain ]] || chain=$(tail -n 20 "$log")
        error "rustup toolchain install $channel failed on all $ATTEMPTS attempts (last exit status $status). rustup's error:
$chain"
        exit "$status"
    fi
    wait_seconds=$(( delay * (1 << (attempt - 1)) ))
    printf 'rust-toolchain: attempt %d failed with exit status %d; retrying in %ds\n' "$attempt" "$status" "$wait_seconds"
    sleep "$wait_seconds"
    attempt=$(( attempt + 1 ))
done

if ! rustup override set "$channel" --path "$directory"; then
    error "rustup override set $channel --path $directory failed, so a cargo command in $directory would fall back to $toolchain_file and install its full component and target list on first use."
    exit 1
fi

if ! expected=$(rustup run "$channel" rustc -V); then
    error "rustup run $channel rustc -V failed right after rustup installed $channel, so this step cannot name the compiler that toolchain holds."
    exit 1
fi
if ! resolved=$(cd "$directory" && rustc -V); then
    error "rustc -V failed in $directory after the override to $channel was set."
    exit 1
fi
# A numbered channel names the version rustc reports; a dated nightly does not (its rustc
# reports the next release's number and the commit date), so every channel is also
# compared against the compiler the installed toolchain itself holds.
if [[ $channel =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ && $resolved != "rustc $channel "* ]]; then
    error "rustc -V in $directory reports '$resolved', not version $channel, which $toolchain_file names."
    exit 1
fi
if [[ $resolved != "$expected" ]]; then
    error "rustc -V in $directory reports '$resolved', but toolchain $channel holds '$expected', so something outranks the override this step set."
    exit 1
fi

printf 'rust-toolchain: %s resolves %s (installed on attempt %d of %d)\n' "$directory" "$resolved" "$attempt" "$ATTEMPTS"
