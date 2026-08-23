#!/usr/bin/env bash
#
# The compiler this directory resolves.
#
# THE CRITERION: a cargo command run in this repository compiles on the version
# `rust-toolchain.toml` names. rustup reads that file for every command run here, and on
# first use installs the channel, components, and targets the file names, so the file
# governs unless something overrides it.
#
# TWO THINGS FALSIFY that criterion, and this script tests both.
#
#   1. `RUSTUP_TOOLCHAIN` holds a value. rustup's own documentation gives that variable
#      precedence over a toolchain file, and it replaces the file entirely — channel,
#      components, and targets alike. A shell carrying it compiles on a version this
#      repository does not name and cross-compiles for whichever targets the other
#      toolchain holds. This script fails on the variable holding a value, not on the
#      version that value selects, because `RUSTUP_TOOLCHAIN=1.98.0` resolves the pinned
#      version and still drops the targets `rust-toolchain.toml` lists.
#
#   2. An installed compiler answers here with some other version. `rustc --version`
#      reports what rustup resolved, and `cargo clippy` runs that same compiler.
#
# WHERE FALSIFIER 2 GOES UNTESTED, stated rather than implied. rustup's shim installs the
# toolchain a directory selects the first time a compiler runs there, and
# `rust-toolchain.toml` names 13 targets, so the first `rustc --version` in a checkout that
# has never compiled downloads about 2 GB. A GitHub runner for a job that compiles nothing
# sits in that state. Once falsifier 1 passes, rustup selects the channel the file names, so
# the comparison's answer is settled before it runs. This script therefore asks
# `rustup toolchain list`, which reads rustup's own directory and installs nothing, and runs
# `rustc` only when rustup already holds the channel. It prints which of the two it did, so
# a caller never reads a skip as a pass.
#
# WHY THIS SCRIPT HOLDS THE COMPARISON. Three callers need it:
# `scripts/check-toolchain-wiring.sh` as its fourth check, `scripts/hooks/pre-commit`
# before that hook runs `cargo fmt` and `cargo clippy`, and `scripts/setup-toolchain.sh`
# after that script resolves the toolchain. Each one held its own copy of the expression
# that reads the channel out of the pin, and this file replaces all three, so one file
# states the criterion.
#
# `.docs/lessons/pin-the-rust-toolchain-or-ci-drifts-from-local.md` records the merge-queue
# outage a compiler disagreement caused, and records that this comparison once ran only in
# a CI job, where no `RUSTUP_TOOLCHAIN` arises, so it reported success forever.
#
# OUTPUT CONTRACT. The script prints one line per finding on stdout and names no colour,
# no prefix, and no severity, so each caller formats the line its own way. It exits 0 when
# the criterion holds and 1 when either falsifier holds or when the pin is unreadable.
#
# Usage: bash scripts/check-resolved-rustc.sh
set -uo pipefail

cd "$(dirname "$0")/.."

PIN="rust-toolchain.toml"

if [[ ! -f $PIN ]]; then
    printf '%s does not exist, so this directory names no Rust version for a compiler to match.\n' "$PIN"
    exit 1
fi

channel=$(sed -nE 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' "$PIN" | head -n 1)
if [[ -z $channel ]]; then
    printf '%s names no [toolchain] channel, so this directory names no Rust version for a compiler to match.\n' "$PIN"
    exit 1
fi

fail=0

# ── Falsifier 1: something in the environment replaces the toolchain file ────────────
if [[ -n ${RUSTUP_TOOLCHAIN:-} ]]; then
    printf 'RUSTUP_TOOLCHAIN=%s is set in this environment, and rustup applies that variable in place of %s — channel, components, and targets alike. Unset it, so rustup reads %s and installs the toolchain that file names.\n' \
        "$RUSTUP_TOOLCHAIN" "$PIN" "$PIN"
    fail=1
fi

# ── Falsifier 2: the installed compiler answers with another version ─────────────────
#
# `compare` stays 1 when running `rustc` installs nothing: either rustup already holds the
# channel, or no rustup manages this rustc, or `RUSTUP_TOOLCHAIN` already selected a
# toolchain whoever set it installed. It drops to 0 only in the one state where the
# comparison would trigger the download and could not disagree with the pin anyway.
compare=1
if command -v rustup >/dev/null 2>&1; then
    compare=0
    while IFS= read -r listed; do
        # `rustup toolchain list` prints "<channel>-<host triple>" and appends " (active)"
        # or " (default)", so the first field carries the channel and the host triple.
        if [[ ${listed%% *} == "$channel"-* ]]; then
            compare=1
            break
        fi
    done < <(rustup toolchain list 2>/dev/null)
fi
if [[ -n ${RUSTUP_TOOLCHAIN:-} ]]; then
    compare=1
fi

if [[ $compare -eq 0 ]]; then
    printf 'rustup holds no %s toolchain, so no compiler has resolved in this directory yet and none can disagree with %s. rustup installs %s the first time a cargo command runs here.\n' \
        "$channel" "$PIN" "$channel"
    exit "$fail"
fi

if ! command -v rustc >/dev/null 2>&1; then
    printf 'rustc is not on PATH, so no compiler answers in this directory. Install rustup from https://rustup.rs, which reads %s and installs the toolchain that file names.\n' "$PIN"
    exit 1
fi

active=$(rustc --version 2>/dev/null | sed -nE 's/^rustc ([0-9]+\.[0-9]+\.[0-9]+).*/\1/p')
if [[ -z $active ]]; then
    printf 'rustc ran but printed no version this script could read, so the compiler this directory resolves is unknown.\n'
    exit 1
fi

if [[ $active != "$channel" ]]; then
    printf 'rustc in this directory is %s, and %s names %s. Every cargo command here compiles and lints on %s, so a lint the pinned release adds appears first in CI, against code nobody changed.\n' \
        "$active" "$PIN" "$channel" "$active"
    exit 1
fi

printf 'rustc %s in this directory is the version %s names.\n' "$active" "$PIN"
exit "$fail"
