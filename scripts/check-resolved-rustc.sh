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
# sits in that state, and this script skips falsifier 2 there.
#
# THE CRITERION FOR SKIPPING: running `rustc` in this directory would make rustup install
# the channel `rust-toolchain.toml` names. That is the one state where the comparison costs
# a download, and it is the same state in which no compiler has answered here yet, so none
# can disagree with the pin. Five facts together prove the state, and each one reads
# rustup's own directory or a file on disk, so proving it installs nothing:
#
#   a. `rustup` answers on PATH, so rustup installs and dispatches the compilers here.
#   b. `rustc` answers on PATH and reads the same bytes as `rustup`, which `cmp` reports.
#      rustup installs its `rustc` as a link to the `rustup` binary, and mise installs its
#      `rustc` shim as a link to the `mise` binary beside its `rustup` shim, so in both
#      installations the two names read one file. A compiler some other installer put on
#      PATH — Homebrew's `rustc` ahead of `~/.cargo/bin` — reads different bytes, answers
#      without consulting rustup, and downloads nothing, so the script compares against it
#      instead of skipping. It also compares when `cmp` is absent from PATH, because it
#      cannot prove this fact without `cmp`.
#   c. `RUSTUP_TOOLCHAIN` holds nothing. rustup applies that variable in place of the
#      toolchain file, and falsifier 1 above reports it.
#   d. `rustup override list` names no directory holding this one. `rustup override set`
#      selects a toolchain for a directory and its children ahead of the toolchain file,
#      and installs that toolchain as it sets it, so a checkout under an override resolves
#      an installed compiler the pin does not name. An earlier revision of this script
#      exited 0 in that state, which is the fail-open this file exists to remove.
#   e. `rustup toolchain list` holds no entry for the pinned channel.
#
# When any one of the five fails, running `rustc` reports a version and downloads nothing,
# so the script runs it. It prints which of the two it did, so a caller never reads a skip
# as a pass.
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
# the criterion holds, and 1 when either falsifier holds, when the pin is unreadable, and
# when the script cannot reach the repository root that holds the pin.
#
# Usage: bash scripts/check-resolved-rustc.sh
set -uo pipefail

# Every path below is relative to the repository root, and the override comparison reads
# `pwd -P`, so a `cd` that fails would compare the wrong directory against rustup's
# overrides. The script reports that rather than proceeding from wherever the caller stood.
if ! cd "$(dirname "$0")/.."; then
    printf 'this script could not enter its own repository root, so it read no rust-toolchain.toml and compared no compiler.\n'
    exit 1
fi

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

# ── Falsifier 2: the compiler answering here reports another version ─────────────────
#
# `compare` starts at 1 and drops to 0 only where facts a through e above all hold, which
# is the one state in which running `rustc` downloads a toolchain.
compare=1
rustc_path=$(command -v rustc 2>/dev/null || true)
rustup_path=$(command -v rustup 2>/dev/null || true)

if [[ -z ${RUSTUP_TOOLCHAIN:-} && -n $rustc_path && -n $rustup_path ]] &&
    command -v cmp >/dev/null 2>&1 && cmp -s "$rustc_path" "$rustup_path"; then
    # Facts a, b, and c hold, so rustup dispatches the compiler that answers on PATH here,
    # and rustup reads a toolchain file unless a directory override redirects it.
    repo_root=$(pwd -P)
    overridden=0
    while IFS= read -r listed; do
        # `rustup override list` prints "<directory><whitespace><toolchain>" for each
        # override it holds, so dropping the last whitespace-delimited field leaves the
        # directory, which may itself hold spaces. Every other line the command prints —
        # "no overrides" when it holds none — leaves something that is not an absolute
        # path, and the test below reads only absolute paths.
        override_dir=$(printf '%s' "$listed" | sed -E 's/[[:space:]]+[^[:space:]]+[[:space:]]*$//')
        [[ $override_dir == /* ]] || continue
        if [[ $repo_root == "$override_dir" || $repo_root == "$override_dir"/* ]]; then
            overridden=1
            break
        fi
    done < <(rustup override list 2>/dev/null)

    if [[ $overridden -eq 0 ]]; then
        compare=0
        while IFS= read -r listed; do
            # `rustup toolchain list` prints "<channel>-<host triple>" and appends
            # " (active)" or " (default)", so the first field carries the channel and the
            # host triple.
            if [[ ${listed%% *} == "$channel"-* ]]; then
                compare=1
                break
            fi
        done < <(rustup toolchain list 2>/dev/null)
    fi
fi

if [[ $compare -eq 0 ]]; then
    printf 'rustup dispatches the rustc on PATH here, no directory override redirects this directory, and rustup holds no %s toolchain, so no compiler has resolved in this directory yet and none can disagree with %s. rustup installs %s the first time a cargo command runs here.\n' \
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
