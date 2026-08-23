#!/usr/bin/env bash
#
# Toolchain-pin agreement gate.
#
# The repository selects a Rust compiler version in more than one place, and the
# places must name the same version. When they disagree, a developer and CI compile
# with different compilers, a new stable release introduces lints that only CI sees,
# and the merge queue fails against code nobody changed. That is the outage recorded
# in `.docs/lessons/pin-the-rust-toolchain-or-ci-drifts-from-local.md`, and a comment
# asking several files to agree is not enforcement.
#
# The gate is closed by construction: it reads a fixed list of known locations,
# extracts one version string from each, and requires exact equality. It never scans
# for version-shaped strings, so it admits nothing it was not told to check.
#
# Stable version — every one of these compiles the workspace:
#   1. `rust-toolchain.toml`      channel        — what plain `cargo` resolves to
#   2. `.mise.toml`               rust version   — what a mise shell resolves to
#   3. `Dockerfile`               FROM rust:X    — what the container build compiles with
#   4. `.docs/standards/rust.md`  rustc row      — the standard that governs the pin
#
# Nightly version — the standalone fuzz crate needs one, and cargo-fuzz does not run
# on stable:
#   5. `fuzz/rust-toolchain.toml`        channel
#   6. `.github/workflows/fuzz.yml`      FUZZ_TOOLCHAIN
#
# The gate FAILS CLOSED. A location that is missing, or whose version string does not
# parse, is a failure — never a skipped check. `.docs/lessons/coverage-gates-must-fail-closed.md`
# records why: a gate that cannot find what it is checking, and passes, is a gate that
# reports success for the case it exists to catch.
#
# Usage: bash scripts/check-toolchain-pin.sh
set -euo pipefail

cd "$(dirname "$0")/.."

fail=0
report() {
    printf 'FAIL: %s\n' "$1" >&2
    fail=1
}

# require <variable> <label> <file> <sed-script>
#
# Assigns the extracted version to the named variable in THIS shell, and fails closed
# when the file is absent or the pattern does not match. `printf -v` assigns without a
# subshell, which is the whole point: an earlier draft of this gate called `report`
# from inside a command substitution, and because a command substitution runs in a
# subshell, `fail=1` was discarded every time. That draft printed FAIL lines and exited
# 0 — the fail-open shape `.docs/lessons/coverage-gates-must-fail-closed.md` forbids.
#
# Leaves the variable empty on failure. The caller must not compare an empty value,
# because two absent locations would otherwise agree with each other.
require() {
    local var=$1 label=$2 file=$3 script=$4 value
    printf -v "$var" '%s' ''
    if [[ ! -f $file ]]; then
        report "$label: $file does not exist"
        return 0
    fi
    value=$(sed -nE "$script" "$file" | head -n 1)
    if [[ -z $value ]]; then
        report "$label: no version string found in $file"
        return 0
    fi
    printf -v "$var" '%s' "$value"
}

require pin_version "rust-toolchain.toml [toolchain] channel" \
    "rust-toolchain.toml" \
    's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p'

require mise_version ".mise.toml [tools] rust version" \
    ".mise.toml" \
    's/^[[:space:]]*rust[[:space:]]*=.*version[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p'

require docker_version "Dockerfile chef stage base image" \
    "Dockerfile" \
    's|^FROM rust:([0-9]+\.[0-9]+(\.[0-9]+)?)-.*|\1|p'

require standard_version ".docs/standards/rust.md toolchain table, rustc row" \
    ".docs/standards/rust.md" \
    's/^\|[[:space:]]*rustc[[:space:]]*\|[[:space:]]*([^|[:space:]]+)[[:space:]]*\|.*/\1/p'

require fuzz_version "fuzz/rust-toolchain.toml [toolchain] channel" \
    "fuzz/rust-toolchain.toml" \
    's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p'

require workflow_version ".github/workflows/fuzz.yml env FUZZ_TOOLCHAIN" \
    ".github/workflows/fuzz.yml" \
    's/^[[:space:]]*FUZZ_TOOLCHAIN:[[:space:]]*([^[:space:]]+)[[:space:]]*$/\1/p'

# Any location that produced no value already set `fail`. Stop here rather than
# compare, because two empty values would otherwise agree with each other.
if [[ $fail -ne 0 ]]; then
    printf '\nEvery location above must name a version before the gate can compare them.\n' >&2
    exit 1
fi

# A Dockerfile tag may drop the patch component (`rust:1.98-slim` selects the newest
# 1.98.x), so accept the pin truncated to major.minor for that one location.
pin_major_minor=${pin_version%.*}

[[ $mise_version == "$pin_version" ]] ||
    report ".mise.toml names rust $mise_version; rust-toolchain.toml names $pin_version"

[[ $docker_version == "$pin_version" || $docker_version == "$pin_major_minor" ]] ||
    report "Dockerfile builds on rust:$docker_version; rust-toolchain.toml names $pin_version"

[[ $standard_version == "$pin_version" ]] ||
    report ".docs/standards/rust.md names rustc $standard_version; rust-toolchain.toml names $pin_version"

# The fuzz crate pins a nightly on purpose. Assert that it still does, so a future
# edit cannot quietly point the fuzz crate at stable, where cargo-fuzz does not run.
[[ $fuzz_version == nightly-* ]] ||
    report "fuzz/rust-toolchain.toml names $fuzz_version; cargo-fuzz requires a nightly channel"

# `.github/workflows/fuzz.yml` runs `cargo +$FUZZ_TOOLCHAIN`, so its value must be the
# nightly the fuzz crate pins, or the scheduled fuzz jobs compile on the wrong compiler.
[[ $workflow_version == "$fuzz_version" ]] ||
    report "fuzz.yml FUZZ_TOOLCHAIN is $workflow_version; fuzz/rust-toolchain.toml names $fuzz_version"

if [[ $fail -eq 0 ]]; then
    printf 'OK: stable pin %s agrees across rust-toolchain.toml, .mise.toml, Dockerfile, and .docs/standards/rust.md\n' "$pin_version"
    printf 'OK: fuzz pin %s agrees across fuzz/rust-toolchain.toml and .github/workflows/fuzz.yml\n' "$fuzz_version"
    exit 0
fi

cat >&2 <<'EOM'

Raising the Rust version is a deliberate change that touches every location above
together. See the "Rust is pinned" paragraph in CLAUDE.md and
.docs/lessons/pin-the-rust-toolchain-or-ci-drifts-from-local.md.
EOM
exit 1
