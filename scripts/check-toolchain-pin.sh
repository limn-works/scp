#!/usr/bin/env bash
#
# Toolchain-pin agreement gate.
#
# The repository selects a Rust compiler version in more than one place, and the
# places must name the same version. When they disagree, a developer and CI compile
# with different compilers, a new stable release introduces lints that only CI sees,
# and the merge queue fails against code nobody changed. That is the outage recorded
# in `.docs/lessons/pin-the-rust-toolchain-or-ci-drifts-from-local.md`, and a comment
# asking three files to agree is not enforcement.
#
# The gate is closed by construction: it reads a fixed list of four known locations,
# extracts one version string from each, and requires exact equality. It does not
# scan for candidate version strings, so it admits nothing it was not told to check.
#
#   1. `rust-toolchain.toml`      channel        — what plain `cargo` resolves to
#   2. `.mise.toml`               rust version   — what a mise shell resolves to
#   3. `Dockerfile`               FROM rust:X    — what the container build compiles with
#   4. `.docs/standards/rust.md`  rustc row      — the standard that governs the pin
#
# The fuzz crate is deliberately excluded: `fuzz/rust-toolchain.toml` pins a nightly
# on purpose, and the gate checks that it stays a nightly rather than matching stable.
#
# Usage: bash scripts/check-toolchain-pin.sh
set -euo pipefail

cd "$(dirname "$0")/.."

fail=0
report() {
    printf 'FAIL: %s\n' "$1" >&2
    fail=1
}

extract() {
    # extract <file> <sed-script> <label>
    local file=$1 script=$2 label=$3 value
    if [[ ! -f $file ]]; then
        report "$label: $file does not exist"
        printf '<missing>'
        return
    fi
    value=$(sed -nE "$script" "$file" | head -n 1)
    if [[ -z $value ]]; then
        report "$label: no version found in $file"
        printf '<none>'
        return
    fi
    printf '%s' "$value"
}

toolchain_channel=$(extract \
    "rust-toolchain.toml" \
    's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' \
    "rust-toolchain.toml [toolchain] channel")

mise_version=$(extract \
    ".mise.toml" \
    's/^[[:space:]]*rust[[:space:]]*=.*version[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' \
    ".mise.toml [tools] rust version")

docker_version=$(extract \
    "Dockerfile" \
    's|^FROM rust:([0-9]+\.[0-9]+(\.[0-9]+)?)-.*|\1|p' \
    "Dockerfile chef stage base image")

standard_version=$(extract \
    ".docs/standards/rust.md" \
    's/^\|[[:space:]]*rustc[[:space:]]*\|[[:space:]]*([^|[:space:]]+)[[:space:]]*\|.*/\1/p' \
    ".docs/standards/rust.md toolchain table, rustc row")

# The Dockerfile tag may drop the patch component (`rust:1.98-slim` selects the
# newest 1.98.x). Compare it against the pin truncated to major.minor.
channel_major_minor=${toolchain_channel%.*}

if [[ $mise_version != "$toolchain_channel" ]]; then
    report ".mise.toml names rust $mise_version; rust-toolchain.toml names $toolchain_channel"
fi

if [[ $docker_version != "$toolchain_channel" && $docker_version != "$channel_major_minor" ]]; then
    report "Dockerfile builds on rust:$docker_version; rust-toolchain.toml names $toolchain_channel"
fi

if [[ $standard_version != "$toolchain_channel" ]]; then
    report ".docs/standards/rust.md names rustc $standard_version; rust-toolchain.toml names $toolchain_channel"
fi

# The fuzz crate pins a nightly on purpose. Assert that it still does, so a future
# edit cannot quietly point the fuzz crate at stable, where cargo-fuzz does not run.
fuzz_channel=$(extract \
    "fuzz/rust-toolchain.toml" \
    's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' \
    "fuzz/rust-toolchain.toml [toolchain] channel")

if [[ $fuzz_channel != nightly-* ]]; then
    report "fuzz/rust-toolchain.toml names $fuzz_channel; cargo-fuzz requires a nightly channel"
fi

# `.github/workflows/fuzz.yml` runs `cargo +$FUZZ_TOOLCHAIN`, so its env value must
# be the nightly the fuzz crate pins, or the scheduled fuzz jobs compile on the
# wrong compiler.
workflow_fuzz=$(extract \
    ".github/workflows/fuzz.yml" \
    's/^[[:space:]]*FUZZ_TOOLCHAIN:[[:space:]]*(.+)[[:space:]]*$/\1/p' \
    ".github/workflows/fuzz.yml env FUZZ_TOOLCHAIN")

if [[ $workflow_fuzz != "$fuzz_channel" ]]; then
    report "fuzz.yml FUZZ_TOOLCHAIN is $workflow_fuzz; fuzz/rust-toolchain.toml names $fuzz_channel"
fi

if [[ $fail -eq 0 ]]; then
    printf 'OK: stable pin %s agrees across rust-toolchain.toml, .mise.toml, Dockerfile, and .docs/standards/rust.md\n' \
        "$toolchain_channel"
    printf 'OK: fuzz pin %s agrees across fuzz/rust-toolchain.toml and .github/workflows/fuzz.yml\n' \
        "$fuzz_channel"
    exit 0
fi

cat >&2 <<'EOM'

Raising the Rust version is a deliberate change that touches every location above
together. See the "Rust is pinned" paragraph in CLAUDE.md and
.docs/lessons/pin-the-rust-toolchain-or-ci-drifts-from-local.md.
EOM
exit 1
