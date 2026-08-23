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
#   1. `rust-toolchain.toml`      channel                   — what plain `cargo` resolves to
#   2. `.mise.toml`               rust version              — what a mise shell resolves to
#   3. `Dockerfile`               every `FROM rust:` tag    — the container build, and
#                                 its `FROM debian:` stage, whose Debian release must
#                                 equal the builder's
#   4. `.docs/standards/rust.md`  rustc/cargo/clippy/rustfmt rows — the governing standard
#
# Nightly version — the standalone fuzz crate needs one, and cargo-fuzz does not run
# on stable:
#   5. `fuzz/rust-toolchain.toml`        channel
#   6. `.github/workflows/fuzz.yml`      FUZZ_TOOLCHAIN
#   7. `.github/workflows/ci.yml`        FUZZ_TOOLCHAIN
#
# It also checks two things that file agreement alone does not establish:
#   * `rustc --version` — the compiler a command in this directory actually resolves
#     to. Files agreeing is not compilers agreeing: mise sets `RUSTUP_TOOLCHAIN`, which
#     overrides `rust-toolchain.toml` entirely, so a shell can compile on a different
#     version while every file reads correct. That is the drift this gate exists for.
#   * `.mise.toml` targets ⊇ `rust-toolchain.toml` targets. `RUSTUP_TOOLCHAIN` discards
#     the pin's target list along with its channel, so a target present only in the pin
#     is a cross-build that CI performs and a mise shell cannot.
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

# Read EVERY `FROM rust:` line, not just the first: a second stage on another version
# would otherwise pass unseen.
docker_versions=$(sed -nE 's|^FROM rust:([^ ]+).*|\1|p' Dockerfile 2>/dev/null || true)
if [[ ! -f Dockerfile ]]; then
    report "Dockerfile base image: Dockerfile does not exist"
elif [[ -z $docker_versions ]]; then
    report "Dockerfile base image: no 'FROM rust:<version>' line found in Dockerfile"
fi

# The toolchain table names four tools. Checking only `rustc` would let the clippy row
# — the tool whose version caused the outage — go stale inside the governing standard.
for tool in rustc cargo clippy rustfmt; do
    require "standard_${tool}_version" ".docs/standards/rust.md toolchain table, $tool row" \
        ".docs/standards/rust.md" \
        "s/^\\|[[:space:]]*${tool}[[:space:]]*\\|[[:space:]]*([^|[:space:]]+)[[:space:]]*\\|.*/\\1/p"
done

require fuzz_version "fuzz/rust-toolchain.toml [toolchain] channel" \
    "fuzz/rust-toolchain.toml" \
    's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p'

require fuzz_workflow_version ".github/workflows/fuzz.yml env FUZZ_TOOLCHAIN" \
    ".github/workflows/fuzz.yml" \
    's/^[[:space:]]*FUZZ_TOOLCHAIN:[[:space:]]*([^[:space:]]+)[[:space:]]*$/\1/p'

require ci_workflow_version ".github/workflows/ci.yml env FUZZ_TOOLCHAIN" \
    ".github/workflows/ci.yml" \
    's/^[[:space:]]*FUZZ_TOOLCHAIN:[[:space:]]*([^[:space:]]+)[[:space:]]*$/\1/p'

# Any location that produced no value already set `fail`. Stop here rather than
# compare, because two empty values would otherwise agree with each other.
if [[ $fail -ne 0 ]]; then
    printf '\nEvery location above must name a version before the gate can compare them.\n' >&2
    exit 1
fi

[[ $mise_version == "$pin_version" ]] ||
    report ".mise.toml names rust $mise_version; rust-toolchain.toml names $pin_version"

# Exact equality, including the patch component. A floating tag such as `rust:1.98-slim`
# resolves to the newest 1.98.x, so the day 1.98.1 ships the container would compile on
# a compiler the pin does not name — the drift this gate exists to stop, admitted by the
# gate itself.
while IFS= read -r tag; do
    [[ -n $tag ]] || continue
    base=${tag%%-*}
    [[ $base == "$pin_version" ]] ||
        report "Dockerfile builds on rust:$tag; rust-toolchain.toml names $pin_version"
done <<< "$docker_versions"

# The `FROM rust:` tag selects a Debian release as well as a compiler version, and the
# runtime stage selects one too. glibc is backward compatible only, so a binary the builder
# links against a newer release's glibc cannot exec on an older one, and the runtime
# container dies at startup with "version `GLIBC_2.xx' not found". Requiring the version to
# match leaves that unchecked, because the version is the part of the tag before the first
# hyphen. Require both stages to name a release, and require the names to be equal. An
# unsuffixed `rust:1.98.0-slim` names none, so it follows whichever Debian the rust image
# currently defaults to and changes distribution under the build without the tag changing —
# which is how `rust:1.85-slim` (Debian 12) became `rust:1.98.0-slim` (Debian 13) during
# this pin's own first draft.
builder_suites=$(sed -nE 's|^FROM rust:[^-]+-slim-([a-z]+)[[:space:]].*|\1|p' Dockerfile 2>/dev/null || true)
runtime_suites=$(sed -nE 's|^FROM debian:([a-z]+)-slim[[:space:]].*|\1|p' Dockerfile 2>/dev/null || true)
if [[ -z $builder_suites ]]; then
    report "Dockerfile builder: no 'FROM rust:<version>-slim-<debian-release>' line found; an unsuffixed tag follows whichever Debian the rust image defaults to"
elif [[ -z $runtime_suites ]]; then
    report "Dockerfile runtime: no 'FROM debian:<debian-release>-slim' line found"
else
    while IFS= read -r suite; do
        [[ -n $suite ]] || continue
        grep -qx "$suite" <<< "$runtime_suites" ||
            report "Dockerfile builds on Debian $suite; its runtime stage runs Debian $(tr '\n' ' ' <<< "$runtime_suites")"
    done <<< "$builder_suites"
fi

for tool in rustc cargo clippy rustfmt; do
    var="standard_${tool}_version"
    [[ ${!var} == "$pin_version" ]] ||
        report ".docs/standards/rust.md names $tool ${!var}; rust-toolchain.toml names $pin_version"
done

# File agreement is not compiler agreement. Resolve what a command run in this
# directory actually gets, which is the question every artifact here claims to settle.
if ! command -v rustc >/dev/null 2>&1; then
    report "rustc is not on PATH, so the gate cannot confirm which compiler this directory resolves to"
else
    active_version=$(rustc --version 2>/dev/null | sed -nE 's/^rustc ([0-9]+\.[0-9]+\.[0-9]+).*/\1/p')
    if [[ -z $active_version ]]; then
        report "could not parse 'rustc --version' output, so the active compiler is unknown"
    elif [[ $active_version != "$pin_version" ]]; then
        report "rustc in this directory is $active_version; rust-toolchain.toml names $pin_version.\
 A RUSTUP_TOOLCHAIN environment variable overrides the pin — mise sets one, so run\
 'mise install' after the pin changes, and check with 'mise x -- printenv RUSTUP_TOOLCHAIN'"
    fi
fi

# `.mise.toml` targets must cover the pin's, because RUSTUP_TOOLCHAIN discards the pin's
# target list together with its channel.
pin_targets=$(sed -nE 's/^[[:space:]]*"([a-z0-9_]+-[a-z0-9_.-]+)",?[[:space:]]*$/\1/p' rust-toolchain.toml)
mise_targets=$(sed -nE 's/^[[:space:]]*rust[[:space:]]*=.*targets[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' .mise.toml | tr ',' '\n')
while IFS= read -r t; do
    [[ -n $t ]] || continue
    grep -qx "$t" <<< "$mise_targets" ||
        report ".mise.toml omits target $t, which rust-toolchain.toml lists"
done <<< "$pin_targets"

# The fuzz crate needs a nightly, because cargo-fuzz does not run on stable. Accept
# both the dated form and plain `nightly`: unpinning to `nightly` is the step both
# `fuzz/rust-toolchain.toml` and `.github/workflows/fuzz.yml` prescribe once openmls
# publishes a prelude that the current rules accept, and a gate that rejected the
# unpin it documents would send whoever performs it to a red check reading "nightly
# is not a nightly".
[[ $fuzz_version == nightly || $fuzz_version == nightly-* ]] ||
    report "fuzz/rust-toolchain.toml names $fuzz_version; cargo-fuzz requires a nightly channel"

# `.github/workflows/fuzz.yml` runs `cargo +$FUZZ_TOOLCHAIN`, so its value must be the
# nightly the fuzz crate pins, or the scheduled fuzz jobs compile on the wrong compiler.
[[ $fuzz_workflow_version == "$fuzz_version" ]] ||
    report "fuzz.yml FUZZ_TOOLCHAIN is $fuzz_workflow_version; fuzz/rust-toolchain.toml names $fuzz_version"

[[ $ci_workflow_version == "$fuzz_version" ]] ||
    report "ci.yml FUZZ_TOOLCHAIN is $ci_workflow_version; fuzz/rust-toolchain.toml names $fuzz_version"

if [[ $fail -eq 0 ]]; then
    printf 'OK: stable pin %s agrees across rust-toolchain.toml, .mise.toml, Dockerfile,\n' "$pin_version"
    printf '    .docs/standards/rust.md, the .mise.toml target list, and the active rustc\n'
    printf 'OK: fuzz pin %s agrees across fuzz/rust-toolchain.toml, fuzz.yml, and ci.yml\n' "$fuzz_version"
    exit 0
fi

cat >&2 <<'EOM'

Raising the Rust version is a deliberate change that touches every location above
together. See the "Rust is pinned" paragraph in CLAUDE.md and
.docs/lessons/pin-the-rust-toolchain-or-ci-drifts-from-local.md.
EOM
exit 1
