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
#   3. the `FROM` lines of `Dockerfile` and of `templates/personal-relay/README.md` —
#      the two container builds of this workspace's crates — each of which must equal
#      a permitted set written in this gate, so the compiler and the Debian release
#      both change deliberately
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

# Every file in the repository that carries a `FROM rust:` line. `templates/personal-relay`
# is on this list because its README documents a container build of `scp-personal-relay`,
# whose manifest depends on `crates/*` by path — so that tag selects a compiler for this
# workspace's code exactly as the root Dockerfile does, and it shipped naming Rust 1.85,
# which predates the `as_chunks` this workspace now calls.
DOCKERFILES=(
    "Dockerfile"
    "templates/personal-relay/README.md"
)
for f in "${DOCKERFILES[@]}"; do
    [[ -f $f ]] || report "container build: $f does not exist"
done

# Files that carry a line-initial `FROM` and are not container builds of this workspace.
# Listing them keeps the comparison below an equality rather than a subset, so a new
# container build cannot hide among them.
NOT_CONTAINER_BUILDS=()

# The loop above asserts that every listed file exists. On its own that leaves the list
# open in the other direction: a Dockerfile added anywhere in the repository tomorrow
# selects a compiler for this workspace's crates and passes unseen, which is exactly how
# `templates/personal-relay/README.md` shipped naming Rust 1.85. Comparing the two sets
# makes a new container build fail this gate the day it lands rather than the morning the
# pin moves.
#
# WHAT THIS SEARCH DOES NOT COVER, stated rather than implied: it matches a line-initial,
# uppercase `FROM`, which is how every container file in this repository writes it and how
# Docker's own documentation writes it. Docker also accepts a lowercase `from` and leading
# whitespace, so a new container file written that way would not be discovered here. The
# byte-exact comparison below has no such gap — it rejects every spelling that is not a
# permitted line — but it only runs on files this search finds.
# `--untracked` matters: a container build added but not yet committed is exactly the case
# a pre-commit or pre-push run has to catch, and plain `git grep` searches only the index.
# Match `rust` with or without a tag, indented or not, in either case, so a file the
# whitelist above would reject cannot escape by not being looked at.
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    report "not inside a git working tree, so the gate cannot search for unlisted container builds"
else
    # Match a line-initial `FROM` and let the declared list below decide which of those
    # files is a container build, rather than pattern-matching the image name — a name
    # admits `rustlang/rust`, `docker.io/library/rust`, a bare `rust`, and a line
    # continuation, each of which defeated an earlier version of this search.
    #
    # This file is excluded because `expected_from_lines` below necessarily contains the
    # permitted `FROM` lines verbatim; it declares them rather than building on them.
    discovered=$(git grep -l --untracked -E '^FROM[[:space:]]' \
        -- . ':!scripts/check-toolchain-pin.sh' | sort)
    # bash 3.2 — the version macOS ships — treats an empty array expansion as an unbound
    # variable under `set -u`, so expand the second list only when it has members.
    listed=$(printf '%s\n' "${DOCKERFILES[@]}" \
        ${NOT_CONTAINER_BUILDS[@]+"${NOT_CONTAINER_BUILDS[@]}"} | sed '/^$/d' | sort)
    if [[ $discovered != "$listed" ]]; then
        unlisted=$(comm -23 <(printf '%s\n' "$discovered") <(printf '%s\n' "$listed") | tr '\n' ' ')
        [[ -z ${unlisted// /} ]] ||
            report "these files carry a line-initial 'FROM' and neither DOCKERFILES nor NOT_CONTAINER_BUILDS names them: $unlisted"
    fi
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
    's/^[[:space:]]*FUZZ_TOOLCHAIN:[[:space:]]*"?([^"[:space:]]+)"?[[:space:]]*$/\1/p'

require ci_workflow_version ".github/workflows/ci.yml env FUZZ_TOOLCHAIN" \
    ".github/workflows/ci.yml" \
    's/^[[:space:]]*FUZZ_TOOLCHAIN:[[:space:]]*"?([^"[:space:]]+)"?[[:space:]]*$/\1/p'

# A job-level `env:` block overrides the workflow-level one for that job's steps, and the
# extraction above reads the first definition in the file. Requiring exactly one definition
# per workflow keeps the value the gate compares equal to the value every job resolves.
for wf in .github/workflows/fuzz.yml .github/workflows/ci.yml; do
    [[ -f $wf ]] || continue
    count=$(grep -cE '^[[:space:]]*FUZZ_TOOLCHAIN:' "$wf" || true)
    [[ $count -eq 1 ]] ||
        report "$wf defines FUZZ_TOOLCHAIN $count times; a job-level env block overrides the workflow-level one, and the gate reads only the first"
done

# Any location that produced no value already set `fail`. Stop here rather than
# compare, because two empty values would otherwise agree with each other.
if [[ $fail -ne 0 ]]; then
    printf '\nEvery location above must name a version before the gate can compare them.\n' >&2
    exit 1
fi

[[ $mise_version == "$pin_version" ]] ||
    report ".mise.toml names rust $mise_version; rust-toolchain.toml names $pin_version"

# Read EVERY `FROM rust:` line in every file on the list, not just the first: a second
# stage on another version would otherwise pass unseen. Require exact equality including
# the patch component, because a floating tag such as `rust:1.98-slim` resolves to the
# newest 1.98.x, so the day 1.98.1 ships the container would compile on a compiler the pin
# does not name — the drift this gate exists to stop, admitted by the gate itself.
# CONTAINER BUILDS — a positive whitelist, not a parser.
#
# Three review rounds each found one more legal Dockerfile spelling this check mishandled:
# an indented `FROM`, a lowercase one, an untagged `FROM rust`, a registry-qualified image,
# and a second stage whose tag named no Debian release. Docker's `FROM` grammar admits many
# spellings of one image, so validating them by pattern is an open-ended denylist, and
# CLAUDE.md's guard against non-convergent enforcement asks for the opposite shape: a
# positive whitelist of permitted forms, closed by construction.
#
# So each container file declares the exact set of `FROM` lines it may contain, with the
# pinned version substituted for @PIN@. The gate compares that set against the file, in
# both directions; `expected_from_lines` below holds those declarations. Every spelling
# above fails, because none of them is a listed line, and
# the fix for a legitimate change is to update the expected set here — which is what makes
# changing a container's compiler or Debian release a deliberate act rather than a silent
# one.
#
# The two files are on the list for the same reason: each documents a container build of
# this workspace's crates. `templates/personal-relay/README.md` depends on `crates/*` by
# path, so its tag selects a compiler for this workspace exactly as the root Dockerfile's
# does, and it shipped naming Rust 1.85 — which predates the `as_chunks` this workspace
# calls.
#
# Every builder stage and every runtime stage names the same Debian release on purpose.
# glibc is backward compatible only, so a binary the builder links against a newer
# release's glibc cannot exec on an older one, and the runtime container dies at startup
# with "version `GLIBC_2.xx' not found". `rust:1.85-slim` was a Debian 12 image and
# `rust:1.98.0-slim` is a Debian 13 one, so a tag naming no release changes distribution
# under the build without the tag changing; naming the release in every line closes that.
expected_from_lines() {
    case $1 in
        Dockerfile)
            cat <<EOF
FROM rust:@PIN@-slim-bookworm AS chef
FROM chef AS planner
FROM chef AS builder
FROM debian:bookworm-slim AS runtime
EOF
            ;;
        templates/personal-relay/README.md)
            cat <<EOF
FROM rust:@PIN@-bookworm AS builder
FROM debian:bookworm-slim
EOF
            ;;
        *)
            return 1
            ;;
    esac
}

for f in "${DOCKERFILES[@]}"; do
    [[ -f $f ]] || continue
    if ! expected=$(expected_from_lines "$f"); then
        report "$f is listed in DOCKERFILES but expected_from_lines does not describe it"
        continue
    fi
    expected=${expected//@PIN@/$pin_version}
    # Case-insensitive and whitespace-tolerant on the way IN, so a lowercase or indented
    # `from` line still lands in the comparison; the expected set is written one way, so
    # any other spelling differs from it and fails.
    actual=$(grep -iE '^[[:space:]]*FROM[[:space:]]' "$f" || true)
    if [[ $actual != "$expected" ]]; then
        report "$f: its 'FROM' lines are not the permitted set for pin $pin_version.
  expected:
$(sed 's/^/    /' <<< "$expected")
  found:
$(sed 's/^/    /' <<< "${actual:-<none>}")
  Change a container's compiler or Debian release by editing expected_from_lines in this
  gate at the same time, so the change is deliberate."
    fi
done

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
    # Capture the status rather than letting `set -e` abort the assignment: a rustc that
    # exits non-zero — rustup failing to fetch the pinned toolchain, most likely — would
    # otherwise kill the gate with rustc's own status and print nothing at all.
    if ! raw_rustc=$(rustc --version 2>&1); then
        report "'rustc --version' failed, so the active compiler is unknown: $raw_rustc"
        raw_rustc=""
    fi
    active_version=$(sed -nE 's/^rustc ([0-9]+\.[0-9]+\.[0-9]+).*/\1/p' <<< "$raw_rustc")
    if [[ -z $raw_rustc ]]; then
        : # already reported
    elif [[ -z $active_version ]]; then
        report "could not parse 'rustc --version' output, so the active compiler is unknown"
    elif [[ $active_version != "$pin_version" ]]; then
        report "rustc in this directory is $active_version; rust-toolchain.toml names $pin_version.\
 A RUSTUP_TOOLCHAIN environment variable overrides the pin — mise sets one, so run\
 'mise install' after the pin changes, and check with 'mise x -- printenv RUSTUP_TOOLCHAIN'"
    fi
fi

# `.mise.toml` targets must cover the pin's, because RUSTUP_TOOLCHAIN discards the pin's
# target list together with its channel.
# Read the whole `targets = [ .. ]` array, however it is wrapped: TOML accepts it inline on
# one line or spread over several, and matching quoted strings line by line reads nothing
# from the inline form and then passes. Strip comments first, so a commented-out or
# illustrative array later in the file cannot become the one the check reads. Fail closed
# when either list is absent.
pin_targets=$(sed 's/#.*//' rust-toolchain.toml | tr '\n' ' ' |
    sed -nE 's/.*targets[[:space:]]*=[[:space:]]*\[([^]]*)\].*/\1/p' |
    tr ',' '\n' | sed -nE 's/[^"]*"([^"]+)".*/\1/p')
mise_targets=$(sed -nE 's/^[[:space:]]*rust[[:space:]]*=.*targets[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' .mise.toml |
    tr ',' '\n' | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')
if [[ -z $pin_targets ]]; then
    report "rust-toolchain.toml: no 'targets = [ .. ]' array found, so the gate cannot check that .mise.toml covers it"
elif [[ -z $mise_targets ]]; then
    report ".mise.toml: no 'targets = \"..\"' list found on the rust entry"
else
    while IFS= read -r t; do
        [[ -n $t ]] || continue
        grep -qx "$t" <<< "$mise_targets" ||
            report ".mise.toml omits target $t, which rust-toolchain.toml lists"
    done <<< "$pin_targets"
fi

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
