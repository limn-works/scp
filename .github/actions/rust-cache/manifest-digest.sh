#!/usr/bin/env bash
# Prints one SHA-256 digest of the Cargo.toml at the root of each workspace named on the
# command line, after dropping the text that changes no compiled artifact or that
# Cargo.lock already keys. action.yml beside this file puts the digest into the
# Swatinem/rust-cache key.
#
# WHY: Swatinem/rust-cache keys an entry on `rustc -vV`, every CARGO*/RUST* variable its
# step sees, `.cargo/config.toml` and `rust-toolchain(.toml)` at any depth, Cargo.lock,
# and the Cargo.toml of each workspace member. A virtual manifest is no member, so the
# root Cargo.toml of this repository, which holds every `[profile.*]` table, every
# `[workspace.dependencies]` feature list and `[patch.crates-io]`, reached no key. When a
# change to it merged, every job restored an entry compiled under the old profile, cargo
# rebuilt each dependency, and the entry was never re-saved because its key still matched
# in full: after `[profile.dev.package."*"] opt-level = 1` merged, merge_group run
# 41477746543 compiled 300 to 660 registry crates per job and took 13.0 minutes against
# 6.8 minutes in run 41465335098 before it.
#
# DROPPED, each with the reason it cannot change an artifact the cache holds:
#   - blank lines and lines that are only a comment;
#   - `[workspace.lints.*]` and `[lints.*]` tables: lint levels reach only workspace
#     members, and rust-cache deletes members' artifacts before it saves;
#   - `[workspace.metadata.*]` and `[package.metadata.*]` tables, which cargo ignores;
#   - in `[package]`, `[workspace.package]` and every dependency table, the `version`
#     value and a dependency's version string: Cargo.lock, which rust-cache hashes,
#     records the version every requirement resolved to. Keeping a version bump out of
#     this digest keeps rust-cache's partial restore from the previous entry, because the
#     restore key ends before the Cargo.lock hash and this digest sits before it.
# Everything else stays, so a section added to Cargo.toml later is keyed until someone
# shows it changes no artifact.
#
# Usage: manifest-digest.sh <workspace root>...
# Exit 1 when a root holds no Cargo.toml or no SHA-256 tool exists, so the cache step
# fails rather than restoring under a key that omits the manifest.
set -euo pipefail

if (($# == 0)); then
    echo "manifest-digest.sh: name at least one workspace root" >&2
    exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
    sha256() { sha256sum | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
    sha256() { shasum -a 256 | cut -d' ' -f1; }
else
    echo "manifest-digest.sh: neither sha256sum nor shasum is installed" >&2
    exit 1
fi

normalize() {
    awk '
        /^[ \t]*\[/ {
            header = $0
            sub(/^[ \t]*\[+[ \t]*/, "", header)
            sub(/[ \t]*\]+.*$/, "", header)
            skip = header ~ /^(workspace\.)?lints(\.|$)/ || header ~ /^(workspace|package)\.metadata(\.|$)/
            deps = header ~ /(^|\.)((dev|build)-)?dependencies$/
            subdep = header ~ /(^|\.)((dev|build)-)?dependencies\.[^.]+$/
            pkg = header ~ /^(workspace\.)?package$/
            if (!skip) print
            next
        }
        skip { next }
        /^[ \t]*(#.*)?$/ { next }
        (pkg || subdep) && /^[ \t]*version[ \t]*=/ { next }
        deps {
            line = $0
            if (line ~ /^[ \t]*[A-Za-z0-9_.-]+[ \t]*=[ \t]*"[^"]*"/) {
                sub(/=[ \t]*"[^"]*"/, "= \"\"", line)
            }
            gsub(/version[ \t]*=[ \t]*"[^"]*"[ \t]*,?[ \t]*/, "", line)
            print line
            next
        }
        { print }
    ' "$1"
}

for root in "$@"; do
    if [[ ! -f ${root%/}/Cargo.toml ]]; then
        echo "manifest-digest.sh: ${root%/}/Cargo.toml does not exist" >&2
        exit 1
    fi
done

for root in "$@"; do
    printf '==\n'
    normalize "${root%/}/Cargo.toml"
done | sha256
