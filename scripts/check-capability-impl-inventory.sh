#!/usr/bin/env bash
# check-capability-impl-inventory.sh — freeze the `impl`s of the seven
# production-capability traits that `.docs/specs/17-persistence-and-storage.md`
# §17.17.2 enumerates, the trait registry those capabilities resolve to, and the
# four lists scripts/check-shipped-feature-graph.sh evaluates.
#
# Wrapper around the syn-based test target
# `crates/scp-testing/tests/integration/capability_impl_inventory.rs`. The Rust
# test is the source of truth; this script is the entry point for CI matrices
# and hooks that already invoke the other `scripts/check-*.sh` gates.
#
# WHAT IT DECIDES. The workspace scan and the baseline
# `ratchet/capability-impl-inventory.json` must hold the same records. Any
# difference fails: an impl added, an impl removed, a `gating` that flipped
# between `production` and `testing-gated`, a change to the registered trait
# names, or an entry added to or removed from any of the four lists
# scripts/check-shipped-feature-graph.sh evaluates (its permitted-production
# feature allowlist, its permitted-production crate allowlist, its nullifier
# control features, and its shipped-artifact list).
#
# WHAT IT RECORDS. Only facts about a DEFINITION: the impl item, its trait, its
# type, the file that holds it, and the `cfg` predicates that decide whether a
# production build compiles it. No field records whether production code
# constructs the type —
# `.docs/lessons/ast-gate-checks-definition-not-name-resolution.md` states that
# verifying a use-site property "is reimplementing the compiler's name
# resolution in an AST walker, which is an unbounded arms race and must not be
# attempted."
#
# WHY IT ASKS THE GATE RATHER THAN READING IT. The four frozen lists come from
# `check-shipped-feature-graph.sh --dump-lists`, which prints what bash
# evaluated. Scraping the arrays out of that file's source text instead lets the
# two disagree: a `cat` heredoc ends at its terminator while the surrounding
# command substitution keeps running, so an `echo` after the terminator adds an
# entry no text reader sees.
#
# WHY IDENTITY AND NOT A COUNT. A ratchet that recorded how many impls exist is
# defeated by deleting one implementation and adding another in the same commit,
# which is the swap this gate exists to catch. Recording each impl's identity
# reports that commit as one addition and one removal. The same reasoning moved
# ratchet/block-in-place-count.json from per-crate aggregates to per-file
# entries.
#
# WHY AN ALLOWLIST ENTRY FAILS TOO. An entry on the permitted-production feature
# allowlist is where an author who wants a nullifier feature shipped would put
# it, and an entry on the permitted-production crate allowlist is where an author
# who wants a nullifier-carrying crate shipped would put it, so growth in either
# needs the same human review a new impl needs.
#
# RELATIONSHIP TO THE OTHER TWO MECHANISMS.
#   - scripts/check-capability-nullifiers.sh keys on the SHAPE of a method body:
#     it flags a method that reads neither `self` nor any parameter and still
#     reports success. An author writing a body that reads a parameter and
#     discards the value evades it.
#   - The failure-path tests key on BEHAVIOUR: they demand a typed error from a
#     production arm, which a fake cannot return. They catch a production arm
#     rewritten in place from real to fake.
#   - Neither notices a new, plausible-looking fake ADDED alongside the real
#     implementations. This gate keys on an implementation EXISTING, which a
#     convincing fake cannot evade.
#
# Exit codes mirror cargo test:
#   0 — the workspace's capability-trait impls and the gate's four lists match
#       the baseline
#   1 — at least one differs; read the reported difference, decide whether the
#       implementation belongs on a production path, and record that decision in
#       ratchet/capability-impl-inventory.json
#
# `--self-test` runs only the fixtures — the added impl, the count-preserving
# swap, the removal and the gating flip, the deletion of one of two identical
# impls, the `cfg` evaluator, the type renderer, the `use`-alias scanner, and
# the gate-list reader — so a caller can confirm the ratchet is alive before
# trusting its verdict on the tree.
#
# `--print` prints the workspace's current inventory as the three JSON members
# the baseline carries, so a human updating the baseline reads a diff rather than
# transcribing a hundred records. Printing is not approving: pasting the output
# without reading the diff is the bypass this gate exists to prevent.
#
# DYLD_LIBRARY_PATH is set to libpython for the linker if missing — every
# scp-testing integration test that touches scp-ffi via cargo workspace linkage
# needs this (see project CLAUDE.md "Language-specific gotchas").

set -euo pipefail

if [[ -z "${DYLD_LIBRARY_PATH:-}" ]]; then
    if command -v python3.12 >/dev/null 2>&1; then
        DYLD_LIBRARY_PATH=$(
            python3.12 -c 'import sysconfig; print(sysconfig.get_config_var("LIBDIR"))'
        )
        export DYLD_LIBRARY_PATH
    fi
fi

if [[ "${1:-}" == "--self-test" ]]; then
    shift
    exec cargo test \
        -p scp-testing \
        --test capability_impl_inventory \
        fixture_ \
        "$@"
fi

if [[ "${1:-}" == "--print" ]]; then
    shift
    exec cargo test \
        -p scp-testing \
        --test capability_impl_inventory \
        print_current_inventory \
        "$@" \
        -- --ignored --nocapture
fi

exec cargo test \
    -p scp-testing \
    --test capability_impl_inventory \
    "$@"
