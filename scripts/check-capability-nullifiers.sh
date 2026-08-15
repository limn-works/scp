#!/usr/bin/env bash
# check-capability-nullifiers.sh — mechanize spec §17.17.2 SCP-CAPSEL-8012
# ("security-nullifier arms MUST be provably absent from shipped production
# artifacts") for the seven provider capabilities
# `.docs/specs/17-persistence-and-storage.md` §17.17.2 enumerates: client
# storage, relay blob storage, DID/DHT resolution, credential storage, key
# custody, device attestation, and the relay querier.
#
# Wrapper around the syn-based test target
# `crates/scp-testing/tests/integration/capability_nullifiers.rs`. The Rust test
# is the source of truth; this script is the entry point for CI matrices and
# hooks that already invoke the other `scripts/check-*.sh` gates.
#
# WHAT IT DECIDES. A capability-trait impl method is flagged when all three of
# these hold: it takes `self` and never reads `self`; it reads none of its other
# parameters and consults no ambient source in their place; and every value it
# can produce constructs `Ok(..)` that is neither an error nor the absent state
# `None`. A method that reads nothing and still reports success asserts an
# outcome it never produced.
#
# WHAT IT DOES NOT DECIDE. Identifier names — `NoOp`, `Noop`, `InMemory`,
# `Stub`, `Fake`, `Dummy` — appear nowhere in the predicate. A name-keyed check
# is defeated by a rename, and the ADR-062 census shows each of those prefixes
# spanning both honest arms and genuine nullifiers. Return-value spellings such
# as `Ok(())` appear nowhere in the predicate either; the detector matches the
# structure of the value path, so `Ok(Default::default())` and a payload bound
# to a local first are flagged the same way.
#
# RELATIONSHIP TO scripts/check-shipped-feature-graph.sh. That gate proves the
# `testing`-gated nullifier arms absent from shipped artifacts. This gate covers
# the UNGATED remainder: an arm nobody gated, in any workspace crate.
#
# Exit codes mirror cargo test:
#   0 — no ungated capability-trait method asserts an outcome it never produced
#   1 — at least one does; make it fail closed (a typed error, or the protocol's
#       absent state), or gate the whole arm behind `feature = "testing"`
#
# `--self-test` runs only the detector's own fixtures — the pinned true positive
# and the pinned false positives — so a caller can confirm the detector is alive
# before trusting its verdict on the tree.
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
        --test capability_nullifiers \
        detector_ \
        "$@"
fi

exec cargo test \
    -p scp-testing \
    --test capability_nullifiers \
    "$@"
