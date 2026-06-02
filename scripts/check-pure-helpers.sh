#!/usr/bin/env bash
# check-pure-helpers.sh — mechanize ADR-048 §1 ("pure protocol helpers
# stay free fns at FFI Rust layer"). Wrapper around the syn-based test
# `pure_helpers_stay_free_fns_at_ffi_layer` inside
# `crates/scp-testing/tests/integration/ffi_conformance.rs`. The Rust test
# is the source of truth; this script is the entry point for hooks and
# CI matrices that already invoke other `scripts/check-*.sh` gates.
#
# Exit codes mirror cargo test:
#   0 — gate passed (no violations or all violations are in the allowlist)
#   1 — at least one method takes `self` but never uses it; move to a free
#       fn, or add a documented exemption to
#       `scripts/pure-helpers-allowlist.txt`.
#
# DYLD_LIBRARY_PATH is set to libpython for the linker if missing — every
# scp-testing integration test that touches scp-ffi via cargo workspace
# linkage needs this (see project CLAUDE.md "Language-specific gotchas").

set -euo pipefail

if [[ -z "${DYLD_LIBRARY_PATH:-}" ]]; then
    if command -v python3.12 >/dev/null 2>&1; then
        DYLD_LIBRARY_PATH=$(
            python3.12 -c 'import sysconfig; print(sysconfig.get_config_var("LIBDIR"))'
        )
        export DYLD_LIBRARY_PATH
    fi
fi

exec cargo test \
    -p scp-testing \
    --test ffi_conformance \
    pure_helpers_stay_free_fns_at_ffi_layer \
    "$@"
