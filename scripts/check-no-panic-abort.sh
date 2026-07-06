#!/usr/bin/env bash
# check-no-panic-abort.sh — CI gate forbidding `panic = "abort"` in any cargo
# profile that reaches the FFI cdylib crates.
#
# ---------------------------------------------------------------------------
# WHY THIS EXISTS
# ---------------------------------------------------------------------------
# The three FFI bridges are compiled as `cdylib`s loaded into a host runtime:
#
#   crates/scp-ffi/        (scp-ffi        — PyO3,  loaded by CPython)
#   crates/scp-ffi/napi/   (scp-ffi-napi   — napi,  loaded by Node/Bun)
#   crates/scp-ffi/uniffi/ (scp-ffi-uniffi — UniFFI, loaded by Swift/Kotlin)
#
# PyO3, napi-rs, and UniFFI all catch a Rust `panic!` at the FFI boundary (via
# stack UNWINDING) and convert it into a host-language exception. With the
# `abort` panic strategy there is no unwinding: any panic — including one the
# host was expected to catch and surface as an exception — instead raises
# SIGABRT and kills the ENTIRE host process (the Python interpreter, the Node
# event loop, the Swift/Kotlin app). That is both a reliability regression and
# a denial-of-service amplifier (a single bad input that would have been a
# catchable exception becomes a whole-process crash). `panic = "abort"` on a
# profile that builds these cdylibs is therefore banned.
#
# ---------------------------------------------------------------------------
# WHAT THIS CHECKS (bounded, sound, closed)
# ---------------------------------------------------------------------------
# Cargo honors `[profile.*]` tables ONLY in the workspace-root manifest; a
# top-level `[profile.<name>] panic = "abort"` there applies to EVERY member,
# including the FFI cdylibs. (`panic` is not a valid per-package profile
# override key — cargo rejects it — so a root-level profile is the only way to
# flip the strategy for these crates.) A member manifest's own `[profile.*]`
# is ignored by cargo with a warning, but a `panic = "abort"` written there
# signals the same mistaken intent, so we flag it too as defense-in-depth.
#
# The scan is a CLOSED set of at most four manifests:
#   - Cargo.toml                         (workspace root — authoritative)
#   - crates/scp-ffi/Cargo.toml          (scp-ffi)
#   - crates/scp-ffi/napi/Cargo.toml     (scp-ffi-napi)
#   - crates/scp-ffi/uniffi/Cargo.toml   (scp-ffi-uniffi)
#
# and a single exact pattern: a non-comment line reading `panic = "abort"`
# (value `abort`, single or double quotes, arbitrary surrounding whitespace).
# `panic = "abort"` is only valid TOML inside a `[profile.*]` table, so a
# match anywhere in these manifests is unambiguously a forbidden profile
# setting — no TOML section parsing is needed. The clippy lint
# `panic = "deny"` (a different value, under `[workspace.lints.clippy]`) does
# not match; a `#`-commented line does not match.
#
# This is NOT an open-ended denylist: it is a fixed file list matched against
# one exact forbidden shape.
#
# ---------------------------------------------------------------------------
# WHEN THIS RUNS
# ---------------------------------------------------------------------------
# On every PR (cheap, no build). It is ADDITIVE coverage — it does not replace
# or weaken any existing enforcement script.
#
# ---------------------------------------------------------------------------
# HOW TO FIX A FAILURE
# ---------------------------------------------------------------------------
# Remove the `panic = "abort"` setting. If a smaller binary or slightly faster
# release build motivated it, it cannot apply workspace-wide while the FFI
# cdylibs must unwind. Keep the default `unwind` strategy for any profile that
# builds scp-ffi / scp-ffi-napi / scp-ffi-uniffi.
#
# ---------------------------------------------------------------------------
# SELF-TEST
# ---------------------------------------------------------------------------
# `check-no-panic-abort.sh --self-test` proves the detector is alive: it plants
# `panic = "abort"` in a scratch manifest (must be DETECTED), and confirms that
# benign lines — `panic = "unwind"`, the clippy lint `panic = "deny"`, and a
# commented `# panic = "abort"` — are NOT detected. It touches only a temp dir
# and reverts itself. CI runs the self-test before the real check.
set -euo pipefail

# Anchor at the repository root so the relative manifest paths below are
# invocation-directory-independent (works from any subdirectory).
cd "$(git rev-parse --show-toplevel)"

# Closed set of manifests whose profiles can reach the FFI cdylibs.
MANIFESTS=(
    "Cargo.toml"
    "crates/scp-ffi/Cargo.toml"
    "crates/scp-ffi/napi/Cargo.toml"
    "crates/scp-ffi/uniffi/Cargo.toml"
)

# The single forbidden shape: a non-comment line setting the profile panic
# strategy to "abort". Anchored at line start (after optional whitespace) so a
# `#`-commented occurrence does not match; the value is pinned to `abort` so
# the `panic = "deny"` clippy lint and a `panic = "unwind"` override do not
# match.
ABORT_RE='^[[:space:]]*panic[[:space:]]*=[[:space:]]*["'"'"']abort["'"'"']'

# scan_manifest FILE
#   Prints `FILE:LINENO:CONTENT` for every forbidden line; returns 0 if any
#   were found, 1 if clean. Absent files are treated as clean (a bridge
#   manifest could be relocated).
scan_manifest() {
    local file="$1"
    [[ -f "$file" ]] || return 1
    grep -nE "$ABORT_RE" "$file" | sed "s#^#${file}:#" && return 0
    return 1
}

# run_check FILE...
#   Scans every FILE argument; returns 1 if any forbidden line was found, 0 if
#   all clean. (Written for the macOS system bash 3.2 — no namerefs.)
run_check() {
    local found=0
    local file
    for file in "$@"; do
        if scan_manifest "$file"; then
            found=1
        fi
    done
    return "$found"
}

self_test() {
    echo "check-no-panic-abort self-test..."
    local tmp rc=0
    tmp="$(mktemp -d)"

    # Fixture 1: a profile with panic = "abort" — MUST be detected.
    cat >"$tmp/bad.toml" <<'EOF'
[profile.release]
panic = "abort"
EOF
    if scan_manifest "$tmp/bad.toml" >/dev/null; then
        echo "  [ok] detected panic = \"abort\""
    else
        echo "  [FAIL] self-test: forbidden panic = \"abort\" was NOT detected" >&2
        rc=1
    fi

    # Fixture 2: benign lines — none MUST be detected.
    cat >"$tmp/good.toml" <<'EOF'
[profile.release]
panic = "unwind"

[workspace.lints.clippy]
panic = "deny"

# panic = "abort"   (a comment, not a setting)
EOF
    if scan_manifest "$tmp/good.toml" >/dev/null; then
        echo "  [FAIL] self-test: a benign line was falsely detected:" >&2
        scan_manifest "$tmp/good.toml" >&2 || true
        rc=1
    else
        echo "  [ok] benign panic = \"unwind\" / \"deny\" / comment not flagged"
    fi

    rm -rf "$tmp"
    if [[ "$rc" -eq 0 ]]; then
        echo "check-no-panic-abort self-test PASSED"
    fi
    return "$rc"
}

main() {
    if [[ "${1:-}" == "--self-test" ]]; then
        self_test
        return
    fi

    echo "Checking for forbidden panic = \"abort\" in FFI-reachable cargo profiles..."
    if run_check "${MANIFESTS[@]}"; then
        echo "check-no-panic-abort: OK (no panic = \"abort\" in FFI-reachable profiles)"
        return 0
    fi

    cat >&2 <<'EOF'

ERROR: `panic = "abort"` found in a cargo profile that reaches the FFI cdylib
crates (scp-ffi / scp-ffi-napi / scp-ffi-uniffi). The `abort` strategy turns
any Rust panic into a whole-host-process SIGABRT instead of a host-language
exception at the FFI boundary. Remove it and keep the default `unwind`
strategy. See the header of scripts/check-no-panic-abort.sh.
EOF
    return 1
}

main "$@"
