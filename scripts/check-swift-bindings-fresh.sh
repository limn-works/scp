#!/usr/bin/env bash
# check-swift-bindings-fresh.sh — CI gate enforcing that the checked-in
# UniFFI-generated Swift bindings
# `bindings/swift/Sources/SCP/Internal/ScpBindings.swift` are byte-identical to
# what `uniffi-bindgen` produces from the current `scp-ffi-uniffi` source.
#
# ---------------------------------------------------------------------------
# WHY THIS EXISTS
# ---------------------------------------------------------------------------
# `ScpBindings.swift` is the ONLY checked-in UniFFI-generated artifact — the
# sibling outputs (`Headers/ScpFFI.h`, `Headers/module.modulemap`) are
# gitignored and regenerated on every build. Nothing regenerated the Swift file
# and compared it against the committed copy, so it silently drifted from the
# Rust source.
#
# That drift is NOT cosmetic. UniFFI folds each function's name, signature, and
# doc text into a per-method checksum and emits a guard into the generated
# Swift:
#
#     if (uniffi_scp_ffi_uniffi_checksum_func_identity_resolve() != 39653) {
#         return InitializationResult.apiChecksumMismatch
#     }
#
# Those guards run inside `uniffiCheckApiChecksums()` at SDK initialization and
# a mismatch is a hard `fatalError` — the Swift SDK dies on startup. A stale
# committed artifact therefore ships a Swift SDK that cannot initialize at all,
# and it was invisible to CI because nothing compared the artifact.
#
# This is not hypothetical: when this gate was written the committed copy was
# stale by five methods (`media_activate_session`, `media_end_session`, and
# three `outlet_streaming_saga_*` methods) and carried five checksum literals
# that no longer matched the Rust source — `identity_resolve`,
# `identity_rotation_event_json`, `configure_local_transport`,
# `configure_relay_transport`, and `identity_execute_recovery`. Each of those
# five literals was a `fatalError` the Swift SDK would have raised at
# initialization. The commit that added this gate regenerated the artifact, so
# the gate and the file it compares landed together. This gate closes that
# class.
#
# Note that `swift-build-test` in CI runs `bindings/swift/build-xcframework.sh
# --dev`, which OVERWRITES the committed file before building. That job
# therefore always compiles fresh bindings and can never observe the staleness
# — which is precisely why a dedicated comparison is required.
#
# ---------------------------------------------------------------------------
# WHAT THIS CHECKS
# ---------------------------------------------------------------------------
#   (1) Build the `scp-ffi-uniffi` cdylib. UniFFI proc-macro metadata is
#       embedded at compile time, so the compiled library — not the source
#       text — is the input to binding generation.
#   (2) Run `uniffi-bindgen generate --language swift` against that library
#       into a temporary directory.
#   (3) Assert the generated Swift file is byte-identical to the committed one.
#
# This is a POSITIVE EQUALITY check against the authoritative generator, not a
# denylist of known-bad patterns: any divergence whatsoever — a new method, a
# changed signature, an edited doc comment, a stale checksum — fails the gate.
# It is closed by construction and cannot be outgrown by a new "spelling".
#
# The build uses the crate's default features, exactly matching the production
# invocation in `bindings/swift/build-xcframework.sh` (non-`--dev` mode) that
# produces the shipped artifact. Generation is invariant under the `testing`
# feature — no `#[uniffi::export]` in the crate is `#[cfg(feature = ...)]`-gated
# — so `--dev` builds produce the same Swift source.
#
# ---------------------------------------------------------------------------
# ENFORCEMENT FILE (see CLAUDE.md)
# ---------------------------------------------------------------------------
# Do not weaken this gate to hide drift. The ONLY legitimate fix for a failure
# is to regenerate the bindings and commit the result:
#
#     bindings/swift/build-xcframework.sh --dev   # macOS; rewrites the file
#     git add bindings/swift/Sources/SCP/Internal/ScpBindings.swift
#
# Expanding coverage is always fine.
#
# Usage:
#   bash scripts/check-swift-bindings-fresh.sh              # verify the tree
#   bash scripts/check-swift-bindings-fresh.sh --self-test  # prove the gate
#                                                           # rejects drift
#
# Exit codes:
#   0 — committed bindings match the generator (or self-test passed)
#   1 — committed bindings are stale, or a prerequisite/self-test failed

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

UNIFFI_CRATE_DIR="$REPO_ROOT/crates/scp-ffi/uniffi"
COMMITTED="$REPO_ROOT/bindings/swift/Sources/SCP/Internal/ScpBindings.swift"
TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"

# Bound the diff echoed on failure — a wholesale regeneration can produce
# thousands of lines. The checksum mismatches (the fatal ones) are always
# printed in full below, separately.
DIFF_PREVIEW_LINES=200

die() {
    echo "ERROR: $*" >&2
    exit 1
}

log() {
    echo "==> $*"
}

[[ -f "$UNIFFI_CRATE_DIR/Cargo.toml" ]] \
    || die "scp-ffi-uniffi crate not found at $UNIFFI_CRATE_DIR"
[[ -f "$COMMITTED" ]] \
    || die "committed Swift bindings not found at $COMMITTED"
command -v cargo >/dev/null 2>&1 \
    || die "cargo not found. Install the Rust toolchain."

SELF_TEST=false
case "${1:-}" in
    "") ;;
    --self-test) SELF_TEST=true ;;
    *) die "unknown argument: $1 (usage: $0 [--self-test])" ;;
esac

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# ---------------------------------------------------------------------------
# Step 1: Build the cdylib. UniFFI reads its metadata out of the compiled
# library, so this build is mandatory — the source alone is not enough.
# ---------------------------------------------------------------------------

log "Building scp-ffi-uniffi cdylib (release, default features)"
cargo build --release --manifest-path "$UNIFFI_CRATE_DIR/Cargo.toml"

case "$(uname -s)" in
    Darwin) DYLIB="$TARGET_DIR/release/libscp_ffi_uniffi.dylib" ;;
    Linux)  DYLIB="$TARGET_DIR/release/libscp_ffi_uniffi.so" ;;
    *)      die "unsupported platform: $(uname -s) (expected Darwin or Linux)" ;;
esac

[[ -f "$DYLIB" ]] || die "compiled library not found at $DYLIB (build failed?)"

# ---------------------------------------------------------------------------
# Step 2: Generate Swift bindings into the temp dir. The `generate` arguments
# are the ones `bindings/swift/build-xcframework.sh` passes, which is what
# produces the shipped artifact.
#
# `--release` builds `uniffi-bindgen` into the same profile directory step 1
# just filled, so the two commands share every compiled dependency.
# `build-xcframework.sh` omits it and pays for a second, debug copy of the
# crate graph; the generated Swift is the same either way, because
# `uniffi-bindgen` reads its input out of the library named by `--library` and
# its own optimization level does not reach the output.
# ---------------------------------------------------------------------------

GEN_DIR="$TMP_DIR/uniffi-out"
mkdir -p "$GEN_DIR"

log "Generating Swift bindings via uniffi-bindgen"
cargo run --release --quiet -p scp-ffi-uniffi --bin uniffi-bindgen -- \
    generate \
    --library "$DYLIB" \
    --language swift \
    --out-dir "$GEN_DIR"

# UniFFI names the file after the UDL namespace (`scp.swift`). Rather than
# hardcoding that name, locate it — but require EXACTLY ONE, so a future
# multi-namespace split fails loudly here instead of silently comparing
# against an arbitrary "first" file. Counted portably: macOS ships bash 3.2,
# which has no `mapfile`.
GENERATED_COUNT="$(find "$GEN_DIR" -name '*.swift' -type f | wc -l | tr -d ' ')"
if [[ "$GENERATED_COUNT" -eq 0 ]]; then
    die "uniffi-bindgen produced no .swift file in $GEN_DIR"
fi
if [[ "$GENERATED_COUNT" -gt 1 ]]; then
    echo "ERROR: uniffi-bindgen produced $GENERATED_COUNT .swift files; expected exactly 1:" >&2
    find "$GEN_DIR" -name '*.swift' -type f | sort | sed 's/^/  /' >&2
    echo "  The Swift SDK checks in a single bindings file. If the crate now" >&2
    echo "  emits several, update this gate and build-xcframework.sh together." >&2
    exit 1
fi
GENERATED="$(find "$GEN_DIR" -name '*.swift' -type f)"

# ---------------------------------------------------------------------------
# Step 3: Compare. `report_drift` prints the actionable failure message.
# ---------------------------------------------------------------------------

# bindings_match — quiet byte comparison. Returns 0 when in sync.
bindings_match() {
    cmp -s "$COMMITTED" "$GENERATED"
}

report_drift() {
    local rel="${COMMITTED#"$REPO_ROOT"/}"
    local diff_file="$TMP_DIR/bindings.diff"
    diff -u "$COMMITTED" "$GENERATED" > "$diff_file" || true

    echo "" >&2
    echo "FAIL: checked-in Swift bindings are STALE." >&2
    echo "" >&2
    echo "  File: $rel" >&2
    echo "" >&2
    echo "  It does not match what uniffi-bindgen generates from the current" >&2
    echo "  scp-ffi-uniffi source. The committed copy is the artifact Swift" >&2
    echo "  consumers compile against, so this drift ships to them." >&2
    echo "" >&2

    # Checksum guards are the fatal class: a stale literal here is a hard
    # `fatalError` inside uniffiCheckApiChecksums() at SDK init. Always print
    # every one of them, unabridged.
    local checksum_file="$TMP_DIR/checksum-drift.txt"
    grep -E '^[+-].*_checksum_(func|method|constructor)_' "$diff_file" \
        > "$checksum_file" || true
    if [[ -s "$checksum_file" ]]; then
        echo "  CHECKSUM GUARD MISMATCHES (each one is a fatalError at SDK init):" >&2
        sed 's/^/    /' "$checksum_file" >&2
        echo "" >&2
    fi

    local total
    total="$(wc -l < "$diff_file" | tr -d ' ')"
    if [[ "$total" -gt "$DIFF_PREVIEW_LINES" ]]; then
        echo "  DIFF (committed -> generated; first $DIFF_PREVIEW_LINES of $total lines):" >&2
        head -n "$DIFF_PREVIEW_LINES" "$diff_file" | sed 's/^/    /' >&2
        echo "    ... ($((total - DIFF_PREVIEW_LINES)) more lines suppressed)" >&2
    else
        echo "  DIFF (committed -> generated):" >&2
        sed 's/^/    /' "$diff_file" >&2
    fi

    echo "" >&2
    echo "  TO FIX — regenerate and commit (do NOT hand-edit the bindings):" >&2
    echo "" >&2
    echo "      bindings/swift/build-xcframework.sh --dev" >&2
    echo "      git add $rel" >&2
    echo "" >&2
    echo "  Run that on macOS (it needs xcodebuild/lipo), then re-run this gate." >&2
}

if [[ "$SELF_TEST" == "true" ]]; then
    # Prove the gate is alive rather than a comparison that always passes.
    # Plant a deliberately-corrupted checksum literal in the committed file —
    # the exact drift shape that fatalErrors at SDK init — and confirm the
    # comparison REJECTS it. Then restore and confirm it ACCEPTS the original,
    # so the self-test covers both directions. A trap guarantees restoration
    # even if the check aborts.
    BACKUP="$TMP_DIR/ScpBindings.swift.orig"
    cp "$COMMITTED" "$BACKUP"
    # shellcheck disable=SC2064  # expand paths now: the trap must not depend
    # on variables that could change before it fires.
    trap "cp '$BACKUP' '$COMMITTED'; rm -rf '$TMP_DIR'" EXIT

    # Corrupt the first checksum guard literal by appending a digit. Anchored
    # on the generic guard SHAPE, not on any particular method name, so the
    # self-test does not rot when the exported surface changes.
    if ! grep -qE '_checksum_(func|method|constructor)_[a-z0-9_]+\(\) != [0-9]+\)' "$COMMITTED"; then
        die "self-test anchor not found: no UniFFI checksum guard in $COMMITTED"
    fi
    perl -0pi -e 's/(_checksum_(?:func|method|constructor)_[a-z0-9_]+\(\) != )(\d+)\)/${1}${2}9)/' \
        -- "$COMMITTED"

    if bindings_match; then
        echo "SELF-TEST FAILED: the gate PASSED on a corrupted checksum guard —" >&2
        echo "                  it is not comparing the artifact at all." >&2
        exit 1
    fi

    cp "$BACKUP" "$COMMITTED"

    if ! bindings_match; then
        echo "SELF-TEST FAILED: the gate REJECTED the restored, unmodified tree." >&2
        echo "                  Either restoration broke, or the committed" >&2
        echo "                  bindings are genuinely stale. Run the gate" >&2
        echo "                  without --self-test for the actionable diff." >&2
        exit 1
    fi

    echo "self-test OK: gate REJECTS a corrupted checksum guard and ACCEPTS the clean tree."
    exit 0
fi

if bindings_match; then
    log "OK: ${COMMITTED#"$REPO_ROOT"/} is in sync with uniffi-bindgen output."
    exit 0
fi

report_drift
exit 1
