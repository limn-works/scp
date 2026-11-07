#!/usr/bin/env bash
# generate-uniffi-kotlin.sh — Generate Kotlin bindings from the scp-ffi-uniffi crate.
#
# UniFFI proc-macro binding generation requires the compiled Rust cdylib because
# metadata is embedded at compile time via uniffi::include_scaffolding!. This script
# builds the library then runs scripts/uniffi-bindgen.sh to produce Kotlin source files.
#
# Usage:
#   ./scripts/generate-uniffi-kotlin.sh [--release] [--features=FEAT] [--skip-build]
#
# Output:
#   bindings/kotlin/scp-kt/src/main/kotlin/works/limn/scp/internal/
#
# Prerequisites:
#   - Rust toolchain (via mise)
#   - cargo build dependencies resolved
#
# See ADR-021 (UniFFI Bridge) and .docs/scaffold/kotlin.md for background.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PROFILE="debug"
FEATURES=""
SKIP_BUILD=false
for arg in "$@"; do
    case "$arg" in
        --release) PROFILE="release" ;;
        --features=*) FEATURES="${arg#--features=}" ;;
        --skip-build) SKIP_BUILD=true ;;
    esac
done

UNIFFI_CRATE_DIR="$REPO_ROOT/crates/scp-ffi/uniffi"
OUTPUT_DIR="$REPO_ROOT/bindings/kotlin/scp-kt/src/main/kotlin/works/limn/scp/internal"

# Cargo writes into the target directory it resolves from `CARGO_TARGET_DIR`, then
# `build.target-dir` in any `.cargo/config.toml` it reads, then `<workspace>/target`.
# A machine whose `~/.cargo/config.toml` points every worktree at one shared directory
# therefore builds the library outside this checkout, so this script asks cargo for the
# directory instead of assuming `$REPO_ROOT/target`. `cargo metadata --no-deps` reads
# the manifests and compiles nothing.
TARGET_DIR=$(cargo metadata --manifest-path "$UNIFFI_CRATE_DIR/Cargo.toml" --format-version 1 --no-deps \
    | sed -nE 's/.*"target_directory":"([^"]*)".*/\1/p')
if [[ -z "$TARGET_DIR" ]]; then
    echo "ERROR: cargo metadata named no target directory for $UNIFFI_CRATE_DIR" >&2
    exit 1
fi
LIB_DIR="$TARGET_DIR/$PROFILE"

# Step 1: Build the Rust cdylib (skip if --skip-build and library exists).
if [[ "$SKIP_BUILD" == "false" ]]; then
    CARGO_ARGS=(build --manifest-path "$UNIFFI_CRATE_DIR/Cargo.toml")
    if [[ "$PROFILE" == "release" ]]; then
        CARGO_ARGS+=(--release)
    fi
    if [[ -n "$FEATURES" ]]; then
        CARGO_ARGS+=(--features "$FEATURES")
    fi
    echo "==> Building scp-ffi-uniffi ($PROFILE)..."
    cargo "${CARGO_ARGS[@]}"
else
    echo "==> Skipping build (--skip-build)"
fi

# Locate the compiled library (platform-dependent name).
if [[ "$(uname)" == "Darwin" ]]; then
    LIB_FILE="$LIB_DIR/libscp_ffi_uniffi.dylib"
elif [[ "$(uname)" == "Linux" ]]; then
    LIB_FILE="$LIB_DIR/libscp_ffi_uniffi.so"
else
    echo "ERROR: Unsupported platform: $(uname)" >&2
    exit 1
fi

if [[ ! -f "$LIB_FILE" ]]; then
    echo "ERROR: Compiled library not found at $LIB_FILE" >&2
    echo "       Build may have failed. Check cargo output above." >&2
    exit 1
fi

# Step 2: Generate Kotlin bindings. scripts/uniffi-bindgen.sh builds the tool from
# tools/uniffi-bindgen, which compiles the `uniffi` crate alone; the tool reads the
# UniFFI metadata symbols out of the library and never loads it.
echo "==> Generating Kotlin bindings..."
mkdir -p "$OUTPUT_DIR"

"$SCRIPT_DIR/uniffi-bindgen.sh" generate \
    --library "$LIB_FILE" \
    --language kotlin \
    --out-dir "$OUTPUT_DIR"

echo "==> Kotlin bindings generated at:"
find "$OUTPUT_DIR" -name "*.kt" -type f | sort

echo "==> Done."
