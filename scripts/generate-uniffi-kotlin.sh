#!/usr/bin/env bash
# generate-uniffi-kotlin.sh — Generate Kotlin bindings from the scp-ffi-uniffi crate.
#
# UniFFI proc-macro binding generation requires the compiled Rust cdylib because
# metadata is embedded at compile time via uniffi::include_scaffolding!. This script
# builds the library then invokes uniffi-bindgen to produce Kotlin source files.
#
# Usage:
#   ./scripts/generate-uniffi-kotlin.sh [--release]
#
# Output:
#   bindings/kotlin/scp-sdk-kotlin/src/main/kotlin/com/limn/scp/internal/
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
if [[ "${1:-}" == "--release" ]]; then
    PROFILE="release"
fi

UNIFFI_CRATE_DIR="$REPO_ROOT/crates/scp-ffi/uniffi"
UDL_FILE="$UNIFFI_CRATE_DIR/src/scp.udl"
OUTPUT_DIR="$REPO_ROOT/bindings/kotlin/scp-sdk-kotlin/src/main/kotlin/com/limn/scp/internal"

# Step 1: Build the Rust cdylib.
echo "==> Building scp-ffi-uniffi ($PROFILE)..."
if [[ "$PROFILE" == "release" ]]; then
    cargo build --manifest-path "$UNIFFI_CRATE_DIR/Cargo.toml" --release
    LIB_DIR="$REPO_ROOT/target/release"
else
    cargo build --manifest-path "$UNIFFI_CRATE_DIR/Cargo.toml"
    LIB_DIR="$REPO_ROOT/target/debug"
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

# Step 2: Build the uniffi-bindgen binary from the crate.
echo "==> Building uniffi-bindgen tool..."
cargo build --manifest-path "$UNIFFI_CRATE_DIR/Cargo.toml" --bin uniffi-bindgen

BINDGEN_BIN="$REPO_ROOT/target/debug/uniffi-bindgen"
if [[ ! -f "$BINDGEN_BIN" ]]; then
    echo "ERROR: uniffi-bindgen binary not found at $BINDGEN_BIN" >&2
    exit 1
fi

# Step 3: Generate Kotlin bindings.
echo "==> Generating Kotlin bindings..."
mkdir -p "$OUTPUT_DIR"

"$BINDGEN_BIN" generate \
    --library "$LIB_FILE" \
    --language kotlin \
    --out-dir "$OUTPUT_DIR"

echo "==> Kotlin bindings generated at:"
find "$OUTPUT_DIR" -name "*.kt" -type f | sort

echo "==> Done."
