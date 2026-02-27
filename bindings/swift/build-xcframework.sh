#!/usr/bin/env bash
# build-xcframework.sh — Build ScpFFI.xcframework for Apple platforms
#
# Compiles the scp-ffi-uniffi Rust crate for all Apple targets, creates fat
# libraries for simulator and macOS via lipo, and packages everything into an
# XCFramework for SPM distribution.
#
# Provenance: SCP-103, .docs/scaffold/swift.md § "XCFramework Build",
#             .docs/adrs/phase-5.md § ADR-026
#
# Usage:
#   ./build-xcframework.sh            # Build from bindings/swift/
#   ./build-xcframework.sh --clean    # Remove artifacts and rebuild
#
# Prerequisites:
#   - Rust toolchain with targets: aarch64-apple-ios, aarch64-apple-ios-sim,
#     x86_64-apple-ios, aarch64-apple-darwin, x86_64-apple-darwin
#   - Xcode command-line tools (xcodebuild, lipo)
#   - UniFFI-generated header at $HEADER_DIR/ScpFFI.h (see below)

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Repository root (two levels up from bindings/swift/)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Rust crate that produces the static library
FFI_CRATE_DIR="$REPO_ROOT/crates/scp-ffi/uniffi"
FFI_LIB_NAME="libscp_ffi_uniffi.a"

# Cargo target directory (respect CARGO_TARGET_DIR if set)
TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"

# Apple targets
TARGET_IOS="aarch64-apple-ios"
TARGET_IOS_SIM_ARM="aarch64-apple-ios-sim"
TARGET_IOS_SIM_X86="x86_64-apple-ios"
TARGET_MACOS_ARM="aarch64-apple-darwin"
TARGET_MACOS_X86="x86_64-apple-darwin"

ALL_TARGETS=(
    "$TARGET_IOS"
    "$TARGET_IOS_SIM_ARM"
    "$TARGET_IOS_SIM_X86"
    "$TARGET_MACOS_ARM"
    "$TARGET_MACOS_X86"
)

# Output paths
BUILD_DIR="$SCRIPT_DIR/.build-xcframework"
XCFRAMEWORK_OUTPUT="$SCRIPT_DIR/ScpFFI.xcframework"

# Header directory — UniFFI's bindgen generates ScpFFI.h here.
# If the header does not exist yet, the script will fail with a clear message.
# Generate it with: cargo run -p scp-ffi-uniffi --bin uniffi-bindgen -- generate \
#   --library target/release/libscp_ffi_uniffi.a --language swift --out-dir <dir>
HEADER_DIR="$SCRIPT_DIR/Headers"
HEADER_FILE="$HEADER_DIR/ScpFFI.h"
MODULE_MAP="$HEADER_DIR/module.modulemap"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log() {
    echo "==> $*"
}

die() {
    echo "ERROR: $*" >&2
    exit 1
}

# ---------------------------------------------------------------------------
# Clean previous artifacts (idempotent rebuild)
# ---------------------------------------------------------------------------

log "Cleaning previous build artifacts"
rm -rf "$XCFRAMEWORK_OUTPUT"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# ---------------------------------------------------------------------------
# Verify prerequisites
# ---------------------------------------------------------------------------

command -v cargo >/dev/null 2>&1 || die "cargo not found. Install the Rust toolchain."
command -v xcodebuild >/dev/null 2>&1 || die "xcodebuild not found. Install Xcode command-line tools."
command -v lipo >/dev/null 2>&1 || die "lipo not found. Install Xcode command-line tools."

# Verify all Rust targets are installed
for target in "${ALL_TARGETS[@]}"; do
    if ! rustup target list --installed | grep -q "^${target}$"; then
        log "Installing missing Rust target: $target"
        rustup target add "$target"
    fi
done

# ---------------------------------------------------------------------------
# Verify header file exists
# ---------------------------------------------------------------------------

if [ ! -f "$HEADER_FILE" ]; then
    die "Header file not found at $HEADER_FILE
UniFFI generates this header via bindgen. To create it:

  1. Build the FFI crate for any target first:
     cargo build --release -p scp-ffi-uniffi

  2. Generate Swift bindings + header:
     cargo run -p scp-ffi-uniffi --bin uniffi-bindgen -- generate \\
       --library $TARGET_DIR/release/libscp_ffi_uniffi.a \\
       --language swift --out-dir $HEADER_DIR

  3. Ensure ScpFFI.h and module.modulemap exist in $HEADER_DIR

Then re-run this script."
fi

if [ ! -f "$MODULE_MAP" ]; then
    # Generate a minimal module map if one doesn't exist alongside the header
    log "Generating module.modulemap"
    cat > "$MODULE_MAP" <<'MODULEMAP'
framework module ScpFFI {
    umbrella header "ScpFFI.h"
    export *
    module * { export * }
}
MODULEMAP
fi

# ---------------------------------------------------------------------------
# Step 1: Compile Rust for all Apple targets
# ---------------------------------------------------------------------------

log "Compiling scp-ffi-uniffi for all Apple targets"

for target in "${ALL_TARGETS[@]}"; do
    log "  Building for $target"
    cargo build \
        --release \
        --target "$target" \
        --manifest-path "$FFI_CRATE_DIR/Cargo.toml"
done

# ---------------------------------------------------------------------------
# Step 2: Verify static libraries exist
# ---------------------------------------------------------------------------

for target in "${ALL_TARGETS[@]}"; do
    lib_path="$TARGET_DIR/$target/release/$FFI_LIB_NAME"
    if [ ! -f "$lib_path" ]; then
        die "Static library not found at $lib_path"
    fi
done

# ---------------------------------------------------------------------------
# Step 3: Create iOS simulator fat library (arm64 + x86_64)
# ---------------------------------------------------------------------------

SIM_FAT_LIB="$BUILD_DIR/libscp_ffi_uniffi_sim.a"

log "Creating iOS simulator fat library (arm64 + x86_64)"
lipo -create \
    "$TARGET_DIR/$TARGET_IOS_SIM_ARM/release/$FFI_LIB_NAME" \
    "$TARGET_DIR/$TARGET_IOS_SIM_X86/release/$FFI_LIB_NAME" \
    -output "$SIM_FAT_LIB"

# ---------------------------------------------------------------------------
# Step 4: Create macOS fat library (arm64 + x86_64)
# ---------------------------------------------------------------------------

MACOS_FAT_LIB="$BUILD_DIR/libscp_ffi_uniffi_macos.a"

log "Creating macOS fat library (arm64 + x86_64)"
lipo -create \
    "$TARGET_DIR/$TARGET_MACOS_ARM/release/$FFI_LIB_NAME" \
    "$TARGET_DIR/$TARGET_MACOS_X86/release/$FFI_LIB_NAME" \
    -output "$MACOS_FAT_LIB"

# ---------------------------------------------------------------------------
# Step 5: Create XCFramework with all three slices + headers
#
# Slices:
#   1. iOS device       — aarch64-apple-ios (single arch)
#   2. iOS simulator    — fat library (aarch64-apple-ios-sim + x86_64-apple-ios)
#   3. macOS            — fat library (aarch64-apple-darwin + x86_64-apple-darwin)
#
# Each slice includes the same header directory for the C interface.
# ---------------------------------------------------------------------------

log "Creating ScpFFI.xcframework"
xcodebuild -create-xcframework \
    -library "$TARGET_DIR/$TARGET_IOS/release/$FFI_LIB_NAME" \
    -headers "$HEADER_DIR" \
    -library "$SIM_FAT_LIB" \
    -headers "$HEADER_DIR" \
    -library "$MACOS_FAT_LIB" \
    -headers "$HEADER_DIR" \
    -output "$XCFRAMEWORK_OUTPUT"

# ---------------------------------------------------------------------------
# Step 6: Clean up intermediate build directory
# ---------------------------------------------------------------------------

rm -rf "$BUILD_DIR"

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

log "ScpFFI.xcframework created at $XCFRAMEWORK_OUTPUT"
log "Contents:"
ls -la "$XCFRAMEWORK_OUTPUT"
