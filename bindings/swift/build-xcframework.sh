#!/usr/bin/env bash
# build-xcframework.sh — Build ScpFFI.xcframework for Apple platforms
#
# Compiles the scp-ffi-uniffi Rust crate for all Apple targets, creates fat
# libraries for simulator and macOS via lipo, and packages everything into an
# XCFramework for SPM distribution. Headers and Swift bindings are generated
# automatically via uniffi-bindgen — no manual prerequisites.
#
# Provenance: SCP-103, .docs/scaffold/swift.md § "XCFramework Build",
#             .docs/adrs/phase-5.md § ADR-026
#
# Usage:
#   ./build-xcframework.sh            # Full build (iOS + macOS)
#   ./build-xcframework.sh --dev      # macOS-only build (fast local testing)
#   ./build-xcframework.sh --clean    # Remove artifacts and rebuild
#
# Prerequisites:
#   - Rust toolchain with Apple targets (auto-installed if missing)
#   - Xcode command-line tools (xcodebuild, lipo)

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

# Output paths
BUILD_DIR="$SCRIPT_DIR/.build-xcframework"
XCFRAMEWORK_OUTPUT="$SCRIPT_DIR/ScpFFI.xcframework"

# Header and bindings output directories
HEADER_DIR="$SCRIPT_DIR/Headers"
HEADER_FILE="$HEADER_DIR/ScpFFI.h"
MODULE_MAP="$HEADER_DIR/module.modulemap"
BINDINGS_DIR="$SCRIPT_DIR/Sources/SCP/Internal"

# UniFFI generation intermediate directory
UNIFFI_OUT_DIR="$BUILD_DIR/uniffi-out"

# ---------------------------------------------------------------------------
# Parse flags
# ---------------------------------------------------------------------------

DEV_MODE=false

for arg in "$@"; do
    case "$arg" in
        --dev)
            DEV_MODE=true
            ;;
        --clean)
            # --clean is handled implicitly (we always clean before building)
            ;;
        *)
            echo "Unknown flag: $arg" >&2
            echo "Usage: $0 [--dev] [--clean]" >&2
            exit 1
            ;;
    esac
done

# Set targets based on mode
if [ "$DEV_MODE" = true ]; then
    ALL_TARGETS=("$TARGET_MACOS_ARM")
    log_mode="dev (macOS arm64 only)"
else
    ALL_TARGETS=(
        "$TARGET_IOS"
        "$TARGET_IOS_SIM_ARM"
        "$TARGET_IOS_SIM_X86"
        "$TARGET_MACOS_ARM"
        "$TARGET_MACOS_X86"
    )
    log_mode="release (all Apple targets)"
fi

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

log "Build mode: $log_mode"
log "Cleaning previous build artifacts"
rm -rf "$XCFRAMEWORK_OUTPUT"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
mkdir -p "$UNIFFI_OUT_DIR"
mkdir -p "$HEADER_DIR"
mkdir -p "$BINDINGS_DIR"

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
# Step 1: Build host dylib for uniffi-bindgen code generation
# ---------------------------------------------------------------------------

log "Building host dylib for uniffi-bindgen (aarch64-apple-darwin)"
cargo build \
    --release \
    --target "$TARGET_MACOS_ARM" \
    --manifest-path "$FFI_CRATE_DIR/Cargo.toml"

HOST_DYLIB="$TARGET_DIR/$TARGET_MACOS_ARM/release/libscp_ffi_uniffi.dylib"
if [ ! -f "$HOST_DYLIB" ]; then
    die "Host dylib not found at $HOST_DYLIB"
fi

# ---------------------------------------------------------------------------
# Step 2: Generate Swift bindings and C header via uniffi-bindgen
# ---------------------------------------------------------------------------

log "Generating Swift bindings and C header via uniffi-bindgen"
cargo run \
    -p scp-ffi-uniffi \
    --bin uniffi-bindgen \
    -- generate \
    --library "$HOST_DYLIB" \
    --language swift \
    --out-dir "$UNIFFI_OUT_DIR"

# UniFFI generates files named after the crate: scp_ffi_uniffi.swift,
# scp_ffi_uniffiFFI.h, scp_ffi_uniffiFFI.modulemap. Rename to match
# project conventions: ScpBindings.swift, ScpFFI.h.
GENERATED_SWIFT=$(find "$UNIFFI_OUT_DIR" -name "*.swift" -type f | head -1)
GENERATED_HEADER=$(find "$UNIFFI_OUT_DIR" -name "*FFI.h" -type f | head -1)
GENERATED_MODULEMAP=$(find "$UNIFFI_OUT_DIR" -name "*.modulemap" -type f | head -1)

if [ -z "$GENERATED_SWIFT" ]; then
    die "uniffi-bindgen did not generate any .swift files"
fi
if [ -z "$GENERATED_HEADER" ]; then
    die "uniffi-bindgen did not generate any FFI.h header"
fi

log "Copying generated bindings"
cp "$GENERATED_SWIFT" "$BINDINGS_DIR/ScpBindings.swift"
cp "$GENERATED_HEADER" "$HEADER_DIR/ScpFFI.h"

# Generate module map for the XCFramework header
log "Generating module.modulemap"
cat > "$MODULE_MAP" <<'MODULEMAP'
framework module ScpFFI {
    umbrella header "ScpFFI.h"
    export *
    module * { export * }
}
MODULEMAP

log "Generated: $BINDINGS_DIR/ScpBindings.swift"
log "Generated: $HEADER_DIR/ScpFFI.h"
log "Generated: $MODULE_MAP"

# ---------------------------------------------------------------------------
# Step 3: Compile Rust for all Apple targets
# ---------------------------------------------------------------------------

log "Compiling scp-ffi-uniffi for ${#ALL_TARGETS[@]} target(s)"

for target in "${ALL_TARGETS[@]}"; do
    # Skip if already built (host target in step 1)
    if [ "$target" = "$TARGET_MACOS_ARM" ]; then
        log "  $target (already built)"
        continue
    fi
    log "  Building for $target"
    cargo build \
        --release \
        --target "$target" \
        --manifest-path "$FFI_CRATE_DIR/Cargo.toml"
done

# ---------------------------------------------------------------------------
# Step 4: Verify static libraries exist
# ---------------------------------------------------------------------------

for target in "${ALL_TARGETS[@]}"; do
    lib_path="$TARGET_DIR/$target/release/$FFI_LIB_NAME"
    if [ ! -f "$lib_path" ]; then
        die "Static library not found at $lib_path"
    fi
done

# ---------------------------------------------------------------------------
# Step 5: Create XCFramework
# ---------------------------------------------------------------------------

if [ "$DEV_MODE" = true ]; then
    # Dev mode: single-slice XCFramework with just macOS arm64
    log "Creating dev XCFramework (macOS arm64 only)"
    xcodebuild -create-xcframework \
        -library "$TARGET_DIR/$TARGET_MACOS_ARM/release/$FFI_LIB_NAME" \
        -headers "$HEADER_DIR" \
        -output "$XCFRAMEWORK_OUTPUT"
else
    # Full build: create fat libraries, then three-slice XCFramework

    # iOS simulator fat library (arm64 + x86_64)
    SIM_FAT_LIB="$BUILD_DIR/libscp_ffi_uniffi_sim.a"
    log "Creating iOS simulator fat library (arm64 + x86_64)"
    lipo -create \
        "$TARGET_DIR/$TARGET_IOS_SIM_ARM/release/$FFI_LIB_NAME" \
        "$TARGET_DIR/$TARGET_IOS_SIM_X86/release/$FFI_LIB_NAME" \
        -output "$SIM_FAT_LIB"

    # macOS fat library (arm64 + x86_64)
    MACOS_FAT_LIB="$BUILD_DIR/libscp_ffi_uniffi_macos.a"
    log "Creating macOS fat library (arm64 + x86_64)"
    lipo -create \
        "$TARGET_DIR/$TARGET_MACOS_ARM/release/$FFI_LIB_NAME" \
        "$TARGET_DIR/$TARGET_MACOS_X86/release/$FFI_LIB_NAME" \
        -output "$MACOS_FAT_LIB"

    # Three-slice XCFramework:
    #   1. iOS device       — aarch64-apple-ios (single arch)
    #   2. iOS simulator    — fat (aarch64-apple-ios-sim + x86_64-apple-ios)
    #   3. macOS            — fat (aarch64-apple-darwin + x86_64-apple-darwin)
    log "Creating ScpFFI.xcframework (3 slices)"
    xcodebuild -create-xcframework \
        -library "$TARGET_DIR/$TARGET_IOS/release/$FFI_LIB_NAME" \
        -headers "$HEADER_DIR" \
        -library "$SIM_FAT_LIB" \
        -headers "$HEADER_DIR" \
        -library "$MACOS_FAT_LIB" \
        -headers "$HEADER_DIR" \
        -output "$XCFRAMEWORK_OUTPUT"
fi

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
