#!/usr/bin/env bash
# generate-uniffi-kotlin.sh — Generate Kotlin bindings from the scp-ffi-uniffi crate.
#
# UniFFI proc-macro binding generation requires the compiled Rust cdylib because
# metadata is embedded at compile time via uniffi::include_scaffolding!. This script
# builds the library then invokes uniffi-bindgen to produce Kotlin source files.
#
# Usage:
#   ./scripts/generate-uniffi-kotlin.sh [--release] [--features=FEAT] [--skip-build] [--print-cargo-args]
#
# --print-cargo-args prints `scp-ffi-uniffi|` followed by the arguments this script
# passes `cargo build` after the manifest path, then exits without building.
# Any other argument fails the script.
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
PRINT_CARGO_ARGS=false
for arg in "$@"; do
    case "$arg" in
        --release) PROFILE="release" ;;
        --features=*) FEATURES="${arg#--features=}" ;;
        --skip-build) SKIP_BUILD=true ;;
        --print-cargo-args) PRINT_CARGO_ARGS=true ;;
        *)
            echo "ERROR: unknown argument: $arg" >&2
            exit 1
            ;;
    esac
done

UNIFFI_CRATE_DIR="$REPO_ROOT/crates/scp-ffi/uniffi"

# CARGO_ARGS[0..2] are `build --manifest-path <manifest>`; step 2 reuses the rest.
CARGO_ARGS=(build --manifest-path "$UNIFFI_CRATE_DIR/Cargo.toml")
if [[ "$PROFILE" == "release" ]]; then
    CARGO_ARGS+=(--release)
fi
if [[ -n "$FEATURES" ]]; then
    CARGO_ARGS+=(--features "$FEATURES")
fi
if [[ "$PRINT_CARGO_ARGS" == "true" ]]; then
    echo "scp-ffi-uniffi|${CARGO_ARGS[*]:3}"
    exit 0
fi
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

# Step 2: Build the uniffi-bindgen binary from the crate, under the profile step 1
# used. Cargo shares no artifact between the debug and release directories, so a
# `--release` step 1 followed by a dev-profile bindgen build compiles the crate graph
# a second time; passing the same profile here compiles the bindgen binary alone.
echo "==> Building uniffi-bindgen tool ($PROFILE)..."
BINDGEN_ARGS=("${CARGO_ARGS[@]:0:3}" --bin uniffi-bindgen "${CARGO_ARGS[@]:3}")
cargo "${BINDGEN_ARGS[@]}"

BINDGEN_BIN="$LIB_DIR/uniffi-bindgen"
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
