#!/usr/bin/env bash
# scripts/android-linkers.sh — Android NDK cross-compilation linkers for Cargo
#
# Sourced by mise via _.source in .mise.toml. Sets CARGO_TARGET_*_LINKER
# env vars so `cargo build --target <android-triple>` works without extra flags.

if [[ -d "${ANDROID_NDK_HOME:-}" ]]; then
  _ndk_toolchain="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt"

  case "$(uname -s)" in
    Darwin) _ndk_host="darwin-x86_64" ;;
    *)      _ndk_host="linux-x86_64"  ;;
  esac

  _ndk_bin="$_ndk_toolchain/$_ndk_host/bin"

  if [[ -d "$_ndk_bin" ]]; then
    export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$_ndk_bin/aarch64-linux-android21-clang"
    export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER="$_ndk_bin/armv7a-linux-androideabi21-clang"
    export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$_ndk_bin/x86_64-linux-android21-clang"
    export CARGO_TARGET_I686_LINUX_ANDROID_LINKER="$_ndk_bin/i686-linux-android21-clang"
  fi

  unset _ndk_toolchain _ndk_host _ndk_bin
fi
