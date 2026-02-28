#!/usr/bin/env bash
# scripts/env.sh — Sourceable environment for SCP local development
#
# Usage:
#   source scripts/env.sh
#
# Add to your shell profile (~/.zshrc or ~/.bashrc):
#   source /path/to/scp/scripts/env.sh

set -euo pipefail 2>/dev/null || true  # safe in both source and execute contexts

# ---------------------------------------------------------------------------
# Android SDK / NDK
# ---------------------------------------------------------------------------
NDK_VERSION="27.2.12479018"

if [[ -d "$HOME/Library/Android/sdk" ]]; then
  export ANDROID_HOME="$HOME/Library/Android/sdk"
elif [[ -d "$HOME/Android/Sdk" ]]; then
  export ANDROID_HOME="$HOME/Android/Sdk"
elif [[ -n "${ANDROID_HOME:-}" ]]; then
  : # already set
else
  export ANDROID_HOME="$HOME/Library/Android/sdk"
fi

export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/$NDK_VERSION"

# ---------------------------------------------------------------------------
# Java (asdf-managed)
# ---------------------------------------------------------------------------
if command -v asdf &>/dev/null; then
  _java_home="$(asdf where java 2>/dev/null)" || true
  if [[ -n "${_java_home:-}" && -d "${_java_home:-}" ]]; then
    export JAVA_HOME="$_java_home"
  fi
  unset _java_home
fi

# ---------------------------------------------------------------------------
# Android NDK cross-compilation linkers (Cargo)
# ---------------------------------------------------------------------------
if [[ -d "${ANDROID_NDK_HOME:-}" ]]; then
  _ndk_toolchain="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt"

  # Detect host platform
  if [[ "$(uname -s)" == "Darwin" ]]; then
    _ndk_host="darwin-x86_64"
  else
    _ndk_host="linux-x86_64"
  fi

  _ndk_bin="$_ndk_toolchain/$_ndk_host/bin"

  if [[ -d "$_ndk_bin" ]]; then
    export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$_ndk_bin/aarch64-linux-android21-clang"
    export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER="$_ndk_bin/armv7a-linux-androideabi21-clang"
    export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$_ndk_bin/x86_64-linux-android21-clang"
    export CARGO_TARGET_I686_LINUX_ANDROID_LINKER="$_ndk_bin/i686-linux-android21-clang"
  fi

  unset _ndk_toolchain _ndk_host _ndk_bin
fi
