#!/usr/bin/env bash
# scripts/setup-toolchain.sh — Idempotent local dev toolchain setup for SCP
#
# Usage:
#   ./scripts/setup-toolchain.sh          # Install/update everything
#   ./scripts/setup-toolchain.sh --check  # Verify-only (no changes)
#
# Prerequisites (install manually first):
#   - Homebrew: https://brew.sh
#   - mise: https://mise.jdx.dev (brew install mise)
#   - rustup: https://rustup.rs
#   - Xcode Command Line Tools: xcode-select --install
#
# mise handles: language versions, cargo tools, npm globals, and environment
# variables (JAVA_HOME, ANDROID_HOME, NDK linkers, etc.)
#
# rustup handles Rust, and `.mise.toml` names no Rust version. rustup reads the
# toolchain file of whichever directory a cargo command runs in, so the workspace
# resolves `rust-toolchain.toml` and `fuzz/` resolves `fuzz/rust-toolchain.toml`;
# mise would export one RUSTUP_TOOLCHAIN for both, which overrides both files.
# The Rust check below therefore compares `rustc --version` against the pin
# instead of asking mise what it installed.
#
# This script also covers what neither can: Android SDK/NDK via sdkmanager.

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
NDK_VERSION="27.2.12479018"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
CHECK_MODE=false
if [[ "${1:-}" == "--check" ]]; then
  CHECK_MODE=true
fi

ERRORS=0

green()  { printf '\033[0;32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[0;33m%s\033[0m\n' "$*"; }
red()    { printf '\033[0;31m%s\033[0m\n' "$*"; }
bold()   { printf '\033[1m%s\033[0m\n' "$*"; }

ok()   { green  "  ✓ $*"; }
warn() { yellow "  ⚠ $*"; }
fail() { red    "  ✗ $*"; ERRORS=$((ERRORS + 1)); }
info() { printf '  %s\n' "$*"; }

section() {
  echo ""
  bold "── $* ──"
}

require_cmd() {
  if command -v "$1" &>/dev/null; then
    ok "$1 found"
    return 0
  else
    fail "$1 not found"
    return 1
  fi
}

# ---------------------------------------------------------------------------
# 1. Prerequisites
# ---------------------------------------------------------------------------
section "Prerequisites"

require_cmd git
require_cmd brew || true
require_cmd mise || true
require_cmd rustup || true

# Xcode CLT
if xcode-select -p &>/dev/null; then
  ok "Xcode Command Line Tools installed"
else
  fail "Xcode Command Line Tools not found (run: xcode-select --install)"
fi

# ---------------------------------------------------------------------------
# 2. mise install (languages, cargo tools, npm globals) + the rustup pin
# ---------------------------------------------------------------------------
section "mise install"

cd "$REPO_ROOT"

if $CHECK_MODE; then
  info "Running mise doctor..."
  mise doctor 2>&1 | head -30 || true
  echo ""

  # Verify key tools are installed
  for tool in java bun python kotlin gradle; do
    if mise ls --installed "$tool" &>/dev/null && [[ -n "$(mise ls --installed "$tool" 2>/dev/null)" ]]; then
      ok "$tool $(mise current "$tool" 2>/dev/null || echo '?')"
    else
      fail "$tool not installed via mise"
    fi
  done

  for cargo_tool in cargo-nextest maturin cargo-deny; do
    if mise ls --installed "cargo:$cargo_tool" &>/dev/null && [[ -n "$(mise ls --installed "cargo:$cargo_tool" 2>/dev/null)" ]]; then
      ok "cargo:$cargo_tool"
    else
      fail "cargo:$cargo_tool not installed via mise"
    fi
  done

  if mise ls --installed "npm:@napi-rs/cli" &>/dev/null && [[ -n "$(mise ls --installed "npm:@napi-rs/cli" 2>/dev/null)" ]]; then
    ok "npm:@napi-rs/cli"
  else
    fail "npm:@napi-rs/cli not installed via mise"
  fi
else
  info "Installing tools from .mise.toml..."
  mise install --yes
  ok "mise install complete"

  # Verify key tools
  for tool in java bun python kotlin gradle; do
    if mise current "$tool" &>/dev/null; then
      ok "$tool $(mise current "$tool" 2>/dev/null)"
    else
      fail "$tool failed to install"
    fi
  done
fi

# ---------------------------------------------------------------------------
# 2b. The Rust toolchain rustup resolves here
# ---------------------------------------------------------------------------
# `rust-toolchain.toml` names the version, and rustup installs it the first time a
# cargo command runs in this directory. This block runs one so the download happens
# during setup rather than during someone's first build, then compares what the shell
# resolved against the pin. `RUSTUP_TOOLCHAIN` overrides the file when it is set, and
# a shell carrying it compiles and lints on a version this repository does not name,
# so the mismatch is reported rather than left to surface in CI.
section "Rust toolchain"

RUST_PIN=$(sed -nE 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' \
  "$REPO_ROOT/rust-toolchain.toml" | head -n 1)

if [[ -z "$RUST_PIN" ]]; then
  fail "rust-toolchain.toml names no [toolchain] channel"
elif ! command -v rustc &>/dev/null; then
  fail "rustc not found — install rustup from https://rustup.rs"
else
  if ! $CHECK_MODE; then
    info "Resolving the pinned toolchain ($RUST_PIN)..."
    cargo --version >/dev/null 2>&1 || true
  fi
  RUST_ACTIVE=$(rustc --version 2>/dev/null | sed -nE 's/^rustc ([0-9]+\.[0-9]+\.[0-9]+).*/\1/p')
  if [[ "$RUST_ACTIVE" == "$RUST_PIN" ]]; then
    ok "rustc $RUST_ACTIVE matches rust-toolchain.toml"
  else
    fail "rustc in this shell is ${RUST_ACTIVE:-unreadable}; rust-toolchain.toml names $RUST_PIN"
    info "RUSTUP_TOOLCHAIN=${RUSTUP_TOOLCHAIN:-<unset>} overrides the file when it is set — unset it"
  fi
fi

# ---------------------------------------------------------------------------
# 3. Homebrew overlap detection
# ---------------------------------------------------------------------------
section "Homebrew overlap detection"

if brew list kotlin &>/dev/null 2>&1; then
  warn "Homebrew kotlin also installed — mise version takes precedence in this repo"
  info "To remove: brew uninstall kotlin"
else
  ok "No Homebrew kotlin overlap"
fi

if brew list openjdk &>/dev/null 2>&1; then
  warn "Homebrew openjdk also installed — mise java takes precedence in this repo"
  info "To remove: brew uninstall openjdk"
else
  ok "No Homebrew openjdk overlap"
fi

# ---------------------------------------------------------------------------
# 4. Bun standalone check
# ---------------------------------------------------------------------------
section "Bun standalone check"

if [[ -d "$HOME/.bun" ]] && [[ ! "$HOME/.bun" -ef "$(mise where bun 2>/dev/null || echo __none__)" ]]; then
  warn "Standalone ~/.bun installation detected"
  warn "Consider removing it in favor of mise-managed bun:"
  warn "  rm -rf ~/.bun && remove bun entries from your shell profile"
else
  ok "No standalone bun conflict"
fi

# ---------------------------------------------------------------------------
# 5. Android SDK + NDK
# ---------------------------------------------------------------------------
section "Android SDK + NDK"

# Resolve ANDROID_HOME/NDK_HOME the same way mise does
if [[ -d "$HOME/Library/Android/sdk" ]]; then
  _ANDROID_HOME="$HOME/Library/Android/sdk"
elif [[ -d "$HOME/Android/Sdk" ]]; then
  _ANDROID_HOME="$HOME/Android/Sdk"
else
  _ANDROID_HOME="$HOME/Library/Android/sdk"
fi
_ANDROID_NDK_HOME="$_ANDROID_HOME/ndk/$NDK_VERSION"

if [[ -d "$_ANDROID_NDK_HOME" ]]; then
  ok "NDK $NDK_VERSION"
elif $CHECK_MODE; then
  fail "NDK $NDK_VERSION not found at $_ANDROID_NDK_HOME"
else
  # Ensure sdkmanager is available
  if ! command -v sdkmanager &>/dev/null; then
    if command -v brew &>/dev/null; then
      info "Installing android-commandlinetools via Homebrew..."
      brew install --cask android-commandlinetools
    else
      fail "sdkmanager not found and Homebrew not available"
    fi
  fi

  if command -v sdkmanager &>/dev/null; then
    info "Installing NDK $NDK_VERSION..."
    yes | sdkmanager "ndk;$NDK_VERSION" || true
    if [[ -d "$_ANDROID_NDK_HOME" ]]; then
      ok "NDK $NDK_VERSION"
    else
      fail "NDK installation may have succeeded but not found at expected path"
      info "Check ANDROID_HOME and run: sdkmanager \"ndk;$NDK_VERSION\""
    fi
  else
    fail "sdkmanager not available — install Android command-line tools manually"
  fi
fi

# Check Android SDK platform tools
if command -v sdkmanager &>/dev/null; then
  ok "sdkmanager available"
else
  warn "sdkmanager not found — Android builds may not work"
fi

# ---------------------------------------------------------------------------
# 6. Summary
# ---------------------------------------------------------------------------
section "Summary"

echo ""
if [[ "$ERRORS" -eq 0 ]]; then
  green "All checks passed!"
else
  red "$ERRORS issue(s) found."
fi

echo ""
bold "Installed versions:"
info "java:    $(mise current java 2>/dev/null || echo 'not found')"
info "bun:     $(mise current bun 2>/dev/null || echo 'not found')"
info "python:  $(mise current python 2>/dev/null || echo 'not found')"
info "kotlin:  $(mise current kotlin 2>/dev/null || echo 'not found')"
info "gradle:  $(mise current gradle 2>/dev/null || echo 'not found')"
info "rustc:   $(rustc --version 2>/dev/null || echo 'not found')"
info "cargo:   $(cargo --version 2>/dev/null || echo 'not found')"

# ---------------------------------------------------------------------------
# Git hooks
# ---------------------------------------------------------------------------
echo ""
bold "Git hooks:"
if $CHECK_MODE; then
  if [[ "$(git config core.hooksPath 2>/dev/null)" == "scripts/hooks" ]]; then
    ok "core.hooksPath = scripts/hooks"
  else
    fail "core.hooksPath not set — run without --check to fix"
  fi
else
  git config core.hooksPath scripts/hooks
  ok "core.hooksPath set to scripts/hooks (pre-commit: lint + format)"
fi

# ---------------------------------------------------------------------------
# Shell environment
# ---------------------------------------------------------------------------
echo ""
bold "Shell environment:"
MISE_LINE='eval "$(mise activate zsh --shims)"'
if grep -qF 'mise activate' ~/.zshenv 2>/dev/null; then
  ok "mise activate already in ~/.zshenv"
elif $CHECK_MODE; then
  fail "mise activate not in ~/.zshenv — run without --check to fix"
else
  echo "" >> ~/.zshenv
  echo '# mise — managed toolchain versions (added by scripts/setup-toolchain.sh)' >> ~/.zshenv
  echo "$MISE_LINE" >> ~/.zshenv
  ok "Added mise activate to ~/.zshenv"
fi

if [[ "$ERRORS" -gt 0 ]]; then
  exit 1
fi
