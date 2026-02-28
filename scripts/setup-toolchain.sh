#!/usr/bin/env bash
# scripts/setup-toolchain.sh — Idempotent local dev toolchain setup for SCP
#
# Usage:
#   ./scripts/setup-toolchain.sh          # Install/update everything
#   ./scripts/setup-toolchain.sh --check  # Verify-only (no changes)
#
# Prerequisites (install manually first):
#   - Homebrew: https://brew.sh
#   - asdf: https://asdf-vm.com (brew install asdf)
#   - rustup: https://rustup.rs
#   - Xcode Command Line Tools: xcode-select --install

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
NDK_VERSION="27.2.12479018"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

RUST_TARGETS=(
  # WASM
  wasm32-unknown-unknown
  # iOS
  aarch64-apple-ios
  aarch64-apple-ios-sim
  x86_64-apple-ios
  # Android
  aarch64-linux-android
  armv7-linux-androideabi
  x86_64-linux-android
  i686-linux-android
  # macOS universal
  x86_64-apple-darwin
  aarch64-apple-darwin
)

CARGO_TOOLS=(
  cargo-nextest
  wasm-pack
  maturin
  cargo-deny
)

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
require_cmd asdf || true
require_cmd rustup || true

# Xcode CLT
if xcode-select -p &>/dev/null; then
  ok "Xcode Command Line Tools installed"
else
  fail "Xcode Command Line Tools not found (run: xcode-select --install)"
fi

# ---------------------------------------------------------------------------
# 2. asdf plugins
# ---------------------------------------------------------------------------
section "asdf plugins"

ASDF_PLUGINS=(java bun python kotlin)

for plugin in "${ASDF_PLUGINS[@]}"; do
  if asdf plugin list 2>/dev/null | grep -q "^${plugin}$"; then
    ok "plugin: $plugin"
  elif $CHECK_MODE; then
    fail "plugin missing: $plugin"
  else
    info "Adding plugin: $plugin"
    asdf plugin add "$plugin"
    ok "plugin added: $plugin"
  fi
done

# ---------------------------------------------------------------------------
# 3. asdf versions (from .tool-versions)
# ---------------------------------------------------------------------------
section "asdf versions"

cd "$REPO_ROOT"

if $CHECK_MODE; then
  # Check each tool version is installed
  while IFS=' ' read -r tool version; do
    [[ -z "$tool" || "$tool" == "#"* ]] && continue
    if asdf list "$tool" 2>/dev/null | grep -q "$version"; then
      ok "$tool $version"
    else
      fail "$tool $version not installed"
    fi
  done < .tool-versions
else
  info "Installing versions from .tool-versions..."
  asdf install
  asdf reshim
  ok "asdf install complete"

  # Verify
  while IFS=' ' read -r tool version; do
    [[ -z "$tool" || "$tool" == "#"* ]] && continue
    if asdf list "$tool" 2>/dev/null | grep -q "$version"; then
      ok "$tool $version"
    else
      fail "$tool $version failed to install"
    fi
  done < .tool-versions
fi

# ---------------------------------------------------------------------------
# 4. Homebrew overlap detection
# ---------------------------------------------------------------------------
section "Homebrew overlap detection"

if brew list kotlin &>/dev/null 2>&1; then
  warn "Homebrew kotlin also installed — asdf version takes precedence in this repo"
  info "To remove: brew uninstall kotlin"
else
  ok "No Homebrew kotlin overlap"
fi

if brew list openjdk &>/dev/null 2>&1; then
  warn "Homebrew openjdk also installed — asdf java takes precedence in this repo"
  info "To remove: brew uninstall openjdk"
else
  ok "No Homebrew openjdk overlap"
fi

# ---------------------------------------------------------------------------
# 5. Bun migration
# ---------------------------------------------------------------------------
section "Bun standalone check"

if [[ -d "$HOME/.bun" ]] && [[ ! "$HOME/.bun" -ef "$(asdf where bun 2>/dev/null || echo __none__)" ]]; then
  warn "Standalone ~/.bun installation detected"
  warn "Consider removing it in favor of asdf-managed bun:"
  warn "  rm -rf ~/.bun && remove bun entries from your shell profile"
else
  ok "No standalone bun conflict"
fi

# ---------------------------------------------------------------------------
# 6. Rust targets
# ---------------------------------------------------------------------------
section "Rust targets"

INSTALLED_TARGETS="$(rustup target list --installed 2>/dev/null || echo "")"

for target in "${RUST_TARGETS[@]}"; do
  if echo "$INSTALLED_TARGETS" | grep -q "^${target}$"; then
    ok "$target"
  elif $CHECK_MODE; then
    fail "$target not installed"
  else
    info "Adding target: $target"
    rustup target add "$target"
    ok "$target"
  fi
done

# ---------------------------------------------------------------------------
# 7. Cargo tools
# ---------------------------------------------------------------------------
section "Cargo tools"

for tool in "${CARGO_TOOLS[@]}"; do
  if cargo install --list 2>/dev/null | grep -q "^${tool} "; then
    ok "$tool"
  elif $CHECK_MODE; then
    fail "$tool not installed"
  else
    info "Installing $tool..."
    cargo install --locked "$tool"
    ok "$tool"
  fi
done

# ---------------------------------------------------------------------------
# 8. Bun globals
# ---------------------------------------------------------------------------
section "Bun globals"

if bun pm ls -g 2>/dev/null | grep -q "@napi-rs/cli"; then
  ok "@napi-rs/cli"
elif $CHECK_MODE; then
  fail "@napi-rs/cli not installed globally"
else
  info "Installing @napi-rs/cli..."
  bun install -g @napi-rs/cli
  ok "@napi-rs/cli"
fi

# ---------------------------------------------------------------------------
# 9. Android SDK + NDK
# ---------------------------------------------------------------------------
section "Android SDK + NDK"

# Source env.sh to get ANDROID_HOME
# shellcheck source=env.sh
source "$REPO_ROOT/scripts/env.sh" 2>/dev/null || true

if [[ -d "${ANDROID_NDK_HOME:-}" ]]; then
  ok "NDK $NDK_VERSION"
elif $CHECK_MODE; then
  fail "NDK $NDK_VERSION not found at ${ANDROID_NDK_HOME:-<unset>}"
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
    if [[ -d "${ANDROID_NDK_HOME:-}" ]]; then
      ok "NDK $NDK_VERSION"
    else
      # Re-source to pick up new install
      source "$REPO_ROOT/scripts/env.sh" 2>/dev/null || true
      if [[ -d "${ANDROID_NDK_HOME:-}" ]]; then
        ok "NDK $NDK_VERSION"
      else
        fail "NDK installation may have succeeded but not found at expected path"
        info "Check ANDROID_HOME and run: sdkmanager \"ndk;$NDK_VERSION\""
      fi
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
# 10. Summary
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
info "java:    $(asdf current java 2>/dev/null | awk 'NR>1{print $2}' || echo 'not found')"
info "bun:     $(asdf current bun 2>/dev/null | awk 'NR>1{print $2}' || echo 'not found')"
info "python:  $(asdf current python 2>/dev/null | awk 'NR>1{print $2}' || echo 'not found')"
info "kotlin:  $(asdf current kotlin 2>/dev/null | awk 'NR>1{print $2}' || echo 'not found')"
info "rustc:   $(rustc --version 2>/dev/null || echo 'not found')"
info "cargo:   $(cargo --version 2>/dev/null || echo 'not found')"

echo ""
bold "Environment setup:"
info "Add to your shell profile (~/.zshrc or ~/.bashrc):"
info ""
info "  source $(cd "$REPO_ROOT" && pwd)/scripts/env.sh"
info ""

if [[ "$ERRORS" -gt 0 ]]; then
  exit 1
fi
