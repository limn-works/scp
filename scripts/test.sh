#!/usr/bin/env bash
set -euo pipefail

# Unified test runner for SCP — dispatches to per-language test commands.
# Usage: ./scripts/test.sh [rust|python|kotlin|typescript|all]
# Default: all

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

run_rust() {
  echo "═══ Rust ═══"
  # scp-ffi needs DYLD_LIBRARY_PATH for libpython on macOS
  local python_libdir
  python_libdir="$(python3 -c "import sysconfig; print(sysconfig.get_config_var('LIBDIR'))" 2>/dev/null || true)"
  if [[ -n "$python_libdir" ]]; then
    export DYLD_LIBRARY_PATH="${python_libdir}${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
  fi

  if command -v cargo-nextest &>/dev/null; then
    cargo nextest run --workspace
  else
    cargo test --workspace
  fi
  cargo test --workspace --doc
}

run_python() {
  echo "═══ Python ═══"
  cd "$REPO_ROOT/bindings/python"
  PYTHONPATH=. python3 -m pytest tests/ -v
}

run_kotlin() {
  echo "═══ Kotlin ═══"
  cd "$REPO_ROOT/bindings/kotlin"
  local java_home
  java_home="$(mise where java 2>/dev/null || true)"
  if [[ -n "$java_home" ]]; then
    export JAVA_HOME="$java_home"
  fi
  ./gradlew test
}

run_typescript() {
  echo "═══ TypeScript ═══"
  cd "$REPO_ROOT/bindings/typescript"
  bun install --frozen-lockfile 2>/dev/null || bun install
  bun test
}

target="${1:-all}"

case "$target" in
  rust)       run_rust ;;
  python)     run_python ;;
  kotlin)     run_kotlin ;;
  typescript) run_typescript ;;
  all)
    run_rust
    run_python
    run_kotlin
    run_typescript
    echo "═══ All tests passed ═══"
    ;;
  *)
    echo "Usage: $0 [rust|python|kotlin|typescript|all]" >&2
    exit 1
    ;;
esac
