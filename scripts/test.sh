#!/usr/bin/env bash
set -euo pipefail

# Unified test runner for SCP — dispatches to per-language test commands.
# Usage: ./scripts/test.sh [rust|python|kotlin|typescript|all]
# Default: all

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

run_rust() (
  set -euo pipefail
  echo "═══ Rust ═══"
  cd "$REPO_ROOT"

  # scp-ffi needs library path for libpython (auto-initialize links against it).
  # Prefer the mise-managed Python matching .mise.toml (3.12) over the system
  # python3 which may be a different version (e.g. Xcode ships 3.9).
  local python_bin
  python_bin="$(command -v python3.12 2>/dev/null || command -v python3 2>/dev/null || true)"
  local python_libdir
  python_libdir="$($python_bin -c "import sysconfig; print(sysconfig.get_config_var('LIBDIR'))" 2>/dev/null || true)"
  if [[ -n "$python_libdir" ]]; then
    export DYLD_LIBRARY_PATH="${python_libdir}${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
    export LD_LIBRARY_PATH="${python_libdir}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
  fi

  if command -v cargo-nextest &>/dev/null; then
    cargo nextest run --workspace
  else
    cargo test --workspace
  fi
  cargo test --workspace --doc
)

run_python() (
  set -euo pipefail
  echo "═══ Python ═══"
  cd "$REPO_ROOT/bindings/python"
  PYTHONPATH=. python3 -m pytest tests/ -v
)

run_kotlin() (
  set -euo pipefail
  echo "═══ Kotlin ═══"
  cd "$REPO_ROOT/bindings/kotlin"
  local java_home
  java_home="$(mise where java 2>/dev/null || true)"
  if [[ -n "$java_home" ]]; then
    export JAVA_HOME="$java_home"
  fi
  ./gradlew test
)

run_typescript() (
  set -euo pipefail
  echo "═══ TypeScript ═══"
  cd "$REPO_ROOT/bindings/typescript"
  bun install --frozen-lockfile 2>/dev/null || bun install
  bun test
)

target="${1:-all}"

case "$target" in
  rust)       run_rust ;;
  python)     run_python ;;
  kotlin)     run_kotlin ;;
  typescript) run_typescript ;;
  all)
    exit_code=0
    run_rust       || exit_code=1
    run_python     || exit_code=1
    run_kotlin     || exit_code=1
    run_typescript || exit_code=1
    if [[ $exit_code -eq 0 ]]; then
      echo "═══ All tests passed ═══"
    else
      echo "═══ Some tests failed ═══" >&2
      exit 1
    fi
    ;;
  *)
    echo "Usage: $0 [rust|python|kotlin|typescript|all]" >&2
    exit 1
    ;;
esac
