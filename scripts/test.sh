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

  # `--workspace` resolves `scp-transport` without `postgres-blob` or
  # `s3-blob`, because `scp-node` and `scp-relay` put both behind their
  # off-by-default `cloud-blobs` feature, so the three commands above run no
  # test in `crates/scp-transport/src/native/postgres_blob.rs` or
  # `crates/scp-transport/src/native/s3_blob.rs` and compile neither module's
  # doctests. Job rust-test-optional-features in .github/workflows/ci.yml
  # carries the two lines below, and carries the two after them. What those two
  # lines cover inside the two modules is the compile: every test both modules
  # define carries `#[ignore]` and opens a connection to a live `PostgreSQL`
  # server or S3-compatible endpoint, and neither line passes `--ignored`, so
  # they build all 36 of those test bodies and run none of them. Start a server
  # yourself and run them with `-- --ignored`; the `# Testing` section at the
  # head of each module names the environment variables it reads.
  if command -v cargo-nextest &>/dev/null; then
    cargo nextest run -p scp-transport --features postgres-blob,s3-blob,startup,sqlite-blob,redb-blob
  else
    cargo test -p scp-transport --features postgres-blob,s3-blob,startup,sqlite-blob,redb-blob
  fi
  cargo test -p scp-transport --features postgres-blob,s3-blob,startup,sqlite-blob,redb-blob --doc

  # The two lines above compile `scp-transport`'s own test targets and link no
  # relay binary, so neither runs the three backend-selection tests in
  # `crates/scp-relay/tests/storage_backend.rs` against a relay that compiled
  # the `postgres` and `s3` arms of `storage_from_env`. Those three tests each
  # assert one of two outcomes, chosen by
  # `scp_transport::startup::backend_is_compiled`, and every command above
  # reaches their not-compiled half. This line reaches the other half, and it is
  # the only place in this script where the relay binary's postgres and s3
  # startup paths run.
  if command -v cargo-nextest &>/dev/null; then
    cargo nextest run --no-tests=fail -p scp-relay --features cloud-blobs
  else
    cargo test -p scp-relay --features cloud-blobs
  fi
  # The same feature on `scp-node`, which docs/guides/relay-operations.md hands
  # an operator as `cargo build --release -p scp-node --features cloud-blobs`.
  # No other command in this script compiles that graph: `--workspace` stopped
  # resolving `postgres-blob` and `s3-blob` when scp-node's manifest stopped
  # enabling them. The compile rejects a typo in either forwarding target of
  # `crates/scp-node/Cargo.toml`. It runs the binary's own unit tests rather
  # than stopping at `cargo check`, because two of them read `help_text()` and
  # assert which `SCP_RELAY_*` lines it prints, and both assertions name the
  # opposite text in a `cloud-blobs` build from the one every other command in
  # this script reaches. `--bin scp-node` keeps the seven integration-test
  # binaries in `crates/scp-node/tests/` out of this run: the `--workspace`
  # commands above already run each one at default features, and none of them
  # reads a cloud backend.
  if command -v cargo-nextest &>/dev/null; then
    cargo nextest run --no-tests=fail -p scp-node --features cloud-blobs --bin scp-node
  else
    cargo test -p scp-node --features cloud-blobs --bin scp-node
  fi
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
