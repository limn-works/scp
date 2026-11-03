#!/usr/bin/env bash
# Experiment driver (branch ci/workspace-crate-cache-exp only): reader compile commands and edit scenarios.
set -u
PY_LIBDIR="$(python3 -c 'import sysconfig; print(sysconfig.get_config_var("LIBDIR"))')"
export LD_LIBRARY_PATH="$PY_LIBDIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
TF=scp-ffi-uniffi/testing,scp-ffi/testing,scp-ffi-napi/testing,scp-core/testing,scp-runtime/testing,scp-runtime/saga-witness-test-mint,scp-ffi/testing,scp-ffi/outlet-capability-test-grant,scp-ffi-napi/testing,scp-ffi-napi/outlet-capability-test-grant,scp-ffi-uniffi/testing,scp-ffi-uniffi/outlet-capability-test-grant
reader_cmds() {
  case "$1" in
    testing) echo "cargo nextest run --no-run -p scp-testing -p scp-platform --features openmls_basic_credential/test-utils,serde_json/unbounded_depth,scp-core/outlet-capability-test-grant,tokio/test-util,scp-runtime/outlet-capability-test-grant,scp-runtime/saga-witness-test-mint,scp-platform/filesystem,scp-ffi-common/custody,scp-ffi-common/server,scp-ffi-common/testing" ;;
    runtime) echo "cargo nextest run --no-run -p scp-runtime -p scp-core --features scp-core/testing,scp-core/allow_unencrypted_storage,scp-runtime/testing,scp-runtime/saga-witness-test-mint,scp-core/outlet-capability-test-grant,serde_json/raw_value,serde_json/unbounded_depth,tracing/log,scp-runtime/outlet-capability-test-grant,scp-dht/production-dht,scp-identity/production-dht,scp-platform/file,scp-platform/sqlite,tokio-util/codec,tokio-util/io" ;;
    napi) printf '%s\n' "cargo test --no-run -p scp-ffi-napi --features server" "cargo test --no-run -p scp-ffi-common" "cargo nextest run --no-run -p scp-ffi-common --features server --test node_start_shipped" "cargo nextest run --no-run -p scp-ffi-napi --features server --lib" "cargo build -p scp-ffi-napi --features server --lib" ;;
    pyo3) printf '%s\n' "cargo build -p scp-ffi --features server" "cargo nextest run --no-run -p scp-ffi --features server --lib" ;;
    uniffi) printf '%s\n' "cargo build -p scp-ffi-uniffi --features server" "cargo clippy -p scp-ffi-uniffi --all-targets --features server -- -D warnings" "cargo test --no-run -p scp-ffi-uniffi --features server" "cargo nextest run --no-run -p scp-ffi-uniffi --features server --lib" ;;
    clippy-ws) echo "cargo clippy --workspace --all-targets --features $TF -- -D warnings" ;;
    clippy-cloud) printf '%s\n' "cargo clippy -p scp-node --features cloud-blobs,testing --all-targets -- -D warnings" "cargo clippy -p scp-relay --features cloud-blobs --all-targets -- -D warnings" ;;
    doctest) echo "cargo test --workspace --doc --features scp-ffi-uniffi/testing,scp-ffi/testing,scp-ffi-napi/testing,scp-core/testing,scp-runtime/testing,scp-runtime/saga-witness-test-mint,scp-ffi/outlet-capability-test-grant,scp-ffi-napi/outlet-capability-test-grant,scp-ffi-uniffi/outlet-capability-test-grant,scp-node/cloud-blobs,scp-relay/cloud-blobs -- --list" ;;
  esac
}
leaf_file() {
  case "$1" in
    testing) echo crates/scp-testing/src/lib.rs ;;
    runtime) echo crates/scp-core/src/lib.rs ;;
    napi) echo crates/scp-ffi/napi/src/lib.rs ;;
    pyo3) echo crates/scp-ffi/src/lib.rs ;;
    uniffi | clippy-ws | doctest) echo crates/scp-ffi/uniffi/src/lib.rs ;;
    clippy-cloud) echo crates/scp-relay/src/main.rs ;;
  esac
}
# run_reader <reader> <label>: runs every command, prints elapsed and the units cargo rebuilt.
run_reader() {
  local r=$1 label=$2 start end rc=0 log
  set +e +o pipefail
  log=$(mktemp)
  start=$(date +%s.%N)
  while IFS= read -r c; do
    [[ -z $c ]] && continue
    echo "+ $c"
    CARGO_TERM_COLOR=never bash -c "$c" >"$log.1" 2>&1 || rc=1
    cat "$log.1" >>"$log"
  done < <(reader_cmds "$r")
  end=$(date +%s.%N)
  local n_ws n_dep
  n_ws=$(command grep -E '^\s*(Compiling|Checking) scp-' "$log" | sort -u | wc -l)
  n_dep=$(command grep -E '^\s*(Compiling|Checking) ' "$log" | command grep -v ' scp-' | sort -u | wc -l)
  printf 'RESULT reader=%s label=%s seconds=%.1f ws_units=%s dep_units=%s rc=%s\n' "$r" "$label" "$(awk -v a="$start" -v b="$end" 'BEGIN{print b-a}')" "$n_ws" "$n_dep" "$rc" | tee -a "$GITHUB_STEP_SUMMARY"
  command grep -E '^\s*(Compiling|Checking) ' "$log" | sed 's/^ */  /' | sort | uniq -c | head -80
  command grep -E '^(error|warning)' "$log" | head -20
  tail -3 "$log"
  rm -f "$log" "$log.1"
  return 0
}
edit() { echo "// workspace-cache experiment $1" >>"$2"; }
