#!/usr/bin/env bash
# Experiment only (branch ci/workspace-crate-cache-exp): on a target restored from the
# clippy-packages workspace-unit archive, prove for job clippy-cloud's scp-relay command
# that each edited crate sits in the graph, that a planted clippy warning fails the job,
# that a warning replayed from a cached unit fails it, and that clippy configuration
# inputs force a re-lint.
set -u
RELAY=(cargo clippy -p scp-relay --features cloud-blobs --all-targets)
out=$RUNNER_TEMP/proof.out
fails=0
PLANT='#[allow(dead_code)] fn workspace_cache_plant(v: &[u8]) -> bool { v.len() == 0 }'

# proof <label> <want rc 0|1> <want len_zero 0|1> <check spec: none|any|+crate|-crate> -- cmd...
proof() {
  local label=$1 want_rc=$2 want_lz=$3 spec=$4
  shift 5
  local start end rc checked lz ok=PASS
  start=$(date +%s.%N)
  CARGO_TERM_COLOR=never "$@" >"$out" 2>&1
  rc=$?
  end=$(date +%s.%N)
  checked=$( (command grep -E '^\s+Checking scp-' "$out" || true) | awk '{print $2}' | sort -u | tr '\n' ' ')
  lz=$( (command grep -E 'clippy::len_zero|len_zero' "$out" || true) | wc -l)
  [[ $rc -ne 0 ]] && rc=1
  [[ $rc != "$want_rc" ]] && ok=FAIL
  if [[ $want_lz == 1 && $lz -eq 0 ]] || [[ $want_lz == 0 && $lz -ne 0 ]]; then ok=FAIL; fi
  case $spec in
    none) [[ -n ${checked// /} ]] && ok=FAIL ;;
    any) [[ -z ${checked// /} ]] && ok=FAIL ;;
    +*) [[ " $checked " == *" ${spec#+} "* ]] || ok=FAIL ;;
    -*) [[ " $checked " == *" ${spec#-} "* ]] && ok=FAIL ;;
  esac
  [[ $ok == FAIL ]] && fails=$((fails + 1))
  printf 'PROOF %s label=%s rc=%s want_rc=%s len_zero_lines=%s seconds=%s checked=[%s]\n' \
    "$ok" "$label" "$rc" "$want_rc" "$lz" "$(awk -v a="$start" -v b="$end" 'BEGIN{print b-a}')" "$checked" | tee -a "$GITHUB_STEP_SUMMARY"
  if [[ $ok == FAIL ]]; then tail -40 "$out"; fi
}

for c in scp-relay scp-runtime scp-crypto; do
  if cargo tree --offline -p scp-relay --features cloud-blobs -e normal,dev --prefix none --format '{p}' | awk '{print $1}' | command grep -qx "$c"; then
    echo "GRAPH $c is in the graph of cargo clippy -p scp-relay --features cloud-blobs" | tee -a "$GITHUB_STEP_SUMMARY"
  else
    echo "GRAPH-MISSING $c" | tee -a "$GITHUB_STEP_SUMMARY"
    fails=$((fails + 1))
  fi
done

proof restored-unchanged 0 0 none -- "${RELAY[@]}" -- -D warnings

for spec in leaf:crates/scp-relay/src/main.rs:scp-relay mid:crates/scp-runtime/src/lib.rs:scp-runtime root:crates/scp-crypto/src/lib.rs:scp-crypto; do
  IFS=: read -r case file crate <<<"$spec"
  cp "$file" "$RUNNER_TEMP/orig"
  echo "$PLANT" >>"$file"
  proof "plant-$case" 1 1 "+$crate" -- "${RELAY[@]}" -- -D warnings
  cp "$RUNNER_TEMP/orig" "$file"
done
proof plants-reverted 0 0 any -- "${RELAY[@]}" -- -D warnings

# Replay: a unit cached while it held a warning (linted without -D warnings).
f=crates/scp-relay/src/main.rs
cp "$f" "$RUNNER_TEMP/orig"
echo "$PLANT" >>"$f"
proof replay-cache-warning 0 1 +scp-relay -- "${RELAY[@]}"
proof replay-fresh-unit-replays-warning 0 1 -scp-relay -- "${RELAY[@]}"
proof replay-under-deny-fails 1 1 any -- "${RELAY[@]}" -- -D warnings
cp "$RUNNER_TEMP/orig" "$f"
proof replay-reverted 0 0 +scp-relay -- "${RELAY[@]}" -- -D warnings
proof settled 0 0 none -- "${RELAY[@]}" -- -D warnings

# Configuration inputs.
proof args-changed 0 0 +scp-relay -- "${RELAY[@]}" -- -D warnings -A clippy::len_zero
proof args-restored 0 0 +scp-relay -- "${RELAY[@]}" -- -D warnings
cp .clippy.toml "$RUNNER_TEMP/clippy.toml"
echo "# workspace-cache experiment" >>.clippy.toml
proof clippy-toml-changed 0 0 +scp-relay -- "${RELAY[@]}" -- -D warnings
cp "$RUNNER_TEMP/clippy.toml" .clippy.toml
proof clippy-toml-restored 0 0 +scp-relay -- "${RELAY[@]}" -- -D warnings
cp Cargo.toml "$RUNNER_TEMP/Cargo.toml"
sed -i 's/^cargo_common_metadata = "allow"$/cargo_common_metadata = "allow"\nlen_zero = "allow"/' Cargo.toml
command grep -q '^len_zero = "allow"$' Cargo.toml || { echo "lint-table edit missed"; fails=$((fails + 1)); }
proof lint-table-changed 0 0 +scp-relay -- "${RELAY[@]}" -- -D warnings
cp "$RUNNER_TEMP/Cargo.toml" Cargo.toml

echo "PROOF-FAILURES $fails" | tee -a "$GITHUB_STEP_SUMMARY"
exit $((fails > 0))
