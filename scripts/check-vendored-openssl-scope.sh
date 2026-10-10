#!/usr/bin/env bash
# Vendored-OpenSSL scope gate. Usage: scripts/check-vendored-openssl-scope.sh [--self-test]
#
# CRITERION: `openssl-src`, the crate whose build script compiles OpenSSL so that
# `openssl-sys` links it statically, is in the dependency graph of the PyPI wheel's
# configuration with libsqlite3-sys's `bundled-sqlcipher-vendored-openssl` feature on, and
# in the graph of no other configuration this repository ships and of no package of the
# root workspace.
#
# Presence: the one entry `scripts/check-shipped-feature-graph.sh --print-wheel-entries`
# writes reaches at least one `openssl-src` under `cargo tree --target all`, keeping build
# edges because `openssl-src` is a build-dependency of `openssl-sys`. A second
# `cargo tree --target all -e no-dev,features -i libsqlite3-sys --depth 1` for that entry
# has to list libsqlite3-sys's `bundled-sqlcipher-vendored-openssl` feature. The edge from
# libsqlite3-sys to openssl-sys proves nothing on its own: libsqlite3-sys declares
# openssl-sys optional without `dep:`, so its implicit `openssl-sys` feature makes the same
# edge while SQLCipher still links the build host's OpenSSL.
#
# Absence: every entry `--print-artifacts` writes except the wheel's, which that list must
# name exactly once beside at least one other entry, and the root workspace under
# `--workspace`, reach no `openssl-src` under `cargo tree --target all`.
#
# Every `cargo tree` call passes `--locked`, so each resolution reads the versions the root
# Cargo.lock pins. Presence resolves the union over every target triple, so it proves the
# wheel's configuration reaches `openssl-src` on some triple, not on each triple the wheel
# ships for.
#
# The gate fails closed: a print mode that exits non-zero, a wheel answer that is not one
# `<file><TAB><package>|<arguments>` line, an entry whose arguments are not a feature
# selection, and a `cargo tree` that exits non-zero each fail the run, because zero
# `openssl-src` is the count absence passes on.
#
# A run calls bash, cargo and grep, and the print modes of the gate above, which run
# python3.12. A PATH entry or an exported function carrying one of those names replaces it.
set -euo pipefail

# Resolved before the cd, so a relative invocation path keeps naming this repository.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

VENDOR_CRATE="openssl-src"
SQLCIPHER_FEATURE="bundled-sqlcipher-vendored-openssl"
FEATURE_GRAPH_GATE="$REPO_ROOT/scripts/check-shipped-feature-graph.sh"

# count_in <tree>: how many `openssl-src` lines a `cargo tree --prefix none` graph holds.
count_in() { printf '%s\n' "$1" | grep -cE "^${VENDOR_CRATE} v" || true; }

# all_target_occurrences <cargo tree argument>...: the `openssl-src` count of a graph over
# every triple. A cargo failure fails the count, because zero is the verdict absence
# passes on.
all_target_occurrences() {
  local tree
  tree="$(cargo tree --locked "$@" -e no-dev --target all --prefix none --format '{p}')" ||
    { echo "cargo tree $* failed" >&2; return 1; }
  count_in "$tree"
}

# is_feature_selection <entry arguments>: succeed when every token is
# --no-default-features, --all-features, or --features <value>. A resolver flag such as
# `--prune openssl-src` would otherwise empty the graph this gate counts, so a flag-shaped
# token fails in the value slot too. The value's feature-name grammar is cargo's to check:
# a malformed list fails `cargo tree`, and the count then fails.
is_feature_selection() {
  local token want_list=0
  for token in $1; do
    if [[ "$want_list" -eq 1 ]]; then
      [[ "$token" != -* ]] || { echo "a shipped configuration names a flag where a feature list belongs: '$token'" >&2; return 1; }
      want_list=0
    elif [[ "$token" == "--features" ]]; then want_list=1
    elif [[ "$token" != "--no-default-features" && "$token" != "--all-features" ]]; then
      echo "a shipped configuration names a cargo argument this gate does not build: '$token'" >&2; return 1
    fi
  done
  [[ "$want_list" -eq 0 ]] || { echo "a shipped configuration ends with '--features'" >&2; return 1; }
}

# wheel_line: the one `<pyproject path><TAB><package>|<feature arguments>` line
# `--print-wheel-entries` writes, after checking that the print mode exited 0, that its
# answer is one line of that shape, and that its arguments are a feature selection.
wheel_line() {
  local line shape=$'^[^\t]+\t[A-Za-z0-9_-]+[|][^\t]*$'
  line="$(bash "$FEATURE_GRAPH_GATE" --print-wheel-entries)" ||
    { echo "$FEATURE_GRAPH_GATE --print-wheel-entries exited non-zero" >&2; return 1; }
  [[ "$line" != *$'\n'* ]] || { echo "expected one wheel entry, got: $line" >&2; return 1; }
  [[ "$line" =~ $shape ]] || { echo "the wheel entry is not '<file><TAB><package>|<arguments>': '$line'" >&2; return 1; }
  is_feature_selection "${line#*|}" || return 1
  printf '%s\n' "$line"
}

# wheel_occurrences <package>|<feature arguments>: the `openssl-src` count of the wheel's
# graph over every triple, or 0 when libsqlite3-sys's bundled-sqlcipher-vendored-openssl
# feature is off in it. A cargo failure fails the count.
wheel_occurrences() {
  local entry="$1" n features
  local -a args=()
  read -r -a args <<<"${entry#*|}"
  n="$(all_target_occurrences -p "${entry%%|*}" ${args[@]+"${args[@]}"})" || return 1
  if [[ "$n" -gt 0 ]]; then
    features="$(cargo tree --locked -p "${entry%%|*}" ${args[@]+"${args[@]}"} -e no-dev,features --target all -i libsqlite3-sys --depth 1 --prefix none --format '{p}')" ||
      { echo "cargo tree -i libsqlite3-sys failed for $entry" >&2; return 1; }
    if ! printf '%s\n' "$features" | grep -xF "libsqlite3-sys feature \"$SQLCIPHER_FEATURE\"" >/dev/null; then
      echo "$VENDOR_CRATE is in the wheel's graph, but libsqlite3-sys's $SQLCIPHER_FEATURE feature is off, so SQLCipher links the build host's OpenSSL" >&2
      n=0
    fi
  fi
  echo "$n"
}

# report <label> <count, or empty on failure> <want: some|none>: one verdict line.
report() {
  if [[ -z "$2" ]]; then echo "    FAIL — $1 resolved no graph"; return 1; fi
  if [[ "$3" == some && "$2" -gt 0 ]] || [[ "$3" == none && "$2" -eq 0 ]]; then echo "    ok   — $1"; return 0; fi
  echo "    FAIL — $1 reaches $2 $VENDOR_CRATE, and this gate wants $3."; return 1
}

run_gate() {
  local failures=0 resolved=0 wheel_seen=0 line wheel_file wheel_entry entry n
  local -a args=()
  line="$(wheel_line)" || { echo "FAIL — no readable wheel entry"; return 1; }
  wheel_file="${line%%$'\t'*}"; wheel_entry="${line#*$'\t'}"
  echo "--> the wheel, $wheel_entry from $wheel_file, over every triple"
  n="$(wheel_occurrences "$wheel_entry")" || n=""
  report "$wheel_entry" "$n" some || failures=$((failures + 1))

  echo "--> every other shipped configuration, over every triple"
  line="$(bash "$FEATURE_GRAPH_GATE" --print-artifacts)" ||
    { echo "FAIL — $FEATURE_GRAPH_GATE --print-artifacts exited non-zero"; return 1; }
  while IFS= read -r entry; do
    [[ -z "$entry" ]] && continue
    [[ "$entry" == "$wheel_entry" ]] && { wheel_seen=$((wheel_seen + 1)); continue; }
    resolved=$((resolved + 1)); n=""
    if is_feature_selection "${entry#*|}"; then
      args=(); read -r -a args <<<"${entry#*|}"
      n="$(all_target_occurrences -p "${entry%%|*}" ${args[@]+"${args[@]}"})" || n=""
    fi
    report "$entry" "$n" none || failures=$((failures + 1))
  done <<<"$line"
  # The skip above must match exactly one printed entry, and at least one other entry
  # must be resolved, so an empty or wheel-less artifact list cannot pass.
  [[ "$wheel_seen" -eq 1 ]] ||
    { echo "    FAIL — --print-artifacts lists the wheel entry $wheel_seen time(s), and this gate wants it once"; failures=$((failures + 1)); }
  [[ "$resolved" -gt 0 ]] ||
    { echo "    FAIL — --print-artifacts lists no shipped configuration besides the wheel"; failures=$((failures + 1)); }

  echo "--> the root workspace, over every triple"
  n="$(all_target_occurrences --workspace)" || n=""
  report "the root workspace" "$n" none || failures=$((failures + 1))

  [[ "$failures" -eq 0 ]] && echo "PASS — $VENDOR_CRATE reaches the wheel and nothing else shipped." && return 0
  echo "FAIL — $failures resolution(s). Select the vendored build through scp-ffi/vendored-openssl on the wheel alone."
  return 1
}

fixture_failures=0
same() { [[ "$1" == "$2" ]] || { echo "      wanted [$2], got [$1]"; return 1; }; }
expect() { # <label> <PASS|FAIL> <rc>
  local got=FAIL; [[ "$3" -eq 0 ]] && got=PASS
  if [[ "$got" == "$2" ]]; then echo "   ok   — $1"; else echo "   FAIL — $1 (wanted $2)"; fixture_failures=$((fixture_failures + 1)); fi
}

# Runs in a subshell (see the end of this file), so the PATH and FEATURE_GRAPH_GATE it
# plants cannot reach run_gate.
# shellcheck disable=SC2016 # the single-quoted lines are scripts written to disk.
run_fixtures() {
  echo ">> fixtures"
  local dir out wheel wheel_entry
  dir="$(mktemp -d)"; mkdir -p "$dir/bin"
  # shellcheck disable=SC2064 # $dir is fixed here, and the trap must remove this one.
  trap "rm -rf '$dir'" EXIT

  is_feature_selection '--features server --prune openssl-src' 2>/dev/null; expect "an entry carrying a resolver flag FAILS" FAIL $?
  is_feature_selection '--features --prune=openssl-src' 2>/dev/null; expect "a resolver flag in the feature-list slot FAILS" FAIL $?
  is_feature_selection '--no-default-features --features' 2>/dev/null; expect "an entry ending in --features FAILS" FAIL $?
  is_feature_selection '--no-default-features --all-features --features extension-module,vendored-openssl' 2>/dev/null; expect "a feature selection PASSES" PASS $?
  same "$(count_in "$(printf '%s\n' 'openssl-sys v0.9.111' 'openssl-src v300.5.5+3.5.5' 'xopenssl-src v1.0.0')")" 1
  expect "count_in counts openssl-src lines alone" PASS $?
  same "$(count_in 'openssl-sys v0.9.111')" 0; expect "count_in writes 0 for a graph without openssl-src" PASS $?

  # A fake cargo that records its arguments. It exits 101 under $FAKE_BROKEN or when its
  # arguments hold the $FAKE_FAIL_ON word, answers `-i libsqlite3-sys` with
  # libsqlite3-sys's `openssl-sys` feature and, unless $FAKE_NO_FEATURE, its
  # `bundled-sqlcipher-vendored-openssl` feature, and prints one openssl-src for each
  # $FAKE_VENDORS word its arguments hold.
  printf '%s\n' '#!/bin/sh' 'printf "%s\n" "$*" >> "$ARGV_LOG"' '[ -n "$FAKE_BROKEN" ] && exit 101' \
    'if [ -n "$FAKE_FAIL_ON" ]; then case " $* " in *" $FAKE_FAIL_ON "*) exit 101;; esac; fi' \
    'case " $* " in *" -i libsqlite3-sys "*) echo "libsqlite3-sys v0.30.1"; echo "libsqlite3-sys feature \"openssl-sys\""; [ -n "$FAKE_NO_FEATURE" ] || echo "libsqlite3-sys feature \"bundled-sqlcipher-vendored-openssl\""; exit 0;; esac' \
    'echo "pkg v0.1.0"' \
    'for w in $FAKE_VENDORS; do case " $* " in *" $w "*) echo "openssl-src v300.5.5+3.5.5";; esac; done' > "$dir/bin/cargo"
  chmod +x "$dir/bin/cargo"
  export ARGV_LOG="$dir/argv" FAKE_BROKEN="" FAKE_FAIL_ON="" FAKE_NO_FEATURE="" FAKE_VENDORS="extension-module,vendored-openssl"
  PATH="$dir/bin:$PATH"
  FAKE_BROKEN=1 all_target_occurrences --workspace >/dev/null 2>&1; expect "a cargo that exits non-zero FAILS rather than counting zero" FAIL $?

  # A planted owner gate. $FAKE_WHEEL and $FAKE_ARTIFACTS, when set, replace a print
  # mode's default answer; $FAKE_WHEEL_RC and $FAKE_ARTIFACTS_RC make that mode exit
  # non-zero after writing it.
  wheel="$(printf 'bindings/python/pyproject.toml\tscp-ffi|--features extension-module,vendored-openssl')"
  wheel_entry="${wheel#*$'\t'}"
  printf '%s\n' '#!/usr/bin/env bash' 'case "$1" in' \
    "  --print-wheel-entries) if [ -n \"\${FAKE_WHEEL+x}\" ]; then printf '%s\n' \"\$FAKE_WHEEL\"; else printf '%s\n' $(printf '%q' "$wheel"); fi; exit \"\${FAKE_WHEEL_RC:-0}\" ;;" \
    "  --print-artifacts) if [ -n \"\${FAKE_ARTIFACTS+x}\" ]; then printf '%s\n' \"\$FAKE_ARTIFACTS\"; else printf '%s\n' 'scp-node|' 'scp-ffi|--no-default-features --features server' $(printf '%q' "$wheel_entry"); fi; exit \"\${FAKE_ARTIFACTS_RC:-0}\" ;;" \
    'esac' > "$dir/gate.sh"
  FEATURE_GRAPH_GATE="$dir/gate.sh"

  # wheel_line's guards, each fed an answer only that guard rejects.
  same "$(wheel_line)" "$wheel"; expect "wheel_line PASSES one well-formed wheel entry through unchanged" PASS $?
  FAKE_WHEEL_RC=1 wheel_line >/dev/null 2>&1; expect "wheel_line FAILS a print mode that exits non-zero" FAIL $?
  FAKE_WHEEL="$(printf '%s\n' "$wheel" --no-default-features)" wheel_line >/dev/null 2>&1; expect "wheel_line FAILS a two-line answer" FAIL $?
  FAKE_WHEEL="" wheel_line >/dev/null 2>&1; expect "wheel_line FAILS an empty answer" FAIL $?
  FAKE_WHEEL="$wheel_entry" wheel_line >/dev/null 2>&1; expect "wheel_line FAILS an answer without its file column" FAIL $?
  FAKE_WHEEL="$wheel --prune openssl-src" wheel_line >/dev/null 2>&1; expect "wheel_line FAILS a wheel entry carrying a resolver flag" FAIL $?

  : > "$ARGV_LOG"
  same "$(wheel_occurrences "$wheel_entry")" 1; expect "wheel_occurrences counts the wheel's openssl-src" PASS $?
  same "$(cat "$ARGV_LOG")" "$(printf '%s\n' \
    "tree --locked -p scp-ffi --features extension-module,vendored-openssl -e no-dev --target all --prefix none --format {p}" \
    "tree --locked -p scp-ffi --features extension-module,vendored-openssl -e no-dev,features --target all -i libsqlite3-sys --depth 1 --prefix none --format {p}")"
  expect "the presence calls resolve the wheel entry over every triple, with build edges and then libsqlite3-sys's enabled features" PASS $?
  FAKE_BROKEN=1 wheel_occurrences "$wheel_entry" >/dev/null 2>&1; expect "a failing wheel graph resolution FAILS the presence count" FAIL $?
  FAKE_FAIL_ON=libsqlite3-sys wheel_occurrences "$wheel_entry" >/dev/null 2>&1; expect "a failing libsqlite3-sys feature resolution FAILS the presence count" FAIL $?

  scenario() { # <label> <want>
    : > "$ARGV_LOG"; out="$(run_gate 2>&1)"; expect "$1" "$2" $?
  }
  scenario "run_gate PASSES when only the wheel reaches $VENDOR_CRATE" PASS
  same "$(grep -cvE '^tree --locked .* --target all ' "$ARGV_LOG" || true)" 0
  expect "every cargo tree call of that run passes --locked and --target all" PASS $?
  grep -xF "tree --locked --workspace -e no-dev --target all --prefix none --format {p}" "$ARGV_LOG" >/dev/null
  expect "that run resolves the root workspace" PASS $?
  FAKE_VENDORS="" scenario "(presence) run_gate FAILS when the wheel reaches no $VENDOR_CRATE" FAIL
  printf '%s\n' "$out" | grep -F "FAIL — $wheel_entry reaches 0" >/dev/null; expect "(presence) it names the wheel entry" PASS $?
  FAKE_NO_FEATURE=1 scenario "(presence) run_gate FAILS when libsqlite3-sys depends on openssl-sys without $SQLCIPHER_FEATURE" FAIL
  printf '%s\n' "$out" | grep -F "$SQLCIPHER_FEATURE feature is off" >/dev/null; expect "(presence) it names the missing SQLCipher feature" PASS $?
  FAKE_WHEEL="$wheel --prune openssl-src" FAKE_ARTIFACTS="$(printf '%s\n' 'scp-node|' "$wheel_entry --prune openssl-src")" \
    scenario "(presence) run_gate FAILS when the wheel entry carries a resolver flag" FAIL
  FAKE_VENDORS="extension-module,vendored-openssl scp-node" scenario "(absence) run_gate FAILS when another shipped configuration reaches $VENDOR_CRATE" FAIL
  printf '%s\n' "$out" | grep -F "FAIL — scp-node| reaches 1" >/dev/null; expect "(absence) it names scp-node" PASS $?
  # The baseline scenario vendors the wheel entry, so a removed skip goes red there;
  # vendoring the scp-ffi bridge entry goes red here, so a skip widened to every scp-ffi
  # entry goes red too.
  FAKE_VENDORS="extension-module,vendored-openssl server" scenario "(absence) run_gate FAILS when a non-wheel scp-ffi entry reaches $VENDOR_CRATE" FAIL
  printf '%s\n' "$out" | grep -F "FAIL — scp-ffi|--no-default-features --features server reaches 1" >/dev/null; expect "(absence) it names that scp-ffi entry" PASS $?
  FAKE_ARTIFACTS="$(printf '%s\n' 'scp-node|--prune openssl-src' "$wheel_entry")" scenario "(absence) run_gate FAILS when an artifact entry carries a resolver flag" FAIL
  FAKE_FAIL_ON=scp-node scenario "(absence) run_gate FAILS when an artifact entry's cargo tree exits non-zero" FAIL
  printf '%s\n' "$out" | grep -F "FAIL — scp-node| resolved no graph" >/dev/null; expect "(absence) it names that entry" PASS $?
  FAKE_ARTIFACTS_RC=1 scenario "(absence) run_gate FAILS when --print-artifacts exits non-zero" FAIL
  FAKE_ARTIFACTS="" scenario "(absence) run_gate FAILS when --print-artifacts lists nothing" FAIL
  printf '%s\n' "$out" | grep -F "lists the wheel entry 0 time(s)" >/dev/null; expect "(absence) it names the missing wheel entry" PASS $?
  printf '%s\n' "$out" | grep -F "lists no shipped configuration besides the wheel" >/dev/null; expect "(absence) it names the empty list" PASS $?
  FAKE_ARTIFACTS='scp-node|' scenario "(absence) run_gate FAILS when --print-artifacts omits the wheel entry" FAIL
  FAKE_ARTIFACTS="$(printf '%s\n' "$wheel_entry" 'scp-node|' "$wheel_entry")" scenario "(absence) run_gate FAILS when --print-artifacts lists the wheel entry twice" FAIL
  FAKE_ARTIFACTS="$wheel_entry" scenario "(absence) run_gate FAILS when --print-artifacts lists only the wheel entry" FAIL
  FAKE_VENDORS="extension-module,vendored-openssl --workspace" scenario "(absence) run_gate FAILS when the root workspace reaches $VENDOR_CRATE" FAIL
  printf '%s\n' "$out" | grep -F "FAIL — the root workspace reaches 1" >/dev/null; expect "(absence) it names the root workspace" PASS $?
  FAKE_FAIL_ON=--workspace scenario "(absence) run_gate FAILS when the root workspace's cargo tree exits non-zero" FAIL

  [[ "$fixture_failures" -eq 0 ]] && echo "   FIXTURES: all passed." && return 0
  echo "   FIXTURES: $fixture_failures failed."; return 1
}

echo "==> vendored-OpenSSL scope: $VENDOR_CRATE reaches the PyPI wheel's configuration and no other configuration this repository ships"
( run_fixtures ) || exit 1
[[ "${1:-}" == "--self-test" ]] && exit 0
run_gate
