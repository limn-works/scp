#!/usr/bin/env bash
# Vendored-OpenSSL scope gate. Usage: scripts/check-vendored-openssl-scope.sh [--self-test]
#
# CRITERION: `openssl-src`, the crate whose build script compiles OpenSSL so that
# `openssl-sys` links it statically, is in the dependency graph of the PyPI wheel's
# configuration on every target triple the `python-wheels` job of
# `.github/workflows/build-matrix.yml` builds, and in the graph of no other
# configuration this repository ships. `pip install` runs no linker, so the wheel
# has to carry SQLCipher's crypto; the scp-node, scp-relay and scp-personal-relay
# containers link the libssl3 their operators upgrade to patch OpenSSL.
#
# Presence: `wheel_triple_occurrences` runs one `cargo tree --target <triple>` per
# wheel triple, keeping build edges because `openssl-src` is a build-dependency of
# `openssl-sys`. `scripts/check-shipped-feature-graph.sh` exempts that one function
# by name from its rule that every `cargo tree` under scripts/ names `--target all`.
# Absence: `--target all` for every entry that gate's `--print-artifacts` writes
# except the wheel's (`--print-wheel-entries`), for the root workspace, and for
# `templates/personal-relay/Cargo.toml`, which declares its own `[workspace]`.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

VENDOR_CRATE="openssl-src"
FEATURE_GRAPH_GATE="scripts/check-shipped-feature-graph.sh"
WHEEL_MATRIX_FILE=".github/workflows/build-matrix.yml"
PERSONAL_RELAY_MANIFEST="templates/personal-relay/Cargo.toml"

# Prints the wheel triples of job argv[2] in workflow argv[1], reading maturin's
# `universal2-apple-darwin` as both darwin triples. It fails on a duplicated key, on
# a matrix holding any key beside `include:`, and on an item whose `target` is not
# one bare triple, so no leg drops out of the presence proof.
read -r -d '' WHEEL_TRIPLES_PROGRAM <<'PYTHON' || true
import re, sys, yaml
class Loader(yaml.SafeLoader): pass
def unique(loader, node):
    keys = [loader.construct_object(k) for k, _ in node.value]
    if len(keys) != len(set(map(str, keys))): sys.exit(f"{sys.argv[1]}: a mapping repeats a key")
    return loader.construct_mapping(node)
Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique)
doc = yaml.load(open(sys.argv[1], encoding="utf-8"), Loader=Loader) or {}
matrix = ((doc.get("jobs") or {}).get(sys.argv[2]) or {}).get("strategy", {}).get("matrix")
if not isinstance(matrix, dict) or list(matrix) != ["include"] or not matrix["include"]:
    sys.exit(f"{sys.argv[1]} job {sys.argv[2]}: strategy.matrix is not a non-empty include list alone")
out = []
for item in matrix["include"]:
    t = item.get("target") if isinstance(item, dict) else None
    if not isinstance(t, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+", t):
        sys.exit(f"{sys.argv[1]}: include item {item!r} names no bare target triple")
    out += ["x86_64-apple-darwin", "aarch64-apple-darwin"] if t == "universal2-apple-darwin" else [t]
print("\n".join(out))
PYTHON

# is_feature_selection <entry arguments>: succeed when every token is
# --no-default-features, --all-features, or --features <list>. A resolver flag such
# as `--prune openssl-src` would otherwise empty the graph this gate counts.
is_feature_selection() {
  local token want_list=0 name='[A-Za-z0-9_.+][A-Za-z0-9_.+-]*' list_re
  list_re="^${name}(/${name})?(,${name}(/${name})?)*$"
  for token in $1; do
    if [[ "$want_list" -eq 1 ]]; then
      [[ "$token" =~ $list_re ]] || { echo "not a cargo feature list: '$token'" >&2; return 1; }
      want_list=0
    elif [[ "$token" == "--features" ]]; then want_list=1
    elif [[ "$token" != "--no-default-features" && "$token" != "--all-features" ]]; then
      echo "a shipped configuration names a cargo argument this gate does not build: '$token'" >&2; return 1
    fi
  done
  [[ "$want_list" -eq 0 ]] || { echo "a shipped configuration ends with '--features'" >&2; return 1; }
}

# count_in <tree>: how many `openssl-src` lines a `cargo tree --prefix none` graph holds.
count_in() { printf '%s\n' "$1" | grep -cE "^${VENDOR_CRATE} v" || true; }

# wheel_triple_occurrences <triple> <package> [<feature argument>...]: the wheel's
# graph on one triple. The owner gate exempts this function, and no other call
# site, from its `--target all` rule. A cargo failure fails the count.
wheel_triple_occurrences() {
  local triple="$1" tree; shift
  tree="$(cargo tree -p "$@" --target "$triple" -e no-dev --prefix none --format '{p}')" ||
    { echo "cargo tree failed for $1 on $triple" >&2; return 1; }
  count_in "$tree"
}

# all_target_occurrences <cargo tree argument>...: a graph over every triple. A
# cargo failure fails the count, because zero is the verdict absence passes on.
all_target_occurrences() {
  local tree
  tree="$(cargo tree "$@" -e no-dev --target all --prefix none --format '{p}')" ||
    { echo "cargo tree $* failed" >&2; return 1; }
  count_in "$tree"
}

# report <label> <count or empty on failure> <want: some|none>: one verdict line.
report() {
  if [[ -z "$2" ]]; then echo "    FAIL — $1 resolved no graph"; return 1; fi
  if [[ "$3" == some && "$2" -gt 0 ]] || [[ "$3" == none && "$2" -eq 0 ]]; then echo "    ok   — $1"; return 0; fi
  echo "    FAIL — $1 reaches $2 $VENDOR_CRATE, and this gate wants $3."; return 1
}

run_gate() {
  local failures=0 line wheel_file wheel_entry entry triple n
  local -a args=()
  # A print mode that exits non-zero fails the gate, so a partial list is never read.
  line="$(bash "$FEATURE_GRAPH_GATE" --print-wheel-entries)" || return 1
  [[ "$(printf '%s\n' "$line" | grep -c .)" -eq 1 ]] || { echo "FAIL — expected one wheel entry, got: $line"; return 1; }
  wheel_file="${line%%$'\t'*}"; wheel_entry="${line#*$'\t'}"
  is_feature_selection "${wheel_entry#*|}" || return 1
  read -r -a args <<<"${wheel_entry#*|}"
  line="$(python3.12 -c "$WHEEL_TRIPLES_PROGRAM" "$WHEEL_MATRIX_FILE" python-wheels)" || return 1
  echo "--> the wheel, $wheel_entry from $wheel_file, on each triple it ships for"
  while IFS= read -r triple; do
    n="$(wheel_triple_occurrences "$triple" "${wheel_entry%%|*}" ${args[@]+"${args[@]}"})" || n=""
    report "$triple" "$n" some || failures=$((failures + 1))
  done <<<"$line"

  echo "--> every other shipped configuration, over every triple"
  line="$(bash "$FEATURE_GRAPH_GATE" --print-artifacts)" || return 1
  while IFS= read -r entry; do
    [[ -z "$entry" || "$entry" == "$wheel_entry" ]] && continue
    n=""
    if is_feature_selection "${entry#*|}"; then
      args=(); read -r -a args <<<"${entry#*|}"
      n="$(all_target_occurrences -p "${entry%%|*}" ${args[@]+"${args[@]}"})" || n=""
    fi
    report "$entry" "$n" none || failures=$((failures + 1))
  done <<<"$line"
  n="$(all_target_occurrences --workspace)" || n=""
  report "the root workspace" "$n" none || failures=$((failures + 1))
  n="$(all_target_occurrences --manifest-path "$PERSONAL_RELAY_MANIFEST" --workspace)" || n=""
  report "$PERSONAL_RELAY_MANIFEST" "$n" none || failures=$((failures + 1))
  [[ "$failures" -eq 0 ]] && echo "PASS — $VENDOR_CRATE reaches the wheel on every triple and nothing else shipped." && return 0
  echo "FAIL — $failures resolution(s). Select the vendored build through scp-ffi/vendored-openssl on the wheel alone."
  return 1
}

fixture_failures=0
same() { [[ "$1" == "$2" ]] || { echo "      wanted [$2], got [$1]"; return 1; }; }
expect() { # <label> <PASS|FAIL> <rc>
  local got=FAIL; [[ "$3" -eq 0 ]] && got=PASS
  if [[ "$got" == "$2" ]]; then echo "   ok   — $1"; else echo "   FAIL — $1 (wanted $2)"; fixture_failures=$((fixture_failures + 1)); fi
}

run_fixtures() {
  echo ">> fixtures"
  local dir out saved_path="$PATH" wheel
  dir="$(mktemp -d)"; mkdir -p "$dir/bin"
  is_feature_selection '--features server --prune openssl-src' 2>/dev/null; expect "an entry carrying a resolver flag FAILS" FAIL $?
  printf '%s\n' 'jobs: {python-wheels: {strategy: {matrix: {include: [{target: universal2-apple-darwin}, {target: x86_64-pc-windows-msvc}]}}}}' > "$dir/m.yml"
  out="$(python3.12 -c "$WHEEL_TRIPLES_PROGRAM" "$dir/m.yml" python-wheels | paste -sd' ' -)"
  same "$out" "x86_64-apple-darwin aarch64-apple-darwin x86_64-pc-windows-msvc"; expect "universal2 reads as both darwin triples" PASS $?
  printf '%s\n' 'jobs: {python-wheels: {strategy: {matrix: {os: [a], include: [{target: x}]}}}}' > "$dir/bad.yml"
  python3.12 -c "$WHEEL_TRIPLES_PROGRAM" "$dir/bad.yml" python-wheels >/dev/null 2>&1; expect "a matrix axis beside include FAILS" FAIL $?

  # A fake cargo that records its arguments and prints openssl-src for a graph naming
  # vendored-openssl on a triple other than $FAKE_DROPPED or naming a $FAKE_VENDORS word.
  printf '%s\n' '#!/bin/sh' 'printf "%s\n" "$*" >> "$ARGV_LOG"' '[ -n "$FAKE_BROKEN" ] && exit 101' 'echo "pkg v0.1.0"' \
    'for w in $FAKE_VENDORS; do case " $* " in *" $w "*) echo "openssl-src v300.5.1";; esac; done' \
    'case " $* " in *" --target all "*|*" --target $FAKE_DROPPED "*) ;; *vendored-openssl*) echo "openssl-src v300.5.1";; esac' > "$dir/bin/cargo"
  chmod +x "$dir/bin/cargo"
  export ARGV_LOG="$dir/argv" FAKE_DROPPED=none FAKE_VENDORS="" FAKE_BROKEN=""
  PATH="$dir/bin:$saved_path"
  wheel_triple_occurrences aarch64-apple-darwin scp-ffi --features a,b >/dev/null
  same "$(cat "$ARGV_LOG")" "tree -p scp-ffi --features a,b --target aarch64-apple-darwin -e no-dev --prefix none --format {p}"
  expect "the presence call resolves the one triple with build edges" PASS $?
  FAKE_BROKEN=1 all_target_occurrences --workspace >/dev/null 2>&1; expect "a cargo that exits non-zero FAILS rather than counting zero" FAIL $?

  # run_gate against a planted owner gate and matrix.
  wheel="$(printf 'bindings/python/pyproject.toml\tscp-ffi|--features extension-module,vendored-openssl')"
  printf '%s\n' '#!/usr/bin/env bash' 'case "$1" in' \
    "  --print-wheel-entries) printf '%s\n' $(printf '%q' "$wheel") ;;" \
    "  --print-artifacts) printf '%s\n' 'scp-node|' 'scp-ffi|--no-default-features --features server' $(printf '%q' "${wheel#*$'\t'}") ;;" \
    'esac' > "$dir/gate.sh"
  scenario() { # <label> <want>
    out="$(FEATURE_GRAPH_GATE="$dir/gate.sh" WHEEL_MATRIX_FILE="$dir/m.yml" run_gate 2>&1)"; expect "$1" "$2" $?
  }
  scenario "run_gate PASSES when only the wheel vendors" PASS
  FAKE_DROPPED=x86_64-pc-windows-msvc scenario "(presence) run_gate FAILS when one wheel triple reaches no $VENDOR_CRATE" FAIL
  printf '%s\n' "$out" | grep -F "FAIL — x86_64-pc-windows-msvc reaches 0" >/dev/null; expect "(presence) it names that triple" PASS $?
  FAKE_VENDORS=scp-node scenario "(absence) run_gate FAILS when another shipped configuration reaches $VENDOR_CRATE" FAIL
  printf '%s\n' "$out" | grep -F "FAIL — scp-node| reaches 1" >/dev/null; expect "(absence) it names scp-node" PASS $?
  FAKE_VENDORS=--workspace scenario "(absence) run_gate FAILS when a workspace resolution reaches $VENDOR_CRATE" FAIL
  PATH="$saved_path"; rm -rf "$dir"
  [[ "$fixture_failures" -eq 0 ]] && echo "   FIXTURES: all passed." && return 0
  echo "   FIXTURES: $fixture_failures failed."; return 1
}

echo "==> vendored-OpenSSL scope: $VENDOR_CRATE reaches the PyPI wheel and nothing else this repository ships"
run_fixtures || exit 1
[[ "${1:-}" == "--self-test" ]] && exit 0
run_gate
