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
# from its rule that every `cargo tree` under scripts/ names `--target all`, and it
# holds the function's text to a pinned hash, so an edit to the function cancels the
# exemption. The function takes only the triple from its caller and reads the
# package and features from wheel_line, which runs the script FEATURE_GRAPH_GATE
# names. This file sets FEATURE_GRAPH_GATE to that owner gate, and only
# run_fixtures overrides it, with a planted gate. The pin holds neither wheel_line
# nor FEATURE_GRAPH_GATE, so a call that overrides FEATURE_GRAPH_GATE or redefines
# wheel_line resolves another configuration on one triple and still passes the
# owner gate's rule; review of this file is what keeps every call of the function
# the wheel's presence proof.
# Absence: `--target all` for every entry that gate's `--print-artifacts` writes
# except the wheel's (`--print-wheel-entries`), and `--workspace` for every tracked
# Cargo.toml cargo treats as a workspace root: one that declares a `workspace` table
# (the root workspace and each separately-workspaced template or scaffold,
# `templates/personal-relay` among them), and a package that no enclosing workspace
# claims, because none sits above it or each one above lists it under `exclude`. A
# new workspace root is so resolved without anyone listing it. The one exclusion is
# NOT_SHIPPED_ROOTS below.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

VENDOR_CRATE="openssl-src"
FEATURE_GRAPH_GATE="scripts/check-shipped-feature-graph.sh"
WHEEL_MATRIX_FILE=".github/workflows/build-matrix.yml"
# `fuzz/Cargo.toml` builds libFuzzer harnesses that no release or template ships,
# and it resolves only under the nightly `fuzz/rust-toolchain.toml` pins.
NOT_SHIPPED_ROOTS="fuzz/Cargo.toml"

# Prints each manifest path, one per stdin line, that cargo treats as a workspace root:
# its TOML document holds a `workspace` table, or it holds a `package` table without
# `package.workspace` and no manifest above it in the input holds a `workspace` table
# whose `exclude` list leaves it out, which is cargo's ancestor search. tomllib decides,
# so `[workspace]`, `[ "workspace" ]` and `workspace = {}` all count, and an
# unparseable manifest fails the run.
read -r -d '' WORKSPACE_ROOTS_PROGRAM <<'PYTHON' || true
import os, sys, tomllib
docs = {}
for path in sys.stdin.read().splitlines():
    try:
        docs[path] = tomllib.load(open(path, "rb"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        sys.exit(f"{path}: {error}")
def claimed(path):
    here = d = os.path.dirname(path)
    while d != os.path.dirname(d) or d == "":
        d = os.path.dirname(d)
        ws = docs.get(os.path.join(d, "Cargo.toml"), {}).get("workspace")
        if isinstance(ws, dict):
            rel = os.path.relpath(here, d or ".").split(os.sep)
            if not any(rel[:len(e)] == e for e in (os.path.normpath(x).split(os.sep) for x in ws.get("exclude", []))):
                return True
        if d == "":
            return False
    return False
for path, doc in docs.items():
    if "workspace" in doc or ("package" in doc and "workspace" not in doc["package"] and not claimed(path)):
        print(path)
PYTHON

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
# --no-default-features, --all-features, or --features <value>. A resolver flag such
# as `--prune openssl-src` would otherwise empty the graph this gate counts, so a
# flag-shaped token fails in the value slot too. The value's feature-name grammar is
# cargo's to check: a malformed list fails `cargo tree`, and the count then fails.
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

# count_in <tree>: how many `openssl-src` lines a `cargo tree --prefix none` graph holds.
count_in() { printf '%s\n' "$1" | grep -cE "^${VENDOR_CRATE} v" || true; }

# wheel_line: the one `<pyproject path>\t<package>|<feature arguments>` line the
# owner gate's `--print-wheel-entries` writes, after checking that it is one line
# whose arguments are a feature selection. A print mode that exits non-zero fails,
# so a partial list is never read.
wheel_line() {
  local line
  line="$(bash "$FEATURE_GRAPH_GATE" --print-wheel-entries)" || return 1
  [[ "$(printf '%s\n' "$line" | grep -c .)" -eq 1 ]] || { echo "FAIL — expected one wheel entry, got: $line" >&2; return 1; }
  is_feature_selection "${line#*|}" || return 1
  printf '%s\n' "$line"
}

# wheel_triple_occurrences <triple>: the wheel's graph on one triple. The package
# and features come from wheel_line, never from the caller's arguments. The owner
# gate exempts this function from its `--target all` rule while the function's
# text hashes to the value it pins; the header above states what that pin does
# not hold. A cargo failure fails the count.
wheel_triple_occurrences() {
  local triple="$1" entry tree
  local -a args=()
  entry="$(wheel_line)" || return 1
  entry="${entry#*$'\t'}"
  read -r -a args <<<"${entry#*|}"
  tree="$(cargo tree -p "${entry%%|*}" ${args[@]+"${args[@]}"} --target "$triple" -e no-dev --prefix none --format '{p}')" ||
    { echo "cargo tree failed for ${entry%%|*} on $triple" >&2; return 1; }
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
  line="$(wheel_line)" || return 1
  wheel_file="${line%%$'\t'*}"; wheel_entry="${line#*$'\t'}"
  line="$(python3.12 -c "$WHEEL_TRIPLES_PROGRAM" "$WHEEL_MATRIX_FILE" python-wheels)" || return 1
  echo "--> the wheel, $wheel_entry from $wheel_file, on each triple it ships for"
  while IFS= read -r triple; do
    n="$(wheel_triple_occurrences "$triple")" || n=""
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
  line="$(git ls-files -- 'Cargo.toml' '*/Cargo.toml' | python3.12 -c "$WORKSPACE_ROOTS_PROGRAM")" || return 1
  [[ -n "$line" ]] || { echo "FAIL — no tracked Cargo.toml declares a workspace"; return 1; }
  while IFS= read -r entry; do
    [[ " $NOT_SHIPPED_ROOTS " == *" $entry "* ]] && continue
    n="$(all_target_occurrences --manifest-path "$entry" --workspace)" || n=""
    report "the $entry workspace" "$n" none || failures=$((failures + 1))
  done <<<"$line"
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
  is_feature_selection '--features --prune=openssl-src' 2>/dev/null; expect "a resolver flag in the feature-list slot FAILS" FAIL $?
  is_feature_selection '--no-default-features --features extension-module,scp-platform/vendored-openssl' 2>/dev/null; expect "a feature selection PASSES" PASS $?
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
  FAKE_BROKEN=1 all_target_occurrences --workspace >/dev/null 2>&1; expect "a cargo that exits non-zero FAILS rather than counting zero" FAIL $?

  # run_gate against a planted owner gate and matrix.
  wheel="$(printf 'bindings/python/pyproject.toml\tscp-ffi|--features extension-module,vendored-openssl')"
  printf '%s\n' '#!/usr/bin/env bash' 'case "$1" in' \
    "  --print-wheel-entries) printf '%s\n' $(printf '%q' "$wheel") ;;" \
    "  --print-artifacts) printf '%s\n' 'scp-node|' 'scp-ffi|--no-default-features --features server' $(printf '%q' "${wheel#*$'\t'}") ;;" \
    'esac' > "$dir/gate.sh"
  : > "$ARGV_LOG"
  FEATURE_GRAPH_GATE="$dir/gate.sh" wheel_triple_occurrences aarch64-apple-darwin >/dev/null
  same "$(cat "$ARGV_LOG")" "tree -p scp-ffi --features extension-module,vendored-openssl --target aarch64-apple-darwin -e no-dev --prefix none --format {p}"
  expect "the presence call resolves the wheel entry on the one triple with build edges" PASS $?
  : > "$ARGV_LOG"
  FEATURE_GRAPH_GATE="$dir/gate.sh" wheel_triple_occurrences aarch64-apple-darwin scp-node --no-default-features >/dev/null
  same "$(cat "$ARGV_LOG")" "tree -p scp-ffi --features extension-module,vendored-openssl --target aarch64-apple-darwin -e no-dev --prefix none --format {p}"
  expect "a caller's package and feature arguments do not reach the one-triple resolution" PASS $?
  scenario() { # <label> <want>
    out="$(FEATURE_GRAPH_GATE="$dir/gate.sh" WHEEL_MATRIX_FILE="$dir/m.yml" run_gate 2>&1)"; expect "$1" "$2" $?
  }
  scenario "run_gate PASSES when only the wheel vendors" PASS
  FAKE_DROPPED=x86_64-pc-windows-msvc scenario "(presence) run_gate FAILS when one wheel triple reaches no $VENDOR_CRATE" FAIL
  printf '%s\n' "$out" | grep -F "FAIL — x86_64-pc-windows-msvc reaches 0" >/dev/null; expect "(presence) it names that triple" PASS $?
  FAKE_VENDORS=scp-node scenario "(absence) run_gate FAILS when another shipped configuration reaches $VENDOR_CRATE" FAIL
  printf '%s\n' "$out" | grep -F "FAIL — scp-node| reaches 1" >/dev/null; expect "(absence) it names scp-node" PASS $?
  # The absence loop skips the wheel entry by exact match. Vendoring the scp-ffi
  # bridge entry fails the run, so a skip widened to every scp-ffi entry goes red;
  # vendoring the wheel entry over every triple passes, so a removed skip goes red.
  FAKE_VENDORS=server scenario "(absence) run_gate FAILS when a non-wheel scp-ffi entry reaches $VENDOR_CRATE" FAIL
  printf '%s\n' "$out" | grep -F "FAIL — scp-ffi|--no-default-features --features server reaches 1" >/dev/null; expect "(absence) it names that scp-ffi entry" PASS $?
  FAKE_VENDORS=extension-module,vendored-openssl scenario "(absence) run_gate skips only the wheel entry, which reaches $VENDOR_CRATE over every triple" PASS
  FAKE_VENDORS=--workspace scenario "(absence) run_gate FAILS when a workspace resolution reaches $VENDOR_CRATE" FAIL
  FAKE_VENDORS=scaffolds/relay/Cargo.toml scenario "(absence) run_gate resolves a workspace root no list names" FAIL
  printf '%s\n' "$out" | grep -F "FAIL — the scaffolds/relay/Cargo.toml workspace reaches 1" >/dev/null; expect "(absence) it names that root" PASS $?
  grep -F -- "--manifest-path fuzz/Cargo.toml" "$ARGV_LOG" >/dev/null; expect "(absence) the not-shipped fuzz root is not resolved" FAIL $?
  mkdir -p "$dir/w/member" "$dir/w/out" "$dir/w/sub/in" "$dir/solo"
  printf '%s\n' '[ "workspace" ]' 'members = ["member"]' 'exclude = ["out", "sub"]' > "$dir/w/Cargo.toml"
  printf '%s\n' '[package]' 'name = "x"' > "$dir/w/member/Cargo.toml"
  cp "$dir/w/member/Cargo.toml" "$dir/w/out/Cargo.toml"; cp "$dir/w/member/Cargo.toml" "$dir/w/sub/in/Cargo.toml"
  cp "$dir/w/member/Cargo.toml" "$dir/solo/Cargo.toml"
  printf '%s\n' '[package]' 'name = "y"' 'workspace = ".."' > "$dir/w/sub/Cargo.toml"
  out="$(printf '%s\n' "$dir/w/Cargo.toml" "$dir/w/member/Cargo.toml" "$dir/w/out/Cargo.toml" "$dir/w/sub/in/Cargo.toml" "$dir/w/sub/Cargo.toml" "$dir/solo/Cargo.toml" |
    python3.12 -c "$WORKSPACE_ROOTS_PROGRAM" | paste -sd' ' -)"
  same "$out" "$dir/w/Cargo.toml $dir/w/out/Cargo.toml $dir/w/sub/in/Cargo.toml $dir/solo/Cargo.toml"
  expect "a quoted [ \"workspace\" ] header, an excluded package, and an unenclosed package count as roots; a member and a package.workspace pointer do not" PASS $?
  printf '%s\n' '[workspace' > "$dir/c.toml"
  echo "$dir/c.toml" | python3.12 -c "$WORKSPACE_ROOTS_PROGRAM" >/dev/null 2>&1; expect "an unparseable manifest FAILS" FAIL $?
  PATH="$saved_path"; rm -rf "$dir"
  [[ "$fixture_failures" -eq 0 ]] && echo "   FIXTURES: all passed." && return 0
  echo "   FIXTURES: $fixture_failures failed."; return 1
}

echo "==> vendored-OpenSSL scope: $VENDOR_CRATE reaches the PyPI wheel's configuration and no other configuration this repository ships"
run_fixtures || exit 1
[[ "${1:-}" == "--self-test" ]] && exit 0
run_gate
