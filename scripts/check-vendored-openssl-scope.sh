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
# from its rule that every `cargo tree` under scripts/ names `--target all` while
# this whole file hashes to the value it pins, so an edit anywhere in this file
# cancels the exemption, an edit to WHEEL_TRIPLES_PROGRAM, which lists the wheel
# triples, or to the `some` verdict run_gate wants from each per-triple count
# included. The function takes only the triple from its caller and reads the
# package and features from wheel_line, which runs the script FEATURE_GRAPH_GATE
# names. The file ends with the lines that run this
# gate: run_fixtures in a subshell, whose planted-gate overrides cannot reach the
# parent, then `readonly` on four functions and two variables, then run_gate. A
# call that sets FEATURE_GRAPH_GATE for itself fails on the readonly name. The pin
# holds this file's text and not what it reads or runs: WHEEL_MATRIX_FILE, the
# gate FEATURE_GRAPH_GATE names, and the environment bash runs in, where a
# function exported into the environment, or a PATH entry, named cargo, bash or
# grep replaces that command.
# Absence: `--target all` for every entry that gate's `--print-artifacts` writes
# except the wheel's (`--print-wheel-entries`), which that list must name exactly
# once beside at least one other entry, and `--workspace` for every
# Cargo.toml, tracked or untracked but not ignored by git, that cargo treats as a
# workspace root: one that declares a `workspace` table
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
# py runs every Python program below. `-P` keeps the working directory off sys.path,
# so no tomllib.py or yaml.py there replaces the parser the gate reads with.
py() { python3.12 -P "$@"; }

# Prints each manifest path, one per stdin line, that cargo treats as a workspace root:
# its TOML document holds a `workspace` table, or it holds a `package` table without
# `package.workspace` and cargo's ancestor search over the input finds no root for it.
# That search walks up and stops at the first manifest holding a `workspace` table whose
# `exclude` list does not leave the package out, or holding a `package.workspace`
# pointer. tomllib decides, so `[workspace]`, `[ "workspace" ]` and `workspace = {}`
# all count, and an unparseable manifest fails the run.
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
        anc = docs.get(os.path.join(d, "Cargo.toml"), {})
        ws = anc.get("workspace")
        if isinstance(ws, dict):
            rel = os.path.relpath(here, d or ".").split(os.sep)
            if not any(rel[:len(e)] == e for e in (os.path.normpath(x).split(os.sep) for x in ws.get("exclude", []))):
                return True
        elif isinstance(anc.get("package"), dict) and "workspace" in anc["package"]:
            return True
        if d == "":
            return False
    return False
for path, doc in docs.items():
    if "workspace" in doc or ("package" in doc and "workspace" not in doc["package"] and not claimed(path)):
        print(path)
PYTHON

# Prints the wheel triples of job argv[2] in workflow argv[1], reading maturin's
# `universal2-apple-darwin` as both darwin triples. It fails on a matrix holding any
# key beside `include:` and on an item whose `target` is not one bare triple, so no leg
# drops out of the presence proof. A duplicated key needs no check here: GitHub Actions
# refuses to load such a workflow, so it runs no leg.
read -r -d '' WHEEL_TRIPLES_PROGRAM <<'PYTHON' || true
import re, sys, yaml
doc = yaml.safe_load(open(sys.argv[1], encoding="utf-8")) or {}
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

# all_target_occurrences <cargo tree argument>...: a graph over every triple. A
# cargo failure fails the count, because zero is the verdict absence passes on.
all_target_occurrences() {
  local tree
  tree="$(cargo tree "$@" -e no-dev --target all --prefix none --format '{p}')" ||
    { echo "cargo tree $* failed" >&2; return 1; }
  count_in "$tree"
}

# manifest_paths: every Cargo.toml git tracks, plus every one in the working tree
# that git does not ignore, so an uncommitted new workspace root is resolved too.
manifest_paths() { git ls-files --cached --others --exclude-standard -- 'Cargo.toml' '*/Cargo.toml'; }

# report <label> <count or empty on failure> <want: some|none>: one verdict line.
report() {
  if [[ -z "$2" ]]; then echo "    FAIL — $1 resolved no graph"; return 1; fi
  if [[ "$3" == some && "$2" -gt 0 ]] || [[ "$3" == none && "$2" -eq 0 ]]; then echo "    ok   — $1"; return 0; fi
  echo "    FAIL — $1 reaches $2 $VENDOR_CRATE, and this gate wants $3."; return 1
}

run_gate() {
  local failures=0 resolved=0 wheel_seen=0 line wheel_file wheel_entry entry triple n
  local -a args=()
  line="$(wheel_line)" || return 1
  wheel_file="${line%%$'\t'*}"; wheel_entry="${line#*$'\t'}"
  line="$(py -c "$WHEEL_TRIPLES_PROGRAM" "$WHEEL_MATRIX_FILE" python-wheels)" || return 1
  echo "--> the wheel, $wheel_entry from $wheel_file, on each triple it ships for"
  while IFS= read -r triple; do
    n="$(wheel_triple_occurrences "$triple")" || n=""
    report "$triple" "$n" some || failures=$((failures + 1))
  done <<<"$line"

  echo "--> every other shipped configuration, over every triple"
  line="$(bash "$FEATURE_GRAPH_GATE" --print-artifacts)" || return 1
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
  line="$(manifest_paths | py -c "$WORKSPACE_ROOTS_PROGRAM")" || return 1
  [[ -n "$line" ]] || { echo "FAIL — no Cargo.toml declares a workspace"; return 1; }
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
  out="$(py -c "$WHEEL_TRIPLES_PROGRAM" "$dir/m.yml" python-wheels | paste -sd' ' -)"
  same "$out" "x86_64-apple-darwin aarch64-apple-darwin x86_64-pc-windows-msvc"; expect "universal2 reads as both darwin triples" PASS $?
  printf '%s\n' 'jobs: {python-wheels: {strategy: {matrix: {os: [a], include: [{target: x}]}}}}' > "$dir/bad.yml"
  py -c "$WHEEL_TRIPLES_PROGRAM" "$dir/bad.yml" python-wheels >/dev/null 2>&1; expect "a matrix axis beside include FAILS" FAIL $?
  printf '%s\n' 'jobs: {python-wheels: {strategy: {matrix: {include: [{target: x}, {runner: r}]}}}}' > "$dir/bad.yml"
  py -c "$WHEEL_TRIPLES_PROGRAM" "$dir/bad.yml" python-wheels >/dev/null 2>&1; expect "an include item with no target FAILS" FAIL $?
  printf '%s\n' 'jobs: {python-wheels: {strategy: {matrix: {include: [{target: "${{ inputs.t }}"}]}}}}' > "$dir/bad.yml"
  py -c "$WHEEL_TRIPLES_PROGRAM" "$dir/bad.yml" python-wheels >/dev/null 2>&1; expect "an expression target FAILS" FAIL $?
  printf '%s\n' 'import sys; sys.exit(0)' > "$dir/yaml.py"; printf '%s\n' 'def load(f): return {"workspace": {}}' > "$dir/tomllib.py"
  out="$(cd "$dir" && py -c "$WHEEL_TRIPLES_PROGRAM" m.yml python-wheels | paste -sd' ' -)"
  same "$out" "x86_64-apple-darwin aarch64-apple-darwin x86_64-pc-windows-msvc"; expect "a yaml.py in the working directory does not replace PyYAML" PASS $?
  out="$(cd "$dir" && printf '%s\n' "$dir/m.yml" | py -c "$WORKSPACE_ROOTS_PROGRAM" 2>/dev/null)"
  same "$out" ""; expect "a tomllib.py in the working directory does not replace tomllib" PASS $?
  rm -f "$dir/yaml.py" "$dir/tomllib.py"

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
    "  --print-artifacts) if [ -n \"\${FAKE_ARTIFACTS+x}\" ]; then printf '%s\n' \"\$FAKE_ARTIFACTS\"; else printf '%s\n' 'scp-node|' 'scp-ffi|--no-default-features --features server' $(printf '%q' "${wheel#*$'\t'}"); fi ;;" \
    'esac' > "$dir/gate.sh"
  : > "$ARGV_LOG"
  FEATURE_GRAPH_GATE="$dir/gate.sh" wheel_triple_occurrences aarch64-apple-darwin >/dev/null
  same "$(cat "$ARGV_LOG")" "tree -p scp-ffi --features extension-module,vendored-openssl --target aarch64-apple-darwin -e no-dev --prefix none --format {p}"
  expect "the presence call resolves the wheel entry on the one triple with build edges" PASS $?
  : > "$ARGV_LOG"
  FEATURE_GRAPH_GATE="$dir/gate.sh" wheel_triple_occurrences aarch64-apple-darwin scp-node --no-default-features >/dev/null
  same "$(cat "$ARGV_LOG")" "tree -p scp-ffi --features extension-module,vendored-openssl --target aarch64-apple-darwin -e no-dev --prefix none --format {p}"
  expect "a caller's package and feature arguments do not reach the one-triple resolution" PASS $?
  # The readonly lines at the end of this file, read from the file and run here in a
  # subshell: after them each pinned variable refuses a call's temporary assignment
  # and each pinned function refuses a redefinition. A readonly line deleted or
  # narrowed lets that override through, and its fixture goes red. A subshell whose
  # eval of those lines fails exits 0, so it cannot pass as a refused override.
  local ro name
  ro="$(grep -E '^readonly ' "${BASH_SOURCE[0]}")" || ro=""
  ( eval "$ro" ) >/dev/null 2>&1; expect "this file's readonly lines run" PASS $?
  ( eval "$ro" || exit 0; FEATURE_GRAPH_GATE="$dir/gate.sh" wheel_triple_occurrences aarch64-apple-darwin ) >/dev/null 2>&1
  expect "after this file's readonly lines, a call that overrides FEATURE_GRAPH_GATE FAILS" FAIL $?
  ( eval "$ro" || exit 0; VENDOR_CRATE=pkg count_in "pkg v0.1.0" ) >/dev/null 2>&1
  expect "after this file's readonly lines, a call that overrides VENDOR_CRATE FAILS" FAIL $?
  for name in wheel_triple_occurrences wheel_line is_feature_selection count_in; do
    ( eval "$ro" || exit 0; eval "$name() { :; }" ) >/dev/null 2>&1
    expect "after this file's readonly lines, a redefinition of $name FAILS" FAIL $?
  done
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
  FAKE_ARTIFACTS="" scenario "(absence) run_gate FAILS when --print-artifacts lists nothing" FAIL
  printf '%s\n' "$out" | grep -F "lists the wheel entry 0 time(s)" >/dev/null; expect "(absence) it names the missing wheel entry" PASS $?
  printf '%s\n' "$out" | grep -F "lists no shipped configuration besides the wheel" >/dev/null; expect "(absence) it names the empty list" PASS $?
  FAKE_ARTIFACTS='scp-node|' scenario "(absence) run_gate FAILS when --print-artifacts omits the wheel entry" FAIL
  FAKE_ARTIFACTS="$(printf '%s\n' "${wheel#*$'\t'}" 'scp-node|' "${wheel#*$'\t'}")" scenario "(absence) run_gate FAILS when --print-artifacts lists the wheel entry twice" FAIL
  FAKE_ARTIFACTS="${wheel#*$'\t'}" scenario "(absence) run_gate FAILS when --print-artifacts lists only the wheel entry" FAIL
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
    py -c "$WORKSPACE_ROOTS_PROGRAM" | paste -sd' ' -)"
  same "$out" "$dir/w/Cargo.toml $dir/w/out/Cargo.toml $dir/solo/Cargo.toml"
  expect "a quoted [ \"workspace\" ] header, an excluded package, and an unenclosed package count as roots; a member, a package.workspace pointer, and a package below that pointer do not" PASS $?
  mkdir -p "$dir/g/new" "$dir/g/skip"; printf '%s\n' skip/ > "$dir/g/.gitignore"
  cp "$dir/w/member/Cargo.toml" "$dir/g/new/Cargo.toml"; cp "$dir/w/member/Cargo.toml" "$dir/g/skip/Cargo.toml"
  out="$(cd "$dir/g" && unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE && git init -q && manifest_paths | paste -sd' ' -)"
  same "$out" "new/Cargo.toml"; expect "an untracked manifest is listed and an ignored one is not" PASS $?
  printf '%s\n' '[workspace' > "$dir/c.toml"
  echo "$dir/c.toml" | py -c "$WORKSPACE_ROOTS_PROGRAM" >/dev/null 2>&1; expect "an unparseable manifest FAILS" FAIL $?
  PATH="$saved_path"; rm -rf "$dir"
  [[ "$fixture_failures" -eq 0 ]] && echo "   FIXTURES: all passed." && return 0
  echo "   FIXTURES: $fixture_failures failed."; return 1
}

# The owner gate pins this whole file (see the header). The function below is the
# one per-triple `cargo tree` its `--target all` rule exempts.
#
# wheel_triple_occurrences <triple>: the wheel's graph on one triple. The package
# and features come from wheel_line, never from the caller's arguments. A cargo
# failure fails the count.
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

VENDOR_CRATE="openssl-src"
FEATURE_GRAPH_GATE="scripts/check-shipped-feature-graph.sh"
echo "==> vendored-OpenSSL scope: $VENDOR_CRATE reaches the PyPI wheel's configuration and no other configuration this repository ships"
# The fixtures run in a subshell, so a definition or assignment they make cannot
# reach run_gate. The readonly lines then fail any later assignment to these names,
# a temporary one on a call included, and any redefinition of these functions.
( run_fixtures ) || exit 1
[[ "${1:-}" == "--self-test" ]] && exit 0
readonly VENDOR_CRATE FEATURE_GRAPH_GATE
readonly -f wheel_triple_occurrences wheel_line is_feature_selection count_in
run_gate
