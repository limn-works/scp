#!/usr/bin/env bash
# Vendored-OpenSSL scope gate. Usage: scripts/check-vendored-openssl-scope.sh [--self-test]
#
# CRITERION: `openssl-src`, the crate whose build script compiles OpenSSL so that
# `openssl-sys` links it statically, is in the dependency graph of the PyPI wheel's
# configuration, with libsqlite3-sys's `bundled-sqlcipher-vendored-openssl` feature on, on every
# target triple the `python-wheels` job of
# `.github/workflows/build-matrix.yml` builds, and in the graph of no other
# configuration this repository ships. `pip install` runs no linker, so the wheel
# has to carry SQLCipher's crypto; the scp-node, scp-relay and scp-personal-relay
# containers link the libssl3 their operators upgrade to patch OpenSSL.
#
# Presence: `wheel_triple_occurrences` runs one `cargo tree --target <triple>` per
# wheel triple, keeping build edges because `openssl-src` is a build-dependency of
# `openssl-sys`, and a second one, `-e no-dev,features -i libsqlite3-sys --depth 1`,
# that has to list libsqlite3-sys's `bundled-sqlcipher-vendored-openssl` feature,
# because only that feature makes SQLCipher compile against the vendored OpenSSL.
# `scripts/check-shipped-feature-graph.sh` exempts that one function from its rule
# that every `cargo tree` under scripts/ names `--target all` while
# this whole file hashes to the value it pins, so an edit anywhere in this file
# cancels the exemption, an edit to WHEEL_TRIPLES_PROGRAM, which lists the wheel
# triples, or to the `some` verdict run_gate wants from each per-triple count
# included. The function takes only the triple from its caller and reads the
# package and features from wheel_line, which runs the script FEATURE_GRAPH_GATE
# names. The file ends with the lines that run this
# gate: run_fixtures in a subshell, whose planted-gate overrides cannot reach the
# parent, then run_gate. The pin
# holds this file's text and not what it reads or runs: WHEEL_MATRIX_FILE, the
# gate FEATURE_GRAPH_GATE names, and the environment bash runs in, where a
# function exported into the environment, or a PATH entry, that carries the name
# of any command this file runs replaces that command. Those commands include
# cargo, bash and grep; python3.12, which runs the parsers that yield the wheel
# triples and the workspace roots; and git, which lists the manifests.
# Absence: `--target all` for every entry that gate's `--print-artifacts` writes
# except the wheel's (`--print-wheel-entries`), which that list must name exactly
# once beside at least one other entry, and `--workspace` for every
# Cargo.toml, tracked or untracked but not ignored by git, that cargo treats as a
# workspace root: one that declares a `workspace` table
# (the root workspace and each separately-workspaced template or scaffold,
# `templates/personal-relay` among them), and a package that no enclosing workspace
# claims, because none sits above it or each one above lists it under `exclude`. A
# new workspace root is so resolved without anyone listing it. The one exclusion is
# NOT_SHIPPED_ROOTS below. Every resolution reads the versions the root Cargo.lock
# pins: the root workspace's under --locked, and a root without a git-tracked Cargo.lock
# of its own through workspace_occurrences, which fails when that root needs a version
# the root Cargo.lock does not pin.
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

# Exits non-zero when the Cargo.lock argv[1] names pins a registry package, by name,
# version and source, that the Cargo.lock argv[2] names does not pin.
read -r -d '' LOCK_SUBSET_PROGRAM <<'PYTHON' || true
import sys, tomllib
pins = lambda path: {(p["name"], p["version"], p["source"]) for p in tomllib.load(open(path, "rb")).get("package", []) if "source" in p}
extra = sorted(pins(sys.argv[1]) - pins(sys.argv[2]))
if extra:
    sys.exit(f"{sys.argv[1]} pins {len(extra)} registry package(s) {sys.argv[2]} does not, {extra[0][0]} {extra[0][1]} first")
PYTHON

# workspace_occurrences <root manifest>: the every-triple count for the workspace that
# manifest heads, resolved from versions the root Cargo.lock pins. A root whose own
# Cargo.lock git tracks resolves under --locked. A root without one (each scaffold and
# template ignores its own) resolves from a copy of the root Cargo.lock, so cargo keeps
# each version that copy pins. An untracked Cargo.lock already there (a local build's,
# or one a killed run left) is set aside for the resolution, never read, and the subshell
# body puts it back on exit, or removes the copy when there was none. The lock the
# resolution leaves must then pin no registry package the root Cargo.lock does not, so a
# version the crates.io index chose on the day of the run fails the count instead of
# deciding it.
workspace_occurrences() (
  lock="${1%Cargo.toml}Cargo.lock"; locked=--locked
  if ! git ls-files --error-unmatch -- "$lock" >/dev/null 2>&1; then
    locked=""; saved="$(mktemp)"
    if [[ -e "$lock" ]]; then cp -p "$lock" "$saved"; trap 'mv -f "$saved" "$lock"' EXIT
    else trap 'rm -f "$lock" "$saved"' EXIT; fi
    cp Cargo.lock "$lock"
  fi
  n="$(all_target_occurrences ${locked:+"$locked"} --manifest-path "$1" --workspace)" || exit 1
  py -c "$LOCK_SUBSET_PROGRAM" "$lock" Cargo.lock || exit 1
  echo "$n"
)

# manifest_paths: every Cargo.toml git tracks that the working tree still holds, plus
# every one in the working tree that git does not ignore, so an uncommitted new
# workspace root is resolved too and an uncommitted deletion leaves no path that
# WORKSPACE_ROOTS_PROGRAM fails to open. `--cached` lists index entries whether or
# not the file exists, so the loop drops each path that is not a regular file.
manifest_paths() {
  local path
  git ls-files --cached --others --exclude-standard -- 'Cargo.toml' '*/Cargo.toml' |
    while IFS= read -r path; do if [[ -f "$path" ]]; then printf '%s\n' "$path"; fi; done
}

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
      n="$(all_target_occurrences --locked -p "${entry%%|*}" ${args[@]+"${args[@]}"})" || n=""
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
    n="$(workspace_occurrences "$entry")" || n=""
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
  # It answers `-i libsqlite3-sys` with libsqlite3-sys's `openssl-sys` feature, and with
  # its `bundled-sqlcipher-vendored-openssl` feature unless $FAKE_NO_FEATURE, so that
  # fixture holds the libsqlite3-sys -> openssl-sys edge without the feature.
  printf '%s\n' '#!/bin/sh' 'printf "%s\n" "$*" >> "$ARGV_LOG"' '[ -n "$FAKE_BROKEN" ] && exit 101' \
    '[ -z "$FAKE_DRIFT" ] || printf "[[package]]\nname = \"drift\"\nversion = \"9.9.9\"\nsource = \"registry+x\"\n" >> "$FAKE_DRIFT"' \
    'case " $* " in *" -i libsqlite3-sys "*) echo "libsqlite3-sys v0.30.1"; echo "libsqlite3-sys feature \"openssl-sys\""; [ -n "$FAKE_NO_FEATURE" ] || echo "libsqlite3-sys feature \"bundled-sqlcipher-vendored-openssl\""; exit 0;; esac' \
    'echo "pkg v0.1.0"' \
    'for w in $FAKE_VENDORS; do case " $* " in *" $w "*) echo "openssl-src v300.5.1";; esac; done' \
    'case " $* " in *" --target all "*|*" --target $FAKE_DROPPED "*) ;; *vendored-openssl*) echo "openssl-src v300.5.1";; esac' > "$dir/bin/cargo"
  chmod +x "$dir/bin/cargo"
  export ARGV_LOG="$dir/argv" FAKE_DROPPED=none FAKE_VENDORS="" FAKE_BROKEN="" FAKE_NO_FEATURE=""
  PATH="$dir/bin:$saved_path"
  FAKE_BROKEN=1 all_target_occurrences --workspace >/dev/null 2>&1; expect "a cargo that exits non-zero FAILS rather than counting zero" FAIL $?
  mkdir -p "$dir/ws/own" "$dir/ws/bare"; printf '%s\n' '[[package]]' 'name = "a"' 'version = "1.0.0"' 'source = "registry+x"' > "$dir/ws/Cargo.lock"
  cp "$dir/ws/Cargo.lock" "$dir/ws/own/Cargo.lock"; : > "$ARGV_LOG"
  (cd "$dir/ws" && unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE && git init -q && git add Cargo.lock own/Cargo.lock)
  (cd "$dir/ws" && unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE && workspace_occurrences bare/Cargo.toml && workspace_occurrences own/Cargo.toml) >/dev/null
  same "$(cut -d' ' -f1-3 "$ARGV_LOG" | paste -sd'|' -)" "tree --manifest-path bare/Cargo.toml|tree --locked --manifest-path"
  expect "a root without a Cargo.lock resolves from a copy of the root one, and a root whose own git tracks resolves under --locked" PASS $?
  [[ ! -e "$dir/ws/bare/Cargo.lock" && -e "$dir/ws/own/Cargo.lock" ]]; expect "the copied Cargo.lock is removed and a root's own is kept" PASS $?
  (cd "$dir/ws" && unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE && FAKE_DRIFT=bare/Cargo.lock workspace_occurrences bare/Cargo.toml) >/dev/null 2>&1
  expect "a resolution that pins a registry package the root Cargo.lock does not FAILS" FAIL $?
  # An untracked stale lock pins a package the root Cargo.lock does not: read under
  # --locked it would fail the subset check, so a pass proves it was set aside.
  printf '%s\n' '[[package]]' 'name = "stale"' 'version = "0.0.1"' 'source = "registry+x"' > "$dir/ws/bare/Cargo.lock"
  : > "$ARGV_LOG"; (cd "$dir/ws" && unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE && workspace_occurrences bare/Cargo.toml) >/dev/null 2>&1
  expect "a root holding an untracked Cargo.lock resolves from a copy of the root one, not from that lock" PASS $?
  same "$(cut -d' ' -f1-3 "$ARGV_LOG")" "tree --manifest-path bare/Cargo.toml"; expect "it resolves without --locked" PASS $?
  grep -qF '"stale"' "$dir/ws/bare/Cargo.lock"; expect "the untracked Cargo.lock is put back afterwards" PASS $?
  rm -f "$dir/ws/bare/Cargo.lock"

  # run_gate against a planted owner gate and matrix.
  wheel="$(printf 'bindings/python/pyproject.toml\tscp-ffi|--features extension-module,vendored-openssl')"
  printf '%s\n' '#!/usr/bin/env bash' 'case "$1" in' \
    "  --print-wheel-entries) printf '%s\n' $(printf '%q' "$wheel") ;;" \
    "  --print-artifacts) if [ -n \"\${FAKE_ARTIFACTS+x}\" ]; then printf '%s\n' \"\$FAKE_ARTIFACTS\"; else printf '%s\n' 'scp-node|' 'scp-ffi|--no-default-features --features server' $(printf '%q' "${wheel#*$'\t'}"); fi ;;" \
    'esac' > "$dir/gate.sh"
  local want_argv
  want_argv="$(printf '%s\n' "tree --locked -p scp-ffi --features extension-module,vendored-openssl --target aarch64-apple-darwin -e no-dev --prefix none --format {p}" \
    "tree --locked -p scp-ffi --features extension-module,vendored-openssl --target aarch64-apple-darwin -e no-dev,features -i libsqlite3-sys --depth 1 --prefix none --format {p}")"
  : > "$ARGV_LOG"
  FEATURE_GRAPH_GATE="$dir/gate.sh" wheel_triple_occurrences aarch64-apple-darwin >/dev/null
  same "$(cat "$ARGV_LOG")" "$want_argv"
  expect "the presence calls resolve the wheel entry on the one triple, with build edges and then libsqlite3-sys's enabled features" PASS $?
  : > "$ARGV_LOG"
  FEATURE_GRAPH_GATE="$dir/gate.sh" wheel_triple_occurrences aarch64-apple-darwin scp-node --no-default-features >/dev/null
  same "$(cat "$ARGV_LOG")" "$want_argv"
  expect "a caller's package and feature arguments do not reach the one-triple resolution" PASS $?
  scenario() { # <label> <want>
    out="$(FEATURE_GRAPH_GATE="$dir/gate.sh" WHEEL_MATRIX_FILE="$dir/m.yml" run_gate 2>&1)"; expect "$1" "$2" $?
  }
  scenario "run_gate PASSES when only the wheel vendors" PASS
  FAKE_DROPPED=x86_64-pc-windows-msvc scenario "(presence) run_gate FAILS when one wheel triple reaches no $VENDOR_CRATE" FAIL
  printf '%s\n' "$out" | grep -F "FAIL — x86_64-pc-windows-msvc reaches 0" >/dev/null; expect "(presence) it names that triple" PASS $?
  FAKE_NO_FEATURE=1 scenario "(presence) run_gate FAILS when $VENDOR_CRATE reaches the wheel and libsqlite3-sys depends on openssl-sys without bundled-sqlcipher-vendored-openssl" FAIL
  printf '%s\n' "$out" | grep -F "libsqlite3-sys's bundled-sqlcipher-vendored-openssl feature is off" >/dev/null; expect "(presence) it names the missing SQLCipher feature" PASS $?
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
  mkdir -p "$dir/g/new" "$dir/g/skip" "$dir/g/gone"; printf '%s\n' skip/ > "$dir/g/.gitignore"
  cp "$dir/w/member/Cargo.toml" "$dir/g/new/Cargo.toml"; cp "$dir/w/member/Cargo.toml" "$dir/g/skip/Cargo.toml"
  cp "$dir/w/member/Cargo.toml" "$dir/g/gone/Cargo.toml"
  out="$(cd "$dir/g" && unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE && git init -q && git add gone/Cargo.toml &&
    rm gone/Cargo.toml && manifest_paths | paste -sd' ' -)"
  same "$out" "new/Cargo.toml"
  expect "an untracked manifest is listed; an ignored one, and a tracked one the working tree deleted, are not" PASS $?
  printf '%s\n' '[workspace' > "$dir/c.toml"
  echo "$dir/c.toml" | py -c "$WORKSPACE_ROOTS_PROGRAM" >/dev/null 2>&1; expect "an unparseable manifest FAILS" FAIL $?
  PATH="$saved_path"; rm -rf "$dir"
  [[ "$fixture_failures" -eq 0 ]] && echo "   FIXTURES: all passed." && return 0
  echo "   FIXTURES: $fixture_failures failed."; return 1
}

# The owner gate pins this whole file (see the header). The function below holds the
# two per-triple `cargo tree` calls its `--target all` rule exempts.
#
# wheel_triple_occurrences <triple>: how many `openssl-src` the wheel's graph on one
# triple holds, or 0 when libsqlite3-sys's `bundled-sqlcipher-vendored-openssl` feature
# is off there. The package and features come from wheel_line, never from the caller's
# arguments. A cargo failure fails the count. libsqlite3-sys 0.30's build script
# compiles SQLCipher against openssl-sys's headers only under that feature; otherwise
# it links the build host's OpenSSL. The libsqlite3-sys -> openssl-sys edge proves
# nothing: libsqlite3-sys declares openssl-sys optional without `dep:`, so its implicit
# `openssl-sys` feature makes the same edge. So an `openssl-src` in the graph counts 0
# unless that feature is on.
wheel_triple_occurrences() {
  local triple="$1" entry tree features
  local -a args=()
  entry="$(wheel_line)" || return 1
  entry="${entry#*$'\t'}"
  read -r -a args <<<"${entry#*|}"
  tree="$(cargo tree --locked -p "${entry%%|*}" ${args[@]+"${args[@]}"} --target "$triple" -e no-dev --prefix none --format '{p}')" ||
    { echo "cargo tree failed for ${entry%%|*} on $triple" >&2; return 1; }
  if [[ "$(count_in "$tree")" -gt 0 ]]; then
    features="$(cargo tree --locked -p "${entry%%|*}" ${args[@]+"${args[@]}"} --target "$triple" -e no-dev,features -i libsqlite3-sys --depth 1 --prefix none --format '{p}')" ||
      { echo "cargo tree -i libsqlite3-sys failed for ${entry%%|*} on $triple" >&2; return 1; }
    if ! printf '%s\n' "$features" | grep -xF 'libsqlite3-sys feature "bundled-sqlcipher-vendored-openssl"' >/dev/null; then
      echo "$triple: $VENDOR_CRATE is in the wheel's graph, but libsqlite3-sys's bundled-sqlcipher-vendored-openssl feature is off, so SQLCipher links the build host's OpenSSL" >&2
      tree=""
    fi
  fi
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

echo "==> vendored-OpenSSL scope: $VENDOR_CRATE reaches the PyPI wheel's configuration and no other configuration this repository ships"
# The fixtures run in a subshell, so a definition or assignment they make cannot
# reach run_gate.
( run_fixtures ) || exit 1
[[ "${1:-}" == "--self-test" ]] && exit 0
run_gate
