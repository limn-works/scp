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
# name exactly once beside at least one other entry, and every workspace root
# WORKSPACE_ROOTS lists except NOT_SHIPPED_ROOTS, each under `--workspace`, reach no
# `openssl-src` under `cargo tree --target all`.
#
# Roots: WORKSPACE_ROOTS is the one list of this repository's Cargo workspace roots. Each
# entry must be a directory `cargo metadata` names as its own workspace root, and every
# Cargo.toml git tracks must be an entry's manifest or a member `cargo metadata --no-deps`
# lists for an entry, so a new workspace root fails the run until it is listed.
#
# Locks: every resolution reads the versions the root Cargo.lock pins. The wheel entry,
# the artifact entries and the root workspace resolve in place under `--locked`. Each other
# root resolves in a temporary directory outside the tree, which holds the files git tracks
# under that root, symbolic links to everything else in the repository so its path
# dependencies resolve, and a copy of the root Cargo.lock in place of any Cargo.lock the
# root holds. After one `cargo fetch --locked` of the root workspace, `cargo tree
# --offline` without `--locked` trims that copy to the root's graph; the trimmed lock
# must pin no registry package the root Cargo.lock does not; and the count resolves
# under `--locked --offline`.
# No Cargo.lock in such a root's directory, tracked or not, is read, and nothing is written
# into the tree.
#
# Presence resolves the union over every target triple, so it proves the wheel's
# configuration reaches `openssl-src` on some triple, not on each triple the wheel ships
# for.
#
# The gate fails closed: a print mode that exits non-zero, a wheel answer that is not one
# `<file><TAB><package>|<arguments>` line, an entry whose arguments are not a feature
# selection, and a cargo, git, python3.12, mktemp or copy step that exits non-zero each
# fail the run, because zero `openssl-src` is the count absence passes on.
#
# run_gate calls bash, cargo, git, grep, python3.12, cp, ln, mkdir, mktemp and rm, and the
# print modes of the gate above, which run python3.12. A PATH entry or an exported function
# carrying one of those names replaces it.
set -euo pipefail

# Resolved before the cd, so a relative invocation path keeps naming this repository, and
# with symbolic links resolved, so it matches the manifest paths `cargo metadata` prints.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$REPO_ROOT"

VENDOR_CRATE="openssl-src"
SQLCIPHER_FEATURE="bundled-sqlcipher-vendored-openssl"
FEATURE_GRAPH_GATE="$REPO_ROOT/scripts/check-shipped-feature-graph.sh"
# Every Cargo workspace root in this repository, as a directory relative to its root.
WORKSPACE_ROOTS=(. scaffolds/relay scaffolds/rust-client templates/cross-context-bridge templates/personal-relay fuzz)
# The WORKSPACE_ROOTS entries absence does not resolve. `fuzz` builds libFuzzer harnesses
# that no release, scaffold or template ships.
NOT_SHIPPED_ROOTS=(fuzz)

# Exits non-zero when the Cargo.lock argv[1] names pins a registry package, by name,
# version and source, that the Cargo.lock argv[2] names does not pin. It runs under
# `python3.12 -P`, so no tomllib.py in the working directory replaces the parser.
read -r -d '' LOCK_SUBSET_PROGRAM <<'PYTHON' || true
import sys, tomllib
pins = lambda path: {(p["name"], p["version"], p["source"]) for p in tomllib.load(open(path, "rb")).get("package", []) if "source" in p}
extra = sorted(pins(sys.argv[1]) - pins(sys.argv[2]))
if extra:
    sys.exit(f"{sys.argv[1]} pins {len(extra)} registry package(s) {sys.argv[2]} does not, {extra[0][0]} {extra[0][1]} first")
PYTHON

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

# unlisted_manifests: print each Cargo.toml git tracks that is neither the manifest of a
# WORKSPACE_ROOTS entry nor a member `cargo metadata --no-deps` lists for one. It fails
# when it prints one, when git lists no manifest or exits non-zero, when `cargo metadata`
# exits non-zero for an entry, and when an entry is not the workspace root cargo reports
# for its own manifest. Paths compare relative to the working directory.
unlisted_manifests() {
  local top root rel json tracked covered="" path unlisted=0
  top="$(pwd -P)"
  tracked="$(git ls-files -- 'Cargo.toml' '*/Cargo.toml')" || { echo "git ls-files failed" >&2; return 1; }
  [[ -n "$tracked" ]] || { echo "git tracks no Cargo.toml" >&2; return 1; }
  for root in "${WORKSPACE_ROOTS[@]}"; do
    rel="Cargo.toml"; [[ "$root" == "." ]] || rel="$root/Cargo.toml"
    json="$(cargo metadata --no-deps --offline --format-version 1 --manifest-path "$rel")" ||
      { echo "cargo metadata failed for the WORKSPACE_ROOTS entry $root" >&2; return 1; }
    path="$top"; [[ "$root" == "." ]] || path="$top/$root"
    printf '%s\n' "$json" | grep -qF "\"workspace_root\":\"$path\"" ||
      { echo "the WORKSPACE_ROOTS entry $root is not a workspace root: cargo places $rel in another workspace" >&2; return 1; }
    covered+="$rel"$'\n'
    while IFS= read -r path; do
      path="${path#\"manifest_path\":\"}"; path="${path%\"}"
      covered+="${path#"$top"/}"$'\n'
    done < <(printf '%s\n' "$json" | grep -oE '"manifest_path":"[^"]*"')
  done
  while IFS= read -r path; do
    printf '%s' "$covered" | grep -qxF -- "$path" && continue
    echo "$path is neither the manifest of a WORKSPACE_ROOTS entry nor a member of one"
    unlisted=1
  done <<<"$tracked"
  [[ "$unlisted" -eq 0 ]]
}

# staged_occurrences <root>: the every-triple `openssl-src` count of the workspace the
# WORKSPACE_ROOTS entry <root> heads, resolved in a temporary directory from a copy of the
# root Cargo.lock (see "Locks" in the header). It needs the packages that lock pins in
# cargo's cache, which run_gate's `cargo fetch --locked` puts there. Every step that can
# change what cargo reads fails the count when it exits non-zero. A link or directory of
# the scaffolding that fails to appear is not checked here: a path dependency through it
# then fails the trim, a copy into it then fails, and a path nothing reaches changes
# no count. The subshell body removes the directory on exit.
staged_occurrences() (
  shopt -s nullglob dotglob
  root="$1"
  stage="$(mktemp -d)" || { echo "mktemp -d failed for $root" >&2; exit 1; }
  trap 'rm -rf "$stage"' EXIT
  base="$stage"; src="$REPO_ROOT"; rest="$root"
  while :; do
    part="${rest%%/*}"
    for entry in "$src"/*; do
      [[ "${entry##*/}" == "$part" ]] || ln -s "$entry" "$base/${entry##*/}"
    done
    mkdir "$base/$part"
    base="$base/$part"; src="$src/$part"
    [[ "$rest" == */* ]] || break
    rest="${rest#*/}"
  done
  files="$(git ls-files -- "$root/")" || { echo "git ls-files failed for $root" >&2; exit 1; }
  while IFS= read -r file; do
    [[ -z "$file" ]] && continue
    { mkdir -p "$stage/${file%/*}" && cp "$file" "$stage/$file"; } || { echo "could not copy $file" >&2; exit 1; }
  done <<<"$files"
  [[ -f "$stage/$root/Cargo.toml" ]] || { echo "git tracks no $root/Cargo.toml" >&2; exit 1; }
  cp Cargo.lock "$stage/$root/Cargo.lock" || { echo "could not copy the root Cargo.lock for $root" >&2; exit 1; }
  cargo tree --offline --manifest-path "$stage/$root/Cargo.toml" --depth 0 --target all >/dev/null ||
    { echo "cargo tree --offline could not trim the Cargo.lock copy for $root" >&2; exit 1; }
  python3.12 -P -c "$LOCK_SUBSET_PROGRAM" "$stage/$root/Cargo.lock" Cargo.lock || exit 1
  all_target_occurrences --offline --manifest-path "$stage/$root/Cargo.toml" --workspace
)

# report <label> <count, or empty on failure> <want: some|none>: one verdict line.
report() {
  if [[ -z "$2" ]]; then echo "    FAIL — $1 resolved no graph"; return 1; fi
  if [[ "$3" == some && "$2" -gt 0 ]] || [[ "$3" == none && "$2" -eq 0 ]]; then echo "    ok   — $1"; return 0; fi
  echo "    FAIL — $1 reaches $2 $VENDOR_CRATE, and this gate wants $3."; return 1
}

run_gate() {
  local failures=0 resolved=0 wheel_seen=0 line wheel_file wheel_entry entry n root
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

  echo "--> every workspace root WORKSPACE_ROOTS lists, which must name every root"
  if unlisted_manifests; then echo "    ok   — every Cargo.toml git tracks is a listed root or a member of one"
  else echo "    FAIL — WORKSPACE_ROOTS does not cover every Cargo.toml git tracks"; failures=$((failures + 1)); fi

  echo "--> the root workspace, over every triple"
  n="$(all_target_occurrences --workspace)" || n=""
  report "the root workspace" "$n" none || failures=$((failures + 1))

  echo "--> every other shipped workspace root, from a copy of the root Cargo.lock, over every triple"
  if cargo fetch --locked >/dev/null; then
    for root in "${WORKSPACE_ROOTS[@]}"; do
      [[ "$root" == "." || " ${NOT_SHIPPED_ROOTS[*]} " == *" $root "* ]] && continue
      n="$(staged_occurrences "$root")" || n=""
      report "the $root workspace" "$n" none || failures=$((failures + 1))
    done
  else
    echo "    FAIL — cargo fetch --locked failed, so no root resolves offline"; failures=$((failures + 1))
  fi

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

  # A fake cargo. It hands `cargo metadata --no-deps`, which unlisted_manifests runs, to
  # the cargo PATH named before the fake led it, unrecorded and with the fake's directory
  # removed from PATH, so a cargo wrapper that looks cargo up again through PATH cannot
  # reach the fake and loop. It records every other argument list. It exits 101 under
  # $FAKE_BROKEN or when its arguments hold the $FAKE_FAIL_ON word. A call holding
  # `--depth 0`, the lock trim, exits 101 when a $FAKE_NEED path is missing beside its
  # --manifest-path, copies the Cargo.lock there to $FAKE_SEEN_LOCK, appends a registry package to that lock under
  # $FAKE_DRIFT, and prints nothing; `cargo fetch` prints nothing. It answers
  # `-i libsqlite3-sys` with libsqlite3-sys's `openssl-sys` feature and, unless
  # $FAKE_NO_FEATURE, its `bundled-sqlcipher-vendored-openssl` feature, and otherwise
  # prints one openssl-src for each $FAKE_VENDORS word its arguments hold and one when they
  # contain $FAKE_VENDOR_PATH.
  printf '%s\n' '#!/bin/sh' \
    'if [ "$1" = metadata ]; then case " $* " in *" --no-deps "*)' \
    '  PATH="$(printf "%s" "$PATH" | tr ":" "\n" | grep -vxF "$FAKE_BIN" | paste -sd: -)" exec "$REAL_CARGO" "$@";; esac; fi' \
    'printf "%s\n" "$*" >> "$ARGV_LOG"' '[ -n "$FAKE_BROKEN" ] && exit 101' \
    'if [ -n "$FAKE_FAIL_ON" ]; then case " $* " in *" $FAKE_FAIL_ON "*) exit 101;; esac; fi' \
    'mp=""; prev=""; for a in "$@"; do [ "$prev" = --manifest-path ] && mp="$a"; prev="$a"; done' \
    'case " $* " in *" --depth 0 "*) for n in $FAKE_NEED; do [ -e "${mp%/Cargo.toml}/$n" ] || exit 101; done' \
    '  [ -z "$FAKE_SEEN_LOCK" ] || cp "${mp%Cargo.toml}Cargo.lock" "$FAKE_SEEN_LOCK"' \
    '  [ -z "$FAKE_DRIFT" ] || printf "[[package]]\nname = \"drift\"\nversion = \"9.9.9\"\nsource = \"registry+x\"\n" >> "${mp%Cargo.toml}Cargo.lock"' \
    '  exit 0;; esac' \
    '[ "$1" = fetch ] && exit 0' \
    'case " $* " in *" -i libsqlite3-sys "*) echo "libsqlite3-sys v0.30.1"; echo "libsqlite3-sys feature \"openssl-sys\""; [ -n "$FAKE_NO_FEATURE" ] || echo "libsqlite3-sys feature \"bundled-sqlcipher-vendored-openssl\""; exit 0;; esac' \
    'echo "pkg v0.1.0"' \
    'for w in $FAKE_VENDORS; do case " $* " in *" $w "*) echo "openssl-src v300.5.5+3.5.5";; esac; done' \
    'if [ -n "$FAKE_VENDOR_PATH" ]; then case "$*" in *"$FAKE_VENDOR_PATH"*) echo "openssl-src v300.5.5+3.5.5";; esac; fi' > "$dir/bin/cargo"
  chmod +x "$dir/bin/cargo"
  REAL_CARGO="$(command -v cargo)"
  export REAL_CARGO FAKE_BIN="$dir/bin" ARGV_LOG="$dir/argv" FAKE_BROKEN="" FAKE_FAIL_ON="" FAKE_NO_FEATURE="" FAKE_VENDORS="extension-module,vendored-openssl" \
    FAKE_NEED="" FAKE_SEEN_LOCK="" FAKE_DRIFT="" FAKE_VENDOR_PATH=""
  PATH="$dir/bin:$PATH"
  FAKE_BROKEN=1 all_target_occurrences --workspace >/dev/null 2>&1; expect "a cargo that exits non-zero FAILS rather than counting zero" FAIL $?

  # unlisted_manifests against a planted repository, with the real `cargo metadata`: a root
  # workspace with member a, and b and c, two packages that each declare a workspace. The
  # repository's toolchain file keeps that cargo on the pinned toolchain.
  local cov="$dir/cov" repo="$dir/repo" seen="$dir/seen.lock" before
  local -a roots_saved=("${WORKSPACE_ROOTS[@]}")
  mkdir -p "$cov/a/src" "$cov/b/src" "$cov/c/src" "$dir/notgit"
  printf '%s\n' '[workspace]' 'resolver = "2"' 'members = ["a"]' > "$cov/Cargo.toml"
  for n in a b c; do printf '%s\n' '[package]' "name = \"$n\"" 'version = "0.1.0"' 'edition = "2021"' > "$cov/$n/Cargo.toml"; : > "$cov/$n/src/lib.rs"; done
  printf '%s\n' '[workspace]' >> "$cov/b/Cargo.toml"; printf '%s\n' '[workspace]' >> "$cov/c/Cargo.toml"
  cp "$REPO_ROOT/rust-toolchain.toml" "$cov/"; cp "$cov/Cargo.toml" "$cov/rust-toolchain.toml" "$dir/notgit/"
  (cd "$cov" && unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE && git init -q && git add Cargo.toml a b c) || return 1
  # covered <repository> <root>...: unlisted_manifests in <repository>, with the roots given
  # in a WORKSPACE_ROOTS local to this call.
  covered() {
    local repo_dir="$1"; shift
    local -a WORKSPACE_ROOTS=("$@")
    (cd "$repo_dir" && unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE && unlisted_manifests 2>&1)
  }
  out="$(covered "$cov" . b c)"; expect "unlisted_manifests PASSES when every tracked manifest is a listed root or a member of one" PASS $?
  # A cargo wrapper that looks cargo up again through PATH, as a toolchain shim does, and
  # exits 99 when it is entered a second time in one call chain.
  printf '%s\n' '#!/bin/sh' '[ -z "$WRAPPED" ] || exit 99' 'WRAPPED=1 exec cargo "$@"' > "$dir/wrapcargo"
  chmod +x "$dir/wrapcargo"
  out="$(REAL_CARGO="$dir/wrapcargo" covered "$cov" . b c)"
  expect "unlisted_manifests PASSES through a cargo wrapper that looks cargo up through PATH" PASS $?
  out="$(covered "$cov" . b)"; expect "(roots) a workspace root WORKSPACE_ROOTS does not list FAILS" FAIL $?
  same "$out" "c/Cargo.toml is neither the manifest of a WORKSPACE_ROOTS entry nor a member of one"; expect "(roots) it names that manifest" PASS $?
  # Each failing case also checks its own message, so a guard deleted while a later one
  # still fails the run goes red here.
  hit() { printf '%s\n' "$out" | grep -F -- "$1" >/dev/null; }
  out="$(covered "$cov" . b c a)"; expect "(roots) a listed member of another workspace FAILS" FAIL $?
  hit "the WORKSPACE_ROOTS entry a is not a workspace root"; expect "(roots) it names that entry" PASS $?
  out="$(covered "$cov" . b c d)"; expect "(roots) a listed directory cargo metadata cannot read FAILS" FAIL $?
  hit "cargo metadata failed for the WORKSPACE_ROOTS entry d"; expect "(roots) it names the failed cargo metadata" PASS $?
  out="$(covered "$dir/notgit" .)"; expect "(roots) a git ls-files that exits non-zero FAILS" FAIL $?
  hit "git ls-files failed"; expect "(roots) it names the failed git ls-files" PASS $?
  (cd "$cov" && unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE && git rm -q --cached -r Cargo.toml a b c) || return 1
  out="$(covered "$cov" . b c)"; expect "(roots) a repository tracking no Cargo.toml FAILS" FAIL $?
  hit "git tracks no Cargo.toml"; expect "(roots) it names the empty manifest list" PASS $?

  # staged_occurrences against a planted repository whose root sub/root holds an untracked
  # Cargo.lock pinning a package the root Cargo.lock does not.
  mkdir -p "$repo/crates/dep" "$repo/sub/root/src" "$repo/sub/sibling" "$repo/sub/untracked"
  printf '%s\n' '[[package]]' 'name = "a"' 'version = "1.0.0"' 'source = "registry+x"' > "$repo/Cargo.lock"
  printf '%s\n' '[package]' 'name = "dep"' > "$repo/crates/dep/Cargo.toml"
  printf '%s\n' '[package]' 'name = "r"' '[workspace]' > "$repo/sub/root/Cargo.toml"; : > "$repo/sub/root/src/lib.rs"; : > "$repo/sub/sibling/x"
  cp "$repo/sub/root/Cargo.toml" "$repo/sub/untracked/Cargo.toml"
  (cd "$repo" && unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE && git init -q && git add Cargo.lock crates sub/root sub/sibling) || return 1
  printf '%s\n' '[[package]]' 'name = "stale"' 'version = "0.0.1"' 'source = "registry+x"' > "$repo/sub/root/Cargo.lock"
  before="$(cd "$repo" && git status --porcelain --ignored && cat sub/root/Cargo.lock)"
  staged() { (cd "$repo" && unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE && REPO_ROOT="$repo" && staged_occurrences "$1" 2>&1); }
  : > "$ARGV_LOG"
  out="$(FAKE_NEED="../../crates/dep/Cargo.toml ../sibling/x src/lib.rs" FAKE_SEEN_LOCK="$seen" staged sub/root)"
  expect "(lock) staged_occurrences resolves a root with its tracked files and its path dependencies' neighbours" PASS $?
  same "$out" 0; expect "(lock) it writes that root's count" PASS $?
  cmp -s "$seen" "$repo/Cargo.lock"; expect "(lock) the lock cargo trims is the root Cargo.lock, not the root's own untracked one" PASS $?
  same "$(sed -E 's#--manifest-path [^ ]*/sub/root/Cargo.toml#--manifest-path STAGE/sub/root/Cargo.toml#' "$ARGV_LOG")" "$(printf '%s\n' \
    "tree --offline --manifest-path STAGE/sub/root/Cargo.toml --depth 0 --target all" \
    "tree --locked --offline --manifest-path STAGE/sub/root/Cargo.toml --workspace -e no-dev --target all --prefix none --format {p}")"
  expect "(lock) it trims the copy offline, then counts under --locked --offline over every triple" PASS $?
  grep -F -- "--manifest-path $repo/" "$ARGV_LOG" >/dev/null; expect "(lock) it resolves outside the tree" FAIL $?
  same "$(cd "$repo" && git status --porcelain --ignored && cat sub/root/Cargo.lock)" "$before"; expect "(lock) it leaves the tree as it found it" PASS $?
  FAKE_DRIFT=1 staged sub/root >/dev/null; expect "(lock) a trimmed lock pinning a registry package the root Cargo.lock does not FAILS" FAIL $?
  printf '%s\n' 'def load(f): return {}' > "$repo/tomllib.py"
  FAKE_DRIFT=1 staged sub/root >/dev/null; expect "(lock) a tomllib.py in the working directory does not replace tomllib" FAIL $?
  rm -f "$repo/tomllib.py"
  out="$(FAKE_FAIL_ON=--depth staged sub/root)"; expect "(lock) a lock trim that exits non-zero FAILS" FAIL $?
  hit "could not trim the Cargo.lock copy for sub/root"; expect "(lock) it names the failed trim" PASS $?
  FAKE_FAIL_ON=--workspace staged sub/root >/dev/null; expect "(lock) a cargo tree that exits non-zero FAILS" FAIL $?
  out="$(staged sub/untracked)"; expect "(lock) a root whose Cargo.toml git does not track FAILS" FAIL $?
  hit "git tracks no sub/untracked/Cargo.toml"; expect "(lock) it names that manifest" PASS $?
  mkdir -p "$dir/failbin"; printf '%s\n' '#!/bin/sh' 'exit 1' > "$dir/failbin/mktemp"; chmod +x "$dir/failbin/mktemp"
  out="$(PATH="$dir/failbin:$PATH" staged sub/root)"; expect "(lock) a mktemp that exits non-zero FAILS" FAIL $?
  hit "mktemp -d failed for sub/root"; expect "(lock) it names the failed mktemp" PASS $?
  mkdir -p "$dir/notgit/sub"; cp "$dir/notgit/Cargo.toml" "$dir/notgit/sub/"
  out="$(cd "$dir/notgit" && unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE && REPO_ROOT="$dir/notgit" && staged_occurrences sub 2>&1)"
  expect "(lock) a git ls-files that exits non-zero FAILS" FAIL $?
  hit "git ls-files failed for sub"; expect "(lock) it names the failed git ls-files" PASS $?
  rm "$repo/sub/root/src/lib.rs"; out="$(staged sub/root)"; expect "(lock) a tracked file that cannot be copied FAILS" FAIL $?
  hit "could not copy sub/root/src/lib.rs"; expect "(lock) it names that file" PASS $?
  : > "$repo/sub/root/src/lib.rs"; mv "$repo/Cargo.lock" "$dir/root.lock"
  out="$(staged sub/root)"; expect "(lock) a root Cargo.lock that cannot be copied FAILS" FAIL $?
  hit "could not copy the root Cargo.lock for sub/root"; expect "(lock) it names the root Cargo.lock" PASS $?
  mv "$dir/root.lock" "$repo/Cargo.lock"

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
  # Every call the fake cargo records is a cargo tree passing --locked and --target all,
  # except the root fetch and one lock trim per staged root, in that order.
  want="fetch --locked"
  for n in "${WORKSPACE_ROOTS[@]}"; do
    [[ "$n" == "." || " ${NOT_SHIPPED_ROOTS[*]} " == *" $n "* ]] && continue
    want+=$'\n'"tree --offline --manifest-path STAGE/$n/Cargo.toml --depth 0 --target all"
  done
  same "$(grep -vE '^tree --locked .* --target all ' "$ARGV_LOG" | sed -E 's#--manifest-path [^ ]*/tmp\.[^/ ]+/#--manifest-path STAGE/#')" "$want"
  expect "every cargo tree call of that run passes --locked and --target all, except the root fetch and one offline lock trim per staged root" PASS $?
  grep -xF "tree --locked --workspace -e no-dev --target all --prefix none --format {p}" "$ARGV_LOG" >/dev/null
  expect "that run resolves the root workspace" PASS $?
  grep -xF "fetch --locked" "$ARGV_LOG" >/dev/null; expect "(roots) that run fetches the root Cargo.lock's packages under --locked" PASS $?
  for n in "${WORKSPACE_ROOTS[@]}"; do
    [[ "$n" == "." || " ${NOT_SHIPPED_ROOTS[*]} " == *" $n "* ]] && continue
    same "$(grep -cxE "tree --locked --offline --manifest-path [^ ]*/$n/Cargo.toml --workspace -e no-dev --target all --prefix none --format [{]p[}]" "$ARGV_LOG" || true)" 1
    expect "(roots) that run resolves $n once, staged and offline" PASS $?
  done
  grep -F "/fuzz/Cargo.toml" "$ARGV_LOG" >/dev/null; expect "(roots) that run does not resolve the not-shipped fuzz root" FAIL $?
  FAKE_VENDOR_PATH=/scaffolds/relay/Cargo.toml scenario "(roots) run_gate FAILS when a staged root reaches $VENDOR_CRATE" FAIL
  printf '%s\n' "$out" | grep -F "FAIL — the scaffolds/relay workspace reaches 1" >/dev/null; expect "(roots) it names that root" PASS $?
  FAKE_FAIL_ON=fetch scenario "(roots) run_gate FAILS when cargo fetch --locked exits non-zero" FAIL
  printf '%s\n' "$out" | grep -F "cargo fetch --locked failed" >/dev/null; expect "(roots) it names the failed fetch" PASS $?
  WORKSPACE_ROOTS=()
  for n in "${roots_saved[@]}"; do [[ "$n" == templates/personal-relay ]] || WORKSPACE_ROOTS+=("$n"); done
  scenario "(roots) run_gate FAILS when WORKSPACE_ROOTS leaves out a root git tracks" FAIL
  printf '%s\n' "$out" | grep -F "templates/personal-relay/Cargo.toml is neither the manifest of a WORKSPACE_ROOTS entry nor a member of one" >/dev/null
  expect "(roots) it names that root's manifest" PASS $?
  WORKSPACE_ROOTS=("${roots_saved[@]}")
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
