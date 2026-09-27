#!/usr/bin/env bash
#
# Vendored-OpenSSL scope gate.
#
# CRITERION
# ---------
# `openssl-src` — the crate whose build script compiles OpenSSL from source so
# `openssl-sys` links it statically — appears in the shipped dependency graph of
# the configuration maturin builds the PyPI wheel with, on every target triple the
# `python-wheels` job of `.github/workflows/build-matrix.yml` builds that wheel
# for; and `openssl-src` appears in the dependency graph of no other configuration
# this repository ships, and in the graph of no workspace member or
# dev-dependency at its default features, resolved over every target triple.
#
# "No other configuration" is two resolutions, and each one covers what the other
# cannot:
#
#   * every `ARTIFACTS` entry of `scripts/check-shipped-feature-graph.sh` except the
#     wheel's own entry, each resolved alone. This covers a configuration that
#     selects features, such as the `--no-default-features --features server`
#     bridge cdylibs. The comparison against the wheel reads the whole
#     `<package>|<feature arguments>` entry, because three entries build package
#     `scp-ffi`;
#   * the whole-workspace build with dev-dependencies: `cargo tree --workspace`,
#     every member at its default features, dev units included. Cargo decides
#     which packages that resolution holds, so every member — each `[[bin]]`, each
#     bridge `cdylib`, a member outside `default-members` such as scp-testing, each
#     package added later — is in it whether or not an `ARTIFACTS` entry names it,
#     and deleting entries from that array uncovers no member. It is a superset of
#     the bare default-members build, because adding roots and dev units only adds
#     features.
#
# The presence proof depends on that second resolution. `cargo metadata` takes no
# `-p`: it unifies features across every member and every dev-dependency, so an
# `openssl-sys -> openssl-src` edge in its graph can come from any member. When the
# whole-workspace resolution reaches no `openssl-src`, no member and no
# dev-dependency selects the vendored build on its own, and the `openssl-src` edge
# the presence walk finds comes from the features the wheel's configuration names.
# The walk's path from the wheel's package down to `openssl-sys` is still read
# from the unified graph, so an optional edge on that path that only another
# member's feature selection switches on is counted too. `run_gate` therefore
# also resolves the wheel's package alone with `cargo tree -p … --target all` and
# fails when that resolution reaches no `openssl-src`. That check is exact about
# features and loose about triples, and the per-triple walk is the reverse, so
# one gap remains: a triple where only the unified graph reaches `openssl-src`
# passes whenever the wheel's own features reach it on some other triple.
#
# Both absence resolutions name `--target all`, the union over every triple, which
# is the correct over-approximation for a proof that a crate is ABSENT, and which
# `assert_every_cargo_tree_resolves_every_target` of the owner gate requires of
# every `cargo tree` call under scripts/. The presence proof needs the opposite,
# because the union accepts an edge that only a target the wheel does not ship for
# compiles. It reads `cargo metadata --filter-platform <triple>` once per wheel
# triple, so an edit that moves the vendored build under a
# `[target.'cfg(…)'.dependencies]` table fails on each wheel triple the edit
# leaves without it.
#
# WHERE EACH FACT COMES FROM
# --------------------------
#   * `bash scripts/check-shipped-feature-graph.sh --print-artifacts` writes that
#     gate's `ARTIFACTS` array, one entry per line, as bash holds it.
#   * `bash scripts/check-shipped-feature-graph.sh --print-wheel-entries` writes one
#     `<maturin project file><TAB><package>|<feature arguments>` line per
#     pyproject.toml a maturin step can read. `run_gate` fails unless exactly one
#     such line came back.
#   * The wheel's triples are the `target:` values of the items of the
#     `python-wheels` job's matrix `include:` list in
#     `.github/workflows/build-matrix.yml`, the job that builds the wheel. An item
#     that yields no bare triple fails the gate, and so does a `matrix:` mapping
#     holding any key beside `include:`.
#
# This gate asks the owner gate to print its lists rather than parsing that file's
# source text, because bash expands every spelling of an array assignment and a
# source-text parser sees only the spellings it was written for.
#
# WHY EACH HALF IS A SEPARATE FAILURE
# -----------------------------------
# The wheel needs the vendored copy: `pip install` runs no linker and installs onto
# a machine whose OpenSSL this build never saw, so SQLCipher's crypto has to travel
# inside the wheel. `bindings/python/pyproject.toml` asks for it by naming
# `vendored-openssl` in its `[tool.maturin] features` array, which reaches
# `scp-platform/vendored-openssl` and from there adds
# `rusqlite/bundled-sqlcipher-vendored-openssl`. Drop that name and the wheel
# silently reverts to taking its crypto from whatever the build host happened to have.
# On an Apple host building an Apple triple the build without it links no
# libcrypto: libsqlite3-sys builds SQLCipher against CommonCrypto from the Security
# framework unless OPENSSL_DIR is set. On a Windows host building a Windows triple
# the build without it does not finish: libsqlite3-sys panics unless OPENSSL_DIR
# names an OpenSSL installation. This gate still requires the vendored build on every wheel
# triple, the two darwin triples included.
#
# Every other shipped configuration must not get it. A vendored OpenSSL changes
# patch level only when someone bumps `Cargo.lock`. `Rust / deny` resolves every
# feature, so it reports a RustSec advisory published against the `openssl-src`
# crate, but acting on that report means a lock bump and a new release; nobody can
# patch the copy inside an installed artifact.
#
#   * `scp-node` and `scp-relay` ship in a container whose operator patches OpenSSL
#     by upgrading `libssl3` in the runtime layer; `Dockerfile` and
#     `templates/personal-relay/README.md` both name that dynamic link as the
#     reason they install `libssl3`. Vendoring into these two breaks an operator
#     procedure this repository documents.
#   * `scp-core` and the six FFI-bridge configurations take their crypto from the
#     build host, which is what they do on `main` today: the host's libcrypto on a
#     Linux host, CommonCrypto on an Apple host building an Apple target, and, on a
#     Windows host building a Windows target, the OpenSSL installation OPENSSL_DIR
#     names, without which libsqlite3-sys panics and the build fails. This gate holds
#     that state so that a workspace-wide feature edit cannot change it as a side
#     effect. This gate does not decide whether a prebuilt `index.node` or
#     XCFramework that `.github/workflows/release.yml` publishes should vendor
#     OpenSSL too; changing what those artifacts select fails this gate by name,
#     so that change has to be made on purpose.
#
# WHAT THIS GATE DOES NOT DECIDE
# ------------------------------
# It reads dependency graphs, so it decides which crates a build compiles and never
# which shared library a finished binary loads. `scripts/check-shipped-feature-graph.sh`
# decides the complementary property, that every resolved SCP-crate feature of each
# shipped artifact sits on one permitted-production allowlist.
#
# Usage:
#   scripts/check-vendored-openssl-scope.sh             # gate the real workspace
#   scripts/check-vendored-openssl-scope.sh --self-test # run the fixtures only
#
# The fixtures run before the workspace gate on every invocation, so a reader that
# has stopped deriving what it claims to derive fails loudly rather than passing a
# tree it never read.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

VENDOR_CRATE="openssl-src"
FEATURE_GRAPH_GATE="scripts/check-shipped-feature-graph.sh"
WHEEL_MATRIX_FILE=".github/workflows/build-matrix.yml"
WHEEL_JOB="python-wheels"

# The program behind wheel_triples: it loads the workflow file on argv[1] with
# PyYAML and prints the `target:` value of every item of the matrix `include:`
# list of the job named on argv[2]. A YAML parser reads every spelling of that
# list that GitHub reads, so the criterion is stated on the parsed document: the
# job's `strategy.matrix` is a mapping whose only key is `include:`, and every item
# of that non-empty list is a mapping whose `target` value is one bare triple. An
# axis key or an `exclude:` key beside `include:` changes the legs GitHub builds,
# and an item whose target is an expression names no triple this gate can resolve,
# so either one FAILS rather than dropping a leg out of the per-triple presence
# proof. A duplicated key FAILS too, because PyYAML keeps the last value where
# GitHub rejects the file.
read -r -d '' WHEEL_TRIPLES_PROGRAM <<'PYTHON' || true
import re
import sys
import yaml

class Loader(yaml.SafeLoader):
    pass
def unique_mapping(loader, node):
    keys = [loader.construct_object(k) for k, _ in node.value]
    for key in keys:
        if keys.count(key) > 1:
            sys.exit(f"{path}: key '{key}' appears twice in one mapping")
    return loader.construct_mapping(node)
Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)

path, job = sys.argv[1], sys.argv[2]
with open(path, encoding="utf-8") as workflow:
    document = yaml.load(workflow, Loader=Loader)
matrix = ((((document or {}).get("jobs") or {}).get(job) or {}).get("strategy") or {}).get("matrix")
if not isinstance(matrix, dict) or list(matrix) != ["include"]:
    sys.exit(f"{path} job '{job}': strategy.matrix is not a mapping whose only key is 'include'")
items = matrix["include"]
if not isinstance(items, list) or not items:
    sys.exit(f"{path} job '{job}' has an empty or non-list matrix include")
triples = []
for item in items:
    target = item.get("target") if isinstance(item, dict) else None
    if not isinstance(target, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+", target):
        sys.exit(f"{path} job '{job}': include item {item!r} names no bare 'target' triple")
    triples.append(target)
print("\n".join(triples))
PYTHON

# The program behind wheel_reach_count: it reads `cargo metadata
# --filter-platform` JSON on stdin and prints how many packages named argv[2] are
# reachable from the workspace member named argv[1] over normal and build edges.
# `--filter-platform` has already removed every edge whose cfg is false on the
# triple, and a dev edge compiles into no shipped artifact, so the walk skips it.
# A name that matches no workspace member, or matches two, fails.
read -r -d '' WHEEL_REACH_PROGRAM <<'PYTHON' || true
import json
import sys

root_name, crate = sys.argv[1], sys.argv[2]
document = json.load(sys.stdin)
names = {package["id"]: package["name"] for package in document["packages"]}
nodes = {node["id"]: node for node in document["resolve"]["nodes"]}
roots = [i for i in document["workspace_members"] if names.get(i) == root_name]
if len(roots) != 1:
    sys.exit(f"{len(roots)} workspace members are named '{root_name}'")
seen, stack = set(), roots
while stack:
    current = stack.pop()
    if current in seen:
        continue
    seen.add(current)
    for dep in nodes[current]["deps"]:
        if any(kind.get("kind") != "dev" for kind in dep["dep_kinds"]):
            stack.append(dep["pkg"])
print(sum(1 for i in seen if names.get(i) == crate))
PYTHON

# The first interpreter on PATH. The metadata walk uses only the standard library;
# wheel_triples also imports PyYAML and FAILS when that interpreter lacks it.
SCOPE_JSON_READER=""
for scope_json_candidate in python3.12 python3 python; do
  if command -v "$scope_json_candidate" >/dev/null 2>&1; then
    SCOPE_JSON_READER="$scope_json_candidate"
    break
  fi
done

fixture_failures=0

# feature_graph_gate_prints <gate-script> <mode>
#   Emit what the gate script writes on stdout in the named print mode. FAILS
#   (non-zero, reason on stderr) when the mode exits non-zero, which is what a
#   gate that stopped answering does, so this gate rejects such a run rather than
#   reading the lines it wrote before it stopped.
#
#   Discarding the lines matters on its own: a mode that wrote four of ten entries
#   and then failed hands `shipped_configurations` four entries, which clears the
#   floor, and every artifact the other six name goes unresolved under a PASS. The
#   fixture below plants exactly that gate.
#
feature_graph_gate_prints() {
  local file="$1" mode="$2" out rc=0
  # Stdout alone. The gate's stderr reaches this gate's stderr, where a human
  # reading a failure sees it; merging the two streams here would put a warning
  # bash wrote into the entry list this gate goes on to resolve.
  out="$(bash "$file" "$mode")" || rc=$?
  if [[ "$rc" -ne 0 ]]; then
    echo "$file $mode exited $rc, so this gate read no list from it" >&2
    return 1
  fi
  printf '%s\n' "$out"
}

# shipped_configurations <gate-script>
#   Emit one `<package>|<feature arguments>` line per entry of the gate script's
#   `ARTIFACTS` array, in the order bash holds them. FAILS on anything
#   feature_graph_gate_prints fails on.
#
#   This reader applies no entry-count floor. `run_gate` checks every
#   configuration this returns, and workspace_occurrences resolves every
#   workspace member at its default features whether or not an entry names it.
#   A feature selection that no entry names, such as a `--features server`
#   bridge build removed from the array, is covered by neither.
shipped_configurations() {
  local file="$1"
  feature_graph_gate_prints "$file" --print-artifacts || return 1
}

# wheel_line <gate-script>
#   Emit the one `<maturin project file><TAB><package>|<feature arguments>` line
#   the gate script writes for the wheel. FAILS on anything
#   feature_graph_gate_prints fails on, and when the mode wrote any number of
#   lines other than one: this gate compares the single vendoring configuration
#   against the single wheel, so two wheels are a question about which one carries
#   the vendored build, and zero wheels means the gate that owns
#   MATURIN_PROJECT_FILES no longer knows of a wheel at all.
wheel_line() {
  local file="$1" lines count
  lines="$(feature_graph_gate_prints "$file" --print-wheel-entries)" || return 1
  count="$(printf '%s\n' "$lines" | grep -cE '.' || true)"
  if [[ "$count" -ne 1 ]]; then
    echo "$file --print-wheel-entries wrote $count wheel entries; this gate compares the one vendoring configuration against one wheel, so name which wheel carries the vendored OpenSSL here before adding another" >&2
    return 1
  fi
  printf '%s\n' "$lines"
}

# feature_list_is_wellformed <list>
#   Succeed when the string is a comma-separated list of cargo feature names,
#   each `name` or `package/name`. One regex decides the whole list, so no empty
#   element and no leading or trailing comma can pass.
#
#   No segment may BEGIN with `-`, which is what keeps a flag standing where a
#   feature list belongs — `--features --depth` — from reading as a feature named
#   `--depth`. A `-` inside a name is ordinary and `vendored-openssl` needs it.
feature_list_is_wellformed() {
  local name='[A-Za-z0-9_.+][A-Za-z0-9_.+-]*'
  local segment="${name}(/${name})?"
  [[ "$1" =~ ^${segment}(,${segment})*$ ]]
}

# cargo_arguments_for <feature-argument-string>
#   Emit one cargo argument per line, built from the fields the string names.
#
#   CRITERION: an entry of the `ARTIFACTS` array names a package's feature
#   selection and nothing else. This reader accepts exactly four token shapes —
#   `--no-default-features`, `--all-features`, `--features <list>`, and
#   `--features=<list>` — and FAILS on every other token, which is every other
#   cargo flag. It is a whitelist of the shapes an entry may carry, not a list of
#   the flags an entry may not, so a flag nobody has thought of is refused by the
#   same branch as one that is.
#
#   WHY THE GATE BUILDS THE COMMAND. An entry spliced into `cargo tree` unquoted
#   could carry any cargo argument, and `--depth 0` truncates a tree to its root
#   line, which hands an absence proof a count of zero. `run_gate` builds the
#   argument list from the fields this reader validates, so no substring of an
#   entry is ever word-split into a command.
cargo_arguments_for() {
  local raw="$1" token expect_list=0
  # The only word-splitting in this gate, and every token it produces is checked
  # against the whitelist below before it is emitted.
  # shellcheck disable=SC2086  # deliberate: the split feeds the whitelist.
  for token in $raw; do
    if [[ "$expect_list" -eq 1 ]]; then
      if ! feature_list_is_wellformed "$token"; then
        echo "a shipped configuration names something that is not a cargo feature list: '$token'" >&2
        return 1
      fi
      printf '%s\n' "$token"
      expect_list=0
      continue
    fi
    case "$token" in
      --no-default-features | --all-features)
        printf '%s\n' "$token"
        ;;
      --features)
        printf '%s\n' "$token"
        expect_list=1
        ;;
      --features=*)
        if ! feature_list_is_wellformed "${token#--features=}"; then
          echo "a shipped configuration names something that is not a cargo feature list: '$token'" >&2
          return 1
        fi
        printf '%s\n' "$token"
        ;;
      *)
        echo "a shipped configuration names a cargo argument this gate does not build: '$token'. An entry names a package's feature selection — --no-default-features, --all-features, --features <list> — and nothing else, so no resolver flag reaches cargo through the ARTIFACTS array." >&2
        return 1
        ;;
    esac
  done
  if [[ "$expect_list" -eq 1 ]]; then
    echo "a shipped configuration ends with '--features' and names no feature list" >&2
    return 1
  fi
}

# tree_count <tree-output>
#   Emit the number of lines of a `cargo tree --prefix none --format '{p}'` graph
#   that name the vendored crate. grep exits 1 on a count of zero, which is the
#   answer every absence proof wants, and above 1 when grep itself failed;
#   `|| grep_rc=$?` keeps those two apart.
tree_count() {
  local count grep_rc=0
  count="$(printf '%s\n' "$1" | grep -cE "^${VENDOR_CRATE} v")" || grep_rc=$?
  if [[ "$grep_rc" -gt 1 ]]; then
    echo "grep exited $grep_rc while counting $VENDOR_CRATE" >&2
    return 1
  fi
  printf '%s\n' "$count"
}

# vendor_crate_occurrences <package> <built-arguments>
#   Emit the number of times the vendored crate appears in the package's
#   dependency graph over every target triple, and return non-zero when cargo
#   resolved no graph. `-e no-dev` drops dev-dependencies, which no shipped
#   artifact compiles. The arguments arrive one per line from cargo_arguments_for,
#   which validated every token, and go into an array, so an `ARTIFACTS` entry
#   cannot carry a resolver flag into this invocation.
#
#   Cargo's exit status decides whether the count means anything: a count taken
#   from a resolution that failed is zero, and zero is the proof the absence half
#   asks for. Every caller treats a non-zero return as a gate failure.
vendor_crate_occurrences() {
  local pkg="$1" built="$2" tree cargo_rc=0 argument
  local -a args=()
  while IFS= read -r argument; do
    [[ -n "$argument" ]] && args+=("$argument")
  done <<<"$built"
  tree="$(cargo tree -p "$pkg" ${args[@]+"${args[@]}"} -e no-dev --target all --prefix none --format '{p}')" || cargo_rc=$?
  if [[ "$cargo_rc" -ne 0 ]]; then
    echo "cargo tree exited $cargo_rc for package '$pkg' with arguments '${args[*]:-none}'" >&2
    return 1
  fi
  tree_count "$tree"
}

# workspace_occurrences
#   Emit the number of times the vendored crate appears in the dependency graph of
#   every workspace member at its default features, dev-dependencies included,
#   over every target triple. FAILS when cargo resolved no graph. Dev edges stay
#   in because `cargo metadata`, which the presence half reads, unifies the
#   features a dev-dependency selects; see the header.
workspace_occurrences() {
  local tree cargo_rc=0
  tree="$(cargo tree --workspace --target all --prefix none --format '{p}')" || cargo_rc=$?
  if [[ "$cargo_rc" -ne 0 ]]; then
    echo "cargo tree exited $cargo_rc for the whole-workspace build" >&2
    return 1
  fi
  tree_count "$tree"
}

# wheel_triples <workflow-file>
#   Emit one target triple per line: the triples the wheel job's matrix builds.
#   FAILS when no interpreter is on PATH, when that interpreter cannot import
#   PyYAML, or when any item of the job's matrix `include:` list yields no single
#   bare triple.
wheel_triples() {
  if [[ -z "$SCOPE_JSON_READER" ]]; then
    echo "no python3.12, python3, or python on PATH, so this gate cannot read the wheel's target triples" >&2
    return 1
  fi
  "$SCOPE_JSON_READER" -c "$WHEEL_TRIPLES_PROGRAM" "$1" "$WHEEL_JOB"
}

# wheel_reach_count <package> <built-arguments> <triple>
#   Emit how many times the vendored crate is reachable from the package in the
#   graph cargo resolves for the one triple. `cargo metadata` resolves the whole
#   workspace, so each feature the configuration names is passed as
#   `<package>/<feature>`, which selects it on that package alone. FAILS when
#   cargo exits non-zero or the JSON names no single such package, and FAILS on
#   `--all-features`, which `cargo metadata` applies to every member and which no
#   `<package>/<feature>` spelling scopes to the one package.
#
#   The unified graph alone does not prove the wheel's own build vendors: another
#   member or a dev-dependency can put the edge there. `run_gate` pairs this count
#   with workspace_occurrences, which fails the gate whenever one does, and with
#   vendor_crate_occurrences on the wheel's package alone, which fails it when the
#   wheel's own features reach no openssl-src.
#
#   Only stdout is parsed. Cargo writes a warning to stderr and still exits 0, and
#   a warning in front of the JSON would fail the parse on a tree that satisfies
#   the criterion.
wheel_reach_count() {
  local pkg="$1" built="$2" triple="$3" argument list name metadata cargo_rc=0 next_is_list=0
  local -a args=()
  if [[ -z "$SCOPE_JSON_READER" ]]; then
    echo "no python3.12, python3, or python on PATH, so this gate cannot read cargo metadata" >&2
    return 1
  fi
  while IFS= read -r argument; do
    [[ -z "$argument" ]] && continue
    if [[ "$next_is_list" -eq 1 || "$argument" == --features=* ]]; then
      next_is_list=0
      list="${argument#--features=}"
      for name in ${list//,/ }; do
        [[ "$name" == */* ]] || name="$pkg/$name"
        args+=(--features "$name")
      done
    elif [[ "$argument" == "--features" ]]; then
      next_is_list=1
    elif [[ "$argument" == "--all-features" ]]; then
      echo "the wheel's configuration names --all-features, which cargo metadata applies to every workspace member rather than to '$pkg'; name the wheel's features" >&2
      return 1
    else
      args+=("$argument")
    fi
  done <<<"$built"
  metadata="$(cargo metadata --format-version 1 --filter-platform "$triple" ${args[@]+"${args[@]}"})" || cargo_rc=$?
  if [[ "$cargo_rc" -ne 0 ]]; then
    echo "cargo metadata exited $cargo_rc for package '$pkg' on '$triple' with arguments '${args[*]:-none}'" >&2
    return 1
  fi
  printf '%s' "$metadata" | "$SCOPE_JSON_READER" -c "$WHEEL_REACH_PROGRAM" "$pkg" "$VENDOR_CRATE"
}

# ---------------------------------------------------------------------------
# Fixtures — behavioural proofs that each reader above derives what it claims to
# derive, and fails closed on an input it cannot reproduce.
# ---------------------------------------------------------------------------
expect() {
  local label="$1" want="$2" rc="$3" got
  if [[ "$rc" -eq 0 ]]; then got="PASS"; else got="FAIL"; fi
  if [[ "$got" == "$want" ]]; then
    echo "   ok   — $label"
  else
    echo "   FAIL — $label (wanted $want, got $got)"
    fixture_failures=$((fixture_failures + 1))
  fi
}

same_string() {
  if [[ "$1" == "$2" ]]; then return 0; fi
  echo "      wanted [$2], got [$1]" >&2
  return 1
}

# plant_gate <path> <wheel-line> <artifacts-entry>...
#   Write a stand-in for the owner gate at <path>: a script answering
#   `--print-artifacts` with the entries given and `--print-wheel-entries` with the
#   line given, and refusing any other argument. The fixtures below drive run_gate
#   through this stand-in, which is what lets them state what run_gate does for a
#   tree this repository does not currently hold.
plant_gate() {
  local path="$1" wheel="$2"; shift 2
  { echo '#!/usr/bin/env bash'
    echo 'set -euo pipefail'
    echo 'ARTIFACTS=('
    printf '  "%s"\n' "$@"
    echo ')'
    printf 'WHEEL_LINE=%q\n' "$wheel"
    echo 'case "${1:-}" in'
    echo '  --print-artifacts) printf "%s\n" "${ARTIFACTS[@]}" ;;'
    echo '  --print-wheel-entries) if [[ -n "$WHEEL_LINE" ]]; then printf "%s\n" "$WHEEL_LINE"; fi ;;'
    echo '  *) echo "planted gate got no print mode: ${1:-}" >&2; exit 2 ;;'
    echo 'esac'
  } > "$path"
}

run_fixtures() {
  echo ">> fixtures: the readers derive the shipped configurations and the wheel's configuration, and fail closed otherwise"
  local dir file out rc wheel built_depth
  dir="$(mktemp -d)"
  trap 'rm -rf "$dir"' RETURN

  file="$dir/gate.sh"
  wheel="$(printf 'bindings/python/pyproject.toml\tscp-ffi|--features extension-module,vendored-openssl')"
  plant_gate "$file" "$wheel" \
    "scp-ffi|--no-default-features --features server" \
    "scp-node|" \
    "scp-ffi|--features extension-module,vendored-openssl"
  out="$(shipped_configurations "$file")"; rc=$?
  expect "the gate's --print-artifacts output is read as the shipped configurations" "PASS" "$rc"
  same_string "$out" "$(printf '%s\n' 'scp-ffi|--no-default-features --features server' 'scp-node|' 'scp-ffi|--features extension-module,vendored-openssl')"; rc=$?
  expect "it yields every entry bash held, in the order the gate wrote them" "PASS" "$rc"
  out="$(wheel_line "$file")"; rc=$?
  expect "the gate's --print-wheel-entries output is read as the wheel's line" "PASS" "$rc"
  same_string "$out" "$wheel"; rc=$?
  expect "that line carries the maturin project file and the whole ARTIFACTS entry" "PASS" "$rc"

  shipped_configurations "$dir/absent.sh" >/dev/null 2>&1; rc=$?
  expect "a missing shipped-artifact list FAILS" "FAIL" "$rc"
  wheel_line "$dir/absent.sh" >/dev/null 2>&1; rc=$?
  expect "a missing shipped-artifact list FAILS the wheel reader too" "FAIL" "$rc"

  # A gate that writes a well-formed answer and THEN exits non-zero: three valid
  # entries, and exactly one wheel line, so the wheel count cannot reject it and
  # only the exit status can. Planting a gate that writes nothing proves less,
  # because the wheel count rejects an empty answer on its own.
  printf '%s\n' '#!/usr/bin/env bash' \
    'case "${1:-}" in' \
    '  --print-artifacts) printf "%s\n" "scp-node|" "scp-relay|" "scp-ffi|--features extension-module,vendored-openssl" ;;' \
    "  --print-wheel-entries) printf '%s\\t%s\\n' 'bindings/python/pyproject.toml' 'scp-ffi|--features extension-module,vendored-openssl' ;;" \
    'esac' \
    'echo "this gate stopped partway through what it holds" >&2' \
    'exit 3' > "$file"
  out="$(shipped_configurations "$file" 2>/dev/null)"; rc=$?
  expect "a gate whose --print-artifacts writes a well-formed list and then exits non-zero FAILS" "FAIL" "$rc"
  same_string "$out" ""; rc=$?
  expect "it hands back none of the lines that run wrote, so no artifact resolves off a run that failed" "PASS" "$rc"
  out="$(wheel_line "$file" 2>/dev/null)"; rc=$?
  expect "a gate whose --print-wheel-entries writes one well-formed line and then exits non-zero FAILS" "FAIL" "$rc"
  same_string "$out" ""; rc=$?
  expect "it hands back no wheel line either" "PASS" "$rc"

  plant_gate "$file" "" "scp-node|" "scp-relay|"
  wheel_line "$file" >/dev/null 2>&1; rc=$?
  expect "a gate naming no wheel at all FAILS" "FAIL" "$rc"

  plant_gate "$file" "$(printf 'a/pyproject.toml\tscp-ffi|\nb/pyproject.toml\tscp-ffi|')" "scp-node|" "scp-relay|"
  wheel_line "$file" >/dev/null 2>&1; rc=$?
  expect "a gate naming two wheels FAILS rather than comparing against the first" "FAIL" "$rc"

  # (entry-whitelist) the four token shapes an entry may carry, and the refusal of
  # everything else. `--depth 0` truncates a tree to its root, which would make
  # an absence proof count zero for a bridge cdylib that reached openssl-src.
  out="$(cargo_arguments_for "--no-default-features --features server")"; rc=$?
  expect "(entry-whitelist) a two-flag entry is built" "PASS" "$rc"
  same_string "$out" "$(printf '%s\n' '--no-default-features' '--features' 'server')"; rc=$?
  expect "(entry-whitelist) it becomes three arguments, the list its own argument" "PASS" "$rc"
  out="$(cargo_arguments_for "")"; rc=$?
  expect "(entry-whitelist) a default-features entry is built" "PASS" "$rc"
  same_string "$out" ""; rc=$?
  expect "(entry-whitelist) it becomes no arguments at all" "PASS" "$rc"
  cargo_arguments_for "--features=extension-module,vendored-openssl" >/dev/null 2>&1; rc=$?
  expect "(entry-whitelist) the '--features=<list>' spelling is built" "PASS" "$rc"
  cargo_arguments_for "--all-features" >/dev/null 2>&1; rc=$?
  expect "(entry-whitelist) '--all-features' is built" "PASS" "$rc"

  cargo_arguments_for "--features scp-platform/vendored-openssl --depth 0" >/dev/null 2>&1; rc=$?
  expect "(entry-whitelist) the planted '--depth 0' entry is REFUSED, not counted as zero" "FAIL" "$rc"
  cargo_arguments_for "--depth 0" >/dev/null 2>&1; rc=$?
  expect "(entry-whitelist) '--depth 0' alone is REFUSED" "FAIL" "$rc"
  cargo_arguments_for "-F vendored-openssl" >/dev/null 2>&1; rc=$?
  expect "(entry-whitelist) cargo's '-F' short form is REFUSED, because this gate builds three shapes and no more" "FAIL" "$rc"
  cargo_arguments_for "--features server --offline" >/dev/null 2>&1; rc=$?
  expect "(entry-whitelist) a flag appended after a valid selection is REFUSED" "FAIL" "$rc"
  cargo_arguments_for "--features" >/dev/null 2>&1; rc=$?
  expect "(entry-whitelist) '--features' naming no list is REFUSED" "FAIL" "$rc"
  cargo_arguments_for "--features --depth" >/dev/null 2>&1; rc=$?
  expect "(entry-whitelist) a flag standing where the feature list belongs is REFUSED" "FAIL" "$rc"
  cargo_arguments_for "--features a,,b" >/dev/null 2>&1; rc=$?
  expect "(entry-whitelist) a feature list holding an empty element is REFUSED" "FAIL" "$rc"
  cargo_arguments_for "--features 'a b'" >/dev/null 2>&1; rc=$?
  expect "(entry-whitelist) a quoted pair inside the list is REFUSED, because each token is checked whole" "FAIL" "$rc"

  # (triples) the wheel's triples come from the wheel job's matrix and from no
  # other job, and a matrix naming none fails.
  printf '%s\n' 'jobs:' '  bridges:' '    strategy:' '      matrix:' '        include:' \
    '          - target: aarch64-apple-ios' '  python-wheels:' '    strategy:' '      matrix:' \
    '        include:' '          - target: x86_64-unknown-linux-gnu' '            runner: ubuntu-latest' \
    '          - target: x86_64-pc-windows-msvc' '    steps:' '      - with:' \
    '          target: ${{ matrix.target }}' '  after:' '    strategy:' '      matrix:' \
    '        include:' '          - target: wasm32-unknown-unknown' > "$dir/matrix.yml"
  out="$(wheel_triples "$dir/matrix.yml")"; rc=$?
  expect "(triples) the wheel job's matrix is read" "PASS" "$rc"
  same_string "$out" "$(printf '%s\n' x86_64-unknown-linux-gnu x86_64-pc-windows-msvc)"; rc=$?
  expect "(triples) it yields that job's triples and none of another job's" "PASS" "$rc"
  printf '%s\n' 'jobs:' '  bridges:' '    strategy:' '      matrix:' '        include:' \
    '          - target: aarch64-apple-ios' > "$dir/nowheel.yml"
  wheel_triples "$dir/nowheel.yml" >/dev/null 2>&1; rc=$?
  expect "(triples) a workflow whose wheel job names no triple FAILS" "FAIL" "$rc"
  # (triples-leg) one leg among several that names no bare triple FAILS the
  # reader, rather than dropping that leg out of the presence proof, and a leg
  # that YAML reads as a bare triple is read whatever its spelling.
  local leg_label leg_lines
  for leg_label in "no target key" "two target keys" "an expression target"; do
    case "$leg_label" in
      "no target key") leg_lines='          - runner: windows-latest' ;;
      "two target keys") leg_lines=$(printf '%s\n' '          - target: x86_64-pc-windows-msvc' '            target: aarch64-pc-windows-msvc') ;;
      "an expression target") leg_lines='          - target: ${{ inputs.triple }}' ;;
    esac
    printf '%s\n' 'jobs:' '  python-wheels:' '    strategy:' '      matrix:' '        include:' \
      '          - target: x86_64-unknown-linux-gnu' "$leg_lines" '    steps:' '      - run: "true"' > "$dir/leg.yml"
    wheel_triples "$dir/leg.yml" >/dev/null 2>&1; rc=$?
    expect "(triples-leg) a wheel leg written with $leg_label FAILS the reader" "FAIL" "$rc"
  done
  for leg_label in "a quoted value" "a trailing comment"; do
    case "$leg_label" in
      "a quoted value") leg_lines='          - target: "x86_64-pc-windows-msvc"' ;;
      "a trailing comment") leg_lines='          - target: x86_64-pc-windows-msvc  # MSVC' ;;
    esac
    printf '%s\n' 'jobs:' '  python-wheels:' '    strategy:' '      matrix:' '        include:' \
      '          - target: x86_64-unknown-linux-gnu' "$leg_lines" '    steps:' '      - run: "true"' > "$dir/leg.yml"
    out="$(wheel_triples "$dir/leg.yml")"; rc=$?
    expect "(triples-leg) a wheel leg written with $leg_label is read" "PASS" "$rc"
    same_string "$out" "$(printf '%s\n' x86_64-unknown-linux-gnu x86_64-pc-windows-msvc)"; rc=$?
    expect "(triples-leg) and the leg written with $leg_label yields its triple" "PASS" "$rc"
  done
  printf '%s\n' 'jobs:' '  python-wheels:' '    strategy:' '      matrix:' '        include:' \
    '          - target: x86_64-unknown-linux-gnu' '            runner: ubuntu-latest' '' \
    '          # a comment between legs' '          - target: aarch64-apple-darwin' '            runner: macos-latest' \
    '# a column-zero comment between legs' '          - runner: windows-latest' '            target: x86_64-pc-windows-msvc' \
    '    steps:' '      - with:' '          target: ${{ matrix.target }}' > "$dir/leg.yml"
  out="$(wheel_triples "$dir/leg.yml")"; rc=$?
  expect "(triples-leg) legs separated by a blank line, an indented comment, and a column-zero comment, and a leg whose first key is not target, are read" "PASS" "$rc"
  same_string "$out" "$(printf '%s\n' x86_64-unknown-linux-gnu aarch64-apple-darwin x86_64-pc-windows-msvc)"; rc=$?
  expect "(triples-leg) and yield one triple per leg, ignoring the step's 'target:' input" "PASS" "$rc"
  # (triples-matrix) the wheel job's matrix holds the include list and no other
  # key, because an axis key or an exclude key beside it adds or removes legs the
  # reader never reads.
  local sibling_label sibling_lines
  for sibling_label in "an axis key after include" "an axis key before include" "an exclude key" "a key between matrix and include depth"; do
    case "$sibling_label" in
      "an axis key after include") sibling_lines=$(printf '%s\n' '        include:' '          - target: x86_64-unknown-linux-gnu' '        target: [riscv64gc-unknown-linux-gnu]') ;;
      "an axis key before include") sibling_lines=$(printf '%s\n' '        target:' '          - riscv64gc-unknown-linux-gnu' '        include:' '          - target: x86_64-unknown-linux-gnu') ;;
      "an exclude key") sibling_lines=$(printf '%s\n' '        include:' '          - target: x86_64-unknown-linux-gnu' '        exclude:' '          - target: x86_64-unknown-linux-gnu') ;;
      "a key between matrix and include depth") sibling_lines=$(printf '%s\n' '       python: ["3.12"]' '        include:' '          - target: x86_64-unknown-linux-gnu') ;;
    esac
    printf '%s\n' 'jobs:' '  python-wheels:' '    strategy:' '      fail-fast: false' '      matrix:' "$sibling_lines" '    steps:' > "$dir/sibling.yml"
    wheel_triples "$dir/sibling.yml" >/dev/null 2>&1; rc=$?
    expect "(triples-matrix) a wheel matrix holding $sibling_label FAILS the reader" "FAIL" "$rc"
  done
  printf '%s\n' 'jobs:' '  python-wheels:' '    strategy:' '      include:' '        - target: x86_64-unknown-linux-gnu' '    steps:' > "$dir/sibling.yml"
  wheel_triples "$dir/sibling.yml" >/dev/null 2>&1; rc=$?
  expect "(triples-matrix) an include key outside any matrix key FAILS the reader" "FAIL" "$rc"
  printf '%s\n' 'jobs:' '  python-wheels:' '    strategy:' '      matrix:' '        # the legs' '        include:' \
    '          - target: x86_64-unknown-linux-gnu' '      fail-fast: false' '    steps:' > "$dir/sibling.yml"
  out="$(wheel_triples "$dir/sibling.yml")"; rc=$?
  expect "(triples-matrix) a strategy key after the matrix is not read as a matrix key" "PASS" "$rc"
  same_string "$out" "x86_64-unknown-linux-gnu"; rc=$?
  expect "(triples-matrix) and the include triple is still read" "PASS" "$rc"

  # The counters run against a `cargo` on PATH that prints a chosen answer or
  # refuses to resolve one. Each proves a present crate is counted, an absent one
  # counts zero, and a refusal FAILS rather than counting zero, which is the
  # answer the absence half reads as proof.
  local saved_path
  mkdir -p "$dir/fakebin"
  saved_path="$PATH"

  printf '%s\n' '#!/bin/sh' 'echo "scp-ffi v0.1.0"' "echo \"${VENDOR_CRATE} v300.5.1+3.5.1\"" \
    'echo "warning: this goes to stderr" >&2' > "$dir/fakebin/cargo"
  chmod +x "$dir/fakebin/cargo"
  PATH="$dir/fakebin:$saved_path"
  out="$(vendor_crate_occurrences "scp-ffi" "" 2>/dev/null)"; rc=$?
  expect "a graph naming the vendored crate is counted" "PASS" "$rc"
  same_string "$out" "1"; rc=$?
  expect "that count is the number of $VENDOR_CRATE lines the graph holds, and cargo's stderr is not read as graph" "PASS" "$rc"
  out="$(workspace_occurrences 2>/dev/null)"; rc=$?
  same_string "$out" "1"; rc=$?
  expect "the whole-workspace counter counts the same graph" "PASS" "$rc"
  PATH="$saved_path"

  printf '%s\n' '#!/bin/sh' 'echo "scp-node v0.1.0"' > "$dir/fakebin/cargo"
  PATH="$dir/fakebin:$saved_path"
  out="$(vendor_crate_occurrences "scp-node" "")"; rc=$?
  PATH="$saved_path"
  same_string "$out" "0"; rc=$?
  expect "a graph naming no $VENDOR_CRATE counts zero" "PASS" "$rc"

  printf '%s\n' '#!/bin/sh' 'echo "scp-node v0.1.0"' 'exit 101' > "$dir/fakebin/cargo"
  PATH="$dir/fakebin:$saved_path"
  vendor_crate_occurrences "scp-node" "" >/dev/null 2>&1; rc=$?
  expect "a cargo tree that exits non-zero FAILS rather than counting zero" "FAIL" "$rc"
  workspace_occurrences >/dev/null 2>&1; rc=$?
  expect "the whole-workspace counter FAILS on the same refusal" "FAIL" "$rc"
  wheel_reach_count "scp-ffi" "" "x86_64-unknown-linux-gnu" >/dev/null 2>&1; rc=$?
  expect "a cargo metadata that exits non-zero FAILS the wheel counter" "FAIL" "$rc"
  PATH="$saved_path"

  # (argv) what each counter hands cargo, read back from a file the fake cargo
  # writes one argument per line. Both absence counters name `--target all`, the
  # wheel counter names the triple, and the wheel counter selects each feature on
  # the wheel's own package.
  printf '%s\n' '#!/bin/sh' ': > "$ARGV_DUMP"' 'for a in "$@"; do printf "%s\\n" "$a" >> "$ARGV_DUMP"; done' \
    'echo "{\"packages\":[{\"id\":\"f\",\"name\":\"scp-ffi\"}],\"workspace_members\":[\"f\"],\"resolve\":{\"nodes\":[{\"id\":\"f\",\"deps\":[]}]}}"' \
    > "$dir/fakebin/cargo"
  PATH="$dir/fakebin:$saved_path"
  ARGV_DUMP="$dir/argv.txt" vendor_crate_occurrences "scp-ffi" "$(cargo_arguments_for '--no-default-features --features a,b')" >/dev/null 2>&1
  same_string "$(cat "$dir/argv.txt")" "$(printf '%s\n' tree -p scp-ffi --no-default-features --features a,b -e no-dev --target all --prefix none --format '{p}')"; rc=$?
  expect "(argv) the package counter resolves every triple, and the feature list reaches cargo as ONE argument" "PASS" "$rc"
  ARGV_DUMP="$dir/argv.txt" workspace_occurrences >/dev/null 2>&1
  same_string "$(cat "$dir/argv.txt")" "$(printf '%s\n' tree --workspace --target all --prefix none --format '{p}')"; rc=$?
  expect "(argv) the whole-workspace counter selects every member, keeps dev edges, and resolves every triple" "PASS" "$rc"
  rm -f "$dir/argv.txt"
  ARGV_DUMP="$dir/argv.txt" wheel_reach_count "scp-ffi" "$(cargo_arguments_for '--all-features')" "aarch64-apple-darwin" >/dev/null 2>&1; rc=$?
  expect "(argv) the wheel counter FAILS on --all-features, which cargo metadata would apply to every member" "FAIL" "$rc"
  if [[ -f "$dir/argv.txt" ]]; then rc=1; else rc=0; fi
  expect "(argv) and runs no cargo metadata for it" "PASS" "$rc"
  ARGV_DUMP="$dir/argv.txt" wheel_reach_count "scp-ffi" "$(cargo_arguments_for '--features extension-module,dep/x')" "aarch64-apple-darwin" >/dev/null 2>&1
  same_string "$(cat "$dir/argv.txt")" "$(printf '%s\n' metadata --format-version 1 --filter-platform aarch64-apple-darwin --features scp-ffi/extension-module --features dep/x)"; rc=$?
  expect "(argv) the wheel counter names the triple and selects each feature on the wheel's package" "PASS" "$rc"
  rm -f "$dir/argv.txt"
  if built_depth="$(cargo_arguments_for '--features server --depth 0' 2>/dev/null)"; then
    ARGV_DUMP="$dir/argv.txt" vendor_crate_occurrences "scp-ffi" "$built_depth" >/dev/null 2>&1
  fi
  PATH="$saved_path"
  if [[ -f "$dir/argv.txt" ]]; then rc=1; else rc=0; fi
  expect "(entry-whitelist) a refused entry runs no cargo at all, so no truncated tree is counted" "PASS" "$rc"

  # (reach) the wheel counter walks normal and build edges and skips dev edges.
  local reach_json
  reach_json='{"packages":[{"id":"f","name":"scp-ffi"},{"id":"p","name":"scp-platform"},{"id":"o","name":"openssl-src"},{"id":"t","name":"scp-testing"}],"workspace_members":["f","p","t"],"resolve":{"nodes":[{"id":"f","deps":[{"pkg":"p","dep_kinds":[{"kind":null}]},{"pkg":"t","dep_kinds":[{"kind":"dev"}]}]},{"id":"p","deps":[DEPS]},{"id":"t","deps":[{"pkg":"o","dep_kinds":[{"kind":null}]}]},{"id":"o","deps":[]}]}}'
  local build_edge='{"pkg":"o","dep_kinds":[{"kind":"build"}]}' normal_edge='{"pkg":"o","dep_kinds":[{"kind":null}]}'
  printf '%s\n' "${reach_json//DEPS/$build_edge}" > "$dir/reach.json"
  printf '%s\n' '#!/bin/sh' "cat '$dir/reach.json'" > "$dir/fakebin/cargo"
  PATH="$dir/fakebin:$saved_path"
  out="$(wheel_reach_count "scp-ffi" "" "x86_64-unknown-linux-gnu")"; rc=$?
  expect "(reach) a crate reached over a build edge is counted" "PASS" "$rc"
  same_string "$out" "1"; rc=$?
  expect "(reach) that count is one" "PASS" "$rc"
  printf '%s\n' "${reach_json//DEPS/}" > "$dir/reach.json"
  out="$(wheel_reach_count "scp-ffi" "" "x86_64-unknown-linux-gnu")"; rc=$?
  same_string "$out" "0"; rc=$?
  expect "(reach) a crate reachable only through a dev edge counts zero" "PASS" "$rc"
  wheel_reach_count "scp-nothing" "" "x86_64-unknown-linux-gnu" >/dev/null 2>&1; rc=$?
  expect "(reach) a package no workspace member is named FAILS" "FAIL" "$rc"
  PATH="$saved_path"

  # run_gate end to end, against a planted gate, a planted wheel matrix, and a
  # cargo that answers both counters from the arguments it receives: the tree
  # reaches openssl-src when the arguments name vendored-openssl or name a package
  # in $FAKE_VENDORS, and the whole-workspace tree reaches it when
  # $FAKE_BARE_VENDORS is set and the arguments keep dev edges, because the
  # selection it stands for can sit in a dev-dependency; the metadata graph reaches it when the arguments
  # name vendored-openssl on a triple other than $FAKE_DROPPED_TRIPLE, or on any
  # such triple when $FAKE_UNIFIED is set, which is how `cargo metadata` answers
  # when another member or a dev-dependency selects the vendored build.
  local gate_file scenario_out
  gate_file="$dir/scenario-gate.sh"
  printf '%s\n' 'jobs:' '  python-wheels:' '    strategy:' '      matrix:' '        include:' \
    '          - target: x86_64-unknown-linux-gnu' '          - target: x86_64-pc-windows-msvc' > "$dir/matrix.yml"
  printf '%s\n' "${reach_json//DEPS/$normal_edge}" > "$dir/reach-yes.json"
  printf '%s\n' "${reach_json//DEPS/}" > "$dir/reach-no.json"
  printf '%s\n' \
    '#!/bin/sh' \
    'if [ "$1" = "metadata" ]; then' \
    '  case "$*" in' \
    "    *\"--filter-platform \$FAKE_DROPPED_TRIPLE \"*) cat '$dir/reach-no.json' ;;" \
    "    *vendored-openssl*) cat '$dir/reach-yes.json' ;;" \
    "    *) if [ -n \"\$FAKE_UNIFIED\" ]; then cat '$dir/reach-yes.json'; else cat '$dir/reach-no.json'; fi ;;" \
    '  esac' \
    '  exit 0' \
    'fi' \
    'echo "the-package v0.1.0"' \
    'case " $* " in' \
    "  *vendored-openssl*) [ -n \"\$FAKE_WHEEL_TREE_EMPTY\" ] || echo \"${VENDOR_CRATE} v300.5.1+3.5.1\" ;;" \
    "  *\" -p \"*) for p in \$FAKE_VENDORS; do case \" \$* \" in *\" -p \$p \"*) echo \"${VENDOR_CRATE} v300.5.1+3.5.1\" ;; esac; done ;;" \
    "  *\" --workspace \"*) case \" \$* \" in *no-dev*) ;; *) [ -n \"\$FAKE_BARE_VENDORS\" ] && echo \"${VENDOR_CRATE} v300.5.1+3.5.1\" ;; esac ;;" \
    'esac' \
    'exit 0' > "$dir/fakebin/cargo"
  chmod +x "$dir/fakebin/cargo"
  local wheel_ok
  wheel_ok="$(printf 'bindings/python/pyproject.toml\tscp-ffi|--features extension-module,vendored-openssl')"

  # scenario <label> <want>: runs run_gate once. The caller's FAKE_* prefix
  # assignments reach the fake cargo, which is a child of this call.
  scenario() {
    PATH="$dir/fakebin:$saved_path"
    scenario_out="$(FEATURE_GRAPH_GATE="$gate_file" WHEEL_MATRIX_FILE="$dir/matrix.yml" run_gate 2>&1)"; rc=$?
    PATH="$saved_path"
    expect "$1" "$2" "$rc"
  }

  plant_gate "$gate_file" "$wheel_ok" "scp-ffi|--no-default-features --features server" "scp-node|" "scp-relay|" \
    "scp-ffi|--features extension-module,vendored-openssl"
  FAKE_DROPPED_TRIPLE=none FAKE_VENDORS="" FAKE_BARE_VENDORS="" scenario "run_gate PASSES on a tree where only the wheel vendors" "PASS"

  # The negative control a package-name comparison admitted: vendored-openssl moves
  # off the wheel's entry onto the `--features server` bridge, package scp-ffi too.
  plant_gate "$gate_file" "$(printf 'bindings/python/pyproject.toml\tscp-ffi|--features extension-module')" \
    "scp-ffi|--no-default-features --features server,vendored-openssl" "scp-ffi|--features extension-module"
  FAKE_DROPPED_TRIPLE=none FAKE_VENDORS="" FAKE_BARE_VENDORS="" scenario "run_gate FAILS when the vendored feature moves onto a sibling scp-ffi configuration" "FAIL"
  printf '%s\n' "$scenario_out" | grep -qF "FAIL — scp-ffi [--no-default-features --features server,vendored-openssl] reaches $VENDOR_CRATE."; rc=$?
  expect "it names the sibling configuration that reaches $VENDOR_CRATE" "PASS" "$rc"

  # (absent-reaches) a workspace dependency table vendors for scp-node and
  # scp-relay without either entry changing a character.
  plant_gate "$gate_file" "$wheel_ok" "scp-node|" "scp-relay|" "scp-ffi|--features extension-module,vendored-openssl"
  FAKE_DROPPED_TRIPLE=none FAKE_VENDORS="scp-node scp-relay" FAKE_BARE_VENDORS="" scenario "(absent-reaches) run_gate FAILS when a binary that selects no feature reaches $VENDOR_CRATE" "FAIL"
  printf '%s\n' "$scenario_out" | grep -qF "FAIL — scp-node [default features] reaches $VENDOR_CRATE."; rc=$?
  expect "(absent-reaches) it names scp-node" "PASS" "$rc"
  printf '%s\n' "$scenario_out" | grep -qF "FAIL — scp-relay [default features] reaches $VENDOR_CRATE."; rc=$?
  expect "(absent-reaches) it names scp-relay as well" "PASS" "$rc"

  # (coverage) every entry but the wheel deleted from ARTIFACTS, and a default
  # member vendors: the whole-workspace resolution still sees it.
  plant_gate "$gate_file" "$wheel_ok" "scp-ffi|--features extension-module,vendored-openssl"
  FAKE_DROPPED_TRIPLE=none FAKE_VENDORS="" FAKE_BARE_VENDORS=1 scenario "(coverage) run_gate FAILS when a member no ARTIFACTS entry names reaches $VENDOR_CRATE" "FAIL"
  printf '%s\n' "$scenario_out" | grep -qF "FAIL — the whole-workspace build reaches $VENDOR_CRATE."; rc=$?
  expect "(coverage) it names the whole-workspace build" "PASS" "$rc"

  # (unified) the wheel drops vendored-openssl while scp-testing, or a
  # dev-dependency, selects it: `cargo metadata` still shows the edge from
  # scp-ffi on every triple, so the presence half passes, and the whole-workspace
  # resolution is what fails the gate.
  plant_gate "$gate_file" "$(printf 'bindings/python/pyproject.toml\tscp-ffi|--features extension-module')" \
    "scp-node|" "scp-ffi|--features extension-module"
  FAKE_UNIFIED=1 FAKE_DROPPED_TRIPLE=none FAKE_VENDORS="" FAKE_BARE_VENDORS=1 scenario "(unified) run_gate FAILS when the wheel selects no vendored build and another member's selection unifies into the metadata graph" "FAIL"
  printf '%s\n' "$scenario_out" | grep -qF "ok   — x86_64-unknown-linux-gnu reaches $VENDOR_CRATE"; rc=$?
  expect "(unified) the presence half alone passes that tree, which is why the workspace resolution exists" "PASS" "$rc"
  printf '%s\n' "$scenario_out" | grep -qF "FAIL — the whole-workspace build reaches $VENDOR_CRATE."; rc=$?
  expect "(unified) the whole-workspace build names the member's selection" "PASS" "$rc"

  # (per-triple) the vendored build survives on the runner's triple and is gone on
  # the Windows wheel.
  plant_gate "$gate_file" "$wheel_ok" "scp-ffi|--features extension-module,vendored-openssl"
  FAKE_DROPPED_TRIPLE=x86_64-pc-windows-msvc FAKE_VENDORS="" FAKE_BARE_VENDORS="" scenario "(per-triple) run_gate FAILS when one wheel triple reaches no $VENDOR_CRATE" "FAIL"
  printf '%s\n' "$scenario_out" | grep -qF "FAIL — x86_64-pc-windows-msvc reaches no $VENDOR_CRATE"; rc=$?
  expect "(per-triple) it names that triple" "PASS" "$rc"
  printf '%s\n' "$scenario_out" | grep -qF "ok   — x86_64-unknown-linux-gnu reaches $VENDOR_CRATE"; rc=$?
  expect "(per-triple) and passes the triple that kept it" "PASS" "$rc"

  # (scoped) the wheel's entry still names vendored-openssl and the unified
  # metadata graph reaches openssl-src on every triple, but the wheel's package
  # resolved alone reaches none, as when scp-ffi stops enabling scp-platform/sqlite
  # while scp-node still does. No member selects the vendored build at default
  # features, so the whole-workspace resolution stays at zero.
  plant_gate "$gate_file" "$wheel_ok" "scp-node|" "scp-ffi|--features extension-module,vendored-openssl"
  FAKE_WHEEL_TREE_EMPTY=1 FAKE_DROPPED_TRIPLE=none FAKE_VENDORS="" FAKE_BARE_VENDORS="" scenario "(scoped) run_gate FAILS when only the unified graph carries the wheel's openssl-src edge" "FAIL"
  printf '%s\n' "$scenario_out" | grep -qF "ok   — x86_64-pc-windows-msvc reaches $VENDOR_CRATE"; rc=$?
  expect "(scoped) the per-triple walk alone passes that tree" "PASS" "$rc"
  printf '%s\n' "$scenario_out" | grep -qF "resolved alone, reaches no"; rc=$?
  expect "(scoped) the resolution of the wheel's package alone names the failure" "PASS" "$rc"
  printf '%s\n' "$scenario_out" | grep -qF "ok   — the whole-workspace build"; rc=$?
  expect "(scoped) and the whole-workspace resolution passes it, so only the scoped check catches it" "PASS" "$rc"

  if [[ "$fixture_failures" -eq 0 ]]; then
    echo "   FIXTURES: all behavioural proofs passed."
    return 0
  fi
  echo "   FIXTURES: $fixture_failures behavioural proof(s) failed."
  return 1
}

# ---------------------------------------------------------------------------
run_gate() {
  local failures=0 configuration pkg feature_args count wheel_entry wheel_file raw line tab
  local built triples triple
  local -a configurations=()

  # A `while read` loop rather than `mapfile`, which bash 3.2 — the interpreter
  # `/bin/bash` runs on a developer's macOS — does not define.
  raw="$(shipped_configurations "$FEATURE_GRAPH_GATE")" || {
    echo "FAIL — the shipped configurations could not be read from $FEATURE_GRAPH_GATE, so no graph was resolved."
    return 1
  }
  while IFS= read -r configuration; do
    [[ -n "$configuration" ]] && configurations+=("$configuration")
  done <<<"$raw"
  echo "--> ${#configurations[@]} shipped configurations read from $FEATURE_GRAPH_GATE --print-artifacts"

  line="$(wheel_line "$FEATURE_GRAPH_GATE")" || {
    echo "FAIL — the wheel's configuration could not be read from $FEATURE_GRAPH_GATE, so no graph was resolved."
    return 1
  }
  tab="$(printf '\t')"
  wheel_file="${line%%"$tab"*}"
  wheel_entry="${line#*"$tab"}"
  echo "--> the wheel builds configuration '$wheel_entry', read from $wheel_file"

  triples="$(wheel_triples "$WHEEL_MATRIX_FILE")" || {
    echo "FAIL — the wheel's target triples could not be read from job '$WHEEL_JOB' of $WHEEL_MATRIX_FILE."
    return 1
  }
  echo

  pkg="${wheel_entry%%|*}"
  feature_args="${wheel_entry#*|}"
  if ! built="$(cargo_arguments_for "$feature_args")"; then
    echo "FAIL — the wheel's configuration carries a cargo argument this gate refuses to build."
    return 1
  fi
  echo "--> the wheel's configuration, $pkg [${feature_args:-default features}], on each triple it ships for"
  while IFS= read -r triple; do
    if ! count="$(wheel_reach_count "$pkg" "$built" "$triple")"; then
      echo "    FAIL — cargo resolved no graph for the wheel on $triple; the stderr above names why."
      failures=$((failures + 1))
    elif [[ "$count" -gt 0 ]]; then
      echo "    ok   — $triple reaches $VENDOR_CRATE"
    else
      echo "    FAIL — $triple reaches no $VENDOR_CRATE, so the wheel built for it takes"
      echo "           its crypto from whatever its build host supplies. Name 'vendored-openssl' in"
      echo "           the [tool.maturin] features array of $wheel_file, and keep that"
      echo "           feature forwarding rusqlite/bundled-sqlcipher-vendored-openssl on"
      echo "           every target — see crates/scp-platform/Cargo.toml."
      failures=$((failures + 1))
    fi
  done <<<"$triples"
  # The per-triple counts read the workspace-unified graph, where another member's
  # features can switch on an edge from the wheel's package. `cargo tree -p`
  # resolves the wheel's package alone, so a count of zero here means the wheel's
  # own features select no openssl-src on any triple.
  if ! count="$(vendor_crate_occurrences "$pkg" "$built")"; then
    echo "    FAIL — cargo resolved no graph for the wheel's package alone; the stderr above names why."
    failures=$((failures + 1))
  elif [[ "$count" -gt 0 ]]; then
    echo "    ok   — $pkg [${feature_args:-default features}], resolved alone, reaches $VENDOR_CRATE"
  else
    echo "    FAIL — $pkg [${feature_args:-default features}], resolved alone, reaches no"
    echo "           $VENDOR_CRATE on any triple; each per-triple count above came from"
    echo "           another member's features in the unified cargo metadata graph."
    failures=$((failures + 1))
  fi
  echo

  echo "--> every other shipped configuration, resolved over every target triple, reaches no $VENDOR_CRATE"
  for configuration in "${configurations[@]}"; do
    [[ "$configuration" == "$wheel_entry" ]] && continue
    pkg="${configuration%%|*}"
    feature_args="${configuration#*|}"
    if ! built="$(cargo_arguments_for "$feature_args")"; then
      echo "    FAIL — $pkg [$feature_args] carries a cargo argument this gate refuses to build;"
      echo "           an entry names a package's feature selection and nothing else."
      failures=$((failures + 1))
      continue
    fi
    if ! count="$(vendor_crate_occurrences "$pkg" "$built")"; then
      echo "    FAIL — cargo resolved no graph for $pkg [${feature_args:-default features}]; the stderr above names why."
      failures=$((failures + 1))
    elif [[ "$count" -eq 0 ]]; then
      echo "    ok   — $pkg [${feature_args:-default features}]"
    else
      echo "    FAIL — $pkg [${feature_args:-default features}] reaches $VENDOR_CRATE."
      failures=$((failures + 1))
    fi
  done
  if ! count="$(workspace_occurrences)"; then
    echo "    FAIL — cargo resolved no graph for the whole-workspace build; the stderr above names why."
    failures=$((failures + 1))
  elif [[ "$count" -eq 0 ]]; then
    echo "    ok   — the whole-workspace build, which holds every member and every dev-dependency"
  else
    echo "    FAIL — the whole-workspace build reaches $VENDOR_CRATE. A member or a"
    echo "           dev-dependency selects the vendored build on its own, which also"
    echo "           lets the wheel's presence count above pass without the wheel's"
    echo "           own features."
    failures=$((failures + 1))
  fi
  echo

  if [[ "$failures" -eq 0 ]]; then
    echo "PASS — $VENDOR_CRATE reaches the PyPI wheel on every triple it ships for and reaches no other shipped artifact."
    return 0
  fi
  echo "FAIL — $failures resolution(s) went the wrong way. An artifact other than the wheel"
  echo "       that reaches $VENDOR_CRATE embeds a statically compiled OpenSSL: for scp-node"
  echo "       and scp-relay that breaks the libssl3 upgrade Dockerfile and"
  echo "       templates/personal-relay/README.md document, and for a bridge it changes"
  echo "       what an npm package or an XCFramework carries. Ask for the vendored build"
  echo "       through scp-platform/vendored-openssl on the wheel alone, never through the"
  echo "       rusqlite feature list in a workspace or crate dependency table."
  return 1
}

main() {
  echo "==> vendored-OpenSSL scope: $VENDOR_CRATE reaches the PyPI wheel and nothing else this repository ships"
  echo
  run_fixtures || exit 1
  echo

  if [[ "${1:-}" == "--self-test" ]]; then
    echo "--self-test: skipping the workspace gate."
    exit 0
  fi

  run_gate || exit 1
  exit 0
}

main "$@"
