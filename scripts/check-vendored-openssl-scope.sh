#!/usr/bin/env bash
#
# Vendored-OpenSSL scope gate.
#
# CRITERION
# ---------
# Exactly one shipped configuration selects the `vendored-openssl` feature, that
# configuration is character for character the configuration maturin builds the
# PyPI wheel with, `openssl-src` — the crate whose build script compiles OpenSSL
# from source so `openssl-sys` links it statically — appears in that
# configuration's shipped dependency graph, and `openssl-src` appears in the
# shipped dependency graph of no other configuration this repository ships.
#
# The comparison reads the whole `<package>|<feature arguments>` entry, not its
# package half. Three entries of the `ARTIFACTS` array build package `scp-ffi` —
# the `--no-default-features --features server` bridge cdylib, the
# default-features bridge cdylib, and the wheel — so a package-name comparison
# admits a tree that moved the vendored build from the wheel onto either bridge,
# which is one of the two outcomes this gate exists to reject.
#
# WHERE EACH FACT COMES FROM
# --------------------------
# This gate hand-writes neither the list of shipped configurations nor the wheel's
# identity, and it parses neither out of another file's source text. It asks the
# gate that owns both lists to print them:
#
#   * `bash scripts/check-shipped-feature-graph.sh --print-artifacts` writes that
#     gate's `ARTIFACTS` array, one entry per line, as bash holds it. That array is
#     where this repository records what it ships, so a configuration added there
#     is checked here on the commit that adds it.
#   * `bash scripts/check-shipped-feature-graph.sh --print-wheel-entries` writes one
#     `<maturin project file><TAB><package>|<feature arguments>` line per entry of
#     that gate's `MATURIN_PROJECT_FILES` array, which holds every pyproject.toml a
#     maturin step of `.github/workflows/build-matrix.yml` can read. Each entry is
#     what that file's `[tool.maturin]` table makes maturin compile, derived by
#     that gate's `maturin_artifact_entry`. `run_gate` below fails unless exactly
#     one such line came back, so a second wheel added to that array stops this run
#     and asks a human which wheel carries the vendored build.
#   * Which configuration carries the vendored build comes from the feature
#     arguments of each entry, so that answer tracks the `ARTIFACTS` array too.
#     `assert_wheel_feature_selection_is_gated` of that same gate fails unless the
#     wheel's `[tool.maturin]` table derives an `ARTIFACTS` entry verbatim, so the
#     two lists this gate compares name the same configurations.
#
# WHY THIS GATE INVOKES A MODE RATHER THAN PARSING A FILE
# -------------------------------------------------------
# An earlier revision read the `ARTIFACTS` array by parsing the source text of
# `scripts/check-shipped-feature-graph.sh`: it searched for an `ARTIFACTS=(`
# opener and read the lines up to the first `)` at column 0. Three review rounds
# each found another way to write a shell array assignment that the parser did not
# see — a second assignment, an `ARTIFACTS+=(` appender, and three further
# spellings — and each one left bash holding entries the parser never reported
# while this gate printed PASS. Every round closed the spelling it found and left
# the next one open, which is the non-convergent enforcement `CLAUDE.md` forbids
# under "Guard against over-engineering and non-convergent enforcement".
#
# Bash expansion sees every spelling of an assignment, so asking bash to expand the
# array closes that whole class by construction instead of by enumeration. The
# owner gate's `assert_print_modes_emit_what_this_gate_holds` holds the mode to
# what bash holds, and plants both a second `ARTIFACTS=(` assignment and an
# `ARTIFACTS+=(` appender into a copy of that file to prove it.
#
# WHY EACH HALF IS A SEPARATE FAILURE
# -----------------------------------
# The wheel needs the vendored copy: `pip install` runs no linker and installs onto
# a machine whose OpenSSL this build never saw, so SQLCipher's crypto has to travel
# inside the wheel. `bindings/python/pyproject.toml` asks for it by naming
# `vendored-openssl` in its `[tool.maturin] features` array, which reaches
# `scp-platform/vendored-openssl` and from there adds
# `rusqlite/bundled-sqlcipher-vendored-openssl`. Drop that name and the wheel
# silently reverts to linking whatever libcrypto the build host happened to have,
# so this gate fails when no shipped configuration selects the feature.
#
# Every other shipped configuration must not get it, for two different reasons. The
# mechanical reason is common to both: a vendored OpenSSL changes patch level only
# when someone bumps `Cargo.lock`, and nothing in this repository reports that copy
# as stale — `Rust / deny` reads the RustSec database over Rust crates, and no job
# runs an SBOM or a container scanner.
#
#   * `scp-node` and `scp-relay` ship in a container whose operator patches OpenSSL
#     by upgrading `libssl3` in the runtime layer; `Dockerfile` and
#     `templates/personal-relay/README.md` both name that dynamic link as the
#     reason they install `libssl3`. Vendoring into these two breaks an operator
#     procedure this repository documents.
#   * `scp-core` and the six FFI-bridge configurations link the libcrypto their
#     build host supplies, which is what they do on `main` today. This gate records
#     that as the shipped state, so a workspace-wide feature edit cannot change it
#     as a side effect. It is not a finding that linking the build host's libcrypto
#     is the right answer for a prebuilt `index.node` or an XCFramework that
#     `.github/workflows/release.yml` publishes to npm and to Maven Central — no
#     operator upgrades `libssl3` inside an installed npm package, and what those
#     artifacts should link is an open question this gate does not answer. Changing
#     the answer means changing what those artifacts select, which fails this gate
#     by name, so that change is a decision someone made rather than a side effect.
#
# Pull request #2119, the Python wheel CI fix, set the vendored feature in the
# workspace dependency table, which reached both binaries — the
# `Docker / relay and node image` job failed inside `openssl-src`'s build script —
# and left both recipes asserting a linkage the build no longer performed. This
# gate reports the next such edit by name rather than by a Docker build breaking,
# and the `absent-reaches` fixture below plants exactly that edit.
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
# `--self-test` runs the fixtures below and skips the workspace gate. The fixtures
# run before the workspace gate on every invocation, so a reader that has stopped
# deriving what it claims to derive fails loudly rather than passing a tree it
# never read.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

VENDOR_CRATE="openssl-src"
VENDOR_FEATURE="vendored-openssl"
FEATURE_GRAPH_GATE="scripts/check-shipped-feature-graph.sh"

# The program that enumerates the packages this workspace ships as binaries.
#
# CRITERION: a default workspace member that builds a `[[bin]]` target is an
# artifact this repository ships, so a shipped-configuration list that names no
# configuration for it leaves it unchecked.
#
# `run_gate` reads this list and fails when a package it names appears in no
# configuration. A typed floor cannot state that property: this gate carried
# `MINIMUM_SHIPPED_CONFIGURATIONS=2` against a list of ten, and an adversarial
# review deleted eight entries, leaving the wheel and one bridge. Both gates
# stayed green while `scp-node` and `scp-relay` — the two artifacts the CRITERION
# section above names as the reason this gate exists — went uncovered, and the
# final line still read "reaches no other shipped artifact".
#
# It reads `cargo metadata`, which resolves `default-members` and every `[[bin]]`
# target for itself, rather than matching manifest text. An enumeration that comes
# back empty fails, because "no binary to cover" and "the reader stopped working"
# must not print the same verdict.
read -r -d '' BINARY_PACKAGES_PROGRAM <<'PYTHON' || true
import json
import sys

document = json.load(sys.stdin)
default_members = set(
    document.get("workspace_default_members")
    or document.get("workspace_members")
    or []
)

names = set()
for package in document.get("packages", []):
    if package.get("id") not in default_members:
        continue
    for target in package.get("targets", []):
        if "bin" in (target.get("kind") or []):
            names.add(package["name"])

if not names:
    print(
        "cargo metadata named no default-member package building a [[bin]] target",
        file=sys.stderr,
    )
    raise SystemExit(1)

for name in sorted(names):
    print(name)
PYTHON

# The first interpreter on PATH. `json` is in every Python standard library, so
# this needs no version floor; `default_member_binary_packages` fails when no
# candidate is present rather than enumerating nothing.
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
#   One condition, not two. An earlier revision tested `-f "$file"` first, and no
#   input separated that branch from this one, because `bash` exits 127 on a file
#   it cannot open and writes its own "No such file or directory" to the stderr
#   this function lets through. A branch no fixture can drive is a branch that
#   states nothing.
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
#   configuration this returns, so the list is its own coverage floor for what it
#   names, and `default_member_binary_packages` below decides what it must name.
shipped_configurations() {
  local file="$1"
  feature_graph_gate_prints "$file" --print-artifacts || return 1
}

# default_member_binary_packages
#   Emit the package name of every default workspace member that builds a
#   `[[bin]]` target, one per line, sorted. FAILS when no interpreter is on PATH,
#   when cargo metadata exits non-zero, and when the enumeration is empty.
default_member_binary_packages() {
  local metadata rc=0
  if [[ -z "$SCOPE_JSON_READER" ]]; then
    echo "no python3.12, python3, or python on PATH, so this gate cannot read cargo metadata to enumerate the binaries this workspace ships" >&2
    return 1
  fi
  metadata="$(cargo metadata --format-version 1 --no-deps 2>&1)" || rc=$?
  if [[ "$rc" -ne 0 ]]; then
    { echo "cargo metadata exited $rc, so this gate enumerated no shipped binary:"
      printf '%s\n' "$metadata"; } >&2
    return 1
  fi
  printf '%s' "$metadata" | "$SCOPE_JSON_READER" -c "$BINARY_PACKAGES_PROGRAM"
}

# host_target
#   Emit the target triple this machine compiles for, read from `rustc -vV`.
#   FAILS when that output names no host.
host_target() {
  local triple
  triple="$(rustc -vV 2>/dev/null | sed -n 's/^host: //p')"
  if [[ -z "$triple" ]]; then
    echo "rustc -vV named no host triple, so this gate cannot resolve the wheel on the target it ships for" >&2
    return 1
  fi
  printf '%s\n' "$triple"
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
#   WHY THE GATE BUILDS THE COMMAND. An earlier revision spliced the whole
#   feature-argument string into `cargo tree` unquoted, so an entry could carry
#   any cargo argument. An adversarial review wrote
#   `scp-ffi|--features scp-platform/vendored-openssl --depth 0` into the
#   `ARTIFACTS` array: `--depth 0` truncates the tree to its root line, the
#   occurrence count came back zero, and this gate printed `ok` for a bridge
#   cdylib that genuinely reached `openssl-src` — the cdylib
#   `.github/workflows/build-matrix.yml` uploads and `.github/workflows/release.yml`
#   signs. The sibling gate resisted the same entry only because it proves
#   PRESENCE, so a truncated tree hands it an empty resolution its non-empty guard
#   rejects; this gate proves ABSENCE, and a truncated tree hands an absence proof
#   exactly the answer it is looking for.
#
#   The repair is that data stops being argv. `run_gate` builds the argument list
#   from the fields this reader validates, so no substring of an entry is ever
#   word-split into a command, and a resolver flag cannot reach cargo through the
#   array at all.
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

# configuration_selects_feature <built-arguments> <feature>
#   Succeed when the configuration compiles the feature: its `--features` list
#   names it, or it names `--all-features`, which selects every feature the
#   package defines. Reads the argument list cargo_arguments_for validated, so it
#   decides membership in a parsed list rather than matching a substring of a
#   string. `not-vendored-openssl` and `vendored-openssl-experimental` are
#   different features and do not match, because the comparison is on whole list
#   elements.
configuration_selects_feature() {
  local built="$1" feature="$2" argument name
  while IFS= read -r argument; do
    [[ -z "$argument" ]] && continue
    if [[ "$argument" == "--all-features" ]]; then
      return 0
    fi
    local list=""
    if [[ "$argument" == --features=* ]]; then
      list="${argument#--features=}"
    elif [[ "$argument" != --* ]]; then
      list="$argument"
    fi
    [[ -z "$list" ]] && continue
    for name in ${list//,/ }; do
      if [[ "$name" == "$feature" ]]; then
        return 0
      fi
    done
  done <<<"$built"
  return 1
}

# vendor_crate_occurrences <package> <built-arguments> <target>
#   Emit the number of times the vendored crate appears in the package's shipped
#   dependency graph, and return non-zero when cargo resolved no graph. `-e no-dev`
#   drops dev-dependencies, which no shipped artifact compiles.
#
#   The arguments arrive one per line from cargo_arguments_for, which validated
#   every token, and this function puts them in an array. Nothing here word-splits
#   a string into a command, so an `ARTIFACTS` entry cannot carry a resolver flag
#   into this invocation.
#
#   <target> is the triple to resolve for, and the two halves of this gate pass
#   different ones — see the SHIPPED-TARGET comment on the invocation below.
#
#   Cargo's exit status decides whether the count means anything, so this function
#   reads that status. A count taken from a resolution that failed is the number
#   zero, and `run_gate` reads zero as the proof that an artifact reaches no
#   `openssl-src`: an earlier version of this function discarded the status, so a
#   renamed package or a renamed feature in one `ARTIFACTS` entry made every absent
#   configuration print `ok` and made the run print `PASS` while cargo had resolved
#   nothing. Both call sites treat a non-zero return as a gate failure.
vendor_crate_occurrences() {
  local pkg="$1" built="$2" target="$3" tree count cargo_rc=0 grep_rc=0 argument
  local -a args=()
  while IFS= read -r argument; do
    [[ -n "$argument" ]] && args+=("$argument")
  done <<<"$built"
  # SHIPPED-TARGET: the caller chooses. The absence half passes `all`, so a
  # dependency edge under a `[target.'cfg(…)'.dependencies]` table that is false
  # on this runner stays visible. The presence half passes the host triple,
  # because `--target all` over-approximates there: it counts an edge only an
  # unshipped target compiles, so moving the rusqlite dependency of
  # crates/scp-platform/Cargo.toml under `[target.'cfg(windows)'.dependencies]`
  # would keep the wheel's count at 1 while every manylinux wheel linked the build
  # host's libcrypto.
  tree="$(cargo tree -p "$pkg" ${args[@]+"${args[@]}"} -e no-dev --target "$target" --prefix none --format '{p}' 2>&1)" || cargo_rc=$?
  if [[ "$cargo_rc" -ne 0 ]]; then
    {
      echo "cargo tree exited $cargo_rc for package '$pkg' on target '$target' with arguments '${args[*]:-none}':"
      printf '%s\n' "$tree"
    } >&2
    return 1
  fi
  # grep exits 1 when the graph names the crate zero times, which is the answer
  # every absent configuration must give, and exits above 1 when grep itself
  # failed. `|| grep_rc=$?` keeps those two apart, where `|| true` merged them.
  count="$(printf '%s\n' "$tree" | grep -cE "^${VENDOR_CRATE} v")" || grep_rc=$?
  if [[ "$grep_rc" -gt 1 ]]; then
    echo "grep exited $grep_rc while counting $VENDOR_CRATE in the graph of '$pkg'" >&2
    return 1
  fi
  printf '%s\n' "$count"
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
  local dir file out rc wheel built_depth coverage_out
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
  # everything else. `--depth 0` is the flag an adversarial review wrote into the
  # ARTIFACTS array to truncate a tree to its root, which made this gate print ok
  # for a bridge cdylib that reached openssl-src.
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

  configuration_selects_feature "$(cargo_arguments_for '--features extension-module,vendored-openssl')" "vendored-openssl"; rc=$?
  expect "a comma-separated feature list selects the feature" "PASS" "$rc"
  configuration_selects_feature "$(cargo_arguments_for '--features=vendored-openssl')" "vendored-openssl"; rc=$?
  expect "the '--features=<list>' spelling selects the feature" "PASS" "$rc"
  configuration_selects_feature "$(cargo_arguments_for '--all-features')" "vendored-openssl"; rc=$?
  expect "'--all-features' selects it, because it selects every feature the package defines" "PASS" "$rc"
  configuration_selects_feature "$(cargo_arguments_for '--no-default-features --features server')" "vendored-openssl"; rc=$?
  expect "a configuration naming another feature does NOT select it" "FAIL" "$rc"
  configuration_selects_feature "$(cargo_arguments_for '')" "vendored-openssl"; rc=$?
  expect "a default-features configuration does NOT select it" "FAIL" "$rc"
  configuration_selects_feature "$(cargo_arguments_for '--features not-vendored-openssl')" "vendored-openssl"; rc=$?
  expect "a longer feature name ending in it does NOT select it" "FAIL" "$rc"
  configuration_selects_feature "$(cargo_arguments_for '--features vendored-openssl-experimental')" "vendored-openssl"; rc=$?
  expect "a longer feature name starting with it does NOT select it" "FAIL" "$rc"

  # `vendor_crate_occurrences` counts lines of a resolved graph, and these three
  # fixtures run it against a `cargo` that prints a chosen graph or refuses to
  # resolve one. They prove the counter reports a present crate, reports an absent
  # crate as zero, and reports a refusal as a failure rather than as a zero. The
  # third one is what makes the absent-configuration half of this gate able to
  # fail: a `cargo tree` that exits non-zero prints no line, and a counter that
  # discarded cargo's status returned zero, which that loop reads as the proof it
  # was asking for.
  local saved_path
  mkdir -p "$dir/fakebin"
  saved_path="$PATH"

  printf '%s\n' \
    '#!/bin/sh' \
    'echo "scp-ffi v0.1.0"' \
    "echo \"${VENDOR_CRATE} v300.5.1+3.5.1\"" \
    'echo "openssl-sys v0.9.109"' > "$dir/fakebin/cargo"
  chmod +x "$dir/fakebin/cargo"
  PATH="$dir/fakebin:$saved_path"
  out="$(vendor_crate_occurrences "scp-ffi" "$(cargo_arguments_for '--features extension-module,vendored-openssl')" "$(host_target)")"; rc=$?
  PATH="$saved_path"
  expect "a graph naming the vendored crate is counted" "PASS" "$rc"
  same_string "$out" "1"; rc=$?
  expect "that count is the number of $VENDOR_CRATE lines the graph holds" "PASS" "$rc"

  printf '%s\n' \
    '#!/bin/sh' \
    'echo "scp-node v0.1.0"' \
    'echo "openssl-sys v0.9.109"' > "$dir/fakebin/cargo"
  chmod +x "$dir/fakebin/cargo"
  PATH="$dir/fakebin:$saved_path"
  out="$(vendor_crate_occurrences "scp-node" "" all)"; rc=$?
  PATH="$saved_path"
  expect "a graph naming no $VENDOR_CRATE is counted" "PASS" "$rc"
  same_string "$out" "0"; rc=$?
  expect "that count is zero, which is what an absent configuration must report" "PASS" "$rc"

  printf '%s\n' \
    '#!/bin/sh' \
    'echo "error: none of the selected packages contains these features" >&2' \
    'exit 101' > "$dir/fakebin/cargo"
  chmod +x "$dir/fakebin/cargo"
  PATH="$dir/fakebin:$saved_path"
  vendor_crate_occurrences "scp-node" "$(cargo_arguments_for '--features gone')" all >/dev/null 2>&1; rc=$?
  PATH="$saved_path"
  expect "a cargo tree that exits non-zero FAILS rather than counting zero" "FAIL" "$rc"

  # (entry-whitelist) the argument vector vendor_crate_occurrences hands cargo.
  # The fake cargo writes each argument it received on its own line, and this
  # reads that file, so the assertion states what the function passed rather than
  # restating the command this file already writes. A feature list must arrive as
  # ONE argument: that is what makes a space inside an ARTIFACTS entry unable to
  # become a second flag.
  printf '%s\n' \
    '#!/bin/sh' \
    ': > "$ARGV_DUMP"' \
    'for a in "$@"; do printf "%s\\n" "$a" >> "$ARGV_DUMP"; done' > "$dir/fakebin/cargo"
  chmod +x "$dir/fakebin/cargo"
  PATH="$dir/fakebin:$saved_path"
  ARGV_DUMP="$dir/argv.txt" vendor_crate_occurrences \
    "scp-ffi" "$(cargo_arguments_for '--no-default-features --features a,b')" all >/dev/null 2>&1
  PATH="$saved_path"
  same_string "$(cat "$dir/argv.txt")" "$(printf '%s\n' 'tree' '-p' 'scp-ffi' '--no-default-features' '--features' 'a,b' '-e' 'no-dev' '--target' 'all' '--prefix' 'none' '--format' '{p}')"; rc=$?
  expect "(entry-whitelist) the feature list reaches cargo as ONE argument, so no space inside an entry becomes a second flag" "PASS" "$rc"

  # And the same read against an entry the whitelist refuses: cargo_arguments_for
  # fails, so the counter is never called and cargo is never run. The dump from
  # the run above is deleted first, so a file still holding those lines would be
  # the previous invocation's and this assertion would be reading a stale answer.
  rm -f "$dir/argv.txt"
  PATH="$dir/fakebin:$saved_path"
  if built_depth="$(cargo_arguments_for '--features server --depth 0' 2>/dev/null)"; then
    ARGV_DUMP="$dir/argv.txt" vendor_crate_occurrences "scp-ffi" "$built_depth" all >/dev/null 2>&1
  fi
  PATH="$saved_path"
  if [[ -f "$dir/argv.txt" ]]; then rc=1; else rc=0; fi
  expect "(entry-whitelist) a refused entry runs no cargo at all, so no truncated tree is counted" "PASS" "$rc"

  # run_gate end to end, against a planted gate and a cargo whose graph names
  # openssl-src exactly when the feature arguments select the vendored feature, so
  # the counter reports what each configuration asked for.
  #
  # Every planted cargo below also answers `metadata` out of $FAKE_METADATA,
  # because run_gate reads the workspace's binary packages before it resolves
  # anything. Each scenario therefore states the workspace it plants as well as
  # the graph, and a scenario that plants a binary its configuration list omits
  # fails on coverage rather than on the property it means to test.
  local gate_file ffi_only_metadata binaries_metadata
  gate_file="$dir/scenario-gate.sh"
  ffi_only_metadata='{"workspace_default_members":["c 0.1.0 (path+file:///w/scp-ffi)"],"packages":[{"id":"c 0.1.0 (path+file:///w/scp-ffi)","name":"scp-ffi","targets":[{"kind":["bin"],"name":"scp-ffi"}]}]}'
  binaries_metadata='{"workspace_default_members":["a 0.1.0 (path+file:///w/scp-node)","b 0.1.0 (path+file:///w/scp-relay)"],"packages":[{"id":"a 0.1.0 (path+file:///w/scp-node)","name":"scp-node","targets":[{"kind":["bin"],"name":"scp-node"}]},{"id":"b 0.1.0 (path+file:///w/scp-relay)","name":"scp-relay","targets":[{"kind":["bin"],"name":"scp-relay"}]}]}'
  printf '%s\n' \
    '#!/bin/sh' \
    'if [ "$1" = "metadata" ]; then printf "%s\\n" "$FAKE_METADATA"; exit 0; fi' \
    'echo "the-package v0.1.0"' \
    'case "$*" in' \
    "  *vendored-openssl*) echo \"${VENDOR_CRATE} v300.5.1+3.5.1\" ;;" \
    'esac' > "$dir/fakebin/cargo"
  chmod +x "$dir/fakebin/cargo"

  # The negative control a package-name comparison admitted: `vendored-openssl`
  # moves off the wheel's entry onto the `--features server` bridge cdylib, whose
  # package is `scp-ffi` as well.
  plant_gate "$gate_file" "$(printf 'bindings/python/pyproject.toml\tscp-ffi|--features extension-module')" \
    "scp-ffi|--no-default-features --features server,vendored-openssl" \
    "scp-ffi|" \
    "scp-ffi|--features extension-module"
  PATH="$dir/fakebin:$saved_path"
  ( FAKE_METADATA="$ffi_only_metadata" FEATURE_GRAPH_GATE="$gate_file" run_gate ) >/dev/null 2>&1; rc=$?
  PATH="$saved_path"
  expect "run_gate FAILS when the vendored feature moves onto a sibling scp-ffi configuration" "FAIL" "$rc"

  # The positive control: the same tree with the feature back on the wheel, which
  # proves the assertion above goes green for a reason other than every input
  # failing.
  plant_gate "$gate_file" "$(printf 'bindings/python/pyproject.toml\tscp-ffi|--features extension-module,vendored-openssl')" \
    "scp-ffi|--no-default-features --features server" \
    "scp-ffi|" \
    "scp-ffi|--features extension-module,vendored-openssl"
  PATH="$dir/fakebin:$saved_path"
  ( FAKE_METADATA="$ffi_only_metadata" FEATURE_GRAPH_GATE="$gate_file" run_gate ) >/dev/null 2>&1; rc=$?
  PATH="$saved_path"
  expect "run_gate PASSES when that same tree keeps the vendored feature on the wheel" "PASS" "$rc"

  # (absent-reaches) the branch this gate exists for, which no fixture reached
  # until this one: an artifact whose configuration names NO feature, whose graph
  # reaches openssl-src anyway. That is what pull request #2119, the Python wheel
  # CI fix, did — it set the vendored feature in the workspace dependency table,
  # which reached `scp-node` and `scp-relay` without either binary's ARTIFACTS
  # entry changing a character, and the `Docker / relay and node image` job failed
  # inside `openssl-src`'s build script rather than this gate naming the two
  # binaries. The cargo below vendors for those two packages whatever features the
  # arguments select, which is what a workspace dependency table does.
  local absent_out
  printf '%s\n' \
    '#!/bin/sh' \
    'if [ "$1" = "metadata" ]; then printf "%s\\n" "$FAKE_METADATA"; exit 0; fi' \
    'echo "the-package v0.1.0"' \
    'case "$*" in' \
    "  *vendored-openssl*|*\"-p scp-node\"*|*\"-p scp-relay\"*) echo \"${VENDOR_CRATE} v300.5.1+3.5.1\" ;;" \
    'esac' > "$dir/fakebin/cargo"
  chmod +x "$dir/fakebin/cargo"
  plant_gate "$gate_file" "$(printf 'bindings/python/pyproject.toml\tscp-ffi|--features extension-module,vendored-openssl')" \
    "scp-node|" \
    "scp-relay|" \
    "scp-ffi|--features extension-module,vendored-openssl"
  PATH="$dir/fakebin:$saved_path"
  absent_out="$( FAKE_METADATA="$binaries_metadata" FEATURE_GRAPH_GATE="$gate_file" run_gate 2>&1 )"; rc=$?
  PATH="$saved_path"
  expect "(absent-reaches) run_gate FAILS when a binary that selects no feature reaches $VENDOR_CRATE" "FAIL" "$rc"
  printf '%s\n' "$absent_out" | grep -E "^ +FAIL — scp-node \[default features\] reaches $VENDOR_CRATE\.$" >/dev/null; rc=$?
  expect "(absent-reaches) it names scp-node, the binary whose container operator patches libssl3" "PASS" "$rc"
  printf '%s\n' "$absent_out" | grep -E "^ +FAIL — scp-relay \[default features\] reaches $VENDOR_CRATE\.$" >/dev/null; rc=$?
  expect "(absent-reaches) it names scp-relay as well, so one report covers every artifact the edit reached" "PASS" "$rc"

  # The positive control for that same tree: a cargo that vendors only for the
  # configuration asking for it leaves both binaries clean and the run green, so
  # the two assertions above reject the planted edit rather than the tree shape.
  printf '%s\n' \
    '#!/bin/sh' \
    'if [ "$1" = "metadata" ]; then printf "%s\\n" "$FAKE_METADATA"; exit 0; fi' \
    'echo "the-package v0.1.0"' \
    'case "$*" in' \
    "  *vendored-openssl*) echo \"${VENDOR_CRATE} v300.5.1+3.5.1\" ;;" \
    'esac' > "$dir/fakebin/cargo"
  chmod +x "$dir/fakebin/cargo"
  PATH="$dir/fakebin:$saved_path"
  ( FAKE_METADATA="$binaries_metadata" FEATURE_GRAPH_GATE="$gate_file" run_gate ) >/dev/null 2>&1; rc=$?
  PATH="$saved_path"
  expect "(absent-reaches) run_gate PASSES on that same tree once only the wheel's configuration vendors" "PASS" "$rc"

  # (binary-coverage) the deletion an adversarial review made: eight of the ten
  # ARTIFACTS entries removed, leaving the wheel and one bridge. Every remaining
  # configuration resolves correctly, so a gate that only checks what the list
  # names prints PASS — and scp-node and scp-relay, the two artifacts the CRITERION
  # section names as the reason this gate exists, are no longer checked at all.
  # run_gate reads the workspace's own binary packages and fails, naming them.
  #
  # The fake cargo answers `metadata` with a workspace whose two default members
  # build binaries, and answers `tree` with a graph that vendors only where the
  # arguments ask, so the failure below is the coverage check and not a resolution.
  local coverage_metadata
  coverage_metadata='{"workspace_default_members":["a 0.1.0 (path+file:///w/scp-node)","b 0.1.0 (path+file:///w/scp-relay)","c 0.1.0 (path+file:///w/scp-ffi)"],"packages":[{"id":"a 0.1.0 (path+file:///w/scp-node)","name":"scp-node","targets":[{"kind":["bin"],"name":"scp-node"}]},{"id":"b 0.1.0 (path+file:///w/scp-relay)","name":"scp-relay","targets":[{"kind":["bin"],"name":"scp-relay"}]},{"id":"c 0.1.0 (path+file:///w/scp-ffi)","name":"scp-ffi","targets":[{"kind":["cdylib"],"name":"scp_ffi"}]}]}'
  printf '%s\n' \
    '#!/bin/sh' \
    'if [ "$1" = "metadata" ]; then printf "%s\\n" "$FAKE_METADATA"; exit 0; fi' \
    'echo "the-package v0.1.0"' \
    'case "$*" in' \
    "  *vendored-openssl*) echo \"${VENDOR_CRATE} v300.5.1+3.5.1\" ;;" \
    'esac' > "$dir/fakebin/cargo"
  chmod +x "$dir/fakebin/cargo"

  plant_gate "$gate_file" "$(printf 'bindings/python/pyproject.toml\tscp-ffi|--features extension-module,vendored-openssl')" \
    "scp-ffi|--no-default-features --features server" \
    "scp-ffi|--features extension-module,vendored-openssl"
  PATH="$dir/fakebin:$saved_path"
  coverage_out="$( FAKE_METADATA="$coverage_metadata" FEATURE_GRAPH_GATE="$gate_file" run_gate 2>&1 )"; rc=$?
  PATH="$saved_path"
  expect "(binary-coverage) run_gate FAILS when the shipped-configuration list names no configuration for a binary this workspace builds" "FAIL" "$rc"
  printf '%s\n' "$coverage_out" | grep -E '^ +scp-node$' >/dev/null; rc=$?
  expect "(binary-coverage) it names scp-node as uncovered" "PASS" "$rc"
  printf '%s\n' "$coverage_out" | grep -E '^ +scp-relay$' >/dev/null; rc=$?
  expect "(binary-coverage) it names scp-relay as uncovered" "PASS" "$rc"

  # The positive control: the same tree with both binaries back in the list passes,
  # so the two assertions above reject the deletion rather than the fixture shape.
  plant_gate "$gate_file" "$(printf 'bindings/python/pyproject.toml\tscp-ffi|--features extension-module,vendored-openssl')" \
    "scp-ffi|--no-default-features --features server" \
    "scp-node|" \
    "scp-relay|" \
    "scp-ffi|--features extension-module,vendored-openssl"
  PATH="$dir/fakebin:$saved_path"
  ( FAKE_METADATA="$coverage_metadata" FEATURE_GRAPH_GATE="$gate_file" run_gate ) >/dev/null 2>&1; rc=$?
  PATH="$saved_path"
  expect "(binary-coverage) run_gate PASSES once both binaries appear in the list again" "PASS" "$rc"

  # A cargo metadata this reader cannot enumerate fails the run rather than
  # reporting that every binary is covered, which is what an empty enumeration
  # would otherwise say.
  printf '%s\n' '#!/bin/sh' 'if [ "$1" = "metadata" ]; then echo "{}"; exit 0; fi' 'echo "the-package v0.1.0"' > "$dir/fakebin/cargo"
  chmod +x "$dir/fakebin/cargo"
  PATH="$dir/fakebin:$saved_path"
  ( FEATURE_GRAPH_GATE="$gate_file" run_gate ) >/dev/null 2>&1; rc=$?
  PATH="$saved_path"
  expect "(binary-coverage) a cargo metadata naming no binary package FAILS rather than covering nothing" "FAIL" "$rc"

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
  local built binaries binary_package covered host
  local -a configurations=() vendoring=() absent=() missing=()

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
  echo

  # Every configuration above is checked below, so the list is its own coverage
  # floor for what it names. That says nothing about what the list OMITS, so this
  # reads the workspace: a default member building a binary is an artifact this
  # repository ships, and a list naming no configuration for it leaves it
  # unchecked. A typed entry-count floor could not state that — this gate carried
  # a floor of two against a list of ten, and deleting eight entries left
  # scp-node and scp-relay uncovered under a green run.
  if ! binaries="$(default_member_binary_packages)"; then
    echo "FAIL — the binaries this workspace ships could not be enumerated, so this"
    echo "       run cannot say whether the shipped-configuration list covers them."
    return 1
  fi
  while IFS= read -r binary_package; do
    [[ -z "$binary_package" ]] && continue
    covered=0
    for configuration in "${configurations[@]}"; do
      if [[ "${configuration%%|*}" == "$binary_package" ]]; then
        covered=1
        break
      fi
    done
    if [[ "$covered" -eq 0 ]]; then
      missing+=("$binary_package")
    fi
  done <<<"$binaries"
  if [[ "${#missing[@]}" -ne 0 ]]; then
    echo "FAIL — this workspace ships ${#missing[@]} binary package(s) that the"
    echo "       shipped-configuration list names no configuration for:"
    printf '       %s\n' "${missing[@]}"
    echo "       Each is a default workspace member building a [[bin]] target, so a"
    echo "       build produces it and nothing here proved what it links. Add an"
    echo "       ARTIFACTS entry for each in $FEATURE_GRAPH_GATE, or drop it from"
    echo "       default-members if this repository no longer ships it."
    return 1
  fi
  echo "--> every default-member binary package appears in that list"
  echo

  for configuration in "${configurations[@]}"; do
    if ! built="$(cargo_arguments_for "${configuration#*|}")"; then
      echo "FAIL — a shipped configuration carries a cargo argument this gate refuses"
      echo "       to build, so no graph was resolved. The stderr above names the"
      echo "       token. An entry names a package's feature selection and nothing"
      echo "       else, which is what keeps a resolver flag — '--depth 0' truncates"
      echo "       a tree to its root and makes every absence proof read zero — out"
      echo "       of the command this gate runs."
      return 1
    fi
    if configuration_selects_feature "$built" "$VENDOR_FEATURE"; then
      vendoring+=("$configuration")
    else
      absent+=("$configuration")
    fi
  done

  if [[ "${#vendoring[@]}" -ne 1 ]]; then
    echo "FAIL — ${#vendoring[@]} shipped configurations select '$VENDOR_FEATURE'; exactly one may."
    if [[ "${#vendoring[@]}" -eq 0 ]]; then
      echo "       No artifact carries its own OpenSSL. A wheel built from this tree links"
      echo "       whatever libcrypto the build host supplies, and installs onto machines"
      echo "       that have a different one. Restore '$VENDOR_FEATURE' to the"
      echo "       [tool.maturin] features array in $wheel_file."
    else
      printf '       %s\n' "${vendoring[@]}"
      echo "       Every artifact but the wheel links the libcrypto its host supplies."
      echo "       Vendoring into another one decides what that artifact ships, so make"
      echo "       that decision here, never as a side effect of a workspace or crate"
      echo "       dependency table naming a rusqlite feature."
    fi
    return 1
  fi

  pkg="${vendoring[0]%%|*}"
  feature_args="${vendoring[0]#*|}"
  if [[ "${vendoring[0]}" != "$wheel_entry" ]]; then
    echo "FAIL — the one configuration selecting '$VENDOR_FEATURE' is"
    echo "           ${vendoring[0]}"
    echo "       and $wheel_file builds the wheel from"
    echo "           $wheel_entry"
    echo "       The vendored OpenSSL sits on a configuration that is not the wheel's."
    echo "       Comparing the whole entry rather than its package half is what makes"
    echo "       this branch reachable: three ARTIFACTS entries build package 'scp-ffi',"
    echo "       and two of them are the bridge cdylibs build-matrix.yml uploads and"
    echo "       release.yml signs. Name '$VENDOR_FEATURE' in the [tool.maturin]"
    echo "       features array of $wheel_file and nowhere else."
    return 1
  fi

  if ! host="$(host_target)"; then
    echo "FAIL — the host triple could not be read, so the wheel's graph was not"
    echo "       resolved on the target it ships for."
    return 1
  fi
  built="$(cargo_arguments_for "$feature_args")" || return 1
  echo "--> the wheel's configuration: $pkg ${feature_args:-default features}, resolved on $host"
  if ! count="$(vendor_crate_occurrences "$pkg" "$built" "$host")"; then
    echo "FAIL — cargo resolved no dependency graph for the wheel's configuration,"
    echo "       so this run proved nothing about what the wheel carries. The stderr"
    echo "       above names what cargo rejected."
    return 1
  fi
  if [[ "$count" -gt 0 ]]; then
    echo "    ok   — the wheel's graph reaches $VENDOR_CRATE, so the wheel carries its own OpenSSL"
  else
    echo "    FAIL — the wheel's graph reaches no $VENDOR_CRATE, though its configuration names"
    echo "           '$VENDOR_FEATURE'. That feature no longer forwards"
    echo "           rusqlite/bundled-sqlcipher-vendored-openssl — see"
    echo "           crates/scp-platform/Cargo.toml."
    failures=$((failures + 1))
  fi
  echo

  echo "--> the ${#absent[@]} shipped configurations that must reach no $VENDOR_CRATE"
  for configuration in "${absent[@]}"; do
    pkg="${configuration%%|*}"
    feature_args="${configuration#*|}"
    built="$(cargo_arguments_for "$feature_args")" || return 1
    if ! count="$(vendor_crate_occurrences "$pkg" "$built" all)"; then
      echo "    FAIL — cargo resolved no dependency graph for $pkg [${feature_args:-default features}],"
      echo "           so this run proved nothing about that artifact. An entry of the"
      echo "           ARTIFACTS array of $FEATURE_GRAPH_GATE names a package or a feature"
      echo "           a manifest no longer defines, or the workspace does not resolve at"
      echo "           all. The stderr above names what cargo rejected."
      failures=$((failures + 1))
      continue
    fi
    if [[ "$count" -eq 0 ]]; then
      echo "    ok   — $pkg [${feature_args:-default features}]"
    else
      echo "    FAIL — $pkg [${feature_args:-default features}] reaches $VENDOR_CRATE."
      echo "           This artifact would embed a statically compiled OpenSSL whose patch"
      echo "           level only a Cargo.lock bump changes. For scp-node and scp-relay that"
      echo "           breaks the operator procedure Dockerfile and"
      echo "           templates/personal-relay/README.md state, which is upgrading libssl3"
      echo "           in the runtime layer. For a bridge it changes what an npm package or"
      echo "           an XCFramework carries. Ask for the vendored build through"
      echo "           scp-platform/vendored-openssl on the one artifact that needs it,"
      echo "           never through the rusqlite feature list in a workspace or crate"
      echo "           dependency table."
      failures=$((failures + 1))
    fi
  done
  echo

  if [[ "$failures" -eq 0 ]]; then
    echo "PASS — $VENDOR_CRATE reaches the PyPI wheel and reaches no other shipped artifact."
    return 0
  fi
  echo "FAIL — $failures configuration(s) resolved the wrong way."
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
