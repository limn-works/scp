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
# identity. It reads both:
#
#   * The configurations come from the `ARTIFACTS` array of
#     `scripts/check-shipped-feature-graph.sh`, which is where this repository
#     records what it ships. A configuration added there is checked here on the
#     commit that adds it; a list this file copied by hand would leave that
#     configuration unchecked until someone remembered to edit two files.
#   * The wheel's configuration comes from the `[tool.maturin]` table of
#     `bindings/python/pyproject.toml` — the project file the maturin step of
#     `.github/workflows/build-matrix.yml` builds the wheel from. Its package is
#     the `[package] name` of the Cargo.toml its `manifest-path` key names, and its
#     feature arguments are the `features`, `no-default-features` and
#     `all-features` keys spelled the way `ARTIFACTS` spells them.
#     `MATURIN_PROJECT_FILES` of that same gate holds this one file, so `PYPROJECT`
#     below names every wheel this repository builds. A second wheel added there
#     and not here fails this gate rather than passing it: the entry derived from
#     the file `PYPROJECT` still names would not equal the one vendoring entry
#     whenever the new wheel is the vendoring one, and two vendoring wheels trip
#     the exactly-one check.
#   * Which configuration carries the vendored build comes from the feature
#     arguments of each entry, so that answer tracks the `ARTIFACTS` array too.
#     `scripts/check-shipped-feature-graph.sh`'s
#     `assert_wheel_feature_selection_is_gated` fails unless the wheel's
#     `[tool.maturin]` table derives an `ARTIFACTS` entry verbatim, so the entry
#     this gate reads is the configuration maturin compiles.
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
# gate reports the next such edit by name rather than by a Docker build breaking.
#
# WHAT THIS GATE DOES NOT DECIDE
# ------------------------------
# It reads dependency graphs, so it decides which crates a build compiles and never
# which shared library a finished binary loads. `scripts/check-shipped-feature-graph.sh`
# decides the complementary property, that every resolved SCP-crate feature of each
# shipped artifact sits on one permitted-production allowlist.
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
PYPROJECT="bindings/python/pyproject.toml"

# The `ARTIFACTS` array is this repository's record of what it ships, and a tree
# that ships fewer configurations than this floor has had entries deleted rather
# than added. The floor makes a reader that silently returns a short list fail
# instead of reporting that every artifact it found resolved correctly.
MINIMUM_SHIPPED_CONFIGURATIONS=2

fixture_failures=0

# shipped_configurations <gate-script>
#   Emit one `<package>|<feature arguments>` line per entry of the gate script's
#   `ARTIFACTS` array, in the order the array writes them. FAILS (non-zero, reason
#   on stderr) when the file holds no `ARTIFACTS=(` opener, when no `)` closes it,
#   when a line inside it is neither a comment nor a single double-quoted string,
#   or when it yields fewer than MINIMUM_SHIPPED_CONFIGURATIONS entries — because a
#   list this reader cannot reproduce must not read as a short list of artifacts
#   that all happened to pass.
shipped_configurations() {
  local file="$1" body entries count offenders
  if [[ ! -f "$file" ]]; then
    echo "the shipped-artifact list does not exist: $file" >&2
    return 1
  fi
  local openers appenders
  openers="$(grep -cE '^ARTIFACTS(\+)?=\(' "$file" || true)"
  appenders="$(grep -cE '^ARTIFACTS\+=\(' "$file" || true)"
  # Exactly one assignment, and no `+=` appender. The awk below stops at the first
  # `)` at column 0, so a second block is invisible to it while bash expands every
  # one. A tree that split the array would hide every entry after the first block
  # and still clear MINIMUM_SHIPPED_CONFIGURATIONS, which is the one bypass of this
  # gate that no other check compensates for: the sibling gate's PERMITTED_ALLOWLIST
  # is one repo-wide union applied to every artifact, so it cannot say which
  # artifact owns the vendored row. Requiring the single spelling this reader
  # reproduces is closed by construction; chasing each new spelling would not be.
  if [[ "$openers" -ne 1 || "$appenders" -ne 0 ]]; then
    echo "$file must carry exactly one 'ARTIFACTS=(' assignment and no 'ARTIFACTS+=(' appender; found $openers assignment(s) and $appenders appender(s), and this reader takes only the first block while bash expands them all" >&2
    return 1
  fi
  if ! grep -qE '^ARTIFACTS=\([[:space:]]*$' "$file"; then
    echo "$file carries no 'ARTIFACTS=(' array opener on a line of its own, so this gate read no shipped configurations" >&2
    return 1
  fi
  body="$(awk '
    /^ARTIFACTS=\([[:space:]]*$/ { collecting = 1; next }
    collecting && /^\)[[:space:]]*$/ { closed = 1; exit }
    collecting { print }
    END { if (!closed) exit 3 }
  ' "$file")" || {
    echo "$file: no ')' closes the ARTIFACTS array" >&2
    return 1
  }
  entries="$(printf '%s\n' "$body" | sed -E '/^[[:space:]]*#/d; /^[[:space:]]*$/d')"
  offenders="$(printf '%s\n' "$entries" | grep -vE '^[[:space:]]*"[^"]*"[[:space:]]*$' || true)"
  if [[ -n "$offenders" ]]; then
    { echo "$file: an ARTIFACTS line is neither a comment nor one double-quoted entry:"
      printf '%s\n' "$offenders" | sed 's/^/  /'; } >&2
    return 1
  fi
  entries="$(printf '%s\n' "$entries" | sed -E 's/^[[:space:]]*"//; s/"[[:space:]]*$//')"
  count="$(printf '%s\n' "$entries" | grep -cE '.' || true)"
  if [[ "$count" -lt "$MINIMUM_SHIPPED_CONFIGURATIONS" ]]; then
    echo "$file: ARTIFACTS yielded $count entries, below the floor of $MINIMUM_SHIPPED_CONFIGURATIONS" >&2
    return 1
  fi
  printf '%s\n' "$entries"
}

# configuration_selects_feature <feature-arguments> <feature>
#   Succeed when the cargo feature arguments name the feature as a whole token —
#   separated from its neighbours by whitespace, by a comma, or by the `=` of
#   `--features=a,b`. `not-vendored-openssl` and `vendored-openssl-experimental`
#   are different features and do not match.
configuration_selects_feature() {
  printf '%s\n' "$1" | grep -qE "(^|[[:space:],=])$2([[:space:],]|\$)"
}

# maturin_table_text <pyproject.toml>
#   Emit the lines of the file's `[tool.maturin]` table. FAILS when the file does
#   not exist.
maturin_table_text() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    echo "the wheel's project file does not exist: $file" >&2
    return 1
  fi
  # The `sub` strips a comment before the key regexes below read the joined text.
  # Those regexes take the FIRST match, so a commented-out `features` or
  # `manifest-path` key placed above the live one would otherwise decide what this
  # gate believes the wheel builds. `maturin_table_text` of
  # scripts/check-shipped-feature-graph.sh strips the same way.
  awk '
    /^[[:space:]]*\[/ {
      in_table = ($0 ~ /^[[:space:]]*\[[[:space:]]*tool[[:space:]]*\.[[:space:]]*maturin[[:space:]]*\][[:space:]]*(#.*)?$/)
      next
    }
    in_table { sub(/(^|[[:space:]])#.*$/, ""); print }
  ' "$file"
}

# wheel_package <pyproject.toml>
#   Emit the `[package] name` of the Cargo.toml the file's `[tool.maturin]
#   manifest-path` names, resolved against the pyproject.toml's directory, or of
#   the Cargo.toml beside the pyproject.toml when the table names none — the two
#   places maturin looks. FAILS when the pyproject.toml does not exist, when that
#   Cargo.toml does not exist, or when it carries no `[package] name`.
wheel_package() {
  local file="$1" text dir manifest pkg
  text="$(maturin_table_text "$file")" || return 1
  dir="$(dirname "$file")"
  local re_mp='(^|[[:space:]])manifest-path[[:space:]]*=[[:space:]]*["'"'"']([^"'"'"']+)["'"'"']'
  if [[ "$text" =~ $re_mp ]]; then
    manifest="${BASH_REMATCH[2]}"
    if [[ "$manifest" != /* ]]; then manifest="$dir/$manifest"; fi
  else
    manifest="$dir/Cargo.toml"
  fi
  if [[ ! -f "$manifest" ]]; then
    echo "$file: [tool.maturin] manifest-path names no file: $manifest" >&2
    return 1
  fi
  pkg="$(awk '
    /^[[:space:]]*\[/ { in_pkg = ($0 ~ /^[[:space:]]*\[package\][[:space:]]*(#.*)?$/); next }
    in_pkg && /^[[:space:]]*name[[:space:]]*=/ {
      sub(/^[[:space:]]*name[[:space:]]*=[[:space:]]*["'"'"']/, ""); sub(/["'"'"'].*$/, ""); print; exit
    }
  ' "$manifest")"
  if [[ -z "$pkg" ]]; then
    echo "$file: $manifest carries no [package] name" >&2
    return 1
  fi
  printf '%s\n' "$pkg"
}

# wheel_feature_args <pyproject.toml>
#   Emit the cargo feature arguments the file's `[tool.maturin]` table selects,
#   spelled the way the ARTIFACTS array spells them: `--all-features`, then
#   `--no-default-features`, then `--features a,b`, each present only when the
#   table selects it; an empty line when the table selects nothing. This mirrors
#   `maturin_feature_args` of scripts/check-shipped-feature-graph.sh, which is
#   what makes the entry this gate derives comparable, character for character,
#   against the ARTIFACTS entries it reads out of that same file. FAILS on a
#   `features` key that is not a TOML array of strings and on an `all-features`
#   or `no-default-features` key that is not a TOML boolean, so a table this
#   reader cannot reproduce fails the gate rather than yielding a short argument
#   string that matches the wrong ARTIFACTS entry.
wheel_feature_args() {
  local file="$1" text args="" list features
  text="$(maturin_table_text "$file")" || return 1
  local re_all='(^|[[:space:]])all-features[[:space:]]*=[[:space:]]*(true|false)([[:space:]]|$)'
  local re_nodef='(^|[[:space:]])no-default-features[[:space:]]*=[[:space:]]*(true|false)([[:space:]]|$)'
  local re_feat='(^|[[:space:]])features[[:space:]]*=[[:space:]]*\[([^]]*)\]'
  if [[ "$text" =~ (^|[[:space:]])all-features[[:space:]]*= ]]; then
    if [[ ! "$text" =~ $re_all ]]; then
      echo "$file: all-features is not a TOML boolean" >&2; return 1
    fi
    if [[ "${BASH_REMATCH[2]}" == "true" ]]; then args="--all-features"; fi
  fi
  if [[ "$text" =~ (^|[[:space:]])no-default-features[[:space:]]*= ]]; then
    if [[ ! "$text" =~ $re_nodef ]]; then
      echo "$file: no-default-features is not a TOML boolean" >&2; return 1
    fi
    if [[ "${BASH_REMATCH[2]}" == "true" ]]; then args="${args:+$args }--no-default-features"; fi
  fi
  if [[ "$text" =~ (^|[[:space:]])features[[:space:]]*= ]]; then
    if [[ ! "$text" =~ $re_feat ]]; then
      echo "$file: features is not a TOML array" >&2; return 1
    fi
    list="${BASH_REMATCH[2]}"
    local re_bad='[^-A-Za-z0-9_./@:+, "'"'"']'
    if [[ "$list" =~ $re_bad ]]; then
      echo "$file: features carries a character no quoted cargo feature name uses: $list" >&2; return 1
    fi
    features="$(printf '%s\n' "$list" | tr -d "\"'" | tr ',' '\n' \
      | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//; /^$/d' | paste -sd, -)"
    if [[ -n "$features" ]]; then args="${args:+$args }--features $features"; fi
  fi
  printf '%s\n' "$args"
}

# wheel_configuration <pyproject.toml>
#   Emit the whole `<package>|<feature arguments>` entry the file's
#   `[tool.maturin]` table makes maturin build — the ARTIFACTS entry that names
#   the wheel. run_gate compares this entry against the one configuration that
#   selects the vendored feature, so a package name alone is not enough: the
#   ARTIFACTS array holds three entries whose package is `scp-ffi`, and two of
#   them are the bridge cdylibs `.github/workflows/build-matrix.yml` uploads and
#   `.github/workflows/release.yml` signs. FAILS on anything wheel_package or
#   wheel_feature_args fails on.
wheel_configuration() {
  local file="$1" pkg args
  pkg="$(wheel_package "$file")" || return 1
  args="$(wheel_feature_args "$file")" || return 1
  printf '%s|%s\n' "$pkg" "$args"
}

# vendor_crate_occurrences <package> <feature-argument-string>
#   Emit the number of times the vendored crate appears in the package's shipped
#   dependency graph, and return non-zero when cargo resolved no graph. `-e no-dev`
#   drops dev-dependencies, which no shipped artifact compiles; `--target all`
#   resolves every target triple, so a cfg-gated edge that is false on this runner
#   stays visible.
#
#   Cargo's exit status decides whether the count means anything, so this function
#   reads that status. A count taken from a resolution that failed is the number
#   zero, and `run_gate` reads zero as the proof that an artifact reaches no
#   `openssl-src`: an earlier version of this function discarded the status, so a
#   renamed package or a renamed feature in one `ARTIFACTS` entry made every absent
#   configuration print `ok` and made the run print `PASS` while cargo had resolved
#   nothing. Both call sites treat a non-zero return as a gate failure.
vendor_crate_occurrences() {
  local pkg="$1" feature_args="$2" tree count cargo_rc=0 grep_rc=0
  # shellcheck disable=SC2086  # feature_args carries several cargo arguments.
  tree="$(cargo tree -p "$pkg" $feature_args -e no-dev --target all --prefix none --format '{p}' 2>&1)" || cargo_rc=$?
  if [[ "$cargo_rc" -ne 0 ]]; then
    {
      echo "cargo tree exited $cargo_rc for package '$pkg' with feature arguments '${feature_args:-none}':"
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

run_fixtures() {
  echo ">> fixtures: the readers derive the shipped configurations and the wheel's package, and fail closed otherwise"
  local dir file out rc
  dir="$(mktemp -d)"
  trap 'rm -rf "$dir"' RETURN

  file="$dir/gate.sh"
  printf '%s\n' \
    'PERMITTED_ALLOWLIST="x"' \
    'ARTIFACTS=(' \
    '  "scp-ffi|--no-default-features --features server"' \
    '  # a comment inside the array' \
    '' \
    '  "scp-node|"' \
    '  "scp-ffi|--features extension-module,vendored-openssl"' \
    ')' \
    'main "$@"' > "$file"
  out="$(shipped_configurations "$file")"; rc=$?
  expect "a well-formed ARTIFACTS array is read" "PASS" "$rc"
  same_string "$out" "$(printf '%s\n' 'scp-ffi|--no-default-features --features server' 'scp-node|' 'scp-ffi|--features extension-module,vendored-openssl')"; rc=$?
  expect "it yields the three entries, with comments and blank lines dropped" "PASS" "$rc"

  printf '%s\n' 'ARTIFACTS="not an array"' > "$file"
  shipped_configurations "$file" >/dev/null 2>&1; rc=$?
  expect "a file with no 'ARTIFACTS=(' opener FAILS" "FAIL" "$rc"

  printf '%s\n' 'ARTIFACTS=(' '  "scp-node|"' '  "scp-relay|"' > "$file"
  shipped_configurations "$file" >/dev/null 2>&1; rc=$?
  expect "an ARTIFACTS array no ')' closes FAILS" "FAIL" "$rc"

  printf '%s\n' 'ARTIFACTS=(' '  "scp-node|"' '  $UNQUOTED' '  "scp-relay|"' ')' > "$file"
  shipped_configurations "$file" >/dev/null 2>&1; rc=$?
  expect "an ARTIFACTS line that is not one quoted string FAILS" "FAIL" "$rc"

  printf '%s\n' 'ARTIFACTS=(' '  "scp-node|"' ')' > "$file"
  shipped_configurations "$file" >/dev/null 2>&1; rc=$?
  expect "an ARTIFACTS array below the entry floor FAILS" "FAIL" "$rc"

  shipped_configurations "$dir/absent.sh" >/dev/null 2>&1; rc=$?
  expect "a missing shipped-artifact list FAILS" "FAIL" "$rc"

  # The two bypasses a planted tree proved against an earlier revision.
  printf '%s\n' 'ARTIFACTS=(' '  "scp-node|"' '  "scp-relay|"' ')' \
    'ARTIFACTS+=(' '  "scp-ffi|--features extension-module,vendored-openssl"' ')' > "$file"
  shipped_configurations "$file" >/dev/null 2>&1; rc=$?
  expect "an ARTIFACTS array split across an 'ARTIFACTS+=(' appender FAILS" "FAIL" "$rc"

  printf '%s\n' 'ARTIFACTS=(' '  "scp-node|"' '  "scp-relay|"' ')' \
    'ARTIFACTS=(' '  "scp-ffi|--features extension-module,vendored-openssl"' ')' > "$file"
  shipped_configurations "$file" >/dev/null 2>&1; rc=$?
  expect "a file carrying two 'ARTIFACTS=(' assignments FAILS" "FAIL" "$rc"

  configuration_selects_feature "--features extension-module,vendored-openssl" "vendored-openssl"; rc=$?
  expect "a comma-separated feature list selects the feature" "PASS" "$rc"
  configuration_selects_feature "--features=vendored-openssl" "vendored-openssl"; rc=$?
  expect "the '--features=<list>' spelling selects the feature" "PASS" "$rc"
  configuration_selects_feature "--no-default-features --features server" "vendored-openssl"; rc=$?
  expect "a configuration naming another feature does NOT select it" "FAIL" "$rc"
  configuration_selects_feature "" "vendored-openssl"; rc=$?
  expect "a default-features configuration does NOT select it" "FAIL" "$rc"
  configuration_selects_feature "--features not-vendored-openssl" "vendored-openssl"; rc=$?
  expect "a longer feature name ending in it does NOT select it" "FAIL" "$rc"
  configuration_selects_feature "--features vendored-openssl-experimental" "vendored-openssl"; rc=$?
  expect "a longer feature name starting with it does NOT select it" "FAIL" "$rc"

  mkdir -p "$dir/bindings/python" "$dir/crates/the-bridge"
  printf '%s\n' '[package]' 'name = "the-bridge"' 'version = "0.1.0"' > "$dir/crates/the-bridge/Cargo.toml"
  file="$dir/bindings/python/pyproject.toml"
  printf '%s\n' \
    '[project]' \
    'name = "scp-python"' \
    '' \
    '[tool.maturin]' \
    'features = ["extension-module", "vendored-openssl"]' \
    'manifest-path = "../../crates/the-bridge/Cargo.toml"' > "$file"
  out="$(wheel_package "$file")"; rc=$?
  expect "the wheel's package is read from its [tool.maturin] manifest-path" "PASS" "$rc"
  same_string "$out" "the-bridge"; rc=$?
  expect "that package is the [package] name of the manifest the key names" "PASS" "$rc"

  # The whole entry, which is what run_gate compares. A package-name comparison
  # admitted any of the three ARTIFACTS entries that build `scp-ffi`, two of which
  # are the bridge cdylibs build-matrix.yml uploads; these fixtures prove the
  # reader carries the feature arguments through as well.
  out="$(wheel_configuration "$file")"; rc=$?
  expect "the wheel's whole ARTIFACTS entry is derived from the [tool.maturin] table" "PASS" "$rc"
  same_string "$out" "the-bridge|--features extension-module,vendored-openssl"; rc=$?
  expect "that entry carries the feature arguments, not the package alone" "PASS" "$rc"

  printf '%s\n' \
    '[tool.maturin]' \
    'no-default-features = true' \
    'features = ["server"]' \
    'manifest-path = "../../crates/the-bridge/Cargo.toml"' > "$file"
  out="$(wheel_configuration "$file")"; rc=$?
  same_string "$out" "the-bridge|--no-default-features --features server"; rc=$?
  expect "no-default-features is spelled the way ARTIFACTS spells it" "PASS" "$rc"

  printf '%s\n' \
    '[tool.maturin]' \
    'manifest-path = "../../crates/the-bridge/Cargo.toml"' > "$file"
  out="$(wheel_configuration "$file")"; rc=$?
  same_string "$out" "the-bridge|"; rc=$?
  expect "a table selecting no feature yields the default-features entry" "PASS" "$rc"

  printf '%s\n' \
    '[tool.maturin]' \
    'features = "extension-module"' \
    'manifest-path = "../../crates/the-bridge/Cargo.toml"' > "$file"
  wheel_configuration "$file" >/dev/null 2>&1; rc=$?
  expect "a features key that is not a TOML array FAILS" "FAIL" "$rc"

  printf '%s\n' \
    '[tool.maturin]' \
    'no-default-features = "yes"' \
    'manifest-path = "../../crates/the-bridge/Cargo.toml"' > "$file"
  wheel_configuration "$file" >/dev/null 2>&1; rc=$?
  expect "a no-default-features key that is not a TOML boolean FAILS" "FAIL" "$rc"

  printf '%s\n' '[tool.maturin]' 'manifest-path = "nowhere/Cargo.toml"' > "$file"
  wheel_package "$file" >/dev/null 2>&1; rc=$?
  expect "a manifest-path naming no file FAILS" "FAIL" "$rc"

  # A commented-out key above the live one. The key regexes take the first match,
  # so an unstripped comment decided what this gate believed the wheel builds.
  printf '%s\n' \
    '[tool.maturin]' \
    '# features = ["extension-module", "vendored-openssl"]' \
    'features = ["extension-module"]' \
    'manifest-path = "../../crates/the-bridge/Cargo.toml"' > "$file"
  printf '%s\n' '[package]' 'name = "the-bridge"' 'version = "0.1.0"' \
    > "$dir/crates/the-bridge/Cargo.toml"
  out="$(wheel_configuration "$file")"; rc=$?
  same_string "$out" "the-bridge|--features extension-module"; rc=$?
  expect "a commented-out features key does NOT decide the wheel's configuration" "PASS" "$rc"

  printf '%s\n' '[workspace]' 'members = []' > "$dir/crates/the-bridge/Cargo.toml"
  printf '%s\n' '[tool.maturin]' 'manifest-path = "../../crates/the-bridge/Cargo.toml"' > "$file"
  wheel_package "$file" >/dev/null 2>&1; rc=$?
  expect "a manifest carrying no [package] name FAILS" "FAIL" "$rc"

  wheel_package "$dir/bindings/python/absent.toml" >/dev/null 2>&1; rc=$?
  expect "a missing wheel project file FAILS" "FAIL" "$rc"
  wheel_configuration "$dir/bindings/python/absent.toml" >/dev/null 2>&1; rc=$?
  expect "a missing wheel project file FAILS the whole-entry reader too" "FAIL" "$rc"

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
  out="$(vendor_crate_occurrences "scp-ffi" "--features extension-module,vendored-openssl")"; rc=$?
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
  out="$(vendor_crate_occurrences "scp-node" "")"; rc=$?
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
  vendor_crate_occurrences "scp-node" "--features gone" >/dev/null 2>&1; rc=$?
  PATH="$saved_path"
  expect "a cargo tree that exits non-zero FAILS rather than counting zero" "FAIL" "$rc"

  # run_gate end to end, against a planted ARTIFACTS array and a planted maturin
  # table. The negative control is the edit a package-name comparison admitted:
  # `vendored-openssl` moves off the wheel's entry onto the `--features server`
  # bridge cdylib, whose package is `scp-ffi` as well. The positive control is the
  # same tree with the feature back on the wheel, which proves the assertion goes
  # green for a reason other than every input failing.
  local gate_file pyproject_file
  mkdir -p "$dir/scenario/crates/the-bridge" "$dir/scenario/bindings/python"
  printf '%s\n' '[package]' 'name = "scp-ffi"' 'version = "0.1.0"' \
    > "$dir/scenario/crates/the-bridge/Cargo.toml"
  gate_file="$dir/scenario/gate.sh"
  pyproject_file="$dir/scenario/bindings/python/pyproject.toml"

  # A cargo whose tree names openssl-src exactly when the arguments select the
  # vendored feature, so the counter reports what the configuration asked for.
  printf '%s\n' \
    '#!/bin/sh' \
    'echo "scp-ffi v0.1.0"' \
    'case "$*" in' \
    "  *vendored-openssl*) echo \"${VENDOR_CRATE} v300.5.1+3.5.1\" ;;" \
    'esac' > "$dir/fakebin/cargo"
  chmod +x "$dir/fakebin/cargo"

  printf '%s\n' \
    'ARTIFACTS=(' \
    '  "scp-ffi|--no-default-features --features server,vendored-openssl"' \
    '  "scp-ffi|"' \
    '  "scp-ffi|--features extension-module"' \
    ')' > "$gate_file"
  printf '%s\n' \
    '[tool.maturin]' \
    'features = ["extension-module"]' \
    'manifest-path = "../../crates/the-bridge/Cargo.toml"' > "$pyproject_file"
  PATH="$dir/fakebin:$saved_path"
  ( FEATURE_GRAPH_GATE="$gate_file" PYPROJECT="$pyproject_file" run_gate ) >/dev/null 2>&1; rc=$?
  PATH="$saved_path"
  expect "run_gate FAILS when the vendored feature moves onto a sibling scp-ffi configuration" "FAIL" "$rc"

  printf '%s\n' \
    'ARTIFACTS=(' \
    '  "scp-ffi|--no-default-features --features server"' \
    '  "scp-ffi|"' \
    '  "scp-ffi|--features extension-module,vendored-openssl"' \
    ')' > "$gate_file"
  printf '%s\n' \
    '[tool.maturin]' \
    'features = ["extension-module", "vendored-openssl"]' \
    'manifest-path = "../../crates/the-bridge/Cargo.toml"' > "$pyproject_file"
  PATH="$dir/fakebin:$saved_path"
  ( FEATURE_GRAPH_GATE="$gate_file" PYPROJECT="$pyproject_file" run_gate ) >/dev/null 2>&1; rc=$?
  PATH="$saved_path"
  expect "run_gate PASSES when that same tree keeps the vendored feature on the wheel" "PASS" "$rc"

  if [[ "$fixture_failures" -eq 0 ]]; then
    echo "   FIXTURES: all behavioural proofs passed."
    return 0
  fi
  echo "   FIXTURES: $fixture_failures behavioural proof(s) failed."
  return 1
}

# ---------------------------------------------------------------------------
run_gate() {
  local failures=0 configuration pkg feature_args count wheel_entry raw
  local -a configurations=() vendoring=() absent=()

  # A `while read` loop rather than `mapfile`, which bash 3.2 — the interpreter
  # `/bin/bash` runs on a developer's macOS — does not define.
  raw="$(shipped_configurations "$FEATURE_GRAPH_GATE")" || {
    echo "FAIL — the shipped configurations could not be read from $FEATURE_GRAPH_GATE, so no graph was resolved."
    return 1
  }
  while IFS= read -r configuration; do
    [[ -n "$configuration" ]] && configurations+=("$configuration")
  done <<<"$raw"
  echo "--> ${#configurations[@]} shipped configurations read from $FEATURE_GRAPH_GATE"

  wheel_entry="$(wheel_configuration "$PYPROJECT")" || {
    echo "FAIL — the wheel's configuration could not be read from $PYPROJECT, so no graph was resolved."
    return 1
  }
  echo "--> the wheel builds configuration '$wheel_entry', read from $PYPROJECT"
  echo

  for configuration in "${configurations[@]}"; do
    if configuration_selects_feature "${configuration#*|}" "$VENDOR_FEATURE"; then
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
      echo "       [tool.maturin] features array in $PYPROJECT."
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
    echo "       and $PYPROJECT builds the wheel from"
    echo "           $wheel_entry"
    echo "       The vendored OpenSSL sits on a configuration that is not the wheel's."
    echo "       Comparing the whole entry rather than its package half is what makes"
    echo "       this branch reachable: three ARTIFACTS entries build package 'scp-ffi',"
    echo "       and two of them are the bridge cdylibs build-matrix.yml uploads and"
    echo "       release.yml signs. Name '$VENDOR_FEATURE' in the [tool.maturin]"
    echo "       features array of $PYPROJECT and nowhere else."
    return 1
  fi

  echo "--> the wheel's configuration: $pkg ${feature_args:-default features}"
  if ! count="$(vendor_crate_occurrences "$pkg" "$feature_args")"; then
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
    if ! count="$(vendor_crate_occurrences "$pkg" "$feature_args")"; then
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
