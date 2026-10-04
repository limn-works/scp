#!/usr/bin/env bash
#
# check-wiping-allocator.sh — every shipped SCP binary and cdylib links the one
# wiping global allocator, and nothing else defines a global allocator
# (09-security-model.md §9.15, freed heap memory; rust.md §Safety Rules).
#
# WHAT THIS PROVES
# ----------------
# 1. Every `bin`, `cdylib` and `staticlib` target `cargo metadata` reports for a
#    workspace member is classified, either in SHIPPED or in DEV_TOOLS with a
#    reason. An unclassified target fails, so a new artifact cannot ship without
#    someone deciding whether it installs the allocator. A SHIPPED or DEV_TOOLS
#    entry that names no real target fails too.
# 2. Every cdylib and staticlib target of a package in
#    check-shipped-feature-graph.sh's ARTIFACTS list is in SHIPPED. Only a bin
#    target may be a DEV_TOOLS entry, so a shipped library cannot be filed as a
#    build-time tool.
# 3. Each SHIPPED target's crate root carries `use scp_alloc as _;` at column 0,
#    with no attribute (`#[cfg(...)]`, `#[cfg_attr(...)]`, anything) on the
#    lines above it. rustc loads a dependency only when the crate names it, so
#    this line is what links scp-alloc's `#[global_allocator]` static into the
#    artifact.
# 4. Each SHIPPED package depends on `scp-alloc` as a normal, non-optional
#    dependency with no target restriction, so no feature or target selection
#    can drop it.
# 5. `crates/scp-alloc/src/lib.rs` holds exactly one `#[global_allocator]`,
#    on the static `WIPING_ALLOCATOR: WipingAllocator =
#    WipingAllocator::new(std::alloc::System);`, and no source file of
#    scp-alloc contains `cfg`, so no build of a crate that links it can leave
#    the allocator out or swap its type.
# 6. No other Rust file carries `#[global_allocator]`, except a file under a
#    `tests/` directory: an integration test is its own binary, never shipped,
#    and may install an inspecting allocator (as scp-alloc's and scp-mls's wipe
#    tests do) provided it does not name `scp_alloc`.
#
# What this does not prove: that a built artifact contains the allocator. The
# `use` line, the dependency edge and the uncfg'd static together make that a
# consequence of how rustc links, and scp-alloc's own test proves the wipe.
#
# Usage:
#   scripts/check-wiping-allocator.sh              # fixtures, then the real tree
#   scripts/check-wiping-allocator.sh --self-test  # fixtures only
#
# Exit codes: 0 pass, 1 a check failed, 2 invocation error.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# ---------------------------------------------------------------------------
# Closed lists. Each entry is `<package>:<target name>`.
# ---------------------------------------------------------------------------
SHIPPED=(
  "scp-node:scp-node"                # Docker image and crates.io binary
  "scp-relay:scp-relay"              # Docker image ENTRYPOINT and release binary
  "scp-ffi:_scp_core"                # PyO3 wheel
  "scp-ffi-napi:scp_ffi_napi"        # npm `index.node`
  "scp-ffi-uniffi:scp_ffi_uniffi"    # XCFramework (staticlib), Android and JVM (cdylib)
  "scp-client-wasm:scp_client_wasm"  # wasm-pack module for @limn-works/scp-ts-wasm
)

# `<package>:<target name>|<reason>`
DEV_TOOLS=(
  "scp-ffi-uniffi:uniffi-bindgen|code generator run at build time to emit Swift and Kotlin bindings; never shipped"
)

INSTALL_LINE='use scp_alloc as _;'
ALLOC_LIB_REL="crates/scp-alloc/src/lib.rs"
ALLOC_SRC_REL="crates/scp-alloc/src"
STATIC_LINE='static WIPING_ALLOCATOR: WipingAllocator = WipingAllocator::new(std::alloc::System);'
FEATURE_GRAPH_REL="scripts/check-shipped-feature-graph.sh"
# `#[cfg(...)]`, `#[cfg_attr(...)]`, `#![cfg(...)]` and `cfg!(...)`.
CFG_PATTERN='#!?\[[[:space:]]*cfg|cfg!'
GLOBAL_ALLOC_PATTERN='#!?\[[[:space:]]*global_allocator'

failures=0
fail() {
  echo "   FAIL — $*"
  failures=$((failures + 1))
}

shipped_has() { # <pkg:target>
  local entry
  for entry in "${SHIPPED[@]}"; do [[ "$entry" == "$1" ]] && return 0; done
  return 1
}

dev_tool_has() { # <pkg:target>
  local entry
  for entry in "${DEV_TOOLS[@]}"; do [[ "${entry%%|*}" == "$1" ]] && return 0; done
  return 1
}

# Packages named in the ARTIFACTS=( ... ) array of the feature-graph gate.
artifact_packages() { # <feature-graph script>
  awk '
    /^ARTIFACTS=\(/ { inside = 1; next }
    inside && /^\)/ { inside = 0 }
    inside && /^[[:space:]]*"/ {
      line = $0
      sub(/^[[:space:]]*"/, "", line)
      sub(/\|.*/, "", line)
      print line
    }
  ' "$1" | sort -u
}

# Artifact targets as `<package>\t<target>\t<src_path>` lines.
artifact_targets() { # <metadata json>
  jq -r '.packages[] as $p | $p.targets[]
    | select(any(.kind[]; . == "bin" or . == "cdylib" or . == "staticlib"))
    | [$p.name, .name, .src_path] | @tsv' "$1"
}

# Artifact targets as `<package>\t<target>\t<kind,kind,...>` lines.
artifact_target_kinds() { # <metadata json>
  jq -r '.packages[] as $p | $p.targets[]
    | select(any(.kind[]; . == "bin" or . == "cdylib" or . == "staticlib"))
    | [$p.name, .name, (.kind | join(","))] | @tsv' "$1"
}

# 0 when `use scp_alloc as _;` sits at column 0 outside any comment and no
# attribute applies to it. Comments are stripped first (`//` to end of line, and
# `/* ... */` across lines, nested as Rust nests them), so an install line inside
# a block comment is not one. An attribute is tracked by its bracket depth until
# its closing `]`, so a `#[cfg(...)]` spread over several lines still applies to
# the item after it. An outer attribute (`#[...]`) or a crate-level
# `#![cfg...]` before the install line, with only blank or comment lines between
# them, fails the check. A `[` inside a string in an attribute leaves the depth
# open, which fails the check rather than passing it.
root_installs_allocator() { # <file>
  awk -v want="$INSTALL_LINE" '
    function strip_comments(line,    out, i, c, two) {
      out = ""
      for (i = 1; i <= length(line); i++) {
        two = substr(line, i, 2)
        if (block > 0) {
          if (two == "/*") { block++; i++ } else if (two == "*/") { block--; i++ }
          continue
        }
        if (two == "//") break
        if (two == "/*") { block = 1; i++; continue }
        out = out substr(line, i, 1)
      }
      return out
    }
    function bracket_delta(s,    opens, closes) {
      opens = gsub(/\[/, "[", s)
      closes = gsub(/\]/, "]", s)
      return opens - closes
    }
    {
      code = strip_comments($0)
      trimmed = code
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", trimmed)
      if (trimmed == "") next
      if (depth > 0) {
        depth += bracket_delta(code)
        if (depth < 0) depth = 0
        next
      }
      if (trimmed ~ /^#\[/ || trimmed ~ /^#!\[[[:space:]]*cfg/) {
        pending = 1
        depth = bracket_delta(code)
        if (depth < 0) depth = 0
        next
      }
      if (trimmed ~ /^#!\[/) {
        depth = bracket_delta(code)
        if (depth < 0) depth = 0
        next
      }
      if ($0 == want && code == want) {
        if (pending) { bad = 1 } else { ok = 1 }
      }
      pending = 0
    }
    END { exit (ok && !bad) ? 0 : 1 }
  ' "$1"
}

# Lines of <path> (a file, or every file under a directory) that match the
# extended regex <pattern> and are not `//` comment lines, as `file:line:text`
# (or `line:text` for a single file). Prose naming an attribute is not one.
code_lines_matching() { # <pattern> <path>
  grep -rnHE "$1" "$2" 2>/dev/null | grep -vE '^[^:]+:[0-9]+:[[:space:]]*//' || true
}

# Rust sources to scan for `#[global_allocator]`, relative to <root>.
rust_sources() { # <root>
  if git -C "$1" rev-parse --show-toplevel >/dev/null 2>&1 \
    && [[ "$(cd "$1" && git rev-parse --show-toplevel)" == "$(cd "$1" && pwd -P)" ]]; then
    git -C "$1" ls-files -- '*.rs'
  else
    (cd "$1" && find . -type f -name '*.rs' -not -path './target/*' | sed 's|^\./||')
  fi
}

# ---------------------------------------------------------------------------
# The checks. <root> is a repository tree, <metadata> a `cargo metadata
# --no-deps --format-version 1` document for it.
# ---------------------------------------------------------------------------
run_checks() { # <root> <metadata json>
  local root="$1" metadata="$2"
  local pkg target src key entry rel

  echo ">> every bin, cdylib and staticlib target is classified"
  local seen=()
  while IFS=$'\t' read -r pkg target src; do
    key="$pkg:$target"
    seen+=("$key")
    if ! shipped_has "$key" && ! dev_tool_has "$key"; then
      fail "$key is a bin/cdylib/staticlib target in neither SHIPPED nor DEV_TOOLS of $0"
    fi
  done < <(artifact_targets "$metadata")
  for entry in "${SHIPPED[@]}" "${DEV_TOOLS[@]%%|*}"; do
    local found=0 s
    for s in "${seen[@]}"; do [[ "$s" == "$entry" ]] && found=1; done
    [[ "$found" -eq 1 ]] || fail "$entry is listed but cargo metadata reports no such bin/cdylib/staticlib target"
  done

  echo ">> every cdylib and staticlib of a shipped-feature-graph ARTIFACTS package is SHIPPED"
  if [[ ! -f "$root/$FEATURE_GRAPH_REL" ]]; then
    fail "$FEATURE_GRAPH_REL is missing, so the ARTIFACTS cross-check cannot run"
  else
    local artifact_pkg kinds
    while IFS= read -r artifact_pkg; do
      [[ -n "$artifact_pkg" ]] || continue
      while IFS=$'\t' read -r pkg target kinds; do
        [[ "$pkg" == "$artifact_pkg" ]] || continue
        key="$pkg:$target"
        case ",$kinds," in
          *,cdylib,* | *,staticlib,*)
            shipped_has "$key" \
              || fail "$key is a library artifact ($kinds) of ARTIFACTS package $pkg but is not in SHIPPED; only a bin target may be a DEV_TOOLS entry"
            ;;
        esac
      done < <(artifact_target_kinds "$metadata")
    done < <(artifact_packages "$root/$FEATURE_GRAPH_REL")
  fi

  echo ">> every SHIPPED crate root links scp-alloc, with no attribute on the line"
  while IFS=$'\t' read -r pkg target src; do
    key="$pkg:$target"
    shipped_has "$key" || continue
    if [[ ! -f "$src" ]]; then
      fail "$key: crate root $src does not exist"
    elif ! root_installs_allocator "$src"; then
      fail "$key: $src lacks a column-0 \`$INSTALL_LINE\` free of any attribute above it"
    fi
  done < <(artifact_targets "$metadata")

  echo ">> every SHIPPED package depends on scp-alloc unconditionally"
  local shipped_pkg
  for shipped_pkg in $(printf '%s\n' "${SHIPPED[@]%%:*}" | sort -u); do
    local edges
    edges=$(jq -r --arg p "$shipped_pkg" '.packages[] | select(.name == $p) | .dependencies[]
      | select(.name == "scp-alloc" and .kind == null and (.optional | not) and .target == null)
      | .name' "$metadata" | wc -l | tr -d ' ')
    [[ "$edges" -ge 1 ]] || fail "$shipped_pkg: no normal, non-optional, untargeted dependency on scp-alloc"
  done

  echo ">> scp-alloc holds the one global allocator, of the wiping type, with no cfg"
  if [[ ! -f "$root/$ALLOC_LIB_REL" ]]; then
    fail "$ALLOC_LIB_REL is missing"
  else
    local count
    count=$(grep -c '^#\[global_allocator\]$' "$root/$ALLOC_LIB_REL" || true)
    [[ "$count" -eq 1 ]] || fail "$ALLOC_LIB_REL must carry exactly one column-0 #[global_allocator], found $count"
    local next
    next=$(awk '/^#\[global_allocator\]$/ { getline; print; exit }' "$root/$ALLOC_LIB_REL")
    [[ "$next" == "$STATIC_LINE" ]] \
      || fail "$ALLOC_LIB_REL: the line after #[global_allocator] must be \`$STATIC_LINE\`, found \`$next\`"
    local cfg_hits
    cfg_hits=$(code_lines_matching "$CFG_PATTERN" "$root/$ALLOC_SRC_REL")
    if [[ -n "$cfg_hits" ]]; then
      fail "$ALLOC_SRC_REL carries a cfg attribute or cfg! outside a comment; nothing may gate the allocator:"
      sed 's/^/          /' <<<"$cfg_hits"
    fi
  fi

  echo ">> no other Rust file outside a tests/ directory defines a global allocator"
  while IFS= read -r rel; do
    [[ "$rel" == "$ALLOC_LIB_REL" ]] && continue
    case "/$rel" in */tests/*) continue ;; esac
    if [[ -n "$(code_lines_matching "$GLOBAL_ALLOC_PATTERN" "$root/$rel")" ]]; then
      fail "$rel carries #[global_allocator] outside a comment; only $ALLOC_LIB_REL may define one"
    fi
  done < <(rust_sources "$root")

  [[ "$failures" -eq 0 ]]
}

# ---------------------------------------------------------------------------
# Self-test: a well-formed fixture tree passes, and each defect fails.
# ---------------------------------------------------------------------------
fixture_failures=0
expect() { # <label> <PASS|FAIL> <rc>
  local actual
  [[ "$3" -eq 0 ]] && actual=PASS || actual=FAIL
  if [[ "$actual" == "$2" ]]; then
    echo "   ok   — $1 (expected $2)"
  else
    echo "   FAIL — $1 (expected $2, got $actual)"
    fixture_failures=$((fixture_failures + 1))
  fi
}

# Writes a passing fixture tree into <dir> and its metadata to <dir>/metadata.json.
make_fixture() { # <dir>
  local d="$1" key pkg target src
  mkdir -p "$d/scripts" "$d/$ALLOC_SRC_REL"
  cat > "$d/$FEATURE_GRAPH_REL" <<'EOF'
ARTIFACTS=(
  "scp-ffi|--no-default-features --features server"
  "scp-core|"
  "scp-node|"
  "scp-ffi-uniffi|"
)
EOF
  cat > "$d/$ALLOC_LIB_REL" <<EOF
#![deny(unsafe_code)]
mod wiping;
pub use wiping::WipingAllocator;
/// Process-global allocator. No \`cfg\` or \`#[cfg(test)]\` gates it.
#[global_allocator]
$STATIC_LINE
EOF
  echo 'pub struct WipingAllocator;' > "$d/$ALLOC_SRC_REL/wiping.rs"
  mkdir -p "$d/crates/scp-mls/tests"
  printf '#[global_allocator]\nstatic A: W = W;\n' > "$d/crates/scp-mls/tests/inspect.rs"

  local packages="[]" tool
  for key in "${SHIPPED[@]}" "${DEV_TOOLS[@]%%|*}"; do
    pkg="${key%%:*}"
    target="${key#*:}"
    src="$d/crates/$pkg/src/$target.rs"
    mkdir -p "$(dirname "$src")"
    if shipped_has "$key"; then
      printf '//! root\n\n// Links the one `#[global_allocator]`.\n%s\n\nuse std::sync::Arc;\n' "$INSTALL_LINE" > "$src"
    else
      printf 'fn main() {}\n' > "$src"
    fi
    tool=$(jq -n --arg p "$pkg" --arg t "$target" --arg s "$src" '{name: $p, targets: [{name: $t, kind: ["bin"], src_path: $s}],
      dependencies: [{name: "scp-alloc", kind: null, optional: false, target: null}]}')
    packages=$(jq --argjson n "$tool" '
      if any(.[]; .name == $n.name) then map(if .name == $n.name then .targets += $n.targets else . end)
      else . + [$n] end' <<<"$packages")
  done
  jq -n --argjson p "$packages" '{packages: $p}' > "$d/metadata.json"
}

run_fixture() { # <dir> — run the checks on a fixture, silently, and return their status
  ( failures=0; run_checks "$1" "$1/metadata.json" >/dev/null 2>&1 )
}

run_fixtures() {
  echo "FIXTURE HARNESS (check-wiping-allocator.sh)"
  local base rc d
  base=$(mktemp -d)
  trap 'rm -rf "$base"' RETURN

  d="$base/good"; make_fixture "$d"
  run_fixture "$d"; rc=$?
  expect "a tree where every shipped root links scp-alloc passes" PASS "$rc"

  d="$base/missing"; make_fixture "$d"
  sed -i.bak "/^use scp_alloc as _;$/d" "$d/crates/scp-relay/src/scp-relay.rs"
  run_fixture "$d"; rc=$?
  expect "a shipped root without the install line fails" FAIL "$rc"

  d="$base/cfg"; make_fixture "$d"
  sed -i.bak 's/^use scp_alloc as _;$/#[cfg(not(debug_assertions))]\nuse scp_alloc as _;/' "$d/crates/scp-ffi-napi/src/scp_ffi_napi.rs"
  grep -q 'cfg(not(debug_assertions))' "$d/crates/scp-ffi-napi/src/scp_ffi_napi.rs" || { echo "   FAIL — cfg fixture not written"; fixture_failures=$((fixture_failures + 1)); }
  run_fixture "$d"; rc=$?
  expect "a cfg-gated install line fails" FAIL "$rc"

  d="$base/indented"; make_fixture "$d"
  sed -i.bak 's/^use scp_alloc as _;$/mod inner {\n    use scp_alloc as _;\n}/' "$d/crates/scp-node/src/scp-node.rs"
  run_fixture "$d"; rc=$?
  expect "an install line nested in a module fails" FAIL "$rc"

  d="$base/multilinecfg"; make_fixture "$d"
  sed -i.bak 's/^use scp_alloc as _;$/#[cfg(all(\n    not(debug_assertions),\n    target_os = "linux",\n))]\nuse scp_alloc as _;/' "$d/crates/scp-relay/src/scp-relay.rs"
  grep -q '^))]$' "$d/crates/scp-relay/src/scp-relay.rs" || { echo "   FAIL — multi-line cfg fixture not written"; fixture_failures=$((fixture_failures + 1)); }
  run_fixture "$d"; rc=$?
  expect "an install line after a multi-line cfg ending in ))] fails" FAIL "$rc"

  d="$base/blockcomment"; make_fixture "$d"
  sed -i.bak 's|^use scp_alloc as _;$|/*\nuse scp_alloc as _;\n*/|' "$d/crates/scp-relay/src/scp-relay.rs"
  grep -q '^/\*$' "$d/crates/scp-relay/src/scp-relay.rs" || { echo "   FAIL — block-comment fixture not written"; fixture_failures=$((fixture_failures + 1)); }
  run_fixture "$d"; rc=$?
  expect "an install line inside a /* */ block comment fails" FAIL "$rc"

  d="$base/othertype"; make_fixture "$d"
  sed -i.bak 's/^static WIPING_ALLOCATOR: .*$/static WIPING_ALLOCATOR: std::alloc::System = std::alloc::System;/' "$d/$ALLOC_LIB_REL"
  run_fixture "$d"; rc=$?
  expect "a different allocator type in scp-alloc fails" FAIL "$rc"

  d="$base/cfgalloc"; make_fixture "$d"
  sed -i.bak 's/^#\[global_allocator\]$/#[cfg(not(feature = "off"))]\n#[global_allocator]/' "$d/$ALLOC_LIB_REL"
  run_fixture "$d"; rc=$?
  expect "a cfg on scp-alloc's static fails" FAIL "$rc"

  d="$base/second"; make_fixture "$d"
  printf '#[global_allocator]\nstatic B: std::alloc::System = std::alloc::System;\n' >> "$d/crates/scp-ffi/src/_scp_core.rs"
  run_fixture "$d"; rc=$?
  expect "a second #[global_allocator] in a crate's src fails" FAIL "$rc"

  d="$base/unclassified"; make_fixture "$d"
  jq '.packages += [{name: "scp-new", targets: [{name: "scp-new", kind: ["bin"], src_path: "/dev/null"}], dependencies: []}]' \
    "$d/metadata.json" > "$d/m.json" && mv "$d/m.json" "$d/metadata.json"
  run_fixture "$d"; rc=$?
  expect "an unclassified new bin target fails" FAIL "$rc"

  d="$base/optional"; make_fixture "$d"
  jq '(.packages[] | select(.name == "scp-relay") | .dependencies) = [{name: "scp-alloc", kind: null, optional: true, target: null}]' \
    "$d/metadata.json" > "$d/m.json" && mv "$d/m.json" "$d/metadata.json"
  run_fixture "$d"; rc=$?
  expect "an optional scp-alloc dependency fails" FAIL "$rc"

  d="$base/drift"; make_fixture "$d"
  printf 'ARTIFACTS=(\n  "scp-extra|"\n)\n' > "$d/$FEATURE_GRAPH_REL"
  jq '.packages += [{name: "scp-extra", targets: [{name: "scp-node", kind: ["cdylib"], src_path: "/dev/null"}], dependencies: []}]' \
    "$d/metadata.json" > "$d/m.json" && mv "$d/m.json" "$d/metadata.json"
  run_fixture "$d"; rc=$?
  expect "an ARTIFACTS package whose cdylib is not SHIPPED fails" FAIL "$rc"

  d="$base/devcdylib"; make_fixture "$d"
  jq '(.packages[] | select(.name == "scp-ffi-uniffi") | .targets[] | select(.name == "uniffi-bindgen") | .kind) = ["cdylib"]' \
    "$d/metadata.json" > "$d/m.json" && mv "$d/m.json" "$d/metadata.json"
  run_fixture "$d"; rc=$?
  expect "an ARTIFACTS cdylib classified as a DEV_TOOLS entry fails" FAIL "$rc"

  d="$base/stale"; make_fixture "$d"
  jq '.packages |= map(select(.name != "scp-client-wasm"))' "$d/metadata.json" > "$d/m.json" && mv "$d/m.json" "$d/metadata.json"
  run_fixture "$d"; rc=$?
  expect "a SHIPPED entry naming no real target fails" FAIL "$rc"

  if [[ "$fixture_failures" -eq 0 ]]; then
    echo "FIXTURE HARNESS: all behavioral proofs passed."
    return 0
  fi
  echo "FIXTURE HARNESS: $fixture_failures behavioral proof(s) failed."
  return 1
}

main() {
  command -v jq >/dev/null || { echo "error: jq is required" >&2; exit 2; }
  run_fixtures || exit 1
  if [[ "${1:-}" == "--self-test" ]]; then
    echo "--self-test: skipping the real workspace."
    exit 0
  fi

  echo
  local metadata
  metadata=$(mktemp)
  trap 'rm -f "$metadata"' EXIT
  (cd "$REPO_ROOT" && cargo metadata --no-deps --format-version 1) > "$metadata"
  if run_checks "$REPO_ROOT" "$metadata"; then
    echo
    echo "PASSED: every shipped binary and cdylib links scp-alloc's wiping allocator, and no other global allocator exists."
    exit 0
  fi
  echo
  echo "FAILED: $failures check(s). §9.15 of 09-security-model.md requires every shipped artifact to"
  echo "install the wiping allocator by linking scp-alloc (\`$INSTALL_LINE\` at its crate root)."
  exit 1
}

main "$@"
