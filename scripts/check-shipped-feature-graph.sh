#!/usr/bin/env bash
#
# G1 — Shipped-feature-graph prove-absence gate (ADR-062 §Decision 6 / §Enforcement,
# spec §17.17 SCP-CAPSEL-8000/8001/8002 + §17.17.2 durability-vs-nullifier).
#
# WHAT THIS PROVES
# ----------------
# For every shipped artifact (the three FFI bridges plus the scp-node and
# scp-relay binaries), the COMPLETE resolved feature set of the SCP
# workspace crates is a SUBSET of a single explicit permitted-production allowlist
# (one superset list covering all five artifacts) permitting durability-only +
# real-backend features and ZERO nullifier features. Any resolved SCP-crate
# feature that is NOT on this allowlist — named or novel, present or future —
# FAILS this gate. This gate's soundness invariant — shipped-graph
# feature-absence ≡ nullifier-type absence — holds for every `testing`-gated
# nullifier double (`InMemoryKeyCustody` / `InMemoryDeviceAttestation` /
# `InMemoryPreRotationCustody` / `InMemoryDhtClient` and a `did:key` test
# method, each gated behind a `testing` feature of scp-platform / scp-dht /
# scp-did / scp-core / scp-protocol / scp-runtime / scp-mls or behind an
# `scp-testing` crate, none of which this whitelist admits — so an absent gating
# feature means a nullifier cannot be compiled in), and it holds equally for
# `allow_unencrypted_storage`, which gates
# `ProtocolRepository::new_for_testing` (a constructor accepting any `Storage`,
# unsealing an `EncryptedStorage` bound that `ProtocolRepository::new` requires).
# Three `scp-*/allow_unencrypted_storage` rows sat on this allowlist until four
# shipped FFI-bridge `scp-node` dependency edges that resolved them were removed;
# `NULLIFIER_CONTROL_FEATURES` now names all three, so an
# `assert_allowlist_has_no_nullifier` fixture rejects any edit that puts them
# back.
#
# WHY A CLOSED ⊆-WHITELIST, NOT A DENYLIST
# ----------------------------------------
# A denylist ("fail if `scp-platform/testing` appears") is FAIL-OPEN: a fourth
# nullifier feature, a renamed one, or the transitive `scp-protocol/Cargo.toml`
# `testing = ["scp-did/testing", …]` did:key edge would bypass it. A positive ⊆
# whitelist is CLOSED BY CONSTRUCTION: anything not explicitly permitted fails,
# so novel/future nullifier features are caught without ever being named here.
# The four nullifier feature names below appear ONLY in the self-test fixtures as
# POSITIVE-CONTROL INPUTS the whitelist must reject — never as the mechanism.
#
# CRITICAL: DEV-DEPENDENCIES ARE EXCLUDED (`-e features,no-dev`)
# -------------------------------------------------------------
# A shipped artifact is built WITHOUT dev-dependencies. `cargo tree` includes
# dev-deps by default (and feature-unifies their `testing` edges into the graph),
# which does NOT reflect what ships. The `no-dev` edge kind restricts the graph to
# the normal + build dependencies that actually compile into the artifact.
#
# Usage:
#   scripts/check-shipped-feature-graph.sh            # gate the real workspace
#   scripts/check-shipped-feature-graph.sh --self-test # run the fixture harness only
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# ---------------------------------------------------------------------------
# Single permitted-production allowlist (EXPLICIT — the whitelist).
#
# Durability-only (SCP-CAPSEL-8010/8011) + real-backend features. ZERO nullifier
# features is a design mandate (ADR-062 §Decision 6; PR #2132), and this list now
# carries zero — no exceptions, no disclosed residue. An
# `assert_allowlist_has_no_nullifier` self-test enforces that no
# NULLIFIER_CONTROL_FEATURES entry is added, so a future edit cannot quietly add
# a nullifier exception.
#
# `scp-platform/in-memory-push` is an intentionally-permitted, currently-unused
# durability-only entry: no shipped artifact resolves it today, but a superset
# allowlist may carry permitted-but-unresolved rows (it is durability-only, not a
# nullifier, so its presence widens nothing that matters).
#
# `scp-platform/filesystem` was such a row until three FFI bridges stopped
# depending on it: `start_node_local` no longer opens a plaintext
# `FilesystemStorage` under its data directory, so no shipped artifact resolves
# that feature. Its row is dropped rather than kept, because keeping it would let
# a future dependency edge pull plaintext key-per-file storage back into a
# shipped graph with no gate failure to announce it.
#
# Five artifacts are gated: the three shipped FFI bridges (built
# `--no-default-features --features server`) plus the scp-node and scp-relay
# binaries (built with DEFAULT features — neither binary has a `server` feature).
# The three bridges resolve one identical SCP-crate feature set; each binary
# resolves a SUBSET of it (scp-node ~25, scp-relay ~19 SCP-crate feature edges).
# This single allowlist is therefore a SUPERSET covering all five — one list
# suffices. `cargo tree` DERIVES each artifact's resolved set (never a hand-list);
# this allowlist is the hand-maintained set of what is PERMITTED.
# ---------------------------------------------------------------------------
PERMITTED_ALLOWLIST="$(cat <<'EOF'
scp-client-wasm/default
scp-client/default
scp-dht/default
scp-dht/production-dht
scp-did/default
scp-ffi-common/custody
scp-ffi-common/default
scp-ffi-common/resolvers
scp-ffi-common/server
scp-ffi-napi/default
scp-ffi-napi/server
scp-ffi-uniffi/default
scp-ffi-uniffi/server
scp-ffi/default
scp-ffi/server
scp-identity/default
scp-identity/production-dht
scp-mls/default
scp-platform/encrypting
scp-platform/file
scp-platform/in-memory-push
scp-platform/in-memory-storage
scp-platform/software_platform
scp-platform/sqlite
scp-protocol/default
scp-transport/postgres-blob
scp-transport/redb-blob
scp-transport/s3-blob
scp-transport/sqlite-blob
scp-transport/startup
EOF
)"

# Shipped artifacts and their exact PRODUCTION build invocation. Two distinct
# shipped configurations, gated exactly as they ship:
#   - FFI bridges (scp-ffi / -napi / -uniffi): built `--no-default-features
#     --features server` — their production bridge configuration.
#   - Binaries (scp-node / scp-relay): built with DEFAULT features, so the
#     feature-arg string is EMPTY. This matches the Dockerfile
#     `cargo build --release -p scp-relay -p scp-node` and the `cargo publish`
#     shipping config. NEITHER binary has a `server` feature (scp-node has no
#     `default` block wiring one; scp-relay has no `[features]` table at all),
#     so passing `--features server` here would ERROR — they are correctly gated
#     with an empty feature-arg string, not with `--features server`.
#
# DRIFT CAVEAT: each entry's build-invocation string above MUST be kept in
# lockstep with the actual shipped build config — the Dockerfile
# `cargo build --release -p scp-relay -p scp-node`, a
# `.github/workflows/release.yml` `cargo publish` step, `maturin`'s
# `--manifest-path crates/scp-ffi/Cargo.toml` wheel build (which keeps default
# features and adds `extension-module`, a pyo3-only feature that changes no
# SCP-crate edge, so it resolves an `scp-ffi` set named below), and a
# `.github/workflows/build-matrix.yml` "Build shipped bridge artifacts" step,
# which builds one package per invocation into `target-shipped` so its uploaded
# cdylibs resolve those same per-package sets these entries name. This gate
# checks a feature config NAMED HERE, not whatever those workflows actually
# build; when those two drift apart, coverage silently narrows (an artifact
# would be gated in a config it no longer ships). One drift class is covered
# mechanically rather than
# by this caveat: a `default-members` check in `run_gate` resolves a bare
# `cargo build` at this root, so a member that unifies a nullifier into its
# siblings fails whether or not anyone updates this comment.
#
# uniffi-bindgen (the third workspace `[[bin]]`, in `crates/scp-ffi/uniffi`) is
# deliberately NOT a separate ARTIFACTS entry: it is a build-time code-generation
# tool, not a shipped runtime artifact, and its dependencies are already covered
# transitively by the `scp-ffi-uniffi` package entry above.
ARTIFACTS=(
  "scp-ffi|--no-default-features --features server"
  "scp-ffi-napi|--no-default-features --features server"
  "scp-ffi-uniffi|--no-default-features --features server"
  "scp-ffi|"
  "scp-ffi-napi|"
  "scp-ffi-uniffi|"
  "scp-core|"
  "scp-node|"
  "scp-relay|"
)

# Shipping files: the three files whose cargo invocations compile or publish a
# shipped artifact. assert_shipping_invocations_are_gated reads exactly these.
SHIPPING_FILES=(
  "Dockerfile"
  ".github/workflows/build-matrix.yml"
  ".github/workflows/release.yml"
)

# Every line of a SHIPPING_FILES file that carries a cargo feature-selection flag
# (`--features`, `-F`, `--all-features`, `--no-default-features`), normalized to
# single spaces with leading and trailing whitespace removed.
#
# assert_shipping_invocations_are_gated compares the shipping files against this
# list and FAILS on any difference, in either direction. Both lines below run
# `cargo test`, which compiles no shipped artifact, so neither one changes what
# ARTIFACTS must gate. A new or edited feature flag in any shipping file fails
# this gate until whoever wrote it either declares it here or adds the
# configuration it selects to ARTIFACTS.
DECLARED_SHIPPING_FEATURE_FLAG_LINES="$(cat <<'EOF'
run: cargo test --workspace --release --target ${{ matrix.target }} --features scp-core/testing,scp-runtime/saga-witness-test-mint
run: cargo test --workspace --release --features scp-ffi-uniffi/testing,scp-ffi/testing,scp-ffi-napi/testing,scp-core/testing,scp-runtime/saga-witness-test-mint
EOF
)"

# Every line of a SHIPPING_FILES file that names an SCP package after `-p` while
# compiling no shipped artifact, normalized to single spaces with leading and
# trailing whitespace removed.
#
# assert_shipping_invocations_are_gated drops these lines before it reads
# package names, and FAILS when a declared line no longer appears in any
# shipping file. The line below runs the conformance suite as a release
# precondition: `cargo nextest run` compiles a test binary and
# `.github/workflows/release.yml` publishes no `scp-testing` crate and uploads
# no artifact built from that command, so the package it names needs no
# ARTIFACTS entry. `scp-testing` is the test-harness crate itself — root
# `Cargo.toml` omits it from `default-members` precisely so its nullifier
# features never unify into a shipped build — so gating it as a shipped
# artifact would assert the opposite of what this gate exists to prove. A `-p`
# line this list does not carry fails the gate until whoever wrote it either
# adds the configuration it builds to ARTIFACTS or declares here why that line
# ships nothing.
DECLARED_NON_SHIPPING_PACKAGE_LINES="$(cat <<'EOF'
cargo nextest run --no-tests=fail --release -p scp-testing -E 'test(conformance)'
EOF
)"

# Nullifier features / crates used ONLY as positive-control fixture inputs and by
# the allowlist-hygiene self-test. NEVER the gate mechanism.
NULLIFIER_CONTROL_FEATURES=(
  "scp-platform/testing"
  "scp-platform/in-memory-custody"
  "scp-platform/in-memory-attestation"
  "scp-platform/in-memory-pre-rotation"
  "scp-dht/testing"
  "scp-did/testing"
  "scp-core/testing"
  "scp-protocol/testing"
  "scp-runtime/testing"
  "scp-mls/testing"
  "scp-client/testing"
  "scp-client-wasm/testing"
  "scp-testing"
  # `allow_unencrypted_storage` gates `ProtocolRepository::new_for_testing`,
  # which takes any `Storage` where `ProtocolRepository::new` demands a sealed
  # `EncryptedStorage` bound, so this feature unseals encryption at rest — a
  # confidentiality nullifier, not a durability-only capability (spec §17.17.2).
  # Each of three crates re-exports one gate down one dependency chain
  # (scp-core → scp-runtime; scp-node → scp-core), so all three names appear.
  "scp-core/allow_unencrypted_storage"
  "scp-node/allow_unencrypted_storage"
  "scp-runtime/allow_unencrypted_storage"
)

# ---------------------------------------------------------------------------
# resolve_scp_features <crate> <features...>
#   Emit the COMPLETE resolved SCP-crate feature set of the shipped artifact,
#   one `crate/feature` per line, sorted-unique. Excludes dev-dependencies.
#
#   DELIBERATE SPLIT from resolve_scp_testing_crate (NOT a redundant twin): this
#   extracts FEATURE edges (`scp-* feature "…"`) from the `-e features,no-dev`
#   tree, whereas resolve_scp_testing_crate probes CRATE-NODE presence
#   (`scp-testing v…`) in the `-e no-dev` tree. A `scp-testing` pulled with
#   `default-features = false` and no features enabled contributes NO feature
#   edge here (so this grep would miss it) yet still appears as a crate node —
#   so the two checks catch distinct cases and are both load-bearing.
# ---------------------------------------------------------------------------
resolve_scp_features() {
  local crate="$1"; shift
  local features="$1"
  local raw rc
  # Capture stdout+stderr and the exit status. Do NOT swallow a cargo failure
  # silently: if resolution fails (e.g. the feature args name a feature this
  # artifact lacks), surface the cargo error and return non-zero so the caller
  # fails loud instead of proceeding with an empty (vacuously-passing) set.
  # shellcheck disable=SC2086
  raw="$(cargo tree -e no-dev --prefix none -f "{f}|{p}" -p "$crate" $features 2>&1)"; rc=$?
  if [[ "$rc" -ne 0 ]]; then
    { echo "cargo tree failed for '$crate' (feature args: '$features'):"
      printf '%s\n' "$raw"; } >&2
    return 1
  fi
  extract_resolved_features "$raw"
}

# ---------------------------------------------------------------------------
# extract_resolved_features <cargo-tree-output>
#   Emit one `crate/feature` line per feature cargo ENABLED on every scp-* node
#   of a `--prefix none -f "{f}|{p}"` tree, sorted-unique.
#
#   WHY `{f}` AND NOT A `feature "…"` NODE
#   --------------------------------------
#   This gate read `cargo tree -e features` and grepped its `scp-<crate> feature
#   "<name>"` pseudo-nodes until #2305's post-merge review. cargo prints such a
#   node for a feature a MANIFEST NAMES ON A DEPENDENCY EDGE (`scp-dht = {
#   features = ["production-dht"] }`) and prints NO node for a feature the root
#   package's own feature table turns on with `dep/feature` syntax. Every
#   nullifier double in this repository is gated behind exactly that second
#   shape — `scp-node/testing = ["scp-dht/testing", "scp-platform/testing", …]`,
#   `scp-ffi-uniffi/testing = ["scp-core/testing", "scp-dht/testing", …]` — so
#   the edge grep resolved `-p scp-node --features testing` to a set with ZERO
#   offenders and this gate printed OK for a build that compiles
#   `InMemoryKeyCustody`, `InMemoryDeviceAttestation`,
#   `InMemoryPreRotationCustody` and `InMemoryDhtClient`. Measured on that tree:
#   25 feature-edge rows, byte-identical to the default-feature run, while
#   `-f "{p} [{f}]"` printed `scp-platform […,testing]` and `scp-dht
#   [default,production-dht,testing]` in the very resolution the gate read as
#   clean. scp-ffi and scp-ffi-napi failed correctly only because their
#   `testing` feature additionally carries `dep:scp-testing`, whose own manifest
#   declares `features = ["testing"]` on its SCP dependency edges — a property of
#   the test-harness crate's manifest, not of the gate.
#
#   `{f}` is cargo's own resolved feature list for a node, so it reports a
#   feature however that feature was enabled: a dependency-edge `features = [..]`
#   list, a `dep/feature` entry in any package's feature table, a `--features`
#   argument, or resolver-2 unification across an invocation's packages.
#
#   `--prefix none` strips the tree-drawing characters, so every node starts at
#   column 0 and the parse needs no tree grammar. `{f}` sits BEFORE `{p}` because
#   a feature name never contains `|` while a package's filesystem path may, so
#   splitting on the FIRST `|` is correct by construction. A node whose features
#   are empty prints a leading `|` and contributes no line.
#
#   Fail-closed on a format change: if cargo ever stops printing this shape, no
#   line matches, the resolved set is EMPTY, and resolution_is_nonempty rejects
#   it in run_gate rather than passing a vacuous "empty ⊆ allowlist".
# ---------------------------------------------------------------------------
extract_resolved_features() {
  printf '%s\n' "$1" \
    | awk -F'|' '
        NF < 2 { next }
        $2 !~ /^scp-[a-z0-9-]+ v[0-9]/ { next }
        {
          split($2, pkg, " ")
          n = split($1, feats, ",")
          for (i = 1; i <= n; i++) {
            if (feats[i] != "") { print pkg[1] "/" feats[i] }
          }
        }' \
    | sort -u
}

# resolve_scp_testing_crate <crate> <features...>
#   Emit "scp-testing" iff the full-stack test-harness crate is in the shipped
#   (no-dev) dependency graph. Its mere presence is a nullifier and FAILS.
#   DELIBERATE SPLIT from resolve_scp_features (NOT a redundant twin): this probes
#   CRATE-NODE presence (`scp-testing v…`), which catches a `scp-testing` pulled
#   with no enabled features — a case the feature-edge grep in resolve_scp_features
#   would miss. Both checks are load-bearing; keep them separate.
#   Fails LOUD on a cargo error, mirroring resolve_scp_features: a swallowed
#   `2>/dev/null` failure produces no output, which the grep would read as
#   "scp-testing absent" — a FAIL-OPEN read that lets a cargo resolution error
#   masquerade as nullifier-crate absence. Capture stdout+stderr and the exit
#   status; on a cargo error, surface it and return non-zero so the caller fails
#   loud instead of silently concluding the test-harness crate is not present.
resolve_scp_testing_crate() {
  local crate="$1"; shift
  local features="$1"
  local raw rc
  # shellcheck disable=SC2086
  raw="$(cargo tree -e no-dev -p "$crate" $features 2>&1)"; rc=$?
  if [[ "$rc" -ne 0 ]]; then
    { echo "cargo tree (scp-testing probe) failed for '$crate' (feature args: '$features'):"
      printf '%s\n' "$raw"; } >&2
    return 1
  fi
  if tree_names_scp_testing_crate "$raw"; then
    echo "scp-testing"
  fi
}

# tree_names_scp_testing_crate <cargo-tree-output>
#   Return 0 when a tree carries a `scp-testing v…` crate node, 1 when it does
#   not. Extracted from resolve_scp_testing_crate so run_fixtures can drive it
#   with synthetic input, and written WITHOUT `grep -q`.
#
#   `set -o pipefail` (line 48) makes a pipeline report a last non-zero exit
#   status any stage returned. `grep -q` stops reading at its first match and
#   exits, which closes a pipe while `printf` is still writing; `printf` then
#   dies of SIGPIPE and returns 141, and pipefail hands 141 to `if`, which takes
#   its else branch. This probe reported "scp-testing absent" on exactly the
#   trees that carry it near a top — a FAIL-OPEN read on a gate whose whole
#   claim is ZERO nullifiers. Measured on this tree: `cargo tree -e no-dev -p
#   scp-node` prints 96,898 bytes, past a 64 KB pipe buffer, and a
#   `scp-testing v0.1.0` line prepended to it read as ABSENT under `grep -q`
#   and as PRESENT under `grep … >/dev/null`. scripts/check-cross-layer.sh
#   carried an identical construct, and the pull request that made a `ci` gate
#   enforce what it claims, #2361, fixed it there.
#
#   `grep -E … >/dev/null` reads its whole input, so `printf` never receives
#   SIGPIPE and a pipeline reports grep's own verdict.
#
#   grep exits 0 on a match, 1 on no match, and 2 or higher on its own error.
#   Returning that status unchanged would make a grep error read as "no match",
#   which is the same FAIL-OPEN verdict SIGPIPE produced, so a status above 1
#   aborts this gate instead.
tree_names_scp_testing_crate() {
  local raw="$1" rc=0
  printf '%s\n' "$raw" | grep -E '(^|[^a-z-])scp-testing v' >/dev/null || rc=$?
  if [[ "$rc" -gt 1 ]]; then
    echo "grep failed with status $rc while probing a tree for a scp-testing crate node" >&2
    exit 1
  fi
  return "$rc"
}

# ---------------------------------------------------------------------------
# check_subset <resolved-lines> <allowlist-lines>
#   Pure ⊆ check: prints every resolved entry NOT on the allowlist. Returns 0 if
#   resolved ⊆ allowlist (no output), 1 otherwise. This function is the sole
#   decision procedure; the fixture harness drives it with synthetic inputs.
# ---------------------------------------------------------------------------
check_subset() {
  local resolved="$1" allowlist="$2" offenders
  offenders="$(comm -23 <(printf '%s\n' "$resolved" | sort -u) \
                        <(printf '%s\n' "$allowlist" | sort -u))"
  if [[ -n "$offenders" ]]; then
    printf '%s\n' "$offenders"
    return 1
  fi
  return 0
}

# ---------------------------------------------------------------------------
# resolution_is_nonempty <resolved-lines>
#   Guards the VACUOUS-PASS hazard. The ⊆ check treats "empty ⊆ allowlist" as a
#   PASS — so an empty resolved set would silently green while checking nothing.
#   Every shipped artifact legitimately resolves a NON-EMPTY SCP-crate feature
#   set (the three bridges, plus scp-node ~25 and scp-relay ~19 feature edges),
#   so an empty result means cargo resolution failed or the feature args are
#   wrong. Returns 0 if the resolved set is non-empty, 1 if empty. Factored out
#   as a pure predicate so the fixture harness can drive it directly.
# ---------------------------------------------------------------------------
resolution_is_nonempty() {
  [[ -n "$1" ]]
}

# ---------------------------------------------------------------------------
# resolve_default_members_features
#   Emit a COMPLETE resolved SCP-crate feature set for a bare `cargo build` at
#   this workspace root — no `-p`, so cargo resolves `[workspace] default-members`
#   and unifies normal-dependency features across every package on that list.
#
#   WHY THIS EXISTS SEPARATELY FROM resolve_scp_features
#   ---------------------------------------------------
#   Every per-artifact entry above models `cargo build -p <package>`. Resolver 2
#   unifies normal-dependency features per INVOCATION, not per package, so a
#   command that builds several members at once resolves a UNION none of those
#   per-package checks sees. `.github/workflows/build-matrix.yml` runs exactly
#   such a bare `cargo build --release --target <triple>` and uploads each FFI
#   bridge cdylib it produces, and `.github/workflows/release.yml`
#   Authenticode-signs those DLLs — so a member carrying a test-harness feature
#   on a normal dependency edge would ship a nullifier through a signed binary
#   while all five per-artifact checks stayed green.
#
#   `crates/scp-testing` is such a member: its `helpers.rs` names in-memory
#   doubles at lib level, so `scp-core/testing`, `scp-platform/testing`,
#   `scp-dht/testing`, and `allow_unencrypted_storage` sit on its NORMAL edges.
#   Root `Cargo.toml` therefore omits it from `default-members`, and this check
#   is what keeps that omission true.
# ---------------------------------------------------------------------------
resolve_default_members_features() {
  local raw rc
  raw="$(cargo tree -e no-dev --prefix none -f "{f}|{p}" 2>&1)"; rc=$?
  if [[ "$rc" -ne 0 ]]; then
    { echo "cargo tree failed for a bare default-members resolution:"
      printf '%s\n' "$raw"; } >&2
    return 1
  fi
  extract_resolved_features "$raw"
}

# resolve_default_members_testing_crate
#   Emit "scp-testing" iff a bare default-members build pulls that crate. Mirrors
#   resolve_scp_testing_crate, which probes CRATE-NODE presence rather than
#   feature edges, and catches a `scp-testing` pulled with no enabled features.
#   Reads its tree through tree_names_scp_testing_crate, the single probe the
#   fixture harness drives, so this function cannot carry the `grep -q` SIGPIPE
#   fail-open that function's comment describes. `cargo tree -e no-dev` over
#   every default member prints a superset of the 96,898-byte tree that comment
#   measured, so a `grep -q` here would have read a scp-testing node near a top
#   of that tree as ABSENT.
resolve_default_members_testing_crate() {
  local raw rc
  raw="$(cargo tree -e no-dev 2>&1)"; rc=$?
  if [[ "$rc" -ne 0 ]]; then
    { echo "cargo tree (scp-testing probe) failed for a bare default-members resolution:"
      printf '%s\n' "$raw"; } >&2
    return 1
  fi
  if tree_names_scp_testing_crate "$raw"; then
    echo "scp-testing"
  fi
}

# ---------------------------------------------------------------------------
# Real gate.
# ---------------------------------------------------------------------------
run_gate() {
  local failures=0
  echo "G1 shipped-feature-graph gate (ADR-062 §Decision 6) — dev-deps EXCLUDED"
  echo "-------------------------------------------------------------------------"
  for spec in "${ARTIFACTS[@]}"; do
    local crate="${spec%%|*}" features="${spec#*|}"
    echo ">> $crate  ($features)"

    local resolved offenders
    # resolve_scp_features returns non-zero (and surfaces cargo's stderr) if
    # resolution fails; the non-empty guard additionally rejects an empty result
    # from any cause. Either way the artifact FAILS LOUD — an empty set must
    # NEVER be accepted as a vacuous "empty ⊆ allowlist" pass.
    if ! resolved="$(resolve_scp_features "$crate" "$features")" \
        || ! resolution_is_nonempty "$resolved"; then
      echo "   FAIL — resolved SCP-crate feature set is EMPTY (cargo resolution"
      echo "          failed or the feature args are wrong — e.g. '$features'"
      echo "          names a feature '$crate' does not have). Every shipped"
      echo "          artifact (3 bridges + scp-node + scp-relay) legitimately"
      echo "          resolves a NON-EMPTY set; refusing to treat an empty"
      echo "          resolution as 'empty ⊆ allowlist' PASS."
      failures=$((failures + 1))
      continue
    fi
    # A present scp-testing crate is itself a nullifier — fold it into the set so
    # the ⊆ check rejects it (it is never on the allowlist). The probe fails loud
    # (non-zero) on a cargo error; refuse to read a probe failure as "no
    # test-harness crate present" (that would be fail-open).
    local testing_crate
    if ! testing_crate="$(resolve_scp_testing_crate "$crate" "$features")"; then
      echo "   FAIL — scp-testing presence probe failed (cargo resolution error);"
      echo "          refusing to read a probe failure as 'no nullifier crate present'."
      failures=$((failures + 1))
      continue
    fi
    [[ -n "$testing_crate" ]] && resolved="$(printf '%s\n%s' "$resolved" "$testing_crate")"

    if offenders="$(check_subset "$resolved" "$PERMITTED_ALLOWLIST")"; then
      echo "   OK — resolved SCP-crate feature set ⊆ permitted-production allowlist"
    else
      echo "   FAIL — resolved features NOT on the permitted-production allowlist:"
      printf '%s\n' "$offenders" | sed 's/^/       ✗ /'
      echo "   These are test-harness / nullifier features that must NOT reach a"
      echo "   shipped artifact. A shipped build carries only durability-only +"
      echo "   real-backend features (ADR-062 §Decision 6; ZERO-nullifier mandate,"
      echo "   zero nullifier exceptions)."
      failures=$((failures + 1))
    fi
  done

  # A bare workspace build — one `.github/workflows/build-matrix.yml` runs
  # and uploads bridge cdylibs from. Resolver 2 unifies normal-dependency
  # features across every default member, so this union can carry a nullifier no
  # per-artifact check above would see.
  echo ">> default-members  (bare \`cargo build\` at this workspace root)"
  local dm_resolved dm_offenders dm_testing
  if ! dm_resolved="$(resolve_default_members_features)" \
      || ! resolution_is_nonempty "$dm_resolved"; then
    echo "   FAIL — resolved SCP-crate feature set is EMPTY (cargo resolution"
    echo "          failed). A default-members build legitimately resolves a"
    echo "          NON-EMPTY set; refusing to treat an empty resolution as"
    echo "          'empty ⊆ allowlist' PASS."
    failures=$((failures + 1))
  elif ! dm_testing="$(resolve_default_members_testing_crate)"; then
    echo "   FAIL — scp-testing presence probe failed (cargo resolution error);"
    echo "          refusing to read a probe failure as 'no nullifier crate present'."
    failures=$((failures + 1))
  else
    [[ -n "$dm_testing" ]] && dm_resolved="$(printf '%s\n%s' "$dm_resolved" "$dm_testing")"
    if dm_offenders="$(check_subset "$dm_resolved" "$PERMITTED_ALLOWLIST")"; then
      echo "   OK — resolved SCP-crate feature set ⊆ permitted-production allowlist"
    else
      echo "   FAIL — a bare workspace build resolves features NOT on a"
      echo "   permitted-production allowlist:"
      printf '%s\n' "$dm_offenders" | sed 's/^/       ✗ /'
      echo "   Resolver 2 unified them from a default member's NORMAL dependency"
      echo "   edge. Move that edge to [dev-dependencies], or drop that member"
      echo "   from \`default-members\` in a root Cargo.toml — do NOT add that"
      echo "   feature to this allowlist."
      failures=$((failures + 1))
    fi
  fi
  return "$failures"
}

# ---------------------------------------------------------------------------
# Self-test / fixture harness (AC7 + AC8 behavioral proofs).
# ---------------------------------------------------------------------------
fixture_failures=0
expect() { # <label> <expected: PASS|FAIL> <actual-rc>
  local label="$1" expected="$2" rc="$3" actual
  [[ "$rc" -eq 0 ]] && actual="PASS" || actual="FAIL"
  if [[ "$actual" == "$expected" ]]; then
    echo "   ok   — $label (expected $expected)"
  else
    echo "   FAIL — $label (expected $expected, got $actual)"
    fixture_failures=$((fixture_failures + 1))
  fi
}

# assert_every_pipeline_reader_consumes_its_input
#   Structural proof that no pipeline in THIS FILE can repeat the SIGPIPE
#   fail-open that tree_names_scp_testing_crate's comment describes.
#
#   The four (SIGPIPE) fixtures below drive tree_names_scp_testing_crate with
#   synthetic trees, so they prove that ONE probe reads its whole input. They
#   cannot see a second probe written elsewhere in this file, and
#   resolve_default_members_testing_crate carried exactly such a second probe:
#   `printf | grep -qE` over the tree `cargo tree -e no-dev` prints for every
#   default member. This fixture closes that gap over the whole file.
#
#   CRITERION: every stage this file pipes into reads its input to end of file.
#   A stage that exits before its writer finishes kills that writer with SIGPIPE,
#   `set -o pipefail` reports 141, and an `if` on that pipeline takes its else
#   branch — the fail-open verdict on a ZERO-nullifier gate.
#
#   The criterion is decidable over this file because the commands this file
#   pipes into are `grep`, `sed`, `sort`, and `comm`, and only `grep` offers an
#   early exit: `-q`/`--quiet`/`--silent`, which stops at a first match, and
#   `-m N`/`--max-count=N`, which stops at an Nth one. `sed`, `sort`, and `comm`
#   read to end of file under every invocation this file writes. So rejecting
#   those two grep options, plus a pipe into `head`, decides the criterion
#   rather than sampling spellings of it.
assert_every_pipeline_reader_consumes_its_input() {
  echo ">> fixture: every stage this gate pipes into reads its whole input, so no probe can report SIGPIPE (141) as a verdict"
  local self offenders
  self="${BASH_SOURCE[0]}"
  offenders="$(grep -nE '\|[[:space:]]*(head[[:space:]]|grep[[:space:]]+(-[a-zA-Z]*q|--quiet|--silent|-m[[:space:]]|--max-count))' "$self" \
    | grep -vE '^[0-9]+:[[:space:]]*#' || true)"
  if [[ -n "$offenders" ]]; then
    echo "   FAIL — a pipeline stage below exits before its writer finishes, so pipefail"
    echo "          reports 141 and the enclosing test reads a match as a NON-match:"
    printf '%s\n' "$offenders" | sed 's/^/       x /'
    echo "          Write 'grep -E ... >/dev/null' and read grep's own status instead."
    fixture_failures=$((fixture_failures + 1))
    return
  fi
  echo "   ok   — no pipeline in this gate feeds a reader that stops early"
}

assert_allowlist_has_no_nullifier() {
  echo ">> fixture: allowlist carries ZERO enumerated control-nullifier features — no NULLIFIER_CONTROL_FEATURES entry (custody/attestation/DHT/did:key/test-harness double, or an allow_unencrypted_storage encryption-at-rest unseal) appears (AC7)"
  local nf
  for nf in "${NULLIFIER_CONTROL_FEATURES[@]}"; do
    # `grep -xF … >/dev/null`, not `grep -qxF`, for a SIGPIPE-under-pipefail
    # reason documented above tree_names_scp_testing_crate: `grep -q` exits at
    # its first match, `printf` dies of SIGPIPE, pipefail reports 141, and this
    # check reads a nullifier ON the allowlist as a nullifier absent from it.
    if printf '%s\n' "$PERMITTED_ALLOWLIST" | grep -xF "$nf" >/dev/null; then
      echo "   FAIL — nullifier feature '$nf' is on the allowlist (forbidden exception)"
      fixture_failures=$((fixture_failures + 1))
    fi
  done
  echo "   ok   — no custody/attestation/DHT/did:key/test-harness/encryption-at-rest-unseal nullifier control-feature appears on this allowlist"
}

# ---------------------------------------------------------------------------
# normalize_shipping_lines <text>
#   Emit the lines of <text> with leading and trailing whitespace removed and
#   every internal whitespace run collapsed to one space, empty lines dropped,
#   sorted-unique. Both declaration lists above are written in this normalized
#   form, so a line indented inside a YAML `run: |` block compares equal to the
#   declaration a reader wrote flush-left.
# ---------------------------------------------------------------------------
normalize_shipping_lines() {
  printf '%s\n' "$1" \
    | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//; s/[[:space:]]+/ /g; /^$/d' \
    | sort -u
}

# ---------------------------------------------------------------------------
# packages_built_by_shipping_lines <shipping-lines> <declared-non-shipping-lines>
#   Emit one SCP package name per line, sorted-unique, for every package the
#   shipping lines name after `-p` or list in a `for pkg in …;` loop, after
#   dropping every line that appears verbatim in <declared-non-shipping-lines>.
#   Both arguments are normalized by normalize_shipping_lines, so a declaration
#   matches its shipping line whatever indentation that line carries.
#
#   The declaration list is what keeps this decidable rather than a guess about
#   which cargo subcommands build something: a `-p` line either names a package
#   this gate resolves, or a human declares in DECLARED_NON_SHIPPING_PACKAGE_LINES
#   why that exact line compiles no shipped artifact. Reading the subcommand
#   instead (`build` ships, `nextest` does not) would be a denylist of spellings,
#   and `cargo run -p scp-ffi-uniffi --bin uniffi-bindgen` already shows a
#   subcommand that neither reading classifies on its name alone.
#
#   Factored out as a pure function so run_fixtures drives it with synthetic
#   lines, including the case a declared line must NOT suppress.
# ---------------------------------------------------------------------------
packages_built_by_shipping_lines() {
  local kept
  kept="$(comm -23 <(normalize_shipping_lines "$1") <(normalize_shipping_lines "$2"))"
  { printf '%s\n' "$kept" | grep -oE '\-p "?scp-[a-z0-9-]+"?' | sed -E 's/^-p "?//; s/"$//' || true
    printf '%s\n' "$kept" | grep -oE '^for pkg in [a-z0-9 -]+;' \
      | sed -E 's/^for pkg in //; s/;$//' | tr ' ' '\n' || true
  } | sed -E '/^$/d' | sort -u
}

# assert_shipping_invocations_are_gated
#   The DRIFT property this gate could not previously assert: ARTIFACTS names a
#   feature configuration per shipped artifact, and nothing read the commands
#   that actually build those artifacts, so an edit to Dockerfile or to a
#   workflow could change what ships while this gate kept resolving the
#   configuration written here and printing OK.
#
#   CRITERION (two halves, each decidable over the shipping files):
#     1. Every SCP package a shipping file names after `-p`, or lists in the
#        `for pkg in …` loop that builds the uploaded bridge cdylibs, is a
#        package this gate resolves — an ARTIFACTS entry, or a node of the
#        default-members tree the default-members check resolves — unless the
#        line naming it appears verbatim in DECLARED_NON_SHIPPING_PACKAGE_LINES,
#        where a human wrote why that line compiles no shipped artifact. A
#        package built alone resolves a SUBSET of what the default-members
#        invocation unifies, so a package inside that clean tree cannot carry a
#        feature the allowlist rejects.
#     2. Every line of a shipping file carrying a cargo feature-selection flag
#        appears verbatim in DECLARED_SHIPPING_FEATURE_FLAG_LINES. The set of
#        flags that changes cargo's feature resolution is closed —
#        `--features`, `-F`, `--all-features`, `--no-default-features` — so
#        matching those four decides the criterion instead of sampling
#        spellings of it. Whoever adds a fifth spelling to cargo also has to add
#        it here, and until then an undeclared flag line fails this gate.
#
#   Both halves fail CLOSED: a shipping file this function cannot read fails, and
#   a package or a flag line it cannot account for fails.
assert_shipping_invocations_are_gated() {
  echo ">> fixture: every package a shipping file builds is gated, and every feature flag in one is declared (drift between ARTIFACTS and the shipped build commands)"
  local file missing_files="" gated_packages="" dm_tree pkg flag_lines undeclared

  for file in "${SHIPPING_FILES[@]}"; do
    [[ -f "$file" ]] || missing_files="$missing_files $file"
  done
  if [[ -n "$missing_files" ]]; then
    echo "   FAIL — shipping file(s) named by SHIPPING_FILES do not exist:$missing_files"
    echo "          A renamed or deleted shipping file leaves its build commands unread."
    fixture_failures=$((fixture_failures + 1))
    return
  fi

  # Half 1 — packages built by a shipping file.
  local spec
  for spec in "${ARTIFACTS[@]}"; do
    gated_packages="$gated_packages
${spec%%|*}"
  done
  if ! dm_tree="$(cargo tree -e no-dev --prefix none -f "{p}" 2>&1)"; then
    echo "   FAIL — cargo could not resolve the default-members tree this fixture reads:"
    printf '%s\n' "$dm_tree" | sed 's/^/       /'
    fixture_failures=$((fixture_failures + 1))
    return
  fi
  gated_packages="$gated_packages
$(printf '%s\n' "$dm_tree" | sed -E -n 's/^(scp-[a-z0-9-]+) v[0-9].*/\1/p')"
  gated_packages="$(printf '%s\n' "$gated_packages" | sed -E '/^$/d' | sort -u)"

  local shipping_lines built_packages ungated="" stale_pkg_lines
  shipping_lines="$(cat "${SHIPPING_FILES[@]}")"
  built_packages="$(packages_built_by_shipping_lines "$shipping_lines" "$DECLARED_NON_SHIPPING_PACKAGE_LINES")"
  for pkg in $built_packages; do
    if ! printf '%s\n' "$gated_packages" | grep -xF "$pkg" >/dev/null; then
      ungated="$ungated $pkg"
    fi
  done
  if [[ -n "$ungated" ]]; then
    echo "   FAIL — a shipping file builds SCP package(s) this gate resolves in no configuration:$ungated"
    echo "          Add an ARTIFACTS entry for each, or restore its default-members membership."
    echo "          A line that compiles no shipped artifact belongs instead in"
    echo "          DECLARED_NON_SHIPPING_PACKAGE_LINES with the reason it ships nothing."
    fixture_failures=$((fixture_failures + 1))
    return
  fi
  stale_pkg_lines="$(comm -13 <(normalize_shipping_lines "$shipping_lines") \
                              <(normalize_shipping_lines "$DECLARED_NON_SHIPPING_PACKAGE_LINES"))"
  if [[ -n "$stale_pkg_lines" ]]; then
    echo "   FAIL — DECLARED_NON_SHIPPING_PACKAGE_LINES declares line(s) no shipping file carries:"
    printf '%s\n' "$stale_pkg_lines" | sed 's/^/       x /'
    echo "          A stale declaration suppresses the next edit to the line it once described."
    fixture_failures=$((fixture_failures + 1))
    return
  fi

  # Half 2 — feature-selection flags in a shipping file.
  flag_lines="$(grep -hE '(^|[[:space:]])(--features|-F|--all-features|--no-default-features)([[:space:]]|=|$)' "${SHIPPING_FILES[@]}" \
    | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//; s/[[:space:]]+/ /g' | sort -u)"
  undeclared="$(comm -23 <(printf '%s\n' "$flag_lines" | sed -E '/^$/d' | sort -u) \
                         <(printf '%s\n' "$DECLARED_SHIPPING_FEATURE_FLAG_LINES" | sed -E '/^$/d' | sort -u))"
  if [[ -n "$undeclared" ]]; then
    echo "   FAIL — a shipping file carries a cargo feature-selection flag this gate never declared:"
    printf '%s\n' "$undeclared" | sed 's/^/       x /'
    echo "          Either that line builds a shipped artifact — then gate its configuration in"
    echo "          ARTIFACTS — or it builds no shipped artifact, and belongs in"
    echo "          DECLARED_SHIPPING_FEATURE_FLAG_LINES with the reason it ships nothing."
    fixture_failures=$((fixture_failures + 1))
    return
  fi
  local stale
  stale="$(comm -13 <(printf '%s\n' "$flag_lines" | sed -E '/^$/d' | sort -u) \
                    <(printf '%s\n' "$DECLARED_SHIPPING_FEATURE_FLAG_LINES" | sed -E '/^$/d' | sort -u))"
  if [[ -n "$stale" ]]; then
    echo "   FAIL — DECLARED_SHIPPING_FEATURE_FLAG_LINES declares line(s) no shipping file carries:"
    printf '%s\n' "$stale" | sed 's/^/       x /'
    echo "          A stale declaration hides the next edit to the line it once described."
    fixture_failures=$((fixture_failures + 1))
    return
  fi
  echo "   ok   — every package a shipping file builds is gated, every feature-flag line in one is declared, and each declaration still names a line a shipping file carries"
}

run_fixtures() {
  echo "G1 fixture harness — behavioral proof the ⊆-whitelist is closed & load-bearing"
  echo "-------------------------------------------------------------------------------"

  # (c) Clean artifact whose resolved set ⊆ allowlist → ACCEPTED.
  local clean rc
  clean="$PERMITTED_ALLOWLIST"
  check_subset "$clean" "$PERMITTED_ALLOWLIST" >/dev/null; rc=$?
  expect "(c) clean resolved set ⊆ allowlist is ACCEPTED" "PASS" "$rc"

  # (a) A NOVEL, never-before-seen feature not on the allowlist → REJECTED.
  #     Proves the check is closed/positive (not a fixed denylist of known names).
  local novel
  novel="$(printf '%s\nscp-platform/some-future-nullifier-9000' "$PERMITTED_ALLOWLIST")"
  check_subset "$novel" "$PERMITTED_ALLOWLIST" >/dev/null 2>&1; rc=$?
  expect "(a) novel feature not on allowlist is REJECTED" "FAIL" "$rc"

  # (b) Allowlist edited to OMIT a genuinely-resolved feature → REJECTED.
  #     Proves the allowlist is load-bearing (⊆ is actually enforced).
  local trimmed
  trimmed="$(printf '%s\n' "$PERMITTED_ALLOWLIST" | grep -vxF 'scp-platform/in-memory-storage')"
  check_subset "$PERMITTED_ALLOWLIST" "$trimmed" >/dev/null 2>&1; rc=$?
  expect "(b) allowlist omitting a resolved feature is REJECTED" "FAIL" "$rc"

  # (AC8 soundness) A synthetic consumer whose graph carries a nullifier feature
  #     (e.g. a mis-wired bridge, or a future consumer that fails to keep a
  #     nullifier behind dev-deps) → REJECTED, because a durability-only +
  #     real-backend allowlist admits no `testing` feature and no
  #     `allow_unencrypted_storage` feature. That is this gate's
  #     feature-absence ≡ nullifier-absence invariant, and it now holds for an
  #     encryption-at-rest unseal as well as for testing doubles: a shipped
  #     artifact that resolved `scp-runtime/allow_unencrypted_storage` would
  #     compile `ProtocolRepository::new_for_testing`, and this fixture proves
  #     that a ⊆ check rejects such a resolved set.
  local nf leaked
  for nf in "scp-platform/testing" "scp-dht/testing" "scp-did/testing" "scp-testing" \
            "scp-core/allow_unencrypted_storage" "scp-node/allow_unencrypted_storage" \
            "scp-runtime/allow_unencrypted_storage"; do
    leaked="$(printf '%s\n%s' "$PERMITTED_ALLOWLIST" "$nf")"
    check_subset "$leaked" "$PERMITTED_ALLOWLIST" >/dev/null 2>&1; rc=$?
    expect "(soundness) leaked nullifier feature '$nf' is REJECTED" "FAIL" "$rc"
  done

  # (empty-resolution guard) An EMPTY resolved set must be REJECTED, never
  #     treated as a vacuous "empty ⊆ allowlist" PASS. This proves the non-empty
  #     assertion wired into run_gate (which fires when cargo resolution fails or
  #     the feature args are wrong) is load-bearing.
  resolution_is_nonempty ""; rc=$?
  expect "(empty-guard) empty resolved set is REJECTED" "FAIL" "$rc"
  resolution_is_nonempty "scp-core/default"; rc=$?
  expect "(empty-guard) non-empty resolved set is ACCEPTED" "PASS" "$rc"

  # (SIGPIPE) A crate-node probe must return one verdict wherever a match sits.
  #     Under `grep -q`, a match on a first line of a tree larger than a pipe
  #     buffer read as ABSENT, which let a shipped artifact carrying the
  #     scp-testing harness pass this gate. Each case below builds a tree past
  #     64 KB and asserts the probe's verdict.
  local padded probe_rc
  padded="$(for ((i = 0; i < 3000; i++)); do
    echo "|   +-- padding-crate-${i} v0.1.0 — widens this tree past a pipe buffer"
  done)"
  tree_names_scp_testing_crate "$(printf 'scp-testing v0.1.0\n%s' "$padded")"; probe_rc=$?
  expect "(SIGPIPE) scp-testing on a first line of a 200 KB tree is FOUND" "PASS" "$probe_rc"
  tree_names_scp_testing_crate "$(printf '%s\nscp-testing v0.1.0' "$padded")"; probe_rc=$?
  expect "(SIGPIPE) scp-testing on a last line of a 200 KB tree is FOUND" "PASS" "$probe_rc"
  tree_names_scp_testing_crate "$padded"; probe_rc=$?
  expect "(SIGPIPE) a tree carrying no scp-testing node is still reported ABSENT" "FAIL" "$probe_rc"
  tree_names_scp_testing_crate "$(printf 'my-scp-testing v0.1.0\n%s' "$padded")"; probe_rc=$?
  expect "(SIGPIPE) a crate whose name merely ends in scp-testing is not matched" "FAIL" "$probe_rc"

  # (extraction) The parse must report a feature cargo enabled, however it was
  #     enabled. A `feature "…"` pseudo-node exists only for a feature named on a
  #     dependency EDGE, and every nullifier double here is enabled instead by a
  #     package's own feature table (`scp-node/testing = ["scp-dht/testing", …]`),
  #     which printed no such node — so the edge grep this replaced resolved
  #     `-p scp-node --features testing` to zero offenders. These cases drive the
  #     parse with the `--prefix none -f "{f}|{p}"` shape cargo prints.
  local synthetic parsed
  synthetic="$(printf '%s\n' \
    'default,production-dht,testing|scp-dht v0.1.0-beta.2 (/w/crates/scp-dht)' \
    'encrypting,sqlite|scp-platform v0.1.0-beta.2 (/w/crates/scp-platform)' \
    '|scp-runtime v0.1.0-beta.2 (/w/crates/scp-runtime)' \
    'default,std|serde v1.0.0' \
    'default|scp-mls v0.1.0-beta.2 (/w/crates/scp-mls) (*)')"
  parsed="$(extract_resolved_features "$synthetic")"
  printf '%s\n' "$parsed" | grep -xF 'scp-dht/testing' >/dev/null; rc=$?
  expect "(extraction) a nullifier feature enabled through a package's own feature table is EXTRACTED" "PASS" "$rc"
  printf '%s\n' "$parsed" | grep -xF 'scp-mls/default' >/dev/null; rc=$?
  expect "(extraction) a deduplicated '(*)' node still contributes its features" "PASS" "$rc"
  printf '%s\n' "$parsed" | grep -E '^(serde|scp-runtime)/' >/dev/null; rc=$?
  expect "(extraction) a non-SCP node and a features-empty node contribute nothing" "FAIL" "$rc"
  check_subset "$parsed" "$PERMITTED_ALLOWLIST" >/dev/null 2>&1; rc=$?
  expect "(extraction) that parsed set is REJECTED by the ⊆ check" "FAIL" "$rc"

  # (live control) The same property against real cargo output, so a future
  #     change to the tree command or its format arguments cannot pass the
  #     synthetic cases while resolving a real nullifier build to a clean set.
  #     `-p scp-node --features testing` enables `scp-dht/testing` and
  #     `scp-platform/testing` through scp-node's own feature table, which is
  #     exactly the shape the replaced grep could not see.
  local live_resolved
  if live_resolved="$(resolve_scp_features "scp-node" "--features testing")"; then
    check_subset "$live_resolved" "$PERMITTED_ALLOWLIST" >/dev/null 2>&1; rc=$?
    expect "(live control) cargo resolving 'scp-node --features testing' yields a set the ⊆ check REJECTS" "FAIL" "$rc"
  else
    echo "   FAIL — (live control) cargo could not resolve 'scp-node --features testing'"
    fixture_failures=$((fixture_failures + 1))
  fi

  # (shipping-drift) packages_built_by_shipping_lines decides half 1 of the
  #     drift check, so these cases prove the declaration list suppresses ONLY
  #     the exact line a human declared. A blanket per-package suppression would
  #     let a later `cargo build -p scp-testing` reach a shipped artifact with no
  #     gate failure, which is the fail-open shape this whole gate exists to
  #     reject.
  local synthetic_lines declared_lines packages
  declared_lines="cargo nextest run --release -p scp-testing -E 'test(conformance)'"
  synthetic_lines="$(printf '%s\n' \
    '            cargo nextest run --release -p scp-testing -E '"'"'test(conformance)'"'"'' \
    'RUN cargo build --release -p scp-relay -p scp-node' \
    '          for pkg in scp-core scp-ffi scp-ffi-napi; do' \
    'echo not a cargo command at all')"
  packages="$(packages_built_by_shipping_lines "$synthetic_lines" "$declared_lines")"
  printf '%s\n' "$packages" | grep -xF 'scp-testing' >/dev/null; rc=$?
  expect "(shipping-drift) a declared non-shipping line contributes no package, whatever its indentation" "FAIL" "$rc"
  printf '%s\n' "$packages" | grep -xF 'scp-node' >/dev/null; rc=$?
  expect "(shipping-drift) an undeclared '-p' line still contributes its package" "PASS" "$rc"
  printf '%s\n' "$packages" | grep -xF 'scp-ffi-napi' >/dev/null; rc=$?
  expect "(shipping-drift) a 'for pkg in …;' loop contributes each package it lists" "PASS" "$rc"
  packages="$(packages_built_by_shipping_lines \
    "$(printf '%s\n%s\n' "$synthetic_lines" 'RUN cargo build --release -p scp-testing')" \
    "$declared_lines")"
  printf '%s\n' "$packages" | grep -xF 'scp-testing' >/dev/null; rc=$?
  expect "(shipping-drift) declaring one line does not suppress the same package on a DIFFERENT line" "PASS" "$rc"
  packages="$(packages_built_by_shipping_lines "$synthetic_lines" "")"
  printf '%s\n' "$packages" | grep -xF 'scp-testing' >/dev/null; rc=$?
  expect "(shipping-drift) an undeclared test invocation naming a package is REPORTED, so the list is load-bearing" "PASS" "$rc"

  assert_every_pipeline_reader_consumes_its_input

  assert_allowlist_has_no_nullifier

  assert_shipping_invocations_are_gated

  echo "-------------------------------------------------------------------------------"
  if [[ "$fixture_failures" -eq 0 ]]; then
    echo "FIXTURE HARNESS: all behavioral proofs passed."
    return 0
  fi
  echo "FIXTURE HARNESS: $fixture_failures behavioral proof(s) failed."
  return 1
}

# ---------------------------------------------------------------------------
main() {
  # Always run the fixture harness first — a broken gate must fail loud before it
  # can pass a real (possibly regressed) tree.
  run_fixtures || exit 1

  if [[ "${1:-}" == "--self-test" ]]; then
    echo "--self-test: skipping real workspace gate."
    exit 0
  fi

  echo
  if run_gate; then
    echo
    echo "G1 PASSED: every shipped artifact's SCP-crate feature set ⊆ this permitted-production allowlist (durability-only + real-backend, zero nullifier exceptions)."
    exit 0
  fi
  echo
  echo "G1 FAILED: a shipped artifact resolves a non-allowlisted (nullifier/test-harness)"
  echo "feature. Fix the dependency edge — do NOT add the feature to the allowlist."
  exit 1
}

main "$@"
