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
# CRITICAL: DEV-DEPENDENCIES ARE EXCLUDED (`no-dev`)
# --------------------------------------------------
# A shipped artifact is built WITHOUT dev-dependencies. `cargo tree` includes
# dev-deps by default (and feature-unifies their `testing` edges into the graph),
# which does NOT reflect what ships. The `no-dev` edge kind restricts the graph to
# the normal + build dependencies that actually compile into the artifact.
#
# CRITICAL: THIS GATE READS TWO CARGO RENDERINGS, NOT ONE
# -------------------------------------------------------
# `cargo tree -e features` renders a feature node for a feature a DEPENDENCY has
# activated, and renders none for a feature the tree's ROOT package activates
# through that package's own `[features]` table. The scp-node and scp-relay
# entries make the root package the artifact itself, so an extraction that read
# only that rendering could not see `crates/scp-node/Cargo.toml`'s own
# `testing = ["scp-dht/testing", "scp-platform/testing",
# "allow_unencrypted_storage"]` — the exact nullifier wiring those two entries
# were added to police — and printed OK for a build carrying all three features.
# Every default member is likewise a root of the bare default-members
# resolution. So both resolvers read the edge rendering AND
# `cargo tree -f '{p}|{f}'`, whose per-package list is each package's resolved
# ENABLED feature set, and check the UNION (merge_resolved_feature_sets).
# run_gate drives a live positive control — `-p scp-node --features testing`
# must FAIL the ⊆ check — so a rendering change that re-blinds either resolver
# fails this gate instead of quietly emptying it.
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
# NINE ROWS NAME A ROOT PACKAGE'S OWN PRODUCTION FEATURE. Each shipped build
# invocation activates a feature on the package it names with `-p`, and cargo
# renders that activation only in the per-package `{f}` list, never as a feature
# edge — so this gate could not see any of the nine until it began reading both
# renderings (see merge_resolved_feature_sets). Their classification:
#   - `scp-ffi/server`, `scp-ffi-napi/server`, `scp-ffi-uniffi/server` — the
#     feature each ARTIFACTS entry passes as `--features server`. Each expands to
#     `["scp-ffi-common/server", "dep:scp-node"]`, the real node/relay startup
#     path.
#   - `scp-ffi/default`, `scp-ffi-napi/default`, `scp-ffi-uniffi/default` — each
#     is `["server"]`, and a bare `cargo build` at this root resolves it for
#     those three default members.
#   - `scp-ffi-common/server` — pulls the real transport, node, platform, and
#     identity crates plus three durability-only `scp-platform` rows this list
#     already carries (`in-memory-storage`, `file`, `encrypting`).
#   - `scp-client-wasm/default` — an EMPTY feature list. Cargo reports `default`
#     as enabled on that default member and it activates nothing.
# None of the nine forwards a `testing` edge or an `allow_unencrypted_storage`
# edge; each such forward resolves as its own `crate/feature` pair that this list
# omits, so admitting a `default` row never admits what that default expands to.
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
# The three bridges resolve one SCP-crate feature set each, differing only in the
# `scp-ffi*/server` row naming the bridge itself (33 pairs); each binary resolves
# 25 pairs for scp-node and 19 for scp-relay. This single allowlist is therefore
# a SUPERSET covering all five — one list suffices. `cargo tree` DERIVES each
# artifact's resolved set (never a hand-list); this allowlist is the
# hand-maintained set of what is PERMITTED.
# ---------------------------------------------------------------------------
PERMITTED_ALLOWLIST="$(cat <<'EOF'
scp-client-wasm/default
scp-client/default
scp-clock/default
scp-core/default
scp-crypto/default
scp-dht/default
scp-dht/production-dht
scp-did/default
scp-event-log/default
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
scp-mcp/default
scp-media/default
scp-mls/default
scp-node/default
scp-platform/default
scp-platform/encrypting
scp-platform/file
scp-platform/in-memory-push
scp-platform/in-memory-storage
scp-platform/software_platform
scp-platform/sqlite
scp-protocol/default
scp-relay-client/default
scp-runtime/default
scp-transport/default
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
  "scp-node|"
  "scp-relay|"
)

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
  local edge_raw pkg_raw rc
  # Capture stdout+stderr and the exit status. Do NOT swallow a cargo failure
  # silently: if resolution fails (e.g. the feature args name a feature this
  # artifact lacks), surface the cargo error and return non-zero so the caller
  # fails loud instead of proceeding with an empty (vacuously-passing) set.
  # shellcheck disable=SC2086
  edge_raw="$(cargo tree -e features,no-dev -p "$crate" $features 2>&1)"; rc=$?
  if [[ "$rc" -ne 0 ]]; then
    { echo "cargo tree (feature edges) failed for '$crate' (feature args: '$features'):"
      printf '%s\n' "$edge_raw"; } >&2
    return 1
  fi
  # shellcheck disable=SC2086
  pkg_raw="$(cargo tree -e no-dev -p "$crate" $features -f '{p}|{f}' 2>&1)"; rc=$?
  if [[ "$rc" -ne 0 ]]; then
    { echo "cargo tree (per-package feature lists) failed for '$crate' (feature args: '$features'):"
      printf '%s\n' "$pkg_raw"; } >&2
    return 1
  fi
  merge_resolved_feature_sets "$edge_raw" "$pkg_raw"
}

# ---------------------------------------------------------------------------
# extract_feature_edges <cargo-tree-output>
#   Emit one `crate/feature` per line for every FEATURE EDGE that `cargo tree
#   -e features` renders — a line of the form `scp-<crate> feature "<name>"`.
#
#   WHAT THIS RENDERING CANNOT SEE: cargo renders a feature node for a feature
#   a DEPENDENCY has activated. It renders none for a feature the tree's ROOT
#   package activates through that package's own `[features]` table. Running
#   `cargo tree -e features,no-dev -p scp-node --features testing` on this
#   workspace prints the string `testing` zero times, and the set this function
#   extracts from that tree is byte-identical to the set it extracts without
#   `--features testing`. extract_package_features below reads the second
#   rendering, which does carry those features, and
#   merge_resolved_feature_sets unions the two.
# ---------------------------------------------------------------------------
extract_feature_edges() {
  printf '%s\n' "$1" \
    | grep -oE 'scp-[a-z0-9-]+ feature "[^"]+"' \
    | sed -E 's/ feature "/\//; s/"$//' \
    | sort -u
}

# ---------------------------------------------------------------------------
# extract_package_features <cargo-tree-output-rendered-as-{p}|{f}>
#   Emit one `crate/feature` per line for every feature ENABLED on every scp-*
#   package the tree names, THE ROOT PACKAGE INCLUDED. `cargo tree -f '{p}|{f}'`
#   prints, per package, `<name> v<version> (<path>)|<f1>,<f2>,…`, where that
#   list is the package's resolved enabled feature set rather than an edge its
#   parent declared. That is the only cargo rendering in which an artifact's OWN
#   `testing` / `allow_unencrypted_storage` activation appears.
#
#   This splits the comma list in a bash `while` loop rather than in a pipe into
#   `awk`, because assert_every_pipeline_reader_consumes_its_input decides its
#   criterion by enumerating the commands this file pipes into, and a bash loop
#   reads its whole input by construction, so splitting here adds no command to
#   that enumeration. The two `sed` stages and the closing `sort -u` each read to
#   end of file.
# ---------------------------------------------------------------------------
extract_package_features() {
  local normalized name feats feature
  # Strip cargo's tree-drawing prefix and its ` (*)` already-shown marker, keep
  # only scp-* package lines, and reduce each to `<name>|<f1>,<f2>,…`.
  normalized="$(printf '%s\n' "$1" \
    | sed -E 's/^[^A-Za-z0-9_]*//; s/ \(\*\)[[:space:]]*$//' \
    | sed -E -n 's/^(scp-[a-z0-9-]+) v.*\|(.*)$/\1|\2/p' \
    | sort -u)"
  while IFS='|' read -r name feats; do
    [[ -z "$name" ]] && continue
    while [[ -n "$feats" ]]; do
      feature="${feats%%,*}"
      if [[ "$feats" == *,* ]]; then feats="${feats#*,}"; else feats=""; fi
      [[ -n "$feature" ]] && printf '%s/%s\n' "$name" "$feature"
    done
  done <<<"$normalized" | sort -u
}

# ---------------------------------------------------------------------------
# merge_resolved_feature_sets <edge-tree> <package-feature-tree>
#   Emit the UNION of both renderings, sorted-unique — one artifact's complete
#   resolved SCP-crate feature set.
#
#   Each rendering carries what the other omits, so this gate reads both and
#   neither alone:
#     - the edge rendering names a `default` edge on a crate that declares no
#       `default` feature (`scp-core feature "default"`, for one), which the
#       per-package rendering reports as an empty feature list;
#     - the per-package rendering names every feature the ROOT package activates
#       through its own `[features]` table, which the edge rendering omits.
#   That second omission made this gate vacuous on the two artifacts whose root
#   package IS the artifact — scp-node and scp-relay — for exactly the
#   activation the gate exists to reject: `crates/scp-node/Cargo.toml` declares
#   `testing = ["scp-dht/testing", "scp-platform/testing",
#   "allow_unencrypted_storage"]`, and the edge-only extraction returned the same
#   set with and without that feature. run_gate now drives a live positive
#   control over this function to prove the union sees it.
#
#   Returns 1 when EITHER rendering yields an empty set. Both legitimately yield
#   a non-empty set for every artifact this gate checks and for a bare
#   default-members build, so an empty one means cargo resolved nothing or a
#   rendering changed shape. Either way the caller fails loud rather than accept
#   a half-empty union.
# ---------------------------------------------------------------------------
merge_resolved_feature_sets() {
  local edge_tree="$1" pkg_tree="$2" edges pkgs
  edges="$(extract_feature_edges "$edge_tree" || true)"
  pkgs="$(extract_package_features "$pkg_tree" || true)"
  if [[ -z "$edges" ]]; then
    echo "no scp-* feature EDGE appears in a cargo tree this gate resolved" >&2
    return 1
  fi
  if [[ -z "$pkgs" ]]; then
    echo "no scp-* PER-PACKAGE feature list appears in a cargo tree this gate resolved" >&2
    return 1
  fi
  printf '%s\n%s\n' "$edges" "$pkgs" | sort -u
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
#
#   EVERY DEFAULT MEMBER IS A ROOT PACKAGE of this resolution, so the feature-edge
#   rendering alone omits every feature each member activates through its own
#   `[features]` table — the same blindness merge_resolved_feature_sets
#   describes. This function therefore reads both renderings and unions them
#   through that one merge helper, as resolve_scp_features does.
# ---------------------------------------------------------------------------
resolve_default_members_features() {
  local edge_raw pkg_raw rc
  edge_raw="$(cargo tree -e features,no-dev 2>&1)"; rc=$?
  if [[ "$rc" -ne 0 ]]; then
    { echo "cargo tree (feature edges) failed for a bare default-members resolution:"
      printf '%s\n' "$edge_raw"; } >&2
    return 1
  fi
  pkg_raw="$(cargo tree -e no-dev -f '{p}|{f}' 2>&1)"; rc=$?
  if [[ "$rc" -ne 0 ]]; then
    { echo "cargo tree (per-package feature lists) failed for a bare default-members resolution:"
      printf '%s\n' "$pkg_raw"; } >&2
    return 1
  fi
  merge_resolved_feature_sets "$edge_raw" "$pkg_raw"
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

  # LIVE POSITIVE CONTROL — this gate must be able to SEE a nullifier that this
  # workspace can actually activate on a shipped artifact.
  #
  # CRITERION: resolving a shipped artifact with a nullifier feature turned on
  # produces a set the ⊆ check REJECTS. Every OK printed above means "this
  # artifact resolves no nullifier feature"; it means that only while the
  # resolver can report one at all. `crates/scp-node/Cargo.toml` declares
  # `testing = ["scp-dht/testing", "scp-platform/testing",
  # "allow_unencrypted_storage"]`, so `-p scp-node --features testing` is the
  # nearest real build to the shipped `scp-node` entry that carries nullifiers.
  #
  # The fixtures prove the same property on synthetic trees; this control proves
  # it against cargo's live rendering, so a future cargo release that changes
  # either rendering fails this gate instead of silently emptying it.
  echo ">> positive control  (scp-node --features testing — a resolution this gate MUST reject)"
  local pc_resolved
  if ! pc_resolved="$(resolve_scp_features "scp-node" "--features testing")"; then
    echo "   FAIL — resolving scp-node with --features testing errored. This gate"
    echo "          cannot demonstrate that it observes a nullifier feature, so"
    echo "          every OK above is unproven. Restore that feature, or point"
    echo "          this control at another artifact whose own [features] table"
    echo "          activates a nullifier."
    failures=$((failures + 1))
  elif check_subset "$pc_resolved" "$PERMITTED_ALLOWLIST" >/dev/null; then
    echo "   FAIL — scp-node built with its own \`testing\` feature resolved a set"
    echo "          this allowlist ACCEPTS. The resolver is blind to the features"
    echo "          an artifact's ROOT package activates through its own"
    echo "          [features] table, so every OK printed above proves nothing."
    echo "          Fix resolve_scp_features — do NOT delete this control."
    failures=$((failures + 1))
  else
    echo "   OK — that resolution is REJECTED, so this gate observes a nullifier"
    echo "        an artifact's own [features] table activates"
  fi

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

# expect_lines <label> <expected-lines> <actual-lines>
#   Compare two newline-separated sets exactly. Used by the root-package
#   fixtures below, which assert WHICH pairs an extractor emits rather than only
#   that it emitted something.
expect_lines() {
  local label="$1" expected="$2" actual="$3"
  if [[ "$expected" == "$actual" ]]; then
    echo "   ok   — $label"
    return
  fi
  echo "   FAIL — $label"
  echo "          expected:"
  printf '%s\n' "$expected" | sed 's/^/            /'
  echo "          actual:"
  printf '%s\n' "$actual" | sed 's/^/            /'
  fixture_failures=$((fixture_failures + 1))
}

# assert_root_package_features_are_extracted
#   The regression this gate shipped with, proved on synthetic input.
#
#   CRITERION: for an artifact whose ROOT package activates a nullifier feature
#   through that package's own `[features]` table, the resolved set this gate
#   checks names that feature, and check_subset rejects the set.
#
#   `cargo tree -e features` renders a feature node only for a feature a
#   DEPENDENCY has activated, so the root package's own activations appear
#   nowhere in that tree. The two synthetic trees below are that exact shape: the
#   edge tree names no `testing` feature at all, and the per-package tree names
#   `scp-node|allow_unencrypted_storage,testing`. Under the edge-only extraction
#   this gate shipped with, the first assertion passed and the ⊆ check returned
#   OK on a graph carrying three nullifier features.
assert_root_package_features_are_extracted() {
  echo ">> fixture: an artifact's ROOT package activating its own testing/allow_unencrypted_storage feature is EXTRACTED and REJECTED (the edge rendering alone cannot see it)"
  local edge_tree pkg_tree edges pkgs merged rc

  # What `cargo tree -e features,no-dev -p scp-node --features testing` prints:
  # feature nodes for DEPENDENCY activations only, and no `testing` anywhere.
  edge_tree="$(cat <<'TREE'
scp-node v0.1.0-beta.2 (/w/crates/scp-node)
├── scp-core feature "default"
│   └── scp-core v0.1.0-beta.2 (/w/crates/scp-core)
└── scp-platform feature "sqlite"
    └── scp-platform v0.1.0-beta.2 (/w/crates/scp-platform)
TREE
)"
  # What `cargo tree -e no-dev -p scp-node --features testing -f '{p}|{f}'`
  # prints for the same resolution: per-package ENABLED feature lists, root
  # included, with cargo's ` (*)` already-shown marker on a repeat node and an
  # empty list on a crate that has no features.
  pkg_tree="$(cat <<'TREE'
scp-node v0.1.0-beta.2 (/w/crates/scp-node)|allow_unencrypted_storage,testing
├── scp-core v0.1.0-beta.2 (/w/crates/scp-core)|default
├── scp-platform v0.1.0-beta.2 (/w/crates/scp-platform)|sqlite,testing (*)
└── scp-clock v0.1.0-beta.2 (/w/crates/scp-clock)|
TREE
)"

  edges="$(extract_feature_edges "$edge_tree")"
  expect_lines "the edge rendering of that resolution names NO root-package feature" \
    "$(printf 'scp-core/default\nscp-platform/sqlite')" "$edges"

  # An edge-only resolved set passes the ⊆ check — the vacuous verdict this
  # gate returned for scp-node and scp-relay.
  check_subset "$edges" "$PERMITTED_ALLOWLIST" >/dev/null 2>&1; rc=$?
  expect "(root-blind) the edge-only set of a nullifier-carrying scp-node build is ACCEPTED, which is why the edge rendering cannot be this gate's only input" "PASS" "$rc"

  pkgs="$(extract_package_features "$pkg_tree")"
  expect_lines "the per-package rendering names the root's own features, drops cargo's (*) marker, and emits nothing for a crate with no features" \
    "$(printf 'scp-core/default\nscp-node/allow_unencrypted_storage\nscp-node/testing\nscp-platform/sqlite\nscp-platform/testing')" \
    "$pkgs"

  merged="$(merge_resolved_feature_sets "$edge_tree" "$pkg_tree")"
  expect_lines "the union carries every pair from both renderings" \
    "$(printf 'scp-core/default\nscp-node/allow_unencrypted_storage\nscp-node/testing\nscp-platform/sqlite\nscp-platform/testing')" \
    "$merged"

  check_subset "$merged" "$PERMITTED_ALLOWLIST" >/dev/null 2>&1; rc=$?
  expect "(root-blind) the union of both renderings is REJECTED for that same build" "FAIL" "$rc"

  # A half-empty union means cargo resolved nothing or a rendering changed
  # shape. Accepting it would hand run_gate a set drawn from one rendering while
  # the message says both — so the merge fails loud instead.
  merge_resolved_feature_sets "" "$pkg_tree" >/dev/null 2>&1; rc=$?
  expect "(root-blind) an empty EDGE rendering fails the merge loud" "FAIL" "$rc"
  merge_resolved_feature_sets "$edge_tree" "" >/dev/null 2>&1; rc=$?
  expect "(root-blind) an empty PER-PACKAGE rendering fails the merge loud" "FAIL" "$rc"
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

  assert_root_package_features_are_extracted

  assert_every_pipeline_reader_consumes_its_input

  assert_allowlist_has_no_nullifier

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
