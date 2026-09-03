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
# CRITICAL: EVERY SHIPPED TARGET TRIPLE IS RESOLVED (`--target all`)
# -----------------------------------------------------------------
# Without `--target`, cargo evaluates every `[target.'cfg(…)'.dependencies]`
# table against the triple the runner happens to compile for, and DISCARDS every
# edge whose cfg is false there. This job runs on `ubuntu-latest`, which resolves
# x86_64-unknown-linux-gnu, while `.github/workflows/build-matrix.yml` builds the
# three gated bridges for aarch64-apple-ios, aarch64-apple-ios-sim,
# x86_64-apple-ios, aarch64-apple-darwin, x86_64-apple-darwin,
# x86_64-pc-windows-msvc and aarch64-unknown-linux-gnu, and
# `.github/workflows/release.yml` Authenticode-signs the Windows DLL and
# Apple-signs the iOS/macOS framework. A `[target.'cfg(target_os = "ios")'
# .dependencies]` table naming `scp-platform = { features = ["testing"] }` is
# therefore invisible to a host-triple resolution and compiles three §17.17.2
# security nullifiers into a signed xcframework. Four workspace crates already
# carry such a table (scp-protocol, scp-mls, scp-client, scp-client-wasm, all on
# `cfg(target_arch = "wasm32")`), so the construct is in use here today.
# `--target all` resolves the UNION over every triple rather than an enumeration
# of the triples anyone remembered to list, so a triple added to a build matrix
# tomorrow is covered without editing this gate. Measured on this tree, the union
# and the host resolution agree row for row on all five artifacts, so `--target
# all` costs no false rejection.
#
# CRITICAL: A PACKAGE'S OWN `[features]` TABLE IS READ (`--format '{p}|{f}'`)
# --------------------------------------------------------------------------
# `cargo tree -e features` prints a feature edge for a feature a package requests
# THROUGH A DEPENDENCY DECLARATION, and prints NO edge for a feature the ROOT
# package of the invocation activates through its own `[features]` table. So
# `cargo tree -e features,no-dev -p scp-node` emits no `scp-dht feature
# "testing"` row when `crates/scp-node/Cargo.toml` says `default = ["testing"]`,
# even though that manifest compiles `InMemoryDhtClient`,
# `InMemoryKeyCustody`/`InMemoryDeviceAttestation` and
# `ProtocolRepository::new_for_testing` into the shipped binary. The two binary
# artifacts are exactly the entries with no parent package to declare them, so
# the feature-edge grep alone left both of them unable to fail for the edit they
# were added to catch. `cargo tree -e no-dev --format '{p}|{f}'` prints each
# resolved package's COMPLETE enabled-feature set, root package included, so the
# union of the two extractions sees a nullifier wherever a manifest turns it on.
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
# Each artifact's resolved set is the UNION of two derivations: the feature EDGES
# a parent declaration requests, and each resolved SCP package's OWN enabled
# features. Measured on this tree, that union is 33 rows for each of the three
# bridges (31 edges ∪ 22 package rows), 25 for scp-node and 19 for scp-relay, and
# each binary's set is a subset of a bridge's.
# This single allowlist is therefore a SUPERSET covering all five — one list
# suffices. `cargo tree` DERIVES each artifact's resolved set (never a hand-list);
# this allowlist is the hand-maintained set of what is PERMITTED.
# ---------------------------------------------------------------------------
#
# Eight rows below became RESOLVED, rather than newly permitted, when this gate
# started reading each package's own `[features]` table: `scp-client-wasm/default`
# (an empty list), the three bridges' `default` (each `["server"]`), the three
# bridges' `server`, and `scp-ffi-common/server`. `server` is the production
# bridge configuration every ARTIFACTS entry already builds with, and it forwards
# `scp-platform/in-memory-storage`, `scp-platform/file` and
# `scp-platform/encrypting` — three durability-only rows already on this list
# (spec §17.17.2). No bridge `testing` row appears, and
# NULLIFIER_CONTROL_FEATURES now names all four bridge `testing` features plus
# `scp-node/testing`, so the hygiene fixture rejects an edit that adds one.
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
  "scp-event-log/testing"
  "scp-identity/testing"
  "scp-testing"
  # A package's own `[features]` table reaches this gate only since it started
  # reading `cargo tree --format '{p}|{f}'`, so these five names became
  # observable rows rather than staying invisible. Each bridge `testing` feature
  # folds in `scp-platform/testing` + `scp-dht/testing` + `dep:scp-testing`, and
  # `scp-node/testing` folds in `scp-dht/testing` + `scp-platform/testing` +
  # `allow_unencrypted_storage`. Naming them here makes the allowlist-hygiene
  # fixture reject an edit that puts any of them on the allowlist to silence a
  # newly-visible failure.
  "scp-ffi/testing"
  "scp-ffi-common/testing"
  "scp-ffi-napi/testing"
  "scp-ffi-uniffi/testing"
  "scp-node/testing"
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
  raw="$(cargo tree -e features,no-dev --target all -p "$crate" $features 2>&1)"; rc=$?
  if [[ "$rc" -ne 0 ]]; then
    { echo "cargo tree failed for '$crate' (feature args: '$features'):"
      printf '%s\n' "$raw"; } >&2
    return 1
  fi
  printf '%s\n' "$raw" \
    | grep -oE 'scp-[a-z0-9-]+ feature "[^"]+"' \
    | sed -E 's/ feature "/\//; s/"$//' \
    | sort -u
}

# ---------------------------------------------------------------------------
# scp_features_from_package_lines <cargo-tree --format '{p}|{f}' output>
#   Emit one `crate/feature` line per SCP-crate enabled feature, sorted-unique.
#   Pure: takes the tree text, runs no cargo, so the fixture harness drives it
#   with synthetic input.
#
#   Each input line reads `<name> v<version> (<source>)|<f1>,<f2>,…`, and cargo
#   appends ` (*)` to a line whose subtree it already printed. `{f}` is the
#   package's COMPLETE enabled-feature set, which is why this parser sees a
#   feature a package turns on in its OWN `[features]` table — the case
#   `cargo tree -e features` prints no edge for.
#
#   The `v` in the `^scp-[a-z0-9-]+ v` anchor is what separates a package name
#   from a package whose name merely starts with one (`scp-node-extras v…` does
#   not match `^scp-node v`), and the leading `^` is what stops a nested tree
#   line from matching — `--prefix none` is therefore load-bearing at the call
#   sites, not cosmetic.
# ---------------------------------------------------------------------------
scp_features_from_package_lines() {
  printf '%s\n' "$1" \
    | sed -E 's/ \(\*\)$//' \
    | grep -E '^scp-[a-z0-9-]+ v' \
    | sed -E 's/^(scp-[a-z0-9-]+) v.*\|/\1|/' \
    | awk -F'|' '$2 != "" { n = split($2, f, ","); for (i = 1; i <= n; i++) print $1 "/" f[i] }' \
    | sort -u
}

# resolve_scp_package_features <crate> <features...>
#   Emit the COMPLETE enabled-feature set of every SCP package in the shipped
#   (no-dev, all-target) graph, INCLUDING the root package's own features.
#
#   DELIBERATE SPLIT from resolve_scp_features (NOT a redundant twin): that
#   function extracts feature EDGES a parent declaration requests, and cargo
#   prints no such edge for a feature the root package activates through its own
#   `[features]` table. `crates/scp-node/Cargo.toml` carries `testing =
#   ["scp-dht/testing", "scp-platform/testing", "allow_unencrypted_storage"]`,
#   and a `default = ["testing"]` added beside it resolved, through the edge grep
#   alone, to a set the ⊆ check ACCEPTED. This probe reports
#   `scp-node/testing`, `scp-dht/testing`, `scp-platform/testing` and three
#   `allow_unencrypted_storage` rows for that same manifest. Both extractions are
#   load-bearing; run_gate takes their union.
resolve_scp_package_features() {
  local crate="$1"; shift
  local features="$1"
  local raw rc
  # shellcheck disable=SC2086
  raw="$(cargo tree -e no-dev --target all -p "$crate" $features --prefix none --format '{p}|{f}' 2>&1)"; rc=$?
  if [[ "$rc" -ne 0 ]]; then
    { echo "cargo tree (package-feature probe) failed for '$crate' (feature args: '$features'):"
      printf '%s\n' "$raw"; } >&2
    return 1
  fi
  scp_features_from_package_lines "$raw"
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
  raw="$(cargo tree -e no-dev --target all -p "$crate" $features 2>&1)"; rc=$?
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
#   set (33 union rows for each bridge, 25 for scp-node, 19 for scp-relay), and
#   each of the two derivations run_gate unions is non-empty on its own, so
#   run_gate applies this predicate to each one separately. An empty result from
#   either means cargo resolution failed or the feature args are wrong. Returns 0
#   if the resolved set is non-empty, 1 if empty. Factored out as a pure
#   predicate so the fixture harness can drive it directly.
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
  raw="$(cargo tree -e features,no-dev --target all 2>&1)"; rc=$?
  if [[ "$rc" -ne 0 ]]; then
    { echo "cargo tree failed for a bare default-members resolution:"
      printf '%s\n' "$raw"; } >&2
    return 1
  fi
  printf '%s\n' "$raw" \
    | grep -oE 'scp-[a-z0-9-]+ feature "[^"]+"' \
    | sed -E 's/ feature "/\//; s/"$//' \
    | sort -u
}

# resolve_default_members_package_features
#   Emit the COMPLETE enabled-feature set of every SCP package a bare
#   `cargo build` at this root resolves, each default member's own
#   `[features]`-table activations included. Mirrors resolve_scp_package_features
#   for the union invocation: a default member that no other member depends on
#   (crates/scp-relay is one — no package declares it as a dependency) has no
#   parent declaration to print a feature edge, so the edge grep alone cannot see
#   a nullifier that member turns on in its own manifest.
resolve_default_members_package_features() {
  local raw rc
  raw="$(cargo tree -e no-dev --target all --prefix none --format '{p}|{f}' 2>&1)"; rc=$?
  if [[ "$rc" -ne 0 ]]; then
    { echo "cargo tree (package-feature probe) failed for a bare default-members resolution:"
      printf '%s\n' "$raw"; } >&2
    return 1
  fi
  scp_features_from_package_lines "$raw"
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
  raw="$(cargo tree -e no-dev --target all 2>&1)"; rc=$?
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
    # Fold in each SCP package's OWN enabled features. `cargo tree -e features`
    # prints no edge for a feature the root package of this invocation activates
    # through its own `[features]` table, and the two binaries are exactly the
    # entries with no parent package to declare one, so without this union
    # neither could fail for a `default = ["testing"]` added to its manifest.
    local pkg_features
    if ! pkg_features="$(resolve_scp_package_features "$crate" "$features")" \
        || ! resolution_is_nonempty "$pkg_features"; then
      echo "   FAIL — the package-feature probe returned EMPTY (cargo resolution"
      echo "          failed, or the feature args are wrong). Every shipped"
      echo "          artifact resolves a NON-EMPTY per-package feature set;"
      echo "          refusing to read an empty probe as 'no features enabled'."
      failures=$((failures + 1))
      continue
    fi
    resolved="$(printf '%s\n%s' "$resolved" "$pkg_features")"

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
  echo ">> default-members  (a bare 'cargo build' at this workspace root)"
  local dm_resolved dm_offenders dm_testing dm_pkg_features
  if ! dm_resolved="$(resolve_default_members_features)" \
      || ! resolution_is_nonempty "$dm_resolved"; then
    echo "   FAIL — resolved SCP-crate feature set is EMPTY (cargo resolution"
    echo "          failed). A default-members build legitimately resolves a"
    echo "          NON-EMPTY set; refusing to treat an empty resolution as"
    echo "          'empty ⊆ allowlist' PASS."
    failures=$((failures + 1))
  elif ! dm_pkg_features="$(resolve_default_members_package_features)" \
      || ! resolution_is_nonempty "$dm_pkg_features"; then
    echo "   FAIL — the package-feature probe returned EMPTY for a bare"
    echo "          default-members resolution (cargo resolution failed);"
    echo "          refusing to read an empty probe as 'no features enabled'."
    failures=$((failures + 1))
  elif ! dm_testing="$(resolve_default_members_testing_crate)"; then
    echo "   FAIL — scp-testing presence probe failed (cargo resolution error);"
    echo "          refusing to read a probe failure as 'no nullifier crate present'."
    failures=$((failures + 1))
  else
    dm_resolved="$(printf '%s\n%s' "$dm_resolved" "$dm_pkg_features")"
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

# assert_every_cargo_tree_resolves_every_target
#   Structural proof that no dependency-graph absence proof under scripts/ reads
#   one host triple.
#
#   CRITERION: every `cargo tree` invocation in every shell script under
#   scripts/ names `--target all`. Without it cargo evaluates each
#   `[target.'cfg(…)'.dependencies]` table against the triple the runner
#   compiles for and DISCARDS every edge whose cfg is false there, so a
#   dependency added under `cfg(target_os = "ios")` is absent from a graph
#   resolved on ubuntu-latest while `.github/workflows/build-matrix.yml` compiles
#   it into a signed xcframework.
#
#   The criterion is decidable over these files because bash starts a command
#   word at a line start, or after `$(`, a backtick, `|`, `;`, or `&`, and this
#   fixture matches `cargo` at each of those positions. It covers
#   scripts/check-protocol-deps.sh as well as this file: that gate proves
#   scp-protocol depends on no tokio / scp-platform / openmls, and
#   crates/scp-protocol/Cargo.toml already carries a
#   `[target.'cfg(target_arch = "wasm32")'.dependencies]` table, so the same
#   host-triple blindness would hide a banned crate declared under a cfg.
assert_every_cargo_tree_resolves_every_target() {
  echo ">> fixture: every cargo tree invocation under scripts/ names --target all, so no cfg-gated dependency edge is invisible to an absence proof"
  local script offenders all_offenders="" cmd_word
  cmd_word='(^|[`;&|]|\$\()[[:space:]]*cargo[[:space:]]+tree[[:space:]]'
  while IFS= read -r script; do
    offenders="$(grep -nE "$cmd_word" "$script" \
      | grep -vE '^[0-9]+:[[:space:]]*#' \
      | grep -vF -e '--target all' || true)"
    if [[ -n "$offenders" ]]; then
      all_offenders="$(printf '%s\n%s' "$all_offenders" \
        "$(printf '%s\n' "$offenders" | sed "s|^|${script}:|")")"
    fi
  done < <(find scripts -type f -name '*.sh' | sort)
  if [[ -n "${all_offenders//[[:space:]]/}" ]]; then
    echo "   FAIL — a cargo tree invocation below resolves only the runner's host"
    echo "          triple, so every cfg-gated dependency edge that is false there"
    echo "          is absent from a graph this repository reads as proof:"
    printf '%s\n' "$all_offenders" | sed 's/^/       x /'
    echo "          Add '--target all' so cargo resolves the union over every triple."
    fixture_failures=$((fixture_failures + 1))
    return
  fi
  echo "   ok   — every cargo tree invocation under scripts/ resolves every target triple"
}

# assert_package_feature_parser_reads_a_root_packages_own_features
#   Behavioral proof for scp_features_from_package_lines, driven with synthetic
#   `cargo tree --format '{p}|{f}'` text so it runs no cargo.
#
#   The first input line is the regression this parser exists for: `cargo tree -e
#   features` prints NO feature edge for a feature the root package activates in
#   its own `[features]` table, so a `default = ["testing"]` in
#   crates/scp-node/Cargo.toml resolved, through the edge grep alone, to a set
#   the ⊆ check accepted. The remaining lines assert the four ways this parser
#   must not over-report: a `(*)` dedupe marker is not a feature, a package with
#   no enabled features contributes no row, a non-SCP package contributes none,
#   and neither a package whose name merely ends in an SCP crate name nor an
#   indented subtree line is read as an SCP package.
assert_package_feature_parser_reads_a_root_packages_own_features() {
  echo ">> fixture: the package-feature parser reports a root package's own [features]-table activations, the case cargo tree -e features prints no edge for"
  local input expected actual
  input="$(cat <<'FIXTURE'
scp-node v0.1.0-beta.2 (/w/crates/scp-node)|allow_unencrypted_storage,default,testing
scp-dht v0.1.0-beta.2 (/w/crates/scp-dht)|default,production-dht,testing (*)
scp-crypto v0.1.0-beta.2 (/w/crates/scp-crypto)|
tokio v1.47.1|full,rt
my-scp-node v0.1.0 (/w/vendor)|testing
|   +-- scp-platform v0.1.0-beta.2 (/w/crates/scp-platform)|testing
FIXTURE
)"
  expected="$(cat <<'FIXTURE'
scp-dht/default
scp-dht/production-dht
scp-dht/testing
scp-node/allow_unencrypted_storage
scp-node/default
scp-node/testing
FIXTURE
)"
  actual="$(scp_features_from_package_lines "$input")"
  if [[ "$actual" == "$expected" ]]; then
    echo "   ok   — parser emitted the six expected rows and no other"
  else
    echo "   FAIL — parser output does not match the expected rows."
    echo "          expected:"; printf '%s\n' "$expected" | sed 's/^/            /'
    echo "          actual:"; printf '%s\n' "$actual" | sed 's/^/            /'
    fixture_failures=$((fixture_failures + 1))
  fi
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
            "scp-runtime/allow_unencrypted_storage" \
            "scp-node/testing" "scp-ffi/testing" "scp-ffi-napi/testing" \
            "scp-ffi-uniffi/testing" "scp-ffi-common/testing"; do
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

  assert_every_pipeline_reader_consumes_its_input

  assert_every_cargo_tree_resolves_every_target

  assert_package_feature_parser_reads_a_root_packages_own_features

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
