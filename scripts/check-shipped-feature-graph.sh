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
# CRITICAL: DEV-DEPENDENCIES ARE EXCLUDED (`-e no-dev`)
# -----------------------------------------------------
# A shipped artifact is built WITHOUT dev-dependencies. `cargo tree` includes
# dev-deps by default (and feature-unifies their `testing` edges into the graph),
# which does NOT reflect what ships. The `no-dev` edge kind restricts the graph to
# the normal + build dependencies that actually compile into the artifact.
#
# CRITICAL: READ CARGO'S RESOLVED FEATURE LIST, NOT THE FEATURE-EDGE TREE
# ----------------------------------------------------------------------
# This gate reads each package's resolved feature list out of
# `cargo tree --format '{p}|{f}'`, where `{f}` prints the features cargo actually
# enabled for that package. It does NOT read the feature-edge tree that
# `cargo tree -e features` draws, because that tree omits an entire class of
# activation: a package's OWN `[features]` table activating a feature on one of
# its dependencies. `cargo tree -e features -p X` roots its display at the
# package node of X, while the edges X's feature table contributes hang off X's
# feature nodes (`X feature "testing"`), which are not in that displayed subtree.
# Measured on this tree: with `default = ["testing"]` added to
# `crates/scp-node/Cargo.toml`, `cargo tree -e features,no-dev -p scp-node`
# printed ZERO lines containing `testing` while `--format '{p}|{f}'` printed
# `scp-dht|default,production-dht,testing` and
# `scp-node|allow_unencrypted_storage,default,testing`. The same blindness held
# for a CLI-supplied feature: `-p scp-node --features quic` pulled `quinn` into
# the crate graph (25 lines) and still drew no `scp-transport feature "quic"`
# edge, and it held for every bridge — `-p scp-ffi --no-default-features
# --features server` drew no `scp-ffi-common feature "server"` edge although
# `server = ["scp-ffi-common/server", "dep:scp-node"]` in
# `crates/scp-ffi/Cargo.toml` activates it.
#
# Every ARTIFACTS entry below is exposed to that class, and the two binaries are
# exposed to it entirely: `scp-node` and `scp-relay` are gated with an empty
# feature-arg string, so their whole nullifier exposure runs through their own
# manifests. The scp-node leak above still failed the run, because
# `crates/scp-ffi` depends on scp-node and the three bridge entries resolved it
# transitively. No package outside scp-relay depends on scp-relay, so scp-relay
# had no such incidental catch: a `default = ["scp-transport/local-cache"]`
# planted in `crates/scp-relay/Cargo.toml` passed the feature-edge reader's
# scp-relay entry, passed its default-members check, and printed
# `G1 PASSED`.
#
# `assert_resolver_sees_own_feature_table_activation` in `run_gate` is the
# positive control that keeps this file on the resolved-list reader: it fails the
# gate if the resolver stops reporting `scp-ffi-common/server`, an activation a
# feature-edge reader cannot see.
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
# `scp-ffi/server`, `scp-ffi-napi/server`, `scp-ffi-uniffi/server` and
# `scp-ffi-common/server` are the production bridge feature this gate itself
# builds each bridge with (`--no-default-features --features server`): it wires
# the shared relay/node startup code into the bridge and compiles no test double.
# They are on this allowlist because the resolved-list reader described in the
# header now SEES a bridge's own `[features]` table activating them; the
# feature-edge reader this gate used before never reported them.
#
# `scp-ffi/default`, `scp-ffi-napi/default`, `scp-ffi-uniffi/default` and
# `scp-client-wasm/default` are what a bare `cargo build` at this root enables on
# those default members, which the default-members check below resolves. The
# three bridge rows expand to `["server"]` and the wasm row expands to `[]`.
# Permitting a `default` row admits nothing beyond its expansion: the reader
# reports cargo's RESOLVED list, so every feature `default` pulls in appears as
# its own row and meets this ⊆ check on its own. Adding a nullifier to any of
# those four `default` lists would surface that nullifier here and FAIL.
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
# resolves a SUBSET of it (scp-node ~17, scp-relay ~11 SCP-crate features).
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
# parse_resolved_features <cargo-tree-output>
#   Turn `cargo tree --prefix none --format '{p}|{f}'` output into one
#   `crate/feature` line per enabled feature of every SCP workspace crate,
#   sorted-unique. `{p}` prints `<name> v<version> (<path>)` and `{f}` prints the
#   comma-separated feature list cargo resolved FOR THAT PACKAGE, so a feature a
#   package's own `[features]` table activated on a dependency appears here — the
#   activation class the feature-edge tree omits (see the header).
#
#   Pure: takes text, writes text, calls no cargo. run_fixtures drives it with
#   synthetic input, so the parse is asserted without a workspace.
#
#   Reads its input with a bash `while read` loop rather than `awk`, so the
#   commands this file pipes into stay `grep`, `sed`, `sort` and `comm` — the
#   closed set `assert_every_pipeline_reader_consumes_its_input` decides its
#   criterion over.
# ---------------------------------------------------------------------------
parse_resolved_features() {
  local raw="$1" normalized pkg feats feature
  # Strip cargo's ` (*)` deduplication marker, keep only SCP workspace packages,
  # and reduce `<name> v<version> (<path>)|<features>` to `<name>|<features>`.
  normalized="$(printf '%s\n' "$raw" \
    | sed -E 's/ \(\*\)$//' \
    | sed -E -n 's/^(scp-[a-z0-9-]+) v[^|]*\|/\1|/p')"
  while IFS='|' read -r pkg feats; do
    [[ -n "$pkg" && -n "$feats" ]] || continue
    local -a enabled=()
    IFS=',' read -ra enabled <<< "$feats"
    for feature in "${enabled[@]}"; do
      [[ -n "$feature" ]] && printf '%s/%s\n' "$pkg" "$feature"
    done
  done <<< "$normalized" | sort -u
}

# ---------------------------------------------------------------------------
# resolve_scp_features <crate> <features...>
#   Emit the COMPLETE resolved SCP-crate feature set of the shipped artifact,
#   one `crate/feature` per line, sorted-unique. Excludes dev-dependencies.
#
#   Reads cargo's RESOLVED FEATURE LIST per package (`--format '{p}|{f}'`), not
#   the `-e features` edge tree. The header records the measurement: the edge
#   tree omits every feature a package's own `[features]` table activates on a
#   dependency, which is the whole nullifier exposure of the two binaries this
#   gate covers with an empty feature-arg string.
#
#   DELIBERATE SPLIT from resolve_scp_testing_crate (NOT a redundant twin): this
#   reports FEATURES, whereas resolve_scp_testing_crate probes CRATE-NODE
#   presence (`scp-testing v…`). A `scp-testing` pulled with
#   `default-features = false` and no features enabled resolves an EMPTY feature
#   list here (so this function emits nothing for it) yet still appears as a
#   crate node — so the two checks catch distinct cases and are both
#   load-bearing.
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
  raw="$(cargo tree -e no-dev -p "$crate" $features --prefix none --format '{p}|{f}' 2>&1)"; rc=$?
  if [[ "$rc" -ne 0 ]]; then
    { echo "cargo tree failed for '$crate' (feature args: '$features'):"
      printf '%s\n' "$raw"; } >&2
    return 1
  fi
  parse_resolved_features "$raw"
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
#   Reads cargo's resolved feature list through parse_resolved_features, the same
#   reader resolve_scp_features uses, so a default member's OWN `[features]`
#   table activating a dependency feature is reported here too. A feature-edge
#   reader reported that class for a member ANOTHER member depends on (scp-ffi
#   depends on scp-node, so scp-node's feature nodes render inside scp-ffi's
#   subtree) and MISSED it for a member nothing depends on, which stays a display
#   root of its own. Measured: with `default = ["scp-transport/local-cache"]`
#   added to `crates/scp-relay/Cargo.toml` — and no package outside scp-relay
#   depending on scp-relay — the feature-edge reader printed OK for the scp-relay
#   entry AND for this default-members check, while this reader fails both.
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
  raw="$(cargo tree -e no-dev --prefix none --format '{p}|{f}' 2>&1)"; rc=$?
  if [[ "$rc" -ne 0 ]]; then
    { echo "cargo tree failed for a bare default-members resolution:"
      printf '%s\n' "$raw"; } >&2
    return 1
  fi
  parse_resolved_features "$raw"
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
# assert_resolver_sees_own_feature_table_activation
#   Positive control on the RESOLVER, not on the ⊆ decision procedure.
#
#   CRITERION: the resolver must report a feature that a shipped artifact's OWN
#   `[features]` table activates on one of that artifact's dependencies. A
#   resolver that reads only the `cargo tree -e features` edge tree reports
#   nothing for that class, and the two binaries in ARTIFACTS carry an empty
#   feature-arg string, so their entire nullifier exposure runs through it.
#
#   WITNESS: `crates/scp-ffi/Cargo.toml` declares
#   `server = ["scp-ffi-common/server", "dep:scp-node"]`, and this gate builds
#   scp-ffi with `--no-default-features --features server`, so a correct resolver
#   reports `scp-ffi-common/server`. Measured against the edge-tree reader this
#   gate used before: `cargo tree -e features,no-dev -p scp-ffi
#   --no-default-features --features server` printed no
#   `scp-ffi-common feature "server"` line at all.
#
#   This assertion FAILS THE GATE rather than warning, and it runs before the
#   artifact loop, so a resolver that has gone blind cannot print five OK lines
#   first. Renaming that feature must break this control loudly; re-point the
#   witness at another own-table activation rather than deleting the control.
# ---------------------------------------------------------------------------
assert_resolver_sees_own_feature_table_activation() {
  local witness_crate="scp-ffi"
  local witness_features="--no-default-features --features server"
  local witness_entry="scp-ffi-common/server"
  local resolved
  echo ">> positive control: the resolver reports a feature an artifact's own [features] table activates on a dependency"
  if ! resolved="$(resolve_scp_features "$witness_crate" "$witness_features")"; then
    echo "   FAIL — the positive-control resolution itself failed for '$witness_crate'."
    return 1
  fi
  if printf '%s\n' "$resolved" | grep -xF "$witness_entry" >/dev/null; then
    echo "   ok   — '$witness_entry' is reported for \`$witness_crate $witness_features\`"
    return 0
  fi
  echo "   FAIL — the resolver did NOT report '$witness_entry' for"
  echo "          \`cargo tree -p $witness_crate $witness_features\`, although"
  echo "          crates/scp-ffi/Cargo.toml declares"
  echo "          server = [\"scp-ffi-common/server\", \"dep:scp-node\"]."
  echo "          A resolver blind to a package's own [features] table cannot see"
  echo "          a nullifier that scp-node or scp-relay enables through its own"
  echo "          manifest — both are gated here with an EMPTY feature-arg string."
  echo "          Read cargo's resolved feature list (--format '{p}|{f}'); do NOT"
  echo "          go back to grepping the \`-e features\` edge tree."
  return 1
}

# ---------------------------------------------------------------------------
# Real gate.
# ---------------------------------------------------------------------------
run_gate() {
  local failures=0
  echo "G1 shipped-feature-graph gate (ADR-062 §Decision 6) — dev-deps EXCLUDED"
  echo "-------------------------------------------------------------------------"
  # Prove the resolver still sees the activation class the edge-tree reader
  # missed BEFORE reading any artifact, so a blind resolver cannot print five OK
  # lines ahead of its own failure.
  assert_resolver_sees_own_feature_table_activation || failures=$((failures + 1))
  echo
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

  # (resolver parse) parse_resolved_features must read the ROOT package's own
  #     resolved feature list, strip cargo's ` (*)` dedup marker, split a
  #     comma-separated list, ignore a non-SCP package, and emit nothing for a
  #     package whose resolved list is empty. The root line is the load-bearing
  #     case: a feature a package's own `[features]` table activates appears in
  #     cargo's resolved list and NOWHERE in the `-e features` edge tree.
  local synthetic parsed expected_parse
  synthetic="$(printf '%s\n' \
    'scp-node v0.1.0-beta.2 (/w/crates/scp-node)|allow_unencrypted_storage,default,testing' \
    'scp-dht v0.1.0-beta.2 (/w/crates/scp-dht)|default,production-dht,testing (*)' \
    'scp-clock v0.1.0-beta.2 (/w/crates/scp-clock)|' \
    'tokio v1.49.0|full,macros')"
  expected_parse="$(printf '%s\n' \
    'scp-dht/default' 'scp-dht/production-dht' 'scp-dht/testing' \
    'scp-node/allow_unencrypted_storage' 'scp-node/default' 'scp-node/testing')"
  parsed="$(parse_resolved_features "$synthetic")"
  if [[ "$parsed" == "$expected_parse" ]]; then rc=0; else rc=1; fi
  expect "(resolver parse) a root package's own resolved features, dedup markers, and non-SCP packages are read correctly" "PASS" "$rc"
  if [[ "$parsed" != "$expected_parse" ]]; then
    echo "          expected:"; printf '%s\n' "$expected_parse" | sed 's/^/            /'
    echo "          got:";      printf '%s\n' "$parsed"          | sed 's/^/            /'
  fi

  # (resolver parse) A resolved list that names a nullifier feature must reach
  #     the ⊆ check as an offender. This joins the parse to the decision
  #     procedure, so neither half can be green while the pair is broken.
  local nullifier_parse
  nullifier_parse="$(parse_resolved_features 'scp-platform v0.1.0-beta.2 (/w/crates/scp-platform)|sqlite,testing')"
  check_subset "$nullifier_parse" "$PERMITTED_ALLOWLIST" >/dev/null 2>&1; rc=$?
  expect "(resolver parse) a parsed 'scp-platform/testing' is REJECTED by the subset check" "FAIL" "$rc"

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
