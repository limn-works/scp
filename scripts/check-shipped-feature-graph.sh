#!/usr/bin/env bash
#
# G1 — Shipped-feature-graph prove-absence gate (ADR-062 §Decision 6 / §Enforcement,
# spec §17.17 SCP-CAPSEL-8000/8001/8002 + §17.17.2 durability-vs-nullifier).
#
# WHAT THIS PROVES
# ----------------
# For every shipped artifact (the three FFI bridges plus the scp-node and
# scp-relay binaries), TWO subset assertions hold over the artifact's own
# cargo-resolved dependency graph:
#
#   1. CRATE DIMENSION — every SCP crate the graph reaches is admitted by name by
#      PERMITTED_CRATES. A crate the list does not name FAILS the gate.
#   2. FEATURE DIMENSION — the COMPLETE resolved feature set of the SCP
#      workspace crates is a SUBSET of PERMITTED_ALLOWLIST, permitting
#      durability-only + real-backend features — with one disclosed
#      confidentiality-nullifier residue (the three
#      `scp-*/allow_unencrypted_storage` entries, tracked for removal in Track B /
#      #2292; full statement in ADR-062 §Status). Any resolved SCP-crate feature
#      that is NOT on the allowlist — named or novel, present or future — FAILS.
#
# WHY THE CRATE DIMENSION EXISTS
# ------------------------------
# The feature dimension compares FEATURE EDGES, and a crate that declares no
# `[features]` table emits none. Such a crate is a node in a shipped graph that
# the feature comparison has nothing to compare and therefore cannot reject.
# `scp-relay` is already such a crate — it declares no `[features]` table, so no
# `scp-relay/…` entry appears on PERMITTED_ALLOWLIST even though every
# `scp-relay` build resolves it. The three bridge crates are in the same
# position for a different reason: cargo emits no `<pkg> feature "…"` edge for
# the tree's own root. Four of the twenty-one crates the five artifacts reach are
# therefore invisible to the feature comparison. A new crate that carries a
# security-nullifier implementation and declares no features would join them, so
# the gate that exists to prove nullifiers absent would not see it. Asserting the
# crate NAMES too closes that hole: a crate reaches a shipped artifact only if a
# human put its name on PERMITTED_CRATES.
#
# WHAT COUNTS AS AN SCP CRATE (the criterion, then the extension)
# --------------------------------------------------------------
# CRITERION: a crate this repository authors, which means a member of this cargo
# workspace. `cargo tree --workspace --depth 0` enumerates those members.
# Membership decides it, and the crate's name never does, so this criterion
# covers a workspace crate whatever an author names it.
# EXTENSION: any reached crate whose name begins `scp-`, which covers a crate
# published elsewhere under an SCP name. Both clauses test membership positively,
# and the crate check must admit their union, so each clause only widens what
# PERMITTED_CRATES has to name.
# A third-party crate satisfies neither clause, and this gate makes no claim
# about one; `cargo deny` governs third-party dependencies.
#
# The gate's TARGET soundness invariant — shipped-graph
# feature-absence ≡ nullifier-type absence — holds for every `testing`-gated
# nullifier double (`InMemoryKeyCustody` / `InMemoryDeviceAttestation` /
# `InMemoryPreRotationCustody` / `InMemoryDhtClient` and the `did:key` test
# method, each gated behind a `testing` feature of scp-platform / scp-dht /
# scp-did / scp-core / scp-protocol / scp-runtime / scp-mls or the `scp-testing`
# crate, none of which the whitelist admits — so an absent gating feature means
# the nullifier cannot be compiled in), but is NOT YET fully achieved while the
# disclosed `allow_unencrypted_storage` residue remains on the allowlist
# (see ADR-062 §Status / #2292).
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
#   scripts/check-shipped-feature-graph.sh             # gate the real workspace
#   scripts/check-shipped-feature-graph.sh --self-test # run the fixture harness only
#   scripts/check-shipped-feature-graph.sh --dump-lists # print the evaluated lists
#
# --dump-lists prints, as `<list-name>\t<entry>` lines, the four lists this
# script EVALUATES: PERMITTED_ALLOWLIST, PERMITTED_CRATES,
# NULLIFIER_CONTROL_FEATURES, and ARTIFACTS.
# `crates/scp-testing/tests/integration/capability_impl_inventory.rs`
# freezes that output against `ratchet/capability-impl-inventory.json`, so a
# change to any of the four fails until a human records it.
#
# The ratchet consumes this output rather than reading the arrays out of this
# file's source text, because bash and a text reader disagree about what the
# arrays hold. A `cat` heredoc ends at its terminator while the surrounding
# command substitution keeps running, so an `echo` placed after the terminator
# adds an entry no text reader sees; a second assignment to either name wins for
# bash and loses to a first-match reader. Printing what the shell evaluated
# removes the disagreement.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# ---------------------------------------------------------------------------
# Single permitted-production allowlist (EXPLICIT — the whitelist).
#
# Durability-only (SCP-CAPSEL-8010/8011) + real-backend features. ZERO nullifier
# features is the design mandate (ADR-062 §Decision 6; PR #2132); the one
# disclosed `allow_unencrypted_storage` residue (the three `scp-*/...` entries
# below) is single-sourced in ADR-062 §Status / #2292 — see there for the full
# classification. The `assert_allowlist_has_no_nullifier` self-test enforces that
# no NULLIFIER_CONTROL_FEATURES entry is added, so a future edit cannot quietly
# add a *new* nullifier exception.
#
# `scp-platform/in-memory-push` is an intentionally-permitted, currently-unused
# durability-only entry: no shipped artifact resolves it today, but a superset
# allowlist may carry permitted-but-unresolved rows (it is durability-only, not a
# nullifier, so its presence widens nothing that matters).
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
scp-clock/default
scp-core/allow_unencrypted_storage
scp-core/default
scp-crypto/default
scp-dht/default
scp-dht/production-dht
scp-did/default
scp-event-log/default
scp-ffi-common/custody
scp-ffi-common/default
scp-ffi-common/resolvers
scp-identity/default
scp-identity/production-dht
scp-mcp/default
scp-media/default
scp-mls/default
scp-node/allow_unencrypted_storage
scp-node/default
scp-platform/default
scp-platform/encrypting
scp-platform/file
scp-platform/filesystem
scp-platform/in-memory-push
scp-platform/in-memory-storage
scp-platform/software_platform
scp-platform/sqlite
scp-protocol/default
scp-relay-client/default
scp-runtime/allow_unencrypted_storage
scp-runtime/default
scp-transport/default
scp-transport/postgres-blob
scp-transport/redb-blob
scp-transport/s3-blob
scp-transport/sqlite-blob
scp-transport/startup
EOF
)"

# ---------------------------------------------------------------------------
# Single permitted-production CRATE allowlist (EXPLICIT — the whitelist for the
# crate dimension).
#
# Every SCP crate a shipped artifact's dependency graph reaches must appear here.
# `cargo tree` DERIVES each artifact's reached crate set (never a hand-list, and
# never a `Cargo.toml` text scan — the gate must assert about the graph cargo
# actually resolves); this list is the hand-maintained set of what is PERMITTED.
#
# Like PERMITTED_ALLOWLIST this is one SUPERSET list covering all five artifacts.
# The five reach 21 SCP crates between them: each bridge reaches 18, scp-node 14,
# scp-relay 14. Every entry below is reached by at least one artifact.
#
# ADDING AN ENTRY IS THE REVIEWABLE ACT. A crate carrying a nullifier
# implementation reaches a shipped binary only by being named here, and
# `ratchet/capability-impl-inventory.json` freezes this list, so an addition
# fails that ratchet until a human records it.
# ---------------------------------------------------------------------------
PERMITTED_CRATES="$(cat <<'EOF'
scp-clock
scp-core
scp-crypto
scp-dht
scp-did
scp-event-log
scp-ffi
scp-ffi-common
scp-ffi-napi
scp-ffi-uniffi
scp-identity
scp-mcp
scp-media
scp-mls
scp-node
scp-platform
scp-protocol
scp-relay
scp-relay-client
scp-runtime
scp-transport
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
# `cargo build --release -p scp-relay -p scp-node` and the
# `.github/workflows/release.yml` `cargo publish` steps. This gate checks the
# feature config NAMED HERE, not whatever those workflows actually build; if the
# two drift apart, coverage silently narrows (an artifact would be gated in a
# config it no longer ships).
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
#
# EVERY ENTRY MUST NAME SOMETHING THAT EXISTS. `assert_control_features_resolve`
# below probes each one with cargo and fails the gate on any that does not
# resolve. That assertion exists because three entries here —
# `scp-platform/in-memory-custody`, `scp-platform/in-memory-attestation`, and
# `scp-platform/in-memory-pre-rotation` — named features `crates/scp-platform`
# never declared. Their `assert_allowlist_has_no_nullifier` iterations searched
# the allowlist for a string nothing could ever produce, so each read as a proof
# and proved nothing. No bypass followed, because `scp-platform/testing` was on
# the list too and is the real control; the defect was an assertion that could
# not fail, not a hole an artifact could slip through.
#
# The three dead names are deleted rather than repaired, because
# `scp-platform/testing` is the ONE control that gates all three capabilities.
# `crates/scp-platform/Cargo.toml` declares `testing` as the gate on the three
# nullifier doubles (`InMemoryKeyCustody`, `InMemoryDeviceAttestation`,
# `InMemoryPreRotationCustody`), and `crates/scp-platform/src/lib.rs` puts all
# three behind one `#[cfg(feature = "testing")] pub mod testing;`. Custody,
# attestation, and pre-rotation therefore have no separate gating features to
# name. Listing three dead names alongside the live one told a reader that three
# separate controls were being proved absent when one control covers all three.
NULLIFIER_CONTROL_FEATURES=(
  "scp-platform/testing"
  "scp-dht/testing"
  "scp-did/testing"
  "scp-core/testing"
  "scp-protocol/testing"
  "scp-runtime/testing"
  "scp-mls/testing"
  "scp-testing"
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
  raw="$(cargo tree -e features,no-dev -p "$crate" $features 2>&1)"; rc=$?
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
# workspace_member_crates
#   Emit every crate this cargo workspace declares as a member, one name per
#   line, sorted-unique. This is the CRITERION for "an SCP crate": a crate this
#   repository authors. cargo answers it from the workspace manifest it already
#   resolves, so the answer cannot drift from what the build sees — a
#   `Cargo.toml` text scan or a hand-written members list would drift.
#
#   Fails LOUD (non-zero, cargo's message on stderr) rather than emitting an
#   empty set, because an empty member set would make every reached crate look
#   third-party and silently narrow the crate check to the `scp-` prefix clause.
#
#   Memoised: the member set is a property of the workspace, not of an artifact,
#   so the five artifacts share one resolution.
# ---------------------------------------------------------------------------
WORKSPACE_MEMBERS_CACHE=""
workspace_member_crates() {
  if [[ -n "$WORKSPACE_MEMBERS_CACHE" ]]; then
    printf '%s\n' "$WORKSPACE_MEMBERS_CACHE"
    return 0
  fi
  local raw rc members
  raw="$(cargo tree -e no-dev --workspace --depth 0 --prefix none 2>&1)"; rc=$?
  if [[ "$rc" -ne 0 ]]; then
    { echo "cargo tree (workspace-member enumeration) failed:"
      printf '%s\n' "$raw"; } >&2
    return 1
  fi
  members="$(printf '%s\n' "$raw" | awk 'NF {print $1}' | sort -u)"
  if [[ -z "$members" ]]; then
    echo "cargo tree --workspace --depth 0 enumerated no workspace member; refusing to" >&2
    echo "treat an empty member set as 'no SCP crate reaches this artifact'." >&2
    return 1
  fi
  WORKSPACE_MEMBERS_CACHE="$members"
  printf '%s\n' "$members"
}

# ---------------------------------------------------------------------------
# resolve_scp_crate_nodes <crate> <features...>
#   Emit every SCP crate the shipped artifact's dependency graph reaches, one
#   name per line, sorted-unique. Excludes dev-dependencies, exactly as
#   resolve_scp_features does, because a shipped artifact is built without them.
#
#   A reached crate is an SCP crate when it is a workspace member (the criterion)
#   or its name begins `scp-` (the extension covering an externally-published
#   crate that takes an SCP name). The union is what the crate ⊆ check must
#   admit.
#
#   DELIBERATE SPLIT from resolve_scp_features (NOT a redundant twin): that
#   function extracts FEATURE edges (`scp-* feature "…"`) from the
#   `-e features,no-dev` tree, and this one extracts CRATE NODES from the
#   `-e no-dev` tree. A crate that declares no `[features]` table contributes no
#   feature edge at all, so the feature extraction cannot see it — which is the
#   hole this function exists to close.
#
#   Fails LOUD on a cargo error, mirroring resolve_scp_features: a swallowed
#   failure produces no output, which the caller would read as "no SCP crate
#   present" — a FAIL-OPEN read.
# ---------------------------------------------------------------------------
resolve_scp_crate_nodes() {
  local crate="$1"; shift
  local features="$1"
  local raw rc nodes members
  # shellcheck disable=SC2086
  raw="$(cargo tree -e no-dev --prefix none -p "$crate" $features 2>&1)"; rc=$?
  if [[ "$rc" -ne 0 ]]; then
    { echo "cargo tree (crate-node resolution) failed for '$crate' (feature args: '$features'):"
      printf '%s\n' "$raw"; } >&2
    return 1
  fi
  members="$(workspace_member_crates)" || return 1
  # `--prefix none` prints one `<name> <version> [(<source>)]` line per graph
  # node with no tree-drawing characters, so the first field is the crate name.
  nodes="$(printf '%s\n' "$raw" | awk 'NF {print $1}' | sort -u)"
  { comm -12 <(printf '%s\n' "$nodes") <(printf '%s\n' "$members")
    printf '%s\n' "$nodes" | grep -E '^scp-' || true
  } | sort -u
}

# resolve_scp_testing_crate <crate> <features...>
#   Emit "scp-testing" iff the full-stack test-harness crate is in the shipped
#   (no-dev) dependency graph. Its mere presence is a nullifier and FAILS.
#   DELIBERATE SPLIT from resolve_scp_features (NOT a redundant twin): this
#   reports CRATE-NODE presence, which catches a `scp-testing` pulled with no
#   enabled features — a case the feature-edge grep in resolve_scp_features would
#   miss. Both checks are load-bearing; keep them separate.
#   It reads the SAME resolved node set the crate ⊆ check reads, so the two
#   cannot disagree about whether a crate is in the graph; and it inherits that
#   function's fail-loud contract, so a cargo resolution error can never
#   masquerade as nullifier-crate absence.
resolve_scp_testing_crate() {
  local crate="$1"; shift
  local features="$1"
  local nodes
  nodes="$(resolve_scp_crate_nodes "$crate" "$features")" || return 1
  printf '%s\n' "$nodes" | grep -xF 'scp-testing' || true
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
# Real gate.
# ---------------------------------------------------------------------------
run_gate() {
  local failures=0
  echo "G1 shipped-feature-graph gate (ADR-062 §Decision 6) — dev-deps EXCLUDED"
  echo "-------------------------------------------------------------------------"
  for spec in "${ARTIFACTS[@]}"; do
    local crate="${spec%%|*}" features="${spec#*|}"
    echo ">> $crate  ($features)"

    local resolved offenders crate_nodes
    # CRATE DIMENSION. Resolve the SCP crates this artifact's graph reaches and
    # assert every one of them is admitted by name. This runs first because a
    # crate that declares no `[features]` table contributes nothing for the
    # feature dimension below to compare, so the feature check alone would print
    # OK for a graph carrying it.
    if ! crate_nodes="$(resolve_scp_crate_nodes "$crate" "$features")" \
        || ! resolution_is_nonempty "$crate_nodes"; then
      echo "   FAIL — resolved SCP-crate set is EMPTY (cargo resolution failed or"
      echo "          the feature args are wrong — e.g. '$features' names a"
      echo "          feature '$crate' does not have). Every shipped artifact"
      echo "          reaches at least itself, so an empty set is never a real"
      echo "          answer; refusing to treat it as 'empty ⊆ permitted crates'."
      failures=$((failures + 1))
      continue
    fi
    if offenders="$(check_subset "$crate_nodes" "$PERMITTED_CRATES")"; then
      echo "   OK — reached SCP crates ⊆ permitted-production crate allowlist ($(printf '%s\n' "$crate_nodes" | wc -l | tr -d ' ') crates)"
    else
      echo "   FAIL — SCP crates in the shipped graph that PERMITTED_CRATES does not admit:"
      printf '%s\n' "$offenders" | sed 's/^/       ✗ /'
      echo "   A crate reaches a shipped artifact only when a human names it on"
      echo "   PERMITTED_CRATES. Sever the dependency edge, or — if the crate"
      echo "   belongs in production — read what it implements before adding it,"
      echo "   because a crate that declares no \`[features]\` table carries its"
      echo "   code into the artifact without appearing in the feature dimension"
      echo "   below."
      failures=$((failures + 1))
    fi

    # FEATURE DIMENSION.
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
      echo "   modulo the disclosed \`allow_unencrypted_storage\` residue — §Status / #2292)."
      failures=$((failures + 1))
    fi
  done
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

# ---------------------------------------------------------------------------
# assert_control_features_resolve
#   Every NULLIFIER_CONTROL_FEATURES entry must name something the workspace
#   actually declares. An entry spelled `crate/feature` must name a feature that
#   crate declares; a bare entry must name a workspace crate.
#
#   WHY THIS ASSERTION EXISTS. `assert_allowlist_has_no_nullifier` searches the
#   allowlist for each control entry. An entry naming a feature no crate declares
#   searches for a string cargo can never emit, so its iteration cannot fail
#   whatever the allowlist contains. It reads as proof and provides none. Three
#   such entries sat in this mandatory gate until this assertion was added.
#
#   HOW IT PROBES. `cargo tree -p <crate> --features <feature> --depth 0` exits
#   non-zero with "the package '<crate>' does not contain this feature:
#   <feature>" when the feature is absent, and exits zero when it is present.
#   That is cargo answering from the manifest it already resolves, rather than
#   this script parsing TOML and drifting from what cargo believes.
# ---------------------------------------------------------------------------
# control_entry_resolves <entry>
#   Returns 0 when the entry names a feature the crate declares (for a
#   `crate/feature` entry) or a workspace crate (for a bare entry), non-zero
#   otherwise. Factored out as a predicate so the fixture harness can drive it
#   with a synthetic dead name — see assert_control_resolution_is_load_bearing.
control_entry_resolves() {
  local entry="$1" crate feature
  if [[ "$entry" == */* ]]; then
    crate="${entry%%/*}"
    feature="${entry#*/}"
    cargo tree -e no-dev -p "$crate" --features "$feature" --depth 0 >/dev/null 2>&1
  else
    cargo tree -e no-dev -p "$entry" --depth 0 >/dev/null 2>&1
  fi
}

# Positive and negative control over control_entry_resolves itself. Every other
# check in run_fixtures is pinned by an expect PASS/FAIL pair; without one here,
# an edit that swallowed the exit status would make the resolution check vacuous
# again — which is the exact defect it was written to fix.
assert_control_resolution_is_load_bearing() {
  local rc
  control_entry_resolves "scp-platform/testing"; rc=$?
  expect "(control-resolution) a declared feature RESOLVES" "PASS" "$rc"
  control_entry_resolves "scp-platform/no-such-feature-9000"; rc=$?
  expect "(control-resolution) an undeclared feature is REJECTED" "FAIL" "$rc"
  control_entry_resolves "scp-no-such-crate-9000"; rc=$?
  expect "(control-resolution) an unknown crate is REJECTED" "FAIL" "$rc"
}

assert_control_features_resolve() {
  echo ">> fixture: every NULLIFIER_CONTROL_FEATURES entry resolves to a feature or crate the workspace declares — an entry naming nothing makes its allowlist-hygiene iteration unable to fail"
  local entry crate feature probe rc unresolved=0
  for entry in "${NULLIFIER_CONTROL_FEATURES[@]}"; do
    if [[ "$entry" == */* ]]; then
      crate="${entry%%/*}"
      feature="${entry#*/}"
      probe="$(cargo tree -e no-dev -p "$crate" --features "$feature" --depth 0 2>&1)"; rc=$?
      if [[ "$rc" -ne 0 ]]; then
        echo "   FAIL — control entry '$entry' names no feature '$crate' declares:"
        printf '%s\n' "$probe" | sed 's/^/          /'
        echo "          Delete the entry, or name the feature that actually gates this"
        echo "          capability. Do NOT rename it to the nearest live feature without"
        echo "          establishing that the live feature is what the dead name meant."
        fixture_failures=$((fixture_failures + 1))
        unresolved=$((unresolved + 1))
      fi
    else
      probe="$(cargo tree -e no-dev -p "$entry" --depth 0 2>&1)"; rc=$?
      if [[ "$rc" -ne 0 ]]; then
        echo "   FAIL — control entry '$entry' names no workspace crate:"
        printf '%s\n' "$probe" | sed 's/^/          /'
        fixture_failures=$((fixture_failures + 1))
        unresolved=$((unresolved + 1))
      fi
    fi
  done
  if [[ "$unresolved" -eq 0 ]]; then
    echo "   ok   — all ${#NULLIFIER_CONTROL_FEATURES[@]} control entries resolve"
  else
    echo "   FAIL — $unresolved of ${#NULLIFIER_CONTROL_FEATURES[@]} control entries name nothing the workspace declares"
  fi
}

# ---------------------------------------------------------------------------
# assert_crate_resolution_is_load_bearing
#   Positive and negative control over resolve_scp_crate_nodes itself, and the
#   demonstration that the crate dimension is not redundant with the feature one.
#
#   The failure this guards against is a crate list derived from something other
#   than what cargo resolves — a `Cargo.toml` text scan, a workspace-members
#   literal, a hand-written enumeration. Any of those would let the gate assert
#   about a graph the build does not have. These proofs drive the real resolver
#   against the real workspace: the crate it returns must be present, a crate the
#   graph does not reach must be absent, and the featureless crate that motivates
#   this whole dimension must appear as a node while contributing no feature edge.
# ---------------------------------------------------------------------------
assert_crate_resolution_is_load_bearing() {
  echo ">> fixture: the crate resolver reads what cargo resolved — a reached crate is present, an unreached crate is absent, and a crate with no [features] table appears as a node while contributing no feature edge"
  local members nodes feats rc

  members="$(workspace_member_crates)"; rc=$?
  expect "(crate-resolution) the workspace-member enumeration SUCCEEDS" "PASS" "$rc"
  printf '%s\n' "$members" | grep -qxF 'scp-relay'; rc=$?
  expect "(crate-resolution) the enumeration names a crate this workspace declares" "PASS" "$rc"

  nodes="$(resolve_scp_crate_nodes "scp-relay" "")"; rc=$?
  expect "(crate-resolution) resolving a shipped artifact's crate nodes SUCCEEDS" "PASS" "$rc"
  printf '%s\n' "$nodes" | grep -qxF 'scp-relay'; rc=$?
  expect "(crate-resolution) a crate that declares no [features] table IS in the resolved node set" "PASS" "$rc"
  printf '%s\n' "$nodes" | grep -qxF 'scp-testing'; rc=$?
  expect "(crate-resolution) a crate the shipped graph does not reach is NOT in the node set" "FAIL" "$rc"

  # This proof pins the premise the crate dimension rests on. If it ever flips to
  # PASS, `scp-relay` gained a `[features]` table and stopped demonstrating the
  # blind spot, so pick another featureless crate here. Do NOT read that flip as
  # the blind spot closing, because the next crate an author adds with no
  # `[features]` table reopens it.
  feats="$(resolve_scp_features "scp-relay" "")"
  printf '%s\n' "$feats" | grep -qE '^scp-relay/'; rc=$?
  expect "(crate-resolution) that same crate contributes NO feature edge, so the feature dimension cannot see it" "FAIL" "$rc"
}

# ---------------------------------------------------------------------------
# assert_permitted_crates_are_declared
#   Every PERMITTED_CRATES entry must name a crate cargo can resolve. An entry
#   naming nothing admits nothing, so it cannot make the gate fail-open; what it
#   does is hide that the list has drifted from the workspace, leaving a reader
#   to believe a crate is being admitted deliberately when the name is dead. The
#   probe is the same `control_entry_resolves` predicate the control-feature
#   check uses, in its bare-name branch.
# ---------------------------------------------------------------------------
assert_permitted_crates_are_declared() {
  echo ">> fixture: every PERMITTED_CRATES entry names a crate cargo resolves — a dead name records a decision about a crate that does not exist"
  local entry rc dead=0 total=0
  while IFS= read -r entry; do
    [[ -z "$entry" ]] && continue
    total=$((total + 1))
    control_entry_resolves "$entry"; rc=$?
    if [[ "$rc" -ne 0 ]]; then
      echo "   FAIL — permitted crate '$entry' names no crate cargo can resolve."
      echo "          Delete the entry, or correct it to the crate actually reached."
      fixture_failures=$((fixture_failures + 1))
      dead=$((dead + 1))
    fi
  done <<< "$PERMITTED_CRATES"
  if [[ "$dead" -eq 0 ]]; then
    echo "   ok   — all $total permitted crates resolve"
  else
    echo "   FAIL — $dead of $total permitted crates name nothing cargo can resolve"
  fi
}

# ---------------------------------------------------------------------------
# assert_permitted_crates_have_no_nullifier_crate
#   The crate-dimension counterpart of assert_allowlist_has_no_nullifier: no
#   NULLIFIER_CONTROL_FEATURES entry that names a CRATE (a bare entry, e.g.
#   `scp-testing`) may appear on PERMITTED_CRATES. Admitting the test-harness
#   crate by name would hand a shipped artifact every nullifier double it
#   carries.
# ---------------------------------------------------------------------------
assert_permitted_crates_have_no_nullifier_crate() {
  echo ">> fixture: PERMITTED_CRATES admits ZERO nullifier crates — no bare NULLIFIER_CONTROL_FEATURES entry (the test-harness crate) appears on it"
  local nf
  for nf in "${NULLIFIER_CONTROL_FEATURES[@]}"; do
    [[ "$nf" == */* ]] && continue
    if printf '%s\n' "$PERMITTED_CRATES" | grep -qxF "$nf"; then
      echo "   FAIL — nullifier crate '$nf' is on PERMITTED_CRATES (forbidden exception)"
      fixture_failures=$((fixture_failures + 1))
    fi
  done
  echo "   ok   — no test-harness nullifier crate appears on PERMITTED_CRATES"
}

assert_allowlist_has_no_nullifier() {
  echo ">> fixture: allowlist carries ZERO enumerated control-nullifier features — no NULLIFIER_CONTROL_FEATURES entry (custody/attestation/DHT/did:key/test-harness double) appears (AC7); disclosed allow_unencrypted_storage residue tracked in §Status / #2292"
  local nf
  for nf in "${NULLIFIER_CONTROL_FEATURES[@]}"; do
    if printf '%s\n' "$PERMITTED_ALLOWLIST" | grep -qxF "$nf"; then
      echo "   FAIL — nullifier feature '$nf' is on the allowlist (forbidden exception)"
      fixture_failures=$((fixture_failures + 1))
    fi
  done
  echo "   ok   — no custody/attestation/DHT/did:key/test-harness nullifier control-feature appears on the allowlist"
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

  # (AC8 soundness) A synthetic consumer whose graph carries a `testing` nullifier
  #     feature (e.g. a mis-wired bridge, or a future consumer that fails to keep
  #     the nullifier behind dev-deps) → REJECTED, because no `testing` feature is
  #     on the durability-only + real-backend allowlist. This is the gate's TARGET
  #     feature-absence ≡ nullifier-absence invariant — fully held for the testing
  #     nullifiers, with the disclosed `allow_unencrypted_storage` residue the one
  #     outstanding gap (§Status / #2292).
  local nf leaked
  for nf in "scp-platform/testing" "scp-dht/testing" "scp-did/testing" "scp-testing"; do
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

  # ── Crate dimension ──────────────────────────────────────────────────────
  # The same four proofs the feature dimension carries, driven through the same
  # check_subset decision procedure with crate names instead of feature names.

  # (crate-c) Clean artifact whose reached crate set ⊆ PERMITTED_CRATES → ACCEPTED.
  local clean_crates
  clean_crates="$PERMITTED_CRATES"
  check_subset "$clean_crates" "$PERMITTED_CRATES" >/dev/null; rc=$?
  expect "(crate-c) clean reached crate set ⊆ permitted crates is ACCEPTED" "PASS" "$rc"

  # (crate-a) A NOVEL crate name not on the list → REJECTED. Proves the crate
  #     check is closed/positive, so a crate nobody has thought of yet fails
  #     without this file ever naming it.
  local novel_crate
  novel_crate="$(printf '%s\nscp-some-future-nullifier-crate-9000' "$PERMITTED_CRATES")"
  check_subset "$novel_crate" "$PERMITTED_CRATES" >/dev/null 2>&1; rc=$?
  expect "(crate-a) novel crate not on PERMITTED_CRATES is REJECTED" "FAIL" "$rc"

  # (crate-b) PERMITTED_CRATES edited to OMIT a genuinely-reached crate →
  #     REJECTED. `scp-relay` is the deliberate choice: it declares no
  #     `[features]` table, so it is exactly the kind of crate the feature
  #     dimension cannot see, and this proves the crate list carrying it is
  #     load-bearing.
  local trimmed_crates
  trimmed_crates="$(printf '%s\n' "$PERMITTED_CRATES" | grep -vxF 'scp-relay')"
  check_subset "$PERMITTED_CRATES" "$trimmed_crates" >/dev/null 2>&1; rc=$?
  expect "(crate-b) permitted crates omitting a reached crate is REJECTED" "FAIL" "$rc"

  # (crate-soundness) The test-harness crate leaking into a shipped graph →
  #     REJECTED by the crate dimension on its own, without the feature edges
  #     that resolve_scp_features would need to see it.
  local leaked_crate
  leaked_crate="$(printf '%s\nscp-testing' "$PERMITTED_CRATES")"
  check_subset "$leaked_crate" "$PERMITTED_CRATES" >/dev/null 2>&1; rc=$?
  expect "(crate-soundness) leaked nullifier crate 'scp-testing' is REJECTED" "FAIL" "$rc"

  # (blind-spot) The hole the crate dimension closes, proved on one synthetic
  #     artifact: a crate that declares no `[features]` table contributes ZERO
  #     feature edges, so the feature dimension sees a clean set and ACCEPTS,
  #     while the crate dimension sees the crate and REJECTS. Both halves are
  #     asserted here, because the proof is the pair — the feature half passing
  #     is what makes the crate half necessary.
  check_subset "$PERMITTED_ALLOWLIST" "$PERMITTED_ALLOWLIST" >/dev/null; rc=$?
  expect "(blind-spot) featureless crate contributes no feature edge, so the feature dimension ACCEPTS" "PASS" "$rc"
  local featureless
  featureless="$(printf '%s\nscp-featureless-nullifier-crate-9000' "$PERMITTED_CRATES")"
  check_subset "$featureless" "$PERMITTED_CRATES" >/dev/null 2>&1; rc=$?
  expect "(blind-spot) the same featureless crate is REJECTED by the crate dimension" "FAIL" "$rc"

  # (empty-guard, crate dimension) An empty reached crate set must be REJECTED,
  #     never read as "no SCP crate reaches this artifact". Every artifact
  #     reaches at least itself.
  resolution_is_nonempty ""; rc=$?
  expect "(empty-guard) empty reached crate set is REJECTED" "FAIL" "$rc"
  resolution_is_nonempty "scp-relay"; rc=$?
  expect "(empty-guard) non-empty reached crate set is ACCEPTED" "PASS" "$rc"

  assert_control_resolution_is_load_bearing
  assert_control_features_resolve
  assert_crate_resolution_is_load_bearing
  assert_permitted_crates_are_declared
  assert_permitted_crates_have_no_nullifier_crate
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
# ---------------------------------------------------------------------------
# dump_lists
#   Print the four lists this script EVALUATES, one `<list-name>\t<entry>` line
#   each, after bash has finished evaluating every assignment in the file.
#
#   This is the ratchet's input. Reading the arrays out of this file's source
#   text instead would let bash and the reader disagree — see the --dump-lists
#   note in the header — so what the shell computed is what gets frozen.
# ---------------------------------------------------------------------------
dump_lists() {
  local entry
  while IFS= read -r entry; do
    [[ -n "$entry" ]] && printf 'permitted_allowlist\t%s\n' "$entry"
  done <<< "$PERMITTED_ALLOWLIST"
  while IFS= read -r entry; do
    [[ -n "$entry" ]] && printf 'permitted_crates\t%s\n' "$entry"
  done <<< "$PERMITTED_CRATES"
  for entry in "${NULLIFIER_CONTROL_FEATURES[@]}"; do
    printf 'nullifier_control_features\t%s\n' "$entry"
  done
  for entry in "${ARTIFACTS[@]}"; do
    printf 'artifacts\t%s\n' "$entry"
  done
}

# ---------------------------------------------------------------------------
main() {
  if [[ "${1:-}" == "--dump-lists" ]]; then
    dump_lists
    exit 0
  fi

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
    echo "G1 PASSED: every shipped artifact reaches only permitted SCP crates, and its SCP-crate feature set ⊆ the permitted-production allowlist (durability-only + real-backend, plus the disclosed \`allow_unencrypted_storage\` residue — §Status / #2292)."
    exit 0
  fi
  echo
  echo "G1 FAILED: a shipped artifact reaches a crate PERMITTED_CRATES does not admit,"
  echo "or resolves a non-allowlisted (nullifier/test-harness) feature. Fix the"
  echo "dependency edge — do NOT add the crate or the feature to make this pass."
  exit 1
}

main "$@"
