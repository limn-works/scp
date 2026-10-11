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
# real-backend features and ZERO nullifier features. Absence from this list means
# one thing: no shipped build may resolve that feature. Absence does not say why
# the list leaves a feature out. The features it leaves out include every
# nullifier; the real-backend features `scp-transport/postgres-blob` and
# `scp-transport/s3-blob`, which every shipped artifact is built without; the
# `scp-node/cloud-blobs` and `scp-relay/cloud-blobs` features, the off-by-default
# features that compile those two backends (ADR-062, capability injection,
# §Enforcement G1); and optional transport features that no shipped build enables,
# such as `scp-node/quic`, `scp-node/upnp`, `scp-transport/quic` and
# `scp-transport/upnp`. Any resolved SCP-crate
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
# A SECOND DIMENSION: THE LOCAL CRATES EACH ARTIFACT REACHES
# ----------------------------------------------------------
# For every ARTIFACTS entry, the set of crates its non-dev graph resolves from a
# LOCAL PATH source is also a SUBSET of a closed list, PERMITTED_CRATES. A local
# crate the list does not name FAILS this gate until a human adds it. The same
# check runs, under default features, on every package a SHIPPING_FILES line
# builds or publishes (`packages_built_by_shipping_files`) that has no
# default-feature ARTIFACTS entry, so a package the drift check admits as a
# default-members node still gets its crate set checked.
#
# Why the feature dimension alone cannot see such a crate: it compares FEATURE
# rows, and a crate contributes no row when no feature of it is enabled. A crate
# that declares no `[features]` table never contributes one, and neither does a
# crate whose table holds only off-by-default features, which is `scp-relay` on
# this tree (its table holds only `cloud-blobs`). Cargo also renders no edge for a
# tree's own root. So a new local crate carrying an always-succeeds verifier and
# declaring no feature would ship under a green feature dimension.
#
# CRITERION: provenance. A crate counts when the WHOLE `cargo tree` node line
# carries a local-path source token, ` (/…)`. Cargo prints a path proc-macro as
# `name v1.0 (proc-macro) (/path)`, marker first, so the line is searched for the
# token rather than the token being anchored after the version. This covers a
# workspace member, a `vendor/` crate that declares its own `[workspace]` table
# (repo-authored, NOT a workspace member), and a path dependency outside the
# repository. A registry crate, a vendored registry crate (cargo prints a crate
# served through a `directory` source replacement exactly as it prints a
# crates.io crate, with no source token; measured with cargo 1.97.1), and a git
# crate carry no local-path token and are not this dimension's subject;
# `cargo deny` and the reviewed `Cargo.lock` govern them.
# INDICATOR, NOT CRITERION: the `scp-` name prefix. It appears only in this
# gate's messages, as a label on each offender, and decides nothing.
#
# The dimension reads BOTH renderings the feature dimension reads (the
# `-e features,no-dev` tree and the `-e no-dev --format '{f}|{p}'` tree, each
# with `--target all`) and checks their union, for the same reason: a cargo
# release that changes one rendering must not empty the check.
#
# WHY A CLOSED ⊆-WHITELIST, NOT A DENYLIST
# ----------------------------------------
# A denylist ("fail if `scp-platform/testing` appears") is FAIL-OPEN: a fourth
# nullifier feature, a renamed one, or the transitive `scp-protocol/Cargo.toml`
# `testing = ["scp-did/testing", …]` did:key edge would bypass it. A positive ⊆
# whitelist is CLOSED BY CONSTRUCTION: anything not explicitly permitted fails,
# so novel/future nullifier features are caught without ever being named here.
# The nullifier feature names in NULLIFIER_CONTROL_FEATURES appear ONLY as
# POSITIVE-CONTROL INPUTS the whitelist must reject, and as the input the
# allowlist-hygiene fixture scans this allowlist for — never as the mechanism.
#
# CRITICAL: DEV-DEPENDENCIES ARE EXCLUDED (`no-dev`)
# --------------------------------------------------
# A shipped artifact is built WITHOUT dev-dependencies. `cargo tree` includes
# dev-deps by default (and feature-unifies their `testing` edges into the graph),
# which does NOT reflect what ships. The `no-dev` edge kind restricts the graph to
# the normal + build dependencies that actually compile into the artifact.
#
# CRITICAL: TWO RENDERINGS, BECAUSE `-e features` IS BLIND AT THE ROOT
# -------------------------------------------------------------------
# `cargo tree -e features` prints a `<crate> feature "<name>"` line for a feature
# a DEPENDENCY declaration activates. It prints NO such line for a feature the
# ROOT package of the invocation activates through that package's own
# `[features]` table, because the root's feature nodes sit above the node cargo
# prints as the tree root. The `scp-node` and `scp-relay` entries in ARTIFACTS
# make the root package the artifact itself and pass an EMPTY feature-arg string,
# so their whole nullifier exposure runs through that blind class.
#
# Measured on this workspace with cargo 1.98.0: the feature-edge extraction over
# `-p scp-node` and over `-p scp-node --features testing` produces a
# byte-identical 25-row set, and the whole `--features testing` tree prints the
# string `testing` zero times, although `crates/scp-node/Cargo.toml` declares
# `testing = ["scp-dht/testing", "scp-platform/testing",
# "allow_unencrypted_storage"]`. Cargo does apply the flag — `--features quic`
# pulls `quinn` into the crate graph — so the RESOLUTION is right and only the
# RENDERING omits the root's own activations.
#
# So every resolution below reads TWO renderings of the same non-dev graph and
# checks their UNION (see resolve_feature_set):
#   1. `-e features,no-dev` — feature EDGES. Names an `X/default` edge for a
#      dependency taken with `default-features = true` even when `X` declares no
#      `default` feature (`scp-core` on this tree), which rendering 2 omits.
#   2. `-e no-dev --prefix none --format '{f}|{p}'` — the ENABLED feature set
#      cargo RESOLVED per package, the root included. Names every
#      root-`[features]`-table activation, at any depth.
# Neither rendering contains the other, so the gate reads both. run_gate drives
# two live positive controls over the union, so a cargo release that changes
# either rendering fails this gate instead of quietly emptying it.
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
# carry such a table — scp-protocol, scp-mls, scp-client and scp-client-wasm, all
# on `cfg(target_arch = "wasm32")` — so the construct is in use here today.
# `--target all` resolves the UNION over every triple rather than an enumeration
# of the triples anyone remembered to list, so a triple a build matrix adds
# tomorrow is covered without editing this gate. Measured on this tree, the union
# and the host resolution agree row for row on every artifact, so `--target all`
# costs no false rejection. `assert_every_cargo_tree_resolves_every_target`
# asserts that flag across every shell script under scripts/.
#
# Usage:
#   scripts/check-shipped-feature-graph.sh            # gate the real workspace
#   scripts/check-shipped-feature-graph.sh --self-test # run the fixture harness only
#   scripts/check-shipped-feature-graph.sh --print-artifacts
#       # write the ARTIFACTS array, one entry per line, and run no check
#   scripts/check-shipped-feature-graph.sh --print-wheel-entries
#       # write one `<maturin project file><TAB><ARTIFACTS entry>` line per
#       # MATURIN_PROJECT_FILES entry, and run no check
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# This file's absolute path, fixed before the cd below: a relative
# BASH_SOURCE stops resolving once the working directory moves to the root,
# and the fixtures that read or re-run this file would then read nothing.
GATE_SELF="$REPO_ROOT/scripts/$(basename "${BASH_SOURCE[0]}")"
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
# ELEVEN ROWS NAME A FEATURE A ROOT PACKAGE ACTIVATES THROUGH ITS OWN `[features]`
# TABLE. `cargo tree -e features` renders no feature EDGE for any of them (see
# "TWO RENDERINGS" in the header), so this gate could not observe one until it
# began reading the per-package resolved-feature rendering. Their classification:
#   - `scp-ffi/server`, `scp-ffi-napi/server`, `scp-ffi-uniffi/server` — the
#     production feature each bridge ARTIFACTS entry passes as
#     `--features server`. Each expands to `["scp-ffi-common/server",
#     "dep:scp-node"]`, the real node/relay startup path.
#   - `scp-ffi-common/server` — what those three activate on the shared bridge
#     crate. It pulls the real transport, node, platform and identity crates plus
#     three durability-only `scp-platform` rows this list already carries
#     (`in-memory-storage`, `file`, `encrypting`).
#   - `scp-ffi/default`, `scp-ffi-napi/default`, `scp-ffi-uniffi/default` — each
#     is `["server"]`, which a bare `cargo build` at this root and the three
#     default-feature bridge ARTIFACTS entries resolve.
#   - `scp-ffi/extension-module` — `["pyo3/extension-module"]`, which tells pyo3
#     to leave the Python symbols to the interpreter that loads the cdylib. It
#     activates no SCP-crate feature and no dependency edge.
#   - `scp-ffi/vendored-openssl` — `["scp-platform/vendored-openssl"]`, the
#     wheel-only feature that forwards to the platform crate.
#   - `scp-platform/vendored-openssl` — what `scp-ffi/vendored-openssl`
#     activates on the platform crate. It is
#     `["libsqlite3-sys?/bundled-sqlcipher-vendored-openssl"]`, on an edge the
#     crate declares for non-Apple targets only. For a Linux or Windows target it
#     compiles the same SQLCipher against an OpenSSL this build produces instead
#     of the host's libcrypto; for an Apple target it activates nothing, so
#     SQLCipher built on an Apple host stays on CommonCrypto unless OPENSSL_DIR (or
#     OPENSSL_LIB_DIR plus OPENSSL_INCLUDE_DIR), bare or prefixed with the target
#     triple, is set; and it activates nothing when `sqlite` is off.
#   - `scp-client-wasm/default` — an EMPTY feature list. Cargo reports `default`
#     as enabled on that default member and it activates nothing.
# The `scp-ffi|--features extension-module,vendored-openssl` ARTIFACTS entry, the
# PyPI wheel's configuration read from `[tool.maturin]`, resolves the two
# `scp-ffi` rows above that no other entry reaches. This gate does not read which
# artifacts reach `openssl-src`; see `scripts/check-vendored-openssl-scope.sh`.
# None of the eleven forwards a `testing` edge or an `allow_unencrypted_storage`
# edge. The reader reports cargo's RESOLVED list, so every feature a `default`
# row expands to appears as its own row and meets this ⊆ check on its own —
# permitting a `default` row therefore admits nothing beyond that row.
# NULLIFIER_CONTROL_FEATURES names all five bridge/binary `testing` features, so
# `assert_allowlist_has_no_nullifier` rejects an edit that adds one here.
#
# Ten artifact configurations are gated: the three shipped FFI bridges under
# `--no-default-features --features server`, the same three under their DEFAULT
# features, `scp-core`, the scp-node and scp-relay binaries (built with DEFAULT
# features — neither binary has a `server` feature), and the PyPI wheel under
# `--features extension-module,vendored-openssl`. Each artifact's resolved set is
# the UNION of the two renderings the header describes. This single allowlist is a
# SUPERSET covering all ten plus the bare default-members build — one list
# suffices. `cargo tree` DERIVES each artifact's resolved set (never a hand-list);
# this allowlist is the hand-maintained set of what is PERMITTED.
# ---------------------------------------------------------------------------
PERMITTED_ALLOWLIST="$(cat <<'EOF'
scp-alloc/default
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
scp-ffi/extension-module
scp-ffi/server
scp-ffi/vendored-openssl
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
scp-platform/vendored-openssl
scp-protocol/default
scp-relay-client/default
scp-runtime/default
scp-sqlite-pools/default
scp-transport/default
scp-transport/redb-blob
scp-transport/sqlite-blob
scp-transport/startup
EOF
)"

# ---------------------------------------------------------------------------
# Permitted-production CRATE list (EXPLICIT, closed): the whitelist for the
# crate dimension the header describes.
#
# Every crate an ARTIFACTS graph, or the graph of a package a shipping file
# builds, resolves from a local path source must appear here. `cargo tree`
# DERIVES each graph's reached set; this list is the hand-maintained set of what
# is PERMITTED. It is one SUPERSET list covering every checked graph, and
# run_gate fails on an entry no checked graph reaches, so the list cannot drift
# into naming crates that do not ship.
# NULLIFIER_CONTROL_FEATURES's bare crate entry (`scp-testing`) may never appear
# here; assert_permitted_crates_have_no_nullifier_crate enforces that.
#
# ADDING AN ENTRY IS THE REVIEWABLE ACT. A crate reaches a shipped binary only by
# being named here, so read what it implements before adding it.
# ---------------------------------------------------------------------------
PERMITTED_CRATES="$(cat <<'EOF'
scp-alloc
scp-client
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
scp-sqlite-pools
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
#     `default` block wiring one; scp-relay's `[features]` table holds only the off-by-default `cloud-blobs`),
#     so passing `--features server` here would ERROR — they are correctly gated
#     with an empty feature-arg string, not with `--features server`.
#
# DRIFT, NOW ASSERTED RATHER THAN CAVEATED: each entry's build-invocation string
# above must stay in lockstep with the actual shipped build config, and
# `assert_shipping_invocations_are_gated` reads the three files that carry those
# commands and fails when they drift. The paragraph below names what those files
# build — the Dockerfile
# `cargo build --release -p scp-relay -p scp-node`, a
# `.github/workflows/release.yml` `cargo publish` step, `maturin`'s
# `working-directory: bindings/python` wheel build, and a
# `.github/workflows/build-matrix.yml` "Build shipped bridge artifacts" step,
# which builds one package per invocation into `target-shipped` so its uploaded
# cdylibs resolve those same per-package sets these entries name. Three
# mechanisms keep that lockstep rather than a reader's diligence: a
# `default-members` check in `run_gate` resolves a bare `cargo build` at this
# root, so a member that unifies a nullifier into its siblings fails whether or
# not anyone updates this comment; `assert_shipping_invocations_are_gated` fails
# when a shipping file names a package this gate resolves in no configuration,
# or carries a feature-selection flag nobody declared; and
# `assert_wheel_feature_selection_is_gated` reads the `[tool.maturin]` table of
# every pyproject.toml maturin builds the wheel from (MATURIN_PROJECT_FILES),
# because the maturin step in build-matrix.yml passes no `--features` and
# maturin takes the wheel's cargo feature list from that table, and fails
# unless ARTIFACTS carries the exact configuration that table selects. Today
# that table selects `extension-module`, a pyo3-only feature that changes no
# SCP-crate edge, and `vendored-openssl`, which reaches
# `scp-platform/vendored-openssl` and from there, on a non-Apple target, adds
# `libsqlite3-sys/bundled-sqlcipher-vendored-openssl`. Neither nullifies a
# security property: the first selects a Python linkage, and the second compiles
# the same SQLCipher against an OpenSSL this build produced instead of the host's
# libcrypto on Linux and Windows, and activates nothing on an Apple target. The
# `scp-ffi|--features extension-module,vendored-openssl` entry below is the
# wheel's configuration.
#
# `scripts/check-vendored-openssl-scope.sh` reads this array through
# `--print-artifacts` and the wheel entry through `--print-wheel-entries`, so an
# entry added here reaches that gate on the same commit.
#
# uniffi-bindgen (the third workspace `[[bin]]`, in `crates/scp-ffi/uniffi`) is
# deliberately NOT a separate ARTIFACTS entry: it is a build-time code-generation
# tool, not a shipped runtime artifact, and its dependencies are already covered
# transitively by the `scp-ffi-uniffi` package entry above.
#
# The four DEFAULT-feature entries below mirror the "Build shipped bridge
# artifacts (one package per invocation)" step of
# `.github/workflows/build-matrix.yml`, which runs
# `for pkg in scp-core scp-ffi scp-ffi-napi scp-ffi-uniffi; do cargo build
# --release --target <triple> -p "$pkg" --target-dir target-shipped; done` and
# uploads what it produces, and `.github/workflows/release.yml` signs those
# uploads. That loop passes no `--features` argument, so it resolves each
# package's DEFAULT feature set — a different resolution from the
# `--no-default-features --features server` one the three bridge entries above
# gate, and one nothing gated until these entries existed.
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
  # The PyPI wheel. `maturin_artifact_entry` derives this exact string from the
  # `[tool.maturin]` table of each MATURIN_PROJECT_FILES file, and
  # `assert_wheel_feature_selection_is_gated` fails when the string it derives
  # is not in this list, so an edit to that table changes what this gate
  # resolves or fails the gate.
  "scp-ffi|--features extension-module,vendored-openssl"
)

# ---------------------------------------------------------------------------
# Shipping files: the three files whose cargo invocations compile or publish a
# shipped artifact. assert_shipping_invocations_are_gated reads exactly these.
# ---------------------------------------------------------------------------
SHIPPING_FILES=(
  "Dockerfile"
  ".github/workflows/build-matrix.yml"
  ".github/workflows/release.yml"
)

# ---------------------------------------------------------------------------
# Maturin project files: every pyproject.toml whose `[tool.maturin]` table
# maturin can read when a shipping file runs it. maturin reads the pyproject.toml
# of its working directory when one exists, and otherwise the one beside the
# Cargo.toml its `--manifest-path` names. build-matrix.yml runs maturin with
# `working-directory: bindings/python` and passes no `--manifest-path`, because
# `bindings/python/pyproject.toml` carries a `[tool.maturin] manifest-path` key,
# so that one file is the wheel build's only input. A shipping line that runs
# maturin fails `assert_maturin_project_files_are_complete` when the
# pyproject.toml it reaches exists and this list omits it. A line whose
# pyproject.toml does not exist, such as a `--manifest-path
# crates/scp-ffi/Cargo.toml` argument, reaches no `[tool.maturin]` table, adds no
# feature selection, and passes. The listed table's `features`, `all-features`,
# and `no-default-features` keys select the wheel's cargo features, and the
# maturin step passes no `--features` of its own, so a `testing` entry added to
# that table compiles `scp-platform/testing`, `scp-dht/testing`, and
# `scp-testing` into a published wheel while every line of SHIPPING_FILES stays
# unchanged.
#
# `assert_wheel_feature_selection_is_gated` derives the cargo configuration each
# file selects and fails unless ARTIFACTS carries it verbatim, and
# `assert_maturin_project_files_are_complete` fails when a `--manifest-path` or
# a `working-directory:` line in a shipping file reaches a pyproject.toml this
# list omits, or when this list names a file no shipping line reaches.
# ---------------------------------------------------------------------------
MATURIN_PROJECT_FILES=(
  "bindings/python/pyproject.toml"
)

# Every line of a SHIPPING_FILES file that lines_carrying_cargo_feature_selection
# reads as carrying a cargo feature-selection flag (`--features`, `-F`,
# `--all-features`, `--no-default-features`, in every spelling cargo's option
# grammar admits), normalized to single spaces with leading and trailing
# whitespace removed. A command the file splits with a trailing backslash is
# declared as the one line join_continued_lines makes of it, one space where
# each break was, because that joined line is what the assertion reads.
#
# assert_shipping_invocations_are_gated compares the shipping files against this
# list and FAILS on any difference, in either direction. The two `cargo test`
# lines below compile no shipped artifact, so neither one changes what ARTIFACTS
# must gate. The three PowerShell lines below carry no cargo flag at all: a
# PowerShell parameter is one dash plus a name (`-FilePath`, `-Force`), which is
# the same token as cargo's `-F` with an attached value, and the reader cannot
# tell a PowerShell command from a cargo command without a denylist of command
# words, so it reads the line and a human declares here that it selects no
# feature. A new or edited line the reader reports in any shipping file fails
# this gate until whoever wrote it either declares it here or adds the
# configuration it selects to ARTIFACTS.
#
# `read -d ''` fills the variable instead of `$(cat <<'EOF' …)` because the first
# PowerShell line ends in a literal backtick (PowerShell's line continuation),
# and bash scans the text inside `$( … )` for a matching backtick before it
# honours the quoted heredoc, so that spelling failed to parse. `read -d ''`
# returns 1 at end of input, hence `|| true` under `set -e`.
IFS= read -r -d '' DECLARED_SHIPPING_FEATURE_FLAG_LINES <<'EOF' || true
run: cargo test --workspace --release --target ${{ matrix.target }} --features scp-core/testing,scp-runtime/saga-witness-test-mint
run: cargo test --workspace --release --features scp-ffi-uniffi/testing,scp-ffi/testing,scp-ffi-napi/testing,scp-core/testing,scp-runtime/saga-witness-test-mint
$cert = Import-PfxCertificate -FilePath $certPath `
-Password (ConvertTo-SecureString -String $env:WINDOWS_SIGN_PWD -AsPlainText -Force)
New-Item -ItemType Directory -Force napi-out | Out-Null
EOF

# Every line of a SHIPPING_FILES file that names an SCP package after `-p` while
# compiling no shipped artifact, normalized the same way, and joined the same
# way when the file splits the command with a trailing backslash.
#
# assert_shipping_invocations_are_gated drops these lines before it reads
# package names, and FAILS when a declared line no longer appears in any
# shipping file. The line below runs the conformance suite as a release
# precondition: `cargo nextest run` compiles a test binary,
# `.github/workflows/release.yml` publishes no `scp-testing` crate and uploads
# no artifact built from that command, so the package it names needs no
# ARTIFACTS entry. `scp-testing` is the test-harness crate itself — root
# `Cargo.toml` omits it from `default-members` precisely so its nullifier
# features never unify into a shipped build — so gating it as a shipped artifact
# would assert the opposite of what this gate exists to prove. A `-p` line this
# list does not carry fails the gate until whoever wrote it either adds the
# configuration it builds to ARTIFACTS or declares here why that line ships
# nothing.
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
  "scp-event-log/testing"
  "scp-identity/testing"
  "scp-testing"
  # A root package's own `testing` feature. The feature-EDGE rendering never
  # names one (see "TWO RENDERINGS" in the header), so until the per-package
  # rendering landed no gate run could produce these names and nobody could
  # allowlist one. The per-package rendering produces them, so name them here.
  # Each bridge `testing` feature folds in `scp-platform/testing` +
  # `scp-dht/testing` + `dep:scp-testing`, and `scp-node/testing` folds in
  # `scp-dht/testing` + `scp-platform/testing` + `allow_unencrypted_storage`.
  "scp-ffi/testing"
  "scp-ffi-common/testing"
  "scp-ffi-napi/testing"
  "scp-ffi-uniffi/testing"
  "scp-node/testing"
  # `outlet-capability-test-grant` mints an outlet capability a real
  # authorization path would have to issue, and `saga-witness-test-mint` mints a
  # saga witness the same way. Each returns success for work it did not do, so
  # each is a nullifier (spec §17.17.2). Every crate that re-exports one gate
  # down a dependency chain is named, for the reason the
  # `allow_unencrypted_storage` block below gives.
  "scp-core/outlet-capability-test-grant"
  "scp-runtime/outlet-capability-test-grant"
  "scp-ffi/outlet-capability-test-grant"
  "scp-ffi-napi/outlet-capability-test-grant"
  "scp-ffi-uniffi/outlet-capability-test-grant"
  "scp-runtime/saga-witness-test-mint"
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
# extract_feature_edges <feature-edge-tree>
#   Pure. Emit one `crate/feature` line per FEATURE EDGE that
#   `cargo tree -e features` renders — a line of the form
#   `scp-<crate> feature "<name>"` — sorted-unique.
#
#   WHAT THIS RENDERING CANNOT SEE: cargo renders a feature node for a feature a
#   DEPENDENCY declaration activated, and none for a feature the tree's ROOT
#   package activates through that package's own `[features]` table. Running
#   `cargo tree -e features,no-dev --target all -p scp-node --features testing`
#   on this workspace prints the string `testing` zero times, and the set this
#   function extracts from that tree is byte-identical to the set it extracts
#   without `--features testing`. extract_package_features reads the second
#   rendering, which does carry those features, and merge_resolved_feature_sets
#   unions the two.
#
#   WHAT ONLY THIS RENDERING SEES: cargo renders an `X feature "default"` edge
#   for a dependency taken with `default-features = true` even when `X` declares
#   no `default` feature — `scp-core` on this tree — and the per-package
#   rendering then lists nothing for `X`. Neither rendering contains the other.
# ---------------------------------------------------------------------------
#   grep exits 0 on a match, 1 on no match, and 2 or higher on its own error.
#   Returning a grep error unchanged would make it read as "this rendering names
#   no feature", which drops half of a resolved set while the ⊆ check still
#   prints OK — the same FAIL-OPEN verdict the SIGPIPE comment above
#   tree_names_scp_testing_crate describes. A status above 1 therefore aborts
#   this gate, and a status of 1 prints nothing and returns 0, which
#   merge_resolved_feature_sets then rejects as an empty half.
extract_feature_edges() {
  local matches rc=0
  matches="$(printf '%s\n' "$1" | grep -oE 'scp-[a-z0-9-]+ feature "[^"]+"')" || rc=$?
  if [[ "$rc" -gt 1 ]]; then
    echo "grep failed with status $rc while extracting feature edges from a cargo tree" >&2
    exit 1
  fi
  [[ -z "$matches" ]] && return 0
  printf '%s\n' "$matches" \
    | sed -E 's/ feature "/\//; s/"$//' \
    | sort -u
}

# ---------------------------------------------------------------------------
# extract_package_features <per-package-tree>
#   Pure. Emit one `crate/feature` line per feature cargo ENABLED on every SCP
#   workspace package the tree names, THE ROOT PACKAGE INCLUDED, sorted-unique.
#
#   Input is what `cargo tree --prefix none --format '{f}|{p}'` prints: one line
#   per node, reading `<f1>,<f2>,…|<name> v<version> (<path>)`, where the
#   left-hand list is that package's RESOLVED enabled feature set rather than an
#   edge its parent declared. That is the only cargo rendering in which an
#   artifact's OWN `testing` / `allow_unencrypted_storage` activation appears.
#
#   `{f}` sits BEFORE `{p}` because a feature name never contains `|` while a
#   package's filesystem path may, so splitting on the FIRST `|` is correct by
#   construction. `--prefix none` strips cargo's tree-drawing characters, so
#   every node starts at column 0 and the `^scp-` anchor on the package field
#   rejects an indented line. The ` v` in that anchor separates a package name
#   from a package whose name merely ends in one: `my-scp-node v0.1.0` does not
#   match `^scp-[a-z0-9-]+ v[0-9]`. Cargo appends ` (*)` to a node whose subtree
#   it already printed, and the `sed` below strips that marker before the parse.
#   A package whose resolved list is empty prints a leading `|` and contributes
#   no line.
#
#   The comma list is split in a bash `while` loop rather than in a pipe into
#   `awk`, because `assert_every_pipeline_reader_consumes_its_input` decides its
#   criterion by enumerating the commands this file pipes into, and a bash loop
#   reads its whole input by construction, so splitting here adds no command to
#   that enumeration. The `sed` stage and the closing `sort -u` each read to end
#   of file.
#
#   Fail-closed on a format change: if cargo stops printing this shape, no line
#   matches, the extracted set is EMPTY, and merge_resolved_feature_sets rejects
#   it rather than handing run_gate half a union.
# ---------------------------------------------------------------------------
extract_package_features() {
  local line feats rest name feature
  printf '%s\n' "$1" \
    | sed -E 's/ \(\*\)[[:space:]]*$//' \
    | while IFS= read -r line; do
        [[ "$line" == *"|"* ]] || continue
        feats="${line%%|*}"
        rest="${line#*|}"
        [[ "$rest" =~ ^(scp-[a-z0-9-]+)\ v[0-9] ]] || continue
        name="${BASH_REMATCH[1]}"
        while [[ -n "$feats" ]]; do
          feature="${feats%%,*}"
          if [[ "$feats" == *,* ]]; then feats="${feats#*,}"; else feats=""; fi
          [[ -n "$feature" ]] && printf '%s/%s\n' "$name" "$feature"
        done
      done \
    | sort -u
}

# ---------------------------------------------------------------------------
# merge_resolved_feature_sets <feature-edge-tree> <per-package-tree>
#   Pure. Emit the UNION of both renderings, sorted-unique — one artifact's
#   complete resolved SCP-crate feature set.
#
#   Returns 1 when EITHER rendering yields an empty set. Both legitimately yield
#   a non-empty set for every artifact this gate checks and for a bare
#   default-members build, so an empty one means cargo resolved nothing or a
#   rendering changed shape. Either way the caller fails loud rather than accept
#   a half-empty union that the ⊆ check would still green.
# ---------------------------------------------------------------------------
merge_resolved_feature_sets() {
  local edge_tree="$1" package_tree="$2" edges pkgs
  edges="$(extract_feature_edges "$edge_tree")"
  pkgs="$(extract_package_features "$package_tree")"
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

# ---------------------------------------------------------------------------
# resolve_feature_set <cargo-tree-args...>
#   Run both renderings of one cargo resolution and emit their union.
#   resolve_scp_features and resolve_default_members_features both call this, so
#   the per-artifact path and the default-members path cannot drift apart in
#   what they observe.
#
#   Capture stdout+stderr and the exit status of each rendering. Do NOT swallow
#   a cargo failure silently: if resolution fails (e.g. the feature args name a
#   feature this artifact lacks), surface the cargo error and return non-zero so
#   the caller fails loud instead of proceeding with an empty
#   (vacuously-passing) set.
# ---------------------------------------------------------------------------
resolve_feature_set() {
  local edge_tree package_tree rc
  edge_tree="$(cargo tree -e features,no-dev --target all "$@" 2>&1)"; rc=$?
  if [[ "$rc" -ne 0 ]]; then
    { echo "cargo tree (feature edges) failed for: cargo tree -e features,no-dev --target all $*"
      printf '%s\n' "$edge_tree"; } >&2
    return 1
  fi
  package_tree="$(cargo tree -e no-dev --target all --prefix none --format '{f}|{p}' "$@" 2>&1)"; rc=$?
  if [[ "$rc" -ne 0 ]]; then
    { echo "cargo tree (per-package feature lists) failed for: cargo tree -e no-dev --target all --prefix none --format '{f}|{p}' $*"
      printf '%s\n' "$package_tree"; } >&2
    return 1
  fi
  merge_resolved_feature_sets "$edge_tree" "$package_tree"
}

# ---------------------------------------------------------------------------
# resolve_scp_features <crate> <features...>
#   Emit the COMPLETE resolved SCP-crate feature set of the shipped artifact,
#   one `crate/feature` per line, sorted-unique. Excludes dev-dependencies.
#
#   DELIBERATE SPLIT from resolve_scp_testing_crate (NOT a redundant twin): this
#   reports FEATURES, whereas resolve_scp_testing_crate probes CRATE-NODE
#   presence (`scp-testing v…`) in the `-e no-dev` tree. A `scp-testing` pulled
#   with `default-features = false` and no features enabled contributes no
#   feature edge and an EMPTY resolved feature list here, so neither rendering
#   names it, yet it still appears as a crate node — the two checks catch
#   distinct cases and are both load-bearing.
# ---------------------------------------------------------------------------
resolve_scp_features() {
  local crate="$1"; shift
  local features="$1"
  # shellcheck disable=SC2086
  resolve_feature_set -p "$crate" $features
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
# local_crate_names <node-lines>
#   Pure. Emit, sorted-unique, the name of every crate node in <node-lines> whose
#   WHOLE line carries a local-path source token ` (/`. A node line begins at
#   column 0 with `<name> v<digit>`, which `--prefix none` guarantees.
#
#   STEP 1 selects node lines. cargo's own status output ("Blocking waiting for
#   file lock on package cache", "Locking 2 packages", "Adding foo v0.1.0
#   (/path)") is INDENTED, and an error line begins `error:`, so the column-0
#   `<name> v<digit>` anchor admits no line cargo writes to stderr. The resolver
#   also keeps stderr out of the parsed text; either measure alone suffices.
#   STEP 2 tests the whole selected line for the source token, never its
#   position, because cargo prints `name v1.0 (proc-macro) (/path)` with the
#   marker FIRST, and a draft that anchored the source right after the version
#   dropped every repo-authored proc-macro crate.
#
#   A bash loop reads to end of input, so this adds no command to the set
#   assert_every_pipeline_reader_consumes_its_input enumerates.
# ---------------------------------------------------------------------------
local_crate_names() {
  local line
  while IFS= read -r line; do
    [[ "$line" =~ ^([A-Za-z0-9_-]+)\ v[0-9] ]] || continue
    [[ "$line" == *" (/"* ]] && printf '%s\n' "${BASH_REMATCH[1]}"
  done <<<"$1" | sort -u
}

# ---------------------------------------------------------------------------
# package_tree_node_lines <per-package-tree>
#   Pure. Strip the `<features>|` field from each line of a
#   `--format '{f}|{p}'` tree, leaving the `{p}` node text local_crate_names
#   reads. The split is at the FIRST `|`, which is correct by construction
#   because a feature name never contains `|` while a path may. A line carrying
#   no `|` is not a node of this rendering and is dropped. The edge rendering
#   needs no such step, and must not get one, because its node lines carry no
#   feature field and a path holding `|` would lose its name.
# ---------------------------------------------------------------------------
package_tree_node_lines() {
  local line
  while IFS= read -r line; do
    [[ "$line" == *"|"* ]] && printf '%s\n' "${line#*|}"
  done <<<"$1"
}

# ---------------------------------------------------------------------------
# merge_resolved_crate_sets <edge-tree> <per-package-tree>
#   Pure. Emit the UNION of the local crates both renderings name. Returns 1
#   when EITHER yields an empty set: every artifact reaches at least itself from
#   a local path, so an empty half means cargo resolved nothing or a rendering
#   changed shape, and the caller fails loud instead of accepting half a union.
# ---------------------------------------------------------------------------
merge_resolved_crate_sets() {
  local edge_crates pkg_crates
  edge_crates="$(local_crate_names "$1")"
  pkg_crates="$(local_crate_names "$(package_tree_node_lines "$2")")"
  if [[ -z "$edge_crates" ]]; then
    echo "no local-path crate node appears in the feature-edge rendering this gate resolved" >&2
    return 1
  fi
  if [[ -z "$pkg_crates" ]]; then
    echo "no local-path crate node appears in the per-package rendering this gate resolved" >&2
    return 1
  fi
  printf '%s\n%s\n' "$edge_crates" "$pkg_crates" | sort -u
}

# ---------------------------------------------------------------------------
# resolve_crate_set <cargo-tree-args...>
#   Run both renderings of one non-dev, every-triple resolution and emit the
#   union of the local crates they name. stderr goes to a file this function
#   prints only when cargo FAILED: cargo writes progress to stderr on a
#   successful run, and folding it into the parsed text once produced a crate
#   named `Blocking`. A cargo failure returns non-zero with cargo's message, so
#   it can never read as "no local crate reached".
# ---------------------------------------------------------------------------
resolve_crate_set() {
  local edge_tree package_tree rc err
  err="$(mktemp)"
  edge_tree="$(cargo tree -e features,no-dev --target all --prefix none "$@" 2>"$err")"; rc=$?
  if [[ "$rc" -ne 0 ]]; then
    { echo "cargo tree (crate nodes, feature-edge rendering) failed for: cargo tree -e features,no-dev --target all --prefix none $*"
      cat "$err"; } >&2
    rm -f "$err"
    return 1
  fi
  package_tree="$(cargo tree -e no-dev --target all --prefix none --format '{f}|{p}' "$@" 2>"$err")"; rc=$?
  if [[ "$rc" -ne 0 ]]; then
    { echo "cargo tree (crate nodes, per-package rendering) failed for: cargo tree -e no-dev --target all --prefix none --format '{f}|{p}' $*"
      cat "$err"; } >&2
    rm -f "$err"
    return 1
  fi
  rm -f "$err"
  merge_resolved_crate_sets "$edge_tree" "$package_tree"
}

# ---------------------------------------------------------------------------
# assert_crates_permitted <reached-crates> <permitted-list>
#   Pure. The crate dimension's verdict for one artifact: require the local
#   crates its graph reaches ⊆ <permitted-list>. Prints one OK or FAIL verdict;
#   returns 0 on OK, 1 on FAIL. An empty <reached-crates> FAILS, because every
#   artifact reaches at least itself from a local path. Both inputs are
#   parameters so the fixture harness drives this exact function with the real
#   workspace's resolution and a list that must reject it.
#
#   Each offender's `scp-` prefix, or its absence, is printed as a labelled
#   INDICATOR. The prefix decided nothing: the offender failed because cargo
#   resolved it from a local path and the list does not name it.
# ---------------------------------------------------------------------------
assert_crates_permitted() {
  local reached="$1" permitted="$2" offenders name
  if ! resolution_is_nonempty "$reached"; then
    echo "   FAIL — the local crate set this artifact reaches is EMPTY. Every"
    echo "          artifact reaches at least itself from a local path; refusing"
    echo "          to treat that as 'empty ⊆ PERMITTED_CRATES'."
    return 1
  fi
  if offenders="$(check_subset "$reached" "$permitted")"; then
    echo "   OK — local crates reached ⊆ PERMITTED_CRATES ($(printf '%s\n' "$reached" | grep -c .) crates)"
    return 0
  fi
  echo "   FAIL — local-path crates in the shipped graph that PERMITTED_CRATES does not name:"
  while IFS= read -r name; do
    if [[ "$name" == scp-* ]]; then
      echo "       ✗ $name   (indicator: carries the scp- prefix; the prefix decided nothing)"
    else
      echo "       ✗ $name   (indicator: no scp- prefix; the prefix decided nothing)"
    fi
  done <<<"$offenders"
  echo "   Each crate above was resolved from a local path source. Sever the edge"
  echo "   that pulls it in, or read what it implements and then add it to"
  echo "   PERMITTED_CRATES; a crate enabling no feature is invisible to the"
  echo "   feature check below."
  return 1
}

# ---------------------------------------------------------------------------
# assert_every_permitted_crate_is_reached <reached-union> <permitted-list>
#   Pure. Require <permitted-list> ⊆ <reached-union>, the union of every
#   artifact's reached set. An entry no artifact reaches is a permission nothing
#   uses, and a later edge to that crate would ship without anyone reading it.
#   An EMPTY union FAILS: every artifact's resolution failed, which run_gate has
#   already counted, and this check must not then report the list as tidy.
# ---------------------------------------------------------------------------
assert_every_permitted_crate_is_reached() {
  local union="$1" permitted="$2" unreached
  if ! resolution_is_nonempty "$(printf '%s' "$union" | sed '/^$/d')"; then
    echo "   FAIL — no artifact's local crate set resolved, so no PERMITTED_CRATES"
    echo "          entry can be shown to ship."
    return 1
  fi
  if unreached="$(check_subset "$permitted" "$(printf '%s' "$union" | sed '/^$/d')")"; then
    echo "   OK — every PERMITTED_CRATES entry is reached by a checked graph"
    return 0
  fi
  echo "   FAIL — PERMITTED_CRATES names crates no checked graph reaches:"
  printf '%s\n' "$unreached" | sed 's/^/       ✗ /'
  echo "   Remove each entry above, or add the artifact that ships it to ARTIFACTS."
  return 1
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
#   EVERY DEFAULT MEMBER IS A ROOT PACKAGE of this resolution, so the
#   feature-edge rendering alone omits every feature each member activates
#   through its own `[features]` table. A member that ANOTHER member depends on
#   escaped that blindness incidentally — `crates/scp-ffi` depends on scp-node,
#   so scp-node's feature nodes render inside scp-ffi's subtree — while a member
#   nothing depends on stayed a display root of its own, and `crates/scp-relay`
#   is such a member. This function therefore reads both renderings through
#   resolve_feature_set, the same helper resolve_scp_features calls, so the two
#   paths cannot drift apart in what they observe.
# ---------------------------------------------------------------------------
resolve_default_members_features() {
  resolve_feature_set
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
# assert_resolver_sees_own_feature_table_activation
#   Positive control on the RESOLVER, not on the ⊆ decision procedure. Returns 0
#   when the resolver reports the witness row, 1 when it does not.
#
#   CRITERION: the resolver reports a feature that a shipped artifact's OWN
#   `[features]` table activates on one of that artifact's dependencies. A
#   resolver that reads only the `cargo tree -e features` edge rendering reports
#   nothing for that class, and the two binaries in ARTIFACTS carry an empty
#   feature-arg string, so their entire nullifier exposure runs through it.
#
#   WITNESS: `crates/scp-ffi/Cargo.toml` declares
#   `server = ["scp-ffi-common/server", "dep:scp-node"]`, and this gate builds
#   scp-ffi with `--no-default-features --features server`, so a correct resolver
#   reports `scp-ffi-common/server`. Measured against the edge-only reader this
#   gate used before: `cargo tree -e features,no-dev -p scp-ffi
#   --no-default-features --features server` printed no
#   `scp-ffi-common feature "server"` line at all.
#
#   This control runs BEFORE the artifact loop, so a resolver that has gone blind
#   cannot print ten OK lines ahead of its own failure. Renaming that feature
#   must break this control loudly; re-point the witness at another own-table
#   activation rather than deleting the control.
# ---------------------------------------------------------------------------
assert_resolver_sees_own_feature_table_activation() {
  local witness_crate="scp-ffi"
  local witness_features="--no-default-features --features server"
  local witness_entry="scp-ffi-common/server"
  local resolved rc=0
  echo ">> positive control: the resolver reports a feature an artifact's own [features] table activates on a dependency"
  if ! resolved="$(resolve_scp_features "$witness_crate" "$witness_features")"; then
    echo "   FAIL — the positive-control resolution itself failed for '$witness_crate'."
    return 1
  fi
  printf '%s\n' "$resolved" | grep -xF "$witness_entry" >/dev/null || rc=$?
  if [[ "$rc" -gt 1 ]]; then
    echo "grep failed with status $rc while probing a resolved feature set for '$witness_entry'" >&2
    exit 1
  fi
  if [[ "$rc" -eq 0 ]]; then
    echo "   OK — '$witness_entry' is reported for \`$witness_crate $witness_features\`"
    return 0
  fi
  echo "   FAIL — the resolver did NOT report '$witness_entry' for"
  echo "          \`cargo tree -p $witness_crate $witness_features\`, although"
  echo "          crates/scp-ffi/Cargo.toml declares"
  echo "          server = [\"scp-ffi-common/server\", \"dep:scp-node\"]."
  echo "          A resolver blind to a package's own [features] table cannot see"
  echo "          a nullifier that scp-node or scp-relay enables through its own"
  echo "          manifest — both are gated here with an EMPTY feature-arg string."
  echo "          Read cargo's resolved feature list (--format '{f}|{p}'); do NOT"
  echo "          go back to reading the \`-e features\` edge rendering alone."
  return 1
}

# ---------------------------------------------------------------------------
# assert_positive_control_rejects_nullifier_build
#   REAL-TREE positive control on the whole gate: resolve
#   `scp-node --features testing` through the same union path run_gate uses for a
#   shipped artifact, and require the ⊆ check to REJECT it. Returns 0 on
#   rejection, 1 when that resolution passes the ⊆ check.
#
#   WHY A REAL-TREE CONTROL AND NOT ONLY A SYNTHETIC FIXTURE
#   -------------------------------------------------------
#   The fixture harness drives check_subset with hand-written strings, so it
#   proves the DECISION PROCEDURE rejects a nullifier row. It cannot prove the
#   RESOLUTION produces that row from a real workspace, and that is exactly what
#   broke: `cargo tree -e features,no-dev -p scp-node --features testing`
#   extracted a set byte-identical to the clean resolve, so every synthetic
#   fixture stayed green while the gate could not fail on the regression the
#   scp-node and scp-relay ARTIFACTS entries exist to catch.
#
#   `crates/scp-node/Cargo.toml` declares `testing = ["scp-dht/testing",
#   "scp-platform/testing", "allow_unencrypted_storage"]`, none of which this
#   allowlist admits, so a working gate MUST reject this resolution. A cargo
#   failure here — scp-node losing its `testing` feature — fails the control
#   rather than passing it: an unresolvable control proves nothing.
# ---------------------------------------------------------------------------
assert_positive_control_rejects_nullifier_build() {
  local control_resolved control_offenders
  if ! control_resolved="$(resolve_scp_features scp-node "--features testing")"; then
    echo "   FAIL — the positive control did not resolve. Does 'scp-node' still"
    echo "          declare a 'testing' feature? A control that cannot resolve"
    echo "          proves nothing about whether this gate can fail."
    return 1
  fi
  if control_offenders="$(check_subset "$control_resolved" "$PERMITTED_ALLOWLIST")"; then
    echo "   FAIL — a scp-node build with --features testing passed the ⊆ check."
    echo "          That build compiles InMemoryDhtClient, DhtMode::Memory,"
    echo "          build_memory_did_method and ProtocolRepository::new_for_testing."
    echo "          This gate cannot fail on the regression it exists to catch, so"
    echo "          its OK lines above are a false guarantee. Fix the resolution —"
    echo "          do NOT delete this control."
    return 1
  fi
  echo "   OK — rejected, on $(printf '%s\n' "$control_offenders" | grep -c .) non-allowlisted feature(s):"
  printf '%s\n' "$control_offenders" | sed 's/^/       ✗ /'
  return 0
}

# ---------------------------------------------------------------------------
# Real gate.
# ---------------------------------------------------------------------------
run_gate() {
  local failures=0
  echo "G1 shipped-feature-graph gate (ADR-062 §Decision 6) — dev-deps EXCLUDED"
  echo "-------------------------------------------------------------------------"
  # Prove the resolver still sees the activation class the edge rendering misses
  # BEFORE reading any artifact, so a blind resolver cannot print a run of OK
  # lines ahead of its own failure.
  assert_resolver_sees_own_feature_table_activation || failures=$((failures + 1))
  echo
  local reached_union=""
  for spec in "${ARTIFACTS[@]}"; do
    local crate="${spec%%|*}" features="${spec#*|}"
    echo ">> $crate  ($features)"

    # Crate dimension FIRST, so a feature-dimension `continue` below cannot skip
    # it. A resolution failure FAILS LOUD and contributes nothing to the union.
    local reached
    # shellcheck disable=SC2086
    if reached="$(resolve_crate_set -p "$crate" $features)"; then
      assert_crates_permitted "$reached" "$PERMITTED_CRATES" || failures=$((failures + 1))
      reached_union="$(printf '%s\n%s' "$reached_union" "$reached")"
    else
      echo "   FAIL — the local crate set this artifact reaches did not resolve"
      echo "          (cargo failed or a rendering yielded no local crate node)."
      failures=$((failures + 1))
    fi

    local resolved offenders
    # resolve_scp_features returns non-zero (and surfaces cargo's stderr) if
    # either rendering fails to resolve or yields an empty extraction; the
    # non-empty guard additionally rejects an empty union from any cause. Either
    # way the artifact FAILS LOUD — an empty set must NEVER be accepted as a
    # vacuous "empty ⊆ allowlist" pass.
    if ! resolved="$(resolve_scp_features "$crate" "$features")" \
        || ! resolution_is_nonempty "$resolved"; then
      echo "   FAIL — resolved SCP-crate feature set is EMPTY (cargo resolution"
      echo "          failed, one of the two renderings changed shape, or the"
      echo "          feature args are wrong — e.g. '$features' names a feature"
      echo "          '$crate' does not have). Every gated artifact"
      echo "          configuration legitimately resolves a NON-EMPTY set under"
      echo "          both renderings; refusing to treat an empty resolution as"
      echo "          'empty ⊆ allowlist' PASS."
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
      echo "   The allowlist leaves each of these out, so no shipped artifact may"
      echo "   resolve it. The features the allowlist leaves out include every"
      echo "   test-harness / nullifier feature; scp-transport/postgres-blob and"
      echo "   scp-transport/s3-blob; scp-node/cloud-blobs and scp-relay/cloud-blobs,"
      echo "   the off-by-default features that compile those two backends; and"
      echo "   optional transport features such as scp-node/quic and scp-node/upnp"
      echo "   (ADR-062 §Decision 6 and §Enforcement G1; ZERO-nullifier mandate,"
      echo "   zero nullifier exceptions)."
      failures=$((failures + 1))
    fi
  done

  # Crate dimension for every package a shipping file builds that no
  # default-feature ARTIFACTS entry already resolved. The drift check admits a
  # default-members node as gated, so without this a package built by `-p` from
  # that set would ship with no crate check.
  local shipped_roots root reached
  if ! shipped_roots="$(packages_built_by_shipping_files)"; then
    echo ">> packages built by a shipping file"
    echo "   FAIL — the shipping files could not be read, so the packages they build"
    echo "          got no crate check."
    failures=$((failures + 1))
  else
    for root in $(packages_without_default_artifact_entry "$shipped_roots" "$(printf '%s\n' "${ARTIFACTS[@]}")"); do
      echo ">> $root  (default features; built by a shipping file, no default-feature ARTIFACTS entry)"
      if reached="$(resolve_crate_set -p "$root")"; then
        assert_crates_permitted "$reached" "$PERMITTED_CRATES" || failures=$((failures + 1))
        reached_union="$(printf '%s\n%s' "$reached_union" "$reached")"
      else
        echo "   FAIL — the local crate set this package reaches did not resolve"
        echo "          (cargo failed or a rendering yielded no local crate node)."
        failures=$((failures + 1))
      fi
    done
  fi

  echo ">> PERMITTED_CRATES hygiene  (every entry reached by at least one checked graph)"
  assert_every_permitted_crate_is_reached "$reached_union" "$PERMITTED_CRATES" \
    || failures=$((failures + 1))

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

  # Real-tree positive control — proves the resolution above can actually go red
  # on the workspace this run reads, not only on a synthetic fixture.
  echo ">> positive control  (scp-node --features testing MUST be rejected)"
  assert_positive_control_rejects_nullifier_build || failures=$((failures + 1))

  return "$failures"
}

# ---------------------------------------------------------------------------
# Self-test / fixture harness (AC7 + AC8 behavioral proofs).
# ---------------------------------------------------------------------------
fixture_failures=0
same_string() { # <actual> <expected> — exit 0 iff equal, so a caller reads a command status
  [[ "$1" == "$2" ]]
}
contains_text() { # <text> <fragment> — exit 0 iff <text> contains <fragment>, read as a command status
  [[ "$1" == *"$2"* ]]
}
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
#   pipes into are `grep`, `sed`, `sort`, `comm`, `tr`, and a bash `while` loop,
#   and only `grep` among them offers an early exit: `-q`/`--quiet`/`--silent`
#   stops at a first match, and `-m N`/`--max-count=N` stops at an Nth one.
#   `sed`, `sort`, `comm`, and `tr` read to end of file under every invocation
#   this file writes, and a bash loop reads to end of file by construction.
#
#   `awk` is the one command in that neighbourhood that can stop early on its own
#   program's `exit`, and deciding whether a given awk program reaches `exit`
#   means reading a program that spans lines, which a line-matching grep cannot
#   do. `extract_package_features` therefore splits its comma list in a bash
#   loop, and this fixture rejects a pipe into `awk` outright rather than
#   inspecting one. Rejecting a pipe into `awk` or into `head`, plus those two
#   grep options, decides the criterion rather than sampling spellings of it.
#   Anyone who wants awk here has to state, in this comment, why the program they
#   wrote reads to end of file — and then this fixture needs a rule that reads
#   that program, not this one.
assert_every_pipeline_reader_consumes_its_input() {
  echo ">> fixture: every stage this gate pipes into reads its whole input, so no probe can report SIGPIPE (141) as a verdict"
  local self offenders
  self="$GATE_SELF"
  expect "(sigpipe) the file this fixture scans is this gate, by an absolute path" "PASS" \
    "$([[ "$self" == /* && -r "$self" && "${self##*/}" == "${BASH_SOURCE[0]##*/}" ]] && echo 0 || echo 1)"
  offenders="$(grep -nE '\|[[:space:]]*(head[[:space:]]|awk[[:space:]]|grep[[:space:]]+(-[a-zA-Z]*q|--quiet|--silent|-m[[:space:]]|--max-count))' "$self" \
    | grep -vE '^[0-9]+:[[:space:]]*#' || true)"
  if [[ -n "$offenders" ]]; then
    echo "   FAIL — a pipeline stage below can stop before its writer finishes, so pipefail"
    echo "          reports 141 and the enclosing test reads a match as a NON-match:"
    printf '%s\n' "$offenders" | sed 's/^/       x /'
    echo "          Write 'grep -E ... >/dev/null' and read grep's own status instead."
    echo "          Split a list in a bash loop rather than in a pipe into awk, whose"
    echo "          program can carry an 'exit' that this line-matching check cannot read."
    fixture_failures=$((fixture_failures + 1))
    return
  fi
  echo "   ok   — no pipeline in this gate feeds a reader that can stop early"
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
#   word at a line start, or after `$(`, an unescaped backtick, `|`, `;`, or `&`,
#   and this fixture matches `cargo` at each of those positions. A `\`` sequence
#   is a literal backtick and starts no command, so the `sed` stage below deletes
#   every escaped backtick before the match; it runs line for line, so grep's
#   line numbers still name the source line. Without that stage a prose line
#   quoting a cargo command inside an escaped-backtick pair read as an
#   invocation. It covers scripts/check-protocol-deps.sh as well as this file:
#   that gate proves scp-protocol depends on no tokio / scp-platform / openmls,
#   and crates/scp-protocol/Cargo.toml already carries a
#   `[target.'cfg(target_arch = "wasm32")'.dependencies]` table, so the same
#   host-triple blindness would hide a banned crate declared under a cfg.
assert_every_cargo_tree_resolves_every_target() {
  echo ">> fixture: every cargo tree invocation under scripts/ names --target all, so no cfg-gated dependency edge is invisible to an absence proof"
  local script offenders all_offenders="" cmd_word
  cmd_word='(^|[`;&|]|\$\()[[:space:]]*cargo[[:space:]]+tree[[:space:]]'
  while IFS= read -r script; do
    offenders="$(sed -E 's/\\`//g' "$script" \
      | grep -nE "$cmd_word" \
      | grep -vE '^[0-9]+:[[:space:]]*#' \
      | grep -vF -e '--target all' || true)"
    if [[ -n "$offenders" ]]; then
      all_offenders="$all_offenders$(printf '%s\n' "$offenders" | sed "s|^|${script}:|")
"
    fi
  done < <(find scripts -type f -name '*.sh' | sort)
  if [[ -n "${all_offenders//[[:space:]]/}" ]]; then
    echo "   FAIL — a cargo tree invocation below resolves only the runner's host"
    echo "          triple, so every cfg-gated dependency edge that is false there"
    echo "          is absent from a graph this repository reads as proof:"
    printf '%s\n' "$all_offenders" | sed -E '/^$/d; s/^/       x /'
    echo "          Add '--target all' so cargo resolves the union over every triple."
    fixture_failures=$((fixture_failures + 1))
    return
  fi
  echo "   ok   — every cargo tree invocation under scripts/ resolves every target triple"
}

# assert_print_modes_emit_what_this_gate_holds
#   CRITERION: `--print-artifacts` writes the ARTIFACTS array as bash holds it
#   when main runs, one entry per line and nothing else, and
#   `--print-wheel-entries` writes the entry `maturin_artifact_entry` derives for
#   each MATURIN_PROJECT_FILES file, beside that file's path. Each mode exits
#   non-zero, writing no line, when its array is empty.
#
#   Bash expands every spelling of an assignment before either mode writes a
#   line, so a copy of this file carrying an appended `ARTIFACTS+=(` writes the
#   appended entry, and a copy carrying a second `ARTIFACTS=(` assignment writes
#   the replacement rather than the block this file holds. Each plant copies this
#   file rather than writing a small stand-in, so the fixture states what a caller
#   gets from this gate, including the `cd` it runs before main.
assert_print_modes_emit_what_this_gate_holds() {
  echo ">> fixture: --print-artifacts writes the array bash holds and --print-wheel-entries writes one entry per maturin project file"
  local self expected printed rc plant_dir copy last_line project_file

  self="$GATE_SELF"
  expect "(print-modes) the file this fixture re-runs is this gate, by an absolute path" "PASS" \
    "$([[ "$self" == /* && -r "$self" && "${self##*/}" == "${BASH_SOURCE[0]##*/}" ]] && echo 0 || echo 1)"
  expected="$(printf '%s\n' "${ARTIFACTS[@]}")"
  printed="$(bash "$self" --print-artifacts)"; rc=$?
  expect "(print-modes) --print-artifacts exits 0" "PASS" "$rc"
  same_string "$printed" "$expected"; rc=$?
  expect "(print-modes) its output is the ARTIFACTS array and carries no other line this gate writes" "PASS" "$rc"

  expected="$(for project_file in "${MATURIN_PROJECT_FILES[@]}"; do
    printf '%s\t%s\n' "$project_file" "$(maturin_artifact_entry "$project_file")"
  done)"
  printed="$(bash "$self" --print-wheel-entries)"; rc=$?
  expect "(print-modes) --print-wheel-entries exits 0" "PASS" "$rc"
  same_string "$printed" "$expected"; rc=$?
  expect "(print-modes) its output names each maturin project file and the entry maturin_artifact_entry derives from it" "PASS" "$rc"

  # Each plant deletes the `main "$@"` line, adds an assignment, and writes that
  # line back, so the added assignment runs before main reads the array. A copy
  # whose last line held something else would carry dead code and prove nothing,
  # so this reads the line it is about to delete.
  plant_dir="$(mktemp -d)"
  mkdir -p "$plant_dir/scripts"
  copy="$plant_dir/scripts/gate.sh"
  last_line="$(tail -n 1 "$self")"
  same_string "$last_line" 'main "$@"'; rc=$?
  expect "(print-modes) this file's last line invokes main, which is the line each plant below writes back" "PASS" "$rc"

  sed '$d' "$self" > "$copy"
  printf '%s\n' 'ARTIFACTS+=("planted-appender|")' 'main "$@"' >> "$copy"
  printed="$(bash "$copy" --print-artifacts)"; rc=$?
  expect "(print-modes) a copy carrying an ARTIFACTS+=( appender exits 0" "PASS" "$rc"
  same_string "$printed" "$(printf '%s\n' "${ARTIFACTS[@]}"; echo 'planted-appender|')"; rc=$?
  expect "(print-modes) that copy writes the appended entry" "PASS" "$rc"

  sed '$d' "$self" > "$copy"
  printf '%s\n' 'ARTIFACTS=("planted-second|")' 'main "$@"' >> "$copy"
  printed="$(bash "$copy" --print-artifacts)"; rc=$?
  expect "(print-modes) a copy carrying a second ARTIFACTS=( assignment exits 0" "PASS" "$rc"
  same_string "$printed" "planted-second|"; rc=$?
  expect "(print-modes) that copy writes what bash holds after the second assignment, not the first block" "PASS" "$rc"

  sed '$d' "$self" > "$copy"
  printf '%s\n' 'ARTIFACTS=()' 'main "$@"' >> "$copy"
  # The two empty-array cases also read stderr: bash before 4.4 aborts on an
  # empty "${array[@]}" under `set -u` for a reason of its own, so the exit code
  # alone would not show that the guard in main ran.
  local print_err="$plant_dir/stderr"
  printed="$(bash "$copy" --print-artifacts 2>"$print_err")"; rc=$?
  expect "(print-modes) a copy whose ARTIFACTS is empty FAILS --print-artifacts" "FAIL" "$rc"
  same_string "$printed" ""; rc=$?
  expect "(print-modes) that copy writes no line" "PASS" "$rc"
  same_string "$(cat "$print_err")" "--print-artifacts: ARTIFACTS is empty"; rc=$?
  expect "(print-modes) that copy states ARTIFACTS is empty" "PASS" "$rc"

  sed '$d' "$self" > "$copy"
  printf '%s\n' 'MATURIN_PROJECT_FILES=()' 'main "$@"' >> "$copy"
  printed="$(bash "$copy" --print-wheel-entries 2>"$print_err")"; rc=$?
  expect "(print-modes) a copy whose MATURIN_PROJECT_FILES is empty FAILS --print-wheel-entries" "FAIL" "$rc"
  same_string "$printed" ""; rc=$?
  expect "(print-modes) that copy writes no line" "PASS" "$rc"
  same_string "$(cat "$print_err")" "--print-wheel-entries: MATURIN_PROJECT_FILES is empty"; rc=$?
  expect "(print-modes) that copy states MATURIN_PROJECT_FILES is empty" "PASS" "$rc"

  sed '$d' "$self" > "$copy"
  printf '%s\n' "MATURIN_PROJECT_FILES=(\"$REPO_ROOT/${MATURIN_PROJECT_FILES[0]}\")" 'main "$@"' >> "$copy"
  printed="$(bash "$copy" --print-wheel-entries 2>/dev/null)"; rc=$?
  expect "(print-modes) a copy naming only the first maturin project file by its absolute path exits 0" "PASS" "$rc"
  same_string "$printed" "$REPO_ROOT/${MATURIN_PROJECT_FILES[0]}"$'\t'"$(maturin_artifact_entry "${MATURIN_PROJECT_FILES[0]}")"; rc=$?
  expect "(print-modes) that copy writes the file's line, so the next case's readable file is readable" "PASS" "$rc"

  sed '$d' "$self" > "$copy"
  printf '%s\n' "MATURIN_PROJECT_FILES=(\"$REPO_ROOT/${MATURIN_PROJECT_FILES[0]}\" \"nowhere/pyproject.toml\")" 'main "$@"' >> "$copy"
  printed="$(bash "$copy" --print-wheel-entries 2>/dev/null)"; rc=$?
  expect "(print-modes) a copy naming a maturin project file the reader cannot read FAILS --print-wheel-entries" "FAIL" "$rc"
  same_string "$printed" ""; rc=$?
  expect "(print-modes) that copy writes no line, not even for the readable file listed before the unreadable one" "PASS" "$rc"
  rm -rf "$plant_dir"
}

# ---------------------------------------------------------------------------
# normalize_shipping_lines <text>
#   Emit the lines of <text> with leading and trailing whitespace removed and
#   every internal whitespace run collapsed to one space, empty lines dropped,
#   sorted-unique. Both declaration lists near ARTIFACTS are written in this
#   normalized form, so a line indented inside a YAML `run: |` block compares
#   equal to the declaration a reader wrote flush-left.
# ---------------------------------------------------------------------------
normalize_shipping_lines() {
  printf '%s\n' "$1" \
    | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//; s/[[:space:]]+/ /g; /^$/d' \
    | sort -u
}

# ---------------------------------------------------------------------------
# join_continued_lines <text>
#   Emit the lines of <text> with every line that ends in a backslash joined to
#   the line after it: the backslash goes, the next line's leading whitespace
#   goes, and one space stands where the break was. A Dockerfile `RUN` and a
#   workflow `run:` block both hand their text to a shell, and the shell reads a
#   trailing backslash as a line continuation, so
#
#       cargo build --release -p \
#           scp-testing
#
#   is the one command `cargo build --release -p scp-testing`. The two token
#   readers below walk one line at a time, so without this join the `-p` on the
#   first line receives an empty value, which its caller drops, and the package
#   name on the second line is a token no reader looks at: the package ships
#   under a passing gate. A feature flag split the same way still fails, because
#   the flag itself stays on the first line, so only the package reader was
#   blind, and the join runs before both readers so they read the same command.
#
#   The join fires on every trailing backslash, including one the shell would
#   read as an escaped literal (`\\` at end of line). A join the shell did not
#   perform merges two commands into one line the readers still walk token by
#   token, and a merged line matches no declaration, so that error fails closed.
#   A join the shell did perform and this function did not would fail open, so
#   the function joins on the shell's spelling alone and never declines.
#   PowerShell continues a line with a backtick, which this function does not
#   read, so the PowerShell declarations above stay one line each.
#
#   Pure, so run_fixtures drives it with a split `-p` line and proves the
#   package reader finds the name only after the join.
# ---------------------------------------------------------------------------
join_continued_lines() {
  local line joined="" continuing=0
  while IFS= read -r line; do
    if (( continuing )); then
      line="${line#"${line%%[![:space:]]*}"}"
      joined="$joined $line"
    else
      joined="$line"
    fi
    if [[ "$joined" == *\\ ]]; then
      joined="${joined%\\}"
      joined="${joined%"${joined##*[![:space:]]}"}"
      continuing=1
      continue
    fi
    printf '%s\n' "$joined"
    continuing=0
  done <<<"$1"
  if (( continuing )); then
    printf '%s\n' "$joined"
  fi
}

# ---------------------------------------------------------------------------
# The option grammar cargo's argument parser (clap) accepts. Both readers below
# walk the whitespace-separated tokens of a line under this grammar, so a line
# carries an option when the grammar says it does, whichever of the accepted
# spellings the line uses:
#
#   --<long> VALUE      --<long>=VALUE
#   -<x> VALUE          -<x>VALUE          -<x>=VALUE
#   -ab<x> VALUE        -ab<x>VALUE        -ab<x>=VALUE
#
# The third row is a short-flag cluster: cargo reads each letter as a flag until
# it reaches a letter that takes a value, and that letter consumes the rest of
# the token, or the next token when the rest is empty. cargo rejects an
# abbreviated long option (`cargo build --feat x` exits 1), so the long spelling
# is exact. The readers cannot know which earlier letter of a cluster consumes
# the rest of the token (`-Fp…` is a feature named `p…`, not a package), so they
# read a cluster as carrying <x> whenever <x> appears anywhere in it. That reads
# MORE lines than cargo does, never fewer, and every extra line fails closed:
# an extra feature-flag line has to be declared, and an extra package value
# either fails the `scp-` name filter or fails the gate naming its line.
#
# An earlier revision matched one spelling per option (`-F ` with a following
# space, `-p ` with a following space), so `-Fscp-node/testing` in Dockerfile
# shipped a nullifier feature under a passing gate. The grammar above is what
# cargo accepts, so a spelling that grammar admits is a spelling these readers
# see.
# ---------------------------------------------------------------------------

# cargo_option_values <lines> <long-name> <short-letter>
#   Emit, one per line, the value every occurrence of the option receives on
#   every line of <lines>, under the grammar above. A `--<long>` or a cluster
#   ending in <short-letter> at the end of a line emits an empty value, which
#   every caller drops.
cargo_option_values() {
  local long="$2" short="$3" line tok i n
  local -a toks
  while IFS= read -r line; do
    read -r -a toks <<<"$line"
    n=${#toks[@]}
    for ((i = 0; i < n; i++)); do
      tok="${toks[i]}"
      case "$tok" in
        --"$long")      printf '%s\n' "${toks[i + 1]:-}" ;;
        --"$long"=*)    printf '%s\n' "${tok#--"$long"=}" ;;
        --*)            ;;
        -*"$short")     printf '%s\n' "${toks[i + 1]:-}" ;;
        -*"$short"*)    tok="${tok#*"$short"}"; printf '%s\n' "${tok#=}" ;;
      esac
    done
  done <<<"$1"
}

# lines_carrying_cargo_feature_selection <lines>
#   Emit every line of <lines> that carries a flag which changes cargo's feature
#   resolution: `--features` (with a following or an attached value), `-F` in
#   any short spelling the grammar above admits, `--all-features`, or
#   `--no-default-features`. Those four options are the closed set cargo
#   documents for feature selection; the grammar decides the spellings.
lines_carrying_cargo_feature_selection() {
  local line tok
  local -a toks
  while IFS= read -r line; do
    read -r -a toks <<<"$line"
    for tok in "${toks[@]+"${toks[@]}"}"; do
      case "$tok" in
        --features|--features=*|--all-features|--no-default-features)
          printf '%s\n' "$line"; break ;;
        --*) ;;
        -*F*) printf '%s\n' "$line"; break ;;
      esac
    done
  done <<<"$1"
}

# ---------------------------------------------------------------------------
# packages_built_by_shipping_lines <shipping-lines> <declared-non-shipping-lines>
#   Emit one SCP package name per line, sorted-unique, for every package the
#   shipping lines pass to `-p`/`--package` in any spelling the grammar above
#   admits, or list in a `for pkg in …;` loop, after dropping every line that
#   appears verbatim in <declared-non-shipping-lines>. Both arguments pass
#   through normalize_shipping_lines, so a declaration matches its shipping line
#   whatever indentation that line carries. A value keeps only its package name:
#   surrounding quotes and a `@version` suffix are stripped, and a value that is
#   not an `scp-` name (a shell variable, a `mkdir -p` directory) is dropped.
#
#   The declaration list is what keeps this decidable rather than a guess about
#   which cargo subcommands build something: a `-p` line either names a package
#   this gate resolves, or a human declares in DECLARED_NON_SHIPPING_PACKAGE_LINES
#   why that exact line compiles no shipped artifact. Reading the subcommand
#   instead — `build` ships, `nextest` does not — would be a denylist of
#   spellings, and `cargo run -p scp-ffi-uniffi --bin uniffi-bindgen` already
#   shows a subcommand that neither reading classifies on its name alone.
#
#   Pure, so run_fixtures drives it with synthetic lines, including the case a
#   declared line must NOT suppress.
# ---------------------------------------------------------------------------
packages_built_by_shipping_lines() {
  local kept
  kept="$(comm -23 <(normalize_shipping_lines "$1") <(normalize_shipping_lines "$2"))"
  { cargo_option_values "$kept" package p \
      | sed -E "s/^[\"']//; s/[\"']$//; s/@.*$//" | grep -E '^scp-[a-z0-9-]+$' || true
    printf '%s\n' "$kept" | grep -oE '^for pkg in [a-z0-9 -]+;' \
      | sed -E 's/^for pkg in //; s/;$//' | tr ' ' '\n' || true
  } | sed -E '/^$/d' | sort -u
}

# ---------------------------------------------------------------------------
# packages_built_by_shipping_files
#   The one source of "which SCP packages a shipping file builds": half 1 of
#   assert_shipping_invocations_are_gated and the crate dimension in run_gate
#   both read it. Returns 1, printing the missing path, when a SHIPPING_FILES
#   entry does not exist, so an unread file never reads as "builds nothing".
# ---------------------------------------------------------------------------
packages_built_by_shipping_files() {
  local file
  for file in "${SHIPPING_FILES[@]}"; do
    if [[ ! -f "$file" ]]; then
      echo "shipping file '$file' named by SHIPPING_FILES does not exist" >&2
      return 1
    fi
  done
  packages_built_by_shipping_lines "$(join_continued_lines "$(cat "${SHIPPING_FILES[@]}")")" \
    "$DECLARED_NON_SHIPPING_PACKAGE_LINES"
}

# ---------------------------------------------------------------------------
# packages_without_default_artifact_entry <packages> <artifact-specs>
#   Pure. Emit each of <packages> for which <artifact-specs> (one `crate|args`
#   per line, as ARTIFACTS holds them) carries no exact `<package>|` entry. A
#   shipping line builds its `-p` packages under default features, because
#   assert_shipping_invocations_are_gated half 2 fails on any undeclared
#   feature-selection line, so each package emitted here is one whose
#   default-feature graph no ARTIFACTS entry resolves.
# ---------------------------------------------------------------------------
packages_without_default_artifact_entry() {
  local pkg
  for pkg in $1; do
    printf '%s\n' "$2" | grep -xF "$pkg|" >/dev/null || printf '%s\n' "$pkg"
  done
}

# ---------------------------------------------------------------------------
# The wheel's feature selection lives outside the shipping files. maturin reads
# `features`, `all-features`, and `no-default-features` from the
# `[tool.maturin]` table of a pyproject.toml and passes them to cargo, so the
# functions below read that table, derive the cargo configuration it
# selects, and tie it to an ARTIFACTS entry.
# ---------------------------------------------------------------------------

# maturin_project_files_named_by_shipping_lines <shipping-lines>
#   Emit, sorted-unique, every repository-relative pyproject.toml that exists
#   beside a Cargo.toml a shipping line passes to `--manifest-path`, or inside a
#   directory a shipping line names after `working-directory:`. Those are the
#   two places maturin looks for its pyproject.toml, so a pyproject.toml this
#   function does not emit is one no shipping-file maturin step can read.
#   Pure over its argument, apart from the existence test on each candidate.
maturin_project_files_named_by_shipping_lines() {
  local line tok i n candidate
  local -a toks
  while IFS= read -r line; do
    read -r -a toks <<<"$line"
    n=${#toks[@]}
    for ((i = 0; i < n; i++)); do
      tok="${toks[i]}"
      candidate=""
      case "$tok" in
        --manifest-path)   candidate="$(dirname "${toks[i + 1]:-.}")/pyproject.toml" ;;
        --manifest-path=*) candidate="$(dirname "${tok#--manifest-path=}")/pyproject.toml" ;;
        working-directory:) candidate="${toks[i + 1]:-.}/pyproject.toml" ;;
      esac
      if [[ -n "$candidate" && -f "$candidate" ]]; then printf '%s\n' "$candidate"; fi
    done
  done <<<"$1" | sed -E 's#^\./##; /^$/d' | sort -u
}

# The program that derives a wheel's ARTIFACTS entry from a maturin project file.
#
# CRITERION: it reports the cargo configuration maturin compiles, for every TOML
# spelling of that project file, or it fails.
#
# `tomllib` decides what the document says, so `[tool.maturin]`, `[tool."maturin"]`,
# `tool.maturin.features = […]`, and `maturin = { features = […] }` are four
# spellings of one table and reach one code path. A reader that matches the table
# header as source text reads `[tool."maturin"]`, which is valid TOML naming the
# table maturin reads, as an absent table, and derives `scp-ffi|`, an ARTIFACTS
# entry this gate holds, from a document selecting `testing`.
#
# The keys of the table are a positive whitelist, MATURIN_KEYS. maturin passes
# more of that table to cargo than the feature keys: `rustc-args` reaches rustc
# (`--cfg feature="testing"` compiles `testing` code that cargo's feature
# resolution never sees), `config` overrides cargo configuration, and `profile`,
# `target`, `unstable-flags` and more change the build. The program therefore
# fails on any key outside MATURIN_KEYS: the four it interprets, and
# `module-name`, `python-source`, `python-packages`, `include` and `exclude`,
# which place files in the wheel and select no compilation. A subtable of
# `[tool.maturin]` is a key too, so it fails the same way. A key maturin adds
# later fails here until someone classifies it into that set.
#
# The program reads the `[package] name` of the manifest with the same parser.
#
# It writes the entry in the spelling ARTIFACTS uses: `--all-features`, then
# `--no-default-features`, then `--features a,b`, each present only when the table
# selects it. It fails on a `tool` that is not a table, on a `[tool.maturin]` that
# is not a table, on a `features` that is not an array of strings, on a feature
# name outside FEATURE_NAME (an empty name or one carrying whitespace, which
# cargo would split or drop), on an `all-features` or `no-default-features` that
# is not a boolean, on a `manifest-path` that is not a string, on a project file
# or manifest it cannot read or parse, and on a manifest carrying no
# `[package] name` — because a value this reader cannot interpret must not read
# as "no features selected".
read -r -d '' MATURIN_ENTRY_PROGRAM <<'PYTHON' || true
import os
import re
import sys
import tomllib

MATURIN_KEYS = frozenset(
    {
        "all-features",
        "no-default-features",
        "features",
        "manifest-path",
        "module-name",
        "python-source",
        "python-packages",
        "include",
        "exclude",
    }
)
FEATURE_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_+./?-]*")


def fail(message):
    print(message, file=sys.stderr)
    raise SystemExit(1)


def load(path, what):
    try:
        with open(path, "rb") as handle:
            return tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        fail(f"{project_file}: {what} {path}: {error}")


project_file = sys.argv[1]
document = load(project_file, "cannot read maturin project file")

tool = document.get("tool", {})
if not isinstance(tool, dict):
    fail(f"{project_file}: tool is not a table")
table = tool.get("maturin", {})
if not isinstance(table, dict):
    fail(f"{project_file}: [tool.maturin] is not a table")

unclassified = sorted(set(table) - MATURIN_KEYS)
if unclassified:
    fail(
        f"{project_file}: [tool.maturin] names key(s) this reader does not classify: {', '.join(unclassified)}"
    )

args = []
for key in ("all-features", "no-default-features"):
    if key in table:
        value = table[key]
        if not isinstance(value, bool):
            fail(f"{project_file}: {key} is not a TOML boolean")
        if value:
            args.append(f"--{key}")

if "features" in table:
    features = table["features"]
    if not isinstance(features, list) or not all(
        isinstance(name, str) for name in features
    ):
        fail(f"{project_file}: features is not a TOML array of strings")
    malformed = [name for name in features if not FEATURE_NAME.fullmatch(name)]
    if malformed:
        fail(
            f"{project_file}: features holds name(s) that are not a cargo feature spelling: {malformed!r}"
        )
    if features:
        args.append("--features " + ",".join(features))

manifest = table.get("manifest-path", "Cargo.toml")
if not isinstance(manifest, str):
    fail(f"{project_file}: manifest-path is not a TOML string")
if not os.path.isabs(manifest):
    manifest = os.path.join(os.path.dirname(project_file) or ".", manifest)

package = load(manifest, "manifest-path names no manifest this reader can read:").get(
    "package"
)
name = package.get("name") if isinstance(package, dict) else None
if not isinstance(name, str) or not name:
    fail(f"{project_file}: {manifest} carries no [package] name")

print(f"{name}|{' '.join(args)}")
PYTHON

# maturin_artifact_entry <pyproject.toml>
#   Emit the ARTIFACTS entry (`<package>|<feature-args>`) the file's
#   `[tool.maturin]` table makes maturin build: the package is the `[package]
#   name` of the Cargo.toml the table's `manifest-path` names, resolved against
#   the pyproject.toml's directory, or of the Cargo.toml beside the
#   pyproject.toml when the table names none. FAILS (non-zero, reason on stderr)
#   on anything MATURIN_ENTRY_PROGRAM above fails on, and when python3.12, the
#   interpreter AGENTS.md §Toolchain names, is absent or cannot import tomllib.
#   `-P` keeps the working directory off sys.path, so no tomllib.py there
#   replaces the parser.
maturin_artifact_entry() {
  python3.12 -P -c "$MATURIN_ENTRY_PROGRAM" "$1"
}

# assert_wheel_feature_selection_is_gated <pyproject.toml>...
#   CRITERION: for every file given, the configuration its `[tool.maturin]`
#   table makes maturin build appears verbatim in ARTIFACTS, so run_gate
#   resolves exactly what the wheel compiles. A file the reader cannot parse
#   fails; a configuration ARTIFACTS lacks fails and names the entry to add,
#   after which run_gate's allowlist decides whether that configuration ships.
#   Takes its files as arguments so run_fixtures can prove, on a planted file,
#   that the assertion goes red.
assert_wheel_feature_selection_is_gated() {
  echo ">> fixture: the cargo configuration each maturin project file selects for the wheel is an ARTIFACTS entry (drift between ARTIFACTS and [tool.maturin])"
  local file entry spec found
  for file in "$@"; do
    if ! entry="$(maturin_artifact_entry "$file" 2>&1)"; then
      echo "   FAIL — cannot derive the wheel configuration from $file:"
      printf '%s\n' "$entry" | sed 's/^/       /'
      echo "          A maturin project file this gate cannot read leaves the wheel's feature list ungated."
      fixture_failures=$((fixture_failures + 1))
      return
    fi
    found=0
    for spec in "${ARTIFACTS[@]}"; do
      if [[ "$spec" == "$entry" ]]; then found=1; fi
    done
    if [[ "$found" -eq 0 ]]; then
      echo "   FAIL — $file makes maturin build a configuration ARTIFACTS does not gate:"
      echo "       x $entry"
      echo "          Add that exact entry to ARTIFACTS so run_gate resolves what the wheel"
      echo "          compiles; the permitted-production allowlist then decides whether it ships."
      fixture_failures=$((fixture_failures + 1))
      return
    fi
  done
  echo "   ok   — every maturin project file selects a configuration ARTIFACTS gates"
}

# assert_maturin_project_files_are_complete
#   CRITERION: the set of pyproject.toml files a shipping-file maturin step can
#   read (maturin_project_files_named_by_shipping_lines over SHIPPING_FILES)
#   equals MATURIN_PROJECT_FILES. A reachable file the list omits fails, because
#   assert_wheel_feature_selection_is_gated never reads it; a listed file no
#   shipping line reaches fails, because a stale entry describes no build.
assert_maturin_project_files_are_complete() {
  echo ">> fixture: every pyproject.toml a shipping-file maturin step can read is a MATURIN_PROJECT_FILES entry, and each entry is reachable"
  local named unlisted stale
  named="$(maturin_project_files_named_by_shipping_lines "$(cat "${SHIPPING_FILES[@]}")")"
  unlisted="$(comm -23 <(printf '%s\n' "$named" | sed -E '/^$/d' | sort -u) \
                       <(printf '%s\n' "${MATURIN_PROJECT_FILES[@]}" | sort -u))"
  if [[ -n "$unlisted" ]]; then
    echo "   FAIL — a shipping file reaches pyproject.toml file(s) MATURIN_PROJECT_FILES omits:"
    printf '%s\n' "$unlisted" | sed 's/^/       x /'
    echo "          Add each one so its [tool.maturin] feature selection is read."
    fixture_failures=$((fixture_failures + 1))
    return
  fi
  stale="$(comm -13 <(printf '%s\n' "$named" | sed -E '/^$/d' | sort -u) \
                    <(printf '%s\n' "${MATURIN_PROJECT_FILES[@]}" | sort -u))"
  if [[ -n "$stale" ]]; then
    echo "   FAIL — MATURIN_PROJECT_FILES names file(s) no shipping line reaches:"
    printf '%s\n' "$stale" | sed 's/^/       x /'
    echo "          A stale entry describes no wheel build; remove it or restore the line that reads it."
    fixture_failures=$((fixture_failures + 1))
    return
  fi
  echo "   ok   — MATURIN_PROJECT_FILES equals the pyproject.toml files the shipping files reach"
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
#        options that changes cargo's feature resolution is closed —
#        `--features`, `-F`, `--all-features`, `--no-default-features` — and
#        lines_carrying_cargo_feature_selection reads each one in every spelling
#        cargo's option grammar admits (`-F x`, `-Fx`, `-F=x`, `-qFx`,
#        `--features=x`), so the grammar decides the criterion instead of one
#        sampled spelling per option. Whoever adds a fifth option to cargo also
#        has to add it there, and until then an undeclared flag line fails this
#        gate.
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
  if ! dm_tree="$(cargo tree -e no-dev --target all --prefix none -f "{p}" 2>&1)"; then
    echo "   FAIL — cargo could not resolve the default-members tree this fixture reads:"
    printf '%s\n' "$dm_tree" | sed 's/^/       /'
    fixture_failures=$((fixture_failures + 1))
    return
  fi
  gated_packages="$gated_packages
$(printf '%s\n' "$dm_tree" | sed -E -n 's/^(scp-[a-z0-9-]+) v[0-9].*/\1/p')"
  gated_packages="$(printf '%s\n' "$gated_packages" | sed -E '/^$/d' | sort -u)"

  local shipping_lines built_packages ungated="" stale_pkg_lines
  # Joined once here, so half 1, half 2, and both stale-declaration checks read
  # the same command the shell runs, whatever line breaks the file spells it with.
  shipping_lines="$(join_continued_lines "$(cat "${SHIPPING_FILES[@]}")")"
  built_packages="$(packages_built_by_shipping_files)"
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
  flag_lines="$(normalize_shipping_lines "$(lines_carrying_cargo_feature_selection "$shipping_lines")")"
  undeclared="$(comm -23 <(printf '%s\n' "$flag_lines" | sed -E '/^$/d' | sort -u) \
                         <(printf '%s\n' "$DECLARED_SHIPPING_FEATURE_FLAG_LINES" | sed -E '/^$/d' | sort -u))"
  if [[ -n "$undeclared" ]]; then
    echo "   FAIL — a shipping file carries a cargo feature-selection flag this gate never declared:"
    printf '%s\n' "$undeclared" | sed 's/^/       x /'
    echo "          Either that line builds a shipped artifact — then gate its configuration in"
    echo "          ARTIFACTS — or it builds no shipped artifact (a test run, or a non-cargo"
    echo "          command whose single-dash parameter spells cargo's -F), and belongs in"
    echo "          DECLARED_SHIPPING_FEATURE_FLAG_LINES with the reason it selects no feature."
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

# assert_permitted_crates_have_no_nullifier_crate <permitted-crate-list>
#   Every NULLIFIER_CONTROL_FEATURES entry without a `/` names a whole crate
#   (`scp-testing`), and none may appear on <permitted-crate-list>. Increments
#   fixture_failures per crate found; the harness also drives it with a planted
#   list that must fail.
assert_permitted_crates_have_no_nullifier_crate() {
  local permitted="$1" nf found=0
  for nf in "${NULLIFIER_CONTROL_FEATURES[@]}"; do
    [[ "$nf" == */* ]] && continue
    # `grep -xF … >/dev/null`, not `grep -q`, for the SIGPIPE reason above.
    if printf '%s\n' "$permitted" | grep -xF "$nf" >/dev/null; then
      echo "   FAIL — nullifier crate '$nf' is on PERMITTED_CRATES (forbidden exception)"
      fixture_failures=$((fixture_failures + 1))
      found=1
    fi
  done
  [[ "$found" -eq 0 ]] && echo "   ok   — no NULLIFIER_CONTROL_FEATURES crate entry appears on PERMITTED_CRATES"
}

# run_crate_dimension_fixtures
#   Behavioral proofs for the crate dimension: the provenance extractor, both
#   renderings' merge, the closed ⊆ verdict against this workspace's real
#   resolution, the hygiene check, and the nullifier-crate exclusion.
run_crate_dimension_fixtures() {
  local rc out names

  # (crate-provenance) local_crate_names keeps a crate exactly when its node line
  #     carries a local-path source token. The input mixes every shape the
  #     extractor must classify: cargo's indented stderr status lines and an
  #     `error:` line, a vendor/ path crate, a path proc-macro whose marker
  #     precedes its source, a workspace member, a registry crate (`axum`), a
  #     registry proc-macro, a crate served through a `directory` source
  #     replacement (`vfoo`, printed exactly like a registry crate; measured with
  #     cargo 1.97.1), a registry crate whose name carries the scp- prefix, and a
  #     feature-edge row.
  local mixed
  mixed="$(printf '%s\n' \
    '    Blocking waiting for file lock on package cache' \
    '    Updating crates.io index' \
    '      Adding limn-attest v0.1.0 (/repo/vendor/limn-attest)' \
    '      Adding stderr-only-crate v0.1.0 (/repo/vendor/stderr-only-crate)' \
    'error: failed to select a version' \
    'limn-attest v0.1.0 (/repo/vendor/limn-attest)' \
    'limn-attest-derive v0.1.0-beta.2+build.1 (proc-macro) (/repo/vendor/limn-attest-derive) (*)' \
    'scp-core v0.1.0-beta.2 (/repo/crates/scp-core) (*)' \
    'scp-core feature "default"' \
    'scp-published-elsewhere v9.9.9' \
    'axum v0.8.8' \
    'tracing-attributes v0.1.31 (proc-macro)' \
    'vfoo v0.1.0')"
  names="$(local_crate_names "$mixed")"
  same_string "$names" "$(printf '%s\n' limn-attest limn-attest-derive scp-core)"; rc=$?
  expect "(crate-provenance) exactly the local-path nodes are kept: a vendor/ crate, a path proc-macro, a member" "PASS" "$rc"
  printf '%s\n' "$names" | grep -xF 'limn-attest-derive' >/dev/null; rc=$?
  expect "(crate-provenance) a path proc-macro, source token after its (proc-macro) marker, COUNTS as local" "PASS" "$rc"
  # Where a fixture expects grep to find NOTHING, a grep error (rc 2) is mapped
  # to rc 0, so a broken grep fails that fixture instead of meeting it.
  printf '%s\n' "$names" | grep -xF 'vfoo' >/dev/null; rc=$?; [[ "$rc" -gt 1 ]] && rc=0
  expect "(crate-provenance) a vendored registry crate (directory source, no source token) does NOT count" "FAIL" "$rc"
  printf '%s\n' "$names" | grep -xF 'scp-published-elsewhere' >/dev/null; rc=$?; [[ "$rc" -gt 1 ]] && rc=0
  expect "(crate-provenance) a registry crate carrying the scp- prefix does NOT count: the prefix decides nothing" "FAIL" "$rc"
  printf '%s\n' "$names" | grep -xE 'Blocking|Updating|Adding|error:?|stderr-only-crate' >/dev/null; rc=$?; [[ "$rc" -gt 1 ]] && rc=0
  expect "(crate-provenance) cargo's stderr status and error lines contribute no crate" "FAIL" "$rc"

  # (crate-provenance, per-package) the `{f}|{p}` rendering: a feature list, a
  #     root with no feature (empty field), and a path proc-macro.
  local pkg_tree
  pkg_tree="$(printf '%s\n' \
    'default,std|scp-core v0.1.0-beta.2 (/repo/crates/scp-core)' \
    '|scp-relay v0.1.0-beta.2 (/repo/crates/scp-relay)' \
    '|limn-attest-derive v0.1.0 (proc-macro) (/repo/vendor/limn-attest-derive) (*)' \
    'default|axum v0.8.8' \
    '|vfoo v0.1.0')"
  same_string "$(local_crate_names "$(package_tree_node_lines "$pkg_tree")")" \
              "$(printf '%s\n' limn-attest-derive scp-core scp-relay)"; rc=$?
  expect "(crate-provenance, per-package) the {f}|{p} rendering yields the same classification" "PASS" "$rc"

  # (crate-merge) each rendering must contribute; an empty half FAILS.
  merge_resolved_crate_sets "$mixed" "" >/dev/null 2>&1; rc=$?
  expect "(crate-merge) an empty per-package half is REJECTED" "FAIL" "$rc"
  merge_resolved_crate_sets "axum v0.8.8" "$pkg_tree" >/dev/null 2>&1; rc=$?
  expect "(crate-merge) an edge half with no local-path node is REJECTED" "FAIL" "$rc"
  out="$(merge_resolved_crate_sets "$mixed" "$pkg_tree")"; rc=$?
  expect "(crate-merge) two non-empty halves merge" "PASS" "$rc"
  same_string "$out" "$(printf '%s\n' limn-attest limn-attest-derive scp-core scp-relay)"; rc=$?
  expect "(crate-merge) the merge is the union of both halves" "PASS" "$rc"

  # (crate-closed) the ⊆ verdict, synthetic.
  assert_crates_permitted "" "$PERMITTED_CRATES" >/dev/null; rc=$?
  expect "(crate-closed) an EMPTY reached set is REJECTED, never 'empty ⊆ list'" "FAIL" "$rc"
  out="$(assert_crates_permitted "$(printf '%s\n' scp-core limn-attest)" "scp-core")"; rc=$?
  expect "(crate-closed) a novel local crate WITHOUT the scp- prefix is REJECTED" "FAIL" "$rc"
  contains_text "$out" "✗ limn-attest   (indicator: no scp- prefix"; rc=$?
  expect "(crate-closed) the offender is named and its prefix shown only as an indicator" "PASS" "$rc"

  # (crate-closed, real tree) this workspace's own resolution of scp-relay.
  #     scp-relay enables none of its features in this build, so the feature
  #     dimension resolves no scp-relay/ row for it: the blind spot this
  #     dimension closes. The crate dimension must see scp-relay, accept the
  #     resolution against PERMITTED_CRATES, and REJECT it against a list derived
  #     from the resolution minus scp-relay.
  local relay_crates relay_features trimmed
  if ! relay_crates="$(resolve_crate_set -p scp-relay 2>&1)"; then
    echo "   FAIL — (crate-closed, real tree) resolve_crate_set -p scp-relay failed:"
    printf '%s\n' "$relay_crates" | sed 's/^/       /'
    fixture_failures=$((fixture_failures + 1))
  else
    printf '%s\n' "$relay_crates" | grep -xF 'scp-relay' >/dev/null; rc=$?
    expect "(crate-closed, real tree) the crate dimension sees scp-relay in its own graph" "PASS" "$rc"
    if relay_features="$(resolve_scp_features scp-relay "" 2>/dev/null)"; then
      printf '%s\n' "$relay_features" | grep '^scp-relay/' >/dev/null; rc=$?
      [[ "$rc" -gt 1 ]] && rc=0
      expect "(crate-closed, real tree) the feature dimension resolves no scp-relay/ row for that same graph" "FAIL" "$rc"
    else
      echo "   FAIL — (crate-closed, real tree) resolve_scp_features scp-relay failed"
      fixture_failures=$((fixture_failures + 1))
    fi
    assert_crates_permitted "$relay_crates" "$PERMITTED_CRATES" >/dev/null; rc=$?
    expect "(crate-closed, real tree) scp-relay's reached crates ⊆ PERMITTED_CRATES" "PASS" "$rc"
    trimmed="$(printf '%s\n' "$relay_crates" | grep -vxF 'scp-relay')"
    out="$(assert_crates_permitted "$relay_crates" "$trimmed")"; rc=$?
    expect "(crate-closed, real tree) a list omitting a reached local crate is REJECTED" "FAIL" "$rc"
    contains_text "$out" "✗ scp-relay "; rc=$?
    expect "(crate-closed, real tree) that rejection names scp-relay" "PASS" "$rc"
  fi

  # (crate-hygiene) every PERMITTED_CRATES entry must be reached.
  assert_every_permitted_crate_is_reached "$(printf '%s\n' scp-a scp-b)" "$(printf '%s\n' scp-a scp-b scp-c)" >/dev/null; rc=$?
  expect "(crate-hygiene) a permitted crate no artifact reaches is REJECTED" "FAIL" "$rc"
  assert_every_permitted_crate_is_reached "$(printf '\n\n')" "scp-a" >/dev/null; rc=$?
  expect "(crate-hygiene) an empty reached union is REJECTED" "FAIL" "$rc"
  assert_every_permitted_crate_is_reached "$(printf '%s\n' scp-a scp-b scp-c)" "$(printf '%s\n' scp-a scp-b)" >/dev/null; rc=$?
  expect "(crate-hygiene) a list every entry of which is reached is ACCEPTED" "PASS" "$rc"

  # (crate-roots) packages_without_default_artifact_entry picks the shipping-file
  #     packages whose default-feature graph no ARTIFACTS entry resolves: a
  #     package with an exact `pkg|` entry is dropped, and a package whose only
  #     entry selects other features is kept.
  out="$(packages_without_default_artifact_entry "scp-core scp-ffi scp-client" \
           "$(printf '%s\n' 'scp-core|' 'scp-ffi|--no-default-features --features server')")"
  same_string "$out" "$(printf '%s\n' scp-ffi scp-client)"; rc=$?
  expect "(crate-roots) a package without an exact default-feature ARTIFACTS entry is kept for the crate check" "PASS" "$rc"
  out="$(packages_without_default_artifact_entry "scp-core" "scp-core|")"
  same_string "$out" ""; rc=$?
  expect "(crate-roots) a package with an exact default-feature ARTIFACTS entry is not checked twice" "PASS" "$rc"

  # (crate-roots, shipping files) the one reader of the shipping files fails on
  #     an unreadable file and, on this tree, sees the published scp-client,
  #     which no ARTIFACTS entry names.
  ( SHIPPING_FILES=("no-such-shipping-file.yml"); packages_built_by_shipping_files >/dev/null 2>&1 ); rc=$?
  expect "(crate-roots, shipping files) a missing shipping file is REJECTED, never read as 'builds nothing'" "FAIL" "$rc"
  if out="$(packages_built_by_shipping_files)"; then
    printf '%s\n' "$(packages_without_default_artifact_entry "$out" "$(printf '%s\n' "${ARTIFACTS[@]}")")" \
      | grep -xF 'scp-client' >/dev/null; rc=$?
  else
    rc=1
  fi
  expect "(crate-roots, shipping files) scp-client, published by release.yml with no ARTIFACTS entry, gets a crate check" "PASS" "$rc"

  # (crate-roots, real tree) a shipping line that builds the test-only
  #     default member scp-relay-mock passes the drift check as a default-members
  #     node; the crate check on that package must REJECT it.
  local mock_roots mock_crates
  mock_roots="$(packages_without_default_artifact_entry \
                  "$(packages_built_by_shipping_lines 'RUN cargo build --release -p scp-relay-mock' '')" \
                  "$(printf '%s\n' "${ARTIFACTS[@]}")")"
  same_string "$mock_roots" "scp-relay-mock"; rc=$?
  expect "(crate-roots, real tree) a -p build of scp-relay-mock is selected for the crate check" "PASS" "$rc"
  if mock_crates="$(resolve_crate_set -p scp-relay-mock 2>&1)"; then
    out="$(assert_crates_permitted "$mock_crates" "$PERMITTED_CRATES")"; rc=$?
    expect "(crate-roots, real tree) scp-relay-mock's crate set is REJECTED against PERMITTED_CRATES" "FAIL" "$rc"
    contains_text "$out" "✗ scp-relay-mock "; rc=$?
    expect "(crate-roots, real tree) that rejection names scp-relay-mock" "PASS" "$rc"
  else
    echo "   FAIL — (crate-roots, real tree) resolve_crate_set -p scp-relay-mock failed:"
    printf '%s\n' "$mock_crates" | sed 's/^/       /'
    fixture_failures=$((fixture_failures + 1))
  fi

  # (crate-nullifier) the exclusion check must fire on a planted list.
  ( fixture_failures=0
    assert_permitted_crates_have_no_nullifier_crate "$(printf '%s\nscp-testing' "$PERMITTED_CRATES")" >/dev/null
    exit "$fixture_failures" ); rc=$?
  expect "(crate-nullifier) a PERMITTED_CRATES carrying scp-testing is REJECTED" "FAIL" "$rc"
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
            "scp-ffi-uniffi/testing" "scp-ffi-common/testing" \
            "scp-event-log/testing" "scp-identity/testing" \
            "scp-core/outlet-capability-test-grant" \
            "scp-runtime/saga-witness-test-mint"; do
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

  # (root-blindness) The per-package rendering must read a ROOT package's own
  #     `[features]`-table activations, at every depth, and the ⊆ check must then
  #     reject them. `cargo tree -e features` renders none of these rows, so the
  #     edge extraction alone reported ABSENCE for a build carrying four
  #     nullifiers. The two synthetic trees below are the shapes cargo prints for
  #     `-p scp-node --features testing`: the edge tree names no `testing`
  #     anywhere, and the per-package tree carries the root's own row first, a
  #     repeated node with cargo's ` (*)` marker, a package with no enabled
  #     feature, a non-SCP package, a package whose name merely ends in an SCP
  #     crate name, and an indented line `--prefix none` would never print.
  local edge_tree pkg_tree edges pkgs merged
  edge_tree="$(cat <<'TREE'
scp-node v0.1.0-beta.2 (/w/crates/scp-node)
├── scp-core feature "default"
│   └── scp-core v0.1.0-beta.2 (/w/crates/scp-core)
└── scp-platform feature "sqlite"
    └── scp-platform v0.1.0-beta.2 (/w/crates/scp-platform)
TREE
)"
  pkg_tree="$(cat <<'TREE'
allow_unencrypted_storage,testing|scp-node v0.1.0-beta.2 (/w/crates/scp-node)
default,production-dht,testing|scp-dht v0.1.0-beta.2 (/w/crates/scp-dht)
sqlite,testing|scp-platform v0.1.0-beta.2 (/w/crates/scp-platform) (*)
allow_unencrypted_storage|scp-runtime v0.1.0-beta.2 (/w/crates/scp-runtime)
|scp-crypto v0.1.0-beta.2 (/w/crates/scp-crypto)
full,macros|tokio v1.49.0
testing|my-scp-node v0.1.0 (/w/vendor)
testing|   +-- scp-media v0.1.0-beta.2 (/w/crates/scp-media)
TREE
)"

  edges="$(extract_feature_edges "$edge_tree")"
  if [[ "$edges" == "$(printf 'scp-core/default\nscp-platform/sqlite')" ]]; then rc=0; else rc=1; fi
  expect "(root-blindness) the edge rendering of a nullifier-carrying scp-node resolve names NO root-package feature" "PASS" "$rc"
  check_subset "$edges" "$PERMITTED_ALLOWLIST" >/dev/null 2>&1; rc=$?
  expect "(root-blindness) that edge-only set is ACCEPTED, which is why the edge rendering cannot be this gate's only input" "PASS" "$rc"

  pkgs="$(extract_package_features "$pkg_tree")"
  local expected_pkgs
  expected_pkgs="$(printf '%s\n' \
    'scp-dht/default' 'scp-dht/production-dht' 'scp-dht/testing' \
    'scp-node/allow_unencrypted_storage' 'scp-node/testing' \
    'scp-platform/sqlite' 'scp-platform/testing' \
    'scp-runtime/allow_unencrypted_storage')"
  if [[ "$pkgs" == "$expected_pkgs" ]]; then rc=0; else rc=1; fi
  expect "(root-blindness) the per-package rendering emits exactly the root's own rows plus every dependency row, dropping cargo's (*) marker, an empty feature list, a non-SCP package, a package whose name merely ends in an SCP crate name, and an indented line" "PASS" "$rc"
  if [[ "$rc" -ne 0 ]]; then
    echo "          expected:"; printf '%s\n' "$expected_pkgs" | sed 's/^/            /'
    echo "          actual:";   printf '%s\n' "$pkgs"          | sed 's/^/            /'
  fi

  merged="$(merge_resolved_feature_sets "$edge_tree" "$pkg_tree")"
  local want
  for want in "scp-node/testing" "scp-node/allow_unencrypted_storage" \
              "scp-dht/testing" "scp-platform/testing" \
              "scp-runtime/allow_unencrypted_storage"; do
    printf '%s\n' "$merged" | grep -xF "$want" >/dev/null; rc=$?
    expect "(root-blindness) the union names '$want', which only the per-package rendering carries" "PASS" "$rc"
  done
  printf '%s\n' "$merged" | grep -xF 'scp-core/default' >/dev/null; rc=$?
  expect "(root-blindness) the union keeps 'scp-core/default', which only the edge rendering carries" "PASS" "$rc"
  check_subset "$merged" "$PERMITTED_ALLOWLIST" >/dev/null 2>&1; rc=$?
  expect "(root-blindness) the union of both renderings is REJECTED for that same build" "FAIL" "$rc"

  # A half-empty union means cargo resolved nothing or a rendering changed
  # shape. Accepting it would hand run_gate a set drawn from one rendering while
  # every message says both, so the merge fails loud instead.
  merge_resolved_feature_sets "" "$pkg_tree" >/dev/null 2>&1; rc=$?
  expect "(root-blindness) an empty EDGE rendering fails the merge loud" "FAIL" "$rc"
  merge_resolved_feature_sets "$edge_tree" "" >/dev/null 2>&1; rc=$?
  expect "(root-blindness) an empty PER-PACKAGE rendering fails the merge loud" "FAIL" "$rc"

  # (shipping-drift) packages_built_by_shipping_lines decides half 1 of the
  #     drift check, so these cases prove the declaration list suppresses ONLY
  #     the exact line a human declared. A blanket per-package suppression would
  #     let a later `cargo build -p scp-testing` reach a shipped artifact with no
  #     gate failure, which is the fail-open shape this whole gate rejects.
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

  # (shipping-drift, spellings) cargo accepts every spelling its option grammar
  #     admits, so each reader has to see each of them. An earlier revision
  #     matched `-p ` and `-F ` with a following space only, and
  #     `RUN cargo build --release -p scp-relay -p scp-node -Fscp-node/testing`
  #     in Dockerfile compiled the scp-node `testing` nullifiers under a passing
  #     gate. Each case below names one spelling; the expected package is a
  #     distinct name per line so a case that passes for the wrong reason
  #     cannot hide behind a neighbour.
  local spelling_lines spelled
  spelling_lines="$(printf '%s\n' \
    'run: cargo build --release -pscp-clock' \
    'run: cargo build --release -p=scp-crypto' \
    'run: cargo build --release --package scp-did' \
    'run: cargo build --release --package=scp-dht' \
    'run: cargo build --release -qp scp-mls' \
    'run: cargo build --release -qpscp-media' \
    'run: cargo build --release -p "scp-identity"' \
    "run: cargo build --release -p 'scp-transport'" \
    'run: cargo build --release -p scp-event-log@0.1.0' \
    'cargo build --release --target ${{ matrix.target }} -p "$pkg" --target-dir target-shipped' \
    'run: mkdir -p dist')"
  spelled="$(packages_built_by_shipping_lines "$spelling_lines" "")"
  for pkg in scp-clock scp-crypto scp-did scp-dht scp-mls scp-media scp-identity scp-transport scp-event-log; do
    printf '%s\n' "$spelled" | grep -xF "$pkg" >/dev/null; rc=$?
    expect "(shipping-drift, spellings) the package spelling that names $pkg is READ" "PASS" "$rc"
  done
  printf '%s\n' "$spelled" | grep -vxE 'scp-[a-z0-9-]+' >/dev/null; rc=$?
  expect "(shipping-drift, spellings) a shell variable or a mkdir directory after -p is NOT read as a package" "FAIL" "$rc"
  printf '%s\n' "$spelled" | sed '/^$/d' | wc -l | tr -d ' ' | grep -xF 9 >/dev/null; rc=$?
  expect "(shipping-drift, spellings) the eleven spelling lines yield exactly the nine packages they name" "PASS" "$rc"

  local flag_probe seen
  flag_probe="$(printf '%s\n' \
    'RUN cargo build --release -p scp-relay -p scp-node -Fscp-node/testing' \
    'RUN cargo build --release -p scp-relay -F scp-node/testing' \
    'RUN cargo build --release -p scp-relay -F=scp-node/testing' \
    'RUN cargo build --release -p scp-relay -qFscp-node/testing' \
    'RUN cargo build --release -p scp-relay --features scp-node/testing' \
    'RUN cargo build --release -p scp-relay --features=scp-node/testing' \
    'RUN cargo build --release -p scp-relay --all-features' \
    'RUN cargo build --release -p scp-relay --no-default-features' \
    'RUN cargo build --release -p scp-relay -p scp-node' \
    'run: cargo build --release --target ${{ matrix.target }}' \
    'echo not a cargo command at all')"
  seen="$(lines_carrying_cargo_feature_selection "$flag_probe")"
  for spelled in '-Fscp-node/testing' '-F scp-node/testing' '-F=scp-node/testing' '-qFscp-node/testing' \
                 '--features scp-node/testing' '--features=scp-node/testing' '--all-features' '--no-default-features'; do
    printf '%s\n' "$seen" | grep -F -- "$spelled" >/dev/null; rc=$?
    expect "(shipping-drift, spellings) a line carrying '$spelled' is READ as feature selection" "PASS" "$rc"
  done
  printf '%s\n' "$seen" | sed '/^$/d' | wc -l | tr -d ' ' | grep -xF 8 >/dev/null; rc=$?
  expect "(shipping-drift, spellings) the three lines carrying no feature-selection flag are NOT read" "PASS" "$rc"

  # (shipping-drift, continuation) the shell joins a line ending in a backslash
  #     to the next one, so `-p \` followed by `scp-testing` on the next line is
  #     the command `-p scp-testing`. An earlier revision read one line at a
  #     time, so that split handed `-p` an empty value and left `scp-testing` an
  #     unread token: `RUN cargo build --release -p scp-relay -p scp-node -p \`
  #     over `    scp-testing` in Dockerfile passed G1. The split feature flag
  #     is included to show the flag reader sees the joined line too, and the
  #     PowerShell backtick line to show a backtick joins nothing. The unjoined
  #     probe is read on purpose: the package must be ABSENT from it, or the
  #     join is not what finds the package.
  local split_probe joined_probe split_packages joined_packages
  split_probe="$(printf '%s\n' \
    'RUN cargo build --release -p scp-relay -p scp-node -p \' \
    '    scp-testing' \
    'run: cargo build --release --features \' \
    '    scp-node/testing' \
    '$cert = Import-PfxCertificate -FilePath $certPath `' \
    '-Password (ConvertTo-SecureString -String $env:WINDOWS_SIGN_PWD -AsPlainText -Force)' \
    'run: cargo build --release --package \' \
    '    scp-clock')"
  joined_probe="$(join_continued_lines "$split_probe")"
  printf '%s\n' "$joined_probe" | grep -xF 'RUN cargo build --release -p scp-relay -p scp-node -p scp-testing' >/dev/null; rc=$?
  expect "(shipping-drift, continuation) a trailing backslash joins the next line with one space where the break was" "PASS" "$rc"
  printf '%s\n' "$joined_probe" | grep -xF 'run: cargo build --release --package scp-clock' >/dev/null; rc=$?
  expect "(shipping-drift, continuation) a continued line at the end of the input is still emitted" "PASS" "$rc"
  printf '%s\n' "$joined_probe" | grep -xF '$cert = Import-PfxCertificate -FilePath $certPath `' >/dev/null; rc=$?
  expect "(shipping-drift, continuation) a PowerShell backtick joins nothing" "PASS" "$rc"
  printf '%s\n' "$joined_probe" | sed '/^$/d' | wc -l | tr -d ' ' | grep -xF 5 >/dev/null; rc=$?
  expect "(shipping-drift, continuation) the eight split lines join into exactly five" "PASS" "$rc"
  split_packages="$(packages_built_by_shipping_lines "$split_probe" "")"
  printf '%s\n' "$split_packages" | grep -xF 'scp-testing' >/dev/null; rc=$?
  expect "(shipping-drift, continuation) WITHOUT the join, the package on the continued line is NOT read (the join is load-bearing)" "FAIL" "$rc"
  joined_packages="$(packages_built_by_shipping_lines "$joined_probe" "")"
  for pkg in scp-testing scp-clock; do
    printf '%s\n' "$joined_packages" | grep -xF "$pkg" >/dev/null; rc=$?
    expect "(shipping-drift, continuation) WITH the join, the package $pkg on the continued line is READ" "PASS" "$rc"
  done
  lines_carrying_cargo_feature_selection "$joined_probe" | grep -xF 'run: cargo build --release --features scp-node/testing' >/dev/null; rc=$?
  expect "(shipping-drift, continuation) the flag reader sees the joined feature line" "PASS" "$rc"

  # (wheel-drift) maturin takes the wheel's cargo feature list from the
  #     `[tool.maturin]` table of a pyproject.toml, which no shipping file
  #     carries. Each case below writes one synthetic pyproject.toml and reads
  #     the ARTIFACTS entry maturin_artifact_entry derives from it, and the
  #     planted case proves assert_wheel_feature_selection_is_gated goes red
  #     when that table adds `testing`. An earlier revision read no maturin
  #     project file, so `features = ["extension-module", "testing"]` in
  #     bindings/python/pyproject.toml published a wheel carrying
  #     scp-platform/testing, scp-dht/testing, and scp-testing under a passing
  #     gate.
  local wheel_dir wheel_file wheel_entry wheel_manifest
  wheel_dir="$(mktemp -d)"
  wheel_file="$wheel_dir/pyproject.toml"
  wheel_manifest="$REPO_ROOT/crates/scp-ffi/Cargo.toml"
  printf '%s\n' \
    '[build-system]' \
    'requires = ["maturin>=1.0,<2.0"]' \
    '' \
    '[tool.maturin]' \
    'features = ["extension-module", "vendored-openssl"] # the features the wheel selects' \
    "manifest-path = \"$wheel_manifest\"" \
    'module-name = "scp_sdk._scp_core"' \
    '' \
    '[tool.other]' \
    'features = ["not-read-from-another-table"]' > "$wheel_file"
  wheel_entry="$(maturin_artifact_entry "$wheel_file" 2>/dev/null)"; rc=$?
  expect "(wheel-drift) a [tool.maturin] table matching the shipped one derives an entry" "PASS" "$rc"
  same_string "$wheel_entry" "scp-ffi|--features extension-module,vendored-openssl"; rc=$?
  expect "(wheel-drift) that entry is 'scp-ffi|--features extension-module,vendored-openssl', read from the main table only" "PASS" "$rc"
  ( fixture_failures=0; assert_wheel_feature_selection_is_gated "$wheel_file" >/dev/null 2>&1; exit "$fixture_failures" ); rc=$?
  expect "(wheel-drift) the assertion ACCEPTS a table whose configuration ARTIFACTS gates" "PASS" "$rc"

  printf '%s\n' \
    '[tool.maturin]' \
    'features = ["extension-module", "testing"]' \
    "manifest-path = \"$wheel_manifest\"" > "$wheel_file"
  wheel_entry="$(maturin_artifact_entry "$wheel_file" 2>/dev/null)"; rc=$?
  expect "(wheel-drift) a table that adds 'testing' still derives an entry" "PASS" "$rc"
  same_string "$wheel_entry" "scp-ffi|--features extension-module,testing"; rc=$?
  expect "(wheel-drift) that entry names both features in cargo's comma spelling" "PASS" "$rc"
  printf '%s\n' 'def load(f): return {"tool": {"maturin": {"features": ["extension-module", "vendored-openssl"], "manifest-path": "'"$wheel_manifest"'"}}, "package": {"name": "scp-ffi"}}' > "$wheel_dir/tomllib.py"
  wheel_entry="$(cd "$wheel_dir" && maturin_artifact_entry "$wheel_file" 2>/dev/null)"
  rm -f "$wheel_dir/tomllib.py"
  same_string "$wheel_entry" "scp-ffi|--features extension-module,testing"; rc=$?
  expect "(wheel-drift) a tomllib.py in the working directory does not replace the parser" "PASS" "$rc"
  printf '%s\n' "${ARTIFACTS[@]}" | grep -xF -- "$wheel_entry" >/dev/null; rc=$?
  expect "(wheel-drift) ARTIFACTS gates no configuration carrying 'testing'" "FAIL" "$rc"
  ( fixture_failures=0; assert_wheel_feature_selection_is_gated "$wheel_file" >/dev/null 2>&1; exit "$fixture_failures" ); rc=$?
  expect "(wheel-drift) the assertion REJECTS a table that adds 'testing', so the reader is load-bearing" "FAIL" "$rc"

  printf '%s\n' \
    '[tool.maturin]' \
    'all-features = false' \
    'no-default-features = true' \
    'features = [' \
    '  "extension-module",' \
    '  "server", # multi-line array' \
    ']' \
    "manifest-path = '$wheel_manifest'" > "$wheel_file"
  wheel_entry="$(maturin_artifact_entry "$wheel_file" 2>/dev/null)"; rc=$?
  expect "(wheel-drift) a multi-line array with boolean keys derives an entry" "PASS" "$rc"
  same_string "$wheel_entry" "scp-ffi|--no-default-features --features extension-module,server"; rc=$?
  expect "(wheel-drift) that entry spells the booleans and the list the way ARTIFACTS does" "PASS" "$rc"

  printf '%s\n' '[tool.maturin]' 'all-features = true' "manifest-path = \"$wheel_manifest\"" > "$wheel_file"
  wheel_entry="$(maturin_artifact_entry "$wheel_file" 2>/dev/null)"; rc=$?
  expect "(wheel-drift) 'all-features = true' derives an entry" "PASS" "$rc"
  same_string "$wheel_entry" "scp-ffi|--all-features"; rc=$?
  expect "(wheel-drift) that entry is 'scp-ffi|--all-features'" "PASS" "$rc"

  printf '%s\n' '[package]' 'name = "fixture-pkg"' 'version = "0.0.0"' > "$wheel_dir/Cargo.toml"
  printf '%s\n' '[build-system]' 'build-backend = "maturin"' > "$wheel_file"
  wheel_entry="$(maturin_artifact_entry "$wheel_file" 2>/dev/null)"; rc=$?
  expect "(wheel-drift) a file with no [tool.maturin] table derives an entry from the Cargo.toml beside it" "PASS" "$rc"
  same_string "$wheel_entry" "fixture-pkg|"; rc=$?
  expect "(wheel-drift) that entry is the package's default configuration" "PASS" "$rc"

  # A `[tool.maturin]` table that is present and names no feature key. The case
  # above deletes the table, which takes a different branch of this reader.
  printf '%s\n' '[tool.maturin]' "manifest-path = \"$wheel_manifest\"" > "$wheel_file"
  wheel_entry="$(maturin_artifact_entry "$wheel_file" 2>/dev/null)"; rc=$?
  expect "(wheel-drift) a [tool.maturin] table naming no feature key derives an entry" "PASS" "$rc"
  same_string "$wheel_entry" "scp-ffi|"; rc=$?
  expect "(wheel-drift) that entry selects the package's default features" "PASS" "$rc"

  # A manifest carrying no `[package] name`, such as a workspace root. The reader
  # fails rather than derive an entry whose package half is empty.
  printf '%s\n' '[workspace]' 'members = []' > "$wheel_dir/Cargo.toml"
  printf '%s\n' '[build-system]' 'build-backend = "maturin"' > "$wheel_file"
  maturin_artifact_entry "$wheel_file" >/dev/null 2>&1; rc=$?
  expect "(wheel-drift) a manifest carrying no [package] name FAILS" "FAIL" "$rc"

  # (wheel-drift, spellings) TOML names one table four ways, and maturin reads the
  # same table however the document spells it, so each spelling below derives the
  # same entry, and none reads as "no features selected".
  local spelling_entry
  printf '%s\n' '[tool."maturin"]' 'features = ["testing"]' "manifest-path = \"$wheel_manifest\"" > "$wheel_file"
  spelling_entry="$(maturin_artifact_entry "$wheel_file" 2>/dev/null)"; rc=$?
  expect "(wheel-drift, spellings) a quoted table header derives an entry" "PASS" "$rc"
  same_string "$spelling_entry" "scp-ffi|--features testing"; rc=$?
  expect "(wheel-drift, spellings) that entry names the feature the quoted table selects" "PASS" "$rc"
  printf '%s\n' 'tool.maturin.features = ["testing"]' "tool.maturin.manifest-path = \"$wheel_manifest\"" > "$wheel_file"
  spelling_entry="$(maturin_artifact_entry "$wheel_file" 2>/dev/null)"; rc=$?
  expect "(wheel-drift, spellings) a dotted-key spelling derives an entry" "PASS" "$rc"
  same_string "$spelling_entry" "scp-ffi|--features testing"; rc=$?
  expect "(wheel-drift, spellings) that entry names the feature too, not 'no features'" "PASS" "$rc"
  printf '%s\n' '[tool]' "maturin = { features = [\"testing\"], manifest-path = \"$wheel_manifest\" }" > "$wheel_file"
  spelling_entry="$(maturin_artifact_entry "$wheel_file" 2>/dev/null)"; rc=$?
  expect "(wheel-drift, spellings) an inline-table spelling derives an entry" "PASS" "$rc"
  same_string "$spelling_entry" "scp-ffi|--features testing"; rc=$?
  expect "(wheel-drift, spellings) that entry names the feature too, not 'no features'" "PASS" "$rc"
  ( fixture_failures=0; assert_wheel_feature_selection_is_gated "$wheel_file" >/dev/null 2>&1; exit "$fixture_failures" ); rc=$?
  expect "(wheel-drift, spellings) the assertion REJECTS an inline-table wheel selecting 'testing'" "FAIL" "$rc"

  # (wheel-drift, keys) a key outside MATURIN_KEYS fails, whether it passes rustc
  # a cfg, overrides cargo configuration, or is a subtable of [tool.maturin]. The
  # last case carries only whitelisted keys and derives, so the three before it
  # fail on the key and on nothing else.
  printf '%s\n' '[tool.maturin]' 'features = ["extension-module"]' 'rustc-args = ["--cfg", "feature=\"testing\""]' "manifest-path = \"$wheel_manifest\"" > "$wheel_file"
  maturin_artifact_entry "$wheel_file" >/dev/null 2>&1; rc=$?
  expect "(wheel-drift, keys) a rustc-args key FAILS" "FAIL" "$rc"
  printf '%s\n' '[tool.maturin]' 'features = ["extension-module"]' 'config = ["build.rustflags=[]"]' "manifest-path = \"$wheel_manifest\"" > "$wheel_file"
  maturin_artifact_entry "$wheel_file" >/dev/null 2>&1; rc=$?
  expect "(wheel-drift, keys) a config key FAILS" "FAIL" "$rc"
  printf '%s\n' '[tool.maturin]' 'features = ["extension-module"]' "manifest-path = \"$wheel_manifest\"" '[tool.maturin.sub]' 'features = ["testing"]' > "$wheel_file"
  maturin_artifact_entry "$wheel_file" >/dev/null 2>&1; rc=$?
  expect "(wheel-drift, keys) a subtable of [tool.maturin] FAILS" "FAIL" "$rc"
  printf '%s\n' '[tool.maturin]' 'features = ["extension-module"]' "manifest-path = \"$wheel_manifest\"" 'module-name = "m"' 'python-source = "."' 'python-packages = []' 'include = []' 'exclude = []' 'all-features = false' 'no-default-features = false' > "$wheel_file"
  wheel_entry="$(maturin_artifact_entry "$wheel_file" 2>/dev/null)"; rc=$?
  expect "(wheel-drift, keys) every whitelisted key together derives an entry" "PASS" "$rc"
  same_string "$wheel_entry" "scp-ffi|--features extension-module"; rc=$?
  expect "(wheel-drift, keys) that entry is the one the feature keys select" "PASS" "$rc"

  # (wheel-drift, shapes) a value this reader cannot interpret fails. The first
  # four cases also read the reason on stderr, because without its guard each
  # value raises a Python exception that exits non-zero for a reason the reader
  # never states.
  local shape_err
  printf '%s\n' 'tool = 5' > "$wheel_file"
  shape_err="$(maturin_artifact_entry "$wheel_file" 2>&1 >/dev/null)"; rc=$?
  expect "(wheel-drift, shapes) a tool key that is not a table FAILS" "FAIL" "$rc"
  same_string "$shape_err" "$wheel_file: tool is not a table"; rc=$?
  expect "(wheel-drift, shapes) that failure states the tool key is not a table" "PASS" "$rc"
  printf '%s\n' '[tool]' 'maturin = 5' > "$wheel_file"
  shape_err="$(maturin_artifact_entry "$wheel_file" 2>&1 >/dev/null)"; rc=$?
  expect "(wheel-drift, shapes) a tool.maturin key that is not a table FAILS" "FAIL" "$rc"
  same_string "$shape_err" "$wheel_file: [tool.maturin] is not a table"; rc=$?
  expect "(wheel-drift, shapes) that failure states [tool.maturin] is not a table" "PASS" "$rc"
  printf '%s\n' '[tool.maturin]' 'features = ["testing"]' 'manifest-path = 17' > "$wheel_file"
  shape_err="$(maturin_artifact_entry "$wheel_file" 2>&1 >/dev/null)"; rc=$?
  expect "(wheel-drift, shapes) a manifest-path that is not a TOML string FAILS" "FAIL" "$rc"
  same_string "$shape_err" "$wheel_file: manifest-path is not a TOML string"; rc=$?
  expect "(wheel-drift, shapes) that failure states manifest-path is not a TOML string" "PASS" "$rc"
  printf '%s\n' '[tool.maturin]' 'features = ["testing"' "manifest-path = \"$wheel_manifest\"" > "$wheel_file"
  shape_err="$(maturin_artifact_entry "$wheel_file" 2>&1 >/dev/null)"; rc=$?
  expect "(wheel-drift, shapes) a document no TOML parser accepts FAILS" "FAIL" "$rc"
  [[ "$shape_err" == "$wheel_file: cannot read maturin project file $wheel_file: "* ]]; rc=$?
  expect "(wheel-drift, shapes) that failure states the project file cannot be read" "PASS" "$rc"
  printf '%s\n' '[tool.maturin]' 'features = ["testing", 17]' "manifest-path = \"$wheel_manifest\"" > "$wheel_file"
  maturin_artifact_entry "$wheel_file" >/dev/null 2>&1; rc=$?
  expect "(wheel-drift, shapes) a features array holding a non-string FAILS" "FAIL" "$rc"
  printf '%s\n' '[tool.maturin]' 'features = ["extension-module", ""]' "manifest-path = \"$wheel_manifest\"" > "$wheel_file"
  maturin_artifact_entry "$wheel_file" >/dev/null 2>&1; rc=$?
  expect "(wheel-drift, shapes) a features array holding an empty name FAILS" "FAIL" "$rc"
  printf '%s\n' '[tool.maturin]' 'features = ["extension-module", "vendored-openssl testing"]' "manifest-path = \"$wheel_manifest\"" > "$wheel_file"
  maturin_artifact_entry "$wheel_file" >/dev/null 2>&1; rc=$?
  expect "(wheel-drift, shapes) a feature name carrying whitespace FAILS" "FAIL" "$rc"
  # A commented-out key above the live one decides nothing.
  printf '%s\n' \
    '[tool.maturin]' \
    '# features = ["extension-module", "vendored-openssl"]' \
    'features = ["extension-module"]' \
    "manifest-path = \"$wheel_manifest\"" > "$wheel_file"
  wheel_entry="$(maturin_artifact_entry "$wheel_file" 2>/dev/null)"; rc=$?
  expect "(wheel-drift) a table whose live features key sits under a commented-out one derives an entry" "PASS" "$rc"
  same_string "$wheel_entry" "scp-ffi|--features extension-module"; rc=$?
  expect "(wheel-drift) that entry comes from the live key" "PASS" "$rc"
  printf '%s\n' '[tool.maturin]' 'features = "testing"' "manifest-path = \"$wheel_manifest\"" > "$wheel_file"
  maturin_artifact_entry "$wheel_file" >/dev/null 2>&1; rc=$?
  expect "(wheel-drift) a features value that is not an array FAILS" "FAIL" "$rc"
  printf '%s\n' '[tool.maturin]' 'no-default-features = "yes"' "manifest-path = \"$wheel_manifest\"" > "$wheel_file"
  maturin_artifact_entry "$wheel_file" >/dev/null 2>&1; rc=$?
  expect "(wheel-drift) a boolean key whose value is not a TOML boolean FAILS" "FAIL" "$rc"
  printf '%s\n' '[tool.maturin]' 'features = ["extension-module"]' 'manifest-path = "nowhere/Cargo.toml"' > "$wheel_file"
  maturin_artifact_entry "$wheel_file" >/dev/null 2>&1; rc=$?
  expect "(wheel-drift) a manifest-path naming no file FAILS" "FAIL" "$rc"
  rm -f "$wheel_file"
  maturin_artifact_entry "$wheel_file" >/dev/null 2>&1; rc=$?
  expect "(wheel-drift) a missing maturin project file FAILS" "FAIL" "$rc"
  ( fixture_failures=0; assert_wheel_feature_selection_is_gated "$wheel_file" >/dev/null 2>&1; exit "$fixture_failures" ); rc=$?
  expect "(wheel-drift) the assertion REJECTS a maturin project file it cannot read" "FAIL" "$rc"
  rm -rf "$wheel_dir"

  # (wheel-drift, reach) the two places maturin looks for its pyproject.toml,
  # proved on a planted tree instead of on this repository's own files, so that
  # deleting a repository pyproject.toml cannot turn a positive proof into one
  # that reaches nothing.
  local reach_lines reached reach_dir
  reach_dir="$(mktemp -d)"
  mkdir -p "$reach_dir/crates/a-bridge" "$reach_dir/crates/b-bridge" \
           "$reach_dir/crates/no-project" "$reach_dir/bindings/a-binding" \
           "$reach_dir/bindings/no-project"
  : > "$reach_dir/crates/a-bridge/Cargo.toml"
  : > "$reach_dir/crates/a-bridge/pyproject.toml"
  : > "$reach_dir/crates/b-bridge/Cargo.toml"
  : > "$reach_dir/crates/b-bridge/pyproject.toml"
  : > "$reach_dir/crates/no-project/Cargo.toml"
  : > "$reach_dir/bindings/a-binding/pyproject.toml"
  reach_lines="$(printf '%s\n' \
    "            --manifest-path $reach_dir/crates/a-bridge/Cargo.toml" \
    "        run: maturin build --manifest-path=$reach_dir/crates/b-bridge/Cargo.toml" \
    "          working-directory: $reach_dir/bindings/a-binding" \
    "          working-directory: $reach_dir/bindings/no-project" \
    "        run: cargo publish --manifest-path=$reach_dir/crates/no-project/Cargo.toml" \
    'echo not a maturin invocation at all')"
  reached="$(maturin_project_files_named_by_shipping_lines "$reach_lines")"
  printf '%s\n' "$reached" | grep -xF "$reach_dir/crates/a-bridge/pyproject.toml" >/dev/null; rc=$?
  expect "(wheel-drift, reach) the pyproject.toml beside a --manifest-path Cargo.toml is reached" "PASS" "$rc"
  printf '%s\n' "$reached" | grep -xF "$reach_dir/crates/b-bridge/pyproject.toml" >/dev/null; rc=$?
  expect "(wheel-drift, reach) the --manifest-path=<file> spelling reaches it too" "PASS" "$rc"
  printf '%s\n' "$reached" | grep -xF "$reach_dir/bindings/a-binding/pyproject.toml" >/dev/null; rc=$?
  expect "(wheel-drift, reach) the pyproject.toml of a working-directory: is reached" "PASS" "$rc"
  printf '%s\n' "$reached" | sed '/^$/d' | wc -l | tr -d ' ' | grep -xF 3 >/dev/null; rc=$?
  expect "(wheel-drift, reach) a directory with no pyproject.toml and a non-maturin line reach nothing" "PASS" "$rc"
  rm -rf "$reach_dir"

  assert_every_pipeline_reader_consumes_its_input

  assert_every_cargo_tree_resolves_every_target

  assert_print_modes_emit_what_this_gate_holds

  assert_allowlist_has_no_nullifier

  echo ">> fixture: the crate dimension (local-path provenance, closed PERMITTED_CRATES)"
  run_crate_dimension_fixtures
  assert_permitted_crates_have_no_nullifier_crate "$PERMITTED_CRATES"

  assert_shipping_invocations_are_gated

  assert_wheel_feature_selection_is_gated "${MATURIN_PROJECT_FILES[@]}"

  assert_maturin_project_files_are_complete

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
  # The two print modes write this gate's own declarations and exit without
  # running a check: `--print-artifacts` writes the ARTIFACTS array as bash holds
  # it, and `--print-wheel-entries` writes the configuration each
  # MATURIN_PROJECT_FILES file makes maturin build, beside the file it read. A
  # caller compares the whole output against the entries it expects, so neither
  # mode writes a fixture line. An empty array, or a project file the reader
  # cannot read, exits non-zero. `assert_print_modes_emit_what_this_gate_holds`
  # proves each property.
  case "${1:-}" in
    --print-artifacts)
      if [[ ${#ARTIFACTS[@]} -eq 0 ]]; then
        echo "--print-artifacts: ARTIFACTS is empty" >&2
        exit 1
      fi
      printf '%s\n' "${ARTIFACTS[@]}"
      exit 0
      ;;
    --print-wheel-entries)
      if [[ ${#MATURIN_PROJECT_FILES[@]} -eq 0 ]]; then
        echo "--print-wheel-entries: MATURIN_PROJECT_FILES is empty" >&2
        exit 1
      fi
      local project_file wheel_entry lines=""
      for project_file in "${MATURIN_PROJECT_FILES[@]}"; do
        wheel_entry="$(maturin_artifact_entry "$project_file")" || exit 1
        lines+="$project_file"$'\t'"$wheel_entry"$'\n'
      done
      printf '%s' "$lines"
      exit 0
      ;;
  esac

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
    echo "G1 PASSED: the local-path crate set of every ARTIFACTS entry and of every package a shipping file builds ⊆ PERMITTED_CRATES, and every entry there is reached."
    exit 0
  fi
  echo
  echo "G1 FAILED: a shipped artifact resolves a non-allowlisted (nullifier/test-harness)"
  echo "feature. Fix the dependency edge — do NOT add the feature to the allowlist."
  echo "Or a shipped artifact reaches a local-path crate PERMITTED_CRATES does not name,"
  echo "or that list names a crate no artifact reaches; the FAIL lines above say which."
  exit 1
}

main "$@"
