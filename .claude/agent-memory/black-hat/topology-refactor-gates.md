# Topology Refactor CI-Gate Gaps (ADR-057 scp-primitives dissolution)

Branch refactor/dissolve-primitives-split-identity (HEAD 8d6819674). scp-primitives
dissolved → scp-clock/scp-crypto/scp-did; DID doc model moved scp-protocol→scp-did.

## Reusable lesson: path-filter gates rot when code moves crate
- `.github/workflows/ci.yml` `fuzz-build` job runs ONLY `if: needs.changes.outputs.fuzz=='true'`.
  fuzz/ is a STANDALONE crate (not in workspace) → nothing else compiles fuzz targets.
- When a fuzzed SUT moves crate, the fuzz path filter must move with it, else the
  fuzz/prod-API-drift gate silently skips.
- FOUND (MEDIUM): `fuzz_scp_credential.rs` retargeted from `scp_runtime::...::ScpCredential`
  (scp-runtime IS in filter) to `scp_mls::credential::ScpCredential` (scp-mls NOT in
  fuzz filter, lines 67-75). scp-mls added to fuzz/Cargo.toml deps but not the filter →
  a scp-mls-only PR skips fuzz-build; the untrusted-input credential parser loses its
  compile-drift gate. Fix: add `- 'crates/scp-mls/**'` to the fuzz filter.

## Verified CLEAN
- check-protocol-deps.sh: banned=tokio|scp-platform|openmls, `cargo tree -p scp-protocol`
  UNCHANGED (comment-only retarget). scp-clock/crypto/did trees pull no banned crate;
  transitively covered by the protocol tree. DID model moved to scp-did = still under
  protocol's tree. No laundering path.
- wasm32 job EXPANDED (coverage-positive): now clock/crypto/did/protocol/mls/client-wasm.
- release.yml publish order topologically valid; exact `=0.1.0-beta.2` pins → no stale/
  foreign crates.io resolution mid-sequence.
- check-no-mutable-globals.sh + .clippy.toml: comment-only. deny.toml untouched (correct).
