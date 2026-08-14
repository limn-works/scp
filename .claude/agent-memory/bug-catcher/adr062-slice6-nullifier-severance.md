---
name: adr062-slice6-nullifier-severance
description: Bug-hunt of ADR-062 Slice 6 / SCP-CAPINJECT-006 (nullifier severance, allow_in_memory_custody→testing rename + fail-closed welds + G1 gate) @554994606 — CLEAN
metadata:
  type: project
---

# ADR-062 Slice 6 nullifier severance (feat/adr062-slice6-nullifier-severance @554994606, base 2adb7dd36)

**Verdict: CLEAN — 0 live defects.** ~442 `allow_in_memory_custody`→`testing` cfg renames + ~25 fail-closed pre-rotation weld sites + G1 gate. Verified end-to-end:

- **Prod build compiles**: `cargo build -p scp-ffi -p scp-ffi-napi -p scp-ffi-uniffi --no-default-features --features server` → Finished, 0 errors/warnings. This is the shipped-artifact config; the crux of the severance.
- **G1 gate** (`scripts/check-shipped-feature-graph.sh`): passes real tree + all fixtures (closed ⊆-whitelist, load-bearing, rejects all 4 nullifier features). Bash is FAIL-CLOSED: grep-empty→pipefail+set -e→CI red; comm inputs both explicitly `sort -u`'d (no unsorted-input bug); line-exact (no substring collision); `resolved="$(...)"` split from `local` so set -e fires on cargo-tree failure. Wired into ci.yml:116/1186/1232 as a required gate.
- **Fail-closed welds all symmetric**: every `#[cfg(not(feature="testing"))]` arm returns typed error (IDENT_1059 `NoPreRotationBackend` for pre-rotation; IDENT_1015/1016/1010 for device-attest), every `#[cfg(feature="testing")]` sibling constructs. Checked pyo3 identity.rs (5 create/migrate), napi identity.rs (5) + scp.rs (1), uniffi bridge.rs (create/migrate/attest ~7), scp-node lib.rs resolve_identity/resolve_identity_persistent (2), scp-identity config.rs create_inner (1). None return Ok/partial.
- **Handle-affinity hoist** (uniffi bridge.rs:16858 `identity_migrate`): `check_handle` hoisted ABOVE the cfg-split, runs on BOTH builds, kept as FIRST statement (satisfies check-handle-affinity.sh). Not dropped in either arm.
- **IdentityEntry.pre_rotation_custody** gated `#[cfg(feature="testing")]`: no prod path constructs it (all 4 construction sites in identity.rs are inside testing arms; runtime.rs test sites gated).
- **Phantom retype** (scp-ffi-common/server.rs:355/468): `IdentitySource::<InMemoryKeyCustody..>::Explicit`→`FileKeyCustody`. Sound — Explicit carries no custody, K is phantom, no InMemoryKeyCustody value materialized.
- No polarity flips in renames (awk-checked adjacent -/+ cfg pairs). `allow_in_memory_custody` FULLY deleted (0 refs in crates/scripts/.github/bindings) — no dangling cfg silently compiling-out code.
- scp-runtime commands.rs/supervisor.rs/Cargo.toml changes are comment-only doc renames.

**NON-issue investigated & dismissed**: runtime.rs:2823 `test_py_bridge_instance_typed_identity_registry_roundtrip` is ungated but constructs the now-testing-gated `pre_rotation_custody` field + uses testing-gated `FfiKeyCustody::InMemory` → E0560/E0599 under `cargo test -p scp-ffi` WITHOUT `--features testing`. NOT a regression: pre-PR the same ungated test already used `FfiKeyCustody::InMemory` which was `allow_in_memory_custody`-gated, so plain `cargo test -p scp-ffi` never compiled the pyo3 test suite (ci.yml:614 documents "pyo3 test suite ... does not compile in prod config"; CI only build-tests the lib there, workspace nextest lane passes scp-ffi/testing). Under canonical `--features testing` all compiles. Zero practical effect. PR gated 2 of 3 IdentityEntry-constructing tests (2422/2504) but not this one — cosmetic gating inconsistency, no live impact.

Already-known (not re-reported): AC3/AC5 missing tests; dead not(testing) block in pyo3 identity_verify_device_attestation (939-951); G1 soundness-comment imprecision; G1 hardcodes --features server.
