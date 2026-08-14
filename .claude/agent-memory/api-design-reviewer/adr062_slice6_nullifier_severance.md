---
name: adr062-slice6-nullifier-severance
description: ADR-062 Slice 6 (SCP-CAPINJECT-006) nullifier-severance API-surface review @554994606 — create fail-closed IDENT_1059 sound & consistent; attestation-code divergence is the finding
metadata:
  type: project
---

ADR-062 Slice 6 / SCP-CAPINJECT-006 (nullifier severance), branch `feat/adr062-slice6-nullifier-severance`, diff `2adb7dd36..554994606`. APPROVE-WITH-CHANGES.

**Why:** severs the in-memory `InMemoryPreRotationCustody` / `InMemoryDeviceAttestation` nullifiers from every production path; renamed FFI feature `allow_in_memory_custody` → `testing` (folded); production `identity_create` fails closed.

**SOUND (don't re-flag):**
- New `IdentityError::NoPreRotationBackend` + `SCP-IDENT-1059` create fail-closed is IDENTICAL & correct across pyo3/napi/uniffi/scp-node (all emit IDENT_1059 via a `no_pre_rotation_backend()` helper). Message is typed, honest, self-explaining, points to #1729/RFC #2130 + #1553. First-pass authorability preserved — `identity_create()` in prod returns a comprehensible "not yet available" typed error, not confusion.
- `allow_in_memory_custody` fully removed from all Cargo.tomls/CI/READMEs; only residual hits are agent-memory + historical PRD JSON (not developer-facing). `allow_unencrypted_storage` is a SEPARATE surviving feature (storage seal, not custody) — don't confuse.

**FINDING (MAJOR, NEW): device-attestation fail-closed CODE diverges across bindings.** This PR adds dedicated honest-absent codes IDENT_1015 (attest)/IDENT_1016 (verify) and wires PyO3 (Python SDK hasattr-shim) + NAPI/TS (shipped `#[napi]` fail-closed methods) to them. But the NEW UniFFI `#[cfg(not(feature="testing"))]` arms (`identity_attest_device_impl` / `identity_verify_device_attestation_impl`, bridge.rs:3902/3954) return `codes::IDENT_1010` for BOTH — IDENT_1010's own doc is "UniFFI identity create error" (generic bucket), so the code mislabels the failure kind. Swift/Kotlin consumers branching on 1015/1016 never match. error_codes.rs IDENT_1015/1016 docs even OMIT UniFFI (tacitly documenting the divergence instead of fixing it). Contradicts the PR's parity + honest-surface goal. Fix: UniFFI fail-closed arms should emit IDENT_1015/IDENT_1016.

**MODERATE:** production `in_memory` custody rejection steers devs to "enable the testing feature for dev/desktop use" WITHOUT naming the valid production alternative. UniFFI (bridge.rs:6482) DOES name "platform" custody; PyO3 (identity.rs:775) + NAPI (scp.rs:515/629) do NOT. Also error TYPE/CODE split (pre-existing, perpetuated): PyO3=ValidationError/VALID_7001, NAPI/UniFFI=Identity/IDENT_1008.

**LOW:** PyO3 in_memory msg has whitespace artifact `"enable the              testing feature"` (pre-existing run of ~14 spaces, on a line this PR edited — cheap cleanup). IDENT_1015 doc says "shipped PyO3 ... identity_attest_device method" but PyO3 attest is testing-gated/absent in prod — it's the Python SDK shim that surfaces 1015.

ALREADY-KNOWN (excluded by task): AC3/AC5 test gaps; dead pyo3 not(testing) block inside testing-gated `identity_verify_device_attestation` pyfunction; G1 items.
