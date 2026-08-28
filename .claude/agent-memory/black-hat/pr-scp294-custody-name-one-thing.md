---
name: pr-scp294-custody-name-one-thing
description: Black-hat findings on branch fix/scp-294-custody-name-means-one-thing — the custody fail-closed change relocates rather than removes the false guarantee
metadata:
  type: project
---

# SCP-294 custody naming — where the false guarantee moved

**Fact:** `identity_create`, `identity_create_with_agent_key`, AND
`identity_create_with_custody` ALL return `SCP-IDENT-1059` (no pre-rotation
backend) in a `cfg(not(feature = "testing"))` build, on all three bridges
(PyO3 `crates/scp-ffi/src/identity.rs`, UniFFI `crates/scp-ffi/uniffi/src/bridge.rs`,
NAPI `crates/scp-ffi/napi/src/scp.rs`). ADR-062 records this; a real
pre-rotation backend is forward work (RFC #2130 / #1729 / #1777).

**Why it matters for every custody review:** any doc, error message, or README
that names `identity_create_with_custody` / `identityCreateWithCustody` as "the
production path" is false in a shipped build. Check this first on any custody PR.

**Corollaries verified 2026-08-28:**
- `KeyCustody::custody_type` has ZERO production consumers (only
  `crates/scp-runtime/tests/phase5_integration.rs:647`). A provider self-reporting
  `"hardware"` is believed verbatim on UniFFI (`bridge.rs:824`) and PyO3
  (`crates/scp-ffi/src/custody.rs:584`), and discarded in favour of a hardcoded
  `CustodyType::Software` on NAPI (`crates/scp-ffi/napi/src/custody.rs:353`).
  Cross-bridge divergence, currently harmless because nothing gates on it.
- `bindings/swift/Sources/SCP/Internal/ScpBindings.swift` is a TRACKED generated
  file. The Kotlin equivalent (`.../internal/uniffi/scp/scp.kt`) is NOT tracked.
  Any UniFFI doc-comment change must regenerate the Swift file or it goes stale.
- `AppleKeyCustody` (Swift) and `AndroidKeyCustody` (Kotlin) do NOT conform to
  `uniffi.scp.KeyCustodyProvider`. Swift signatures differ by argument label and
  return type (`sign(_:data:)` vs `sign(keyId:message:)`, `destroyKey -> DestructionAttestation`
  vs `-> Void`, `derivePseudonym -> PseudonymResult` vs `-> Data`).
- Spec §17.17.2 SCP-CAPSEL-8011: "a durability-only arm may never be the sole
  option a shipped artifact offers for its capability." Swift/Kotlin/TS
  `CustodyType` now offer only `in_memory`, a nullifier §17.8 names explicitly.

See [[surfaces-crypto-economy-persona]] for the wider custody surface.
