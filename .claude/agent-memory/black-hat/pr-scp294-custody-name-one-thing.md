---
name: pr-scp294-custody-name-one-thing
description: Black-hat findings on branch fix/scp-294-custody-name-means-one-thing — the bridges fail closed, but four upstream documents still tell a reader that custody="platform" reaches an OS keystore
metadata:
  type: project
---

# SCP-294 custody naming — the bridges fail closed; the docs still lie

**Fact:** `identity_create`, `identity_create_with_agent_key`, AND
`identity_create_with_custody` ALL return `SCP-IDENT-1059` (no pre-rotation
backend) in a `cfg(not(feature = "testing"))` build, on all three bridges
(PyO3 `crates/scp-ffi/src/identity.rs`, UniFFI `crates/scp-ffi/uniffi/src/bridge.rs`,
NAPI `crates/scp-ffi/napi/src/scp.rs`). ADR-062 §Decision 6 records this.

**Why it matters on every custody review:** any doc, error message, or README
that names `identity_create_with_custody` / `identityCreateWithCustody` as "the
production path" is false in a shipped build. Check this first.

## Verified 2026-08-28, round 2

Bridge code is sound. `"platform"` reaches no key store under ANY feature
combination on any of the three bridges — the `"platform"` arm is not
`cfg`-gated on NAPI (`napi/src/scp.rs:534`) or UniFFI
(`uniffi/src/bridge.rs` `parse_custody_method`), and PyO3's arm
(`crates/scp-ffi/src/identity.rs:827`) sits ahead of the `"file"` arm.
Only two production callers reach `parse_custody*` in PyO3, so there is no
bypass.

**Where the false guarantee survives — upstream artifacts nobody swept:**
- `docs/examples/typescript/identity.ts:18` and `docs/examples/swift/Identity.swift:20`
  still say to use `"platform"` for Keychain/Keystore storage. The Python and
  Kotlin siblings were fixed; the matrix has two empty cells.
- `.docs/adrs/phase-5.md:503,564`, `.docs/adrs/phase-6.md:50,411,473,669,1083,1102`,
  `.docs/adrs/phase-4.md:689,1066`, `.docs/architecture.md:915`.
  `phase-6.md:1102` claims `Scp.create(custody = "platform", ...)` "returns an
  Scp instance with hardware-backed identity on API 33+".
- Story SCP-294's own action item names phase-5 and phase-6; only phase-3 was
  edited.

**Dormant assertions:** `crates/scp-ffi/src/identity.rs:3122`
(`#[cfg(all(test, not(feature = "testing")))] mod prod_custody_message_tests`)
and `crates/scp-ffi/uniffi/src/lib.rs:652` never execute. `.github/workflows/ci.yml:634`
runs `scp-ffi` / `scp-ffi-uniffi` tests only WITH `testing`; their only
production-config lanes are `cargo build` (ci.yml:730, :757). NAPI is the one
bridge with a prod-config test lane (ci.yml:687).

## Corollaries (still true)

- `KeyCustody::custody_type` has ZERO production consumers. A provider
  self-reporting `"hardware"` is believed verbatim on UniFFI
  (`uniffi/src/bridge.rs:827`) and PyO3 (`crates/scp-ffi/src/custody.rs:584`),
  and discarded for a hardcoded `CustodyType::Software` on NAPI
  (`napi/src/custody.rs:365`). Harmless today because nothing gates on it.
- `bindings/swift/Sources/SCP/Internal/ScpBindings.swift` is a TRACKED generated
  file. The Kotlin equivalent is NOT tracked (generated at build time). Any
  UniFFI doc-comment change must regenerate the Swift file or it goes stale.
- `AppleKeyCustody` (Swift) and `AndroidKeyCustody` (Kotlin) do NOT conform to
  `uniffi.scp.KeyCustodyProvider`, so neither SDK ships a provider a caller can
  pass to `identityCreateWithCustody`. The four SDK READMEs now say so.
- CORRECTED: the SDK `CustodyType` enums keep `platform` and `software`. An
  earlier revision deleted them and that deletion was reverted, because §3.2 of
  the identity spec owns the vocabulary and open question OQ-9 on pull request
  #2411 is unresolved. Every member of the TS / Swift / Kotlin type throws on a
  shipped build, which is fail-closed but leaves the type with no usable value.

See [[surfaces-crypto-economy-persona]] for the wider custody surface.
