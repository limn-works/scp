---
name: pr2415-custody-vocabulary
description: Adversarial findings on PR #2415 (spec/custody-vocabulary-names-the-backend) — the derive-only published-custody guarantee reduces to an unverified foreign self-report, and nothing publishes the attestation at all
metadata:
  type: project
---

# PR #2415 — custody vocabulary names the backend (§3.2.2 of `.docs/specs/03-identity.md`)

The branch splits custody into a request-side vocabulary (`encrypted_file`, `os_keystore`)
and a published side (`non-extractable-biometric`, `non-extractable-pin`,
`extractable-passphrase`) derived from a `CustodySubstrate`, and adds
`identity_published_custody` on all three bridges.

## The load-bearing weakness

Every Rust-side `CustodySubstrate` reports an **extractable** key:
- `crates/scp-platform/src/file.rs:981` → `(true, Passphrase)`
- `crates/scp-platform/src/sqlite/key_custody.rs:530` → `(true, Passphrase | CallerSuppliedKey)`
- `crates/scp-platform/src/testing/key_custody.rs:515` → `(true, Unprotected)`

So the two *trust-positive* published values (`non-extractable-*`) can only ever come from
the injected `KeyCustodyProvider` callback, whose `key_is_extractable` / `unlock_factor` a
foreign SDK consumer answers however it likes
(`crates/scp-ffi/uniffi/src/lib.rs:482`, `:497`; napi `custody.rs:100`, `:107`; PyO3
`custody.rs` `PyCallbackKeyCustody::custody_substrate`). `ReportedCustodySubstrate::new`
(`crates/scp-ffi/common/src/custody_substrate.rs:91`) stores the answers verbatim.
The repo ships the exploit as a passing test:
`bindings/python/tests/test_identity_create_with_custody.py:203` `_FakeBiometricKeychain`
is a pure-Python dict of seeds and `:282` asserts it publishes `non-extractable-biometric`.

Spec §3.2.2 claims "not because a verifier catches the claim, but because no field exists
to write it in." That claim is false three ways: the provider self-report above; serde
`Deserialize` on `ScpKeyCustodyAttestation` (`crates/scp-did/src/attestation.rs:60`) plus
public `from_service_entry` (`:403`); and `DidDocument.service` being a public
`Vec<Service>` with public String fields (`crates/scp-did/src/document.rs:199`, `:228`).
`scp-did` is a versioned published crate, so a Rust consumer reaches all of it.

## Nothing publishes it

`set_custody_attestation` (`crates/scp-did/src/document.rs:671`) still has zero production
callers — only `crates/scp-runtime/tests/agent_binding_integration.rs:177` and unit tests.
`.docs/specs/27-attestations.md:566` §27.4.4 already records both "There is no verifier"
and "Nothing writes one either" (OQ-3, OQ-23). The new SDK docs and the capability-matrix
note nevertheless describe `identity_published_custody` as "the custody value a DID
document publishes" — no DID document carries it.

## Also noted
- `crates/scp-platform/src/android/key_custody.rs:36` still says the callback interface
  "carries one custody question today — `custody_type`"; the same PR added two more.
- `crates/scp-ffi/uniffi/src/bridge.rs:10210` ships a user-facing error message with 22
  consecutive embedded spaces.
- `derive`'s `platform` and `platform_attestation` arguments stay caller-declared and
  unverified (`crates/scp-did/src/attestation.rs:314`).
- Both shipped platform adapters (Apple, Android) honestly report pairs that publish
  nothing, and their method labels do not match the generated UniFFI protocol, so a
  consumer must hand-write the conformer that answers the two questions.
