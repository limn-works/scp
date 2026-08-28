---
name: custody-derived-not-declared-2415
description: Defense assessment of PR #2415 (spec/custody-vocabulary-names-the-backend) — where the "published custody is derived, not declared" invariant is enforced by construction and where it is only convention.
metadata:
  type: project
---

# PR #2415 custody vocabulary — defense assessment (2026-08-28)

**Claim under review:** the DID-document custody value is derived off the running
backend, so a publisher "has no field to write a false claim into."

## Where the invariant is NOT enforced by the type system
- `ScpKeyCustodyAttestation` derives `Deserialize` (`crates/scp-did/src/attestation.rs:60`).
  Serde's generated impl lives in the defining module, so private fields are no
  barrier: `from_service_entry` (`:403`, pub) turns attacker-authored JSON into a
  fully-formed struct with any `KeyCustodyModel`. `derive`'s doc at `:295` ("the only
  way to build an attestation"), the module header at `:16`-`:20`, and
  `.docs/specs/03-identity.md:163` all state a property serde falsifies.
- `DidDocument::service` is `pub` (`crates/scp-did/src/document.rs:199`) and `Service`'s
  three fields are pub (`:230`-`:238`) — a caller pushes a hand-written service entry
  and never touches the attestation type.
- **Fix shape:** split reader type from writer type. Writer gets `Serialize` only.
  Make `service` private behind typed accessors.

## The invariant currently guards nothing
`derive` and `set_custody_attestation` have ZERO non-test callers. §27.4.4 of
`.docs/specs/27-attestations.md` says so in-branch ("Nothing writes one either").
The shipped surface is `identity_published_custody` — a read-only accessor returning
`Option<String>` to the local caller. No DID document publishes a custody value.

## Fail-closed in the three `build_key_custody` factories
- Structural: `other => Err(VALID_7005)` wildcard default-deny; `in_memory` is
  compile-excluded (cfg-gated `scp_platform::testing` module + cfg-gated enum variant),
  not comment-excluded; `custody_substrate` is an exhaustive match per bridge.
- Convention only: the `os_keystore`-without-provider `None => Err(IDENT_1003)` arm,
  hand-written three times (`scp-ffi/src/identity.rs:739`,
  `scp-ffi/uniffi/src/bridge.rs:6768`, `scp-ffi/napi/src/custody.rs:766`).
  **Positive construction:** `enum CustodySelection<P> { EncryptedFile, OsKeystore(P) }`
  makes provider-less `os_keystore` uninhabited; hoist the parse to `scp-ffi-common`
  (the shared `custody_substrate.rs` in this PR proves the shape works).

## Trust boundary at the callback
`key_is_extractable`/`unlock_factor` are answered by the SDK consumer's own adapter.
For `os_keystore` the adapter author and the publisher are the same participant, so
deriving moves the lie from a struct field to a callback body. Protocol may conclude
only "the injected adapter said so." Rust-side backends (`FileKeyCustody`,
`SqliteKeyCustody`) are a real derivation but can only produce `extractable-passphrase`
or nothing.

## Detection: none
No verifier (`custody_attestation()` parses and checks nothing). No producer of
`CustodyViolationType::AttestationMismatch` outside its own tests. F4 carries no
signature; on `did:web` (not self-certifying) it carries no authentication at all.
No telemetry on a custody value changing between document versions.

## Well defended (keep)
`parse_unlock_factor` positive whitelist → unknown string degrades to
`CallerSuppliedKey` (publishes nothing), never to a claim. `from_substrate` three
explicit pairs + `_ => Err`. `InMemoryKeyCustody` reports (true, Unprotected) →
cannot mint a publishable claim, with a test asserting `derive` errors.
`AppleKeyCustody.unlockFactor` returns `"caller_supplied_key"` under
`BiometricPolicy.none` rather than guess between `"passphrase"` and `"unprotected"` —
fail-closed applied to an open question. `CustodyMigrationTarget::InMemory` deleted
from an ungated production enum (real nullifier severance).

## Stale docs introduced/left by this PR
- `crates/scp-platform/src/android/key_custody.rs:35`-`:41` says the UniFFI callback
  "asks the adapter neither" question — the same PR adds both
  (`scp-ffi/uniffi/src/lib.rs:482,497`) and Android implements them
  (`AndroidKeyCustody.kt:612,648`).
- OQ-11 in `.docs/specs/03-identity.md` asks how a callback reports extractability —
  the same PR answers it.
