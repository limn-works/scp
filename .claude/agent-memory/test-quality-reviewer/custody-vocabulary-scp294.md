---
name: custody-vocabulary-scp294
description: Test-coverage map and holes for the SCP-294 custody vocabulary rename (PR #2415) — which bridge/SDK cells assert what, and the three cells nothing covers.
metadata:
  type: project
---

# SCP-294 custody vocabulary (PR #2415) — coverage matrix

**Fact.** The branch replaced the request-side custody vocabulary with two values
(`encrypted_file`, `os_keystore`), retired five strings (`platform`, `software`,
`file`, `platform_managed`, `hardware`), and added a derived published-custody
value read off the running backend.

**Why:** reviewed for tests that pass while the behaviour they name is broken.
Findings are load-bearing for any follow-up custody work.

**How to apply:** before adding custody tests, check this matrix — the holes are
still holes unless a later commit filled them.

## What is genuinely covered

- Retired-string rejection reaches all three bridges through a real SDK entry
  point with an exact code assertion: Python `test_real_ffi.py:296` (parametrized,
  `[SCP-VALID-7005]`), TS `integration.test.ts:871-887` (real NAPI),
  Swift `CustodyTypeTests.swift:166`, Kotlin `CustodyCallErrorCodeTest.kt:147`.
  No dead `let _ = fn;` references anywhere in the branch.
- `os_keystore` without a provider → `SCP-IDENT-1003` drives the real
  `build_key_custody` on all four SDKs, not the parser.
- Derived-custody over the *real* `FileKeyCustody`:
  `crates/scp-platform/src/file.rs::derived_published_custody_is_extractable_passphrase`
  plus Python `test_real_ffi.py:234` (`extractable-passphrase`).
- `ScpKeyCustodyAttestation` fields are private with only `derive` — a caller
  cannot name a published value. Enforced by the type system, not a test.
- Kotlin conformance dispatcher asserts `assertNull(stubBindings.identityCreateCustody)`,
  which proves the bridge was not called on a rejected fixture.

## The holes

1. **`CallbackKeyCustody::custody_substrate` has zero coverage on two of three
   bridges.** `crates/scp-ffi/uniffi/src/bridge.rs:929-945` and
   `crates/scp-ffi/napi/src/custody.rs:278-300` carry the adapter's two answers
   across the FFI. No Swift, Kotlin, TS, or Rust test reads a non-null published
   value through them. Only PyO3's is covered
   (`test_identity_create_with_custody.py:270`).
2. **Every non-Python published-custody test asserts `null`.** UniFFI Rust tests
   (`bridge.rs:23444`), Swift (`CustodyTypeTests.swift:193`), Kotlin, and TS
   (`integration.test.ts:891`) all use the in-memory backend, whose
   (extractable, unprotected) pair is unstatable. A `published_custody_wire_value`
   that returned `None` unconditionally passes all of them.
3. **Nothing publishes the attestation into a DID document.**
   `set_custody_attestation` / `ScpKeyCustodyAttestation::derive` are called only
   from tests. `identity_published_custody` reads the live custody registry, not
   the document. The capability-matrix note and the method name both claim
   DID-document publication that does not happen.
4. **`AppleKeyCustody` declares no `KeyCustodyProvider` conformance**
   (`public final class AppleKeyCustody: Sendable`, AppleKeyCustody.swift:240) and
   its methods use unlabeled first parameters (`keyIsExtractable(_ keyId:)`) where
   the UniFFI protocol requires `keyIsExtractable(keyId:)`. Same for Android:
   `works.limn.scp.android.platform.KeyCustodyProvider` takes `KeyHandle`, the
   UniFFI one takes `keyId: String`, and no adapter bridges them.
5. **No shipped adapter can reach `NonExtractableBiometric` or
   `NonExtractablePin`.** Apple `.required` reports (extractable, biometric);
   Apple `.none` reports caller_supplied_key; Android always reports
   `"unprotected"`. Both non-extractable values exist only under test fakes.
6. `biometricRequiredReportsBiometricUnlockFactor`
   (AppleKeyCustodyTests.swift:692) is gated on `biometricKeychainAvailable`,
   which is false on an unentitled CI runner — the only assertion of
   `unlockFactor == "biometric"` never runs there.

Related: [[feedback_test_duplication]]
