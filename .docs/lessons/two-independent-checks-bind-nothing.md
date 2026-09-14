# Two Independent Checks Bind Nothing

**Rule**: When a validator reads two parts of one credential, it must compare a value that appears in both. Checking each part against a constant leaves an attacker free to pair one genuine part with a part he wrote.

**Date:** 2026-08-17
**Source:** pull request #2363, the ADR-025 App Attest fail-closed change — `AppleDeviceAttestation.verify(token:)`

## What happened

`verify(token:)` applied two clauses that shared no value. Clause 3 evaluated the `x5c`
certificate chain as an X.509 path anchored at Apple's App Attest root and read
no byte of `authData`. Clause 4 compared `authData` bytes 0–31 against
`SHA-256(appId)`, bytes 37–52 against an AAGUID, and bytes 53–54 against
`0x0020`, and it read no certificate. Both clauses passed on their own inputs,
and no value crossed between them.

An attacker who enrols his own App Attest-entitled app, calls
`DCAppAttestService.attestKey`, and keeps the `x5c` array Apple issued for his
key can then write 87 bytes of `authData` carrying the victim app's App ID hash,
an AAGUID, and a length. All three of those are public constants, and `verify`
returned `true` for that pair.

Apple's article "Validating Apps That Connect to Your Server" states the missing
comparison twice: its step 5 hashes the credential certificate's public key and
compares that hash against the app's key identifier, and its step 9 compares the
credential ID inside `authData` against the same identifier. One value, named by
both halves.

## The pattern

A structural validator decomposes into per-field checks, and each field check is
easy to write, easy to review, and easy to test. The composition is where the
guarantee lives, and nothing about the per-field checks makes the composition
visible: the code reads as a complete list of constraints while the object it
accepts is two objects glued together.

Two questions catch it:

- Which value does part A share with part B? If the answer is none, the validator
  decides nothing about the pair.
- Could the parts come from two different producers, and would this validator
  notice? Assemble that hybrid by hand and run the validator on it.

## How this repository catches it

Write the cross-part comparison as its own named step, and give it a test that
builds the hybrid the check exists to reject.
`AppAttestCredentialBindingTests` in
`bindings/swift/Tests/SCPTests/Platform/AppleDeviceAttestationTests.swift`
builds one genuinely anchored chain beside a second chain's key identifier and
asserts `false`, which is the substitution the missing clause admitted.

## Related

- `.docs/lessons/new-precondition-makes-rejection-tests-vacuous.md` — the test
  hazard that arrives with the fix.
- `.docs/lessons/behavioral-invariant-must-be-asserted-on-every-bridge.md`
