# A New Precondition Makes Existing Rejection Tests Vacuous

**Rule**: When you add a check that a validator applies to every input, every existing case that asserts rejection can start passing for the new reason. Re-establish each case's own reason before you call the change done.

**Date:** 2026-08-17
**Source:** pull request #2363, the ADR-025 App Attest fail-closed change — `AppleDeviceAttestation.verify(token:)`

## What happened

`verify(token:)` gained clause 5, which requires the credential ID in `authData`
to equal `SHA-256` of the credential certificate's public key and to equal the
App Attest key identifier the adapter stored. Roughly forty cases in
`AppleDeviceAttestationTests.swift` assert `verify(token:) == false`, each naming
one clause it breaks.

Two hazards arrived with that clause, and both make a case pass while testing
nothing:

- Every case built its adapter through a helper that stored no key identifier.
  Clause 5 rejects every token for such an adapter, so all forty cases would have
  passed with clauses 1 through 4 deleted.
- Four cases put a certificate other than `credentialCertificate` at `x5c`
  element 0 while leaving the default credential ID in `authData`. Those tokens
  broke clause 5 as well as the clause each case names, so each would have passed
  with the anchor evaluation removed.

## The pattern

A rejection test proves nothing unless exactly one constraint fails. A new
precondition that applies to every input is the fastest way to break that, and
the suite stays green throughout, so nothing announces the loss.

## How to catch it

Run the mutation the case exists to catch. Delete the check the case names —
return `true` from it — and confirm that case fails. `verify` gained clause 5 and
the sign-counter constraint in one change, and mutating each one in turn is what
surfaced the four cases whose token broke two clauses at once. Repairing them
meant giving each token a credential ID matching its own element 0, and seeding
the adapter with that same identifier, so clause 5 holds and the named clause is
the only one left to fail.

## Related

- `.docs/lessons/two-independent-checks-bind-nothing.md` — the defect whose fix
  introduced this hazard.
- `.docs/lessons/test-whitelist-masks-ci-red.md`
- `.docs/lessons/conformance-kdoc-is-not-coverage.md`
