# A Convenience Wrapper That Hard-Codes a Security Parameter Hides Every Omission

**Date:** 2026-08-16
**Source:** `verify_attestation` in `crates/scp-protocol/src/trust/attestation.rs` shipped as a
three-argument wrapper that called the four-argument verifier with
`revocation_checker: None`. Three FFI bridges called that wrapper. Each bridge's docstring told a
reader it checked "revocation status," and §7.4.4 of
`.docs/specs/07-trust-validation-and-capabilities.md` states that revocation is immediate for a new
verification. A caller who revoked an attestation and then verified it got `valid: true`.

## Rule

When a function takes a security check as an optional parameter, do not ship a shorter wrapper that
supplies a value for it. Make every caller write the argument. A caller that supplies no checker
writes `None` at its own call site, where a reader and a grep both find it.

## Why the wrapper is the defect

`Option<&dyn AttestationRevocationChecker>` already encodes the choice honestly: a caller states
which revocation list it consulted, and `None` states that it consulted none. A wrapper that fills
in `None` moves that statement out of every call site and into one line inside a library, so:

- A reviewer reading a bridge sees `verify_attestation(&att, &resolver, &clock)` and reads a full
  verification, because nothing at that call site mentions revocation.
- A grep for `None` across the bridges finds nothing, so an audit that greps for the omission
  concludes the omission does not exist.
- A docstring that promises a revocation check reads as true against the wrapper's name, so ordinary
  doc review passes it.

Deleting the wrapper turned one hidden default into four visible arguments: three bridges now pass a
checker backed by a real revocation list, and `renew_attestation` takes the parameter from its own
caller.

## Related failure this is NOT

Answering `None` from a checker that consulted a real, empty revocation list is not this defect. That
answer reports what a context's list holds. The defect is a construct that answers "not revoked"
without reading any list, which is the nullifier class the builder tenets forbid — see
`.docs/standards/sdk-common.md` §Stub and Placeholder Policy. `NoOpRevocationChecker`, a public type
whose `check_revocation` returned `None` for every id, was deleted in the same change for that
reason; tests that need an empty list now define one locally.

## How to check for this class

For each parameter that gates a security check, ask two questions:

1. Does any wrapper, default argument, or builder supply this parameter without a caller naming it?
2. Does a docstring anywhere upstream of that wrapper promise the check the parameter performs?

An answer of yes to both is this defect.

## Related

- `.docs/lessons/behavioral-invariant-must-be-asserted-on-every-bridge.md` — the sibling rule for
  invariants that every bridge must re-assert in bytes.
- `.docs/lessons/coverage-gates-must-fail-closed.md`
