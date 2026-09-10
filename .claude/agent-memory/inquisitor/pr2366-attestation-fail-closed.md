---
name: pr2366-attestation-fail-closed
description: Interrogation of pull request #2366 (attestation verification fail-closed, issue #2335) — which premises it inherited without a human deciding, and which compromises it documented instead of fixing
metadata:
  type: project
---

# Pull request #2366 — attestation verification fail-closed (GitHub issue #2335 findings 2, 9, 11, 13)

Verdict returned: UNSOUND — REVERSE in part. A pure `verify_identity_link_attestation`
seam in `crates/scp-protocol/src/identity/attestation.rs` is sound; a scope boundary and a
boolean bridge surface are not.

**Why:** a review asked for every premise this change inherited without a human deciding it,
plus every compromise it documented instead of fixing. CLAUDE.md's scar-tissue defense makes
each such item a blocker.

**How to apply:** when a later pass revisits attestation verification, re-check these before
re-litigating anything else.

## Blockers named

1. Spec `.docs/specs/03-identity.md:373` — "revocation endpoint check (§18.2.2
   `AttestationRevocations`) is ALWAYS required regardless of `revocation_status` value" — is
   unimplemented, while a doc comment and a pull-request body both claim "every §3.5.4 step".
   A resolved DID document already sits in hand at each bridge call site.
2. Three SDK wrapper files excluded "because other agents hold them". File ownership is not an
   external constraint. Every other compromise below descends from that one boundary.
3. Capability-matrix cell `verify_attestation.kotlin: true`
   (`.docs/standards/sdk-capability-matrix.json:188`) states a falsehood this change created,
   and its own adjacent `notes` string contradicts it.
4. Caller-supplied `issuer_public_key_hex` retained as an assertion to check. Spec §3.5.4 asks
   a caller for no key; a two-argument signature survived so three wrapper call sites keep
   compiling.
5. Class-2 (Reference) attestations return `false`, which §3.5.4 Class 2 step 3 forbids
   treating as a negative ("Do not cache a negative result").
6. §3.5.4 step 5 freshness degradation is computed in a seam and discarded by
   `decide_link_attestation`.
7. A `call_invariants` regex named three production Rust functions `*_module_scope`, then
   `scripts/bridge-aliases.json` widened to admit those names.
8. `ensure_did_resolver_initialized_on` lost a `#[cfg(feature = "testing")]` gate on a UniFFI
   bridge, which makes UCAN-validation resolver strength depend on call order within one
   instance (`DispatchDidResolver::new(None)` selects a DID-string-parse fallback).

## Cross-slice incoherence recorded

One pull request ships two contradictory answers to "which key signs an attestation":
identity-link verification resolves a document and uses `#active`/`#agent`, while threshold
verification uses `IdentityDidPublicKeyResolver`, a `#0`-from-DID-string parse whose own doc
comment disclaims `#active`/`#agent` use. Root: an inherited ADR-017 `#0` claim nobody
re-examined.

Related: [[scp-out-046-streaming-saga-seal-fsm]], [[adr057-reciprocal-announce-mesh]]
