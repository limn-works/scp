---
name: crypto22-s4-attestation-seam
description: CRYPTO-22 S4 KeyPackage-attestation two-layer verify seam — Add-only ground-truth struct makes Update unrepresentable; three-layer error stack; crate-root re-export gap
metadata:
  type: project
---

CRYPTO-22 S4 (branch crypto22-s4-code, final commit e51741b6) added the async DidResolver-backed KeyPackage-attestation verifier.

Two-layer seam:
- Layer A (scp-mls, wasm-safe, pure): `verify_attestation_with_resolution(attestation, &AttestationLeafGroundTruth, &resolved_doc, resolved_at, now)`. Trigger-GENERAL (`AttestationLeafGroundTruth` has a `trigger: AttestationTrigger` field, Add|Update). Enforces §9.7.1 checks 1–2 then delegates 3–13 to pure `verify_attestation`. Errors: `AttestationResolutionVerifyError` { ResolvedDocumentStale, CurrentKeyNotFound, Delegated(AttestationVerifyError) }.
- Layer B (scp-runtime, async): `verify_add_attestation(resolver, clock, attestation, &AttestationAddGroundTruth)`. Add-ONLY. `AttestationAddGroundTruth` has NO trigger field — carries `kp_init_key` directly, builds `AttestationTrigger::Add` internally. Because the async seam accepts only this type, Update is unrepresentable BY CONSTRUCTION (not just documented) — a model application of "make illegal states unrepresentable." Rationale: Update needs a last-known-good resolution-failure grace (S7) that isn't built; routing Update through this fail-closed-only seam = censorship/liveness regression. Errors: `AttestationRuntimeVerifyError` { Resolution(IdentityError), ResolutionNotFound, Verify(AttestationResolutionVerifyError) }.

**Why-is-Update-excluded** is the key design decision — carried in doc comments on both `AttestationAddGroundTruth` and `verify_add_attestation`. Layer A stays trigger-general because it does no resolution (no grace to get wrong).

Verdict: SHIP IT. Design is clean, misuse-resistant. Open LOW notes for future S6/S7 wiring review:
- `AttestationVerifyError` (+ `verify_attestation`, `AttestationVerificationContext`) NOT re-exported at scp-mls crate root, yet it's the public payload of crate-root `AttestationResolutionVerifyError::Delegated`. Deep-match consumers must import `scp_mls::keypackage_attestation::AttestationVerifyError`. Consistency gap — re-export at crate root.
- The two ground-truth structs share 6 of 7 fields with no type-level sync guard (a new Layer-A check field must be manually mirrored into `AttestationAddGroundTruth` + its internal build). Accepted cost of flat agent-first structs over a shared nested sub-struct.
- Layer B seam is public but NOT yet wired into ContextManager/Supervisor (S6/S7, gated on #2211 real resolver + SCP-CRYPTO22-005). Fails closed. Staged, not a nullifier.
- Testing carve-out (did:test:/did:key: skip resolution) is `#[cfg(any(test, feature="testing"))]`, compiled out of shipped builds, positive whitelist, did:web NOT exempt — compliant with no-dev-stand-in mandate.
