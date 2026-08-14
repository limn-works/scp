---
name: trust-hardening-canon-fallibility
description: CLEAN review of fu-trust-hardening (7a336214c, #1998/#1999/#2000) — canon-error threading + is_adverse exhaustive + advisory-renewal docs
metadata:
  type: project
---

# fu-trust-hardening @7a336214c — CLEAN (no defects)

Reviewed the fallibility-threading + is_adverse + advisory-renewal hardening set. Resolves #1998/#1999/#2000.

**Why clean:** the fallible-conversion is transparent because every canonicalized value on a real path is a `serde_json::Value`, and JCS/serde canonicalization of a `Value` cannot fail (serde_json Number can't hold NaN/Inf). So no input that used to succeed now early-returns; happy path byte-identical; no hashed-bytes/wire change (attestation, revoke, tool-registration, challenge all unchanged).

Traced escrow error paths (invoke.rs):
- `invoke_tool` (economy): helper `?`→Err caught at call site → `void_escrow_and_rollback` (voids un-captured escrow + `reverse_spend`). ✓
- `invoke_tool_with_cancellation`: input_hash + output_hash errors each `void_escrow_and_rollback` BEFORE `finalize_tool_escrow` (capture) and before `economy_post_check` → escrow not yet captured, no double-refund, no half-commit. Same shape as pre-existing output-validation-fail branch. ✓
- mcp.rs: output_hash routed through `refund` closure (refunds hard-rate-limit token) — consistent with every other failure branch; event not yet appended → no half-commit. ✓
- uniffi bridge invoke_tool: no escrow/rate-limit; output_hash `?` just skips event append. ✓
- resolvers.rs `token_revoked_payload()?`: UcanError == CoreUcanError, event not appended on err. ✓

`is_adverse` exhaustive match (no wildcard): true-set = exactly {RemoveMember, SuspendCapability, SuspendAccess, RevokeAccess, ResetMember} — identical to deleted ADVERSE_ACTION_TYPES. String bridge `is_adverse_variant_name` via `adverse_representative` (5 arms→rest None→false); `is_adverse_action_type` keeps `empty ⇒ adverse` + `unknown ⇒ non-adverse`. Behavior identical to old `is_empty() || contains`. New GovernanceAction variant now fails to compile until classified. ✓

New variants: ToolError::CanonicalizationFailed is genuinely new (0 on main); ExecutionFailed/RevocationFailed reused. No exhaustive-match breakage (workspace compiles).

Tests assert what they claim: `renewal_fields_are_unauthenticated` is mutation-sound (asserts baseline==tampered canonical bytes + tampered still verifies — fails if renewal fields entered preimage). `identity_resolver_is_total` uses across-2-calls determinism as observable proxy for "no transient err path" (real guarantee is the pure no-I/O impl). attestation.rs authenticated-field doc list exactly matches canonical_attestation_bytes (id/type/issuer/subject/claim/evidence/issued_at/expires_at/revocation_status; renewal fields excluded). renewed_at consumers (renewal.rs needs_renewal, aggregate.rs filter_by_freshness) only drive degraded/soft status = consistent with "advisory only" doc.

Verified: 3171 scp-protocol lib tests + 18 runtime invoke tests pass; scp-ffi-uniffi/-common/-napi cargo check clean.
