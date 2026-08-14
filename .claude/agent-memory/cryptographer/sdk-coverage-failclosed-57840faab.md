---
name: sdk-coverage-failclosed-57840faab
description: Review of fix/sdk-coverage-fail-closed-and-parity @57840faab — identity citation §3.2.1→§9.12, PERM-3030 re-raise, BridgeTrustLevel discriminants, MLS provider comments-only — APPROVED
metadata:
  type: project
---

Branch fix/sdk-coverage-fail-closed-and-parity @57840faab — crypto review APPROVED (no blocking findings).

**§9.12 vs §3.2.1 citation fix (SOUND).** §9.12 = Compromise Recovery Protocol (DID-CHANGING migrate_identity, mints DidRotationEvent, ADR-003 §4b). §3.2.1 = Key Custody Migration (DID-PRESERVING). All migration/rotation-event doc-comments across 4 bridges + SDKs flipped §3.2.1→§9.12,ADR-003 §4b. Verified identity_execute_custody_migration RETAINS §3.2.1 (scp.py:639). Remaining §3.2.1 cites all legit: two-key model #0/#active, rotate_key (Layer1 ADR-003 §4a), §7.3.2.1 participation (different section). Note: old "§9.12 step 4b" was phantom — §9.12 has no numbered step 4b; rotation-event distribution lives in §9.12 step 1. New cite §9.12,ADR-003 §4b is correct.

**PERM-3030 re-raise (SOUND, anchored).** Both anchored to START: TS trust.ts:461 `/^\[SCP-PERM-3030\]/.test(msg)`, Python trust.py `error_msg.startswith("[SCP-PERM-3030]")`. NAPI error fmt `[{code}] permission error: {msg}` (error.rs:69) → msg begins `[SCP-PERM-3030]`. PERM_3030=handle-affinity (error_codes.rs:505); From<HandleAffinityError> maps to Permission{code:PERM_3030} (error.rs:543). No substring spoof. TS has 2-stage gate: `^\[SCP-PERM-\d+\]` (only UCAN-perm classified) then PERM-3030 re-raise.

**BridgeTrustLevel discriminants (MATCH).** Rust provenance.rs:48-67 ShadowBridged=0,ClaimedBridged=1,NativeBridged=2,NativeNative=3. TS bridge.ts:38 `0|1|2|3` weakest→strongest. evaluateTrust forwards (isBridged,isNativeTransport,shadowStatus) to bridge_evaluate_trust (bridge_connector.rs:98, UNCHANGED): is_bridged=false→evaluate_trust_level(None,native), true→shadow_status drives Shadow/Claimed, native ignored (bridge provenance dominates). No inversion. Defaults isBridged=false/native=true/shadow="shadow" mirror Python.

**MLS provider.rs (COMMENTS-ONLY, verified).** grep for non-comment changed lines = empty. Stale ContextManager refs (deleted per ADR-049)→"context actor/receive handler"; removed obsolete "default implementation overridden by..." trait-language (now inherent methods). Verify-after-decrypt invariant preserved verbatim ("Signature verification NOT performed here — receive handler verifies via key_resolver after open returns"). No crypto logic touched.

Side note: trust.py removed fabricated contexts_participated=1 → honest default 0 (completeness tenet, not crypto).
