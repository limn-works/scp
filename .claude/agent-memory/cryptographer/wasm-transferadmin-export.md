---
name: wasm-transferadmin-export
description: WASM TransferAdmin convergence (d05e8ad7d) + signed context-export re-confirmation — SOUND, one cosmetic comment nit
metadata:
  type: project
---

# WASM TransferAdmin → native convergence + signed-export re-audit (commit d05e8ad7d, slice1-roles)

VERDICT: cryptographically SOUND. No blocking findings. One LOW cosmetic comment-staleness nit.

## TransferAdmin change (manager.rs:4055, dispatch_governance_action_ext)
- New arm: (a) reject non-member new_admin BEFORE any mutation (CTX_2015), (b) collect EVERY assignment with role_name=="admin", demote each to "member" via shared `system_assign_role`, (c) promote new_admin to "admin". STOPS writing creator_did.
- Uses SHARED `scp_protocol::context::roles::ContextRoleState::system_assign_role` (NOT a WASM re-impl). manager.rs:49 imports ContextRoleState directly.

## Why immutable creator_did is crypto-correct
creator_did is the single root-of-trust for the export: export SIGNING key (sign_with_identity(creator_did,"#active")), HMAC identity (compute_export_hmac(creator_did)), exporter_did (envelope; import asserts exporter_did==creator_did), import verify-key source (verify_snapshot_signature resolves key from snapshot.role_state.creator_did), UCAN root issuer (mint_role_tokens iss=creator_did) + token mint issuer.
- Keeping it immutable: a context exported AFTER an admin transfer still verifies under the ORIGINAL creator. Round-trip sound.
- OLD behavior (relocate creator_did→new_admin) would have BROKEN export: both sign_with_identity (identity.rs:3285) and compute_export_hmac (identity.rs:616) require a `Local` registry record with key material. new_admin is not Local on the creator's node → next export_context FAILS (IDENT_1028 Resolved / IDENT_1001 absent). Even if Local, it relocates the entire root-of-trust + creates iss/creator_did inconsistency. Confirmed fail-closed.

## Role-token re-mint (random nnc) vs export digest determinism
- system_assign_role → mint_role_tokens (roles.rs:2216) mints fresh UcanToken{iss,aud,att,nnc} per capability; nnc=generate_nonce (nonce.rs:69, OsRng CSPRNG — sound). NO signature, NO expiry field on UcanToken (by design, roles.rs:1247 — authority grounded in signed governance action + signed snapshot).
- Re-mint only happens on LIVE governance (TransferAdmin), NOT on import (import restores role_state VERBATIM, snap.role_state.clone()). So tokens are minted once, carried verbatim through export/import.
- DETERMINISM: digest = SHA-256(WASM_EXPORT_SIGN_DOMAIN "SCP-CONTEXT-EXPORT-V1:" || EXPORT_SCOPE_TAG_FULL || JCS(snapshot)). For a FIXED role_state value the JCS is byte-stable → sign/verify round-trip + re-verification of a received export are correct (JCS preserves array order; verifier re-canonicalizes received bytes). The nnc randomness is INSIDE the signed preimage, fine.
- NUANCE (NOT a finding, native-matching, pre-existing): RoleAssignment.tokens is plain Vec<UcanToken> (roles.rs:1352) with NO sort attr; mint_role_tokens iterates role.capabilities (HashSet) so token Vec order = HashSet iter order = non-deterministic ACROSS independent re-mints. Does NOT affect: single-export sign/verify, import (verbatim), or cross-member convergence (each creator signs only its OWN snapshot; export digest is per-exporter, never compared cross-member). Native embeds the identical ContextRoleState via the same mint_role_tokens, so WASM CONVERGES to native — the point of the change. No nonce-reuse (nnc is replay id, not AEAD nonce). No expiry (no expiry field).

## Re-confirmed (unchanged this commit)
- ContextRoleState set/map fields ALL deterministic: members serde_sorted_set, member_capabilities/suspended_capabilities serde_sorted_set_map, RoleDefinition.capabilities serde_sorted_set, ceiling serde_sorted_set. canonicalize_snapshot_sets (manager.rs:7565) sorts read_exclusion_list/revoked_tokens/seen_nonces_v3/executed_proposals/broadcast. JCS sorts outer object keys.
- Signature binds FULL role_state (it's inside JCS(snapshot)).
- Version gate (manager.rs:6549/6568) uses symbolic WASM_EXPORT_VERSION (now =5, bumped from 4). version>5 → CTX_2094; version<5 → CTX_2094 (fail closed before sig verify). Only exactly-5 reaches verify_snapshot_signature. No downgrade/replay. Pre-signed (v<5) refused.
- crypto:None on import (manager.rs ~6982): imported ctx holds NO live MLS state; role_state advisory only; member_sequence_numbers sidecar decoupled from any AEAD key → reset/forged seq CANNOT cause GCM nonce reuse (no key bound until fresh Welcome starts counters at 0). debug_assert!(crypto.is_none()). Comment flags future-risk if crypto ever populated from import.
- exporter_did==creator_did enforced (manager.rs ~6650, CTX_2093). verify_strict against #active→#agent fallback. Empty/invalid sig → CTX_2093 fail-closed. WASM_MAX_EXPORT_BYTES=16MiB DoS guard BEFORE canonicalize.

## LOW (cosmetic, non-blocking)
- manager.rs:6563 comment says "Versions below 4 carried no Ed25519 signature" but constant is now 5; the LOGIC uses `< WASM_EXPORT_VERSION` so it's correct — only the literal "4" in prose is stale. Recommend updating comment to track the constant (or drop the literal).
