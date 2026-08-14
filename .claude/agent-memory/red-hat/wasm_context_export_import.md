---
name: wasm-context-export-import
description: Attack-surface analysis of WASM context export/import verbatim role_state restore (slice1-roles, commit f319ca863)
metadata:
  type: project
---

# WASM Context Export/Import (verbatim ContextRoleState restore)

**Why:** PR converged WASM `export_context`/`import_context` to native — snapshot embeds shared `ContextRoleState` restored VERBATIM (no `system_assign_role` recompute), fixing BLACK-CEIL-01 (suspended-then-widened member silently regained widened cap on import recompute). Signed envelope: Ed25519 over SHA-256(domain || EXPORT_SCOPE_TAG_FULL || JCS(snapshot)).
**How to apply:** When reviewing WASM export/import or any "restore verbatim from signed snapshot" path, the trust hinges on the signature-verification key resolution path.

## Trust model (the load-bearing facts)
- `crates/scp-ffi/wasm/src/manager.rs:6627` — import enforces `exporter_did == snapshot.role_state.creator_did`.
- `verify_snapshot_signature` (manager.rs:6682) resolves the verifying key ONLY from the local `IDENTITY_REGISTRY` via `resolve_verification_method_key(creator_did, "#active" then "#agent")`.
- `resolve_verification_method_key` (identity.rs:642): `#active`/`#agent` keys are exposed ONLY for `IdentityRecord::Local` (holds private key bytes). The `Resolved` arm (DID-resolution-only handle, identity.rs:684) HARD-REJECTS `#active`/`#agent`. Unknown DID → "not found".
- CONSEQUENCE: WASM import signature verification SUCCEEDS ONLY if the importer holds the creator's `Local` record (private key material). A genuine cross-party import (creator's DID resolved-only, no private keys) FAILS CLOSED at signature verify. There is NO cross-party WASM import path in this bridge today.
- DID binding: `identity_create` (identity.rs:1429) derives `did = did:dht:z<zbase32(#0 pubkey)>`. Cannot register a `Local` record under a victim's DID without the victim's `#0` private key. NOTE: DID commits to `#0` only; `#active` binding is the registry's word — but you still need `#0` priv to occupy the DID slot.
- `crypto: None` on import (manager.rs ~6990) — imported context carries NO MLS state. Imported `role_state` membership/capabilities are ADVISORY metadata; decryption requires a fresh MLS Welcome via `join_context_encrypted`. Importing a snapshot grants ZERO message-decryption ability by itself.
- `join_context_encrypted` (manager.rs:2283) rejects a member already in `role_state.members` (membership-only guard at :1840). An imported member (already in members verbatim) can't re-establish crypto through that exact path.

## Divergence from native (NOT a vuln, but note)
- Native `import_context` (scp-runtime/src/context/lifecycle_helpers.rs:1721) takes `verifying_key: &ed25519_dalek::VerifyingKey` as an EXPLICIT param — the FFI/SDK caller DHT-resolves the creator key and passes it. WASM has no such param (ADR-034: no DHT on WASM side); it resolves locally. So native supports true cross-party import; WASM is effectively self-import / same-registry only. This is a documented ADR-034 design choice, not a bug.

## Verdict
- All assemble-malicious-snapshot chains require the creator's signing key (= creator collusion / compromise) → native-equivalent, in-band, NOT a WASM-specific finding.
- Version gate strict (==5, manager.rs:7264): rejects both newer and older → no downgrade/replay across versions.
- `member_sequence_numbers` sidecar reset: feeds GCM seq for `encrypt_message` (manager.rs:2110), but `crypto: None` on import means a fresh MLS group is needed before any send; a reused seq under a NEW MLS epoch/key is not a nonce-reuse against the old key. Low concern in WASM.
- Anti-replay timestamps clamped to now (nonces, executed_proposals); `creation_timestamp_secs` consumed verbatim (signed, §9.9.3 convergence) — sound.
- CLEAN for WASM-specific threats. The verbatim-trust is gated behind a signature whose key is only resolvable for locally-held identities.
