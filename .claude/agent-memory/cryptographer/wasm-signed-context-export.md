---
name: wasm-signed-context-export
description: WASM signed context-export (§23.16.8/ADR-050) construction soundness — JCS+Ed25519 verbatim role_state snapshot; reviewed HEAD cde3c1002, SOUND
metadata:
  type: project
---

# WASM Signed Context Export (crates/scp-ffi/wasm/src/manager.rs)

Reviewed at HEAD `cde3c1002` (branch slice1-roles). Construction is SOUND, no blocking findings.

**Why:** final crypto sweep before ship of WASM signed context export — JCS-canonicalized Ed25519-signed snapshot embedding shared `ContextRoleState` + member_sequence_numbers sidecar.

**How to apply:** if any of these load-bearing facts change, re-review.

## Construction
- Preimage: `SHA-256(WASM_EXPORT_SIGN_DOMAIN=b"SCP-CONTEXT-EXPORT-V1:" || [EXPORT_SCOPE_TAG_FULL] || snapshot_jcs)` via single-source `wasm_export_snapshot_digest` (manager.rs:7675). Producer + verifier + test all route through it — no drift. Mirrors native `ContextExport::canonical_snapshot_hash`.
- Sign: creator `#active` Ed25519 over digest (export_context ~6557). Verify: `verify_strict` against creator-DID-resolved #active→#agent key (verify_snapshot_signature ~6740). Fail-closed on empty/invalid sig, bad hex, key-resolve failure.
- snapshot serialized via `serde_json_canonicalizer::to_vec` (RFC 8785 JCS) AFTER `canonicalize_snapshot_sets`.

## Digest determinism (the crux) — SOUND
- `canonicalize_snapshot_sets` (manager.rs:7640) sorts every snapshot-level Vec-from-HashSet/HashMap (read_exclusion_list, revoked_tokens, seen_nonces_v3 by nonce, executed_proposals by proposal_id, broadcast.subscribers, author_block_lists values). Snapshot-level HashMaps (resolved_proposals_json, cooldown_until, member_sequence_numbers, key_epochs) rely on JCS object-key sort.
- `role_state: ContextRoleState` NOT touched by canonicalize_snapshot_sets — every HashSet under it carries `#[serde(with="serde_sorted_set")]` and every `HashMap<String,HashSet>` carries `serde_sorted_set_map` (roles.rs:495 ceiling.capabilities, :510 CapabilityCeilingRaw, :1060 RoleDefinition.capabilities, :1396 members, :1404 member_capabilities, :1425 suspended_capabilities). Outer plain maps `assignments`/`role_definitions` → JCS object-key sort.
- `serde_sorted_set` (serde_util.rs:466) sorts by per-element JCS canonical bytes (NOT Ord — Capability has no Ord). Set elements distinct → distinct JCS bytes → total order, no ties. JCS failure propagates as hard ser error (never empty-key collapse). SOUND.
- ONLY non-byte-stable subtree: `assignments[*].tokens` Vec<UcanToken> — order-preserving mint order + fresh random `nnc` per token. INTENTIONALLY unsorted. SOUND for single-signer VERBATIM model: exporter signs exact bytes it produced, importer re-canonicalizes + verify_strict THOSE SAME received bytes, tokens carried verbatim never re-minted on either side. No cross-family byte-parity claimed (ADR-050). UcanToken/UcanPayload contain only Vec+scalar+optional fct:Value (no unsorted map/set; fct objects JCS-sorted).

## Authority binding — SOUND
- exporter_did == snapshot.role_state.creator_did enforced (deserialize_and_verify_envelope ~6687, CTX_2093). Verify key ALWAYS from creator_did, never envelope.
- `TransferAdmin` (manager.rs:4119) transfers ONLY the `admin` ROLE (demote current admins→member, promote new→admin); `creator_did` NEVER mutated. Export-signer identity immutable across admin transfer — sig authority cannot be hijacked. Tests at :10530/:10592 pin this.
- Version gate: `version != WASM_EXPORT_VERSION(=5)` rejected (>= CTX_2094 newer, < CTX_2094 "predates signed format, refusing unverifiable"). No downgrade/replay to unsigned.

## crypto:None decoupling — SOUND
- import_context sets `crypto: None` (manager.rs:7057) + debug_assert. Imported role_state is advisory metadata, confers NO decryption. member_sequence_numbers sidecar decoupled from any live AEAD key → no GCM nonce reuse (no nonce exists until fresh Welcome establishes crypto with counters from 0). Documented re-eval trigger if crypto ever populated from imported MLS.
- Broadcast import mints FRESH `generate_sender_key()` per author (manager.rs:6922) — not a reused/derived key.

## Defense-in-depth / DoS
- HMAC-SHA256 (HKDF domain-sep, derive_export_hmac_key identity.rs) over snapshot_json; verified ONLY on self-import (creator_key_available). Constant-time `mac.verify_slice` (identity.rs:737). Subsumed by Ed25519. Minor DOC imprecision: comment says "identical preimage" but HMAC is over raw snapshot_json while Ed25519 is over SHA256(domain||tag||snapshot_json) — both authenticate same canonical bytes, harmless.
- WASM_MAX_EXPORT_BYTES = 16 MiB length cap BEFORE from_slice/JCS (DoS amplifier guard, CTX_2032).
- Cross-party import where importer holds only Resolved (no Local) record → resolve_verification_method_key FAILS CLOSED (cannot get #active/#agent without DHT). Rejects, never accepts. Availability limitation, not security defect.

## Anti-replay clamp
- seen_nonces_v3.inserted_at_ms & executed_at_ms `.min(now)` clamped (no future-push). creation_timestamp_secs consumed VERBATIM (NOT clamped) — §9.9.3 cross-member TTL-base convergence; authenticated by creator sig so forging needs creator key.

## Test gotcha
- `cargo test -p scp-ffi-wasm --target wasm32-unknown-unknown` FAILS compile (23 errs) — tests ref `scp_identity::` unlinked under this invocation. Pre-existing tooling issue, unrelated to construction.
