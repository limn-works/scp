# WASM Slice1 Roles — Signed Context Export w/ ContextRoleState (branch wasm/1877-slice1-adopt-context-role-state, HEAD 4babda7ba)

Audit verdict: SOUND. No blocking crypto findings. 2 LOW (fail-closed coverage gap + unsigned advisory field).

## Construction
- `crates/scp-ffi/wasm/src/manager.rs`. Export digest single-source `wasm_export_snapshot_digest` (L7616): `SHA-256(WASM_EXPORT_SIGN_DOMAIN="SCP-CONTEXT-EXPORT-V1:" || [EXPORT_SCOPE_TAG_FULL=0x00] || JCS(snapshot))`. Used by producer (export_context L6500) AND verifier (verify_snapshot_signature L6685). No divergent inline digest (other Sha256 at 5671-5776 are deploy-id/wire, unrelated).
- Domain is fixed const ending in ':'; scope tag is exactly 1 byte → JCS starts at fixed offset, no length-prefix ambiguity. Sound preimage.
- Ed25519 sign via `sign_with_identity(creator_did, "#active", digest)`; verify via `verify_strict` (rejects malleability) against key resolved STRICTLY from `creator_did` local registry (#active→#agent fallback), NEVER envelope-supplied. import enforces `exporter_did == snapshot.role_state.creator_did` (creator_did is INSIDE signed snapshot).

## Determinism (the crux)
- snapshot-level set→array fields sorted by `canonicalize_snapshot_sets` (L7581): read_exclusion_list, revoked_tokens, seen_nonces_v3 (by nonce), executed_proposals (by pid), broadcast.subscribers + author_block_lists. Applied identically on export AND import before JCS.
- ContextRoleState (scp-protocol/src/context/roles.rs) inner sets self-canonicalize via serde codecs (serde_util.rs L430/L500): `serde_sorted_set` sorts HashSet by element canonical-JSON bytes (total order, fails LOUD on JCS err — no empty-key collapse); `serde_sorted_set_map` sorts inner sets. Covers: members, member_capabilities, suspended_capabilities, ceiling.capabilities, role_definitions[*].capabilities.
- Outer HashMaps (assignments, role_definitions, member_sequence_numbers, resolved_proposals_json, cooldown_until, broadcast maps) → JCS object-key sorted. Deterministic.
- Capability enum: default externally-tagged serde; unit→string, ToolInvoke/Custom→{tag:string}. Deterministic under JCS.
- INTENTIONAL non-determinism (documented, SOUND): assignments[*].tokens is Vec<UcanToken>, NOT sorted. mint_role_tokens (roles.rs L1248) iterates capabilities HashSet in unspec order + fresh random nnc per token. Single-signer VERBATIM model: signer signs exact JCS bytes it produced; importer re-canonicalizes THOSE received bytes (Vec order preserved by JCS) + verify_strict. Faithful export → identical bytes → verifies; tamper → fails. Byte-parity across independent exports/native NOT claimed. Tokens carried verbatim, NEVER re-minted either side. SOUND for this model.

## Injectivity: no two semantically-distinct role_states collide (distinct maps→distinct keys/values→distinct JSON). Tokens random-nonce divergence is intra-state, not a collision.

## Signature coverage: only `snapshot` is signed. Unsigned envelope fields all safe:
- version: exact-match gate (==WASM_EXPORT_VERSION=5) BEFORE sig check; downgrade rejected CTX_2094 not accepted.
- exporter_did: ==signed creator_did else self-reject.
- exported_at: set on export, NEVER read on import (verified grep). Advisory. LOW: unsigned but unused.
- integrity_mac: defense-in-depth HMAC over same preimage; empty→skipped, Ed25519 still mandatory. self-import only (creator key local).

## MLS / nonce-reuse: import sets `crypto: None` (L6996) + debug_assert. role_state advisory metadata (no decryption power); member_sequence_numbers sidecar decoupled from any live AEAD key. No GCM key bound at import → no nonce to reuse until fresh Welcome (starts counters from 0). Documented WARNING: if future code populates crypto from imported MLS, sidecar becomes nonce-reuse vector — re-evaluate. Broadcast import mints FRESH generate_sender_key() per author + next_sequence:1 (no key reuse). SOUND.

## LOW findings
1. IdentityRecord::Resolved (DID-string-only, no local key) FAILS CLOSED for #active/#agent in resolve_verification_method_key (identity.rs L642) → genuine cross-party import where importer lacks creator local key CANNOT verify → rejects. Fail-closed (never accepts unverifiable), but means cross-party import is non-functional without JS-side DHT resolution. Coverage gap, not vuln.
2. exported_at unsigned (cosmetic; unused).

## Anti-replay clamp: seen_nonces_v3.inserted_at_ms (f64, IS in signed snapshot) + executed_at_ms clamped `.min(now)` ONLY on import AFTER verify — doesn't affect verified bytes. creation_timestamp_secs consumed VERBATIM (signed; §9.9.3 convergence requires it; backdate only shortens TTL).
