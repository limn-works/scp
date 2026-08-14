# WASM Signed Context Export — slice1-roles (HEAD a56fd0e31) — SOUND

Audit verdict: cryptographic construction SOUND, no blocking findings. Reviewed crates/scp-ffi/wasm/src/manager.rs (HEAD via `git show`, Read serves stale).

## Construction
- Digest: SHA-256(b"SCP-CONTEXT-EXPORT-V1:" || EXPORT_SCOPE_TAG_FULL(0x00) || JCS(snapshot)) via wasm_export_snapshot_digest (manager.rs:7615). Single-source helper shared producer/verifier/test.
- Domain (WASM_EXPORT_SIGN_DOMAIN, manager.rs:7314) == native CONTEXT_EXPORT_DOMAIN_SEPARATOR (export_import.rs:139), both "SCP-CONTEXT-EXPORT-V1:". Scope tag shared const scp-protocol/context/export.rs:26. Domain fixed-len(22)+tag fixed-len(1)+var JCS = unambiguous concat, no length-prefix needed.
- Sign: creator #active key over digest (manager.rs:6500). Envelope embeds snapshot+sig+HMAC.
- Verify: deserialize_and_verify_envelope (6539): size cap WASM_MAX_EXPORT_BYTES first → version gate EXACT-match WASM_EXPORT_VERSION=5 (rejects <5 as unsigned CTX_2094, >5 CTX_2094) → re-canonicalize → exporter_did==snapshot.creator_did (6626, CTX_2093) → empty-sig reject → verify_snapshot_signature with verify_strict against creator #active then #agent (6720) → HMAC only if creator key local (additive DiD, AFTER mandatory sig).

## Digest determinism (the load-bearing claim) — VERIFIED
- canonicalize_snapshot_sets (7580) sorts snapshot-level set-derived Vecs: read_exclusion_list, revoked_tokens, seen_nonces_v3(by nonce), executed_proposals(by pid), broadcast.subscribers + author_block_lists values. HashMap fields (resolved_proposals_json, cooldown_until, member_sequence_numbers, key_epochs) → JSON objects → JCS sorts keys.
- role_state NOT touched by canonicalize_snapshot_sets — instead self-canonicalizes via serde codecs: members/ceiling.capabilities/role_definitions[*].capabilities use serde_sorted_set; member_capabilities/suspended_capabilities use serde_sorted_set_map (roles.rs:804,812,820,380,500). Codec (serde_util.rs:438) sorts by EACH ELEMENT'S OWN RFC8785 JCS bytes — serializer-independent, FAILS LOUD on JCS error (no silent empty-key collapse). Capability has no Ord; sort key is canonical bytes — sound.
- assignments/role_definitions outer HashMaps → JCS object-key sorted. NO unwrapped set/map under signed snapshot → digest deterministic.
- params_json/resolved_proposals_json are serde_json::Value → JCS (ES6 number canon). No arbitrary_precision feature. Same crate/feature set both sides → identical.

## assignments[*].tokens (acknowledged non-byte-parity) — SOUND for model
- roles::UcanToken {iss,aud,att:Vec<UcanAttestation>,nnc} (roles.rs:693). NO exp, NO prf, NO signature field. att=unordered Vec, nnc=random. NOT the cryptographic ucan::UcanToken (crypto/ucan/mod.rs:411, which has exp/prf/sig).
- tokens Vec deliberately NOT sorted (7558-7565). Sound because single-signer VERBATIM: exporter signs exact JCS it produced; importer re-canonicalizes & verify_strict's THOSE SAME received bytes. Faithful round-trip = identical bytes; any tamper changes bytes → verify_strict fails. Cross-export/cross-family byte-parity NOT claimed (ADR-050).
- Role tokens never independently verified as authority in wasm: authz goes through role_state.member_capabilities/member_has_capability (the signed verbatim state). roles::UcanToken is carried metadata. ucan.rs verify_token_signature operates on the DIFFERENT ucan::UcanToken type. So token nnc/expiry/proof-chain absence is not an authz hole — grounded in signed snapshot + governance, as documented.

## crypto:None decoupling — SOUND
- import sets crypto:None (manager.rs:6997) with explicit SECURITY note + debug_assert (7022). member_sequence_numbers restored verbatim as sidecar but bound to NO live AEAD key → forged/reset counter cannot cause GCM nonce reuse; fresh Welcome starts counters clean. Documented re-eval trigger if crypto ever populated from imported MLS.

## Key resolution / immutability — SOUND
- Verify key always from snapshot.role_state.creator_did (never envelope), #active→#agent (ADR-039). creator_did NEVER mutated by TransferAdmin (manager.rs:4076 + tests 10472,10520) — admin is a transferable ROLE; creator_did is immutable export signer. Stable signing/verify identity.

## No downgrade/replay
- version gate exact-match (no <v5 unsigned path accepted). exporter_did bound to signed creator_did. revoked_tokens carried in signed snapshot. seen_nonces_v3/executed_proposals inserted_at clamped to now on import (forgery can't push future); creation_timestamp_secs consumed verbatim (signed; §9.9.3 convergence; TTL-only consumer).

## Belt checks
- import validates ceiling grammar (validate_entries 6830), DIDs, role-name len, state enum, min_protocol_version, antispam bounds — all AFTER verify, defense-in-depth fail-loud.
