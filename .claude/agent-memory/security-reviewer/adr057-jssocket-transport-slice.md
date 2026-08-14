---
name: adr057-jssocket-transport-slice
description: ADR-057 #1980 browser relay transport slice review (JsSocket, pseudonym fan-out, MLS-seed derive) — no blockers, key patterns
metadata:
  type: project
---

# ADR-057 JsSocket transport slice (branch feat/adr057-transport-jssocket @68f986c9a) — 2026-07-17

Reviewed diff origin/main...HEAD. NO BLOCKERS. Clean private-key handling.

**Why:** browser has no identity key in wasm; only wasm-held Ed25519 is the per-context MLS signing keypair. So browser derives pseudonym over MLS key (Option A, MLS-keyed not identity-keyed — documented human-ruled deviation from §9.10.4.A).

**How to apply / key facts:**
- `scp-mls::group::extract_ed25519_seed` recovers 32-byte seed via `rmp_serde::to_vec_named(signer)` + deserialize `{private: Vec<u8>}` (private() accessor is test-utils-gated). ALL copies zeroized: serialized Vec, extract.private Vec, seed is `Zeroizing<[u8;32]>`. Workspace ed25519-dalek has `zeroize` feature ON → SigningKey is ZeroizeOnDrop, so the reconstructed key + derived pseudonym keypair also wipe. Only public `verifying_key().to_bytes()` returned. Cross-check test pins serde shape vs test-utils private().
- Forgery guard is SOUND: `classify_pseudonym_announcement` checks `member_did == sender_did`, and sender_did is the MLS-AUTHENTICATED credential from `Inbound::Application`. A member cannot forge another's DID. Reserved-value + cross-DID-collision checks present. Reject path drops with no side effects.
- Pump (`handle_relay_frame`) fails closed: `RelayMessage::from_bytes` size-guards (MAX_MESSAGE_SIZE) BEFORE rmp decode → no unbounded alloc. Unknown routing_id → silent drop. Malformed → Codec err. No panic/OOB.
- Empty-registry guard raised BEFORE ratchet advance (no crypto consumed on retry). Snapshot v4 persists peer_pseudonyms but NOT local_pseudonym (re-derived from MLS key on restore).
- `unsafe impl Send/Sync` on JsSocketAdapter: wasm32-only, same single-thread justification as custody/storage. Sound. `frame: Vec<u8>` by-value = detached copy (no wasm-memory aliasing). Correct.

**KNOWN MINOR GAP (shared with native, not a divergence):** collision check registry (`peer_pseudonyms` / native `peer_registry()`) EXCLUDES the local member's own pseudonym. A malicious member who learned victim's pseudonym (public, shared on announce channel) can announce own-DID→victim_pseudonym; victim accepts (own pseudonym not in its peer registry), then misroutes its app-data-to-attacker back to itself. Self-limited directed DoS, no confidentiality breach, no redirect-to-attacker. Third parties correctly reject (victim's pseudonym IS in their registry). Fix belongs in shared `classify_pseudonym_announcement` core (feed local pseudonym into reserved/collision set) → benefits native too.
