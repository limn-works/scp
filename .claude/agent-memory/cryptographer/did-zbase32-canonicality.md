---
name: did-zbase32-canonicality
description: z-base-32 DID-string canonicality authority + single-parser injectivity invariant (branch refactor/dissolve-primitives-split-identity, HEAD cc23e51f6)
metadata:
  type: project
---

# DID z-base-32 canonicality (ADR-057 T1 / split-primitives)

**Invariant:** DID-string ↔ key injectivity. z-base-32 over a 32-byte payload is
NOT injective on trailing bit-padding: 51 full chars (255 bits) + 52nd char = 1
payload bit + 4 padding bits → 16 alternate suffixes decode to the same key. The
`zbase32` crate decode is LENIENT on padding bits (confirmed: tests decode a
padding-toggled suffix back to the same 32 bytes). Fix = re-encode decoded bytes
and byte-exact compare against input suffix (no case folding; encoder emits
lowercase canonical).

**Two authority parsers (byte-for-byte equivalent, both enforce canonicality):**
- `scp_did::extract_public_key_from_did` (lib.rs:120) — wasm-safe. Returns `String` err.
  strip "did:dht:z" → zbase32::decode → try_into [u8;32] → re-encode → compare.
- `scp_identity::dht::extract_public_key` (dht.rs:2722) — native. Returns `IdentityError`.
  strip "did:dht:" + strip 'z' (== "did:dht:z") → same steps. Equivalent remainder.
- Pinned equal by `native_and_scp_did_parsers_agree_on_canonicality` (dht.rs:3394):
  same fixture, both accept canonical→same bytes, both reject non-canonical. This
  test is the divergence guard for the two-copy duplication (native vs wasm-safe).

**Every DID-string z-base-32 decode routes through one of the two authorities.**
Only 2 production `zbase32::decode` sites (the two parsers); all others are test
fixtures. Callers: event-log tree.rs:320 (actor_did verify), claiming.rs:210
(claimant_did), scp-ffi resolvers.rs:58 (BridgeDidResolver UCAN path),
app_sandbox.rs:912 (app-decl verify), + all scp-identity internal callers.

**Separate decode path (NOT this invariant, unchanged):** `decode_multibase_key`
(scp-did document.rs, base58btc) decodes DID-*document* VM `public_key_multibase`
FIELDS, not the DID string suffix. Used by MLS credential.rs, bridge_auth,
self-cert VM comparison. Different subsystem.

**app_sandbox did:key branch stays LOCAL & is correct:** it's W3C
did:key:z<base58btc(0xed01||key)> — a DIFFERENT format/alphabet than scp-did's
did:key:{hex} test convenience. Delegating it to scp-did would break valid W3C
did:key. Branches are mutually exclusive on distinct prefixes; only "did:dht:"
strings reach scp-did, so no cross-confusion even in test builds.

**HEAD cc23e51f6 delta (all fail-closed strengthenings, no legitimate rejection —
all prod DIDs are canonical-by-construction via `zbase32::encode`):**
- DidDht::verify: was `decoded == public_key` (no canonicality) → now via extract_public_key.
- BridgeDidResolver: hand-rolled decode (no canonicality) → delegates to scp-did;
  did:key branch now gated by forwarded `scp-did/testing` feature.
- app_sandbox: REAL BUG — stripped only "did:dht:" (not 'z') → 33 bytes → rejected
  EVERY valid did:dht. Fixed (un-rejects canonical) + adds canonicality guard.
- Topology move d12691ef6 carried the fn verbatim (no canonicality); c1ef1394d added it.
