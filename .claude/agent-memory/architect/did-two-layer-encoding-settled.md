---
name: did-two-layer-encoding-settled
description: SCP DID resolution uses two layers with two different encodings; the did:dht method facts that settle the Mainline side, verified against the method specification
metadata:
  type: project
---

SCP publishes a DID document in two encodings, one per resolution layer. The SCP relay network is primary and carries the full JSON document (cap `MAX_DID_RECORD_VALUE_LEN` = 262,039 bytes). Mainline BitTorrent DHT is the external fallback and carries a reduced bootstrap core as a did:dht DNS packet (cap 1,000 bytes, measured on the **bencoded** BEP44 `v` value). The two layers carry different bytes under different signatures, and no resolver compares one layer's sequence number against the other's.

**Why:** the smallest document §18.2.2A permits is 1,255 bytes minified, and reducing the field set does not close the gap — the bootstrap core is still exactly 1,000 bytes as minified JSON, which bencoding pushes to 1,005. Only changing the encoding closes it. Do not try to shrink the full document to 1,000 bytes; that target came from wrongly treating Mainline as primary and is a known dead end.

**did:dht method facts, verified against `spec/spec.md` in `decentralized-identity/did-dht` (renders at https://did-dht.com):**
- The BEP44 payload is a bencoded DNS packet compressed per **RFC 1035 §4.1.4**. The method says "gzip" nowhere. Issue #2297 said gzip; its body was corrected.
- JSON is the DID Document representation and the gateway HTTP body, never the BEP44 payload.
- A did:dht document **MUST NOT** include `@context`. SCP's relay-layer JSON keeps `@context` and is therefore not a did:dht document; it lives at an SCP routing ID a did:dht resolver never queries.
- `seq` **MUST** be the current Unix timestamp in seconds. That is the strongest reason Mainline's sequence number is incomparable with the relay layer's publish counter.
- The DID suffix is `Z-BASE-32(raw-public-key-bytes)` with no prepended character. The method states no length; 52 is what 32 bytes yield. `z` is a valid z-base-32 data character, so SCP's 53-character suffix passes the method's character class and fails only the transformation.
- Root record `_did.<ID>.` TXT carries `v=;vm=;auth=;asm=;inv=;del=;svc=`, with `vm` "always containing at least `k0`". Verification methods are `_kN._did.` TXT, services `_sN._did.` TXT, recommended TTL 7,200s.

**Measured Mainline packet sizes (bencoded BEP44 `v`, constructed from wire bytes and round-trip parsed, not extrapolated):** 479 bytes at 1 relay entry with `wss://relay.example.com/scp/v1`; 619 at 3; 676 at 3 with a realistic operator hostname; 854 at 5 realistic. Each further relay entry costs 70 bytes (short hostname) or 89 (realistic). The 1,000-byte cap admits 8 relay entries short, 6 realistic. §18.2.3's recommended minimum of 3 fits with 324 bytes spare. Two consequences: the design has real headroom, and RFC 1035 compression saves only 12–28 bytes here because only the root record's name carries the 52-character DID — compression is not what makes the core fit.

**SCP's one mapping choice, decided in §18.2.2C:** the service record's `t=` carries the SCP service type string verbatim (`t=SCPRelay`, `t=PreRotationCommitment`).

**How to apply:** treat all of the above as settled and cited in `.docs/specs/18-addressability-and-deployment.md` §18.2.2A–§18.2.2D. Read those sections rather than re-deriving. See [[did-document-membership-criteria]] for what belongs in the document at all.
