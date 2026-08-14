---
name: crypto22-s1-attestation-parser
description: CRYPTO-22 Slice 1 scp-mls KeyPackageAttestation type + 0xFF03 parser — untrusted-input hardening review, SHIP IT
metadata:
  type: project
---

# CRYPTO-22 Slice 1 — KeyPackageAttestation parser (crypto22-s1-attestation-type, caeafe724)

`crates/scp-mls/src/keypackage_attestation.rs` — pure type + §9.5.1 serialization + `from_extension_body(&[u8])` strict parser for the attacker-controlled `0xFF03` LeafNode extension body. NO signer/verifier/wiring in this slice (later). Vector 37 §25.23 KAT pinned (211B preimage / 245B body).

**Why:** first security-critical surface of the KeyPackage-attestation feature is the wire parser.

**How to apply / verdict — SHIP IT, 0 BLOCKER/HIGH/MEDIUM.** The `Cursor` is the pattern to trust and reuse:
- **No allocation DoS.** Parse BORROWS slices (`take_var_bytes` returns `&'a [u8]`); the only heap alloc is `did.to_owned()`, bounded by bytes actually present. NO `Vec::with_capacity(untrusted_len)` anywhere on the parse path. A `0xFFFFFFFF` did length prefix → `take(4294967295)` → `checked_add` fine on 64-bit → `slice.get(pos..huge)` returns None → typed error; nothing is ever allocated at the claimed length.
- **Panic-free.** No unwrap/expect/panic outside `#[cfg(test)]`. Every read via `slice::get`, `pos.checked_add`, `<[u8;N]>::try_from` + `map_err`. `expect_end` can't underflow (`pos <= len` always, since `take` only advances after a successful bounded `get`).
- **Strict / non-malleable.** `expect_end` rejects trailing bytes; truncated/empty error; canonical because fully length-determined + exact-consumption + `SigningKeyId::from_fragment` is EXACT-match (`#active`/`#agent` only, case-sensitive) with `as_bytes` the exact inverse ⇒ round-trip is injective, no alternative encoding for a given struct.
- **Encoder `u32::try_from(len).unwrap_or(u32::MAX)`** (write_canonical_fields) is ENCODE-side only, over the local struct's own tiny did/skid — physically-impossible >4GiB branch, cannot truncate a real length. Acknowledged in doc. Fine.

**LOW (test breadth only, behavior correct):** negative tests cover truncated/empty/trailing/oversized-did-len/unknown-skid, but NOT: non-UTF-8 did, non-UTF-8 signing_key_id (both handled in code, enumerated as strict-parse guarantees in the doc comment), oversized len-prefix on the *skid* var field (only did tested), zero-length did. Adding the two UTF-8 negatives would lock the doc-stated guarantee mechanically. Not blocking.
