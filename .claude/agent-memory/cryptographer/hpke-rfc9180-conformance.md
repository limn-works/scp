---
name: hpke-rfc9180-conformance
description: The single RFC 9180 HPKE core every key-distribution path uses, its implementation traps, the custody Decap contract, and the 48-byte wire form
metadata:
  type: project
---

Five hand-rolled "HPKE" constructions (actually custom ECIES) were replaced by one
hand-implemented RFC 9180 Base-mode single-shot core in
`crates/scp-protocol/src/crypto/hpke.rs`. It compiles for wasm32, so the browser client uses
the same code.

**Suite:** DHKEM(X25519, HKDF-SHA256) `0x0020` / HKDF-SHA256 `0x0001` / AES-128-GCM
`0x0001`, mode `0x00`. Every seal generates a fresh ephemeral key and seals once at sequence
0, so the nonce is `base_nonce`. API: `seal(pk, info, aad, pt) -> (enc, ct)`,
`open(sk, enc, info, aad, ct)`, `custody::open_with_external_dh(dh, pkRm, enc, info, aad, ct)`.

**Implementation traps:**
- `LabeledExtract` must call `Hkdf::extract(Some(salt), ...)` with the empty-string salt.
  `None` gives an all-zero salt block, which RFC 9180 does not specify.
- The known-answer tests are RFC 9180 Appendix A.1 values, including intermediate
  `shared_secret`, `key`, and `base_nonce`, and hpke-rs 0.6 is a dev-dependency oracle in both
  directions. hpke-rs's `open` rejects an empty plaintext as `InvalidInput`, so an
  our-seal-then-reference-open test needs at least one byte of plaintext.
- A raw DH output copied out of `SharedSecret` (`*dh.as_bytes()`) escapes zeroization; wrap
  the copy in `Zeroizing`.

**Custody Decap contract:** a caller of `open_with_external_dh` passes
`dh = KeyCustody::dh_agree(handle, enc)` and `pkRm = KeyCustody::public_key(handle)` for the
same handle and the same `enc`. The core binds `enc ‖ pkRm` through `kem_context`, which closes
the unknown-key-share gap the old raw-DH-export paths had. A wrong `dh`, `pkRm`, or `enc`
fails only at the AEAD tag, with one error string, so it is not an oracle.

**Wire form:** a sealed 32-byte key is 48 bytes (32 ciphertext + 16 tag); the nonce is
derived, not transmitted. `SenderKeyResponse.hpke_sealed_key` and
`AccessKeyResponse.hpke_sealed_key` are both `[u8; 48]`.

**`info` strings:** each HPKE use has its own BE32-length-prefixed `info` layout, registered
in spec §9.18.2. The label `scp-private-state-v1` appears both in the PSK-rotation `info` and
in a routing-id HKDF in `private_state.rs`; they never meet in one KDF invocation, but a new
use must pick a fresh label.
