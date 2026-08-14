# scp-did zbase32 canonicality parity (ADR-057 T1, commit c1ef1394d)

`scp_did::extract_public_key_from_did` (crates/scp-did/src/lib.rs ~L123-145) NOW enforces
z-base-32 canonicality via re-encode-and-compare, ported verbatim from native
`scp_identity::dht::extract_public_key` (dht.rs ~L2748-2760). Both: decode did:dht:z suffix ->
[u8;32] -> `zbase32::encode(bytes) != suffix` -> Err. Byte-exact, no case folding.

Why it matters: wasm/browser signature-verify path (scp-event-log tree.rs, scp-protocol
bridge/claiming.rs, trust/attestation.rs) reaches ONLY this wasm-safe parser. Before the port it
was the WEAKER parser (no round-trip) -> DID-string<->key non-injectivity on the browser side
only. Now native+browser reject identical inputs.

Crate: `z-base-32` v0.1.4 (workspace dep declared "0.1.3"), imported as `zbase32`. Source facts
(grounded, /Users/alec/.cargo/.../z-base-32-0.1.4/src/lib.rs):
- encode: pure/deterministic, no RNG/global state; padding bits ALWAYS 0; last (52nd) char of a
  32-byte payload = ALPHABET[(b31&1)<<4] i.e. only 'y'(bit0) or 'o'(bit1). 32-byte gate forces
  suffix len == 52 exactly (floor(len*5/8)==32 only at len 52).
- decode: lowercase-only (INVERSE_ALPHABET maps uppercase 65-90 -> -1 -> DecodeError, so NO case
  alias); clean bijection on the 32 valid chars; trailing 4 padding bits land in truncated byte
  32 -> ignored -> 16 aliases per payload-bit-value. Round-trip closes ALL of them: accepted set =
  {encode(k)}, encode is a function => distinct accepted strings decode to distinct keys (injective).
- Comparison is on PUBLIC data (DID string + pub key); variable-time str eq is fine, no secret branch.

Fixture math (key=[42u8;32]): b31=42, low bit 0 -> canonical last char 'y' (idx 0). `last_idx ^ 1`
= idx 1 = 'b', toggles padding bit0 only (payload bit4 unchanged) -> distinct string, same 32 bytes.
Test asserts decode(mutated)==key AND parser rejects. Genuine non-canonical pair. Both new tests
pass (scp-did extract_public_key_rejects_non_canonical_zbase32_padding;
scp-identity native_and_scp_did_parsers_agree_on_canonicality, run with --features testing).

Verdict: SOUND, no regression. Rest of 86519aa6f..HEAD (scp-primitives dissolution -> scp-clock/
scp-crypto/scp-did) is pure module moves + DidDocumentError->DidError rename + import repoint;
verify_ed25519_signature relocated (shim delete) unchanged; decode_multibase_key unchanged.
