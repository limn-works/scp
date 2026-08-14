---
name: crypto22-slice1-attestation-encoding
description: CRYPTO-22 slice 1 (0xFF03 KeyPackageAttestation type/serde/Vector37) adversarial pass — COULD NOT BREAK the encoding; residual concerns are cross-slice verifier discipline
metadata:
  type: project
---

## Re-attack after canonical-builder swap @d39636213 (Pass A double-zero)
COULD NOT BREAK — no new malleability. Fix replaced hand-rolled `write_canonical_fields` with `scp_protocol::crypto::canonical::canonical_hash_bytes(domain, &[CanonicalField;8])`. Byte-IDENTICAL: VarBytes = 4-byte BE `u32::to_be_bytes` prefix (== old BE32, NOT tls_codec var-len), Fixed32 raw-no-prefix, U64 8-byte BE; domain raw-no-prefix. `signing_preimage`=canonical_hash_bytes(DOMAIN,..), `to_extension_body`=canonical_hash_bytes(b"",..)+sig. Empty-domain body is NEVER a verified input (sig always over signing_hash=SHA256(DOMAIN||fields)); no domain-strip replay (every signed struct has non-empty domain). Fixed 8-field schema → injective, no field-set collision. PARSE path (Cursor) UNCHANGED by diff → round-trip symmetry preserved. All 3 vector_37 KAT byte-pins intact (211-byte preimage / 50cf61db hash / 245-byte body) + 3 new negative tests + parse strictness — 19/19 pass empirically. Cross-slice invariants (did-eq check9, verify-over-signing_hash-same-domain, init_key Add-structure-gate) all hold as type contract. ONLY residual (LOW, unreachable): >u32::MAX VarBytes → Err→`unwrap_or_default()`→empty preimage→SHA256("") constant; parse caps did/skid at u32::MAX (exactly encodable) so wire-unreachable; needs local 4GiB String construction. Same class as pre-swap `unwrap_or(u32::MAX)`, not newly exploitable.

CRYPTO-22 SLICE 1 @caeafe724 (branch crypto22-s1-attestation-type, base origin/main).
File: crates/scp-mls/src/keypackage_attestation.rs. Pure type + §9.5.1 canonical serde + §25.23 Vector 37 KAT. NO signer/verifier/wiring (later slices).

VERDICT: encoding is CANONICAL and NON-MALLEABLE. Could not construct a forgery/substitution vector at this layer.
- Encoding is uniquely decodable: BE32-len did || 4×raw-32B keys (fixed, positional) || BE32-len skid || 2×8B u64 || 64B sig. Length-prefixed + fixed-length ⇒ injective; no field-boundary smuggling, no did↔skid byte-move (fixed keys have no length to steal).
- Domain separator ONLY in signed preimage (b"SCP-KEYPACKAGE-ATTESTATION-V1:", 30B), hardcoded in signing_preimage(); absent from 0xFF03 body. Cross-structure/cross-protocol reuse blocked by unique domain. 0xFF01(wrapping raw-32B)/0xFF02(ctx-params) distinct type IDs + distinct body shapes.
- signing_key_id fully closed: SigningKeyId::from_fragment (scp-did/src/lib.rs:247) exact-match "#active"/"#agent" only, 2-variant enum; as_bytes emits exactly those. "#0" rejected. Length prefix effectively pinned to 6/7.
- Parse strict: Cursor bounds-checked via slice::get (no panic), expect_end rejects trailing, oversized len overruns→err, non-UTF-8 did/skid→err. Round-trip bijective (parse→struct→serialize identity); no non-canonical input accepted.
- Key reorder/alias: 4 keys positional+signed-in-order ⇒ swap breaks sig. Aliasing representable but needs signer (none in slice-1).
- Code reproduces Vector 37 byte-for-byte (211B preimage, 32B hash 50cf61…8957, 245B body). u32::MAX len fallback unreachable (>4GiB String).

RESIDUAL (cross-slice, NOT slice-1 bugs):
1. did NOT validated well-formed/non-empty at parse (empty did len=0 round-trips). Relies wholly on later verifier §9.7.1 check 9 (did==ScpCredential.did). By design (context-agnostic pure type). Guard: verifier MUST enforce equality, never trust attestation.did standalone.
2. Sig is over SHA-256(preimage) (pre-hashed 32B), domain inside preimage. Later verifier MUST Ed25519-verify over signing_hash() 32B (not body/not preimage), and MUST reconstruct preimage with the SAME hardcoded domain const. Slice-1 centralizes domain in one const (good).
3. init_key==leaf_encryption_key is LEGIT for bare creator/PCS-Update leaves. Verifier MUST gate Add-time init_key check on handshake structure, NEVER on field equality (spec §9.5.2 explicit warning; slice-1 doc lines 143-146 restate it). Watch the verifier slice for this.

Relates to [[crypto22-keypackage-attestation]] (that note = LATER concern: non-revocable context-agnostic attestation reuse for new-group joins — a different layer).
