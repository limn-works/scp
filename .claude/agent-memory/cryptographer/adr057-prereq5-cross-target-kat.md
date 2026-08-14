---
name: adr057-prereq5-cross-target-kat
description: ADR-057 Prereq-5 cross-target (native/wasm32) determinism KAT crypto review — SOUND, 2 LOW doc-accuracy + 1 coverage note
metadata:
  type: project
---

# ADR-057 Prereq-5 cross-target determinism KAT (branch feat/adr057-test-stack, HEAD deb07953f)

File: `crates/scp-client-wasm/tests/cross_target_determinism_kat.rs`. VERDICT: crypto/determinism SOUND.

**Why:** guards the ADR-057 "byte-identical across native/wasm32 for deterministic artifacts" invariant (wasm32 is 32-bit — usize/`as`/HashMap-order risk). Ships a real CI `wasm-test` job (`wasm-pack test --node crates/scp-client-wasm`) wired into the aggregate gate, so the wasm leg genuinely executes.

**How to apply / verified facts:**
- Event-log leaf/root preimage = `SHA-256(0x00 ‖ rmp_serde::to_vec(Event))`. Event fields: EventType (fieldless enum → msgpack int variant-index, NOT native usize), DID(String), timestamp u64, sequence u64, EventPayload{data serde_bytes→bin}, prev_hash [u8;32]→msgpack array-of-32-u8, signature serde_bytes→bin. NO usize/float/HashMap in preimage ⇒ deterministic across targets. Root pins BOTH root AND each leaf (defeats compensating leaf bugs). CORRECT anchor for §9.9.3 convergence.
- Convergent AAD golden `5343505401000000006553f100` = `SCPT`(53435054) ‖ ver=01 ‖ u64-BE(1_700_000_000=000000006553f100). Verified byte-exact. Pure BE, no usize.
- ScpCredential::to_bytes = `rmp_serde::to_vec` positional array `93`=[did-str, None(c0), "#active"(a7...)] . SigningKeyId custom Serialize→string "#active". Deterministic.
- AEAD sender-layer: nonce = random OsRng ⇒ KAT correctly asserts ROUNDTRIP (not ciphertext bytes) + wrong-sequence(AAD) rejection. Fail-loud on wasm if getrandom js unwired.
- MLS legs (Commit/Welcome/KeyPackage) = round-trip of ONE committed golden blob via canonical openmls TLS codec (`PrivateMessageIn`/`Welcome`/`KeyPackageIn` deserialize→`tls_serialize_detached`==golden). Sound: TLS VLBytes length prefixes are minimal-length canonical + value-derived (not width-derived), decode→encode is identity on native (golden committed), so native==golden ∧ wasm==golden ⇒ native==wasm. Respects ADR line-22 caveat (no diffing of two randomized constructions). Golden = MLS BODY (post-`MlsMessageIn::extract`, 4-byte version+wireformat u16 header stripped) — correct determinism surface.

**Findings (all LOW/INFO, no blocker):**
1. LOW doc: KAT docstrings (lines ~38-48,144) call rmp_serde "name-tagged"/"by name/tag" — FALSE, `to_vec` is POSITIONAL fixarray (golden `93`/`93` confirm). Determinism UNAFFECTED (positional is deterministic) but mischaracterizes preimage; positional means struct field REORDER silently changes preimage (golden re-derivation is the guard, already noted). Fix wording to "positional array w/ explicit msgpack int widths."
2. LOW doc: ADR added sentence attributes "fixed-blob round-trip, not construction" to legs "(i)/(iii)", but (iii)="credential/KeyPackage" and the CREDENTIAL half is a deterministic RNG-free CONSTRUCTION (new+to_bytes vs golden), not a round-trip. Sentence enumerates only "Commit/Welcome/KeyPackage" (excludes credential) so not wrong, but credential's construction modality left unstated.
3. INFO coverage: Commit leg round-trips an ENCRYPTED PrivateMessage → exercises only outer framing (opaque ciphertext VLBytes); inner Commit ordering-risk structures (proposal list, UpdatePath, GroupContext ext vector) are encrypted/opaque, NOT exercised. BUT KeyPackage leg round-trips CLEARTEXT LeafNode/capabilities (ciphersuites/extensions/proposals TLS vectors) — covers nested vector-ordering + length-prefix codec. So ordering-risk surface IS covered; Commit leg is envelope-only. No hidden browser↔native divergence axis.
