---
name: modelb-did-record-relay-frame
description: Model B DID-record relay frame (§9.10.12) spec redesign — crypto review, SOUND
metadata:
  type: project
---

# Model B DID-record relay frame (§9.10.12, issue #482)

SPEC change (03-identity §3.10.2/.4/.5/.8, 09-security-model §9.10.12, 10-infra §10.12.4). Replaces Model A "SCPR" multi-kind envelope. **VERDICT: SOUND.**

Frame: `version(1) ‖ public_key[32] ‖ seq(u64 BE) ‖ signature[64] ‖ value(trailing remainder)`. Fixed prefix 105B (1+32+8+64), total=105+len(value). No magic, no kind byte — routing_id domain (`SHA-256("scp:did:"||did_string)`) is the type discriminant.

**Why sound:**
- Byte-deterministic: all fixed-width except trailing-remainder value (no value_len → no two-disagreeing-lengths footgun). Raw fixed layout, no self-describing codec. did:dht = single canonical z-base-32 of pubkey (§3.10.759, airtight).
- No authority from unsigned framing: BEP44 sig covers `bencode(seq,value)` (seq before value). seq/value values are bound because verification RECONSTRUCTS the bencode from the frame's seq/value and checks — tamper → sig fails. public_key is the only field never cross-checked by the client's verify, and the client IGNORES it entirely (verifies against DID-string-derived key).
- Carried public_key = NO substitution risk. Client ignores it. Relay uses it but cross-checks binding `SHA-256("scp:did:"||did(public_key))==routing_id` → forces frame pubkey == DID's real key when published at victim routing_id (else rejected). Attacker can only publish valid frames at their OWN routing_id. Relay-accept ⟺ client-accept (same key). Even if relay botches, client re-derive from DID string → substitution cryptographically impossible.
- Flood-inert claim (§3.10.8) CORRECT on validating single-slot relay: displacing genuine seq-N record needs valid seq>N frame = owner's signature (seq is INSIDE BEP44 sig, §3.10.7 owner-only monotonic) → attacker can't. Junk = rejected (bad sig/binding) or ≤seq (rejected). Empty slot can't be pre-occupied with anything valid.
- BEP44 byte-identity across DHT/relay: triple (value,sig,seq) identical, only container differs. ✓
- Decoder rules correct: version-first-gate, require full 105 prefix, reject empty value, widened-arith bound (262144−105), single decode-verify site. verify-before-use explicit (§3.10.4 step 4).
- Byte-level disjoint from OuterEnvelope: frame first byte=0x01, OuterEnvelope=msgpack map marker 0x80-0x8f/0xde/0xdf. Relay validation precedented by BRIDGE_REGISTER §10.12.4 (same Ed25519+binding pattern).
- No stale SCPR/kind/value_len/82 refs left (grep clean; remaining "SCPR"=SCPRelay service type, unrelated).

**IMPLEMENTATION LANDED & VERIFIED (commit b383ebd8c, SCP-RELAYRES-001):** `crates/scp-protocol/src/envelope/did_record.rs` — `DidRecordV1` {public_key:[u8;32], seq:u64, signature:[u8;64], value:Vec<u8>} (version is NOT a field, always 1 on encode). encode = push(1)‖pk‖seq.to_be_bytes()‖sig‖value; total 105+len. decode enforces all 4 rules IN ORDER (first()→UnknownVersion vs Truncated{0}; len<105→Truncated; value_len=len-105 only after; ==0→EmptyValue; >262039→ValueTooLarge; fixed-width try_into infallible-but-defensively-mapped, no unwrap/panic). Offsets pk[1..33] seq[33..41] sig[41..105] value[105..]. VERDICT SOUND — byte-exact vs spec, injective (no malleability: value=remainder, all prefix fixed-width), encode deterministic total, no underflow/panic (verified proptest never-panic + boundary tests). Decode does NO verify (client ignores frame public_key; BEP44 verify vs DID-derived key is caller's job, separate site). ONE LOW observation: local `const MAX_BLOB_SIZE=262_144` re-declares the authoritative scp-transport::native::protocol MAX_BLOB_SIZE (drift risk) — but FORCED by crate-dep direction (scp-protocol is the wasm-safe leaf, can't import from scp-transport); value correct + pinned by constants_match_spec test. Not a blocker.

**Non-blocking observations (NOT crypto soundness flaws):**
- A. limit:1 demotes non-validating/foreign relays to best-effort for suppression (Model A limit:16 handled shadow on honest-but-non-validating relay). Honestly documented as residual; anti-suppression now delivered by validating relays + DHT. Design/threat-model tradeoff.
- B. bencode signed-buffer shorthand `3:seqi<seq>e1:v<value>` omits the v byte-string length prefix `<len>:`. PRE-EXISTING (unchanged by Model B), deferred to "BEP44 authoritative." Minor determinism-clarity nit.
- C. Replay of old genuine record into empty validating-relay slot = bounded stale-serve, self-heals via republish (seq supersession) + cross-layer highest-seq selection. Covered by §3.10.7.
