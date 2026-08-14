---
name: relayres003-did-record-validation
description: SCP-RELAYRES-003 relay-side DID-record frame validation (classify_did_record_frame + DidSlotRegistry) — SOUND, no findings
metadata:
  type: project
---

# SCP-RELAYRES-003 Relay-side DID-record validation (commit da1f610ae) — SOUND

Files: `crates/scp-transport/src/relay/did_record_validation.rs` (pure classifier), `native/did_slot.rs` (stateful slot index), `native/server.rs` (handle_publish/handle_query wiring). Precedent: `relay/bridge.rs::verify_bridge_registration` (§10.12.4). Frame type: `scp_protocol::envelope::did_record::DidRecordV1` (fixed layout version(1)||pk(32)||seq(8 BE)||sig(64)||value[rem], no self-describing codec, verify_strict).

**Why SOUND (all 5 audited properties hold):**
- Binding: did = `did_from_ed25519_public_key(pk)` (=did:dht:z||zbase32(pk)); routing_id = `did_routing_id(did)` = SHA-256("scp:did:"||did). SAME functions as bridge + resolver (`scp_identity::did_routing_id` re-exports `resolution::did_routing_id`; single defn resolution.rs:55). To plant wrong-key frame at victim rid = second-preimage on SHA-256 (infeasible). Relay computes canonical zbase32 itself (no decode-ambiguity on this path).
- Sig: `verify_bep44_signature(pk, sig, value, seq)` builds shared `bep44_signable(value,seq)` = "3:seqi"+dec(seq)+"e1:v"+dec(len)+":"+val, verify_strict. seq bound inside signature ⇒ can't inflate seq to squat without the key. Byte-identical to client/DHT.
- Order: decode → binding(hash) → sig(Ed25519), strictly cheapest-first; mis-addressed frame never costs a verify. (bridge does ts→sig→binding; this order is stronger for DoS.) Relay acceptance feeds ONLY slot bookkeeping, never a client trust input (client re-derives key from the DID it resolves, RELAYRES-002).
- Equal-seq idempotency: blob_id = SHA-256(full frame); byte-identity = blob_id match. Two different valid frames same seq ⇒ SHA-256 collision (infeasible) ⇒ else NonSuperseding (§3.10.4 conflict). Replay of same bytes = benign TTL refresh, no new record, seq unchanged.
- Key confusion closed: attacker's self-consistent frame binds ONLY to attacker's own rid; swapping embedded pk to victim's ⇒ SignatureInvalid (no victim key). Occupying victim rid needs pk→victim rid (2nd-preimage ⇒ victim pk) AND valid sig under it (victim priv key). Neither available.

Config `DidRecordValidation::Enabled` default; OPTIONAL, availability/anti-suppression only, never integrity. Encrypted OuterEnvelope first byte = msgpack map marker ≠ 0x01 ⇒ NotAFrame ⇒ opaque path. No crypto findings; slot reversion/pre-seed race are documented availability concerns covered by client re-verification.
