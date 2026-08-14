---
name: scpr-slice11-relay-querier
description: SCP-CAPINJECT-011 / ADR-062 Slice 11 SCPR relay frame crypto review — codec sound, one HIGH latent bug (heal Relay arm bypasses SCPR)
metadata:
  type: project
---

# SCPR Relay Public-Record Frame (ADR-062 Slice 11, §9.10.12)

Branch `feat/adr062-slice11-relay-querier` (f4e1e2d08). Reviewed 2026-08-02.

## Construction (SOUND)
- `crates/scp-protocol/src/envelope/scpr.rs` `encode/decode_did_record` matches §9.10.12 byte-for-byte: magic[4]=`SCPR`(0x53534352) ‖ version u8=1 ‖ kind u8=1 ‖ seq u64-BE ‖ sig[64] ‖ value_len u32-BE ‖ value. Fixed=82.
- All 5 decoder rules present & correct: magic reject; version reject before body; kind reject; value_len bound-checked FIRST with widened u64 arith (`u64::from(value_len) > (MAX_BLOB_SIZE-82) as u64`) then exact-length equality `blob.len() as u64 == 82+value_len_u64`. No overflow, no panic, no partial parse. decode returns (value,sig,seq) triple ONLY, NO verification.
- **Framing outside signed authority**: `TransportRelayQuerier` (scp-transport/src/did_relay.rs) decodes SCPR, first-decodable-wins, NO verify. `RealMultiRelayQuerier` (scp-identity/src/relay_querier.rs) BEP44-verifies via key from DID string (`extract_public_key(&did)`, not the frame) + self-cert, first-VALID-wins. Substitution-resistant.
- BEP44: `scp_dht::bep44_signable` (scp-dht/src/lib.rs:121) = `3:seqi<seq>e1:v<len>:<val>`, seq-before-value per BEP44. verify uses `verify_strict`. SINGLE canonical impl on branch (local main has stale dupes — ignore). Byte-identity §3.10.5 holds: write paths sign `value` and SCPR-wrap the SAME `value`.
- Raw transport path (manager/native adapter+client) forwards blobs verbatim, no OuterEnvelope codec. Clean.
- Write paths correctly SCPR-wrap: republish.rs relay_republish_loop:731; scp-ffi common resolvers.rs:56 publish_did_record_to_relay (all bridges); PyO3 identity.rs:278.

## HIGH (latent, must-fix): heal Relay arm bypasses SCPR
`DualLayerHealingPublisher::heal` (scp-identity/src/resolver.rs ~L380 StaleLayer::Relay arm) publishes **bare `document_bytes`** as the raw blob: `relay_publisher.publish(&routing_id, DID_DOCUMENT_BLOB_TTL_SECS, &document_bytes)`. Must SCPR-wrap: `encode_did_record(&document_bytes, &signature, seq)` exactly like republish loop. Bare JSON (first byte 0x7B) fails `scpr::decode_did_record` on read (BadMagic) → healed relay record is undecodable/unverifiable, silently corrupts the DID routing ID. Violates RelayPublisher trait contract (blob MUST be SCPR frame). Currently LATENT: no shipped path wires `with_healing`+`DualLayerHealingPublisher` (bridges use `DualLayerResolver::new`); untested (heal tests use `InMemoryHealingPublisher` double that bypasses real heal code). DHT arm is correct (native BEP44, no SCPR). This is the exact bug republish.rs comment warns against, reintroduced in the sibling healing publisher — incomplete SCPR migration in Slice 11.
