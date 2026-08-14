---
name: relayres003-slot-exclusivity
description: SCP-RELAYRES-003 DID-record slot-exclusivity — fix commit 7cdd735d6 confirmed; remaining surfaces (unauth DELETE, WebTransport latent asymmetry, cold-establish lock DoS)
metadata:
  type: project
---

# SCP-RELAYRES-003 relay-side DID-record slot-exclusivity

Fix commit `7cdd735d6` (branch relayres-003-fixes). Closes BLACK-RR003-001
(QUIC/UDP bypassed slot registry while sharing WS blob store).

**CONFIRMED FIXED:**
- QUIC (`quic/listener.rs`) + UDP (`udp/listener.rs`) `handle_publish` now gate via
  `classify_did_record_frame` + `publish_frame`/`is_claimed`; QUERY + SUBSCRIBE-backfill
  return only `slot_blob` when claimed. Flood is inert.
- ONE shared registry: `config.rs:951-963` — single `Arc<BlobStorageBackend>` + one
  `relay_server.did_slot_registry()`, threaded into QUIC via `NodeState.did_slot_registry`.
  QUIC gets `state.blob_storage` (same Arc). No split-brain: `did_record_validation: rc....`
  is the same RelayConfig for WS + QUIC.
- Cold-index seq reconciliation (`did_slot.rs publish_frame` None branch): `highest_valid_frame`
  adopts highest-seq stored genuine frame and REJECTS lower-seq newcomer → replay cannot delete
  fresher genuine record. Sound. Attacker replay only re-establishes/pins genuine records.
- Ed25519 cold-scan DoS NOT viable: valid-binding-bad-sig frames are rejected at publish (never
  stored); only NotAFrame junk pre-seeds, classify rejects it cheaply (structural decode).

**WebTransport verdict: NOT a live bypass.** `spawn_http3_listener` H3RequestHandler serves ONLY
`GET /.well-known/scp`, 404 else. NO `WebTransportServer::new`/`WebTransportSessionHandler::new`
caller outside `src/webtransport/` tests. http3 adapter has zero webtransport refs. Genuinely
unreachable. BUT latent library asymmetry: same opaque-store publish pattern, ungated — the one
relay-capable transport left without the registry param. Gate now for symmetry / future footgun.

**Remaining surfaces (NOT introduced by fix):**
- MEDIUM (pre-existing): unauthenticated DELETE on ALL transports (WS `server.rs:1667`,
  QUIC, UDP `handle_udp_delete`) removes any blob by blob_id, NO is_claimed gate. DID records are
  public → attacker knows blob_id → DELETE genuine slot blob → `revert_if_stale` un-claims slot →
  attacker replays old genuine lower-seq frame → pins stale slot (QUERY returns only it, rule c).
  Integrity still held by resolver seq-monotonicity + DHT + multi-relay (availability-only model).
  Recommend gating DELETE at a claimed DID slot.
- LOW/informational: `publish_frame` holds global `slots.write()` across storage query(u32::MAX)
  + N deletes on cold establish → head-of-line blocking for all DID publishes on durable backends.
  Bounded by per-IP rate limit, one-time per routing_id, availability-only.
