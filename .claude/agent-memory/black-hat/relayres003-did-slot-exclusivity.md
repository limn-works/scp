---
name: relayres003-did-slot-exclusivity
description: SCP-RELAYRES-003 relay-side DID-record validation + slot-exclusivity — audit verdict + the one surviving attack (co-deployed QUIC bypass)
metadata:
  type: project
---

# SCP-RELAYRES-003 (commit da1f610ae) — flood-suppression audit

The WS validating relay closes the four §3.10.8 flood variants correctly.
Files: `native/did_slot.rs` (DidSlotRegistry), `native/server.rs` (handle_publish/handle_query validating branch), `relay/did_record_validation.rs` (classify_did_record_frame).

**SOUND (no surviving attack on the WS path):**
- single-slot/seq rule, binding-before-sig ordering (hash cheaper, gates the Ed25519 verify), eviction rule (b) via store_as_sole_slot, expiry reversion (get() filters expires_at>now), concurrency (publish_frame holds slots.write across storage ops → valid publishes serialize). Binding derives routing_id from the frame's embedded pubkey and compares — no cross-DID acceptance; SHA-256 preimage infeasible.

**SURVIVING ATTACK (HIGH): co-deployed non-validating transport bypass.**
- `RelayServer::did_slot_registry()` is EXPOSED but consumed NOWHERE. Only the WS relay is wired to the registry.
- QUIC listener (`quic/listener.rs`) shares the SAME blob_storage + subscription_registry (node wiring: `scp-node/src/http.rs:1792 spawn_quic_listener`, `Arc::clone(&state.blob_storage)`), but is explicitly non-validating: PUBLISH stores opaquely with no is_claimed gate (~L823); QUERY (L1038) and SUBSCRIBE-backfill (L942-944) call `storage.query` DIRECTLY — not registry-gated.
- Attack: genuine slot established via WS; attacker PUBLISHes junk via QUIC at the same claimed routing_id (accepted); resolver reaching the node over QUIC (spec §10.14.3: WS+QUIC share one address) QUERYs → gets genuine + up to 999 junk (MAX_QUERY_LIMIT=1000, oldest-first keeps genuine reachable so integrity holds, but the flood is NOT inert). Anti-suppression/availability — the story's whole point — is defeated on that transport. Junk persists until next WS DID write (rule-b eviction) or TTL (~6-day republish window); attacker re-injects.
- UDP listener (`udp/listener.rs:898/950`) is the same class. QUIC is the node-wired, default-shipped-if-`quic`-feature instance.
- The QUIC handle_publish doc comment defends only the WS relay's query ("registry-gated QUERY still returns only the genuine slot") and mislabels this "not a correctness gap here" — it ignores QUIC's own un-gated query/subscribe path.
- Fix: wire the shared DidSlotRegistry into every co-deployed transport's publish (is_claimed gate) + query/subscribe (slot_blob gate), OR forbid co-deploying a non-validating transport on a validating relay's store.

Secondary: correct-binding+bad-sig frame forces one Ed25519 verify (attacker embeds victim's public pubkey) — LOW, rate-limited. Lingering opaque-store race on WS is QUERY-invisible on WS but becomes visible via QUIC (folds into main finding).
