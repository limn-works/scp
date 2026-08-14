---
name: adr062-slice11-relay-querier-verdict
description: ADR-062 Slice 11 (SCP-CAPINJECT-011) relay DID resolution verdict — SHIP-AFTER-FIXES; codec/verify/FFI/severance sound, relay selection+storage semantics not prod-ready
metadata:
  type: project
---

# ADR-062 Slice 11 — relay DID resolution (branch feat/adr062-slice11-relay-querier @ 04c666220)

Verdict: **SHIP-AFTER-FIXES** (relay layer NOT prod-shippable as-is; codec/verify/FFI substructure IS sound and can stay).

**Why:** Reviewed 2026-08-02. The stated purpose ("production relay-based DID resolution") is not met while the relay-layer availability/freshness defects stand.

## STAKE-MY-REP: SOUND (verified, keep)
- **SCPR codec** (scp-protocol/src/envelope/scpr.rs): clean fixed-82+value framing, widened value_len bound-check (no overflow), exact-length equality (rejects truncation+trailing), no verification in decoder (framing grants no authority) — correct. Well-tested incl. near-u32::MAX, boundary.
- **verify_relay_record** (scp-identity/src/resolution.rs): single shared path = BEP44 sig over bencode(seq,value) against DID-suffix key + UTF-8/JSON + self-cert (doc #0 key == DID suffix). Used by BOTH composer and resolver (defense-in-depth). Substitution cryptographically impossible; seq covered by sig. SOUND.
- **InMemory severance HONEST**: InMemoryRelayQuerier + InMemoryRelayPublisher are `#[cfg(any(test,feature="testing"))]` — cannot compile into shipped artifact. All 3 prod bridges (napi identity.rs:201, pyo3 identity.rs:149, uniffi bridge.rs:9341) wire `RealMultiRelayQuerier::new(TransportRelayQuerier::new(transport_handle()))`. NoOpRelayQuerier remaining uses are test modules + self_host DHT-only-by-design. SOUND.
- SCPR-wrap encode contract consistent at all 3 write sites (relay_republish_loop, DualLayerHealingPublisher::heal Relay arm, publish_did_record_to_relay).

## BLOCKERS
- **#1 (known) flood-suppression — CONFIRMED + WORSE than stated.** Unauthenticated publish_raw + DID-derivable routing_id + storage query() oldest-first `truncate(16)` (scp-transport/src/native/storage.rs query()) + wire cap MAX_DID_RECORD_QUERY_BLOBS=16. Attacker plants ≥16 decoy SCPR frames with older stored_at → genuine record truncated out → relay resolution suppressed. **System's own republish/healing makes it WORSE**: republish overwrites blob_id→refreshes stored_at→genuine becomes NEWEST→guaranteed excluded by oldest-first once ≥16 older decoys exist. Also **silently defeats healing** (relay-None → pick_winner sees (None,Some(dht)) → no divergence → no heal). DHT backstops resolution integrity (no wrong doc ever returned), so it's availability of relay layer + §3.10.6 anti-segmentation violation. Fix = relay-side BEP44 single-slot/highest-seq/sig-checked DID-record kind = PERMANENT wire-semantics decision (DOA-class per builder tenets "No DOA decisions"/"No deferral") — must be decided now, not patched later.
- **#4 (NEW, not in known list) composer selects first-valid OLDEST-FIRST, not highest-seq.** relay_querier.rs RealMultiRelayQuerier returns first candidate that verifies; candidates arrive in storage oldest-first order. Relay storage is append-only (7-day TTL, no single-slot). After ANY seq bump (key rotation; DID string unchanged so same routing_id) or healing, old+new genuine frames coexist → composer returns STALE frame. Non-adversarial. Backstopped by DHT cross-layer max-seq in dual mode BUT: (a) DHT-disabled/relay-only nodes (supported+tested: `disabled_node_resolves_self_and_peer_via_relay` w/ DisabledDhtClient) on cold cache serve PRE-rotation doc; (b) dual-mode triggers a PERPETUAL heal storm — every resolve sees relay=stale-oldest → divergence → re-heal → refresh → repeat forever until old TTL. Fix: composer must pick highest-seq valid candidate; real fix folds into #1 single-slot.

## NON-BLOCKING (land with the relay-storage pass)
- **#3 (known) dedup self-suppression:** client seen_blob_ids LRU checked in reader dispatch (native/client.rs:464) gates the temp subscription query_raw uses. 2nd query_raw for same DID blob_id on a long-lived connection returns empty → relay None. Bounded (resolver 24h cache fronts it) but real. Fix: one-shot raw query must bypass reconnect-dedup LRU.
- **#2 (known) RelayPublisher::publish takes opaque `&[u8]`** — footgun (bare-bytes → BadMagic silent drop). Exactly 3 callers, all wrap today (not a live bug). Fix to `&DidRecord`/encode-internally.
- **Test-coverage honesty gap:** did_relay_round_trip.rs test-double InMemoryRawRelay.query_raw returns ALL blobs unordered, no cap/dedup → GREEN tests do NOT exercise #1 or #3 (they're structurally absent from the double). Passing suite gives false assurance on exactly the two live-relay defects. Real-relay integration test needed.
- bootstrap cold-cache #2211 (already known non-blocking).

## Fix scope: days. One relay-storage-semantics pass: single-slot/highest-seq/sig-checked DID-record kind (fixes #1+#4), bypass-dedup for one-shot raw query (#3), &DidRecord API (#2), real-relay integration test. All downstream of a permanent wire decision that needs Alec sign-off.
