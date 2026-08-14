---
name: adr062-slice11-relay-did-resolution
description: Fresh audit of relay-based DID resolution (feat/adr062-slice11-relay-querier @04c666220) — SCPR frame + relay querier composer + native storage/client. 3 real findings; relay layer cannot meet §3.10.8 without relay-side validation.
metadata:
  type: project
---

# ADR-062 Slice 11 relay DID resolution — audit @04c666220 (2026-08-02)

Branch `feat/adr062-slice11-relay-querier`. Model: relay stores opaque BEP44-signed
DID-record blobs at routing_id = SHA-256("scp:did:"||did); anyone can publish (per-IP
rate-limit only); QUERY returns a bounded, ordered blob set; relay does NOT validate.
Runs in parallel with single-slot Mainline DHT layer.

## Finding 1 — HIGH: QUERY-window eviction suppression (oldest-first truncate)
- native/storage.rs:404-407 sorts candidates OLDEST-first then `truncate(limit)` → QUERY
  window = oldest N blobs. client.rs:72 MAX_DID_RECORD_QUERY_BLOBS=16; did_relay.rs
  MAX_RELAY_CANDIDATES=16; all aligned at 16. No per-routing-id blob cap (only global
  max_blobs + per-IP publish rate limit).
- Exploit: plant ≥16 long-TTL junk blobs (distinct content ⇒ distinct blob_ids) at the
  victim's DID-derivable routing_id. Each genuine (re)publish makes the genuine record the
  NEWEST ⇒ it falls outside the oldest-16 window ⇒ never returned. Near-permanent, ~16
  publishes per TTL period, trivially within rate limit.
- **CANNOT be fixed client-side** — genuine bytes aren't in what the relay returns.
  Composer's "iterate every candidate" only defeats intra-window SHADOWING, not window
  EVICTION. Requires RELAY-SIDE: verify BEP44 + single highest-seq slot per routing_id
  (mirror the DHT). This is the §3.10.8 bottom line.

## Finding 2 — HIGH: composer returns FIRST-valid, not HIGHEST-seq (rollback/freshness)
- relay_querier.rs:106-127: loops candidates, returns the FIRST that verifies. Combined
  with storage oldest-first ordering ⇒ relay layer actively prefers the OLDEST valid =
  MOST-superseded record. After a key rotation both old(seq5) and new(seq6) verify (same
  DID key signs both; self-cert passes both) → composer returns seq5.
- Dual-layer resolver picks highest across layers, so DHT usually corrects it — but if DHT
  times out/absent or on cold start (cached_seq=None), the stale rotated-out key is served.
  Spec §3.10.4 step 6 says highest-seq; impl says first. Fix CLIENT-SIDE: select highest-seq
  valid candidate. Related to #1855 (in-mem floor) but distinct — this discards a higher-seq
  record already in hand.

## Finding 3 — HIGH: shared dedup LRU drops genuine record on repeat query_raw
- query_raw→collect_blobs registers a temp subscription; blobs arrive via the SAME
  dispatch_relay_message BLOB arm that consults seen_blob_ids (client.rs:464 dedup check,
  :526 commit). DID record blob_id is content-addressed = STABLE across queries. First
  query delivers + commits blob_id to LRU; SECOND query for the unchanged DID hits the
  dedup `return` at :464 → genuine record never reaches collect_blobs → relay layer returns
  empty. LRU cap 10_000 (client.rs), persists across the 24h/7d DidCache TTL. Degrades relay
  resolution to zero after first success. Fix CLIENT-SIDE: QUERY path must bypass
  seen_blob_ids (dedup is a subscribe-path concern).

## Positive (Finding 4 clean)
- scpr::decode_did_record does NO verification (framing grants no authority) — correct.
  verify_relay_record uses DID-derived key (extract_public_key(&did)), never frame-supplied;
  seq lives in unsigned framing but is bound by BEP44 sig over (seq,value) → seq tamper /
  inflation fails verification. Self-cert binds embedded key to DID suffix. Verify applied at
  composer AND re-applied at resolver (defense-in-depth). Sound.

## Bottom line for §3.10.8
Relay layer CANNOT meet suppression-resistance without relay-side changes (verify + single
highest-seq slot). Findings 2 & 3 are client-side-closable; Finding 1 is not.
