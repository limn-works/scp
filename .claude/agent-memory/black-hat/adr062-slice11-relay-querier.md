---
name: adr062-slice11-relay-querier
description: ADR-062 Slice 11 relay DID resolution — round-1 shadow-DoS fix is INCOMPLETE; oldest-first+cap(16) still suppresses
metadata:
  type: project
---

# ADR-062 Slice 11 (SCP-CAPINJECT-011) relay DID resolution @04c666220

Branch feat/adr062-slice11-relay-querier. Production relay-based DID resolution over UNAUTHENTICATED public relay blobs (publish_raw/query_raw, §9.10.12). SCPR framing unsigned; only BEP44 (value,seq) triple signed.

## HEADLINE — BLACK-S11-1 (HIGH): round-1 shadow-DoS fix is INCOMPLETE — bounded shadow survives the cap
Round-1 fixed intra-relay shadow by returning Vec of ALL candidates + verify-each-first-valid. But TWO caps + oldest-first ordering reintroduce the exact suppression:
- storage query returns blobs OLDEST-FIRST then `truncate(limit)` — crates/scp-transport/src/native/storage.rs:403-407.
- wire+client cap MAX_DID_RECORD_QUERY_BLOBS=16 — client.rs:72, query_raw client.rs:906-908, collect_blobs cap break client.rs:842-844.
- composer decode cap MAX_RELAY_CANDIDATES=16 — did_relay.rs:86.
Attack: attacker (anyone) publish_raw's 16 blobs (even garbage) at DID-derivable routing_id BEFORE victim's genuine publish. Oldest-first + truncate(16) => query_raw returns ONLY the 16 attacker blobs; genuine record (newer, 17th) never fetched => composer exhausts, returns Ok(None) (relay_querier.rs:133) => relay resolution SUPPRESSED. Reduced exploit from 1 blob (round-1) to 16 — NOT eliminated. Fix doc-comment claim ("planting one blob to permanently suppress" prevented) violated at N=16.
- HEALING CANNOT CURE: §3.10.7 heal republishes with a NEW (newest) stored_at; oldest-first truncate keeps the 16 oldest attacker blobs => healed record still excluded. Self-healing defeated by construction.
- Duration: up to blob TTL (7d) per plant, cheap+repeatable; strongest vs not-yet-published DIDs (attacker wins oldest race deterministically).
Fix direction: DID-record query must not be a blind oldest-first truncate — need highest-seq-biased server selection, or client pages past the cap when all candidates invalid, or dedup-to-single-valid at relay. A raw oldest-first truncate on an unauthenticated flood-able routing_id cannot satisfy §3.10.8.

## Cleared (no finding)
- scpr.rs decode: solid (widened value_len bound, exact-length, kind/version/magic reject, no partial parse, no overflow).
- LiveTransport (did_relay.rs): current() drops RwLockReadGuard before return (no lock-across-await), poison=>None fail-closed, unconnected=>Ok(None)/RelayNotConnected fail-closed. Clean.
- Healing forge: heal only republishes BEP44-verified higher-seq ValidatedRecord; attacker can't inject forged doc. Minor amplification (perpetual divergence spawns tasks) but mutually exclusive with full suppression.
- first-valid-not-highest-seq: pre-existing/known, not re-reported.
