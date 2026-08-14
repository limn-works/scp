---
name: adr062-slice11-relay-querier-scpr
description: ADR-062 Slice 11 (#482) relay DID resolution + SCPR wire format review @ origin/feat/adr062-slice11-relay-querier 04c666220 — SOUND, ship w/ fixes
metadata:
  type: project
---

# ADR-062 Slice 11 — relay DID resolution + SCPR (issue #482) @ 04c666220

VERDICT: architecturally SOUND / approve-with-changes. The earlier BLOCKER I recorded in
[[adr062-011-relay-blocker]] (unspecified relay DID-record blob framing = DOA wire-format needing Alec)
was resolved the RIGHT way: spec §9.10.12 written FIRST (proper artifact flow), then coded down. ADR-062
§Decision 5 + slice-11 line 158 mandate EXACTLY what was built.

## The 4 questions
- **Q1 design/#482 ACs:** all 3 traits now have prod impls (RelayQuerier→TransportRelayQuerier,
  MultiRelayQuerier→RealMultiRelayQuerier, RelayPublisher→TransportRelayPublisher), wired into all 3 FFI
  bridges via per-instance LiveTransport handle (late-binding, exactly the arch I proposed in the blocker
  memo). Round-trip integration test present. #482 ACs met — but #482's literal "publish DID doc blobs"
  is INCOMPLETE: old code published bare document_bytes, DROPPING signature+seq → unverifiable on read
  (republish.rs:703 bug, called out in ADR line 158). A self-certifying record MUST carry (value,sig,seq),
  so SOME framing is mandatory; #482 (pre-SCPR) just didn't know it.
- **Q2 SCPR warranted?** YES, appropriately minimal. Reusing OuterEnvelope = the #2202 encrypted_blob
  misuse being fixed. Reusing BEP44 bencode mutable-item rejected soundly (spec "Alternative rejected":
  k derivable from DID so NOT byte-identical anyway; house style §9.5.1 = raw length-prefix not bencode;
  multi-kind extensible family). 6 framing bytes (magic4+ver1+kind1) buy the byte-disjoint-from-OuterEnvelope
  backstop + versioning + kind-2 KeyPackage migration (#2202, filed) reusing publish_raw/query_raw. Not
  over-built given No-DOA/no-deferral tenets. Decoder is textbook (widened bound-check, exact-length,
  reject-unknown-kind, no partial parse, 14 tests).
- **Q3 protocol-unaware relay (Model A):** RIGHT call, not pointless. Core tenet "relays are untrusted
  dumb pipes" + 17-adapter transport-independence ⇒ can't rely on relay validation (Nostr/Matrix won't
  validate SCP records); client MUST self-verify regardless, so relay validation would be redundant +
  non-portable + protocol-coupling. §3.10.8 substitution-impossible (routing_id from DID, verify vs DID key).
  BUT Model A append-no-supersession shifts BOTH validity AND freshness duties to the client, and the code
  does validity but NOT intra-relay freshness — see finding.
- **Q4 abstractions:** right-shaped. Generic RealMultiRelayQuerier<Q> keeps composer in scp-identity (no
  scp-transport dep) while prod injects TransportRelayQuerier from scp-transport (dep-cycle seam — transport
  depends on identity). publish_raw/query_raw as default trait methods (err / empty) keeps 17 adapters
  compiling. RelayNotConnected vs RelayPublishFailed split deliberate (quiet interim vs alarm). Not
  accidental complexity.

## Findings
- **MEDIUM (primary): composer returns FIRST valid record, not FRESHEST (max-seq).** relay_querier.rs
  RealMultiRelayQuerier::query returns Ok(Some) on first BEP44-verify success. In Model A's multi-blob
  routing ID an attacker can replay an OLD-but-validly-signed DID doc (pre-key-rotation) ordered first;
  composer returns stale. Cross-layer seq arbitration in DualLayerResolver rescues this ONLY when a fresher
  cache/DHT record exists — for a COLD Disabled node (empty cache, DHT off) resolving a peer first-time,
  stale-valid is accepted = downgrade/rollback vector. BEP44 DHT single-slot prevents this; Model A must
  replicate it CLIENT-side. Cheap fix: composer already fetches ALL candidates per relay — select max-seq
  valid instead of first-valid.
- **LOW: cap-overflow suppression.** MAX_RELAY_CANDIDATES/MAX_DID_RECORD_QUERY_BLOBS=16: 16 well-framed
  bad-sig decoys planted before genuine → genuine beyond cap → relay resolve suppressed. DHT-backstopped
  (spec accepts reduced suppression-resilience, §3.10.6 dual-layer=SHOULD), so bounded, but note it.
- **OBS: Disabled scp-node colocated governance still inert.** self_host.rs:1410 build_shared_cache_key_resolver
  keeps NoOpRelayQuerier (loopback relay genuinely not a DID source, §10.4 — CORRECT). But ADR line 158/167
  claims "a Disabled node resolves own+peers via relay after Slice 11." Delivered for FFI SDK clients; the
  node's colocated path does NOT reach an external relay, so Disabled-node colocated governance stays inert
  (ADR line 169 disclosed this). Verify whether node peer (non-loopback) resolution wires the real querier.

## Verified
- RepublishManager<D,R> default type param SEVERED (no `=InMemoryRelayPublisher`); InMemoryRelayPublisher
  now #[cfg(any(test,feature=testing))]. republish loop wraps SCPR frame carrying full triple (fixes :703).
- one-shot publish_did_record_to_relay wired in all 3 bridges (identity create/rotate).
- collect_blobs refactor clean: query() decodes OuterEnvelope, query_raw() returns raw bytes; disjoint
  routing-ID spaces + byte-level 0x53-vs-mapmarker backstop.
- scpr exported scp-protocol → re-exported scp-core::envelope::scpr. LiveTransport slot set at set_transport.
