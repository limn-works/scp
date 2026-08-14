---
name: adr062-slice11-final-relay-querier
description: ADR-062 Slice 11 (SCP-CAPINJECT-011) FINAL review @ 04c666220 — mechanics ALIGNED but §3.10.8 anti-suppression guarantee falsified by cheap relay-flood; spec+ADR threat model must update before ship
metadata:
  type: project
---

# ADR-062 Slice 11 / SCP-CAPINJECT-011 FINAL @ 04c666220 (feat/adr062-slice11-relay-querier) — NEEDS DISCUSSION

Branch tip 04c666220 is docs/memory; code = f4e1e2d08 (feat) + 38d0e2f74 (011-review fixup). Verified vs ORIGIN.

**Mechanics ALIGNED (a,b,d,e all pass):**
- 13 ACs structurally satisfied. RealMultiRelayQuerier<Q> composer (scp-identity/relay_querier.rs:62/78), concrete TransportRelayQuerier (scp-transport/did_relay.rs:125), TransportRelayPublisher (did_relay.rs:212). publish_raw/query_raw on traits+manager+native adapter+client.
- Decision-5 honored: NoOpRelayQuerier STAYS shipped (resolver.rs:281, AC5 fail-closed test :1431); InMemoryRelayQuerier (resolution.rs:177) + InMemoryRelayPublisher (republish.rs:170) both `#[cfg(any(test, feature="testing"))]`; `= InMemoryRelayPublisher` default type param SEVERED (grep=0).
- SCPR encode (scpr.rs:165) byte layout EXACT per §9.10.12: magic[4] ver[1] kind[1] seq(u64 BE) sig[64] value_len(u32 BE) value. Decoder enforces 5 rules.
- ADR rollout correction (#2201, commit 7e05ed15e) RESOLVED my prior stale-line flag: ADR line 158 + Decision-5 (line 94) + classification table (line 41) all now say NoOp ships / only InMemory demotes. No stale contradiction.
- No phantom story refs: KeyPackage→SCPR kind-2 is "future slice/issue to be filed" (kind 2 = Reserved in spec), no fabricated SCP-NNN.
- write half present + wired into every bridge DID-publish path (best-effort relay alongside DHT).

**FINDING (special-focus CONFIRMED) — §3.10.8 anti-suppression guarantee is FALSIFIED for the relay layer; spec threat model under-specified. NEEDS-DISCUSSION / spec-fix-before-ship.**
The cheap-flood attack DIVERGES from the spec's guarantee. Chain, all verified on origin:
- routing_id = SHA-256("scp:did:"||did_string) is DID-derivable (public).
- Relay raw-blob PUBLISH is UNAUTHENTICATED: no server-side signature check (grep verify in webtransport/session.rs = empty); §9.10.12 mandates relay stays protocol-UNAWARE ("no relay-side change permitted", stores opaque bytes) → relay STRUCTURALLY CANNOT dedupe by DID/highest-seq.
- Relay QUERY serves OLDEST-FIRST + truncate(limit): trait contract storage.rs:147, and every backend (s3_blob.rs:544-550, storage.rs:403-407, local_cache oldest-first evict, sqlite idx_routing on stored_at).
- Client query_raw caps at MAX_DID_RECORD_QUERY_BLOBS=16 (client.rs:72,906).
=> Attacker publishes 16 junk blobs at victim's DID routing_id; the bounded read window returns 16 junk, genuine record pushed out. RealMultiRelayQuerier verify-each/first-valid can only pick from what it RECEIVES — evicted genuine never seen. Cost: 16 tiny blobs × N relays; bootstrap relay set (§18.5.1) small+well-known → flooding ALL relays is cheap. 6-day republish makes it WORSE (fresh stored_at re-buries genuine under maintained older junk).

Why §3.10.8 does NOT cover it: §3.10.8 enumerates "relay serves stale / suppresses / serves wrong DID" and claims "attacker must suppress ALL relays AND ALL DHT — strictly harder." That assumes per-relay suppression is COSTLY (true for DHT: BEP44-verified single slot keyed by pubkey; you can't inject junk at someone's mutable key). FALSE for Model-A relay: unauthenticated append at a public routing_id overflowing a 16-entry read window. The relay layer adds ~ZERO suppression resilience under this cheap attack — it degrades to DHT-only.

Artifact-flow angle: this is the "resilience falsified on arrival" pattern. The stated JUSTIFICATION for landing 011's write half — ADR Decision-5 line 94 + rollout line 158: "only both halves genuinely restore §3.10.8 dual-layer suppression resilience" — does NOT hold for the relay layer as implemented. Shipping 011 as-is = phantom provenance (code claims a spec-guaranteed property it can't deliver).

The gap is FUNDAMENTAL to Model A, not an impl oversight: §9.10.12's "relay unchanged / opaque blobs" forbids the relay-side dedup that would fix it. The MAX=16 cap (added in 38d0e2f74 to defeat unbounded-buffer + intra-window shadow) is the ENABLER of eviction; client.rs:66-72 comment "covers a bounded number of attacker-planted decoy frames" is misleading — it protects against unbounded stream, NOT suppression-by-eviction. Tests only cover the WEAK case: suppression_on_one_layer_defeated_by_other (test :215) empties the relay; shadow test (:330) is bad-then-good WITHIN window. Flood-eviction (>16 junk) is untested — and would break the test's own case (b) "relay defeats DHT suppression."

Resolution needed (spec-level decision, before ship): either (1) downgrade §3.10.8 to state the relay layer provides reachability/latency but NOT suppression resilience — DHT is the sole suppression-resistant layer; or (2) add a real mitigation (authenticated/rate-limited/PoW raw-blob publish, or client reads highest-seq-valid over a larger window) — each a spec change touching §9.10.12's protocol-unaware-relay premise. Fix §3.10.8 + ADR §Decision-5 first, then reconcile 011.

Non-blocking already-known (do not re-report): empty bootstrap_relays cold-cache (#2211); AC7 opaque-blob publisher fix in flight.
