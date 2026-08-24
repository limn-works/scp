---
name: scp245-per-layer-healing
description: SCP-245 (per-layer DID healing) verdict — 1 of 9 criteria met; the shipped healing trigger is cross-layer and unreachable in production
metadata:
  type: project
---

SCP-245, "Implement per-layer healing", is pending: 1 of its 9 acceptance criteria is met.

**Why:** §3.10.7 of the identity spec (`.docs/specs/03-identity.md`) was amended by the
two-encoding change so that healing is per layer — a layer's own encoding republished back
to that same layer, triggered by that layer's own cached sequence number. The code in
`crates/scp-identity/src/resolver.rs` implements the removed cross-layer form: the only
healing trigger is `relay_rec.resolved.seq.cmp(&dht_rec.resolved.seq)` (line 562), and
`DualLayerHealingPublisher::heal` copies the relay record's bytes to Mainline (lines
345-350) and the DHT record's bytes to a relay (lines 354-361), which the amended §3.10.7
forbids as unperformable under two encodings.

**How to apply:** when re-reviewing this story, check three things that decide it.
(a) `DidCache` holds one `sequence` per DID (`crates/scp-identity/src/cache.rs:64`,
`cached_sequence` at line 254), not one per (DID, layer), so the per-layer trigger the
story requires has no data behind it. (b) No bootstrap-core / DNS-packet encoding exists
anywhere under `crates/` — grep for `bootstrap_core|BootstrapCore|DnsPacket` returns zero
Rust hits — so the Mainline half of the story cannot be satisfied until that encoding
lands. (c) `DualLayerResolver::with_healing` (line 398) is called only from the crate's
own `#[cfg(test)]` module (module starts at line 837); all 20 `DualLayerResolver::new`
sites set `healing_publisher: None` (line 383). The absent capability is honest rather
than stubbed, so it is not a nullifier finding.

The one met criterion is the no-healing conformance path: test
`healing_not_triggered_without_healing_publisher` (line 1945) resolves through
`make_resolver` (line 992) and asserts the unchanged result at line 1987.

Related: [[did_two_encoding_amendment_2297]].
