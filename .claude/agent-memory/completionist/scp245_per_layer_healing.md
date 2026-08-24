---
name: scp245-per-layer-healing
description: SCP-245 (per-layer DID healing) verdict — 4 of 9 criteria met (only scaffolding; all four per-layer-behaviour criteria unmet); the shipped healing trigger is cross-layer and unreachable in production
metadata:
  type: project
---

SCP-245, "Implement per-layer healing", is pending: 4 of its 9 acceptance criteria are met,
and all four are scaffolding rather than behaviour. Criteria 1, 2, 3, 4 and 7 — every one that
describes what per-layer healing does — are unmet.

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

The four met criteria are all mechanism, and they attach to the FORBIDDEN cross-layer
trigger rather than to the per-layer one the story asks for. Count them as met, and say so
plainly: asynchrony (`tokio::spawn`, line 625), best-effort (`warn!`-and-discard, lines
627-635), the failure test (`healing_failure_does_not_affect_resolve_result`, line 1880),
and the no-healing conformance path (`healing_not_triggered_without_healing_publisher`,
line 1945, resolving through `make_resolver` at line 992). An earlier pass of mine counted
only the last one; the count moved to 4 on re-reading, not the verdict.

The deciding criterion is #4, "never triggers healing from a cross-layer sequence
comparison": resolver.rs:562 is the only healing trigger in the workspace and it is exactly
that comparison. Criterion 3 is worse than absent — it is inverted, and
`healing_triggered_when_relay_stale_dht_fresher` (line 1653) asserts the forbidden copy at
line 1712 (`heals[0].document_bytes == value_v5`, the DHT bytes, with `stale_layer ==
Relay`).

**`SUPERSEDED` is the wrong word for this story's `result` field.** The story was re-scoped:
§3.10.7 still specifies per-layer healing as a MAY, the story title still names work in the
imperative, and its criteria still ask for it. What was superseded is the shipped
implementation, not the story. Say "the shipped implementation no longer satisfies this
story," never "superseded."

Related: [[did_two_encoding_amendment_2297]].
