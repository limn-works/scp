---
name: adr062-slice1-dht-e1-round3
description: ADR-062 Slice1/SCP-CAPINJECT-001 round-3 verify — R2-1/R2-2 config.dht threading RESOLVED clean; residual stale Memory-fail-safe docs
metadata:
  type: project
---

# ADR-062 Slice 1 (SCP-CAPINJECT-001) round-3 verification @ scp-wt agent-a84a486b70f195952, commit 5584761bc (delta e54de4fae..5584761bc)

Round-2 HIGH (mine): host_site re-derived DhtMode from skip_nat, discarding config.dht.

**R2-1 RESOLVED (clean).** `host_site_until` destructures `dht: dht_mode` from config once (self_host.rs:1227). That single `dht_mode` (Copy) now drives BOTH: (a) concrete DID-method `D` via `dispatch_hosted_site_by_dht_mode(dht_mode,...)` and (b) `NodeConfig.dht` via `build_host_site_node(...,dht_mode)` → `let dht = dht_mode` (2207, replacing `skip_nat?Disabled:Production`). Threads through existing `ServeHostedSite` struct + build_host_site_node param list — no new coupling; only added `#[allow(clippy::too_many_arguments)]` (acceptable internal builder). `{NatTraversal,Disabled}` now selects DisabledDhtClient AND NodeConfig.dht=Disabled → publish skipped, node starts. OBSERVATION: new integration test `nat_traversal_disabled_dht_node_starts_without_publishing` constructs NodeConfig DIRECTLY (not via build_host_site_node/host_site_until), so it proves the config is startable but does NOT guard the threading regression — a revert to skip_nat-derivation would still pass. Contrast R2-2's tests (below) which go through Node::start_for_testing properly.

**R2-2 RESOLVED (clean, well-tested).** `build_domain_inner` takes `dht_mode`, routes `publish_did_document_for_mode(dht_mode,...)` instead of unconditional `did_method.publish().await?` (lib.rs:3057). Both publish paths (no-domain + Domain-success + TLS-fallthrough) now converge on ONE chokepoint. Two real tests via Node::start_for_testing: `domain_disabled_starts_without_publishing` (0 publish attempts, node up in domain mode) + `domain_production_publish_failure_fails_closed` (fatal DhtPublishFailed, exactly 1 attempt).

**R2-8 PARTIAL.** Named targets fixed: HostSiteConfig.dht doc (Memory→Disabled fail-safe + load-bearing note), dht_gateways doc (validate_gateway_url, Production-only), NodeConfig.dht ("Load-bearing not advisory"), NodeConfig.dht_gateways (honest "not threaded e2e, see #2153"). BUT six SIBLING doc comments in self_host.rs (883,1044,1105,1197,1237,2562) still frame `DhtMode::Memory (no publish) is the fail-safe direction and valid for every reach`. Post-R2-4 Memory is `#[cfg(feature="testing")]`-only (unconstructible in shipped builds) — Disabled is the shipped fail-safe. Self-contradicts corrected HostSiteConfig.dht doc a few lines away. Same class as R2-8, incompletely swept. LOW/doc-only, non-blocking.

**R2-4 gating (Memory→feature="testing" only)** applied consistently across all 3 sites (config.rs enum variant, lib.rs publish arm, self_host.rs dispatch arm) — strengthens G1 (single activation path, invisible to feature-graph check). ADR-062 Decision 1 / G1 soundness HOLDS.

**R2-5 ci.yml** `cargo test -p scp-ffi-common` default-features lane added — additive positive lane (not enforcement weakening), makes absence tripwires live. #2153 is a REAL open issue (gateway e2e wiring).

VERDICT: APPROVE-WITH-CHANGES — only change is finishing the R2-8 doc sweep (six Memory→Disabled fail-safe comments). No correctness/architecture defect.
