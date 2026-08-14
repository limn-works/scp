---
name: adr052-p3c-hostsiteconfig
description: PR #1818 HostSiteOptions→HostSiteConfig review — bool→enum fold is behavior-preserving for lib; binary M2 divergence + stale guide/help docs
metadata:
  type: project
---

# PR #1818 (feat/p3c-site-config) — HostSiteOptions → HostSiteConfig

**Why:** ADR-052 Phase B-P3c folds host-site bools into enums, dodges FFI `projection::SiteConfig` name collision, promotes `DhtMode` to `config.rs`.

**How to apply:** When reviewing similar bool→enum config folds, check that the OLD downstream consumers (`build_host_site_node`, `open_self_host_public_surface`) are UNCHANGED — they still take `(plaintext, skip_nat)` bools — so the only question is whether the new `lower_*` fn reproduces the same bools. It does: `Plaintext⇒true/SelfSigned⇒false`, `Local|Tunnel⇒skip_nat=true / NatTraversal⇒false`.

**Key architectural fact:** In scp-node, `NodeConfig.dht` is ADVISORY/dropped (config.rs ~517-532). Actual DHT publication is decided by the concrete DID-method type `D` (chosen by `match dht_mode` → `build_memory_did_method` vs `build_production_did_method`). `validate_config` only sees the skip_nat-coupled internal `dht`, never the user's publication selector. This decoupling is why the OLD `host_site` allowed 4 independent `(skip_nat, dht_mode)` combos.

**Findings:**
- LOW/divergence (binary): NEW `lower_host_site_reach_tls` M2 guard rejects `NatTraversal + Memory`. The binary defaults `skip_nat=false → Reach::NatTraversal` and `dht_mode=production`. Setting `SCP_NODE_DHT_MODE=memory` ALONE (without `SCP_NODE_SELF_HOST_NO_NAT=1`) now exits 1 (InvalidConfig). OLD binary RAN that combo (probed NAT, InMemoryDhtClient = no publish). Intended M2 tightening, but help text (main.rs:172) + doc-comment (main.rs:625 "unless SCP_NODE_DHT_MODE=memory") are now STALE/misleading — they imply `memory` alone suppresses publishing; it now requires NO_NAT too.
- LOW/provenance: both `.docs/guides/self-hosting-a-website-on-scp.md` (line ~386, the guide the new code doc-comments point to) AND `.docs/guides/deploying-an-scp-website.md` (4 refs) still name `host_site(HostSiteOptions)` — a type that no longer exists. Doc-only, not compiled, but broken provenance.

**No code defect:** library fold is behavior-preserving; DhtMode single def; example/main/test compile; projection.rs + all enforcement/matrix/bridge files untouched; Row 2 (skip_nat=true+Production = publish loopback URL) still representable as `Reach::Local + DhtMode::Production`.
