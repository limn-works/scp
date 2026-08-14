---
name: hostsiteconfig-legal-subset-p5
description: HostSiteConfig reuses the full shared TlsMode/Reach enums but host_site only honors a subset — a legibility trap docs must close
metadata:
  type: project
---

`HostSiteConfig` (crates/scp-node/src/self_host.rs) reuses the SHARED `TlsMode` and `Reach` enums defined in crates/scp-node/src/config.rs (also used by `NodeConfig`), but the `host_site` driver only honors a SUBSET. `lower_host_site_reach_tls` (self_host.rs ~L914-955) rejects at runtime with `HostSiteError::InvalidConfig`:
- `TlsMode::Acme`, `TlsMode::Terminated`, `TlsMode::Custom` — only `SelfSigned` / `Plaintext` are legal for host_site.
- `Reach::Domain` — only `NatTraversal` / `Local` / `Tunnel` are legal.

Trap: `TlsMode::Terminated` is the semantically obvious pick for the tunnel/reverse-proxy recipes (they DO terminate TLS upstream) but it errors here. An LLM authoring from the enum shape will reach for it.

Also: `Reach::Tunnel { public_url }` — `public_url` is NOT threaded in P1 (config.rs:136 "not yet threaded; builder publishes loopback"); `Tunnel` just folds to `skip_nat=true`. Docs that present the URL as load-bearing mislead.

**Why:** ADR-052 M1 collapsed phantom-state markers + bools into shared enums; reuse across NodeConfig/HostSiteConfig means the type signature advertises variants the specific driver forbids.

**How to apply:** When reviewing P5/downstream HostSiteConfig docs/examples, require the docs to state the LEGAL SUBSET explicitly (knob tables read as illustrative, not exhaustive — an LLM won't infer the forbidden variants). Watch for stale field names too: the field is `dht:` not `dht_mode:`. Related: [[whole-config-spread-idiom]] if written later.
