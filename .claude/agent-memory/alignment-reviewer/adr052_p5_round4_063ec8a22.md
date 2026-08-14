---
name: adr052-p5-round4-063ec8a22
description: ADR-052 P5 HostSiteOptions→HostSiteConfig doc/example migration round-4 review at HEAD 063ec8a22 — ALIGNED, clean
metadata:
  type: project
---

# ADR-052 Phase B-P5 round-4 review (branch `feat/p5-downstream-updates`, HEAD `063ec8a22`, 2026-06-16) — ALIGNED

Related: [[adr052-p5-round2-71ac11de5]] (round-2/3 base), [[adr052_p5_hostsiteconfig_downstream]] (round-1).

HEAD `063ec8a22` is ONE commit past the round-2/3 base `71ac11de5`. The new commit (`063ec8a22` "trim duplicate inline comments from website.rs") and the prior `d5b64fdad` ("trim README public-hosting prose to pointer") are both pure prose trims. No new identifier surface introduced.

**Scope:** 4 docs/example files — `crates/scp-node/examples/website.rs`, `crates/scp-node/examples/README.md`, `.docs/guides/deploying-an-scp-website.md`, `.docs/guides/self-hosting-a-website-on-scp.md`.

**Verified clean against ground truth:**
- Stale-shape grep across all 4 files for `HostSiteOptions|skip_nat:|plaintext:|dht_mode|.plaintext|opts` → ZERO real hits. The two raw matches are FALSE POSITIVES: README:42 `DhtMode::Production opts into` + self-hosting:295 `SCP_NODE_SELF_HOST_PLAINTEXT=1 opts out` are English verb "opts"/env-var-name, not the old `opts` config var or a `plaintext:` field.
- All 5 `website.rs` imports (`DhtMode, HostSiteConfig, Reach, TlsMode, host_site`) confirmed public re-exports: `HostSiteConfig`/`host_site` at lib.rs:48-52 (from `self_host`); `DhtMode`/`Reach`/`TlsMode` at lib.rs:58-60 (from `config`).
- `website.rs` compiles clean (`cargo build -p scp-node --example website` → Finished, no errors).
- Struct + `defaults(Reach)` parity: `HostSiteConfig` at self_host.rs:701-761 (reach required; tls folds plaintext bool; dht M2; defaulted site_dir/port/storage_path/dht_gateways/projection_rate_limit/refresh_interval/on_ready); `defaults(reach: Reach)` ONE-arg at :785, fail-safe defaults tls=SelfSigned dht=Memory. Example spread `..HostSiteConfig::defaults(Reach::Local)` + all 3 recipe spreads match.
- TLS/Reach validity prose in deploying-guide §18-19 matches `lower_host_site_reach_tls` (self_host.rs:914-958): Acme/Terminated/Custom each → InvalidConfig (:918-941); Reach::Domain → InvalidConfig (:947-954); only SelfSigned+Plaintext and NatTraversal/Local/Tunnel accepted.
- M2 framing accurate: DhtMode::Memory valid for EVERY Reach incl. NatTraversal, never an error — matches self_host.rs:905-913 + construction.md:63/:194. "At a glance" table and trade-offs teach this correctly; no false "publishing reach + Memory ⇒ error" rule anywhere.
- construction.md §179-196 host_site shape (reach required / tls folds plaintext / dht M2 / defaulted fields) conforms to the impl. Sugar-tier framing (host_site constructs full config, delegates to Node::start) matches.

**Verdict ALIGNED, 0 required, 0 material.** Two consecutive clean rounds (round-3 `d5b64fdad`, round-4 `063ec8a22`).

**1 carried-forward INFORMATIONAL note (unchanged, non-blocking):** `Reach::Tunnel { public_url }` is a documented P1 deferral (config.rs:136 "public_url not yet threaded; builder publishes loopback"; one-time `tracing::warn!` at config.rs:684, fired :768). Recipes 2/3 supply `public_url` but the node publishes loopback. Both remain operationally correct: the tunnel/proxy provides external reachability and forwards to localhost:8443, and neither guide claims the node consumes the field. Honest as-built, not phantom provenance.
