---
name: adr052-p5-round-guides-fe3eca2fd
description: ADR-052 Phase B-P5 guide-polish round @ fe3eca2fd (feat/p5-downstream-updates) — ALIGNED, 0 findings; line-pin→symbol refactor + 2 factual fixes
metadata:
  type: project
---

ADR-052 Phase B-P5, branch `feat/p5-downstream-updates`, HEAD `fe3eca2fd` (2026-06-17) — ALIGNED, 0 findings.

4 commits past prior-reviewed `aac9851dc` (`2c134b339`/`6d7490a09`/`338019e0d`/`fe3eca2fd`); `git diff aac9851dc fe3eca2fd` = the TWO GUIDE FILES ONLY (deploying +1/-1, self-hosting +22/-22). website.rs / examples README / main.rs / self_host.rs byte-identical to prior FINAL rounds.

**Two change categories, both verified:**
1. **Line-pin → symbol-reference refactor** (resolves the standing brittleness concern): all `file:NNNN` pins replaced with `fn name`/`impl` references. Verified every new symbol resolves to exactly one def in code: `fn site_handler`, `fn build_no_domain_inner`(pub(crate), lib.rs:3170), `fn try_tier1_upnp`, `fn probe_reachability`, `fn map_port`, `impl NatStrategy for DefaultNatStrategy`. Surviving line-pins (broadcast.rs:615, broadcast_helpers.rs:58, context.rs:4052, messaging_helpers.rs:1002, pkarr_client.rs:271/:303, context/mod.rs:122, broadcast_content.rs:298) all spot-checked accurate — commits bumped the stale ones (context.rs 3949→4052, messaging_helpers 999→1002) in the same diff. Also fixed INVALID pseudo-code `HostSiteConfig::defaults(Reach::NatTraversal) { … }` (can't put struct body after a fn call) → accurate prose `HostSiteConfig { reach, tls, dht, … } + host_site_until`.
2. **Two factual fixes:** (a) `fe3eca2fd` corrected §2 addressing-gap that OMITTED `SCPBroadcastContext` — guide now lists BOTH `SCPRelay`(document.rs:203) + `SCPBroadcastContext`(:212) as the closed-set network endpoint types; both carry relay URLs not origin HTTP IP:port; no SCPSite/SCPHttp exists (verified). (b) `Tunnel.public_url` deferral warning-SCOPE precision: guide now says warning fires on `NodeConfig` path only, on `host_site` path field is "silently accepted but unused." VERIFIED: `host_site_until` lowers reach via `lower_host_site_reach_tls(&reach,&tls)` (self_host.rs:914) which matches `Reach::Tunnel{..}`→skip_nat=true WITHOUT reading public_url and WITHOUT calling `warn_tunnel_public_url_deferred`; that warn (config.rs:684) is only called from config.rs:769 in the NodeConfig lowering. Claim is exactly right and a genuine accuracy IMPROVEMENT over prior version (which implied warning on both paths).

**no_domain audit:** only current-tense mention is `fn build_no_domain_inner` (real pub(crate) fn, threads http_bind_addr.port()→select_tier as guide claims — NOT the deleted public `no_domain()` builder method). All other no_domain/ApplicationNodeBuilder hits are inside §6 strikethrough or §7 dated 2026-06-13/14 running-log marked historical by the 2026-06-16 entry.

Example COMPILES + clippy `-D warnings` CLEAN. All cross-links resolve. deploying-guide knob table + 3 recipes + at-a-glance still match API (Reach/TlsMode/DhtMode variants + defaults(Reach) + InvalidConfig caveats all confirmed vs config.rs/self_host.rs).

REUSABLE: a symbol-reference is only an improvement over a line-pin if the symbol EXISTS and is UNIQUE — grep -c each one. A function name containing a deleted-API token (build_no_domain_inner vs deleted no_domain()) is NOT stale; distinguish internal helper names from the deleted public surface before flagging.
