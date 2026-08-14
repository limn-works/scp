---
name: adr052-hostsiteconfig-review
description: ADR-052 host_site construction-pattern API review (HostSiteConfig migration from HostSiteOptions)
metadata:
  type: project
---

ADR-052 Phase B migrates `scp_node::host_site` from loose `HostSiteOptions` (plaintext/skip_nat/dht_mode) to `HostSiteConfig` mirroring `NodeConfig`: M1 enums (Reach/TlsMode/DhtMode in `crates/scp-node/src/config.rs`), M4 `defaults(reach)` constructor (no whole-struct Default — `reach` is the irreducible required field), fail-loud `HostSiteError::InvalidConfig` for inapplicable enum variants. `host_site_until` lowers enums to internal `(plaintext, skip_nat)` bools via `lower_host_site_reach_tls`.

**Why:** construction-pattern standardization (`.docs/standards/construction.md`); the two surfaces (Node + hosted-site) share one enum vocabulary.

**How to apply:** When reviewing this area, check cross-surface CONSISTENCY between `HostSiteConfig` (self_host.rs) and `NodeConfig` (config.rs) — they share Reach/TlsMode/DhtMode and should treat identical input identically.

Findings in P5 review (branch feat/p5-downstream-updates @1619d8733):
- BLOCKING: `Reach::Tunnel { public_url }` — NodeConfig path emits `warn_tunnel_public_url_deferred` (config.rs ~684/768); host_site path's `lower_host_site_reach_tls` silently discards public_url. Same enum, divergent feedback. Docs admit the gap. Fix: emit same warning from host_site path.
- OBSERVATION: `HostSiteReady.plaintext: bool` is stale vocab — input side now uses TlsMode enum, output DTO still a bool; example on_ready branches on `ready.plaintext`. Bool can't represent future TLS variants.
- Good: defaults(reach)+spread idiom, InvalidConfig with actionable messages naming valid alternatives, justified `HostSiteConfig` (not bare `SiteConfig` — name taken by FFI virtual-host type).

GOTCHA: prompt claimed working-tree HEAD was the review branch but it was NOT — tree was on a different branch with the OLD API. Always verify `git rev-parse HEAD` and `git branch --show-current` against the prompt's claimed ref; read files via explicit `git show <ref>:<path>` when they diverge. The harness's "git show HEAD:" also returned inconsistent content here — pin the explicit commit hash, not HEAD.
