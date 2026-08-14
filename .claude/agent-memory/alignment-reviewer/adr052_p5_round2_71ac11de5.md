---
name: adr052-p5-round2-71ac11de5
description: ADR-052 P5 HostSiteOptions→HostSiteConfig doc/example migration round-2 review at HEAD 71ac11de5 — ALIGNED, clean
metadata:
  type: project
---

# ADR-052 Phase B-P5 round-2 review (branch `feat/p5-downstream-updates`, HEAD `71ac11de5`, 2026-06-16) — ALIGNED

Related: [[adr052_p5_hostsiteconfig_downstream]] (round-1 at `a4d38862d`).

HEAD `71ac11de5` is ONE commit past round-1's `a4d38862d`; its message is "fix stale dht_mode field name + document valid TlsMode/Reach subset (ADR-052 P5 review)" — i.e. the round-1 required fix (the `dht_mode:` prose leak in `deploying-an-scp-website.md`) plus the TlsMode/Reach validity documentation were addressed in this commit.

**Scope:** 4 docs/example files — `crates/scp-node/examples/website.rs`, `crates/scp-node/examples/README.md`, `.docs/guides/deploying-an-scp-website.md`, `.docs/guides/self-hosting-a-website-on-scp.md`.

**Verified clean against ground truth:**
- Grep across all 4 files for `HostSiteOptions|skip_nat|dht_mode|plaintext:|.plaintext` → ZERO matches (exit 1). Old-API surface fully gone.
- Struct/signature parity: `HostSiteConfig` at `self_host.rs:701-761`; `defaults(reach: Reach)` ONE-arg at `:785`; `Reach`/`TlsMode`/`DhtMode` enums at `config.rs:120/165/210` (DhtMode promoted to config.rs, shared by Node+Site). Example spread idiom `..HostSiteConfig::defaults(Reach::Local)` matches doc-comment example verbatim.
- TLS/Reach validity prose matches `lower_host_site_reach_tls` (`self_host.rs:914-958`): `Acme`/`Terminated`/`Custom` each return `InvalidConfig` (`:918-941`); `Reach::Domain` returns `InvalidConfig` (`:947-954`); only `SelfSigned`+`Plaintext` and `NatTraversal`/`Local`/`Tunnel` accepted. Both guides state this correctly.
- M2 fail-safe framing accurate: `DhtMode::Memory` valid for EVERY Reach incl. `NatTraversal` (reachable-but-unpublished), never an error — matches `:905-913` lowering doc + construction.md M2. Deploying-guide "At a glance" table + trade-offs teach this correctly; no false "publishing reach + Memory ⇒ error" rule anywhere.
- `Reach::Tunnel { public_url }` P1 deferral confirmed unchanged (`config.rs:136` "public_url not yet threaded; builder publishes loopback"). Recipes 2/3 supply public_url but remain operationally correct (tunnel/proxy provides reachability, forwards to localhost:8443); guide does not claim node consumes the field. Honest as-built, not phantom provenance.

**Verdict ALIGNED, 0 required, 0 material.** This is the clean follow-up to round-1's single required fix.

REUSABLE: round-1's required fix here was a snake-case FIELD name (`dht_mode:`) leaking in a trade-off PARAGRAPH — the compiler catches struct-literal `HostSiteOptions` but NOT prose field names. Always grep every old identifier shape including snake_case field names in prose when reviewing API-rename downstream doc migrations.
