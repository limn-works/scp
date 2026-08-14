---
name: adr052-p5-hostsiteconfig-downstream
description: ADR-052 P5 host_site downstream migration — at HEAD fe3eca2fd the SHIPPED shape is HostSiteConfig (Reach/TlsMode/DhtMode enums + defaults(reach) spread), APPROVED; supersedes an earlier revision that wrongly recorded HostSiteOptions bools
metadata:
  type: project
---

# ADR-052 Phase B-P5 — host_site downstream docs/example (branch feat/p5-downstream-updates)

## Current state at HEAD fe3eca2fd (verified 2026-06-17 via `git show HEAD:<path>`)

The shipped config object is **`HostSiteConfig`** — flat struct with required enum
`reach: Reach`, plus `tls: TlsMode` / `dht: DhtMode`, **no whole-struct `Default`**
(`reach` is irreducibly required), and a `HostSiteConfig::defaults(reach: Reach) -> Self`
spread-idiom constructor. `Reach` (config.rs:120) and `TlsMode` (config.rs:165) and
`DhtMode` (config.rs:210) all exist. `host_site(HostSiteConfig)` /
`host_site_until(HostSiteConfig, shutdown)` are the entry points; the `--self-host`
binary builds `HostSiteConfig { reach, tls, dht, … }` in `main.rs::run_self_host` and
calls `host_site_until`. The legacy `ApplicationNodeBuilder`/`.no_domain()` was deleted
in P3a (PR #1815). VERDICT: APPROVED (docs + example migration; no public API defined or
changed in the diff).

### CAUTION — this file previously recorded the OPPOSITE and was WRONG
An earlier revision claimed HEAD shipped `HostSiteOptions` (bool `plaintext`/`skip_nat`,
whole-struct `Default`, no `Reach`/`TlsMode`) and that `self_host_banner` over-warned
unconditionally. That was a STALE read (the index even flagged "Read tool served STALE
self_host.rs"). Re-verified against `git show HEAD:` at the SAME commit fe3eca2fd: the
enum/HostSiteConfig form is what's on disk, and `self_host_banner(port, plaintext,
publishes_dht)` DOES branch its DHT line on `publishes_dht` (main.rs:570). The old
banner-over-warns finding is RESOLVED/moot. Trust the live tree, not this paragraph's
predecessor.

## API assessment (HostSiteConfig, current)
- Fail-safe defaults preserved: `defaults(reach)` sets `tls=SelfSigned`, `dht=Memory`
  (no publish); `DhtMode::Production` (IP<->DID location disclosure) is deliberate opt-in.
- Fail-loud narrowing: `lower_host_site_reach_tls` rejects `Reach::Domain` and
  `TlsMode::Acme/Terminated/Custom` with `HostSiteError::InvalidConfig` — never a silent
  no-op. DHT axis is never an error (Memory valid for every reach).
- Library prints nothing; caller prints via `on_ready: Option<Box<dyn FnOnce(HostSiteReady)>>`.
  Example website.rs uses `ready.plaintext` to pick http/https scheme. Compiles.
- Migration complete: no residual `HostSiteOptions`/`skip_nat`/`dht_mode:` in scope files.

## Latent gap (pre-existing, NOT in this diff — future round)
`Reach::Tunnel.public_url` is silently discarded on the `host_site` path
(`lower_host_site_reach_tls` matches `Reach::Tunnel { .. }` and drops it) while the
`NodeConfig` path calls `warn_tunnel_public_url_deferred` (config.rs:684). Same field,
accept-but-warn on one entry point, accept-but-silent on the other. Deploying-guide
Recipe 2/3 tell readers to pass a real public_url that host_site throws away with no
signal. Docs disclose the asymmetry honestly (knob table) — right interim mitigation;
durable fix is to thread public_url or emit the same warning on the host_site path.
Don't re-flag as blocking on a docs/example diff. See [[p5_hostsiteconfig_docs_review]]
and [[hostsiteconfig_legal_subset_p5]].

## Reusable review lesson
When a config object's shape is under active churn, the on-disk HEAD is authoritative —
re-derive it via `git show HEAD:<path>` (the Read tool has served stale copies of
self_host.rs on this branch). Do not trust a prior round's memory naming the struct/enums;
grep for the type AND every field-name shape before grounding a verdict.
