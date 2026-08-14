---
name: p5-hostsiteconfig-docs-review
description: P5 self-host docs review (HostSiteConfig/host_site API, ADR-052) — Round 3 APPROVED, code-accurate, with Reach::Tunnel P1-no-op honesty note
metadata:
  type: project
---

# P5 self-host docs review (HostSiteConfig / host_site, ADR-052)

Round 3 independent review on branch `feat/p5-downstream-updates`. Verdict: APPROVED (no blocking).

Docs reviewed: `crates/scp-node/examples/website.rs`, `crates/scp-node/examples/README.md`, `.docs/guides/deploying-an-scp-website.md`, `.docs/guides/self-hosting-a-website-on-scp.md`.

**Why:** ADR-052 agent-first API tenet — flat named-field config (`HostSiteConfig`), spread idiom via `HostSiteConfig::defaults(Reach)`, enums over bools (`Reach`/`TlsMode`/`DhtMode` replace `skip_nat`/`plaintext`/dht-client bools), no silent security defaults (`DhtMode::Memory` default, `Production` explicit opt-in). The review's job was to verify the docs make valid-variant subsets legible and the spread idiom clear for first-pass LLM authorability.

**How to apply (verified ground truth for future rounds):**
- `host_site` valid `Reach`: `NatTraversal`/`Tunnel`/`Local` only; `Domain` → `HostSiteError::InvalidConfig`. Enforced in `lower_host_site_reach_tls` (`crates/scp-node/src/self_host.rs:914`).
- `host_site` valid `TlsMode`: `SelfSigned`/`Plaintext` only; `Acme`/`Terminated`/`Custom` → `InvalidConfig`. Same fn.
- DHT axis is NOT validated by the lowering — `DhtMode::Memory` valid for every reach (the "reachable but unpublished" case). `Production` is the only disclosing variant and already an opt-in (Memory is `#[default]`).
- Listener binds `0.0.0.0` unconditionally (`self_host.rs:1034`) — so `Reach::Local`+`Memory` is LAN-reachable but never DHT-published; README states this correctly.
- Misuse resistance is RUNTIME (shared enums + `InvalidConfig`), not type-system (no narrower HostSiteReach type). Deliberate: keeps identical shape across bindings per agent-first tenet. Docs compensate by stating valid subset in the knob table.

**Honesty gap worth re-checking if code changes:** `Reach::Tunnel { public_url }` carries `// P1: public_url not yet threaded; builder publishes loopback` (`config.rs:136`). Recipes 2/3 read as if `public_url` is consumed; it isn't yet (recipes still work via `skip_nat=true` + external tunnel/proxy). Flagged as a minor surface-of-truth note, not blocking. If P-something threads `public_url`, this note resolves.

Good patterns observed: error messages name the fix ("Use TlsMode::SelfSigned or TlsMode::Plaintext") — excellent misuse-recovery ergonomics; README orients + defers without duplicating the knob table (correct doc layering); example port 8080 vs config default 8443 divergence is explained inline (collision avoidance).
