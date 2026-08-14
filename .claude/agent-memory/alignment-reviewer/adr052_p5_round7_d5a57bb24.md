---
name: adr052-p5-round7-d5a57bb24
description: ADR-052 Phase B-P5 round-7 alignment review at HEAD d5a57bb24 — ApplicationNodeBuilder stale-ref purge from live guide sections + 2 website.rs prose nits; ALIGNED
metadata:
  type: project
---

# ADR-052 Phase B-P5 Round-7 Review (branch `feat/p5-downstream-updates`, HEAD `d5a57bb24`, 2026-06-16) — ALIGNED

4 commits past prior round-3 base (`d5b64fdad`): `71ac11de5` (dht_mode fix), `d5b64fdad` (README trim), `063ec8a22` (website.rs inline-comment trim), `007147e03` (README knob-bullet one-liner), `d5a57bb24` (ApplicationNodeBuilder live-section purge + 2 website.rs prose nits).

**Verdict: ALIGNED. 0 blocking, 0 material. 1 carried-forward informational note.**

## What round-7 did (commit d5a57bb24)
- Purged ALL `ApplicationNodeBuilder` / `no_domain()` / `.identity_with_storage()` / `build()` refs from the **live body** of `self-hosting-a-website-on-scp.md` (§3, §4, §5, §6) → replaced with `host_site` / `HostSiteConfig::defaults(Reach::NatTraversal)` / `host_site_until` terminology.
- Added a §7 running-log entry (line 396) documenting the P3a deletion + preservation of historical entries.
- 2 website.rs prose nits (commit 063ec8a22): removed inline 3-knob comment that duplicated the module doc verbatim; compressed PORT comment to the 8080-vs-8443 rationale.

## Verification performed (all PASS)
- `ApplicationNodeBuilder` FULLY DELETED from source (`grep struct ApplicationNodeBuilder crates/scp-node/src/` = 0; no `fn no_domain`/`fn identity_with_storage` either — only unrelated `no_domain_*` test fns + `no_domain_relay_url` helper remain).
- Example COMPILES clean (`cargo build -p scp-node --example website`).
- All 5 website.rs imports (`DhtMode, HostSiteConfig, Reach, TlsMode, host_site`) confirmed public re-exports: lib.rs:48-52 (`pub use self_host::{...host_site...}`) + lib.rs:58-60 (`pub use config::{DhtMode, ..., Reach, TlsMode}`).
- website.rs struct-literal fields + `defaults(Reach::Local)` match impl exactly (self_host.rs:701 struct, :785 one-arg `defaults`).
- `0.0.0.0` bind claim (website.rs doc-comment lines 10-11) matches `DEFAULT_HTTP_BIND_ADDR = 0.0.0.0:8443` (lib.rs:66-79, "binds to all network interfaces").
- deploying-an-scp-website.md knob-table validation caveats (only 3 Reach variants valid; only SelfSigned/Plaintext valid; Acme/Terminated/Custom + Reach::Domain → InvalidConfig; DHT axis never validated) match `lower_host_site_reach_tls` exactly (self_host.rs:914-958).
- `run_self_host` (main.rs:650) confirmed to construct `HostSiteConfig` from `defaults(...)` + enum lowering — NO ApplicationNodeBuilder. Guide §7 line-396 claim accurate.
- All README + guide relative links resolve (`../../../.docs/guides/*`, `../../crates/scp-node/examples/website.rs`, `./website-site/`).
- Full stale-shape sweep (`HostSiteOptions`/`skip_nat:`/`plaintext:`/`dht_mode`/`.plaintext`/`.skip_nat`/`no_domain()`/`ApplicationNodeBuilder`) across all 4 files: the ONLY hits are in `self-hosting` §3-gap-#2 strikethrough (lines 189-190, struck-through "was X / **Fixed**" honest record) and §7 running-log (lines 377, 379 — 2026-06-14 historical entry, plain prose). All live-section non-historical positions are clean.

## Carried-forward informational note (not blocking, NOT introduced by this PR)
- `Reach::Tunnel { public_url }` P1-deferral: config.rs:136 `// P1: public_url not yet threaded; builder publishes loopback`. Recipes 2 & 3 (deploying-an-scp-website.md) pass a `public_url` that is ignored at runtime, but the recipes stay operationally correct because the operator forwards the tunnel/proxy → loopback regardless. No action required this round.

## Notes on framing
- §7 "Running log" entries at lines 377/379 carry plain-prose `no_domain()`/`ApplicationNodeBuilder::identity_with_storage()` — these are CORRECTLY preserved historical record (explicitly stated by the line-396 entry). Updating them would falsify the chronological log. Do NOT flag as stale.
- Line 396 cites "PR #1815" — issue/PR number in a `.docs/` guide. `feedback_no_issue_refs_in_code` applies to SOURCE code/comments/tests, NOT docs guides (which cite PRs/ADRs/specs as provenance throughout). Not a violation.

## REUSABLE
- When purging a deleted-API name from a doc that has a chronological running-log section, distinguish LIVE body (must update) from HISTORICAL log (must preserve). A grep hit in the log is correct, not a finding — verify the section header (`awk 'NR<=N && /^## /{h=$0} END{print h}'`).
- Strikethrough `~~old~~ **Fixed:** new` is the honest pattern for "was X, now Y" gap records — the struck text legitimately still names the old API.
