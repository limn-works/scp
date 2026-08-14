---
name: project-adr051-construction-pattern
description: PR #1805 ADR-051 unified construction pattern — supersedes ADR-032 §AC-6 typestate builder with flat config objects; provenance review found one false-attribution claim
metadata:
  type: project
---

PR #1805 (branch `docs/adr-051-construction-pattern`, docs-only, Phase A artifacts) adds ADR-051 "Unified Construction Pattern": replaces the `ApplicationNodeBuilder` typestate builder with flat `NodeConfig` config objects + `Node::start(config)` across all 5 SDKs. Supersedes ONLY ADR-032 §AC-6 (item 6 of ADR-032's Acceptance Criteria — verified, the AC numbering is correct: list item 6 = AC-6). Rest of ADR-032 stands.

Artifacts in the set: ADR-051 (phase-2.md), construction.md standard (M1–M5 rules), sdk-common.md Context Creation rewrite, architecture.md §3 agent-first criterion, CLAUDE.md "Agent-first API design" builder tenet, lesson llm-first-config-objects-over-typestate.md.

**Why:** SDK's primary author is an LLM; typestate phantom-ordering causes compile-retry loops and doesn't translate to 4/5 languages. Enforcement (check-construction-pattern.py per AC-9) is Phase B-P4, correctly NOT present in this docs-only PR.

**How to apply / KNOWN DEFECT found in review:** ADR-051 claims (twice — Context §"ADR-032 §AC-6 mandated..." para, and Rationale point invoking continuation) that "ADR-032 itself already rejected typestate-for-its-own-sake (see its Rejected Alternatives)". FALSE: ADR-032 (phase-2.md lines 1009–1094) has NO Rejected Alternatives section of its own — the Rejected Alternatives at line 1142 belongs to ADR-035. ADR-032 never mentions typestate/builders being rejected; it mandated the builder in AC-6. This is phantom provenance — a fabricated supporting citation. If revisiting, the supersession is still sound on its own merits; just drop the false "continuation of ADR-032's direction" framing.

Secondary nit: construction.md and the ADR-051 supersession note describe `host_site(dir)` taking a dir, but the real signature is `host_site(opts: HostSiteOptions)` (crates/scp-node/src/self_host.rs:853). Cosmetic — the standard's intent (host_site survives as fail-safe sugar delegating to SiteConfig) is correct.

All other cited targets verified to resolve: EncryptedStorage sealed trait (scp-platform/src/encrypted.rs:35), StorageConfig enum across 3 FFI bridges, ApplicationNodeBuilder+PhantomData (scp-node/src/lib.rs), RelayConfig.supports_bridge (scp-transport/src/native/server.rs), ADR-035/042/048/049, architecture.md §2.5, per-sdk-idiom lesson, sdk-common §"Context Creation".
