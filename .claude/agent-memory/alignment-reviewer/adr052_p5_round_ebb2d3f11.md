---
name: adr052-p5-round-ebb2d3f11
description: ADR-052 Phase B-P5 review at ebb2d3f11 — parse_dht_mode_or_exit refactor + Tunnel-warn doc-comment; ALIGNED 0 findings
metadata:
  type: project
---

# ADR-052 Phase B-P5 Round @ `ebb2d3f11` (branch `feat/p5-downstream-updates`, 2026-06-17) — ALIGNED, 0 findings

1 commit past `d2bd8d45f`. `git diff --stat d2bd8d45f ebb2d3f11` = main.rs (+26/-27 region) + self_host.rs ONLY. No docs/examples touched this round.

**main.rs — `parse_dht_mode_or_exit()` extraction (pure refactor).** Both former inline `SCP_NODE_DHT_MODE` matches (run_full_node_persistent :468, run_self_host :668) collapsed into one helper (def :527). Behavior byte-for-byte preserved: default `"production"`, `memory`→DhtMode::Memory, `production`→DhtMode::Production, else→tracing::error!+exit(1). Verified: helper uses correct re-export `scp_node::DhtMode::{Memory,Production}` (lib.rs:59 `pub use config::{DhtMode,...}`). Ephemeral path (main.rs:335) deliberately IGNORES the env var (forces in-memory) and is correctly NOT migrated — helper only for the two env-honoring paths. Single helper def confirmed (`grep -c` == 1).

**self_host.rs — doc-comment only (+5/-4).** `lower_host_site_reach_tls` rustdoc Reach bullet updated: split Local/Tunnel, and Tunnel now documents "*and* emits a `tracing::warn!` that `public_url` is not yet threaded." PRECISE match to impl at :945 — the warn is UNCONDITIONAL (no `if !public_url.is_empty()` guard; the d2bd8d45f change held). No conditional qualifier in the doc, matching the unconditional warn.

**Validation:** `cargo clippy -p scp-node --lib --features allow_unencrypted_storage` CLEAN (0 warnings on scp-node). REUSABLE TRAP STILL HOLDS: never bare `clippy -p scp-node --all-targets` (no feature) — integration.rs test-cfg gating fails; always feature-bearing lib clippy.

Working tree note: `git checkout HEAD -- .` after reads leaves only `??` untracked memory files; no tracked source dirtied.
