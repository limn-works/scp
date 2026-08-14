---
name: wasm-stale-followup-488a445d7
description: ALIGNED review of chore/wasm-stale-followup (ADR-055 WASM-bridge-removal residual scrub) — 1 minor ADR-049 residual
metadata:
  type: project
---

# WASM-stale-followup ADR/comment scrub @ `488a445d7` (2026-06-29) — ALIGNED

Branch `chore/wasm-stale-followup`, 1 commit over origin/main, follow-up to merged PR #1952 (ADR-055 WASM bridge removal). 8 files, banner/comment/file-map edits only.

**Why:** ADR-055 deletes the WASM FFI bridge (browser = remote thin clients to server-side scp-node). Three-bridge world now: PyO3/UniFFI/napi-rs. This PR scrubs residual WASM refs #1952 missed.

**How to apply:** All 5 confirmation points verified true:
1. `crates/scp-ffi/common/src/saga_errors.rs` + lib.rs comment rewrites accurate — module is `#[cfg(feature="resolvers")]`, imports `scp_core::context::supervisor::{SagaAbortReason,SagaError}`, `resolvers` pulls `dep:scp-core` (common/Cargo.toml:14), sits alongside event_log/trust_store/broadcast/export_verify gated identically. 0 WASM refs left in common/src.
2. ADR-050 re-point correct: `ContextExport::canonical_snapshot_hash` EXISTS at export_import.rs:338, computes `SHA-256(CONTEXT_EXPORT_DOMAIN_SEPARATOR || scope.tag_byte() || jcs::to_vec(snapshot))` (sep="SCP-CONTEXT-EXPORT-V1:" @:127). No phantom provenance.
3. Banners mirror ADR-034/047 style; ADR-022 (phase-4:911) + ADR-034 (phase-4:1413) get `Status: Superseded by ADR-055` banners only — bodies NOT rewritten (phase-4 diff = 2 lines).
4. Removed ADR-048 §7b "retained one release cycle" notes (identity_rotate_key/link_attestation/checkpoint) lost nothing live — all WASM-divergence vs deleted bridge; bridge-aliases.json has 0 divergence entries, 0 in-source `SEMANTIC DIVERGENCE: see ADR-048 §7b` comments survive; SCP pre-release.
5. Artifact-flow respected; no scope creep.

**FINDING (minor, doc-precision):** ADR-049:323 + :359 — two PRE-EXISTING present-tense claims that `scp-ffi/wasm` re-implementation path still operates survive. ADR-049 is `Status: Proposed` (active design, not superseded body) and its amendment banner is narrowly scoped to §10 panic-hook + `cargo check -p scp-ffi-wasm` cmd, saying rest is "unchanged" — so these read as still-true. Same class the PR scrubs; outside enumerated touch-set. Fix: re-tense to past OR extend banner to enumerate them (like ADR-046 banner does for mode="wasm"/wasm-pack/@scp-ts-wasm). NOT a blocker.

**Legit-to-keep (verified):** ~12 phase-4 `scp-ffi/wasm` hits (934-1476) all inside Superseded ADR-022/034 bodies or ADR-055's own body — bannered historical record. `cargo check -p scp-protocol --target wasm32` kept (pure sync core, NOT deleted bridge; Cargo.toml exists). scp-ffi/wasm crate confirmed deleted.

GOTCHA: review target = worktree file. Distinguish `Status: Superseded` (full body recast historical) from narrow `Amended by` banner (only enumerated items historical, rest reads current) — Proposed ADRs with narrow amend banners leave un-enumerated present-tense claims reading as live.
