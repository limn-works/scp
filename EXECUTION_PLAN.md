# Production Readiness Execution Plan

64 open issues. This plan sequences them to minimize merge conflicts,
maximize parallelism, and respect hard dependency ordering.

**Notation:**
- `→` = must complete before (hard dependency)
- `||` = can run in parallel (no file overlap)
- `BRANCH: name` = issues sharing a git branch
- `BASE: X` = branch starts from the merge of X into main

---

## Phase 1: Surgical Fixes (leaf changes, max parallelism)

All branches start from `main`. No inter-branch dependencies.
7 parallel lanes touching disjoint files.

### Lane A — `fix/wire-format-transport`
**Issues:** #345, #313
**Crate:** `scp-transport`
**Files:** `src/native/protocol.rs` (#345), `src/config.rs` (#313)
**Conflict risk:** None (different files)

| # | Title | Files | Size |
|---|-------|-------|------|
| #345 | Wire format field name renames (`ref_id`→`ref`, `event_type`→`type`) | protocol.rs | S |
| #313 | Dedup cache TTL 1hr→24hr | config.rs | XS |

### Lane B — `fix/sender-key-wire-format`
**Issues:** #312, #346
**Crate:** `scp-core`
**Files:** `src/crypto/sender_keys/key_protocol.rs` (both)
**Conflict risk:** HIGH between these two — same file, must share branch

| # | Title | Files | Size |
|---|-------|-------|------|
| #312 | HPKE domain separator: `hpke-v1`→`v1` | key_protocol.rs:47 | XS |
| #346 | 4 wire format fixes: JSON→msgpack, add signing_key_id, nonce serde_bytes, future timestamp | key_protocol.rs:116,156,231,675 | M |

### Lane C — `fix/envelope-types`
**Issues:** #351, #290
**Crate:** `scp-core`
**Files:** `src/envelope/inner.rs` (both)
**Conflict risk:** MEDIUM — same file, but different sections. Share branch.

| # | Title | Files | Size |
|---|-------|-------|------|
| #351 | `deny_unknown_fields` on InnerEnvelope | inner.rs:77 | XS |
| #290 | Bind MessageType::Signaling into envelope + canonical hash | inner.rs:37-51, inner.rs:381 | M |

### Lane D — `fix/store-serialization`
**Issues:** #348
**Crate:** `scp-core`
**Files:** `src/store/mod.rs`
**Conflict risk:** None

| # | Title | Files | Size |
|---|-------|-------|------|
| #348 | ProtocolStore positional→named MessagePack | store/mod.rs:204,292 | XS |

### Lane E — `fix/broadcast-bugs`
**Issues:** #353, #352
**Crate:** `scp-core`
**Files:** `src/context/broadcast.rs` (both), `src/crypto/sender_keys/broadcast.rs` (#352)
**Conflict risk:** MEDIUM — #353 touches broadcast.rs methods, #352 adds fields to BroadcastEnvelope. Share branch, do #353 first (smaller).

| # | Title | Files | Size |
|---|-------|-------|------|
| #353 | block_subscriber: per-author not context-wide | context/broadcast.rs:513 | S |
| #352 | BroadcastEnvelope: add 5 missing spec fields | crypto/sender_keys/broadcast.rs, context/broadcast.rs | M |

### Lane F — `fix/misc-standalone`
**Issues:** #354, #355, #291, #350
**Crate:** multiple (all disjoint)
**Files:** all different crates/files
**Conflict risk:** None between these. Can share branch for convenience or split.

| # | Title | Files | Size |
|---|-------|-------|------|
| #354 | RotateContentKeys + duplicate RemoveMember conflict detection | sync/conflict_resolution.rs | S |
| #355 | Projection UCAN re-parse caching | scp-node/src/projection.rs | S |
| #291 | Stub policy: add SCP-NNN story IDs to 4 locations | 4 separate files | XS |
| #350 | ContextParams: wire full RoleDefinition + ToolRegistration | context/params.rs, roles.rs, templates.rs, tools/lifecycle.rs | M |

### Lane G — `fix/node-dev-api`
**Issues:** #301
**Crate:** `scp-node`
**Files:** `src/dev_api.rs`, `src/http.rs`
**Conflict risk:** None

| # | Title | Files | Size |
|---|-------|-------|------|
| #301 | Dev API: wire real metrics instead of hardcoded zeros | dev_api.rs, http.rs | M |

**Phase 1 summary:** 7 parallel branches, 14 issues, all from `main`.
Estimated: ~1 session per lane. All lanes independent.

```
main ─┬─ Lane A (#345, #313) ─────────── PR → main
      ├─ Lane B (#312, #346) ─────────── PR → main
      ├─ Lane C (#351, #290) ─────────── PR → main
      ├─ Lane D (#348) ──────────────── PR → main
      ├─ Lane E (#353, #352) ─────────── PR → main
      ├─ Lane F (#354, #355, #291, #350) PR → main
      └─ Lane G (#301) ──────────────── PR → main
```

---

## Phase 2: Governance Cleanup

**BASE:** `main` after Phase 1 merges (specifically needs Lane F for #350).
All governance issues touch `scp-core/src/context/governance/` and/or
`src/context/manager.rs`. High conflict risk — serialize within a single
branch chain.

### Branch: `fix/governance-types`
**Issues:** #349 → #359 → #358 → #357 → #360
**BASE:** `main` (post-Phase-1)

Ordering rationale:
- #349 changes `f64`→`u32` in majority.rs + mod.rs (type change, pervasive)
- #359 does the same for retention multipliers (same pattern, same area)
- #358 changes `HashSet<String>`→`HashSet<DID>` in manager.rs
- #357 adds vote signature verification in manager.rs (reads existing types)
- #360 adds capacity bounds in manager.rs (reads existing collection types)

| Order | # | Title | Files | Size |
|-------|---|-------|-------|------|
| 1 | #349 | min_participation f64→u32 basis points | governance/majority.rs, mod.rs | S |
| 2 | #359 | Retention multipliers f64→u32 basis points | governance/mod.rs | S |
| 3 | #358 | write_revoked_members String→DID | manager.rs | S |
| 4 | #357 | PromoteContext: verify vote signatures | manager.rs | M |
| 5 | #360 | Upper bounds on governance collections | manager.rs | S |

### Branch: `feat/governance-actions`
**Issues:** #320
**BASE:** `fix/governance-types` merged (or branched off its HEAD)

| # | Title | Files | Size |
|---|-------|-------|------|
| #320 | Implement 13 missing GovernanceAction variants + deprecate BlockAuthor | governance/mod.rs, manager.rs, all engines | L |

**Why separate:** #320 is large (adds 13 enum variants, match arms in every engine,
new methods in manager). Everything that touches governance types should land first
to minimize rebase pain.

```
main (post-P1) ── fix/governance-types (#349→#359→#358→#357→#360)
                          └── feat/governance-actions (#320)
                                    └── PR → main
```

---

## Phase 3: Security Hardening

**BASE:** `main` after Phase 1 (needs Lanes A+B for clean file state).
3 parallel lanes.

### Lane A — `fix/deser-limits`
**Issues:** #347
**BASE:** `main` post-Phase-1 (needs #345, #346 merged — touches same files)
**Files:** protocol.rs, server.rs, key_protocol.rs, inner.rs, outer.rs, broadcast.rs

| # | Title | Files | Size |
|---|-------|-------|------|
| #347 | Add deserialization size limits across all wire types | 6 files across scp-transport + scp-core | M |

**Why after Phase 1:** #347 touches `protocol.rs` (same as #345), `key_protocol.rs`
(same as #312, #346), and `inner.rs` (same as #351). Must merge those first.

### Lane B — `fix/ucan-security`
**Issues:** #299, #319, #326
**BASE:** `main` (no file overlap with Phase 1)
**Files:** `context/roles.rs`, `scp-ffi/src/mcp_bridge.rs`, `scp-ffi/uniffi/src/bridge.rs`

| # | Title | Files | Size |
|---|-------|-------|------|
| #299 | Sign UCAN tokens in broadcast role assignment | context/roles.rs, crypto/ucan/mint.rs | M |
| #319 | Validate UCAN at tool invocation boundary | scp-ffi/src/mcp_bridge.rs | M |
| #326 | UniFFI UCAN: use persistent keys, not ephemeral | scp-ffi/uniffi/src/bridge.rs | S |

### Lane C — `fix/governance-enforcement`
**Issues:** #339, #340
**BASE:** `main` post-Phase-2 (touches manager.rs, must wait for governance cleanup)
**Files:** `runtime.rs`, `manager.rs`, `params.rs`

| # | Title | Files | Size |
|---|-------|-------|------|
| #339 | Enforce capability ceiling on every operation | scp-ffi/src/runtime.rs, context/manager.rs | M |
| #340 | Enforce promotion policy (no_promotion/promotable) | context/manager.rs, params.rs | S |

### Lane D — `fix/timestamp-validation`
**Issues:** #321
**BASE:** `main` post-Phase-1 Lane C (#290 touches envelope)
**Files:** `envelope/inner.rs`, `envelope/mod.rs`

| # | Title | Files | Size |
|---|-------|-------|------|
| #321 | Wire timestamp monotonicity + bounds into message pipeline | envelope/ | M |

```
main (post-P1) ─┬─ Lane A (#347) ──────────────── PR → main
                 ├─ Lane B (#299, #319, #326) ──── PR → main
                 └─ Lane D (#321) ──────────────── PR → main

main (post-P2) ─── Lane C (#339, #340) ─────────── PR → main
```

---

## Phase 4: Identity Infrastructure

**BASE:** `main` (identity crate is mostly independent of core changes).
Can run in parallel with Phases 2-3.

### Lane A — `fix/identity-persistence`
**Issues:** #327 → #310 → #311
**Crate:** `scp-identity`
**Ordering:** #327 (sequence counter) is a prerequisite for #310 (DhtClient
needs sequence persistence), and #311 (connecting resolvers) depends on
both being functional.

| Order | # | Title | Files | Size |
|-------|---|-------|-------|------|
| 1 | #327 | DID sequence counter persistence | scp-identity/src/dht.rs | S |
| 2 | #310 | Production DhtClient (pkarr-based) | scp-identity/src/dht_client.rs | L |
| 3 | #311 | Connect three DID resolution systems | scp-identity/src/resolver.rs, scp-core/src/trust/attestation.rs | M |

### Lane B — `fix/identity-features`
**Issues:** #315, #325
**Crate:** `scp-core` (key_continuity module)
**No dependency on Lane A.**

| # | Title | Files | Size |
|---|-------|-------|------|
| #315 | BIP-39 mnemonic display in fingerprints | crypto/key_continuity/ | S |
| #325 | TOFU key tracking + certificate pinning | crypto/key_continuity/, scp-transport | M |

```
main ─┬─ Lane A (#327→#310→#311) ── PR → main
      └─ Lane B (#315, #325) ─────── PR → main
```

---

## Phase 5: Core Infrastructure (CRITICAL PATH — sequential)

This is the critical path. Each step depends on the previous.

**BASE:** `main` after Phases 1-3 merged (especially #345, #346, #351 for clean wire types).

### Step 1: `feat/production-providers`
**Issues:** #300
**Creates:** production implementations of ContextCryptoProvider,
ContextTransportProvider, ContextEventLogProvider
**This is the #1 prerequisite for everything downstream.**

| # | Title | Files | Size |
|---|-------|-------|------|
| #300 | Production provider implementations | scp-core/src/context/builder.rs (trait is here), new files in scp-transport or scp-core | L |

### Step 2: `refactor/ffi-context-manager`
**Issues:** #356
**BASE:** Step 1 merged (needs production providers to wire)
**Resolves downstream:** #328, #332 (verify these close after #356 lands)

| # | Title | Files | Size |
|---|-------|-------|------|
| #356 | Wire all 4 FFI bridges through ContextManager | scp-ffi/{src,uniffi,napi,wasm}/runtime.rs, context.rs | XL |

### Step 3: `feat/envelope-pipeline`
**Issues:** #338
**BASE:** Step 2 merged (needs transport provider from ContextManager)

| # | Title | Files | Size |
|---|-------|-------|------|
| #338 | Complete Inner→SenderKey→MLS→Outer→Transport pipeline | envelope/, crypto/, transport/ | L |

### Step 4: Verify closures
After Step 2 merges, verify and close:
- #328 (py_context_send now routes through ContextManager)
- #332 (py_context_receive now fed by transport provider)
- #329 (ProtocolStore now wired via ContextPersistence)

```
main (post-P1/P2/P3) ── #300 ── #356 ── #338
                              (verify: #328, #332, #329 close)
```

---

## Phase 6: MLS & Encryption (depends on Phase 5)

### Branch: `feat/mls-integration`
**Issues:** #333 → #324 → #314
**BASE:** Phase 5 Step 2 merged (#356 — needs ContextCryptoProvider wired)

| Order | # | Title | Size |
|-------|---|-------|------|
| 1 | #333 | MLS integration: OpenMLS group management | XL |
| 2 | #324 | Fix max_past_epochs=0 vs sender key grace window | S |
| 3 | #314 | MLS LeafNode scp_wrapping_key extension | M |

### Branch: `feat/content-access-control`
**Issues:** #309 → #317
**BASE:** `feat/mls-integration` merged (needs MLS for key wrapping)

| Order | # | Title | Size |
|-------|---|-------|------|
| 1 | #309 | ADR-038 content access control: AccessKey, WrappedCek, AES-256-KW | XL |
| 2 | #317 | SDK-mandated state destruction (Layer 2 blocking) | M |

```
#356 merged ── feat/mls-integration (#333→#324→#314)
                       └── feat/content-access-control (#309→#317)
```

---

## Phase 7: Feature Completions (parallelizable, depend on Phase 5)

All lanes depend on Phase 5 (#356 merged) but are independent of each other.

### Lane A — `feat/broadcast-completeness`
**Issues:** #335
**BASE:** Phase 5 merged + Phase 1 Lane E (#352, #353)
**Files:** `crypto/sender_keys/`, `scp-transport/`

| # | Title | Size |
|---|-------|------|
| #335 | Broadcast sender key distribution transport path | M |

### Lane B — `feat/context-features`
**Issues:** #336, #337, #334
**BASE:** Phase 5 merged (discovery needs transport, ephemeral needs ContextManager)
**#334 also depends on Phase 2 (#320 — governance actions)**

| # | Title | Depends on | Size |
|---|-------|------------|------|
| #336 | Relay-based + DHT-based context discovery | #356 | M |
| #337 | Ephemeral context: ciphertext deletion + key destruction | #356 | M |
| #334 | Economic governance: spending UCANs + budget | #320 | M |

### Lane C — `feat/trust-provenance`
**Issues:** #318, #330
**BASE:** Phase 5 merged (trust engine needs production callers wired)

| # | Title | Size |
|---|-------|------|
| #318 | Wire trust engine into production callers | M |
| #330 | Envelope provenance: Merkle proof + chain | M |

### Lane D — `feat/identity-advanced`
**Issues:** #316, #323
**BASE:** Phase 4 merged + Phase 5 merged

| # | Title | Size |
|---|-------|------|
| #316 | Compromise recovery protocol (6-step) | L |
| #323 | Platform key custody (Secure Enclave, Keystore, TPM) | L |

### Lane E — `fix/node-production`
**Issues:** #302, #305, #342
**BASE:** Phase 4 Lane A (#310 — needs production DhtClient) + Phase 5 (#300 — needs production providers)

| # | Title | Size |
|---|-------|------|
| #302 | scp-node: use production providers instead of InMemory | M |
| #305 | ACME HTTP-01 TLS: mount router + fix 3 defects | M |
| #342 | scp-relay: use persistent blob storage backend | S |

```
Phase 5 merged ─┬─ Lane A (#335) ──────────────── PR → main
                 ├─ Lane B (#336, #337) ─────────── PR → main
                 ├─ Lane C (#318, #330) ─────────── PR → main
                 ├─ Lane D (#316, #323) ─────────── PR → main
                 └─ Lane E (#302, #305, #342) ──── PR → main

Phase 2 (#320) merged ── Lane B continued (#334) ─ PR → main
```

---

## Phase 8: SDK Bindings (depends on Phase 5)

All SDK binding work depends on Phase 5 (#356 — FFI→ContextManager rewiring).
Lanes are independent by language/bridge.

### Lane A — `feat/wasm-bridge`
**Issues:** #306, #341
**BASE:** Phase 5 merged

| # | Title | Size |
|---|-------|------|
| #306 | WASM bridge: implement tool, event log, UCAN, context stubs | L |
| #341 | TypeScript SDK: add runtime implementation backed by WASM | L |

### Lane B — `feat/uniffi-napi-bridge`
**Issues:** #307, #326 (if not done in Phase 3), #331, #322
**BASE:** Phase 5 merged

| # | Title | Size |
|---|-------|------|
| #307 | UniFFI + NAPI: implement tool ops, context_send, transport | L |
| #331 | Swift SDK: export Trust + MCP from UniFFI bridge | M |
| #322 | Cross-context tool interfaces via FFI | M |

### Lane C — `feat/sdk-scaffolding`
**Issues:** #304
**BASE:** Phase 5 merged (for implementation patterns)

| # | Title | Size |
|---|-------|------|
| #304 | Go, Java, C# bindings: initial implementation | XL |

```
Phase 5 merged ─┬─ Lane A (#306, #341) ──── PR → main
                 ├─ Lane B (#307, #331, #322) PR → main
                 └─ Lane C (#304) ─────────── PR → main
```

---

## Phase 9: Low Priority / Polish

No blocking dependencies. Can start anytime after Phase 1.

### `fix/artifact-health`
**Issues:** #344
**Docs only. No code conflicts.**

| # | Title | Size |
|---|-------|------|
| #344 | Artifact health: fix 11 findings in .docs/ | M |

### `feat/tier2-adapters`
**Issues:** #343
**BASE:** `main` (transport crate, new files only)

| # | Title | Size |
|---|-------|------|
| #343 | Tier 2 transport adapters (0 of 12 implemented) | XL |

### `feat/gated-broadcast-auth`
**Issues:** #266
**BASE:** Phase 7 Lane A (#335 — broadcast transport needed)

| # | Title | Size |
|---|-------|------|
| #266 | Gated-broadcast projection authentication | M |

### `feat/event-log-query`
**Issues:** #303
**BASE:** Phase 5 merged (#356 — needs ContextManager wiring)

| # | Title | Size |
|---|-------|------|
| #303 | Event log query: return stored events, not just Merkle summary | M |

---

## Dependency Graph (critical path highlighted)

```
PHASE 1 (parallel) ──────────────────────────────────────────────────────
  Lane A: #345, #313          ─┐
  Lane B: #312, #346          ─┤
  Lane C: #351, #290          ─┤
  Lane D: #348                ─┤── all merge to main
  Lane E: #353, #352          ─┤
  Lane F: #354, #355, #291, #350 ┤
  Lane G: #301                ─┘

PHASE 2 (serial, from main) ─────────────────────────────────────────────
  #349 → #359 → #358 → #357 → #360 → [#320]

PHASE 3 (parallel, after P1) ────────────────────────────────────────────
  Lane A: #347         (needs P1 Lanes A+B+C merged)
  Lane B: #299, #319, #326
  Lane C: #339, #340   (needs P2 merged)
  Lane D: #321         (needs P1 Lane C merged)

PHASE 4 (parallel with P2/P3) ──────────────────────────────────────────
  Lane A: #327 → #310 → #311
  Lane B: #315, #325

═══════════════════ CRITICAL PATH ═══════════════════════════════════════
PHASE 5 (sequential) ───────────────────────────────────────────────────
  ★ #300 → #356 → #338
    (closes #328, #332, #329 after #356)

PHASE 6 (sequential, after P5) ─────────────────────────────────────────
  ★ #333 → #324 → #314 → #309 → #317
═══════════════════════════════════════════════════════════════════════════

PHASE 7 (parallel, after P5) ───────────────────────────────────────────
  Lane A: #335
  Lane B: #336, #337, #334 (also needs P2 #320)
  Lane C: #318, #330
  Lane D: #316, #323
  Lane E: #302, #305, #342 (also needs P4 #310)

PHASE 8 (parallel, after P5) ───────────────────────────────────────────
  Lane A: #306, #341
  Lane B: #307, #331, #322
  Lane C: #304

PHASE 9 (anytime) ──────────────────────────────────────────────────────
  #344, #343, #266, #303
```

---

## Parallelism Summary

| Phase | Max concurrent branches | Estimated sessions |
|-------|------------------------|--------------------|
| 1 | 7 | 1-2 (all small) |
| 2 | 1 (serial) | 2 |
| 3 | 4 | 1-2 |
| 4 | 2 || with P2/P3 | 2 |
| 5 | 1 (CRITICAL PATH) | 3-4 |
| 6 | 1 (serial chain) | 3-4 |
| 7 | 5 | 2-3 |
| 8 | 3 | 3-4 |
| 9 | 4 | 1-2 |

**Critical path length:** P1 → P5 (#300 → #356 → #338) → P6 (#333 → #309)

Everything else can parallelize around the critical path. Phases 2, 3, 4
can all run concurrently with each other. Phases 7, 8 can all run
concurrently with Phase 6.

---

## Merge Conflict Hot Spots

These files are touched by multiple issues across phases. Sequence carefully.

| File | Issues | Conflict mitigation |
|------|--------|---------------------|
| `context/manager.rs` | #350, #357, #358, #360, #320, #339, #340, #356 | P1(#350) → P2(#357,#358,#360) → P2(#320) → P3(#339,#340) → P5(#356) |
| `key_protocol.rs` | #312, #346, #314, #347 | P1(#312,#346) → P3(#347) → P6(#314) |
| `envelope/inner.rs` | #351, #290, #347, #321 | P1(#351,#290) → P3(#347,#321) |
| `governance/mod.rs` | #349, #359, #320 | P2(#349,#359) → P2(#320) |
| `protocol.rs` | #345, #347 | P1(#345) → P3(#347) |
| `context/broadcast.rs` | #353, #352, #335 | P1(#353,#352) → P7(#335) |
| `scp-ffi/src/context.rs` | #328, #332, #336, #356 | P5(#356) resolves #328,#332; P7(#336) after |
| `scp-ffi/src/runtime.rs` | #339, #303, #356 | P5(#356) first, then P3(#339), then P9(#303) |

---

## Issues Resolved Without Dedicated Work

These close as side-effects of other issues:

| Issue | Resolved by | Reason |
|-------|-------------|--------|
| #328 | #356 | py_context_send routes through ContextManager |
| #332 | #356 | py_context_receive fed by transport provider |
| #329 | #356 | ProtocolStore wired via ContextPersistence |
