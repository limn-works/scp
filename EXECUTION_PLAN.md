# Production Readiness Execution Plan

## Definition: Functioning Network

A functioning SCP network means two or more nodes can:

1. Start and discover each other via relay
2. Create and resolve DIDs (with device attestation where available)
3. Create contexts with governance policies
4. Join/leave contexts with MLS-backed encryption
5. Exchange encrypted messages end-to-end through SDK bindings
6. Enforce governance mechanically (ceiling, promotion, roles, UCAN)
7. Persist all state across restarts
8. Discover contexts, agents, and capabilities
9. Operate broadcast contexts with per-author sender keys
10. Block/unblock members with sender key denial + state destruction
11. Recover from key compromise
12. Sync after offline periods

Every capability above must work through at least one SDK binding (Python).

---

## Current State

**What works E2E today:**
- UCAN pipeline (mint → validate → delegate → revoke)
- Identity pipeline (create → resolve → rotate) — but only with InMemoryDhtClient
- ApplicationNode + relay (HTTP, WebSocket, .well-known)
- All scp-core subsystems in isolation (envelope, MLS crypto, sender keys, governance, trust, tools, sync, broadcast, bridge)

**What breaks:** Every path that goes through FFI → ContextManager. The FFI bridges maintain parallel state (#356). This blocks message send/receive, governance enforcement, persistence, and MLS integration through any SDK binding.

---

## Issue + PRD Story Inventory

### GitHub Issues: 67 open

| Tier | Count | Issues |
|------|-------|--------|
| BLOCKER | 9 | #356, #300, #328, #332, #338, #345, #346, #347, #351 |
| HIGH | 8 | #333, #309, #320, #335, #305, #306, #307, #319 |
| MEDIUM | 16 | #290, #299, #302, #310, #311, #312, #313, #314, #321, #324, #326, #327, #339, #340, #349, #350 |
| LOW | 19 | #291, #301, #303, #304, #315, #316, #317, #318, #322, #323, #325, #329, #330, #331, #334, #336, #337, #341, #348 |
| POLISH | 15 | #342, #343, #344, #352, #353, #354, #355, #357, #360, #362, #363, #364, #365, #366, #367 |

### PRD Stories: 22 across 3 files

| PRD | Stories | Gate |
|-----|---------|------|
| capability-registry.json | SCP-ACR-001–007 | URI parser, challenge unification, DID capabilities, admission |
| bridge-cooperative.json | SCP-BCH-001–009 | Auth, endpoints, webhook, credential lifecycle |
| participation-admission.json | SCP-BA-001–006 | Types, context integration, blind verification, FFI, production |

### What's NOT tracked (gaps found during audit)

None identified. All capabilities required for a functioning network are covered by existing issues or PRD stories. See capability map below.

---

## Capability Map: Functioning Network

Every row maps a network capability to the issues/stories that must close for it to work.

### Tier 1: Network Can Exist (nodes start, find each other, create identities)

| Capability | Status | Blocking issues | PRD stories |
|---|---|---|---|
| Node starts and serves traffic | ✅ Works | — | — |
| Relay starts and serves traffic | ⚠️ In-memory only | #342 (persistent blob storage) | — |
| DID creation | ✅ Works | — | — |
| DID resolution (production DHT) | ❌ InMemory only | #310 (production DhtClient) | — |
| DID sequence persistence | ❌ Starts at 0 | #327 (sequence counter) | — |
| DID resolution systems connected | ❌ Disconnected | #311 (3 systems) | — |
| Device attestation wired | ❌ Not wired | #362 (DeviceAttestation) | — |
| Node uses production providers | ❌ All InMemory | #302 (scp-node InMemory), #300 (providers) | — |
| TLS provisioning | ❌ ACME broken | #305 (3 defects) | — |

### Tier 2: Contexts Work (create, join, leave, close with encryption)

| Capability | Status | Blocking issues | PRD stories |
|---|---|---|---|
| FFI → ContextManager wiring | ❌ ROOT CAUSE | #356 | — |
| Context create via FFI | ❌ Parallel state | #356 | — |
| Context join via FFI | ❌ No-op | #356 | — |
| Context leave via FFI | ❌ No-op | #356 | — |
| MLS group management | ❌ Trait stubs | #333 | — |
| MLS LeafNode extension | ❌ Not impl | #314 | — |
| MLS epoch/grace window | ❌ Conflict | #324 | — |
| Production crypto provider | ❌ None | #300 | — |
| Production transport provider | ❌ None | #300 | — |
| Production event log provider | ❌ None | #300 | — |
| Context persistence via FFI | ❌ Unused | #329 | — |

### Tier 3: Messages Flow (send, receive, encrypt, decrypt)

| Capability | Status | Blocking issues | PRD stories |
|---|---|---|---|
| Message send via FFI | ❌ Discarded | #328 (depends #356) | — |
| Message receive via FFI | ❌ No producer | #332 (depends #356) | — |
| Envelope pipeline (Inner→Outer) | ❌ Not wired | #338 (depends #356) | — |
| Wire format field names | ❌ Breaks interop | #345 | — |
| Sender key wire format | ❌ 4 deviations | #346 | — |
| Deserialization size limits | ❌ OOM DoS | #347 | — |
| InnerEnvelope deny_unknown_fields | ❌ Confused deputy | #351 | — |
| Signaling message type | ❌ Not bound | #290 | — |
| Timestamp validation | ❌ Not wired | #321 | — |
| HPKE domain separator | ❌ Mismatch | #312 | — |
| Dedup cache TTL | ⚠️ 1hr not 24hr | #313 | — |
| Envelope provenance fields | ❌ Incomplete | #330 | — |
| ProtocolStore named msgpack | ⚠️ Positional | #348 | — |

### Tier 4: Security Enforcement (UCAN, governance, trust)

| Capability | Status | Blocking issues | PRD stories |
|---|---|---|---|
| UCAN at tool invocation | ❌ Bypass | #319 | — |
| UCAN signing (UniFFI) | ❌ Ephemeral keys | #326 | — |
| UCAN in broadcast roles | ❌ Unsigned | #299 | — |
| Ceiling enforcement | ❌ Not checked | #339 | — |
| Promotion policy enforcement | ❌ Not checked | #340 | — |
| All 24 governance actions | ⚠️ 12/24 | #320 | — |
| min_participation basis points | ❌ f64 not u32 | #349 | — |
| RoleDefinition/ToolRegistration stubs | ❌ Name-only | #350 | — |
| Content access control (ADR-038) | ❌ Zero impl | #309 | — |
| SDK state destruction (blocking) | ❌ Not impl | #317 | — |
| Platform key custody | ❌ Not impl | #323 | — |
| Trust engine wired to callers | ❌ No callers | #318 | — |
| TOFU key tracking | ❌ Not impl | #325 | — |
| Compromise recovery orchestrator | ❌ Not impl | #316 | — |
| Vote signature verification | ❌ Not verified | #357 | — |
| Governance collection bounds | ❌ Unbounded | #360 | — |

### Tier 5: Advanced Features (broadcast, sync, bridge, discovery)

| Capability | Status | Blocking issues | PRD stories |
|---|---|---|---|
| Broadcast sender key transport | ❌ No path | #335 | — |
| BroadcastEnvelope spec fields | ❌ 3/9 | #352 | — |
| Block subscriber scoping | ❌ Context-wide | #353 | — |
| Conflict detection gaps | ⚠️ 2 cases | #354 | — |
| Projection UCAN caching | ⚠️ Re-parses | #355 | — |
| Context discovery (remote) | ❌ Local only | #336 | — |
| Ephemeral context mode | ❌ Not impl | #337 | — |
| Economic governance | ❌ Not impl | #334 | — |
| Context state export/import | ❌ Not impl | #363 | — |
| Cross-context tool interfaces | ❌ Not exposed | #322 | — |
| BIP-39 mnemonics | ❌ Not impl | #315 | — |

### Tier 6: SDK Bindings (FFI exposure)

| Capability | Status | Blocking issues | PRD stories |
|---|---|---|---|
| Python SDK | ⚠️ ~85% types, 0% E2E | #356, #328, #332 | — |
| WASM bridge | ❌ Critical stubs | #306 | — |
| UniFFI bridge (Swift/Kotlin) | ❌ No-ops | #307 | — |
| NAPI bridge (TypeScript) | ❌ No-ops | #307 | — |
| TypeScript SDK runtime | ❌ Types only | #341 | — |
| Swift Trust/MCP modules | ❌ No exports | #331 | — |
| Go/Java/C# bindings | ❌ README only | #304 | — |
| Reference agent | ❌ Not impl | #364 | — |

### Tier 7: New Features (from open questions resolution)

| Capability | Status | Blocking issues | PRD stories |
|---|---|---|---|
| Capability URI namespace | ❌ Not impl | — | SCP-ACR-001–007 |
| Bridge cooperative HTTP binding | ❌ Not impl | — | SCP-BCH-001–007 |
| Bridge credential lifecycle | ❌ Not impl | — | SCP-BCH-008–009 |
| Participation admission (blind) | ❌ Not impl | — | SCP-BA-001–006 |
| Summary dispute resolution | ❌ Not impl | #365 | — |
| Pseudonym fanout jitter | ❌ Not impl | #366 | — |
| Tool integrity verification | ❌ Not impl | #367 | — |

### Documentation / Polish

| Capability | Status | Blocking issues | PRD stories |
|---|---|---|---|
| Stub policy compliance | ⚠️ 4 violations | #291 | — |
| Dev API real metrics | ❌ Hardcoded 0s | #301 | — |
| Event log full query | ❌ Summary only | #303 | — |
| Artifact health fixes | ⚠️ 11 findings | #344 | — |
| Tier 2 transport adapters | ❌ 0/12 | #343 | — |

---

## Execution Phases

### Phase 1: Surgical Fixes (max parallelism, no dependencies)

7 parallel lanes. All branch from `main`. No inter-lane dependencies.

**Lane A** — `fix/wire-format-transport` (#345, #313)
- scp-transport: serde rename annotations + TTL fix
- Files: `protocol.rs`, `config.rs`

**Lane B** — `fix/sender-key-wire-format` (#312, #346)
- scp-core: HPKE domain separator + 4 wire format fixes
- Files: `key_protocol.rs` (same file — must share branch)

**Lane C** — `fix/envelope-types` (#351, #290)
- scp-core: deny_unknown_fields + signaling message binding
- Files: `inner.rs`

**Lane D** — `fix/store-serialization` (#348)
- scp-core: positional → named MessagePack
- Files: `store/mod.rs`

**Lane E** — `fix/broadcast-bugs` (#353, #352)
- scp-core: block_subscriber scope + BroadcastEnvelope fields
- Files: `broadcast.rs`, `sender_keys/broadcast.rs`

**Lane F** — `fix/misc-standalone` (#354, #355, #291, #350)
- 4 separate crates/files, no conflicts
- Files: `conflict_resolution.rs`, `projection.rs`, 4 stub locations, `params.rs`

**Lane G** — `fix/node-dev-api` (#301)
- scp-node: wire real metrics
- Files: `dev_api.rs`

### Phase 2: Governance Cleanup (serial — same files)

**Branch:** `fix/governance-types` from `main` post-Phase-1
- #349 → #357 → #360 (all touch `manager.rs` or `governance/mod.rs`)
- Then: `feat/governance-actions` (#320) — 12 missing variants

### Phase 3: Security Hardening (parallel, needs Phase 1 merged)

**Lane A** — `fix/deser-limits` (#347) — needs #345, #346 merged (same files)
**Lane B** — `fix/ucan-security` (#299, #319, #326)
**Lane C** — `fix/governance-enforcement` (#339, #340) — needs Phase 2 merged
**Lane D** — `fix/timestamp-validation` (#321) — needs Phase 1 Lane C merged

### Phase 4: Identity Infrastructure (parallel with Phases 2-3)

**Lane A** — `fix/identity-persistence` (#327 → #310 → #311)
**Lane B** — `fix/identity-features` (#315, #325)

### Phase 5: Core Infrastructure (CRITICAL PATH — sequential)

**Step 1:** `feat/production-providers` (#300)
**Step 2:** `refactor/ffi-context-manager` (#356) — depends on #300
  - Closes: #328, #332, #329
**Step 3:** `feat/envelope-pipeline` (#338) — depends on #356

### Phase 6: MLS & Encryption (depends on Phase 5)

#333 → #324 → #314 → #309 → #317

### Phase 7: Feature Completions (parallel, depends on Phase 5)

**Lane A:** #335 (broadcast transport)
**Lane B:** #336, #337, #334 (context features)
**Lane C:** #318, #330 (trust/provenance wiring)
**Lane D:** #316, #323 (identity features)
**Lane E:** #302, #305, #342 (node/relay production)

### Phase 8: SDK Bindings (depends on Phase 5)

**Lane A:** #306, #341 (WASM + TypeScript)
**Lane B:** #307, #331, #322 (UniFFI + NAPI + cross-context tools)
**Lane C:** #304 (Go/Java/C#)

### Phase 9: New Features (from open questions — independent)

**Lane A:** SCP-ACR-001–007 (capability registry)
**Lane B:** SCP-BCH-001–009 (bridge cooperative + credentials)
**Lane C:** SCP-BA-001–006 (participation admission)
**Lane D:** #362, #363, #364, #365, #366, #367

### Phase 10: Polish

#291, #301, #303, #343, #344

---

## Dependency Graph

```
PHASE 1 (parallel, 7 lanes) ─────────────────────────────────────────
  A: #345,#313  B: #312,#346  C: #351,#290  D: #348
  E: #353,#352  F: #354,#355,#291,#350  G: #301

PHASE 2 (serial) ────────────────────────────────────────────────────
  #349 → #357 → #360 → #320

PHASE 3 (parallel, needs P1) ────────────────────────────────────────
  A: #347  B: #299,#319,#326  C: #339,#340  D: #321

PHASE 4 (parallel with P2/P3) ──────────────────────────────────────
  A: #327→#310→#311  B: #315,#325

═══════════ CRITICAL PATH ═══════════════════════════════════════════
PHASE 5: #300 → #356 → #338 (closes #328,#332,#329)
PHASE 6: #333 → #324 → #314 → #309 → #317
═════════════════════════════════════════════════════════════════════

PHASE 7 (parallel, needs P5) ───────────────────────────────────────
  A: #335  B: #336,#337,#334  C: #318,#330  D: #316,#323  E: #302,#305,#342

PHASE 8 (parallel, needs P5) ───────────────────────────────────────
  A: #306,#341  B: #307,#331,#322  C: #304

PHASE 9 (independent) ─────────────────────────────────────────────
  A: SCP-ACR-*  B: SCP-BCH-*  C: SCP-BA-*  D: #362-367

PHASE 10: #291,#301,#303,#343,#344
```

---

## Merge Conflict Hot Spots

| File | Issues | Sequence |
|------|--------|----------|
| `context/manager.rs` | #350,#357,#360,#320,#339,#340,#356 | P1→P2→P3→P5 |
| `key_protocol.rs` | #312,#346,#314,#347 | P1→P3→P6 |
| `envelope/inner.rs` | #351,#290,#347,#321 | P1→P3 |
| `governance/mod.rs` | #349,#320 | P2 |
| `protocol.rs` | #345,#347 | P1→P3 |
| `context/broadcast.rs` | #353,#352,#335 | P1→P7 |
| `scp-ffi/src/context.rs` | #356,#336 | P5→P7 |
| `scp-ffi/src/runtime.rs` | #356,#339 | P5→P3 |

---

## Issues Resolved Without Dedicated Work

| Issue | Resolved by | Reason |
|-------|-------------|--------|
| #328 | #356 | py_context_send routes through ContextManager |
| #332 | #356 | py_context_receive fed by transport provider |
| #329 | #356 | ProtocolStore wired via ContextPersistence |

---

## Totals

| Category | Count |
|----------|-------|
| GitHub issues | 67 |
| PRD stories | 22 |
| Auto-closed by root cause | 3 |
| **Total work items** | **86** |
| **Net after auto-close** | **83** |
