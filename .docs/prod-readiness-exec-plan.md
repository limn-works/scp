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

## Issue + PRD Story + Spec Audit Inventory

### GitHub Issues: 80 open

| Tier | Count | Issues |
|------|-------|--------|
| BLOCKER | 9 | #356, #300, #328, #332, #338, #345, #346, #347, #351 |
| HIGH | 8 | #333, #309, #320, #335, #305, #306, #307, #319 |
| MEDIUM | 16 | #290, #299, #302, #310, #311, #312, #313, #314, #321, #324, #326, #327, #339, #340, #349, #350 |
| LOW | 19 | #291, #301, #303, #304, #315, #316, #317, #318, #322, #323, #325, #329, #330, #331, #334, #336, #337, #341, #348 |
| POLISH | 15 | #342, #343, #344, #352, #353, #354, #355, #357, #360, #362, #363, #364, #365, #366, #367 |

### PRD Stories: 52 unfinished across 6 files

| PRD | Pending | In-Progress | Done | Gate | Blocked By |
|-----|---------|-------------|------|------|------------|
| content-access.json | 10 (SCP-CAC-001–010) | 0 | 0 | Block list, access keys, CEK wrapping, state destruction | #309, #356, Phase 0 S-A (canonical serialization for key wrapping AAD) |
| governance-integration.json | 8 (SCP-267–274) | 0 | 0 | GovernanceEngine wiring, proposal lifecycle, conflict detection, cosignatures | #356 (ContextManager), #320 (actions) |
| capability-registry.json | 7 (SCP-ACR-001–007) | 0 | 0 | URI parser, challenge unification, DID capabilities, admission | — (independent) |
| bridge-cooperative.json | 13 (SCP-BCH-001–013) | 0 | 0 | Auth, endpoints, webhook, credential lifecycle, sender key encryption | **Phase 0 S-D** (bridge MLS model) |
| participation-admission.json | 6 (SCP-BA-001–006) | 0 | 0 | Types, context integration, blind verification, FFI, production | Phase 0 S-A (canonical serialization for profiles) |
| main.json | 9 | 3 | 173 | Kotlin SDK, FFI wiring, signaling | #356 (FFI), #306/#307 (bridges) |

#### main.json unfinished stories detail

| ID | Title | Status | Blocked By |
|---|---|---|---|
| SCP-038 | PyO3 identity bridge functions | in-progress | — |
| SCP-092 | Signaling message construction and routing | in-progress | #290 |
| SCP-116 | Kotlin Flow/Channel streaming layer | pending | — |
| SCP-117 | Android lifecycle-aware SCP resource management | pending | — |
| SCP-118 | Jetpack Compose state holders for SCP | pending | SCP-116 |
| SCP-120 | Kotlin SDK cross-platform conformance tests | pending | SCP-116, SCP-117 |
| SCP-214 | Wire KeyCustodyProvider callbacks across all FFI bridges | pending | #356 |
| SCP-215 | Error code range audit and normalization | done | — |
| SCP-218 | Wire WASM bridge to scp-core for tools, UCAN, event log | pending | #306 |
| SCP-220 | Wire UniFFI bridge to scp-core for UCAN and event log | pending | #307 |
| SCP-221 | Wire Swift SDK wrapper functions to UniFFI bridge | pending | #307 |
| SCP-227 | Broadcast subscriber registration, blocking, integration | in-progress | — |

### Spec Audit Findings: 48 NEW untracked (VERIFIED-DEDUPED-REPORT.md)

| Severity | New | Partially Tracked | Tracked |
|----------|-----|-------------------|---------|
| CRITICAL | 11 | 13 | 1 |
| HIGH | 37 | ~93 | ~15 |

**The 11 NEW CRITICALs and 37 NEW HIGHs are spec-level gaps — they require spec changes before correct implementation is possible.** Many existing issues will produce incorrect implementations if the underlying spec gap isn't resolved first.

---

## Blocking Sequences: Spec Audit → Implementation

These spec findings **block** existing implementation work. Implementing the code without resolving the spec gap will produce non-interoperable or insecure results.

### HARD BLOCKS (spec fix BEFORE code)

| Spec Finding | Blocks | Issue |
|---|---|---|
| **CRYPTO-04** (sender key nonce generation) | #346 (sender key wire format) | — |
| **CRYPTO-03** (HPKE not RFC 9180) | #312 (HPKE domain separator), #346 | — |
| **ADR-016-C3** (UCAN nonce format) | #313, #319, #326 | #380 |
| **ADR-029-C3** (ResetRequest anti-replay) | #324 (MLS epoch conflict) | #381 |
| **5.13.2** (relay eligibility for encrypted) | #333 (MLS integration) | #374 |

### BLOCKS (spec fix BEFORE code)

| Spec Finding | Blocks | Issue |
|---|---|---|
| CRYPTO-14 (ParticipationProfile signing key KDF) | SCP-BA-001–006 | — |
| CRYPTO-18 (broadcast key nonce) | #352 (BroadcastEnvelope fields) | — |
| 03-IDENTITY-1/2 (private state encryption) | #329 (ProtocolStore persistence) | #372 |
| 8.4/9.1 (app sandboxing) | SCP-ACR-* (capability registry) | #376 |
| 15-001 (GDPR erasure — §15 clarification) | — | #379 |

---

## Conflict Identification

### Spec Findings That Conflict With Each Other

| Finding A | Finding B | Conflict |
|---|---|---|
| 9.10.3/9.10.6 (bucket size) | — | Internal spec contradiction. Must pick one scheme. Factor-of-4 matches implementation. |
| H-18 (chain depth hard vs configurable) | — | 3-way spec contradiction. Must pick: hard limit in SS9, or configurable in SS24. |
| H-13 (TTL "all parties" vs "all members") | — | Spec self-contradiction. "All members" is correct for governance; "all parties" is ambiguous. |
| H-07 (KeyPackage signing key) | — | SS9 line 287 vs 332. Active Signing Key (#active) is correct per RFC 9420. |

### Spec Findings That Conflict With Existing Issues

| Spec Finding | Existing Issue | Conflict |
|---|---|---|
| CRYPTO-03 (HPKE not RFC 9180) | #312 (domain separator mismatch) | #312 fixes the info string. CRYPTO-03 says the entire construction is wrong. Fixing only the string while leaving the bespoke ECDH+HKDF is insufficient. Must resolve together. |
| ADR-016-C3 (nonce format) | #313 (dedup TTL) | #313 changes TTL from 1hr to 24hr. ADR-016-C3 says the nonce format itself is contradictory (UUID v4 vs timestamp-hex). The TTL fix is pointless if the format is wrong. |
| ADR-029-C3 (ResetRequest replay) | #324 (MLS epochs conflict) | #324 addresses the epoch/grace window mismatch. ADR-029-C3 says the ResetRequest message itself is vulnerable. Both are sync protocol issues that should be resolved together. |

### Existing GH Issues That Need Expanded Scope

These issues exist but don't cover spec gaps found by the audit. Expand acceptance criteria.

| GH Issue | Currently Covers | Should Also Cover |
|---|---|---|
| #352 | BroadcastEnvelope missing 5 of 9 fields | Domain separator, length prefixes, nonce field for broadcast key layer |
| #346 | 4 wire format deviations | Non-compliance with RFC 9180 HPKE, SenderKeyRequest signature preimage |
| #309 | ADR-038 zero implementation | Coordinated key deletion protocol, AAD binding specification |
| #334 | Economic governance not implemented | Relay payment wire protocol, measurement windows, spending enforcement |
| #303 | Event log summary only | Pruning/checkpoint specification |
| #316 | Compromise recovery | Total key loss recovery (social/device recovery — different scenario) |
| #319 | UCAN tool invocation bypass | Root issuer trust gap in multi-admin |
| #366 | Pseudonym rotation | Pseudonym HMAC public key derivation concern |
| #347 | No deser size limits | Relay storage quota per client |
| #349 | f64 basis points | Systemic f64 usage across multiple ADRs (not just min_participation) |

### Code File Conflicts (Same Files Touched by Multiple Items)

| File | Issues + Findings | Sequence |
|------|-------------------|----------|
| `key_protocol.rs` | CRYPTO-01, CRYPTO-03, CRYPTO-04, #312, #346, #314, #347 | Spec fixes → #312+#346 → #314 → #347 |
| `envelope/inner.rs` | CRYPTO-01, #351, #290, #347, #321, #338 | CRYPTO-01 → #351+#290 → #321 → #347 → #338 |
| `context/manager.rs` | #350, #357, #360, #320, #339, #340, #356 | P1→P2→P3→P5 |
| `governance/mod.rs` | #349, #320 | P2 |
| `ucan/validation.rs` | ADR-016-C3, #313, #319, #326 | ADR-016-C3 → #313 → #319+#326 |
| `context/broadcast.rs` | CRYPTO-18, #353, #352, #335 | CRYPTO-18 → #352+#353 → #335 |
| `sync/` | ADR-029-C3, #324 | ADR-029-C3 → #324 |
| `bridge/` | 12.6-001/002, #370, SCP-BCH-* | 12.6-001/002 → #370 → SCP-BCH-* |
| `scp-ffi/src/context.rs` | #385, #386, #328, #332, #336, #369 | #385 → #386 → closes #328/#332/#336/#369 |
| `scp-identity/src/dht.rs` | #310, #327, #362 | #327 → #310; #362 independent |

---

## GH Issue Provenance Audit

### Broken Spec References (25 issues)

Issues with wrong file names, section numbers, or ADR locations in their bodies. These don't affect the validity of the issue (the problem is real) but the references are misleading.

**Wrong spec file names (13 issues):**

| Issue | References | Actual File |
|---|---|---|
| #318 | `10-trust-model.md` | `10-infrastructure-and-self-hosting.md` |
| #319 | `06-tools.md` | `06-cross-context-communication.md` |
| #319 | `08-capabilities.md` | `08-products-and-apps-in-the-graph.md` |
| #320 | `07-governance.md` | Does not exist; governance is in `05-contexts.md` §5.9 |
| #321 | `09-timestamps.md` (implied) | `09-security-model.md` |
| #325 | `09-security.md` (for TOFU) | `09-security-model.md` §9.11 (not §9.12) |
| #333 | ADR-019 for MLS | ADR-019 is Data Provenance; MLS is ADR-001 in `phase-1.md` |
| #334 | ADR-031 in `phase-5.md` | ADR-031 is in `phase-6.md` |
| #337 | §5.7 for ephemeral | Should be §5.10/§5.11 |
| #339 | `08-capabilities.md` | `08-products-and-apps-in-the-graph.md` |
| #340 | `06-tools.md` | `06-cross-context-communication.md` |
| #341 | `07-trust.md` | `07-trust-validation-and-capabilities.md` |
| #342 | `10-transport.md` | `10-infrastructure-and-self-hosting.md` |

**Wrong section numbers (9 issues):**

| Issue | Claims | Actual |
|---|---|---|
| #299 | §5.8, §6.1 | §5.14.3 (subscriber registration), §6.2 |
| #300 | §5.3, §6.1 | §5.2 (context creation), §6.2 |
| #310 | §3.4 | §3.10 (DID resolution) |
| #311 | §3.3 | §3.10.1 (parallel resolution) |
| #313 | §9.9b | §9.8.2(b) (replay protection) |
| #315 | §9.12 for mnemonic | §9.11 (key continuity fingerprints) |
| #320 | ADR-031 in phase-5.md | phase-6.md line 2279 |
| #321 | §9.9a, §9.9c | §9.8.2(c), §9.8.5 |
| #325 | §9.12 for TOFU | §9.11 |

**Factual inaccuracies (3 issues):**

| Issue | Claim | Reality |
|---|---|---|
| #320 | Governance models: "Consensus, Delegated, Weighted, Tiered" | Actual: SingleAdmin, Threshold, Majority, Unanimity |
| #320 | "No multi-party governance exists" | majority.rs, unanimity.rs, multisig.rs exist; PR #296 implemented all 24 variants |
| #337 | Conflates ContextMode with memory_scope | These are separate concepts |
| #340 | Mischaracterizes what "promotion" means | §5.10 defines promotion as ephemeral→persistent, not capability escalation |

### Missing Dependency Declarations (19 — now added as GH comments)

These blocking relationships exist per the execution plan but are not declared in issue bodies.

**Phase 2 serial chain:**
- #349 → #357 → #360 → #320 (all touch `governance/mod.rs` or `manager.rs`)
- #320 → #339, #320 → #340 (governance enforcement needs governance actions)

**Phase 4 serial chain:**
- #327 → #310 → #311 (DID sequence → production DHT → resolver unification)

**Phase 6 MLS chain:**
- #333 → #324 → #314 → #309 → #317

**Cross-phase file conflicts:**
- #345 → #347 (same file: `protocol.rs`)
- #346 → #347 (same file: `key_protocol.rs`)
- #306 → #341 (WASM bridge before TypeScript SDK)
- #307 → #331 (UniFFI bridge before Swift Trust/MCP)
- #356 → #336 (ContextManager before context discovery)
- #371 → #290 (canonical serialization before signaling binding)

**New spec audit issues:**
- #372 → #316 (identity encryption spec before compromise recovery)
- #373 → #333 (invitation bundle format before MLS integration)
- #377 → #333 (bridge MLS model before MLS accounts for bridges)
- #381 → #333 (reset anti-replay before MLS sync)

### Hardest Bottleneck

**#338 (envelope pipeline)** has 7 direct blocking predecessors: #300, #314, #328, #332, #333, #356, #371. It sits at the convergence point of the entire dependency graph.

---

## Parallelization Map

### What Can Run In Parallel RIGHT NOW (no dependencies)

```
SPEC TRACK (all parallel — spec-only changes, no code conflicts):

  S-B: UCAN nonce format fix (#380)          S-C: Versioning spec (§13, #378)
       Pick {unix_millis}-{hex16}                  Define version field, negotiation,
       Update ADR-016 mint_ucan                    forward compat, degraded mode

  S-E: Identity private state spec (#372)    S-F: Sender key crypto spec
       Specify encryption algo, multi-device       (CRYPTO-03, CRYPTO-04)
       Specify social/device recovery              Specify RFC 9180 mode + nonce gen

  S-G: Sync anti-replay (#381)              S-H: Context nesting eligibility (#374)
       Add nonce to ResetRequest                   Specify mechanism for relay to verify
       Add freshness binding                       parent membership in encrypted contexts

  S-I: §15 erasure clarification (#379)
       3 sentences: ephemeral enforcement,
       local deletion, Merkle leaf retention
```

S-A (canonical serialization) and S-D (bridge MLS model) are DONE.

```
CODE TRACK (can start now — no remaining spec dependencies):

  C-A: #345,#313 [needs S-B]     C-B: #348         C-C: #354,#355,#291,#350
  C-D: #301                      C-E: #353          C-F: #349→#357→#360→#320
  C-G: #351, #290 (envelope types — S-A done, unblocked)
```

### What CANNOT Start Until Spec Fixes Land

| Code Work | Waiting On Spec |
|---|---|
| #346 (sender key wire format) | S-F (HPKE/nonce) |
| #312 (HPKE domain separator) | S-F (RFC 9180 mode decision) |
| #313 (dedup TTL) | S-B (nonce format) |
| #319, #326 (UCAN security) | S-B (nonce format) |
| #324 (MLS epoch conflict) | S-G (ResetRequest anti-replay) |
| SCP-BA-* (participation admission) | CRYPTO-14 (signing key KDF) |
| #352 (BroadcastEnvelope fields) | S-F (broadcast key nonce) |

---

## Revised Execution Phases

### Phase 0: Spec Fixes — COMPLETE

All 8 spec lanes merged to `feat/achieve-production-readiness`:
- S-A: Canonical serialization (pre-existing)
- S-B: UCAN nonce format (#380) → aa92b92
- S-C: Protocol versioning §13 (#378) → 23c4b32
- S-D: Bridge MLS model (pre-existing)
- S-E: Identity private state (#372) → f8bbc6e
- S-F: Sender key & broadcast crypto → e6ecaa3
- S-G: Sync anti-replay (#381) → 8c7ae18
- S-H: Context nesting eligibility (#374) → 5c79ab7
- S-I: §15 erasure (#379) → aeaf5f9

### Phase 1: Surgical Code Fixes — COMPLETE

All 7 lanes merged to `feat/achieve-production-readiness`:
- Lane A: #345 (af4192c), #313 (2444c9a)
- Lane B: #312 (53ed083), #346 (7f341b8, 5fb0266)
- Lane C: #351 (26e2222), #290 (5f88141)
- Lane D: #348 (d174211, 34d05b2)
- Lane E: #353, #352 (c78f1b6)
- Lane F: #354 (38fe1cf), #355, #350 (dd392ae)
- Lane G: #301 (cf3cc06)

Additional review fixes (81185a1): deny_unknown_fields on 4 sender key wire types, HandleRequestParams nonce/timestamp validation, saturating_add, conflict detection tests, actions_conflict docstring.

### Phase 2: Governance Cleanup (serial — same files) — COMPLETE

**Step 1:** #349 (f64→u32 basis points) — **COMPLETE** → fadf4ff
**Step 2:** #357 (vote signature verification) — **COMPLETE** → eba59b9 + review fix fbf0577
**Step 3:** #360 (governance collection bounds) — **COMPLETE** → fe86235 + review fix de6984a
**Step 4:** #320 (GovernanceModel enum + proposal lifecycle) — **COMPLETE** → d535efa

### Phase 3: Security Hardening (parallel, needs Phase 1 merged) — COMPLETE

**Lane A** — #347 (deser size limits) — **COMPLETE** → 155f2b3 + review fix 1bd9403
**Lane B** — #319 — **COMPLETE** → e6b86a9 + review fix 04c2281. #299 — **COMPLETE** → ffd3272 + review fix fbf0577. #326 done in prior iteration.
**Lane C** — #340 (promotion policy tests) — **COMPLETE** → c33675d. #339 (ceiling enforcement) — **COMPLETE** → 72deffe (governance actions) + 2c6d5c9 + 4a2d2e0 (UCAN minting/delegation + FFI wiring)
**Lane D** — #321 — **COMPLETE** (prior iteration) → b7b4e1e + review fix 3eacfb2

### Phase 4: Identity Infrastructure (parallel with Phases 2-3) — COMPLETE

**Lane A** — #327 (BEP44 sequence persistence) — **COMPLETE** → cc5eff1. #310 (PkarrDhtClient) — **COMPLETE** → 59f18b2 + review fix 04c2281. #311 (DID resolver unification) — **COMPLETE** → 6b2885e + review fix fbf0577
**Lane B** — #315 (BIP-39 mnemonic) — **COMPLETE** → 7e61bb3. #325 (TOFU + cert pinning) — **COMPLETE** → 225c862 + review fix 1bd9403

### Phase 5: Core Infrastructure (CRITICAL PATH) — COMPLETE

#356 has been decomposed into 6 sub-issues. #300 is absorbed into #385.

**Step 1:** #385 — Production provider implementations (ContextCrypto, Transport, EventLog, Persistence) — **COMPLETE** → cd90541 + 0e2dd00
  - Absorbs #300 (no production providers)
  - Pure scp-core/scp-transport, no FFI
  - MlsCryptoProvider, RelayTransportProvider, MerkleEventLogProvider, InMemoryPersistence + ProtocolStorePersistence
  - 31 new tests
**Step 2 (parallel):** Bridge rewrites — **COMPLETE**
  - #386 — PyO3 bridge rewrite → 83c6630 (ContextRuntime → ContextManager + FfiBridgeState)
  - #387 — UniFFI bridge rewrite → 7901cff (shared Arc<ContextManager>, no-op validation stubs)
  - #388 — NAPI bridge rewrite → b733858 (UcanContextState retained separately, DashMap persistence)
  - #389 — WASM bridge rewrite → 1ca2970 (WasmContextManager centralizing state)
  - Integration fixes → 606cf0d (key_resolver, did_resolver, error variants, missing fields)
  - Closes: #328, #332, #329, #335, #336, #338
  - Partially advances: #306, #307, #369, #370 (context ops fixed; remaining stubs in Phase 9)
**Step 3:** #390 — E2E integration tests — **COMPLETE** → 9f22230
  - 8 E2E tests: message round-trip, governance, broadcast, persistence, lifecycle, multi-bridge API
  - All through ContextManager pipeline (same API surface as FFI bridges)

Blocking chain: `#385 → (#386 + #387 + #388 + #389 parallel) → #390` — **ALL COMPLETE**

### Phase 6: MLS, Encryption & Content Access (depends on Phase 5)

**Step 1:** #333 (MLS integration) — **COMPLETE** → 723ec9e
**Step 2:** #324 (MLS epoch conflict) — **COMPLETE** → d57a7f8
**Step 3:** #314 (MLS LeafNode extension) — **COMPLETE** → 1789598
**Step 4:** #309 (ADR-038 content access control) — unlocks SCP-CAC-*
**Step 5:** #317 (SDK-mandated state destruction) — **DONE** (closed)

Then content access PRD (serial — same subsystem, depends on #309):
SCP-CAC-001 — **COMPLETE** → 7d56fdf
SCP-CAC-004 — **COMPLETE** → 8c38383
SCP-CAC-002 — **COMPLETE** → 586e025
SCP-CAC-005 — **COMPLETE** → 7ede865
SCP-CAC-003 → SCP-CAC-006 → SCP-CAC-007 → SCP-CAC-008 → SCP-CAC-009 → SCP-CAC-010

### Phase 7: Governance Integration (depends on Phase 2 + Phase 5)

Governance PRD (serial — each builds on prior, all touch `manager.rs`):
SCP-267 → SCP-268 → SCP-269 → SCP-270 → SCP-271 → SCP-272 → SCP-273 → SCP-274

- SCP-267 — **COMPLETE** → bfe5245
- SCP-268 — **COMPLETE** → 3df2cd7
- SCP-269 — **COMPLETE** → a758149
- SCP-270 — **COMPLETE** → 6a5cea5
- SCP-271 — **COMPLETE** → 6ae5dc2
- SCP-267–268 need #356 (ContextManager wiring)
- SCP-269–270 need #320 (GovernanceModel enum expansion + proposal lifecycle — all 24 actions already dispatched per PR #296)
- SCP-272 needs #354 (conflict detection)
- SCP-273 needs #330 (provenance/checkpoint fields)

### Phase 8: Feature Completions (parallel, depends on Phase 5)

**Lane A:** SCP-227 (subscriber registration — in-progress). Note: #335 closed by Phase 5 bridge rewrites.
**Lane B:** #337 — **COMPLETE** → 9180dd5. #334 remaining.
**Lane C:** #318 — **COMPLETE** → 91317fc. #330 — **COMPLETE** → 032cb41.
**Lane D:** #316, #323 (identity features — decomposed: #391 file custody → #392+#393+#394 parallel)
**Lane E:** #302 — **COMPLETE** → bf53ec5. #305 — **COMPLETE** → 1dc533b. #342 — **COMPLETE** → 254ed89.

### Phase 9: SDK Bindings (depends on Phase 5)

**Lane A:** #306, SCP-218 (WASM bridge wiring) → #341 (TypeScript SDK)
**Lane B:** #307, SCP-220, SCP-221 (UniFFI bridge + Swift wiring) → #331 (Swift Trust/MCP)
**Lane C:** SCP-214 (KeyCustodyProvider callbacks across all FFI bridges) — needs #386/#387/#388/#389 (bridge rewrites)
**Lane D:** #322 (cross-context tool interfaces)
**Lane E:** SCP-215 (error code range audit — independent)
**Lane F:** #304 (Go/Java/C#)
**Lane G:** SCP-116 → SCP-117 → SCP-118 → SCP-120 (Kotlin SDK completion)

### Phase 10: New Features (partially blocked by spec)

**Lane A:** SCP-ACR-001 — **COMPLETE** → ad83cef. SCP-ACR-002 — **COMPLETE** → 5b26f18. SCP-ACR-003–007 remaining
**Lane B:** SCP-BCH-001–013 (bridge cooperative + credentials + sender key encryption) — **BLOCKED by S-D** (bridge MLS model)
**Lane C:** SCP-BA-001–006 (participation admission) — **soft-blocked by S-A** (canonical serialization for profiles)
**Lane D:** #362, #363, #364, #365, #366, #367
**Lane E:** SCP-038 (PyO3 identity bridge — in-progress), SCP-092 (signaling — in-progress, #290 done)

### Phase 11: Spec Audit NEW HIGHs (parallel with Phase 8+)

Spec-only fixes for the 37 NEW HIGH findings. Grouped by topic:

**Lane H-A** — Identity spec gaps (H-01 through H-06)
- Key custody migration, private state event log, routing_id, earned capacity, KeyPackage signing key, Merkle hash chain

**Lane H-B** — Context spec gaps (H-07 through H-12)
- Creation failure states, metadata signing, multi-parent matching, group_context extension, TOCTOU, context migration

**Lane H-C** — Trust spec gaps (H-13 through H-18)
- Chain depth contradiction, self-service auth, proof-of-absence, attestation independence, revocation format, counterparties privacy

**Lane H-D** — Security spec gaps (H-19 through H-26)
- Equivocation response, chunking, AccessKeyRequest timing, push registration, multi-device sync, media keys, QUIC 0-RTT, UCAN CID

**Lane H-E** — Versioning spec gaps (H-28 through H-32)
- Already covered by Phase 0 Lane S-C

**Lane H-F** — Bridge spec gaps (H-27, H-33)
- Bridge metadata in SS5.7, reverse bridge flow

**Lane H-G** — Sync/provenance spec gaps (H-34 through H-37)
- Counterparties privacy, EpochGraceStore crash recovery, checkpoint verification, event log reconciliation trust

### Spec-Code Alignment (parallel with Phase 6+)

Wire format and crypto fixes identified by spec review. All are code changes to match prescriptive spec:

- #395 — HPKE sender key wrapping: add context_id/sender_did/epoch to info + AAD ✅ (1fe28a47)
- #396 — BroadcastEnvelope: add top-level nonce field, expand AAD with context_id + sequence ✅ (b4b9161c)
- #397 — ResetRequest: add nonce field, anti-replay validation (signature + 30s freshness + nonce dedup) ✅ (d6146a16)
- #398 — Envelope version field: add `version: u16` to InnerEnvelope, BroadcastEnvelope, OuterEnvelope + canonical hashes

### Phase 12: Polish

#291, #301, #303, #343, #344

---

## Parallel Loom Execution (2026-03-07)

Four loom sessions running simultaneously on separate branches to maximize throughput.
File ownership is strictly partitioned to prevent merge conflicts.

| Loom | Branch | Scope | Owned Files |
|------|--------|-------|-------------|
| Loom 1 (primary) | `feat/achieve-production-readiness` | Phase 6, Phase 7, #398 | `manager.rs`, `inner.rs`, `broadcast.rs`, `context/` governance |
| Loom 2 | `feat/phase-9-sdk` | Phase 9 (SDK bindings) | `scp-ffi/`, `bindings/` |
| Loom 3 | `feat/phase-10-features` | Phase 10 (new features) | PRD story modules, new files |
| Loom 4 | `feat/phase-11-spec-polish` | Phase 11, Phase 12, #395-397 | `.docs/specs/`, misc code, `key_protocol.rs`, `sync/` |

**Merge order:** All branches merge into `feat/achieve-production-readiness` after completion.
**Conflict avoidance:** #398 assigned to Loom 1 (touches same files as Phase 6/7). #395-397 assigned to Loom 4 (no overlap with Loom 1's files).

---

## Issue Audit Notes (2026-03-06)

All ~50 open issues audited for AC quality, spec reference accuracy, and scope. Changes applied directly to GitHub issues.

**Decomposed:**
- #356 → #385, #386, #387, #388, #389, #390 (providers + 4 bridge rewrites + E2E tests)
- #323 → #391, #392, #393, #394 (file custody, Apple, Android, restriction)
- #309 → tracked as epic, PRD stories SCP-CAC-001–010 are the implementation units

**Scope reduced (already partially/fully implemented):**
- #320 — all 24 GovernanceAction variants already dispatched (PR #296). Real gap: GovernanceModel enum + proposal lifecycle API
- #340 — enforcement already exists at `manager.rs:2609-2615`. Downgraded to LOW (needs tests only)
- #339 — ceiling IS checked during UCAN validation (step 8, `validate.rs:549`). Gap: not checked during minting
- #299 — `mint_role_tokens()` stub already fixed. Real gap: broadcast subscriber registration

**Wrong spec references fixed (14 issues):** #310, #311, #318, #319, #320, #325, #330, #333, #334, #336, #337, #339, #340, #366

**Overlap with bridge rewrites noted:** #306, #307, #328, #329, #332, #369, #370 — all reference #385/#386/#387/#388/#389 as blockers

---

## Dependency Graph

```
PHASE 0 — SPEC FIXES (all parallel, spec-only) ────────────────────
  S-A: Canonical serialization   S-B: UCAN nonce format
  S-C: Versioning (§13)          S-D: Bridge MLS model
  S-E: Identity private state    S-F: Sender key crypto
  S-G: Sync anti-replay          S-H: Context nesting eligibility

                    ↓ S-A,S-B,S-F must merge before P1 lanes that touch affected code
                    ↓ S-D must merge before SCP-BCH-*
                    ↓ S-G must merge before #324
                    ↓ S-H should merge before #333

PHASE 1 (parallel, 7 lanes — gated on relevant P0 lanes) ─────────
  A: #345,#313 [needs S-B]     B: #312,#346 [needs S-A,S-F]
  C: #351,#290 [needs S-A]     D: #348
  E: #353,#352 [needs S-F]     F: #354,#355,#291,#350     G: #301

PHASE 2 (serial) ──────────────────────────────────────────────────
  #349 → #357 → #360 → #320

PHASE 3 (parallel, needs P1) ──────────────────────────────────────
  A: #347  B: #299,#319,#326 [needs S-B]  C: #339,#340  D: #321

PHASE 4 (parallel with P2/P3) ────────────────────────────────────
  A: #327→#310→#311  B: #315,#325

═══════════ CRITICAL PATH ═════════════════════════════════════════
PHASE 5: #385 (providers, absorbs #300)
         → #386 + #387 + #388 + #389 (4 bridge rewrites, parallel)
         → #390 (E2E integration tests)
         Closes: #328,#332,#329,#335,#336,#338
         Advances: #306,#307,#369,#370 (remaining stubs in P9)
PHASE 6: #333 [needs S-H] → #324 [needs S-G] → #314 → #309 → #317
         then SCP-CAC-001→010 (serial, needs #309)
═══════════════════════════════════════════════════════════════════

PHASE 7 (needs P2+P5) ────────────────────────────────────────────
  SCP-267→268 [needs #356] →269→270 [needs #320] →271→272→273→274

PHASE 8 (parallel, needs P5) ─────────────────────────────────────
  A: #335,SCP-227  B: #336,#337,#334  C: #318,#330
  D: #316,#323     E: #302,#305,#342

PHASE 9 — SDK BINDINGS (parallel, needs P5) ──────────────────────
  A: #306,SCP-218→#341       B: #307,SCP-220,SCP-221→#331
  C: SCP-214 [needs #356]    D: #322    E: SCP-215
  F: #304                    G: SCP-116→117→118→120

PHASE 10 — NEW FEATURES (partially blocked by spec) ──────────────
  A: SCP-ACR-*               B: SCP-BCH-* [BLOCKED by S-D]
  C: SCP-BA-* [soft S-A]     D: #362-367
  E: SCP-038,SCP-092

PHASE 11 — SPEC AUDIT HIGHs (parallel with P8+) ─────────────────
  H-A: Identity  H-B: Context  H-C: Trust  H-D: Security
  H-E: (in S-C)  H-F: Bridge   H-G: Sync/provenance

PHASE 12: #291,#301,#303,#343,#344
```

---

## Merge Conflict Hot Spots

| File | Issues + Findings | Sequence |
|------|-------------------|----------|
| `key_protocol.rs` | CRYPTO-01, CRYPTO-03, CRYPTO-04, #312, #346, #314, #347 | S-A+S-F → #312+#346 → #314 → #347 |
| `envelope/inner.rs` | CRYPTO-01, #351, #290, #347, #321, #338 | S-A → #351+#290 → #321 → #347 → #338 |
| `context/manager.rs` | #350, #357, #360, #320, #339, #340, #356 | P1→P2→P3→P5 |
| `governance/mod.rs` | #349, #320 | P2 |
| `ucan/validation.rs` | ADR-016-C3, #313, #319, #326 | S-B → #313 → #319+#326 |
| `context/broadcast.rs` | CRYPTO-18, #353, #352, #335 | S-F → #352+#353 → #335 |
| `protocol.rs` | #345, #347 | P1→P3 |
| `sync/` | ADR-029-C3, #324 | S-G → #324 |
| `bridge/` | 12.6-001/002, #370, SCP-BCH-* | S-D → #370 → SCP-BCH-* |
| `scp-ffi/src/context.rs` | #356, #336 | P5→P7 |
| `scp-ffi/src/runtime.rs` | #356, #339 | P5→P3 |

---

## Issues Resolved Without Dedicated Work

| Issue | Resolved by | Reason |
|-------|-------------|--------|
| #328 | #356 | py_context_send routes through ContextManager |
| #332 | #356 | py_context_receive fed by transport provider |
| #329 | #356 | ProtocolStore wired via ContextPersistence |

---

## PRD Breakdown

| PRD | Unfinished | Blocked By |
|-----|------------|------------|
| main.json | 12 | #356, #290, #306, #307 |
| content-access.json | 10 | #309 (Phase 6), #356 |
| governance-integration.json | 8 | #356, #320 (Phase 2) |
| capability-registry.json | 7 | — (independent) |
| bridge-cooperative.json | 13 (SCP-BCH-001–013) | — (S-D resolved) |
| participation-admission.json | 6 | CRYPTO-14 (signing key KDF) |

---

## Critical Path Timeline

```
         NOW                 NEXT                THEN                THEN
    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
    │  PHASE 0    │    │  PHASE 1    │    │  PHASE 5    │    │  PHASE 6    │
    │  6 spec     │───→│  Code fixes │───→│  #300→#356  │───→│  MLS chain  │
    │  lanes left │    │  (8 lanes)  │    │  →#338      │    │  #333→#317  │
    └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
         │                   │
         │              ┌────┴────┐
         │              │ PHASE 2 │ (governance)
         │              │ PHASE 3 │ (security)
         │              │ PHASE 4 │ (identity)
         │              └─────────┘
         │
    ┌────┴────┐
    │ PHASE 9 │ (new features — SCP-ACR, SCP-BA, etc.)
    │ can run │ (SCP-BCH blocked until S-D resolves)
    │ in ||   │
    └─────────┘
```

Phase 0 is the new gate. Without it, Phases 1 and 6 produce implementations that lock in wrong formats.
