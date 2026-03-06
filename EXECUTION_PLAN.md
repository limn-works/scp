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
| bridge-cooperative.json | 9 (SCP-BCH-001–009) | 0 | 0 | Auth, endpoints, webhook, credential lifecycle | **Phase 0 S-D** (bridge MLS model) |
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
| SCP-215 | Error code range audit and normalization | pending | — |
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

### HARD BLOCKS (implement this spec fix BEFORE touching the code issue)

| Spec Finding | Blocks | Why |
|---|---|---|
| **CRYPTO-01** (canonical serialization) | #338 (envelope pipeline), #346 (sender key wire), #351 (InnerEnvelope) | Two implementations can't verify each other's signatures without length prefixes. Implementing the pipeline now locks in the wrong format. |
| **CRYPTO-04** (sender key nonce) | #346 (sender key wire format) | #346 fixes 4 deviations but nonce generation isn't one of them. Without specifying nonce, the fix is incomplete and GCM nonce reuse is possible. |
| **CRYPTO-03** (HPKE not RFC 9180) | #312 (HPKE domain separator), #346 | #312 fixes the domain string but the underlying construction is still informal. Must decide: adopt RFC 9180 modes or fully specify the bespoke construction. |
| **ADR-016-C3** (UCAN nonce format) | #313 (dedup TTL), #319 (UCAN at tool boundary), #326 (UniFFI UCAN) | Minted tokens will fail validation. Fix the spec contradiction first, then implement nonce handling consistently. |
| **12.6-001/002** (bridge MLS model) | ALL SCP-BCH-* stories | Can't implement bridge HTTP endpoints until the fundamental question is answered: does the bridge join the MLS group? |
| **ADR-029-C3** (ResetRequest anti-replay) | #324 (MLS epoch conflict) | The sync protocol's reset mechanism is exploitable via replay. Must add nonce/freshness before wiring sync. |
| **5.13.2** (relay eligibility for encrypted) | #333 (MLS integration) | Context nesting validation can't work if the relay can't see membership. Resolve mechanism before implementing MLS group ops. |

### SOFT BLOCKS (should fix spec, but code can proceed with a TODO)

| Spec Finding | Affects | Risk if deferred |
|---|---|---|
| CRYPTO-12 (attestation canonicalization) | SCP-BA-001–006 (participation admission) | Participation profiles won't be verifiable cross-implementation. Can implement with a canonical format and backfill spec. |
| CRYPTO-14 (ParticipationProfile signing key) | SCP-BA-001–006 | Same — implement with a chosen KDF and document it. |
| CRYPTO-18 (broadcast key nonce) | #352 (BroadcastEnvelope fields) | Missing nonce field in struct. Can add it and document, then update spec. |
| 03-IDENTITY-1/2 (private state encryption) | #329 (ProtocolStore persistence) | Identity private state is a future feature. Does not block core network. |
| 8.4/9.1 (app sandboxing) | SCP-ACR-* (capability registry) | Capability declarations work without runtime sandboxing. Security risk, not interop risk. |
| 15-001 (GDPR vs Merkle) | #303 (event log) | Tombstoning can be added later. Does not block core event log implementation. |

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
| CRYPTO-01 (length prefixes) | #346 (sender key wire format) | #346 fixes 4 deviations in sender key wire format. CRYPTO-01 says the signature preimage itself needs length prefixes. Both touch `key_protocol.rs` — the CRYPTO-01 fix must come first or be bundled with #346. |
| CRYPTO-03 (HPKE not RFC 9180) | #312 (domain separator mismatch) | #312 fixes the info string. CRYPTO-03 says the entire construction is wrong. Fixing only the string while leaving the bespoke ECDH+HKDF is insufficient. Must resolve together. |
| ADR-016-C3 (nonce format) | #313 (dedup TTL) | #313 changes TTL from 1hr to 24hr. ADR-016-C3 says the nonce format itself is contradictory (UUID v4 vs timestamp-hex). The TTL fix is pointless if the format is wrong. |
| 12.6-001 (bridge MLS) | #370 (bridge zero FFI) | #370 tracks missing FFI exposure for bridge module. But the bridge module itself can't work for encrypted contexts until the MLS membership model is decided. |
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
| `scp-ffi/src/context.rs` | #300, #328, #332, #336, #356, #369 | #300 → #356 → #328/#332/#336/#369 |
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

  S-A: Canonical serialization spec          S-B: UCAN nonce format fix
       (CRYPTO-01, CRYPTO-12, CRYPTO-13)          (ADR-016-C3)
       Define CanonicalHash trait pattern          Pick {unix_millis}-{hex16}
       Add length prefixes to all formulas         Update ADR-016 mint_ucan

  S-C: Versioning spec (§13)                 S-D: Bridge MLS model decision
       (H-28–H-32, 13-002)                       (12.6-001, 12.6-002, 12-SECURITY)
       Define version field, negotiation,          Decide: bridge joins MLS group?
       forward compat, degraded mode               Add threat model for bridge operators

  S-E: Identity private state spec           S-F: Sender key crypto spec
       (03-IDENTITY-1, 03-IDENTITY-2)             (CRYPTO-03, CRYPTO-04)
       Specify encryption algo, multi-device       Specify RFC 9180 mode + nonce gen
       Specify social/device recovery              Specify wire format with nonce field

  S-G: Sync protocol anti-replay             S-H: Context nesting eligibility
       (ADR-029-C3)                                (5.13.2)
       Add nonce to ResetRequest                   Specify mechanism for relay to verify
       Add freshness binding                       parent membership in encrypted contexts
```

### What Can Run In Parallel With Spec Track (existing code issues, no spec dependencies)

```
CODE TRACK (Phase 1 — same as before):

  C-A: #345,#313  C-B: #348  C-C: #354,#355,#291,#350  C-D: #301
  C-E: #353       C-F: #349→#357→#360→#320 (governance serial chain)
```

### What CANNOT Start Until Spec Decisions Land

| Code Work | Waiting On Spec |
|---|---|
| #346 (sender key wire format) | S-A (canonical serialization) + S-F (HPKE/nonce) |
| #312 (HPKE domain separator) | S-F (RFC 9180 mode decision) |
| #351, #290 (envelope types) | S-A (length prefix pattern) |
| #338 (envelope pipeline) | S-A + #356 (both) |
| #313 (dedup TTL) | S-B (nonce format) |
| #319, #326 (UCAN security) | S-B (nonce format) |
| SCP-BCH-* (bridge cooperative) | S-D (bridge MLS model) |
| #324 (MLS epoch conflict) | S-G (ResetRequest anti-replay) |
| SCP-BA-* (participation admission) | S-A (canonical serialization for profiles) |
| #352 (BroadcastEnvelope fields) | S-F (broadcast key nonce) |

---

## Revised Execution Phases

### Phase 0: Spec Fixes (NEW — max parallelism, spec-only)

8 parallel lanes. All are spec/ADR document changes. No code changes. No inter-lane dependencies. Target: resolve all hard-block spec gaps before implementation proceeds.

**Lane S-A** — Canonical Serialization Pattern
- Define `CanonicalHash` construction: 4-byte BE length prefix on all variable-length fields + domain separator prefix
- Update: SS9 §9.5 (line 214, 216), SS7 §7.4.1, §7.3.2.1, ADR-002 criterion 2
- Template: migration proof at SS9 line ~350

**Lane S-B** — UCAN Nonce Format Resolution
- Pick `{unix_millis}-{hex16}` (matches validation step 9 and implementation)
- Update: ADR-016 mint_ucan criterion 3 (remove "UUID v4 or 32 random bytes")

**Lane S-C** — Protocol Versioning (§13)
- Define version number, wire format field, negotiation mechanism, forward compat rules, degraded mode
- Update: SS13 (currently 10 lines → needs full spec section)
- Add version field to InnerEnvelope and BroadcastEnvelope structs

**Lane S-D** — Bridge MLS Membership Model
- Decide architectural question: bridge as MLS group member (degrades E2E) or alternative access model
- Add bridge operator threat model to SS9 §9.2
- Update: SS12 §12.6, §12.10.5, §12.10.7

**Lane S-E** — Identity Private State
- Specify encryption: X25519 key derived from Ed25519 Identity Key via RFC 7748, AES-256-GCM
- Specify multi-device: key sharing via HPKE to device-specific X25519 keys
- Specify social/device recovery: quorum threshold, wire format, failure semantics
- Update: SS3 §3.3, §3.7

**Lane S-F** — Sender Key & Broadcast Crypto
- Specify RFC 9180 HPKE Base mode with explicit suite ID, info string, AAD
- Specify nonce: random 12-byte per encryption, included in wire format
- Add nonce field to BroadcastEnvelope struct
- Update: SS9 §9.16.1, §9.16.2, SS5 §5.14.5, ADR-007

**Lane S-G** — Sync Protocol Anti-Replay
- Add nonce + timestamp + challenge-response freshness to ResetRequest
- Update: ADR-029 §4, SS23 §23.5.2

**Lane S-H** — Context Nesting Eligibility
- Specify mechanism for relay to verify parent membership for encrypted contexts
- Options: membership attestation, governance-signed eligibility proof, or remove relay-level validation for encrypted nesting
- Update: SS5 §5.13.2

### Phase 1: Surgical Code Fixes (max parallelism, no dependencies)

7 parallel lanes. All branch from `main`. No inter-lane dependencies.
**Requires:** Phase 0 lanes S-A, S-B, S-F merged (for lanes B, C that touch affected files).

**Lane A** — `fix/wire-format-transport` (#345, #313)
- scp-transport: serde rename annotations + TTL fix
- **Requires S-B merged** (nonce format affects TTL/dedup)

**Lane B** — `fix/sender-key-wire-format` (#312, #346)
- scp-core: HPKE domain separator + 4 wire format fixes + length prefixes + nonce field
- **Requires S-A + S-F merged** (canonical serialization + HPKE mode)

**Lane C** — `fix/envelope-types` (#351, #290)
- scp-core: deny_unknown_fields + signaling message binding + length prefixes in signature
- **Requires S-A merged** (canonical serialization pattern)

**Lane D** — `fix/store-serialization` (#348)
- scp-core: positional → named MessagePack

**Lane E** — `fix/broadcast-bugs` (#353, #352)
- scp-core: block_subscriber scope + BroadcastEnvelope fields + nonce field
- **Requires S-F merged** (broadcast key nonce)

**Lane F** — `fix/misc-standalone` (#354, #355, #291, #350)
- 4 separate crates/files, no conflicts

**Lane G** — `fix/node-dev-api` (#301)
- scp-node: wire real metrics

### Phase 2: Governance Cleanup (serial — same files)

**Branch:** `fix/governance-types` from `main` post-Phase 1
- #349 → #357 → #360 (all touch `manager.rs` or `governance/mod.rs`)
- Then: `feat/governance-actions` (#320) — 12 missing variants

### Phase 3: Security Hardening (parallel, needs Phase 1 merged)

**Lane A** — `fix/deser-limits` (#347) — needs #345, #346 merged (same files)
**Lane B** — `fix/ucan-security` (#299, #319, #326) — needs S-B merged
**Lane C** — `fix/governance-enforcement` (#339, #340) — needs Phase 2 merged
**Lane D** — `fix/timestamp-validation` (#321) — needs Phase 1 Lane C merged

### Phase 4: Identity Infrastructure (parallel with Phases 2-3)

**Lane A** — `fix/identity-persistence` (#327 → #310 → #311)
**Lane B** — `fix/identity-features` (#315, #325)

### Phase 5: Core Infrastructure (CRITICAL PATH — sequential)

**Step 1:** `feat/production-providers` (#300)
**Step 2:** `refactor/ffi-context-manager` (#356) — depends on #300
  - Closes: #328, #332, #329
**Step 3:** `feat/envelope-pipeline` (#338) — depends on #356 + S-A

### Phase 6: MLS, Encryption & Content Access (depends on Phase 5)

**Step 1:** #333 (MLS integration) — **requires S-H merged**
**Step 2:** #324 (MLS epoch conflict) — **requires S-G merged**
**Step 3:** #314 (MLS LeafNode extension)
**Step 4:** #309 (ADR-038 content access control) — unlocks SCP-CAC-*
**Step 5:** #317 (SDK-mandated state destruction)

Then content access PRD (serial — same subsystem, depends on #309):
SCP-CAC-001 → SCP-CAC-002 → SCP-CAC-003 → SCP-CAC-004 → SCP-CAC-005 → SCP-CAC-006 → SCP-CAC-007 → SCP-CAC-008 → SCP-CAC-009 → SCP-CAC-010

### Phase 7: Governance Integration (depends on Phase 2 + Phase 5)

Governance PRD (serial — each builds on prior, all touch `manager.rs`):
SCP-267 → SCP-268 → SCP-269 → SCP-270 → SCP-271 → SCP-272 → SCP-273 → SCP-274

- SCP-267–268 need #356 (ContextManager wiring)
- SCP-269–270 need #320 (all 24 governance actions)
- SCP-272 needs #354 (conflict detection)
- SCP-273 needs #330 (provenance/checkpoint fields)

### Phase 8: Feature Completions (parallel, depends on Phase 5)

**Lane A:** #335 (broadcast transport), SCP-227 (subscriber registration — in-progress)
**Lane B:** #336, #337, #334 (context features)
**Lane C:** #318, #330 (trust/provenance wiring)
**Lane D:** #316, #323 (identity features)
**Lane E:** #302, #305, #342 (node/relay production)

### Phase 9: SDK Bindings (depends on Phase 5)

**Lane A:** #306, SCP-218 (WASM bridge wiring) → #341 (TypeScript SDK)
**Lane B:** #307, SCP-220, SCP-221 (UniFFI bridge + Swift wiring) → #331 (Swift Trust/MCP)
**Lane C:** SCP-214 (KeyCustodyProvider callbacks across all FFI bridges) — needs #356
**Lane D:** #322 (cross-context tool interfaces)
**Lane E:** SCP-215 (error code range audit — independent)
**Lane F:** #304 (Go/Java/C#)
**Lane G:** SCP-116 → SCP-117 → SCP-118 → SCP-120 (Kotlin SDK completion)

### Phase 10: New Features (partially blocked by spec)

**Lane A:** SCP-ACR-001–007 (capability registry) — independent, can start now
**Lane B:** SCP-BCH-001–009 (bridge cooperative + credentials) — **BLOCKED by S-D** (bridge MLS model)
**Lane C:** SCP-BA-001–006 (participation admission) — **soft-blocked by S-A** (canonical serialization for profiles)
**Lane D:** #362, #363, #364, #365, #366, #367
**Lane E:** SCP-038 (PyO3 identity bridge — in-progress), SCP-092 (signaling — in-progress, needs #290)

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

### Phase 12: Polish

#291, #301, #303, #343, #344

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
PHASE 5: #300 → #356 → #338 [needs S-A] (closes #328,#332,#329)
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

## Totals

| Category | Count |
|----------|-------|
| GitHub issues | 80 |
| PRD stories (unfinished) | 52 (across 6 PRDs) |
| PRD stories (done) | 272 |
| Spec audit: NEW CRITICALs | 11 |
| Spec audit: NEW HIGHs | 37 |
| Spec audit: PARTIALLY TRACKED (need issue expansion) | ~106 |
| Auto-closed by root cause (#356) | 3 |
| GH issue provenance errors | 25 broken spec refs, 3 factual inaccuracies, 18 missing dep declarations |
| **Total open work items** | **177** |
| **Net after auto-close** | **174** |

### PRD Breakdown

| PRD | Done | Unfinished | Blocked By |
|-----|------|------------|------------|
| main.json | 173 | 12 | #356, #290, #306, #307 |
| content-access.json | 0 | 10 | #309 (Phase 6), #356 |
| governance-integration.json | 0 | 8 | #356, #320 (Phase 2) |
| capability-registry.json | 0 | 7 | — (independent) |
| bridge-cooperative.json | 0 | 9 | **Phase 0 S-D** (bridge MLS model) |
| participation-admission.json | 0 | 6 | Phase 0 S-A (soft) |
| agent-binding.json | 22 | 0 | — |
| http-features.json | 8 | 0 | — |
| persistence.json | 36 | 0 | — |
| reachability.json | 16 | 0 | — |
| transport-expansion.json | 17 | 0 | — |

---

## Critical Path Timeline

```
         WEEK 1              WEEK 2              WEEK 3              WEEK 4
    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
    │  PHASE 0    │    │  PHASE 1    │    │  PHASE 5    │    │  PHASE 6    │
    │  Spec fixes │───→│  Code fixes │───→│  #300→#356  │───→│  MLS chain  │
    │  (8 lanes)  │    │  (7 lanes)  │    │  →#338      │    │  #333→#317  │
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
