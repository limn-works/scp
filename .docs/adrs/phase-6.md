# Phase 6 Architecture Decision Records — Android, Kotlin, Scale Hardening, Advanced Governance

**Date:** February 23, 2026
**Phase goal:** Android platform, Kotlin SDK, scale hardening, security audit, advanced governance, offline strategy.
**Timeline:** Weeks 21+

**Note:** All Phase 6 ADRs are Pending. Phase 6 follows Phases 1-5 implementation and depends on real-world implementation experience for concrete decisions. Each ADR below documents the decision space, known constraints, and approach guidance — enough for the Loom to know what's NOT decided and what to reference instead.

**Dependencies between ADRs:**

```
Phase 1-5 ADRs
       |
       ├── ADR-027 (Android) <── ADR-021 (UniFFI) + ADR-025 (Apple reference)
       │        |
       │        v
       ├── ADR-028 (Kotlin) <── ADR-027 + ADR-021 + ADR-026 (Swift reference)
       │
       ├── ADR-029 (Offline/Sync) <── Phase 1-2 implementation + empirical data
       ├── ADR-030 (Event Log Pruning) <── Phase 2 event log + empirical data
       └── ADR-031 (Multi-Admin Governance) <── Phase 2 UCAN + single-admin governance
```

---

## ADR-027: Android Platform Adapter

**Status:** Pending

### What This ADR Will Decide

Platform-specific implementations for Android: Android Keystore key custody, Play Integrity device attestation, FCM push notification delivery, and Android-specific storage encryption (TEE-backed key derivation for SQLCipher).

### Blockers

- Phase 1-2 Rust core must be implemented.
- ADR-021 (UniFFI) must define the FFI bridge.
- ADR-025 (Apple platform) serves as reference — Android adapter mirrors its structure.

### Required Inputs When Writing

- Same platform trait signatures as ADR-025 (`KeyCustody`, `PushProvider`, `DeviceAttestation`, `Storage`).
- Android Keystore capability by API level: Ed25519 support requires API 33+ (Android 13+).
- FCM payload constraints and opacity requirements.
- Play Integrity API integration pattern (standard vs classic).
- TEE availability vs StrongBox availability across device ecosystem.

### References

- §17.8 — Android Keystore: TEE-backed, API 33+ for Ed25519. StrongBox available but dramatically slow.
- §9.12 — Compromise recovery (same 6 steps, Android-specific key rotation).
- §9.15 — Key destruction verification (Android Keystore attestation).
- `scaffold/kotlin.md` — Gradle/KTS build, UniFFI bridge, coroutine patterns.
- `standards/kotlin.md` — Kotlin coroutines, JVM 11+, ktlint + detekt.
- ADR-025 — Apple adapter as parallel reference.

### Expected Decisions

- **Minimum API level:** API 33+ for Ed25519 Keystore, or software fallback for older devices.
- **TEE vs StrongBox policy:** Performance vs security tradeoff — StrongBox operations are dramatically slower than TEE-backed operations.
- **FCM payload format:** Parallel to APNs opacity decision in ADR-025.
- **Play Integrity integration level:** Standard requests vs classic attestation.
- **SQLCipher key derivation:** TEE-backed key derivation for database encryption key.

### Optimal Approach

Write after ADR-025 (Apple). Mirror the Apple adapter structure. Test on physical devices — emulator Keystore behavior differs from hardware.

### Scope

`scp-platform/android/` — ~5 files, ~20 functions.

---

## ADR-028: Kotlin SDK

**Status:** Pending

### What This ADR Will Decide

Kotlin SDK ergonomics layer on UniFFI-generated bindings. Covers coroutine integration, Android lifecycle awareness, Jetpack Compose integration, and Maven Central distribution.

### Blockers

- ADR-021 (UniFFI) must produce the UDL.
- ADR-027 (Android platform) must be written.
- ADR-026 (Swift SDK) serves as reference — parallel structure.

### Required Inputs When Writing

- UniFFI-generated Kotlin types and suspend functions.
- Android platform adapter implementations.
- Cross-platform conformance test suite.

### References

- `scaffold/kotlin.md` — package structure, UniFFI bridge, coroutine patterns, Gradle build.
- `standards/kotlin.md` — `kotlinx.coroutines`, `Dispatchers.IO` for FFI, JUnit 5, JVM 11+.
- `scaffold/shared.md` — cross-language naming, conformance tests.
- ADR-026 (Swift SDK) as parallel reference, ADR-014 (Python SDK) as pattern.

### Expected Decisions

- **Coroutine dispatcher strategy:** Which operations run on `Dispatchers.IO` vs `Dispatchers.Default`.
- **Flow vs Channel** for streaming (`Flow` preferred for cold streams, `Channel` for hot).
- **Android lifecycle integration:** `LifecycleOwner`-aware cleanup of SCP resources.
- **Jetpack Compose integration:** State holders, `remember` patterns.
- **Maven Central publishing configuration** (`com.limn:scp-sdk-kotlin`).

### Optimal Approach

Write after ADR-026 (Swift SDK). Mirror Swift ergonomics decisions where applicable. Kotlin/Swift parallels are strong (both use UniFFI, both have async/await, both have reactive frameworks).

### Scope

`bindings/kotlin/` — ~10 files, ~30 functions.

---

## ADR-029: Offline/Sync Strategy

**Status:** Pending

### Why This Is the Hardest Problem

Architecture.md §9 explicitly flags offline MLS re-sync as "the hardest unsolved problem." Members offline for extended periods accumulate pending MLS proposals. Group state reset trigger conditions, initiation protocol, and context lifecycle during reset are all unspecified.

### What This ADR Will Decide

How devices that have been offline (hours to days) rebuild full context state. Conflict resolution for concurrent offline operations. MLS re-sync protocol for long-offline members. Sync strategy for multi-device scenarios.

### Blockers

- Phase 1-2 implementation must be complete — need real MLS group behavior data.
- Phase 2 multi-relay delivery must be tested — offline resilience depends on relay behavior.
- Need empirical data: typical offline duration distribution, MLS epoch accumulation rates, context state growth rates.

### Known Constraints

- Devices are full protocol participants (§10.2), not thin clients.
- SCP does not require synchronized clocks (§9.8.3).
- KeyPackages pre-published for offline member addition (§9.6).
- SDK SHOULD issue MLS Update after reconnecting (§9.12).
- 30-second gap timeout, 100-message buffer (§9.8.5 reorder buffer spec).
- Relays provide availability but are untrusted.

### Open Questions That Block This ADR

- Conflict resolution for concurrent offline governance changes (two admins both offline, both propose role changes).
- Full state reconstruction semantics after extended offline (what's authoritative vs derivable).
- Standing bilateral context lifetime vs offline duration (weeks-offline scenario).
- MLS group state reset: trigger conditions, who initiates, what happens to in-flight messages.

### References

- §10.2 — Device as node design.
- §9.8.3 — Timestamp model (no synchronized clocks).
- §9.8.5 — Message gap handling (30s timeout, 100-message buffer).
- §9.6 — KeyPackage pre-publication for offline members.
- §9.12 — Compromise recovery (MLS Update after reconnect).
- `00-open-questions.md` — Offline/sync flagged as uncovered area.

### Expected Approach Directions (Not Decisions)

- **Hours-scale offline:** Relay buffering + MLS catch-up (likely works with current design).
- **Days-scale offline:** State snapshot + delta sync (needs design).
- **Weeks-scale offline:** Forced re-join with state reset (needs design).
- **Conflict resolution:** Last-writer-wins for metadata, Merkle tree for event ordering, governance deadlock = context fork.

### Optimal Approach

Implement Phase 1-2, run stress tests with simulated offline scenarios (`NetworkSimulator` from §16.8 with partition topologies). Gather data on MLS epoch accumulation, state divergence patterns, and recovery complexity. Then design the sync protocol from empirical evidence.

---

## ADR-030: Event Log Pruning and Checkpointing

**Status:** Pending

### What This ADR Will Decide

How append-only Merkle event logs (ADR-011) manage unbounded growth. Checkpoint strategy, pruning rules, proof compaction, and availability requirements for historical events.

### Blockers

- Phase 2 event log implementation must be running with real contexts.
- Need empirical data: typical event log growth rates per context type, device storage constraints, proof verification frequency.

### The Core Tension

Event logs are verifiable because they're append-only. Pruning breaks append-only. The protocol must balance verifiability (full history provable) with storage (unbounded growth unsustainable on mobile devices).

### Known Constraints

- Protocol state footprint is deliberately minimal (§10.3): membership, roles, tokens, tool registrations, governance, content hashes — NOT content itself.
- Event logs are per-context Merkle trees with SHA-256 hash chain (ADR-011).
- Must support inclusion proofs and consistency verification.
- Behavioral validation (§7.3.1) depends on verifiable event logs.

### Design Space (Not Decisions)

1. **Full log forever** — simplest, unbounded storage.
2. **Periodic checkpoints** (Merkle root snapshots) + pruned older entries — compresses, complicates proof verification.
3. **Distributed log shards** — scales, adds availability complexity.
4. **Tiered storage:** hot (recent, on-device) + cold (old, relay-hosted, proof-fetchable).

### References

- ADR-011 — Event log design (append-only, Merkle tree, entry structure).
- §10.3 — Protocol state footprint.
- §7.3.1 — Verifiable event logs (behavioral validation depends on them).
- §17.4 — ProtocolStore event log key convention (zero-padded sequences).

### Optimal Approach

Implement Phase 2 event logs. Monitor growth rates in test scenarios. Profile proof generation/verification cost. Then design checkpointing with concrete numbers.

---

## ADR-031: Multi-Admin Governance Models

**Status:** Pending

### What This ADR Will Decide

Governance models beyond single-admin (Phase 2 baseline). Multi-sig (M-of-N), consensus (majority/supermajority), weighted voting. Proposal lifecycle, quorum rules, voting windows, deadlock recovery.

### Blockers

- Phase 2 single-admin governance (ADR-008) must be implemented and tested.
- Phase 2 UCAN validation (ADR-016) must be running — governance actions are UCAN-authorized.
- Need to understand how governance proposals interact with MLS epoch advances and context state.

### Known Constraints

- Governance is a pluggable interface (§5.9): protocol defines propose/approve/reject, implementations vary.
- Context governance controls: role changes, membership, settings, ceiling expansion, interface decisions (§5.9).
- Exit as veto: members can leave if governance makes unacceptable decisions (§9.2.1).
- Governance actions are context events in the Merkle log — auditable and verifiable.

### Open Questions That Block This ADR

- Proposal message format (structured event type in Merkle log).
- Quorum rules per model type (majority? supermajority? unanimity for which actions?).
- Voting window duration and timeout handling.
- Multi-sig semantics: order-sensitive or order-independent? Withdrawal allowed?
- Consensus deadlock recovery: what if N-of-M signers are unavailable?
- Interaction with UCAN: who holds the governance UCAN? How is it delegated in multi-admin?

### References

- §5.9 — Context governance model (pluggable interface).
- §9.2.1 — Security boundaries (exit as veto, single-admin as minimum).
- ADR-008 — Context lifecycle state machine (single-admin governance).
- ADR-009 — Role assignment and capability ceiling.
- ADR-016 — UCAN validation.

### Expected Approach

Define the governance interface contract (propose/approve/reject with typed proposals). Implement three concrete models:

1. **Multi-sig (M-of-N threshold):** Simplest semantics, most useful, least ambiguous. A proposal passes when M of N designated signers approve.
2. **Majority vote (>50%):** Each member gets one vote. Proposal passes at majority. Suitable for peer groups.
3. **Unanimity (all members):** Every member must approve. Suitable for high-stakes decisions (ceiling changes, context closure).

Each model implements the same governance interface. Start with multi-sig — simplest semantics, most useful for the common case of "2-of-3 admins."

### Optimal Approach

Implement Phase 2 single-admin. Identify governance pain points from real context operation. Design multi-admin to solve observed problems, not hypothetical ones.
