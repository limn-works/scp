# Phase 6 Architecture Decision Records — Android, Kotlin, Scale Hardening, Advanced Governance

**Date:** February 23, 2026
**Phase goal:** Android platform, Kotlin SDK, scale hardening, security audit, advanced governance, offline strategy.
**Timeline:** Weeks 21+

**Note:** Phase 6 follows Phases 1-5 implementation. ADR-029 (Offline/Sync) and ADR-030 (Event Log Pruning) are Decided. Remaining ADRs (ADR-027, ADR-028, ADR-031) are Pending and depend on real-world implementation experience for concrete decisions. Each Pending ADR below documents the decision space, known constraints, and approach guidance — enough for the Loom to know what's NOT decided and what to reference instead.

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

**Status:** Decided

### Context

Architecture.md §6 explicitly flags offline MLS re-sync as "the hardest unsolved problem" with High likelihood and High impact. Members offline for extended periods accumulate pending MLS proposals and Commits. The group state advances without them — epochs increment, sender keys rotate, members join and leave, governance actions execute. When the offline member reconnects, they must reconcile their stale local state with the group's current state. The difficulty is that MLS requires sequential epoch processing (each Commit depends on the previous epoch's key schedule), forward secrecy means old epoch keys are destroyed after the grace window (ADR-001 criterion 6), and relays are untrusted infrastructure that may or may not retain the full message history.

SCP's design makes this simultaneously harder and easier than in traditional messaging systems. Harder: devices are full protocol participants (§10.2), not thin clients that can ask a server for the current state. There is no authoritative server — only relays holding encrypted blobs and peers holding decrypted state. Easier: the verifiable event log (ADR-011) provides a cryptographic mechanism for state reconciliation — two members can compare Merkle roots and prove exactly where their views diverge. The protocol's minimal state footprint (§10.3) means what needs syncing is small: membership, roles, tokens, tool registrations, governance, and event hashes — not content.

This ADR defines the offline/sync strategy across three time horizons (hours, days, weeks), resolves conflict semantics for concurrent offline operations, specifies the MLS epoch catch-up protocol, and defines when and how group state resets occur.

### Scope

**What this ADR covers:**

- Client-side message queue for outbound messages during disconnection.
- Reconnection protocol: relay catch-up, MLS epoch reconciliation, event log sync.
- Offline duration tiers and the strategy for each (hours, days, weeks).
- MLS group state reset: trigger conditions, initiation protocol, member lifecycle during reset.
- Conflict resolution for concurrent offline governance and membership changes.
- Sender key re-acquisition after missed rotations.
- Multi-device sync coordination for offline/online transitions.

**What this ADR does NOT cover:**

- Content storage and retrieval (app-layer, §10.6).
- Event log pruning and checkpointing (ADR-030).
- Multi-admin governance conflict resolution beyond single-admin (ADR-031).
- Real-time media session recovery (§10.9.1 — media sessions are ephemeral and do not survive disconnection).

### Decision

Implement a three-tier offline/sync strategy in `scp-core/sync/` that classifies offline durations and applies progressively stronger reconciliation mechanisms. The tiers are: **Tier 1 (Short offline, < 4 hours)** using relay buffering and sequential MLS catch-up; **Tier 2 (Extended offline, 4 hours to 7 days)** using state snapshot comparison and delta sync with selective epoch reconstruction; and **Tier 3 (Long offline, > 7 days)** using forced re-join via MLS group state reset. All tiers use the Merkle event log (ADR-011) as the authoritative state reconciliation mechanism and the relay's store-and-forward capability (ADR-004) as the primary message recovery path.

#### 1. Client-Side Outbound Queue

When the SDK detects disconnection (all relay WebSocket connections lost), outbound messages are queued locally rather than dropped.

The outbound queue operates as follows:

- Messages are serialized to their inner envelope form (signed, padded) and stored in `ProtocolStore` under `queue/{context_id}/{seq:020d}`. The inner envelope is fully constructed (including signature and padding) but NOT MLS-encrypted — MLS encryption requires the current epoch's key schedule, which may advance while offline. MLS encryption is applied at drain time using the then-current epoch.
- The queue is bounded at 1,000 messages per context and 10,000 messages total across all contexts. When full, the oldest messages are dropped with a `QueueOverflow` event emitted to the application layer.
- Queue entries include a `queued_at` timestamp. On reconnection, entries older than the context's `blob_ttl` (or 7 days if no TTL) are discarded — they would expire on relays before delivery anyway.
- The queue drains automatically on reconnection, after MLS epoch catch-up completes. Messages are MLS-encrypted with the current epoch's key schedule and sent in queue order.

```rust
pub struct QueuedMessage {
    pub context_id: ContextId,
    pub inner_envelope: Vec<u8>,  // Serialized, signed, padded inner envelope
    pub queued_at: u64,           // Unix timestamp when queued
    pub sequence: u64,            // Local queue sequence (for ordering)
}

pub struct OutboundQueue {
    store: Arc<ProtocolStore>,
    per_context_limit: usize,     // Default: 1_000
    total_limit: usize,           // Default: 10_000
}
```

#### 2. Reconnection Protocol

On reconnection (at least one relay WebSocket connection re-established), the SDK executes the following ordered protocol:

**Phase 1 — Relay catch-up.** For each active context, re-issue `SUBSCRIBE` with `since` = last received `stored_at` minus 5-second overlap (ADR-004 Connection Recovery). Process all backfilled blobs. Deduplicate by `blob_id` (ADR-012 dedup cache). This recovers all messages that relays retained during the offline period.

**Phase 2 — MLS epoch reconciliation.** For each context, compare the local MLS epoch number against the epoch numbers in received messages. If the local epoch is behind, enter the epoch catch-up procedure (section 3 below). If epochs match, the context is current.

**Phase 3 — Event log sync.** For each context, exchange consistency checkpoints (ADR-011 criterion 8) with online members. Compare Merkle roots. If roots match at the same event count, the logs are consistent. If they diverge, identify the first divergent event and resolve (section 5 below).

**Phase 4 — Sender key re-acquisition.** For each context, check for `SenderKeyEpochAdvance` events received during catch-up. For any sender whose key epoch has advanced beyond the locally cached version, issue `SenderKeyRequest` (ADR-007 criterion 4c) to obtain the current key. Messages encrypted with missed sender key epochs are buffered until the key is obtained or a 60-second timeout expires. After timeout, those messages are marked as `UnrecoverableSenderKey` and the application layer is notified.

**Phase 5 — MLS Update.** After catch-up is complete, the SDK issues an MLS Update proposal in each active context (§9.7.3: "SDK SHOULD issue an Update after re-establishing connectivity following an offline period"). This provides post-compromise security for the reconnecting member.

**Phase 6 — Queue drain.** Drain the outbound queue for each context. Each queued inner envelope is MLS-encrypted with the current epoch's key schedule and sent. If a queued message references a context that no longer exists (closed or expired while offline), the message is discarded with a `ContextGone` notification to the application layer.

#### 3. MLS Epoch Catch-Up (Tier 1 and Tier 2)

MLS requires sequential epoch processing — each Commit depends on the previous epoch's key schedule. An offline member at epoch E who reconnects to find the group at epoch E+N must process all N intermediate Commits in order.

**Commit recovery sources (tried in order):**

1. **Relay backfill.** MLS Commits are sent as MLS `PublicMessage` (Commit messages are not application messages; they are protocol messages delivered via the transport layer). Relays store them like any other blob. If the relay's retention covers the offline period, all Commits are recoverable.
2. **Peer request.** If relays have expired some Commits (blob_ttl elapsed), the reconnecting member broadcasts a `CommitRangeRequest { context_id, from_epoch, to_epoch }` as an MLS application message (using their current epoch keys — they can still encrypt at their stale epoch). Online members who have persisted the Commit messages respond with the missing Commits. This is a best-effort protocol — members are not required to retain raw Commit messages beyond the MLS grace window.
3. **Welcome-based fast-forward.** If the epoch gap is too large (> 100 epochs or no member can provide the full Commit chain), the reconnecting member is treated as a new joiner. An online admin (or any member with `MemberInvite` capability) generates a fresh Welcome message for the reconnecting member's pre-published KeyPackage, effectively re-adding them to the group at the current epoch. The member's old leaf node is removed. This is the Tier 2 fallback — it preserves membership and context continuity but the member loses access to messages encrypted in epochs between their stale epoch and the current epoch (forward secrecy is maintained).

**Epoch catch-up limits:**

- The SDK processes at most 100 sequential Commits per catch-up attempt. If more than 100 Commits are pending, the SDK switches to Welcome-based fast-forward.
- Each Commit is processed within a 5-second timeout. Commits that fail to process (corrupted, missing dependencies) are logged as `EpochCatchUpFailure` and the SDK falls through to the next recovery source.
- The 100-Commit limit is a practical bound. In a context with 24-hour PCS Update intervals and 10 members, 100 Commits represents roughly 10 days of activity. Contexts with higher churn (frequent joins/leaves) may hit this limit sooner.

```rust
pub struct EpochCatchUpState {
    pub context_id: ContextId,
    pub local_epoch: u64,
    pub target_epoch: u64,
    pub commits_processed: u64,
    pub status: CatchUpStatus,
}

pub enum CatchUpStatus {
    /// Sequential Commit processing in progress.
    Processing,
    /// All epochs caught up successfully.
    Complete,
    /// Fell back to Welcome-based fast-forward.
    FastForwarded { skipped_from: u64, skipped_to: u64 },
    /// Catch-up failed — context may need group reset.
    Failed { reason: String },
}

pub struct CommitRangeRequest {
    pub context_id: ContextId,
    pub from_epoch: u64,
    pub to_epoch: u64,
    pub requester_did: DID,
    pub signature: Ed25519Signature,
}

pub struct CommitRangeResponse {
    pub context_id: ContextId,
    pub commits: Vec<Vec<u8>>,  // Serialized MLS Commit messages, in epoch order
    pub responder_did: DID,
    pub signature: Ed25519Signature,
}
```

#### 4. MLS Group State Reset (Tier 3)

When a member has been offline for more than 7 days, or when the epoch catch-up procedure fails (no recovery source can provide the Commit chain and no member can generate a Welcome), the member triggers a group state reset for their participation.

**Group state reset is NOT a group-wide operation.** It affects only the offline member's participation. The group continues operating normally. The reset is equivalent to: the offline member leaves and immediately re-joins.

**Trigger conditions (any one triggers reset):**

1. Offline duration exceeds 7 days (measured from last successful relay interaction timestamp, persisted in `ProtocolStore`).
2. Epoch catch-up fails: relay backfill, peer request, and Welcome-based fast-forward all failed.
3. The context's governance model explicitly requests reset (future: ADR-031 governance action).

**Reset protocol:**

1. The reconnecting member publishes a `ResetRequest { context_id, member_did, last_known_epoch, reason, signature }` via the relay (not MLS-encrypted — the member may not be able to encrypt at the current epoch). The request is signed by the member's Active Signing Key for authentication.
2. An online member with `MemberRemove` + `MemberInvite` capabilities (typically admin) processes the reset: (a) removes the offline member's stale leaf node via MLS `remove_member()`, (b) immediately re-adds the member using a fresh KeyPackage via MLS `add_member()`, (c) distributes the new Welcome message via relay.
3. The reconnecting member processes the Welcome, joining the group at the current epoch. They request sender keys for all current members via the pull-based protocol (ADR-007 criterion 4c).
4. The reconnecting member's outbound queue is drained using the new epoch's key schedule.
5. A `MemberReset` event (distinct from `MemberLeft` + `MemberJoined`) is appended to the event log, recording the reset reason, old epoch, new epoch, and the admin who processed it.

**What the reset member loses:**

- Access to messages encrypted in epochs between their last known epoch and the current epoch. Forward secrecy is preserved — old epoch keys were destroyed per ADR-001 criterion 6.
- Any pending governance proposals they initiated while offline (proposals reference specific epochs).
- Queue entries that reference the old epoch (re-queued messages are re-encrypted with the new epoch).

**What the reset member retains:**

- Their DID and identity.
- Their role in the context (the admin re-assigns the same role during re-add).
- Their event log history up to the last known epoch.
- Context metadata (params, tools, ceiling) — this is public and queryable via the metadata routing ID (ADR-004).

```rust
pub struct ResetRequest {
    pub context_id: ContextId,
    pub member_did: DID,
    pub last_known_epoch: u64,
    pub reason: ResetReason,
    pub timestamp: u64,
    pub signature: Ed25519Signature,
}

pub enum ResetReason {
    /// Offline duration exceeded the 7-day threshold.
    ExtendedOffline { offline_duration_secs: u64 },
    /// Epoch catch-up failed after exhausting all recovery sources.
    CatchUpFailed { attempted_sources: Vec<String> },
    /// Governance-initiated reset.
    GovernanceAction { proposal_id: String },
}
```

#### 5. Conflict Resolution

Concurrent offline operations create conflicts when two or more members make incompatible changes while unable to observe each other's actions. SCP resolves conflicts using three principles: (a) the Merkle event log order is authoritative (§9.14), (b) MLS epoch boundaries are synchronization points (§9.8.3), and (c) governance actions are serialized through the admin role (Phase 2 single-admin model).

**Conflict categories and resolution:**

**5a. Concurrent messages (no conflict).** Messages from different senders in the same epoch are ordered by `(epoch, sender_generation_number, timestamp)` per §9.8.3. Messages queued while offline receive fresh sequence numbers at drain time. No conflict — messages are independent.

**5b. Concurrent membership changes.** MLS serializes membership changes through Commits. Only one Commit can advance the epoch. If two members propose Add/Remove simultaneously, the first Commit to be processed wins; the second proposal becomes invalid (it references a stale epoch) and must be re-proposed. The reconnecting member detects this during epoch catch-up and re-issues any stale proposals.

**5c. Concurrent governance changes.** In Phase 2 (single-admin), governance changes are serialized through the admin. If the admin is offline, no governance changes can occur — this is by design. If a non-admin proposes a governance action while the admin is offline, the proposal is queued in the event log and processed when the admin reconnects. There is no conflict because governance is single-threaded.

For future multi-admin governance (ADR-031): if two admins both offline propose conflicting role changes, the conflict is resolved by Merkle log order — the first proposal to be committed to the log wins. The second admin's proposal is rejected as conflicting and must be re-proposed with awareness of the first. If both proposals are committed simultaneously (same event log sequence), the protocol treats this as a log fork — equivocation detection (§9.9.3) fires and the context enters a `GovernanceConflict` state requiring manual resolution by an admin with sufficient capability. This is the "governance deadlock = context fork" outcome from the stub — but formalized: the context is not forked automatically. Instead, it is frozen (no new governance actions) until an admin resolves the conflict.

**5d. Concurrent sender key rotations.** If a sender rotates their key while a peer is offline, the peer requests the new key on reconnection (Phase 4 of the reconnection protocol). If the sender rotated multiple times, only the current key is needed — intermediate keys are irrelevant (messages encrypted with intermediate keys during the offline period are recovered via relay backfill before the sender key was rotated, or are unrecoverable if the relay expired them).

**5e. Context closure or expiry during offline.** If a context was closed or expired while the member was offline, the reconnecting member discovers this during relay catch-up (the `ContextClosing`, `ContextClosed`, or `ContextExpired` events are in the backfill). The member processes the closure locally, destroys key material per the context's memory scope, and discards any queued messages for that context.

#### 6. Event Log Reconciliation

The Merkle event log (ADR-011) is the authoritative state record. After relay catch-up and epoch reconciliation, the SDK verifies event log consistency:

1. **Exchange checkpoints.** The reconnecting member generates a `ConsistencyCheckpoint` (ADR-011 criterion 8) from their local log state and sends it to the context. Online members compare and respond with their own checkpoints.
2. **Compare Merkle roots.** If roots match at the same event count, the logs are consistent — no further action.
3. **Behind.** If the reconnecting member's event count is less than the group's (the expected case after offline), the member requests the missing events via `CommitRangeRequest`-style event range requests. Events are verified by recomputing the Merkle path from each event to the known root.
4. **Divergent.** If Merkle roots differ at the same event count, equivocation has occurred (a relay showed different histories to different members, per §9.9.3). The reconnecting member raises a `EquivocationDetected` alert. Resolution follows the relay consistency protocol: identify the divergent relay, flag it in reliability scoring (ADR-012), and prefer the event chain signed by more members.

```rust
pub struct EventSyncRequest {
    pub context_id: ContextId,
    pub local_event_count: u64,
    pub local_merkle_root: [u8; 32],
    pub requester_did: DID,
    pub signature: Ed25519Signature,
}

pub struct EventSyncResponse {
    pub context_id: ContextId,
    pub remote_event_count: u64,
    pub remote_merkle_root: [u8; 32],
    pub events: Option<Vec<Event>>,  // Missing events if requester is behind
    pub responder_did: DID,
    pub signature: Ed25519Signature,
}
```

#### 7. Multi-Device Coordination

Multi-device sync during offline/online transitions follows the principle from §10.8: "the protocol delivers the same encrypted envelopes to all devices; the client decides how to present them."

Each device independently runs the reconnection protocol. There is no device-to-device coordination at the protocol level. However, the SDK provides hooks for client-layer coordination:

- **Reconnection deduplication.** If multiple devices reconnect simultaneously and all issue MLS Updates, the resulting epoch churn is harmless but wasteful. The SDK emits a `ReconnectionStarted { device_id, context_id }` event to the identity's private state log (§3.7, encrypted, synced across devices). Devices observing another device's reconnection event within a 30-second window defer their own MLS Update to avoid redundant epoch advances.
- **Queue deduplication.** Each queued message includes a content-addressable hash (`payload_hash` from ADR-002). If multiple devices queued the same message (e.g., user typed a message on phone, then opened laptop), the first device to drain delivers the message; the second device recognizes the duplicate `payload_hash` in the event log and discards the queued copy.

### Rationale

**Why three tiers instead of one unified strategy:**

The core tension is between simplicity and correctness. A single strategy that handles all offline durations either (a) is too conservative (always resets, losing message history even for short disconnections) or (b) is too optimistic (always tries sequential catch-up, hanging indefinitely when hundreds of epochs have passed). The three-tier approach matches the strategy to the problem scale:

- Tier 1 (< 4 hours) handles the common case — mobile devices sleeping, brief network outages, moving between WiFi and cellular. This is 95%+ of offline events. Relay buffering covers it with zero special handling beyond the existing connection recovery protocol (ADR-004).
- Tier 2 (4 hours to 7 days) handles the uncommon but important case — devices left offline overnight, travel without connectivity, hardware issues. Welcome-based fast-forward provides a clean recovery at the cost of losing access to messages encrypted in the skipped epoch range. This is an acceptable trade-off: the messages exist in the relay (if not expired) but cannot be decrypted due to forward secrecy. The member is informed of the gap.
- Tier 3 (> 7 days) handles the rare but catastrophic case — extended disconnection where relays have expired all buffered messages and no peer can reconstruct the Commit chain. Group state reset is the only option. This is the "hardest problem" case, and the answer is: treat it as a re-join, preserving identity and role but accepting the gap.

**Why 100-epoch catch-up limit:**

Sequential Commit processing is O(N) in the number of missed epochs. Each Commit requires tree ratcheting (MLS tree-based key management). At 100 Commits, this is several seconds of processing on mobile hardware. Beyond 100, the user experience degrades unacceptably, and the probability of encountering a corrupted or missing Commit in the chain increases. The Welcome-based fast-forward is O(1) — processing a single Welcome message regardless of how many epochs were missed.

**Why group reset is per-member, not group-wide:**

A group-wide reset would destroy all members' current key material and force everyone to re-establish. This is catastrophic for a group where only one member went offline. Per-member reset (leave + re-join) affects only the offline member's key state while the rest of the group continues uninterrupted.

**Why queued messages are not MLS-encrypted until drain:**

The MLS epoch may advance while the member is offline. Encrypting at queue time would bind the message to a stale epoch, making it undecryptable by members who have advanced. By deferring MLS encryption to drain time, queued messages are encrypted with the current (post-catch-up) epoch, ensuring all current members can decrypt them.

**Conflict resolution — why Merkle log order is authoritative:**

The alternative approaches (vector clocks, CRDTs, consensus protocols) all add complexity that SCP's architecture does not need. SCP's event log already provides a total order via the hash chain. The single-admin governance model (Phase 2) eliminates most governance conflicts by construction. The remaining conflicts (concurrent membership proposals) are resolved by MLS's natural serialization through Commits. Merkle log order is the tie-breaker because it is already the system of record — no new mechanism is needed.

### Implementation

- **Language:** Rust
- **Async runtime:** tokio (reconnection timers, concurrent relay catch-up, queue drain)
- **Crate:** `scp-core`
- **Module:** `scp-core/sync/`
- **Persistence:** Via `ProtocolStore` (§17.4) for queue state, last-seen timestamps, and catch-up progress. Key conventions:
  - `queue/{context_id}/{seq:020d}` — queued outbound messages
  - `sync/{context_id}/last_relay_contact` — last successful relay interaction timestamp
  - `sync/{context_id}/catch_up_state` — in-progress catch-up state (survives process restart)

### Dependencies

- **ADR-001 (MLS):** MLS epoch processing, Commit handling, Welcome message processing, Update proposal generation. The epoch catch-up and group reset protocols are built directly on MLS group operations.
- **ADR-004 (Native Relay):** Relay `SUBSCRIBE` with `since` parameter for backfill. Relay blob TTL determines the maximum Tier 1 offline duration. Connection recovery with exponential backoff (1s to 30s cap).
- **ADR-007 (Sender Keys):** Sender key re-acquisition via pull-based protocol after missed `SenderKeyEpochAdvance` events.
- **ADR-008 (Context Lifecycle):** Context state machine determines valid operations during catch-up. Context closure/expiry events discovered during reconnection trigger local cleanup.
- **ADR-011 (Event Log):** Merkle tree consistency checkpoints for state reconciliation. Inclusion proofs for verifying recovered events. Event log as authoritative ordering for conflict resolution.
- **ADR-012 (Multi-Transport):** Multi-relay subscription recovery. Relay reliability scoring — degraded relays that failed to retain messages during offline period are penalized.
- **ProtocolStore (§17.4):** Queue persistence, sync state persistence, event log range queries for catch-up.

### Acceptance Criteria

1. **`OutboundQueue` struct and operations:**

```rust
pub struct OutboundQueue {
    store: Arc<ProtocolStore>,
    per_context_limit: usize,
    total_limit: usize,
}

impl OutboundQueue {
    pub fn new(store: Arc<ProtocolStore>) -> Self;
    pub async fn enqueue(&self, msg: QueuedMessage) -> Result<(), QueueError>;
    pub async fn drain(&self, context_id: &ContextId, mls_group: &mut MlsGroup) -> Result<Vec<OuterEnvelope>, QueueError>;
    pub async fn discard_expired(&self, context_id: &ContextId, max_age_secs: u64) -> Result<u64, QueueError>;
    pub async fn discard_context(&self, context_id: &ContextId) -> Result<u64, QueueError>;
    pub async fn queue_depth(&self, context_id: &ContextId) -> Result<u64, QueueError>;
    pub async fn total_depth(&self) -> Result<u64, QueueError>;
}
```

   - `enqueue` stores a `QueuedMessage` in `ProtocolStore`. Returns `QueueError::ContextFull` or `QueueError::TotalFull` if limits are reached (oldest messages dropped).
   - `drain` MLS-encrypts each queued message with the current epoch and returns sealed outer envelopes ready for transport. Drains in queue order. Removes drained entries from storage.
   - `discard_expired` removes entries older than `max_age_secs`. Returns count discarded.
   - `discard_context` removes all entries for a context (used on context closure/expiry). Returns count discarded.

2. **`ReconnectionCoordinator` struct:**

```rust
pub struct ReconnectionCoordinator {
    context_manager: Arc<ContextManager>,
    transport_manager: Arc<TransportManager>,
    queue: Arc<OutboundQueue>,
    store: Arc<ProtocolStore>,
}

impl ReconnectionCoordinator {
    pub async fn on_reconnect(&self) -> ReconnectionReport;
}

pub struct ReconnectionReport {
    pub contexts_synced: Vec<ContextSyncResult>,
    pub messages_drained: u64,
    pub messages_discarded: u64,
    pub total_duration_ms: u64,
}

pub struct ContextSyncResult {
    pub context_id: ContextId,
    pub tier: OfflineTier,
    pub epochs_caught_up: u64,
    pub events_recovered: u64,
    pub messages_unrecoverable: u64,
    pub outcome: SyncOutcome,
}

pub enum OfflineTier {
    Short,     // < 4 hours
    Extended,  // 4 hours to 7 days
    Long,      // > 7 days
}

pub enum SyncOutcome {
    FullyCaughtUp,
    FastForwarded { skipped_epochs: u64 },
    Reset,
    ContextGone,  // Context was closed/expired while offline
    Failed { reason: String },
}
```

   - `on_reconnect` executes the six-phase reconnection protocol for all active contexts. Returns a report detailing per-context sync results.
   - Each context is synced concurrently (tokio tasks), with a 120-second overall timeout. Contexts that timeout are marked as `Failed`.

3. **`epoch_catch_up(context_id, local_epoch, target_epoch) -> Result<CatchUpStatus, SyncError>`**

   - Implements the three-source epoch catch-up: relay backfill, peer request, Welcome-based fast-forward.
   - Processes at most 100 sequential Commits with 5-second per-Commit timeout.
   - Falls back to Welcome-based fast-forward if sequential processing fails or the gap exceeds 100 epochs.
   - Returns `CatchUpStatus` indicating the outcome.

4. **`request_group_reset(context_id, reason) -> Result<(), SyncError>`**

   - Publishes a `ResetRequest` to the relay.
   - Waits for a Welcome message (60-second timeout).
   - On receipt, processes the Welcome, re-acquires sender keys, drains the queue.
   - Appends `MemberReset` event to the local event log.

5. **`sync_event_log(context_id) -> Result<EventSyncResult, SyncError>`**

   - Exchanges `ConsistencyCheckpoint` with online members.
   - Requests missing events if behind.
   - Verifies each recovered event against the Merkle tree.
   - Raises `EquivocationDetected` if Merkle roots diverge at the same event count.

6. **Offline tier classification:**

```rust
pub fn classify_offline_duration(last_relay_contact: u64, now: u64) -> OfflineTier {
    let duration_secs = now.saturating_sub(last_relay_contact);
    match duration_secs {
        0..=14_400 => OfflineTier::Short,          // < 4 hours
        14_401..=604_800 => OfflineTier::Extended,  // 4 hours to 7 days
        _ => OfflineTier::Long,                     // > 7 days
    }
}
```

7. **Event types added to `EventType` enum (ADR-011):**

```rust
// Additions to EventType in scp-core/event_log/
MemberReset {
    member_did: DID,
    old_epoch: u64,
    new_epoch: u64,
    reason: ResetReason,
    processed_by: DID,
},
QueueDrained {
    member_did: DID,
    message_count: u64,
    discarded_count: u64,
},
```

8. **Integration test (exercises all tiers):**

```
1. Alice and Bob create identities and a context (ADR-008).
2. Alice and Bob exchange messages (verify baseline).

--- Tier 1 test ---
3. Bob goes offline (transport disconnected).
4. Alice sends 5 messages while Bob is offline.
5. Bob reconnects. Relay backfill delivers all 5 messages.
   Bob processes MLS catch-up (if any epoch advanced). Bob's event log syncs.

--- Tier 2 test ---
6. Bob goes offline again. Simulate 50 epoch advances (members joining/leaving/updating).
7. Bob reconnects. Sequential catch-up processes all 50 Commits.
   Bob's event log catches up. Bob drains any queued messages.

8. Bob goes offline again. Simulate 150 epoch advances (exceeds 100-Commit limit).
9. Bob reconnects. Sequential catch-up processes first 100, then falls back to
   Welcome-based fast-forward. Bob re-joins at current epoch.
   Bob's event log records the fast-forward gap.

--- Tier 3 test ---
10. Bob goes offline. Simulate relay expiry of all buffered messages (TTL elapsed)
    AND epoch gap > 100 AND no peer can provide Commits.
11. Bob reconnects. Tier classification = Long. Bob issues ResetRequest.
    Alice (admin) processes reset: removes Bob, re-adds Bob with fresh Welcome.
    Bob joins at current epoch, re-acquires sender keys, drains queue.
    Event log records MemberReset.

--- Conflict resolution test ---
12. Bob and Alice both go offline simultaneously.
13. Both queue governance-irrelevant messages.
14. Both reconnect. Both drain queues. Messages interleave by timestamp.
    No conflict — messages from different senders are independent.

--- Context closure while offline ---
15. Bob goes offline. Alice closes the context.
16. Bob reconnects. Relay backfill contains ContextClosing + ContextClosed events.
    Bob processes closure, discards queued messages for that context, destroys keys.
```

### Scope

**Files (~5-7):**

| File | Purpose |
|------|---------|
| `mod.rs` | Module root, `OfflineTier`, tier classification, re-exports |
| `queue.rs` | `OutboundQueue`, `QueuedMessage`, queue persistence, drain logic |
| `reconnect.rs` | `ReconnectionCoordinator`, six-phase reconnection protocol, `ReconnectionReport` |
| `epoch_catch_up.rs` | `EpochCatchUpState`, three-source catch-up, `CommitRangeRequest`/`Response`, Welcome-based fast-forward |
| `reset.rs` | `ResetRequest`, `ResetReason`, group state reset protocol, `MemberReset` event |
| `event_sync.rs` | `EventSyncRequest`/`Response`, Merkle root comparison, event range recovery, equivocation detection |
| `conflict.rs` | Conflict classification, resolution strategies, governance conflict handling |

**Estimated functions:** ~20-25 public functions, ~15-20 internal helpers.

---

## ADR-030: Event Log Pruning and Checkpointing

**Status:** Decided

### Context

Every SCP context maintains an append-only Merkle event log (ADR-011) that records all protocol events — membership changes, governance actions, tool invocations, messages, role assignments, block notifications, and consistency checkpoints. The log is the foundation for behavioral validation (§7.3.1), equivocation detection (§9.9.3), and the trust model's Layer 2 (verifiable behavioral records, §7.3.2). Its append-only structure is what makes claims about context history verifiable rather than trust-dependent.

The problem is that event logs grow without bound. A long-lived context with active participants accumulates millions of events. Each event is a leaf in the Merkle tree, with interior nodes stored for proof generation (ADR-011, key convention: `context/{context_id}/event/{seq:020d}` for events, `context/{context_id}/event_tree/{level}/{index}` for tree nodes — §17.3). On mobile devices with constrained storage, maintaining full history for every active context is unsustainable. A context with 1 million events at ~200 bytes per event plus Merkle tree overhead consumes hundreds of megabytes for a single context.

The core tension is that pruning contradicts the append-only property that makes the log verifiable. Deleting old events means their content cannot be independently re-verified. The protocol must balance verifiability (full history provable) with storage reality (unbounded growth is not viable on resource-constrained clients). The solution is checkpointing: periodically capturing a signed snapshot of the full context state anchored to a specific Merkle root, then pruning events behind the checkpoint while retaining enough Merkle tree structure to prove that pruned events were once part of the log.

### Scope

**What this ADR covers:**

- Pruning strategies: time-based, size-based, and event-type-based criteria for removing old events from local storage.
- Checkpoint creation: full context state snapshots anchored to a Merkle root at a specific sequence number.
- State reconstruction: loading a checkpoint and replaying post-checkpoint events to recover current state.
- Merkle proof interaction: how pruning affects proof validity and how "pruned proofs" work.
- Governance of pruning policies: how contexts configure and enforce pruning rules.
- Storage key management: how pruning interacts with the `ProtocolStore` key convention (§17.3).

**What this ADR does NOT cover:**

- Offline/sync strategy for reconnecting members (ADR-029).
- Multi-admin governance models (ADR-031).
- Content storage and retrieval (app-layer, §10.6 — event logs store protocol events and content hashes, not content itself).
- Relay-side storage management (relays manage blob TTL independently per ADR-004).

### Decision

Implement a checkpoint-and-prune system in `scp-core/event_log/` that creates signed state snapshots at configurable intervals and allows pruning of events behind checkpoints according to per-context policy. Pruning removes event payloads and optionally Merkle tree leaf data from local storage, but retains the Merkle tree's interior nodes so that inclusion proofs for pruned events remain verifiable against the checkpoint's Merkle root. The pruning policy is a context parameter set at creation or modified via governance, with a protocol-enforced minimum retention period of 30 days.

#### 1. Checkpoint Structure

A checkpoint captures the complete, deterministic context state at a specific event log sequence number. Checkpoints are published to the event log as a special `Checkpoint` event type so that all members observe and can verify them.

```rust
pub struct Checkpoint {
    /// The context this checkpoint belongs to.
    pub context_id: ContextId,
    /// The event log sequence number this checkpoint covers (inclusive).
    /// All events from 0 through checkpoint_seq are summarized.
    pub checkpoint_seq: u64,
    /// The Merkle root of the event log at checkpoint_seq.
    pub merkle_root: [u8; 32],
    /// The total number of events in the log at checkpoint time.
    pub event_count: u64,
    /// The hash of the last event at checkpoint_seq (hash chain tip).
    pub last_event_hash: [u8; 32],
    /// Full context state snapshot — deterministically serialized.
    pub state_snapshot: ContextStateSnapshot,
    /// DID of the checkpoint creator.
    pub creator_did: DID,
    /// Unix timestamp of checkpoint creation.
    pub created_at: u64,
    /// Ed25519 signature over SHA-256(context_id || checkpoint_seq ||
    /// merkle_root || event_count || last_event_hash ||
    /// SHA-256(serialize(state_snapshot)) || created_at).
    pub signature: Ed25519Signature,
    /// Optional governance quorum signatures (for multi-admin contexts, ADR-031).
    /// In single-admin contexts, this is empty and creator_did must be the admin.
    pub cosignatures: Vec<CosignedCheckpoint>,
}

pub struct CosignedCheckpoint {
    pub signer_did: DID,
    pub signature: Ed25519Signature,
}

pub struct ContextStateSnapshot {
    /// Current membership: DID -> role mapping.
    pub membership: Vec<(DID, RoleName)>,
    /// Current capability ceiling.
    pub capability_ceiling: Vec<Capability>,
    /// Ceiling policy (locked, governed, admin-only).
    pub ceiling_policy: CeilingPolicy,
    /// Governance model identifier and configuration.
    pub governance: GovernanceConfig,
    /// Memory scope.
    pub memory_scope: MemoryScope,
    /// TTL remaining (None if no TTL or if persistent).
    pub ttl_remaining_secs: Option<u64>,
    /// Registered tools.
    pub tools: Vec<ToolRegistration>,
    /// Active sender key epochs per member.
    pub sender_key_epochs: Vec<(DID, u64)>,
    /// Current MLS epoch (None for Broadcast contexts).
    pub mls_epoch: Option<u64>,
    /// Active block relationships: (blocker, blocked).
    pub blocks: Vec<(DID, DID)>,
    /// Context mode (Encrypted or Broadcast).
    pub context_mode: ContextMode,
    /// Parent context IDs (empty for root contexts).
    pub parent_context_ids: Vec<ContextId>,
    /// Active UCAN revocations.
    pub ucan_revocations: Vec<String>,
}
```

**Checkpoint creation rules:**

- In single-admin contexts (Phase 2 governance), only the admin can create checkpoints. The checkpoint is signed by the admin's Active Signing Key.
- In multi-admin contexts (ADR-031), checkpoints require signatures from a governance quorum (e.g., M-of-N admins). The `cosignatures` field carries additional signer attestations.
- Members receiving a checkpoint verify the signature(s) against known admin DID(s), then verify that the `merkle_root` matches their local Merkle root at `checkpoint_seq`. If it matches, the checkpoint is trusted. If it diverges, the member raises an equivocation alert (same mechanism as §9.9.3 consistency checkpoint divergence).
- The `state_snapshot` is deterministically serialized (sorted keys, canonical MessagePack encoding) so that any member can independently compute `SHA-256(serialize(state_snapshot))` and verify the signature covers the correct state.

#### 2. Pruning Strategies

Pruning removes event data from local storage to reclaim space. Three pruning strategies are supported, and they compose: a context's pruning policy can combine multiple strategies with OR semantics (prune when any condition is met).

**2a. Time-based pruning.** Prune events older than a configured duration. Events with `timestamp` older than `now - retention_duration` are eligible for pruning, provided they are behind a valid checkpoint.

```rust
pub struct TimeBasedPolicy {
    /// Minimum age before an event becomes prunable.
    /// Protocol minimum: 30 days (2_592_000 seconds). Contexts may set higher.
    pub retention_secs: u64,
}
```

**2b. Size-based pruning.** Prune when the event log exceeds a configured size. The oldest events behind a valid checkpoint are pruned first until the log is within bounds.

```rust
pub struct SizeBasedPolicy {
    /// Maximum number of events to retain locally. When exceeded,
    /// oldest events behind a checkpoint are pruned.
    pub max_event_count: u64,
    /// Maximum total storage bytes for event log data (events + tree nodes).
    /// When exceeded, oldest events behind a checkpoint are pruned.
    pub max_storage_bytes: u64,
}
```

**2c. Event-type-based retention tiers.** Different event types have different retention priorities. Governance and membership events are retained longer than message events because they define the context's structural evolution and are essential for state reconstruction verification.

```rust
pub struct EventTypeRetention {
    /// Governance and structural events: ContextCreated, MemberJoined, MemberLeft,
    /// RoleAssigned, GovernanceAction, ContextClosing, ContextClosed, ContextExpired,
    /// MemberBlocked, Checkpoint.
    /// These are retained for the full retention period (or indefinitely if no
    /// time-based policy).
    pub structural_retention_multiplier: f64,  // Default: 3.0x the base retention

    /// Operational events: MessageSent, ToolInvoked, ToolVerified,
    /// ConsistencyCheckpoint, KeyEpochAdvance, AbsenceProofRequested.
    /// These are retained for the base retention period.
    pub operational_retention_multiplier: f64,  // Default: 1.0x
}
```

Event-type retention interacts with time-based pruning: the effective retention for a structural event is `retention_secs * structural_retention_multiplier`. A context with a 30-day base retention and a 3.0x structural multiplier retains governance events for 90 days while message events are prunable after 30 days.

**Pruning invariants (enforced mechanically):**

1. Events are never pruned unless they are behind a valid, locally-verified checkpoint. No checkpoint = no pruning.
2. The protocol-enforced minimum retention period is 30 days. A context cannot configure a retention shorter than 30 days. This ensures behavioral validation (§7.3.1) has sufficient history for meaningful evaluation.
3. Pruning never removes checkpoint events themselves. Checkpoints are retained indefinitely (they are small and serve as trust anchors).
4. Pruning is always local. A member's decision to prune does not affect other members' logs. Members who need full history can retain it regardless of the context's pruning policy.
5. The hash chain is preserved: even when event payloads are pruned, the `prev_hash` chain continuity is maintained through retained leaf hashes.

#### 3. Checkpoint Scheduling

Checkpoints are created at configurable intervals, balancing proof compaction benefit against checkpoint creation cost.

```rust
pub struct CheckpointPolicy {
    /// Create a checkpoint every N events. Default: 10_000.
    pub event_interval: u64,
    /// Create a checkpoint every N seconds. Default: 86_400 (24 hours).
    pub time_interval_secs: u64,
    /// Minimum events since last checkpoint before a new one is created.
    /// Prevents checkpoint spam in low-activity contexts. Default: 100.
    pub min_events_since_last: u64,
}
```

Checkpoint creation is triggered by the context admin's SDK when either the event interval or time interval is reached, provided the minimum event threshold since the last checkpoint is met. For low-activity contexts (fewer than 100 events per day), checkpoints are created at the time interval even if the event threshold is not met — the time interval serves as an upper bound on checkpoint staleness.

When a checkpoint is created, it is appended to the event log as a `Checkpoint` event type (extending the `EventType` enum from ADR-011). This ensures all members receive and can verify the checkpoint through normal event log synchronization.

#### 4. Merkle Proof Interaction

Pruning event payloads does not invalidate inclusion proofs for pruned events, provided the Merkle tree's interior nodes are retained. This is the key insight that makes pruning compatible with verifiability.

**4a. Proof layers after pruning:**

The Merkle tree (ADR-011) has three layers of data:

1. **Event payloads** — the serialized `Event` structs. These are what pruning removes.
2. **Leaf hashes** — `SHA-256(serialize(event))` for each event. These are 32 bytes each and are retained after pruning.
3. **Interior nodes** — hash pairs at each tree level. These are retained after pruning.

After pruning, the leaf hashes and interior nodes remain. An inclusion proof for a pruned event still works: the verifier provides the event's leaf hash (which the prover retains), and the proof path through interior nodes to the root is unchanged.

**What is lost after pruning:** The ability to independently recompute the leaf hash from the event payload. A verifier who never saw the original event cannot verify that a claimed leaf hash corresponds to a specific event. They can only verify that *some* event with that leaf hash was included in the log at that position.

**4b. Pruned proofs:**

A "pruned proof" proves that an event was included in the log at a specific position, verified against a checkpoint's Merkle root rather than the current root.

```rust
pub struct PrunedInclusionProof {
    /// The leaf hash of the pruned event.
    pub leaf_hash: [u8; 32],
    /// The leaf index in the log.
    pub leaf_index: u64,
    /// Standard Merkle inclusion proof path (sibling hashes + directions).
    pub path: Vec<ProofStep>,
    /// The checkpoint Merkle root this proof verifies against.
    pub checkpoint_root: [u8; 32],
    /// The checkpoint sequence number.
    pub checkpoint_seq: u64,
}
```

Verification: recompute the root from `leaf_hash` and `path`. If the computed root equals `checkpoint_root`, and the checkpoint itself is trusted (signature verified), then the event was in the log at `leaf_index` as of `checkpoint_seq`.

**4c. Full proof chains:**

For events that span a checkpoint boundary (some events before the checkpoint, some after), a full proof chain combines a pruned proof (against the checkpoint root) with a standard inclusion proof (against the current root) and the checkpoint event's own inclusion proof linking the two roots.

```rust
pub struct FullProofChain {
    /// Proof of the event against the checkpoint's Merkle root.
    pub pruned_proof: PrunedInclusionProof,
    /// Proof that the checkpoint event itself is in the current log.
    pub checkpoint_inclusion: InclusionProof,
    /// The checkpoint (contains the Merkle root used by pruned_proof).
    pub checkpoint: Checkpoint,
}
```

Verification steps:
1. Verify `checkpoint.signature` against the checkpoint creator's DID.
2. Verify `checkpoint_inclusion` — the checkpoint event is in the current log.
3. Verify `pruned_proof.checkpoint_root == checkpoint.merkle_root`.
4. Verify `pruned_proof` — the target event was in the log at `checkpoint_seq`.

This three-step chain provides the same assurance as a direct inclusion proof: the event was part of the log's history, the checkpoint is authentic, and the checkpoint is itself part of the current log.

**4d. Interior node retention strategy:**

After pruning, interior nodes from the Merkle tree are compacted. For a pruned region of the tree (all leaves behind a checkpoint), only the nodes on proof paths that connect to the checkpoint root need to be retained. In practice, the simplest strategy is to retain all interior nodes — at 32 bytes per node and O(n) total nodes for n leaves, the overhead is modest compared to event payloads. For a log with 1 million events, interior nodes consume approximately 64 MB (2n nodes * 32 bytes). If this proves excessive on mobile, a future optimization can prune interior nodes whose subtrees are entirely behind two consecutive checkpoints, retaining only the subtree roots.

Storage key convention for checkpoint-related data (extending §17.3):

```
context/{context_id}/checkpoint/{seq:020d}           -- checkpoint data
context/{context_id}/checkpoint_meta/latest           -- latest checkpoint sequence
context/{context_id}/pruning_policy                   -- current pruning policy
context/{context_id}/prune_cursor                     -- last pruned sequence number
```

#### 5. State Reconstruction from Checkpoints

When a member joins a context with a long history, or when a member's local state is corrupted, they can reconstruct the current context state from the most recent checkpoint plus post-checkpoint events rather than replaying the entire log from genesis.

**Reconstruction protocol:**

1. **Obtain the latest checkpoint.** Query the context's event log (via relay QUERY or peer request) for the most recent `Checkpoint` event. Verify its signature against the admin's DID.
2. **Verify checkpoint consistency.** Compute or request the current Merkle root from an online member (via consistency checkpoint exchange, ADR-011 criterion 8). Verify that the checkpoint event is included in the current log via standard inclusion proof.
3. **Load state snapshot.** Deserialize the checkpoint's `ContextStateSnapshot`. This provides complete context state as of the checkpoint: membership, roles, governance, tools, ceilings, blocks, and sender key epochs.
4. **Replay post-checkpoint events.** Request events from `checkpoint_seq + 1` through the current event count. Verify each event against the Merkle tree (hash chain integrity, inclusion proof). Apply each event's state mutation to the snapshot.
5. **Verify final state.** After replay, the reconstructed state should be consistent with the current Merkle root and the latest consistency checkpoint from online members.

**Reconstruction is not the same as sync.** ADR-029 covers reconnection and sync for members who were part of the context and went offline. State reconstruction is for members who either (a) are joining a context with a long history, (b) have lost local state, or (c) are recovering from storage corruption. The checkpoint provides a known-good starting point; the replay provides the delta.

```rust
pub struct StateReconstructor {
    store: Arc<ProtocolStore>,
}

impl StateReconstructor {
    /// Reconstruct context state from a checkpoint and post-checkpoint events.
    pub async fn reconstruct(
        &self,
        checkpoint: &Checkpoint,
        post_checkpoint_events: &[Event],
        current_merkle_root: &[u8; 32],
    ) -> Result<ReconstructedState, ReconstructionError>;
}

pub struct ReconstructedState {
    pub context_state: ContextStateSnapshot,
    pub event_count: u64,
    pub merkle_root: [u8; 32],
    pub events_replayed: u64,
}

pub enum ReconstructionError {
    /// Checkpoint signature verification failed.
    InvalidCheckpoint(String),
    /// Hash chain broken during event replay.
    BrokenHashChain { expected: [u8; 32], got: [u8; 32], at_seq: u64 },
    /// Final state does not match expected Merkle root.
    StateMismatch { expected_root: [u8; 32], computed_root: [u8; 32] },
    /// Missing events in the replay sequence.
    MissingEvents { from_seq: u64, to_seq: u64 },
}
```

#### 6. Governance of Pruning Policies

The pruning policy is a context parameter, set at creation or modified through the context's governance model. It is included in the context's publicly visible metadata (§5.7) so prospective members can evaluate the context's data retention posture before joining.

```rust
pub struct PruningPolicy {
    /// Time-based pruning. None = no time-based pruning.
    pub time_based: Option<TimeBasedPolicy>,
    /// Size-based pruning. None = no size-based pruning.
    pub size_based: Option<SizeBasedPolicy>,
    /// Event-type retention multipliers.
    pub event_type_retention: EventTypeRetention,
    /// Checkpoint creation schedule.
    pub checkpoint_schedule: CheckpointPolicy,
    /// Whether members are allowed to request full log history from peers.
    /// Default: true. If false, peers SHOULD NOT serve events behind their
    /// most recent checkpoint to other members.
    pub allow_full_history_requests: bool,
}
```

**Governance rules:**

- **Setting at creation.** The context creator includes `PruningPolicy` in `ContextParameters`. If omitted, the default policy applies: no time-based pruning, no size-based pruning, default checkpoint schedule (every 10,000 events or 24 hours), structural events retained 3x longer than operational events, full history requests allowed.
- **Modifying via governance.** The pruning policy can be modified through the context's governance model (admin decision in single-admin, governance vote in multi-admin). Changes are recorded in the event log as a `GovernanceAction` event.
- **Protocol minimum.** The protocol enforces a 30-day minimum for `time_based.retention_secs`. Governance cannot set a shorter retention. This floor ensures behavioral validation (§7.3.1) and equivocation detection (§9.9.3) have meaningful history to work with.
- **Structural event floor.** Governance and membership events (structural events) cannot have an effective retention shorter than 90 days (`structural_retention_multiplier` is clamped to produce at least 90 days of structural event retention). This ensures that context governance history — who joined, who left, what roles changed, what governance actions occurred — is preserved long enough for accountability.
- **Member autonomy.** A member's SDK can retain the full unprocessed event log locally regardless of the context's pruning policy. The pruning policy governs what the protocol considers the minimum retention obligation and what peers are expected to serve. A member who wants full history retains it; a member on a constrained device prunes according to policy.

**Default pruning policy:**

```rust
impl Default for PruningPolicy {
    fn default() -> Self {
        Self {
            time_based: None,         // No time-based pruning by default
            size_based: None,          // No size-based pruning by default
            event_type_retention: EventTypeRetention {
                structural_retention_multiplier: 3.0,
                operational_retention_multiplier: 1.0,
            },
            checkpoint_schedule: CheckpointPolicy {
                event_interval: 10_000,
                time_interval_secs: 86_400,
                min_events_since_last: 100,
            },
            allow_full_history_requests: true,
        }
    }
}
```

**Context templates (§5.12) with pruning presets:**

- `ephemeral`: 30-day retention, 50,000 max events, checkpoints every 5,000 events.
- `conversation`: 90-day retention, 100,000 max events, checkpoints every 10,000 events.
- `persistent` / `full`: No time-based or size-based pruning (default policy). Full history retained.
- `high_volume`: 30-day retention, 500,000 max events, checkpoints every 10,000 events, structural multiplier 5.0x.

#### 7. Pruning Execution

Pruning is a local operation performed by the SDK. It is never triggered by relays or remote peers. The SDK runs a background pruning task that evaluates the pruning policy periodically.

```rust
pub struct PruningExecutor {
    store: Arc<ProtocolStore>,
}

impl PruningExecutor {
    /// Evaluate the pruning policy for a context and prune eligible events.
    /// Returns a report of what was pruned.
    pub async fn prune(
        &self,
        context_id: &ContextId,
        policy: &PruningPolicy,
        now: u64,
    ) -> Result<PruneReport, PruneError>;
}

pub struct PruneReport {
    pub context_id: ContextId,
    /// Number of event payloads removed.
    pub events_pruned: u64,
    /// Bytes reclaimed from storage.
    pub bytes_reclaimed: u64,
    /// The sequence number of the checkpoint used as the pruning boundary.
    pub pruned_up_to_checkpoint: u64,
    /// The sequence number of the oldest retained event payload.
    pub oldest_retained_seq: u64,
}

pub enum PruneError {
    /// No valid checkpoint exists — cannot prune.
    NoCheckpoint,
    /// All events are within the minimum retention period.
    NothingToPrune,
    /// Storage operation failed.
    StorageError(String),
}
```

**Pruning algorithm:**

1. Load the latest verified checkpoint for the context.
2. Determine the eligible pruning boundary: `min(checkpoint_seq, oldest_event_meeting_retention_criteria)`. Events beyond the checkpoint cannot be pruned (no checkpoint to anchor proofs). Events within the retention window cannot be pruned.
3. For each event from the oldest to the pruning boundary:
   a. Check event-type retention: if the event is structural and within the structural retention window, skip.
   b. Delete the event payload from `ProtocolStore` (key: `context/{context_id}/event/{seq:020d}`).
   c. Retain the leaf hash in a compact index (key: `context/{context_id}/pruned_leaf/{seq:020d}`, value: 32-byte hash). This enables pruned proofs.
4. Update the prune cursor: `context/{context_id}/prune_cursor` = highest pruned sequence number.
5. Optionally compact interior tree nodes (Phase 6 optimization — retain all by default).

**Pruning frequency:** The background task runs every 6 hours. On mobile platforms, it defers to when the device is charging and on Wi-Fi (if the platform adapter exposes this information). Pruning is not time-critical — a few hours of delay does not affect correctness.

### Rationale

**Why checkpoint-based pruning instead of rolling windows:**

A rolling window (keep last N events, discard older) breaks Merkle proof continuity. There is no anchor point to verify that pruned events were once part of the log. Checkpoints provide this anchor: the checkpoint's signed Merkle root is the verifiable claim that "all events up to sequence S produced this root." Pruned proofs work because the Merkle tree structure (leaf hashes + interior nodes) is retained even when payloads are removed.

**Why 30-day minimum retention:**

Behavioral validation (§7.3.1) computes records from event log history. A 30-day minimum ensures at least one month of behavioral data is available for trust evaluation. Shorter windows would make behavioral records unreliable — a participant could misbehave, wait for pruning, and have no verifiable behavioral record of the misbehavior. The 30-day floor is a practical balance between storage and accountability. Contexts that need longer accountability windows (governance, financial) set longer retention.

**Why event-type tiers:**

Governance and membership events are small (a role assignment is ~200 bytes) and structurally critical (they define who can do what in the context). Message events are more numerous and less structurally important after verification. Retaining structural events 3x longer than operational events costs minimal storage (structural events are typically <5% of total events by count) while preserving the governance audit trail. This is the same principle as database archival: metadata about the data outlives the data itself.

**Why checkpoints are published to the event log:**

Publishing checkpoints as event log entries makes them discoverable through the same mechanisms as any other event: relay subscription, peer sync, and event range queries. It also means checkpoints are included in the Merkle tree, so their authenticity is verifiable by the same proof machinery. A checkpoint event's inclusion in the log proves it was created when claimed and observed by all members.

**Why pruning is local-only:**

SCP's trust model treats relays as untrusted dumb pipes (§9.9.1). Relays should not influence what clients retain. Similarly, other members should not be able to force a client to prune — that would be a censorship vector (force prune evidence of misbehavior). Pruning is always the local member's decision, constrained by the protocol's minimum retention floor. The pruning policy is a recommendation that the SDK follows by default, not an enforcement mechanism.

**Why members can retain full history:**

The "member autonomy" principle ensures that pruning is a storage optimization, not a privacy guarantee. A context cannot promise that its event log will disappear after 30 days — any member who was present could have retained the full log. This is by design: SCP prioritizes accountability and verifiability over retroactive deletion. If a context needs content destruction guarantees, it uses ephemeral memory scope (§5.11) which destroys encryption keys, not event log hashes.

### Implementation

- **Language:** Rust
- **Async runtime:** tokio (background pruning task, checkpoint creation)
- **Crate:** `scp-core`
- **Module:** `scp-core/event_log/` (extends existing event log module from ADR-011)
- **Persistence:** Via `ProtocolStore` (§17.4). Key conventions:
  - `context/{context_id}/checkpoint/{seq:020d}` — serialized `Checkpoint` structs
  - `context/{context_id}/checkpoint_meta/latest` — latest checkpoint sequence number
  - `context/{context_id}/pruning_policy` — serialized `PruningPolicy`
  - `context/{context_id}/prune_cursor` — last pruned sequence number
  - `context/{context_id}/pruned_leaf/{seq:020d}` — retained leaf hashes for pruned events

### Dependencies

- **ADR-011 (Event Log):** The checkpoint-and-prune system extends the Merkle event log. Checkpoints are a new `EventType`. Pruned proofs use the existing `InclusionProof` structure verified against a checkpoint root instead of the current root.
- **ADR-008 (Context Lifecycle):** Pruning policy is a context parameter. Context creation includes optional `PruningPolicy` in `ContextParameters`. Context closure triggers final checkpoint creation before key destruction (for ephemeral/summary memory scopes).
- **ADR-009 (Roles):** Checkpoint creation requires the admin role (or governance quorum in multi-admin contexts).
- **ADR-029 (Offline/Sync):** State reconstruction from checkpoints provides the fast-start path for members who missed many events during extended offline periods. The `StateReconstructor` complements the `ReconnectionCoordinator` — reconnecting members can load the latest checkpoint instead of replaying the full log.
- **ProtocolStore (§17.4):** Storage and retrieval of checkpoints, pruning policy, prune cursor, and retained leaf hashes. Range queries via `list_keys` with zero-padded sequence numbers.

### Acceptance Criteria

1. **`Checkpoint` struct and event type (extends ADR-011 `EventType` enum):**

```rust
// Addition to EventType in scp-core/event_log/
Checkpoint {
    checkpoint_seq: u64,
    merkle_root: [u8; 32],
    state_snapshot_hash: [u8; 32],  // SHA-256 of serialized ContextStateSnapshot
},
```

2. **`create_checkpoint(event_log, context_state, signing_key) -> Result<Checkpoint, CheckpointError>`**

   - Captures the current Merkle root, event count, and last event hash from the event log.
   - Serializes the full `ContextStateSnapshot` deterministically.
   - Signs the checkpoint with the provided signing key (admin's Active Signing Key).
   - Appends the checkpoint as a `Checkpoint` event to the event log.
   - Persists the checkpoint to `ProtocolStore` at `context/{id}/checkpoint/{seq:020d}`.
   - Updates `context/{id}/checkpoint_meta/latest`.
   - Returns the signed checkpoint.

3. **`verify_checkpoint(checkpoint, admin_public_key, event_log) -> Result<bool, CheckpointError>`**

   - Verifies the checkpoint signature against the admin's public key.
   - Verifies the `merkle_root` matches the event log's root at `checkpoint_seq`.
   - Verifies `state_snapshot_hash` matches `SHA-256(serialize(checkpoint.state_snapshot))`.
   - Returns true if all verifications pass.

4. **`PruningPolicy` struct and validation:**

   - `validate_policy(policy) -> Result<(), PolicyError>`: Rejects policies with `time_based.retention_secs < 2_592_000` (30 days). Rejects policies where the effective structural retention is less than 90 days. Clamps `structural_retention_multiplier` to produce at least 90 days.

5. **`PruningExecutor::prune(context_id, policy, now) -> Result<PruneReport, PruneError>`**

   - Loads the latest checkpoint. Returns `PruneError::NoCheckpoint` if none exists.
   - Computes the pruning boundary from the intersection of checkpoint coverage and retention policy.
   - Iterates events from oldest to boundary, respecting event-type retention tiers.
   - Deletes event payloads from `ProtocolStore`.
   - Retains leaf hashes at `context/{id}/pruned_leaf/{seq:020d}`.
   - Updates `prune_cursor`.
   - Returns a `PruneReport` with statistics.

6. **`prove_pruned_inclusion(event_log, leaf_hash, leaf_index, checkpoint) -> Result<PrunedInclusionProof, EventLogError>`**

   - Generates a Merkle inclusion proof for a pruned event using the retained leaf hash and interior nodes.
   - The proof verifies against the checkpoint's `merkle_root`.

7. **`build_full_proof_chain(pruned_proof, checkpoint, event_log) -> Result<FullProofChain, EventLogError>`**

   - Combines a pruned inclusion proof with the checkpoint's own inclusion proof in the current log.
   - Returns a `FullProofChain` that can be verified by any third party with access to the current Merkle root.

8. **`StateReconstructor::reconstruct(checkpoint, events, current_root) -> Result<ReconstructedState, ReconstructionError>`**

   - Verifies the checkpoint signature.
   - Loads the `ContextStateSnapshot` from the checkpoint.
   - Replays each post-checkpoint event, verifying hash chain continuity.
   - Applies each event's state mutation to the snapshot.
   - Verifies the final Merkle root matches `current_root`.
   - Returns the reconstructed state.

9. **Background checkpoint and pruning tasks:**

   - `CheckpointScheduler`: monitors event count and time since last checkpoint. Triggers `create_checkpoint` when thresholds are met. Runs as a tokio background task.
   - `PruningTask`: runs every 6 hours. Evaluates the pruning policy for each active context and calls `PruningExecutor::prune`. Defers on mobile when not charging (if platform adapter reports power state).

10. **Integration test:**

```
1. Alice creates an identity and a context with a pruning policy:
   time-based 30-day retention, checkpoint every 100 events.
2. Alice and Bob exchange 250 messages (250 events in the log).
3. Verify: checkpoint was created automatically at event 100 and event 200.
4. Verify: both checkpoints are in the event log as Checkpoint events.
5. Verify: checkpoint state_snapshot matches actual context state at those points.
6. Simulate time advance of 31 days.
7. Run pruning. Verify: events 0-199 (behind the checkpoint at 200, older
   than 30 days) are pruned. Events 200-249 are retained.
8. Verify: event payloads for 0-199 are gone from ProtocolStore.
9. Verify: leaf hashes for 0-199 are retained in pruned_leaf/ keys.
10. Generate a pruned inclusion proof for event 50 against checkpoint at 200.
    Verify it succeeds.
11. Build a full proof chain for event 50. Verify it validates against
    the current Merkle root.
12. Carol joins the context. Carol reconstructs state from the latest
    checkpoint (200) + events 200-249. Verify Carol's reconstructed state
    matches Alice and Bob's current state.
13. Verify: governance events (MemberJoined for Bob) with structural
    retention multiplier 3.0x would be retained for 90 days even as
    message events are pruned at 30 days.
```

### Scope

**Files (~5-7):**

| File | Purpose |
|------|---------|
| `checkpoint.rs` | `Checkpoint`, `ContextStateSnapshot`, `CosignedCheckpoint`, `create_checkpoint`, `verify_checkpoint`, `CheckpointScheduler` |
| `pruning.rs` | `PruningPolicy`, `TimeBasedPolicy`, `SizeBasedPolicy`, `EventTypeRetention`, `PruningExecutor`, `PruneReport`, policy validation |
| `pruned_proof.rs` | `PrunedInclusionProof`, `FullProofChain`, `prove_pruned_inclusion`, `build_full_proof_chain` |
| `reconstruct.rs` | `StateReconstructor`, `ReconstructedState`, `ReconstructionError`, state replay logic |
| `policy.rs` | `CheckpointPolicy`, default policies, template presets, policy governance integration |

**Estimated functions:** ~20-25 public functions, ~15-20 internal helpers.

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
