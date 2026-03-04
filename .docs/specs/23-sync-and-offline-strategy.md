# 23. Sync and Offline Strategy

Members offline for extended periods accumulate pending MLS proposals and Commits. The group state advances without them -- epochs increment, sender keys rotate, members join and leave, governance actions execute. When the offline member reconnects, they must reconcile their stale local state with the group's current state. This section specifies the sync architecture, offline tier definitions, reconnection protocol, conflict resolution strategy, and MLS group rebuild process.

SCP's design makes this simultaneously harder and easier than in traditional messaging systems. Harder: devices are full protocol participants (section 10.2), not thin clients that can ask a server for the current state. There is no authoritative server -- only relays holding encrypted blobs and peers holding decrypted state. Easier: the verifiable event log (section 9.14, ADR-011) provides a cryptographic mechanism for state reconciliation -- two members can compare Merkle roots and prove exactly where their views diverge. The protocol's minimal state footprint (section 10.3) means what needs syncing is small: membership, roles, tokens, tool registrations, governance, and event hashes -- not content.

See ADR-029 in `.docs/adrs/phase-6.md` for the full architectural decision record. Implementation: `crates/scp-core/src/sync/`.

## 23.1 Three-Tier Offline Strategy

Offline durations are classified into three tiers, each with a progressively stronger reconciliation mechanism:

| Tier | Duration | Strategy | Trade-off |
|------|----------|----------|-----------|
| **Tier 1 (Short)** | < 4 hours | Relay buffering + sequential MLS catch-up | Lossless recovery. Handles 95%+ of offline events (mobile sleep, brief network outages, WiFi/cellular transitions). |
| **Tier 2 (Extended)** | 4 hours -- 7 days | State snapshot comparison + delta sync with selective epoch reconstruction | May lose access to messages encrypted in skipped epochs (forward secrecy preserved). Covers overnight offline, travel, hardware issues. |
| **Tier 3 (Long)** | > 7 days | Forced re-join via MLS group state reset | Loses access to messages in the gap. Identity, role, and event log history are preserved. Last resort for extended disconnection. |

Tier classification uses `saturating_sub` for the duration calculation -- SCP does not require synchronized clocks (section 9.8.3). If the reconnection timestamp precedes the last relay contact (clock skew), the duration is treated as zero (Tier 1).

```
classify_offline_duration(last_relay_contact, now) -> OfflineTier:
    duration_secs = now.saturating_sub(last_relay_contact)
    if duration_secs <= 14_400:       return Short     // <= 4 hours
    if duration_secs <= 604_800:      return Extended   // <= 7 days
    else:                             return Long       // > 7 days
```

All tiers use the Merkle event log (ADR-011) as the authoritative state reconciliation mechanism and the relay's store-and-forward capability (ADR-004) as the primary message recovery path.

## 23.2 Client-Side Outbound Queue

When the SDK detects disconnection (all relay WebSocket connections lost), outbound messages are queued locally rather than dropped.

**Queue mechanics:**

- Messages are serialized to their inner envelope form (signed, padded) and stored in `ProtocolStore` under `queue/{context_id}/{seq:020d}`. The inner envelope is fully constructed (including signature and padding) but NOT MLS-encrypted -- MLS encryption requires the current epoch's key schedule, which may advance while offline. MLS encryption is applied at drain time using the then-current epoch.
- The queue is bounded at **1,000 messages per context** and **10,000 messages total** across all contexts. When full, the oldest messages are dropped with a `QueueOverflow` event emitted to the application layer.
- Queue entries include a `queued_at` timestamp. On reconnection, entries older than the context's `blob_ttl` (or 7 days if no TTL) are discarded -- they would expire on relays before delivery anyway.
- The queue drains automatically on reconnection, after MLS epoch catch-up completes. Messages are MLS-encrypted with the current epoch's key schedule and sent in queue order.

**Why deferred encryption:** The MLS epoch may advance while the member is offline. Encrypting at queue time would bind the message to a stale epoch, making it undecryptable by members who have advanced. Deferring MLS encryption to drain time ensures queued messages are encrypted with the current (post-catch-up) epoch.

## 23.3 Reconnection Protocol

On reconnection (at least one relay WebSocket connection re-established), the SDK executes the following ordered six-phase protocol:

**Phase 1 -- Relay catch-up.** For each active context, re-issue `SUBSCRIBE` with `since` = last received `stored_at` minus 5-second overlap (ADR-004 Connection Recovery). Process all backfilled blobs. Deduplicate by `blob_id` (ADR-012 dedup cache). This recovers all messages that relays retained during the offline period.

**Phase 2 -- MLS epoch reconciliation.** For each context, compare the local MLS epoch number against the epoch numbers in received messages. If the local epoch is behind, enter the epoch catch-up procedure (section 23.4). If epochs match, the context is current.

**Phase 3 -- Event log sync.** For each context, exchange consistency checkpoints (ADR-011 criterion 8) with online members. Compare Merkle roots. If roots match at the same event count, the logs are consistent. If they diverge, identify the first divergent event and resolve (section 23.6).

**Phase 4 -- Sender key re-acquisition.** For each context, check for `SenderKeyEpochAdvance` events received during catch-up. For any sender whose key epoch has advanced beyond the locally cached version, issue `SenderKeyRequest` (ADR-007) to obtain the current key. Messages encrypted with missed sender key epochs are buffered until the key is obtained or a **60-second timeout** expires. After timeout, those messages are marked as `UnrecoverableSenderKey` and the application layer is notified.

**Phase 5 -- MLS Update.** After catch-up is complete, the SDK issues an MLS Update proposal in each active context (section 9.7.3: "SDK SHOULD issue an Update after re-establishing connectivity following an offline period"). This provides post-compromise security for the reconnecting member.

**Phase 6 -- Queue drain.** Drain the outbound queue for each context. Each queued inner envelope is MLS-encrypted with the current epoch's key schedule and sent. If a queued message references a context that no longer exists (closed or expired while offline), the message is discarded with a `ContextGone` notification to the application layer.

Each context is synced concurrently, with a **120-second overall timeout**. Contexts that timeout are marked as `Failed`.

## 23.4 MLS Epoch Catch-Up (Tier 1 and Tier 2)

MLS requires sequential epoch processing -- each Commit depends on the previous epoch's key schedule. An offline member at epoch E who reconnects to find the group at epoch E+N must process all N intermediate Commits in order.

### 23.4.1 Commit Recovery Sources

Tried in order:

1. **Relay backfill.** MLS Commits are sent as MLS `PublicMessage` (protocol messages delivered via the transport layer). Relays store them like any other blob. If the relay's retention covers the offline period, all Commits are recoverable.

2. **Peer request.** If relays have expired some Commits (blob_ttl elapsed), the reconnecting member broadcasts a `CommitRangeRequest` as an MLS application message (using their current epoch keys -- they can still encrypt at their stale epoch). Online members who have persisted the Commit messages respond with the missing Commits. This is best-effort -- members are not required to retain raw Commit messages beyond the MLS grace window.

3. **Welcome-based fast-forward.** If the epoch gap is too large (> 100 epochs or no member can provide the full Commit chain), the reconnecting member is treated as a new joiner. An online admin (or any member with `MemberInvite` capability) generates a fresh Welcome message for the reconnecting member's pre-published KeyPackage, effectively re-adding them to the group at the current epoch. The member's old leaf node is removed. This preserves membership and context continuity, but the member loses access to messages encrypted in epochs between their stale epoch and the current epoch (forward secrecy is maintained).

### 23.4.2 Epoch Catch-Up Limits

- The SDK processes at most **100 sequential Commits** per catch-up attempt. Beyond 100 Commits, the SDK switches to Welcome-based fast-forward.
- Each Commit is processed within a **5-second timeout**. Commits that fail to process (corrupted, missing dependencies) are logged as `EpochCatchUpFailure` and the SDK falls through to the next recovery source.
- The 100-Commit limit is a practical bound. In a context with 24-hour PCS Update intervals and 10 members, 100 Commits represents roughly 10 days of activity. Contexts with higher churn (frequent joins/leaves) may hit this limit sooner.

### 23.4.3 Catch-Up Status

The catch-up procedure produces one of four outcomes:

- **Processing** -- sequential Commit processing is in progress.
- **Complete** -- all epochs caught up successfully via sequential processing.
- **FastForwarded** -- caught up via Welcome-based fast-forward (records the skipped epoch range).
- **Failed** -- catch-up failed; context may need group reset (Tier 3).

## 23.5 MLS Group State Reset (Tier 3)

When a member has been offline for more than 7 days, or when the epoch catch-up procedure fails (no recovery source can provide the Commit chain and no member can generate a Welcome), the member triggers a group state reset for their participation.

**Group state reset is NOT a group-wide operation.** It affects only the offline member's participation. The group continues operating normally. The reset is equivalent to: the offline member leaves and immediately re-joins.

### 23.5.1 Trigger Conditions

Any one of the following triggers a group state reset:

1. Offline duration exceeds 7 days (measured from last successful relay interaction timestamp, persisted in `ProtocolStore`).
2. Epoch catch-up fails: relay backfill, peer request, and Welcome-based fast-forward all failed.
3. The context's governance model explicitly requests reset (governance action).

### 23.5.2 Reset Protocol

1. The reconnecting member publishes a `ResetRequest` via the relay (not MLS-encrypted -- the member may not be able to encrypt at the current epoch). The request is signed by the member's Active Signing Key or Agent Signing Key (`#active` or `#agent`) for authentication. Includes context_id, member_did, last_known_epoch, reset reason, and signature.
2. An online member with `MemberRemove` + `MemberInvite` capabilities (typically admin) processes the reset: (a) removes the offline member's stale leaf node via MLS `remove_member()`, (b) immediately re-adds the member using a fresh KeyPackage via MLS `add_member()`, (c) distributes the new Welcome message via relay.
3. The reconnecting member processes the Welcome, joining the group at the current epoch. They request sender keys for all current members via the pull-based protocol (ADR-007).
4. The reconnecting member's outbound queue is drained using the new epoch's key schedule.
5. A `MemberReset` event (distinct from `MemberLeft` + `MemberJoined`) is appended to the event log, recording the reset reason, old epoch, new epoch, and the admin who processed it.

### 23.5.3 State Preservation

**What the reset member loses:**

- Access to messages encrypted in epochs between their last known epoch and the current epoch. Forward secrecy is preserved -- old epoch keys were destroyed per ADR-001.
- Any pending governance proposals they initiated while offline (proposals reference specific epochs).
- Queue entries that reference the old epoch (re-queued messages are re-encrypted with the new epoch).

**What the reset member retains:**

- Their DID and identity.
- Their role in the context (the admin re-assigns the same role during re-add).
- Their event log history up to the last known epoch.
- Context metadata (params, tools, ceiling) -- this is public and queryable via the metadata routing ID (ADR-004).

### 23.5.4 Bilateral Context Recovery

Standing bilateral contexts (section 5.12.4--5.12.6) receive special handling during Tier 3 recovery. In a two-person context where one member has been offline for weeks, the other member is always the admin and can process the reset unilaterally. The bilateral context must survive weeks-offline -- it represents a persistent relationship, not a transient interaction. The SDK prioritizes bilateral context reset over multi-member context reset during reconnection.

## 23.6 Conflict Resolution

Concurrent offline operations create conflicts when two or more members make incompatible changes while unable to observe each other's actions. SCP resolves conflicts using three principles:

1. The Merkle event log order is authoritative (section 9.14).
2. MLS epoch boundaries are synchronization points (section 9.8.3).
3. No synchronized clock dependency -- ordering is determined by Merkle tree leaf indices, not wall-clock time.

### 23.6.1 Resolution Strategies

**Metadata conflicts (last-writer-wins).** "Last" is determined by Merkle tree leaf index (lower index = earlier = wins). This provides deterministic, clock-free ordering.

**Governance conflicts (Merkle-ordered).** The proposal with the lower event log sequence number wins. The losing proposal is invalidated. In the single-admin model, governance changes are serialized through the admin -- if the admin is offline, no governance changes can occur (by design).

**Simultaneous commits (same sequence).** If two proposals are committed at the same event log sequence, the context enters a `GovernanceFreeze` state. No new governance actions are accepted until an admin explicitly resolves the conflict. This is the "governance deadlock = context freeze" outcome -- the context is not forked automatically.

**Deadlock detection.** Detected when the governance model requires votes from permanently unavailable DIDs. An admin with sufficient capability must resolve the deadlock by removing the unavailable member or modifying the governance configuration.

**Concurrent messages (no conflict).** Messages from different senders in the same epoch are ordered by `(epoch, sender_generation_number, timestamp)` per section 9.8.3. Messages queued while offline receive fresh sequence numbers at drain time.

**Concurrent membership changes.** MLS serializes membership changes through Commits. Only one Commit can advance the epoch. If two members propose Add/Remove simultaneously, the first Commit to be processed wins; the second proposal becomes invalid (references a stale epoch) and must be re-proposed.

**Concurrent sender key rotations.** If a sender rotates their key while a peer is offline, the peer requests the new key on reconnection (Phase 4 of the reconnection protocol). Only the current key is needed -- intermediate keys are irrelevant.

**Context closure during offline.** If a context was closed or expired while the member was offline, the reconnecting member discovers this during relay catch-up. The member processes the closure locally, destroys key material per the context's memory scope, and discards any queued messages for that context.

## 23.7 Event Log Reconciliation

The Merkle event log (ADR-011) is the authoritative state record. After relay catch-up and epoch reconciliation, the SDK verifies event log consistency:

1. **Exchange checkpoints.** The reconnecting member generates a `ConsistencyCheckpoint` from their local log state and sends it to the context. Online members compare and respond with their own checkpoints.
2. **Compare Merkle roots.** If roots match at the same event count, the logs are consistent -- no further action.
3. **Behind.** If the reconnecting member's event count is less than the group's (the expected case after offline), the member requests the missing events via event range requests. Events are verified by recomputing the Merkle path from each event to the known root.
4. **Divergent.** If Merkle roots differ at the same event count, equivocation has occurred (a relay showed different histories to different members, per section 9.9.3). The reconnecting member raises an `EquivocationDetected` alert. Resolution follows the relay consistency protocol: identify the divergent relay, flag it in reliability scoring (ADR-012), and prefer the event chain signed by more members.

## 23.8 Multi-Device Coordination

Multi-device sync during offline/online transitions follows the principle from section 10.8: "the protocol delivers the same encrypted envelopes to all devices; the client decides how to present them."

Each device independently runs the reconnection protocol. There is no device-to-device coordination at the protocol level. The SDK provides hooks for client-layer coordination:

- **Reconnection deduplication.** If multiple devices reconnect simultaneously and all issue MLS Updates, the resulting epoch churn is harmless but wasteful. The SDK emits a `ReconnectionStarted` event to the identity's private state log (section 3.7, encrypted, synced across devices). Devices observing another device's reconnection event within a **30-second deduplication window** defer their own MLS Update to avoid redundant epoch advances.
- **Queue deduplication.** Each queued message includes a content-addressable hash. If multiple devices queued the same message (e.g., user typed a message on phone, then opened laptop), the first device to drain delivers the message; the second device recognizes the duplicate hash in the event log and discards the queued copy.

## 23.9 Reorder Buffering

Messages may arrive out of order due to relay batching, multi-relay delivery, or reconnection race conditions. The SDK maintains a per-context reorder buffer:

- **Gap timeout:** 30 seconds. If a gap in the message sequence is not filled within this duration, the buffer delivers what it has and marks the gap.
- **Buffer capacity:** 100 messages. When the buffer reaches capacity, the oldest buffered messages are delivered in order regardless of gaps.
- **Integration with catch-up:** During epoch catch-up, the reorder buffer is active -- Commits and application messages may arrive interleaved from different recovery sources.

## 23.10 KeyPackage Pre-Publication

To support offline member addition (a member can be added to a group even when they are not currently connected), the SDK pre-publishes `KeyPackage`s to relays. This ensures that an admin can add an offline member using a valid, pre-stored KeyPackage rather than waiting for the member to come online. KeyPackages are single-use and signed by the identity key `#0` (section 9.6). **Custody note (ADR-039):** Only `#0` (Identity Key) can sign KeyPackages — the `#agent` verification method cannot publish KeyPackages because KeyPackage signing is a Category A operation requiring the identity key.

## 23.11 Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| `TIER_1_THRESHOLD_SECS` | 14,400 (4 hours) | Upper bound for Tier 1 (Short) offline duration |
| `TIER_2_THRESHOLD_SECS` | 604,800 (7 days) | Upper bound for Tier 2 (Extended) offline duration |
| `GAP_TIMEOUT` | 30 seconds | Reorder buffer gap timeout |
| `REORDER_BUFFER_CAPACITY` | 100 messages | Maximum messages in the reorder buffer |
| `MAX_SEQUENTIAL_COMMITS` | 100 | Epoch catch-up limit before Welcome-based fast-forward |
| `COMMIT_PROCESS_TIMEOUT` | 5 seconds | Per-Commit processing timeout |
| `SENDER_KEY_TIMEOUT` | 60 seconds | Sender key re-acquisition timeout |
| `RECONNECTION_DEDUP_WINDOW` | 30 seconds | Multi-device reconnection deduplication window |

## 23.12 Error Model

Sync errors are categorized by the reconnection phase in which they occur:

- **RelayCatchUpFailed** -- Phase 1 relay catch-up failed.
- **EpochCatchUpFailed** -- Phase 2 MLS epoch catch-up failed.
- **EventLogSyncFailed** -- Phase 3 event log sync failed.
- **SenderKeyTimeout** -- Phase 4 sender key re-acquisition timed out.
- **MlsUpdateFailed** -- Phase 5 MLS Update issuance failed.
- **QueueDrainFailed** -- Phase 6 queue drain failed.
- **ContextGone** -- Context was closed or expired while the member was offline.
- **ReorderBufferOverflow** -- Reorder buffer exceeded capacity.
- **CommitProcessingFailed** -- A Commit in the catch-up sequence was corrupted or failed.
- **GapTimeoutExpired** -- Gap timeout expired before a missing message arrived.
- **ReconnectionTimeout** -- Overall 120-second reconnection timeout exceeded.

Per-context sync outcomes are reported to the application layer:

- **FullyCaughtUp** -- all epochs and events caught up via sequential processing.
- **FastForwarded** -- caught up via Welcome-based fast-forward (some epochs skipped).
- **Reset** -- member underwent group state reset (Tier 3).
- **ContextGone** -- context was closed or expired while offline.
- **Failed** -- sync failed with a reported reason.
