# 23. Sync and Offline Strategy

Members offline for extended periods accumulate pending MLS proposals and Commits. The group state advances without them -- epochs increment, sender keys rotate, members join and leave, governance actions execute. When the offline member reconnects, they must reconcile their stale local state with the group's current state. This section specifies the sync architecture, offline tier definitions, reconnection protocol, conflict resolution strategy, and MLS group rebuild process.

SCP's design makes this simultaneously harder and easier than in traditional messaging systems. Harder: devices are full protocol participants (section 10.2), not thin clients that can ask a server for the current state. There is no authoritative server -- only relays holding encrypted blobs and peers holding decrypted state. Easier: the verifiable event log (section 9.14, ADR-011) provides a cryptographic mechanism for state reconciliation -- two members can compare Merkle roots and prove exactly where their views diverge. The protocol's minimal state footprint (section 10.3) means what needs syncing is small: membership, roles, tokens, outlet registrations, governance, and event hashes -- not content.

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

- Messages are serialized to their inner envelope form (signed, padded) and stored in `ProtocolRepository` under `queue/{context_id}/{seq:020d}`. The inner envelope is fully constructed (including signature and padding) but NOT MLS-encrypted -- MLS encryption requires the current epoch's key schedule, which may advance while offline. MLS encryption is applied at drain time using the then-current epoch.
- The queue is bounded at **1,000 messages per context** and **10,000 messages total** across all contexts. When full, the oldest messages are dropped with a `QueueOverflow` event emitted to the application layer.
- Queue entries include a `queued_at` timestamp. On reconnection, entries older than the context's `blob_ttl` (or 7 days if no TTL) are discarded -- they would expire on relays before delivery anyway.
- The queue drains automatically on reconnection, after MLS epoch catch-up completes. Messages are MLS-encrypted with the current epoch's key schedule and sent in queue order.

**Why deferred encryption:** The MLS epoch may advance while the member is offline. Encrypting at queue time would bind the message to a stale epoch, making it undecryptable by members who have advanced. Deferring MLS encryption to drain time ensures queued messages are encrypted with the current (post-catch-up) epoch.

## 23.3 Reconnection Protocol

On reconnection (at least one relay WebSocket connection re-established), the SDK executes the following ordered six-phase protocol:

**Phase 1 -- Relay catch-up.** For each active context, re-issue `SUBSCRIBE` with `since` = last received `stored_at` minus 5-second overlap (ADR-004 Connection Recovery). Process all backfilled blobs. Deduplicate by `blob_id` (ADR-012 dedup cache). This recovers all messages that relays retained during the offline period.

**Phase 2 -- MLS epoch reconciliation.** For each context, compare the local MLS epoch number against the epoch numbers in received messages. If the local epoch is behind, enter the epoch catch-up procedure (section 23.4). If epochs match, the context is current.

**Phase 3 -- Event log sync.** For each context, exchange consistency checkpoints (ADR-011 criterion 8) with online members. Compare Merkle roots. If roots match at the same event count, the logs are consistent. If they diverge, identify the first divergent event and resolve (section 23.6).

**Phase 4 -- Sender key re-acquisition.** For each context, check for `SenderKeyEpochAdvance` events received during catch-up. For any sender whose key epoch has advanced beyond the locally cached version, issue `SenderKeyRequest` (ADR-007) to obtain the current key. Messages encrypted with missed sender key epochs are buffered until the key is obtained or the sender key timeout expires (RECOMMENDED default: **60 seconds**, configurable via `SyncPolicy`). After timeout, those messages are marked as `UnrecoverableSenderKey` and the application layer is notified.

**Phase 5 -- MLS Update.** After catch-up is complete, the SDK issues an MLS Update proposal in each active context (section 9.7.3: "SDK SHOULD issue an Update after re-establishing connectivity following an offline period"). This provides post-compromise security for the reconnecting member.

**Phase 6 -- Queue drain.** Drain the outbound queue for each context. Each queued inner envelope is MLS-encrypted with the current epoch's key schedule and sent. If a queued message references a context that no longer exists (closed or expired while offline), the message is discarded with a `ContextGone` notification to the application layer.

Each context is synced concurrently, with an overall timeout (RECOMMENDED default: **120 seconds**, configurable via `SyncPolicy`). Contexts that timeout are marked as `Failed`.

## 23.4 MLS Epoch Catch-Up (Tier 1 and Tier 2)

MLS requires sequential epoch processing -- each Commit depends on the previous epoch's key schedule. An offline member at epoch E who reconnects to find the group at epoch E+N must process all N intermediate Commits in order.

### 23.4.1 Commit Recovery Sources

Tried in order:

1. **Relay backfill.** MLS Commits are sent as MLS `PublicMessage` (protocol messages delivered via the transport layer). Relays store them like any other blob. If the relay's retention covers the offline period, all Commits are recoverable.

2. **Peer request.** If relays have expired some Commits (blob_ttl elapsed), the reconnecting member broadcasts a `CommitRangeRequest` as an MLS application message (using their current epoch keys -- they can still encrypt at their stale epoch). Online members who have persisted the Commit messages respond with the missing Commits. This is best-effort -- members are not required to retain raw Commit messages beyond the MLS grace window.

3. **Welcome-based fast-forward.** If the epoch gap is too large (> 100 epochs or no member can provide the full Commit chain), the reconnecting member is treated as a new joiner. An online admin (or any member with `MemberInvite` capability) generates a fresh Welcome message for the reconnecting member's pre-published KeyPackage, effectively re-adding them to the group at the current epoch. The member's old leaf node is removed. This preserves membership and context continuity, but the member loses access to messages encrypted in epochs between their stale epoch and the current epoch (forward secrecy is maintained).

### 23.4.2 Epoch Catch-Up Limits

- The SDK SHOULD process at most **100 sequential Commits** per catch-up attempt (RECOMMENDED implementation default, configurable via `SyncPolicy`). Beyond this limit, the SDK switches to Welcome-based fast-forward.
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

1. Offline duration exceeds 7 days (measured from last successful relay interaction timestamp, persisted in `ProtocolRepository`).
2. Epoch catch-up fails: relay backfill, peer request, and Welcome-based fast-forward all failed.
3. The context's governance model explicitly requests reset (governance action).

### 23.5.2 Reset Protocol

1. The reconnecting member publishes a `ResetRequest` via the relay (not MLS-encrypted -- the member may not be able to encrypt at the current epoch). The request includes context_id, member_did, last_known_epoch, reset reason, a 16-byte random nonce (CSPRNG), and a timestamp (Unix seconds). The request is signed by the member's Active Signing Key or Agent Signing Key (`#active` or `#agent`) for authentication, using the canonical hash construction (section 9.5.1) with domain separator `"SCP-RESET-REQUEST-V1:"`. The signed preimage includes: `context_id || member_did || last_known_epoch || reason_tag || nonce || timestamp`.

   **Anti-replay validation.** Because the ResetRequest is transmitted as plaintext (not MLS-encrypted), it is visible to relays and network observers. An attacker who captures a valid ResetRequest could replay it to force-remove and re-add the member repeatedly, disrupting their session at low cost. To prevent this, the relay (or any recipient processing the request) MUST validate all three of the following before forwarding or acting on the request:

   - **(a) Signature validity.** Verify the Ed25519 signature against the member's DID document (`#active` or `#agent` verification method).
   - **(b) Timestamp freshness.** Reject requests where `|relay_clock - timestamp| > 30 seconds` (matching the freshness window used for SenderKeyRequest in section 9.16.2 and AccessKeyRequest in section 9.17).
   - **(c) Nonce uniqueness.** Maintain a deduplication cache of `(member_did, nonce)` pairs with a 60-second TTL. Reject any request whose nonce has been seen within the TTL window. The 60-second TTL is 2x the freshness window to prevent replay after nonce eviction at the window boundary. Cache capacity: bounded at 10,000 entries with oldest-first eviction.

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
- Context metadata (params, outlets, ceiling) -- this is public and queryable via the metadata routing ID (ADR-004).

### 23.5.4 Bilateral Context Recovery

Standing bilateral contexts (section 5.12.4--5.12.6) receive special handling during Tier 3 recovery. In a two-person context where one member has been offline for weeks, the other member is always the admin and can process the reset unilaterally. The bilateral context must survive weeks-offline -- it represents a persistent relationship, not a transient interaction. The SDK prioritizes bilateral context reset over multi-member context reset during reconnection.

## 23.6 Conflict Resolution

Concurrent offline operations create conflicts when two or more members make incompatible changes while unable to observe each other's actions. SCP resolves conflicts using three principles:

1. The Merkle event log order is authoritative (section 9.14).
2. MLS epoch boundaries are synchronization points (section 9.8.3).
3. No synchronized clock dependency -- ordering is determined by Merkle tree leaf indices, not wall-clock time.

### 23.6.1 Resolution Strategies

**Metadata conflicts (first-writer-wins).** Conflicts are resolved by Merkle tree leaf index: lower index = earlier = wins. This provides deterministic, clock-free ordering. The first event to be appended to the log takes precedence.

**Governance conflicts (Merkle-ordered).** The proposal with the lower event log sequence number wins. The losing proposal is invalidated. In the single-admin model, governance changes are serialized through the admin -- if the admin is offline, no governance changes can occur (by design). **Exception -- mutual removal:** When both proposals in a conflict pair are `RemoveMember` actions targeting each other's proposers (A removes B, B removes A), the conflict is unresolvable by Merkle ordering. Executing the earlier removal invalidates the authority of the later proposer, yet the later proposal is already committed -- a circular dependency. In this case, Merkle ordering is not applied; the conflict always triggers a `GovernanceFreeze` (see ADR-031 §7). The freeze includes all conflicting proposals in the set, not just the mutual-removal pair, so that no conflicts are silently dropped.

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
3. **Behind.** If the reconnecting member's event count is less than the group's (the expected case after offline), the member obtains the missing events through the **Phase 1 relay backfill** (`SUBSCRIBE` with `since`, section 23.3) -- relays are untrusted dumb pipes, so there is no distinct event-range request/response wire message and no peer-supplied proof. The backfilled suffix events are independently authenticated by the normal MLS receive path: per-event signature verification (section 23.13 paragraph 1), sequence-number ordering (section 23.13 paragraph 3), and `prev_hash` chain continuity (section 23.13 paragraph 5). To confirm the fetched suffix is a genuine continuation of the member's own history -- and that the relay did not rewrite the events the member already held -- the member then verifies catch-up integrity **locally**: it computes a Merkle **consistency proof** (RFC 6962 section 2.1.2; ADR-011) via `verify_consistency` that its pre-gap last-known checkpoint root is a **prefix** of the root it reaches by replaying the backfilled events, and gates that reached root (via constant-time `ct_eq`) against the peer's **already-authenticated** signed `ConsistencyCheckpoint` target root (membership plus Ed25519 signature, per section 23.12 and section 9.9.3). The member constructs and checks the consistency proof itself; no peer supplies it. This is the same-log catch-up integrity check, distinct from cross-member equivocation detection (which compares roots across members, per section 9.9.3).
4. **Divergent.** If Merkle roots differ at the same event count, equivocation has occurred (a relay showed different histories to different members, per section 9.9.3). Raising the local, SDK-surfaced `EquivocationDetected` alert here is tier (a) of the two-tier equivocation response (§9.9.3) — the detect-and-surface step, and the minimum conformant detection behavior. It does NOT require constructing the signed, proof-bearing `EquivocationAlert` MLS message or enforcing `equivocation_policy`; that signed-alert-plus-policy flow is the equivocation governance response (tier (b)), specified separately in §9.9.3. The cryptographic equivocation test is equal event count with different Merkle root (§9.9.3); the event-count tolerance used elsewhere to distinguish Behind/Ahead catch-up from an alarm is an application-layer heuristic, not this test. Resolution follows the relay consistency protocol (§9.9.3): identify the divergent relay, flag it in reliability scoring (ADR-012), and exchange Merkle **inclusion** proofs to attribute the divergence. This is NOT a majority vote -- any divergence between any two honest members detects equivocation regardless of how many peers agree with the attacker (§9.9.3 Sybil-amplified equivocation defense).

## 23.8 Multi-Device Coordination

Multi-device sync during offline/online transitions follows the principle from section 10.8: "the protocol delivers the same encrypted envelopes to all devices; the client decides how to present them."

Each device independently runs the reconnection protocol. There is no device-to-device coordination at the protocol level. The SDK provides hooks for client-layer coordination:

- **Reconnection deduplication.** If multiple devices reconnect simultaneously and all issue MLS Updates, the resulting epoch churn is harmless but wasteful. The SDK emits a `ReconnectionStarted` event to the identity's private state log (section 3.7, encrypted, synced across devices). Devices observing another device's reconnection event within a deduplication window (RECOMMENDED default: **30 seconds**, configurable via `SyncPolicy`) defer their own MLS Update to avoid redundant epoch advances.
- **Queue deduplication.** Each queued message includes a content-addressable hash. If multiple devices queued the same message (e.g., user typed a message on phone, then opened laptop), the first device to drain delivers the message; the second device recognizes the duplicate hash in the event log and discards the queued copy.

## 23.9 Reorder Buffering

Messages may arrive out of order due to relay batching, multi-relay delivery, or reconnection race conditions. The SDK maintains a per-context reorder buffer:

- **Gap timeout:** 30 seconds. If a gap in the message sequence is not filled within this duration, the buffer delivers what it has and marks the gap.
- **Buffer capacity:** 100 messages. When the buffer reaches capacity, the oldest buffered messages are delivered in order regardless of gaps.
- **Integration with catch-up:** During epoch catch-up, the reorder buffer is active -- Commits and application messages may arrive interleaved from different recovery sources.

## 23.10 KeyPackage Pre-Publication

To support offline member addition (a member can be added to a group even when they are not currently connected), the SDK pre-publishes `KeyPackage`s to relays. This ensures that an admin can add an offline member using a valid, pre-stored KeyPackage rather than waiting for the member to come online. KeyPackages are single-use and signed by the credential key (`#active` or `#agent`) matching the member's `ScpCredential.signing_key_id` (ADR-039). This is consistent with standard MLS behavior where the leaf node signature key matches the credential key, and avoids requiring the hardware-backed `#0` for routine background operations.

## 23.11 EpochGraceStore Crash Recovery

The `EpochGraceStore` (ADR-001) holds old epoch keys in memory during the grace window after an MLS epoch transition. If the node crashes mid-epoch-transition or during the grace window, the in-memory grace store is lost. This section specifies crash recovery semantics.

**Transactional persistence with MLS group state.** EpochGraceStore state -- specifically the set of epoch numbers with active grace windows and their expiration timestamps -- MUST be persisted transactionally with the MLS group state update. When a Commit is processed and the epoch advances, the following MUST occur in a single database transaction:

1. The new MLS group state is written to `ProtocolRepository`.
2. The grace window entries are persisted atomically within the `ContextSnapshot` blob alongside all other context state (membership, roles, governance, TTL, etc.). This ensures transactional consistency: either the entire snapshot (including grace entries) is written, or none of it is. Individual grace entry CRUD methods (`store_grace_entry`, `load_grace_entries`, `delete_grace_entry`) are available on `ProtocolRepository` under `context/{context_id}/grace/{epoch:020d}` for direct-access patterns, but the snapshot path is the primary production persistence mechanism.
3. Any expired grace window entries are excluded from the snapshot within the same transaction.

If the transaction fails, neither the MLS group state nor the grace window entries are persisted -- the node remains at the previous epoch.

**Recovery on startup.** On node startup after a crash, the SDK MUST:

1. Load all persisted grace window entries from the `ContextSnapshot` blob (which includes grace entries alongside other context state).
2. For each entry, compare the persisted expiration timestamp against the current wall-clock time.
3. If the grace period has expired during downtime, immediately destroy the corresponding old epoch keys (remove the grace entry and any cached key material for that epoch). These keys MUST NOT be retained past their expiration -- forward secrecy requires prompt destruction.
4. If the grace period has NOT yet expired, retain the keys and restart the grace timer from the persisted expiration timestamp (not from recovery time). This ensures the total grace window duration is preserved regardless of crash timing.

**Inconsistent state fallback.** If the persisted grace state is inconsistent with the persisted MLS group state (e.g., a grace entry references an epoch newer than the persisted group epoch, indicating a partial write that escaped the transaction), the SDK MUST:

1. Discard all grace window entries.
2. Destroy any old epoch key material.
3. Mark the context as requiring reconnection (`needs_reconnect = true`). The reconnection protocol (section 23.3) requires network I/O that is not available during context restore at startup. When message processing begins for the affected context (i.e., at least one relay WebSocket connection is re-established), the SDK MUST detect the `needs_reconnect` flag and initiate the reconnection protocol before processing any new messages. The flag is cleared once the reconnection protocol completes successfully.
4. Log an `EpochGraceStoreInconsistency` warning to the application layer.

This fallback is conservative -- it prioritizes forward secrecy (destroy keys) over message recovery (retain keys). Messages encrypted under the lost epoch keys are unrecoverable, which is the same outcome as a grace window expiring normally.

## 23.12 Checkpoint Signature Verification

Consistency checkpoints (ADR-011, section 23.7) are exchanged between members during event log reconciliation. Each checkpoint includes the Merkle root, event count, and a signature from the checkpoint's author. Without mandatory signature verification, a malicious relay or peer could forge checkpoints to trigger false equivocation alerts or suppress real equivocation detection.

**Verification requirements:**

1. Clients MUST verify the signature on every received `ConsistencyCheckpoint` before accepting it for comparison. The signature is verified against the checkpoint author's public key, resolved from their DID document using the `signing_key_id` field (ADR-039: `#active` or `#agent`).

2. If signature verification fails, the checkpoint MUST be rejected entirely. The client MUST NOT use the checkpoint's Merkle root or event count for any comparison or reconciliation decision. A failed verification SHOULD be reported as a `CheckpointSignatureFailure` event to the application layer, indicating a potential relay compromise or peer impersonation.

3. For relay-generated checkpoints (checkpoints that relays produce as part of their store-and-forward operations), the signing key is the relay's known public key, established during relay registration (section 18.3). The client MUST have obtained and cached the relay's public key during initial relay connection. Relay checkpoints signed with an unknown key MUST be rejected.

4. For multi-relay contexts (contexts with multiple relay endpoints), each relay signs its own checkpoints independently. Clients MUST verify each checkpoint against the respective relay's key. Cross-relay checkpoint comparison (section 9.9.3) MUST only use checkpoints that have passed signature verification.

5. A checkpoint with a valid signature from a known key but containing a Merkle root that diverges from the local log at the same event count is NOT a verification failure -- it is a legitimate equivocation detection signal. Signature verification confirms authenticity; divergence detection confirms consistency. These are separate concerns.

## 23.13 Event Verification During Reconciliation

During event log reconciliation (section 23.7, Phase 3 of the reconnection protocol), the reconnecting member receives events from peers to fill gaps in their local log. Without per-event verification, a malicious peer could inject fabricated events -- forging governance actions, membership changes, or other protocol events that never occurred.

**Per-event signature verification:**

1. During reconciliation, each received event MUST be verified against the claimed sender's signing key before being accepted into the local event log. The verification uses the `actor_did` and `signing_key_id` fields of the `Event` struct (ADR-011) to resolve the correct public key from the actor's DID document. Events that fail signature verification MUST be rejected and MUST NOT be added to the local log.

2. The SDK MUST log rejected events with the reason (`InvalidSignature`) and the claimed actor DID. If more than 3 events from the same peer fail verification in a single reconciliation session, the SDK MUST abort reconciliation with that peer and attempt reconciliation with a different online member.

**Sequence number ordering:**

3. The reconciliation protocol MUST verify event ordering: sequence numbers MUST be monotonically increasing per sender within the context's event log. An event with a sequence number less than or equal to the last known sequence number from that sender (that is not already in the local log as a duplicate) indicates either replay or fabrication. Such events MUST be rejected.

4. If the backfill yields events with gaps in the sequence (e.g., events 5 and 8 from a sender arrive but not events 6 and 7), the client MUST obtain the missing events -- via the Phase 1 relay backfill (`SUBSCRIBE` with `since`, section 23.3) -- and verify them (local consistency proof, section 23.7 step 3) before accepting the later ones. Events MUST NOT be accepted out of order -- the gap must be filled first. There is no distinct event-range request/response wire message; relays are untrusted dumb pipes and the suffix is authenticated by the normal MLS receive path (paragraphs 1, 3, and 5). If the missing events cannot be obtained within the reconnection timeout (section 23.3), the events after the gap are discarded and the gap is recorded as an `EventGapDetected` notification to the application layer.

**Hash chain continuity:**

5. Each event's `prev_hash` field MUST chain to the hash of the immediately preceding event in the log (ADR-011 criterion 2). During reconciliation, the SDK MUST verify this chain for every received event. If an event's `prev_hash` does not match the hash of the event at `sequence - 1`, the chain is broken. A broken hash chain indicates tampering or data loss.

6. When a hash chain break is detected, the SDK MUST reject the event and all subsequent events from that peer in the current reconciliation. The SDK MUST attempt to obtain the correct event chain from a different peer. If no peer can provide a consistent chain, the SDK MUST raise an `EventChainTampered` alert to the application layer and mark the context's event log as `Unverified` until a consistent chain is obtained.

**Merkle proof verification:**

7. After accepting events into the local log, the SDK MUST recompute the Merkle tree and verify -- via constant-time comparison (`ct_eq`) -- that the resulting root matches the root carried by the single signed `ConsistencyCheckpoint` target it is reconciling against (membership plus Ed25519 signature verified per section 23.12). This is the same-log catch-up integrity check of section 23.7 step 3: the recomputed root is gated against one already-authenticated checkpoint, NOT against a root agreed by a majority of peers. There is no majority vote -- consistent with section 9.9.3, which detects cross-member equivocation by equal-count-different-root comparison between honest members and resolves it with inclusion proofs, never by majority. Individual event verification (paragraphs 1, 3, 5) ensures authenticity; this root comparison ensures completeness (no events were omitted).

## 23.14 Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| `TIER_1_THRESHOLD_SECS` | 14,400 (4 hours) | Upper bound for Tier 1 (Short) offline duration |
| `TIER_2_THRESHOLD_SECS` | 604,800 (7 days) | Upper bound for Tier 2 (Extended) offline duration |
| `GAP_TIMEOUT` | 30 seconds | Reorder buffer gap timeout |
| `REORDER_BUFFER_CAPACITY` | 100 messages | Maximum messages in the reorder buffer |
| `MAX_SEQUENTIAL_COMMITS` | 100 | RECOMMENDED implementation default. Epoch catch-up limit before Welcome-based fast-forward. Configurable via `SyncPolicy`. |
| `COMMIT_PROCESS_TIMEOUT` | 5 seconds | Per-Commit processing timeout |
| `SENDER_KEY_TIMEOUT` | 60 seconds | RECOMMENDED implementation default. Sender key re-acquisition timeout. Configurable via `SyncPolicy`. |
| `RECONNECTION_DEDUP_WINDOW` | 30 seconds | RECOMMENDED implementation default. Multi-device reconnection deduplication window. Configurable via `SyncPolicy`. |
| `RESET_REQUEST_NONCE_SIZE` | 16 bytes | Random nonce size for ResetRequest anti-replay |
| `RESET_REQUEST_FRESHNESS_WINDOW` | 30 seconds | Maximum age of a valid ResetRequest timestamp |
| `RESET_NONCE_DEDUP_TTL` | 60 seconds | TTL for ResetRequest nonce deduplication cache entries |
| `RESET_NONCE_DEDUP_CAPACITY` | 10,000 entries | Maximum entries in ResetRequest nonce dedup cache |
| `MAX_PEER_VERIFICATION_FAILURES` | 3 | Maximum event signature failures from a single peer before aborting reconciliation with that peer |

## 23.15 Error Model

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
- **ResetRequestRejected** -- ResetRequest failed anti-replay validation (invalid signature, stale timestamp, or replayed nonce).
- **CheckpointSignatureFailure** -- A received checkpoint failed signature verification (section 23.12).
- **EpochGraceStoreInconsistency** -- Persisted grace state was inconsistent with MLS group state on recovery (section 23.11).
- **EventSignatureFailure** -- A received event failed per-event signature verification during reconciliation (section 23.13).
- **EventGapDetected** -- Gap in event sequence could not be filled during reconciliation (section 23.13).
- **EventChainTampered** -- Hash chain continuity was broken during reconciliation, indicating tampering or data loss (section 23.13).
- **SnapshotFloorRegression** -- Imported or restored snapshot would lower the local SequenceFloor for one or more senders, indicating stale state or a replay attempt (section 23.17).

Per-context sync outcomes are reported to the application layer:

- **FullyCaughtUp** -- all epochs and events caught up via sequential processing.
- **FastForwarded** -- caught up via Welcome-based fast-forward (some epochs skipped).
- **Reset** -- member underwent group state reset (Tier 3).
- **ContextGone** -- context was closed or expired while offline.
- **Failed** -- sync failed with a reported reason.

## 23.16 Sync Protocol Wire Formats

All sync protocol messages are serialized as MessagePack with named fields (`rmp-serde` with `named` configuration). Types exchanged between implementations as MLS application messages or via relay must use these exact field names and types.

### 23.16.1 ConsistencyCheckpoint

Exchanged between members as MLS application messages during event log reconciliation (§23.7, §9.9.3).

| Field | Type | Description |
|-------|------|-------------|
| `context_id` | string | Context identifier |
| `sender_did` | string | DID of the checkpoint sender |
| `event_count` | u64 | Number of events in sender's local event log |
| `merkle_root` | bytes (32) | SHA-256 Merkle root of sender's event log |
| `epoch` | u64 or null | MLS epoch on sender's device; null for Broadcast contexts |
| `timestamp` | u64 | Unix seconds when generated |
| `signature` | bytes (64) | Ed25519 signature over canonical hash of all fields above |

**Signature construction:** Domain separator `"SCP-CHECKPOINT-V1:"` (§9.18.2). The canonical hash follows §9.5.1: `SHA-256("SCP-CHECKPOINT-V1:" || BE32(len(context_id)) || context_id || BE32(len(sender_did)) || sender_did || event_count (8-byte BE u64) || merkle_root (32 bytes) || epoch_flag (1 byte: 0x01 if present, 0x00 if null) || epoch (8-byte BE u64, omitted if null) || timestamp (8-byte BE u64))`. All variable-length fields use `BE32(len())` prefixes per §9.5.1. The `sender_did` is included to prevent checkpoint misattribution. The `epoch` field uses a presence flag: `0x01 || epoch_BE` when present, `0x00` when null (Broadcast contexts). The signature is Ed25519 over this hash, signed by the sender's `#active` or `#agent` verification method key (ADR-039).

### 23.16.2 CommitRangeRequest

Sent as MLS application message when relay backfill does not contain all Commits needed for epoch catch-up (§23.4.1, source 2).

| Field | Type | Description |
|-------|------|-------------|
| `context_id` | string | Context identifier |
| `from_epoch` | u64 | First epoch to retrieve (inclusive) |
| `to_epoch` | u64 | Last epoch to retrieve (inclusive) |
| `requester_did` | string | DID of the requesting member |
| `signature` | bytes (64) | Ed25519 signature for authentication |

**Signature construction:** Domain separator `"SCP-COMMIT-RANGE-REQ-V1:"` (§9.18.2). Canonical hash per §9.5.1: `SHA-256("SCP-COMMIT-RANGE-REQ-V1:" || BE32(len(context_id)) || context_id || from_epoch (8-byte BE u64) || to_epoch (8-byte BE u64) || BE32(len(requester_did)) || requester_did)`. The signature authenticates the requester and prevents request forgery.

### 23.16.3 CommitRangeResponse

Response to CommitRangeRequest, sent as MLS application message (§23.4.1, source 2).

| Field | Type | Description |
|-------|------|-------------|
| `context_id` | string | Context identifier |
| `commits` | array of bytes | Serialized MLS Commit messages, strictly ascending epoch order |
| `responder_did` | string | DID of the responding member |
| `signature` | bytes (64) | Ed25519 signature for authentication |

**Signature construction:** Domain separator `"SCP-COMMIT-RANGE-RESP-V1:"` (§9.18.2). Canonical hash per §9.5.1: `SHA-256("SCP-COMMIT-RANGE-RESP-V1:" || BE32(len(context_id)) || context_id || BE32(len(commits_concat)) || commits_concat || BE32(len(responder_did)) || responder_did)`, where `commits_concat` is each commit entry prefixed by its own `BE32(len())` and then concatenated. The signature authenticates the responder and prevents response tampering.

Each entry in `commits` is an opaque serialized MLS Commit message as produced by the MLS library. Ordering MUST be strictly ascending by epoch.

### 23.16.4 ContextSnapshot

Self-contained context state at a point in time. Used for Tier 2 delta sync recovery (§23.5, ADR-029).

| Field | Type | Description |
|-------|------|-------------|
| `context_id` | string | Context identifier |
| `timestamp` | u64 | Unix seconds when snapshot was taken |
| `mls_epoch` | u64 or null | MLS epoch at snapshot time; null for Broadcast contexts |
| `event_log_merkle_root` | bytes (32) | SHA-256 Merkle root at snapshot time |
| `event_count` | u64 | Number of events in log at snapshot time |
| `members` | map<string, MembershipEntry> | DID string → membership entry (BTreeMap for deterministic ordering) |
| `role_definitions` | map<string, array of string> | Role name → capability names |
| `params_hash` | bytes (32) | SHA-256 of serialized ContextParams |
| `outlet_names` | array of string | Registered outlet names at snapshot time |
| `creator_did` | string | DID of snapshot creator |
| `signature` | bytes (64) | Ed25519 signature over all fields except `signature` |
| `sequence` | u64 | Monotonically increasing snapshot sequence per context |

**Signature construction:** Domain separator `"SCP-CONTEXT-SNAPSHOT-V1:"` (§9.18.2). Canonical hash per §9.5.1: `SHA-256("SCP-CONTEXT-SNAPSHOT-V1:" || BE32(len(context_id)) || context_id || timestamp (8-byte BE u64) || mls_epoch_flag (1 byte: 0x01 if present, 0x00 if null) || mls_epoch (8-byte BE u64, omitted if null) || event_log_merkle_root (32 bytes) || event_count (8-byte BE u64) || members_hash (32 bytes) || role_definitions_hash (32 bytes) || params_hash (32 bytes) || outlet_names_hash (32 bytes) || BE32(len(creator_did)) || creator_did || sequence (8-byte BE u64))`. The `members_hash` is `SHA-256` of BTreeMap entries serialized in key order: for each `(did, entry)`, emit `BE32(len(did)) || did || BE32(len(role_name)) || role_name || sequence_number (8-byte BE u64)`. The `role_definitions_hash` is `SHA-256` of entries in key order: for each `(role, caps)`, emit `BE32(len(role)) || role || BE32(count) || [BE32(len(cap)) || cap ...]`. The `outlet_names_hash` is `SHA-256` of `BE32(count) || [BE32(len(name)) || name ...]` in array order. The `mls_epoch` field uses a presence flag matching ConsistencyCheckpoint (§23.16.1). The signature is Ed25519 over this hash, signed by `creator_did`'s `#active` or `#agent` verification method key (ADR-039).

**MembershipEntry:**

| Field | Type | Description |
|-------|------|-------------|
| `did` | string | Member's DID |
| `role_name` | string | Assigned role name (e.g., `"admin"`, `"member"`) |
| `sequence_number` | u64 | Per-sender monotonic sequence number at snapshot time. MUST be preserved under the invariants specified in §23.17. |

### 23.16.5 SnapshotDelta

Computed difference between two ContextSnapshots for efficient state update (§23.5, Tier 2).

| Field | Type | Description |
|-------|------|-------------|
| `context_id` | string | Context identifier |
| `from_sequence` | u64 | Old (stale) snapshot sequence number |
| `to_sequence` | u64 | New (current) snapshot sequence number |
| `from_epoch` | u64 or null | MLS epoch at old snapshot |
| `to_epoch` | u64 or null | MLS epoch at new snapshot |
| `membership_changes` | array of MembershipChange | Changes between snapshots |
| `role_definition_changes` | map<string, array of string> | Roles added or modified |
| `removed_role_definitions` | array of string | Roles removed |
| `added_outlets` | array of string | Outlets added |
| `removed_outlets` | array of string | Outlets removed |
| `params_changed` | bool | Whether context parameters hash changed |
| `events_added` | u64 | Number of events added between snapshots |
| `old_merkle_root` | bytes (32) | Merkle root from old snapshot |
| `new_merkle_root` | bytes (32) | Merkle root from new snapshot |

**MembershipChange** (tagged enum):

| Variant | Fields | Description |
|---------|--------|-------------|
| `Joined` | `MembershipEntry` | New member joined |
| `Left` | `did: string` | Member left or was removed |
| `RoleChanged` | `did: string, old_role: string, new_role: string` | Member's role changed |

### 23.16.6 EquivocationAlert

Raised when relay equivocation is detected (§9.9.3, §23.7). May be recorded in the event log.

| Field | Type | Description |
|-------|------|-------------|
| `context_id` | string | Context where equivocation was detected |
| `detector_did` | string | DID of the detecting member |
| `divergent_did` | string | DID of the member whose checkpoint diverges |
| `divergent_event_count` | u64 | Event count at which Merkle roots diverge |
| `local_merkle_root` | bytes (32) | Detector's Merkle root at divergent count |
| `remote_merkle_root` | bytes (32) | Divergent member's Merkle root |
| `evidence` | EquivocationEvidence or null | Conflicting checkpoints if available |
| `detected_at` | u64 | Unix seconds when alert was raised |
| `local_epoch` | u64 or null | MLS epoch on detector's device |

**EquivocationEvidence:**

| Field | Type | Description |
|-------|------|-------------|
| `local_checkpoint` | ConsistencyCheckpoint | Detector's checkpoint |
| `remote_checkpoint` | ConsistencyCheckpoint | Divergent member's checkpoint |
| `divergent_event_count` | u64 | Event count at divergence |

### 23.16.7 ResetRequest

Sent via relay as **plaintext** (not MLS-encrypted) when the member cannot encrypt at the current epoch. Already specified in §23.5.2; field table provided here for completeness.

| Field | Type | Description |
|-------|------|-------------|
| `context_id` | string | Context identifier |
| `member_did` | string | DID of the requesting member |
| `last_known_epoch` | u64 | Last MLS epoch the member has state for |
| `reason` | ResetReason | Why the reset is needed |
| `nonce` | bytes (16) | CSPRNG random, anti-replay |
| `timestamp` | u64 | Unix seconds |
| `signature` | bytes (64) | Ed25519 signature using domain separator `"SCP-RESET-REQUEST-V1:"` per §9.18.2 |

**ResetReason** (tagged enum):

| Variant | Fields | Description |
|---------|--------|-------------|
| `ExtendedOffline` | `offline_duration_secs: u64` | Member was offline for extended period |
| `CatchUpFailed` | `attempted_sources: array of string` | Epoch catch-up failed despite trying listed sources |
| `GovernanceAction` | `proposal_id: string` | Governance action triggered the reset |

Canonical hash construction for ResetRequest signature is specified in §23.5.2.

### 23.16.8 Signed Context Export

**Scope.** This section governs the signed integrity proof on the `ContextExport` snapshot — the *full* embedded context state produced for backup, migration, and device transfer (§17.5). This is a different artifact from the §23.16.4 `ContextSnapshot`, which is the Tier-2 sync delta type exchanged as an MLS application message (§23.5) and is used only there. The §23.16.4 enumerated-subset hash recipe MUST NOT be used to sign a `ContextExport`; the construction below is normative for export.

A `ContextExport` restores trusted context state verbatim on import — role ceilings, per-member capabilities, suspended capabilities, role assignments, threshold signer set and threshold value, governance model configuration, economic policy, consequence rules, the read-exclusion list, the access-key store, any pending ceiling modification, and outlet registrations are all read directly from the snapshot into the importing instance's authoritative state (see `import_context`, `lifecycle_helpers.rs:1309-1691`). Every field the importer trusts MUST therefore be covered by the signature. An enumerated-subset hash that signs only membership/role-definitions/params/outlet-names leaves the remaining trusted fields forgeable: a tampered export could raise a role's ceiling, inject member capabilities, rewrite the threshold quorum, swap the governance model, or alter the economic policy, and the importer would restore the forged state with a valid signature. The signature MUST cover the whole snapshot.

**Event-log binding (normative).** The exported event log is restored verbatim on import and is therefore trusted state. To bring it under the signature, the event log's Merkle root MUST be carried as a field of the signed `ContextSnapshot` (`event_log_merkle_root`, the root of the exported `event_log_data` at export time; all-zero when no event log is included, e.g. an `ExportScope::Public` export). Because the signature covers `JCS(ContextSnapshot)`, this binds the root into the signed preimage. On import, after the signature verifies, the importer MUST recompute the Merkle root over the received `event_log_data` and compare it (constant-time) to the **signed** `snapshot.event_log_merkle_root`; a mismatch MUST reject the import. The `ContextExport` envelope MAY also carry an unsigned `merkle_root` for observability, but that envelope field is attacker-controlled in transit and MUST NOT be the sole comparison target: if present it MUST equal the signed snapshot root or the import is rejected. Without this binding, a holder of one validly-signed snapshot could substitute a different internally-consistent event log (and matching envelope root) and have it accepted, since neither the envelope root nor the event log itself would be under the signature. The `event_log_merkle_root` is the RFC 6962 `tree::root` (ADR-011) computed over typed-event leaves (`SHA-256(0x00 ‖ rmp_serde(Event))`), NOT the head of the prior free-form-string hash-chain. The importer recomputes `tree::root` over the received `event_log_data` and gates it against the signed root. Because the `tree::root` binds the entire ordered leaf set, any alteration yields a different root than the creator signed — dropping the oldest entries (a *prefix* truncation), dropping the newest entries (a suffix truncation), or removing, reordering, adding, or forging any entry — and is rejected. Truncation forgery is closed by construction, not merely detected.

**Construction.** The export signature is **Ed25519 over `SHA-256(domain || scope-tag-byte || JCS(ContextSnapshot))`**, where:

- `domain` is the byte string `"SCP-CONTEXT-EXPORT-V1:"` (the domain separator registered in §9.18.2), concatenated as a prefix with no separator byte. This is DISTINCT from the §23.16.4 sync-delta separator `"SCP-CONTEXT-SNAPSHOT-V1:"`: the signed-export digest and the sync-delta digest are both Ed25519-signed under the same `creator_did` key, so they MUST be domain-separated at the hash preimage to prevent cross-protocol signature confusion. An implementation MUST NOT use the sync-delta separator for export, and MUST NOT use the export separator for the sync-delta hash.
- `scope-tag-byte` is a single byte encoding the export scope discriminant, placed IMMEDIATELY after the domain separator and BEFORE the JCS bytes: `0x00` for a `Full` export, `0x01` for a `Public` export. Binding the scope into the signed preimage means a holder of a legitimately-signed `Public` export cannot flip the (otherwise unsigned) envelope `scope` field to `Full` (or vice versa) and have it still verify — the verifier sources the scope from the received envelope, recomputes the digest with that scope byte, and a flipped scope yields a different digest than the creator signed, so verification fails by construction. This replaces the prior reliance on the "hollow context" argument (that a flipped-to-`Full` public export was benign because it carried no sensitive state). The byte values are stable wire values that MUST NEVER change once shipped; new scopes take new, never-reused byte values.
- `JCS(ContextSnapshot)` is the RFC 8785 (JSON Canonicalization Scheme) canonical-JSON serialization of the *entire* `ContextSnapshot` value embedded in the export — every field, not a subset. This is the repo's canonical-JSON convention (serde_json_canonicalizer; cf. `scp-protocol::jcs`). The reference implementation is `ContextExport::canonical_snapshot_hash` in the native runtime (`scp-runtime/src/context/export_import.rs`, produced by `create_export`): serialize the snapshot to canonical JSON, then `SHA-256(domain-bytes || scope-tag-byte || snapshot-json-bytes)`, then sign the 32-byte digest.
- The signature is produced over that 32-byte digest (not over the raw JSON), using Ed25519.

**Set/Map canonicalization (normative).** Any field of the snapshot whose Rust type is a set or map with non-deterministic iteration order (e.g. `HashSet`, `HashMap`) MUST be canonicalized to a deterministic ordering — sorted by key for maps, sorted by element for sets (the `BTreeMap`/`BTreeSet` convention) — in the value that is fed to JCS, so that the canonical JSON and therefore the digest are byte-identical across runs. RFC 8785 already fixes object-member ordering by key, but the producing implementation MUST NOT rely on a set/map's incidental iteration order for array-valued fields: array elements derived from a set MUST be emitted in sorted order before serialization. The determinism requirement is that the implementation MUST produce the same digest for the same logical snapshot across runs and regardless of incidental set/map insertion or iteration order. The export construction — domain separator, scope-tag byte, full-JCS digest over the snapshot value, Ed25519, `creator_did` signer, verify-before-restore, and `exporter_did == creator_did` — is the native runtime's single implementation; the protocol engine runs in one place (ADR-055), so there is no second serializer to converge against.

**Signer.** The signer is the snapshot's `creator_did` (located at `role_state.creator_did`). The signature is produced by `creator_did`'s `#active` verification-method key, falling back to `#agent` if `#active` is absent (ADR-039). The exporter signs with the custody key backing that verification method.

**Importer verification and authorization (normative).** Before restoring *any* state from a `ContextExport`, an importing implementation MUST:

1. **Resolve the verifying key from `creator_did`.** Resolve the snapshot's `creator_did` to its DID document and select the `#active` (then `#agent`) verification-method key (ADR-039). The verifying key is derived from `creator_did` — never from an unauthenticated envelope field.
2. **Assert `exporter_did == creator_did`.** The export envelope's `exporter_did` MUST equal the snapshot's `creator_did`. An export whose declared exporter is not the snapshot creator MUST be rejected. This binds the signing authority to the creator identity and prevents a non-creator from re-wrapping a snapshot under their own key.
3. **Verify the signature before restore.** Recompute `SHA-256(domain || scope-tag-byte || JCS(snapshot))` over the *received* envelope — sourcing the `scope-tag-byte` from the received envelope's `scope` field — and verify the Ed25519 signature against the resolved verifying key (strict verification). Because the scope byte is in the preimage, a tampered envelope scope makes the recomputed digest diverge from the signed one and the signature fails. Verification MUST happen before any field of the snapshot is read into authoritative state. A failed signature MUST abort the import with a signature error (`SCP-CTX-2093`) distinct from the version error (`SCP-CTX-2094`).

**Signed vs. wiped fields.** The signature covers the *entire* `ContextSnapshot`. However, certain per-instance fields carried in the snapshot are deliberately NOT trusted from the import even though they are signed: the importer intentionally wipes or sanitizes them because they are local-instance anti-abuse or accounting state with no cross-instance meaning, and inheriting them from a (possibly hostile, possibly merely foreign) exporter would let the exporter pre-load enforcement state against the importing node. Per `import_context` (`lifecycle_helpers.rs:1518-1632`), the importer WIPES `approved_proposals` (rebuilt from the imported event log), resets `next_proposal_seq` to `0`, WIPES `budget_tracker`, WIPES `participation_cache`, starts a FRESH spending-nonce tracker (the import path diverges from the local `restore_context` reload, which rehydrates the nonce tracker), WIPES `proposal_timestamps`, and validates/sanitizes the anti-spam snapshot state (hard-rate-limit and velocity trackers rejected if they carry future timestamps; `cooldown_until` clamped to a bounded horizon). The signature guarantees these fields were not tampered in transit; the wipe guarantees they cannot be weaponized regardless. The fields enumerated under *Construction* above (ceiling, member/suspended capabilities, assignments, threshold set/value, governance model config, economic policy, consequence rules, read-exclusion list, access-key store, pending ceiling modification, outlet registrations) are by contrast trusted verbatim and depend entirely on the full-snapshot signature for their integrity.

**Format version.** The export format `version` (§17.5, `StoredValue`-wrapped MessagePack envelope) is **4** for the scope-bound full-snapshot signed construction (it incremented from 3, which signed the full snapshot but left the scope discriminant out of the preimage). Imports MUST reject any version that is not the current signed format with a dedicated *version* error (`SCP-CTX-2094`), which is distinct from a signature-verification failure (`SCP-CTX-2093`); the version gate fires before any signature is checked, so a caller can tell an old/unsupported format apart from a forged signature. SCP is pre-release with no deployed exports, so prior versions are not accepted on import — the correct end state ships directly.

## 23.17 Snapshot Sequence-Floor Invariants

The `ContextSnapshot` wire format (§23.16.4) persists each member's `sequence_number` in the `MembershipEntry` map, and other per-sender monotonic counters live in related persisted state (MLS epoch, `send_sequence`, sender-key epoch, receive-side sequence tracker). To prevent snapshot-mediated replay — where an attacker uses an older snapshot to roll a node's accepted-sequence high-water mark backward — this section specifies the normative invariants that restoring and importing implementations MUST enforce.

### 23.17.1 Definitions

- **Local sequence floor.** For each context `C` and each sender DID `D`, the local node's `SequenceFloor[C, D]` is the highest sequence number the node has ever accepted from `D` in `C`. Sequence numbers strictly below the floor are always rejected as replay (§23.13 paragraph 3).
- **Snapshot sequence floor.** For each `MembershipEntry` in a `ContextSnapshot`, the `sequence_number` field is the snapshot author's floor for that member at snapshot time. The floor concept also applies transitively to `mls_epoch`, `send_sequence`, sender-key `epoch` (§9.16.1, §9.17), and receive-side sequence-tracker entries persisted alongside or within the snapshot.

### 23.17.2 Invariants

**Invariant 1 — Floor monotonicity on save.** When taking a snapshot, each per-sender sequence value written into the snapshot MUST equal the current local floor for that sender. Implementations MUST NOT write a lower value for any sender. A snapshot that regresses any floor relative to a prior snapshot from the same node for the same context is a protocol violation.

**Invariant 2 — Floor preservation on restore.** When restoring a local snapshot (Tier 3 recovery, crash recovery, or device migration from this node's own prior state), the restoring node MUST initialize each `SequenceFloor[C, D]` to:

```
max(snapshot_floor[D], retained_floor[D])
```

where `retained_floor[D]` is any value the node retains through persistence paths orthogonal to the snapshot (for example, event-log entries for `D` at a sequence higher than the snapshot's `MembershipEntry.sequence_number`, or a sender-key epoch high-water map persisted alongside the snapshot). The restored floor MUST NEVER be lower than either source. If the node has no other retained state for `D`, the snapshot's value is authoritative.

**Invariant 3 — Floor monotonicity on import.** When importing a snapshot received from another member (delta sync recovery, device migration from a peer), the importing node MUST compare each per-sender sequence value in the imported snapshot against the node's current local floor for that sender:

- If the imported value is greater than or equal to the local floor, the local floor is updated to `max(local, imported)`.
- If the imported value is strictly less than the local floor for ANY sender, the import MUST be rejected entirely with `SnapshotFloorRegression` (§23.15). A partial import that accepts some senders' floors but rejects others is forbidden — the snapshot is atomic.

**Invariant 4 — Append-only dominance.** A receiving node MUST NEVER lower its own `SequenceFloor` as the result of snapshot import or restore. The floor is append-only over the lifetime of the node's state for a given context. If a snapshot would require lowering the floor for any sender, the snapshot is malformed, stale, or adversarial, and the import MUST be rejected.

### 23.17.3 Scope

These invariants apply to every per-sender monotonic counter persisted as part of context state, including but not limited to:

- `MembershipEntry.sequence_number` for each context member (§23.16.4).
- The sending node's own `send_sequence` counter per context (§9.16.1 sender-key AEAD AAD binding).
- Per-sender `mls_epoch` observation from received Commits where tracked.
- Sender-key `epoch` high-water mark maintained by the sender-key store (§9.16.1, §9.17) — preserved on member removal per the sender-key store contract.
- Receive-side sequence tracker entries keyed by `(context_id, sender_did)` (§9.16.1 anti-replay defense-in-depth).
- Broadcast context `epoch` and `next_sequence` counters.

An implementation MUST ensure every counter in this set is covered by a concrete save/restore/import path that honors the invariants above. Gaps are bugs.

### 23.17.4 Rationale

Without these invariants, an attacker who obtains any historical snapshot of a context can replay it at a victim node to reset the victim's replay-detection state, allowing previously-rejected messages (replayed from a captured event log or relay buffer) to be accepted as fresh. The floor invariants guarantee that a node's accepted-sequence state is strictly non-decreasing over time regardless of snapshot lineage, matching the per-sender monotonicity guarantee in §23.13 and the sender-key epoch monotonicity guarantee in §9.16.1.

### 23.17.5 Error reporting

A rejected snapshot MUST produce a `SnapshotFloorRegression` error (§23.15) with per-sender details (sender DID, local floor value, imported value) suitable for diagnostic logging. The error MUST NOT be silently swallowed, as it may indicate either benign stale state (for example, an out-of-order delta sync) or an active replay attempt. Implementations SHOULD log each per-sender regression distinctly so operators can distinguish single-sender anomalies from broad-front replay attempts.

### 23.17.6 Interaction with reconciliation

After a valid snapshot restore, the node's `SequenceFloor` map is initialized per Invariant 2 and remains subject to §23.13 paragraph 3: any subsequent event received during reconciliation with a `sequence_number` at or below the floor is rejected as replay. Reconciliation NEVER overrides the floor — it only accepts events at or above it. Conversely, reconciliation MAY advance the floor when it accepts a higher-numbered event for a sender; this advancement is propagated into the next snapshot save per Invariant 1.
