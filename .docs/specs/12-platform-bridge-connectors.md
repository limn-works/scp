# 12. Platform Bridge Connectors

## 12.1 The Problem

The social graph doesn't start empty. Users have relationships, conversations, communities, and history on existing platforms — X, Facebook, Instagram, WhatsApp, Discord, Slack, and whatever comes next. SCP must provide a path to participate alongside these platforms without requiring their cooperation or conformance.

This is not the same as local data import. Local import (scraping your own data, downloading your archive) is a user-level concern handled by local agent orchestration below the protocol boundary. Bridge connectors are a **protocol-level primitive** — a standardized interface through which non-SCP platforms can participate in SCP contexts, and SCP contexts can reach into external platforms.

## 12.2 Bridge Connectors as Protocol Entities

A bridge connector is a registered protocol entity — distinct from agents, outlets, and contexts. It translates between an external platform's native protocol and SCP's protocol semantics.

```
┌───────────────────────────────────────────────────────────────────┐
│                         SCP CONTEXT                                │
│                                                                    │
│  Native members:              Shadow identities:                  │
│                                                                    │
│  Alice·Agent (admin)          @dave_x (shadow, via X Bridge)      │
│  Bob·Agent   (member)         @eve_fb (shadow, via FB Bridge)     │
│  Carol·Agent (member)         @frank_wa (shadow, via WA Bridge)   │
│                                                                    │
│                  ┌─────────────────────────┐                      │
│                  │    Bridge Connector      │                      │
│                  │                          │                      │
│                  │  Operator: did:dht:...   │ ← Accountable       │
│                  │  Platform: X (Twitter)   │   identity runs      │
│                  │  Mode: relay | puppet    │   the bridge.        │
│                  │  Provenance: marked      │                      │
│                  └────────────┬─────────────┘                      │
│                               │                                    │
└───────────────────────────────┼────────────────────────────────────┘
                                │
                     ┌──────────▼──────────┐
                     │   External Platform  │
                     │   (X, FB, WA, etc.)  │
                     └─────────────────────┘
```

Properties of bridge connectors:

- **Operated by accountable identities.** Every bridge has a human operator bound by DID. Bridge misbehavior traces to a person. This is consistent with SCP's core invariant: every action traces to a human.
- **Registered with contexts.** A bridge connector registers with a specific context. The context's governance model controls whether the bridge is admitted. Context members can see which bridges are active and who operates them.
- **Transparent.** Bridge presence, operator identity, connected platform, and operating mode are visible to all context members via the `bridges` structural field in context metadata (§5.7). Because `bridges` is a structural field, it is always visible before opt-in — prospective members see active bridges before deciding whether to join. The canonical definition of `BridgeMetadata` lives in §5.7; this section describes the protocol semantics. When a bridge is registered, revoked, or suspended, the context's metadata record MUST be republished with updated bridge metadata (§5.7.1).
- **Revocable.** Context governance can remove a bridge at any time, severing the connection to the external platform.

### 12.2.1 Bridge Registration Protocol

Bridge registration is a governance-gated operation using the `RegisterBridge` governance action:

```
RegisterBridge {
  operator_did:    DID,              // the bridge operator's DID
  platform:        String,           // platform identifier (e.g., "discord", "slack", "x")
  mode:            BridgeMode,       // Relay | Puppet | API | Cooperative
  webhook_url:     Option<String>,   // for cooperative mode: platform's webhook receiver URL
  platform_key:    Option<[u8; 32]>, // for cooperative mode: platform's Ed25519 public key
  max_shadows:     u32,              // governance-configured shadow limit for this bridge
  metadata:        BridgeRegistrationMetadata, // display name, description, operator contact
}
```

**Registration flow:**

1. The bridge operator submits a `RegisterBridge` proposal to the context via the standard governance mechanism (§5.9). The operator MUST be a context member, because the bridge node decrypts SCP messages as that member (bridge encryption model, §12.6.1) and reads bridge admission from the event log that the node holds as that member (bridge node lifecycle, §12.10.6 step 1).
2. The context's governance model processes the proposal (SingleAdmin: admin approves; Threshold/MajorityVote/Unanimity: members vote). ADR-023 (bridge connector protocol) states in acceptance criterion 2: "The approver must be a different DID from the operator (self-approval is forbidden)." A context executing an approved `RegisterBridge` action whose approving actor is the operator the proposal names therefore appends no `BridgeRegistered` leaf, assigns no `bridge_id`, and records that proposal's resolution alone, exactly as step 3 has it record the resolution of an approval whose derived identifier the context already assigned. Every member applies that rule while executing the approval, so the leaf a self-approval would have produced reaches no member's log and the admission criterion of §12.10.6 step 1 reads none: that criterion states the five clauses it reads and states no sixth clause for this rule. A SingleAdmin context whose admin is the bridge operator registers no bridge until its governance model admits a second actor whose decision approves the proposal, and a self-hosted bridge (§12.7) carries no exemption from this rule, because ADR-023 states it for every bridge.
3. On approval, the context appends a `BridgeRegistered` leaf (event type `BridgeRegistered`, ADR-011, verifiable event log) to its Merkle event log. The leaf payload is a `BridgeRegistrationEvent` with `action: Approved` (bridge registration wire table, §12.12.2). That payload carries the assigned `bridge_id` (a 64-character lowercase hex string carried as `String` on the wire, holding the SHA-256 of the preimage this step encodes over `context_id`, `operator_did`, `platform` and `timestamp`), the `operator_did` from the proposal, the `governance_did` of the actor whose decision approved the proposal, the `context_id` of the context that executed the proposal, and the leaf `timestamp` that event sequencing assigns (verifiable event logs, §7.3.1). The `timestamp` the derivation reads is this same leaf's `timestamp` and is no member's local clock reading. The preimage follows the canonical hash construction (canonical hash construction, §9.5.1 of the security-model spec): `SHA-256("SCP-BRIDGE-ID-V1:" || len(context_id) || context_id || len(operator_did) || operator_did || len(platform) || platform || timestamp)`. The domain separator `SCP-BRIDGE-ID-V1:` contributes its UTF-8 bytes and carries no length prefix, each of the three string components contributes a 4-byte big-endian `u32` holding the length in bytes of its UTF-8 encoding followed by those UTF-8 bytes, and the `timestamp` component contributes the 8 bytes of its `u64` value in big-endian order. Those length prefixes make the encoding injective, so two different `(context_id, operator_did, platform, timestamp)` tuples produce two different preimages and no shift of the boundary between two string components maps two tuples to one preimage. §9.5.1 governs this preimage as it governs every other hash the protocol takes over variable-length fields, and the version suffix `V1` in the separator carries the rule §9.5.1 states for changing a field's encoding, adding a field, or removing one. Two members that executed one approval therefore hash one byte string and derive one identifier. A derivation that left the `timestamp` encoding to the implementation would not give them that: a member that wrote the ASCII decimal representation §12.10.2 pins for `X-SCP-Timestamp` and a member that wrote the big-endian bytes would write two different `bridge_id` values into one leaf's payload, their two leaves would differ byte for byte, and equivocation detection would read that difference as equivocation by two honest members (§9.9.3). Every member executes the approved `RegisterBridge` payload under the context's governance model (governance, §5.9), and step 4 publishes the resulting bridge metadata.

   That derivation reads a `timestamp` of one-second resolution, so two approvals that carry one `context_id`, one `operator_did` and one `platform` and that execute within one second derive one identifier. A context therefore holds, as convergent context state, the set of every `bridge_id` it has assigned. A member derives that set by executing the context's commits: the set gains one identifier for each `BridgeRegistered` leaf the context appends, and loses none. The context appends a `BridgeRegistered` leaf for an approved `RegisterBridge` action only when that set does not already hold the derived identifier. For an approval whose identifier the set already holds, the context appends no `BridgeRegistered` leaf, records the proposal's resolution alone, and the operator submits the registration again; the resubmitted approval executes at a later `timestamp` and derives a different identifier. A context executes the approvals that one commit carries in the order that commit carries them, and adds each identifier it assigns to the set before it evaluates the next approval of that same commit, so two approvals in one commit produce one bridge and one identifier. The set retains an identifier after governance revokes the bridge that identifier named, so an approval that re-derives an assigned identifier appends no leaf whatever became of that bridge, and `Revoked` stays terminal (bridge status state machine, §12.2.1).

   The rule reads that derived set and reads the payload of no leaf, because a rule that read payloads would not converge. Log pruning removes event payloads and leaves the state a member already derived from them untouched, and ADR-030 (event log pruning and checkpointing) makes each member's decision to prune local to that member, so two members that pruned different prefixes hold different payload sets. A context that decided the append by reading the `bridge_id` payload of the `BridgeRegistered` leaves its log still carries would let the member that pruned the earlier payload append a leaf the member that retained it skipped. Those two members would then hold different event counts at one commit position, and equivocation detection would read that difference as equivocation by two honest members (§9.9.3). The derived set survives the prune that removes the payload the member derived it from, so every member reaches one verdict for one approval.

   One `bridge_id` therefore names one bridge in one context, on two grounds: the context assigns each identifier once, and the preimage above encodes the four components injectively. A SHA-256 collision is the one remaining route that maps two component tuples to one identifier, and both readers of the identifier refuse rather than mis-resolve when a collision produces one. The admission criterion (bridge node lifecycle, §12.10.6 step 1) reads only leaves whose payload `context_id` names the context whose log holds them, so a collision admits a bridge into no context its registration did not name. The webhook key identifier (authentication, §12.10.2 step 6) digests the `bridge_id`, and a node that holds two stored (bridge, key) pairs carrying one key identifier answers the delivery with the rejected webhook response rather than choosing one of the two bridges, so a collision moves no platform event across a context boundary.

4. The context metadata is republished with the new bridge in the `bridges` structural field (§5.7).
5. For cooperative mode: the bridge node stores the `platform_key` for webhook signature verification (§12.10.2).

**Bridge status state machine:**

```
Active ──→ Suspended ──→ Active     (reactivation via governance)
Active ──→ Suspended ──→ Revoked    (permanent removal)
Active ──→ Revoked                  (immediate permanent removal)
```

`Revoked` is a terminal state — a revoked bridge cannot be reactivated. A new `RegisterBridge` proposal is required to re-establish a bridge with the same operator and platform.

### 12.2.2 Bridge Removal Protocol

Bridge removal uses the `RevokeBridge` governance action:

```
RevokeBridge {
  bridge_id:       [u8; 32],         // the bridge to revoke
  reason:          String,           // governance justification
  destroy_shadows: bool,             // true = retire all shadows; false = shadows persist as orphaned
}
```

**Removal flow:**

1. An admin or governance-authorized member submits a `RevokeBridge` proposal.
2. On governance approval, the context appends a `BridgeRevoked` leaf (event type `BridgeRevoked`, ADR-011, verifiable event log) to its Merkle event log. The leaf payload is a `BridgeRegistrationEvent` with `action: Revoked` (bridge registration wire table, §12.12.2).
3. The bridge's `BridgeStatus` transitions to `Revoked`.
4. If `destroy_shadows` is true: all shadow identities associated with this bridge are retired. Each shadow retirement emits a `ShadowRetired` event. Historical actions attributed to shadows remain in the event log with their original provenance.
5. If `destroy_shadows` is false: shadows persist but are orphaned — no new messages can be emitted through them, but their historical attributions remain.
6. The credential store for this bridge instance MUST destroy all delegated credentials (§12.11.1 Phase 5).
7. In-flight messages from shadows that have not yet been committed to the event log are dropped. The bridge node receives the `BRIDGE_FORBIDDEN` error (error format, §12.10.3) on subsequent authenticated bridge API calls, and receives `BRIDGE_SUSPENDED` on none of them, because a revoked bridge fails the admission criterion on the revocation clause rather than on the suspension clause (bridge node lifecycle, §12.10.6 step 1). That step assigns the code for every failure of the criterion, and a node that answered a revocation with `BRIDGE_SUSPENDED` would tell the operator that governance suspended a bridge governance revoked.
8. Context metadata is republished with the bridge removed from the `bridges` field.

**Suspension** uses `SuspendBridge { bridge_id, reason, duration: Option<u64> }`. On governance approval, the context appends a `BridgeSuspended` leaf (event type `BridgeSuspended`, ADR-011, verifiable event log) to its Merkle event log. The leaf payload is a `BridgeRegistrationEvent` with `action: Suspended { reason, duration }` (bridge registration wire table, §12.12.2). Suspension stops message processing but retains shadow state and credentials (§12.11.1).

A suspension whose payload `duration` is `Some(d)` expires on a deadline, and its expiry appends no leaf. The node computes that deadline as the later of two sums, and takes each sum with saturating addition: the leaf `timestamp` plus `d`, and the instant at which the node executed the commit that appended the leaf plus `d`. The second sum bounds the deadline below, because the first sum alone does not bound it below at all. Event sequencing (§7.3.1) makes the leaf `timestamp` the `created_at` that the committing member assigned to its own commit envelope, and §9.8.2(c) rejects a `created_at` more than 5 minutes in the future while bounding the past only by non-regression within one sender's own envelopes. Every governance model other than SingleAdmin lets any member commit an approved action (§7.3.1, event sequencing), so the bridge operator — the party a suspension acts against — can commit its own suspension. An operator who has sent no envelope in the context for longer than `d` seconds can therefore stamp that commit with a `created_at` older than `d`, every member copies that value into its own leaf, and a node reading the first sum alone would read the suspension as already expired at the instant governance approved it. The node MUST record that execution instant durably, alongside the leaf, when it executes the commit that appends the leaf, and MUST compute the deadline from the recorded value on every later evaluation. A node that finds no recorded instant for a leaf — because the node restarted before it recorded one, or because it restored storage that carries none — substitutes the instant at which it first read the leaf after that restart, and MUST record that substitute durably in the same place before it computes a deadline from it. The record makes the substitution happen once per leaf, so the node computes one deadline from one substitute and no later restart moves that deadline again. The substitute exceeds the instant at which the node executed the commit by however long the node was down, and this rule bounds that distance nowhere, so a node that crashed before it recorded an instant holds the suspension past the instant a `d`-second duration named. The substitution moves a deadline later and moves no deadline earlier, so it readmits no bridge before the deadline the recorded execution instant would have produced, and a node that holds a suspension longer than governance intended withholds admission rather than granting it. Without the record the node would substitute a fresh instant on every restart, each restart would move the deadline another `d` seconds into the future, and a bounded suspension would never expire on a node that restarts more often than every `d` seconds, which is the outcome the rest of this paragraph forbids. Saturating addition makes a `duration` whose sum would exceed the representable range produce a deadline the node's clock never reaches, so the node refuses the bridge until governance reactivates it. A bridge whose last bridge lifecycle leaf is that `BridgeSuspended` leaf passes the admission criterion again once the deadline has passed (bridge node lifecycle, §12.10.6 step 1), so the bridge reactivates without any member appending anything. That deadline readmits a bridge only while the admission criterion can order the bridge's lifecycle leaves. Event sequencing (§7.3.1) gives each author of a broadcast context an independent counter, so once two members have appended lifecycle leaves for one bridge the criterion reads no last leaf and readmits that bridge in no case, whatever the deadline; §12.10.6 step 1 (which lifecycle leaf is the last one) states that refusal and the operator's remedy.

Expiry MUST NOT append a leaf. Only the bridge operator's own node evaluates the admission criterion (bridge node lifecycle, §12.10.6 step 1), and that node computes the deadline from the `BridgeSuspended` leaf it already holds, so an expiry leaf would record no fact the log does not already carry. Event sequencing (§7.3.1) does admit leaves that a member-local timer triggers — TTL expiry and close, governance-freeze expiry, and deferred economic-policy application — and keeps each one convergent by stamping it with the pre-computed deadline that convergent context state already holds. The protocol appends no leaf for a bridge-suspension expiry because that expiry records no fact, not because a timer-triggered leaf cannot converge. A leaf that a member-local timer appended with that member's own `now()` in place of a pre-computed deadline would break the equal-event-count ⇒ equal-root property that equivocation detection reads (§9.9.3), because two members would then stamp the same event with two different timestamps.

A suspension whose payload `duration` is `None` expires on no deadline, so it stands until governance approves an explicit `ReactivateBridge { bridge_id }` action. On that approval the context appends a `BridgeReactivated` leaf (event type `BridgeReactivated`, ADR-011, verifiable event log) whose payload is a `BridgeRegistrationEvent` with `action: Reactivated`. The `BridgeReactivated` leaf readmits the bridge on the bridge node only while the admission criterion can order the bridge's lifecycle leaves. In a broadcast context, once two members have appended lifecycle leaves for one bridge, §7.3.1 orders one author's leaf against another author's not at all, so the criterion reads no last leaf and the `BridgeReactivated` leaf readmits that bridge in no case; the operator's remedy is a fresh `RegisterBridge` proposal, which §12.10.6 step 1 (which lifecycle leaf is the last one) states together with the rest of that refusal. A `BridgeSuspended` leaf supersedes every bridge lifecycle leaf below it, so the deadline of a superseded suspension readmits no bridge: the deadline clause of §12.10.6 step 1 reads the last bridge lifecycle leaf and reads no earlier one. The revocation clause of that same criterion reads every one of the bridge's lifecycle leaves rather than the last leaf alone, so a `BridgeReactivated` leaf appended after a `BridgeRevoked` leaf readmits no bridge. A `BridgeRevoked` leaf makes the bridge fail §12.10.6 step 1 permanently, whatever leaf follows it, because `Revoked` is terminal (bridge status state machine, §12.2.1).

### 12.2.3 Terminology: Bridge Connector vs. FFI `BridgeInstance`

Two concepts share the name "bridge" in this system and MUST be kept distinct:

1. **Bridge connector (this section).** A protocol-level entity that translates between an external platform and an SCP context. Every bridge connector has an operator DID (§12.2 above). This is a governed, accountable actor inside an SCP context.

2. **FFI `BridgeInstance` (implementation detail).** A runtime container in the FFI layer (`scp-ffi-common`) that holds per-instance infrastructure — the context supervisor (which owns the per-context actors; ADR-049), DID resolver, storage provider, identity registry. It is the SDK's entry point, not a protocol entity. An `FFI::BridgeInstance` has NO DID requirement; it is infrastructure that exists before any identity is created. An SDK consumer may use the FFI `BridgeInstance` purely to resolve DIDs or verify attestations without ever creating a local identity. Multiple `BridgeInstance`s may coexist in a process (ADR-048).

The protocol invariant "every action traces to a human" (§04, §09) applies to **bridge connectors** (protocol entities with operator DIDs) — it does NOT apply to the FFI `BridgeInstance` container. Conflating the two produces a chicken-and-egg during SDK initialization: DID resolution is needed to verify signatures on any DID (including remote members'), and must not require a local identity to exist first.

When reading protocol documents, "bridge" means bridge connector unless the context explicitly refers to FFI layer code.

The FFI `BridgeInstance` is the layer that selects the storage backend and threads it into the supervisor. Storage selection at this layer MUST fail closed: if the caller selects a durable backend that cannot be opened, the `BridgeInstance` MUST return an error rather than silently falling back to in-memory or no storage. In-memory storage is reachable only via an explicit in-memory selection and is dev/test-only. The runtime never defaults storage — the `BridgeInstance` supplies it as a required parameter. These rules are normative in §17.6 ("In-Memory Storage Is Dev/Test-Only", "Storage Selection Fails Closed", "The Runtime Never Defaults Storage").

## 12.3 Shadow Identities

When a bridge connector brings external platform participants into an SCP context, it creates **shadow identities** — protocol-level representations of entities that exist on the external platform but do not (yet) have native SCP identities.

Shadow identities differ from native SCP identities in critical ways:

- **Attributed but not verified.** A shadow identity for `@dave_x` asserts that this entity is Dave on X. The assertion comes from the bridge operator, not from Dave himself. The trust in this attribution depends on trust in the bridge operator.
- **Restricted by default.** Shadow identities receive a constrained role — typically observer-equivalent. They cannot exercise capabilities that require verified identity. Specific role assignment is up to context governance.
- **Marked as bridged.** All actions and content associated with a shadow identity carry provenance marking indicating the bridge source. No shadow identity can be mistaken for a native SCP participant.
- **Bounded per bridge.** Each bridge has a governance-configured `max_shadows` limit (set during registration, §12.2.1). The protocol default is 10,000 shadows per bridge instance. Contexts MAY set lower limits. When the limit is reached, `POST /v1/scp/bridge/shadow` returns `RATE_LIMITED` (429) with a message indicating the shadow cap. The limit prevents resource exhaustion from unbounded shadow creation.
- **Claimable.** If Dave later joins SCP and publishes an identity attestation (§3.5) binding his X handle to his DID, his shadow identity can be claimed and merged with his native identity. Past actions attributed to the shadow are now attributed to Dave's DID. This transition is one-way and irreversible — once claimed, the shadow is retired.

**Claimed shadow role upgrade path.** When a shadow is claimed by a DID:

1. The shadow's `provenance_status` transitions from `Shadow` to `Claimed`.
2. The claimant does NOT automatically become a context member — claiming a shadow and joining a context are independent operations. The claimant MUST separately join the context via the standard join flow (§5.12).
3. On successful join, the context governance MAY automatically upgrade the claimant's role from the default join role to the shadow's previous role (if the governance model permits role inheritance from claimed shadows). This is a governance policy decision, not a protocol default.
4. Historical messages attributed to the shadow are retroactively associated with the claimant's DID in the event log metadata. The original `BridgeProvenance` marking is preserved — historical content carries `provenance_status: "ClaimedHistorical"` to distinguish pre-claim bridged content from post-claim native content.
5. The shadow entry is retired: no further messages can be emitted through it via the bridge. The bridge operator receives `SHADOW_ALREADY_CLAIMED` (409) on subsequent message attempts for this shadow.

```
  Before claiming:                   After claiming:

  @dave_x (shadow)                   Dave·Agent (did:dht:xyz)
  ├─ source: X Bridge                ├─ native SCP identity
  ├─ operator: bridge_did            ├─ attestation: @dave_x on X
  ├─ role: observer                  ├─ role: member (upgraded by governance)
  ├─ trust: depends on bridge        ├─ trust: depends on Dave's DID
  └─ provenance: bridged             └─ provenance: native
                                         └─ historical: bridged (pre-claim)
```

## 12.4 Bridge Operating Modes

Bridge connectors operate in one of several modes, reflecting the practical constraints of interfacing with uncooperative platforms:

**Relay mode.** The bridge operates a single account on the external platform and relays content through it. External participants appear via shadow identities. Attribution depends on the bridge parsing the external platform's messages correctly. This is the most robust mode — it requires no user credentials and works even when platforms actively resist bridging.

**Puppet mode.** The bridge authenticates as the SCP user on the external platform, using credentials the user has delegated. Messages appear to come from the user natively on the external platform. This provides better fidelity but requires the user to trust the bridge operator with their external platform credentials. Self-hosted bridges mitigate this — users run their own bridge and delegate credentials only to software they control.

**API mode.** The bridge uses the external platform's official API (where available). This is the most stable mode but limited by whatever the platform exposes. Some platforms (Bluesky/AT Protocol, Mastodon/ActivityPub) are fully open and make this trivial. Others (X, Facebook) restrict API access to the point of uselessness for social bridging.

**Cooperative mode.** The external platform voluntarily implements the bridge connector interface. This does not require the platform to adopt SCP — only to expose a structured interface that the bridge can consume. This is the aspirational end state: platforms don't conform to SCP, but they interface with a connector to participate. This mode requires no credential delegation, no scraping, no reverse engineering.

The protocol defines the bridge connector interface such that cooperative mode is clean and well-documented, making the ask to platforms minimal: "You don't need to change anything about your system. Just implement this interface and your users can participate in SCP contexts."

## 12.5 Trust and Provenance for Bridged Content

All content entering an SCP context through a bridge carries a **provenance chain** that includes:

- The originating platform
- The bridge connector that carried it
- The bridge operator's DID
- The bridge operating mode
- The shadow identity it's attributed to (or the native DID if claimed)

This provenance is structural, not content-level. It flows through the data provenance system (§7.7) and is available to any agent evaluating trust.

Trust evaluation for bridged content is necessarily weaker than for native content. The hierarchy reflects two independent axes — **identity confidence** (who is the author?) and **transport confidence** (how did the content arrive?):

```
Trust hierarchy:

  IDENTITY                TRANSPORT              COMBINED

  Native SCP identity     Native action          ← strongest
  (DID verified)          (end-to-end SCP)         Both axes at full confidence.

  Native SCP identity     Bridged action          ← strong
  (DID verified)          (via bridge infra)        Identity is verified — an attestation
                                                    links the external handle to the DID.
                                                    But content traveled through bridge
                                                    infrastructure: timestamps are platform-
                                                    reported, content integrity depends on
                                                    bridge operator fidelity.

  Claimed shadow          Historical bridged      ← moderate
  (retroactive DID link)  (pre-claim content)       User joined SCP and claimed an existing
                                                    shadow. Old content gets retroactive
                                                    attribution, but was created before any
                                                    SCP identity existed to verify against.

  Shadow identity         Bridged action          ← weakest
  (no DID claim)          (via bridge infra)        No SCP identity has claimed this shadow.
                                                    Trust depends entirely on the bridge
                                                    operator's DID and reputation.
```

Agents can calibrate their behavior based on provenance. A conservative agent might ignore all shadow-attributed content. A permissive agent might treat claimed shadows equivalently to native identities. The protocol makes the distinction legible; the evaluation is up to the participant.

**Integration with DataProvenance (§24).** `BridgeProvenance` extends `DataProvenance` (§24.2) for bridge-originated content:

```
BridgeProvenance {
  // Inherited from DataProvenance (§24.2.1):
  source_context:     ContextId,
  source_type:        .persistent,          // bridge contexts are always persistent
  counterparties:     [DID],                // includes shadow DIDs
  purpose:            String,
  discovery_method:   DiscoveryMethod,
  age:                Duration,
  memory_scope:       MemoryScope,
  chain_depth:        u8,                   // 0 for direct bridge content

  // Bridge-specific extensions:
  originating_platform: String,             // "discord", "slack", "x", etc.
  bridge_mode:          BridgeMode,         // Relay | Puppet | API | Cooperative
  shadow_status:        ShadowStatus,       // Shadow | Claimed | ClaimedHistorical
  operator_did:         DID,                // bridge operator's DID
  platform_timestamp:   Option<u64>,        // platform-reported timestamp (untrusted)
  platform_message_id:  Option<String>,     // cross-reference to platform message
}
```

When the quality evaluation pipeline (§24.5) encounters bridge-originated content, it applies the following `source_type` mapping:

| Bridge mode | Shadow status | Equivalent `ProvenanceQuality` | Rationale |
|-------------|---------------|-------------------------------|-----------|
| Cooperative | Claimed | `PersistentVerifiable` (minus 1 tier) | Platform vouched for identity, but content transited bridge infrastructure |
| Cooperative | Shadow | `PersistentPartial` | Platform vouched for attribution, no DID binding |
| API | Claimed | `PersistentPartial` | API-sourced, platform did not actively vouch |
| API | Shadow | `EphemeralKnown` | API-sourced, no identity verification |
| Relay/Puppet | Any | `EphemeralKnown` | Bridge operator is sole trust anchor |

This mapping feeds into the `evaluate_quality` pipeline (§24.5.1) so that bridge-originated content receives appropriate quality scoring without requiring special-case logic in the provenance evaluation engine.

## 12.6 Bridge Connectors and Context Isolation

Bridge connectors do not violate context isolation. A bridge registered in Context A has no access to Context B. If the same external platform is bridged into two contexts, they are separate bridge instances with separate registrations.

Bridge connectors are not agents — they cannot initiate actions, exercise capabilities, or participate in governance. They are translation infrastructure. All agency flows through the agents and governance of the context they're registered in.

### 12.6.1 Bridge Encryption Model

Bridge connectors — the translation infrastructure — are **not MLS group members**. Shadow identities created by a bridge do not receive MLS key schedule material.

However, the **bridge operator** (the DID-bearing human who runs the bridge) IS an MLS group member admitted through normal context governance. The operator must be a member to receive and decrypt SCP messages for SCP-to-platform forwarding (§12.10.5). This means the bridge operator can read all MLS-encrypted messages in the context — a necessary consequence of bidirectional bridging. The trust implications are explicit: admitting a bridge means trusting the bridge operator with access to context content. This is visible in context metadata (§5.7) so members can make informed consent decisions.

Shadow identity messages use the **sender key layer** (§9.16) rather than MLS encryption. The bridge operator generates a sender key per shadow identity and distributes it via the same pull-based protocol used in broadcast contexts. Native members decrypt bridge-originated messages using the shadow's sender key.

This creates two envelope types within a bridged encrypted context:

- **MLS-encrypted envelopes** — from native members and the bridge operator, using the MLS group key schedule.
- **Sender-key-encrypted envelopes** — from shadow identities, using per-shadow sender keys. All context members (native and bridge operator) can decrypt these.

The receiver distinguishes the two paths by envelope structure: MLS-encrypted envelopes contain an MLS ciphertext payload, while sender-key-encrypted envelopes contain a sender key ciphertext with the shadow's DID in the sender field. Both decryption paths already exist in the protocol — MLS for encrypted contexts, sender keys for broadcast contexts.

Context metadata (§5.7) MUST include a `BridgeMetadata` entry in the `bridges` structural field when a bridge is registered, including the bridge operator's DID, the connected platform, the bridge's capabilities, and its directionality mode. This is a structural field visible before opt-in, so prospective members can see that a bridge is present and evaluate trust accordingly before joining.

### 12.6.2 Bridge Threat Model

A malicious bridge operator can:

1. **Read all MLS-encrypted messages in the context** — the bridge operator is an MLS group member (§12.6.1) and can decrypt all messages. This is an inherent property of bidirectional bridging, not mitigated — it is why bridge admission is a governance decision.
2. **Fabricate shadow messages** — attribute content to platform users who did not produce it. Mitigated by `BridgeProvenance` (§12.5) which makes bridge attribution visible.
3. **Selectively drop messages** — suppress platform-to-SCP or SCP-to-platform delivery. Detectable via the platform's own delivery confirmation mechanisms.
4. **Correlate activity** — observe which platform users correspond to which shadow identities across contexts it operates in. Mitigated by separate bridge registrations per context (§12.6).
5. **Inject false attestations** — claim platform identity verification that did not occur. Mitigated by attestation freshness checks (§7.4.4) and governance-level bridge revocation (§12.2).

A malicious bridge operator **cannot**:

- Modify native member messages (MLS authentication prevents forgery).
- Exercise capabilities or participate in governance beyond the operator's own member role (bridge connector is not an agent).
- Access other contexts (bridge registration is per-context).

Note: the bridge operator CAN read all MLS-encrypted messages in the context (they are an MLS group member — see §12.6.1). This is an inherent property of bidirectional bridging and is why bridge admission is a governance decision visible in context metadata (§5.7).

## 12.7 Self-Hosting Bridges

Consistent with SCP's self-hosting philosophy (§10), bridge connectors are self-hostable. A user can run their own bridge to connect their own external platform accounts into SCP contexts they participate in. Self-hosted bridges eliminate the need to trust a third-party bridge operator with credentials or data.

The managed infrastructure layer (§10.5) may offer hosted bridges as a convenience service, but the protocol treats self-hosted and managed bridges identically.

## 12.8 Platform Resistance

Platforms can and will resist bridging. This is expected and acknowledged. Resistance takes forms:

- API restriction or removal
- Rate limiting authenticated sessions
- Protocol changes that break reverse-engineered integrations
- Legal threats (ToS enforcement, cease-and-desist)

The protocol's response is structural, not adversarial:

- **Cooperative mode** gives platforms a reason to participate rather than resist — their users can reach SCP contexts without leaving the platform.
- **Relay and puppet modes** are resilient but fragile. The ecosystem maintains bridge implementations communally, similar to how Matrix bridges are maintained today.
- **Data portability rights** (GDPR, CCPA, EU Digital Markets Act) provide legal backing for users accessing their own data.
- **The aspirational path** is that as SCP's network grows, platforms face economic pressure to offer cooperative mode rather than lose users to a network they can't see into.

## 12.9 Incentive Structure for Cooperative Mode

Cooperative mode should not be aspirational — it should be the path of least resistance for platforms. The protocol achieves this by making non-cooperation expensive and cooperation cheap.

**Why platforms resist bridging (Matrix's experience):** Bridges leak users off the platform. A WhatsApp user who can read WhatsApp messages in Matrix has less reason to open WhatsApp. The platform loses engagement metrics, ad impressions, and data collection surface.

**Why SCP changes the equation:**

- **Shadow identities are second-class.** Bridged content via relay/puppet mode is provenance-marked as weak-trust. Platform users who show up as shadows in SCP contexts are legible but untrusted. If the platform implements cooperative mode, their users get stronger provenance — bridged-cooperative is more trusted than bridged-relay because the platform has vouched for the attribution.
- **Cooperative mode gives the platform a seat.** In cooperative mode, the platform can include metadata about its users that strengthens trust evaluation. This gives the platform influence over how its users are perceived in SCP — influence it doesn't have in relay/puppet mode where a third party is scraping.
- **The bridge happens anyway.** If users want to bridge, relay and puppet modes exist. The platform can't prevent it without hurting its own users' experience. Cooperative mode gives the platform control over a process that will happen regardless.
- **Minimal implementation cost.** The bridge connector interface is deliberately small — a handful of structured endpoints. Not a protocol adoption, not an architecture change. Comparable to implementing an OAuth provider or a webhook receiver.

The design principle: make the protocol's trust model reward cooperation and make non-cooperation a worse experience for the platform's own users, without making it an ultimatum.

## 12.10 Cooperative Mode HTTP Binding

This section specifies the concrete HTTP API that a cooperating external platform implements to participate in SCP contexts via cooperative mode (§12.4). The API maps directly to existing bridge operations in `scp-core/bridge/`. A bridge node operated by an SCP participant mediates between the platform's HTTP endpoints and SCP protocol semantics.

### 12.10.1 Design Principles

- **Platform implements, bridge node consumes.** The platform exposes these endpoints. The bridge node calls them and also exposes a webhook receiver for platform-initiated events. The platform never calls SCP directly.
- **Minimal surface area.** Six endpoints. No SCP-specific data structures leak into the platform's API — all SCP envelope construction, sender key encryption (§12.6.1), and provenance marking happen on the bridge node.
- **Authentication via DID-signed tokens.** The bridge operator's DID signs bearer tokens used for all requests. The platform validates signatures against the operator's published DID document.
- **Idempotent where possible.** Shadow creation and deletion are idempotent to tolerate retries.
- **JSON over HTTPS.** All requests and responses use `Content-Type: application/json`. TLS 1.3 required per §9.13.
- **Versioned.** All paths are prefixed with `/v1/`. Future breaking changes increment the version prefix.

### 12.10.2 Authentication

The bridge operator authenticates to the platform using DID-signed bearer tokens:

```
Authorization: Bearer <DID-signed-JWT>
```

The JWT payload contains:

```json
{
  "iss": "did:dht:z6MkOperator...",
  "aud": "https://platform.example.com",
  "iat": 1700000000,
  "exp": 1700003600,
  "scp_bridge_id": "bridge-abc123",
  "scp_context_id": "ctx-def456"
}
```

The platform verifies the JWT signature against the operator's DID document (§3.2). Token lifetime SHOULD NOT exceed 1 hour. The platform MAY cache resolved DID documents with TTL.

**JWT signing algorithm.** The JWT `alg` header MUST be `EdDSA` (RFC 8037) using Ed25519, consistent with the protocol's key infrastructure. SDKs MUST reject JWTs with any other algorithm.

For webhook callbacks (platform to bridge node), the platform signs the request body with the following scheme:

```
X-SCP-Signature: <base64url(Ed25519-sign(signing_key, canonical_payload))>
X-SCP-Platform-Key-Id: <key identifier of step 6 below>
X-SCP-Timestamp: <Unix timestamp in seconds>
```

**Canonical payload construction.** The signed payload is constructed as: `timestamp_bytes || raw_request_body_bytes`, where `timestamp_bytes` is the ASCII decimal representation of the `X-SCP-Timestamp` value. This prevents replay attacks — the bridge node MUST reject requests where `X-SCP-Timestamp` differs from the current time by more than 300 seconds (5 minutes).

**Platform key registration mechanism.** The platform's Ed25519 public key is registered during bridge setup via the `RegisterBridge` governance action (§12.2.1), which includes an optional `platform_key: Option<[u8; 32]>` field. For cooperative mode, this field is REQUIRED. The key exchange flow:

1. Before registration, the bridge operator and platform operator exchange the platform's Ed25519 public key out-of-band (e.g., via the platform's developer console, an API call to the platform, or manual configuration).
2. The bridge operator includes the `platform_key` in the `RegisterBridge` proposal.
3. On governance approval, the bridge node stores the platform key associated with the bridge instance, and the bridge operator sends the platform the key identifier of step 6 for that bridge. The operator sends it after the approval, because §12.2.1 step 3 assigns the `bridge_id` that the identifier covers on approval.
4. All subsequent webhook requests from the platform are verified against this key.
5. Key rotation: the platform publishes a new key by having the bridge operator submit a `UpdateBridgePlatformKey { bridge_id, new_platform_key }` governance action. During the rotation period the bridge node accepts signatures from either key. The new key carries its own key identifier under step 6, which the operator sends the platform on approval; both identifiers name the same bridge for the rotation period, because both cover that bridge's `bridge_id`.

   The rotation period ends on a deadline, and the node computes that deadline as the earlier of two sums, taking each sum with saturating addition: the `timestamp` of the `GovernanceActionExecuted` leaf that records the context's execution of the approved `UpdateBridgePlatformKey` action plus 86400 seconds, and the instant at which the node executed the commit that appended that leaf plus 86400 seconds. That leaf is the one this action produces: §12.2.1 step 3 and §12.2.2 append a bridge lifecycle leaf for an approved `RegisterBridge`, `SuspendBridge`, `ReactivateBridge` and `RevokeBridge` action and append none for an approved `UpdateBridgePlatformKey` action, and ADR-011, the verifiable event log, declares `GovernanceActionExecuted` as the event type a context appends when it executes an approved governance action. At that deadline and after it the node accepts a signature from the superseded key not at all, and accepts a signature from the new key alone. The node MUST record that execution instant durably when it executes that commit, as §12.2.2 obliges it to record the execution instant of a `BridgeSuspended` leaf, and a node that holds no recorded instant for that `GovernanceActionExecuted` leaf accepts the superseded key not at all.

   §12.2.2 computes the suspension deadline as the **later** of its two sums and this step computes the rotation deadline as the **earlier** of its two, and one rule decides both directions: each node takes the sum that withholds what the deadline grants. A longer suspension refuses a bridge, and a shorter rotation period refuses a superseded key. Event sequencing (§7.3.1) makes the leaf `timestamp` the `created_at` that the committing member assigned to its own commit envelope, §9.8.2(c) rejects a `created_at` more than 5 minutes in the future and bounds the past only by non-regression within one sender's own envelopes, and every governance model other than SingleAdmin lets any member commit an approved action, so a member can stamp that commit with a `created_at` up to 5 minutes ahead of the instant it commits and with one arbitrarily far behind. The execution-instant sum bounds the future direction, so a member that post-dated its commit extends the node's acceptance of the superseded key by no time at all; the leaf-`timestamp` sum bounds nothing below, so a member that backdated its commit shortens the rotation period on every node, and the node then rejects deliveries the platform signed with the superseded key. The platform's remedy for a shortened period is to sign with the new key, whose identifier step 3 has the operator send it on approval. The node writes no substitute for a missing execution instant under the same rule: a substitute exceeds the execution instant it stands in for by however long the node was down, so a deadline computed from it would extend the node's acceptance of a key governance superseded, while refusing that key withholds acceptance rather than granting it.
6. Key identifier: `X-SCP-Platform-Key-Id` carries a 64-character lowercase hex string holding `SHA-256("SCP-BRIDGE-PLATFORM-KEY-ID-V1:" || bridge_id || platform_key)`, where `bridge_id` contributes the 64 ASCII bytes of the bridge's lowercase hex `bridge_id` and `platform_key` contributes the 32 bytes that the approved `RegisterBridge` or `UpdateBridgePlatformKey` action registered for that bridge. That preimage follows the canonical hash construction (canonical hash construction, §9.5.1 of the security-model spec): the domain separator carries no length prefix, and the schema fixes the length of both components, so neither component carries a length prefix either. The digest covers the `bridge_id` because the key bytes alone name no bridge: a platform publishes one webhook signing key, one operator may run one bridge into each of two contexts against that one platform, and both `RegisterBridge` approvals then register the same 32 bytes. A digest over those bytes alone would name both of those bridges and would therefore name both of those contexts, and a node that chose either one would move a platform event across a context boundary on its own choice rather than on a governed path (bridge connectors as protocol entities, §12.2). §12.2.1 step 3 makes one `bridge_id` name one bridge in one context: a context appends a `BridgeRegistered` leaf only for an approval whose derived identifier the set of identifiers that context has assigned does not already hold. Two bridges in two contexts carry one `bridge_id` on a SHA-256 collision and on no other route, because §12.2.1 step 3 encodes that identifier's preimage injectively, so a node that operates both of those bridges and stores one platform key for each holds two pairs carrying one key identifier. The last rule of this step answers that delivery with the rejected webhook response, so the pairs that produce any one key identifier either all name one bridge or name no bridge the node serves that delivery for. A bridge that rotates to the key bytes it already registered holds two pairs that produce one identifier, and that identifier still names that one bridge. The bridge node computes that identifier for every (bridge, key) pair it stores, so the header resolves to the stored pairs carrying that identifier without the node verifying any signature first, and through them to the one bridge whose governance approval registered those pairs' key (bridge node lifecycle, §12.10.6 step 1). The platform names the bridge a delivery is for by stamping that bridge's key identifier on it, which is how a platform that serves two of a node's bridges names which context each delivery enters. A delivery whose `X-SCP-Platform-Key-Id` matches the identifier of no (bridge, key) pair the node stores resolves to no bridge, and the node rejects it (§12.10.6 step 1). A delivery whose identifier matches pairs of two different bridges resolves to no bridge either, and the node rejects it. A node holding two such pairs either operates two bridges whose `bridge_id` values collide under the derivation of §12.2.1 step 3, or holds a key store that a party with write access to the node's storage rewrote; §12.2.1 step 3 keeps the governance path of one context from producing two of them, and it bounds no pair of contexts. The node refuses that delivery in both cases rather than choosing one of the two bridges.

### 12.10.3 Error Format

All error responses use a consistent JSON structure:

```json
{
  "error": {
    "code": "SHADOW_NOT_FOUND",
    "message": "No shadow identity exists with the given ID",
    "details": {}
  }
}
```

Standard error codes:

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `SHADOW_NOT_FOUND` | 404 | Shadow identity does not exist |
| `SHADOW_ALREADY_EXISTS` | 409 | Shadow with this platform_user_id already exists |
| `SHADOW_ALREADY_CLAIMED` | 409 | Shadow has been claimed and cannot be modified |
| `BRIDGE_NOT_AUTHORIZED` | 401 | The node did not verify the caller's bearer token — the call carried none, or the token's signature failed verification, or the token expired — or the node verified the token and then failed to bind the verified caller to the bridge the token names, under the two claim bindings of §12.10.6 step 1 |
| `BRIDGE_FORBIDDEN` | 403 | The node verified the caller's bearer token and bound the verified caller to the bridge the token names, under the two claim bindings of §12.10.6 step 1, and that bridge then failed the admission criterion of that step on a clause other than the suspension clause. A bridge any of whose lifecycle leaves is a `BridgeRevoked` leaf receives this code whatever its last lifecycle leaf is, a `BridgeSuspended` leaf that a member appended after the revocation included (§12.2.2 step 7). The node reports this code on an authenticated bridge API call and reports it on no webhook delivery |
| `BRIDGE_SUSPENDED` | 403 | The node verified and bound the caller as the `BRIDGE_FORBIDDEN` row above states, and the bridge's last lifecycle leaf is then a `BridgeSuspended` leaf whose payload `duration` is `None`, or is `Some(d)` whose suspension deadline (§12.2.2) has not passed, while none of that bridge's lifecycle leaves is a `BridgeRevoked` leaf (§12.10.6 step 1). The node reports this code on an authenticated bridge API call and reports it on no webhook delivery |
| `RATE_LIMITED` | 429 | Request rate exceeds platform-configured limit |
| `INVALID_REQUEST` | 400 | Malformed request body |
| `INTERNAL_ERROR` | 500 | Unexpected server error |

Rate limiting uses standard `Retry-After` headers (seconds). Limits are platform-configurable and visible in the bridge status response.

### 12.10.4 Endpoints

#### POST /v1/scp/bridge/shadow

Create a shadow identity for an external platform user. Maps to `create_shadow()` in `scp-core/bridge/shadow.rs`.

**Request:**

```json
{
  "platform_handle": "@dave#1234",
  "platform_user_id": "usr_abc123",
  "metadata": {
    "display_name": "Dave",
    "avatar_url": "https://platform.example.com/avatars/dave.png",
    "joined_platform_at": "2024-01-15T00:00:00Z"
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `platform_handle` | string | yes | The user's handle on the external platform |
| `platform_user_id` | string | yes | The platform's internal user identifier (stable, not display name) |
| `metadata` | object | no | Platform-provided metadata about the user. Not interpreted by SCP — passed through for display/trust evaluation |

**Response (201 Created):**

```json
{
  "shadow_id": "shadow-xyz789",
  "platform_handle": "@dave#1234",
  "platform_user_id": "usr_abc123",
  "attributed_role": "observer",
  "created_at": 1700000100
}
```

The shadow starts with the `"observer"` role per §12.3. Context governance may subsequently upgrade the role.

**Idempotency:** If a shadow with the same `platform_user_id` already exists for this bridge, the existing shadow is returned with status `200 OK` instead of `201 Created`.

#### POST /v1/scp/bridge/message

Emit a message attributed to a shadow identity. The bridge node receives this, constructs the SCP envelope with appropriate provenance marking (§12.5), and publishes to the context via the standard message pipeline.

**Request:**

```json
{
  "shadow_id": "shadow-xyz789",
  "content": "Hello from the external platform!",
  "content_type": "text/plain",
  "platform_message_id": "msg_ext_456",
  "platform_timestamp": 1700000200
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `shadow_id` | string | yes | The shadow identity sending the message |
| `content` | string | yes | Message content |
| `content_type` | string | yes | MIME type of the content (`text/plain`, `text/markdown`, `application/json`). Binary content types are not supported — binary data MUST be base64-encoded and sent as `application/json` with the encoded data in a JSON field |
| `platform_message_id` | string | no | The message ID on the originating platform (for deduplication and cross-reference) |
| `platform_timestamp` | integer | no | Unix timestamp (seconds) when the message was created on the platform. Preserved in provenance as platform-reported time |

**Response (202 Accepted):**

```json
{
  "message_id": "msg-scp-abc123",
  "sequence": 42,
  "bridge_provenance": {
    "originating_platform": "discord",
    "bridge_mode": "Cooperative",
    "shadow_status": "Shadow",
    "operator_did": "did:dht:z6MkOperator..."
  }
}
```

The `202 Accepted` status indicates the bridge node has accepted the message for processing. Envelope construction and sender key encryption (§12.6.1) happen asynchronously. The `bridge_provenance` field confirms the provenance chain that will be attached.

**Content size limit.** The `content` field MUST NOT exceed 262,144 bytes (256 KiB), matching the relay's default `max_blob_size` (§10). Requests exceeding this limit are rejected with `INVALID_REQUEST` (400) and the message `"Content exceeds maximum size of 262144 bytes"`. The bridge node MUST enforce this limit before attempting MLS envelope construction.

**Claimed shadows:** If the shadow has been claimed (bound to a DID), messages can still be emitted through this endpoint, but the provenance chain will reflect the claimed status (`shadow_status: "Claimed"`) and the trust level evaluation will place it at the `ClaimedBridged` tier (§12.5).

#### POST /v1/scp/bridge/attest

Platform vouches for a user's identity. This produces an `IdentityLink` attestation (§3.5) signed by the bridge operator, asserting the platform's confidence in the mapping between the platform handle and the user. This attestation feeds into the shadow claiming flow (§12.3) — a user who later joins SCP can present this attestation to claim their shadow identity.

**Request:**

```json
{
  "platform_handle": "@dave#1234",
  "platform_user_id": "usr_abc123",
  "attestation_evidence": {
    "evidence_type": "platform-verified",
    "verification_method": "oauth2",
    "verified_at": 1700000300,
    "platform_confidence": "high",
    "additional_signals": {
      "account_age_days": 730,
      "email_verified": true,
      "phone_verified": true
    }
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `platform_handle` | string | yes | The user's handle on the external platform |
| `platform_user_id` | string | yes | The platform's internal user identifier |
| `attestation_evidence` | object | yes | Evidence supporting the identity assertion |
| `attestation_evidence.evidence_type` | string | yes | Type of evidence (`platform-verified`, `oauth2`, `signed-challenge`) |
| `attestation_evidence.verification_method` | string | yes | How the platform verified the user |
| `attestation_evidence.verified_at` | integer | yes | Unix timestamp (seconds) of verification |
| `attestation_evidence.platform_confidence` | string | yes | `"high"`, `"medium"`, or `"low"` |
| `attestation_evidence.additional_signals` | object | no | Platform-specific trust signals |

**Response (201 Created):**

```json
{
  "attestation_id": "attest-abc123",
  "status": "active",
  "platform_handle": "@dave#1234",
  "issued_at": 1700000300,
  "expires_at": 1700086700
}
```

The bridge node stores the attestation and signs it with the operator's DID. Attestation expiry defaults to 24 hours; the platform MAY request a different TTL. Expired attestations require re-attestation.

#### GET /v1/scp/bridge/status

Return bridge status and the shadow roster. This endpoint is called by context members to inspect bridge state (legibility tenet — bridge presence is visible before opt-in per §12.2).

**Response (200 OK):**

```json
{
  "bridge_id": "bridge-abc123",
  "status": "Active",
  "platform": "discord",
  "mode": "Cooperative",
  "operator_did": "did:dht:z6MkOperator...",
  "registered_at": 1700000000,
  "shadow_count": 3,
  "rate_limits": {
    "messages_per_minute": 60,
    "shadows_per_hour": 100
  },
  "shadows": [
    {
      "shadow_id": "shadow-xyz789",
      "platform_handle": "@dave#1234",
      "attributed_role": "observer",
      "provenance_status": "Shadow",
      "created_at": 1700000100
    },
    {
      "shadow_id": "shadow-xyz790",
      "platform_handle": "@eve",
      "attributed_role": "observer",
      "provenance_status": "Claimed",
      "created_at": 1700000110
    }
  ]
}
```

The `shadows` array includes all shadow identities managed by this bridge in this context. The array MAY be paginated for large rosters using standard `Link` headers with `rel="next"`.

#### DELETE /v1/scp/bridge/shadow/{shadow_id}

Remove a shadow identity. The shadow and its attributed role are retired. Historical actions attributed to the shadow remain in the event log with their original provenance — deletion does not erase history. The deletion is recorded as a context event in the Merkle log (ADR-011).

**Response (204 No Content):** Empty body on success.

**Response (404 Not Found):** If the shadow does not exist.

**Response (409 Conflict):** If the shadow has been claimed (bound to a DID). Claimed shadows cannot be deleted — they are owned by the claimant, not the bridge operator.

**Idempotency:** Deleting an already-deleted shadow returns `204 No Content` (not `404`).

#### POST /v1/scp/bridge/webhook

Webhook receiver on the bridge node for platform-initiated events. The platform pushes events when relevant state changes occur on the platform side. The bridge node processes these events and translates them into SCP protocol operations.

**Request:**

```json
{
  "event_type": "message",
  "event_id": "evt_platform_789",
  "timestamp": 1700000400,
  "payload": {
    "platform_user_id": "usr_abc123",
    "platform_handle": "@dave#1234",
    "content": "A message from the platform",
    "content_type": "text/plain",
    "platform_message_id": "msg_ext_789"
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `event_type` | string | yes | One of: `message`, `presence`, `identity_update`, `user_departed`, `message_edit`, `message_delete` |
| `event_id` | string | yes | Platform-assigned event identifier (for deduplication) |
| `timestamp` | integer | yes | Unix timestamp (seconds) when the event occurred on the platform |
| `payload` | object | yes | Event-specific payload (see below) |

**Event types and payloads:**

- **`message`** — A new message on the platform. Payload: `platform_user_id`, `platform_handle`, `content`, `content_type`, `platform_message_id`.
- **`presence`** — User online/offline status change. Payload: `platform_user_id`, `platform_handle`, `status` (`"online"`, `"offline"`, `"idle"`).
- **`identity_update`** — User changed their handle, display name, or avatar. Payload: `platform_user_id`, `old_handle`, `new_handle`, `metadata`.
- **`user_departed`** — User left the platform or deleted their account. Payload: `platform_user_id`, `platform_handle`, `reason` (`"left"`, `"banned"`, `"deleted"`).
- **`message_edit`** — A previously bridged message was edited on the external platform. Payload: `platform_message_id`, `new_content`, `new_content_type`, `edited_at`. Because SCP event logs are immutable (Merkle-logged), edits cannot modify the original message. The bridge node translates an edit into a **new SCP message** with a `references` field pointing to the original message's `message_id` and a `reference_type` of `"edit"`. The new message carries `BridgeProvenance` with the original `platform_message_id`. Receiving SDKs SHOULD display the edit as an update to the original message in the UI, while preserving both versions in the event log.
- **`message_delete`** — A previously bridged message was deleted on the external platform. Payload: `platform_message_id`, `deleted_at`. Deletions are translated into a **new SCP message** with `reference_type: "deletion_notice"` pointing to the original message's `message_id`. The original message remains in the event log (immutability is preserved). Receiving SDKs SHOULD display a deletion indicator in the UI (e.g., "This message was deleted on the original platform"). The deletion notice carries `BridgeProvenance` with the `platform_message_id` and `deleted_at` timestamp.

**Response (200 OK):**

```json
{
  "accepted": true,
  "event_id": "evt_platform_789"
}
```

**Response (200 OK, rejected):**

```json
{
  "accepted": false,
  "event_id": "evt_platform_789",
  "reason": "Unknown platform_user_id — no shadow exists for this user"
}
```

A delivery that fails the bridge admission criterion (bridge node lifecycle, §12.10.6 step 1), and a delivery whose `X-SCP-Platform-Key-Id` resolves to no one bridge, receive this rejected response with the fixed `reason` string `Bridge not admitted`; the node answers those deliveries before it verifies any signature, so §12.10.6 step 1 pins that string rather than leaving the node free text that an unauthenticated caller reads. Every other rejection, including the unknown-`platform_user_id` rejection shown above, writes its own `reason`.

Webhook delivery uses at-least-once semantics. The bridge node deduplicates by `event_id`. The platform SHOULD retry failed deliveries with exponential backoff (initial 1s, max 60s, 5 retries). The bridge node MUST respond within 5 seconds; events requiring longer processing are queued internally.

### 12.10.5 SCP-to-Platform Message Flow

The cooperative mode HTTP binding (§12.10.4) specifies how platform-originated messages enter SCP. This section specifies the reverse direction: how SCP messages are forwarded to external platform users via the bridge.

**Bridge operator as MLS group member.** The bridge operator's DID is a full context member admitted through normal governance (§12.2). In encrypted contexts (`ContextMode::Encrypted`), the bridge operator participates in the MLS group and receives encrypted messages like any native member. In broadcast contexts (`ContextMode::Broadcast`), the bridge operator holds sender key material via the standard pull-based distribution protocol (§9.16). This is distinct from the bridge connector itself — the connector is translation infrastructure (§12.6), but the operator is a DID-bearing participant with MLS membership. Shadow identities created by the bridge do NOT have MLS membership; they use per-shadow sender keys (§12.6.1).

**Decryption.** The bridge operator decrypts incoming SCP messages using its MLS epoch keys (encrypted contexts) or sender keys (broadcast contexts). Decryption uses the same protocol path as any other member — no special bridge-specific decryption mechanism exists.

**Translation.** The bridge translates decrypted SCP messages into the external platform's native format. Translation is platform-specific and defined by each platform adapter. The mapping includes:

- **Content format:** SCP `text/plain` and `text/markdown` content types map to the platform's native text format. Rich content (attachments, embeds) maps to platform equivalents where available; unsupported content types are rendered as plaintext fallbacks with a note indicating the original type.
- **Author attribution:** The SCP sender's display name (or DID if no display name is set) is prepended or attributed per the platform's conventions (e.g., "Alice via SCP: ..."). Native SCP identity information is not leaked to the platform beyond the display name.
- **Threading:** SCP message reply references (if present) map to platform reply/thread primitives where available. Platforms without threading receive messages as flat sequential posts.
- **Metadata stripping:** SCP-internal metadata (sequence numbers, Merkle proofs, MLS epoch info) is stripped before forwarding. Only user-visible content reaches the platform.

**Forwarding.** The bridge forwards translated messages to the external platform using the platform's API (cooperative mode: the platform's documented endpoints; relay/puppet mode: the platform's user-facing API or web interface). The bridge authenticates to the platform using credentials managed per §12.11.

**Provenance annotation.** Messages forwarded from SCP to the platform carry a `bridge_forwarded` provenance annotation on the SCP side, recorded in the context's event log. The annotation includes:

```rust
pub struct BridgeForwardedAnnotation {
    /// DID of the bridge operator that forwarded the message.
    pub bridge_did: DID,
    /// Timestamp when the bridge forwarded the message to the platform.
    pub forwarded_at: u64,
    /// Platform the message was forwarded to.
    pub target_platform: String,
    /// Delivery status (updated asynchronously).
    pub delivery_status: BridgeDeliveryStatus,
}

pub enum BridgeDeliveryStatus {
    /// Successfully delivered to the platform.
    Delivered,
    /// Delivery failed after all retry attempts.
    Failed,
    /// Delivery is pending (initial state).
    Pending,
}
```

This annotation is attached to the SCP message's provenance chain, making it auditable that the message was forwarded and to where.

**Failure handling.** If platform delivery fails, the bridge retries with exponential backoff: initial delay 1 second, multiplied by 2 on each retry, maximum 3 attempts (delays: 1s, 2s, 4s). If all 3 attempts fail, the bridge:

1. Updates the `BridgeForwardedAnnotation.delivery_status` to `Failed`.
2. Records the failure in the context's event log (visible to context members).
3. Does NOT retry further. The message is marked as undeliverable. The bridge operator MAY manually re-trigger delivery through bridge-specific tooling, but the protocol does not mandate automatic recovery beyond the 3-attempt limit.

**Export policy enforcement.** The bridge MUST respect the context's export policies. If the context's governance prohibits content export (e.g., via a `no_export` ceiling constraint or equivalent governance policy), the bridge MUST NOT forward any SCP messages to the external platform. A bridge operating in a no-export context functions as a one-way inbound bridge only — external platform content enters SCP, but SCP content does not leave. Violation of export policy by a bridge operator is a governance violation subject to the same enforcement mechanisms as any other member violation (§5.3).

**Rate limiting.** The bridge SHOULD rate-limit outbound forwarding to respect platform API limits. Rate limits are platform-specific and configured per bridge instance. The bridge MUST NOT drop messages due to rate limiting — it queues them and delivers in order when rate limit windows reset.

**Local-event webhook taxonomy.** Separately from platform forwarding, a bridge node MAY expose an outbound webhook dispatcher that notifies registered HTTP targets when context events occur locally on the node. This is the SCP-to-operator-tooling channel (distinct from the SCP-to-platform forwarding above): each local `ContextEvent` emitted by a context the node hosts is mapped to a webhook event with a stable, dot-separated `event_type` and a JSON payload. Signing and headers follow the same conventions as the inbound webhook endpoint (§12.10.4). The defined event types are:

| `event_type` | Emitted when | Payload fields |
|--------------|--------------|----------------|
| `message.received` | A message is received in the context | `sender_did` (string) |
| `message.sent` | A message is sent in the context | `sender_did` (string), `sequence_number` (integer) |
| `member.joined` | A member joins the context | `member_did` (string), `role_name` (string) |
| `member.left` | A member leaves the context | `member_did` (string) |
| `governance.action` | A governance action executes | `proposal_id` (hex string), `action_summary` (string), `executor_did` (string), `resulting_epoch` (integer), `target_did` (string or null) |
| `context.event` | Any other context event (generic fallback) | `variant` (string — the event variant name) |

The `context.event` generic fallback carries only the variant name so that new `ContextEvent` variants surface to webhook consumers without silent omission, while structured payloads are reserved for the explicitly enumerated, externally meaningful event types above. Payload fields contain only metadata — message content is never included in webhook payloads (export-policy enforcement and metadata stripping apply as described above).

**Delivery is best-effort and lossy under load.** Local events for all contexts a node hosts pass through a single shared bounded channel before reaching the dispatcher. Loss occurs in two windows. First, under sustained load — a high-traffic context emitting faster than the consumer drains — the channel drops the **oldest** undelivered events (the consumer logs the dropped count at `error` level but cannot recover them). Second, during the **node-startup window before the consumer subscribes**: the broadcast channel has fan-out-from-subscription semantics, so any event emitted in the interval between a context actor coming online and the node's webhook consumer calling `subscribe_events()` is dropped without even a `Lagged` log entry (the subscriber simply never sees events that predate its subscription). A slow or unreachable webhook target compounds load-window loss: dispatch is fire-and-forget with bounded retries, and a non-2xx or timed-out delivery is logged and abandoned, not queued. Consequently, webhook delivery MUST NOT be relied on as the sole channel for security-relevant audit (e.g. `member.left`, member-blocked, or `governance.action` events): a dropped or failed webhook leaves no gap-marker on the wire. The **durable Merkle event log** (ADR-011) is the authoritative, gap-detectable record of context events; operator tooling that requires completeness MUST reconcile against it rather than treating webhooks as lossless.

### 12.10.6 Bridge Node Lifecycle

The bridge node mediates between the platform's HTTP API and SCP protocol operations. The lifecycle is:

1. **Registration and admission.** The bridge operator submits a `RegisterBridge` proposal, whose payload carries the platform's webhook URL and webhook signing key, and the context's governance model decides that proposal (bridge registration protocol, §12.2.1). A bridge node MUST admit a bridge only on a governance approval that the node itself verifies. The node verifies an approval by executing it. The bridge operator is a member of the context, and the operator's membership lives on the bridge node, because the node decrypts SCP messages as that member (bridge encryption model, §12.6.1; SCP-to-platform message flow, §12.10.5). As a member, the node derives the context's event log from the MLS-commit-ordered stream (verifiable event logs, §7.3.1; equivocation detection, §9.9.3) and executes each approved governance action under the governance model the context declared at creation (governance, §5.9). The four bridge lifecycle leaves — `BridgeRegistered` (§12.2.1 step 3), `BridgeSuspended` and `BridgeReactivated` (suspension, §12.2.2), and `BridgeRevoked` (§12.2.2 step 2), each carrying a `BridgeRegistrationEvent` payload (ADR-011, verifiable event log; bridge registration wire table, §12.12.2) — therefore enter the node's copy of the log only after the node itself executed the governance action that produced each one.

   **The admission criterion.** The node applies this criterion before it admits a bridge, and applies it again before it verifies a webhook signature, constructs an SCP envelope, or creates a shadow for that bridge. Take the bridge lifecycle leaves in the event log that the node holds as a member of the context whose payload `bridge_id` names that bridge and whose payload `context_id` names the context whose log holds the leaf; this paragraph calls those leaves the bridge's lifecycle leaves. The node admits the bridge when all five of the following hold, and refuses it otherwise:

   - The bridge's lifecycle leaves include a `BridgeRegistered` leaf with `action: Approved`. A bridge with no `BridgeRegistered` leaf fails the criterion.
   - No lifecycle leaf of the bridge is a `BridgeRevoked` leaf. One `BridgeRevoked` leaf fails the criterion for as long as the log holds it, because §12.2.1 makes `Revoked` terminal. The criterion reads every lifecycle leaf for this clause rather than the last leaf alone, so no leaf appended after a revocation readmits a revoked bridge.
   - The payload `operator_did` of that bridge's `BridgeRegistered` leaf equals the DID under which the node holds its membership in the context (bridge operator as MLS group member, §12.10.5). A bridge whose `BridgeRegistered` leaf names another member as `operator_did` fails it on every node but that member's, because every member's log holds the same leaf and only the operator's node runs the bridge.
   - The last of the bridge's lifecycle leaves is a `BridgeRegistered` leaf with `action: Approved`, a `BridgeReactivated` leaf with `action: Reactivated`, or a `BridgeSuspended` leaf whose payload `duration` is `Some(d)` and whose suspension deadline has passed. §12.2.2 (suspension) defines that deadline as the later of the leaf `timestamp` plus `d` and the node's own commit-execution instant plus `d`, each sum taken with saturating addition, because the leaf `timestamp` alone carries no lower bound. §12.2.2 makes that execution instant a value the node records durably once per leaf, so a restart moves no deadline the node has already computed. A node that holds no recorded instant for a leaf substitutes and records its first-read instant under §12.2.2, which moves that leaf's deadline later and moves it no earlier, so the criterion readmits the bridge no earlier than the deadline the recorded execution instant would have produced and readmits it later when the node was down before it recorded one. This clause reads the last lifecycle leaf and reads no earlier one; the revocation clause above reads every lifecycle leaf. A bridge whose last lifecycle leaf is a `BridgeSuspended` leaf fails the criterion whenever that leaf's `duration` is `None`, and whenever that leaf's `duration` is `Some(d)` and the deadline has not passed; for that bridge the node retains shadow state and credentials (credential requirements, §12.11.2), and answers each webhook delivery that claims that bridge with the same rejected webhook response it gives for every other failure of this criterion. The node reports `BRIDGE_SUSPENDED` (error format, §12.10.3) on an authenticated bridge API call whose bearer token the node verified under the JWT rules of §12.10.2 (authentication), reports it on no webhook delivery, and reports it only for a bridge whose lifecycle leaves hold no `BridgeRevoked` leaf. A bridge whose lifecycle leaves hold one receives `BRIDGE_FORBIDDEN` whatever its last lifecycle leaf is, including a `BridgeSuspended` leaf that a member appended after the revocation, because §12.2.2 step 7 pins `BRIDGE_FORBIDDEN` for a revoked bridge and pins `BRIDGE_SUSPENDED` on none of its authenticated calls. The node reports `BRIDGE_SUSPENDED` for a `duration` of `None` exactly as it reports it for an unexpired `Some(d)`, because §12.2.2 makes both of them suspensions that an approved `ReactivateBridge` action reverses, and a node that answered a `None` suspension with `BRIDGE_FORBIDDEN` would tell the operator that governance revoked a bridge governance suspended, which is the confusion §12.2.2 step 7 removes in the other direction. On those same authenticated bridge API calls the node reports `BRIDGE_FORBIDDEN` (error format, §12.10.3) for every other failure of this criterion, whichever clause the bridge failed, and reports `BRIDGE_FORBIDDEN` on no webhook delivery either. The node MUST verify the bearer token's signature under the JWT rules of §12.10.2 (authentication), and MUST resolve the bridge from the verified token's `scp_bridge_id` claim, before it applies this criterion on that surface. The node MUST then bind that verified caller to the bridge it resolved, on two claims of the same token, before it applies this criterion on that surface: the token's `iss` claim MUST equal the payload `operator_did` of that bridge's `BridgeRegistered` leaf, and the token's `scp_context_id` claim MUST equal the payload `context_id` of that same leaf, which names the context whose log this criterion reads. The five clauses of this criterion read the node's own membership and the bridge's lifecycle leaves and read nothing the caller presented, so without the first binding every clause holds for any caller whose token the node verified under the JWT rules of §12.10.2, whichever key signed it, as long as that token names a bridge the node operates; this criterion would then admit that caller as the operator, and the envelopes the node builds for it would carry the `BridgeProvenance` (§12.5) that names the operator. Without the second binding the node reaches a bridge whose `BridgeRegistered` leaf names one context while the token that authorized the call named another, so the caller directs the operator's bridge into a context its own token did not name. A caller that fails either binding receives `BRIDGE_NOT_AUTHORIZED` (error format, §12.10.3), the same response this paragraph gives a caller whose token the node did not verify, and the node applies this criterion for that caller not at all. A caller whose token the node did not verify receives `BRIDGE_NOT_AUTHORIZED` (error format, §12.10.3) for every `scp_bridge_id` it names, whether that claim names a suspended bridge, a revoked bridge, a bridge the node serves in neither state, or no bridge the node holds at all, and the node applies this criterion for that caller not at all. The node separates the two codes only after that verification and both bindings, and only on that surface, because the caller that reads the separated codes proved that it holds the signing key of the operator that bridge's `BridgeRegistered` leaf names, while a webhook caller presented nothing the node verified and receives the one rejected webhook response this step already pins. Ordering the resolution of the bridge ahead of the verification would be the cheaper order, since an unresolvable `scp_bridge_id` needs no signature check, and it would let a caller that proved nothing read `BRIDGE_SUSPENDED` against `BRIDGE_FORBIDDEN` and learn which governance action a context took against a bridge; this paragraph forbids that order for that reason.
   - The node's own log records that the bridge's operator still holds the authority to act as a member of the context: the log holds a `MemberJoined` leaf for the operator, and above that leaf the log holds no leaf recording a governance action against the operator that ended its membership or withdrew any part of its authority to act in the context, unless a later leaf records that governance restored what that action took (membership-change payload, ADR-011, verifiable event log). A node applies that sentence, and applies it alone, to decide this clause. The event taxonomy ADR-011 declares carries such a withdrawal on a `MemberLeft` leaf (the operator left, or governance removed it), a `MemberBlocked` leaf, a `MemberSuspended` leaf (`SuspendCapability`), a `MemberSuspendedAll` leaf (`SuspendAccess`), and an `AccessRevoked` leaf (`RevokeReadAccess` or `RevokeWriteAccess`), and carries a restoration on a `MemberUnblocked` leaf and an `AccessRestored` leaf. Those leaf names tell a reader which leaves carry a withdrawal on the taxonomy as ADR-011 declares it today, and a node reads none of them as the test: a leaf that ADR-011 adds later and that records a withdrawal fails this clause under the sentence above, and that sentence does not have to name it first. A node applying this clause reads whether governance withdrew the operator's authority and reads no capability name, so a capability suspension whose capabilities the bridge's own operations never exercise refuses the bridge too; that refusal withholds admission rather than granting it, and the operator's remedy is a governance action that restores what the suspension took. Governance withdrawing that authority appends one of those leaves, and the node executes the commit that appends it, so the withdrawal reaches the same log this criterion already reads. A removal ends the node's commit stream for that context, so after a removal no later leaf reaches that log and the bridge's last lifecycle leaf stands at whatever governance left it. A suspension that leaves the operator in the MLS group ends no commit stream, so the node keeps receiving that context's commits and reads every later leaf, a restoration included. Without this clause a node whose operator governance removed, blocked or suspended would keep admitting the bridge, keep verifying platform webhook signatures for it, keep creating shadows for it, and keep signing the bridge-operator attestations of §12.10.4 (`POST /v1/scp/bridge/attest`) naming a context that withdrew its operator's authority, until a separate `RevokeBridge` or `SuspendBridge` proposal reached that log. §12.2.1 step 1 makes that membership the premise of every other clause, because the node reads this log as that member.

   **Which lifecycle leaf is the last one.** Event sequencing (§7.3.1) orders the leaves of an encrypted context by the committer-assigned sequence, so in an encrypted context the last lifecycle leaf is the one carrying the highest committer-assigned sequence. In a broadcast context §7.3.1 gives each author an independent counter, which orders one author's leaf against another author's not at all, so the criterion reads a last leaf only while one author appended every one of the bridge's lifecycle leaves; when the bridge's lifecycle leaves carry two authors the criterion has no last leaf, it fails, and the node admits that bridge into no context. A node that guessed an order across two authors' counters would admit a bridge whose suspension it had ranked below its registration. Whether a broadcast context ranks two authors' bridge lifecycle leaves, and against what value, is a question that §7.3.1 owns and has not answered, and no other artifact answers it. The criterion as written settles what a node does with such a bridge, and it settles all three of that refusal's consequences without §7.3.1 answering anything. An approved `ReactivateBridge` action appends a `BridgeReactivated` leaf, and whichever member commits that action the bridge's lifecycle leaves still carry two authors, so the criterion still reads no last leaf and readmits that bridge in no case. The refusal covers the leaves of one `bridge_id` and covers no other bridge, so it stands for the life of that bridge and not for the life of the context, and the node keeps admitting every other bridge in that context whose lifecycle leaves carry one author. The operator's remedy is a fresh `RegisterBridge` proposal: §12.2.1 step 3 derives the identifier from that approval's own leaf `timestamp`, so the approval registers a bridge under a different identifier whose lifecycle leaves begin at one leaf and therefore carry one author, and the node admits that bridge until two authors have appended its lifecycle leaves. What §7.3.1 has not answered stays unanswered here: an answer would let a node rank two authors' leaves and read a last leaf, which would readmit a bridge this criterion refuses, and this specification states no such ranking. The refusal withholds admission rather than granting it.

   **Which bridge a webhook delivery claims.** A webhook delivery carries no bridge field in its body (`POST /v1/scp/bridge/webhook`, endpoints, §12.10.4); it names the platform signing key that signed it in its `X-SCP-Platform-Key-Id` header (authentication, §12.10.2), and that header is the key identifier of §12.10.2 step 6, which digests the bridge's `bridge_id` together with the registered key bytes. The bridge a delivery claims is therefore the one bridge for which the node stores a key whose identifier equals that header; §12.10.2 step 6 makes the pairs carrying one identifier name one bridge. The identifier covers the `bridge_id` so that this resolution names one bridge rather than two: two bridges the same node operates against one platform register the same key bytes, and a header over the key bytes alone would name both of them and therefore both of their contexts. A delivery whose header matches the identifier of no (bridge, key) pair the node stores, and a delivery whose header matches pairs of two different bridges, each claim no bridge, and the node answers each with the rejected webhook response (`accepted: false`) without verifying its signature, because the node has no one bridge to apply this criterion to.

   **The node reads admission from that log and from no other input.** A registration that reaches the node by any other path is not in that log, so the node MUST refuse it; the paths this rule refuses include a configuration file the node's operator writes, a request body, and a leaf that any party supplies to the node as an input the node did not execute, the node's own operator included. That refusal covers every input the node reads from outside its own executed state. The paragraph below headed "The log the criterion reads is a log the node executed" states which bytes the criterion counts as that executed state, and names the one party the criterion refuses nothing against. Bridge connectors as protocol entities (§12.2) gives admission to the context's governance model and gives it to no node operator. A node whose operator governance removed from a context keeps the log it accumulated up to the removal commit, and the membership clause of the criterion refuses every bridge in that context from that leaf onward. A node that holds no `BridgeRegistered` leaf for a bridge holds no platform key for that bridge, because the node stores the platform key when governance approves the registration (authentication, §12.10.2). The node verifies no webhook signature for a bridge that fails the criterion, constructs no SCP envelope that carries that bridge's provenance, and creates no shadow for that bridge. The node answers every webhook delivery that claims a bridge failing this criterion with one response — the rejected webhook response (`accepted: false`; `POST /v1/scp/bridge/webhook`, endpoints, §12.10.4) — whichever clause the bridge failed, and answers a delivery whose `X-SCP-Platform-Key-Id` matches the key identifier of no stored (bridge, key) pair, and a delivery whose identifier matches pairs of two different bridges, with that same response. A webhook delivery carries no credential the node verified before it answers, because the node verifies no signature for a bridge that fails the criterion, so a caller that proved nothing reaches this answer; one response for every failure tells that caller which bridges the node serves and tells it nothing about which governance action a context took against a bridge it does not serve. That one response carries `accepted: false`, the `event_id` the delivery itself supplied, and the `reason` string `Bridge not admitted` (`POST /v1/scp/bridge/webhook`, endpoints, §12.10.4), and the node writes no other text into `reason` for any failure of this criterion. The node pins that string because `reason` is free-form text that the same caller reads: a node that wrote one string for an unexpired suspension, another for a revocation, and a third for a header matching no stored pair would restore in `reason` the same disclosure that answering every failure with one status code removes. A rejection that a later step raises — the unknown-`platform_user_id` rejection §12.10.4 shows — writes its own `reason`, because the node reaches that step only after this criterion admitted the bridge and the node verified the delivery's signature.

   **The log the criterion reads is a log the node executed.** The node derives that log by executing the context's commits, and two paths populate a context's event log from bytes instead. Importing a context from a `ContextExport` gives the node leaves it never executed, and the party that supplies both the export and the key that validates it is the node's own operator, which is the party this criterion refuses. For an imported context the node MUST therefore treat every bridge lifecycle leaf at or below the log position that the import produced as absent from the criterion, so the node admits a bridge into that context only after the node itself executes a commit that appends a `BridgeRegistered` leaf for that bridge, and nothing the operator writes admits one. The node MUST hold a durable import-position record for every context whose log this criterion reads, and MUST read that record on every evaluation of the criterion, because a node that held the position in memory alone would read every imported leaf as one it executed after the next restart. For a context the node created or joined, that record names position zero, which covers no leaf, and the criterion reads every bridge lifecycle leaf of that context. For a context the node imported, the record names the position the import produced. The node MUST write that record before it writes that context's first leaf into the log the criterion reads, and MUST NOT write an imported leaf into that log until the record that covers that leaf is durable. The node writes the record for every context rather than for an imported context alone because a node that wrote it only for an import could not tell an absent record apart from a context it created or joined: it would read the absence as a context carrying no imported leaf and admit every bridge in a context whose record a party deleted, which is the state the refusal sentence below covers. That order decides both windows in which the node can die during an import. A node that dies after the record is durable and before the leaves are holds a record covering a position its log has not reached, and the criterion treats leaves the log does not hold as absent, which refuses bridges and admits none. A node that dies before the record is durable holds no leaf of that context at all, because the record precedes every leaf of that context, so that context's log holds no bridge lifecycle leaf for the criterion to read. Writing the leaves first would leave the third state — leaves the log holds and no record that covers them — in which the node reads every one of them as a leaf it executed, which is the outcome this paragraph refuses. A node that finds a log whose import-position record it cannot read treats every bridge lifecycle leaf in that log as absent from the criterion, and admits a bridge into that context only after it writes that record and then executes a commit that appends a `BridgeRegistered` leaf for that bridge. Governance approving a `RegisterBridge` proposal after the import restores the imported bridge itself in no case: §12.2.1 step 3 derives the `bridge_id` from the leaf `timestamp` of the approval that assigns it, so that approval assigns whatever identifier its own leaf derives and registers the bridge that identifier names. The imported bridge fails clause 1 on that node for as long as the import position stands, whatever identifier the new approval assigned, and the node's records for the imported bridge — the platform key it stores (authentication, §12.10.2), its shadows, and the delegated credentials and `bridge_credential_key` that §12.11.1 phase 2 keys by `bridge_id` — are records for a bridge this criterion refuses. The node MUST use none of those records, and the operator provisions the platform key, the shadows, and the delegated credentials again under the identifier the new approval assigned. Restoring a context from the node's own storage re-reads leaves that the node executed before it wrote that storage, so a restored leaf satisfies the criterion. The criterion reads a restored leaf and a leaf the node holds in memory as the same bytes and separates the two by no property of those bytes, so a party that rewrites the node's storage makes the node admit a bridge the context's governance never approved. No criterion a node evaluates over its own storage refuses that party, because that party is the party that holds the context membership key the node decrypts with (§12.10.5) and reads and writes the storage that key protects, so it already acts as that member on that node. The criterion therefore refuses a leaf that reaches the node as an input from outside its own executed state, and refuses nothing against a party with write access to the node's own storage and its key material. What that party gains is confined to the node it controls: the `BridgeProvenance` that §12.5 attaches to every envelope the bridge produces names that operator, every other member's log carries no `BridgeRegistered` leaf for that `bridge_id`, and the Merkle root each member computes over its own log (§9.9.3) records that absence.

   **Retention of the leaves the criterion reads.** Every input this criterion reads is a payload field of a bridge lifecycle leaf, and log pruning removes event payloads while retaining leaf hashes and the tree structure (ADR-030, event log pruning and checkpointing). A bridge node MUST retain the payload of every bridge lifecycle leaf of every bridge it operates, for as long as it operates that bridge, and MUST prune no such payload under the context's pruning policy. ADR-030 pruning invariant 4 gives the node that retention: "Pruning is always local. A member's decision to prune does not affect other members' logs. Members who need full history can retain it regardless of the context's pruning policy." The obligation covers the lifecycle leaves of the bridges the node operates and covers no other leaf, so the node prunes the rest of that context's log under the context's policy as every other member does. Without the obligation the context's own policy would remove the criterion's inputs while the bridge still stands, because neither pruning dimension ADR-030 defines reads whether a leaf's bridge is still admitted: under a time-based policy (ADR-030 §2a) the prefix cut removes every payload older than the retention window that ADR-030 §2c multiplies for a structural event, and ADR-030 §6 (governance of pruning policies) clamps that product to at least 90 days; under a size-based policy (ADR-030 §2b) the cut removes the oldest payloads until the log holds `max_event_count` events, and reads no age at all. Neither cut reaches an event that no checkpoint covers: ADR-030 pruning invariant 1 prunes no event unless a valid, locally-verified checkpoint stands ahead of it, so a log that passed `max_event_count` before its first checkpoint loses no payload. A node that pruned a `BridgeRegistered` payload against this obligation reads no registration, fails clause 1, and refuses a bridge that governance never suspended and never revoked; no governance action re-emits that leaf, and the operator's remedy is a fresh `RegisterBridge` proposal, which §12.2.1 step 3 registers under the identifier that approval's own leaf derives. That refusal withholds admission rather than granting it.
2. **Shadow creation.** The bridge node calls `POST /v1/scp/bridge/shadow` to create shadow identities for platform participants as they become relevant to the context.
3. **Bidirectional message flow.** SCP-to-platform: the bridge operator receives and decrypts SCP messages as an MLS group member, translates them to the platform's native format, and forwards them via the platform's API (§12.10.5). Platform-to-SCP: the platform pushes events via the webhook endpoint, and the bridge node constructs SCP envelopes with bridge provenance (§12.10.4).
4. **Attestation.** The platform attests to user identities via `POST /v1/scp/bridge/attest`. These attestations strengthen the trust evaluation for cooperative-mode shadows.
5. **Suspension/revocation.** Context governance can suspend or revoke the bridge at any time (§12.2). On suspension, the bridge node stops processing messages but retains shadow state. On revocation, the bridge is permanently disconnected. The node learns of suspension, reactivation, and revocation from the `BridgeSuspended`, `BridgeReactivated`, and `BridgeRevoked` leaves in the event log it holds as a member, under the criterion of step 1.

### 12.10.7 Cooperative Mode Trust Differentiation

Content entering SCP through the cooperative mode HTTP binding receives enhanced trust evaluation compared to relay or puppet mode. The trust differentiation (§12.5) applies:

- **Shadow + Cooperative transport** is evaluated more favorably than **Shadow + Relay transport** because the platform has vouched for the attribution via its own identity infrastructure.
- The `bridge_mode` field in `BridgeProvenance` distinguishes `Cooperative` from other modes. Trust engines (§7) and agents MAY treat cooperative-mode provenance as a positive signal.
- Platform-provided attestation evidence (via `POST /v1/scp/bridge/attest`) further strengthens identity confidence for individual shadows.

### 12.10.8 Implementation Considerations

**For platforms implementing this API:**

- The API surface is six endpoints. No SCP protocol knowledge is required beyond understanding shadow identities and provenance.
- Webhook delivery is the primary integration pattern. The platform pushes events; the bridge node pulls status.
- Credential delegation is not required. The platform retains full control of its authentication and authorization. The bridge operator authenticates to the platform using DID-signed tokens — the platform decides what access those tokens grant.
- The platform MAY implement a subset of endpoints. At minimum, shadow creation and the message webhook enable basic participation. Attestation is optional but improves trust evaluation for the platform's users.

**For bridge node implementors:**

- All SCP envelope construction, sender key encryption (§12.6.1), and provenance marking happen on the bridge node. The bridge does NOT perform MLS encryption — it uses per-shadow sender keys. The platform never sees SCP protocol internals.
- The bridge node is responsible for rate limiting outbound requests to the platform, respecting the platform's `Retry-After` headers.
- Shadow state is authoritative on the bridge node. Platform-side state changes arrive via webhooks and are reconciled by the bridge node.
- Webhook event deduplication is required. The `event_id` field serves as the idempotency key.

## 12.11 Bridge Credential Lifecycle

The credential model for bridge connectors is platform-specific — OAuth, API keys, session tokens, webhook secrets — but the protocol provides structure for how credentials are managed regardless of the authentication flow. This gives bridge implementors a consistent lifecycle to build against while accommodating the diversity of external platform authentication systems.

### 12.11.1 Lifecycle Phases

Bridge credentials pass through five phases:

1. **Provision.** The user authorizes the bridge to act on their behalf on the external platform. The authorization mechanism is platform-specific: OAuth Authorization Code flow, API key generation, manual token entry, etc. The bridge operator initiates this flow; the user completes it.

2. **Store.** Credentials are encrypted at rest and stored in isolation from the operator's SCP identity keys. The credential encryption key MUST NOT be derived from the `#active` signing key, because `#active` rotates (software key, periodic rotation per §3.4) — rotation would silently invalidate all encrypted credentials. Instead, the credential encryption key is a random 32-byte value generated once per bridge instance at provisioning time and stored within the custody boundary (alongside `pseudonym_secret` and other non-exportable secrets per §3.7). This is the `bridge_credential_key`.

   The `bridge_credential_key` is generated and stored as follows:
   ```
   bridge_credential_key = CSPRNG(32)  // generated once at bridge provisioning
   // Stored in ProtocolRepository under: custody/{did}/bridge_credential_key/{bridge_id}
   // Protected by the same custody boundary as identity keys
   ```

   The per-credential encryption key is then derived from the `bridge_credential_key` using HKDF-SHA-256:
   ```
   ikm  = bridge_credential_key                       // 32 bytes, per-bridge random secret
   salt = SHA-256("SCP-BRIDGE-CREDENTIAL-V1")          // fixed salt, 32 bytes
   info = "scp-bridge-credential:" || bridge_id        // bridge_id as UTF-8 string bytes
   prk  = HKDF-Extract(salt, ikm)                      // 32 bytes
   okm  = HKDF-Expand(prk, info, 32)                   // 32 bytes — AES-256-GCM key
   ```

   **Encoding note:** `bridge_id` is a `String` (§12.12) — specifically, the lowercase hex-encoded SHA-256 hash assigned at registration (§12.2.1). In the `info` parameter, `bridge_id` is concatenated as its UTF-8 string bytes (i.e., the hex characters themselves, not the raw hash bytes). For example, if `bridge_id` is `"a1b2c3..."`, the info bytes are `b"scp-bridge-credential:a1b2c3..."`. Implementations MUST NOT decode the hex string back to raw bytes before concatenation.

   Encryption algorithm: AES-256-GCM. Nonce: 12 bytes, randomly generated per encryption operation via CSPRNG. The nonce is prepended to the ciphertext. Authentication tag: 16 bytes, appended to the ciphertext. Stored format: `nonce (12 bytes) || ciphertext || tag (16 bytes)`.

   This design avoids coupling credential encryption to any key that rotates (`#active`) or that hardware custody may prevent exporting (`#0`). The `bridge_credential_key` is a standalone secret with the same lifecycle as the bridge instance — created at provisioning, destroyed at revocation (Phase 5).

   Credentials MUST be stored separately from the operator's SCP identity keys — the credential store is a distinct storage domain under `bridge/{bridge_id}/credential/{credential_type}` in `ProtocolRepository`, not a field on the bridge entity.

3. **Use.** The bridge authenticates to the external platform using stored credentials. Credential access is scoped to the bridge instance — a bridge registered in Context A cannot use credentials provisioned for a bridge in Context B, even if operated by the same DID.

4. **Rotate.** Credentials are refreshed before expiry. For OAuth tokens, this means using refresh tokens to obtain new access tokens before the current token expires. For API keys, this means re-provisioning when keys approach their rotation deadline. Rotation SHOULD be automatic with exponential backoff on failure.

5. **Revoke.** When `BridgeStatus` transitions to `Revoked`, the credential store MUST destroy all delegated credentials for that bridge instance. This includes calling the external platform's revocation endpoint (if available) and then destroying local credential material. When `BridgeStatus` transitions to `Suspended`, credential use MUST stop immediately, but credentials are retained for potential reactivation. The bridge then resumes without re-provisioning whenever the admission criterion readmits it (bridge node lifecycle, §12.10.6 step 1). That criterion readmits no bridge whose lifecycle leaves two members of a broadcast context appended, so for that bridge the operator submits a fresh `RegisterBridge` proposal and provisions the delegated credentials again under the identifier the new approval assigns.

### 12.11.2 Requirements

- Credentials MUST be encrypted at rest using a key derived from the bridge's `bridge_credential_key` (§12.11.1 Phase 2). The `bridge_credential_key` is a per-bridge random secret stored in the custody boundary — it is NOT derived from any identity key.
- Credentials MUST be stored separately from the operator's SCP identity keys (key isolation). A compromise of the credential store does not compromise the operator's SCP identity. A compromise of the operator's SCP identity keys does not expose platform credentials (the `bridge_credential_key` is an independent random secret, not derived from identity material).
- When `BridgeStatus` transitions to `Revoked`, the credential store MUST destroy all delegated credentials for that bridge instance. Destruction means: (a) call the platform's revocation endpoint if one exists, (b) overwrite local credential material with zeros, (c) delete the credential record, (d) overwrite and delete the `bridge_credential_key` from the custody boundary.
- When `BridgeStatus` transitions to `Suspended`, credential use MUST stop but credentials are retained for potential reactivation, and the admission criterion of §12.10.6 step 1 decides whether a later reactivation readmits the bridge under the same `bridge_id`.
- Credential storage SHOULD support multiple concurrent credential types per bridge instance (e.g., an OAuth access token + a webhook signing secret + an API key for a secondary service).
- Credential access MUST be scoped to the bridge instance. Cross-bridge credential sharing is prohibited even under the same operator DID.

### 12.11.3 OAuth 2.0 Reference Binding

Approximately 80% of major platforms use OAuth 2.0 for third-party authorization. This section provides a reference binding for OAuth-based bridges.

**Authorization flow:**

1. Bridge operator initiates OAuth Authorization Code flow with PKCE (`S256` code challenge method).
2. User is redirected to the platform's authorization endpoint.
3. User authorizes the requested scopes and is redirected back to the bridge's callback URL.
4. Bridge exchanges the authorization code for an access token and refresh token.
5. Both tokens are encrypted at rest per §12.11.2 and stored in the credential store.

**Token storage:**

- `access_token` — Short-lived (typically 1 hour). Used for API requests to the platform.
- `refresh_token` — Long-lived (days to months). Used to obtain new access tokens without user re-authorization.
- Both are encrypted at rest using a key derived from the bridge's `bridge_credential_key` (§12.11.1 Phase 2).

**Token refresh:**

- The bridge MUST refresh the access token before it expires. A recommended approach: refresh when 80% of the token lifetime has elapsed.
- On refresh failure, retry with exponential backoff (initial 1s, max 60s, 5 retries).
- If refresh fails after all retries (e.g., refresh token revoked by the platform), transition the bridge to a degraded state and notify the operator via the bridge status endpoint.

**Revocation:**

- On bridge revocation (`BridgeStatus::Revoked`): (a) call the platform's OAuth token revocation endpoint (RFC 7009) for both access and refresh tokens, (b) overwrite local token material with zeros, (c) delete the credential record.
- On bridge suspension (`BridgeStatus::Suspended`): stop using tokens but retain them. Do not call the platform's revocation endpoint.

**Scope minimization:**

- OAuth scopes MUST be minimal — request only what the bridge mode requires.
- Relay mode: read-only scopes (e.g., `read:messages`, `read:users`).
- Puppet mode: read + write scopes (e.g., `read:messages`, `write:messages`, `read:users`).
- API mode: scopes determined by the platform's API requirements for the bridged functionality.
- Cooperative mode: typically no OAuth needed — the platform authenticates the bridge via DID-signed tokens (§12.10.2).

**Example: Discord OAuth bridge**

```
1. Bridge initiates:
   GET https://discord.com/api/oauth2/authorize
     ?response_type=code
     &client_id=BRIDGE_CLIENT_ID
     &redirect_uri=https://bridge.example.com/callback
     &scope=messages.read+guilds
     &code_challenge=BASE64URL(SHA256(verifier))
     &code_challenge_method=S256

2. User authorizes. Discord redirects:
   GET https://bridge.example.com/callback?code=AUTH_CODE

3. Bridge exchanges code:
   POST https://discord.com/api/oauth2/token
   Body: grant_type=authorization_code&code=AUTH_CODE&code_verifier=VERIFIER&...

4. Response:
   { "access_token": "...", "refresh_token": "...", "expires_in": 604800 }

5. Bridge encrypts and stores both tokens.
```

### 12.11.4 Self-Hosted Bridge Credential Isolation

Self-hosted bridges (§12.7) eliminate third-party trust for credential custody. The operator runs the bridge software on their own infrastructure, and credentials never leave their machine. The credential lifecycle is identical to managed bridges — the same five phases, the same encryption requirements, the same revocation behavior. The protocol treats self-hosted and managed bridges identically.

The security benefit of self-hosting is operational, not protocol-level: the credential material exists on infrastructure the operator controls, rather than on a third-party service. The protocol's role is to ensure that regardless of hosting model, the credential lifecycle is consistent and the revocation guarantees are honored.

## 12.12 Wire Format Tables

This section tabulates the wire format for all bridge protocol types that cross the network. All types use serde serialization (JSON for outlet call payloads, MessagePack for MLS application messages and event log entries). An independent implementer MUST implement these types with exactly the field names, types, and semantics shown below. All constants referenced here are defined in §9.18.

### 12.12.1 Core Bridge Entities

**`BridgeMode`** — Enum for bridge operating modes (§12.4).

| Variant | Serde Tag | Semantics |
|---------|-----------|-----------|
| `Relay` | `"Relay"` | Bridge relays messages without platform interaction. Read-only ingestion. |
| `Puppet` | `"Puppet"` | Bridge controls a platform account. Bidirectional but synthetic. |
| `Api` | `"Api"` | Bridge uses official platform API. Bidirectional with rate limits. |
| `Cooperative` | `"Cooperative"` | Platform natively supports SCP. Full fidelity. |

**`BridgeStatus`** — Enum for bridge lifecycle states.

| Variant | Serde Tag | Semantics |
|---------|-----------|-----------|
| `Active` | `"Active"` | Bridge is operational. |
| `Suspended` | `"Suspended"` | Bridge is temporarily suspended by governance. |
| `Revoked` | `"Revoked"` | Bridge is permanently revoked. |

**`BridgeConnector`** — A registered bridge connector entity.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `bridge_id` | `String` | Yes | Unique bridge identifier — lowercase hex-encoded SHA-256 hash (64 characters, see §12.2.1). |
| `operator_did` | `String` (DID) | Yes | DID of the human operator. |
| `platform` | `String` | Yes | Target platform name (e.g., `"slack"`, `"discord"`). |
| `mode` | `BridgeMode` | Yes | Operating mode. |
| `status` | `BridgeStatus` | Yes | Current lifecycle state. |
| `registration_context` | `String` | Yes | Context ID where the bridge is registered. |
| `registered_at` | `u64` | Yes | Unix timestamp (seconds). |

### 12.12.2 Bridge Registration

**`BridgeRegistrationRequest`** — Request to register a bridge with a context.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `operator_did` | `String` (DID) | Yes | Operator's DID. |
| `platform` | `String` | Yes | Target platform. |
| `mode` | `BridgeMode` | Yes | Requested operating mode. |
| `context_id` | `String` | Yes | Context to register with. |
| `self_hosted` | `bool` | Yes | Whether the operator runs bridge infrastructure. |
| `webhook_url` | `Option<String>` | Yes | The platform's webhook receiver URL. The operator fills this field for a cooperative-mode bridge and writes `None` into it for every other mode (`RegisterBridge` payload, §12.2.1). |
| `platform_key` | `Option<[u8; 32]>` | Yes | The platform's Ed25519 public key. The bridge node stores this key when governance approves the registration, and verifies the signature of each webhook delivery under it (authentication, §12.10.2 step 3). The operator fills this field for a cooperative-mode bridge and writes `None` into it for every other mode. |
| `max_shadows` | `u32` | Yes | The shadow limit the context's governance sets for this bridge. It overrides the shadow registry's own default (`RegisterBridge` payload, §12.2.1). |
| `metadata` | `BridgeRegistrationMetadata` | Yes | Display name, description, and operator contact (§12.12.2, `BridgeRegistrationMetadata`). The context's governance model reads these three values while it decides the proposal (`RegisterBridge` payload, §12.2.1). |

Seven of these nine rows — `operator_did`, `platform`, `mode`, `webhook_url`, `platform_key`, `max_shadows` and `metadata` — carry the `RegisterBridge` payload §12.2.1 declares, and the remaining two — `context_id` and `self_hosted` — carry what the operator states about the request itself. This table lists every field of the type: a `BridgeRegistrationRequest` that declared a tenth field would carry a value no rule in this specification reads.

`BridgeRegistrationRequest` carries no bridge identifier. §12.2.1 step 3 derives the `bridge_id` from the `timestamp` of the leaf that records the approval, and that leaf does not exist while the operator is building the request, so the operator can put no assigned identifier in the request and the context reads none out of it. A requester that filled such a field would name the bridge by one value while the approval filed its lifecycle leaves under another, and the criterion of §12.10.6 step 1 reads the leaves. A pending registration is the governance proposal that carries the `RegisterBridge` action (governance, §5.9), and that proposal's identifier names the pending registration until the approval assigns a `bridge_id`.

`BridgeRegistrationRequest` carries no requester-supplied timestamp either. Every rule this specification states over a bridge registration reads a leaf `timestamp` that event sequencing assigned (§7.3.1): §12.2.1 step 3 derives the `bridge_id` from the approval leaf's own `timestamp`, and §12.2.2 computes a suspension deadline from the `BridgeSuspended` leaf's own `timestamp`. A requester-supplied timestamp feeds neither derivation, so a `BridgeRegistrationRequest` that declared one would carry a value every member ignores, and an operator reading that value would take it for the timestamp the registration is filed under.

**`BridgeRegistrationMetadata`** — The human-readable values the `metadata` field of a `BridgeRegistrationRequest` carries. It is a different type from the `BridgeMetadata` of §5.7, which the context publishes in the `bridges` structural field and which carries the platform, the operator, the bridge's capabilities and its directionality mode (§12.2, §12.6.1). A member reads `BridgeRegistrationMetadata` while governance decides the proposal, and reads `BridgeMetadata` off the published context metadata after the approval.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `display_name` | `String` | Yes | The name the proposal shows a member deciding it (e.g. `"Acme Discord Bridge"`). |
| `description` | `String` | Yes | What the operator states the bridge does in this context. |
| `operator_contact` | `String` | Yes | The address at which a member reaches the operator (e.g. an email address or a URL). |

**`RegistrationDecision`** — Governance decision on bridge registration.

| Variant | Serde Tag | Fields | Semantics |
|---------|-----------|--------|-----------|
| `Approved` | `"Approved"` | — | Registration accepted. |
| `Rejected` | `"Rejected"` | `reason: String` | Registration denied with explanation. |

**`BridgeRegistrationAction`** — Tagged enum for registration lifecycle actions.

| Variant | Tag | Fields | Semantics |
|---------|-----|--------|-----------|
| `Requested` | `"Requested"` | — | Registration submitted. |
| `Approved` | `"Approved"` | — | Governance approved the registration. |
| `Rejected` | `"Rejected"` | `reason: String` | Governance rejected with reason. |
| `Revoked` | `"Revoked"` | — | Governance revoked an active bridge. |
| `Suspended` | `"Suspended"` | `reason: String`, `duration: Option<u64>` | Governance suspended an active bridge; `duration` is seconds until automatic reactivation, `None` until an explicit `ReactivateBridge` (suspension, §12.2.2). |
| `Reactivated` | `"Reactivated"` | — | Governance reactivated a suspended bridge. An elapsed suspension `duration` expires the suspension and writes no record (suspension, §12.2.2). |

**`BridgeRegistrationEvent`** — Event log entry for bridge registration lifecycle. It is the payload of the `BridgeRegistered`, `BridgeSuspended`, `BridgeReactivated`, and `BridgeRevoked` leaves (ADR-011, verifiable event log), serialized as MessagePack into `EventPayload::data`.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `action` | `BridgeRegistrationAction` | Yes | The lifecycle action. |
| `bridge_id` | `String` | Yes | The 64-character lowercase hex identifier that §12.2.1 step 3 assigned to this bridge on the approval that registered it. |
| `operator_did` | `String` (DID) | Yes | Bridge operator's DID. |
| `governance_did` | `String` (DID) | Yes | DID of the governance actor who made the decision. §12.2.1 step 2 forbids this actor from being the operator on a `RegisterBridge` approval. |
| `context_id` | `String` | Yes | Context ID. |
| `timestamp` | `u64` | Yes | Unix timestamp (seconds): the leaf `timestamp` that event sequencing assigns (§7.3.1), which is the committer-assigned `created_at` of the commit envelope that appended this leaf and is no member's local clock reading. §12.2.1 step 3 derives the `bridge_id` from this value on a `BridgeRegistered` leaf, and §12.2.2 computes a suspension deadline from it on a `BridgeSuspended` leaf. |

### 12.12.3 Shadow Identity Management

**`ShadowProvenanceStatus`** — Enum for shadow identity provenance state.

| Variant | Serde Tag | Semantics |
|---------|-----------|-----------|
| `Shadow` | `"Shadow"` | Unclaimed. Attributed to bridge operator. |
| `Claimed` | `"Claimed"` | Claimed by a verified DID via attestation proof. |

**`ShadowIdentity`** — A shadow identity representing a non-SCP platform user.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `shadow_id` | `String` | Yes | Unique shadow identifier. |
| `platform_handle` | `String` | Yes | User's handle on the external platform. |
| `bridge_id` | `String` | Yes | Bridge that created this shadow. |
| `attributed_role` | `String` | Yes | Role within the context (e.g., `"reader"`). |
| `provenance_status` | `ShadowProvenanceStatus` | Yes | Whether claimed by a verified DID. |
| `created_at` | `u64` | Yes | Unix timestamp (seconds). |

**`ShadowCreationEvent`** — Event log entry for shadow identity creation.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `shadow_id` | `String` | Yes | Shadow identifier. |
| `platform_handle` | `String` | Yes | External platform handle. |
| `bridge_id` | `String` | Yes | Creating bridge. |
| `bridge_mode` | `BridgeMode` | Yes | Bridge operating mode at creation time. |
| `initial_role` | `String` | Yes | Initial context role. |
| `context_id` | `String` | Yes | Context ID. |
| `timestamp` | `u64` | Yes | Unix timestamp (seconds). |

**`ShadowRoleUpgradeEvent`** — Event log entry for shadow role changes.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `shadow_id` | `String` | Yes | Shadow identifier. |
| `previous_role` | `String` | Yes | Role before upgrade. |
| `new_role` | `String` | Yes | Role after upgrade. |
| `governance_did` | `String` (DID) | Yes | DID authorizing the change. |
| `context_id` | `String` | Yes | Context ID. |
| `timestamp` | `u64` | Yes | Unix timestamp (seconds). |

**`GovernanceAction`** — A governance action associated with shadow management.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `governance_did` | `String` (DID) | Yes | DID of the governance actor. |
| `context_id` | `String` | Yes | Context ID. |
| `timestamp` | `u64` | Yes | Unix timestamp (seconds). |
| `justification` | `String` | Yes | Reason for the action. |

### 12.12.4 Shadow Claiming

**`ClaimRequest`** — Request to claim a shadow identity.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `shadow_id` | `String` | Yes | Shadow to claim. |
| `claimant_did` | `String` (DID) | Yes | DID of the claimant. |
| `attestation_proof` | `Vec<u8>` (serde_bytes) | Yes | Cryptographic proof binding the platform identity to the DID (§3.5). |
| `requested_at` | `u64` | Yes | Unix timestamp (seconds). |

**`ShadowClaimEvent`** — Event log entry for a successful claim.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `shadow_id` | `String` | Yes | Claimed shadow. |
| `claimant_did` | `String` (DID) | Yes | DID that claimed the shadow. |
| `claimed_at` | `u64` | Yes | Unix timestamp (seconds). |
| `context_id` | `String` | Yes | Context ID. |

### 12.12.5 Bridge Provenance

**`BridgeTrustLevel`** — Enum for bridge trust ordering (lowest to highest).

| Variant | Serde Tag | Numeric Order | Semantics |
|---------|-----------|---------------|-----------|
| `ShadowBridged` | `"ShadowBridged"` | 0 | Content from unclaimed shadow identity. Lowest trust. |
| `ClaimedBridged` | `"ClaimedBridged"` | 1 | Content from claimed (DID-verified) shadow. |
| `NativeBridged` | `"NativeBridged"` | 2 | Content from native SCP member via bridge transport. |
| `NativeNative` | `"NativeNative"` | 3 | Content from native SCP member via native transport. Highest trust. |

**`BridgeProvenance`** — Extended provenance for bridged content (extends `DataProvenance` §24).

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `base` | `DataProvenance` | Yes | Standard provenance fields. |
| `originating_platform` | `String` | Yes | Platform name (e.g., `"slack"`). |
| `bridge_connector_id` | `String` | Yes | Bridge that relayed the content. |
| `operator_did` | `String` (DID) | Yes | Bridge operator's DID. |
| `bridge_mode` | `BridgeMode` | Yes | Operating mode of the bridge. |
| `shadow_status` | `ShadowProvenanceStatus` | Yes | Whether the original sender is a shadow or claimed. |

### 12.12.6 Bridge Message Envelope

**`SenderKeyEnvelope`** — Envelope for bridged messages using sender key encryption.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `sender_did` | `String` | Yes | DID of the message sender (bridge operator for shadow senders). |
| `encryption_type` | `String` | Yes | `"sender_key"` or `"mls"`. |
| `ciphertext` | `Vec<u8>` (serde_bytes) | Yes | Encrypted message payload. |
| `bridge_provenance` | `BridgeProvenance` | Yes | Provenance metadata. |
| `platform_message_id` | `String` | No | Original message ID on the external platform. |
| `platform_timestamp` | `u64` | No | Original timestamp on the external platform. |

### 12.12.7 Bridge Credentials

**`CredentialType`** — Enum for credential categories.

| Variant | Serde Tag | Semantics |
|---------|-----------|-----------|
| `OAuthAccessToken` | `"OAuthAccessToken"` | OAuth 2.0 access token. |
| `OAuthRefreshToken` | `"OAuthRefreshToken"` | OAuth 2.0 refresh token. |
| `ApiKey` | `"ApiKey"` | Platform API key. |
| `WebhookSecret` | `"WebhookSecret"` | Webhook signing secret. |
| `Custom` | `"Custom"` | Custom credential type. Carries `type_name: String`. |

**`BridgeCredential`** — Encrypted credential storage record.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `encrypted_data` | `Vec<u8>` (serde_bytes) | Yes | Format: `[12-byte AES-GCM nonce][ciphertext + 16-byte tag]`. Encrypted with bridge operator's key. |
| `credential_type` | `CredentialType` | Yes | What kind of credential this is. |
| `created_at` | `u64` | Yes | Unix timestamp (seconds). |
| `expires_at` | `u64` | No | Expiry timestamp. Absent for non-expiring credentials. |
| `bridge_id` | `String` | Yes | Bridge this credential belongs to. |
