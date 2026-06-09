# 12. Platform Bridge Connectors

## 12.1 The Problem

The social graph doesn't start empty. Users have relationships, conversations, communities, and history on existing platforms — X, Facebook, Instagram, WhatsApp, Discord, Slack, and whatever comes next. SCP must provide a path to participate alongside these platforms without requiring their cooperation or conformance.

This is not the same as local data import. Local import (scraping your own data, downloading your archive) is a user-level concern handled by local agent orchestration below the protocol boundary. Bridge connectors are a **protocol-level primitive** — a standardized interface through which non-SCP platforms can participate in SCP contexts, and SCP contexts can reach into external platforms.

## 12.2 Bridge Connectors as Protocol Entities

A bridge connector is a registered protocol entity — distinct from agents, tools, and contexts. It translates between an external platform's native protocol and SCP's protocol semantics.

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
  metadata:        BridgeMetadata,   // display name, description, operator contact
}
```

**Registration flow:**

1. The bridge operator submits a `RegisterBridge` proposal to the context via the standard governance mechanism (§5.9). The operator MUST be a context member or hold a valid UCAN granting `bridging` capability in the context.
2. The context's governance model processes the proposal (SingleAdmin: admin approves; Threshold/MajorityVote/Unanimity: members vote).
3. On approval, the context emits a `BridgeRegistered` event in the Merkle event log containing the full `RegisterBridge` payload, the approving governance action ID, and the assigned `bridge_id` (lowercase hex-encoded SHA-256 of `context_id || operator_did || platform || timestamp`). The result is a 64-character hex string carried as `String` on the wire (see §12.12).
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
2. On governance approval, the context emits a `BridgeRevoked` event in the Merkle event log.
3. The bridge's `BridgeStatus` transitions to `Revoked`.
4. If `destroy_shadows` is true: all shadow identities associated with this bridge are retired. Each shadow retirement emits a `ShadowRetired` event. Historical actions attributed to shadows remain in the event log with their original provenance.
5. If `destroy_shadows` is false: shadows persist but are orphaned — no new messages can be emitted through them, but their historical attributions remain.
6. The credential store for this bridge instance MUST destroy all delegated credentials (§12.11.1 Phase 5).
7. In-flight messages from shadows that have not yet been committed to the event log are dropped. The bridge node receives a `BRIDGE_SUSPENDED` or `BRIDGE_FORBIDDEN` error on subsequent API calls.
8. Context metadata is republished with the bridge removed from the `bridges` field.

**Suspension** uses `SuspendBridge { bridge_id, reason, duration: Option<u64> }`. Suspension stops message processing but retains shadow state and credentials (§12.11.1). If `duration` is set, the bridge automatically reactivates after the specified seconds. Otherwise, explicit `ReactivateBridge { bridge_id }` governance action is required.

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
X-SCP-Platform-Key-Id: <platform's signing key identifier>
X-SCP-Timestamp: <Unix timestamp in seconds>
```

**Canonical payload construction.** The signed payload is constructed as: `timestamp_bytes || raw_request_body_bytes`, where `timestamp_bytes` is the ASCII decimal representation of the `X-SCP-Timestamp` value. This prevents replay attacks — the bridge node MUST reject requests where `X-SCP-Timestamp` differs from the current time by more than 300 seconds (5 minutes).

**Platform key registration mechanism.** The platform's Ed25519 public key is registered during bridge setup via the `RegisterBridge` governance action (§12.2.1), which includes an optional `platform_key: Option<[u8; 32]>` field. For cooperative mode, this field is REQUIRED. The key exchange flow:

1. Before registration, the bridge operator and platform operator exchange the platform's Ed25519 public key out-of-band (e.g., via the platform's developer console, an API call to the platform, or manual configuration).
2. The bridge operator includes the `platform_key` in the `RegisterBridge` proposal.
3. On governance approval, the bridge node stores the platform key associated with the bridge instance.
4. All subsequent webhook requests from the platform are verified against this key.
5. Key rotation: the platform publishes a new key by having the bridge operator submit a `UpdateBridgePlatformKey { bridge_id, new_platform_key }` governance action. During the rotation period (24 hours), the bridge node accepts signatures from either key.

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
| `BRIDGE_NOT_AUTHORIZED` | 401 | Bearer token invalid or expired |
| `BRIDGE_FORBIDDEN` | 403 | Bridge not authorized for this operation |
| `BRIDGE_SUSPENDED` | 403 | Bridge is suspended by context governance |
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

**Local-event webhook taxonomy.** Separately from platform forwarding, a bridge node MAY expose an outbound webhook dispatcher that notifies registered HTTP targets when context events occur locally on the node. This is the SCP-to-operator-tooling channel (distinct from the SCP-to-platform forwarding above): each local `ContextEvent` emitted by a context the node hosts is mapped to a webhook event with a stable, dot-separated `event_type` and a JSON payload. Delivery is best-effort and at-least-once; signing and headers follow the same conventions as the inbound webhook endpoint (§12.10.4). The defined event types are:

| `event_type` | Emitted when | Payload fields |
|--------------|--------------|----------------|
| `message.received` | A message is received in the context | `sender_did` (string) |
| `message.sent` | A message is sent in the context | `sender_did` (string), `sequence_number` (integer) |
| `member.joined` | A member joins the context | `member_did` (string), `role_name` (string) |
| `member.left` | A member leaves the context | `member_did` (string) |
| `governance.action` | A governance action executes | `proposal_id` (hex string), `action_summary` (string), `executor_did` (string), `resulting_epoch` (integer), `target_did` (string or null) |
| `context.event` | Any other context event (generic fallback) | `variant` (string — the event variant name) |

The `context.event` generic fallback carries only the variant name so that new `ContextEvent` variants surface to webhook consumers without silent omission, while structured payloads are reserved for the explicitly enumerated, externally meaningful event types above. Payload fields contain only metadata — message content is never included in webhook payloads (export-policy enforcement and metadata stripping apply as described above).

### 12.10.6 Bridge Node Lifecycle

The bridge node mediates between the platform's HTTP API and SCP protocol operations. The lifecycle is:

1. **Registration.** The bridge operator registers the bridge with an SCP context via `register_bridge()` (§12.2). The registration includes the platform's webhook URL and authentication credentials.
2. **Shadow creation.** The bridge node calls `POST /v1/scp/bridge/shadow` to create shadow identities for platform participants as they become relevant to the context.
3. **Bidirectional message flow.** SCP-to-platform: the bridge operator receives and decrypts SCP messages as an MLS group member, translates them to the platform's native format, and forwards them via the platform's API (§12.10.5). Platform-to-SCP: the platform pushes events via the webhook endpoint, and the bridge node constructs SCP envelopes with bridge provenance (§12.10.4).
4. **Attestation.** The platform attests to user identities via `POST /v1/scp/bridge/attest`. These attestations strengthen the trust evaluation for cooperative-mode shadows.
5. **Suspension/revocation.** Context governance can suspend or revoke the bridge at any time (§12.2). On suspension, the bridge node stops processing messages but retains shadow state. On revocation, the bridge is permanently disconnected.

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

5. **Revoke.** When `BridgeStatus` transitions to `Revoked`, the credential store MUST destroy all delegated credentials for that bridge instance. This includes calling the external platform's revocation endpoint (if available) and then destroying local credential material. When `BridgeStatus` transitions to `Suspended`, credential use MUST stop immediately, but credentials are retained for potential reactivation — the bridge may resume without re-provisioning.

### 12.11.2 Requirements

- Credentials MUST be encrypted at rest using a key derived from the bridge's `bridge_credential_key` (§12.11.1 Phase 2). The `bridge_credential_key` is a per-bridge random secret stored in the custody boundary — it is NOT derived from any identity key.
- Credentials MUST be stored separately from the operator's SCP identity keys (key isolation). A compromise of the credential store does not compromise the operator's SCP identity. A compromise of the operator's SCP identity keys does not expose platform credentials (the `bridge_credential_key` is an independent random secret, not derived from identity material).
- When `BridgeStatus` transitions to `Revoked`, the credential store MUST destroy all delegated credentials for that bridge instance. Destruction means: (a) call the platform's revocation endpoint if one exists, (b) overwrite local credential material with zeros, (c) delete the credential record, (d) overwrite and delete the `bridge_credential_key` from the custody boundary.
- When `BridgeStatus` transitions to `Suspended`, credential use MUST stop but credentials are retained for potential reactivation.
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

This section tabulates the wire format for all bridge protocol types that cross the network. All types use serde serialization (JSON for tool call payloads, MessagePack for MLS application messages and event log entries). An independent implementer MUST implement these types with exactly the field names, types, and semantics shown below. All constants referenced here are defined in §9.18.

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
| `bridge_id` | `String` | Yes | Proposed bridge identifier. |
| `operator_did` | `String` (DID) | Yes | Operator's DID. |
| `platform` | `String` | Yes | Target platform. |
| `mode` | `BridgeMode` | Yes | Requested operating mode. |
| `context_id` | `String` | Yes | Context to register with. |
| `requested_at` | `u64` | Yes | Unix timestamp (seconds). |
| `self_hosted` | `bool` | Yes | Whether the operator runs bridge infrastructure. |

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

**`BridgeRegistrationEvent`** — Event log entry for bridge registration lifecycle.

| Field | Type | Required | Semantics |
|-------|------|----------|-----------|
| `action` | `BridgeRegistrationAction` | Yes | The lifecycle action. |
| `bridge_id` | `String` | Yes | Bridge identifier. |
| `operator_did` | `String` (DID) | Yes | Bridge operator's DID. |
| `governance_did` | `String` (DID) | Yes | DID of the governance actor who made the decision. |
| `context_id` | `String` | Yes | Context ID. |
| `timestamp` | `u64` | Yes | Unix timestamp (seconds). |

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
