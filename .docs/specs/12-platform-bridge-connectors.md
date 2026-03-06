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
│                  │  Operator: did:key:...   │ ← Accountable       │
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
- **Transparent.** Bridge presence, operator identity, connected platform, and operating mode are visible to all context members and in context metadata (visible before opt-in).
- **Revocable.** Context governance can remove a bridge at any time, severing the connection to the external platform.

## 12.3 Shadow Identities

When a bridge connector brings external platform participants into an SCP context, it creates **shadow identities** — protocol-level representations of entities that exist on the external platform but do not (yet) have native SCP identities.

Shadow identities differ from native SCP identities in critical ways:

- **Attributed but not verified.** A shadow identity for `@dave_x` asserts that this entity is Dave on X. The assertion comes from the bridge operator, not from Dave himself. The trust in this attribution depends on trust in the bridge operator.
- **Restricted by default.** Shadow identities receive a constrained role — typically observer-equivalent. They cannot exercise capabilities that require verified identity. Specific role assignment is up to context governance.
- **Marked as bridged.** All actions and content associated with a shadow identity carry provenance marking indicating the bridge source. No shadow identity can be mistaken for a native SCP participant.
- **Claimable.** If Dave later joins SCP and publishes an identity attestation (§3.5) binding his X handle to his DID, his shadow identity can be claimed and merged with his native identity. Past actions attributed to the shadow are now attributed to Dave's DID. This transition is one-way and irreversible — once claimed, the shadow is retired.

```
  Before claiming:                   After claiming:

  @dave_x (shadow)                   Dave·Agent (did:key:xyz)
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

## 12.6 Bridge Connectors and Context Isolation

Bridge connectors do not violate context isolation. A bridge registered in Context A has no access to Context B. If the same external platform is bridged into two contexts, they are separate bridge instances with separate registrations.

Bridge connectors are not agents — they cannot initiate actions, exercise capabilities, or participate in governance. They are translation infrastructure. All agency flows through the agents and governance of the context they're registered in.

### 12.6.1 Bridge Encryption Model

Bridge connectors are **not MLS group members**. They do not receive MLS key schedule material and cannot decrypt messages between native context members. End-to-end encryption is preserved for native-to-native communication in bridged contexts.

Shadow identity messages use the **sender key layer** (§9.16) rather than MLS encryption. The bridge operator generates a sender key per shadow identity and distributes it via the same pull-based protocol used in broadcast contexts. Native members decrypt bridge-originated messages using the shadow's sender key.

This creates two envelope types within a bridged encrypted context:

- **MLS-encrypted envelopes** — from native members, using the MLS group key schedule. Bridge cannot decrypt these.
- **Sender-key-encrypted envelopes** — from shadow identities, using per-shadow sender keys. All context members (native and bridge) can decrypt these.

The envelope type discriminator (§9.5) distinguishes the two paths on the receive side. Both decryption paths already exist in the protocol — MLS for encrypted contexts, sender keys for broadcast contexts.

Context metadata (§5.7) MUST include `bridge_operator_did` when a bridge is registered, so members can see that a bridge is present and evaluate trust accordingly.

### 12.6.2 Bridge Threat Model

A malicious bridge operator can:

1. **Fabricate shadow messages** — attribute content to platform users who did not produce it. Mitigated by `BridgeProvenance` (§12.4) which makes bridge attribution visible.
2. **Selectively drop messages** — suppress platform-to-SCP or SCP-to-platform delivery. Detectable via the platform's own delivery confirmation mechanisms.
3. **Correlate activity** — observe which platform users correspond to which shadow identities across contexts it operates in. Mitigated by separate bridge registrations per context (§12.6).
4. **Inject false attestations** — claim platform identity verification that did not occur. Mitigated by attestation freshness checks (§7.4.4) and governance-level bridge revocation (§12.2).

A malicious bridge operator **cannot**:

- Read native-to-native messages (no MLS key material).
- Modify native member messages (MLS authentication prevents forgery).
- Exercise capabilities or participate in governance (bridge is not an agent).
- Access other contexts (bridge registration is per-context).

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
- **Minimal surface area.** Six endpoints. No SCP-specific data structures leak into the platform's API — all SCP envelope construction, MLS encryption, and provenance marking happen on the bridge node.
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

For webhook callbacks (platform to bridge node), the platform signs the request body:

```
X-SCP-Signature: <Ed25519 signature over raw request body>
X-SCP-Platform-Key-Id: <platform's signing key identifier>
```

The bridge node verifies the signature against the platform's pre-registered public key (exchanged during bridge registration).

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
| `content_type` | string | yes | MIME type of the content (`text/plain`, `text/markdown`, `application/json`) |
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

The `202 Accepted` status indicates the bridge node has accepted the message for processing. Envelope construction and MLS encryption happen asynchronously. The `bridge_provenance` field confirms the provenance chain that will be attached.

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
- **`message_edit`** — A previously bridged message was edited. Payload: `platform_message_id`, `new_content`, `new_content_type`, `edited_at`.
- **`message_delete`** — A previously bridged message was deleted on the platform. Payload: `platform_message_id`, `deleted_at`.

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

### 12.10.5 Bridge Node Lifecycle

The bridge node mediates between the platform's HTTP API and SCP protocol operations. The lifecycle is:

1. **Registration.** The bridge operator registers the bridge with an SCP context via `register_bridge()` (§12.2). The registration includes the platform's webhook URL and authentication credentials.
2. **Shadow creation.** The bridge node calls `POST /v1/scp/bridge/shadow` to create shadow identities for platform participants as they become relevant to the context.
3. **Bidirectional message flow.** SCP-to-platform: the bridge node receives SCP messages and calls platform APIs to deliver them. Platform-to-SCP: the platform pushes events via the webhook endpoint, and the bridge node constructs SCP envelopes with bridge provenance.
4. **Attestation.** The platform attests to user identities via `POST /v1/scp/bridge/attest`. These attestations strengthen the trust evaluation for cooperative-mode shadows.
5. **Suspension/revocation.** Context governance can suspend or revoke the bridge at any time (§12.2). On suspension, the bridge node stops processing messages but retains shadow state. On revocation, the bridge is permanently disconnected.

### 12.10.6 Cooperative Mode Trust Differentiation

Content entering SCP through the cooperative mode HTTP binding receives enhanced trust evaluation compared to relay or puppet mode. The trust differentiation (§12.5) applies:

- **Shadow + Cooperative transport** is evaluated more favorably than **Shadow + Relay transport** because the platform has vouched for the attribution via its own identity infrastructure.
- The `bridge_mode` field in `BridgeProvenance` distinguishes `Cooperative` from other modes. Trust engines (§7) and agents MAY treat cooperative-mode provenance as a positive signal.
- Platform-provided attestation evidence (via `POST /v1/scp/bridge/attest`) further strengthens identity confidence for individual shadows.

### 12.10.7 Implementation Considerations

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

2. **Store.** Credentials are encrypted at rest and stored in isolation from the operator's SCP identity keys. Credentials MUST be encrypted using a key derived from the bridge operator's identity key material (e.g., HKDF from the operator's signing key with a bridge-specific salt). Credentials MUST be stored separately from the operator's SCP identity keys — the credential store is a distinct storage domain, not a field on the bridge entity.

3. **Use.** The bridge authenticates to the external platform using stored credentials. Credential access is scoped to the bridge instance — a bridge registered in Context A cannot use credentials provisioned for a bridge in Context B, even if operated by the same DID.

4. **Rotate.** Credentials are refreshed before expiry. For OAuth tokens, this means using refresh tokens to obtain new access tokens before the current token expires. For API keys, this means re-provisioning when keys approach their rotation deadline. Rotation SHOULD be automatic with exponential backoff on failure.

5. **Revoke.** When `BridgeStatus` transitions to `Revoked`, the credential store MUST destroy all delegated credentials for that bridge instance. This includes calling the external platform's revocation endpoint (if available) and then destroying local credential material. When `BridgeStatus` transitions to `Suspended`, credential use MUST stop immediately, but credentials are retained for potential reactivation — the bridge may resume without re-provisioning.

### 12.11.2 Requirements

- Credentials MUST be encrypted at rest using a key derived from the bridge operator's identity key material.
- Credentials MUST be stored separately from the operator's SCP identity keys (key isolation). A compromise of the credential store does not compromise the operator's SCP identity. A compromise of the operator's SCP keys does not directly expose platform credentials (derived key, not the identity key itself).
- When `BridgeStatus` transitions to `Revoked`, the credential store MUST destroy all delegated credentials for that bridge instance. Destruction means: (a) call the platform's revocation endpoint if one exists, (b) overwrite local credential material with zeros, (c) delete the credential record.
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
- Both are encrypted at rest using a key derived from the operator's identity key material.

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
