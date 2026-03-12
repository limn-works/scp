# 13. Versioning and Protocol Evolution

The protocol will evolve. New capabilities, new attestation types, new transport bindings, refinements to governance primitives. This section defines the concrete mechanisms that ensure evolution is orderly: a version numbering scheme, wire-level version fields, negotiation rules, forward compatibility contracts, degraded-mode behavior, and an extension point registry.

## 13.1 Protocol Version Number

SCP uses a two-component version: `major.minor`. The initial release is **SCP/1.0**.

- **Major version** increments on breaking wire format changes — changes that make messages from the new version unreadable by the old version even when following the forward compatibility rules (§13.5). Examples: redefining the signed structure field order, changing the encryption scheme, removing a required field.
- **Minor version** increments on backward-compatible additions — new optional fields, new message types, new extension point registrations. An SCP/1.0 implementation encountering an SCP/1.1 message can still process it (with degraded feature set per §13.6).

Version numbers are monotonically increasing integers. There is no patch component — the protocol specification is not software. Editorial corrections to the spec that do not change wire behavior do not change the version number.

**Current version:** SCP/1.0.

## 13.2 Version Field in Wire Structures

Every top-level wire structure includes a `version` field as its first serialized field. This field is a `u16` encoding `(major << 8) | minor`, giving range `0.0` through `255.255`. SCP/1.0 encodes as `0x0100` (decimal 256).

### 13.2.1 InnerEnvelope

The `version` field is added as the first field in the signed structure (§9.5.2). The domain separator is unchanged — the version is data within the structure, not part of the domain separator. The domain separator version suffix (e.g., `"SCP-INNER-ENVELOPE-V1:"`) tracks structural layout changes independently; the `version` field inside the structure tracks protocol semantics.

**Updated signed structure:**

| Order | Field | Encoding |
|-------|-------|----------|
| 1 | `version` | 2-byte BE u16 |
| 2 | `message_type` | 1-byte U8 discriminator (0x00=Content, 0x01=Signaling, 0x02=KeyDistribution) |
| 3 | `context_id` | 4-byte BE length + UTF-8 bytes |
| 4 | `sender_did` | 4-byte BE length + UTF-8 bytes |
| 5 | `epoch` | 8-byte BE u64 |
| 6 | `generation_number` | 8-byte BE u64 |
| 7 | `sequence_number` | 8-byte BE u64 |
| 8 | `timestamp` | 8-byte BE u64 |
| 9 | `payload_hash` | 4-byte BE length + 32 bytes |
| 10 | `provenance_hash` | 4-byte BE length + 32 bytes (or `SHA-256(0x00)` sentinel if absent) |
| 11 | `signing_key_id` | 4-byte BE length + UTF-8 bytes |

Adding `version` as field 1 and `message_type` as field 2 changes the field positions of all subsequent fields, which changes the signed bytes. This is intentional — both fields are part of the signature commitment. The `message_type` discriminator byte prevents type-flipping attacks where an adversary replays a message under a different type semantics (#290). The domain separator is `"SCP-INNER-ENVELOPE-V1:"` for the initial protocol version (v1). Future protocol versions will increment the domain separator (e.g., `V2`) when the signed structure changes.

The `InnerEnvelope` MessagePack serialization includes `version` as the first map key (or first positional field if using positional encoding — see §9.5.2 for the canonical field ordering).

### 13.2.2 BroadcastEnvelope

Same pattern. The `version` field is the first field in the signed structure:

| Order | Field | Encoding |
|-------|-------|----------|
| 1 | `version` | 2-byte BE u16 |
| 2 | `context_id` | 4-byte BE length + UTF-8 bytes |
| 3 | `sender_did` | 4-byte BE length + UTF-8 bytes |
| 4 | `signing_key_id` | 4-byte BE length + UTF-8 bytes |
| 5 | `sequence` | 8-byte BE u64 |
| 6 | `key_epoch` | 8-byte BE u64 |
| 7 | `timestamp` | 8-byte BE u64 |
| 8 | `content_hash` | 32 bytes (SHA-256 of original plaintext) |
| 9 | `provenance_hash` | 32 bytes (SHA-256 of serialized provenance, or `SHA-256(0x00)` if absent) |

Domain separator increments to `"SCP-BROADCAST-ENVELOPE-V2:"`.

### 13.2.3 OuterEnvelope

The outer envelope gains a `version` field as its first serialized field. Since the outer envelope is unsigned (§9.10.2), this is purely for deserialization routing — it tells the recipient which version's deserializer to use.

**Updated outer envelope fields (what relays see):**

1. **Version** — `u16`, protocol version
2. **Routing identifier** — per-context pseudonym (§9.10.4)
3. **Recipient hint** — recipient pseudonym for directed messages, or broadcast marker
4. **Blob TTL** — how long the relay should store before deletion
5. **Encrypted blob** — everything else

Relays MUST forward outer envelopes with unrecognized version numbers without modification. The relay is a dumb pipe — it does not interpret the version field. Recipients use the version field to select the correct deserialization path for the encrypted blob's inner contents.

### 13.2.4 Relay Protocol Messages

The relay wire format (ADR-004) already uses URL-path versioning (`/scp/v1`) for major version negotiation and requires unknown fields to be ignored (forward compatibility). The relay message envelope gains an optional `v` field:

```
{
  "op": <string>,
  "ref": <string>,
  "v": <u16>,        // protocol version (optional; absent = 0x0100 / SCP/1.0)
  ...
}
```

The `v` field is optional for backward compatibility — messages without `v` are treated as SCP/1.0. This field enables minor-version feature detection within a single URL-path major version. For example, a relay running SCP/1.2 that receives a `PUBLISH` with `v: 0x0103` (SCP/1.3) knows the client supports features up to 1.3.

Major version changes use a new URL path (`/scp/v2`). A relay MAY serve multiple major versions simultaneously on different paths. A relay that does not support a requested major version path returns HTTP 404 (existing ADR-004 behavior).

## 13.3 Version Advertisement

Implementations advertise their supported protocol version through three mechanisms, each serving a different discovery context:

### 13.3.1 DID Document Service Endpoint

The `SCPRelay` service endpoint (§18.2.1) URL already encodes the major version in its path (`/scp/v1`). No change required for major version advertisement.

For minor version advertisement, the `SCPRelay` service entry gains an optional `scpVersion` property:

```json
{
  "id": "#scp-relay-1",
  "type": "SCPRelay",
  "serviceEndpoint": "wss://relay.example.com/scp/v1",
  "scpVersion": "1.0"
}
```

When absent, `scpVersion` defaults to `"1.0"`. The value is a string in `"major.minor"` format. This tells peers the highest protocol version the relay supports within the URL path's major version.

### 13.3.2 .well-known/scp

The `.well-known/scp` document (§18.3) already has a `version` field (currently `1`). This field is the document format version, not the protocol version. A new `protocol_version` field is added:

```json
{
  "version": 1,
  "protocol_version": "1.0",
  "did": "did:dht:z6Mk...",
  "relay": "wss://relay.example.com/scp/v1",
  ...
}
```

When absent, `protocol_version` defaults to `"1.0"`. This enables web-based discovery of the operator's protocol version before connecting.

### 13.3.3 Relay Handshake

Upon WebSocket connection to `/scp/v1`, the relay sends an unsolicited `EVENT` message with type `hello`:

```
{
  "op": "EVENT",
  "type": "hello",
  "protocol_version": "1.0",
  "extensions": ["scp:ext:broadcast-projection/v1"],
  "limits": {
    "max_blob_size": 262144,
    "max_blob_ttl": 604800,
    "max_subscriptions": 100,
    "max_query_limit": 1000
  }
}
```

The `hello` event is the relay's self-description. It is sent once, immediately after the WebSocket connection is established, before the client sends any messages. Fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `protocol_version` | string | Yes | Highest supported protocol version (`"major.minor"` format). |
| `extensions` | array of string | No | Supported protocol extensions (§13.7). Empty array or absent if none. |
| `limits` | object | No | Relay operator limits (same fields as ADR-004 §Relay Operator Configuration). |

Clients that receive a `hello` with a higher minor version than they support proceed normally — the forward compatibility rules (§13.5) ensure interoperability. Clients that receive a `hello` with a higher major version than they support MUST disconnect and attempt a lower-versioned URL path if available.

Relays that predate the `hello` event (SCP/1.0 implementations deployed before this mechanism was added) will not send it. Clients MUST NOT require `hello` — if no `hello` is received within 5 seconds of connection, the client assumes SCP/1.0 with default limits.

## 13.4 Version Negotiation

SCP uses a **highest-common-version** model. There is no explicit negotiation handshake — version selection is implicit from the connection path and message version fields.

**Major version:** Selected by URL path. A client connects to `/scp/v1` or `/scp/v2`. If the relay returns 404, the client tries lower major versions in descending order. The first successful connection establishes the major version for that session.

**Minor version:** Selected per-message. Each message carries its own version field (§13.2). A sender uses the highest minor version it supports. A recipient processes the message according to the forward compatibility rules (§13.5) — if the message contains features from a higher minor version, the recipient ignores unknown fields and processes what it understands.

**Context-level minimum version:** Contexts MAY declare a `min_protocol_version` in their `ContextParams`:

```
min_protocol_version: Option<(u8, u8)>  // (major, minor), e.g., (1, 2) for SCP/1.2
```

When set, the SDK MUST reject attempts to join a context whose `min_protocol_version` exceeds the SDK's supported version. This is enforced client-side — the SDK checks the context metadata (§5.7, visible before opt-in) and refuses to join if incompatible. The `min_protocol_version` field is visible in context structural metadata alongside the capability ceiling and governance model.

When absent, `min_protocol_version` defaults to `(1, 0)`.

## 13.5 Forward Compatibility Rules

These rules define how implementations handle messages from higher minor versions within the same major version. They are MANDATORY for all SCP implementations.

### 13.5.1 Unknown Fields

Implementations MUST ignore unknown fields in MessagePack maps. This is already required by ADR-004 for relay protocol messages and is extended to all SCP wire structures:

- **InnerEnvelope:** Unknown fields MUST be preserved for forward-compatible roundtripping. The signature covers only the fields defined in the signed structure (§13.2.1). Unknown fields are not part of the signature commitment and MUST NOT cause signature verification failure. Intermediaries and SDK storage layers that deserialize and re-serialize inner envelopes MUST NOT strip fields they do not recognize. Implementations MUST preserve the MessagePack type fidelity of unknown fields — a Binary field MUST roundtrip as Binary, not degrade to Array. Extensions carry no authenticity guarantee: fields in the extensions map are not covered by the envelope signature and MUST NOT be used for security-sensitive decisions.
- **BroadcastEnvelope:** Same rule as InnerEnvelope — unknown fields MUST be ignored during processing but need not be preserved (broadcast envelopes are not forwarded by intermediaries).
- **OuterEnvelope:** Unknown fields MUST be preserved during relay forwarding. Relays MUST NOT strip unknown fields from outer envelopes.
- **Relay protocol messages:** Unknown fields MUST be ignored (existing ADR-004 rule).
- **ContextParams:** Unknown fields in context metadata MUST be ignored during join evaluation. An SCP/1.0 client encountering a context with SCP/1.2 fields it doesn't recognize proceeds with the fields it understands.

### 13.5.2 Unknown Message Types

Implementations MUST handle unknown relay protocol `op` values gracefully:

- **Relay receiving unknown client op:** Responds with `ERR { code: 4001, msg: "unknown op" }` (existing ADR-004 behavior).
- **Client receiving unknown relay op:** Logs the message and ignores it. MUST NOT disconnect. Unknown ops from the relay are assumed to be informational (like new `EVENT` types from a higher minor version).

### 13.5.3 Unknown Attestation Types

Unknown `attestation_type` tags (§9.5.2) MUST be preserved in storage and forwarding but ignored during trust evaluation. An SCP/1.0 implementation encountering an attestation with type tag `0x0010` (defined in SCP/1.2) stores it faithfully and passes it through, but does not factor it into trust scores. This ensures attestations are not lost during version transitions.

### 13.5.4 Unknown Capability URIs

The capability URI namespace (ADR-041) is self-versioning — each capability includes `/v{N}`. Unknown `scp:capability:*` URIs MUST be rejected by SDKs (existing ADR-041 rule — this prevents capability spoofing). Unknown `scp:system:*` URIs MUST be ignored. DID-scoped custom capabilities are always accepted (authority is the definer's DID, not the protocol).

### 13.5.5 Unknown Context Modes

If a context's metadata declares a `ContextMode` value that the SDK does not recognize, the SDK MUST NOT join the context. Unknown modes may have security properties the SDK cannot enforce. The SDK SHOULD report the unrecognized mode to the application layer so the user can update their SDK.

## 13.6 Degraded Mode

When an implementation encounters a context or peer using a higher minor version, it operates in degraded mode: full participation in understood features, silent non-participation in unrecognized features.

### 13.6.1 Degraded Mode Behaviors

| Situation | Behavior |
|-----------|----------|
| Unknown fields in InnerEnvelope | Preserve for roundtrip forwarding. Process known fields normally. |
| Unknown fields in ContextParams | Ignore. Join and participate using known parameters. |
| Unknown relay EVENT type | Ignore. Continue normal operation. |
| Context `min_protocol_version` exceeds SDK version | Refuse to join. Report to application layer. |
| Unknown `ContextMode` | Refuse to join. Report to application layer. |
| Unknown governance action variant | Do not vote on or execute. Abstain. Log warning. |
| Peer sends message with higher minor version | Process known fields. Ignore unknown. |
| Relay `hello` shows higher minor version | Proceed normally. |
| Relay `hello` shows higher major version | Disconnect. Try lower major version path. |

### 13.6.2 Degraded Mode Reporting

SDKs MUST expose degraded-mode status to the application layer. When operating in degraded mode, the SDK emits a structured event:

```
DegradedMode {
    context_id: ContextId,
    local_version: (u8, u8),
    remote_version: (u8, u8),    // highest version observed from peers
    unsupported_features: Vec<String>,  // human-readable descriptions
}
```

The application decides how to present this to users — update prompts, feature unavailability indicators, or silent acceptance.

## 13.7 Extension Point Registration

Extensions add protocol features without incrementing the protocol version. They are opt-in capabilities that implementations can advertise and negotiate independently. Extensions use the `scp:ext:` URI namespace.

### 13.7.1 Extension URI Format

```
scp:ext:{kebab-case-name}/v{integer}
```

Examples: `scp:ext:broadcast-projection/v1`, `scp:ext:media-signaling/v1`, `scp:ext:coap-transport/v1`.

The `scp:ext:` prefix is reserved for protocol-defined extensions. Third-party extensions use DID-scoped URIs: `did:{method}:{id}:ext:{name}/v{integer}`.

### 13.7.2 Extension Advertisement

Extensions are advertised through the same three mechanisms as protocol version (§13.3):

- **Relay `hello` event:** `extensions` array lists supported relay-side extensions.
- **DID document:** `SCPRelay` service entry gains optional `extensions` array.
- **`.well-known/scp`:** `relay_config` gains optional `extensions` array.

Context-level extensions are declared in `ContextParams` as an optional `extensions: Vec<String>` field. Contexts can require specific extensions for participation — a context that uses a new encryption scheme defined as an extension can declare it, and SDKs that don't support the extension refuse to join (same as `min_protocol_version`).

### 13.7.3 Extension Negotiation

Extensions follow the same highest-common model as version negotiation. There is no handshake — implementations use extensions they support and ignore extension-specific features they don't. If a context requires an extension (listed in `ContextParams.extensions`), SDKs that do not support the extension MUST NOT join.

### 13.7.4 Extension vs. Version Bump

| Change type | Mechanism |
|-------------|-----------|
| New optional field in existing structure | Minor version bump |
| New message type | Minor version bump |
| New attestation type | Extension (self-versioned via `attestation_type` tag) |
| New capability URI | Extension (self-versioned via `/v{N}` suffix per ADR-041) |
| New transport binding | Extension (independent of protocol version) |
| New `ContextMode` | Minor version bump (security implications require version gate) |
| Changed field encoding in signed structure | Major version bump + domain separator increment |
| Removed required field | Major version bump |
| New encryption algorithm | Major version bump (security-critical) |

### 13.7.5 Registered Extensions

The initial SCP/1.0 release defines zero extensions. The extension registry is empty at launch. New extensions are defined in subsequent spec updates or ADRs, each with:

1. Extension URI
2. Scope (relay-side, client-side, or both)
3. Wire format additions (new fields, new message types)
4. Interaction with existing features
5. Forward compatibility impact

The extension registry is maintained as part of the protocol specification. There is no separate registry service — the spec is the registry. This follows the "protocol requires no operator" tenet.

## 13.8 Version Transition Procedure

When a new major version is released:

1. **Dual-serve period.** Relays SHOULD serve both the old and new major version paths simultaneously for a transition period. The transition period length is defined in the version's release notes (recommended minimum: 6 months).
2. **Context migration.** Contexts do not automatically upgrade. A context created under SCP/1.x remains an SCP/1.x context. To use SCP/2.x features, create a new context and migrate members. Context migration tooling (member re-invitation, history reference) is an SDK concern, not a protocol concern.
3. **Identity continuity.** DID documents span protocol versions. An identity's DID document MAY advertise relay endpoints for multiple major versions simultaneously. The DID itself does not change across protocol versions.
4. **No implicit upgrade.** The protocol never silently upgrades a context or connection to a new major version. All major version transitions are explicit — new URL path, new context, new wire format.

## 13.9 Implementation Conformance

An implementation claiming SCP/1.x conformance MUST:

1. Include the `version` field as the first field in all wire structures (§13.2).
2. Set `version` to `0x0100` (SCP/1.0) or the highest minor version it fully implements.
3. Ignore unknown fields in all deserialized structures, except `InnerEnvelope` and `OuterEnvelope` where unknown fields MUST be preserved for forward-compatible roundtripping with full type fidelity (§13.5.1).
4. Handle unknown relay ops without disconnecting (§13.5.2).
5. Preserve unknown fields in `InnerEnvelope` and `OuterEnvelope` when forwarding or re-serializing — including intermediaries, SDK storage layers, and relays (§13.5.1).
6. Refuse to join contexts with unrecognized `ContextMode` (§13.5.5).
7. Refuse to join contexts with `min_protocol_version` higher than supported (§13.4).
8. Report degraded-mode status to the application layer (§13.6.2).

Conformance testing for version handling is part of the SDK conformance suite (§16).
