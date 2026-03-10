# 6. Cross-Context Communication

## 6.1 Agent Isolation

Agents cannot cross contexts at the protocol level. This is absolute. An agent in Context A cannot send a message to Context B, read Context B's state, or interact with Context B's tools or members. From the protocol's perspective, the agent in A and the agent in B (even if operated by the same human) are entirely separate instances.

Information may cross context boundaries through two protocol-level mechanisms:

1. **Cross-context tool interfaces (§6.2)** — asymmetric, structured, request/response. One context queries another's tool. Governed by both contexts per call.
2. **Multi-parent child contexts (§5.13)** — symmetric, full context. A shared space governed by multiple parent contexts. Members from different parents interact as peers.

Both mechanisms require explicit consent from all involved contexts. Neither allows agents to directly access another context's state. The first is for service-style interactions; the second is for collaborative ones.

## 6.2 Context-to-Context Tool Interfaces

### 6.2.0 Tool Interface Transport

Cross-context tool calls require a physical transport mechanism to bridge the boundary between two isolated contexts. Two protocol-level mechanisms provide this:

1. **Shared-member bridging (primary).** When a human participates in both contexts, their SDK bridges tool requests and responses locally. The human's agent in Context A makes a tool call targeting Context B; the SDK routes the request through the human's membership in Context B, executes the call under Context B's governance, and returns the response to Context A. No relay-level cross-context routing is needed — the bridge operates entirely within the human's local SDK. Both contexts' governance is enforced: Context A's outbound policy and Context B's inbound policy are validated before the call proceeds. The human's SDK is the transport, and both event logs record the interaction with full provenance.

2. **Multi-parent child contexts (fallback).** For cases without a shared member, a child context with parents from both the source and target contexts can serve as a bridge (§5.13). The child context inherits capability ceilings from both parents (intersection). Members from both parent contexts who join the child context can mediate tool calls within the child's governed space. This is heavier than shared-member bridging but covers the case where no single human has membership in both contexts.

These two mechanisms cover all cross-context tool call scenarios. Direct agent-to-agent communication is not needed — tool interfaces with stateful sessions (§6.2.1) provide the same functional coverage (negotiation, coordination, multi-step workflows) with stronger security guarantees: every interaction is context-governed, schema-declared, rate-limited, and auditable. The context governs the tool call, not the agent.

Contexts can expose tool endpoints to other contexts. **The context governs the tool call, not the agent.** An agent in Context A does not directly contact Context B — the agent requests from Context A, Context A's governance decides whether to permit the outbound call, and Context B's governance decides whether to permit the inbound call and how to respond. Both contexts mediate. The agent never directly touches the other context.

This is the mechanism for all structured inter-agent interaction across context boundaries. Both contexts' governance models, capability ceilings, and role permissions gate every interaction.

Properties:

- Both contexts opt in explicitly (bidirectional consent at the context level, not the agent level — see §6.2.0.1 for the consent protocol).
- Data flows through defined function signatures, not through agent memory or discretion.
- Auditable: every call through an interface is logged in both contexts' event logs with full provenance (§7.7).
- Tool interfaces carry provenance: data received through an interface carries its origin context, invoking agent, timestamp, and chain depth (§7.7.1).
- Rate-limited: both contexts can enforce rate limits on interface calls (see §6.2.0.2 for defaults).
- **Chain depth limit.** Cross-context tool calls carry a `chain_depth` counter, incremented on each hop. A tool call at maximum depth cannot trigger further cross-context tool calls. The protocol defines a hard maximum of 5 hops that cannot be exceeded. Contexts MAY configure a lower maximum via `max_chain_depth` in `ContextParams` (RECOMMENDED default: 3). This bounds amplification and makes transitive provenance degradation mechanically enforced (§9.2.1, §24.4).
- **Schema constraints.** Tool schemas must satisfy a structural specificity floor at registration time — no unbounded string-only interfaces, minimum two distinct fields in input or output. This prevents degenerate broad-schema tools that function as arbitrary message channels (§9.2.1).
- **Tool-level costs.** Individual tools may declare per-invocation costs in their registration metadata (§5.4). These are additive with context-level costs and carry their own payee DID. Cross-context tool calls inherit the target tool's cost structure. See §19.3 for economic policy and §19.2.2 for the payment integration sequence.

#### 6.2.0.1 Bidirectional Consent Protocol

Tool interface creation requires explicit consent from both the exposing context and the consuming context. The consent protocol:

1. **Interface proposal.** An admin in Context A proposes exposing a tool to Context B via a governance action:
   ```
   ProposeToolInterface {
     tool_id:        ToolId,       // Tool to expose
     target_context: ContextId,    // Context B
     outbound_policy: OutboundPolicy,
     max_calls_per_minute: u32,    // Rate limit for this interface
   }
   ```
   This proposal follows Context A's governance model (§5.9).

2. **Outbound policy validation.** Context A validates that `toolInterface` is in its ceiling (§5.3) and the proposer holds the `toolInterface` capability.

3. **Interface offer.** On governance approval, Context A publishes an `InterfaceOffer` to its event log:
   ```
   InterfaceOffer {
     offer_id:       [u8; 32],     // SHA-256(context_a_id || tool_id || context_b_id || timestamp)
     source_context: ContextId,    // Context A
     target_context: ContextId,    // Context B
     tool_schema:    ToolRegistration, // Full tool schema (§5.4.1)
     outbound_policy: OutboundPolicy,
     expires_at:     u64,          // Offer expires if not accepted within 7 days
   }
   ```

4. **Acceptance.** A shared member carries the offer to Context B (shared-member bridging). Context B's governance decides whether to accept:
   ```
   AcceptToolInterface {
     offer_id:       [u8; 32],
     inbound_policy: InboundPolicy,
   }
   ```
   This follows Context B's governance model. Acceptance creates an `InterfaceEstablished` event in both event logs.

5. **Teardown.** Either context can revoke the interface at any time via governance action `RevokeToolInterface { interface_id }`. Revocation is unilateral — no consent from the other side is needed. An `InterfaceRevoked` event is recorded in the revoking context's event log.

**Outbound and inbound policies:**

```
OutboundPolicy {
  allowed_callers:      Vec<DID>,   // DIDs in Context A authorized to use this interface.
                                    // Empty = any member with toolInterface capability.
  max_calls_per_minute: u32,        // Rate limit from Context A's perspective.
  max_payload_bytes:    u32,        // Maximum request payload size. Default: 65536 (64 KiB).
  require_provenance:   bool,       // Whether responses must carry provenance. Default: true.
}

InboundPolicy {
  allowed_source_roles: Vec<String>, // Roles in Context A whose members can call. Empty = any.
  max_calls_per_minute: u32,        // Rate limit from Context B's perspective.
  max_response_bytes:   u32,        // Maximum response payload size. Default: 65536 (64 KiB).
  require_spending_ucan: bool,      // Whether callers must present spending UCANs. Default: false.
}
```

Outbound policy is set by Context A (the exposing context). Inbound policy is set by Context B (the consuming context). Both policies are enforced — a call must satisfy BOTH to proceed. The effective rate limit is `min(outbound.max_calls_per_minute, inbound.max_calls_per_minute)`.

#### 6.2.0.2 Tool Interface Rate Limit Defaults

Rate limits for cross-context tool interfaces use a sliding window counter with the following defaults:

| Parameter | Default | Configurable range |
|-----------|---------|-------------------|
| Per-interface calls/minute | 60 | 1 - 6000 |
| Per-caller calls/minute | 10 | 1 - 1000 |
| Burst allowance | 5 (calls above limit within 1 second) | 0 - 50 |
| Window duration | 60 seconds (sliding) | 10 - 3600 seconds |

**Enforcement semantics.** When a rate limit is exceeded, the call is rejected with error code `TOOL_INTERFACE_RATE_LIMITED` (code 4030). The response includes a `Retry-After` header indicating seconds until the next call will be accepted. Calls are NOT queued — rate-limited calls fail immediately. The caller's SDK MAY retry after the indicated delay.

**Per-caller vs. per-interface limits.** Both limits are enforced independently. A single caller is limited to 10 calls/minute by default; all callers combined are limited to 60 calls/minute per interface. This prevents a single caller from monopolizing an interface.

### 6.2.1 Stateful Tool Sessions

Tool interfaces support optional session-based multi-turn interaction. A tool can accept a session identifier and maintain state across sequential invocations. This enables multi-step workflows (negotiation, coordination, iterative refinement) within the governed tool call framework.

```
// First call: initiate a scheduling session
Context A → Context B tool "schedule_meeting":
  input:  { action: "propose", times: ["Tue 3pm", "Thu 2pm"] }
  output: { session_id: "sched:abc123", status: "pending", counter: ["Tue 4pm"] }

// Second call: continue the session
Context A → Context B tool "schedule_meeting":
  input:  { session_id: "sched:abc123", action: "accept", time: "Tue 4pm" }
  output: { session_id: "sched:abc123", status: "confirmed", time: "Tue 4pm" }
```

Session state is maintained by the tool's context (Context B), not by the calling agent. Each call in the session is individually governed — Context A's governance permits each outbound call, Context B's governance permits each inbound call. The session does not create a persistent channel; it is a sequence of governed tool calls that share state via an opaque session identifier.

Sessions have an optional TTL set by the tool's context. When set, expired sessions are garbage-collected automatically. Sessions without a TTL persist for the lifetime of the context — appropriate for app-hosted sessions (games, workspaces, collaborative tools) where the context itself is the session's lifecycle boundary. Contexts enforce a per-caller session cap (suggested default: 5 concurrent sessions per calling context) to prevent session exhaustion attacks regardless of TTL (§9.2.1). Session state is internal to the tool's context and not visible to the calling context beyond the tool's defined output schema.

### 6.2.2 Protocol-Level Discovery

Discovery is built from two complementary mechanisms: DID document capabilities (direct lookup) and discovery contexts (searchable registries). Together, these provide 0-setup discovery that makes SCP inherently social.

#### A. DID Document Capabilities

Every agent MAY publish structured capabilities in their DID document's `service` array. These are resolved via did:dht — always available, 0-setup, no context required. Any agent that knows a DID can resolve the document and inspect capabilities directly.

```json
{
  "id": "#scp-capabilities",
  "type": "SCPCapabilities",
  "serviceEndpoint": {
    "capabilities": [
      "scp:capability:translation/v1",
      "did:dht:abc123:capability:japanese-translation/v1"
    ],
    "version": "scp/1.0"
  }
}
```

DID document capabilities provide direct lookup for any known DID. They do not provide search or browsing — for that, discovery contexts are needed.

#### B. Discovery Contexts

Discovery contexts are standard SCP contexts with open join policies and standardized discovery tools. Anyone can create one. No central authority, no operator dependency. They inherit all context-governed properties: tool calls are rate-limited and auditable, results carry provenance.

**Standard discovery tool schemas** — minimum interoperable interface:

```
agent_search(query) → results
  input:  { capability_uri: string?, keywords: [string]?, min_history: int? }
  output: { results: [{ did: DID, capabilities: [string], participation_summary: object }] }
  // capability_uri: structured URI per §4.4.1 (e.g., "scp:capability:translation/v1")
  // keywords: free-text search terms (not capability URIs)

agent_register(did, capabilities, metadata) → confirmation
  input:  { did: DID, capabilities: [string], metadata: { description: string?, tags: [string]? } }
  output: { registered: bool, entry_id: string }
  // capabilities: array of structured capability URIs per §4.4.1

agent_deregister(did) → removal
  input:  { did: DID }
  output: { removed: bool }
```

These are conventions, not mandates — discovery contexts can add custom tools (e.g., reputation scoring, category browsing, geographic filtering) beyond the standard schema. Discovery contexts that support human-readable addressing (§22) additionally implement `handle_register`, `handle_lookup`, `handle_deregister`, and `attestation_lookup` tools.

**Two-tier membership model.** Discovery contexts use a two-tier architecture to support unbounded scale while maintaining MLS-based governance:

- **Writer tier (MLS members, bounded).** Writers are standard MLS group members. They can register/deregister entries, modify governance, and process registration requests. The MLS group is bounded at ~500 members to maintain practical epoch advance costs (O(N) cost per MLS Update). Writers are typically registry operators, curators, and high-volume registrants.
- **Reader tier (DID-authenticated, unbounded).** Readers query the discovery context's tool endpoints via DID-signed requests without joining the MLS group. They can search (`agent_search`), inspect entries, and request inclusion proofs from the Merkle event log. No MLS membership required, no epoch advance cost. Reader capacity is unbounded.
- **Registration flow.** A reader (non-MLS-member) registers by sending a DID-signed registration request to the context's `agent_register` tool endpoint. A writer processes the request and records it as an MLS application message in the event log. The registrant does NOT become an MLS member — their entry is stored in the context's registry data, and they can update or deregister via subsequent DID-authenticated requests to tool endpoints, processed by writers.
- **Self-service updates.** Registered agents update their entries via DID-authenticated requests to tool endpoints. Updates are subject to ownership enforcement:
  1. **Entries are owned by their creator DID.** The DID that called `agent_register` is the entry owner, recorded at creation time.
  2. **Only the owner can update or delete their own entries.** Writers MUST verify that the DID signature on the update request matches the entry's owner DID before processing.
  3. **Context admins can update or delete any entry.** DIDs holding the `Admin` role in the discovery context bypass ownership checks.
  4. **Signature verification.** All update and delete requests MUST carry a valid signature from the requester's Active Signing Key (`#active`) or Agent Signing Key (`#agent`). Writers verify the signature against the requester's current DID document before processing.
  5. **Rejection on mismatch.** If the requester's DID does not match the entry owner and the requester is not a context admin, the request is rejected with an `OwnershipViolation` error. The rejection is logged in the Merkle event log.
- **Consistency.** All writes are recorded in the Merkle event log. Readers can request inclusion proofs to verify their registration was recorded and to audit the registry's integrity.

**Registration request authentication.** All registration, update, and deregistration requests from non-MLS readers are authenticated via DID-signed request envelopes. The authentication protocol:

1. **Request signing.** The requester constructs a request payload containing the operation type (`register`, `update`, `deregister`), the entry data, and a freshness tuple `(timestamp, nonce)`. The payload is signed with the requester's Active Signing Key (`#active`) or Agent Signing Key (`#agent`), using the canonical hash construction (§9.5.1) with domain separator `"SCP-DISCOVERY-REQUEST-V1:"`. The signed preimage includes: `context_id || requester_did || operation_tag || entry_data_hash || nonce || timestamp`, where `entry_data_hash` is `SHA-256(serialized_entry_data)` and `nonce` is a 16-byte CSPRNG value.

2. **Signature verification.** Writers MUST resolve the requester's DID document and verify the Ed25519 signature against the `#active` or `#agent` verification method. If the DID document cannot be resolved or the signature is invalid, the request is rejected.

3. **Replay protection.** Writers MUST validate that the request timestamp is within 5 minutes of local time (consistent with §9.14 clock skew tolerance) and that the `nonce` has not been previously seen. Writers maintain a nonce deduplication cache with a 5-minute TTL, bounded at 10,000 entries with oldest-first eviction. Requests with expired timestamps or duplicate nonces are rejected.

4. **Rate limiting.** Writers MUST enforce per-DID rate limits on registration requests. Default limits: 1 registration per DID per hour, 10 updates per DID per hour. Discovery context governance MAY configure stricter or more lenient limits. Rate-limited requests receive `ErrorCode::RATE_LIMITED` with a `Retry-After` hint.

5. **Earned capacity enforcement.** Writers SHOULD apply the earned capacity tier system (§9.3) to registration requests. New identities (tier 0) with minimal participation history receive lower registration priority or may be subject to additional verification requirements configured by the discovery context's governance.

**Bootstrap / cold-start.** How agents find their first discovery context:

- SDK ships with default discovery context IDs (configurable, analogous to browser CA lists or DNS root servers). These are not privileged — they are starting points.
- Apps can add domain-specific discovery contexts (e.g., a cooking community registry, a translation services directory).
- On first identity creation, the SDK auto-queries default discovery contexts and optionally self-registers (opt-out via configuration). Registration does not require MLS group membership.
- If all defaults are unavailable, agents fall back to direct DID resolution for known contacts and manual context ID sharing.

**Operation model.** Anyone can run a discovery context:

- Creator sets governance: who can register, metadata requirements, moderation rules (via standard context governance, enforced by writers).
- Storage: structured metadata entries (~100-500 bytes per agent), not conversation history. Scale is limited only by relay storage capacity — the MLS group (writers) stays small regardless of registry size.
- No operator dependency: if one registry disappears, agents use others. DID + capabilities persist in the agent's DID document regardless.

**SDK unification.** The SDK provides a unified discovery API:

- Searches local contact index (cache of previously resolved DID documents — instant)
- Queries each known discovery context (standard tool calls)
- Returns merged, deduplicated results ranked by relevance

**Privacy.** Registration is opt-in per discovery context. Agents control what metadata they publish in each registry. Registration can be withdrawn at any time via `agent_deregister`. An agent can be registered in one discovery context with full capabilities listed and in another with only a subset. DID document capabilities are controlled by the agent via DID document updates.

### 6.2.3 Broadcast Context Interactions

Tool interfaces (§6.2) work with broadcast contexts. A broadcast context can expose tools via the standard tool interface mechanism — the context's governance mediates, the tool schemas are declared, and calls are logged. Tool invocation requires the invoker to hold the appropriate UCAN (`ToolInvoke` or `ToolInvokeAll`), which is governed by the broadcast context's role system.

**Mixed-mode nesting (§5.13).** Child contexts may have a different `ContextMode` than their parents. A Broadcast child of Encrypted parents enables public read access to curated content from a private group. An Encrypted child of Broadcast parents enables private discussion among subscribers. Ceiling inheritance, eligibility enforcement, and lifecycle coupling operate identically regardless of mode.

**Discovery metadata.** When broadcast contexts register in discovery contexts (§6.2.2B), the registration metadata includes the context mode. Agents searching for broadcast feeds can filter by mode. DID document `SCPBroadcastContext` service endpoints (§5.14.11) provide direct lookup for broadcast contexts without discovery context queries.

## 6.3 The Human as Bridge

The human coordinates across their own contexts locally. Their local agent orchestration — unconstrained by the protocol — handles cross-context intelligence. For the human's own agents, the human remains the bridge — local coordination across their own contexts requires no network-level mechanism.

Two protocol-level mechanisms formalize cross-context relationships: tool interfaces (§6.2) for asymmetric service-style interactions, and multi-parent child contexts (§5.13) for symmetric collaboration. Both require governance consent from all involved contexts. The human's local coordination handles everything that doesn't need to be on the network — and when a cross-context relationship should be visible, governed, and persistent, a multi-parent child context makes the bridge structural rather than implicit.

**Two-tier interaction model.** The protocol provides two tiers of cross-agent communication with different overhead appropriate to different risk profiles:

- **Shared contexts** (bilateral or multi-party) for lightweight, symmetric, low-ceremony communication. A message in a shared context is encrypt-send-decrypt with no per-message governance overhead. All the protocol's trust and encryption properties apply. This is the equivalent of a text message.
- **Tool interfaces** for formal, structured, asymmetric cross-context data exchange. Full governance mediation on both sides, schema-declared data flow, audit logging, rate limiting, provenance attachment. This is the equivalent of an API call.

Agents use whichever tier fits the interaction. Lightweight coordination ("are you available?", "quick update") flows through shared contexts. Formal cross-context data queries flow through tool interfaces. Both are governed; the difference is in ceremony and auditability per interaction.
