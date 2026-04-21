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
- **Chain depth limit.** Cross-context tool calls carry a `chain_depth` counter, incremented on each hop. A tool call at maximum depth cannot trigger further cross-context tool calls. Context-configurable via `ContextParams::max_chain_depth` (default: 8, range [1, 255]). There is no protocol hard maximum — chain depth is a context concern, and provenance quality naturally degrades with depth. This bounds amplification and makes transitive provenance degradation mechanically enforced (§9.2.1, §24.4, ADR-043).
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

2. **Outbound policy validation.** Context A validates that `tool:interface` is in its ceiling (§5.3) and the proposer holds the `tool:interface` capability.

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

   **`hop_salt` derivation.** The `InterfaceEstablished` event carries a `hop_salt: [u8; 32]` used to pseudonymize `source_chain.context_id` entries for observers who are not members of each hop (§5.4.4). The salt is deterministically derived from both contexts' MLS exporter keys so no raw random sampling is required, revocation of the interface rotates the salt automatically on re-establishment, and the salt cannot be chosen by either party alone:

   ```
   // Both contexts derive the same 32-byte salt independently at acceptance time.
   // MLS_EXPORTER(label, context, length) is the RFC 9420 §8.5 export primitive.
   ikm_a = MLS_EXPORTER("scp-context-hop-salt-v1", b"", 32)  // exporter on Context A's current epoch
   ikm_b = MLS_EXPORTER("scp-context-hop-salt-v1", b"", 32)  // exporter on Context B's current epoch

   // Canonical concatenation: lexicographically smaller context_id first, so both sides agree.
   ordered = if context_a_id < context_b_id { (ikm_a, ikm_b) } else { (ikm_b, ikm_a) }

   hop_salt = HKDF-SHA-256(
     salt = b"",
     ikm  = ordered.0 || ordered.1,
     info = "SCP-CONTEXT-HOP-SALT-V1:" || canonical_context_pair(a_id, b_id),
     L    = 32,
   )

   // canonical_context_pair sorts the two context_ids lexicographically, emits them as
   //   len_be32(min_id) || min_id || len_be32(max_id) || max_id
   ```

   Because MLS exporter keys rotate on every epoch advance, `hop_salt` rotates naturally with each context's epoch progression without any interface-level bookkeeping. Revoking and re-establishing the interface also forces a fresh salt (each side re-exports on whatever epoch is current at re-acceptance). The `SCP-CONTEXT-HOP-SALT-V1:` separator is registered in §9.18.2. Both contexts store the derived salt in their interface state record; cross-context error wrapping (§5.4.4) reads the salt from this record when pseudonymizing hops.

5. **Teardown.** Either context can revoke the interface at any time via governance action `RevokeToolInterface { interface_id }`. Revocation is unilateral — no consent from the other side is needed. An `InterfaceRevoked` event is recorded in the revoking context's event log.

**Outbound and inbound policies:**

```
OutboundPolicy {
  allowed_callers:      Vec<DID>,   // DIDs in Context A authorized to use this interface.
                                    // Empty = any member with tool:interface capability.
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

**Classification-aware rate tiers (§5.4.2).** Defaults differ for Query and Action outlets. Query outlets: per-interface 600 calls/min, per-caller 100 calls/min — an order of magnitude higher, reflecting the idempotent read-only contract. Action outlets: per-interface 60 calls/min, per-caller 10 calls/min (the original defaults). Both tiers are independently configurable within the range shown in the table.

#### 6.2.0.3 Chain Amplification Rule

Cross-context outlet calls inherit an **`origin_kind`** (an `OutletKind` per §5.4.2) from the outermost caller. At each cross-context hop, the runtime enforces:

- **Query → Query: permitted.** A Query invocation may transitively invoke Query outlets in downstream contexts.
- **Query → Action: forbidden.** A Query invocation MUST NOT trigger any Action invocation, directly or transitively. The runtime rejects the amplification attempt at the cross-context consent gate (§6.2.0.1) with `OutletErrorClass::Authorization::AmplificationViolation`.
- **Action → Query: permitted.** An Action invocation may transitively invoke Query outlets.
- **Action → Action: permitted.** An Action invocation may transitively invoke Action outlets, subject to chain depth.

The rule closes the "free read laundered into paid write" class of attacks: Query is the cacheable, cost-capped tier, and allowing a Query to cascade into an Action would let an adversary exercise Action semantics under Query rate limits and economics.

**`origin_kind` is bound to the UCAN delegation chain, not to runtime state.** The outermost caller sets `origin_kind` equal to the stem it exercises — `Query` when it exercises `outlet_query:*`, `Action` when it exercises `outlet_call:*`. The stem lives inside a signed UCAN delegation, so the outermost `origin_kind` is not a claim any participant makes at runtime; it is a property of the token. Every cross-context hop propagates `origin_kind` inside the delegated UCAN's `nb` field as the dedicated `origin_kind` slot of `InvocationCaveats` (§7.3.8). Because `origin_kind` is a field of the signed `InvocationCaveats`, it is covered by each hop's delegation signature.

The caveats-layer `narrow()` rule (§7.3.8) enforces equality between child and parent `origin_kind` at every delegation step:

```
child.nb.InvocationCaveats.origin_kind  ==  parent.nb.InvocationCaveats.origin_kind
```

— that is, `origin_kind` is preserved across every delegation step; a child delegation MUST NOT reset, widen, or narrow it. An `origin_kind` mismatch between a child and its parent is an attenuation violation at Step 7b of the UCAN validation pipeline (§7.2.1) and returns `OutletErrorClass::Authorization::AttenuationViolation`. This makes the "origin_kind is signed" claim operationally true: the equality check runs on the `narrow()` verifier, which is the single chokepoint where the signed child-parent relationship is validated.

Because `origin_kind` is covered by each hop's UCAN signature, the hop target cannot be tricked into treating a `Query`-originated call as `Action`-originated by a forged claim at the transport layer — forging `origin_kind` would require forging the signed delegation.

The amplification check `origin_kind != Query || hop_kind == Query` MUST be evaluated at the hop target (inside the acceptance path, after UCAN validation and before the outlet is dispatched), not only at the hop source. A malicious source that skipped the check client-side is caught at the target.

#### 6.2.0.4 Chain Depth Split

The context-level `max_chain_depth` parameter (default 8) is partitioned by kind:

- **Query chain budget:** `max_chain_depth` (full budget).
- **Action chain budget:** `max(1, max_chain_depth / 2)` (default 4).

On each cross-context hop, the runtime decrements the kind-appropriate counter. A Query → Query → Action chain at budget `(8, 4)` decrements Query on hops 1 and 2 and then, because Query → Action is forbidden under §6.2.0.3, is rejected before the Action hop consumes budget. The split ensures Action invocations have stricter amplification bounds than Query invocations without requiring two unrelated parameters.

### 6.2.0.5 Cross-Context Streaming

Outlet streams (§5.4.5) cross context boundaries under the same §6.2 tool-interface model. A shared-member bridge transports chunks from the target context to the source context, re-encrypting each chunk per-recipient as it crosses (source-context encryption on the outbound leg; target-context decryption on the inbound leg). The bridge does NOT buffer the full stream — chunks flow through as they arrive, subject to the credit window.

- **`chain_depth` is set at open.** Every chunk inherits the chain depth recorded at the opening cross-context hop. Chunks do not recompute depth. Opening is subject to §6.2.0.3 and §6.2.0.4; chunks after open are not re-checked.
- **Credit is end-to-end.** Credit grants from the invoker propagate across the bridge to the executor without re-accounting at the bridge.
- **UCAN check locus.** UCAN is validated ONCE at stream open (§5.4.5). Mid-stream revocation terminates at the next executor checkpoint, but already-emitted chunks remain authorized.
- **Event log recording.** Each of the two contexts records exactly one `OutletInvokedEvent` for the stream, with the same `stream_manifest_hash` (§5.4.5). Cross-context provenance (§7.7) chains the two events via the `source_chain` field on the error envelope (when the stream fails) or on the final `End.provenance` (when it succeeds).

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

Sessions have an optional TTL set by the tool's context. When set, expired sessions are garbage-collected automatically. Sessions without a TTL persist for the lifetime of the context — appropriate for app-hosted sessions (games, workspaces, collaborative tools) where the context itself is the session's lifecycle boundary. Contexts enforce a per-caller session cap, context-configurable via `ContextParams::session_cap` (default: 1000 concurrent sessions per calling context), to prevent session exhaustion attacks regardless of TTL (§9.2.1, ADR-043). Session state is internal to the tool's context and not visible to the calling context beyond the tool's defined output schema.

**Session chain-amplification binding.** A session inherits the `origin_kind` (§6.2.0.3) of the first call that created it. Every subsequent call routed through the session (identified by `session_id` in the input) is treated by the runtime as carrying the session's recorded `origin_kind`, regardless of any new UCAN presented by the caller or any `origin_kind` claim in a later delegation. Concretely: if a session was opened by a `Query`-originated call, every call through that session is treated as `origin_kind = Query` for amplification-rule purposes, and any attempt to call an Action outlet through the session is rejected with `AmplificationViolation`. This prevents async self-triggered amplification — a `Query`-originated session cannot "mature" into an Action session by the caller later presenting an Action-rooted UCAN.

Sessions store their recorded `origin_kind` alongside the session state. A session opened with `origin_kind = Action` retains Action semantics for its lifetime; a session opened with `origin_kind = Query` retains Query semantics for its lifetime. There is no session upgrade path — re-opening as Action requires a new session with a fresh `session_id`.

#### 6.2.1.1 Stateful Outlet Sessions × Streaming

When a streaming outlet (§5.4.5) participates in a session, the session and stream lifecycles interact through five invariants. The session owns the long-lived authorization state; each stream owns its per-invocation chunk flow.

(a) **`session_id` carried on open.** `OutletStreamOpen` carries an optional `session_id: Option<String>` field. When present, the open MUST reference an existing, non-expired session whose `session_id` matches, whose TTL has not elapsed, and whose recorded `origin_kind` is compatible with the outlet's kind per §6.2.0.3. An `OutletStreamOpen` referencing an unknown, expired, or amplification-incompatible session is rejected at open with `OutletErrorClass::Protocol::UnknownSession` or `OutletErrorClass::Authorization::AmplificationViolation` respectively.

(b) **One concurrent stream per session.** A session supports AT MOST one concurrent stream. A second `OutletStreamOpen` referencing a `session_id` that already has a live stream is rejected with `OutletErrorClass::Protocol::StreamAlreadyOpen` (class Protocol, slug `protocol.stream-already-open`). The rule closes the "parallel billing channels through one session" surface. A stream is considered live from open until the terminal chunk is written (End or Error{terminal:true}) or the stream is cancelled and the cancel-ack chunk arrives.

(c) **Session owns `origin_kind`.** The session's recorded `origin_kind` (§6.2.1 "Session chain-amplification binding") is the authoritative value for every stream opened against the session. The opening `OutletStreamOpen`'s `effective_caveats.origin_kind` MUST equal the session's recorded `origin_kind`; a mismatch is an attenuation failure (not a silent override). This means a session opened as `Query` cannot host a stream whose narrowed caveats claim `Action` — the session's `origin_kind` shields the hop target from any later attempt to re-classify.

(d) **Session owns `caveats_binding`.** The session's first stream establishes the session's pinned `caveats_binding` at session-open time (recorded from that stream's `OutletStreamOpen.caveats_binding`). Every subsequent stream opened against the same session MUST present an identical `caveats_binding`; a mismatch is rejected as `OutletErrorClass::Authorization::AttenuationViolation` under the caveats-binding-pinning invariant (§5.4.5). This extends stream-level pinning to the session lifetime — a single session cannot host multiple streams under different caveat sets, only retries of the same caveat contract.

(e) **`stream_epoch` matches session's MLS epoch at open.** Each stream records `stream_epoch` equal to the hosting context's MLS epoch counter at the moment of `OutletStreamOpen` acceptance. The session independently records the MLS epoch at which it was opened (`session_epoch`). A stream whose `stream_epoch != session_epoch` is permitted (sessions persist across epoch advances), but the re-encryption bridge on cross-context streaming (§6.2.0.5) uses `stream_epoch` for chunk-level re-encryption, not `session_epoch`. Recording the two separately means a long-lived session spanning many MLS epochs still produces a per-stream chunk manifest bound to its own epoch, so a single compromised epoch exposes chunks from only the streams opened within that epoch, not the session's entire history.

Together these invariants make sessions a legitimate long-lived authorization envelope without allowing them to be used as a channel that escapes stream-level billing, amplification, or caveats enforcement.

### 6.2.2 Protocol-Level Discovery

Discovery is built from two complementary mechanisms: DID document capabilities (direct lookup) and contexts with discovery tools (searchable registries). Together, these provide 0-setup discovery that makes SCP inherently social.

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

DID document capabilities provide direct lookup for any known DID. They do not provide search or browsing — for that, contexts with discovery tools are needed.

#### B. Contexts with Discovery Tools

These are standard SCP contexts with open join policies and standardized discovery tools. Anyone can create one. No central authority, no operator dependency. They inherit all context-governed properties: tool calls are rate-limited and auditable, results carry provenance.

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

These are conventions, not mandates — contexts with discovery tools can add custom tools (e.g., reputation scoring, category browsing, geographic filtering) beyond the standard schema. Contexts that support human-readable addressing (§22) additionally implement `handle_register`, `handle_lookup`, `handle_deregister`, and `attestation_lookup` tools. Contexts that serve as scope registries (§22.3.5) additionally implement `scope_register`, `scope_lookup`, `scope_deregister` — independent tools with separate storage, constrained to context-only targets and dot-free scope names (ADR-043).

**Two-tier membership model.** Contexts use a two-tier architecture to support unbounded scale while maintaining MLS-based governance:

- **Writer tier (MLS members, bounded).** Writers are standard MLS group members. They can register/deregister entries, modify governance, and process registration requests. The MLS group is bounded at ~500 members to maintain practical epoch advance costs (O(N) cost per MLS Update). Writers are typically registry operators, curators, and high-volume registrants.
- **Reader tier (DID-authenticated, unbounded).** Readers query the context's tool endpoints via DID-signed requests without joining the MLS group. They can search (`agent_search`), inspect entries, and request inclusion proofs from the Merkle event log. No MLS membership required, no epoch advance cost. Reader capacity is unbounded.
- **Registration flow.** A reader (non-MLS-member) registers by sending a DID-signed registration request to the context's `agent_register` tool endpoint. A writer processes the request and records it as an MLS application message in the event log. The registrant does NOT become an MLS member — their entry is stored in the context's registry data, and they can update or deregister via subsequent DID-authenticated requests to tool endpoints, processed by writers.
- **Self-service updates.** Registered agents update their entries via DID-authenticated requests to tool endpoints. Updates are subject to ownership enforcement:
  1. **Entries are owned by their creator DID.** The DID that called `agent_register` is the entry owner, recorded at creation time.
  2. **Only the owner can update or delete their own entries.** Writers MUST verify that the DID signature on the update request matches the entry's owner DID before processing.
  3. **Context admins can update or delete any entry.** DIDs holding the `Admin` role in the context bypass ownership checks.
  4. **Signature verification.** All update and delete requests MUST carry a valid signature from the requester's Active Signing Key (`#active`) or Agent Signing Key (`#agent`). Writers verify the signature against the requester's current DID document before processing.
  5. **Rejection on mismatch.** If the requester's DID does not match the entry owner and the requester is not a context admin, the request is rejected with an `OwnershipViolation` error. The rejection is logged in the Merkle event log.
- **Consistency.** All writes are recorded in the Merkle event log. Readers can request inclusion proofs to verify their registration was recorded and to audit the registry's integrity.

**Registration request authentication.** All registration, update, and deregistration requests from non-MLS readers are authenticated via DID-signed request envelopes. The authentication protocol:

1. **Request signing.** The requester constructs a request payload containing the operation type (`register`, `update`, `deregister`), the entry data, and a freshness tuple `(timestamp, nonce)`. The payload is signed with the requester's Active Signing Key (`#active`) or Agent Signing Key (`#agent`), using the canonical hash construction (§9.5.1) with domain separator `"SCP-DISCOVERY-REQUEST-V1:"`. The signed preimage includes: `context_id || requester_did || operation_tag || entry_data_hash || nonce || timestamp`, where `entry_data_hash` is `SHA-256(serialized_entry_data)` and `nonce` is a 16-byte CSPRNG value.

2. **Signature verification.** Writers MUST resolve the requester's DID document and verify the Ed25519 signature against the `#active` or `#agent` verification method. If the DID document cannot be resolved or the signature is invalid, the request is rejected.

3. **Replay protection.** Writers MUST validate that the request timestamp is within 5 minutes of local time (consistent with §9.14 clock skew tolerance) and that the `nonce` has not been previously seen. Writers maintain a nonce deduplication cache with a 5-minute TTL, bounded at 10,000 entries with oldest-first eviction. Requests with expired timestamps or duplicate nonces are rejected.

4. **Rate limiting.** Writers MUST enforce per-DID rate limits on registration requests. Default limits: 1 registration per DID per hour, 10 updates per DID per hour. Context governance MAY configure stricter or more lenient limits. Rate-limited requests receive `ErrorCode::RATE_LIMITED` with a `Retry-After` hint.

5. **Earned capacity enforcement.** Writers SHOULD apply the earned capacity tier system (§9.3) to registration requests. New identities (tier 0) with minimal participation history receive lower registration priority or may be subject to additional verification requirements configured by the context's governance.

**Bootstrap / cold-start.** How agents find their first context:

- SDK ships with default bootstrap context IDs (configurable, analogous to browser CA lists or DNS root servers). These are not privileged — they are starting points.
- Apps can add domain-specific contexts with discovery tools (e.g., a cooking community registry, a translation services directory).
- On first identity creation, the SDK auto-queries default contexts with discovery tools and optionally self-registers (opt-out via configuration). Registration does not require MLS group membership.
- If all defaults are unavailable, agents fall back to direct DID resolution for known contacts and manual context ID sharing.

**Operation model.** Anyone can run a context with discovery tools:

- Creator sets governance: who can register, metadata requirements, moderation rules (via standard context governance, enforced by writers).
- Storage: structured metadata entries (~100-500 bytes per agent), not conversation history. Scale is limited only by relay storage capacity — the MLS group (writers) stays small regardless of registry size.
- No operator dependency: if one registry disappears, agents use others. DID + capabilities persist in the agent's DID document regardless.

**SDK unification.** The SDK provides a unified discovery API:

- Searches local contact index (cache of previously resolved DID documents — instant)
- Queries each known context (standard tool calls)
- Returns merged, deduplicated results ranked by relevance

**Privacy.** Registration is opt-in per context. Agents control what metadata they publish in each registry. Registration can be withdrawn at any time via `agent_deregister`. An agent can be registered in one context with full capabilities listed and in another with only a subset. DID document capabilities are controlled by the agent via DID document updates.

### 6.2.3 Broadcast Context Interactions

Tool interfaces (§6.2) work with broadcast contexts. A broadcast context can expose tools via the standard tool interface mechanism — the context's governance mediates, the tool schemas are declared, and calls are logged. Tool invocation requires the invoker to hold the appropriate UCAN (`ToolInvoke` or `ToolInvokeAll`), which is governed by the broadcast context's role system.

**Mixed-mode nesting (§5.13).** Child contexts may have a different `ContextMode` than their parents. A Broadcast child of Encrypted parents enables public read access to curated content from a private group. An Encrypted child of Broadcast parents enables private discussion among subscribers. Ceiling inheritance, eligibility enforcement, and lifecycle coupling operate identically regardless of mode.

**Discovery metadata.** When broadcast contexts register in contexts with discovery tools (§6.2.2B), the registration metadata includes the context mode. Agents searching for broadcast feeds can filter by mode. DID document `SCPBroadcastContext` service endpoints (§5.14.11) provide direct lookup for broadcast contexts without context queries.

## 6.3 The Human as Bridge

The human coordinates across their own contexts locally. Their local agent orchestration — unconstrained by the protocol — handles cross-context intelligence. For the human's own agents, the human remains the bridge — local coordination across their own contexts requires no network-level mechanism.

Two protocol-level mechanisms formalize cross-context relationships: tool interfaces (§6.2) for asymmetric service-style interactions, and multi-parent child contexts (§5.13) for symmetric collaboration. Both require governance consent from all involved contexts. The human's local coordination handles everything that doesn't need to be on the network — and when a cross-context relationship should be visible, governed, and persistent, a multi-parent child context makes the bridge structural rather than implicit.

**Two-tier interaction model.** The protocol provides two tiers of cross-agent communication with different overhead appropriate to different risk profiles:

- **Shared contexts** (bilateral or multi-party) for lightweight, symmetric, low-ceremony communication. A message in a shared context is encrypt-send-decrypt with no per-message governance overhead. All the protocol's trust and encryption properties apply. This is the equivalent of a text message.
- **Tool interfaces** for formal, structured, asymmetric cross-context data exchange. Full governance mediation on both sides, schema-declared data flow, audit logging, rate limiting, provenance attachment. This is the equivalent of an API call.

Agents use whichever tier fits the interaction. Lightweight coordination ("are you available?", "quick update") flows through shared contexts. Formal cross-context data queries flow through tool interfaces. Both are governed; the difference is in ceremony and auditability per interaction.
